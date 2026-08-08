<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Shows mailboxes with email forwarding enabled in Exchange Online.

.DESCRIPTION
    Enumerates mailboxes and reports both mailbox-level forwarding
    (ForwardingAddress / ForwardingSmtpAddress + DeliverToMailboxAndForward)
    and Inbox rule-based forwarding/redirect actions. Combining both is
    important for data-leakage detection, since users can configure covert
    forwarding via an Inbox rule even when mailbox-level forwarding is
    disabled. Only mailboxes with at least one forwarding mechanism active
    are included in the report. Always returns full result objects to the
    console/pipeline; CSV export is optional.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (MailboxForwarding_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\mailboxforwarding.csv'): the parent
        folder must already exist; the file itself is created/overwritten
        as given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER Identity
    Optional. One or more mailbox identities to scope the report to.
    Defaults to all mailboxes.

.PARAMETER IncludeInboxRules
    Optional switch. Also scan Inbox rules for ForwardTo/RedirectTo/
    ForwardAsAttachmentTo actions. Slower (one extra call per mailbox) but
    catches user-configured covert forwarding that mailbox-level settings
    would miss.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per mailbox with forwarding active.
    Always returned to the console/pipeline; also written to CSV when
    -OutputPath is supplied.

.EXAMPLE
    Get-MailboxForwarding -Identity 'user@contoso.com' -IncludeInboxRules

    Reports mailbox-level forwarding and Inbox-rule-based forwarding
    for the specified mailbox only, returned to the console/pipeline
    without writing a CSV file.

.EXAMPLE
    Get-MailboxForwarding -IncludeInboxRules

    Reports mailbox-level and Inbox-rule-based forwarding across the tenant,
    returned to the console/pipeline only - no CSV written.

.EXAMPLE
    Get-MailboxForwarding -OutputPath 'C:\Reports' -IncludeInboxRules

    Same as above, and additionally exports to
    C:\Reports\MailboxForwarding_<timestamp>.csv

.EXAMPLE
    Get-MailboxForwarding -OutputPath 'C:\Reports\mailboxforwarding.csv' -Identity 'user@contoso.com'

    Reports mailbox-level forwarding for the specified mailbox only, and
    exports to the exact file C:\Reports\mailboxforwarding.csv (no
    timestamp appended).

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (30-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. ExchangeOnlineManagement module (v3.x recommended) installed
    2. An active Connect-ExchangeOnline session with rights to run
       Get-EXOMailbox and (if -IncludeInboxRules) Get-InboxRule
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Inbox rule scanning requires per-mailbox impersonation/scope rights;
      may be slow on large tenants - consider scoping with -Identity first
    - Client-side (Outlook desktop) auto-forward rules that never sync to
      the server are not detectable via any API and are out of scope

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailbox

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-inboxrule

#>


Function Get-MailboxForwarding
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ($_ -match '[<>"|?*]') { throw "OutputPath contains invalid path characters." }

            $isFilePath = [System.IO.Path]::GetExtension($_) -eq '.csv'
            $parentDir  = if ($isFilePath) { Split-Path -Path $_ -Parent } else { $_ }
            if ([string]::IsNullOrWhiteSpace($parentDir)) { $parentDir = '.' }

            if (-not (Test-Path -Path $parentDir -PathType Container)) { throw "Directory '$parentDir' does not exist." }
            $true
        })]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeInboxRules
    )

    #region Connection check
    try
    {
        $null = Get-ConnectionInformation -ErrorAction Stop
        Write-Verbose "Active Exchange Online session detected."
    }
    catch
    {
        Write-Warning "No active Exchange Online session found. Attempting Connect-ExchangeOnline..."
        try { Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop }
        catch { Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"; return }
    }
    #endregion

    #region Enumerate mailboxes
    Write-Progress -Activity "Get-MailboxForwarding" -Status "Retrieving mailbox list..." -PercentComplete 0
    try
    {
        if ($Identity)
        {
            $mailboxes = foreach ($id in $Identity) { Get-EXOMailbox -Identity $id -ErrorAction Stop `
                -Properties DisplayName,PrimarySmtpAddress,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward }
        }
        else
        {
            $mailboxes = Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop `
                -Properties DisplayName,PrimarySmtpAddress,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward
        }
    }
    catch
    {
        Write-Error "Failed to retrieve mailboxes: $($_.Exception.Message)"
        return
    }
    Write-Verbose "Evaluating $($mailboxes.Count) mailbox(es) for forwarding."

    if (-not $mailboxes -or $mailboxes.Count -eq 0)
    {
        Write-Host "No mailboxes found in the resolved scope." -ForegroundColor Yellow
        return
    }
    #endregion

    #region Build report rows
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $mailboxes.Count
    $counter = 0

    foreach ($mbx in $mailboxes)
    {
        $counter++
        Write-Progress -Activity "Get-MailboxForwarding" -Status "Processing $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $hasMailboxForwarding = [bool]($mbx.ForwardingAddress -or $mbx.ForwardingSmtpAddress)

            $ruleForwardTargets = @()
            if ($IncludeInboxRules)
            {
                try
                {
                    $rules = Get-InboxRule -Mailbox $mbx.PrimarySmtpAddress -ErrorAction Stop |
                        Where-Object { $_.Enabled -and ($_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo) }

                    foreach ($rule in $rules)
                    {
                        $targets = @($rule.ForwardTo) + @($rule.RedirectTo) + @($rule.ForwardAsAttachmentTo) | Where-Object { $_ }
                        $ruleForwardTargets += $targets
                    }
                }
                catch
                {
                    Write-Warning "Could not read Inbox rules for '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
                }
            }

            if ($hasMailboxForwarding -or $ruleForwardTargets.Count -gt 0)
            {
                $report.Add([PSCustomObject]@{
                    DisplayName                 = $mbx.DisplayName
                    PrimarySmtpAddress          = $mbx.PrimarySmtpAddress
                    MailboxLevelForwardingSet   = $hasMailboxForwarding
                    ForwardingAddress           = $mbx.ForwardingAddress
                    ForwardingSmtpAddress       = $mbx.ForwardingSmtpAddress
                    DeliverToMailboxAndForward  = $mbx.DeliverToMailboxAndForward
                    InboxRuleForwardTargets     = ($ruleForwardTargets -join '; ')
                })
            }
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-MailboxForwarding" -Completed
    #endregion

    if ($report.Count -eq 0)
    {
        Write-Host "No mailboxes with forwarding (mailbox-level or Inbox rule) were found." -ForegroundColor Yellow
        return
    }
    #endregion

    #region Export (optional)
    if ($OutputPath)
    {
        if ([System.IO.Path]::GetExtension($OutputPath) -eq '.csv')
        {
            # Caller supplied an exact file path - use it as given, no timestamp appended
            $outFile = $OutputPath
        }
        else
        {
            # Caller supplied a folder - auto-generate a timestamped filename
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $outFile   = Join-Path -Path $OutputPath -ChildPath "MailboxForwarding_$timestamp.csv"
        }

        try
        {
            $report | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Host "Report exported: $outFile" -ForegroundColor Green
        }
        catch
        {
            Write-Error "Failed to export CSV to '$outFile': $($_.Exception.Message)"
        }
    }
    else
    {
        Write-Verbose "No -OutputPath supplied; results returned to the console/pipeline only."
    }
    #endregion

    return $report
}
