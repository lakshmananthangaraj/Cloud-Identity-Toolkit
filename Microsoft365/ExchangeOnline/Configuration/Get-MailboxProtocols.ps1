<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Shows POP, IMAP, MAPI, OWA, and ActiveSync protocol status for
    Exchange Online mailboxes.

.DESCRIPTION
    Enumerates mailbox client-access protocol settings via Get-EXOCasMailbox
    to identify insecure or unnecessary protocols left enabled (particularly
    legacy POP3/IMAP4, which are common vectors for password-spray and
    legacy-auth attacks). Flags each mailbox with a simple
    HasLegacyProtocolEnabled indicator for quick triage. Always returns
    full result objects to the console/pipeline; CSV export is optional.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (MailboxProtocols_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\mailboxprotocols.csv'): the parent
        folder must already exist; the file itself is created/overwritten
        as given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER Identity
    Optional. One or more mailbox identities to scope the report to.
    Defaults to all mailboxes.

.PARAMETER RecipientTypeDetailsFilter
    Optional. Restrict the report to one or more recipient type details.
    Ignored if -Identity is supplied.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per mailbox, containing protocol
    enablement status. Always returned to the console/pipeline; also
    written to CSV when -OutputPath is supplied.

.EXAMPLE
    Get-MailboxProtocols

    Reports protocol status for all mailboxes and flags any with legacy
    POP/IMAP enabled, to the console/pipeline only - no CSV written.

.EXAMPLE
    Get-MailboxProtocols -OutputPath 'C:\Reports'

    Same scope as above, and additionally exports to
    C:\Reports\MailboxProtocols_<timestamp>.csv

.EXAMPLE
    Get-MailboxProtocols -OutputPath 'C:\Reports\mailboxprotocols.csv'

    Same scope as above, and exports to the exact file
    C:\Reports\mailboxprotocols.csv (no timestamp appended).

.EXAMPLE
    Get-MailboxProtocols -Identity 'sales@contoso.com','hr@contoso.com'

    Reports protocol status only for the two specified mailboxes, to the
    console/pipeline only.

.EXAMPLE
    Get-MailboxProtocols -RecipientTypeDetailsFilter 'UserMailbox'

    Reports protocol status for user mailboxes only, to the
    console/pipeline only.

.EXAMPLE
    Get-MailboxProtocols -OutputPath 'C:\Reports' -RecipientTypeDetailsFilter 'SharedMailbox' -Verbose

    Reports protocol status for shared mailboxes only, with verbose
    progress output, and exports to
    C:\Reports\MailboxProtocols_<timestamp>.csv

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
       Get-EXOCasMailbox
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Per-mailbox protocol flags can be overridden tenant-wide by
      Authentication Policies or the org-wide "block legacy auth"
      Conditional Access setting; a protocol showing "Enabled" here may
      still be blocked in practice at the tenant/CA layer
    - Reflects configuration only, not actual recent connection activity by
      protocol - cross-reference with sign-in logs for real usage evidence

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exocasmailbox

.LINK
    https://learn.microsoft.com/en-us/exchange/clients/pop3-and-imap4/pop3-and-imap4

#>


Function Get-MailboxProtocols
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
        [ValidateSet('UserMailbox','SharedMailbox','RoomMailbox','EquipmentMailbox','DiscoveryMailbox','TeamMailbox')]
        [string[]]$RecipientTypeDetailsFilter
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
    Write-Progress -Activity "Get-MailboxProtocols" -Status "Retrieving CAS mailbox settings..." -PercentComplete 0
    try
    {
        $properties = 'DisplayName','PrimarySmtpAddress','PopEnabled','ImapEnabled','MAPIEnabled','OWAEnabled',
            'ActiveSyncEnabled','EwsEnabled','OwaMailboxPolicy'

        if ($Identity)
        {
            $casMailboxes = foreach ($id in $Identity) { Get-EXOCasMailbox -Identity $id -ErrorAction Stop -Properties $properties }
        }
        else
        {
            $casMailboxes = Get-EXOCasMailbox -ResultSize Unlimited -ErrorAction Stop -Properties $properties
            if ($RecipientTypeDetailsFilter)
            {
                $casMailboxes = $casMailboxes | Where-Object { $_.RecipientTypeDetails -in $RecipientTypeDetailsFilter }
            }
        }
    }
    catch
    {
        Write-Error "Failed to retrieve CAS mailbox settings: $($_.Exception.Message)"
        return
    }
    Write-Verbose "Evaluating protocol status for $($casMailboxes.Count) mailbox(es)."

    if (-not $casMailboxes -or $casMailboxes.Count -eq 0)
    {
        Write-Host "No mailboxes found in the resolved scope." -ForegroundColor Yellow
        return
    }
    #endregion

    #region Build report rows
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $casMailboxes.Count
    $counter = 0

    foreach ($mbx in $casMailboxes)
    {
        $counter++
        Write-Progress -Activity "Get-MailboxProtocols" -Status "Processing $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $hasLegacyProtocol = [bool]($mbx.PopEnabled -or $mbx.ImapEnabled)

            $report.Add([PSCustomObject]@{
                DisplayName             = $mbx.DisplayName
                PrimarySmtpAddress      = $mbx.PrimarySmtpAddress
                PopEnabled              = $mbx.PopEnabled
                ImapEnabled             = $mbx.ImapEnabled
                MAPIEnabled             = $mbx.MAPIEnabled
                OWAEnabled              = $mbx.OWAEnabled
                ActiveSyncEnabled       = $mbx.ActiveSyncEnabled
                EwsEnabled              = $mbx.EwsEnabled
                OwaMailboxPolicy        = $mbx.OwaMailboxPolicy
                HasLegacyProtocolEnabled = $hasLegacyProtocol
            })
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-MailboxProtocols" -Completed
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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "MailboxProtocols_$timestamp.csv"
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
