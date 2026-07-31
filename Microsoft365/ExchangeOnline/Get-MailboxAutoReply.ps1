<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Lists automatic reply (Out of Office) settings for Exchange Online
    mailboxes.

.DESCRIPTION
    Connects to (or reuses) an existing Exchange Online PowerShell session and
    reports each mailbox's automatic reply state (Disabled/Enabled/
    Scheduled), scheduled start/end times, and internal/external message
    bodies. HTML tags are stripped from message bodies for cleaner CSV
    review. Useful for audits and troubleshooting reports of "my OOF isn't
    working" or verifying scheduled auto-replies before/after a leave
    period. Always returns full report objects to the console/pipeline;
    CSV export is optional.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (MailboxAutoReply_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\autoreply.csv'): the parent folder
        must already exist; the file itself is created/overwritten as
        given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER Identity
    Optional. One or more mailbox identities to scope the report to.
    Defaults to all user and shared mailboxes.

.PARAMETER ActiveOnly
    Optional switch. Only include mailboxes where AutoReplyState is
    'Enabled' or 'Scheduled' (i.e. skip mailboxes with auto-reply off).

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per mailbox, containing per-mailbox
    auto-reply configuration. Always returned to the console/pipeline;
    also written to CSV when -OutputPath is supplied.

.EXAMPLE
    Get-MailboxAutoReply

    Returns auto-reply configuration for all user/shared mailboxes to the
    console/pipeline, no CSV written.

.EXAMPLE
    Get-MailboxAutoReply -OutputPath 'C:\Reports'

    Returns auto-reply configuration for all mailboxes and additionally
    exports to C:\Reports\MailboxAutoReply_<timestamp>.csv

.EXAMPLE
    Get-MailboxAutoReply -OutputPath 'C:\Reports\autoreply.csv'

    Returns auto-reply configuration for all mailboxes and exports to the
    exact file C:\Reports\autoreply.csv (no timestamp appended).

.EXAMPLE
    Get-MailboxAutoReply -Identity 'jdoe@contoso.com','shared-hr@contoso.com'

    Returns auto-reply configuration for only the specified mailboxes, no
    CSV written.

.EXAMPLE
    Get-MailboxAutoReply -ActiveOnly

    Returns only mailboxes currently sending or scheduled to send automatic
    replies, no CSV written.

.EXAMPLE
    Get-MailboxAutoReply -Identity 'jdoe@contoso.com' -ActiveOnly -OutputPath 'C:\Reports' -Verbose

    Returns active auto-reply configuration for the specified mailbox,
    exports to C:\Reports\MailboxAutoReply_<timestamp>.csv, with verbose
    diagnostic output.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (31-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. ExchangeOnlineManagement module (v3.x recommended) installed
    2. An active Connect-ExchangeOnline session with rights to run
       Get-EXOMailbox and Get-MailboxAutoReplyConfiguration
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Message bodies are HTML-stripped with a simple regex, not a full HTML
      parser - complex formatting (tables, embedded images) may leave
      residual artifacts in the plain-text output
    - Shared/room/equipment mailboxes rarely have auto-reply configured;
      script includes user/shared mailboxes by default but -Identity can be
      used to scope to specific mailbox types if preferred
    - Large tenants (50k+ mailboxes) may take several minutes to enumerate;
      consider running during off-peak hours - and console output on very
      large result sets can be slow to render/scroll; pipe to
      Out-GridView or use -OutputPath for large tenants instead of
      reading directly off the console

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-mailboxautoreplyconfiguration

#>


Function Get-MailboxAutoReply
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
        [switch]$ActiveOnly
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
        try
        {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
        catch
        {
            Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
            return
        }
    }
    #endregion

    #region Enumerate mailboxes
    Write-Progress -Activity "Get-MailboxAutoReply" -Status "Retrieving mailbox list..." -PercentComplete 0
    try
    {
        if ($Identity)
        {
            $mailboxes = foreach ($id in $Identity) { Get-EXOMailbox -Identity $id -ErrorAction Stop -Properties DisplayName,PrimarySmtpAddress }
        }
        else
        {
            $mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox,SharedMailbox -ErrorAction Stop `
                -Properties DisplayName,PrimarySmtpAddress
        }
    }
    catch
    {
        Write-Error "Failed to retrieve mailboxes: $($_.Exception.Message)"
        return
    }
    Write-Verbose "Retrieving auto-reply configuration for $($mailboxes.Count) mailbox(es)."
    #endregion

    #region Build report rows
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $mailboxes.Count
    $counter = 0

    foreach ($mbx in $mailboxes)
    {
        $counter++
        Write-Progress -Activity "Get-MailboxAutoReply" -Status "Processing $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $config = Get-MailboxAutoReplyConfiguration -Identity $mbx.PrimarySmtpAddress -ErrorAction Stop

            if ($ActiveOnly -and $config.AutoReplyState -eq 'Disabled')
            {
                continue
            }

            $internalPlain = if ($config.InternalMessage) { ($config.InternalMessage -replace '<[^>]+>','').Trim() } else { $null }
            $externalPlain = if ($config.ExternalMessage) { ($config.ExternalMessage -replace '<[^>]+>','').Trim() } else { $null }

            $report.Add([PSCustomObject]@{
                DisplayName        = $mbx.DisplayName
                PrimarySmtpAddress = $mbx.PrimarySmtpAddress
                AutoReplyState     = $config.AutoReplyState
                ScheduledStartTime = $config.StartTime
                ScheduledEndTime   = $config.EndTime
                ExternalAudience   = $config.ExternalAudience
                InternalMessage    = $internalPlain
                ExternalMessage    = $externalPlain
            })
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-MailboxAutoReply" -Completed
    Write-Verbose "Found $($report.Count) mailbox(es) matching the report criteria."

    if ($report.Count -eq 0)
    {
        Write-Host "No mailboxes found matching the specified criteria." -ForegroundColor Yellow
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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "MailboxAutoReply_$timestamp.csv"
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
