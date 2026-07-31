<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Lists mailboxes on Litigation Hold or In-Place Hold in Exchange Online.

.DESCRIPTION
    Connects to (or reuses) an existing Exchange Online PowerShell session and
    enumerates mailboxes, reporting LitigationHoldEnabled state (with hold
    owner/date/duration) and separately flagging any Microsoft Purview
    in-place holds (InPlaceHolds) applied to the mailbox. Only mailboxes with
    at least one hold mechanism active are included, to support legal/
    compliance hold verification. Always returns full report objects to the
    console/pipeline; CSV export is optional.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (MailboxLitigationHold_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\holds.csv'): the parent folder must
        already exist; the file itself is created/overwritten as given, with
        no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER Identity
    Optional. One or more mailbox identities to scope the report to.
    Defaults to all mailboxes.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per mailbox on hold, containing hold
    status per mailbox. Always returned to the console/pipeline; also
    written to CSV when -OutputPath is supplied.

.EXAMPLE
    Get-MailboxLitigationHold

    Returns all mailboxes currently on litigation hold or an in-place hold
    to the console/pipeline, no CSV written.

.EXAMPLE
    Get-MailboxLitigationHold -OutputPath 'C:\Reports'

    Returns all mailboxes on hold and additionally exports to
    C:\Reports\MailboxLitigationHold_<timestamp>.csv

.EXAMPLE
    Get-MailboxLitigationHold -OutputPath 'C:\Reports\holds.csv'

    Returns all mailboxes on hold and exports to the exact file
    C:\Reports\holds.csv (no timestamp appended).

.EXAMPLE
    Get-MailboxLitigationHold -Identity 'jdoe@contoso.com','shared-legal@contoso.com'

    Returns hold status for only the specified mailboxes, no CSV written.

.EXAMPLE
    Get-MailboxLitigationHold -Identity 'jdoe@contoso.com' -OutputPath 'C:\Reports' -Verbose

    Returns hold status for the specified mailbox, exports to
    C:\Reports\MailboxLitigationHold_<timestamp>.csv, with verbose
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
       Get-EXOMailbox
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - InPlaceHolds returns hold policy GUIDs, not friendly names; cross-
      reference against Get-RetentionCompliancePolicy in Security &
      Compliance PowerShell to resolve them to policy names
    - Does not report eDiscovery case-level hold associations - only the
      mailbox-side hold flags
    - A mailbox can be on hold without LitigationHoldEnabled = $true if the
      hold is applied solely via a Purview retention policy - both columns
      should be reviewed together
    - Large tenants (50k+ mailboxes) may take several minutes to enumerate;
      consider running during off-peak hours - and console output on very
      large result sets can be slow to render/scroll; pipe to
      Out-GridView or use -OutputPath for large tenants instead of
      reading directly off the console

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailbox

.LINK
    https://learn.microsoft.com/en-us/purview/create-a-litigation-hold

#>


Function Get-MailboxLitigationHold
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
        [string[]]$Identity
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
    Write-Progress -Activity "Get-MailboxLitigationHold" -Status "Retrieving mailbox list..." -PercentComplete 0
    try
    {
        $properties = 'DisplayName','PrimarySmtpAddress','RecipientTypeDetails','LitigationHoldEnabled',
            'LitigationHoldDate','LitigationHoldOwner','LitigationHoldDuration','InPlaceHolds'

        if ($Identity)
        {
            $mailboxes = foreach ($id in $Identity) { Get-EXOMailbox -Identity $id -ErrorAction Stop -Properties $properties }
        }
        else
        {
            $mailboxes = Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop -Properties $properties
        }
    }
    catch
    {
        Write-Error "Failed to retrieve mailboxes: $($_.Exception.Message)"
        return
    }
    Write-Verbose "Evaluating hold status for $($mailboxes.Count) mailbox(es)."
    #endregion

    #region Build report rows
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $mailboxes.Count
    $counter = 0

    foreach ($mbx in $mailboxes)
    {
        $counter++
        Write-Progress -Activity "Get-MailboxLitigationHold" -Status "Processing $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $hasInPlaceHold = [bool]($mbx.InPlaceHolds -and $mbx.InPlaceHolds.Count -gt 0)

            if ($mbx.LitigationHoldEnabled -or $hasInPlaceHold)
            {
                $report.Add([PSCustomObject]@{
                    DisplayName            = $mbx.DisplayName
                    PrimarySmtpAddress     = $mbx.PrimarySmtpAddress
                    RecipientType          = $mbx.RecipientTypeDetails
                    LitigationHoldEnabled  = $mbx.LitigationHoldEnabled
                    LitigationHoldDate     = $mbx.LitigationHoldDate
                    LitigationHoldOwner    = $mbx.LitigationHoldOwner
                    LitigationHoldDuration = $mbx.LitigationHoldDuration
                    InPlaceHoldCount       = $mbx.InPlaceHolds.Count
                    InPlaceHoldIdentifiers = ($mbx.InPlaceHolds -join '; ')
                })
            }
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-MailboxLitigationHold" -Completed
    Write-Verbose "Found $($report.Count) mailbox(es) with an active hold."
    #endregion

    if ($report.Count -eq 0)
    {
        Write-Host "No mailboxes found with an active litigation hold or in-place hold." -ForegroundColor Yellow
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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "MailboxLitigationHold_$timestamp.csv"
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
