<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Retrieves usage statistics (size, item count, last logon) for Exchange
    Online mailboxes.

.DESCRIPTION
    Enumerates mailboxes (optionally scoped by identity or recipient type)
    and pulls per-mailbox statistics - total item size, item count, last
    logon time, and deleted item size - for storage management, activity
    monitoring, and capacity planning. Always returns full result objects
    to the console/pipeline; CSV export is optional. Per-mailbox failures
    are logged as warnings and do not abort the run.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (MailboxStatistics_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\mailboxstatistics.csv'): the parent
        folder must already exist; the file itself is created/overwritten
        as given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER Identity
    Optional. One or more mailbox identities (SMTP address, alias, or
    display name) to scope the report to. Defaults to all mailboxes.

.PARAMETER RecipientTypeDetailsFilter
    Optional. Restrict the report to one or more recipient type details
    (e.g. UserMailbox, SharedMailbox). Ignored if -Identity is supplied.

.PARAMETER InactiveDaysThreshold
    Optional. Number of days since last logon used to flag a mailbox as
    "Inactive" in the IsInactive column. Defaults to 90.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per mailbox, containing usage
    statistics. Always returned to the console/pipeline; also written to
    CSV when -OutputPath is supplied.

.EXAMPLE
    Get-MailboxStatistics

    Returns usage statistics for all mailboxes using the default 90-day
    inactivity threshold, to the console/pipeline only - no CSV written.

.EXAMPLE
    Get-MailboxStatistics -Identity "mailbox@contoso.com"

    Returns usage statistics for the specified mailbox using the default
    90-day inactivity threshold. Results are returned to the console/pipeline
    only; no CSV file is written.
    
.EXAMPLE
    Get-MailboxStatistics -OutputPath 'C:\Reports'

    Returns usage statistics for all mailboxes and additionally exports to
    C:\Reports\MailboxStatistics_<timestamp>.csv

.EXAMPLE
    Get-MailboxStatistics -OutputPath 'C:\Reports\mailboxstatistics.csv' -RecipientTypeDetailsFilter 'UserMailbox' -InactiveDaysThreshold 60

    Returns statistics for user mailboxes only, flagging anything not
    logged into within 60 days as inactive, and exports to the exact file
    C:\Reports\mailboxstatistics.csv (no timestamp appended).

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
       Get-EXOMailbox and Get-EXOMailboxStatistics
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - LastLogonTime can be $null for mailboxes never accessed; these are
      always flagged as inactive regardless of threshold
    - TotalItemSize is parsed to MB for easier CSV sorting/filtering; raw
      value is not preserved in the report
    - Statistics reflect the last replication cycle, not real-time state

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailboxstatistics

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailbox

#>


Function Get-MailboxStatistics
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
        [string[]]$RecipientTypeDetailsFilter,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1,3650)]
        [int]$InactiveDaysThreshold = 90
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

    #region Enumerate target mailboxes
    Write-Progress -Activity "Get-MailboxStatistics" -Status "Resolving mailbox scope..." -PercentComplete 0

    try
    {
        if ($Identity)
        {
            $targetMailboxes = foreach ($id in $Identity)
            {
                Get-EXOMailbox -Identity $id -ErrorAction Stop -Properties DisplayName,PrimarySmtpAddress,RecipientTypeDetails
            }
        }
        else
        {
            $targetMailboxes = Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop `
                -Properties DisplayName,PrimarySmtpAddress,RecipientTypeDetails
            if ($RecipientTypeDetailsFilter)
            {
                $targetMailboxes = $targetMailboxes | Where-Object { $_.RecipientTypeDetails -in $RecipientTypeDetailsFilter }
            }
        }
    }
    catch
    {
        Write-Error "Failed to retrieve mailbox scope: $($_.Exception.Message)"
        return
    }

    Write-Verbose "Retrieving statistics for $($targetMailboxes.Count) mailbox(es)."

    if (-not $targetMailboxes -or $targetMailboxes.Count -eq 0)
    {
        Write-Host "No mailboxes found in the resolved scope." -ForegroundColor Yellow
        return
    }
    #endregion

    #region Build report rows
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $targetMailboxes.Count
    $counter = 0
    $now     = Get-Date

    foreach ($mbx in $targetMailboxes)
    {
        $counter++
        Write-Progress -Activity "Get-MailboxStatistics" -Status "Processing $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $stats = Get-EXOMailboxStatistics -Identity $mbx.PrimarySmtpAddress -ErrorAction Stop `
                -Properties TotalItemSize,ItemCount,LastLogonTime,TotalDeletedItemSize,DeletedItemCount

            $sizeMb = $null
            if ($stats.TotalItemSize)
            {
                # TotalItemSize format: "1.23 GB (1,234,567 bytes)" - extract the raw byte count
                if ($stats.TotalItemSize.ToString() -match '\(([\d,]+)\s+bytes\)')
                {
                    $sizeMb = [Math]::Round(([int64]($matches[1] -replace ',','')) / 1MB, 2)
                }
            }

            $daysSinceLogon = if ($stats.LastLogonTime) { ($now - $stats.LastLogonTime).Days } else { $null }
            $isInactive = (-not $stats.LastLogonTime) -or ($daysSinceLogon -ge $InactiveDaysThreshold)

            $report.Add([PSCustomObject]@{
                DisplayName          = $mbx.DisplayName
                PrimarySmtpAddress   = $mbx.PrimarySmtpAddress
                RecipientType        = $mbx.RecipientTypeDetails
                TotalItemSizeMB      = $sizeMb
                ItemCount            = $stats.ItemCount
                LastLogonTime        = $stats.LastLogonTime
                DaysSinceLastLogon   = $daysSinceLogon
                IsInactive           = $isInactive
                DeletedItemCount     = $stats.DeletedItemCount
            })
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-MailboxStatistics" -Completed
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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "MailboxStatistics_$timestamp.csv"
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
