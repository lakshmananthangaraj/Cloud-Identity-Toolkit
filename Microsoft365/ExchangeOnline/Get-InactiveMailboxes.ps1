<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Identifies inactive or unused mailboxes in Exchange Online.

.DESCRIPTION
    Combines two categories of "inactive" for cleanup and license
    optimization purposes:
      1. Active mailboxes with no logon within -InactiveDaysThreshold days
         (or never logged into at all).
      2. Soft-deleted mailboxes retained under a hold (in-place, litigation,
         or Microsoft 365 retention policy) - Exchange calls these
         "Inactive Mailboxes."
    Both categories consume a license or storage and are common cleanup
    candidates, but they are flagged separately in the InactiveCategory
    column so they aren't conflated during review. Always returns full
    result objects to the console/pipeline; CSV export is optional.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (InactiveMailboxes_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\inactivemailboxes.csv'): the parent
        folder must already exist; the file itself is created/overwritten
        as given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER InactiveDaysThreshold
    Optional. Number of days since last logon used to flag an active
    mailbox as unused. Defaults to 90.

.PARAMETER RecipientTypeDetailsFilter
    Optional. Restrict the scan to one or more recipient type details.
    Defaults to all mailbox types.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per flagged inactive/unused mailbox.
    Always returned to the console/pipeline; also written to CSV when
    -OutputPath is supplied.

.EXAMPLE
    Get-InactiveMailboxes

    Flags mailboxes not logged into within the default 90 days, plus all
    soft-deleted mailboxes retained under hold, to the console/pipeline
    only - no CSV written.

.EXAMPLE
    Get-InactiveMailboxes -OutputPath 'C:\Reports'

    Same scope as above, and additionally exports to
    C:\Reports\InactiveMailboxes_<timestamp>.csv

.EXAMPLE
    Get-InactiveMailboxes -OutputPath 'C:\Reports\inactivemailboxes.csv'

    Same scope as above, and exports to the exact file
    C:\Reports\inactivemailboxes.csv (no timestamp appended).

.EXAMPLE
    Get-InactiveMailboxes -InactiveDaysThreshold 60

    Flags mailboxes not logged into within 60 days, plus all soft-deleted
    mailboxes retained under hold, to the console/pipeline only.

.EXAMPLE
    Get-InactiveMailboxes -RecipientTypeDetailsFilter 'UserMailbox','SharedMailbox'

    Restricts the active-but-unused scan to user and shared mailboxes only,
    using the default 90-day threshold, to the console/pipeline only.

.EXAMPLE
    Get-InactiveMailboxes -OutputPath 'C:\Reports' -InactiveDaysThreshold 60 -RecipientTypeDetailsFilter 'UserMailbox'

    Flags user mailboxes not logged into within 60 days, plus all
    soft-deleted mailboxes retained under hold, and exports to
    C:\Reports\InactiveMailboxes_<timestamp>.csv

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
       Get-EXOMailbox (including -InactiveMailboxOnly) and
       Get-EXOMailboxStatistics
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - LastLogonTime reflects any access, including background sync clients
      (mobile/desktop) - a mailbox can appear "active" without a human
      actually reading mail
    - Soft-deleted inactive mailboxes only persist while a hold is applied;
      once the hold is removed, Exchange purges the mailbox and it will no
      longer appear here
    - License removal is not performed by this script - it is
      read/report-only by design

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailbox

.LINK
    https://learn.microsoft.com/en-us/purview/create-and-manage-inactive-mailboxes

#>


Function Get-InactiveMailboxes
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
        [ValidateRange(1,3650)]
        [int]$InactiveDaysThreshold = 90,

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

    $report = [System.Collections.Generic.List[object]]::new()
    $now    = Get-Date

    #region Category 1 - active-but-unused mailboxes
    Write-Progress -Activity "Get-InactiveMailboxes" -Status "Retrieving active mailbox list..." -PercentComplete 0
    try
    {
        $activeMailboxes = Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop `
            -Properties DisplayName,PrimarySmtpAddress,RecipientTypeDetails,WhenCreated
        if ($RecipientTypeDetailsFilter)
        {
            $activeMailboxes = $activeMailboxes | Where-Object { $_.RecipientTypeDetails -in $RecipientTypeDetailsFilter }
        }
    }
    catch
    {
        Write-Error "Failed to retrieve active mailboxes: $($_.Exception.Message)"
        return
    }

    $total = $activeMailboxes.Count
    $counter = 0
    foreach ($mbx in $activeMailboxes)
    {
        $counter++
        Write-Progress -Activity "Get-InactiveMailboxes" -Status "Checking activity: $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $stats = Get-EXOMailboxStatistics -Identity $mbx.PrimarySmtpAddress -ErrorAction Stop -Properties LastLogonTime
            $daysSinceLogon = if ($stats.LastLogonTime) { ($now - $stats.LastLogonTime).Days } else { $null }

            if (-not $stats.LastLogonTime -or $daysSinceLogon -ge $InactiveDaysThreshold)
            {
                $report.Add([PSCustomObject]@{
                    DisplayName        = $mbx.DisplayName
                    PrimarySmtpAddress = $mbx.PrimarySmtpAddress
                    RecipientType      = $mbx.RecipientTypeDetails
                    InactiveCategory   = 'Active mailbox - unused'
                    LastLogonTime      = $stats.LastLogonTime
                    DaysSinceLastLogon = $daysSinceLogon
                    WhenCreated        = $mbx.WhenCreated
                })
            }
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    #endregion

    #region Category 2 - soft-deleted mailboxes retained under hold
    Write-Progress -Activity "Get-InactiveMailboxes" -Status "Retrieving soft-deleted inactive mailboxes..." -PercentComplete 50
    try
    {
        $softDeleted = Get-EXOMailbox -InactiveMailboxOnly -ResultSize Unlimited -ErrorAction Stop `
            -Properties DisplayName,PrimarySmtpAddress,RecipientTypeDetails,WhenSoftDeleted,LitigationHoldEnabled,WhenCreated

        foreach ($mbx in $softDeleted)
        {
            try
            {
                $report.Add([PSCustomObject]@{
                    DisplayName        = $mbx.DisplayName
                    PrimarySmtpAddress = $mbx.PrimarySmtpAddress
                    RecipientType      = $mbx.RecipientTypeDetails
                    InactiveCategory   = 'Soft-deleted (retained under hold)'
                    LastLogonTime      = $null
                    DaysSinceLastLogon = $null
                    WhenCreated        = $mbx.WhenCreated
                    WhenSoftDeleted    = $mbx.WhenSoftDeleted
                    LitigationHold     = $mbx.LitigationHoldEnabled
                })
            }
            catch
            {
                Write-Warning "Skipped inactive mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
                continue
            }
        }
    }
    catch
    {
        Write-Warning "Failed to retrieve soft-deleted inactive mailboxes: $($_.Exception.Message)"
    }
    Write-Progress -Activity "Get-InactiveMailboxes" -Completed
    #endregion

    if ($report.Count -eq 0)
    {
        Write-Host "No inactive/unused mailboxes were found (neither active-but-unused nor soft-deleted-under-hold)." -ForegroundColor Yellow
        return
    }

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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "InactiveMailboxes_$timestamp.csv"
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
