<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Lists delegated mailbox access across Exchange Online.

.DESCRIPTION
    Reports who can access another user's mailbox, combining FullAccess
    and SendOnBehalf delegate grants with Calendar folder delegate
    permissions (e.g. Editor, Reviewer, Author). This is complementary to
    Get-MailboxPermissions.ps1 (which covers the broader FullAccess/SendAs/
    SendOnBehalf audit); this script is scoped specifically to "who can act
    as or see into this person's mailbox/calendar," which is the common
    delegate-access verification scenario (e.g. EA/manager delegation).
    Always returns full result objects to the console/pipeline; CSV export
    is optional.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (MailboxDelegates_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\mailboxdelegates.csv'): the parent
        folder must already exist; the file itself is created/overwritten
        as given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER Identity
    Optional. One or more mailbox identities to scope the report to.
    Defaults to all user mailboxes.

.PARAMETER IncludeCalendarDelegates
    Optional switch. Also reports Calendar folder permissions granted to
    users other than Default/Anonymous. Adds one extra call per mailbox.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per delegate grant (mailbox-level or
    calendar-level). Always returned to the console/pipeline; also written
    to CSV when -OutputPath is supplied.

.EXAMPLE
    Get-MailboxDelegates

    Returns FullAccess/SendOnBehalf delegates for all user mailboxes to the
    console/pipeline only - no CSV written, no calendar delegates included.

.EXAMPLE
    Get-MailboxDelegates -OutputPath 'C:\Reports'

    Same scope as above, and additionally exports to
    C:\Reports\MailboxDelegates_<timestamp>.csv

.EXAMPLE
    Get-MailboxDelegates -OutputPath 'C:\Reports\mailboxdelegates.csv'

    Same scope as above, and exports to the exact file
    C:\Reports\mailboxdelegates.csv (no timestamp appended).

.EXAMPLE
    Get-MailboxDelegates -Identity 'manager@contoso.com','ea@contoso.com'

    Returns FullAccess/SendOnBehalf delegates for only the two specified
    mailboxes, to the console/pipeline only.

.EXAMPLE
    Get-MailboxDelegates -IncludeCalendarDelegates

    Returns FullAccess/SendOnBehalf delegates plus calendar folder delegates
    for all user mailboxes, to the console/pipeline only.

.EXAMPLE
    Get-MailboxDelegates -OutputPath 'C:\Reports' -Identity 'manager@contoso.com' -IncludeCalendarDelegates

    Reports FullAccess/SendOnBehalf delegates plus calendar delegates for
    the specified mailbox only, and exports to
    C:\Reports\MailboxDelegates_<timestamp>.csv

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
       Get-EXOMailbox, Get-EXOMailboxPermission, and (if
       -IncludeCalendarDelegates) Get-MailboxFolderPermission
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Calendar folder name is localized (e.g. "Calendar" vs "Kalender");
      script resolves the folder via the mailbox's own folder statistics
      rather than assuming an English name
    - Group-based delegate access is reported as the group object, not
      expanded to individual members
    - SendAs is intentionally excluded here (see Get-MailboxPermissions.ps1
      for the full SendAs/FullAccess/SendOnBehalf compliance audit)

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailboxpermission

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-mailboxfolderpermission

#>


Function Get-MailboxDelegates
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
        [switch]$IncludeCalendarDelegates
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
    Write-Progress -Activity "Get-MailboxDelegates" -Status "Retrieving mailbox list..." -PercentComplete 0
    try
    {
        if ($Identity)
        {
            $mailboxes = foreach ($id in $Identity) { Get-EXOMailbox -Identity $id -ErrorAction Stop `
                -Properties DisplayName,PrimarySmtpAddress,GrantSendOnBehalfTo }
        }
        else
        {
            $mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -ErrorAction Stop `
                -Properties DisplayName,PrimarySmtpAddress,GrantSendOnBehalfTo
        }
    }
    catch
    {
        Write-Error "Failed to retrieve mailboxes: $($_.Exception.Message)"
        return
    }
    Write-Verbose "Evaluating delegates for $($mailboxes.Count) mailbox(es)."

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
        Write-Progress -Activity "Get-MailboxDelegates" -Status "Processing $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $fullAccess = Get-EXOMailboxPermission -Identity $mbx.PrimarySmtpAddress -ErrorAction Stop |
                Where-Object { $_.User -notlike 'NT AUTHORITY\SELF' -and $_.AccessRights -contains 'FullAccess' -and -not $_.IsInherited }

            foreach ($entry in $fullAccess)
            {
                $report.Add([PSCustomObject]@{
                    MailboxDisplayName = $mbx.DisplayName
                    MailboxSmtp        = $mbx.PrimarySmtpAddress
                    Delegate           = $entry.User
                    DelegateScope      = 'FullAccess (entire mailbox)'
                })
            }

            if ($mbx.GrantSendOnBehalfTo)
            {
                foreach ($delegate in $mbx.GrantSendOnBehalfTo)
                {
                    $report.Add([PSCustomObject]@{
                        MailboxDisplayName = $mbx.DisplayName
                        MailboxSmtp        = $mbx.PrimarySmtpAddress
                        Delegate           = $delegate
                        DelegateScope      = 'SendOnBehalf'
                    })
                }
            }

            if ($IncludeCalendarDelegates)
            {
                try
                {
                    $calendarFolder = (Get-EXOMailboxFolderStatistics -Identity $mbx.PrimarySmtpAddress -FolderScope Calendar -ErrorAction Stop |
                        Select-Object -First 1).Name

                    if ($calendarFolder)
                    {
                        $calPerms = Get-MailboxFolderPermission -Identity "$($mbx.PrimarySmtpAddress):\$calendarFolder" -ErrorAction Stop |
                            Where-Object { $_.User.DisplayName -notin @('Default','Anonymous') }

                        foreach ($perm in $calPerms)
                        {
                            $report.Add([PSCustomObject]@{
                                MailboxDisplayName = $mbx.DisplayName
                                MailboxSmtp        = $mbx.PrimarySmtpAddress
                                Delegate           = $perm.User.DisplayName
                                DelegateScope      = "Calendar ($($perm.AccessRights -join ','))"
                            })
                        }
                    }
                }
                catch
                {
                    Write-Warning "Could not read calendar permissions for '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
                }
            }
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-MailboxDelegates" -Completed

    if ($report.Count -eq 0)
    {
        Write-Host "No delegate access (FullAccess, SendOnBehalf, or Calendar) was found for the resolved scope." -ForegroundColor Yellow
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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "MailboxDelegates_$timestamp.csv"
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
