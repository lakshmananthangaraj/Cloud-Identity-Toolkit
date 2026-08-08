<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Lists shared mailboxes in Exchange Online with their members and permissions.

.DESCRIPTION
    Enumerates all shared mailboxes and, for each one, resolves FullAccess and
    SendAs delegate members. Builds one row per (mailbox, delegate,
    permission type) combination so the report can be filtered/pivoted easily
    for access reviews. Always returns full result objects to the
    console/pipeline; CSV export is optional. Skips per-mailbox failures
    rather than aborting the full run.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (SharedMailboxes_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\sharedmailboxes.csv'): the parent
        folder must already exist; the file itself is created/overwritten
        as given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER Identity
    Optional. One or more shared mailbox identities (SMTP address, alias, or
    display name) to scope the report to. Defaults to all shared mailboxes
    in the tenant.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per (mailbox, delegate, permission type)
    combination. Always returned to the console/pipeline; also written to
    CSV when -OutputPath is supplied.

.EXAMPLE
    Get-SharedMailboxes

    Returns shared mailbox membership/permission rows to the console/pipeline,
    no CSV written.

.EXAMPLE
    Get-SharedMailboxes -OutputPath 'C:\Reports'

    Returns all shared mailboxes with their members and permissions, and
    additionally exports to C:\Reports\SharedMailboxes_<timestamp>.csv

.EXAMPLE
    Get-SharedMailboxes -OutputPath 'C:\Reports\sharedmailboxes.csv' -Identity 'sales@contoso.com','hr@contoso.com'

    Returns permission details only for the two specified shared mailboxes,
    and exports to the exact file C:\Reports\sharedmailboxes.csv (no
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
       Get-EXOMailbox, Get-EXOMailboxPermission, Get-RecipientPermission
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - "SELF" permission entries (default Outlook self-access) are excluded
      from output as noise
    - Nested/group-based delegate access is reported as the group object,
      not expanded to individual group members
    - Does not report SendOnBehalf beyond what Get-EXOMailbox exposes
    - Large tenants with many shared mailboxes may take a while to enumerate;
      console output on very large result sets can be slow to render/scroll -
      pipe to Out-GridView or use -OutputPath for large tenants instead of
      reading directly off the console

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailboxpermission

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-recipientpermission

#>


Function Get-SharedMailboxes
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

    #region Enumerate shared mailboxes
    Write-Progress -Activity "Get-SharedMailboxes" -Status "Retrieving shared mailbox list..." -PercentComplete 0

    try
    {
        if ($Identity)
        {
            $sharedMailboxes = foreach ($id in $Identity)
            {
                Get-EXOMailbox -Identity $id -ErrorAction Stop -Properties DisplayName,PrimarySmtpAddress,RecipientTypeDetails |
                    Where-Object { $_.RecipientTypeDetails -eq 'SharedMailbox' }
            }
        }
        else
        {
            $sharedMailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails SharedMailbox -ErrorAction Stop `
                -Properties DisplayName,PrimarySmtpAddress,RecipientTypeDetails
        }
    }
    catch
    {
        Write-Error "Failed to retrieve shared mailboxes: $($_.Exception.Message)"
        return
    }

    Write-Verbose "Retrieved $($sharedMailboxes.Count) shared mailbox object(s)."

    if (-not $sharedMailboxes -or $sharedMailboxes.Count -eq 0)
    {
        Write-Host "No shared mailboxes found in this environment/scope." -ForegroundColor Yellow
        return
    }
    #endregion

    #region Build report rows
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $sharedMailboxes.Count
    $counter = 0

    foreach ($mbx in $sharedMailboxes)
    {
        $counter++
        Write-Progress -Activity "Get-SharedMailboxes" -Status "Processing $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            # FullAccess delegates
            $fullAccessEntries = Get-EXOMailboxPermission -Identity $mbx.PrimarySmtpAddress -ErrorAction Stop |
                Where-Object { $_.User -notlike 'NT AUTHORITY\SELF' -and $_.AccessRights -contains 'FullAccess' -and -not $_.IsInherited }

            foreach ($entry in $fullAccessEntries)
            {
                $report.Add([PSCustomObject]@{
                    MailboxDisplayName = $mbx.DisplayName
                    MailboxSmtp        = $mbx.PrimarySmtpAddress
                    Delegate           = $entry.User
                    PermissionType     = 'FullAccess'
                    AutoMapping        = $entry.IsInherited
                })
            }

            # SendAs delegates
            $sendAsEntries = Get-RecipientPermission -Identity $mbx.PrimarySmtpAddress -ErrorAction Stop |
                Where-Object { $_.Trustee -notlike 'NT AUTHORITY\SELF' }

            foreach ($entry in $sendAsEntries)
            {
                $report.Add([PSCustomObject]@{
                    MailboxDisplayName = $mbx.DisplayName
                    MailboxSmtp        = $mbx.PrimarySmtpAddress
                    Delegate           = $entry.Trustee
                    PermissionType     = 'SendAs'
                    AutoMapping        = $null
                })
            }

            if (-not $fullAccessEntries -and -not $sendAsEntries)
            {
                $report.Add([PSCustomObject]@{
                    MailboxDisplayName = $mbx.DisplayName
                    MailboxSmtp        = $mbx.PrimarySmtpAddress
                    Delegate           = '(none)'
                    PermissionType     = '(none)'
                    AutoMapping        = $null
                })
            }
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-SharedMailboxes" -Completed
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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "SharedMailboxes_$timestamp.csv"
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

    # Always return full objects - PowerShell's default formatter will render
    # this as a per-row list on screen (>4 properties), while still being
    # fully usable if captured into a variable or piped further.
    return $report
}
