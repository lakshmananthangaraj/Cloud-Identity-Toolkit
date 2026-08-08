<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Displays mailbox permissions (SendAs, SendOnBehalf, FullAccess) across
    Exchange Online for audit and compliance review.

.DESCRIPTION
    Enumerates mailboxes (optionally scoped by identity or recipient type)
    and reports every non-self, non-inherited FullAccess, SendAs, and
    SendOnBehalf delegate grant as a separate row. Intended as a
    point-in-time access review artifact for security/compliance audits.
    Always returns full result objects to the console/pipeline; CSV export
    is optional. Per-mailbox failures are logged as warnings and do not
    abort the run.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (MailboxPermissions_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\mailboxpermissions.csv'): the parent
        folder must already exist; the file itself is created/overwritten
        as given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER Identity
    Optional. One or more mailbox identities (SMTP address, alias, or
    display name) to scope the audit to. Defaults to all mailboxes.

.PARAMETER RecipientTypeDetailsFilter
    Optional. Restrict the audit to one or more recipient type details
    (e.g. UserMailbox, SharedMailbox). Ignored if -Identity is supplied.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per delegate permission grant. Always
    returned to the console/pipeline; also written to CSV when -OutputPath
    is supplied.

.EXAMPLE
    Get-MailboxPermissions

    Audits FullAccess/SendAs/SendOnBehalf permissions across all mailboxes,
    returned to the console/pipeline only - no CSV written.

.EXAMPLE
    Get-MailboxPermissions -Identity "mailbox@contoso.com"

    Audits FullAccess/SendAs/SendOnBehalf permissions on specific mailboxes/identity,
    returned to the console/pipeline only - no CSV written.

.EXAMPLE
    Get-MailboxPermissions -OutputPath 'C:\Reports'

    Audits all mailboxes and additionally exports to
    C:\Reports\MailboxPermissions_<timestamp>.csv

.EXAMPLE
    Get-MailboxPermissions -OutputPath 'C:\Reports\mailboxpermissions.csv' -RecipientTypeDetailsFilter 'UserMailbox' -Verbose

    Audits only user mailboxes, with verbose progress output, and exports to
    the exact file C:\Reports\mailboxpermissions.csv (no timestamp appended).

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
    - "SELF" and inherited permission entries are excluded as noise
    - Group-based delegate access is reported as the group object, not
      expanded to individual group members
    - Large tenants may take significant time; consider scoping with
      -RecipientTypeDetailsFilter or -Identity for faster targeted audits

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailboxpermission

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-recipientpermission

#>


Function Get-MailboxPermissions
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
    Write-Progress -Activity "Get-MailboxPermissions" -Status "Resolving mailbox scope..." -PercentComplete 0

    try
    {
        if ($Identity)
        {
            $targetMailboxes = foreach ($id in $Identity)
            {
                Get-EXOMailbox -Identity $id -ErrorAction Stop -Properties DisplayName,PrimarySmtpAddress,RecipientTypeDetails,GrantSendOnBehalfTo
            }
        }
        else
        {
            $getParams = @{ ResultSize = 'Unlimited'; ErrorAction = 'Stop'; Properties = @('DisplayName','PrimarySmtpAddress','RecipientTypeDetails','GrantSendOnBehalfTo') }
            $targetMailboxes = Get-EXOMailbox @getParams
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

    Write-Verbose "Auditing permissions for $($targetMailboxes.Count) mailbox(es)."

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

    foreach ($mbx in $targetMailboxes)
    {
        $counter++
        Write-Progress -Activity "Get-MailboxPermissions" -Status "Auditing $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            # FullAccess
            $fullAccess = Get-EXOMailboxPermission -Identity $mbx.PrimarySmtpAddress -ErrorAction Stop |
                Where-Object { $_.User -notlike 'NT AUTHORITY\SELF' -and $_.AccessRights -contains 'FullAccess' -and -not $_.IsInherited }
            foreach ($entry in $fullAccess)
            {
                $report.Add([PSCustomObject]@{
                    MailboxDisplayName = $mbx.DisplayName
                    MailboxSmtp        = $mbx.PrimarySmtpAddress
                    RecipientType      = $mbx.RecipientTypeDetails
                    Trustee            = $entry.User
                    PermissionType     = 'FullAccess'
                })
            }

            # SendAs
            $sendAs = Get-RecipientPermission -Identity $mbx.PrimarySmtpAddress -ErrorAction Stop |
                Where-Object { $_.Trustee -notlike 'NT AUTHORITY\SELF' }
            foreach ($entry in $sendAs)
            {
                $report.Add([PSCustomObject]@{
                    MailboxDisplayName = $mbx.DisplayName
                    MailboxSmtp        = $mbx.PrimarySmtpAddress
                    RecipientType      = $mbx.RecipientTypeDetails
                    Trustee            = $entry.Trustee
                    PermissionType     = 'SendAs'
                })
            }

            # SendOnBehalf
            if ($mbx.GrantSendOnBehalfTo)
            {
                foreach ($delegate in $mbx.GrantSendOnBehalfTo)
                {
                    $report.Add([PSCustomObject]@{
                        MailboxDisplayName = $mbx.DisplayName
                        MailboxSmtp        = $mbx.PrimarySmtpAddress
                        RecipientType      = $mbx.RecipientTypeDetails
                        Trustee            = $delegate
                        PermissionType     = 'SendOnBehalf'
                    })
                }
            }

            if (-not $fullAccess -and -not $sendAs -and -not $mbx.GrantSendOnBehalfTo)
            {
                $report.Add([PSCustomObject]@{
                    MailboxDisplayName = $mbx.DisplayName
                    MailboxSmtp        = $mbx.PrimarySmtpAddress
                    RecipientType      = $mbx.RecipientTypeDetails
                    Trustee            = '(none)'
                    PermissionType     = '(none)'
                })
            }
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-MailboxPermissions" -Completed
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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "MailboxPermissions_$timestamp.csv"
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
