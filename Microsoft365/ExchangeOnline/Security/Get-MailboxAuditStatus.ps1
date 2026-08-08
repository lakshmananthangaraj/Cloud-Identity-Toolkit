<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Shows whether mailbox auditing is enabled across Exchange Online.

.DESCRIPTION
    Reports per-mailbox audit configuration - whether auditing is enabled,
    the configured audit log retention age, and which owner/delegate/admin
    actions are being audited - to support compliance and security
    monitoring reviews. Also flags mailboxes relying solely on the
    organization-wide default (AuditEnabled not explicitly set) versus an
    explicit per-mailbox override. Always returns full result objects to
    the console/pipeline; CSV export is optional.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (MailboxAuditStatus_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\mailboxauditstatus.csv'): the parent
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
    An array of custom objects, one per mailbox, containing audit
    configuration. Always returned to the console/pipeline; also written
    to CSV when -OutputPath is supplied.

.EXAMPLE
    Get-MailboxAuditStatus

    Reports audit configuration for all mailboxes in the tenant, to the
    console/pipeline only - no CSV written.

.EXAMPLE
    Get-MailboxAuditStatus -OutputPath 'C:\Reports'

    Same scope as above, and additionally exports to
    C:\Reports\MailboxAuditStatus_<timestamp>.csv

.EXAMPLE
    Get-MailboxAuditStatus -OutputPath 'C:\Reports\mailboxauditstatus.csv'

    Same scope as above, and exports to the exact file
    C:\Reports\mailboxauditstatus.csv (no timestamp appended).

.EXAMPLE
    Get-MailboxAuditStatus -Identity 'sales@contoso.com','hr@contoso.com'

    Reports audit configuration only for the two specified mailboxes, to
    the console/pipeline only.

.EXAMPLE
    Get-MailboxAuditStatus -RecipientTypeDetailsFilter 'UserMailbox'

    Reports audit configuration for user mailboxes only, to the
    console/pipeline only.

.EXAMPLE
    Get-MailboxAuditStatus -OutputPath 'C:\Reports' -RecipientTypeDetailsFilter 'SharedMailbox' -Verbose

    Reports audit configuration for shared mailboxes only, with verbose
    progress output, and exports to
    C:\Reports\MailboxAuditStatus_<timestamp>.csv

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
       Get-EXOMailbox and Get-OrganizationConfig
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Microsoft enabled mailbox auditing by default tenant-wide in 2019;
      AuditEnabled = $false on a mailbox is an explicit override worth
      investigating, not necessarily an oversight
    - Does not validate whether Unified Audit Log search itself is enabled
      at the tenant level - only mailbox-level audit configuration
    - Actual audit *log content* (who did what, when) is out of scope for
      this script - see Search-UnifiedAuditLog for that

.LINK
    https://learn.microsoft.com/en-us/purview/audit-mailboxes

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailbox

#>


Function Get-MailboxAuditStatus
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

    #region Tenant default (for context)
    try
    {
        $orgDefaultAuditingEnabled = (Get-OrganizationConfig -ErrorAction Stop).AuditDisabled -eq $false
    }
    catch
    {
        Write-Warning "Could not retrieve organization audit default: $($_.Exception.Message)"
        $orgDefaultAuditingEnabled = $null
    }
    #endregion

    #region Enumerate mailboxes
    Write-Progress -Activity "Get-MailboxAuditStatus" -Status "Retrieving mailbox list..." -PercentComplete 0
    try
    {
        $properties = 'DisplayName','PrimarySmtpAddress','RecipientTypeDetails','AuditEnabled','AuditLogAgeLimit',
            'AuditOwner','AuditDelegate','AuditAdmin'

        if ($Identity)
        {
            $mailboxes = foreach ($id in $Identity) { Get-EXOMailbox -Identity $id -ErrorAction Stop -Properties $properties }
        }
        else
        {
            $mailboxes = Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop -Properties $properties
            if ($RecipientTypeDetailsFilter)
            {
                $mailboxes = $mailboxes | Where-Object { $_.RecipientTypeDetails -in $RecipientTypeDetailsFilter }
            }
        }
    }
    catch
    {
        Write-Error "Failed to retrieve mailboxes: $($_.Exception.Message)"
        return
    }
    Write-Verbose "Evaluating audit configuration for $($mailboxes.Count) mailbox(es)."

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
        Write-Progress -Activity "Get-MailboxAuditStatus" -Status "Processing $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $report.Add([PSCustomObject]@{
                DisplayName             = $mbx.DisplayName
                PrimarySmtpAddress      = $mbx.PrimarySmtpAddress
                RecipientType           = $mbx.RecipientTypeDetails
                AuditEnabled            = $mbx.AuditEnabled
                EffectiveAuditingSource = if ($null -ne $mbx.AuditEnabled) { 'Explicit per-mailbox setting' } else { "Tenant default ($orgDefaultAuditingEnabled)" }
                AuditLogAgeLimit        = $mbx.AuditLogAgeLimit
                AuditOwnerActions       = ($mbx.AuditOwner -join ';')
                AuditDelegateActions    = ($mbx.AuditDelegate -join ';')
                AuditAdminActions       = ($mbx.AuditAdmin -join ';')
            })
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-MailboxAuditStatus" -Completed
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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "MailboxAuditStatus_$timestamp.csv"
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
