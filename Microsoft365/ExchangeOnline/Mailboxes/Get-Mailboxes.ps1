<#

Author       : Lakshmanan Thangaraj
Version      : 1.1
Created-On   : 30 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Retrieves all mailboxes in Exchange Online with core inventory properties.

.DESCRIPTION
    Connects to (or reuses) an existing Exchange Online PowerShell session and
    enumerates all mailboxes, capturing identity, type, usage location,
    primary SMTP/alias/UPN, all proxy addresses, and archive/litigation-hold
    state. Always returns full mailbox objects to the console/pipeline;
    CSV export is optional. Designed to run independently or as the first
    step in a larger inventory pipeline (see Get-SharedMailboxes.ps1,
    Get-MailboxPermissions.ps1, Get-MailboxStatistics.ps1).

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (Mailboxes_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\mailboxes.csv'): the parent
        folder must already exist; the file itself is created/overwritten
        as given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER RecipientTypeDetailsFilter
    Optional. Restrict results to one or more recipient type details
    (e.g. UserMailbox, SharedMailbox, RoomMailbox, EquipmentMailbox).
    Defaults to all mailbox types.

.PARAMETER IncludeInactiveMailboxes
    Optional switch. Include soft-deleted / inactive (litigation-hold
    retained) mailboxes in the results.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per mailbox, containing identity,
    type, addressing, and hold/archive attributes. Always returned to the
    console/pipeline; also written to CSV when -OutputPath is supplied.

.EXAMPLE
    Get-Mailboxes

    Returns all mailboxes to the console/pipeline, no CSV written.

.EXAMPLE
    Get-Mailboxes -OutputPath 'C:\Reports'

    Returns all mailboxes and additionally exports to
    C:\Reports\Mailboxes_<timestamp>.csv

.EXAMPLE
    Get-Mailboxes -OutputPath 'C:\Reports\mailboxes.csv'

    Returns all mailboxes and exports to the exact file
    C:\Reports\mailboxes.csv (no timestamp appended).

.EXAMPLE
    Get-Mailboxes -RecipientTypeDetailsFilter 'UserMailbox','SharedMailbox' -Verbose

    Returns only user and shared mailboxes, with verbose diagnostic output,
    no CSV written.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.1 (31-Jul-2026) - Made -OutputPath optional (console/pipeline output is
                         now always returned regardless of export); expanded
                         captured properties to include ExternalDirectoryObjectId,
                         UserPrincipalName, Alias, EmailAddresses, RecipientType,
                         Identity, Id, ExchangeVersion, Name, DistinguishedName,
                         OrganizationId, and Guid; removed narrow Format-Table
                         projection on return so full objects are usable
    1.0 (30-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. ExchangeOnlineManagement module (v3.x recommended) installed
    2. An active Connect-ExchangeOnline session (or sufficient role, e.g.
       View-Only Recipients, to run Get-EXOMailbox)
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Does not include on-premises (hybrid) mailbox objects
    - Large tenants (50k+ mailboxes) may take several minutes to enumerate;
      consider running during off-peak hours - and console output on very
      large result sets can be slow to render/scroll; pipe to
      Out-GridView or use -OutputPath for large tenants instead of
      reading directly off the console
    - ProhibitSendQuota / usage figures are not returned here - see
      Get-MailboxStatistics.ps1 for size and activity data

.LINK
    https://learn.microsoft.com/en-us/powershell/module/exchange/get-exomailbox

.LINK
    https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell

#>


Function Get-Mailboxes
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
        [ValidateSet('UserMailbox','SharedMailbox','RoomMailbox','EquipmentMailbox','DiscoveryMailbox','TeamMailbox')]
        [string[]]$RecipientTypeDetailsFilter,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeInactiveMailboxes
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
    Write-Progress -Activity "Get-Mailboxes" -Status "Retrieving mailbox list..." -PercentComplete 0

    $getParams = @{
        ResultSize  = 'Unlimited'
        ErrorAction = 'Stop'
    }
    if ($IncludeInactiveMailboxes) { $getParams['IncludeInactiveMailbox'] = $true }

    try
    {
        $allMailboxes = Get-EXOMailbox @getParams -Properties DisplayName,UserPrincipalName,Alias,EmailAddresses,
            PrimarySmtpAddress,RecipientType,RecipientTypeDetails,ExternalDirectoryObjectId,UsageLocation,
            ArchiveStatus,LitigationHoldEnabled,WhenCreated,IsInactiveMailbox,HiddenFromAddressListsEnabled
    }
    catch
    {
        Write-Error "Failed to retrieve mailboxes: $($_.Exception.Message)"
        return
    }

    if ($RecipientTypeDetailsFilter)
    {
        $allMailboxes = $allMailboxes | Where-Object { $_.RecipientTypeDetails -in $RecipientTypeDetailsFilter }
    }

    Write-Verbose "Retrieved $($allMailboxes.Count) mailbox object(s) after filtering."
    #endregion

    #region Build report rows
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $allMailboxes.Count
    $counter = 0

    foreach ($mbx in $allMailboxes)
    {
        $counter++
        Write-Progress -Activity "Get-Mailboxes" -Status "Processing $($mbx.PrimarySmtpAddress)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $report.Add([PSCustomObject]@{
                ExternalDirectoryObjectId = $mbx.ExternalDirectoryObjectId
                UserPrincipalName         = $mbx.UserPrincipalName
                Alias                     = $mbx.Alias
                DisplayName               = $mbx.DisplayName
                EmailAddresses            = ($mbx.EmailAddresses -join '; ')
                PrimarySmtpAddress        = $mbx.PrimarySmtpAddress
                RecipientType             = $mbx.RecipientType
                RecipientTypeDetails      = $mbx.RecipientTypeDetails
                Identity                  = $mbx.Identity
                Id                        = $mbx.Id
                ExchangeVersion           = $mbx.ExchangeVersion
                Name                      = $mbx.Name
                DistinguishedName         = $mbx.DistinguishedName
                OrganizationId            = $mbx.OrganizationId
                Guid                      = $mbx.Guid
                UsageLocation             = $mbx.UsageLocation
                ArchiveStatus             = $mbx.ArchiveStatus
                LitigationHoldEnabled     = $mbx.LitigationHoldEnabled
                HiddenFromGAL             = $mbx.HiddenFromAddressListsEnabled
                IsInactiveMailbox         = $mbx.IsInactiveMailbox
                WhenCreated               = $mbx.WhenCreated
            })
        }
        catch
        {
            Write-Warning "Skipped mailbox '$($mbx.PrimarySmtpAddress)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-Mailboxes" -Completed
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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "Mailboxes_$timestamp.csv"
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
    # this as a per-mailbox list on screen (>4 properties), while still being
    # fully usable if captured into a variable or piped further.
    return $report
}
