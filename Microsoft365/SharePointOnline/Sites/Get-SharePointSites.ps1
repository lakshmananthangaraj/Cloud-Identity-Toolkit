<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 31 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Lists all SharePoint Online sites, including communication sites and
    team sites.

.DESCRIPTION
    Connects to the SharePoint Online tenant admin center via PnP PowerShell
    and enumerates all site collections, capturing URL, title, template/site
    type, primary owner, storage usage, sharing capability, and hub/lock
    state. Serves as the foundation for SharePoint governance and inventory
    automation (feeds Get-SitePermissions, Get-SiteOwners, and
    Get-ExternalSharing). Always returns full report objects to the
    console/pipeline; CSV export is optional.

.PARAMETER TenantAdminUrl
    Mandatory. The SharePoint Online tenant admin center URL, e.g.
    'https://contoso-admin.sharepoint.com'.

.PARAMETER ClientId
    Optional. Azure AD application (client) ID used for authentication.
    Defaults to the well-known "PnP Management Shell" multi-tenant app ID.
    Requires a tenant admin to have run Register-PnPManagementShellAccess
    once (or use your own registered app's Client ID).

.PARAMETER Tenant
    Optional. Tenant domain (e.g. 'contoso.onmicrosoft.com'). Supply
    together with -Thumbprint to authenticate unattended via certificate
    (app-only) instead of interactive login.

.PARAMETER Thumbprint
    Optional. Certificate thumbprint (from the local certificate store)
    for app-only authentication. Supply together with -Tenant.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output.
      - Folder (e.g. 'C:\Reports'): must already exist; filename is
        auto-generated with a timestamp (Sites_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\sites.csv'): the parent folder
        must already exist; the file itself is created/overwritten as
        given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER IncludeOneDriveSites
    Optional switch. Include OneDrive for Business (personal) sites in the
    results. Excluded by default.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per site, containing site inventory
    details. Always returned to the console/pipeline; also written to CSV
    when -OutputPath is supplied.

.EXAMPLE
    Get-SharePointSites -TenantAdminUrl 'https://contoso-admin.sharepoint.com'

    Returns all communication and team sites (no OneDrive sites) to the
    console/pipeline, no CSV written.

.EXAMPLE
    Get-SharePointSites -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -OutputPath 'C:\Reports'

    Returns all sites and additionally exports to
    C:\Reports\Sites_<timestamp>.csv

.EXAMPLE
    Get-SharePointSites -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -OutputPath 'C:\Reports\sites.csv' -IncludeOneDriveSites

    Returns all sites, including OneDrive personal sites, and exports to the
    exact file C:\Reports\sites.csv (no timestamp appended).

.EXAMPLE
    Get-SharePointSites -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -Tenant 'contoso.onmicrosoft.com' -Thumbprint 'AB12CD34...' -ClientId '11111111-1111-1111-1111-111111111111' -Verbose

    Authenticates unattended via certificate (app-only) using a custom
    Azure AD app registration, with verbose diagnostic output.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (31-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. PnP.PowerShell module installed
    2. Either: Register-PnPManagementShellAccess has been run once by a
       tenant admin (for -Interactive login with the default -ClientId), or
       a custom Azure AD app registration with SharePoint admin permissions
    3. SharePoint Online Administrator (or Global Administrator) role
    4. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - SiteType is inferred from the Template property using a best-effort
      mapping; uncommon/custom templates fall back to showing the raw
      Template value
    - Does not include on-premises / hybrid SharePoint site collections
    - Large tenants (10k+ sites) may take several minutes to enumerate;
      consider running during off-peak hours and use -OutputPath rather
      than reading directly off the console for large result sets

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPTenantSite.html

.LINK
    https://pnp.github.io/powershell/articles/registerapplication.html

#>

Function Get-SharePointSites
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^https://[a-zA-Z0-9-]+-admin\.sharepoint\.com/?$')]
        [string]$TenantAdminUrl,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId = '31359c7f-bd7e-475c-86db-fdb8c937548e',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Tenant,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint,

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
        [switch]$IncludeOneDriveSites
    )

    #region Connection helper
    function Connect-ToSPO
    {
        param([Parameter(Mandatory = $true)][string]$Url)

        if ($Tenant -and $Thumbprint)
        {
            return Connect-PnPOnline -Url $Url -ClientId $ClientId -Thumbprint $Thumbprint -Tenant $Tenant -ReturnConnection -ErrorAction Stop
        }
        else
        {
            return Connect-PnPOnline -Url $Url -ClientId $ClientId -Interactive -ReturnConnection -ErrorAction Stop
        }
    }
    #endregion

    #region Connection check (Tenant Admin)
    try
    {
        Write-Verbose "Connecting to tenant admin center '$TenantAdminUrl'..."
        $adminConn = Connect-ToSPO -Url $TenantAdminUrl
    }
    catch
    {
        Write-Error "Failed to connect to SharePoint Online admin center '$TenantAdminUrl': $($_.Exception.Message)"
        return
    }
    #endregion

    #region Enumerate sites
    Write-Progress -Activity "Get-SharePointSites" -Status "Retrieving site list..." -PercentComplete 0
    try
    {
        $allSites = Get-PnPTenantSite -Detailed -IncludeOneDriveSites:$IncludeOneDriveSites -Connection $adminConn -ErrorAction Stop
    }
    catch
    {
        Write-Error "Failed to retrieve tenant site list: $($_.Exception.Message)"
        return
    }
    Write-Verbose "Retrieved $($allSites.Count) site(s)."
    #endregion

    #region Build report rows
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $allSites.Count
    $counter = 0

    foreach ($site in $allSites)
    {
        $counter++
        Write-Progress -Activity "Get-SharePointSites" -Status "Processing $($site.Url)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $siteType = switch -Regex ($site.Template)
            {
                '^SITEPAGEPUBLISHING#0' { 'Communication Site'; break }
                '^GROUP#0'              { 'Team Site (Microsoft 365 Group-connected)'; break }
                '^STS#3'                { 'Team Site (no Microsoft 365 Group)'; break }
                '^TEAMCHANNEL#'         { 'Team Channel Site'; break }
                '^SPSPERS'              { 'OneDrive (Personal Site)'; break }
                default                 { "Other ($($site.Template))" }
            }

            $report.Add([PSCustomObject]@{
                Title                   = $site.Title
                Url                     = $site.Url
                SiteType                = $siteType
                Template                = $site.Template
                Owner                   = $site.Owner
                StorageUsageCurrentMB   = $site.StorageUsageCurrent
                StorageQuotaMB          = $site.StorageQuota
                SharingCapability       = $site.SharingCapability
                LastContentModifiedDate = $site.LastContentModifiedDate
                LockState               = $site.LockState
                IsHubSite               = $site.IsHubSite
                GroupId                 = $site.GroupId
            })
        }
        catch
        {
            Write-Warning "Skipped site '$($site.Url)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-SharePointSites" -Completed
    Write-Verbose "Built report for $($report.Count) site(s)."

    if ($report.Count -eq 0)
    {
        Write-Host "No sites were found for the specified criteria." -ForegroundColor Yellow
    }
    #endregion

    #region Export (optional)
    if ($OutputPath)
    {
        if ([System.IO.Path]::GetExtension($OutputPath) -eq '.csv')
        {
            $outFile = $OutputPath
        }
        else
        {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $outFile   = Join-Path -Path $OutputPath -ChildPath "Sites_$timestamp.csv"
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
