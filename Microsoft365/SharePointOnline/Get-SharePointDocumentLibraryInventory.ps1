<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 31 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Reports document libraries, item counts, versioning settings, and sizes
    for SharePoint Online sites.

.DESCRIPTION
    Connects to the SharePoint Online tenant admin center via PnP PowerShell
    to resolve the target site scope, then connects to each individual site
    to enumerate document libraries, capturing item count, versioning
    configuration, and storage size (via Get-PnPFolderStorageMetric).
    Excellent for storage optimization and governance. Always returns full
    report objects to the console/pipeline; CSV export is optional.

.PARAMETER TenantAdminUrl
    Mandatory. The SharePoint Online tenant admin center URL, e.g.
    'https://contoso-admin.sharepoint.com'.

.PARAMETER SiteUrl
    Optional. One or more specific site URLs to scope the report to.
    Mutually exclusive with -All and -SiteId.

.PARAMETER SiteId
    Optional. One or more specific site GUIDs (SiteId) to scope the report
    to. Mutually exclusive with -All and -SiteUrl.

.PARAMETER ClientId
    Optional. Azure AD application (client) ID used for authentication.
    Defaults to the well-known "PnP Management Shell" multi-tenant app ID.

.PARAMETER Tenant
    Optional. Tenant domain. Supply together with -Thumbprint to
    authenticate unattended via certificate (app-only).

.PARAMETER Thumbprint
    Optional. Certificate thumbprint for app-only authentication. Supply
    together with -Tenant.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where results will
    be written, in addition to the on-screen/pipeline output. If omitted,
    results are returned to the console/pipeline only.

.PARAMETER All
    Optional switch. Scan every site in the tenant. Default behaviour when
    neither -SiteUrl nor -SiteId is supplied.

.PARAMETER IncludeOneDriveSites
    Optional switch. When using -All, include OneDrive for Business
    (personal) sites. Excluded by default.

.PARAMETER IncludeHiddenLibraries
    Optional switch. Include hidden/system document libraries in the
    report. Excluded by default.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per document library, containing
    inventory details. Always returned to the console/pipeline; also
    written to CSV when -OutputPath is supplied.

.EXAMPLE
    Get-SharePointDocumentLibraryInventory -TenantAdminUrl 'https://contoso-admin.sharepoint.com'

    Inventories document libraries across every site in the tenant.

.EXAMPLE
    Get-SharePointDocumentLibraryInventory -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -OutputPath 'C:\Reports'

    Same as above, and additionally exports to
    C:\Reports\SharePointDocumentLibraryInventory_<timestamp>.csv

.EXAMPLE
    Get-SharePointDocumentLibraryInventory -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Engineering'

    Inventories document libraries for only the specified site.

.EXAMPLE
    Get-SharePointDocumentLibraryInventory -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteId '11111111-2222-3333-4444-555555555555' -IncludeHiddenLibraries -OutputPath 'C:\Reports\eng-libraries.csv'

    Inventories document libraries (including hidden ones) for the site
    matching the specified SiteId and exports to the exact file (no
    timestamp appended).

.EXAMPLE
    Get-SharePointDocumentLibraryInventory -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -Tenant 'contoso.onmicrosoft.com' -Thumbprint 'AB12CD34...' -ClientId '11111111-1111-1111-1111-111111111111' -Verbose

    Authenticates unattended via certificate (app-only), scanning all
    sites, with verbose diagnostic output.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (31-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. PnP.PowerShell module installed
    2. Register-PnPManagementShellAccess run once (or a custom Azure AD app)
    3. SharePoint Online Administrator role, plus Site Collection
       Administrator rights on each target site
    4. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - SizeMB is computed via Get-PnPFolderStorageMetric per library; if
      that cmdlet is unavailable in your installed PnP.PowerShell version,
      SizeMB is reported as $null with a warning rather than failing the
      whole site
    - "Versions" reflects the library's versioning configuration
      (enabled/disabled and major version limit), not a per-item count of
      historical versions, which would require an expensive per-item scan
    - Large document libraries (100k+ items) may take time to enumerate

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPList.html

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPFolderStorageMetric.html

#>


Function Get-SharePointDocumentLibraryInventory
{
    [CmdletBinding(DefaultParameterSetName = 'All')]
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

        [Parameter(Mandatory = $true, ParameterSetName = 'BySiteUrl')]
        [ValidateNotNullOrEmpty()]
        [string[]]$SiteUrl,

        [Parameter(Mandatory = $true, ParameterSetName = 'BySiteId')]
        [ValidateNotNullOrEmpty()]
        [guid[]]$SiteId,

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

        [Parameter(Mandatory = $false, ParameterSetName = 'All')]
        [switch]$All,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeOneDriveSites,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeHiddenLibraries
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

    #region Connection check and scope resolution
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

    Write-Progress -Activity "Get-SharePointDocumentLibraryInventory" -Status "Resolving site scope..." -PercentComplete 0
    try
    {
        $allSites = Get-PnPTenantSite -Detailed -IncludeOneDriveSites:$IncludeOneDriveSites -Connection $adminConn -ErrorAction Stop
    }
    catch
    {
        Write-Error "Failed to retrieve tenant site list: $($_.Exception.Message)"
        return
    }

    switch ($PSCmdlet.ParameterSetName)
    {
        'BySiteUrl'
        {
            $normalized  = $SiteUrl | ForEach-Object { $_.TrimEnd('/') }
            $targetSites = $allSites | Where-Object { $normalized -contains $_.Url.TrimEnd('/') }
            foreach ($u in ($normalized | Where-Object { $_ -notin ($targetSites.Url.TrimEnd('/')) })) { Write-Warning "Site URL not found in tenant: '$u'" }
        }
        'BySiteId'
        {
            $targetSites = $allSites | Where-Object { $_.SiteId -in $SiteId }
            foreach ($id in ($SiteId | Where-Object { $_ -notin $targetSites.SiteId })) { Write-Warning "SiteId not found in tenant: '$id'" }
        }
        default { $targetSites = $allSites }
    }
    Write-Verbose "Resolved $($targetSites.Count) target site(s)."
    #endregion

    #region Build report rows
    $report      = [System.Collections.Generic.List[object]]::new()
    $totalSites  = $targetSites.Count
    $siteCounter = 0

    foreach ($site in $targetSites)
    {
        $siteCounter++
        Write-Progress -Activity "Get-SharePointDocumentLibraryInventory" -Status "Processing $($site.Url)" `
            -PercentComplete (($siteCounter / [Math]::Max($totalSites,1)) * 100)

        try
        {
            $siteConn   = Connect-ToSPO -Url $site.Url
            $libraries  = Get-PnPList -Connection $siteConn -ErrorAction Stop | Where-Object {
                $_.BaseTemplate -eq 101 -and ($IncludeHiddenLibraries -or -not $_.Hidden)
            }

            foreach ($lib in $libraries)
            {
                $sizeMB = $null
                try
                {
                    $metrics = Get-PnPFolderStorageMetric -List $lib -Connection $siteConn -ErrorAction Stop
                    if ($metrics) { $sizeMB = [Math]::Round(($metrics.TotalSize / 1MB), 2) }
                }
                catch
                {
                    Write-Warning "Could not compute size for library '$($lib.Title)' on site '$($site.Url)': $($_.Exception.Message)"
                }

                $report.Add([PSCustomObject]@{
                    SiteUrl              = $site.Url
                    SiteTitle            = $site.Title
                    LibraryTitle         = $lib.Title
                    ItemCount            = $lib.ItemCount
                    VersioningEnabled    = $lib.EnableVersioning
                    MajorVersionLimit    = $lib.MajorVersionLimit
                    SizeMB               = $sizeMB
                    LastItemModifiedDate = $lib.LastItemModifiedDate
                    IsHidden             = $lib.Hidden
                })
            }
        }
        catch
        {
            Write-Warning "Skipped site '$($site.Url)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-SharePointDocumentLibraryInventory" -Completed
    Write-Verbose "Built report with $($report.Count) library row(s) across $($targetSites.Count) site(s)."

    if ($report.Count -eq 0)
    {
        Write-Host "No document libraries were found for the specified scope." -ForegroundColor Yellow
    }
    #endregion

    #region Export (optional)
    if ($OutputPath)
    {
        if ([System.IO.Path]::GetExtension($OutputPath) -eq '.csv') { $outFile = $OutputPath }
        else
        {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $outFile   = Join-Path -Path $OutputPath -ChildPath "SharePointDocumentLibraryInventory_$timestamp.csv"
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
