<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 31 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Reports lists, libraries, and (optionally) folders with broken
    permission inheritance on SharePoint Online sites.

.DESCRIPTION
    Connects to the SharePoint Online tenant admin center via PnP PowerShell
    to resolve the target site scope, then connects to each individual site
    to identify lists and libraries with HasUniqueRoleAssignments set (i.e.
    permission inheritance from the site has been broken). Defaults to
    list/library-level scanning only, since folder-level and item-level
    scanning is significantly more expensive; -IncludeFolders opts into a
    deeper (slower) scan of folders within document libraries. One of the
    most requested governance reports. Always returns full report objects
    to the console/pipeline; CSV export is optional.

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
    neither -SiteUrl nor -SiteId is supplied. Note this is the most
    expensive report in this series when combined with -IncludeFolders -
    consider scoping to specific sites for large tenants.

.PARAMETER IncludeOneDriveSites
    Optional switch. When using -All, include OneDrive for Business
    (personal) sites. Excluded by default.

.PARAMETER IncludeFolders
    Optional switch. Also scan folders within document libraries for
    broken inheritance, in addition to the default list/library level.
    Significantly increases runtime on libraries with many folders.

.PARAMETER MaxFoldersPerLibrary
    Optional. When -IncludeFolders is used, caps the number of folders
    scanned per library to avoid runaway scans on very large libraries.
    Defaults to 2000.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per list/library (and per folder when
    -IncludeFolders is used) with broken inheritance. Always returned to
    the console/pipeline; also written to CSV when -OutputPath is
    supplied.

.EXAMPLE
    Get-SharePointUniquePermissionReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com'

    Scans every site (default -All) for lists/libraries with broken
    permission inheritance (list/library level only).

.EXAMPLE
    Get-SharePointUniquePermissionReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Legal' -IncludeFolders

    Scans the specified site down to folder level for broken inheritance.

.EXAMPLE
    Get-SharePointUniquePermissionReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteId '11111111-2222-3333-4444-555555555555' -OutputPath 'C:\Reports\legal-permissions.csv'

    Scans the site matching the specified SiteId (list/library level only)
    and exports to the exact file (no timestamp appended).

.EXAMPLE
    Get-SharePointUniquePermissionReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -All -IncludeFolders -MaxFoldersPerLibrary 500 -OutputPath 'C:\Reports' -Verbose

    Scans every site down to folder level, capping each library at 500
    folders, exports to C:\Reports\SharePointUniquePermissionReport_<timestamp>.csv,
    with verbose diagnostic output.

.EXAMPLE
    Get-SharePointUniquePermissionReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -Tenant 'contoso.onmicrosoft.com' -Thumbprint 'AB12CD34...' -ClientId '11111111-1111-1111-1111-111111111111'

    Authenticates unattended via certificate (app-only), scanning all
    sites at list/library level.

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
    - Item-level (individual file/list item) unique permissions are never
      scanned by this script, even with -IncludeFolders, due to cost at
      scale - only lists/libraries and folders within them are checked
    - -IncludeFolders makes one additional property-load call per folder;
      on a tenant-wide -All scan this can take a very long time - scope to
      specific sites where possible
    - -MaxFoldersPerLibrary silently truncates very large libraries; a
      Warning is written when the cap is hit so it isn't silent in the log

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPList.html

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPFolder.html

#>


Function Get-SharePointUniquePermissionReport
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
        [switch]$IncludeFolders,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1,[int]::MaxValue)]
        [int]$MaxFoldersPerLibrary = 2000
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

    Write-Progress -Activity "Get-SharePointUniquePermissionReport" -Status "Resolving site scope..." -PercentComplete 0
    try
    {
        $allSites = Get-PnPTenantSite -IncludeOneDriveSites:$IncludeOneDriveSites -Connection $adminConn -ErrorAction Stop
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
        Write-Progress -Activity "Get-SharePointUniquePermissionReport" -Status "Processing $($site.Url)" `
            -PercentComplete (($siteCounter / [Math]::Max($totalSites,1)) * 100)

        try
        {
            $siteConn = Connect-ToSPO -Url $site.Url
            $lists    = Get-PnPList -Connection $siteConn -Includes HasUniqueRoleAssignments -ErrorAction Stop | Where-Object { -not $_.Hidden }

            foreach ($list in $lists)
            {
                if ($list.HasUniqueRoleAssignments)
                {
                    $report.Add([PSCustomObject]@{
                        SiteUrl   = $site.Url
                        SiteTitle = $site.Title
                        Level     = 'List/Library'
                        ItemTitle = $list.Title
                        ItemUrl   = $list.RootFolder.ServerRelativeUrl
                    })
                }

                if ($IncludeFolders -and $list.BaseTemplate -eq 101)
                {
                    try
                    {
                        $items = Get-PnPListItem -List $list -PageSize 500 -Connection $siteConn -ErrorAction Stop | Where-Object { $_.FileSystemObjectType -eq 'Folder' }

                        if ($items.Count -gt $MaxFoldersPerLibrary)
                        {
                            Write-Warning "Library '$($list.Title)' on site '$($site.Url)' has $($items.Count) folders, exceeding -MaxFoldersPerLibrary ($MaxFoldersPerLibrary). Only the first $MaxFoldersPerLibrary will be scanned."
                            $items = $items | Select-Object -First $MaxFoldersPerLibrary
                        }

                        foreach ($folderItem in $items)
                        {
                            try
                            {
                                Get-PnPProperty -ClientObject $folderItem -Property HasUniqueRoleAssignments -Connection $siteConn -ErrorAction Stop
                                if ($folderItem.HasUniqueRoleAssignments)
                                {
                                    $report.Add([PSCustomObject]@{
                                        SiteUrl   = $site.Url
                                        SiteTitle = $site.Title
                                        Level     = 'Folder'
                                        ItemTitle = $folderItem.FieldValues['FileLeafRef']
                                        ItemUrl   = $folderItem.FieldValues['FileRef']
                                    })
                                }
                            }
                            catch
                            {
                                Write-Warning "Could not evaluate a folder in library '$($list.Title)' on site '$($site.Url)': $($_.Exception.Message)"
                                continue
                            }
                        }
                    }
                    catch
                    {
                        Write-Warning "Could not enumerate folders in library '$($list.Title)' on site '$($site.Url)': $($_.Exception.Message)"
                    }
                }
            }
        }
        catch
        {
            Write-Warning "Skipped site '$($site.Url)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-SharePointUniquePermissionReport" -Completed
    Write-Verbose "Built report with $($report.Count) row(s) with broken inheritance across $($targetSites.Count) site(s)."

    if ($report.Count -eq 0)
    {
        Write-Host "No lists, libraries, or folders with broken permission inheritance were found." -ForegroundColor Yellow
    }
    #endregion

    #region Export (optional)
    if ($OutputPath)
    {
        if ([System.IO.Path]::GetExtension($OutputPath) -eq '.csv') { $outFile = $OutputPath }
        else
        {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $outFile   = Join-Path -Path $OutputPath -ChildPath "SharePointUniquePermissionReport_$timestamp.csv"
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
