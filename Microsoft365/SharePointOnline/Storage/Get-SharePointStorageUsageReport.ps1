<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 31 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Reports storage consumption for SharePoint Online sites.

.DESCRIPTION
    Connects to the SharePoint Online tenant admin center via PnP PowerShell
    and reports current storage usage, quota, and percent-used for each
    site, flagging sites nearing their quota. Helps identify sites
    consuming excessive storage and supports capacity planning. Works
    entirely from the tenant admin connection - no per-site reconnect is
    required. Always returns full report objects to the console/pipeline;
    CSV export is optional.

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
    Optional. Tenant domain (e.g. 'contoso.onmicrosoft.com'). Supply
    together with -Thumbprint to authenticate unattended via certificate
    (app-only) instead of interactive login.

.PARAMETER Thumbprint
    Optional. Certificate thumbprint (from the local certificate store)
    for app-only authentication. Supply together with -Tenant.

.PARAMETER WarningThresholdPercent
    Optional. Percentage of quota used at which a site is flagged as
    NearingQuota. Defaults to 80.

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

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per site, containing storage usage
    details. Always returned to the console/pipeline; also written to CSV
    when -OutputPath is supplied.

.EXAMPLE
    Get-SharePointStorageUsageReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com'

    Reports storage usage for every site in the tenant (default -All).

.EXAMPLE
    Get-SharePointStorageUsageReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -WarningThresholdPercent 90 -OutputPath 'C:\Reports'

    Flags sites over 90% of quota and exports to
    C:\Reports\SharePointStorageUsageReport_<timestamp>.csv

.EXAMPLE
    Get-SharePointStorageUsageReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Finance'

    Reports storage usage for only the specified site.

.EXAMPLE
    Get-SharePointStorageUsageReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteId '11111111-2222-3333-4444-555555555555' -OutputPath 'C:\Reports\finance-storage.csv'

    Reports storage usage for the site matching the specified SiteId and
    exports to the exact file (no timestamp appended).

.EXAMPLE
    Get-SharePointStorageUsageReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -IncludeOneDriveSites -Verbose

    Reports storage usage for all sites including OneDrive personal sites,
    with verbose diagnostic output.

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
    3. SharePoint Online Administrator (or Global Administrator) role
    4. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - StorageUsageCurrent/StorageQuota values reflect the last tenant sync
      and may lag actual usage by up to 24 hours
    - Large tenants (10k+ sites) may take several minutes to enumerate

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPTenantSite.html

#>


Function Get-SharePointStorageUsageReport
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
        [ValidateRange(1,100)]
        [int]$WarningThresholdPercent = 80,

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

    Write-Progress -Activity "Get-SharePointStorageUsageReport" -Status "Retrieving site list..." -PercentComplete 0
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
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $targetSites.Count
    $counter = 0

    foreach ($site in $targetSites)
    {
        $counter++
        Write-Progress -Activity "Get-SharePointStorageUsageReport" -Status "Processing $($site.Url)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $percentUsed = if ($site.StorageQuota -gt 0) { [Math]::Round(($site.StorageUsageCurrent / $site.StorageQuota) * 100, 2) } else { 0 }

            $report.Add([PSCustomObject]@{
                Title                   = $site.Title
                Url                     = $site.Url
                StorageUsageCurrentMB   = $site.StorageUsageCurrent
                StorageQuotaMB          = $site.StorageQuota
                PercentUsed             = $percentUsed
                NearingQuota            = ($percentUsed -ge $WarningThresholdPercent)
                LastContentModifiedDate = $site.LastContentModifiedDate
            })
        }
        catch
        {
            Write-Warning "Skipped site '$($site.Url)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-SharePointStorageUsageReport" -Completed
    Write-Verbose "Built report for $($report.Count) site(s)."

    if ($report.Count -eq 0)
    {
        Write-Host "No sites were found for the specified scope." -ForegroundColor Yellow
    }
    #endregion

    #region Export (optional)
    if ($OutputPath)
    {
        if ([System.IO.Path]::GetExtension($OutputPath) -eq '.csv') { $outFile = $OutputPath }
        else
        {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $outFile   = Join-Path -Path $OutputPath -ChildPath "SharePointStorageUsageReport_$timestamp.csv"
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
