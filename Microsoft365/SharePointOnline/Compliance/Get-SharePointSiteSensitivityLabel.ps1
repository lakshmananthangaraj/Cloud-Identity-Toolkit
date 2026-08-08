<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 31 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Lists sensitivity labels assigned to SharePoint Online sites.

.DESCRIPTION
    Connects to the SharePoint Online tenant admin center via PnP PowerShell
    and reports the Microsoft Purview sensitivity label applied to each
    site. Queries each site individually via Get-PnPTenantSite -Identity,
    since bulk tenant-site retrieval does not reliably return the
    SensitivityLabel property. Resolves the label GUID to its display name
    via Get-PnPSensitivityLabel. Useful for compliance and information
    protection audits. Always returns full report objects to the
    console/pipeline; CSV export is optional.

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

.PARAMETER UnlabeledOnly
    Optional switch. Only include sites that do NOT have a sensitivity
    label applied - useful for finding compliance gaps.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per site, containing sensitivity label
    details. Always returned to the console/pipeline; also written to CSV
    when -OutputPath is supplied.

.EXAMPLE
    Get-SharePointSiteSensitivityLabel -TenantAdminUrl 'https://contoso-admin.sharepoint.com'

    Reports the sensitivity label for every site in the tenant.

.EXAMPLE
    Get-SharePointSiteSensitivityLabel -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -UnlabeledOnly -OutputPath 'C:\Reports'

    Reports only unlabeled sites and exports to
    C:\Reports\SharePointSiteSensitivityLabel_<timestamp>.csv

.EXAMPLE
    Get-SharePointSiteSensitivityLabel -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Legal'

    Reports the sensitivity label for only the specified site.

.EXAMPLE
    Get-SharePointSiteSensitivityLabel -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteId '11111111-2222-3333-4444-555555555555' -OutputPath 'C:\Reports\legal-label.csv'

    Reports the sensitivity label for the site matching the specified
    SiteId and exports to the exact file (no timestamp appended).

.EXAMPLE
    Get-SharePointSiteSensitivityLabel -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -IncludeOneDriveSites -Verbose

    Reports sensitivity labels for all sites including OneDrive personal
    sites, with verbose diagnostic output.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (31-Jul-2026) - Initial release
    1.0 (01-Aug-2026) - Fixed incorrect cmdlet reference: Get-PnPSensitivityLabel
                         does not exist in released PnP.PowerShell versions;
                         corrected to Get-PnPAvailableSensitivityLabel

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. PnP.PowerShell module installed
    2. Register-PnPManagementShellAccess run once (or a custom Azure AD app)
    3. SharePoint Online Administrator role, with sensitivity labels
       published to the connecting account/app
    4. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Queries each site individually (one Get-PnPTenantSite -Identity call
      per site) since bulk retrieval does not reliably surface the
      SensitivityLabel property; this is slower than other reports in this
      series on large tenants
    - If the connecting account/app cannot see the tenant's sensitivity
      label set, label GUIDs will be reported without a resolved name

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPTenantSite.html

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPAvailableSensitivityLabel.html

#>


Function Get-SharePointSiteSensitivityLabel
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
        [switch]$UnlabeledOnly
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

    Write-Progress -Activity "Get-SharePointSiteSensitivityLabel" -Status "Resolving site scope..." -PercentComplete 0
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

    try
    {
        $labelLookup = @{}
        Get-PnPAvailableSensitivityLabel -Connection $adminConn -ErrorAction Stop | ForEach-Object { $labelLookup[$_.Id.ToString()] = $_.Name }
        Write-Verbose "Loaded $($labelLookup.Count) sensitivity label(s) from the tenant."
    }
    catch
    {
        Write-Warning "Could not retrieve the tenant's sensitivity label set; label names will not be resolved. $($_.Exception.Message)"
        $labelLookup = @{}
    }
    #endregion

    #region Build report rows
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $targetSites.Count
    $counter = 0

    foreach ($site in $targetSites)
    {
        $counter++
        Write-Progress -Activity "Get-SharePointSiteSensitivityLabel" -Status "Processing $($site.Url)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $detailedSite = Get-PnPTenantSite -Identity $site.Url -Detailed -Connection $adminConn -ErrorAction Stop
            $labelId      = $detailedSite.SensitivityLabel
            $hasLabel     = -not [string]::IsNullOrEmpty($labelId) -and $labelId -ne [guid]::Empty
            $labelName    = if ($hasLabel -and $labelLookup.ContainsKey($labelId.ToString())) { $labelLookup[$labelId.ToString()] } elseif ($hasLabel) { '(unresolved)' } else { $null }

            if ($UnlabeledOnly -and $hasLabel) { continue }

            $report.Add([PSCustomObject]@{
                Title                = $site.Title
                Url                  = $site.Url
                SensitivityLabelId   = if ($hasLabel) { $labelId } else { $null }
                SensitivityLabelName = $labelName
                HasLabel             = $hasLabel
            })
        }
        catch
        {
            Write-Warning "Skipped site '$($site.Url)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-SharePointSiteSensitivityLabel" -Completed
    Write-Verbose "Built report for $($report.Count) site(s)."

    if ($report.Count -eq 0)
    {
        Write-Host "No sites were found matching the specified criteria." -ForegroundColor Yellow
    }
    #endregion

    #region Export (optional)
    if ($OutputPath)
    {
        if ([System.IO.Path]::GetExtension($OutputPath) -eq '.csv') { $outFile = $OutputPath }
        else
        {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $outFile   = Join-Path -Path $OutputPath -ChildPath "SharePointSiteSensitivityLabel_$timestamp.csv"
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
