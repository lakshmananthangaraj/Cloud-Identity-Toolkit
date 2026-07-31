<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 31 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Identifies owners of SharePoint Online sites for accountability and
    management.

.DESCRIPTION
    Connects to the SharePoint Online tenant admin center via PnP PowerShell
    to resolve the target site scope, then connects to each individual site
    to capture the tenant-recorded primary owner, the Site Collection
    Administrators, and - for Microsoft 365 group-connected sites - the
    connected group's owners. Optionally expands the SharePoint "Owners"
    associated group into individual members. Helps with site lifecycle and
    owner-stewardship tracking. Always returns full report objects to the
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
        auto-generated with a timestamp (SiteOwners_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\owners.csv'): the parent folder
        must already exist; the file itself is created/overwritten as
        given, with no timestamp appended.
    If omitted, results are returned to the console/pipeline only - no
    file is written.

.PARAMETER All
    Optional switch. Scan every site in the tenant. This is the default
    behaviour when neither -SiteUrl nor -SiteId is supplied.

.PARAMETER IncludeOneDriveSites
    Optional switch. When using -All, include OneDrive for Business
    (personal) sites in the scan. Excluded by default.

.PARAMETER IncludeOwnersGroupMembers
    Optional switch. Also resolve and include the individual members of
    each site's SharePoint "Owners" associated group.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per site, containing owner/stewardship
    details. Always returned to the console/pipeline; also written to CSV
    when -OutputPath is supplied.

.EXAMPLE
    Get-SharePointSiteOwners -TenantAdminUrl 'https://contoso-admin.sharepoint.com'

    Scans every site in the tenant (default -All behaviour) and returns
    owner details to the console/pipeline.

.EXAMPLE
    Get-SharePointSiteOwners -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -All -OutputPath 'C:\Reports'

    Same as above, explicitly using -All, and additionally exports to
    C:\Reports\SiteOwners_<timestamp>.csv

.EXAMPLE
    Get-SharePointSiteOwners -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Finance'

    Returns owner details for only the specified site, no CSV written.

.EXAMPLE
    Get-SharePointSiteOwners -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteId '11111111-2222-3333-4444-555555555555' -OutputPath 'C:\Reports\finance-owners.csv'

    Returns owner details for the site matching the specified SiteId and
    exports to the exact file C:\Reports\finance-owners.csv (no timestamp
    appended).

.EXAMPLE
    Get-SharePointSiteOwners -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Finance' -IncludeOwnersGroupMembers -Verbose

    Returns owner details for the specified site, including individual
    members of the site's "Owners" SharePoint group, with verbose
    diagnostic output.

.EXAMPLE
    Get-SharePointSiteOwners -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -Tenant 'contoso.onmicrosoft.com' -Thumbprint 'AB12CD34...' -ClientId '11111111-1111-1111-1111-111111111111'

    Authenticates unattended via certificate (app-only) using a custom
    Azure AD app registration, scanning all sites.

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
       a custom Azure AD app registration with SharePoint site collection
       admin permissions (and Group.Read.All in Graph, for M365 group
       owner lookups)
    3. SharePoint Online Administrator (or Global Administrator) role, plus
       Site Collection Administrator rights on each target site
    4. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Microsoft365GroupOwners can only be resolved for group-connected
      sites (Template GROUP#0) and requires Microsoft Graph permissions on
      the connecting app/account; failures are reported per-site as a
      warning rather than aborting the run, and the column is left blank
    - PrimaryOwner reflects the tenant-recorded owner field, which is not
      always kept current by site owners - cross-reference with
      SiteCollectionAdministrators for the authoritative access list
    - -IncludeOwnersGroupMembers adds an additional call per site and will
      increase runtime on sites with large Owners groups

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPSiteCollectionAdmin.html

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPMicrosoft365Group.html

#>

Function Get-SharePointSiteOwners
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
        [switch]$IncludeOwnersGroupMembers
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

    #region Connection check (Tenant Admin) and scope resolution
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

    Write-Progress -Activity "Get-SharePointSiteOwners" -Status "Resolving site scope..." -PercentComplete 0
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

            $notFound = $normalized | Where-Object { $_ -notin ($targetSites.Url.TrimEnd('/')) }
            foreach ($u in $notFound) { Write-Warning "Site URL not found in tenant: '$u'" }
        }
        'BySiteId'
        {
            $targetSites = $allSites | Where-Object { $_.SiteId -in $SiteId }

            $foundIds = $targetSites.SiteId
            $notFound = $SiteId | Where-Object { $_ -notin $foundIds }
            foreach ($id in $notFound) { Write-Warning "SiteId not found in tenant: '$id'" }
        }
        default
        {
            $targetSites = $allSites
        }
    }
    Write-Verbose "Resolved $($targetSites.Count) target site(s) for scope '$($PSCmdlet.ParameterSetName)'."
    #endregion

    #region Build report rows
    $report  = [System.Collections.Generic.List[object]]::new()
    $total   = $targetSites.Count
    $counter = 0

    foreach ($site in $targetSites)
    {
        $counter++
        Write-Progress -Activity "Get-SharePointSiteOwners" -Status "Processing $($site.Url)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            $siteConn = Connect-ToSPO -Url $site.Url

            $scAdmins    = Get-PnPSiteCollectionAdmin -Connection $siteConn -ErrorAction Stop
            $scAdminList = ($scAdmins | ForEach-Object { $_.Email } | Where-Object { $_ }) -join '; '

            $isGroupConnected  = -not [string]::IsNullOrEmpty($site.GroupId) -and $site.GroupId -ne [guid]::Empty
            $m365GroupOwners   = $null

            if ($isGroupConnected)
            {
                try
                {
                    $group = Get-PnPMicrosoft365Group -Identity $site.GroupId -IncludeOwners -Connection $siteConn -ErrorAction Stop
                    $m365GroupOwners = ($group.Owners | ForEach-Object { $_.Email } | Where-Object { $_ }) -join '; '
                }
                catch
                {
                    Write-Warning "Could not resolve Microsoft 365 Group owners for site '$($site.Url)': $($_.Exception.Message)"
                }
            }

            $ownersGroupMembers = $null
            if ($IncludeOwnersGroupMembers)
            {
                try
                {
                    $ownersGroup        = Get-PnPGroup -AssociatedOwnerGroup -Connection $siteConn -ErrorAction Stop
                    $members            = Get-PnPGroupMember -Identity $ownersGroup -Connection $siteConn -ErrorAction Stop
                    $ownersGroupMembers = ($members | ForEach-Object { $_.Email } | Where-Object { $_ }) -join '; '
                }
                catch
                {
                    Write-Warning "Could not resolve Owners group members for site '$($site.Url)': $($_.Exception.Message)"
                }
            }

            $report.Add([PSCustomObject]@{
                SiteUrl                    = $site.Url
                SiteTitle                  = $site.Title
                PrimaryOwner               = $site.Owner
                SiteCollectionAdmins       = $scAdminList
                IsGroupConnected           = $isGroupConnected
                GroupId                    = $site.GroupId
                Microsoft365GroupOwners    = $m365GroupOwners
                OwnersGroupMembers         = $ownersGroupMembers
            })
        }
        catch
        {
            Write-Warning "Skipped site '$($site.Url)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-SharePointSiteOwners" -Completed
    Write-Verbose "Built report for $($report.Count) site(s)."

    if ($report.Count -eq 0)
    {
        Write-Host "No sites were found for the specified scope." -ForegroundColor Yellow
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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "SiteOwners_$timestamp.csv"
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
