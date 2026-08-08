<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 31 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Reports external sharing settings and external users on SharePoint
    Online sites.

.DESCRIPTION
    Connects to the SharePoint Online tenant admin center via PnP PowerShell
    to resolve the target site scope, then reports each site's sharing
    capability setting alongside the external (guest) users who have been
    invited into that site. Critical for security and data leakage
    prevention (DLP) assessments. Always returns full report objects to the
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
        auto-generated with a timestamp (ExternalSharing_yyyyMMdd_HHmmss.csv).
      - Full file path (e.g. 'C:\Reports\external.csv'): the parent folder
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

.PARAMETER ExpandExternalUsers
    Optional switch. Changes report granularity from one row per site
    (with a joined list of external user emails) to one row per external
    user per site, including invited-by and invitation-date details.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects - one per site (default), or one per
    external user per site (with -ExpandExternalUsers). Always returned to
    the console/pipeline; also written to CSV when -OutputPath is
    supplied.

.EXAMPLE
    Get-SharePointExternalSharingReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com'

    Scans every site in the tenant (default -All behaviour) and returns one
    row per site with sharing capability and external user count/emails.

.EXAMPLE
    Get-SharePointExternalSharingReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -All -OutputPath 'C:\Reports'

    Same as above, explicitly using -All, and additionally exports to
    C:\Reports\ExternalSharing_<timestamp>.csv

.EXAMPLE
    Get-SharePointExternalSharingReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Partners'

    Returns external sharing details for only the specified site, no CSV
    written.

.EXAMPLE
    Get-SharePointExternalSharingReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteId '11111111-2222-3333-4444-555555555555' -OutputPath 'C:\Reports\partners-external.csv'

    Returns external sharing details for the site matching the specified
    SiteId and exports to the exact file C:\Reports\partners-external.csv
    (no timestamp appended).

.EXAMPLE
    Get-SharePointExternalSharingReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -ExpandExternalUsers -Verbose

    Scans every site and returns one row per external user per site
    (email, display name, invited-by, invitation date), with verbose
    diagnostic output.

.EXAMPLE
    Get-SharePointExternalSharingReport -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -Tenant 'contoso.onmicrosoft.com' -Thumbprint 'AB12CD34...' -ClientId '11111111-1111-1111-1111-111111111111'

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
       a custom Azure AD app registration with SharePoint admin permissions
    3. SharePoint Online Administrator (or Global Administrator) role
       (Get-PnPExternalUser requires access to the tenant admin site)
    4. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - SharingCapability reflects the site-level setting; it does not
      reflect tenant-wide sharing policy overrides or sharing link
      expiration/domain restriction settings
    - Get-PnPExternalUser is paginated internally in batches of 50 to work
      around the underlying API's per-call limit; very large external-user
      counts on a single site will increase runtime accordingly
    - Only reports users invited via the standard external sharing/guest
      invitation flow; anonymous "Anyone" links are not enumerated here

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPExternalUser.html

.LINK
    https://pnp.github.io/powershell/cmdlets/Get-PnPTenantSite.html

#>

Function Get-SharePointExternalSharingReport
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
        [switch]$ExpandExternalUsers
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

    Write-Progress -Activity "Get-SharePointExternalSharingReport" -Status "Resolving site scope..." -PercentComplete 0
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
        Write-Progress -Activity "Get-SharePointExternalSharingReport" -Status "Processing $($site.Url)" `
            -PercentComplete (($counter / [Math]::Max($total,1)) * 100)

        try
        {
            # Page through external users in batches of 50 (API limit)
            $externalUsers = [System.Collections.Generic.List[object]]::new()
            $position      = 0
            do
            {
                $page = Get-PnPExternalUser -SiteUrl $site.Url -Position $position -PageSize 50 -Connection $adminConn -ErrorAction Stop
                if ($page) { $externalUsers.AddRange(@($page)) }
                $position += 50
            }
            while ($page -and @($page).Count -eq 50)

            if ($ExpandExternalUsers)
            {
                if ($externalUsers.Count -eq 0)
                {
                    $report.Add([PSCustomObject]@{
                        SiteUrl           = $site.Url
                        SiteTitle         = $site.Title
                        SharingCapability = $site.SharingCapability
                        ExternalUserEmail = $null
                        DisplayName       = $null
                        InvitedBy         = $null
                        WhenCreated       = $null
                    })
                }
                else
                {
                    foreach ($eu in $externalUsers)
                    {
                        $report.Add([PSCustomObject]@{
                            SiteUrl           = $site.Url
                            SiteTitle         = $site.Title
                            SharingCapability = $site.SharingCapability
                            ExternalUserEmail = $eu.Email
                            DisplayName       = $eu.DisplayName
                            InvitedBy         = $eu.InvitedBy
                            WhenCreated       = $eu.WhenCreated
                        })
                    }
                }
            }
            else
            {
                $report.Add([PSCustomObject]@{
                    SiteUrl            = $site.Url
                    SiteTitle          = $site.Title
                    SharingCapability  = $site.SharingCapability
                    ExternalUserCount  = $externalUsers.Count
                    ExternalUserEmails = ($externalUsers | ForEach-Object { $_.Email } | Where-Object { $_ }) -join '; '
                })
            }
        }
        catch
        {
            Write-Warning "Skipped site '$($site.Url)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-SharePointExternalSharingReport" -Completed
    Write-Verbose "Built report with $($report.Count) row(s) across $($targetSites.Count) site(s)."

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
            $outFile   = Join-Path -Path $OutputPath -ChildPath "ExternalSharing_$timestamp.csv"
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
