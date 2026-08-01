<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 31 July 2026
Modified-On  : 31 July 2026

.SYNOPSIS
    Finds files exceeding a configurable size threshold across SharePoint
    Online sites.

.DESCRIPTION
    Connects to the SharePoint Online tenant admin center via PnP PowerShell
    and uses the SharePoint Search index (Submit-PnPSearchQuery) to find
    files larger than -MinSizeMB, scoped to the target site(s). Search is
    used for speed across a tenant-wide scan; results reflect the search
    index and may lag the live document store by hours or days. Helps
    reduce storage costs and identify unusually large files. Always returns
    full report objects to the console/pipeline; CSV export is optional.

.PARAMETER TenantAdminUrl
    Mandatory. The SharePoint Online tenant admin center URL, e.g.
    'https://contoso-admin.sharepoint.com'.

.PARAMETER MinSizeMB
    Optional. Minimum file size, in megabytes, to include in the report.
    Defaults to 100.

.PARAMETER SiteUrl
    Optional. One or more specific site URLs to scope the search to.
    Mutually exclusive with -All and -SiteId.

.PARAMETER SiteId
    Optional. One or more specific site GUIDs (SiteId) to scope the search
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
    Optional switch. Search every site in the tenant. Default behaviour
    when neither -SiteUrl nor -SiteId is supplied.

.PARAMETER MaxResults
    Optional. Maximum number of files to return. Defaults to 500 (the
    practical single-batch cap for this search query).

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per file, containing file details.
    Always returned to the console/pipeline; also written to CSV when
    -OutputPath is supplied.

.EXAMPLE
    Get-SharePointLargeFiles -TenantAdminUrl 'https://contoso-admin.sharepoint.com'

    Finds files 100 MB or larger across every site in the tenant (default
    -All, default -MinSizeMB 100).

.EXAMPLE
    Get-SharePointLargeFiles -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -MinSizeMB 500 -OutputPath 'C:\Reports'

    Finds files 500 MB or larger and exports to
    C:\Reports\SharePointLargeFiles_<timestamp>.csv

.EXAMPLE
    Get-SharePointLargeFiles -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Media' -MinSizeMB 250

    Finds files 250 MB or larger on only the specified site.

.EXAMPLE
    Get-SharePointLargeFiles -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -SiteId '11111111-2222-3333-4444-555555555555' -OutputPath 'C:\Reports\media-large.csv'

    Finds files 100 MB or larger on the site matching the specified SiteId
    and exports to the exact file (no timestamp appended).

.EXAMPLE
    Get-SharePointLargeFiles -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -MinSizeMB 1000 -MaxResults 200 -Verbose

    Finds files 1 GB or larger tenant-wide, capped at 200 results, with
    verbose diagnostic output.

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
    3. SharePoint Online Administrator role
    4. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Results come from the SharePoint Search index, not a live file scan;
      very recently uploaded/modified files may not yet be reflected
    - -MaxResults caps a single search call; extremely large result sets
      beyond that cap are not paginated in this version
    - Files in libraries excluded from search (e.g. via search exclusion
      settings) will not appear in results

.LINK
    https://pnp.github.io/powershell/cmdlets/Submit-PnPSearchQuery.html

#>


Function Get-SharePointLargeFiles
{
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^https://[a-zA-Z0-9-]+-admin\.sharepoint\.com/?$')]
        [string]$TenantAdminUrl,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1,[int]::MaxValue)]
        [int]$MinSizeMB = 100,

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
        [ValidateRange(1,500)]
        [int]$MaxResults = 500
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

    $sizeBytes  = $MinSizeMB * 1MB
    $pathClause = $null

    switch ($PSCmdlet.ParameterSetName)
    {
        'BySiteUrl'
        {
            $clauses    = $SiteUrl | ForEach-Object { "Path:$($_.TrimEnd('/'))*" }
            $pathClause = '(' + ($clauses -join ' OR ') + ')'
        }
        'BySiteId'
        {
            try
            {
                $allSites   = Get-PnPTenantSite -Connection $adminConn -ErrorAction Stop
                $matched    = $allSites | Where-Object { $_.SiteId -in $SiteId }
                foreach ($id in ($SiteId | Where-Object { $_ -notin $matched.SiteId })) { Write-Warning "SiteId not found in tenant: '$id'" }
                $clauses    = $matched.Url | ForEach-Object { "Path:$($_.TrimEnd('/'))*" }
                $pathClause = if ($clauses) { '(' + ($clauses -join ' OR ') + ')' } else { $null }
            }
            catch
            {
                Write-Error "Failed to resolve -SiteId to a site URL: $($_.Exception.Message)"
                return
            }
        }
        default { $pathClause = $null }
    }

    if ($PSCmdlet.ParameterSetName -eq 'BySiteId' -and -not $pathClause)
    {
        Write-Host "No sites were found matching the specified SiteId(s)." -ForegroundColor Yellow
        return @()
    }
    #endregion

    #region Search
    Write-Progress -Activity "Get-SharePointLargeFiles" -Status "Querying search index..." -PercentComplete 50
    $query = "contentclass:STS_ListItem_File AND Size>=$sizeBytes AND IsDocument:True"
    if ($pathClause) { $query = "$query AND $pathClause" }

    Write-Verbose "Search query: $query"

    try
    {
        $results = Submit-PnPSearchQuery -Query $query -SelectProperties "Title","Path","Size","LastModifiedTime","SPSiteUrl","Author" `
            -SortList @{Size="Descending"} -MaxResults $MaxResults -Connection $adminConn -ErrorAction Stop
    }
    catch
    {
        Write-Error "Search query failed: $($_.Exception.Message)"
        return
    }
    Write-Progress -Activity "Get-SharePointLargeFiles" -Completed
    #endregion

    #region Build report rows
    $report = [System.Collections.Generic.List[object]]::new()

    foreach ($row in $results.ResultRows)
    {
        try
        {
            $sizeBytesVal = [int64]$row["Size"]
            $report.Add([PSCustomObject]@{
                Title             = $row["Title"]
                Path              = $row["Path"]
                SiteUrl           = $row["SPSiteUrl"]
                SizeMB            = [Math]::Round(($sizeBytesVal / 1MB), 2)
                Author            = $row["Author"]
                LastModifiedTime  = $row["LastModifiedTime"]
            })
        }
        catch
        {
            Write-Warning "Skipped a search result row: $($_.Exception.Message)"
            continue
        }
    }
    Write-Verbose "Built report with $($report.Count) file(s) at or above $MinSizeMB MB."

    if ($report.Count -eq 0)
    {
        Write-Host "No files at or above $MinSizeMB MB were found for the specified scope." -ForegroundColor Yellow
    }
    #endregion

    #region Export (optional)
    if ($OutputPath)
    {
        if ([System.IO.Path]::GetExtension($OutputPath) -eq '.csv') { $outFile = $OutputPath }
        else
        {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $outFile   = Join-Path -Path $OutputPath -ChildPath "SharePointLargeFiles_$timestamp.csv"
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
