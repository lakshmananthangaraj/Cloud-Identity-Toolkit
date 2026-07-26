<#

Author          : Lakshmanan Thangaraj
Version         : 2.1
Created-On      : 23 February 2026
Modified-On     : 26 July 2026

.SYNOPSIS
    Retrieves SharePoint site permissions for a specific Entra ID application
    (forward lookup), OR retrieves all applications with access to a specific
    SharePoint site (reverse lookup).

.DESCRIPTION
    Forward Lookup (default):
        Scans all SharePoint sites and reports which ones have granted access
        to the -TargetAppId application via Sites.Selected permission.

    Reverse Lookup (when -TargetSiteId or -TargetSiteUrl is provided):
        Queries a single specified site and returns every application that
        currently holds a permission entry on that site.

    Authentication supports two modes:
    - Interactive      : Delegated login using the current user's credentials
    - ServicePrincipal : App-only login using Client ID + Client Secret

    This function is read-only — it never modifies site permissions. If a
    Graph session is already connected when this function is called, it is
    reused (and left connected) rather than being torn down at the end.

.PARAMETER TargetAppId
    The Application (Client) ID of the app whose Sites.Selected permissions
    you want to audit.
    Required for forward lookup. Optional for reverse lookup (if supplied,
    reverse lookup results are filtered to this app only).

.PARAMETER TargetSiteId
    Graph Site ID of the SharePoint site to inspect (reverse lookup).
    Format: <hostname>,<site-collection-id>,<web-id>
    Provide either -TargetSiteId or -TargetSiteUrl, not both.

.PARAMETER TargetSiteUrl
    Full URL of the SharePoint site to inspect (reverse lookup).
    E.g. https://contoso.sharepoint.com/sites/HR
    Provide either -TargetSiteUrl or -TargetSiteId, not both.

.PARAMETER AuthMode
    Authentication mode. Accepted values: 'Interactive' or 'ServicePrincipal'

.PARAMETER TenantId
    Your Entra ID Tenant ID (GUID). Required for ServicePrincipal mode.

.PARAMETER ClientId
    The Application (Client) ID used for app-only authentication (GUID).
    Required for ServicePrincipal mode.

.PARAMETER ClientSecret
    The Client Secret as a SecureString. Preferred over -ClientSecretPlainText.
    Required for ServicePrincipal mode (via one of the two secret parameters).

.PARAMETER ClientSecretPlainText
    The Client Secret as plain text. Provided for automation/CI scenarios only.
    Prefer -ClientSecret (SecureString) or a secrets manager where possible.

.PARAMETER ThrottleLimit
    Number of sites to process in parallel (default: 10, PowerShell 7+ only).
    Increase for faster scans; decrease if you hit Graph API 429 errors.

.PARAMETER ExportCsv
    Optional. Path to export results as a CSV file.
    E.g. "C:\reports\results.csv"

.EXAMPLE
    ── Example 1: Interactive login (forward lookup) ─────────────
    Get-AppSiteSelectedPermissions `
        -TargetAppId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -AuthMode    Interactive

.EXAMPLE
    ── Example 2: Service Principal login (forward lookup, SecureString) ──
    $secret = Read-Host "Client Secret" -AsSecureString
    Get-AppSiteSelectedPermissions `
        -TargetAppId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -AuthMode    ServicePrincipal `
        -TenantId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret $secret

.EXAMPLE
    ── Example 3: SP login + Export to CSV ───────────────────────
    Get-AppSiteSelectedPermissions `
        -TargetAppId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -AuthMode    ServicePrincipal `
        -TenantId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret $secret `
        -ExportCsv   "C:\Reports\SitePermissions.csv"

.EXAMPLE
    ── Example 4: Reverse lookup by Site URL — who has access? ───
    Get-AppSiteSelectedPermissions -AuthMode Interactive `
        -TargetSiteUrl "https://contoso.sharepoint.com/sites/HR"

.EXAMPLE
    ── Example 5: Reverse lookup filtered to one app ──────────────
    Get-AppSiteSelectedPermissions -AuthMode Interactive `
        -TargetSiteId "contoso.sharepoint.com,abc,def" `
        -TargetAppId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    ── Example 6: Parallel forward scan with custom throttle ──────
    Get-AppSiteSelectedPermissions `
        -TargetAppId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -AuthMode    ServicePrincipal `
        -TenantId    $tenantId -ClientId $clientId -ClientSecret $secret `
        -ThrottleLimit 20

.NOTES
    Required Graph Permissions (Application):
      - Sites.FullControl.All   (Graph does not currently expose a lower,
                                  read-only permission for the site
                                  permissions endpoint used here)
      - Application.Read.All    (to resolve the target app's service principal)

    Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Sites, Microsoft.Graph.Applications

    Parallel execution requires PowerShell 7.0 or later.
    On PowerShell 5.x the script automatically falls back to sequential mode.

    Large tenants: This function retrieves permissions for each SharePoint
    site individually. In environments with a large number of sites (for
    example, 50,000+), the operation may take a considerable amount of time,
    even when parallel processing is enabled. Consider using -ExportCsv to
    save results and schedule execution during off-peak hours. Resume or
    checkpoint functionality is not currently supported.

    CHANGELOG:
      v2.1 - 26 July 2026 - Security/bug-fix pass for public release:
                            - Removed a wasted Get-MgSite call that fetched a
                              full page of sites and immediately discarded it
                              before the real paginated fetch began.
                            - Parallel block no longer captures the full $sites
                              collection via $using: just to read a count;
                              the count is now precomputed once outside the
                              parallel block.
                            - Session handling: if a Graph session is already
                              connected when this Function starts, it is
                              reused and left connected afterward instead of
                              being force-disconnected.
                            - Wrapped main execution in try/finally so
                              Write-Progress and cleanup always run, even on
                              a thrown error mid-scan.
                            - Added SecureString -ClientSecret (plain text
                              still available via -ClientSecretPlainText for
                              automation, with an explicit warning).
                            - Added GUID format validation on TenantId/ClientId.
      v2.0 - 28 April 2026 - Added reverse lookup, parallel scan, throttle
                              control, CSV export.
      v1.0 - 23 February 2026 - Initial release (forward lookup only).
#>


Function Get-AppSiteSelectedPermissions
{
    [CmdletBinding(DefaultParameterSetName = "Interactive")]
    param (
        [Parameter(HelpMessage = "Client ID of the app to audit (Sites.Selected target app)")]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$TargetAppId,

        [Parameter(HelpMessage = "Graph Site ID for reverse lookup (hostname,siteId,webId)")]
        [string]$TargetSiteId,

        [Parameter(HelpMessage = "Full SharePoint URL for reverse lookup")]
        [string]$TargetSiteUrl,

        [Parameter(Mandatory, HelpMessage = "Authentication mode: 'Interactive' or 'ServicePrincipal'")]
        [ValidateSet('Interactive', 'ServicePrincipal')]
        [string]$AuthMode,

        [Parameter(HelpMessage = "Tenant ID (GUID, required for ServicePrincipal mode)")]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$TenantId,

        [Parameter(HelpMessage = "Client ID of the authenticating app (GUID, required for ServicePrincipal mode)")]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$ClientId,

        [Parameter(HelpMessage = "Client Secret as a SecureString (recommended for ServicePrincipal mode).")]
        [SecureString]$ClientSecret,

        [Parameter(HelpMessage = "Client Secret as plain text. Prefer -ClientSecret. For automation only.")]
        [string]$ClientSecretPlainText,

        [Parameter(HelpMessage = "Parallel threads for scanning (default 10). Reduce if you see 429 errors.")]
        [ValidateRange(1, 50)]
        [int]$ThrottleLimit = 10,

        [Parameter(HelpMessage = "Optional CSV export path e.g. C:\reports\results.csv")]
        [string]$ExportCsv
    )

    # ─────────────────────────────────────────────
    #  HELPER: UI Utilities (scoped locally so this Function never clobbers
    #  same-named helpers the caller may have loaded from elsewhere)
    # ─────────────────────────────────────────────

    Function Write-Banner
    {
        Clear-Host
        $banner = @"
╔══════════════════════════════════════════════════════════════════╗
║       SharePoint Sites.Selected Permission Auditor               ║
║       Entra ID Application Access Inspector  v2.1                ║
╚══════════════════════════════════════════════════════════════════╝
"@
        Write-Host $banner -ForegroundColor Cyan
        Write-Host ""
    }

    Function Write-Step
    {
        param([int]$Step, [int]$Total, [string]$Message)
        Write-Host "  [" -NoNewline -ForegroundColor DarkGray
        Write-Host "$Step/$Total" -NoNewline -ForegroundColor Yellow
        Write-Host "] " -NoNewline -ForegroundColor DarkGray
        Write-Host $Message -ForegroundColor White
    }

    Function Write-Success
    {
        param([string]$Message)
        Write-Host "  ✔ " -NoNewline -ForegroundColor Green
        Write-Host $Message -ForegroundColor White
    }

    Function Write-Failure
    {
        param([string]$Message)
        Write-Host "  ✖ " -NoNewline -ForegroundColor Red
        Write-Host $Message -ForegroundColor White
    }

    Function Write-Info
    {
        param([string]$Message)
        Write-Host "  ℹ " -NoNewline -ForegroundColor Cyan
        Write-Host $Message -ForegroundColor Gray
    }

    Function Write-SectionHeader
    {
        param([string]$Title)
        Write-Host ""
        Write-Host "  ─── $Title " -ForegroundColor DarkCyan
        Write-Host ""
    }

    Function Write-ProgressBar
    {
        param([int]$Current, [int]$Total, [string]$Label)
        $pct = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
        Write-Progress -Activity "Scanning SharePoint Sites" `
                       -Status   "$Label  ($Current of $Total)" `
                       -PercentComplete $pct
    }

    # ─────────────────────────────────────────────
    #  STEP 0: Validate parameters
    # ─────────────────────────────────────────────

    Write-Banner

    if ($TargetSiteId -and $TargetSiteUrl)
    {
        Write-Failure "Provide either -TargetSiteId OR -TargetSiteUrl, not both."
        throw "Conflicting parameters: -TargetSiteId and -TargetSiteUrl are mutually exclusive."
    }

    $isReverseLookup = ($TargetSiteId -or $TargetSiteUrl)

    if (-not $isReverseLookup -and -not $TargetAppId)
    {
        Write-Failure "-TargetAppId is required when performing a forward (tenant-wide) scan."
        throw "Missing required parameter: -TargetAppId"
    }

    $secretPlain = $null
    if ($AuthMode -eq 'ServicePrincipal')
    {
        $missing = @()
        if (-not $TenantId) { $missing += '-TenantId' }
        if (-not $ClientId) { $missing += '-ClientId' }
        if (-not $ClientSecret -and -not $ClientSecretPlainText) { $missing += '-ClientSecret (or -ClientSecretPlainText)' }

        if ($missing.Count -gt 0) {
            Write-Failure "ServicePrincipal mode requires the following missing parameters:"
            $missing | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
            Write-Host ""
            throw "Missing required parameters for ServicePrincipal auth mode."
        }

        if ($ClientSecret) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
            try   { $secretPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
        else {
            Write-Warning "Using -ClientSecretPlainText passes the secret as plain text (visible in PS history/process listing). Prefer -ClientSecret (SecureString) where possible."
            $secretPlain = $ClientSecretPlainText
        }
    }

    # ── Reuse an existing Graph session rather than forcing a fresh one,
    #    and remember whether WE opened the connection so we only close
    #    what we opened.
    $preexistingContext = Get-MgContext
    $weConnected = $false
    $results = @()

    try
    {
        # ─────────────────────────────────────────
        #  STEP 1: Authentication
        # ─────────────────────────────────────────

        Write-SectionHeader "AUTHENTICATION"

        if ($preexistingContext) {
            Write-Step 1 4 "Reusing existing Microsoft Graph session"
            Write-Info "Account   : $($preexistingContext.Account)"
            Write-Info "Tenant ID : $($preexistingContext.TenantId)"
        }
        else {
            Write-Step 1 4 "Connecting to Microsoft Graph  [$AuthMode mode]"
            try {
                if ($AuthMode -eq 'Interactive') {
                    Write-Info "A browser window will open for interactive login..."
                    Connect-MgGraph -Scopes "Sites.FullControl.All", "Application.Read.All" -NoWelcome -ErrorAction Stop
                }
                else {
                    $secureSecret = ConvertTo-SecureString $secretPlain -AsPlainText -Force
                    $credential   = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)
                    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop
                }
                $weConnected = $true

                $ctx = Get-MgContext
                Write-Success "Connected successfully!"
                Write-Info    "Auth Type  : $($ctx.AuthType)"
                Write-Info    "Account    : $($ctx.Account)"
                Write-Info    "Tenant ID  : $($ctx.TenantId)"
            }
            catch {
                Write-Failure "Authentication failed: $($_.Exception.Message)"
                throw
            }
        }

        # ─────────────────────────────────────────
        #  STEP 2: Resolve Target App Service Principal
        #  (skipped for pure reverse lookup with no TargetAppId)
        # ─────────────────────────────────────────

        $sp = $null

        if ($TargetAppId)
        {
            Write-Host ""
            Write-Step 2 4 "Resolving target application Service Principal..."

            try {
                $sp = Get-MgServicePrincipal -Filter "appId eq '$TargetAppId'" -ErrorAction Stop

                if (-not $sp) {
                    Write-Failure "No service principal found for App ID: $TargetAppId"
                    throw "Service principal not found."
                }

                Write-Success "Target App resolved!"
                Write-Info    "App Name   : $($sp.DisplayName)"
                Write-Info    "App ID     : $($sp.AppId)"
                Write-Info    "SP Object  : $($sp.Id)"
            }
            catch {
                Write-Failure "Failed to resolve service principal: $($_.Exception.Message)"
                throw
            }
        }

        # ─────────────────────────────────────────
        #  REVERSE LOOKUP BRANCH
        # ─────────────────────────────────────────

        if ($isReverseLookup)
        {
            Write-SectionHeader "REVERSE LOOKUP"

            $targetSite = $null

            if ($TargetSiteUrl)
            {
                Write-Step 2 4 "Resolving site from URL..."
                try {
                    $uri          = [System.Uri]$TargetSiteUrl
                    $hostname     = $uri.Host
                    $relativePath = $uri.AbsolutePath
                    $siteIdParam  = "$hostname`:$relativePath`:"

                    $targetSite = Get-MgSite -SiteId $siteIdParam -Property "Id,DisplayName,WebUrl" -ErrorAction Stop
                }
                catch {
                    Write-Failure "Could not resolve site from URL '$TargetSiteUrl': $($_.Exception.Message)"
                    throw
                }
            }
            else
            {
                Write-Step 2 4 "Resolving site from Site ID..."
                try {
                    $targetSite = Get-MgSite -SiteId $TargetSiteId -Property "Id,DisplayName,WebUrl" -ErrorAction Stop
                }
                catch {
                    Write-Failure "Could not retrieve site with ID '$TargetSiteId': $($_.Exception.Message)"
                    throw
                }
            }

            Write-Success "Site resolved: $($targetSite.DisplayName)"
            Write-Info    "URL   : $($targetSite.WebUrl)"
            Write-Info    "ID    : $($targetSite.Id)"

            Write-Host ""
            Write-Step 3 4 "Fetching all application permissions on site..."

            try {
                $perms = Get-MgSitePermission -SiteId $targetSite.Id -ErrorAction Stop
            }
            catch {
                Write-Failure "Failed to read permissions: $($_.Exception.Message)"
                throw
            }

            Write-Step 4 4 "Building results..."

            $localResults = @()
            $scannedAt    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            foreach ($perm in $perms)
            {
                $grantedApps = @()

                if ($perm.GrantedToIdentitiesV2) {
                    $grantedApps += $perm.GrantedToIdentitiesV2 |
                        Where-Object { $_.Application } |
                        Select-Object -ExpandProperty Application
                }
                if ($perm.GrantedToIdentities) {
                    $grantedApps += $perm.GrantedToIdentities |
                        Where-Object { $_.Application } |
                        Select-Object -ExpandProperty Application
                }

                foreach ($app in $grantedApps)
                {
                    if ($TargetAppId -and ($app.Id -ne $sp.AppId)) { continue }

                    $localResults += [PSCustomObject]@{
                        SiteName     = $targetSite.DisplayName
                        SiteUrl      = $targetSite.WebUrl
                        SiteId       = $targetSite.Id
                        PermissionId = $perm.Id
                        Roles        = ($perm.Roles -join ", ")
                        AppName      = $app.DisplayName
                        AppId        = $app.Id
                        ScannedAt    = $scannedAt
                    }
                }
            }

            Write-SectionHeader "REVERSE LOOKUP RESULTS"

            Write-Host "  Site          : " -NoNewline -ForegroundColor Gray
            Write-Host $targetSite.DisplayName -ForegroundColor White

            Write-Host "  Apps Found    : " -NoNewline -ForegroundColor Gray
            Write-Host $localResults.Count -ForegroundColor $(if ($localResults.Count -gt 0) { "Green" } else { "Yellow" })
            Write-Host ""

            if ($localResults.Count -gt 0)
            {
                foreach ($r in $localResults)
                {
                    Write-Host "  ● " -NoNewline -ForegroundColor Green
                    Write-Host "$($r.AppName)  [$($r.AppId)]" -ForegroundColor White
                    Write-Host "    Roles        : $($r.Roles)"        -ForegroundColor Cyan
                    Write-Host "    Permission ID: $($r.PermissionId)" -ForegroundColor DarkGray
                    Write-Host ""
                }

                if ($ExportCsv)
                {
                    try {
                        $exportDir = Split-Path $ExportCsv -Parent
                        if ($exportDir -and -not (Test-Path $exportDir)) {
                            New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
                        }
                        $localResults | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
                        Write-Success "Results exported to: $ExportCsv"
                    }
                    catch {
                        Write-Failure "CSV export failed: $($_.Exception.Message)"
                    }
                }
            }
            else
            {
                Write-Host "  ⚠  No application permissions found on this site." -ForegroundColor Yellow
                if ($TargetAppId) {
                    Write-Info "The application '$($sp.DisplayName)' has no explicit access to this site."
                }
            }

            Write-SectionHeader "COMPLETE"
            Write-Success "Audit finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            Write-Host ""

            $results = $localResults
            return $results
        }

        # ─────────────────────────────────────────
        #  STEP 3: Enumerate All SharePoint Sites (paginated, single pass)
        # ─────────────────────────────────────────

        Write-Host ""
        Write-Step 3 4 "Fetching all SharePoint sites in tenant (this takes several minutes for large tenants)..."
        Write-Info "Paginating through Graph API — one dot per page:"
        Write-Host "  " -NoNewline

        $sites     = [System.Collections.Generic.List[object]]::new()
        $pageCount = 0

        try
        {
            $rawPage = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites?`$select=id,displayName,webUrl&`$top=999" -ErrorAction Stop

            while ($true)
            {
                foreach ($item in $rawPage.value)
                {
                    # Invoke-MgGraphRequest returns Hashtables, not PSCustomObjects;
                    # bracket-notation avoids throwing when a key is absent.
                    $siteId   = $item['id']
                    $siteName = $item['displayName']
                    $siteUrl  = $item['webUrl']

                    if ([string]::IsNullOrEmpty($siteId)) { continue }

                    $sites.Add([PSCustomObject]@{
                        Id          = $siteId
                        DisplayName = if ($siteName) { $siteName } else { "(No display name) [$siteId]" }
                        WebUrl      = if ($siteUrl)  { $siteUrl  } else { "(No URL)" }
                    })
                }

                $pageCount++
                Write-Host "." -NoNewline -ForegroundColor DarkCyan
                if ($pageCount % 10 -eq 0) {
                    Write-Host " [$($sites.Count)]" -NoNewline -ForegroundColor Yellow
                }

                if (-not $rawPage['@odata.nextLink']) { break }
                $rawPage = Invoke-MgGraphRequest -Method GET -Uri $rawPage['@odata.nextLink'] -ErrorAction Stop
            }

            Write-Host ""
            Write-Success "Retrieved $($sites.Count) site(s) across $pageCount page(s) from tenant."
        }
        catch
        {
            Write-Host ""
            Write-Failure "Failed to retrieve sites: $($_.Exception.Message)"
            throw
        }

        # ─────────────────────────────────────────
        #  STEP 4: Scan Each Site — PARALLEL EXECUTION
        # ─────────────────────────────────────────

        Write-Host ""
        Write-Step 4 4 "Scanning site permissions for target app..."
        Write-Host ""

        $useParallel = ($PSVersionTable.PSVersion.Major -ge 7)

        if ($useParallel) {
            Write-Info "PowerShell 7+ detected — using parallel scan (ThrottleLimit: $ThrottleLimit)"
        } else {
            Write-Info "PowerShell 5.x detected — using sequential scan"
        }
        Write-Host ""

        $resultsBag = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
        $scannedRef = [ref]0
        $errorRef   = [ref]0
        $matchRef   = [ref]0

        $spAppId       = $sp.AppId
        $spName        = $sp.DisplayName
        $scannedAt     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $totalSiteCount = $sites.Count   # precomputed once — avoids copying the whole $sites list into every runspace just to read a count

        if ($useParallel)
        {
            $sites | ForEach-Object -Parallel {

                $site        = $_
                $localSpId   = $using:spAppId
                $localSpName = $using:spName
                $localAt     = $using:scannedAt
                $bag         = $using:resultsBag
                $scRef       = $using:scannedRef
                $erRef       = $using:errorRef
                $maRef       = $using:matchRef
                $totalCount  = $using:totalSiteCount

                $currentCount = [System.Threading.Interlocked]::Increment($scRef)

                if ($currentCount % 500 -eq 0)
                {
                    $pct = [math]::Round(($currentCount / $totalCount) * 100)
                    Write-Host "  ↻ Scanned $currentCount / $totalCount sites  ($pct%)  — Matches so far: $($maRef.Value)" `
                               -ForegroundColor DarkGray
                }

                try {
                    $perms = Get-MgSitePermission -SiteId $site.Id -ErrorAction Stop

                    foreach ($perm in $perms)
                    {
                        $grantedAppIds = @()
                        if ($perm.GrantedToIdentitiesV2) {
                            $grantedAppIds += $perm.GrantedToIdentitiesV2 |
                                Where-Object { $_.Application } |
                                ForEach-Object { $_.Application.Id }
                        }
                        if ($perm.GrantedToIdentities) {
                            $grantedAppIds += $perm.GrantedToIdentities |
                                Where-Object { $_.Application } |
                                ForEach-Object { $_.Application.Id }
                        }

                        if ($grantedAppIds -contains $localSpId)
                        {
                            [System.Threading.Interlocked]::Increment($maRef) | Out-Null

                            $bag.Add([PSCustomObject]@{
                                SiteName     = $site.DisplayName
                                SiteUrl      = $site.WebUrl
                                SiteId       = $site.Id
                                PermissionId = $perm.Id
                                Roles        = ($perm.Roles -join ", ")
                                AppName      = $localSpName
                                AppId        = $localSpId
                                ScannedAt    = $localAt
                            })
                        }
                    }
                }
                catch {
                    [System.Threading.Interlocked]::Increment($erRef) | Out-Null
                }

            } -ThrottleLimit $ThrottleLimit
        }
        else
        {
            $scanned    = 0
            $errorCount = 0
            $matchCount = 0

            foreach ($site in $sites)
            {
                $scanned++
                Write-ProgressBar -Current $scanned -Total $sites.Count -Label $site.DisplayName

                try {
                    $perms = Get-MgSitePermission -SiteId $site.Id -ErrorAction Stop

                    foreach ($perm in $perms)
                    {
                        $grantedAppIds = @()
                        if ($perm.GrantedToIdentitiesV2) {
                            $grantedAppIds += $perm.GrantedToIdentitiesV2 |
                                Where-Object { $_.Application } |
                                ForEach-Object { $_.Application.Id }
                        }
                        if ($perm.GrantedToIdentities) {
                            $grantedAppIds += $perm.GrantedToIdentities |
                                Where-Object { $_.Application } |
                                ForEach-Object { $_.Application.Id }
                        }

                        if ($grantedAppIds -contains $sp.AppId)
                        {
                            $matchCount++
                            $resultsBag.Add([PSCustomObject]@{
                                SiteName     = $site.DisplayName
                                SiteUrl      = $site.WebUrl
                                SiteId       = $site.Id
                                PermissionId = $perm.Id
                                Roles        = ($perm.Roles -join ", ")
                                AppName      = $sp.DisplayName
                                AppId        = $sp.AppId
                                ScannedAt    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                            })
                        }
                    }
                }
                catch { $errorCount++ }
            }

            $scannedRef.Value = $scanned
            $errorRef.Value   = $errorCount
            $matchRef.Value   = $matchCount
        }

        Write-Progress -Activity "Scanning SharePoint Sites" -Completed

        $results = $resultsBag | Sort-Object SiteName

        Write-SectionHeader "SCAN RESULTS"

        Write-Host "  Sites Scanned   : " -NoNewline -ForegroundColor Gray
        Write-Host $scannedRef.Value -ForegroundColor White

        Write-Host "  Sites Matched   : " -NoNewline -ForegroundColor Gray
        Write-Host $matchRef.Value -ForegroundColor $(if ($matchRef.Value -gt 0) { "Green" } else { "Yellow" })

        Write-Host "  Sites Skipped   : " -NoNewline -ForegroundColor Gray
        Write-Host $errorRef.Value -ForegroundColor $(if ($errorRef.Value -gt 0) { "DarkYellow" } else { "Gray" })

        Write-Host ""

        if ($results.Count -gt 0) {
            Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGreen
            Write-Host "  │  Sites with explicit access granted to: $($sp.DisplayName)" -ForegroundColor Green
            Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGreen
            Write-Host ""

            foreach ($r in $results) {
                Write-Host "  ● " -NoNewline -ForegroundColor Green
                Write-Host "$($r.SiteName)" -ForegroundColor White
                Write-Host "    URL   : $($r.SiteUrl)"   -ForegroundColor Gray
                Write-Host "    Roles : $($r.Roles)"     -ForegroundColor Cyan
                Write-Host "    SiteId: $($r.SiteId)"    -ForegroundColor DarkGray
                Write-Host ""
            }

            if ($ExportCsv) {
                try {
                    $exportDir = Split-Path $ExportCsv -Parent
                    if ($exportDir -and -not (Test-Path $exportDir)) {
                        New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
                    }
                    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
                    Write-Success "Results exported to: $ExportCsv"
                }
                catch {
                    Write-Failure "CSV export failed: $($_.Exception.Message)"
                }
            }
        }
        else {
            Write-Host "  ⚠  No SharePoint sites found with explicit Sites.Selected access" -ForegroundColor Yellow
            Write-Host "     for application: $($sp.DisplayName)" -ForegroundColor DarkYellow
            Write-Host ""
            Write-Info "This could mean:"
            Write-Info "  • No sites have been explicitly granted to this app yet"
            Write-Info "  • The app uses a different permission model (not Sites.Selected)"
            Write-Info "  • Your authenticating app lacks Sites.FullControl.All consent"
        }

        Write-SectionHeader "COMPLETE"
        Write-Success "Audit finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Write-Host ""

        return $results
    }
    finally
    {
        # Always release the progress bar, and only close the Graph session
        # if THIS invocation opened it.
        Write-Progress -Activity "Scanning SharePoint Sites" -Completed -ErrorAction SilentlyContinue
        $secretPlain = $null
        if ($weConnected) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
