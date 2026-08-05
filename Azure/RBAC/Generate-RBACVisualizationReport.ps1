<#

Author       : Lakshmanan Thangaraj
Version      : 2.0
Created-On   : 02 March 2026
Modified-On  : 05 August 2026

.SYNOPSIS
    Generates an interactive HTML visualization report from Azure RBAC assignment CSV data.

.DESCRIPTION
    The Generate-RBACVisualizationReport function transforms Azure RBAC assignment data,
    previously exported to CSV (e.g. via Get-AzureRBACAssignments.ps1), into a self-contained,
    interactive HTML dashboard following the Cloud-Identity-Toolkit golden design system.

    Features:
        - Fixed sidebar navigation with dark / light mode toggle
        - Overview        — KPI stat cards, scope donut, object-type distribution, top principals
                           bar chart, top roles bar chart
        - Environments    — Auto-detected Dev / UAT / Prod / Test / Staging breakdown; per-env
                           stat cards, principal counts, role distribution
        - Principals      — Per-principal assignment breakdown with SignInName, searchable /
                           filterable / paginated table, slide-in detail drawer
        - Roles           — Per-role usage breakdown, permission-level badge, animated bar chart
        - Subscriptions   — Per-subscription cards with slide-in detail drawer showing metadata,
                           top roles, top principals, full assignment table
        - Raw Data        — All nine CSV columns (SubscriptionName, SubscriptionId, TenantId,
                           DisplayName, SignInName, ObjectType, RoleDefinitionName, ResourceType,
                           Scope) with multi-filter, text search, CSV export
        - Recommendations — Automated least-privilege findings (Owner-role ratio,
                           over-provisioned principals), custom-role design suggestions

.PARAMETER CsvPath
    Path to the input CSV file containing Azure RBAC assignments.
    Expected columns: SubscriptionName, SubscriptionId, TenantId, DisplayName, SignInName,
    ObjectType, RoleDefinitionName, ResourceType, Scope.
    (Matches the export format of Get-AzureRBACAssignments.ps1.)

.PARAMETER OutputPath
    Path where the generated HTML report will be saved.
    Default: RBAC-Visualization-Report.html

.PARAMETER GroupCategories
    Optional hashtable to categorize principals by naming pattern.
    Example: @{ Reader = @('*reader*'); Developer = @('*dev*') }
    Reserved for a future release — accepted but not yet surfaced in the HTML output.

.INPUTS
    None. Reads from -CsvPath on disk.

.OUTPUTS
    None. Writes a self-contained HTML file to -OutputPath.

.EXAMPLE
    Generate-RBACVisualizationReport -CsvPath ".\rbac-assignments.csv"

.EXAMPLE
    Generate-RBACVisualizationReport -CsvPath ".\rbac-assignments.csv" -OutputPath ".\reports\rbac-report.html"

.EXAMPLE
    Generate-RBACVisualizationReport -CsvPath ".\rbac-assignments.csv" -OutputPath "C:\Reports\rbac.html" -Verbose

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        2.0 (05-Aug-2026)      - Major redesign: golden dark/light dashboard theme,
                                 fixed sidebar navigation, dark/light toggle. New tabs:
                                 Environments (auto-detect dev/uat/prod/test/staging),
                                 Subscriptions (per-sub detail drawer), Principals
                                 (SignInName column + drawer), Raw Data (all 9 CSV
                                 columns, multi-filter, CSV export). __TOKEN__ injection
                                 pattern replaces string interpolation in here-string.
        1.0 (22-Jul-2026)      - Initial public release.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. PowerShell 5.1 or higher.
        2. Input CSV produced by Get-AzureRBACAssignments.ps1 (-ExportToCsv switch).
        3. Internet access for Chart.js CDN (cdn.jsdelivr.net) — charts degrade
           gracefully with an inline message when CDN is unavailable.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - -GroupCategories is accepted and computed but not yet surfaced in the HTML
          output. Treat as reserved for a future release.
        - Environment auto-detection scans SubscriptionName for the keywords
          dev / uat / prod / test / staging (case-insensitive). Subscriptions that
          do not match any keyword are labelled "Unknown". Pass a more specific
          SubscriptionName convention to improve accuracy.
        - The Principal-Role matrix is capped at 50 principals × 20 roles for
          browser performance on very large tenants.

.LINK
    Get-AzureRBACAssignments.ps1 (companion script — generates compatible CSV input)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/RBAC/Get-AzureRBACAssignments.ps1

#>

Function Generate-RBACVisualizationReport
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$CsvPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = 'C:\temp\RBAC-Visualization-Report.html',

        [Parameter(Mandatory = $false)]
        [hashtable]$GroupCategories = @{}
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    #region ── Helpers ────────────────────────────────────────────────────────

    function ConvertTo-JsonSafe
    {
        param([string]$Text)
        $Text `
            -replace '\\',      '\\\\' `
            -replace '"',       '\"'   `
            -replace "`r`n",    '\n'   `
            -replace "`n",      '\n'   `
            -replace "`r",      '\n'   `
            -replace "`t",      '\t'   `
            -replace '<',       '\u003c' `
            -replace '>',       '\u003e' `
            -replace '\$',      '\u0024'
    }

    function Get-Environment {
        param([string]$SubscriptionName)

        $name = $SubscriptionName.ToLower()

        switch -Regex ($name) {

            'non-prod|nonprod'                   { return 'NonProd' }
            'pre-prod|preprod|preproduction'     { return 'PreProd' }
            'prod|production'                    { return 'Prod' }

            'dev|development'                    { return 'Dev' }
            'uat'                                { return 'UAT' }
            'sit'                                { return 'SIT' }
            'qa'                                 { return 'QA' }
            'test|testing'                       { return 'Test' }

            'stage|staging'                      { return 'Staging' }
            'sandbox|sbx'                        { return 'Sandbox' }

            'poc|proof.?of.?concept'             { return 'POC' }
            'lab|demo'                           { return 'Lab' }

            'pilot'                              { return 'Pilot' }
            'training|train'                     { return 'Training' }

            'dr|disaster.?recovery'              { return 'DR' }

            'engineering|engg|eng'               { return 'Engineering' }

            default                              { return 'Unknown' }
        }
    }

    #endregion

    #region ── Banner ─────────────────────────────────────────────────────────

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║     Azure RBAC Visualization Report Generator  v2.0          ║' -ForegroundColor Cyan
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''

    #endregion

    #region ── Import & Validate ──────────────────────────────────────────────

    Write-Host '  [1/5] Importing CSV data...' -ForegroundColor Yellow
    try
    {
        $rbacData     = @(Import-Csv -Path $CsvPath -Encoding UTF8)
        $totalRecords = $rbacData.Count
        Write-Host "        ✓ Loaded $totalRecords RBAC assignments" -ForegroundColor Green
    }
    catch
    {
        Write-Error "Failed to import CSV: $_"
        return
    }

    if ($totalRecords -eq 0)
    {
        Write-Error "The CSV at '$CsvPath' contains no data rows. Nothing to report on."
        return
    }

    Write-Host '  [2/5] Validating CSV structure...' -ForegroundColor Yellow
    $requiredColumns = @('SubscriptionName','SubscriptionId','DisplayName','RoleDefinitionName','Scope')
    $csvColumns      = $rbacData[0].PSObject.Properties.Name
    foreach ($col in $requiredColumns)
    {
        if ($col -notin $csvColumns)
        {
            Write-Error "Missing required column: $col"
            return
        }
    }
    Write-Host '        ✓ CSV structure validated' -ForegroundColor Green

    #endregion

    #region ── Analysis ───────────────────────────────────────────────────────

    Write-Host '  [3/5] Analysing RBAC assignments...' -ForegroundColor Yellow

    # Enrich each row with Environment
    $enriched = $rbacData | ForEach-Object {
        $env = Get-Environment -SubscriptionName ($_.SubscriptionName)
        $_ | Select-Object *,
            @{ N = 'Environment'; E = { $env } },
            @{ N = 'TenantIdSafe';    E = { if ($_.PSObject.Properties['TenantId'])    { $_.TenantId    } else { '' } } },
            @{ N = 'SignInNameSafe';  E = { if ($_.PSObject.Properties['SignInName'])  { $_.SignInName  } else { '' } } },
            @{ N = 'ObjectTypeSafe';  E = { if ($_.PSObject.Properties['ObjectType'])  { $_.ObjectType  } else { 'Unknown' } } },
            @{ N = 'ResourceTypeSafe';E = { if ($_.PSObject.Properties['ResourceType']){ $_.ResourceType } else { '' } } }
    }

    $uniqueSubscriptions  = @($enriched | Select-Object -ExpandProperty SubscriptionName -Unique | Sort-Object)
    $uniqueRoles          = @($enriched | Select-Object -ExpandProperty RoleDefinitionName -Unique | Sort-Object)
    $uniquePrincipals     = @($enriched | Select-Object -ExpandProperty DisplayName -Unique | Sort-Object)
    $uniqueResourceTypes  = @($enriched | Where-Object { $_.ResourceTypeSafe } | Select-Object -ExpandProperty ResourceTypeSafe -Unique | Sort-Object)
    $uniqueEnvironments   = @($enriched | Select-Object -ExpandProperty Environment -Unique | Sort-Object)

    # Categorise principals (reserved for future surfacing)
    $categorizedPrincipals = @{}
    if ($GroupCategories.Count -gt 0)
    {
        foreach ($category in $GroupCategories.Keys)
        {
            $patterns = $GroupCategories[$category]
            $categorizedPrincipals[$category] = $uniquePrincipals | Where-Object {
                $principal = $_
                $matched   = $false
                foreach ($pattern in $patterns) { if ($principal -like $pattern) { $matched = $true; break } }
                $matched
            }
        }
    }

    # ── Scope distribution ──
    $scopeDistribution = $enriched | Group-Object -Property {
        if     ($_.Scope -match '/subscriptions/[^/]+$')   { 'Subscription' }
        elseif ($_.Scope -match '/resourceGroups/[^/]+$')  { 'Resource Group' }
        else                                                { 'Resource' }
    } | Select-Object Name, Count

    # ── Object type distribution ──
    $objectTypeDistribution = $enriched | Group-Object -Property ObjectTypeSafe |
        Select-Object Name, Count | Sort-Object Count -Descending

    # ── Top principals & roles ──
    $topPrincipals = $enriched | Group-Object -Property DisplayName |
        Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 15

    $topRoles = $enriched | Group-Object -Property RoleDefinitionName |
        Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 15

    # ── Resource type distribution ──
    $resourceTypeDistribution = $enriched | Where-Object { $_.ResourceTypeSafe } |
        Group-Object -Property ResourceTypeSafe |
        Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 20

    # ── Environment breakdown ──
    $environmentStats = $enriched | Group-Object -Property Environment | ForEach-Object {
        $envRows       = $_.Group
        $envPrincipals = @($envRows | Select-Object -ExpandProperty DisplayName -Unique).Count
        $envRoles      = @($envRows | Select-Object -ExpandProperty RoleDefinitionName -Unique).Count
        $envSubs       = @($envRows | Select-Object -ExpandProperty SubscriptionName -Unique).Count
        [PSCustomObject]@{
            Environment = $_.Name
            Count       = $_.Count
            Principals  = $envPrincipals
            Roles       = $envRoles
            Subscriptions = $envSubs
        }
    } | Sort-Object Count -Descending

    # ── Per-subscription stats ──
    $subscriptionStats = $enriched | Group-Object -Property SubscriptionName | ForEach-Object {
        $subRows   = $_.Group
        $firstRow  = $subRows[0]
        $subId     = $firstRow.SubscriptionId
        $tenantId  = $firstRow.TenantIdSafe
        $subEnv    = $firstRow.Environment
        $topSubRoles = $subRows | Group-Object -Property RoleDefinitionName |
            Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 5
        $topSubPrincipals = $subRows | Group-Object -Property DisplayName |
            Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 5
        [PSCustomObject]@{
            SubscriptionName = $_.Name
            SubscriptionId   = $subId
            TenantId         = $tenantId
            Environment      = $subEnv
            TotalAssignments = $_.Count
            UniquePrincipals = @($subRows | Select-Object -ExpandProperty DisplayName -Unique).Count
            UniqueRoles      = @($subRows | Select-Object -ExpandProperty RoleDefinitionName -Unique).Count
            TopRoles         = $topSubRoles
            TopPrincipals    = $topSubPrincipals
        }
    } | Sort-Object TotalAssignments -Descending

    Write-Host "        ✓ Analysis complete" -ForegroundColor Green
    Write-Host "          Subscriptions    : $($uniqueSubscriptions.Count)"   -ForegroundColor Gray
    Write-Host "          Unique Roles     : $($uniqueRoles.Count)"           -ForegroundColor Gray
    Write-Host "          Unique Principals: $($uniquePrincipals.Count)"      -ForegroundColor Gray
    Write-Host "          Resource Types   : $($uniqueResourceTypes.Count)"   -ForegroundColor Gray
    Write-Host "          Environments     : $($uniqueEnvironments -join ', ')" -ForegroundColor Gray

    #endregion

    #region ── JSON blobs ─────────────────────────────────────────────────────

    Write-Host '  [4/5] Building JSON data blobs...' -ForegroundColor Yellow

    $reportTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $reportDate      = Get-Date -Format 'MMMM dd, yyyy'

    # ── enrichedJson: all rows with Environment ──
    $enrichedJson = ($enriched | ForEach-Object {
        $subN  = ConvertTo-JsonSafe $_.SubscriptionName
        $subId = ConvertTo-JsonSafe $_.SubscriptionId
        $tenId = ConvertTo-JsonSafe $_.TenantIdSafe
        $dn    = ConvertTo-JsonSafe $_.DisplayName
        $sin   = ConvertTo-JsonSafe $_.SignInNameSafe
        $ot    = ConvertTo-JsonSafe $_.ObjectTypeSafe
        $role  = ConvertTo-JsonSafe $_.RoleDefinitionName
        $rt    = ConvertTo-JsonSafe $_.ResourceTypeSafe
        $sc    = ConvertTo-JsonSafe $_.Scope
        $ev    = ConvertTo-JsonSafe $_.Environment
        "{`"SubscriptionName`":`"$subN`",`"SubscriptionId`":`"$subId`",`"TenantId`":`"$tenId`",`"DisplayName`":`"$dn`",`"SignInName`":`"$sin`",`"ObjectType`":`"$ot`",`"RoleDefinitionName`":`"$role`",`"ResourceType`":`"$rt`",`"Scope`":`"$sc`",`"Environment`":`"$ev`"}"
    }) -join ','

    $scopeJson = ($scopeDistribution | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name
        "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $objTypeJson = ($objectTypeDistribution | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name
        "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $topPrincJson = ($topPrincipals | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name
        "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $topRolesJson = ($topRoles | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name
        "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $resTypeJson = ($resourceTypeDistribution | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name
        "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $envStatsJson = ($environmentStats | ForEach-Object {
        $e = ConvertTo-JsonSafe $_.Environment
        "{`"Environment`":`"$e`",`"Count`":$($_.Count),`"Principals`":$($_.Principals),`"Roles`":$($_.Roles),`"Subscriptions`":$($_.Subscriptions)}"
    }) -join ','

    $subStatsJson = ($subscriptionStats | ForEach-Object {
        $sn  = ConvertTo-JsonSafe $_.SubscriptionName
        $sid = ConvertTo-JsonSafe $_.SubscriptionId
        $tid = ConvertTo-JsonSafe $_.TenantId
        $ev  = ConvertTo-JsonSafe $_.Environment
        $trJson = ($_.TopRoles | ForEach-Object {
            $rn = ConvertTo-JsonSafe $_.Name
            "{`"Name`":`"$rn`",`"Count`":$($_.Count)}"
        }) -join ','
        $tpJson = ($_.TopPrincipals | ForEach-Object {
            $pn = ConvertTo-JsonSafe $_.Name
            "{`"Name`":`"$pn`",`"Count`":$($_.Count)}"
        }) -join ','
        "{`"SubscriptionName`":`"$sn`",`"SubscriptionId`":`"$sid`",`"TenantId`":`"$tid`",`"Environment`":`"$ev`",`"TotalAssignments`":$($_.TotalAssignments),`"UniquePrincipals`":$($_.UniquePrincipals),`"UniqueRoles`":$($_.UniqueRoles),`"TopRoles`":[$trJson],`"TopPrincipals`":[$tpJson]}"
    }) -join ','

    $uniqueSubsJson   = ($uniqueSubscriptions  | ForEach-Object { "`"$(ConvertTo-JsonSafe $_)`"" }) -join ','
    $uniqueRolesJson  = ($uniqueRoles           | ForEach-Object { "`"$(ConvertTo-JsonSafe $_)`"" }) -join ','
    $uniqueEnvsJson   = ($uniqueEnvironments    | ForEach-Object { "`"$(ConvertTo-JsonSafe $_)`"" }) -join ','

    Write-Host '        ✓ JSON blobs ready' -ForegroundColor Green

    #endregion

    #region ── HTML ───────────────────────────────────────────────────────────

    Write-Host '  [5/5] Generating HTML dashboard...' -ForegroundColor Yellow

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure RBAC Analysis Report</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg:#0d1117; --surface:#161b22; --surface2:#1c2333; --surface3:#243048;
  --border:#30363d; --accent:#388bfd; --accent2:#39c5cf; --accent3:#a371f7;
  --green:#3fb950; --amber:#d29922; --red:#f85149;
  --text:#e6edf3; --muted:#7d8590; --muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px; --radius-sm:6px; --shadow:0 4px 24px rgba(0,0,0,.5);
}
body.light-theme {
  --bg:#f6f8fa; --surface:#fff; --surface2:#f0f3f6; --surface3:#e4e9ef;
  --border:#d0d7de; --accent:#0969da; --accent2:#0284a8; --accent3:#7c3aed;
  --green:#1a7f37; --amber:#b08000; --red:#cf222e;
  --text:#1f2328; --muted:#636c76; --muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}

/* ── Sidebar ── */
#sidebar{position:fixed;top:0;left:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text)}
.sidebar-logo p{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.version-badge{display:inline-block;margin-top:5px;background:rgba(56,139,253,.15);color:var(--accent);font-family:var(--mono);font-size:10px;padding:1px 8px;border-radius:20px;border:1px solid rgba(56,139,253,.3)}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13.5px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.nav-btn .nav-badge{margin-left:auto;background:var(--surface3);color:var(--muted2);font-family:var(--mono);font-size:11px;padding:1px 7px;border-radius:20px}
.nav-btn:hover{color:var(--text);background:var(--surface2)}
.nav-btn.active{color:var(--accent);background:rgba(56,139,253,.1)}
.nav-btn.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);border-radius:0 2px 2px 0}
.theme-toggle-wrap{padding:10px 14px;border-top:1px solid var(--border)}
.theme-toggle{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;transition:all .2s}
.theme-toggle:hover{border-color:var(--accent);color:var(--text)}
.toggle-pill{width:34px;height:18px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--muted2);transition:transform .2s,background .2s}
body.light-theme .toggle-pill{background:var(--accent)}
body.light-theme .toggle-pill::after{transform:translateX(16px);background:#fff}
.sidebar-footer{padding:10px 18px 12px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);font-family:var(--mono);line-height:1.6}
kbd{display:inline-block;padding:1px 5px;background:var(--surface3);border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:11px;color:var(--muted)}

/* ── Main ── */
#main{margin-left:236px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:24px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn.btn-green{border-color:var(--green);color:var(--green)}
.btn.btn-green:hover{background:rgba(63,185,80,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

/* ── Stat cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:25px;font-weight:700;color:var(--text);line-height:1}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}

/* ── Panel / chart grid ── */
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.chart-wrap{position:relative;height:320px}
.chart-wrap.tall{height:400px}

/* ── Bar list ── */
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-family:var(--mono);font-size:11px;color:var(--muted2);width:140px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:30px;text-align:right;flex-shrink:0}

/* ── Environment cards ── */
.env-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px;margin-bottom:22px}
.env-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;cursor:pointer;transition:border-color .2s,transform .2s}
.env-card:hover{border-color:var(--accent2);transform:translateY(-2px)}
.env-badge{display:inline-block;padding:3px 12px;border-radius:20px;font-size:11px;font-weight:700;font-family:var(--mono);letter-spacing:.04em;margin-bottom:10px}
.env-badge.prod{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.4)}
.env-badge.uat{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.4)}
.env-badge.dev{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.4)}
.env-badge.test{background:rgba(163,113,247,.15);color:var(--accent3);border:1px solid rgba(163,113,247,.4)}
.env-badge.unknown{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
.env-total{font-size:28px;font-weight:700;color:var(--text);line-height:1}
.env-sub-stats{display:flex;gap:14px;margin-top:8px;font-size:12px;color:var(--muted2)}
.env-sub-stat{display:flex;flex-direction:column;gap:2px}
.env-sub-stat span:first-child{font-family:var(--mono);font-size:14px;color:var(--text);font-weight:600}

/* ── Subscription cards ── */
.sub-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-bottom:22px}
.sub-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;cursor:pointer;transition:border-color .2s,transform .2s;display:flex;flex-direction:column;gap:10px}
.sub-card:hover{border-color:var(--accent);transform:translateY(-2px)}
.sub-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:8px}
.sub-name{font-size:13px;font-weight:700;color:var(--text);line-height:1.3}
.sub-id{font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:3px;word-break:break-all}
.sub-stats-row{display:flex;gap:12px}
.sub-stat{display:flex;flex-direction:column;gap:1px}
.sub-stat span:first-child{font-family:var(--mono);font-size:15px;font-weight:700;color:var(--accent2)}
.sub-stat span:last-child{font-size:11px;color:var(--muted)}

/* ── Table ── */
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;padding:8px 11px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--accent)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:13px;flex-shrink:0}
.page-size-wrap{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.page-size-wrap select{padding:5px 8px;font-size:12px}
.rbac-table{width:100%;border-collapse:collapse}
.rbac-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);white-space:nowrap}
.rbac-table tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.rbac-table tbody tr:hover{background:var(--surface2)}
.rbac-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13px}
.td-mono{font-family:var(--mono);font-size:12px;color:var(--accent2)}
.td-scope{font-family:var(--mono);font-size:11px;color:var(--muted);max-width:260px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:12px}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}

/* ── Badges ── */
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600;font-family:var(--sans)}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3)}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3)}
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.badge-purple{background:rgba(163,113,247,.15);color:var(--accent3);border:1px solid rgba(163,113,247,.3)}
.badge-muted{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}

/* ── Info / warning boxes ── */
.info-box{background:rgba(56,139,253,.08);border-left:3px solid var(--accent);padding:14px 16px;border-radius:0 var(--radius-sm) var(--radius-sm) 0;margin-bottom:18px}
.info-box h4{color:var(--accent);font-size:13px;margin-bottom:4px}
.info-box p{color:var(--muted2);font-size:13px}
.warn-box{background:rgba(210,153,34,.08);border-left:3px solid var(--amber);padding:14px 16px;border-radius:0 var(--radius-sm) var(--radius-sm) 0;margin-bottom:18px}
.warn-box h4{color:var(--amber);font-size:13px;margin-bottom:4px}
.warn-box p{color:var(--muted2);font-size:13px}
.danger-box{background:rgba(248,81,73,.08);border-left:3px solid var(--red);padding:14px 16px;border-radius:0 var(--radius-sm) var(--radius-sm) 0;margin-bottom:12px}
.danger-box h4{color:var(--red);font-size:13px;margin-bottom:4px}
.danger-box p{color:var(--muted2);font-size:13px}

/* ── Detail drawer ── */
#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(680px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:24px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
.detail-toolbar-title{font-family:var(--mono);font-size:13px;color:var(--muted2);flex:1}
#detailClose{background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--red);color:#fff}
#detailContent{flex:1;overflow-y:auto}
.detail-header{margin-bottom:16px}
.detail-name{font-family:var(--mono);font-size:16px;color:var(--accent2);font-weight:600;word-break:break-all}
.detail-sub{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:4px;word-break:break-all}
.detail-meta-row{display:flex;gap:9px;flex-wrap:wrap;margin:12px 0}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:12px;color:var(--muted2)}
.detail-section{margin-top:18px}
.detail-section-title{font-size:11.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:9px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.detail-mini-row{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12.5px}
.detail-mini-row:last-child{border-bottom:none}
.detail-mini-label{color:var(--muted);width:120px;flex-shrink:0;font-size:12px}
.detail-mini-val{color:var(--text);font-family:var(--mono);font-size:12px;flex:1;word-break:break-all}

/* ── Toast ── */
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

/* ── Mobile ── */
@media(max-width:768px){
  #sidebar{transform:translateX(-236px);transition:transform .3s}
  #sidebar.open{transform:translateX(0)}
  #main{margin-left:0}
  .page{padding:18px}
  #menuToggle{display:flex}
  .chart-grid{grid-template-columns:1fr}
}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<!-- ════════════════ SIDEBAR ════════════════ -->
<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🔐</div>
    <h1>RBAC Analysis</h1>
    <p>__REPORTDATE__</p>
    <span class="version-badge">v2.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">📊</span> Overview
    </button>
    <button class="nav-btn" onclick="showPage('environments',this)">
      <span class="nav-icon">🌍</span> Environments
    </button>
    <button class="nav-btn" onclick="showPage('principals',this)">
      <span class="nav-icon">👥</span> Principals
      <span class="nav-badge">__PRINCIPALCOUNT__</span>
    </button>
    <button class="nav-btn" onclick="showPage('roles',this)">
      <span class="nav-icon">🎭</span> Roles
      <span class="nav-badge">__ROLECOUNT__</span>
    </button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)">
      <span class="nav-icon">📋</span> Subscriptions
      <span class="nav-badge">__SUBCOUNT__</span>
    </button>
    <button class="nav-btn" onclick="showPage('rawdata',this)">
      <span class="nav-icon">🗄</span> Raw Data
      <span class="nav-badge">__TOTALRECORDS__</span>
    </button>
    <button class="nav-btn" onclick="showPage('recommendations',this)">
      <span class="nav-icon">💡</span> Recommendations
    </button>
  </div>
  <div class="theme-toggle-wrap">
    <button class="theme-toggle" onclick="toggleTheme()">
      <span id="themeIcon">🌙</span>
      <span id="themeLabel" style="flex:1;text-align:left">Dark Mode</span>
      <span class="toggle-pill"></span>
    </button>
  </div>
  <div class="sidebar-footer">
    Generated<br>__REPORTTIMESTAMP__<br>
    <span style="color:var(--accent2)">⌨</span>&nbsp;<kbd>/</kbd> search&nbsp;&nbsp;<kbd>Esc</kbd> close drawer
  </div>
</nav>

<!-- ════════════════ MAIN ════════════════ -->
<main id="main">

<!-- ── OVERVIEW ── -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">RBAC Overview</div>
      <div class="page-subtitle">Tenant-wide identity &amp; access snapshot</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportAllCSV()">⬇ Export Full CSV</button>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">📌</div><div class="stat-value">__TOTALRECORDS__</div><div class="stat-label">Total Assignments</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">👤</div><div class="stat-value">__PRINCIPALCOUNT__</div><div class="stat-label">Unique Principals</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">🎭</div><div class="stat-value">__ROLECOUNT__</div><div class="stat-label">Unique Roles</div></div>
    <div class="stat-card c-green"><div class="stat-icon">🗂</div><div class="stat-value">__SUBCOUNT__</div><div class="stat-label">Subscriptions</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">🌍</div><div class="stat-value">__ENVCOUNT__</div><div class="stat-label">Environments</div></div>
    <div class="stat-card c-red"><div class="stat-icon">⚠</div><div class="stat-value" id="ownerCountStat">-</div><div class="stat-label">Owner Assignments</div></div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🍩 Scope Distribution</div>
      <div class="chart-wrap"><canvas id="scopeChart"></canvas></div>
    </div>
    <div class="panel">
      <div class="section-title">👤 Object Type Distribution</div>
      <div class="chart-wrap"><canvas id="objTypeChart"></canvas></div>
    </div>
  </div>

  <div class="panel">
    <div class="section-title">🏆 Top 15 Principals by Assignment Count</div>
    <div class="chart-wrap tall"><canvas id="topPrincChart"></canvas></div>
  </div>

  <div class="panel">
    <div class="section-title">🎯 Top 15 Roles by Usage</div>
    <div class="chart-wrap tall"><canvas id="topRolesChart"></canvas></div>
  </div>
</section>

<!-- ── ENVIRONMENTS ── -->
<section id="page-environments" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Environment Breakdown</div>
      <div class="page-subtitle">Auto-detected from subscription name keywords</div>
    </div>
  </div>
  <div class="info-box">
    <h4>📌 Detection Logic</h4>
    <p>Environments are inferred by scanning each SubscriptionName for the keywords: <strong>prod / production, uat / staging, dev / development, test / testing</strong>. Subscriptions not matching any keyword are labelled <em>Unknown</em>.</p>
  </div>
  <div class="env-grid" id="envCardsContainer"></div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Assignments per Environment</div>
      <div class="chart-wrap"><canvas id="envAssignChart"></canvas></div>
    </div>
    <div class="panel">
      <div class="section-title">👥 Principals per Environment</div>
      <div class="chart-wrap"><canvas id="envPrincChart"></canvas></div>
    </div>
  </div>
</section>

<!-- ── PRINCIPALS ── -->
<section id="page-principals" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Principal Analysis</div>
      <div class="page-subtitle">Per-user / group / service-principal assignment breakdown</div>
    </div>
    <div class="btn-group">
      <button class="btn btn-green" onclick="exportPrincCSV()">⬇ Export CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="princSearch" placeholder="Search name or sign-in…" oninput="renderPrincTable()"/>
    </div>
    <select id="princEnvFilter" onchange="renderPrincTable()"><option value="">All Environments</option></select>
    <select id="princTypeFilter" onchange="renderPrincTable()"><option value="">All Object Types</option></select>
    <div class="page-size-wrap">Show <select id="princPageSize" onchange="renderPrincTable()"><option>25</option><option>50</option><option>100</option></select></div>
    <span class="result-count" id="princResultCount"></span>
  </div>
  <div style="overflow-x:auto">
    <table class="rbac-table">
      <thead><tr>
        <th>Principal</th>
        <th>Sign-In Name</th>
        <th>Object Type</th>
        <th>Assignments</th>
        <th>Unique Roles</th>
        <th>Subscriptions</th>
        <th>Environment(s)</th>
      </tr></thead>
      <tbody id="princTableBody"></tbody>
    </table>
  </div>
  <div class="pagination" id="princPagination"></div>
</section>

<!-- ── ROLES ── -->
<section id="page-roles" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Role Usage Analysis</div>
      <div class="page-subtitle">How roles are distributed across the tenant</div>
    </div>
    <div class="btn-group">
      <button class="btn btn-green" onclick="exportRolesCSV()">⬇ Export CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="roleSearch" placeholder="Search roles…" oninput="renderRoleTable()"/>
    </div>
    <select id="rolePermFilter" onchange="renderRoleTable()">
      <option value="">All Levels</option>
      <option value="owner">Owner</option>
      <option value="contributor">Contributor</option>
      <option value="reader">Reader</option>
      <option value="custom">Custom / Other</option>
    </select>
    <span class="result-count" id="roleResultCount"></span>
  </div>
  <div style="overflow-x:auto">
    <table class="rbac-table">
      <thead><tr>
        <th>Role Name</th>
        <th>Assignments</th>
        <th>Unique Principals</th>
        <th>Subscriptions</th>
        <th>Permission Level</th>
      </tr></thead>
      <tbody id="roleTableBody"></tbody>
    </table>
  </div>
  <div class="panel" style="margin-top:22px">
    <div class="section-title">📊 Top 10 Roles — Bar Distribution</div>
    <div id="roleBarList"></div>
  </div>
</section>

<!-- ── SUBSCRIPTIONS ── -->
<section id="page-subscriptions" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Subscriptions</div>
      <div class="page-subtitle">Per-subscription assignment summary — click a card to drill down</div>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="subSearch" placeholder="Search subscriptions…" oninput="renderSubCards()"/>
    </div>
    <select id="subEnvFilter" onchange="renderSubCards()"><option value="">All Environments</option></select>
  </div>
  <div class="sub-grid" id="subCardsContainer"></div>
</section>

<!-- ── RAW DATA ── -->
<section id="page-rawdata" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Raw Data</div>
      <div class="page-subtitle">All __TOTALRECORDS__ RBAC assignments — full 9-column view</div>
    </div>
    <div class="btn-group">
      <button class="btn btn-green" onclick="exportRawCSV()">⬇ Export Filtered CSV</button>
    </div>
  </div>
  <div class="toolbar" style="flex-wrap:wrap;gap:8px">
    <div class="search-wrap" style="min-width:220px">
      <span class="icon">🔎</span>
      <input type="text" id="rawSearch" placeholder="Search all fields…" oninput="renderRawTable()"/>
    </div>
    <select id="rawSubFilter"  onchange="renderRawTable()"><option value="">All Subscriptions</option></select>
    <select id="rawRoleFilter" onchange="renderRawTable()"><option value="">All Roles</option></select>
    <select id="rawEnvFilter"  onchange="renderRawTable()"><option value="">All Environments</option></select>
    <select id="rawTypeFilter" onchange="renderRawTable()"><option value="">All Object Types</option></select>
    <div class="page-size-wrap">Show <select id="rawPageSize" onchange="renderRawTable()"><option>25</option><option>50</option><option>100</option></select></div>
    <span class="result-count" id="rawResultCount"></span>
  </div>
  <div style="overflow-x:auto">
    <table class="rbac-table">
      <thead><tr>
        <th>Subscription</th>
        <th>Subscription ID</th>
        <th>Tenant ID</th>
        <th>Display Name</th>
        <th>Sign-In Name</th>
        <th>Object Type</th>
        <th>Role</th>
        <th>Resource Type</th>
        <th>Scope</th>
        <th>Environment</th>
      </tr></thead>
      <tbody id="rawTableBody"></tbody>
    </table>
  </div>
  <div class="pagination" id="rawPagination"></div>
</section>

<!-- ── RECOMMENDATIONS ── -->
<section id="page-recommendations" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Recommendations</div>
      <div class="page-subtitle">Automated least-privilege findings &amp; custom-role design guidance</div>
    </div>
  </div>
  <div id="recoContent"></div>
</section>

</main><!-- /#main -->

<!-- ════════════════ DETAIL DRAWER ════════════════ -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDetail()"></div>
  <div id="detailDrawer">
    <div class="detail-toolbar">
      <span class="detail-toolbar-title" id="detailTitle">Details</span>
      <button id="detailClose" onclick="closeDetail()" title="Close (Esc)">✕</button>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<!-- ════════════════ TOAST ════════════════ -->
<div id="toast"></div>

<!-- ════════════════ JAVASCRIPT ════════════════ -->
<script>
// ── Data ──────────────────────────────────────────────────────────────────────
const DATA        = [__ENRICHED_JSON__];
const SCOPE_DIST  = [__SCOPE_JSON__];
const OBJ_DIST    = [__OBJTYPE_JSON__];
const TOP_PRINC   = [__TOP_PRINC_JSON__];
const TOP_ROLES   = [__TOP_ROLES_JSON__];
const RES_TYPE    = [__RESTYPE_JSON__];
const ENV_STATS   = [__ENVSTATS_JSON__];
const SUB_STATS   = [__SUBSTATS_JSON__];
const UNIQUE_SUBS = [__UNIQUE_SUBS_JSON__];
const UNIQUE_ROLES= [__UNIQUE_ROLES_JSON__];
const UNIQUE_ENVS = [__UNIQUE_ENVS_JSON__];

// ── Escape helpers ────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

// ── Theme ─────────────────────────────────────────────────────────────────────
function toggleTheme(){
  document.body.classList.toggle('light-theme');
  const isLight=document.body.classList.contains('light-theme');
  document.getElementById('themeIcon').textContent=isLight?'☀':'🌙';
  document.getElementById('themeLabel').textContent=isLight?'Light Mode':'Dark Mode';
  localStorage.setItem('rbac-theme',isLight?'light':'dark');
}
(function(){
  const saved=localStorage.getItem('rbac-theme');
  if(saved==='light'){document.body.classList.add('light-theme');document.getElementById('themeIcon').textContent='☀';document.getElementById('themeLabel').textContent='Light Mode';}
})();

// ── Page navigation ───────────────────────────────────────────────────────────
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
}

// ── Toast ─────────────────────────────────────────────────────────────────────
let toastTimer;
function showToast(msg,icon){
  const t=document.getElementById('toast');
  t.innerHTML=(icon||'✅')+' '+escH(msg);
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>t.classList.remove('show'),3000);
}

// ── Detail drawer ─────────────────────────────────────────────────────────────
function openDetail(html,title){
  document.getElementById('detailTitle').textContent=title||'Details';
  document.getElementById('detailContent').innerHTML=html;
  document.getElementById('detailPanel').classList.add('open');
  document.body.style.overflow='hidden';
  document.getElementById('detailContent').scrollTo(0,0);
}
function closeDetail(){
  document.getElementById('detailPanel').classList.remove('open');
  document.body.style.overflow='';
}

// ── Palette ───────────────────────────────────────────────────────────────────
const PALETTE=['#388bfd','#39c5cf','#a371f7','#3fb950','#d29922','#f85149','#58a6ff','#56d364','#ffa657','#ff7b72','#79c0ff','#d2a8ff'];
function envColor(env){
  const e=(env||'').toLowerCase();
  if(e==='prod'||e==='production')return'var(--red)';
  if(e==='uat'||e==='staging')   return'var(--amber)';
  if(e==='dev'||e==='development')return'var(--green)';
  if(e==='test'||e==='testing')  return'var(--accent3)';
  return'var(--muted)';
}
function envBadgeClass(env){
  const e=(env||'').toLowerCase();
  if(e==='prod'||e==='production')return'env-badge prod';
  if(e==='uat'||e==='staging')   return'env-badge uat';
  if(e==='dev'||e==='development')return'env-badge dev';
  if(e==='test'||e==='testing')  return'env-badge test';
  return'env-badge unknown';
}
function permBadge(role){
  const r=(role||'').toLowerCase();
  if(r.includes('owner'))      return'<span class="badge badge-red">Owner</span>';
  if(r.includes('contributor'))return'<span class="badge badge-amber">Contributor</span>';
  if(r.includes('reader'))     return'<span class="badge badge-green">Reader</span>';
  return'<span class="badge badge-muted">Custom</span>';
}

// ── Charts ────────────────────────────────────────────────────────────────────
function safeChart(id,cfg){
  const el=document.getElementById(id);
  if(!el||typeof Chart==='undefined')return;
  const existing=Chart.getChart(el);
  if(existing)existing.destroy();
  new Chart(el,cfg);
}

function initOverviewCharts(){
  const isDark=!document.body.classList.contains('light-theme');
  const textColor=isDark?'#adbac7':'#424a53';

  safeChart('scopeChart',{type:'doughnut',data:{
    labels:SCOPE_DIST.map(s=>s.Name),
    datasets:[{data:SCOPE_DIST.map(s=>s.Count),backgroundColor:PALETTE,borderWidth:2,borderColor:'transparent'}]
  },options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:textColor,padding:12,font:{size:11}}},tooltip:{callbacks:{label:ctx=>{const tot=ctx.dataset.data.reduce((a,b)=>a+b,0);return ctx.label+': '+ctx.parsed+' ('+(ctx.parsed/tot*100).toFixed(1)+'%)';}}}}}});

  safeChart('objTypeChart',{type:'pie',data:{
    labels:OBJ_DIST.map(o=>o.Name||'Unknown'),
    datasets:[{data:OBJ_DIST.map(o=>o.Count),backgroundColor:PALETTE.slice(3),borderWidth:2,borderColor:'transparent'}]
  },options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:textColor,padding:12,font:{size:11}}},tooltip:{callbacks:{label:ctx=>{const tot=ctx.dataset.data.reduce((a,b)=>a+b,0);return ctx.label+': '+ctx.parsed+' ('+(ctx.parsed/tot*100).toFixed(1)+'%)';}}}}}});

  safeChart('topPrincChart',{type:'bar',data:{
    labels:TOP_PRINC.map(p=>p.Name.length>45?p.Name.slice(0,45)+'…':p.Name),
    datasets:[{label:'Assignments',data:TOP_PRINC.map(p=>p.Count),backgroundColor:'#388bfd',borderRadius:4}]
  },options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{title:ctx=>TOP_PRINC[ctx[0].dataIndex].Name}}},scales:{x:{beginAtZero:true,grid:{color:'rgba(127,127,127,.1)'},ticks:{color:textColor}},y:{grid:{display:false},ticks:{color:textColor}}}}});

  safeChart('topRolesChart',{type:'bar',data:{
    labels:TOP_ROLES.map(r=>r.Name.length>45?r.Name.slice(0,45)+'…':r.Name),
    datasets:[{label:'Usage',data:TOP_ROLES.map(r=>r.Count),backgroundColor:'#3fb950',borderRadius:4}]
  },options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{title:ctx=>TOP_ROLES[ctx[0].dataIndex].Name}}},scales:{x:{beginAtZero:true,grid:{color:'rgba(127,127,127,.1)'},ticks:{color:textColor}},y:{grid:{display:false},ticks:{color:textColor}}}}});
}

function initEnvCharts(){
  const isDark=!document.body.classList.contains('light-theme');
  const textColor=isDark?'#adbac7':'#424a53';
  const colors=ENV_STATS.map(e=>envColor(e.Environment));

  safeChart('envAssignChart',{type:'bar',data:{
    labels:ENV_STATS.map(e=>e.Environment),
    datasets:[{label:'Assignments',data:ENV_STATS.map(e=>e.Count),backgroundColor:colors,borderRadius:6}]
  },options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:textColor}},y:{beginAtZero:true,grid:{color:'rgba(127,127,127,.1)'},ticks:{color:textColor}}}}});

  safeChart('envPrincChart',{type:'bar',data:{
    labels:ENV_STATS.map(e=>e.Environment),
    datasets:[{label:'Principals',data:ENV_STATS.map(e=>e.Principals),backgroundColor:colors.map(c=>c+'88'),borderRadius:6}]
  },options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:textColor}},y:{beginAtZero:true,grid:{color:'rgba(127,127,127,.1)'},ticks:{color:textColor}}}}});
}

// ── Overview owner count ───────────────────────────────────────────────────────
function setOwnerCount(){
  const cnt=DATA.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner')).length;
  document.getElementById('ownerCountStat').textContent=cnt;
}

// ── Environment cards ─────────────────────────────────────────────────────────
function renderEnvCards(){
  const container=document.getElementById('envCardsContainer');
  container.innerHTML=ENV_STATS.map(e=>`
    <div class="env-card" onclick="">
      <span class="${envBadgeClass(e.Environment)}">${escH(e.Environment)}</span>
      <div class="env-total">${e.Count} <span style="font-size:13px;font-weight:400;color:var(--muted)">assignments</span></div>
      <div class="env-sub-stats">
        <div class="env-sub-stat"><span>${e.Subscriptions}</span><span>Subscriptions</span></div>
        <div class="env-sub-stat"><span>${e.Principals}</span><span>Principals</span></div>
        <div class="env-sub-stat"><span>${e.Roles}</span><span>Roles</span></div>
      </div>
    </div>`).join('');
}

// ── Principals table ──────────────────────────────────────────────────────────
let princData=[], princPage=1, princPageSz=25;
function buildPrincData(){
  const map={};
  DATA.forEach(r=>{
    const k=r.DisplayName;
    if(!map[k])map[k]={name:k,signIn:r.SignInName,type:r.ObjectType||'Unknown',count:0,roles:new Set(),subs:new Set(),envs:new Set()};
    map[k].count++;
    map[k].roles.add(r.RoleDefinitionName);
    map[k].subs.add(r.SubscriptionName);
    map[k].envs.add(r.Environment);
    if(!map[k].signIn&&r.SignInName)map[k].signIn=r.SignInName;
  });
  princData=Object.values(map).sort((a,b)=>b.count-a.count);

  // populate type filter
  const types=[...new Set(princData.map(p=>p.type))].sort();
  const tf=document.getElementById('princTypeFilter');
  types.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;tf.appendChild(o);});

  // populate env filter
  const ef=document.getElementById('princEnvFilter');
  UNIQUE_ENVS.forEach(e=>{const o=document.createElement('option');o.value=e;o.textContent=e;ef.appendChild(o);});
}
function renderPrincTable(){
  const q=(document.getElementById('princSearch').value||'').toLowerCase();
  const envF=document.getElementById('princEnvFilter').value;
  const typeF=document.getElementById('princTypeFilter').value;
  princPageSz=+document.getElementById('princPageSize').value;

  let filtered=princData.filter(p=>{
    if(q&&!p.name.toLowerCase().includes(q)&&!p.signIn.toLowerCase().includes(q))return false;
    if(envF&&![...p.envs].includes(envF))return false;
    if(typeF&&p.type!==typeF)return false;
    return true;
  });
  document.getElementById('princResultCount').textContent=filtered.length+' result'+(filtered.length!==1?'s':'');
  const pages=Math.max(1,Math.ceil(filtered.length/princPageSz));
  if(princPage>pages)princPage=1;
  const slice=filtered.slice((princPage-1)*princPageSz,princPage*princPageSz);

  const tbody=document.getElementById('princTableBody');
  tbody.innerHTML=slice.map(p=>`<tr onclick="openPrincDetail('${escJ(p.name)}')">
    <td><strong>${escH(p.name)}</strong></td>
    <td class="td-mono" style="font-size:11px">${escH(p.signIn||'—')}</td>
    <td><span class="badge badge-blue">${escH(p.type)}</span></td>
    <td>${p.count}</td>
    <td>${p.roles.size}</td>
    <td>${p.subs.size}</td>
    <td>${[...p.envs].map(e=>`<span class="${envBadgeClass(e)}" style="margin-right:3px">${escH(e)}</span>`).join('')}</td>
  </tr>`).join('');

  renderPagination('princPagination',pages,princPage,pg=>{princPage=pg;renderPrincTable();});
}
function openPrincDetail(name){
  const rows=DATA.filter(r=>r.DisplayName===name);
  if(!rows.length)return;
  const p=princData.find(x=>x.name===name);
  const roleList=[...new Map(rows.map(r=>[r.RoleDefinitionName,r])).values()];
  const html=`
    <div class="detail-header">
      <div class="detail-name">${escH(name)}</div>
      ${p.signIn?`<div class="detail-sub">${escH(p.signIn)}</div>`:''}
    </div>
    <div class="detail-meta-row">
      <span class="detail-chip"><span class="badge badge-blue">${escH(p.type)}</span></span>
      <span class="detail-chip">📌 ${p.count} assignments</span>
      <span class="detail-chip">🎭 ${p.roles.size} roles</span>
      <span class="detail-chip">🗂 ${p.subs.size} subscriptions</span>
      ${[...p.envs].map(e=>`<span class="detail-chip"><span class="${envBadgeClass(e)}">${escH(e)}</span></span>`).join('')}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Roles Assigned</div>
      ${roleList.map(r=>`<div class="detail-mini-row">${permBadge(r.RoleDefinitionName)}<span style="font-family:var(--mono);font-size:12px;color:var(--text);margin-left:8px">${escH(r.RoleDefinitionName)}</span></div>`).join('')}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">All Assignments (${rows.length})</div>
      <div style="overflow-x:auto;margin-top:6px">
        <table class="rbac-table">
          <thead><tr><th>Subscription</th><th>Role</th><th>Resource Type</th><th>Scope</th></tr></thead>
          <tbody>${rows.map(r=>`<tr>
            <td>${escH(r.SubscriptionName)}</td>
            <td>${escH(r.RoleDefinitionName)}</td>
            <td>${escH(r.ResourceType||'—')}</td>
            <td class="td-scope" title="${escH(r.Scope)}">${escH(r.Scope)}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>
    </div>`;
  openDetail(html, name);
}
function exportPrincCSV(){
  const rows=['Principal,SignInName,ObjectType,Assignments,UniqueRoles,Subscriptions,Environments'];
  princData.forEach(p=>rows.push(`"${p.name.replace(/"/g,'""')}","${(p.signIn||'').replace(/"/g,'""')}","${p.type}",${p.count},${p.roles.size},${p.subs.size},"${[...p.envs].join('; ')}"`));
  dlFile(rows.join('\r\n'),'rbac-principals.csv','text/csv');
  showToast('Exported '+princData.length+' principals');
}

// ── Roles table ───────────────────────────────────────────────────────────────
let rolesData=[];
function buildRolesData(){
  const map={};
  DATA.forEach(r=>{
    const k=r.RoleDefinitionName;
    if(!map[k])map[k]={name:k,count:0,principals:new Set(),subs:new Set()};
    map[k].count++;
    map[k].principals.add(r.DisplayName);
    map[k].subs.add(r.SubscriptionName);
  });
  rolesData=Object.values(map).sort((a,b)=>b.count-a.count);
}
function renderRoleTable(){
  const q=(document.getElementById('roleSearch').value||'').toLowerCase();
  const permF=document.getElementById('rolePermFilter').value;
  let filtered=rolesData.filter(r=>{
    if(q&&!r.name.toLowerCase().includes(q))return false;
    if(permF){
      const rn=r.name.toLowerCase();
      if(permF==='owner'&&!rn.includes('owner'))return false;
      if(permF==='contributor'&&!rn.includes('contributor'))return false;
      if(permF==='reader'&&!rn.includes('reader'))return false;
      if(permF==='custom'&&(rn.includes('owner')||rn.includes('contributor')||rn.includes('reader')))return false;
    }
    return true;
  });
  document.getElementById('roleResultCount').textContent=filtered.length+' result'+(filtered.length!==1?'s':'');
  const tbody=document.getElementById('roleTableBody');
  tbody.innerHTML=filtered.map(r=>`<tr>
    <td><strong>${escH(r.name)}</strong></td>
    <td>${r.count}</td>
    <td>${r.principals.size}</td>
    <td>${r.subs.size}</td>
    <td>${permBadge(r.name)}</td>
  </tr>`).join('');

  // bar list (top 10 of all roles, not filtered)
  const top10=rolesData.slice(0,10);
  const maxC=top10[0]?top10[0].count:1;
  document.getElementById('roleBarList').innerHTML=top10.map((r,i)=>`
    <div class="bar-row">
      <span class="bar-label" title="${escH(r.name)}">${escH(r.name.length>30?r.name.slice(0,30)+'…':r.name)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:0%;background:${PALETTE[i%PALETTE.length]}" data-pct="${Math.round(r.count/maxC*100)}"></div></div>
      <span class="bar-count">${r.count}</span>
    </div>`).join('');
  requestAnimationFrame(()=>document.querySelectorAll('#roleBarList .bar-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';}));
}
function exportRolesCSV(){
  const rows=['RoleName,Assignments,UniquePrincipals,Subscriptions,PermissionLevel'];
  rolesData.forEach(r=>{
    const lvl=r.name.toLowerCase().includes('owner')?'Owner':r.name.toLowerCase().includes('contributor')?'Contributor':r.name.toLowerCase().includes('reader')?'Reader':'Custom';
    rows.push(`"${r.name.replace(/"/g,'""')}",${r.count},${r.principals.size},${r.subs.size},"${lvl}"`);
  });
  dlFile(rows.join('\r\n'),'rbac-roles.csv','text/csv');
  showToast('Exported '+rolesData.length+' roles');
}

// ── Subscriptions ─────────────────────────────────────────────────────────────
function renderSubCards(){
  const q=(document.getElementById('subSearch').value||'').toLowerCase();
  const envF=document.getElementById('subEnvFilter').value;
  const filtered=SUB_STATS.filter(s=>{
    if(q&&!s.SubscriptionName.toLowerCase().includes(q)&&!s.SubscriptionId.toLowerCase().includes(q))return false;
    if(envF&&s.Environment!==envF)return false;
    return true;
  });
  document.getElementById('subCardsContainer').innerHTML=filtered.map((s,i)=>`
    <div class="sub-card" onclick="openSubDetail(${i})">
      <div class="sub-card-head">
        <div>
          <div class="sub-name">${escH(s.SubscriptionName)}</div>
          <div class="sub-id">${escH(s.SubscriptionId)}</div>
        </div>
        <span class="${envBadgeClass(s.Environment)}">${escH(s.Environment)}</span>
      </div>
      <div class="sub-stats-row">
        <div class="sub-stat"><span>${s.TotalAssignments}</span><span>Assignments</span></div>
        <div class="sub-stat"><span>${s.UniquePrincipals}</span><span>Principals</span></div>
        <div class="sub-stat"><span>${s.UniqueRoles}</span><span>Roles</span></div>
      </div>
    </div>`).join('');
  window._filteredSubStats=filtered;
}
function openSubDetail(idx){
  const s=window._filteredSubStats[idx];
  if(!s)return;
  const subRows=DATA.filter(r=>r.SubscriptionName===s.SubscriptionName);
  const ownerCnt=subRows.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner')).length;
  const html=`
    <div class="detail-header">
      <div class="detail-name">${escH(s.SubscriptionName)}</div>
      <div class="detail-sub">${escH(s.SubscriptionId)}</div>
    </div>
    <div class="detail-meta-row">
      <span class="detail-chip"><span class="${envBadgeClass(s.Environment)}">${escH(s.Environment)}</span></span>
      <span class="detail-chip">TenantId: <span class="td-mono" style="font-size:11px">${escH(s.TenantId||'—')}</span></span>
      <span class="detail-chip">📌 ${s.TotalAssignments} assignments</span>
      <span class="detail-chip">👤 ${s.UniquePrincipals} principals</span>
      <span class="detail-chip">🎭 ${s.UniqueRoles} roles</span>
      ${ownerCnt>0?`<span class="detail-chip" style="color:var(--red)">⚠ ${ownerCnt} Owner</span>`:''}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Top Roles</div>
      ${s.TopRoles.map(r=>`<div class="detail-mini-row">${permBadge(r.Name)}<span style="font-family:var(--mono);font-size:12px;margin-left:8px;flex:1">${escH(r.Name)}</span><span style="font-family:var(--mono);font-size:12px;color:var(--muted)">${r.Count}</span></div>`).join('')}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Top Principals</div>
      ${s.TopPrincipals.map(p=>`<div class="detail-mini-row"><span style="font-size:13px">👤</span><span style="flex:1;font-size:13px;margin-left:8px">${escH(p.Name)}</span><span style="font-family:var(--mono);font-size:12px;color:var(--muted)">${p.Count}</span></div>`).join('')}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">All Assignments (${subRows.length})</div>
      <div style="overflow-x:auto;margin-top:6px;max-height:340px;overflow-y:auto">
        <table class="rbac-table">
          <thead><tr><th>Principal</th><th>Sign-In</th><th>Role</th><th>Resource Type</th><th>Scope</th></tr></thead>
          <tbody>${subRows.map(r=>`<tr>
            <td>${escH(r.DisplayName)}</td>
            <td class="td-mono" style="font-size:11px">${escH(r.SignInName||'—')}</td>
            <td>${escH(r.RoleDefinitionName)}</td>
            <td>${escH(r.ResourceType||'—')}</td>
            <td class="td-scope" title="${escH(r.Scope)}">${escH(r.Scope)}</td>
          </tr>`).join('')}</tbody>
        </table>
      </div>
    </div>`;
  openDetail(html, s.SubscriptionName);
}

// ── Raw data table ────────────────────────────────────────────────────────────
let rawPage=1, rawPageSz=25, rawFiltered=DATA;
function populateRawFilters(){
  const subF=document.getElementById('rawSubFilter');
  const roleF=document.getElementById('rawRoleFilter');
  const envF=document.getElementById('rawEnvFilter');
  const typeF=document.getElementById('rawTypeFilter');
  UNIQUE_SUBS.forEach(s=>{const o=document.createElement('option');o.value=s;o.textContent=s;subF.appendChild(o);});
  UNIQUE_ROLES.forEach(r=>{const o=document.createElement('option');o.value=r;o.textContent=r;roleF.appendChild(o);});
  UNIQUE_ENVS.forEach(e=>{const o=document.createElement('option');o.value=e;o.textContent=e;envF.appendChild(o);});
  const types=[...new Set(DATA.map(r=>r.ObjectType||'Unknown'))].sort();
  types.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;typeF.appendChild(o);});
}
function renderRawTable(){
  const q=(document.getElementById('rawSearch').value||'').toLowerCase();
  const subF=document.getElementById('rawSubFilter').value;
  const roleF=document.getElementById('rawRoleFilter').value;
  const envF=document.getElementById('rawEnvFilter').value;
  const typeF=document.getElementById('rawTypeFilter').value;
  rawPageSz=+document.getElementById('rawPageSize').value;

  rawFiltered=DATA.filter(r=>{
    if(subF&&r.SubscriptionName!==subF)return false;
    if(roleF&&r.RoleDefinitionName!==roleF)return false;
    if(envF&&r.Environment!==envF)return false;
    if(typeF&&(r.ObjectType||'Unknown')!==typeF)return false;
    if(q){
      const blob=(r.SubscriptionName+r.SubscriptionId+r.TenantId+r.DisplayName+r.SignInName+r.ObjectType+r.RoleDefinitionName+r.ResourceType+r.Scope+r.Environment).toLowerCase();
      if(!blob.includes(q))return false;
    }
    return true;
  });
  document.getElementById('rawResultCount').textContent=rawFiltered.length+' of '+DATA.length;
  const pages=Math.max(1,Math.ceil(rawFiltered.length/rawPageSz));
  if(rawPage>pages)rawPage=1;
  const slice=rawFiltered.slice((rawPage-1)*rawPageSz,rawPage*rawPageSz);

  const tbody=document.getElementById('rawTableBody');
  tbody.innerHTML=slice.map(r=>`<tr>
    <td>${escH(r.SubscriptionName)}</td>
    <td class="td-mono" style="font-size:11px">${escH(r.SubscriptionId)}</td>
    <td class="td-mono" style="font-size:11px">${escH(r.TenantId||'—')}</td>
    <td><strong>${escH(r.DisplayName)}</strong></td>
    <td class="td-mono" style="font-size:11px">${escH(r.SignInName||'—')}</td>
    <td><span class="badge badge-blue">${escH(r.ObjectType||'Unknown')}</span></td>
    <td>${escH(r.RoleDefinitionName)}</td>
    <td>${escH(r.ResourceType||'—')}</td>
    <td class="td-scope" title="${escH(r.Scope)}">${escH(r.Scope)}</td>
    <td><span class="${envBadgeClass(r.Environment)}">${escH(r.Environment)}</span></td>
  </tr>`).join('');

  renderPagination('rawPagination',pages,rawPage,pg=>{rawPage=pg;renderRawTable();});
}
function exportRawCSV(){
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const header='SubscriptionName,SubscriptionId,TenantId,DisplayName,SignInName,ObjectType,RoleDefinitionName,ResourceType,Scope,Environment';
  const rows=rawFiltered.map(r=>[r.SubscriptionName,r.SubscriptionId,r.TenantId,r.DisplayName,r.SignInName,r.ObjectType,r.RoleDefinitionName,r.ResourceType,r.Scope,r.Environment].map(esc).join(','));
  dlFile([header,...rows].join('\r\n'),'rbac-filtered-export.csv','text/csv');
  showToast('Exported '+rawFiltered.length+' records');
}
function exportAllCSV(){
  rawFiltered=DATA;
  exportRawCSV();
}

// ── Subscriptions env filter population ──────────────────────────────────────
function populateSubEnvFilter(){
  const ef=document.getElementById('subEnvFilter');
  UNIQUE_ENVS.forEach(e=>{const o=document.createElement('option');o.value=e;o.textContent=e;ef.appendChild(o);});
}

// ── Recommendations ───────────────────────────────────────────────────────────
function renderRecommendations(){
  const ownerRows=DATA.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner'));
  const ownerPct=DATA.length?((ownerRows.length/DATA.length)*100).toFixed(1):0;
  const overProvisioned=Object.values(
    DATA.reduce((m,r)=>{m[r.DisplayName]=(m[r.DisplayName]||0)+1;return m;},{})
  ).filter(c=>c>10).length;
  const prodOwners=ownerRows.filter(r=>r.Environment==='Prod').length;

  let html=`
    <div class="panel">
      <div class="section-title">🔍 Key Findings</div>
      <div class="detail-mini-row"><span class="detail-mini-label">Total Assignments</span><span class="detail-mini-val">${DATA.length} across ${UNIQUE_SUBS.length} subscription(s)</span></div>
      <div class="detail-mini-row"><span class="detail-mini-label">Unique Principals</span><span class="detail-mini-val">${[...new Set(DATA.map(r=>r.DisplayName))].length}</span></div>
      <div class="detail-mini-row"><span class="detail-mini-label">Unique Roles</span><span class="detail-mini-val">${UNIQUE_ROLES.length}</span></div>
      <div class="detail-mini-row"><span class="detail-mini-label">Owner Assignments</span><span class="detail-mini-val" style="color:var(--red)">${ownerRows.length} (${ownerPct}% of total)</span></div>
      <div class="detail-mini-row"><span class="detail-mini-label">Prod Owner Assignments</span><span class="detail-mini-val" style="color:var(--red)">${prodOwners}</span></div>
      <div class="detail-mini-row"><span class="detail-mini-label">Over-provisioned</span><span class="detail-mini-val">${overProvisioned} principal(s) with 10+ assignments</span></div>
    </div>`;

  // Security concerns
  let concerns='';
  if(+ownerPct>10)
    concerns+=`<div class="danger-box"><h4>⚠ High Owner Ratio</h4><p>${ownerRows.length} Owner assignments detected (${ownerPct}%). Review and replace with scoped custom roles wherever possible.</p></div>`;
  if(prodOwners>0)
    concerns+=`<div class="danger-box"><h4>⚠ Owner Roles in Production</h4><p>${prodOwners} Owner role assignment(s) found in Prod environment. Apply least-privilege and time-bound access via PIM.</p></div>`;
  if(overProvisioned>0)
    concerns+=`<div class="warn-box"><h4>🔍 Over-provisioned Principals</h4><p>${overProvisioned} principal(s) have 10 or more role assignments. Audit for role consolidation opportunities.</p></div>`;
  if(!concerns)
    concerns=`<div class="info-box"><h4>✅ No Critical Concerns Detected</h4><p>Your RBAC configuration looks reasonable. Focus on implementing custom roles for better governance.</p></div>`;

  html+=`<div class="panel"><div class="section-title">⚠ Security Concerns</div>${concerns}</div>`;

  // Recommended actions
  html+=`<div class="panel">
    <div class="section-title">✅ Recommended Actions</div>
    <div class="info-box"><h4>1. Design Three Custom Role Tiers</h4><p>Based on actual resource access patterns, create custom roles for Reader, Developer, and Architect personas.</p></div>
    <div class="info-box"><h4>2. Consolidate Redundant Assignments</h4><p>Review principals with multiple similar roles and consolidate into single custom role assignments per subscription.</p></div>
    <div class="info-box"><h4>3. Implement PIM for Owner and Contributor</h4><p>Move permanent Owner / Contributor assignments to Azure PIM just-in-time access. ${ownerRows.length} assignments are candidates.</p></div>
    <div class="info-box"><h4>4. Scope Custom Roles to Resource Group Level</h4><p>Begin at Resource Group scope for testing, then scale. Avoid subscription-scoped assignments where RG scope is sufficient.</p></div>
    <div class="info-box"><h4>5. Quarterly Access Reviews</h4><p>Schedule recurring RBAC audits and regenerate this report to track remediation progress over time.</p></div>
  </div>`;

  document.getElementById('recoContent').innerHTML=html;
}

// ── Pagination helper ─────────────────────────────────────────────────────────
function renderPagination(containerId,pages,current,onPage){
  const el=document.getElementById(containerId);
  if(pages<=1){el.innerHTML='';return;}
  let html='';
  const show=(p)=>`<button class="page-btn${p===current?' active':''}" onclick="(${onPage.toString()})(${p})">${p}</button>`;
  if(current>1)html+=`<button class="page-btn" onclick="(${onPage.toString()})(${current-1})">‹</button>`;
  if(pages<=7){for(let i=1;i<=pages;i++)html+=show(i);}
  else{
    html+=show(1);
    if(current>3)html+='<span style="color:var(--muted);padding:0 4px">…</span>';
    for(let i=Math.max(2,current-1);i<=Math.min(pages-1,current+1);i++)html+=show(i);
    if(current<pages-2)html+='<span style="color:var(--muted);padding:0 4px">…</span>';
    html+=show(pages);
  }
  if(current<pages)html+=`<button class="page-btn" onclick="(${onPage.toString()})(${current+1})">›</button>`;
  el.innerHTML=html;
}

// ── File download ─────────────────────────────────────────────────────────────
function dlFile(content,name,type){
  const b=new Blob([content],{type});
  const u=URL.createObjectURL(b);
  const a=document.createElement('a');
  a.href=u;a.download=name;a.click();
  URL.revokeObjectURL(u);
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closeDetail();return;}
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'&&document.activeElement.tagName!=='SELECT'){
    e.preventDefault();
    const inp=document.querySelector('.page.active input[type=text]');
    if(inp)inp.focus();
  }
});

// ── Bootstrap ─────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded',function(){
  try{
    if(typeof Chart==='undefined'){
      document.querySelectorAll('.chart-wrap').forEach(el=>{
        el.innerHTML='<p style="text-align:center;padding:2rem;color:var(--amber)">⚠ Chart.js unavailable (CDN blocked). Data tables are fully functional.</p>';
      });
    }else{
      Chart.defaults.font.family="'Calibri','Segoe UI',sans-serif";
      initOverviewCharts();
      initEnvCharts();
    }
    setOwnerCount();
    renderEnvCards();
    buildPrincData();
    renderPrincTable();
    buildRolesData();
    renderRoleTable();
    populateSubEnvFilter();
    renderSubCards();
    populateRawFilters();
    renderRawTable();
    renderRecommendations();
  }catch(e){
    console.error('Dashboard init error:',e);
    showToast('Init error: '+e.message,'⚠');
  }
});
</script>
</body>
</html>
'@

    #endregion

    #region ── Token substitution ─────────────────────────────────────────────

    $html = $html `
        -replace '__REPORTDATE__',        $reportDate `
        -replace '__REPORTTIMESTAMP__',   $reportTimestamp `
        -replace '__TOTALRECORDS__',      $totalRecords `
        -replace '__PRINCIPALCOUNT__',    $uniquePrincipals.Count `
        -replace '__ROLECOUNT__',         $uniqueRoles.Count `
        -replace '__SUBCOUNT__',          $uniqueSubscriptions.Count `
        -replace '__ENVCOUNT__',          $uniqueEnvironments.Count `
        -replace '__ENRICHED_JSON__',     $enrichedJson `
        -replace '__SCOPE_JSON__',        $scopeJson `
        -replace '__OBJTYPE_JSON__',      $objTypeJson `
        -replace '__TOP_PRINC_JSON__',    $topPrincJson `
        -replace '__TOP_ROLES_JSON__',    $topRolesJson `
        -replace '__RESTYPE_JSON__',      $resTypeJson `
        -replace '__ENVSTATS_JSON__',     $envStatsJson `
        -replace '__SUBSTATS_JSON__',     $subStatsJson `
        -replace '__UNIQUE_SUBS_JSON__',  $uniqueSubsJson `
        -replace '__UNIQUE_ROLES_JSON__', $uniqueRolesJson `
        -replace '__UNIQUE_ENVS_JSON__',  $uniqueEnvsJson

    #endregion

    #region ── Write output ───────────────────────────────────────────────────

    try
    {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Host '        ✓ HTML report written' -ForegroundColor Green
    }
    catch
    {
        Write-Error "Failed to write HTML report: $_"
        return
    }

    #endregion

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Green
    Write-Host '║   ✅  RBAC Visualization Report v2.0 — Generated!            ║' -ForegroundColor Green
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Green
    Write-Host ''
    Write-Host "  📊  Records analysed   : $totalRecords"                                     -ForegroundColor White
    Write-Host "  👤  Unique principals  : $($uniquePrincipals.Count)"                        -ForegroundColor White
    Write-Host "  🎭  Unique roles       : $($uniqueRoles.Count)"                             -ForegroundColor White
    Write-Host "  🗂   Subscriptions      : $($uniqueSubscriptions.Count)"                     -ForegroundColor White
    Write-Host "  🌍  Environments       : $($uniqueEnvironments -join ', ')"                 -ForegroundColor White
    Write-Host "  📁  Output file        : $OutputPath"                                       -ForegroundColor White
    Write-Host ''
}
