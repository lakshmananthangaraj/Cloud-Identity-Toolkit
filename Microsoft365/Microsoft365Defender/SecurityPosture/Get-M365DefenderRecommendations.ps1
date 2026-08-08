<#

Author          : Lakshmanan Thangaraj
Version         : 1.1
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Lists actionable Secure Score recommendations for the tenant using Microsoft Graph API.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 /security/secureScoreControlProfiles
    endpoint to retrieve the catalog of security controls that contribute to (or could
    improve) the tenant's Secure Score, along with their current implementation state.

    It handles pagination automatically via @odata.nextLink, retries on API throttling
    (HTTP 429) using the Retry-After header, and validates the JSON response before
    processing it further.

    Array-valued properties (threats, vendorInformation) are flattened into
    comma/semicolon-separated strings for CSV friendliness.

    Results can optionally be exported to CSV, or to a self-contained, multi-tab
    interactive HTML dashboard (Overview / All Recommendations / Category Explorer /
    Analytics) for end-user-friendly review.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK below,
    then pass its returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        SecurityEvents.Read.All (Application)

.PARAMETER ControlCategory
    Optional filter to return only controls belonging to a specific controlCategory
    (e.g. "Identity", "Data", "Device", "Apps"). Free-text — categories are Microsoft-defined
    and not exposed as a fixed enum via Graph.

.PARAMETER IncludeDeprecated
    Switch. By default, controls flagged as deprecated by Microsoft are excluded. Pass this
    switch to include them in the output.

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV  - flat, spreadsheet-friendly export (unchanged from v1.0).
        HTML - self-contained, multi-tab interactive dashboard (Overview / All
               Recommendations / Category Explorer / Analytics) with search, filter,
               sort, pagination, and a detail drawer per recommendation. Intended for
               end users who need a friendlier view than a raw CSV/table.

.PARAMETER ExportPath
    File path where the exported CSV or HTML output will be saved.
    Required only when ExportFormat is set to CSV or HTML.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
        An array of custom objects containing Secure Score control/recommendation
        attributes. Also optionally exports to CSV or HTML.

.EXAMPLE
    Get-M365DefenderRecommendations -AccessToken $token

    Retrieves all non-deprecated Secure Score recommendations for the tenant.

.EXAMPLE
    Get-M365DefenderRecommendations -AccessToken $token -ControlCategory "Identity" -ExportFormat CSV -ExportPath "C:\Reports\IdentityRecommendations.csv"

    Retrieves only Identity-category recommendations and exports them to CSV.

.EXAMPLE
    Get-M365DefenderRecommendations -AccessToken $token -ExportFormat HTML -ExportPath "C:\Reports\SecureScoreDashboard.html"

    Retrieves all non-deprecated Secure Score recommendations and generates a multi-tab
    interactive HTML dashboard for end-user review.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.1 (01-Aug-2026)  - Added "HTML" to -ExportFormat, producing a self-contained
                              multi-tab dashboard (Overview / All Recommendations /
                              Category Explorer / Analytics) with search, filter, sort,
                              pagination, and a prev/next detail drawer per
                              recommendation. Purely additive: the Graph retrieval,
                              pagination/throttle handling, filtering logic, and the
                              existing CSV export path are unchanged.
        1.0 (01-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permission:
                SecurityEvents.Read.All (Application)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - controlStateUpdates (history of who assigned/ignored/resolved a control) is
            not flattened into this output; only the control's current definition and
            scoring metadata are returned. Treat controlStateUpdates as a future
            enhancement if per-control assignment history is needed.
        - -ControlCategory is applied client-side after retrieval, not as a server-side
            $filter, since Graph's support for filtering this endpoint by category is
            inconsistent across tenants.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer
            token for the entire pagination run and does not refresh it mid-run. In
            very large tenants this could fail with 401 if the full pull outlives the
            token's lifetime.
        - HTML EXPORT — REMEDIATION RENDERING: the "remediation" field returned by Graph
            is Microsoft-authored HTML (ordered lists, links). The dashboard renders it
            as-is (not HTML-escaped) inside the detail drawer so steps and links stay
            usable; every other field is HTML-escaped before display. Only pass
            -ExportFormat HTML against the genuine Graph endpoint, not a modified/proxied
            response, since the remediation field is trusted as coming from Microsoft.
        - HTML EXPORT — FONTS: the dashboard references Google Fonts (JetBrains Mono) via
            a CDN link for the monospace styling. On a machine with no internet access at
            view-time, the browser falls back to the system monospace stack automatically
            — no functional impact, purely cosmetic.
        - HTML EXPORT is a single static file with all recommendation data embedded as
            inline JSON; it does not re-query Graph, so it reflects data as of the run
            that generated it.

.LINK
    Microsoft Graph API - secureScoreControlProfile resource type
    https://learn.microsoft.com/en-us/graph/api/resources/securescorecontrolprofile

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function ConvertTo-JsonSafe
{
    # Escapes a string for safe embedding inside a hand-built JSON literal in the
    # generated HTML dashboard. Used only by the -ExportFormat HTML path below;
    # does not touch the CSV export path or the core Graph retrieval logic.
    param([string]$Text)

    $Text `
        -replace '\\',      '\\\\'   `
        -replace '"',       '\"'     `
        -replace "`r`n",    '\n'     `
        -replace "`n",      '\n'     `
        -replace "`r",      '\n'     `
        -replace "`t",      '\t'     `
        -replace '<',       '\u003c' `
        -replace '>',       '\u003e' `
        -replace '\$',      '\u0024'
}


Function Get-M365DefenderRecommendations
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [string]$ControlCategory,

        [switch]$IncludeDeprecated,

        [ValidateSet("CSV", "HTML")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    if ($ExportPath -and ($ExportPath -match '\.\.[\\/]'))
    {
        Write-Error "ExportPath contains path-traversal characters and was rejected. Exiting function."
        return
    }

    $allControls = New-Object System.Collections.ArrayList
    $totalControls = 0

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $uri = "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?`$top=100"

    do
    {
        Try
        {
            $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            $statusCode = $partialData.StatusCode
        }
        catch
        {
            $statusCode = $_.Exception.Response.StatusCode
            $ErrorObject = $_

            if ($statusCode -eq 429)
            {
                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                Start-Sleep -Seconds $sleepTime
                continue
            }
            else
            {
                $ErrorOutput = [PSCustomObject][ordered]@{
                    Response   = $($ErrorObject.Exception.Response)
                    StatusCode = $($ErrorObject.Exception.Response.StatusCode)
                    Message    = $($ErrorObject.Exception.Message)
                }
                $ErrorOutput | Format-List
                return
            }
        }

        if ($partialData)
        {
            $controlData = $partialData.Content | ConvertFrom-Json
        }

        $controlData.value | ForEach-Object {

            $control = $_

            if (-not $IncludeDeprecated -and $control.deprecated) { return }
            if ($ControlCategory -and ($control.controlCategory -ne $ControlCategory)) { return }

            $null = $allControls.Add(
                [PSCustomObject][ordered]@{
                    id                 = $control.id
                    title              = $control.title
                    controlCategory    = $control.controlCategory
                    tier               = $control.tier
                    service            = $control.service
                    actionType         = $control.actionType
                    rank               = $control.rank
                    maxScore           = $control.maxScore
                    userImpact         = $control.userImpact
                    implementationCost = $control.implementationCost
                    deprecated         = $control.deprecated
                    threats            = if ($control.threats) { $control.threats -join "; " } else { $null }
                    remediation        = $control.remediation
                    remediationImpact  = $control.remediationImpact
                    lastModifiedDateTime = $control.lastModifiedDateTime
                }
            )
        }

        $totalControls += $controlData.value.Count
        Write-Host "Progress: $totalControls recommendation(s) retrieved so far" -ForegroundColor Cyan

        if ($controlData.PSObject.Properties['@odata.nextLink']) { $uri = $controlData.'@odata.nextLink' } else { $uri = $null }

    } until (-not $uri)

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allControls | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host ""
        Write-Host "Secure Score recommendations exported successfully -> $ExportPath" -ForegroundColor Green
    }
    elseif ($ExportFormat -eq "HTML" -and $ExportPath)
    {
        Write-Host ""
        Write-Host "Building interactive HTML dashboard..." -ForegroundColor Cyan

        $categories      = $allControls | Group-Object controlCategory | Sort-Object Count -Descending
        $totalRecs       = $allControls.Count
        $categoryCount   = $categories.Count
        $totalMaxScoreRaw = ($allControls | Measure-Object maxScore -Sum).Sum
        $totalMaxScore   = if ($totalMaxScoreRaw) { [math]::Round($totalMaxScoreRaw, 1) } else { 0 }
        $avgMaxScore     = if ($totalRecs -gt 0) { [math]::Round($totalMaxScore / $totalRecs, 2) } else { 0 }
        $deprecatedCount = ($allControls | Where-Object { $_.deprecated }).Count
        $quickWinCount   = ($allControls | Where-Object { $_.implementationCost -eq 'Low' }).Count
        $quickWinPct     = if ($totalRecs -gt 0) { [math]::Round(($quickWinCount / $totalRecs) * 100, 0) } else { 0 }
        $generatedAt     = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')
        $filterDisplay   = if ($ControlCategory) { "Category: $ControlCategory" } else { "All categories" }
        if ($IncludeDeprecated) { $filterDisplay += " (incl. deprecated)" }

        $categoriesJson = ($categories | ForEach-Object {
            "{`"category`":`"$(ConvertTo-JsonSafe $_.Name)`",`"count`":$($_.Count)}"
        }) -join ','

        $controlsJson = ($allControls | ForEach-Object {
            $threatsJson = if ($_.threats) {
                (($_.threats -split ';') | ForEach-Object { "`"$(ConvertTo-JsonSafe $_.Trim())`"" }) -join ','
            } else { '' }

            $idSafe                 = ConvertTo-JsonSafe $_.id
            $titleSafe              = ConvertTo-JsonSafe $_.title
            $categorySafe           = ConvertTo-JsonSafe $_.controlCategory
            $tierSafe               = ConvertTo-JsonSafe $_.tier
            $serviceSafe            = ConvertTo-JsonSafe $_.service
            $actionTypeSafe         = ConvertTo-JsonSafe $_.actionType
            $userImpactSafe         = ConvertTo-JsonSafe $_.userImpact
            $implementationCostSafe = ConvertTo-JsonSafe $_.implementationCost
            $remediationSafe        = ConvertTo-JsonSafe $_.remediation
            $remediationImpactSafe  = ConvertTo-JsonSafe $_.remediationImpact
            $lastModifiedSafe       = ConvertTo-JsonSafe $_.lastModifiedDateTime

            $rankVal       = if ($null -ne $_.rank) { $_.rank } else { 0 }
            $maxScoreVal   = if ($null -ne $_.maxScore) { $_.maxScore } else { 0 }
            $deprecatedVal = if ($_.deprecated) { 'true' } else { 'false' }

            "{`"id`":`"$idSafe`",`"title`":`"$titleSafe`",`"category`":`"$categorySafe`",`"tier`":`"$tierSafe`",`"service`":`"$serviceSafe`",`"actionType`":`"$actionTypeSafe`",`"rank`":$rankVal,`"maxScore`":$maxScoreVal,`"userImpact`":`"$userImpactSafe`",`"implementationCost`":`"$implementationCostSafe`",`"deprecated`":$deprecatedVal,`"threats`":[$threatsJson],`"remediation`":`"$remediationSafe`",`"remediationImpact`":`"$remediationImpactSafe`",`"lastModified`":`"$lastModifiedSafe`"}"
        }) -join ','

        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Secure Score Recommendations Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
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

/* Sidebar */
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

/* Main */
#main{margin-left:236px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:24px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

/* Stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-card::after{content:'';position:absolute;top:-26px;right:-26px;width:68px;height:68px;border-radius:50%;background:radial-gradient(circle,rgba(59,130,246,.1),transparent 70%)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:25px;font-weight:700;color:var(--text);line-height:1}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}

/* Health card */
.health-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;display:flex;align-items:center;gap:18px;margin-bottom:22px;flex-wrap:wrap}
.health-ring-wrap{position:relative;width:76px;height:76px;flex-shrink:0}
.health-ring-wrap svg{width:76px;height:76px}
.health-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.health-score-num{font-family:var(--mono);font-size:19px;font-weight:700;line-height:1}
.health-score-pct{font-size:9px;color:var(--muted)}
.health-info{flex:1;min-width:200px}
.health-info h3{font-size:14px;font-weight:700;margin-bottom:4px}
.health-info p{font-size:12px;color:var(--muted2)}
.health-bar-row{display:flex;align-items:center;gap:8px;margin-top:8px;font-size:12px}
.health-mini-bar{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.health-mini-fill{height:100%;border-radius:3px;transition:width 1s ease}

/* Panels & charts */
.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px;cursor:pointer}
.bar-row:hover .bar-label{color:var(--text)}
.bar-label{font-family:var(--mono);font-size:11px;color:var(--muted2);width:110px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:28px;text-align:right;flex-shrink:0}
#donutWrap{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
#donutSvg{width:180px;height:180px;flex-shrink:0}
.legend-list{flex:1;min-width:130px;display:flex;flex-direction:column;gap:5px;max-height:220px;overflow-y:auto}
.legend-item{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted2);cursor:pointer;padding:2px 4px;border-radius:4px}
.legend-item:hover{background:var(--surface2)}
.legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.legend-pct{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}
.recent-row{display:flex;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid var(--border)}
.recent-row:last-child{border-bottom:none}
.recent-icon{color:var(--accent);font-size:13px;width:18px;text-align:center;flex-shrink:0}
.recent-name{font-family:var(--mono);font-size:12.5px;color:var(--accent2);flex:1;cursor:pointer}
.recent-name:hover{text-decoration:underline}
.recent-date{color:var(--muted);font-size:11.5px;flex-shrink:0}

/* Table */
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
.scripts-table{width:100%;border-collapse:collapse}
.scripts-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.scripts-table thead th:hover{color:var(--text)}
.scripts-table thead th.sort-active{color:var(--accent)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.scripts-table tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.scripts-table tbody tr:hover{background:var(--surface2)}
.scripts-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13.5px}
.td-name{font-family:var(--mono);font-size:12.5px;color:var(--accent2);font-weight:600}
.verb-badge{display:inline-block;padding:2px 9px;border-radius:20px;font-family:var(--sans);font-size:11.5px;font-weight:600}
.td-synopsis{color:var(--muted2);max-width:300px}
.td-synopsis span{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:300px}
.td-meta{color:var(--muted);font-family:var(--mono);font-size:12px;white-space:nowrap}
.help-dot{display:inline-block;width:8px;height:8px;border-radius:50%}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}

/* Detail panel */
#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(660px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:24px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
#detailClose{margin-left:auto;background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--red);color:#fff}
#detailContent{flex:1;overflow-y:auto}
.detail-header{margin-bottom:16px}
.detail-name{font-family:var(--mono);font-size:16px;color:var(--accent2);font-weight:600;word-break:break-all}
.detail-path{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:4px;word-break:break-all}
.detail-synopsis{color:var(--muted2);font-size:13.5px;margin-top:7px;font-style:italic}
.detail-meta-row{display:flex;gap:9px;flex-wrap:wrap;margin:12px 0}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:12px;color:var(--muted2)}
.detail-section{margin-top:18px}
.detail-section-title{font-size:11.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:9px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.detail-description{color:var(--muted2);font-size:13.5px;line-height:1.7}
.detail-description ol,.detail-description ul{margin:8px 0 8px 20px}
.detail-description li{margin-bottom:6px}
.detail-description a{color:var(--accent2)}
.param-card{background:var(--surface2);border-radius:var(--radius-sm);padding:9px 12px;margin-bottom:5px;border:1px solid var(--border)}
.param-name{font-family:var(--mono);font-size:12.5px;color:var(--accent3)}
.param-desc{color:var(--muted2);font-size:12.5px;margin-top:3px}

/* Explorer */
.explorer-toolbar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.explorer-search-wrap{flex:1;min-width:200px;position:relative}
.explorer-search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none}
#explorerSearch{width:100%;padding:8px 11px 8px 34px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;outline:none;transition:border-color .2s}
#explorerSearch:focus{border-color:var(--accent)}
.explorer-count{color:var(--muted);font-size:13px}
.explorer-sort{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.verb-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px;align-items:start}
.verb-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);display:flex;flex-direction:column;transition:border-color .2s,box-shadow .2s}
.verb-card:hover{border-color:var(--accent);box-shadow:0 2px 12px rgba(56,139,253,.1)}
.verb-card.expanded{max-height:70vh}
.verb-card-head{display:flex;align-items:center;justify-content:space-between;padding:11px 14px;border-bottom:1px solid var(--border);background:var(--surface2);border-radius:var(--radius) var(--radius) 0 0;flex-shrink:0;gap:8px}
.verb-card-head .vname{font-family:var(--mono);font-size:13.5px;font-weight:600}
.verb-card-head .vcount{font-size:12px;background:var(--surface3);border-radius:20px;padding:2px 9px;color:var(--accent2);flex-shrink:0}
.verb-scripts{padding:5px 7px;overflow-y:hidden;flex:1}
.verb-card.expanded .verb-scripts{overflow-y:auto}
.verb-script-row{display:flex;align-items:center;gap:7px;padding:6px 7px;border-radius:var(--radius-sm);cursor:pointer;transition:background .15s}
.verb-script-row:hover{background:var(--surface2)}
.vs-icon{color:var(--muted);font-size:10px;flex-shrink:0}
.vs-name{font-family:var(--mono);font-size:12px;color:var(--accent2);flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vs-synopsis{color:var(--muted);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:70px;flex-shrink:0}
.verb-footer{flex-shrink:0;border-top:1px solid var(--border);background:var(--surface);border-radius:0 0 var(--radius) var(--radius)}
.verb-show-more{display:flex;align-items:center;justify-content:center;gap:6px;padding:8px 12px;cursor:pointer;font-size:12px;font-family:var(--sans);transition:background .15s;border-radius:0 0 var(--radius) var(--radius)}
.verb-show-more:hover{background:var(--surface2)}
.show-more-btn{color:var(--accent)}
.vm-count{background:var(--surface3);border-radius:20px;padding:1px 8px;font-family:var(--mono);font-size:11px;color:var(--accent2)}
.show-less-btn{color:var(--muted2);display:none}
.verb-card.expanded .show-more-btn{display:none}
.verb-card.expanded .show-less-btn{display:flex}
.verb-hidden{display:none}
.verb-card.expanded .verb-hidden{display:flex}

/* Analytics */
.analytics-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;margin-bottom:18px}
.analytics-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.top-list-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);cursor:pointer}
.top-list-row:last-child{border-bottom:none}
.top-list-row:hover .tl-name{color:var(--accent)}
.tl-rank{font-family:var(--mono);font-size:11px;color:var(--muted);width:20px;flex-shrink:0;text-align:center}
.tl-name{font-family:var(--mono);font-size:12px;color:var(--accent2);flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tl-val{font-family:var(--mono);font-size:12px;color:var(--muted);flex-shrink:0}
.hc-row{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px}
.hc-label{width:110px;flex-shrink:0;color:var(--muted2);font-family:var(--mono);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hc-track{flex:1;height:10px;background:var(--surface3);border-radius:5px;overflow:hidden}
.hc-fill{height:100%;border-radius:5px;transition:width .9s ease}
.hc-count{font-family:var(--mono);font-size:12px;color:var(--muted);flex-shrink:0;width:110px;text-align:right}

/* Toast */
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

/* Responsive */
@media(max-width:768px){#sidebar{transform:translateX(-236px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🛡️</div>
    <h1>Secure Score Dashboard</h1>
    <p title="__FILTERDISPLAY__">__FILTERDISPLAY__</p>
    <span class="version-badge">v1.1</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">📊</span> Overview
    </button>
    <button class="nav-btn" onclick="showPage('recs',this)">
      <span class="nav-icon">📄</span> All Recommendations
      <span class="nav-badge">__RECCOUNT__</span>
    </button>
    <button class="nav-btn" onclick="showPage('explorer',this)">
      <span class="nav-icon">🗂</span> Category Explorer
    </button>
    <button class="nav-btn" onclick="showPage('analytics',this)">
      <span class="nav-icon">📈</span> Analytics
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
    Generated<br>__GENERATEDAT__<br>
    <span style="color:var(--accent2)">⌨</span> <kbd>/</kbd> search &nbsp; <kbd>←</kbd><kbd>→</kbd> navigate
  </div>
</nav>

<main id="main">

<!-- OVERVIEW -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Secure Score Recommendations Overview</div>
      <div class="page-subtitle">A bird's-eye view of your tenant's actionable recommendations</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(false)">⬇ Export CSV</button>
      <button class="btn" onclick="exportJSON(false)">⬇ Export JSON</button>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">📄</div><div class="stat-value">__RECCOUNT__</div><div class="stat-label">Total Recommendations</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">🏷</div><div class="stat-value">__CATCOUNT__</div><div class="stat-label">Categories</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">💯</div><div class="stat-value">__TOTALSCORE__</div><div class="stat-label">Total Score Potential</div></div>
    <div class="stat-card c-green"><div class="stat-icon">⚡</div><div class="stat-value">__QUICKWINCOUNT__</div><div class="stat-label">Quick Wins (Low Cost)</div></div>
    <div class="stat-card c-red"><div class="stat-icon">⚠</div><div class="stat-value">__DEPRECATEDCOUNT__</div><div class="stat-label">Deprecated Controls</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">📐</div><div class="stat-value">__AVGSCORE__</div><div class="stat-label">Avg Points / Recommendation</div></div>
  </div>

  <div class="health-card">
    <div class="health-ring-wrap">
      <svg viewBox="0 0 76 76">
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--surface3)" stroke-width="9"/>
        <circle cx="38" cy="38" r="30" fill="none" stroke="#3fb950" stroke-width="9"
          stroke-dasharray="188.5" stroke-dashoffset="188.5" stroke-linecap="round"
          transform="rotate(-90 38 38)" id="healthArc" style="transition:stroke-dashoffset 1.2s ease"/>
      </svg>
      <div class="health-ring-center">
        <span class="health-score-num" id="healthNum" style="color:#3fb950">__QUICKWINPCT__%</span>
        <span class="health-score-pct">quick wins</span>
      </div>
    </div>
    <div class="health-info">
      <h3>Quick Win Ratio</h3>
      <p>Share of recommendations flagged Low implementation cost — tackle these first</p>
      <div class="health-bar-row">
        <span style="color:var(--green);font-size:12px">⚡ Low cost</span>
        <div class="health-mini-bar"><div class="health-mini-fill" id="hHelp" style="background:var(--green);width:0%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">__QUICKWINCOUNT__</span>
      </div>
      <div class="health-bar-row">
        <span style="color:var(--amber);font-size:12px">⏳ Moderate/High cost</span>
        <div class="health-mini-bar"><div class="health-mini-fill" id="hNoHelp" style="background:var(--amber);width:0%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">__RECCOUNT__</span>
      </div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Recommendations by Category <span style="font-size:11px;color:var(--muted);font-weight:400">(click to filter)</span></div>
      <div id="barsContainer"></div>
    </div>
    <div class="panel">
      <div class="section-title">🍩 Implementation Cost Distribution</div>
      <div id="donutWrap">
        <svg id="donutSvg" viewBox="0 0 180 180"></svg>
        <div class="legend-list" id="donutLegend"></div>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="section-title">🎯 Top Threats Mitigated</div>
    <div id="recentList"></div>
  </div>
</section>

<!-- ALL RECOMMENDATIONS -->
<section id="page-recs" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">All Recommendations</div>
      <div class="page-subtitle">Browse, filter and inspect every recommendation for this tenant</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(true)">⬇ Export Filtered CSV</button>
      <button class="btn" onclick="exportJSON(true)">⬇ Export Filtered JSON</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="tableSearch" placeholder="Search title, category, service, threats… (press / to focus)" oninput="filterTable()"/>
    </div>
    <select id="categoryFilter" onchange="filterTable()"><option value="">All Categories</option></select>
    <select id="tierFilter" onchange="filterTable()"><option value="">All Tiers</option></select>
    <select id="impactFilter" onchange="filterTable()">
      <option value="">Any User Impact</option>
      <option value="Low">Low Impact</option>
      <option value="Moderate">Moderate Impact</option>
      <option value="High">High Impact</option>
    </select>
    <select id="costFilter" onchange="filterTable()">
      <option value="">Any Implementation Cost</option>
      <option value="Low">Low Cost</option>
      <option value="Moderate">Moderate Cost</option>
      <option value="High">High Cost</option>
    </select>
    <select id="sortSelect" onchange="filterTable()">
      <option value="rank-asc">Rank (lowest first)</option>
      <option value="title-asc">Title A→Z</option>
      <option value="title-desc">Title Z→A</option>
      <option value="score-desc">Highest Score Potential</option>
      <option value="cost-asc">Lowest Implementation Cost</option>
    </select>
    <div class="page-size-wrap">
      Show <select id="pageSizeSelect" onchange="changePageSize()"><option>20</option><option>50</option><option>100</option></select>
    </div>
    <span class="result-count" id="resultCount"></span>
  </div>
  <table class="scripts-table">
    <thead><tr>
      <th onclick="sortByCol('title')" id="th-title">Recommendation <span class="sort-arrow">↕</span></th>
      <th onclick="sortByCol('category')" id="th-category">Category <span class="sort-arrow">↕</span></th>
      <th>Tier</th>
      <th onclick="sortByCol('score')" id="th-score">Score <span class="sort-arrow">↕</span></th>
      <th>User Impact</th>
      <th onclick="sortByCol('cost')" id="th-cost">Impl. Cost <span class="sort-arrow">↕</span></th>
      <th>Threats</th>
      <th title="Deprecated status">Status</th>
    </tr></thead>
    <tbody id="recsTableBody"></tbody>
  </table>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:12px">
    <span id="pageInfo" style="font-size:12px;color:var(--muted)"></span>
    <div class="pagination" id="pagination"></div>
  </div>
</section>

<!-- CATEGORY EXPLORER -->
<section id="page-explorer" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Category Explorer</div>
      <div class="page-subtitle">Browse recommendations organised by Secure Score category</div>
    </div>
  </div>
  <div class="explorer-toolbar">
    <div class="explorer-search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="explorerSearch" placeholder="Filter categories or recommendations…" oninput="filterExplorer()"/>
    </div>
    <div class="explorer-sort">
      Sort: <select id="explorerSort" onchange="filterExplorer()">
        <option value="count-desc">Most Recommendations</option>
        <option value="score-desc">Highest Score Potential</option>
        <option value="alpha">Alphabetical</option>
      </select>
    </div>
    <span class="explorer-count" id="explorerCount"></span>
  </div>
  <div class="verb-grid" id="verbGrid"></div>
</section>

<!-- ANALYTICS -->
<section id="page-analytics" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Analytics</div>
      <div class="page-subtitle">Deeper insights into the recommendation catalogue</div>
    </div>
  </div>
  <div class="analytics-grid">
    <div class="analytics-panel">
      <div class="section-title">💯 Top by Score Potential</div>
      <div id="topByScore"></div>
    </div>
    <div class="analytics-panel">
      <div class="section-title">🎯 Most Common Threats</div>
      <div id="topThreats"></div>
    </div>
    <div class="analytics-panel">
      <div class="section-title">🏷 Score Potential by Category</div>
      <div id="scoreByCategory"></div>
    </div>
    <div class="analytics-panel">
      <div class="section-title">🧱 Tier Breakdown</div>
      <div id="tierBreakdown"></div>
    </div>
  </div>
  <div class="panel" style="margin-bottom:16px">
    <div class="section-title">🛠 Implementation Cost Distribution</div>
    <div id="costDistribution"></div>
  </div>
  <div class="panel">
    <div class="section-title">👤 User Impact Distribution</div>
    <div id="impactDistribution"></div>
  </div>
</section>

</main>

<!-- DETAIL PANEL -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDetail()"></div>
  <div id="detailDrawer">
    <div class="detail-toolbar">
      <button class="btn" id="detailPrevBtn" onclick="navigateDetail(-1)">‹ Prev</button>
      <button class="btn" id="detailNextBtn" onclick="navigateDetail(1)">Next ›</button>
      <button class="btn" onclick="copyDetailId()">📋 Copy ID</button>
      <button id="detailClose" onclick="closeDetail()" title="Close (Esc)">✕</button>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<div id="toast"><span id="toastIcon">✅</span><span id="toastMsg">Done</span></div>

<script>
const CONTROLS   = [__CONTROLS_JSON__];
const CATEGORIES = [__CATEGORIES_JSON__];
const PALETTE    = ['#3b82f6','#06b6d4','#8b5cf6','#10b981','#f59e0b','#ef4444','#ec4899','#84cc16','#f97316','#a78bfa','#34d399','#fbbf24','#60a5fa','#2dd4bf','#c084fc'];

const CATEGORY_COLORS = {};
CATEGORIES.forEach((c,i) => { CATEGORY_COLORS[c.category] = PALETTE[i % PALETTE.length]; });

function catBadge(cat) {
  const col = CATEGORY_COLORS[cat] || '#64748b';
  return `<span class="verb-badge" style="background:${col}22;color:${col};border:1px solid ${col}44">${escH(cat||'—')}</span>`;
}
function levelColor(v) {
  if (v === 'Low') return 'var(--green)';
  if (v === 'Moderate') return 'var(--amber)';
  if (v === 'High') return 'var(--red)';
  return 'var(--muted)';
}

// ── Toast ──
let _toastT;
function showToast(msg, icon='✅') {
  document.getElementById('toastMsg').textContent = msg;
  document.getElementById('toastIcon').textContent = icon;
  const el = document.getElementById('toast');
  el.classList.add('show');
  clearTimeout(_toastT);
  _toastT = setTimeout(() => el.classList.remove('show'), 2600);
}

// ── Theme ──
function toggleTheme() {
  const light = document.body.classList.toggle('light-theme');
  document.getElementById('themeIcon').textContent  = light ? '☀️' : '🌙';
  document.getElementById('themeLabel').textContent = light ? 'Light Mode' : 'Dark Mode';
  try { localStorage.setItem('ss-dash-theme', light ? 'light' : 'dark'); } catch(e){}
}
(function(){
  try { if (localStorage.getItem('ss-dash-theme') === 'light') {
    document.body.classList.add('light-theme');
    document.getElementById('themeIcon').textContent  = '☀️';
    document.getElementById('themeLabel').textContent = 'Light Mode';
  }} catch(e){}
})();

// ── Navigation ──
function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  if (btn) btn.classList.add('active');
}

// ── Quick-win ring ──
(function(){
  const score = __QUICKWINPCT__;
  const arc = document.getElementById('healthArc');
  const num = document.getElementById('healthNum');
  const circ = 2 * Math.PI * 30;
  const col = score >= 60 ? '#3fb950' : score >= 30 ? '#d29922' : '#f85149';
  arc.style.stroke = col; num.style.color = col;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    arc.style.strokeDashoffset = circ * (1 - score / 100);
  }));
  document.getElementById('hHelp').style.width   = score + '%';
  document.getElementById('hNoHelp').style.width = (100 - score) + '%';
})();

// ── Bars: Recommendations by Category ──
(function(){
  const max = Math.max(...CATEGORIES.map(c => c.count), 1);
  const el = document.getElementById('barsContainer');
  CATEGORIES.slice(0,15).forEach((cat,i) => {
    const pct = Math.round((cat.count/max)*100);
    const col = PALETTE[i%PALETTE.length];
    el.innerHTML += `<div class="bar-row" onclick="goToCategory('${escJ(cat.category)}')">
      <span class="bar-label" title="${escH(cat.category)}">${escH(cat.category)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:0%;background:${col}" data-pct="${pct}"></div></div>
      <span class="bar-count">${cat.count}</span></div>`;
  });
  requestAnimationFrame(() => {
    document.querySelectorAll('.bar-fill').forEach(el => { el.style.width = el.dataset.pct + '%'; });
  });
})();

function goToCategory(cat) {
  document.querySelectorAll('.nav-btn')[1].click();
  setTimeout(() => { document.getElementById('categoryFilter').value = cat; filterTable(); }, 50);
}
function goToCost(cost) {
  document.querySelectorAll('.nav-btn')[1].click();
  setTimeout(() => { document.getElementById('costFilter').value = cost; filterTable(); }, 50);
}

// ── Donut: Implementation Cost Distribution ──
(function(){
  const svg = document.getElementById('donutSvg');
  const legend = document.getElementById('donutLegend');
  const order = ['Low','Moderate','High'];
  const colors = {Low:'#3fb950',Moderate:'#d29922',High:'#f85149'};
  let buckets = order.map(k => ({ key:k, count: CONTROLS.filter(c=>c.implementationCost===k).length }));
  const otherCnt = CONTROLS.filter(c => !order.includes(c.implementationCost)).length;
  if (otherCnt > 0) buckets.push({ key:'Other', count: otherCnt });
  buckets = buckets.filter(b => b.count > 0);
  const total = buckets.reduce((s,b)=>s+b.count,0) || 1;
  const R=68,cx=90,cy=90,stroke=24;
  const circ = 2*Math.PI*R;
  let offset=0;
  const GAP = 1.5/360;
  buckets.forEach((b,i) => {
    const frac=b.count/total, drawFrac=Math.max(0,frac-GAP);
    const dashLen=drawFrac*circ, gap=circ-dashLen;
    const col = colors[b.key] || '#64748b';
    const c=document.createElementNS('http://www.w3.org/2000/svg','circle');
    c.setAttribute('cx',cx);c.setAttribute('cy',cy);c.setAttribute('r',R);
    c.setAttribute('fill','none');c.setAttribute('stroke',col);c.setAttribute('stroke-width',stroke);
    c.setAttribute('stroke-dasharray',`${dashLen} ${gap}`);
    const finalOffset=-(offset*circ)+circ*0.25;
    c.setAttribute('stroke-dashoffset',circ);
    c.style.transition=`stroke-dashoffset 0.9s cubic-bezier(.4,0,.2,1) ${i*0.06}s`;
    svg.appendChild(c);
    requestAnimationFrame(()=>requestAnimationFrame(()=>{c.style.strokeDashoffset=finalOffset;}));
    offset+=frac;
    const pct=Math.round(frac*100);
    legend.innerHTML+=`<div class="legend-item" onclick="goToCost('${escJ(b.key)}')"><span class="legend-dot" style="background:${col}"></span><span>${escH(b.key)} Cost</span><span class="legend-pct">${b.count} (${pct}%)</span></div>`;
  });
  const mk=(y,sz,fw,fill,txt)=>{const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',cx);t.setAttribute('y',y);t.setAttribute('text-anchor','middle');t.setAttribute('fill',fill);t.setAttribute('font-size',sz);t.setAttribute('font-weight',fw);t.textContent=txt;svg.appendChild(t);};
  mk(cy-6,'20','800','#e2e8f0',total);
  mk(cy+12,'10','400','#64748b','controls');
})();

// ── Top Threats Mitigated (Overview) ──
(function(){
  const freq = {};
  CONTROLS.forEach(c => c.threats.forEach(t => { if (t) freq[t] = (freq[t]||0)+1; }));
  const sorted = Object.entries(freq).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const el = document.getElementById('recentList');
  if (!sorted.length) { el.innerHTML = '<p style="color:var(--muted);font-size:13px">No threat data mapped on these recommendations.</p>'; return; }
  sorted.forEach(([threat,count]) => {
    el.innerHTML += `<div class="recent-row"><span class="recent-icon">⚠</span><span class="recent-name">${escH(threat)}</span><span class="recent-date">${count} recommendation${count!==1?'s':''}</span></div>`;
  });
})();

// ── Recommendations Table ──
let PAGE_SIZE=20, filteredControls=[...CONTROLS], currentPage=1, currentSort='rank-asc';
(function(){
  const catSel = document.getElementById('categoryFilter');
  CATEGORIES.forEach(c=>{const o=document.createElement('option');o.value=c.category;o.textContent=`${c.category} (${c.count})`;catSel.appendChild(o);});
  const tierSel = document.getElementById('tierFilter');
  const tiers = [...new Set(CONTROLS.map(c=>c.tier).filter(Boolean))].sort();
  tiers.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;tierSel.appendChild(o);});
  filterTable();
})();

function changePageSize() { PAGE_SIZE=parseInt(document.getElementById('pageSizeSelect').value); currentPage=1; renderTable(); }

function sortByCol(col) {
  const map={title:'title-asc',category:'category-asc',score:'score-desc',cost:'cost-asc'};
  const flip={asc:'desc',desc:'asc'};
  const cur=currentSort;
  if (cur.startsWith(col)) { const d=flip[cur.endsWith('asc')?'asc':'desc']; currentSort=col+'-'+d; }
  else { currentSort=map[col]||col+'-asc'; }
  document.getElementById('sortSelect').value = document.getElementById('sortSelect').querySelector(`option[value="${currentSort}"]`) ? currentSort : document.getElementById('sortSelect').value;
  document.querySelectorAll('.scripts-table thead th').forEach(t=>t.classList.remove('sort-active'));
  const th=document.getElementById('th-'+col);
  if(th){th.classList.add('sort-active');const a=th.querySelector('.sort-arrow');if(a)a.textContent=currentSort.endsWith('asc')?'↑':'↓';}
  filterTable();
}

function filterTable() {
  const q=document.getElementById('tableSearch').value.toLowerCase().trim();
  const category=document.getElementById('categoryFilter').value;
  const tier=document.getElementById('tierFilter').value;
  const impact=document.getElementById('impactFilter').value;
  const cost=document.getElementById('costFilter').value;
  currentSort=document.getElementById('sortSelect').value;
  filteredControls=CONTROLS.filter(c=>{
    const mQ=!q||c.title.toLowerCase().includes(q)||c.category.toLowerCase().includes(q)||c.service.toLowerCase().includes(q)||c.threats.some(t=>t.toLowerCase().includes(q));
    const mCat=!category||c.category===category;
    const mTier=!tier||c.tier===tier;
    const mImp=!impact||c.userImpact===impact;
    const mCost=!cost||c.implementationCost===cost;
    return mQ&&mCat&&mTier&&mImp&&mCost;
  });
  const costRank={Low:0,Moderate:1,High:2};
  const sorts={
    'title-asc':(a,b)=>a.title.localeCompare(b.title),
    'title-desc':(a,b)=>b.title.localeCompare(a.title),
    'category-asc':(a,b)=>a.category.localeCompare(b.category),
    'category-desc':(a,b)=>b.category.localeCompare(a.category),
    'rank-asc':(a,b)=>a.rank-b.rank,
    'score-desc':(a,b)=>b.maxScore-a.maxScore,
    'cost-asc':(a,b)=>(costRank[a.implementationCost]??9)-(costRank[b.implementationCost]??9),
    'cost-desc':(a,b)=>(costRank[b.implementationCost]??9)-(costRank[a.implementationCost]??9)
  };
  if(sorts[currentSort]) filteredControls.sort(sorts[currentSort]);
  currentPage=1; renderTable();
}

function renderTable() {
  const start=(currentPage-1)*PAGE_SIZE;
  const slice=filteredControls.slice(start,start+PAGE_SIZE);
  document.getElementById('resultCount').textContent=`${filteredControls.length} of ${CONTROLS.length}`;
  document.getElementById('pageInfo').textContent=`Showing ${filteredControls.length?start+1:0}–${Math.min(start+PAGE_SIZE,filteredControls.length)} of ${filteredControls.length}`;
  document.getElementById('recsTableBody').innerHTML=slice.map((c,idx)=>`
    <tr onclick="openDetailFromList(${start+idx})">
      <td class="td-name">${escH(c.title)}</td>
      <td>${catBadge(c.category)}</td>
      <td class="td-meta">${escH(c.tier||'—')}</td>
      <td class="td-meta">${c.maxScore}</td>
      <td class="td-meta" style="color:${levelColor(c.userImpact)}">${escH(c.userImpact||'—')}</td>
      <td class="td-meta" style="color:${levelColor(c.implementationCost)}">${escH(c.implementationCost||'—')}</td>
      <td class="td-meta">${c.threats.length}</td>
      <td><span class="help-dot" style="background:${c.deprecated?'var(--red)':'var(--green)'}" title="${c.deprecated?'Deprecated':'Active'}"></span></td>
    </tr>`).join('');
  renderPagination();
}

function renderPagination() {
  const total=Math.ceil(filteredControls.length/PAGE_SIZE);
  const el=document.getElementById('pagination');
  if(total<=1){el.innerHTML='';return;}
  let h=`<button class="page-btn" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>‹</button>`;
  for(let i=1;i<=total;i++){
    if(i===1||i===total||Math.abs(i-currentPage)<=1) h+=`<button class="page-btn ${i===currentPage?'active':''}" onclick="goPage(${i})">${i}</button>`;
    else if(Math.abs(i-currentPage)===2) h+=`<span style="color:var(--muted);padding:0 4px">…</span>`;
  }
  h+=`<button class="page-btn" onclick="goPage(${currentPage+1})" ${currentPage===total?'disabled':''}>›</button>`;
  el.innerHTML=h;
}

function goPage(p) {
  const total=Math.ceil(filteredControls.length/PAGE_SIZE);
  if(p<1||p>total) return;
  currentPage=p; renderTable();
  document.getElementById('page-recs').scrollTo(0,0);
}

// ── Category Explorer ──
const SHOW_INITIAL=6;
function buildExplorer(ft) {
  const grid=document.getElementById('verbGrid');
  const q=(ft||'').toLowerCase().trim();
  const sm=document.getElementById('explorerSort').value;
  grid.innerHTML=''; let vis=0;
  let cats=CATEGORIES.map(c=>({...c, totalScore: CONTROLS.filter(x=>x.category===c.category).reduce((s,x)=>s+x.maxScore,0)}));
  if(sm==='score-desc') cats.sort((a,b)=>b.totalScore-a.totalScore);
  else if(sm==='alpha') cats.sort((a,b)=>a.category.localeCompare(b.category));
  else cats.sort((a,b)=>b.count-a.count);
  cats.forEach((cat,i)=>{
    const col=CATEGORY_COLORS[cat.category]||PALETTE[i%PALETTE.length];
    let recs=CONTROLS.filter(c=>c.category===cat.category);
    if(q){recs=recs.filter(c=>cat.category.toLowerCase().includes(q)||c.title.toLowerCase().includes(q));if(!recs.length&&!cat.category.toLowerCase().includes(q))return;}
    if(!recs.length)return; vis++;
    recs=[...recs].sort((a,b)=>b.maxScore-a.maxScore);
    const init=recs.slice(0,SHOW_INITIAL), extra=recs.slice(SHOW_INITIAL), hasMore=extra.length>0;
    const mkRow=(c,h)=>`<div class="verb-script-row${h?' verb-hidden':''}" onclick="openDetail('${escJ(c.id)}')"><span class="vs-icon">▸</span><span class="vs-name" title="${escH(c.title)}">${escH(c.title)}</span><span class="vs-synopsis">${c.maxScore} pts</span></div>`;
    const footer=hasMore?`<div class="verb-footer"><div class="verb-show-more show-more-btn" onclick="toggleVerbExpand(this)"><span>▾ Show all</span><span class="vm-count">+${extra.length} more</span></div><div class="verb-show-more show-less-btn" onclick="toggleVerbExpand(this)"><span>▴ Show less</span></div></div>`:'';
    grid.innerHTML+=`<div class="verb-card" data-verb="${escH(cat.category)}"><div class="verb-card-head" style="border-left:3px solid ${col}"><span class="vname" style="color:${col}">${escH(cat.category)}</span><span class="vcount">${recs.length} · ${cat.totalScore} pts</span></div><div class="verb-scripts">${init.map(c=>mkRow(c,false)).join('')}${extra.map(c=>mkRow(c,true)).join('')}</div>${footer}</div>`;
  });
  const c=document.getElementById('explorerCount');
  if(c) c.textContent=vis+' categor'+(vis===1?'y':'ies');
}
function toggleVerbExpand(btn) {
  const card=btn.closest('.verb-card');
  const expanding=!card.classList.contains('expanded');
  card.classList.toggle('expanded');
  setTimeout(()=>card.scrollIntoView({behavior:'smooth',block:expanding?'start':'nearest'}),40);
}
function filterExplorer(){buildExplorer(document.getElementById('explorerSearch').value);}
buildExplorer();

// ── Analytics ──
(function(){
  const topScore=[...CONTROLS].sort((a,b)=>b.maxScore-a.maxScore).slice(0,8);
  document.getElementById('topByScore').innerHTML=topScore.map((c,i)=>`<div class="top-list-row" onclick="openDetail('${escJ(c.id)}')"><span class="tl-rank">${i+1}</span><span class="tl-name" title="${escH(c.title)}">${escH(c.title)}</span><span class="tl-val">${c.maxScore} pts</span></div>`).join('');

  const freq = {};
  CONTROLS.forEach(c => c.threats.forEach(t => { if (t) freq[t] = (freq[t]||0)+1; }));
  const topT = Object.entries(freq).sort((a,b)=>b[1]-a[1]).slice(0,8);
  document.getElementById('topThreats').innerHTML = topT.length ? topT.map(([t,cnt],i)=>`<div class="top-list-row"><span class="tl-rank">${i+1}</span><span class="tl-name" title="${escH(t)}">${escH(t)}</span><span class="tl-val">${cnt}</span></div>`).join('') : '<p style="color:var(--muted);font-size:13px">No threat data mapped.</p>';

  const catScores = CATEGORIES.map(c=>({category:c.category,total:CONTROLS.filter(x=>x.category===c.category).reduce((s,x)=>s+x.maxScore,0)})).sort((a,b)=>b.total-a.total);
  const csMax = Math.max(...catScores.map(c=>c.total),1);
  document.getElementById('scoreByCategory').innerHTML = catScores.map((c,i)=>{
    const col=CATEGORY_COLORS[c.category]||PALETTE[i%PALETTE.length], pct=Math.round((c.total/csMax)*100);
    return `<div class="hc-row"><span class="hc-label" title="${escH(c.category)}">${escH(c.category)}</span><div class="hc-track"><div class="hc-fill" style="width:0%;background:${col}" data-pct="${pct}"></div></div><span class="hc-count">${c.total} pts</span></div>`;
  }).join('');

  const tiers = [...new Set(CONTROLS.map(c=>c.tier).filter(Boolean))];
  const tMax = Math.max(...tiers.map(t=>CONTROLS.filter(c=>c.tier===t).length),1);
  document.getElementById('tierBreakdown').innerHTML = tiers.length ? tiers.map((t,i)=>{
    const cnt=CONTROLS.filter(c=>c.tier===t).length, pct=Math.round((cnt/tMax)*100), col=PALETTE[i%PALETTE.length];
    return `<div class="hc-row"><span class="hc-label" title="${escH(t)}">${escH(t)}</span><div class="hc-track"><div class="hc-fill" style="width:0%;background:${col}" data-pct="${pct}"></div></div><span class="hc-count">${cnt} recs</span></div>`;
  }).join('') : '<p style="color:var(--muted);font-size:13px">No tier data available.</p>';

  const costLevels=['Low','Moderate','High'];
  const cMax = Math.max(...costLevels.map(l=>CONTROLS.filter(c=>c.implementationCost===l).length),1);
  document.getElementById('costDistribution').innerHTML = costLevels.map(l=>{
    const cnt=CONTROLS.filter(c=>c.implementationCost===l).length, pct=Math.round((cnt/cMax)*100);
    return `<div class="hc-row"><span class="hc-label">${l} Cost</span><div class="hc-track"><div class="hc-fill" style="width:0%;background:${levelColor(l)}" data-pct="${pct}"></div></div><span class="hc-count">${cnt} recs</span></div>`;
  }).join('');

  const impLevels=['Low','Moderate','High'];
  const iMax = Math.max(...impLevels.map(l=>CONTROLS.filter(c=>c.userImpact===l).length),1);
  document.getElementById('impactDistribution').innerHTML = impLevels.map(l=>{
    const cnt=CONTROLS.filter(c=>c.userImpact===l).length, pct=Math.round((cnt/iMax)*100);
    return `<div class="hc-row"><span class="hc-label">${l} Impact</span><div class="hc-track"><div class="hc-fill" style="width:0%;background:${levelColor(l)}" data-pct="${pct}"></div></div><span class="hc-count">${cnt} recs</span></div>`;
  }).join('');

  requestAnimationFrame(()=>{
    document.querySelectorAll('.hc-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';});
  });
})();

// ── Detail panel ──
let currentDetailIndex=-1, detailList=CONTROLS;
function openDetailFromList(idx){detailList=filteredControls;currentDetailIndex=idx;_renderDetail(detailList[idx]);}
function openDetail(id){const idx=CONTROLS.findIndex(x=>x.id===id);detailList=CONTROLS;currentDetailIndex=idx;if(idx>=0)_renderDetail(CONTROLS[idx]);}
function navigateDetail(dir){const ni=currentDetailIndex+dir;if(ni<0||ni>=detailList.length)return;currentDetailIndex=ni;_renderDetail(detailList[ni]);}
function _renderDetail(c){
  if(!c)return;
  document.getElementById('detailPrevBtn').disabled=currentDetailIndex<=0;
  document.getElementById('detailNextBtn').disabled=currentDetailIndex>=detailList.length-1;
  const threatsHtml = c.threats.length ? c.threats.map(t=>`<span class="detail-chip">⚠ ${escH(t)}</span>`).join('') : '<span class="detail-chip" style="color:var(--muted)">No threats mapped</span>';
  // NOTE: c.remediation is Microsoft-authored HTML from Graph and is intentionally
  // rendered raw (not escaped) so ordered-list steps and links stay usable. See the
  // "HTML EXPORT — REMEDIATION RENDERING" note in the function's comment-based help.
  const remediationHtml = c.remediation ? c.remediation : '<p style="color:var(--muted)">No remediation guidance provided.</p>';
  document.getElementById('detailContent').innerHTML=`
    <div class="detail-header">
      <div class="detail-name">${escH(c.title)}</div>
      <div class="detail-path">${escH(c.id)} &middot; ${escH(c.service||'—')}</div>
    </div>
    <div class="detail-meta-row">
      ${catBadge(c.category)}
      <span class="detail-chip">🏷 ${escH(c.tier||'—')}</span>
      <span class="detail-chip">⚙ ${escH(c.actionType||'—')}</span>
      <span class="detail-chip">🔢 Rank ${c.rank}</span>
      <span class="detail-chip">💯 ${c.maxScore} pts</span>
      <span class="detail-chip" style="color:${levelColor(c.userImpact)}">👤 ${escH(c.userImpact||'—')} impact</span>
      <span class="detail-chip" style="color:${levelColor(c.implementationCost)}">🛠 ${escH(c.implementationCost||'—')} cost</span>
      <span class="detail-chip" style="color:${c.deprecated?'var(--red)':'var(--green)'}">${c.deprecated?'⚠ Deprecated':'✅ Active'}</span>
      <span class="detail-chip">🕐 ${escH(c.lastModified||'—')}</span>
    </div>
    <div class="detail-section"><div class="detail-section-title">Threats Mitigated</div><div class="detail-meta-row">${threatsHtml}</div></div>
    <div class="detail-section"><div class="detail-section-title">Remediation Steps</div><div class="detail-description">${remediationHtml}</div></div>
    <div class="detail-section"><div class="detail-section-title">Remediation Impact</div><div class="detail-description">${escH(c.remediationImpact)||'—'}</div></div>`;
  document.getElementById('detailPanel').classList.add('open');
  document.body.style.overflow='hidden';
  document.getElementById('detailContent').scrollTo(0,0);
}
function closeDetail(){document.getElementById('detailPanel').classList.remove('open');document.body.style.overflow='';}
function copyDetailId(){if(currentDetailIndex>=0&&detailList[currentDetailIndex])copyText(detailList[currentDetailIndex].id,null);}
function copyText(text,btn){
  try{navigator.clipboard.writeText(text).then(()=>{showToast('Copied to clipboard!');if(btn){btn.textContent='Copied!';btn.classList.add('copied');setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('copied');},1800);}});}
  catch(e){showToast('Copy not available','⚠');}
}

// ── Exports ──
function exportCSV(filtered){
  const data=filtered?filteredControls:CONTROLS;
  const esc=v=>`"${String(v??'').replace(/"/g,'""')}"`;
  const rows=data.map(c=>[esc(c.id),esc(c.title),esc(c.category),esc(c.tier),esc(c.service),esc(c.actionType),c.rank,c.maxScore,esc(c.userImpact),esc(c.implementationCost),c.deprecated,esc(c.threats.join('; ')),esc(c.lastModified)].join(','));
  dlFile(['Id,Title,Category,Tier,Service,ActionType,Rank,MaxScore,UserImpact,ImplementationCost,Deprecated,Threats,LastModified',...rows].join('\r\n'),'SecureScoreRecommendations.csv','text/csv');
  showToast(`Exported ${data.length} recommendations as CSV`);
}
function exportJSON(filtered){
  const data=filtered?filteredControls:CONTROLS;
  dlFile(JSON.stringify(data,null,2),'SecureScoreRecommendations.json','application/json');
  showToast(`Exported ${data.length} recommendations as JSON`);
}
function dlFile(content,name,type){const b=new Blob([content],{type});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=name;a.click();URL.revokeObjectURL(u);}

// ── Keyboard shortcuts ──
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closeDetail();return;}
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'&&document.activeElement.tagName!=='SELECT'){
    e.preventDefault();
    const inp=document.querySelector('.page.active input[type=text]');
    if(inp) inp.focus();
  }
  if(document.getElementById('detailPanel').classList.contains('open')){
    if(e.key==='ArrowLeft')  navigateDetail(-1);
    if(e.key==='ArrowRight') navigateDetail(1);
  }
});

// ── Utils ──
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
</script>
</body>
</html>
'@

        $html = $html `
            -replace '__FILTERDISPLAY__',   $filterDisplay `
            -replace '__RECCOUNT__',        $totalRecs `
            -replace '__CATCOUNT__',        $categoryCount `
            -replace '__TOTALSCORE__',      $totalMaxScore `
            -replace '__AVGSCORE__',        $avgMaxScore `
            -replace '__DEPRECATEDCOUNT__', $deprecatedCount `
            -replace '__QUICKWINCOUNT__',   $quickWinCount `
            -replace '__QUICKWINPCT__',     $quickWinPct `
            -replace '__GENERATEDAT__',     $generatedAt `
            -replace '__CONTROLS_JSON__',   $controlsJson `
            -replace '__CATEGORIES_JSON__', $categoriesJson

        $html | Out-File -FilePath $ExportPath -Encoding UTF8 -Force

        Write-Host ""
        Write-Host "Secure Score dashboard exported successfully -> $ExportPath" -ForegroundColor Green
    }

    return $allControls
}
