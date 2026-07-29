<#

Author       : Lakshmanan Thangaraj
Version      : 2.0
Created-On   : 29 July 2026
Modified-On  : 29 July 2026

.SYNOPSIS
    Builds a self-contained HTML dashboard from an Azure NSG inventory CSV
    with risk scoring, an NSG explorer, a searchable rules table, and a
    drag-drop control to swap in a fresher CSV.

.DESCRIPTION
    Generate-AzureNSGDashboard reads an Azure NSG inventory CSV - the export
    produced by Get-AzureNSGInventory.ps1 - and embeds its raw text into a
    static HTML file. The dashboard renders client-side via a single
    JavaScript CSV parser that also backs an in-browser "Load CSV" drag-drop
    control, so the same rendering logic handles both the PowerShell-generated
    snapshot and any CSV dropped onto the page later, with no duplicated
    parsing logic between PowerShell and JavaScript.

    Dashboard tabs:
        - Overview      - stat cards, risk score ring, top risky rules,
                           direction/protocol/access breakdowns
        - NSG Explorer  - card per NSG (subs/RG/location/associations),
                          click for full per-NSG rule detail panel
        - Rules Table   - search/filter/sort every rule, CSV export
        - Risk Analysis - only flagged rules, severity-sorted, with reason
        - Rule Conflicts - shadowed (unreachable) rules and exact duplicate
                            rules, detected within the same NSG + direction
        - Summary       - one-page printable executive summary of the
                           current scope (stat rollup, exposure breakdown,
                           conflict counts, top flagged rules)

    Risk heuristic (client-side, transparent - not a compliance verdict):
    a rule is flagged when Direction is Inbound, Access is Allow, and the
    source is "*" / "Internet" / "0.0.0.0/0" (or SourceAddressAll = true).
    Severity is Critical when the destination port is "*" (all ports open),
    High when it is a sensitive port (22, 3389, 1433, 3306, 5432, 445, 6379,
    27017, 21, 23, 5900), otherwise Medium. Whether a flagged rule is
    actually exploitable could not be confirmed from the CSV alone (for
    example, compensating NVA or route-table controls) - the dashboard
    labels this a review candidate, not a confirmed vulnerability.

    Rule Conflicts heuristic (client-side, also a review candidate, not a
    certainty): within the same NSG + direction, rules are evaluated in
    ascending priority order. A rule is "shadowed" when an earlier-priority
    rule already covers everything it would match (protocol/source/port each
    equal or wildcarded by the earlier rule) - regardless of Access - because
    Azure NSGs stop at the first matching rule. Two rules are "duplicates"
    when protocol, source, destination port, and access are all identical.

.PARAMETER CsvPath
    Path to the Azure NSG inventory CSV produced by Get-AzureNSGInventory.ps1.

.PARAMETER OutputPath
    Where to save the generated HTML dashboard.
    Defaults to "$env:TEMP\AzureNSGDashboard.html".

.PARAMETER OpenBrowser
    If specified, opens the generated dashboard in the default browser.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None. Writes an HTML file to -OutputPath.

.EXAMPLE
    Generate-AzureNSGDashboard -CsvPath "C:\Reports\Azure_NSG_Inventory.csv" -OpenBrowser

    Generates the dashboard and opens it in the default browser.

.EXAMPLE
    Generate-AzureNSGDashboard -CsvPath ".\NSG_Inventory.csv" -OutputPath "C:\Reports\NSGDashboard.html"

    Generates the dashboard to a specific output path without opening it.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    2.1 (29-Jul-2026) - Bug fix: the embedded dashboard called
                         computeConflicts(), renderConflicts(), renderSummary()
                         and printSummary() from renderAll() / the Summary tab's
                         Print button, but none of the four were actually
                         defined in the embedded JavaScript. computeConflicts()
                         being undefined threw a ReferenceError on every load,
                         which silently aborted the rest of renderAll() - so
                         the Rule Conflicts tab, the Summary tab, and the
                         sidebar's Rule Conflicts badge count never rendered
                         (the Summary tab is what surfaced as "empty" since it
                         has no other content to fall back on). Implemented all
                         four functions. No change to any other tab, to the
                         risk heuristic, to the embedded-CSV/JSON-escape
                         mechanism, or to any existing markup/CSS/param
                         validation.
    2.0 (29-Jul-2026) - Converted from a standalone script to an advanced
                         function (Generate-AzureNSGDashboard) so it can be
                         dot-sourced/imported alongside the rest of the
                         toolkit instead of invoked as a .ps1 file; brought
                         comment-based help in line with the repo template
                         (Version History / Pre-Requisites / Known
                         Limitations under .NOTES); added the
                         Get-AzureNSGInventory.ps1 source-script link under
                         .LINK. No change to dashboard behaviour or output.
    1.0 (29-Jul-2026) - Initial release (standalone script).

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. PowerShell 5.1 or later.
    2. A CSV produced by Get-AzureNSGInventory.ps1 (or one matching its
       column headers) - see the .LINK section below for the source script.
    3. No internet connection is required to view the generated dashboard;
       it has no CDN dependencies.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW:
    ─────────────────────────────────────────────────────────────────────────────
    1. Validate -CsvPath exists, is a .csv file, and contains no
       path-traversal characters.
    2. Read the raw CSV text and JSON-escape it for safe embedding in
       <script>.
    3. Inject the escaped text and generation metadata into the HTML
       template.
    4. Write the HTML file to -OutputPath.
    5. Optionally open it in the default browser.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Risk heuristic covers common Allow+Inbound+Any exposure patterns only;
      it does not evaluate route tables, Azure Firewall, or third-party NVAs
      sitting in front of the subnet, so a flagged rule is a review
      candidate, not a confirmed vulnerability.
    - Rule Conflicts heuristic matches on protocol/source/destination-port
      equality-or-wildcard only; it does not evaluate CIDR subset/overlap
      (e.g. 10.0.0.0/8 vs 10.1.0.0/16) or port-range overlap (e.g. 20-25 vs
      22), so it will under-report partial overlaps - shadowed/duplicate
      results are a review candidate, not a certainty.
    - Expects the exact column headers emitted by Get-AzureNSGInventory.ps1;
      if that script's schema changes, update the COLMAP object in the
      embedded JavaScript.

.LINK
    Get-AzureNSGInventory.ps1 - source script that generates the input CSV
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/Network/Get-AzureNSGInventory.ps1

.LINK
    Azure network security groups overview
    https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview

.LINK
    about_Functions_Advanced
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions_advanced

#>


Function Generate-AzureNSGDashboard
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if ($_ -match '\.\.') { throw "CsvPath must not contain path-traversal characters ('..')." }
        if (-not (Test-Path -Path $_ -PathType Leaf)) { throw "File not found: $_" }
        if ([System.IO.Path]::GetExtension($_) -ne '.csv') { throw "CsvPath must point to a .csv file." }
        $true
      })]
    [string]$CsvPath,

    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if ($_ -match '\.\.') { throw "OutputPath must not contain path-traversal characters ('..')." }
        $true
      })]
    [string]$OutputPath = "$env:TEMP\AzureNSGDashboard.html",

    [switch]$OpenBrowser
  )

  #region ── Read & Validate CSV ────────────────────────────────────────────────

  Write-Host ""
  Write-Host "  🔎  Reading NSG inventory CSV…" -ForegroundColor Cyan

  $rawCsvText = ''
  $rowCount = 0
  $sourceLabel = Split-Path -Path $CsvPath -Leaf

  try {
    $rawCsvText = Get-Content -Path $CsvPath -Raw -ErrorAction Stop

    # Sanity-check: parse once so we fail fast on a malformed CSV with a clear message.
    $parsedRows = Import-Csv -Path $CsvPath -ErrorAction Stop
    $rowCount = $parsedRows.Count

    if ($rowCount -eq 0) {
      Write-Warning "CSV parsed successfully but contains 0 data rows. Dashboard will render empty."
    }

    $requiredColumns = @('NSGName', 'RuleDirection', 'RuleAccess', 'SourceAddressPrefix', 'DestinationPortRange')
    $actualColumns = ($parsedRows | Select-Object -First 1).PSObject.Properties.Name
    $missingColumns = $requiredColumns | Where-Object { $_ -notin $actualColumns }
    if ($missingColumns) {
      throw "CSV is missing expected column(s): $($missingColumns -join ', '). This does not look like Get-AzureNSGInventory.ps1 output."
    }
  }
  catch {
    Write-Error "Failed to read/validate CSV at '$CsvPath': $($_.Exception.Message)"
    return
  }

  Write-Host "  ✅  CSV validated — $rowCount rule rows found." -ForegroundColor Green

  #endregion

  #region ── JSON-safe embed of raw CSV text ────────────────────────────────────

  # ConvertTo-Json on a raw string yields a correctly-escaped, quoted JS string
  # literal (handles quotes, backslashes, newlines, unicode) — reused verbatim
  # in the HTML template so PowerShell never has to re-implement CSV parsing.
  $csvJsonLiteral = $rawCsvText | ConvertTo-Json -Compress

  $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')

  #endregion

  #region ── HTML Dashboard Template ────────────────────────────────────────────

  $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure NSG Inventory Dashboard</title>
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
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s;display:flex;align-items:stretch}
a{color:var(--accent)}

/* Sidebar */
#sidebar{position:sticky;top:0;height:100vh;flex:0 0 236px;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
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
.upload-wrap{padding:10px 14px;border-top:1px solid var(--border)}
.scope-wrap{padding:12px 14px;border-top:1px solid var(--border)}
.scope-label{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.scope-select{width:100%;padding:7px 9px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:12px;margin-bottom:6px}
.scope-select:last-child{margin-bottom:0}
.scope-active-note{font-size:10.5px;color:var(--accent);margin-top:4px;display:none}
.sev-Gap{background:rgba(248,81,73,.18);color:var(--red)}
.sev-Blocked{background:rgba(210,153,34,.18);color:var(--amber)}
.sev-Duplicate{background:rgba(163,113,247,.18);color:var(--accent3)}
.summary-sheet{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:28px;max-width:760px}
.summary-sheet h2{font-size:19px;margin-bottom:2px}
.summary-sheet .sm-sub{font-size:12px;color:var(--muted);margin-bottom:18px}
.sm-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
.sm-cell{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px;text-align:center}
.sm-cell .sm-val{font-size:20px;font-weight:700;font-family:var(--mono)}
.sm-cell .sm-lbl{font-size:10px;color:var(--muted);margin-top:2px}
.sm-section{margin-bottom:16px}
.sm-section h4{font-size:12.5px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted2);margin-bottom:8px}
.sm-row{display:flex;justify-content:space-between;font-size:12.5px;padding:6px 0;border-bottom:1px solid var(--border)}
.sm-note{font-size:11px;color:var(--muted);margin-top:14px;border-top:1px solid var(--border);padding-top:10px}
@media print{
  #sidebar,.toast,.overlay,#detailPanel,.btn-group,.upload-wrap,.scope-wrap,.theme-toggle-wrap,.sidebar-footer{display:none !important}
  body{display:block}
  #main{margin:0;padding:0}
  .page{display:none !important}
  .page.active{display:block !important}
  .summary-sheet{border:none;max-width:100%}
}
.upload-btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:9px 12px;background:var(--surface2);border:1px dashed var(--accent);border-radius:var(--radius-sm);cursor:pointer;color:var(--accent);font-family:var(--sans);font-size:12.5px;font-weight:600;transition:all .2s}
.upload-btn:hover{background:rgba(56,139,253,.12)}
.upload-btn input{display:none}
.theme-toggle-wrap{padding:10px 14px;border-top:1px solid var(--border)}
.theme-toggle{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;transition:all .2s}
.theme-toggle:hover{border-color:var(--accent);color:var(--text)}
.toggle-pill{width:34px;height:18px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--muted2);transition:transform .2s,background .2s}
body.light-theme .toggle-pill{background:var(--accent)}
body.light-theme .toggle-pill::after{transform:translateX(16px);background:#fff}
.sidebar-footer{padding:12px 18px;border-top:1px solid var(--border);font-size:10.5px;color:var(--muted);font-family:var(--mono);line-height:1.5}
kbd{background:var(--surface3);border:1px solid var(--border);border-radius:3px;padding:0 4px;font-size:10px}

/* Main */
#main{flex:1 1 auto;min-width:0;padding:24px 30px 60px}
.page{display:none;animation:fadeIn .25s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.page-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:20px}
.page-title{font-size:22px;font-weight:700}
.page-subtitle{font-size:13px;color:var(--muted);margin-top:2px}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
.btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px 14px;border-radius:var(--radius-sm);font-size:12.5px;font-family:var(--sans);cursor:pointer;transition:all .18s}
.btn:hover{border-color:var(--accent);color:var(--accent)}

.stats-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px}
@media(max-width:1200px){.stats-grid{grid-template-columns:repeat(3,1fr)}}
@media(max-width:640px){.stats-grid{grid-template-columns:repeat(2,1fr)}#main{padding:18px}body{flex-direction:column}#sidebar{position:relative;top:auto;height:auto;flex:0 0 auto;width:100%}}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;position:relative;overflow:hidden}
.stat-icon{font-size:18px;opacity:.85;margin-bottom:6px}
.stat-value{font-size:24px;font-weight:700;font-family:var(--mono)}
.stat-label{font-size:11.5px;color:var(--muted);margin-top:2px}
.c-blue .stat-value{color:var(--accent)} .c-cyan .stat-value{color:var(--accent2)} .c-purple .stat-value{color:var(--accent3)}
.c-green .stat-value{color:var(--green)} .c-red .stat-value{color:var(--red)} .c-amber .stat-value{color:var(--amber)}

.health-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;display:flex;gap:24px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
.health-ring-wrap{position:relative;width:110px;height:110px;flex-shrink:0}
.health-ring-wrap svg{width:100%;height:100%}
.health-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.health-score-num{font-size:26px;font-weight:700;font-family:var(--mono)}
.health-score-pct{font-size:10px;color:var(--muted)}
.health-info{flex:1;min-width:220px}
.health-info h3{font-size:15px;margin-bottom:3px}
.health-info p{font-size:12.5px;color:var(--muted);margin-bottom:10px}
.health-bar-row{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.health-mini-bar{flex:1;height:7px;background:var(--surface3);border-radius:4px;overflow:hidden}
.health-mini-fill{height:100%;border-radius:4px;transition:width 1s ease}

.chart-grid{display:grid;grid-template-columns:1.3fr 1fr;gap:16px;margin-bottom:20px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.section-title{font-size:13.5px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:6px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px;cursor:pointer}
.bar-label{width:120px;font-size:12px;color:var(--muted2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0}
.bar-track{flex:1;height:16px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .9s ease}
.bar-count{width:34px;text-align:right;font-family:var(--mono);font-size:12px;color:var(--muted)}
.legend-list{display:flex;flex-direction:column;gap:6px;margin-top:10px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:12px}
.legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}

.top-list-row{display:flex;align-items:center;gap:10px;padding:8px 4px;border-bottom:1px solid var(--border);cursor:pointer;font-size:12.5px}
.top-list-row:last-child{border-bottom:none}
.top-list-row:hover{background:var(--surface2)}
.tl-rank{width:20px;text-align:center;color:var(--muted);font-family:var(--mono);flex-shrink:0}
.tl-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tl-val{font-family:var(--mono);color:var(--muted);font-size:11.5px}
.sev-badge{font-size:10px;font-weight:700;padding:2px 7px;border-radius:20px;font-family:var(--mono);flex-shrink:0}
.sev-Critical{background:rgba(248,81,73,.18);color:var(--red)}
.sev-High{background:rgba(210,153,34,.18);color:var(--amber)}
.sev-Medium{background:rgba(56,139,253,.18);color:var(--accent)}
.sev-None{background:rgba(63,185,80,.18);color:var(--green)}

/* Toolbar / table */
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.search-wrap{position:relative;flex:1;min-width:220px}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);font-size:13px;opacity:.6}
.search-wrap input{width:100%;padding:9px 12px 9px 32px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px}
select{padding:8px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:12.5px;font-family:var(--sans)}
.result-count{font-size:12px;color:var(--muted);white-space:nowrap}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;font-size:12.5px}
thead th{text-align:left;padding:10px 12px;background:var(--surface2);color:var(--muted2);font-size:11px;text-transform:uppercase;letter-spacing:.04em;cursor:pointer;white-space:nowrap;user-select:none}
thead th:hover{color:var(--accent)}
.sort-arrow{opacity:.4;font-size:10px}
tbody td{padding:9px 12px;border-top:1px solid var(--border);vertical-align:top}
tbody tr:hover{background:var(--surface2)}
.chip{display:inline-block;padding:1px 8px;border-radius:20px;font-size:10.5px;font-family:var(--mono)}
.chip-allow{background:rgba(63,185,80,.15);color:var(--green)}
.chip-deny{background:rgba(248,81,73,.15);color:var(--red)}
.chip-in{background:rgba(56,139,253,.15);color:var(--accent)}
.chip-out{background:rgba(163,113,247,.15);color:var(--accent3)}
.mono{font-family:var(--mono);font-size:12px}
.pagination{display:flex;gap:5px}
.pagination button{width:28px;height:28px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);cursor:pointer;font-size:12px}
.pagination button.active{background:var(--accent);border-color:var(--accent);color:#fff}
.pagination button:disabled{opacity:.35;cursor:default}

/* NSG Explorer */
.nsg-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.nsg-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;cursor:pointer;transition:all .18s}
.nsg-card:hover{border-color:var(--accent);transform:translateY(-2px)}
.nsg-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:8px}
.nsg-card-name{font-size:14.5px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nsg-card-sub{font-size:11.5px;color:var(--muted);margin-bottom:10px}
.nsg-card-meta{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.meta-chip{background:var(--surface3);color:var(--muted2);font-size:10.5px;padding:2px 8px;border-radius:20px;font-family:var(--mono)}
.nsg-card-foot{display:flex;justify-content:space-between;align-items:center;padding-top:10px;border-top:1px solid var(--border)}
.orphan-flag{color:var(--amber);font-size:11px;font-weight:600}

/* Detail panel */
#detailPanel{position:fixed;top:0;right:-560px;width:560px;max-width:92vw;bottom:0;background:var(--surface);border-left:1px solid var(--border);z-index:200;transition:right .3s ease;display:flex;flex-direction:column;box-shadow:var(--shadow)}
#detailPanel.open{right:0}
.detail-topbar{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--border)}
.detail-close{background:var(--surface2);border:1px solid var(--border);border-radius:6px;width:30px;height:30px;cursor:pointer;color:var(--text);font-size:14px}
#detailContent{flex:1;overflow-y:auto;padding:20px}
.detail-name{font-size:17px;font-weight:700;margin-bottom:4px}
.detail-path{font-family:var(--mono);font-size:11px;color:var(--muted);word-break:break-all;margin-bottom:12px}
.detail-meta-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
.detail-chip{background:var(--surface3);padding:4px 10px;border-radius:20px;font-size:11.5px}
.detail-section{margin-bottom:16px}
.detail-section-title{font-size:12.5px;font-weight:700;color:var(--muted2);margin-bottom:8px;text-transform:uppercase;letter-spacing:.03em}
.mini-rule{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:8px;font-size:12px}
.mini-rule-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;font-weight:700}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:150;display:none}
.overlay.open{display:block}

.dropzone{border:2px dashed var(--border);border-radius:var(--radius);padding:40px 20px;text-align:center;color:var(--muted);margin-bottom:20px;transition:all .2s}
.dropzone.dragover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.06)}

.toast{position:fixed;bottom:20px;right:20px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:10px 16px;border-radius:8px;font-size:13px;box-shadow:var(--shadow);z-index:300;opacity:0;transform:translateY(10px);transition:all .25s}
.toast.show{opacity:1;transform:none}
</style>
</head>
<body>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🛡️</div>
    <h1>NSG Inventory Dashboard</h1>
    <p id="sourceLabel">__SOURCELABEL__</p>
    <span class="version-badge">v1.0</span>
  </div>
  <div class="scope-wrap">
    <div class="scope-label">Scope</div>
    <select class="scope-select" id="scopeSub" onchange="onScopeSubChange()"><option value="">All Subscriptions</option></select>
    <select class="scope-select" id="scopeRG" onchange="applyScope()"><option value="">All Resource Groups</option></select>
    <div class="scope-active-note" id="scopeActiveNote"></div>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Dashboard</div>
    <button class="nav-btn active" data-page="overview" onclick="goToPage('overview')"><span class="nav-icon">📊</span>Overview</button>
    <button class="nav-btn" data-page="explorer" onclick="goToPage('explorer')"><span class="nav-icon">🗂️</span>NSG Explorer<span class="nav-badge" id="navNsgCount">0</span></button>
    <button class="nav-btn" data-page="rules" onclick="goToPage('rules')"><span class="nav-icon">📋</span>Rules Table<span class="nav-badge" id="navRuleCount">0</span></button>
    <button class="nav-btn" data-page="risk" onclick="goToPage('risk')"><span class="nav-icon">⚠️</span>Risk Analysis<span class="nav-badge" id="navRiskCount">0</span></button>
    <button class="nav-btn" data-page="conflicts" onclick="goToPage('conflicts')"><span class="nav-icon">🧩</span>Rule Conflicts<span class="nav-badge" id="navConflictCount">0</span></button>
    <button class="nav-btn" data-page="summary" onclick="goToPage('summary')"><span class="nav-icon">🖨️</span>Summary</button>
  </div>
  <div class="upload-wrap">
    <label class="upload-btn">📁 Load CSV
      <input type="file" id="fileInput" accept=".csv" onchange="handleFileInput(event)"/>
    </label>
  </div>
  <div class="theme-toggle-wrap">
    <button class="theme-toggle" onclick="toggleTheme()"><span class="toggle-pill" id="togglePill"></span><span id="themeLabel">Dark theme</span></button>
  </div>
  <div class="sidebar-footer">
    Generated<br>__GENERATEDAT__<br>
    <span style="color:var(--accent2)">⌨</span> <kbd>/</kbd> search
  </div>
</nav>

<main id="main">

<!-- OVERVIEW -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Overview</div>
      <div class="page-subtitle">Snapshot of NSGs and rules across your subscriptions</div>
    </div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('rules')">⬇ Export Rules CSV</button></div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">🛡️</div><div class="stat-value" id="statNsgs">0</div><div class="stat-label">NSGs</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">📋</div><div class="stat-value" id="statRules">0</div><div class="stat-label">Total Rules</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">🏢</div><div class="stat-value" id="statSubs">0</div><div class="stat-label">Subscriptions</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">📁</div><div class="stat-value" id="statRGs">0</div><div class="stat-label">Resource Groups</div></div>
    <div class="stat-card c-red"><div class="stat-icon">🚨</div><div class="stat-value" id="statFlagged">0</div><div class="stat-label">Flagged Rules</div></div>
    <div class="stat-card c-green"><div class="stat-icon">🕸️</div><div class="stat-value" id="statOrphan">0</div><div class="stat-label">Orphaned NSGs</div></div>
  </div>

  <div class="health-card">
    <div class="health-ring-wrap">
      <svg viewBox="0 0 76 76">
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--surface3)" stroke-width="9"/>
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--green)" stroke-width="9"
          stroke-dasharray="188.5" stroke-dashoffset="188.5" stroke-linecap="round"
          transform="rotate(-90 38 38)" id="riskArc" style="transition:stroke-dashoffset 1.2s ease"/>
      </svg>
      <div class="health-ring-center"><span class="health-score-num" id="riskNum">100</span><span class="health-score-pct">/ 100</span></div>
    </div>
    <div class="health-info">
      <h3>Exposure Score</h3>
      <p>100 = no flagged Allow+Inbound+Any rules found. Lower = more/worse exposure. A review candidate, not a compliance verdict.</p>
      <div class="health-bar-row"><span style="color:var(--red);font-size:12px">🔴 Critical</span><div class="health-mini-bar"><div class="health-mini-fill" id="hCrit" style="background:var(--red);width:0%"></div></div><span class="mono" id="hCritN" style="font-size:12px;color:var(--muted)">0</span></div>
      <div class="health-bar-row"><span style="color:var(--amber);font-size:12px">🟠 High</span><div class="health-mini-bar"><div class="health-mini-fill" id="hHigh" style="background:var(--amber);width:0%"></div></div><span class="mono" id="hHighN" style="font-size:12px;color:var(--muted)">0</span></div>
      <div class="health-bar-row"><span style="color:var(--accent);font-size:12px">🔵 Medium</span><div class="health-mini-bar"><div class="health-mini-fill" id="hMed" style="background:var(--accent);width:0%"></div></div><span class="mono" id="hMedN" style="font-size:12px;color:var(--muted)">0</span></div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Rules by Protocol</div>
      <div id="protoBars"></div>
    </div>
    <div class="panel">
      <div class="section-title">🍩 Direction / Access</div>
      <div id="dirLegend" class="legend-list"></div>
    </div>
  </div>

  <div class="panel">
    <div class="section-title">⚠️ Top Flagged Rules <span style="font-size:11px;color:var(--muted);font-weight:400">(click to inspect the NSG)</span></div>
    <div id="topRisky"></div>
  </div>
</section>

<!-- NSG EXPLORER -->
<section id="page-explorer" class="page">
  <div class="page-header">
    <div><div class="page-title">NSG Explorer</div><div class="page-subtitle">Every NSG with its associations and rule count</div></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔎</span><input type="text" id="explorerSearch" placeholder="Search NSG, resource group, subscription…" oninput="renderExplorer()"/></div>
    <select id="explorerSort" onchange="renderExplorer()">
      <option value="risk-desc">Most Flagged Rules</option>
      <option value="rules-desc">Most Rules</option>
      <option value="alpha">Alphabetical</option>
    </select>
    <span class="result-count" id="explorerCount"></span>
  </div>
  <div class="nsg-grid" id="nsgGrid"></div>
</section>

<!-- RULES TABLE -->
<section id="page-rules" class="page">
  <div class="page-header">
    <div><div class="page-title">Rules Table</div><div class="page-subtitle">Search, filter and export every NSG rule</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('filtered')">⬇ Export Filtered CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔎</span><input type="text" id="rulesSearch" placeholder="Search NSG, rule name, prefix, port… (press / to focus)" oninput="filterRules()"/></div>
    <select id="dirFilter" onchange="filterRules()"><option value="">All Directions</option><option value="Inbound">Inbound</option><option value="Outbound">Outbound</option></select>
    <select id="accessFilter" onchange="filterRules()"><option value="">All Access</option><option value="Allow">Allow</option><option value="Deny">Deny</option></select>
    <select id="riskFilter" onchange="filterRules()"><option value="">All Rules</option><option value="flagged">🚨 Flagged only</option></select>
    <span class="result-count" id="rulesResultCount"></span>
  </div>
  <table>
    <thead><tr>
      <th onclick="sortRules('nsgName')">NSG <span class="sort-arrow">↕</span></th>
      <th onclick="sortRules('ruleName')">Rule <span class="sort-arrow">↕</span></th>
      <th onclick="sortRules('direction')">Dir <span class="sort-arrow">↕</span></th>
      <th onclick="sortRules('priority')">Pri <span class="sort-arrow">↕</span></th>
      <th onclick="sortRules('access')">Access <span class="sort-arrow">↕</span></th>
      <th>Protocol</th><th>Source</th><th>Dest Port</th><th>Risk</th>
    </tr></thead>
    <tbody id="rulesTableBody"></tbody>
  </table>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:12px">
    <span id="rulesPageInfo" style="font-size:12px;color:var(--muted)"></span>
    <div class="pagination" id="rulesPagination"></div>
  </div>
</section>

<!-- RISK ANALYSIS -->
<section id="page-risk" class="page">
  <div class="page-header">
    <div><div class="page-title">Risk Analysis</div><div class="page-subtitle">Allow + Inbound + Any-source rules, worst first</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('risk')">⬇ Export Flagged CSV</button></div>
  </div>
  <div id="riskEmpty" style="display:none" class="panel">✅ No Allow+Inbound+Any-source rules found in this dataset.</div>
  <table id="riskTable">
    <thead><tr><th>Severity</th><th>NSG</th><th>Rule</th><th>Priority</th><th>Source</th><th>Dest Port</th><th>Reason</th></tr></thead>
    <tbody id="riskTableBody"></tbody>
  </table>
</section>

<!-- RULE CONFLICTS -->
<section id="page-conflicts" class="page">
  <div class="page-header">
    <div><div class="page-title">Rule Conflicts</div><div class="page-subtitle">Shadowed rules (overridden by an earlier-priority rule) and exact duplicates, within the same NSG + direction</div></div>
  </div>

  <div class="panel" style="margin-bottom:16px">
    <div class="section-title">🕶️ Shadowed Rules <span style="font-size:11px;color:var(--muted);font-weight:400">— a later rule that an earlier, overlapping rule already decided</span></div>
    <div id="shadowEmpty" style="display:none;color:var(--muted);font-size:12.5px">✅ No shadowed rules detected — every rule can actually be reached.</div>
    <table id="shadowTable" style="display:none">
      <thead><tr><th>Type</th><th>NSG</th><th>Direction</th><th>Shadowed Rule (pri)</th><th>Overridden By (pri)</th><th>Explanation</th></tr></thead>
      <tbody id="shadowTableBody"></tbody>
    </table>
  </div>

  <div class="panel">
    <div class="section-title">📑 Duplicate Rules <span style="font-size:11px;color:var(--muted);font-weight:400">— identical protocol / source / port / access defined twice</span></div>
    <div id="dupEmpty" style="display:none;color:var(--muted);font-size:12.5px">✅ No exact duplicate rules detected.</div>
    <table id="dupTable" style="display:none">
      <thead><tr><th>NSG</th><th>Direction</th><th>Rule A (pri)</th><th>Rule B (pri)</th><th>Protocol</th><th>Source</th><th>Dest Port</th></tr></thead>
      <tbody id="dupTableBody"></tbody>
    </table>
  </div>
</section>

<!-- SUMMARY / PRINT -->
<section id="page-summary" class="page">
  <div class="page-header">
    <div><div class="page-title">Executive Summary</div><div class="page-subtitle">One-page printable snapshot of the current scope</div></div>
    <div class="btn-group"><button class="btn" onclick="printSummary()">🖨 Print / Save as PDF</button></div>
  </div>
  <div class="summary-sheet" id="summarySheet"></div>
</section>

</main>

<div class="overlay" id="overlay" onclick="closeDetail()"></div>
<div id="detailPanel">
  <div class="detail-topbar"><strong>NSG Detail</strong><button class="detail-close" onclick="closeDetail()">✕</button></div>
  <div id="detailContent"></div>
</div>

<div class="toast" id="toast"></div>

<script>
// ── Embedded CSV (from PowerShell) ──
const EMBEDDED_CSV_TEXT = __CSV_JSON__;
const SOURCE_LABEL = "__SOURCELABEL__";

// Column map — update here if Get-AzureNSGInventory.ps1's schema changes.
const COLMAP = {
  sub:'SubscriptionName', rg:'ResourceGroup', nsg:'NSGName', nsgId:'NSGResourceId',
  loc:'NSGLocation', tags:'NSGTags', subnets:'AssociatedSubnets', nics:'AssociatedNICs',
  subnetCount:'TotalSubnetAssociations', nicCount:'TotalNICAssociations',
  ruleName:'RuleName', direction:'RuleDirection', priority:'RulePriority', access:'RuleAccess',
  protocol:'RuleProtocol', srcPrefix:'SourceAddressPrefix', srcAll:'SourceAddressAll',
  dstPortRange:'DestinationPortRange', dstPortAll:'DestinationPortAll', desc:'RuleDescription'
};
const SENSITIVE_PORTS = ['22','3389','1433','3306','5432','445','6379','27017','21','23','5900'];
const ANY_SOURCE_VALUES = ['*','any','internet','0.0.0.0/0'];

// ── Minimal RFC4180-ish CSV parser (handles quoted fields, embedded commas/quotes/newlines) ──
function parseCSV(text){
  const rows=[]; let row=[]; let field=''; let inQuotes=false;
  for(let i=0;i<text.length;i++){
    const c=text[i];
    if(inQuotes){
      if(c==='"'){
        if(text[i+1]==='"'){ field+='"'; i++; } else { inQuotes=false; }
      } else { field+=c; }
    } else {
      if(c==='"'){ inQuotes=true; }
      else if(c===','){ row.push(field); field=''; }
      else if(c==='\r'){ /* skip */ }
      else if(c==='\n'){ row.push(field); rows.push(row); row=[]; field=''; }
      else { field+=c; }
    }
  }
  if(field.length || row.length){ row.push(field); rows.push(row); }
  if(!rows.length) return [];
  const header=rows[0];
  return rows.slice(1).filter(r=>r.length===header.length && r.some(v=>v!=='')).map(r=>{
    const o={}; header.forEach((h,i)=>o[h]=r[i]); return o;
  });
}

function isAnySource(row){
  const v=(row[COLMAP.srcPrefix]||'').trim().toLowerCase();
  return row[COLMAP.srcAll]==='true' || ANY_SOURCE_VALUES.includes(v);
}
function classifyRisk(row){
  const dir=(row[COLMAP.direction]||'');
  const acc=(row[COLMAP.access]||'');
  if(dir!=='Inbound' || acc!=='Allow' || !isAnySource(row)) return {flagged:false, severity:'None', reason:''};
  const port=(row[COLMAP.dstPortRange]||'').trim();
  if(port==='*' || row[COLMAP.dstPortAll]==='true'){
    return {flagged:true, severity:'Critical', reason:'Any source \u2192 all destination ports open'};
  }
  if(SENSITIVE_PORTS.includes(port)){
    return {flagged:true, severity:'High', reason:'Any source \u2192 sensitive port '+port};
  }
  return {flagged:true, severity:'Medium', reason:'Any source \u2192 port '+(port||'(range)')};
}

let RAW_ROWS=[], ROWS=[], NSGS=[], filteredRules=[], sortState={col:'priority',dir:'asc'}, rulesPage=1, rulesPageSize=25;
let CONFLICTS={shadows:[],duplicates:[]};

function loadData(csvText, label){
  RAW_ROWS = parseCSV(csvText).map(r=>{
    const risk = classifyRisk(r);
    return Object.assign({}, r, {_risk:risk});
  });
  document.getElementById('sourceLabel').textContent = label;
  populateScopeFilters();
  applyScope();
  showToast('Loaded '+RAW_ROWS.length+' rule rows from '+label);
}

function populateScopeFilters(){
  const subSel=document.getElementById('scopeSub');
  const subs=Array.from(new Set(RAW_ROWS.map(r=>r[COLMAP.sub]))).sort();
  subSel.innerHTML='<option value="">All Subscriptions</option>'+subs.map(s=>`<option value="${escH(s)}">${escH(s)}</option>`).join('');
  populateRGOptions();
}
function populateRGOptions(){
  const subVal=document.getElementById('scopeSub').value;
  const rgSel=document.getElementById('scopeRG');
  const pool = subVal ? RAW_ROWS.filter(r=>r[COLMAP.sub]===subVal) : RAW_ROWS;
  const rgs=Array.from(new Set(pool.map(r=>r[COLMAP.rg]))).sort();
  rgSel.innerHTML='<option value="">All Resource Groups</option>'+rgs.map(g=>`<option value="${escH(g)}">${escH(g)}</option>`).join('');
}
function onScopeSubChange(){
  populateRGOptions();
  applyScope();
}
function applyScope(){
  const subVal=document.getElementById('scopeSub').value;
  const rgVal=document.getElementById('scopeRG').value;
  ROWS = RAW_ROWS.filter(r=> (!subVal || r[COLMAP.sub]===subVal) && (!rgVal || r[COLMAP.rg]===rgVal));
  rebuildNSGSFromRows();
  const note=document.getElementById('scopeActiveNote');
  if(subVal || rgVal){
    note.style.display='block';
    note.textContent='Scoped: '+(subVal||'All subs')+(rgVal?' / '+rgVal:'');
  } else {
    note.style.display='none';
  }
  renderAll();
}
function rebuildNSGSFromRows(){
  const nsgMap=new Map();
  ROWS.forEach(r=>{
    const id=r[COLMAP.nsgId]||r[COLMAP.nsg];
    if(!nsgMap.has(id)){
      nsgMap.set(id,{
        id, name:r[COLMAP.nsg], sub:r[COLMAP.sub], rg:r[COLMAP.rg], loc:r[COLMAP.loc],
        tags:r[COLMAP.tags], subnets:r[COLMAP.subnets], nics:r[COLMAP.nics],
        subnetCount:parseInt(r[COLMAP.subnetCount]||'0',10), nicCount:parseInt(r[COLMAP.nicCount]||'0',10),
        rules:[]
      });
    }
    nsgMap.get(id).rules.push(r);
  });
  NSGS = Array.from(nsgMap.values());
}

function renderAll(){
  renderOverview();
  renderExplorer();
  filterRules();
  renderRisk();
  CONFLICTS = computeConflicts(ROWS);
  renderConflicts();
  renderSummary();
  document.getElementById('navNsgCount').textContent=NSGS.length;
  document.getElementById('navRuleCount').textContent=ROWS.length;
  document.getElementById('navRiskCount').textContent=ROWS.filter(r=>r._risk.flagged).length;
  document.getElementById('navConflictCount').textContent=CONFLICTS.shadows.length+CONFLICTS.duplicates.length;
}

// ── Overview ──
function renderOverview(){
  const subs=new Set(ROWS.map(r=>r[COLMAP.sub]));
  const rgs=new Set(ROWS.map(r=>r[COLMAP.rg]));
  const flagged=ROWS.filter(r=>r._risk.flagged);
  const orphans=NSGS.filter(n=>n.subnetCount===0 && n.nicCount===0);
  const crit=flagged.filter(r=>r._risk.severity==='Critical').length;
  const high=flagged.filter(r=>r._risk.severity==='High').length;
  const med=flagged.filter(r=>r._risk.severity==='Medium').length;

  document.getElementById('statNsgs').textContent=NSGS.length;
  document.getElementById('statRules').textContent=ROWS.length;
  document.getElementById('statSubs').textContent=subs.size;
  document.getElementById('statRGs').textContent=rgs.size;
  document.getElementById('statFlagged').textContent=flagged.length;
  document.getElementById('statOrphan').textContent=orphans.length;

  const penalty = Math.min(100, crit*12 + high*6 + med*2);
  const score = Math.max(0, 100-penalty);
  const col = score>=80?'var(--green)':score>=50?'var(--amber)':'var(--red)';
  document.getElementById('riskNum').textContent=score;
  document.getElementById('riskNum').style.color=col;
  const circumference=188.5;
  document.getElementById('riskArc').setAttribute('stroke',col);
  document.getElementById('riskArc').style.strokeDashoffset=circumference-(circumference*score/100);
  const maxSev=Math.max(crit,high,med,1);
  document.getElementById('hCrit').style.width=(crit/maxSev*100)+'%'; document.getElementById('hCritN').textContent=crit;
  document.getElementById('hHigh').style.width=(high/maxSev*100)+'%'; document.getElementById('hHighN').textContent=high;
  document.getElementById('hMed').style.width=(med/maxSev*100)+'%'; document.getElementById('hMedN').textContent=med;

  const protoCounts={};
  ROWS.forEach(r=>{const p=r[COLMAP.protocol]||'*';protoCounts[p]=(protoCounts[p]||0)+1;});
  const protoEntries=Object.entries(protoCounts).sort((a,b)=>b[1]-a[1]);
  const protoMax=protoEntries.length?protoEntries[0][1]:1;
  const palette=['#388bfd','#39c5cf','#a371f7','#3fb950','#d29922','#f85149'];
  document.getElementById('protoBars').innerHTML=protoEntries.map(([p,c],i)=>`
    <div class="bar-row"><span class="bar-label">${escH(p)}</span>
    <div class="bar-track"><div class="bar-fill" style="width:${Math.round(c/protoMax*100)}%;background:${palette[i%palette.length]}"></div></div>
    <span class="bar-count">${c}</span></div>`).join('');

  const dirAccess={};
  ROWS.forEach(r=>{const k=r[COLMAP.direction]+' / '+r[COLMAP.access]; dirAccess[k]=(dirAccess[k]||0)+1;});
  document.getElementById('dirLegend').innerHTML=Object.entries(dirAccess).sort((a,b)=>b[1]-a[1]).map(([k,c],i)=>`
    <div class="legend-item"><span class="legend-dot" style="background:${palette[i%palette.length]}"></span>${escH(k)}<span style="margin-left:auto;color:var(--muted);font-family:var(--mono);font-size:11px">${c}</span></div>`).join('');

  const sevRank={Critical:3,High:2,Medium:1};
  const top=flagged.slice().sort((a,b)=>sevRank[b._risk.severity]-sevRank[a._risk.severity]).slice(0,10);
  document.getElementById('topRisky').innerHTML = top.length ? top.map((r,i)=>`
    <div class="top-list-row" onclick="openNsgDetail('${escJ(r[COLMAP.nsgId]||r[COLMAP.nsg])}')">
      <span class="tl-rank">${i+1}</span>
      <span class="tl-name" title="${escH(r[COLMAP.nsg])} / ${escH(r[COLMAP.ruleName])}">${escH(r[COLMAP.nsg])} — ${escH(r[COLMAP.ruleName])}</span>
      <span class="sev-badge sev-${r._risk.severity}">${r._risk.severity}</span>
      <span class="tl-val">port ${escH(r[COLMAP.dstPortRange]||'*')}</span>
    </div>`).join('') : '<p style="color:var(--muted);font-size:12.5px">No flagged rules — nothing to show 🎉</p>';
}

// ── NSG Explorer ──
function renderExplorer(){
  const q=(document.getElementById('explorerSearch').value||'').toLowerCase();
  const sortMode=document.getElementById('explorerSort').value;
  let list=NSGS.filter(n=>!q || [n.name,n.rg,n.sub,n.loc].join(' ').toLowerCase().includes(q));
  list.forEach(n=>{ n._flaggedCount = n.rules.filter(r=>r._risk.flagged).length; });
  if(sortMode==='risk-desc') list.sort((a,b)=>b._flaggedCount-a._flaggedCount);
  else if(sortMode==='rules-desc') list.sort((a,b)=>b.rules.length-a.rules.length);
  else list.sort((a,b)=>a.name.localeCompare(b.name));
  document.getElementById('explorerCount').textContent=list.length+' NSG'+(list.length!==1?'s':'');
  document.getElementById('nsgGrid').innerHTML=list.map(n=>{
    const orphan = n.subnetCount===0 && n.nicCount===0;
    return `<div class="nsg-card" onclick="openNsgDetail('${escJ(n.id)}')">
      <div class="nsg-card-head"><div class="nsg-card-name" title="${escH(n.name)}">${escH(n.name)}</div>${n._flaggedCount?`<span class="sev-badge sev-High">${n._flaggedCount} flagged</span>`:''}</div>
      <div class="nsg-card-sub">${escH(n.sub)} / ${escH(n.rg)} / ${escH(n.loc)}</div>
      <div class="nsg-card-meta">
        <span class="meta-chip">📋 ${n.rules.length} rules</span>
        <span class="meta-chip">🔗 ${n.subnetCount} subnets</span>
        <span class="meta-chip">🖧 ${n.nicCount} NICs</span>
      </div>
      <div class="nsg-card-foot">
        ${orphan?'<span class="orphan-flag">⚠ Orphaned (no associations)</span>':'<span style="color:var(--muted);font-size:11px">Associated</span>'}
        <span style="color:var(--accent);font-size:11.5px">View →</span>
      </div>
    </div>`;
  }).join('');
}

function openNsgDetail(id){
  const n = NSGS.find(x=>x.id===id) || NSGS.find(x=>x.name===id);
  if(!n) return;
  const rulesHtml = n.rules.slice().sort((a,b)=>parseInt(a[COLMAP.priority])-parseInt(b[COLMAP.priority])).map(r=>{
    const acc=r[COLMAP.access]==='Allow'?'chip-allow':'chip-deny';
    const dir=r[COLMAP.direction]==='Inbound'?'chip-in':'chip-out';
    return `<div class="mini-rule">
      <div class="mini-rule-head"><span>${escH(r[COLMAP.ruleName])}</span>${r._risk.flagged?`<span class="sev-badge sev-${r._risk.severity}">${r._risk.severity}</span>`:''}</div>
      <span class="chip ${dir}">${escH(r[COLMAP.direction])}</span> <span class="chip ${acc}">${escH(r[COLMAP.access])}</span>
      <span class="mono" style="margin-left:6px">pri ${escH(r[COLMAP.priority])} · ${escH(r[COLMAP.protocol])} · src ${escH(r[COLMAP.srcPrefix]||'-')} · dport ${escH(r[COLMAP.dstPortRange]||'-')}</span>
      ${r[COLMAP.desc]?`<div style="color:var(--muted);margin-top:4px">${escH(r[COLMAP.desc])}</div>`:''}
    </div>`;
  }).join('');
  document.getElementById('detailContent').innerHTML=`
    <div class="detail-name">${escH(n.name)}</div>
    <div class="detail-path">${escH(n.id)}</div>
    <div class="detail-meta-row">
      <span class="detail-chip">🏢 ${escH(n.sub)}</span>
      <span class="detail-chip">📁 ${escH(n.rg)}</span>
      <span class="detail-chip">📍 ${escH(n.loc)}</span>
      <span class="detail-chip">🔗 ${n.subnetCount} subnets</span>
      <span class="detail-chip">🖧 ${n.nicCount} NICs</span>
    </div>
    <div class="detail-section"><div class="detail-section-title">Rules (${n.rules.length})</div>${rulesHtml}</div>`;
  document.getElementById('detailPanel').classList.add('open');
  document.getElementById('overlay').classList.add('open');
}
function closeDetail(){document.getElementById('detailPanel').classList.remove('open');document.getElementById('overlay').classList.remove('open');}

// ── Rules table ──
function filterRules(){
  const q=(document.getElementById('rulesSearch').value||'').toLowerCase();
  const dir=document.getElementById('dirFilter').value;
  const acc=document.getElementById('accessFilter').value;
  const riskOnly=document.getElementById('riskFilter').value==='flagged';
  filteredRules = ROWS.filter(r=>{
    if(dir && r[COLMAP.direction]!==dir) return false;
    if(acc && r[COLMAP.access]!==acc) return false;
    if(riskOnly && !r._risk.flagged) return false;
    if(q){
      const hay=[r[COLMAP.nsg],r[COLMAP.ruleName],r[COLMAP.srcPrefix],r[COLMAP.dstPortRange],r[COLMAP.protocol]].join(' ').toLowerCase();
      if(!hay.includes(q)) return false;
    }
    return true;
  });
  rulesPage=1;
  sortRules(sortState.col, true);
}
function sortRules(col, keepDir){
  if(!keepDir){ sortState.dir = (sortState.col===col && sortState.dir==='asc') ? 'desc':'asc'; sortState.col=col; }
  const key = {nsgName:COLMAP.nsg, ruleName:COLMAP.ruleName, direction:COLMAP.direction, priority:COLMAP.priority, access:COLMAP.access}[sortState.col] || COLMAP.priority;
  filteredRules.sort((a,b)=>{
    let av=a[key], bv=b[key];
    if(sortState.col==='priority'){ av=parseInt(av||0); bv=parseInt(bv||0); }
    else { av=(av||'').toLowerCase(); bv=(bv||'').toLowerCase(); }
    if(av<bv) return sortState.dir==='asc'?-1:1;
    if(av>bv) return sortState.dir==='asc'?1:-1;
    return 0;
  });
  renderRulesTable();
}
function renderRulesTable(){
  const total=filteredRules.length;
  const pages=Math.max(1,Math.ceil(total/rulesPageSize));
  if(rulesPage>pages) rulesPage=pages;
  const start=(rulesPage-1)*rulesPageSize;
  const pageRows=filteredRules.slice(start,start+rulesPageSize);
  document.getElementById('rulesResultCount').textContent=total+' rule'+(total!==1?'s':'');
  document.getElementById('rulesTableBody').innerHTML=pageRows.map(r=>{
    const acc=r[COLMAP.access]==='Allow'?'chip-allow':'chip-deny';
    const dir=r[COLMAP.direction]==='Inbound'?'chip-in':'chip-out';
    return `<tr>
      <td>${escH(r[COLMAP.nsg])}</td>
      <td>${escH(r[COLMAP.ruleName])}</td>
      <td><span class="chip ${dir}">${escH(r[COLMAP.direction])}</span></td>
      <td class="mono">${escH(r[COLMAP.priority])}</td>
      <td><span class="chip ${acc}">${escH(r[COLMAP.access])}</span></td>
      <td class="mono">${escH(r[COLMAP.protocol])}</td>
      <td class="mono">${escH(r[COLMAP.srcPrefix]||'-')}</td>
      <td class="mono">${escH(r[COLMAP.dstPortRange]||'-')}</td>
      <td>${r._risk.flagged?`<span class="sev-badge sev-${r._risk.severity}">${r._risk.severity}</span>`:'<span style="color:var(--muted);font-size:11px">—</span>'}</td>
    </tr>`;
  }).join('');
  document.getElementById('rulesPageInfo').textContent=`Showing ${total?start+1:0}–${Math.min(start+rulesPageSize,total)} of ${total}`;
  const pag=document.getElementById('rulesPagination');
  let btns=`<button ${rulesPage<=1?'disabled':''} onclick="rulesPage--;renderRulesTable()">‹</button>`;
  const span=2;
  for(let p=1;p<=pages;p++){
    if(p===1||p===pages||Math.abs(p-rulesPage)<=span){
      btns+=`<button class="${p===rulesPage?'active':''}" onclick="rulesPage=${p};renderRulesTable()">${p}</button>`;
    } else if(Math.abs(p-rulesPage)===span+1){ btns+=`<span style="color:var(--muted);padding:0 4px">…</span>`; }
  }
  btns+=`<button ${rulesPage>=pages?'disabled':''} onclick="rulesPage++;renderRulesTable()">›</button>`;
  pag.innerHTML=btns;
}

// ── Risk Analysis tab ──
function renderRisk(){
  const sevRank={Critical:3,High:2,Medium:1};
  const flagged = ROWS.filter(r=>r._risk.flagged).sort((a,b)=>sevRank[b._risk.severity]-sevRank[a._risk.severity] || (parseInt(a[COLMAP.priority])-parseInt(b[COLMAP.priority])));
  document.getElementById('riskEmpty').style.display = flagged.length? 'none':'block';
  document.getElementById('riskTable').style.display = flagged.length? 'table':'none';
  document.getElementById('riskTableBody').innerHTML = flagged.map(r=>`
    <tr>
      <td><span class="sev-badge sev-${r._risk.severity}">${r._risk.severity}</span></td>
      <td>${escH(r[COLMAP.nsg])}</td>
      <td>${escH(r[COLMAP.ruleName])}</td>
      <td class="mono">${escH(r[COLMAP.priority])}</td>
      <td class="mono">${escH(r[COLMAP.srcPrefix]||'*')}</td>
      <td class="mono">${escH(r[COLMAP.dstPortRange]||'*')}</td>
      <td style="color:var(--muted)">${escH(r._risk.reason)}</td>
    </tr>`).join('');
}

// ── Rule Conflicts tab ──
// normVal/fieldCovers/rulesOverlapCovers/isExactDuplicate are pure helpers with
// no DOM/state side effects, so they are safe to unit-test in isolation.
function normVal(v){ return (v===undefined||v===null) ? '' : String(v).trim().toLowerCase(); }

// True when "earlierVal" (a rule evaluated first) already covers "laterVal":
// either field is wildcard/blank counts as "matches anything".
function fieldCovers(earlierVal, laterVal){
  const e=normVal(earlierVal), l=normVal(laterVal);
  if(e===''||e==='*') return true;
  if(l===''||l==='*') return false;
  return e===l;
}

// A rule is shadowed when an earlier-priority rule in the same NSG+direction
// already matches every packet it would match (protocol/source/port each
// equal-or-wildcarded by the earlier rule). Access is intentionally not
// compared: Azure NSGs stop at the first matching rule regardless of whether
// that rule Allows or Denies, so either access value hides the later rule.
function rulesOverlapCovers(earlier, later){
  return fieldCovers(earlier[COLMAP.protocol], later[COLMAP.protocol])
      && fieldCovers(earlier[COLMAP.srcPrefix], later[COLMAP.srcPrefix])
      && fieldCovers(earlier[COLMAP.dstPortRange], later[COLMAP.dstPortRange]);
}

function isExactDuplicate(a,b){
  return normVal(a[COLMAP.protocol])===normVal(b[COLMAP.protocol])
      && normVal(a[COLMAP.srcPrefix])===normVal(b[COLMAP.srcPrefix])
      && normVal(a[COLMAP.dstPortRange])===normVal(b[COLMAP.dstPortRange])
      && normVal(a[COLMAP.access])===normVal(b[COLMAP.access]);
}

function computeConflicts(rows){
  const shadows=[], duplicates=[];
  const groups=new Map();
  rows.forEach(r=>{
    const key=(r[COLMAP.nsgId]||r[COLMAP.nsg])+'|'+r[COLMAP.direction];
    if(!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  });
  groups.forEach(list=>{
    // Ascending priority = Azure NSG evaluation order (lowest number first).
    const sorted=list.slice().sort((a,b)=>parseInt(a[COLMAP.priority]||0)-parseInt(b[COLMAP.priority]||0));
    for(let i=0;i<sorted.length;i++){
      const later=sorted[i];
      for(let j=0;j<i;j++){
        const earlier=sorted[j];
        if(rulesOverlapCovers(earlier, later)){
          shadows.push({
            nsg:later[COLMAP.nsg], direction:later[COLMAP.direction],
            shadowedName:later[COLMAP.ruleName], shadowedPri:later[COLMAP.priority],
            byName:earlier[COLMAP.ruleName], byPri:earlier[COLMAP.priority],
            explanation:`Rule '${later[COLMAP.ruleName]}' (pri ${later[COLMAP.priority]}) can never be reached — rule '${earlier[COLMAP.ruleName]}' (pri ${earlier[COLMAP.priority]}) is evaluated first and already matches every packet it would match.`
          });
          break; // report only the nearest rule that shadows it
        }
      }
    }
    for(let i=0;i<sorted.length;i++){
      for(let j=i+1;j<sorted.length;j++){
        const a=sorted[i], b=sorted[j];
        if(isExactDuplicate(a,b)){
          duplicates.push({
            nsg:a[COLMAP.nsg], direction:a[COLMAP.direction],
            nameA:a[COLMAP.ruleName], priA:a[COLMAP.priority],
            nameB:b[COLMAP.ruleName], priB:b[COLMAP.priority],
            protocol:a[COLMAP.protocol], source:a[COLMAP.srcPrefix]||'*', port:a[COLMAP.dstPortRange]||'*'
          });
        }
      }
    }
  });
  return {shadows, duplicates};
}

function renderConflicts(){
  const shadowTable=document.getElementById('shadowTable');
  const shadowEmpty=document.getElementById('shadowEmpty');
  if(CONFLICTS.shadows.length){
    shadowTable.style.display='table'; shadowEmpty.style.display='none';
    document.getElementById('shadowTableBody').innerHTML = CONFLICTS.shadows.map(s=>`
      <tr>
        <td><span class="sev-badge sev-Blocked">Shadowed</span></td>
        <td>${escH(s.nsg)}</td>
        <td><span class="chip ${s.direction==='Inbound'?'chip-in':'chip-out'}">${escH(s.direction)}</span></td>
        <td class="mono">${escH(s.shadowedName)} (${escH(s.shadowedPri)})</td>
        <td class="mono">${escH(s.byName)} (${escH(s.byPri)})</td>
        <td style="color:var(--muted)">${escH(s.explanation)}</td>
      </tr>`).join('');
  } else {
    shadowTable.style.display='none'; shadowEmpty.style.display='block';
  }

  const dupTable=document.getElementById('dupTable');
  const dupEmpty=document.getElementById('dupEmpty');
  if(CONFLICTS.duplicates.length){
    dupTable.style.display='table'; dupEmpty.style.display='none';
    document.getElementById('dupTableBody').innerHTML = CONFLICTS.duplicates.map(d=>`
      <tr>
        <td>${escH(d.nsg)}</td>
        <td><span class="chip ${d.direction==='Inbound'?'chip-in':'chip-out'}">${escH(d.direction)}</span></td>
        <td class="mono">${escH(d.nameA)} (${escH(d.priA)})</td>
        <td class="mono">${escH(d.nameB)} (${escH(d.priB)})</td>
        <td class="mono">${escH(d.protocol)}</td>
        <td class="mono">${escH(d.source)}</td>
        <td class="mono">${escH(d.port)}</td>
      </tr>`).join('');
  } else {
    dupTable.style.display='none'; dupEmpty.style.display='block';
  }
}

// ── Summary / Print tab ──
function renderSummary(){
  const flagged=ROWS.filter(r=>r._risk.flagged);
  const crit=flagged.filter(r=>r._risk.severity==='Critical').length;
  const high=flagged.filter(r=>r._risk.severity==='High').length;
  const med=flagged.filter(r=>r._risk.severity==='Medium').length;
  const orphans=NSGS.filter(n=>n.subnetCount===0 && n.nicCount===0);
  const subCount=new Set(ROWS.map(r=>r[COLMAP.sub])).size;
  const rgCount=new Set(ROWS.map(r=>r[COLMAP.rg])).size;
  const scopeNote=document.getElementById('scopeActiveNote');
  const scopeText = (scopeNote && scopeNote.style.display!=='none' && scopeNote.textContent) ? scopeNote.textContent : 'All subscriptions / all resource groups';

  const sevRank={Critical:3,High:2,Medium:1};
  const top=flagged.slice().sort((a,b)=>sevRank[b._risk.severity]-sevRank[a._risk.severity]).slice(0,5);
  const topRowsHtml = top.length
    ? top.map(r=>`<div class="sm-row"><span>${escH(r[COLMAP.nsg])} — ${escH(r[COLMAP.ruleName])}</span><span class="sev-badge sev-${r._risk.severity}">${r._risk.severity}</span></div>`).join('')
    : '<div class="sm-row"><span style="color:var(--muted)">No flagged rules in the current scope 🎉</span><span></span></div>';

  document.getElementById('summarySheet').innerHTML = `
    <h2>Azure NSG Inventory — Executive Summary</h2>
    <div class="sm-sub">Source: ${escH(SOURCE_LABEL)} &nbsp;·&nbsp; Scope: ${escH(scopeText)}</div>
    <div class="sm-grid">
      <div class="sm-cell"><div class="sm-val">${NSGS.length}</div><div class="sm-lbl">NSGs</div></div>
      <div class="sm-cell"><div class="sm-val">${ROWS.length}</div><div class="sm-lbl">Rules</div></div>
      <div class="sm-cell"><div class="sm-val">${subCount}</div><div class="sm-lbl">Subscriptions</div></div>
      <div class="sm-cell"><div class="sm-val">${rgCount}</div><div class="sm-lbl">Resource Groups</div></div>
    </div>
    <div class="sm-section">
      <h4>Exposure Breakdown</h4>
      <div class="sm-row"><span>🔴 Critical (Allow+Inbound+Any, all ports)</span><span>${crit}</span></div>
      <div class="sm-row"><span>🟠 High (Allow+Inbound+Any, sensitive port)</span><span>${high}</span></div>
      <div class="sm-row"><span>🔵 Medium (Allow+Inbound+Any, other port)</span><span>${med}</span></div>
      <div class="sm-row"><span>Orphaned NSGs (no subnet/NIC association)</span><span>${orphans.length}</span></div>
    </div>
    <div class="sm-section">
      <h4>Rule Conflicts</h4>
      <div class="sm-row"><span>Shadowed (unreachable) rules</span><span>${CONFLICTS.shadows.length}</span></div>
      <div class="sm-row"><span>Exact duplicate rules</span><span>${CONFLICTS.duplicates.length}</span></div>
    </div>
    <div class="sm-section">
      <h4>Top Flagged Rules</h4>
      ${topRowsHtml}
    </div>
    <div class="sm-note">Risk and conflict findings are review candidates surfaced from the CSV alone — they do not account for route tables, Azure Firewall, or third-party NVAs, and are not a confirmed vulnerability or compliance verdict. Generated __GENERATEDAT__.</div>`;
}

function printSummary(){
  goToPage('summary');
  window.print();
}

// ── Nav / theme / toast ──
function goToPage(name){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  document.querySelector(`.nav-btn[data-page="${name}"]`).classList.add('active');
}
function toggleTheme(){
  document.body.classList.toggle('light-theme');
  const light=document.body.classList.contains('light-theme');
  document.getElementById('themeLabel').textContent = light?'Light theme':'Dark theme';
}
function showToast(msg){
  const t=document.getElementById('toast'); t.textContent=msg; t.classList.add('show');
  clearTimeout(window._toastTimer); window._toastTimer=setTimeout(()=>t.classList.remove('show'),2600);
}

// ── Upload / drag-drop (reuses parseCSV / loadData — same path as embedded data) ──
function handleFileInput(e){
  const f=e.target.files && e.target.files[0];
  if(!f) return;
  readFileAndLoad(f);
}
function readFileAndLoad(f){
  const reader=new FileReader();
  reader.onload=ev=>loadData(ev.target.result, f.name);
  reader.onerror=()=>showToast('⚠ Could not read file');
  reader.readAsText(f);
}
document.addEventListener('dragover', e=>{ e.preventDefault(); });
document.addEventListener('drop', e=>{
  e.preventDefault();
  const f=e.dataTransfer.files && e.dataTransfer.files[0];
  if(f && f.name.toLowerCase().endsWith('.csv')) readFileAndLoad(f);
  else if(f) showToast('⚠ Please drop a .csv file');
});

// ── Exports ──
function toCSVRows(rows){
  const cols=[COLMAP.sub,COLMAP.rg,COLMAP.nsg,COLMAP.direction,COLMAP.priority,COLMAP.access,COLMAP.protocol,COLMAP.srcPrefix,COLMAP.dstPortRange,COLMAP.ruleName,COLMAP.desc];
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const header=cols.join(',');
  const body=rows.map(r=>cols.map(c=>esc(r[c])).join(',')).join('\r\n');
  return header+'\r\n'+body;
}
function exportCSV(which){
  let data, name;
  if(which==='risk'){ data=ROWS.filter(r=>r._risk.flagged); name='NSG_FlaggedRules.csv'; }
  else if(which==='filtered'){ data=filteredRules; name='NSG_FilteredRules.csv'; }
  else { data=ROWS; name='NSG_AllRules.csv'; }
  dlFile(toCSVRows(data), name, 'text/csv');
  showToast('Exported '+data.length+' rows');
}
function dlFile(content,name,type){const b=new Blob([content],{type});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=name;a.click();URL.revokeObjectURL(u);}

// ── Utils ──
function escH(s){return String(s===undefined||s===null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){ closeDetail(); return; }
  if(e.key==='/' && document.activeElement.tagName!=='INPUT' && document.activeElement.tagName!=='SELECT'){
    e.preventDefault();
    const inp=document.querySelector('.page.active input[type=text]');
    if(inp) inp.focus();
  }
});

// ── Boot ──
loadData(EMBEDDED_CSV_TEXT, SOURCE_LABEL);
</script>
</body>
</html>
'@

  $html = $html `
    -replace '__CSV_JSON__', $csvJsonLiteral `
    -replace '__SOURCELABEL__', $sourceLabel `
    -replace '__GENERATEDAT__', $generatedAt

  #endregion

  #region ── Output ─────────────────────────────────────────────────────────────

  try {
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force -ErrorAction Stop
  }
  catch {
    Write-Error "Failed to write dashboard to '$OutputPath': $($_.Exception.Message)"
    return
  }

  $flaggedPreview = ($parsedRows | Where-Object {
      $_.RuleDirection -eq 'Inbound' -and $_.RuleAccess -eq 'Allow' -and
      ($_.SourceAddressPrefix -in @('*', 'Internet', '0.0.0.0/0') -or $_.SourceAddressAll -eq 'true')
    }).Count

  Write-Host ""
  Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
  Write-Host "║   ✅  Azure NSG Dashboard v2.1 — generated!          ║" -ForegroundColor Cyan
  Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "  📋  Rule rows          : $rowCount"          -ForegroundColor White
  Write-Host "  🚨  Flagged (Allow/In/Any) : $flaggedPreview" -ForegroundColor $(if ($flaggedPreview -gt 0) { 'Yellow' } else { 'Green' })
  Write-Host "  📁  Output file         : $OutputPath"        -ForegroundColor White
  Write-Host ""

  if ($OpenBrowser) {
    Write-Host "  🌐  Opening in browser…" -ForegroundColor Green
    Start-Process $OutputPath
  }

  #endregion

}
