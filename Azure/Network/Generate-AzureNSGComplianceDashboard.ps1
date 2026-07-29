<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 29 July 2026
Modified-On  : 29 July 2026

.SYNOPSIS
  Builds a self-contained HTML dashboard from the Findings + Summary CSVs
  produced by Test-AzureNSGCompliance.ps1, with a scored NSG explorer,
  a searchable findings table, a dedicated Critical/High view, a
  conflicts/duplicates view, and a printable executive summary.

.DESCRIPTION
  Generate-AzureNSGComplianceDashboard reads the two CSV reports emitted by
  Test-AzureNSGCompliance.ps1 - the detailed findings CSV
  ("<Prefix>_Findings_<timestamp>.csv") and the per-NSG summary CSV
  ("<Prefix>_Summary_<timestamp>.csv") - and embeds their raw text into a
  static HTML file. The dashboard renders entirely client-side via the same
  embedded-CSV-parser approach used by Generate-AzureNSGDashboard.ps1, so it
  has no server/API dependency and also supports dropping a fresher pair of
  CSVs onto the page later.

  This function only visualizes findings that Test-AzureNSGCompliance.ps1
  already computed - it does not re-run, re-score, or re-validate any check.
  All of that script's Known Limitations (exact-match/wildcard scope
  comparisons, name-based VNet flow log correlation, general compliance
  reference text, etc.) apply equally here.

  Dashboard tabs:
      - Overview       - stat cards, average compliance score ring,
                          findings-by-category bars, severity legend,
                          worst-scoring NSGs
      - NSG Explorer   - card per NSG (from the Summary CSV) with its
                          compliance score and severity badge counts;
                          click for the full finding list for that NSG
      - Findings Table - search/filter/sort every finding, CSV export
      - Critical & High- only Critical/High severity findings, worst first
      - Conflicts       - Priority Conflict and Duplicate Rule findings,
                          split into two tables
      - Summary        - one-page printable executive summary of the
                          current scope

  A Subscription / Resource Group scope filter (sidebar) applies across all
  tabs, mirroring the pattern used in Generate-AzureNSGDashboard.ps1.

.PARAMETER FindingsCsvPath
  Path to the detailed findings CSV produced by Test-AzureNSGCompliance.ps1
  (the "<Prefix>_Findings_<timestamp>.csv" file).

.PARAMETER SummaryCsvPath
  Optional. Path to the per-NSG summary CSV produced by the same run of
  Test-AzureNSGCompliance.ps1 (the "<Prefix>_Summary_<timestamp>.csv" file).
  If omitted, this function attempts to auto-derive it by replacing
  "_Findings_" with "_Summary_" in -FindingsCsvPath. If no summary can be
  found, the dashboard still renders, but NSG compliance scores and any
  fully-clean NSG (zero findings) will not be visible - only NSGs that
  appear in the findings CSV can be shown. A warning is written in that case.

.PARAMETER OutputPath
  Where to save the generated HTML dashboard.
  Defaults to "$env:TEMP\AzureNSGComplianceDashboard.html".

.PARAMETER OpenBrowser
  If specified, opens the generated dashboard in the default browser.

.INPUTS
  None. This function does not accept pipeline input.

.OUTPUTS
  None. Writes an HTML file to -OutputPath.

.EXAMPLE
  Generate-AzureNSGComplianceDashboard -FindingsCsvPath "C:\Reports\AzureNSGCompliance_Findings_20260729_154713.csv" -OpenBrowser

  Auto-derives the matching Summary CSV in the same folder and opens the
  dashboard in the default browser.

.EXAMPLE
  Generate-AzureNSGComplianceDashboard `
      -FindingsCsvPath "C:\Reports\AzureNSGCompliance_Findings_20260729_154713.csv" `
      -SummaryCsvPath  "C:\Reports\AzureNSGCompliance_Summary_20260729_154713.csv" `
      -OutputPath "C:\Reports\NSGComplianceDashboard.html"

  Generates the dashboard to a specific output path without opening it.

.EXAMPLE
  # Full Requirement 1 pipeline

  Get-AzureNSGInventory -OutputPath "C:\Reports"
  Test-AzureNSGCompliance -CsvPath "C:\Reports\NSG_Inventory_<timestamp>.csv" -OutputPath "C:\Reports" -IncludeJsonExport
  Generate-AzureNSGComplianceDashboard -FindingsCsvPath "C:\Reports\NSG_Compliance_Findings_<timestamp>.csv" -OpenBrowser

.NOTES
  ─────────────────────────────────────────────────────────────────────────
  Version History:
  ─────────────────────────────────────────────────────────────────────────
  1.0 (29-Jul-2026) - Initial release.

  ─────────────────────────────────────────────────────────────────────────
  Pre-Requisites:
  ─────────────────────────────────────────────────────────────────────────
  1. PowerShell 5.1 or later.
  2. A findings CSV produced by Test-AzureNSGCompliance.ps1 (and, ideally,
      its matching summary CSV from the same run).
  3. No internet connection is required to view the generated dashboard;
      it has no CDN dependencies for data or logic (the Google Fonts stylesheet
      link is decorative only and degrades to a system monospace font offline).

  ─────────────────────────────────────────────────────────────────────────
  Execution Flow:
  ─────────────────────────────────────────────────────────────────────────
  1. Validate -FindingsCsvPath exists, is a .csv file, and contains no
      path-traversal characters. Resolve -SummaryCsvPath (explicit value, or
      auto-derived by name); missing summary is a warning, not a fatal error.
  2. Read both raw CSV texts and JSON-escape them for safe embedding in
      <script>. Detect the "no findings identified" placeholder row that
      Test-AzureNSGCompliance.ps1 emits when a run found zero findings, so
      the dashboard renders a clean-bill-of-health state instead of erroring.
  3. Inject the escaped text and generation metadata into the HTML template.
  4. Write the HTML file to -OutputPath.
  5. Optionally open it in the default browser.

  ─────────────────────────────────────────────────────────────────────────
  Known Limitations:
  ─────────────────────────────────────────────────────────────────────────
  - This dashboard is a pure visualization layer. It inherits every
    accuracy caveat already documented in Test-AzureNSGCompliance.ps1's own
    Known Limitations (exact-match/wildcard scope comparisons - not
    CIDR-aware; name-based VNet Flow Log correlation; general, non-version-
    pinned ComplianceReference text). Nothing here re-checks or re-scores
    those findings.
  - If -SummaryCsvPath cannot be found or fails validation, NSGs with zero
    findings are invisible to this dashboard (they never appear in the
    findings CSV at all), and compliance scores cannot be shown. Always
    keep the Summary CSV alongside the Findings CSV from the same run.
  - Expects the exact column headers emitted by Test-AzureNSGCompliance.ps1;
    if that script's schema changes, update the FINDINGS_COLMAP /
    SUMMARY_COLMAP objects in the embedded JavaScript.

.LINK
  Test-AzureNSGCompliance.ps1 - source script that generates the input CSVs
  https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/Network/Test-AzureNSGCompliance.ps1

.LINK
  Generate-AzureNSGDashboard.ps1 - design template this dashboard reuses
  https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/Network/Generate-AzureNSGDashboard.ps1

.LINK
  https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview

#>


Function Generate-AzureNSGComplianceDashboard
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Path to the Findings CSV produced by Test-AzureNSGCompliance.")]
        [ValidateScript({
            if ($_ -match '\.\.') { throw "FindingsCsvPath must not contain path-traversal characters ('..')." }
            if (-not (Test-Path -Path $_ -PathType Leaf)) { throw "File not found: $_" }
            if ([System.IO.Path]::GetExtension($_) -ne '.csv') { throw "FindingsCsvPath must point to a .csv file." }
            $true
        })]
        [string]$FindingsCsvPath,

        [Parameter(Mandatory = $false, HelpMessage = "Path to the matching Summary CSV. Auto-derived from FindingsCsvPath if omitted.")]
        [ValidateScript({
            if ($_ -match '\.\.') { throw "SummaryCsvPath must not contain path-traversal characters ('..')." }
            if ([System.IO.Path]::GetExtension($_) -ne '.csv') { throw "SummaryCsvPath must point to a .csv file." }
            $true
        })]
        [string]$SummaryCsvPath,

        [Parameter(Mandatory = $false, HelpMessage = "Where to save the generated HTML dashboard.")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ($_ -match '\.\.') { throw "OutputPath must not contain path-traversal characters ('..')." }
            $true
        })]
        [string]$OutputPath = "$env:TEMP\AzureNSGComplianceDashboard.html",

        [switch]$OpenBrowser
    )

    #region ── Resolve Summary Path ──────────────────────────────────────────────
    $summaryAvailable = $false

    if (-not $SummaryCsvPath)
    {
        $candidate = $FindingsCsvPath -replace '_Findings_', '_Summary_'
        if ($candidate -ne $FindingsCsvPath -and (Test-Path -Path $candidate -PathType Leaf))
        {
            $SummaryCsvPath = $candidate
        }
    }
    #endregion

    #region ── Read & Validate Findings CSV ──────────────────────────────────────
    Write-Host ""
    Write-Host "  🔎  Reading NSG compliance findings CSV…" -ForegroundColor Cyan

    $rawFindingsText = ''
    $findingsRowCount = 0
    $findingsIsEmptyPlaceholder = $false
    $findingsSourceLabel = Split-Path -Path $FindingsCsvPath -Leaf

    try
    {
        $rawFindingsText = Get-Content -Path $FindingsCsvPath -Raw -ErrorAction Stop
        $parsedFindings = @(Import-Csv -Path $FindingsCsvPath -ErrorAction Stop)
        $findingsRowCount = $parsedFindings.Count

        if ($findingsRowCount -eq 0)
        {
            throw "CSV parsed successfully but contains 0 data rows."
        }

        $firstRowColumns = ($parsedFindings[0].PSObject.Properties | Select-Object -ExpandProperty Name)

        if ($findingsRowCount -eq 1 -and $firstRowColumns.Count -eq 1 -and $firstRowColumns[0] -eq 'Result')
        {
            # Test-AzureNSGCompliance.ps1 emits a single "Result" column when
            # zero findings were identified. Treat that as a valid, clean state.
            $findingsIsEmptyPlaceholder = $true
            Write-Host "  ✅  Findings CSV indicates zero findings were identified — rendering a clean-bill-of-health dashboard." -ForegroundColor Green
        }
        else
        {
            $requiredFindingColumns = @(
                'SubscriptionName', 'ResourceGroup', 'NSGName', 'NSGResourceId', 'NSGLocation',
                'RuleName', 'RuleDirection', 'RulePriority', 'CheckCategory', 'Severity',
                'Finding', 'Recommendation', 'ComplianceReference', 'RelatedRule'
            )
            $missingFindingColumns = @($requiredFindingColumns | Where-Object { $firstRowColumns -notcontains $_ })
            if ($missingFindingColumns.Count -gt 0)
            {
                throw "CSV is missing expected column(s): $($missingFindingColumns -join ', '). This does not look like Test-AzureNSGCompliance.ps1 Findings output."
            }
        }
    }
    catch
    {
        Write-Error "Failed to read/validate Findings CSV at '$FindingsCsvPath': $($_.Exception.Message)"
        return
    }

    Write-Host "  ✅  Findings CSV validated — $findingsRowCount row(s) found." -ForegroundColor Green
    #endregion

    #region ── Read & Validate Summary CSV (optional) ────────────────────────────
    $rawSummaryText = ''
    $summarySourceLabel = ''
    $summaryRowCount = 0

    if ($SummaryCsvPath -and (Test-Path -Path $SummaryCsvPath -PathType Leaf))
    {
        Write-Host "  🔎  Reading NSG compliance summary CSV…" -ForegroundColor Cyan
        try
        {
            $rawSummaryText = Get-Content -Path $SummaryCsvPath -Raw -ErrorAction Stop
            $parsedSummary = @(Import-Csv -Path $SummaryCsvPath -ErrorAction Stop)
            $summaryRowCount = $parsedSummary.Count

            if ($summaryRowCount -eq 0)
            {
                throw "Summary CSV parsed successfully but contains 0 data rows."
            }

            $summaryColumns = ($parsedSummary[0].PSObject.Properties | Select-Object -ExpandProperty Name)
            $requiredSummaryColumns = @(
                'SubscriptionName', 'ResourceGroup', 'NSGName', 'NSGResourceId',
                'CriticalFindings', 'HighFindings', 'MediumFindings', 'LowFindings',
                'InformationalFindings', 'TotalFindings', 'ComplianceScore'
            )
            $missingSummaryColumns = @($requiredSummaryColumns | Where-Object { $summaryColumns -notcontains $_ })
            if ($missingSummaryColumns.Count -gt 0)
            {
                throw "Summary CSV is missing expected column(s): $($missingSummaryColumns -join ', ')."
            }

            $summaryAvailable = $true
            $summarySourceLabel = Split-Path -Path $SummaryCsvPath -Leaf
            Write-Host "  ✅  Summary CSV validated — $summaryRowCount NSG(s) found." -ForegroundColor Green
        }
        catch
        {
            Write-Warning "Summary CSV at '$SummaryCsvPath' could not be used: $($_.Exception.Message). Continuing without it - compliance scores and zero-finding NSGs will not be shown."
            $rawSummaryText = ''
            $summaryAvailable = $false
        }
    }
    else
    {
        Write-Warning "No Summary CSV found or provided. Continuing without it - compliance scores and zero-finding NSGs will not be shown. Pass -SummaryCsvPath explicitly, or keep it alongside the Findings CSV from the same Test-AzureNSGCompliance run."
    }
    #endregion

    #region ── JSON-safe embed of raw CSV text ────────────────────────────────────
    $findingsJsonLiteral = $rawFindingsText | ConvertTo-Json -Compress
    $summaryJsonLiteral  = if ($summaryAvailable) { $rawSummaryText | ConvertTo-Json -Compress } else { '""' }
    $findingsIsEmptyJs   = if ($findingsIsEmptyPlaceholder) { 'true' } else { 'false' }
    $summaryAvailableJs  = if ($summaryAvailable) { 'true' } else { 'false' }
    $generatedAt         = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')
    #endregion

    #region ── HTML Dashboard Template ────────────────────────────────────────────

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure NSG Compliance Dashboard</title>
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
.upload-wrap{padding:10px 14px;display:flex;flex-direction:column;gap:6px;border-top:1px solid var(--border)}
.scope-wrap{padding:12px 14px;border-top:1px solid var(--border)}
.scope-label{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.scope-select{width:100%;padding:7px 9px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:12px;margin-bottom:6px}
.scope-select:last-child{margin-bottom:0}
.scope-active-note{font-size:10.5px;color:var(--accent);margin-top:4px;display:none}
.data-note{font-size:10.5px;color:var(--amber);padding:8px 14px;border-top:1px solid var(--border);line-height:1.5;display:none}
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
  #sidebar,.toast,.overlay,#detailPanel,.btn-group,.upload-wrap,.scope-wrap,.theme-toggle-wrap,.sidebar-footer,.data-note{display:none !important}
  body{display:block}
  #main{margin:0;padding:0}
  .page{display:none !important}
  .page.active{display:block !important}
  .summary-sheet{border:none;max-width:100%}
}
.upload-btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px dashed var(--accent);border-radius:var(--radius-sm);cursor:pointer;color:var(--accent);font-family:var(--sans);font-size:11.5px;font-weight:600;transition:all .2s}
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
.bar-label{width:150px;font-size:12px;color:var(--muted2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0}
.bar-track{flex:1;height:16px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .9s ease}
.bar-count{width:34px;text-align:right;font-family:var(--mono);font-size:12px;color:var(--muted)}
.legend-list{display:flex;flex-direction:column;gap:6px;margin-top:10px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer}
.legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}

.top-list-row{display:flex;align-items:center;gap:10px;padding:8px 4px;border-bottom:1px solid var(--border);cursor:pointer;font-size:12.5px}
.top-list-row:last-child{border-bottom:none}
.top-list-row:hover{background:var(--surface2)}
.tl-rank{width:20px;text-align:center;color:var(--muted);font-family:var(--mono);flex-shrink:0}
.tl-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tl-val{font-family:var(--mono);color:var(--muted);font-size:11.5px}
.sev-badge{font-size:10px;font-weight:700;padding:2px 7px;border-radius:20px;font-family:var(--mono);flex-shrink:0;white-space:nowrap}
.sev-Critical{background:rgba(248,81,73,.18);color:var(--red)}
.sev-High{background:rgba(210,153,34,.18);color:var(--amber)}
.sev-Medium{background:rgba(56,139,253,.18);color:var(--accent)}
.sev-Low{background:rgba(57,197,207,.18);color:var(--accent2)}
.sev-Informational{background:rgba(173,186,194,.15);color:var(--muted2)}
.sev-None{background:rgba(63,185,80,.18);color:var(--green)}
.sev-Blocked{background:rgba(210,153,34,.18);color:var(--amber)}
.sev-Duplicate{background:rgba(163,113,247,.18);color:var(--accent3)}

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
tbody tr.clickable{cursor:pointer}
.chip{display:inline-block;padding:1px 8px;border-radius:20px;font-size:10.5px;font-family:var(--mono)}
.chip-in{background:rgba(56,139,253,.15);color:var(--accent)}
.chip-out{background:rgba(163,113,247,.15);color:var(--accent3)}
.mono{font-family:var(--mono);font-size:12px}
.truncate{max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
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
.nsg-card-score{font-family:var(--mono);font-size:16px;font-weight:700;flex-shrink:0}
.nsg-card-sub{font-size:11.5px;color:var(--muted);margin-bottom:10px}
.nsg-card-meta{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.meta-chip{background:var(--surface3);color:var(--muted2);font-size:10.5px;padding:2px 8px;border-radius:20px;font-family:var(--mono)}
.nsg-card-foot{display:flex;justify-content:flex-end;align-items:center;padding-top:10px;border-top:1px solid var(--border)}

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
.mini-rule-head{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:4px;font-weight:700}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:150;display:none}
.overlay.open{display:block}

.toast{position:fixed;bottom:20px;right:20px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:10px 16px;border-radius:8px;font-size:13px;box-shadow:var(--shadow);z-index:300;opacity:0;transform:translateY(10px);transition:all .25s}
.toast.show{opacity:1;transform:none}
</style>
</head>
<body>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">✅</div>
    <h1>NSG Compliance Dashboard</h1>
    <p id="findingsSourceLabel" title="__FINDINGSSOURCELABEL__">__FINDINGSSOURCELABEL__</p>
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
    <button class="nav-btn" data-page="findings" onclick="goToPage('findings')"><span class="nav-icon">📋</span>Findings Table<span class="nav-badge" id="navFindingCount">0</span></button>
    <button class="nav-btn" data-page="critical" onclick="goToPage('critical')"><span class="nav-icon">🚨</span>Critical &amp; High<span class="nav-badge" id="navCritHighCount">0</span></button>
    <button class="nav-btn" data-page="conflicts" onclick="goToPage('conflicts')"><span class="nav-icon">🧩</span>Conflicts<span class="nav-badge" id="navConflictCount">0</span></button>
    <button class="nav-btn" data-page="summary" onclick="goToPage('summary')"><span class="nav-icon">🖨️</span>Summary</button>
  </div>
  <div class="upload-wrap">
    <label class="upload-btn">📁 Load Findings CSV
      <input type="file" id="findingsFileInput" accept=".csv" onchange="handleFindingsFileInput(event)"/>
    </label>
    <label class="upload-btn">📁 Load Summary CSV
      <input type="file" id="summaryFileInput" accept=".csv" onchange="handleSummaryFileInput(event)"/>
    </label>
  </div>
  <div class="theme-toggle-wrap">
    <button class="theme-toggle" onclick="toggleTheme()"><span class="toggle-pill" id="togglePill"></span><span id="themeLabel">Dark theme</span></button>
  </div>
  <div class="data-note" id="dataNote">⚠ No Summary CSV loaded — compliance scores and zero-finding NSGs are not shown. Use "Load Summary CSV" above.</div>
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
      <div class="page-subtitle">Compliance findings across your NSGs, as computed by Test-AzureNSGCompliance.ps1</div>
    </div>
    <div class="btn-group"><button class="btn" onclick="exportFindingsCSV('all')">⬇ Export All Findings CSV</button></div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">🛡️</div><div class="stat-value" id="statNsgs">0</div><div class="stat-label">NSGs Analyzed</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">📋</div><div class="stat-value" id="statFindings">0</div><div class="stat-label">Total Findings</div></div>
    <div class="stat-card c-red"><div class="stat-icon">🔴</div><div class="stat-value" id="statCritical">0</div><div class="stat-label">Critical</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">🟠</div><div class="stat-value" id="statHigh">0</div><div class="stat-label">High</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">🔵</div><div class="stat-value" id="statMedium">0</div><div class="stat-label">Medium</div></div>
    <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-value" id="statClean">0</div><div class="stat-label">Clean NSGs</div></div>
  </div>

  <div class="health-card">
    <div class="health-ring-wrap">
      <svg viewBox="0 0 76 76">
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--surface3)" stroke-width="9"/>
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--green)" stroke-width="9"
          stroke-dasharray="188.5" stroke-dashoffset="188.5" stroke-linecap="round"
          transform="rotate(-90 38 38)" id="scoreArc" style="transition:stroke-dashoffset 1.2s ease"/>
      </svg>
      <div class="health-ring-center"><span class="health-score-num" id="scoreNum">–</span><span class="health-score-pct">/ 100</span></div>
    </div>
    <div class="health-info">
      <h3>Average Compliance Score</h3>
      <p id="scoreExplain">Average of each NSG's score from Test-AzureNSGCompliance.ps1 (100 minus weighted deductions per finding). A review candidate, not a certified audit result.</p>
      <div class="health-bar-row"><span style="color:var(--red);font-size:12px">🔴 Critical</span><div class="health-mini-bar"><div class="health-mini-fill" id="hCrit" style="background:var(--red);width:0%"></div></div><span class="mono" id="hCritN" style="font-size:12px;color:var(--muted)">0</span></div>
      <div class="health-bar-row"><span style="color:var(--amber);font-size:12px">🟠 High</span><div class="health-mini-bar"><div class="health-mini-fill" id="hHigh" style="background:var(--amber);width:0%"></div></div><span class="mono" id="hHighN" style="font-size:12px;color:var(--muted)">0</span></div>
      <div class="health-bar-row"><span style="color:var(--accent);font-size:12px">🔵 Medium</span><div class="health-mini-bar"><div class="health-mini-fill" id="hMed" style="background:var(--accent);width:0%"></div></div><span class="mono" id="hMedN" style="font-size:12px;color:var(--muted)">0</span></div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Findings by Check Category <span style="font-size:11px;color:var(--muted);font-weight:400">(click to filter)</span></div>
      <div id="categoryBars"></div>
    </div>
    <div class="panel">
      <div class="section-title">🔎 Findings by Severity <span style="font-size:11px;color:var(--muted);font-weight:400">(click to filter)</span></div>
      <div id="severityLegend" class="legend-list"></div>
    </div>
  </div>

  <div class="panel">
    <div class="section-title">⚠️ Worst-Scoring NSGs <span style="font-size:11px;color:var(--muted);font-weight:400">(click to inspect)</span></div>
    <div id="worstNsgs"></div>
  </div>
</section>

<!-- NSG EXPLORER -->
<section id="page-explorer" class="page">
  <div class="page-header">
    <div><div class="page-title">NSG Explorer</div><div class="page-subtitle">Every analyzed NSG with its compliance score and finding counts</div></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔎</span><input type="text" id="explorerSearch" placeholder="Search NSG, resource group, subscription…" oninput="renderExplorer()"/></div>
    <select id="explorerSort" onchange="renderExplorer()">
      <option value="score-asc">Worst Score First</option>
      <option value="findings-desc">Most Findings</option>
      <option value="alpha">Alphabetical</option>
    </select>
    <span class="result-count" id="explorerCount"></span>
  </div>
  <div class="nsg-grid" id="nsgGrid"></div>
</section>

<!-- FINDINGS TABLE -->
<section id="page-findings" class="page">
  <div class="page-header">
    <div><div class="page-title">Findings Table</div><div class="page-subtitle">Search, filter and export every compliance finding</div></div>
    <div class="btn-group"><button class="btn" onclick="exportFindingsCSV('filtered')">⬇ Export Filtered CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔎</span><input type="text" id="findingsSearch" placeholder="Search NSG, rule name, finding text… (press / to focus)" oninput="filterFindings()"/></div>
    <select id="severityFilter" onchange="filterFindings()">
      <option value="">All Severities</option>
      <option value="Critical">Critical</option><option value="High">High</option>
      <option value="Medium">Medium</option><option value="Low">Low</option>
      <option value="Informational">Informational</option>
    </select>
    <select id="categoryFilter" onchange="filterFindings()"><option value="">All Categories</option></select>
    <select id="directionFilter" onchange="filterFindings()"><option value="">All Directions</option><option value="Inbound">Inbound</option><option value="Outbound">Outbound</option><option value="N/A">N/A</option></select>
    <span class="result-count" id="findingsResultCount"></span>
  </div>
  <table>
    <thead><tr>
      <th onclick="sortFindings('nsg')">NSG <span class="sort-arrow">↕</span></th>
      <th onclick="sortFindings('rule')">Rule <span class="sort-arrow">↕</span></th>
      <th onclick="sortFindings('direction')">Dir <span class="sort-arrow">↕</span></th>
      <th onclick="sortFindings('category')">Category <span class="sort-arrow">↕</span></th>
      <th onclick="sortFindings('severity')">Severity <span class="sort-arrow">↕</span></th>
      <th>Finding</th>
    </tr></thead>
    <tbody id="findingsTableBody"></tbody>
  </table>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:12px">
    <span id="findingsPageInfo" style="font-size:12px;color:var(--muted)"></span>
    <div class="pagination" id="findingsPagination"></div>
  </div>
</section>

<!-- CRITICAL & HIGH -->
<section id="page-critical" class="page">
  <div class="page-header">
    <div><div class="page-title">Critical &amp; High Findings</div><div class="page-subtitle">Only the most severe findings, worst first</div></div>
    <div class="btn-group"><button class="btn" onclick="exportFindingsCSV('critHigh')">⬇ Export CSV</button></div>
  </div>
  <div id="critHighEmpty" style="display:none" class="panel">✅ No Critical or High severity findings in the current scope.</div>
  <table id="critHighTable">
    <thead><tr><th>Severity</th><th>NSG</th><th>Rule</th><th>Direction</th><th>Category</th><th>Finding</th><th>Recommendation</th></tr></thead>
    <tbody id="critHighTableBody"></tbody>
  </table>
</section>

<!-- CONFLICTS -->
<section id="page-conflicts" class="page">
  <div class="page-header">
    <div><div class="page-title">Conflicts &amp; Duplicates</div><div class="page-subtitle">Priority-conflict (shadowed) rules and duplicate rules identified by Test-AzureNSGCompliance.ps1</div></div>
  </div>

  <div class="panel" style="margin-bottom:16px">
    <div class="section-title">🕶️ Priority Conflicts <span style="font-size:11px;color:var(--muted);font-weight:400">— a rule that may be shadowed by an earlier, conflicting-action rule</span></div>
    <div id="conflictEmpty" style="display:none;color:var(--muted);font-size:12.5px">✅ No priority conflicts detected.</div>
    <table id="conflictTable" style="display:none">
      <thead><tr><th>NSG</th><th>Direction</th><th>Rule (priority)</th><th>Conflicting Rule</th><th>Explanation</th></tr></thead>
      <tbody id="conflictTableBody"></tbody>
    </table>
  </div>

  <div class="panel">
    <div class="section-title">📑 Duplicate Rules <span style="font-size:11px;color:var(--muted);font-weight:400">— rules with the same effective scope</span></div>
    <div id="dupEmpty" style="display:none;color:var(--muted);font-size:12.5px">✅ No duplicate rules detected.</div>
    <table id="dupTable" style="display:none">
      <thead><tr><th>NSG</th><th>Direction</th><th>Rule</th><th>Duplicate Of</th><th>Details</th></tr></thead>
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
  <div class="detail-topbar"><strong id="detailTitle">Detail</strong><button class="detail-close" onclick="closeDetail()">✕</button></div>
  <div id="detailContent"></div>
</div>

<div class="toast" id="toast"></div>

<script>
// ── Embedded CSVs (from PowerShell) ──
const EMBEDDED_FINDINGS_CSV_TEXT = __FINDINGS_CSV_JSON__;
const EMBEDDED_SUMMARY_CSV_TEXT  = __SUMMARY_CSV_JSON__;
const FINDINGS_IS_EMPTY_PLACEHOLDER = __FINDINGS_IS_EMPTY__;
const SUMMARY_AVAILABLE_INITIAL = __SUMMARY_AVAILABLE__;
const FINDINGS_SOURCE_LABEL = "__FINDINGSSOURCELABEL__";
const SUMMARY_SOURCE_LABEL  = "__SUMMARYSOURCELABEL__";

// Column maps — update here if Test-AzureNSGCompliance.ps1's schema changes.
const FINDINGS_COLMAP = {
  sub:'SubscriptionName', rg:'ResourceGroup', nsg:'NSGName', nsgId:'NSGResourceId', loc:'NSGLocation',
  ruleName:'RuleName', direction:'RuleDirection', priority:'RulePriority',
  category:'CheckCategory', severity:'Severity', finding:'Finding', recommendation:'Recommendation',
  compliance:'ComplianceReference', related:'RelatedRule', collected:'CollectedAtUTC'
};
const SUMMARY_COLMAP = {
  sub:'SubscriptionName', rg:'ResourceGroup', nsg:'NSGName', nsgId:'NSGResourceId',
  crit:'CriticalFindings', high:'HighFindings', med:'MediumFindings', low:'LowFindings', info:'InformationalFindings',
  total:'TotalFindings', score:'ComplianceScore'
};
const SEV_RANK = {Critical:4, High:3, Medium:2, Low:1, Informational:0};
const CATEGORY_LABELS = {
  AnyToAnyAllow:'Any → Any Allow', RDPExposedToInternet:'RDP Exposed to Internet',
  SSHExposedToInternet:'SSH Exposed to Internet', SensitivePortExposedToInternet:'Sensitive Port Exposed to Internet',
  WidePortRangeExposedToInternet:'Wide Port Range Exposed to Internet', MissingDescription:'Missing Description',
  DuplicateRule:'Duplicate Rule', PriorityConflict:'Priority Conflict', OrphanedNSG:'Orphaned NSG',
  UnusedNSG:'Unused NSG', NoRulesDefined:'No Rules Defined', RuleSprawl:'Rule Sprawl',
  MissingFlowLogs:'Missing Flow Logs', LegacyFlowLogsInUse:'Legacy Flow Logs In Use'
};
function categoryLabel(c){ return CATEGORY_LABELS[c] || c || 'Unknown'; }

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

let RAW_FINDINGS=[], FINDINGS=[], RAW_SUMMARY=[], SUMMARY_ROWS=[];
let SUMMARY_AVAILABLE = SUMMARY_AVAILABLE_INITIAL;
let filteredFindings=[], findingsSortState={col:'severity',dir:'desc'}, findingsPage=1, findingsPageSize=25;
let CONFLICTS={conflicts:[],duplicates:[]};

function loadFindings(csvText, label, isEmptyPlaceholder){
  RAW_FINDINGS = isEmptyPlaceholder ? [] : parseCSV(csvText);
  document.getElementById('findingsSourceLabel').textContent = label;
  document.getElementById('findingsSourceLabel').title = label;
  populateScopeFilters();
  populateCategoryFilter();
  applyScope();
  showToast('Loaded '+RAW_FINDINGS.length+' finding row(s) from '+label);
}
function loadSummary(csvText, label){
  RAW_SUMMARY = parseCSV(csvText);
  SUMMARY_AVAILABLE = RAW_SUMMARY.length > 0;
  document.getElementById('dataNote').style.display = SUMMARY_AVAILABLE ? 'none' : 'block';
  populateScopeFilters();
  applyScope();
  showToast('Loaded '+RAW_SUMMARY.length+' NSG summary row(s) from '+label);
}

function populateScopeFilters(){
  const subSel=document.getElementById('scopeSub');
  const pool = SUMMARY_AVAILABLE ? RAW_SUMMARY : RAW_FINDINGS;
  const subs=Array.from(new Set(pool.map(r=>r[SUMMARY_COLMAP.sub] || r[FINDINGS_COLMAP.sub]))).filter(Boolean).sort();
  const prevSub = subSel.value;
  subSel.innerHTML='<option value="">All Subscriptions</option>'+subs.map(s=>`<option value="${escH(s)}">${escH(s)}</option>`).join('');
  if(subs.includes(prevSub)) subSel.value = prevSub;
  populateRGOptions();
}
function populateRGOptions(){
  const subVal=document.getElementById('scopeSub').value;
  const rgSel=document.getElementById('scopeRG');
  const pool = SUMMARY_AVAILABLE ? RAW_SUMMARY : RAW_FINDINGS;
  const filteredPool = subVal ? pool.filter(r=>(r[SUMMARY_COLMAP.sub]||r[FINDINGS_COLMAP.sub])===subVal) : pool;
  const prevRg = rgSel.value;
  const rgs=Array.from(new Set(filteredPool.map(r=>r[SUMMARY_COLMAP.rg]||r[FINDINGS_COLMAP.rg]))).filter(Boolean).sort();
  rgSel.innerHTML='<option value="">All Resource Groups</option>'+rgs.map(g=>`<option value="${escH(g)}">${escH(g)}</option>`).join('');
  if(rgs.includes(prevRg)) rgSel.value = prevRg;
}
function populateCategoryFilter(){
  const sel=document.getElementById('categoryFilter');
  const prev=sel.value;
  const cats=Array.from(new Set(RAW_FINDINGS.map(r=>r[FINDINGS_COLMAP.category]))).filter(Boolean).sort();
  sel.innerHTML='<option value="">All Categories</option>'+cats.map(c=>`<option value="${escH(c)}">${escH(categoryLabel(c))}</option>`).join('');
  if(cats.includes(prev)) sel.value=prev;
}
function onScopeSubChange(){
  populateRGOptions();
  applyScope();
}
function applyScope(){
  const subVal=document.getElementById('scopeSub').value;
  const rgVal=document.getElementById('scopeRG').value;
  FINDINGS = RAW_FINDINGS.filter(r=> (!subVal || r[FINDINGS_COLMAP.sub]===subVal) && (!rgVal || r[FINDINGS_COLMAP.rg]===rgVal));
  SUMMARY_ROWS = SUMMARY_AVAILABLE ? RAW_SUMMARY.filter(r=> (!subVal || r[SUMMARY_COLMAP.sub]===subVal) && (!rgVal || r[SUMMARY_COLMAP.rg]===rgVal)) : [];
  const note=document.getElementById('scopeActiveNote');
  if(subVal || rgVal){
    note.style.display='block';
    note.textContent='Scoped: '+(subVal||'All subs')+(rgVal?' / '+rgVal:'');
  } else {
    note.style.display='none';
  }
  CONFLICTS = computeConflicts(FINDINGS);
  renderAll();
}

function nsgCountForScope(){
  if(SUMMARY_AVAILABLE) return SUMMARY_ROWS.length;
  return new Set(FINDINGS.map(r=>r[FINDINGS_COLMAP.nsgId]||r[FINDINGS_COLMAP.nsg])).size;
}

function renderAll(){
  renderOverview();
  renderExplorer();
  filterFindings();
  renderCritHigh();
  renderConflicts();
  renderSummary();
  document.getElementById('navNsgCount').textContent = nsgCountForScope();
  document.getElementById('navFindingCount').textContent = FINDINGS.length;
  document.getElementById('navCritHighCount').textContent = FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='Critical'||r[FINDINGS_COLMAP.severity]==='High').length;
  document.getElementById('navConflictCount').textContent = CONFLICTS.conflicts.length + CONFLICTS.duplicates.length;
}

// ── Overview ──
function renderOverview(){
  const crit=FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='Critical').length;
  const high=FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='High').length;
  const med=FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='Medium').length;

  document.getElementById('statNsgs').textContent = nsgCountForScope();
  document.getElementById('statFindings').textContent = FINDINGS.length;
  document.getElementById('statCritical').textContent = crit;
  document.getElementById('statHigh').textContent = high;
  document.getElementById('statMedium').textContent = med;
  document.getElementById('statClean').textContent = SUMMARY_AVAILABLE ? SUMMARY_ROWS.filter(r=>parseInt(r[SUMMARY_COLMAP.total]||0)===0).length : 0;

  const scoreArc=document.getElementById('scoreArc');
  const scoreNum=document.getElementById('scoreNum');
  if(SUMMARY_AVAILABLE && SUMMARY_ROWS.length){
    const avgScore = Math.round(SUMMARY_ROWS.reduce((s,r)=>s+parseFloat(r[SUMMARY_COLMAP.score]||0),0) / SUMMARY_ROWS.length);
    const col = avgScore>=80?'var(--green)':avgScore>=50?'var(--amber)':'var(--red)';
    scoreNum.textContent=avgScore; scoreNum.style.color=col;
    const circumference=188.5;
    scoreArc.setAttribute('stroke',col);
    scoreArc.style.strokeDashoffset=circumference-(circumference*avgScore/100);
  } else {
    scoreNum.textContent='–'; scoreNum.style.color='var(--muted)';
    scoreArc.setAttribute('stroke','var(--surface3)');
    scoreArc.style.strokeDashoffset=188.5;
  }

  const maxSev=Math.max(crit,high,med,1);
  document.getElementById('hCrit').style.width=(crit/maxSev*100)+'%'; document.getElementById('hCritN').textContent=crit;
  document.getElementById('hHigh').style.width=(high/maxSev*100)+'%'; document.getElementById('hHighN').textContent=high;
  document.getElementById('hMed').style.width=(med/maxSev*100)+'%'; document.getElementById('hMedN').textContent=med;

  const catCounts={};
  FINDINGS.forEach(r=>{const c=r[FINDINGS_COLMAP.category]||'Unknown';catCounts[c]=(catCounts[c]||0)+1;});
  const catEntries=Object.entries(catCounts).sort((a,b)=>b[1]-a[1]);
  const catMax=catEntries.length?catEntries[0][1]:1;
  const palette=['#f85149','#d29922','#388bfd','#39c5cf','#a371f7','#3fb950'];
  document.getElementById('categoryBars').innerHTML = catEntries.length ? catEntries.map(([c,n],i)=>`
    <div class="bar-row" onclick="filterByCategory('${escJ(c)}')"><span class="bar-label" title="${escH(categoryLabel(c))}">${escH(categoryLabel(c))}</span>
    <div class="bar-track"><div class="bar-fill" style="width:${Math.round(n/catMax*100)}%;background:${palette[i%palette.length]}"></div></div>
    <span class="bar-count">${n}</span></div>`).join('') : '<p style="color:var(--muted);font-size:12.5px">No findings in the current scope 🎉</p>';

  const sevCounts={};
  FINDINGS.forEach(r=>{const s=r[FINDINGS_COLMAP.severity]||'Informational';sevCounts[s]=(sevCounts[s]||0)+1;});
  const sevOrder=['Critical','High','Medium','Low','Informational'];
  document.getElementById('severityLegend').innerHTML = FINDINGS.length ? sevOrder.filter(s=>sevCounts[s]).map(s=>`
    <div class="legend-item" onclick="filterBySeverity('${s}')"><span class="sev-badge sev-${s}">${s}</span><span style="margin-left:auto;color:var(--muted);font-family:var(--mono);font-size:11px">${sevCounts[s]}</span></div>`).join('') : '<p style="color:var(--muted);font-size:12.5px">No findings in the current scope 🎉</p>';

  const worstEl=document.getElementById('worstNsgs');
  if(SUMMARY_AVAILABLE && SUMMARY_ROWS.length){
    const worst=[...SUMMARY_ROWS].sort((a,b)=>parseFloat(a[SUMMARY_COLMAP.score]||100)-parseFloat(b[SUMMARY_COLMAP.score]||100)).slice(0,10);
    worstEl.innerHTML = worst.map((r,i)=>{
      const score=parseFloat(r[SUMMARY_COLMAP.score]||100);
      const col=score>=80?'var(--green)':score>=50?'var(--amber)':'var(--red)';
      return `<div class="top-list-row" onclick="openNsgDetail('${escJ(r[SUMMARY_COLMAP.nsgId]||r[SUMMARY_COLMAP.nsg])}')">
        <span class="tl-rank">${i+1}</span>
        <span class="tl-name" title="${escH(r[SUMMARY_COLMAP.nsg])}">${escH(r[SUMMARY_COLMAP.nsg])}</span>
        <span class="tl-val">${r[SUMMARY_COLMAP.total]} finding(s)</span>
        <span class="mono" style="color:${col};font-weight:700">${score}</span>
      </div>`;
    }).join('');
  } else {
    worstEl.innerHTML = '<p style="color:var(--muted);font-size:12.5px">Load a Summary CSV to see per-NSG compliance scores.</p>';
  }
}
function filterByCategory(cat){
  goToPage('findings');
  document.getElementById('categoryFilter').value=cat;
  filterFindings();
}
function filterBySeverity(sev){
  goToPage('findings');
  document.getElementById('severityFilter').value=sev;
  filterFindings();
}

// ── NSG Explorer ──
function renderExplorer(){
  const q=(document.getElementById('explorerSearch').value||'').toLowerCase();
  const sortMode=document.getElementById('explorerSort').value;
  const grid=document.getElementById('nsgGrid');

  if(!SUMMARY_AVAILABLE || !SUMMARY_ROWS.length){
    document.getElementById('explorerCount').textContent='';
    grid.innerHTML = '<p style="color:var(--muted);font-size:13px">No Summary CSV loaded — load one via the sidebar to browse NSGs with their compliance scores.</p>';
    return;
  }

  let list=SUMMARY_ROWS.filter(n=>!q || [n[SUMMARY_COLMAP.nsg],n[SUMMARY_COLMAP.rg],n[SUMMARY_COLMAP.sub]].join(' ').toLowerCase().includes(q));
  if(sortMode==='score-asc') list=[...list].sort((a,b)=>parseFloat(a[SUMMARY_COLMAP.score]||100)-parseFloat(b[SUMMARY_COLMAP.score]||100));
  else if(sortMode==='findings-desc') list=[...list].sort((a,b)=>parseInt(b[SUMMARY_COLMAP.total]||0)-parseInt(a[SUMMARY_COLMAP.total]||0));
  else list=[...list].sort((a,b)=>(a[SUMMARY_COLMAP.nsg]||'').localeCompare(b[SUMMARY_COLMAP.nsg]||''));

  document.getElementById('explorerCount').textContent=list.length+' NSG'+(list.length!==1?'s':'');
  grid.innerHTML=list.map(n=>{
    const score=parseFloat(n[SUMMARY_COLMAP.score]||100);
    const col=score>=80?'var(--green)':score>=50?'var(--amber)':'var(--red)';
    const chips=[];
    if(parseInt(n[SUMMARY_COLMAP.crit]||0)>0) chips.push(`<span class="sev-badge sev-Critical">${n[SUMMARY_COLMAP.crit]} Crit</span>`);
    if(parseInt(n[SUMMARY_COLMAP.high]||0)>0) chips.push(`<span class="sev-badge sev-High">${n[SUMMARY_COLMAP.high]} High</span>`);
    if(parseInt(n[SUMMARY_COLMAP.med]||0)>0) chips.push(`<span class="sev-badge sev-Medium">${n[SUMMARY_COLMAP.med]} Med</span>`);
    if(parseInt(n[SUMMARY_COLMAP.low]||0)>0) chips.push(`<span class="sev-badge sev-Low">${n[SUMMARY_COLMAP.low]} Low</span>`);
    if(parseInt(n[SUMMARY_COLMAP.info]||0)>0) chips.push(`<span class="sev-badge sev-Informational">${n[SUMMARY_COLMAP.info]} Info</span>`);
    return `<div class="nsg-card" onclick="openNsgDetail('${escJ(n[SUMMARY_COLMAP.nsgId]||n[SUMMARY_COLMAP.nsg])}')">
      <div class="nsg-card-head"><div class="nsg-card-name" title="${escH(n[SUMMARY_COLMAP.nsg])}">${escH(n[SUMMARY_COLMAP.nsg])}</div><div class="nsg-card-score" style="color:${col}">${score}</div></div>
      <div class="nsg-card-sub">${escH(n[SUMMARY_COLMAP.sub])} / ${escH(n[SUMMARY_COLMAP.rg])}</div>
      <div class="nsg-card-meta">${chips.length?chips.join(''):'<span class="meta-chip">No findings</span>'}</div>
      <div class="nsg-card-foot"><span style="color:var(--accent);font-size:11.5px">View →</span></div>
    </div>`;
  }).join('');
}

function openNsgDetail(id){
  const nsgFindings = FINDINGS.filter(r=>(r[FINDINGS_COLMAP.nsgId]||r[FINDINGS_COLMAP.nsg])===id).sort((a,b)=>(SEV_RANK[b[FINDINGS_COLMAP.severity]]||0)-(SEV_RANK[a[FINDINGS_COLMAP.severity]]||0));
  const summaryRow = SUMMARY_ROWS.find(r=>(r[SUMMARY_COLMAP.nsgId]||r[SUMMARY_COLMAP.nsg])===id);
  const name = summaryRow ? summaryRow[SUMMARY_COLMAP.nsg] : (nsgFindings[0] ? nsgFindings[0][FINDINGS_COLMAP.nsg] : id);
  const sub = summaryRow ? summaryRow[SUMMARY_COLMAP.sub] : (nsgFindings[0] ? nsgFindings[0][FINDINGS_COLMAP.sub] : '');
  const rg = summaryRow ? summaryRow[SUMMARY_COLMAP.rg] : (nsgFindings[0] ? nsgFindings[0][FINDINGS_COLMAP.rg] : '');
  const score = summaryRow ? parseFloat(summaryRow[SUMMARY_COLMAP.score]||100) : null;

  const findingsHtml = nsgFindings.length ? nsgFindings.map(r=>{
    const dir=r[FINDINGS_COLMAP.direction]==='Inbound'?'chip-in':(r[FINDINGS_COLMAP.direction]==='Outbound'?'chip-out':'');
    return `<div class="mini-rule">
      <div class="mini-rule-head"><span>${escH(r[FINDINGS_COLMAP.ruleName])}</span><span class="sev-badge sev-${r[FINDINGS_COLMAP.severity]}">${escH(r[FINDINGS_COLMAP.severity])}</span></div>
      ${r[FINDINGS_COLMAP.direction] && r[FINDINGS_COLMAP.direction]!=='N/A' ? `<span class="chip ${dir}">${escH(r[FINDINGS_COLMAP.direction])}</span> ` : ''}
      <span class="mono">${escH(categoryLabel(r[FINDINGS_COLMAP.category]))}</span>
      <div style="color:var(--muted2);margin-top:6px">${escH(r[FINDINGS_COLMAP.finding])}</div>
      <div style="color:var(--muted);margin-top:4px;font-style:italic">${escH(r[FINDINGS_COLMAP.recommendation])}</div>
    </div>`;
  }).join('') : '<p style="color:var(--green);font-size:12.5px">✅ No findings — this NSG passed every check.</p>';

  document.getElementById('detailTitle').textContent='NSG Detail';
  document.getElementById('detailContent').innerHTML=`
    <div class="detail-name">${escH(name)}</div>
    <div class="detail-path">${escH(id)}</div>
    <div class="detail-meta-row">
      <span class="detail-chip">🏢 ${escH(sub||'')}</span>
      <span class="detail-chip">📁 ${escH(rg||'')}</span>
      ${score!==null?`<span class="detail-chip" style="font-weight:700">Score: ${score}</span>`:''}
      <span class="detail-chip">${nsgFindings.length} finding(s)</span>
    </div>
    <div class="detail-section"><div class="detail-section-title">Findings</div>${findingsHtml}</div>`;
  document.getElementById('detailPanel').classList.add('open');
  document.getElementById('overlay').classList.add('open');
}
function closeDetail(){document.getElementById('detailPanel').classList.remove('open');document.getElementById('overlay').classList.remove('open');}

// ── Findings table ──
function filterFindings(){
  const q=(document.getElementById('findingsSearch').value||'').toLowerCase();
  const sev=document.getElementById('severityFilter').value;
  const cat=document.getElementById('categoryFilter').value;
  const dir=document.getElementById('directionFilter').value;
  filteredFindings = FINDINGS.filter(r=>{
    if(sev && r[FINDINGS_COLMAP.severity]!==sev) return false;
    if(cat && r[FINDINGS_COLMAP.category]!==cat) return false;
    if(dir && r[FINDINGS_COLMAP.direction]!==dir) return false;
    if(q){
      const hay=[r[FINDINGS_COLMAP.nsg],r[FINDINGS_COLMAP.ruleName],r[FINDINGS_COLMAP.finding],r[FINDINGS_COLMAP.category]].join(' ').toLowerCase();
      if(!hay.includes(q)) return false;
    }
    return true;
  });
  findingsPage=1;
  sortFindings(findingsSortState.col, true);
}
function sortFindings(col, keepDir){
  if(!keepDir){ findingsSortState.dir = (findingsSortState.col===col && findingsSortState.dir==='asc') ? 'desc':'asc'; findingsSortState.col=col; }
  const key = {nsg:FINDINGS_COLMAP.nsg, rule:FINDINGS_COLMAP.ruleName, direction:FINDINGS_COLMAP.direction, category:FINDINGS_COLMAP.category, severity:FINDINGS_COLMAP.severity}[findingsSortState.col] || FINDINGS_COLMAP.severity;
  filteredFindings.sort((a,b)=>{
    let av=a[key], bv=b[key];
    if(findingsSortState.col==='severity'){ av=SEV_RANK[av]||0; bv=SEV_RANK[bv]||0; }
    else { av=(av||'').toLowerCase(); bv=(bv||'').toLowerCase(); }
    if(av<bv) return findingsSortState.dir==='asc'?-1:1;
    if(av>bv) return findingsSortState.dir==='asc'?1:-1;
    return 0;
  });
  renderFindingsTable();
}
function renderFindingsTable(){
  const total=filteredFindings.length;
  const pages=Math.max(1,Math.ceil(total/findingsPageSize));
  if(findingsPage>pages) findingsPage=pages;
  const start=(findingsPage-1)*findingsPageSize;
  const pageRows=filteredFindings.slice(start,start+findingsPageSize);
  document.getElementById('findingsResultCount').textContent=total+' finding'+(total!==1?'s':'');
  document.getElementById('findingsTableBody').innerHTML=pageRows.map((r)=>{
    const dir=r[FINDINGS_COLMAP.direction]==='Inbound'?'chip-in':(r[FINDINGS_COLMAP.direction]==='Outbound'?'chip-out':'');
    const idxInFindings=FINDINGS.indexOf(r);
    return `<tr class="clickable" onclick="openFindingDetail(${idxInFindings})">
      <td>${escH(r[FINDINGS_COLMAP.nsg])}</td>
      <td>${escH(r[FINDINGS_COLMAP.ruleName])}</td>
      <td>${r[FINDINGS_COLMAP.direction] && r[FINDINGS_COLMAP.direction]!=='N/A' ? `<span class="chip ${dir}">${escH(r[FINDINGS_COLMAP.direction])}</span>` : '<span style="color:var(--muted)">—</span>'}</td>
      <td class="mono">${escH(categoryLabel(r[FINDINGS_COLMAP.category]))}</td>
      <td><span class="sev-badge sev-${r[FINDINGS_COLMAP.severity]}">${escH(r[FINDINGS_COLMAP.severity])}</span></td>
      <td><span class="truncate" title="${escH(r[FINDINGS_COLMAP.finding])}">${escH(r[FINDINGS_COLMAP.finding])}</span></td>
    </tr>`;
  }).join('');
  document.getElementById('findingsPageInfo').textContent=`Showing ${total?start+1:0}–${Math.min(start+findingsPageSize,total)} of ${total}`;
  const pag=document.getElementById('findingsPagination');
  let btns=`<button ${findingsPage<=1?'disabled':''} onclick="findingsPage--;renderFindingsTable()">‹</button>`;
  const span=2;
  for(let p=1;p<=pages;p++){
    if(p===1||p===pages||Math.abs(p-findingsPage)<=span){
      btns+=`<button class="${p===findingsPage?'active':''}" onclick="findingsPage=${p};renderFindingsTable()">${p}</button>`;
    } else if(Math.abs(p-findingsPage)===span+1){ btns+=`<span style="color:var(--muted);padding:0 4px">…</span>`; }
  }
  btns+=`<button ${findingsPage>=pages?'disabled':''} onclick="findingsPage++;renderFindingsTable()">›</button>`;
  pag.innerHTML=btns;
}

function openFindingDetail(idxInFindings){
  const r = FINDINGS[idxInFindings];
  if(!r) return;
  const dir=r[FINDINGS_COLMAP.direction]==='Inbound'?'chip-in':(r[FINDINGS_COLMAP.direction]==='Outbound'?'chip-out':'');
  document.getElementById('detailTitle').textContent='Finding Detail';
  document.getElementById('detailContent').innerHTML=`
    <div class="detail-name">${escH(r[FINDINGS_COLMAP.ruleName])}</div>
    <div class="detail-path">${escH(r[FINDINGS_COLMAP.nsg])} — ${escH(r[FINDINGS_COLMAP.nsgId])}</div>
    <div class="detail-meta-row">
      <span class="sev-badge sev-${r[FINDINGS_COLMAP.severity]}">${escH(r[FINDINGS_COLMAP.severity])}</span>
      ${r[FINDINGS_COLMAP.direction] && r[FINDINGS_COLMAP.direction]!=='N/A' ? `<span class="chip ${dir}">${escH(r[FINDINGS_COLMAP.direction])}</span>` : ''}
      <span class="detail-chip">Priority: ${escH(r[FINDINGS_COLMAP.priority])}</span>
      <span class="detail-chip">${escH(categoryLabel(r[FINDINGS_COLMAP.category]))}</span>
    </div>
    <div class="detail-section"><div class="detail-section-title">Finding</div><div class="detail-description" style="color:var(--muted2);font-size:13px">${escH(r[FINDINGS_COLMAP.finding])}</div></div>
    <div class="detail-section"><div class="detail-section-title">Recommendation</div><div style="color:var(--muted2);font-size:13px">${escH(r[FINDINGS_COLMAP.recommendation])}</div></div>
    ${r[FINDINGS_COLMAP.related] ? `<div class="detail-section"><div class="detail-section-title">Related Rule</div><div class="mono" style="font-size:12.5px">${escH(r[FINDINGS_COLMAP.related])}</div></div>` : ''}
    <div class="detail-section"><div class="detail-section-title">Compliance Reference</div><div style="color:var(--muted);font-size:12px">${escH(r[FINDINGS_COLMAP.compliance])}</div></div>`;
  document.getElementById('detailPanel').classList.add('open');
  document.getElementById('overlay').classList.add('open');
}

// ── Critical & High tab ──
function renderCritHigh(){
  const rows = FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='Critical'||r[FINDINGS_COLMAP.severity]==='High')
    .sort((a,b)=>(SEV_RANK[b[FINDINGS_COLMAP.severity]]||0)-(SEV_RANK[a[FINDINGS_COLMAP.severity]]||0));
  document.getElementById('critHighEmpty').style.display = rows.length? 'none':'block';
  document.getElementById('critHighTable').style.display = rows.length? 'table':'none';
  document.getElementById('critHighTableBody').innerHTML = rows.map(r=>{
    const dir=r[FINDINGS_COLMAP.direction]==='Inbound'?'chip-in':(r[FINDINGS_COLMAP.direction]==='Outbound'?'chip-out':'');
    return `<tr>
      <td><span class="sev-badge sev-${r[FINDINGS_COLMAP.severity]}">${escH(r[FINDINGS_COLMAP.severity])}</span></td>
      <td>${escH(r[FINDINGS_COLMAP.nsg])}</td>
      <td>${escH(r[FINDINGS_COLMAP.ruleName])}</td>
      <td>${r[FINDINGS_COLMAP.direction] && r[FINDINGS_COLMAP.direction]!=='N/A' ? `<span class="chip ${dir}">${escH(r[FINDINGS_COLMAP.direction])}</span>` : '<span style="color:var(--muted)">—</span>'}</td>
      <td class="mono">${escH(categoryLabel(r[FINDINGS_COLMAP.category]))}</td>
      <td style="color:var(--muted2)">${escH(r[FINDINGS_COLMAP.finding])}</td>
      <td style="color:var(--muted)">${escH(r[FINDINGS_COLMAP.recommendation])}</td>
    </tr>`;
  }).join('');
}

// ── Conflicts tab ──
function computeConflicts(rows){
  return {
    conflicts: rows.filter(r=>r[FINDINGS_COLMAP.category]==='PriorityConflict'),
    duplicates: rows.filter(r=>r[FINDINGS_COLMAP.category]==='DuplicateRule')
  };
}
function renderConflicts(){
  const conflictTable=document.getElementById('conflictTable');
  const conflictEmpty=document.getElementById('conflictEmpty');
  if(CONFLICTS.conflicts.length){
    conflictTable.style.display='table'; conflictEmpty.style.display='none';
    document.getElementById('conflictTableBody').innerHTML = CONFLICTS.conflicts.map(r=>{
      const dir=r[FINDINGS_COLMAP.direction]==='Inbound'?'chip-in':(r[FINDINGS_COLMAP.direction]==='Outbound'?'chip-out':'');
      return `<tr>
        <td>${escH(r[FINDINGS_COLMAP.nsg])}</td>
        <td>${r[FINDINGS_COLMAP.direction] && r[FINDINGS_COLMAP.direction]!=='N/A' ? `<span class="chip ${dir}">${escH(r[FINDINGS_COLMAP.direction])}</span>` : '—'}</td>
        <td class="mono">${escH(r[FINDINGS_COLMAP.ruleName])} (${escH(r[FINDINGS_COLMAP.priority])})</td>
        <td class="mono">${escH(r[FINDINGS_COLMAP.related])}</td>
        <td style="color:var(--muted)">${escH(r[FINDINGS_COLMAP.finding])}</td>
      </tr>`;
    }).join('');
  } else {
    conflictTable.style.display='none'; conflictEmpty.style.display='block';
  }

  const dupTable=document.getElementById('dupTable');
  const dupEmpty=document.getElementById('dupEmpty');
  if(CONFLICTS.duplicates.length){
    dupTable.style.display='table'; dupEmpty.style.display='none';
    document.getElementById('dupTableBody').innerHTML = CONFLICTS.duplicates.map(r=>{
      const dir=r[FINDINGS_COLMAP.direction]==='Inbound'?'chip-in':(r[FINDINGS_COLMAP.direction]==='Outbound'?'chip-out':'');
      return `<tr>
        <td>${escH(r[FINDINGS_COLMAP.nsg])}</td>
        <td>${r[FINDINGS_COLMAP.direction] && r[FINDINGS_COLMAP.direction]!=='N/A' ? `<span class="chip ${dir}">${escH(r[FINDINGS_COLMAP.direction])}</span>` : '—'}</td>
        <td class="mono">${escH(r[FINDINGS_COLMAP.ruleName])}</td>
        <td class="mono">${escH(r[FINDINGS_COLMAP.related])}</td>
        <td style="color:var(--muted)">${escH(r[FINDINGS_COLMAP.finding])}</td>
      </tr>`;
    }).join('');
  } else {
    dupTable.style.display='none'; dupEmpty.style.display='block';
  }
}

// ── Summary / Print tab ──
function renderSummary(){
  const crit=FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='Critical').length;
  const high=FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='High').length;
  const med=FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='Medium').length;
  const low=FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='Low').length;
  const info=FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='Informational').length;
  const scopeNote=document.getElementById('scopeActiveNote');
  const scopeText = (scopeNote && scopeNote.style.display!=='none' && scopeNote.textContent) ? scopeNote.textContent : 'All subscriptions / all resource groups';

  let avgScoreHtml = 'Not available (no Summary CSV loaded)';
  if(SUMMARY_AVAILABLE && SUMMARY_ROWS.length){
    const avgScore = Math.round(SUMMARY_ROWS.reduce((s,r)=>s+parseFloat(r[SUMMARY_COLMAP.score]||0),0) / SUMMARY_ROWS.length);
    avgScoreHtml = avgScore + ' / 100';
  }

  const worstRowsHtml = (SUMMARY_AVAILABLE && SUMMARY_ROWS.length)
    ? [...SUMMARY_ROWS].sort((a,b)=>parseFloat(a[SUMMARY_COLMAP.score]||100)-parseFloat(b[SUMMARY_COLMAP.score]||100)).slice(0,5)
        .map(r=>`<div class="sm-row"><span>${escH(r[SUMMARY_COLMAP.nsg])}</span><span>${r[SUMMARY_COLMAP.score]} / 100</span></div>`).join('')
    : '<div class="sm-row"><span style="color:var(--muted)">Load a Summary CSV to see the worst-scoring NSGs</span><span></span></div>';

  document.getElementById('summarySheet').innerHTML = `
    <h2>Azure NSG Compliance — Executive Summary</h2>
    <div class="sm-sub">Findings source: ${escH(FINDINGS_SOURCE_LABEL)}${SUMMARY_AVAILABLE?' &nbsp;·&nbsp; Summary source: '+escH(SUMMARY_SOURCE_LABEL):''} &nbsp;·&nbsp; Scope: ${escH(scopeText)}</div>
    <div class="sm-grid">
      <div class="sm-cell"><div class="sm-val">${nsgCountForScope()}</div><div class="sm-lbl">NSGs</div></div>
      <div class="sm-cell"><div class="sm-val">${FINDINGS.length}</div><div class="sm-lbl">Findings</div></div>
      <div class="sm-cell"><div class="sm-val">${avgScoreHtml}</div><div class="sm-lbl">Avg Compliance Score</div></div>
      <div class="sm-cell"><div class="sm-val">${CONFLICTS.conflicts.length + CONFLICTS.duplicates.length}</div><div class="sm-lbl">Conflicts/Duplicates</div></div>
    </div>
    <div class="sm-section">
      <h4>Severity Breakdown</h4>
      <div class="sm-row"><span>🔴 Critical</span><span>${crit}</span></div>
      <div class="sm-row"><span>🟠 High</span><span>${high}</span></div>
      <div class="sm-row"><span>🔵 Medium</span><span>${med}</span></div>
      <div class="sm-row"><span>⚪ Low</span><span>${low}</span></div>
      <div class="sm-row"><span>⚪ Informational</span><span>${info}</span></div>
    </div>
    <div class="sm-section">
      <h4>Worst-Scoring NSGs</h4>
      ${worstRowsHtml}
    </div>
    <div class="sm-note">Findings and scores come directly from Test-AzureNSGCompliance.ps1's offline analysis; this dashboard only visualizes them and does not re-evaluate your NSGs. Generated __GENERATEDAT__.</div>`;
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

// ── Upload / drag-drop ──
function handleFindingsFileInput(e){
  const f=e.target.files && e.target.files[0];
  if(!f) return;
  readFindingsFileAndLoad(f);
}
function handleSummaryFileInput(e){
  const f=e.target.files && e.target.files[0];
  if(!f) return;
  readSummaryFileAndLoad(f);
}
function readFindingsFileAndLoad(f){
  const reader=new FileReader();
  reader.onload=ev=>loadFindings(ev.target.result, f.name, false);
  reader.onerror=()=>showToast('⚠ Could not read file');
  reader.readAsText(f);
}
function readSummaryFileAndLoad(f){
  const reader=new FileReader();
  reader.onload=ev=>loadSummary(ev.target.result, f.name);
  reader.onerror=()=>showToast('⚠ Could not read file');
  reader.readAsText(f);
}
document.addEventListener('dragover', e=>{ e.preventDefault(); });
document.addEventListener('drop', e=>{
  e.preventDefault();
  const f=e.dataTransfer.files && e.dataTransfer.files[0];
  if(!f){ return; }
  if(!f.name.toLowerCase().endsWith('.csv')){ showToast('⚠ Please drop a .csv file'); return; }
  const lname=f.name.toLowerCase();
  if(lname.includes('summary')) readSummaryFileAndLoad(f);
  else readFindingsFileAndLoad(f);
});

// ── Exports ──
function toCSVRows(rows){
  const cols=[FINDINGS_COLMAP.sub,FINDINGS_COLMAP.rg,FINDINGS_COLMAP.nsg,FINDINGS_COLMAP.ruleName,FINDINGS_COLMAP.direction,FINDINGS_COLMAP.priority,FINDINGS_COLMAP.category,FINDINGS_COLMAP.severity,FINDINGS_COLMAP.finding,FINDINGS_COLMAP.recommendation,FINDINGS_COLMAP.compliance,FINDINGS_COLMAP.related];
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const header=cols.join(',');
  const body=rows.map(r=>cols.map(c=>esc(r[c])).join(',')).join('\r\n');
  return header+'\r\n'+body;
}
function exportFindingsCSV(which){
  let data, name;
  if(which==='critHigh'){ data=FINDINGS.filter(r=>r[FINDINGS_COLMAP.severity]==='Critical'||r[FINDINGS_COLMAP.severity]==='High'); name='NSG_CriticalHighFindings.csv'; }
  else if(which==='filtered'){ data=filteredFindings; name='NSG_FilteredFindings.csv'; }
  else { data=FINDINGS; name='NSG_AllFindings.csv'; }
  if(!data.length){ showToast('Nothing to export in the current scope'); return; }
  dlFile(toCSVRows(data), name, 'text/csv');
  showToast('Exported '+data.length+' row(s)');
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
document.getElementById('dataNote').style.display = SUMMARY_AVAILABLE_INITIAL ? 'none' : 'block';
loadFindings(EMBEDDED_FINDINGS_CSV_TEXT, FINDINGS_SOURCE_LABEL, FINDINGS_IS_EMPTY_PLACEHOLDER);
if (SUMMARY_AVAILABLE_INITIAL) { loadSummary(EMBEDDED_SUMMARY_CSV_TEXT, SUMMARY_SOURCE_LABEL); }
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__FINDINGS_CSV_JSON__', $findingsJsonLiteral `
        -replace '__SUMMARY_CSV_JSON__', $summaryJsonLiteral `
        -replace '__FINDINGS_IS_EMPTY__', $findingsIsEmptyJs `
        -replace '__SUMMARY_AVAILABLE__', $summaryAvailableJs `
        -replace '__FINDINGSSOURCELABEL__', $findingsSourceLabel `
        -replace '__SUMMARYSOURCELABEL__', $summarySourceLabel `
        -replace '__GENERATEDAT__', $generatedAt

    #endregion

    #region ── Output ─────────────────────────────────────────────────────────────
    try
    {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force -ErrorAction Stop
    }
    catch
    {
        Write-Error "Failed to write dashboard to '$OutputPath': $($_.Exception.Message)"
        return
    }

    Write-Host ""
    Write-Host "╔═════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  ✅ Azure NSG Compliance Dashboard v1.0 — Generated!       ║" -ForegroundColor Cyan
    Write-Host "╚═════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  📋  Finding rows        : $findingsRowCount" -ForegroundColor White
    Write-Host "  🗂️  Summary rows        : $(if ($summaryAvailable) { $summaryRowCount } else { 'not loaded' })" -ForegroundColor $(if ($summaryAvailable) { 'White' } else { 'Yellow' })
    Write-Host "  📁  Output file         : $OutputPath" -ForegroundColor White
    Write-Host ""

    if ($OpenBrowser)
    {
        Write-Host "  🌐  Opening in browser…" -ForegroundColor Green
        Start-Process $OutputPath
    }
    #endregion
}
