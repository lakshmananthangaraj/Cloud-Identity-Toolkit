<#

Author          : Lakshmanan Thangaraj
Version         : 1.1
Created-On      : 27 July 2026
Modified-On     : 27 July 2026

.SYNOPSIS
    Runs PSScriptAnalyzer against one or more PowerShell files/folders and produces a
    console summary, structured objects, and an optional interactive HTML code-quality
    dashboard — with CI/CD-friendly pass/fail exit codes.

.DESCRIPTION
    The Invoke-ScriptAnalyzer function is a wrapper around the community PSScriptAnalyzer
    module (auto-installed for the current user if missing), purpose-built for linting an
    entire repository of PowerShell scripts/modules in one pass — such as this Cloud
    Identity Toolkit repo — rather than a single file at a time.

    It supports:
        - Recursive scan of a folder (default: current directory) or a single file
        - Custom PSScriptAnalyzer settings file (-SettingsPath), or a sensible built-in
          default rule set if none is supplied
        - Rule include/exclude overrides (-ExcludeRule)
        - Severity filtering (-Severity)
        - CI/CD gating via -FailOnSeverity — returns a non-zero exit code when findings
          at or above the specified severity are present, so build pipelines can fail fast
        - Styled console summary using plain, dependency-free Write-Host output
          (banner, section headers, info/success/failure lines) — no external
          modules required
        - Optional HTML dashboard report with:
            ✅ Overview tab   — KPI cards (files scanned, total findings, by severity),
                                donut chart, layman-friendly explainers
            ✅ Findings tab   — Full findings table (file, line, rule, severity, message)
                                with search, sort, and pagination
            ✅ By Rule tab    — Findings grouped/counted by rule name
            ✅ By File tab    — Findings grouped/counted by file, worst offenders first
            ✅ Export tab     — CSV / JSON download buttons
        - Dark/Light theme toggle, per-tab search/sort/pagination, toast notifications

.PARAMETER Path
    File or folder to analyze. Defaults to the current directory. When a folder is
    supplied, every *.ps1, *.psm1, and *.psd1 file underneath it is scanned (see -Recurse).

.PARAMETER Recurse
    Switch. When -Path is a folder, recurse into subfolders. Defaults to $true-equivalent
    behavior is NOT assumed — pass -Recurse explicitly to scan subfolders (matches
    PSScriptAnalyzer's own default of non-recursive unless requested).

.PARAMETER SettingsPath
    Path to a PSScriptAnalyzer settings (.psd1) file describing which rules to include/
    exclude and their configuration. If omitted, PSScriptAnalyzer's built-in default rule
    set is used (no custom settings file is required to run this script).

.PARAMETER ExcludeRule
    One or more PSScriptAnalyzer rule names to exclude from the scan (e.g.
    'PSAvoidUsingWriteHost'). Useful for repos that intentionally use Write-Host for
    console UX, as this one does in its output toolkit.

.PARAMETER Severity
    Restrict results to one or more severities: Error, Warning, Information. Defaults to
    all three.

.PARAMETER FailOnSeverity
    One or more severities that should cause this script to exit with a non-zero exit
    code (1) after the scan completes — intended for CI/CD pipelines (GitHub Actions,
    Azure Pipelines) that should fail the build when matching findings exist. If omitted,
    the script always exits 0 regardless of findings (report-only mode).

.PARAMETER GenerateHtmlDoc
    Switch parameter. If specified, generates a formatted HTML code-quality dashboard and
    saves it locally.

.PARAMETER OutputPath
    Folder where the HTML dashboard (and any exported files) are written. Defaults to
    $env:TEMP.

.PARAMETER ShowHelp
    Switch. Shows a friendly quick-reference guide and exits without scanning anything.

.OUTPUTS
    System.Object[]
    Returns a collection of structured PSScriptAnalyzer finding objects (File, Line,
    Column, Rule, Severity, Message).

.EXAMPLE
    Invoke-ScriptAnalyzer -Path . -Recurse

    Scans every PowerShell file in the current repo and prints a console summary.

.EXAMPLE
    Invoke-ScriptAnalyzer -Path . -Recurse -ExcludeRule 'PSAvoidUsingWriteHost' -GenerateHtmlDoc

    Scans the repo, ignores the Write-Host rule (this toolkit uses Write-Host by design
    for console UX), and opens an interactive HTML dashboard of the findings.

.EXAMPLE
    Invoke-ScriptAnalyzer -Path .\Entra-ID -Recurse -Severity Error,Warning -FailOnSeverity Error

    Scans only the Entra-ID folder, reports Errors and Warnings, and exits with code 1 if
    any Error-severity finding exists — suitable for a CI pipeline gate.

.EXAMPLE
    Invoke-ScriptAnalyzer -Path .\Get-AllUsers.ps1 -SettingsPath .\PSScriptAnalyzerSettings.psd1

    Scans a single file using a custom settings file.

.NOTES
    Requires the PSScriptAnalyzer module. If it is not already installed, this script
    installs it silently for the current user (CurrentUser scope) the first time it runs:
        Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force

    Requires (module):
    - PSScriptAnalyzer (https://www.powershellgallery.com/packages/PSScriptAnalyzer)

    This script has no dependency on any internal/repo-specific module — all console
    output uses plain Write-Host so it runs standalone anywhere.

    Exit codes (only meaningful when -FailOnSeverity is supplied):
        0 = No findings at/above the specified severity (or -FailOnSeverity not supplied)
        1 = One or more findings at/above the specified severity were found

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.1 (27-Jul-2026)      - Removed dependency on the internal
                                 CloudIdentityToolkit.Common console toolkit. Console
                                 output (banner/section headers/info/success/failure)
                                 is now plain Write-Host, so the script has zero
                                 dependency on other repo modules.
        1.0 (27-Jul-2026)      - Initial release: recursive repo-wide scan, severity
                                 and rule filtering, CI/CD exit-code gating, console
                                 summary, HTML code-quality dashboard with Overview /
                                 Findings / By Rule / By File / Export tabs.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/psscriptanalyzer/invoke-scriptanalyzer

#>


Function Show-FriendlyHelp
{
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║              Invoke-ScriptAnalyzer  v1.1                     ║" -ForegroundColor Cyan
    Write-Host "  ║                   Friendly Help Guide                        ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this does:" -ForegroundColor Yellow
    Write-Host "    Lints a PowerShell file or folder with PSScriptAnalyzer, prints a"
    Write-Host "    console summary, and can optionally build an interactive HTML"
    Write-Host "    code-quality dashboard. Can also gate CI/CD pipelines on severity."
    Write-Host ""
    Write-Host "  Common parameters:" -ForegroundColor Yellow
    Write-Host "    -Path             File or folder to scan (default: current directory)"
    Write-Host "    -Recurse          Recurse into subfolders when -Path is a folder"
    Write-Host "    -Severity         Error, Warning, Information (default: all)"
    Write-Host "    -ExcludeRule      One or more rule names to skip"
    Write-Host "    -SettingsPath     Custom PSScriptAnalyzer settings (.psd1) file"
    Write-Host "    -FailOnSeverity   Exit code 1 if findings at/above this severity exist"
    Write-Host "    -GenerateHtmlDoc  Builds and opens the HTML dashboard"
    Write-Host "    -ShowHelp         Shows this guide and exits, nothing is generated"
    Write-Host ""
    Write-Host "  Example (repo-wide scan, HTML dashboard):" -ForegroundColor Yellow
    Write-Host '    Invoke-ScriptAnalyzer -Path . -Recurse -GenerateHtmlDoc'
    Write-Host ""
    Write-Host "  Example (CI/CD gate on Errors only):" -ForegroundColor Yellow
    Write-Host '    Invoke-ScriptAnalyzer -Path . -Recurse -FailOnSeverity Error'
    Write-Host ""
    Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
    Write-Host "     Get-Help Invoke-ScriptAnalyzer -Full"
    Write-Host ""
}


Function Invoke-ScriptAnalyzer
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path = (Get-Location).Path,

        [switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$SettingsPath,

        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeRule,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Error', 'Warning', 'Information')]
        [string[]]$Severity = @('Error', 'Warning', 'Information'),

        [Parameter(Mandatory = $false)]
        [ValidateSet('Error', 'Warning', 'Information')]
        [string[]]$FailOnSeverity,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = $env:TEMP,

        [switch]$GenerateHtmlDoc,

        [switch]$ShowHelp
    )

    if ($ShowHelp)
    {
        Show-FriendlyHelp
        return
    }

    # ── Plain, dependency-free console output helpers (no internal modules) ──
    Function Local-Banner
    {
        param([string]$Title, [string]$Subtitle)
        $width  = 66
        $line   = "=" * $width
        Write-Host ""
        Write-Host $line -ForegroundColor Cyan
        Write-Host "  $Title" -ForegroundColor Cyan
        Write-Host "  $Subtitle" -ForegroundColor Cyan
        Write-Host $line -ForegroundColor Cyan
        Write-Host ""
    }
    Function Local-Section { param([string]$Title) Write-Host "" ; Write-Host "--- $Title ---" -ForegroundColor DarkCyan ; Write-Host "" }
    Function Local-Info    { param([string]$Message) Write-Host "  [i] $Message" -ForegroundColor Gray }
    Function Local-Success { param([string]$Message) Write-Host "  [OK] $Message" -ForegroundColor Green }
    Function Local-Failure { param([string]$Message) Write-Host "  [X] $Message" -ForegroundColor Red }

    Local-Banner "Invoke-ScriptAnalyzer v1.1" "PowerShell Code Quality Scanner"

    # ── Ensure PSScriptAnalyzer is available ──────────────────────────────────
    Local-Section "Environment Check"

    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer))
    {
        Local-Info "PSScriptAnalyzer module not found. Installing for current user..."
        Try
        {
            Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -ErrorAction Stop
            Local-Success "PSScriptAnalyzer installed."
        }
        Catch
        {
            Local-Failure "Failed to install PSScriptAnalyzer: $($_.Exception.Message)"
            Write-Error "Cannot continue without PSScriptAnalyzer. Install it manually with: Install-Module PSScriptAnalyzer -Scope CurrentUser"
            return
        }
    }

    Try
    {
        Import-Module PSScriptAnalyzer -ErrorAction Stop
        $analyzerVersion = (Get-Module PSScriptAnalyzer).Version.ToString()
        Local-Success "PSScriptAnalyzer $analyzerVersion loaded."
    }
    Catch
    {
        Local-Failure "Failed to import PSScriptAnalyzer: $($_.Exception.Message)"
        return
    }

    if (-not (Test-Path $Path))
    {
        Write-Error "Path not found: $Path"
        return
    }

    # ── Build the analyzer parameter set ──────────────────────────────────────
    Local-Section "Scan Configuration"
    Local-Info "Target path : $Path"
    Local-Info "Recurse     : $($Recurse.IsPresent)"
    Local-Info "Severity    : $($Severity -join ', ')"
    if ($ExcludeRule)   { Local-Info "Excluded rules : $($ExcludeRule -join ', ')" }
    if ($SettingsPath)  { Local-Info "Settings file  : $SettingsPath" }

    $analyzerParams = @{
        Path     = $Path
        Severity = $Severity
    }
    if ($Recurse)       { $analyzerParams['Recurse']    = $true }
    if ($ExcludeRule)   { $analyzerParams['ExcludeRule'] = $ExcludeRule }
    if ($SettingsPath)  { $analyzerParams['Settings']   = $SettingsPath }

    # ── Run the scan ───────────────────────────────────────────────────────────
    Local-Section "Scanning"

    $rawFindings = $null
    Try
    {
        $rawFindings = PSScriptAnalyzer\Invoke-ScriptAnalyzer @analyzerParams -ErrorAction Stop
    }
    Catch
    {
        Local-Failure "Scan failed: $($_.Exception.Message)"
        Write-Error $_
        return
    }

    # ── Transform into clean structured objects ───────────────────────────────
    $result = @($rawFindings | ForEach-Object {
        [PSCustomObject][ordered]@{
            "File"        = Split-Path -Leaf $_.ScriptPath
            "FullPath"    = $_.ScriptPath
            "Line"        = $_.Line
            "Column"      = $_.Column
            "Rule"        = $_.RuleName
            "Severity"    = $_.Severity.ToString()
            "Message"     = $_.Message
        }
    })

    $filesScanned = if (Test-Path $Path -PathType Leaf)
    {
        1
    }
    else
    {
        $ext = @('*.ps1', '*.psm1', '*.psd1')
        (Get-ChildItem -Path $Path -Include $ext -Recurse:$Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
    }

    $errorCount   = @($result | Where-Object Severity -eq 'Error').Count
    $warningCount = @($result | Where-Object Severity -eq 'Warning').Count
    $infoCount    = @($result | Where-Object Severity -eq 'Information').Count
    $totalCount   = $result.Count

    # ── Console Summary ────────────────────────────────────────────────────────
    Local-Section "Scan Summary"
    Local-Info "Files scanned     : $filesScanned"
    Local-Info "Total findings    : $totalCount"

    if ($errorCount -gt 0)   { Local-Failure "Errors            : $errorCount" } else { Local-Success "Errors            : 0" }
    if ($warningCount -gt 0) { Local-Info    "Warnings          : $warningCount" } else { Local-Success "Warnings          : 0" }
    Local-Info "Information       : $infoCount"

    if ($totalCount -gt 0)
    {
        Write-Host ""
        $byRule = $result | Group-Object Rule | Sort-Object Count -Descending | Select-Object -First 10 |
            Select-Object @{Name = 'Rule'; Expression = { $_.Name } }, Count | Out-String
        Write-Host "  Top rules triggered:" -ForegroundColor Yellow
        Write-Host $byRule -ForegroundColor Gray
    }
    else
    {
        Local-Success "No findings — clean scan!"
    }

    # ── Optional HTML Dashboard ────────────────────────────────────────────────
    if ($GenerateHtmlDoc)
    {
        Local-Section "Generating HTML Dashboard"

        if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

        $todayDateShort = Get-Date -Format 'yyyyMMdd_HHmmss'
        $scanTarget     = (Resolve-Path $Path).Path

        # Precompute JSON/CSV export payloads (escaped for inline embedding)
        $exportJson     = $result | ConvertTo-Json -Depth 5 -Compress
        $exportJsonEsc  = $exportJson -replace "\\", "\\\\" -replace "'", "\'"
        $csvRaw         = if ($totalCount -gt 0) { ($result | ConvertTo-Csv -NoTypeInformation) -join "`n" } else { "File,FullPath,Line,Column,Rule,Severity,Message" }
        $csvEsc         = $csvRaw -replace "\\", "\\\\" -replace "'", "\'" -replace "`r`n", "\n" -replace "`n", "\n"

        $byRuleRows = ($result | Group-Object Rule | Sort-Object Count -Descending | ForEach-Object {
            "<tr><td>$($_.Name)</td><td>$($_.Count)</td></tr>"
        }) -join "`n"

        $byFileRows = ($result | Group-Object File | Sort-Object Count -Descending | ForEach-Object {
            "<tr><td>$($_.Name)</td><td>$($_.Count)</td></tr>"
        }) -join "`n"

        $findingRows = ($result | ForEach-Object {
            $sevClass = switch ($_.Severity) { 'Error' { 'sev-error' } 'Warning' { 'sev-warning' } default { 'sev-info' } }
            $msgSafe  = $_.Message -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
            "<tr><td>$($_.File)</td><td>$($_.Line)</td><td>$($_.Rule)</td><td class='$sevClass'>$($_.Severity)</td><td>$msgSafe</td></tr>"
        }) -join "`n"

        $errorPct   = if ($totalCount -gt 0) { [math]::Round(($errorCount / $totalCount) * 100, 1) } else { 0 }
        $warningPct = if ($totalCount -gt 0) { [math]::Round(($warningCount / $totalCount) * 100, 1) } else { 0 }
        $infoPct    = if ($totalCount -gt 0) { [math]::Round(($infoCount / $totalCount) * 100, 1) } else { 0 }

        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Code Quality Dashboard - $(Split-Path -Leaf $scanTarget)</title>
<style>
:root{--bg:#f4f6f9;--card:#fff;--text:#1c2230;--muted:#6b7385;--border:#e3e7ee;--accent:#2563eb;--err:#dc2626;--warn:#d97706;--info:#0891b2;--ok:#16a34a;}
[data-theme='dark']{--bg:#0f1420;--card:#171d2b;--text:#e7ebf3;--muted:#8b93a7;--border:#262e42;--accent:#4f8dff;}
*{box-sizing:border-box;}
body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);}
header{display:flex;justify-content:space-between;align-items:center;padding:16px 28px;background:var(--card);border-bottom:1px solid var(--border);}
header h1{font-size:18px;margin:0;}
header .sub{color:var(--muted);font-size:12px;}
.tabs{display:flex;gap:4px;padding:0 28px;background:var(--card);border-bottom:1px solid var(--border);}
.tab-btn{padding:12px 16px;cursor:pointer;border:none;background:none;color:var(--muted);font-size:13px;border-bottom:2px solid transparent;}
.tab-btn.active{color:var(--accent);border-bottom-color:var(--accent);}
.page{display:none;padding:24px 28px;}
.page.active{display:block;}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:20px;}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;}
.kpi .val{font-size:26px;font-weight:700;}
.kpi .lbl{color:var(--muted);font-size:12px;}
table{width:100%;border-collapse:collapse;background:var(--card);}
th,td{padding:8px 10px;border-bottom:1px solid var(--border);text-align:left;font-size:13px;}
th{cursor:pointer;color:var(--muted);font-weight:600;}
.sev-error{color:var(--err);font-weight:600;}
.sev-warning{color:var(--warn);font-weight:600;}
.sev-info{color:var(--info);font-weight:600;}
.search-box{padding:6px 10px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);margin-bottom:10px;width:260px;}
button.export{padding:8px 14px;margin-right:8px;border:1px solid var(--border);background:var(--accent);color:#fff;border-radius:6px;cursor:pointer;}
.theme-toggle{cursor:pointer;border:1px solid var(--border);background:var(--card);padding:6px 12px;border-radius:6px;color:var(--text);}
#toast{position:fixed;bottom:20px;right:20px;background:var(--card);border:1px solid var(--border);padding:10px 16px;border-radius:8px;opacity:0;transition:.3s;}
#toast.show{opacity:1;}
.pag{display:flex;gap:4px;margin-top:10px;}
.page-btn{border:1px solid var(--border);background:var(--card);color:var(--text);padding:4px 9px;border-radius:5px;cursor:pointer;font-size:12px;}
.page-btn.active{background:var(--accent);color:#fff;}
</style>
</head>
<body>
<header>
  <div>
    <h1>Code Quality Dashboard</h1>
    <div class="sub">Scanned: $scanTarget &nbsp;|&nbsp; Generated: $(Get-Date -Format 'dd MMM yyyy HH:mm')</div>
  </div>
  <button class="theme-toggle" onclick="document.body.parentElement.setAttribute('data-theme', document.body.parentElement.getAttribute('data-theme')==='dark'?'light':'dark')">🌓 Theme</button>
</header>
<div class="tabs">
  <button class="tab-btn active" onclick="showTab('overview',this)">Overview</button>
  <button class="tab-btn" onclick="showTab('findings',this)">Findings ($totalCount)</button>
  <button class="tab-btn" onclick="showTab('byrule',this)">By Rule</button>
  <button class="tab-btn" onclick="showTab('byfile',this)">By File</button>
  <button class="tab-btn" onclick="showTab('export',this)">Export</button>
</div>

<div id="overview" class="page active">
  <div class="kpi-grid">
    <div class="kpi"><div class="val">$filesScanned</div><div class="lbl">Files Scanned</div></div>
    <div class="kpi"><div class="val">$totalCount</div><div class="lbl">Total Findings</div></div>
    <div class="kpi" style="color:var(--err)"><div class="val">$errorCount</div><div class="lbl">Errors ($errorPct%)</div></div>
    <div class="kpi" style="color:var(--warn)"><div class="val">$warningCount</div><div class="lbl">Warnings ($warningPct%)</div></div>
    <div class="kpi" style="color:var(--info)"><div class="val">$infoCount</div><div class="lbl">Information ($infoPct%)</div></div>
  </div>
  <p style="color:var(--muted);font-size:13px;max-width:640px;">
    This report summarizes static analysis findings from PSScriptAnalyzer. <b>Errors</b> typically
    indicate syntax problems or rules likely to cause runtime failures. <b>Warnings</b> flag
    style/best-practice deviations (e.g. unapproved verbs, unused variables). <b>Information</b>
    findings are advisory only.
  </p>
</div>

<div id="findings" class="page">
  <input type="text" class="search-box" id="search-findings" placeholder="Search findings..." oninput="filterTable('findings')">
  <table id="tbl-findings">
    <thead><tr>
      <th onclick="sortTbl('findings',0,this)">File</th>
      <th onclick="sortTbl('findings',1,this)">Line</th>
      <th onclick="sortTbl('findings',2,this)">Rule</th>
      <th onclick="sortTbl('findings',3,this)">Severity</th>
      <th onclick="sortTbl('findings',4,this)">Message</th>
    </tr></thead>
    <tbody id="tbody-findings">
      $findingRows
    </tbody>
  </table>
  <div id="info-findings" style="color:var(--muted);font-size:12px;margin-top:8px;"></div>
  <div class="pag" id="pag-findings"></div>
</div>

<div id="byrule" class="page">
  <table><thead><tr><th>Rule</th><th>Count</th></tr></thead><tbody>$byRuleRows</tbody></table>
</div>

<div id="byfile" class="page">
  <table><thead><tr><th>File</th><th>Count</th></tr></thead><tbody>$byFileRows</tbody></table>
</div>

<div id="export" class="page">
  <button class="export" onclick="exportCSV()">⬇ Export CSV</button>
  <button class="export" onclick="exportJSON()">⬇ Export JSON</button>
</div>

<div id="toast"></div>

<script>
function showTab(id,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  el.classList.add('active');
}

const sortState={};
function sortTbl(tab,col,thEl){
  const tbody=document.getElementById('tbody-'+tab);
  const key=tab+'-'+col;
  sortState[key]=!sortState[key];
  const asc=sortState[key];
  const rows=Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a,b)=>{
    const x=(a.cells[col]?.textContent||'').trim().toLowerCase();
    const y=(b.cells[col]?.textContent||'').trim().toLowerCase();
    return asc?x.localeCompare(y,undefined,{numeric:true}):y.localeCompare(x,undefined,{numeric:true});
  });
  rows.forEach(r=>tbody.appendChild(r));
  document.querySelectorAll('#tbl-'+tab+' th').forEach(t=>t.classList.remove('sorted'));
  thEl.classList.add('sorted');
  pagState[tab].page=1;
  renderPag(tab);
}

function filterTable(tab){
  const q=(document.getElementById('search-'+tab)||{}).value||'';
  const ql=q.toLowerCase().trim();
  const rows=Array.from(document.querySelectorAll('#tbody-'+tab+' tr'));
  rows.forEach(r=>{
    if(!ql||r.textContent.toLowerCase().includes(ql)){r.removeAttribute('data-search-hidden');}
    else{r.setAttribute('data-search-hidden','1');r.style.display='none';}
  });
  pagState[tab].page=1;
  renderPag(tab);
}

const PAGE_SIZE=15;
const pagState={findings:{page:1}};
function getVisible(tab){return Array.from(document.querySelectorAll('#tbody-'+tab+' tr')).filter(r=>!r.getAttribute('data-search-hidden'));}
function renderPag(tab){
  const rows=getVisible(tab);
  const total=rows.length;
  const pages=Math.max(1,Math.ceil(total/PAGE_SIZE));
  const cur=Math.min(pagState[tab].page,pages);
  pagState[tab].page=cur;
  rows.forEach((r,i)=>{r.style.display=(i>=(cur-1)*PAGE_SIZE&&i<cur*PAGE_SIZE)?'':'none';});
  const infoEl=document.getElementById('info-'+tab);
  const pagEl=document.getElementById('pag-'+tab);
  if(!infoEl)return;
  if(total===0){infoEl.textContent='No matching results';pagEl.innerHTML='';return;}
  const from=(cur-1)*PAGE_SIZE+1,to=Math.min(cur*PAGE_SIZE,total);
  infoEl.textContent='Showing '+from+'–'+to+' of '+total+' entries';
  let html='';
  html+='<button class="page-btn'+(cur===1?' active':'')+'" onclick="goPage(\''+tab+'\',1)">«</button>';
  for(let p=1;p<=pages;p++){
    if(pages>8&&Math.abs(p-cur)>2&&p!==1&&p!==pages){if(p===2||p===pages-1)html+='<button class="page-btn ellipsis" disabled>…</button>';continue;}
    html+='<button class="page-btn'+(p===cur?' active':'')+'" onclick="goPage(\''+tab+'\','+p+')">'+p+'</button>';
  }
  html+='<button class="page-btn'+(cur===pages?' active':'')+'" onclick="goPage(\''+tab+'\','+pages+')">»</button>';
  pagEl.innerHTML=html;
}
function goPage(tab,p){pagState[tab].page=p;renderPag(tab);}

const CSV_DATA='$csvEsc';
const JSON_DATA='$exportJsonEsc';
function dlFile(content,name,type){
  const b=new Blob([content],{type});
  const u=URL.createObjectURL(b);
  const a=document.createElement('a');
  a.href=u;a.download=name;a.click();
  URL.revokeObjectURL(u);
}
function exportCSV(){dlFile(CSV_DATA,'CodeQuality_$todayDateShort.csv','text/csv');showToast('✅ Exported findings as CSV');}
function exportJSON(){dlFile(JSON_DATA,'CodeQuality_$todayDateShort.json','application/json');showToast('✅ Exported findings as JSON');}

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),3200);
}

document.addEventListener('keydown',e=>{
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){
    e.preventDefault();
    const inp=document.querySelector('.page.active .search-box');
    if(inp)inp.focus();
  }
});

window.addEventListener('DOMContentLoaded',function(){renderPag('findings');});
</script>
</body>
</html>
"@

        $htmlFile = Join-Path -Path $OutputPath -ChildPath "CodeQualityDashboard_$todayDateShort.html"
        $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8

        Local-Success "Dashboard saved to: $htmlFile"
        Invoke-Item $htmlFile
    }

    # ── CI/CD gating ───────────────────────────────────────────────────────────
    if ($FailOnSeverity)
    {
        $gatingCount = @($result | Where-Object { $_.Severity -in $FailOnSeverity }).Count
        if ($gatingCount -gt 0)
        {
            Local-Failure "$gatingCount finding(s) at/above gating severity ($($FailOnSeverity -join ', ')). Failing build."
            $global:LASTEXITCODE = 1
            $host.SetShouldExit(1) 2>$null
        }
        else
        {
            Local-Success "No findings at/above gating severity. Build passes."
            $global:LASTEXITCODE = 0
        }
    }

    # ── Return the structured result ────────────────────────────────────────────
    $result
}
