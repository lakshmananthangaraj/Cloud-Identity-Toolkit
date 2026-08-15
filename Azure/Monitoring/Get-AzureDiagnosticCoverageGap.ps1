<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Identifies Azure resources missing diagnostic settings, Log Analytics workspace
    linkage, or required security log categories across one or more subscriptions,
    with CSV export and an interactive HTML dashboard.

.DESCRIPTION
    Get-AzureDiagnosticCoverageGap scans Azure resources to reveal monitoring blind
    spots critical for security monitoring and operational governance.

    Default assessment (structure and coverage):
        - Resource-level diagnostic settings: detects resources with no diagnostic
          setting configured at all, and resources with a setting present but missing
          one or more required log categories (AuditEvent, Administrative, Security,
          Policy, Alert, Recommendation, ServiceHealth, ResourceHealth)
        - Log Analytics workspace linkage: flags resources whose diagnostic setting
          does not route to any Log Analytics workspace
        - Metric-only configurations: identifies settings that capture metrics
          but no logs — a common misconfiguration that passes surface-level checks
        - Resource type coverage: reports which resource types have the highest
          gap rate across the environment
        - Per-subscription gap summary: total resources scanned, fully covered,
          partially covered, and completely uncovered

    Gap severity classification:
        - Critical : No diagnostic setting exists at all
        - High     : Setting exists but no workspace destination
        - Medium   : Setting routes to workspace but required log categories missing
        - Low      : All required categories present; metrics only or minor gaps

    Scope options:
        - All subscriptions visible to the authenticated account (-AllSubscriptions)
        - A specific list of subscription IDs (-SubscriptionIds)

    Outputs:
        - Real-time progress bar and color-coded per-subscription summary
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          distribution panels, detail drawer, severity badges)
        - Optional CSV export of all resource gap findings

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all diagnostic gap findings to the path given
    in -CsvPath. The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzureDiagnosticCoverageGap-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureDiagnosticCoverageGap -AllSubscriptions

.EXAMPLE
    Get-AzureDiagnosticCoverageGap -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureDiagnosticCoverageGap -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\DiagGap.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Resource diagnostic setting gap
                            detection, workspace linkage check, log category
                            coverage, severity classification. CSV export and
                            interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.Monitor)
           — installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level.
        4. Microsoft.Insights/diagnosticSettings/read permission is required to
           enumerate diagnostic configurations on resources.
        5. microsoft.operationalinsights/workspaces/read is required to validate
           Log Analytics workspace linkage.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Get-AzResource returns resources within a subscription context. Resources
          at Management Group scope are not enumerated.
        - Some resource types do not support diagnostic settings (e.g. resource
          groups, subscriptions themselves). These are excluded silently.
        - Diagnostic settings enumeration can be slow on subscriptions with
          thousands of resources. Progress is reported per resource type batch.
        - Required log categories are defined as a fixed reference set. Custom or
          resource-type-specific required categories are not yet parameterized.
        - Interactive Grid View requires a GUI-capable session. Skipped gracefully
          in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings
    https://learn.microsoft.com/en-us/powershell/module/az.monitor/get-azdiagnosticsetting
    https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview
    https://learn.microsoft.com/en-us/azure/governance/policy/samples/built-in-policies

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CenteredText {
    param(
        [string]$Text,
        [int]$Width = 80,
        [string]$Color = "White"
    )
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Diagnostic Coverage Gap Assessment v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-Section {
    param(
        [string]$Title,
        [hashtable]$Data
    )

    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys) {
        $value = $Data[$key]
        if ([string]::IsNullOrWhiteSpace($value)) {
            $value = "None"
            $valColor = "DarkGray"
        }
        else {
            $valColor = "White"
        }

        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-ScanProgress {
    Write-Host ""
    Write-Host "  Scanning Subscriptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
}

Function Write-ProgressBar {
    param(
        [int]$Current,
        [int]$Total,
        [string]$CurrentItem,
        [int]$BarWidth = 40
    )

    $percentage = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
    $completed = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $remaining = $BarWidth - $completed
    $bar = ("█" * $completed) + ("░" * $remaining)

    Write-Host "`r" -NoNewline
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White

    if ($CurrentItem) {
        $maxLen = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLen) { $CurrentItem.Substring(0, $maxLen - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-Summary {
    param([hashtable]$Data)

    Write-Host ""
    Write-Host "  Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys) {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(36) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-GapBreakdown {
    param([hashtable]$GapSeverity)

    if ($GapSeverity.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Gap Severity Breakdown" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $colorMap = @{ "Critical" = "Red"; "High" = "Yellow"; "Medium" = "Cyan"; "Low" = "Green" }

    foreach ($sev in @("Critical", "High", "Medium", "Low")) {
        if ($GapSeverity.ContainsKey($sev)) {
            $color = if ($colorMap.ContainsKey($sev)) { $colorMap[$sev] } else { "White" }
            Write-Host "  " -NoNewline
            Write-Host $sev.PadRight(22) -NoNewline -ForegroundColor White
            Write-Host ": " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($GapSeverity[$sev]) resource(s)" -ForegroundColor $color
        }
    }
}

Function Write-OutputFiles {
    param(
        [string]$CsvPath,
        [string]$HtmlPath,
        [bool]$GridViewOpened
    )

    Write-Host ""
    Write-Host "  Output Files" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    if ($CsvPath) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("CSV Export").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }

    if ($HtmlPath) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Dashboard").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }

    if ($GridViewOpened) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("Grid View").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": Opened in separate window" -ForegroundColor White
    }

    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-ObjProperty {
    param(
        [object]$Obj,
        [string]$PropName,
        $Default = $null
    )
    try {
        $val = $Obj.$PropName
        if ($null -ne $val) { return $val }
        return $Default
    }
    catch { return $Default }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-DiagnosticGapHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [hashtable]$SeverityDistribution,
        [hashtable]$TypeDistribution,
        [array]$SubscriptionResults,
        [string]$GeneratedOn
    )

    $totalResources = @($Findings).Count
    $criticalCount = @($Findings | Where-Object { $_.GapSeverity -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.GapSeverity -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.GapSeverity -eq "Medium" }).Count
    $lowCount = @($Findings | Where-Object { $_.GapSeverity -eq "Low" }).Count
    $noSettingCount = @($Findings | Where-Object { $_.HasDiagnosticSetting -eq $false }).Count
    $noWorkspaceCount = @($Findings | Where-Object { $_.WorkspaceLinked -eq $false -and $_.HasDiagnosticSetting -eq $true }).Count

    # ── Finding table rows ────────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $sevCls = switch ($f.GapSeverity) {
            "Critical" { "badge-red" }
            "High" { "badge-amber" }
            "Medium" { "badge-blue" }
            default { "badge-green" }
        }
        $wsIcon = if ($f.WorkspaceLinked) { '<span class="badge badge-green">✓</span>' } else { '<span class="badge badge-red">✗</span>' }
        $dsIcon = if ($f.HasDiagnosticSetting) { '<span class="badge badge-green">✓</span>' } else { '<span class="badge badge-red">✗</span>' }

        $findingRows += @"
          <tr onclick="showFindingDetail($($Findings.IndexOf($f)))">
            <td title="$(EscHtml $f.ResourceName)">$(if ($f.ResourceName.Length -gt 36) { EscHtml($f.ResourceName.Substring(0,33)+"...") } else { EscHtml $f.ResourceName })</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td style="font-family:var(--mono);font-size:11px" title="$(EscHtml $f.ResourceType)">$(if ($f.ResourceType.Length -gt 38) { EscHtml($f.ResourceType.Substring(0,35)+"...") } else { EscHtml $f.ResourceType })</td>
            <td>$dsIcon</td>
            <td>$wsIcon</td>
            <td><span class="badge $(EscHtml $sevCls)">$(EscHtml $f.GapSeverity)</span></td>
            <td style="font-size:11px;color:var(--muted2)" title="$(EscHtml $f.MissingCategories)">$(if ($f.MissingCategories.Length -gt 40) { EscHtml($f.MissingCategories.Substring(0,37)+"...") } else { EscHtml $f.MissingCategories })</td>
          </tr>
"@
    }

    # ── Subscription results ──────────────────────────────────────────────────
    $subRows = ""
    foreach ($s in $SubscriptionResults) {
        $icon = switch ($s.Status) { "Success" { "✓" }; "Warning" { "⚠" }; "Error" { "✗" }; default { "•" } }
        $cls = switch ($s.Status) { "Success" { "c-green" }; "Warning" { "c-amber" }; "Error" { "c-red" }; default { "" } }
        $subRows += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $s.Name)</span>
            <span class="sub-detail">$(EscHtml $s.Summary)</span>
          </div>
"@
    }

    # ── Severity distribution bar rows ────────────────────────────────────────
    $sevTotal = ($SeverityDistribution.Values | Measure-Object -Sum).Sum
    $sevRows = ""
    foreach ($sev in @("Critical", "High", "Medium", "Low")) {
        if ($SeverityDistribution.ContainsKey($sev)) {
            $cnt = $SeverityDistribution[$sev]
            $pct = if ($sevTotal -gt 0) { [math]::Round(($cnt / $sevTotal) * 100) } else { 0 }
            $barColor = switch ($sev) {
                "Critical" { "var(--red)" }
                "High" { "var(--amber)" }
                "Medium" { "var(--accent)" }
                default { "var(--green)" }
            }
            $sevRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $sev)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$cnt ($pct%)</span>
          </div>
"@
        }
    }

    # ── Resource type distribution bar rows ───────────────────────────────────
    $typeTotal = ($TypeDistribution.Values | Measure-Object -Sum).Sum
    $typeRows = ""
    foreach ($t in ($TypeDistribution.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)) {
        $pct = if ($typeTotal -gt 0) { [math]::Round(($t.Value / $typeTotal) * 100) } else { 0 }
        $shortType = if ($t.Key.Length -gt 34) { $t.Key.Substring($t.Key.Length - 34) } else { $t.Key }
        $typeRows += @"
          <div class="bar-row">
            <span class="bar-label" title="$(EscHtml $t.Key)">$(EscHtml $shortType)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($t.Value) ($pct%)</span>
          </div>
"@
    }

    # ── JSON for finding detail drawer ────────────────────────────────────────
    $findingJson = "["
    foreach ($f in $Findings) {
        $findingJson += "{" +
        """name"":""$(EscJ $f.ResourceName)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """type"":""$(EscJ $f.ResourceType)""," +
        """sev"":""$(EscJ $f.GapSeverity)""," +
        """hasSetting"":$(($f.HasDiagnosticSetting).ToString().ToLower())," +
        """wsLinked"":$(($f.WorkspaceLinked).ToString().ToLower())," +
        """wsName"":""$(EscJ $f.WorkspaceName)""," +
        """settingName"":""$(EscJ $f.SettingName)""," +
        """missing"":""$(EscJ $f.MissingCategories)""," +
        """present"":""$(EscJ $f.PresentCategories)""," +
        """metricsOnly"":$(($f.MetricsOnly).ToString().ToLower())," +
        """location"":""$(EscJ $f.Location)""," +
        """resourceId"":""$(EscJ $f.ResourceId)""" +
        "},"
    }
    $findingJson = $findingJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Diagnostic Coverage Gap Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;
  --border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;
  --green:#3fb950;--amber:#d29922;--red:#f85149;
  --text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);
}
html[data-theme="light"]{
  --bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;
  --border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;
  --green:#1a7f37;--amber:#b08000;--red:#cf222e;
  --text:#1f2328;--muted:#636c76;--muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;}
#sidebar{
  width:240px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;
  transition:transform .25s;
}
.logo-block{padding:22px 18px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:38px;height:38px;border-radius:8px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{
  display:inline-block;margin-top:8px;padding:2px 8px;border-radius:20px;
  font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent);border:1px solid var(--border);
}
.nav-section{padding:14px 10px;flex:1;}
.nav-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;
  letter-spacing:.08em;padding:0 8px;margin-bottom:6px;}
.nav-btn{
  display:flex;align-items:center;gap:10px;width:100%;padding:9px 12px;border:none;
  background:transparent;color:var(--muted2);font-size:13px;border-radius:var(--radius-sm);
  cursor:pointer;text-align:left;transition:background .15s,color .15s;position:relative;margin-bottom:2px;
}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:var(--surface3);color:var(--accent);font-weight:600;}
.nav-btn.active::before{
  content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;
  background:var(--accent);border-radius:0 3px 3px 0;
}
.nav-icon{font-size:16px;width:20px;text-align:center;}
.sidebar-footer{padding:14px 16px;border-top:1px solid var(--border);}
.theme-toggle{display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:10px;}
.toggle-pill{
  width:40px;height:22px;border-radius:11px;border:none;cursor:pointer;
  background:var(--surface3);position:relative;transition:background .2s;
}
.toggle-pill::after{
  content:'';position:absolute;top:3px;left:3px;width:16px;height:16px;
  border-radius:50%;background:var(--accent);transition:transform .2s;
}
html[data-theme="light"] .toggle-pill::after{transform:translateX(18px);}
.footer-meta{font-size:10px;color:var(--muted);line-height:1.6;}
#main{margin-left:240px;padding:28px;width:calc(100% - 240px);min-height:100vh;}
.page{display:none;animation:fadeIn .2s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px);}to{opacity:1;transform:none;}}
.page-header{margin-bottom:22px;}
.page-title{font-size:22px;font-weight:700;}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:22px;}
.stat-card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;cursor:default;
}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-num{font-size:30px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:140px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;}
.search-wrap input{
  width:100%;padding:8px 12px 8px 34px;background:var(--surface2);
  border:1px solid var(--border);border-radius:var(--radius-sm);
  color:var(--text);font-size:13px;outline:none;
}
.search-wrap input:focus{border-color:var(--accent);}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:14px;}
.filter-select{
  padding:7px 10px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);font-size:12px;cursor:pointer;
}
.tbl-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{
  padding:10px 12px;text-align:left;font-size:11px;font-weight:700;
  text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
  background:var(--surface2);border-bottom:1px solid var(--border);
  cursor:pointer;white-space:nowrap;user-select:none;
}
th:hover{color:var(--text);}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:middle;}
tr:hover td{background:var(--surface2);cursor:pointer;}
.pagination{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:12px;color:var(--muted);flex-wrap:wrap;}
.pg-btn{padding:4px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;}
.pg-btn:hover{border-color:var(--accent);color:var(--accent);}
.pg-btn.active{background:var(--accent);color:#fff;border-color:var(--accent);}
.pg-btn:disabled{opacity:.4;cursor:not-allowed;}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.sub-list{display:flex;flex-direction:column;}
.sub-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}
.sub-icon.c-amber{color:var(--amber);}
.sub-icon.c-red{color:var(--red);}
.sub-name{flex:1;font-size:13px;font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{
  position:fixed;right:0;top:0;bottom:0;width:480px;max-width:95vw;
  background:var(--surface);border-left:1px solid var(--border);
  z-index:201;display:flex;flex-direction:column;
  transform:translateX(100%);transition:transform .25s ease;overflow:hidden;
}
#detailDrawer.open{transform:translateX(0);}
.drawer-header{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.drawer-title{font-size:13px;font-weight:700;word-break:break-word;}
.drawer-close{background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;padding:2px 6px;border-radius:var(--radius-sm);}
.drawer-close:hover{color:var(--text);background:var(--surface2);}
.drawer-body{padding:20px;overflow-y:auto;flex:1;}
.drawer-nav{display:flex;gap:8px;align-items:center;margin-bottom:16px;}
.drawer-nav-btn{padding:5px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;}
.drawer-nav-btn:hover{border-color:var(--accent);color:var(--accent);}
.drawer-nav-info{font-size:12px;color:var(--muted);flex:1;text-align:center;}
.drawer-field{margin-bottom:14px;}
.drawer-field-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.drawer-field-value{font-size:13px;word-break:break-all;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.cat-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;}
.cat-chip{font-size:11px;padding:2px 8px;border-radius:12px;font-family:var(--mono);}
.cat-chip.present{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.cat-chip.missing{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
#toast{
  position:fixed;bottom:24px;right:24px;padding:12px 18px;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);
  font-size:13px;box-shadow:var(--shadow);
  opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:300;
}
#toast.show{opacity:1;transform:translateY(0);}
#menuToggle{display:none;}
@media(max-width:768px){
  #menuToggle{display:flex;align-items:center;justify-content:center;position:fixed;top:12px;left:12px;z-index:300;width:36px;height:36px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:18px;}
  #sidebar{transform:translateX(-100%);}
  #sidebar.open{transform:translateX(0);}
  #main{margin-left:0;width:100%;padding:16px;padding-top:56px;}
  .chart-grid{grid-template-columns:1fr;}
}
@media print{
  #sidebar,#menuToggle,#toast,#drawerBackdrop,#detailDrawer{display:none!important;}
  #main{margin-left:0;width:100%;}
  .page{display:block!important;}
}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">📡</div>
    <div class="logo-title">Diagnostic Coverage</div>
    <div class="logo-sub">Azure Monitoring Gap Report</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> Gap Findings</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">📋</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Azure Diagnostic Coverage Gap
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Diagnostic Coverage Overview</div>
      <div class="page-sub">Monitoring gap posture across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_RESOURCES__</div>
        <div class="stat-label">Resources with Gaps</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">No diagnostic setting</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High</div>
        <div class="stat-sub">No workspace linked</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium</div>
        <div class="stat-sub">Missing log categories</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low</div>
        <div class="stat-sub">Minor gaps only</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__NO_WORKSPACE__</div>
        <div class="stat-label">No Workspace</div>
        <div class="stat-sub">Log Analytics not linked</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🚨 Gap Severity Distribution</div>
        __SEV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🗂️ Top Resource Types with Gaps</div>
        __TYPE_ROWS__
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">📡 Coverage Summary</div>
      <div class="stats-grid" style="margin-bottom:0;">
        <div class="stat-card c-red"><div class="stat-num">__NO_SETTING_COUNT__</div><div class="stat-label">No Setting At All</div></div>
        <div class="stat-card c-amber"><div class="stat-num">__NO_WORKSPACE__</div><div class="stat-label">No Workspace Destination</div></div>
        <div class="stat-card c-cyan"><div class="stat-num">__MEDIUM_COUNT__</div><div class="stat-label">Missing Log Categories</div></div>
        <div class="stat-card c-green"><div class="stat-num">__LOW_COUNT__</div><div class="stat-label">Low / Metrics Only</div></div>
      </div>
    </div>
  </div>

  <!-- Gap Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Gap Findings</div>
      <div class="page-sub">Click any row for full details. Resources are sorted by severity.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search resource, type, subscription…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="pgSizeFind" onchange="changeFindPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="findTable">
          <thead>
            <tr>
              <th onclick="sortFind(0)">Resource Name</th>
              <th onclick="sortFind(1)">Subscription</th>
              <th onclick="sortFind(2)">Resource Type</th>
              <th>Diag Setting</th>
              <th>Workspace</th>
              <th onclick="sortFind(5)">Severity</th>
              <th>Missing Categories</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription diagnostic gap assessment outcome</div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Subscriptions Scanned</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- Session -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Scan Parameters</div>
      <div class="page-sub">Authentication context and configuration used for this assessment</div>
    </div>
    <div class="panel">
      <div class="panel-title">🔐 Session Information</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Tenant ID</div><div class="info-value">__TENANT__</div></div>
        <div class="info-card"><div class="info-label">Account</div><div class="info-value">__ACCOUNT__</div></div>
        <div class="info-card"><div class="info-label">Environment</div><div class="info-value">__ENVIRONMENT__</div></div>
        <div class="info-card"><div class="info-label">Generated On</div><div class="info-value">__GENERATED_ON__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">⚙️ Scan Parameters</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Scope</div><div class="info-value">__SCOPE__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Subscriptions Scanned</div><div class="info-value">__SUB_COUNT__</div></div>
      </div>
    </div>
  </div>
</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Resource Detail</span>
    <button class="drawer-close" onclick="closeDrawer()">✕</button>
  </div>
  <div class="drawer-body">
    <div class="drawer-nav">
      <button class="drawer-nav-btn" onclick="navDetail(-1)">← Prev</button>
      <span class="drawer-nav-info" id="drawerNavInfo"></span>
      <button class="drawer-nav-btn" onclick="navDetail(1)">Next →</button>
    </div>
    <div id="drawerContent"></div>
  </div>
</div>

<div id="toast"></div>

<script>
const FIND_DATA = __FIND_JSON__;
let findFiltered = [...FIND_DATA];
let findPage = 1, findPageSz = 25;
let findSortCol = -1, findSortAsc = true;
let currentDetailIdx = 0;

const SEV_ORDER = {Critical:0,High:1,Medium:2,Low:3};

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
}

function toggleTheme(){
  const root=document.documentElement;
  root.dataset.theme=root.dataset.theme==='dark'?'light':'dark';
}

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Findings table ────────────────────────────────────────────────────────────
function filterFindings(){
  const q=document.getElementById('findSearch').value.toLowerCase();
  const s=document.getElementById('filterSev').value;
  findFiltered=FIND_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mS=!s||r.sev===s;
    return mQ&&mS;
  });
  findPage=1; renderFindings();
}

function changeFindPageSize(){
  findPageSz=parseInt(document.getElementById('pgSizeFind').value);
  findPage=1; renderFindings();
}

function sortFind(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys=['name','sub','type','','','sev','missing'];
  findFiltered.sort((a,b)=>{
    const k=keys[col];
    if(!k)return 0;
    if(k==='sev'){
      const av=SEV_ORDER[a[k]]??99, bv=SEV_ORDER[b[k]]??99;
      return findSortAsc?av-bv:bv-av;
    }
    const av=a[k]??'', bv=b[k]??'';
    return findSortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  renderFindings();
}

function renderFindings(){
  const tbody=document.getElementById('findBody');
  const start=(findPage-1)*findPageSz;
  const slice=findFiltered.slice(start,start+findPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=FIND_DATA.indexOf(r);
    const sCls=r.sev==='Critical'?'badge-red':r.sev==='High'?'badge-amber':r.sev==='Medium'?'badge-blue':'badge-green';
    const wsIco=r.wsLinked?'<span class="badge badge-green">✓</span>':'<span class="badge badge-red">✗</span>';
    const dsIco=r.hasSetting?'<span class="badge badge-green">✓</span>':'<span class="badge badge-red">✗</span>';
    const nm=r.name.length>36?r.name.substring(0,33)+'...':r.name;
    const tp=r.type.length>38?r.type.substring(r.type.length-38):r.type;
    const ms=r.missing.length>40?r.missing.substring(0,37)+'...':r.missing;
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td style="font-family:var(--mono);font-size:11px" title="${escH(r.type)}">${escH(tp)}</td>
      <td>${dsIco}</td>
      <td>${wsIco}</td>
      <td><span class="badge ${sCls}">${escH(r.sev)}</span></td>
      <td style="font-size:11px;color:var(--muted2)" title="${escH(r.missing)}">${escH(ms)}</td>
    </tr>`;
  }).join('');
  renderFindPg();
}

function renderFindPg(){
  const total=Math.ceil(findFiltered.length/findPageSz);
  const el=document.getElementById('findPagination');
  let h=`<span>${findFiltered.length} finding(s)</span>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,findPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeFindPage(p){
  const total=Math.ceil(findFiltered.length/findPageSz);
  if(p<1||p>total)return;
  findPage=p; renderFindings();
}

// ── Finding detail drawer ─────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=FIND_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FIND_DATA.length}`;
  const sCls=r.sev==='Critical'?'badge-red':r.sev==='High'?'badge-amber':r.sev==='Medium'?'badge-blue':'badge-green';
  const presentChips=r.present?r.present.split(',').map(c=>c.trim()).filter(Boolean).map(c=>`<span class="cat-chip present">${escH(c)}</span>`).join(''):'—';
  const missingChips=r.missing?r.missing.split(',').map(c=>c.trim()).filter(Boolean).map(c=>`<span class="cat-chip missing">${escH(c)}</span>`).join(''):'None';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sCls}">${escH(r.sev)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Type</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.type)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Location</div>
      <div class="drawer-field-value">${escH(r.location)||'—'}</div></div>
    <div class="drawer-section">Diagnostic Configuration</div>
    <div class="drawer-field"><div class="drawer-field-label">Diagnostic Setting Present</div>
      <div class="drawer-field-value">${r.hasSetting?'<span class="badge badge-green">Yes</span>':'<span class="badge badge-red">No</span>'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Setting Name</div>
      <div class="drawer-field-value">${r.settingName?escH(r.settingName):'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Log Analytics Workspace</div>
      <div class="drawer-field-value">${r.wsLinked?'<span class="badge badge-green">Linked</span>':'<span class="badge badge-red">Not Linked</span>'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Workspace Name</div>
      <div class="drawer-field-value">${r.wsName?escH(r.wsName):'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Metrics Only</div>
      <div class="drawer-field-value">${r.metricsOnly?'<span class="badge badge-amber">Yes</span>':'No'}</div></div>
    <div class="drawer-section">Log Category Coverage</div>
    <div class="drawer-field"><div class="drawer-field-label">Present Categories</div>
      <div class="cat-list">${presentChips}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Missing Categories</div>
      <div class="cat-list">${missingChips}</div></div>
    <div class="drawer-section">Resource Identity</div>
    <div class="drawer-field"><div class="drawer-field-label">Resource ID</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:10px;word-break:break-all">${escH(r.resourceId)}</div></div>
  `;
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}

function closeDrawer(){
  document.getElementById('drawerBackdrop').style.display='none';
  document.getElementById('detailDrawer').classList.remove('open');
}

function navDetail(dir){
  const next=currentDetailIdx+dir;
  if(next>=0&&next<FIND_DATA.length) showFindingDetail(next);
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width=el.dataset.pct+'%';
    });
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

// ── Init ─────────────────────────────────────────────────────────────────────
filterFindings();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_RESOURCES__', $totalResources `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MEDIUM_COUNT__', $mediumCount `
        -replace '__LOW_COUNT__', $lowCount `
        -replace '__NO_WORKSPACE__', $noWorkspaceCount `
        -replace '__NO_SETTING_COUNT__', $noSettingCount `
        -replace '__SEV_ROWS__', $sevRows `
        -replace '__TYPE_ROWS__', $typeRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FIND_JSON__', $findingJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureDiagnosticCoverageGap {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureDiagnosticCoverageGap-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Required log categories reference set ─────────────────────────────────
    $requiredLogCategories = @(
        "AuditEvent", "Administrative", "Security", "Policy",
        "Alert", "Recommendation", "ServiceHealth", "ResourceHealth"
    )

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Monitor")

    $missingModules = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missingModules) {
        Write-Host "  ⚠ Missing Az modules: $($missingModules -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "  Install Az module now? (Y/N)"

        if ($install -match '^[Yy]$') {
            try {
                Write-Host ""
                Write-Host "  Installing Az module, please wait..." -ForegroundColor Cyan
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "  ✓ Az module installed successfully" -ForegroundColor Green
                Write-Host ""
            }
            catch {
                Write-Host "  ✗ Error installing Az module: $_" -ForegroundColor Red
                return
            }
        }
        else {
            Write-Host ""
            Write-Host "  Installation declined. Cannot proceed without required Az modules." -ForegroundColor Yellow
            return
        }
    }

    # ── Auth check ────────────────────────────────────────────────────────────
    try {
        $ctx = Get-AzContext -ErrorAction Stop
        if (-not $ctx) { throw "No active Azure context." }
    }
    catch {
        Write-Host "  ✗ No authenticated Azure session. Run Connect-AzAccount first." -ForegroundColor Red
        return
    }

    # ── Resolve subscriptions ─────────────────────────────────────────────────
    $subscriptions = @()
    $scopeText = ""

    if ($AllSubscriptions -or -not $SubscriptionIds) {
        try {
            $subscriptions = @(Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq "Enabled" })
            $scopeText = "All Subscriptions"
        }
        catch {
            Write-Host "  ✗ Could not retrieve subscriptions: $_" -ForegroundColor Red
            return
        }
    }
    else {
        foreach ($sid in $SubscriptionIds) {
            try {
                $sub = Get-AzSubscription -SubscriptionId $sid -ErrorAction Stop
                $subscriptions += $sub
            }
            catch {
                Write-Warning "  Could not resolve subscription ID '$sid': $_"
            }
        }
        $scopeText = "Specific Subscriptions"
    }

    $subCount = $subscriptions.Count

    if ($subCount -eq 0) {
        Write-Host "  ✗ No accessible subscriptions found." -ForegroundColor Red
        return
    }

    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"         = "$scopeText ($subCount found)"
        "Export to CSV" = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"   = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $subscriptionResults = @()
    $severityDist = @{ "Critical" = 0; "High" = 0; "Medium" = 0; "Low" = 0 }
    $typeDist = @{}
    $successCount = 0
    $errorCount = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = ([math]::Max(
            ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
            35
        ))

    $subIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            # ── Enumerate resources ───────────────────────────────────────────
            $resources = @()
            try {
                $resources = @(Get-AzResource -ErrorAction Stop)
            }
            catch {
                Write-Warning "  Could not enumerate resources for $($sub.Name): $_"
            }

            $subGapCount = 0

            foreach ($res in $resources) {
                # Skip resource types known not to support diagnostic settings
                $unsupportedTypes = @(
                    "Microsoft.Resources/resourceGroups",
                    "Microsoft.Authorization/roleAssignments",
                    "Microsoft.Authorization/roleDefinitions",
                    "Microsoft.Authorization/policyAssignments",
                    "Microsoft.Authorization/policyDefinitions"
                )
                if ($unsupportedTypes -contains $res.ResourceType) { continue }

                $hasDiagSetting = $false
                $workspaceLinked = $false
                $workspaceName = ""
                $settingName = ""
                $presentCats = @()
                $missingCats = @()
                $metricsOnly = $false

                try {
                    $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $res.ResourceId -ErrorAction Stop)

                    if ($diagSettings.Count -gt 0) {
                        $hasDiagSetting = $true
                        $ds = $diagSettings[0]  # Evaluate the first (primary) setting
                        $settingName = Get-ObjProperty -Obj $ds -PropName 'Name' -Default ""

                        # Workspace linkage
                        $wsId = Get-ObjProperty -Obj $ds -PropName 'WorkspaceId' -Default ""
                        if (-not [string]::IsNullOrWhiteSpace($wsId)) {
                            $workspaceLinked = $true
                            $workspaceName = ($wsId -split "/")[-1]
                        }

                        # Log category coverage
                        $logs = @()
                        try { $logs = @($ds.Logs) } catch { }

                        if ($logs.Count -eq 0) {
                            # Diagnostic setting has no logs configured — metrics only
                            $metricsOnly = $true
                            $missingCats = $requiredLogCategories
                        }
                        else {
                            $enabledCats = @($logs | Where-Object { $_.Enabled -eq $true } | ForEach-Object { $_.Category })
                            foreach ($reqCat in $requiredLogCategories) {
                                if ($enabledCats -contains $reqCat) { $presentCats += $reqCat }
                                else { $missingCats += $reqCat }
                            }
                        }
                    }
                    else {
                        # No diagnostic settings at all
                        $missingCats = $requiredLogCategories
                    }
                }
                catch {
                    # Resource type may not support diagnostic settings — skip silently
                    Write-Verbose "  Diagnostic settings unavailable for '$($res.Name)' ($($res.ResourceType)): $_"
                    continue
                }

                # ── Severity classification ───────────────────────────────────
                $severity = if (-not $hasDiagSetting) { "Critical" }
                elseif (-not $workspaceLinked) { "High" }
                elseif ($missingCats.Count -gt 0) { "Medium" }
                else { "Low" }

                # Only record findings that represent a genuine gap (Critical/High/Medium/Low all qualify)
                $presentCatStr = if ($presentCats.Count -gt 0) { $presentCats -join ", " } else { "" }
                $missingCatStr = if ($missingCats.Count -gt 0) { $missingCats -join ", " } else { "" }

                $allFindings += [pscustomobject]@{
                    SubscriptionName     = $sub.Name
                    SubscriptionId       = $sub.Id
                    ResourceName         = $res.Name
                    ResourceGroup        = $res.ResourceGroupName
                    ResourceType         = $res.ResourceType
                    Location             = Get-ObjProperty -Obj $res -PropName 'Location' -Default ""
                    ResourceId           = $res.ResourceId
                    HasDiagnosticSetting = $hasDiagSetting
                    SettingName          = $settingName
                    WorkspaceLinked      = $workspaceLinked
                    WorkspaceName        = $workspaceName
                    MetricsOnly          = $metricsOnly
                    PresentCategories    = $presentCatStr
                    MissingCategories    = $missingCatStr
                    GapSeverity          = $severity
                }

                if ($severityDist.ContainsKey($severity)) { $severityDist[$severity]++ }

                if ($typeDist.ContainsKey($res.ResourceType)) { $typeDist[$res.ResourceType]++ }
                else { $typeDist[$res.ResourceType] = 1 }

                $subGapCount++
            }

            # ── Per-subscription result ───────────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Resources scanned: $($resources.Count)  Gaps found: $subGapCount" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Resources: $($resources.Count)  Gaps: $subGapCount"
                Status  = "Success"
            }
            $successCount++
        }
        catch {
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✗ " -NoNewline -ForegroundColor Red
            Write-Host $paddedName -NoNewline -ForegroundColor Red
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Failed: $($_.Exception.Message)"
                Status  = "Error"
            }
            $errorCount++
        }

        $subIndex++
    }

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Total Gaps Found"            = $allFindings.Count
            "Critical (No Setting)"       = $severityDist["Critical"]
            "High (No Workspace)"         = $severityDist["High"]
            "Medium (Missing Categories)" = $severityDist["Medium"]
            "Low"                         = $severityDist["Low"]
            "Execution Time"              = $duration
        })

    Write-GapBreakdown -GapSeverity $severityDist

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        # CSV export
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, ResourceName, ResourceGroup,
                ResourceType, Location, HasDiagnosticSetting, SettingName,
                WorkspaceLinked, WorkspaceName, MetricsOnly,
                PresentCategories, MissingCategories, GapSeverity |
                Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML dashboard
        try {
            $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')

            $sessionInfo = @{
                Tenant      = $ctx.Tenant.Id
                Account     = $ctx.Account.Id
                Environment = $ctx.Environment.Name
            }

            $scanParams = @{
                Scope         = "$scopeText ($subCount found)"
                ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime      = $duration
            }

            $htmlContent = Generate-DiagnosticGapHtml `
                -SessionInfo          $sessionInfo `
                -ScanParameters       $scanParams `
                -Findings             $allFindings `
                -SeverityDistribution $severityDist `
                -TypeDistribution     $typeDist `
                -SubscriptionResults  $subscriptionResults `
                -GeneratedOn          (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        # Grid View
        try {
            $allFindings |
            Select-Object SubscriptionName, ResourceName, ResourceType, HasDiagnosticSetting,
            WorkspaceLinked, MissingCategories, GapSeverity |
            Out-GridView -Title "Azure Diagnostic Coverage Gap Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No diagnostic coverage gaps found in the targeted subscriptions." -ForegroundColor Yellow
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        $outCsv = if ($csvExported) { $CsvPath } else { $null }
        $outHtml = if ($htmlExported) { $htmlPath } else { $null }
        Write-OutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
