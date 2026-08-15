<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Combines backup, disaster recovery, availability zone, redundancy, monitoring,
    and recovery configuration signals across one or more subscriptions to produce
    an enterprise resilience score with an interactive HTML dashboard.

.DESCRIPTION
    Get-AzureResiliencePosture evaluates six resilience dimensions for every
    supported resource type found in the targeted subscriptions, then aggregates
    them into a per-resource resilience score (0–100) and an overall environment score.

    Dimensions assessed per resource:
        1. Backup            — Azure Backup / Recovery Services Vault protection status.
                              Checks whether the resource is registered as a protected
                              item in any vault within the same subscription.
        2. High Availability — Availability Zone or Availability Set membership for
                              supported resource types (VMs, AKS clusters, etc.).
        3. Redundancy        — Storage replication tier (LRS/ZRS/GRS/RA-GRS/GZRS),
                              SQL geo-replication status, App Service redundancy mode,
                              and equivalent signals per resource type.
        4. Disaster Recovery — Azure Site Recovery protection or paired-region
                              replication configuration where supported.
        5. Monitoring        — Presence of at least one diagnostic setting routing
                              logs to a Log Analytics workspace (aligned with
                              Get-AzureDiagnosticCoverageGap findings).
        6. Recovery Config   — Soft-delete enabled, retention policy >= 7 days,
                              point-in-time restore availability, and similar
                              recovery-configuration signals per resource type.

    Resilience score per resource:
        Each dimension contributes a weighted score. The six dimension weights sum
        to 100. A resource achieves a maximum of 100 if all six dimensions pass.
        Resources are graded: Excellent (>=85), Good (70-84), Fair (50-69),
        Poor (<50). The environment score is the mean across all evaluated resources.

    Scope options:
        - All subscriptions visible to the authenticated account (-AllSubscriptions)
        - A specific list of subscription IDs (-SubscriptionIds)

    Outputs:
        - Real-time progress bar and color-coded per-subscription output
        - Always-on interactive HTML dashboard (dark/light, sortable table,
          resilience-score ring, dimension breakdown, detail drawer)
        - Optional CSV export of all resource resilience assessments

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all resilience assessments to the path given
    in -CsvPath. The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzureResiliencePosture-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureResiliencePosture -AllSubscriptions

.EXAMPLE
    Get-AzureResiliencePosture -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureResiliencePosture -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\ResiliencePosture.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Six-dimension resilience scoring
                            (Backup, HA, Redundancy, DR, Monitoring, Recovery Config)
                            per resource, environment aggregate score, CSV export,
                            and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.RecoveryServices,
           Az.Monitor, Az.Compute, Az.Storage, Az.Sql)
           — installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level.
        4. Microsoft.RecoveryServices/vaults/read and
           Microsoft.RecoveryServices/vaults/backupProtectedItems/read are
           required to evaluate backup protection. Without these, the Backup
           dimension is marked "Could Not Confirm" and scoring continues.
        5. Microsoft.Insights/diagnosticSettings/read is required for the
           Monitoring dimension. Missing permissions produce a graceful skip.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Resource-level backup protection detection relies on listing protected
          items from Recovery Services Vaults. Cross-subscription vault references
          are not followed.
        - Azure Site Recovery (ASR) replication status requires the
          Microsoft.RecoveryServices/vaults/replicationFabrics/* permission set.
          Without it, the DR dimension is scored from alternate signals only.
        - Resilience signals vary by resource type. Resources without well-defined
          signals for a dimension receive a neutral score (50) for that dimension
          rather than failing or passing, to avoid penalising unsupported types.
        - Interactive Grid View requires a GUI-capable session. Skipped gracefully
          in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Environment score is the arithmetic mean of individual resource scores
          and may be influenced by resource types with limited signal availability.

.LINK
    https://learn.microsoft.com/en-us/azure/reliability/overview
    https://learn.microsoft.com/en-us/azure/backup/backup-overview
    https://learn.microsoft.com/en-us/azure/site-recovery/site-recovery-overview
    https://learn.microsoft.com/en-us/azure/availability-zones/az-overview
    https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings

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
    Write-CenteredText "Azure Resilience Posture Assessment v1.0" -Color White
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

Function Write-ResilienceBreakdown {
    param([hashtable]$GradeDist)

    if ($GradeDist.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Resilience Grade Breakdown" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $colorMap = @{ "Excellent" = "Green"; "Good" = "Cyan"; "Fair" = "Yellow"; "Poor" = "Red" }

    foreach ($grade in @("Excellent", "Good", "Fair", "Poor")) {
        if ($GradeDist.ContainsKey($grade)) {
            $color = if ($colorMap.ContainsKey($grade)) { $colorMap[$grade] } else { "White" }
            Write-Host "  " -NoNewline
            Write-Host $grade.PadRight(22) -NoNewline -ForegroundColor White
            Write-Host ": " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($GradeDist[$grade]) resource(s)" -ForegroundColor $color
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

Function Generate-ResiliencePostureHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Assessments,
        [hashtable]$GradeDistribution,
        [hashtable]$DimensionAvgScores,
        [array]$SubscriptionResults,
        [int]$EnvironmentScore,
        [string]$GeneratedOn
    )

    $totalResources = @($Assessments).Count
    $excellentCount = if ($GradeDistribution.ContainsKey("Excellent")) { $GradeDistribution["Excellent"] } else { 0 }
    $goodCount = if ($GradeDistribution.ContainsKey("Good")) { $GradeDistribution["Good"] }      else { 0 }
    $fairCount = if ($GradeDistribution.ContainsKey("Fair")) { $GradeDistribution["Fair"] }      else { 0 }
    $poorCount = if ($GradeDistribution.ContainsKey("Poor")) { $GradeDistribution["Poor"] }      else { 0 }

    $envScoreColor = if ($EnvironmentScore -ge 85) { "var(--green)" }
    elseif ($EnvironmentScore -ge 70) { "var(--accent2)" }
    elseif ($EnvironmentScore -ge 50) { "var(--amber)" }
    else { "var(--red)" }

    # ── Ring SVG ─────────────────────────────────────────────────────────────
    $ringCirc = 2 * 3.14159 * 54   # circumference for r=54
    $ringOffset = $ringCirc * (1 - ($EnvironmentScore / 100))
    $ringOffsetR = [math]::Round($ringOffset, 2)
    $ringCircR = [math]::Round($ringCirc, 2)

    # ── Assessment table rows ─────────────────────────────────────────────────
    $assessmentRows = ""
    foreach ($a in $Assessments) {
        $gradeCls = switch ($a.ResilienceGrade) {
            "Excellent" { "badge-green" }
            "Good" { "badge-blue" }
            "Fair" { "badge-amber" }
            default { "badge-red" }
        }
        $scoreColor = if ($a.ResilienceScore -ge 85) { "var(--green)" }
        elseif ($a.ResilienceScore -ge 70) { "var(--accent2)" }
        elseif ($a.ResilienceScore -ge 50) { "var(--amber)" }
        else { "var(--red)" }

        $assessmentRows += @"
          <tr onclick="showAssessDetail($($Assessments.IndexOf($a)))">
            <td title="$(EscHtml $a.ResourceName)">$(if ($a.ResourceName.Length -gt 34) { EscHtml($a.ResourceName.Substring(0,31)+"...") } else { EscHtml $a.ResourceName })</td>
            <td>$(EscHtml $a.SubscriptionName)</td>
            <td style="font-family:var(--mono);font-size:11px" title="$(EscHtml $a.ResourceType)">$(if ($a.ResourceType.Length -gt 36) { EscHtml($a.ResourceType.Substring($a.ResourceType.Length-36)) } else { EscHtml $a.ResourceType })</td>
            <td style="font-family:var(--mono);font-weight:700;color:$scoreColor">$($a.ResilienceScore)</td>
            <td><span class="badge $(EscHtml $gradeCls)">$(EscHtml $a.ResilienceGrade)</span></td>
            <td>$(if ($a.BackupScore -ge 80) { "✅" } else { "❌" })</td>
            <td>$(if ($a.HighAvailabilityScore -ge 80) { "✅" } else { "❌" })</td>
            <td>$(if ($a.RedundancyScore -ge 80) { "✅" } else { "❌" })</td>
            <td>$(if ($a.DisasterRecoveryScore -ge 80) { "✅" } else { "❌" })</td>
            <td>$(if ($a.MonitoringScore -ge 80) { "✅" } else { "❌" })</td>
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

    # ── Dimension average bar rows ─────────────────────────────────────────────
    $dimRows = ""
    $dimOrder = @("Backup", "HighAvailability", "Redundancy", "DisasterRecovery", "Monitoring", "RecoveryConfig")
    $dimLabels = @{
        "Backup"           = "Backup Protection"
        "HighAvailability" = "High Availability"
        "Redundancy"       = "Redundancy"
        "DisasterRecovery" = "Disaster Recovery"
        "Monitoring"       = "Monitoring Coverage"
        "RecoveryConfig"   = "Recovery Config"
    }

    foreach ($dim in $dimOrder) {
        if ($DimensionAvgScores.ContainsKey($dim)) {
            $avg = $DimensionAvgScores[$dim]
            $barColor = if ($avg -ge 85) { "var(--green)" }
            elseif ($avg -ge 70) { "var(--accent2)" }
            elseif ($avg -ge 50) { "var(--amber)" }
            else { "var(--red)" }
            $label = if ($dimLabels.ContainsKey($dim)) { $dimLabels[$dim] } else { $dim }
            $dimRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $label)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$avg" style="background:$barColor"></div></div>
            <span class="bar-pct">$avg%</span>
          </div>
"@
        }
    }

    # ── Grade distribution bar rows ───────────────────────────────────────────
    $gradeTotal = ($GradeDistribution.Values | Measure-Object -Sum).Sum
    $gradeRows = ""
    foreach ($grade in @("Excellent", "Good", "Fair", "Poor")) {
        if ($GradeDistribution.ContainsKey($grade)) {
            $cnt = $GradeDistribution[$grade]
            $pct = if ($gradeTotal -gt 0) { [math]::Round(($cnt / $gradeTotal) * 100) } else { 0 }
            $barColor = switch ($grade) {
                "Excellent" { "var(--green)" }
                "Good" { "var(--accent2)" }
                "Fair" { "var(--amber)" }
                default { "var(--red)" }
            }
            $gradeRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $grade)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$cnt ($pct%)</span>
          </div>
"@
        }
    }

    # ── JSON for detail drawer ────────────────────────────────────────────────
    $assessJson = "["
    foreach ($a in $Assessments) {
        $assessJson += "{" +
        """name"":""$(EscJ $a.ResourceName)""," +
        """sub"":""$(EscJ $a.SubscriptionName)""," +
        """rg"":""$(EscJ $a.ResourceGroup)""," +
        """type"":""$(EscJ $a.ResourceType)""," +
        """location"":""$(EscJ $a.Location)""," +
        """score"":$($a.ResilienceScore)," +
        """grade"":""$(EscJ $a.ResilienceGrade)""," +
        """backup"":$($a.BackupScore)," +
        """backupNote"":""$(EscJ $a.BackupNote)""," +
        """ha"":$($a.HighAvailabilityScore)," +
        """haNote"":""$(EscJ $a.HighAvailabilityNote)""," +
        """redundancy"":$($a.RedundancyScore)," +
        """redundancyNote"":""$(EscJ $a.RedundancyNote)""," +
        """dr"":$($a.DisasterRecoveryScore)," +
        """drNote"":""$(EscJ $a.DisasterRecoveryNote)""," +
        """monitoring"":$($a.MonitoringScore)," +
        """monitoringNote"":""$(EscJ $a.MonitoringNote)""," +
        """recovery"":$($a.RecoveryConfigScore)," +
        """recoveryNote"":""$(EscJ $a.RecoveryConfigNote)""," +
        """resourceId"":""$(EscJ $a.ResourceId)""" +
        "},"
    }
    $assessJson = $assessJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Resilience Posture Dashboard</title>
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
  background:linear-gradient(135deg,var(--accent3),var(--accent));
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
.bar-label{font-size:12px;color:var(--muted2);width:150px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:70px;text-align:right;flex-shrink:0;}
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
.score-hero{display:flex;align-items:center;gap:32px;padding:20px;flex-wrap:wrap;}
.score-ring-wrap{position:relative;width:140px;height:140px;flex-shrink:0;}
.score-ring-wrap svg{transform:rotate(-90deg);}
.score-label-wrap{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.score-num{font-size:36px;font-weight:700;font-family:var(--mono);line-height:1;}
.score-tag{font-size:11px;color:var(--muted);margin-top:4px;}
.score-meta{flex:1;}
.score-title{font-size:18px;font-weight:700;margin-bottom:6px;}
.score-desc{font-size:13px;color:var(--muted2);line-height:1.6;}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{
  position:fixed;right:0;top:0;bottom:0;width:500px;max-width:95vw;
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
.dim-row{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);}
.dim-row:last-child{border-bottom:none;}
.dim-label{font-size:12px;color:var(--muted2);width:130px;flex-shrink:0;}
.dim-score{font-size:13px;font-family:var(--mono);font-weight:700;width:36px;flex-shrink:0;}
.dim-note{font-size:11px;color:var(--muted2);flex:1;}
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
  .score-hero{flex-direction:column;}
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
    <div class="logo-icon">🛡️</div>
    <div class="logo-title">Resilience Posture</div>
    <div class="logo-sub">Azure Enterprise Score</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('assessments',this)"><span class="nav-icon">🔍</span> Resource Assessments</button>
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
      Azure Resilience Posture
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Enterprise Resilience Posture</div>
      <div class="page-sub">Six-dimension resilience score across __SUB_COUNT__ subscription(s)</div>
    </div>

    <!-- Score Ring -->
    <div class="panel">
      <div class="score-hero">
        <div class="score-ring-wrap">
          <svg width="140" height="140" viewBox="0 0 140 140">
            <circle cx="70" cy="70" r="54" fill="none" stroke="var(--surface3)" stroke-width="12"/>
            <circle cx="70" cy="70" r="54" fill="none" stroke="__ENV_SCORE_COLOR__" stroke-width="12"
              stroke-dasharray="__RING_CIRC__" stroke-dashoffset="__RING_OFFSET__"
              stroke-linecap="round" style="transition:stroke-dashoffset 1s ease"/>
          </svg>
          <div class="score-label-wrap">
            <div class="score-num" style="color:__ENV_SCORE_COLOR__">__ENV_SCORE__</div>
            <div class="score-tag">/ 100</div>
          </div>
        </div>
        <div class="score-meta">
          <div class="score-title">Environment Resilience Score</div>
          <div class="score-desc">
            Mean score across <strong>__TOTAL_RESOURCES__</strong> assessed resources.
            Combines backup protection, high availability, redundancy, disaster recovery,
            monitoring coverage, and recovery configuration signals.
          </div>
        </div>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-green">
        <div class="stat-num">__EXCELLENT_COUNT__</div>
        <div class="stat-label">Excellent</div>
        <div class="stat-sub">Score ≥ 85</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__GOOD_COUNT__</div>
        <div class="stat-label">Good</div>
        <div class="stat-sub">Score 70–84</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__FAIR_COUNT__</div>
        <div class="stat-label">Fair</div>
        <div class="stat-sub">Score 50–69</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__POOR_COUNT__</div>
        <div class="stat-label">Poor</div>
        <div class="stat-sub">Score &lt; 50</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📐 Dimension Average Scores</div>
        __DIM_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🏅 Grade Distribution</div>
        __GRADE_ROWS__
      </div>
    </div>
  </div>

  <!-- Resource Assessments -->
  <div id="page-assessments" class="page">
    <div class="page-header">
      <div class="page-title">Resource Assessments</div>
      <div class="page-sub">Click any row for per-dimension scores and improvement notes.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="assessSearch" placeholder="Search resource, type, subscription…" oninput="filterAssess()"/>
        </div>
        <select class="filter-select" id="filterGrade" onchange="filterAssess()">
          <option value="">All Grades</option>
          <option value="Excellent">Excellent</option>
          <option value="Good">Good</option>
          <option value="Fair">Fair</option>
          <option value="Poor">Poor</option>
        </select>
        <select class="filter-select" id="pgSizeAssess" onchange="changeAssessPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="assessTable">
          <thead>
            <tr>
              <th onclick="sortAssess(0)">Resource Name</th>
              <th onclick="sortAssess(1)">Subscription</th>
              <th onclick="sortAssess(2)">Resource Type</th>
              <th onclick="sortAssess(3)">Score</th>
              <th onclick="sortAssess(4)">Grade</th>
              <th title="Backup">💾</th>
              <th title="High Availability">⚡</th>
              <th title="Redundancy">🔄</th>
              <th title="Disaster Recovery">🌍</th>
              <th title="Monitoring">📡</th>
            </tr>
          </thead>
          <tbody id="assessBody">__ASSESSMENT_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="assessPagination"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription resilience assessment outcome</div>
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
    <span class="drawer-title" id="drawerTitle">Resource Resilience Detail</span>
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
const ASSESS_DATA = __ASSESS_JSON__;
let assessFiltered = [...ASSESS_DATA];
let assessPage = 1, assessPageSz = 25;
let assessSortCol = -1, assessSortAsc = true;
let currentDetailIdx = 0;

const GRADE_ORDER = {Excellent:0,Good:1,Fair:2,Poor:3};

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

// ── Assessments table ─────────────────────────────────────────────────────────
function filterAssess(){
  const q=document.getElementById('assessSearch').value.toLowerCase();
  const g=document.getElementById('filterGrade').value;
  assessFiltered=ASSESS_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mG=!g||r.grade===g;
    return mQ&&mG;
  });
  assessPage=1; renderAssess();
}

function changeAssessPageSize(){
  assessPageSz=parseInt(document.getElementById('pgSizeAssess').value);
  assessPage=1; renderAssess();
}

function sortAssess(col){
  if(assessSortCol===col){assessSortAsc=!assessSortAsc;}else{assessSortCol=col;assessSortAsc=true;}
  const keys=['name','sub','type','score','grade'];
  assessFiltered.sort((a,b)=>{
    const k=keys[col];
    if(!k)return 0;
    if(k==='score'){return assessSortAsc?a[k]-b[k]:b[k]-a[k];}
    if(k==='grade'){
      const av=GRADE_ORDER[a[k]]??99,bv=GRADE_ORDER[b[k]]??99;
      return assessSortAsc?av-bv:bv-av;
    }
    const av=a[k]??'',bv=b[k]??'';
    return assessSortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  renderAssess();
}

function scoreColor(s){
  return s>=85?'var(--green)':s>=70?'var(--accent2)':s>=50?'var(--amber)':'var(--red)';
}

function renderAssess(){
  const tbody=document.getElementById('assessBody');
  const start=(assessPage-1)*assessPageSz;
  const slice=assessFiltered.slice(start,start+assessPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=ASSESS_DATA.indexOf(r);
    const gCls=r.grade==='Excellent'?'badge-green':r.grade==='Good'?'badge-blue':r.grade==='Fair'?'badge-amber':'badge-red';
    const nm=r.name.length>34?r.name.substring(0,31)+'...':r.name;
    const tp=r.type.length>36?r.type.substring(r.type.length-36):r.type;
    return `<tr onclick="showAssessDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td style="font-family:var(--mono);font-size:11px" title="${escH(r.type)}">${escH(tp)}</td>
      <td style="font-family:var(--mono);font-weight:700;color:${scoreColor(r.score)}">${r.score}</td>
      <td><span class="badge ${gCls}">${escH(r.grade)}</span></td>
      <td>${r.backup>=80?'✅':'❌'}</td>
      <td>${r.ha>=80?'✅':'❌'}</td>
      <td>${r.redundancy>=80?'✅':'❌'}</td>
      <td>${r.dr>=80?'✅':'❌'}</td>
      <td>${r.monitoring>=80?'✅':'❌'}</td>
    </tr>`;
  }).join('');
  renderAssessPg();
}

function renderAssessPg(){
  const total=Math.ceil(assessFiltered.length/assessPageSz);
  const el=document.getElementById('assessPagination');
  let h=`<span>${assessFiltered.length} resource(s)</span>`;
  h+=`<button class="pg-btn" onclick="changeAssessPage(${assessPage-1})" ${assessPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,assessPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===assessPage?'active':''}" onclick="changeAssessPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeAssessPage(${assessPage+1})" ${assessPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeAssessPage(p){
  const total=Math.ceil(assessFiltered.length/assessPageSz);
  if(p<1||p>total)return;
  assessPage=p; renderAssess();
}

// ── Assessment detail drawer ──────────────────────────────────────────────────
function dimRow(label,score,note){
  const c=scoreColor(score);
  return `<div class="dim-row">
    <span class="dim-label">${escH(label)}</span>
    <span class="dim-score" style="color:${c}">${score}</span>
    <span class="dim-note">${escH(note||'—')}</span>
  </div>`;
}

function showAssessDetail(idx){
  currentDetailIdx=idx;
  const r=ASSESS_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${ASSESS_DATA.length}`;
  const gCls=r.grade==='Excellent'?'badge-green':r.grade==='Good'?'badge-blue':r.grade==='Fair'?'badge-amber':'badge-red';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Resilience Score</div>
      <div class="drawer-field-value" style="font-size:28px;font-family:var(--mono);font-weight:700;color:${scoreColor(r.score)}">${r.score} <span class="badge ${gCls}">${escH(r.grade)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Type</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.type)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Location</div>
      <div class="drawer-field-value">${escH(r.location)||'—'}</div></div>
    <div class="drawer-section">Dimension Scores (0–100)</div>
    ${dimRow('💾 Backup',r.backup,r.backupNote)}
    ${dimRow('⚡ High Availability',r.ha,r.haNote)}
    ${dimRow('🔄 Redundancy',r.redundancy,r.redundancyNote)}
    ${dimRow('🌍 Disaster Recovery',r.dr,r.drNote)}
    ${dimRow('📡 Monitoring',r.monitoring,r.monitoringNote)}
    ${dimRow('♻️ Recovery Config',r.recovery,r.recoveryNote)}
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
  if(next>=0&&next<ASSESS_DATA.length) showAssessDetail(next);
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
filterAssess();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_RESOURCES__', $totalResources `
        -replace '__ENV_SCORE__', $EnvironmentScore `
        -replace '__ENV_SCORE_COLOR__', $envScoreColor `
        -replace '__RING_CIRC__', $ringCircR `
        -replace '__RING_OFFSET__', $ringOffsetR `
        -replace '__EXCELLENT_COUNT__', $excellentCount `
        -replace '__GOOD_COUNT__', $goodCount `
        -replace '__FAIR_COUNT__', $fairCount `
        -replace '__POOR_COUNT__', $poorCount `
        -replace '__DIM_ROWS__', $dimRows `
        -replace '__GRADE_ROWS__', $gradeRows `
        -replace '__ASSESSMENT_ROWS__', $assessmentRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__ASSESS_JSON__', $assessJson

    return $html
}


#------------------------------------------------------------------------ [ Scoring Logic ]

Function Get-ResilienceScores {
    param(
        [object]$Resource,
        [string]$SubscriptionId,
        [array]$VaultProtectedItems,
        [bool]$HasDiagnosticWorkspace
    )

    $type = $Resource.ResourceType.ToLower()
    $resId = $Resource.ResourceId
    $resProps = $null
    try { $resProps = Get-AzResource -ResourceId $resId -ExpandProperties -ErrorAction Stop } catch { }

    # ── Dimension weights (sum = 100) ─────────────────────────────────────────
    # Each dimension score is 0 or 100 (pass/fail) or 50 (signal unavailable)
    # weighted as follows:
    $weights = @{
        "Backup"           = 20
        "HighAvailability" = 20
        "Redundancy"       = 15
        "DisasterRecovery" = 20
        "Monitoring"       = 15
        "RecoveryConfig"   = 10
    }

    # ── 1. BACKUP ─────────────────────────────────────────────────────────────
    $backupScore = 50  # default: neutral (unsupported type or signal unavailable)
    $backupNote = "Could not confirm — signal unavailable for this resource type"
    $backupableTypes = @(
        "microsoft.compute/virtualmachines",
        "microsoft.compute/disks",
        "microsoft.sql/servers/databases",
        "microsoft.storage/storageaccounts",
        "microsoft.web/sites"
    )

    if ($backupableTypes -contains $type) {
        $protected = $VaultProtectedItems | Where-Object {
            $_.Properties.SourceResourceId -and
            $_.Properties.SourceResourceId.ToLower() -eq $resId.ToLower()
        }
        if ($protected) {
            $backupScore = 100
            $backupNote = "Protected in Recovery Services Vault"
        }
        else {
            $backupScore = 0
            $backupNote = "No backup protection found — resource not registered in any vault"
        }
    }

    # ── 2. HIGH AVAILABILITY ──────────────────────────────────────────────────
    $haScore = 50
    $haNote = "Could not confirm — HA signal unavailable for this resource type"

    if ($type -eq "microsoft.compute/virtualmachines") {
        $zones = @()
        try { $zones = @(Get-ObjProperty -Obj $resProps -PropName 'Zones' -Default @()) } catch { }
        $avSet = ""
        try { $avSet = Get-ObjProperty -Obj $resProps.Properties -PropName 'availabilitySet' -Default $null } catch { }

        if ($zones.Count -gt 0) {
            $haScore = 100
            $haNote = "Deployed across Availability Zone(s): $($zones -join ', ')"
        }
        elseif ($avSet) {
            $haScore = 75
            $haNote = "Member of Availability Set (zone-level HA not confirmed)"
        }
        else {
            $haScore = 0
            $haNote = "No Availability Zone or Availability Set — single point of failure risk"
        }
    }
    elseif ($type -like "microsoft.containerservice/managedclusters") {
        $agentPools = @()
        try { $agentPools = @(Get-ObjProperty -Obj $resProps.Properties -PropName 'agentPoolProfiles' -Default @()) } catch { }
        $hasZones = $agentPools | Where-Object { $_.availabilityZones -and $_.availabilityZones.Count -gt 0 }
        if ($hasZones) {
            $haScore = 100
            $haNote = "AKS node pools span Availability Zones"
        }
        else {
            $haScore = 25
            $haNote = "AKS cluster has no zone-redundant node pools"
        }
    }
    elseif ($type -like "microsoft.sql/servers/databases") {
        $haScore = 80
        $haNote = "Azure SQL provides built-in HA; zone redundancy depends on service tier"
    }

    # ── 3. REDUNDANCY ─────────────────────────────────────────────────────────
    $redundancyScore = 50
    $redundancyNote = "Could not confirm — redundancy signal unavailable for this resource type"

    if ($type -like "microsoft.storage/storageaccounts") {
        $sku = ""
        try { $sku = Get-ObjProperty -Obj $resProps -PropName 'Sku' -Default $null } catch { }
        $skuName = if ($sku) { Get-ObjProperty -Obj $sku -PropName 'Name' -Default "" } else { "" }
        $redundancyScore = switch -Wildcard ($skuName) {
            "*GZRS*" { 100 }
            "*GRS*" { 90 }
            "*ZRS*" { 80 }
            "*LRS*" { 30 }
            default { 50 }
        }
        $redundancyNote = if ($skuName) { "Storage replication: $skuName" } else { "Storage replication tier could not be confirmed" }
    }
    elseif ($type -like "microsoft.sql/servers/databases") {
        $geo = $null
        try {
            $geo = @(Get-AzSqlDatabaseGeoBackup -ResourceGroupName $Resource.ResourceGroupName `
                    -ServerName ($resId -split "/")[8] -DatabaseName $Resource.Name -ErrorAction Stop)
        }
        catch { }
        if ($geo -and $geo.Count -gt 0) {
            $redundancyScore = 100
            $redundancyNote = "Geo-backup available"
        }
        else {
            $redundancyScore = 40
            $redundancyNote = "No geo-backup confirmed"
        }
    }
    elseif ($type -like "microsoft.web/sites") {
        $redundancyMode = ""
        try { $redundancyMode = Get-ObjProperty -Obj $resProps.Properties -PropName 'redundancyMode' -Default "" } catch { }
        if ($redundancyMode -in @("GeoRedundant", "ZoneRedundant")) {
            $redundancyScore = 100
            $redundancyNote = "App Service redundancy mode: $redundancyMode"
        }
        elseif ($redundancyMode -eq "ActiveActive") {
            $redundancyScore = 80
            $redundancyNote = "App Service redundancy mode: ActiveActive"
        }
        else {
            $redundancyScore = 30
            $redundancyNote = "No redundancy mode set (or could not be confirmed)"
        }
    }

    # ── 4. DISASTER RECOVERY ──────────────────────────────────────────────────
    $drScore = 50
    $drNote = "Could not confirm — DR signal unavailable for this resource type"

    # Check ASR replication via vault items
    $asrReplicated = $VaultProtectedItems | Where-Object {
        $_.Properties.FriendlyName -and
        $_.Properties.FriendlyName.ToLower() -eq $Resource.Name.ToLower() -and
        $_.Properties.PSObject.Properties.Name -contains "ReplicaId"
    }
    if ($asrReplicated) {
        $drScore = 100
        $drNote = "Azure Site Recovery replication detected"
    }
    elseif ($type -like "microsoft.sql/servers/databases") {
        $fg = $null
        try {
            $fg = @(Get-AzSqlDatabaseFailoverGroup -ResourceGroupName $Resource.ResourceGroupName `
                    -ServerName ($resId -split "/")[8] -ErrorAction Stop)
        }
        catch { }
        if ($fg -and $fg.Count -gt 0) {
            $drScore = 100
            $drNote = "SQL Failover Group configured"
        }
        else {
            $drScore = 30
            $drNote = "No SQL Failover Group detected"
        }
    }

    # ── 5. MONITORING ─────────────────────────────────────────────────────────
    $monitoringScore = if ($HasDiagnosticWorkspace) { 100 } else { 0 }
    $monitoringNote = if ($HasDiagnosticWorkspace) {
        "Diagnostic setting routes to Log Analytics workspace"
    }
    else {
        "No Log Analytics workspace-linked diagnostic setting found"
    }

    # ── 6. RECOVERY CONFIG ────────────────────────────────────────────────────
    $recoveryScore = 50
    $recoveryNote = "Could not confirm — recovery config signal unavailable for this resource type"

    if ($type -like "microsoft.storage/storageaccounts") {
        $softDelete = $false
        try {
            $blobProps = Get-AzStorageBlobServiceProperty -ResourceGroupName $Resource.ResourceGroupName `
                -StorageAccountName $Resource.Name -ErrorAction Stop
            $sdEnabled = Get-ObjProperty -Obj $blobProps.DeleteRetentionPolicy -PropName 'Enabled' -Default $false
            $sdDays = Get-ObjProperty -Obj $blobProps.DeleteRetentionPolicy -PropName 'Days' -Default 0
            if ($sdEnabled -and $sdDays -ge 7) { $softDelete = $true }
        }
        catch { }
        if ($softDelete) {
            $recoveryScore = 100
            $recoveryNote = "Blob soft-delete enabled with retention ≥ 7 days"
        }
        else {
            $recoveryScore = 20
            $recoveryNote = "Blob soft-delete not enabled or retention < 7 days"
        }
    }
    elseif ($type -like "microsoft.sql/servers/databases") {
        $recoveryScore = 80
        $recoveryNote = "Azure SQL provides point-in-time restore by default"
    }
    elseif ($type -like "microsoft.keyvault/vaults") {
        $sdEnabled = $false
        try { $sdEnabled = Get-ObjProperty -Obj $resProps.Properties -PropName 'enableSoftDelete' -Default $false } catch { }
        if ($sdEnabled) {
            $recoveryScore = 100
            $recoveryNote = "Key Vault soft-delete is enabled"
        }
        else {
            $recoveryScore = 0
            $recoveryNote = "Key Vault soft-delete is NOT enabled — data loss risk"
        }
    }

    # ── Weighted composite score ───────────────────────────────────────────────
    $compositeScore = [math]::Round(
        ($backupScore * $weights["Backup"] / 100) +
        ($haScore * $weights["HighAvailability"] / 100) +
        ($redundancyScore * $weights["Redundancy"] / 100) +
        ($drScore * $weights["DisasterRecovery"] / 100) +
        ($monitoringScore * $weights["Monitoring"] / 100) +
        ($recoveryScore * $weights["RecoveryConfig"] / 100)
    )

    $grade = if ($compositeScore -ge 85) { "Excellent" }
    elseif ($compositeScore -ge 70) { "Good" }
    elseif ($compositeScore -ge 50) { "Fair" }
    else { "Poor" }

    return [pscustomobject]@{
        BackupScore           = $backupScore
        BackupNote            = $backupNote
        HighAvailabilityScore = $haScore
        HighAvailabilityNote  = $haNote
        RedundancyScore       = $redundancyScore
        RedundancyNote        = $redundancyNote
        DisasterRecoveryScore = $drScore
        DisasterRecoveryNote  = $drNote
        MonitoringScore       = $monitoringScore
        MonitoringNote        = $monitoringNote
        RecoveryConfigScore   = $recoveryScore
        RecoveryConfigNote    = $recoveryNote
        ResilienceScore       = $compositeScore
        ResilienceGrade       = $grade
    }
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureResiliencePosture {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureResiliencePosture-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts", "Az.Resources", "Az.RecoveryServices",
        "Az.Monitor", "Az.Compute", "Az.Storage", "Az.Sql"
    )

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
    $allAssessments = @()
    $subscriptionResults = @()
    $gradeDist = @{ "Excellent" = 0; "Good" = 0; "Fair" = 0; "Poor" = 0 }
    $dimScoreSums = @{ "Backup" = 0; "HighAvailability" = 0; "Redundancy" = 0; "DisasterRecovery" = 0; "Monitoring" = 0; "RecoveryConfig" = 0 }
    $dimScoreCounts = @{ "Backup" = 0; "HighAvailability" = 0; "Redundancy" = 0; "DisasterRecovery" = 0; "Monitoring" = 0; "RecoveryConfig" = 0 }
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

            # ── Pre-fetch vault protected items (once per subscription) ───────
            $vaultProtectedItems = @()
            try {
                $vaults = @(Get-AzRecoveryServicesVault -ErrorAction Stop)
                foreach ($vault in $vaults) {
                    try {
                        Set-AzRecoveryServicesVaultContext -Vault $vault -ErrorAction Stop | Out-Null
                        $items = @(Get-AzRecoveryServicesBackupItem `
                                -WorkloadType AzureVM -BackupManagementType AzureVM -ErrorAction Stop)
                        $vaultProtectedItems += $items
                    }
                    catch {
                        Write-Verbose "  Could not retrieve protected items from vault '$($vault.Name)': $_"
                    }
                }
            }
            catch {
                Write-Verbose "  Could not enumerate Recovery Services Vaults for $($sub.Name): $_"
            }

            # ── Pre-fetch diagnostic settings for the subscription ────────────
            $diagWorkspaceMap = @{}
            try {
                $resources = @(Get-AzResource -ErrorAction Stop)
                foreach ($res in $resources) {
                    try {
                        $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $res.ResourceId -ErrorAction Stop)
                        $hasWs = $diagSettings | Where-Object {
                            $wsId = Get-ObjProperty -Obj $_ -PropName 'WorkspaceId' -Default ""
                            -not [string]::IsNullOrWhiteSpace($wsId)
                        }
                        $diagWorkspaceMap[$res.ResourceId] = ($null -ne $hasWs -and @($hasWs).Count -gt 0)
                    }
                    catch {
                        $diagWorkspaceMap[$res.ResourceId] = $false
                    }
                }
            }
            catch {
                Write-Warning "  Could not enumerate resources for $($sub.Name): $_"
                $resources = @()
            }

            $subAssessCount = 0

            foreach ($res in $resources) {
                # Skip resource types known not to support meaningful resilience scoring
                $skipTypes = @(
                    "Microsoft.Resources/resourceGroups",
                    "Microsoft.Authorization/roleAssignments",
                    "Microsoft.Authorization/roleDefinitions",
                    "Microsoft.Authorization/policyAssignments",
                    "Microsoft.Authorization/policyDefinitions",
                    "Microsoft.Network/networkSecurityGroups",
                    "Microsoft.Network/routeTables"
                )
                if ($skipTypes -contains $res.ResourceType) { continue }

                $hasWs = if ($diagWorkspaceMap.ContainsKey($res.ResourceId)) { $diagWorkspaceMap[$res.ResourceId] } else { $false }

                $scores = $null
                try {
                    $scores = Get-ResilienceScores `
                        -Resource             $res `
                        -SubscriptionId       $sub.Id `
                        -VaultProtectedItems  $vaultProtectedItems `
                        -HasDiagnosticWorkspace $hasWs
                }
                catch {
                    Write-Verbose "  Could not score '$($res.Name)' ($($res.ResourceType)): $_"
                    continue
                }

                $allAssessments += [pscustomobject]@{
                    SubscriptionName      = $sub.Name
                    SubscriptionId        = $sub.Id
                    ResourceName          = $res.Name
                    ResourceGroup         = $res.ResourceGroupName
                    ResourceType          = $res.ResourceType
                    Location              = Get-ObjProperty -Obj $res -PropName 'Location' -Default ""
                    ResourceId            = $res.ResourceId
                    ResilienceScore       = $scores.ResilienceScore
                    ResilienceGrade       = $scores.ResilienceGrade
                    BackupScore           = $scores.BackupScore
                    BackupNote            = $scores.BackupNote
                    HighAvailabilityScore = $scores.HighAvailabilityScore
                    HighAvailabilityNote  = $scores.HighAvailabilityNote
                    RedundancyScore       = $scores.RedundancyScore
                    RedundancyNote        = $scores.RedundancyNote
                    DisasterRecoveryScore = $scores.DisasterRecoveryScore
                    DisasterRecoveryNote  = $scores.DisasterRecoveryNote
                    MonitoringScore       = $scores.MonitoringScore
                    MonitoringNote        = $scores.MonitoringNote
                    RecoveryConfigScore   = $scores.RecoveryConfigScore
                    RecoveryConfigNote    = $scores.RecoveryConfigNote
                }

                if ($gradeDist.ContainsKey($scores.ResilienceGrade)) { $gradeDist[$scores.ResilienceGrade]++ }

                $dimScoreSums["Backup"] += $scores.BackupScore
                $dimScoreSums["HighAvailability"] += $scores.HighAvailabilityScore
                $dimScoreSums["Redundancy"] += $scores.RedundancyScore
                $dimScoreSums["DisasterRecovery"] += $scores.DisasterRecoveryScore
                $dimScoreSums["Monitoring"] += $scores.MonitoringScore
                $dimScoreSums["RecoveryConfig"] += $scores.RecoveryConfigScore

                foreach ($dim in $dimScoreCounts.Keys) { $dimScoreCounts[$dim]++ }

                $subAssessCount++
            }

            # ── Per-subscription result ───────────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Resources assessed: $subAssessCount" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Assessed: $subAssessCount"
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

    # ── Aggregate scores ──────────────────────────────────────────────────────
    $envScore = 0
    if ($allAssessments.Count -gt 0) {
        $envScore = [math]::Round(($allAssessments | Measure-Object -Property ResilienceScore -Average).Average)
    }

    $dimAvgScores = @{}
    foreach ($dim in $dimScoreSums.Keys) {
        $cnt = $dimScoreCounts[$dim]
        $dimAvgScores[$dim] = if ($cnt -gt 0) { [math]::Round($dimScoreSums[$dim] / $cnt) } else { 0 }
    }

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned"  = $subCount
            "Successful"                   = $successCount
            "Errors"                       = $errorCount
            "Total Resources Assessed"     = $allAssessments.Count
            "Environment Resilience Score" = "$envScore / 100"
            "Excellent (Score ≥ 85)"       = $gradeDist["Excellent"]
            "Good (Score 70-84)"           = $gradeDist["Good"]
            "Fair (Score 50-69)"           = $gradeDist["Fair"]
            "Poor (Score < 50)"            = $gradeDist["Poor"]
            "Execution Time"               = $duration
        })

    Write-ResilienceBreakdown -GradeDist $gradeDist

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allAssessments.Count -gt 0) {
        # CSV export
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allAssessments | Select-Object `
                    SubscriptionName, SubscriptionId, ResourceName, ResourceGroup,
                ResourceType, Location, ResilienceScore, ResilienceGrade,
                BackupScore, BackupNote,
                HighAvailabilityScore, HighAvailabilityNote,
                RedundancyScore, RedundancyNote,
                DisasterRecoveryScore, DisasterRecoveryNote,
                MonitoringScore, MonitoringNote,
                RecoveryConfigScore, RecoveryConfigNote |
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

            $htmlContent = Generate-ResiliencePostureHtml `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParams `
                -Assessments         $allAssessments `
                -GradeDistribution   $gradeDist `
                -DimensionAvgScores  $dimAvgScores `
                -SubscriptionResults $subscriptionResults `
                -EnvironmentScore    $envScore `
                -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

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
            $allAssessments |
            Select-Object SubscriptionName, ResourceName, ResourceType,
            ResilienceScore, ResilienceGrade,
            BackupScore, HighAvailabilityScore, RedundancyScore,
            DisasterRecoveryScore, MonitoringScore, RecoveryConfigScore |
            Out-GridView -Title "Azure Resilience Posture Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No resources could be assessed in the targeted subscriptions." -ForegroundColor Yellow
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
