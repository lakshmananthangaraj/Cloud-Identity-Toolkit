<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Identifies idle, unattached, and potentially oversized Azure resources
    that represent optimization opportunities across one or more subscriptions,
    producing a finding-based gap report from a Cloud Solution Architect
    and FinOps perspective.

.DESCRIPTION
    Get-AzureCostOptimizationGap scans Azure subscriptions for resource types
    that commonly accumulate waste or represent right-sizing opportunities.
    Every finding is evaluated for severity, financial impact confidence, and
    business-context caveats — acknowledging that apparently idle resources
    may be retained intentionally for DR, scheduled workloads, migration
    staging, or other valid reasons.

    Resource categories assessed:

        Compute
        ───────
        Stopped (non-deallocated) VMs
            VMs in a stopped-but-not-deallocated state still incur compute
            charges. Severity: High. Confidence: High — deallocating is
            always preferable when the VM is intentionally unused.

        Deallocated VMs (persistent disk cost)
            Deallocated VMs do not incur compute charges but their managed
            disks continue to accrue storage costs. Included as Low severity
            informational findings when -IncludeDeallocatedVMs is specified.
            Confidence: Low — many deallocated VMs are intentionally retained.

        Storage
        ───────
        Unattached managed disks
            Managed disks with DiskState = Unattached are paying for storage
            with no active consumer. Severity: High. Confidence: High.

        Snapshots older than -SnapshotAgeThresholdDays (default: 90)
            Old snapshots accumulate silently and are rarely revisited.
            Severity: Medium. Confidence: Medium — some are retained for
            compliance, DR, or rollback purposes.

        Networking
        ──────────
        Unassociated public IP addresses
            Static/standard public IPs that are not attached to any resource
            incur a reservation charge. Severity: Medium. Confidence: High.

        Unassociated network interfaces
            NICs not linked to a VM signal lifecycle hygiene gaps and may
            indicate orphaned deployments. Severity: Low. Confidence: Medium.

        Load balancers with empty backend pools
            Standard-tier load balancers with no backend pool members are
            paying the per-rule/per-hour charge with no traffic benefit.
            Severity: Medium. Confidence: Medium — pools may be temporarily
            empty during a migration or blue/green switch.

        App Service
        ───────────
        Empty or underutilised App Service Plans
            Plans at Standard tier or above with zero deployed apps, or plans
            where the number of hosted apps is below the configured minimum.
            Severity: Medium. Confidence: Medium — plans may be reserved for
            imminent deployments.

        Resource Management
        ───────────────────
        Empty resource groups
            Resource groups containing zero resources add no value and create
            management overhead. Severity: Low. Confidence: Low — some are
            kept as templates or placeholders.

    Finding severity, financial impact, and confidence columns are included
    to help architects triage findings and avoid false-positive remediation.

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and colour-coded per-subscription console output
        - Per-subscription optimization gap score (High/Medium/Low/Minimal)
        - Optional CSV export of all findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable
          table, bar charts, finding-category distribution, detail drawer)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behaviour when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER SnapshotAgeThresholdDays
    Integer. Snapshots older than this many days are flagged as findings.
    Default: 90.

.PARAMETER IncludeDeallocatedVMs
    Switch. When specified, deallocated VMs are included as Low severity
    informational findings (persistent managed-disk cost only; no compute
    charge). Disabled by default to reduce noise — most deallocated VMs
    are intentionally retained.

.PARAMETER ExportToCsv
    Switch. If specified, exports all findings to the path given in
    -OutputDirectory. The HTML dashboard is always generated regardless.

.PARAMETER OutputDirectory
    Directory where the CSV and HTML files will be written.
    Default: C:\Temp

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard to
    -OutputDirectory. Optionally writes a CSV file when -ExportToCsv is
    specified. Displays results in an interactive Grid View where a GUI
    is available.

.EXAMPLE
    Get-AzureCostOptimizationGap -AllSubscriptions

.EXAMPLE
    Get-AzureCostOptimizationGap -AllSubscriptions -IncludeDeallocatedVMs -ExportToCsv

.EXAMPLE
    Get-AzureCostOptimizationGap -SubscriptionIds @("sub-id-1","sub-id-2") -SnapshotAgeThresholdDays 60

.EXAMPLE
    Get-AzureCostOptimizationGap -AllSubscriptions -ExportToCsv -OutputDirectory "C:\Reports"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Stopped VMs, unattached disks,
                            old snapshots, idle public IPs, orphaned NICs,
                            empty LBs, underutilised ASPs, empty RGs.
                            Per-subscription gap scoring, severity/confidence
                            classification, CSV export, HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az.Accounts  — Get-AzContext, Get-AzSubscription, Set-AzContext
        2. Az.Compute   — Get-AzVM, Get-AzDisk, Get-AzSnapshot
        3. Az.Network   — Get-AzNetworkInterface, Get-AzPublicIpAddress,
                          Get-AzLoadBalancer
        4. Az.Resources — Get-AzResourceGroup
        5. Az.Websites  — Get-AzAppServicePlan, Get-AzWebApp
        6. Authenticated Azure session (Connect-AzAccount).
        7. Reader role (minimum) at subscription scope for all resource
           enumeration. No write permissions are required or requested.

    ─────────────────────────────────────────────────────────────────────────────
    Important Notes on Financial Impact:
    ─────────────────────────────────────────────────────────────────────────────
        - Financial impact columns are qualitative (High/Medium/Low), not
          monetary estimates. Actual cost depends on SKU, region, retention
          policy, tier, and your specific billing agreement.
        - Confidence reflects how likely it is that a finding represents
          genuine, remediable waste — not the certainty of the resource
          being flagged. Low confidence findings should be reviewed with
          resource owners before any remediation action.
        - Stopped (non-deallocated) VMs are the highest-confidence finding
          because simply deallocating stops the compute charge with no
          functional impact on the disk or configuration.
        - Deallocated VMs, old snapshots, and empty LBs may be intentionally
          retained. Always confirm with the workload owner before deletion.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The script does not assess CPU/memory utilisation metrics. Oversized
          but running VMs require Azure Monitor data and are out of scope.
        - App Service assessment uses app count as a proxy for utilisation.
          Premium V3 plans with one app may still be appropriately sized.
        - Load balancer assessment checks backend pool membership at the ARM
          level only; active NATted connections are not verified.
        - Empty resource group detection includes system-managed RGs
          (e.g. NetworkWatcherRG, cloud-shell-storage-*) which are typically
          expected to be empty or lightly populated.
        - Interactive Grid View requires a GUI-capable session. Skipped
          gracefully in headless/CI/Linux sessions; CSV/HTML output is
          unaffected.
        - Default -OutputDirectory (C:\Temp) is Windows-specific. Supply an
          explicit -OutputDirectory on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/advisor/advisor-cost-recommendations
    https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/cost-mgt-best-practices
    https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/finops/

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CoCenteredText {
  param(
    [string]$Text,
    [int]$Width = 80,
    [string]$Color = "White"
  )
  $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
  Write-Host (" " * $padding) -NoNewline
  Write-Host $Text -ForegroundColor $Color
}

Function Write-CoBanner {
  Clear-Host
  Write-Host ""
  Write-Host ("═" * 80) -ForegroundColor Cyan
  Write-CoCenteredText "Azure Cost Optimization Gap Assessment v1.0" -Color White
  Write-Host ("═" * 80) -ForegroundColor Cyan
  Write-Host ""
}

Function Write-CoSection {
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
      $value    = "None"
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

Function Write-CoScanProgress {
  Write-Host ""
  Write-Host "  Scanning Subscriptions" -ForegroundColor Cyan
  Write-Host "  " -NoNewline
  Write-Host ("─" * 76) -ForegroundColor DarkGray
  Write-Host ""
}

Function Write-CoProgressBar {
  param(
    [int]$Current,
    [int]$Total,
    [string]$CurrentItem,
    [int]$BarWidth = 40
  )
  $percentage = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
  $completed  = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
  $remaining  = $BarWidth - $completed
  $bar = ("█" * $completed) + ("░" * $remaining)
  Write-Host "`r" -NoNewline
  Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
  Write-Host $bar -NoNewline -ForegroundColor Cyan
  Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White
  if ($CurrentItem) {
    $maxLen      = 35
    $displayItem = if ($CurrentItem.Length -gt $maxLen) { $CurrentItem.Substring(0, $maxLen - 3) + "..." } else { $CurrentItem }
    Write-Host " | " -NoNewline -ForegroundColor DarkGray
    Write-Host "Current: " -NoNewline -ForegroundColor Gray
    Write-Host $displayItem -NoNewline -ForegroundColor Cyan
  }
}

Function Write-CoSummary {
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

Function Write-CoGapSummary {
  param([array]$SubResults)
  if ($SubResults.Count -eq 0) { return }
  $high    = @($SubResults | Where-Object { $_.GapScore -eq "High" }).Count
  $medium  = @($SubResults | Where-Object { $_.GapScore -eq "Medium" }).Count
  $low     = @($SubResults | Where-Object { $_.GapScore -eq "Low" }).Count
  $minimal = @($SubResults | Where-Object { $_.GapScore -eq "Minimal" }).Count
  Write-Host ""
  Write-Host "  Optimization Gap Score" -ForegroundColor Cyan
  Write-Host "  " -NoNewline
  Write-Host ("─" * 76) -ForegroundColor DarkGray
  Write-Host "  High Gap     : $high subscription(s)" -ForegroundColor Red
  Write-Host "  Medium Gap   : $medium subscription(s)" -ForegroundColor Yellow
  Write-Host "  Low Gap      : $low subscription(s)" -ForegroundColor Cyan
  Write-Host "  Minimal Gap  : $minimal subscription(s)" -ForegroundColor Green
}

Function Write-CoOutputFiles {
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


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-CostOptimizationHtml {
  param(
    [hashtable]$SessionInfo,
    [hashtable]$ScanParameters,
    [array]$AllFindings,
    [array]$SubResults,
    [array]$SubscriptionResults,
    [string]$GeneratedOn
  )

  $totalFindings   = @($AllFindings).Count
  $highFindings    = @($AllFindings | Where-Object { $_.Severity -eq "High"   }).Count
  $mediumFindings  = @($AllFindings | Where-Object { $_.Severity -eq "Medium" }).Count
  $lowFindings     = @($AllFindings | Where-Object { $_.Severity -eq "Low"    }).Count

  # ── Category distribution — count per finding category ───────────────────
  $categoryMap = @{}
  foreach ($f in $AllFindings) {
    if (-not $categoryMap.ContainsKey($f.Category)) { $categoryMap[$f.Category] = 0 }
    $categoryMap[$f.Category]++
  }

  # ── Severity distribution bars ────────────────────────────────────────────
  $sevColors = @{ High = "var(--red)"; Medium = "var(--amber)"; Low = "var(--accent2)" }
  $sevRows   = ""
  foreach ($sev in @("High", "Medium", "Low")) {
    $count = @($AllFindings | Where-Object { $_.Severity -eq $sev }).Count
    $pct   = if ($totalFindings -gt 0) { [math]::Round(($count / $totalFindings) * 100) } else { 0 }
    $sevRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $sev) Severity</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$($sevColors[$sev])"></div></div>
            <span class="bar-pct">$count ($pct%)</span>
          </div>
"@
  }

  # ── Category distribution bars ────────────────────────────────────────────
  $catRows = ""
  foreach ($cat in ($categoryMap.GetEnumerator() | Sort-Object Value -Descending)) {
    $pct = if ($totalFindings -gt 0) { [math]::Round(($cat.Value / $totalFindings) * 100) } else { 0 }
    $catRows += @"
          <div class="bar-row">
            <span class="bar-label" title="$(EscHtml $cat.Key)">$(EscHtml $cat.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($cat.Value) ($pct%)</span>
          </div>
"@
  }

  # ── Gap score distribution bars ───────────────────────────────────────────
  $gapDist   = @{ High = 0; Medium = 0; Low = 0; Minimal = 0 }
  $gapColors = @{ High = "var(--red)"; Medium = "var(--amber)"; Low = "var(--accent2)"; Minimal = "var(--green)" }
  foreach ($s in $SubResults) {
    if ($gapDist.ContainsKey($s.GapScore)) { $gapDist[$s.GapScore]++ }
  }
  $gapRows = ""
  foreach ($key in @("High", "Medium", "Low", "Minimal")) {
    $count = $gapDist[$key]
    $pct   = if ($SubResults.Count -gt 0) { [math]::Round(($count / $SubResults.Count) * 100) } else { 0 }
    $gapRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $key) Gap</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$($gapColors[$key])"></div></div>
            <span class="bar-pct">$count ($pct%)</span>
          </div>
"@
  }

  # ── Top 5 subscriptions by total finding count ───────────────────────────
  $topSubsHtml = ""
  foreach ($s in ($SubResults | Sort-Object TotalFindings -Descending | Select-Object -First 5)) {
    $icon = switch ($s.GapScore) { "High" { "🔴" }; "Medium" { "🟠" }; "Low" { "🔵" }; default { "🟢" } }
    $cls  = switch ($s.GapScore) { "High" { "c-red" }; "Medium" { "c-amber" }; "Low" { "c-cyan" }; default { "c-green" } }
    $topSubsHtml += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $s.SubscriptionName)</span>
            <span class="sub-detail">Gap Score: $(EscHtml $s.GapScore) · $($s.TotalFindings) finding(s) · $($s.HighFindings) High</span>
          </div>
"@
  }

  # ── Findings table rows (main table) ─────────────────────────────────────
  $findingRows  = ""
  $severitySort = @{ High = 0; Medium = 1; Low = 2 }
  $findingsSorted = @($AllFindings | Sort-Object `
      @{ Expression = { $severitySort[$_.Severity] } },
      @{ Expression = { $_.Category } })

  $sevBadgeMap    = @{ High = "badge-red"; Medium = "badge-amber"; Low = "badge-cyan" }
  $impactBadgeMap = @{ High = "badge-red"; Medium = "badge-amber"; Low = "" }
  $confBadgeMap   = @{ High = "badge-green"; Medium = "badge-amber"; Low = "badge-muted" }

  foreach ($f in $findingsSorted) {
    $idx     = $findingsSorted.IndexOf($f)
    $sCls    = if ($sevBadgeMap.ContainsKey($f.Severity))      { $sevBadgeMap[$f.Severity] }    else { "" }
    $iCls    = if ($impactBadgeMap.ContainsKey($f.Impact))     { $impactBadgeMap[$f.Impact] }   else { "" }
    $cCls    = if ($confBadgeMap.ContainsKey($f.Confidence))   { $confBadgeMap[$f.Confidence] } else { "" }
    $rscName = if ($f.ResourceName.Length -gt 30) { $f.ResourceName.Substring(0, 27) + "..." } else { $f.ResourceName }

    $findingRows += @"
          <tr onclick="showFindingDetail($idx)">
            <td><span class="badge $sCls">$(EscHtml $f.Severity)</span></td>
            <td>$(EscHtml $f.Category)</td>
            <td title="$(EscHtml $f.ResourceName)">$(EscHtml $rscName)</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td style="font-size:11px;color:var(--muted2)">$(EscHtml $f.ResourceGroup)</td>
            <td><span class="badge $iCls">$(EscHtml $f.Impact)</span></td>
            <td><span class="badge $cCls">$(EscHtml $f.Confidence)</span></td>
          </tr>
"@
  }

  # ── Subscription gap score tab rows ──────────────────────────────────────
  $subGapRows = ""
  foreach ($s in ($SubResults | Sort-Object @{ Expression = { $severitySort[$_.GapScore] ?? 3 }; Ascending = $true })) {
    $icon = switch ($s.GapScore) { "High" { "🔴" }; "Medium" { "🟠" }; "Low" { "🔵" }; default { "🟢" } }
    $cls  = switch ($s.GapScore) { "High" { "c-red" }; "Medium" { "c-amber" }; "Low" { "c-cyan" }; default { "c-green" } }
    $subGapRows += @"
          <tr>
            <td>$(EscHtml $s.SubscriptionName)</td>
            <td style="text-align:center">$icon</td>
            <td>$(EscHtml $s.GapScore)</td>
            <td style="text-align:center;font-family:var(--mono)">$($s.TotalFindings)</td>
            <td style="text-align:center;font-family:var(--mono);color:var(--red)">$($s.HighFindings)</td>
            <td style="text-align:center;font-family:var(--mono);color:var(--amber)">$($s.MediumFindings)</td>
            <td style="text-align:center;font-family:var(--mono);color:var(--accent2)">$($s.LowFindings)</td>
          </tr>
"@
  }

  # ── Subscription scan results rows ───────────────────────────────────────
  $subRows = ""
  foreach ($s in $SubscriptionResults) {
    $icon = switch ($s.Status) { "Success" { "✓" }; "Warning" { "⚠" }; "Error" { "✗" }; default { "•" } }
    $cls  = switch ($s.Status) { "Success" { "c-green" }; "Warning" { "c-amber" }; "Error" { "c-red" }; default { "" } }
    $subRows += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $s.Name)</span>
            <span class="sub-detail">$(EscHtml $s.Summary)</span>
          </div>
"@
  }

  # ── JSON for findings detail drawer ──────────────────────────────────────
  $findingsJson = "["
  foreach ($f in $findingsSorted) {
    $findingsJson += "{" +
      """severity"":""$(EscJ $f.Severity)""," +
      """category"":""$(EscJ $f.Category)""," +
      """resourceName"":""$(EscJ $f.ResourceName)""," +
      """resourceType"":""$(EscJ $f.ResourceType)""," +
      """resourceGroup"":""$(EscJ $f.ResourceGroup)""," +
      """location"":""$(EscJ $f.Location)""," +
      """sub"":""$(EscJ $f.SubscriptionName)""," +
      """finding"":""$(EscJ $f.Finding)""," +
      """impact"":""$(EscJ $f.Impact)""," +
      """confidence"":""$(EscJ $f.Confidence)""," +
      """recommendation"":""$(EscJ $f.Recommendation)""," +
      """caveat"":""$(EscJ $f.Caveat)""," +
      """detail"":""$(EscJ $f.Detail)""" +
      "},"
  }
  $findingsJson = $findingsJson.TrimEnd(",") + "]"

  $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Cost Optimization Gap Dashboard</title>
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
#sidebar{width:240px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:transform .25s;}
.logo-block{padding:22px 18px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{display:inline-block;margin-top:8px;padding:2px 8px;border-radius:20px;font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent);border:1px solid var(--border);}
.nav-section{padding:14px 10px;flex:1;}
.nav-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;padding:0 8px;margin-bottom:6px;}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 12px;border:none;background:transparent;color:var(--muted2);font-size:13px;border-radius:var(--radius-sm);cursor:pointer;text-align:left;transition:background .15s,color .15s;position:relative;margin-bottom:2px;}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:var(--surface3);color:var(--accent);font-weight:600;}
.nav-btn.active::before{content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;background:var(--accent);border-radius:0 3px 3px 0;}
.nav-icon{font-size:16px;width:20px;text-align:center;}
.sidebar-footer{padding:14px 16px;border-top:1px solid var(--border);}
.theme-toggle{display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:10px;}
.toggle-pill{width:40px;height:22px;border-radius:11px;border:none;cursor:pointer;background:var(--surface3);position:relative;transition:background .2s;}
.toggle-pill::after{content:'';position:absolute;top:3px;left:3px;width:16px;height:16px;border-radius:50%;background:var(--accent);transition:transform .2s;}
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
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;cursor:default;}
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
.bar-label{font-size:12px;color:var(--muted2);width:160px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;}
.search-wrap input{width:100%;padding:8px 12px 8px 34px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;outline:none;}
.search-wrap input:focus{border-color:var(--accent);}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:14px;}
.filter-select{padding:7px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:12px;cursor:pointer;}
.tbl-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{padding:10px 12px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);background:var(--surface2);border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap;user-select:none;}
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
.badge-cyan{background:rgba(57,197,207,.15);color:var(--accent2);border:1px solid rgba(57,197,207,.3);}
.badge-muted{background:var(--surface3);color:var(--muted);border:1px solid var(--border);}
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
.sub-icon.c-cyan{color:var(--accent2);}
.sub-name{flex:1;font-size:13px;font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:460px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
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
.caveat-box{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.3);border-radius:var(--radius-sm);padding:10px 12px;font-size:12px;color:var(--amber);margin-top:8px;line-height:1.5;}
#toast{position:fixed;bottom:24px;right:24px;padding:12px 18px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);font-size:13px;box-shadow:var(--shadow);opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:300;}
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
    <div class="logo-icon">📉</div>
    <div class="logo-title">Cost Optimization Gap</div>
    <div class="logo-sub">Azure FinOps Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> Resource Findings</button>
    <button class="nav-btn" onclick="showPage('gapscore',this)"><span class="nav-icon">📈</span> Gap Score</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">🗂️</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Azure Cost Optimization Gap
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Cost Optimization Gap Overview</div>
      <div class="page-sub">Resource-level waste and right-sizing opportunities across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_FINDINGS__</div>
        <div class="stat-label">Total Findings</div>
        <div class="stat-sub">Across all categories</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__HIGH_FINDINGS__</div>
        <div class="stat-label">High Severity</div>
        <div class="stat-sub">Prioritize for remediation</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MEDIUM_FINDINGS__</div>
        <div class="stat-label">Medium Severity</div>
        <div class="stat-sub">Review with owners</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__LOW_FINDINGS__</div>
        <div class="stat-label">Low Severity</div>
        <div class="stat-sub">Informational</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__CATEGORIES__</div>
        <div class="stat-label">Finding Categories</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__SUB_COUNT__</div>
        <div class="stat-label">Subscriptions</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">⚠️ Findings by Severity</div>
        __SEV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">📦 Findings by Category</div>
        __CAT_ROWS__
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📈 Gap Score Distribution</div>
        __GAP_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🔴 Subscriptions with Most Findings</div>
        <div class="sub-list">__TOP_SUBS__</div>
      </div>
    </div>
  </div>

  <!-- Resource Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Resource Findings</div>
      <div class="page-sub">Click any row for the full finding detail, recommendation, and business-context caveat.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findingSearch" placeholder="Search resource, subscription, category…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="filterCat" onchange="filterFindings()">
          <option value="">All Categories</option>
          __CAT_OPTIONS__
        </select>
        <select class="filter-select" id="pgSizeFinding" onchange="changeFindingPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="findingTable">
          <thead>
            <tr>
              <th onclick="sortFindings(0)">Severity</th>
              <th onclick="sortFindings(1)">Category</th>
              <th onclick="sortFindings(2)">Resource</th>
              <th onclick="sortFindings(3)">Subscription</th>
              <th onclick="sortFindings(4)">Resource Group</th>
              <th onclick="sortFindings(5)">Impact</th>
              <th onclick="sortFindings(6)">Confidence</th>
            </tr>
          </thead>
          <tbody id="findingBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findingPagination"></div>
    </div>
  </div>

  <!-- Gap Score -->
  <div id="page-gapscore" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Gap Score</div>
      <div class="page-sub">Per-subscription optimization gap rating based on total, high, and medium finding counts</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Subscription</th>
              <th style="text-align:center">Rating</th>
              <th>Gap Score</th>
              <th style="text-align:center">Total</th>
              <th style="text-align:center">High</th>
              <th style="text-align:center">Medium</th>
              <th style="text-align:center">Low</th>
            </tr>
          </thead>
          <tbody>__SUB_GAP_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription optimization gap assessment outcome</div>
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
        <div class="info-card"><div class="info-label">Snapshot Age Threshold</div><div class="info-value">__SNAPSHOT_DAYS__ days</div></div>
        <div class="info-card"><div class="info-label">Deallocated VMs Included</div><div class="info-value">__DEALLOC_INCLUDED__</div></div>
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
    <span class="drawer-title" id="drawerTitle">Finding Detail</span>
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
const FINDING_DATA = __FINDINGS_JSON__;
let findingFiltered = [...FINDING_DATA];
let findingPage = 1, findingPageSz = 25;
let findingSortCol = -1, findingSortAsc = true;
let currentDetailIdx = 0;

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

// ── Findings table ─────────────────────────────────────────────────────────────
const sevBadge   = {High:'badge-red',Medium:'badge-amber',Low:'badge-cyan'};
const impBadge   = {High:'badge-red',Medium:'badge-amber',Low:''};
const confBadge  = {High:'badge-green',Medium:'badge-amber',Low:'badge-muted'};
const sevRank    = {High:0,Medium:1,Low:2};

function filterFindings(){
  const q=document.getElementById('findingSearch').value.toLowerCase();
  const s=document.getElementById('filterSev').value;
  const c=document.getElementById('filterCat').value;
  findingFiltered=FINDING_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mS=!s||r.severity===s;
    const mC=!c||r.category===c;
    return mQ&&mS&&mC;
  });
  findingPage=1; renderFindings();
}

function changeFindingPageSize(){
  findingPageSz=parseInt(document.getElementById('pgSizeFinding').value);
  findingPage=1; renderFindings();
}

function sortFindings(col){
  if(findingSortCol===col){findingSortAsc=!findingSortAsc;}else{findingSortCol=col;findingSortAsc=true;}
  const keys=['severity','category','resourceName','sub','resourceGroup','impact','confidence'];
  findingFiltered.sort((a,b)=>{
    const k=keys[col];
    let av=a[k]??'', bv=b[k]??'';
    if(k==='severity'){av=sevRank[av]??9;bv=sevRank[bv]??9;}
    return findingSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                         :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderFindings();
}

function renderFindings(){
  const tbody=document.getElementById('findingBody');
  const start=(findingPage-1)*findingPageSz;
  const slice=findingFiltered.slice(start,start+findingPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=FINDING_DATA.indexOf(r);
    const nm=r.resourceName.length>30?r.resourceName.substring(0,27)+'...':r.resourceName;
    const sCls=sevBadge[r.severity]||'';
    const iCls=impBadge[r.impact]||'';
    const cCls=confBadge[r.confidence]||'';
    return `<tr onclick="showFindingDetail(${gi})">
      <td><span class="badge ${sCls}">${escH(r.severity)}</span></td>
      <td>${escH(r.category)}</td>
      <td title="${escH(r.resourceName)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td style="font-size:11px;color:var(--muted2)">${escH(r.resourceGroup)}</td>
      <td><span class="badge ${iCls}">${escH(r.impact)}</span></td>
      <td><span class="badge ${cCls}">${escH(r.confidence)}</span></td>
    </tr>`;
  }).join('');
  renderFindingPg();
}

function renderFindingPg(){
  const total=Math.ceil(findingFiltered.length/findingPageSz);
  const el=document.getElementById('findingPagination');
  let h=`<span>${findingFiltered.length} findings</span>`;
  h+=`<button class="pg-btn" onclick="changeFindingPage(${findingPage-1})" ${findingPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,findingPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findingPage?'active':''}" onclick="changeFindingPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeFindingPage(${findingPage+1})" ${findingPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeFindingPage(p){
  const total=Math.ceil(findingFiltered.length/findingPageSz);
  if(p<1||p>total)return;
  findingPage=p; renderFindings();
}

// ── Finding detail drawer ───────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=FINDING_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.resourceName;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FINDING_DATA.length}`;
  const sCls=sevBadge[r.severity]||'';
  const iCls=impBadge[r.impact]||'';
  const cCls=confBadge[r.confidence]||'';
  const caveatBlock=r.caveat?`<div class="caveat-box">⚠ ${escH(r.caveat)}</div>`:'';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Severity / Impact / Confidence</div>
      <div class="drawer-field-value" style="display:flex;gap:6px;flex-wrap:wrap">
        <span class="badge ${sCls}">${escH(r.severity)}</span>
        <span class="badge ${iCls}">Impact: ${escH(r.impact)}</span>
        <span class="badge ${cCls}">Confidence: ${escH(r.confidence)}</span>
      </div></div>
    <div class="drawer-field"><div class="drawer-field-label">Category</div>
      <div class="drawer-field-value">${escH(r.category)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Type</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.resourceType)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group / Location</div>
      <div class="drawer-field-value">${escH(r.resourceGroup)} · ${escH(r.location)}</div></div>
    <div class="drawer-section">Finding</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.finding)}</div></div>
    ${r.detail?`<div class="drawer-field"><div class="drawer-field-label">Detail</div><div class="drawer-field-value" style="font-size:12px;color:var(--muted2)">${escH(r.detail)}</div></div>`:''}
    <div class="drawer-section">Recommendation</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.recommendation)}</div></div>
    ${caveatBlock}
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
  if(next>=0&&next<FINDING_DATA.length) showFindingDetail(next);
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

// ── Init ──────────────────────────────────────────────────────────────────────
filterFindings();
animateBars();
</script>
</body>
</html>
'@

  # Build category filter <option> elements for the findings page dropdown
  $catOptions = ""
  foreach ($cat in ($categoryMap.Keys | Sort-Object)) {
    $catOptions += "          <option value=`"$(EscHtml $cat)`">$(EscHtml $cat)</option>`n"
  }

  $html = $html `
    -replace '__GENERATED_ON__',    $GeneratedOn `
    -replace '__SUB_COUNT__',       ($SubscriptionResults.Count) `
    -replace '__TOTAL_FINDINGS__',  $totalFindings `
    -replace '__HIGH_FINDINGS__',   $highFindings `
    -replace '__MEDIUM_FINDINGS__', $mediumFindings `
    -replace '__LOW_FINDINGS__',    $lowFindings `
    -replace '__CATEGORIES__',      ($categoryMap.Keys.Count) `
    -replace '__SEV_ROWS__',        $sevRows `
    -replace '__CAT_ROWS__',        $catRows `
    -replace '__GAP_ROWS__',        $gapRows `
    -replace '__TOP_SUBS__',        $topSubsHtml `
    -replace '__FINDING_ROWS__',    $findingRows `
    -replace '__CAT_OPTIONS__',     $catOptions `
    -replace '__SUB_GAP_ROWS__',    $subGapRows `
    -replace '__SUB_ROWS__',        $subRows `
    -replace '__TENANT__',          $SessionInfo.Tenant `
    -replace '__ACCOUNT__',         $SessionInfo.Account `
    -replace '__ENVIRONMENT__',     $SessionInfo.Environment `
    -replace '__SCOPE__',           $ScanParameters.Scope `
    -replace '__SNAPSHOT_DAYS__',   $ScanParameters.SnapshotDays `
    -replace '__DEALLOC_INCLUDED__',$ScanParameters.DeallocIncluded `
    -replace '__EXPORT_ENABLED__',  $ScanParameters.ExportEnabled `
    -replace '__EXEC_TIME__',       $ScanParameters.ExecTime `
    -replace '__FINDINGS_JSON__',   $findingsJson

  return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureCostOptimizationGap {
  [CmdletBinding()]
  param (
    [switch]$AllSubscriptions,

    [string[]]$SubscriptionIds,

    [ValidateRange(1, 3650)]
    [int]$SnapshotAgeThresholdDays = 90,

    [switch]$IncludeDeallocatedVMs,

    [switch]$ExportToCsv,

    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = "C:\Temp"
  )

  $startTime = Get-Date

  Write-CoBanner

  # ── Module check ──────────────────────────────────────────────────────────
  # Az.Accounts  : Get-AzContext, Get-AzSubscription, Set-AzContext
  # Az.Compute   : Get-AzVM, Get-AzDisk, Get-AzSnapshot
  # Az.Network   : Get-AzNetworkInterface, Get-AzPublicIpAddress, Get-AzLoadBalancer
  # Az.Resources : Get-AzResourceGroup
  # Az.Websites  : Get-AzAppServicePlan, Get-AzWebApp
  $requiredModules = @("Az.Accounts", "Az.Compute", "Az.Network", "Az.Resources", "Az.Websites")

  $missingModules = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

  if ($missingModules) {
    Write-Host "  ✗ Required Az module(s) not found: $($missingModules -join ', ')" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Install them manually with:" -ForegroundColor Yellow
    foreach ($m in $missingModules) {
      Write-Host "      Install-Module -Name $m -Scope CurrentUser -AllowClobber -Force" -ForegroundColor Gray
    }
    Write-Host ""
    return
  }

  # ── Authentication ────────────────────────────────────────────────────────
  $ctx = Get-AzContext -ErrorAction SilentlyContinue
  if (-not $ctx) {
    Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
    Connect-AzAccount -WarningAction SilentlyContinue
    $ctx = Get-AzContext
  }

  # ── Subscription resolution ───────────────────────────────────────────────
  if ($AllSubscriptions -or -not $SubscriptionIds) {
    $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
    $scopeText     = "All Subscriptions"
  }
  else {
    $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
      Where-Object { $SubscriptionIds -contains $_.Id })
    $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count))"
  }

  $subCount = $subscriptions.Count

  # ── Validate output directory ─────────────────────────────────────────────
  if (-not (Test-Path $OutputDirectory)) {
    try {
      New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    catch {
      Write-Host "  ✗ Cannot create output directory '$OutputDirectory': $_" -ForegroundColor Red
      return
    }
  }

  # ── Display session / params ──────────────────────────────────────────────
  Write-CoSection -Title "Session Information" -Data @{
    "Tenant"      = $ctx.Tenant.Id
    "Account"     = $ctx.Account.Id
    "Environment" = $ctx.Environment.Name
  }

  Write-CoSection -Title "Scan Parameters" -Data @{
    "Scope"                  = "$scopeText ($subCount found)"
    "Snapshot Age Threshold" = "$SnapshotAgeThresholdDays days"
    "Deallocated VMs"        = if ($IncludeDeallocatedVMs.IsPresent) { "Included (Low severity, informational)" } else { "Excluded (use -IncludeDeallocatedVMs to include)" }
    "Export to CSV"          = if ($ExportToCsv.IsPresent) { "Enabled — $OutputDirectory" } else { "Disabled" }
  }

  # ── Collections ───────────────────────────────────────────────────────────
  $allFindings         = @()
  $allSubResults       = @()
  $subscriptionResults = @()
  $successCount        = 0
  $errorCount          = 0
  $snapshotCutoff      = (Get-Date).AddDays(-$SnapshotAgeThresholdDays)

  # ── Scan ──────────────────────────────────────────────────────────────────
  Write-CoScanProgress
  Write-CoProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

  $maxNameLen = ([math]::Max(
      ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
      35
    ))

  $subIndex = 1

  foreach ($sub in $subscriptions) {
    $subFindings = @()

    try {
      Write-CoProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

      Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

      # Helper: build a finding object consistently
      $newFinding = {
        param($Category, $Severity, $Impact, $Confidence, $ResourceName, $ResourceType,
              $ResourceGroup, $Location, $Finding, $Recommendation, $Caveat, $Detail)
        [pscustomobject]@{
          SubscriptionName = $sub.Name
          SubscriptionId   = $sub.Id
          Category         = $Category
          Severity         = $Severity
          Impact           = $Impact
          Confidence       = $Confidence
          ResourceName     = $ResourceName
          ResourceType     = $ResourceType
          ResourceGroup    = $ResourceGroup
          Location         = $Location
          Finding          = $Finding
          Recommendation   = $Recommendation
          Caveat           = $Caveat
          Detail           = $Detail
        }
      }

      # ── Compute: Stopped (non-deallocated) VMs ────────────────────────
      try {
        $vms = @(Get-AzVM -Status -ErrorAction Stop)
        foreach ($vm in $vms) {
          $powerState = ($vm.Statuses | Where-Object { $_.Code -match "^PowerState/" } |
            Select-Object -First 1).DisplayStatus

          if ($powerState -eq "VM stopped") {
            # Stopped but NOT deallocated — compute billing is still active
            $subFindings += & $newFinding `
              -Category       "Stopped VM" `
              -Severity       "High" `
              -Impact         "High" `
              -Confidence     "High" `
              -ResourceName   $vm.Name `
              -ResourceType   "Microsoft.Compute/virtualMachines" `
              -ResourceGroup  $vm.ResourceGroupName `
              -Location       $vm.Location `
              -Finding        "VM is stopped but not deallocated. Compute charges continue to accrue because the allocation is still held." `
              -Recommendation "Deallocate the VM (Stop-AzVM -Deallocate) to stop compute billing. The OS disk and configuration are preserved. Restart is identical to a full cold start." `
              -Caveat         "Confirm the VM is not stopped intentionally before a scheduled maintenance window or a dependent deployment step. Verify with the resource owner." `
              -Detail         "Power state: $powerState · Size: $($vm.HardwareProfile.VmSize)"
          }
          elseif ($powerState -eq "VM deallocated" -and $IncludeDeallocatedVMs.IsPresent) {
            # Deallocated — no compute charge, but managed disks still cost
            $subFindings += & $newFinding `
              -Category       "Deallocated VM" `
              -Severity       "Low" `
              -Impact         "Low" `
              -Confidence     "Low" `
              -ResourceName   $vm.Name `
              -ResourceType   "Microsoft.Compute/virtualMachines" `
              -ResourceGroup  $vm.ResourceGroupName `
              -Location       $vm.Location `
              -Finding        "VM is deallocated. No compute charge, but attached managed disks continue to incur storage costs." `
              -Recommendation "If the VM is no longer needed, consider deleting it along with its associated disks and NICs to eliminate all remaining charges. If retained for DR or future use, this finding is informational only." `
              -Caveat         "Deallocated VMs are commonly retained intentionally for DR standby, cost-saving outside business hours, migration staging, or test environments. Do not delete without confirming with the workload owner." `
              -Detail         "Power state: $powerState · Size: $($vm.HardwareProfile.VmSize)"
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve VMs for $($sub.Name): $_"
      }

      # ── Storage: Unattached managed disks ─────────────────────────────
      try {
        $disks = @(Get-AzDisk -ErrorAction Stop)
        foreach ($disk in $disks) {
          if ($disk.DiskState -eq "Unattached") {
            $sku  = $disk.Sku.Name
            $size = "$($disk.DiskSizeGB) GiB"
            $subFindings += & $newFinding `
              -Category       "Unattached Disk" `
              -Severity       "High" `
              -Impact         "High" `
              -Confidence     "High" `
              -ResourceName   $disk.Name `
              -ResourceType   "Microsoft.Compute/disks" `
              -ResourceGroup  $disk.ResourceGroupName `
              -Location       $disk.Location `
              -Finding        "Managed disk is unattached (DiskState = Unattached). Storage charges accrue with no active consumer." `
              -Recommendation "Snapshot the disk if a recovery copy is required, then delete it. If the disk was detached from a deleted VM, confirm no restore is planned before removal." `
              -Caveat         "Some unattached disks are deliberately retained as offline backups or restore points pending a decision. Confirm with the resource owner before deletion." `
              -Detail         "SKU: $sku · Size: $size · Created: $($disk.TimeCreated)"
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve disks for $($sub.Name): $_"
      }

      # ── Storage: Old snapshots ─────────────────────────────────────────
      try {
        $snapshots = @(Get-AzSnapshot -ErrorAction Stop)
        foreach ($snap in $snapshots) {
          if ($snap.TimeCreated -lt $snapshotCutoff) {
            $ageDays = [math]::Floor(((Get-Date) - $snap.TimeCreated).TotalDays)
            $subFindings += & $newFinding `
              -Category       "Old Snapshot" `
              -Severity       "Medium" `
              -Impact         "Medium" `
              -Confidence     "Medium" `
              -ResourceName   $snap.Name `
              -ResourceType   "Microsoft.Compute/snapshots" `
              -ResourceGroup  $snap.ResourceGroupName `
              -Location       $snap.Location `
              -Finding        "Snapshot is $ageDays days old (threshold: $SnapshotAgeThresholdDays days). Old snapshots accumulate silently and are rarely revisited." `
              -Recommendation "Review with the workload owner. Delete if no longer required for rollback, DR, or compliance. If retained for compliance, document the retention reason and expected expiry date." `
              -Caveat         "Some snapshots are retained for regulatory compliance, audit, or contractual obligations with multi-year retention periods. Do not delete without confirming retention policy with the data owner." `
              -Detail         "Size: $($snap.DiskSizeGB) GiB · Created: $($snap.TimeCreated.ToString('yyyy-MM-dd')) · Source disk: $($snap.CreationData.SourceUri -replace '^.*disks/', '' -replace '/.*$', '')"
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve snapshots for $($sub.Name): $_"
      }

      # ── Networking: Unassociated public IP addresses ───────────────────
      try {
        $pips = @(Get-AzPublicIpAddress -ErrorAction Stop)
        foreach ($pip in $pips) {
          # A public IP is idle if it has no associated resource (NIC, LB frontend, gateway)
          $isIdle = (-not $pip.IpConfiguration -and -not $pip.NatGateway)
          if ($isIdle) {
            $subFindings += & $newFinding `
              -Category       "Idle Public IP" `
              -Severity       "Medium" `
              -Impact         "Medium" `
              -Confidence     "High" `
              -ResourceName   $pip.Name `
              -ResourceType   "Microsoft.Network/publicIPAddresses" `
              -ResourceGroup  $pip.ResourceGroupName `
              -Location       $pip.Location `
              -Finding        "Public IP address is not associated with any resource (NIC, load balancer frontend, or NAT gateway). Static/Standard-tier IPs incur a reservation charge when idle." `
              -Recommendation "Delete the public IP if it is no longer needed. If a specific IP address must be preserved for DNS or allow-list reasons, document the retention reason; otherwise deletion eliminates the charge immediately." `
              -Caveat         "Some unassociated IPs are reserved to maintain a specific IP for DNS, firewall rules, or allow-lists ahead of a planned deployment. Confirm intent before deletion." `
              -Detail         "SKU: $($pip.Sku.Name) · Allocation: $($pip.PublicIpAllocationMethod) · Address: $($pip.IpAddress)"
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve public IPs for $($sub.Name): $_"
      }

      # ── Networking: Unassociated network interfaces ────────────────────
      try {
        $nics = @(Get-AzNetworkInterface -ErrorAction Stop)
        foreach ($nic in $nics) {
          if (-not $nic.VirtualMachine) {
            $subFindings += & $newFinding `
              -Category       "Orphaned NIC" `
              -Severity       "Low" `
              -Impact         "Low" `
              -Confidence     "Medium" `
              -ResourceName   $nic.Name `
              -ResourceType   "Microsoft.Network/networkInterfaces" `
              -ResourceGroup  $nic.ResourceGroupName `
              -Location       $nic.Location `
              -Finding        "Network interface is not attached to any virtual machine. Orphaned NICs signal lifecycle management gaps and may indicate a partially deleted VM deployment." `
              -Recommendation "Delete the NIC after confirming it is not referenced by any automation, template, or pending deployment. Check for any associated public IPs or NSGs that should also be cleaned up." `
              -Caveat         "NICs are occasionally pre-created ahead of a VM deployment or retained for network configuration reference. Confirm with the resource owner before deletion." `
              -Detail         "Private IP: $($nic.IpConfigurations[0].PrivateIpAddress) · Subnet: $($nic.IpConfigurations[0].Subnet.Id -replace '^.*subnets/', '')"
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve NICs for $($sub.Name): $_"
      }

      # ── Networking: Load balancers with empty backend pools ────────────
      try {
        $lbs = @(Get-AzLoadBalancer -ErrorAction Stop)
        foreach ($lb in $lbs) {
          if ($lb.Sku.Name -notin @("Standard", "Gateway")) { continue }
          $hasMembers = $false
          foreach ($pool in $lb.BackendAddressPools) {
            if ($pool.BackendIpConfigurations.Count -gt 0 -or $pool.LoadBalancerBackendAddresses.Count -gt 0) {
              $hasMembers = $true
              break
            }
          }
          if (-not $hasMembers) {
            $ruleCount = $lb.LoadBalancingRules.Count
            $subFindings += & $newFinding `
              -Category       "Empty Load Balancer" `
              -Severity       "Medium" `
              -Impact         "Medium" `
              -Confidence     "Medium" `
              -ResourceName   $lb.Name `
              -ResourceType   "Microsoft.Network/loadBalancers" `
              -ResourceGroup  $lb.ResourceGroupName `
              -Location       $lb.Location `
              -Finding        "Standard-tier load balancer has no backend pool members. Per-rule and per-hour charges continue regardless of throughput." `
              -Recommendation "If the load balancer is no longer serving active workloads, delete it to eliminate charges. If backend members are temporarily absent (e.g. during a blue/green switch or VMSS scale-in), this is expected and the finding can be dismissed." `
              -Caveat         "Backend pools can be temporarily empty during blue/green deployments, VMSS scale-in events, or planned maintenance. Confirm the state is not transient before taking action." `
              -Detail         "SKU: $($lb.Sku.Name) · Rules: $ruleCount · Backend pools: $($lb.BackendAddressPools.Count)"
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve load balancers for $($sub.Name): $_"
      }

      # ── App Service: Underutilised or empty App Service Plans ──────────
      try {
        $asps = @(Get-AzAppServicePlan -ErrorAction Stop)
        foreach ($asp in $asps) {
          # Skip Free and Shared tiers — they don't have meaningful hourly cost
          if ($asp.Sku.Tier -in @("Free", "Shared", "Dynamic", "ElasticPremium")) { continue }

          try {
            $apps = @(Get-AzWebApp -AppServicePlan $asp -ErrorAction Stop)
          }
          catch {
            $apps = @()
            Write-Verbose "  Could not retrieve apps for plan $($asp.Name): $_"
          }

          $appCount = $apps.Count

          if ($appCount -eq 0) {
            $subFindings += & $newFinding `
              -Category       "Empty App Service Plan" `
              -Severity       "Medium" `
              -Impact         "Medium" `
              -Confidence     "Medium" `
              -ResourceName   $asp.Name `
              -ResourceType   "Microsoft.Web/serverfarms" `
              -ResourceGroup  $asp.ResourceGroupName `
              -Location       $asp.Location `
              -Finding        "App Service Plan ($($asp.Sku.Tier) tier) has no deployed apps. The plan incurs its full hourly cost with no workload." `
              -Recommendation "Delete the plan if it is not needed. If apps are being migrated onto it, set a target date and track the plan's activation. Downgrade to a lower tier temporarily if possible." `
              -Caveat         "Plans are sometimes pre-provisioned ahead of application deployments or retained to preserve SSL bindings and custom domains. Confirm with the application team before deletion." `
              -Detail         "SKU: $($asp.Sku.Name) · Tier: $($asp.Sku.Tier) · Workers: $($asp.Sku.Capacity) · Apps hosted: 0"
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve App Service Plans for $($sub.Name): $_"
      }

      # ── Resource Management: Empty resource groups ─────────────────────
      try {
        $rgs = @(Get-AzResourceGroup -ErrorAction Stop)
        foreach ($rg in $rgs) {
          try {
            $resourceCount = (Get-AzResource -ResourceGroupName $rg.ResourceGroupName -ErrorAction Stop).Count
            if ($resourceCount -eq 0) {
              $subFindings += & $newFinding `
                -Category       "Empty Resource Group" `
                -Severity       "Low" `
                -Impact         "Low" `
                -Confidence     "Low" `
                -ResourceName   $rg.ResourceGroupName `
                -ResourceType   "Microsoft.Resources/resourceGroups" `
                -ResourceGroup  $rg.ResourceGroupName `
                -Location       $rg.Location `
                -Finding        "Resource group contains zero resources. Empty groups add management overhead and may indicate forgotten or abandoned infrastructure." `
                -Recommendation "Delete the resource group if it is no longer needed. Confirm it does not contain hidden or recently deleted resources before removal." `
                -Caveat         "Some empty resource groups are intentionally maintained as deployment targets, template containers, or access boundary scopes. Well-known system-managed groups (e.g. NetworkWatcherRG) are expected to be lightly populated." `
                -Detail         "Location: $($rg.Location) · Tags: $($rg.Tags.Count)"
            }
          }
          catch {
            Write-Verbose "  Could not count resources in $($rg.ResourceGroupName): $_"
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve resource groups for $($sub.Name): $_"
      }

      # ── Per-subscription gap score ─────────────────────────────────────
      # Weighted: High findings count 3, Medium count 1, Low count 0
      $subHigh   = @($subFindings | Where-Object { $_.Severity -eq "High"   }).Count
      $subMedium = @($subFindings | Where-Object { $_.Severity -eq "Medium" }).Count
      $subLow    = @($subFindings | Where-Object { $_.Severity -eq "Low"    }).Count
      $gapWeight = ($subHigh * 3) + ($subMedium * 1)

      $gapScore = if    ($subHigh -ge 5 -or $gapWeight -ge 15) { "High" }
      elseif           ($subHigh -ge 2 -or $gapWeight -ge 5)   { "Medium" }
      elseif           ($subFindings.Count -gt 0)               { "Low" }
      else                                                       { "Minimal" }

      $allSubResults += [pscustomobject]@{
        SubscriptionName = $sub.Name
        SubscriptionId   = $sub.Id
        TotalFindings    = $subFindings.Count
        HighFindings     = $subHigh
        MediumFindings   = $subMedium
        LowFindings      = $subLow
        GapScore         = $gapScore
      }

      $allFindings += $subFindings

      # ── Per-subscription console output ───────────────────────────────
      Write-Host "`r$(' ' * 120)`r" -NoNewline
      $paddedName = $sub.Name.PadRight($maxNameLen)

      Write-Host "  " -NoNewline
      Write-Host "✓ " -NoNewline -ForegroundColor Green
      Write-Host $paddedName -NoNewline -ForegroundColor Green
      Write-Host " → " -NoNewline -ForegroundColor DarkGray
      Write-Host "Findings: $($subFindings.Count)  High: $subHigh  Medium: $subMedium  Low: $subLow  Gap: $gapScore" -ForegroundColor White

      $subscriptionResults += @{
        Name    = $sub.Name
        Summary = "Findings: $($subFindings.Count)  High: $subHigh  Medium: $subMedium  Low: $subLow  Gap Score: $gapScore"
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
  $endTime  = Get-Date
  $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

  $totalHigh   = @($allFindings | Where-Object { $_.Severity -eq "High"   }).Count
  $totalMedium = @($allFindings | Where-Object { $_.Severity -eq "Medium" }).Count
  $totalLow    = @($allFindings | Where-Object { $_.Severity -eq "Low"    }).Count

  Write-CoSummary -Data ([ordered]@{
      "Total Subscriptions Scanned" = $subCount
      "Successful"                  = $successCount
      "Errors"                      = $errorCount
      "Total Findings"              = $allFindings.Count
      "High Severity"               = $totalHigh
      "Medium Severity"             = $totalMedium
      "Low Severity"                = $totalLow
      "Deallocated VMs Included"    = if ($IncludeDeallocatedVMs) { "Yes" } else { "No" }
      "Execution Time"              = $duration
    })

  Write-CoGapSummary -SubResults $allSubResults

  # ── Output files ──────────────────────────────────────────────────────────
  $csvExported    = $false
  $htmlExported   = $false
  $gridViewOpened = $false
  $htmlPath       = ""
  $csvPath        = ""

  if ($allFindings.Count -gt 0 -or $subCount -gt 0) {

    # CSV export
    if ($ExportToCsv) {
      try {
        $csvPath = Join-Path $OutputDirectory "AzureCostOptimizationGap-Findings.csv"
        $allFindings | Select-Object `
          SubscriptionName, SubscriptionId, Category, Severity, Impact, Confidence,
          ResourceName, ResourceType, ResourceGroup, Location, Finding,
          Recommendation, Caveat, Detail |
          Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $csvExported = $true
      }
      catch {
        Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
      }
    }

    # HTML dashboard
    try {
      $htmlPath = Join-Path $OutputDirectory "AzureCostOptimizationGap-Dashboard.html"

      $sessionInfo = @{
        Tenant      = $ctx.Tenant.Id
        Account     = $ctx.Account.Id
        Environment = $ctx.Environment.Name
      }

      $scanParams = @{
        Scope           = "$scopeText ($subCount found)"
        SnapshotDays    = $SnapshotAgeThresholdDays
        DeallocIncluded = if ($IncludeDeallocatedVMs.IsPresent) { "Yes" } else { "No" }
        ExportEnabled   = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        ExecTime        = $duration
      }

      $htmlContent = Generate-CostOptimizationHtml `
        -SessionInfo          $sessionInfo `
        -ScanParameters       $scanParams `
        -AllFindings          $allFindings `
        -SubResults           $allSubResults `
        -SubscriptionResults  $subscriptionResults `
        -GeneratedOn          (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

      $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
      $htmlExported = $true
    }
    catch {
      Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
    }

    # Grid View
    try {
      $allFindings |
        Select-Object SubscriptionName, Category, Severity, Impact, Confidence,
          ResourceName, ResourceGroup, Finding |
        Out-GridView -Title "Azure Cost Optimization Gap Assessment — Findings"
      $gridViewOpened = $true
    }
    catch {
      Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
    }
  }
  else {
    Write-Host ""
    Write-Host "  ✓ No optimization gap findings identified in the targeted subscriptions." -ForegroundColor Green
  }

  if ($csvExported -or $htmlExported -or $gridViewOpened) {
    $outCsv  = if ($csvExported)  { $csvPath  } else { $null }
    $outHtml = if ($htmlExported) { $htmlPath } else { $null }
    Write-CoOutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
  }
  else {
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
  }
}
