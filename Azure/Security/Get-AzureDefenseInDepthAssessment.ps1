<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Evaluates layered security controls across identity, network, workload, data,
    detection, and recovery to determine whether Azure workloads have multiple
    effective, complementary security layers — not just a single point of protection.

.DESCRIPTION
    Get-AzureDefenseInDepthAssessment assesses whether Azure workloads are protected
    by multiple, independent security layers aligned to the Defense in Depth (DiD)
    architecture model. The script explicitly looks for layering gaps — scenarios where
    a workload or resource tier depends on a single control and would be unprotected if
    that control is bypassed or fails.

    The assessment is organized into six DiD layers:

        Layer 1 — Identity & Access Controls
            - MFA and Conditional Access coverage (baseline identity layer)
            - PIM and just-in-time privileged access
            - Legacy authentication block (secondary identity control)
            - Shared access / service account detection

        Layer 2 — Network Perimeter Controls
            - Azure Firewall / NVA centralized inspection (perimeter layer)
            - NSG coverage on subnets (network micro-segmentation layer)
            - DDoS Protection Standard coverage (volumetric attack layer)
            - VPN / ExpressRoute vs public endpoint exposure

        Layer 3 — Compute & Host Controls
            - Defender for Servers plan coverage (host layer)
            - Endpoint protection / antimalware extension presence on VMs
            - VM Guest Policy / Azure Policy for compute baseline enforcement
            - JIT VM access and Azure Bastion (access control at compute layer)

        Layer 4 — Application Controls
            - Azure Web Application Firewall (WAF) on Application Gateway / Front Door
            - API Management with authentication policy presence
            - App Service Authentication (Easy Auth) enablement
            - TLS minimum version enforcement on App Services and Storage

        Layer 5 — Data Protection Controls
            - Encryption at rest: CMK vs platform-managed key detection
            - Azure Backup coverage for VMs and storage
            - Key Vault secret / key expiry enforcement
            - SQL Transparent Data Encryption and Advanced Threat Protection

        Layer 6 — Detection & Recovery Controls
            - Microsoft Sentinel (SIEM / SOAR layer)
            - Defender for Cloud alert suppression rules
            - Recovery Services vault and backup policy coverage
            - Azure Site Recovery / geo-redundant storage coverage

    For each finding the script records:
        - Layer       : Which DiD layer is being assessed
        - LayerDepth  : Whether the layer is Present, Weak, or Missing
        - Control     : The specific control being assessed
        - Why         : Why layering matters for this control
        - CurrentState: The observed configuration
        - SinglePointOfFailure: Whether a gap creates a single point of failure
        - Risk        : The gap or risk if this layer is absent or weak
        - Severity    : High | Medium | Low | Info
        - Impact      : Business / security impact of the gap
        - Recommendation: Suggested improvement

    The script supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of all findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable findings
          table, layer depth distribution, single-point-of-failure highlight panel,
          per-layer drilldown pages, detail drawer)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all Defense in Depth findings to the path
    given in -CsvPath. The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzureDefenseInDepthAssessment-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureDefenseInDepthAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureDefenseInDepthAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureDefenseInDepthAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\DiD.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Six-layer Defense in Depth assessment
                            covering identity, network perimeter, compute/host,
                            application, data protection, and detection/recovery.
                            CSV export and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Network, Az.Compute, Az.Security,
           Az.Storage, Az.KeyVault, Az.Monitor, Az.OperationalInsights, Az.Resources,
           Az.Websites, Az.RecoveryServices, Az.Sql)
           — installed automatically with user consent if not present.
        2. Microsoft.Graph PowerShell module (Microsoft.Graph.Identity.SignIns)
           — installed automatically with user consent if not present.
           Required for Layer 1 identity checks (Conditional Access, MFA, legacy auth).
        3. Authenticated Azure session (Connect-AzAccount).
        4. Microsoft Graph session (Connect-MgGraph) with scope Policy.Read.All.
        5. Reader role (minimum) at the subscription level for Azure resource checks.
        6. Security Reader role for Defender for Cloud access.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Layer 1 identity checks require Microsoft Graph with Policy.Read.All scope.
          Without it, Layer 1 checks are marked "Not Assessed" and assessment
          continues with Layers 2–6.
        - App Service Authentication (Easy Auth) detection requires the Az.Websites
          module and Get-AzWebAppAuthSettings. Skipped gracefully if unavailable.
        - CMK detection is best-effort; not all resource types expose encryption
          key references consistently via the ARM API at subscription scope.
        - SQL TDE and ATP checks require Az.Sql. Skipped gracefully if not installed.
        - Azure Site Recovery (ASR) presence is detected by checking Recovery Services
          vault replication items — this may be slow in large environments.
        - Interactive Grid View requires a GUI-capable session. Skipped gracefully
          in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/security/fundamentals/defense-in-depth
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction
    https://learn.microsoft.com/en-us/azure/web-application-firewall/overview
    https://learn.microsoft.com/en-us/azure/backup/backup-overview
    https://learn.microsoft.com/en-us/azure/site-recovery/site-recovery-overview

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
    Write-CenteredText "Azure Defense in Depth Assessment v1.0" -Color White
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

Function Write-LayerBreakdown {
    param([hashtable]$Layers)

    if ($Layers.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  DiD Layer Finding Counts" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($l in ($Layers.GetEnumerator() | Sort-Object Value -Descending)) {
        Write-Host "  " -NoNewline
        Write-Host $l.Key.PadRight(36) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($l.Value) finding(s)" -ForegroundColor White
    }
}

Function Write-SpofSummary {
    param([int]$SpofCount)

    Write-Host ""
    Write-Host "  Single Points of Failure Detected" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    if ($SpofCount -gt 0) {
        Write-Host "  ✗ $SpofCount finding(s) identified as creating a Single Point of Failure" -ForegroundColor Red
        Write-Host "    These resources or tiers rely on only one security control. Review the" -ForegroundColor DarkGray
        Write-Host "    HTML dashboard SPOF panel for details and prioritize remediation." -ForegroundColor DarkGray
    }
    else {
        Write-Host "  ✓ No single points of failure detected in this scan" -ForegroundColor Green
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

# ── Finding builder ───────────────────────────────────────────────────────────
Function New-DidFinding {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$Layer,
        [string]$LayerDepth,     # Present | Weak | Missing
        [string]$Control,
        [string]$Why,
        [string]$CurrentState,
        [bool]$SinglePointOfFailure,
        [string]$Risk,
        [string]$Severity,       # High | Medium | Low | Info
        [string]$Impact,
        [string]$Recommendation,
        [string]$ResourceScope = ""
    )
    return [pscustomobject]@{
        SubscriptionName     = $SubscriptionName
        SubscriptionId       = $SubscriptionId
        Layer                = $Layer
        LayerDepth           = $LayerDepth
        Control              = $Control
        Why                  = $Why
        CurrentState         = $CurrentState
        SinglePointOfFailure = if ($SinglePointOfFailure) { "Yes" } else { "No" }
        Risk                 = $Risk
        Severity             = $Severity
        Impact               = $Impact
        Recommendation       = $Recommendation
        ResourceScope        = $ResourceScope
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-DefenseInDepthHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [hashtable]$LayerDistribution,
        [hashtable]$DepthDistribution,
        [hashtable]$RiskDistribution,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [bool]$GraphConnected
    )

    $totalFindings = @($Findings).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $medCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount = @($Findings | Where-Object { $_.Severity -eq "Info" }).Count
    $spofCount = @($Findings | Where-Object { $_.SinglePointOfFailure -eq "Yes" }).Count

    $graphBadge = if ($GraphConnected) { "connected" } else { "skipped" }
    $graphText = if ($GraphConnected) { "Connected" } else { "Not Connected — Layer 1 Identity checks skipped" }

    # ── Finding table rows ────────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $sevCls = switch ($f.Severity) { "High" { "badge-red" }; "Medium" { "badge-amber" }; "Low" { "badge-green" }; default { "badge-blue" } }
        $depthCls = switch ($f.LayerDepth) { "Missing" { "badge-red" }; "Weak" { "badge-amber" }; "Present" { "badge-green" }; default { "badge-blue" } }
        $spofBadge = if ($f.SinglePointOfFailure -eq "Yes") { '<span class="badge badge-red">⚠ SPOF</span>' } else { "" }
        $ctrlDisp = if ($f.Control.Length -gt 42) { (EscHtml $f.Control.Substring(0, 39)) + "..." } else { EscHtml $f.Control }
        $idx = [array]::IndexOf($Findings, $f)
        $findingRows += @"
          <tr onclick="showFindingDetail($idx)">
            <td title="$(EscHtml $f.Control)">$ctrlDisp</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td><span class="badge badge-blue">$(EscHtml ($f.Layer -replace ' Controls',''))</span></td>
            <td><span class="badge $depthCls">$(EscHtml $f.LayerDepth)</span></td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td>$spofBadge</td>
          </tr>
"@
    }

    # ── SPOF findings panel rows ───────────────────────────────────────────────
    $spofRows = ""
    $spofFindings = @($Findings | Where-Object { $_.SinglePointOfFailure -eq "Yes" })
    foreach ($f in $spofFindings) {
        $sevCls = switch ($f.Severity) { "High" { "badge-red" }; "Medium" { "badge-amber" }; "Low" { "badge-green" }; default { "badge-blue" } }
        $idx = [array]::IndexOf($Findings, $f)
        $spofRows += @"
          <div class="spof-row" onclick="showFindingDetail($idx)" style="cursor:pointer;">
            <span class="spof-icon">⚠</span>
            <div class="spof-body">
              <div class="spof-ctrl">$(EscHtml $f.Control)</div>
              <div class="spof-sub">$(EscHtml $f.SubscriptionName) · $(EscHtml $f.Layer) · <span class="badge $sevCls" style="font-size:10px;">$(EscHtml $f.Severity)</span></div>
            </div>
          </div>
"@
    }
    if ($spofRows -eq "") { $spofRows = '<div style="color:var(--muted);font-size:13px;padding:12px 0;">No single points of failure detected.</div>' }

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

    # ── Layer distribution bar rows ───────────────────────────────────────────
    $layerTotal = ($LayerDistribution.Values | Measure-Object -Sum).Sum
    $layerRows = ""
    $layerColors = @{
        "Layer 1 — Identity"           = "var(--accent)"
        "Layer 2 — Network"            = "var(--accent2)"
        "Layer 3 — Compute/Host"       = "var(--accent3)"
        "Layer 4 — Application"        = "var(--green)"
        "Layer 5 — Data"               = "var(--amber)"
        "Layer 6 — Detection/Recovery" = "var(--red)"
    }
    foreach ($l in ($LayerDistribution.GetEnumerator() | Sort-Object Key)) {
        $pct = if ($layerTotal -gt 0) { [math]::Round(($l.Value / $layerTotal) * 100) } else { 0 }
        $barColor = if ($layerColors.ContainsKey($l.Key)) { $layerColors[$l.Key] } else { "var(--accent)" }
        $layerRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $l.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($l.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Layer depth distribution bar rows ─────────────────────────────────────
    $depthTotal = ($DepthDistribution.Values | Measure-Object -Sum).Sum
    $depthRows = ""
    $depthColors = @{ "Missing" = "var(--red)"; "Weak" = "var(--amber)"; "Present" = "var(--green)"; "Info" = "var(--muted)" }
    foreach ($d in ($DepthDistribution.GetEnumerator() | Sort-Object { @("Missing", "Weak", "Present", "Info").IndexOf($_.Key) })) {
        $pct = if ($depthTotal -gt 0) { [math]::Round(($d.Value / $depthTotal) * 100) } else { 0 }
        $barColor = if ($depthColors.ContainsKey($d.Key)) { $depthColors[$d.Key] } else { "var(--muted)" }
        $depthRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $d.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($d.Value) ($pct%)</span>
          </div>
"@
    }

    # ── JSON for findings detail drawer ───────────────────────────────────────
    $findJson = "["
    foreach ($f in $Findings) {
        $findJson += "{" +
        """ctrl"":""$(EscJ $f.Control)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """layer"":""$(EscJ $f.Layer)""," +
        """depth"":""$(EscJ $f.LayerDepth)""," +
        """sev"":""$(EscJ $f.Severity)""," +
        """spof"":""$(EscJ $f.SinglePointOfFailure)""," +
        """why"":""$(EscJ $f.Why)""," +
        """state"":""$(EscJ $f.CurrentState)""," +
        """risk"":""$(EscJ $f.Risk)""," +
        """impact"":""$(EscJ $f.Impact)""," +
        """rec"":""$(EscJ $f.Recommendation)""," +
        """scope"":""$(EscJ $f.ResourceScope)""" +
        "},"
    }
    $findJson = $findJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Defense in Depth Assessment Dashboard</title>
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
  background:linear-gradient(135deg,var(--accent3),var(--red));
  display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{
  display:inline-block;margin-top:8px;padding:2px 8px;border-radius:20px;
  font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent);border:1px solid var(--border);
}
.nav-section{padding:14px 10px;flex:1;overflow-y:auto;}
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin-bottom:22px;}
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
.bar-label{font-size:12px;color:var(--muted2);width:170px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
.spof-row{display:flex;align-items:flex-start;gap:12px;padding:12px 0;border-bottom:1px solid var(--border);transition:background .1s;}
.spof-row:last-child{border-bottom:none;}
.spof-row:hover{background:var(--surface2);border-radius:var(--radius-sm);padding-left:6px;}
.spof-icon{font-size:18px;color:var(--red);flex-shrink:0;margin-top:2px;}
.spof-body{flex:1;}
.spof-ctrl{font-size:13px;font-weight:500;line-height:1.4;}
.spof-sub{font-size:11px;color:var(--muted2);margin-top:4px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;}
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
.graph-banner{
  padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:16px;
  display:flex;align-items:center;gap:10px;font-size:13px;
}
.graph-banner.connected{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.3);color:var(--green);}
.graph-banner.skipped{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3);color:var(--amber);}
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
  position:fixed;right:0;top:0;bottom:0;width:490px;max-width:95vw;
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
.drawer-field-value{font-size:13px;word-break:break-word;line-height:1.5;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.spof-alert{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.3);border-radius:var(--radius-sm);padding:10px 14px;margin-bottom:14px;font-size:12px;color:var(--red);}
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
    <div class="logo-icon">🛡</div>
    <div class="logo-title">Defense in Depth</div>
    <div class="logo-sub">Azure Security Layering</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> All Findings</button>
    <button class="nav-btn" onclick="showPage('spof',this)"><span class="nav-icon">⚠️</span> SPOF Findings</button>
    <div class="nav-label" style="margin-top:10px;">DiD Layers</div>
    <button class="nav-btn" onclick="showPage('l1',this)"><span class="nav-icon">🆔</span> L1 · Identity</button>
    <button class="nav-btn" onclick="showPage('l2',this)"><span class="nav-icon">🌐</span> L2 · Network</button>
    <button class="nav-btn" onclick="showPage('l3',this)"><span class="nav-icon">⚙️</span> L3 · Compute/Host</button>
    <button class="nav-btn" onclick="showPage('l4',this)"><span class="nav-icon">🧩</span> L4 · Application</button>
    <button class="nav-btn" onclick="showPage('l5',this)"><span class="nav-icon">🗄️</span> L5 · Data</button>
    <button class="nav-btn" onclick="showPage('l6',this)"><span class="nav-icon">📡</span> L6 · Detection/Recovery</button>
    <div class="nav-label" style="margin-top:10px;">Info</div>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">☁️</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Azure Defense in Depth Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Defense in Depth Assessment Overview</div>
      <div class="page-sub">Six-layer security architecture evaluation across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="graph-banner __GRAPH_BANNER_CLS__">
      <span>🔗</span>
      <span><strong>Microsoft Graph:</strong> __GRAPH_BANNER_TEXT__</span>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_FINDINGS__</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Severity</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MED_COUNT__</div>
        <div class="stat-label">Medium Severity</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low Severity</div>
      </div>
      <div class="stat-card c-red" style="border-top-color:#e8854f">
        <div class="stat-num">__SPOF_COUNT__</div>
        <div class="stat-label">SPOF Findings</div>
        <div class="stat-sub">Single point of failure</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__INFO_COUNT__</div>
        <div class="stat-label">Informational</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🏛️ Findings by DiD Layer</div>
        __LAYER_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🔍 Layer Depth Distribution</div>
        __DEPTH_ROWS__
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">⚠️ Single Points of Failure — Click to view detail</div>
      __SPOF_ROWS__
    </div>
  </div>

  <!-- All Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">All Findings</div>
      <div class="page-sub">Click any row for full finding context — layer rationale, layering gap, impact, and recommendation</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search control, subscription…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterLayer" onchange="filterFindings()">
          <option value="">All Layers</option>
          <option value="Layer 1 — Identity">L1 · Identity</option>
          <option value="Layer 2 — Network">L2 · Network</option>
          <option value="Layer 3 — Compute/Host">L3 · Compute/Host</option>
          <option value="Layer 4 — Application">L4 · Application</option>
          <option value="Layer 5 — Data">L5 · Data</option>
          <option value="Layer 6 — Detection/Recovery">L6 · Detection/Recovery</option>
        </select>
        <select class="filter-select" id="filterDepth" onchange="filterFindings()">
          <option value="">All Depths</option>
          <option value="Missing">Missing</option>
          <option value="Weak">Weak</option>
          <option value="Present">Present</option>
        </select>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
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
              <th onclick="sortFindings(0)">Control</th>
              <th onclick="sortFindings(1)">Subscription</th>
              <th onclick="sortFindings(2)">Layer</th>
              <th onclick="sortFindings(3)">Depth</th>
              <th onclick="sortFindings(4)">Severity</th>
              <th>SPOF</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- SPOF page -->
  <div id="page-spof" class="page">
    <div class="page-header">
      <div class="page-title">Single Points of Failure</div>
      <div class="page-sub">Resources or tiers protected by only one security layer — highest remediation priority</div>
    </div>
    <div class="panel">
      <div class="panel-title">⚠️ SPOF Findings — Click any item for full detail</div>
      __SPOF_ROWS_PAGE__
    </div>
  </div>

  <!-- Per-Layer pages -->
  <div id="page-l1" class="page"><div class="page-header"><div class="page-title">Layer 1 — Identity Controls</div><div class="page-sub">MFA, Conditional Access, PIM, and legacy authentication — the first control plane layer</div></div><div id="layerContent-l1"></div></div>
  <div id="page-l2" class="page"><div class="page-header"><div class="page-title">Layer 2 — Network Controls</div><div class="page-sub">Firewall, NSG, DDoS protection — the perimeter and micro-segmentation layers</div></div><div id="layerContent-l2"></div></div>
  <div id="page-l3" class="page"><div class="page-header"><div class="page-title">Layer 3 — Compute / Host Controls</div><div class="page-sub">Defender for Servers, antimalware, Guest Policy, JIT, Bastion — the host layer</div></div><div id="layerContent-l3"></div></div>
  <div id="page-l4" class="page"><div class="page-header"><div class="page-title">Layer 4 — Application Controls</div><div class="page-sub">WAF, API Management, Easy Auth, TLS enforcement — the application layer</div></div><div id="layerContent-l4"></div></div>
  <div id="page-l5" class="page"><div class="page-header"><div class="page-title">Layer 5 — Data Protection Controls</div><div class="page-sub">CMK encryption, Backup, Key Vault expiry, SQL TDE and ATP — the data layer</div></div><div id="layerContent-l5"></div></div>
  <div id="page-l6" class="page"><div class="page-header"><div class="page-title">Layer 6 — Detection &amp; Recovery</div><div class="page-sub">Sentinel, Defender alerts, Recovery Services, Site Recovery — the detection and resilience layer</div></div><div id="layerContent-l6"></div></div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription Defense in Depth assessment outcome</div>
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
        <div class="info-card"><div class="info-label">Microsoft Graph</div><div class="info-value">__GRAPH_TEXT__</div></div>
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
const FIND_DATA = __FIND_JSON__;
let findFiltered = [...FIND_DATA];
let findPage = 1, findPageSz = 25;
let findSortCol = -1, findSortAsc = true;
let currentDetailIdx = 0;

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

const LAYER_PAGE_MAP = {
  'Layer 1 — Identity'          : 'l1',
  'Layer 2 — Network'           : 'l2',
  'Layer 3 — Compute/Host'      : 'l3',
  'Layer 4 — Application'       : 'l4',
  'Layer 5 — Data'              : 'l5',
  'Layer 6 — Detection/Recovery': 'l6'
};

function showPage(id, btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
  const layerContentEl = document.getElementById('layerContent-'+id);
  if(layerContentEl && layerContentEl.innerHTML==='') renderLayerPage(id, layerContentEl);
}

function layerForPage(pageId){
  return Object.keys(LAYER_PAGE_MAP).find(k=>LAYER_PAGE_MAP[k]===pageId)||'';
}

function renderLayerPage(pageId, el){
  const layer = layerForPage(pageId);
  const rows  = FIND_DATA.filter(f=>f.layer===layer);
  if(rows.length===0){
    el.innerHTML='<div class="panel" style="color:var(--muted);font-size:13px;">No findings recorded for this layer.</div>';
    return;
  }
  const tbody = rows.map(f=>{
    const gi       = FIND_DATA.indexOf(f);
    const sevCls   = f.sev==='High'?'badge-red':f.sev==='Medium'?'badge-amber':f.sev==='Low'?'badge-green':'badge-blue';
    const depthCls = f.depth==='Missing'?'badge-red':f.depth==='Weak'?'badge-amber':f.depth==='Present'?'badge-green':'badge-blue';
    const spofBadge = f.spof==='Yes'?'<span class="badge badge-red">⚠ SPOF</span>':'';
    const nm = f.ctrl.length>44?f.ctrl.substring(0,41)+'...':f.ctrl;
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(f.ctrl)}">${escH(nm)}</td>
      <td>${escH(f.sub)}</td>
      <td><span class="badge ${depthCls}">${escH(f.depth)}</span></td>
      <td><span class="badge ${sevCls}">${escH(f.sev)}</span></td>
      <td>${spofBadge}</td>
    </tr>`;
  }).join('');
  el.innerHTML=`<div class="panel"><div class="tbl-wrap"><table>
    <thead><tr><th>Control</th><th>Subscription</th><th>Layer Depth</th><th>Severity</th><th>SPOF</th></tr></thead>
    <tbody>${tbody}</tbody></table></div></div>`;
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
  const q  = document.getElementById('findSearch').value.toLowerCase();
  const l  = document.getElementById('filterLayer').value;
  const d  = document.getElementById('filterDepth').value;
  const sv = document.getElementById('filterSev').value;
  findFiltered = FIND_DATA.filter(r=>{
    const mQ = !q  || JSON.stringify(r).toLowerCase().includes(q);
    const mL = !l  || r.layer===l;
    const mD = !d  || r.depth===d;
    const mS = !sv || r.sev===sv;
    return mQ && mL && mD && mS;
  });
  findPage=1; renderFindings();
}

function changeFindPageSize(){
  findPageSz=parseInt(document.getElementById('pgSizeFind').value);
  findPage=1; renderFindings();
}

function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys=['ctrl','sub','layer','depth','sev'];
  findFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    return findSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                      :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderFindings();
}

function renderFindings(){
  const tbody=document.getElementById('findBody');
  const start=(findPage-1)*findPageSz;
  const slice=findFiltered.slice(start,start+findPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi       = FIND_DATA.indexOf(r);
    const sevCls   = r.sev==='High'?'badge-red':r.sev==='Medium'?'badge-amber':r.sev==='Low'?'badge-green':'badge-blue';
    const depthCls = r.depth==='Missing'?'badge-red':r.depth==='Weak'?'badge-amber':r.depth==='Present'?'badge-green':'badge-blue';
    const spofBadge = r.spof==='Yes'?'<span class="badge badge-red">⚠ SPOF</span>':'';
    const nm = r.ctrl.length>42?r.ctrl.substring(0,39)+'...':r.ctrl;
    const layerShort = r.layer.replace('Layer ','L').replace(' — ',' · ');
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.ctrl)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td><span class="badge badge-blue">${escH(layerShort)}</span></td>
      <td><span class="badge ${depthCls}">${escH(r.depth)}</span></td>
      <td><span class="badge ${sevCls}">${escH(r.sev)}</span></td>
      <td>${spofBadge}</td>
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
  document.getElementById('drawerTitle').textContent=r.ctrl;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FIND_DATA.length}`;
  const sevCls   = r.sev==='High'?'badge-red':r.sev==='Medium'?'badge-amber':r.sev==='Low'?'badge-green':'badge-blue';
  const depthCls = r.depth==='Missing'?'badge-red':r.depth==='Weak'?'badge-amber':r.depth==='Present'?'badge-green':'badge-blue';
  const spofAlert = r.spof==='Yes'?`<div class="spof-alert">⚠ Single Point of Failure — this resource or tier is protected by only one security layer. Prioritize adding a complementary control.</div>`:'';
  document.getElementById('drawerContent').innerHTML=`
    ${spofAlert}
    <div class="drawer-field"><div class="drawer-field-label">Layer</div>
      <div class="drawer-field-value"><span class="badge badge-blue">${escH(r.layer)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Layer Depth</div>
      <div class="drawer-field-value"><span class="badge ${depthCls}">${escH(r.depth)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sevCls}">${escH(r.sev)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    ${r.scope?`<div class="drawer-field"><div class="drawer-field-label">Resource / Scope</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.scope)}</div></div>`:''}
    <div class="drawer-section">Why Layering Matters Here</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.why)}</div></div>
    <div class="drawer-section">Current State</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.state)}</div></div>
    <div class="drawer-section">Risk / Layering Gap</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.risk)}</div></div>
    <div class="drawer-section">Business / Security Impact</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.impact)}</div></div>
    <div class="drawer-section">Recommendation</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.rec)}</div></div>
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
        -replace '__TOTAL_FINDINGS__', $totalFindings `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MED_COUNT__', $medCount `
        -replace '__LOW_COUNT__', $lowCount `
        -replace '__INFO_COUNT__', $infoCount `
        -replace '__SPOF_COUNT__', $spofCount `
        -replace '__GRAPH_BANNER_CLS__', $graphBadge `
        -replace '__GRAPH_BANNER_TEXT__', $graphText `
        -replace '__GRAPH_TEXT__', $graphText `
        -replace '__LAYER_ROWS__', $layerRows `
        -replace '__DEPTH_ROWS__', $depthRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__SPOF_ROWS__', $spofRows `
        -replace '__SPOF_ROWS_PAGE__', $spofRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FIND_JSON__', $findJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureDefenseInDepthAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureDefenseInDepthAssessment-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check — Az ─────────────────────────────────────────────────────
    $requiredAzModules = @(
        "Az.Accounts", "Az.Network", "Az.Compute", "Az.Security",
        "Az.Storage", "Az.KeyVault", "Az.Monitor", "Az.OperationalInsights",
        "Az.Resources", "Az.Websites", "Az.RecoveryServices", "Az.Sql"
    )

    $missingAz = $requiredAzModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missingAz) {
        Write-Host "  ⚠ Missing Az modules: $($missingAz -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "  Install Az module now? (Y/N)"
        if ($install -match '^[Yy]$') {
            try {
                Write-Host "  Installing Az module, please wait..." -ForegroundColor Cyan
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "  ✓ Az module installed successfully" -ForegroundColor Green
            }
            catch {
                Write-Host "  ✗ Error installing Az module: $_" -ForegroundColor Red
                return
            }
        }
        else {
            Write-Host "  Installation declined. Cannot proceed without required Az modules." -ForegroundColor Yellow
            return
        }
    }

    # ── Microsoft.Graph (optional — Layer 1 only) ─────────────────────────────
    $missingGraph = -not (Get-Module -ListAvailable -Name "Microsoft.Graph.Identity.SignIns")
    if ($missingGraph) {
        Write-Host ""
        Write-Host "  ⚠ Microsoft.Graph.Identity.SignIns not found." -ForegroundColor Yellow
        $installGraph = Read-Host "  Install Microsoft.Graph for Layer 1 Identity checks? (Y/N)"
        if ($installGraph -match '^[Yy]$') {
            try {
                Install-Module Microsoft.Graph -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Write-Host "  ✓ Microsoft.Graph installed" -ForegroundColor Green
            }
            catch {
                Write-Host "  ⚠ Microsoft.Graph installation failed — Layer 1 checks will be skipped" -ForegroundColor Yellow
            }
        }
    }

    # ── Azure authentication ──────────────────────────────────────────────────
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        Write-Host "  ⚠ No active Azure session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $ctx = Get-AzContext
    }

    # ── Microsoft Graph authentication (optional) ─────────────────────────────
    $graphConnected = $false
    try {
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $mgContext) {
            Write-Host ""
            Write-Host "  Connecting to Microsoft Graph (Policy.Read.All)..." -ForegroundColor Gray
            Connect-MgGraph -Scopes "Policy.Read.All" -NoWelcome -ErrorAction Stop
        }
        $graphConnected = $true
        Write-Host "  ✓ Microsoft Graph connected" -ForegroundColor Green
    }
    catch {
        Write-Host "  ⚠ Microsoft Graph connection failed or skipped — Layer 1 Identity checks will be marked 'Not Assessed'" -ForegroundColor Yellow
    }

    # ── Subscription resolution ───────────────────────────────────────────────
    if ($AllSubscriptions -or -not $SubscriptionIds) {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText = "All Subscriptions"
    }
    else {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
            Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count))"
    }

    $subCount = $subscriptions.Count

    # ── Display session / params ──────────────────────────────────────────────
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"           = "$scopeText ($subCount found)"
        "Microsoft Graph" = if ($graphConnected) { "Connected" } else { "Not Connected — Layer 1 checks skipped" }
        "Export to CSV"   = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"     = if ($ExportToCsv.IsPresent) { $CsvPath }  else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $subscriptionResults = @()
    $layerDist = @{
        "Layer 1 — Identity"           = 0
        "Layer 2 — Network"            = 0
        "Layer 3 — Compute/Host"       = 0
        "Layer 4 — Application"        = 0
        "Layer 5 — Data"               = 0
        "Layer 6 — Detection/Recovery" = 0
    }
    $depthDist = @{ "Missing" = 0; "Weak" = 0; "Present" = 0; "Info" = 0 }
    $riskDist = @{ "High" = 0; "Medium" = 0; "Low" = 0; "Info" = 0 }
    $successCount = 0
    $errorCount = 0

    # ── Layer 1 — Identity (tenant-scoped, run once) ──────────────────────────
    Write-Host ""
    Write-Host "  Layer 1 — Identity Controls (Tenant-Scoped)" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $tenantSubName = "Tenant-Wide"
    $tenantSubId = if ($ctx.Tenant.Id) { $ctx.Tenant.Id } else { "N/A" }

    if ($graphConnected) {
        # MFA via Conditional Access
        try {
            $caPolicies = @(Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop)
            $enabledCa = @($caPolicies | Where-Object { $_.State -eq "enabled" })
            $mfaCa = @($enabledCa  | Where-Object { $_.GrantControls -and ($_.GrantControls.BuiltInControls -contains "mfa") })
            $legacyBlock = @($enabledCa  | Where-Object {
                    $_.Conditions.ClientAppTypes -and
                    ($_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or $_.Conditions.ClientAppTypes -contains "other") -and
                    $_.GrantControls.Operator -eq "OR" -and $_.GrantControls.BuiltInControls -contains "block"
                })

            # MFA layer
            $mfaDepth = if ($mfaCa.Count -gt 0) { "Present" } else { "Missing" }
            $mfaSpof = ($mfaCa.Count -eq 0)  # if MFA is missing, identity has no defensive layer at all
            $allFindings += New-DidFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
                -Layer "Layer 1 — Identity" `
                -LayerDepth $mfaDepth `
                -Control "Identity Layer — MFA via Conditional Access" `
                -Why "Without MFA, the identity layer has only a single factor (password). A compromised password grants full access. MFA is the first complementary control that creates a second identity layer. Without it there is no depth at all at Layer 1." `
                -CurrentState $(if ($mfaCa.Count -gt 0) { "$($mfaCa.Count) CA policy/policies enforce MFA. Total CA policies: $($caPolicies.Count)." } else { "No enabled CA policy enforces MFA. Total CA policies: $($caPolicies.Count), Enabled: $($enabledCa.Count)." }) `
                -SinglePointOfFailure $mfaSpof `
                -Risk $(if ($mfaSpof) { "Single Point of Failure — password alone protects all identities. There is no second layer at the identity tier." } else { "MFA coverage exists. Verify scope and exclude-lists." }) `
                -Severity $(if ($mfaSpof) { "High" } else { "Info" }) `
                -Impact $(if ($mfaSpof) { "Credential phishing or spray attacks succeed without additional challenge, granting attackers immediate access to all resources the identity can reach." } else { "MFA provides a strong second identity layer." }) `
                -Recommendation $(if ($mfaSpof) { "Create a Conditional Access policy requiring MFA for all users targeting all cloud apps. Enable Microsoft Entra ID Protection for risk-based enforcement as a third identity layer." } else { "Audit CA scope, exclude-lists, and named locations. Enable sign-in risk policies as a third layer." })

            # Legacy auth layer
            $legacyDepth = if ($legacyBlock.Count -gt 0) { "Present" } else { "Missing" }
            $allFindings += New-DidFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
                -Layer "Layer 1 — Identity" `
                -LayerDepth $legacyDepth `
                -Control "Identity Layer — Legacy Authentication Block" `
                -Why "Legacy auth protocols bypass MFA entirely — they cannot negotiate Conditional Access tokens. Blocking legacy auth is a mandatory complementary control to MFA; without it, MFA provides no protection for those protocol paths." `
                -CurrentState $(if ($legacyBlock.Count -gt 0) { "Legacy auth block CA policy present ($($legacyBlock.Count) policy/policies)." } else { "No CA policy blocking legacy authentication detected." }) `
                -SinglePointOfFailure ($legacyBlock.Count -eq 0 -and $mfaCa.Count -gt 0) `
                -Risk $(if ($legacyBlock.Count -eq 0) { "MFA enforcement is bypassed via legacy protocols (SMTP Auth, IMAP, POP3, Basic Auth). Attackers use password-spray attacks directly against legacy endpoints." } else { "Legacy auth block present." }) `
                -Severity $(if ($legacyBlock.Count -eq 0) { "High" } else { "Info" }) `
                -Impact $(if ($legacyBlock.Count -eq 0) { "Password-spray attacks against legacy endpoints succeed even with MFA CA policies in place. The MFA layer provides no defense for these paths." } else { "Legacy auth block complements MFA — no bypass path via legacy protocols." }) `
                -Recommendation "Create a CA policy targeting 'Exchange ActiveSync clients' and 'Other clients' for all users with a Block grant control. Test in report-only mode first."

            Write-Host "  ✓ Layer 1 Identity checks complete (CA: $($caPolicies.Count) policies)" -ForegroundColor Green
        }
        catch {
            Write-Host "  ⚠ Layer 1 Identity check failed: $_" -ForegroundColor Yellow
            $allFindings += New-DidFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
                -Layer "Layer 1 — Identity" -LayerDepth "Info" `
                -Control "Layer 1 — Identity Assessment" `
                -Why "Requires Microsoft Graph connection with Policy.Read.All." `
                -CurrentState "Not Assessed — Graph call failed: $($_.Exception.Message)" `
                -SinglePointOfFailure $false `
                -Risk "Could not be confirmed." -Severity "Info" `
                -Impact "Manual review required." -Recommendation "Ensure Policy.Read.All Graph permission is granted and re-run."
        }
    }
    else {
        $allFindings += New-DidFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
            -Layer "Layer 1 — Identity" -LayerDepth "Info" `
            -Control "Layer 1 — Identity Assessment" `
            -Why "Requires Microsoft Graph connection." `
            -CurrentState "Not Assessed — Microsoft Graph connection was not established." `
            -SinglePointOfFailure $false `
            -Risk "Layer 1 identity controls could not be evaluated." -Severity "Info" `
            -Impact "Run Connect-MgGraph -Scopes 'Policy.Read.All' before assessment." `
            -Recommendation "Re-run after connecting to Microsoft Graph."
    }

    # ── Per-subscription scan ─────────────────────────────────────────────────
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

            $subFindings = 0

            # ──────────────────────────────────────────────────────────────────────
            # LAYER 2 — NETWORK
            # ──────────────────────────────────────────────────────────────────────

            # Azure Firewall / NVA (perimeter layer)
            try {
                $azFirewalls = @(Get-AzFirewall -ErrorAction Stop)
                $routeTables = @(Get-AzRouteTable -ErrorAction Stop)
                $hasNvaRoute = ($routeTables | ForEach-Object { $_.Routes | Where-Object { $_.NextHopType -eq "VirtualAppliance" } }).Count -gt 0
                $firewallLayer = if ($azFirewalls.Count -gt 0) { "Present" } elseif ($hasNvaRoute) { "Weak" } else { "Missing" }

                $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                    -Layer "Layer 2 — Network" `
                    -LayerDepth $firewallLayer `
                    -Control "Network Layer — Centralized Firewall (Perimeter)" `
                    -Why "Defense in Depth requires that the network layer has multiple controls: a centralized inspection point (firewall) AND subnet-level micro-segmentation (NSGs). NSGs alone provide only one network layer with no deep packet inspection. A firewall adds a second, independent network control." `
                    -CurrentState $(switch ($firewallLayer) {
                        "Present" { "Azure Firewall present ($($azFirewalls.Count) instance(s)). Perimeter layer exists." }
                        "Weak" { "No Azure Firewall found. NVA route(s) detected via UDRs — partial perimeter coverage." }
                        "Missing" { "No Azure Firewall or NVA route table detected. Network traffic is not being centrally inspected." }
                    }) `
                    -SinglePointOfFailure ($firewallLayer -eq "Missing") `
                    -Risk $(if ($firewallLayer -eq "Missing") { "Single Point of Failure — NSGs are the only network control. There is no centralized threat detection, FQDN filtering, or IDPS capability. NSG bypass (misconfiguration or rule error) leaves workloads fully exposed." } `
                        elseif ($firewallLayer -eq "Weak") { "NVA routing exists but Azure Firewall is preferred. Verify NVA provides equivalent inspection and HA coverage." } `
                        else { "Perimeter layer present." }) `
                    -Severity $(if ($firewallLayer -eq "Missing") { "High" } elseif ($firewallLayer -eq "Weak") { "Medium" } else { "Info" }) `
                    -Impact $(if ($firewallLayer -eq "Missing") { "C2 traffic, exfiltration, and lateral movement between VNets traverse the network uninspected. One misconfigured NSG rule exposes all resources in the affected subnet." } else { "Centralized inspection provides defence beyond NSG allow/deny rules." }) `
                    -Recommendation "Deploy Azure Firewall Premium in a hub VNet. Enable IDPS, TLS inspection, threat intelligence, and FQDN filtering. Route all spoke traffic via UDR to the firewall. Treat this as a second network layer complementing NSGs." `
                    -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Network/azureFirewalls"
                $subFindings++
            }
            catch {
                Write-Verbose "  Could not retrieve Firewall/UDR data for $($sub.Name): $_"
            }

            # NSG coverage (micro-segmentation layer)
            try {
                $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop)
                foreach ($vnet in $vnets) {
                    $subnetsWithoutNsg = @($vnet.Subnets | Where-Object {
                            $_.Name -notlike "AzureBastionSubnet" -and
                            $_.Name -notlike "GatewaySubnet" -and
                            $_.Name -notlike "AzureFirewallSubnet" -and
                            $_.Name -notlike "RouteServerSubnet" -and
                            (-not $_.NetworkSecurityGroup)
                        })

                    if ($subnetsWithoutNsg.Count -gt 0) {
                        $subnetNames = ($subnetsWithoutNsg | ForEach-Object { $_.Name }) -join ", "
                        $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                            -Layer "Layer 2 — Network" `
                            -LayerDepth "Weak" `
                            -Control "Network Layer — NSG Coverage (Micro-Segmentation)" `
                            -Why "NSGs are the subnet-level micro-segmentation control. Even with a perimeter firewall, subnets without NSGs have no local traffic filtering — east-west traffic between subnets is unrestricted. NSGs and firewall are complementary layers, not alternatives." `
                            -CurrentState "VNet '$($vnet.Name)': $($subnetsWithoutNsg.Count) subnet(s) without an NSG attached: $subnetNames" `
                            -SinglePointOfFailure $false `
                            -Risk "Traffic between unprotected subnets is not inspected at the subnet level. A workload compromise in one subnet can reach all resources in adjacent unprotected subnets." `
                            -Severity "Medium" `
                            -Impact "Lateral movement between tiers (web → app → data) is unrestricted if the perimeter firewall is bypassed or misconfigured." `
                            -Recommendation "Attach an NSG to every non-system subnet. Apply explicit allow rules for required inter-tier traffic and default-deny all other east-west flows. Pair with firewall east-west rules for dual-layer control." `
                            -ResourceScope $vnet.Id
                        $subFindings++
                    }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve VNet/NSG data for $($sub.Name): $_"
            }

            # DDoS Protection
            try {
                $ddosPlans = @(Get-AzDdosProtectionPlan -ErrorAction Stop)
                $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop)
                $ddosEnabled = @($vnets | Where-Object { $_.DdosProtectionPlan -or $_.EnableDdosProtection })

                if ($ddosEnabled.Count -eq 0 -and $vnets.Count -gt 0) {
                    $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -Layer "Layer 2 — Network" `
                        -LayerDepth "Missing" `
                        -Control "Network Layer — DDoS Protection Standard" `
                        -Why "DDoS protection is a third network layer that defends against volumetric and protocol attacks targeting public IPs. NSGs and firewalls cannot absorb or detect DDoS floods. Each layer protects against a different attack class — this is the essence of Defense in Depth." `
                        -CurrentState "No VNet in subscription '$($sub.Name)' has DDoS Protection Standard enabled. DDoS protection plans found: $($ddosPlans.Count). VNets found: $($vnets.Count)." `
                        -SinglePointOfFailure $false `
                        -Risk "Public IP addresses and VNet workloads are vulnerable to volumetric DDoS attacks that can exhaust bandwidth and service capacity without alerting security controls." `
                        -Severity "Medium" `
                        -Impact "A sustained DDoS attack can cause complete service unavailability, impacting customer-facing applications and SLA commitments. Unlike most attacks, it can succeed even with correct firewall and NSG configuration." `
                        -Recommendation "Enable Azure DDoS Protection Standard on VNets hosting public-facing workloads. Configure DDoS diagnostic alerts. This is a separate, specialized network layer that complements firewall and NSG controls." `
                        -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Network/virtualNetworks"
                    $subFindings++
                }
            }
            catch {
                Write-Verbose "  Could not retrieve DDoS plans for $($sub.Name): $_"
            }

            # ──────────────────────────────────────────────────────────────────────
            # LAYER 3 — COMPUTE / HOST
            # ──────────────────────────────────────────────────────────────────────

            # Defender for Servers
            try {
                $defenderPlans = @(Get-AzSecurityPricing -ErrorAction Stop)
                $serversPlan = $defenderPlans | Where-Object { $_.Name -like "VirtualMachines*" -or $_.Name -eq "Servers" }
                $serversEnabled = ($null -ne $serversPlan) -and ($serversPlan.PricingTier -eq "Standard")

                $hostLayerDepth = if ($serversEnabled) { "Present" } else { "Missing" }
                $vms = @()
                try { $vms = @(Get-AzVM -ErrorAction Stop) } catch { }

                if ($vms.Count -gt 0) {
                    $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -Layer "Layer 3 — Compute/Host" `
                        -LayerDepth $hostLayerDepth `
                        -Control "Host Layer — Defender for Servers (Runtime Threat Detection)" `
                        -Why "The host layer must have controls at both the OS/hypervisor level (Defender for Servers: behavioral detection, file integrity monitoring, vulnerability assessment) and the network layer (NSGs). Without host-level detection, network controls alone cannot detect in-process attacks, fileless malware, or credential dumping." `
                        -CurrentState $(if ($serversEnabled) { "Defender for Servers is enabled in this subscription. Host-layer runtime protection is active." } else { "Defender for Servers is on Free tier or not enabled. $($vms.Count) VM(s) found without host-layer runtime detection." }) `
                        -SinglePointOfFailure (-not $serversEnabled -and $vms.Count -gt 0) `
                        -Risk $(if (-not $serversEnabled) { "Single Point of Failure — VMs rely solely on network controls (NSGs/firewall). In-process attacks, credential dumping (Mimikatz), fileless malware, and lateral movement via legitimate tools cannot be detected." } else { "Host-layer protection present." }) `
                        -Severity $(if (-not $serversEnabled -and $vms.Count -gt 0) { "High" } else { "Info" }) `
                        -Impact $(if (-not $serversEnabled) { "Ransomware operators frequently use living-off-the-land techniques that produce no network anomalies — only host-level behavioral detection catches them before encryption begins." } else { "Defender for Servers provides endpoint detection and response as a complementary host layer." }) `
                        -Recommendation $(if (-not $serversEnabled) { "Enable Defender for Servers Plan 2 in Defender for Cloud. This activates Microsoft Defender for Endpoint integration, behavioral alerts, file integrity monitoring, adaptive application controls, and vulnerability assessment — all adding independent host-layer depth." } else { "Verify Defender for Endpoint integration is active. Enable file integrity monitoring and adaptive application controls for additional host-layer depth." }) `
                        -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Security/pricings"
                    $subFindings++
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Defender for Servers plan for $($sub.Name): $_"
            }

            # JIT VM Access and Bastion (access control at host layer)
            try {
                $vms = @(Get-AzVM -ErrorAction Stop)
                $bastions = @()
                try { $bastions = @(Get-AzBastion -ErrorAction Stop) } catch { }

                $jitPolicies = @()
                try { $jitPolicies = @(Get-AzJitNetworkAccessPolicy -ErrorAction Stop) } catch { }

                if ($vms.Count -gt 0) {
                    $accessLayerDepth = if ($bastions.Count -gt 0) { "Present" } elseif ($jitPolicies.Count -gt 0) { "Weak" } else { "Missing" }
                    $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -Layer "Layer 3 — Compute/Host" `
                        -LayerDepth $accessLayerDepth `
                        -Control "Host Layer — Secure Management Access (Bastion / JIT)" `
                        -Why "VM management ports (RDP 3389, SSH 22) are a dedicated attack surface. Defense in Depth at the compute layer requires not just network controls (NSG/firewall) but also an access control mechanism (Bastion/JIT) that eliminates standing port exposure. These are complementary controls, not alternatives." `
                        -CurrentState $(switch ($accessLayerDepth) {
                            "Present" { "Azure Bastion deployed ($($bastions.Count) host(s)). Secure, browser-based management access without public IP exposure." }
                            "Weak" { "JIT VM access policies detected ($($jitPolicies.Count) policy/policies). No Azure Bastion. JIT provides time-limited access but still uses public IPs." }
                            "Missing" { "No Azure Bastion or JIT VM access policy found. $($vms.Count) VM(s) in subscription." }
                        }) `
                        -SinglePointOfFailure ($accessLayerDepth -eq "Missing") `
                        -Risk $(if ($accessLayerDepth -eq "Missing") { "Single Point of Failure at host access layer — management port security depends entirely on NSG rules. Any NSG misconfiguration or overly permissive rule directly exposes RDP/SSH to the internet." } else { "Management access layer present." }) `
                        -Severity $(if ($accessLayerDepth -eq "Missing") { "High" } elseif ($accessLayerDepth -eq "Weak") { "Low" } else { "Info" }) `
                        -Impact $(if ($accessLayerDepth -eq "Missing") { "Brute-force, credential-spray, and exploitation of RDP/SSH vulnerabilities are the most common ransomware initial access vectors. Without a second access-control layer, NSG alone is insufficient." } else { "Secure management access reduces the attack surface at the host layer." }) `
                        -Recommendation "Deploy Azure Bastion for all VNets hosting VMs. Remove all public IPs from VMs. Enable JIT access as an additional time-limiting control even with Bastion. This creates two independent access-control layers at the compute tier." `
                        -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Compute/virtualMachines"
                    $subFindings++
                }
            }
            catch {
                Write-Verbose "  Could not retrieve VM management access posture for $($sub.Name): $_"
            }

            # ──────────────────────────────────────────────────────────────────────
            # LAYER 4 — APPLICATION
            # ──────────────────────────────────────────────────────────────────────

            # WAF coverage
            try {
                $appGateways = @(Get-AzApplicationGateway -ErrorAction Stop)
                $wafEnabled = @($appGateways | Where-Object { $_.WebApplicationFirewallConfiguration -and $_.WebApplicationFirewallConfiguration.Enabled })

                $frontDoorWaf = @()
                try {
                    $frontDoors = @(Get-AzFrontDoor -ErrorAction Stop)
                    $frontDoorWaf = @($frontDoors | Where-Object { $_.WebApplicationFirewallPolicy })
                }
                catch { }

                $webApps = @()
                try { $webApps = @(Get-AzWebApp -ErrorAction Stop) } catch { }

                $wafDepth = if ($wafEnabled.Count -gt 0 -or $frontDoorWaf.Count -gt 0) { "Present" } `
                    elseif ($appGateways.Count -gt 0) { "Weak" } `
                    else { "Info" }

                if ($webApps.Count -gt 0 -or $appGateways.Count -gt 0) {
                    $wafSpof = ($wafDepth -eq "Info" -and $webApps.Count -gt 0)
                    $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -Layer "Layer 4 — Application" `
                        -LayerDepth $wafDepth `
                        -Control "Application Layer — Web Application Firewall (WAF)" `
                        -Why "Application-layer attacks (OWASP Top 10: SQLi, XSS, CSRF, path traversal) bypass all network and host-layer controls and target the application directly. WAF is the dedicated application-layer control — without it, the application has no protection against L7 attacks regardless of how strong the network and host layers are." `
                        -CurrentState $(switch ($wafDepth) {
                            "Present" { "WAF enabled: App Gateway WAF: $($wafEnabled.Count) instance(s), Front Door WAF: $($frontDoorWaf.Count) instance(s)." }
                            "Weak" { "Application Gateway found but WAF is not enabled on it. $($webApps.Count) App Service(s) detected." }
                            default { "No Application Gateway or Front Door found. $($webApps.Count) App Service(s) detected without WAF coverage." }
                        }) `
                        -SinglePointOfFailure $wafSpof `
                        -Risk $(if ($wafDepth -ne "Present") { "Without WAF, web applications are vulnerable to OWASP Top 10 attacks. SQL injection can exfiltrate or corrupt databases. XSS can steal session tokens. Path traversal can expose sensitive files. None of these attacks are blocked by network or host controls." } else { "WAF provides application-layer protection." }) `
                        -Severity $(if ($wafSpof) { "High" } elseif ($wafDepth -eq "Weak") { "Medium" } else { "Info" }) `
                        -Impact $(if ($wafDepth -ne "Present") { "Application-layer attacks are the leading cause of web application data breaches. A successful SQLi attack can exfiltrate entire databases through the application tier, bypassing all network-layer controls." } else { "WAF adds a dedicated application-layer defence." }) `
                        -Recommendation "Deploy Azure Application Gateway WAF v2 or Azure Front Door WAF in Prevention mode. Apply OWASP Core Rule Set 3.2+. Enable bot protection and custom rules for application-specific threats. This is an independent application layer control that complements network and host layers." `
                        -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Network/applicationGateways"
                    $subFindings++
                }
            }
            catch {
                Write-Verbose "  Could not retrieve WAF/App Gateway data for $($sub.Name): $_"
            }

            # App Service TLS enforcement
            try {
                $webApps = @(Get-AzWebApp -ErrorAction Stop)
                foreach ($app in $webApps) {
                    try {
                        $appConfig = Get-AzWebApp -ResourceGroupName $app.ResourceGroup -Name $app.Name -ErrorAction Stop
                        $httpsOnly = $appConfig.HttpsOnly
                        $tlsVersion = $appConfig.SiteConfig.MinTlsVersion

                        if (-not $httpsOnly -or $tlsVersion -lt "1.2") {
                            $issues = @()
                            if (-not $httpsOnly) { $issues += "HTTPS-only not enforced" }
                            if ($tlsVersion -lt "1.2") { $issues += "Minimum TLS version is $tlsVersion (below 1.2)" }

                            $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                                -Layer "Layer 4 — Application" `
                                -LayerDepth "Weak" `
                                -Control "Application Layer — TLS Enforcement (App Service)" `
                                -Why "Transport encryption is a foundational application-layer control. Weak TLS configurations or HTTP support allow data in transit interception — bypassing all authentication controls because credentials and session tokens are exposed in plaintext." `
                                -CurrentState "App Service '$($app.Name)': $($issues -join '; ')." `
                                -SinglePointOfFailure $false `
                                -Risk "Weak TLS or HTTP enables man-in-the-middle attacks that intercept credentials, session tokens, and sensitive data in transit — independent of any other security controls." `
                                -Severity "Medium" `
                                -Impact "MITM interception of credentials can fully compromise user sessions. Weak cipher suites (TLS 1.0/1.1) are vulnerable to known cryptographic attacks (BEAST, POODLE)." `
                                -Recommendation "Enable HTTPS-only on all App Services. Set Minimum TLS Version to 1.2 (prefer 1.3 where supported). Disable HTTP redirect to ensure no plaintext fallback path exists." `
                                -ResourceScope $app.Id
                            $subFindings++
                        }
                    }
                    catch { }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve App Service TLS configuration for $($sub.Name): $_"
            }

            # ──────────────────────────────────────────────────────────────────────
            # LAYER 5 — DATA PROTECTION
            # ──────────────────────────────────────────────────────────────────────

            # Azure Backup coverage for VMs
            try {
                $vms = @(Get-AzVM -ErrorAction Stop)
                $rsvaults = @(Get-AzRecoveryServicesVault -ErrorAction Stop)

                if ($vms.Count -gt 0) {
                    $backedUpVms = 0
                    foreach ($vault in $rsvaults) {
                        try {
                            Set-AzRecoveryServicesVaultContext -Vault $vault -ErrorAction SilentlyContinue | Out-Null
                            $backupItems = @(Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType AzureVM -ErrorAction Stop)
                            $backedUpVms += $backupItems.Count
                        }
                        catch { }
                    }

                    $backupDepth = if ($backedUpVms -ge $vms.Count) { "Present" } `
                        elseif ($backedUpVms -gt 0) { "Weak" } `
                        else { "Missing" }

                    $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -Layer "Layer 5 — Data" `
                        -LayerDepth $backupDepth `
                        -Control "Data Layer — Azure Backup Coverage (Virtual Machines)" `
                        -Why "Data protection requires both preventive controls (encryption, access control) and recovery controls (backup). Without backup, a successful ransomware attack or accidental deletion is unrecoverable regardless of how strong all other layers are. Backup is the data-layer control that no other layer can substitute." `
                        -CurrentState $(switch ($backupDepth) {
                            "Present" { "Azure Backup coverage: $backedUpVms/$($vms.Count) VM(s) appear to have backup items in Recovery Services vaults." }
                            "Weak" { "Partial backup coverage: $backedUpVms of $($vms.Count) VM(s) have backup items. $($vms.Count - $backedUpVms) VM(s) may be unprotected." }
                            "Missing" { "No backup items found across $($rsvaults.Count) Recovery Services vault(s). $($vms.Count) VM(s) are unprotected." }
                        }) `
                        -SinglePointOfFailure ($backupDepth -eq "Missing") `
                        -Risk $(if ($backupDepth -eq "Missing") { "Single Point of Failure at data layer — no backup means ransomware encryption or accidental deletion results in permanent data loss. No other security layer can compensate for missing backup." } `
                            elseif ($backupDepth -eq "Weak") { "Partial coverage — VMs without backup have no recovery path." } `
                            else { "Backup coverage present." }) `
                        -Severity $(if ($backupDepth -eq "Missing") { "High" } elseif ($backupDepth -eq "Weak") { "Medium" } else { "Info" }) `
                        -Impact $(if ($backupDepth -ne "Present") { "Without backup, a ransomware event or storage corruption results in permanent, unrecoverable data loss for unprotected VMs. This is the most common business-ending outcome of cyberattacks." } else { "Backup provides the data-layer recovery control complementing all preventive layers." }) `
                        -Recommendation "Enable Azure Backup for all VMs using a Recovery Services vault with a backup policy (daily backup, 30-day minimum retention). Configure immutable vault to prevent backup deletion by ransomware. Test restore procedures regularly." `
                        -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Compute/virtualMachines"
                    $subFindings++
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Backup coverage for $($sub.Name): $_"
            }

            # Key Vault key/secret expiry
            try {
                $keyVaults = @(Get-AzKeyVault -ErrorAction Stop)
                foreach ($kvRef in $keyVaults) {
                    try {
                        $secrets = @(Get-AzKeyVaultSecret -VaultName $kvRef.VaultName -ErrorAction Stop)
                        $keys = @(Get-AzKeyVaultKey    -VaultName $kvRef.VaultName -ErrorAction Stop)

                        $noExpirySecrets = @($secrets | Where-Object { -not $_.Expires })
                        $noExpiryKeys = @($keys    | Where-Object { -not $_.Expires })
                        $expiredSecrets = @($secrets | Where-Object { $_.Expires -and $_.Expires -lt (Get-Date) })
                        $expiredKeys = @($keys    | Where-Object { $_.Expires -and $_.Expires -lt (Get-Date) })

                        if ($noExpirySecrets.Count -gt 0 -or $noExpiryKeys.Count -gt 0) {
                            $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                                -Layer "Layer 5 — Data" `
                                -LayerDepth "Weak" `
                                -Control "Data Layer — Key Vault Secret/Key Expiry Enforcement" `
                                -Why "Non-expiring secrets and keys create indefinite exposure windows. Secret expiry is a complementary data-layer control to access control policies — it limits the blast radius and duration of any secret compromise. A compromised secret without expiry grants permanent access to the resource it protects." `
                                -CurrentState "Key Vault '$($kvRef.VaultName)': $($noExpirySecrets.Count) secret(s) and $($noExpiryKeys.Count) key(s) have no expiry date set. $($expiredSecrets.Count) secret(s) and $($expiredKeys.Count) key(s) are expired but not rotated." `
                                -SinglePointOfFailure $false `
                                -Risk "Non-expiring secrets leak through code repositories, logs, or configuration files and remain valid indefinitely. The data layer has access control but no time-bounding layer on credential exposure." `
                                -Severity "Medium" `
                                -Impact "A secret with no expiry that is exfiltrated from a config file, environment variable, or memory dump provides permanent access to the protected resource — no rotation event will invalidate it." `
                                -Recommendation "Set expiry dates on all Key Vault secrets and keys (90-180 day maximum for secrets, 1-2 years for keys). Use Azure Key Vault references in App Service and AKS to automate rotation. Configure Key Vault expiry alerts in Azure Monitor." `
                                -ResourceScope "/subscriptions/$($sub.Id)/resourceGroups/$($kvRef.ResourceGroupName)/providers/Microsoft.KeyVault/vaults/$($kvRef.VaultName)"
                            $subFindings++
                        }
                    }
                    catch {
                        Write-Verbose "  Could not retrieve Key Vault secrets/keys for $($kvRef.VaultName): $_"
                    }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Key Vaults for $($sub.Name): $_"
            }

            # SQL Transparent Data Encryption + ATP
            try {
                $sqlServers = @(Get-AzSqlServer -ErrorAction Stop)
                foreach ($srv in $sqlServers) {
                    try {
                        $databases = @(Get-AzSqlDatabase -ServerName $srv.ServerName -ResourceGroupName $srv.ResourceGroupName -ErrorAction Stop |
                            Where-Object { $_.DatabaseName -ne "master" })

                        foreach ($db in $databases) {
                            try {
                                $tde = Get-AzSqlDatabaseTransparentDataEncryption -ServerName $srv.ServerName `
                                    -ResourceGroupName $srv.ResourceGroupName -DatabaseName $db.DatabaseName -ErrorAction Stop

                                if ($tde.State -ne "Enabled") {
                                    $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                                        -Layer "Layer 5 — Data" `
                                        -LayerDepth "Missing" `
                                        -Control "Data Layer — SQL Transparent Data Encryption (TDE)" `
                                        -Why "Encryption at rest is an independent data-layer control that protects data even if storage media, backup files, or the storage service itself is compromised. TDE is a complementary control to access control — an attacker with direct storage access (stolen drive, backup file exfiltration) cannot read data without the encryption key." `
                                        -CurrentState "SQL Database '$($db.DatabaseName)' on server '$($srv.ServerName)': TDE is not enabled. Data at rest is unencrypted." `
                                        -SinglePointOfFailure $true `
                                        -Risk "Single Point of Failure — data at rest is unprotected. Physical storage compromise, backup file theft, or storage account access gives an attacker readable data. Access control is the only data protection layer." `
                                        -Severity "High" `
                                        -Impact "Unencrypted databases expose all data in the event of storage media theft, backup exfiltration, or cross-tenant storage isolation failure. Compliance violations (GDPR, PCI-DSS, HIPAA) are immediate." `
                                        -Recommendation "Enable TDE on all SQL databases (default for new databases). Consider Customer-Managed Keys (CMK) via Azure Key Vault for additional data-layer control, enabling key revocation as an incident response action." `
                                        -ResourceScope $db.ResourceId
                                    $subFindings++
                                }
                            }
                            catch { }
                        }

                        # ATP (Advanced Threat Protection at data layer)
                        try {
                            $atp = Get-AzSqlServerAdvancedThreatProtectionSetting -ServerName $srv.ServerName `
                                -ResourceGroupName $srv.ResourceGroupName -ErrorAction Stop

                            if ($atp.ThreatDetectionState -ne "Enabled") {
                                $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                                    -Layer "Layer 5 — Data" `
                                    -LayerDepth "Missing" `
                                    -Control "Data Layer — SQL Advanced Threat Protection (ATP)" `
                                    -Why "SQL ATP is a dedicated data-layer detection control: it monitors query patterns for SQL injection, anomalous access, and data exfiltration attempts. Without ATP, the data layer has only access control (authentication/authorization) and no detection capability — detection depends entirely on network and host layers which cannot see SQL-layer attacks." `
                                    -CurrentState "SQL Server '$($srv.ServerName)': Advanced Threat Protection is not enabled. No SQL-layer threat detection in place." `
                                    -SinglePointOfFailure $false `
                                    -Risk "SQL injection, stored procedure abuse, and bulk data extraction by compromised accounts generate no alerts without SQL-layer detection. These attacks succeed even with perfect network controls." `
                                    -Severity "Medium" `
                                    -Impact "SQL injection and insider data theft are invisible to network and host-layer controls. Without ATP, the data layer has no detection depth — only preventive controls." `
                                    -Recommendation "Enable Microsoft Defender for SQL (Advanced Threat Protection) on all SQL servers. Configure email alerts and integrate with Microsoft Sentinel. This adds a detection layer specifically at the data tier." `
                                    -ResourceScope $srv.ResourceId
                                $subFindings++
                            }
                        }
                        catch { }
                    }
                    catch { }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve SQL Server data for $($sub.Name): $_"
            }

            # ──────────────────────────────────────────────────────────────────────
            # LAYER 6 — DETECTION & RECOVERY
            # ──────────────────────────────────────────────────────────────────────

            # Microsoft Sentinel
            try {
                $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop)
                $sentinelWs = @()

                foreach ($ws in $workspaces) {
                    try {
                        $solutions = @(Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $ws.ResourceGroupName `
                                -WorkspaceName $ws.Name -ErrorAction Stop |
                            Where-Object { $_.Name -eq "SecurityInsights" -and $_.Enabled -eq $true })
                        if ($solutions.Count -gt 0) { $sentinelWs += $ws }
                    }
                    catch { }
                }

                $sentinelDepth = if ($sentinelWs.Count -gt 0) { "Present" } else { "Missing" }
                $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                    -Layer "Layer 6 — Detection/Recovery" `
                    -LayerDepth $sentinelDepth `
                    -Control "Detection Layer — Microsoft Sentinel (SIEM/SOAR)" `
                    -Why "Defense in Depth requires that attacks which bypass all preventive layers are detected and contained before they cause maximum impact. Sentinel provides correlated, cross-layer detection — it sees signals from identity, network, host, application, and data layers simultaneously. Without it, each layer's logs are siloed, multi-stage attacks go undetected, and dwell time extends to months." `
                    -CurrentState $(if ($sentinelWs.Count -gt 0) { "Microsoft Sentinel active on $($sentinelWs.Count) workspace(s): $(($sentinelWs | ForEach-Object { $_.Name }) -join ', ')." } else { "No Microsoft Sentinel workspace detected. $($workspaces.Count) Log Analytics workspace(s) found without SecurityInsights solution." }) `
                    -SinglePointOfFailure ($sentinelDepth -eq "Missing") `
                    -Risk $(if ($sentinelDepth -eq "Missing") { "Single Point of Failure at the detection layer — if any preventive control across layers 1–5 is bypassed, the breach will go undetected. Multi-stage attacks (initial access → privilege escalation → data exfiltration) require cross-layer correlation to detect." } else { "SIEM detection layer present." }) `
                    -Severity $(if ($sentinelDepth -eq "Missing") { "High" } else { "Info" }) `
                    -Impact $(if ($sentinelDepth -eq "Missing") { "The average breach dwell time without a SIEM is 200+ days. An attacker who bypasses any preventive layer operates freely, harvesting credentials, escalating privileges, and exfiltrating data without triggering any alert." } else { "Sentinel provides the cross-layer detection capability that makes Defense in Depth operationally effective." }) `
                    -Recommendation "Deploy Microsoft Sentinel on a centralized Log Analytics workspace. Enable data connectors for all layers (Entra ID, Defender, Azure Activity, NSG flow logs, App Gateway WAF, SQL ATP). Enable analytics rules, UEBA, and threat intelligence. Configure SOAR playbooks for automated containment." `
                    -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.OperationalInsights/workspaces"
                $subFindings++
            }
            catch {
                Write-Verbose "  Could not retrieve Sentinel/Log Analytics data for $($sub.Name): $_"
            }

            # Recovery Services Vault / ASR
            try {
                $rsvaults = @(Get-AzRecoveryServicesVault -ErrorAction Stop)

                if ($rsvaults.Count -eq 0) {
                    $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -Layer "Layer 6 — Detection/Recovery" `
                        -LayerDepth "Missing" `
                        -Control "Recovery Layer — Recovery Services Vault Presence" `
                        -Why "Recovery is an independent layer of Defense in Depth. If all preventive and detection controls fail — or if an attack succeeds before detection — recovery capability determines whether the outcome is a brief incident or a catastrophic business disruption. Backup and recovery are non-negotiable complementary controls to all other layers." `
                        -CurrentState "No Recovery Services Vault found in subscription '$($sub.Name)'. No backup or disaster recovery infrastructure is configured." `
                        -SinglePointOfFailure $true `
                        -Risk "Single Point of Failure at the recovery layer — if any attack across layers 1–5 succeeds and causes data loss or service disruption, there is no recovery path. The organization is entirely dependent on preventive controls not failing." `
                        -Severity "High" `
                        -Impact "A ransomware attack, catastrophic misconfig, or insider deletion event with no backup and no Recovery Services vault results in permanent, unrecoverable data and service loss — regardless of how strong all other security layers are." `
                        -Recommendation "Create at least one Recovery Services Vault. Configure Azure Backup for all VMs, databases, and file shares. Evaluate Azure Site Recovery for critical workloads. Enable vault immutability to prevent ransomware from deleting backups. Test restore procedures on a quarterly schedule." `
                        -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.RecoveryServices/vaults"
                    $subFindings++
                }
                else {
                    # Check for immutable vaults
                    $immutableVaults = @($rsvaults | Where-Object {
                            try {
                                (Get-AzRecoveryServicesVaultProperty -VaultId $_.ID -ErrorAction Stop).ImmutabilityState -eq "Unlocked" -or
                                (Get-AzRecoveryServicesVaultProperty -VaultId $_.ID -ErrorAction Stop).ImmutabilityState -eq "Locked" 
                            }
                            catch { $false }
                        })

                    if ($immutableVaults.Count -eq 0) {
                        $allFindings += New-DidFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                            -Layer "Layer 6 — Detection/Recovery" `
                            -LayerDepth "Weak" `
                            -Control "Recovery Layer — Vault Immutability (Ransomware-Proof Backup)" `
                            -Why "Modern ransomware operators specifically target and delete backups before deploying encryption payloads. Vault immutability is a complementary control to backup presence — it ensures the recovery layer cannot itself be compromised. Without it, the recovery layer is a single, destroyable control." `
                            -CurrentState "$($rsvaults.Count) Recovery Services Vault(s) found but none appear to have immutability enabled. Backup data can be deleted by any identity with Backup Contributor access." `
                            -SinglePointOfFailure $false `
                            -Risk "An attacker with Backup Contributor or higher access can delete all backup data, destroying the recovery layer before deploying ransomware. Without immutability, backup provides no defense against sophisticated attackers who target backup infrastructure." `
                            -Severity "Medium" `
                            -Impact "Ransomware groups specifically delete backups as part of their playbook. Non-immutable vaults mean ransomware can successfully encrypt all production data AND destroy the recovery capability simultaneously." `
                            -Recommendation "Enable vault immutability on all Recovery Services Vaults (start with 'Unlocked' to allow operational changes, then consider 'Locked' for critical vaults). Restrict Backup Delete permissions using RBAC. Store at least one backup copy offline or in a geo-redundant immutable vault." `
                            -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.RecoveryServices/vaults"
                        $subFindings++
                    }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Recovery Services Vault data for $($sub.Name): $_"
            }

            # ── Per-subscription result ───────────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Findings: $subFindings" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Findings: $subFindings"
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

    # ── Aggregate distributions ───────────────────────────────────────────────
    foreach ($f in $allFindings) {
        if ($layerDist.ContainsKey($f.Layer)) { $layerDist[$f.Layer]++ }  else { $layerDist[$f.Layer] = 1 }
        if ($depthDist.ContainsKey($f.LayerDepth)) { $depthDist[$f.LayerDepth]++ }  else { $depthDist[$f.LayerDepth] = 1 }
        if ($riskDist.ContainsKey($f.Severity)) { $riskDist[$f.Severity]++ }
    }

    $spofTotal = @($allFindings | Where-Object { $_.SinglePointOfFailure -eq "Yes" }).Count

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Total Findings"              = $allFindings.Count
            "High Severity"               = ($allFindings | Where-Object { $_.Severity -eq "High" } | Measure-Object).Count
            "Medium Severity"             = ($allFindings | Where-Object { $_.Severity -eq "Medium" } | Measure-Object).Count
            "Low Severity"                = ($allFindings | Where-Object { $_.Severity -eq "Low" } | Measure-Object).Count
            "Informational"               = ($allFindings | Where-Object { $_.Severity -eq "Info" } | Measure-Object).Count
            "Single Points of Failure"    = $spofTotal
            "Missing Layers"              = $depthDist["Missing"]
            "Weak Layers"                 = $depthDist["Weak"]
            "Microsoft Graph Connected"   = if ($graphConnected) { "Yes" } else { "No" }
            "Execution Time"              = $duration
        })

    Write-LayerBreakdown -Layers $layerDist
    Write-SpofSummary    -SpofCount $spofTotal

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
                $allFindings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

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

            $htmlContent = Generate-DefenseInDepthHtml `
                -SessionInfo          $sessionInfo `
                -ScanParameters       $scanParams `
                -Findings             $allFindings `
                -LayerDistribution    $layerDist `
                -DepthDistribution    $depthDist `
                -RiskDistribution     $riskDist `
                -SubscriptionResults  $subscriptionResults `
                -GeneratedOn          (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -GraphConnected       $graphConnected

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        try {
            $allFindings |
            Select-Object SubscriptionName, Layer, LayerDepth, Control, Severity, SinglePointOfFailure, Recommendation |
            Out-GridView -Title "Azure Defense in Depth Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No findings generated. Verify permissions and that resources exist in the targeted subscriptions." -ForegroundColor Yellow
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
