<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Assesses Azure network architecture posture — VNets, subnets, peering, hub-and-spoke
    topology, route tables, NSGs, Azure Firewall, Private Endpoints, and public exposure —
    across one or more subscriptions, with an architectural risk model and interactive
    HTML dashboard.

.DESCRIPTION
    Get-AzureNetworkArchitectureAssessment evaluates the Azure network as an architecture,
    not as a collection of individual resource inventories. It models connectivity topology,
    identifies architectural patterns (hub-and-spoke, flat/mesh peering, standalone VNets),
    and surfaces findings that represent meaningful architectural, security, or resilience
    risk — not configuration drift checklists.

    Assessment areas:

    Topology & Connectivity
        - Hub-and-spoke detection (VNets with multiple spoke peers)
        - Orphaned or isolated VNets with no connectivity
        - VNet peering relationships and transitivity gaps
        - Missing or asymmetric peering configurations

    Segmentation & Trust Boundaries
        - Subnets without NSG coverage (potential lateral movement paths)
        - Subnets without route table control (uncontrolled egress)
        - Wide address spaces with no subnet segmentation
        - Mixed workload subnets where tier isolation is absent

    Traffic Control & Routing
        - Default route 0.0.0.0/0 to Internet (egress not centralized)
        - User-Defined Routes present but potentially bypassing central security
        - VNets with no egress control — no Firewall, no UDR, no NVA
        - BGP propagation disabled (potential black-hole routes)

    Public Exposure & Internet-Facing Resources
        - Subnets with internet-facing resources and weak NSG coverage
        - Resources with public IPs where Private Endpoints should be preferred
        - NSGs with broad inbound allow rules (any source, low port ranges)
        - Application Gateways and Load Balancers without WAF or DDoS cover

    Private Connectivity
        - Private Endpoints inventory and DNS integration gaps
        - Key Vault, Storage, SQL without private endpoint where public access is on
        - Missing Private DNS Zones for private endpoint resolution

    Centralized Security Controls
        - Azure Firewall presence and coverage relative to VNets
        - VNets routing internet egress without passing through a Firewall
        - DDoS Protection Standard coverage across production VNets

    Resilience & Single Points of Failure
        - Single-region hub VNets without redundancy signals
        - VPN/ExpressRoute gateways without redundant connections
        - Critical subnets mapped to single availability zone or no zone

    Each finding is assigned:
        - Severity  : Critical / High / Medium / Low
        - Category  : Topology | Segmentation | Routing | Exposure | PrivateConn | Security | Resilience
        - BusinessImpact : concise description of the business/operational risk
        - Recommendation : architect-grade actionable next step

    The script does not flag every deviation from Azure defaults. It focuses on findings
    where the gap materially affects security, resilience, scalability, or business continuity.

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. Exports all architecture findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same directory, .html extension).
    Default: C:\Temp\AzureNetworkArchitecture-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside -CsvPath
    (or the default path). Optionally writes a CSV file when -ExportToCsv is specified.
    Displays results in an interactive Grid View window where a GUI is available.

.EXAMPLE
    Get-AzureNetworkArchitectureAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureNetworkArchitectureAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureNetworkArchitectureAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\NetworkArch.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Network architecture posture assessment
                            covering topology, segmentation, routing, public exposure,
                            private connectivity, centralized security controls, and
                            resilience patterns. CSV export and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Network) — installed automatically
           with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at subscription scope.
        4. Microsoft.Network/*/read permissions across VNets, NSGs, Route Tables,
           Firewalls, Private Endpoints, and Public IP addresses.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Hub detection is heuristic: a VNet with 3+ peers OR named with hub/transit/shared
          patterns is treated as a hub candidate. Manual review is recommended.
        - NSG effective rules (merged inherited + direct rules) are not evaluated;
          the assessment works at the association level. For effective rule analysis,
          use Get-AzEffectiveNetworkSecurityGroup separately.
        - ExpressRoute circuit health and BGP prefix counts are not retrieved;
          gateway presence is assessed, not circuit-level connectivity state.
        - Cross-subscription peering is detected by inspecting each subscription's own
          VNet objects; remote-side peering state confirmation requires Reader access
          to the remote subscription.
        - Interactive Grid View requires a GUI-capable session. Skipped gracefully in
          headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview
    https://learn.microsoft.com/en-us/azure/architecture/reference-architectures/hybrid-networking/hub-spoke
    https://learn.microsoft.com/en-us/azure/firewall/overview
    https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview
    https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview

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
  Write-CenteredText "Azure Network Architecture Assessment v1.0" -Color White
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

Function Write-FindingSummary {
  param([array]$Findings)

  if ($Findings.Count -eq 0) { return }

  $critical = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
  $high = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
  $medium = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
  $low = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count

  Write-Host ""
  Write-Host "  Risk Finding Summary" -ForegroundColor Cyan
  Write-Host "  " -NoNewline
  Write-Host ("─" * 76) -ForegroundColor DarkGray
  Write-Host "  Total Findings     : $($Findings.Count)" -ForegroundColor White
  Write-Host "  Critical           : $critical" -ForegroundColor Red
  Write-Host "  High               : $high"     -ForegroundColor Yellow
  Write-Host "  Medium             : $medium"   -ForegroundColor Cyan
  Write-Host "  Low                : $low"      -ForegroundColor DarkGray
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

Function New-Finding {
  param(
    [string]$SubscriptionName,
    [string]$SubscriptionId,
    [string]$ResourceName,
    [string]$ResourceType,
    [string]$ResourceGroup,
    [string]$Category,
    [string]$Severity,
    [string]$FindingTitle,
    [string]$Detail,
    [string]$BusinessImpact,
    [string]$Recommendation
  )

  return [pscustomobject]@{
    SubscriptionName = $SubscriptionName
    SubscriptionId   = $SubscriptionId
    ResourceName     = $ResourceName
    ResourceType     = $ResourceType
    ResourceGroup    = $ResourceGroup
    Category         = $Category
    Severity         = $Severity
    FindingTitle     = $FindingTitle
    Detail           = $Detail
    BusinessImpact   = $BusinessImpact
    Recommendation   = $Recommendation
  }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-NetworkArchitectureHtml {
  param(
    [hashtable]$SessionInfo,
    [hashtable]$ScanParameters,
    [array]$Findings,
    [array]$VNetSummary,
    [hashtable]$CategoryDist,
    [hashtable]$SeverityDist,
    [array]$SubscriptionResults,
    [string]$GeneratedOn
  )

  $totalFindings = @($Findings).Count
  $criticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
  $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
  $mediumCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
  $lowCount = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
  $totalVnets = @($VNetSummary).Count

  # ── Finding table rows ────────────────────────────────────────────────────
  $findingRows = ""
  $fIdx = 0
  foreach ($f in $Findings) {
    $sevCls = switch ($f.Severity) {
      "Critical" { "badge-red" }
      "High" { "badge-amber" }
      "Medium" { "badge-blue" }
      default { "" }
    }
    $catCls = switch ($f.Category) {
      "Topology" { "badge-blue" }
      "Segmentation" { "badge-amber" }
      "Routing" { "badge-blue" }
      "Exposure" { "badge-red" }
      "PrivateConn" { "badge-amber" }
      "Security" { "badge-red" }
      "Resilience" { "badge-amber" }
      default { "" }
    }
    $title = if ($f.FindingTitle.Length -gt 50) { EscHtml($f.FindingTitle.Substring(0, 47) + "...") } else { EscHtml $f.FindingTitle }
    $resName = if ($f.ResourceName.Length -gt 30) { EscHtml($f.ResourceName.Substring(0, 27) + "...") } else { EscHtml $f.ResourceName }
    $findingRows += @"
          <tr onclick="showFindingDetail($fIdx)">
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td><span class="badge $catCls">$(EscHtml $f.Category)</span></td>
            <td title="$(EscHtml $f.FindingTitle)">$title</td>
            <td title="$(EscHtml $f.ResourceName)">$resName</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
          </tr>
"@
    $fIdx++
  }

  # ── VNet summary rows ─────────────────────────────────────────────────────
  $vnetRows = ""
  foreach ($v in $VNetSummary) {
    $roleLabel = $v.Role
    $roleCls = switch ($v.Role) {
      "Hub" { "badge-blue" }
      "Spoke" { "badge-green" }
      "Isolated" { "badge-red" }
      default { "" }
    }
    $ddosBadge = if ($v.DdosEnabled) {
      '<span class="badge badge-green">✓ DDoS</span>'
    }
    else {
      '<span class="badge badge-amber">No DDoS</span>'
    }
    $vnetRows += @"
          <tr>
            <td title="$(EscHtml $v.Name)">$(if ($v.Name.Length -gt 34) { EscHtml($v.Name.Substring(0,31)+"...") } else { EscHtml $v.Name })</td>
            <td>$(EscHtml $v.SubscriptionName)</td>
            <td><span class="badge $roleCls">$roleLabel</span></td>
            <td style="font-family:var(--mono);font-size:11px">$(EscHtml $v.AddressSpace)</td>
            <td>$($v.SubnetCount)</td>
            <td>$($v.PeerCount)</td>
            <td>$ddosBadge</td>
          </tr>
"@
  }

  # ── Subscription rows ─────────────────────────────────────────────────────
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

  # ── Category bar rows ─────────────────────────────────────────────────────
  $catTotal = ($CategoryDist.Values | Measure-Object -Sum).Sum
  $catRows = ""
  $catColors = @{
    "Topology"     = "var(--accent)"
    "Segmentation" = "var(--amber)"
    "Routing"      = "var(--accent2)"
    "Exposure"     = "var(--red)"
    "PrivateConn"  = "var(--amber)"
    "Security"     = "var(--red)"
    "Resilience"   = "var(--accent3)"
  }
  foreach ($c in ($CategoryDist.GetEnumerator() | Sort-Object Value -Descending)) {
    $pct = if ($catTotal -gt 0) { [math]::Round(($c.Value / $catTotal) * 100) } else { 0 }
    $barColor = if ($catColors.ContainsKey($c.Key)) { $catColors[$c.Key] } else { "var(--accent)" }
    $catRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $c.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($c.Value) ($pct%)</span>
          </div>
"@
  }

  # ── Severity bar rows ─────────────────────────────────────────────────────
  $sevTotal = ($SeverityDist.Values | Measure-Object -Sum).Sum
  $sevRows = ""
  $sevColors = @{ "Critical" = "var(--red)"; "High" = "var(--amber)"; "Medium" = "var(--accent)"; "Low" = "var(--muted)" }
  foreach ($sv in @("Critical", "High", "Medium", "Low")) {
    $cnt = if ($SeverityDist.ContainsKey($sv)) { $SeverityDist[$sv] } else { 0 }
    $pct = if ($sevTotal -gt 0) { [math]::Round(($cnt / $sevTotal) * 100) } else { 0 }
    $barColor = if ($sevColors.ContainsKey($sv)) { $sevColors[$sv] } else { "var(--accent)" }
    $sevRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $sv)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$cnt ($pct%)</span>
          </div>
"@
  }

  # ── Findings JSON for detail drawer ──────────────────────────────────────
  $findingsJson = "["
  foreach ($f in $Findings) {
    $findingsJson += "{" +
    """sev"":""$(EscJ $f.Severity)""," +
    """cat"":""$(EscJ $f.Category)""," +
    """title"":""$(EscJ $f.FindingTitle)""," +
    """detail"":""$(EscJ $f.Detail)""," +
    """impact"":""$(EscJ $f.BusinessImpact)""," +
    """rec"":""$(EscJ $f.Recommendation)""," +
    """res"":""$(EscJ $f.ResourceName)""," +
    """resType"":""$(EscJ $f.ResourceType)""," +
    """rg"":""$(EscJ $f.ResourceGroup)""," +
    """sub"":""$(EscJ $f.SubscriptionName)""" +
    "},"
  }
  $findingsJson = $findingsJson.TrimEnd(",") + "]"

  $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Network Architecture Assessment</title>
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
.drawer-field-value{font-size:13px;word-break:break-word;line-height:1.5;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.impact-box{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.3);border-radius:var(--radius-sm);padding:12px 14px;font-size:13px;line-height:1.5;color:var(--amber);margin-bottom:14px;}
.rec-box{background:rgba(56,139,253,.08);border:1px solid rgba(56,139,253,.3);border-radius:var(--radius-sm);padding:12px 14px;font-size:13px;line-height:1.5;color:var(--accent);margin-bottom:14px;}
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
    <div class="logo-icon">🌐</div>
    <div class="logo-title">Network Architecture</div>
    <div class="logo-sub">Azure Architecture Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">⚠️</span> Findings</button>
    <button class="nav-btn" onclick="showPage('vnets',this)"><span class="nav-icon">🔗</span> VNet Inventory</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">🔍</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Network Architecture Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Network Architecture Overview</div>
      <div class="page-sub">Architecture posture across __SUB_COUNT__ subscription(s) · __TOTAL_VNETS__ VNets assessed</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical Findings</div>
        <div class="stat-sub">Immediate attention required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Findings</div>
        <div class="stat-sub">Address in near-term</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium Findings</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low Findings</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__TOTAL_FINDINGS__</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__TOTAL_VNETS__</div>
        <div class="stat-label">VNets Assessed</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📂 Findings by Category</div>
        __CAT_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🎯 Findings by Severity</div>
        __SEV_ROWS__
      </div>
    </div>
  </div>

  <!-- Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Architecture Findings</div>
      <div class="page-sub">Click any row to view full details, business impact, and recommended action</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findingSearch" placeholder="Search finding, resource, subscription…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="filterCat" onchange="filterFindings()">
          <option value="">All Categories</option>
          <option value="Topology">Topology</option>
          <option value="Segmentation">Segmentation</option>
          <option value="Routing">Routing</option>
          <option value="Exposure">Exposure</option>
          <option value="PrivateConn">PrivateConn</option>
          <option value="Security">Security</option>
          <option value="Resilience">Resilience</option>
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
              <th onclick="sortFindings(2)">Finding</th>
              <th onclick="sortFindings(3)">Resource</th>
              <th onclick="sortFindings(4)">Subscription</th>
            </tr>
          </thead>
          <tbody id="findingBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findingPagination"></div>
    </div>
  </div>

  <!-- VNet Inventory -->
  <div id="page-vnets" class="page">
    <div class="page-header">
      <div class="page-title">VNet Inventory</div>
      <div class="page-sub">All assessed Virtual Networks with topology role, addressing, and DDoS coverage</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>VNet Name</th>
              <th>Subscription</th>
              <th>Role</th>
              <th>Address Space</th>
              <th>Subnets</th>
              <th>Peers</th>
              <th>DDoS</th>
            </tr>
          </thead>
          <tbody>__VNET_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription assessment outcome</div>
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

function filterFindings(){
  const q=document.getElementById('findingSearch').value.toLowerCase();
  const sv=document.getElementById('filterSev').value;
  const ct=document.getElementById('filterCat').value;
  findingFiltered=FINDING_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mS=!sv||r.sev===sv;
    const mC=!ct||r.cat===ct;
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
  const keys=['sev','cat','title','res','sub'];
  findingFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    const sevOrd={Critical:0,High:1,Medium:2,Low:3};
    if(k==='sev') return findingSortAsc?(sevOrd[av]??9)-(sevOrd[bv]??9):(sevOrd[bv]??9)-(sevOrd[av]??9);
    return findingSortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  renderFindings();
}

function renderFindings(){
  const tbody=document.getElementById('findingBody');
  const start=(findingPage-1)*findingPageSz;
  const slice=findingFiltered.slice(start,start+findingPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=FINDING_DATA.indexOf(r);
    const sCls=r.sev==='Critical'?'badge-red':r.sev==='High'?'badge-amber':r.sev==='Medium'?'badge-blue':'';
    const cCls=r.cat==='Exposure'||r.cat==='Security'?'badge-red':r.cat==='Segmentation'||r.cat==='Resilience'||r.cat==='PrivateConn'?'badge-amber':'badge-blue';
    const nm=r.title.length>50?r.title.substring(0,47)+'...':r.title;
    const rn=r.res.length>30?r.res.substring(0,27)+'...':r.res;
    return `<tr onclick="showFindingDetail(${gi})">
      <td><span class="badge ${sCls}">${escH(r.sev)}</span></td>
      <td><span class="badge ${cCls}">${escH(r.cat)}</span></td>
      <td title="${escH(r.title)}">${escH(nm)}</td>
      <td title="${escH(r.res)}">${escH(rn)}</td>
      <td>${escH(r.sub)}</td>
    </tr>`;
  }).join('');
  renderFindingPg();
}

function renderFindingPg(){
  const total=Math.ceil(findingFiltered.length/findingPageSz);
  const el=document.getElementById('findingPagination');
  let h=`<span>${findingFiltered.length} finding(s)</span>`;
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

function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=FINDING_DATA[idx];
  if(!r)return;
  const sCls=r.sev==='Critical'?'badge-red':r.sev==='High'?'badge-amber':r.sev==='Medium'?'badge-blue':'';
  document.getElementById('drawerTitle').textContent=r.title;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FINDING_DATA.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field">
      <div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sCls}">${escH(r.sev)}</span>&nbsp;<span class="badge badge-blue">${escH(r.cat)}</span></div>
    </div>
    <div class="drawer-field"><div class="drawer-field-label">Resource</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.res)}<br/><span style="color:var(--muted)">${escH(r.resType)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-section">Finding Detail</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.detail)}</div></div>
    <div class="drawer-section">Business Impact</div>
    <div class="impact-box">${escH(r.impact)}</div>
    <div class="drawer-section">Recommended Action</div>
    <div class="rec-box">${escH(r.rec)}</div>
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
    -replace '__CRITICAL_COUNT__', $criticalCount `
    -replace '__HIGH_COUNT__', $highCount `
    -replace '__MEDIUM_COUNT__', $mediumCount `
    -replace '__LOW_COUNT__', $lowCount `
    -replace '__TOTAL_VNETS__', $totalVnets `
    -replace '__CAT_ROWS__', $catRows `
    -replace '__SEV_ROWS__', $sevRows `
    -replace '__FINDING_ROWS__', $findingRows `
    -replace '__VNET_ROWS__', $vnetRows `
    -replace '__SUB_ROWS__', $subRows `
    -replace '__TENANT__', $SessionInfo.Tenant `
    -replace '__ACCOUNT__', $SessionInfo.Account `
    -replace '__ENVIRONMENT__', $SessionInfo.Environment `
    -replace '__SCOPE__', $ScanParameters.Scope `
    -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
    -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
    -replace '__FINDINGS_JSON__', $findingsJson

  return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureNetworkArchitectureAssessment {
  [CmdletBinding()]
  param (
    [switch]$AllSubscriptions,

    [string[]]$SubscriptionIds,

    [switch]$ExportToCsv,

    [ValidateNotNullOrEmpty()]
    [string]$CsvPath = "C:\Temp\AzureNetworkArchitecture-Report.csv"
  )

  $startTime = Get-Date

  Write-Banner

  # ── Module check ──────────────────────────────────────────────────────────
  $requiredModules = @("Az.Accounts", "Az.Network")

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
    if (-not $ctx -or -not $ctx.Subscription) {
      Write-Host "  ✗ No active Azure session found. Please run Connect-AzAccount first." -ForegroundColor Red
      return
    }
  }
  catch {
    Write-Host "  ✗ Could not retrieve Azure context: $_" -ForegroundColor Red
    return
  }

  # ── Resolve subscriptions ─────────────────────────────────────────────────
  $subscriptions = @()
  try {
    if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0 -and -not $AllSubscriptions.IsPresent) {
      foreach ($sid in $SubscriptionIds) {
        $sub = Get-AzSubscription -SubscriptionId $sid -ErrorAction SilentlyContinue
        if ($sub) { $subscriptions += $sub }
        else { Write-Warning "  Subscription '$sid' not found or not accessible." }
      }
      $scopeText = "Specified Subscriptions"
    }
    else {
      $subscriptions = @(Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq "Enabled" })
      $scopeText = "All Enabled Subscriptions"
    }
  }
  catch {
    Write-Host "  ✗ Could not retrieve subscriptions: $_" -ForegroundColor Red
    return
  }

  $subCount = $subscriptions.Count

  if ($subCount -eq 0) {
    Write-Host "  ⚠ No accessible subscriptions found." -ForegroundColor Yellow
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
    "Export Path"   = if ($ExportToCsv.IsPresent) { $CsvPath }  else { "" }
  }

  # ── Collections ───────────────────────────────────────────────────────────
  $allFindings = @()
  $allVnetSummary = @()
  $subscriptionResults = @()
  $categoryDist = @{}
  $severityDist = @{ "Critical" = 0; "High" = 0; "Medium" = 0; "Low" = 0 }
  $successCount = 0
  $errorCount = 0

  # ── Scan ──────────────────────────────────────────────────────────────────
  Write-ScanProgress
  Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

  # $maxNameLen = ([math]::Max(
  #  ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
  #  35
  # ))

  $maxNameLen = 35

  foreach ($subscription in @($subscriptions)) {
    if ($null -ne $subscription -and $null -ne $subscription.Name) {
      $nameLength = $subscription.Name.ToString().Length

      if ($nameLength -gt $maxNameLen) {
        $maxNameLen = $nameLength
      }
    }
  }

  $subIndex = 1

  foreach ($sub in $subscriptions) {
    try {
      Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

      Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

      # ── Retrieve Network Resources ────────────────────────────────────
      $vnets = @()
      $nsgs = @()
      $routeTables = @()
      $firewalls = @()
      $privateEndpts = @()
      $publicIps = @()
      $appGateways = @()

      try { $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop) }           catch { Write-Verbose "VNet retrieval failed for $($sub.Name): $_" }
      try { $nsgs = @(Get-AzNetworkSecurityGroup -ErrorAction Stop) }      catch { Write-Verbose "NSG retrieval failed for $($sub.Name): $_" }
      try { $routeTables = @(Get-AzRouteTable -ErrorAction Stop) }                catch { Write-Verbose "Route table retrieval failed for $($sub.Name): $_" }
      try { $firewalls = @(Get-AzFirewall -ErrorAction Stop) }                  catch { Write-Verbose "Firewall retrieval failed for $($sub.Name): $_" }
      try { $privateEndpts = @(Get-AzPrivateEndpoint -ErrorAction Stop) }           catch { Write-Verbose "Private endpoint retrieval failed for $($sub.Name): $_" }
      try { $publicIps = @(Get-AzPublicIpAddress -ErrorAction Stop) }           catch { Write-Verbose "Public IP retrieval failed for $($sub.Name): $_" }
      try { $appGateways = @(Get-AzApplicationGateway -ErrorAction Stop) }        catch { Write-Verbose "App Gateway retrieval failed for $($sub.Name): $_" }

      # ── Build VNet context map ────────────────────────────────────────
      # Map VNet ID → name for peering resolution
      $vnetIdMap = @{}
      foreach ($v in $vnets) {
        if ($v.Id) { $vnetIdMap[$v.Id.ToLower()] = $v.Name }
      }

      $subFindingCount = 0

      foreach ($vnet in $vnets) {
        $vnetName = $vnet.Name
        $vnetRg = $vnet.ResourceGroupName
        $subnets = @($vnet.Subnets)
        $peers = @($vnet.VirtualNetworkPeerings)
        $peerCount = $peers.Count

        # Address space string
        $addrSpace = ($vnet.AddressSpace.AddressPrefixes -join ", ")

        # DDoS protection
        $ddosEnabled = $false
        try { $ddosEnabled = ($vnet.EnableDdosProtection -eq $true) }
        catch { }

        # Topology role heuristic
        # Hub: 3+ peers OR name contains hub/transit/shared/connectivity/network patterns
        $hubNamePattern = "hub|transit|shared|connectivity|core-net|platform|landing.zone.net"
        $isHubByName = ($vnetName -match $hubNamePattern)
        $isHubByPeers = ($peerCount -ge 3)
        $vnetRole = if ($isHubByName -or $isHubByPeers) { "Hub" }
        elseif ($peerCount -eq 0) { "Isolated" }
        else { "Spoke" }

        $allVnetSummary += [pscustomobject]@{
          Name             = $vnetName
          SubscriptionName = $sub.Name
          SubscriptionId   = $sub.Id
          Role             = $vnetRole
          AddressSpace     = $addrSpace
          SubnetCount      = $subnets.Count
          PeerCount        = $peerCount
          DdosEnabled      = $ddosEnabled
          ResourceGroup    = $vnetRg
        }

        # ── T1: Isolated VNet — no connectivity ───────────────────────
        if ($peerCount -eq 0 -and $firewalls.Count -eq 0) {
          $subnetsWithResources = @($subnets | Where-Object {
              $_.IpConfigurations -and $_.IpConfigurations.Count -gt 0
            }).Count

          if ($subnetsWithResources -gt 0) {
            $f = New-Finding `
              -SubscriptionName $sub.Name `
              -SubscriptionId   $sub.Id `
              -ResourceName     $vnetName `
              -ResourceType     "VirtualNetwork" `
              -ResourceGroup    $vnetRg `
              -Category         "Topology" `
              -Severity         "High" `
              -FindingTitle     "Isolated VNet with active resources and no connectivity" `
              -Detail           "VNet '$vnetName' has $($subnets.Count) subnet(s) and active IP configurations but no VNet peering and no Azure Firewall present in the subscription. It exists as an island with no integration into the broader network architecture." `
              -BusinessImpact   "Resources in this VNet cannot communicate with other workloads, on-premises systems, or shared services. This may indicate a forgotten or unmanaged workload, or a workload that was intended to be connected but is not, creating operational and support gaps." `
              -Recommendation   "Determine whether this VNet is intentionally isolated (air-gapped). If not, connect it to the hub VNet via peering or ExpressRoute, and validate that DNS resolution and routing are correctly configured. If the VNet is retired, evaluate decommissioning."
            $allFindings += $f
            $subFindingCount++
          }
        }

        # ── T2: Hub candidate with asymmetric peering ─────────────────
        if ($vnetRole -eq "Hub" -and $peerCount -gt 0) {
          $disconnectedPeers = @($peers | Where-Object {
              $_.PeeringState -ne "Connected"
            })

          if ($disconnectedPeers.Count -gt 0) {
            $f = New-Finding `
              -SubscriptionName $sub.Name `
              -SubscriptionId   $sub.Id `
              -ResourceName     $vnetName `
              -ResourceType     "VirtualNetwork" `
              -ResourceGroup    $vnetRg `
              -Category         "Topology" `
              -Severity         "High" `
              -FindingTitle     "Hub VNet has $($disconnectedPeers.Count) disconnected peering(s)" `
              -Detail           "VNet '$vnetName' is identified as a hub candidate ($peerCount total peers) but $($disconnectedPeers.Count) peer(s) are in a non-Connected state: $($disconnectedPeers.Name -join ', '). Disconnected peerings indicate one-sided configuration or a deleted remote VNet." `
              -BusinessImpact   "Spokes with disconnected peerings lose access to shared services, internet egress controls, and hybrid connectivity routed through the hub. This creates uncontrolled traffic paths and monitoring blindspots." `
              -Recommendation   "Investigate each disconnected peering. Confirm the remote VNet still exists and that the remote-side peering is configured and in Connected state. Remove stale peerings referencing deleted VNets."
            $allFindings += $f
            $subFindingCount++
          }
        }

        # ── S1: Subnets without NSG ────────────────────────────────────
        # Skip gateway subnets and Azure Bastion subnets — these legitimately have no NSG
        $unprotectedSubnets = @($subnets | Where-Object {
            $sn = $_
            $snName = $sn.Name
            $isExempt = ($snName -in @("GatewaySubnet", "AzureFirewallSubnet", "AzureFirewallManagementSubnet",
                "AzureBastionSubnet", "RouteServerSubnet"))
            $hasNsg = ($null -ne $sn.NetworkSecurityGroup)
            (-not $isExempt) -and (-not $hasNsg)
          })

        if ($unprotectedSubnets.Count -gt 0) {
          $severity = if ($unprotectedSubnets.Count -ge 3) { "High" } else { "Medium" }
          $f = New-Finding `
            -SubscriptionName $sub.Name `
            -SubscriptionId   $sub.Id `
            -ResourceName     $vnetName `
            -ResourceType     "VirtualNetwork/Subnet" `
            -ResourceGroup    $vnetRg `
            -Category         "Segmentation" `
            -Severity         $severity `
            -FindingTitle     "$($unprotectedSubnets.Count) subnet(s) in '$vnetName' have no NSG" `
            -Detail           "The following subnets have no Network Security Group attached: $($unprotectedSubnets.Name -join ', '). Without an NSG, traffic between subnets and from the internet is unrestricted at the subnet boundary. VNet default allow-rules permit internal traffic freely." `
            -BusinessImpact   "A compromised resource in an unprotected subnet can move laterally to any other subnet in the VNet without hitting a network-layer control. This significantly increases blast radius in the event of a compromise." `
            -Recommendation   "Attach a Network Security Group to every non-exempt subnet. Apply least-privilege inbound rules limiting traffic to only required ports and source ranges. Use ASGs (Application Security Groups) to reduce rule management overhead across subnets."
          $allFindings += $f
          $subFindingCount++
        }

        # ── S2: Subnets without route table (no traffic control) ───────
        # Only flag where VNet has more than 2 subnets — single-subnet VNets may be intentional
        $unroutedSubnets = @($subnets | Where-Object {
            $sn = $_
            $snName = $sn.Name
            $isExempt = ($snName -in @("GatewaySubnet", "AzureFirewallSubnet", "AzureFirewallManagementSubnet",
                "AzureBastionSubnet", "RouteServerSubnet"))
            $hasRt = ($null -ne $sn.RouteTable)
            (-not $isExempt) -and (-not $hasRt)
          })

        if ($subnets.Count -gt 2 -and $unroutedSubnets.Count -gt 0 -and $firewalls.Count -eq 0) {
          $f = New-Finding `
            -SubscriptionName $sub.Name `
            -SubscriptionId   $sub.Id `
            -ResourceName     $vnetName `
            -ResourceType     "VirtualNetwork/Subnet" `
            -ResourceGroup    $vnetRg `
            -Category         "Routing" `
            -Severity         "Medium" `
            -FindingTitle     "$($unroutedSubnets.Count) subnet(s) in '$vnetName' have no route table" `
            -Detail           "In VNet '$vnetName', $($unroutedSubnets.Count) subnet(s) have no User-Defined Route table and no Azure Firewall is present to intercept egress: $($unroutedSubnets.Name -join ', '). Traffic from these subnets relies entirely on Azure system routes, which allow direct internet egress." `
            -BusinessImpact   "Without a UDR forcing traffic through a central security control, egress traffic from these subnets bypasses inspection. Data exfiltration, command-and-control communications, or unauthorized outbound connections may go undetected." `
            -Recommendation   "Attach a route table to each subnet with a default route (0.0.0.0/0) pointing to the Azure Firewall or NVA in the hub. Validate that the Firewall policy permits only necessary outbound destinations."
          $allFindings += $f
          $subFindingCount++
        }

        # ── R1: Default route to Internet (no centralized egress) ──────
        $vnetHasFirewall = ($firewalls.Count -gt 0)

        if (-not $vnetHasFirewall) {
          foreach ($rt in $routeTables) {
            $defaultToInternet = @($rt.Routes | Where-Object {
                $_.AddressPrefix -eq "0.0.0.0/0" -and
                $_.NextHopType -eq "Internet"
              })

            if ($defaultToInternet.Count -gt 0) {
              $f = New-Finding `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -ResourceName     $rt.Name `
                -ResourceType     "RouteTable" `
                -ResourceGroup    $rt.ResourceGroupName `
                -Category         "Routing" `
                -Severity         "High" `
                -FindingTitle     "Route table '$($rt.Name)' routes 0.0.0.0/0 directly to Internet" `
                -Detail           "Route table '$($rt.Name)' contains a default route pointing directly to the Internet next-hop. No Azure Firewall is present in the subscription. Traffic from subnets using this route table exits directly to the internet without centralized inspection or filtering." `
                -BusinessImpact   "All outbound traffic from associated subnets bypasses any centralized security control. Malware callbacks, data exfiltration, and unauthorized outbound connections are invisible to security teams. This is a common pattern in less-mature Azure environments that creates significant security blind spots." `
                -Recommendation   "Deploy an Azure Firewall (or NVA equivalent) in a dedicated hub VNet. Update the default route to next-hop the firewall's private IP. Define an explicit Application or Network rule policy to allow only required outbound destinations."
              $allFindings += $f
              $subFindingCount++
              break  # One finding per VNet context, not per route table
            }
          }
        }

        # ── E1: Large address space with few subnets (poor segmentation) ─
        $addressPrefixes = $vnet.AddressSpace.AddressPrefixes
        $largeSpaces = @($addressPrefixes | Where-Object {
            try {
              $prefix = $_ -split "/"
              [int]$mask = $prefix[1]
              $mask -le 16   # /16 or larger = 65K+ hosts
            }
            catch { $false }
          })

        if ($largeSpaces.Count -gt 0 -and $subnets.Count -le 2) {
          $f = New-Finding `
            -SubscriptionName $sub.Name `
            -SubscriptionId   $sub.Id `
            -ResourceName     $vnetName `
            -ResourceType     "VirtualNetwork" `
            -ResourceGroup    $vnetRg `
            -Category         "Segmentation" `
            -Severity         "Low" `
            -FindingTitle     "Large address space in '$vnetName' with minimal subnet segmentation" `
            -Detail           "VNet '$vnetName' uses address space(s) with /16 or larger prefix ($($largeSpaces -join ', ')) but has only $($subnets.Count) subnet(s). A flat VNet with a large address space limits the ability to apply differentiated NSG policies per tier or workload." `
            -BusinessImpact   "Without subnet segmentation, workloads of different trust levels (web, app, data) share the same network boundary. This prevents enforcement of tier-level access controls and complicates future workload isolation." `
            -Recommendation   "Redesign the subnet structure to align with workload tiers (e.g., presentation, application, data, management). Apply separate NSGs to each subnet with rules appropriate for that tier's trust level. Plan address space allocations that support expected growth without over-provisioning."
          $allFindings += $f
          $subFindingCount++
        }

        # ── P1: VNet without DDoS protection and public-facing resources ─
        if (-not $ddosEnabled) {
          # Check if any subnet has public IPs attached
          $subnetIds = @($subnets | ForEach-Object { $_.Id })
          $publicIpsInVnet = @($publicIps | Where-Object {
              $pip = $_
              $isAttached = $pip.IpConfiguration -and $pip.IpConfiguration.Id
              $isInVnet = $false
              if ($isAttached) {
                foreach ($sid in $subnetIds) {
                  if ($pip.IpConfiguration.Id -like "$sid*") { $isInVnet = $true; break }
                }
              }
              $isAttached -and $isInVnet
            })

          if ($publicIpsInVnet.Count -gt 0) {
            $f = New-Finding `
              -SubscriptionName $sub.Name `
              -SubscriptionId   $sub.Id `
              -ResourceName     $vnetName `
              -ResourceType     "VirtualNetwork" `
              -ResourceGroup    $vnetRg `
              -Category         "Security" `
              -Severity         "Medium" `
              -FindingTitle     "'$vnetName' has public-facing resources but no DDoS Protection Standard" `
              -Detail           "VNet '$vnetName' has $($publicIpsInVnet.Count) public IP(s) attached to resources within it but DDoS Protection Standard is not enabled. Only DDoS Basic (infrastructure-level) protection is active, which does not provide per-resource adaptive tuning, attack telemetry, or SLA guarantees." `
              -BusinessImpact   "Internet-facing services without DDoS Standard protection are vulnerable to volumetric and protocol-level attacks that can exhaust resources and cause service unavailability. This is particularly significant for customer-facing or revenue-generating workloads." `
              -Recommendation   "Enable Azure DDoS Protection Standard on VNets that contain internet-facing resources. Prioritize VNets hosting public-facing Application Gateways, Load Balancers, or API Management. Use DDoS diagnostic logs to establish baselines and configure rapid response alerting."
            $allFindings += $f
            $subFindingCount++
          }
        }

      }  # end foreach vnet

      # ── Subscription-level findings ───────────────────────────────────

      # ── C1: No Azure Firewall in subscription ─────────────────────────
      if ($firewalls.Count -eq 0 -and $vnets.Count -gt 0) {
        $vnetWithMultipleSubnets = @($vnets | Where-Object { $_.Subnets.Count -gt 1 })
        if ($vnetWithMultipleSubnets.Count -gt 0) {
          $f = New-Finding `
            -SubscriptionName $sub.Name `
            -SubscriptionId   $sub.Id `
            -ResourceName     $sub.Name `
            -ResourceType     "Subscription" `
            -ResourceGroup    "" `
            -Category         "Security" `
            -Severity         "High" `
            -FindingTitle     "No Azure Firewall present — centralized egress inspection absent" `
            -Detail           "Subscription '$($sub.Name)' has $($vnets.Count) VNet(s) with no Azure Firewall deployed. Without a centralized firewall, outbound traffic inspection, threat intelligence-based filtering, and application-level egress control are not available. NSGs alone provide port-level filtering but not application-aware inspection." `
            -BusinessImpact   "Without centralized egress inspection, security teams cannot enforce outbound allow-lists, detect command-and-control traffic, or log all outbound connections for forensic purposes. This is a common gap that adversaries exploit for long-term persistence." `
            -Recommendation   "Deploy Azure Firewall (Standard or Premium tier based on TLS inspection requirements) in a dedicated hub VNet. Use Firewall Policy to define application rules for allowed outbound FQDNs and network rules for required IP destinations. Route all spoke subnet default routes through the firewall."
          $allFindings += $f
          $subFindingCount++
        }
      }

      # ── C2: NSG with overly broad inbound rules ────────────────────────
      foreach ($nsg in $nsgs) {
        $broadRules = @($nsg.SecurityRules | Where-Object {
            $r = $_
            $r.Direction -eq "Inbound" -and
            $r.Access -eq "Allow" -and
            ($r.SourceAddressPrefix -in @("*", "Internet", "0.0.0.0/0", "Any")) -and
            ($r.DestinationPortRange -in @("*", "Any") -or
            ($r.DestinationPortRange -is [string] -and
            $r.DestinationPortRange -match "^\d+$" -and
            [int]$r.DestinationPortRange -le 1024 -and
            [int]$r.DestinationPortRange -gt 0 -and
            $r.DestinationPortRange -ne "443"))
          })

        if ($broadRules.Count -gt 0) {
          $ruleDesc = ($broadRules | ForEach-Object { "$($_.Name) (port $($_.DestinationPortRange))" }) -join "; "
          $f = New-Finding `
            -SubscriptionName $sub.Name `
            -SubscriptionId   $sub.Id `
            -ResourceName     $nsg.Name `
            -ResourceType     "NetworkSecurityGroup" `
            -ResourceGroup    $nsg.ResourceGroupName `
            -Category         "Exposure" `
            -Severity         "High" `
            -FindingTitle     "NSG '$($nsg.Name)' has broad inbound allow rules from Internet" `
            -Detail           "NSG '$($nsg.Name)' has $($broadRules.Count) inbound Allow rule(s) permitting traffic from any internet source (*, Internet, or 0.0.0.0/0) to sensitive port ranges: $ruleDesc. These rules expose resources to direct internet scanning and attack." `
            -BusinessImpact   "Resources protected by this NSG are reachable from any internet IP on the permitted ports. This directly increases the attack surface for brute-force, exploitation, and reconnaissance. Port 22 (SSH), 3389 (RDP), and management ports exposed to 'Any' source are consistently targeted by automated scanning tools." `
            -Recommendation   "Replace 'Any' source rules with explicit source IP ranges or prefixes corresponding to authorized management jump hosts, corporate IP ranges, or Azure Bastion. For RDP and SSH, enforce access exclusively through Azure Bastion or a VPN gateway rather than direct internet exposure."
          $allFindings += $f
          $subFindingCount++
        }
      }

      # ── R2: Private Endpoint DNS resolution gap ────────────────────────
      if ($privateEndpts.Count -gt 0) {
        # Check for Private DNS Zones in the subscription
        $privateDnsZones = @()
        try { $privateDnsZones = @(Get-AzPrivateDnsZone -ErrorAction Stop) }
        catch { Write-Verbose "Private DNS Zone retrieval failed for $($sub.Name): $_" }

        if ($privateDnsZones.Count -eq 0 -and $privateEndpts.Count -gt 0) {
          $f = New-Finding `
            -SubscriptionName $sub.Name `
            -SubscriptionId   $sub.Id `
            -ResourceName     $sub.Name `
            -ResourceType     "Subscription" `
            -ResourceGroup    "" `
            -Category         "PrivateConn" `
            -Severity         "High" `
            -FindingTitle     "$($privateEndpts.Count) Private Endpoint(s) present but no Private DNS Zones found" `
            -Detail           "Subscription '$($sub.Name)' has $($privateEndpts.Count) Private Endpoint(s) configured but no Azure Private DNS Zones are present. Without Private DNS Zone integration, DNS queries for private endpoint FQDNs resolve to public IPs, causing connections to bypass the private endpoint entirely and route over the internet." `
            -BusinessImpact   "Resources intended to communicate over private endpoints will silently fall back to public internet routes if DNS is not correctly configured. This defeats the purpose of private connectivity and may cause data to traverse public networks unexpectedly, violating data residency or compliance requirements." `
            -Recommendation   "Create Private DNS Zones for each private endpoint service type (e.g., privatelink.blob.core.windows.net, privatelink.vaultcore.azure.net). Link each zone to the VNets that require private resolution. Validate resolution from within the VNet using nslookup or Test-NetConnection."
          $allFindings += $f
          $subFindingCount++
        }
      }

      # ── Re2: Application Gateway without WAF ──────────────────────────
      foreach ($agw in $appGateways) {
        $wafEnabled = $false
        try { $wafEnabled = ($agw.Sku.Tier -in @("WAF", "WAF_v2")) }
        catch { }

        if (-not $wafEnabled) {
          $f = New-Finding `
            -SubscriptionName $sub.Name `
            -SubscriptionId   $sub.Id `
            -ResourceName     $agw.Name `
            -ResourceType     "ApplicationGateway" `
            -ResourceGroup    $agw.ResourceGroupName `
            -Category         "Exposure" `
            -Severity         "High" `
            -FindingTitle     "Application Gateway '$($agw.Name)' is not WAF-enabled" `
            -Detail           "Application Gateway '$($agw.Name)' is deployed using the Standard or Standard_v2 SKU without Web Application Firewall capability. Internet-facing HTTP/HTTPS traffic is load-balanced without OWASP rule-based protection against injection, XSS, and other application-layer attacks." `
            -BusinessImpact   "Web applications fronted by a non-WAF Application Gateway are vulnerable to OWASP Top 10 attacks without application-layer detection or blocking. Customer data, application integrity, and regulatory compliance (PCI DSS, GDPR) may be affected by exploits that a WAF would have blocked." `
            -Recommendation   "Migrate to the WAF_v2 SKU and enable a WAF Policy in Prevention mode with the OWASP 3.2 ruleset. Review and tune custom exclusions to reduce false positives. Enable WAF diagnostic logs and alert on high-severity rule triggers."
          $allFindings += $f
          $subFindingCount++
        }
      }

      # ── Res1: VPN/ER gateways without redundancy check ────────────────
      try {
        $gateways = @(Get-AzVirtualNetworkGateway -ErrorAction Stop)
        foreach ($gw in $gateways) {
          $isActiveActive = $false
          try { $isActiveActive = ($gw.ActiveActive -eq $true) }
          catch { }

          if (-not $isActiveActive) {
            $gwType = if ($gw.GatewayType) { $gw.GatewayType } else { "VPN/ER" }
            $f = New-Finding `
              -SubscriptionName $sub.Name `
              -SubscriptionId   $sub.Id `
              -ResourceName     $gw.Name `
              -ResourceType     "VirtualNetworkGateway" `
              -ResourceGroup    $gw.ResourceGroupName `
              -Category         "Resilience" `
              -Severity         "Medium" `
              -FindingTitle     "Gateway '$($gw.Name)' is not in active-active mode" `
              -Detail           "Virtual Network Gateway '$($gw.Name)' (type: $gwType) is configured in active-standby mode. In this configuration, a gateway instance failure triggers a failover that may cause hybrid connectivity interruption for several minutes, with BGP reconvergence adding additional recovery time." `
              -BusinessImpact   "Hybrid connectivity (on-premises to Azure or branch connectivity) has a single point of failure at the gateway level. Gateway failures during business hours can affect all workloads depending on this connectivity path, including any applications integrated with on-premises systems or services." `
              -Recommendation   "Enable active-active mode on the VPN Gateway to maintain two active BGP sessions with on-premises devices. Pair with two on-premises VPN devices for full redundancy. For ExpressRoute, provision a second circuit from a different provider or peering location for geographic redundancy."
            $allFindings += $f
            $subFindingCount++
          }
        }
      }
      catch { Write-Verbose "Gateway retrieval failed for $($sub.Name): $_" }

      # ── Update distributions ───────────────────────────────────────────
      foreach ($f in ($allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id })) {
        if ($categoryDist.ContainsKey($f.Category)) { $categoryDist[$f.Category]++ }
        else { $categoryDist[$f.Category] = 1 }

        if ($severityDist.ContainsKey($f.Severity)) { $severityDist[$f.Severity]++ }
      }

      # ── Per-subscription result ────────────────────────────────────────
      Write-Host "`r$(' ' * 120)`r" -NoNewline
      $paddedName = $sub.Name.PadRight($maxNameLen)

      Write-Host "  " -NoNewline
      Write-Host "✓ " -NoNewline -ForegroundColor Green
      Write-Host $paddedName -NoNewline -ForegroundColor Green
      Write-Host " → " -NoNewline -ForegroundColor DarkGray
      Write-Host "VNets: $($vnets.Count)  NSGs: $($nsgs.Count)  Firewalls: $($firewalls.Count)  Findings: $subFindingCount" -ForegroundColor White

      $subscriptionResults += @{
        Name    = $sub.Name
        Summary = "VNets: $($vnets.Count)  NSGs: $($nsgs.Count)  Firewalls: $($firewalls.Count)  Findings: $subFindingCount"
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
      "Total VNets Assessed"        = $allVnetSummary.Count
      "Total Findings"              = $allFindings.Count
      "Critical"                    = $severityDist["Critical"]
      "High"                        = $severityDist["High"]
      "Medium"                      = $severityDist["Medium"]
      "Low"                         = $severityDist["Low"]
      "Execution Time"              = $duration
    })

  Write-FindingSummary -Findings $allFindings

  # ── Output files ──────────────────────────────────────────────────────────
  $csvExported = $false
  $htmlExported = $false
  $gridViewOpened = $false
  $htmlPath = ""

  if ($allFindings.Count -gt 0 -or $allVnetSummary.Count -gt 0) {
    # CSV
    if ($ExportToCsv) {
      try {
        $csvDir = Split-Path -Parent $CsvPath
        if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

        $allFindings | Select-Object `
          SubscriptionName, SubscriptionId, ResourceName, ResourceType, ResourceGroup,
        Category, Severity, FindingTitle, Detail, BusinessImpact, Recommendation |
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

      $htmlContent = Generate-NetworkArchitectureHtml `
        -SessionInfo          $sessionInfo `
        -ScanParameters       $scanParams `
        -Findings             $allFindings `
        -VNetSummary          $allVnetSummary `
        -CategoryDist         $categoryDist `
        -SeverityDist         $severityDist `
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
      Select-Object Severity, Category, FindingTitle, ResourceName, SubscriptionName |
      Out-GridView -Title "Azure Network Architecture Assessment"
      $gridViewOpened = $true
    }
    catch {
      Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
    }
  }
  else {
    Write-Host ""
    Write-Host "  ⚠ No network data found in the targeted subscriptions." -ForegroundColor Yellow
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
