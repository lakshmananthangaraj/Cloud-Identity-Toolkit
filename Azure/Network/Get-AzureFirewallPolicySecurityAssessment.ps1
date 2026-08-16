<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 16 August 2026
Modified-On     : 16 August 2026

.SYNOPSIS
    Assesses Azure Firewall policies for overly broad rules, risky destinations,
    rule priority conflicts, and architectural gaps — across one or more subscriptions —
    with optional CSV export and an interactive HTML dashboard.

.DESCRIPTION
    Get-AzureFirewallPolicySecurityAssessment evaluates the security posture of
    Azure Firewall Policies and Classic Firewall rule collections from a Cloud
    Architect perspective. Rather than simply enumerating rules, the script analyses
    them for real-world risk patterns:

    Rule Collection Group & Priority Analysis
        - Detects missing or duplicate rule priorities that could produce unintended
          traffic flow (lower-priority allow rules accidentally shadowing denies)
        - Flags Rule Collection Groups with no explicit DenyAll terminating rule,
          indicating a default-permit posture
        - Identifies missing IDPS policy linkage (Premium SKU only)
        - Detects whether Threat Intelligence mode is Alert-only vs Alert+Deny

    Network Rule Risks
        - Any-to-Any rules (* source to * destination) — full bypass of segmentation
        - Rules allowing unrestricted management ports (RDP 3389, SSH 22, WinRM 5985/5986)
          from Internet or wildcard sources
        - Rules with overly broad destination IP ranges (e.g. /8 or wider CIDRs)
        - Rules with protocol=Any on non-trivial port ranges
        - RFC 1918 ↔ Internet rules that indicate routing anomalies

    Application Rule Risks
        - Wildcard FQDN rules (*.* or *) that bypass domain-level filtering
        - HTTP (non-TLS) targets in application rules where TLS inspection is expected
        - Rules targeting known risky TLDs or uncategorised destinations
        - Absence of TLS inspection on application rule collections

    NAT Rule Risks
        - DNAT rules exposing management ports (RDP, SSH, WinRM) directly to the Internet
        - DNAT rules with wildcard source addresses
        - Multiple DNAT rules pointing to the same internal destination (duplication risk)

    Architecture Gaps
        - Firewall Policies with no Rule Collection Groups defined (empty policy)
        - Classic Firewalls (non-policy-based) flagged for migration to Policy model
        - Policies not linked to any Firewall or Firewall Hub (orphaned policy)
        - Azure Firewall deployed without Diagnostic Settings (no logging)
        - Firewalls not in a Hub-Spoke topology (deployed directly in workload VNet)

    For each finding the script records:
        - What (control/check being assessed)
        - Why (architectural or security reason it matters)
        - Current State (observed configuration)
        - Risk (what an attacker or misconfiguration could exploit)
        - Severity (Critical / High / Medium / Low / Info)
        - Recommendation (specific, actionable remediation step)
        - Resource (Firewall Policy or Firewall resource path)

    The script supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of all findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          severity distribution, risk-category breakdown, detail drawer)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzureFirewallPolicyAssessment-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureFirewallPolicySecurityAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureFirewallPolicySecurityAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureFirewallPolicySecurityAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\FWPolicy.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (16-Aug-2026) - Initial release. Firewall Policy and Classic Firewall
                            assessment covering network rules, application rules,
                            NAT rules, priority conflicts, and architecture gaps.
                            CSV export and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Network, Az.Monitor)
           — installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level.
        4. Microsoft.Network/azureFirewalls/read and
           Microsoft.Network/firewallPolicies/read at subscription scope.
        5. Microsoft.Insights/diagnosticSettings/read for the diagnostic
           settings check — skipped gracefully if not available.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Classic Firewall rule collection analysis uses the ARM representation
          of rules. Some very large classic rule sets (>500 rules per collection)
          may be slow to enumerate.
        - FQDN tag analysis (e.g. WindowsUpdate, AzureKubernetesService) is
          not included — FQDN-tagged application rules are reported as informational.
        - TLS inspection status is detected via policy TlsCertificate property;
          individual rule collection-level TLS inspection override detection
          requires Premium SKU policy and may not be visible in all API versions.
        - Orphaned policy detection compares policy ResourceId against all
          Firewalls' FirewallPolicy.Id within the same subscription only —
          cross-subscription Hub policy assignments may appear orphaned.
        - Interactive Grid View requires a GUI-capable session. Skipped gracefully
          in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/firewall/policy-rule-sets
    https://learn.microsoft.com/en-us/azure/firewall/premium-features
    https://learn.microsoft.com/en-us/azure/firewall/threat-intel-mode
    https://learn.microsoft.com/en-us/azure/firewall/rule-processing
    https://learn.microsoft.com/en-us/azure/firewall/migrate-to-policy

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
    Write-CenteredText "Azure Firewall Policy Security Assessment v1.0" -Color White
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

Function Write-SeverityBreakdown {
    param([hashtable]$Severity)

    if ($Severity.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Severity Breakdown" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $colorMap = @{
        "Critical" = "Red"
        "High"     = "Red"
        "Medium"   = "Yellow"
        "Low"      = "Green"
        "Info"     = "DarkGray"
    }

    foreach ($sev in @("Critical", "High", "Medium", "Low", "Info")) {
        if ($Severity.ContainsKey($sev)) {
            $color = if ($colorMap.ContainsKey($sev)) { $colorMap[$sev] } else { "White" }
            Write-Host "  " -NoNewline
            Write-Host $sev.PadRight(22) -NoNewline -ForegroundColor $color
            Write-Host ": " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($Severity[$sev]) finding(s)" -ForegroundColor $color
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

# ── Risk helper — detects overly-broad CIDR (prefix length ≤ 8 for IPv4) ────
Function Test-BroadCidr {
    param([string]$Address)
    if ($Address -match '^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$') {
        $prefix = [int]($Matches[2])
        return $prefix -le 8
    }
    return $false
}

# ── Risk helper — detects management port exposure ───────────────────────────
Function Test-ManagementPort {
    param([string[]]$Ports)
    $mgmtPorts = @("3389", "22", "5985", "5986", "23", "21", "161", "445")
    foreach ($p in $Ports) {
        foreach ($m in $mgmtPorts) {
            if ($p -eq $m -or $p -eq "*") { return $true }
            # Range check e.g. "3000-4000"
            if ($p -match '^(\d+)-(\d+)$') {
                $low = [int]$Matches[1]
                $high = [int]$Matches[2]
                if ([int]$m -ge $low -and [int]$m -le $high) { return $true }
            }
        }
    }
    return $false
}


#------------------------------------------------------------------------ [ Finding Builder ]

Function New-FwFinding {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$ResourceName,
        [string]$ResourceId,
        [string]$ResourceType,     # FirewallPolicy | Firewall | RuleCollection
        [string]$Category,         # Network Rule | Application Rule | NAT Rule | Architecture | Priority | Threat Intel
        [string]$CheckName,
        [string]$Why,
        [string]$CurrentState,
        [string]$Risk,
        [string]$Severity,         # Critical | High | Medium | Low | Info
        [string]$Recommendation
    )
    return [pscustomobject]@{
        SubscriptionName = $SubscriptionName
        SubscriptionId   = $SubscriptionId
        ResourceName     = $ResourceName
        ResourceId       = $ResourceId
        ResourceType     = $ResourceType
        Category         = $Category
        CheckName        = $CheckName
        Why              = $Why
        CurrentState     = $CurrentState
        Risk             = $Risk
        Severity         = $Severity
        Recommendation   = $Recommendation
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-FirewallPolicyHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [hashtable]$SeverityDistribution,
        [hashtable]$CategoryDistribution,
        [array]$SubscriptionResults,
        [string]$GeneratedOn
    )

    $totalFindings = @($Findings).Count
    $criticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount = @($Findings | Where-Object { $_.Severity -eq "Info" }).Count

    # ── Finding table rows ────────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $sevCls = switch ($f.Severity) {
            "Critical" { "badge-critical" }
            "High" { "badge-red" }
            "Medium" { "badge-amber" }
            "Low" { "badge-green" }
            default { "badge-blue" }
        }
        $catCls = "badge-blue"
        $nameDisplay = if ($f.CheckName.Length -gt 40) { (EscHtml $f.CheckName.Substring(0, 37)) + "..." } else { EscHtml $f.CheckName }
        $findingRows += @"
          <tr onclick="showFindingDetail($($Findings.IndexOf($f)))">
            <td title="$(EscHtml $f.CheckName)">$nameDisplay</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$(EscHtml $f.ResourceName)</td>
            <td><span class="badge $catCls">$(EscHtml $f.Category)</span></td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
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

    # ── Severity distribution bars ────────────────────────────────────────────
    $sevTotal = ($SeverityDistribution.Values | Measure-Object -Sum).Sum
    $sevRows = ""
    $sevColors = @{
        "Critical" = "var(--critical)"
        "High"     = "var(--red)"
        "Medium"   = "var(--amber)"
        "Low"      = "var(--green)"
        "Info"     = "var(--muted)"
    }
    foreach ($sev in @("Critical", "High", "Medium", "Low", "Info")) {
        if ($SeverityDistribution.ContainsKey($sev)) {
            $val = $SeverityDistribution[$sev]
            $pct = if ($sevTotal -gt 0) { [math]::Round(($val / $sevTotal) * 100) } else { 0 }
            $color = if ($sevColors.ContainsKey($sev)) { $sevColors[$sev] } else { "var(--accent)" }
            $sevRows += @"
          <div class="bar-row">
            <span class="bar-label">$sev</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$color"></div></div>
            <span class="bar-pct">$val ($pct%)</span>
          </div>
"@
        }
    }

    # ── Category distribution bars ────────────────────────────────────────────
    $catTotal = ($CategoryDistribution.Values | Measure-Object -Sum).Sum
    $catRows = ""
    $catColors = @{
        "Network Rule"     = "var(--accent)"
        "Application Rule" = "var(--accent2)"
        "NAT Rule"         = "var(--accent3)"
        "Architecture"     = "var(--amber)"
        "Priority"         = "var(--red)"
        "Threat Intel"     = "var(--critical)"
    }
    foreach ($cat in ($CategoryDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($catTotal -gt 0) { [math]::Round(($cat.Value / $catTotal) * 100) } else { 0 }
        $color = if ($catColors.ContainsKey($cat.Key)) { $catColors[$cat.Key] } else { "var(--accent)" }
        $catRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $cat.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$color"></div></div>
            <span class="bar-pct">$($cat.Value) ($pct%)</span>
          </div>
"@
    }

    # ── JSON for detail drawer ────────────────────────────────────────────────
    $findJson = "["
    foreach ($f in $Findings) {
        $findJson += "{" +
        """check"":""$(EscJ $f.CheckName)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """res"":""$(EscJ $f.ResourceName)""," +
        """resId"":""$(EscJ $f.ResourceId)""," +
        """resType"":""$(EscJ $f.ResourceType)""," +
        """cat"":""$(EscJ $f.Category)""," +
        """sev"":""$(EscJ $f.Severity)""," +
        """why"":""$(EscJ $f.Why)""," +
        """state"":""$(EscJ $f.CurrentState)""," +
        """risk"":""$(EscJ $f.Risk)""," +
        """rec"":""$(EscJ $f.Recommendation)""" +
        "},"
    }
    $findJson = $findJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Firewall Policy Security Assessment</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;
  --border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;
  --green:#3fb950;--amber:#d29922;--red:#f85149;--critical:#ff6b35;
  --text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);
}
html[data-theme="light"]{
  --bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;
  --border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;
  --green:#1a7f37;--amber:#b08000;--red:#cf222e;--critical:#c0392b;
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
  background:linear-gradient(135deg,var(--red),var(--critical));
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px;}
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
.stat-card.c-critical{border-top-color:var(--critical);}
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
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:80px;text-align:right;flex-shrink:0;}
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
.badge-critical{background:rgba(255,107,53,.18);color:var(--critical);border:1px solid rgba(255,107,53,.35);}
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
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
.drawer-field-value{font-size:13px;word-break:break-word;line-height:1.5;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
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
    <div class="logo-icon">🔥</div>
    <div class="logo-title">Firewall Policy Assessment</div>
    <div class="logo-sub">Network Security Architecture</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> All Findings</button>
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
      Azure Firewall Policy Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Firewall Policy Security Assessment</div>
      <div class="page-sub">Rule, architecture, and threat-intel risk findings across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_FINDINGS__</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card c-critical">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">Immediate action</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__INFO_COUNT__</div>
        <div class="stat-label">Info</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">⚠️ Severity Distribution</div>
        __SEV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">📂 Findings by Rule Category</div>
        __CAT_ROWS__
      </div>
    </div>
  </div>

  <!-- All Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">All Findings</div>
      <div class="page-sub">Click any row for detailed context — why it matters, current state, risk, and recommendation</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search check, resource, subscription…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterCat" onchange="filterFindings()">
          <option value="">All Categories</option>
          <option value="Network Rule">Network Rule</option>
          <option value="Application Rule">Application Rule</option>
          <option value="NAT Rule">NAT Rule</option>
          <option value="Architecture">Architecture</option>
          <option value="Priority">Priority</option>
          <option value="Threat Intel">Threat Intel</option>
        </select>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
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
              <th onclick="sortFindings(0)">Check</th>
              <th onclick="sortFindings(1)">Subscription</th>
              <th onclick="sortFindings(2)">Resource</th>
              <th onclick="sortFindings(3)">Category</th>
              <th onclick="sortFindings(4)">Severity</th>
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
      <div class="page-sub">Per-subscription firewall policy assessment outcome</div>
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
const FIND_DATA = __FIND_JSON__;
let findFiltered = [...FIND_DATA];
let findPage = 1, findPageSz = 25;
let findSortCol = -1, findSortAsc = true;
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

// ── Findings table ─────────────────────────────────────────────────────────
function filterFindings(){
  const q  = document.getElementById('findSearch').value.toLowerCase();
  const c  = document.getElementById('filterCat').value;
  const sv = document.getElementById('filterSev').value;
  findFiltered = FIND_DATA.filter(r=>{
    const mQ = !q  || JSON.stringify(r).toLowerCase().includes(q);
    const mC = !c  || r.cat === c;
    const mS = !sv || r.sev === sv;
    return mQ && mC && mS;
  });
  findPage = 1; renderFindings();
}

function changeFindPageSize(){
  findPageSz = parseInt(document.getElementById('pgSizeFind').value);
  findPage   = 1; renderFindings();
}

function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys = ['check','sub','res','cat','sev'];
  findFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    return findSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                      :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderFindings();
}

function renderFindings(){
  const tbody = document.getElementById('findBody');
  const start = (findPage-1)*findPageSz;
  const slice = findFiltered.slice(start, start+findPageSz);
  tbody.innerHTML = slice.map(r=>{
    const gi = FIND_DATA.indexOf(r);
    const sevCls = r.sev==='Critical'?'badge-critical':r.sev==='High'?'badge-red':r.sev==='Medium'?'badge-amber':r.sev==='Low'?'badge-green':'badge-blue';
    const nm = r.check.length>40?r.check.substring(0,37)+'...':r.check;
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.check)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td>${escH(r.res)}</td>
      <td><span class="badge badge-blue">${escH(r.cat)}</span></td>
      <td><span class="badge ${sevCls}">${escH(r.sev)}</span></td>
    </tr>`;
  }).join('');
  renderFindPg();
}

function renderFindPg(){
  const total = Math.ceil(findFiltered.length/findPageSz);
  const el    = document.getElementById('findPagination');
  let h = `<span>${findFiltered.length} finding(s)</span>`;
  h += `<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,findPage-2), e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h += `<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML = h;
}

function changeFindPage(p){
  const total=Math.ceil(findFiltered.length/findPageSz);
  if(p<1||p>total)return;
  findPage=p; renderFindings();
}

// ── Finding detail drawer ──────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx = idx;
  const r = FIND_DATA[idx];
  if(!r) return;
  document.getElementById('drawerTitle').textContent = r.check;
  document.getElementById('drawerNavInfo').textContent = `${idx+1} of ${FIND_DATA.length}`;
  const sevCls = r.sev==='Critical'?'badge-critical':r.sev==='High'?'badge-red':r.sev==='Medium'?'badge-amber':r.sev==='Low'?'badge-green':'badge-blue';
  document.getElementById('drawerContent').innerHTML = `
    <div class="drawer-field"><div class="drawer-field-label">Category</div>
      <div class="drawer-field-value"><span class="badge badge-blue">${escH(r.cat)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sevCls}">${escH(r.sev)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource</div>
      <div class="drawer-field-value">${escH(r.res)} <span style="color:var(--muted);font-size:11px">(${escH(r.resType)})</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource ID</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.resId)}</div></div>
    <div class="drawer-section">Why This Matters</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.why)}</div></div>
    <div class="drawer-section">Current State</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.state)}</div></div>
    <div class="drawer-section">Risk</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.risk)}</div></div>
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

// ── Init ──────────────────────────────────────────────────────────────────
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
        -replace '__INFO_COUNT__', $infoCount `
        -replace '__SEV_ROWS__', $sevRows `
        -replace '__CAT_ROWS__', $catRows `
        -replace '__FINDING_ROWS__', $findingRows `
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

Function Get-AzureFirewallPolicySecurityAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureFirewallPolicyAssessment-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Network", "Az.Monitor")
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
        $scopeText = "All Subscriptions"
    }
    else {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
            Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count))"
    }

    $subCount = $subscriptions.Count

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
    $subscriptionResults = @()
    $severityDist = @{ "Critical" = 0; "High" = 0; "Medium" = 0; "Low" = 0; "Info" = 0 }
    $categoryDist = @{}
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

            $subFindingCount = 0

            # ── Retrieve Firewall Policies ────────────────────────────────────
            $fwPolicies = @()
            try {
                $fwPolicies = @(Get-AzFirewallPolicy -ErrorAction Stop)
            }
            catch {
                Write-Verbose "  Could not retrieve Firewall Policies for $($sub.Name): $_"
            }

            # ── Retrieve Classic Firewalls ────────────────────────────────────
            $classicFws = @()
            try {
                $classicFws = @(Get-AzFirewall -ErrorAction Stop)
            }
            catch {
                Write-Verbose "  Could not retrieve Azure Firewalls for $($sub.Name): $_"
            }

            # ─────────────────────────────────────────────────────────────────
            # A R C H I T E C T U R E   C H E C K S
            # ─────────────────────────────────────────────────────────────────

            # Check 1 — Classic firewalls not using Policy model
            $classicRulesFws = @($classicFws | Where-Object { -not $_.FirewallPolicy })
            if ($classicRulesFws.Count -gt 0) {
                foreach ($cfw in $classicRulesFws) {
                    $allFindings += New-FwFinding `
                        -SubscriptionName $sub.Name `
                        -SubscriptionId   $sub.Id `
                        -ResourceName     $cfw.Name `
                        -ResourceId       $cfw.Id `
                        -ResourceType     "Firewall" `
                        -Category         "Architecture" `
                        -CheckName        "Classic Firewall — No Policy Attached" `
                        -Why              "Azure Firewall Policies provide centralised, version-controlled rule management with inheritance (parent/child), IDPS, URL filtering, and TLS inspection. Classic inline rule collections on the Firewall object are a legacy model that cannot be promoted to Premium features and cannot be shared across Firewalls." `
                        -CurrentState     "Firewall '$($cfw.Name)' uses classic inline rule collections rather than a Firewall Policy object. SKU: $($cfw.Sku.Name)." `
                        -Risk             "Classic rule collections cannot enforce IDPS, URL filtering, or TLS inspection. They cannot be centrally governed across a Hub-Spoke topology. Changes require full firewall re-deployment rather than policy update." `
                        -Severity         "Medium" `
                        -Recommendation   "Migrate to Azure Firewall Policy using the Azure Firewall Policy migration tooling. Associate the new policy with the existing Firewall. Plan for Premium SKU upgrade if IDPS and TLS inspection are required."
                    $subFindingCount++
                }
            }

            # Check 2 — Orphaned Firewall Policies (not linked to any Firewall)
            $linkedPolicyIds = @($classicFws | Where-Object { $_.FirewallPolicy } | ForEach-Object { $_.FirewallPolicy.Id.ToLower() })
            foreach ($policy in $fwPolicies) {
                $isLinked = $linkedPolicyIds -contains $policy.Id.ToLower()
                if (-not $isLinked) {
                    $allFindings += New-FwFinding `
                        -SubscriptionName $sub.Name `
                        -SubscriptionId   $sub.Id `
                        -ResourceName     $policy.Name `
                        -ResourceId       $policy.Id `
                        -ResourceType     "FirewallPolicy" `
                        -Category         "Architecture" `
                        -CheckName        "Orphaned Firewall Policy — Not Linked to Any Firewall" `
                        -Why              "A Firewall Policy not attached to any Firewall is not enforcing any rules. It represents dead configuration that incurs cost and risks being mistakenly edited as if it were active — creating confusion during incident response." `
                        -CurrentState     "Policy '$($policy.Name)' (SKU: $($policy.Sku.Tier)) is not referenced by any Azure Firewall in this subscription." `
                        -Risk             "Orphaned policies may contain stale or incorrect rules. If reattached without review, unintended traffic could be allowed or blocked. They also waste Azure Policy compute allocation costs." `
                        -Severity         "Low" `
                        -Recommendation   "Either link this policy to an Azure Firewall, use it as a parent (base) policy for child policies, or delete it if it is no longer required. Document the intended use of all Firewall Policies in your network architecture."
                    $subFindingCount++
                }
            }

            # Check 3 — Firewall without Diagnostic Settings
            foreach ($fw in $classicFws) {
                try {
                    $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $fw.Id -ErrorAction Stop)
                    $hasLogging = ($diagSettings | Where-Object {
                            ($_.Logs | Where-Object { $_.Enabled -eq $true }).Count -gt 0
                        }).Count -gt 0

                    if (-not $hasLogging) {
                        $allFindings += New-FwFinding `
                            -SubscriptionName $sub.Name `
                            -SubscriptionId   $sub.Id `
                            -ResourceName     $fw.Name `
                            -ResourceId       $fw.Id `
                            -ResourceType     "Firewall" `
                            -Category         "Architecture" `
                            -CheckName        "Firewall — No Diagnostic Settings (Logging Disabled)" `
                            -Why              "Azure Firewall logs are the authoritative source of truth for allowed and denied traffic flows. Without diagnostic settings exporting to Log Analytics or Storage, there is no audit trail for security investigations, compliance, or SIEM correlation. A firewall with no logs is operationally blind." `
                            -CurrentState     "Firewall '$($fw.Name)' has no diagnostic settings enabled. AzureFirewallNetworkRule, AzureFirewallApplicationRule, and AzureFirewallDnsProxy logs are not being captured." `
                            -Risk             "Without firewall logs: (1) security incidents cannot be investigated; (2) threat hunting is impossible; (3) compliance mandates (PCI-DSS, ISO 27001, NIST) requiring network log retention cannot be met; (4) Microsoft Sentinel cannot correlate firewall data." `
                            -Severity         "High" `
                            -Recommendation   "Enable Diagnostic Settings on all Azure Firewalls, routing AzureFirewallNetworkRule, AzureFirewallApplicationRule, AzureFirewallDnsProxy, and AllMetrics logs to a Log Analytics workspace. Retain logs for a minimum of 90 days (365 days for compliance-regulated environments)."
                        $subFindingCount++
                    }
                }
                catch {
                    Write-Verbose "  Could not retrieve diagnostic settings for Firewall '$($fw.Name)': $_"
                }
            }

            # Check 4 — Threat Intelligence mode not set to Deny
            foreach ($policy in $fwPolicies) {
                $tiMode = Get-ObjProperty -Obj $policy -PropName 'ThreatIntelMode' -Default "Off"
                if ($tiMode -ne "Deny") {
                    $allFindings += New-FwFinding `
                        -SubscriptionName $sub.Name `
                        -SubscriptionId   $sub.Id `
                        -ResourceName     $policy.Name `
                        -ResourceId       $policy.Id `
                        -ResourceType     "FirewallPolicy" `
                        -Category         "Threat Intel" `
                        -CheckName        "Threat Intelligence Mode — Alert Only (Not Deny)" `
                        -Why              "Azure Firewall Threat Intelligence uses Microsoft's global threat feed to identify known malicious IPs and FQDNs. In Alert-only mode, traffic to/from known-bad destinations is logged but not blocked. In Deny mode, the firewall actively prevents communication with known threat actors at zero additional rule-processing cost." `
                        -CurrentState     "Policy '$($policy.Name)' ThreatIntelMode is '$tiMode'. Connections to/from Microsoft-identified malicious IPs and FQDNs are $(if ($tiMode -eq 'Alert') { 'alerted but not blocked' } else { 'neither alerted nor blocked' })." `
                        -Risk             "Known malicious actors can establish outbound C2 connections and receive inbound attack traffic through a firewall that is not blocking known-bad destinations. This is a zero-effort, near-zero-false-positive control that should always be enabled at maximum effectiveness." `
                        -Severity         $(if ($tiMode -eq "Alert") { "Medium" } else { "High" }) `
                        -Recommendation   "Set ThreatIntelMode to 'Deny' on all Firewall Policies. Test in 'Alert' mode for 48 hours in non-production environments to confirm no legitimate traffic is blocked, then switch to 'Deny'. False positives should be handled via IP Group allowlist entries, not by keeping TI in Alert mode."
                    $subFindingCount++
                }
            }

            # Check 5 — Premium SKU policies not using IDPS
            foreach ($policy in $fwPolicies) {
                $sku = Get-ObjProperty -Obj $policy.Sku -PropName 'Tier' -Default ""
                $idps = Get-ObjProperty -Obj $policy     -PropName 'IntrusionDetection' -Default $null
                $idpsMode = if ($idps) { Get-ObjProperty -Obj $idps -PropName 'Mode' -Default "Off" } else { "Off" }

                if ($sku -eq "Premium" -and $idpsMode -ne "Deny") {
                    $allFindings += New-FwFinding `
                        -SubscriptionName $sub.Name `
                        -SubscriptionId   $sub.Id `
                        -ResourceName     $policy.Name `
                        -ResourceId       $policy.Id `
                        -ResourceType     "FirewallPolicy" `
                        -Category         "Threat Intel" `
                        -CheckName        "Premium Policy — IDPS Not in Deny Mode" `
                        -Why              "Azure Firewall Premium includes signature-based Intrusion Detection and Prevention (IDPS) powered by Suricata. IDPS in Deny mode blocks network-layer exploits, protocol anomalies, and C2 traffic that pass the firewall's rule evaluation. A Premium SKU without IDPS active is paying for capabilities it is not using." `
                        -CurrentState     "Premium policy '$($policy.Name)' has IDPS mode set to '$idpsMode'. Full signature-based intrusion prevention is not active." `
                        -Risk             "Without IDPS in Deny mode, the Premium Firewall cannot stop exploit traffic, protocol-level attacks (e.g. SMB exploits, DNS tunnelling, SQL injection over the wire) even if the traffic matches an Allow rule. The Premium SKU investment provides no additional protection over Standard SKU." `
                        -Severity         "High" `
                        -Recommendation   "Enable IDPS in 'Deny' mode on the Premium Firewall Policy. Start with 'Alert' mode to baseline false positives in the environment, then transition to 'Deny'. Configure signature overrides only for confirmed false positives, not as a blanket override for signature categories."
                    $subFindingCount++
                }
            }

            # ─────────────────────────────────────────────────────────────────
            # R U L E   C O L L E C T I O N   A N A L Y S I S
            # ─────────────────────────────────────────────────────────────────

            foreach ($policy in $fwPolicies) {
                # Retrieve Rule Collection Groups
                $rcGroups = @()
                try {
                    $rcGroups = @(Get-AzFirewallPolicyRuleCollectionGroup -FirewallPolicyName $policy.Name `
                            -ResourceGroupName $policy.ResourceGroupName -ErrorAction Stop)
                }
                catch {
                    Write-Verbose "  Could not retrieve Rule Collection Groups for policy '$($policy.Name)': $_"
                }

                # Check 6 — Empty policy (no rule collection groups)
                if ($rcGroups.Count -eq 0) {
                    $allFindings += New-FwFinding `
                        -SubscriptionName $sub.Name `
                        -SubscriptionId   $sub.Id `
                        -ResourceName     $policy.Name `
                        -ResourceId       $policy.Id `
                        -ResourceType     "FirewallPolicy" `
                        -Category         "Architecture" `
                        -CheckName        "Firewall Policy — No Rule Collection Groups Defined" `
                        -Why              "A Firewall Policy with no Rule Collection Groups is effectively an open policy — all traffic defaults to whatever the implicit deny rule permits. If this policy is linked to a Firewall, the firewall is passing all traffic or relying entirely on a parent policy." `
                        -CurrentState     "Policy '$($policy.Name)' has zero Rule Collection Groups defined." `
                        -Risk             "An empty policy attached to a production Firewall indicates the network security boundary may not be enforcing any explicit rules. Traffic may be passing uninspected." `
                        -Severity         "Medium" `
                        -Recommendation   "Populate the policy with appropriate Network, Application, and NAT Rule Collection Groups. If this is a child policy intentionally inheriting from a parent, document that design and verify the parent policy's rules cover the required traffic flows."
                    $subFindingCount++
                    continue  # No rules to analyse further
                }

                # Collect all priorities for duplicate detection
                $rcgPriorities = @()

                foreach ($rcg in $rcGroups) {
                    $rcgPri = Get-ObjProperty -Obj $rcg.Properties -PropName 'Priority' -Default 0
                    $rcgPriorities += $rcgPri

                    $ruleCollections = Get-ObjProperty -Obj $rcg.Properties -PropName 'RuleCollection' -Default @()
                    if (-not $ruleCollections) { $ruleCollections = @() }

                    # Check 7 — Duplicate Rule Collection Group priority
                    # (evaluated after collecting all priorities below)

                    # Check: No explicit Deny All rule collection in the group
                    $hasDenyAll = $false
                    foreach ($rc in $ruleCollections) {
                        $rcAction = Get-ObjProperty -Obj $rc.Action -PropName 'Type' -Default ""
                        if ($rcAction -eq "Deny") {
                            foreach ($rule in (Get-ObjProperty -Obj $rc -PropName 'Rules' -Default @())) {
                                $ruleSrc = Get-ObjProperty -Obj $rule -PropName 'SourceAddresses'  -Default @()
                                $ruleDest = Get-ObjProperty -Obj $rule -PropName 'DestinationAddresses' -Default @()
                                if (($ruleSrc -contains "*" -or $ruleSrc -contains "0.0.0.0/0") -and
                                    ($ruleDest -contains "*" -or $ruleDest -contains "0.0.0.0/0")) {
                                    $hasDenyAll = $true
                                }
                            }
                        }
                    }

                    # ── Per rule collection analysis ──────────────────────────
                    foreach ($rc in $ruleCollections) {
                        $rcName = Get-ObjProperty -Obj $rc -PropName 'Name'   -Default "UnknownCollection"
                        $rcAction = Get-ObjProperty -Obj $rc.Action -PropName 'Type' -Default "Unknown"
                        $rcRules = Get-ObjProperty -Obj $rc -PropName 'Rules' -Default @()
                        if (-not $rcRules) { $rcRules = @() }

                        $rcType = ""
                        # Determine rule type from first rule
                        if ($rcRules.Count -gt 0) {
                            $firstRule = $rcRules[0]
                            if ($firstRule.PSObject.Properties.Name -contains "Protocols" -and
                                $firstRule.PSObject.Properties.Name -contains "TargetFqdns") {
                                $rcType = "Application"
                            }
                            elseif ($firstRule.PSObject.Properties.Name -contains "TranslatedAddress") {
                                $rcType = "NAT"
                            }
                            else {
                                $rcType = "Network"
                            }
                        }

                        foreach ($rule in $rcRules) {
                            $ruleName = Get-ObjProperty -Obj $rule -PropName 'Name' -Default "UnknownRule"

                            # ── NETWORK RULE CHECKS ───────────────────────────
                            if ($rcType -eq "Network") {
                                $srcAddresses = @(Get-ObjProperty -Obj $rule -PropName 'SourceAddresses'      -Default @())
                                $destAddresses = @(Get-ObjProperty -Obj $rule -PropName 'DestinationAddresses' -Default @())
                                $protocols = @(Get-ObjProperty -Obj $rule -PropName 'IpProtocols'          -Default @())
                                $destPorts = @(Get-ObjProperty -Obj $rule -PropName 'DestinationPorts'     -Default @())

                                # Check 8 — Any-to-Any network rule
                                $srcAny = $srcAddresses -contains "*" -or $srcAddresses -contains "0.0.0.0/0"
                                $destAny = $destAddresses -contains "*" -or $destAddresses -contains "0.0.0.0/0"
                                $portAny = $destPorts -contains "*"
                                $protoAny = $protocols -contains "Any" -or $protocols -contains "TCP,UDP" -or $protocols.Count -eq 0

                                if ($rcAction -eq "Allow" -and $srcAny -and $destAny -and $portAny) {
                                    $allFindings += New-FwFinding `
                                        -SubscriptionName $sub.Name `
                                        -SubscriptionId   $sub.Id `
                                        -ResourceName     "$($policy.Name) / $rcName / $ruleName" `
                                        -ResourceId       $policy.Id `
                                        -ResourceType     "FirewallPolicy" `
                                        -Category         "Network Rule" `
                                        -CheckName        "Any-to-Any Allow Rule (* → * : *)" `
                                        -Why              "An Any-to-Any Allow rule completely bypasses network segmentation. The firewall becomes a stateful packet counter rather than a security control. Any compromised host inside the network can reach any destination on any port without restriction." `
                                        -CurrentState     "Rule '$ruleName' in collection '$rcName' allows all sources to all destinations on all ports. Protocol(s): $($protocols -join ',')." `
                                        -Risk             "Complete east-west and north-south freedom of movement. Ransomware, lateral movement, data exfiltration, and C2 beaconing are all unrestricted. This rule alone nullifies the value of the entire firewall deployment." `
                                        -Severity         "Critical" `
                                        -Recommendation   "Remove the Any-to-Any rule immediately. Replace with explicit, least-privilege Allow rules scoped to specific source/destination IP Groups, required destination ports, and approved protocols. Use Azure Firewall's IP Groups feature to maintain manageable, reusable address sets."
                                    $subFindingCount++
                                }

                                # Check 9 — Management port exposure from wildcard sources
                                if ($rcAction -eq "Allow" -and $srcAny -and (Test-ManagementPort -Ports $destPorts)) {
                                    $exposedPorts = $destPorts -join ", "
                                    $allFindings += New-FwFinding `
                                        -SubscriptionName $sub.Name `
                                        -SubscriptionId   $sub.Id `
                                        -ResourceName     "$($policy.Name) / $rcName / $ruleName" `
                                        -ResourceId       $policy.Id `
                                        -ResourceType     "FirewallPolicy" `
                                        -Category         "Network Rule" `
                                        -CheckName        "Management Port Allowed from Wildcard Source" `
                                        -Why              "Management protocols (RDP, SSH, WinRM, Telnet, FTP) on port 3389/22/5985/23/21 should never be accessible from the Internet or wildcard sources. Exposure to Internet-scale credential spray, brute force, and zero-day exploitation is inevitable on these ports." `
                                        -CurrentState     "Rule '$ruleName' allows management port(s) ($exposedPorts) from source '*' or '0.0.0.0/0'. Collection action: $rcAction." `
                                        -Risk             "Internet-exposed management ports are among the top initial access vectors for ransomware groups. Automated scanners find these ports within minutes of exposure. A single weak credential or unpatched service leads directly to full host compromise." `
                                        -Severity         "Critical" `
                                        -Recommendation   "Restrict management port rules to specific, named source IP Groups (jump host IPs, VPN ranges, PAW subnets). Prefer Azure Bastion for browser-based RDP/SSH access and eliminate direct management port rules to non-Bastion sources entirely."
                                    $subFindingCount++
                                }

                                # Check 10 — Overly broad destination CIDR
                                foreach ($dest in $destAddresses) {
                                    if ($rcAction -eq "Allow" -and (Test-BroadCidr -Address $dest)) {
                                        $allFindings += New-FwFinding `
                                            -SubscriptionName $sub.Name `
                                            -SubscriptionId   $sub.Id `
                                            -ResourceName     "$($policy.Name) / $rcName / $ruleName" `
                                            -ResourceId       $policy.Id `
                                            -ResourceType     "FirewallPolicy" `
                                            -Category         "Network Rule" `
                                            -CheckName        "Allow Rule — Overly Broad Destination CIDR (≤/8)" `
                                            -Why              "Allowing traffic to a /8 or wider CIDR (e.g. 10.0.0.0/8) effectively permits access to 16 million+ IP addresses. In a segmented network, this defeats micro-segmentation goals and permits lateral movement or data exfiltration to any host in that range." `
                                            -CurrentState     "Rule '$ruleName' allows traffic to destination '$dest' (/$(($dest -split '/')[1]) prefix) from source(s): $($srcAddresses -join ', ')." `
                                            -Risk             "Large destination CIDRs allow traffic to entire network regions, including potential future hosts not intended to be reachable. An attacker with a foothold can move to any IP within the allowed range." `
                                            -Severity         "Medium" `
                                            -Recommendation   "Replace broad CIDR destinations with specific IP Groups containing only the required host IPs or /24–/28 subnets. Use Azure Firewall IP Groups to define and version-control address sets by application tier or environment."
                                        $subFindingCount++
                                        break   # Report once per rule even if multiple broad CIDRs
                                    }
                                }

                                # Check 11 — Protocol=Any on non-trivial port range
                                if ($rcAction -eq "Allow" -and ($protocols -contains "Any") -and -not $portAny) {
                                    $allFindings += New-FwFinding `
                                        -SubscriptionName $sub.Name `
                                        -SubscriptionId   $sub.Id `
                                        -ResourceName     "$($policy.Name) / $rcName / $ruleName" `
                                        -ResourceId       $policy.Id `
                                        -ResourceType     "FirewallPolicy" `
                                        -Category         "Network Rule" `
                                        -CheckName        "Allow Rule — Protocol Set to Any" `
                                        -Why              "Using protocol 'Any' allows both TCP and UDP (and ICMP) on the specified ports. Many application ports have different security profiles over TCP vs UDP. Wildcarding the protocol allows covert channels and protocol-based evasion techniques." `
                                        -CurrentState     "Rule '$ruleName' uses Protocol=Any on port(s): $($destPorts -join ', '). Destinations: $($destAddresses -join ', ')." `
                                        -Risk             "Protocol=Any can allow UDP-based data exfiltration on ports that are expected to carry only TCP. DNS tunnelling and ICMP-based C2 can operate through these rules." `
                                        -Severity         "Low" `
                                        -Recommendation   "Replace Protocol=Any with the explicit protocol(s) required by the application (TCP, UDP, or ICMP as appropriate). Document the protocol requirement in the rule description."
                                    $subFindingCount++
                                }
                            }

                            # ── APPLICATION RULE CHECKS ───────────────────────
                            if ($rcType -eq "Application") {
                                $targetFqdns = @(Get-ObjProperty -Obj $rule -PropName 'TargetFqdns'  -Default @())
                                $ruleProtocols = @(Get-ObjProperty -Obj $rule -PropName 'Protocols'    -Default @())
                                $srcAddresses = @(Get-ObjProperty -Obj $rule -PropName 'SourceAddresses' -Default @())

                                # Check 12 — Wildcard FQDN
                                $wildcardFqdns = @($targetFqdns | Where-Object { $_ -eq "*" -or $_ -eq "*.*" -or $_ -match '^\*\.\*' })
                                if ($rcAction -eq "Allow" -and $wildcardFqdns.Count -gt 0) {
                                    $allFindings += New-FwFinding `
                                        -SubscriptionName $sub.Name `
                                        -SubscriptionId   $sub.Id `
                                        -ResourceName     "$($policy.Name) / $rcName / $ruleName" `
                                        -ResourceId       $policy.Id `
                                        -ResourceType     "FirewallPolicy" `
                                        -Category         "Application Rule" `
                                        -CheckName        "Application Rule — Wildcard FQDN (* or *.*)" `
                                        -Why              "A wildcard FQDN in an application rule allows HTTP/HTTPS traffic to any domain, bypassing domain-level filtering entirely. This is equivalent to disabling the application rule layer for the affected sources and is worse than having no rule, since it creates a false impression of filtering." `
                                        -CurrentState     "Rule '$ruleName' (action: $rcAction) targets wildcard FQDN(s): $($wildcardFqdns -join ', '). Source(s): $($srcAddresses -join ', ')." `
                                        -Risk             "All web destinations are permitted — malware C2 domains, data exfiltration endpoints, phishing sites, and risky SaaS services pass through without inspection. Web content filtering and category-based blocking are completely circumvented." `
                                        -Severity         "Critical" `
                                        -Recommendation   "Replace wildcard FQDNs with explicit domain allowlists. Use Azure Firewall's Web Category filtering (Premium) or FQDN Tags to allow broad categories (e.g. WindowsUpdate) without opening the rule to all domains. Apply default-deny for all uncategorised destinations."
                                    $subFindingCount++
                                }

                                # Check 13 — HTTP (non-TLS) in application rule
                                $httpProtocols = @($ruleProtocols | Where-Object {
                                        $portProp = Get-ObjProperty -Obj $_ -PropName 'Port' -Default ""
                                        $proto = Get-ObjProperty -Obj $_ -PropName 'ProtocolType' -Default ""
                                        $proto -eq "Http" -or $portProp -eq "80"
                                    })
                                if ($httpProtocols.Count -gt 0 -and $rcAction -eq "Allow") {
                                    $allFindings += New-FwFinding `
                                        -SubscriptionName $sub.Name `
                                        -SubscriptionId   $sub.Id `
                                        -ResourceName     "$($policy.Name) / $rcName / $ruleName" `
                                        -ResourceId       $policy.Id `
                                        -ResourceType     "FirewallPolicy" `
                                        -Category         "Application Rule" `
                                        -CheckName        "Application Rule — HTTP (Port 80) Destination Allowed" `
                                        -Why              "HTTP (port 80) traffic is unencrypted and cannot be inspected at the content level for data exfiltration or injected malware by the Firewall's FQDN-based application rules. Allowing HTTP enables plaintext credential and data transmission, and prevents TLS inspection from applying." `
                                        -CurrentState     "Rule '$ruleName' permits HTTP (port 80) to FQDN(s): $($targetFqdns -join ', ')." `
                                        -Risk             "Unencrypted HTTP allows MITM interception, credential harvesting, content injection by network-level adversaries, and data exfiltration via plaintext channels that TLS inspection cannot see." `
                                        -Severity         "Medium" `
                                        -Recommendation   "Replace HTTP rules with HTTPS-only (port 443). Enable TLS Inspection on the Premium Firewall Policy to decrypt, inspect, and re-encrypt HTTPS traffic. For workloads that require HTTP to specific destinations (e.g. package managers), limit the FQDN scope to the minimum required set."
                                    $subFindingCount++
                                }
                            }

                            # ── NAT RULE CHECKS ───────────────────────────────
                            if ($rcType -eq "NAT") {
                                $srcAddresses = @(Get-ObjProperty -Obj $rule -PropName 'SourceAddresses'  -Default @())
                                $translatedAddr = Get-ObjProperty -Obj $rule -PropName 'TranslatedAddress'  -Default ""
                                $translatedPort = Get-ObjProperty -Obj $rule -PropName 'TranslatedPort'     -Default ""
                                $destPorts = @(Get-ObjProperty -Obj $rule -PropName 'DestinationPorts' -Default @())

                                # Check 14 — DNAT exposing management ports
                                if (Test-ManagementPort -Ports $translatedPort) {
                                    $allFindings += New-FwFinding `
                                        -SubscriptionName $sub.Name `
                                        -SubscriptionId   $sub.Id `
                                        -ResourceName     "$($policy.Name) / $rcName / $ruleName" `
                                        -ResourceId       $policy.Id `
                                        -ResourceType     "FirewallPolicy" `
                                        -Category         "NAT Rule" `
                                        -CheckName        "DNAT Rule — Management Port Exposed to Internet" `
                                        -Why              "DNAT rules that forward traffic to internal management ports (RDP 3389, SSH 22, WinRM 5985/5986) through the firewall directly expose virtual machines to Internet-sourced attacks. Azure Firewall DNAT is not a substitute for a secure management access pattern." `
                                        -CurrentState     "NAT rule '$ruleName' translates incoming traffic on port(s) $($destPorts -join ',') to internal address $translatedAddr port $translatedPort. Source restriction: $($srcAddresses -join ', ')." `
                                        -Risk             "Internet-routable management port DNAT is one of the highest-risk network configurations. Attackers perform continuous credential spray and exploit scanning against these endpoints. A single successful authentication or exploitation results in direct VM access." `
                                        -Severity         "Critical" `
                                        -Recommendation   "Remove DNAT rules for management ports immediately. Deploy Azure Bastion in the Hub VNet for browser-based, private RDP/SSH access without requiring public IP or open firewall rules. For emergency access, use Just-In-Time (JIT) VM access via Defender for Cloud with source IP restriction."
                                    $subFindingCount++
                                }

                                # Check 15 — DNAT with wildcard source (no source restriction)
                                $srcAny = $srcAddresses -contains "*" -or $srcAddresses -contains "0.0.0.0/0" -or $srcAddresses.Count -eq 0
                                if ($srcAny) {
                                    $allFindings += New-FwFinding `
                                        -SubscriptionName $sub.Name `
                                        -SubscriptionId   $sub.Id `
                                        -ResourceName     "$($policy.Name) / $rcName / $ruleName" `
                                        -ResourceId       $policy.Id `
                                        -ResourceType     "FirewallPolicy" `
                                        -Category         "NAT Rule" `
                                        -CheckName        "DNAT Rule — No Source IP Restriction (Any Source)" `
                                        -Why              "A DNAT rule with no source restriction allows any IP on the Internet to initiate a connection to the translated internal destination. Even for legitimate exposed services, no source restriction eliminates a layer of defence and exposes the service to Internet-wide scanning." `
                                        -CurrentState     "NAT rule '$ruleName' has source address '*' or no source restriction. Translating to: ${translatedAddr}:${translatedPort}." `
                                        -Risk             "Unrestricted DNAT source allows all Internet hosts to probe and connect to the translated internal destination, maximising the attack surface for the exposed service." `
                                        -Severity         "High" `
                                        -Recommendation   "Where possible, restrict DNAT source addresses to known client IP ranges, CDN service tags, or partner IP blocks. For public services that genuinely require open access, deploy Azure DDoS Protection and Application Gateway WAF in front of the service rather than exposing it via raw DNAT."
                                    $subFindingCount++
                                }
                            }
                        } # end foreach rule
                    } # end foreach rule collection

                    # Check 16 — Duplicate priorities within a policy
                    $dupPriorities = $rcgPriorities | Group-Object | Where-Object { $_.Count -gt 1 }
                    if ($dupPriorities) {
                        $dupList = ($dupPriorities | ForEach-Object { $_.Name }) -join ", "
                        $allFindings += New-FwFinding `
                            -SubscriptionName $sub.Name `
                            -SubscriptionId   $sub.Id `
                            -ResourceName     $policy.Name `
                            -ResourceId       $policy.Id `
                            -ResourceType     "FirewallPolicy" `
                            -Category         "Priority" `
                            -CheckName        "Duplicate Rule Collection Group Priority Values" `
                            -Why              "Azure Firewall processes Rule Collection Groups in ascending priority order (lowest number first). Duplicate priority values create non-deterministic rule processing order — the firewall may process groups in any order when priorities are equal, leading to unpredictable allow/deny outcomes that are difficult to audit and reproduce." `
                            -CurrentState     "Policy '$($policy.Name)' has $($dupPriorities.Count) duplicate Rule Collection Group priority value(s): $dupList." `
                            -Risk             "Non-deterministic rule processing can cause intermittent allow/deny outcomes for the same traffic flow. Security rules intended to deny traffic may be evaluated after an allow rule with the same priority, inadvertently permitting traffic." `
                            -Severity         "High" `
                            -Recommendation   "Assign unique priority values to all Rule Collection Groups. Implement a priority numbering convention (e.g. DNAT: 100-199, Network Deny: 200-299, Network Allow: 300-399, Application: 400-499) documented in your network architecture design."
                        $subFindingCount++
                    }

                } # end foreach rcg
            } # end foreach policy

            # ── Per-subscription result ───────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Policies: $($fwPolicies.Count)  Firewalls: $($classicFws.Count)  Findings: $subFindingCount" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Policies: $($fwPolicies.Count)  Firewalls: $($classicFws.Count)  Findings: $subFindingCount"
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
        if ($severityDist.ContainsKey($f.Severity)) { $severityDist[$f.Severity]++ }
        if ($categoryDist.ContainsKey($f.Category)) { $categoryDist[$f.Category]++ }
        else { $categoryDist[$f.Category] = 1 }
    }

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Total Findings"              = $allFindings.Count
            "Critical"                    = $severityDist["Critical"]
            "High"                        = $severityDist["High"]
            "Medium"                      = $severityDist["Medium"]
            "Low"                         = $severityDist["Low"]
            "Informational"               = $severityDist["Info"]
            "Execution Time"              = $duration
        })

    Write-SeverityBreakdown -Severity $severityDist

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

            $htmlContent = Generate-FirewallPolicyHtml `
                -SessionInfo            $sessionInfo `
                -ScanParameters         $scanParams `
                -Findings               $allFindings `
                -SeverityDistribution   $severityDist `
                -CategoryDistribution   $categoryDist `
                -SubscriptionResults    $subscriptionResults `
                -GeneratedOn            (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

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
            Select-Object SubscriptionName, ResourceName, ResourceType, Category, CheckName, Severity, Recommendation |
            Out-GridView -Title "Azure Firewall Policy Security Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No Azure Firewall Policies or Firewalls found in the targeted subscriptions." -ForegroundColor Yellow
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
