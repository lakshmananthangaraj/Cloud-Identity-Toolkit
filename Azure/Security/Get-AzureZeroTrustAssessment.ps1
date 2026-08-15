<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Assesses Azure workloads against Zero Trust principles across identity, network,
    workload, data, device, monitoring, and least-privilege controls, with CSV export
    and an interactive HTML dashboard.

.DESCRIPTION
    Get-AzureZeroTrustAssessment evaluates how well Azure resources and configurations
    align with Zero Trust architecture principles across one or more subscriptions.

    The assessment is organized into seven Zero Trust pillars:

        Identity Controls
            - Conditional Access policy coverage (MFA, sign-in risk, device compliance)
            - Privileged Identity Management (PIM) usage for role activation
            - Legacy authentication protocol block status
            - Guest / external identity presence and review indicators

        Network Controls
            - Virtual Network segmentation (subnets per VNet, peering topology)
            - Network Security Group (NSG) attachment and permissive-rule detection
            - Azure Firewall or NVA presence per virtual network hub
            - Private Endpoint adoption vs public endpoint exposure for PaaS services

        Workload Controls
            - Defender for Cloud coverage per subscription (standard / free tier)
            - Secure Score and unhealthy recommendation counts
            - Publicly exposed VMs (public IP, no JIT, no Bastion)
            - System-assigned vs user-assigned managed identity adoption

        Data Controls
            - Storage account public access and HTTPS-only posture
            - Azure Key Vault soft-delete, purge protection, and access model
            - SQL / Cosmos / Storage diagnostic log enablement
            - Customer-managed key (CMK) adoption indicators

        Device Controls (Entra / Intune posture indicators)
            - Device compliance policy presence (Intune)
            - Conditional Access device-filter / device-compliance conditions
            - Hybrid Azure AD join vs Entra ID join coverage

        Monitoring & Threat Detection Controls
            - Microsoft Sentinel workspace presence per subscription
            - Diagnostic settings coverage (Activity Log, resource logs)
            - Microsoft Defender for Cloud alert suppression rules
            - Log Analytics workspace retention period

        Least-Privilege Controls
            - Subscription-level Owner / Contributor direct role assignments
            - Classic administrator presence (deprecated)
            - Azure RBAC custom role proliferation
            - Service principal secret (password credential) age

    For each finding the script records:
        - Control     : Which Zero Trust pillar and control is being assessed
        - Why         : Why the control matters to Zero Trust
        - CurrentState: The observed configuration or count
        - Risk        : The gap or risk if the control is weak
        - Impact      : Business / security impact of the gap
        - Recommendation: Suggested improvement

    The script supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of all findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          pillar distribution panel, risk severity breakdown, detail drawer)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all Zero Trust findings to the path given in
    -CsvPath. The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzureZeroTrustAssessment-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureZeroTrustAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureZeroTrustAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureZeroTrustAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\ZeroTrust.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Seven-pillar Zero Trust assessment
                            covering identity, network, workload, data, device,
                            monitoring, and least-privilege controls. CSV export
                            and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Network, Az.Compute, Az.Security,
           Az.Storage, Az.KeyVault, Az.Monitor, Az.OperationalInsights, Az.Resources)
           — installed automatically with user consent if not present.
        2. Microsoft.Graph PowerShell module (Microsoft.Graph.Identity.SignIns,
           Microsoft.Graph.Identity.Governance, Microsoft.Graph.DeviceManagement)
           — installed automatically with user consent if not present.
           Required for Identity and Device pillar checks (Conditional Access, PIM,
           legacy auth, Intune compliance policies).
        3. Authenticated Azure session (Connect-AzAccount).
        4. Microsoft Graph session (Connect-MgGraph) with scopes:
               Policy.Read.All, RoleManagement.Read.Directory,
               DeviceManagementConfiguration.Read.All,
               Directory.Read.All, AuditLog.Read.All
        5. Reader role (minimum) at the subscription level for Azure resource checks.
        6. Security Reader role for Defender for Cloud / Secure Score access.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Conditional Access and PIM checks require a Microsoft Graph connection
          with sufficient privileges. Without it, Identity pillar checks are
          gracefully marked "Not Assessed — Graph connection required" and assessment
          continues with the remaining pillars.
        - Device pillar checks (Intune compliance policies) require
          DeviceManagementConfiguration.Read.All Graph scope. Skipped gracefully if
          not available.
        - CMK adoption detection is best-effort; not all resource types surface
          encryption key references via the ARM API.
        - Defender for Cloud Secure Score is retrieved at subscription scope; it may
          take up to 24 hours to reflect recent remediation actions.
        - Interactive Grid View requires a GUI-capable session. Skipped gracefully
          in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Management Group-scoped role assignments are not enumerated when the
          caller context is set to subscription scope.

.LINK
    https://learn.microsoft.com/en-us/security/zero-trust/azure-infrastructure-overview
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls
    https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview
    https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure
    https://learn.microsoft.com/en-us/azure/networking/fundamentals/network-overview

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
  Write-CenteredText "Azure Zero Trust Assessment v1.0" -Color White
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
  $completed   = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
  $remaining   = $BarWidth - $completed
  $bar         = ("█" * $completed) + ("░" * $remaining)

  Write-Host "`r" -NoNewline
  Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
  Write-Host $bar -NoNewline -ForegroundColor Cyan
  Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White

  if ($CurrentItem) {
    $maxLen     = 35
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

Function Write-PillarBreakdown {
  param([hashtable]$Pillar)

  if ($Pillar.Count -eq 0) { return }

  Write-Host ""
  Write-Host "  Zero Trust Pillar Finding Counts" -ForegroundColor Cyan
  Write-Host "  " -NoNewline
  Write-Host ("─" * 76) -ForegroundColor DarkGray

  foreach ($p in ($Pillar.GetEnumerator() | Sort-Object Value -Descending)) {
    Write-Host "  " -NoNewline
    Write-Host $p.Key.PadRight(30) -NoNewline -ForegroundColor White
    Write-Host ": " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($p.Value) finding(s)" -ForegroundColor White
  }
}

Function Write-RiskBreakdown {
  param([hashtable]$Risk)

  if ($Risk.Count -eq 0) { return }

  Write-Host ""
  Write-Host "  Risk Severity Breakdown" -ForegroundColor Cyan
  Write-Host "  " -NoNewline
  Write-Host ("─" * 76) -ForegroundColor DarkGray

  $colorMap = @{ "High" = "Red"; "Medium" = "Yellow"; "Low" = "Green"; "Info" = "DarkGray" }

  foreach ($r in ($Risk.GetEnumerator() | Sort-Object Key)) {
    $color = if ($colorMap.ContainsKey($r.Key)) { $colorMap[$r.Key] } else { "White" }
    Write-Host "  " -NoNewline
    Write-Host $r.Key.PadRight(22) -NoNewline -ForegroundColor $color
    Write-Host ": " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($r.Value) finding(s)" -ForegroundColor $color
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
Function New-ZtFinding {
  param(
    [string]$SubscriptionName,
    [string]$SubscriptionId,
    [string]$Pillar,
    [string]$Control,
    [string]$Why,
    [string]$CurrentState,
    [string]$Risk,
    [string]$Severity,          # High | Medium | Low | Info
    [string]$Impact,
    [string]$Recommendation,
    [string]$ResourceScope = ""
  )
  return [pscustomobject]@{
    SubscriptionName = $SubscriptionName
    SubscriptionId   = $SubscriptionId
    Pillar           = $Pillar
    Control          = $Control
    Why              = $Why
    CurrentState     = $CurrentState
    Risk             = $Risk
    Severity         = $Severity
    Impact           = $Impact
    Recommendation   = $Recommendation
    ResourceScope    = $ResourceScope
  }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-ZeroTrustHtml {
  param(
    [hashtable]$SessionInfo,
    [hashtable]$ScanParameters,
    [array]$Findings,
    [hashtable]$PillarDistribution,
    [hashtable]$RiskDistribution,
    [array]$SubscriptionResults,
    [string]$GeneratedOn,
    [bool]$GraphConnected
  )

  $totalFindings = @($Findings).Count
  $highCount     = @($Findings | Where-Object { $_.Severity -eq "High"   }).Count
  $medCount      = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
  $lowCount      = @($Findings | Where-Object { $_.Severity -eq "Low"    }).Count
  $infoCount     = @($Findings | Where-Object { $_.Severity -eq "Info"   }).Count

  $graphBadge = if ($GraphConnected) {
    '<span class="badge badge-green">✓ Connected</span>'
  }
  else {
    '<span class="badge badge-amber">⚠ Not Connected — Identity/Device checks skipped</span>'
  }
  $graphText = if ($GraphConnected) { "Connected" } else { "Not Connected — run Connect-MgGraph before assessment for full coverage" }

  # ── Finding table rows ────────────────────────────────────────────────────
  $findingRows = ""
  foreach ($f in $Findings) {
    $sevCls = switch ($f.Severity) {
      "High"   { "badge-red"   }
      "Medium" { "badge-amber" }
      "Low"    { "badge-green" }
      default  { "badge-blue"  }
    }
    $pillarShort = $f.Pillar -replace " Controls", "" -replace " & ", "/"
    $ctrlDisp    = if ($f.Control.Length -gt 42) { (EscHtml $f.Control.Substring(0, 39)) + "..." } else { EscHtml $f.Control }
    $findingRows += @"
          <tr onclick="showFindingDetail($($Findings.IndexOf($f)))">
            <td title="$(EscHtml $f.Control)">$ctrlDisp</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td><span class="badge badge-blue">$(EscHtml $pillarShort)</span></td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td title="$(EscHtml $f.CurrentState)">$(if ($f.CurrentState.Length -gt 48) { (EscHtml $f.CurrentState.Substring(0,45)) + "..." } else { EscHtml $f.CurrentState })</td>
          </tr>
"@
  }

  # ── Subscription results ──────────────────────────────────────────────────
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

  # ── Pillar distribution bar rows ──────────────────────────────────────────
  $pillarTotal = ($PillarDistribution.Values | Measure-Object -Sum).Sum
  $pillarRows  = ""
  $pillarColors = @{
    "Identity Controls"      = "var(--accent)"
    "Network Controls"       = "var(--accent2)"
    "Workload Controls"      = "var(--accent3)"
    "Data Controls"          = "var(--green)"
    "Device Controls"        = "var(--amber)"
    "Monitoring & Detection" = "var(--red)"
    "Least-Privilege"        = "#e8854f"
  }
  foreach ($p in ($PillarDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
    $pct      = if ($pillarTotal -gt 0) { [math]::Round(($p.Value / $pillarTotal) * 100) } else { 0 }
    $barColor = if ($pillarColors.ContainsKey($p.Key)) { $pillarColors[$p.Key] } else { "var(--accent)" }
    $pillarRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $p.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($p.Value) ($pct%)</span>
          </div>
"@
  }

  # ── Risk distribution bar rows ────────────────────────────────────────────
  $riskTotal = ($RiskDistribution.Values | Measure-Object -Sum).Sum
  $riskRows  = ""
  $riskColors = @{ "High" = "var(--red)"; "Medium" = "var(--amber)"; "Low" = "var(--green)"; "Info" = "var(--muted)" }
  foreach ($r in ($RiskDistribution.GetEnumerator() | Sort-Object { @("High","Medium","Low","Info").IndexOf($_.Key) })) {
    $pct      = if ($riskTotal -gt 0) { [math]::Round(($r.Value / $riskTotal) * 100) } else { 0 }
    $barColor = if ($riskColors.ContainsKey($r.Key)) { $riskColors[$r.Key] } else { "var(--muted)" }
    $riskRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $r.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($r.Value) ($pct%)</span>
          </div>
"@
  }

  # ── JSON for findings detail drawer ───────────────────────────────────────
  $findJson = "["
  foreach ($f in $Findings) {
    $findJson += "{" +
      """ctrl"":""$(EscJ $f.Control)""," +
      """sub"":""$(EscJ $f.SubscriptionName)""," +
      """pillar"":""$(EscJ $f.Pillar)""," +
      """sev"":""$(EscJ $f.Severity)""," +
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
<title>Azure Zero Trust Assessment Dashboard</title>
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
.bar-label{font-size:12px;color:var(--muted2);width:160px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
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
.zt-pillars{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:18px;}
.pillar-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px 12px;text-align:center;}
.pillar-count{font-size:26px;font-weight:700;font-family:var(--mono);}
.pillar-name{font-size:10px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.05em;}
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
  .zt-pillars{grid-template-columns:repeat(2,1fr);}
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
    <div class="logo-title">Zero Trust Assessment</div>
    <div class="logo-sub">Azure Security Architecture</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> All Findings</button>
    <button class="nav-btn" onclick="showPage('identity',this)"><span class="nav-icon">🆔</span> Identity</button>
    <button class="nav-btn" onclick="showPage('network',this)"><span class="nav-icon">🌐</span> Network</button>
    <button class="nav-btn" onclick="showPage('workload',this)"><span class="nav-icon">⚙️</span> Workload</button>
    <button class="nav-btn" onclick="showPage('data',this)"><span class="nav-icon">🗄️</span> Data</button>
    <button class="nav-btn" onclick="showPage('device',this)"><span class="nav-icon">💻</span> Device</button>
    <button class="nav-btn" onclick="showPage('monitoring',this)"><span class="nav-icon">📡</span> Monitoring</button>
    <button class="nav-btn" onclick="showPage('leastpriv',this)"><span class="nav-icon">🔒</span> Least-Privilege</button>
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
      Azure Zero Trust Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Zero Trust Assessment Overview</div>
      <div class="page-sub">Seven-pillar security architecture assessment across __SUB_COUNT__ subscription(s)</div>
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
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MED_COUNT__</div>
        <div class="stat-label">Medium Severity</div>
        <div class="stat-sub">Plan remediation</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low Severity</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__INFO_COUNT__</div>
        <div class="stat-label">Informational</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__SUB_COUNT__</div>
        <div class="stat-label">Subscriptions Scanned</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🏛️ Findings by Zero Trust Pillar</div>
        __PILLAR_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">⚠️ Risk Severity Distribution</div>
        __RISK_ROWS__
      </div>
    </div>
  </div>

  <!-- All Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">All Findings</div>
      <div class="page-sub">Click any row for the full finding detail — control context, risk, impact, and recommendation</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search control, subscription…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterPillar" onchange="filterFindings()">
          <option value="">All Pillars</option>
          <option value="Identity Controls">Identity</option>
          <option value="Network Controls">Network</option>
          <option value="Workload Controls">Workload</option>
          <option value="Data Controls">Data</option>
          <option value="Device Controls">Device</option>
          <option value="Monitoring &amp; Detection">Monitoring</option>
          <option value="Least-Privilege">Least-Privilege</option>
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
              <th onclick="sortFindings(2)">Pillar</th>
              <th onclick="sortFindings(3)">Severity</th>
              <th onclick="sortFindings(4)">Current State</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- Pillar pages — Identity, Network, Workload, Data, Device, Monitoring, Least-Privilege -->
  <div id="page-identity"   class="page"><div class="page-header"><div class="page-title">Identity Controls</div><div class="page-sub">Conditional Access, PIM, legacy authentication, and guest identity posture</div></div><div id="pillarContent-identity"></div></div>
  <div id="page-network"    class="page"><div class="page-header"><div class="page-title">Network Controls</div><div class="page-sub">VNet segmentation, NSG posture, firewall coverage, and private endpoint adoption</div></div><div id="pillarContent-network"></div></div>
  <div id="page-workload"   class="page"><div class="page-header"><div class="page-title">Workload Controls</div><div class="page-sub">Defender for Cloud coverage, Secure Score, VM exposure, and managed identity adoption</div></div><div id="pillarContent-workload"></div></div>
  <div id="page-data"       class="page"><div class="page-header"><div class="page-title">Data Controls</div><div class="page-sub">Storage access posture, Key Vault hardening, diagnostic logging, and CMK adoption</div></div><div id="pillarContent-data"></div></div>
  <div id="page-device"     class="page"><div class="page-header"><div class="page-title">Device Controls</div><div class="page-sub">Intune compliance policies and Conditional Access device-filter conditions</div></div><div id="pillarContent-device"></div></div>
  <div id="page-monitoring" class="page"><div class="page-header"><div class="page-title">Monitoring &amp; Detection</div><div class="page-sub">Sentinel coverage, diagnostic settings, alert suppression, and log retention</div></div><div id="pillarContent-monitoring"></div></div>
  <div id="page-leastpriv"  class="page"><div class="page-header"><div class="page-title">Least-Privilege Controls</div><div class="page-sub">Privileged role assignments, classic admins, custom role sprawl, and SPN credential age</div></div><div id="pillarContent-leastpriv"></div></div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription Zero Trust assessment outcome</div>
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

// ── Pillar page maps ──────────────────────────────────────────────────────────
const PILLAR_PAGE_MAP = {
  'Identity Controls'     : 'identity',
  'Network Controls'      : 'network',
  'Workload Controls'     : 'workload',
  'Data Controls'         : 'data',
  'Device Controls'       : 'device',
  'Monitoring & Detection': 'monitoring',
  'Least-Privilege'       : 'leastpriv'
};

function showPage(id, btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
  // Render pillar-specific table if needed
  const pillarContentEl = document.getElementById('pillarContent-'+id);
  if(pillarContentEl && pillarContentEl.innerHTML===''){
    renderPillarPage(id, pillarContentEl);
  }
}

function pillarForPage(pageId){
  return Object.keys(PILLAR_PAGE_MAP).find(k=>PILLAR_PAGE_MAP[k]===pageId)||'';
}

function renderPillarPage(pageId, el){
  const pillar = pillarForPage(pageId);
  const rows = FIND_DATA.filter(f=>f.pillar===pillar);
  if(rows.length===0){
    el.innerHTML='<div class="panel" style="color:var(--muted);font-size:13px;">No findings recorded for this pillar.</div>';
    return;
  }
  const tbody = rows.map((f,i)=>{
    const gi = FIND_DATA.indexOf(f);
    const sevCls = f.sev==='High'?'badge-red':f.sev==='Medium'?'badge-amber':f.sev==='Low'?'badge-green':'badge-blue';
    const nm = f.ctrl.length>44?f.ctrl.substring(0,41)+'...':f.ctrl;
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(f.ctrl)}">${escH(nm)}</td>
      <td>${escH(f.sub)}</td>
      <td><span class="badge ${sevCls}">${escH(f.sev)}</span></td>
      <td title="${escH(f.state)}">${escH(f.state.length>52?f.state.substring(0,49)+'...':f.state)}</td>
    </tr>`;
  }).join('');
  el.innerHTML=`<div class="panel"><div class="tbl-wrap"><table>
    <thead><tr><th>Control</th><th>Subscription</th><th>Severity</th><th>Current State</th></tr></thead>
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
  const p  = document.getElementById('filterPillar').value;
  const sv = document.getElementById('filterSev').value;
  findFiltered = FIND_DATA.filter(r=>{
    const mQ = !q  || JSON.stringify(r).toLowerCase().includes(q);
    const mP = !p  || r.pillar===p;
    const mS = !sv || r.sev===sv;
    return mQ && mP && mS;
  });
  findPage=1; renderFindings();
}

function changeFindPageSize(){
  findPageSz=parseInt(document.getElementById('pgSizeFind').value);
  findPage=1; renderFindings();
}

function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys=['ctrl','sub','pillar','sev','state'];
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
    const gi=FIND_DATA.indexOf(r);
    const sevCls=r.sev==='High'?'badge-red':r.sev==='Medium'?'badge-amber':r.sev==='Low'?'badge-green':'badge-blue';
    const nm=r.ctrl.length>42?r.ctrl.substring(0,39)+'...':r.ctrl;
    const pillarShort = r.pillar.replace(' Controls','').replace(' & ','/');
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.ctrl)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td><span class="badge badge-blue">${escH(pillarShort)}</span></td>
      <td><span class="badge ${sevCls}">${escH(r.sev)}</span></td>
      <td title="${escH(r.state)}">${escH(r.state.length>48?r.state.substring(0,45)+'...':r.state)}</td>
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
  const sevCls=r.sev==='High'?'badge-red':r.sev==='Medium'?'badge-amber':r.sev==='Low'?'badge-green':'badge-blue';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Pillar</div>
      <div class="drawer-field-value"><span class="badge badge-blue">${escH(r.pillar)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sevCls}">${escH(r.sev)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    ${r.scope?`<div class="drawer-field"><div class="drawer-field-label">Resource / Scope</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.scope)}</div></div>`:''}
    <div class="drawer-section">Why This Matters</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.why)}</div></div>
    <div class="drawer-section">Current State</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.state)}</div></div>
    <div class="drawer-section">Risk / Gap</div>
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
    -replace '__GENERATED_ON__',    $GeneratedOn `
    -replace '__SUB_COUNT__',       ($SubscriptionResults.Count) `
    -replace '__TOTAL_FINDINGS__',  $totalFindings `
    -replace '__HIGH_COUNT__',      $highCount `
    -replace '__MED_COUNT__',       $medCount `
    -replace '__LOW_COUNT__',       $lowCount `
    -replace '__INFO_COUNT__',      $infoCount `
    -replace '__GRAPH_BANNER_CLS__', $(if ($GraphConnected) { "connected" } else { "skipped" }) `
    -replace '__GRAPH_BANNER_TEXT__', $graphText `
    -replace '__GRAPH_TEXT__',      $graphText `
    -replace '__PILLAR_ROWS__',     $pillarRows `
    -replace '__RISK_ROWS__',       $riskRows `
    -replace '__FINDING_ROWS__',    $findingRows `
    -replace '__SUB_ROWS__',        $subRows `
    -replace '__TENANT__',          $SessionInfo.Tenant `
    -replace '__ACCOUNT__',         $SessionInfo.Account `
    -replace '__ENVIRONMENT__',     $SessionInfo.Environment `
    -replace '__SCOPE__',           $ScanParameters.Scope `
    -replace '__EXPORT_ENABLED__',  $ScanParameters.ExportEnabled `
    -replace '__EXEC_TIME__',       $ScanParameters.ExecTime `
    -replace '__FIND_JSON__',       $findJson

  return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureZeroTrustAssessment {
  [CmdletBinding()]
  param (
    [switch]$AllSubscriptions,

    [string[]]$SubscriptionIds,

    [switch]$ExportToCsv,

    [ValidateNotNullOrEmpty()]
    [string]$CsvPath = "C:\Temp\AzureZeroTrustAssessment-Report.csv"
  )

  $startTime = Get-Date

  Write-Banner

  # ── Module check — Az ─────────────────────────────────────────────────────
  $requiredAzModules = @(
    "Az.Accounts", "Az.Network", "Az.Compute", "Az.Security",
    "Az.Storage", "Az.KeyVault", "Az.Monitor", "Az.OperationalInsights", "Az.Resources"
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

  # ── Module check — Microsoft.Graph (optional, graceful) ───────────────────
  $graphModules = @(
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Identity.Governance",
    "Microsoft.Graph.DeviceManagement"
  )

  $missingGraph = $graphModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
  if ($missingGraph) {
    Write-Host ""
    Write-Host "  ⚠ Microsoft.Graph modules not found: $($missingGraph -join ', ')" -ForegroundColor Yellow
    $installGraph = Read-Host "  Install Microsoft.Graph module for Identity/Device pillar checks? (Y/N)"
    if ($installGraph -match '^[Yy]$') {
      try {
        Install-Module Microsoft.Graph -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
        Write-Host "  ✓ Microsoft.Graph installed" -ForegroundColor Green
      }
      catch {
        Write-Host "  ⚠ Microsoft.Graph installation failed: $_ — Identity/Device checks will be skipped" -ForegroundColor Yellow
      }
    }
    else {
      Write-Host "  ⚠ Microsoft.Graph skipped — Identity and Device pillar checks will be marked 'Not Assessed'" -ForegroundColor Yellow
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
      Write-Host "  ⚠ No active Microsoft Graph session." -ForegroundColor Yellow
      Write-Host "  Connecting to Microsoft Graph (Policy.Read.All, RoleManagement.Read.Directory," -ForegroundColor Gray
      Write-Host "  DeviceManagementConfiguration.Read.All, Directory.Read.All, AuditLog.Read.All)..." -ForegroundColor Gray
      Connect-MgGraph -Scopes "Policy.Read.All", "RoleManagement.Read.Directory", "DeviceManagementConfiguration.Read.All", "Directory.Read.All", "AuditLog.Read.All" -NoWelcome -ErrorAction Stop
    }
    $graphConnected = $true
    Write-Host "  ✓ Microsoft Graph connected" -ForegroundColor Green
  }
  catch {
    Write-Host "  ⚠ Microsoft Graph connection failed or skipped: $_ — Identity/Device checks will be marked 'Not Assessed'" -ForegroundColor Yellow
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

  # ── Display session / params ──────────────────────────────────────────────
  Write-Section -Title "Session Information" -Data @{
    "Tenant"      = $ctx.Tenant.Id
    "Account"     = $ctx.Account.Id
    "Environment" = $ctx.Environment.Name
  }

  Write-Section -Title "Scan Parameters" -Data @{
    "Scope"           = "$scopeText ($subCount found)"
    "Microsoft Graph" = if ($graphConnected) { "Connected" } else { "Not Connected — Identity/Device checks skipped" }
    "Export to CSV"   = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
    "Export Path"     = if ($ExportToCsv.IsPresent) { $CsvPath }  else { "" }
  }

  # ── Collections ───────────────────────────────────────────────────────────
  $allFindings         = @()
  $subscriptionResults = @()
  $pillarDist          = @{
    "Identity Controls"      = 0
    "Network Controls"       = 0
    "Workload Controls"      = 0
    "Data Controls"          = 0
    "Device Controls"        = 0
    "Monitoring & Detection" = 0
    "Least-Privilege"        = 0
  }
  $riskDist   = @{ "High" = 0; "Medium" = 0; "Low" = 0; "Info" = 0 }
  $successCount = 0
  $errorCount   = 0

  # ── Identity & Device pillar (tenant-scoped — run once) ───────────────────
  Write-Host ""
  Write-Host "  Identity & Device Pillar (Tenant-Scoped)" -ForegroundColor Cyan
  Write-Host "  " -NoNewline
  Write-Host ("─" * 76) -ForegroundColor DarkGray
  Write-Host ""

  $tenantSubName = "Tenant-Wide"
  $tenantSubId   = if ($ctx.Tenant.Id) { $ctx.Tenant.Id } else { "N/A" }

  if ($graphConnected) {
    # ── Conditional Access ─────────────────────────────────────────────────
    try {
      $caPolicies = @(Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop)
      $enabledCa  = @($caPolicies | Where-Object { $_.State -eq "enabled" })
      $mfaCa      = @($enabledCa  | Where-Object { $_.GrantControls -and ($_.GrantControls.BuiltInControls -contains "mfa") })
      $riskCa     = @($enabledCa  | Where-Object { $_.Conditions.UserRiskLevels -or $_.Conditions.SignInRiskLevels })

      if ($mfaCa.Count -eq 0) {
        $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
          -Pillar "Identity Controls" `
          -Control "Conditional Access — MFA Enforcement" `
          -Why "Zero Trust requires that identity is verified on every access request. MFA is the single most effective control against credential-based attacks." `
          -CurrentState "No enabled Conditional Access policy enforces MFA. Total CA policies: $($caPolicies.Count), Enabled: $($enabledCa.Count)" `
          -Risk "Without MFA enforcement, a compromised password gives an attacker full, persistent access to any resource the account can reach." `
          -Severity "High" `
          -Impact "Identity compromise enables lateral movement, data exfiltration, and ransomware deployment across the entire tenant." `
          -Recommendation "Create and enable at least one Conditional Access policy that requires MFA for all users (or all privileged users at minimum), targeting all cloud apps."
      }
      else {
        $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
          -Pillar "Identity Controls" `
          -Control "Conditional Access — MFA Enforcement" `
          -Why "MFA is the baseline Zero Trust identity verification control." `
          -CurrentState "$($mfaCa.Count) enabled CA policy/policies enforce MFA out of $($enabledCa.Count) enabled policies." `
          -Risk "Low — MFA coverage exists. Verify scope includes all users and all cloud apps." `
          -Severity "Info" `
          -Impact "Existing MFA controls reduce credential-based attack risk significantly." `
          -Recommendation "Audit CA policy scope — exclude-lists and 'All Users' exceptions may leave privileged accounts unprotected."
      }

      if ($riskCa.Count -eq 0) {
        $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
          -Pillar "Identity Controls" `
          -Control "Conditional Access — Sign-In Risk Policy" `
          -Why "Zero Trust assumes breach. Sign-in risk policies allow automated response to anomalous authentication patterns before an attacker gains access." `
          -CurrentState "No enabled CA policy targets user or sign-in risk levels. Enabled policies: $($enabledCa.Count)" `
          -Risk "Risky sign-ins (atypical travel, leaked credentials, anonymous IPs) can succeed without challenge or block." `
          -Severity "Medium" `
          -Impact "Attackers using compromised credentials from unexpected locations can authenticate unimpeded." `
          -Recommendation "Enable Microsoft Entra ID Protection. Create CA policies that require MFA or block access for medium/high sign-in risk, and require password change for high user risk."
      }
      Write-Host "  ✓ Conditional Access policies assessed ($($caPolicies.Count) total)" -ForegroundColor Green
    }
    catch {
      Write-Host "  ⚠ Could not retrieve Conditional Access policies: $_" -ForegroundColor Yellow
      $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
        -Pillar "Identity Controls" -Control "Conditional Access Assessment" `
        -Why "CA policies are the primary Zero Trust identity enforcement mechanism." `
        -CurrentState "Not Assessed — Graph call failed: $($_.Exception.Message)" `
        -Risk "Could not be confirmed." -Severity "Info" `
        -Impact "Manual review required." -Recommendation "Ensure Policy.Read.All Graph permission is granted."
    }

    # ── PIM ───────────────────────────────────────────────────────────────
    try {
      $pimAssignments = @(Get-MgRoleManagementDirectoryRoleAssignment -Filter "status eq 'Provisioned'" -ErrorAction Stop)
      $permanentPriv  = @($pimAssignments | Where-Object {
          $_.RoleDefinitionId -in @(
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d"   # Security Administrator
          )
        })

      if ($permanentPriv.Count -gt 0) {
        $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
          -Pillar "Identity Controls" `
          -Control "PIM — Permanent Privileged Role Assignments" `
          -Why "Zero Trust least-privilege requires that privileged access is time-limited and just-in-time. Permanent assignments keep high-risk roles always active." `
          -CurrentState "$($permanentPriv.Count) permanent assignment(s) detected in Global Administrator, Privileged Role Administrator, or Security Administrator roles." `
          -Risk "Permanently privileged accounts are high-value targets. Compromise means immediate, unrestricted tenant-admin access." `
          -Severity "High" `
          -Impact "A single compromised permanent Global Admin account gives an attacker complete control over the entire Microsoft 365 and Azure environment." `
          -Recommendation "Activate PIM (Microsoft Entra Privileged Identity Management). Convert permanent role assignments to eligible assignments with approval workflows, MFA on activation, and time-bounded access."
      }
      else {
        $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
          -Pillar "Identity Controls" -Control "PIM — Permanent Privileged Role Assignments" `
          -Why "PIM enforces just-in-time privileged access." `
          -CurrentState "No permanent assignments found in top-tier privileged roles via Graph API." `
          -Risk "Low — PIM appears active for top-tier roles." -Severity "Info" `
          -Impact "JIT access significantly reduces the standing attack surface for privilege escalation." `
          -Recommendation "Extend PIM coverage to all Entra ID and Azure subscription roles, not just directory roles."
      }
      Write-Host "  ✓ PIM / privileged role assignments assessed" -ForegroundColor Green
    }
    catch {
      Write-Host "  ⚠ Could not retrieve PIM assignments: $_" -ForegroundColor Yellow
    }

    # ── Legacy Authentication ─────────────────────────────────────────────
    try {
      $legacyBlock = @(Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop | Where-Object {
          $_.State -eq "enabled" -and
          $_.Conditions.ClientAppTypes -and
          ($_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
           $_.Conditions.ClientAppTypes -contains "other") -and
          $_.GrantControls.Operator -eq "OR" -and
          $_.GrantControls.BuiltInControls -contains "block"
        })

      if ($legacyBlock.Count -eq 0) {
        $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
          -Pillar "Identity Controls" `
          -Control "Legacy Authentication Protocol Block" `
          -Why "Legacy auth protocols (SMTP Auth, IMAP, POP3, Basic Auth) do not support MFA or modern token-based auth, making them a common initial access vector." `
          -CurrentState "No Conditional Access policy found that explicitly blocks legacy authentication (clientAppTypes: exchangeActiveSync / other with Block grant control)." `
          -Risk "Attackers perform password-spray attacks against legacy auth endpoints, bypassing all MFA controls entirely." `
          -Severity "High" `
          -Impact "Successful legacy-auth compromise gives persistent access to mailboxes and resources without triggering MFA — invisible to modern sign-in risk policies." `
          -Recommendation "Create a Conditional Access policy targeting 'Exchange ActiveSync clients' and 'Other clients' for all users, grant: Block. Test in report-only mode first, then enforce."
      }
      Write-Host "  ✓ Legacy authentication block assessed" -ForegroundColor Green
    }
    catch {
      Write-Host "  ⚠ Could not assess legacy authentication block: $_" -ForegroundColor Yellow
    }

    # ── Intune Device Compliance ───────────────────────────────────────────
    try {
      $compliancePolicies = @(Get-MgDeviceManagementDeviceCompliancePolicy -ErrorAction Stop)
      if ($compliancePolicies.Count -eq 0) {
        $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
          -Pillar "Device Controls" `
          -Control "Intune Device Compliance Policies" `
          -Why "Zero Trust requires that devices are known, healthy, and compliant before being trusted to access corporate resources." `
          -CurrentState "No Intune device compliance policies found in the tenant." `
          -Risk "Without compliance policies, any device (personal, unmanaged, or compromised) can access corporate resources." `
          -Severity "High" `
          -Impact "Unmanaged or compromised endpoints become a direct path to data and workloads, bypassing identity controls." `
          -Recommendation "Deploy Intune device compliance policies for each platform (Windows, iOS, Android, macOS). Pair with a CA policy requiring 'Compliant device' for all cloud app access."
      }
      else {
        $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
          -Pillar "Device Controls" -Control "Intune Device Compliance Policies" `
          -Why "Compliance policies establish the device health baseline for Zero Trust access decisions." `
          -CurrentState "$($compliancePolicies.Count) compliance policy/policies configured in Intune." `
          -Risk "Low — policies exist. Confirm CA policy enforces compliance as an access condition." -Severity "Info" `
          -Impact "Device compliance enforcement prevents unmanaged endpoints from accessing sensitive resources." `
          -Recommendation "Audit CA policies to confirm 'Require device to be marked as compliant' is enforced for all cloud apps and all platforms."
      }
      Write-Host "  ✓ Intune compliance policies assessed ($($compliancePolicies.Count) found)" -ForegroundColor Green
    }
    catch {
      Write-Host "  ⚠ Could not retrieve Intune compliance policies: $_" -ForegroundColor Yellow
      $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
        -Pillar "Device Controls" -Control "Intune Device Compliance Policies" `
        -Why "Device compliance is a core Zero Trust control." `
        -CurrentState "Not Assessed — Graph call failed or DeviceManagementConfiguration.Read.All scope missing." `
        -Risk "Could not be confirmed." -Severity "Info" `
        -Impact "Manual review required." `
        -Recommendation "Grant DeviceManagementConfiguration.Read.All to the service principal and re-run."
    }
  }
  else {
    # Graph not connected — mark Identity and Device as skipped
    foreach ($pillarName in @("Identity Controls", "Device Controls")) {
      $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
        -Pillar $pillarName -Control "$pillarName — Not Assessed" `
        -Why "Requires Microsoft Graph connection." `
        -CurrentState "Not Assessed — Microsoft Graph connection was not established." `
        -Risk "Identity and Device controls could not be evaluated without Graph access." `
        -Severity "Info" `
        -Impact "Run Connect-MgGraph before assessment for full coverage." `
        -Recommendation "Re-run the assessment after Connect-MgGraph with Policy.Read.All, RoleManagement.Read.Directory, DeviceManagementConfiguration.Read.All, Directory.Read.All, AuditLog.Read.All scopes."
    }
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

      # ────────────────────────────────────────────────────────────────────
      # NETWORK CONTROLS
      # ────────────────────────────────────────────────────────────────────

      # VNet segmentation
      try {
        $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop)
        foreach ($vnet in $vnets) {
          $subnetCount = @($vnet.Subnets).Count
          if ($subnetCount -le 1) {
            $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
              -Pillar "Network Controls" `
              -Control "VNet Segmentation — Subnet Count" `
              -Why "Zero Trust network architecture requires micro-segmentation so that lateral movement between workload tiers (web, app, data) is controlled and inspected." `
              -CurrentState "VNet '$($vnet.Name)' has $subnetCount subnet(s). Insufficient segmentation for multi-tier workloads." `
              -Risk "A flat network with a single subnet allows unrestricted east-west traffic; compromise of any resource gives access to all resources in the VNet." `
              -Severity "Medium" `
              -Impact "Lateral movement is unrestricted within the VNet — one compromised VM can reach databases and management interfaces directly." `
              -Recommendation "Redesign the VNet with dedicated subnets per tier (e.g., AzureBastionSubnet, GatewaySubnet, app-subnet, data-subnet). Apply NSGs to each subnet with explicit allow rules and default-deny." `
              -ResourceScope $vnet.Id
          }
          $subFindings++
        }

        if ($vnets.Count -eq 0) {
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Network Controls" -Control "VNet Presence" `
            -Why "Network segmentation is a foundational Zero Trust control." `
            -CurrentState "No Virtual Networks found in subscription '$($sub.Name)'." `
            -Risk "Workloads may be using only public endpoints with no network perimeter control." -Severity "Info" `
            -Impact "Assess whether workloads are PaaS-only (acceptable) or rely on public endpoints without segmentation." `
            -Recommendation "If compute workloads are deployed, ensure they reside within a segmented VNet with NSGs and private endpoints."
        }
      }
      catch {
        Write-Verbose "  Could not retrieve VNets for $($sub.Name): $_"
      }

      # NSG assessment
      try {
        $nsgs = @(Get-AzNetworkSecurityGroup -ErrorAction Stop)
        foreach ($nsg in $nsgs) {
          $permissiveInbound = @($nsg.SecurityRules | Where-Object {
              $_.Direction -eq "Inbound" -and
              $_.Access -eq "Allow" -and
              ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "Internet" -or $_.SourceAddressPrefix -eq "0.0.0.0/0") -and
              ($_.DestinationPortRange -eq "*" -or $_.DestinationPortRange -eq "0-65535")
            })

          if ($permissiveInbound.Count -gt 0) {
            $ruleNames = ($permissiveInbound | ForEach-Object { $_.Name }) -join ", "
            $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
              -Pillar "Network Controls" `
              -Control "NSG — Permissive Inbound Rules (Allow-All)" `
              -Why "Zero Trust requires explicit, least-privilege network access. Allow-all inbound rules negate network segmentation and expose every port of every resource in the NSG scope." `
              -CurrentState "NSG '$($nsg.Name)' has $($permissiveInbound.Count) rule(s) allowing all inbound traffic from Internet/Any: $ruleNames" `
              -Risk "All ports of all resources associated with this NSG are reachable from the internet or any source, including management ports (RDP 3389, SSH 22, WinRM 5985)." `
              -Severity "High" `
              -Impact "Exposed management ports are actively scanned by threat actors. Brute-force and exploitation of unpatched services leads directly to VM compromise." `
              -Recommendation "Replace wildcard allow rules with explicit rules for required ports and known source IPs or service tags. Deploy Azure Bastion and enable JIT VM access instead of exposing RDP/SSH directly." `
              -ResourceScope $nsg.Id
            $subFindings++
          }

          # NSG attachment check
          $attachedToSubnet = @($nsg.Subnets).Count -gt 0
          $attachedToNic    = @($nsg.NetworkInterfaces).Count -gt 0
          if (-not $attachedToSubnet -and -not $attachedToNic) {
            $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
              -Pillar "Network Controls" `
              -Control "NSG — Unattached Network Security Group" `
              -Why "An NSG not attached to a subnet or NIC provides no actual protection — it is security theater." `
              -CurrentState "NSG '$($nsg.Name)' is not attached to any subnet or network interface." `
              -Risk "Resources that should be protected by this NSG are unprotected. The NSG rules are not enforced." `
              -Severity "Medium" `
              -Impact "Network controls that exist on paper but are not attached offer no real protection, creating a false sense of security." `
              -Recommendation "Attach the NSG to the intended subnet(s) or NICs, or delete it if it is obsolete. Review all subnet and NIC associations." `
              -ResourceScope $nsg.Id
            $subFindings++
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve NSGs for $($sub.Name): $_"
      }

      # Private Endpoint adoption
      try {
        $storageAccounts   = @(Get-AzStorageAccount -ErrorAction Stop)
        $publicStorage     = @($storageAccounts | Where-Object {
            $_.PublicNetworkAccess -ne "Disabled" -and
            ($null -eq $_.NetworkRuleSet -or $_.NetworkRuleSet.DefaultAction -eq "Allow")
          })

        if ($publicStorage.Count -gt 0) {
          $names = ($publicStorage | ForEach-Object { $_.StorageAccountName }) -join ", "
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Network Controls" `
            -Control "Private Endpoint Adoption — Storage Accounts (Public Access)" `
            -Why "Zero Trust requires that PaaS service access is network-segmented via private endpoints, eliminating public internet exposure of data plane endpoints." `
            -CurrentState "$($publicStorage.Count) storage account(s) with public network access enabled and no restricting network rules: $names" `
            -Risk "Storage accounts accessible from the internet are targets for unauthorized access, data exfiltration, and SAS token abuse." `
            -Severity "High" `
            -Impact "Exposed storage accounts risk sensitive data leakage, ransomware encryption of blob data, and compliance violations (GDPR, PCI-DSS)." `
            -Recommendation "Enable private endpoints for all storage accounts and set PublicNetworkAccess to 'Disabled'. Restrict network rules to known VNet/subnet ranges and trusted Azure services only." `
            -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Storage/storageAccounts"
          $subFindings++
        }
      }
      catch {
        Write-Verbose "  Could not retrieve Storage Accounts for $($sub.Name): $_"
      }

      # Azure Firewall / NVA presence
      try {
        $azFirewalls = @(Get-AzFirewall -ErrorAction Stop)
        if ($azFirewalls.Count -eq 0) {
          # Check for any UDR that might indicate NVA routing
          $routeTables = @(Get-AzRouteTable -ErrorAction Stop)
          $hasNvaRoute = ($routeTables | ForEach-Object {
              $_.Routes | Where-Object { $_.NextHopType -eq "VirtualAppliance" }
            }).Count -gt 0

          if (-not $hasNvaRoute) {
            $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
              -Pillar "Network Controls" `
              -Control "Centralized Firewall / NVA Coverage" `
              -Why "Zero Trust network architecture requires that all traffic (north-south and east-west) passes through an inspection point. NSGs alone do not provide deep packet inspection, IDPS, or centralized policy enforcement." `
              -CurrentState "No Azure Firewall or NVA route (UDR with VirtualAppliance next-hop) detected in subscription '$($sub.Name)'." `
              -Risk "Without a centralized firewall, network-layer threats cannot be detected or blocked. C2 communications and lateral movement traffic pass uninspected." `
              -Severity "Medium" `
              -Impact "Attackers with a foothold in the network can communicate freely with command-and-control infrastructure and pivot to other resources without detection." `
              -Recommendation "Deploy Azure Firewall Premium (IDPS, TLS inspection) in a hub VNet and route all spoke traffic through it. Use Firewall Policy with FQDN rules and threat intelligence filtering enabled."
            $subFindings++
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve Azure Firewall resources for $($sub.Name): $_"
      }

      # ────────────────────────────────────────────────────────────────────
      # WORKLOAD CONTROLS
      # ────────────────────────────────────────────────────────────────────

      # Defender for Cloud coverage
      try {
        $defenderPlans = @(Get-AzSecurityPricing -ErrorAction Stop)
        $freeCount     = @($defenderPlans | Where-Object { $_.PricingTier -eq "Free" }).Count
        $standardCount = @($defenderPlans | Where-Object { $_.PricingTier -eq "Standard" }).Count

        if ($freeCount -gt 0) {
          $freePlans = ($defenderPlans | Where-Object { $_.PricingTier -eq "Free" } | ForEach-Object { $_.Name }) -join ", "
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Workload Controls" `
            -Control "Defender for Cloud — Plan Coverage (Free Tier Detected)" `
            -Why "Zero Trust workload security requires continuous threat detection across all resource types. Defender for Cloud (Standard/Defender plans) provides workload-specific threat intelligence, JIT VM access, adaptive application controls, and file integrity monitoring." `
            -CurrentState "$freeCount plan(s) on Free tier: $freePlans. $standardCount plan(s) on Standard/Defender tier." `
            -Risk "Free tier provides only basic Secure Score recommendations without runtime threat detection, JIT VM access, or adaptive controls." `
            -Severity "High" `
            -Impact "Workloads on Free tier have no runtime threat detection. Attacks against VMs, containers, SQL, and App Services go undetected." `
            -Recommendation "Enable Defender plans for Servers, SQL, Storage, Key Vault, Containers, and App Service at minimum. Prioritize based on workload criticality." `
            -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Security/pricings"
          $subFindings++
        }
      }
      catch {
        Write-Verbose "  Could not retrieve Defender for Cloud plans for $($sub.Name): $_"
      }

      # Secure Score
      try {
        $secureScore = Get-AzSecuritySecureScore -Name "ascScore" -ErrorAction Stop
        $score       = if ($secureScore.PercentageScore) { [math]::Round($secureScore.PercentageScore * 100, 1) } else { 0 }

        if ($score -lt 70) {
          $sev = if ($score -lt 40) { "High" } else { "Medium" }
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Workload Controls" `
            -Control "Defender for Cloud — Secure Score" `
            -Why "Secure Score aggregates unhealthy recommendation counts into a posture indicator. A low score means many basic hardening controls are not in place across the subscription." `
            -CurrentState "Secure Score: $score%. Subscriptions below 70% typically have significant misconfiguration exposure across compute, networking, identity, and data resources." `
            -Risk "Low Secure Scores indicate a large attack surface — misconfigured resources, missing patches, overly permissive access, and weak authentication controls." `
            -Severity $sev `
            -Impact "Unresolved recommendations represent exploitable misconfigurations. Attackers actively probe for these gaps using automated scanning tools." `
            -Recommendation "Review and remediate unhealthy recommendations in Defender for Cloud, prioritizing High severity items. Target a Secure Score above 75% as a baseline posture threshold." `
            -ResourceScope "/subscriptions/$($sub.Id)"
          $subFindings++
        }
      }
      catch {
        Write-Verbose "  Could not retrieve Secure Score for $($sub.Name): $_"
      }

      # VM public exposure
      try {
        $publicIps = @(Get-AzPublicIpAddress -ErrorAction Stop | Where-Object { $_.IpAddress -ne "Not Assigned" })
        $vms       = @(Get-AzVM -ErrorAction Stop)

        # Check JIT policy
        $jitPolicies = @()
        try { $jitPolicies = @(Get-AzJitNetworkAccessPolicy -ErrorAction Stop) } catch { }

        # Check Bastion
        $bastions = @()
        try { $bastions = @(Get-AzBastion -ErrorAction Stop) } catch { }

        $vmPublicIpCount = 0
        foreach ($vm in $vms) {
          $vmNicIds = $vm.NetworkProfile.NetworkInterfaces | ForEach-Object { $_.Id }
          foreach ($nicId in $vmNicIds) {
            try {
              $nicName = ($nicId -split "/")[-1]
              $nicRg   = ($nicId -split "/")[4]
              $nic     = Get-AzNetworkInterface -Name $nicName -ResourceGroupName $nicRg -ErrorAction SilentlyContinue
              if ($nic) {
                $nicPublicIpId = $nic.IpConfigurations | Where-Object { $_.PublicIpAddress } | Select-Object -First 1 -ExpandProperty PublicIpAddress | Select-Object -ExpandProperty Id
                if ($nicPublicIpId) {
                  $vmPublicIpCount++
                }
              }
            }
            catch { }
          }
        }

        if ($vmPublicIpCount -gt 0 -and $bastions.Count -eq 0 -and $jitPolicies.Count -eq 0) {
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Workload Controls" `
            -Control "VM Exposure — Public IP Without Bastion or JIT" `
            -Why "Zero Trust assumes all networks are untrusted. VMs with public IPs and no JIT or Bastion are directly exposed to internet-based attacks on management ports." `
            -CurrentState "$vmPublicIpCount VM NIC(s) with public IPs detected. No Azure Bastion or JIT VM access policy found in the subscription." `
            -Risk "Public IPs on VMs expose RDP (3389) and SSH (22) to internet scanning and brute-force attacks. Without JIT, management ports are permanently open." `
            -Severity "High" `
            -Impact "Direct internet exposure of management interfaces is one of the most common initial access vectors used by ransomware operators and nation-state actors." `
            -Recommendation "Remove public IPs from VMs. Deploy Azure Bastion for secure browser-based RDP/SSH. Enable JIT VM access in Defender for Cloud to open management ports only on-demand for specific source IPs and durations." `
            -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Compute/virtualMachines"
          $subFindings++
        }
      }
      catch {
        Write-Verbose "  Could not retrieve VM exposure data for $($sub.Name): $_"
      }

      # Managed Identity adoption
      try {
        $vms        = @(Get-AzVM -ErrorAction Stop)
        $noIdentity = @($vms | Where-Object { -not $_.Identity -or $_.Identity.Type -eq "None" })

        if ($noIdentity.Count -gt 0 -and $vms.Count -gt 0) {
          $pct = [math]::Round(($noIdentity.Count / $vms.Count) * 100)
          $sev = if ($pct -gt 60) { "Medium" } else { "Low" }
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Workload Controls" `
            -Control "Managed Identity Adoption — Virtual Machines" `
            -Why "Zero Trust requires workloads to authenticate with verifiable, non-secret identities. Managed identities eliminate stored credentials and enable resource-level RBAC without secret management risk." `
            -CurrentState "$($noIdentity.Count) of $($vms.Count) VMs ($pct%) have no managed identity assigned." `
            -Risk "VMs without managed identities typically use stored credentials (service account passwords, shared keys) to access Azure resources, which can be exfiltrated from config files or environment variables." `
            -Severity $sev `
            -Impact "Credential exposure through configuration files or instance metadata endpoints allows attackers to access storage, Key Vault, databases, and other resources without additional exploitation." `
            -Recommendation "Assign system-assigned managed identities to all VMs. Grant the minimum RBAC roles needed. Refactor workloads to use the managed identity credential instead of stored secrets or connection strings." `
            -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Compute/virtualMachines"
          $subFindings++
        }
      }
      catch {
        Write-Verbose "  Could not retrieve VM identity data for $($sub.Name): $_"
      }

      # ────────────────────────────────────────────────────────────────────
      # DATA CONTROLS
      # ────────────────────────────────────────────────────────────────────

      # Key Vault hardening
      try {
        $keyVaults = @(Get-AzKeyVault -ErrorAction Stop)
        foreach ($kvRef in $keyVaults) {
          try {
            $kv = Get-AzKeyVault -VaultName $kvRef.VaultName -ResourceGroupName $kvRef.ResourceGroupName -ErrorAction Stop

            $softDelete     = $kv.EnableSoftDelete
            $purgeProtection = $kv.EnablePurgeProtection

            if (-not $softDelete -or -not $purgeProtection) {
              $missing = @()
              if (-not $softDelete)      { $missing += "Soft Delete" }
              if (-not $purgeProtection) { $missing += "Purge Protection" }

              $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                -Pillar "Data Controls" `
                -Control "Key Vault — Soft Delete and Purge Protection" `
                -Why "Secrets, keys, and certificates in Key Vault are foundational to workload security. Without soft delete and purge protection, they can be permanently deleted — accidentally or by an attacker — with no recovery path." `
                -CurrentState "Key Vault '$($kv.VaultName)' is missing: $($missing -join ', ')." `
                -Risk "An attacker or misconfigured automation script can permanently destroy cryptographic keys and secrets, causing application outages and unrecoverable data loss if CMK-protected data is involved." `
                -Severity "High" `
                -Impact "Permanent deletion of a CMK-encrypted resource's key renders the data permanently inaccessible. Soft-delete bypass also enables hiding of attacker activity." `
                -Recommendation "Enable Soft Delete (90-day retention) and Purge Protection on all Key Vaults. Note: once enabled, purge protection cannot be disabled. Plan before enabling on production Key Vaults." `
                -ResourceScope $kv.ResourceId
              $subFindings++
            }

            # Access model
            if ($kv.EnableRbacAuthorization -ne $true) {
              $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                -Pillar "Data Controls" `
                -Control "Key Vault — Access Model (Vault Access Policy vs RBAC)" `
                -Why "Zero Trust requires fine-grained, auditable access control. Vault Access Policies grant access at the vault level and cannot be scoped to individual secrets or keys. Azure RBAC provides object-level control and full audit trail integration." `
                -CurrentState "Key Vault '$($kv.VaultName)' is using Vault Access Policies (RBAC Authorization disabled)." `
                -Risk "Vault Access Policies grant access to all secrets, keys, or certificates in a vault — the minimum permission is too broad for a least-privilege model." `
                -Severity "Medium" `
                -Impact "A single compromised identity with 'Get' vault access policy can read all secrets in the vault, not just the ones the application needs." `
                -Recommendation "Migrate Key Vault to Azure RBAC authorization model (EnableRbacAuthorization = true). Assign Key Vault Secrets User / Key Vault Reader roles scoped to individual secrets where supported." `
                -ResourceScope $kv.ResourceId
              $subFindings++
            }
          }
          catch {
            Write-Verbose "  Could not retrieve Key Vault details for $($kvRef.VaultName): $_"
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve Key Vaults for $($sub.Name): $_"
      }

      # Storage HTTPS enforcement
      try {
        $storageAccounts = @(Get-AzStorageAccount -ErrorAction Stop)
        $httpStorage     = @($storageAccounts | Where-Object { -not $_.EnableHttpsTrafficOnly })

        if ($httpStorage.Count -gt 0) {
          $names = ($httpStorage | ForEach-Object { $_.StorageAccountName }) -join ", "
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Data Controls" `
            -Control "Storage — HTTPS-Only Enforcement" `
            -Why "Data in transit must be encrypted to prevent interception. Azure Storage accounts that allow HTTP expose data to man-in-the-middle attacks on unencrypted connections." `
            -CurrentState "$($httpStorage.Count) storage account(s) do not enforce HTTPS-only traffic: $names" `
            -Risk "Applications connecting over HTTP expose data to network eavesdropping. Credentials and sensitive content can be captured." `
            -Severity "Medium" `
            -Impact "Unencrypted data in transit violates compliance standards (PCI-DSS 4.2.1, HIPAA §164.312, ISO 27001 A.10.1) and can expose sensitive data to network-level attackers." `
            -Recommendation "Enable 'Secure transfer required' (EnableHttpsTrafficOnly = true) on all storage accounts. This is now the default for new accounts but must be explicitly set for existing ones." `
            -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.Storage/storageAccounts"
          $subFindings++
        }
      }
      catch {
        Write-Verbose "  Could not retrieve Storage HTTPS posture for $($sub.Name): $_"
      }

      # ────────────────────────────────────────────────────────────────────
      # MONITORING & DETECTION CONTROLS
      # ────────────────────────────────────────────────────────────────────

      # Sentinel presence
      try {
        $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop)
        $sentinelWs = @()

        foreach ($ws in $workspaces) {
          try {
            $solutions = @(Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $ws.ResourceGroupName -WorkspaceName $ws.Name -ErrorAction Stop |
              Where-Object { $_.Name -eq "SecurityInsights" -and $_.Enabled -eq $true })
            if ($solutions.Count -gt 0) { $sentinelWs += $ws }
          }
          catch { }
        }

        if ($sentinelWs.Count -eq 0) {
          $sev = if ($workspaces.Count -gt 0) { "Medium" } else { "High" }
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Monitoring & Detection" `
            -Control "Microsoft Sentinel — Workspace Presence" `
            -Why "Zero Trust assumes breach and requires continuous monitoring and threat detection. Microsoft Sentinel provides SIEM/SOAR capabilities, correlating signals across identity, network, workload, and data to detect multi-stage attacks." `
            -CurrentState "No Microsoft Sentinel workspace (SecurityInsights solution) detected in subscription '$($sub.Name)'. Log Analytics workspaces found: $($workspaces.Count)." `
            -Risk "Without Sentinel, security events are fragmented across individual resource logs with no correlation, alert, or investigation capability. Dwell time for undetected breaches increases significantly." `
            -Severity $sev `
            -Impact "The average time to detect a breach without a SIEM is measured in months. Sentinel enables near-real-time detection, investigation, and automated response to reduce dwell time and blast radius." `
            -Recommendation "Deploy Microsoft Sentinel on a centralized Log Analytics workspace. Enable data connectors for Azure Activity, Microsoft Entra ID, Microsoft Defender, and network flow logs. Enable UEBA and threat intelligence." `
            -ResourceScope "/subscriptions/$($sub.Id)/providers/Microsoft.OperationalInsights/workspaces"
          $subFindings++
        }
        else {
          $wsNames = ($sentinelWs | ForEach-Object { $_.Name }) -join ", "
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Monitoring & Detection" -Control "Microsoft Sentinel — Workspace Presence" `
            -Why "Sentinel is the Zero Trust monitoring and detection platform." `
            -CurrentState "Sentinel active on $($sentinelWs.Count) workspace(s): $wsNames" `
            -Risk "Low — Sentinel is deployed. Verify data connectors, analytics rules, and UEBA are enabled." -Severity "Info" `
            -Impact "Sentinel provides correlated threat detection across all Zero Trust pillars." `
            -Recommendation "Review Sentinel data connector coverage, ensure analytics rules are tuned, and validate SOAR playbooks for key alert types."
        }
      }
      catch {
        Write-Verbose "  Could not retrieve Sentinel workspaces for $($sub.Name): $_"
      }

      # Activity Log diagnostic settings
      try {
        $diagSettings = @(Get-AzDiagnosticSetting -ResourceId "/subscriptions/$($sub.Id)" -ErrorAction Stop)
        if ($diagSettings.Count -eq 0) {
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Monitoring & Detection" `
            -Control "Activity Log — Diagnostic Settings" `
            -Why "The Azure Activity Log is the primary audit trail for all control-plane operations (resource creation, deletion, role assignment changes, policy changes). Without export, logs are retained for only 90 days and are not integrated with SIEM." `
            -CurrentState "No diagnostic setting found for the Activity Log in subscription '$($sub.Name)'. Logs are not being exported to Log Analytics or Storage." `
            -Risk "Control-plane activity — including privilege escalation, resource deletion, and policy modification — is not captured in a tamper-resistant, long-term store." `
            -Severity "Medium" `
            -Impact "Attackers can modify policies, escalate privileges, or delete resources, and the evidence may be lost after the 90-day Activity Log retention window." `
            -Recommendation "Create a diagnostic setting on the subscription that routes Activity Logs (Administrative, Security, ServiceHealth, Alert, Policy, Autoscale, ResourceHealth) to a Log Analytics workspace and/or a storage account with immutable retention for compliance." `
            -ResourceScope "/subscriptions/$($sub.Id)"
          $subFindings++
        }
      }
      catch {
        Write-Verbose "  Could not retrieve Activity Log diagnostic settings for $($sub.Name): $_"
      }

      # Log retention
      try {
        $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop)
        foreach ($ws in $workspaces) {
          if ($ws.RetentionInDays -lt 90) {
            $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
              -Pillar "Monitoring & Detection" `
              -Control "Log Analytics — Retention Period" `
              -Why "Security investigations require sufficient log history to reconstruct attack timelines and satisfy compliance requirements (NIST 800-92, ISO 27001, PCI-DSS). Short retention windows limit forensic capability." `
              -CurrentState "Workspace '$($ws.Name)' has a retention period of $($ws.RetentionInDays) days — below the recommended 90-day minimum." `
              -Risk "Insufficient log retention prevents detection of slow-moving attacks that span weeks or months, and limits post-incident investigation scope." `
              -Severity "Medium" `
              -Impact "Forensic investigations are constrained to the retention window. Compliance audits requiring 12-month log history cannot be satisfied." `
              -Recommendation "Set Log Analytics workspace retention to a minimum of 90 days (interactive) with long-term retention (up to 12 years) using the workspace Archive feature. Consider regulatory requirements when setting retention." `
              -ResourceScope $ws.ResourceId
            $subFindings++
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve Log Analytics workspaces for $($sub.Name): $_"
      }

      # ────────────────────────────────────────────────────────────────────
      # LEAST-PRIVILEGE CONTROLS
      # ────────────────────────────────────────────────────────────────────

      # Subscription-level privileged role assignments
      try {
        $subRoles = @(Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction Stop)

        $directOwners = @($subRoles | Where-Object {
            $_.RoleDefinitionName -eq "Owner" -and
            $_.Scope -eq "/subscriptions/$($sub.Id)" -and
            $_.ObjectType -eq "User"
          })

        $directContribs = @($subRoles | Where-Object {
            $_.RoleDefinitionName -eq "Contributor" -and
            $_.Scope -eq "/subscriptions/$($sub.Id)" -and
            $_.ObjectType -eq "User"
          })

        if ($directOwners.Count -gt 3) {
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Least-Privilege" `
            -Control "Subscription — Direct Owner Role Assignments (Users)" `
            -Why "Zero Trust least-privilege requires that subscription Owner — which grants full control over all resources — is held by the minimum number of identities necessary, ideally via PIM eligible assignments rather than permanent direct assignments." `
            -CurrentState "$($directOwners.Count) user accounts have direct (permanent) Owner role at subscription scope." `
            -Risk "Each Owner-level account is a high-value target. Compromise of any one account gives complete control over all resources, RBAC assignments, and security configurations in the subscription." `
            -Severity "High" `
            -Impact "A compromised subscription Owner can disable Defender for Cloud, exfiltrate all data, deploy malware, and cover their tracks by modifying audit settings — all within minutes." `
            -Recommendation "Reduce direct Owner assignments to the minimum required (ideally 2-3 break-glass accounts). Convert remaining Owners to PIM eligible assignments requiring approval and MFA. Use Contributor or specific resource roles for day-to-day operations." `
            -ResourceScope "/subscriptions/$($sub.Id)"
          $subFindings++
        }

        # Classic administrators
        $classicAdmins = @($subRoles | Where-Object { $_.RoleDefinitionName -in @("CoAdministrator", "ServiceAdministrator") })
        if ($classicAdmins.Count -gt 0) {
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Least-Privilege" `
            -Control "Classic Administrator Assignments (Deprecated)" `
            -Why "Classic Administrator roles (Co-Administrator, Service Administrator) predate Azure RBAC, bypass modern access controls, and are not visible in standard RBAC queries. They represent a shadow privileged access channel." `
            -CurrentState "$($classicAdmins.Count) classic administrator assignment(s) detected: $((($classicAdmins | ForEach-Object { $_.SignInName }) -join ', '))" `
            -Risk "Classic admins have subscription-level access equivalent to Owner but are excluded from Azure PIM, Conditional Access policies, and some RBAC audit tools — making them invisible to standard governance controls." `
            -Severity "High" `
            -Impact "Classic admin accounts used for legitimate purposes may be forgotten and left active indefinitely, creating persistent high-privilege access that bypasses modern identity governance." `
            -Recommendation "Remove all classic administrator assignments. Migrate any legitimate access requirements to Azure RBAC Owner or Contributor roles, then apply PIM for just-in-time access." `
            -ResourceScope "/subscriptions/$($sub.Id)"
          $subFindings++
        }

        # Custom role proliferation
        $customRoles = @(Get-AzRoleDefinition -Custom -ErrorAction Stop | Where-Object { $_.AssignableScopes -contains "/subscriptions/$($sub.Id)" -or $_.AssignableScopes -contains "/" })
        if ($customRoles.Count -gt 10) {
          $allFindings += New-ZtFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
            -Pillar "Least-Privilege" `
            -Control "Custom RBAC Role Proliferation" `
            -Why "Custom roles are powerful but require governance. Too many custom roles indicate organic growth without a role lifecycle management process, often resulting in overly permissive or redundant roles that are difficult to audit." `
            -CurrentState "$($customRoles.Count) custom RBAC role definitions assignable in this subscription — above the recommended threshold of 10 for routine governance." `
            -Risk "Unreviewed custom roles may grant excessive permissions. Without lifecycle management, stale custom roles accumulate, expanding the available permission set beyond what is necessary." `
            -Severity "Low" `
            -Impact "Excessive custom roles increase the blast radius of any identity compromise and complicate access reviews, making it harder to enforce least-privilege at scale." `
            -Recommendation "Conduct a custom role review. Identify redundant or overly permissive roles. Use built-in roles where possible. Implement a role lifecycle management process with quarterly reviews and retire roles that are no longer needed." `
            -ResourceScope "/subscriptions/$($sub.Id)"
          $subFindings++
        }
      }
      catch {
        Write-Verbose "  Could not retrieve role assignments for $($sub.Name): $_"
      }

      # Service principal secret age
      if ($graphConnected) {
        try {
          $spns       = @(Get-MgServicePrincipal -All -ErrorAction Stop)
          $oldSecrets = @()
          $cutoff     = (Get-Date).AddDays(-180)

          foreach ($spn in $spns) {
            $oldCreds = @($spn.PasswordCredentials | Where-Object {
                $_.StartDateTime -and $_.StartDateTime -lt $cutoff
              })
            if ($oldCreds.Count -gt 0) { $oldSecrets += $spn }
          }

          if ($oldSecrets.Count -gt 0) {
            $allFindings += New-ZtFinding -SubscriptionName $tenantSubName -SubscriptionId $tenantSubId `
              -Pillar "Least-Privilege" `
              -Control "Service Principal — Old Password Credentials (>180 days)" `
              -Why "Zero Trust requires secrets to be rotated regularly. Long-lived service principal passwords increase the exposure window if a secret is compromised — whether through code repository leaks, configuration file exposure, or memory dump attacks." `
              -CurrentState "$($oldSecrets.Count) service principal(s) with password credentials older than 180 days. Examples: $(($oldSecrets | Select-Object -First 3 | ForEach-Object { $_.DisplayName }) -join ', ')" `
              -Risk "Old secrets may have been exposed in source code, logs, or configuration files without the team's awareness. A secret rotated 180+ days ago has had maximum time for exfiltration and use." `
              -Severity "Medium" `
              -Impact "Compromised SPN credentials enable attackers to authenticate as service identities, accessing storage, databases, and APIs with the permissions of the service — often with no MFA requirement." `
              -Recommendation "Rotate all service principal secrets older than 90 days. Prefer managed identities over SPNs with secrets wherever possible. Implement secret rotation automation via Key Vault references or workload identity federation."
            $subFindings++
          }
        }
        catch {
          Write-Verbose "  Could not retrieve service principal credentials: $_"
        }
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

  # ── Aggregate pillar and risk distributions ───────────────────────────────
  foreach ($f in $allFindings) {
    if ($pillarDist.ContainsKey($f.Pillar)) { $pillarDist[$f.Pillar]++ } else { $pillarDist[$f.Pillar] = 1 }
    if ($riskDist.ContainsKey($f.Severity)) { $riskDist[$f.Severity]++ }
  }

  # ── Summary output ────────────────────────────────────────────────────────
  $endTime  = Get-Date
  $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

  Write-Summary -Data ([ordered]@{
      "Total Subscriptions Scanned" = $subCount
      "Successful"                  = $successCount
      "Errors"                      = $errorCount
      "Total Findings"              = $allFindings.Count
      "High Severity"               = ($allFindings | Where-Object { $_.Severity -eq "High"   } | Measure-Object).Count
      "Medium Severity"             = ($allFindings | Where-Object { $_.Severity -eq "Medium" } | Measure-Object).Count
      "Low Severity"                = ($allFindings | Where-Object { $_.Severity -eq "Low"    } | Measure-Object).Count
      "Informational"               = ($allFindings | Where-Object { $_.Severity -eq "Info"   } | Measure-Object).Count
      "Microsoft Graph Connected"   = if ($graphConnected) { "Yes" } else { "No" }
      "Execution Time"              = $duration
    })

  Write-PillarBreakdown -Pillar $pillarDist
  Write-RiskBreakdown   -Risk   $riskDist

  # ── Output files ──────────────────────────────────────────────────────────
  $csvExported     = $false
  $htmlExported    = $false
  $gridViewOpened  = $false
  $htmlPath        = ""

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

      $htmlContent = Generate-ZeroTrustHtml `
        -SessionInfo          $sessionInfo `
        -ScanParameters       $scanParams `
        -Findings             $allFindings `
        -PillarDistribution   $pillarDist `
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
      Select-Object SubscriptionName, Pillar, Control, Severity, CurrentState, Recommendation |
      Out-GridView -Title "Azure Zero Trust Assessment"
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
    $outCsv  = if ($csvExported)    { $CsvPath  } else { $null }
    $outHtml = if ($htmlExported)   { $htmlPath } else { $null }
    Write-OutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
  }
  else {
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
  }
}
