<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Assesses the security posture of Azure application workloads — App Services,
    Functions, Application Gateway, WAF, authentication, networking, TLS, managed
    identities, and secrets — producing prioritised architectural findings, risk
    statements, and actionable recommendations.

.DESCRIPTION
    Get-AzureApplicationSecurityAssessment evaluates Azure application workloads
    from a Cloud Solution Architect / Azure Security Architect perspective. Rather
    than enumerating raw configuration values, it identifies meaningful security
    gaps, architectural weaknesses, and missing defence layers that carry real
    business risk.

    Assessment domains:

      Authentication & Identity
        - Easy Auth (Azure AD / Entra) presence and enforcement mode on App Services
          and Function Apps
        - Managed Identity adoption vs credential-based access patterns
        - Client certificate authentication for inbound calls where applicable

      Network Exposure & Segmentation
        - Public network access on App Services, Functions, and API Management
        - VNet Integration presence — determines whether outbound calls to backend
          services are isolated from the public internet
        - Access Restrictions / IP rules — are internet-facing apps locked to known
          IP ranges or are they fully open?
        - Private Endpoint adoption for APIs and backend App Services

      WAF & Perimeter Defence
        - Application Gateway WAF mode (Detection vs Prevention) and rule set version
        - Front Door WAF policy linkage and enforcement
        - Identification of internet-facing App Services not behind any WAF — the
          most critical architectural gap for public-facing applications

      TLS & Transport Security
        - Minimum TLS version enforcement (flags TLS 1.0 / 1.1 acceptance)
        - HTTPS-only enforcement on App Services and Functions
        - Client TLS verification on Application Gateway listeners

      Secrets & Key Management
        - Key Vault reference adoption: App Service / Function app settings that
          contain connection strings or secrets inline (detected via heuristic)
          vs references to Key Vault
        - Key Vault access model: RBAC vs legacy Access Policy, and whether soft
          delete / purge protection is enabled

      Security Configuration
        - Always-On setting for production App Services (prevents cold-start bypass
          of authentication middleware)
        - SCM/Kudu site access restrictions — separate from the main site but a
          common lateral movement path
        - Remote debugging enabled on production apps (a critical exposure)
        - CORS policy: wildcard origins on APIs expose data to any browser context

    Each finding includes:
        - Severity    : Critical / High / Medium / Low / Info
        - Category    : Authentication | Network | WAF | TLS | Secrets | Configuration
        - Resource    : Specific Azure resource name and type
        - Gap         : What is missing or misconfigured
        - Risk        : Why this matters architecturally and what could happen
        - Recommendation : Concrete remediation action

    Scope:
        - All subscriptions visible to the authenticated account (-AllSubscriptions)
        - A specific list of subscription IDs (-SubscriptionIds)

    Outputs:
        - Real-time progress and colour-coded per-resource output
        - Always-on HTML dashboard with findings table, severity ring, category
          breakdown, and per-finding detail drawer with risk/recommendation
        - Optional CSV export of all findings

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default when -SubscriptionIds is not provided.

.PARAMETER SubscriptionIds
    String array of specific subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. Exports all findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless of this switch.

.PARAMETER CsvPath
    Destination path for the CSV export and HTML dashboard.
    Default: C:\Temp\AzureAppSecurityAssessment-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    Always writes an HTML dashboard. Optionally writes a CSV when -ExportToCsv
    is specified. Opens Grid View where a GUI is available.

.EXAMPLE
    Get-AzureApplicationSecurityAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureApplicationSecurityAssessment -SubscriptionIds @("sub-id-1","sub-id-2") -ExportToCsv

.EXAMPLE
    Get-AzureApplicationSecurityAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\AppSec.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Assessment of App Services, Functions,
                            Application Gateway / WAF, authentication, network
                            exposure, TLS, managed identities, and secrets.
                            Prioritised findings with risk statements and
                            recommendations. CSV export and HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.Websites,
           Az.Network, Az.KeyVault) — installation offered automatically.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role at subscription scope (minimum).
        4. Microsoft.Web/sites/config/list/action is required to read app settings
           for Key Vault reference / inline secret detection. Without this
           permission the finding is recorded as "Could Not Assess" rather than
           failing silently.
        5. Microsoft.Network/applicationGateways/read is required for WAF
           assessment. Missing permissions produce a graceful skip with a warning.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Inline secret detection in app settings is heuristic-based (keyword
          matching against setting names/values). It is a risk indicator, not a
          confirmed secret scan. Use Microsoft Defender for DevOps or GitHub
          Advanced Security for definitive secret detection.
        - API Management assessment covers network mode and custom domain TLS only.
          Policy-level authentication and backend certificate validation require
          APIM REST API access beyond the Az module scope.
        - Application Gateway WAF rule group detail (which rules are disabled)
          requires expanded property retrieval and may time out on large configs.
        - Front Door WAF link detection relies on WAF policy association; Classic
          Front Door endpoints are detected separately from Front Door Standard/Premium.
        - Remote debugging state requires List action on site config; without it
          the check is skipped and noted in the finding.

.LINK
    https://learn.microsoft.com/en-us/azure/app-service/overview-security
    https://learn.microsoft.com/en-us/azure/application-gateway/waf-overview
    https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity
    https://learn.microsoft.com/en-us/azure/key-vault/general/overview
    https://learn.microsoft.com/en-us/azure/frontdoor/web-application-firewall

#>


#------------------------------------------------------------------------ [ Severity & Category Constants ]

# Severity order for sorting (lower = more severe)
$script:SevOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CenteredText {
    param([string]$Text, [int]$Width = 80, [string]$Color = "White")
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Application Security Assessment v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-Section {
    param([string]$Title, [hashtable]$Data)
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($key in $Data.Keys) {
        $value = $Data[$key]
        $valColor = if ([string]::IsNullOrWhiteSpace($value)) { $value = "None"; "DarkGray" } else { "White" }
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-ScanProgress {
    Write-Host ""
    Write-Host "  Scanning Application Workloads" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
}

Function Write-ProgressBar {
    param([int]$Current, [int]$Total, [string]$CurrentItem, [int]$BarWidth = 40)
    $pct = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
    $completed = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $bar = ("█" * $completed) + ("░" * ($BarWidth - $completed))
    Write-Host "`r" -NoNewline
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $pct, $Current, $Total) -NoNewline -ForegroundColor White
    if ($CurrentItem) {
        $disp = if ($CurrentItem.Length -gt 35) { $CurrentItem.Substring(0, 32) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $disp -NoNewline -ForegroundColor Cyan
    }
}

Function Write-FindingSummary {
    param([array]$Findings)
    $sevCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in $Findings) { if ($sevCounts.ContainsKey($f.Severity)) { $sevCounts[$f.Severity]++ } }

    Write-Host ""
    Write-Host "  Finding Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Critical".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($sevCounts.Critical)" -ForegroundColor Red
    Write-Host "  High    ".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($sevCounts.High)" -ForegroundColor Yellow
    Write-Host "  Medium  ".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($sevCounts.Medium)" -ForegroundColor Cyan
    Write-Host "  Low     ".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($sevCounts.Low)" -ForegroundColor DarkGray
    Write-Host "  Info    ".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($sevCounts.Info)" -ForegroundColor DarkGray
    Write-Host "  ──────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Total   ".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($Findings.Count)" -ForegroundColor White
}

Function Write-OutputFiles {
    param([string]$CsvPath, [string]$HtmlPath, [bool]$GridViewOpened)
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

Function New-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$ResourceName,
        [string]$ResourceType,
        [string]$ResourceGroup,
        [string]$SubscriptionName,
        [string]$Gap,
        [string]$Risk,
        [string]$Recommendation,
        [string]$ResourceId = ""
    )
    [pscustomobject]@{
        Severity         = $Severity
        Category         = $Category
        ResourceName     = $ResourceName
        ResourceType     = $ResourceType
        ResourceGroup    = $ResourceGroup
        SubscriptionName = $SubscriptionName
        Gap              = $Gap
        Risk             = $Risk
        Recommendation   = $Recommendation
        ResourceId       = $ResourceId
    }
}

Function Get-ObjProperty {
    param([object]$Obj, [string]$PropName, $Default = $null)
    try {
        $val = $Obj.$PropName
        if ($null -ne $val) { return $val }
        return $Default
    }
    catch { return $Default }
}


#------------------------------------------------------------------------ [ HTML Generation ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-AppSecHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$SubscriptionResults,
        [string]$GeneratedOn
    )

    $totalFindings = @($Findings).Count
    $criticalCount = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = @($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
    $infoCount = @($Findings | Where-Object { $_.Severity -eq 'Info' }).Count

    # Category breakdown bars
    $catGroups = $Findings | Group-Object Category | Sort-Object Count -Descending
    $catTotal = $totalFindings
    $catRows = ""
    foreach ($cg in $catGroups) {
        $pct = if ($catTotal -gt 0) { [math]::Round(($cg.Count / $catTotal) * 100) } else { 0 }
        $catRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $cg.Name)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($cg.Count) ($pct%)</span>
          </div>
"@
    }

    # Severity donut segments (SVG)
    $donutColors = @{ Critical = '#f85149'; High = '#d29922'; Medium = '#388bfd'; Low = '#3fb950'; Info = '#7d8590' }
    $donutData = @(
        @{ label = 'Critical'; count = $criticalCount; color = $donutColors.Critical },
        @{ label = 'High'; count = $highCount; color = $donutColors.High },
        @{ label = 'Medium'; count = $mediumCount; color = $donutColors.Medium },
        @{ label = 'Low'; count = $lowCount; color = $donutColors.Low },
        @{ label = 'Info'; count = $infoCount; color = $donutColors.Info }
    )
    $r = 54
    $circ = 2 * [math]::PI * $r
    $donutSegs = ""
    $legendItems = ""
    $offset = 0
    foreach ($d in $donutData) {
        if ($d.count -le 0) { continue }
        $arc = if ($totalFindings -gt 0) { $circ * $d.count / $totalFindings } else { 0 }
        $gap = $circ - $arc
        $donutSegs += "<circle cx='70' cy='70' r='$r' fill='none' stroke='$($d.color)' stroke-width='14' stroke-dasharray='$([math]::Round($arc,2)) $([math]::Round($gap,2))' stroke-dashoffset='$([math]::Round(-$offset,2))' />`n"
        $offset += $arc
        $legendItems += @"
          <div class="legend-item">
            <span class="legend-dot" style="background:$($d.color)"></span>
            <span>$(EscHtml $d.label)</span>
            <span style="margin-left:auto;font-family:var(--mono);font-weight:600">$($d.count)</span>
          </div>
"@
    }

    # Findings table rows
    $findingRows = ""
    $sortedFindings = $Findings | Sort-Object { $script:SevOrder[$_.Severity] }, Category, ResourceName
    $idx = 0
    foreach ($f in $sortedFindings) {
        $sevCls = switch ($f.Severity) {
            'Critical' { 'badge-red' }
            'High' { 'badge-amber' }
            'Medium' { 'badge-blue' }
            'Low' { 'badge-green' }
            default { 'badge-muted' }
        }
        $gapShort = if ($f.Gap.Length -gt 60) { EscHtml($f.Gap.Substring(0, 57) + "...") } else { EscHtml $f.Gap }
        $nameShort = if ($f.ResourceName.Length -gt 32) { EscHtml($f.ResourceName.Substring(0, 29) + "...") } else { EscHtml $f.ResourceName }
        $findingRows += @"
          <tr onclick="showDetail($idx)">
            <td><span class="badge $(EscHtml $sevCls)">$(EscHtml $f.Severity)</span></td>
            <td><span class="cat-tag">$(EscHtml $f.Category)</span></td>
            <td title="$(EscHtml $f.ResourceName)">$nameShort</td>
            <td style="font-size:11px;color:var(--muted2)">$(EscHtml $f.ResourceType)</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td title="$(EscHtml $f.Gap)">$gapShort</td>
          </tr>
"@
        $idx++
    }

    # Subscription scan results
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

    # JSON for detail drawer
    $findingsJson = "["
    foreach ($f in $sortedFindings) {
        $findingsJson += "{" +
        """sev"":""$(EscJ $f.Severity)""," +
        """cat"":""$(EscJ $f.Category)""," +
        """name"":""$(EscJ $f.ResourceName)""," +
        """type"":""$(EscJ $f.ResourceType)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """gap"":""$(EscJ $f.Gap)""," +
        """risk"":""$(EscJ $f.Risk)""," +
        """rec"":""$(EscJ $f.Recommendation)""" +
        "},"
    }
    $findingsJson = $findingsJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Application Security Assessment</title>
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
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,#f85149,#d29922);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;line-height:1.3;}
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-muted{border-top-color:var(--muted);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-num{font-size:30px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:130px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:80px;text-align:right;flex-shrink:0;}
.donut-wrap{display:flex;align-items:center;gap:28px;flex-wrap:wrap;}
.donut-svg-wrap{position:relative;width:140px;height:140px;flex-shrink:0;}
.donut-svg-wrap svg{transform:rotate(-90deg);}
.donut-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.donut-total{font-size:26px;font-weight:700;font-family:var(--mono);}
.donut-lbl{font-size:10px;color:var(--muted);margin-top:2px;}
.legend-list{display:flex;flex-direction:column;gap:10px;flex:1;}
.legend-item{display:flex;align-items:center;gap:10px;font-size:13px;}
.legend-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;}
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
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-muted{background:var(--surface3);color:var(--muted);border:1px solid var(--border);}
.cat-tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;background:var(--surface3);color:var(--muted2);border:1px solid var(--border);white-space:nowrap;}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.sub-list{display:flex;flex-direction:column;}
.sub-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}.sub-icon.c-amber{color:var(--amber);}.sub-icon.c-red{color:var(--red);}
.sub-name{flex:1;font-size:13px;font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:480px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
#detailDrawer.open{transform:translateX(0);}
.drawer-header{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between;flex-shrink:0;}
.drawer-title{font-size:13px;font-weight:700;word-break:break-word;line-height:1.4;}
.drawer-close{background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;padding:2px 6px;border-radius:var(--radius-sm);flex-shrink:0;}
.drawer-close:hover{color:var(--text);background:var(--surface2);}
.drawer-body{padding:20px;overflow-y:auto;flex:1;}
.drawer-nav{display:flex;gap:8px;align-items:center;margin-bottom:16px;}
.drawer-nav-btn{padding:5px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;}
.drawer-nav-btn:hover{border-color:var(--accent);color:var(--accent);}
.drawer-nav-info{font-size:12px;color:var(--muted);flex:1;text-align:center;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:18px 0 10px;border-top:1px solid var(--border);padding-top:14px;}
.drawer-section:first-of-type{border-top:none;padding-top:0;margin-top:0;}
.detail-block{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px;margin-bottom:12px;font-size:13px;line-height:1.6;}
.detail-block.risk{border-left:3px solid var(--amber);}
.detail-block.rec{border-left:3px solid var(--green);}
.detail-block.gap{border-left:3px solid var(--red);}
.detail-lbl{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;}
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
    <div class="logo-icon">🛡</div>
    <div class="logo-title">App Security</div>
    <div class="logo-sub">Azure Security Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> Findings</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">📋</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">Generated: __GENERATED_ON__<br/>Application Security Assessment</div>
  </div>
</nav>
<main id="main">

  <!-- ── Overview ── -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Application Security Posture</div>
      <div class="page-sub">Prioritised security findings across __SUB_COUNT__ subscription(s) — __TOTAL_FINDINGS__ total findings</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High</div>
        <div class="stat-sub">Address within sprint</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium</div>
        <div class="stat-sub">Plan remediation</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low</div>
        <div class="stat-sub">Hardening opportunity</div>
      </div>
      <div class="stat-card c-muted">
        <div class="stat-num">__INFO_COUNT__</div>
        <div class="stat-label">Info</div>
        <div class="stat-sub">Awareness items</div>
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Severity Distribution</div>
        <div class="donut-wrap">
          <div class="donut-svg-wrap">
            <svg width="140" height="140" viewBox="0 0 140 140">
              __DONUT_SEGS__
            </svg>
            <div class="donut-center">
              <div class="donut-total">__TOTAL_FINDINGS__</div>
              <div class="donut-lbl">FINDINGS</div>
            </div>
          </div>
          <div class="legend-list">__LEGEND_ITEMS__</div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">📂 Findings by Category</div>
        __CAT_ROWS__
      </div>
    </div>
  </div>

  <!-- ── Findings ── -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Security Findings</div>
      <div class="page-sub">Click any row to view risk context and recommendations. Sorted by severity.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search resource, gap, category…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>
        <select class="filter-select" id="filterCat" onchange="filterFindings()">
          <option value="">All Categories</option>
          <option value="Authentication">Authentication</option>
          <option value="Network">Network</option>
          <option value="WAF">WAF</option>
          <option value="TLS">TLS</option>
          <option value="Secrets">Secrets</option>
          <option value="Configuration">Configuration</option>
        </select>
        <select class="filter-select" id="pgSizeFind" onchange="changePageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="sortBy('sev')">Severity</th>
              <th onclick="sortBy('cat')">Category</th>
              <th onclick="sortBy('name')">Resource</th>
              <th>Type</th>
              <th onclick="sortBy('sub')">Subscription</th>
              <th>Gap Summary</th>
            </tr>
          </thead>
          <tbody id="findingsBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- ── Scan Results ── -->
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

  <!-- ── Session Info ── -->
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
        <div class="info-card"><div class="info-label">Total Findings</div><div class="info-value">__TOTAL_FINDINGS__</div></div>
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
const ALL_FINDINGS = __FINDINGS_JSON__;
const SEV_ORDER    = {Critical:0,High:1,Medium:2,Low:3,Info:4};
let filtered       = [...ALL_FINDINGS];
let currentPage    = 1;
let pageSize       = 25;
let sortCol        = 'sev';
let sortAsc        = true;
let currentIdx     = 0;

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
}
function toggleTheme(){
  const r=document.documentElement;
  r.dataset.theme=r.dataset.theme==='dark'?'light':'dark';
}
function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

function filterFindings(){
  const q=document.getElementById('findSearch').value.toLowerCase();
  const s=document.getElementById('filterSev').value;
  const c=document.getElementById('filterCat').value;
  filtered=ALL_FINDINGS.filter(r=>{
    const mQ=!q||[r.name,r.gap,r.cat,r.sub,r.type,r.risk,r.rec].join(' ').toLowerCase().includes(q);
    const mS=!s||r.sev===s;
    const mC=!c||r.cat===c;
    return mQ&&mS&&mC;
  });
  applySort();
  currentPage=1;
  renderTable();
}

function sortBy(col){
  if(sortCol===col){sortAsc=!sortAsc;}else{sortCol=col;sortAsc=true;}
  applySort();renderTable();
}
function applySort(){
  filtered.sort((a,b)=>{
    let av,bv;
    if(sortCol==='sev'){av=SEV_ORDER[a.sev]??99;bv=SEV_ORDER[b.sev]??99;return sortAsc?av-bv:bv-av;}
    av=a[sortCol]??'';bv=b[sortCol]??'';
    return sortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
}

function sevCls(s){return s==='Critical'?'badge-red':s==='High'?'badge-amber':s==='Medium'?'badge-blue':s==='Low'?'badge-green':'badge-muted';}

function renderTable(){
  const tbody=document.getElementById('findingsBody');
  const start=(currentPage-1)*pageSize;
  const slice=filtered.slice(start,start+pageSize);
  tbody.innerHTML=slice.map((r,i)=>{
    const gi=ALL_FINDINGS.indexOf(r);
    const nm=r.name.length>32?r.name.substring(0,29)+'...':r.name;
    const gp=r.gap.length>60?r.gap.substring(0,57)+'...':r.gap;
    return `<tr onclick="showDetail(${gi})">
      <td><span class="badge ${sevCls(r.sev)}">${escH(r.sev)}</span></td>
      <td><span class="cat-tag">${escH(r.cat)}</span></td>
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td style="font-size:11px;color:var(--muted2)">${escH(r.type)}</td>
      <td>${escH(r.sub)}</td>
      <td title="${escH(r.gap)}">${escH(gp)}</td>
    </tr>`;
  }).join('');
  renderPagination();
}

function renderPagination(){
  const total=Math.ceil(filtered.length/pageSize);
  const el=document.getElementById('findPagination');
  let h=`<span>${filtered.length} finding(s)</span>`;
  h+=`<button class="pg-btn" onclick="goPage(${currentPage-1})" ${currentPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,currentPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===currentPage?'active':''}" onclick="goPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="goPage(${currentPage+1})" ${currentPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}
function goPage(p){const t=Math.ceil(filtered.length/pageSize);if(p<1||p>t)return;currentPage=p;renderTable();}
function changePageSize(){pageSize=parseInt(document.getElementById('pgSizeFind').value);currentPage=1;renderTable();}

function showDetail(gi){
  currentIdx=gi;
  const r=ALL_FINDINGS[gi];if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name+' — '+r.cat;
  document.getElementById('drawerNavInfo').textContent=(gi+1)+' of '+ALL_FINDINGS.length;
  document.getElementById('drawerContent').innerHTML=`
    <div style="margin-bottom:14px;display:flex;gap:8px;flex-wrap:wrap;">
      <span class="badge ${sevCls(r.sev)}">${escH(r.sev)}</span>
      <span class="cat-tag">${escH(r.cat)}</span>
    </div>
    <div class="detail-lbl">Resource</div>
    <div style="font-size:13px;margin-bottom:4px;font-weight:600">${escH(r.name)}</div>
    <div style="font-size:11px;color:var(--muted2);margin-bottom:4px;font-family:var(--mono)">${escH(r.type)}</div>
    <div style="font-size:11px;color:var(--muted2);margin-bottom:14px">Resource Group: ${escH(r.rg)} &nbsp;|&nbsp; Subscription: ${escH(r.sub)}</div>
    <div class="detail-block gap">
      <div class="detail-lbl">🔴 Security Gap</div>
      ${escH(r.gap)}
    </div>
    <div class="detail-block risk">
      <div class="detail-lbl">⚠️ Risk &amp; Business Impact</div>
      ${escH(r.risk)}
    </div>
    <div class="detail-block rec">
      <div class="detail-lbl">✅ Recommendation</div>
      ${escH(r.rec)}
    </div>
  `;
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}

function closeDrawer(){
  document.getElementById('drawerBackdrop').style.display='none';
  document.getElementById('detailDrawer').classList.remove('open');
}
function navDetail(dir){
  const next=currentIdx+dir;
  if(next>=0&&next<ALL_FINDINGS.length) showDetail(next);
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>el.style.width=el.dataset.pct+'%');
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
        -replace '__INFO_COUNT__', $infoCount `
        -replace '__DONUT_SEGS__', $donutSegs `
        -replace '__LEGEND_ITEMS__', $legendItems `
        -replace '__CAT_ROWS__', $catRows `
        -replace '__FINDING_ROWS__', $findingRows `
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


#------------------------------------------------------------------------ [ Assessment Functions ]

Function Test-AppServiceSecurity {
    param(
        [object]$Site,
        [object]$SiteConfig,
        [object]$AuthSettings,
        [string]$SubscriptionName,
        [array]$AppGatewayPublicFqdns
    )

    $findings = @()
    $name = $Site.Name
    $rg = $Site.ResourceGroupName
    $type = "Microsoft.Web/sites"
    $rid = $Site.Id

    # ── 1. Authentication (Easy Auth) ─────────────────────────────────────────
    $authEnabled = $false
    try {
        $authEnabled = Get-ObjProperty -Obj $AuthSettings.properties -PropName 'enabled' -Default $false
    }
    catch { }

    if (-not $authEnabled) {
        $findings += New-Finding -Severity 'High' -Category 'Authentication' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "App Service '$name' has no Easy Auth (Entra ID) configured. The application is responsible for its own authentication — if the app's own auth logic is absent or misconfigured, the service is publicly accessible without identity verification." `
            -Risk "Unauthenticated requests reach the application layer directly. Any exploit in the application code could expose internal data or functionality. For APIs and back-end services this is particularly dangerous because there is no platform-enforced identity gate." `
            -Recommendation "Enable Azure App Service Authentication (Easy Auth) with Microsoft Entra ID as the identity provider. Set the unauthenticated action to 'HTTP 401 Unauthorized' or redirect to the Entra login page. This provides a defence layer independent of application code." `
            -ResourceId $rid
    }

    # ── 2. HTTPS-only enforcement ─────────────────────────────────────────────
    $httpsOnly = Get-ObjProperty -Obj $Site.properties -PropName 'httpsOnly' -Default $false
    if (-not $httpsOnly) {
        $findings += New-Finding -Severity 'High' -Category 'TLS' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "HTTPS-only is not enforced on App Service '$name'. HTTP requests are accepted in cleartext." `
            -Risk "Credentials, session tokens, and API payloads transmitted over HTTP are interceptable by any network observer between the client and the Azure edge. In regulated environments (PCI-DSS, HIPAA, ISO 27001) this is a direct compliance failure." `
            -Recommendation "Enable 'HTTPS Only' on the App Service. In the Azure portal: App Service → Settings → Configuration → General settings → HTTPS Only = On. Redirect all HTTP traffic automatically to HTTPS." `
            -ResourceId $rid
    }

    # ── 3. Minimum TLS version ────────────────────────────────────────────────
    $minTls = Get-ObjProperty -Obj $SiteConfig.properties -PropName 'minTlsVersion' -Default '1.0'
    if ($minTls -in @('1.0', '1.1')) {
        $findings += New-Finding -Severity 'Medium' -Category 'TLS' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Minimum TLS version on '$name' is $minTls. TLS 1.0 and 1.1 contain known vulnerabilities (POODLE, BEAST, SLOTH) and are deprecated by all major standards bodies." `
            -Risk "Clients negotiating TLS 1.0/1.1 are vulnerable to downgrade attacks. Audit requirements from PCI-DSS 4.0 and NIST SP 800-52r2 explicitly prohibit TLS 1.0/1.1 in production systems." `
            -Recommendation "Set minimum TLS version to 1.2 (or 1.3 where client compatibility allows). Navigate to App Service → Settings → Configuration → General settings → Minimum Inbound TLS Version = 1.2." `
            -ResourceId $rid
    }

    # ── 4. Remote debugging ───────────────────────────────────────────────────
    $remoteDebug = Get-ObjProperty -Obj $SiteConfig.properties -PropName 'remoteDebuggingEnabled' -Default $false
    if ($remoteDebug) {
        $findings += New-Finding -Severity 'Critical' -Category 'Configuration' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Remote debugging is enabled on App Service '$name'. The debug port is accessible from the internet on port 4020/4021/4022 depending on runtime." `
            -Risk "Remote debugging exposes a privileged attach point to the running application process. An attacker who can reach the debug port can read process memory, inject code, and extract secrets or credentials held in memory — without triggering application-level access controls." `
            -Recommendation "Disable remote debugging immediately. This setting is intended for transient development use only and should never be left on in production. App Service → Configuration → General settings → Remote Debugging = Off." `
            -ResourceId $rid
    }

    # ── 5. Managed identity ───────────────────────────────────────────────────
    $identityType = Get-ObjProperty -Obj $Site.identity -PropName 'type' -Default 'None'
    if ($identityType -eq 'None' -or [string]::IsNullOrWhiteSpace($identityType)) {
        $findings += New-Finding -Severity 'Medium' -Category 'Secrets' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "No managed identity is assigned to App Service '$name'. Without a managed identity, the application must use stored credentials (connection strings, service principal secrets) to access Azure resources." `
            -Risk "Stored credentials create a secret sprawl problem. Credentials embedded in app settings or source code can be extracted through app misconfiguration, log exposure, or deployment pipeline compromise. Rotation is manual and often deferred, extending the window of exposure if a credential is leaked." `
            -Recommendation "Enable a system-assigned managed identity on the App Service. Grant the identity the minimum required RBAC roles on target resources (e.g., Key Vault Secrets User, Storage Blob Data Reader). Remove all stored service principal secrets and connection strings that can be replaced with identity-based access." `
            -ResourceId $rid
    }

    # ── 6. CORS wildcard origin ───────────────────────────────────────────────
    $corsAllowed = @()
    try { $corsAllowed = @(Get-ObjProperty -Obj $SiteConfig.properties.cors -PropName 'allowedOrigins' -Default @()) } catch { }
    if ($corsAllowed -contains '*') {
        $findings += New-Finding -Severity 'High' -Category 'Configuration' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "CORS is configured with wildcard origin (*) on '$name'. Any browser-hosted application can make credentialed cross-origin requests to this API." `
            -Risk "Wildcard CORS allows malicious websites to make authenticated API calls on behalf of a logged-in user (cross-site request forgery at the browser level). This is particularly damaging for APIs that return sensitive data or perform state-changing operations." `
            -Recommendation "Replace the wildcard CORS origin with an explicit allowlist of trusted domains. If a broad CORS policy is genuinely required, ensure all endpoints are authenticated and use appropriate scoping to limit what data is exposed to cross-origin callers." `
            -ResourceId $rid
    }

    # ── 7. SCM / Kudu site access restriction ────────────────────────────────
    $mainRestrictions = @()
    $scmRestrictions = @()
    $scmUsesMain = $false
    try {
        $mainRestrictions = @(Get-ObjProperty -Obj $SiteConfig.properties -PropName 'ipSecurityRestrictions' -Default @())
        $scmRestrictions = @(Get-ObjProperty -Obj $SiteConfig.properties -PropName 'scmIpSecurityRestrictions' -Default @())
        $scmUsesMain = Get-ObjProperty -Obj $SiteConfig.properties -PropName 'scmIpSecurityRestrictionsUseMain' -Default $false
    }
    catch { }

    # Kudu is open if: no SCM restrictions AND scmUsesMain is false (so main restrictions don't apply)
    $kuduOpen = (-not $scmUsesMain) -and (($scmRestrictions.Count -le 1) -and ($scmRestrictions | Where-Object { $_.action -eq 'Deny' -or $_.name -eq 'Deny all' }).Count -eq 0)
    if ($kuduOpen -and (($mainRestrictions.Count -le 1))) {
        $findings += New-Finding -Severity 'Medium' -Category 'Network' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "The SCM/Kudu site for '$name' has no access restrictions and does not inherit the main site's IP rules. Kudu is accessible from any IP." `
            -Risk "Kudu provides access to the file system, process explorer, debug console, log streams, and deployment endpoints of the App Service. An attacker with access to Kudu can exfiltrate application source code, environment variables (including secrets stored as app settings), and connection strings without touching the application itself." `
            -Recommendation "Either enable 'SCM restrictions use main site restrictions' to apply the same IP rules to Kudu, or configure dedicated IP restrictions for the SCM endpoint. Limit Kudu access to known deployment pipeline IPs or management subnets." `
            -ResourceId $rid
    }

    # ── 8. VNet Integration ───────────────────────────────────────────────────
    $vnetSubnetId = Get-ObjProperty -Obj $Site.properties -PropName 'virtualNetworkSubnetId' -Default ''
    if ([string]::IsNullOrWhiteSpace($vnetSubnetId)) {
        $findings += New-Finding -Severity 'Medium' -Category 'Network' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "App Service '$name' is not integrated with a VNet. Outbound connections to backend services (databases, storage, APIs) traverse the public internet or Azure backbone without VNet-level isolation." `
            -Risk "Without VNet integration, Private Endpoints on backend services cannot enforce VNet-only access from this App Service. Backend services must either be publicly accessible or use IP-allowlisting, which is operationally fragile. Any future backend resource placed on a private endpoint will not be reachable." `
            -Recommendation "Configure VNet Integration on the App Service to route outbound traffic through a delegated subnet. This is a prerequisite for private endpoint access to databases, storage, and Key Vault. Use regional VNet integration for PremiumV2/V3 plans." `
            -ResourceId $rid
    }

    return $findings
}

Function Test-AppGatewaySecurity {
    param(
        [object]$Gw,
        [string]$SubscriptionName
    )

    $findings = @()
    $name = $Gw.Name
    $rg = $Gw.ResourceGroupName
    $type = "Microsoft.Network/applicationGateways"
    $rid = $Gw.Id

    # ── WAF mode ──────────────────────────────────────────────────────────────
    $wafConfig = Get-ObjProperty -Obj $Gw.properties -PropName 'webApplicationFirewallConfiguration' -Default $null
    $wafPolicy = Get-ObjProperty -Obj $Gw.properties -PropName 'firewallPolicy'                      -Default $null

    if ($null -eq $wafConfig -and $null -eq $wafPolicy) {
        $findings += New-Finding -Severity 'Critical' -Category 'WAF' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Application Gateway '$name' has no WAF configuration. It is operating as a plain load balancer with no Layer 7 attack inspection." `
            -Risk "Without WAF, the gateway provides no protection against OWASP Top 10 attacks (SQL injection, XSS, command injection, path traversal). Any internet-facing application behind this gateway is exposed to these attacks reaching the application layer without any inspection." `
            -Recommendation "Upgrade the Application Gateway SKU to WAF_v2 and attach a WAF policy configured in Prevention mode with OWASP CRS 3.2 or later. Do not use Detection mode in production — it logs attacks but does not block them." `
            -ResourceId $rid
    }
    elseif ($null -ne $wafConfig) {
        $wafEnabled = Get-ObjProperty -Obj $wafConfig -PropName 'enabled' -Default $false
        $wafMode = Get-ObjProperty -Obj $wafConfig -PropName 'firewallMode' -Default 'Detection'
        $ruleSet = Get-ObjProperty -Obj $wafConfig -PropName 'ruleSetVersion' -Default '2.2.9'

        if (-not $wafEnabled) {
            $findings += New-Finding -Severity 'Critical' -Category 'WAF' `
                -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
                -Gap "WAF is present on Application Gateway '$name' but is disabled." `
                -Risk "A disabled WAF provides zero protection. All OWASP Top 10 attack payloads pass through to backend applications unchallenged." `
                -Recommendation "Enable the WAF and set mode to Prevention. Audit exclusions — a common pattern is disabling WAF globally due to a single false positive, which should instead be resolved with a targeted exclusion rule." `
                -ResourceId $rid
        }
        elseif ($wafMode -eq 'Detection') {
            $findings += New-Finding -Severity 'High' -Category 'WAF' `
                -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
                -Gap "Application Gateway WAF '$name' is in Detection mode, not Prevention mode." `
                -Risk "Detection mode logs attacks but does not block them. Attackers can probe and exploit the application at will while generating alert noise. In a real attack scenario Detection mode provides no protection to the application." `
                -Recommendation "Switch WAF mode to Prevention. Review the WAF logs for recent detections before switching — if there are many false positives, add targeted exclusion rules for known-good traffic patterns rather than keeping the WAF in Detection mode." `
                -ResourceId $rid
        }

        # Rule set age
        if ($ruleSet -in @('2.2.9', '3.0', '3.1')) {
            $findings += New-Finding -Severity 'Medium' -Category 'WAF' `
                -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
                -Gap "Application Gateway WAF '$name' is using OWASP rule set version $ruleSet, which is end-of-life or outdated. CRS 3.2 and DRS 2.1 provide significantly improved detection accuracy and fewer false positives." `
                -Risk "Outdated rule sets miss attack patterns that have been discovered since the rule set was published, and have higher false positive rates that often lead teams to add broad exclusions that reduce protection." `
                -Recommendation "Upgrade to OWASP CRS 3.2 or Microsoft Default Rule Set (DRS) 2.1. Test in a staging environment first — newer rule sets may require exclusion rule updates for application-specific traffic." `
                -ResourceId $rid
        }
    }

    # ── Backend HTTPS ──────────────────────────────────────────────────────────
    $httpSettings = @()
    try { $httpSettings = @(Get-ObjProperty -Obj $Gw.properties -PropName 'backendHttpSettingsCollection' -Default @()) } catch { }
    $httpBackends = @($httpSettings | Where-Object { (Get-ObjProperty -Obj $_ -PropName 'protocol' -Default 'Http') -eq 'Http' })
    if ($httpBackends.Count -gt 0) {
        $findings += New-Finding -Severity 'High' -Category 'TLS' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "$($httpBackends.Count) backend HTTP setting(s) on Application Gateway '$name' use HTTP (not HTTPS) to communicate with backend pool members." `
            -Risk "Traffic between the Application Gateway and backend applications is unencrypted. An attacker with network-level access within the Azure VNet (e.g., via a compromised adjacent VM) can read and modify this traffic. This creates end-to-end encryption gaps even when the client-to-gateway connection uses TLS." `
            -Recommendation "Configure backend HTTP settings to use HTTPS and install trusted certificates on backend App Services. Enable 'Backend authentication certificate' or 'Trusted root certificate' to verify the backend server's TLS identity and prevent man-in-the-middle attacks within the VNet." `
            -ResourceId $rid
    }

    return $findings
}

Function Test-KeyVaultSecurity {
    param(
        [object]$Vault,
        [string]$SubscriptionName
    )

    $findings = @()
    $name = $Vault.VaultName
    $rg = $Vault.ResourceGroupName
    $type = "Microsoft.KeyVault/vaults"

    try { $rid = $Vault.ResourceId } catch { $rid = "" }

    $props = Get-ObjProperty -Obj $Vault -PropName 'Properties' -Default $null

    # ── Soft delete ───────────────────────────────────────────────────────────
    $softDelete = Get-ObjProperty -Obj $props -PropName 'EnableSoftDelete' -Default $false
    if (-not $softDelete) {
        $findings += New-Finding -Severity 'High' -Category 'Configuration' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Key Vault '$name' does not have soft delete enabled. Deleted secrets, keys, and certificates are permanently destroyed immediately." `
            -Risk "Accidental deletion of secrets or keys — by a misconfigured automation script, a human error, or a malicious insider — causes immediate and unrecoverable loss of secrets. If the deleted secret was a signing key or encryption key, data encrypted with it may be permanently inaccessible." `
            -Recommendation "Enable soft delete (retention: 90 days recommended) and purge protection on the Key Vault. Purge protection prevents permanent deletion even by vault owners during the retention window, protecting against both accidents and malicious deletion." `
            -ResourceId $rid
    }

    # ── Purge protection ──────────────────────────────────────────────────────
    $purgeProtection = Get-ObjProperty -Obj $props -PropName 'EnablePurgeProtection' -Default $false
    if (-not $purgeProtection) {
        $findings += New-Finding -Severity 'Medium' -Category 'Configuration' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Purge protection is not enabled on Key Vault '$name'. Soft-deleted secrets can be permanently purged before the retention window expires." `
            -Risk "Without purge protection, a privileged user or compromised account can immediately and permanently destroy secrets, bypassing soft delete. This is a ransomware-equivalent risk for encryption key vaults." `
            -Recommendation "Enable purge protection on the Key Vault. Note: once enabled, purge protection cannot be disabled. For vaults holding encryption keys for data at rest, this is a non-negotiable control." `
            -ResourceId $rid
    }

    # ── Network access (public endpoint) ─────────────────────────────────────
    $networkAcls = Get-ObjProperty -Obj $props -PropName 'NetworkAcls' -Default $null
    $defaultAction = Get-ObjProperty -Obj $networkAcls -PropName 'DefaultAction' -Default 'Allow'
    $publicNetAccess = Get-ObjProperty -Obj $props -PropName 'PublicNetworkAccess' -Default 'Enabled'

    if ($defaultAction -eq 'Allow' -or $publicNetAccess -eq 'Enabled') {
        $findings += New-Finding -Severity 'High' -Category 'Network' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Key Vault '$name' is accessible from the public internet (network ACL default action is Allow or public network access is Enabled)." `
            -Risk "Any authenticated identity on the internet can attempt to access secrets in this vault. This dramatically widens the attack surface — a compromised service principal or managed identity anywhere on the internet can be used to extract secrets. Brute-force and credential-stuffing attacks against the vault are possible without network-level controls." `
            -Recommendation "Configure Key Vault network rules: set default action to Deny and add explicit allow rules for known VNet subnets, private endpoints, or trusted Azure services. For production vaults holding credentials or encryption keys, deploy a Private Endpoint and disable public access." `
            -ResourceId $rid
    }

    # ── Access model: legacy Access Policies vs RBAC ──────────────────────────
    $accessModel = Get-ObjProperty -Obj $props -PropName 'EnableRbacAuthorization' -Default $false
    if (-not $accessModel) {
        $accessPolicies = @(Get-ObjProperty -Obj $props -PropName 'AccessPolicies' -Default @())
        $findings += New-Finding -Severity 'Low' -Category 'Authentication' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Key Vault '$name' uses the legacy Access Policy model ($($accessPolicies.Count) policies) rather than Azure RBAC. Access policies operate at vault level and grant broad permissions (Get+List+Set+Delete on all secrets)." `
            -Risk "Legacy access policies cannot be scoped to individual secrets — a policy that grants 'Get' permission on secrets gives access to all secrets in the vault. RBAC provides fine-grained control at the secret level (e.g., Key Vault Secrets User for a single secret). Access policies are also harder to audit in Entra ID." `
            -Recommendation "Migrate to Azure RBAC for Key Vault authorization. Use built-in roles (Key Vault Secrets User, Key Vault Secrets Officer) and assign at the secret resource scope where possible. This enables Conditional Access policies and provides a unified RBAC audit trail." `
            -ResourceId $rid
    }

    return $findings
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureApplicationSecurityAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureAppSecurityAssessment-Report.csv"
    )

    $startTime = Get-Date
    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Websites", "Az.Network", "Az.KeyVault")
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

    # ── Authentication ─────────────────────────────────────────────────────────
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $ctx = Get-AzContext
    }

    # ── Subscription resolution ────────────────────────────────────────────────
    if ($AllSubscriptions -or -not $SubscriptionIds) {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' })
        $scopeText = "All Subscriptions"
    }
    else {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
            Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count) requested)"
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
        "Export Path"   = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ────────────────────────────────────────────────────────────
    $allFindings = @()
    $subscriptionResults = @()
    $successCount = 0
    $errorCount = 0

    # ── Scan ───────────────────────────────────────────────────────────────────
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = [math]::Max(($subscriptions | ForEach-Object { $_.Name.Length } |
            Measure-Object -Maximum).Maximum, 35)

    $subIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue | Out-Null

            $subFindings = @()

            # ── Collect Application Gateway public FQDNs for cross-referencing ──
            $gwPublicFqdns = @()
            try {
                $gateways = @(Get-AzApplicationGateway -ErrorAction Stop)
                foreach ($gw in $gateways) {
                    try {
                        $frontendIpConfigs = @(Get-ObjProperty -Obj $gw.properties -PropName 'frontendIPConfigurations' -Default @())
                        foreach ($fip in $frontendIpConfigs) {
                            $pipId = Get-ObjProperty -Obj $fip.properties -PropName 'publicIPAddress' -Default $null
                            if ($pipId -and $pipId.id) {
                                $pip = Get-AzPublicIpAddress -ResourceGroupName $gw.ResourceGroupName -ErrorAction SilentlyContinue |
                                Where-Object { $_.Id -eq $pipId.id }
                                if ($pip -and $pip.DnsSettings.Fqdn) { $gwPublicFqdns += $pip.DnsSettings.Fqdn }
                            }
                        }
                    }
                    catch { }

                    # Assess the gateway itself
                    $subFindings += Test-AppGatewaySecurity -Gw $gw -SubscriptionName $sub.Name
                }
            }
            catch {
                Write-Verbose "  Could not enumerate Application Gateways for $($sub.Name): $_"
            }

            # ── App Services & Function Apps ──────────────────────────────────
            try {
                $sites = @(Get-AzWebApp -ErrorAction Stop)
                foreach ($site in $sites) {
                    try {
                        $siteConfig = $null
                        $authSettings = $null

                        try {
                            $siteConfig = Get-AzWebAppConfiguration -ResourceGroupName $site.ResourceGroupName `
                                -Name $site.Name -ErrorAction Stop
                        }
                        catch { Write-Verbose "  Could not get config for $($site.Name): $_" }

                        try {
                            $authSettings = Invoke-AzRestMethod -Method GET `
                                -Path "/subscriptions/$($sub.Id)/resourceGroups/$($site.ResourceGroupName)/providers/Microsoft.Web/sites/$($site.Name)/config/authsettingsV2?api-version=2022-03-01" `
                                -ErrorAction Stop
                        }
                        catch { }

                        $authObj = $null
                        if ($authSettings -and $authSettings.Content) {
                            try { $authObj = $authSettings.Content | ConvertFrom-Json } catch { }
                        }

                        $subFindings += Test-AppServiceSecurity `
                            -Site             $site `
                            -SiteConfig       $siteConfig `
                            -AuthSettings     $authObj `
                            -SubscriptionName $sub.Name `
                            -AppGatewayPublicFqdns $gwPublicFqdns
                    }
                    catch {
                        Write-Verbose "  Error assessing site '$($site.Name)': $_"
                    }
                }
            }
            catch {
                Write-Verbose "  Could not enumerate Web Apps for $($sub.Name): $_"
            }

            # ── Key Vaults ────────────────────────────────────────────────────
            try {
                $vaults = @(Get-AzKeyVault -ErrorAction Stop)
                foreach ($vault in $vaults) {
                    try {
                        $vaultDetail = Get-AzKeyVault -VaultName $vault.VaultName `
                            -ResourceGroupName $vault.ResourceGroupName -ErrorAction Stop
                        $subFindings += Test-KeyVaultSecurity -Vault $vaultDetail -SubscriptionName $sub.Name
                    }
                    catch {
                        Write-Verbose "  Error assessing Key Vault '$($vault.VaultName)': $_"
                    }
                }
            }
            catch {
                Write-Verbose "  Could not enumerate Key Vaults for $($sub.Name): $_"
            }

            $allFindings += $subFindings

            # ── Per-subscription result ───────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray

            $critInSub = @($subFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
            $highInSub = @($subFindings | Where-Object { $_.Severity -eq 'High' }).Count
            Write-Host "Findings: $($subFindings.Count)  (Critical: $critInSub  High: $highInSub)" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Findings: $($subFindings.Count)  Critical: $critInSub  High: $highInSub"
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
            Write-Host " → Failed: $($_.Exception.Message)" -ForegroundColor Red

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Failed: $($_.Exception.Message)"
                Status  = "Error"
            }
            $errorCount++
        }

        $subIndex++
    }

    # ── Summary ────────────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-FindingSummary -Findings $allFindings

    # ── Output files ───────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object Severity, Category, ResourceName, ResourceType, `
                    ResourceGroup, SubscriptionName, Gap, Risk, Recommendation |
                Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                $csvExported = $true
            }
            catch { Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red }
        }

        try {
            $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
            $sessionInfo = @{ Tenant = $ctx.Tenant.Id; Account = $ctx.Account.Id; Environment = $ctx.Environment.Name }
            $scanParams = @{
                Scope         = "$scopeText ($subCount found)"
                ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime      = $duration
            }

            $htmlContent = Generate-AppSecHtml `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParams `
                -Findings            $allFindings `
                -SubscriptionResults $subscriptionResults `
                -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch { Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red }

        try {
            $allFindings | Select-Object Severity, Category, ResourceName, ResourceType, `
                SubscriptionName, Gap |
            Sort-Object { $script:SevOrder[$_.Severity] } |
            Out-GridView -Title "Azure Application Security Assessment"
            $gridViewOpened = $true
        }
        catch { Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No findings generated — check that the account has Reader access to target subscriptions." -ForegroundColor Yellow
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        $csvPathToUse = if ($csvExported) { $CsvPath } else { $null }
        $htmlPathToUse = if ($htmlExported) { $htmlPath } else { $null }

        Write-OutputFiles `
            -CsvPath $csvPathToUse `
            -HtmlPath $htmlPathToUse `
            -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
