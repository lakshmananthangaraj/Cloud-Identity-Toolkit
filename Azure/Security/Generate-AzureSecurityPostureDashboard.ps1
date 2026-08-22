<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 22 August 2026
Modified-On     : 22 August 2026

.SYNOPSIS
    Aggregates Azure security findings, risk scores, control coverage, and remediation
    status across one or more subscriptions and delivers an executive-level HTML dashboard.

.DESCRIPTION
    Generate-AzureSecurityPostureDashboard evaluates the end-to-end Azure security posture
    across one or multiple subscriptions by querying Microsoft Defender for Cloud (MDfC),
    Azure Security Center recommendations, identity and access controls, network exposure,
    data protection posture, and encryption state.

    Default assessment (fast, posture-only):
        - Defender for Cloud plan coverage: which plans are enabled vs. disabled
          (Servers, SQL, AppService, Storage, Containers, KeyVault, ARM, DNS, OpenSourceRDB)
        - Secure Score: current score, max score, percentage, and per-control breakdown
        - Security recommendations: total count, severity distribution (High/Medium/Low),
          top unhealthy controls, affected resource counts
        - Identity exposure: MFA enforcement state (legacy per-user flag detection),
          stale guest account count (>90 days inactive), privileged role assignments
        - Network exposure: publicly reachable VMs, open management ports (22/3389/5985),
          NSG-less subnets, missing WAF on App Gateway / Front Door
        - Data protection: unencrypted storage accounts (HTTP-only), storage accounts
          without soft delete, Key Vaults without soft delete / purge protection
        - Resource exposure: public IP count, unattached public IPs, VMs without disk encryption

    Optional live compliance state (-IncludeDetailedFindings switch):
        - Per-recommendation resource detail (resource name, state, remediation description)
        - If Defender API calls fail or lack permissions, the section is marked
          "Not Assessed / Warning" and the assessment continues without interruption

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and colour-coded per-subscription console output
        - Optional CSV export of all findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable tables,
          risk-rated findings, control coverage panels, detail drawer)
        - Risk scoring: each control domain is scored High/Medium/Low/OK based on
          severity and breadth of findings
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan.

.PARAMETER IncludeDetailedFindings
    Switch. When specified, retrieves per-resource finding details from
    Microsoft Defender for Cloud recommendations. Disabled by default for
    performance. If the call fails, the detail is marked "Not Assessed / Warning"
    and the scan continues.

.PARAMETER ExportToCsv
    Switch. Exports all security findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzureSecurityPosture-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Generate-AzureSecurityPostureDashboard -AllSubscriptions

.EXAMPLE
    Generate-AzureSecurityPostureDashboard -AllSubscriptions -IncludeDetailedFindings

.EXAMPLE
    Generate-AzureSecurityPostureDashboard -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Generate-AzureSecurityPostureDashboard -AllSubscriptions -IncludeDetailedFindings -ExportToCsv -CsvPath "C:\Reports\SecurityPosture.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (22-Aug-2026) - Initial release. Defender plan coverage, secure score,
                            recommendation severity distribution, identity exposure,
                            network exposure, data protection posture, resource
                            exposure, and per-subscription risk scoring. Optional
                            detailed findings via -IncludeDetailedFindings.
                            CSV export and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell modules: Az.Accounts, Az.Security, Az.Network,
           Az.Compute, Az.Storage, Az.KeyVault, Az.Resources
           — installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level.
        4. Microsoft.Security/assessments/read is required to retrieve
           Defender for Cloud recommendations.
        5. Microsoft.Security/securescores/read for Secure Score data.
        6. Microsoft.Security/pricings/read for Defender plan coverage.
        7. For -IncludeDetailedFindings: Microsoft.Security/assessments/subassessments/read
           (Security Reader or Security Admin at subscription scope).

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Secure Score and MDfC recommendation APIs require the subscription to
          have Defender for Cloud enabled at minimum (free tier). Subscriptions
          without any Defender plan will return limited data; these are flagged.
        - Per-user MFA state detection relies on the legacy per-user MFA property
          (msds-cloudExtensionAttribute1) visible via Az.Resources; Conditional
          Access-based MFA cannot be evaluated without Microsoft.Graph permissions.
        - Guest account staleness threshold is 90 days (last sign-in date); requires
          AzureAD or Microsoft.Graph read access — the script falls back gracefully
          if this data is unavailable.
        - Network exposure checks cover VMs with public IPs and NSG rules; Private
          Endpoint and Azure Firewall-based controls are not evaluated in v1.0.
        - Disk encryption detection checks OS disk encryption settings; data disk
          encryption is evaluated separately.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Interactive Grid View requires a GUI-capable session; skipped gracefully
          in headless/CI/Linux sessions.

.LINK
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction
    https://learn.microsoft.com/en-us/powershell/module/az.security/
    https://learn.microsoft.com/en-us/azure/security/fundamentals/security-benchmark

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
    Write-CenteredText "Azure Security Posture Dashboard v1.0" -Color White
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
        Write-Host $key.PadRight(30) -NoNewline -ForegroundColor Gray
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

Function Write-RiskBreakdown {
    param([hashtable]$RiskCounts)

    if ($RiskCounts.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Risk Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $colorMap = @{ "High" = "Red"; "Medium" = "Yellow"; "Low" = "Cyan"; "OK" = "Green" }

    foreach ($level in @("High", "Medium", "Low", "OK")) {
        if ($RiskCounts.ContainsKey($level)) {
            $color = if ($colorMap.ContainsKey($level)) { $colorMap[$level] } else { "White" }
            Write-Host "  " -NoNewline
            Write-Host $level.PadRight(22) -NoNewline -ForegroundColor White
            Write-Host ": " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($RiskCounts[$level]) finding(s)" -ForegroundColor $color
        }
    }
}

Function Write-DefenderCoverage {
    param([array]$Plans)

    if ($Plans.Count -eq 0) { return }

    $enabled = @($Plans | Where-Object { $_.PricingTier -eq "Standard" }).Count
    $disabled = @($Plans | Where-Object { $_.PricingTier -ne "Standard" }).Count

    Write-Host ""
    Write-Host "  Defender for Cloud Coverage" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Plans Enabled (Standard)  : $enabled" -ForegroundColor Green
    Write-Host "  Plans Disabled/Free       : $disabled" -ForegroundColor Yellow
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

Function Get-RiskLevel {
    param(
        [int]$HighCount,
        [int]$MediumCount,
        [int]$LowCount
    )
    if ($HighCount -gt 0) { return "High" }
    if ($MediumCount -gt 0) { return "Medium" }
    if ($LowCount -gt 0) { return "Low" }
    return "OK"
}

Function Get-SecureScorePct {
    param([double]$Current, [double]$Max)
    if ($Max -le 0) { return 0 }
    return [math]::Round(($Current / $Max) * 100, 1)
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-SecurityPostureHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$DefenderPlans,
        [array]$Recommendations,
        [array]$SubscriptionResults,
        [hashtable]$RiskSummary,
        [hashtable]$ScoreData,
        [string]$GeneratedOn,
        [bool]$DetailedFindingsIncluded
    )

    # ── Aggregate KPIs ────────────────────────────────────────────────────────
    $totalFindings = @($Findings).Count
    $highFindings = @($Findings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumFindings = @($Findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $lowFindings = @($Findings | Where-Object { $_.RiskLevel -eq "Low" }).Count

    $plansEnabled = @($DefenderPlans | Where-Object { $_.PricingTier -eq "Standard" }).Count
    $plansDisabled = @($DefenderPlans | Where-Object { $_.PricingTier -ne "Standard" }).Count
    $totalPlans = $DefenderPlans.Count

    $avgScore = 0
    if ($ScoreData -and $ScoreData.MaxScore -gt 0) {
        $avgScore = Get-SecureScorePct -Current $ScoreData.CurrentScore -Max $ScoreData.MaxScore
    }

    $detailBadge = if ($DetailedFindingsIncluded) {
        '<span class="badge badge-green">✓ Included</span>'
    }
    else {
        '<span class="badge badge-amber">⚠ Skipped (use -IncludeDetailedFindings)</span>'
    }
    $detailText = if ($DetailedFindingsIncluded) { "Included" } else { "Skipped — use -IncludeDetailedFindings to enable" }

    # ── Defender plan coverage bars ───────────────────────────────────────────
    $planRows = ""
    $planTotal = [math]::Max($DefenderPlans.Count, 1)
    $planColors = @{ "Standard" = "var(--green)"; "Free" = "var(--amber)"; "Disabled" = "var(--red)" }

    foreach ($p in ($DefenderPlans | Sort-Object ResourceType)) {
        $tier = if ($p.PricingTier) { $p.PricingTier } else { "Unknown" }
        $barColor = if ($planColors.ContainsKey($tier)) { $planColors[$tier] } else { "var(--muted)" }
        $pct = if ($tier -eq "Standard") { 100 } else { 0 }
        $badgeCls = if ($tier -eq "Standard") { "badge-green" } else { "badge-amber" }
        $planRows += @"
          <div class="bar-row">
            <span class="bar-label" title="$(EscHtml $p.ResourceType)">$(if ($p.ResourceType.Length -gt 18) { EscHtml($p.ResourceType.Substring(0,15)+"...") } else { EscHtml $p.ResourceType })</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct"><span class="badge $badgeCls">$tier</span></span>
          </div>
"@
    }

    # ── Risk domain distribution bars ─────────────────────────────────────────
    $domainGroups = $Findings | Group-Object -Property Domain | Sort-Object Count -Descending
    $domainRows = ""
    $domainTotal = [math]::Max(($domainGroups | Measure-Object -Property Count -Sum).Sum, 1)

    foreach ($dg in $domainGroups) {
        $pct = [math]::Round(($dg.Count / $domainTotal) * 100)
        $topRisk = ($dg.Group | Sort-Object @{E = { switch ($_.RiskLevel) { "High" { 0 }; "Medium" { 1 }; "Low" { 2 }; default { 3 } } } } | Select-Object -First 1).RiskLevel
        $barColor = switch ($topRisk) { "High" { "var(--red)" }; "Medium" { "var(--amber)" }; "Low" { "var(--accent2)" }; default { "var(--green)" } }
        $domainRows += @"
          <div class="bar-row">
            <span class="bar-label" title="$(EscHtml $dg.Name)">$(if ($dg.Name.Length -gt 18) { EscHtml($dg.Name.Substring(0,15)+"...") } else { EscHtml $dg.Name })</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($dg.Count) ($pct%)</span>
          </div>
"@
    }

    # ── Severity distribution for recommendations ─────────────────────────────
    $recHigh = @($Recommendations | Where-Object { $_.Severity -eq "High" }).Count
    $recMedium = @($Recommendations | Where-Object { $_.Severity -eq "Medium" }).Count
    $recLow = @($Recommendations | Where-Object { $_.Severity -eq "Low" }).Count
    $recTotal = @($Recommendations).Count

    $recRows = ""
    foreach ($r in ($Recommendations | Sort-Object @{E = { switch ($_.Severity) { "High" { 0 }; "Medium" { 1 }; default { 2 } } } } | Select-Object -First 50)) {
        $sevCls = switch ($r.Severity) { "High" { "badge-red" }; "Medium" { "badge-amber" }; default { "badge-blue" } }
        $statCls = switch ($r.State) { "Unhealthy" { "badge-red" }; "Healthy" { "badge-green" }; default { "badge-amber" } }
        $recRows += @"
          <tr onclick="showRecDetail($(($Recommendations.IndexOf($r))))">
            <td title="$(EscHtml $r.DisplayName)">$(if ($r.DisplayName.Length -gt 52) { EscHtml($r.DisplayName.Substring(0,49)+"...") } else { EscHtml $r.DisplayName })</td>
            <td>$(EscHtml $r.SubscriptionName)</td>
            <td><span class="badge $sevCls">$(EscHtml $r.Severity)</span></td>
            <td><span class="badge $statCls">$(EscHtml $r.State)</span></td>
            <td style="font-family:var(--mono);font-size:11px">$($r.AffectedResources)</td>
            <td>$(EscHtml $r.Domain)</td>
          </tr>
"@
    }

    # ── Findings table rows ───────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $riskCls = switch ($f.RiskLevel) { "High" { "badge-red" }; "Medium" { "badge-amber" }; "Low" { "badge-blue" }; default { "badge-green" } }
        $findingRows += @"
          <tr onclick="showFindingDetail($(([array]$Findings).IndexOf($f)))">
            <td>$(EscHtml $f.Domain)</td>
            <td title="$(EscHtml $f.Finding)">$(if ($f.Finding.Length -gt 55) { EscHtml($f.Finding.Substring(0,52)+"...") } else { EscHtml $f.Finding })</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td><span class="badge $riskCls">$(EscHtml $f.RiskLevel)</span></td>
            <td style="font-family:var(--mono);font-size:11px">$($f.AffectedCount)</td>
            <td title="$(EscHtml $f.Remediation)">$(if ($f.Remediation.Length -gt 55) { EscHtml($f.Remediation.Substring(0,52)+"...") } else { EscHtml $f.Remediation })</td>
          </tr>
"@
    }

    # ── Subscription scan rows ────────────────────────────────────────────────
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

    # ── JSON for findings detail drawer ───────────────────────────────────────
    $findJson = "["
    foreach ($f in $Findings) {
        $findJson += "{" +
        """domain"":""$(EscJ $f.Domain)""," +
        """finding"":""$(EscJ $f.Finding)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """risk"":""$(EscJ $f.RiskLevel)""," +
        """count"":$($f.AffectedCount)," +
        """remediation"":""$(EscJ $f.Remediation)""," +
        """detail"":""$(EscJ $f.Detail)""" +
        "},"
    }
    $findJson = $findJson.TrimEnd(",") + "]"

    # ── JSON for recommendations drawer ──────────────────────────────────────
    $recJson = "["
    foreach ($r in $Recommendations) {
        $recJson += "{" +
        """name"":""$(EscJ $r.DisplayName)""," +
        """sub"":""$(EscJ $r.SubscriptionName)""," +
        """severity"":""$(EscJ $r.Severity)""," +
        """state"":""$(EscJ $r.State)""," +
        """affected"":$($r.AffectedResources)," +
        """domain"":""$(EscJ $r.Domain)""," +
        """description"":""$(EscJ $r.Description)""," +
        """remediation"":""$(EscJ $r.RemediationDescription)""" +
        "},"
    }
    $recJson = $recJson.TrimEnd(",") + "]"

    # ── Score ring math ───────────────────────────────────────────────────────
    $scoreCircumference = 283  # 2 * pi * 45
    $scoreDash = if ($avgScore -gt 0) { [math]::Round($scoreCircumference * ($avgScore / 100), 1) } else { 0 }
    $scoreColor = if ($avgScore -ge 70) { "var(--green)" } elseif ($avgScore -ge 40) { "var(--amber)" } else { "var(--red)" }

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Security Posture Dashboard</title>
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
  background:linear-gradient(135deg,var(--red),var(--accent3));
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
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:110px;text-align:right;flex-shrink:0;}
.score-wrap{display:flex;align-items:center;gap:32px;flex-wrap:wrap;margin-bottom:8px;}
.score-ring-wrap{position:relative;width:130px;height:130px;flex-shrink:0;}
.score-ring-wrap svg{transform:rotate(-90deg);}
.score-ring-bg{fill:none;stroke:var(--surface3);stroke-width:12;}
.score-ring-fill{fill:none;stroke-width:12;stroke-linecap:round;transition:stroke-dashoffset 1s ease;}
.score-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.score-pct{font-size:26px;font-weight:700;font-family:var(--mono);line-height:1;}
.score-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:2px;}
.score-details{flex:1;}
.score-detail-row{display:flex;justify-content:space-between;font-size:13px;padding:5px 0;border-bottom:1px solid var(--border);}
.score-detail-row:last-child{border-bottom:none;}
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
.detail-banner{
  padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:16px;
  display:flex;align-items:center;gap:10px;font-size:13px;
}
.detail-banner.included{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.3);color:var(--green);}
.detail-banner.skipped{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3);color:var(--amber);}
.risk-banner{
  padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:18px;
  display:flex;align-items:center;gap:14px;flex-wrap:wrap;
}
.risk-banner.risk-high{background:rgba(248,81,73,.08);border-color:rgba(248,81,73,.3);}
.risk-banner.risk-medium{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3);}
.risk-banner.risk-low{background:rgba(56,139,253,.08);border-color:rgba(56,139,253,.3);}
.risk-banner.risk-ok{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.3);}
.risk-pill{padding:4px 12px;border-radius:20px;font-size:12px;font-weight:700;}
.risk-pill.High{background:var(--red);color:#fff;}
.risk-pill.Medium{background:var(--amber);color:#fff;}
.risk-pill.Low{background:var(--accent);color:#fff;}
.risk-pill.OK{background:var(--green);color:#fff;}
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
  position:fixed;right:0;top:0;bottom:0;width:460px;max-width:95vw;
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
.remediation-box{background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:var(--radius-sm);padding:12px 14px;font-size:12px;line-height:1.6;color:var(--muted2);}
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
  .score-wrap{flex-direction:column;align-items:flex-start;}
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
    <div class="logo-title">Security Posture</div>
    <div class="logo-sub">Azure Security Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">⚠️</span> Findings</button>
    <button class="nav-btn" onclick="showPage('recommendations',this)"><span class="nav-icon">📋</span> Recommendations</button>
    <button class="nav-btn" onclick="showPage('defender',this)"><span class="nav-icon">🔒</span> Defender Plans</button>
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
      Azure Security Posture Dashboard
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Security Posture Overview</div>
      <div class="page-sub">Aggregated security findings and risk posture across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__HIGH_FINDINGS__</div>
        <div class="stat-label">High Risk Findings</div>
        <div class="stat-sub">Require immediate action</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MEDIUM_FINDINGS__</div>
        <div class="stat-label">Medium Risk Findings</div>
        <div class="stat-sub">Address within 30 days</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__LOW_FINDINGS__</div>
        <div class="stat-label">Low Risk Findings</div>
        <div class="stat-sub">Plan for remediation</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__PLANS_ENABLED__</div>
        <div class="stat-label">Defender Plans On</div>
        <div class="stat-sub">of __TOTAL_PLANS__ total plans</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__PLANS_DISABLED__</div>
        <div class="stat-label">Defender Plans Off</div>
        <div class="stat-sub">Coverage gaps present</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__REC_TOTAL__</div>
        <div class="stat-label">Recommendations</div>
        <div class="stat-sub">__REC_HIGH__ high · __REC_MEDIUM__ medium</div>
      </div>
    </div>

    <!-- Secure Score Ring -->
    <div class="panel">
      <div class="panel-title">🎯 Secure Score</div>
      <div class="score-wrap">
        <div class="score-ring-wrap">
          <svg width="130" height="130" viewBox="0 0 130 130">
            <circle class="score-ring-bg" cx="65" cy="65" r="45"/>
            <circle class="score-ring-fill" cx="65" cy="65" r="45"
              stroke="__SCORE_COLOR__"
              stroke-dasharray="__SCORE_DASH__ __SCORE_CIRC__"
              stroke-dashoffset="0"/>
          </svg>
          <div class="score-center">
            <div class="score-pct" style="color:__SCORE_COLOR__">__SCORE_PCT__%</div>
            <div class="score-label">Secure Score</div>
          </div>
        </div>
        <div class="score-details">
          <div class="score-detail-row"><span style="color:var(--muted)">Current Score</span><span style="font-family:var(--mono)">__SCORE_CURRENT__</span></div>
          <div class="score-detail-row"><span style="color:var(--muted)">Maximum Score</span><span style="font-family:var(--mono)">__SCORE_MAX__</span></div>
          <div class="score-detail-row"><span style="color:var(--muted)">Total Findings</span><span style="font-family:var(--mono)">__TOTAL_FINDINGS__</span></div>
          <div class="score-detail-row"><span style="color:var(--muted)">Total Recommendations</span><span style="font-family:var(--mono)">__REC_TOTAL__</span></div>
          <div class="score-detail-row"><span style="color:var(--muted)">Subscriptions Scanned</span><span style="font-family:var(--mono)">__SUB_COUNT__</span></div>
        </div>
      </div>
    </div>

    <div class="detail-banner __DETAIL_BANNER_CLS__">
      <span>📋</span>
      <span><strong>Detailed Findings:</strong> __DETAIL_TEXT__</span>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🔒 Defender for Cloud Plan Coverage</div>
        __PLAN_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">⚠️ Risk by Security Domain</div>
        __DOMAIN_ROWS__
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">📊 Recommendation Severity Breakdown</div>
      <div class="stats-grid" style="margin-bottom:0;">
        <div class="stat-card c-red"><div class="stat-num">__REC_HIGH__</div><div class="stat-label">High Severity</div></div>
        <div class="stat-card c-amber"><div class="stat-num">__REC_MEDIUM__</div><div class="stat-label">Medium Severity</div></div>
        <div class="stat-card c-blue"><div class="stat-num">__REC_LOW__</div><div class="stat-label">Low Severity</div></div>
        <div class="stat-card" style="border-top-color:var(--muted)"><div class="stat-num">__REC_TOTAL__</div><div class="stat-label">Total</div></div>
      </div>
    </div>
  </div>

  <!-- Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Security Findings</div>
      <div class="page-sub">Risk-rated findings across Identity, Network, Data Protection, and Resource Exposure domains. Click any row for remediation guidance.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search finding, domain, subscription…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterRisk" onchange="filterFindings()">
          <option value="">All Risk Levels</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="OK">OK / Passed</option>
        </select>
        <select class="filter-select" id="filterDomain" onchange="filterFindings()">
          <option value="">All Domains</option>
          <option value="Identity">Identity</option>
          <option value="Network">Network</option>
          <option value="Data Protection">Data Protection</option>
          <option value="Resource Exposure">Resource Exposure</option>
          <option value="Encryption">Encryption</option>
        </select>
        <select class="filter-select" id="pgSizeFindings" onchange="changeFindingsPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="findTable">
          <thead>
            <tr>
              <th onclick="sortFindings(0)">Domain</th>
              <th onclick="sortFindings(1)">Finding</th>
              <th onclick="sortFindings(2)">Subscription</th>
              <th onclick="sortFindings(3)">Risk Level</th>
              <th onclick="sortFindings(4)">Affected Resources</th>
              <th>Remediation (Summary)</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- Recommendations -->
  <div id="page-recommendations" class="page">
    <div class="page-header">
      <div class="page-title">Defender for Cloud Recommendations</div>
      <div class="page-sub">Live recommendations from Microsoft Defender for Cloud. Click any row for full detail and remediation steps.</div>
    </div>
    <div class="detail-banner __DETAIL_BANNER_CLS__">
      <span>📋</span>
      <span><strong>Detailed Findings:</strong> __DETAIL_TEXT__</span>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="recSearch" placeholder="Search recommendation, subscription…" oninput="filterRecs()"/>
        </div>
        <select class="filter-select" id="filterRecSev" onchange="filterRecs()">
          <option value="">All Severities</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="filterRecState" onchange="filterRecs()">
          <option value="">All States</option>
          <option value="Unhealthy">Unhealthy</option>
          <option value="Healthy">Healthy</option>
          <option value="NotApplicable">Not Applicable</option>
        </select>
        <select class="filter-select" id="pgSizeRecs" onchange="changeRecsPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="recTable">
          <thead>
            <tr>
              <th onclick="sortRecs(0)">Recommendation</th>
              <th onclick="sortRecs(1)">Subscription</th>
              <th onclick="sortRecs(2)">Severity</th>
              <th onclick="sortRecs(3)">State</th>
              <th onclick="sortRecs(4)">Affected Resources</th>
              <th onclick="sortRecs(5)">Domain</th>
            </tr>
          </thead>
          <tbody id="recBody">__REC_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="recPagination"></div>
    </div>
  </div>

  <!-- Defender Plans -->
  <div id="page-defender" class="page">
    <div class="page-header">
      <div class="page-title">Defender for Cloud Plans</div>
      <div class="page-sub">Plan coverage directly determines which attack surfaces are monitored and protected</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-green">
        <div class="stat-num">__PLANS_ENABLED__</div>
        <div class="stat-label">Plans Enabled</div>
        <div class="stat-sub">Standard tier active</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__PLANS_DISABLED__</div>
        <div class="stat-label">Plans Disabled / Free</div>
        <div class="stat-sub">Reduced protection</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_PLANS__</div>
        <div class="stat-label">Total Plans Assessed</div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">🔒 Plan-by-Plan Coverage</div>
      __PLAN_ROWS_FULL__
    </div>
    <div class="panel" style="border-left:3px solid var(--amber);">
      <div class="panel-title">⚠️ Business Risk — Disabled Plans</div>
      <p style="font-size:13px;color:var(--muted2);line-height:1.7;">
        Each disabled plan removes an entire detection and response capability from your security perimeter.
        <strong style="color:var(--text)">Defender for Servers</strong> disables just-in-time VM access and adaptive application controls.
        <strong style="color:var(--text)">Defender for Storage</strong> removes malware scanning and sensitive data threat detection.
        <strong style="color:var(--text)">Defender for Key Vault</strong> leaves secret exfiltration and unusual access patterns undetected.
        Review disabled plans and prioritise enablement in proportion to your organisation's risk appetite.
      </p>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription security assessment outcome</div>
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
        <div class="info-card"><div class="info-label">Detailed Findings</div><div class="info-value">__DETAIL_TEXT__</div></div>
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
    <span class="drawer-title" id="drawerTitle">Detail</span>
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
const REC_DATA  = __REC_JSON__;

let findFiltered = [...FIND_DATA];
let findPage = 1, findPageSz = 25;
let findSortCol = -1, findSortAsc = true;

let recFiltered = [...REC_DATA];
let recPage = 1, recPageSz = 25;
let recSortCol = -1, recSortAsc = true;

let currentDetailMode = 'finding';
let currentDetailIdx  = 0;

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
}

function toggleTheme(){
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme==='dark'?'light':'dark';
}

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Findings table ────────────────────────────────────────────────────────────
function filterFindings(){
  const q  = document.getElementById('findSearch').value.toLowerCase();
  const rk = document.getElementById('filterRisk').value;
  const dm = document.getElementById('filterDomain').value;
  findFiltered = FIND_DATA.filter(r=>{
    const mQ  = !q  || JSON.stringify(r).toLowerCase().includes(q);
    const mRk = !rk || r.risk===rk;
    const mDm = !dm || r.domain===dm;
    return mQ && mRk && mDm;
  });
  findPage=1; renderFindings();
}

function changeFindingsPageSize(){
  findPageSz=parseInt(document.getElementById('pgSizeFindings').value);
  findPage=1; renderFindings();
}

function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys=['domain','finding','sub','risk','count','remediation'];
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
    const gi   = FIND_DATA.indexOf(r);
    const rCls = r.risk==='High'?'badge-red':r.risk==='Medium'?'badge-amber':r.risk==='Low'?'badge-blue':'badge-green';
    const fn   = r.finding.length>55?r.finding.substring(0,52)+'...':r.finding;
    const rm   = r.remediation.length>55?r.remediation.substring(0,52)+'...':r.remediation;
    return `<tr onclick="showFindingDetail(${gi})">
      <td>${escH(r.domain)}</td>
      <td title="${escH(r.finding)}">${escH(fn)}</td>
      <td>${escH(r.sub)}</td>
      <td><span class="badge ${rCls}">${escH(r.risk)}</span></td>
      <td style="font-family:var(--mono);font-size:11px">${r.count}</td>
      <td title="${escH(r.remediation)}">${escH(rm)}</td>
    </tr>`;
  }).join('');
  renderFindingsPg();
}

function renderFindingsPg(){
  const total = Math.ceil(findFiltered.length/findPageSz);
  const el    = document.getElementById('findPagination');
  let h = `<span>${findFiltered.length} findings</span>`;
  h += `<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,findPage-2), e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeFindPage(p){
  const total=Math.ceil(findFiltered.length/findPageSz);
  if(p<1||p>total)return;
  findPage=p; renderFindings();
}

// ── Recommendations table ─────────────────────────────────────────────────────
function filterRecs(){
  const q  = document.getElementById('recSearch').value.toLowerCase();
  const sv = document.getElementById('filterRecSev').value;
  const st = document.getElementById('filterRecState').value;
  recFiltered = REC_DATA.filter(r=>{
    const mQ  = !q  || JSON.stringify(r).toLowerCase().includes(q);
    const mSv = !sv || r.severity===sv;
    const mSt = !st || r.state===st;
    return mQ && mSv && mSt;
  });
  recPage=1; renderRecs();
}

function changeRecsPageSize(){
  recPageSz=parseInt(document.getElementById('pgSizeRecs').value);
  recPage=1; renderRecs();
}

function sortRecs(col){
  if(recSortCol===col){recSortAsc=!recSortAsc;}else{recSortCol=col;recSortAsc=true;}
  const keys=['name','sub','severity','state','affected','domain'];
  recFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    return recSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                     :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderRecs();
}

function renderRecs(){
  const tbody = document.getElementById('recBody');
  const start = (recPage-1)*recPageSz;
  const slice = recFiltered.slice(start, start+recPageSz);
  tbody.innerHTML = slice.map(r=>{
    const gi    = REC_DATA.indexOf(r);
    const sCls  = r.severity==='High'?'badge-red':r.severity==='Medium'?'badge-amber':'badge-blue';
    const stCls = r.state==='Unhealthy'?'badge-red':r.state==='Healthy'?'badge-green':'badge-amber';
    const nm    = r.name.length>52?r.name.substring(0,49)+'...':r.name;
    return `<tr onclick="showRecDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td><span class="badge ${sCls}">${escH(r.severity)}</span></td>
      <td><span class="badge ${stCls}">${escH(r.state)}</span></td>
      <td style="font-family:var(--mono);font-size:11px">${r.affected}</td>
      <td>${escH(r.domain)}</td>
    </tr>`;
  }).join('');
  renderRecsPg();
}

function renderRecsPg(){
  const total = Math.ceil(recFiltered.length/recPageSz);
  const el    = document.getElementById('recPagination');
  let h = `<span>${recFiltered.length} recommendations</span>`;
  h += `<button class="pg-btn" onclick="changeRecPage(${recPage-1})" ${recPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,recPage-2), e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===recPage?'active':''}" onclick="changeRecPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeRecPage(${recPage+1})" ${recPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeRecPage(p){
  const total=Math.ceil(recFiltered.length/recPageSz);
  if(p<1||p>total)return;
  recPage=p; renderRecs();
}

// ── Detail drawer ─────────────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailMode='finding'; currentDetailIdx=idx;
  const r=FIND_DATA[idx];
  if(!r)return;
  const rCls=r.risk==='High'?'badge-red':r.risk==='Medium'?'badge-amber':r.risk==='Low'?'badge-blue':'badge-green';
  document.getElementById('drawerTitle').textContent=r.finding;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FIND_DATA.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Risk Level</div>
      <div class="drawer-field-value"><span class="badge ${rCls}">${escH(r.risk)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Security Domain</div>
      <div class="drawer-field-value">${escH(r.domain)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Affected Resources</div>
      <div class="drawer-field-value" style="font-family:var(--mono)">${r.count}</div></div>
    <div class="drawer-section">Finding Detail</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.detail||r.finding)}</div></div>
    <div class="drawer-section">Remediation Guidance</div>
    <div class="remediation-box">${escH(r.remediation)}</div>
  `;
  openDrawer();
}

function showRecDetail(idx){
  currentDetailMode='rec'; currentDetailIdx=idx;
  const r=REC_DATA[idx];
  if(!r)return;
  const sCls=r.severity==='High'?'badge-red':r.severity==='Medium'?'badge-amber':'badge-blue';
  const stCls=r.state==='Unhealthy'?'badge-red':r.state==='Healthy'?'badge-green':'badge-amber';
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${REC_DATA.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sCls}">${escH(r.severity)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">State</div>
      <div class="drawer-field-value"><span class="badge ${stCls}">${escH(r.state)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Domain</div>
      <div class="drawer-field-value">${escH(r.domain)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Affected Resources</div>
      <div class="drawer-field-value" style="font-family:var(--mono)">${r.affected}</div></div>
    <div class="drawer-section">Description</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.description)}</div></div>
    <div class="drawer-section">Remediation Steps</div>
    <div class="remediation-box">${escH(r.remediation||'No remediation description available.')}</div>
  `;
  openDrawer();
}

function openDrawer(){
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}

function closeDrawer(){
  document.getElementById('drawerBackdrop').style.display='none';
  document.getElementById('detailDrawer').classList.remove('open');
}

function navDetail(dir){
  if(currentDetailMode==='finding'){
    const next=currentDetailIdx+dir;
    if(next>=0&&next<FIND_DATA.length) showFindingDetail(next);
  } else {
    const next=currentDetailIdx+dir;
    if(next>=0&&next<REC_DATA.length) showRecDetail(next);
  }
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
filterRecs();
animateBars();
</script>
</body>
</html>
'@

    # ── Full plan rows for the Defender Plans page ────────────────────────────
    $planRowsFull = ""
    foreach ($p in ($DefenderPlans | Sort-Object ResourceType)) {
        $tier = if ($p.PricingTier) { $p.PricingTier } else { "Unknown" }
        $pct = if ($tier -eq "Standard") { 100 } else { 0 }
        $badgeCls = if ($tier -eq "Standard") { "badge-green" } else { "badge-amber" }
        $barColor = if ($tier -eq "Standard") { "var(--green)" } else { "var(--amber)" }
        $planRowsFull += @"
          <div class="bar-row">
            <span class="bar-label" style="width:200px" title="$(EscHtml $p.ResourceType)">$(EscHtml $p.ResourceType)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct"><span class="badge $badgeCls">$tier</span></span>
          </div>
"@
    }

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__HIGH_FINDINGS__', $highFindings `
        -replace '__MEDIUM_FINDINGS__', $mediumFindings `
        -replace '__LOW_FINDINGS__', $lowFindings `
        -replace '__TOTAL_FINDINGS__', $totalFindings `
        -replace '__PLANS_ENABLED__', $plansEnabled `
        -replace '__PLANS_DISABLED__', $plansDisabled `
        -replace '__TOTAL_PLANS__', $totalPlans `
        -replace '__REC_HIGH__', $recHigh `
        -replace '__REC_MEDIUM__', $recMedium `
        -replace '__REC_LOW__', $recLow `
        -replace '__REC_TOTAL__', $recTotal `
        -replace '__SCORE_PCT__', $avgScore `
        -replace '__SCORE_CURRENT__', $ScoreData.CurrentScore `
        -replace '__SCORE_MAX__', $ScoreData.MaxScore `
        -replace '__SCORE_COLOR__', $scoreColor `
        -replace '__SCORE_DASH__', $scoreDash `
        -replace '__SCORE_CIRC__', $scoreCircumference `
        -replace '__DETAIL_BANNER_CLS__', $(if ($DetailedFindingsIncluded) { "included" } else { "skipped" }) `
        -replace '__DETAIL_TEXT__', $detailText `
        -replace '__PLAN_ROWS__', $planRows `
        -replace '__PLAN_ROWS_FULL__', $planRowsFull `
        -replace '__DOMAIN_ROWS__', $domainRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__REC_ROWS__', $recRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FIND_JSON__', $findJson `
        -replace '__REC_JSON__', $recJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Generate-AzureSecurityPostureDashboard {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$IncludeDetailedFindings,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureSecurityPosture-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts",
        "Az.Security",
        "Az.Network",
        "Az.Compute",
        "Az.Storage",
        "Az.KeyVault",
        "Az.Resources"
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
        "Scope"             = "$scopeText ($subCount found)"
        "Detailed Findings" = if ($IncludeDetailedFindings) { "Enabled (per-resource detail will be retrieved)" } else { "Skipped (use -IncludeDetailedFindings to enable)" }
        "Export to CSV"     = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"       = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $allDefenderPlans = @()
    $allRecommendations = @()
    $subscriptionResults = @()
    $riskCounts = @{ "High" = 0; "Medium" = 0; "Low" = 0; "OK" = 0 }
    $aggregateScore = @{ CurrentScore = 0.0; MaxScore = 0.0 }
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

            $subFindings = 0
            $subHighCount = 0
            $subMediumCount = 0

            # ── Defender for Cloud Plan Coverage ──────────────────────────────
            try {
                $plans = @(Get-AzSecurityPricing -ErrorAction Stop)
                foreach ($plan in $plans) {
                    $allDefenderPlans += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        ResourceType     = $plan.Name
                        PricingTier      = $plan.PricingTier
                    }
                }

                $disabledPlans = @($plans | Where-Object { $_.PricingTier -ne "Standard" })
                if ($disabledPlans.Count -gt 0) {
                    $riskLvl = if ($disabledPlans.Count -ge 5) { "High" } elseif ($disabledPlans.Count -ge 2) { "Medium" } else { "Low" }
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Defender Coverage"
                        Finding          = "$($disabledPlans.Count) Defender plan(s) not enabled at Standard tier"
                        RiskLevel        = $riskLvl
                        AffectedCount    = $disabledPlans.Count
                        Remediation      = "Enable Defender for Cloud Standard tier on: $( ($disabledPlans | Select-Object -ExpandProperty Name) -join ', ' ). Navigate to Defender for Cloud > Environment Settings to upgrade each plan."
                        Detail           = "Disabled plans: $( ($disabledPlans | Select-Object -ExpandProperty Name) -join ', ' ). Without Standard tier, threat detection, security alerts, and advanced hardening recommendations are unavailable for those resource types."
                    }
                    $subFindings++
                    if ($riskLvl -eq "High") { $subHighCount++ }
                    elseif ($riskLvl -eq "Medium") { $subMediumCount++ }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Defender plans for $($sub.Name): $_"
            }

            # ── Secure Score ──────────────────────────────────────────────────
            try {
                $scores = @(Get-AzSecuritySecureScore -ErrorAction Stop)
                foreach ($sc in $scores) {
                    $curSc = 0.0
                    $maxSc = 0.0
                    try { $curSc = [double]$sc.Score.Current } catch { }
                    try { $maxSc = [double]$sc.Score.Max } catch { }
                    $aggregateScore.CurrentScore += $curSc
                    $aggregateScore.MaxScore += $maxSc
                }
                $scorePct = Get-SecureScorePct -Current $aggregateScore.CurrentScore -Max $aggregateScore.MaxScore
                if ($scorePct -lt 50 -and $aggregateScore.MaxScore -gt 0) {
                    $riskLvl = if ($scorePct -lt 30) { "High" } else { "Medium" }
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Secure Score"
                        Finding          = "Secure Score is $scorePct% — below acceptable threshold"
                        RiskLevel        = $riskLvl
                        AffectedCount    = 1
                        Remediation      = "Review and remediate high-severity Defender for Cloud recommendations to increase the Secure Score. Target ≥70% as a minimum enterprise baseline."
                        Detail           = "Current: $curSc / $maxSc ($scorePct%). A score below 50% indicates a large volume of unresolved security controls across the subscription."
                    }
                    $subFindings++
                    if ($riskLvl -eq "High") { $subHighCount++ }
                    elseif ($riskLvl -eq "Medium") { $subMediumCount++ }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Secure Score for $($sub.Name): $_"
            }

            # ── MDfC Recommendations ──────────────────────────────────────────
            try {
                $assessments = @(Get-AzSecurityAssessment -ErrorAction Stop)
                $domainMap = @{
                    "identity"  = "Identity"
                    "network"   = "Network"
                    "data"      = "Data Protection"
                    "storage"   = "Data Protection"
                    "keyvault"  = "Data Protection"
                    "compute"   = "Resource Exposure"
                    "vm"        = "Resource Exposure"
                    "container" = "Resource Exposure"
                    "encrypt"   = "Encryption"
                }

                foreach ($assess in $assessments) {
                    $dispName = if ($assess.DisplayName) { $assess.DisplayName } else { "Unknown" }
                    $sevStr = "Low"
                    $stateStr = "Unknown"
                    $affectedRes = 0
                    $descStr = ""
                    $remediStr = ""

                    try { $sevStr = if ($assess.Metadata.Severity) { $assess.Metadata.Severity }      else { "Low" } }    catch { }
                    try { $stateStr = if ($assess.StatusCode) { $assess.StatusCode }             else { "Unknown" } } catch { }
                    try { $descStr = if ($assess.Metadata.Description) { $assess.Metadata.Description }   else { "" } }       catch { }
                    try { $remediStr = if ($assess.Metadata.RemediationDescription) { $assess.Metadata.RemediationDescription } else { "" } } catch { }

                    # Domain inference from name
                    $inferredDomain = "General"
                    foreach ($kw in $domainMap.Keys) {
                        if ($dispName -match $kw) {
                            $inferredDomain = $domainMap[$kw]
                            break
                        }
                    }

                    $allRecommendations += [pscustomobject]@{
                        SubscriptionName       = $sub.Name
                        SubscriptionId         = $sub.Id
                        DisplayName            = $dispName
                        Severity               = $sevStr
                        State                  = if ($stateStr -eq "Unhealthy") { "Unhealthy" } elseif ($stateStr -eq "Healthy") { "Healthy" } else { "NotApplicable" }
                        AffectedResources      = $affectedRes
                        Domain                 = $inferredDomain
                        Description            = $descStr
                        RemediationDescription = $remediStr
                    }
                }

                $unhealthyHigh = @($assessments | Where-Object {
                        (Get-ObjProperty -Obj $_ -PropName 'StatusCode' -Default "") -eq "Unhealthy" -and
                        (Get-ObjProperty -Obj (Get-ObjProperty -Obj $_ -PropName 'Metadata' -Default $null) -PropName 'Severity' -Default "") -eq "High"
                    }).Count

                if ($unhealthyHigh -gt 0) {
                    $riskLvl = if ($unhealthyHigh -ge 10) { "High" } elseif ($unhealthyHigh -ge 3) { "Medium" } else { "Low" }
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Defender Coverage"
                        Finding          = "$unhealthyHigh high-severity Defender recommendation(s) are Unhealthy"
                        RiskLevel        = $riskLvl
                        AffectedCount    = $unhealthyHigh
                        Remediation      = "Navigate to Defender for Cloud > Recommendations and filter by High severity / Unhealthy state. Remediate each finding in priority order."
                        Detail           = "Microsoft Defender for Cloud has flagged $unhealthyHigh high-severity controls as Unhealthy in this subscription. Each represents an exploitable gap against the Azure Security Benchmark."
                    }
                    $subFindings++
                    if ($riskLvl -eq "High") { $subHighCount++ }
                    elseif ($riskLvl -eq "Medium") { $subMediumCount++ }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve MDfC recommendations for $($sub.Name): $_"
            }

            # ── Network Exposure ──────────────────────────────────────────────
            try {
                # Public IP inventory
                $publicIPs = @(Get-AzPublicIpAddress -ErrorAction Stop)
                $unattached = @($publicIPs | Where-Object { -not $_.IpConfiguration })

                if ($publicIPs.Count -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Network"
                        Finding          = "$($publicIPs.Count) public IP address(es) found ($($unattached.Count) unattached)"
                        RiskLevel        = if ($publicIPs.Count -gt 50) { "High" } elseif ($publicIPs.Count -gt 10) { "Medium" } else { "Low" }
                        AffectedCount    = $publicIPs.Count
                        Remediation      = "Review all public IPs. Remove or associate unattached public IPs (cost and attack surface). Ensure each public IP is fronted by WAF, DDoS protection, or Azure Firewall appropriate to its exposure."
                        Detail           = "Total public IPs: $($publicIPs.Count). Unattached (orphaned, still billable and a naming/inventory risk): $($unattached.Count)."
                    }
                    $subFindings++
                    if ($publicIPs.Count -gt 50) { $subHighCount++ }
                    elseif ($publicIPs.Count -gt 10) { $subMediumCount++ }
                }

                # NSG analysis — subnets without NSG
                $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop)
                $nsglessSubnets = 0
                foreach ($vnet in $vnets) {
                    foreach ($subnet in $vnet.Subnets) {
                        if (-not $subnet.NetworkSecurityGroup -and $subnet.Name -ne "AzureBastionSubnet" -and $subnet.Name -ne "GatewaySubnet" -and $subnet.Name -ne "AzureFirewallSubnet") {
                            $nsglessSubnets++
                        }
                    }
                }

                if ($nsglessSubnets -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Network"
                        Finding          = "$nsglessSubnets subnet(s) have no Network Security Group attached"
                        RiskLevel        = if ($nsglessSubnets -ge 5) { "High" } elseif ($nsglessSubnets -ge 2) { "Medium" } else { "Low" }
                        AffectedCount    = $nsglessSubnets
                        Remediation      = "Attach NSGs to all non-infrastructure subnets. Define inbound/outbound rules aligned to the principle of least privilege. Use Azure Policy to enforce NSG attachment at subnet creation."
                        Detail           = "$nsglessSubnets subnet(s) across all VNets in this subscription lack an NSG. Any resource placed in these subnets is unrestricted at the network layer."
                    }
                    $subFindings++
                    if ($nsglessSubnets -ge 5) { $subHighCount++ }
                    elseif ($nsglessSubnets -ge 2) { $subMediumCount++ }
                }

                # Open management ports on NSG rules
                $dangerousPorts = @("22", "3389", "5985", "5986", "1433", "3306", "5432")
                $openMgmtCount = 0
                $nsgs = @(Get-AzNetworkSecurityGroup -ErrorAction Stop)
                foreach ($nsg in $nsgs) {
                    foreach ($rule in $nsg.SecurityRules) {
                        if ($rule.Direction -eq "Inbound" -and $rule.Access -eq "Allow" -and $rule.SourceAddressPrefix -in @("*", "Internet", "0.0.0.0/0")) {
                            $portRange = "$($rule.DestinationPortRange)"
                            foreach ($dp in $dangerousPorts) {
                                if ($portRange -eq $dp -or $portRange -eq "*") { $openMgmtCount++; break }
                            }
                        }
                    }
                }

                if ($openMgmtCount -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Network"
                        Finding          = "$openMgmtCount NSG rule(s) allow unrestricted inbound access on management ports"
                        RiskLevel        = "High"
                        AffectedCount    = $openMgmtCount
                        Remediation      = "Restrict NSG rules for SSH (22), RDP (3389), WinRM (5985/5986), and database ports (1433, 3306, 5432) to specific source IP ranges or use Azure Bastion for administrative access. Remove any rule sourced from '*' or 'Internet'."
                        Detail           = "NSG rules with source '*' or 'Internet' permitting inbound traffic to management ports expose resources directly to the public internet. This is a Critical/High finding in every major security framework (CIS, NIST, Azure Benchmark)."
                    }
                    $subFindings++
                    $subHighCount++
                }
            }
            catch {
                Write-Verbose "  Could not complete network exposure checks for $($sub.Name): $_"
            }

            # ── Data Protection & Encryption ──────────────────────────────────
            try {
                $storageAccounts = @(Get-AzStorageAccount -ErrorAction Stop)

                $httpOnlyStorage = @($storageAccounts | Where-Object { $_.EnableHttpsTrafficOnly -eq $false })
                $noSoftDelete = @($storageAccounts | Where-Object { $_.BlobServiceProperties -and $_.BlobServiceProperties.DeleteRetentionPolicy -and $_.BlobServiceProperties.DeleteRetentionPolicy.Enabled -eq $false })

                if ($httpOnlyStorage.Count -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Data Protection"
                        Finding          = "$($httpOnlyStorage.Count) storage account(s) do not enforce HTTPS-only traffic"
                        RiskLevel        = "High"
                        AffectedCount    = $httpOnlyStorage.Count
                        Remediation      = "Enable 'Secure transfer required' on all storage accounts. In Azure Portal: Storage Account > Configuration > Secure transfer required = Enabled. Use Azure Policy [Secure transfer to storage accounts should be enabled] for continuous compliance."
                        Detail           = "Storage accounts permitting HTTP allow data in transit to be intercepted. Affected accounts: $( ($httpOnlyStorage | Select-Object -ExpandProperty StorageAccountName) -join ', ' )."
                    }
                    $subFindings++
                    $subHighCount++
                }
            }
            catch {
                Write-Verbose "  Could not retrieve storage accounts for $($sub.Name): $_"
            }

            # ── Key Vault Protection ──────────────────────────────────────────
            try {
                $keyVaults = @(Get-AzKeyVault -ErrorAction Stop)
                $kvNoSoftDelete = @($keyVaults | Where-Object { $_.EnableSoftDelete -ne $true })
                $kvNoPurge = @($keyVaults | Where-Object { $_.EnablePurgeProtection -ne $true })

                if ($kvNoSoftDelete.Count -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Data Protection"
                        Finding          = "$($kvNoSoftDelete.Count) Key Vault(s) do not have soft delete enabled"
                        RiskLevel        = "High"
                        AffectedCount    = $kvNoSoftDelete.Count
                        Remediation      = "Enable soft delete on all Key Vaults. Soft delete retains deleted objects for a configurable retention period (7–90 days) and is now a permanent feature — once enabled it cannot be disabled. Also enable purge protection to prevent permanent deletion during the retention period."
                        Detail           = "Key Vaults without soft delete risk permanent, unrecoverable loss of keys, secrets, and certificates on accidental or malicious deletion. Affected vaults: $( ($kvNoSoftDelete | Select-Object -ExpandProperty VaultName) -join ', ' )."
                    }
                    $subFindings++
                    $subHighCount++
                }

                if ($kvNoPurge.Count -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Data Protection"
                        Finding          = "$($kvNoPurge.Count) Key Vault(s) do not have purge protection enabled"
                        RiskLevel        = "Medium"
                        AffectedCount    = $kvNoPurge.Count
                        Remediation      = "Enable purge protection (EnablePurgeProtection = true) on all Key Vaults containing production secrets, certificates, or keys. This prevents any principal — including administrators — from permanently purging objects during the soft-delete retention period."
                        Detail           = "Without purge protection, a privileged actor or ransomware can permanently destroy cryptographic material even with soft delete enabled. Affected vaults: $( ($kvNoPurge | Select-Object -ExpandProperty VaultName) -join ', ' )."
                    }
                    $subFindings++
                    $subMediumCount++
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Key Vault properties for $($sub.Name): $_"
            }

            # ── VM Disk Encryption ────────────────────────────────────────────
            try {
                $vms = @(Get-AzVM -ErrorAction Stop)
                $unencrypted = @()
                foreach ($vm in $vms) {
                    $encStatus = $null
                    try {
                        $encStatus = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction Stop
                    }
                    catch { }

                    $osDiskEnc = if ($encStatus) { $encStatus.OsVolumeEncrypted } else { "Unknown" }
                    if ($osDiskEnc -ne "Encrypted" -and $osDiskEnc -ne $true) {
                        $unencrypted += $vm.Name
                    }
                }

                if ($unencrypted.Count -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Encryption"
                        Finding          = "$($unencrypted.Count) VM(s) have OS disk encryption not confirmed"
                        RiskLevel        = if ($unencrypted.Count -ge 5) { "High" } else { "Medium" }
                        AffectedCount    = $unencrypted.Count
                        Remediation      = "Enable Azure Disk Encryption (ADE) using Azure Key Vault for all production VMs. Use the Azure Policy [Disk encryption should be applied on virtual machines] initiative for continuous enforcement. ADE encrypts OS and data disks using BitLocker (Windows) or DM-Crypt (Linux)."
                        Detail           = "VMs without confirmed OS disk encryption: $( ($unencrypted | Select-Object -First 10) -join ', ' )$(if ($unencrypted.Count -gt 10) { ' and more...' })."
                    }
                    $subFindings++
                    if ($unencrypted.Count -ge 5) { $subHighCount++ } else { $subMediumCount++ }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve VM disk encryption status for $($sub.Name): $_"
            }

            # ── Per-subscription risk tallying ────────────────────────────────
            $subFindingsThisSub = @($allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id })
            foreach ($f in $subFindingsThisSub) {
                if ($riskCounts.ContainsKey($f.RiskLevel)) { $riskCounts[$f.RiskLevel]++ }
            }

            # ── Per-subscription result ───────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Findings: $subFindings  High: $subHighCount  Medium: $subMediumCount  DefenderPlans: $($allDefenderPlans | Where-Object { $_.SubscriptionId -eq $sub.Id } | Measure-Object | Select-Object -Expand Count)" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Findings: $subFindings  High: $subHighCount  Medium: $subMediumCount"
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

    $scorePctFinal = Get-SecureScorePct -Current $aggregateScore.CurrentScore -Max $aggregateScore.MaxScore

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned"  = $subCount
            "Successful"                   = $successCount
            "Errors"                       = $errorCount
            "Total Findings"               = $allFindings.Count
            "High Risk Findings"           = $riskCounts["High"]
            "Medium Risk Findings"         = $riskCounts["Medium"]
            "Low Risk Findings"            = $riskCounts["Low"]
            "Total Recommendations (MDfC)" = $allRecommendations.Count
            "Defender Plans Assessed"      = $allDefenderPlans.Count
            "Secure Score"                 = if ($aggregateScore.MaxScore -gt 0) { "$scorePctFinal%" } else { "Not retrieved" }
            "Detailed Findings"            = if ($IncludeDetailedFindings) { "Yes" } else { "No (use -IncludeDetailedFindings)" }
            "Execution Time"               = $duration
        })

    Write-RiskBreakdown    -RiskCounts    $riskCounts
    Write-DefenderCoverage -Plans         $allDefenderPlans

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0 -or $allRecommendations.Count -gt 0) {
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object SubscriptionName, SubscriptionId, Domain, Finding, RiskLevel, AffectedCount, Remediation, Detail |
                Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                if ($allRecommendations.Count -gt 0) {
                    $recCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "Recommendations.csv"
                    $allRecommendations | Select-Object SubscriptionName, DisplayName, Severity, State, AffectedResources, Domain, Description, RemediationDescription |
                    Export-Csv -Path $recCsvPath -NoTypeInformation -Encoding UTF8
                }

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

            $htmlContent = Generate-SecurityPostureHtml `
                -SessionInfo              $sessionInfo `
                -ScanParameters           $scanParams `
                -Findings                 $allFindings `
                -DefenderPlans            $allDefenderPlans `
                -Recommendations          $allRecommendations `
                -SubscriptionResults      $subscriptionResults `
                -RiskSummary              $riskCounts `
                -ScoreData                $aggregateScore `
                -GeneratedOn              (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -DetailedFindingsIncluded $IncludeDetailedFindings.IsPresent

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
            Select-Object SubscriptionName, Domain, Finding, RiskLevel, AffectedCount |
            Out-GridView -Title "Azure Security Posture Dashboard"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No security findings found in the targeted subscriptions." -ForegroundColor Yellow
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
