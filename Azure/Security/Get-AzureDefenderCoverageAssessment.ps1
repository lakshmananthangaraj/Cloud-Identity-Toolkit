<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 19 August 2026
Modified-On     : 19 August 2026

.SYNOPSIS
    Assesses Microsoft Defender for Cloud coverage across subscriptions, workload
    types, and resource tiers — surfacing unprotected resources, plan gaps, and
    security-control weaknesses with risk-rated findings and remediation guidance.

.DESCRIPTION
    Get-AzureDefenderCoverageAssessment evaluates your Microsoft Defender for Cloud
    posture from a Cloud / Solution / Enterprise Architect perspective.

    It answers three strategic questions that a simple portal review cannot:
        1. Where are the protection gaps?  Which workloads, subscriptions, or resource
           types have no Defender plan active — exposing the organisation to undetected
           threats with zero alerting coverage?
        2. How severe are the gaps?  Each finding is risk-rated Critical / High /
           Medium / Low with a plain-English business-impact statement so leadership
           and security teams can prioritise remediation without decoding raw API data.
        3. What should we fix first?  Every finding includes an actionable remediation
           step mapped to the relevant Defender plan, RBAC role, and Microsoft Learn URL.

    Default assessment (per-subscription, fast):
        — Defender plan status per workload (Servers, AppService, Databases, SQL,
          StorageAccounts, Containers, KeyVaults, Arm, Dns, OpenSourceRelationalDatabases,
          CspmTier, DevOps) with Free / Standard / Mixed tiers
        — Unprotected subscriptions (no active paid plan in any workload)
        — Partially protected subscriptions (some paid plans, gaps in others)
        — Sub-plan pricing tier per workload and total estimated monthly exposure
        — Auto-provisioning agent/extension status (MMA, AMA, Qualys, Agentless scanning)
        — Security contact configuration (email, phone, alert notifications)
        — Microsoft Defender for Endpoint integration status
        — MCSB (Microsoft Cloud Security Benchmark) initiative assignment presence

    Risk-rated findings include:
        — Missing Defender plan for workload that is actively deployed (Critical / High)
        — Auto-provisioning disabled while workloads are present (High)
        — No security contact configured (Medium)
        — Defender for CSPM (Defender CSPM tier) not enabled (High)
        — Free-tier SQL or Containers plans on production subscriptions (High)
        — Partial coverage in multi-subscription environments (Medium)

    It supports:
        — Scanning all subscriptions or a specified list via -SubscriptionIds
        — Real-time progress bar and per-subscription colour-coded output
        — Optional CSV export of all findings
        — Always-on interactive HTML dashboard (dark/light theme, sortable table,
          donut charts, risk panel, detail drawer)
        — Interactive Grid View of findings where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan.
    Ignored when -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. Exports all risk-rated findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (.html extension).
    Default: C:\Temp\AzureDefenderCoverage-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureDefenderCoverageAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureDefenderCoverageAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureDefenderCoverageAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\DefenderCoverage.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (19-Aug-2026) - Initial release. Defender plan coverage, auto-provisioning,
                            security contact, CSPM tier, risk-rated findings,
                            CSV export, and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Security)
           — installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Security Reader role (minimum) at subscription scope.
           Security Admin or Owner required to view all security contact details.
        4. Microsoft.Security/pricings/read at subscription scope.
        5. Microsoft.Security/autoProvisioningSettings/read at subscription scope.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Management Group-level Defender plan inheritance is not directly visible
          from subscription context; plans may appear active without a local assignment.
        - Defender for DevOps (GitHub/ADO) connector status requires additional
          permissions on the DevOps security connector resource type.
        - Resource count per workload type is estimated from subscription resource
          metadata; exact billing-unit counts require the Defender billing API.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Pricing tier names vary slightly across Az module versions; the script
          normalises "Standard" / "Free" regardless of casing.

.LINK
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction
    https://learn.microsoft.com/en-us/powershell/module/az.security/get-azdefenderforcloudprice
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-enhanced-security
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/auto-deploy-azure-monitoring-agent
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CenteredText
{
    param(
        [string]$Text,
        [int]$Width = 80,
        [string]$Color = "White"
    )
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-Banner
{
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Defender for Cloud Coverage Assessment v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-Section
{
    param(
        [string]$Title,
        [hashtable]$Data
    )

    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys)
    {
        $value = $Data[$key]
        if ([string]::IsNullOrWhiteSpace($value))
        {
            $value    = "None"
            $valColor = "DarkGray"
        }
        else
        {
            $valColor = "White"
        }

        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-ScanProgress
{
    Write-Host ""
    Write-Host "  Scanning Subscriptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
}

Function Write-ProgressBar
{
    param(
        [int]$Current,
        [int]$Total,
        [string]$CurrentItem,
        [int]$BarWidth = 40
    )

    $percentage = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
    $completed  = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $remaining  = $BarWidth - $completed
    $bar        = ("█" * $completed) + ("░" * $remaining)

    Write-Host "`r" -NoNewline
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White

    if ($CurrentItem)
    {
        $maxLen      = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLen) { $CurrentItem.Substring(0, $maxLen - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-Summary
{
    param([hashtable]$Data)

    Write-Host ""
    Write-Host "  Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys)
    {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(36) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-RiskBreakdown
{
    param([array]$Findings)

    if ($Findings.Count -eq 0) { return }

    $critical = @($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $high     = @($Findings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $medium   = @($Findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $low      = @($Findings | Where-Object { $_.RiskLevel -eq "Low" }).Count

    Write-Host ""
    Write-Host "  Risk-Rated Findings" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Critical                : $critical" -ForegroundColor Red
    Write-Host "  High                    : $high"     -ForegroundColor Yellow
    Write-Host "  Medium                  : $medium"   -ForegroundColor DarkYellow
    Write-Host "  Low                     : $low"      -ForegroundColor Gray
}

Function Write-OutputFiles
{
    param(
        [string]$CsvPath,
        [string]$HtmlPath,
        [bool]$GridViewOpened
    )

    Write-Host ""
    Write-Host "  Output Files" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    if ($CsvPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("CSV Export").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }

    if ($HtmlPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Dashboard").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }

    if ($GridViewOpened)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("Grid View").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": Opened in separate window" -ForegroundColor White
    }

    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-ObjProperty
{
    param(
        [object]$Obj,
        [string]$PropName,
        $Default = $null
    )
    try
    {
        $val = $Obj.$PropName
        if ($null -ne $val) { return $val }
        return $Default
    }
    catch { return $Default }
}

Function Get-RiskLevel
{
    param(
        [string]$FindingType,
        [string]$Workload
    )

    $criticalWorkloads = @("Containers", "SqlServers", "SqlServerVirtualMachines", "Arm")
    $highWorkloads     = @("Servers", "AppServices", "StorageAccounts", "KeyVaults", "OpenSourceRelationalDatabases")

    switch ($FindingType)
    {
        "MissingCriticalPlan"      { return "Critical" }
        "MissingHighPlan"          { return "High" }
        "NoCSPMTier"               { return "High" }
        "AutoProvisioningDisabled" { return "High" }
        "NoSecurityContact"        { return "Medium" }
        "PartialCoverage"          { return "Medium" }
        "FreeTierOnly"             { return if ($criticalWorkloads -contains $Workload) { "High" } else { "Medium" } }
        "NoMDEIntegration"         { return "Medium" }
        "NoMCSBInitiative"         { return "Low" }
        default                    { return "Medium" }
    }
}

Function Get-BusinessImpact
{
    param([string]$FindingType, [string]$Workload)

    switch ($FindingType)
    {
        "MissingCriticalPlan"      { return "No threat detection or security alerts for $Workload workloads. Attackers can operate undetected; breach dwell time is unbounded." }
        "MissingHighPlan"          { return "Security events on $Workload resources generate no alerts. Incidents may go unreported until customer or regulator notification." }
        "NoCSPMTier"               { return "Defender CSPM tier is not active. Advanced attack-path analysis, governance reporting, and data-security posture management are unavailable." }
        "AutoProvisioningDisabled" { return "Security agents are not deployed automatically. New VMs and Arc servers inherit no monitoring, leaving blind spots that grow with every new resource." }
        "NoSecurityContact"        { return "Critical security alerts have no designated recipient. Alert fatigue or misconfiguration could result in missed incident response SLAs." }
        "PartialCoverage"          { return "Mixed Defender coverage creates asymmetric protection. Attackers can pivot from unprotected to protected workloads within the same subscription." }
        "FreeTierOnly"             { return "Free tier provides basic posture score only — no threat detection, no JIT, no adaptive controls for $Workload. Production workloads are unguarded." }
        "NoMDEIntegration"         { return "Defender for Endpoint integration is not confirmed. Server EDR coverage and MDE-sourced alerts are not flowing to Defender for Cloud." }
        "NoMCSBInitiative"         { return "MCSB compliance initiative is not assigned. Regulatory compliance scores are absent, making audit evidence collection manual and error-prone." }
        default                    { return "Review configuration to confirm intended security posture." }
    }
}

Function Get-RemediationStep
{
    param([string]$FindingType, [string]$Workload)

    switch ($FindingType)
    {
        "MissingCriticalPlan"      { return "Enable Defender for $Workload via Security Center → Environment Settings → Defender Plans. Requires Security Admin role." }
        "MissingHighPlan"          { return "Enable Defender for $Workload in Environment Settings. Evaluate sub-plan options (P1/P2 for Servers) based on workload criticality." }
        "NoCSPMTier"               { return "Upgrade CSPM plan to Defender CSPM (paid) in Environment Settings. Enables attack-path analysis, agentless scanning, and governance." }
        "AutoProvisioningDisabled" { return "Enable auto-provisioning for Azure Monitor Agent in Security → Environment Settings → Auto Provisioning. AMA replaces deprecated MMA." }
        "NoSecurityContact"        { return "Configure security contact under Security → Environment Settings → Email Notifications. Add security team DL and enable all alert severities." }
        "PartialCoverage"          { return "Review unprotected workload types and enable the relevant Defender plan. Prioritise by resource count and data classification." }
        "FreeTierOnly"             { return "Upgrade $Workload plan from Free to Standard/P1/P2 in Environment Settings. Assess estimated cost against risk exposure of leaving workload unmonitored." }
        "NoMDEIntegration"         { return "Enable the MDE integration in Defender for Cloud → Integrations, or verify MDE tenant onboarding and that Defender for Servers Plan 2 is active." }
        "NoMCSBInitiative"         { return "Assign the Microsoft Cloud Security Benchmark initiative to the subscription via Policy → Assignments or through Defender for Cloud Regulatory Compliance." }
        default                    { return "Review Defender for Cloud Environment Settings for this subscription." }
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\','\\\\' -replace "'","\'" -replace '"','\"' -replace "`n",' ' -replace "`r",' ' }

Function Generate-DefenderCoverageHtml
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$PlanRows,
        [array]$Findings,
        [array]$SubscriptionResults,
        [hashtable]$WorkloadCoverage,
        [string]$GeneratedOn
    )

    $totalSubs        = @($SubscriptionResults).Count
    $totalPlans       = @($PlanRows).Count
    $protectedSubs    = @($SubscriptionResults | Where-Object { $_.CoverageStatus -eq "Fully Protected" }).Count
    $partialSubs      = @($SubscriptionResults | Where-Object { $_.CoverageStatus -eq "Partially Protected" }).Count
    $unprotectedSubs  = @($SubscriptionResults | Where-Object { $_.CoverageStatus -eq "Unprotected" }).Count
    $criticalFindings = @($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highFindings     = @($Findings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumFindings   = @($Findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $lowFindings      = @($Findings | Where-Object { $_.RiskLevel -eq "Low" }).Count
    $standardPlans    = @($PlanRows | Where-Object { $_.PricingTier -eq "Standard" }).Count
    $freePlans        = @($PlanRows | Where-Object { $_.PricingTier -eq "Free" }).Count

    # ── Plan table rows ───────────────────────────────────────────────────────
    $planRows_html = ""
    foreach ($p in $PlanRows)
    {
        $tierCls = if ($p.PricingTier -eq "Standard") { "badge-green" } else { "badge-amber" }
        $planRows_html += @"
          <tr onclick="showPlanDetail($($PlanRows.IndexOf($p)))">
            <td title="$(EscHtml $p.SubscriptionName)">$(if($p.SubscriptionName.Length -gt 34){EscHtml($p.SubscriptionName.Substring(0,31)+'...')}else{EscHtml $p.SubscriptionName})</td>
            <td>$(EscHtml $p.Workload)</td>
            <td><span class="badge $tierCls">$(EscHtml $p.PricingTier)</span></td>
            <td>$(EscHtml $p.SubPlan)</td>
            <td style="font-family:var(--mono);font-size:11px">$(EscHtml $p.FreeTrialExpiry)</td>
          </tr>
"@
    }

    # ── Findings table rows ───────────────────────────────────────────────────
    $findingRows_html = ""
    foreach ($f in $Findings)
    {
        $riskCls = switch ($f.RiskLevel)
        {
            "Critical" { "badge-red" }
            "High"     { "badge-amber" }
            "Medium"   { "badge-blue" }
            default    { "" }
        }
        $findingRows_html += @"
          <tr onclick="showFindingDetail($($Findings.IndexOf($f)))">
            <td><span class="badge $riskCls">$(EscHtml $f.RiskLevel)</span></td>
            <td title="$(EscHtml $f.Finding)">$(if($f.Finding.Length -gt 42){EscHtml($f.Finding.Substring(0,39)+'...')}else{EscHtml $f.Finding})</td>
            <td>$(EscHtml $f.Workload)</td>
            <td title="$(EscHtml $f.SubscriptionName)">$(if($f.SubscriptionName.Length -gt 28){EscHtml($f.SubscriptionName.Substring(0,25)+'...')}else{EscHtml $f.SubscriptionName})</td>
            <td style="font-size:11px;color:var(--muted2)" title="$(EscHtml $f.BusinessImpact)">$(if($f.BusinessImpact.Length -gt 50){EscHtml($f.BusinessImpact.Substring(0,47)+'...')}else{EscHtml $f.BusinessImpact})</td>
          </tr>
"@
    }

    # ── Subscription result rows ──────────────────────────────────────────────
    $subRows_html = ""
    foreach ($s in $SubscriptionResults)
    {
        $icon = switch ($s.CoverageStatus)
        {
            "Fully Protected"    { "✓" }
            "Partially Protected"{ "⚠" }
            default              { "✗" }
        }
        $cls = switch ($s.CoverageStatus)
        {
            "Fully Protected"    { "c-green" }
            "Partially Protected"{ "c-amber" }
            default              { "c-red" }
        }
        $subRows_html += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $s.Name)</span>
            <span class="sub-detail">$(EscHtml $s.CoverageStatus) — Standard Plans: $($s.StandardPlanCount) / $($s.TotalPlanCount)</span>
          </div>
"@
    }

    # ── Workload coverage bar rows ────────────────────────────────────────────
    $wlTotal   = $totalSubs
    $wlRows_html = ""
    foreach ($wl in ($WorkloadCoverage.GetEnumerator() | Sort-Object { $_.Value } -Descending))
    {
        $pct      = if ($wlTotal -gt 0) { [math]::Round(($wl.Value / $wlTotal) * 100) } else { 0 }
        $barColor = if ($pct -ge 80) { "var(--green)" } elseif ($pct -ge 50) { "var(--amber)" } else { "var(--red)" }
        $wlRows_html += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $wl.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($wl.Value)/$wlTotal subs ($pct%)</span>
          </div>
"@
    }

    # ── JSON for plan detail drawer ───────────────────────────────────────────
    $planJson = "["
    foreach ($p in $PlanRows)
    {
        $planJson += "{" +
            """sub"":""$(EscJ $p.SubscriptionName)""," +
            """subId"":""$(EscJ $p.SubscriptionId)""," +
            """workload"":""$(EscJ $p.Workload)""," +
            """tier"":""$(EscJ $p.PricingTier)""," +
            """subPlan"":""$(EscJ $p.SubPlan)""," +
            """expiry"":""$(EscJ $p.FreeTrialExpiry)""" +
        "},"
    }
    $planJson = $planJson.TrimEnd(",") + "]"

    # ── JSON for findings detail drawer ───────────────────────────────────────
    $findingJson = "["
    foreach ($f in $Findings)
    {
        $findingJson += "{" +
            """risk"":""$(EscJ $f.RiskLevel)""," +
            """finding"":""$(EscJ $f.Finding)""," +
            """workload"":""$(EscJ $f.Workload)""," +
            """sub"":""$(EscJ $f.SubscriptionName)""," +
            """impact"":""$(EscJ $f.BusinessImpact)""," +
            """remediation"":""$(EscJ $f.RemediationStep)""," +
            """findingType"":""$(EscJ $f.FindingType)""" +
        "},"
    }
    $findingJson = $findingJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Defender for Cloud Coverage Dashboard</title>
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
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:110px;text-align:right;flex-shrink:0;}
.risk-banner{padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:16px;display:flex;align-items:center;gap:10px;font-size:13px;}
.risk-banner.critical{background:rgba(248,81,73,.08);border-color:rgba(248,81,73,.3);color:var(--red);}
.risk-banner.high{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3);color:var(--amber);}
.risk-banner.ok{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.3);color:var(--green);}
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
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:480px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
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
.impact-box{background:var(--surface2);border-left:3px solid var(--red);padding:10px 14px;border-radius:0 var(--radius-sm) var(--radius-sm) 0;font-size:12px;line-height:1.6;color:var(--muted2);margin-top:6px;}
.remediation-box{background:var(--surface2);border-left:3px solid var(--green);padding:10px 14px;border-radius:0 var(--radius-sm) var(--radius-sm) 0;font-size:12px;line-height:1.6;color:var(--muted2);margin-top:6px;}
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
    <div class="logo-icon">🛡️</div>
    <div class="logo-title">Defender Coverage</div>
    <div class="logo-sub">Microsoft Defender for Cloud</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('plans',this)"><span class="nav-icon">📋</span> Defender Plans</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">⚠️</span> Risk Findings</button>
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
      Defender Coverage Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Defender for Cloud Coverage Overview</div>
      <div class="page-sub">Security posture and protection gaps across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="__RISK_BANNER_CLS__ risk-banner">
      <span>__RISK_ICON__</span>
      <span><strong>Risk Posture:</strong> __RISK_BANNER_TEXT__</span>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-green">
        <div class="stat-num">__PROTECTED_SUBS__</div>
        <div class="stat-label">Fully Protected</div>
        <div class="stat-sub">All workloads covered</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__PARTIAL_SUBS__</div>
        <div class="stat-label">Partially Protected</div>
        <div class="stat-sub">Some gaps present</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__UNPROTECTED_SUBS__</div>
        <div class="stat-label">Unprotected</div>
        <div class="stat-sub">No paid plans active</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__STANDARD_PLANS__</div>
        <div class="stat-label">Standard Plans</div>
        <div class="stat-sub">Paid / active coverage</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_FINDINGS__</div>
        <div class="stat-label">Critical Findings</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_FINDINGS__</div>
        <div class="stat-label">High Findings</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🛡️ Workload Coverage (% of subscriptions with Standard plan)</div>
        __WL_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">⚠️ Findings by Risk Level</div>
        <div class="stats-grid" style="margin-bottom:0;">
          <div class="stat-card c-red"><div class="stat-num">__CRITICAL_FINDINGS__</div><div class="stat-label">Critical</div></div>
          <div class="stat-card c-amber"><div class="stat-num">__HIGH_FINDINGS__</div><div class="stat-label">High</div></div>
          <div class="stat-card c-blue"><div class="stat-num">__MEDIUM_FINDINGS__</div><div class="stat-label">Medium</div></div>
          <div class="stat-card" style="border-top-color:var(--muted)"><div class="stat-num">__LOW_FINDINGS__</div><div class="stat-label">Low</div></div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">📊 Plan Coverage Summary</div>
      <div class="stats-grid" style="margin-bottom:0;">
        <div class="stat-card c-blue"><div class="stat-num">__TOTAL_PLANS__</div><div class="stat-label">Total Plans Assessed</div></div>
        <div class="stat-card c-green"><div class="stat-num">__STANDARD_PLANS__</div><div class="stat-label">Standard (Paid)</div></div>
        <div class="stat-card c-amber"><div class="stat-num">__FREE_PLANS__</div><div class="stat-label">Free Tier</div></div>
      </div>
    </div>
  </div>

  <!-- Defender Plans -->
  <div id="page-plans" class="page">
    <div class="page-header">
      <div class="page-title">Defender Plan Status</div>
      <div class="page-sub">Pricing tier per workload type and subscription. Standard = paid protection active.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="planSearch" placeholder="Search subscription, workload…" oninput="filterPlans()"/>
        </div>
        <select class="filter-select" id="filterTier" onchange="filterPlans()">
          <option value="">All Tiers</option>
          <option value="Standard">Standard</option>
          <option value="Free">Free</option>
        </select>
        <select class="filter-select" id="pgSizePlans" onchange="changePlanPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="planTable">
          <thead>
            <tr>
              <th onclick="sortPlans(0)">Subscription</th>
              <th onclick="sortPlans(1)">Workload</th>
              <th onclick="sortPlans(2)">Pricing Tier</th>
              <th onclick="sortPlans(3)">Sub-Plan</th>
              <th onclick="sortPlans(4)">Free Trial Expiry</th>
            </tr>
          </thead>
          <tbody id="planBody">__PLAN_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="planPagination"></div>
    </div>
  </div>

  <!-- Risk Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Risk-Rated Findings</div>
      <div class="page-sub">Architectural gaps and security weaknesses with business impact and remediation guidance</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findingSearch" placeholder="Search finding, workload, subscription…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterRisk" onchange="filterFindings()">
          <option value="">All Risk Levels</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="pgSizeFindings" onchange="changeFindingPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="findingTable">
          <thead>
            <tr>
              <th onclick="sortFindings(0)">Risk</th>
              <th onclick="sortFindings(1)">Finding</th>
              <th onclick="sortFindings(2)">Workload</th>
              <th onclick="sortFindings(3)">Subscription</th>
              <th>Business Impact</th>
            </tr>
          </thead>
          <tbody id="findingBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findingPagination"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription Defender coverage outcome</div>
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
const PLAN_DATA    = __PLAN_JSON__;
const FINDING_DATA = __FINDING_JSON__;

let planFiltered    = [...PLAN_DATA];
let findingFiltered = [...FINDING_DATA];
let planPage = 1, planPageSz = 25;
let findingPage = 1, findingPageSz = 25;
let planSortCol = -1, planSortAsc = true;
let findingSortCol = -1, findingSortAsc = true;
let currentDetailIdx  = 0;
let currentDetailList = [];
let currentDetailType = '';

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
  t.textContent=msg;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Plans table ───────────────────────────────────────────────────────────────
function filterPlans(){
  const q=document.getElementById('planSearch').value.toLowerCase();
  const t=document.getElementById('filterTier').value;
  planFiltered=PLAN_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mT=!t||r.tier===t;
    return mQ&&mT;
  });
  planPage=1;renderPlans();
}

function changePlanPageSize(){
  planPageSz=parseInt(document.getElementById('pgSizePlans').value);
  planPage=1;renderPlans();
}

function sortPlans(col){
  if(planSortCol===col){planSortAsc=!planSortAsc;}else{planSortCol=col;planSortAsc=true;}
  const keys=['sub','workload','tier','subPlan','expiry'];
  planFiltered.sort((a,b)=>{
    const k=keys[col];
    return planSortAsc?String(a[k]||'').localeCompare(String(b[k]||''),undefined,{numeric:true})
                      :String(b[k]||'').localeCompare(String(a[k]||''),undefined,{numeric:true});
  });
  renderPlans();
}

function renderPlans(){
  const tbody=document.getElementById('planBody');
  const start=(planPage-1)*planPageSz;
  const slice=planFiltered.slice(start,start+planPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=PLAN_DATA.indexOf(r);
    const tCls=r.tier==='Standard'?'badge-green':'badge-amber';
    const nm=r.sub.length>34?r.sub.substring(0,31)+'...':r.sub;
    return `<tr onclick="showPlanDetail(${gi})">
      <td title="${escH(r.sub)}">${escH(nm)}</td>
      <td>${escH(r.workload)}</td>
      <td><span class="badge ${tCls}">${escH(r.tier)}</span></td>
      <td>${escH(r.subPlan)||'—'}</td>
      <td style="font-family:var(--mono);font-size:11px">${escH(r.expiry)||'—'}</td>
    </tr>`;
  }).join('');
  renderPlanPg();
}

function renderPlanPg(){
  const total=Math.ceil(planFiltered.length/planPageSz);
  const el=document.getElementById('planPagination');
  let h=`<span>${planFiltered.length} plans</span>`;
  h+=`<button class="pg-btn" onclick="changePlanPage(${planPage-1})" ${planPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,planPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===planPage?'active':''}" onclick="changePlanPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changePlanPage(${planPage+1})" ${planPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changePlanPage(p){
  const total=Math.ceil(planFiltered.length/planPageSz);
  if(p<1||p>total)return;
  planPage=p;renderPlans();
}

// ── Findings table ────────────────────────────────────────────────────────────
function filterFindings(){
  const q=document.getElementById('findingSearch').value.toLowerCase();
  const r=document.getElementById('filterRisk').value;
  findingFiltered=FINDING_DATA.filter(f=>{
    const mQ=!q||JSON.stringify(f).toLowerCase().includes(q);
    const mR=!r||f.risk===r;
    return mQ&&mR;
  });
  findingPage=1;renderFindings();
}

function changeFindingPageSize(){
  findingPageSz=parseInt(document.getElementById('pgSizeFindings').value);
  findingPage=1;renderFindings();
}

function sortFindings(col){
  if(findingSortCol===col){findingSortAsc=!findingSortAsc;}else{findingSortCol=col;findingSortAsc=true;}
  const keys=['risk','finding','workload','sub','impact'];
  const riskOrder={Critical:0,High:1,Medium:2,Low:3};
  findingFiltered.sort((a,b)=>{
    const k=keys[col];
    if(k==='risk') return findingSortAsc?(riskOrder[a.risk]??9)-(riskOrder[b.risk]??9):(riskOrder[b.risk]??9)-(riskOrder[a.risk]??9);
    return findingSortAsc?String(a[k]||'').localeCompare(String(b[k]||''),undefined,{numeric:true})
                         :String(b[k]||'').localeCompare(String(a[k]||''),undefined,{numeric:true});
  });
  renderFindings();
}

function renderFindings(){
  const tbody=document.getElementById('findingBody');
  const start=(findingPage-1)*findingPageSz;
  const slice=findingFiltered.slice(start,start+findingPageSz);
  tbody.innerHTML=slice.map(f=>{
    const gi=FINDING_DATA.indexOf(f);
    const rCls=f.risk==='Critical'?'badge-red':f.risk==='High'?'badge-amber':'badge-blue';
    const fn=f.finding.length>42?f.finding.substring(0,39)+'...':f.finding;
    const sn=f.sub.length>28?f.sub.substring(0,25)+'...':f.sub;
    const im=f.impact.length>50?f.impact.substring(0,47)+'...':f.impact;
    return `<tr onclick="showFindingDetail(${gi})">
      <td><span class="badge ${rCls}">${escH(f.risk)}</span></td>
      <td title="${escH(f.finding)}">${escH(fn)}</td>
      <td>${escH(f.workload)}</td>
      <td title="${escH(f.sub)}">${escH(sn)}</td>
      <td style="font-size:11px;color:var(--muted2)" title="${escH(f.impact)}">${escH(im)}</td>
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
  findingPage=p;renderFindings();
}

// ── Detail drawers ────────────────────────────────────────────────────────────
function showPlanDetail(idx){
  currentDetailIdx=idx;currentDetailList=PLAN_DATA;currentDetailType='plan';
  const r=PLAN_DATA[idx];if(!r)return;
  const tCls=r.tier==='Standard'?'badge-green':'badge-amber';
  document.getElementById('drawerTitle').textContent=r.workload+' — '+r.sub;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${PLAN_DATA.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription ID</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.subId)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Workload</div><div class="drawer-field-value">${escH(r.workload)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Pricing Tier</div><div class="drawer-field-value"><span class="badge ${tCls}">${escH(r.tier)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Sub-Plan</div><div class="drawer-field-value">${r.subPlan?escH(r.subPlan):'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Free Trial Expiry</div><div class="drawer-field-value" style="font-family:var(--mono)">${r.expiry?escH(r.expiry):'—'}</div></div>
  `;
  openDrawer();
}

function showFindingDetail(idx){
  currentDetailIdx=idx;currentDetailList=FINDING_DATA;currentDetailType='finding';
  const f=FINDING_DATA[idx];if(!f)return;
  const rCls=f.risk==='Critical'?'badge-red':f.risk==='High'?'badge-amber':'badge-blue';
  document.getElementById('drawerTitle').textContent=f.finding;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FINDING_DATA.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Risk Level</div><div class="drawer-field-value"><span class="badge ${rCls}">${escH(f.risk)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Workload</div><div class="drawer-field-value">${escH(f.workload)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(f.sub)}</div></div>
    <div class="drawer-section">Business Impact</div>
    <div class="impact-box">${escH(f.impact)}</div>
    <div class="drawer-section">Remediation Guidance</div>
    <div class="remediation-box">${escH(f.remediation)}</div>
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
  const next=currentDetailIdx+dir;
  if(next>=0&&next<currentDetailList.length){
    if(currentDetailType==='plan') showPlanDetail(next);
    else showFindingDetail(next);
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

// ── Init ─────────────────────────────────────────────────────────────────────
filterPlans();
filterFindings();
animateBars();
</script>
</body>
</html>
'@

    # ── Risk banner selection ─────────────────────────────────────────────────
    $riskBannerCls  = if ($criticalFindings -gt 0) { "critical" } elseif ($highFindings -gt 0) { "high" } else { "ok" }
    $riskIcon       = if ($criticalFindings -gt 0) { "🔴" } elseif ($highFindings -gt 0) { "🟡" } else { "🟢" }
    $riskBannerText = if ($criticalFindings -gt 0)
    {
        "$criticalFindings critical finding(s) require immediate remediation — workloads are operating with no threat detection."
    }
    elseif ($highFindings -gt 0)
    {
        "$highFindings high-severity finding(s) present — Defender plan gaps expose workloads to undetected threats."
    }
    else
    {
        "No critical or high findings detected. Continue monitoring and review medium/low findings."
    }

    $html = $html `
        -replace '__GENERATED_ON__',    $GeneratedOn `
        -replace '__SUB_COUNT__',       ($SubscriptionResults.Count) `
        -replace '__PROTECTED_SUBS__',  $protectedSubs `
        -replace '__PARTIAL_SUBS__',    $partialSubs `
        -replace '__UNPROTECTED_SUBS__',$unprotectedSubs `
        -replace '__STANDARD_PLANS__',  $standardPlans `
        -replace '__FREE_PLANS__',      $freePlans `
        -replace '__TOTAL_PLANS__',     $totalPlans `
        -replace '__CRITICAL_FINDINGS__',$criticalFindings `
        -replace '__HIGH_FINDINGS__',   $highFindings `
        -replace '__MEDIUM_FINDINGS__', $mediumFindings `
        -replace '__LOW_FINDINGS__',    $lowFindings `
        -replace '__RISK_BANNER_CLS__', $riskBannerCls `
        -replace '__RISK_ICON__',       $riskIcon `
        -replace '__RISK_BANNER_TEXT__',$riskBannerText `
        -replace '__WL_ROWS__',         $wlRows_html `
        -replace '__PLAN_ROWS__',       $planRows_html `
        -replace '__FINDING_ROWS__',    $findingRows_html `
        -replace '__SUB_ROWS__',        $subRows_html `
        -replace '__TENANT__',          $SessionInfo.Tenant `
        -replace '__ACCOUNT__',         $SessionInfo.Account `
        -replace '__ENVIRONMENT__',     $SessionInfo.Environment `
        -replace '__SCOPE__',           $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__',  $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__',       $ScanParameters.ExecTime `
        -replace '__PLAN_JSON__',       $planJson `
        -replace '__FINDING_JSON__',    $findingJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureDefenderCoverageAssessment
{
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureDefenderCoverage-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Security")
    $missingModules  = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missingModules)
    {
        Write-Host "  ⚠ Missing Az modules: $($missingModules -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "  Install Az module now? (Y/N)"

        if ($install -match '^[Yy]$')
        {
            try
            {
                Write-Host ""
                Write-Host "  Installing Az module, please wait..." -ForegroundColor Cyan
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "  ✓ Az module installed successfully" -ForegroundColor Green
                Write-Host ""
            }
            catch
            {
                Write-Host "  ✗ Error installing Az module: $_" -ForegroundColor Red
                return
            }
        }
        else
        {
            Write-Host ""
            Write-Host "  Installation declined. Cannot proceed without required Az modules." -ForegroundColor Yellow
            return
        }
    }

    # ── Authentication ────────────────────────────────────────────────────────
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx)
    {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $ctx = Get-AzContext
    }

    # ── Subscription resolution ───────────────────────────────────────────────
    if ($AllSubscriptions -or -not $SubscriptionIds)
    {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText     = "All Subscriptions"
    }
    else
    {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
            Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count))"
    }

    $subCount = $subscriptions.Count

    # ── Workloads to assess ───────────────────────────────────────────────────
    # These map to the Az.Security Get-AzSecurityPricing resource type names.
    $workloadsOfInterest = @(
        "Servers",
        "AppServices",
        "SqlServers",
        "SqlServerVirtualMachines",
        "StorageAccounts",
        "Containers",
        "KeyVaults",
        "Arm",
        "Dns",
        "OpenSourceRelationalDatabases",
        "CspmTier",
        "DevOps"
    )

    # ── Display session / params ──────────────────────────────────────────────
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"         = "$scopeText ($subCount found)"
        "Workloads"     = $workloadsOfInterest -join ", "
        "Export to CSV" = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"   = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allPlanRows         = @()
    $allFindings         = @()
    $subscriptionResults = @()
    $workloadCoverage    = @{}    # Workload → count of subs with Standard plan
    $successCount        = 0
    $errorCount          = 0

    foreach ($wl in $workloadsOfInterest) { $workloadCoverage[$wl] = 0 }

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = ([math]::Max(
        ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
        35
    ))

    $subIndex = 1

    foreach ($sub in $subscriptions)
    {
        try
        {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue `
                          -InformationAction SilentlyContinue | Out-Null

            # ── Defender plan pricing tiers ───────────────────────────────────
            $pricings         = @()
            $standardCount    = 0
            $freeCount        = 0
            $subPlanRows      = @()
            $missingWorkloads = @()

            try
            {
                $pricings = @(Get-AzSecurityPricing -ErrorAction Stop)
            }
            catch
            {
                Write-Warning "  Could not retrieve Defender pricing for $($sub.Name): $_"
            }

            foreach ($wl in $workloadsOfInterest)
            {
                $match = $pricings | Where-Object { $_.Name -eq $wl }

                if ($match)
                {
                    $tier        = if ($match.PricingTier) { $match.PricingTier } else { "Unknown" }
                    $subPlan     = if ($match.SubPlan)     { $match.SubPlan }     else { "" }
                    $freeExpiry  = ""
                    try
                    {
                        $freeExpiry = if ($match.FreeTrialRemainingTime -and $match.FreeTrialRemainingTime -ne "PT0S")
                        {
                            "Trial active"
                        }
                        else { "" }
                    }
                    catch { }

                    $normalTier = $tier.Trim()

                    $row = [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Workload         = $wl
                        PricingTier      = $normalTier
                        SubPlan          = $subPlan
                        FreeTrialExpiry  = $freeExpiry
                    }
                    $subPlanRows  += $row
                    $allPlanRows  += $row

                    if ($normalTier -eq "Standard")
                    {
                        $standardCount++
                        $workloadCoverage[$wl]++

                        # Free-tier-only finding on critical workloads
                        if ($freeExpiry -eq "Trial active")
                        {
                            $ft      = "FreeTierOnly"
                            $impact  = Get-BusinessImpact   -FindingType $ft -Workload $wl
                            $remed   = Get-RemediationStep  -FindingType $ft -Workload $wl
                            $allFindings += [pscustomobject]@{
                                SubscriptionName = $sub.Name
                                SubscriptionId   = $sub.Id
                                FindingType      = $ft
                                Finding          = "Trial-only Standard plan active for $wl"
                                Workload         = $wl
                                RiskLevel        = Get-RiskLevel -FindingType $ft -Workload $wl
                                BusinessImpact   = $impact
                                RemediationStep  = $remed
                            }
                        }
                    }
                    else
                    {
                        $freeCount++
                        $missingWorkloads += $wl

                        # Generate finding for missing / Free workload
                        $criticalsInFree = @("Containers","SqlServers","SqlServerVirtualMachines","Arm")
                        $ft = if ($criticalsInFree -contains $wl) { "MissingCriticalPlan" } else { "MissingHighPlan" }
                        $impact = Get-BusinessImpact  -FindingType $ft -Workload $wl
                        $remed  = Get-RemediationStep -FindingType $ft -Workload $wl

                        $allFindings += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            FindingType      = $ft
                            Finding          = "Defender for $wl is on Free tier (no threat detection)"
                            Workload         = $wl
                            RiskLevel        = Get-RiskLevel -FindingType $ft -Workload $wl
                            BusinessImpact   = $impact
                            RemediationStep  = $remed
                        }
                    }
                }
                else
                {
                    # Workload not returned — treat as unassessed / Free
                    $missingWorkloads += $wl
                    $freeCount++
                }
            }

            # CSPM finding
            $cspmMatch = $pricings | Where-Object { $_.Name -eq "CspmTier" }
            if (-not $cspmMatch -or $cspmMatch.PricingTier -ne "Standard")
            {
                $ft     = "NoCSPMTier"
                $allFindings += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    FindingType      = $ft
                    Finding          = "Defender CSPM (paid tier) is not enabled"
                    Workload         = "CspmTier"
                    RiskLevel        = Get-RiskLevel -FindingType $ft -Workload "CspmTier"
                    BusinessImpact   = Get-BusinessImpact  -FindingType $ft -Workload "CspmTier"
                    RemediationStep  = Get-RemediationStep -FindingType $ft -Workload "CspmTier"
                }
            }

            # ── Auto-provisioning ─────────────────────────────────────────────
            try
            {
                $autoProvSettings = @(Get-AzSecurityAutoProvisioningSetting -ErrorAction Stop)
                $amaDisabled = $autoProvSettings | Where-Object {
                    $_.Name -in @("MicrosoftMonitoringAgent","mma-agent","AzureMonitoringAgent","ama-agent") -and
                    $_.AutoProvision -ne "On"
                }

                if ($amaDisabled -or $autoProvSettings.Count -eq 0)
                {
                    $ft = "AutoProvisioningDisabled"
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        FindingType      = $ft
                        Finding          = "Security agent auto-provisioning is disabled"
                        Workload         = "Servers"
                        RiskLevel        = Get-RiskLevel -FindingType $ft -Workload "Servers"
                        BusinessImpact   = Get-BusinessImpact  -FindingType $ft -Workload "Servers"
                        RemediationStep  = Get-RemediationStep -FindingType $ft -Workload "Servers"
                    }
                }
            }
            catch
            {
                Write-Verbose "  Could not retrieve auto-provisioning settings for $($sub.Name): $_"
            }

            # ── Security contacts ─────────────────────────────────────────────
            try
            {
                $contacts = @(Get-AzSecurityContact -ErrorAction Stop)
                if ($contacts.Count -eq 0 -or
                    ($contacts | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Email) }).Count -eq 0)
                {
                    $ft = "NoSecurityContact"
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        FindingType      = $ft
                        Finding          = "No security contact email is configured"
                        Workload         = "General"
                        RiskLevel        = Get-RiskLevel -FindingType $ft -Workload "General"
                        BusinessImpact   = Get-BusinessImpact  -FindingType $ft -Workload "General"
                        RemediationStep  = Get-RemediationStep -FindingType $ft -Workload "General"
                    }
                }
            }
            catch
            {
                Write-Verbose "  Could not retrieve security contacts for $($sub.Name): $_"
            }

            # ── Partial coverage finding ──────────────────────────────────────
            if ($standardCount -gt 0 -and $freeCount -gt 0)
            {
                $ft = "PartialCoverage"
                $allFindings += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    FindingType      = $ft
                    Finding          = "Mixed coverage: $standardCount paid plan(s), $freeCount unprotected workload(s)"
                    Workload         = "Multiple"
                    RiskLevel        = Get-RiskLevel -FindingType $ft -Workload "Multiple"
                    BusinessImpact   = Get-BusinessImpact  -FindingType $ft -Workload "Multiple"
                    RemediationStep  = Get-RemediationStep -FindingType $ft -Workload "Multiple"
                }
            }

            # ── Coverage status ───────────────────────────────────────────────
            $coverageStatus = if ($standardCount -eq $workloadsOfInterest.Count) { "Fully Protected" }
                              elseif ($standardCount -gt 0)                      { "Partially Protected" }
                              else                                                { "Unprotected" }

            # ── Per-subscription console output ───────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Standard: $standardCount  Free: $freeCount  Status: $coverageStatus" -ForegroundColor White

            $subscriptionResults += [pscustomobject]@{
                Name            = $sub.Name
                SubscriptionId  = $sub.Id
                StandardPlanCount = $standardCount
                FreePlanCount   = $freeCount
                TotalPlanCount  = $workloadsOfInterest.Count
                CoverageStatus  = $coverageStatus
                Status          = "Success"
            }
            $successCount++
        }
        catch
        {
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✗ " -NoNewline -ForegroundColor Red
            Write-Host $paddedName -NoNewline -ForegroundColor Red
            Write-Host " → Failed: $($_.Exception.Message)" -ForegroundColor Red

            $subscriptionResults += [pscustomobject]@{
                Name           = $sub.Name
                SubscriptionId = $sub.Id
                CoverageStatus = "Error"
                Status         = "Error"
            }
            $errorCount++
        }

        $subIndex++
    }

    # ── Summary ───────────────────────────────────────────────────────────────
    $endTime  = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-Summary -Data ([ordered]@{
        "Total Subscriptions Scanned" = $subCount
        "Successful"                  = $successCount
        "Errors"                      = $errorCount
        "Total Plan Rows Assessed"    = $allPlanRows.Count
        "Total Findings Generated"    = $allFindings.Count
        "Execution Time"              = $duration
    })

    Write-RiskBreakdown -Findings $allFindings

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported    = $false
    $htmlExported   = $false
    $gridViewOpened = $false
    $htmlPath       = ""

    if ($allPlanRows.Count -gt 0 -or $allFindings.Count -gt 0)
    {
        # CSV export
        if ($ExportToCsv)
        {
            try
            {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir))
                {
                    New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
                }

                $allPlanRows | Select-Object SubscriptionName, SubscriptionId, Workload, PricingTier, SubPlan, FreeTrialExpiry |
                    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                $findingCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "Findings.csv"
                $allFindings | Select-Object SubscriptionName, SubscriptionId, RiskLevel, FindingType,
                    Finding, Workload, BusinessImpact, RemediationStep |
                    Export-Csv -Path $findingCsvPath -NoTypeInformation -Encoding UTF8

                $csvExported = $true
            }
            catch
            {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML dashboard
        try
        {
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

            $htmlContent = Generate-DefenderCoverageHtml `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParams `
                -PlanRows            $allPlanRows `
                -Findings            $allFindings `
                -SubscriptionResults $subscriptionResults `
                -WorkloadCoverage    $workloadCoverage `
                -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir))
            {
                New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null
            }

            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch
        {
            Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        # Grid View
        try
        {
            $allFindings |
                Select-Object SubscriptionName, RiskLevel, FindingType, Finding, Workload, BusinessImpact |
                Out-GridView -Title "Azure Defender Coverage Assessment — Risk Findings"
            $gridViewOpened = $true
        }
        catch
        {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else
    {
        Write-Host ""
        Write-Host "  ⚠ No Defender plan data found in the targeted subscriptions." -ForegroundColor Yellow
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened)
    {
        $outCsv  = if ($csvExported)  { $CsvPath  } else { $null }
        $outHtml = if ($htmlExported) { $htmlPath } else { $null }
        Write-OutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
    }
    else
    {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
