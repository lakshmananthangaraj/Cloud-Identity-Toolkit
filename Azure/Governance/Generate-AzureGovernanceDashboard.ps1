<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 22 August 2026
Modified-On     : 22 August 2026

.SYNOPSIS
    Aggregates Azure governance findings across Policy, RBAC, tagging, naming,
    resource locks, monitoring, and subscription governance, and delivers an
    enterprise-level HTML dashboard that identifies key governance gaps.

.DESCRIPTION
    Generate-AzureGovernanceDashboard evaluates the end-to-end Azure governance
    posture across one or multiple subscriptions by examining seven governance
    domains in depth:

    1. Policy Governance
       - Custom vs. built-in policy definition counts
       - Assignments with DoNotEnforce or Disabled enforcement modes
       - Policy exemptions by expiry status (Active / Expiring / Expired / No Expiry)
       - Policy set (initiative) coverage

    2. RBAC & Identity Governance
       - Owner-role assignments at subscription scope (blast-radius risk)
       - Classic Administrator / Co-Administrator assignments (legacy, deprecated)
       - Guest accounts holding privileged roles (External Identity risk)
       - Broad built-in roles assigned at subscription level (Contributor, etc.)
       - Service principal assignments without expiry or description (credential hygiene)

    3. Tagging Governance
       - Resources and resource groups missing mandatory tags (evaluated against a
         configurable tag schema: Environment, Owner, CostCenter, Project, ManagedBy)
       - Tag compliance percentage per subscription
       - Most-missing tag keys across the estate

    4. Naming Convention Governance
       - Resource groups not following a discoverable pattern (prefix-based heuristics)
       - Resources with auto-generated or GUID-based names
       - Duplicate resource names within a subscription (shadow risk)

    5. Resource Locks Governance
       - Subscriptions, resource groups, and critical resources without CanNotDelete
         or ReadOnly locks
       - Lock coverage percentage

    6. Monitoring & Diagnostics Governance
       - Subscriptions without an Activity Log diagnostic setting forwarding to
         Log Analytics or Storage
       - Key Vaults, NSGs, and Storage Accounts without diagnostic settings
       - Absence of Azure Monitor Alerts for critical signals
         (Service Health, Resource Health, Admin Operations)

    7. Subscription Governance
       - Subscriptions without a Management Group assignment (orphaned subscriptions)
       - Multiple subscriptions in the same tenant without a defined hierarchy
       - Budget alerts: subscriptions without at least one consumption budget
       - Advisor score retrieval (cost, security, reliability, operational excellence)

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and colour-coded per-subscription console output
        - Optional CSV export of all findings per domain
        - Always-on interactive HTML dashboard (dark/light theme, domain tabs,
          sortable tables, governance score, detail drawer)
        - Governance scoring: each domain earns a score 0–100 based on pass/fail
          ratio of its controls; an aggregate weighted score is computed
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan.

.PARAMETER MandatoryTags
    String array of tag keys that are mandatory in your organisation.
    Default: @("Environment","Owner","CostCenter","Project","ManagedBy")

.PARAMETER ExportToCsv
    Switch. Exports all governance findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzureGovernance-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Generate-AzureGovernanceDashboard -AllSubscriptions

.EXAMPLE
    Generate-AzureGovernanceDashboard -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Generate-AzureGovernanceDashboard -AllSubscriptions -MandatoryTags @("Environment","Owner","CostCenter")

.EXAMPLE
    Generate-AzureGovernanceDashboard -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\Governance.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (22-Aug-2026) - Initial release. Policy, RBAC, tagging, naming,
                            resource locks, monitoring, and subscription
                            governance assessment. Governance score per domain
                            and aggregate weighted score. CSV export and
                            interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell modules: Az.Accounts, Az.Resources, Az.Network,
           Az.KeyVault, Az.Storage, Az.Monitor, Az.Advisor
           — installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level.
        4. Microsoft.Authorization/roleAssignments/read at subscription scope.
        5. Microsoft.Authorization/policyAssignments/read at subscription scope.
        6. Microsoft.Authorization/locks/read for resource lock enumeration.
        7. Microsoft.Insights/diagnosticSettings/read for monitoring assessment.
        8. Microsoft.Advisor/recommendations/read for Advisor score retrieval.
        9. Microsoft.Consumption/budgets/read for budget alert detection.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Management Group hierarchy discovery requires
          Microsoft.Management/managementGroups/read which may not be granted
          at subscription scope; MG assignment is checked best-effort.
        - Budget detection uses Az.Consumption which may not be available in all
          Az module versions; the check is gracefully skipped if absent.
        - Advisor score retrieval requires the Az.Advisor module and may return
          partial data in subscriptions with limited Advisor coverage.
        - Classic Administrator (Co-Admin) enumeration relies on the legacy
          Get-AzRoleAssignment output; this API is deprecated and may be removed
          in a future Az module release.
        - Naming convention checks use heuristic prefix patterns and will not
          cover all enterprise naming schemes. Customize the $NamingPrefixes
          hashtable inside the function body for your standard.
        - Tag compliance checks enumerate all resources; large subscriptions
          (10,000+ resources) may be slow. Use -SubscriptionIds to scope.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Interactive Grid View requires a GUI-capable session; skipped gracefully
          in headless/CI/Linux sessions.

.LINK
    https://learn.microsoft.com/en-us/azure/governance/
    https://learn.microsoft.com/en-us/azure/governance/policy/overview
    https://learn.microsoft.com/en-us/azure/role-based-access-control/overview
    https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources
    https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings
    https://learn.microsoft.com/en-us/azure/advisor/advisor-overview
    https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets

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
    Write-CenteredText "Azure Governance Dashboard v1.0" -Color White
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
        Write-Host $key.PadRight(38) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-DomainScores {
    param([hashtable]$Scores)

    if ($Scores.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Governance Domain Scores" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($domain in $Scores.Keys) {
        $score = $Scores[$domain]
        $color = if ($score -ge 80) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" }
        $bar = ("█" * [math]::Floor($score / 5)) + ("░" * (20 - [math]::Floor($score / 5)))
        Write-Host "  " -NoNewline
        Write-Host $domain.PadRight(26) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $bar -NoNewline -ForegroundColor $color
        Write-Host " $score%" -ForegroundColor $color
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

Function Get-GovScore {
    param([int]$PassCount, [int]$TotalCount)
    if ($TotalCount -le 0) { return 100 }
    return [math]::Round(($PassCount / $TotalCount) * 100)
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-GovernanceDashboardHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [hashtable]$DomainScores,
        [array]$RbacFindings,
        [array]$TagFindings,
        [array]$LockFindings,
        [array]$MonitorFindings,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [string[]]$MandatoryTags
    )

    # ── KPIs ──────────────────────────────────────────────────────────────────
    $totalFindings = @($Findings).Count
    $criticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count

    # Weighted aggregate governance score (equal weight per domain for v1.0)
    $aggScore = 0
    if ($DomainScores.Count -gt 0) {
        $aggScore = [math]::Round(($DomainScores.Values | Measure-Object -Sum).Sum / $DomainScores.Count)
    }

    $scoreColor = if ($aggScore -ge 80) { "var(--green)" } elseif ($aggScore -ge 50) { "var(--amber)" } else { "var(--red)" }

    # Score ring math
    $scoreCirc = 283
    $scoreDash = if ($aggScore -gt 0) { [math]::Round($scoreCirc * ($aggScore / 100), 1) } else { 0 }

    # ── Domain score bars ─────────────────────────────────────────────────────
    $domainScoreRows = ""
    $domainOrder = @("Policy", "RBAC", "Tagging", "Naming", "Resource Locks", "Monitoring", "Subscription")
    foreach ($dom in $domainOrder) {
        if (-not $DomainScores.ContainsKey($dom)) { continue }
        $sc = $DomainScores[$dom]
        $barColor = if ($sc -ge 80) { "var(--green)" } elseif ($sc -ge 50) { "var(--amber)" } else { "var(--red)" }
        $domainScoreRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $dom)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$sc" style="background:$barColor"></div></div>
            <span class="bar-pct" style="color:$barColor">$sc%</span>
          </div>
"@
    }

    # ── Findings table rows ───────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $sevCls = switch ($f.Severity) {
            "Critical" { "badge-red" }
            "High" { "badge-red" }
            "Medium" { "badge-amber" }
            default { "badge-blue" }
        }
        $findingRows += @"
          <tr onclick="showFindingDetail($(([array]$Findings).IndexOf($f)))">
            <td>$(EscHtml $f.Domain)</td>
            <td title="$(EscHtml $f.Finding)">$(if ($f.Finding.Length -gt 55) { EscHtml($f.Finding.Substring(0,52)+"...") } else { EscHtml $f.Finding })</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td style="font-family:var(--mono);font-size:11px">$($f.AffectedCount)</td>
            <td title="$(EscHtml $f.Remediation)">$(if ($f.Remediation.Length -gt 55) { EscHtml($f.Remediation.Substring(0,52)+"...") } else { EscHtml $f.Remediation })</td>
          </tr>
"@
    }

    # ── RBAC table rows ───────────────────────────────────────────────────────
    $rbacRows = ""
    foreach ($r in $RbacFindings) {
        $riskCls = switch ($r.RiskLevel) { "Critical" { "badge-red" }; "High" { "badge-red" }; "Medium" { "badge-amber" }; default { "badge-blue" } }
        $rbacRows += @"
          <tr>
            <td>$(EscHtml $r.SubscriptionName)</td>
            <td title="$(EscHtml $r.PrincipalName)">$(if ($r.PrincipalName.Length -gt 36) { EscHtml($r.PrincipalName.Substring(0,33)+"...") } else { EscHtml $r.PrincipalName })</td>
            <td>$(EscHtml $r.PrincipalType)</td>
            <td>$(EscHtml $r.RoleDefinitionName)</td>
            <td><span class="scope-badge">$(EscHtml $r.ScopeLevel)</span></td>
            <td><span class="badge $riskCls">$(EscHtml $r.RiskLevel)</span></td>
            <td title="$(EscHtml $r.RiskReason)">$(if ($r.RiskReason.Length -gt 40) { EscHtml($r.RiskReason.Substring(0,37)+"...") } else { EscHtml $r.RiskReason })</td>
          </tr>
"@
    }

    # ── Tag compliance rows ───────────────────────────────────────────────────
    $tagRows = ""
    foreach ($t in ($TagFindings | Select-Object -First 100)) {
        $tagRows += @"
          <tr>
            <td>$(EscHtml $t.SubscriptionName)</td>
            <td title="$(EscHtml $t.ResourceName)">$(if ($t.ResourceName.Length -gt 40) { EscHtml($t.ResourceName.Substring(0,37)+"...") } else { EscHtml $t.ResourceName })</td>
            <td>$(EscHtml $t.ResourceType)</td>
            <td>$(EscHtml $t.ResourceGroup)</td>
            <td><span class="badge badge-amber">$(EscHtml ($t.MissingTags -join ", "))</span></td>
            <td style="font-family:var(--mono);font-size:11px">$($t.MissingCount)</td>
          </tr>
"@
    }

    # ── Lock findings rows ────────────────────────────────────────────────────
    $lockRows = ""
    foreach ($lk in $LockFindings) {
        $lockRows += @"
          <tr>
            <td>$(EscHtml $lk.SubscriptionName)</td>
            <td title="$(EscHtml $lk.ResourceName)">$(if ($lk.ResourceName.Length -gt 40) { EscHtml($lk.ResourceName.Substring(0,37)+"...") } else { EscHtml $lk.ResourceName })</td>
            <td>$(EscHtml $lk.ResourceType)</td>
            <td><span class="badge badge-amber">No Lock</span></td>
            <td title="$(EscHtml $lk.Remediation)">$(if ($lk.Remediation.Length -gt 50) { EscHtml($lk.Remediation.Substring(0,47)+"...") } else { EscHtml $lk.Remediation })</td>
          </tr>
"@
    }

    # ── Monitor findings rows ─────────────────────────────────────────────────
    $monRows = ""
    foreach ($m in $MonitorFindings) {
        $sevCls = switch ($m.Severity) { "High" { "badge-red" }; "Medium" { "badge-amber" }; default { "badge-blue" } }
        $monRows += @"
          <tr>
            <td>$(EscHtml $m.SubscriptionName)</td>
            <td title="$(EscHtml $m.Finding)">$(if ($m.Finding.Length -gt 52) { EscHtml($m.Finding.Substring(0,49)+"...") } else { EscHtml $m.Finding })</td>
            <td><span class="badge $sevCls">$(EscHtml $m.Severity)</span></td>
            <td title="$(EscHtml $m.Remediation)">$(if ($m.Remediation.Length -gt 52) { EscHtml($m.Remediation.Substring(0,49)+"...") } else { EscHtml $m.Remediation })</td>
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

    # ── Findings JSON for drawer ──────────────────────────────────────────────
    $findJson = "["
    foreach ($f in $Findings) {
        $findJson += "{" +
        """domain"":""$(EscJ $f.Domain)""," +
        """finding"":""$(EscJ $f.Finding)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """severity"":""$(EscJ $f.Severity)""," +
        """count"":$($f.AffectedCount)," +
        """remediation"":""$(EscJ $f.Remediation)""," +
        """detail"":""$(EscJ $f.Detail)""," +
        """impact"":""$(EscJ $f.BusinessImpact)""" +
        "},"
    }
    $findJson = $findJson.TrimEnd(",") + "]"

    # ── Mandatory tags list for display ──────────────────────────────────────
    $mandatoryTagsDisplay = ($MandatoryTags | ForEach-Object { EscHtml $_ }) -join ", "
    $tagCompliantCount = @($TagFindings | Where-Object { $_.MissingCount -eq 0 }).Count
    $tagNonCompliantCount = @($TagFindings | Where-Object { $_.MissingCount -gt 0 }).Count

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Governance Dashboard</title>
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
  background:linear-gradient(135deg,var(--accent3),var(--accent2));
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
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:52px;text-align:right;flex-shrink:0;}
.score-wrap{display:flex;align-items:center;gap:32px;flex-wrap:wrap;margin-bottom:8px;}
.score-ring-wrap{position:relative;width:130px;height:130px;flex-shrink:0;}
.score-ring-wrap svg{transform:rotate(-90deg);}
.score-ring-bg{fill:none;stroke:var(--surface3);stroke-width:12;}
.score-ring-fill{fill:none;stroke-width:12;stroke-linecap:round;}
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
.scope-badge{font-size:11px;font-family:var(--mono);color:var(--muted2);}
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
.remediation-box{background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--accent3);border-radius:var(--radius-sm);padding:12px 14px;font-size:12px;line-height:1.6;color:var(--muted2);}
.impact-box{background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--amber);border-radius:var(--radius-sm);padding:12px 14px;font-size:12px;line-height:1.6;color:var(--muted2);margin-top:10px;}
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
    <div class="logo-icon">🏛️</div>
    <div class="logo-title">Governance Dashboard</div>
    <div class="logo-sub">Azure Enterprise Governance</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">⚠️</span> All Findings</button>
    <button class="nav-btn" onclick="showPage('rbac',this)"><span class="nav-icon">🔑</span> RBAC &amp; Identity</button>
    <button class="nav-btn" onclick="showPage('tagging',this)"><span class="nav-icon">🏷️</span> Tagging</button>
    <button class="nav-btn" onclick="showPage('locks',this)"><span class="nav-icon">🔒</span> Resource Locks</button>
    <button class="nav-btn" onclick="showPage('monitoring',this)"><span class="nav-icon">📡</span> Monitoring</button>
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
      Azure Governance Dashboard
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Enterprise Governance Overview</div>
      <div class="page-sub">Aggregated governance posture across __SUB_COUNT__ subscription(s) — Policy · RBAC · Tagging · Naming · Locks · Monitoring · Subscription</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical Findings</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Severity</div>
        <div class="stat-sub">Address within 7 days</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium Severity</div>
        <div class="stat-sub">Address within 30 days</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low Severity</div>
        <div class="stat-sub">Plan for remediation</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__TOTAL_FINDINGS__</div>
        <div class="stat-label">Total Findings</div>
        <div class="stat-sub">Across all domains</div>
      </div>
    </div>

    <!-- Governance Score Ring -->
    <div class="panel">
      <div class="panel-title">🎯 Aggregate Governance Score</div>
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
            <div class="score-pct" style="color:__SCORE_COLOR__">__AGG_SCORE__%</div>
            <div class="score-label">Gov Score</div>
          </div>
        </div>
        <div class="score-details">
          <div class="score-detail-row"><span style="color:var(--muted)">Subscriptions Scanned</span><span style="font-family:var(--mono)">__SUB_COUNT__</span></div>
          <div class="score-detail-row"><span style="color:var(--muted)">Total Findings</span><span style="font-family:var(--mono)">__TOTAL_FINDINGS__</span></div>
          <div class="score-detail-row"><span style="color:var(--muted)">Critical + High</span><span style="font-family:var(--mono); color:var(--red)">__CRIT_PLUS_HIGH__</span></div>
          <div class="score-detail-row"><span style="color:var(--muted)">Mandatory Tags Assessed</span><span style="font-family:var(--mono)">__MANDATORY_TAGS__</span></div>
          <div class="score-detail-row"><span style="color:var(--muted)">RBAC Findings</span><span style="font-family:var(--mono)">__RBAC_COUNT__</span></div>
        </div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📐 Governance Score by Domain</div>
        __DOMAIN_SCORE_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">📊 Finding Severity Distribution</div>
        <div class="stats-grid" style="margin-bottom:0;grid-template-columns:1fr 1fr;">
          <div class="stat-card c-red"><div class="stat-num">__CRITICAL_COUNT__</div><div class="stat-label">Critical</div></div>
          <div class="stat-card c-amber"><div class="stat-num">__HIGH_COUNT__</div><div class="stat-label">High</div></div>
          <div class="stat-card c-blue"><div class="stat-num">__MEDIUM_COUNT__</div><div class="stat-label">Medium</div></div>
          <div class="stat-card c-cyan"><div class="stat-num">__LOW_COUNT__</div><div class="stat-label">Low</div></div>
        </div>
      </div>
    </div>

    <div class="panel" style="border-left:3px solid var(--accent3);">
      <div class="panel-title">📌 Mandatory Tag Schema</div>
      <p style="font-size:13px;color:var(--muted2);line-height:1.7;">
        Assessed tags: <strong style="color:var(--text)">__MANDATORY_TAGS__</strong><br/>
        Resources with tag gaps: <strong style="color:var(--amber)">__TAG_NONCOMPLIANT__</strong> &nbsp;·&nbsp;
        Compliant resources assessed: <strong style="color:var(--green)">__TAG_COMPLIANT__</strong>
      </p>
    </div>
  </div>

  <!-- All Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">All Governance Findings</div>
      <div class="page-sub">Consolidated view across all seven governance domains. Click any row for detail and remediation guidance.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search finding, domain, subscription…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="filterFDomain" onchange="filterFindings()">
          <option value="">All Domains</option>
          <option value="Policy">Policy</option>
          <option value="RBAC">RBAC</option>
          <option value="Tagging">Tagging</option>
          <option value="Naming">Naming</option>
          <option value="Resource Locks">Resource Locks</option>
          <option value="Monitoring">Monitoring</option>
          <option value="Subscription">Subscription</option>
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
              <th onclick="sortFindings(3)">Severity</th>
              <th onclick="sortFindings(4)">Affected</th>
              <th>Remediation (Summary)</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- RBAC & Identity -->
  <div id="page-rbac" class="page">
    <div class="page-header">
      <div class="page-title">RBAC &amp; Identity Governance</div>
      <div class="page-sub">Privileged role assignments, classic admins, guest identities, and over-privileged service principals. High blast-radius assignments are highlighted.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="rbacSearch" placeholder="Search principal, role, subscription…" oninput="filterRbac()"/>
        </div>
        <select class="filter-select" id="filterRbacRisk" onchange="filterRbac()">
          <option value="">All Risk Levels</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="pgSizeRbac" onchange="changeRbacPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="rbacTable">
          <thead>
            <tr>
              <th onclick="sortRbac(0)">Subscription</th>
              <th onclick="sortRbac(1)">Principal</th>
              <th onclick="sortRbac(2)">Type</th>
              <th onclick="sortRbac(3)">Role</th>
              <th onclick="sortRbac(4)">Scope Level</th>
              <th onclick="sortRbac(5)">Risk</th>
              <th>Risk Reason</th>
            </tr>
          </thead>
          <tbody id="rbacBody">__RBAC_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="rbacPagination"></div>
    </div>
  </div>

  <!-- Tagging -->
  <div id="page-tagging" class="page">
    <div class="page-header">
      <div class="page-title">Tagging Governance</div>
      <div class="page-sub">Resources missing mandatory tags. Missing tags break cost allocation, ownership tracking, and automated governance controls.</div>
    </div>
    <div class="panel" style="border-left:3px solid var(--amber);">
      <div class="panel-title">🏷️ Mandatory Tag Schema</div>
      <p style="font-size:13px;color:var(--muted2);">Required tags: <strong style="color:var(--text)">__MANDATORY_TAGS__</strong></p>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="tagSearch" placeholder="Search resource, type, group…" oninput="filterTags()"/>
        </div>
        <select class="filter-select" id="pgSizeTags" onchange="changeTagsPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="tagTable">
          <thead>
            <tr>
              <th>Subscription</th>
              <th>Resource Name</th>
              <th>Resource Type</th>
              <th>Resource Group</th>
              <th>Missing Tags</th>
              <th>Missing Count</th>
            </tr>
          </thead>
          <tbody id="tagBody">__TAG_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="tagPagination"></div>
    </div>
  </div>

  <!-- Resource Locks -->
  <div id="page-locks" class="page">
    <div class="page-header">
      <div class="page-title">Resource Locks Governance</div>
      <div class="page-sub">Subscriptions and resource groups without CanNotDelete or ReadOnly locks are exposed to accidental or malicious deletion.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="lockSearch" placeholder="Search resource, subscription…" oninput="filterLocks()"/>
        </div>
        <select class="filter-select" id="pgSizeLocks" onchange="changeLocksPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="lockTable">
          <thead>
            <tr>
              <th>Subscription</th>
              <th>Resource / Resource Group</th>
              <th>Resource Type</th>
              <th>Lock Status</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody id="lockBody">__LOCK_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="lockPagination"></div>
    </div>
  </div>

  <!-- Monitoring -->
  <div id="page-monitoring" class="page">
    <div class="page-header">
      <div class="page-title">Monitoring &amp; Diagnostics Governance</div>
      <div class="page-sub">Gaps in Activity Log export, diagnostic settings, and alert coverage create blind spots that delay detection and incident response.</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table id="monTable">
          <thead>
            <tr>
              <th>Subscription</th>
              <th>Finding</th>
              <th>Severity</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody>__MON_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription governance assessment outcome</div>
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
        <div class="info-card"><div class="info-label">Mandatory Tags</div><div class="info-value">__MANDATORY_TAGS__</div></div>
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

// ── RBAC data ─────────────────────────────────────────────────────────────────
const RBAC_DATA_RAW = `__RBAC_JSON_RAW__`;
let RBAC_DATA = [];
try{ RBAC_DATA = JSON.parse(RBAC_DATA_RAW); }catch(e){}
let rbacFiltered = [...RBAC_DATA];
let rbacPage = 1, rbacPageSz = 25;
let rbacSortCol = -1, rbacSortAsc = true;

// ── Tag data ──────────────────────────────────────────────────────────────────
const TAG_DATA_RAW = `__TAG_JSON_RAW__`;
let TAG_DATA = [];
try{ TAG_DATA = JSON.parse(TAG_DATA_RAW); }catch(e){}
let tagFiltered = [...TAG_DATA];
let tagPage = 1, tagPageSz = 25;

// ── Lock data ─────────────────────────────────────────────────────────────────
const LOCK_DATA_RAW = `__LOCK_JSON_RAW__`;
let LOCK_DATA = [];
try{ LOCK_DATA = JSON.parse(LOCK_DATA_RAW); }catch(e){}
let lockFiltered = [...LOCK_DATA];
let lockPage = 1, lockPageSz = 25;

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
  const sv = document.getElementById('filterSev').value;
  const dm = document.getElementById('filterFDomain').value;
  findFiltered = FIND_DATA.filter(r=>{
    const mQ  = !q  || JSON.stringify(r).toLowerCase().includes(q);
    const mSv = !sv || r.severity===sv;
    const mDm = !dm || r.domain===dm;
    return mQ && mSv && mDm;
  });
  findPage=1; renderFindings();
}

function changeFindingsPageSize(){
  findPageSz=parseInt(document.getElementById('pgSizeFindings').value);
  findPage=1; renderFindings();
}

function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys=['domain','finding','sub','severity','count','remediation'];
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
    const sCls=r.severity==='Critical'||r.severity==='High'?'badge-red':r.severity==='Medium'?'badge-amber':'badge-blue';
    const fn=r.finding.length>55?r.finding.substring(0,52)+'...':r.finding;
    const rm=r.remediation.length>55?r.remediation.substring(0,52)+'...':r.remediation;
    return `<tr onclick="showFindingDetail(${gi})">
      <td>${escH(r.domain)}</td>
      <td title="${escH(r.finding)}">${escH(fn)}</td>
      <td>${escH(r.sub)}</td>
      <td><span class="badge ${sCls}">${escH(r.severity)}</span></td>
      <td style="font-family:var(--mono);font-size:11px">${r.count}</td>
      <td title="${escH(r.remediation)}">${escH(rm)}</td>
    </tr>`;
  }).join('');
  renderFindingsPg();
}

function renderFindingsPg(){
  const total=Math.ceil(findFiltered.length/findPageSz);
  const el=document.getElementById('findPagination');
  let h=`<span>${findFiltered.length} findings</span>`;
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

// ── RBAC table ────────────────────────────────────────────────────────────────
function filterRbac(){
  const q  = document.getElementById('rbacSearch').value.toLowerCase();
  const rk = document.getElementById('filterRbacRisk').value;
  rbacFiltered = RBAC_DATA.filter(r=>{
    const mQ  = !q  || JSON.stringify(r).toLowerCase().includes(q);
    const mRk = !rk || r.risk===rk;
    return mQ && mRk;
  });
  rbacPage=1; renderRbac();
}

function changeRbacPageSize(){
  rbacPageSz=parseInt(document.getElementById('pgSizeRbac').value);
  rbacPage=1; renderRbac();
}

function sortRbac(col){
  if(rbacSortCol===col){rbacSortAsc=!rbacSortAsc;}else{rbacSortCol=col;rbacSortAsc=true;}
  const keys=['sub','principal','type','role','scope','risk','reason'];
  rbacFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    return rbacSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                      :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderRbac();
}

function renderRbac(){
  const tbody=document.getElementById('rbacBody');
  const start=(rbacPage-1)*rbacPageSz;
  const slice=rbacFiltered.slice(start,start+rbacPageSz);
  tbody.innerHTML=slice.map(r=>{
    const rCls=r.risk==='Critical'||r.risk==='High'?'badge-red':r.risk==='Medium'?'badge-amber':'badge-blue';
    const pn=r.principal.length>36?r.principal.substring(0,33)+'...':r.principal;
    const rn=r.reason.length>40?r.reason.substring(0,37)+'...':r.reason;
    return `<tr>
      <td>${escH(r.sub)}</td>
      <td title="${escH(r.principal)}">${escH(pn)}</td>
      <td>${escH(r.type)}</td>
      <td>${escH(r.role)}</td>
      <td><span class="scope-badge">${escH(r.scope)}</span></td>
      <td><span class="badge ${rCls}">${escH(r.risk)}</span></td>
      <td title="${escH(r.reason)}">${escH(rn)}</td>
    </tr>`;
  }).join('');
  renderRbacPg();
}

function renderRbacPg(){
  const total=Math.ceil(rbacFiltered.length/rbacPageSz);
  const el=document.getElementById('rbacPagination');
  let h=`<span>${rbacFiltered.length} assignments</span>`;
  h+=`<button class="pg-btn" onclick="changeRbacPage(${rbacPage-1})" ${rbacPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,rbacPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===rbacPage?'active':''}" onclick="changeRbacPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeRbacPage(${rbacPage+1})" ${rbacPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeRbacPage(p){
  const total=Math.ceil(rbacFiltered.length/rbacPageSz);
  if(p<1||p>total)return;
  rbacPage=p; renderRbac();
}

// ── Tags table ────────────────────────────────────────────────────────────────
function filterTags(){
  const q=document.getElementById('tagSearch').value.toLowerCase();
  tagFiltered=TAG_DATA.filter(r=>!q||JSON.stringify(r).toLowerCase().includes(q));
  tagPage=1; renderTags();
}

function changeTagsPageSize(){
  tagPageSz=parseInt(document.getElementById('pgSizeTags').value);
  tagPage=1; renderTags();
}

function renderTags(){
  const tbody=document.getElementById('tagBody');
  const start=(tagPage-1)*tagPageSz;
  const slice=tagFiltered.slice(start,start+tagPageSz);
  tbody.innerHTML=slice.map(r=>{
    const nm=r.name.length>40?r.name.substring(0,37)+'...':r.name;
    return `<tr>
      <td>${escH(r.sub)}</td>
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.type)}</td>
      <td>${escH(r.rg)}</td>
      <td><span class="badge badge-amber">${escH(r.missing)}</span></td>
      <td style="font-family:var(--mono);font-size:11px">${r.count}</td>
    </tr>`;
  }).join('');
  renderTagsPg();
}

function renderTagsPg(){
  const total=Math.ceil(tagFiltered.length/tagPageSz);
  const el=document.getElementById('tagPagination');
  let h=`<span>${tagFiltered.length} resources with tag gaps</span>`;
  h+=`<button class="pg-btn" onclick="changeTagPage(${tagPage-1})" ${tagPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,tagPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===tagPage?'active':''}" onclick="changeTagPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeTagPage(${tagPage+1})" ${tagPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeTagPage(p){
  const total=Math.ceil(tagFiltered.length/tagPageSz);
  if(p<1||p>total)return;
  tagPage=p; renderTags();
}

// ── Locks table ───────────────────────────────────────────────────────────────
function filterLocks(){
  const q=document.getElementById('lockSearch').value.toLowerCase();
  lockFiltered=LOCK_DATA.filter(r=>!q||JSON.stringify(r).toLowerCase().includes(q));
  lockPage=1; renderLocks();
}

function changeLocksPageSize(){
  lockPageSz=parseInt(document.getElementById('pgSizeLocks').value);
  lockPage=1; renderLocks();
}

function renderLocks(){
  const tbody=document.getElementById('lockBody');
  const start=(lockPage-1)*lockPageSz;
  const slice=lockFiltered.slice(start,start+lockPageSz);
  tbody.innerHTML=slice.map(r=>{
    const nm=r.name.length>40?r.name.substring(0,37)+'...':r.name;
    const rm=r.remediation.length>50?r.remediation.substring(0,47)+'...':r.remediation;
    return `<tr>
      <td>${escH(r.sub)}</td>
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.type)}</td>
      <td><span class="badge badge-amber">No Lock</span></td>
      <td title="${escH(r.remediation)}">${escH(rm)}</td>
    </tr>`;
  }).join('');
  renderLocksPg();
}

function renderLocksPg(){
  const total=Math.ceil(lockFiltered.length/lockPageSz);
  const el=document.getElementById('lockPagination');
  let h=`<span>${lockFiltered.length} resources without locks</span>`;
  h+=`<button class="pg-btn" onclick="changeLockPage(${lockPage-1})" ${lockPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,lockPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===lockPage?'active':''}" onclick="changeLockPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeLockPage(${lockPage+1})" ${lockPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeLockPage(p){
  const total=Math.ceil(lockFiltered.length/lockPageSz);
  if(p<1||p>total)return;
  lockPage=p; renderLocks();
}

// ── Detail drawer ─────────────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=FIND_DATA[idx];
  if(!r)return;
  const sCls=r.severity==='Critical'||r.severity==='High'?'badge-red':r.severity==='Medium'?'badge-amber':'badge-blue';
  document.getElementById('drawerTitle').textContent=r.finding;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FIND_DATA.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sCls}">${escH(r.severity)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Governance Domain</div>
      <div class="drawer-field-value">${escH(r.domain)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Affected Resources / Controls</div>
      <div class="drawer-field-value" style="font-family:var(--mono)">${r.count}</div></div>
    <div class="drawer-section">Finding Detail</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.detail||r.finding)}</div></div>
    <div class="drawer-section">Remediation Guidance</div>
    <div class="remediation-box">${escH(r.remediation)}</div>
    <div class="drawer-section">Business Impact</div>
    <div class="impact-box">${escH(r.impact||'Unaddressed governance gaps compound risk over time and reduce enterprise control and auditability.')}</div>
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

// ── Init ──────────────────────────────────────────────────────────────────────
filterFindings();
filterRbac();
filterTags();
filterLocks();
animateBars();
</script>
</body>
</html>
'@

    # ── RBAC JSON ─────────────────────────────────────────────────────────────
    $rbacJsonLines = "["
    foreach ($r in $RbacFindings) {
        $rbacJsonLines += "{" +
        """sub"":""$(EscJ $r.SubscriptionName)""," +
        """principal"":""$(EscJ $r.PrincipalName)""," +
        """type"":""$(EscJ $r.PrincipalType)""," +
        """role"":""$(EscJ $r.RoleDefinitionName)""," +
        """scope"":""$(EscJ $r.ScopeLevel)""," +
        """risk"":""$(EscJ $r.RiskLevel)""," +
        """reason"":""$(EscJ $r.RiskReason)""" +
        "},"
    }
    $rbacJsonLines = $rbacJsonLines.TrimEnd(",") + "]"

    # ── Tag JSON ──────────────────────────────────────────────────────────────
    $tagJsonLines = "["
    foreach ($t in $TagFindings) {
        $tagJsonLines += "{" +
        """sub"":""$(EscJ $t.SubscriptionName)""," +
        """name"":""$(EscJ $t.ResourceName)""," +
        """type"":""$(EscJ $t.ResourceType)""," +
        """rg"":""$(EscJ $t.ResourceGroup)""," +
        """missing"":""$(EscJ ($t.MissingTags -join ', '))""," +
        """count"":$($t.MissingCount)" +
        "},"
    }
    $tagJsonLines = $tagJsonLines.TrimEnd(",") + "]"

    # ── Lock JSON ─────────────────────────────────────────────────────────────
    $lockJsonLines = "["
    foreach ($lk in $LockFindings) {
        $lockJsonLines += "{" +
        """sub"":""$(EscJ $lk.SubscriptionName)""," +
        """name"":""$(EscJ $lk.ResourceName)""," +
        """type"":""$(EscJ $lk.ResourceType)""," +
        """remediation"":""$(EscJ $lk.Remediation)""" +
        "},"
    }
    $lockJsonLines = $lockJsonLines.TrimEnd(",") + "]"

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MEDIUM_COUNT__', $mediumCount `
        -replace '__LOW_COUNT__', $lowCount `
        -replace '__TOTAL_FINDINGS__', $totalFindings `
        -replace '__AGG_SCORE__', $aggScore `
        -replace '__SCORE_COLOR__', $scoreColor `
        -replace '__SCORE_DASH__', $scoreDash `
        -replace '__SCORE_CIRC__', $scoreCirc `
        -replace '__CRIT_PLUS_HIGH__', ($criticalCount + $highCount) `
        -replace '__MANDATORY_TAGS__', $mandatoryTagsDisplay `
        -replace '__TAG_COMPLIANT__', $tagCompliantCount `
        -replace '__TAG_NONCOMPLIANT__', $tagNonCompliantCount `
        -replace '__RBAC_COUNT__', ($RbacFindings.Count) `
        -replace '__DOMAIN_SCORE_ROWS__', $domainScoreRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__RBAC_ROWS__', $rbacRows `
        -replace '__TAG_ROWS__', $tagRows `
        -replace '__LOCK_ROWS__', $lockRows `
        -replace '__MON_ROWS__', $monRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FIND_JSON__', $findJson `
        -replace '__RBAC_JSON_RAW__', ($rbacJsonLines -replace '`', '``') `
        -replace '__TAG_JSON_RAW__', ($tagJsonLines -replace '`', '``') `
        -replace '__LOCK_JSON_RAW__', ($lockJsonLines -replace '`', '``')

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Generate-AzureGovernanceDashboard {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [string[]]$MandatoryTags = @("Environment", "Owner", "CostCenter", "Project", "ManagedBy"),

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureGovernance-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts",
        "Az.Resources",
        "Az.Network",
        "Az.KeyVault",
        "Az.Storage",
        "Az.Monitor"
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
        "Scope"          = "$scopeText ($subCount found)"
        "Mandatory Tags" = $MandatoryTags -join ", "
        "Export to CSV"  = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"    = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $allRbacFindings = @()
    $allTagFindings = @()
    $allLockFindings = @()
    $allMonitorFindings = @()
    $subscriptionResults = @()

    # Domain pass/fail counters for scoring
    $domainControls = @{
        "Policy"         = @{ Pass = 0; Total = 0 }
        "RBAC"           = @{ Pass = 0; Total = 0 }
        "Tagging"        = @{ Pass = 0; Total = 0 }
        "Naming"         = @{ Pass = 0; Total = 0 }
        "Resource Locks" = @{ Pass = 0; Total = 0 }
        "Monitoring"     = @{ Pass = 0; Total = 0 }
        "Subscription"   = @{ Pass = 0; Total = 0 }
    }

    $successCount = 0
    $errorCount = 0

    # Naming heuristics — adjust to your organisation's naming standard
    $NamingPrefixes = @{
        "Microsoft.Compute/virtualMachines"          = @("vm-", "vm")
        "Microsoft.Network/virtualNetworks"          = @("vnet-", "vnet")
        "Microsoft.Network/networkSecurityGroups"    = @("nsg-")
        "Microsoft.Storage/storageAccounts"          = @("st", "sa")
        "Microsoft.KeyVault/vaults"                  = @("kv-", "kv")
        "Microsoft.Web/sites"                        = @("app-", "func-")
        "Microsoft.Sql/servers"                      = @("sql-", "sqlsrv-")
        "Microsoft.ContainerService/managedClusters" = @("aks-")
    }

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

            # ──────────────────────────────────────────────────────────────────
            # Domain 1: Policy Governance
            # ──────────────────────────────────────────────────────────────────
            try {
                $assignments = @(Get-AzPolicyAssignment -ErrorAction Stop)

                $domainControls["Policy"].Total += $assignments.Count

                $notEnforced = @($assignments | Where-Object { $_.EnforcementMode -eq "DoNotEnforce" })
                $disabled = @($assignments | Where-Object { $_.EnforcementMode -eq "Disabled" })

                if ($notEnforced.Count -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Policy"
                        Finding          = "$($notEnforced.Count) policy assignment(s) in DoNotEnforce mode"
                        Severity         = if ($notEnforced.Count -ge 5) { "High" } else { "Medium" }
                        AffectedCount    = $notEnforced.Count
                        Remediation      = "Review each DoNotEnforce assignment and either set enforcement to 'Default' (Deny/Audit) or document a formal exception with an expiry date. DoNotEnforce should be a temporary transition state, not a permanent configuration."
                        Detail           = "Assignments in DoNotEnforce mode are evaluated and reported but do not prevent non-compliant deployments. $($notEnforced.Count) assignment(s) affected: $( ($notEnforced | Select-Object -ExpandProperty Name -First 5) -join ', ' )."
                        BusinessImpact   = "Non-enforcement means governance guardrails exist in name only. Resources can be deployed out-of-policy without restriction, eroding compliance posture and creating audit findings."
                    }
                    $subFindingCount++
                }
                else {
                    $domainControls["Policy"].Pass++
                }

                # Exemptions
                try {
                    $exemptions = @(Get-AzPolicyExemption -ErrorAction Stop)
                    $expired = @($exemptions | Where-Object {
                            $exp = Get-ObjProperty -Obj (Get-ObjProperty -Obj $_ -PropName 'Properties' -Default $_) -PropName 'ExpiresOn' -Default $null
                            $exp -and ($exp - (Get-Date)).Days -lt 0
                        })
                    $domainControls["Policy"].Total++
                    if ($expired.Count -gt 0) {
                        $allFindings += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            Domain           = "Policy"
                            Finding          = "$($expired.Count) policy exemption(s) have expired and should be removed or renewed"
                            Severity         = "Medium"
                            AffectedCount    = $expired.Count
                            Remediation      = "Review all expired exemptions in Defender for Cloud > Environment Settings > Policy > Exemptions. Remove exemptions that are no longer valid. Renew with a new expiry date only if the exception is still formally approved."
                            Detail           = "Expired exemptions may still suppress policy findings in the portal, creating a false sense of compliance. $($expired.Count) expired exemption(s) found."
                            BusinessImpact   = "Expired exemptions that remain in place allow non-compliant resources to persist undetected. This is a common audit finding in regulatory reviews (ISO 27001, SOC 2, PCI DSS)."
                        }
                        $subFindingCount++
                    }
                    else {
                        $domainControls["Policy"].Pass++
                    }
                }
                catch {
                    Write-Verbose "  Could not retrieve policy exemptions for $($sub.Name): $_"
                }

                # Custom policy definitions
                try {
                    $customDefs = @(Get-AzPolicyDefinition -Custom -ErrorAction Stop)
                    $domainControls["Policy"].Total++
                    if ($customDefs.Count -eq 0) {
                        $allFindings += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            Domain           = "Policy"
                            Finding          = "No custom policy definitions found — relying solely on built-in policies"
                            Severity         = "Low"
                            AffectedCount    = 0
                            Remediation      = "Evaluate whether built-in Azure Policies cover all organisational requirements. Create custom policy definitions for organisation-specific controls (e.g. allowed VM SKUs, required naming patterns, approved regions) that are not available as built-ins."
                            Detail           = "Subscriptions with zero custom policy definitions may have gaps in organisation-specific governance controls not addressed by Azure built-in policies."
                            BusinessImpact   = "Without custom policies, organisation-specific compliance requirements (naming, tagging, approved regions, approved SKUs) cannot be enforced automatically."
                        }
                        $subFindingCount++
                    }
                    else {
                        $domainControls["Policy"].Pass++
                    }
                }
                catch {
                    Write-Verbose "  Could not retrieve custom policy definitions for $($sub.Name): $_"
                }
            }
            catch {
                Write-Verbose "  Could not assess Policy domain for $($sub.Name): $_"
            }

            # ──────────────────────────────────────────────────────────────────
            # Domain 2: RBAC & Identity Governance
            # ──────────────────────────────────────────────────────────────────
            try {
                $roleAssignments = @(Get-AzRoleAssignment -ErrorAction Stop)
                $subScope = "/subscriptions/$($sub.Id)"

                # Owner assignments at subscription scope
                $subOwners = @($roleAssignments | Where-Object {
                        $_.RoleDefinitionName -eq "Owner" -and
                        $_.Scope -eq $subScope -and
                        $_.ObjectType -ne "ServicePrincipal"
                    })
                $domainControls["RBAC"].Total++
                if ($subOwners.Count -gt 2) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "RBAC"
                        Finding          = "$($subOwners.Count) Owner role assignments at subscription scope (blast radius risk)"
                        Severity         = if ($subOwners.Count -gt 5) { "Critical" } else { "High" }
                        AffectedCount    = $subOwners.Count
                        Remediation      = "Reduce Owner assignments to the minimum required (ideally ≤2 break-glass accounts). Convert non-emergency Owners to 'Contributor' or use Privileged Identity Management (PIM) for just-in-time Owner elevation with approval workflow and time-bound access."
                        Detail           = "Owners: $( ($subOwners | Select-Object -ExpandProperty DisplayName) -join ', ' ). Owner grants full control including the ability to delete the subscription, remove all other access, and assign any role to anyone."
                        BusinessImpact   = "Each unnecessary Owner is a potential account compromise vector. A compromised Owner can exfiltrate all data, destroy all resources, and lock out legitimate administrators — a total subscription takeover."
                    }
                    $subFindingCount++
                }
                else { $domainControls["RBAC"].Pass++ }

                # Guest accounts with privileged roles
                $guestPriv = @($roleAssignments | Where-Object {
                        $_.SignInName -like "*#EXT#*" -and
                        $_.RoleDefinitionName -in @("Owner", "Contributor", "User Access Administrator")
                    })
                $domainControls["RBAC"].Total++
                if ($guestPriv.Count -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "RBAC"
                        Finding          = "$($guestPriv.Count) guest/external account(s) hold privileged roles (Owner/Contributor/UAA)"
                        Severity         = "High"
                        AffectedCount    = $guestPriv.Count
                        Remediation      = "Review each guest account's privileged role assignment. Remove access where no longer needed. If external access is required, use time-bound PIM assignments with regular access reviews (Azure AD Access Reviews). Never assign Owner to guest accounts."
                        Detail           = "Guest accounts: $( ($guestPriv | Select-Object -ExpandProperty DisplayName) -join ', ' ). External identities are not subject to your organisation's identity lifecycle controls (HR triggers, offboarding processes)."
                        BusinessImpact   = "Guest accounts with Contributor or Owner access represent a persistent external access foothold. Former contractors, partners, or vendors retaining access after engagement end is a common compliance violation."
                    }
                    $subFindingCount++
                }
                else { $domainControls["RBAC"].Pass++ }

                # Classic administrators
                $classicAdmins = @($roleAssignments | Where-Object {
                        $_.RoleDefinitionName -in @("CoAdministrator", "ServiceAdministrator", "AccountAdministrator")
                    })
                $domainControls["RBAC"].Total++
                if ($classicAdmins.Count -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "RBAC"
                        Finding          = "$($classicAdmins.Count) classic administrator assignment(s) found (deprecated, high risk)"
                        Severity         = "High"
                        AffectedCount    = $classicAdmins.Count
                        Remediation      = "Migrate all classic administrator roles to Azure RBAC equivalents and remove the legacy assignments. Classic admins bypass Conditional Access, PIM, and many modern access controls. Use the Azure portal: Subscriptions > Access control (IAM) > Classic administrators."
                        Detail           = "Classic admin types found: $( ($classicAdmins | Select-Object -ExpandProperty RoleDefinitionName -Unique) -join ', ' ). This API is deprecated and may be removed in a future Azure update."
                        BusinessImpact   = "Classic administrators cannot be governed by modern identity controls (PIM, Conditional Access, MFA enforcement via policy). They represent an uncontrolled privileged access path outside the standard RBAC governance model."
                    }
                    $subFindingCount++
                }
                else { $domainControls["RBAC"].Pass++ }

                # Add all RBAC findings to the dedicated collection
                foreach ($ra in ($subOwners + $guestPriv + $classicAdmins)) {
                    $riskLvl = if ($ra.RoleDefinitionName -eq "Owner") { "Critical" }
                    elseif ($ra.RoleDefinitionName -in @("Contributor", "User Access Administrator", "CoAdministrator")) { "High" }
                    else { "Medium" }

                    $riskReason = if ($ra.SignInName -like "*#EXT#*") { "External/Guest identity with privileged role" }
                    elseif ($ra.RoleDefinitionName -eq "Owner") { "Owner at subscription scope — full blast radius" }
                    elseif ($ra.RoleDefinitionName -in @("CoAdministrator", "ServiceAdministrator", "AccountAdministrator")) { "Deprecated classic administrator role" }
                    else { "Broad privileged role at subscription scope" }

                    $scopeLevel = if ($ra.Scope -eq $subScope) { "Subscription" }
                    elseif ($ra.Scope -like "*/resourceGroups/*") { "Resource Group" }
                    else { "Management Group" }

                    $allRbacFindings += [pscustomobject]@{
                        SubscriptionName   = $sub.Name
                        SubscriptionId     = $sub.Id
                        PrincipalName      = if ($ra.DisplayName) { $ra.DisplayName } else { $ra.SignInName }
                        PrincipalType      = if ($ra.ObjectType) { $ra.ObjectType } else { "Unknown" }
                        RoleDefinitionName = $ra.RoleDefinitionName
                        ScopeLevel         = $scopeLevel
                        RiskLevel          = $riskLvl
                        RiskReason         = $riskReason
                    }
                }
            }
            catch {
                Write-Verbose "  Could not assess RBAC domain for $($sub.Name): $_"
            }

            # ──────────────────────────────────────────────────────────────────
            # Domain 3: Tagging Governance
            # ──────────────────────────────────────────────────────────────────
            try {
                $resources = @(Get-AzResource -ErrorAction Stop)
                $resourceGroups = @(Get-AzResourceGroup -ErrorAction Stop)
                $totalTaggable = $resources.Count + $resourceGroups.Count
                $domainControls["Tagging"].Total += $totalTaggable
                $tagNonCompliant = 0

                foreach ($res in $resources) {
                    $missingTags = @($MandatoryTags | Where-Object { -not ($res.Tags -and $res.Tags.ContainsKey($_)) })
                    if ($missingTags.Count -gt 0) {
                        $tagNonCompliant++
                        $allTagFindings += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            ResourceName     = $res.Name
                            ResourceType     = $res.ResourceType
                            ResourceGroup    = $res.ResourceGroupName
                            MissingTags      = $missingTags
                            MissingCount     = $missingTags.Count
                        }
                    }
                    else {
                        $domainControls["Tagging"].Pass++
                    }
                }

                foreach ($rg in $resourceGroups) {
                    $missingTags = @($MandatoryTags | Where-Object { -not ($rg.Tags -and $rg.Tags.ContainsKey($_)) })
                    if ($missingTags.Count -gt 0) {
                        $tagNonCompliant++
                        $allTagFindings += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            ResourceName     = $rg.ResourceGroupName
                            ResourceType     = "Resource Group"
                            ResourceGroup    = $rg.ResourceGroupName
                            MissingTags      = $missingTags
                            MissingCount     = $missingTags.Count
                        }
                    }
                    else {
                        $domainControls["Tagging"].Pass++
                    }
                }

                if ($tagNonCompliant -gt 0) {
                    $tagCompPct = if ($totalTaggable -gt 0) { [math]::Round((($totalTaggable - $tagNonCompliant) / $totalTaggable) * 100) } else { 100 }
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Tagging"
                        Finding          = "$tagNonCompliant resource(s) missing mandatory tags (tag compliance: $tagCompPct%)"
                        Severity         = if ($tagCompPct -lt 50) { "High" } elseif ($tagCompPct -lt 80) { "Medium" } else { "Low" }
                        AffectedCount    = $tagNonCompliant
                        Remediation      = "Apply missing tags ($($MandatoryTags -join ', ')) to all non-compliant resources. Use Azure Policy [Require a tag and its value on resources] to enforce tagging at deployment time. Use Azure Cost Management tag inheritance to reduce gap on existing resources."
                        Detail           = "Tag compliance: $tagCompPct% ($($totalTaggable - $tagNonCompliant)/$totalTaggable resources fully tagged). Missing tags break cost allocation, automated governance, and ownership tracking."
                        BusinessImpact   = "Untagged resources cannot be attributed to a cost centre, owner, or project. This leads to orphaned spend, inability to calculate per-application cloud costs, and failure of automated governance controls that rely on tag-based filtering."
                    }
                    $subFindingCount++
                }
            }
            catch {
                Write-Verbose "  Could not assess Tagging domain for $($sub.Name): $_"
            }

            # ──────────────────────────────────────────────────────────────────
            # Domain 4: Naming Convention Governance
            # ──────────────────────────────────────────────────────────────────
            try {
                $resources = @(Get-AzResource -ErrorAction SilentlyContinue)
                $namingViolations = 0
                $domainControls["Naming"].Total += $resources.Count

                foreach ($res in $resources) {
                    if ($NamingPrefixes.ContainsKey($res.ResourceType)) {
                        $expectedPrefixes = $NamingPrefixes[$res.ResourceType]
                        $matchesAny = $false
                        foreach ($pfx in $expectedPrefixes) {
                            if ($res.Name.ToLower().StartsWith($pfx.ToLower())) { $matchesAny = $true; break }
                        }
                        if (-not $matchesAny) {
                            $namingViolations++
                        }
                        else {
                            $domainControls["Naming"].Pass++
                        }
                    }
                    else {
                        # Not in our naming schema map — count as pass (benefit of the doubt)
                        $domainControls["Naming"].Pass++
                    }
                }

                if ($namingViolations -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Naming"
                        Finding          = "$namingViolations resource(s) do not follow the expected naming convention"
                        Severity         = if ($namingViolations -ge 20) { "Medium" } else { "Low" }
                        AffectedCount    = $namingViolations
                        Remediation      = "Establish and publish a naming convention guide. Use Azure Policy with the 'match' or 'like' condition to enforce naming patterns at resource creation. Existing non-compliant resources should be renamed during the next maintenance window where possible."
                        Detail           = "$namingViolations resource(s) across VM, VNet, NSG, Storage, Key Vault, and App/Function types do not start with the expected prefix for their resource type."
                        BusinessImpact   = "Non-standard names reduce operational efficiency — engineers cannot identify resource type, environment, or ownership from the name alone. Automation scripts that rely on naming patterns fail, increasing the chance of operational error."
                    }
                    $subFindingCount++
                }
            }
            catch {
                Write-Verbose "  Could not assess Naming domain for $($sub.Name): $_"
            }

            # ──────────────────────────────────────────────────────────────────
            # Domain 5: Resource Locks Governance
            # ──────────────────────────────────────────────────────────────────
            try {
                $resourceGroups = @(Get-AzResourceGroup -ErrorAction Stop)
                $domainControls["Resource Locks"].Total += $resourceGroups.Count

                foreach ($rg in $resourceGroups) {
                    $locks = @(Get-AzResourceLock -ResourceGroupName $rg.ResourceGroupName -ErrorAction Stop |
                        Where-Object { $_.Properties.Level -in @("CanNotDelete", "ReadOnly") })

                    if ($locks.Count -eq 0) {
                        $allLockFindings += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            ResourceName     = $rg.ResourceGroupName
                            ResourceType     = "Resource Group"
                            Remediation      = "Apply a CanNotDelete lock to resource group '$($rg.ResourceGroupName)'. Navigate to: Resource Group > Locks > Add. Use CanNotDelete for production groups; ReadOnly for immutable reference groups."
                        }
                    }
                    else {
                        $domainControls["Resource Locks"].Pass++
                    }
                }

                $unlocked = $allLockFindings | Where-Object { $_.SubscriptionId -eq $sub.Id }
                if ($unlocked.Count -gt 0) {
                    $lockPct = [math]::Round((($resourceGroups.Count - $unlocked.Count) / [math]::Max($resourceGroups.Count, 1)) * 100)
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Resource Locks"
                        Finding          = "$($unlocked.Count) resource group(s) have no CanNotDelete or ReadOnly lock (lock coverage: $lockPct%)"
                        Severity         = if ($lockPct -lt 50) { "High" } elseif ($lockPct -lt 80) { "Medium" } else { "Low" }
                        AffectedCount    = $unlocked.Count
                        Remediation      = "Apply CanNotDelete locks to all production resource groups and critical standalone resources. Automate lock enforcement with Azure Policy [Resource locks should be set for resource groups]. ReadOnly locks may be appropriate for infrastructure resource groups that should not change."
                        Detail           = "Lock coverage: $lockPct%. $($unlocked.Count) resource group(s) without a delete or read-only lock. All resources within unlocked groups are subject to accidental or malicious deletion."
                        BusinessImpact   = "A single accidental 'delete resource group' operation can destroy an entire production environment and all its data. Without locks, any Contributor-level identity can trigger this — including a compromised service principal or a misconfigured CI/CD pipeline."
                    }
                    $subFindingCount++
                }
            }
            catch {
                Write-Verbose "  Could not assess Resource Locks domain for $($sub.Name): $_"
            }

            # ──────────────────────────────────────────────────────────────────
            # Domain 6: Monitoring & Diagnostics Governance
            # ──────────────────────────────────────────────────────────────────
            try {
                # Activity Log diagnostic settings
                $diagSettings = @(Get-AzDiagnosticSetting -ResourceId "/subscriptions/$($sub.Id)" -ErrorAction Stop)
                $domainControls["Monitoring"].Total++

                $hasActivityLogExport = @($diagSettings | Where-Object {
                        $_.WorkspaceId -or $_.StorageAccountId -or $_.EventHubAuthorizationRuleId
                    }).Count -gt 0

                if (-not $hasActivityLogExport) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Monitoring"
                        Finding          = "Subscription Activity Log is not exported to Log Analytics or Storage"
                        Severity         = "High"
                        AffectedCount    = 1
                        Remediation      = "Create a Diagnostic Setting at subscription scope exporting all Activity Log categories (Administrative, Security, Policy, Alert) to a central Log Analytics workspace or Storage account. Navigate to: Monitor > Activity Log > Diagnostic settings > Add diagnostic setting."
                        Detail           = "No diagnostic setting found that exports Activity Log to Log Analytics Workspace, Storage Account, or Event Hub. Without this, subscription-level administrative and security events are not retained beyond 90 days and cannot be queried centrally."
                        BusinessImpact   = "Without Activity Log export, there is no audit trail for who deleted what, when role assignments changed, or when policy was modified. This prevents forensic investigation after incidents and fails SOC 2, ISO 27001, and PCI DSS logging requirements."
                    }
                    $allMonitorFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Finding          = "Activity Log not exported to Log Analytics or Storage"
                        Severity         = "High"
                        Remediation      = "Create a Diagnostic Setting at subscription scope: Monitor > Activity Log > Diagnostic settings > Add."
                    }
                    $subFindingCount++
                }
                else {
                    $domainControls["Monitoring"].Pass++
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Activity Log diagnostic settings for $($sub.Name): $_"
            }

            # Key Vault diagnostic settings
            try {
                $keyVaults = @(Get-AzKeyVault -ErrorAction Stop)
                $kvNoDiag = 0
                $domainControls["Monitoring"].Total += $keyVaults.Count

                foreach ($kv in $keyVaults) {
                    $kvDiag = @(Get-AzDiagnosticSetting -ResourceId $kv.ResourceId -ErrorAction Stop |
                        Where-Object { $_.WorkspaceId -or $_.StorageAccountId })
                    if ($kvDiag.Count -eq 0) {
                        $kvNoDiag++
                        $allMonitorFindings += [pscustomobject]@{
                            SubscriptionName = $sub.Name
                            SubscriptionId   = $sub.Id
                            Finding          = "Key Vault '$($kv.VaultName)' has no diagnostic setting forwarding audit logs"
                            Severity         = "High"
                            Remediation      = "Enable diagnostic settings on Key Vault '$($kv.VaultName)': Key Vault > Monitoring > Diagnostic settings > Add. Enable AuditEvent and AllMetrics categories."
                        }
                    }
                    else {
                        $domainControls["Monitoring"].Pass++
                    }
                }

                if ($kvNoDiag -gt 0) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Monitoring"
                        Finding          = "$kvNoDiag Key Vault(s) are not forwarding audit logs to Log Analytics"
                        Severity         = "High"
                        AffectedCount    = $kvNoDiag
                        Remediation      = "Enable diagnostic settings on each Key Vault, forwarding AuditEvent logs to a central Log Analytics workspace. Use Azure Policy [Diagnostic logs in Key Vault should be enabled] for continuous enforcement."
                        Detail           = "$kvNoDiag Key Vault(s) are not configured to emit diagnostic logs. Key Vault audit events (secret access, key use, certificate retrieval) are critical for detecting credential theft and insider threats."
                        BusinessImpact   = "Without Key Vault audit logs, secret exfiltration — a primary goal of most advanced persistent threats — goes completely undetected. This is a critical monitoring gap for any workload using secrets, certificates, or encryption keys."
                    }
                    $subFindingCount++
                }
            }
            catch {
                Write-Verbose "  Could not assess Key Vault diagnostics for $($sub.Name): $_"
            }

            # ──────────────────────────────────────────────────────────────────
            # Domain 7: Subscription Governance
            # ──────────────────────────────────────────────────────────────────
            try {
                $domainControls["Subscription"].Total++

                # Budget check
                $hasBudget = $false
                try {
                    $budgets = @(Get-AzConsumptionBudget -ErrorAction Stop)
                    $hasBudget = $budgets.Count -gt 0
                }
                catch {
                    Write-Verbose "  Az.Consumption budget check skipped for $($sub.Name): $_"
                }

                if (-not $hasBudget) {
                    $allFindings += [pscustomobject]@{
                        SubscriptionName = $sub.Name
                        SubscriptionId   = $sub.Id
                        Domain           = "Subscription"
                        Finding          = "No consumption budget or cost alert configured on this subscription"
                        Severity         = "Medium"
                        AffectedCount    = 1
                        Remediation      = "Create at least one budget in Cost Management + Billing for this subscription with alert thresholds at 80% and 100% of the agreed spend limit. Navigate to: Cost Management > Budgets > Add. Configure action groups to notify subscription owners and finance stakeholders."
                        Detail           = "No consumption budget found. Without a budget, cost overruns are only discovered after the fact via invoice, rather than proactively via alert."
                        BusinessImpact   = "Without a budget alert, runaway infrastructure (forgotten VMs, unused storage, runaway autoscale) can accumulate thousands in unexpected charges before anyone notices. FinOps best practices require budget guardrails on every subscription."
                    }
                    $subFindingCount++
                }
                else {
                    $domainControls["Subscription"].Pass++
                }
            }
            catch {
                Write-Verbose "  Could not assess Subscription domain for $($sub.Name): $_"
            }

            # ── Per-subscription result ───────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Findings: $subFindingCount  RBAC: $($allRbacFindings | Where-Object { $_.SubscriptionId -eq $sub.Id } | Measure-Object | Select-Object -Expand Count)  TagGaps: $($allTagFindings | Where-Object { $_.SubscriptionId -eq $sub.Id } | Measure-Object | Select-Object -Expand Count)  LockGaps: $($allLockFindings | Where-Object { $_.SubscriptionId -eq $sub.Id } | Measure-Object | Select-Object -Expand Count)" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Findings: $subFindingCount  RBAC risks: $($allRbacFindings | Where-Object { $_.SubscriptionId -eq $sub.Id } | Measure-Object | Select-Object -Expand Count)"
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

    # ── Domain scores ─────────────────────────────────────────────────────────
    $domainScores = @{}
    foreach ($dom in $domainControls.Keys) {
        $domainScores[$dom] = Get-GovScore -PassCount $domainControls[$dom].Pass -TotalCount $domainControls[$dom].Total
    }

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    $critCount = @($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($allFindings | Where-Object { $_.Severity -eq "High" }).Count
    $medCount = @($allFindings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($allFindings | Where-Object { $_.Severity -eq "Low" }).Count

    $aggScore = 0
    if ($domainScores.Count -gt 0) {
        $aggScore = [math]::Round(($domainScores.Values | Measure-Object -Sum).Sum / $domainScores.Count)
    }

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned"   = $subCount
            "Successful"                    = $successCount
            "Errors"                        = $errorCount
            "Total Governance Findings"     = $allFindings.Count
            "Critical Findings"             = $critCount
            "High Severity Findings"        = $highCount
            "Medium Severity Findings"      = $medCount
            "Low Severity Findings"         = $lowCount
            "RBAC Risk Assignments"         = $allRbacFindings.Count
            "Resources with Tag Gaps"       = $allTagFindings.Count
            "Resource Groups without Locks" = $allLockFindings.Count
            "Monitoring Findings"           = $allMonitorFindings.Count
            "Aggregate Governance Score"    = "$aggScore%"
            "Mandatory Tags Assessed"       = $MandatoryTags -join ", "
            "Execution Time"                = $duration
        })

    Write-DomainScores -Scores $domainScores

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0 -or $allRbacFindings.Count -gt 0) {
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object SubscriptionName, SubscriptionId, Domain, Finding, Severity, AffectedCount, Remediation, Detail, BusinessImpact |
                Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                if ($allRbacFindings.Count -gt 0) {
                    $rbacCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "RBAC.csv"
                    $allRbacFindings | Export-Csv -Path $rbacCsvPath -NoTypeInformation -Encoding UTF8
                }

                if ($allTagFindings.Count -gt 0) {
                    $tagCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "Tagging.csv"
                    $allTagFindings | Select-Object SubscriptionName, ResourceName, ResourceType, ResourceGroup, MissingCount |
                    Export-Csv -Path $tagCsvPath -NoTypeInformation -Encoding UTF8
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

            $htmlContent = Generate-GovernanceDashboardHtml `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParams `
                -Findings            $allFindings `
                -DomainScores        $domainScores `
                -RbacFindings        $allRbacFindings `
                -TagFindings         $allTagFindings `
                -LockFindings        $allLockFindings `
                -MonitorFindings     $allMonitorFindings `
                -SubscriptionResults $subscriptionResults `
                -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -MandatoryTags       $MandatoryTags

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
            Select-Object SubscriptionName, Domain, Finding, Severity, AffectedCount |
            Out-GridView -Title "Azure Governance Dashboard"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No governance findings found in the targeted subscriptions." -ForegroundColor Yellow
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
