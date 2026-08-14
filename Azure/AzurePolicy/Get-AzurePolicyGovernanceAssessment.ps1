<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 13 August 2026
Modified-On     : 13 August 2026

.SYNOPSIS
    Assesses Azure Policy governance structure — definitions, assignments, initiatives,
    exemptions, and enforcement modes — across one or more subscriptions, with optional
    live compliance state retrieval, CSV export, and an interactive HTML dashboard.

.DESCRIPTION
    Get-AzurePolicyGovernanceAssessment evaluates the Azure Policy governance posture
    across one or multiple subscriptions.

    Default assessment (fast, structure-only):
        - Policy definitions: custom vs built-in counts per subscription
        - Policy assignments: scope, enforcement mode (Audit/Deny/Disabled),
          parameter count, assigned initiative reference
        - Policy initiatives (sets): definition count, assignment count, scope
        - Policy exemptions: category (Waiver/Mitigated), expiry status
          (Active / Expiring Soon / Expired / No Expiry Set), scope
        - Scope-level distribution: Management Group / Subscription /
          Resource Group / Resource

    Optional compliance state (-IncludeComplianceState switch):
        - Calls Get-AzPolicyState per assignment to retrieve live non-compliant
          resource counts and non-compliance reasons
        - If Get-AzPolicyState fails or is inaccessible due to permissions,
          the section is marked "Not Assessed / Warning" and the reason is
          captured; assessment continues without interruption

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of all findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          donut charts, distribution panels, detail drawer)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER IncludeComplianceState
    Switch. When specified, calls Get-AzPolicyState per assignment to retrieve
    live non-compliant resource counts. Disabled by default for performance.
    If the call fails, the non-compliance data is marked "Not Assessed / Warning"
    and the scan continues.

.PARAMETER ExportToCsv
    Switch. If specified, exports all policy governance findings to the path
    given in -CsvPath. The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzurePolicyGovernance-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzurePolicyGovernanceAssessment -AllSubscriptions

.EXAMPLE
    Get-AzurePolicyGovernanceAssessment -AllSubscriptions -IncludeComplianceState

.EXAMPLE
    Get-AzurePolicyGovernanceAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzurePolicyGovernanceAssessment -AllSubscriptions -IncludeComplianceState -ExportToCsv -CsvPath "C:\Reports\PolicyGovernance.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (13-Aug-2026) - Initial release. Policy definition, assignment,
                            initiative, and exemption assessment. Optional
                            live compliance state via -IncludeComplianceState.
                            CSV export and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.PolicyInsights)
           — installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level.
        4. Microsoft.Authorization/policyAssignments/read at subscription scope.
        5. Microsoft.PolicyInsights/policyStates/queryResults/action is required
           for -IncludeComplianceState (Policy Insights Reader or equivalent).
           Without this permission the compliance state section is gracefully
           marked "Not Assessed / Warning" and assessment continues.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Management Group-scoped policy assignments are not enumerated by
          Get-AzPolicyAssignment when called at subscription context; only
          assignments at subscription scope and below are returned.
        - Get-AzPolicyState can be slow on subscriptions with many resources.
          Use -IncludeComplianceState selectively for large environments.
        - Interactive Grid View requires a GUI-capable session. Skipped
          gracefully in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Policy definitions with very large parameter blocks may produce
          truncated parameter counts if the JSON depth limit is hit during parsing.

.LINK
    https://learn.microsoft.com/en-us/azure/governance/policy/overview
    https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azpolicyassignment
    https://learn.microsoft.com/en-us/powershell/module/az.policyinsights/get-azpolicystate
    https://learn.microsoft.com/en-us/azure/governance/policy/concepts/exemption-structure

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
  Write-CenteredText "Azure Policy Governance Assessment v1.0" -Color White
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

Function Write-EnforcementBreakdown {
  param([hashtable]$Enforcement)

  if ($Enforcement.Count -eq 0) { return }

  Write-Host ""
  Write-Host "  Enforcement Mode Breakdown" -ForegroundColor Cyan
  Write-Host "  " -NoNewline
  Write-Host ("─" * 76) -ForegroundColor DarkGray

  $colorMap = @{ "Default" = "Red"; "DoNotEnforce" = "Yellow"; "Disabled" = "DarkGray" }

  foreach ($mode in ($Enforcement.GetEnumerator() | Sort-Object Value -Descending)) {
    $color = if ($colorMap.ContainsKey($mode.Key)) { $colorMap[$mode.Key] } else { "White" }
    Write-Host "  " -NoNewline
    Write-Host $mode.Key.PadRight(22) -NoNewline -ForegroundColor White
    Write-Host ": " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($mode.Value) assignment(s)" -ForegroundColor $color
  }
}

Function Write-ExemptionSummary {
  param([array]$Exemptions)

  if ($Exemptions.Count -eq 0) { return }

  $expired = @($Exemptions | Where-Object { $_.ExpiryStatus -eq "Expired" }).Count
  $expiringSoon = @($Exemptions | Where-Object { $_.ExpiryStatus -eq "Expiring Soon" }).Count
  $active = @($Exemptions | Where-Object { $_.ExpiryStatus -eq "Active" }).Count
  $noExpiry = @($Exemptions | Where-Object { $_.ExpiryStatus -eq "No Expiry Set" }).Count

  Write-Host ""
  Write-Host "  Exemption Summary" -ForegroundColor Cyan
  Write-Host "  " -NoNewline
  Write-Host ("─" * 76) -ForegroundColor DarkGray
  Write-Host "  Total Exemptions      : $($Exemptions.Count)" -ForegroundColor White
  Write-Host "  Active                : $active" -ForegroundColor Green
  Write-Host "  Expiring Within 30d   : $expiringSoon" -ForegroundColor Yellow
  Write-Host "  Expired               : $expired" -ForegroundColor Red
  Write-Host "  No Expiry Set         : $noExpiry" -ForegroundColor DarkGray
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

Function Generate-PolicyGovernanceHtml {
  param(
    [hashtable]$SessionInfo,
    [hashtable]$ScanParameters,
    [array]$Assignments,
    [array]$Exemptions,
    [hashtable]$ScopeDistribution,
    [hashtable]$EnforcementDistribution,
    [hashtable]$DefinitionSummary,
    [array]$Initiatives,
    [array]$SubscriptionResults,
    [string]$GeneratedOn,
    [bool]$ComplianceStateIncluded
  )

  $totalAssignments = @($Assignments).Count
  $totalExemptions = @($Exemptions).Count
  $totalInitiatives = @($Initiatives).Count
  $totalCustomDefs = ($DefinitionSummary.Values | Measure-Object -Sum).Sum

  $denyCount = @($Assignments | Where-Object { $_.EnforcementMode -eq "Default" -and $_.Effect -eq "Deny" }).Count
  $auditCount = @($Assignments | Where-Object { $_.Effect -in @("Audit", "AuditIfNotExists") }).Count
  $doNotEnforceCount = @($Assignments | Where-Object { $_.EnforcementMode -eq "DoNotEnforce" }).Count

  $expiredCount = @($Exemptions  | Where-Object { $_.ExpiryStatus -eq "Expired" }).Count
  $expiringSoonCount = @($Exemptions  | Where-Object { $_.ExpiryStatus -eq "Expiring Soon" }).Count

  $complianceStateBadge = if ($ComplianceStateIncluded) {
    '<span class="badge badge-green">✓ Included</span>'
  }
  else {
    '<span class="badge badge-amber">⚠ Skipped (use -IncludeComplianceState)</span>'
  }

  $complianceStateText = if ($ComplianceStateIncluded) { "Included" } else { "Skipped — use -IncludeComplianceState to enable" }

  # ── Assignment table rows ─────────────────────────────────────────────────
  $assignmentRows = ""
  foreach ($a in $Assignments) {
    $enfCls = switch ($a.EnforcementMode) {
      "Default" { "badge-red" }
      "DoNotEnforce" { "badge-amber" }
      default { "badge-blue" }
    }
    $csBadge = if ($ComplianceStateIncluded) {
      if ($a.ComplianceStateStatus -eq "Not Assessed / Warning") { '<span class="badge badge-amber">⚠ Not Assessed</span>' }
      elseif ($a.NonCompliantResources -gt 0) { "<span class='badge badge-red'>✗ $($a.NonCompliantResources)</span>" }
      else { '<span class="badge badge-green">✓ 0</span>' }
    }
    else { '<span class="badge" style="background:var(--surface3);color:var(--muted)">—</span>' }

    $scopeShort = if ($a.ScopeLevel) { $a.ScopeLevel } else { "Unknown" }
    $assignmentRows += @"
          <tr onclick="showAssignDetail($($Assignments.IndexOf($a)))">
            <td title="$(EscHtml $a.PolicyName)">$(if ($a.PolicyName.Length -gt 36) { EscHtml($a.PolicyName.Substring(0,33)+"...") } else { EscHtml $a.PolicyName })</td>
            <td>$(EscHtml $a.SubscriptionName)</td>
            <td><span class="badge $(EscHtml $enfCls)">$(EscHtml $a.EnforcementMode)</span></td>
            <td><span class="scope-badge">$(EscHtml $scopeShort)</span></td>
            <td>$(EscHtml $a.Type)</td>
            <td>$($a.ParameterCount)</td>
            <td>$csBadge</td>
          </tr>
"@
  }

  # ── Exemption table rows ──────────────────────────────────────────────────
  $exemptionRows = ""
  foreach ($e in $Exemptions) {
    $expCls = switch ($e.ExpiryStatus) {
      "Expired" { "badge-red" }
      "Expiring Soon" { "badge-amber" }
      "Active" { "badge-green" }
      default { "" }
    }
    $exemptionRows += @"
          <tr>
            <td title="$(EscHtml $e.ExemptionName)">$(if ($e.ExemptionName.Length -gt 32) { EscHtml($e.ExemptionName.Substring(0,29)+"...") } else { EscHtml $e.ExemptionName })</td>
            <td>$(EscHtml $e.SubscriptionName)</td>
            <td>$(EscHtml $e.PolicyAssignmentName)</td>
            <td>$(EscHtml $e.Category)</td>
            <td><span class="badge $expCls">$(EscHtml $e.ExpiryStatus)</span></td>
            <td style="font-family:var(--mono);font-size:11px">$(EscHtml $e.ExpiryDate)</td>
          </tr>
"@
  }

  # ── Initiative table rows ─────────────────────────────────────────────────
  $initiativeRows = ""
  foreach ($i in $Initiatives) {
    $initiativeRows += @"
          <tr>
            <td title="$(EscHtml $i.DisplayName)">$(if ($i.DisplayName.Length -gt 40) { EscHtml($i.DisplayName.Substring(0,37)+"...") } else { EscHtml $i.DisplayName })</td>
            <td>$(EscHtml $i.SubscriptionName)</td>
            <td>$(EscHtml $i.PolicyType)</td>
            <td>$($i.PolicyDefinitionCount)</td>
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

  # ── Enforcement distribution bar rows ─────────────────────────────────────
  $enfTotal = ($EnforcementDistribution.Values | Measure-Object -Sum).Sum
  $enfRows = ""
  foreach ($e in ($EnforcementDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
    $pct = if ($enfTotal -gt 0) { [math]::Round(($e.Value / $enfTotal) * 100) } else { 0 }
    $barColor = switch ($e.Key) {
      "Default" { "var(--red)" }
      "DoNotEnforce" { "var(--amber)" }
      default { "var(--muted)" }
    }
    $enfRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $e.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($e.Value) ($pct%)</span>
          </div>
"@
  }

  # ── Scope distribution bar rows ───────────────────────────────────────────
  $scopeTotal = ($ScopeDistribution.Values | Measure-Object -Sum).Sum
  $scopeRows = ""
  foreach ($s in ($ScopeDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
    $pct = if ($scopeTotal -gt 0) { [math]::Round(($s.Value / $scopeTotal) * 100) } else { 0 }
    $scopeRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $s.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($s.Value) ($pct%)</span>
          </div>
"@
  }

  # ── JSON for assignments detail drawer ────────────────────────────────────
  $assignJson = "["
  foreach ($a in $Assignments) {
    $ncText = if ($ComplianceStateIncluded) {
      if ($a.ComplianceStateStatus -eq "Not Assessed / Warning") { "Not Assessed / Warning: $(EscJ $a.ComplianceStateReason)" }
      else { "$($a.NonCompliantResources) non-compliant resource(s)" }
    }
    else { "Not included — run with -IncludeComplianceState" }

    $assignJson += "{" +
    """name"":""$(EscJ $a.PolicyName)""," +
    """sub"":""$(EscJ $a.SubscriptionName)""," +
    """mode"":""$(EscJ $a.EnforcementMode)""," +
    """scope"":""$(EscJ $a.Scope)""," +
    """scopeLevel"":""$(EscJ $a.ScopeLevel)""," +
    """type"":""$(EscJ $a.Type)""," +
    """params"":$($a.ParameterCount)," +
    """initiative"":""$(EscJ $a.InitiativeName)""," +
    """effect"":""$(EscJ $a.Effect)""," +
    """nc"":""$(EscJ $ncText)""" +
    "},"
  }
  $assignJson = $assignJson.TrimEnd(",") + "]"

  $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Policy Governance Dashboard</title>
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
.donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.legend-list{display:flex;flex-direction:column;gap:10px;}
.legend-item{display:flex;align-items:center;gap:10px;font-size:13px;}
.legend-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;}
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
.info-value.muted{color:var(--muted);font-style:italic;}
.cs-banner{
  padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:16px;
  display:flex;align-items:center;gap:10px;font-size:13px;
}
.cs-banner.included{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.3);color:var(--green);}
.cs-banner.skipped{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3);color:var(--amber);}
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
  position:fixed;right:0;top:0;bottom:0;width:440px;max-width:95vw;
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
    <div class="logo-icon">📜</div>
    <div class="logo-title">Policy Governance</div>
    <div class="logo-sub">Azure Policy Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('assignments',this)"><span class="nav-icon">📋</span> Assignments</button>
    <button class="nav-btn" onclick="showPage('initiatives',this)"><span class="nav-icon">📦</span> Initiatives</button>
    <button class="nav-btn" onclick="showPage('exemptions',this)"><span class="nav-icon">🛡️</span> Exemptions</button>
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
      Azure Policy Governance Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Policy Governance Overview</div>
      <div class="page-sub">Azure Policy posture across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_ASSIGNMENTS__</div>
        <div class="stat-label">Assignments</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__DENY_COUNT__</div>
        <div class="stat-label">Deny Mode</div>
        <div class="stat-sub">Default enforcement</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__DO_NOT_ENFORCE__</div>
        <div class="stat-label">DoNotEnforce</div>
        <div class="stat-sub">Not enforcing</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__TOTAL_INITIATIVES__</div>
        <div class="stat-label">Initiatives</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__TOTAL_EXEMPTIONS__</div>
        <div class="stat-label">Exemptions</div>
        <div class="stat-sub">__EXPIRED_COUNT__ expired · __EXPIRING_COUNT__ expiring</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__CUSTOM_DEFS__</div>
        <div class="stat-label">Custom Definitions</div>
      </div>
    </div>

    <div class="cs-banner __CS_BANNER_CLS__">
      <span>📊</span>
      <span><strong>Compliance State:</strong> __CS_BANNER_TEXT__</span>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🔒 Enforcement Mode Distribution</div>
        __ENF_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🎯 Assignment Scope Distribution</div>
        __SCOPE_ROWS__
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">⚠️ Exemption Risk Summary</div>
      <div class="stats-grid" style="margin-bottom:0;">
        <div class="stat-card c-green"><div class="stat-num">__EX_ACTIVE__</div><div class="stat-label">Active</div></div>
        <div class="stat-card c-amber"><div class="stat-num">__EX_EXPIRING__</div><div class="stat-label">Expiring ≤30d</div></div>
        <div class="stat-card c-red"><div class="stat-num">__EX_EXPIRED__</div><div class="stat-label">Expired</div></div>
        <div class="stat-card" style="border-top-color:var(--muted)"><div class="stat-num">__EX_NOEXPIRY__</div><div class="stat-label">No Expiry Set</div></div>
      </div>
    </div>
  </div>

  <!-- Assignments -->
  <div id="page-assignments" class="page">
    <div class="page-header">
      <div class="page-title">Policy Assignments</div>
      <div class="page-sub">Click any row for details. Enforcement mode indicates governance strength.</div>
    </div>
    <div class="cs-banner __CS_BANNER_CLS__">
      <span>📊</span>
      <span><strong>Compliance State:</strong> __CS_BANNER_TEXT__</span>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="assignSearch" placeholder="Search policy, subscription…" oninput="filterAssign()"/>
        </div>
        <select class="filter-select" id="filterEnf" onchange="filterAssign()">
          <option value="">All Enforcement</option>
          <option value="Default">Default (Enforce)</option>
          <option value="DoNotEnforce">DoNotEnforce</option>
        </select>
        <select class="filter-select" id="pgSizeAssign" onchange="changeAssignPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="assignTable">
          <thead>
            <tr>
              <th onclick="sortAssign(0)">Policy Name</th>
              <th onclick="sortAssign(1)">Subscription</th>
              <th onclick="sortAssign(2)">Enforcement</th>
              <th onclick="sortAssign(3)">Scope Level</th>
              <th onclick="sortAssign(4)">Type</th>
              <th onclick="sortAssign(5)">Parameters</th>
              <th>Non-Compliant Resources</th>
            </tr>
          </thead>
          <tbody id="assignBody">__ASSIGNMENT_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="assignPagination"></div>
    </div>
  </div>

  <!-- Initiatives -->
  <div id="page-initiatives" class="page">
    <div class="page-header">
      <div class="page-title">Policy Initiatives (Sets)</div>
      <div class="page-sub">Initiative sets group related policy definitions for coordinated enforcement</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Display Name</th>
              <th>Subscription</th>
              <th>Type</th>
              <th>Definitions</th>
            </tr>
          </thead>
          <tbody>__INITIATIVE_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Exemptions -->
  <div id="page-exemptions" class="page">
    <div class="page-header">
      <div class="page-title">Policy Exemptions</div>
      <div class="page-sub">Review expired and expiring exemptions — these may represent unmanaged governance gaps</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="exemptSearch" placeholder="Search exemption, policy…" oninput="filterExempt()"/>
        </div>
        <select class="filter-select" id="filterExpiry" onchange="filterExempt()">
          <option value="">All Expiry Status</option>
          <option value="Expired">Expired</option>
          <option value="Expiring Soon">Expiring Soon</option>
          <option value="Active">Active</option>
          <option value="No Expiry Set">No Expiry Set</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="exemptTable">
          <thead>
            <tr>
              <th>Exemption Name</th>
              <th>Subscription</th>
              <th>Policy Assignment</th>
              <th>Category</th>
              <th>Expiry Status</th>
              <th>Expiry Date</th>
            </tr>
          </thead>
          <tbody id="exemptBody">__EXEMPTION_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="exemptPagination"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription policy assessment outcome</div>
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
        <div class="info-card"><div class="info-label">Compliance State</div><div class="info-value">__CS_TEXT__</div></div>
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
    <span class="drawer-title" id="drawerTitle">Assignment Detail</span>
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
const ASSIGN_DATA = __ASSIGN_JSON__;
let assignFiltered = [...ASSIGN_DATA];
let assignPage = 1, assignPageSz = 25;
let assignSortCol = -1, assignSortAsc = true;
let currentDetailIdx = 0;

const EXEMPT_DATA_RAW = `__EXEMPT_JSON_RAW__`;
let EXEMPT_DATA = [];
try{ EXEMPT_DATA = JSON.parse(EXEMPT_DATA_RAW); }catch(e){}
let exemptFiltered = [...EXEMPT_DATA];
let exemptPage = 1, exemptPageSz = 25;

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

// ── Assignments table ─────────────────────────────────────────────────────────
function filterAssign(){
  const q=document.getElementById('assignSearch').value.toLowerCase();
  const e=document.getElementById('filterEnf').value;
  assignFiltered=ASSIGN_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mE=!e||r.mode===e;
    return mQ&&mE;
  });
  assignPage=1; renderAssign();
}

function changeAssignPageSize(){
  assignPageSz=parseInt(document.getElementById('pgSizeAssign').value);
  assignPage=1; renderAssign();
}

function sortAssign(col){
  if(assignSortCol===col){assignSortAsc=!assignSortAsc;}else{assignSortCol=col;assignSortAsc=true;}
  const keys=['name','sub','mode','scopeLevel','type','params','nc'];
  assignFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    return assignSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                        :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderAssign();
}

function renderAssign(){
  const tbody=document.getElementById('assignBody');
  const start=(assignPage-1)*assignPageSz;
  const slice=assignFiltered.slice(start,start+assignPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=ASSIGN_DATA.indexOf(r);
    const eCls=r.mode==='Default'?'badge-red':r.mode==='DoNotEnforce'?'badge-amber':'badge-blue';
    const nm=r.name.length>36?r.name.substring(0,33)+'...':r.name;
    return `<tr onclick="showAssignDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td><span class="badge ${eCls}">${escH(r.mode)}</span></td>
      <td><span class="scope-badge">${escH(r.scopeLevel)}</span></td>
      <td>${escH(r.type)}</td>
      <td>${r.params}</td>
      <td>${escH(r.nc)}</td>
    </tr>`;
  }).join('');
  renderAssignPg();
}

function renderAssignPg(){
  const total=Math.ceil(assignFiltered.length/assignPageSz);
  const el=document.getElementById('assignPagination');
  let h=`<span>${assignFiltered.length} assignments</span>`;
  h+=`<button class="pg-btn" onclick="changeAssignPage(${assignPage-1})" ${assignPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,assignPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===assignPage?'active':''}" onclick="changeAssignPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeAssignPage(${assignPage+1})" ${assignPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeAssignPage(p){
  const total=Math.ceil(assignFiltered.length/assignPageSz);
  if(p<1||p>total)return;
  assignPage=p; renderAssign();
}

// ── Exemptions table ──────────────────────────────────────────────────────────
function filterExempt(){
  const q=document.getElementById('exemptSearch').value.toLowerCase();
  const e=document.getElementById('filterExpiry').value;
  exemptFiltered=EXEMPT_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mE=!e||r.expiry===e;
    return mQ&&mE;
  });
  exemptPage=1; renderExempt();
}

function renderExempt(){
  const tbody=document.getElementById('exemptBody');
  const start=(exemptPage-1)*exemptPageSz;
  const slice=exemptFiltered.slice(start,start+exemptPageSz);
  tbody.innerHTML=slice.map(r=>{
    const eCls=r.expiry==='Expired'?'badge-red':r.expiry==='Expiring Soon'?'badge-amber':r.expiry==='Active'?'badge-green':'';
    const nm=r.name.length>32?r.name.substring(0,29)+'...':r.name;
    return `<tr>
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td>${escH(r.policy)}</td>
      <td>${escH(r.category)}</td>
      <td><span class="badge ${eCls}">${escH(r.expiry)}</span></td>
      <td style="font-family:var(--mono);font-size:11px">${escH(r.date)}</td>
    </tr>`;
  }).join('');
  renderExemptPg();
}

function renderExemptPg(){
  const total=Math.ceil(exemptFiltered.length/exemptPageSz);
  const el=document.getElementById('exemptPagination');
  let h=`<span>${exemptFiltered.length} exemptions</span>`;
  h+=`<button class="pg-btn" onclick="changeExemptPage(${exemptPage-1})" ${exemptPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,exemptPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===exemptPage?'active':''}" onclick="changeExemptPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeExemptPage(${exemptPage+1})" ${exemptPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeExemptPage(p){
  const total=Math.ceil(exemptFiltered.length/exemptPageSz);
  if(p<1||p>total)return;
  exemptPage=p; renderExempt();
}

// ── Assignment detail drawer ──────────────────────────────────────────────────
function showAssignDetail(idx){
  currentDetailIdx=idx;
  const r=ASSIGN_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${ASSIGN_DATA.length}`;
  const eCls=r.mode==='Default'?'badge-red':r.mode==='DoNotEnforce'?'badge-amber':'badge-blue';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Enforcement Mode</div>
      <div class="drawer-field-value"><span class="badge ${eCls}">${escH(r.mode)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Scope Level</div>
      <div class="drawer-field-value">${escH(r.scopeLevel)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Scope</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.scope)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Type</div>
      <div class="drawer-field-value">${escH(r.type)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Effect</div>
      <div class="drawer-field-value">${escH(r.effect)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Parameter Count</div>
      <div class="drawer-field-value">${r.params}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Initiative</div>
      <div class="drawer-field-value">${r.initiative?escH(r.initiative):'—'}</div></div>
    <div class="drawer-section">Compliance State</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.nc)}</div></div>
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
  if(next>=0&&next<ASSIGN_DATA.length) showAssignDetail(next);
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
filterAssign();
filterExempt();
animateBars();
</script>
</body>
</html>
'@

  # ── Exemption JSON (built separately to keep the here-string clean) ───────
  $exemptJsonLines = "["
  foreach ($e in $Exemptions) {
    $exemptJsonLines += "{" +
    """name"":""$(EscJ $e.ExemptionName)""," +
    """sub"":""$(EscJ $e.SubscriptionName)""," +
    """policy"":""$(EscJ $e.PolicyAssignmentName)""," +
    """category"":""$(EscJ $e.Category)""," +
    """expiry"":""$(EscJ $e.ExpiryStatus)""," +
    """date"":""$(EscJ $e.ExpiryDate)""" +
    "},"
  }
  $exemptJsonLines = $exemptJsonLines.TrimEnd(",") + "]"

  # ── Exemption stat counts ─────────────────────────────────────────────────
  $exActive = @($Exemptions | Where-Object { $_.ExpiryStatus -eq "Active" }).Count
  $exExpiring = @($Exemptions | Where-Object { $_.ExpiryStatus -eq "Expiring Soon" }).Count
  $exExpired = @($Exemptions | Where-Object { $_.ExpiryStatus -eq "Expired" }).Count
  $exNoExpiry = @($Exemptions | Where-Object { $_.ExpiryStatus -eq "No Expiry Set" }).Count

  $html = $html `
    -replace '__GENERATED_ON__', $GeneratedOn `
    -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
    -replace '__TOTAL_ASSIGNMENTS__', $totalAssignments `
    -replace '__DENY_COUNT__', $denyCount `
    -replace '__DO_NOT_ENFORCE__', $doNotEnforceCount `
    -replace '__TOTAL_INITIATIVES__', $totalInitiatives `
    -replace '__TOTAL_EXEMPTIONS__', $totalExemptions `
    -replace '__EXPIRED_COUNT__', $expiredCount `
    -replace '__EXPIRING_COUNT__', $expiringSoonCount `
    -replace '__CUSTOM_DEFS__', $totalCustomDefs `
    -replace '__CS_BANNER_CLS__', $(if ($ComplianceStateIncluded) { "included" } else { "skipped" }) `
    -replace '__CS_BANNER_TEXT__', $complianceStateText `
    -replace '__ENF_ROWS__', $enfRows `
    -replace '__SCOPE_ROWS__', $scopeRows `
    -replace '__EX_ACTIVE__', $exActive `
    -replace '__EX_EXPIRING__', $exExpiring `
    -replace '__EX_EXPIRED__', $exExpired `
    -replace '__EX_NOEXPIRY__', $exNoExpiry `
    -replace '__ASSIGNMENT_ROWS__', $assignmentRows `
    -replace '__INITIATIVE_ROWS__', $initiativeRows `
    -replace '__EXEMPTION_ROWS__', $exemptionRows `
    -replace '__SUB_ROWS__', $subRows `
    -replace '__TENANT__', $SessionInfo.Tenant `
    -replace '__ACCOUNT__', $SessionInfo.Account `
    -replace '__ENVIRONMENT__', $SessionInfo.Environment `
    -replace '__SCOPE__', $ScanParameters.Scope `
    -replace '__CS_TEXT__', $complianceStateText `
    -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
    -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
    -replace '__ASSIGN_JSON__', $assignJson `
    -replace '__EXEMPT_JSON_RAW__', ($exemptJsonLines -replace '`', '``')

  return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzurePolicyGovernanceAssessment {
  [CmdletBinding()]
  param (
    [switch]$AllSubscriptions,

    [string[]]$SubscriptionIds,

    [switch]$IncludeComplianceState,

    [switch]$ExportToCsv,

    [ValidateNotNullOrEmpty()]
    [string]$CsvPath = "C:\Temp\AzurePolicyGovernance-Report.csv"
  )

  $startTime = Get-Date

  Write-Banner

  # ── Module check ──────────────────────────────────────────────────────────
  $requiredModules = @("Az.Accounts", "Az.Resources")
  if ($IncludeComplianceState) { $requiredModules += "Az.PolicyInsights" }

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

  # ── Display session / params ──────────────────────────────────────────────
  Write-Section -Title "Session Information" -Data @{
    "Tenant"      = $ctx.Tenant.Id
    "Account"     = $ctx.Account.Id
    "Environment" = $ctx.Environment.Name
  }

  Write-Section -Title "Scan Parameters" -Data @{
    "Scope"            = "$scopeText ($subCount found)"
    "Compliance State" = if ($IncludeComplianceState) { "Enabled (Get-AzPolicyState will be called)" } else { "Skipped (use -IncludeComplianceState to enable)" }
    "Export to CSV"    = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
    "Export Path"      = if ($ExportToCsv.IsPresent) { $CsvPath }  else { "" }
  }

  # ── Collections ───────────────────────────────────────────────────────────
  $allAssignments = @()
  $allExemptions = @()
  $allInitiatives = @()
  $subscriptionResults = @()
  $definitionSummary = @{}     # SubscriptionName → custom def count
  $enforcementDist = @{}
  $scopeDist = @{ "Management Group" = 0; "Subscription" = 0; "Resource Group" = 0; "Resource" = 0 }
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

      # ── Policy Definitions ────────────────────────────────────────────
      $customDefs = 0
      try {
        $defs = @(Get-AzPolicyDefinition -Custom -ErrorAction Stop)
        $customDefs = $defs.Count
      }
      catch {
        Write-Verbose "  Could not retrieve custom policy definitions for $($sub.Name): $_"
      }
      $definitionSummary[$sub.Name] = $customDefs

      # ── Policy Assignments ────────────────────────────────────────────
      $assignments = @()
      try {
        $assignments = @(Get-AzPolicyAssignment -ErrorAction Stop)
      }
      catch {
        Write-Warning "  Could not retrieve policy assignments for $($sub.Name): $_"
      }

      foreach ($a in $assignments) {
        # Scope level classification
        $scope = if ($a.Scope) { $a.Scope } else { "" }
        if ([string]::IsNullOrWhiteSpace($scope)) { $scope = "" }
        $scopeLevel = if ($scope -like "*/providers/Microsoft.Management/managementGroups/*") { "Management Group" }
        elseif ($scope -match "^/subscriptions/[^/]+$") { "Subscription" }
        elseif ($scope -match "^/subscriptions/[^/]+/resourceGroups/[^/]+$") { "Resource Group" }
        else { "Resource" }

        # Enforcement mode
        $enfMode = if ($a.EnforcementMode) { $a.EnforcementMode } else { "Default" }
        if ([string]::IsNullOrWhiteSpace($enfMode)) { $enfMode = "Default" }

        # Effect (best-effort from parameters)
        $effect = ""
        try {
          try {
            $effect = if ($a.Parameter -and $a.Parameter.effect) { "$($a.Parameter.effect)" } else { "" }
          }
          catch { $effect = "" }
        }
        catch { }

        # Parameter count
        $paramCount = 0
        try {
          try {
            $paramCount = if ($a.Parameter) { @($a.Parameter | Get-Member -MemberType NoteProperty).Count } else { 0 }
          }
          catch { $paramCount = 0 }
        }
        catch { }

        # Initiative reference
        $initiativeName = ""
        try {
          $policyRef = if ($a.PolicyDefinitionId) { $a.PolicyDefinitionId } else { "" }
          if ($policyRef -like "*/policySetDefinitions/*") {
            $initiativeName = ($policyRef -split "/")[-1]
          }
        }
        catch { }

        # Enforcement distribution
        if ($enforcementDist.ContainsKey($enfMode)) { $enforcementDist[$enfMode]++ } else { $enforcementDist[$enfMode] = 1 }

        # Scope distribution
        if ($scopeDist.ContainsKey($scopeLevel)) { $scopeDist[$scopeLevel]++ }

        # Compliance state (optional)
        $ncResources = 0
        $csStatus = "Not Requested"
        $csReason = ""

        if ($IncludeComplianceState) {
          try {
            $policyStates = @(Get-AzPolicyState -PolicyAssignmentName $a.Name -ErrorAction Stop |
              Where-Object { $_.ComplianceState -eq "NonCompliant" })
            $ncResources = $policyStates.Count
            $csStatus = "Assessed"
          }
          catch {
            $csStatus = "Not Assessed / Warning"
            $csReason = $_.Exception.Message
            Write-Host ""
            Write-Host "  ⚠ Compliance state unavailable for '$($a.Name)': $csReason" -ForegroundColor Yellow
          }
        }

        $displayName = if ($a.DisplayName) { $a.DisplayName } elseif ($a.Name) { $a.Name } else { "Unknown" }
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = Get-ObjProperty -Obj $a -PropName 'Name' -Default "Unknown" }

        $allAssignments += [pscustomobject]@{
          SubscriptionName      = $sub.Name
          SubscriptionId        = $sub.Id
          PolicyName            = $displayName
          AssignmentId          = if ($a.Id) { $a.Id } else { $a.Name }
          EnforcementMode       = $enfMode
          Scope                 = $scope
          ScopeLevel            = $scopeLevel
          Type                  = if ($initiativeName) { "Initiative" } else { "Policy" }
          ParameterCount        = $paramCount
          Effect                = $effect
          InitiativeName        = $initiativeName
          NonCompliantResources = $ncResources
          ComplianceStateStatus = $csStatus
          ComplianceStateReason = $csReason
        }
      }

      # ── Policy Initiatives ────────────────────────────────────────────
      try {
        $sets = @(Get-AzPolicySetDefinition -ErrorAction Stop)
        # Write-Host "Exemption type: $($exemptions[0].GetType().FullName)"
        # $exemptions[0] | Get-Member -MemberType Properties | Format-Table Name, MemberType -AutoSize
        foreach ($s in $sets) {
          $defCount = 0
          try {
            try { $defCount = @($s.PolicyDefinition).Count } catch { $defCount = 0 }
          }
          catch { }

          $sDispName = if ($s.DisplayName) { $s.DisplayName } else { $s.Name }
          $sPolicyType = if ($s.PolicyType) { $s.PolicyType } else { "Unknown" }
          $sPolicySetId = if ($s.Id) { $s.Id } else { $s.Name }

          $allInitiatives += [pscustomobject]@{
            SubscriptionName      = $sub.Name
            SubscriptionId        = $sub.Id
            DisplayName           = $sDispName
            PolicySetDefinitionId = $sPolicySetId
            PolicyType            = $sPolicyType
            PolicyDefinitionCount = $defCount
          }
        }
      }
      catch {
        Write-Host "  ⚠ Initiatives error for $($sub.Name): $_" -ForegroundColor Yellow
      }

      # ── Policy Exemptions ─────────────────────────────────────────────
      try {
        $exemptions = @(Get-AzPolicyExemption -ErrorAction Stop)
        # if ($exemptions.Count -gt 0) {
        #   Write-Host "Exemption type: $($exemptions[0].GetType().FullName)"
        #   $exemptions[0] | Get-Member -MemberType Properties | Format-Table Name, MemberType -AutoSize
        # }
        foreach ($e in $exemptions) {
          $expiryStatus = "No Expiry Set"
          $expiryDate = "N/A"

          $eProps = Get-ObjProperty -Obj $e -PropName 'Properties' -Default $null
          $expiresOn = Get-ObjProperty -Obj $eProps -PropName 'ExpiresOn' -Default (Get-ObjProperty -Obj $e -PropName 'ExpiresOn' -Default $null)
          if ($expiresOn) {
            $expiryDate = $expiresOn.ToString("yyyy-MM-dd")
            $daysLeft = ($expiresOn - (Get-Date)).Days
            $expiryStatus = if ($daysLeft -lt 0) { "Expired" }
            elseif ($daysLeft -le 30) { "Expiring Soon" }
            else { "Active" }
          }

          $assignmentName = ""
          try { 
            $epaid = Get-ObjProperty -Obj $eProps -PropName 'PolicyAssignmentId' -Default (Get-ObjProperty -Obj $e -PropName 'PolicyAssignmentId' -Default "")
            if ($epaid) { $assignmentName = ($epaid -split "/")[-1] }
          } 
          catch { }

          $allExemptions += [pscustomobject]@{
            SubscriptionName     = $sub.Name
            SubscriptionId       = $sub.Id
            ExemptionName        = Get-ObjProperty -Obj $eProps -PropName 'DisplayName'       -Default (Get-ObjProperty -Obj $e -PropName 'Name' -Default "Unknown")
            PolicyAssignmentName = $assignmentName
            Category             = Get-ObjProperty -Obj $eProps -PropName 'ExemptionCategory' -Default (Get-ObjProperty -Obj $e -PropName 'ExemptionCategory' -Default "Unknown")
            ExpiryStatus         = $expiryStatus
            ExpiryDate           = $expiryDate
            Scope                = if ($e.Id) { $e.Id } else { "" }
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve policy exemptions for $($sub.Name): $_"
      }

      # ── Per-subscription result ───────────────────────────────────────
      Write-Host "`r$(' ' * 120)`r" -NoNewline
      $paddedName = $sub.Name.PadRight($maxNameLen)

      Write-Host "  " -NoNewline
      Write-Host "✓ " -NoNewline -ForegroundColor Green
      Write-Host $paddedName -NoNewline -ForegroundColor Green
      Write-Host " → " -NoNewline -ForegroundColor DarkGray
      Write-Host "Assignments: $($assignments.Count)  Initiatives: $($allInitiatives | Where-Object { $_.SubscriptionId -eq $sub.Id } | Measure-Object | Select-Object -Expand Count)  CustomDefs: $customDefs" -ForegroundColor White

      $subscriptionResults += @{
        Name    = $sub.Name
        Summary = "Assignments: $($assignments.Count)  CustomDefs: $customDefs"
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
      "Total Assignments Found"     = $allAssignments.Count
      "Total Initiatives Found"     = $allInitiatives.Count
      "Total Exemptions Found"      = $allExemptions.Count
      "Compliance State Assessed"   = if ($IncludeComplianceState) { "Yes" } else { "No (use -IncludeComplianceState)" }
      "Execution Time"              = $duration
    })

  Write-EnforcementBreakdown -Enforcement $enforcementDist
  Write-ExemptionSummary     -Exemptions  $allExemptions

  # ── Output files ──────────────────────────────────────────────────────────
  $csvExported = $false
  $htmlExported = $false
  $gridViewOpened = $false
  $htmlPath = ""

  if ($allAssignments.Count -gt 0 -or $allExemptions.Count -gt 0) {
    # CSV — flatten to two sheets worth of data in one file
    if ($ExportToCsv) {
      try {
        $csvDir = Split-Path -Parent $CsvPath
        if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

        $csvRows = $allAssignments | Select-Object `
          SubscriptionName, SubscriptionId, PolicyName, AssignmentId,
        EnforcementMode, Scope, ScopeLevel, Type, ParameterCount, Effect,
        InitiativeName, NonCompliantResources, ComplianceStateStatus, ComplianceStateReason

        $csvRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

        # Exemptions as a second CSV alongside the main one
        if ($allExemptions.Count -gt 0) {
          $exemptCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "Exemptions.csv"
          $allExemptions | Export-Csv -Path $exemptCsvPath -NoTypeInformation -Encoding UTF8
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

      $htmlContent = Generate-PolicyGovernanceHtml `
        -SessionInfo            $sessionInfo `
        -ScanParameters         $scanParams `
        -Assignments            $allAssignments `
        -Exemptions             $allExemptions `
        -ScopeDistribution      $scopeDist `
        -EnforcementDistribution $enforcementDist `
        -DefinitionSummary      $definitionSummary `
        -Initiatives            $allInitiatives `
        -SubscriptionResults    $subscriptionResults `
        -GeneratedOn            (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
        -ComplianceStateIncluded $IncludeComplianceState.IsPresent

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
      $allAssignments |
      Select-Object SubscriptionName, PolicyName, EnforcementMode, ScopeLevel, Type, ParameterCount, NonCompliantResources, ComplianceStateStatus |
      Out-GridView -Title "Azure Policy Governance Assessment"
      $gridViewOpened = $true
    }
    catch {
      Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
    }
  }
  else {
    Write-Host ""
    Write-Host "  ⚠ No policy data found in the targeted subscriptions." -ForegroundColor Yellow
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
