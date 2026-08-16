<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Analyses Azure Policy exemptions across one or more subscriptions to surface
    governance weaknesses, risk-rated findings, and actionable recommendations
    via an interactive HTML dashboard and optional CSV export.

.DESCRIPTION
    Get-AzurePolicyExemptionRiskReport approaches exemptions as a governance risk
    problem, not a data-collection exercise. Policy exemptions are the most common
    way that real enforcement is silently undermined: a team grants an exemption to
    unblock a deployment, the justification is minimal, no expiry is set, and the
    control is effectively gone — permanently, and invisibly.

    This report surfaces that problem at scale. For every exemption found it evaluates
    six independent risk dimensions and produces a composite Risk Level
    (Critical / High / Medium / Low):

      1. Expiry Risk
           No expiry set on a non-Mitigated exemption — the control is permanently bypassed.
           Already expired — the exemption is invalid but the record still exists,
           meaning it may still be in scope for some policy engines and creates
           confusion about actual coverage.
           Expiring within 30 days — action needed before the exemption lapses unexpectedly.

      2. Scope Risk
           Subscription-level or management-group-level exemptions have the broadest
           blast radius. A single exemption at subscription scope can bypass a policy
           for every resource in that subscription.

      3. Category Risk
           Waiver category with no expiry or broad scope is highest risk — it asserts
           the policy is inapplicable without a compensating control and without a
           time limit.
           Mitigated category asserts a compensating control exists; this is lower risk
           but still requires periodic review to confirm the compensating control remains
           in place.

      4. Justification Quality
           Missing, very short (<20 characters), or default-placeholder descriptions
           indicate the exemption was granted without meaningful governance review.
           Without a documented justification, there is no basis for future audit or
           review to assess whether the exemption remains appropriate.

      5. Policy Assignment Criticality
           Exemptions from assignments linked to security initiatives (Microsoft Defender
           for Cloud, CIS, NIST, PCI, ISO) carry materially higher risk than exemptions
           from operational or cost policies.

      6. Age Without Expiry
           Exemptions older than 90 days with no expiry date set indicate stale records
           that have never been reviewed. Per best-practice governance, all exemptions
           should have a maximum lifetime and a defined review cycle.

    Composite Risk Level:
        Critical  — No expiry + Waiver + subscription/MG scope, or any combination of
                    3+ high-risk signals
        High      — No expiry + broad scope, or expired exemption still on record,
                    or security-critical assignment + no expiry
        Medium    — 1–2 moderate risk signals (e.g., expiring soon + missing justification)
        Low       — All signals acceptable; may still benefit from periodic review

    Outputs:
        - Real-time progress bar and colour-coded per-subscription result
        - Always-on interactive HTML dashboard: risk overview, category breakdown,
          filterable exemption register, detail drawer (per-exemption risk narrative
          and recommended action), scan results, session info
        - Optional CSV export of all exemption findings

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. Exports all exemption risk findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless of this switch.

.PARAMETER CsvPath
    Path for the CSV export file. Also used to derive the HTML dashboard filename
    (same path, .html extension).
    Default: C:\Temp\AzurePolicyExemptionRisk-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard. Optionally
    writes a CSV when -ExportToCsv is specified. Opens Grid View where a GUI
    is available.

.EXAMPLE
    Get-AzurePolicyExemptionRiskReport -AllSubscriptions

.EXAMPLE
    Get-AzurePolicyExemptionRiskReport -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzurePolicyExemptionRiskReport -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\ExemptionRisk.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Six-dimension risk model per exemption,
                            composite Risk Level, HTML dashboard with risk register,
                            detail drawer with per-exemption narrative and recommended
                            actions, CSV export.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources) — installed
           automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level.
        4. Microsoft.Authorization/policyExemptions/read at subscription scope.
        5. Microsoft.Authorization/policyAssignments/read is used to look up
           display names for referenced policy assignments. If unavailable,
           assignment names are used as fallback without interrupting the scan.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Policy exemptions defined at Management Group scope are not returned by
          Get-AzPolicyExemption when called at subscription context. Run the script
          with appropriate MG-scoped credentials and subscription context to surface
          those if required.
        - The policy assignment criticality check uses keyword matching on the
          assignment display name and initiative ID. Custom initiative names that do
          not contain recognisable security keywords will not be flagged as critical
          even if they contain security policies.
        - Interactive Grid View requires a GUI session; skipped gracefully in
          headless or Linux environments with no effect on CSV/HTML output.
        - Default -CsvPath is Windows-specific; supply an explicit path on macOS
          or Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/governance/policy/concepts/exemption-structure
    https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azpolicyexemption
    https://learn.microsoft.com/en-us/azure/governance/policy/how-to/exempt-resource

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
  Write-CenteredText "Azure Policy Exemption Risk Report v1.0" -Color White
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
    if ([string]::IsNullOrWhiteSpace($value)) { $value = "None"; $valColor = "DarkGray" }
    else { $valColor = "White" }
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
  $completed  = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
  $remaining  = $BarWidth - $completed
  $bar        = ("█" * $completed) + ("░" * $remaining)
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
  param([array]$Findings)
  if ($Findings.Count -eq 0) { return }
  $critical = @($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
  $high     = @($Findings | Where-Object { $_.RiskLevel -eq "High"     }).Count
  $medium   = @($Findings | Where-Object { $_.RiskLevel -eq "Medium"   }).Count
  $low      = @($Findings | Where-Object { $_.RiskLevel -eq "Low"      }).Count
  Write-Host ""
  Write-Host "  Risk Level Breakdown" -ForegroundColor Cyan
  Write-Host "  " -NoNewline
  Write-Host ("─" * 76) -ForegroundColor DarkGray
  Write-Host "  Critical".PadRight(30) -NoNewline -ForegroundColor Gray; Write-Host ": $critical" -ForegroundColor Red
  Write-Host "  High    ".PadRight(30) -NoNewline -ForegroundColor Gray; Write-Host ": $high"     -ForegroundColor Yellow
  Write-Host "  Medium  ".PadRight(30) -NoNewline -ForegroundColor Gray; Write-Host ": $medium"   -ForegroundColor Cyan
  Write-Host "  Low     ".PadRight(30) -NoNewline -ForegroundColor Gray; Write-Host ": $low"      -ForegroundColor Green
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


#------------------------------------------------------------------------ [ Risk Scoring Engine ]

Function Get-ExemptionRisk {
  param(
    [pscustomobject]$Exemption
  )

  $signals  = @()   # human-readable risk signals for the narrative
  $score    = 0     # cumulative integer score; drives composite Risk Level

  # ── 1. Expiry Risk ─────────────────────────────────────────────────────────
  switch ($Exemption.ExpiryStatus) {
    "No Expiry Set" {
      if ($Exemption.Category -eq "Waiver") {
        $score += 40
        $signals += "No expiry date — Waiver exemptions without a time limit permanently bypass the policy with no scheduled review."
      }
      else {
        $score += 25
        $signals += "No expiry date — Mitigated exemptions should still carry an expiry to confirm the compensating control remains in place."
      }
    }
    "Expired" {
      $score += 35
      $signals += "Exemption has EXPIRED — the record is invalid but may still be evaluated by some policy engines. It must be removed or renewed immediately."
    }
    "Expiring Soon" {
      $score += 15
      $signals += "Expiring within 30 days — action needed to either renew (with fresh justification) or remove the exemption."
    }
    default { } # Active — no signal
  }

  # ── 2. Scope Risk ──────────────────────────────────────────────────────────
  switch ($Exemption.ScopeLevel) {
    "Management Group" {
      $score += 30
      $signals += "Management-group scope — applies to ALL subscriptions under the management group, maximising blast radius."
    }
    "Subscription" {
      $score += 20
      $signals += "Subscription scope — bypasses the policy for every resource in the subscription."
    }
    "Resource Group" {
      $score += 5
      $signals += "Resource-group scope — applies broadly within the resource group."
    }
    default { } # Resource-level — lowest scope risk
  }

  # ── 3. Category Risk ───────────────────────────────────────────────────────
  if ($Exemption.Category -eq "Waiver") {
    $score += 10
    $signals += "Waiver category — asserts the policy is inapplicable rather than mitigated by a compensating control."
  }

  # ── 4. Justification Quality ───────────────────────────────────────────────
  $descLen = $Exemption.Description.Length
  if ($descLen -eq 0) {
    $score += 20
    $signals += "No justification provided — the exemption was granted without any documented rationale, making future review impossible."
  }
  elseif ($descLen -lt 20) {
    $score += 10
    $signals += "Justification is very short ($descLen characters) — insufficient to support a meaningful governance review."
  }

  # ── 5. Policy Assignment Criticality ──────────────────────────────────────
  $critKeywords = @(
    "defender","security center","cis","nist","pci","iso 27001","hipaa","soc",
    "benchmark","mcsb","microsoft cloud security","regulatory compliance"
  )
  $assignLower = $Exemption.PolicyAssignmentName.ToLower()
  $isCritical  = $critKeywords | Where-Object { $assignLower -contains $_ }
  if (-not $isCritical) {
    # Also check the initiative ID fragment
    $initLower = $Exemption.PolicyDefinitionId.ToLower()
    $isCritical = $critKeywords | Where-Object { $initLower -contains $_ }
  }
  if ($isCritical) {
    $score += 25
    $signals += "Referenced assignment is linked to a security/compliance initiative ($($Exemption.PolicyAssignmentName)) — exemptions from these controls carry the highest governance impact."
  }

  # ── 6. Age Without Expiry ─────────────────────────────────────────────────
  if ($Exemption.ExpiryStatus -eq "No Expiry Set" -and $Exemption.AgeInDays -ge 90) {
    $score += 15
    $signals += "Exemption is $($Exemption.AgeInDays) days old with no expiry — stale exemptions accumulate governance debt and are rarely reviewed without a forcing function."
  }

  # ── Composite Risk Level ──────────────────────────────────────────────────
  $riskLevel = if ($score -ge 65) { "Critical" }
               elseif ($score -ge 40) { "High" }
               elseif ($score -ge 20) { "Medium" }
               else { "Low" }

  # ── Recommended Action ───────────────────────────────────────────────────
  $recommendation = switch ($riskLevel) {
    "Critical" { "Immediate review required. Either remove the exemption or renew it with a formal justification, defined owner, and an expiry date not exceeding 90 days. Escalate to the governance or security team if the exemption cannot be substantiated." }
    "High"     { "Schedule review within 2 weeks. Confirm the exemption is still valid, add or update the justification, set an expiry date, and assign a named owner who is accountable for the next review cycle." }
    "Medium"   { "Include in the next governance review cycle (within 30 days). Ensure justification is adequate, expiry is set, and the scope is as narrow as the use case allows." }
    "Low"      { "Exemption appears well-governed. Include in quarterly review to confirm the compensating control (for Mitigated) or inapplicability rationale (for Waiver) remains valid." }
  }

  return [pscustomobject]@{
    RiskLevel      = $riskLevel
    RiskScore      = $score
    RiskSignals    = ($signals -join " | ")
    Recommendation = $recommendation
  }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-ExemptionRiskHtml {
  param(
    [hashtable]$SessionInfo,
    [hashtable]$ScanParameters,
    [array]$Findings,
    [array]$SubscriptionResults,
    [string]$GeneratedOn
  )

  $total    = @($Findings).Count
  $critical = @($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
  $high     = @($Findings | Where-Object { $_.RiskLevel -eq "High"     }).Count
  $medium   = @($Findings | Where-Object { $_.RiskLevel -eq "Medium"   }).Count
  $low      = @($Findings | Where-Object { $_.RiskLevel -eq "Low"      }).Count
  $noExpiry = @($Findings | Where-Object { $_.ExpiryStatus -eq "No Expiry Set" }).Count
  $expired  = @($Findings | Where-Object { $_.ExpiryStatus -eq "Expired"       }).Count
  $waiver   = @($Findings | Where-Object { $_.Category -eq "Waiver"            }).Count
  $noDesc   = @($Findings | Where-Object { $_.Description.Length -lt 20        }).Count

  # ── Risk donut SVG ────────────────────────────────────────────────────────
  $donutData = @(
    @{ label = "Critical"; count = $critical; color = "var(--red)"   }
    @{ label = "High";     count = $high;     color = "var(--amber)" }
    @{ label = "Medium";   count = $medium;   color = "var(--accent)" }
    @{ label = "Low";      count = $low;      color = "var(--green)" }
  )
  $donutSegs   = ""
  $legendItems = ""
  $r     = 54
  $circ  = 2 * 3.14159265 * $r
  $offset = 0
  foreach ($d in $donutData) {
    if ($d.count -gt 0 -and $total -gt 0) {
      $arc    = $circ * ($d.count / $total)
      $donutSegs += "<circle r='$r' cx='60' cy='60' fill='transparent' stroke='$($d.color)' stroke-width='18' stroke-dasharray='$([math]::Round($arc,2)) $([math]::Round($circ - $arc,2))' stroke-dashoffset='-$([math]::Round($offset,2))' />"
      $offset += $arc
    }
    $legendItems += "<div class='legend-item'><span class='legend-dot' style='background:$($d.color)'></span><span>$($d.label)</span><span style='margin-left:auto;font-family:var(--mono);font-weight:700'>$($d.count)</span></div>"
  }

  # ── Risk distribution bars ────────────────────────────────────────────────
  $riskBarRows = ""
  foreach ($d in $donutData) {
    $pct = if ($total -gt 0) { [math]::Round(($d.count / $total) * 100) } else { 0 }
    $riskBarRows += "<div class='bar-row'><span class='bar-label'>$($d.label)</span><div class='bar-track'><div class='bar-fill' data-pct='$pct' style='background:$($d.color)'></div></div><span class='bar-pct'>$($d.count) ($pct%)</span></div>"
  }

  # ── Category distribution bars ────────────────────────────────────────────
  $catDist = $Findings | Group-Object Category | Sort-Object Count -Descending
  $catBarRows = ""
  foreach ($c in $catDist) {
    $pct = if ($total -gt 0) { [math]::Round(($c.Count / $total) * 100) } else { 0 }
    $catBarRows += "<div class='bar-row'><span class='bar-label'>$(EscHtml $c.Name)</span><div class='bar-track'><div class='bar-fill' data-pct='$pct'></div></div><span class='bar-pct'>$($c.Count) ($pct%)</span></div>"
  }

  # ── Scope distribution bars ───────────────────────────────────────────────
  $scopeDist = $Findings | Group-Object ScopeLevel | Sort-Object Count -Descending
  $scopeBarRows = ""
  foreach ($s in $scopeDist) {
    $pct = if ($total -gt 0) { [math]::Round(($s.Count / $total) * 100) } else { 0 }
    $scopeBarRows += "<div class='bar-row'><span class='bar-label'>$(EscHtml $s.Name)</span><div class='bar-track'><div class='bar-fill' data-pct='$pct'></div></div><span class='bar-pct'>$($s.Count) ($pct%)</span></div>"
  }

  # ── Exemption table rows ──────────────────────────────────────────────────
  $sortedFindings = $Findings | Sort-Object @{e={
    switch ($_.RiskLevel) { "Critical"{0}"High"{1}"Medium"{2}"Low"{3} }
  }}, ExpiryStatus, ExemptionName

  $exemptRows = ""
  $findingIdx = 0
  foreach ($f in $sortedFindings) {
    $rCls = switch ($f.RiskLevel) { "Critical"{"badge-red"} "High"{"badge-amber"} "Medium"{"badge-blue"} "Low"{"badge-green"} }
    $eCls = switch ($f.ExpiryStatus) { "Expired"{"badge-red"} "Expiring Soon"{"badge-amber"} "Active"{"badge-green"} default{""} }
    $nameShort = if ($f.ExemptionName.Length -gt 32) { EscHtml($f.ExemptionName.Substring(0,29) + "...") } else { EscHtml $f.ExemptionName }

    $exemptRows += @"
      <tr onclick="showDetail($findingIdx)">
        <td><span class="badge $(EscHtml $rCls)">$(EscHtml $f.RiskLevel)</span></td>
        <td title="$(EscHtml $f.ExemptionName)">$nameShort</td>
        <td>$(EscHtml $f.SubscriptionName)</td>
        <td>$(EscHtml $f.Category)</td>
        <td><span class="scope-badge">$(EscHtml $f.ScopeLevel)</span></td>
        <td><span class="badge $(EscHtml $eCls)">$(EscHtml $f.ExpiryStatus)</span></td>
        <td style="font-family:var(--mono);font-size:11px">$(EscHtml $f.ExpiryDate)</td>
        <td>$($f.RiskScore)</td>
      </tr>
"@
    $findingIdx++
  }

  # ── Subscription results ──────────────────────────────────────────────────
  $subRows = ""
  foreach ($s in $SubscriptionResults) {
    $icon = switch ($s.Status) { "Success"{"✓"} "Warning"{"⚠"} "Error"{"✗"} default{"•"} }
    $cls  = switch ($s.Status) { "Success"{"c-green"} "Warning"{"c-amber"} "Error"{"c-red"} default{""} }
    $subRows += "<div class='sub-row'><span class='sub-icon $cls'>$icon</span><span class='sub-name'>$(EscHtml $s.Name)</span><span class='sub-detail'>$(EscHtml $s.Summary)</span></div>"
  }

  # ── JSON for detail drawer ────────────────────────────────────────────────
  $findingsJson = "["
  foreach ($f in $sortedFindings) {
    $findingsJson += "{" +
      """riskLevel"":""$(EscJ $f.RiskLevel)""," +
      """riskScore"":$($f.RiskScore)," +
      """name"":""$(EscJ $f.ExemptionName)""," +
      """sub"":""$(EscJ $f.SubscriptionName)""," +
      """subId"":""$(EscJ $f.SubscriptionId)""," +
      """category"":""$(EscJ $f.Category)""," +
      """scopeLevel"":""$(EscJ $f.ScopeLevel)""," +
      """scope"":""$(EscJ $f.Scope)""," +
      """policy"":""$(EscJ $f.PolicyAssignmentName)""," +
      """expiryStatus"":""$(EscJ $f.ExpiryStatus)""," +
      """expiryDate"":""$(EscJ $f.ExpiryDate)""," +
      """ageInDays"":$($f.AgeInDays)," +
      """description"":""$(EscJ $f.Description)""," +
      """signals"":""$(EscJ $f.RiskSignals)""," +
      """recommendation"":""$(EscJ $f.Recommendation)""" +
      "},"
  }
  $findingsJson = $findingsJson.TrimEnd(",") + "]"

  $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Policy Exemption Risk Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;--border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;--green:#3fb950;--amber:#d29922;--red:#f85149;--text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;--mono:'JetBrains Mono','Consolas','Courier New',monospace;--sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;--radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);}
html[data-theme="light"]{--bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;--border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;--green:#1a7f37;--amber:#b08000;--red:#cf222e;--text:#1f2328;--muted:#636c76;--muted2:#424a53;--shadow:0 4px 24px rgba(0,0,0,.12);}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;}
#sidebar{width:236px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:transform .25s;}
.logo-block{padding:20px 16px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,var(--red),var(--amber));display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;}
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
#main{margin-left:236px;padding:28px;width:calc(100% - 236px);min-height:100vh;}
.page{display:none;animation:fadeIn .2s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px);}to{opacity:1;transform:none;}}
.page-header{margin-bottom:22px;}
.page-title{font-size:22px;font-weight:700;}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:22px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;border-top:3px solid var(--border);transition:transform .15s,box-shadow .15s;}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-num{font-size:28px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:13px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:130px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:80px;text-align:right;flex-shrink:0;}
.donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
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
.drawer-field-value{font-size:13px;word-break:break-all;line-height:1.5;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.signal-list{display:flex;flex-direction:column;gap:8px;margin-top:4px;}
.signal-item{background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--amber);border-radius:var(--radius-sm);padding:10px 12px;font-size:12px;line-height:1.5;color:var(--muted2);}
.rec-box{background:rgba(56,139,253,.08);border:1px solid rgba(56,139,253,.3);border-radius:var(--radius-sm);padding:14px;font-size:12px;line-height:1.6;color:var(--text);margin-top:8px;}
.risk-score-bar{display:flex;align-items:center;gap:12px;margin-top:6px;}
.risk-score-track{flex:1;height:10px;background:var(--surface3);border-radius:5px;overflow:hidden;}
.risk-score-fill{height:100%;border-radius:5px;background:var(--accent);transition:width .6s ease;}
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
    <div class="logo-icon">⚠️</div>
    <div class="logo-title">Exemption Risk</div>
    <div class="logo-sub">Policy Exemption Report</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('register',this)"><span class="nav-icon">📋</span> Risk Register</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">🔍</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">Generated: __GENERATED_ON__<br/>Policy Exemption Risk Report</div>
  </div>
</nav>
<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Policy Exemption Risk Overview</div>
      <div class="page-sub">Governance risk analysis across __TOTAL__ exemption(s) in __SUB_COUNT__ subscription(s)</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL__</div>
        <div class="stat-label">Critical Risk</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH__</div>
        <div class="stat-label">High Risk</div>
        <div class="stat-sub">Review within 2 weeks</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__MEDIUM__</div>
        <div class="stat-label">Medium Risk</div>
        <div class="stat-sub">Next governance cycle</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__LOW__</div>
        <div class="stat-label">Low Risk</div>
        <div class="stat-sub">Quarterly review</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__NO_EXPIRY__</div>
        <div class="stat-label">No Expiry Set</div>
        <div class="stat-sub">Permanent bypass risk</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__EXPIRED__</div>
        <div class="stat-label">Already Expired</div>
        <div class="stat-sub">Invalid — remove or renew</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__WAIVER__</div>
        <div class="stat-label">Waiver Category</div>
        <div class="stat-sub">No compensating control</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__NO_DESC__</div>
        <div class="stat-label">Missing Justification</div>
        <div class="stat-sub">Description &lt; 20 chars</div>
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Risk Level Distribution</div>
        <div class="donut-wrap">
          <svg width="120" height="120" viewBox="0 0 120 120" style="transform:rotate(-90deg);flex-shrink:0">__DONUT_SEGS__</svg>
          <div class="legend-list">__LEGEND_ITEMS__</div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">📊 Risk by Level</div>
        __RISK_BAR_ROWS__
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📂 By Category</div>
        __CAT_BAR_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🎯 By Scope Level</div>
        __SCOPE_BAR_ROWS__
      </div>
    </div>
  </div>

  <!-- Risk Register -->
  <div id="page-register" class="page">
    <div class="page-header">
      <div class="page-title">Exemption Risk Register</div>
      <div class="page-sub">Click any row to view full risk narrative and recommended action. Sorted by risk level (highest first).</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="regSearch" placeholder="Search exemption name, subscription, policy…" oninput="filterReg()"/>
        </div>
        <select class="filter-select" id="filterRisk" onchange="filterReg()">
          <option value="">All Risk Levels</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="filterExpiry" onchange="filterReg()">
          <option value="">All Expiry Statuses</option>
          <option value="Expired">Expired</option>
          <option value="Expiring Soon">Expiring Soon</option>
          <option value="No Expiry Set">No Expiry Set</option>
          <option value="Active">Active</option>
        </select>
        <select class="filter-select" id="regPageSz" onchange="regChangePageSz()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="regSort('riskLevel')">Risk Level</th>
              <th onclick="regSort('name')">Exemption Name</th>
              <th onclick="regSort('sub')">Subscription</th>
              <th onclick="regSort('category')">Category</th>
              <th onclick="regSort('scopeLevel')">Scope</th>
              <th onclick="regSort('expiryStatus')">Expiry Status</th>
              <th onclick="regSort('expiryDate')">Expiry Date</th>
              <th onclick="regSort('riskScore')">Score</th>
            </tr>
          </thead>
          <tbody id="regBody">__EXEMPT_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="regPagination"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription exemption scan outcome</div>
    </div>
    <div class="panel">
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- Session Info -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Scan Parameters</div>
    </div>
    <div class="panel">
      <div class="panel-title">🔐 Session Information</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Tenant</div><div class="info-value">__TENANT__</div></div>
        <div class="info-card"><div class="info-label">Account</div><div class="info-value">__ACCOUNT__</div></div>
        <div class="info-card"><div class="info-label">Environment</div><div class="info-value">__ENVIRONMENT__</div></div>
        <div class="info-card"><div class="info-label">Generated</div><div class="info-value">__GENERATED_ON__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">⚙️ Scan Parameters</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Scope</div><div class="info-value">__SCOPE__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Total Exemptions</div><div class="info-value">__TOTAL__</div></div>
      </div>
    </div>
  </div>
</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Exemption Detail</span>
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
const FINDINGS_DATA = __FINDINGS_JSON__;
let regFiltered = [...FINDINGS_DATA];
let regPage = 1, regPageSz = 25;
let regSortCol = 'riskLevel', regSortAsc = true;
let currentDetailIdx = 0;

const RISK_ORDER = {Critical:0,High:1,Medium:2,Low:3};

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
}

function toggleTheme(){
  const h=document.documentElement;
  h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';
}

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

function filterReg(){
  const q=document.getElementById('regSearch').value.toLowerCase();
  const r=document.getElementById('filterRisk').value;
  const e=document.getElementById('filterExpiry').value;
  regFiltered=FINDINGS_DATA.filter(d=>{
    const mQ=!q||JSON.stringify(d).toLowerCase().includes(q);
    const mR=!r||d.riskLevel===r;
    const mE=!e||d.expiryStatus===e;
    return mQ&&mR&&mE;
  });
  regPage=1;regSort(regSortCol,true);
}

function regSort(col,keepDir){
  if(!keepDir){if(regSortCol===col)regSortAsc=!regSortAsc;else{regSortCol=col;regSortAsc=true;}}
  regFiltered.sort((a,b)=>{
    if(col==='riskLevel'){const av=RISK_ORDER[a.riskLevel]??99,bv=RISK_ORDER[b.riskLevel]??99;return regSortAsc?av-bv:bv-av;}
    if(col==='riskScore'){return regSortAsc?a.riskScore-b.riskScore:b.riskScore-a.riskScore;}
    const av=String(a[col]||''),bv=String(b[col]||'');
    return regSortAsc?av.localeCompare(bv):bv.localeCompare(av);
  });
  renderReg();
}

function renderReg(){
  const tbody=document.getElementById('regBody');
  const start=(regPage-1)*regPageSz;
  const slice=regFiltered.slice(start,start+regPageSz);
  tbody.innerHTML=slice.map((r,i)=>{
    const gi=FINDINGS_DATA.indexOf(r);
    const rCls=r.riskLevel==='Critical'?'badge-red':r.riskLevel==='High'?'badge-amber':r.riskLevel==='Medium'?'badge-blue':'badge-green';
    const eCls=r.expiryStatus==='Expired'?'badge-red':r.expiryStatus==='Expiring Soon'?'badge-amber':r.expiryStatus==='Active'?'badge-green':'';
    const nm=r.name.length>32?r.name.substring(0,29)+'...':r.name;
    return `<tr onclick="showDetail(${gi})">
      <td><span class="badge ${rCls}">${escH(r.riskLevel)}</span></td>
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td>${escH(r.category)}</td>
      <td><span class="scope-badge">${escH(r.scopeLevel)}</span></td>
      <td><span class="badge ${eCls}">${escH(r.expiryStatus)}</span></td>
      <td style="font-family:var(--mono);font-size:11px">${escH(r.expiryDate)}</td>
      <td style="font-family:var(--mono);font-weight:700">${r.riskScore}</td>
    </tr>`;
  }).join('');
  renderRegPg();
}

function renderRegPg(){
  const total=Math.ceil(regFiltered.length/regPageSz);
  const el=document.getElementById('regPagination');
  let h=`<span>${regFiltered.length} exemption(s)</span>`;
  h+=`<button class="pg-btn" onclick="changeRegPage(${regPage-1})" ${regPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,regPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===regPage?'active':''}" onclick="changeRegPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeRegPage(${regPage+1})" ${regPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeRegPage(p){const t=Math.ceil(regFiltered.length/regPageSz);if(p<1||p>t)return;regPage=p;renderReg();}
function regChangePageSz(){regPageSz=parseInt(document.getElementById('regPageSz').value);regPage=1;renderReg();}

function showDetail(gi){
  currentDetailIdx=gi;
  const r=FINDINGS_DATA[gi];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerNavInfo').textContent=`${gi+1} of ${FINDINGS_DATA.length}`;
  const rCls=r.riskLevel==='Critical'?'badge-red':r.riskLevel==='High'?'badge-amber':r.riskLevel==='Medium'?'badge-blue':'badge-green';
  const eCls=r.expiryStatus==='Expired'?'badge-red':r.expiryStatus==='Expiring Soon'?'badge-amber':r.expiryStatus==='Active'?'badge-green':'';
  const scorePct=Math.min(r.riskScore,100);
  const scoreColor=r.riskLevel==='Critical'?'var(--red)':r.riskLevel==='High'?'var(--amber)':r.riskLevel==='Medium'?'var(--accent)':'var(--green)';
  const signals=r.signals?r.signals.split(' | ').filter(s=>s.trim()).map(s=>`<div class="signal-item">• ${escH(s)}</div>`).join(''):'<div class="signal-item">No risk signals identified.</div>';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field">
      <div class="drawer-field-label">Composite Risk Level</div>
      <div style="display:flex;align-items:center;gap:12px;margin-top:4px">
        <span class="badge ${rCls}">${escH(r.riskLevel)}</span>
        <div class="risk-score-bar" style="flex:1">
          <div class="risk-score-track"><div class="risk-score-fill" style="width:${scorePct}%;background:${scoreColor}"></div></div>
          <span style="font-family:var(--mono);font-size:12px;color:var(--muted2);flex-shrink:0">Score: ${r.riskScore}</span>
        </div>
      </div>
    </div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Category</div><div class="drawer-field-value">${escH(r.category)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Scope Level</div><div class="drawer-field-value"><span class="scope-badge">${escH(r.scopeLevel)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Scope Path</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.scope)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Referenced Policy Assignment</div><div class="drawer-field-value">${escH(r.policy)||'—'}</div></div>
    <div class="drawer-field">
      <div class="drawer-field-label">Expiry Status</div>
      <div style="margin-top:4px"><span class="badge ${eCls}">${escH(r.expiryStatus)}</span> <span style="font-family:var(--mono);font-size:11px;color:var(--muted2);margin-left:8px">${escH(r.expiryDate)}</span></div>
    </div>
    <div class="drawer-field"><div class="drawer-field-label">Age (days)</div><div class="drawer-field-value">${r.ageInDays} day(s)</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Justification / Description</div><div class="drawer-field-value" style="color:${r.description.length<20?'var(--amber)':'var(--text)'}">${r.description||'<em style="color:var(--red)">No description provided</em>'}</div></div>
    <div class="drawer-section">Risk Signals</div>
    <div class="signal-list">${signals}</div>
    <div class="drawer-section">Recommended Action</div>
    <div class="rec-box">${escH(r.recommendation)}</div>
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
  if(next>=0&&next<FINDINGS_DATA.length) showDetail(next);
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{el.style.width=el.dataset.pct+'%';});
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

filterReg();
animateBars();
</script>
</body>
</html>
'@

  $html = $html `
    -replace '__GENERATED_ON__',  $GeneratedOn `
    -replace '__SUB_COUNT__',     ($SubscriptionResults.Count) `
    -replace '__TOTAL__',         $total `
    -replace '__CRITICAL__',      $critical `
    -replace '__HIGH__',          $high `
    -replace '__MEDIUM__',        $medium `
    -replace '__LOW__',           $low `
    -replace '__NO_EXPIRY__',     $noExpiry `
    -replace '__EXPIRED__',       $expired `
    -replace '__WAIVER__',        $waiver `
    -replace '__NO_DESC__',       $noDesc `
    -replace '__DONUT_SEGS__',    $donutSegs `
    -replace '__LEGEND_ITEMS__',  $legendItems `
    -replace '__RISK_BAR_ROWS__', $riskBarRows `
    -replace '__CAT_BAR_ROWS__',  $catBarRows `
    -replace '__SCOPE_BAR_ROWS__',$scopeBarRows `
    -replace '__EXEMPT_ROWS__',   $exemptRows `
    -replace '__SUB_ROWS__',      $subRows `
    -replace '__TENANT__',        $SessionInfo.Tenant `
    -replace '__ACCOUNT__',       $SessionInfo.Account `
    -replace '__ENVIRONMENT__',   $SessionInfo.Environment `
    -replace '__SCOPE__',         $ScanParameters.Scope `
    -replace '__EXPORT_ENABLED__',$ScanParameters.ExportEnabled `
    -replace '__EXEC_TIME__',     $ScanParameters.ExecTime `
    -replace '__FINDINGS_JSON__', $findingsJson

  return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzurePolicyExemptionRiskReport {
  [CmdletBinding()]
  param (
    [switch]$AllSubscriptions,

    [string[]]$SubscriptionIds,

    [switch]$ExportToCsv,

    [ValidateNotNullOrEmpty()]
    [string]$CsvPath = "C:\Temp\AzurePolicyExemptionRisk-Report.csv"
  )

  $startTime = Get-Date

  Write-Banner

  # ── Module check ──────────────────────────────────────────────────────────
  $requiredModules = @("Az.Accounts", "Az.Resources")
  $missingModules  = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

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
    $scopeText     = "All Subscriptions"
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
    "Export Path"   = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
  }

  # ── Collections ───────────────────────────────────────────────────────────
  $allFindings         = @()
  $subscriptionResults = @()
  $successCount        = 0
  $errorCount          = 0

  # ── Scan ──────────────────────────────────────────────────────────────────
  Write-ScanProgress
  Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

  $maxNameLen = [math]::Max(
    ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
    35
  )

  $subIndex = 1

  foreach ($sub in $subscriptions) {
    try {
      Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

      Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue `
        -InformationAction SilentlyContinue | Out-Null

      # ── Build assignment name lookup (best-effort) ────────────────────
      $assignmentNames = @{}
      try {
        $assignments = @(Get-AzPolicyAssignment -ErrorAction Stop)
        foreach ($a in $assignments) {
          $aId   = if ($a.Id)   { $a.Id   } else { "" }
          $aName = if ($a.DisplayName -and $a.DisplayName.Trim()) { $a.DisplayName } else { $a.Name }
          if ($aId) { $assignmentNames[$aId.ToLower()] = $aName }
        }
      }
      catch {
        Write-Verbose "  Could not pre-fetch assignments for $($sub.Name): $_"
      }

      # ── Retrieve exemptions ───────────────────────────────────────────
      $exemptions = @()
      try {
        $exemptions = @(Get-AzPolicyExemption -ErrorAction Stop)
      }
      catch {
        Write-Warning "  Could not retrieve policy exemptions for $($sub.Name): $_"
      }

      $subFindingCount = 0

      foreach ($e in $exemptions) {

        # ── Extract core properties (handles both flat and .Properties shapes) ──
        $eProps = Get-ObjProperty -Obj $e -PropName 'Properties' -Default $null

        $exemptionName = Get-ObjProperty -Obj $eProps -PropName 'DisplayName' `
          -Default (Get-ObjProperty -Obj $e -PropName 'Name' -Default "Unknown")
        if ([string]::IsNullOrWhiteSpace($exemptionName)) { $exemptionName = Get-ObjProperty -Obj $e -PropName 'Name' -Default "Unknown" }

        $category = Get-ObjProperty -Obj $eProps -PropName 'ExemptionCategory' `
          -Default (Get-ObjProperty -Obj $e -PropName 'ExemptionCategory' -Default "Unknown")

        $description = Get-ObjProperty -Obj $eProps -PropName 'Description' `
          -Default (Get-ObjProperty -Obj $e -PropName 'Description' -Default "")
        if ($null -eq $description) { $description = "" }

        $policyAssignmentId = ""
        try {
          $policyAssignmentId = Get-ObjProperty -Obj $eProps -PropName 'PolicyAssignmentId' `
            -Default (Get-ObjProperty -Obj $e -PropName 'PolicyAssignmentId' -Default "")
          if ($null -eq $policyAssignmentId) { $policyAssignmentId = "" }
        }
        catch { }

        $policyAssignmentName = if ($policyAssignmentId -and $assignmentNames.ContainsKey($policyAssignmentId.ToLower())) {
          $assignmentNames[$policyAssignmentId.ToLower()]
        }
        elseif ($policyAssignmentId) {
          ($policyAssignmentId -split "/")[-1]
        }
        else { "Unknown" }

        # Scope and scope level
        $scopeId = if ($e.Id) { $e.Id } else { "" }
        $scopeLevel = if ($scopeId -like "*/providers/Microsoft.Management/managementGroups/*") { "Management Group" }
                      elseif ($scopeId -match "/subscriptions/[^/]+/resourceGroups/[^/]+") { "Resource Group" }
                      elseif ($scopeId -match "/subscriptions/[^/]+/resourceGroups/[^/]+/.+") { "Resource" }
                      elseif ($scopeId -match "^/subscriptions/[^/]+") { "Subscription" }
                      else { "Unknown" }

        # Expiry
        $expiryStatus = "No Expiry Set"
        $expiryDate   = "N/A"
        $expiresOn    = Get-ObjProperty -Obj $eProps -PropName 'ExpiresOn' `
          -Default (Get-ObjProperty -Obj $e -PropName 'ExpiresOn' -Default $null)

        if ($expiresOn) {
          try {
            $expiryDate   = $expiresOn.ToString("yyyy-MM-dd")
            $daysLeft     = ($expiresOn - (Get-Date)).Days
            $expiryStatus = if ($daysLeft -lt 0) { "Expired" }
                            elseif ($daysLeft -le 30) { "Expiring Soon" }
                            else { "Active" }
          }
          catch {
            $expiryDate   = $expiresOn.ToString()
            $expiryStatus = "Active"
          }
        }

        # Age
        $createdOn  = Get-ObjProperty -Obj $eProps -PropName 'CreatedOn' `
          -Default (Get-ObjProperty -Obj $e -PropName 'CreatedOn' -Default $null)
        $ageInDays  = if ($createdOn) { [math]::Round(((Get-Date) - $createdOn).TotalDays) } else { 0 }

        # Initiative ID from the assignment reference
        $policyDefinitionId = ""
        try {
          $policyDefinitionId = Get-ObjProperty -Obj $eProps -PropName 'PolicyDefinitionReferenceIds' -Default ""
          if ($null -eq $policyDefinitionId) { $policyDefinitionId = "" }
        }
        catch { }

        # ── Risk scoring ──────────────────────────────────────────────────
        $finding = [pscustomobject]@{
          SubscriptionName     = $sub.Name
          SubscriptionId       = $sub.Id
          ExemptionName        = $exemptionName
          Category             = $category
          Description          = $description
          PolicyAssignmentName = $policyAssignmentName
          PolicyDefinitionId   = $policyDefinitionId
          ScopeLevel           = $scopeLevel
          Scope                = $scopeId
          ExpiryStatus         = $expiryStatus
          ExpiryDate           = $expiryDate
          AgeInDays            = $ageInDays
          RiskLevel            = ""
          RiskScore            = 0
          RiskSignals          = ""
          Recommendation       = ""
        }

        $risk = Get-ExemptionRisk -Exemption $finding
        $finding.RiskLevel      = $risk.RiskLevel
        $finding.RiskScore      = $risk.RiskScore
        $finding.RiskSignals    = $risk.RiskSignals
        $finding.Recommendation = $risk.Recommendation

        $allFindings += $finding
        $subFindingCount++
      }

      # ── Per-subscription result ───────────────────────────────────────
      Write-Host "`r$(' ' * 120)`r" -NoNewline
      $paddedName = $sub.Name.PadRight($maxNameLen)

      $critSub = @($allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id -and $_.RiskLevel -eq "Critical" }).Count
      $highSub = @($allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id -and $_.RiskLevel -eq "High"     }).Count

      Write-Host "  " -NoNewline
      Write-Host "✓ " -NoNewline -ForegroundColor Green
      Write-Host $paddedName -NoNewline -ForegroundColor Green
      Write-Host " → " -NoNewline -ForegroundColor DarkGray
      Write-Host "Exemptions: $subFindingCount  Critical: $critSub  High: $highSub" -ForegroundColor White

      $subscriptionResults += @{
        Name    = $sub.Name
        Summary = "Exemptions: $subFindingCount  Critical: $critSub  High: $highSub"
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

  # ── Summary ───────────────────────────────────────────────────────────────
  $endTime  = Get-Date
  $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

  Write-Summary -Data ([ordered]@{
    "Total Subscriptions Scanned"  = $subCount
    "Successful"                   = $successCount
    "Errors"                       = $errorCount
    "Total Exemptions Found"       = $allFindings.Count
    "Execution Time"               = $duration
  })

  Write-RiskBreakdown -Findings $allFindings

  # ── Output files ──────────────────────────────────────────────────────────
  $csvExported    = $false
  $htmlExported   = $false
  $gridViewOpened = $false
  $htmlPath       = ""

  if ($allFindings.Count -gt 0) {

    if ($ExportToCsv) {
      try {
        $csvDir = Split-Path -Parent $CsvPath
        if ($csvDir -and -not (Test-Path $csvDir)) {
          New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
        }
        $allFindings | Select-Object `
          SubscriptionName, SubscriptionId, ExemptionName, Category, Description,
          PolicyAssignmentName, ScopeLevel, Scope, ExpiryStatus, ExpiryDate,
          AgeInDays, RiskLevel, RiskScore, RiskSignals, Recommendation |
          Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        $csvExported = $true
      }
      catch {
        Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
      }
    }

    try {
      $htmlPath    = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
      $sessionInfo = @{
        Tenant      = $ctx.Tenant.Id
        Account     = $ctx.Account.Id
        Environment = $ctx.Environment.Name
      }
      $scanParams  = @{
        Scope         = "$scopeText ($subCount found)"
        ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        ExecTime      = $duration
      }
      $htmlContent = Generate-ExemptionRiskHtml `
        -SessionInfo         $sessionInfo `
        -ScanParameters      $scanParams `
        -Findings            $allFindings `
        -SubscriptionResults $subscriptionResults `
        -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

      $htmlDir = Split-Path -Parent $htmlPath
      if ($htmlDir -and -not (Test-Path $htmlDir)) {
        New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null
      }
      $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
      $htmlExported = $true
    }
    catch {
      Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
    }

    try {
      $allFindings |
        Select-Object RiskLevel, RiskScore, ExemptionName, SubscriptionName,
          Category, ScopeLevel, ExpiryStatus, ExpiryDate, AgeInDays,
          PolicyAssignmentName |
        Sort-Object @{e={ switch ($_.RiskLevel) { "Critical"{0}"High"{1}"Medium"{2}"Low"{3} } }} |
        Out-GridView -Title "Azure Policy Exemption Risk Report"
      $gridViewOpened = $true
    }
    catch {
      Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
    }
  }
  else {
    Write-Host ""
    Write-Host "  ⚠ No policy exemptions found in the targeted subscriptions." -ForegroundColor Yellow
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
