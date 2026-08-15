<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Assesses Azure cost governance posture — budget coverage, alert health,
    tag compliance, resource group ownership, and cost allocation discipline
    — across one or more subscriptions, with optional spend trend analysis
    and an interactive HTML dashboard.

.DESCRIPTION
    Get-AzureCostGovernanceAssessment evaluates the cost governance framework
    across one or multiple subscriptions from a Cloud Solution Architect and
    FinOps perspective.

    Default assessment (fast, governance-structure only):
        - Budget coverage: presence, amount, time-grain, and expiry status
          of Cost Management budgets at subscription scope
        - Budget alert health: notification threshold count and whether any
          alert contacts (email or action group) are configured
        - Budget utilisation: current spend as a percentage of the budget
          amount; classified as OK / Warning / Critical / No Data based on
          the configurable thresholds
        - Tag compliance: evaluates each resource group for the presence of
          required tags (configurable via -RequiredTags); classifies
          coverage as Good / Partial / Missing
        - Resource group ownership: flags RGs where none of the required
          owner-identifying tags are present
        - Subscription governance score: composite of budget coverage,
          alert health, and tag compliance — expressed as a FinOps risk
          rating (Good / Needs Attention / Critical Gap)

    Optional spend trend analysis (-IncludeSpendAnalysis switch):
        - Calls the Azure Cost Management Query API (Invoke-AzRestMethod)
          per subscription to retrieve month-to-date and last-month spend
        - Computes month-over-month change (%) and flags unusual spikes
        - If the API call fails or is inaccessible (permissions, account
          type), the section is marked "Not Available" and the assessment
          continues without interruption
        - Note: Cost Management query access requires the Cost Management
          Reader role or equivalent at subscription scope

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and colour-coded per-subscription console output
        - Optional CSV export of all budget and tag findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable
          table, bar charts, distribution panels, detail drawer)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behaviour when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER RequiredTags
    String array of tag keys that are expected on every resource group.
    Tag matching is case-insensitive. Defaults to: Owner, CostCenter, Environment.

.PARAMETER BudgetWarningThreshold
    Integer (1–99). Budget utilisation percentage at which a budget is
    classified as Warning. Default: 80.

.PARAMETER BudgetCriticalThreshold
    Integer (1–200). Budget utilisation percentage at which a budget is
    classified as Critical. Default: 100.

.PARAMETER IncludeSpendAnalysis
    Switch. When specified, calls the Azure Cost Management Query API per
    subscription to retrieve month-to-date and last-month actual spend,
    then computes a month-over-month change percentage.
    Disabled by default for performance. Requires Cost Management Reader
    or equivalent. If the call fails, the section is marked "Not Available"
    and the scan continues.

.PARAMETER ExportToCsv
    Switch. If specified, exports all findings to the path given in
    -OutputDirectory. The HTML dashboard is always generated regardless.

.PARAMETER OutputDirectory
    Directory where the CSV and HTML files will be written.
    Default: C:\Temp

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard to
    -OutputDirectory. Optionally writes CSV files when -ExportToCsv is
    specified. Displays results in an interactive Grid View where a GUI
    is available.

.EXAMPLE
    Get-AzureCostGovernanceAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureCostGovernanceAssessment -AllSubscriptions -IncludeSpendAnalysis

.EXAMPLE
    Get-AzureCostGovernanceAssessment -SubscriptionIds @("sub-id-1","sub-id-2") -RequiredTags @("Owner","CostCenter","Project")

.EXAMPLE
    Get-AzureCostGovernanceAssessment -AllSubscriptions -IncludeSpendAnalysis -ExportToCsv -OutputDirectory "C:\Reports" -BudgetWarningThreshold 70 -BudgetCriticalThreshold 90

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Budget coverage, alert health,
                            utilisation, tag compliance, and governance scoring.
                            Optional spend trend via -IncludeSpendAnalysis.
                            CSV export and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az.Accounts  — Get-AzContext, Get-AzSubscription, Set-AzContext,
                          Invoke-AzRestMethod (budget + spend REST calls)
        2. Az.Resources — Get-AzResourceGroup, Get-AzTag
        3. Authenticated Azure session (Connect-AzAccount).
        4. Reader role (minimum) at subscription scope for resource enumeration.
        5. Cost Management Reader (or equivalent) at subscription scope is
           required for -IncludeSpendAnalysis. Without this permission the
           spend analysis section is gracefully marked "Not Available" and
           the assessment continues.
        6. Budget data is retrieved via the Azure Cost Management REST API
           (Invoke-AzRestMethod / Invoke-AzRestMethod) rather than the legacy
           Az.Billing Consumption cmdlets, which are restricted to Enterprise
           Agreement accounts. The REST approach works across EA, MCA, and
           Pay-As-You-Go subscription types.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Budget data is retrieved at subscription scope only. Management
          Group-scoped or resource-group-scoped budgets in Cost Management
          are not enumerated by this script.
        - Spend analysis via -IncludeSpendAnalysis relies on the
          Microsoft.CostManagement/query API. Access and data availability
          vary by subscription offer type and billing agreement. If access
          is denied, the section is marked "Not Available" and assessment
          continues.
        - Tag compliance checks are performed at the resource group level
          only; individual resource tags are not evaluated.
        - Budget utilisation shows "No Data" when the CurrentSpend property
          is null, which can occur for newly created budgets or subscriptions
          where cost data has not yet been ingested.
        - Interactive Grid View requires a GUI-capable session. Skipped
          gracefully in headless/CI/Linux sessions; CSV/HTML output is
          unaffected.
        - Default -OutputDirectory (C:\Temp) is Windows-specific. Supply an
          explicit -OutputDirectory on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets
    https://learn.microsoft.com/en-us/rest/api/cost-management/budgets/list
    https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/cost-mgt-best-practices
    https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/finops/

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CgCenteredText {
    param(
        [string]$Text,
        [int]$Width = 80,
        [string]$Color = "White"
    )
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-CgBanner {
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CgCenteredText "Azure Cost Governance Assessment v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-CgSection {
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

Function Write-CgScanProgress {
    Write-Host ""
    Write-Host "  Scanning Subscriptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
}

Function Write-CgProgressBar {
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

Function Write-CgSummary {
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

Function Write-CgGovernanceSummary {
    param([array]$SubResults)
    if ($SubResults.Count -eq 0) { return }
    $critical = @($SubResults | Where-Object { $_.GovernanceRating -eq "Critical Gap" }).Count
    $attention = @($SubResults | Where-Object { $_.GovernanceRating -eq "Needs Attention" }).Count
    $good = @($SubResults | Where-Object { $_.GovernanceRating -eq "Good" }).Count
    Write-Host ""
    Write-Host "  FinOps Governance Rating" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Critical Gap      : $critical subscription(s)" -ForegroundColor Red
    Write-Host "  Needs Attention   : $attention subscription(s)" -ForegroundColor Yellow
    Write-Host "  Good              : $good subscription(s)" -ForegroundColor Green
}

Function Write-CgOutputFiles {
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

Function Get-CgObjProperty {
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

Function Generate-CostGovernanceHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$BudgetFindings,
        [array]$TagFindings,
        [array]$SubResults,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [bool]$SpendAnalysisIncluded
    )

    $totalBudgets = @($BudgetFindings).Count
    $totalRGs = @($TagFindings).Count
    $subsWithBudget = @($SubResults | Where-Object { $_.BudgetCount -gt 0 }).Count
    $subsNoBudget = @($SubResults | Where-Object { $_.BudgetCount -eq 0 }).Count
    $criticalBudgets = @($BudgetFindings | Where-Object { $_.UtilisationStatus -eq "Critical" }).Count
    $warningBudgets = @($BudgetFindings | Where-Object { $_.UtilisationStatus -eq "Warning" }).Count
    $noAlertBudgets = @($BudgetFindings | Where-Object { $_.AlertConfigured -eq $false }).Count
    $rgsGoodTag = @($TagFindings | Where-Object { $_.TagCoverage -eq "Good" }).Count
    $rgsPartialTag = @($TagFindings | Where-Object { $_.TagCoverage -eq "Partial" }).Count
    $rgsMissingTag = @($TagFindings | Where-Object { $_.TagCoverage -eq "Missing" }).Count

    $spendBannerCls = if ($SpendAnalysisIncluded) { "included" } else { "skipped" }
    $spendBannerText = if ($SpendAnalysisIncluded) { "Included" } else { "Skipped — use -IncludeSpendAnalysis to enable" }

    # ── Budget status distribution bar rows ──────────────────────────────────
    $budgetStatusDist = @{ OK = 0; Warning = 0; Critical = 0; "No Data" = 0 }
    foreach ($b in $BudgetFindings) {
        if ($budgetStatusDist.ContainsKey($b.UtilisationStatus)) { $budgetStatusDist[$b.UtilisationStatus]++ }
        else { $budgetStatusDist["No Data"]++ }
    }
    $budgetDistRows = ""
    $budgetBarColors = @{ OK = "var(--green)"; Warning = "var(--amber)"; Critical = "var(--red)"; "No Data" = "var(--muted)" }
    $budgetOrder = @("Critical", "Warning", "OK", "No Data")
    foreach ($key in $budgetOrder) {
        $count = $budgetStatusDist[$key]
        $pct = if ($totalBudgets -gt 0) { [math]::Round(($count / $totalBudgets) * 100) } else { 0 }
        $budgetDistRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$($budgetBarColors[$key])"></div></div>
            <span class="bar-pct">$count ($pct%)</span>
          </div>
"@
    }

    # ── Tag coverage distribution bar rows ───────────────────────────────────
    $tagCoverageOrder = @("Good", "Partial", "Missing")
    $tagCoverageColors = @{ Good = "var(--green)"; Partial = "var(--amber)"; Missing = "var(--red)" }
    $tagCoverageCount = @{ Good = $rgsGoodTag; Partial = $rgsPartialTag; Missing = $rgsMissingTag }
    $tagDistRows = ""
    foreach ($key in $tagCoverageOrder) {
        $count = $tagCoverageCount[$key]
        $pct = if ($totalRGs -gt 0) { [math]::Round(($count / $totalRGs) * 100) } else { 0 }
        $tagDistRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$($tagCoverageColors[$key])"></div></div>
            <span class="bar-pct">$count ($pct%)</span>
          </div>
"@
    }

    # ── Governance rating bars ────────────────────────────────────────────────
    $govDist = @{ Good = 0; "Needs Attention" = 0; "Critical Gap" = 0 }
    foreach ($s in $SubResults) {
        if ($govDist.ContainsKey($s.GovernanceRating)) { $govDist[$s.GovernanceRating]++ }
    }
    $govColors = @{ Good = "var(--green)"; "Needs Attention" = "var(--amber)"; "Critical Gap" = "var(--red)" }
    $govRows = ""
    foreach ($key in @("Critical Gap", "Needs Attention", "Good")) {
        $count = $govDist[$key]
        $pct = if ($SubResults.Count -gt 0) { [math]::Round(($count / $SubResults.Count) * 100) } else { 0 }
        $govRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$($govColors[$key])"></div></div>
            <span class="bar-pct">$count ($pct%)</span>
          </div>
"@
    }

    # ── Top 5 at-risk subscriptions ───────────────────────────────────────────
    $topAtRisk = ""
    $atRiskSorted = @($SubResults |
        Sort-Object @{ Expression = {
                switch ($_.GovernanceRating) { "Critical Gap" { 0 }; "Needs Attention" { 1 }; default { 2 } }
            }
        }, @{ Expression = { $_.TagMissingCount }; Descending = $true } |
        Select-Object -First 5)
    foreach ($s in $atRiskSorted) {
        $icon = switch ($s.GovernanceRating) { "Critical Gap" { "🔴" }; "Needs Attention" { "🟠" }; default { "🟢" } }
        $cls = switch ($s.GovernanceRating) { "Critical Gap" { "c-red" }; "Needs Attention" { "c-amber" }; default { "c-green" } }
        $topAtRisk += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $s.SubscriptionName)</span>
            <span class="sub-detail">$(EscHtml $s.GovernanceRating) · Budgets: $($s.BudgetCount) · RGs without full tags: $($s.TagMissingCount)</span>
          </div>
"@
    }

    # ── Budget findings table rows ────────────────────────────────────────────
    $budgetRows = ""
    $utilBadgeMap = @{ OK = "badge-green"; Warning = "badge-amber"; Critical = "badge-red"; "No Data" = "" }
    foreach ($b in ($BudgetFindings | Sort-Object @{ Expression = {
                    switch ($_.UtilisationStatus) { "Critical" { 0 }; "Warning" { 1 }; "No Data" { 2 }; default { 3 } }
                } 
            })) {
        $uCls = if ($utilBadgeMap.ContainsKey($b.UtilisationStatus)) { $utilBadgeMap[$b.UtilisationStatus] } else { "" }
        $alertBadge = if ($b.AlertConfigured) { '<span class="badge badge-green">✓ Configured</span>' } else { '<span class="badge badge-red">✗ None</span>' }
        $utilPct = if ($b.UtilisationPct -ge 0) { "$($b.UtilisationPct)%" } else { "—" }
        $budgetRows += @"
          <tr onclick="showBudgetDetail($($BudgetFindings.IndexOf($b)))">
            <td title="$(EscHtml $b.BudgetName)">$(if ($b.BudgetName.Length -gt 34) { EscHtml($b.BudgetName.Substring(0,31)+"...") } else { EscHtml $b.BudgetName })</td>
            <td>$(EscHtml $b.SubscriptionName)</td>
            <td style="font-family:var(--mono)">$(EscHtml $b.AmountFormatted)</td>
            <td style="font-family:var(--mono)">$utilPct</td>
            <td><span class="badge $uCls">$(EscHtml $b.UtilisationStatus)</span></td>
            <td>$(EscHtml $b.TimeGrain)</td>
            <td>$alertBadge</td>
          </tr>
"@
    }

    # ── Tag findings table rows ───────────────────────────────────────────────
    $tagRows = ""
    $tagCovBadgeMap = @{ Good = "badge-green"; Partial = "badge-amber"; Missing = "badge-red" }
    foreach ($t in ($TagFindings | Sort-Object @{ Expression = {
                    switch ($_.TagCoverage) { "Missing" { 0 }; "Partial" { 1 }; default { 2 } }
                } 
            })) {
        $cCls = if ($tagCovBadgeMap.ContainsKey($t.TagCoverage)) { $tagCovBadgeMap[$t.TagCoverage] } else { "" }
        $tagRows += @"
          <tr onclick="showTagDetail($($TagFindings.IndexOf($t)))">
            <td title="$(EscHtml $t.ResourceGroupName)">$(if ($t.ResourceGroupName.Length -gt 32) { EscHtml($t.ResourceGroupName.Substring(0,29)+"...") } else { EscHtml $t.ResourceGroupName })</td>
            <td>$(EscHtml $t.SubscriptionName)</td>
            <td style="text-align:center;font-family:var(--mono)">$($t.PresentTagCount) / $($t.RequiredTagCount)</td>
            <td><span class="badge $cCls">$(EscHtml $t.TagCoverage)</span></td>
            <td style="font-size:11px;color:var(--muted2)">$(EscHtml $t.MissingTags)</td>
          </tr>
"@
    }

    # ── Spend analysis table rows ─────────────────────────────────────────────
    $spendRows = ""
    foreach ($s in ($SubResults | Sort-Object @{ Expression = { [math]::Abs($_.MoMChangePct) }; Descending = $true })) {
        if (-not $SpendAnalysisIncluded) { continue }
        $momBadge = if ($s.SpendStatus -eq "Not Available") {
            '<span class="badge" style="background:var(--surface3);color:var(--muted)">N/A</span>'
        }
        elseif ($s.MoMChangePct -gt 30) {
            "<span class='badge badge-red'>▲ $($s.MoMChangePct)%</span>"
        }
        elseif ($s.MoMChangePct -lt -10) {
            "<span class='badge badge-green'>▼ $([math]::Abs($s.MoMChangePct))%</span>"
        }
        else {
            "<span class='badge badge-blue'>$($s.MoMChangePct)%</span>"
        }
        $spendRows += @"
          <tr>
            <td>$(EscHtml $s.SubscriptionName)</td>
            <td style="font-family:var(--mono)">$(EscHtml $s.LastMonthSpend)</td>
            <td style="font-family:var(--mono)">$(EscHtml $s.MtdSpend)</td>
            <td>$momBadge</td>
            <td>$(EscHtml $s.SpendStatus)</td>
          </tr>
"@
    }

    # ── Subscription scan results ─────────────────────────────────────────────
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

    # ── JSON for budget detail drawer ─────────────────────────────────────────
    $budgetJson = "["
    foreach ($b in $BudgetFindings) {
        $budgetJson += "{" +
        """name"":""$(EscJ $b.BudgetName)""," +
        """sub"":""$(EscJ $b.SubscriptionName)""," +
        """amount"":""$(EscJ $b.AmountFormatted)""," +
        """grain"":""$(EscJ $b.TimeGrain)""," +
        """startDate"":""$(EscJ $b.StartDate)""," +
        """endDate"":""$(EscJ $b.EndDate)""," +
        """currentSpend"":""$(EscJ $b.CurrentSpendFormatted)""," +
        """utilisationPct"":$(if ($b.UtilisationPct -ge 0) { $b.UtilisationPct } else { -1 })," +
        """utilisationStatus"":""$(EscJ $b.UtilisationStatus)""," +
        """alertConfigured"":$(if ($b.AlertConfigured) { "true" } else { "false" })," +
        """alertThresholds"":""$(EscJ $b.AlertThresholds)""," +
        """alertContacts"":""$(EscJ $b.AlertContacts)""" +
        "},"
    }
    $budgetJson = $budgetJson.TrimEnd(",") + "]"

    # ── JSON for tag detail drawer ────────────────────────────────────────────
    $tagJsonLines = "["
    foreach ($t in $TagFindings) {
        $tagJsonLines += "{" +
        """rgName"":""$(EscJ $t.ResourceGroupName)""," +
        """sub"":""$(EscJ $t.SubscriptionName)""," +
        """location"":""$(EscJ $t.Location)""," +
        """coverage"":""$(EscJ $t.TagCoverage)""," +
        """present"":$($t.PresentTagCount)," +
        """required"":$($t.RequiredTagCount)," +
        """presentTags"":""$(EscJ $t.PresentTags)""," +
        """missingTags"":""$(EscJ $t.MissingTags)""" +
        "},"
    }
    $tagJsonLines = $tagJsonLines.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Cost Governance Dashboard</title>
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
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
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
.bar-label{font-size:12px;color:var(--muted2);width:140px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
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
.info-value.muted{color:var(--muted);font-style:italic;}
.cs-banner{padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:16px;display:flex;align-items:center;gap:10px;font-size:13px;}
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
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:440px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
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
    <div class="logo-icon">💰</div>
    <div class="logo-title">Cost Governance</div>
    <div class="logo-sub">Azure FinOps Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('budgets',this)"><span class="nav-icon">💵</span> Budgets</button>
    <button class="nav-btn" onclick="showPage('tags',this)"><span class="nav-icon">🏷️</span> Tag Governance</button>
    <button class="nav-btn" onclick="showPage('spend',this)"><span class="nav-icon">📈</span> Spend Analysis</button>
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
      Azure Cost Governance Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Cost Governance Overview</div>
      <div class="page-sub">FinOps governance posture across __SUB_COUNT__ subscription(s) · Required tags: __REQUIRED_TAGS__</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_BUDGETS__</div>
        <div class="stat-label">Budgets Found</div>
        <div class="stat-sub">__SUBS_WITH_BUDGET__ sub(s) covered</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__SUBS_NO_BUDGET__</div>
        <div class="stat-label">Subs Without Budget</div>
        <div class="stat-sub">No spend guardrail</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__CRITICAL_BUDGETS__</div>
        <div class="stat-label">Critical Budgets</div>
        <div class="stat-sub">__WARNING_BUDGETS__ at Warning</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__NO_ALERT_BUDGETS__</div>
        <div class="stat-label">Budgets Without Alerts</div>
        <div class="stat-sub">Silent overruns possible</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__RGS_GOOD_TAG__</div>
        <div class="stat-label">RGs Fully Tagged</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__RGS_MISSING_TAG__</div>
        <div class="stat-label">RGs Missing All Tags</div>
        <div class="stat-sub">__RGS_PARTIAL_TAG__ partial</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">💵 Budget Utilisation Status</div>
        __BUDGET_DIST_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🏷️ Resource Group Tag Coverage</div>
        __TAG_DIST_ROWS__
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📊 Subscription Governance Rating</div>
        __GOV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">⚠️ At-Risk Subscriptions</div>
        <div class="sub-list">__TOP_AT_RISK__</div>
      </div>
    </div>
  </div>

  <!-- Budgets -->
  <div id="page-budgets" class="page">
    <div class="page-header">
      <div class="page-title">Budget Assessment</div>
      <div class="page-sub">Click any row for full alert and period details. Sorted by criticality first.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="budgetSearch" placeholder="Search budget, subscription…" oninput="filterBudgets()"/>
        </div>
        <select class="filter-select" id="filterUtil" onchange="filterBudgets()">
          <option value="">All Statuses</option>
          <option value="Critical">Critical</option>
          <option value="Warning">Warning</option>
          <option value="OK">OK</option>
          <option value="No Data">No Data</option>
        </select>
        <select class="filter-select" id="pgSizeBudget" onchange="changeBudgetPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="budgetTable">
          <thead>
            <tr>
              <th onclick="sortBudgets(0)">Budget Name</th>
              <th onclick="sortBudgets(1)">Subscription</th>
              <th onclick="sortBudgets(2)">Amount</th>
              <th onclick="sortBudgets(3)">Utilisation %</th>
              <th onclick="sortBudgets(4)">Status</th>
              <th onclick="sortBudgets(5)">Time Grain</th>
              <th>Alert Contacts</th>
            </tr>
          </thead>
          <tbody id="budgetBody">__BUDGET_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="budgetPagination"></div>
    </div>
  </div>

  <!-- Tag Governance -->
  <div id="page-tags" class="page">
    <div class="page-header">
      <div class="page-title">Tag Governance</div>
      <div class="page-sub">Resource group tag compliance for required tags: __REQUIRED_TAGS__ · Click any row for tag detail.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="tagSearch" placeholder="Search resource group, subscription…" oninput="filterTags()"/>
        </div>
        <select class="filter-select" id="filterCoverage" onchange="filterTags()">
          <option value="">All Coverage Levels</option>
          <option value="Missing">Missing</option>
          <option value="Partial">Partial</option>
          <option value="Good">Good</option>
        </select>
        <select class="filter-select" id="pgSizeTag" onchange="changeTagPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="tagTable">
          <thead>
            <tr>
              <th onclick="sortTags(0)">Resource Group</th>
              <th onclick="sortTags(1)">Subscription</th>
              <th onclick="sortTags(2)">Tags Present</th>
              <th onclick="sortTags(3)">Coverage</th>
              <th>Missing Tags</th>
            </tr>
          </thead>
          <tbody id="tagBody">__TAG_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="tagPagination"></div>
    </div>
  </div>

  <!-- Spend Analysis -->
  <div id="page-spend" class="page">
    <div class="page-header">
      <div class="page-title">Spend Analysis</div>
      <div class="page-sub">Month-over-month spend trends per subscription. Spikes >30% are flagged for review.</div>
    </div>
    <div class="cs-banner __SPEND_BANNER_CLS__">
      <span>📈</span>
      <span><strong>Spend Analysis:</strong> __SPEND_BANNER_TEXT__</span>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Subscription</th>
              <th>Last Month (USD)</th>
              <th>Month to Date (USD)</th>
              <th>MoM Change</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>__SPEND_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription cost governance assessment outcome</div>
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
        <div class="info-card"><div class="info-label">Required Tags</div><div class="info-value">__REQUIRED_TAGS__</div></div>
        <div class="info-card"><div class="info-label">Warning Threshold</div><div class="info-value">__WARN_THRESHOLD__%</div></div>
        <div class="info-card"><div class="info-label">Critical Threshold</div><div class="info-value">__CRIT_THRESHOLD__%</div></div>
        <div class="info-card"><div class="info-label">Spend Analysis</div><div class="info-value">__SPEND_TEXT__</div></div>
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
const BUDGET_DATA = __BUDGET_JSON__;
const TAG_DATA_RAW = `__TAG_JSON_RAW__`;
let TAG_DATA = [];
try { TAG_DATA = JSON.parse(TAG_DATA_RAW); } catch(e){}

let budgetFiltered = [...BUDGET_DATA];
let budgetPage = 1, budgetPageSz = 25;
let budgetSortCol = -1, budgetSortAsc = true;
let tagFiltered = [...TAG_DATA];
let tagPage = 1, tagPageSz = 25;
let tagSortCol = -1, tagSortAsc = true;
let currentDetailMode = 'budget';
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

// ── Budgets table ──────────────────────────────────────────────────────────────
const utilBadge={'Critical':'badge-red','Warning':'badge-amber','OK':'badge-green','No Data':''};

function filterBudgets(){
  const q=document.getElementById('budgetSearch').value.toLowerCase();
  const u=document.getElementById('filterUtil').value;
  budgetFiltered=BUDGET_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mU=!u||r.utilisationStatus===u;
    return mQ&&mU;
  });
  budgetPage=1; renderBudgets();
}

function changeBudgetPageSize(){
  budgetPageSz=parseInt(document.getElementById('pgSizeBudget').value);
  budgetPage=1; renderBudgets();
}

function sortBudgets(col){
  if(budgetSortCol===col){budgetSortAsc=!budgetSortAsc;}else{budgetSortCol=col;budgetSortAsc=true;}
  const keys=['name','sub','amount','utilisationPct','utilisationStatus','grain','alertConfigured'];
  budgetFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    return budgetSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                        :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderBudgets();
}

function renderBudgets(){
  const tbody=document.getElementById('budgetBody');
  const start=(budgetPage-1)*budgetPageSz;
  const slice=budgetFiltered.slice(start,start+budgetPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=BUDGET_DATA.indexOf(r);
    const nm=r.name.length>34?r.name.substring(0,31)+'...':r.name;
    const uCls=utilBadge[r.utilisationStatus]||'';
    const pct=r.utilisationPct>=0?r.utilisationPct+'%':'—';
    const alertB=r.alertConfigured?'<span class="badge badge-green">✓ Configured</span>':'<span class="badge badge-red">✗ None</span>';
    return `<tr onclick="showBudgetDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td style="font-family:var(--mono)">${escH(r.amount)}</td>
      <td style="font-family:var(--mono)">${pct}</td>
      <td><span class="badge ${uCls}">${escH(r.utilisationStatus)}</span></td>
      <td>${escH(r.grain)}</td>
      <td>${alertB}</td>
    </tr>`;
  }).join('');
  renderBudgetPg();
}

function renderBudgetPg(){
  const total=Math.ceil(budgetFiltered.length/budgetPageSz);
  const el=document.getElementById('budgetPagination');
  let h=`<span>${budgetFiltered.length} budgets</span>`;
  h+=`<button class="pg-btn" onclick="changeBudgetPage(${budgetPage-1})" ${budgetPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,budgetPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===budgetPage?'active':''}" onclick="changeBudgetPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeBudgetPage(${budgetPage+1})" ${budgetPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeBudgetPage(p){
  const total=Math.ceil(budgetFiltered.length/budgetPageSz);
  if(p<1||p>total)return;
  budgetPage=p; renderBudgets();
}

// ── Tag table ──────────────────────────────────────────────────────────────────
function filterTags(){
  const q=document.getElementById('tagSearch').value.toLowerCase();
  const c=document.getElementById('filterCoverage').value;
  tagFiltered=TAG_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mC=!c||r.coverage===c;
    return mQ&&mC;
  });
  tagPage=1; renderTags();
}

function changeTagPageSize(){
  tagPageSz=parseInt(document.getElementById('pgSizeTag').value);
  tagPage=1; renderTags();
}

function sortTags(col){
  if(tagSortCol===col){tagSortAsc=!tagSortAsc;}else{tagSortCol=col;tagSortAsc=true;}
  const keys=['rgName','sub','present','coverage'];
  tagFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    return tagSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                     :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderTags();
}

function renderTags(){
  const tbody=document.getElementById('tagBody');
  const start=(tagPage-1)*tagPageSz;
  const slice=tagFiltered.slice(start,start+tagPageSz);
  const cvBadge={'Good':'badge-green','Partial':'badge-amber','Missing':'badge-red'};
  tbody.innerHTML=slice.map(r=>{
    const gi=TAG_DATA.indexOf(r);
    const nm=r.rgName.length>32?r.rgName.substring(0,29)+'...':r.rgName;
    const cCls=cvBadge[r.coverage]||'';
    return `<tr onclick="showTagDetail(${gi})">
      <td title="${escH(r.rgName)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td style="text-align:center;font-family:var(--mono)">${r.present} / ${r.required}</td>
      <td><span class="badge ${cCls}">${escH(r.coverage)}</span></td>
      <td style="font-size:11px;color:var(--muted2)">${escH(r.missingTags||'—')}</td>
    </tr>`;
  }).join('');
  renderTagPg();
}

function renderTagPg(){
  const total=Math.ceil(tagFiltered.length/tagPageSz);
  const el=document.getElementById('tagPagination');
  let h=`<span>${tagFiltered.length} resource groups</span>`;
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

// ── Detail drawers ─────────────────────────────────────────────────────────────
function showBudgetDetail(idx){
  currentDetailMode='budget';
  currentDetailIdx=idx;
  const r=BUDGET_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${BUDGET_DATA.length}`;
  const uCls=utilBadge[r.utilisationStatus]||'';
  const pct=r.utilisationPct>=0?r.utilisationPct+'%':'No Data';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Utilisation Status</div>
      <div class="drawer-field-value"><span class="badge ${uCls}">${escH(r.utilisationStatus)}</span> — ${pct}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Budget Amount</div>
      <div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.amount)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Current Spend</div>
      <div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.currentSpend)||'No Data'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Time Grain</div>
      <div class="drawer-field-value">${escH(r.grain)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Period</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.startDate)} → ${escH(r.endDate)}</div></div>
    <div class="drawer-section">Alert Configuration</div>
    <div class="drawer-field"><div class="drawer-field-label">Alert Contacts Configured</div>
      <div class="drawer-field-value">${r.alertConfigured?'<span class="badge badge-green">✓ Yes</span>':'<span class="badge badge-red">✗ No — silent overrun risk</span>'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Alert Thresholds</div>
      <div class="drawer-field-value">${escH(r.alertThresholds)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Alert Contacts</div>
      <div class="drawer-field-value" style="font-size:11px">${escH(r.alertContacts)||'—'}</div></div>
  `;
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}

function showTagDetail(idx){
  currentDetailMode='tag';
  currentDetailIdx=idx;
  const r=TAG_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.rgName;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${TAG_DATA.length}`;
  const cvBadge={'Good':'badge-green','Partial':'badge-amber','Missing':'badge-red'};
  const cCls=cvBadge[r.coverage]||'';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Tag Coverage</div>
      <div class="drawer-field-value"><span class="badge ${cCls}">${escH(r.coverage)}</span> — ${r.present} of ${r.required} required tags present</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Location</div>
      <div class="drawer-field-value">${escH(r.location)||'—'}</div></div>
    <div class="drawer-section">Tag Detail</div>
    <div class="drawer-field"><div class="drawer-field-label">Tags Present</div>
      <div class="drawer-field-value" style="font-size:11px">${escH(r.presentTags)||'None'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Tags Missing</div>
      <div class="drawer-field-value" style="font-size:11px;color:var(--red)">${escH(r.missingTags)||'None'}</div></div>
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
  if(currentDetailMode==='budget'&&next>=0&&next<BUDGET_DATA.length) showBudgetDetail(next);
  if(currentDetailMode==='tag'&&next>=0&&next<TAG_DATA.length) showTagDetail(next);
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

// ── Init ────────────────────────────────────────────────────────────────────
filterBudgets();
filterTags();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__REQUIRED_TAGS__', $ScanParameters.RequiredTags `
        -replace '__TOTAL_BUDGETS__', $totalBudgets `
        -replace '__SUBS_WITH_BUDGET__', $subsWithBudget `
        -replace '__SUBS_NO_BUDGET__', $subsNoBudget `
        -replace '__CRITICAL_BUDGETS__', $criticalBudgets `
        -replace '__WARNING_BUDGETS__', $warningBudgets `
        -replace '__NO_ALERT_BUDGETS__', $noAlertBudgets `
        -replace '__RGS_GOOD_TAG__', $rgsGoodTag `
        -replace '__RGS_PARTIAL_TAG__', $rgsPartialTag `
        -replace '__RGS_MISSING_TAG__', $rgsMissingTag `
        -replace '__BUDGET_DIST_ROWS__', $budgetDistRows `
        -replace '__TAG_DIST_ROWS__', $tagDistRows `
        -replace '__GOV_ROWS__', $govRows `
        -replace '__TOP_AT_RISK__', $topAtRisk `
        -replace '__BUDGET_ROWS__', $budgetRows `
        -replace '__TAG_ROWS__', $tagRows `
        -replace '__SPEND_ROWS__', $spendRows `
        -replace '__SPEND_BANNER_CLS__', $spendBannerCls `
        -replace '__SPEND_BANNER_TEXT__', $spendBannerText `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__WARN_THRESHOLD__', $ScanParameters.WarnThreshold `
        -replace '__CRIT_THRESHOLD__', $ScanParameters.CritThreshold `
        -replace '__SPEND_TEXT__', $spendBannerText `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__BUDGET_JSON__', $budgetJson `
        -replace '__TAG_JSON_RAW__', ($tagJsonLines -replace '`', '``')

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureCostGovernanceAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [string[]]$RequiredTags = @("Owner", "CostCenter", "Environment"),

        [ValidateRange(1, 99)]
        [int]$BudgetWarningThreshold = 80,

        [ValidateRange(1, 200)]
        [int]$BudgetCriticalThreshold = 100,

        [switch]$IncludeSpendAnalysis,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$OutputDirectory = "C:\Temp"
    )

    $startTime = Get-Date

    Write-CgBanner

    # ── Module check ──────────────────────────────────────────────────────────
    # Az.Accounts  : Get-AzContext, Get-AzSubscription, Set-AzContext, Invoke-AzRestMethod
    # Az.Resources : Get-AzResourceGroup, Get-AzTag
    $requiredModules = @("Az.Accounts", "Az.Resources")

    $missingModules = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missingModules) {
        Write-Host "  ✗ Required Az module(s) not found: $($missingModules -join ', ')" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Install them manually with:" -ForegroundColor Yellow
        foreach ($m in $missingModules) {
            Write-Host "      Install-Module -Name $m -Scope CurrentUser -AllowClobber -Force" -ForegroundColor Gray
        }
        Write-Host ""
        return
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

    # ── Validate output directory ─────────────────────────────────────────────
    if (-not (Test-Path $OutputDirectory)) {
        try {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }
        catch {
            Write-Host "  ✗ Cannot create output directory '$OutputDirectory': $_" -ForegroundColor Red
            return
        }
    }

    # ── Display session / params ──────────────────────────────────────────────
    Write-CgSection -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-CgSection -Title "Scan Parameters" -Data @{
        "Scope"              = "$scopeText ($subCount found)"
        "Required Tags"      = $RequiredTags -join ", "
        "Warning Threshold"  = "$BudgetWarningThreshold%"
        "Critical Threshold" = "$BudgetCriticalThreshold%"
        "Spend Analysis"     = if ($IncludeSpendAnalysis) { "Enabled (Cost Management Query API)" } else { "Skipped (use -IncludeSpendAnalysis to enable)" }
        "Export to CSV"      = if ($ExportToCsv.IsPresent) { "Enabled — $OutputDirectory" } else { "Disabled" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allBudgetFindings = @()
    $allTagFindings = @()
    $allSubResults = @()
    $subscriptionResults = @()
    $successCount = 0
    $errorCount = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-CgScanProgress
    Write-CgProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = ([math]::Max(
            ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
            35
        ))

    $subIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-CgProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            # ── Budget discovery via Cost Management REST API ──────────────────
            # Uses Invoke-AzRestMethod against microsoft.CostManagement/budgets
            # (api-version 2023-11-01) which works across EA, MCA, and PAYG
            # subscriptions — unlike the legacy Az.Billing Consumption cmdlets
            # which are restricted to Enterprise Agreement accounts only.
            $budgetsFound = @()
            $budgetApiUri = "/subscriptions/$($sub.Id)/providers/Microsoft.Consumption/budgets?api-version=2023-04-01"
            try {
                $budgetResp = Invoke-AzRestMethod -Path $budgetApiUri -Method GET -ErrorAction Stop
                if ($budgetResp.StatusCode -eq 200) {
                    $budgetContent = $budgetResp.Content | ConvertFrom-Json -ErrorAction Stop
                    $budgetsFound = @($budgetContent.value)
                }
                else {
                    Write-Verbose "  Budget API returned $($budgetResp.StatusCode) for $($sub.Name)"
                }
            }
            catch {
                Write-Verbose "  Could not retrieve budgets for $($sub.Name): $_"
            }

            foreach ($b in $budgetsFound) {
                $bp = if ($b.properties) { $b.properties } else { $b }

                # Amount
                $amount = Get-CgObjProperty -Obj $bp -PropName 'amount'    -Default 0
                $currency = Get-CgObjProperty -Obj $bp -PropName 'currency'  -Default 'USD'
                $timeGrain = Get-CgObjProperty -Obj $bp -PropName 'timeGrain' -Default 'Monthly'

                # Current spend — may be null for new budgets
                $currentSpend = $null
                $utilisationPct = -1
                $utilisationStat = "No Data"
                try {
                    $csObj = Get-CgObjProperty -Obj $bp -PropName 'currentSpend' -Default $null
                    if ($csObj) {
                        $currentSpend = [double](Get-CgObjProperty -Obj $csObj -PropName 'amount' -Default 0)
                        if ($amount -gt 0) {
                            $utilisationPct = [math]::Round(($currentSpend / $amount) * 100, 1)
                            $utilisationStat = if ($utilisationPct -ge $BudgetCriticalThreshold) { "Critical" }
                            elseif ($utilisationPct -ge $BudgetWarningThreshold) { "Warning" }
                            else { "OK" }
                        }
                    }
                }
                catch { Write-Verbose "  Could not parse currentSpend for $($b.name)" }

                # Time period
                $tpObj = Get-CgObjProperty -Obj $bp -PropName 'timePeriod' -Default $null
                $startDt = if ($tpObj) { Get-CgObjProperty -Obj $tpObj -PropName 'startDate' -Default "N/A" } else { "N/A" }
                $endDt = if ($tpObj) { Get-CgObjProperty -Obj $tpObj -PropName 'endDate'   -Default "N/A" } else { "N/A" }

                # Alert notifications
                $alertThresholds = @()
                $alertContacts = @()
                $alertConfigured = $false
                try {
                    $notifications = Get-CgObjProperty -Obj $bp -PropName 'notifications' -Default $null
                    if ($notifications) {
                        $notifications.PSObject.Properties | ForEach-Object {
                            $n = $_.Value
                            $threshold = Get-CgObjProperty -Obj $n -PropName 'threshold' -Default ""
                            if ($threshold) { $alertThresholds += "$threshold%" }
                            $emails = Get-CgObjProperty -Obj $n -PropName 'contactEmails' -Default @()
                            $groups = Get-CgObjProperty -Obj $n -PropName 'contactGroups' -Default @()
                            if ($emails -or $groups) { $alertConfigured = $true }
                            $alertContacts += $emails
                            $alertContacts += $groups
                        }
                    }
                }
                catch { Write-Verbose "  Could not parse notifications for $($b.name)" }

                $allBudgetFindings += [pscustomobject]@{
                    SubscriptionName      = $sub.Name
                    SubscriptionId        = $sub.Id
                    BudgetName            = if ($b.name) { $b.name } else { "Unknown" }
                    AmountFormatted       = "$currency $amount"
                    Amount                = [double]$amount
                    Currency              = $currency
                    TimeGrain             = $timeGrain
                    StartDate             = $startDt
                    EndDate               = $endDt
                    CurrentSpend          = $currentSpend
                    CurrentSpendFormatted = if ($null -ne $currentSpend) { "$currency $currentSpend" } else { "No Data" }
                    UtilisationPct        = $utilisationPct
                    UtilisationStatus     = $utilisationStat
                    AlertConfigured       = $alertConfigured
                    AlertThresholds       = ($alertThresholds -join ", ")
                    AlertContacts         = (($alertContacts | Select-Object -Unique) -join "; ")
                }
            }

            # ── Tag compliance — resource group level ──────────────────────────
            $rgs = @()
            try {
                $rgs = @(Get-AzResourceGroup -ErrorAction Stop)
            }
            catch {
                Write-Warning "  Could not retrieve resource groups for $($sub.Name): $_"
            }

            $tagMissingCount = 0
            foreach ($rg in $rgs) {
                $rgTags = if ($rg.Tags) { $rg.Tags } else { @{} }

                $presentTags = @()
                $missingTags = @()
                foreach ($reqTag in $RequiredTags) {
                    $matched = $rgTags.Keys | Where-Object { $_ -ieq $reqTag }
                    if ($matched) { $presentTags += $reqTag }
                    else { $missingTags += $reqTag }
                }

                $coverage = if ($missingTags.Count -eq 0) { "Good" }
                elseif ($presentTags.Count -eq 0) { "Missing" }
                else { "Partial" }

                if ($coverage -ne "Good") { $tagMissingCount++ }

                $allTagFindings += [pscustomobject]@{
                    SubscriptionName  = $sub.Name
                    SubscriptionId    = $sub.Id
                    ResourceGroupName = $rg.ResourceGroupName
                    Location          = $rg.Location
                    TagCoverage       = $coverage
                    PresentTagCount   = $presentTags.Count
                    RequiredTagCount  = $RequiredTags.Count
                    PresentTags       = ($presentTags -join ", ")
                    MissingTags       = ($missingTags -join ", ")
                }
            }

            # ── Spend analysis (optional) ──────────────────────────────────────
            $lastMonthSpend = "Not Available"
            $mtdSpend = "Not Available"
            $momChangePct = 0
            $spendStatus = "Not Requested"

            if ($IncludeSpendAnalysis) {
                $spendStatus = "Not Available"
                try {
                    $now = Get-Date
                    $mtdStart = (Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0).ToString("yyyy-MM-dd")
                    $mtdEnd = $now.ToString("yyyy-MM-dd")
                    $lastMoStart = (Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0).AddMonths(-1).ToString("yyyy-MM-dd")
                    $lastMoEnd = (Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0).AddDays(-1).ToString("yyyy-MM-dd")

                    $queryBody = @{
                        type       = "ActualCost"
                        timeframe  = "Custom"
                        timePeriod = @{ from = $lastMoStart; to = $mtdEnd }
                        dataset    = @{
                            granularity = "Monthly"
                            aggregation = @{ totalCost = @{ name = "Cost"; function = "Sum" } }
                        }
                    } | ConvertTo-Json -Depth 6

                    $spendUri = "/subscriptions/$($sub.Id)/providers/Microsoft.CostManagement/query?api-version=2023-11-01"
                    $spendResp = Invoke-AzRestMethod -Path $spendUri -Method POST -Payload $queryBody -ErrorAction Stop

                    if ($spendResp.StatusCode -in 200, 201) {
                        $spendData = $spendResp.Content | ConvertFrom-Json -ErrorAction Stop
                        $rows = @($spendData.properties.rows)

                        # rows = [cost, currency, billingMonth]
                        $lastMoRow = $rows | Where-Object { $_[2] -match ($lastMoStart.Substring(0, 7) -replace '-', '') }
                        $mtdRow = $rows | Where-Object { $_[2] -match ($mtdStart.Substring(0, 7) -replace '-', '') }

                        $lmAmt = if ($lastMoRow) { [math]::Round($lastMoRow[0], 2) } else { 0 }
                        $mtdAmt = if ($mtdRow) { [math]::Round($mtdRow[0], 2) }    else { 0 }

                        $lastMonthSpend = "USD $lmAmt"
                        $mtdSpend = "USD $mtdAmt"
                        $momChangePct = if ($lmAmt -gt 0) { [math]::Round((($mtdAmt - $lmAmt) / $lmAmt) * 100) } else { 0 }
                        $spendStatus = if ($momChangePct -gt 30) { "Spike Detected (>30%)" }
                        elseif ($momChangePct -lt -10) { "Significant Decrease" }
                        else { "Normal" }
                    }
                    else {
                        Write-Verbose "  Spend API returned $($spendResp.StatusCode) for $($sub.Name)"
                    }
                }
                catch {
                    Write-Host ""
                    Write-Host "  ⚠ Spend analysis unavailable for '$($sub.Name)': $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }

            # ── Subscription-level governance score ───────────────────────────
            # Composite rating based on: budget presence, alert health, tag coverage
            $hasBudget = ($budgetsFound.Count -gt 0)
            $hasAlerts = @($allBudgetFindings | Where-Object { $_.SubscriptionId -eq $sub.Id -and $_.AlertConfigured }).Count -gt 0
            $rgCount = $rgs.Count
            $missingTagRgs = @($allTagFindings | Where-Object { $_.SubscriptionId -eq $sub.Id -and $_.TagCoverage -ne "Good" }).Count
            $tagCovPct = if ($rgCount -gt 0) { [math]::Round((($rgCount - $missingTagRgs) / $rgCount) * 100) } else { 100 }

            $govRating = if (-not $hasBudget -or $tagCovPct -lt 50) { "Critical Gap" }
            elseif (-not $hasAlerts -or $tagCovPct -lt 80) { "Needs Attention" }
            else { "Good" }

            $allSubResults += [pscustomobject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                BudgetCount      = $budgetsFound.Count
                HasBudgetAlerts  = $hasAlerts
                RgCount          = $rgCount
                TagMissingCount  = $missingTagRgs
                TagCoveragePct   = $tagCovPct
                GovernanceRating = $govRating
                LastMonthSpend   = $lastMonthSpend
                MtdSpend         = $mtdSpend
                MoMChangePct     = $momChangePct
                SpendStatus      = $spendStatus
            }

            # ── Per-subscription console output ───────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Budgets: $($budgetsFound.Count)  RGs: $($rgs.Count)  Tag Coverage: $tagCovPct%  Rating: $govRating" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Budgets: $($budgetsFound.Count)  RGs: $($rgs.Count)  Tag Coverage: $tagCovPct%  Rating: $govRating"
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

    Write-CgSummary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Total Budgets Found"         = $allBudgetFindings.Count
            "Total Resource Groups"       = $allTagFindings.Count
            "Spend Analysis"              = if ($IncludeSpendAnalysis) { "Included" } else { "Skipped" }
            "Execution Time"              = $duration
        })

    Write-CgGovernanceSummary -SubResults $allSubResults

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""
    $csvPath = ""

    if ($allBudgetFindings.Count -gt 0 -or $allTagFindings.Count -gt 0) {

        # CSV export
        if ($ExportToCsv) {
            try {
                $csvPath = Join-Path $OutputDirectory "AzureCostGovernance-Budgets.csv"
                $allBudgetFindings | Select-Object `
                    SubscriptionName, SubscriptionId, BudgetName, AmountFormatted, TimeGrain,
                StartDate, EndDate, CurrentSpendFormatted, UtilisationPct, UtilisationStatus,
                AlertConfigured, AlertThresholds, AlertContacts |
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

                if ($allTagFindings.Count -gt 0) {
                    $tagCsvPath = Join-Path $OutputDirectory "AzureCostGovernance-Tags.csv"
                    $allTagFindings | Export-Csv -Path $tagCsvPath -NoTypeInformation -Encoding UTF8
                }

                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML dashboard
        try {
            $htmlPath = Join-Path $OutputDirectory "AzureCostGovernance-Dashboard.html"

            $sessionInfo = @{
                Tenant      = $ctx.Tenant.Id
                Account     = $ctx.Account.Id
                Environment = $ctx.Environment.Name
            }

            $scanParams = @{
                Scope         = "$scopeText ($subCount found)"
                RequiredTags  = $RequiredTags -join ", "
                WarnThreshold = $BudgetWarningThreshold
                CritThreshold = $BudgetCriticalThreshold
                ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime      = $duration
            }

            $htmlContent = Generate-CostGovernanceHtml `
                -SessionInfo           $sessionInfo `
                -ScanParameters        $scanParams `
                -BudgetFindings        $allBudgetFindings `
                -TagFindings           $allTagFindings `
                -SubResults            $allSubResults `
                -SubscriptionResults   $subscriptionResults `
                -GeneratedOn           (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -SpendAnalysisIncluded $IncludeSpendAnalysis.IsPresent

            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        # Grid View
        try {
            $allBudgetFindings |
            Select-Object SubscriptionName, BudgetName, AmountFormatted, CurrentSpendFormatted,
            UtilisationPct, UtilisationStatus, AlertConfigured, TimeGrain |
            Out-GridView -Title "Azure Cost Governance Assessment — Budgets"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No budget or resource group data found in the targeted subscriptions." -ForegroundColor Yellow
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        $outCsv = if ($csvExported) { $csvPath } else { $null }
        $outHtml = if ($htmlExported) { $htmlPath } else { $null }
        Write-CgOutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
