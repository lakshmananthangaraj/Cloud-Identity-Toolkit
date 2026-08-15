<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Identifies Azure resources that lack appropriate monitoring, diagnostic coverage,
    alerting, or observability — assessed against inferred business criticality —
    across one or more subscriptions, with an interactive HTML dashboard.

.DESCRIPTION
    Get-AzureCriticalResourceMonitoringGap connects business criticality with monitoring
    and observability posture. It goes beyond checking whether Diagnostic Settings are
    enabled. It evaluates whether important resources have sufficient coverage across
    multiple observability dimensions — diagnostics, log collection, metrics, alerts,
    and action group connectivity — to answer the question:

        "If this important resource experiences a problem, will the organization
         know about it quickly enough to respond?"

    Business Criticality Classification:
        Resources are classified into three tiers using heuristic signals:
        - Tier 1 (Business Critical):  Production workloads, databases, Key Vaults,
          API Management, Service Bus, Event Hub, Application Gateways,
          resources with production/prod naming patterns, or resources
          in subscriptions or resource groups with production indicators.
        - Tier 2 (Important):  Non-production resources of the above types,
          App Services, Container Apps, AKS, Logic Apps, Service Fabric.
        - Tier 3 (Standard):  Supporting infrastructure, storage accounts,
          development/test resources, and low-signal resources.

    Monitoring Gap Categories:
        DiagnosticGap       : Resource has no Diagnostic Settings configured
        LogGap              : Diagnostic Settings exist but no Log Analytics workspace
                              destination is configured
        MetricGap           : No metric alerts found for the resource or its resource group
        AlertGap            : Action Groups exist but no alert rules reference the resource
        ActionGroupGap      : Alert rules exist but point to empty or misconfigured Action Groups
        ObservabilityGap    : Multiple monitoring dimensions are absent simultaneously
                              (combined gap — highest business risk)

    Severity model:
        Tier 1 + ObservabilityGap     → Critical
        Tier 1 + DiagnosticGap        → High
        Tier 1 + any single gap       → High
        Tier 2 + ObservabilityGap     → High
        Tier 2 + DiagnosticGap        → Medium
        Tier 2 + any single gap       → Medium
        Tier 3 + any meaningful gap   → Low

    The script does not flag every resource that is missing one optional metric.
    It focuses on resources where monitoring gaps could meaningfully affect
    incident detection, response time, or business continuity.

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. Exports all monitoring gap findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same directory, .html extension).
    Default: C:\Temp\AzureMonitoringGap-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside -CsvPath
    (or the default path). Optionally writes a CSV file when -ExportToCsv is specified.
    Displays results in an interactive Grid View window where a GUI is available.

.EXAMPLE
    Get-AzureCriticalResourceMonitoringGap -AllSubscriptions

.EXAMPLE
    Get-AzureCriticalResourceMonitoringGap -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureCriticalResourceMonitoringGap -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\MonitoringGap.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Business-criticality-aware monitoring
                            gap assessment covering diagnostic settings, log
                            collection, metric alerting, action group connectivity,
                            and combined observability gap detection. CSV export
                            and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Monitor, Az.Resources) — installed
           automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at subscription scope.
        4. Microsoft.Insights/diagnosticSettings/read permission.
        5. Microsoft.Insights/metricAlerts/read and
           Microsoft.Insights/alertRules/read permission.
        6. Microsoft.Insights/actionGroups/read permission.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Business criticality is inferred from resource type, naming patterns,
          and resource group naming. It is a heuristic and may not reflect actual
          organizational criticality. Tags-based criticality overrides are not
          implemented in v1.0.
        - Diagnostic Settings are queried via the Azure Monitor Diagnostic Settings
          API. Some resource types return empty diagnostic settings even when
          platform metrics are emitted natively — these are not flagged as gaps.
        - Log Analytics workspace linking is determined by the presence of a
          workspaceId destination in the Diagnostic Settings sink. Azure Monitor
          Agent (AMA) and Data Collection Rules (DCRs) are not assessed in v1.0.
        - Alert rule coverage is assessed at the resource group level for metric
          alerts. Resource-level alert scoping requires iterating individual alert
          rules which may be slow in large environments.
        - Interactive Grid View requires a GUI-capable session. Skipped gracefully in
          headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/azure-monitor/overview
    https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings
    https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-overview
    https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/action-groups
    https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview

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
    Write-CenteredText "Azure Critical Resource Monitoring Gap Assessment v1.0" -Color White
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

Function Write-GapSummary {
    param([array]$Findings)

    if ($Findings.Count -eq 0) { return }

    $critical = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $high = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $medium = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $low = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $tier1 = @($Findings | Where-Object { $_.CriticalityTier -eq "Tier1-BusinessCritical" }).Count
    $tier2 = @($Findings | Where-Object { $_.CriticalityTier -eq "Tier2-Important" }).Count

    Write-Host ""
    Write-Host "  Monitoring Gap Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Total Gaps Found         : $($Findings.Count)" -ForegroundColor White
    Write-Host "  Critical                 : $critical"           -ForegroundColor Red
    Write-Host "  High                     : $high"               -ForegroundColor Yellow
    Write-Host "  Medium                   : $medium"             -ForegroundColor Cyan
    Write-Host "  Low                      : $low"                -ForegroundColor DarkGray
    Write-Host "  Tier 1 (Business Critical): $tier1"            -ForegroundColor Red
    Write-Host "  Tier 2 (Important)        : $tier2"            -ForegroundColor Yellow
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

Function Get-CriticalityTier {
    param(
        [string]$ResourceType,
        [string]$ResourceName,
        [string]$ResourceGroupName,
        [string]$SubscriptionName
    )

    # Tier 1 resource types — always business critical regardless of naming
    $tier1Types = @(
        "Microsoft.Sql/servers",
        "Microsoft.Sql/servers/databases",
        "Microsoft.DBforMySQL/servers",
        "Microsoft.DBforPostgreSQL/servers",
        "Microsoft.DBforMySQL/flexibleServers",
        "Microsoft.DBforPostgreSQL/flexibleServers",
        "Microsoft.DocumentDB/databaseAccounts",
        "Microsoft.KeyVault/vaults",
        "Microsoft.ApiManagement/service",
        "Microsoft.ServiceBus/namespaces",
        "Microsoft.EventHub/namespaces",
        "Microsoft.Network/applicationGateways",
        "Microsoft.Network/expressRouteCircuits",
        "Microsoft.Cache/Redis",
        "Microsoft.Synapse/workspaces",
        "Microsoft.MachineLearningServices/workspaces"
    )

    # Tier 2 resource types — important, context-dependent criticality
    $tier2Types = @(
        "Microsoft.Web/sites",
        "Microsoft.Web/serverFarms",
        "Microsoft.ContainerService/managedClusters",
        "Microsoft.App/containerApps",
        "Microsoft.Logic/workflows",
        "Microsoft.ServiceFabric/clusters",
        "Microsoft.Batch/batchAccounts",
        "Microsoft.EventGrid/topics",
        "Microsoft.EventGrid/domains",
        "Microsoft.Cdn/profiles",
        "Microsoft.Search/searchServices",
        "Microsoft.CognitiveServices/accounts"
    )

    # Production naming signals
    $prodPattern = "prod|prd|production|live|critical|core|shared|hub|platform|enterprise"

    $nameIsProd = ($ResourceName -match $prodPattern) -or
    ($ResourceGroupName -match $prodPattern) -or
    ($SubscriptionName -match $prodPattern)

    $typeNormalized = $ResourceType.ToLower()

    $isTier1Type = $tier1Types | Where-Object { $typeNormalized -like $_.ToLower() }
    $isTier2Type = $tier2Types | Where-Object { $typeNormalized -like $_.ToLower() }

    if ($isTier1Type) { return "Tier1-BusinessCritical" }
    if ($isTier2Type -and $nameIsProd) { return "Tier1-BusinessCritical" }
    if ($isTier2Type) { return "Tier2-Important" }
    if ($nameIsProd) { return "Tier2-Important" }

    return "Tier3-Standard"
}

Function Get-FindingSeverity {
    param(
        [string]$CriticalityTier,
        [string]$GapCategory
    )

    switch ($CriticalityTier) {
        "Tier1-BusinessCritical" {
            if ($GapCategory -eq "ObservabilityGap") { return "Critical" }
            if ($GapCategory -eq "DiagnosticGap") { return "High" }
            return "High"
        }
        "Tier2-Important" {
            if ($GapCategory -eq "ObservabilityGap") { return "High" }
            if ($GapCategory -eq "DiagnosticGap") { return "Medium" }
            return "Medium"
        }
        default { return "Low" }
    }
}

Function New-MonitoringFinding {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$ResourceName,
        [string]$ResourceType,
        [string]$ResourceGroup,
        [string]$CriticalityTier,
        [string]$GapCategory,
        [string]$Severity,
        [string]$FindingTitle,
        [string]$Detail,
        [string]$BusinessImpact,
        [string]$Recommendation,
        [string]$DiagnosticsStatus,
        [string]$LogAnalyticsStatus,
        [string]$MetricAlertStatus,
        [string]$ActionGroupStatus
    )

    return [pscustomobject]@{
        SubscriptionName   = $SubscriptionName
        SubscriptionId     = $SubscriptionId
        ResourceName       = $ResourceName
        ResourceType       = $ResourceType
        ResourceGroup      = $ResourceGroup
        CriticalityTier    = $CriticalityTier
        GapCategory        = $GapCategory
        Severity           = $Severity
        FindingTitle       = $FindingTitle
        Detail             = $Detail
        BusinessImpact     = $BusinessImpact
        Recommendation     = $Recommendation
        DiagnosticsStatus  = $DiagnosticsStatus
        LogAnalyticsStatus = $LogAnalyticsStatus
        MetricAlertStatus  = $MetricAlertStatus
        ActionGroupStatus  = $ActionGroupStatus
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-MonitoringGapHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [hashtable]$GapCategoryDist,
        [hashtable]$SeverityDist,
        [hashtable]$TierDist,
        [array]$SubscriptionResults,
        [string]$GeneratedOn
    )

    $totalFindings = @($Findings).Count
    $criticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $tier1Count = if ($TierDist.ContainsKey("Tier1-BusinessCritical")) { $TierDist["Tier1-BusinessCritical"] } else { 0 }
    $tier2Count = if ($TierDist.ContainsKey("Tier2-Important")) { $TierDist["Tier2-Important"] } else { 0 }

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
        $tierCls = switch ($f.CriticalityTier) {
            "Tier1-BusinessCritical" { "badge-red" }
            "Tier2-Important" { "badge-amber" }
            default { "" }
        }
        $tierLabel = switch ($f.CriticalityTier) {
            "Tier1-BusinessCritical" { "T1 Critical" }
            "Tier2-Important" { "T2 Important" }
            default { "T3 Standard" }
        }
        $title = if ($f.FindingTitle.Length -gt 48) { EscHtml($f.FindingTitle.Substring(0, 45) + "...") } else { EscHtml $f.FindingTitle }
        $resName = if ($f.ResourceName.Length -gt 28) { EscHtml($f.ResourceName.Substring(0, 25) + "...") } else { EscHtml $f.ResourceName }

        $diagBadge = if ($f.DiagnosticsStatus -eq "Configured") {
            '<span class="badge badge-green">✓</span>'
        }
        elseif ($f.DiagnosticsStatus -eq "Missing") {
            '<span class="badge badge-red">✗</span>'
        }
        else {
            '<span class="badge" style="background:var(--surface3);color:var(--muted)">—</span>'
        }
        $logBadge = if ($f.LogAnalyticsStatus -eq "Connected") {
            '<span class="badge badge-green">✓</span>'
        }
        elseif ($f.LogAnalyticsStatus -eq "Missing") {
            '<span class="badge badge-red">✗</span>'
        }
        else {
            '<span class="badge" style="background:var(--surface3);color:var(--muted)">—</span>'
        }
        $alertBadge = if ($f.MetricAlertStatus -eq "Configured") {
            '<span class="badge badge-green">✓</span>'
        }
        elseif ($f.MetricAlertStatus -eq "Missing") {
            '<span class="badge badge-amber">✗</span>'
        }
        else {
            '<span class="badge" style="background:var(--surface3);color:var(--muted)">—</span>'
        }

        $findingRows += @"
          <tr onclick="showFindingDetail($fIdx)">
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td><span class="badge $tierCls">$tierLabel</span></td>
            <td><span class="badge badge-blue">$(EscHtml $f.GapCategory)</span></td>
            <td title="$(EscHtml $f.FindingTitle)">$title</td>
            <td title="$(EscHtml $f.ResourceName)">$resName</td>
            <td>$diagBadge</td>
            <td>$logBadge</td>
            <td>$alertBadge</td>
          </tr>
"@
        $fIdx++
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

    # ── Gap category bar rows ─────────────────────────────────────────────────
    $gapTotal = ($GapCategoryDist.Values | Measure-Object -Sum).Sum
    $gapRows = ""
    $gapColors = @{
        "ObservabilityGap" = "var(--red)"
        "DiagnosticGap"    = "var(--amber)"
        "LogGap"           = "var(--amber)"
        "MetricGap"        = "var(--accent)"
        "AlertGap"         = "var(--accent2)"
        "ActionGroupGap"   = "var(--accent3)"
    }
    foreach ($g in ($GapCategoryDist.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($gapTotal -gt 0) { [math]::Round(($g.Value / $gapTotal) * 100) } else { 0 }
        $barColor = if ($gapColors.ContainsKey($g.Key)) { $gapColors[$g.Key] } else { "var(--accent)" }
        $gapRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $g.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($g.Value) ($pct%)</span>
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

    # ── Tier distribution bar rows ────────────────────────────────────────────
    $tierTotal = ($TierDist.Values | Measure-Object -Sum).Sum
    $tierRows = ""
    $tierLabels = [ordered]@{
        "Tier1-BusinessCritical" = "Tier 1 — Business Critical"
        "Tier2-Important"        = "Tier 2 — Important"
        "Tier3-Standard"         = "Tier 3 — Standard"
    }
    $tierColors = @{
        "Tier1-BusinessCritical" = "var(--red)"
        "Tier2-Important"        = "var(--amber)"
        "Tier3-Standard"         = "var(--muted)"
    }
    foreach ($tier in $tierLabels.Keys) {
        $cnt = if ($TierDist.ContainsKey($tier)) { $TierDist[$tier] } else { 0 }
        $pct = if ($tierTotal -gt 0) { [math]::Round(($cnt / $tierTotal) * 100) } else { 0 }
        $barColor = if ($tierColors.ContainsKey($tier)) { $tierColors[$tier] } else { "var(--accent)" }
        $tierRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $tierLabels[$tier])</span>
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
        """tier"":""$(EscJ $f.CriticalityTier)""," +
        """gap"":""$(EscJ $f.GapCategory)""," +
        """title"":""$(EscJ $f.FindingTitle)""," +
        """detail"":""$(EscJ $f.Detail)""," +
        """impact"":""$(EscJ $f.BusinessImpact)""," +
        """rec"":""$(EscJ $f.Recommendation)""," +
        """res"":""$(EscJ $f.ResourceName)""," +
        """resType"":""$(EscJ $f.ResourceType)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """diag"":""$(EscJ $f.DiagnosticsStatus)""," +
        """log"":""$(EscJ $f.LogAnalyticsStatus)""," +
        """alert"":""$(EscJ $f.MetricAlertStatus)""," +
        """ag"":""$(EscJ $f.ActionGroupStatus)""" +
        "},"
    }
    $findingsJson = $findingsJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Monitoring Gap Assessment</title>
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
.chart-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-bottom:18px;}
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
.coverage-icon{font-size:14px;display:inline-block;text-align:center;width:22px;}
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
  position:fixed;right:0;top:0;bottom:0;width:520px;max-width:95vw;
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
.coverage-row{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px;}
.coverage-row:last-child{border-bottom:none;}
.coverage-label{flex:1;color:var(--muted2);}
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
  .chart-grid-3{grid-template-columns:1fr;}
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
    <div class="logo-icon">📡</div>
    <div class="logo-title">Monitoring Gap</div>
    <div class="logo-sub">Azure Observability Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">⚠️</span> Findings</button>
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
      Monitoring Gap Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Monitoring Gap Overview</div>
      <div class="page-sub">Observability posture across __SUB_COUNT__ subscription(s) — connecting business criticality with monitoring coverage</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical Gaps</div>
        <div class="stat-sub">Tier 1 resources — blind spots</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Gaps</div>
        <div class="stat-sub">Important resources — limited visibility</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium Gaps</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low Gaps</div>
      </div>
      <div class="stat-card c-red" style="border-top-color:var(--red)">
        <div class="stat-num">__TIER1_COUNT__</div>
        <div class="stat-label">Tier 1 Affected</div>
        <div class="stat-sub">Business Critical resources</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__TIER2_COUNT__</div>
        <div class="stat-label">Tier 2 Affected</div>
        <div class="stat-sub">Important resources</div>
      </div>
    </div>

    <div class="chart-grid-3">
      <div class="panel">
        <div class="panel-title">📂 Gaps by Category</div>
        __GAP_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🎯 Gaps by Severity</div>
        __SEV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🏷️ Gaps by Criticality Tier</div>
        __TIER_ROWS__
      </div>
    </div>
  </div>

  <!-- Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Monitoring Gap Findings</div>
      <div class="page-sub">Click any row to view full details, coverage status, business impact, and recommended action</div>
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
        <select class="filter-select" id="filterTier" onchange="filterFindings()">
          <option value="">All Tiers</option>
          <option value="Tier1-BusinessCritical">Tier 1 — Business Critical</option>
          <option value="Tier2-Important">Tier 2 — Important</option>
          <option value="Tier3-Standard">Tier 3 — Standard</option>
        </select>
        <select class="filter-select" id="filterGap" onchange="filterFindings()">
          <option value="">All Gap Types</option>
          <option value="ObservabilityGap">ObservabilityGap</option>
          <option value="DiagnosticGap">DiagnosticGap</option>
          <option value="LogGap">LogGap</option>
          <option value="MetricGap">MetricGap</option>
          <option value="AlertGap">AlertGap</option>
          <option value="ActionGroupGap">ActionGroupGap</option>
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
              <th onclick="sortFindings(1)">Tier</th>
              <th onclick="sortFindings(2)">Gap Type</th>
              <th onclick="sortFindings(3)">Finding</th>
              <th onclick="sortFindings(4)">Resource</th>
              <th title="Diagnostic Settings">Diag</th>
              <th title="Log Analytics">Logs</th>
              <th title="Metric Alerts">Alerts</th>
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
  const ti=document.getElementById('filterTier').value;
  const gp=document.getElementById('filterGap').value;
  findingFiltered=FINDING_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mS=!sv||r.sev===sv;
    const mT=!ti||r.tier===ti;
    const mG=!gp||r.gap===gp;
    return mQ&&mS&&mT&&mG;
  });
  findingPage=1; renderFindings();
}

function changeFindingPageSize(){
  findingPageSz=parseInt(document.getElementById('pgSizeFinding').value);
  findingPage=1; renderFindings();
}

function sortFindings(col){
  if(findingSortCol===col){findingSortAsc=!findingSortAsc;}else{findingSortCol=col;findingSortAsc=true;}
  const keys=['sev','tier','gap','title','res'];
  findingFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    const sevOrd={Critical:0,High:1,Medium:2,Low:3};
    if(k==='sev') return findingSortAsc?(sevOrd[av]??9)-(sevOrd[bv]??9):(sevOrd[bv]??9)-(sevOrd[av]??9);
    const tierOrd={'Tier1-BusinessCritical':0,'Tier2-Important':1,'Tier3-Standard':2};
    if(k==='tier') return findingSortAsc?(tierOrd[av]??9)-(tierOrd[bv]??9):(tierOrd[bv]??9)-(tierOrd[av]??9);
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
    const tCls=r.tier==='Tier1-BusinessCritical'?'badge-red':r.tier==='Tier2-Important'?'badge-amber':'';
    const tLbl=r.tier==='Tier1-BusinessCritical'?'T1 Critical':r.tier==='Tier2-Important'?'T2 Important':'T3 Standard';
    const nm=r.title.length>48?r.title.substring(0,45)+'...':r.title;
    const rn=r.res.length>28?r.res.substring(0,25)+'...':r.res;
    const dIcon=r.diag==='Configured'?'<span class="badge badge-green">✓</span>':r.diag==='Missing'?'<span class="badge badge-red">✗</span>':'<span class="badge" style="background:var(--surface3);color:var(--muted)">—</span>';
    const lIcon=r.log==='Connected'?'<span class="badge badge-green">✓</span>':r.log==='Missing'?'<span class="badge badge-red">✗</span>':'<span class="badge" style="background:var(--surface3);color:var(--muted)">—</span>';
    const aIcon=r.alert==='Configured'?'<span class="badge badge-green">✓</span>':r.alert==='Missing'?'<span class="badge badge-amber">✗</span>':'<span class="badge" style="background:var(--surface3);color:var(--muted)">—</span>';
    return `<tr onclick="showFindingDetail(${gi})">
      <td><span class="badge ${sCls}">${escH(r.sev)}</span></td>
      <td><span class="badge ${tCls}">${tLbl}</span></td>
      <td><span class="badge badge-blue">${escH(r.gap)}</span></td>
      <td title="${escH(r.title)}">${escH(nm)}</td>
      <td title="${escH(r.res)}">${escH(rn)}</td>
      <td>${dIcon}</td>
      <td>${lIcon}</td>
      <td>${aIcon}</td>
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

function statusIcon(v,yes,no){
  if(v===yes) return '<span class="badge badge-green">✓ '+escH(v)+'</span>';
  if(v===no||v==='Missing') return '<span class="badge badge-red">✗ '+escH(v)+'</span>';
  return '<span class="badge badge-amber">'+escH(v||'Unknown')+'</span>';
}

function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=FINDING_DATA[idx];
  if(!r)return;
  const sCls=r.sev==='Critical'?'badge-red':r.sev==='High'?'badge-amber':r.sev==='Medium'?'badge-blue':'';
  const tCls=r.tier==='Tier1-BusinessCritical'?'badge-red':r.tier==='Tier2-Important'?'badge-amber':'';
  const tLbl=r.tier==='Tier1-BusinessCritical'?'Tier 1 — Business Critical':r.tier==='Tier2-Important'?'Tier 2 — Important':'Tier 3 — Standard';
  document.getElementById('drawerTitle').textContent=r.title;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FINDING_DATA.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field">
      <div class="drawer-field-label">Severity &amp; Criticality</div>
      <div class="drawer-field-value"><span class="badge ${sCls}">${escH(r.sev)}</span>&nbsp;<span class="badge ${tCls}">${tLbl}</span>&nbsp;<span class="badge badge-blue">${escH(r.gap)}</span></div>
    </div>
    <div class="drawer-field"><div class="drawer-field-label">Resource</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.res)}<br/><span style="color:var(--muted)">${escH(r.resType)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-section">Monitoring Coverage</div>
    <div class="coverage-row"><span class="coverage-label">Diagnostic Settings</span>${statusIcon(r.diag,'Configured','Missing')}</div>
    <div class="coverage-row"><span class="coverage-label">Log Analytics Destination</span>${statusIcon(r.log,'Connected','Missing')}</div>
    <div class="coverage-row"><span class="coverage-label">Metric Alert Rules</span>${statusIcon(r.alert,'Configured','Missing')}</div>
    <div class="coverage-row"><span class="coverage-label">Action Group</span>${statusIcon(r.ag,'Connected','Missing')}</div>
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
        -replace '__TIER1_COUNT__', $tier1Count `
        -replace '__TIER2_COUNT__', $tier2Count `
        -replace '__GAP_ROWS__', $gapRows `
        -replace '__SEV_ROWS__', $sevRows `
        -replace '__TIER_ROWS__', $tierRows `
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


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureCriticalResourceMonitoringGap {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureMonitoringGap-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Monitor", "Az.Resources")

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
    $subscriptionResults = @()
    $gapCategoryDist = @{}
    $severityDist = @{ "Critical" = 0; "High" = 0; "Medium" = 0; "Low" = 0 }
    $tierDist = @{}
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

            # ── Retrieve subscription-wide monitor artifacts ───────────────────
            $actionGroups = @()
            $metricAlerts = @()
            $activityAlerts = @()

            try { $actionGroups = @(Get-AzActionGroup -ErrorAction Stop) }          catch { Write-Verbose "Action Group retrieval failed for $($sub.Name): $_" }
            try { $metricAlerts = @(Get-AzMetricAlertRuleV2 -ErrorAction Stop) }    catch {
                try { $metricAlerts = @(Get-AzMetricAlertRule -ErrorAction Stop) }       catch { Write-Verbose "Metric alert retrieval failed for $($sub.Name): $_" }
            }
            try { $activityAlerts = @(Get-AzActivityLogAlert -ErrorAction Stop) }     catch { Write-Verbose "Activity alert retrieval failed for $($sub.Name): $_" }

            # Build set of resource groups that have at least one metric alert
            $alertedRgSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($ma in $metricAlerts) {
                try {
                    $scopeStr = if ($ma.Scopes) { $ma.Scopes[0] } elseif ($ma.TargetResourceId) { $ma.TargetResourceId } else { "" }
                    if ($scopeStr -match "/resourceGroups/([^/]+)") {
                        [void]$alertedRgSet.Add($Matches[1])
                    }
                }
                catch { }
            }

            # Check whether action groups have at least one receiver
            $actionGroupHasReceiver = @{}
            foreach ($ag in $actionGroups) {
                $hasReceiver = $false
                try {
                    $hasReceiver = (
                        ($ag.EmailReceiver -and $ag.EmailReceiver.Count -gt 0) -or
                        ($ag.SmsReceiver -and $ag.SmsReceiver.Count -gt 0) -or
                        ($ag.WebhookReceiver -and $ag.WebhookReceiver.Count -gt 0) -or
                        ($ag.ArmRoleReceiver -and $ag.ArmRoleReceiver.Count -gt 0) -or
                        ($ag.AzureAppPushReceiver -and $ag.AzureAppPushReceiver.Count -gt 0)
                    )
                }
                catch { }
                $actionGroupHasReceiver[$ag.Id] = $hasReceiver
            }

            # Subscription-level: No action groups at all
            if ($actionGroups.Count -eq 0) {
                $tier = "Tier2-Important"
                $gap = "ActionGroupGap"
                $severity = Get-FindingSeverity -CriticalityTier $tier -GapCategory $gap

                $f = New-MonitoringFinding `
                    -SubscriptionName   $sub.Name `
                    -SubscriptionId     $sub.Id `
                    -ResourceName       $sub.Name `
                    -ResourceType       "Subscription" `
                    -ResourceGroup      "" `
                    -CriticalityTier    $tier `
                    -GapCategory        $gap `
                    -Severity           $severity `
                    -FindingTitle       "No Action Groups defined — alerts cannot notify anyone" `
                    -Detail             "Subscription '$($sub.Name)' has no Azure Monitor Action Groups configured. Without Action Groups, any alert rules that are or will be configured have no notification channel — they fire silently without reaching operations teams." `
                    -BusinessImpact     "Alert rules are only useful if they trigger notifications that reach people. Without Action Groups, incidents detected by Azure Monitor will not result in automated notifications to on-call engineers, ticketing systems, or ITSM integrations. Mean Time to Awareness (MTTA) effectively becomes unbounded." `
                    -Recommendation     "Create at least one Action Group per operational team. Include email/SMS for on-call engineers and webhook receivers for ITSM integration (ServiceNow, PagerDuty). Consider Azure Automation Runbooks as receivers for self-healing actions." `
                    -DiagnosticsStatus  "N/A" `
                    -LogAnalyticsStatus "N/A" `
                    -MetricAlertStatus  "N/A" `
                    -ActionGroupStatus  "Missing"

                $allFindings += $f
            }
            elseif ($actionGroups | Where-Object { -not $actionGroupHasReceiver[$_.Id] }) {
                # Action groups exist but some have no receivers
                $emptyAgs = @($actionGroups | Where-Object { -not $actionGroupHasReceiver[$_.Id] })
                $tier = "Tier2-Important"
                $gap = "ActionGroupGap"
                $severity = Get-FindingSeverity -CriticalityTier $tier -GapCategory $gap

                $f = New-MonitoringFinding `
                    -SubscriptionName   $sub.Name `
                    -SubscriptionId     $sub.Id `
                    -ResourceName       $sub.Name `
                    -ResourceType       "Subscription" `
                    -ResourceGroup      "" `
                    -CriticalityTier    $tier `
                    -GapCategory        $gap `
                    -Severity           $severity `
                    -FindingTitle       "$($emptyAgs.Count) Action Group(s) have no receivers configured" `
                    -Detail             "The following Action Groups in '$($sub.Name)' have no email, SMS, webhook, or other receivers: $($emptyAgs.Name -join ', '). Alert rules referencing these groups will fire but deliver notifications to no one." `
                    -BusinessImpact     "If alert rules reference empty Action Groups, incidents will be silently swallowed. Operations teams will have no awareness of triggered alerts until they manually review the Azure Monitor portal — by which time the impact window has already extended." `
                    -Recommendation     "Add at least one receiver (email, SMS, webhook, or Azure App push) to every Action Group referenced by alert rules. Validate end-to-end by sending a test notification from each Action Group." `
                    -DiagnosticsStatus  "N/A" `
                    -LogAnalyticsStatus "N/A" `
                    -MetricAlertStatus  "N/A" `
                    -ActionGroupStatus  "EmptyReceivers"

                $allFindings += $f
            }

            # ── Per-resource assessment ───────────────────────────────────────
            # Get resources of interest (Tier 1 and Tier 2 types)
            $assessableTypes = @(
                "Microsoft.Sql/servers/databases",
                "Microsoft.DocumentDB/databaseAccounts",
                "Microsoft.KeyVault/vaults",
                "Microsoft.ApiManagement/service",
                "Microsoft.ServiceBus/namespaces",
                "Microsoft.EventHub/namespaces",
                "Microsoft.Network/applicationGateways",
                "Microsoft.Cache/Redis",
                "Microsoft.Web/sites",
                "Microsoft.ContainerService/managedClusters",
                "Microsoft.App/containerApps",
                "Microsoft.Logic/workflows",
                "Microsoft.Storage/storageAccounts",
                "Microsoft.DBforMySQL/flexibleServers",
                "Microsoft.DBforPostgreSQL/flexibleServers",
                "Microsoft.Sql/servers"
            )

            $resources = @()
            try {
                $resources = @(Get-AzResource -ErrorAction Stop |
                    Where-Object { $_.ResourceType -in $assessableTypes })
            }
            catch {
                Write-Verbose "Resource retrieval failed for $($sub.Name): $_"
            }

            $subFindingCount = 0

            foreach ($res in $resources) {
                $resName = $res.Name
                $resType = $res.ResourceType
                $resRg = $res.ResourceGroupName
                $resId = $res.ResourceId

                # Determine criticality tier
                $tier = Get-CriticalityTier `
                    -ResourceType       $resType `
                    -ResourceName       $resName `
                    -ResourceGroupName  $resRg `
                    -SubscriptionName   $sub.Name

                # Skip Tier 3 unless they have production naming and would be interesting
                # (reduces noise for standard storage accounts, etc.)
                if ($tier -eq "Tier3-Standard") { continue }

                # ── Check Diagnostic Settings ─────────────────────────────────
                $diagSettings = @()
                $diagStatus = "Missing"
                $logAnalyticsStatus = "Missing"

                try {
                    $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $resId -ErrorAction Stop)
                    if ($diagSettings.Count -gt 0) {
                        $diagStatus = "Configured"

                        # Check for Log Analytics workspace destination
                        $hasLogAnalytics = $diagSettings | Where-Object {
                            $ds = $_
                            $hasWs = $false
                            try {
                                $hasWs = ($null -ne $ds.WorkspaceId -and $ds.WorkspaceId -ne "")
                            }
                            catch { }
                            $hasWs
                        }
                        $logAnalyticsStatus = if ($hasLogAnalytics) { "Connected" } else { "Missing" }
                    }
                }
                catch {
                    # Some resource types don't support diagnostic settings — skip those silently
                    $diagStatus = "N/A"
                    $logAnalyticsStatus = "N/A"
                }

                # ── Check metric alert coverage ────────────────────────────────
                $metricAlertStatus = "Missing"
                $hasAlertForRes = $false

                # Check if there's any alert scoped to this resource's RG or the resource directly
                if ($alertedRgSet.Contains($resRg)) { $hasAlertForRes = $true }
                else {
                    foreach ($ma in $metricAlerts) {
                        try {
                            $scopeStr = if ($ma.Scopes) { $ma.Scopes[0] } elseif ($ma.TargetResourceId) { $ma.TargetResourceId } else { "" }
                            if ($scopeStr -like "*$resId*" -or $scopeStr -like "*$resName*") { $hasAlertForRes = $true; break }
                        }
                        catch { }
                    }
                }

                $metricAlertStatus = if ($hasAlertForRes) { "Configured" } else { "Missing" }

                # ── Determine gap severity and classification ──────────────────
                $missingDiag = ($diagStatus -eq "Missing")
                $missingLog = ($logAnalyticsStatus -eq "Missing")
                $missingAlert = ($metricAlertStatus -eq "Missing")

                $gapCount = ($missingDiag -as [int]) + ($missingLog -as [int]) + ($missingAlert -as [int])

                # Only create findings where there is a meaningful gap
                if ($gapCount -eq 0) { continue }

                # Classify gap category
                $gapCategory = if ($gapCount -ge 2 -and $missingDiag) { "ObservabilityGap" }
                elseif ($missingDiag) { "DiagnosticGap" }
                elseif ($missingLog) { "LogGap" }
                elseif ($missingAlert) { "MetricGap" }
                else { "AlertGap" }

                $severity = Get-FindingSeverity -CriticalityTier $tier -GapCategory $gapCategory

                # Compose gap-specific description
                $gapParts = @()
                if ($missingDiag) { $gapParts += "Diagnostic Settings not configured" }
                if ($missingLog) { $gapParts += "Log Analytics workspace not connected" }
                if ($missingAlert) { $gapParts += "No metric alert rules found" }

                $gapDetail = "$resType '$resName' in resource group '$resRg' has the following monitoring gaps: $($gapParts -join '; ')."

                $tierLabel = switch ($tier) {
                    "Tier1-BusinessCritical" { "Tier 1 (Business Critical)" }
                    "Tier2-Important" { "Tier 2 (Important)" }
                    default { "Tier 3 (Standard)" }
                }

                $businessImpact = switch ($gapCategory) {
                    "ObservabilityGap" {
                        "This $tierLabel resource has multiple monitoring dimensions missing simultaneously. Failures, degradation, security events, and performance anomalies affecting this resource will not be logged, centralized, or trigger alerts. The organization will have no awareness of problems until they manifest as user-reported incidents — by which time impact has already materialized."
                    }
                    "DiagnosticGap" {
                        "Without Diagnostic Settings, platform-level events, audit logs, and availability signals from this $tierLabel resource are not captured. Security incidents (unauthorized access, configuration changes) and availability events will leave no trace, making incident investigation impossible and compliance evidence unavailable."
                    }
                    "LogGap" {
                        "Diagnostic Settings are configured but logs are not directed to a Log Analytics workspace. Without centralized log collection, security operations teams cannot query, correlate, or alert on log data from this resource. Anomaly detection and threat hunting are not possible without a workspace destination."
                    }
                    "MetricGap" {
                        "No metric alert rules are configured for this $tierLabel resource or its resource group. Capacity exhaustion, error rate spikes, latency increases, and availability drops will not trigger automated notifications. Operations teams will only discover issues reactively, after business impact has occurred."
                    }
                    default {
                        "Monitoring gaps exist for this $tierLabel resource that may reduce the organization's ability to detect and respond to operational or security events in time to prevent business impact."
                    }
                }

                $recommendation = switch ($gapCategory) {
                    "ObservabilityGap" {
                        "Implement a complete monitoring baseline for this resource: (1) Configure Diagnostic Settings to send all relevant logs and metrics to a central Log Analytics workspace. (2) Create metric alert rules for key signals: availability, error rate, latency, and capacity. (3) Configure an Action Group to route alerts to the appropriate operations team. (4) Verify end-to-end by triggering a test condition and confirming alert delivery."
                    }
                    "DiagnosticGap" {
                        "Enable Diagnostic Settings on this resource. Configure at minimum: all available log categories, and metrics export to a Log Analytics workspace. Use Azure Policy (built-in or custom) to enforce diagnostic settings at scale and prevent future gaps from emerging. Consider deploying DeployIfNotExists policies for all critical resource types."
                    }
                    "LogGap" {
                        "Update the existing Diagnostic Settings to add a Log Analytics workspace as a destination. Ensure the workspace is in the same or a connected Azure subscription. If a central Log Analytics workspace exists, prefer sending all logs to it for cross-resource query correlation and SIEM integration."
                    }
                    "MetricGap" {
                        "Create metric alert rules covering the key availability and performance signals for this resource type. Use Azure Monitor recommended alerts as a baseline (available in the Azure portal for most resource types). Scope alerts to the resource directly where possible, or to the resource group. Assign an Action Group so alerts reach on-call teams. Enable alert processing rules to suppress noise during maintenance windows."
                    }
                    default {
                        "Review all monitoring dimensions for this resource: Diagnostic Settings, Log Analytics destination, metric alert coverage, and Action Group connectivity. Implement missing components to establish a complete monitoring baseline appropriate for the resource's business criticality."
                    }
                }

                $f = New-MonitoringFinding `
                    -SubscriptionName   $sub.Name `
                    -SubscriptionId     $sub.Id `
                    -ResourceName       $resName `
                    -ResourceType       $resType `
                    -ResourceGroup      $resRg `
                    -CriticalityTier    $tier `
                    -GapCategory        $gapCategory `
                    -Severity           $severity `
                    -FindingTitle       "$gapCategory — $resName ($tierLabel)" `
                    -Detail             $gapDetail `
                    -BusinessImpact     $businessImpact `
                    -Recommendation     $recommendation `
                    -DiagnosticsStatus  $diagStatus `
                    -LogAnalyticsStatus $logAnalyticsStatus `
                    -MetricAlertStatus  $metricAlertStatus `
                    -ActionGroupStatus  $(if ($actionGroups.Count -gt 0) { "Present" } else { "Missing" })

                $allFindings += $f
                $subFindingCount++
            }

            # ── Update distributions ───────────────────────────────────────────
            foreach ($f in ($allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id })) {
                if ($gapCategoryDist.ContainsKey($f.GapCategory)) { $gapCategoryDist[$f.GapCategory]++ }
                else { $gapCategoryDist[$f.GapCategory] = 1 }

                if ($severityDist.ContainsKey($f.Severity)) { $severityDist[$f.Severity]++ }

                if ($tierDist.ContainsKey($f.CriticalityTier)) { $tierDist[$f.CriticalityTier]++ }
                else { $tierDist[$f.CriticalityTier] = 1 }
            }

            # ── Per-subscription result ────────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Resources assessed: $($resources.Count)  Action Groups: $($actionGroups.Count)  Metric Alerts: $($metricAlerts.Count)  Findings: $subFindingCount" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Resources: $($resources.Count)  ActionGroups: $($actionGroups.Count)  MetricAlerts: $($metricAlerts.Count)  Findings: $subFindingCount"
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
            "Total Subscriptions Scanned"     = $subCount
            "Successful"                      = $successCount
            "Errors"                          = $errorCount
            "Total Monitoring Gaps Found"     = $allFindings.Count
            "Critical"                        = $severityDist["Critical"]
            "High"                            = $severityDist["High"]
            "Medium"                          = $severityDist["Medium"]
            "Low"                             = $severityDist["Low"]
            "Tier 1 (Business Critical) Gaps" = if ($tierDist.ContainsKey("Tier1-BusinessCritical")) { $tierDist["Tier1-BusinessCritical"] } else { 0 }
            "Tier 2 (Important) Gaps"         = if ($tierDist.ContainsKey("Tier2-Important")) { $tierDist["Tier2-Important"] } else { 0 }
            "Execution Time"                  = $duration
        })

    Write-GapSummary -Findings $allFindings

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        # CSV
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, ResourceName, ResourceType, ResourceGroup,
                CriticalityTier, GapCategory, Severity, FindingTitle,
                DiagnosticsStatus, LogAnalyticsStatus, MetricAlertStatus, ActionGroupStatus,
                Detail, BusinessImpact, Recommendation |
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

            $htmlContent = Generate-MonitoringGapHtml `
                -SessionInfo          $sessionInfo `
                -ScanParameters       $scanParams `
                -Findings             $allFindings `
                -GapCategoryDist      $gapCategoryDist `
                -SeverityDist         $severityDist `
                -TierDist             $tierDist `
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
            Select-Object Severity, CriticalityTier, GapCategory, FindingTitle, ResourceName, SubscriptionName,
            DiagnosticsStatus, LogAnalyticsStatus, MetricAlertStatus |
            Out-GridView -Title "Azure Critical Resource Monitoring Gap Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ✓ No significant monitoring gaps identified in the targeted subscriptions." -ForegroundColor Green
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
