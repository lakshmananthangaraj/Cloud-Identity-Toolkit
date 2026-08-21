<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 21 August 2026
Modified-On     : 21 August 2026

.SYNOPSIS
    Assesses Azure Monitor architecture — Log Analytics workspaces, diagnostic settings,
    alert rules, action groups, and overall observability posture — across one or more
    subscriptions, with risk-rated architectural findings, CSV export, and an interactive
    HTML dashboard.

.DESCRIPTION
    Get-AzureMonitoringArchitectureAssessment evaluates the monitoring and observability
    architecture of an Azure environment from a Cloud Architect and Enterprise Architecture
    perspective.

    It does not simply enumerate monitoring resources. Every significant finding is rated
    by risk level (Critical / High / Medium / Low / Informational), categorised by
    architectural domain (Security / Compliance / Reliability / Operational Visibility /
    Architecture / Resilience), and accompanied by a business-impact statement and a
    concrete recommendation — making the output immediately actionable for platform
    engineering teams, architects, and compliance auditors.

    Assessment areas per subscription:

        Log Analytics Workspaces
            Workspace count and distribution (single-workspace vs fragmented),
            data retention configuration vs enterprise baseline (90-day minimum),
            commitment tier vs pay-as-you-go pricing (cost and commitment risk),
            region alignment with compute resources, linked Automation Accounts.

        Diagnostic Settings
            Coverage assessment across high-value resource types:
            Key Vault, Storage Account, NSG, App Service, Azure Functions,
            Azure SQL, Virtual Machines, AKS, Application Gateway,
            Azure Firewall, API Management.
            For each resource: whether diagnostic settings exist, whether a Log
            Analytics workspace is the destination, and whether audit/security
            log categories are enabled.

        Alert Rules
            Metric alerts, log (scheduled query) alerts, and Activity Log alerts.
            Assessment covers: alert existence per resource type, alert state
            (enabled/disabled), severity configuration, missing critical alert
            coverage, and orphaned alert rules pointing to deleted resources.

        Action Groups
            Receiver presence (email, SMS, webhook, ITSM, Azure Function, Logic App),
            action groups with no receivers configured, action groups not linked to
            any alert rule (orphaned), receiver count per group.

    For each finding a structured record is generated:
        ResourceName, ResourceType, SubscriptionName, SubscriptionId,
        Area, Setting, CurrentValue, ExpectedValue, IsCompliant,
        RiskLevel, RiskCategory, Finding, BusinessImpact,
        ArchitecturalImpact, Recommendation

    Workspace records include:
        WorkspaceName, ResourceGroup, Region, RetentionDays, PricingTier,
        DailyQuotaGB, LinkedAutomationAccount, ResourceCount

    Alert records include:
        AlertName, AlertType, Severity, IsEnabled, TargetResource, ActionGroups

    Output:
        - Always-on interactive HTML dashboard (7 tabs, dark/light theme,
          sortable filterable tables, risk cards with detail drawer, bar charts)
        - Optional CSV export (-ExportToCsv)
        - Interactive Grid View where a GUI is available (-ResourceTypes to scope
          diagnostic settings assessment in large environments)

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. Exports all findings to the path specified by -CsvPath. Separate
    CSVs are written for workspace and alert records. The HTML dashboard is
    always generated regardless of this switch.

.PARAMETER CsvPath
    Full path for the primary CSV export.
    Default: C:\Temp\AzureMonitoringArchitecture-Report.csv
    The HTML dashboard is written to the same path with a .html extension.
    Workspace and alert detail CSVs are written alongside with suffixed names.

.PARAMETER ResourceTypes
    Optional string array to restrict the diagnostic settings assessment to
    specific resource types. Useful in large environments with thousands of
    resources where a full scan would be time-consuming.
    Accepted values: KeyVault, Storage, NSG, AppService, Functions, SQL,
                     VirtualMachine, AKS, AppGateway, Firewall, APIM
    Default: All supported resource types are assessed.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath. Optionally writes CSV files when -ExportToCsv is specified.
    Displays non-compliant findings in an interactive Grid View where a GUI
    is available.

.EXAMPLE
    Get-AzureMonitoringArchitectureAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureMonitoringArchitectureAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureMonitoringArchitectureAssessment -AllSubscriptions -ExportToCsv

.EXAMPLE
    Get-AzureMonitoringArchitectureAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\Monitoring.csv"

.EXAMPLE
    Get-AzureMonitoringArchitectureAssessment -AllSubscriptions -ResourceTypes @("KeyVault","SQL","AppGateway")

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (21-Aug-2026) - Initial release. Log Analytics workspace architecture,
                            diagnostic settings coverage (11 resource types),
                            metric/log/activity alert assessment, action group
                            health, and risk-rated architectural findings with
                            interactive HTML dashboard and CSV export.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module — the following sub-modules are used:
               Az.Accounts, Az.OperationalInsights, Az.Monitor,
               Az.Resources, Az.Automation
           Install via: Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level for all targeted
           subscriptions. No write permissions are required — this is a
           read-only assessment.
        4. Microsoft.Insights resource provider must be registered in each
           subscription for diagnostic settings and alert rules to be enumerable.
           Subscriptions with an unregistered provider will generate partial results.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Diagnostic settings are retrieved via the Az.Monitor REST API wrapper.
          Very large subscriptions (1000+ resources per type) may experience
          throttling; use -ResourceTypes to scope the assessment.
        - Microsoft Sentinel and Defender for Cloud integration are out of scope
          for this version.
        - AKS and Container Apps workload-level monitoring (Prometheus, container
          insights agent) is not assessed — only the AKS resource diagnostic
          settings at the control-plane level are evaluated.
        - Log alert rules using custom KQL queries are assessed for configuration
          health (enabled/disabled, severity, action group linkage) but the KQL
          logic itself is not evaluated.
        - Activity Log alerts based on Resource Health are not yet differentiated
          from standard Activity Log alerts.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an
          explicit -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/azure-monitor/overview
    https://learn.microsoft.com/en-us/azure/azure-monitor/logs/workspace-design
    https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings
    https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-overview
    https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/action-groups
    https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-logging-threat-detection

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
    Write-CenteredText "Azure Monitoring Architecture Assessment v1.0" -Color White
    Write-CenteredText "Observability, Alerting & Log Analytics Architecture" -Color Gray
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
        else { $valColor = "White" }
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

Function Write-RiskBreakdown {
    param([array]$Findings)
    if ($Findings.Count -eq 0) { return }
    $critical = @($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $high = @($Findings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $medium = @($Findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $low = @($Findings | Where-Object { $_.RiskLevel -eq "Low" }).Count
    $info = @($Findings | Where-Object { $_.RiskLevel -eq "Informational" }).Count
    Write-Host ""
    Write-Host "  Risk Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Critical              : $critical" -ForegroundColor Red
    Write-Host "  High                  : $high"     -ForegroundColor Red
    Write-Host "  Medium                : $medium"   -ForegroundColor Yellow
    Write-Host "  Low                   : $low"      -ForegroundColor Gray
    Write-Host "  Informational         : $info"     -ForegroundColor DarkGray
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


#------------------------------------------------------------------------ [ Risk / Finding Engine ]

Function New-MonitoringFinding {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$ResourceName,
        [string]$ResourceGroup,
        [string]$ResourceType,
        [string]$Area,
        [string]$Setting,
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [bool]$IsCompliant,
        [string]$RiskLevel,
        [string]$RiskCategory,
        [string]$Finding,
        [string]$BusinessImpact,
        [string]$ArchitecturalImpact,
        [string]$Recommendation
    )
    return [pscustomobject]@{
        SubscriptionName    = $SubscriptionName
        SubscriptionId      = $SubscriptionId
        ResourceName        = $ResourceName
        ResourceGroup       = $ResourceGroup
        ResourceType        = $ResourceType
        Area                = $Area
        Setting             = $Setting
        CurrentValue        = $CurrentValue
        ExpectedValue       = $ExpectedValue
        IsCompliant         = if ($IsCompliant) { "Yes" } else { "No" }
        RiskLevel           = $RiskLevel
        RiskCategory        = $RiskCategory
        Finding             = $Finding
        BusinessImpact      = $BusinessImpact
        ArchitecturalImpact = $ArchitecturalImpact
        Recommendation      = $Recommendation
    }
}


#------------------------------------------------------------------------ [ HTML Escape Helpers ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function Generate-MonitoringAssessmentHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$Workspaces,
        [array]$AlertRecords,
        [array]$SubscriptionResults,
        [string]$GeneratedOn
    )

    # ── Aggregate counts ──────────────────────────────────────────────────────
    $totalFindings = @($Findings).Count
    $criticalCount = @($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $nonCompliant = @($Findings | Where-Object { $_.IsCompliant -eq "No" }).Count
    $compliant = @($Findings | Where-Object { $_.IsCompliant -eq "Yes" }).Count
    $totalWorkspaces = @($Workspaces).Count
    $totalAlerts = @($AlertRecords).Count
    $disabledAlerts = @($AlertRecords | Where-Object { $_.IsEnabled -eq "No" }).Count
    $diagFindings = @($Findings | Where-Object { $_.Area -eq "Diagnostic Settings" -and $_.IsCompliant -eq "No" }).Count
    $agFindings = @($Findings | Where-Object { $_.Area -eq "Action Groups" -and $_.IsCompliant -eq "No" }).Count

    # ── Area distribution bar rows ────────────────────────────────────────────
    $areaDist = @{}
    foreach ($f in $Findings) {
        $a = $f.Area
        if ($areaDist.ContainsKey($a)) { $areaDist[$a]++ } else { $areaDist[$a] = 1 }
    }
    $areaTotal = ($areaDist.Values | Measure-Object -Sum).Sum
    $areaBarRows = ""
    foreach ($item in ($areaDist.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($areaTotal -gt 0) { [math]::Round(($item.Value / $areaTotal) * 100) } else { 0 }
        $areaBarRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $item.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($item.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Risk level bar rows ───────────────────────────────────────────────────
    $rlDist = [ordered]@{ "Critical" = $criticalCount; "High" = $highCount; "Medium" = $mediumCount; "Low" = @($Findings | Where-Object { $_.RiskLevel -eq "Low" }).Count; "Informational" = @($Findings | Where-Object { $_.RiskLevel -eq "Informational" }).Count }
    $rlTotal = ($rlDist.Values | Measure-Object -Sum).Sum
    $rlBarRows = ""
    $rlColors = @{ "Critical" = "var(--red)"; "High" = "var(--red)"; "Medium" = "var(--amber)"; "Low" = "var(--green)"; "Informational" = "var(--muted)" }
    foreach ($rl in $rlDist.GetEnumerator()) {
        if ($rl.Value -eq 0) { continue }
        $pct = if ($rlTotal -gt 0) { [math]::Round(($rl.Value / $rlTotal) * 100) } else { 0 }
        $barColor = if ($rlColors.ContainsKey($rl.Key)) { $rlColors[$rl.Key] } else { "var(--accent)" }
        $rlBarRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $rl.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($rl.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Findings table rows (Service Details tab) ─────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $riskCls = switch ($f.RiskLevel) { "Critical" { "badge-red" }; "High" { "badge-red" }; "Medium" { "badge-amber" }; "Low" { "badge-green" }; default { "badge-blue" } }
        $compCls = if ($f.IsCompliant -eq "Yes") { "badge-green" } else { "badge-red" }
        $rn = if ($f.ResourceName.Length -gt 28) { $f.ResourceName.Substring(0, 25) + "..." } else { $f.ResourceName }
        $findingRows += @"
          <tr>
            <td title="$(EscHtml $f.ResourceName)">$(EscHtml $rn)</td>
            <td><span class="scope-badge">$(EscHtml $f.ResourceType)</span></td>
            <td><span class="area-badge">$(EscHtml $f.Area)</span></td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$(EscHtml $f.Setting)</td>
            <td><span class="badge $riskCls">$(EscHtml $f.RiskLevel)</span></td>
            <td><span class="badge $compCls">$(EscHtml $f.IsCompliant)</span></td>
          </tr>
"@
    }

    # ── Findings JSON for detail drawer ───────────────────────────────────────
    $findingsJson = "["
    foreach ($f in $Findings) {
        $findingsJson += "{" +
        """res"":""$(EscJ $f.ResourceName)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """rtype"":""$(EscJ $f.ResourceType)""," +
        """area"":""$(EscJ $f.Area)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """setting"":""$(EscJ $f.Setting)""," +
        """current"":""$(EscJ $f.CurrentValue)""," +
        """expected"":""$(EscJ $f.ExpectedValue)""," +
        """compliant"":""$(EscJ $f.IsCompliant)""," +
        """risk"":""$(EscJ $f.RiskLevel)""," +
        """cat"":""$(EscJ $f.RiskCategory)""," +
        """finding"":""$(EscJ $f.Finding)""," +
        """impact"":""$(EscJ $f.BusinessImpact)""," +
        """arch"":""$(EscJ $f.ArchitecturalImpact)""," +
        """rec"":""$(EscJ $f.Recommendation)""" +
        "},"
    }
    $findingsJson = $findingsJson.TrimEnd(",") + "]"

    # ── Diagnostic Settings tab rows ──────────────────────────────────────────
    $diagFinds = @($Findings | Where-Object { $_.Area -eq "Diagnostic Settings" })
    $diagRows = ""
    foreach ($f in $diagFinds) {
        $compCls = if ($f.IsCompliant -eq "Yes") { "badge-green" } else { "badge-red" }
        $riskCls = switch ($f.RiskLevel) { "Critical" { "badge-red" }; "High" { "badge-red" }; "Medium" { "badge-amber" }; "Low" { "badge-green" }; default { "badge-blue" } }
        $rn = if ($f.ResourceName.Length -gt 30) { $f.ResourceName.Substring(0, 27) + "..." } else { $f.ResourceName }
        $diagRows += @"
          <tr>
            <td title="$(EscHtml $f.ResourceName)">$(EscHtml $rn)</td>
            <td><span class="scope-badge">$(EscHtml $f.ResourceType)</span></td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$(EscHtml $f.Setting)</td>
            <td>$(EscHtml $f.CurrentValue)</td>
            <td><span class="badge $riskCls">$(EscHtml $f.RiskLevel)</span></td>
            <td><span class="badge $compCls">$(EscHtml $f.IsCompliant)</span></td>
          </tr>
"@
    }
    if ($diagRows -eq "") { $diagRows = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px">No diagnostic settings findings generated.</td></tr>' }

    # ── Alerts & Action Groups tab rows ───────────────────────────────────────
    $alertRows = ""
    foreach ($a in $AlertRecords) {
        $sevCls = switch ($a.Severity) { "Sev0" { "badge-red" }; "Sev1" { "badge-red" }; "Sev2" { "badge-amber" }; "Sev3" { "badge-green" }; "Sev4" { "badge-blue" }; default { "badge-blue" } }
        $enaCls = if ($a.IsEnabled -eq "Yes") { "badge-green" } else { "badge-red" }
        $an = if ($a.AlertName.Length -gt 30) { $a.AlertName.Substring(0, 27) + "..." } else { $a.AlertName }
        $alertRows += @"
          <tr>
            <td title="$(EscHtml $a.AlertName)">$(EscHtml $an)</td>
            <td><span class="scope-badge">$(EscHtml $a.AlertType)</span></td>
            <td>$(EscHtml $a.SubscriptionName)</td>
            <td><span class="badge $sevCls">$(EscHtml $a.Severity)</span></td>
            <td><span class="badge $enaCls">$(EscHtml $a.IsEnabled)</span></td>
            <td>$(EscHtml $a.ActionGroupCount)</td>
            <td style="font-size:11px;font-family:var(--mono)">$(EscHtml $a.TargetResource)</td>
          </tr>
"@
    }
    if ($alertRows -eq "") { $alertRows = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px">No alert rules found in scanned subscriptions.</td></tr>' }

    # ── Workspace Architecture tab rows ───────────────────────────────────────
    $wsRows = ""
    foreach ($w in $Workspaces) {
        $retCls = if ($w.RetentionDays -ge 90) { "badge-green" } else { "badge-amber" }
        $tierCls = if ($w.PricingTier -eq "PerGB2018") { "badge-amber" } else { "badge-green" }
        $wsRows += @"
          <tr>
            <td>$(EscHtml $w.WorkspaceName)</td>
            <td>$(EscHtml $w.SubscriptionName)</td>
            <td>$(EscHtml $w.ResourceGroup)</td>
            <td>$(EscHtml $w.Region)</td>
            <td style="font-family:var(--mono)"><span class="badge $retCls">$($w.RetentionDays)d</span></td>
            <td><span class="badge $tierCls">$(EscHtml $w.PricingTier)</span></td>
            <td style="font-family:var(--mono)">$(EscHtml $w.DailyQuotaGB)</td>
            <td>$(EscHtml $w.LinkedAutomationAccount)</td>
          </tr>
"@
    }
    if ($wsRows -eq "") { $wsRows = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:20px">No Log Analytics workspaces found in scanned subscriptions.</td></tr>' }

    # ── Workspace region distribution ─────────────────────────────────────────
    $wsByRegion = @{}
    foreach ($w in $Workspaces) {
        $r = if ($w.Region) { $w.Region } else { "Unknown" }
        if ($wsByRegion.ContainsKey($r)) { $wsByRegion[$r]++ } else { $wsByRegion[$r] = 1 }
    }
    $wsRegTotal = ($wsByRegion.Values | Measure-Object -Sum).Sum
    $wsRegRows = ""
    foreach ($item in ($wsByRegion.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($wsRegTotal -gt 0) { [math]::Round(($item.Value / $wsRegTotal) * 100) } else { 0 }
        $wsRegRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $item.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($item.Value) ($pct%)</span>
          </div>
"@
    }
    if ($wsRegRows -eq "") { $wsRegRows = '<div style="color:var(--muted);padding:12px;font-size:13px">No workspaces found.</div>' }

    # ── Retention tier distribution ───────────────────────────────────────────
    $retBuckets = @{ "< 30d" = 0; "30–89d" = 0; "90–180d" = 0; "180–365d" = 0; "> 365d" = 0 }
    foreach ($w in $Workspaces) {
        $r = [int]$w.RetentionDays
        if ($r -lt 30) { $retBuckets["< 30d"]++ }
        elseif ($r -lt 90) { $retBuckets["30–89d"]++ }
        elseif ($r -lt 180) { $retBuckets["90–180d"]++ }
        elseif ($r -le 365) { $retBuckets["180–365d"]++ }
        else { $retBuckets["> 365d"]++ }
    }
    $retTotal = ($retBuckets.Values | Measure-Object -Sum).Sum
    $retBarRows = ""
    foreach ($item in $retBuckets.GetEnumerator()) {
        if ($item.Value -eq 0) { continue }
        $pct = if ($retTotal -gt 0) { [math]::Round(($item.Value / $retTotal) * 100) } else { 0 }
        $barColor = if ($item.Key -in @("< 30d", "30–89d")) { "var(--red)" } elseif ($item.Key -eq "90–180d") { "var(--amber)" } else { "var(--green)" }
        $retBarRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $item.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($item.Value) ($pct%)</span>
          </div>
"@
    }
    if ($retBarRows -eq "") { $retBarRows = '<div style="color:var(--muted);padding:12px;font-size:13px">No workspaces to chart.</div>' }

    # ── Architectural Risk cards ──────────────────────────────────────────────
    $riskFindings = @($Findings | Where-Object { $_.IsCompliant -eq "No" -and $_.RiskLevel -in @("Critical", "High", "Medium") } |
        Sort-Object { switch ($_.RiskLevel) { "Critical" { 0 }; "High" { 1 }; "Medium" { 2 } } })
    $riskRows = ""
    foreach ($r in $riskFindings) {
        $riskCls = switch ($r.RiskLevel) { "Critical" { "badge-red" }; "High" { "badge-red" }; "Medium" { "badge-amber" }; default { "badge-blue" } }
        $catIcon = switch ($r.RiskCategory) { "Security" { "🔐" }; "Compliance" { "📋" }; "Reliability" { "🔄" }; "Operational Visibility" { "📡" }; "Architecture" { "🏗️" }; "Resilience" { "🛡️" }; default { "⚠️" } }
        $riskRows += @"
          <div class="risk-card">
            <div class="risk-card-header">
              <span class="badge $riskCls">$(EscHtml $r.RiskLevel)</span>
              <span class="risk-cat-badge">$catIcon $(EscHtml $r.RiskCategory)</span>
              <span class="risk-area-badge">$(EscHtml $r.Area)</span>
              <span class="risk-resource">$(EscHtml $r.ResourceName) · <span class="scope-badge">$(EscHtml $r.ResourceType)</span></span>
            </div>
            <div class="risk-finding">$(EscHtml $r.Finding)</div>
            <div class="risk-impacts">
              <div class="risk-impact-block">
                <div class="risk-impact-label">Business Impact</div>
                <div class="risk-impact-text">$(EscHtml $r.BusinessImpact)</div>
              </div>
              <div class="risk-impact-block">
                <div class="risk-impact-label">Architectural Impact</div>
                <div class="risk-impact-text">$(EscHtml $r.ArchitecturalImpact)</div>
              </div>
            </div>
            <div class="risk-rec">
              <span class="risk-rec-label">Recommendation:</span> $(EscHtml $r.Recommendation)
            </div>
            <div class="risk-meta">$(EscHtml $r.SubscriptionName) · $(EscHtml $r.Setting) · Current: <strong>$(EscHtml $r.CurrentValue)</strong></div>
          </div>
"@
    }
    if ($riskRows -eq "") { $riskRows = '<div class="risk-empty">✅ No Critical, High, or Medium findings identified.</div>' }

    # ── Subscription scan result rows ─────────────────────────────────────────
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

    # ── Alert JSON ────────────────────────────────────────────────────────────
    $alertJsonLines = "["
    foreach ($a in $AlertRecords) {
        $alertJsonLines += "{" +
        """name"":""$(EscJ $a.AlertName)""," +
        """type"":""$(EscJ $a.AlertType)""," +
        """sub"":""$(EscJ $a.SubscriptionName)""," +
        """sev"":""$(EscJ $a.Severity)""," +
        """enabled"":""$(EscJ $a.IsEnabled)""," +
        """agCount"":""$(EscJ $a.ActionGroupCount)""," +
        """target"":""$(EscJ $a.TargetResource)""" +
        "},"
    }
    $alertJsonLines = $alertJsonLines.TrimEnd(",") + "]"

    # ── Workspace JSON ────────────────────────────────────────────────────────
    $wsJsonLines = "["
    foreach ($w in $Workspaces) {
        $wsJsonLines += "{" +
        """name"":""$(EscJ $w.WorkspaceName)""," +
        """sub"":""$(EscJ $w.SubscriptionName)""," +
        """rg"":""$(EscJ $w.ResourceGroup)""," +
        """region"":""$(EscJ $w.Region)""," +
        """retention"":$($w.RetentionDays)," +
        """tier"":""$(EscJ $w.PricingTier)""," +
        """quota"":""$(EscJ $w.DailyQuotaGB)""," +
        """automation"":""$(EscJ $w.LinkedAutomationAccount)""" +
        "},"
    }
    $wsJsonLines = $wsJsonLines.TrimEnd(",") + "]"

    # ─────────────────────────────────────────────────────────────────────────
    # HTML HERE-STRING
    # ─────────────────────────────────────────────────────────────────────────
    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Monitoring Architecture Assessment</title>
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
  background:linear-gradient(135deg,var(--accent2),var(--accent3));
  display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{
  display:inline-block;margin-top:8px;padding:2px 8px;border-radius:20px;
  font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent2);border:1px solid var(--border);
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
.nav-btn.active{background:var(--surface3);color:var(--accent2);font-weight:600;}
.nav-btn.active::before{
  content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;
  background:var(--accent2);border-radius:0 3px 3px 0;
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
  border-radius:50%;background:var(--accent2);transition:transform .2s;
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin-bottom:22px;}
.stat-card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;
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
.bar-fill{height:100%;border-radius:4px;background:var(--accent2);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;}
.search-wrap input{
  width:100%;padding:8px 12px 8px 34px;background:var(--surface2);
  border:1px solid var(--border);border-radius:var(--radius-sm);
  color:var(--text);font-size:13px;outline:none;
}
.search-wrap input:focus{border-color:var(--accent2);}
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
.pg-btn:hover{border-color:var(--accent2);color:var(--accent2);}
.pg-btn.active{background:var(--accent2);color:#fff;border-color:var(--accent2);}
.pg-btn:disabled{opacity:.4;cursor:not-allowed;}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.badge-cyan{background:rgba(57,197,207,.15);color:var(--accent2);border:1px solid rgba(57,197,207,.3);}
.scope-badge{font-size:11px;font-family:var(--mono);color:var(--muted2);}
.area-badge{font-size:11px;color:var(--accent2);background:rgba(57,197,207,.1);padding:1px 7px;border-radius:20px;border:1px solid rgba(57,197,207,.25);}
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
/* Risk cards */
.risk-card{
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:18px;margin-bottom:14px;
}
.risk-card:hover{border-color:var(--accent2);}
.risk-card-header{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap;}
.risk-cat-badge{font-size:11px;color:var(--muted2);background:var(--surface3);padding:2px 8px;border-radius:20px;border:1px solid var(--border);}
.risk-area-badge{font-size:11px;color:var(--accent2);background:rgba(57,197,207,.1);padding:2px 8px;border-radius:20px;border:1px solid rgba(57,197,207,.25);}
.risk-resource{font-size:12px;color:var(--muted2);margin-left:auto;}
.risk-finding{font-size:13px;color:var(--text);margin-bottom:12px;line-height:1.6;font-weight:500;}
.risk-impacts{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px;}
.risk-impact-block{background:var(--surface3);border-radius:var(--radius-sm);padding:10px 12px;}
.risk-impact-label{font-size:10px;font-weight:700;color:var(--amber);text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px;}
.risk-impact-text{font-size:12px;color:var(--muted2);line-height:1.55;}
.risk-rec{font-size:12px;color:var(--text);background:rgba(63,185,80,.07);border-left:3px solid var(--green);padding:10px 14px;border-radius:0 var(--radius-sm) var(--radius-sm) 0;margin-bottom:10px;line-height:1.55;}
.risk-rec-label{font-weight:700;color:var(--green);}
.risk-meta{font-size:11px;color:var(--muted);font-family:var(--mono);}
.risk-empty{padding:24px;text-align:center;color:var(--green);font-size:14px;}
/* Detail drawer */
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{
  position:fixed;right:0;top:0;bottom:0;width:500px;max-width:95vw;
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
.drawer-nav-btn:hover{border-color:var(--accent2);color:var(--accent2);}
.drawer-nav-info{font-size:12px;color:var(--muted);flex:1;text-align:center;}
.drawer-field{margin-bottom:12px;}
.drawer-field-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.drawer-field-value{font-size:13px;word-break:break-word;line-height:1.5;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.drawer-impact-box{background:var(--surface2);border-left:3px solid var(--amber);border-radius:0 var(--radius-sm) var(--radius-sm) 0;padding:10px 14px;font-size:12px;line-height:1.6;color:var(--muted2);margin-bottom:8px;}
.drawer-rec-box{background:var(--surface2);border-left:3px solid var(--green);border-radius:0 var(--radius-sm) var(--radius-sm) 0;padding:10px 14px;font-size:12px;line-height:1.6;color:var(--muted2);}
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
  .risk-impacts{grid-template-columns:1fr;}
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
    <div class="logo-title">Monitoring Architecture</div>
    <div class="logo-sub">Observability Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔎</span> All Findings</button>
    <button class="nav-btn" onclick="showPage('diag',this)"><span class="nav-icon">🛠️</span> Diagnostic Settings</button>
    <button class="nav-btn" onclick="showPage('alerts',this)"><span class="nav-icon">🔔</span> Alerts &amp; Action Groups</button>
    <button class="nav-btn" onclick="showPage('workspace',this)"><span class="nav-icon">🗄️</span> Workspace Architecture</button>
    <button class="nav-btn" onclick="showPage('risks',this)"><span class="nav-icon">⚠️</span> Architectural Risks</button>
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
      Azure Monitoring Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- ── Overview ──────────────────────────────────────────────────────────── -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Monitoring Architecture Overview</div>
      <div class="page-sub">Observability posture across __SUB_COUNT__ subscription(s) · __TOTAL_FINDINGS__ findings generated</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Risk</div>
        <div class="stat-sub">Prioritise remediation</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium Risk</div>
        <div class="stat-sub">Plan for resolution</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__NON_COMPLIANT__</div>
        <div class="stat-label">Non-Compliant</div>
        <div class="stat-sub">Settings below baseline</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__TOTAL_WORKSPACES__</div>
        <div class="stat-label">Log Analytics Workspaces</div>
        <div class="stat-sub">Across all subscriptions</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_ALERTS__</div>
        <div class="stat-label">Alert Rules</div>
        <div class="stat-sub">__DISABLED_ALERTS__ disabled</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__DIAG_NON_COMPLIANT__</div>
        <div class="stat-label">Diagnostic Gaps</div>
        <div class="stat-sub">Resources without full coverage</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__COMPLIANT__</div>
        <div class="stat-label">Compliant</div>
        <div class="stat-sub">Meeting baseline</div>
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📊 Risk Level Distribution</div>
        __RL_BAR_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🗂️ Findings by Assessment Area</div>
        __AREA_BAR_ROWS__
      </div>
    </div>
  </div>

  <!-- ── All Findings ───────────────────────────────────────────────────────── -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">All Findings</div>
      <div class="page-sub">Complete findings across all assessment areas — click any row to view full context and recommendation</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search resource, area, setting…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterArea" onchange="filterFindings()">
          <option value="">All Areas</option>
          <option value="Log Analytics">Log Analytics</option>
          <option value="Diagnostic Settings">Diagnostic Settings</option>
          <option value="Alert Rules">Alert Rules</option>
          <option value="Action Groups">Action Groups</option>
        </select>
        <select class="filter-select" id="filterRisk" onchange="filterFindings()">
          <option value="">All Risk Levels</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Informational">Informational</option>
        </select>
        <select class="filter-select" id="filterCompliant" onchange="filterFindings()">
          <option value="">All Compliance</option>
          <option value="No">Non-Compliant</option>
          <option value="Yes">Compliant</option>
        </select>
        <select class="filter-select" id="pgSizeFind" onchange="changeFindPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="sortFindings(0)">Resource</th>
              <th onclick="sortFindings(1)">Type</th>
              <th onclick="sortFindings(2)">Area</th>
              <th onclick="sortFindings(3)">Subscription</th>
              <th onclick="sortFindings(4)">Setting</th>
              <th onclick="sortFindings(5)">Risk Level</th>
              <th onclick="sortFindings(6)">Compliant</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- ── Diagnostic Settings ────────────────────────────────────────────────── -->
  <div id="page-diag" class="page">
    <div class="page-header">
      <div class="page-title">Diagnostic Settings Coverage</div>
      <div class="page-sub">Log forwarding and audit-log coverage for high-value resource types — gaps here create blind spots in security monitoring</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="diagSearch" placeholder="Search resource, type…" oninput="filterDiag()"/>
        </div>
        <select class="filter-select" id="filterDiagRisk" onchange="filterDiag()">
          <option value="">All Risk Levels</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Informational">Informational</option>
        </select>
        <select class="filter-select" id="filterDiagCompliant" onchange="filterDiag()">
          <option value="">All Compliance</option>
          <option value="No">Non-Compliant</option>
          <option value="Yes">Compliant</option>
        </select>
        <select class="filter-select" id="pgSizeDiag" onchange="changeDiagPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="sortDiag(0)">Resource</th>
              <th onclick="sortDiag(1)">Type</th>
              <th onclick="sortDiag(2)">Subscription</th>
              <th onclick="sortDiag(3)">Setting</th>
              <th onclick="sortDiag(4)">Current Value</th>
              <th onclick="sortDiag(5)">Risk Level</th>
              <th onclick="sortDiag(6)">Compliant</th>
            </tr>
          </thead>
          <tbody id="diagBody">__DIAG_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="diagPagination"></div>
    </div>
  </div>

  <!-- ── Alerts & Action Groups ─────────────────────────────────────────────── -->
  <div id="page-alerts" class="page">
    <div class="page-header">
      <div class="page-title">Alerts &amp; Action Groups</div>
      <div class="page-sub">Alert rule inventory and action group health — disabled alerts and orphaned action groups create silent failure modes</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="alertSearch" placeholder="Search alert name, target…" oninput="filterAlerts()"/>
        </div>
        <select class="filter-select" id="filterAlertType" onchange="filterAlerts()">
          <option value="">All Alert Types</option>
          <option value="Metric Alert">Metric Alert</option>
          <option value="Log Alert">Log Alert</option>
          <option value="Activity Log Alert">Activity Log Alert</option>
        </select>
        <select class="filter-select" id="filterAlertEnabled" onchange="filterAlerts()">
          <option value="">All States</option>
          <option value="Yes">Enabled</option>
          <option value="No">Disabled</option>
        </select>
        <select class="filter-select" id="pgSizeAlert" onchange="changeAlertPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="sortAlerts(0)">Alert Name</th>
              <th onclick="sortAlerts(1)">Type</th>
              <th onclick="sortAlerts(2)">Subscription</th>
              <th onclick="sortAlerts(3)">Severity</th>
              <th onclick="sortAlerts(4)">Enabled</th>
              <th onclick="sortAlerts(5)">Action Groups</th>
              <th onclick="sortAlerts(6)">Target Resource</th>
            </tr>
          </thead>
          <tbody id="alertBody">__ALERT_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="alertPagination"></div>
    </div>
  </div>

  <!-- ── Workspace Architecture ─────────────────────────────────────────────── -->
  <div id="page-workspace" class="page">
    <div class="page-header">
      <div class="page-title">Log Analytics Workspace Architecture</div>
      <div class="page-sub">Workspace distribution, retention configuration, pricing tier, and architectural coherence</div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🌍 Workspaces by Region</div>
        __WS_REGION_BAR_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">📅 Retention Distribution</div>
        __RET_BAR_ROWS__
      </div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="wsSearch" placeholder="Search workspace, region…" oninput="filterWs()"/>
        </div>
        <select class="filter-select" id="pgSizeWs" onchange="changeWsPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="sortWs(0)">Workspace Name</th>
              <th onclick="sortWs(1)">Subscription</th>
              <th onclick="sortWs(2)">Resource Group</th>
              <th onclick="sortWs(3)">Region</th>
              <th onclick="sortWs(4)">Retention</th>
              <th onclick="sortWs(5)">Pricing Tier</th>
              <th onclick="sortWs(6)">Daily Quota (GB)</th>
              <th onclick="sortWs(7)">Linked Automation</th>
            </tr>
          </thead>
          <tbody id="wsBody">__WS_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="wsPagination"></div>
    </div>
  </div>

  <!-- ── Architectural Risks ────────────────────────────────────────────────── -->
  <div id="page-risks" class="page">
    <div class="page-header">
      <div class="page-title">Architectural Risk Findings</div>
      <div class="page-sub">Critical, High, and Medium findings with business context, architectural impact, and remediation guidance</div>
    </div>
    <div class="panel">
      __RISK_ROWS__
    </div>
  </div>

  <!-- ── Scan Results ───────────────────────────────────────────────────────── -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription monitoring assessment outcome</div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Subscriptions Scanned</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- ── Session Info ───────────────────────────────────────────────────────── -->
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
        <div class="info-card"><div class="info-label">Resource Types Filter</div><div class="info-value">__RESOURCE_TYPES_FILTER__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Subscriptions Scanned</div><div class="info-value">__SUB_COUNT__</div></div>
        <div class="info-card"><div class="info-label">Total Findings</div><div class="info-value">__TOTAL_FINDINGS__</div></div>
        <div class="info-card"><div class="info-label">Workspaces Assessed</div><div class="info-value">__TOTAL_WORKSPACES__</div></div>
        <div class="info-card"><div class="info-label">Alert Rules Found</div><div class="info-value">__TOTAL_ALERTS__</div></div>
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
const FIND_DATA  = __FINDINGS_JSON__;
const ALERT_DATA_RAW = `__ALERT_JSON_RAW__`;
const WS_DATA_RAW    = `__WS_JSON_RAW__`;

let ALERT_DATA = []; try{ ALERT_DATA = JSON.parse(ALERT_DATA_RAW); }catch(e){}
let WS_DATA    = []; try{ WS_DATA    = JSON.parse(WS_DATA_RAW);    }catch(e){}

const DIAG_DATA  = FIND_DATA.filter(r => r.area === 'Diagnostic Settings');

let findFiltered  = [...FIND_DATA];
let diagFiltered  = [...DIAG_DATA];
let alertFiltered = [...ALERT_DATA];
let wsFiltered    = [...WS_DATA];

let findPage=1,  findPageSz=25,  findSortCol=-1, findSortAsc=true;
let diagPage=1,  diagPageSz=25,  diagSortCol=-1, diagSortAsc=true;
let alertPage=1, alertPageSz=25, alertSortCol=-1,alertSortAsc=true;
let wsPage=1,    wsPageSz=25,    wsSortCol=-1,   wsSortAsc=true;
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
  const r=document.documentElement;
  r.dataset.theme=r.dataset.theme==='dark'?'light':'dark';
}
function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Generic table helpers ─────────────────────────────────────────────────────
function makeBadge(val, map, def){
  const cls = map[val] || def || 'badge-blue';
  return `<span class="badge ${cls}">${escH(val)}</span>`;
}
function renderPagination(containerId, page, total, pageSize, changeFn){
  const pages = Math.ceil(total/pageSize);
  const el = document.getElementById(containerId);
  let h = `<span>${total} items</span>`;
  h += `<button class="pg-btn" onclick="${changeFn}(${page-1})" ${page<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,page-2), e=Math.min(pages,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===page?'active':''}" onclick="${changeFn}(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="${changeFn}(${page+1})" ${page>=pages?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

// ── Findings table ────────────────────────────────────────────────────────────
function filterFindings(){
  const q=document.getElementById('findSearch').value.toLowerCase();
  const a=document.getElementById('filterArea').value;
  const r=document.getElementById('filterRisk').value;
  const c=document.getElementById('filterCompliant').value;
  findFiltered=FIND_DATA.filter(f=>{
    return (!q||JSON.stringify(f).toLowerCase().includes(q))&&
           (!a||f.area===a)&&(!r||f.risk===r)&&(!c||f.compliant===c);
  });
  findPage=1; renderFindings();
}
function changeFindPageSize(){findPageSz=parseInt(document.getElementById('pgSizeFind').value);findPage=1;renderFindings();}
function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys=['res','rtype','area','sub','setting','risk','compliant'];
  findFiltered.sort((a,b)=>{
    const k=keys[col],av=a[k]??'',bv=b[k]??'';
    return findSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true}):String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderFindings();
}
function renderFindings(){
  const riskMap={'Critical':'badge-red','High':'badge-red','Medium':'badge-amber','Low':'badge-green','Informational':'badge-blue'};
  const tbody=document.getElementById('findBody');
  const slice=findFiltered.slice((findPage-1)*findPageSz, findPage*findPageSz);
  tbody.innerHTML=slice.map(f=>{
    const gi=FIND_DATA.indexOf(f);
    const nm=f.res.length>28?f.res.substring(0,25)+'...':f.res;
    return `<tr onclick="showFindingDetail(${gi})" style="cursor:pointer">
      <td title="${escH(f.res)}">${escH(nm)}</td>
      <td><span class="scope-badge">${escH(f.rtype)}</span></td>
      <td><span class="area-badge">${escH(f.area)}</span></td>
      <td>${escH(f.sub)}</td>
      <td>${escH(f.setting)}</td>
      <td>${makeBadge(f.risk,riskMap,'badge-blue')}</td>
      <td>${makeBadge(f.compliant,{'Yes':'badge-green','No':'badge-red'},'badge-blue')}</td>
    </tr>`;
  }).join('');
  renderPagination('findPagination',findPage,findFiltered.length,findPageSz,'changeFindPage');
}
function changeFindPage(p){const t=Math.ceil(findFiltered.length/findPageSz);if(p<1||p>t)return;findPage=p;renderFindings();}

// ── Diagnostic table ──────────────────────────────────────────────────────────
function filterDiag(){
  const q=document.getElementById('diagSearch').value.toLowerCase();
  const r=document.getElementById('filterDiagRisk').value;
  const c=document.getElementById('filterDiagCompliant').value;
  diagFiltered=DIAG_DATA.filter(f=>{
    return (!q||JSON.stringify(f).toLowerCase().includes(q))&&(!r||f.risk===r)&&(!c||f.compliant===c);
  });
  diagPage=1; renderDiag();
}
function changeDiagPageSize(){diagPageSz=parseInt(document.getElementById('pgSizeDiag').value);diagPage=1;renderDiag();}
function sortDiag(col){
  if(diagSortCol===col){diagSortAsc=!diagSortAsc;}else{diagSortCol=col;diagSortAsc=true;}
  const keys=['res','rtype','sub','setting','current','risk','compliant'];
  diagFiltered.sort((a,b)=>{
    const k=keys[col],av=a[k]??'',bv=b[k]??'';
    return diagSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true}):String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderDiag();
}
function renderDiag(){
  const riskMap={'Critical':'badge-red','High':'badge-red','Medium':'badge-amber','Low':'badge-green','Informational':'badge-blue'};
  const tbody=document.getElementById('diagBody');
  const slice=diagFiltered.slice((diagPage-1)*diagPageSz, diagPage*diagPageSz);
  tbody.innerHTML=slice.map(f=>{
    const gi=FIND_DATA.indexOf(f);
    const nm=f.res.length>30?f.res.substring(0,27)+'...':f.res;
    return `<tr onclick="showFindingDetail(${gi})" style="cursor:pointer">
      <td title="${escH(f.res)}">${escH(nm)}</td>
      <td><span class="scope-badge">${escH(f.rtype)}</span></td>
      <td>${escH(f.sub)}</td>
      <td>${escH(f.setting)}</td>
      <td>${escH(f.current)}</td>
      <td>${makeBadge(f.risk,riskMap,'badge-blue')}</td>
      <td>${makeBadge(f.compliant,{'Yes':'badge-green','No':'badge-red'},'badge-blue')}</td>
    </tr>`;
  }).join('');
  renderPagination('diagPagination',diagPage,diagFiltered.length,diagPageSz,'changeDiagPage');
}
function changeDiagPage(p){const t=Math.ceil(diagFiltered.length/diagPageSz);if(p<1||p>t)return;diagPage=p;renderDiag();}

// ── Alert table ───────────────────────────────────────────────────────────────
function filterAlerts(){
  const q=document.getElementById('alertSearch').value.toLowerCase();
  const t=document.getElementById('filterAlertType').value;
  const e=document.getElementById('filterAlertEnabled').value;
  alertFiltered=ALERT_DATA.filter(a=>{
    return (!q||JSON.stringify(a).toLowerCase().includes(q))&&(!t||a.type===t)&&(!e||a.enabled===e);
  });
  alertPage=1; renderAlerts();
}
function changeAlertPageSize(){alertPageSz=parseInt(document.getElementById('pgSizeAlert').value);alertPage=1;renderAlerts();}
function sortAlerts(col){
  if(alertSortCol===col){alertSortAsc=!alertSortAsc;}else{alertSortCol=col;alertSortAsc=true;}
  const keys=['name','type','sub','sev','enabled','agCount','target'];
  alertFiltered.sort((a,b)=>{
    const k=keys[col],av=a[k]??'',bv=b[k]??'';
    return alertSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true}):String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderAlerts();
}
function renderAlerts(){
  const sevMap={'Sev0':'badge-red','Sev1':'badge-red','Sev2':'badge-amber','Sev3':'badge-green','Sev4':'badge-blue'};
  const tbody=document.getElementById('alertBody');
  const slice=alertFiltered.slice((alertPage-1)*alertPageSz, alertPage*alertPageSz);
  tbody.innerHTML=slice.map(a=>{
    const nm=a.name.length>30?a.name.substring(0,27)+'...':a.name;
    const tgt=a.target.length>40?a.target.substring(0,37)+'...':a.target;
    return `<tr>
      <td title="${escH(a.name)}">${escH(nm)}</td>
      <td><span class="scope-badge">${escH(a.type)}</span></td>
      <td>${escH(a.sub)}</td>
      <td>${makeBadge(a.sev,sevMap,'badge-blue')}</td>
      <td>${makeBadge(a.enabled,{'Yes':'badge-green','No':'badge-red'},'badge-red')}</td>
      <td style="font-family:var(--mono)">${escH(a.agCount)}</td>
      <td style="font-size:11px;font-family:var(--mono)">${escH(tgt)}</td>
    </tr>`;
  }).join('');
  renderPagination('alertPagination',alertPage,alertFiltered.length,alertPageSz,'changeAlertPage');
}
function changeAlertPage(p){const t=Math.ceil(alertFiltered.length/alertPageSz);if(p<1||p>t)return;alertPage=p;renderAlerts();}

// ── Workspace table ───────────────────────────────────────────────────────────
function filterWs(){
  const q=document.getElementById('wsSearch').value.toLowerCase();
  wsFiltered=WS_DATA.filter(w=>!q||JSON.stringify(w).toLowerCase().includes(q));
  wsPage=1; renderWs();
}
function changeWsPageSize(){wsPageSz=parseInt(document.getElementById('pgSizeWs').value);wsPage=1;renderWs();}
function sortWs(col){
  if(wsSortCol===col){wsSortAsc=!wsSortAsc;}else{wsSortCol=col;wsSortAsc=true;}
  const keys=['name','sub','rg','region','retention','tier','quota','automation'];
  wsFiltered.sort((a,b)=>{
    const k=keys[col],av=a[k]??'',bv=b[k]??'';
    return wsSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true}):String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderWs();
}
function renderWs(){
  const tbody=document.getElementById('wsBody');
  const slice=wsFiltered.slice((wsPage-1)*wsPageSz, wsPage*wsPageSz);
  tbody.innerHTML=slice.map(w=>{
    const retCls=w.retention>=90?'badge-green':'badge-amber';
    const tierCls=w.tier==='PerGB2018'?'badge-amber':'badge-green';
    return `<tr>
      <td>${escH(w.name)}</td>
      <td>${escH(w.sub)}</td>
      <td>${escH(w.rg)}</td>
      <td>${escH(w.region)}</td>
      <td style="font-family:var(--mono)"><span class="badge ${retCls}">${w.retention}d</span></td>
      <td><span class="badge ${tierCls}">${escH(w.tier)}</span></td>
      <td style="font-family:var(--mono)">${escH(w.quota)}</td>
      <td>${escH(w.automation)}</td>
    </tr>`;
  }).join('');
  renderPagination('wsPagination',wsPage,wsFiltered.length,wsPageSz,'changeWsPage');
}
function changeWsPage(p){const t=Math.ceil(wsFiltered.length/wsPageSz);if(p<1||p>t)return;wsPage=p;renderWs();}

// ── Finding detail drawer ─────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=FIND_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.res+' · '+r.setting;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FIND_DATA.length}`;
  const riskMap={'Critical':'badge-red','High':'badge-red','Medium':'badge-amber','Low':'badge-green','Informational':'badge-blue'};
  const rCls=riskMap[r.risk]||'badge-blue';
  const cCls=r.compliant==='Yes'?'badge-green':'badge-red';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Resource</div><div class="drawer-field-value">${escH(r.res)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Type</div><div class="drawer-field-value"><span class="scope-badge">${escH(r.rtype)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Assessment Area</div><div class="drawer-field-value"><span class="area-badge">${escH(r.area)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Setting</div><div class="drawer-field-value">${escH(r.setting)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Current Value</div><div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.current)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Expected Value</div><div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.expected)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Risk Level</div><div class="drawer-field-value"><span class="badge ${rCls}">${escH(r.risk)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Risk Category</div><div class="drawer-field-value">${escH(r.cat)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Compliant</div><div class="drawer-field-value"><span class="badge ${cCls}">${escH(r.compliant)}</span></div></div>
    <div class="drawer-section">Finding</div>
    <div class="drawer-field-value" style="font-size:13px;line-height:1.6">${escH(r.finding)}</div>
    <div class="drawer-section">Business Impact</div>
    <div class="drawer-impact-box">${escH(r.impact)}</div>
    <div class="drawer-section">Architectural Impact</div>
    <div class="drawer-impact-box">${escH(r.arch)}</div>
    <div class="drawer-section">Recommendation</div>
    <div class="drawer-rec-box">${escH(r.rec)}</div>
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
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{ el.style.width=el.dataset.pct+'%'; });
  });
}
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft'&&document.getElementById('detailDrawer').classList.contains('open')) navDetail(-1);
  if(e.key==='ArrowRight'&&document.getElementById('detailDrawer').classList.contains('open')) navDetail(1);
});

// ── Init ──────────────────────────────────────────────────────────────────────
filterFindings();
filterDiag();
filterAlerts();
filterWs();
animateBars();
</script>
</body>
</html>
'@

    # ── Token substitution ────────────────────────────────────────────────────
    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_FINDINGS__', $totalFindings `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MEDIUM_COUNT__', $mediumCount `
        -replace '__NON_COMPLIANT__', $nonCompliant `
        -replace '__COMPLIANT__', $compliant `
        -replace '__TOTAL_WORKSPACES__', $totalWorkspaces `
        -replace '__TOTAL_ALERTS__', $totalAlerts `
        -replace '__DISABLED_ALERTS__', $disabledAlerts `
        -replace '__DIAG_NON_COMPLIANT__', $diagFindings `
        -replace '__RL_BAR_ROWS__', $rlBarRows `
        -replace '__AREA_BAR_ROWS__', $areaBarRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__DIAG_ROWS__', $diagRows `
        -replace '__ALERT_ROWS__', $alertRows `
        -replace '__WS_ROWS__', $wsRows `
        -replace '__WS_REGION_BAR_ROWS__', $wsRegRows `
        -replace '__RET_BAR_ROWS__', $retBarRows `
        -replace '__RISK_ROWS__', $riskRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__RESOURCE_TYPES_FILTER__', $ScanParameters.ResourceTypesFilter `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FINDINGS_JSON__', $findingsJson `
        -replace '__ALERT_JSON_RAW__', ($alertJsonLines -replace '`', '``') `
        -replace '__WS_JSON_RAW__', ($wsJsonLines -replace '`', '``')

    return $html
}


#------------------------------------------------------------------------ [ Service Assessors ]

# ── Log Analytics Workspaces ──────────────────────────────────────────────────

Function Invoke-WorkspaceAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings,
        [ref]$WorkspaceRecords
    )

    try {
        $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Log Analytics workspaces for $SubscriptionName : $_"
        return
    }

    if ($workspaces.Count -eq 0) {
        $Findings.Value += New-MonitoringFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $SubscriptionName `
            -ResourceGroup       "N/A" `
            -ResourceType        "Log Analytics" `
            -Area                "Log Analytics" `
            -Setting             "Workspace Presence" `
            -CurrentValue        "No workspaces found" `
            -ExpectedValue       "At least one Log Analytics workspace" `
            -IsCompliant         $false `
            -RiskLevel           "Critical" `
            -RiskCategory        "Operational Visibility" `
            -Finding             "No Log Analytics workspaces are deployed in this subscription. There is no centralised log collection or monitoring infrastructure." `
            -BusinessImpact      "Without a Log Analytics workspace, this subscription has no security monitoring, no audit trail, no alerting capability, and no forensic evidence collection. In the event of a security incident, there is no data available to determine what happened, when it started, or what was affected. This represents a critical gap in the organisation's ability to detect, investigate, and respond to threats." `
            -ArchitecturalImpact "Log Analytics is the foundational data plane for the entire Azure Monitor ecosystem. Without it, Azure Security Center/Defender for Cloud cannot collect signals, Azure Sentinel cannot ingest logs, alert rules have no log data to evaluate, and diagnostic settings have no destination to route to. Every other monitoring investment is ineffective without this foundation." `
            -Recommendation      "Deploy at least one Log Analytics workspace in this subscription. For enterprise environments, evaluate whether a centralised multi-subscription workspace model or a dedicated per-subscription model better fits the organisation's security, compliance, and operational requirements. A centralised model reduces tooling fragmentation but requires careful RBAC and data isolation design."

        return
    }

    # ── Per-workspace assessment ──────────────────────────────────────────────
    foreach ($ws in $workspaces) {
        $rg = $ws.ResourceGroupName
        $name = $ws.Name
        $region = $ws.Location
        $retention = [int](Get-ObjProperty -Obj $ws -PropName 'RetentionInDays' -Default 30)
        $tier = Get-ObjProperty -Obj $ws -PropName 'Sku' -Default "PerGB2018"

        # Handle SKU object vs string
        if ($tier -is [Microsoft.Azure.Commands.OperationalInsights.Models.PSWorkspaceSku]) {
            $tier = $tier.Name
        }
        if (-not $tier) { $tier = "PerGB2018" }

        # Daily quota
        $dailyQuota = "Not Set"
        try {
            $wsCfg = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -ErrorAction Stop
            $dailyCapGB = Get-ObjProperty -Obj $wsCfg -PropName 'WorkspaceCapping' -Default $null
            if ($dailyCapGB) { $dailyQuota = "$($dailyCapGB.DailyQuotaGb) GB" }
        }
        catch { Write-Verbose "  Could not read workspace config for ${name}: $_" }

        # Linked Automation Account
        $linkedAuto = "None"
        try {
            $links = @(Get-AzOperationalInsightsLinkedService -ResourceGroupName $rg -WorkspaceName $name -ErrorAction Stop)
            $autoLink = $links | Where-Object { $_.Type -like "*Automation*" }
            if ($autoLink) { $linkedAuto = ($autoLink | Select-Object -First 1).ResourceId.Split('/')[-1] }
        }
        catch { Write-Verbose "  Could not retrieve linked services for ${name}: $_" }

        $WorkspaceRecords.Value += [pscustomobject]@{
            WorkspaceName           = $name
            SubscriptionName        = $SubscriptionName
            SubscriptionId          = $SubscriptionId
            ResourceGroup           = $rg
            Region                  = $region
            RetentionDays           = $retention
            PricingTier             = $tier
            DailyQuotaGB            = $dailyQuota
            LinkedAutomationAccount = $linkedAuto
        }

        # ── Retention assessment ──────────────────────────────────────────────
        $retentionCompliant = ($retention -ge 90)
        $Findings.Value += New-MonitoringFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Log Analytics Workspace" `
            -Area                "Log Analytics" `
            -Setting             "Data Retention Period" `
            -CurrentValue        "${retention} days" `
            -ExpectedValue       "90 days minimum (365 days recommended for regulated workloads)" `
            -IsCompliant         $retentionCompliant `
            -RiskLevel           $(if ($retentionCompliant) { "Informational" } elseif ($retention -ge 30) { "High" } else { "Critical" }) `
            -RiskCategory        "Compliance" `
            -Finding             $(if ($retentionCompliant) { "Log retention is set to ${retention} days, meeting the 90-day minimum baseline." } else { "Log retention is set to ${retention} days, which is below the 90-day enterprise minimum. Security and audit logs may be purged before investigations can be completed." }) `
            -BusinessImpact      $(if ($retentionCompliant) { "Compliant. Retention meets the enterprise baseline. For regulated industries (PCI DSS, HIPAA, ISO 27001), evaluate whether 365-day retention is required for specific log categories." } else { "Insufficient log retention means that security events, access logs, and audit trails may no longer exist when needed for an investigation. Incident investigations typically require 30–90 days of historical log access. Regulatory frameworks including PCI DSS (12 months), ISO 27001, and NIST SP 800-92 require extended log retention. Short retention also limits the organisation's ability to detect long-duration attacks such as persistent threats that exfiltrate data over weeks or months." }) `
            -ArchitecturalImpact $(if ($retentionCompliant) { "Compliant." } else { "Log Analytics is the single authoritative source for security event history in most Azure architectures. Truncated retention creates an irrecoverable gap in the audit trail — once logs are purged, they cannot be reconstructed. Short retention periods also reduce the effectiveness of anomaly detection and behavioural analytics, as ML models in Azure Monitor and Sentinel need historical baselines to establish normal behaviour patterns." }) `
            -Recommendation      $(if ($retentionCompliant) { "No action required. Consider whether compliance requirements mandate longer retention for specific tables (e.g. AuditLogs, SigninLogs). Use workspace-level table retention settings to apply longer retention to security-critical log types without incurring full workspace retention costs." } else { "Increase the retention period to a minimum of 90 days. For regulated environments, target 365 days. Use table-level retention settings in Log Analytics to apply longer retention only to security-critical categories, optimising cost while meeting compliance requirements." })

        # ── Pricing tier assessment ───────────────────────────────────────────
        $isPayAsYouGo = ($tier -eq "PerGB2018")
        $Findings.Value += New-MonitoringFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Log Analytics Workspace" `
            -Area                "Log Analytics" `
            -Setting             "Pricing Tier" `
            -CurrentValue        $tier `
            -ExpectedValue       "Commitment Tier (if daily ingestion > 100 GB)" `
            -IsCompliant         (-not $isPayAsYouGo) `
            -RiskLevel           $(if ($isPayAsYouGo) { "Medium" } else { "Informational" }) `
            -RiskCategory        "Architecture" `
            -Finding             $(if ($isPayAsYouGo) { "This workspace uses the Pay-As-You-Go (PerGB2018) pricing tier. For workspaces ingesting more than 100 GB/day, a Commitment Tier provides significant cost savings." } else { "This workspace uses a Commitment Tier pricing model ($tier), which optimises cost for predictable ingestion volumes." }) `
            -BusinessImpact      $(if ($isPayAsYouGo) { "Pay-As-You-Go pricing on high-volume workspaces can result in significantly higher monitoring costs compared to Commitment Tiers. Organisations sometimes reduce log collection to control costs on pay-as-you-go workspaces, which inadvertently creates monitoring blind spots. Cost pressure should not drive decisions about which security logs to collect." } else { "Compliant. Commitment Tier pricing demonstrates proactive cost management and ensures predictable monitoring expenditure." }) `
            -ArchitecturalImpact $(if ($isPayAsYouGo) { "Monitoring architecture decisions should be cost-optimised to ensure comprehensive log collection is financially sustainable. If pay-as-you-go costs lead to selective log filtering, the monitoring architecture's coverage and effectiveness are compromised. The architecture should support maximum visibility at predictable cost." } else { "Compliant." }) `
            -Recommendation      $(if ($isPayAsYouGo) { "Review the daily ingestion volume for this workspace. If average daily ingestion exceeds 100 GB, evaluate switching to a Commitment Tier. Use the Log Analytics Workspace Insights workbook in the Azure Portal to analyse ingestion volumes by table and source. Consider Microsoft Sentinel's commitment tiers if Sentinel is enabled, as they include Log Analytics ingestion in the pricing." } else { "No action required. Periodically review ingestion volumes against the committed tier to ensure the commitment level remains cost-optimal." })

        # ── Daily cap assessment ──────────────────────────────────────────────
        $Findings.Value += New-MonitoringFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Log Analytics Workspace" `
            -Area                "Log Analytics" `
            -Setting             "Daily Ingestion Cap" `
            -CurrentValue        $dailyQuota `
            -ExpectedValue       "Not Set (or set above security log requirements)" `
            -IsCompliant         ($dailyQuota -eq "Not Set") `
            -RiskLevel           $(if ($dailyQuota -eq "Not Set") { "Informational" } else { "High" }) `
            -RiskCategory        "Operational Visibility" `
            -Finding             $(if ($dailyQuota -eq "Not Set") { "No daily ingestion cap is configured. The workspace accepts all log data without volume restriction." } else { "A daily ingestion cap of $dailyQuota is configured. When this cap is reached, log ingestion stops for the remainder of the day, creating monitoring blind spots." }) `
            -BusinessImpact      $(if ($dailyQuota -eq "Not Set") { "No cap is in place — monitoring completeness is not artificially constrained. Monitor ingestion costs as volumes grow." } else { "A hard ingestion cap is one of the most dangerous monitoring architecture misconfigurations. Attackers aware of the daily cap can time their activities to coincide with the period when logging has stopped. When the cap is hit, security events, audit logs, and threat indicators are silently dropped with no indication in the workspace itself. Incident investigations for events that occurred after the cap was hit have no log evidence." }) `
            -ArchitecturalImpact $(if ($dailyQuota -eq "Not Set") { "Compliant. No artificial log truncation." } else { "A daily cap creates a predictable and exploitable gap in monitoring coverage. In a well-designed monitoring architecture, cost control should be achieved through log source selection and commitment tier pricing — not by capping total ingestion. The cap creates a binary failure mode: the workspace either works fully or stops logging entirely, with no graceful degradation." }) `
            -Recommendation      $(if ($dailyQuota -eq "Not Set") { "No action required. Establish cost alerts on the workspace to notify when ingestion exceeds expected thresholds, without stopping ingestion." } else { "Remove or significantly raise the daily ingestion cap on this workspace. If cost control is the concern, use Log Analytics pricing tiers and table-level sampling to reduce costs without truncating security-critical log streams. Configure Azure Monitor billing alerts to manage cost without sacrificing monitoring completeness." })

        # ── Automation Account linkage ─────────────────────────────────────────
        $hasAutoLink = ($linkedAuto -ne "None")
        $Findings.Value += New-MonitoringFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Log Analytics Workspace" `
            -Area                "Log Analytics" `
            -Setting             "Linked Automation Account" `
            -CurrentValue        $linkedAuto `
            -ExpectedValue       "Linked Automation Account for runbook-based remediation" `
            -IsCompliant         $hasAutoLink `
            -RiskLevel           $(if ($hasAutoLink) { "Informational" } else { "Low" }) `
            -RiskCategory        "Architecture" `
            -Finding             $(if ($hasAutoLink) { "This workspace is linked to Automation Account '$linkedAuto', enabling Update Management, Change Tracking, and runbook-based automated remediation." } else { "No Automation Account is linked to this workspace. Automated operational capabilities such as Update Management, Change Tracking, and alert-triggered runbooks are not configured." }) `
            -BusinessImpact      $(if ($hasAutoLink) { "Compliant. Automation account linkage enables proactive operational capabilities and automated remediation workflows." } else { "Without an Automation Account linked to the workspace, the organisation cannot use Update Management for patch compliance tracking, Change Tracking for configuration drift detection, or automated runbook-based remediation triggered by Azure Monitor alerts. These capabilities are often required for SOC 2 and ISO 27001 operational controls." }) `
            -ArchitecturalImpact $(if ($hasAutoLink) { "Compliant." } else { "An isolated Log Analytics workspace without an Automation Account linkage limits the monitoring architecture to observation only — it cannot close the loop from alert detection to automated remediation. In a mature monitoring architecture, the feedback loop from detect (Log Analytics) to respond (Automation Runbooks) is a core design requirement." }) `
            -Recommendation      $(if ($hasAutoLink) { "No action required. Periodically review runbooks to ensure they remain current and aligned with operational procedures." } else { "Link an Azure Automation Account to this workspace. This enables Update Management for patch visibility, Change Tracking for configuration drift, Inventory collection, and automated alert-triggered runbooks. The linkage is free and takes less than five minutes to configure." })
    }

    # ── Multi-workspace architecture assessment ───────────────────────────────
    if ($workspaces.Count -gt 5) {
        $Findings.Value += New-MonitoringFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $SubscriptionName `
            -ResourceGroup       "N/A" `
            -ResourceType        "Log Analytics Architecture" `
            -Area                "Log Analytics" `
            -Setting             "Workspace Count" `
            -CurrentValue        "$($workspaces.Count) workspaces in this subscription" `
            -ExpectedValue       "1–3 workspaces per subscription (unless driven by regulatory isolation requirements)" `
            -IsCompliant         $false `
            -RiskLevel           "Medium" `
            -RiskCategory        "Architecture" `
            -Finding             "This subscription contains $($workspaces.Count) Log Analytics workspaces. A high workspace count indicates fragmented monitoring architecture with potential gaps in cross-resource visibility." `
            -BusinessImpact      "Fragmented workspaces create operational overhead — security teams must query multiple workspaces to investigate incidents, correlation across resource boundaries becomes manual and error-prone, and SIEM integrations must be configured independently for each workspace. The result is higher operational cost, slower incident response, and reduced detection effectiveness." `
            -ArchitecturalImpact "Log Analytics workspace fragmentation is one of the most common anti-patterns in Azure monitoring architecture. Each workspace is an island — KQL queries, alert rules, workbooks, and Sentinel analytics rules cannot span workspaces natively without workspace-union queries that significantly increase query complexity and cost. A consolidated workspace strategy with RBAC-based table-level access control provides the same data isolation with far better analytical capability." `
            -Recommendation      "Review the rationale for each workspace. Consolidate where possible into a smaller number of workspaces. Valid reasons to maintain multiple workspaces include regulatory data residency requirements, strict security boundary isolation (e.g. production vs non-production), and sovereign cloud isolation. Where consolidation is not possible, implement cross-workspace queries and a common querying layer (e.g. Azure Data Explorer or Sentinel multi-workspace mode) to maintain analytical coherence."
    }
}


# ── Diagnostic Settings ───────────────────────────────────────────────────────

Function Invoke-DiagnosticSettingsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string[]]$ResourceTypeFilter,
        [ref]$Findings
    )

    # Resource type definitions: ResourceType API string → friendly name → risk level for missing diag
    $resourceTypeMap = [ordered]@{
        "Microsoft.KeyVault/vaults"                  = @{ Name = "Key Vault"; Risk = "Critical"; ShortKey = "KeyVault" }
        "Microsoft.Storage/storageAccounts"          = @{ Name = "Storage Account"; Risk = "High"; ShortKey = "Storage" }
        "Microsoft.Network/networkSecurityGroups"    = @{ Name = "NSG"; Risk = "High"; ShortKey = "NSG" }
        "Microsoft.Web/sites"                        = @{ Name = "App Service"; Risk = "High"; ShortKey = "AppService" }
        "Microsoft.Sql/servers/databases"            = @{ Name = "Azure SQL Database"; Risk = "High"; ShortKey = "SQL" }
        "Microsoft.Compute/virtualMachines"          = @{ Name = "Virtual Machine"; Risk = "High"; ShortKey = "VirtualMachine" }
        "Microsoft.ContainerService/managedClusters" = @{ Name = "AKS"; Risk = "High"; ShortKey = "AKS" }
        "Microsoft.Network/applicationGateways"      = @{ Name = "Application Gateway"; Risk = "Medium"; ShortKey = "AppGateway" }
        "Microsoft.Network/azureFirewalls"           = @{ Name = "Azure Firewall"; Risk = "Critical"; ShortKey = "Firewall" }
        "Microsoft.ApiManagement/service"            = @{ Name = "API Management"; Risk = "High"; ShortKey = "APIM" }
    }

    foreach ($rtKey in $resourceTypeMap.Keys) {
        $rtMeta = $resourceTypeMap[$rtKey]

        # Honour -ResourceTypes filter
        if ($ResourceTypeFilter -and $ResourceTypeFilter.Count -gt 0) {
            if ($rtMeta.ShortKey -notin $ResourceTypeFilter) { continue }
        }

        try {
            $resources = @(Get-AzResource -ResourceType $rtKey -ErrorAction Stop)
        }
        catch {
            Write-Verbose "  Could not retrieve $($rtMeta.Name) resources: $_"
            continue
        }

        if ($resources.Count -eq 0) { continue }

        foreach ($resource in $resources) {
            $rg = $resource.ResourceGroupName
            $name = $resource.Name
            $rid = $resource.ResourceId

            # ── Check diagnostic settings via REST ────────────────────────
            $diagSettings = @()
            try {
                $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $rid -ErrorAction Stop)
            }
            catch {
                Write-Verbose "    Could not retrieve diagnostic settings for ${name}: $_"
            }

            $hasAnyDiagSettings = ($diagSettings.Count -gt 0)
            $hasLaDestination = $false
            $hasAuditLogs = $false

            foreach ($ds in $diagSettings) {
                # Check for Log Analytics workspace destination
                $wsDest = Get-ObjProperty -Obj $ds -PropName 'WorkspaceId' -Default ""
                if ($wsDest) { $hasLaDestination = $true }

                # Check if any audit/security log categories are enabled
                $logCategories = @(Get-ObjProperty -Obj $ds -PropName 'Logs' -Default @())
                foreach ($lc in $logCategories) {
                    $catName = Get-ObjProperty -Obj $lc -PropName 'Category' -Default ""
                    $enabled = Get-ObjProperty -Obj $lc -PropName 'Enabled' -Default $false
                    if ($enabled -and ($catName -match "Audit|Security|Admin|Access|Operation|Policy|Alert|Risk")) {
                        $hasAuditLogs = $true
                    }
                }
            }

            # ── Finding: Diagnostic settings presence ──────────────────────
            $Findings.Value += New-MonitoringFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        $rtMeta.Name `
                -Area                "Diagnostic Settings" `
                -Setting             "Diagnostic Settings Configured" `
                -CurrentValue        $(if ($hasAnyDiagSettings) { "$($diagSettings.Count) setting(s) configured" } else { "Not configured" }) `
                -ExpectedValue       "At least one diagnostic setting with Log Analytics destination" `
                -IsCompliant         $hasAnyDiagSettings `
                -RiskLevel           $(if ($hasAnyDiagSettings) { "Informational" } else { $rtMeta.Risk }) `
                -RiskCategory        "Operational Visibility" `
                -Finding             $(if ($hasAnyDiagSettings) { "Diagnostic settings are configured on this $($rtMeta.Name). Logs and metrics are being forwarded to one or more destinations." } else { "No diagnostic settings are configured on this $($rtMeta.Name). Operational logs, security events, and metrics from this resource are not being collected." }) `
                -BusinessImpact      $(if ($hasAnyDiagSettings) { "Diagnostic settings confirmed. Validate that the destination is an active Log Analytics workspace and that security-relevant log categories are enabled." } else { "A $($rtMeta.Name) without diagnostic settings is invisible to the monitoring and security operations infrastructure. Security events, access patterns, configuration changes, and operational errors from this resource produce no telemetry. In the event of a security incident or operational failure involving this resource, there is no evidence to investigate." }) `
                -ArchitecturalImpact $(if ($hasAnyDiagSettings) { "Compliant." } else { "Each resource without diagnostic settings is a blind spot in the monitoring architecture. Depending on the resource type, this can mean missing access audit logs (Key Vault, Storage), network flow logs (NSG), authentication events (API Management), or database query audit trails (SQL). These are precisely the log categories required to detect, investigate, and prove the scope of security incidents." }) `
                -Recommendation      $(if ($hasAnyDiagSettings) { "Verify that at least one destination is a Log Analytics workspace. Use Azure Policy with the 'Deploy Diagnostic Settings' built-in initiative to enforce and auto-remediate diagnostic settings across resource types at scale." } else { "Configure diagnostic settings on this $($rtMeta.Name) immediately. Route logs to the central Log Analytics workspace for this subscription or region. Use the 'Enable Azure Monitor for $($rtMeta.Name)' Azure Policy built-in to enforce this at scale and prevent future resources from being deployed without diagnostic settings." })

            # ── Finding: Log Analytics destination ────────────────────────
            if ($hasAnyDiagSettings) {
                $Findings.Value += New-MonitoringFinding `
                    -SubscriptionName    $SubscriptionName `
                    -SubscriptionId      $SubscriptionId `
                    -ResourceName        $name `
                    -ResourceGroup       $rg `
                    -ResourceType        $rtMeta.Name `
                    -Area                "Diagnostic Settings" `
                    -Setting             "Log Analytics Workspace Destination" `
                    -CurrentValue        $(if ($hasLaDestination) { "Configured" } else { "Not configured (Storage or Event Hub only)" }) `
                    -ExpectedValue       "Log Analytics workspace as destination" `
                    -IsCompliant         $hasLaDestination `
                    -RiskLevel           $(if ($hasLaDestination) { "Informational" } else { "High" }) `
                    -RiskCategory        "Operational Visibility" `
                    -Finding             $(if ($hasLaDestination) { "Diagnostic logs are routed to a Log Analytics workspace, enabling real-time alerting, querying, and integration with security tools." } else { "Diagnostic settings are configured but no Log Analytics workspace is set as a destination. Logs are going to Storage or Event Hub only, which does not support real-time alerting or interactive security investigation." }) `
                    -BusinessImpact      $(if ($hasLaDestination) { "Compliant. Logs are queryable and alertable in real time." } else { "Logs stored only in a Storage Account or forwarded only to Event Hub cannot be interactively queried, cannot trigger alerts, and cannot be correlated with other resources in Log Analytics. The organisation is collecting logs but cannot operationally use them for security monitoring or incident response without additional tooling to process the Storage or Event Hub destination." }) `
                    -ArchitecturalImpact $(if ($hasLaDestination) { "Compliant." } else { "The value of diagnostic log collection is almost entirely dependent on where the logs land. A Log Analytics destination makes logs immediately searchable via KQL, correlatable across resources, and usable as alert signal sources. Storage and Event Hub destinations require downstream processing pipelines to achieve the same capability — adding architectural complexity and lag that degrades incident response speed." }) `
                    -Recommendation      $(if ($hasLaDestination) { "No action required. Ensure the destination workspace has sufficient retention and that relevant alert rules consume these log categories." } else { "Add a Log Analytics workspace as a destination to the existing diagnostic settings. The Storage Account or Event Hub destination can be retained for archive or streaming purposes, but a Log Analytics destination must be present for operational monitoring." })

                # ── Finding: Audit log categories enabled ─────────────────
                $Findings.Value += New-MonitoringFinding `
                    -SubscriptionName    $SubscriptionName `
                    -SubscriptionId      $SubscriptionId `
                    -ResourceName        $name `
                    -ResourceGroup       $rg `
                    -ResourceType        $rtMeta.Name `
                    -Area                "Diagnostic Settings" `
                    -Setting             "Security/Audit Log Categories Enabled" `
                    -CurrentValue        $(if ($hasAuditLogs) { "Audit/security categories enabled" } else { "No audit/security categories enabled" }) `
                    -ExpectedValue       "Audit and security log categories enabled" `
                    -IsCompliant         $hasAuditLogs `
                    -RiskLevel           $(if ($hasAuditLogs) { "Informational" } else { "High" }) `
                    -RiskCategory        "Security" `
                    -Finding             $(if ($hasAuditLogs) { "Security and audit log categories are enabled in the diagnostic settings for this $($rtMeta.Name)." } else { "Diagnostic settings exist but no security or audit log categories (such as AuditEvent, AdminOperations, or SecurityAlert) are enabled. Only performance metrics or non-security categories may be collected." }) `
                    -BusinessImpact      $(if ($hasAuditLogs) { "Compliant. Security-relevant log categories are being collected, enabling threat detection and compliance audit trails." } else { "Collecting metrics and operational logs without enabling audit and security categories means the organisation has monitoring coverage for performance and availability but not for security events. Access patterns, privilege escalation, configuration changes, and policy violations are not recorded. This gap prevents the detection of insider threats, compromised accounts, and misuse of the resource." }) `
                    -ArchitecturalImpact $(if ($hasAuditLogs) { "Compliant." } else { "A monitoring architecture that selectively enables only performance-oriented log categories misses the most security-relevant telemetry. The security team's ability to detect and investigate threats is directly proportional to the completeness of audit log collection. Enabling audit categories is typically a zero-cost change — log volume is low for audit events but the security value is very high." }) `
                    -Recommendation      $(if ($hasAuditLogs) { "No action required. Periodically review which categories are enabled against the resource's available log categories to ensure new categories added by the service are evaluated and enabled where relevant." } else { "Edit the diagnostic settings for this resource and enable all available audit, security, and access log categories. For Key Vault, enable AuditEvent. For NSG, enable NetworkSecurityGroupEvent and NetworkSecurityGroupRuleCounter. For Storage, enable StorageRead, StorageWrite, and StorageDelete. Review the Azure documentation for each resource type's available log categories." })
            }
        }
    }
}


# ── Alert Rules ───────────────────────────────────────────────────────────────

Function Invoke-AlertAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings,
        [ref]$AlertRecords
    )

    # ── Metric Alerts ─────────────────────────────────────────────────────────
    $metricAlerts = @()
    try {
        $metricAlerts = @(Get-AzMetricAlertRuleV2 -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve metric alerts for $SubscriptionName : $_"
    }

    foreach ($alert in $metricAlerts) {
        $rg = $alert.ResourceGroupName
        $name = $alert.Name
        $enabled = $alert.Enabled
        $sev = "Sev$($alert.Severity)"
        $agCount = @(Get-ObjProperty -Obj $alert -PropName 'Actions' -Default @()).Count
        $target = ""
        try { $target = ($alert.Scopes -join "; ") } catch { }

        $AlertRecords.Value += [pscustomobject]@{
            AlertName        = $name
            AlertType        = "Metric Alert"
            SubscriptionName = $SubscriptionName
            SubscriptionId   = $SubscriptionId
            ResourceGroup    = $rg
            Severity         = $sev
            IsEnabled        = if ($enabled) { "Yes" } else { "No" }
            ActionGroupCount = "$agCount action group(s)"
            TargetResource   = $target
        }

        if (-not $enabled) {
            $Findings.Value += New-MonitoringFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        "Metric Alert" `
                -Area                "Alert Rules" `
                -Setting             "Alert Enabled State" `
                -CurrentValue        "Disabled" `
                -ExpectedValue       "Enabled" `
                -IsCompliant         $false `
                -RiskLevel           $(if ($sev -in @("Sev0", "Sev1")) { "High" } else { "Medium" }) `
                -RiskCategory        "Operational Visibility" `
                -Finding             "Metric alert '$name' (severity $sev) is disabled. This alert will not fire regardless of the monitored condition." `
                -BusinessImpact      "A disabled alert is indistinguishable from no alert at all from an operational perspective. If this alert was designed to detect a resource failure, performance degradation, or threshold breach, those conditions will now occur silently. Engineering teams and on-call responders will not be notified, and SLA commitments tied to this metric may be violated before anyone is aware of the problem." `
                -ArchitecturalImpact "Alert rules are the notification layer of the monitoring architecture. A disabled alert rule represents a permanent gap in the alerting coverage until it is re-enabled. In many environments, alerts are disabled temporarily to suppress noise during maintenance and are never re-enabled. Over time, this erodes the reliability of the alerting model — the organisation believes it is monitored when it is not." `
                -Recommendation      "Investigate why this alert is disabled. If it was suppressed during maintenance, re-enable it. If it generates too much noise, refine the threshold or frequency condition rather than disabling it. If the alert is no longer relevant, delete it to keep the alert inventory accurate. Never leave critical or high-severity alerts in a permanently disabled state."
        }

        if ($agCount -eq 0) {
            $Findings.Value += New-MonitoringFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        "Metric Alert" `
                -Area                "Alert Rules" `
                -Setting             "Action Group Configured" `
                -CurrentValue        "No action groups linked" `
                -ExpectedValue       "At least one action group with active receivers" `
                -IsCompliant         $false `
                -RiskLevel           "High" `
                -RiskCategory        "Operational Visibility" `
                -Finding             "Metric alert '$name' has no action groups linked. This alert will fire but no notifications will be sent and no automated remediation will be triggered." `
                -BusinessImpact      "An alert without an action group is a silent alarm — it may fire in the Azure portal, but nobody is notified and no automated response occurs. Depending on the alerting architecture, this alert may also be excluded from ITSM ticket generation and on-call scheduling systems, meaning the event is completely invisible to the operations team." `
                -ArchitecturalImpact "Alert rules without action groups represent orphaned notification pipelines. In a well-designed monitoring architecture, every alert rule must have at least one action group ensuring notification reaches the responsible team. Alerts without action groups also cannot trigger Logic Apps, Azure Functions, or runbooks for automated remediation." `
                -Recommendation      "Link at least one action group to this alert rule. The action group should route notifications to the appropriate team via email, SMS, PagerDuty webhook, or ITSM connector. For critical infrastructure alerts, the action group should also trigger an automated remediation runbook or Logic App."
        }
    }

    # ── Log (Scheduled Query) Alerts ─────────────────────────────────────────
    $logAlerts = @()
    try {
        $logAlerts = @(Get-AzScheduledQueryRule -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve log alert rules for $SubscriptionName : $_"
    }

    foreach ($la in $logAlerts) {
        $rg = $la.ResourceGroupName
        $name = $la.Name
        $enabled = $la.Enabled
        $sev = "Sev$($la.Severity)"
        $agCount = @(Get-ObjProperty -Obj $la -PropName 'Action' -Default $null | ForEach-Object { Get-ObjProperty -Obj $_ -PropName 'ActionGroupId' -Default @() }).Count
        $target = ""
        try { $target = ($la.Scopes -join "; ") } catch { }

        $AlertRecords.Value += [pscustomobject]@{
            AlertName        = $name
            AlertType        = "Log Alert"
            SubscriptionName = $SubscriptionName
            SubscriptionId   = $SubscriptionId
            ResourceGroup    = $rg
            Severity         = $sev
            IsEnabled        = if ($enabled) { "Yes" } else { "No" }
            ActionGroupCount = "$agCount action group(s)"
            TargetResource   = $target
        }

        if (-not $enabled) {
            $Findings.Value += New-MonitoringFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        "Log Alert" `
                -Area                "Alert Rules" `
                -Setting             "Alert Enabled State" `
                -CurrentValue        "Disabled" `
                -ExpectedValue       "Enabled" `
                -IsCompliant         $false `
                -RiskLevel           $(if ($sev -in @("Sev0", "Sev1")) { "High" } else { "Medium" }) `
                -RiskCategory        "Operational Visibility" `
                -Finding             "Log alert rule '$name' (severity $sev) is disabled. KQL queries underpinning this alert are not being evaluated against incoming log data." `
                -BusinessImpact      "A disabled log alert means its detection logic — regardless of how sophisticated the KQL query — is not running. Security detections, anomaly detection rules, and operational threshold monitors all fail silently when disabled. This creates a gap that may not be noticed until the detection is urgently needed during an incident." `
                -ArchitecturalImpact "Log alert rules are the detection layer built on top of the Log Analytics data plane. Each disabled rule represents a detection gap — a class of threat or operational condition that is no longer being monitored. Unlike metric alerts where the platform evaluates a simple threshold, log alerts may encode complex multi-step detection logic. Re-enabling them restores that detection capability immediately." `
                -Recommendation      "Re-enable this log alert rule if it was suppressed during maintenance. If it generates false positives, tune the KQL query conditions (time window, threshold, frequency) rather than disabling the rule. Review all disabled log alert rules quarterly as part of alert hygiene."
        }

        if ($agCount -eq 0) {
            $Findings.Value += New-MonitoringFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        "Log Alert" `
                -Area                "Alert Rules" `
                -Setting             "Action Group Configured" `
                -CurrentValue        "No action groups linked" `
                -ExpectedValue       "At least one action group" `
                -IsCompliant         $false `
                -RiskLevel           "High" `
                -RiskCategory        "Operational Visibility" `
                -Finding             "Log alert '$name' has no action groups configured. Alert evaluations that meet the trigger condition will fire with no downstream notification or automated response." `
                -BusinessImpact      "A log alert without an action group may be visible in the Azure Monitor Alerts portal, but will not trigger any notification to on-call teams, ITSM systems, or automated remediation workflows. The organisation is paying for alert evaluation compute time while receiving no operational value from the alert." `
                -ArchitecturalImpact "Action groups are the notification and response backbone of the Azure Monitor alerting model. Alerts without them are analytically complete but operationally inert. Every alert rule — regardless of type — must be wired to at least one action group to be architecturally complete." `
                -Recommendation      "Add at least one action group to this alert rule. Leverage existing action groups where appropriate to reduce duplication. Ensure the action group routes to the team responsible for the resource or workload being monitored."
        }
    }

    # ── Activity Log Alerts ───────────────────────────────────────────────────
    $activityAlerts = @()
    try {
        $activityAlerts = @(Get-AzActivityLogAlert -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Activity Log alerts for $SubscriptionName : $_"
    }

    foreach ($ala in $activityAlerts) {
        $rg = $ala.ResourceGroupName
        $name = $ala.Name
        $enabled = $ala.Enabled
        $agCount = @(Get-ObjProperty -Obj $ala -PropName 'Actions' -Default @() |
            ForEach-Object { Get-ObjProperty -Obj $_ -PropName 'ActionGroups' -Default @() }).Count

        $AlertRecords.Value += [pscustomobject]@{
            AlertName        = $name
            AlertType        = "Activity Log Alert"
            SubscriptionName = $SubscriptionName
            SubscriptionId   = $SubscriptionId
            ResourceGroup    = $rg
            Severity         = "N/A"
            IsEnabled        = if ($enabled) { "Yes" } else { "No" }
            ActionGroupCount = "$agCount action group(s)"
            TargetResource   = $SubscriptionName
        }

        if (-not $enabled) {
            $Findings.Value += New-MonitoringFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        "Activity Log Alert" `
                -Area                "Alert Rules" `
                -Setting             "Alert Enabled State" `
                -CurrentValue        "Disabled" `
                -ExpectedValue       "Enabled" `
                -IsCompliant         $false `
                -RiskLevel           "High" `
                -RiskCategory        "Security" `
                -Finding             "Activity Log alert '$name' is disabled. Azure control-plane events matching this alert's conditions will not generate notifications." `
                -BusinessImpact      "Activity Log alerts are the primary mechanism for detecting privileged administrative actions against Azure resources — policy changes, resource deletions, role assignments, security configuration changes, and service health events. Disabling these alerts creates a blind spot in control-plane governance monitoring. Insider threats, compromised Azure administrator accounts, and accidental destructive changes can occur without any notification reaching the security or operations team." `
                -ArchitecturalImpact "Activity Log alerts are the only native mechanism for detecting Azure Resource Manager (control-plane) events in real time. Unlike data-plane events (which flow through diagnostic settings to Log Analytics), control-plane events from the Activity Log are only alertable via Activity Log alert rules. Disabling them removes a layer of detection that cannot be replicated through diagnostic settings alone." `
                -Recommendation      "Re-enable this Activity Log alert. Critical Activity Log alerts to maintain include: Security policy changes, Role Assignment changes (RBAC), Resource deletions, Key Vault access policy changes, Azure Firewall rule changes, and Service Health events. These should never be suppressed for extended periods."
        }
    }

    # ── Missing critical Activity Log alert coverage check ────────────────────
    $criticalPatterns = @(
        @{ Pattern = "Microsoft.Authorization/roleAssignments"; FriendlyName = "RBAC Role Assignment Changes" }
        @{ Pattern = "Microsoft.Security/policies"; FriendlyName = "Security Policy Changes" }
        @{ Pattern = "Microsoft.KeyVault/vaults/delete"; FriendlyName = "Key Vault Deletion" }
        @{ Pattern = "Microsoft.Network/networkSecurityGroups"; FriendlyName = "NSG Modification" }
        @{ Pattern = "Microsoft.Sql/servers/firewallRules"; FriendlyName = "SQL Firewall Rule Changes" }
    )

    foreach ($pattern in $criticalPatterns) {
        $covered = $false
        foreach ($ala in $activityAlerts) {
            try {
                $conditions = Get-ObjProperty -Obj $ala -PropName 'Condition' -Default $null
                $allOf = Get-ObjProperty -Obj $conditions -PropName 'AllOf' -Default @()
                foreach ($cond in $allOf) {
                    $fieldVal = Get-ObjProperty -Obj $cond -PropName 'Equals' -Default ""
                    if ($fieldVal -and $fieldVal -like "*$($pattern.Pattern)*") {
                        $covered = $true
                        break
                    }
                }
            }
            catch { }
            if ($covered) { break }
        }

        if (-not $covered) {
            $Findings.Value += New-MonitoringFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $SubscriptionName `
                -ResourceGroup       "N/A" `
                -ResourceType        "Activity Log Alert" `
                -Area                "Alert Rules" `
                -Setting             "Critical Alert Coverage: $($pattern.FriendlyName)" `
                -CurrentValue        "No Activity Log alert covering this event type" `
                -ExpectedValue       "Activity Log alert configured for $($pattern.FriendlyName)" `
                -IsCompliant         $false `
                -RiskLevel           "High" `
                -RiskCategory        "Security" `
                -Finding             "No Activity Log alert is configured to detect '$($pattern.FriendlyName)' events. Changes of this type can occur without any notification to the security or operations team." `
                -BusinessImpact      "Missing coverage for $($pattern.FriendlyName) means that security-relevant control-plane events in this subscription go undetected in real time. For an attacker who has gained access to an Azure administrative identity, the absence of this alert allows them to make changes — escalate privileges, modify firewall rules, disable security controls — without triggering any automated response." `
                -ArchitecturalImpact "A complete Azure monitoring architecture must include Activity Log alerts for all security-relevant administrative actions. The CIS Azure Benchmark, Microsoft Cloud Security Benchmark, and most enterprise security frameworks explicitly require alerting on RBAC changes, security policy modifications, and critical resource operations. Missing these alerts represents a gap against these compliance frameworks." `
                -Recommendation      "Create an Activity Log alert for '$($pattern.FriendlyName)' at the subscription scope. Assign it to an action group that notifies the security team immediately. Review the CIS Microsoft Azure Foundations Benchmark Section 5 and the Microsoft Cloud Security Benchmark for the complete list of Activity Log alerts that should be configured."
        }
    }
}


# ── Action Groups ─────────────────────────────────────────────────────────────

Function Invoke-ActionGroupAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings
    )

    try {
        $actionGroups = @(Get-AzActionGroup -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Action Groups for $SubscriptionName : $_"
        return
    }

    if ($actionGroups.Count -eq 0) {
        $Findings.Value += New-MonitoringFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $SubscriptionName `
            -ResourceGroup       "N/A" `
            -ResourceType        "Action Group" `
            -Area                "Action Groups" `
            -Setting             "Action Group Presence" `
            -CurrentValue        "No action groups found" `
            -ExpectedValue       "At least one action group with active receivers" `
            -IsCompliant         $false `
            -RiskLevel           "Critical" `
            -RiskCategory        "Operational Visibility" `
            -Finding             "No Action Groups are configured in this subscription. Alert rules cannot send notifications or trigger automated responses without action groups." `
            -BusinessImpact      "Without action groups, all alert rules in this subscription fire silently. No notifications reach on-call engineers, SRE teams, or ITSM systems. No automated remediation runbooks or Logic Apps are triggered. The monitoring architecture is collecting telemetry and evaluating alert conditions, but the notification and response layer is completely absent. This is equivalent to having smoke detectors without an alarm." `
            -ArchitecturalImpact "Action Groups are the essential bridge between alert detection and human/automated response in the Azure Monitor architecture. Without them, the monitoring stack is analytically complete but operationally inert. Every alert rule configuration, every KQL detection query, and every metric threshold becomes meaningless without an action group to deliver the signal to a responsible team." `
            -Recommendation      "Create action groups immediately for each operational and security team that should receive alerts. Define action groups for at minimum: Critical infrastructure alerts (email + SMS + webhook to ITSM), Security events (email + webhook to SIEM or SOC tooling), and Automated remediation (Azure Function or Logic App). Reference action groups across multiple alert rules to reduce duplication."
        return
    }

    foreach ($ag in $actionGroups) {
        $rg = $ag.ResourceGroupName
        $name = $ag.Name

        # Count receivers across all receiver types
        $emailReceivers = @(Get-ObjProperty -Obj $ag -PropName 'EmailReceiver'    -Default @()).Count
        $smsReceivers = @(Get-ObjProperty -Obj $ag -PropName 'SmsReceiver'      -Default @()).Count
        $webhookReceivers = @(Get-ObjProperty -Obj $ag -PropName 'WebhookReceiver'  -Default @()).Count
        $itsmReceivers = @(Get-ObjProperty -Obj $ag -PropName 'ItsmReceiver'     -Default @()).Count
        $funcReceivers = @(Get-ObjProperty -Obj $ag -PropName 'AzureFunctionReceiver' -Default @()).Count
        $logicAppReceivers = @(Get-ObjProperty -Obj $ag -PropName 'LogicAppReceiver' -Default @()).Count
        $armReceivers = @(Get-ObjProperty -Obj $ag -PropName 'ArmRoleReceiver'  -Default @()).Count
        $totalReceivers = $emailReceivers + $smsReceivers + $webhookReceivers + $itsmReceivers + $funcReceivers + $logicAppReceivers + $armReceivers

        $hasReceivers = ($totalReceivers -gt 0)

        $receiverSummary = "Email:$emailReceivers SMS:$smsReceivers Webhook:$webhookReceivers ITSM:$itsmReceivers Function:$funcReceivers LogicApp:$logicAppReceivers Role:$armReceivers"

        $Findings.Value += New-MonitoringFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Action Group" `
            -Area                "Action Groups" `
            -Setting             "Receiver Configuration" `
            -CurrentValue        $(if ($hasReceivers) { "$totalReceivers receiver(s): $receiverSummary" } else { "No receivers configured" }) `
            -ExpectedValue       "At least one active receiver" `
            -IsCompliant         $hasReceivers `
            -RiskLevel           $(if ($hasReceivers) { "Informational" } else { "Critical" }) `
            -RiskCategory        "Operational Visibility" `
            -Finding             $(if ($hasReceivers) { "Action group '$name' has $totalReceivers receiver(s) configured ($receiverSummary)." } else { "Action group '$name' has no receivers configured. Any alert rule linked to this action group will fire without generating any notification or automated response." }) `
            -BusinessImpact      $(if ($hasReceivers) { "Compliant. Ensure receiver addresses are current and validated. Periodically test the action group to confirm delivery." } else { "An action group with no receivers is a silent notification pipeline. Alert rules linked to this action group appear correctly configured but deliver no value — engineers are never notified of the conditions the alerts are designed to detect. This is a particularly dangerous misconfiguration because it creates a false sense of monitoring completeness." }) `
            -ArchitecturalImpact $(if ($hasReceivers) { "Compliant." } else { "An empty action group is an architectural failure mode — it breaks the detect → notify → respond lifecycle without any visible indication in the alert rule configuration. Teams reviewing the alert rule see a linked action group and assume notifications are being sent, when in reality the action group is a dead end." }) `
            -Recommendation      $(if ($hasReceivers) { "No action required. Test the action group periodically using the Test button in the Azure Portal to confirm all receivers are reachable and deliverable. Review receiver email addresses for accuracy if team membership has changed." } else { "Add at least one receiver to this action group immediately. At a minimum, add an email receiver pointing to the responsible team's distribution list. For critical infrastructure, add SMS and webhook receivers to ensure redundant notification delivery. Delete empty action groups that are no longer needed to keep the alert inventory accurate." })

        # ── Check for ITSM or webhook integration for mature organisations ─
        $hasAdvancedIntegration = ($webhookReceivers -gt 0 -or $itsmReceivers -gt 0 -or $funcReceivers -gt 0 -or $logicAppReceivers -gt 0)
        $hasOnlyEmailSms = ($hasReceivers -and -not $hasAdvancedIntegration)

        if ($hasOnlyEmailSms) {
            $Findings.Value += New-MonitoringFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        "Action Group" `
                -Area                "Action Groups" `
                -Setting             "Integration Type" `
                -CurrentValue        "Email/SMS only" `
                -ExpectedValue       "Webhook, ITSM, Function, or Logic App integration for automated response" `
                -IsCompliant         $false `
                -RiskLevel           "Low" `
                -RiskCategory        "Architecture" `
                -Finding             "Action group '$name' uses only email/SMS receivers. No webhook, ITSM connector, Azure Function, or Logic App integration is configured for automated response or ITSM ticket creation." `
                -BusinessImpact      "Email-only action groups rely entirely on human attention and response speed. During non-business hours, high alert volumes, or when team members are unavailable, email notifications may be missed or delayed. For production workloads with SLA commitments, relying exclusively on email notification means that the mean time to response is bounded by human availability rather than automated trigger speed." `
                -ArchitecturalImpact "A mature monitoring architecture closes the loop from detection to response without requiring manual intervention for routine alert types. Webhook and ITSM integrations enable automatic ticket creation, PagerDuty/OpsGenie escalation, and runbook-triggered remediation — reducing mean time to acknowledge (MTTA) and mean time to resolve (MTTR). Email-only notification is appropriate for informational alerts but insufficient for critical or high-severity events." `
                -Recommendation      "Evaluate adding a webhook receiver to integrate with the organisation's ITSM platform (ServiceNow, Jira, PagerDuty, OpsGenie) for automatic ticket creation. For automated remediation use cases, add an Azure Function or Logic App receiver that can take corrective action without human intervention. Reserve email/SMS for informational and low-severity notifications."
        }
    }
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureMonitoringArchitectureAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureMonitoringArchitecture-Report.csv",

        [ValidateSet("KeyVault", "Storage", "NSG", "AppService", "Functions", "SQL",
            "VirtualMachine", "AKS", "AppGateway", "Firewall", "APIM", "All")]
        [string[]]$ResourceTypes = @("All")
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts",
        "Az.OperationalInsights",
        "Az.Monitor",
        "Az.Resources",
        "Az.Automation"
    )

    $missingRequired = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missingRequired) {
        Write-Host "  ⚠ Missing Az modules: $($missingRequired -join ', ')" -ForegroundColor Yellow
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

    # ── Resource type filter ──────────────────────────────────────────────────
    $rtFilter = @()
    $rtFilterText = "All"
    if ("All" -notin $ResourceTypes) {
        $rtFilter = $ResourceTypes
        $rtFilterText = $ResourceTypes -join ", "
    }

    # ── Display session / params ──────────────────────────────────────────────
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"                 = "$scopeText ($subCount found)"
        "Resource Types (Diag)" = $rtFilterText
        "Export to CSV"         = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"           = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $allWorkspaces = @()
    $allAlertRecords = @()
    $subscriptionResults = @()
    $successCount = 0
    $errorCount = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-ScanProgress

    $maxNameLen = ([math]::Max(
            ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
            35
        ))

    $subIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $subFindings = [System.Collections.ArrayList]@()
            $subWorkspaces = [System.Collections.ArrayList]@()
            $subAlertRecords = [System.Collections.ArrayList]@()

            # ── Log Analytics Workspaces ───────────────────────────────────
            Invoke-WorkspaceAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings) `
                -WorkspaceRecords ([ref]$subWorkspaces)

            # ── Diagnostic Settings ────────────────────────────────────────
            Invoke-DiagnosticSettingsAssessment `
                -SubscriptionName  $sub.Name `
                -SubscriptionId    $sub.Id `
                -ResourceTypeFilter $rtFilter `
                -Findings          ([ref]$subFindings)

            # ── Alert Rules ────────────────────────────────────────────────
            Invoke-AlertAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings) `
                -AlertRecords     ([ref]$subAlertRecords)

            # ── Action Groups ──────────────────────────────────────────────
            Invoke-ActionGroupAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings)

            $allFindings += $subFindings
            $allWorkspaces += $subWorkspaces
            $allAlertRecords += $subAlertRecords

            $subNonCompliant = @($subFindings | Where-Object { $_.IsCompliant -eq "No" }).Count
            $subCritHigh = @($subFindings | Where-Object { $_.RiskLevel -in @("Critical", "High") }).Count
            $subDisabledAl = @($subAlertRecords | Where-Object { $_.IsEnabled -eq "No" }).Count

            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host ("Findings: $($subFindings.Count)  Non-Compliant: $subNonCompliant  Critical/High: $subCritHigh  Workspaces: $($subWorkspaces.Count)  Alerts: $($subAlertRecords.Count) ($subDisabledAl disabled)") -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Findings: $($subFindings.Count)  Non-Compliant: $subNonCompliant  Workspaces: $($subWorkspaces.Count)"
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

    $criticalTotal = @($allFindings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highTotal = @($allFindings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $nonComplTotal = @($allFindings | Where-Object { $_.IsCompliant -eq "No" }).Count
    $disabledAlerts = @($allAlertRecords | Where-Object { $_.IsEnabled -eq "No" }).Count
    $noAgAlerts = @($allAlertRecords | Where-Object { $_.ActionGroupCount -eq "0 action group(s)" }).Count

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned"  = $subCount
            "Successful"                   = $successCount
            "Errors"                       = $errorCount
            "Total Findings"               = $allFindings.Count
            "Non-Compliant Findings"       = $nonComplTotal
            "Critical Findings"            = $criticalTotal
            "High Findings"                = $highTotal
            "Log Analytics Workspaces"     = $allWorkspaces.Count
            "Alert Rules Found"            = $allAlertRecords.Count
            "Disabled Alert Rules"         = $disabledAlerts
            "Alerts Without Action Groups" = $noAgAlerts
            "Execution Time"               = $duration
        })

    Write-RiskBreakdown -Findings $allFindings

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0 -or $allWorkspaces.Count -gt 0) {
        # CSV export
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, ResourceName, ResourceGroup, ResourceType,
                Area, Setting, CurrentValue, ExpectedValue, IsCompliant,
                RiskLevel, RiskCategory, Finding, BusinessImpact, ArchitecturalImpact, Recommendation |
                Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                if ($allWorkspaces.Count -gt 0) {
                    $wsCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "Workspaces.csv"
                    $allWorkspaces | Export-Csv -Path $wsCsvPath -NoTypeInformation -Encoding UTF8
                }

                if ($allAlertRecords.Count -gt 0) {
                    $alertCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "Alerts.csv"
                    $allAlertRecords | Export-Csv -Path $alertCsvPath -NoTypeInformation -Encoding UTF8
                }

                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML Dashboard
        try {
            $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')

            $sessionInfo = @{
                Tenant      = $ctx.Tenant.Id
                Account     = $ctx.Account.Id
                Environment = $ctx.Environment.Name
            }

            $scanParams = @{
                Scope               = "$scopeText ($subCount found)"
                ResourceTypesFilter = $rtFilterText
                ExportEnabled       = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime            = $duration
            }

            $htmlContent = Generate-MonitoringAssessmentHtml `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParams `
                -Findings            $allFindings `
                -Workspaces          $allWorkspaces `
                -AlertRecords        $allAlertRecords `
                -SubscriptionResults $subscriptionResults `
                -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

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
            Where-Object { $_.IsCompliant -eq "No" } |
            Select-Object SubscriptionName, ResourceName, ResourceType, Area, Setting, CurrentValue, RiskLevel, RiskCategory |
            Sort-Object { switch ($_.RiskLevel) { "Critical" { 0 }; "High" { 1 }; "Medium" { 2 }; "Low" { 3 }; default { 4 } } } |
            Out-GridView -Title "Azure Monitoring Architecture Assessment — Non-Compliant Findings"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No resources found in the targeted subscriptions." -ForegroundColor Yellow
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
