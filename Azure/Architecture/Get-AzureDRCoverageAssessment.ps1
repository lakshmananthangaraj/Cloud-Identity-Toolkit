<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 19 August 2026
Modified-On     : 19 August 2026

.SYNOPSIS
    Assesses Azure Site Recovery (ASR) disaster recovery coverage across one or
    more subscriptions — evaluating Azure-to-Azure VM replication status,
    replication health, RPO compliance, test-failover currency, and recovery
    readiness — then producing a risk-rated findings report with business impact
    and actionable remediation guidance.

.DESCRIPTION
    Get-AzureDRCoverageAssessment evaluates the disaster recovery posture of
    Azure Virtual Machines across one or multiple subscriptions using Azure
    Site Recovery (ASR) Azure-to-Azure (A2A) replication.

    Assessment pipeline:

        Workload Discovery → Replication Status → Health Validation →
        RPO Compliance → Test Failover Currency → Risk Rating →
        Business Impact → Remediation

    v1.0 scope:
        - Azure Virtual Machines (IaaS) via Azure Site Recovery (A2A)
        - Recovery Services Vault ASR fabric and replication container enumeration
        - Per-VM replication item status, health, and RPO retrieval
        - Test failover date and staleness assessment
        - Configurable RPO thresholds and test failover age thresholds

    Out of scope (v1.0):
        - On-premises to Azure replication (VMware / Hyper-V / Physical)
        - Azure Front Door, Traffic Manager, Load Balancer, or DNS failover
        - Application-level or network-layer failover readiness
        - Azure NetApp Files or other specialized replication scenarios

    For each VM, the script determines:
        1. Configuration Existence   — Is ASR replication configured?
        2. Replication Status        — Is replication actively running?
        3. Operational Health        — Is replication healthy (no warnings/errors)?
        4. RPO Compliance            — Is the current RPO within defined thresholds?
        5. Test Failover Currency    — Has a test failover been run within the threshold?
        6. Business Risk             — What is the potential impact if this VM cannot be recovered?
        7. Remediation               — What action reduces the risk?

    Risk Severity Levels:
        Critical     — No DR protection for a critical/production VM, or severe
                       health failure that prevents recovery
        High         — DR configured but with significant gap (unhealthy replication,
                       RPO breach, never tested)
        Medium       — Governance weakness (stale test failover, missing tags)
        Low          — Minor configuration or optimization issue
        Informational— Observation with no direct resilience risk

    Business Impact Categories:
        Operational | Financial | Regulatory/Compliance | Customer | Reputational |
        Data Loss

    The script supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Configurable criticality and environment tag names
        - Configurable RPO thresholds and test failover staleness thresholds
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of all findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          donut charts, replication health panels, detail drawer with remediation)
        - Interactive Grid View where a GUI session is available

    Where RTO cannot be accurately calculated from ASR metadata, the script
    explicitly states this limitation rather than making assumptions.

    Where Azure APIs cannot provide sufficient evidence, the limitation is
    explicitly reported.

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all DR coverage findings to -CsvPath.
    The HTML dashboard is always generated regardless of this switch.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard filename (same path, .html extension).
    Default: C:\Temp\AzureDRCoverage-Report.csv

.PARAMETER CriticalityTagName
    Name of the Azure resource tag that indicates workload criticality.
    Accepted values: Critical, High, Medium, Low (case-insensitive).
    Default: Criticality

.PARAMETER EnvironmentTagName
    Name of the Azure resource tag that indicates the workload environment.
    Values matching ProductionTagValues are treated as production workloads.
    Default: Environment

.PARAMETER ProductionTagValues
    Comma-separated list of tag values that identify a production environment.
    Default: Production, Prod, PRD, PROD

.PARAMETER MaxAllowedRPOMinutes
    RPO (Recovery Point Objective) breach threshold in minutes.
    Current RPO above this value is rated High. Default: 60

.PARAMETER CriticalRPOMultiplier
    If the current RPO exceeds MaxAllowedRPOMinutes by this multiplier or more,
    the finding is escalated to Critical. Default: 4
    Example: if MaxAllowedRPOMinutes=60 and CriticalRPOMultiplier=4,
    RPO > 240 minutes is Critical.

.PARAMETER MaxTestFailoverAgeDays
    A test failover older than this many days is considered stale.
    A VM that has never had a test failover is always flagged. Default: 90

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureDRCoverageAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureDRCoverageAssessment -AllSubscriptions -ExportToCsv

.EXAMPLE
    Get-AzureDRCoverageAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureDRCoverageAssessment -AllSubscriptions -ExportToCsv `
        -CsvPath "C:\Reports\DRCoverage.csv" `
        -MaxAllowedRPOMinutes 30 `
        -MaxTestFailoverAgeDays 60

.EXAMPLE
    Get-AzureDRCoverageAssessment -AllSubscriptions `
        -CriticalityTagName "AppCriticality" `
        -EnvironmentTagName "Env" `
        -ProductionTagValues "Prod","Production","Live"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (19-Aug-2026) - Initial release. Azure VM Azure-to-Azure (A2A) ASR
                            replication coverage assessment. Replication health,
                            RPO compliance, and test failover currency checks.
                            Risk model with severity and business impact.
                            CSV export and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Execution Flow:
    ─────────────────────────────────────────────────────────────────────────────
        1.  Module check / optional install (Az.Accounts, Az.RecoveryServices,
            Az.Resources)
        2.  Authentication validation (Get-AzContext)
        3.  Subscription enumeration (All or specified list)
        4.  Per-subscription loop:
            a.  Discover all Azure VMs
            b.  Enumerate Recovery Services Vaults enabled for ASR
            c.  Enumerate ASR fabrics, protection containers, and replication items
            d.  Match each VM against replication items
            e.  For replicated VMs: retrieve replication health, RPO, target region
            f.  For replicated VMs: retrieve last test failover date
            g.  Apply risk severity model (deterministic, explainable rules)
            h.  Assign business impact category and level
            i.  Generate remediation recommendation
            j.  Accumulate findings
        5.  Console summary output
        6.  CSV export (if -ExportToCsv)
        7.  HTML dashboard generation (always)
        8.  Grid View (if GUI available)

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1.  Az PowerShell module (Az.Accounts, Az.RecoveryServices, Az.Resources)
            — installed automatically with user consent if absent.
        2.  Authenticated Azure session (Connect-AzAccount).
        3.  Reader role (minimum) at the subscription level.
        4.  Microsoft.RecoveryServices/vaults/read and
            Microsoft.RecoveryServices/vaults/replicationFabrics/read and
            Microsoft.RecoveryServices/vaults/replicationProtectionItems/read
            for ASR item enumeration.
        5.  Microsoft.Compute/virtualMachines/read for VM discovery.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Only Azure-to-Azure (A2A) replication is assessed in v1.0. VMware,
          Hyper-V, and physical server replication scenarios are not covered.
        - RTO (Recovery Time Objective) cannot be accurately calculated from
          ASR metadata alone. RTO is treated as a declared business requirement,
          not a computed value. The script reports this limitation explicitly.
        - Application-level, network, DNS, and traffic-routing failover readiness
          are outside the current assessment scope. A complete DR review should
          also assess Azure Front Door, Traffic Manager, Load Balancer, and
          application-layer failover.
        - ASR replication item RPO is reported as the last known value from the
          API; there may be a brief lag between actual replication state and the
          API-reported value.
        - Interactive Grid View requires a GUI-capable session; skipped
          gracefully in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific; supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - VMs in a deallocated state may still have replication configured;
          the script reports the replication status as returned by ASR, which
          may differ from expected behaviour for stopped VMs.

.LINK
    https://learn.microsoft.com/en-us/azure/site-recovery/azure-to-azure-tutorial-enable-replication
    https://learn.microsoft.com/en-us/azure/site-recovery/site-recovery-overview
    https://learn.microsoft.com/en-us/powershell/module/az.recoveryservices/get-azrecoveryservicesasrreplicationprotecteditem
    https://learn.microsoft.com/en-us/azure/site-recovery/concepts-azure-to-azure-architecture
    https://learn.microsoft.com/en-us/azure/site-recovery/site-recovery-test-failover-to-azure

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
    Write-CenteredText "Azure DR Coverage Assessment v1.0" -Color White
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
        Write-Host $key.PadRight(34) -NoNewline -ForegroundColor Gray
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

Function Write-DRSummary {
    param([hashtable]$Data)
    Write-Host ""
    Write-Host "  Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($key in $Data.Keys) {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(40) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-RiskBreakdown {
    param([hashtable]$RiskDist)
    if ($RiskDist.Count -eq 0) { return }
    Write-Host ""
    Write-Host "  Risk Severity Breakdown" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    $colorMap = @{
        "Critical"      = "Red"
        "High"          = "Yellow"
        "Medium"        = "Cyan"
        "Low"           = "Green"
        "Informational" = "Gray"
        "Healthy"       = "Green"
    }
    foreach ($r in ($RiskDist.GetEnumerator() | Sort-Object { @("Critical", "High", "Medium", "Low", "Informational", "Healthy").IndexOf($_.Key) })) {
        $color = if ($colorMap.ContainsKey($r.Key)) { $colorMap[$r.Key] } else { "White" }
        Write-Host "  " -NoNewline
        Write-Host $r.Key.PadRight(22) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($r.Value) VM(s)" -ForegroundColor $color
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
    param([object]$Obj, [string]$PropName, $Default = $null)
    try {
        $val = $Obj.$PropName
        if ($null -ne $val) { return $val }
        return $Default
    }
    catch { return $Default }
}


#------------------------------------------------------------------------ [ Risk Rating Engine ]

Function Get-WorkloadCriticality {
    param(
        [hashtable]$Tags,
        [string]$CritTagName,
        [string]$EnvTagName,
        [string[]]$ProdTagValues
    )

    $criticality = "Unknown"
    $environment = "Unknown"

    if ($Tags -and $Tags.ContainsKey($CritTagName)) {
        $tagVal = $Tags[$CritTagName]
        $criticality = switch -Wildcard ($tagVal.ToLower()) {
            "critical" { "Critical" }
            "high" { "High" }
            "medium" { "Medium" }
            "low" { "Low" }
            default { "Unknown" }
        }
    }

    if ($Tags -and $Tags.ContainsKey($EnvTagName)) {
        $envVal = $Tags[$EnvTagName]
        $isProd = $ProdTagValues | Where-Object { $_ -ieq $envVal }
        $environment = if ($isProd) { "Production" } else { "Non-Production" }
    }

    return @{ Criticality = $criticality; Environment = $environment }
}

Function Get-DRRiskSeverity {
    param(
        [string]$VMCriticality,
        [string]$VMEnvironment,
        [bool]$IsReplicated,
        [bool]$IsHealthy,
        [string]$HealthIssueReason,
        [string]$ReplicationStatus,
        [long]$CurrentRPOMinutes,
        [int]$MaxRPOMinutes,
        [int]$CriticalRPOMultiplier,
        [bool]$TestFailoverEverRun,
        [int]$TestFailoverAgeDays,
        [int]$MaxTestFailoverAgeDays
    )

    $isCritOrProd = ($VMCriticality -in @("Critical", "High") -or $VMEnvironment -eq "Production")
    $critRPOThreshold = $MaxRPOMinutes * $CriticalRPOMultiplier

    # Rule 1: No ASR replication configured
    if (-not $IsReplicated) {
        if ($isCritOrProd) {
            return @{
                Severity     = "Critical"
                RiskCategory = "No DR Protection"
                Reason       = "VM has no Azure Site Recovery replication configured."
                WhyItMatters = "A $VMCriticality/$VMEnvironment VM with no ASR replication has no automated recovery path in the event of a regional Azure outage or catastrophic failure. Manual recovery would require significant time, potentially violating RTO commitments."
                Impact       = @{ Category = "Operational"; Level = "Critical" }
                Action       = "Enable Azure Site Recovery replication for this VM. Configure A2A replication to a paired or selected target region. Define RPO targets and test failover procedures before enabling replication in production."
            }
        }
        elseif ($VMCriticality -eq "Unknown") {
            return @{
                Severity     = "High"
                RiskCategory = "No DR Protection"
                Reason       = "VM has no ASR replication and criticality is unknown (tag missing)."
                WhyItMatters = "Without a criticality tag, the business impact of losing this VM cannot be determined. An untagged VM with no DR protection represents unquantified risk that should be resolved before a DR event occurs."
                Impact       = @{ Category = "Operational"; Level = "High" }
                Action       = "Apply a '$CritTagName' criticality tag to classify this VM, then evaluate whether ASR replication is required. Document a formal exclusion decision if DR is not warranted."
            }
        }
        else {
            return @{
                Severity     = "Medium"
                RiskCategory = "No DR Protection"
                Reason       = "VM has no ASR replication configured."
                WhyItMatters = "Even lower-criticality workloads benefit from a documented DR position. An undocumented absence of DR protection is a governance gap."
                Impact       = @{ Category = "Operational"; Level = "Medium" }
                Action       = "Either enable ASR replication or document a formal exclusion decision with the workload owner confirming acceptable recovery objectives for this VM."
            }
        }
    }

    # Rule 2: Replication is configured but in a non-active/failed state
    if (-not $IsHealthy -or $ReplicationStatus -in @("FailoverCommitted", "Failover", "FailedOver", "DisabledProtection", "SwitchProtectionCommitted")) {
        $severity = if ($isCritOrProd) { "Critical" } else { "High" }
        $reason = if ($HealthIssueReason) { $HealthIssueReason } else { "Replication status: $ReplicationStatus" }
        return @{
            Severity     = $severity
            RiskCategory = "Replication Unhealthy"
            Reason       = "ASR replication is configured but not healthy: $reason"
            WhyItMatters = "An unhealthy or non-active replication state means the VM cannot be recovered to the target region in the event of a disaster. Despite appearing covered, the VM is effectively unprotected."
            Impact       = @{ Category = "Data Loss"; Level = $severity }
            Action       = "Investigate the ASR replication health issue immediately. Open the Recovery Services Vault in the Azure Portal, navigate to Site Recovery → Replicated Items, and review the health warnings and errors for this VM. Resolve blocking issues and confirm replication resumes to a healthy state."
        }
    }

    # Rule 3: RPO breach — Critical
    if ($CurrentRPOMinutes -ge 0 -and $CurrentRPOMinutes -gt $critRPOThreshold) {
        $severity = if ($isCritOrProd) { "Critical" } else { "High" }
        return @{
            Severity     = $severity
            RiskCategory = "RPO Breach — Critical"
            Reason       = "Current RPO is $CurrentRPOMinutes minute(s), exceeding the critical threshold of $critRPOThreshold minute(s) (${MaxRPOMinutes}min × ${CriticalRPOMultiplier}x)."
            WhyItMatters = "An RPO this far beyond the defined baseline indicates that replication is significantly lagging. In a disaster scenario, the amount of data loss would greatly exceed the organisation's stated recovery objectives."
            Impact       = @{ Category = "Data Loss"; Level = $severity }
            Action       = "Immediately investigate why ASR replication lag has reached this level. Check network bandwidth between source and target regions, review ASR agent health, and verify that no large writes or throttling events are affecting the replication stream."
        }
    }

    # Rule 4: RPO breach — High
    if ($CurrentRPOMinutes -ge 0 -and $CurrentRPOMinutes -gt $MaxRPOMinutes) {
        return @{
            Severity     = "High"
            RiskCategory = "RPO Breach"
            Reason       = "Current RPO is $CurrentRPOMinutes minute(s), exceeding the defined maximum of $MaxRPOMinutes minute(s)."
            WhyItMatters = "The replication lag is beyond the acceptable RPO threshold. A failure now would result in more data loss than the organisation's stated recovery objectives permit."
            Impact       = @{ Category = "Data Loss"; Level = "High" }
            Action       = "Review ASR replication performance for this VM. Check for network congestion, high write rates, or misconfigured churn thresholds. Consider adjusting replication frequency or network bandwidth allocation."
        }
    }

    # Rule 5: Test failover never performed
    if (-not $TestFailoverEverRun) {
        $severity = if ($isCritOrProd) { "High" } else { "Medium" }
        return @{
            Severity     = $severity
            RiskCategory = "Test Failover Never Performed"
            Reason       = "No test failover has ever been performed for this VM."
            WhyItMatters = "Replication configuration alone does not prove recoverability. Without a test failover, the organisation cannot confirm that the VM would start correctly in the target region, that network configuration is correct, or that application dependencies are satisfied. Discovering failover issues during an actual disaster has severe business consequences."
            Impact       = @{ Category = "Operational"; Level = $severity }
            Action       = "Schedule and perform a test failover as soon as possible. Test failovers can be executed without interrupting production replication. Document the test outcome and remediate any issues found. Establish a recurring test failover schedule (minimum every $MaxTestFailoverAgeDays days)."
        }
    }

    # Rule 6: Test failover is stale
    if ($TestFailoverAgeDays -ge $MaxTestFailoverAgeDays) {
        $severity = if ($isCritOrProd) { "High" } else { "Medium" }
        return @{
            Severity     = $severity
            RiskCategory = "Test Failover Stale"
            Reason       = "Last test failover was $TestFailoverAgeDays day(s) ago, exceeding the maximum of $MaxTestFailoverAgeDays day(s)."
            WhyItMatters = "Infrastructure changes (network, security groups, target region resources) may have occurred since the last test, potentially causing a real failover to fail. Stale test results cannot be relied upon to confirm recoverability."
            Impact       = @{ Category = "Operational"; Level = $severity }
            Action       = "Perform a new test failover and clean up the test environment afterwards. Update runbooks and DR documentation to reflect the current configuration. Establish a regular test failover cadence."
        }
    }

    # Rule 7: All checks pass
    return @{
        Severity     = "Healthy"
        RiskCategory = "Healthy"
        Reason       = "ASR replication is active, healthy, RPO is within threshold, and test failover is current."
        WhyItMatters = "No immediate action required. Continue monitoring replication health and maintain the test failover schedule."
        Impact       = @{ Category = "None"; Level = "None" }
        Action       = "No remediation required. Maintain the test failover schedule (every $MaxTestFailoverAgeDays days). Review replication health regularly via Azure Monitor or the Recovery Services Vault."
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-DRCoverageHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$ASRVaults,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [hashtable]$RiskDistribution,
        [hashtable]$ReplicationHealthDist,
        [hashtable]$RPODistribution
    )

    $totalVMs = @($Findings).Count
    $replicatedCount = @($Findings | Where-Object { $_.IsReplicated }).Count
    $unreplicatedCount = @($Findings | Where-Object { -not $_.IsReplicated }).Count
    $criticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $healthyCount = @($Findings | Where-Object { $_.Severity -eq "Healthy" }).Count
    $neverTestedCount = @($Findings | Where-Object { $_.IsReplicated -and -not $_.TestFailoverEverRun }).Count
    $staleTestCount = @($Findings | Where-Object { $_.IsReplicated -and $_.TestFailoverEverRun -and $_.TestFailoverAgeDays -ge $ScanParameters.MaxTestFailoverAgeDays }).Count
    $vaultCount = @($ASRVaults).Count

    $coveragePct = if ($totalVMs -gt 0) { [math]::Round(($replicatedCount / $totalVMs) * 100) } else { 0 }

    # ── Risk donut ────────────────────────────────────────────────────────────
    $riskOrder = @("Critical", "High", "Medium", "Low", "Informational", "Healthy")
    $riskColors = @{
        "Critical"      = "#f85149"
        "High"          = "#d29922"
        "Medium"        = "#39c5cf"
        "Low"           = "#3fb950"
        "Informational" = "#7d8590"
        "Healthy"       = "#3fb950"
    }

    $circumference = 2 * [math]::PI * 54
    $donutTotal = if ($totalVMs -gt 0) { $totalVMs } else { 1 }
    $donutSegments = ""
    $legendItems = ""
    $offset = 0

    foreach ($level in $riskOrder) {
        $cnt = if ($RiskDistribution.ContainsKey($level)) { $RiskDistribution[$level] } else { 0 }
        if ($cnt -eq 0) { continue }
        $pct = $cnt / $donutTotal
        $dash = [math]::Round($circumference * $pct, 2)
        $gap = [math]::Round($circumference - $dash, 2)
        $color = $riskColors[$level]
        $donutSegments += "<circle cx='64' cy='64' r='54' fill='none' stroke='$color' stroke-width='20' stroke-dasharray='$dash $gap' stroke-dashoffset='-$offset' transform='rotate(-90 64 64)'/>`n"
        $offset += $dash
        $legendItems += "<div class='legend-item'><div class='legend-dot' style='background:$color'></div><span style='flex:1'>$level</span><strong>$cnt</strong></div>`n"
    }

    # ── Replication health bar rows ───────────────────────────────────────────
    $healthTotal = ($ReplicationHealthDist.Values | Measure-Object -Sum).Sum
    if ($healthTotal -eq 0) { $healthTotal = 1 }
    $healthColors = @{
        "Normal"        = "var(--green)"
        "Warning"       = "var(--amber)"
        "Critical"      = "var(--red)"
        "NotReplicated" = "var(--muted)"
    }
    $healthRows = ""
    foreach ($h in ($ReplicationHealthDist.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = [math]::Round(($h.Value / $healthTotal) * 100)
        $color = if ($healthColors.ContainsKey($h.Key)) { $healthColors[$h.Key] } else { "var(--muted)" }
        $healthRows += "<div class='bar-row'><span class='bar-label'>$(EscHtml $h.Key)</span><div class='bar-track'><div class='bar-fill' data-pct='$pct' style='background:$color'></div></div><span class='bar-pct'>$($h.Value) ($pct%)</span></div>`n"
    }

    # ── RPO distribution bar rows ─────────────────────────────────────────────
    $rpoTotal = ($RPODistribution.Values | Measure-Object -Sum).Sum
    if ($rpoTotal -eq 0) { $rpoTotal = 1 }
    $rpoColors = @{
        "Within Threshold" = "var(--green)"
        "Exceeds High"     = "var(--amber)"
        "Exceeds Critical" = "var(--red)"
        "Not Available"    = "var(--muted)"
    }
    $rpoRows = ""
    foreach ($rpo in @("Within Threshold", "Exceeds High", "Exceeds Critical", "Not Available")) {
        $cnt = if ($RPODistribution.ContainsKey($rpo)) { $RPODistribution[$rpo] } else { 0 }
        $pct = [math]::Round(($cnt / $rpoTotal) * 100)
        $col = if ($rpoColors.ContainsKey($rpo)) { $rpoColors[$rpo] } else { "var(--muted)" }
        $rpoRows += "<div class='bar-row'><span class='bar-label'>$(EscHtml $rpo)</span><div class='bar-track'><div class='bar-fill' data-pct='$pct' style='background:$col'></div></div><span class='bar-pct'>$cnt ($pct%)</span></div>`n"
    }

    # ── All findings table rows ───────────────────────────────────────────────
    $findingRows = ""
    $idx = 0
    foreach ($f in $Findings) {
        $sevCls = switch ($f.Severity) {
            "Critical" { "badge-red" }
            "High" { "badge-amber" }
            "Medium" { "badge-blue" }
            "Low" { "badge-green" }
            "Healthy" { "badge-green" }
            "Informational" { "" }
            default { "" }
        }
        $repBadge = if ($f.IsReplicated) { '<span class="badge badge-green">✓ Replicated</span>' } else { '<span class="badge badge-red">✗ Not Replicated</span>' }
        $tfBadge = if (-not $f.IsReplicated) { '<span class="badge" style="background:var(--surface3);color:var(--muted)">—</span>' }
        elseif (-not $f.TestFailoverEverRun) { '<span class="badge badge-red">Never</span>' }
        elseif ($f.TestFailoverAgeDays -ge $ScanParameters.MaxTestFailoverAgeDays) { '<span class="badge badge-amber">Stale</span>' }
        else { '<span class="badge badge-green">Current</span>' }
        $rpoBadge = if (-not $f.IsReplicated -or $f.CurrentRPOMinutes -lt 0) { '<span class="badge" style="background:var(--surface3);color:var(--muted)">N/A</span>' }
        elseif ($f.CurrentRPOMinutes -gt ($ScanParameters.MaxRPOMinutes * $ScanParameters.CritRPOMultiplier)) { "<span class='badge badge-red'>$($f.CurrentRPOMinutes)m</span>" }
        elseif ($f.CurrentRPOMinutes -gt $ScanParameters.MaxRPOMinutes) { "<span class='badge badge-amber'>$($f.CurrentRPOMinutes)m</span>" }
        else { "<span class='badge badge-green'>$($f.CurrentRPOMinutes)m</span>" }
        $critBadge = switch ($f.VMCriticality) {
            "Critical" { '<span class="badge badge-red">Critical</span>' }
            "High" { '<span class="badge badge-amber">High</span>' }
            "Medium" { '<span class="badge badge-blue">Medium</span>' }
            "Low" { '<span class="badge badge-green">Low</span>' }
            default { '<span class="badge" style="background:var(--surface3);color:var(--muted)">Unknown</span>' }
        }
        $nameShort = if ($f.VMName.Length -gt 30) { $f.VMName.Substring(0, 27) + "..." } else { $f.VMName }
        $findingRows += @"
          <tr onclick="showFindingDetail($idx)">
            <td title="$(EscHtml $f.VMName)">$(EscHtml $nameShort)</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$(EscHtml $f.ResourceGroup)</td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td>$repBadge</td>
            <td>$rpoBadge</td>
            <td>$tfBadge</td>
            <td>$critBadge</td>
          </tr>
"@
        $idx++
    }

    # ── Unprotected VMs table rows ────────────────────────────────────────────
    $unprotectedRows = ""
    foreach ($u in @($Findings | Where-Object { -not $_.IsReplicated })) {
        $critBadge = switch ($u.VMCriticality) {
            "Critical" { '<span class="badge badge-red">Critical</span>' }
            "High" { '<span class="badge badge-amber">High</span>' }
            "Medium" { '<span class="badge badge-blue">Medium</span>' }
            "Low" { '<span class="badge badge-green">Low</span>' }
            default { '<span class="badge" style="background:var(--surface3);color:var(--muted)">Unknown</span>' }
        }
        $unprotectedRows += @"
          <tr>
            <td>$(EscHtml $u.VMName)</td>
            <td>$(EscHtml $u.SubscriptionName)</td>
            <td>$(EscHtml $u.ResourceGroup)</td>
            <td>$(EscHtml $u.Location)</td>
            <td>$critBadge</td>
            <td>$(EscHtml $u.VMEnvironment)</td>
            <td style="font-size:11px;color:var(--muted2)">$(EscHtml $u.RemediationAction)</td>
          </tr>
"@
    }

    # ── Replication health table rows ─────────────────────────────────────────
    $replicationRows = ""
    foreach ($r in @($Findings | Where-Object { $_.IsReplicated })) {
        $healthCls = switch ($r.ReplicationHealth) {
            "Normal" { "badge-green" }
            "Warning" { "badge-amber" }
            "Critical" { "badge-red" }
            default { "" }
        }
        $rpoDisplay = if ($r.CurrentRPOMinutes -lt 0) { "N/A" } else { "$($r.CurrentRPOMinutes)m" }
        $replicationRows += @"
          <tr>
            <td>$(EscHtml $r.VMName)</td>
            <td>$(EscHtml $r.SubscriptionName)</td>
            <td>$(EscHtml $r.TargetRegion)</td>
            <td>$(EscHtml $r.ASRVaultName)</td>
            <td><span class="badge $healthCls">$(EscHtml $r.ReplicationHealth)</span></td>
            <td style="font-family:var(--mono)">$(EscHtml $rpoDisplay)</td>
            <td>$(EscHtml $r.ReplicationStatus)</td>
          </tr>
"@
    }

    # ── Test Failover table rows ──────────────────────────────────────────────
    $testFailoverRows = ""
    foreach ($t in @($Findings | Where-Object { $_.IsReplicated })) {
        $tfStatus = if (-not $t.TestFailoverEverRun) { "Never Performed" }
        elseif ($t.TestFailoverAgeDays -ge $ScanParameters.MaxTestFailoverAgeDays) { "Stale ($($t.TestFailoverAgeDays) days ago)" }
        else { "Current ($($t.TestFailoverAgeDays) days ago)" }
        $tfCls = if (-not $t.TestFailoverEverRun) { "badge-red" }
        elseif ($t.TestFailoverAgeDays -ge $ScanParameters.MaxTestFailoverAgeDays) { "badge-amber" }
        else { "badge-green" }
        $testFailoverRows += @"
          <tr>
            <td>$(EscHtml $t.VMName)</td>
            <td>$(EscHtml $t.SubscriptionName)</td>
            <td>$(EscHtml $t.ASRVaultName)</td>
            <td>$(EscHtml $t.TargetRegion)</td>
            <td style="font-family:var(--mono);font-size:11px">$(EscHtml $t.LastTestFailoverDate)</td>
            <td><span class="badge $tfCls">$(EscHtml $tfStatus)</span></td>
          </tr>
"@
    }

    # ── Vault rows ────────────────────────────────────────────────────────────
    $vaultRows = ""
    foreach ($v in $ASRVaults) {
        $vaultRows += @"
          <tr>
            <td>$(EscHtml $v.VaultName)</td>
            <td>$(EscHtml $v.SubscriptionName)</td>
            <td>$(EscHtml $v.ResourceGroup)</td>
            <td>$(EscHtml $v.Location)</td>
            <td>$($v.ReplicatedItemCount)</td>
          </tr>
"@
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

    # ── JSON for findings detail drawer ───────────────────────────────────────
    $findingsJson = "["
    foreach ($f in $Findings) {
        $findingsJson += "{" +
        """id"":""$(EscJ $f.VMId)""," +
        """name"":""$(EscJ $f.VMName)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """location"":""$(EscJ $f.Location)""," +
        """severity"":""$(EscJ $f.Severity)""," +
        """riskCategory"":""$(EscJ $f.RiskCategory)""," +
        """replicated"":$(if ($f.IsReplicated) { 'true' } else { 'false' })," +
        """healthy"":$(if ($f.ReplicationHealth -eq 'Normal') { 'true' } else { 'false' })," +
        """criticality"":""$(EscJ $f.VMCriticality)""," +
        """environment"":""$(EscJ $f.VMEnvironment)""," +
        """vault"":""$(EscJ $f.ASRVaultName)""," +
        """targetRegion"":""$(EscJ $f.TargetRegion)""," +
        """sourceRegion"":""$(EscJ $f.Location)""," +
        """replicationStatus"":""$(EscJ $f.ReplicationStatus)""," +
        """replicationHealth"":""$(EscJ $f.ReplicationHealth)""," +
        """healthErrors"":""$(EscJ $f.ReplicationHealthErrors)""," +
        """rpoMinutes"":$($f.CurrentRPOMinutes)," +
        """testFailoverEverRun"":$(if ($f.TestFailoverEverRun) { 'true' } else { 'false' })," +
        """testFailoverDate"":""$(EscJ $f.LastTestFailoverDate)""," +
        """testFailoverAgeDays"":$($f.TestFailoverAgeDays)," +
        """reason"":""$(EscJ $f.RiskReason)""," +
        """whyMatters"":""$(EscJ $f.WhyItMatters)""," +
        """impactCategory"":""$(EscJ $f.ImpactCategory)""," +
        """impactLevel"":""$(EscJ $f.ImpactLevel)""," +
        """action"":""$(EscJ $f.RemediationAction)""" +
        "},"
    }
    $findingsJson = $findingsJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure DR Coverage Assessment</title>
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
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,var(--accent2),var(--accent3));display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
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
.bar-label{font-size:12px;color:var(--muted2);width:150px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
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
.coverage-ring{width:160px;height:160px;flex-shrink:0;}
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
.scope-note{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.3);color:var(--amber);padding:12px 16px;border-radius:var(--radius-sm);font-size:12px;margin-bottom:16px;}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:500px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
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
.remediation-box{background:rgba(56,139,253,.08);border:1px solid rgba(56,139,253,.3);border-radius:var(--radius-sm);padding:12px 14px;font-size:12px;line-height:1.6;color:var(--text);}
.impact-row{display:flex;gap:12px;flex-wrap:wrap;}
.impact-chip{padding:4px 10px;border-radius:20px;font-size:11px;font-weight:600;background:var(--surface3);border:1px solid var(--border);}
.rto-note{background:rgba(163,113,247,.08);border:1px solid rgba(163,113,247,.3);border-radius:var(--radius-sm);padding:10px 14px;font-size:12px;color:var(--accent3);margin-top:10px;}
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
    <div class="logo-icon">🔁</div>
    <div class="logo-title">DR Coverage</div>
    <div class="logo-sub">Azure Site Recovery Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('replicated',this)"><span class="nav-icon">💻</span> Replicated Items</button>
    <button class="nav-btn" onclick="showPage('unprotected',this)"><span class="nav-icon">⚠️</span> Unprotected</button>
    <button class="nav-btn" onclick="showPage('rephealth',this)"><span class="nav-icon">❤️</span> Replication Health</button>
    <button class="nav-btn" onclick="showPage('testfailover',this)"><span class="nav-icon">🧪</span> Test Failover Status</button>
    <button class="nav-btn" onclick="showPage('scanresults',this)"><span class="nav-icon">🔍</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">Generated: __GENERATED_ON__<br/>Azure DR Coverage Assessment</div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">DR Coverage Overview</div>
      <div class="page-sub">Azure Site Recovery (A2A) posture across __SUB_COUNT__ subscription(s) — __TOTAL_VMS__ VMs assessed</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_VMS__</div>
        <div class="stat-label">Total VMs</div>
        <div class="stat-sub">Assessed for DR</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__REPLICATED_COUNT__</div>
        <div class="stat-label">Replicated</div>
        <div class="stat-sub">__COVERAGE_PCT__% coverage</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__UNREPLICATED_COUNT__</div>
        <div class="stat-label">Not Replicated</div>
        <div class="stat-sub">No ASR protection</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical Findings</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Findings</div>
        <div class="stat-sub">Significant DR gaps</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__NEVER_TESTED_COUNT__</div>
        <div class="stat-label">Never Tested</div>
        <div class="stat-sub">No test failover run</div>
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Risk Severity Distribution</div>
        <div class="donut-wrap">
          <svg class="coverage-ring" viewBox="0 0 128 128">
            <circle cx="64" cy="64" r="54" fill="none" stroke="var(--surface3)" stroke-width="20"/>
            __DONUT_SEGMENTS__
            <text x="64" y="60" text-anchor="middle" font-size="22" font-weight="700" fill="var(--text)" font-family="JetBrains Mono,monospace">__COVERAGE_PCT__%</text>
            <text x="64" y="76" text-anchor="middle" font-size="9" fill="var(--muted)" font-family="Calibri,Segoe UI,sans-serif">DR COVERAGE</text>
          </svg>
          <div class="legend-list">__LEGEND_ITEMS__</div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">❤️ Replication Health Distribution</div>
        __HEALTH_ROWS__
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">📡 RPO Status Distribution</div>
      __RPO_ROWS__
    </div>
  </div>

  <!-- Replicated Items -->
  <div id="page-replicated" class="page">
    <div class="page-header">
      <div class="page-title">Replicated Items</div>
      <div class="page-sub">All assessed VMs — click any row for full details, RPO status, and remediation guidance</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="vmSearch" placeholder="Search VM, subscription, resource group…" oninput="filterVMs()"/>
        </div>
        <select class="filter-select" id="filterSeverity" onchange="filterVMs()">
          <option value="">All Severity</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Healthy">Healthy</option>
        </select>
        <select class="filter-select" id="filterReplicated" onchange="filterVMs()">
          <option value="">All VMs</option>
          <option value="true">Replicated</option>
          <option value="false">Not Replicated</option>
        </select>
        <select class="filter-select" id="pgSizeVm" onchange="changeVmPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="vmTable">
          <thead>
            <tr>
              <th onclick="sortVMs(0)">VM Name</th>
              <th onclick="sortVMs(1)">Subscription</th>
              <th onclick="sortVMs(2)">Resource Group</th>
              <th onclick="sortVMs(3)">Severity</th>
              <th onclick="sortVMs(4)">Replication</th>
              <th onclick="sortVMs(5)">Current RPO</th>
              <th onclick="sortVMs(6)">Test Failover</th>
              <th onclick="sortVMs(7)">Criticality</th>
            </tr>
          </thead>
          <tbody id="vmBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="vmPagination"></div>
    </div>
  </div>

  <!-- Unprotected -->
  <div id="page-unprotected" class="page">
    <div class="page-header">
      <div class="page-title">Unprotected VMs</div>
      <div class="page-sub">__UNREPLICATED_COUNT__ VM(s) with no ASR replication — prioritise by criticality and environment</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>VM Name</th>
              <th>Subscription</th>
              <th>Resource Group</th>
              <th>Location</th>
              <th>Criticality</th>
              <th>Environment</th>
              <th>Recommended Action</th>
            </tr>
          </thead>
          <tbody>__UNPROTECTED_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Replication Health -->
  <div id="page-rephealth" class="page">
    <div class="page-header">
      <div class="page-title">Replication Health</div>
      <div class="page-sub">Per-VM replication status and health — warning and critical items require investigation</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>VM Name</th>
              <th>Subscription</th>
              <th>Target Region</th>
              <th>ASR Vault</th>
              <th>Health</th>
              <th>Current RPO</th>
              <th>Replication Status</th>
            </tr>
          </thead>
          <tbody>__REPLICATION_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Test Failover Status -->
  <div id="page-testfailover" class="page">
    <div class="page-header">
      <div class="page-title">Test Failover Status</div>
      <div class="page-sub">Replication configuration alone does not prove recoverability — test failovers must be performed and kept current</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>VM Name</th>
              <th>Subscription</th>
              <th>ASR Vault</th>
              <th>Target Region</th>
              <th>Last Test Failover</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>__TEST_FAILOVER_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-scanresults" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription DR assessment outcome</div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Subscriptions Scanned</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
    <div class="panel">
      <div class="panel-title">🏦 ASR-Enabled Recovery Services Vaults</div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Vault Name</th>
              <th>Subscription</th>
              <th>Resource Group</th>
              <th>Location</th>
              <th>Replicated Items</th>
            </tr>
          </thead>
          <tbody>__VAULT_ROWS__</tbody>
        </table>
      </div>
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
        <div class="info-card"><div class="info-label">Criticality Tag</div><div class="info-value">__CRIT_TAG__</div></div>
        <div class="info-card"><div class="info-label">Environment Tag</div><div class="info-value">__ENV_TAG__</div></div>
        <div class="info-card"><div class="info-label">Production Values</div><div class="info-value">__PROD_VALS__</div></div>
        <div class="info-card"><div class="info-label">Max RPO (High)</div><div class="info-value">__MAX_RPO__ min</div></div>
        <div class="info-card"><div class="info-label">Critical RPO Multiplier</div><div class="info-value">__CRIT_RPO_MULT__x (≥__CRIT_RPO_THRESH__ min)</div></div>
        <div class="info-card"><div class="info-label">Max Test Failover Age</div><div class="info-value">__MAX_TF_AGE__ days</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">⚠️ Assessment Scope &amp; RTO Note</div>
      <div class="scope-note">
        <strong>Scope (v1.0):</strong> This assessment covers Azure Virtual Machines using Azure Site Recovery (A2A) replication only.
        VMware, Hyper-V, and physical server replication are not assessed.<br/><br/>
        <strong>RTO Note:</strong> Recovery Time Objective (RTO) cannot be accurately calculated from ASR metadata alone.
        RTO depends on VM size, disk count, target region resource availability, application startup time, and failover orchestration.
        RTO should be treated as a declared business requirement and validated through test failovers, not estimated from replication configuration.<br/><br/>
        <strong>Out of Scope:</strong> Azure Front Door, Traffic Manager, Load Balancer, DNS failover, and application-layer failover
        are not assessed here. A complete DR review should also cover network, DNS, and application-layer recoverability.
        Run <strong>Get-AzureBackupCoverageAssessment</strong> to complement this assessment with backup coverage.
      </div>
    </div>
  </div>
</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">VM DR Detail</span>
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
let vmFiltered = [...FINDINGS_DATA];
let vmPage = 1, vmPageSz = 25;
let vmSortCol = -1, vmSortAsc = true;
let currentDetailIdx = 0;
const MAX_RPO = __MAX_RPO_JS__;
const CRIT_RPO_MULT = __CRIT_RPO_MULT_JS__;
const MAX_TF_AGE = __MAX_TF_AGE_JS__;

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

// ── VMs table ─────────────────────────────────────────────────────────────────
function filterVMs(){
  const q=document.getElementById('vmSearch').value.toLowerCase();
  const sv=document.getElementById('filterSeverity').value;
  const rp=document.getElementById('filterReplicated').value;
  vmFiltered=FINDINGS_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mS=!sv||r.severity===sv;
    const mR=!rp||(rp==='true'?r.replicated:!r.replicated);
    return mQ&&mS&&mR;
  });
  vmPage=1; renderVMs();
}
function changeVmPageSize(){
  vmPageSz=parseInt(document.getElementById('pgSizeVm').value);
  vmPage=1; renderVMs();
}
function sortVMs(col){
  if(vmSortCol===col){vmSortAsc=!vmSortAsc;}else{vmSortCol=col;vmSortAsc=true;}
  const keys=['name','sub','rg','severity','replicated','rpoMinutes','testFailoverEverRun','criticality'];
  vmFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'',bv=b[k]??'';
    return vmSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                    :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderVMs();
}
function renderVMs(){
  const tbody=document.getElementById('vmBody');
  const start=(vmPage-1)*vmPageSz;
  const slice=vmFiltered.slice(start,start+vmPageSz);
  const sevCls={'Critical':'badge-red','High':'badge-amber','Medium':'badge-blue','Low':'badge-green','Healthy':'badge-green','Informational':''};
  const critCls={'Critical':'badge-red','High':'badge-amber','Medium':'badge-blue','Low':'badge-green'};
  tbody.innerHTML=slice.map(r=>{
    const gi=FINDINGS_DATA.indexOf(r);
    const sc=sevCls[r.severity]||'';
    const cc=critCls[r.criticality]||'';
    const repBadge=r.replicated?'<span class="badge badge-green">✓ Replicated</span>':'<span class="badge badge-red">✗ Not Replicated</span>';
    const rpoBadge=!r.replicated||r.rpoMinutes<0?'<span class="badge" style="background:var(--surface3);color:var(--muted)">N/A</span>':
      r.rpoMinutes>(MAX_RPO*CRIT_RPO_MULT)?`<span class="badge badge-red">${r.rpoMinutes}m</span>`:
      r.rpoMinutes>MAX_RPO?`<span class="badge badge-amber">${r.rpoMinutes}m</span>`:
      `<span class="badge badge-green">${r.rpoMinutes}m</span>`;
    const tfBadge=!r.replicated?'<span class="badge" style="background:var(--surface3);color:var(--muted)">—</span>':
      !r.testFailoverEverRun?'<span class="badge badge-red">Never</span>':
      r.testFailoverAgeDays>=MAX_TF_AGE?'<span class="badge badge-amber">Stale</span>':
      '<span class="badge badge-green">Current</span>';
    const critBadge=cc?`<span class="badge ${cc}">${escH(r.criticality)}</span>`:`<span class="badge" style="background:var(--surface3);color:var(--muted)">${escH(r.criticality)}</span>`;
    const nm=r.name.length>30?r.name.substring(0,27)+'...':r.name;
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td>${escH(r.rg)}</td>
      <td><span class="badge ${sc}">${escH(r.severity)}</span></td>
      <td>${repBadge}</td>
      <td>${rpoBadge}</td>
      <td>${tfBadge}</td>
      <td>${critBadge}</td>
    </tr>`;
  }).join('');
  renderVMPg();
}
function renderVMPg(){
  const total=Math.ceil(vmFiltered.length/vmPageSz);
  const el=document.getElementById('vmPagination');
  let h=`<span>${vmFiltered.length} VMs</span>`;
  h+=`<button class="pg-btn" onclick="changeVmPage(${vmPage-1})" ${vmPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,vmPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===vmPage?'active':''}" onclick="changeVmPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeVmPage(${vmPage+1})" ${vmPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}
function changeVmPage(p){
  const total=Math.ceil(vmFiltered.length/vmPageSz);
  if(p<1||p>total)return;
  vmPage=p; renderVMs();
}

// ── Detail drawer ─────────────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=FINDINGS_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FINDINGS_DATA.length}`;
  const sevCls={'Critical':'badge-red','High':'badge-amber','Medium':'badge-blue','Low':'badge-green','Healthy':'badge-green'};
  const sc=sevCls[r.severity]||'';
  const repBadge=r.replicated?'<span class="badge badge-green">✓ Replicated</span>':'<span class="badge badge-red">✗ Not Replicated</span>';
  const healthBadge=r.healthy?'<span class="badge badge-green">✓ Normal</span>':'<span class="badge badge-red">⚠ Unhealthy</span>';
  const rpoBadge=!r.replicated||r.rpoMinutes<0?'<span class="badge" style="background:var(--surface3);color:var(--muted)">N/A</span>':
    r.rpoMinutes>(MAX_RPO*CRIT_RPO_MULT)?`<span class="badge badge-red">${r.rpoMinutes} min (Critical)</span>`:
    r.rpoMinutes>MAX_RPO?`<span class="badge badge-amber">${r.rpoMinutes} min (Exceeds threshold)</span>`:
    `<span class="badge badge-green">${r.rpoMinutes} min (Within threshold)</span>`;
  const tfBadge=!r.replicated?'<span class="badge" style="background:var(--surface3);color:var(--muted)">N/A</span>':
    !r.testFailoverEverRun?'<span class="badge badge-red">Never Performed</span>':
    r.testFailoverAgeDays>=MAX_TF_AGE?`<span class="badge badge-amber">Stale — ${r.testFailoverAgeDays} days ago</span>`:
    `<span class="badge badge-green">Current — ${r.testFailoverAgeDays} days ago</span>`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sc}">${escH(r.severity)}</span>&nbsp;<span style="font-size:12px;color:var(--muted)">${escH(r.riskCategory)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Source Location</div>
      <div class="drawer-field-value">${escH(r.location)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Criticality / Environment</div>
      <div class="drawer-field-value">${escH(r.criticality)} / ${escH(r.environment)}</div></div>
    <div class="drawer-section">Replication Status</div>
    <div class="drawer-field"><div class="drawer-field-label">Replication</div>
      <div class="drawer-field-value">${repBadge}</div></div>
    ${r.replicated?`
    <div class="drawer-field"><div class="drawer-field-label">Health</div>
      <div class="drawer-field-value">${healthBadge}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Replication Status</div>
      <div class="drawer-field-value">${escH(r.replicationStatus)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">ASR Vault</div>
      <div class="drawer-field-value">${escH(r.vault)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Target Region</div>
      <div class="drawer-field-value">${escH(r.targetRegion)||'—'}</div></div>
    ${r.healthErrors?`<div class="drawer-field"><div class="drawer-field-label">Health Errors</div><div class="drawer-field-value" style="color:var(--amber);font-size:12px">${escH(r.healthErrors)}</div></div>`:''}
    <div class="drawer-section">RPO &amp; Test Failover</div>
    <div class="drawer-field"><div class="drawer-field-label">Current RPO</div>
      <div class="drawer-field-value">${rpoBadge}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Test Failover</div>
      <div class="drawer-field-value">${tfBadge}</div></div>
    ${r.testFailoverEverRun?`<div class="drawer-field"><div class="drawer-field-label">Last Test Failover Date</div><div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.testFailoverDate)}</div></div>`:''}
    <div class="rto-note">⚠️ <strong>RTO Note:</strong> Recovery Time Objective cannot be accurately calculated from ASR metadata alone. RTO depends on VM size, disk count, target region capacity, application startup time, and orchestration. Validate RTO through test failovers.</div>
    `:''}
    <div class="drawer-section">Risk &amp; Business Impact</div>
    <div class="drawer-field"><div class="drawer-field-label">Finding</div>
      <div class="drawer-field-value">${escH(r.reason)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Why It Matters</div>
      <div class="drawer-field-value" style="color:var(--muted2);font-size:12px;line-height:1.5">${escH(r.whyMatters)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Business Impact</div>
      <div class="impact-row">
        <span class="impact-chip">📌 ${escH(r.impactCategory)}</span>
        <span class="impact-chip">📊 ${escH(r.impactLevel)}</span>
      </div>
    </div>
    <div class="drawer-section">Remediation</div>
    <div class="remediation-box">${escH(r.action)}</div>
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
  if(next>=0&&next<FINDINGS_DATA.length) showFindingDetail(next);
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
filterVMs();
animateBars();
</script>
</body>
</html>
'@

    $critRPOThreshold = $ScanParameters.MaxRPOMinutes * $ScanParameters.CritRPOMultiplier

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_VMS__', $totalVMs `
        -replace '__REPLICATED_COUNT__', $replicatedCount `
        -replace '__UNREPLICATED_COUNT__', $unreplicatedCount `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__NEVER_TESTED_COUNT__', $neverTestedCount `
        -replace '__COVERAGE_PCT__', $coveragePct `
        -replace '__DONUT_SEGMENTS__', $donutSegments `
        -replace '__LEGEND_ITEMS__', $legendItems `
        -replace '__HEALTH_ROWS__', $healthRows `
        -replace '__RPO_ROWS__', $rpoRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__UNPROTECTED_ROWS__', $unprotectedRows `
        -replace '__REPLICATION_ROWS__', $replicationRows `
        -replace '__TEST_FAILOVER_ROWS__', $testFailoverRows `
        -replace '__VAULT_ROWS__', $vaultRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', (EscHtml $SessionInfo.Tenant) `
        -replace '__ACCOUNT__', (EscHtml $SessionInfo.Account) `
        -replace '__ENVIRONMENT__', (EscHtml $SessionInfo.Environment) `
        -replace '__SCOPE__', (EscHtml $ScanParameters.Scope) `
        -replace '__CRIT_TAG__', (EscHtml $ScanParameters.CriticalityTagName) `
        -replace '__ENV_TAG__', (EscHtml $ScanParameters.EnvironmentTagName) `
        -replace '__PROD_VALS__', (EscHtml $ScanParameters.ProductionTagValues) `
        -replace '__MAX_RPO__', $ScanParameters.MaxRPOMinutes `
        -replace '__CRIT_RPO_MULT__', $ScanParameters.CritRPOMultiplier `
        -replace '__CRIT_RPO_THRESH__', $critRPOThreshold `
        -replace '__MAX_TF_AGE__', $ScanParameters.MaxTestFailoverAgeDays `
        -replace '__EXPORT_ENABLED__', (EscHtml $ScanParameters.ExportEnabled) `
        -replace '__EXEC_TIME__', (EscHtml $ScanParameters.ExecTime) `
        -replace '__MAX_RPO_JS__', $ScanParameters.MaxRPOMinutes `
        -replace '__CRIT_RPO_MULT_JS__', $ScanParameters.CritRPOMultiplier `
        -replace '__MAX_TF_AGE_JS__', $ScanParameters.MaxTestFailoverAgeDays `
        -replace '__FINDINGS_JSON__', $findingsJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureDRCoverageAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureDRCoverage-Report.csv",

        [ValidateNotNullOrEmpty()]
        [string]$CriticalityTagName = "Criticality",

        [ValidateNotNullOrEmpty()]
        [string]$EnvironmentTagName = "Environment",

        [string[]]$ProductionTagValues = @("Production", "Prod", "PRD", "PROD"),

        [ValidateRange(1, 1440)]
        [int]$MaxAllowedRPOMinutes = 60,

        [ValidateRange(2, 10)]
        [int]$CriticalRPOMultiplier = 4,

        [ValidateRange(1, 365)]
        [int]$MaxTestFailoverAgeDays = 90
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.RecoveryServices", "Az.Resources")

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
    $ctx = $null
    try {
        $ctx = Get-AzContext -ErrorAction Stop
        if (-not $ctx -or -not $ctx.Account) {
            Write-Host "  ✗ No active Azure session. Run Connect-AzAccount first." -ForegroundColor Red
            return
        }
    }
    catch {
        Write-Host "  ✗ Could not retrieve Azure context: $_" -ForegroundColor Red
        return
    }

    # ── Subscription resolution ───────────────────────────────────────────────
    $subscriptions = @()
    try {
        if ($AllSubscriptions -or -not $SubscriptionIds) {
            $subscriptions = @(Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq "Enabled" })
            $scopeText = "All Enabled Subscriptions"
        }
        else {
            foreach ($sid in $SubscriptionIds) {
                $s = Get-AzSubscription -SubscriptionId $sid -ErrorAction SilentlyContinue
                if ($s) { $subscriptions += $s }
                else { Write-Warning "  Subscription '$sid' not found or not accessible." }
            }
            $scopeText = "Specified Subscriptions"
        }
    }
    catch {
        Write-Host "  ✗ Failed to retrieve subscriptions: $_" -ForegroundColor Red
        return
    }

    $subCount = $subscriptions.Count
    if ($subCount -eq 0) {
        Write-Host "  ✗ No accessible subscriptions found." -ForegroundColor Red
        return
    }

    Write-Section -Title "Session Information" -Data ([ordered]@{
            "Tenant"      = $ctx.Tenant.Id
            "Account"     = $ctx.Account.Id
            "Environment" = $ctx.Environment.Name
        })

    Write-Section -Title "Scan Parameters" -Data ([ordered]@{
            "Scope"                        = "$scopeText ($subCount found)"
            "Criticality Tag"              = $CriticalityTagName
            "Environment Tag"              = $EnvironmentTagName
            "Production Tag Values"        = $ProductionTagValues -join ", "
            "Max RPO (High, minutes)"      = $MaxAllowedRPOMinutes
            "Critical RPO Threshold"       = "$($MaxAllowedRPOMinutes * $CriticalRPOMultiplier) min (${MaxAllowedRPOMinutes}m × ${CriticalRPOMultiplier}x)"
            "Test Failover Max Age (days)" = $MaxTestFailoverAgeDays
            "Export to CSV"                = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
            "Export Path"                  = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
        })

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $allASRVaults = @()
    $subscriptionResults = @()
    $riskDistribution = @{}
    $replicationHealthDist = @{ "Normal" = 0; "Warning" = 0; "Critical" = 0; "NotReplicated" = 0 }
    $rpoDistribution = @{ "Within Threshold" = 0; "Exceeds High" = 0; "Exceeds Critical" = 0; "Not Available" = 0 }
    $successCount = 0
    $errorCount = 0

    $critRPOThreshold = $MaxAllowedRPOMinutes * $CriticalRPOMultiplier

    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = ([math]::Max(
            ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum, 35
        ))

    $subIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $subVMCount = 0
            $subReplicatedCount = 0

            # ── Discover all VMs ─────────────────────────────────────────────────
            $vms = @()
            try {
                $vms = @(Get-AzVM -ErrorAction Stop)
            }
            catch {
                Write-Warning "  Could not retrieve VMs for $($sub.Name): $_"
            }

            $subVMCount = $vms.Count

            # ── Enumerate Recovery Services Vaults ───────────────────────────────
            $rsvList = @()
            try {
                $rsvList = @(Get-AzRecoveryServicesVault -ErrorAction Stop)
            }
            catch {
                Write-Verbose "  Could not retrieve Recovery Services Vaults for $($sub.Name): $_"
            }

            # ── Build replication item lookup: VM resource ID → replication item ─
            # Key: vm resource ID (lowercase) → replication item with vault context
            $replicationItemMap = @{}

            foreach ($rsv in $rsvList) {
                try {
                    Set-AzRecoveryServicesVaultContext -Vault $rsv -ErrorAction Stop | Out-Null

                    # Check if this vault has ASR fabrics (not all RSVs are ASR-enabled)
                    $fabrics = @(Get-AzRecoveryServicesAsrFabric -ErrorAction SilentlyContinue)
                    if ($fabrics.Count -eq 0) { continue }

                    $vaultReplicatedCount = 0

                    foreach ($fabric in $fabrics) {
                        try {
                            $containers = @(Get-AzRecoveryServicesAsrProtectionContainer -Fabric $fabric -ErrorAction SilentlyContinue)
                            foreach ($container in $containers) {
                                try {
                                    $repItems = @(Get-AzRecoveryServicesAsrReplicationProtectedItem `
                                            -ProtectionContainer $container -ErrorAction SilentlyContinue)

                                    $vaultReplicatedCount += $repItems.Count

                                    foreach ($ri in $repItems) {
                                        $vmId = ""
                                        try {
                                            # A2A provider details expose the VM resource ID
                                            $providerDetails = $ri.ProviderSpecificDetails
                                            $vmId = if ($providerDetails -and $providerDetails.FabricObjectId) {
                                                $providerDetails.FabricObjectId.ToLower()
                                            }
                                            elseif ($ri.FriendlyName) {
                                                # Fallback: try to match by friendly name (less reliable)
                                                ""
                                            }
                                            else { "" }
                                        }
                                        catch { $vmId = "" }

                                        if ($vmId -and -not $replicationItemMap.ContainsKey($vmId)) {
                                            $replicationItemMap[$vmId] = @{
                                                Item      = $ri
                                                Vault     = $rsv
                                                Fabric    = $fabric
                                                Container = $container
                                            }
                                        }
                                    }
                                }
                                catch {
                                    Write-Verbose "    Container '$($container.Name)' enumeration failed: $_"
                                }
                            }
                        }
                        catch {
                            Write-Verbose "    Fabric '$($fabric.Name)' protection container enumeration failed: $_"
                        }
                    }

                    if ($vaultReplicatedCount -gt 0) {
                        $allASRVaults += [pscustomobject]@{
                            VaultName           = $rsv.Name
                            SubscriptionName    = $sub.Name
                            SubscriptionId      = $sub.Id
                            ResourceGroup       = $rsv.ResourceGroupName
                            Location            = $rsv.Location
                            ReplicatedItemCount = $vaultReplicatedCount
                        }
                    }
                }
                catch {
                    Write-Verbose "  Could not assess ASR fabric in vault '$($rsv.Name)': $_"
                }
            }

            # ── Assess each VM ───────────────────────────────────────────────────
            foreach ($vm in $vms) {
                $vmId = $vm.Id.ToLower()

                # Criticality from tags
                $tags = $null
                try { $tags = $vm.Tags } catch { }
                if (-not $tags) { $tags = @{} }

                $critInfo = Get-WorkloadCriticality -Tags $tags -CritTagName $CriticalityTagName -EnvTagName $EnvironmentTagName -ProdTagValues $ProductionTagValues
                $criticality = $critInfo.Criticality
                $environment = $critInfo.Environment

                # Replication lookup
                $riEntry = $replicationItemMap[$vmId]
                $isReplicated = $null -ne $riEntry

                $replicationStatus = "Not Replicated"
                $replicationHealth = "NotReplicated"
                $replicationHealthErrors = ""
                $targetRegion = ""
                $asrVaultName = ""
                $currentRPOMinutes = -1
                $testFailoverEverRun = $false
                $lastTestFailoverDate = "Never"
                $testFailoverAgeDays = [int]::MaxValue

                if ($isReplicated) {
                    $ri = $riEntry.Item

                    try { $asrVaultName = $riEntry.Vault.Name } catch { }

                    # Replication status
                    try { $replicationStatus = if ($ri.ReplicationState) { $ri.ReplicationState } else { "Unknown" } } catch { }

                    # Health
                    try {
                        $health = $ri.ReplicationHealth
                        $replicationHealth = if ($health) { $health } else { "Unknown" }
                    }
                    catch { $replicationHealth = "Unknown" }

                    # Health errors
                    try {
                        $errors = @($ri.ReplicationHealthErrors)
                        if ($errors.Count -gt 0) {
                            $replicationHealthErrors = ($errors | ForEach-Object {
                                    $msg = if ($_.ErrorMessage) { $_.ErrorMessage } else { $_.Message }
                                    if ($msg) { $msg } else { "Unknown error" }
                                }) -join "; "
                        }
                    }
                    catch { }

                    # Target region (A2A provider details)
                    try {
                        $pDetails = $ri.ProviderSpecificDetails
                        if ($pDetails) {
                            $targetRegion = if ($pDetails.RecoveryAzureResourceGroupId) {
                                # Extract region from RG ID: /subscriptions/.../resourceGroups/rg-dr
                                # Region is in the RecoveryAzureRegion property for A2A
                                if ($pDetails.RecoveryAzureRegion) { $pDetails.RecoveryAzureRegion }
                                else { "See vault" }
                            }
                            else { "See vault" }
                        }
                    }
                    catch { $targetRegion = "Could not be determined" }

                    # RPO — A2A provider exposes last RPO value
                    try {
                        $pDetails = $ri.ProviderSpecificDetails
                        $rpoSeconds = if ($pDetails -and $null -ne $pDetails.LastRpoCalculatedTime) {
                            # LastRpoCalculatedTime is a DateTime; RPO in seconds comes from RecoveryPointHistory
                            # Actual current RPO is best retrieved from A2AReplicationDetails.RecoveryPointHistory
                            # or as the delta between SourceLastRecoveryPoint and LastRpoCalculatedTime
                            $null
                        }
                        else { $null }

                        # Try direct RpoInSeconds property
                        $rpoSec = Get-ObjProperty -Obj $pDetails -PropName 'RpoInSeconds' -Default $null
                        if ($null -ne $rpoSec) {
                            $currentRPOMinutes = [math]::Ceiling([long]$rpoSec / 60)
                        }
                        else {
                            # Fallback: compute from last recovery point age
                            $lastRPTime = Get-ObjProperty -Obj $pDetails -PropName 'LastRecoveryPointReceived' -Default $null
                            if ($null -eq $lastRPTime) {
                                $lastRPTime = Get-ObjProperty -Obj $ri -PropName 'LastRecoveryPointObject' -Default $null
                            }
                            if ($null -ne $lastRPTime) {
                                $currentRPOMinutes = [math]::Ceiling(((Get-Date) - $lastRPTime).TotalMinutes)
                            }
                        }
                    }
                    catch {
                        Write-Verbose "    Could not retrieve RPO for VM '$($vm.Name)': $_"
                        $currentRPOMinutes = -1
                    }

                    # Test failover date
                    try {
                        $tfDate = Get-ObjProperty -Obj $ri -PropName 'LastSuccessfulTestFailoverTime' -Default $null
                        if ($null -eq $tfDate) {
                            $pDetails = $ri.ProviderSpecificDetails
                            $tfDate = Get-ObjProperty -Obj $pDetails -PropName 'LastSuccessfulTestFailoverTime' -Default $null
                        }
                        if ($null -ne $tfDate) {
                            $testFailoverEverRun = $true
                            $lastTestFailoverDate = $tfDate.ToString("yyyy-MM-dd HH:mm:ss")
                            $testFailoverAgeDays = [math]::Floor(((Get-Date) - $tfDate).TotalDays)
                        }
                    }
                    catch {
                        Write-Verbose "    Could not retrieve test failover date for VM '$($vm.Name)': $_"
                    }

                    $subReplicatedCount++
                }

                # ── Risk rating ───────────────────────────────────────────────────
                $isHealthy = ($replicationHealth -eq "Normal")
                $healthIssueReason = if (-not $isHealthy -and $replicationHealthErrors) {
                    "Health: $replicationHealth. Errors: $replicationHealthErrors"
                }
                elseif (-not $isHealthy) {
                    "Replication health: $replicationHealth"
                }
                else { "" }

                $riskResult = Get-DRRiskSeverity `
                    -VMCriticality           $criticality `
                    -VMEnvironment           $environment `
                    -IsReplicated            $isReplicated `
                    -IsHealthy               $isHealthy `
                    -HealthIssueReason       $healthIssueReason `
                    -ReplicationStatus       $replicationStatus `
                    -CurrentRPOMinutes       $currentRPOMinutes `
                    -MaxRPOMinutes           $MaxAllowedRPOMinutes `
                    -CriticalRPOMultiplier   $CriticalRPOMultiplier `
                    -TestFailoverEverRun     $testFailoverEverRun `
                    -TestFailoverAgeDays     $testFailoverAgeDays `
                    -MaxTestFailoverAgeDays  $MaxTestFailoverAgeDays

                # ── Risk and health distribution tracking ─────────────────────────
                if (-not $riskDistribution.ContainsKey($riskResult.Severity)) { $riskDistribution[$riskResult.Severity] = 0 }
                $riskDistribution[$riskResult.Severity]++

                if ($isReplicated) {
                    if ($replicationHealthDist.ContainsKey($replicationHealth)) { $replicationHealthDist[$replicationHealth]++ }
                    else { $replicationHealthDist[$replicationHealth] = 1 }

                    # RPO distribution
                    if ($currentRPOMinutes -lt 0) {
                        $rpoDistribution["Not Available"]++
                    }
                    elseif ($currentRPOMinutes -gt $critRPOThreshold) {
                        $rpoDistribution["Exceeds Critical"]++
                    }
                    elseif ($currentRPOMinutes -gt $MaxAllowedRPOMinutes) {
                        $rpoDistribution["Exceeds High"]++
                    }
                    else {
                        $rpoDistribution["Within Threshold"]++
                    }
                }
                else {
                    $replicationHealthDist["NotReplicated"]++
                    $rpoDistribution["Not Available"]++
                }

                $allFindings += [pscustomobject]@{
                    SubscriptionName        = $sub.Name
                    SubscriptionId          = $sub.Id
                    VMId                    = $vm.Id
                    VMName                  = $vm.Name
                    ResourceGroup           = $vm.ResourceGroupName
                    Location                = $vm.Location
                    VMCriticality           = $criticality
                    VMEnvironment           = $environment
                    IsReplicated            = $isReplicated
                    ReplicationStatus       = $replicationStatus
                    ReplicationHealth       = $replicationHealth
                    ReplicationHealthErrors = $replicationHealthErrors
                    ASRVaultName            = $asrVaultName
                    TargetRegion            = $targetRegion
                    CurrentRPOMinutes       = $currentRPOMinutes
                    TestFailoverEverRun     = $testFailoverEverRun
                    LastTestFailoverDate    = $lastTestFailoverDate
                    TestFailoverAgeDays     = if ($testFailoverAgeDays -eq [int]::MaxValue) { -1 } else { $testFailoverAgeDays }
                    Severity                = $riskResult.Severity
                    RiskCategory            = $riskResult.RiskCategory
                    RiskReason              = $riskResult.Reason
                    WhyItMatters            = $riskResult.WhyItMatters
                    ImpactCategory          = $riskResult.Impact.Category
                    ImpactLevel             = $riskResult.Impact.Level
                    RemediationAction       = $riskResult.Action
                }
            }

            # ── Per-subscription result ───────────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "VMs: $subVMCount  Replicated: $subReplicatedCount  Not Replicated: $($subVMCount - $subReplicatedCount)" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "VMs: $subVMCount  Replicated: $subReplicatedCount"
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
    $totalVMs = $allFindings.Count
    $totalRep = @($allFindings | Where-Object { $_.IsReplicated }).Count
    $covPct = if ($totalVMs -gt 0) { [math]::Round(($totalRep / $totalVMs) * 100, 1) } else { 0 }

    Write-DRSummary -Data ([ordered]@{
            "Total Subscriptions Scanned"   = $subCount
            "Successful"                    = $successCount
            "Errors"                        = $errorCount
            "Total VMs Assessed"            = $totalVMs
            "Replicated (ASR)"              = $totalRep
            "Not Replicated"                = ($totalVMs - $totalRep)
            "DR Coverage Percentage"        = "$covPct%"
            "Critical Findings"             = @($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
            "High Findings"                 = @($allFindings | Where-Object { $_.Severity -eq "High" }).Count
            "Medium Findings"               = @($allFindings | Where-Object { $_.Severity -eq "Medium" }).Count
            "Never Tested (Replicated VMs)" = @($allFindings | Where-Object { $_.IsReplicated -and -not $_.TestFailoverEverRun }).Count
            "ASR Vaults Found"              = $allASRVaults.Count
            "Execution Time"                = $duration
        })

    Write-RiskBreakdown -RiskDist $riskDistribution

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, VMName, ResourceGroup, Location,
                VMCriticality, VMEnvironment, IsReplicated, ReplicationStatus, ReplicationHealth,
                ASRVaultName, TargetRegion, CurrentRPOMinutes, TestFailoverEverRun,
                LastTestFailoverDate, TestFailoverAgeDays, Severity, RiskCategory, RiskReason,
                WhyItMatters, ImpactCategory, ImpactLevel, RemediationAction |
                Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

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
                Scope                  = "$scopeText ($subCount found)"
                CriticalityTagName     = $CriticalityTagName
                EnvironmentTagName     = $EnvironmentTagName
                ProductionTagValues    = $ProductionTagValues -join ", "
                MaxRPOMinutes          = $MaxAllowedRPOMinutes
                CritRPOMultiplier      = $CriticalRPOMultiplier
                MaxTestFailoverAgeDays = $MaxTestFailoverAgeDays
                ExportEnabled          = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime               = $duration
            }

            $htmlContent = Generate-DRCoverageHtml `
                -SessionInfo            $sessionInfo `
                -ScanParameters         $scanParams `
                -Findings               $allFindings `
                -ASRVaults              $allASRVaults `
                -SubscriptionResults    $subscriptionResults `
                -GeneratedOn            (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -RiskDistribution       $riskDistribution `
                -ReplicationHealthDist  $replicationHealthDist `
                -RPODistribution        $rpoDistribution

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
            Select-Object SubscriptionName, VMName, ResourceGroup, Location,
            VMCriticality, VMEnvironment, IsReplicated, ReplicationHealth,
            CurrentRPOMinutes, TestFailoverEverRun, LastTestFailoverDate,
            Severity, RiskCategory, ImpactCategory, ImpactLevel |
            Out-GridView -Title "Azure DR Coverage Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No VMs found in the targeted subscriptions." -ForegroundColor Yellow
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
