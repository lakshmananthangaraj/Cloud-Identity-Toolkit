<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 19 August 2026
Modified-On     : 19 August 2026

.SYNOPSIS
    Assesses Azure Backup coverage across one or more subscriptions — identifying
    unprotected workloads, inadequate retention/policy configuration, and operational
    backup health, then producing a risk-rated findings report with business impact
    and actionable remediation guidance.

.DESCRIPTION
    Get-AzureBackupCoverageAssessment evaluates the backup resilience posture of
    critical Azure workloads across one or multiple subscriptions.

    Assessment pipeline:

        Workload Discovery → Protection Status → Policy Adequacy →
        Operational Health → Risk Rating → Business Impact → Remediation

    Workload types assessed (v1.0):
        - Azure Virtual Machines (IaaS)
        - Azure SQL Databases
        - Azure SQL Managed Instances
        - Azure Files (File Shares)
        - Azure Blob Storage (where supported via Backup Vaults)
        - SAP HANA on Azure (where discoverable)

    Vault types assessed:
        - Recovery Services Vaults (RSV) — VMs, SQL, Files, SAP HANA
        - Backup Vaults (BV)            — Blobs, Disks

    For each workload, the script determines:
        1. Configuration Existence   — Is backup configured?
        2. Protection Status         — Is the workload actively protected?
        3. Operational Health        — Is the protection actually working?
        4. Policy Adequacy           — Does the policy meet the defined baseline?
        5. Business Risk             — What is the potential impact of failure?
        6. Remediation               — What action reduces the risk?

    Risk Severity Levels:
        Critical     — No protection for a critical/production workload, or severe
                       failure that could result in significant data loss
        High         — Protection exists but has a significant gap (stale backup,
                       unhealthy replication, inadequate retention, excessive RPO)
        Medium       — Governance weakness that should be addressed but does not
                       represent an immediate major risk
        Low          — Minor configuration or optimization issue
        Informational— Observation with no direct resilience risk

    Business Impact Categories:
        Operational | Financial | Regulatory/Compliance | Customer | Reputational |
        Data Loss

    The script supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Configurable criticality and environment tag names
        - Configurable retention, staleness, and SQL log backup thresholds
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of all findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          donut charts, distribution panels, detail drawer with remediation guidance)
        - Interactive Grid View where a GUI session is available

    Where Azure APIs cannot provide sufficient evidence to make a determination,
    the limitation is explicitly reported rather than assumptions being made.

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all backup coverage findings to -CsvPath.
    The HTML dashboard is always generated regardless of this switch.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard filename (same path, .html extension).
    Default: C:\Temp\AzureBackupCoverage-Report.csv

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

.PARAMETER MinVMRetentionDaysCritical
    VM backup retention below this threshold is rated Critical.
    Default: 7

.PARAMETER MinVMRetentionDaysHigh
    VM backup retention below this threshold (but >= Critical) is rated High.
    Default: 30

.PARAMETER MaxSQLLogBackupIntervalMinutes
    SQL log backup interval above this value in minutes is rated High.
    Default: 60

.PARAMETER MaxBackupStalenessDaysCritical
    A workload whose last successful backup is older than this many days is
    rated Critical for staleness.
    Default: 3

.PARAMETER MaxBackupStalenessDaysHigh
    A workload whose last successful backup is older than this many days (but
    less than MaxBackupStalenessDaysCritical) is rated High for staleness.
    Default: 1

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureBackupCoverageAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureBackupCoverageAssessment -AllSubscriptions -ExportToCsv

.EXAMPLE
    Get-AzureBackupCoverageAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureBackupCoverageAssessment -AllSubscriptions -ExportToCsv `
        -CsvPath "C:\Reports\BackupCoverage.csv" `
        -MinVMRetentionDaysHigh 60 `
        -MaxBackupStalenessDaysCritical 2

.EXAMPLE
    Get-AzureBackupCoverageAssessment -AllSubscriptions `
        -CriticalityTagName "AppCriticality" `
        -EnvironmentTagName "Env" `
        -ProductionTagValues "Prod","Production","Live"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (19-Aug-2026) - Initial release. VM, SQL Database, SQL Managed
                            Instance, Azure Files, Blob Storage, and SAP HANA
                            backup coverage assessment. Recovery Services Vault
                            and Backup Vault support. Risk model with severity
                            and business impact. CSV export and interactive
                            HTML dashboard with detail drawer and remediation.

    ─────────────────────────────────────────────────────────────────────────────
    Execution Flow:
    ─────────────────────────────────────────────────────────────────────────────
        1.  Module check / optional install (Az.Accounts, Az.RecoveryServices,
            Az.Resources, Az.Storage)
        2.  Authentication validation (Get-AzContext)
        3.  Subscription enumeration (All or specified list)
        4.  Per-subscription loop:
            a.  Enumerate Recovery Services Vaults and Backup Vaults
            b.  Discover workloads: VMs, SQL DBs, SQL MIs, File Shares, Blobs,
                SAP HANA
            c.  Match each workload against vault protected items
            d.  For protected items: retrieve backup policy and evaluate adequacy
            e.  For protected items: retrieve last backup job status / staleness
            f.  Assess operational health (recent failures, stale backups)
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
        1.  Az PowerShell module (Az.Accounts, Az.RecoveryServices, Az.Resources,
            Az.Storage) — installed automatically with user consent if absent.
        2.  Authenticated Azure session (Connect-AzAccount).
        3.  Reader role (minimum) at the subscription level.
        4.  Microsoft.RecoveryServices/vaults/read and
            Microsoft.RecoveryServices/vaults/backupProtectedItems/read for
            backup item enumeration.
        5.  Microsoft.RecoveryServices/vaults/backupJobs/read for operational
            health assessment (last backup job status).
        6.  Microsoft.DataProtection/backupVaults/read for Backup Vault
            (blob/disk) assessment.
        7.  Microsoft.Compute/virtualMachines/read,
            Microsoft.Sql/servers/databases/read,
            Microsoft.Sql/managedInstances/databases/read,
            Microsoft.Storage/storageAccounts/read for workload discovery.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - SAP HANA backup assessment depends on the workload being registered in
          a Recovery Services Vault; unregistered SAP HANA instances are not
          independently discoverable via standard Az cmdlets.
        - Azure Blob backup via Backup Vaults requires the Az.DataProtection
          module; this assessment falls back gracefully if the module is absent.
        - Backup policy retention detail extraction depends on the policy type
          and version returned by the API; complex GFS policies may report
          simplified retention values.
        - Backup job history is typically retained for 60 days in RSV; older
          history is not available via the API.
        - Interactive Grid View requires a GUI-capable session; skipped
          gracefully in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific; supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Application-level, database-consistent, and VSS writer backup
          configuration cannot be fully assessed from Azure metadata alone;
          guest-OS-level checks are outside scope.

.LINK
    https://learn.microsoft.com/en-us/azure/backup/backup-overview
    https://learn.microsoft.com/en-us/azure/backup/backup-azure-vms-introduction
    https://learn.microsoft.com/en-us/powershell/module/az.recoveryservices/get-azrecoveryservicesbackupitem
    https://learn.microsoft.com/en-us/azure/backup/backup-center-overview
    https://learn.microsoft.com/en-us/azure/backup/blob-backup-overview
    https://learn.microsoft.com/en-us/azure/backup/sap-hana-backup-support-matrix

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
    Write-CenteredText "Azure Backup Coverage Assessment v1.0" -Color White
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
        Write-Host $key.PadRight(32) -NoNewline -ForegroundColor Gray
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

Function Write-BackupSummary {
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
        Write-Host "$($r.Value) workload(s)" -ForegroundColor $color
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
        $envTagVal = $Tags[$EnvTagName]
        $isProd = $ProdTagValues | Where-Object { $_ -ieq $envTagVal }
        $environment = if ($isProd) { "Production" } else { "Non-Production" }
    }

    return @{ Criticality = $criticality; Environment = $environment }
}

Function Get-RiskSeverity {
    param(
        [string]$WorkloadCriticality,
        [string]$WorkloadEnvironment,
        [bool]$IsProtected,
        [bool]$PolicyAdequate,
        [string]$PolicyInadequacyReason,
        [bool]$IsHealthy,
        [string]$HealthIssueReason,
        [int]$BackupAgeInDays,
        [int]$StalenessCriticalDays,
        [int]$StalenessHighDays
    )

    # Rule 1: No protection at all
    if (-not $IsProtected) {
        if ($WorkloadCriticality -in @("Critical", "High") -or $WorkloadEnvironment -eq "Production") {
            return @{
                Severity     = "Critical"
                Reason       = "Workload has no backup protection configured."
                WhyItMatters = "A $WorkloadCriticality/$WorkloadEnvironment workload with no backup has no recovery path in the event of data corruption, accidental deletion, or infrastructure failure."
                Impact       = @{ Category = "Data Loss"; Level = "Critical" }
                Action       = "Enable Azure Backup immediately. For VMs, assign a Recovery Services Vault with a policy that meets or exceeds the minimum retention baseline."
            }
        }
        elseif ($WorkloadCriticality -eq "Unknown") {
            return @{
                Severity     = "High"
                Reason       = "Workload has no backup protection and criticality is unknown (tag missing)."
                WhyItMatters = "Without a criticality tag, the business impact of losing this workload cannot be determined. Absence of backup combined with unknown criticality represents unacceptable unquantified risk."
                Impact       = @{ Category = "Operational"; Level = "High" }
                Action       = "Enable Azure Backup and apply a '$($WorkloadCriticality)' criticality tag to classify the workload correctly."
            }
        }
        else {
            return @{
                Severity     = "Medium"
                Reason       = "Workload has no backup protection configured."
                WhyItMatters = "Even non-critical workloads should have a documented backup or exclusion decision. An undocumented absence of backup is a governance gap."
                Impact       = @{ Category = "Operational"; Level = "Medium" }
                Action       = "Either enable Azure Backup or document a formal exclusion decision with the workload owner."
            }
        }
    }

    # Rule 2: Protection exists but is unhealthy (operational failures)
    if (-not $IsHealthy) {
        $severity = if ($WorkloadCriticality -in @("Critical", "High") -or $WorkloadEnvironment -eq "Production") { "Critical" } else { "High" }
        $impactLevel = $severity
        return @{
            Severity     = $severity
            Reason       = "Backup is configured but not healthy: $HealthIssueReason"
            WhyItMatters = "A backup configuration that is continuously failing provides no actual data protection. The workload is effectively unprotected despite appearing covered."
            Impact       = @{ Category = "Data Loss"; Level = $impactLevel }
            Action       = "Investigate and resolve the backup health issue: $HealthIssueReason. Review the Azure Backup job log in the Recovery Services Vault for the specific failure reason and remediate."
        }
    }

    # Rule 3: Backup is stale (last successful backup too old)
    if ($BackupAgeInDays -ge 0) {
        if ($BackupAgeInDays -ge $StalenessCriticalDays) {
            $sev = if ($WorkloadCriticality -in @("Critical", "High") -or $WorkloadEnvironment -eq "Production") { "Critical" } else { "High" }
            return @{
                Severity     = $sev
                Reason       = "Last successful backup is $BackupAgeInDays day(s) old, exceeding the critical staleness threshold of $StalenessCriticalDays day(s)."
                WhyItMatters = "The recovery point is significantly outdated. In a failure scenario, data loss will extend back to the last successful backup."
                Impact       = @{ Category = "Data Loss"; Level = $sev }
                Action       = "Trigger a manual on-demand backup immediately. Investigate why scheduled backups are not completing successfully. Check backup job logs for failures."
            }
        }
        elseif ($BackupAgeInDays -ge $StalenessHighDays) {
            return @{
                Severity     = "High"
                Reason       = "Last successful backup is $BackupAgeInDays day(s) old, exceeding the high staleness threshold of $StalenessHighDays day(s)."
                WhyItMatters = "The backup is running behind schedule. A failure now would result in more data loss than expected based on the backup policy."
                Impact       = @{ Category = "Data Loss"; Level = "High" }
                Action       = "Verify the scheduled backup job completed successfully. Review backup job history for failures or missed schedules."
            }
        }
    }

    # Rule 4: Policy is inadequate
    if (-not $PolicyAdequate) {
        $sev = if ($WorkloadCriticality -in @("Critical", "High") -or $WorkloadEnvironment -eq "Production") { "High" } else { "Medium" }
        return @{
            Severity     = $sev
            Reason       = "Backup policy does not meet the defined baseline: $PolicyInadequacyReason"
            WhyItMatters = "A backup policy with insufficient retention or infrequent schedules reduces the organization's ability to recover data to an acceptable point in time."
            Impact       = @{ Category = "Regulatory/Compliance"; Level = $sev }
            Action       = "Update the backup policy to meet the enterprise retention baseline. Review the backup policy in the Recovery Services Vault and increase retention or adjust the schedule as required."
        }
    }

    # Rule 5: All checks pass — healthy and adequate
    return @{
        Severity     = "Healthy"
        Reason       = "Backup is configured, protection is active, operational health is good, and the policy meets the defined baseline."
        WhyItMatters = "No action required at this time. Continue monitoring backup job health."
        Impact       = @{ Category = "None"; Level = "None" }
        Action       = "No remediation required. Periodically review backup policy alignment as workload criticality changes."
    }
}

Function Test-BackupPolicyAdequacy {
    param(
        [object]$Policy,
        [string]$WorkloadType,
        [int]$MinVMRetentionCritical,
        [int]$MinVMRetentionHigh,
        [int]$MaxSQLLogIntervalMinutes
    )

    $adequate = $true
    $reasons = @()

    try {
        if ($WorkloadType -eq "VM") {
            $schedulePolicy = Get-ObjProperty -Obj $Policy -PropName 'SchedulePolicy'  -Default $null
            $retentionPolicy = Get-ObjProperty -Obj $Policy -PropName 'RetentionPolicy' -Default $null

            if ($retentionPolicy) {
                $dailyRetention = 0
                try {
                    $dailySchedule = Get-ObjProperty -Obj $retentionPolicy -PropName 'DailySchedule'  -Default $null
                    if ($dailySchedule) {
                        $retDuration = Get-ObjProperty -Obj $dailySchedule -PropName 'DurationCountInDays' -Default 0
                        $dailyRetention = [int]$retDuration
                    }
                }
                catch { $dailyRetention = 0 }

                if ($dailyRetention -gt 0 -and $dailyRetention -lt $MinVMRetentionCritical) {
                    $adequate = $false
                    $reasons += "Daily retention is $dailyRetention day(s), below the critical minimum of $MinVMRetentionCritical day(s)"
                }
                elseif ($dailyRetention -gt 0 -and $dailyRetention -lt $MinVMRetentionHigh) {
                    $adequate = $false
                    $reasons += "Daily retention is $dailyRetention day(s), below the recommended minimum of $MinVMRetentionHigh day(s)"
                }
            }
        }
        elseif ($WorkloadType -in @("SQLDatabase", "SQLMI", "SAPHANA")) {
            $logPolicy = Get-ObjProperty -Obj $Policy -PropName 'SchedulePolicy' -Default $null
            if ($logPolicy) {
                $scheduleFreq = Get-ObjProperty -Obj $logPolicy -PropName 'ScheduleFrequencyInMins' -Default 0
                if ($scheduleFreq -gt $MaxSQLLogIntervalMinutes) {
                    $adequate = $false
                    $reasons += "Log backup interval is $scheduleFreq minute(s), exceeding the maximum of $MaxSQLLogIntervalMinutes minute(s)"
                }
            }
        }
    }
    catch {
        # Cannot fully evaluate policy — return as unknown/adequate to avoid false positives
        $adequate = $true
        $reasons = @("Policy adequacy could not be fully evaluated from available API metadata")
    }

    return @{
        IsAdequate = $adequate
        Reasons    = ($reasons -join "; ")
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-BackupCoverageHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$Vaults,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [hashtable]$RiskDistribution,
        [hashtable]$WorkloadTypeDistribution,
        [hashtable]$CoverageByType
    )

    $totalWorkloads = @($Findings).Count
    $protectedCount = @($Findings | Where-Object { $_.IsProtected }).Count
    $unprotectedCount = @($Findings | Where-Object { -not $_.IsProtected }).Count
    $criticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $healthyCount = @($Findings | Where-Object { $_.Severity -eq "Healthy" }).Count
    $vaultCount = @($Vaults).Count

    $coveragePct = if ($totalWorkloads -gt 0) { [math]::Round(($protectedCount / $totalWorkloads) * 100) } else { 0 }

    # ── Risk distribution donut segments ──────────────────────────────────────
    $riskOrder = @("Critical", "High", "Medium", "Low", "Informational", "Healthy")
    $riskColors = @{
        "Critical"      = "#f85149"
        "High"          = "#d29922"
        "Medium"        = "#39c5cf"
        "Low"           = "#3fb950"
        "Informational" = "#7d8590"
        "Healthy"       = "#3fb950"
    }

    # Build donut segments
    $donutTotal = $totalWorkloads
    if ($donutTotal -eq 0) { $donutTotal = 1 }
    $circumference = 2 * [math]::PI * 54  # r=54
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

    # ── Workload type bar rows ─────────────────────────────────────────────────
    $wlTotal = ($WorkloadTypeDistribution.Values | Measure-Object -Sum).Sum
    if ($wlTotal -eq 0) { $wlTotal = 1 }
    $wlRows = ""
    $wlColors = @{
        "VM"          = "var(--accent)"
        "SQLDatabase" = "var(--accent2)"
        "SQLMI"       = "var(--accent3)"
        "AzureFiles"  = "var(--amber)"
        "BlobStorage" = "var(--green)"
        "SAPHANA"     = "var(--red)"
        "Unknown"     = "var(--muted)"
    }
    foreach ($wl in ($WorkloadTypeDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = [math]::Round(($wl.Value / $wlTotal) * 100)
        $color = if ($wlColors.ContainsKey($wl.Key)) { $wlColors[$wl.Key] } else { "var(--muted)" }
        $wlRows += "<div class='bar-row'><span class='bar-label'>$(EscHtml $wl.Key)</span><div class='bar-track'><div class='bar-fill' data-pct='$pct' style='background:$color'></div></div><span class='bar-pct'>$($wl.Value) ($pct%)</span></div>`n"
    }

    # ── Coverage by type bar rows ─────────────────────────────────────────────
    $covRows = ""
    foreach ($ct in ($CoverageByType.GetEnumerator() | Sort-Object { $_.Value.Total } -Descending)) {
        $total = $ct.Value.Total
        $protected = $ct.Value.Protected
        $pct = if ($total -gt 0) { [math]::Round(($protected / $total) * 100) } else { 0 }
        $barColor = if ($pct -ge 90) { "var(--green)" } elseif ($pct -ge 50) { "var(--amber)" } else { "var(--red)" }
        $covRows += "<div class='bar-row'><span class='bar-label'>$(EscHtml $ct.Key)</span><div class='bar-track'><div class='bar-fill' data-pct='$pct' style='background:$barColor'></div></div><span class='bar-pct'>$protected/$total ($pct%)</span></div>`n"
    }

    # ── Findings table rows ───────────────────────────────────────────────────
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
        $protBadge = if ($f.IsProtected) { '<span class="badge badge-green">✓ Protected</span>' } else { '<span class="badge badge-red">✗ Unprotected</span>' }
        $critBadge = switch ($f.WorkloadCriticality) {
            "Critical" { '<span class="badge badge-red">Critical</span>' }
            "High" { '<span class="badge badge-amber">High</span>' }
            "Medium" { '<span class="badge badge-blue">Medium</span>' }
            "Low" { '<span class="badge badge-green">Low</span>' }
            default { '<span class="badge" style="background:var(--surface3);color:var(--muted)">Unknown</span>' }
        }
        $nameShort = if ($f.WorkloadName.Length -gt 34) { $f.WorkloadName.Substring(0, 31) + "..." } else { $f.WorkloadName }
        $findingRows += @"
          <tr onclick="showFindingDetail($idx)">
            <td title="$(EscHtml $f.WorkloadName)">$(EscHtml $nameShort)</td>
            <td>$(EscHtml $f.WorkloadType)</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$(EscHtml $f.ResourceGroup)</td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td>$protBadge</td>
            <td>$critBadge</td>
            <td style="font-family:var(--mono);font-size:11px">$(EscHtml $f.LastSuccessfulBackup)</td>
          </tr>
"@
        $idx++
    }

    # ── Unprotected table rows ────────────────────────────────────────────────
    $unprotectedRows = ""
    $unprotected = @($Findings | Where-Object { -not $_.IsProtected })
    foreach ($u in $unprotected) {
        $critBadge = switch ($u.WorkloadCriticality) {
            "Critical" { '<span class="badge badge-red">Critical</span>' }
            "High" { '<span class="badge badge-amber">High</span>' }
            "Medium" { '<span class="badge badge-blue">Medium</span>' }
            "Low" { '<span class="badge badge-green">Low</span>' }
            default { '<span class="badge" style="background:var(--surface3);color:var(--muted)">Unknown</span>' }
        }
        $unprotectedRows += @"
          <tr>
            <td>$(EscHtml $u.WorkloadName)</td>
            <td>$(EscHtml $u.WorkloadType)</td>
            <td>$(EscHtml $u.SubscriptionName)</td>
            <td>$(EscHtml $u.ResourceGroup)</td>
            <td>$critBadge</td>
            <td>$(EscHtml $u.WorkloadEnvironment)</td>
            <td style="font-size:11px;color:var(--muted2)">$(EscHtml $u.RemediationAction)</td>
          </tr>
"@
    }

    # ── Backup Policy table rows ──────────────────────────────────────────────
    $policyRows = ""
    $policyItems = @($Findings | Where-Object { $_.IsProtected -and -not [string]::IsNullOrWhiteSpace($_.BackupPolicyName) })
    foreach ($p in $policyItems) {
        $adqBadge = if ($p.PolicyAdequate) { '<span class="badge badge-green">✓ Adequate</span>' } else { '<span class="badge badge-amber">⚠ Inadequate</span>' }
        $policyRows += @"
          <tr>
            <td>$(EscHtml $p.WorkloadName)</td>
            <td>$(EscHtml $p.WorkloadType)</td>
            <td>$(EscHtml $p.BackupPolicyName)</td>
            <td>$(EscHtml $p.VaultName)</td>
            <td>$(EscHtml $p.RetentionSummary)</td>
            <td>$adqBadge</td>
            <td style="font-size:11px;color:var(--muted2)">$(EscHtml $p.PolicyInadequacyReason)</td>
          </tr>
"@
    }

    # ── Vault table rows ──────────────────────────────────────────────────────
    $vaultRows = ""
    foreach ($v in $Vaults) {
        $typeBadge = if ($v.VaultType -eq "RecoveryServicesVault") { '<span class="badge badge-blue">RSV</span>' } else { '<span class="badge badge-purple" style="background:rgba(163,113,247,.15);color:var(--accent3);border:1px solid rgba(163,113,247,.3)">BV</span>' }
        $vaultRows += @"
          <tr>
            <td>$(EscHtml $v.VaultName)</td>
            <td>$(EscHtml $v.SubscriptionName)</td>
            <td>$(EscHtml $v.ResourceGroup)</td>
            <td>$(EscHtml $v.Location)</td>
            <td>$typeBadge</td>
            <td>$($v.ProtectedItemCount)</td>
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

    # ── JSON for findings detail drawer ───────────────────────────────────────
    $findingsJson = "["
    foreach ($f in $Findings) {
        $findingsJson += "{" +
        """id"":""$(EscJ $f.WorkloadId)""," +
        """name"":""$(EscJ $f.WorkloadName)""," +
        """type"":""$(EscJ $f.WorkloadType)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """location"":""$(EscJ $f.Location)""," +
        """severity"":""$(EscJ $f.Severity)""," +
        """protected"":$(if ($f.IsProtected) { 'true' } else { 'false' })," +
        """healthy"":$(if ($f.IsHealthy) { 'true' } else { 'false' })," +
        """policyAdequate"":$(if ($f.PolicyAdequate) { 'true' } else { 'false' })," +
        """criticality"":""$(EscJ $f.WorkloadCriticality)""," +
        """environment"":""$(EscJ $f.WorkloadEnvironment)""," +
        """vault"":""$(EscJ $f.VaultName)""," +
        """policy"":""$(EscJ $f.BackupPolicyName)""," +
        """retention"":""$(EscJ $f.RetentionSummary)""," +
        """lastBackup"":""$(EscJ $f.LastSuccessfulBackup)""," +
        """backupAge"":$($f.BackupAgeInDays)," +
        """reason"":""$(EscJ $f.RiskReason)""," +
        """whyMatters"":""$(EscJ $f.WhyItMatters)""," +
        """impactCategory"":""$(EscJ $f.ImpactCategory)""," +
        """impactLevel"":""$(EscJ $f.ImpactLevel)""," +
        """action"":""$(EscJ $f.RemediationAction)""," +
        """policyInadequacy"":""$(EscJ $f.PolicyInadequacyReason)""" +
        "},"
    }
    $findingsJson = $findingsJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Backup Coverage Assessment</title>
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
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--green));display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
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
.bar-label{font-size:12px;color:var(--muted2);width:130px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:100px;text-align:right;flex-shrink:0;}
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
.remediation-box{background:rgba(56,139,253,.08);border:1px solid rgba(56,139,253,.3);border-radius:var(--radius-sm);padding:12px 14px;font-size:12px;line-height:1.6;color:var(--text);}
.impact-row{display:flex;gap:12px;flex-wrap:wrap;}
.impact-chip{padding:4px 10px;border-radius:20px;font-size:11px;font-weight:600;background:var(--surface3);border:1px solid var(--border);}
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
    <div class="logo-title">Backup Coverage</div>
    <div class="logo-sub">Azure Backup Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('workloads',this)"><span class="nav-icon">💻</span> Workloads</button>
    <button class="nav-btn" onclick="showPage('unprotected',this)"><span class="nav-icon">⚠️</span> Unprotected</button>
    <button class="nav-btn" onclick="showPage('policies',this)"><span class="nav-icon">📋</span> Backup Policies</button>
    <button class="nav-btn" onclick="showPage('vaults',this)"><span class="nav-icon">🏦</span> Vaults</button>
    <button class="nav-btn" onclick="showPage('scanresults',this)"><span class="nav-icon">🔍</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">Generated: __GENERATED_ON__<br/>Azure Backup Coverage Assessment</div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Backup Coverage Overview</div>
      <div class="page-sub">Azure Backup resilience posture across __SUB_COUNT__ subscription(s) — __TOTAL_WORKLOADS__ workloads assessed</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_WORKLOADS__</div>
        <div class="stat-label">Total Workloads</div>
        <div class="stat-sub">Across all types</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__PROTECTED_COUNT__</div>
        <div class="stat-label">Protected</div>
        <div class="stat-sub">__COVERAGE_PCT__% coverage</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__UNPROTECTED_COUNT__</div>
        <div class="stat-label">Unprotected</div>
        <div class="stat-sub">No backup configured</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical Findings</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Findings</div>
        <div class="stat-sub">Significant gaps</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__VAULT_COUNT__</div>
        <div class="stat-label">Vaults</div>
        <div class="stat-sub">RSV + Backup Vaults</div>
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
            <text x="64" y="76" text-anchor="middle" font-size="9" fill="var(--muted)" font-family="Calibri,Segoe UI,sans-serif">COVERAGE</text>
          </svg>
          <div class="legend-list">__LEGEND_ITEMS__</div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">💻 Workload Type Distribution</div>
        __WL_ROWS__
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">📈 Coverage by Workload Type</div>
      __COV_ROWS__
    </div>
  </div>

  <!-- Workloads -->
  <div id="page-workloads" class="page">
    <div class="page-header">
      <div class="page-title">Workloads</div>
      <div class="page-sub">All assessed workloads — click any row for full details and remediation guidance</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="wlSearch" placeholder="Search workload, subscription, resource group…" oninput="filterWorkloads()"/>
        </div>
        <select class="filter-select" id="filterSeverity" onchange="filterWorkloads()">
          <option value="">All Severity</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Healthy">Healthy</option>
        </select>
        <select class="filter-select" id="filterType" onchange="filterWorkloads()">
          <option value="">All Types</option>
          <option value="VM">VM</option>
          <option value="SQLDatabase">SQL Database</option>
          <option value="SQLMI">SQL Managed Instance</option>
          <option value="AzureFiles">Azure Files</option>
          <option value="BlobStorage">Blob Storage</option>
          <option value="SAPHANA">SAP HANA</option>
        </select>
        <select class="filter-select" id="filterProtected" onchange="filterWorkloads()">
          <option value="">All Protection</option>
          <option value="true">Protected</option>
          <option value="false">Unprotected</option>
        </select>
        <select class="filter-select" id="pgSizeWl" onchange="changeWlPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="wlTable">
          <thead>
            <tr>
              <th onclick="sortWl(0)">Workload Name</th>
              <th onclick="sortWl(1)">Type</th>
              <th onclick="sortWl(2)">Subscription</th>
              <th onclick="sortWl(3)">Resource Group</th>
              <th onclick="sortWl(4)">Severity</th>
              <th onclick="sortWl(5)">Protection</th>
              <th onclick="sortWl(6)">Criticality</th>
              <th onclick="sortWl(7)">Last Backup</th>
            </tr>
          </thead>
          <tbody id="wlBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="wlPagination"></div>
    </div>
  </div>

  <!-- Unprotected -->
  <div id="page-unprotected" class="page">
    <div class="page-header">
      <div class="page-title">Unprotected Workloads</div>
      <div class="page-sub">__UNPROTECTED_COUNT__ workload(s) with no backup protection — prioritise by criticality and environment</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Workload Name</th>
              <th>Type</th>
              <th>Subscription</th>
              <th>Resource Group</th>
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

  <!-- Backup Policies -->
  <div id="page-policies" class="page">
    <div class="page-header">
      <div class="page-title">Backup Policies</div>
      <div class="page-sub">Policy adequacy assessment for all protected workloads — inadequate policies should be updated even if protection is active</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Workload</th>
              <th>Type</th>
              <th>Policy Name</th>
              <th>Vault</th>
              <th>Retention</th>
              <th>Adequacy</th>
              <th>Issue</th>
            </tr>
          </thead>
          <tbody>__POLICY_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Vaults -->
  <div id="page-vaults" class="page">
    <div class="page-header">
      <div class="page-title">Backup Vaults</div>
      <div class="page-sub">Recovery Services Vaults (RSV) and Backup Vaults (BV) across all scanned subscriptions</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Vault Name</th>
              <th>Subscription</th>
              <th>Resource Group</th>
              <th>Location</th>
              <th>Type</th>
              <th>Protected Items</th>
            </tr>
          </thead>
          <tbody>__VAULT_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-scanresults" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription backup assessment outcome</div>
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
        <div class="info-card"><div class="info-label">Criticality Tag</div><div class="info-value">__CRIT_TAG__</div></div>
        <div class="info-card"><div class="info-label">Environment Tag</div><div class="info-value">__ENV_TAG__</div></div>
        <div class="info-card"><div class="info-label">Production Values</div><div class="info-value">__PROD_VALS__</div></div>
        <div class="info-card"><div class="info-label">VM Retention Critical</div><div class="info-value">__VM_RET_CRIT__ days</div></div>
        <div class="info-card"><div class="info-label">VM Retention High</div><div class="info-value">__VM_RET_HIGH__ days</div></div>
        <div class="info-card"><div class="info-label">SQL Log Interval Max</div><div class="info-value">__SQL_LOG_MAX__ min</div></div>
        <div class="info-card"><div class="info-label">Backup Staleness Critical</div><div class="info-value">__STALE_CRIT__ days</div></div>
        <div class="info-card"><div class="info-label">Backup Staleness High</div><div class="info-value">__STALE_HIGH__ days</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">⚠️ Assessment Scope Notes</div>
      <div class="scope-note">
        This assessment covers Azure VM, SQL Database, SQL Managed Instance, Azure Files, Blob Storage, and SAP HANA backup coverage via Recovery Services Vaults and Backup Vaults.
        Application-level consistency, guest-OS VSS writers, and cross-region backup are not assessed in v1.0.
        Azure Monitor integration and historical trend analysis are outside current scope.
        For a complete BC/DR assessment, also run <strong>Get-AzureDRCoverageAssessment</strong> for Site Recovery / replication coverage.
      </div>
    </div>
  </div>
</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Workload Detail</span>
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
let wlFiltered = [...FINDINGS_DATA];
let wlPage = 1, wlPageSz = 25;
let wlSortCol = -1, wlSortAsc = true;
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
  t.textContent=msg;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Workloads table ──────────────────────────────────────────────────────────
function filterWorkloads(){
  const q=document.getElementById('wlSearch').value.toLowerCase();
  const sv=document.getElementById('filterSeverity').value;
  const tp=document.getElementById('filterType').value;
  const pr=document.getElementById('filterProtected').value;
  wlFiltered=FINDINGS_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mS=!sv||r.severity===sv;
    const mT=!tp||r.type===tp;
    const mP=!pr||(pr==='true'?r.protected:!r.protected);
    return mQ&&mS&&mT&&mP;
  });
  wlPage=1; renderWl();
}
function changeWlPageSize(){
  wlPageSz=parseInt(document.getElementById('pgSizeWl').value);
  wlPage=1; renderWl();
}
function sortWl(col){
  if(wlSortCol===col){wlSortAsc=!wlSortAsc;}else{wlSortCol=col;wlSortAsc=true;}
  const keys=['name','type','sub','rg','severity','protected','criticality','lastBackup'];
  wlFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'',bv=b[k]??'';
    return wlSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                    :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderWl();
}
function renderWl(){
  const tbody=document.getElementById('wlBody');
  const start=(wlPage-1)*wlPageSz;
  const slice=wlFiltered.slice(start,start+wlPageSz);
  const sevCls={'Critical':'badge-red','High':'badge-amber','Medium':'badge-blue','Low':'badge-green','Healthy':'badge-green','Informational':''};
  const critCls={'Critical':'badge-red','High':'badge-amber','Medium':'badge-blue','Low':'badge-green'};
  tbody.innerHTML=slice.map(r=>{
    const gi=FINDINGS_DATA.indexOf(r);
    const sc=sevCls[r.severity]||'';
    const cc=critCls[r.criticality]||'';
    const protBadge=r.protected?'<span class="badge badge-green">✓ Protected</span>':'<span class="badge badge-red">✗ Unprotected</span>';
    const critBadge=cc?`<span class="badge ${cc}">${escH(r.criticality)}</span>`:`<span class="badge" style="background:var(--surface3);color:var(--muted)">${escH(r.criticality)}</span>`;
    const nm=r.name.length>34?r.name.substring(0,31)+'...':r.name;
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.type)}</td>
      <td>${escH(r.sub)}</td>
      <td>${escH(r.rg)}</td>
      <td><span class="badge ${sc}">${escH(r.severity)}</span></td>
      <td>${protBadge}</td>
      <td>${critBadge}</td>
      <td style="font-family:var(--mono);font-size:11px">${escH(r.lastBackup)}</td>
    </tr>`;
  }).join('');
  renderWlPg();
}
function renderWlPg(){
  const total=Math.ceil(wlFiltered.length/wlPageSz);
  const el=document.getElementById('wlPagination');
  let h=`<span>${wlFiltered.length} workloads</span>`;
  h+=`<button class="pg-btn" onclick="changeWlPage(${wlPage-1})" ${wlPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,wlPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===wlPage?'active':''}" onclick="changeWlPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeWlPage(${wlPage+1})" ${wlPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}
function changeWlPage(p){
  const total=Math.ceil(wlFiltered.length/wlPageSz);
  if(p<1||p>total)return;
  wlPage=p; renderWl();
}

// ── Detail drawer ─────────────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=FINDINGS_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FINDINGS_DATA.length}`;
  const sevCls={'Critical':'badge-red','High':'badge-amber','Medium':'badge-blue','Low':'badge-green','Healthy':'badge-green','Informational':''};
  const sc=sevCls[r.severity]||'';
  const protBadge=r.protected?'<span class="badge badge-green">✓ Protected</span>':'<span class="badge badge-red">✗ Unprotected</span>';
  const healthBadge=r.healthy?'<span class="badge badge-green">✓ Healthy</span>':'<span class="badge badge-red">✗ Unhealthy</span>';
  const policyBadge=r.policyAdequate?'<span class="badge badge-green">✓ Adequate</span>':'<span class="badge badge-amber">⚠ Inadequate</span>';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sc}">${escH(r.severity)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Workload Type</div>
      <div class="drawer-field-value">${escH(r.type)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Location</div>
      <div class="drawer-field-value">${escH(r.location)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Criticality / Environment</div>
      <div class="drawer-field-value">${escH(r.criticality)} / ${escH(r.environment)}</div></div>
    <div class="drawer-section">Protection Status</div>
    <div class="drawer-field"><div class="drawer-field-label">Protection</div>
      <div class="drawer-field-value">${protBadge}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Operational Health</div>
      <div class="drawer-field-value">${healthBadge}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Policy Adequacy</div>
      <div class="drawer-field-value">${policyBadge}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Vault</div>
      <div class="drawer-field-value">${r.vault?escH(r.vault):'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Backup Policy</div>
      <div class="drawer-field-value">${r.policy?escH(r.policy):'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Retention</div>
      <div class="drawer-field-value">${r.retention?escH(r.retention):'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Last Successful Backup</div>
      <div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.lastBackup)}</div></div>
    ${r.policyInadequacy?`<div class="drawer-field"><div class="drawer-field-label">Policy Issue</div><div class="drawer-field-value" style="color:var(--amber)">${escH(r.policyInadequacy)}</div></div>`:''}
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
filterWorkloads();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_WORKLOADS__', $totalWorkloads `
        -replace '__PROTECTED_COUNT__', $protectedCount `
        -replace '__UNPROTECTED_COUNT__', $unprotectedCount `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__VAULT_COUNT__', $vaultCount `
        -replace '__COVERAGE_PCT__', $coveragePct `
        -replace '__DONUT_SEGMENTS__', $donutSegments `
        -replace '__LEGEND_ITEMS__', $legendItems `
        -replace '__WL_ROWS__', $wlRows `
        -replace '__COV_ROWS__', $covRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__UNPROTECTED_ROWS__', $unprotectedRows `
        -replace '__POLICY_ROWS__', $policyRows `
        -replace '__VAULT_ROWS__', $vaultRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', (EscHtml $SessionInfo.Tenant) `
        -replace '__ACCOUNT__', (EscHtml $SessionInfo.Account) `
        -replace '__ENVIRONMENT__', (EscHtml $SessionInfo.Environment) `
        -replace '__SCOPE__', (EscHtml $ScanParameters.Scope) `
        -replace '__CRIT_TAG__', (EscHtml $ScanParameters.CriticalityTagName) `
        -replace '__ENV_TAG__', (EscHtml $ScanParameters.EnvironmentTagName) `
        -replace '__PROD_VALS__', (EscHtml $ScanParameters.ProductionTagValues) `
        -replace '__VM_RET_CRIT__', $ScanParameters.MinVMRetentionCritical `
        -replace '__VM_RET_HIGH__', $ScanParameters.MinVMRetentionHigh `
        -replace '__SQL_LOG_MAX__', $ScanParameters.MaxSQLLogIntervalMinutes `
        -replace '__STALE_CRIT__', $ScanParameters.MaxStalenessCritical `
        -replace '__STALE_HIGH__', $ScanParameters.MaxStalenessHigh `
        -replace '__EXPORT_ENABLED__', (EscHtml $ScanParameters.ExportEnabled) `
        -replace '__EXEC_TIME__', (EscHtml $ScanParameters.ExecTime) `
        -replace '__FINDINGS_JSON__', $findingsJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureBackupCoverageAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureBackupCoverage-Report.csv",

        [ValidateNotNullOrEmpty()]
        [string]$CriticalityTagName = "Criticality",

        [ValidateNotNullOrEmpty()]
        [string]$EnvironmentTagName = "Environment",

        [string[]]$ProductionTagValues = @("Production", "Prod", "PRD", "PROD"),

        [ValidateRange(1, 365)]
        [int]$MinVMRetentionDaysCritical = 7,

        [ValidateRange(1, 365)]
        [int]$MinVMRetentionDaysHigh = 30,

        [ValidateRange(1, 1440)]
        [int]$MaxSQLLogBackupIntervalMinutes = 60,

        [ValidateRange(1, 365)]
        [int]$MaxBackupStalenessDaysCritical = 3,

        [ValidateRange(1, 365)]
        [int]$MaxBackupStalenessDaysHigh = 1
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
            "VM Retention Critical (days)" = $MinVMRetentionDaysCritical
            "VM Retention High (days)"     = $MinVMRetentionDaysHigh
            "SQL Log Backup Max (min)"     = $MaxSQLLogBackupIntervalMinutes
            "Backup Staleness Critical"    = "$MaxBackupStalenessDaysCritical day(s)"
            "Backup Staleness High"        = "$MaxBackupStalenessDaysHigh day(s)"
            "Export to CSV"                = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
            "Export Path"                  = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
        })

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $allVaults = @()
    $subscriptionResults = @()
    $riskDistribution = @{}
    $workloadTypeDist = @{}
    $coverageByType = @{}
    $successCount = 0
    $errorCount = 0

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

            $subWorkloadCount = 0
            $subProtectedCount = 0

            # ── Enumerate Recovery Services Vaults ───────────────────────────────
            $rsvList = @()
            try {
                $rsvList = @(Get-AzRecoveryServicesVault -ErrorAction Stop)
                foreach ($v in $rsvList) {
                    $allVaults += [pscustomobject]@{
                        VaultName          = $v.Name
                        VaultType          = "RecoveryServicesVault"
                        SubscriptionName   = $sub.Name
                        SubscriptionId     = $sub.Id
                        ResourceGroup      = $v.ResourceGroupName
                        Location           = $v.Location
                        ProtectedItemCount = 0    # updated below
                    }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Recovery Services Vaults for $($sub.Name): $_"
            }

            # ── Enumerate Backup Vaults (Az.DataProtection) ──────────────────────
            try {
                if (Get-Module -ListAvailable -Name "Az.DataProtection" -ErrorAction SilentlyContinue) {
                    Import-Module Az.DataProtection -ErrorAction SilentlyContinue
                    $bvList = @(Get-AzDataProtectionBackupVault -SubscriptionId $sub.Id -ErrorAction Stop)
                    foreach ($bv in $bvList) {
                        $allVaults += [pscustomobject]@{
                            VaultName          = $bv.Name
                            VaultType          = "BackupVault"
                            SubscriptionName   = $sub.Name
                            SubscriptionId     = $sub.Id
                            ResourceGroup      = $bv.ResourceGroupName
                            Location           = $bv.Location
                            ProtectedItemCount = 0
                        }
                    }
                }
            }
            catch {
                Write-Verbose "  Backup Vault enumeration skipped for $($sub.Name): $_"
            }

            # ── Build a lookup of protected items across all RSVs ─────────────────
            # Key: resource ID (lowercase) → protected item object
            $protectedItemMap = @{}

            foreach ($rsv in $rsvList) {
                try {
                    Set-AzRecoveryServicesVaultContext -Vault $rsv -ErrorAction Stop | Out-Null

                    $protectedItems = @(Get-AzRecoveryServicesBackupItem `
                            -WorkloadType AzureVM       -VaultId $rsv.ID -ErrorAction SilentlyContinue)
                    $protectedItems += @(Get-AzRecoveryServicesBackupItem `
                            -WorkloadType MSSQL         -VaultId $rsv.ID -ErrorAction SilentlyContinue)
                    $protectedItems += @(Get-AzRecoveryServicesBackupItem `
                            -WorkloadType AzureFiles    -VaultId $rsv.ID -ErrorAction SilentlyContinue)
                    $protectedItems += @(Get-AzRecoveryServicesBackupItem `
                            -WorkloadType SAPHanaDatabase -VaultId $rsv.ID -ErrorAction SilentlyContinue)

                    # Update vault item count
                    $vaultEntry = $allVaults | Where-Object { $_.VaultName -eq $rsv.Name -and $_.VaultType -eq "RecoveryServicesVault" } | Select-Object -First 1
                    if ($vaultEntry) { $vaultEntry.ProtectedItemCount = $protectedItems.Count }

                    foreach ($pi in $protectedItems) {
                        $piKey = ""
                        try {
                            # Use VirtualMachineId or SourceResourceId as the lookup key
                            $srcId = if ($pi.VirtualMachineId) { $pi.VirtualMachineId }
                            elseif ($pi.SourceResourceId) { $pi.SourceResourceId }
                            else { $pi.Id }
                            $piKey = $srcId.ToLower()
                        }
                        catch { $piKey = $pi.Id.ToLower() }

                        if (-not $protectedItemMap.ContainsKey($piKey)) {
                            $protectedItemMap[$piKey] = @{
                                Item    = $pi
                                VaultId = $rsv.ID
                                Vault   = $rsv
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "  Could not enumerate backup items in vault '$($rsv.Name)': $_"
                }
            }

            # ── Helper: assess one workload ───────────────────────────────────────
            Function Invoke-WorkloadBackupAssessment {
                param(
                    [object]$Resource,
                    [string]$ResourceId,
                    [string]$WorkloadType,
                    [string]$DisplayName,
                    [hashtable]$ProtectedItemMap,
                    [string]$SubName,
                    [string]$SubId,
                    [string]$CritTagName,
                    [string]$EnvTagName,
                    [string[]]$ProdTagVals,
                    [int]$VmRetCrit,
                    [int]$VmRetHigh,
                    [int]$SqlLogMax,
                    [int]$StaleCrit,
                    [int]$StaleHigh
                )

                # Resolve tags
                $tags = $null
                try { $tags = $Resource.Tags }
                catch { }
                if (-not $tags) { $tags = @{} }

                $critInfo = Get-WorkloadCriticality -Tags $tags -CritTagName $CritTagName -EnvTagName $EnvTagName -ProdTagValues $ProdTagVals
                $criticality = $critInfo.Criticality
                $environment = $critInfo.Environment

                # Look up in protected item map
                $piEntry = $ProtectedItemMap[$ResourceId.ToLower()]
                $isProtected = $null -ne $piEntry

                $vaultName = ""
                $backupPolicyName = ""
                $retentionSummary = ""
                $lastSuccessfulBackup = "Never / Unknown"
                $backupAgeInDays = -1
                $isHealthy = $true
                $healthIssueReason = ""
                $policyAdequate = $true
                $policyInadequacyReason = ""

                if ($isProtected) {
                    $pi = $piEntry.Item
                    $vaultObj = $piEntry.Vault

                    $vaultName = $vaultObj.Name

                    # Policy
                    try {
                        $backupPolicyName = if ($pi.ProtectionPolicyName) { $pi.ProtectionPolicyName } else { "" }

                        $policy = $null
                        if ($backupPolicyName) {
                            $policy = Get-AzRecoveryServicesBackupProtectionPolicy `
                                -Name $backupPolicyName -VaultId $piEntry.VaultId -ErrorAction SilentlyContinue
                        }

                        if ($policy) {
                            # Retention summary (best-effort)
                            try {
                                $retPol = $policy.RetentionPolicy
                                $dailyDays = 0
                                try { $dailyDays = $retPol.DailySchedule.DurationCountInDays } catch { }
                                if ($dailyDays -gt 0) { $retentionSummary = "Daily: $dailyDays day(s)" }
                                else {
                                    $weeklyWks = 0
                                    try { $weeklyWks = $retPol.WeeklySchedule.DurationCountInWeeks } catch { }
                                    if ($weeklyWks -gt 0) { $retentionSummary += " Weekly: $weeklyWks wk(s)" }
                                }
                            }
                            catch { $retentionSummary = "Could not be determined" }

                            $adequacyResult = Test-BackupPolicyAdequacy `
                                -Policy                 $policy `
                                -WorkloadType           $WorkloadType `
                                -MinVMRetentionCritical $VmRetCrit `
                                -MinVMRetentionHigh     $VmRetHigh `
                                -MaxSQLLogIntervalMinutes $SqlLogMax

                            $policyAdequate = $adequacyResult.IsAdequate
                            $policyInadequacyReason = $adequacyResult.Reasons
                        }
                    }
                    catch {
                        Write-Verbose "    Could not evaluate backup policy for ${DisplayName}: $_"
                    }

                    # Last backup / operational health
                    try {
                        $piHealth = $pi.LastBackupStatus
                        if ($piHealth -and $piHealth -ne "Completed") {
                            $isHealthy = $false
                            $healthIssueReason = "Last backup status: $piHealth"
                        }

                        $lastBackupTime = $pi.LastBackupTime
                        if ($lastBackupTime) {
                            $lastSuccessfulBackup = $lastBackupTime.ToString("yyyy-MM-dd HH:mm:ss")
                            $backupAgeInDays = [math]::Floor(((Get-Date) - $lastBackupTime).TotalDays)
                        }
                    }
                    catch {
                        Write-Verbose "    Could not retrieve last backup time for ${DisplayName}: $_"
                    }
                }

                # Risk rating
                $riskResult = Get-RiskSeverity `
                    -WorkloadCriticality     $criticality `
                    -WorkloadEnvironment     $environment `
                    -IsProtected             $isProtected `
                    -PolicyAdequate          $policyAdequate `
                    -PolicyInadequacyReason  $policyInadequacyReason `
                    -IsHealthy               $isHealthy `
                    -HealthIssueReason       $healthIssueReason `
                    -BackupAgeInDays         $backupAgeInDays `
                    -StalenessCriticalDays   $StaleCrit `
                    -StalenessHighDays       $StaleHigh

                return [pscustomobject]@{
                    SubscriptionName       = $SubName
                    SubscriptionId         = $SubId
                    WorkloadId             = $ResourceId
                    WorkloadName           = $DisplayName
                    WorkloadType           = $WorkloadType
                    ResourceGroup          = if ($Resource.ResourceGroupName) { $Resource.ResourceGroupName } else { "" }
                    Location               = if ($Resource.Location) { $Resource.Location } else { "" }
                    WorkloadCriticality    = $criticality
                    WorkloadEnvironment    = $environment
                    IsProtected            = $isProtected
                    IsHealthy              = $isHealthy
                    PolicyAdequate         = $policyAdequate
                    PolicyInadequacyReason = $policyInadequacyReason
                    VaultName              = $vaultName
                    BackupPolicyName       = $backupPolicyName
                    RetentionSummary       = $retentionSummary
                    LastSuccessfulBackup   = $lastSuccessfulBackup
                    BackupAgeInDays        = $backupAgeInDays
                    Severity               = $riskResult.Severity
                    RiskReason             = $riskResult.Reason
                    WhyItMatters           = $riskResult.WhyItMatters
                    ImpactCategory         = $riskResult.Impact.Category
                    ImpactLevel            = $riskResult.Impact.Level
                    RemediationAction      = $riskResult.Action
                }
            }

            # ── Virtual Machines ──────────────────────────────────────────────────
            try {
                $vms = @(Get-AzVM -ErrorAction Stop)
                foreach ($vm in $vms) {
                    $finding = Invoke-WorkloadBackupAssessment `
                        -Resource          $vm `
                        -ResourceId        $vm.Id `
                        -WorkloadType      "VM" `
                        -DisplayName       $vm.Name `
                        -ProtectedItemMap  $protectedItemMap `
                        -SubName           $sub.Name `
                        -SubId             $sub.Id `
                        -CritTagName       $CriticalityTagName `
                        -EnvTagName        $EnvironmentTagName `
                        -ProdTagVals       $ProductionTagValues `
                        -VmRetCrit         $MinVMRetentionDaysCritical `
                        -VmRetHigh         $MinVMRetentionDaysHigh `
                        -SqlLogMax         $MaxSQLLogBackupIntervalMinutes `
                        -StaleCrit         $MaxBackupStalenessDaysCritical `
                        -StaleHigh         $MaxBackupStalenessDaysHigh

                    $allFindings += $finding
                    $subWorkloadCount++
                    if ($finding.IsProtected) { $subProtectedCount++ }

                    if (-not $coverageByType.ContainsKey("VM")) { $coverageByType["VM"] = @{ Total = 0; Protected = 0 } }
                    $coverageByType["VM"].Total++
                    if ($finding.IsProtected) { $coverageByType["VM"].Protected++ }

                    if (-not $workloadTypeDist.ContainsKey("VM")) { $workloadTypeDist["VM"] = 0 }
                    $workloadTypeDist["VM"]++

                    if (-not $riskDistribution.ContainsKey($finding.Severity)) { $riskDistribution[$finding.Severity] = 0 }
                    $riskDistribution[$finding.Severity]++
                }
            }
            catch {
                Write-Verbose "  VM discovery failed for $($sub.Name): $_"
            }

            # ── SQL Databases ─────────────────────────────────────────────────────
            try {
                $sqlServers = @(Get-AzSqlServer -ErrorAction Stop)
                foreach ($srv in $sqlServers) {
                    $dbs = @(Get-AzSqlDatabase -ServerName $srv.ServerName -ResourceGroupName $srv.ResourceGroupName -ErrorAction SilentlyContinue |
                        Where-Object { $_.DatabaseName -ne "master" })
                    foreach ($db in $dbs) {
                        # Synthesize a resource object compatible with our helper
                        $dbResource = [pscustomobject]@{
                            ResourceGroupName = $db.ResourceGroupName
                            Location          = $db.Location
                            Tags              = $db.Tags
                        }
                        $finding = Invoke-WorkloadBackupAssessment `
                            -Resource          $dbResource `
                            -ResourceId        $db.ResourceId `
                            -WorkloadType      "SQLDatabase" `
                            -DisplayName       "$($srv.ServerName)/$($db.DatabaseName)" `
                            -ProtectedItemMap  $protectedItemMap `
                            -SubName           $sub.Name `
                            -SubId             $sub.Id `
                            -CritTagName       $CriticalityTagName `
                            -EnvTagName        $EnvironmentTagName `
                            -ProdTagVals       $ProductionTagValues `
                            -VmRetCrit         $MinVMRetentionDaysCritical `
                            -VmRetHigh         $MinVMRetentionDaysHigh `
                            -SqlLogMax         $MaxSQLLogBackupIntervalMinutes `
                            -StaleCrit         $MaxBackupStalenessDaysCritical `
                            -StaleHigh         $MaxBackupStalenessDaysHigh

                        $allFindings += $finding
                        $subWorkloadCount++
                        if ($finding.IsProtected) { $subProtectedCount++ }

                        if (-not $coverageByType.ContainsKey("SQLDatabase")) { $coverageByType["SQLDatabase"] = @{ Total = 0; Protected = 0 } }
                        $coverageByType["SQLDatabase"].Total++
                        if ($finding.IsProtected) { $coverageByType["SQLDatabase"].Protected++ }

                        if (-not $workloadTypeDist.ContainsKey("SQLDatabase")) { $workloadTypeDist["SQLDatabase"] = 0 }
                        $workloadTypeDist["SQLDatabase"]++

                        if (-not $riskDistribution.ContainsKey($finding.Severity)) { $riskDistribution[$finding.Severity] = 0 }
                        $riskDistribution[$finding.Severity]++
                    }
                }
            }
            catch {
                Write-Verbose "  SQL Database discovery failed for $($sub.Name): $_"
            }

            # ── SQL Managed Instances ─────────────────────────────────────────────
            try {
                $managedInstances = @(Get-AzSqlInstance -ErrorAction Stop)
                foreach ($mi in $managedInstances) {
                    $miDbs = @(Get-AzSqlInstanceDatabase -InstanceName $mi.ManagedInstanceName -ResourceGroupName $mi.ResourceGroupName -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -ne "master" })
                    foreach ($mdb in $miDbs) {
                        $mdbResource = [pscustomobject]@{
                            ResourceGroupName = $mi.ResourceGroupName
                            Location          = $mi.Location
                            Tags              = $mi.Tags
                        }
                        $finding = Invoke-WorkloadBackupAssessment `
                            -Resource          $mdbResource `
                            -ResourceId        $mdb.Id `
                            -WorkloadType      "SQLMI" `
                            -DisplayName       "$($mi.ManagedInstanceName)/$($mdb.Name)" `
                            -ProtectedItemMap  $protectedItemMap `
                            -SubName           $sub.Name `
                            -SubId             $sub.Id `
                            -CritTagName       $CriticalityTagName `
                            -EnvTagName        $EnvironmentTagName `
                            -ProdTagVals       $ProductionTagValues `
                            -VmRetCrit         $MinVMRetentionDaysCritical `
                            -VmRetHigh         $MinVMRetentionDaysHigh `
                            -SqlLogMax         $MaxSQLLogBackupIntervalMinutes `
                            -StaleCrit         $MaxBackupStalenessDaysCritical `
                            -StaleHigh         $MaxBackupStalenessDaysHigh

                        $allFindings += $finding
                        $subWorkloadCount++
                        if ($finding.IsProtected) { $subProtectedCount++ }

                        if (-not $coverageByType.ContainsKey("SQLMI")) { $coverageByType["SQLMI"] = @{ Total = 0; Protected = 0 } }
                        $coverageByType["SQLMI"].Total++
                        if ($finding.IsProtected) { $coverageByType["SQLMI"].Protected++ }

                        if (-not $workloadTypeDist.ContainsKey("SQLMI")) { $workloadTypeDist["SQLMI"] = 0 }
                        $workloadTypeDist["SQLMI"]++

                        if (-not $riskDistribution.ContainsKey($finding.Severity)) { $riskDistribution[$finding.Severity] = 0 }
                        $riskDistribution[$finding.Severity]++
                    }
                }
            }
            catch {
                Write-Verbose "  SQL Managed Instance discovery failed for $($sub.Name): $_"
            }

            # ── Azure Files ───────────────────────────────────────────────────────
            try {
                $storageAccounts = @(Get-AzStorageAccount -ErrorAction Stop)
                foreach ($sa in $storageAccounts) {
                    try {
                        $ctx2 = $sa.Context
                        $shares = @(Get-AzStorageShare -Context $ctx2 -ErrorAction SilentlyContinue | Where-Object { $_.IsSnapshot -eq $false })
                        foreach ($share in $shares) {
                            $shareId = "$($sa.Id)/fileServices/default/shares/$($share.Name)"
                            $saResource = [pscustomobject]@{
                                ResourceGroupName = $sa.ResourceGroupName
                                Location          = $sa.Location
                                Tags              = $sa.Tags
                            }
                            $finding = Invoke-WorkloadBackupAssessment `
                                -Resource          $saResource `
                                -ResourceId        $shareId `
                                -WorkloadType      "AzureFiles" `
                                -DisplayName       "$($sa.StorageAccountName)/$($share.Name)" `
                                -ProtectedItemMap  $protectedItemMap `
                                -SubName           $sub.Name `
                                -SubId             $sub.Id `
                                -CritTagName       $CriticalityTagName `
                                -EnvTagName        $EnvironmentTagName `
                                -ProdTagVals       $ProductionTagValues `
                                -VmRetCrit         $MinVMRetentionDaysCritical `
                                -VmRetHigh         $MinVMRetentionDaysHigh `
                                -SqlLogMax         $MaxSQLLogBackupIntervalMinutes `
                                -StaleCrit         $MaxBackupStalenessDaysCritical `
                                -StaleHigh         $MaxBackupStalenessDaysHigh

                            $allFindings += $finding
                            $subWorkloadCount++
                            if ($finding.IsProtected) { $subProtectedCount++ }

                            if (-not $coverageByType.ContainsKey("AzureFiles")) { $coverageByType["AzureFiles"] = @{ Total = 0; Protected = 0 } }
                            $coverageByType["AzureFiles"].Total++
                            if ($finding.IsProtected) { $coverageByType["AzureFiles"].Protected++ }

                            if (-not $workloadTypeDist.ContainsKey("AzureFiles")) { $workloadTypeDist["AzureFiles"] = 0 }
                            $workloadTypeDist["AzureFiles"]++

                            if (-not $riskDistribution.ContainsKey($finding.Severity)) { $riskDistribution[$finding.Severity] = 0 }
                            $riskDistribution[$finding.Severity]++
                        }
                    }
                    catch {
                        Write-Verbose "    Could not enumerate shares for storage account '$($sa.StorageAccountName)': $_"
                    }
                }
            }
            catch {
                Write-Verbose "  Azure Files discovery failed for $($sub.Name): $_"
            }

            # ── Per-subscription result ───────────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Workloads: $subWorkloadCount  Protected: $subProtectedCount  Unprotected: $($subWorkloadCount - $subProtectedCount)" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Workloads: $subWorkloadCount  Protected: $subProtectedCount"
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
    $totalWL = $allFindings.Count
    $totalProt = @($allFindings | Where-Object { $_.IsProtected }).Count
    $covPct = if ($totalWL -gt 0) { [math]::Round(($totalProt / $totalWL) * 100, 1) } else { 0 }

    Write-BackupSummary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Total Workloads Assessed"    = $totalWL
            "Protected Workloads"         = $totalProt
            "Unprotected Workloads"       = ($totalWL - $totalProt)
            "Coverage Percentage"         = "$covPct%"
            "Critical Findings"           = @($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
            "High Findings"               = @($allFindings | Where-Object { $_.Severity -eq "High" }).Count
            "Medium Findings"             = @($allFindings | Where-Object { $_.Severity -eq "Medium" }).Count
            "Total Vaults Found"          = $allVaults.Count
            "Execution Time"              = $duration
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
                    SubscriptionName, SubscriptionId, WorkloadName, WorkloadType, ResourceGroup, Location,
                WorkloadCriticality, WorkloadEnvironment, IsProtected, IsHealthy, PolicyAdequate,
                VaultName, BackupPolicyName, RetentionSummary, LastSuccessfulBackup, BackupAgeInDays,
                Severity, RiskReason, WhyItMatters, ImpactCategory, ImpactLevel, RemediationAction,
                PolicyInadequacyReason |
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
                Scope                    = "$scopeText ($subCount found)"
                CriticalityTagName       = $CriticalityTagName
                EnvironmentTagName       = $EnvironmentTagName
                ProductionTagValues      = $ProductionTagValues -join ", "
                MinVMRetentionCritical   = $MinVMRetentionDaysCritical
                MinVMRetentionHigh       = $MinVMRetentionDaysHigh
                MaxSQLLogIntervalMinutes = $MaxSQLLogBackupIntervalMinutes
                MaxStalenessCritical     = $MaxBackupStalenessDaysCritical
                MaxStalenessHigh         = $MaxBackupStalenessDaysHigh
                ExportEnabled            = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime                 = $duration
            }

            $htmlContent = Generate-BackupCoverageHtml `
                -SessionInfo             $sessionInfo `
                -ScanParameters          $scanParams `
                -Findings                $allFindings `
                -Vaults                  $allVaults `
                -SubscriptionResults     $subscriptionResults `
                -GeneratedOn             (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -RiskDistribution        $riskDistribution `
                -WorkloadTypeDistribution $workloadTypeDist `
                -CoverageByType          $coverageByType

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
            Select-Object SubscriptionName, WorkloadName, WorkloadType, ResourceGroup,
            WorkloadCriticality, WorkloadEnvironment, IsProtected, Severity,
            LastSuccessfulBackup, BackupAgeInDays, ImpactCategory, ImpactLevel |
            Out-GridView -Title "Azure Backup Coverage Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No workloads found in the targeted subscriptions." -ForegroundColor Yellow
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
