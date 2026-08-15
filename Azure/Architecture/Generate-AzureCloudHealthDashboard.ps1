<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 14 August 2026
Modified-On     : 14 August 2026

.SYNOPSIS
    Combines Security, Governance, Resilience, Operations, and Cost into a single
    Azure estate scorecard with pillar scores, RAG ratings, and an interactive HTML dashboard.

.DESCRIPTION
    Generate-AzureCloudHealthDashboard evaluates the Azure estate across five health pillars:

        Security    (30%) — Defender for Cloud, secure score, Key Vault, NSG posture
        Governance  (20%) — Policy compliance, RBAC, resource locks, tagging
        Resilience  (20%) — Backup coverage, zone distribution, Basic SKU usage
        Operations  (15%) — Diagnostic settings, Activity Log alerts, Log Analytics
        Cost        (15%) — Budget alerts, orphaned resources, advisor recommendations

    Each pillar collects data from multiple Azure sources independently (no dependency
    on other assessment scripts). Where data is unavailable or permissions are insufficient,
    the metric is marked "Not Assessed" and assessment continues without failure.

    Assessment layers (logically separated):
        1. Azure Data Collection  — per-pillar collector functions
        2. Metric Evaluation      — measurable health indicators per pillar
        3. Scoring Engine         — 0–100 pillar score + weighted overall estate score
        4. Results Aggregation    — structured PillarResult objects
        5. HTML Presentation      — Generate-CloudHealthHtml (presentation only)

    Pillar weights: Security 30% | Governance 20% | Resilience 20% | Operations 15% | Cost 15%

    RAG thresholds: Green ≥ 71 | Amber 41–70 | Red ≤ 40

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan.

.PARAMETER ExportToCsv
    Switch. Exports all pillar metrics to a CSV alongside the HTML dashboard.

.PARAMETER OutputPath
    Base output path. HTML dashboard written here (.html). CSV alongside (.csv).
    Default: C:\Temp\AzureCloudHealthDashboard.html

.INPUTS
    None. Does not accept pipeline input.

.OUTPUTS
    None to the pipeline. Always writes an HTML dashboard to -OutputPath.
    Optionally writes a CSV when -ExportToCsv is specified.

.EXAMPLE
    Generate-AzureCloudHealthDashboard -AllSubscriptions

.EXAMPLE
    Generate-AzureCloudHealthDashboard -AllSubscriptions -ExportToCsv

.EXAMPLE
    Generate-AzureCloudHealthDashboard -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Generate-AzureCloudHealthDashboard -AllSubscriptions -ExportToCsv -OutputPath "C:\Reports\CloudHealth.html"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (14-Aug-2026) - Initial release. Five-pillar health assessment:
                            Security, Governance, Resilience, Operations, Cost.
                            Weighted 0–100 estate score with RAG rating.
                            CSV export and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell modules: Az.Accounts, Az.Resources, Az.Security,
           Az.Network, Az.Compute, Az.Storage, Az.Monitor, Az.RecoveryServices,
           Az.OperationalInsights, Az.Advisor.
           Installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at subscription scope.
        4. Security Reader or higher for Defender for Cloud data.
           Metrics marked "Not Assessed" if permission is absent.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Defender for Cloud Secure Score requires Microsoft.Security/securescores/read.
          Assessment continues gracefully if unavailable.
        - Azure Advisor recommendations may take time on large subscriptions.
          Use -SubscriptionIds to limit scope where needed.
        - Backup item enumeration requires Recovery Services Vault context per vault,
          which can be slow in environments with many vaults.
        - Default -OutputPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -OutputPath on macOS/Linux PowerShell 7.
        - This script is self-contained for V1. Common collection logic may be
          extracted to shared modules in future versions without breaking changes.

.LINK
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls
    https://learn.microsoft.com/en-us/azure/governance/policy/overview
    https://learn.microsoft.com/en-us/azure/backup/backup-overview
    https://learn.microsoft.com/en-us/azure/azure-monitor/overview
    https://learn.microsoft.com/en-us/azure/cost-management-billing/

#>


#region ── [ Helper Functions — Console Output ] ──────────────────────────────

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
    Write-CenteredText "Azure Cloud Health Dashboard v1.0" -Color White
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
        $valColor = if ([string]::IsNullOrWhiteSpace($value)) { $value = "None"; "DarkGray" } else { "White" }
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-ScanProgress {
    Write-Host ""
    Write-Host "  Assessing Subscriptions" -ForegroundColor Cyan
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

Function Write-HealthSummary {
    param([hashtable]$Data)
    Write-Host ""
    Write-Host "  Health Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys) {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(36) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-PillarBreakdown {
    param([array]$PillarResults)
    if (@($PillarResults).Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Pillar Health Scores" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $colorMap = @{ "Red" = "Red"; "Amber" = "Yellow"; "Green" = "Green" }

    foreach ($p in $PillarResults) {
        $color = if ($colorMap.ContainsKey($p.RagStatus)) { $colorMap[$p.RagStatus] } else { "White" }
        $bar = ""
        $filled = [math]::Floor($p.Score / 5)
        $empty = 20 - $filled
        $bar = ("█" * $filled) + ("░" * $empty)

        Write-Host "  " -NoNewline
        Write-Host $p.Pillar.PadRight(14) -NoNewline -ForegroundColor White
        Write-Host $bar -NoNewline -ForegroundColor $color
        Write-Host "  $($p.Score)/100  $($p.RagStatus)" -ForegroundColor $color
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

#endregion


#region ── [ Scoring Engine ] ──────────────────────────────────────────────────

# Pillar weight definitions — single source of truth.
# Future: externalize to JSON/CSV without changing scoring logic.
$Script:PillarWeights = @{
    Security   = 0.30
    Governance = 0.20
    Resilience = 0.20
    Operations = 0.15
    Cost       = 0.15
}

Function Get-RagStatus {
    param([int]$Score)
    if ($Score -le 40) { return "Red" }
    elseif ($Score -le 70) { return "Amber" }
    else { return "Green" }
}

Function Get-RagLabel {
    param([int]$Score)
    if ($Score -le 40) { return "Critical Risk" }
    elseif ($Score -le 70) { return "Needs Attention" }
    else { return "Healthy" }
}

Function Invoke-PillarScore {
    # Calculates a 0–100 score from a collection of metric objects.
    # Each metric: Name, Passed (bool), Weight (1–10), Status ("Assessed"/"Not Assessed"), Value (string)
    param([array]$Metrics)

    $assessed = @($Metrics | Where-Object { $_.Status -eq "Assessed" })
    if ($assessed.Count -eq 0) { return 50 }   # neutral when nothing assessed

    $totalWeight = [int]($assessed | Measure-Object -Property Weight -Sum | Select-Object -ExpandProperty Sum)
    $passedWeight = [int]($assessed | Where-Object { $_.Passed -eq $true } | Measure-Object -Property Weight -Sum | Select-Object -ExpandProperty Sum)

    return [math]::Round(($passedWeight / [math]::Max($totalWeight, 1)) * 100)
}

Function Invoke-EstateScore {
    param([array]$PillarResults)

    $score = 0
    foreach ($p in $PillarResults) {
        $weight = $Script:PillarWeights[$p.Pillar]
        $score += $p.Score * $weight
    }
    return [math]::Round($score)
}

Function New-Metric {
    param(
        [string]$Name,
        [bool]$Passed,
        [int]$Weight,
        [string]$Status = "Assessed",   # "Assessed" | "Not Assessed"
        [string]$Value = "",
        [string]$Detail = ""
    )
    return [pscustomobject]@{
        Name   = $Name
        Passed = $Passed
        Weight = $Weight
        Status = $Status
        Value  = $Value
        Detail = $Detail
    }
}

Function New-PillarResult {
    param(
        [string]$Pillar,
        [int]$Score,
        [array]$Metrics,
        [array]$KeyFindings,
        [string]$SubscriptionId,
        [string]$SubscriptionName
    )
    return [pscustomobject]@{
        Pillar           = $Pillar
        Score            = $Score
        RagStatus        = Get-RagStatus -Score $Score
        RagLabel         = Get-RagLabel  -Score $Score
        Metrics          = $Metrics
        KeyFindings      = $KeyFindings
        SubscriptionId   = $SubscriptionId
        SubscriptionName = $SubscriptionName
    }
}

#endregion


#region ── [ Pillar Collectors ] ──────────────────────────────────────────────

Function Get-SecurityPillar {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName
    )

    $metrics = @()
    $keyFindings = @()

    # SEC-M1: Defender for Cloud Secure Score
    try {
        $scores = @(Get-AzSecuritySecureScore -ErrorAction Stop)
        $builtIn = $scores | Where-Object { $_.Name -eq "ascScore" }
        if ($builtIn) {
            $pct = [math]::Round($builtIn.CurrentScore / [math]::Max($builtIn.MaxScore, 1) * 100)
            $passed = $pct -ge 70
            $metrics += New-Metric -Name "Defender Secure Score" -Passed $passed -Weight 10 `
                -Value "$($builtIn.CurrentScore) / $($builtIn.MaxScore) ($pct%)" `
                -Detail "Secure score reflects the current security posture across active recommendations"
            if (-not $passed) { $keyFindings += "Defender Secure Score below 70% — review active security recommendations" }
        }
        else {
            $metrics += New-Metric -Name "Defender Secure Score" -Passed $false -Weight 10 `
                -Status "Not Assessed" -Value "Not available" -Detail "ascScore not returned"
        }
    }
    catch {
        $metrics += New-Metric -Name "Defender Secure Score" -Passed $false -Weight 10 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # SEC-M2: Defender for Cloud Standard tier — key resource types
    try {
        $pricings = @(Get-AzSecurityPricing -ErrorAction Stop)
        $keyTypes = @("VirtualMachines", "StorageAccounts", "KeyVaults", "SqlServers", "AppServices")
        $freeCount = @($pricings | Where-Object { $keyTypes -contains $_.Name -and $_.PricingTier -eq "Free" }).Count
        $passed = $freeCount -eq 0
        $metrics += New-Metric -Name "Defender Plans (Standard)" -Passed $passed -Weight 9 `
            -Value "$freeCount key plan(s) on Free tier" `
            -Detail "VMs, Storage, Key Vaults, SQL, App Services checked"
        if (-not $passed) { $keyFindings += "$freeCount Defender plan(s) on Free tier — threat detection disabled for those resource types" }
    }
    catch {
        $metrics += New-Metric -Name "Defender Plans (Standard)" -Passed $false -Weight 9 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # SEC-M3: Security contacts configured
    try {
        $contacts = @(Get-AzSecurityContact -ErrorAction Stop)
        $hasEmail = $contacts.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace(($contacts | Select-Object -First 1).Email)
        $metrics += New-Metric -Name "Security Contact Configured" -Passed $hasEmail -Weight 5 `
            -Value (if ($hasEmail) { "Configured" } else { "Not configured" }) `
            -Detail "Security contact receives high-severity Defender alerts"
        if (-not $hasEmail) { $keyFindings += "No security contact email — critical Defender alerts may go unnoticed" }
    }
    catch {
        $metrics += New-Metric -Name "Security Contact Configured" -Passed $false -Weight 5 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # SEC-M4: NSGs — no open management ports from Internet
    try {
        $nsgs = @(Get-AzNetworkSecurityGroup -ErrorAction Stop)
        $openMgmt = @($nsgs | Where-Object {
                $_.SecurityRules | Where-Object {
                    $_.Direction -eq "Inbound" -and $_.Access -eq "Allow" -and
                    ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "0.0.0.0/0" -or $_.SourceAddressPrefix -eq "Internet") -and
                    ($_.DestinationPortRange -eq "3389" -or $_.DestinationPortRange -eq "22" -or $_.DestinationPortRange -eq "*")
                }
            })
        $passed = $openMgmt.Count -eq 0
        $metrics += New-Metric -Name "No Open Management Ports" -Passed $passed -Weight 9 `
            -Value "$($openMgmt.Count) NSG(s) with open RDP/SSH from Internet" `
            -Detail "NSGs checked for inbound * → 3389 or 22 rules"
        if (-not $passed) { $keyFindings += "$($openMgmt.Count) NSG(s) expose RDP/SSH to the Internet — critical attack surface" }
    }
    catch {
        $metrics += New-Metric -Name "No Open Management Ports" -Passed $false -Weight 9 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # SEC-M5: Key Vault soft delete and purge protection
    try {
        $vaults = @(Get-AzKeyVault -ErrorAction Stop)
        $noSoftDel = 0
        foreach ($kvRef in $vaults) {
            try {
                $kv = Get-AzKeyVault -VaultName $kvRef.VaultName -ResourceGroupName $kvRef.ResourceGroupName -ErrorAction Stop
                if (-not $kv.EnableSoftDelete) { $noSoftDel++ }
            }
            catch { }
        }
        $passed = $noSoftDel -eq 0
        $metrics += New-Metric -Name "Key Vault Soft Delete" -Passed $passed -Weight 6 `
            -Value "$noSoftDel vault(s) without soft delete" `
            -Detail "Soft delete prevents permanent secret/key loss"
        if (-not $passed) { $keyFindings += "$noSoftDel Key Vault(s) have soft delete disabled — data loss risk on accidental deletion" }
    }
    catch {
        $metrics += New-Metric -Name "Key Vault Soft Delete" -Passed $false -Weight 6 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # SEC-M6: Storage accounts — public blob access blocked
    try {
        $accounts = @(Get-AzStorageAccount -ErrorAction Stop)
        $publicBlob = @($accounts | Where-Object { $_.AllowBlobPublicAccess -eq $true }).Count
        $passed = $publicBlob -eq 0
        $metrics += New-Metric -Name "Storage Public Blob Blocked" -Passed $passed -Weight 8 `
            -Value "$publicBlob account(s) allow public blob access" `
            -Detail "AllowBlobPublicAccess checked on all storage accounts"
        if (-not $passed) { $keyFindings += "$publicBlob storage account(s) allow public blob access — data exposure risk" }
    }
    catch {
        $metrics += New-Metric -Name "Storage Public Blob Blocked" -Passed $false -Weight 8 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    $score = Invoke-PillarScore -Metrics $metrics
    return New-PillarResult -Pillar "Security" -Score $score -Metrics $metrics `
        -KeyFindings $keyFindings -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName
}

Function Get-GovernancePillar {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName
    )

    $metrics = @()
    $keyFindings = @()

    # GOV-M1: Policy compliance — non-compliant assignments
    try {
        $assignments = @(Get-AzPolicyAssignment -ErrorAction Stop)
        $nonCompliant = 0
        $totalAssessed = 0
        foreach ($a in $assignments) {
            try {
                $states = @(Get-AzPolicyState -PolicyAssignmentName $a.Name -ErrorAction Stop |
                    Where-Object { $_.ComplianceState -eq "NonCompliant" })
                $nonCompliant += $states.Count
                $totalAssessed++
            }
            catch { }
        }
        $passed = $nonCompliant -eq 0
        $metrics += New-Metric -Name "Policy Compliance" -Passed $passed -Weight 9 `
            -Value "$nonCompliant non-compliant resource(s) across $totalAssessed assignment(s)" `
            -Detail "Get-AzPolicyState checked per assignment"
        if (-not $passed) { $keyFindings += "$nonCompliant non-compliant resource(s) found — review policy assignments and remediation tasks" }
    }
    catch {
        $metrics += New-Metric -Name "Policy Compliance" -Passed $false -Weight 9 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # GOV-M2: Direct privileged RBAC at subscription scope
    try {
        $scope = "/subscriptions/$SubscriptionId"
        $assigns = @(Get-AzRoleAssignment -Scope $scope -ErrorAction Stop)
        $directPriv = @($assigns | Where-Object {
                $_.Scope -eq $scope -and
                ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor") -and
                $_.ObjectType -eq "User"
            }).Count
        $passed = $directPriv -eq 0
        $metrics += New-Metric -Name "No Direct Privileged Users" -Passed $passed -Weight 8 `
            -Value "$directPriv direct user Owner/Contributor assignment(s)" `
            -Detail "Direct user assignments at subscription scope bypass group-based governance"
        if (-not $passed) { $keyFindings += "$directPriv user(s) with direct Owner/Contributor at subscription scope — use groups + PIM" }
    }
    catch {
        $metrics += New-Metric -Name "No Direct Privileged Users" -Passed $false -Weight 8 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # GOV-M3: Resource locks present
    try {
        $locks = @(Get-AzResourceLock -ErrorAction Stop)
        $passed = $locks.Count -gt 0
        $metrics += New-Metric -Name "Resource Locks Present" -Passed $passed -Weight 6 `
            -Value "$($locks.Count) management lock(s)" `
            -Detail "Locks at subscription or resource group scope protect production resources"
        if (-not $passed) { $keyFindings += "No management locks — production resources unprotected from accidental deletion" }
    }
    catch {
        $metrics += New-Metric -Name "Resource Locks Present" -Passed $false -Weight 6 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # GOV-M4: Resource group tagging coverage
    try {
        $rgs = @(Get-AzResourceGroup -ErrorAction Stop)
        $untagged = @($rgs | Where-Object { $null -eq $_.Tags -or $_.Tags.Count -eq 0 }).Count
        $coverage = if ($rgs.Count -gt 0) { [math]::Round((($rgs.Count - $untagged) / $rgs.Count) * 100) } else { 100 }
        $passed = $coverage -ge 80
        $metrics += New-Metric -Name "Resource Group Tag Coverage" -Passed $passed -Weight 5 `
            -Value "$coverage% tagged ($untagged untagged out of $($rgs.Count))" `
            -Detail "Tagging coverage threshold: 80%"
        if (-not $passed) { $keyFindings += "Only $coverage% of resource groups tagged — cost attribution and governance automation impaired" }
    }
    catch {
        $metrics += New-Metric -Name "Resource Group Tag Coverage" -Passed $false -Weight 5 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # GOV-M5: Guest user privileged roles
    try {
        $scope = "/subscriptions/$SubscriptionId"
        $assigns = @(Get-AzRoleAssignment -Scope $scope -ErrorAction Stop)
        $guestPriv = @($assigns | Where-Object {
                ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor") -and
                $_.SignInName -like "*#EXT#*"
            }).Count
        $passed = $guestPriv -eq 0
        $metrics += New-Metric -Name "No Guest Privileged Access" -Passed $passed -Weight 7 `
            -Value "$guestPriv guest account(s) with Owner/Contributor" `
            -Detail "External identities should not hold privileged subscription roles"
        if (-not $passed) { $keyFindings += "$guestPriv guest account(s) hold privileged roles — external identity risk" }
    }
    catch {
        $metrics += New-Metric -Name "No Guest Privileged Access" -Passed $false -Weight 7 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    $score = Invoke-PillarScore -Metrics $metrics
    return New-PillarResult -Pillar "Governance" -Score $score -Metrics $metrics `
        -KeyFindings $keyFindings -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName
}

Function Get-ResiliencePillar {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName
    )

    $metrics = @()
    $keyFindings = @()

    # RES-M1: Recovery Services vault exists
    try {
        $vaults = @(Get-AzRecoveryServicesVault -ErrorAction Stop)
        $passed = $vaults.Count -gt 0
        $metrics += New-Metric -Name "Recovery Services Vault" -Passed $passed -Weight 9 `
            -Value "$($vaults.Count) vault(s)" `
            -Detail "Recovery Services vault required for Azure Backup and Site Recovery"
        if (-not $passed) { $keyFindings += "No Recovery Services vault — Azure Backup and Site Recovery unavailable" }
    }
    catch {
        $metrics += New-Metric -Name "Recovery Services Vault" -Passed $false -Weight 9 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # RES-M2: VM backup coverage
    try {
        $vms = @(Get-AzVM -ErrorAction Stop)
        $protectedCount = 0

        try {
            $vaults2 = @(Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue)
            foreach ($vault in $vaults2) {
                try {
                    Set-AzRecoveryServicesVaultContext -Vault $vault -ErrorAction SilentlyContinue
                    $items = @(Get-AzRecoveryServicesBackupItem -WorkloadType AzureVM -BackupManagementType AzureVM -ErrorAction SilentlyContinue)
                    $protectedCount += $items.Count
                }
                catch { }
            }
        }
        catch { }

        $coverage = if ($vms.Count -gt 0) { [math]::Round(([math]::Min($protectedCount, $vms.Count) / $vms.Count) * 100) } else { 100 }
        $passed = $coverage -ge 80
        $metrics += New-Metric -Name "VM Backup Coverage" -Passed $passed -Weight 9 `
            -Value "$coverage% ($protectedCount protected of $($vms.Count) VMs)" `
            -Detail "Backup coverage threshold: 80% of VMs"
        if (-not $passed) { $keyFindings += "VM backup coverage is $coverage% — $($vms.Count - [math]::Min($protectedCount,$vms.Count)) VM(s) unprotected" }
    }
    catch {
        $metrics += New-Metric -Name "VM Backup Coverage" -Passed $false -Weight 9 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # RES-M3: No Basic SKU Load Balancers
    try {
        $basicLbs = @(Get-AzLoadBalancer -ErrorAction Stop | Where-Object { $_.Sku.Name -eq "Basic" }).Count
        $passed = $basicLbs -eq 0
        $metrics += New-Metric -Name "No Basic SKU Load Balancers" -Passed $passed -Weight 7 `
            -Value "$basicLbs Basic SKU Load Balancer(s)" `
            -Detail "Basic LB is being retired; no zone redundancy or SLA guarantee"
        if (-not $passed) { $keyFindings += "$basicLbs Basic SKU Load Balancer(s) — no zone redundancy, pending retirement" }
    }
    catch {
        $metrics += New-Metric -Name "No Basic SKU Load Balancers" -Passed $false -Weight 7 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # RES-M4: VMs with Availability Zone or Set
    try {
        $vms = @(Get-AzVM -ErrorAction Stop)
        $redundant = @($vms | Where-Object {
                ($null -ne $_.Zones -and $_.Zones.Count -gt 0) -or
                $null -ne $_.AvailabilitySetReference
            }).Count
        $coverage = if ($vms.Count -gt 0) { [math]::Round(($redundant / $vms.Count) * 100) } else { 100 }
        $passed = $coverage -ge 70
        $metrics += New-Metric -Name "VM Redundancy Coverage" -Passed $passed -Weight 7 `
            -Value "$coverage% ($redundant of $($vms.Count) VMs have zone/set)" `
            -Detail "VMs in Availability Zone or Availability Set"
        if (-not $passed) { $keyFindings += "Only $coverage% of VMs have zone or availability set redundancy" }
    }
    catch {
        $metrics += New-Metric -Name "VM Redundancy Coverage" -Passed $false -Weight 7 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # RES-M5: No Basic SKU Public IPs
    try {
        $basicPips = @(Get-AzPublicIpAddress -ErrorAction Stop | Where-Object { $_.Sku.Name -eq "Basic" }).Count
        $passed = $basicPips -eq 0
        $metrics += New-Metric -Name "No Basic SKU Public IPs" -Passed $passed -Weight 5 `
            -Value "$basicPips Basic SKU Public IP(s)" `
            -Detail "Basic Public IPs are open by default, not zone-redundant, pending retirement"
        if (-not $passed) { $keyFindings += "$basicPips Basic SKU Public IP(s) — security and resilience risk, pending retirement" }
    }
    catch {
        $metrics += New-Metric -Name "No Basic SKU Public IPs" -Passed $false -Weight 5 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    $score = Invoke-PillarScore -Metrics $metrics
    return New-PillarResult -Pillar "Resilience" -Score $score -Metrics $metrics `
        -KeyFindings $keyFindings -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName
}

Function Get-OperationsPillar {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName
    )

    $metrics = @()
    $keyFindings = @()

    # OPS-M1: Log Analytics Workspace exists
    try {
        $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop)
        $passed = $workspaces.Count -gt 0
        $metrics += New-Metric -Name "Log Analytics Workspace" -Passed $passed -Weight 9 `
            -Value "$($workspaces.Count) workspace(s)" `
            -Detail "Central workspace required for log aggregation, monitoring, and SIEM"
        if (-not $passed) { $keyFindings += "No Log Analytics Workspace — no centralised log collection or SIEM integration" }
    }
    catch {
        $metrics += New-Metric -Name "Log Analytics Workspace" -Passed $false -Weight 9 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # OPS-M2: Activity Log alerts configured
    try {
        $alerts = @(Get-AzActivityLogAlert -ErrorAction Stop)
        $passed = $alerts.Count -gt 0
        $metrics += New-Metric -Name "Activity Log Alerts" -Passed $passed -Weight 8 `
            -Value "$($alerts.Count) alert rule(s)" `
            -Detail "Activity Log alerts provide operational awareness for critical Azure events"
        if (-not $passed) { $keyFindings += "No Activity Log alerts — critical Azure platform events go unnotified" }
    }
    catch {
        $metrics += New-Metric -Name "Activity Log Alerts" -Passed $false -Weight 8 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # OPS-M3: Diagnostic settings coverage on VMs
    try {
        $vms = @(Get-AzVM -ErrorAction Stop)
        $withDiag = 0
        foreach ($vm in $vms) {
            try {
                $diag = @(Get-AzDiagnosticSetting -ResourceId $vm.Id -ErrorAction Stop)
                if ($diag.Count -gt 0) { $withDiag++ }
            }
            catch { }
        }
        $coverage = if ($vms.Count -gt 0) { [math]::Round(($withDiag / $vms.Count) * 100) } else { 100 }
        $passed = $coverage -ge 80
        $metrics += New-Metric -Name "VM Diagnostic Coverage" -Passed $passed -Weight 7 `
            -Value "$coverage% ($withDiag of $($vms.Count) VMs)" `
            -Detail "VMs with diagnostic settings sending to Log Analytics"
        if (-not $passed) { $keyFindings += "VM diagnostic coverage is $coverage% — guest OS logs not captured for remaining VMs" }
    }
    catch {
        $metrics += New-Metric -Name "VM Diagnostic Coverage" -Passed $false -Weight 7 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # OPS-M4: NSG flow logs
    try {
        $nsgs = @(Get-AzNetworkSecurityGroup -ErrorAction Stop)
        $withLogs = 0
        foreach ($nsg in $nsgs) {
            try {
                $diag = @(Get-AzDiagnosticSetting -ResourceId $nsg.Id -ErrorAction Stop)
                if ($diag.Count -gt 0) { $withLogs++ }
            }
            catch { }
        }
        $coverage = if ($nsgs.Count -gt 0) { [math]::Round(($withLogs / $nsgs.Count) * 100) } else { 100 }
        $passed = $coverage -ge 80
        $metrics += New-Metric -Name "NSG Diagnostic Coverage" -Passed $passed -Weight 6 `
            -Value "$coverage% ($withLogs of $($nsgs.Count) NSGs)" `
            -Detail "NSGs with flow logs / diagnostic settings enabled"
        if (-not $passed) { $keyFindings += "NSG diagnostic coverage is $coverage% — network traffic not logged for forensics" }
    }
    catch {
        $metrics += New-Metric -Name "NSG Diagnostic Coverage" -Passed $false -Weight 6 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # OPS-M5: Key Vault diagnostic settings
    try {
        $vaults = @(Get-AzKeyVault -ErrorAction Stop)
        $withDiag = 0
        foreach ($kv in $vaults) {
            try {
                $kvFull = Get-AzKeyVault -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName -ErrorAction Stop
                $diag = @(Get-AzDiagnosticSetting -ResourceId $kvFull.ResourceId -ErrorAction Stop)
                if ($diag.Count -gt 0) { $withDiag++ }
            }
            catch { }
        }
        $coverage = if ($vaults.Count -gt 0) { [math]::Round(($withDiag / $vaults.Count) * 100) } else { 100 }
        $passed = $coverage -ge 80
        $metrics += New-Metric -Name "Key Vault Diagnostic Coverage" -Passed $passed -Weight 6 `
            -Value "$coverage% ($withDiag of $($vaults.Count) Key Vaults)" `
            -Detail "Key Vault audit logs required for secret access monitoring"
        if (-not $passed) { $keyFindings += "Key Vault diagnostic coverage is $coverage% — secret access audit trail incomplete" }
    }
    catch {
        $metrics += New-Metric -Name "Key Vault Diagnostic Coverage" -Passed $false -Weight 6 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    $score = Invoke-PillarScore -Metrics $metrics
    return New-PillarResult -Pillar "Operations" -Score $score -Metrics $metrics `
        -KeyFindings $keyFindings -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName
}

Function Get-CostPillar {
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName
    )

    $metrics = @()
    $keyFindings = @()

    # COST-M1: Budget alerts configured
    try {
        $budgets = @(Get-AzConsumptionBudget -ErrorAction Stop)
        $passed = $budgets.Count -gt 0
        $metrics += New-Metric -Name "Budget Alerts Configured" -Passed $passed -Weight 8 `
            -Value "$($budgets.Count) budget(s)" `
            -Detail "Consumption budgets with alert thresholds at subscription scope"
        if (-not $passed) { $keyFindings += "No budget alerts — no financial boundary or spend notification configured" }
    }
    catch {
        $metrics += New-Metric -Name "Budget Alerts Configured" -Passed $false -Weight 8 `
            -Status "Not Assessed" -Value "Permission or API error (Az.Billing may be required)" -Detail $_.Exception.Message
    }

    # COST-M2: Orphaned managed disks
    try {
        $orphanDisks = @(Get-AzDisk -ErrorAction Stop | Where-Object { $_.DiskState -eq "Unattached" })
        $passed = $orphanDisks.Count -eq 0
        $totalSizeGb = [int]($orphanDisks | Measure-Object -Property DiskSizeGB -Sum | Select-Object -ExpandProperty Sum)
        $metrics += New-Metric -Name "No Orphaned Disks" -Passed $passed -Weight 7 `
            -Value "$($orphanDisks.Count) unattached disk(s) ($totalSizeGb GB wasted)" `
            -Detail "Unattached managed disks incur ongoing cost with no workload value"
        if (-not $passed) { $keyFindings += "$($orphanDisks.Count) orphaned disk(s) ($totalSizeGb GB) — ongoing cost with no workload value" }
    }
    catch {
        $metrics += New-Metric -Name "No Orphaned Disks" -Passed $false -Weight 7 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # COST-M3: Unattached Public IPs
    try {
        $orphanPips = @(Get-AzPublicIpAddress -ErrorAction Stop | Where-Object { $null -eq $_.IpConfiguration })
        $passed = $orphanPips.Count -eq 0
        $metrics += New-Metric -Name "No Orphaned Public IPs" -Passed $passed -Weight 5 `
            -Value "$($orphanPips.Count) unattached Public IP(s)" `
            -Detail "Unattached PIPs incur cost and expand attack surface unnecessarily"
        if (-not $passed) { $keyFindings += "$($orphanPips.Count) unattached Public IP(s) — wasted cost and expanded attack surface" }
    }
    catch {
        $metrics += New-Metric -Name "No Orphaned Public IPs" -Passed $false -Weight 5 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # COST-M4: Azure Advisor cost recommendations
    try {
        $costRecs = @(Get-AzAdvisorRecommendation -Category Cost -ErrorAction Stop)
        $passed = $costRecs.Count -eq 0
        $metrics += New-Metric -Name "No Advisor Cost Findings" -Passed $passed -Weight 6 `
            -Value "$($costRecs.Count) Advisor cost recommendation(s)" `
            -Detail "Azure Advisor cost recommendations identify rightsizing and reservation opportunities"
        if (-not $passed) { $keyFindings += "$($costRecs.Count) Advisor cost recommendation(s) — potential cost optimisation opportunities" }
    }
    catch {
        $metrics += New-Metric -Name "No Advisor Cost Findings" -Passed $false -Weight 6 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    # COST-M5: Empty resource groups (no resources)
    try {
        $rgs = @(Get-AzResourceGroup -ErrorAction Stop)
        $emptyRgs = 0
        foreach ($rg in $rgs) {
            try {
                $resources = @(Get-AzResource -ResourceGroupName $rg.ResourceGroupName -ErrorAction Stop)
                if ($resources.Count -eq 0) { $emptyRgs++ }
            }
            catch { }
        }
        $passed = $emptyRgs -eq 0
        $metrics += New-Metric -Name "No Empty Resource Groups" -Passed $passed -Weight 4 `
            -Value "$emptyRgs empty resource group(s)" `
            -Detail "Empty resource groups indicate abandoned workloads or ungoverned lifecycle"
        if (-not $passed) { $keyFindings += "$emptyRgs empty resource group(s) — potential abandoned workloads" }
    }
    catch {
        $metrics += New-Metric -Name "No Empty Resource Groups" -Passed $false -Weight 4 `
            -Status "Not Assessed" -Value "Permission or API error" -Detail $_.Exception.Message
    }

    $score = Invoke-PillarScore -Metrics $metrics
    return New-PillarResult -Pillar "Cost" -Score $score -Metrics $metrics `
        -KeyFindings $keyFindings -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName
}

#endregion


#region ── [ HTML Presentation Layer ] ────────────────────────────────────────

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Get-RagBadgeClass {
    param([string]$Rag)
    switch ($Rag) {
        "Red" { return "badge-red" }
        "Amber" { return "badge-amber" }
        "Green" { return "badge-green" }
        default { return "badge-muted" }
    }
}

Function Get-MetricPassClass {
    param([bool]$Passed, [string]$Status)
    if ($Status -eq "Not Assessed") { return "badge-muted" }
    if ($Passed) { return "badge-green" } else { return "badge-red" }
}

Function Get-MetricPassLabel {
    param([bool]$Passed, [string]$Status)
    if ($Status -eq "Not Assessed") { return "Not Assessed" }
    if ($Passed) { return "✓ Pass" } else { return "✗ Fail" }
}

Function Generate-CloudHealthHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [int]$EstateScore,
        [string]$EstateRag,
        [string]$EstateRagLabel,
        [array]$AggregatedPillars,       # one entry per pillar, averaged across subscriptions
        [array]$AllPillarResults,         # raw per-subscription pillar results
        [array]$SubscriptionResults,
        [string]$GeneratedOn
    )

    $ringColorVar = switch ($EstateRag) { "Red" { "var(--red)" }; "Amber" { "var(--amber)" }; default { "var(--green)" } }
    $ragBadge = Get-RagBadgeClass -Rag $EstateRag
    $subCount = $SubscriptionResults.Count

    # ── Pillar score cards ────────────────────────────────────────────────────
    $pillarCards = ""
    $pillarBarRows = ""
    $pillarOrder = @("Security", "Governance", "Resilience", "Operations", "Cost")
    $pillarIcons = @{ Security = "🔒"; Governance = "📋"; Resilience = "🛡️"; Operations = "📡"; Cost = "💰" }
    $pillarWeightPc = @{ Security = "30%"; Governance = "20%"; Resilience = "20%"; Operations = "15%"; Cost = "15%" }

    foreach ($pName in $pillarOrder) {
        $p = $AggregatedPillars | Where-Object { $_.Pillar -eq $pName }
        if (-not $p) { continue }

        $ragCls = Get-RagBadgeClass -Rag $p.RagStatus
        $barColor = switch ($p.RagStatus) { "Red" { "var(--red)" }; "Amber" { "var(--amber)" }; default { "var(--green)" } }
        $icon = $pillarIcons[$pName]
        $wt = $pillarWeightPc[$pName]

        $pillarCards += @"
      <div class="pillar-card">
        <div class="pillar-header">
          <span class="pillar-icon">$icon</span>
          <div>
            <div class="pillar-name">$(EscHtml $pName)</div>
            <div class="pillar-weight">Weight: $wt</div>
          </div>
          <span class="badge $ragCls" style="margin-left:auto">$(EscHtml $p.RagStatus)</span>
        </div>
        <div class="pillar-score-row">
          <span class="pillar-score-num" style="color:$barColor">$($p.Score)</span>
          <span class="pillar-score-denom">/ 100</span>
        </div>
        <div class="pillar-bar-track">
          <div class="pillar-bar-fill" data-pct="$($p.Score)" style="background:$barColor"></div>
        </div>
        <div class="pillar-label">$(EscHtml $p.RagLabel)</div>
      </div>
"@

        $pillarBarRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $pName)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$($p.Score)" style="background:$barColor"></div></div>
            <span class="bar-pct">$($p.Score) / 100</span>
          </div>
"@
    }

    # ── Metric detail rows (flat list for the Metrics page) ───────────────────
    $metricRows = ""
    $metricJson = "["
    $mIdx = 0
    foreach ($pr in $AllPillarResults) {
        foreach ($m in $pr.Metrics) {
            $passCls = Get-MetricPassClass  -Passed $m.Passed -Status $m.Status
            $passLabel = Get-MetricPassLabel  -Passed $m.Passed -Status $m.Status
            $shortVal = if ($m.Value.Length -gt 50) { EscHtml($m.Value.Substring(0, 47) + "...") } else { EscHtml $m.Value }

            $metricRows += @"
          <tr onclick="showMetricDetail($mIdx)">
            <td>$(EscHtml $pr.Pillar)</td>
            <td title="$(EscHtml $m.Name)">$(EscHtml $m.Name)</td>
            <td><span class="badge $passCls">$passLabel</span></td>
            <td>$($m.Weight)</td>
            <td>$(EscHtml $pr.SubscriptionName)</td>
            <td title="$(EscHtml $m.Value)">$shortVal</td>
          </tr>
"@
            $metricJson += "{" +
            """pillar"":""$(EscJ $pr.Pillar)""," +
            """name"":""$(EscJ $m.Name)""," +
            """passed"":$(if($m.Passed){"true"}else{"false"})," +
            """status"":""$(EscJ $m.Status)""," +
            """weight"":$($m.Weight)," +
            """sub"":""$(EscJ $pr.SubscriptionName)""," +
            """value"":""$(EscJ $m.Value)""," +
            """detail"":""$(EscJ $m.Detail)""" +
            "},"
            $mIdx++
        }
    }
    $metricJson = $metricJson.TrimEnd(",") + "]"

    # ── Key findings rows ─────────────────────────────────────────────────────
    $findingRows = ""
    foreach ($pr in ($AllPillarResults | Sort-Object { $Script:PillarWeights[$_.Pillar] } -Descending)) {
        foreach ($kf in $pr.KeyFindings) {
            $ragCls = Get-RagBadgeClass -Rag $pr.RagStatus
            $findingRows += @"
          <tr>
            <td>$(EscHtml $pr.Pillar)</td>
            <td><span class="badge $ragCls">$(EscHtml $pr.RagStatus)</span></td>
            <td>$(EscHtml $pr.SubscriptionName)</td>
            <td>$(EscHtml $kf)</td>
          </tr>
"@
        }
    }

    # ── Subscription result rows ───────────────────────────────────────────────
    $subRows = ""
    foreach ($s in $SubscriptionResults) {
        $icon = switch ($s.Status) { "Success" { "✓" }; "Error" { "✗" }; default { "•" } }
        $iconCls = switch ($s.Status) { "Success" { "c-green" }; "Error" { "c-red" }; default { "" } }
        $ragCls = Get-RagBadgeClass -Rag $s.EstateRag
        $pillarScoreHtml = ""
        foreach ($pName in $pillarOrder) {
            $pScore = $s.PillarScores[$pName]
            $pRag = if ($pScore -le 40) { "badge-red" } elseif ($pScore -le 70) { "badge-amber" } else { "badge-green" }
            $pillarScoreHtml += "<span class='badge $pRag' style='margin:1px 2px;font-size:10px'>$pName $pScore</span>"
        }
        $subRows += @"
          <div class="sub-row-detail">
            <div class="sub-row-top">
              <span class="sub-icon $iconCls">$icon</span>
              <span class="sub-name">$(EscHtml $s.Name)</span>
              <span class="badge $ragCls">$($s.EstateRag) — $($s.EstateScore)/100</span>
            </div>
            <div class="sub-pillar-scores">$pillarScoreHtml</div>
          </div>
"@
    }

    # ── Scoring methodology table rows ─────────────────────────────────────────
    $methodRows = ""
    foreach ($pName in $pillarOrder) {
        $wt = $pillarWeightPc[$pName]
        $methodRows += "<tr><td>$($pillarIcons[$pName]) $(EscHtml $pName)</td><td>$wt</td><td>0–100 (metric pass/fail weighted sum)</td></tr>"
    }

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Cloud Health Dashboard</title>
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
#sidebar{width:240px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:transform .25s;}
.logo-block{padding:22px 18px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:38px;height:38px;border-radius:8px;
  background:linear-gradient(135deg,var(--accent2),var(--green));
  display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{display:inline-block;margin-top:8px;padding:2px 8px;border-radius:20px;
  font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent);border:1px solid var(--border);}
.nav-section{padding:14px 10px;flex:1;}
.nav-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;
  letter-spacing:.08em;padding:0 8px;margin-bottom:6px;}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 12px;border:none;
  background:transparent;color:var(--muted2);font-size:13px;border-radius:var(--radius-sm);
  cursor:pointer;text-align:left;transition:background .15s,color .15s;position:relative;margin-bottom:2px;}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:var(--surface3);color:var(--accent);font-weight:600;}
.nav-btn.active::before{content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;
  background:var(--accent);border-radius:0 3px 3px 0;}
.nav-icon{font-size:16px;width:20px;text-align:center;}
.sidebar-footer{padding:14px 16px;border-top:1px solid var(--border);}
.theme-toggle{display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:10px;}
.toggle-pill{width:40px;height:22px;border-radius:11px;border:none;cursor:pointer;
  background:var(--surface3);position:relative;transition:background .2s;}
.toggle-pill::after{content:'';position:absolute;top:3px;left:3px;width:16px;height:16px;
  border-radius:50%;background:var(--accent);transition:transform .2s;}
html[data-theme="light"] .toggle-pill::after{transform:translateX(18px);}
.footer-meta{font-size:10px;color:var(--muted);line-height:1.6;}
#main{margin-left:240px;padding:28px;width:calc(100% - 240px);min-height:100vh;}
.page{display:none;animation:fadeIn .2s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px);}to{opacity:1;transform:none;}}
.page-header{margin-bottom:22px;}
.page-title{font-size:22px;font-weight:700;}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}
.estate-hero{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:24px;margin-bottom:22px;display:flex;align-items:center;gap:32px;flex-wrap:wrap;}
.score-ring-wrap{position:relative;flex-shrink:0;}
.score-ring-wrap svg{transform:rotate(-90deg);}
.ring-track{fill:none;stroke:var(--surface3);stroke-width:8;}
.ring-fill{fill:none;stroke-width:8;stroke-linecap:round;stroke-dasharray:251.2;
  stroke-dashoffset:251.2;transition:stroke-dashoffset 1.2s ease;}
.score-label-inner{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;}
.score-num{font-size:26px;font-weight:700;font-family:var(--mono);line-height:1;}
.score-sub{font-size:10px;color:var(--muted);margin-top:2px;text-transform:uppercase;}
.estate-details{flex:1;}
.estate-title{font-size:18px;font-weight:700;margin-bottom:6px;}
.estate-desc{font-size:13px;color:var(--muted2);margin-bottom:14px;line-height:1.6;}
.estate-meta-row{display:flex;gap:12px;flex-wrap:wrap;}
.estate-meta-item{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 14px;}
.estate-meta-label{font-size:10px;color:var(--muted);text-transform:uppercase;margin-bottom:3px;}
.estate-meta-val{font-size:13px;font-family:var(--mono);}
.pillar-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:22px;}
.pillar-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px 16px;transition:transform .15s,box-shadow .15s;}
.pillar-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.pillar-header{display:flex;align-items:center;gap:10px;margin-bottom:12px;}
.pillar-icon{font-size:20px;}
.pillar-name{font-size:14px;font-weight:700;}
.pillar-weight{font-size:11px;color:var(--muted);}
.pillar-score-row{display:flex;align-items:baseline;gap:4px;margin-bottom:8px;}
.pillar-score-num{font-size:28px;font-weight:700;font-family:var(--mono);}
.pillar-score-denom{font-size:13px;color:var(--muted);}
.pillar-bar-track{height:6px;background:var(--surface3);border-radius:3px;overflow:hidden;margin-bottom:8px;}
.pillar-bar-fill{height:100%;border-radius:3px;width:0;transition:width .8s ease;}
.pillar-label{font-size:11px;color:var(--muted2);}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:110px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:70px;text-align:right;flex-shrink:0;}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;}
.search-wrap input{width:100%;padding:8px 12px 8px 34px;background:var(--surface2);
  border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;outline:none;}
.search-wrap input:focus{border-color:var(--accent);}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:14px;}
.filter-select{padding:7px 10px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);font-size:12px;cursor:pointer;}
.tbl-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{padding:10px 12px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;
  letter-spacing:.05em;color:var(--muted);background:var(--surface2);border-bottom:1px solid var(--border);
  cursor:pointer;white-space:nowrap;user-select:none;}
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
.badge-red  {background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-blue {background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.badge-muted{background:var(--surface3);color:var(--muted2);border:1px solid var(--border);}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.sub-row-detail{padding:12px 0;border-bottom:1px solid var(--border);}
.sub-row-detail:last-child{border-bottom:none;}
.sub-row-top{display:flex;align-items:center;gap:12px;margin-bottom:6px;}
.sub-pillar-scores{padding-left:34px;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}
.sub-icon.c-amber{color:var(--amber);}
.sub-icon.c-red{color:var(--red);}
.sub-name{flex:1;font-size:13px;font-weight:500;}
.finding-row-detail{font-size:12px;color:var(--muted2);}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:460px;max-width:95vw;
  background:var(--surface);border-left:1px solid var(--border);z-index:201;
  display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
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
.drawer-field-value{font-size:13px;word-break:break-word;line-height:1.6;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.detail-box{background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:var(--radius-sm);padding:12px 14px;font-size:12px;line-height:1.7;color:var(--muted2);}
#toast{position:fixed;bottom:24px;right:24px;padding:12px 18px;background:var(--surface2);
  border:1px solid var(--border);border-radius:var(--radius);font-size:13px;box-shadow:var(--shadow);
  opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:300;}
#toast.show{opacity:1;transform:translateY(0);}
#menuToggle{display:none;}
@media(max-width:768px){
  #menuToggle{display:flex;align-items:center;justify-content:center;position:fixed;top:12px;left:12px;z-index:300;
    width:36px;height:36px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:18px;}
  #sidebar{transform:translateX(-100%);}
  #sidebar.open{transform:translateX(0);}
  #main{margin-left:0;width:100%;padding:16px;padding-top:56px;}
  .chart-grid{grid-template-columns:1fr;}
  .estate-hero{flex-direction:column;align-items:flex-start;}
  .pillar-grid{grid-template-columns:1fr 1fr;}
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
    <div class="logo-icon">☁️</div>
    <div class="logo-title">Cloud Health</div>
    <div class="logo-sub">Azure Estate Scorecard</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('pillars',this)"><span class="nav-icon">🏛️</span> Pillars</button>
    <button class="nav-btn" onclick="showPage('metrics',this)"><span class="nav-icon">📐</span> Metrics</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">⚠️</span> Key Findings</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">🗂️</span> Subscriptions</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Azure Cloud Health Dashboard
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Azure Cloud Health Overview</div>
      <div class="page-sub">Five-pillar estate assessment across __SUB_COUNT__ subscription(s)</div>
    </div>

    <!-- Estate Score Hero -->
    <div class="estate-hero">
      <div class="score-ring-wrap">
        <svg width="110" height="110" viewBox="0 0 110 110">
          <circle class="ring-track" cx="55" cy="55" r="40"/>
          <circle class="ring-fill" id="estateRing" cx="55" cy="55" r="40" stroke="__RING_COLOR__"/>
        </svg>
        <div class="score-label-inner">
          <div class="score-num" style="color:__RING_COLOR__">__ESTATE_SCORE__</div>
          <div class="score-sub">/ 100</div>
        </div>
      </div>
      <div class="estate-details">
        <div class="estate-title">Overall Azure Estate Health: <span class="badge __RAG_BADGE_CLASS__">__ESTATE_RAG__</span> — __ESTATE_RAG_LABEL__</div>
        <div class="estate-desc">
          The estate score is a weighted combination of five pillar scores: Security (30%),
          Governance (20%), Resilience (20%), Operations (15%), and Cost (15%).
          Each pillar score reflects the pass/fail ratio of assessed health metrics weighted by importance.
          Metrics marked "Not Assessed" are excluded from scoring — they do not penalise the pillar.
        </div>
        <div class="estate-meta-row">
          <div class="estate-meta-item"><div class="estate-meta-label">Subscriptions</div><div class="estate-meta-val">__SUB_COUNT__</div></div>
          <div class="estate-meta-item"><div class="estate-meta-label">Pillars Assessed</div><div class="estate-meta-val">5</div></div>
          <div class="estate-meta-item"><div class="estate-meta-label">Execution Time</div><div class="estate-meta-val">__EXEC_TIME__</div></div>
          <div class="estate-meta-item"><div class="estate-meta-label">Generated</div><div class="estate-meta-val">__GENERATED_ON__</div></div>
        </div>
      </div>
    </div>

    <!-- Pillar Cards -->
    <div class="pillar-grid">
      __PILLAR_CARDS__
    </div>

    <!-- Charts -->
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📊 Pillar Health Scores</div>
        __PILLAR_BAR_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">📋 Scoring Methodology</div>
        <table>
          <thead><tr><th>Pillar</th><th>Weight</th><th>Scoring Basis</th></tr></thead>
          <tbody>__METHOD_ROWS__</tbody>
        </table>
        <div style="margin-top:14px;font-size:12px;color:var(--muted2);line-height:1.7;">
          RAG: <span style="color:var(--green)">Green ≥ 71</span> &nbsp;
          <span style="color:var(--amber)">Amber 41–70</span> &nbsp;
          <span style="color:var(--red)">Red ≤ 40</span><br/>
          "Not Assessed" metrics are excluded from pillar scoring — not penalised.
        </div>
      </div>
    </div>
  </div>

  <!-- Pillars -->
  <div id="page-pillars" class="page">
    <div class="page-header">
      <div class="page-title">Pillar Health Detail</div>
      <div class="page-sub">Per-pillar score, RAG status, and key findings summary</div>
    </div>
    <div class="pillar-grid">__PILLAR_CARDS_2__</div>
  </div>

  <!-- Metrics -->
  <div id="page-metrics" class="page">
    <div class="page-header">
      <div class="page-title">Health Metrics</div>
      <div class="page-sub">All individual health indicators across all pillars and subscriptions. Click any row for detail.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="metricSearch" placeholder="Search metric, pillar, subscription…" oninput="filterMetrics()"/>
        </div>
        <select class="filter-select" id="filterPillar" onchange="filterMetrics()">
          <option value="">All Pillars</option>
          <option value="Security">Security</option>
          <option value="Governance">Governance</option>
          <option value="Resilience">Resilience</option>
          <option value="Operations">Operations</option>
          <option value="Cost">Cost</option>
        </select>
        <select class="filter-select" id="filterPass" onchange="filterMetrics()">
          <option value="">All Results</option>
          <option value="pass">Pass</option>
          <option value="fail">Fail</option>
          <option value="na">Not Assessed</option>
        </select>
        <select class="filter-select" id="pgSizeMetric" onchange="changeMetricPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="sortMetrics(0)">Pillar</th>
              <th onclick="sortMetrics(1)">Metric</th>
              <th onclick="sortMetrics(2)">Result</th>
              <th onclick="sortMetrics(3)">Weight</th>
              <th onclick="sortMetrics(4)">Subscription</th>
              <th>Value / Evidence</th>
            </tr>
          </thead>
          <tbody id="metricBody">__METRIC_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="metricPagination"></div>
    </div>
  </div>

  <!-- Key Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Key Findings</div>
      <div class="page-sub">All actionable findings from failed health metrics, ordered by pillar weight</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Pillar</th>
              <th>RAG</th>
              <th>Subscription</th>
              <th>Finding</th>
            </tr>
          </thead>
          <tbody>__FINDING_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Subscriptions -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Health</div>
      <div class="page-sub">Per-subscription estate score and pillar breakdown</div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Subscriptions Assessed</div>
      <div>__SUB_ROWS__</div>
    </div>
  </div>

  <!-- Session -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Scan Parameters</div>
      <div class="page-sub">Authentication context and scan configuration</div>
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
        <div class="info-card"><div class="info-label">Estate Score</div><div class="info-value">__ESTATE_SCORE__ / 100</div></div>
        <div class="info-card"><div class="info-label">Estate RAG</div><div class="info-value">__ESTATE_RAG__ — __ESTATE_RAG_LABEL__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">📐 Scoring Methodology</div>
      <p style="font-size:13px;color:var(--muted2);line-height:1.8;">
        Each pillar score = weighted sum of passed metrics / total assessed metric weights × 100.
        Metrics with Status "Not Assessed" are excluded from the denominator — they do not penalise the pillar.
        Estate score = Σ(pillar score × pillar weight): Security 30%, Governance 20%, Resilience 20%, Operations 15%, Cost 15%.
        RAG thresholds: <span style="color:var(--green)">Green ≥ 71</span>,
        <span style="color:var(--amber)">Amber 41–70</span>,
        <span style="color:var(--red)">Red ≤ 40</span>.
        When multiple subscriptions are scanned, pillar scores are averaged across subscriptions before the estate score is computed.
      </p>
    </div>
  </div>
</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Metric Detail</span>
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
const ALL_METRICS = __METRIC_JSON__;
let metricFiltered = [...ALL_METRICS];
let metricPage = 1, metricPageSz = 25;
let metricSortCol = -1, metricSortAsc = true;
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

function filterMetrics(){
  const q=document.getElementById('metricSearch').value.toLowerCase();
  const p=document.getElementById('filterPillar').value;
  const r=document.getElementById('filterPass').value;
  metricFiltered=ALL_METRICS.filter(m=>{
    const mQ=!q||JSON.stringify(m).toLowerCase().includes(q);
    const mP=!p||m.pillar===p;
    const mR=!r||(r==='pass'&&m.passed&&m.status==='Assessed')||(r==='fail'&&!m.passed&&m.status==='Assessed')||(r==='na'&&m.status!=='Assessed');
    return mQ&&mP&&mR;
  });
  metricPage=1; renderMetrics();
}

function changeMetricPageSize(){
  metricPageSz=parseInt(document.getElementById('pgSizeMetric').value);
  metricPage=1; renderMetrics();
}

function sortMetrics(col){
  if(metricSortCol===col){metricSortAsc=!metricSortAsc;}else{metricSortCol=col;metricSortAsc=true;}
  const keys=['pillar','name','passed','weight','sub'];
  metricFiltered.sort((a,b)=>{
    const k=keys[col];
    if(!k)return 0;
    const av=a[k]??'',bv=b[k]??'';
    return metricSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                        :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderMetrics();
}

function renderMetrics(){
  const tbody=document.getElementById('metricBody');
  const start=(metricPage-1)*metricPageSz;
  const slice=metricFiltered.slice(start,start+metricPageSz);
  tbody.innerHTML=slice.map(m=>{
    const gi=ALL_METRICS.indexOf(m);
    const sCls=m.status!=='Assessed'?'badge-muted':m.passed?'badge-green':'badge-red';
    const sLbl=m.status!=='Assessed'?'Not Assessed':m.passed?'✓ Pass':'✗ Fail';
    const shortVal=m.value.length>50?m.value.substring(0,47)+'...':m.value;
    return `<tr onclick="showMetricDetail(${gi})">
      <td>${escH(m.pillar)}</td>
      <td>${escH(m.name)}</td>
      <td><span class="badge ${sCls}">${sLbl}</span></td>
      <td>${m.weight}</td>
      <td>${escH(m.sub)}</td>
      <td title="${escH(m.value)}">${escH(shortVal)}</td>
    </tr>`;
  }).join('');
  renderMetricPg();
}

function renderMetricPg(){
  const total=Math.ceil(metricFiltered.length/metricPageSz);
  const el=document.getElementById('metricPagination');
  let h=`<span>${metricFiltered.length} metrics</span>`;
  h+=`<button class="pg-btn" onclick="changeMetricPage(${metricPage-1})" ${metricPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,metricPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===metricPage?'active':''}" onclick="changeMetricPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeMetricPage(${metricPage+1})" ${metricPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeMetricPage(p){
  const total=Math.ceil(metricFiltered.length/metricPageSz);
  if(p<1||p>total)return;
  metricPage=p; renderMetrics();
}

function showMetricDetail(idx){
  currentDetailIdx=idx;
  const m=ALL_METRICS[idx];
  if(!m)return;
  const sCls=m.status!=='Assessed'?'badge-muted':m.passed?'badge-green':'badge-red';
  const sLbl=m.status!=='Assessed'?'Not Assessed':m.passed?'✓ Pass':'✗ Fail';
  document.getElementById('drawerTitle').textContent=m.pillar+' — '+m.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${ALL_METRICS.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field">
      <div class="drawer-field-label">Result</div>
      <div class="drawer-field-value"><span class="badge ${sCls}">${sLbl}</span></div>
    </div>
    <div class="drawer-field"><div class="drawer-field-label">Pillar</div><div class="drawer-field-value">${escH(m.pillar)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Metric</div><div class="drawer-field-value">${escH(m.name)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Weight</div><div class="drawer-field-value" style="font-family:var(--mono)">${m.weight}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(m.sub)}</div></div>
    <div class="drawer-section">Evidence</div>
    <div class="drawer-field"><div class="drawer-field-label">Value</div><div class="drawer-field-value" style="font-family:var(--mono)">${escH(m.value)}</div></div>
    <div class="drawer-section">Detail</div>
    <div class="detail-box">${escH(m.detail)}</div>
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
  if(next>=0&&next<ALL_METRICS.length) showMetricDetail(next);
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct],.pillar-bar-fill[data-pct]').forEach(el=>{
      el.style.width=el.dataset.pct+'%';
    });
    const ring=document.getElementById('estateRing');
    if(ring){
      const pct=__ESTATE_SCORE__;
      ring.style.strokeDashoffset=(251.2-(251.2*pct/100)).toFixed(1);
    }
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

filterMetrics();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', $subCount `
        -replace '__ESTATE_SCORE__', $EstateScore `
        -replace '__ESTATE_RAG__', $EstateRag `
        -replace '__ESTATE_RAG_LABEL__', $EstateRagLabel `
        -replace '__RAG_BADGE_CLASS__', $ragBadge `
        -replace '__RING_COLOR__', $ringColorVar `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__PILLAR_CARDS__', $pillarCards `
        -replace '__PILLAR_CARDS_2__', $pillarCards `
        -replace '__PILLAR_BAR_ROWS__', $pillarBarRows `
        -replace '__METHOD_ROWS__', $methodRows `
        -replace '__METRIC_ROWS__', $metricRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__METRIC_JSON__', $metricJson

    return $html
}

#endregion


#region ── [ Aggregation Helpers ] ─────────────────────────────────────────────

Function Get-AggregatedPillars {
    # Averages pillar scores across all subscriptions for the overview display.
    param([array]$AllPillarResults)

    $pillarNames = @("Security", "Governance", "Resilience", "Operations", "Cost")
    $aggregated = @()

    foreach ($pName in $pillarNames) {
        $pillarGroup = @($AllPillarResults | Where-Object { $_.Pillar -eq $pName })
        if ($pillarGroup.Count -eq 0) { continue }

        $avgScore = [math]::Round(($pillarGroup | Measure-Object -Property Score -Average).Average)
        $rag = Get-RagStatus -Score $avgScore

        $aggregated += [pscustomobject]@{
            Pillar      = $pName
            Score       = $avgScore
            RagStatus   = $rag
            RagLabel    = Get-RagLabel -Score $avgScore
            KeyFindings = $pillarGroup | ForEach-Object { $_.KeyFindings } | Select-Object -Unique
        }
    }

    return $aggregated
}

#endregion


#region ── [ Main Function ] ───────────────────────────────────────────────────

Function Generate-AzureCloudHealthDashboard {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = "C:\Temp\AzureCloudHealthDashboard.html"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts", "Az.Resources", "Az.Security", "Az.Network",
        "Az.Compute", "Az.Storage", "Az.Monitor", "Az.RecoveryServices",
        "Az.OperationalInsights", "Az.Advisor"
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

    # ── Display session / params ──────────────────────────────────────────────
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"          = "$scopeText ($subCount found)"
        "Export to CSV"  = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Output Path"    = $OutputPath
        "Pillar Weights" = "Security 30% | Governance 20% | Resilience 20% | Operations 15% | Cost 15%"
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allPillarResults = @()
    $subscriptionResults = @()
    $successCount = 0
    $errorCount = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
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

            # ── Collect all five pillars ──────────────────────────────────
            $secResult = Get-SecurityPillar   -SubscriptionId $sub.Id -SubscriptionName $sub.Name
            $govResult = Get-GovernancePillar  -SubscriptionId $sub.Id -SubscriptionName $sub.Name
            $resResult = Get-ResiliencePillar  -SubscriptionId $sub.Id -SubscriptionName $sub.Name
            $opsResult = Get-OperationsPillar  -SubscriptionId $sub.Id -SubscriptionName $sub.Name
            $costResult = Get-CostPillar        -SubscriptionId $sub.Id -SubscriptionName $sub.Name

            $subPillarResults = @($secResult, $govResult, $resResult, $opsResult, $costResult)
            $allPillarResults += $subPillarResults

            # ── Per-subscription estate score ─────────────────────────────
            $subEstateScore = Invoke-EstateScore -PillarResults $subPillarResults
            $subEstateRag = Get-RagStatus      -Score $subEstateScore

            $pillarScores = @{}
            foreach ($pr in $subPillarResults) { $pillarScores[$pr.Pillar] = $pr.Score }

            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Estate: $subEstateScore ($subEstateRag) | Sec:$($secResult.Score) Gov:$($govResult.Score) Res:$($resResult.Score) Ops:$($opsResult.Score) Cost:$($costResult.Score)" -ForegroundColor White

            $subscriptionResults += @{
                Name         = $sub.Name
                EstateScore  = $subEstateScore
                EstateRag    = $subEstateRag
                PillarScores = $pillarScores
                Status       = "Success"
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
                Name         = $sub.Name
                EstateScore  = 0
                EstateRag    = "Red"
                PillarScores = @{}
                Status       = "Error"
            }
            $errorCount++
        }

        $subIndex++
    }

    # ── Aggregate + estate score ───────────────────────────────────────────────
    $aggregatedPillars = Get-AggregatedPillars -AllPillarResults $allPillarResults
    $estateScore = Invoke-EstateScore    -PillarResults $aggregatedPillars
    $estateRag = Get-RagStatus         -Score $estateScore
    $estateRagLabel = Get-RagLabel          -Score $estateScore

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-HealthSummary -Data ([ordered]@{
            "Subscriptions Scanned" = $subCount
            "Successful"            = $successCount
            "Errors"                = $errorCount
            "Overall Estate Score"  = "$estateScore / 100 ($estateRag)"
            "Execution Time"        = $duration
        })

    Write-PillarBreakdown -PillarResults $aggregatedPillars

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $csvPath = ""

    # CSV export
    if ($ExportToCsv) {
        try {
            $csvPath = [System.IO.Path]::ChangeExtension($OutputPath, '.csv')
            $csvDir = Split-Path -Parent $csvPath
            if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

            $csvRows = @()
            foreach ($pr in $allPillarResults) {
                foreach ($m in $pr.Metrics) {
                    $csvRows += [pscustomobject]@{
                        SubscriptionName = $pr.SubscriptionName
                        SubscriptionId   = $pr.SubscriptionId
                        Pillar           = $pr.Pillar
                        PillarScore      = $pr.Score
                        PillarRag        = $pr.RagStatus
                        MetricName       = $m.Name
                        Result           = if ($m.Status -ne "Assessed") { "Not Assessed" } elseif ($m.Passed) { "Pass" } else { "Fail" }
                        Weight           = $m.Weight
                        Value            = $m.Value
                        Detail           = $m.Detail
                    }
                }
            }

            $csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            $csvExported = $true
        }
        catch {
            Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
        }
    }

    # HTML dashboard
    try {
        $htmlDir = Split-Path -Parent $OutputPath
        if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }

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

        $htmlContent = Generate-CloudHealthHtml `
            -SessionInfo        $sessionInfo `
            -ScanParameters     $scanParams `
            -EstateScore        $estateScore `
            -EstateRag          $estateRag `
            -EstateRagLabel     $estateRagLabel `
            -AggregatedPillars  $aggregatedPillars `
            -AllPillarResults   $allPillarResults `
            -SubscriptionResults $subscriptionResults `
            -GeneratedOn        (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

        $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        $htmlExported = $true
    }
    catch {
        Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
    }

    # Grid View
    try {
        $gridData = @()
        foreach ($pr in $allPillarResults) {
            foreach ($m in $pr.Metrics) {
                $gridData += [pscustomobject]@{
                    Subscription = $pr.SubscriptionName
                    Pillar       = $pr.Pillar
                    PillarScore  = $pr.Score
                    PillarRag    = $pr.RagStatus
                    Metric       = $m.Name
                    Result       = if ($m.Status -ne "Assessed") { "Not Assessed" } elseif ($m.Passed) { "Pass" } else { "Fail" }
                    Weight       = $m.Weight
                    Value        = $m.Value
                }
            }
        }
        $gridData | Out-GridView -Title "Azure Cloud Health Dashboard"
        $gridViewOpened = $true
    }
    catch {
        Write-Verbose "Could not open Grid View (no GUI available)"
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        $outCsv = if ($csvExported) { $csvPath } else { $null }
        $outHtml = if ($htmlExported) { $OutputPath } else { $null }
        Write-OutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}

#endregion
