<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 12 August 2026
Modified-On     : 12 August 2026

.SYNOPSIS
    Identifies Azure Policy coverage gaps against a Management-Group-defined
    enterprise baseline, across Subscriptions, Resource Groups, and
    individual Resources, with optional CSV export and an auto-generated
    HTML summary report.

.DESCRIPTION
    The Get-AzurePolicyCoverageGap function evaluates a specified "baseline"
    Management Group's directly-assigned Azure Policies/Initiatives and
    reports where that baseline is NOT effectively protecting the estate
    beneath it. Two distinct gap types are reported:

        - Assignment Gap : a Subscription or Resource Group that has been
          excluded from a baseline assignment via that assignment's
          NotScopes property, i.e. it inherits NO coverage from the
          baseline despite sitting under the baseline Management Group.

        - Compliance Gap : a Resource that IS covered by a baseline
          assignment but is evaluated as NonCompliant against it, per
          Azure Policy Insights (Get-AzPolicyState).

    It supports:
        - Resolving the full Subscription tree beneath -BaselineManagementGroupId
          (recursing through any nested child Management Groups)
        - Resolving baseline requirements from policy/initiative assignments
          created directly at that Management Group (assignments inherited
          from a higher-level ancestor are NOT treated as the baseline)
        - Real-time progress tracking with a live progress bar and color-coded
          console status per subscription
        - Assignment-level gap detection via NotScopes exclusion analysis at
          Subscription and Resource Group level
        - Resource-level compliance gap detection via Azure Policy Insights,
          filtered to only the baseline's required policies/initiatives
        - Optional CSV export of all collected gap rows (Assignment + Compliance)
        - Always-on HTML report generation (Azure-themed, self-contained)
          summarizing session info, scan parameters, statistics, and
          distributions
        - Interactive Grid View display of results (where a GUI is available)

.PARAMETER BaselineManagementGroupId
    Mandatory. The Management Group ID whose DIRECTLY-assigned policies and
    initiatives define the required enterprise baseline. Every Subscription,
    Resource Group, and Resource beneath this Management Group is evaluated
    against that baseline.

.PARAMETER SubscriptionIds
    Optional string array. Restricts the scan to specific Subscription IDs
    within the baseline Management Group's tree, instead of all of them.
    Any ID not found beneath -BaselineManagementGroupId is skipped with a
    warning.

.PARAMETER ExportToCsv
    Switch. If specified, exports all collected gap rows (Assignment Gaps
    and Compliance Gaps combined, distinguished by a GapType column) to the
    path given in -CsvPath. An HTML report is generated regardless of
    whether this switch is used.

.PARAMETER CsvPath
    Path where the CSV export will be written if -ExportToCsv is specified.
    Also used to derive the HTML report's file name/location (same path,
    .html extension).
    Default: C:\Temp\AzurePolicyCoverageGap-Report.csv

.PARAMETER SkipResourceLevelCompliance
    Switch. If specified, skips the Policy Insights resource-level
    compliance-gap scan and reports Assignment Gaps only. Use this to
    reduce runtime/API load in very large tenants where a full
    resource-level compliance pull is impractical for a single run.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML report alongside
    -CsvPath (or the default path). Optionally writes a CSV file if
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzurePolicyCoverageGap -BaselineManagementGroupId "mg-enterprise-baseline"

.EXAMPLE
    Get-AzurePolicyCoverageGap -BaselineManagementGroupId "mg-enterprise-baseline" -SubscriptionIds @("SubscriptionID1", "SubscriptionID2")

.EXAMPLE
    Get-AzurePolicyCoverageGap -BaselineManagementGroupId "mg-enterprise-baseline" -SkipResourceLevelCompliance

    Reports Assignment Gaps only (Subscription/Resource Group level), skipping the resource-level Policy Insights compliance pull.

.EXAMPLE
    Get-AzurePolicyCoverageGap -BaselineManagementGroupId "mg-enterprise-baseline" -ExportToCsv -CsvPath "C:\Path\To\Output.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (12-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az.Accounts, Az.Resources, and Az.PolicyInsights PowerShell modules
           (installed/imported automatically if missing, with user consent at
           the console prompt).
        2. A valid Azure account with, at minimum:
                Reader at the baseline Management Group scope
                Microsoft.Authorization/policyAssignments/read at the baseline
                    Management Group scope
                Reader at every in-scope Subscription (to enumerate Resource
                    Groups and query Policy Insights)
        3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve the Subscription tree beneath -BaselineManagementGroupId
                    (recursing through nested child Management Groups)
        Step 2  →  Resolve baseline requirements: policy/initiative assignments
                    created DIRECTLY at -BaselineManagementGroupId
        Step 3  →  For each in-scope Subscription: enumerate Resource Groups and
                    check each baseline assignment's NotScopes for exclusions
                    at Subscription/Resource Group level → Assignment Gap rows
        Step 4  →  Unless -SkipResourceLevelCompliance: query Get-AzPolicyState
                    per Subscription, filtered to NonCompliant resources against
                    baseline assignments only → Compliance Gap rows
        Step 5  →  Aggregate statistics (gap counts, distributions, top
                    non-compliant policies)
        Step 6  →  Export to CSV (if requested) and generate the HTML report
                    (always)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - "Baseline" is defined strictly as assignments whose resource ID shows
            they were created directly at -BaselineManagementGroupId. An
            assignment inherited onto that Management Group from a higher-level
            ancestor Management Group is NOT included in the baseline; if your
            enterprise policies actually live further up the hierarchy, point
            -BaselineManagementGroupId at that higher Management Group instead.
        - Assignment Gap detection is based on the NotScopes exclusion list of
            each baseline assignment. It does NOT detect a lower-scope
            assignment that overrides/conflicts with the baseline (e.g. a
            Subscription-level assignment of the same initiative with
            Enforcement Mode set to DoNotEnforce). Treat a "no gap" result as
            "not explicitly excluded," not as "confirmed enforced" — this could
            not be confirmed without a deeper per-scope assignment diff, which
            is a good candidate for a future enhancement.
        - Initiatives (Policy Sets) are evaluated as a single baseline
            requirement, not exploded into per-member-policy compliance rows.
            Get-AzPolicyState results are attributed to the initiative
            assignment as a whole.
        - Az module cmdlet output shapes for policy assignments (NotScopes,
            PolicyDefinitionId, ResourceId/Id) have varied slightly across Az
            module versions. This script defensively checks multiple property
            names, but if your installed Az version differs significantly,
            validate against Get-Member before relying on results in
            production.
        - RESOURCE-LEVEL COMPLIANCE SCAN COST: Get-AzPolicyState at Subscription
            scope can return a large result set in big enterprise tenants. Use
            -SkipResourceLevelCompliance or -SubscriptionIds to scope down a
            first run before scanning tenant-wide.
        - Interactive Grid View requires a GUI-capable session (Windows
            PowerShell ISE, or Microsoft.PowerShell.GraphicalTools on PS7). In
            headless/CI/Linux sessions this step is skipped gracefully;
            CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is a Windows-specific path. On
            macOS/Linux PowerShell 7, supply an explicit -CsvPath.

.LINK
    Microsoft Graph API / Az - Policy assignments, NotScopes
    https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure

.LINK
    Az PowerShell - Get-AzPolicyState (Policy Insights)
    https://learn.microsoft.com/en-us/powershell/module/az.policyinsights/get-azpolicystate

.LINK
    Get-AzureRBACAssignments.ps1 (reference implementation this script's
    structure and HTML report style are based on)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/RBAC/Get-AzureRBACAssignments.ps1

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
    Write-CenteredText "Azure Policy Coverage Gap Analyzer v1.0" -Color White
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
            $valueColor = "DarkGray"
        }
        else {
            $valueColor = "White"
        }

        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valueColor
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
    Write-Host ("  Progress: ") -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White

    if ($CurrentItem) {
        $maxLength = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLength) {
            $CurrentItem.Substring(0, $maxLength - 3) + "..."
        }
        else {
            $CurrentItem
        }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-Summary {
    param(
        [hashtable]$Data
    )

    Write-Host ""
    Write-Host "  Scan Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys) {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(30) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-TopItems {
    param(
        [string]$Title,
        [hashtable]$Items,
        [string]$Suffix = "gaps"
    )

    if ($Items.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $counter = 1
    foreach ($item in ($Items.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
        Write-Host "  " -NoNewline
        Write-Host "$counter. " -NoNewline -ForegroundColor Gray
        Write-Host $item.Key.PadRight(45) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($item.Value) $Suffix" -ForegroundColor Cyan
        $counter++
    }
}

Function Write-Distribution {
    param(
        [string]$Title,
        [hashtable]$Data,
        [int]$Total
    )

    if ($Total -eq 0 -or $Data.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys) {
        $percent = [math]::Round(($Data[$key] / $Total) * 100)
        Write-Host "  $key".PadRight(35) -NoNewline
        Write-Host ": $percent%" -ForegroundColor White
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
        Write-Host (("CSV Export").PadRight(20) + ": ") -NoNewline -ForegroundColor Gray
        Write-Host $CsvPath -ForegroundColor White
    }

    if ($HtmlPath) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host (("HTML Report").PadRight(20) + ": ") -NoNewline -ForegroundColor Gray
        Write-Host $HtmlPath -ForegroundColor White
    }

    if ($GridViewOpened) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host (("Grid View").PadRight(20) + ": ") -NoNewline -ForegroundColor Gray
        Write-Host "Opened in separate window" -ForegroundColor White
    }

    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-ChildSubscriptionIds {
    <#
        Recursively walks an expanded Get-AzManagementGroup result and returns
        every Subscription ID found beneath it (including nested child
        Management Groups).
    #>
    param(
        [Parameter(Mandatory = $true)]
        $ManagementGroupNode
    )

    $found = New-Object System.Collections.ArrayList

    if (-not $ManagementGroupNode.Children) { return $found }

    foreach ($child in $ManagementGroupNode.Children) {
        if ($child.Type -eq '/subscriptions') {
            $null = $found.Add($child.Name)
        }
        elseif ($child.Type -eq 'Microsoft.Management/managementGroups') {
            $nested = Get-ChildSubscriptionIds -ManagementGroupNode $child
            $nested | ForEach-Object { $null = $found.Add($_) }
        }
    }

    return $found
}

Function Get-BaselinePolicyDisplayName {
    <#
        Resolves a friendly display name for a baseline assignment's target
        policy or initiative, caching lookups in $script:PolicyNameCache to
        avoid duplicate Graph/Az calls.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyDefinitionId
    )

    if ($script:PolicyNameCache.ContainsKey($PolicyDefinitionId)) {
        return $script:PolicyNameCache[$PolicyDefinitionId]
    }

    $displayName = "Could not be confirmed"

    Try {
        if ($PolicyDefinitionId -match '/policySetDefinitions/') {
            $def = Get-AzPolicySetDefinition -Id $PolicyDefinitionId -ErrorAction Stop
            $displayName = if ($def.Properties.DisplayName) { $def.Properties.DisplayName } else { $def.Name }
        }
        else {
            $def = Get-AzPolicyDefinition -Id $PolicyDefinitionId -ErrorAction Stop
            $displayName = if ($def.Properties.DisplayName) { $def.Properties.DisplayName } else { $def.Name }
        }
    }
    Catch {
        Write-Warning "Could not resolve display name for policy definition '$PolicyDefinitionId': $($_.Exception.Message)"
    }

    $script:PolicyNameCache[$PolicyDefinitionId] = $displayName
    return $displayName
}

Function Generate-HtmlReport {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [hashtable]$ScanSummary,
        [array]$SubscriptionResults,
        [hashtable]$TopNonCompliantPolicies,
        [hashtable]$GapTypeDistribution,
        [hashtable]$ScopeLevelDistribution,
        [int]$TotalGaps,
        [string]$CsvPath,
        [string]$HtmlPath,
        [bool]$GridViewOpened
    )

    $timestamp = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    $subscriptionHtml = ""
    foreach ($sub in $SubscriptionResults) {
        $icon = switch ($sub.Status) {
            "Success" { "✓" }
            "Warning" { "⚠" }
            "Error" { "✗" }
            default { "•" }
        }

        $subscriptionHtml += @"
                    <div class="subscription-item">
                        <span class="status-icon">$icon</span>
                        <span class="subscription-name">$($sub.Name)</span>
                        <span class="assignment-count">$($sub.Count)</span>
                    </div>
"@
    }

    $topPoliciesHtml = ""
    $counter = 1
    foreach ($item in ($TopNonCompliantPolicies.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
        $topPoliciesHtml += @"
                    <div class="top-item">
                        <div class="rank">$counter</div>
                        <div class="item-name">$($item.Key)</div>
                        <div class="item-count">$($item.Value) gaps</div>
                    </div>
"@
        $counter++
    }

    $gapTypeHtml = ""
    foreach ($key in $GapTypeDistribution.Keys) {
        $percent = if ($TotalGaps -gt 0) { [math]::Round(($GapTypeDistribution[$key] / $TotalGaps) * 100) } else { 0 }
        $gapTypeHtml += @"
                    <div class="distribution-item">
                        <div class="distribution-label">
                            <span>$key</span>
                            <span>$percent%</span>
                        </div>
                        <div class="distribution-bar">
                            <div class="distribution-fill" style="width: $percent%;"></div>
                        </div>
                    </div>
"@
    }

    $scopeLevelHtml = ""
    foreach ($key in $ScopeLevelDistribution.Keys) {
        $percent = if ($TotalGaps -gt 0) { [math]::Round(($ScopeLevelDistribution[$key] / $TotalGaps) * 100) } else { 0 }
        $scopeLevelHtml += @"
                    <div class="distribution-item">
                        <div class="distribution-label">
                            <span>$key</span>
                            <span>$percent%</span>
                        </div>
                        <div class="distribution-bar">
                            <div class="distribution-fill" style="width: $percent%;"></div>
                        </div>
                    </div>
"@
    }

    $outputFilesHtml = ""
    if ($CsvPath) {
        $outputFilesHtml += @"
                    <div class="output-item">
                        <div class="output-icon">✓</div>
                        <div class="output-details">
                            <div class="output-label">CSV Export</div>
                            <div class="output-value">$CsvPath</div>
                        </div>
                    </div>
"@
    }

    if ($HtmlPath) {
        $outputFilesHtml += @"
                    <div class="output-item">
                        <div class="output-icon">✓</div>
                        <div class="output-details">
                            <div class="output-label">HTML Report</div>
                            <div class="output-value">$HtmlPath</div>
                        </div>
                    </div>
"@
    }

    if ($GridViewOpened) {
        $outputFilesHtml += @"
                    <div class="output-item">
                        <div class="output-icon">✓</div>
                        <div class="output-details">
                            <div class="output-label">Grid View</div>
                            <div class="output-value">Opened in separate window</div>
                        </div>
                    </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Policy Coverage Gap Analyzer - Execution Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #0078D4 0%, #50E6FF 100%); padding: 20px; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 10px 40px rgba(0, 120, 212, 0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #0078D4 0%, #50E6FF 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 32px; margin-bottom: 10px; font-weight: 300; letter-spacing: 1px; }
        .header .timestamp { font-size: 14px; opacity: 0.9; }
        .content { padding: 40px; }
        .section { margin-bottom: 40px; }
        .section-title { font-size: 20px; color: #0078D4; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #f0f0f0; font-weight: 600; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .info-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #0078D4; }
        .info-label { font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
        .info-value { font-size: 18px; color: #333; font-weight: 600; }
        .info-value.none { color: #999; font-style: italic; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: linear-gradient(135deg, #0078D4 0%, #50E6FF 100%); color: white; padding: 25px; border-radius: 8px; text-align: center; box-shadow: 0 4px 15px rgba(0, 120, 212, 0.3); }
        .stat-number { font-size: 36px; font-weight: 700; margin-bottom: 8px; }
        .stat-label { font-size: 12px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px; }
        .subscription-list { background: #f8f9fa; padding: 20px; border-radius: 8px; max-height: 400px; overflow-y: auto; }
        .subscription-item { display: flex; align-items: center; padding: 12px 0; border-bottom: 1px solid #e0e0e0; }
        .subscription-item:last-child { border-bottom: none; }
        .status-icon { width: 24px; height: 24px; margin-right: 15px; display: flex; align-items: center; justify-content: center; font-size: 18px; }
        .subscription-name { flex: 1; font-weight: 500; color: #333; }
        .assignment-count { color: #0078D4; font-weight: 600; }
        .top-list { background: #f8f9fa; padding: 20px; border-radius: 8px; }
        .top-item { display: flex; align-items: center; padding: 15px; margin-bottom: 10px; background: white; border-radius: 6px; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05); }
        .rank { width: 32px; height: 32px; background: linear-gradient(135deg, #0078D4 0%, #50E6FF 100%); color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; margin-right: 15px; font-size: 14px; }
        .item-name { flex: 1; font-weight: 500; color: #333; }
        .item-count { color: #0078D4; font-weight: 600; }
        .distribution { background: #f8f9fa; padding: 20px; border-radius: 8px; }
        .distribution-item { margin-bottom: 20px; }
        .distribution-label { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 14px; }
        .distribution-bar { height: 8px; background: #e0e0e0; border-radius: 4px; overflow: hidden; }
        .distribution-fill { height: 100%; background: linear-gradient(90deg, #0078D4 0%, #50E6FF 100%); border-radius: 4px; transition: width 0.3s ease; }
        .output-section { background: #f0f7ff; padding: 20px; border-radius: 8px; border: 1px solid #d0e4ff; }
        .output-item { display: flex; align-items: center; padding: 15px; margin-bottom: 10px; background: white; border-radius: 6px; }
        .output-icon { width: 40px; height: 40px; background: #28a745; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 15px; font-size: 20px; }
        .output-details { flex: 1; }
        .output-label { font-size: 12px; color: #888; margin-bottom: 4px; }
        .output-value { font-weight: 600; color: #333; word-break: break-all; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #888; font-size: 12px; border-top: 1px solid #e0e0e0; }
        @media (max-width: 768px) { .container { margin: 10px; } .content { padding: 20px; } .stat-card { padding: 15px; } .stat-number { font-size: 28px; } }
        @media print { body { background: white; padding: 0; } .container { box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Azure Policy Coverage Gap Analyzer</h1>
            <div class="timestamp">Execution Report - Generated on $timestamp</div>
        </div>

        <div class="content">
            <div class="section">
                <h2 class="section-title">📋 Session Information</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <div class="info-label">Tenant ID</div>
                        <div class="info-value">$($SessionInfo.Tenant)</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Account</div>
                        <div class="info-value">$($SessionInfo.Account)</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Environment</div>
                        <div class="info-value">$($SessionInfo.Environment)</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">⚙️ Scan Parameters</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <div class="info-label">Baseline Management Group</div>
                        <div class="info-value">$($ScanParameters.BaselineManagementGroupId)</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Baseline Requirements</div>
                        <div class="info-value">$($ScanParameters.BaselineRequirementCount)</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Resource-Level Compliance Scan</div>
                        <div class="info-value">$($ScanParameters.ResourceLevelScan)</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Export to CSV</div>
                        <div class="info-value">$($ScanParameters.ExportEnabled)</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">📊 Scan Summary</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">$($ScanSummary.TotalGaps)</div>
                        <div class="stat-label">Total Gaps</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">$($ScanSummary.AssignmentGaps)</div>
                        <div class="stat-label">Assignment Gaps</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">$($ScanSummary.ComplianceGaps)</div>
                        <div class="stat-label">Compliance Gaps</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">$($ScanSummary.SubscriptionsScanned)</div>
                        <div class="stat-label">Subscriptions Scanned</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">$($ScanSummary.ExecutionTime)</div>
                        <div class="stat-label">Execution Time</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">🔍 Subscription Scan Results</h2>
                <div class="subscription-list">
$subscriptionHtml
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">📛 Top 5 Policies/Initiatives Driving Gaps</h2>
                <div class="top-list">
$topPoliciesHtml
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">🧩 Gap Type Distribution</h2>
                <div class="distribution">
$gapTypeHtml
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">🎯 Scope Level Distribution</h2>
                <div class="distribution">
$scopeLevelHtml
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">📁 Output Files</h2>
                <div class="output-section">
$outputFilesHtml
                </div>
            </div>
        </div>

        <div class="footer">
            Generated by Azure Policy Coverage Gap Analyzer v1.0 | Microsoft Azure | PowerShell Script
        </div>
    </div>
</body>
</html>
"@

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzurePolicyCoverageGap {
    param (
        [Parameter(Mandatory = $true)]
        [string]$BaselineManagementGroupId,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [string]$CsvPath = "C:\Temp\AzurePolicyCoverageGap-Report.csv",

        [switch]$SkipResourceLevelCompliance
    )

    $startTime = Get-Date

    Write-Banner

    # Check for the specific Az sub-modules required (not the coarse Az umbrella module)
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.PolicyInsights")
    $missingModules = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if (@($missingModules).Count -gt 0) {
        Write-Host "  ⚠ Missing required module(s): $($missingModules -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        $installModules = Read-Host "  Install now? (Y/N)"

        if ($installModules -eq 'Y' -or $installModules -eq 'y') {
            Try {
                Write-Host ""
                Write-Host "  Installing missing module(s), please wait..." -ForegroundColor Cyan
                foreach ($moduleName in $missingModules) {
                    Install-Module -Name $moduleName -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                    Import-Module $moduleName -ErrorAction Stop
                }
                Write-Host "  ✓ Required module(s) installed successfully" -ForegroundColor Green
                Write-Host ""
            }
            Catch {
                Write-Host "  ✗ Error installing module(s): $_" -ForegroundColor Red
                Exit
            }
        }
        else {
            Write-Host ""
            Write-Host "  Installation declined. Cannot proceed without required modules." -ForegroundColor Yellow
            Exit
        }
    }

    # Initialize collections
    $allGapRows = @()
    $subscriptionResults = @()
    $script:PolicyNameCache = @{}
    $statistics = @{
        SuccessCount                   = 0
        ErrorCount                     = 0
        AssignmentGapCount             = 0
        ComplianceGapCount             = 0
        NonCompliantPolicyDistribution = @{}
        GapTypeDistribution            = @{
            "Assignment Gap" = 0
            "Compliance Gap" = 0
        }
        ScopeLevelDistribution         = @{
            Subscription  = 0
            ResourceGroup = 0
            Resource      = 0
        }
    }

    # Check for an active session
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext) {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    # Resolve the baseline Management Group and its Subscription tree
    Write-Host "  Resolving Management Group tree beneath '$BaselineManagementGroupId'..." -ForegroundColor Cyan

    Try {
        $baselineMg = Get-AzManagementGroup -GroupId $BaselineManagementGroupId -Expand -Recurse -ErrorAction Stop
    }
    Catch {
        Write-Host "  ✗ Failed to resolve Management Group '$BaselineManagementGroupId': $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $treeSubscriptionIds = Get-ChildSubscriptionIds -ManagementGroupNode $baselineMg

    if ($SubscriptionIds) {
        $inScopeSubscriptionIds = @($treeSubscriptionIds | Where-Object { $SubscriptionIds -contains $_ })
        $notFound = @($SubscriptionIds | Where-Object { $treeSubscriptionIds -notcontains $_ })
        if ($notFound.Count -gt 0) {
            Write-Warning "The following -SubscriptionIds were not found beneath '$BaselineManagementGroupId' and will be skipped: $($notFound -join ', ')"
        }
    }
    else {
        $inScopeSubscriptionIds = $treeSubscriptionIds
    }

    if ($inScopeSubscriptionIds.Count -eq 0) {
        Write-Host "  ✗ No in-scope subscriptions were found beneath '$BaselineManagementGroupId'." -ForegroundColor Red
        return
    }

    # Resolve baseline requirements: assignments created DIRECTLY at the baseline Management Group
    Write-Host "  Resolving baseline policy/initiative assignments..." -ForegroundColor Cyan

    $mgScope = "/providers/Microsoft.Management/managementGroups/$BaselineManagementGroupId"
    $directAssignmentPrefix = "$mgScope/providers/Microsoft.Authorization/policyAssignments/"

    Try {
        $allAssignmentsAtMg = Get-AzPolicyAssignment -Scope $mgScope -ErrorAction Stop
    }
    Catch {
        Write-Host "  ✗ Failed to retrieve policy assignments at '$mgScope': $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $baselineAssignments = @($allAssignmentsAtMg | Where-Object {
            $assignmentResourceId = if ($_.ResourceId) { $_.ResourceId } elseif ($_.Id) { $_.Id } else { "" }
            $assignmentResourceId -like "$directAssignmentPrefix*"
        })

    if ($baselineAssignments.Count -eq 0) {
        Write-Host "  ⚠ No policy/initiative assignments found directly at '$BaselineManagementGroupId'. Nothing to evaluate." -ForegroundColor Yellow
        return
    }

    # Resolve display names and NotScopes per baseline assignment
    $baselineRequirements = @()
    foreach ($assignment in $baselineAssignments) {
        $assignmentResourceId = if ($assignment.ResourceId) { $assignment.ResourceId } elseif ($assignment.Id) { $assignment.Id } else { $null }
        $policyDefinitionId = if ($assignment.PolicyDefinitionId) { $assignment.PolicyDefinitionId } elseif ($assignment.Properties.PolicyDefinitionId) { $assignment.Properties.PolicyDefinitionId } else { $null }
        $notScopes = if ($assignment.NotScopes) { @($assignment.NotScopes) } elseif ($assignment.Properties.NotScopes) { @($assignment.Properties.NotScopes) } else { @() }
        $displayName = if ($assignment.DisplayName) { $assignment.DisplayName } elseif ($assignment.Properties.DisplayName) { $assignment.Properties.DisplayName } else { $assignment.Name }

        $baselineRequirements += [PSCustomObject]@{
            AssignmentId       = $assignmentResourceId
            AssignmentName     = $assignment.Name
            DisplayName        = $displayName
            PolicyDefinitionId = $policyDefinitionId
            PolicyDisplayName  = if ($policyDefinitionId) { Get-BaselinePolicyDisplayName -PolicyDefinitionId $policyDefinitionId } else { "Could not be confirmed" }
            IsInitiative       = ($policyDefinitionId -match '/policySetDefinitions/')
            NotScopes          = $notScopes
        }
    }

    Write-Host "  ✓ Resolved $($baselineRequirements.Count) baseline requirement(s) across $($inScopeSubscriptionIds.Count) in-scope subscription(s)" -ForegroundColor Green

    # Resolve subscription objects (for display names)
    $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $inScopeSubscriptionIds -contains $_.Id })
    $subscriptionCount = $subscriptions.Count

    # Store session info / scan parameters for reporting
    $sessionInfo = @{
        Tenant      = $currentContext.Tenant.Id
        Account     = $currentContext.Account.Id
        Environment = $currentContext.Environment.Name
    }

    $scanParameters = @{
        BaselineManagementGroupId = $BaselineManagementGroupId
        BaselineRequirementCount  = $baselineRequirements.Count
        ResourceLevelScan         = if ($SkipResourceLevelCompliance.IsPresent) { "Skipped" } else { "Enabled" }
        ExportEnabled             = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
    }

    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $currentContext.Tenant.Id
        "Account"     = $currentContext.Account.Id
        "Environment" = $currentContext.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Baseline Management Group" = $BaselineManagementGroupId
        "Baseline Requirements"     = $baselineRequirements.Count
        "Subscriptions In Scope"    = $subscriptionCount
        "Resource-Level Scan"       = if ($SkipResourceLevelCompliance.IsPresent) { "Skipped" } else { "Enabled" }
        "Export to CSV"             = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"               = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subscriptionCount -CurrentItem "Starting..."

    $maxNameLength = ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
    $maxNameLength = [math]::Max($maxNameLength, 35)

    $subscriptionIndex = 1

    foreach ($sub in $subscriptions) {
        Try {
            Write-ProgressBar -Current $subscriptionIndex -Total $subscriptionCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $subGapCount = 0
            $subResourceId = "/subscriptions/$($sub.Id)"

            # ---- Assignment Gap check: Subscription + Resource Group level ----
            $resourceGroups = @(Get-AzResourceGroup -ErrorAction Stop)

            foreach ($requirement in $baselineRequirements) {
                $subExcluded = $false
                foreach ($notScope in $requirement.NotScopes) {
                    if ($subResourceId -like "$notScope*") { $subExcluded = $true; break }
                }

                if ($subExcluded) {
                    $allGapRows += [PSCustomObject]@{
                        GapType           = "Assignment Gap"
                        ScopeLevel        = "Subscription"
                        SubscriptionName  = $sub.Name
                        SubscriptionId    = $sub.Id
                        ResourceGroupName = $null
                        ResourceId        = $null
                        ResourceType      = $null
                        RequirementName   = $requirement.DisplayName
                        RequirementType   = if ($requirement.IsInitiative) { "Initiative" } else { "Policy" }
                        ComplianceState   = $null
                        Reason            = "Subscription excluded via NotScopes on baseline assignment '$($requirement.AssignmentName)'"
                    }
                    $subGapCount++
                    $statistics.AssignmentGapCount++
                    $statistics.GapTypeDistribution["Assignment Gap"]++
                    $statistics.ScopeLevelDistribution.Subscription++

                    $key = $requirement.DisplayName
                    if ($statistics.NonCompliantPolicyDistribution.ContainsKey($key)) { $statistics.NonCompliantPolicyDistribution[$key]++ } else { $statistics.NonCompliantPolicyDistribution[$key] = 1 }

                    continue
                }

                # Subscription is covered; check each Resource Group for a narrower exclusion
                foreach ($rg in $resourceGroups) {
                    $rgResourceId = "$subResourceId/resourceGroups/$($rg.ResourceGroupName)"
                    $rgExcluded = $false
                    foreach ($notScope in $requirement.NotScopes) {
                        if ($rgResourceId -like "$notScope*") { $rgExcluded = $true; break }
                    }

                    if ($rgExcluded) {
                        $allGapRows += [PSCustomObject]@{
                            GapType           = "Assignment Gap"
                            ScopeLevel        = "ResourceGroup"
                            SubscriptionName  = $sub.Name
                            SubscriptionId    = $sub.Id
                            ResourceGroupName = $rg.ResourceGroupName
                            ResourceId        = $null
                            ResourceType      = $null
                            RequirementName   = $requirement.DisplayName
                            RequirementType   = if ($requirement.IsInitiative) { "Initiative" } else { "Policy" }
                            ComplianceState   = $null
                            Reason            = "Resource Group excluded via NotScopes on baseline assignment '$($requirement.AssignmentName)'"
                        }
                        $subGapCount++
                        $statistics.AssignmentGapCount++
                        $statistics.GapTypeDistribution["Assignment Gap"]++
                        $statistics.ScopeLevelDistribution.ResourceGroup++

                        $key = $requirement.DisplayName
                        if ($statistics.NonCompliantPolicyDistribution.ContainsKey($key)) { $statistics.NonCompliantPolicyDistribution[$key]++ } else { $statistics.NonCompliantPolicyDistribution[$key] = 1 }
                    }
                }
            }

            # ---- Compliance Gap check: Resource level, via Policy Insights ----
            if (-not $SkipResourceLevelCompliance) {
                $baselineAssignmentIds = $baselineRequirements.AssignmentId

                Try {
                    $nonCompliantStates = @(Get-AzPolicyState -SubscriptionId $sub.Id -Filter "ComplianceState eq 'NonCompliant'" -ErrorAction Stop)
                }
                Catch {
                    Write-Warning "Failed to retrieve Policy Insights states for subscription '$($sub.Name)': $($_.Exception.Message)"
                    $nonCompliantStates = @()
                }

                foreach ($state in $nonCompliantStates) {
                    if ($baselineAssignmentIds -notcontains $state.PolicyAssignmentId) { continue }

                    $matchingRequirement = $baselineRequirements | Where-Object { $_.AssignmentId -eq $state.PolicyAssignmentId } | Select-Object -First 1
                    $rgNameFromResourceId = if ($state.ResourceId -match '/resourceGroups/([^/]+)/') { $matches[1] } else { "Could not be confirmed" }

                    $allGapRows += [PSCustomObject]@{
                        GapType           = "Compliance Gap"
                        ScopeLevel        = "Resource"
                        SubscriptionName  = $sub.Name
                        SubscriptionId    = $sub.Id
                        ResourceGroupName = $rgNameFromResourceId
                        ResourceId        = $state.ResourceId
                        ResourceType      = $state.ResourceType
                        RequirementName   = if ($matchingRequirement) { $matchingRequirement.DisplayName } else { "Could not be confirmed" }
                        RequirementType   = if ($matchingRequirement -and $matchingRequirement.IsInitiative) { "Initiative" } else { "Policy" }
                        ComplianceState   = $state.ComplianceState
                        Reason            = "Resource is NonCompliant against baseline requirement"
                    }
                    $subGapCount++
                    $statistics.ComplianceGapCount++
                    $statistics.GapTypeDistribution["Compliance Gap"]++
                    $statistics.ScopeLevelDistribution.Resource++

                    $key = if ($matchingRequirement) { $matchingRequirement.DisplayName } else { "Unknown requirement" }
                    if ($statistics.NonCompliantPolicyDistribution.ContainsKey($key)) { $statistics.NonCompliantPolicyDistribution[$key]++ } else { $statistics.NonCompliantPolicyDistribution[$key] = 1 }
                }
            }

            # Clear the progress line and display result
            Write-Host "`r" -NoNewline
            Write-Host (" " * 120) -NoNewline
            Write-Host "`r" -NoNewline

            $paddedName = $sub.Name.PadRight($maxNameLength)

            Write-Host "  " -NoNewline
            if ($subGapCount -gt 0) {
                Write-Host "⚠ " -NoNewline -ForegroundColor Yellow
                Write-Host $paddedName -NoNewline -ForegroundColor Yellow
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "$subGapCount gap(s)" -ForegroundColor White
                $statistics.SuccessCount++
                $subscriptionResults += @{ Name = $sub.Name; Count = "$subGapCount gap(s)"; Status = "Warning" }
            }
            else {
                Write-Host "✓ " -NoNewline -ForegroundColor Green
                Write-Host $paddedName -NoNewline -ForegroundColor Green
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "No gaps found" -ForegroundColor DarkGray
                $statistics.SuccessCount++
                $subscriptionResults += @{ Name = $sub.Name; Count = "No gaps found"; Status = "Success" }
            }

            $subscriptionIndex++
        }
        Catch {
            Write-Host "`r" -NoNewline
            Write-Host (" " * 120) -NoNewline
            Write-Host "`r" -NoNewline

            $paddedName = $sub.Name.PadRight($maxNameLength)
            Write-Host "  " -NoNewline
            Write-Host "✗ " -NoNewline -ForegroundColor Red
            Write-Host $paddedName -NoNewline -ForegroundColor Red
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
            $statistics.ErrorCount++
            $subscriptionResults += @{ Name = $sub.Name; Count = "Failed: $($_.Exception.Message)"; Status = "Error" }
            $subscriptionIndex++
        }
    }

    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration

    $scanSummary = @{
        TotalGaps            = $allGapRows.Count
        AssignmentGaps       = $statistics.AssignmentGapCount
        ComplianceGaps       = $statistics.ComplianceGapCount
        SubscriptionsScanned = $subscriptionCount
        ExecutionTime        = $durationFormatted
    }

    Write-Summary -Data @{
        "Total Subscriptions Scanned" = $subscriptionCount
        "Successful"                  = $statistics.SuccessCount
        "Errors"                      = $statistics.ErrorCount
        "Total Gaps Found"            = $allGapRows.Count
        "Assignment Gaps"             = $statistics.AssignmentGapCount
        "Compliance Gaps"             = $statistics.ComplianceGapCount
        "Execution Time"              = $durationFormatted
    }

    Write-TopItems -Title "Top 5 Policies/Initiatives Driving Gaps" -Items $statistics.NonCompliantPolicyDistribution -Suffix "gaps"
    Write-Distribution -Title "Gap Type Distribution" -Data $statistics.GapTypeDistribution -Total $allGapRows.Count
    Write-Distribution -Title "Scope Level Distribution" -Data $statistics.ScopeLevelDistribution -Total $allGapRows.Count

    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allGapRows.Count -gt 0) {
        if ($ExportToCsv) {
            Try {
                $allGapRows | Export-Csv -Path $CsvPath -NoTypeInformation
                $csvExported = $true
            }
            Catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        Try {
            $htmlPath = $CsvPath -replace '\.csv$', '.html'
            if (-not $htmlPath.EndsWith('.html')) {
                $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
            }

            $htmlContent = Generate-HtmlReport `
                -SessionInfo $sessionInfo `
                -ScanParameters $scanParameters `
                -ScanSummary $scanSummary `
                -SubscriptionResults $subscriptionResults `
                -TopNonCompliantPolicies $statistics.NonCompliantPolicyDistribution `
                -GapTypeDistribution $statistics.GapTypeDistribution `
                -ScopeLevelDistribution $statistics.ScopeLevelDistribution `
                -TotalGaps $allGapRows.Count `
                -CsvPath $(if ($csvExported) { $CsvPath } else { $null }) `
                -HtmlPath $htmlPath `
                -GridViewOpened $false

            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
            $htmlExported = $true
        }
        Catch {
            Write-Host "  ✗ HTML report generation failed: $_" -ForegroundColor Red
        }

        Try {
            $allGapRows | Out-GridView -Title "Azure Policy Coverage Gaps"
            $gridViewOpened = $true
        }
        Catch {
            Write-Host "  ⚠ Could not open Grid View" -ForegroundColor Yellow
        }
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        Write-OutputFiles `
            -CsvPath $(if ($csvExported) { $CsvPath } else { $null }) `
            -HtmlPath $(if ($htmlExported) { $htmlPath } else { $null }) `
            -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }

    return $allGapRows
}
