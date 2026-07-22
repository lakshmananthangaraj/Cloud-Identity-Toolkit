<#

Author          : Lakshmanan Thangaraj
Version         : 1.8
Created-On      : 1 October 2024
Modified-On     : 22 July 2026

.SYNOPSIS
    Retrieves and analyzes Azure RBAC role assignments across one or more subscriptions,
    with optional CSV export and an auto-generated HTML summary report.

.DESCRIPTION
    The Get-AzureRBACAssignments function retrieves Azure Role-Based Access Control (RBAC)
    role assignments across one or multiple Azure subscriptions.

    It supports:
        - Scanning all subscriptions in the tenant, or a specified list of subscription IDs
        - Filtering by Azure resource provider (-ResourceType), e.g. Microsoft.KeyVault,
          Microsoft.Storage, Microsoft.Compute
        - Filtering by RBAC role name (-RoleName), e.g. Reader, Contributor, Key Vault
          Administrator
        - Real-time progress tracking with a live progress bar and color-coded console
          status per subscription
        - Scope-level classification (Management Group / Subscription / Resource Group /
          Resource) and Principal Type distribution (User / Group / Service Principal)
        - Optional CSV export of all collected assignments
        - Always-on HTML report generation (Azure-themed, self-contained) summarizing
          session info, scan parameters, statistics, and distributions
        - Interactive Grid View display of results (where a GUI is available)

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account/context.
    This is also the default behavior if -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan, instead of all subscriptions.
    Ignored if -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all collected RBAC assignments to the path given in
    -CsvPath. An HTML report is generated regardless of whether this switch is used.

.PARAMETER CsvPath
    Path where the CSV export will be written if -ExportToCsv is specified. Also used
    to derive the HTML report's file name/location (same path, .html extension).
    Default: C:\Temp\AzureRBACAssignments-Report.csv

.PARAMETER ResourceType
    Optional filter. Restricts results to RBAC assignments scoped to a specific Azure
    resource provider, e.g. "Microsoft.KeyVault", "Microsoft.Storage", "Microsoft.Compute".

.PARAMETER RoleName
    Optional filter. Restricts results to a specific RBAC role definition name,
    e.g. "Reader", "Contributor", "Key Vault Administrator".

.OUTPUTS
    None directly to the pipeline. Always writes an HTML report alongside -CsvPath
    (or the default path). Optionally writes a CSV file if -ExportToCsv is specified.
    Displays results in an interactive Grid View window where a GUI is available.

.EXAMPLE
    Get-AzureRBACAssignments -AllSubscriptions

.EXAMPLE
    Get-AzureRBACAssignments -SubscriptionIds @("SubscriptionID1", "SubscriptionID2")

.EXAMPLE
    Get-AzureRBACAssignments -AllSubscriptions -ResourceType Microsoft.KeyVault

.EXAMPLE
    Get-AzureRBACAssignments -AllSubscriptions -RoleName Reader

.EXAMPLE
    Get-AzureRBACAssignments -AllSubscriptions -ResourceType Microsoft.KeyVault -RoleName "Key Vault Administrator"

.EXAMPLE
    Get-AzureRBACAssignments -AllSubscriptions -ExportToCsv -CsvPath "C:\Path\To\Output.csv"

.NOTES
    Requirements:
        - Az PowerShell module (installed/imported automatically if missing, with
          user consent at the console prompt)
        - A valid Azure account with Reader role (minimum) at the subscription level

    Permissions:
        - Microsoft.Authorization/roleAssignments/read at the subscription level
        - Access to each specified subscription, if using -SubscriptionIds

    Known limitations:
        - Interactive Grid View requires a GUI-capable session (Windows PowerShell ISE,
          or Microsoft.PowerShell.GraphicalTools on PS7). In headless/CI/Linux sessions
          this step is skipped gracefully; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is a Windows-specific path. On macOS/Linux
          PowerShell 7, supply an explicit -CsvPath.
        - If neither -AllSubscriptions nor -SubscriptionIds is supplied, the function
          defaults to scanning ALL subscriptions visible to the current account with
          no additional confirmation prompt.

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Oct-2024)      - Initial release. Retrieved RBAC assignments across
                                 all or selected subscriptions.
        1.1 (11-Feb-2026)      - Added -ResourceType parameter to filter RBAC
                                 assignments by Azure resource provider.
        1.2 (11-Feb-2026)      - Added -RoleName parameter to filter RBAC assignments
                                 by specific RBAC roles. Enhanced usage flexibility
                                 for targeted RBAC audits and governance scenarios.
        1.3 (27-Feb-2026)      - Enhanced UI/UX with modern, clean console design.
                                 Added visual progress tracking with progress bars,
                                 color-coded status messages, and execution summary
                                 with key metrics. Improved error messages with
                                 context. Added statistics tracking (role distribution,
                                 object types). No changes to core logic.
        1.4 (27-Feb-2026)      - Added ResourceType column in output. Implemented
                                 accurate scope parsing to detect Management Group /
                                 Subscription / Resource Group / Resource-level
                                 assignments. No changes to existing logic.
        1.5 (27-Feb-2026)      - Added ResourceType distribution statistics, Top 5
                                 Resource Types summary, and Scope Level percentage
                                 distribution. No changes to core logic.
        1.6 (27-Feb-2026)      - Enhanced Scope Level Distribution tracking. Added
                                 Management Group level assignment tracking and
                                 Principal Type distribution (User, Group, Service
                                 Principal). Refactored for performance/maintainability.
        1.7 (27-Feb-2026)      - Added HTML report generation with modern Azure-themed
                                 design, auto-generated at end of execution alongside
                                 CSV export for a complete audit trail. No changes to
                                 existing logic.
        1.8 (22-Jul-2026)      - Documentation-only update: reformatted header into
                                 standard comment-based help (.SYNOPSIS/.PARAMETER/
                                 .OUTPUTS/.EXAMPLE/.NOTES/.LINK), added explicit
                                 Known Limitations section (Grid View GUI dependency,
                                 Windows-specific default path, silent all-subscription
                                 default). No functional/logic changes.

.LINK
    Generate-RBACVisualizationReport.ps1 (companion script — consumes this script's
    CSV export to produce an interactive HTML visualization report)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/RBAC/Generate-RBACVisualizationReport.ps1

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
    Write-CenteredText "Azure RBAC Assignment Scanner v1.7" -Color White
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
        } else {
            $valueColor = "White"
        }
        
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(18) -NoNewline -ForegroundColor Gray
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
    
    # Move cursor to beginning of line and clear it
    Write-Host "`r" -NoNewline
    Write-Host ("  Progress: ") -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White
    
    if ($CurrentItem) {
        # Truncate if too long
        $maxLength = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLength) { 
            $CurrentItem.Substring(0, $maxLength - 3) + "..." 
        } else { 
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

Function Write-TopRoles {
    param([hashtable]$Roles)
    
    if ($Roles.Count -eq 0) { return }
    
    Write-Host ""
    Write-Host "  Top 5 Most Assigned Roles" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    
    $counter = 1
    foreach ($role in ($Roles.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
        Write-Host "  " -NoNewline
        Write-Host "$counter. " -NoNewline -ForegroundColor Gray
        Write-Host $role.Key.PadRight(40) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($role.Value) assignments" -ForegroundColor Cyan
        $counter++
    }
}

Function Write-TopResourceTypes {
    param([hashtable]$ResourceTypes)

    if ($ResourceTypes.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Top 5 Resource Types" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $counter = 1
    foreach ($item in ($ResourceTypes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
        Write-Host "  " -NoNewline
        Write-Host "$counter. " -NoNewline -ForegroundColor Gray
        Write-Host $item.Key.PadRight(40) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($item.Value) assignments" -ForegroundColor Cyan
        $counter++
    }
}

Function Write-ScopeDistribution {
    param(
        [hashtable]$ScopeData,
        [int]$TotalAssignments
    )

    if ($TotalAssignments -eq 0) { return }

    Write-Host ""
    Write-Host "  Scope Level Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $ScopeData.Keys) {
        $percent = [math]::Round(($ScopeData[$key] / $TotalAssignments) * 100)
        Write-Host "  $key Assignments".PadRight(35) -NoNewline
        Write-Host ": $percent%" -ForegroundColor White
    }
}

Function Write-PrincipalDistribution {
    param(
        [hashtable]$PrincipalData,
        [int]$TotalAssignments
    )

    if ($PrincipalData.Count -eq 0 -or $TotalAssignments -eq 0) { return }

    Write-Host ""
    Write-Host "  Principal Type Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($item in ($PrincipalData.GetEnumerator() | Sort-Object Value -Descending)) {
        $percent = [math]::Round(($item.Value / $TotalAssignments) * 100)
        Write-Host "  $($item.Key)".PadRight(35) -NoNewline
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

Function Generate-HtmlReport {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [hashtable]$ScanSummary,
        [array]$SubscriptionResults,
        [hashtable]$TopRoles,
        [hashtable]$TopResourceTypes,
        [hashtable]$ScopeDistribution,
        [hashtable]$PrincipalDistribution,
        [int]$TotalAssignments,
        [string]$CsvPath,
        [string]$HtmlPath,
        [bool]$GridViewOpened
    )
    
    $timestamp = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"
    
    # Build subscription results HTML
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
    
    # Build top roles HTML
    $topRolesHtml = ""
    $counter = 1
    foreach ($role in ($TopRoles.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
        $topRolesHtml += @"
                    <div class="top-item">
                        <div class="rank">$counter</div>
                        <div class="item-name">$($role.Key)</div>
                        <div class="item-count">$($role.Value) assignments</div>
                    </div>
"@
        $counter++
    }
    
    # Build top resource types HTML
    $topResourceTypesHtml = ""
    $counter = 1
    foreach ($item in ($TopResourceTypes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
        $topResourceTypesHtml += @"
                    <div class="top-item">
                        <div class="rank">$counter</div>
                        <div class="item-name">$($item.Key)</div>
                        <div class="item-count">$($item.Value) assignments</div>
                    </div>
"@
        $counter++
    }
    
    # Build scope distribution HTML
    $scopeDistributionHtml = ""
    foreach ($key in $ScopeDistribution.Keys) {
        $percent = if ($TotalAssignments -gt 0) { [math]::Round(($ScopeDistribution[$key] / $TotalAssignments) * 100) } else { 0 }
        $scopeDistributionHtml += @"
                    <div class="distribution-item">
                        <div class="distribution-label">
                            <span>$key Assignments</span>
                            <span>$percent%</span>
                        </div>
                        <div class="distribution-bar">
                            <div class="distribution-fill" style="width: $percent%;"></div>
                        </div>
                    </div>
"@
    }
    
    # Build principal distribution HTML
    $principalDistributionHtml = ""
    foreach ($item in ($PrincipalDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $percent = if ($TotalAssignments -gt 0) { [math]::Round(($item.Value / $TotalAssignments) * 100) } else { 0 }
        $principalDistributionHtml += @"
                    <div class="distribution-item">
                        <div class="distribution-label">
                            <span>$($item.Key)</span>
                            <span>$percent%</span>
                        </div>
                        <div class="distribution-bar">
                            <div class="distribution-fill" style="width: $percent%;"></div>
                        </div>
                    </div>
"@
    }
    
    # Build output files HTML
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
    
    # Generate complete HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure RBAC Assignment Scanner - Execution Report</title>
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
            <h1>Azure RBAC Assignment Scanner</h1>
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
                        <div class="info-label">Scope</div>
                        <div class="info-value">$($ScanParameters.Scope)</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Resource Type Filter</div>
                        <div class="info-value$(if ([string]::IsNullOrWhiteSpace($ScanParameters.ResourceType)) { ' none' })">$(if ($ScanParameters.ResourceType) { $ScanParameters.ResourceType } else { 'None' })</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Role Name Filter</div>
                        <div class="info-value$(if ([string]::IsNullOrWhiteSpace($ScanParameters.RoleName)) { ' none' })">$(if ($ScanParameters.RoleName) { $ScanParameters.RoleName } else { 'None' })</div>
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
                        <div class="stat-number">$($ScanSummary.TotalAssignments)</div>
                        <div class="stat-label">Total Assignments</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">$($ScanSummary.SubscriptionsScanned)</div>
                        <div class="stat-label">Subscriptions Scanned</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">$($ScanSummary.UniquePrincipals)</div>
                        <div class="stat-label">Unique Principals</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">$($ScanSummary.UniqueRoles)</div>
                        <div class="stat-label">Unique Roles</div>
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
                <h2 class="section-title">👥 Top 5 Most Assigned Roles</h2>
                <div class="top-list">
$topRolesHtml
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">📦 Top 5 Resource Types</h2>
                <div class="top-list">
$topResourceTypesHtml
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">🎯 Scope Level Distribution</h2>
                <div class="distribution">
$scopeDistributionHtml
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">👤 Principal Type Distribution</h2>
                <div class="distribution">
$principalDistributionHtml
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
            Generated by Azure RBAC Assignment Scanner v1.7 | Microsoft Azure | PowerShell Script
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureRBACAssignments
{
    param (
        [switch]$AllSubscriptions,
        [string[]]$SubscriptionIds,
        [switch]$ExportToCsv,
        [string]$CsvPath = "C:\Temp\AzureRBACAssignments-Report.csv",
        [string]$ResourceType,
        [string]$RoleName
    )

    # Start timing
    $startTime = Get-Date

    # Display banner
    Write-Banner

    # Check if the Az module is installed
    if (-not (Get-Module -ListAvailable -Name Az)) 
    {
        Write-Host "  ⚠ Az module not found" -ForegroundColor Yellow
        Write-Host ""
        $installAz = Read-Host "  Install now? (Y/N)"
    
        if ($installAz -eq 'Y' -or $installAz -eq 'y') 
        {
            try 
            {
                Write-Host ""
                Write-Host "  Installing Az module, please wait..." -ForegroundColor Cyan
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "  ✓ Az module installed successfully" -ForegroundColor Green
                Write-Host ""
            } 
            catch 
            {
                Write-Host "  ✗ Error installing Az module: $_" -ForegroundColor Red
                Exit
            }
        } 
        else 
        {
            Write-Host ""
            Write-Host "  Installation declined. Cannot proceed without Az module." -ForegroundColor Yellow
            Exit
        }
    }

    # Initialize collections
    $allRoleAssignments = @()
    $subscriptionResults = @()
    $statistics = @{
        SuccessCount = 0
        ErrorCount = 0
        RoleDistribution = @{}
        UniquePrincipals = @()
        ResourceTypeDistribution = @{}
        ScopeLevelCount = @{
            ManagementGroup = 0
            Subscription = 0
            ResourceGroup = 0
            Resource = 0
        }
        PrincipalTypeDistribution = @{}
    }

    # Check for an active session
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext) 
    {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    # Get subscriptions
    if ($AllSubscriptions -or -not $SubscriptionIds) 
    {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue) 
        $scopeText = "All Subscriptions"
    } 
    else 
    {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count))"
    }

    $subscriptionCount = $subscriptions.Count

    # Store session info for HTML report
    $sessionInfo = @{
        Tenant = $currentContext.Tenant.Id
        Account = $currentContext.Account.Id
        Environment = $currentContext.Environment.Name
    }

    # Store scan parameters for HTML report
    $scanParameters = @{
        Scope = "$scopeText ($subscriptionCount found)"
        ResourceType = $ResourceType
        RoleName = $RoleName
        ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
    }

    # Display Session Information
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $currentContext.Tenant.Id
        "Account"     = $currentContext.Account.Id
        "Environment" = $currentContext.Environment.Name
    }

    # Display Parameters
    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"           = "$scopeText ($subscriptionCount found)"
        "Resource Type"   = if ($ResourceType) { $ResourceType } else { "" }
        "Role Name"       = if ($RoleName) { $RoleName } else { "" }
        "Export to CSV"   = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"     = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # Start scanning
    Write-ScanProgress
    
    # Initial progress bar
    Write-ProgressBar -Current 0 -Total $subscriptionCount -CurrentItem "Starting..."

    # Calculate max subscription name length for alignment
    $maxNameLength = ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
    $maxNameLength = [math]::Max($maxNameLength, 35)

    $subscriptionIndex = 1

    foreach ($sub in $subscriptions) 
    {
        try 
        {
            # Update progress bar with current subscription
            Write-ProgressBar -Current $subscriptionIndex -Total $subscriptionCount -CurrentItem $sub.Name
            
            # Set context
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            # Get role assignments
            $roleAssignments = Get-AzRoleAssignment

            # Apply filters
            if ($ResourceType) 
            {
                $roleAssignments = $roleAssignments | Where-Object { $_.Scope -like "*/providers/$ResourceType/*" }
            }

            if ($RoleName)
            {
                $roleAssignments = $roleAssignments | Where-Object { $_.RoleDefinitionName -eq $RoleName }
            }

            $assignmentCount = $roleAssignments.Count

            # Process assignments
            foreach ($assignment in $roleAssignments) {
                
                # Determine Resource Type from Scope
                $scope = $assignment.Scope
                if (-not $scope) { $scope = "" }
                $resourceTypeValue = ""

                if ($scope -like "/providers/Microsoft.Management/managementGroups/*") {
                    $resourceTypeValue = "ManagementGroup"
                }
                elseif ($scope -match "^/subscriptions/[^/]+$") {
                    $resourceTypeValue = "Subscription"
                }
                elseif ($scope -match "^/subscriptions/[^/]+/resourceGroups/[^/]+$") {
                    $resourceTypeValue = "ResourceGroup"
                }
                elseif ($scope -match "/providers/([^/]+/[^/]+)") {
                    $resourceTypeValue = $matches[1]
                }
                else {
                    $resourceTypeValue = "Unknown"
                }

                # Track statistics
                if ($assignment.RoleDefinitionName) {
                    if ($statistics.RoleDistribution.ContainsKey($assignment.RoleDefinitionName)) {
                        $statistics.RoleDistribution[$assignment.RoleDefinitionName]++
                    } else {
                        $statistics.RoleDistribution[$assignment.RoleDefinitionName] = 1
                    }
                }
                
                if ($assignment.DisplayName -and $assignment.DisplayName -notin $statistics.UniquePrincipals) {
                    $statistics.UniquePrincipals += $assignment.DisplayName
                }

                # Track ResourceType distribution
                if ([string]::IsNullOrWhiteSpace($resourceTypeValue)) {
                    $resourceTypeValue = "Unknown"
                }

                if ($statistics.ResourceTypeDistribution.ContainsKey($resourceTypeValue)) {
                    $statistics.ResourceTypeDistribution[$resourceTypeValue]++
                }
                else {
                    $statistics.ResourceTypeDistribution[$resourceTypeValue] = 1
                }

                # Track Scope Level Distribution
                switch ($resourceTypeValue) {
                    "ManagementGroup" { $statistics.ScopeLevelCount.ManagementGroup++ }
                    "Subscription"    { $statistics.ScopeLevelCount.Subscription++ }
                    "ResourceGroup"   { $statistics.ScopeLevelCount.ResourceGroup++ }
                    default {
                        if ($resourceTypeValue -ne "Unknown") {
                            $statistics.ScopeLevelCount.Resource++
                        }
                    }
                }

                # Track Principal Type distribution
                $principalType = if ($assignment.ObjectType) { $assignment.ObjectType } else { "Unknown" }

                if ($statistics.PrincipalTypeDistribution.ContainsKey($principalType)) {
                    $statistics.PrincipalTypeDistribution[$principalType]++
                }
                else {
                    $statistics.PrincipalTypeDistribution[$principalType] = 1
                }

                # Add to collection
                $allRoleAssignments += [pscustomobject]@{
                    SubscriptionName   = $sub.Name
                    SubscriptionId     = $sub.Id
                    TenantId           = $sub.TenantId
                    DisplayName        = $assignment.DisplayName
                    SignInName         = $assignment.SignInName
                    ObjectType         = $assignment.ObjectType
                    RoleDefinitionName = $assignment.RoleDefinitionName
                    ResourceType       = $resourceTypeValue
                    Scope              = $assignment.Scope
                }
            }

            # Clear the progress line and display result
            Write-Host "`r" -NoNewline
            Write-Host (" " * 120) -NoNewline
            Write-Host "`r" -NoNewline
            
            $paddedName = $sub.Name.PadRight($maxNameLength)
            
            Write-Host "  " -NoNewline
            if ($assignmentCount -gt 0) {
                Write-Host "✓ " -NoNewline -ForegroundColor Green
                Write-Host $paddedName -NoNewline -ForegroundColor Green
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "$assignmentCount assignments" -ForegroundColor White
                $statistics.SuccessCount++
                $subscriptionResults += @{ Name = $sub.Name; Count = "$assignmentCount assignments"; Status = "Success" }
            } else {
                Write-Host "⚠ " -NoNewline -ForegroundColor Yellow
                Write-Host $paddedName -NoNewline -ForegroundColor Yellow
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "No assignments" -ForegroundColor DarkGray
                $statistics.SuccessCount++
                $subscriptionResults += @{ Name = $sub.Name; Count = "No assignments"; Status = "Warning" }
            }

            $subscriptionIndex++
        }
        catch 
        {
            # Clear the progress line
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

    # Calculate duration
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration

    # Prepare scan summary for HTML
    $scanSummary = @{
        TotalAssignments = $allRoleAssignments.Count
        SubscriptionsScanned = $subscriptionCount
        UniquePrincipals = $statistics.UniquePrincipals.Count
        UniqueRoles = $statistics.RoleDistribution.Count
        ExecutionTime = $durationFormatted
    }

    # Display summary
    Write-Summary -Data @{
        "Total Subscriptions Scanned" = $subscriptionCount
        "Successful"                  = $statistics.SuccessCount
        "Errors"                      = $statistics.ErrorCount
        "Total Assignments Found"     = $allRoleAssignments.Count
        "Unique Principals"           = $statistics.UniquePrincipals.Count
        "Unique Roles"                = $statistics.RoleDistribution.Count
        "Execution Time"              = $durationFormatted
    }

    # Display top roles
    Write-TopRoles -Roles $statistics.RoleDistribution

    # Display top resource types
    Write-TopResourceTypes -ResourceTypes $statistics.ResourceTypeDistribution
    
    # Display scope distribution
    Write-ScopeDistribution -ScopeData $statistics.ScopeLevelCount -TotalAssignments $allRoleAssignments.Count

    # Display principal distribution
    Write-PrincipalDistribution -PrincipalData $statistics.PrincipalTypeDistribution -TotalAssignments $allRoleAssignments.Count

    # Process output
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allRoleAssignments.Count -gt 0) 
    {
        # Export to CSV if requested
        if ($ExportToCsv) 
        {
            try {
                $allRoleAssignments | Export-Csv -Path $CsvPath -NoTypeInformation
                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # Generate HTML Report (always)
        try {
            $htmlPath = $CsvPath -replace '\.csv$', '.html'
            if (-not $htmlPath.EndsWith('.html')) {
                $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
            }
            
            $htmlContent = Generate-HtmlReport `
                -SessionInfo $sessionInfo `
                -ScanParameters $scanParameters `
                -ScanSummary $scanSummary `
                -SubscriptionResults $subscriptionResults `
                -TopRoles $statistics.RoleDistribution `
                -TopResourceTypes $statistics.ResourceTypeDistribution `
                -ScopeDistribution $statistics.ScopeLevelCount `
                -PrincipalDistribution $statistics.PrincipalTypeDistribution `
                -TotalAssignments $allRoleAssignments.Count `
                -CsvPath $(if ($csvExported) { $CsvPath } else { $null }) `
                -HtmlPath $htmlPath `
                -GridViewOpened $false
            
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML report generation failed: $_" -ForegroundColor Red
        }

        # Display in GridView
        try {
            $allRoleAssignments | Out-GridView -Title "Azure RBAC Role Assignments"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View" -ForegroundColor Yellow
        }
    }

    # Display output files
    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        Write-OutputFiles `
            -CsvPath $(if ($csvExported) { $CsvPath } else { $null }) `
            -HtmlPath $(if ($htmlExported) { $htmlPath } else { $null }) `
            -GridViewOpened $gridViewOpened
    } else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
