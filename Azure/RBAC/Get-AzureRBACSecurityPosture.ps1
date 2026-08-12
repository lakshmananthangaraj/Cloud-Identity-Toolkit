<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 12 August 2026
Modified-On     : 12 August 2026

.SYNOPSIS
    Analyzes Azure RBAC security posture across one or more subscriptions, surfacing
    high-risk assignments and least-privilege gaps with per-finding risk ratings.

.DESCRIPTION
    Get-AzureRBACSecurityPosture performs a comprehensive RBAC security posture
    assessment across Azure subscriptions. It examines role assignments for
    indicators of over-privilege, misconfiguration, and identity risk, including:

        - Privileged role detection (Owner, Contributor, User Access Administrator)
        - Custom role definition enumeration and custom-role assignment identification
        - Assignment scope classification (Management Group / Subscription / Resource Group
          / Resource) with risk weighting — broad scopes on powerful roles are rated High
        - Principal type classification (User / Group / ServicePrincipal) with
          GroupBased assignment flagging (group is identified; membership is not expanded
          in V1)
        - Service principal identification with AppId capture for remediation
        - PIM eligibility assessment (best-effort; requires Microsoft.Graph and
          PrivilegedAccess.Read.AzureResources; skips gracefully if unavailable)
        - Per-finding risk rating (High / Medium / Low / Informational) based on role
          privilege level and assignment scope
        - Optional CSV export of all collected findings
        - Always-on interactive HTML report (dark-themed, self-contained) with sidebar
          navigation, sortable findings table, stat cards, distribution charts, and
          per-finding detail drawer
        - Interactive Grid View display of findings (where a GUI is available)

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account/context.
    This is also the default behavior if -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan instead of all subscriptions.
    Ignored if -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all collected findings to the path given in -CsvPath.
    The HTML report is generated regardless of whether this switch is used.

.PARAMETER CsvPath
    Path where the CSV export will be written if -ExportToCsv is specified. The HTML
    report path is derived from this value by replacing the .csv extension with .html.
    Default: C:\Temp\AzureRBACSecurityPosture-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML report alongside -CsvPath
    (or the default path). Optionally writes a CSV file if -ExportToCsv is specified.
    Displays results in an interactive Grid View window where a GUI is available.

.EXAMPLE
    Get-AzureRBACSecurityPosture -AllSubscriptions

.EXAMPLE
    Get-AzureRBACSecurityPosture -SubscriptionIds @("SubscriptionID1", "SubscriptionID2")

.EXAMPLE
    Get-AzureRBACSecurityPosture -AllSubscriptions -ExportToCsv -CsvPath "C:\Audits\RBACPosture.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (12-Aug-2026) - Initial release. Privileged-role detection, custom role
                        enumeration, scope classification, principal-type analysis,
                        service principal capture, best-effort PIM assessment,
                        per-finding risk ratings, CSV + HTML report output.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts module — authentication and subscription enumeration
    2. Az.Resources module — role assignment and role definition retrieval
       (Microsoft.Authorization/roleAssignments/read at subscription scope)
    3. Microsoft.Graph module (optional) — PIM eligibility assessment
       Permission required: PrivilegedAccess.Read.AzureResources
       If absent, PIM columns are populated with "Not Assessed".
    4. A valid Azure account with Reader role (minimum) at the subscription level.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Group membership is not expanded in V1. Group-based assignments are flagged
      with the group identity; member enumeration requires Microsoft.Graph and
      is deferred to a future release.
    - PIM assessment is best-effort. If Microsoft.Graph, required permissions, or
      Azure AD P2 / Governance licensing are unavailable, PIM status is reported
      as "Not Assessed" and execution continues.
    - Interactive Grid View requires a GUI-capable session. In headless/CI/Linux
      sessions this step is skipped gracefully; CSV/HTML output is unaffected.
    - Default -CsvPath (C:\Temp\...) is a Windows-specific path. On macOS/Linux
      PowerShell 7, supply an explicit -CsvPath.
    - Management Group-scoped assignments are reported under the subscription
      context in which they appear; MG-level enumeration requires explicit
      Set-AzContext to a management group scope.

.LINK
    https://learn.microsoft.com/en-us/azure/role-based-access-control/overview

.LINK
    https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices

.LINK
    https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure

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
    Write-CenteredText "Azure RBAC Security Posture Analyzer v1.0" -Color White
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
        Write-Host $key.PadRight(22) -NoNewline -ForegroundColor Gray
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
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White

    if ($CurrentItem) {
        $maxLength = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLength) {
            $CurrentItem.Substring(0, $maxLength - 3) + "..."
        }
        else { $CurrentItem }

        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-Summary {
    param([hashtable]$Data)

    Write-Host ""
    Write-Host "  Scan Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys) {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(34) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-RiskDistribution {
    param(
        [hashtable]$RiskData,
        [int]$TotalFindings
    )

    if ($TotalFindings -eq 0) { return }

    Write-Host ""
    Write-Host "  Risk Level Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $riskColors = @{
        High          = "Red"
        Medium        = "Yellow"
        Low           = "Green"
        Informational = "Cyan"
    }

    foreach ($level in @("High", "Medium", "Low", "Informational")) {
        $count = if ($RiskData.ContainsKey($level)) { $RiskData[$level] } else { 0 }
        $percent = [math]::Round(($count / $TotalFindings) * 100)
        $color = $riskColors[$level]

        Write-Host "  " -NoNewline
        Write-Host $level.PadRight(18) -NoNewline -ForegroundColor $color
        Write-Host ": $count findings ($percent%)" -ForegroundColor White
    }
}

Function Write-TopPrivilegedRoles {
    param([hashtable]$Roles)

    if ($Roles.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Top 5 Privileged Role Assignments" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $counter = 1
    foreach ($role in ($Roles.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
        Write-Host "  " -NoNewline
        Write-Host "$counter. " -NoNewline -ForegroundColor Gray
        Write-Host $role.Key.PadRight(42) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($role.Value) assignments" -ForegroundColor Cyan
        $counter++
    }
}

Function Write-PrincipalDistribution {
    param(
        [hashtable]$PrincipalData,
        [int]$TotalFindings
    )

    if ($PrincipalData.Count -eq 0 -or $TotalFindings -eq 0) { return }

    Write-Host ""
    Write-Host "  Principal Type Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($item in ($PrincipalData.GetEnumerator() | Sort-Object Value -Descending)) {
        $percent = [math]::Round(($item.Value / $TotalFindings) * 100)
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


#------------------------------------------------------------------------ [ Risk Rating Engine ]

Function Get-RBACRiskRating {
    param(
        [string]$RoleDefinitionName,
        [bool]$IsCustomRole,
        [string]$ScopeLevel,
        [string]$ObjectType
    )

    # Roles that are intrinsically high-privilege
    $highPrivilegeRoles = @(
        "Owner",
        "User Access Administrator",
        "Role Based Access Control Administrator"
    )

    # Roles that are elevated but scoped
    $mediumPrivilegeRoles = @(
        "Contributor",
        "Security Admin",
        "Security Center Admin",
        "Key Vault Administrator",
        "Storage Account Contributor",
        "Virtual Machine Contributor",
        "Network Contributor",
        "Managed Identity Operator",
        "Azure Kubernetes Service Cluster Admin Role"
    )

    $isHighRole = $highPrivilegeRoles -contains $RoleDefinitionName
    $isMediumRole = $mediumPrivilegeRoles -contains $RoleDefinitionName

    # Broad scopes amplify risk
    $isBroadScope = $ScopeLevel -in @("ManagementGroup", "Subscription")

    if ($isHighRole -and $isBroadScope) { return "High" }
    if ($isHighRole) { return "High" }
    if ($isMediumRole -and $isBroadScope) { return "High" }
    if ($isMediumRole) { return "Medium" }
    if ($IsCustomRole -and $isBroadScope) { return "Medium" }
    if ($IsCustomRole) { return "Low" }
    if ($isBroadScope -and $ObjectType -eq "ServicePrincipal") { return "Medium" }

    return "Informational"
}


#------------------------------------------------------------------------ [ HTML Report Generator ]

Function Generate-RBACPostureHtmlReport {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [hashtable]$ScanSummary,
        [array]$SubscriptionResults,
        [hashtable]$RiskDistribution,
        [hashtable]$RoleDistribution,
        [hashtable]$PrincipalDistribution,
        [hashtable]$ScopeLevelCount,
        [array]$AllFindings,
        [int]$TotalFindings,
        [bool]$PimAssessed,
        [string]$PimSkipReason,
        [string]$CsvPath,
        [string]$HtmlPath,
        [bool]$GridViewOpened
    )

    $timestamp = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    #---------------------------------------------------------------- Build subscription rows
    $subscriptionRowsJson = ""
    foreach ($sub in $SubscriptionResults) {
        $iconClass = switch ($sub.Status) {
            "Success" { "icon-success" }
            "Warning" { "icon-warn" }
            "Error" { "icon-error" }
            default { "icon-info" }
        }
        $icon = switch ($sub.Status) {
            "Success" { "✓" }
            "Warning" { "⚠" }
            "Error" { "✗" }
            default { "•" }
        }
        $subscriptionRowsJson += @"
        <div class="sub-item">
            <span class="sub-icon $iconClass">$icon</span>
            <span class="sub-name">$([System.Web.HttpUtility]::HtmlEncode($sub.Name))</span>
            <span class="sub-count">$([System.Web.HttpUtility]::HtmlEncode($sub.Count))</span>
        </div>
"@
    }

    #---------------------------------------------------------------- Build risk stat cards
    $highCount = if ($RiskDistribution.ContainsKey("High")) { $RiskDistribution["High"] }          else { 0 }
    $medCount = if ($RiskDistribution.ContainsKey("Medium")) { $RiskDistribution["Medium"] }        else { 0 }
    $lowCount = if ($RiskDistribution.ContainsKey("Low")) { $RiskDistribution["Low"] }           else { 0 }
    $infoCount = if ($RiskDistribution.ContainsKey("Informational")) { $RiskDistribution["Informational"] } else { 0 }

    #---------------------------------------------------------------- Build risk bar chart rows
    $riskBarsHtml = ""
    foreach ($level in @("High", "Medium", "Low", "Informational")) {
        $count = if ($RiskDistribution.ContainsKey($level)) { $RiskDistribution[$level] } else { 0 }
        $pct = if ($TotalFindings -gt 0) { [math]::Round(($count / $TotalFindings) * 100) } else { 0 }
        $barColor = switch ($level) {
            "High" { "var(--red)" }
            "Medium" { "var(--amber)" }
            "Low" { "var(--green)" }
            "Informational" { "var(--accent2)" }
        }
        $riskBarsHtml += @"
        <div class="bar-row">
            <span class="bar-label">$level</span>
            <div class="bar-track">
                <div class="bar-fill" data-pct="$pct" style="background:$barColor;"></div>
            </div>
            <span class="bar-val">$count ($pct%)</span>
        </div>
"@
    }

    #---------------------------------------------------------------- Build scope distribution rows
    $scopeBarsHtml = ""
    foreach ($scope in @("ManagementGroup", "Subscription", "ResourceGroup", "Resource")) {
        $count = if ($ScopeLevelCount.ContainsKey($scope)) { $ScopeLevelCount[$scope] } else { 0 }
        $pct = if ($TotalFindings -gt 0) { [math]::Round(($count / $TotalFindings) * 100) } else { 0 }
        $scopeBarsHtml += @"
        <div class="bar-row">
            <span class="bar-label">$scope</span>
            <div class="bar-track">
                <div class="bar-fill" data-pct="$pct" style="background:var(--accent);"></div>
            </div>
            <span class="bar-val">$count ($pct%)</span>
        </div>
"@
    }

    #---------------------------------------------------------------- Build principal distribution rows
    $principalBarsHtml = ""
    foreach ($item in ($PrincipalDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($TotalFindings -gt 0) { [math]::Round(($item.Value / $TotalFindings) * 100) } else { 0 }
        $principalBarsHtml += @"
        <div class="bar-row">
            <span class="bar-label">$($item.Key)</span>
            <div class="bar-track">
                <div class="bar-fill" data-pct="$pct" style="background:var(--accent3);"></div>
            </div>
            <span class="bar-val">$($item.Value) ($pct%)</span>
        </div>
"@
    }

    #---------------------------------------------------------------- Build top roles rows
    $topRolesHtml = ""
    $counter = 1
    foreach ($role in ($RoleDistribution.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8)) {
        $topRolesHtml += @"
        <div class="top-item">
            <span class="rank-badge">$counter</span>
            <span class="top-name">$([System.Web.HttpUtility]::HtmlEncode($role.Key))</span>
            <span class="top-count">$($role.Value)</span>
        </div>
"@
        $counter++
    }

    #---------------------------------------------------------------- Build findings table rows
    $findingRowsHtml = ""
    $rowIndex = 0

    $riskBadgeClass = @{
        "High"          = "badge-high"
        "Medium"        = "badge-medium"
        "Low"           = "badge-low"
        "Informational" = "badge-info"
    }

    foreach ($finding in $AllFindings) {
        $riskClass = if ($riskBadgeClass.ContainsKey($finding.RiskLevel)) { $riskBadgeClass[$finding.RiskLevel] } else { "badge-info" }
        $customBadge = if ($finding.IsCustomRole -eq "Yes") { '<span class="badge badge-custom">Custom</span>' } else { "" }
        $pimBadge = switch ($finding.PimStatus) {
            "Eligible" { '<span class="badge badge-pim-eligible">PIM-Eligible</span>' }
            "Active" { '<span class="badge badge-pim-active">PIM-Active</span>' }
            default { "" }
        }

        $safeSubName = [System.Web.HttpUtility]::HtmlEncode($finding.SubscriptionName)
        $safeDisplay = [System.Web.HttpUtility]::HtmlEncode($finding.DisplayName)
        $safeRole = [System.Web.HttpUtility]::HtmlEncode($finding.RoleDefinitionName)
        $safeScope = [System.Web.HttpUtility]::HtmlEncode($finding.Scope)
        $safeObjType = [System.Web.HttpUtility]::HtmlEncode($finding.ObjectType)
        $safeAssign = [System.Web.HttpUtility]::HtmlEncode($finding.AssignmentType)

        $findingRowsHtml += @"
        <tr class="finding-row"
            data-risk="$($finding.RiskLevel)"
            data-principal-type="$($finding.ObjectType)"
            data-custom="$($finding.IsCustomRole)"
            data-sub="$safeSubName"
            data-display="$safeDisplay"
            data-role="$safeRole"
            data-scope="$safeScope"
            data-scopelevel="$($finding.ScopeLevel)"
            data-assign="$safeAssign"
            data-pim="$($finding.PimStatus)"
            data-appid="$([System.Web.HttpUtility]::HtmlEncode($finding.ServicePrincipalAppId))"
            data-signin="$([System.Web.HttpUtility]::HtmlEncode($finding.SignInName))"
            data-subid="$([System.Web.HttpUtility]::HtmlEncode($finding.SubscriptionId))"
            data-tenantid="$([System.Web.HttpUtility]::HtmlEncode($finding.TenantId))"
            data-index="$rowIndex">
            <td><span class="risk-badge $riskClass">$($finding.RiskLevel)</span></td>
            <td class="mono-cell">$safeSubName</td>
            <td>$safeDisplay $pimBadge</td>
            <td>$safeObjType</td>
            <td>$safeRole $customBadge</td>
            <td>$($finding.ScopeLevel)</td>
            <td>$safeAssign</td>
        </tr>
"@
        $rowIndex++
    }

    #---------------------------------------------------------------- PIM status banner
    $pimStatusHtml = if ($PimAssessed) {
        '<div class="pim-status pim-ok">✓ PIM assessment completed via Microsoft.Graph</div>'
    }
    else {
        $safeReason = [System.Web.HttpUtility]::HtmlEncode($PimSkipReason)
        "<div class='pim-status pim-warn'>⚠ PIM assessment skipped — $safeReason. PIM columns show &quot;Not Assessed&quot;.</div>"
    }

    #---------------------------------------------------------------- Output files section
    $outputFilesHtml = ""
    if ($CsvPath) {
        $outputFilesHtml += @"
        <div class="output-item"><span class="output-icon">✓</span>
            <div><div class="output-label">CSV Export</div>
            <div class="output-val">$([System.Web.HttpUtility]::HtmlEncode($CsvPath))</div></div>
        </div>
"@
    }
    if ($HtmlPath) {
        $outputFilesHtml += @"
        <div class="output-item"><span class="output-icon">✓</span>
            <div><div class="output-label">HTML Report</div>
            <div class="output-val">$([System.Web.HttpUtility]::HtmlEncode($HtmlPath))</div></div>
        </div>
"@
    }
    if ($GridViewOpened) {
        $outputFilesHtml += @"
        <div class="output-item"><span class="output-icon">✓</span>
            <div><div class="output-label">Grid View</div>
            <div class="output-val">Opened in separate window</div></div>
        </div>
"@
    }

    #---------------------------------------------------------------- Scan parameters info cards
    $pimAssessedLabel = if ($PimAssessed) { "Yes (Microsoft.Graph)" } else { "No (skipped)" }
    $exportEnabledLabel = $ScanParameters.ExportEnabled

    #---------------------------------------------------------------- Build full HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure RBAC Security Posture — Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg:#0d1117; --surface:#161b22; --surface2:#1c2333; --surface3:#243048;
            --border:#30363d; --accent:#388bfd; --accent2:#39c5cf; --accent3:#a371f7;
            --green:#3fb950; --amber:#d29922; --red:#f85149;
            --text:#e6edf3; --muted:#7d8590; --muted2:#adbac7;
            --mono:'JetBrains Mono','Consolas','Courier New',monospace;
            --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
            --radius:10px; --radius-sm:6px; --shadow:0 4px 24px rgba(0,0,0,.5);
        }
        body.light-theme {
            --bg:#f6f8fa; --surface:#fff; --surface2:#f0f3f6; --surface3:#e4e9ef;
            --border:#d0d7de; --accent:#0969da; --accent2:#0284a8; --accent3:#7c3aed;
            --green:#1a7f37; --amber:#b08000; --red:#cf222e;
            --text:#1f2328; --muted:#636c76; --muted2:#424a53;
            --shadow:0 4px 24px rgba(0,0,0,.12);
        }
        *,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
        body { font-family:var(--sans); background:var(--bg); color:var(--text); min-height:100vh; display:flex; }
        a { color:var(--accent); }

        /* ── Sidebar ── */
        #sidebar {
            width:236px; min-height:100vh; background:var(--surface);
            border-right:1px solid var(--border); position:fixed; top:0; left:0;
            display:flex; flex-direction:column; z-index:100;
        }
        .logo-block {
            padding:22px 18px 16px;
            border-bottom:1px solid var(--border);
        }
        .logo-icon {
            width:36px; height:36px; border-radius:8px;
            background:linear-gradient(135deg,var(--accent),var(--accent3));
            display:flex; align-items:center; justify-content:center;
            font-size:18px; margin-bottom:10px;
        }
        .logo-title { font-size:13px; font-weight:700; color:var(--text); line-height:1.3; }
        .logo-sub   { font-size:11px; color:var(--muted); margin-top:2px; }
        .ver-badge  {
            display:inline-block; margin-top:8px; padding:2px 8px;
            background:var(--surface3); border:1px solid var(--border);
            border-radius:20px; font-size:10px; color:var(--muted2);
            font-family:var(--mono);
        }
        .nav-section { padding:12px 0; flex:1; }
        .nav-label   { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; padding:0 18px 6px; }
        .nav-btn {
            width:100%; display:flex; align-items:center; gap:10px;
            padding:9px 18px; background:none; border:none; color:var(--muted2);
            font-size:13px; font-family:var(--sans); cursor:pointer; text-align:left;
            border-left:3px solid transparent; transition:all .15s;
        }
        .nav-btn:hover  { background:var(--surface2); color:var(--text); }
        .nav-btn.active { background:var(--surface2); color:var(--accent); border-left-color:var(--accent); font-weight:600; }
        .nav-btn .nav-icon { font-size:15px; width:20px; text-align:center; }
        .sidebar-footer {
            padding:14px 18px; border-top:1px solid var(--border);
            font-size:11px; color:var(--muted);
        }
        .theme-toggle {
            display:flex; align-items:center; gap:8px; margin-bottom:10px; cursor:pointer;
        }
        .toggle-pill {
            width:36px; height:20px; background:var(--surface3); border-radius:10px;
            position:relative; transition:background .2s; border:1px solid var(--border);
        }
        .toggle-pill::after {
            content:''; width:14px; height:14px; border-radius:50%;
            background:var(--muted2); position:absolute; top:2px; left:2px; transition:all .2s;
        }
        body.light-theme .toggle-pill { background:var(--accent); }
        body.light-theme .toggle-pill::after { left:18px; background:#fff; }
        .toggle-label { font-size:11px; color:var(--muted); }

        /* ── Main ── */
        #main { margin-left:236px; flex:1; padding:28px 32px; min-width:0; }
        .page { display:none; animation:fadeIn .25s ease; }
        .page.active { display:block; }
        @keyframes fadeIn { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:none} }

        .page-header { margin-bottom:24px; }
        .page-title  { font-size:22px; font-weight:700; color:var(--text); }
        .page-sub    { font-size:13px; color:var(--muted); margin-top:4px; }

        /* ── Stat cards ── */
        .stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:24px; }
        .stat-card  {
            background:var(--surface); border:1px solid var(--border);
            border-radius:var(--radius); padding:18px 16px;
            border-top:3px solid var(--accent); transition:box-shadow .2s;
        }
        .stat-card:hover { box-shadow:var(--shadow); }
        .stat-card.c-red    { border-top-color:var(--red); }
        .stat-card.c-amber  { border-top-color:var(--amber); }
        .stat-card.c-green  { border-top-color:var(--green); }
        .stat-card.c-cyan   { border-top-color:var(--accent2); }
        .stat-card.c-purple { border-top-color:var(--accent3); }
        .stat-card.c-blue   { border-top-color:var(--accent); }
        .stat-num   { font-size:30px; font-weight:700; color:var(--text); line-height:1.1; }
        .stat-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.8px; margin-top:6px; }

        /* ── Panels ── */
        .panel {
            background:var(--surface); border:1px solid var(--border);
            border-radius:var(--radius); padding:20px; margin-bottom:20px;
        }
        .panel-title { font-size:14px; font-weight:600; color:var(--text); margin-bottom:16px; }
        .chart-grid  { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px; }
        @media(max-width:900px){ .chart-grid{ grid-template-columns:1fr; } }

        /* ── Bar rows ── */
        .bar-row   { display:flex; align-items:center; gap:10px; margin-bottom:10px; font-size:13px; }
        .bar-label { width:130px; color:var(--muted2); flex-shrink:0; }
        .bar-track { flex:1; height:8px; background:var(--surface3); border-radius:4px; overflow:hidden; }
        .bar-fill  { height:100%; width:0; border-radius:4px; transition:width .6s ease; }
        .bar-val   { width:90px; text-align:right; font-size:12px; color:var(--muted); font-family:var(--mono); }

        /* ── Top-items list ── */
        .top-item   { display:flex; align-items:center; gap:12px; padding:10px 0; border-bottom:1px solid var(--border); }
        .top-item:last-child { border-bottom:none; }
        .rank-badge { width:26px; height:26px; border-radius:50%; background:var(--surface3);
                      border:1px solid var(--border); display:flex; align-items:center;
                      justify-content:center; font-size:11px; font-weight:700; color:var(--accent); flex-shrink:0; }
        .top-name   { flex:1; font-size:13px; color:var(--text); }
        .top-count  { font-family:var(--mono); font-size:13px; color:var(--accent); font-weight:600; }

        /* ── Subscription results ── */
        .sub-list   { max-height:320px; overflow-y:auto; }
        .sub-item   { display:flex; align-items:center; gap:12px; padding:10px 0; border-bottom:1px solid var(--border); font-size:13px; }
        .sub-item:last-child { border-bottom:none; }
        .sub-icon   { width:22px; height:22px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:13px; font-weight:700; flex-shrink:0; }
        .icon-success { background:rgba(63,185,80,.15); color:var(--green); }
        .icon-warn    { background:rgba(210,153,34,.15); color:var(--amber); }
        .icon-error   { background:rgba(248,81,73,.15);  color:var(--red); }
        .sub-name   { flex:1; color:var(--text); }
        .sub-count  { font-family:var(--mono); font-size:12px; color:var(--muted); }

        /* ── Info grid (session / scan params) ── */
        .info-grid  { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:14px; }
        .info-card  { background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:14px 16px; }
        .info-label { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.8px; margin-bottom:6px; }
        .info-value { font-size:14px; color:var(--text); font-weight:600; word-break:break-all; }
        .info-value.none { color:var(--muted); font-style:italic; font-weight:400; }

        /* ── Findings table ── */
        .toolbar    { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
        .search-wrap { position:relative; }
        .search-wrap input {
            background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm);
            padding:7px 12px 7px 32px; color:var(--text); font-size:13px; width:260px;
        }
        .search-wrap input:focus { outline:none; border-color:var(--accent); }
        .search-icon { position:absolute; left:10px; top:50%; transform:translateY(-50%); color:var(--muted); font-size:13px; }
        .filter-sel {
            background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm);
            padding:7px 10px; color:var(--text); font-size:13px; cursor:pointer;
        }
        .filter-sel:focus { outline:none; border-color:var(--accent); }
        .result-count { font-size:12px; color:var(--muted); margin-left:auto; font-family:var(--mono); }

        .table-wrap { overflow-x:auto; }
        table { width:100%; border-collapse:collapse; font-size:13px; }
        th {
            background:var(--surface2); color:var(--muted2); font-size:11px;
            text-transform:uppercase; letter-spacing:.6px; padding:10px 12px;
            text-align:left; border-bottom:1px solid var(--border); cursor:pointer;
            white-space:nowrap; user-select:none;
        }
        th:hover { color:var(--text); }
        th.sort-active { color:var(--accent); }
        .sort-arrow { font-size:9px; margin-left:4px; }
        td { padding:10px 12px; border-bottom:1px solid var(--border); vertical-align:top; }
        tr.finding-row:hover { background:var(--surface2); cursor:pointer; }
        .mono-cell { font-family:var(--mono); font-size:12px; }

        /* ── Risk / status badges ── */
        .risk-badge, .badge {
            display:inline-block; padding:2px 8px; border-radius:20px;
            font-size:11px; font-weight:600; white-space:nowrap;
        }
        .badge-high   { background:rgba(248,81,73,.15);  color:var(--red);    border:1px solid rgba(248,81,73,.3); }
        .badge-medium { background:rgba(210,153,34,.15); color:var(--amber);  border:1px solid rgba(210,153,34,.3); }
        .badge-low    { background:rgba(63,185,80,.15);  color:var(--green);  border:1px solid rgba(63,185,80,.3); }
        .badge-info   { background:rgba(57,197,207,.15); color:var(--accent2);border:1px solid rgba(57,197,207,.3); }
        .badge-custom { background:rgba(163,113,247,.15);color:var(--accent3);border:1px solid rgba(163,113,247,.3); margin-left:4px; }
        .badge-pim-eligible { background:rgba(56,139,253,.15);color:var(--accent); border:1px solid rgba(56,139,253,.3); margin-left:4px; }
        .badge-pim-active   { background:rgba(248,81,73,.12); color:var(--red);   border:1px solid rgba(248,81,73,.3);  margin-left:4px; }

        /* ── Pagination ── */
        .pagination { display:flex; align-items:center; gap:6px; margin-top:14px; flex-wrap:wrap; }
        .pg-btn {
            background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm);
            padding:5px 10px; color:var(--text); font-size:12px; cursor:pointer;
        }
        .pg-btn:hover  { border-color:var(--accent); color:var(--accent); }
        .pg-btn.active { background:var(--accent); color:#fff; border-color:var(--accent); }
        .pg-info { font-size:12px; color:var(--muted); margin-left:auto; font-family:var(--mono); }

        /* ── Detail drawer ── */
        #detailBackdrop {
            display:none; position:fixed; inset:0; background:rgba(0,0,0,.5); z-index:200;
        }
        #detailDrawer {
            position:fixed; top:0; right:0; width:480px; max-width:100vw;
            height:100vh; background:var(--surface); border-left:1px solid var(--border);
            z-index:201; overflow-y:auto; padding:24px;
            transform:translateX(100%); transition:transform .25s ease;
        }
        #detailDrawer.open { transform:none; }
        .drawer-header { display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:20px; }
        .drawer-title  { font-size:16px; font-weight:700; color:var(--text); }
        .drawer-close  { background:none; border:none; color:var(--muted); font-size:20px; cursor:pointer; padding:0 4px; }
        .drawer-nav    { display:flex; gap:8px; margin-bottom:20px; }
        .drawer-nav-btn { background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:5px 12px; color:var(--text); font-size:12px; cursor:pointer; }
        .drawer-nav-btn:hover { border-color:var(--accent); color:var(--accent); }
        .detail-section { margin-bottom:18px; }
        .detail-section-title { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.8px; margin-bottom:8px; border-bottom:1px solid var(--border); padding-bottom:4px; }
        .detail-row { display:flex; gap:8px; margin-bottom:8px; font-size:13px; }
        .detail-key { width:140px; color:var(--muted2); flex-shrink:0; }
        .detail-val { color:var(--text); font-family:var(--mono); font-size:12px; word-break:break-all; }
        .scope-path { background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:10px 12px; font-family:var(--mono); font-size:11px; color:var(--muted2); word-break:break-all; margin-top:6px; }

        /* ── PIM status banner ── */
        .pim-status { padding:10px 14px; border-radius:var(--radius-sm); font-size:12px; margin-bottom:20px; }
        .pim-ok     { background:rgba(63,185,80,.1); border:1px solid rgba(63,185,80,.3); color:var(--green); }
        .pim-warn   { background:rgba(210,153,34,.1);border:1px solid rgba(210,153,34,.3);color:var(--amber); }

        /* ── Output files ── */
        .output-list  { display:flex; flex-direction:column; gap:10px; }
        .output-item  { display:flex; align-items:flex-start; gap:12px; background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:12px 14px; }
        .output-icon  { font-size:18px; color:var(--green); flex-shrink:0; }
        .output-label { font-size:11px; color:var(--muted); margin-bottom:2px; }
        .output-val   { font-family:var(--mono); font-size:12px; color:var(--text); word-break:break-all; }

        /* ── Toast ── */
        #toast {
            position:fixed; bottom:24px; right:24px; background:var(--surface2);
            border:1px solid var(--border); border-radius:var(--radius-sm);
            padding:10px 16px; font-size:13px; color:var(--text);
            opacity:0; transform:translateY(12px); pointer-events:none; z-index:300;
            transition:all .25s;
        }
        #toast.show { opacity:1; transform:none; }

        /* ── Mobile ── */
        #menuToggle { display:none; position:fixed; top:12px; left:12px; z-index:150; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); padding:6px 10px; cursor:pointer; color:var(--text); font-size:16px; }
        @media(max-width:768px) {
            #sidebar { transform:translateX(-100%); transition:transform .25s; }
            #sidebar.open { transform:none; }
            #main { margin-left:0; padding:16px; }
            #menuToggle { display:block; }
            #detailDrawer { width:100vw; }
        }
        @media print { #sidebar{display:none;} #main{margin-left:0;} #detailBackdrop,#detailDrawer,#toast{display:none!important;} }
    </style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<!-- ═══ Sidebar ═══ -->
<nav id="sidebar">
    <div class="logo-block">
        <div class="logo-icon">🔐</div>
        <div class="logo-title">Azure RBAC Security Posture</div>
        <div class="logo-sub">Least-Privilege Assessment</div>
        <span class="ver-badge">v1.0</span>
    </div>
    <div class="nav-section">
        <div class="nav-label">Report Sections</div>
        <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
        <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> Findings</button>
        <button class="nav-btn" onclick="showPage('distributions',this)"><span class="nav-icon">📈</span> Distributions</button>
        <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">🗂️</span> Subscriptions</button>
        <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">ℹ️</span> Session Info</button>
        <button class="nav-btn" onclick="showPage('outputs',this)"><span class="nav-icon">📁</span> Output Files</button>
    </div>
    <div class="sidebar-footer">
        <div class="theme-toggle" onclick="toggleTheme()">
            <div class="toggle-pill"></div>
            <span class="toggle-label">Light theme</span>
        </div>
        <div>Generated $timestamp</div>
    </div>
</nav>

<!-- ═══ Main Content ═══ -->
<main id="main">

    <!-- ── Overview ── -->
    <div id="overview" class="page active">
        <div class="page-header">
            <div class="page-title">RBAC Security Posture — Overview</div>
            <div class="page-sub">Risk-rated findings across $($ScanSummary.SubscriptionsScanned) subscription(s) &nbsp;·&nbsp; Completed in $($ScanSummary.ExecutionTime)</div>
        </div>
        $pimStatusHtml
        <div class="stats-grid">
            <div class="stat-card c-blue">
                <div class="stat-num">$TotalFindings</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card c-red">
                <div class="stat-num">$highCount</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-card c-amber">
                <div class="stat-num">$medCount</div>
                <div class="stat-label">Medium Risk</div>
            </div>
            <div class="stat-card c-green">
                <div class="stat-num">$lowCount</div>
                <div class="stat-label">Low Risk</div>
            </div>
            <div class="stat-card c-cyan">
                <div class="stat-num">$infoCount</div>
                <div class="stat-label">Informational</div>
            </div>
            <div class="stat-card c-purple">
                <div class="stat-num">$($ScanSummary.UniqueRoles)</div>
                <div class="stat-label">Unique Roles</div>
            </div>
            <div class="stat-card c-blue">
                <div class="stat-num">$($ScanSummary.UniquePrincipals)</div>
                <div class="stat-label">Unique Principals</div>
            </div>
            <div class="stat-card c-blue">
                <div class="stat-num">$($ScanSummary.CustomRoleAssignments)</div>
                <div class="stat-label">Custom-Role Assignments</div>
            </div>
        </div>

        <div class="chart-grid">
            <div class="panel">
                <div class="panel-title">Risk Level Distribution</div>
$riskBarsHtml
            </div>
            <div class="panel">
                <div class="panel-title">Top 8 Most-Assigned Roles</div>
$topRolesHtml
            </div>
        </div>
    </div>

    <!-- ── Findings ── -->
    <div id="findings" class="page">
        <div class="page-header">
            <div class="page-title">All Findings</div>
            <div class="page-sub">Click any row to open the detail drawer &nbsp;·&nbsp; Sortable columns &nbsp;·&nbsp; Filter by risk level or principal type</div>
        </div>
        <div class="panel">
            <div class="toolbar">
                <div class="search-wrap">
                    <span class="search-icon">🔎</span>
                    <input type="text" id="findingSearch" placeholder="Search principal, role, subscription…" oninput="applyFilters()">
                </div>
                <select class="filter-sel" id="riskFilter" onchange="applyFilters()">
                    <option value="">All Risk Levels</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Informational">Informational</option>
                </select>
                <select class="filter-sel" id="principalFilter" onchange="applyFilters()">
                    <option value="">All Principal Types</option>
                    <option value="User">User</option>
                    <option value="Group">Group</option>
                    <option value="ServicePrincipal">ServicePrincipal</option>
                </select>
                <select class="filter-sel" id="customFilter" onchange="applyFilters()">
                    <option value="">All Roles</option>
                    <option value="Yes">Custom Roles Only</option>
                    <option value="No">Built-in Roles Only</option>
                </select>
                <span class="result-count" id="resultCount"></span>
            </div>
            <div class="table-wrap">
                <table id="findingsTable">
                    <thead>
                        <tr>
                            <th onclick="sortTable(0)" data-col="0">Risk <span class="sort-arrow" id="sa0"></span></th>
                            <th onclick="sortTable(1)" data-col="1">Subscription <span class="sort-arrow" id="sa1"></span></th>
                            <th onclick="sortTable(2)" data-col="2">Principal <span class="sort-arrow" id="sa2"></span></th>
                            <th onclick="sortTable(3)" data-col="3">Type <span class="sort-arrow" id="sa3"></span></th>
                            <th onclick="sortTable(4)" data-col="4">Role <span class="sort-arrow" id="sa4"></span></th>
                            <th onclick="sortTable(5)" data-col="5">Scope Level <span class="sort-arrow" id="sa5"></span></th>
                            <th onclick="sortTable(6)" data-col="6">Assignment <span class="sort-arrow" id="sa6"></span></th>
                        </tr>
                    </thead>
                    <tbody id="findingsBody">
$findingRowsHtml
                    </tbody>
                </table>
            </div>
            <div class="pagination" id="pagination"></div>
            <div class="pg-info" id="pgInfo"></div>
        </div>
    </div>

    <!-- ── Distributions ── -->
    <div id="distributions" class="page">
        <div class="page-header">
            <div class="page-title">Distributions</div>
            <div class="page-sub">Scope, principal type, and role breakdown across all findings</div>
        </div>
        <div class="chart-grid">
            <div class="panel">
                <div class="panel-title">Scope Level Distribution</div>
$scopeBarsHtml
            </div>
            <div class="panel">
                <div class="panel-title">Principal Type Distribution</div>
$principalBarsHtml
            </div>
        </div>
        <div class="panel">
            <div class="panel-title">Risk Level Distribution</div>
$riskBarsHtml
        </div>
    </div>

    <!-- ── Subscriptions ── -->
    <div id="subscriptions" class="page">
        <div class="page-header">
            <div class="page-title">Subscription Scan Results</div>
            <div class="page-sub">Per-subscription finding counts and scan status</div>
        </div>
        <div class="panel">
            <div class="sub-list">
$subscriptionRowsJson
            </div>
        </div>
    </div>

    <!-- ── Session Info ── -->
    <div id="session" class="page">
        <div class="page-header">
            <div class="page-title">Session &amp; Scan Parameters</div>
            <div class="page-sub">Azure context used during this assessment</div>
        </div>
        <div class="panel" style="margin-bottom:20px;">
            <div class="panel-title">Session Information</div>
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
        <div class="panel">
            <div class="panel-title">Scan Parameters</div>
            <div class="info-grid">
                <div class="info-card">
                    <div class="info-label">Scope</div>
                    <div class="info-value">$($ScanParameters.Scope)</div>
                </div>
                <div class="info-card">
                    <div class="info-label">Export to CSV</div>
                    <div class="info-value">$exportEnabledLabel</div>
                </div>
                <div class="info-card">
                    <div class="info-label">PIM Assessment</div>
                    <div class="info-value">$pimAssessedLabel</div>
                </div>
                <div class="info-card">
                    <div class="info-label">Execution Time</div>
                    <div class="info-value">$($ScanSummary.ExecutionTime)</div>
                </div>
            </div>
        </div>
    </div>

    <!-- ── Output Files ── -->
    <div id="outputs" class="page">
        <div class="page-header">
            <div class="page-title">Output Files</div>
            <div class="page-sub">Files generated during this assessment run</div>
        </div>
        <div class="panel">
            <div class="output-list">
$outputFilesHtml
            </div>
        </div>
    </div>

</main>

<!-- ═══ Detail Drawer ═══ -->
<div id="detailBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
    <div class="drawer-header">
        <div class="drawer-title" id="drawerTitle">Finding Detail</div>
        <button class="drawer-close" onclick="closeDrawer()">✕</button>
    </div>
    <div class="drawer-nav">
        <button class="drawer-nav-btn" onclick="navDrawer(-1)">← Previous</button>
        <button class="drawer-nav-btn" onclick="navDrawer(1)">Next →</button>
        <span id="drawerPos" style="font-size:12px;color:var(--muted);margin-left:auto;align-self:center;"></span>
    </div>
    <div id="drawerContent"></div>
</div>

<div id="toast"></div>

<script>
    /* ── Escape helpers ── */
    function escH(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

    /* ── Theme toggle ── */
    function toggleTheme(){
        document.body.classList.toggle('light-theme');
        localStorage.setItem('theme', document.body.classList.contains('light-theme') ? 'light' : 'dark');
    }
    (function(){ if(localStorage.getItem('theme')==='light') document.body.classList.add('light-theme'); })();

    /* ── Navigation ── */
    function showPage(id, btn){
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        if(btn) btn.classList.add('active');
        animateBars();
    }

    /* ── Animate bar fills ── */
    function animateBars(){
        requestAnimationFrame(function(){
            document.querySelectorAll('.bar-fill').forEach(function(el){
                el.style.width = (el.dataset.pct || 0) + '%';
            });
        });
    }
    window.addEventListener('load', animateBars);

    /* ── Findings table state ── */
    var allRows      = Array.from(document.querySelectorAll('#findingsBody tr.finding-row'));
    var filteredRows = allRows.slice();
    var currentPage  = 1;
    var pageSize     = 25;
    var sortCol      = -1;
    var sortAsc      = true;
    var currentDetailIndex = 0;

    /* ── Filtering ── */
    function applyFilters(){
        var q    = document.getElementById('findingSearch').value.toLowerCase();
        var risk = document.getElementById('riskFilter').value;
        var pri  = document.getElementById('principalFilter').value;
        var cust = document.getElementById('customFilter').value;

        filteredRows = allRows.filter(function(row){
            var matchQ    = !q || row.textContent.toLowerCase().includes(q);
            var matchRisk = !risk || row.dataset.risk === risk;
            var matchPri  = !pri  || row.dataset.principalType === pri;
            var matchCust = !cust || row.dataset.custom === cust;
            return matchQ && matchRisk && matchPri && matchCust;
        });

        currentPage = 1;
        renderPage();
    }

    function renderPage(){
        var start  = (currentPage - 1) * pageSize;
        var end    = start + pageSize;
        var body   = document.getElementById('findingsBody');

        allRows.forEach(function(r){ r.style.display = 'none'; });
        filteredRows.slice(start, end).forEach(function(r){ r.style.display = ''; });

        document.getElementById('resultCount').textContent = filteredRows.length + ' finding(s)';
        renderPagination();
    }

    function renderPagination(){
        var total    = Math.ceil(filteredRows.length / pageSize);
        var pg       = document.getElementById('pagination');
        var pgInfo   = document.getElementById('pgInfo');
        pg.innerHTML = '';

        if(total <= 1){ pgInfo.textContent = ''; return; }

        for(var i = 1; i <= total; i++){
            (function(page){
                var btn = document.createElement('button');
                btn.className = 'pg-btn' + (page === currentPage ? ' active' : '');
                btn.textContent = page;
                btn.onclick = function(){ currentPage = page; renderPage(); };
                pg.appendChild(btn);
            })(i);
        }
        var start = (currentPage-1)*pageSize + 1;
        var end   = Math.min(currentPage*pageSize, filteredRows.length);
        pgInfo.textContent = start + '–' + end + ' of ' + filteredRows.length;
    }

    /* ── Sorting ── */
    function sortTable(col){
        if(sortCol === col){ sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
        document.querySelectorAll('.sort-arrow').forEach(function(a){ a.textContent=''; });
        document.querySelectorAll('th').forEach(function(t){ t.classList.remove('sort-active'); });
        var th = document.querySelectorAll('th')[col];
        th.classList.add('sort-active');
        th.querySelector('.sort-arrow').textContent = sortAsc ? '▲' : '▼';

        filteredRows.sort(function(a,b){
            var aText = a.cells[col] ? a.cells[col].textContent.trim() : '';
            var bText = b.cells[col] ? b.cells[col].textContent.trim() : '';
            var riskOrder = {High:0, Medium:1, Low:2, Informational:3};
            if(col===0){ return sortAsc ? (riskOrder[aText]||9)-(riskOrder[bText]||9) : (riskOrder[bText]||9)-(riskOrder[aText]||9); }
            return sortAsc ? aText.localeCompare(bText) : bText.localeCompare(aText);
        });

        var body = document.getElementById('findingsBody');
        filteredRows.forEach(function(r){ body.appendChild(r); });
        allRows.filter(function(r){ return !filteredRows.includes(r); }).forEach(function(r){ body.appendChild(r); });
        currentPage = 1;
        renderPage();
    }

    /* ── Detail drawer ── */
    allRows.forEach(function(row, idx){
        row.addEventListener('click', function(){ openDrawer(idx); });
    });

    function openDrawer(globalIdx){
        currentDetailIndex = filteredRows.findIndex(function(r){ return r === allRows[globalIdx]; });
        if(currentDetailIndex < 0) currentDetailIndex = 0;
        renderDrawer(currentDetailIndex);
        document.getElementById('detailBackdrop').style.display = 'block';
        document.getElementById('detailDrawer').classList.add('open');
    }

    function closeDrawer(){
        document.getElementById('detailBackdrop').style.display = 'none';
        document.getElementById('detailDrawer').classList.remove('open');
    }

    function navDrawer(dir){
        currentDetailIndex = Math.max(0, Math.min(filteredRows.length-1, currentDetailIndex+dir));
        renderDrawer(currentDetailIndex);
    }

    function renderDrawer(idx){
        var row = filteredRows[idx];
        if(!row) return;
        var d = row.dataset;
        var riskBadgeMap = {High:'badge-high',Medium:'badge-medium',Low:'badge-low',Informational:'badge-info'};
        var riskClass = riskBadgeMap[d.risk] || 'badge-info';

        document.getElementById('drawerTitle').textContent = escH(d.display) || 'Finding Detail';
        document.getElementById('drawerPos').textContent = (idx+1) + ' / ' + filteredRows.length;

        var pimRow = d.pim && d.pim !== '' ? '<div class="detail-row"><span class="detail-key">PIM Status</span><span class="detail-val">' + escH(d.pim) + '</span></div>' : '';
        var appIdRow = d.appid && d.appid !== '' ? '<div class="detail-row"><span class="detail-key">App ID (SP)</span><span class="detail-val">' + escH(d.appid) + '</span></div>' : '';
        var signInRow = d.signin && d.signin !== '' ? '<div class="detail-row"><span class="detail-key">Sign-In Name</span><span class="detail-val">' + escH(d.signin) + '</span></div>' : '';

        document.getElementById('drawerContent').innerHTML =
            '<div class="detail-section">' +
                '<div class="detail-section-title">Risk Assessment</div>' +
                '<div class="detail-row"><span class="detail-key">Risk Level</span><span class="detail-val"><span class="risk-badge ' + riskClass + '">' + escH(d.risk) + '</span></span></div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-section-title">Identity</div>' +
                '<div class="detail-row"><span class="detail-key">Display Name</span><span class="detail-val">' + escH(d.display) + '</span></div>' +
                signInRow +
                '<div class="detail-row"><span class="detail-key">Principal Type</span><span class="detail-val">' + escH(d.principalType) + '</span></div>' +
                '<div class="detail-row"><span class="detail-key">Assignment Type</span><span class="detail-val">' + escH(d.assign) + '</span></div>' +
                pimRow +
                appIdRow +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-section-title">Role</div>' +
                '<div class="detail-row"><span class="detail-key">Role Name</span><span class="detail-val">' + escH(d.role) + '</span></div>' +
                '<div class="detail-row"><span class="detail-key">Custom Role</span><span class="detail-val">' + escH(d.custom) + '</span></div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-section-title">Scope</div>' +
                '<div class="detail-row"><span class="detail-key">Scope Level</span><span class="detail-val">' + escH(d.scopelevel) + '</span></div>' +
                '<div class="detail-row"><span class="detail-key">Subscription</span><span class="detail-val">' + escH(d.sub) + '</span></div>' +
                '<div class="detail-row"><span class="detail-key">Subscription ID</span><span class="detail-val">' + escH(d.subid) + '</span></div>' +
                '<div class="detail-row"><span class="detail-key">Tenant ID</span><span class="detail-val">' + escH(d.tenantid) + '</span></div>' +
                '<div class="scope-path">' + escH(d.scope) + '</div>' +
            '</div>';
    }

    /* ── Keyboard shortcuts ── */
    document.addEventListener('keydown', function(e){
        if(e.key === 'Escape') closeDrawer();
        if(e.key === 'ArrowLeft'  && document.getElementById('detailDrawer').classList.contains('open')) navDrawer(-1);
        if(e.key === 'ArrowRight' && document.getElementById('detailDrawer').classList.contains('open')) navDrawer(1);
        if(e.key === '/' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)){
            e.preventDefault();
            var si = document.getElementById('findingSearch');
            if(si){ showPage('findings', document.querySelector('.nav-btn:nth-child(2)')); si.focus(); }
        }
    });

    /* ── Toast ── */
    function showToast(msg){
        var t = document.getElementById('toast');
        t.textContent = msg;
        t.classList.add('show');
        setTimeout(function(){ t.classList.remove('show'); }, 3000);
    }

    /* ── Init ── */
    applyFilters();
</script>
</body>
</html>
"@

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureRBACSecurityPosture {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureRBACSecurityPosture-Report.csv"
    )

    # Start timing
    $startTime = Get-Date

    # Display banner
    Write-Banner

    #---------------------------------------------------------------- Module checks
    # Az.Accounts
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Host "  ⚠ Az.Accounts module not found" -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "  Install Az.Accounts now? (Y/N)"

        if ($install -in @('Y', 'y')) {
            try {
                Write-Host ""
                Write-Host "  Installing Az.Accounts, please wait..." -ForegroundColor Cyan
                Install-Module -Name Az.Accounts -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az.Accounts -ErrorAction Stop
                Write-Host "  ✓ Az.Accounts installed" -ForegroundColor Green
            }
            catch {
                Write-Host "  ✗ Error installing Az.Accounts: $_" -ForegroundColor Red
                return
            }
        }
        else {
            Write-Host "  Installation declined. Cannot proceed." -ForegroundColor Yellow
            return
        }
    }

    # Az.Resources
    if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
        try {
            Write-Host "  Installing Az.Resources, please wait..." -ForegroundColor Cyan
            Install-Module -Name Az.Resources -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
            Import-Module Az.Resources -ErrorAction Stop
            Write-Host "  ✓ Az.Resources installed" -ForegroundColor Green
        }
        catch {
            Write-Host "  ✗ Error installing Az.Resources: $_" -ForegroundColor Red
            return
        }
    }

    # Microsoft.Graph — optional (PIM)
    $pimAvailable = $false
    $pimSkipReason = ""

    try {
        $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph.Identity.Governance -ErrorAction SilentlyContinue
        if ($graphModule) {
            Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop
            $pimAvailable = $true
        }
        else {
            $pimSkipReason = "Microsoft.Graph.Identity.Governance module not found"
        }
    }
    catch {
        $pimSkipReason = "Failed to import Microsoft.Graph.Identity.Governance: $($_.Exception.Message)"
    }

    if (-not $pimAvailable) {
        Write-Host ""
        Write-Host "  ⚠ PIM assessment will be skipped: $pimSkipReason" -ForegroundColor Yellow
    }

    #---------------------------------------------------------------- Azure session
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue

    if (-not $currentContext) {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    #---------------------------------------------------------------- Subscriptions
    if ($AllSubscriptions -or -not $SubscriptionIds) {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText = "All Subscriptions"
    }
    else {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
            Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count))"
    }

    $subscriptionCount = $subscriptions.Count

    #---------------------------------------------------------------- Session / parameters for report
    $sessionInfo = @{
        Tenant      = $currentContext.Tenant.Id
        Account     = $currentContext.Account.Id
        Environment = $currentContext.Environment.Name
    }

    $scanParameters = @{
        Scope         = "$scopeText ($subscriptionCount found)"
        ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
    }

    #---------------------------------------------------------------- Display pre-scan info
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $currentContext.Tenant.Id
        "Account"     = $currentContext.Account.Id
        "Environment" = $currentContext.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"          = "$scopeText ($subscriptionCount found)"
        "Export to CSV"  = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"    = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
        "PIM Assessment" = if ($pimAvailable) { "Enabled (Microsoft.Graph)" } else { "Skipped — $pimSkipReason" }
    }

    #---------------------------------------------------------------- Enumerate custom role definitions (tenant-wide)
    Write-Host ""
    Write-Host "  Enumerating custom role definitions..." -ForegroundColor Cyan

    $customRoleDefinitions = @{}

    try {
        $customDefs = Get-AzRoleDefinition -Custom -ErrorAction Stop
        foreach ($def in $customDefs) {
            $customRoleDefinitions[$def.Name] = $def
        }
        Write-Host "  ✓ Found $($customRoleDefinitions.Count) custom role definition(s)" -ForegroundColor Green
    }
    catch {
        Write-Host "  ⚠ Could not enumerate custom role definitions: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    #---------------------------------------------------------------- PIM scope data (best-effort)
    $pimEligibleIds = @{}

    if ($pimAvailable) {
        Write-Host "  Querying PIM eligible assignments..." -ForegroundColor Cyan

        try {
            Connect-MgGraph -Scopes "PrivilegedAccess.Read.AzureResources" -NoWelcome -ErrorAction Stop

            $pimSchedules = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule `
                -All -ErrorAction Stop

            foreach ($schedule in $pimSchedules) {
                if ($schedule.PrincipalId) {
                    $pimEligibleIds[$schedule.PrincipalId] = "Eligible"
                }
            }
            Write-Host "  ✓ PIM: $($pimEligibleIds.Count) eligible principal(s) found" -ForegroundColor Green
        }
        catch {
            $pimSkipReason = "Graph query failed: $($_.Exception.Message)"
            $pimAvailable = $false
            Write-Host "  ⚠ PIM query failed — $pimSkipReason. Continuing without PIM data." -ForegroundColor Yellow
        }
    }

    #---------------------------------------------------------------- Initialise statistics
    $allFindings = @()
    $subscriptionResults = @()

    $statistics = @{
        SuccessCount          = 0
        ErrorCount            = 0
        RoleDistribution      = @{}
        UniquePrincipals      = @()
        RiskDistribution      = @{
            High          = 0
            Medium        = 0
            Low           = 0
            Informational = 0
        }
        PrincipalDistribution = @{}
        ScopeLevelCount       = @{
            ManagementGroup = 0
            Subscription    = 0
            ResourceGroup   = 0
            Resource        = 0
        }
        CustomRoleAssignments = 0
    }

    #---------------------------------------------------------------- Scan subscriptions
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subscriptionCount -CurrentItem "Starting..."

    $maxNameLength = ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
    $maxNameLength = [math]::Max($maxNameLength, 35)
    $subscriptionIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subscriptionIndex -Total $subscriptionCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id `
                -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue | Out-Null

            $roleAssignments = Get-AzRoleAssignment -ErrorAction Stop
            $findingCount = 0

            foreach ($assignment in $roleAssignments) {
                #------------------------------------------------ Scope level classification
                $scope = if ($assignment.Scope) { $assignment.Scope } else { "" }
                $scopeLevel = ""

                if ($scope -like "/providers/Microsoft.Management/managementGroups/*") {
                    $scopeLevel = "ManagementGroup"
                }
                elseif ($scope -match "^/subscriptions/[^/]+$") {
                    $scopeLevel = "Subscription"
                }
                elseif ($scope -match "^/subscriptions/[^/]+/resourceGroups/[^/]+$") {
                    $scopeLevel = "ResourceGroup"
                }
                elseif ($scope -match "/providers/") {
                    $scopeLevel = "Resource"
                }
                else {
                    $scopeLevel = "Unknown"
                }

                #------------------------------------------------ Custom role flag
                $isCustomRole = $assignment.RoleDefinitionName -and
                $customRoleDefinitions.ContainsKey($assignment.RoleDefinitionName)
                $isCustomDisplay = if ($isCustomRole) { "Yes" } else { "No" }

                #------------------------------------------------ Assignment type
                $principalType = if ($assignment.ObjectType) { $assignment.ObjectType } else { "Unknown" }

                $assignmentType = switch ($principalType) {
                    "Group" { "GroupBased" }
                    "ServicePrincipal" { "ServicePrincipal" }
                    default { "Direct" }
                }

                #------------------------------------------------ PIM status
                $pimStatus = "Not Assessed"

                if ($pimAvailable) {
                    $objId = $assignment.ObjectId
                    if ($objId -and $pimEligibleIds.ContainsKey($objId)) {
                        $pimStatus = $pimEligibleIds[$objId]
                    }
                    else {
                        $pimStatus = "Permanent"
                    }
                }

                #------------------------------------------------ Service principal AppId
                $spAppId = ""
                if ($principalType -eq "ServicePrincipal" -and $assignment.ObjectId) {
                    try {
                        $sp = Get-AzADServicePrincipal -ObjectId $assignment.ObjectId -ErrorAction SilentlyContinue
                        $spAppId = if ($sp) { $sp.AppId } else { "" }
                    }
                    catch { $spAppId = "" }
                }

                #------------------------------------------------ Risk rating
                $riskLevel = Get-RBACRiskRating `
                    -RoleDefinitionName $assignment.RoleDefinitionName `
                    -IsCustomRole $isCustomRole `
                    -ScopeLevel $scopeLevel `
                    -ObjectType $principalType

                #------------------------------------------------ Statistics
                if ($assignment.RoleDefinitionName) {
                    if ($statistics.RoleDistribution.ContainsKey($assignment.RoleDefinitionName)) {
                        $statistics.RoleDistribution[$assignment.RoleDefinitionName]++
                    }
                    else {
                        $statistics.RoleDistribution[$assignment.RoleDefinitionName] = 1
                    }
                }

                if ($assignment.ObjectId -and $assignment.ObjectId -notin $statistics.UniquePrincipals) {
                    $statistics.UniquePrincipals += $assignment.ObjectId
                }

                if ($statistics.RiskDistribution.ContainsKey($riskLevel)) {
                    $statistics.RiskDistribution[$riskLevel]++
                }

                if ($statistics.PrincipalDistribution.ContainsKey($principalType)) {
                    $statistics.PrincipalDistribution[$principalType]++
                }
                else {
                    $statistics.PrincipalDistribution[$principalType] = 1
                }

                switch ($scopeLevel) {
                    "ManagementGroup" { $statistics.ScopeLevelCount.ManagementGroup++ }
                    "Subscription" { $statistics.ScopeLevelCount.Subscription++ }
                    "ResourceGroup" { $statistics.ScopeLevelCount.ResourceGroup++ }
                    "Resource" { $statistics.ScopeLevelCount.Resource++ }
                }

                if ($isCustomRole) { $statistics.CustomRoleAssignments++ }

                #------------------------------------------------ Collect finding
                $allFindings += [pscustomobject]@{
                    SubscriptionName      = $sub.Name
                    SubscriptionId        = $sub.Id
                    TenantId              = $sub.TenantId
                    DisplayName           = $assignment.DisplayName
                    SignInName            = $assignment.SignInName
                    ObjectType            = $principalType
                    RoleDefinitionName    = $assignment.RoleDefinitionName
                    IsCustomRole          = $isCustomDisplay
                    Scope                 = $scope
                    ScopeLevel            = $scopeLevel
                    AssignmentType        = $assignmentType
                    PimStatus             = $pimStatus
                    ServicePrincipalAppId = $spAppId
                    RiskLevel             = $riskLevel
                }

                $findingCount++
            }

            # Clear progress line and show result
            Write-Host "`r" -NoNewline
            Write-Host (" " * 120) -NoNewline
            Write-Host "`r" -NoNewline

            $paddedName = $sub.Name.PadRight($maxNameLength)

            Write-Host "  " -NoNewline
            if ($findingCount -gt 0) {
                Write-Host "✓ " -NoNewline -ForegroundColor Green
                Write-Host $paddedName -NoNewline -ForegroundColor Green
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "$findingCount findings" -ForegroundColor White
            }
            else {
                Write-Host "⚠ " -NoNewline -ForegroundColor Yellow
                Write-Host $paddedName -NoNewline -ForegroundColor Yellow
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "No assignments" -ForegroundColor DarkGray
            }

            $statistics.SuccessCount++
            $subscriptionResults += @{
                Name   = $sub.Name
                Count  = if ($findingCount -gt 0) { "$findingCount findings" } else { "No assignments" }
                Status = if ($findingCount -gt 0) { "Success" } else { "Warning" }
            }
        }
        catch {
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
            $subscriptionResults += @{
                Name   = $sub.Name
                Count  = "Failed: $($_.Exception.Message)"
                Status = "Error"
            }
        }

        $subscriptionIndex++
    }

    #---------------------------------------------------------------- Duration
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration

    $totalFindings = $allFindings.Count

    $scanSummary = @{
        TotalFindings         = $totalFindings
        SubscriptionsScanned  = $subscriptionCount
        UniquePrincipals      = $statistics.UniquePrincipals.Count
        UniqueRoles           = $statistics.RoleDistribution.Count
        CustomRoleAssignments = $statistics.CustomRoleAssignments
        ExecutionTime         = $durationFormatted
    }

    #---------------------------------------------------------------- Console summary
    Write-Summary -Data @{
        "Total Subscriptions Scanned" = $subscriptionCount
        "Successful"                  = $statistics.SuccessCount
        "Errors"                      = $statistics.ErrorCount
        "Total Findings"              = $totalFindings
        "High Risk"                   = $statistics.RiskDistribution.High
        "Medium Risk"                 = $statistics.RiskDistribution.Medium
        "Low Risk"                    = $statistics.RiskDistribution.Low
        "Informational"               = $statistics.RiskDistribution.Informational
        "Unique Principals"           = $statistics.UniquePrincipals.Count
        "Unique Roles"                = $statistics.RoleDistribution.Count
        "Custom Role Assignments"     = $statistics.CustomRoleAssignments
        "Execution Time"              = $durationFormatted
    }

    Write-TopPrivilegedRoles -Roles $statistics.RoleDistribution
    Write-RiskDistribution   -RiskData $statistics.RiskDistribution -TotalFindings $totalFindings
    Write-PrincipalDistribution -PrincipalData $statistics.PrincipalDistribution -TotalFindings $totalFindings

    #---------------------------------------------------------------- Output
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($totalFindings -gt 0) {
        # CSV export (optional)
        if ($ExportToCsv) {
            try {
                # Validate path does not contain traversal characters
                $safePath = $CsvPath -replace '\.\.', ''
                $allFindings | Export-Csv -Path $safePath -NoTypeInformation -Force
                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML report (always)
        try {
            $htmlPath = $CsvPath -replace '\.csv$', '.html'
            if (-not $htmlPath.EndsWith('.html')) {
                $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
            }

            $htmlContent = Generate-RBACPostureHtmlReport `
                -SessionInfo          $sessionInfo `
                -ScanParameters       $scanParameters `
                -ScanSummary          $scanSummary `
                -SubscriptionResults  $subscriptionResults `
                -RiskDistribution     $statistics.RiskDistribution `
                -RoleDistribution     $statistics.RoleDistribution `
                -PrincipalDistribution $statistics.PrincipalDistribution `
                -ScopeLevelCount      $statistics.ScopeLevelCount `
                -AllFindings          $allFindings `
                -TotalFindings        $totalFindings `
                -PimAssessed          $pimAvailable `
                -PimSkipReason        $pimSkipReason `
                -CsvPath              $(if ($csvExported) { $CsvPath } else { $null }) `
                -HtmlPath             $htmlPath `
                -GridViewOpened       $false

            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML report generation failed: $_" -ForegroundColor Red
        }

        # Grid View
        try {
            $allFindings | Out-GridView -Title "Azure RBAC Security Posture — Findings"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View" -ForegroundColor Yellow
        }
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        Write-OutputFiles `
            -CsvPath        $(if ($csvExported) { $CsvPath }  else { $null }) `
            -HtmlPath       $(if ($htmlExported) { $htmlPath } else { $null }) `
            -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
