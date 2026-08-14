<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 14 August 2025
Modified-On     : 14 August 2025

.SYNOPSIS
    Inventories Azure Managed Identities (User-Assigned and System-Assigned) across
    one or more subscriptions and evaluates their RBAC permissions, assignment scope,
    and privilege level to surface over-privileged workload identities.

.DESCRIPTION
    The Get-AzureManagedIdentitySecurityAssessment function discovers every managed
    identity visible to the authenticated account — both User-Assigned identities
    (standalone resources) and System-Assigned identities (attached to compute, App
    Service, Function App, Logic App, etc.) — and evaluates each against a four-tier
    privilege classification aligned to the principle of least privilege.

    Privilege levels are assigned as follows:

        Critical  — Holds Owner, User Access Administrator, or Role Based Access
                    Control Administrator at Subscription scope or above
        High      — Holds Contributor, or any role whose definition includes
                    "*/write" or "*/delete" actions, at Resource Group scope or above
        Medium    — Holds service-specific privileged roles such as Key Vault
                    Administrator, Storage Blob Data Owner, SQL DB Contributor, or
                    similar data-plane admin roles
        Low       — Holds Reader-only or narrowly scoped, limited roles

    The function supports:
        - Scanning all subscriptions in the tenant, or a specified list of IDs
        - Discovery of both User-Assigned and System-Assigned managed identities
        - Per-identity RBAC assignment enumeration using the identity's Principal ID
        - Scope-level classification of each RBAC assignment (Management Group /
          Subscription / Resource Group / Resource)
        - Privilege level derivation based on role name, scope, and action patterns
        - Real-time progress tracking with a live progress bar and color-coded
          console status per subscription
        - Optional CSV export of all identity findings
        - Always-on self-contained HTML report with Azure dark-theme design,
          summarizing session info, scan parameters, statistics, privilege distribution,
          top over-privileged identities, and subscription results
        - Interactive Grid View display of results (where a GUI is available)

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account/context.
    This is also the default behavior if -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan, instead of all
    subscriptions. Ignored if -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all identity findings to the path given in -CsvPath.
    An HTML report is generated regardless of whether this switch is used.

.PARAMETER CsvPath
    Path where the CSV export will be written if -ExportToCsv is specified. Also
    used to derive the HTML report file name (same path, .html extension).
    Default: C:\Temp\AzureManagedIdentitySecurityAssessment-Report.csv

.INPUTS
    None. All input is supplied via parameters.

.OUTPUTS
    None directly to the pipeline. Always writes a self-contained HTML report
    alongside -CsvPath (or the default path). Optionally writes a CSV file if
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureManagedIdentitySecurityAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureManagedIdentitySecurityAssessment -SubscriptionIds @("sub-id-1", "sub-id-2")

.EXAMPLE
    Get-AzureManagedIdentitySecurityAssessment -AllSubscriptions -ExportToCsv

.EXAMPLE
    Get-AzureManagedIdentitySecurityAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Audits\MI-Report.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (14-Aug-2025)   - Initial release. Discovers User-Assigned and
                              System-Assigned managed identities across all or
                              selected subscriptions. Evaluates RBAC assignments per
                              identity against a four-tier privilege classification
                              (Critical / High / Medium / Low). Produces per-identity
                              finding rows with scope, role, and privilege metadata.
                              CSV + self-contained HTML report output.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az.Accounts module  — required for context and subscription resolution
        2. Az.Resources module — required for Get-AzResource (System-Assigned identity
           discovery via resource tags/identity property)
        3. Az.ManagedServiceIdentity module — required for Get-AzUserAssignedIdentity
        4. Az.Authorization module (part of Az) — required for Get-AzRoleAssignment
        5. Authenticated Azure account with at minimum:
               Microsoft.ManagedIdentity/userAssignedIdentities/read
               Microsoft.Authorization/roleAssignments/read
               */read on compute, App Service, and Function App resource types
           at the subscription level for each subscription scanned

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - System-Assigned identity discovery iterates over all resources and filters
          by the Identity.Type property. This can be slow on subscriptions with large
          resource counts; progress is reported per subscription, not per resource.
        - Custom role privilege classification uses action-pattern matching
          ("*/write", "*/delete"). Roles with unusual or highly granular action strings
          may be classified as Low rather than High; review custom roles manually.
        - RBAC assignment enumeration is performed per Principal ID. In subscriptions
          with very high role assignment volumes, this may incur throttling; errors
          are caught per identity and the scan continues gracefully.
        - Interactive Grid View requires a GUI-capable PowerShell session. Skipped
          gracefully in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. On macOS/Linux
          PowerShell 7, supply an explicit -CsvPath.
        - If neither -AllSubscriptions nor -SubscriptionIds is supplied, the function
          defaults to scanning ALL subscriptions with no confirmation prompt.

.LINK
    https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
    https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/managed-identity-best-practice-recommendations
    https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-managed-identities-security-baseline

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-MiCenteredText {
    param(
        [string]$Text,
        [int]$Width = 80,
        [string]$Color = "White"
    )
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-MiBanner {
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-MiCenteredText "Azure Managed Identity Security Assessment v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-MiSection {
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

Function Write-MiScanProgress {
    Write-Host ""
    Write-Host "  Scanning Subscriptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
}

Function Write-MiProgressBar {
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
        else {
            $CurrentItem
        }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-MiSummary {
    param([hashtable]$Data)

    Write-Host ""
    Write-Host "  Scan Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys) {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(36) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-MiPrivilegeDistribution {
    param(
        [hashtable]$PrivilegeData,
        [int]$TotalIdentities
    )

    if ($TotalIdentities -eq 0) { return }

    Write-Host ""
    Write-Host "  Privilege Level Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $order = @("Critical", "High", "Medium", "Low", "None")
    $colors = @{ Critical = "Red"; High = "DarkYellow"; Medium = "Yellow"; Low = "Green"; None = "DarkGray" }

    foreach ($level in $order) {
        $count = if ($PrivilegeData.ContainsKey($level)) { $PrivilegeData[$level] } else { 0 }
        $percent = [math]::Round(($count / $TotalIdentities) * 100)
        $color = $colors[$level]

        Write-Host "  " -NoNewline
        Write-Host $level.PadRight(12) -NoNewline -ForegroundColor $color
        Write-Host ": $count identities ($percent%)" -ForegroundColor White
    }
}

Function Write-MiIdentityTypeDistribution {
    param(
        [hashtable]$TypeData,
        [int]$TotalIdentities
    )

    if ($TotalIdentities -eq 0) { return }

    Write-Host ""
    Write-Host "  Identity Type Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($item in ($TypeData.GetEnumerator() | Sort-Object Value -Descending)) {
        $percent = [math]::Round(($item.Value / $TotalIdentities) * 100)
        Write-Host "  $($item.Key)".PadRight(35) -NoNewline
        Write-Host ": $($item.Value) ($percent%)" -ForegroundColor White
    }
}

Function Write-MiTopOverPrivileged {
    param([array]$Identities)

    if ($Identities.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Top 5 Most Over-Privileged Identities" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $privilegeOrder = @{ Critical = 4; High = 3; Medium = 2; Low = 1; None = 0 }

    $counter = 1
    foreach ($id in ($Identities | Sort-Object `
            @{ Expression = { $privilegeOrder[$_.PrivilegeLevel] }; Descending = $true },
            @{ Expression = { $_.AssignmentCount }; Descending = $true } |
            Select-Object -First 5)) {
        Write-Host "  " -NoNewline
        Write-Host "$counter. " -NoNewline -ForegroundColor Gray
        Write-Host $id.IdentityName.PadRight(36) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($id.PrivilegeLevel) — $($id.AssignmentCount) assignment(s)" -ForegroundColor Cyan
        $counter++
    }
}

Function Write-MiTopRoles {
    param([hashtable]$Roles)

    if ($Roles.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Top 5 Roles Held by Managed Identities" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $counter = 1
    foreach ($role in ($Roles.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
        Write-Host "  " -NoNewline
        Write-Host "$counter. " -NoNewline -ForegroundColor Gray
        Write-Host $role.Key.PadRight(46) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($role.Value) identity/identities" -ForegroundColor Cyan
        $counter++
    }
}

Function Write-MiOutputFiles {
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


#------------------------------------------------------------------------ [ Privilege Classification Engine ]

# Known Critical roles — any of these at Subscription scope or above = Critical
$Script:MiCriticalRoles = @(
    "Owner",
    "User Access Administrator",
    "Role Based Access Control Administrator"
)

# Known High privilege roles — these at RG scope or above = High
$Script:MiHighRoles = @(
    "Contributor",
    "Azure Kubernetes Service Cluster Admin Role",
    "Azure Kubernetes Service RBAC Cluster Admin",
    "Virtual Machine Contributor",
    "Network Contributor",
    "Storage Account Contributor",
    "SQL Server Contributor",
    "SQL Managed Instance Contributor",
    "Azure Arc Enabled Kubernetes Cluster User Role"
)

# Known Medium privilege service roles
$Script:MiMediumRoles = @(
    "Key Vault Administrator",
    "Key Vault Secrets Officer",
    "Key Vault Certificates Officer",
    "Storage Blob Data Owner",
    "Storage Blob Data Contributor",
    "Storage Queue Data Contributor",
    "Storage Table Data Contributor",
    "SQL DB Contributor",
    "Cosmos DB Account Reader Role",
    "DocumentDB Account Contributor",
    "Service Bus Data Owner",
    "Event Hubs Data Owner",
    "Azure Event Hubs Data Sender",
    "SignalR/Web PubSub Contributor",
    "App Configuration Data Owner",
    "Azure Spring Apps Data Reader",
    "Managed Application Contributor Role",
    "Logic App Contributor",
    "Azure Digital Twins Data Owner",
    "Cognitive Services Contributor",
    "Search Service Contributor",
    "Azure AI Developer"
)

Function Get-MiScopeLevel {
    param([string]$Scope)

    if ([string]::IsNullOrWhiteSpace($Scope)) { return "Unknown" }

    if ($Scope -like "/providers/Microsoft.Management/managementGroups/*") {
        return "ManagementGroup"
    }
    elseif ($Scope -match "^/subscriptions/[^/]+$") {
        return "Subscription"
    }
    elseif ($Scope -match "^/subscriptions/[^/]+/resourceGroups/[^/]+$") {
        return "ResourceGroup"
    }
    else {
        return "Resource"
    }
}

Function Get-MiPrivilegeLevel {
    param(
        [array]$Assignments,
        [string]$SubscriptionId
    )

    if ($Assignments.Count -eq 0) { return "None" }

    $highestLevel = "Low"

    foreach ($assignment in $Assignments) {
        $roleName = $assignment.RoleDefinitionName
        $scope = $assignment.Scope
        $scopeLevel = Get-MiScopeLevel -Scope $scope

        # ── Critical check ────────────────────────────────────────────────────────
        $isCriticalScope = $scopeLevel -in @("ManagementGroup", "Subscription")
        if ($isCriticalScope -and ($Script:MiCriticalRoles -contains $roleName)) {
            return "Critical"
        }

        # Owner at any scope is still Critical
        if ($roleName -eq "Owner") {
            return "Critical"
        }

        # ── High check ────────────────────────────────────────────────────────────
        $isHighScope = $scopeLevel -in @("ManagementGroup", "Subscription", "ResourceGroup")
        if ($isHighScope -and ($Script:MiHighRoles -contains $roleName)) {
            if ($highestLevel -ne "Critical") { $highestLevel = "High" }
        }

        # Custom role action check — if the role definition includes */write or */delete
        # at a broad scope, classify as High
        if ($isHighScope) {
            try {
                $roleDef = Get-AzRoleDefinition -Name $roleName -ErrorAction SilentlyContinue
                if ($roleDef) {
                    $hasWriteOrDelete = $roleDef.Actions | Where-Object {
                        $_ -like "*/write" -or $_ -like "*/delete" -or
                        $_ -eq "*"
                    }
                    if ($hasWriteOrDelete) {
                        if ($highestLevel -notin @("Critical", "High")) { $highestLevel = "High" }
                    }
                }
            }
            catch { <# Role definition lookup failed — do not escalate #> }
        }

        # ── Medium check ─────────────────────────────────────────────────────────
        if ($Script:MiMediumRoles -contains $roleName) {
            if ($highestLevel -eq "Low") { $highestLevel = "Medium" }
        }
    }

    return $highestLevel
}


#------------------------------------------------------------------------ [ HTML Report Generator ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-MiHtmlReport {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [hashtable]$ScanSummary,
        [array]$SubscriptionResults,
        [array]$AllFindings,
        [hashtable]$PrivilegeDistribution,
        [hashtable]$IdentityTypeDistribution,
        [hashtable]$RoleDistribution,
        [int]$TotalIdentities,
        [string]$CsvPath,
        [string]$HtmlPath,
        [bool]$GridViewOpened
    )

    $generatedOn = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    $privOrder = @("Critical", "High", "Medium", "Low", "None")
    $privBadgeCls = @{ Critical = "badge-red"; High = "badge-amber"; Medium = "badge-purple"; Low = "badge-green"; None = "" }
    $privBarColor = @{ Critical = "var(--red)"; High = "var(--amber)"; Medium = "var(--accent3)"; Low = "var(--green)"; None = "var(--muted)" }
    $privilegeOrder = @{ Critical = 4; High = 3; Medium = 2; Low = 1; None = 0 }

    function Get-PrivBadge {
        param([string]$Level)
        $cls = $privBadgeCls[$Level]
        if ($cls) { return "<span class=`"badge $cls`">$(EscHtml $Level)</span>" }
        return "<span class=`"badge`" style=`"background:var(--surface3);color:var(--muted)`">$(EscHtml $Level)</span>"
    }

    $criticalCount = if ($PrivilegeDistribution.ContainsKey('Critical')) { $PrivilegeDistribution['Critical'] } else { 0 }
    $highCount = if ($PrivilegeDistribution.ContainsKey('High')) { $PrivilegeDistribution['High'] } else { 0 }

    # ── Privilege distribution bar rows (reused on Overview + Privilege & Roles tabs)
    $privRows = ""
    foreach ($level in $privOrder) {
        $count = if ($PrivilegeDistribution.ContainsKey($level)) { $PrivilegeDistribution[$level] } else { 0 }
        $pct = if ($TotalIdentities -gt 0) { [math]::Round(($count / $TotalIdentities) * 100) } else { 0 }
        $privRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $level)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$($privBarColor[$level])"></div></div>
            <span class="bar-pct">$count ($pct%)</span>
          </div>
"@
    }

    # ── Identity type distribution bar rows ─────────────────────────────────────────
    $typeRows = ""
    foreach ($item in ($IdentityTypeDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($TotalIdentities -gt 0) { [math]::Round(($item.Value / $TotalIdentities) * 100) } else { 0 }
        $typeRows += @"
          <div class="bar-row">
            <span class="bar-label" title="$(EscHtml $item.Key)">$(EscHtml $item.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($item.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Role distribution bar rows (top 5 for Overview, full for Privilege & Roles) ─
    $roleTotal = ($RoleDistribution.Values | Measure-Object -Sum).Sum
    $roleRowsFull = ""
    $roleRowsTop = ""
    $roleCounter = 0
    foreach ($role in ($RoleDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($roleTotal -gt 0) { [math]::Round(($role.Value / $roleTotal) * 100) } else { 0 }
        $row = @"
          <div class="bar-row">
            <span class="bar-label" title="$(EscHtml $role.Key)">$(EscHtml $role.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($role.Value) ($pct%)</span>
          </div>
"@
        $roleRowsFull += $row
        if ($roleCounter -lt 5) { $roleRowsTop += $row }
        $roleCounter++
    }

    # ── Top 5 over-privileged identities (reuses sub-row markup) ───────────────────
    $topOverPrivHtml = ""
    foreach ($id in ($AllFindings |
            Sort-Object `
            @{ Expression = { $privilegeOrder[$_.PrivilegeLevel] }; Descending = $true },
            @{ Expression = { $_.AssignmentCount }; Descending = $true } |
            Select-Object -First 5)) {
        $cls = switch ($id.PrivilegeLevel) { "Critical" { "c-red" }; "High" { "c-amber" }; "Medium" { "c-purple" }; "Low" { "c-green" }; default { "" } }
        $icon = switch ($id.PrivilegeLevel) { "Critical" { "🔴" }; "High" { "🟠" }; "Medium" { "🟣" }; "Low" { "🟢" }; default { "•" } }
        $topOverPrivHtml += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $id.IdentityName)</span>
            <span class="sub-detail">$(EscHtml $id.PrivilegeLevel) — $($id.AssignmentCount) role(s) · $(EscHtml $id.SubscriptionName)</span>
          </div>
"@
    }

    # ── Top 5 roles (reuses sub-row markup) ─────────────────────────────────────────
    $topRolesHtml = ""
    foreach ($role in ($RoleDistribution.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
        $topRolesHtml += @"
          <div class="sub-row">
            <span class="sub-icon">🎭</span>
            <span class="sub-name">$(EscHtml $role.Key)</span>
            <span class="sub-detail">$($role.Value) identity/identities</span>
          </div>
"@
    }

    # ── Identity findings table rows ────────────────────────────────────────────────
    $findingRows = ""
    $findingsSorted = @($AllFindings |
        Sort-Object `
        @{ Expression = { $privilegeOrder[$_.PrivilegeLevel] }; Descending = $true },
        @{ Expression = { $_.AssignmentCount }; Descending = $true })
    foreach ($f in $findingsSorted) {
        $idx = $findingsSorted.IndexOf($f)
        $privBadge = Get-PrivBadge -Level $f.PrivilegeLevel
        $findingRows += @"
          <tr onclick="showIdentityDetail($idx)">
            <td title="$(EscHtml $f.IdentityName)">$(if ($f.IdentityName.Length -gt 30) { EscHtml($f.IdentityName.Substring(0,27)+"...") } else { EscHtml $f.IdentityName })</td>
            <td style="font-size:11px;">$(EscHtml $f.IdentityType)</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$privBadge</td>
            <td style="text-align:center;font-family:var(--mono)">$($f.AssignmentCount)</td>
            <td><span class="scope-badge">$(EscHtml $f.BroadestScope)</span></td>
            <td style="font-size:11px;" title="$(EscHtml $f.HighestPrivilegeRole)">$(if ($f.HighestPrivilegeRole.Length -gt 28) { EscHtml($f.HighestPrivilegeRole.Substring(0,25)+"...") } else { EscHtml $f.HighestPrivilegeRole })</td>
          </tr>
"@
    }

    # ── JSON for identity findings (table + detail drawer) ─────────────────────────
    $findingsJson = "["
    foreach ($f in $findingsSorted) {
        $findingsJson += "{" +
        """name"":""$(EscJ $f.IdentityName)""," +
        """type"":""$(EscJ $f.IdentityType)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """loc"":""$(EscJ $f.Location)""," +
        """principalId"":""$(EscJ $f.PrincipalId)""," +
        """clientId"":""$(EscJ $f.ClientId)""," +
        """privilege"":""$(EscJ $f.PrivilegeLevel)""," +
        """assignCount"":$($f.AssignmentCount)," +
        """broadestScope"":""$(EscJ $f.BroadestScope)""," +
        """highestRole"":""$(EscJ $f.HighestPrivilegeRole)""," +
        """allRoles"":""$(EscJ $f.AllRoleNames)""" +
        "},"
    }
    $findingsJson = $findingsJson.TrimEnd(",") + "]"

    # ── Subscription results rows ───────────────────────────────────────────────────
    $subRows = ""
    foreach ($s in $SubscriptionResults) {
        $icon = switch ($s.Status) { "Success" { "✓" }; "Warning" { "⚠" }; "Error" { "✗" }; default { "•" } }
        $cls = switch ($s.Status) { "Success" { "c-green" }; "Warning" { "c-amber" }; "Error" { "c-red" }; default { "" } }
        $subRows += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $s.Name)</span>
            <span class="sub-detail">$(EscHtml $s.Count)</span>
          </div>
"@
    }

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Managed Identity Security Assessment</title>
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
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:170px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
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
.badge-purple{background:rgba(163,113,247,.15);color:var(--accent3);border:1px solid rgba(163,113,247,.3);}
.scope-badge{font-size:11px;font-family:var(--mono);color:var(--muted2);}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.info-value.muted{color:var(--muted);font-style:italic;}
.sub-list{display:flex;flex-direction:column;}
.sub-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}
.sub-icon.c-amber{color:var(--amber);}
.sub-icon.c-red{color:var(--red);}
.sub-icon.c-purple{color:var(--accent3);}
.sub-name{flex:1;font-size:13px;font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{
  position:fixed;right:0;top:0;bottom:0;width:440px;max-width:95vw;
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
.drawer-field-value{font-size:13px;word-break:break-all;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
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
    <div class="logo-icon">🪪</div>
    <div class="logo-title">Managed Identity Security</div>
    <div class="logo-sub">Azure Managed Identity Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🪪</span> Identity Findings</button>
    <button class="nav-btn" onclick="showPage('privileges',this)"><span class="nav-icon">🎯</span> Privilege & Roles</button>
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
      Azure Managed Identity Security Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Managed Identity Security Overview</div>
      <div class="page-sub">Identity privilege posture across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_IDENTITIES__</div>
        <div class="stat-label">Identities Found</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__USER_ASSIGNED__</div>
        <div class="stat-label">User-Assigned</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__SYSTEM_ASSIGNED__</div>
        <div class="stat-label">System-Assigned</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical Privilege</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Privilege</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__SUB_COUNT__</div>
        <div class="stat-label">Subscriptions</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Privilege Level Distribution</div>
        __PRIV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🪪 Identity Type Distribution</div>
        __TYPE_ROWS__
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">⚠️ Most Over-Privileged Identities</div>
        <div class="sub-list">__TOP_OVERPRIV__</div>
      </div>
      <div class="panel">
        <div class="panel-title">🎭 Most Common Roles Held</div>
        <div class="sub-list">__TOP_ROLES__</div>
      </div>
    </div>
  </div>

  <!-- Identity Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Identity Findings</div>
      <div class="page-sub">Click any row for the full role and scope breakdown. Sorted by privilege, highest first.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="idSearch" placeholder="Search identity, subscription…" oninput="filterIdentities()"/>
        </div>
        <select class="filter-select" id="filterPriv" onchange="filterIdentities()">
          <option value="">All Privilege Levels</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="None">None</option>
        </select>
        <select class="filter-select" id="pgSizeId" onchange="changeIdPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="idTable">
          <thead>
            <tr>
              <th onclick="sortIdentities(0)">Identity Name</th>
              <th onclick="sortIdentities(1)">Type</th>
              <th onclick="sortIdentities(2)">Subscription</th>
              <th onclick="sortIdentities(3)">Privilege</th>
              <th onclick="sortIdentities(4)">Assignments</th>
              <th onclick="sortIdentities(5)">Broadest Scope</th>
              <th>Highest Role</th>
            </tr>
          </thead>
          <tbody id="idBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="idPagination"></div>
    </div>
  </div>

  <!-- Privilege & Roles -->
  <div id="page-privileges" class="page">
    <div class="page-header">
      <div class="page-title">Privilege & Role Analysis</div>
      <div class="page-sub">Full distribution of privilege levels and every role held across all discovered identities</div>
    </div>
    <div class="panel">
      <div class="panel-title">🎯 Privilege Level Distribution</div>
      __PRIV_ROWS_2__
    </div>
    <div class="panel">
      <div class="panel-title">🎭 Role Distribution (all roles)</div>
      __ROLE_ROWS_FULL__
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription identity assessment outcome</div>
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
        <div class="info-card"><div class="info-label">Export Path</div><div class="info-value__EXPORT_PATH_CLS__">__EXPORT_PATH__</div></div>
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
    <span class="drawer-title" id="drawerTitle">Identity Detail</span>
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
const ID_DATA = __FINDINGS_JSON__;
let idFiltered = [...ID_DATA];
let idPage = 1, idPageSz = 25;
let idSortCol = -1, idSortAsc = true;
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
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme==='dark'?'light':'dark';
}

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Identity findings table ─────────────────────────────────────────────────────
const privBadgeCls = {Critical:'badge-red',High:'badge-amber',Medium:'badge-purple',Low:'badge-green',None:''};
function privBadgeHtml(level){
  const cls = privBadgeCls[level];
  if(cls) return `<span class="badge ${cls}">${escH(level)}</span>`;
  return `<span class="badge" style="background:var(--surface3);color:var(--muted)">${escH(level)}</span>`;
}

function filterIdentities(){
  const q=document.getElementById('idSearch').value.toLowerCase();
  const p=document.getElementById('filterPriv').value;
  idFiltered=ID_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mP=!p||r.privilege===p;
    return mQ&&mP;
  });
  idPage=1; renderIdentities();
}

function changeIdPageSize(){
  idPageSz=parseInt(document.getElementById('pgSizeId').value);
  idPage=1; renderIdentities();
}

const privRank = {Critical:4,High:3,Medium:2,Low:1,None:0};
function sortIdentities(col){
  if(idSortCol===col){idSortAsc=!idSortAsc;}else{idSortCol=col;idSortAsc=true;}
  const keys=['name','type','sub','privilege','assignCount','broadestScope'];
  idFiltered.sort((a,b)=>{
    const k=keys[col];
    let av=a[k]??'', bv=b[k]??'';
    if(k==='privilege'){ av=privRank[av]??0; bv=privRank[bv]??0; }
    return idSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                    :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderIdentities();
}

function renderIdentities(){
  const tbody=document.getElementById('idBody');
  const start=(idPage-1)*idPageSz;
  const slice=idFiltered.slice(start,start+idPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=ID_DATA.indexOf(r);
    const nm=r.name.length>30?r.name.substring(0,27)+'...':r.name;
    const role=r.highestRole.length>28?r.highestRole.substring(0,25)+'...':r.highestRole;
    return `<tr onclick="showIdentityDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td style="font-size:11px;">${escH(r.type)}</td>
      <td>${escH(r.sub)}</td>
      <td>${privBadgeHtml(r.privilege)}</td>
      <td style="text-align:center;font-family:var(--mono)">${r.assignCount}</td>
      <td><span class="scope-badge">${escH(r.broadestScope)}</span></td>
      <td style="font-size:11px;" title="${escH(r.highestRole)}">${escH(role)}</td>
    </tr>`;
  }).join('');
  renderIdPg();
}

function renderIdPg(){
  const total=Math.ceil(idFiltered.length/idPageSz);
  const el=document.getElementById('idPagination');
  let h=`<span>${idFiltered.length} identities</span>`;
  h+=`<button class="pg-btn" onclick="changeIdPage(${idPage-1})" ${idPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,idPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===idPage?'active':''}" onclick="changeIdPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeIdPage(${idPage+1})" ${idPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeIdPage(p){
  const total=Math.ceil(idFiltered.length/idPageSz);
  if(p<1||p>total)return;
  idPage=p; renderIdentities();
}

// ── Identity detail drawer ──────────────────────────────────────────────────────
function showIdentityDetail(idx){
  currentDetailIdx=idx;
  const r=ID_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${ID_DATA.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Privilege Level</div>
      <div class="drawer-field-value">${privBadgeHtml(r.privilege)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Identity Type</div>
      <div class="drawer-field-value">${escH(r.type)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Location</div>
      <div class="drawer-field-value">${escH(r.loc)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Principal ID</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.principalId)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Client ID</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.clientId)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Assignment Count</div>
      <div class="drawer-field-value">${r.assignCount}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Broadest Scope</div>
      <div class="drawer-field-value">${escH(r.broadestScope)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Highest Privilege Role</div>
      <div class="drawer-field-value">${escH(r.highestRole)}</div></div>
    <div class="drawer-section">All Roles Held</div>
    <div class="drawer-field"><div class="drawer-field-value">${r.allRoles?escH(r.allRoles):'—'}</div></div>
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
  if(next>=0&&next<ID_DATA.length) showIdentityDetail(next);
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

// ── Init ─────────────────────────────────────────────────────────────────────
filterIdentities();
animateBars();
</script>
</body>
</html>
'@

    $exportPathCls = if ([string]::IsNullOrWhiteSpace($ScanParameters.ExportPath)) { ' muted' } else { '' }
    $exportPathText = if ($ScanParameters.ExportPath) { $ScanParameters.ExportPath } else { 'N/A' }

    $html = $html `
        -replace '__GENERATED_ON__', $generatedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_IDENTITIES__', $TotalIdentities `
        -replace '__USER_ASSIGNED__', $ScanSummary.UserAssigned `
        -replace '__SYSTEM_ASSIGNED__', $ScanSummary.SystemAssigned `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__PRIV_ROWS_2__', $privRows `
        -replace '__PRIV_ROWS__', $privRows `
        -replace '__TYPE_ROWS__', $typeRows `
        -replace '__TOP_OVERPRIV__', $topOverPrivHtml `
        -replace '__TOP_ROLES__', $topRolesHtml `
        -replace '__ROLE_ROWS_FULL__', $roleRowsFull `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXPORT_PATH_CLS__', $exportPathCls `
        -replace '__EXPORT_PATH__', $exportPathText `
        -replace '__EXEC_TIME__', $ScanSummary.ExecutionTime `
        -replace '__FINDINGS_JSON__', $findingsJson

    return $html
}

#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureManagedIdentitySecurityAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,
        [string[]]$SubscriptionIds,
        [switch]$ExportToCsv,
        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureManagedIdentitySecurityAssessment-Report.csv"
    )

    # Start timing
    $startTime = Get-Date

    # Display banner
    Write-MiBanner

    # ── Module check ─────────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.ManagedServiceIdentity")

    foreach ($moduleName in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Host "  ⚠ Module '$moduleName' not found." -ForegroundColor Yellow
            Write-Host ""
            $installChoice = Read-Host "  Install '$moduleName' now? (Y/N)"

            if ($installChoice -eq 'Y' -or $installChoice -eq 'y') {
                try {
                    Write-Host ""
                    Write-Host "  Installing $moduleName, please wait..." -ForegroundColor Cyan
                    Install-Module -Name $moduleName -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                    Import-Module $moduleName -ErrorAction Stop
                    Write-Host "  ✓ $moduleName installed successfully" -ForegroundColor Green
                    Write-Host ""
                }
                catch {
                    Write-Host "  ✗ Error installing $moduleName`: $_" -ForegroundColor Red
                    return
                }
            }
            else {
                Write-Host ""
                Write-Host "  Installation declined. Cannot proceed without $moduleName." -ForegroundColor Yellow
                return
            }
        }
    }

    # ── Authentication ────────────────────────────────────────────────────────────
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext) {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    # ── Subscription resolution ───────────────────────────────────────────────────
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

    # ── Session & parameter metadata ─────────────────────────────────────────────
    $sessionInfo = @{
        Tenant      = $currentContext.Tenant.Id
        Account     = $currentContext.Account.Id
        Environment = $currentContext.Environment.Name
    }

    $scanParameters = @{
        Scope         = "$scopeText ($subscriptionCount found)"
        ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        ExportPath    = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Console: session + parameter display ─────────────────────────────────────
    Write-MiSection -Title "Session Information" -Data @{
        "Tenant"      = $currentContext.Tenant.Id
        "Account"     = $currentContext.Account.Id
        "Environment" = $currentContext.Environment.Name
    }

    Write-MiSection -Title "Scan Parameters" -Data @{
        "Scope"         = "$scopeText ($subscriptionCount found)"
        "Export to CSV" = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"   = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────────
    $allFindings = @()
    $subscriptionResults = @()
    $statistics = @{
        SuccessCount             = 0
        ErrorCount               = 0
        UserAssignedCount        = 0
        SystemAssignedCount      = 0
        PrivilegeDistribution    = @{ Critical = 0; High = 0; Medium = 0; Low = 0; None = 0 }
        IdentityTypeDistribution = @{}
        RoleDistribution         = @{}
    }

    # ── Scan loop ─────────────────────────────────────────────────────────────────
    Write-MiScanProgress
    Write-MiProgressBar -Current 0 -Total $subscriptionCount -CurrentItem "Starting..."

    $maxNameLength = ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
    $maxNameLength = [math]::Max($maxNameLength, 35)
    $subscriptionIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-MiProgressBar -Current $subscriptionIndex -Total $subscriptionCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id `
                -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue | Out-Null

            $identityCount = 0

            # ── A. User-Assigned Managed Identities ───────────────────────────────
            $userAssignedIdentities = @()
            try {
                $userAssignedIdentities = @(Get-AzUserAssignedIdentity `
                        -ErrorAction SilentlyContinue `
                        -WarningAction SilentlyContinue)
            }
            catch {
                Write-Verbose "  Could not retrieve User-Assigned identities in '$($sub.Name)': $($_.Exception.Message)"
            }

            foreach ($uai in $userAssignedIdentities) {
                try {
                    # Get RBAC assignments for this identity's principal
                    $assignments = @()
                    try {
                        $assignments = @(Get-AzRoleAssignment `
                                -ObjectId $uai.PrincipalId `
                                -ErrorAction SilentlyContinue `
                                -WarningAction SilentlyContinue)
                    }
                    catch { $assignments = @() }

                    $privilegeLevel = Get-MiPrivilegeLevel -Assignments $assignments -SubscriptionId $sub.Id
                    $broadestScope = "None"
                    $highestPrivRole = "None"
                    $allRoleNames = ""

                    if ($assignments.Count -gt 0) {
                        # Determine broadest scope
                        $scopePriority = @{ ManagementGroup = 4; Subscription = 3; ResourceGroup = 2; Resource = 1; Unknown = 0 }
                        $broadestScope = $assignments |
                        ForEach-Object { Get-MiScopeLevel -Scope $_.Scope } |
                        Sort-Object { $scopePriority[$_] } -Descending |
                        Select-Object -First 1

                        # Derive highest privilege role (by privilege level classification)
                        $highestPrivRole = $assignments |
                        Where-Object { $Script:MiCriticalRoles -contains $_.RoleDefinitionName } |
                        Select-Object -First 1 -ExpandProperty RoleDefinitionName

                        if (-not $highestPrivRole) {
                            $highestPrivRole = $assignments |
                            Where-Object { $Script:MiHighRoles -contains $_.RoleDefinitionName } |
                            Select-Object -First 1 -ExpandProperty RoleDefinitionName
                        }
                        if (-not $highestPrivRole) {
                            $highestPrivRole = $assignments |
                            Where-Object { $Script:MiMediumRoles -contains $_.RoleDefinitionName } |
                            Select-Object -First 1 -ExpandProperty RoleDefinitionName
                        }
                        if (-not $highestPrivRole) {
                            $highestPrivRole = $assignments |
                            Select-Object -First 1 -ExpandProperty RoleDefinitionName
                        }

                        $allRoleNames = ($assignments |
                            Select-Object -ExpandProperty RoleDefinitionName -Unique) -join "; "

                        # Track role distribution
                        foreach ($a in $assignments) {
                            if ($a.RoleDefinitionName) {
                                if ($statistics.RoleDistribution.ContainsKey($a.RoleDefinitionName)) {
                                    $statistics.RoleDistribution[$a.RoleDefinitionName]++
                                }
                                else {
                                    $statistics.RoleDistribution[$a.RoleDefinitionName] = 1
                                }
                            }
                        }
                    }

                    $finding = [pscustomobject]@{
                        SubscriptionName     = $sub.Name
                        SubscriptionId       = $sub.Id
                        TenantId             = $sub.TenantId
                        ResourceGroup        = $uai.ResourceGroupName
                        IdentityName         = $uai.Name
                        IdentityType         = "UserAssigned"
                        PrincipalId          = $uai.PrincipalId
                        ClientId             = $uai.ClientId
                        Location             = $uai.Location
                        AssignmentCount      = $assignments.Count
                        HighestPrivilegeRole = if ($highestPrivRole) { $highestPrivRole } else { "None" }
                        BroadestScope        = $broadestScope
                        PrivilegeLevel       = $privilegeLevel
                        AllRoleNames         = $allRoleNames
                    }

                    $allFindings += $finding
                    $statistics.UserAssignedCount++
                    $identityCount++

                    if ($statistics.PrivilegeDistribution.ContainsKey($privilegeLevel)) {
                        $statistics.PrivilegeDistribution[$privilegeLevel]++
                    }

                    if ($statistics.IdentityTypeDistribution.ContainsKey("UserAssigned")) {
                        $statistics.IdentityTypeDistribution["UserAssigned"]++
                    }
                    else {
                        $statistics.IdentityTypeDistribution["UserAssigned"] = 1
                    }
                }
                catch {
                    Write-Verbose "  Skipping User-Assigned identity '$($uai.Name)': $($_.Exception.Message)"
                }
            }

            # ── B. System-Assigned Managed Identities ─────────────────────────────
            # Discover resources that have a SystemAssigned identity enabled
            $systemAssignedResources = @()
            try {
                $systemAssignedResources = @(Get-AzResource -ErrorAction SilentlyContinue |
                    Where-Object { $_.Identity -and $_.Identity.Type -like "*SystemAssigned*" })
            }
            catch {
                Write-Verbose "  Could not retrieve resources in '$($sub.Name)': $($_.Exception.Message)"
            }

            foreach ($resource in $systemAssignedResources) {
                try {
                    $principalId = $resource.Identity.PrincipalId
                    if ([string]::IsNullOrWhiteSpace($principalId)) { continue }

                    # Get RBAC assignments for this system identity's principal
                    $assignments = @()
                    try {
                        $assignments = @(Get-AzRoleAssignment `
                                -ObjectId $principalId `
                                -ErrorAction SilentlyContinue `
                                -WarningAction SilentlyContinue)
                    }
                    catch { $assignments = @() }

                    $privilegeLevel = Get-MiPrivilegeLevel -Assignments $assignments -SubscriptionId $sub.Id
                    $broadestScope = "None"
                    $highestPrivRole = "None"
                    $allRoleNames = ""

                    if ($assignments.Count -gt 0) {
                        $scopePriority = @{ ManagementGroup = 4; Subscription = 3; ResourceGroup = 2; Resource = 1; Unknown = 0 }
                        $broadestScope = $assignments |
                        ForEach-Object { Get-MiScopeLevel -Scope $_.Scope } |
                        Sort-Object { $scopePriority[$_] } -Descending |
                        Select-Object -First 1

                        $highestPrivRole = $assignments |
                        Where-Object { $Script:MiCriticalRoles -contains $_.RoleDefinitionName } |
                        Select-Object -First 1 -ExpandProperty RoleDefinitionName

                        if (-not $highestPrivRole) {
                            $highestPrivRole = $assignments |
                            Where-Object { $Script:MiHighRoles -contains $_.RoleDefinitionName } |
                            Select-Object -First 1 -ExpandProperty RoleDefinitionName
                        }
                        if (-not $highestPrivRole) {
                            $highestPrivRole = $assignments |
                            Where-Object { $Script:MiMediumRoles -contains $_.RoleDefinitionName } |
                            Select-Object -First 1 -ExpandProperty RoleDefinitionName
                        }
                        if (-not $highestPrivRole) {
                            $highestPrivRole = $assignments |
                            Select-Object -First 1 -ExpandProperty RoleDefinitionName
                        }

                        $allRoleNames = ($assignments |
                            Select-Object -ExpandProperty RoleDefinitionName -Unique) -join "; "

                        foreach ($a in $assignments) {
                            if ($a.RoleDefinitionName) {
                                if ($statistics.RoleDistribution.ContainsKey($a.RoleDefinitionName)) {
                                    $statistics.RoleDistribution[$a.RoleDefinitionName]++
                                }
                                else {
                                    $statistics.RoleDistribution[$a.RoleDefinitionName] = 1
                                }
                            }
                        }
                    }

                    $finding = [pscustomobject]@{
                        SubscriptionName     = $sub.Name
                        SubscriptionId       = $sub.Id
                        TenantId             = $sub.TenantId
                        ResourceGroup        = $resource.ResourceGroupName
                        IdentityName         = $resource.Name
                        IdentityType         = "SystemAssigned ($($resource.ResourceType))"
                        PrincipalId          = $principalId
                        ClientId             = "N/A"
                        Location             = $resource.Location
                        AssignmentCount      = $assignments.Count
                        HighestPrivilegeRole = if ($highestPrivRole) { $highestPrivRole } else { "None" }
                        BroadestScope        = $broadestScope
                        PrivilegeLevel       = $privilegeLevel
                        AllRoleNames         = $allRoleNames
                    }

                    $allFindings += $finding
                    $statistics.SystemAssignedCount++
                    $identityCount++

                    if ($statistics.PrivilegeDistribution.ContainsKey($privilegeLevel)) {
                        $statistics.PrivilegeDistribution[$privilegeLevel]++
                    }

                    $typeKey = "SystemAssigned"
                    if ($statistics.IdentityTypeDistribution.ContainsKey($typeKey)) {
                        $statistics.IdentityTypeDistribution[$typeKey]++
                    }
                    else {
                        $statistics.IdentityTypeDistribution[$typeKey] = 1
                    }
                }
                catch {
                    Write-Verbose "  Skipping System-Assigned identity on '$($resource.Name)': $($_.Exception.Message)"
                }
            }

            # Clear progress line and display subscription result
            Write-Host "`r" -NoNewline
            Write-Host (" " * 120) -NoNewline
            Write-Host "`r" -NoNewline

            $paddedName = $sub.Name.PadRight($maxNameLength)

            Write-Host "  " -NoNewline
            if ($identityCount -gt 0) {
                Write-Host "✓ " -NoNewline -ForegroundColor Green
                Write-Host $paddedName -NoNewline -ForegroundColor Green
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "$identityCount identity/identities found" -ForegroundColor White
                $statistics.SuccessCount++
                $subscriptionResults += @{ Name = $sub.Name; Count = "$identityCount identity/identities found"; Status = "Success" }
            }
            else {
                Write-Host "⚠ " -NoNewline -ForegroundColor Yellow
                Write-Host $paddedName -NoNewline -ForegroundColor Yellow
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "No managed identities found" -ForegroundColor DarkGray
                $statistics.SuccessCount++
                $subscriptionResults += @{ Name = $sub.Name; Count = "No managed identities found"; Status = "Warning" }
            }

            $subscriptionIndex++
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
            $subscriptionResults += @{ Name = $sub.Name; Count = "Failed: $($_.Exception.Message)"; Status = "Error" }
            $subscriptionIndex++
        }
    }

    # ── Execution time ────────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration

    # ── Scan summary ──────────────────────────────────────────────────────────────
    $scanSummary = @{
        TotalIdentities      = $allFindings.Count
        UserAssigned         = $statistics.UserAssignedCount
        SystemAssigned       = $statistics.SystemAssignedCount
        SubscriptionsScanned = $subscriptionCount
        ExecutionTime        = $durationFormatted
    }

    # ── Console summary output ────────────────────────────────────────────────────
    Write-MiSummary -Data @{
        "Total Subscriptions Scanned"   = $subscriptionCount
        "Successful"                    = $statistics.SuccessCount
        "Errors"                        = $statistics.ErrorCount
        "Total Identities Found"        = $allFindings.Count
        "User-Assigned"                 = $statistics.UserAssignedCount
        "System-Assigned"               = $statistics.SystemAssignedCount
        "Critical Privilege Identities" = $statistics.PrivilegeDistribution["Critical"]
        "High Privilege Identities"     = $statistics.PrivilegeDistribution["High"]
        "Medium Privilege Identities"   = $statistics.PrivilegeDistribution["Medium"]
        "Low Privilege Identities"      = $statistics.PrivilegeDistribution["Low"]
        "No RBAC Assignments"           = $statistics.PrivilegeDistribution["None"]
        "Execution Time"                = $durationFormatted
    }

    Write-MiPrivilegeDistribution   -PrivilegeData $statistics.PrivilegeDistribution  -TotalIdentities $allFindings.Count
    Write-MiIdentityTypeDistribution -TypeData $statistics.IdentityTypeDistribution     -TotalIdentities $allFindings.Count
    Write-MiTopOverPrivileged        -Identities $allFindings
    Write-MiTopRoles                 -Roles $statistics.RoleDistribution

    # ── Output processing ─────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        # CSV export (optional)
        if ($ExportToCsv) {
            try {
                $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, TenantId, ResourceGroup,
                IdentityName, IdentityType, PrincipalId, ClientId, Location,
                AssignmentCount, HighestPrivilegeRole, BroadestScope,
                PrivilegeLevel, AllRoleNames |
                Export-Csv -Path $CsvPath -NoTypeInformation -ErrorAction Stop
                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML report (always generated)
        try {
            $htmlPath = $CsvPath -replace '\.csv$', '.html'
            if (-not $htmlPath.EndsWith('.html')) {
                $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
            }

            $htmlContent = Generate-MiHtmlReport `
                -SessionInfo              $sessionInfo `
                -ScanParameters           $scanParameters `
                -ScanSummary              $scanSummary `
                -SubscriptionResults      $subscriptionResults `
                -AllFindings              $allFindings `
                -PrivilegeDistribution    $statistics.PrivilegeDistribution `
                -IdentityTypeDistribution $statistics.IdentityTypeDistribution `
                -RoleDistribution         $statistics.RoleDistribution `
                -TotalIdentities          $allFindings.Count `
                -CsvPath                  $(if ($csvExported) { $CsvPath } else { $null }) `
                -HtmlPath                 $htmlPath `
                -GridViewOpened           $false

            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML report generation failed: $_" -ForegroundColor Red
        }

        # Grid View (best-effort)
        try {
            $allFindings | Select-Object `
                IdentityName, IdentityType, SubscriptionName, ResourceGroup, Location,
            PrivilegeLevel, AssignmentCount, HighestPrivilegeRole, BroadestScope,
            AllRoleNames, PrincipalId, ClientId |
            Out-GridView -Title "Azure Managed Identity Security Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View" -ForegroundColor Yellow
        }
    }

    # Display output file summary
    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        Write-MiOutputFiles `
            -CsvPath        $(if ($csvExported) { $CsvPath } else { $null }) `
            -HtmlPath       $(if ($htmlExported) { $htmlPath } else { $null }) `
            -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
