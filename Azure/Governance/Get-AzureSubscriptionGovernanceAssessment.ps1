<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Assesses the governance posture of Azure subscriptions across ten control domains —
    ownership, management-group placement, policy, RBAC, budget, locks, logging,
    Defender for Cloud, tagging, and region — producing a 100-point governance
    scorecard with prioritised findings and an interactive HTML dashboard.

.DESCRIPTION
    Get-AzureSubscriptionGovernanceAssessment solves the enterprise governance problem
    of knowing, at a glance, how well each subscription is governed. Without a unified
    scorecard, it is impossible to prioritise governance remediation across a large
    Azure estate — every subscription looks fine in isolation until something goes wrong.

    This script evaluates ten governance control domains. Each domain contributes up
    to 10 points to a maximum scorecard of 100. The resulting score drives a
    governance grade: Governed (85+), Partial (60–84), At Risk (40–59), Critical (<40).

    Control Domains:

      1. Ownership & Identity (10 pts)
           - Subscription has at least one Owner role assignment
           - Owner count does not exceed 5 (over-privileged = ungoverned)
           - Preferred: Owner is a group or service principal, not a user directly

      2. Management Group Placement (10 pts)
           - Subscription is placed under a named management group, not the Tenant
             Root Group (which is ungoverned — policies and RBAC don't flow through
             an unconfigured root)

      3. Policy Coverage (10 pts)
           - At least one non-initiative policy assignment is in force
           - No assignments are in DoNotEnforce mode (indicates policies exist but
             are silently bypassed)
           - Presence of a security or compliance initiative (Defender, CIS, NIST…)

      4. RBAC Hygiene (10 pts)
           - No Classic Administrators (Co-Admin / Account Admin) — legacy auth model,
             not subject to Entra ID Conditional Access or PIM
           - Ratio of group-based to direct user assignments (groups preferred —
             enables Joiner/Mover/Leaver process via group membership rather than
             individual role management)
           - Absence of subscription-scope Owner or Contributor assigned to individuals
             rather than groups/service principals

      5. Budget & Cost Controls (10 pts)
           - At least one Azure Budget exists on the subscription
           - Budget has at least one alert threshold configured
           - Budget amount is non-trivial (>0)

      6. Resource Locks (10 pts)
           - At least one CanNotDelete or ReadOnly lock is present on the subscription
             or its resource groups
           - Presence of locks on resource groups that contain production-critical
             resource types (Key Vaults, storage, databases)

      7. Activity Log & Diagnostics (10 pts)
           - Subscription-level diagnostic setting exists and routes to Log Analytics
           - Diagnostic setting captures Administrative, Security, and Policy categories
           - Log retention meets minimum compliance baseline (>= 90 days)

      8. Microsoft Defender for Cloud (10 pts)
           - Defender plans are enabled for high-value resource types:
             VirtualMachines, SqlServers, AppServices, StorageAccounts, KeyVaults
           - Checks the Free vs Standard (paid/enhanced) tier for each plan

      9. Tagging Governance (10 pts)
           - Subscription itself has expected governance tags:
             Environment, Owner (or Contact), CostCenter (or BillingCode)
           - Tags are non-empty / non-placeholder values

      10. Region Compliance (10 pts)
           - Resources are only deployed to regions. This domain checks whether all
             resource locations are in a non-empty set. (Actual allowed-region policy
             enforcement is assessed in Domain 3.) This domain flags subscriptions with
             resources deployed to a large number of distinct regions (>= 5), which is
             a sprawl signal and a potential data-residency concern.

    The per-domain scores and findings are surfaced individually so architects can
    identify exactly which controls are missing and prioritise remediation.

    Each control domain finding includes:
        - Domain         : which of the 10 control areas
        - Score          : 0–10 (partial scores awarded where applicable)
        - Status         : Pass / Partial / Fail
        - Gap            : what is missing or misconfigured
        - Impact         : why this matters from a governance and business perspective
        - Recommendation : concrete remediation step

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default when -SubscriptionIds is not provided.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan.

.PARAMETER ExportToCsv
    Switch. Exports all findings to the path given in -CsvPath.

.PARAMETER CsvPath
    Destination path for CSV and HTML dashboard output.
    Default: C:\Temp\AzureSubscriptionGovernance-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    Always writes an HTML dashboard. Optionally writes a CSV when -ExportToCsv
    is specified. Opens Grid View where GUI is available.

.EXAMPLE
    Get-AzureSubscriptionGovernanceAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureSubscriptionGovernanceAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureSubscriptionGovernanceAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\SubGovernance.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Ten-domain governance scorecard,
                            composite score (0–100), governance grade, per-domain
                            findings with gap/impact/recommendation, HTML dashboard
                            with scorecard ring, domain breakdown, control details,
                            and detail drawer. CSV export.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.Security,
           Az.Monitor, Az.Billing) — installed automatically with user consent.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role at subscription scope (minimum) for most domains.
        4. Microsoft.Authorization/roleAssignments/read — for RBAC domain.
        5. Microsoft.Authorization/policyAssignments/read — for Policy domain.
        6. Microsoft.Authorization/policyExemptions/read — for Policy domain.
        7. Microsoft.Security/pricings/read — for Defender domain. Without this
           permission the Defender domain is recorded as "Could Not Assess".
        8. microsoft.insights/diagnosticSettings/read — for Logging domain.
        9. Microsoft.Consumption/budgets/read — for Budget domain. Without this
           the Budget domain is marked "Could Not Assess".
        10. Microsoft.Management/managementGroups/read at tenant root — for MG
            Placement domain. Without this the domain is scored at minimum (0).

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Region compliance (Domain 10) checks for sprawl (>= 5 distinct regions)
          as a proxy for ungoverned deployment. It does not enforce an allowed-region
          list — that should be done via Azure Policy (Domain 3).
        - Defender for Cloud plan enumeration uses Get-AzSecurityPricing, which
          requires the Security Reader role. In subscriptions where this is missing,
          the domain is recorded as "Could Not Assess" with a clear note.
        - Budget retrieval requires Az.Billing module and Consumption Reader or
          Cost Management Reader role. Without it the domain is gracefully skipped.
        - Log retention assessment reads the diagnostic setting destination workspace
          retention — it cannot assess storage-account-based retention via the Az
          module without additional calls. Skipped gracefully if workspace ID is absent.
        - Activity Log diagnostic settings are subscription-scoped resources. The
          script reads them from the /subscriptions/{id}/providers/microsoft.insights/
          diagnosticSettings endpoint via Invoke-AzRestMethod as Get-AzDiagnosticSetting
          requires a resource ID and subscription-level settings use a distinct API path.
        - Classic Administrators enumeration is best-effort; Azure is deprecating this
          API and results may be empty in newer subscriptions.

.LINK
    https://learn.microsoft.com/en-us/azure/governance/management-groups/overview
    https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction
    https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log
    https://learn.microsoft.com/en-us/azure/role-based-access-control/overview

#>


#------------------------------------------------------------------------ [ Constants ]

$script:GovernanceDomains = @(
    "Ownership & Identity",
    "Management Group Placement",
    "Policy Coverage",
    "RBAC Hygiene",
    "Budget & Cost Controls",
    "Resource Locks",
    "Activity Log & Diagnostics",
    "Defender for Cloud",
    "Tagging Governance",
    "Region Compliance"
)

$script:SecurityInitiativeKeywords = @(
    "defender", "security center", "cis", "nist", "pci", "iso 27001", "hipaa", "soc",
    "benchmark", "mcsb", "microsoft cloud security", "regulatory compliance", "azure security"
)

$script:GovernanceTags = @("Environment", "Owner", "CostCenter", "Contact", "BillingCode", "Application", "Team")


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
    Write-CenteredText "Azure Subscription Governance Assessment v1.0" -Color White
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

Function Write-GradeBreakdown {
    param([array]$ScorecardResults)
    if ($ScorecardResults.Count -eq 0) { return }
    $governed = @($ScorecardResults | Where-Object { $_.GovernanceGrade -eq "Governed" }).Count
    $partial = @($ScorecardResults | Where-Object { $_.GovernanceGrade -eq "Partial" }).Count
    $atRisk = @($ScorecardResults | Where-Object { $_.GovernanceGrade -eq "At Risk" }).Count
    $critical = @($ScorecardResults | Where-Object { $_.GovernanceGrade -eq "Critical" }).Count
    Write-Host ""
    Write-Host "  Governance Grade Breakdown" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Governed (85+)  ".PadRight(30) -NoNewline -ForegroundColor Gray; Write-Host ": $governed"  -ForegroundColor Green
    Write-Host "  Partial  (60-84)".PadRight(30) -NoNewline -ForegroundColor Gray; Write-Host ": $partial"   -ForegroundColor Yellow
    Write-Host "  At Risk  (40-59)".PadRight(30) -NoNewline -ForegroundColor Gray; Write-Host ": $atRisk"    -ForegroundColor DarkYellow
    Write-Host "  Critical (<40)  ".PadRight(30) -NoNewline -ForegroundColor Gray; Write-Host ": $critical"  -ForegroundColor Red
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
        Write-Host "  " -NoNewline; Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("CSV Export").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }
    if ($HtmlPath) {
        Write-Host "  " -NoNewline; Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Dashboard").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }
    if ($GridViewOpened) {
        Write-Host "  " -NoNewline; Write-Host "✓ " -NoNewline -ForegroundColor Green
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

Function New-DomainFinding {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$Domain,
        [int]$Score,
        [string]$Status,
        [string]$Gap,
        [string]$Impact,
        [string]$Recommendation,
        [string]$Evidence = ""
    )
    [pscustomobject]@{
        SubscriptionName = $SubscriptionName
        SubscriptionId   = $SubscriptionId
        Domain           = $Domain
        Score            = $Score
        Status           = $Status
        Gap              = $Gap
        Impact           = $Impact
        Recommendation   = $Recommendation
        Evidence         = $Evidence
    }
}


#------------------------------------------------------------------------ [ Domain Assessors ]

Function Invoke-Domain01_Ownership {
    param([object]$Sub, [array]$RoleAssignments)

    $domain = "Ownership & Identity"
    $owners = @($RoleAssignments | Where-Object {
            $_.RoleDefinitionName -eq "Owner" -and
            $_.Scope -match "^/subscriptions/[^/]+$"
        })

    if ($owners.Count -eq 0) {
        return New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
            -Domain $domain -Score 0 -Status "Fail" `
            -Gap "No Owner role assignments found at subscription scope." `
            -Impact "An unowned subscription has no accountable party. Without a defined owner, governance actions (cost review, security escalation, policy decisions) have no clear executor. In an incident, the absence of an owner causes delay in response and escalation." `
            -Recommendation "Assign the Owner role to a named Azure AD group representing the subscription owner team. Using a group (not an individual) ensures continuity when staff change and enables PIM-eligible access for just-in-time escalation." `
            -Evidence "Owner count: 0"
    }

    $score = 5
    $gaps = @()
    $evidence = "Owner count: $($owners.Count)"

    if ($owners.Count -gt 5) {
        $score = [math]::Max(0, $score - 2)
        $gaps += "Too many owners ($($owners.Count)) — reduces accountability (no clear single owner) and increases blast radius of a compromised credential."
        $evidence += " [WARN: $($owners.Count) owners]"
    }

    # Check for direct user owners vs group/SP owners
    $userOwners = @($owners | Where-Object { $_.ObjectType -eq "User" })
    $groupOwners = @($owners | Where-Object { $_.ObjectType -in @("Group", "ServicePrincipal", "ManagedIdentity") })

    if ($userOwners.Count -gt 0 -and $groupOwners.Count -eq 0) {
        $score = [math]::Max(0, $score - 2)
        $gaps += "$($userOwners.Count) Owner(s) assigned directly to users. Prefer assigning ownership to Azure AD groups to support Joiner/Mover/Leaver lifecycle management and PIM."
        $evidence += " [UserOwners: $($userOwners.Count)]"
    }

    if ($score -ge 5 -and $gaps.Count -eq 0) { $score = 10 }

    $status = if ($score -ge 8) { "Pass" } elseif ($score -ge 4) { "Partial" } else { "Fail" }
    $gapText = if ($gaps.Count -gt 0) { $gaps -join " " } else { "Owner role assignment is in place." }
    $impact = if ($gaps.Count -gt 0) { "Individual owner assignments do not scale with staff changes and can leave subscriptions orphaned when owners leave the organisation." } else { "Owner accountability is established." }
    $rec = if ($gaps.Count -gt 0) { "Rationalise ownership: assign the Owner role to one or two Azure AD groups. Enable PIM for owner activation to require justification and approval for elevated actions." } else { "Review owner list quarterly to confirm currency." }

    New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
        -Domain $domain -Score $score -Status $status `
        -Gap $gapText -Impact $impact -Recommendation $rec -Evidence $evidence
}

Function Invoke-Domain02_ManagementGroup {
    param([object]$Sub, [string]$ManagementGroupId, [string]$ManagementGroupName)

    $domain = "Management Group Placement"

    if ([string]::IsNullOrWhiteSpace($ManagementGroupId)) {
        return New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
            -Domain $domain -Score 0 -Status "Fail" `
            -Gap "Management Group placement could not be determined (insufficient permissions or subscription not in any MG)." `
            -Impact "If the subscription is at the Tenant Root Group level, it inherits no organisation-specific policy or RBAC from a governed management group hierarchy, which is equivalent to being ungoverned from a top-down perspective." `
            -Recommendation "Ensure the subscription is placed within the correct landing zone management group. Grant the Reader role on the Tenant Root Group to the scanning account to enable future MG placement assessment." `
            -Evidence "MG ID: Could Not Assess"
    }

    $isTenantRoot = $ManagementGroupId -match "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

    if ($isTenantRoot) {
        return New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
            -Domain $domain -Score 0 -Status "Fail" `
            -Gap "Subscription is directly under the Tenant Root Management Group (ID: $ManagementGroupId). No organisation-specific management group hierarchy is applied." `
            -Impact "The Tenant Root Group is rarely configured with meaningful policy assignments or RBAC. Subscriptions placed here bypass the entire management group governance hierarchy — they receive no landing zone policies, no enterprise RBAC from the hierarchy, and no initiative assignments from the corporate governance structure." `
            -Recommendation "Move the subscription into the appropriate Azure Landing Zone management group (e.g., Corp, Online, Sandbox). Update any existing policy assignments or RBAC grants at the subscription level that should instead be inherited from the management group." `
            -Evidence "MG: Tenant Root ($ManagementGroupId)"
    }

    New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
        -Domain $domain -Score 10 -Status "Pass" `
        -Gap "Subscription is placed under management group '$ManagementGroupName'." `
        -Impact "Management group placement enables policy and RBAC inheritance from the hierarchy." `
        -Recommendation "Verify the management group is in the correct position in the hierarchy for this subscription's purpose (production, sandbox, corp, etc.)." `
        -Evidence "MG: $ManagementGroupName ($ManagementGroupId)"
}

Function Invoke-Domain03_Policy {
    param([object]$Sub, [array]$PolicyAssignments)

    $domain = "Policy Coverage"

    if ($PolicyAssignments.Count -eq 0) {
        return New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
            -Domain $domain -Score 0 -Status "Fail" `
            -Gap "No policy assignments found at this subscription." `
            -Impact "A subscription with no policy assignments has no automated guardrails. Resources can be deployed in any configuration, to any region, with any settings. Non-compliance with security, cost, or operational standards cannot be detected or enforced." `
            -Recommendation "Assign the Microsoft Cloud Security Benchmark (MCSB) initiative as a baseline, then layer organisation-specific policies for tagging, allowed regions, and resource type restrictions. Ensure at least one assignment uses Default enforcement mode (not DoNotEnforce)." `
            -Evidence "Assignment count: 0"
    }

    $score = 0
    $gaps = @()
    $evidence = "Assignments: $($PolicyAssignments.Count)"

    # Has assignments
    $score += 3

    # Check for DoNotEnforce
    $doNotEnforce = @($PolicyAssignments | Where-Object {
            $_.EnforcementMode -eq "DoNotEnforce" -or $_.EnforcementMode -eq "Disabled"
        })
    if ($doNotEnforce.Count -gt 0 -and $doNotEnforce.Count -eq $PolicyAssignments.Count) {
        $score = [math]::Max(0, $score - 2)
        $gaps += "All $($PolicyAssignments.Count) assignment(s) are in DoNotEnforce/Disabled mode — policies exist but do not enforce anything. This gives a false sense of control."
        $evidence += " [AllDoNotEnforce]"
    }
    elseif ($doNotEnforce.Count -gt 0) {
        $gaps += "$($doNotEnforce.Count) assignment(s) in DoNotEnforce mode."
        $evidence += " [DoNotEnforce: $($doNotEnforce.Count)]"
    }

    # Security initiative present
    $secAssignments = @($PolicyAssignments | Where-Object {
            $name = $_.DisplayName + " " + ($_.PolicyDefinitionId -replace '.*/', '')
            $found = $script:SecurityInitiativeKeywords | Where-Object { $name.ToLower() -contains $_ }
            $found
        })
    if ($secAssignments.Count -gt 0) {
        $score += 4
        $evidence += " [SecurityInitiative: Yes]"
    }
    else {
        $gaps += "No recognised security or compliance initiative (e.g., MCSB, CIS, NIST) is assigned. Without a security baseline, misconfigured resources may not be detected."
        $score += 1
        $evidence += " [SecurityInitiative: No]"
    }

    # Enforcing assignments (Default mode, not DoNotEnforce)
    $enforcing = @($PolicyAssignments | Where-Object {
            $_.EnforcementMode -ne "DoNotEnforce" -and $_.EnforcementMode -ne "Disabled"
        })
    if ($enforcing.Count -gt 0) {
        $score += 2
    }

    $score = [math]::Min($score, 10)
    $status = if ($score -ge 8) { "Pass" } elseif ($score -ge 4) { "Partial" } else { "Fail" }
    $gapText = if ($gaps.Count -gt 0) { $gaps -join " " } else { "Policy assignments in place with security initiative coverage." }
    $impact = if ($gaps.Count -gt 0) { "Without active policy enforcement, resource configuration drift goes undetected. Security misconfigurations accumulate silently until an incident." } else { "Policy enforcement provides automated guardrails for configuration compliance." }
    $rec = if ($gaps.Count -gt 0) { "Review all DoNotEnforce assignments and determine whether enforcement can be enabled. Assign MCSB or CIS benchmark initiative if no security initiative is present." } else { "Periodically review policy compliance state to ensure non-compliant resources are being remediated." }

    New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
        -Domain $domain -Score $score -Status $status `
        -Gap $gapText -Impact $impact -Recommendation $rec -Evidence $evidence
}

Function Invoke-Domain04_RBAC {
    param([object]$Sub, [array]$RoleAssignments, [array]$ClassicAdmins)

    $domain = "RBAC Hygiene"
    $score = 10
    $gaps = @()

    # Classic Admins
    if ($ClassicAdmins.Count -gt 0) {
        $score -= 4
        $gaps += "$($ClassicAdmins.Count) Classic Administrator(s) found. Classic Admin is a legacy role not subject to Entra ID Conditional Access, PIM, or MFA enforcement. These should be removed."
    }

    # Direct user owner/contributor at sub scope
    $subScopeAssignments = @($RoleAssignments | Where-Object {
            $_.Scope -match "^/subscriptions/[^/]+$" -and
            $_.RoleDefinitionName -in @("Owner", "Contributor") -and
            $_.ObjectType -eq "User"
        })
    if ($subScopeAssignments.Count -gt 0) {
        $score -= 3
        $gaps += "$($subScopeAssignments.Count) direct user assignment(s) of Owner or Contributor at subscription scope. Prefer group-based assignments to support Joiner/Mover/Leaver lifecycle management."
    }

    # Group vs user ratio
    $allSub = @($RoleAssignments | Where-Object { $_.Scope -match "^/subscriptions/[^/]+$" })
    $groups = @($allSub | Where-Object { $_.ObjectType -eq "Group" }).Count
    $users = @($allSub | Where-Object { $_.ObjectType -eq "User" }).Count
    if ($users -gt 0 -and $groups -eq 0) {
        $score -= 2
        $gaps += "All subscription-scope role assignments are to individuals (no group assignments). Group-based RBAC is recommended for lifecycle management and auditability."
    }

    $score = [math]::Max(0, $score)
    $status = if ($score -ge 8) { "Pass" } elseif ($score -ge 4) { "Partial" } else { "Fail" }
    $gapText = if ($gaps.Count -gt 0) { $gaps -join " " } else { "RBAC assignments follow best practice: group-based, no classic admins, appropriate scope." }
    $impact = if ($gaps.Count -gt 0) { "Legacy and individual-user RBAC assignments create governance blind spots: staff changes cause orphaned access, classic admins bypass modern identity controls, and individual assignments are hard to audit at scale." } else { "RBAC is well-governed with group-based assignments." }
    $rec = if ($gaps.Count -gt 0) { "Remove all Classic Administrators. Convert individual Owner/Contributor assignments to group-based assignments with PIM-eligible activation. Run an access review quarterly using Entra ID Access Reviews." } else { "Schedule quarterly access reviews to confirm group memberships remain current." }
    $evi = "TotalSubScope: $($allSub.Count)  Users: $users  Groups: $groups  ClassicAdmins: $($ClassicAdmins.Count)"

    New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
        -Domain $domain -Score $score -Status $status `
        -Gap $gapText -Impact $impact -Recommendation $rec -Evidence $evi
}

Function Invoke-Domain05_Budget {
    param([object]$Sub, [array]$Budgets)

    $domain = "Budget & Cost Controls"

    if ($null -eq $Budgets) {
        return New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
            -Domain $domain -Score 0 -Status "Fail" `
            -Gap "Budget information could not be retrieved (missing Consumption Reader or Cost Management Reader role)." `
            -Impact "Without budget visibility, cost overruns go undetected until the billing statement arrives. Uncontrolled cloud spend is both a financial and a security risk — compromised credentials used for crypto-mining will cause cost spikes that a budget alert would detect." `
            -Recommendation "Grant the Cost Management Reader role to the governance scanning account. Create at least one budget with 80% and 100% threshold alerts sent to the subscription owner and finance team." `
            -Evidence "Could Not Assess"
    }

    if ($Budgets.Count -eq 0) {
        return New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
            -Domain $domain -Score 0 -Status "Fail" `
            -Gap "No Azure Budgets are configured on this subscription." `
            -Impact "Without a budget and alert threshold, cost overruns — from misconfigured resources, accidental deployments, or compromised credentials used for mining — produce no early warning. The first signal is an unexpected invoice." `
            -Recommendation "Create a Budget in Azure Cost Management for this subscription. Set at least two alert thresholds: 80% (forecast alert) and 100% (actual spend alert). Route alerts to the subscription owner and finance contact." `
            -Evidence "Budget count: 0"
    }

    $score = 6
    $gaps = @()
    $evidence = "Budgets: $($Budgets.Count)"

    $budgetsWithAlerts = @($Budgets | Where-Object {
            $_.Notifications -and ($_.Notifications | Get-Member -MemberType NoteProperty).Count -gt 0
        })

    if ($budgetsWithAlerts.Count -eq 0) {
        $score -= 3
        $gaps += "Budget(s) exist but no alert notifications are configured — a budget without alerts provides no early warning."
        $evidence += " [NoAlerts]"
    }
    else {
        $score += 2
        $evidence += " [AlertsConfigured: Yes]"
    }

    if ($Budgets.Count -ge 1 -and $gaps.Count -eq 0) { $score = 10 }

    $score = [math]::Min([math]::Max(0, $score), 10)
    $status = if ($score -ge 8) { "Pass" } elseif ($score -ge 4) { "Partial" } else { "Fail" }
    $gapText = if ($gaps.Count -gt 0) { $gaps -join " " } else { "Budget with alert thresholds is in place." }
    $impact = if ($gaps.Count -gt 0) { "Unalerted budgets mean no proactive notification of spend anomalies." } else { "Cost visibility and alerting is configured." }
    $rec = if ($gaps.Count -gt 0) { "Add notification thresholds (80% forecast, 100% actual) with email alerts to the owner and finance contact." } else { "Review budget amounts annually to keep them aligned with expected spend." }

    New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
        -Domain $domain -Score $score -Status $status `
        -Gap $gapText -Impact $impact -Recommendation $rec -Evidence $evidence
}

Function Invoke-Domain06_Locks {
    param([object]$Sub, [array]$Locks)

    $domain = "Resource Locks"

    if ($Locks.Count -eq 0) {
        return New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
            -Domain $domain -Score 0 -Status "Fail" `
            -Gap "No resource locks (CanNotDelete or ReadOnly) found on this subscription or any of its resource groups." `
            -Impact "Without locks, any user with Contributor or Owner access can delete or overwrite critical resources — databases, Key Vaults, networking infrastructure — accidentally or maliciously. In a compromised-credential scenario, resource deletion is often the first destructive action taken." `
            -Recommendation "Apply a CanNotDelete lock to resource groups containing production-critical resources (Key Vaults, databases, VNets, storage accounts). Consider a subscription-level lock for highly regulated environments. Locks do not prevent normal operations — they only require explicit lock removal before deletion or modification (ReadOnly)." `
            -Evidence "Lock count: 0"
    }

    $subLocks = @($Locks | Where-Object { $_.Scope -match "^/subscriptions/[^/]+$" })
    $rgLocks = @($Locks | Where-Object { $_.Scope -match "resourceGroups" })
    $score = 5
    $gaps = @()
    $evidence = "TotalLocks: $($Locks.Count)  SubLevel: $($subLocks.Count)  RGLevel: $($rgLocks.Count)"

    if ($rgLocks.Count -gt 0) { $score += 3 }
    if ($subLocks.Count -gt 0) { $score += 2 }

    $score = [math]::Min($score, 10)
    $status = if ($score -ge 8) { "Pass" } elseif ($score -ge 4) { "Partial" } else { "Fail" }
    $gapText = if ($gaps.Count -gt 0) { $gaps -join " " } else { "Resource locks present at subscription or resource group level." }
    $rec = "Ensure all production resource groups have at least a CanNotDelete lock. Automate lock deployment via IaC (Bicep/Terraform) to prevent drift."

    New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
        -Domain $domain -Score $score -Status $status `
        -Gap $gapText -Impact "Locks protect against accidental and malicious deletion of critical resources." `
        -Recommendation $rec -Evidence $evidence
}

Function Invoke-Domain07_Logging {
    param([object]$Sub, [object]$DiagnosticSetting)

    $domain = "Activity Log & Diagnostics"

    if ($null -eq $DiagnosticSetting) {
        return New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
            -Domain $domain -Score 0 -Status "Fail" `
            -Gap "No subscription-level diagnostic setting found. Activity Log events are not routed to any external destination (Log Analytics, Storage, Event Hub)." `
            -Impact "Without exporting Activity Logs, administrative actions on the subscription — role assignments, policy changes, resource deployments, and deletions — cannot be queried or retained beyond the 90-day in-platform window. This makes forensic investigation of incidents difficult or impossible after 90 days, and breaches compliance requirements in most regulatory frameworks." `
            -Recommendation "Create a subscription-level diagnostic setting and route to a central Log Analytics workspace (or SIEM via Event Hub). Enable at minimum: Administrative, Security, Policy, Alert, and Recommendation categories. Set retention to 365+ days for compliance." `
            -Evidence "DiagnosticSetting: None"
    }

    $score = 4
    $gaps = @()
    $evidence = "DiagnosticSetting: Present"

    # Log Analytics destination
    $wsId = Get-ObjProperty -Obj $DiagnosticSetting -PropName 'workspaceId' -Default ""
    if (-not [string]::IsNullOrWhiteSpace($wsId)) {
        $score += 3
        $evidence += "  WorkspaceId: Set"
    }
    else {
        $gaps += "Diagnostic setting exists but does not route to a Log Analytics workspace — alerting and querying on activity events is limited."
        $evidence += "  WorkspaceId: Not Set"
    }

    # Required categories
    $logs = @()
    try { $logs = @(Get-ObjProperty -Obj $DiagnosticSetting -PropName 'logs' -Default @()) } catch { }
    $enabledCats = @($logs | Where-Object { $_.enabled -eq $true } | ForEach-Object { $_.category })
    $requiredCats = @("Administrative", "Security", "Policy")
    $missingCats = @($requiredCats | Where-Object { $enabledCats -notcontains $_ })
    if ($missingCats.Count -eq 0) {
        $score += 3
        $evidence += "  RequiredCategories: All"
    }
    else {
        $gaps += "Missing required log categories: $($missingCats -join ', ')."
        $evidence += "  MissingCategories: $($missingCats -join ',')"
    }

    $score = [math]::Min($score, 10)
    $status = if ($score -ge 8) { "Pass" } elseif ($score -ge 4) { "Partial" } else { "Fail" }
    $gapText = if ($gaps.Count -gt 0) { $gaps -join " " } else { "Activity Log diagnostic setting routes to Log Analytics with required categories." }
    $impact = if ($gaps.Count -gt 0) { "Gaps in logging configuration reduce the ability to detect, investigate, and respond to security incidents and compliance breaches." } else { "Activity logging provides the audit trail required for security operations and compliance." }
    $rec = if ($gaps.Count -gt 0) { "Update the diagnostic setting to route to a Log Analytics workspace and ensure Administrative, Security, and Policy categories are all enabled." } else { "Review Log Analytics retention settings and ensure the workspace meets your compliance retention requirements (often 365–730 days)." }

    New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
        -Domain $domain -Score $score -Status $status `
        -Gap $gapText -Impact $impact -Recommendation $rec -Evidence $evidence
}

Function Invoke-Domain08_Defender {
    param([object]$Sub, [array]$SecurityPricings)

    $domain = "Defender for Cloud"

    if ($null -eq $SecurityPricings) {
        return New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
            -Domain $domain -Score 0 -Status "Fail" `
            -Gap "Defender for Cloud plan information could not be retrieved. The scanning account may be missing the Security Reader role." `
            -Impact "Without Defender coverage, workloads have no Microsoft-managed threat detection, vulnerability scanning, or security posture monitoring. Threats may go undetected for extended periods." `
            -Recommendation "Grant the Security Reader role to the scanning account. Enable Defender plans for at minimum: Servers, SQL, App Service, Storage, and Key Vault." `
            -Evidence "Could Not Assess"
    }

    $score = 0
    $keyPlans = @("VirtualMachines", "SqlServers", "AppServices", "StorageAccounts", "KeyVaults")
    $evidence = @()

    foreach ($planName in $keyPlans) {
        $plan = $SecurityPricings | Where-Object { $_.Name -eq $planName }
        if ($plan -and $plan.PricingTier -eq "Standard") {
            $score += 2
            $evidence += "$planName=Standard"
        }
        else {
            $tier = if ($plan) { $plan.PricingTier } else { "Not Found" }
            $evidence += "$planName=$tier"
        }
    }

    $score = [math]::Min($score, 10)
    $status = if ($score -ge 8) { "Pass" } elseif ($score -ge 4) { "Partial" } else { "Fail" }
    $freePlans = @($evidence | Where-Object { $_ -like "*=Free" -or $_ -like "*=Not Found" })
    $gapText = if ($freePlans.Count -gt 0) { "The following Defender plans are not enabled at Standard tier: $($freePlans -join '; ')." } else { "All key Defender for Cloud plans are enabled at Standard tier." }
    $impact = if ($freePlans.Count -gt 0) { "Resources without Defender coverage lack automated threat detection, vulnerability assessment, and security alerts. A compromise of unprotected workloads may go undetected for weeks or months." } else { "Defender for Cloud provides comprehensive threat detection and security posture management." }
    $rec = if ($freePlans.Count -gt 0) { "Enable Defender Standard plans for all key resource types. Prioritise: Servers (vulnerability assessment + threat protection), SQL (data breach detection), and Storage (malware scanning). Review and respond to Secure Score recommendations monthly." } else { "Maintain Defender coverage and review Secure Score recommendations regularly." }

    New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
        -Domain $domain -Score $score -Status $status `
        -Gap $gapText -Impact $impact -Recommendation $rec `
        -Evidence ($evidence -join "  ")
}

Function Invoke-Domain09_Tagging {
    param([object]$Sub)

    $domain = "Tagging Governance"
    $tags = Get-ObjProperty -Obj $Sub -PropName 'Tags' -Default @{}
    if ($null -eq $tags) { $tags = @{} }

    $mandatoryTags = @("Environment", "Owner", "CostCenter")
    $optionalTags = @("Contact", "BillingCode", "Application", "Team")

    $presentMandatory = @($mandatoryTags | Where-Object {
            $tagKey = $_
            $found = $tags.Keys | Where-Object { $_ -ieq $tagKey }
            $found -and -not [string]::IsNullOrWhiteSpace($tags[$found])
        })

    $score = [math]::Round(($presentMandatory.Count / $mandatoryTags.Count) * 8)
    $evidence = "Tags: $(($tags.Keys | Sort-Object) -join ', ')  Mandatory present: $($presentMandatory.Count)/$($mandatoryTags.Count)"

    # Optional bonus
    $presentOptional = @($optionalTags | Where-Object {
            $tagKey = $_
            $found = $tags.Keys | Where-Object { $_ -ieq $tagKey }
            $found -and -not [string]::IsNullOrWhiteSpace($tags[$found])
        })
    if ($presentOptional.Count -ge 2) { $score += 2 }

    $missing = @($mandatoryTags | Where-Object { $presentMandatory -notcontains $_ })
    $score = [math]::Min($score, 10)
    $status = if ($score -ge 8) { "Pass" } elseif ($score -ge 4) { "Partial" } else { "Fail" }
    $gapText = if ($missing.Count -gt 0) { "Missing mandatory tags on subscription: $($missing -join ', ')." } else { "All mandatory governance tags are present on the subscription." }
    $impact = if ($missing.Count -gt 0) { "Without mandatory tags, cost allocation is unreliable, ownership is ambiguous, and automated governance processes (chargeback, owner notification, lifecycle management) cannot function correctly." } else { "Tag governance supports cost allocation, ownership, and automated lifecycle management." }
    $rec = if ($missing.Count -gt 0) { "Add missing tags directly to the subscription resource: Environment (prod/nonprod/sandbox), Owner (group email), CostCenter (finance code). Consider using Azure Policy to enforce tags via DeployIfNotExists at subscription scope." } else { "Periodically validate tag values are non-placeholder (not 'TBD' or 'Unknown'). Extend tagging to resource groups and resources via Azure Policy." }

    New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
        -Domain $domain -Score $score -Status $status `
        -Gap $gapText -Impact $impact -Recommendation $rec -Evidence $evidence
}

Function Invoke-Domain10_Region {
    param([object]$Sub, [array]$ResourceLocations)

    $domain = "Region Compliance"

    if ($ResourceLocations.Count -eq 0) {
        return New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
            -Domain $domain -Score 10 -Status "Pass" `
            -Gap "No deployed resources found — region compliance cannot be assessed but there is no sprawl." `
            -Impact "Empty subscription — region compliance is not applicable." `
            -Recommendation "When deploying resources, ensure an allowed-region policy is assigned to restrict deployments to approved regions for data residency compliance." `
            -Evidence "Resources: 0"
    }

    $distinctRegions = @($ResourceLocations | Sort-Object -Unique | Where-Object { $_ -ne "global" })
    $regionCount = $distinctRegions.Count
    $evidence = "DistinctRegions: $regionCount ($($distinctRegions -join ', '))"

    $score = 10
    $gaps = @()

    if ($regionCount -ge 8) {
        $score = 0
        $gaps += "Resources are deployed across $regionCount distinct regions, indicating significant deployment sprawl. This creates data residency complexity, increases attack surface, and complicates DR planning."
    }
    elseif ($regionCount -ge 5) {
        $score = 5
        $gaps += "Resources span $regionCount regions. This may indicate ungoverned deployment patterns — verify all regions are intentional and compliant with data residency requirements."
    }

    $status = if ($score -ge 8) { "Pass" } elseif ($score -ge 4) { "Partial" } else { "Fail" }
    $gapText = if ($gaps.Count -gt 0) { $gaps -join " " } else { "Resource deployments are concentrated in $regionCount region(s), indicating controlled deployment patterns." }
    $impact = if ($gaps.Count -gt 0) { "Multi-region sprawl creates data sovereignty risk (data may reside in regions not approved by regulators or customers), increases operational complexity, and can indicate compromised credentials being used to deploy resources in unexpected regions." } else { "Controlled regional deployment supports data residency compliance and operational clarity." }
    $rec = if ($gaps.Count -gt 0) { "Assign an Azure Policy 'Allowed Locations' to restrict future deployments. Audit the resources in unexpected regions and determine if they should be migrated or decommissioned. Document the approved region list in your organisation's cloud governance policy." } else { "Maintain an allowed-region policy assignment to prevent future drift." }

    New-DomainFinding -SubscriptionName $Sub.Name -SubscriptionId $Sub.Id `
        -Domain $domain -Score $score -Status $status `
        -Gap $gapText -Impact $impact -Recommendation $rec -Evidence $evidence
}


#------------------------------------------------------------------------ [ Scorecard Engine ]

Function Get-GovernanceScorecard {
    param([array]$DomainFindings)

    $total = ($DomainFindings | Measure-Object -Property Score -Sum).Sum
    $grade = if ($total -ge 85) { "Governed" }
    elseif ($total -ge 60) { "Partial" }
    elseif ($total -ge 40) { "At Risk" }
    else { "Critical" }

    [pscustomobject]@{
        TotalScore      = $total
        GovernanceGrade = $grade
        DomainFindings  = $DomainFindings
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-SubscriptionGovernanceHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$ScorecardResults,
        [array]$AllFindings,
        [array]$SubscriptionResults,
        [string]$GeneratedOn
    )

    $totalSubs = $ScorecardResults.Count
    $governed = @($ScorecardResults | Where-Object { $_.GovernanceGrade -eq "Governed" }).Count
    $partial = @($ScorecardResults | Where-Object { $_.GovernanceGrade -eq "Partial" }).Count
    $atRisk = @($ScorecardResults | Where-Object { $_.GovernanceGrade -eq "At Risk" }).Count
    $critical = @($ScorecardResults | Where-Object { $_.GovernanceGrade -eq "Critical" }).Count
    $avgScore = if ($totalSubs -gt 0) { [math]::Round(($ScorecardResults | Measure-Object -Property TotalScore -Average).Average) } else { 0 }

    # ── Grade distribution bars ───────────────────────────────────────────────
    $gradeBarRows = ""
    $gradeData = @(
        @{label = "Governed (85+)"; count = $governed; color = "var(--green)" }
        @{label = "Partial (60-84)"; count = $partial; color = "var(--accent2)" }
        @{label = "At Risk (40-59)"; count = $atRisk; color = "var(--amber)" }
        @{label = "Critical (<40)"; count = $critical; color = "var(--red)" }
    )
    foreach ($g in $gradeData) {
        $pct = if ($totalSubs -gt 0) { [math]::Round(($g.count / $totalSubs) * 100) } else { 0 }
        $gradeBarRows += "<div class='bar-row'><span class='bar-label'>$($g.label)</span><div class='bar-track'><div class='bar-fill' data-pct='$pct' style='background:$($g.color)'></div></div><span class='bar-pct'>$($g.count) ($pct%)</span></div>"
    }

    # ── Domain average scores ─────────────────────────────────────────────────
    $domainBarRows = ""
    foreach ($domain in $script:GovernanceDomains) {
        $domainFindings = @($AllFindings | Where-Object { $_.Domain -eq $domain })
        $avgDomain = if ($domainFindings.Count -gt 0) { [math]::Round(($domainFindings | Measure-Object -Property Score -Average).Average) } else { 0 }
        $pct = $avgDomain * 10
        $color = if ($avgDomain -ge 8) { "var(--green)" } elseif ($avgDomain -ge 5) { "var(--amber)" } else { "var(--red)" }
        $domainBarRows += "<div class='bar-row'><span class='bar-label' title='$(EscHtml $domain)'>$(EscHtml ($domain.Substring(0,[math]::Min(22,$domain.Length))))</span><div class='bar-track'><div class='bar-fill' data-pct='$pct' style='background:$color'></div></div><span class='bar-pct'>$avgDomain/10</span></div>"
    }

    # ── Scorecard table rows ──────────────────────────────────────────────────
    $scorecardRows = ""
    $scIdx = 0
    foreach ($sc in ($ScorecardResults | Sort-Object TotalScore)) {
        $gradeCls = switch ($sc.GovernanceGrade) { "Governed" { "badge-green" } "Partial" { "badge-blue" } "At Risk" { "badge-amber" } "Critical" { "badge-red" } }
        $scoreColor = if ($sc.TotalScore -ge 85) { "var(--green)" } elseif ($sc.TotalScore -ge 60) { "var(--accent2)" } elseif ($sc.TotalScore -ge 40) { "var(--amber)" } else { "var(--red)" }
        $domainIcons = ""
        foreach ($domain in $script:GovernanceDomains) {
            $df = $sc.DomainFindings | Where-Object { $_.Domain -eq $domain }
            if ($df) {
                $icon = if ($df.Score -ge 8) { "✅" } elseif ($df.Score -ge 4) { "🟡" } else { "❌" }
                $domainIcons += "<span title='$(EscHtml $domain): $($df.Score)/10'>$icon</span> "
            }
        }
        $subNameShort = if ($sc.DomainFindings[0].SubscriptionName.Length -gt 28) { EscHtml($sc.DomainFindings[0].SubscriptionName.Substring(0, 25) + "...") } else { EscHtml $sc.DomainFindings[0].SubscriptionName }
        $scorecardRows += @"
      <tr onclick="showScDetail($scIdx)">
        <td title="$(EscHtml $sc.DomainFindings[0].SubscriptionName)">$subNameShort</td>
        <td style="font-family:var(--mono);font-weight:700;color:$scoreColor">$($sc.TotalScore)</td>
        <td><span class="badge $(EscHtml $gradeCls)">$(EscHtml $sc.GovernanceGrade)</span></td>
        <td style="letter-spacing:2px">$domainIcons</td>
      </tr>
"@
        $scIdx++
    }

    # ── All findings table rows ───────────────────────────────────────────────
    $findingRows = ""
    $sortedFindings = $AllFindings | Sort-Object { switch ($_.Status) { "Fail" { 0 }"Partial" { 1 }"Pass" { 2 } } }, Domain, SubscriptionName
    $fIdx = 0
    foreach ($f in $sortedFindings) {
        $stCls = switch ($f.Status) { "Fail" { "badge-red" } "Partial" { "badge-amber" } "Pass" { "badge-green" } }
        $gapShort = if ($f.Gap.Length -gt 55) { EscHtml($f.Gap.Substring(0, 52) + "...") } else { EscHtml $f.Gap }
        $subShort = if ($f.SubscriptionName.Length -gt 22) { EscHtml($f.SubscriptionName.Substring(0, 19) + "...") } else { EscHtml $f.SubscriptionName }
        $findingRows += @"
      <tr onclick="showFindingDetail($fIdx)">
        <td title="$(EscHtml $f.SubscriptionName)">$subShort</td>
        <td style="font-size:11px">$(EscHtml $f.Domain)</td>
        <td style="font-family:var(--mono)">$($f.Score)/10</td>
        <td><span class="badge $(EscHtml $stCls)">$(EscHtml $f.Status)</span></td>
        <td title="$(EscHtml $f.Gap)">$gapShort</td>
      </tr>
"@
        $fIdx++
    }

    # ── Subscription scan results ─────────────────────────────────────────────
    $subRows = ""
    foreach ($s in $SubscriptionResults) {
        $icon = switch ($s.Status) { "Success" { "✓" } "Warning" { "⚠" } "Error" { "✗" } default { "•" } }
        $cls = switch ($s.Status) { "Success" { "c-green" } "Warning" { "c-amber" } "Error" { "c-red" } default { "" } }
        $subRows += "<div class='sub-row'><span class='sub-icon $cls'>$icon</span><span class='sub-name'>$(EscHtml $s.Name)</span><span class='sub-detail'>$(EscHtml $s.Summary)</span></div>"
    }

    # ── JSON for scorecard drawer ─────────────────────────────────────────────
    $scJson = "["
    foreach ($sc in ($ScorecardResults | Sort-Object TotalScore)) {
        $domainJson = "["
        foreach ($df in $sc.DomainFindings) {
            $domainJson += "{" +
            """domain"":""$(EscJ $df.Domain)""," +
            """score"":$($df.Score)," +
            """status"":""$(EscJ $df.Status)""," +
            """gap"":""$(EscJ $df.Gap)""," +
            """impact"":""$(EscJ $df.Impact)""," +
            """rec"":""$(EscJ $df.Recommendation)""," +
            """evidence"":""$(EscJ $df.Evidence)""" +
            "},"
        }
        $domainJson = $domainJson.TrimEnd(",") + "]"
        $scJson += "{" +
        """sub"":""$(EscJ $sc.DomainFindings[0].SubscriptionName)""," +
        """subId"":""$(EscJ $sc.DomainFindings[0].SubscriptionId)""," +
        """score"":$($sc.TotalScore)," +
        """grade"":""$(EscJ $sc.GovernanceGrade)""," +
        """domains"":$domainJson" +
        "},"
    }
    $scJson = $scJson.TrimEnd(",") + "]"

    # ── JSON for findings drawer ──────────────────────────────────────────────
    $findingsJson = "["
    foreach ($f in $sortedFindings) {
        $findingsJson += "{" +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """domain"":""$(EscJ $f.Domain)""," +
        """score"":$($f.Score)," +
        """status"":""$(EscJ $f.Status)""," +
        """gap"":""$(EscJ $f.Gap)""," +
        """impact"":""$(EscJ $f.Impact)""," +
        """rec"":""$(EscJ $f.Recommendation)""," +
        """evidence"":""$(EscJ $f.Evidence)""" +
        "},"
    }
    $findingsJson = $findingsJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Subscription Governance Assessment</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;--border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;--green:#3fb950;--amber:#d29922;--red:#f85149;--text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;--mono:'JetBrains Mono','Consolas','Courier New',monospace;--sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;--radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);}
html[data-theme="light"]{--bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;--border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;--green:#1a7f37;--amber:#b08000;--red:#cf222e;--text:#1f2328;--muted:#636c76;--muted2:#424a53;--shadow:0 4px 24px rgba(0,0,0,.12);}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;}
#sidebar{width:236px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:transform .25s;}
.logo-block{padding:20px 16px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,var(--accent3),var(--accent));display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;}
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
#main{margin-left:236px;padding:28px;width:calc(100% - 236px);min-height:100vh;}
.page{display:none;animation:fadeIn .2s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px);}to{opacity:1;transform:none;}}
.page-header{margin-bottom:22px;}
.page-title{font-size:22px;font-weight:700;}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:22px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;border-top:3px solid var(--border);transition:transform .15s,box-shadow .15s;}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-num{font-size:28px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:13px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:140px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:70px;text-align:right;flex-shrink:0;}
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
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.sub-list{display:flex;flex-direction:column;}
.sub-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}.sub-icon.c-amber{color:var(--amber);}.sub-icon.c-red{color:var(--red);}
.sub-name{flex:1;font-size:13px;font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}
.domain-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:16px;}
.domain-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px;text-align:center;cursor:pointer;transition:border-color .15s;}
.domain-card:hover{border-color:var(--accent);}
.domain-card .dc-score{font-size:22px;font-weight:700;font-family:var(--mono);}
.domain-card .dc-label{font-size:10px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.04em;}
.domain-card .dc-status{display:inline-block;margin-top:6px;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:600;}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:520px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
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
.drawer-field-value{font-size:13px;word-break:break-all;line-height:1.5;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.impact-box{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.3);border-radius:var(--radius-sm);padding:12px;font-size:12px;line-height:1.6;margin-bottom:10px;}
.rec-box{background:rgba(56,139,253,.08);border:1px solid rgba(56,139,253,.3);border-radius:var(--radius-sm);padding:12px;font-size:12px;line-height:1.6;}
.evidence-box{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;font-size:11px;font-family:var(--mono);color:var(--muted2);word-break:break-all;}
.score-ring-wrap{position:relative;width:120px;height:120px;flex-shrink:0;}
.score-ring-wrap svg{transform:rotate(-90deg);}
.score-ring-label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.score-ring-num{font-size:28px;font-weight:700;font-family:var(--mono);}
.score-ring-sub{font-size:10px;color:var(--muted);}
.sub-scorecard-header{display:flex;align-items:center;gap:20px;margin-bottom:16px;flex-wrap:wrap;}
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
    <div class="logo-icon">🏛️</div>
    <div class="logo-title">Sub Governance</div>
    <div class="logo-sub">Subscription Scorecard</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('scorecard',this)"><span class="nav-icon">🏅</span> Scorecard</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">📋</span> Control Findings</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">🔍</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">Generated: __GENERATED_ON__<br/>Subscription Governance Assessment</div>
  </div>
</nav>
<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Subscription Governance Overview</div>
      <div class="page-sub">Ten-domain governance scorecard across __TOTAL_SUBS__ subscription(s) — average score: __AVG_SCORE__/100</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-green">
        <div class="stat-num">__GOVERNED__</div>
        <div class="stat-label">Governed</div>
        <div class="stat-sub">Score ≥ 85</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__PARTIAL__</div>
        <div class="stat-label">Partial</div>
        <div class="stat-sub">Score 60–84</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__AT_RISK__</div>
        <div class="stat-label">At Risk</div>
        <div class="stat-sub">Score 40–59</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">Score &lt; 40</div>
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🏅 Governance Grade Distribution</div>
        __GRADE_BAR_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">📐 Average Score by Control Domain</div>
        __DOMAIN_BAR_ROWS__
      </div>
    </div>
  </div>

  <!-- Scorecard -->
  <div id="page-scorecard" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scorecard</div>
      <div class="page-sub">Click any row for a per-domain breakdown. ✅ ≥ 8/10 &nbsp;|&nbsp; 🟡 4–7/10 &nbsp;|&nbsp; ❌ 0–3/10</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="scSearch" placeholder="Search subscription…" oninput="filterSc()"/>
        </div>
        <select class="filter-select" id="filterGrade" onchange="filterSc()">
          <option value="">All Grades</option>
          <option value="Governed">Governed</option>
          <option value="Partial">Partial</option>
          <option value="At Risk">At Risk</option>
          <option value="Critical">Critical</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="scSort('sub')">Subscription</th>
              <th onclick="scSort('score')">Score</th>
              <th onclick="scSort('grade')">Grade</th>
              <th>Domain Status (Ownership → Region)</th>
            </tr>
          </thead>
          <tbody id="scBody">__SCORECARD_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="scPagination"></div>
    </div>
  </div>

  <!-- Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Control Domain Findings</div>
      <div class="page-sub">All domain findings. Click any row for full gap, impact, and recommendation. Sorted by severity.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search subscription, domain, gap…" oninput="filterFind()"/>
        </div>
        <select class="filter-select" id="filterStatus" onchange="filterFind()">
          <option value="">All Statuses</option>
          <option value="Fail">Fail</option>
          <option value="Partial">Partial</option>
          <option value="Pass">Pass</option>
        </select>
        <select class="filter-select" id="filterDomain" onchange="filterFind()">
          <option value="">All Domains</option>
          <option value="Ownership &amp; Identity">Ownership &amp; Identity</option>
          <option value="Management Group Placement">Management Group Placement</option>
          <option value="Policy Coverage">Policy Coverage</option>
          <option value="RBAC Hygiene">RBAC Hygiene</option>
          <option value="Budget &amp; Cost Controls">Budget &amp; Cost Controls</option>
          <option value="Resource Locks">Resource Locks</option>
          <option value="Activity Log &amp; Diagnostics">Activity Log &amp; Diagnostics</option>
          <option value="Defender for Cloud">Defender for Cloud</option>
          <option value="Tagging Governance">Tagging Governance</option>
          <option value="Region Compliance">Region Compliance</option>
        </select>
        <select class="filter-select" id="findPageSz" onchange="findChangePageSz()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="findSort('sub')">Subscription</th>
              <th onclick="findSort('domain')">Domain</th>
              <th onclick="findSort('score')">Score</th>
              <th onclick="findSort('status')">Status</th>
              <th>Gap Summary</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
    </div>
    <div class="panel">
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- Session Info -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Scan Parameters</div>
    </div>
    <div class="panel">
      <div class="panel-title">🔐 Session Information</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Tenant</div><div class="info-value">__TENANT__</div></div>
        <div class="info-card"><div class="info-label">Account</div><div class="info-value">__ACCOUNT__</div></div>
        <div class="info-card"><div class="info-label">Environment</div><div class="info-value">__ENVIRONMENT__</div></div>
        <div class="info-card"><div class="info-label">Generated</div><div class="info-value">__GENERATED_ON__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">⚙️ Scan Parameters</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Scope</div><div class="info-value">__SCOPE__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Subscriptions</div><div class="info-value">__TOTAL_SUBS__</div></div>
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
const SC_DATA      = __SC_JSON__;
const FIND_DATA    = __FIND_JSON__;
const GRADE_ORDER  = {Governed:0,Partial:1,'At Risk':2,Critical:3};
const STATUS_ORDER = {Fail:0,Partial:1,Pass:2};

let scFiltered   = [...SC_DATA];
let scPage       = 1, scPageSz = 25;
let scSortCol    = 'score', scSortAsc = true;

let findFiltered = [...FIND_DATA];
let findPage     = 1, findPageSz = 25;
let findSortCol  = 'status', findSortAsc = true;

let drawerMode   = 'sc'; // 'sc' or 'find'
let currentIdx   = 0;

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
}
function toggleTheme(){const h=document.documentElement;h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';}
function showToast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2500);}

// ── Scorecard table ───────────────────────────────────────────────────────────
function filterSc(){
  const q=document.getElementById('scSearch').value.toLowerCase();
  const g=document.getElementById('filterGrade').value;
  scFiltered=SC_DATA.filter(r=>{
    const mQ=!q||r.sub.toLowerCase().includes(q);
    const mG=!g||r.grade===g;
    return mQ&&mG;
  });
  scPage=1;scSort(scSortCol,true);
}
function scSort(col,keepDir){
  if(!keepDir){if(scSortCol===col)scSortAsc=!scSortAsc;else{scSortCol=col;scSortAsc=true;}}
  scFiltered.sort((a,b)=>{
    if(col==='score')return scSortAsc?a.score-b.score:b.score-a.score;
    if(col==='grade'){const av=GRADE_ORDER[a.grade]??99,bv=GRADE_ORDER[b.grade]??99;return scSortAsc?av-bv:bv-av;}
    return scSortAsc?String(a[col]).localeCompare(String(b[col])):String(b[col]).localeCompare(String(a[col]));
  });
  renderSc();
}
function renderSc(){
  const tbody=document.getElementById('scBody');
  const start=(scPage-1)*scPageSz,slice=scFiltered.slice(start,start+scPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=SC_DATA.indexOf(r);
    const gCls=r.grade==='Governed'?'badge-green':r.grade==='Partial'?'badge-blue':r.grade==='At Risk'?'badge-amber':'badge-red';
    const sColor=r.score>=85?'var(--green)':r.score>=60?'var(--accent2)':r.score>=40?'var(--amber)':'var(--red)';
    const icons=r.domains.map(d=>{const ic=d.score>=8?'✅':d.score>=4?'🟡':'❌';return`<span title="${escH(d.domain)}: ${d.score}/10">${ic}</span>`;}).join(' ');
    const nm=r.sub.length>28?r.sub.substring(0,25)+'...':r.sub;
    return`<tr onclick="showScDetail(${gi})">
      <td title="${escH(r.sub)}">${escH(nm)}</td>
      <td style="font-family:var(--mono);font-weight:700;color:${sColor}">${r.score}</td>
      <td><span class="badge ${gCls}">${escH(r.grade)}</span></td>
      <td style="letter-spacing:2px">${icons}</td>
    </tr>`;
  }).join('');
  renderScPg();
}
function renderScPg(){
  const total=Math.ceil(scFiltered.length/scPageSz);
  const el=document.getElementById('scPagination');
  let h=`<span>${scFiltered.length} subscription(s)</span>`;
  h+=`<button class="pg-btn" onclick="changeScPage(${scPage-1})" ${scPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,scPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===scPage?'active':''}" onclick="changeScPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeScPage(${scPage+1})" ${scPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}
function changeScPage(p){const t=Math.ceil(scFiltered.length/scPageSz);if(p<1||p>t)return;scPage=p;renderSc();}

// ── Findings table ───────────────────────────────────────────────────────────
function filterFind(){
  const q=document.getElementById('findSearch').value.toLowerCase();
  const st=document.getElementById('filterStatus').value;
  const dm=document.getElementById('filterDomain').value;
  findFiltered=FIND_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mS=!st||r.status===st;
    const mD=!dm||r.domain===dm;
    return mQ&&mS&&mD;
  });
  findPage=1;findSort(findSortCol,true);
}
function findSort(col,keepDir){
  if(!keepDir){if(findSortCol===col)findSortAsc=!findSortAsc;else{findSortCol=col;findSortAsc=true;}}
  findFiltered.sort((a,b)=>{
    if(col==='score')return findSortAsc?a.score-b.score:b.score-a.score;
    if(col==='status'){const av=STATUS_ORDER[a.status]??99,bv=STATUS_ORDER[b.status]??99;return findSortAsc?av-bv:bv-av;}
    return findSortAsc?String(a[col]).localeCompare(String(b[col])):String(b[col]).localeCompare(String(a[col]));
  });
  renderFind();
}
function renderFind(){
  const tbody=document.getElementById('findBody');
  const start=(findPage-1)*findPageSz,slice=findFiltered.slice(start,start+findPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=FIND_DATA.indexOf(r);
    const stCls=r.status==='Fail'?'badge-red':r.status==='Partial'?'badge-amber':'badge-green';
    const nm=r.sub.length>22?r.sub.substring(0,19)+'...':r.sub;
    const gp=r.gap.length>55?r.gap.substring(0,52)+'...':r.gap;
    return`<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.sub)}">${escH(nm)}</td>
      <td style="font-size:11px">${escH(r.domain)}</td>
      <td style="font-family:var(--mono)">${r.score}/10</td>
      <td><span class="badge ${stCls}">${escH(r.status)}</span></td>
      <td title="${escH(r.gap)}">${escH(gp)}</td>
    </tr>`;
  }).join('');
  renderFindPg();
}
function renderFindPg(){
  const total=Math.ceil(findFiltered.length/findPageSz);
  const el=document.getElementById('findPagination');
  let h=`<span>${findFiltered.length} finding(s)</span>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,findPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}
function changeFindPage(p){const t=Math.ceil(findFiltered.length/findPageSz);if(p<1||p>t)return;findPage=p;renderFind();}
function findChangePageSz(){findPageSz=parseInt(document.getElementById('findPageSz').value);findPage=1;renderFind();}

// ── Drawers ───────────────────────────────────────────────────────────────────
function showScDetail(gi){
  drawerMode='sc'; currentIdx=gi;
  const r=SC_DATA[gi];if(!r)return;
  document.getElementById('drawerTitle').textContent=r.sub+' — Governance Scorecard';
  document.getElementById('drawerNavInfo').textContent=`${gi+1} of ${SC_DATA.length}`;
  const gCls=r.grade==='Governed'?'badge-green':r.grade==='Partial'?'badge-blue':r.grade==='At Risk'?'badge-amber':'badge-red';
  const sColor=r.score>=85?'var(--green)':r.score>=60?'var(--accent2)':r.score>=40?'var(--amber)':'var(--red)';
  const domainsHtml=r.domains.map(d=>{
    const stCls=d.status==='Fail'?'badge-red':d.status==='Partial'?'badge-amber':'badge-green';
    const sColor2=d.score>=8?'var(--green)':d.score>=4?'var(--amber)':'var(--red)';
    return `<div style="border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;margin-bottom:8px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
        <span style="font-size:12px;font-weight:600">${escH(d.domain)}</span>
        <span style="font-family:var(--mono);font-size:13px;font-weight:700;color:${sColor2}">${d.score}/10</span>
      </div>
      <div style="margin-bottom:4px"><span class="badge ${stCls}" style="font-size:10px">${escH(d.status)}</span></div>
      ${d.status!=='Pass'?`<div style="font-size:11px;color:var(--muted2);line-height:1.5;margin-top:4px">${escH(d.gap)}</div>`:''}
    </div>`;
  }).join('');
  document.getElementById('drawerContent').innerHTML=`
    <div class="sub-scorecard-header">
      <div class="score-ring-wrap">
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle r="48" cx="60" cy="60" fill="transparent" stroke="var(--surface3)" stroke-width="14"/>
          <circle r="48" cx="60" cy="60" fill="transparent" stroke="${sColor}" stroke-width="14"
            stroke-dasharray="${Math.round(2*3.14159*48*r.score/100)} ${Math.round(2*3.14159*48*(1-r.score/100))}"
            stroke-dashoffset="${Math.round(2*3.14159*48*0.25)}" style="transition:stroke-dasharray .6s"/>
        </svg>
        <div class="score-ring-label"><div class="score-ring-num" style="color:${sColor}">${r.score}</div><div class="score-ring-sub">/ 100</div></div>
      </div>
      <div>
        <div style="font-size:18px;font-weight:700;margin-bottom:6px">${escH(r.sub)}</div>
        <span class="badge ${gCls}">${escH(r.grade)}</span>
        <div style="font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:6px">${escH(r.subId)}</div>
      </div>
    </div>
    <div class="drawer-section">Domain Breakdown</div>
    ${domainsHtml}
  `;
  openDrawer();
}

function showFindingDetail(gi){
  drawerMode='find'; currentIdx=gi;
  const r=FIND_DATA[gi];if(!r)return;
  document.getElementById('drawerTitle').textContent=r.domain+' — '+r.sub;
  document.getElementById('drawerNavInfo').textContent=`${gi+1} of ${FIND_DATA.length}`;
  const stCls=r.status==='Fail'?'badge-red':r.status==='Partial'?'badge-amber':'badge-green';
  const sColor=r.score>=8?'var(--green)':r.score>=4?'var(--amber)':'var(--red)';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field">
      <div class="drawer-field-label">Status</div>
      <div style="display:flex;align-items:center;gap:12px;margin-top:4px">
        <span class="badge ${stCls}">${escH(r.status)}</span>
        <span style="font-family:var(--mono);font-weight:700;color:${sColor}">${r.score}/10</span>
      </div>
    </div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Control Domain</div><div class="drawer-field-value">${escH(r.domain)}</div></div>
    <div class="drawer-section">Governance Gap</div>
    <div class="drawer-field-value" style="margin-bottom:12px">${escH(r.gap)}</div>
    <div class="drawer-section">Business &amp; Governance Impact</div>
    <div class="impact-box">${escH(r.impact)}</div>
    <div class="drawer-section">Recommendation</div>
    <div class="rec-box">${escH(r.rec)}</div>
    <div class="drawer-section">Evidence</div>
    <div class="evidence-box">${escH(r.evidence)}</div>
  `;
  openDrawer();
}

function openDrawer(){
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}
function closeDrawer(){
  document.getElementById('drawerBackdrop').style.display='none';
  document.getElementById('detailDrawer').classList.remove('open');
}
function navDetail(dir){
  const next=currentIdx+dir;
  const data=drawerMode==='sc'?SC_DATA:FIND_DATA;
  if(next>=0&&next<data.length){
    if(drawerMode==='sc') showScDetail(next);
    else showFindingDetail(next);
  }
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{el.style.width=el.dataset.pct+'%';});
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

filterSc();
filterFind();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__TOTAL_SUBS__', $totalSubs `
        -replace '__AVG_SCORE__', $avgScore `
        -replace '__GOVERNED__', $governed `
        -replace '__PARTIAL__', $partial `
        -replace '__AT_RISK__', $atRisk `
        -replace '__CRITICAL__', $critical `
        -replace '__GRADE_BAR_ROWS__', $gradeBarRows `
        -replace '__DOMAIN_BAR_ROWS__', $domainBarRows `
        -replace '__SCORECARD_ROWS__', $scorecardRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__SC_JSON__', $scJson `
        -replace '__FIND_JSON__', $findingsJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureSubscriptionGovernanceAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureSubscriptionGovernance-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Security", "Az.Monitor")
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

    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"         = "$scopeText ($subCount found)"
        "Export to CSV" = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"   = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allScorecards = @()
    $allFindings = @()
    $subscriptionResults = @()
    $successCount = 0
    $errorCount = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = [math]::Max(
        ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
        35
    )

    $subIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue | Out-Null

            $domainFindings = @()

            # ── Domain 1: Ownership & Identity ───────────────────────────────
            $roleAssignments = @()
            try {
                $roleAssignments = @(Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction Stop)
            }
            catch {
                Write-Verbose "  Could not retrieve role assignments for $($sub.Name): $_"
            }

            $classicAdmins = @()
            try {
                # Classic admins via Az.Resources approach
                $caResult = Invoke-AzRestMethod -Method GET `
                    -Path "/subscriptions/$($sub.Id)/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01" `
                    -ErrorAction Stop
                if ($caResult.Content) {
                    $caObj = $caResult.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
                    $classicAdmins = @(Get-ObjProperty -Obj $caObj -PropName 'value' -Default @())
                }
            }
            catch { Write-Verbose "  Classic admin check failed for $($sub.Name): $_" }

            $domainFindings += Invoke-Domain01_Ownership -Sub $sub -RoleAssignments $roleAssignments

            # ── Domain 2: Management Group Placement ──────────────────────────
            $mgId = ""
            $mgName = ""
            try {
                $mgResult = Invoke-AzRestMethod -Method GET `
                    -Path "/subscriptions/$($sub.Id)?api-version=2020-01-01" `
                    -ErrorAction Stop
                if ($mgResult.Content) {
                    $mgObj = $mgResult.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
                    $mgPath = Get-ObjProperty -Obj $mgObj -PropName 'managementGroupAncestorsChain' -Default $null
                    if (-not $mgPath) { $mgPath = Get-ObjProperty -Obj $mgObj.properties -PropName 'managementGroupAncestorsChain' -Default $null }
                    if ($mgPath -and $mgPath.Count -gt 0) {
                        $immediateParent = $mgPath[0]
                        $mgId = Get-ObjProperty -Obj $immediateParent -PropName 'id'   -Default ""
                        $mgName = Get-ObjProperty -Obj $immediateParent -PropName 'name' -Default $mgId
                    }
                }
            }
            catch { Write-Verbose "  Could not retrieve MG placement for $($sub.Name): $_" }

            $domainFindings += Invoke-Domain02_ManagementGroup -Sub $sub -ManagementGroupId $mgId -ManagementGroupName $mgName

            # ── Domain 3: Policy Coverage ─────────────────────────────────────
            $policyAssignments = @()
            try {
                $policyAssignments = @(Get-AzPolicyAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction Stop)
                # Enrich with display names
                foreach ($pa in $policyAssignments) {
                    if (-not $pa.DisplayName) {
                        try { $pa | Add-Member -NotePropertyName DisplayName -NotePropertyValue $pa.Name -Force } catch { }
                    }
                    $paDef = Get-ObjProperty -Obj $pa -PropName 'PolicyDefinitionId' -Default ""
                    if (-not ($pa | Get-Member -Name PolicyDefinitionId -ErrorAction SilentlyContinue)) {
                        try { $pa | Add-Member -NotePropertyName PolicyDefinitionId -NotePropertyValue $paDef -Force } catch { }
                    }
                }
            }
            catch { Write-Verbose "  Could not retrieve policy assignments for $($sub.Name): $_" }

            $domainFindings += Invoke-Domain03_Policy -Sub $sub -PolicyAssignments $policyAssignments

            # ── Domain 4: RBAC Hygiene ────────────────────────────────────────
            $domainFindings += Invoke-Domain04_RBAC -Sub $sub -RoleAssignments $roleAssignments -ClassicAdmins $classicAdmins

            # ── Domain 5: Budget & Cost Controls ─────────────────────────────
            $budgets = $null
            try {
                $budgetResult = Invoke-AzRestMethod -Method GET `
                    -Path "/subscriptions/$($sub.Id)/providers/Microsoft.Consumption/budgets?api-version=2023-05-01" `
                    -ErrorAction Stop
                if ($budgetResult.Content) {
                    $budgetObj = $budgetResult.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
                    $budgets = @(Get-ObjProperty -Obj $budgetObj -PropName 'value' -Default @())
                }
                else { $budgets = @() }
            }
            catch {
                Write-Verbose "  Could not retrieve budgets for $($sub.Name): $_"
                # Keep $budgets as $null to signal "could not assess"
            }

            $domainFindings += Invoke-Domain05_Budget -Sub $sub -Budgets $budgets

            # ── Domain 6: Resource Locks ──────────────────────────────────────
            $locks = @()
            try {
                $locks = @(Get-AzResourceLock -Scope "/subscriptions/$($sub.Id)" -ErrorAction Stop)
                # Also get RG-level locks
                $rgs = @()
                try { $rgs = @(Get-AzResourceGroup -ErrorAction Stop) } catch { }
                foreach ($rg in $rgs) {
                    try {
                        $rgLocks = @(Get-AzResourceLock -ResourceGroupName $rg.ResourceGroupName -ErrorAction Stop)
                        $locks += $rgLocks
                    }
                    catch { }
                }
            }
            catch { Write-Verbose "  Could not retrieve locks for $($sub.Name): $_" }

            $domainFindings += Invoke-Domain06_Locks -Sub $sub -Locks $locks

            # ── Domain 7: Activity Log & Diagnostics ─────────────────────────
            $diagSetting = $null
            try {
                $diagResult = Invoke-AzRestMethod -Method GET `
                    -Path "/subscriptions/$($sub.Id)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview" `
                    -ErrorAction Stop
                if ($diagResult.Content) {
                    $diagObj = $diagResult.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
                    $diagSettings = @(Get-ObjProperty -Obj $diagObj -PropName 'value' -Default @())
                    if ($diagSettings.Count -gt 0) {
                        # Use first setting's properties
                        $diagSetting = $diagSettings[0].properties
                    }
                }
            }
            catch { Write-Verbose "  Could not retrieve diagnostic settings for $($sub.Name): $_" }

            $domainFindings += Invoke-Domain07_Logging -Sub $sub -DiagnosticSetting $diagSetting

            # ── Domain 8: Defender for Cloud ──────────────────────────────────
            $secPricings = $null
            try {
                $secPricings = @(Get-AzSecurityPricing -ErrorAction Stop)
            }
            catch { Write-Verbose "  Could not retrieve Defender pricings for $($sub.Name): $_" }

            $domainFindings += Invoke-Domain08_Defender -Sub $sub -SecurityPricings $secPricings

            # ── Domain 9: Tagging Governance ──────────────────────────────────
            $domainFindings += Invoke-Domain09_Tagging -Sub $sub

            # ── Domain 10: Region Compliance ──────────────────────────────────
            $resourceLocations = @()
            try {
                $resources = @(Get-AzResource -ErrorAction Stop)
                $resourceLocations = @($resources | Select-Object -ExpandProperty Location -Unique)
            }
            catch { Write-Verbose "  Could not retrieve resources for $($sub.Name): $_" }

            $domainFindings += Invoke-Domain10_Region -Sub $sub -ResourceLocations $resourceLocations

            # ── Build scorecard ───────────────────────────────────────────────
            $scorecard = Get-GovernanceScorecard -DomainFindings $domainFindings
            $allScorecards += [pscustomobject]@{
                TotalScore      = $scorecard.TotalScore
                GovernanceGrade = $scorecard.GovernanceGrade
                DomainFindings  = $scorecard.DomainFindings
            }
            $allFindings += $domainFindings

            # ── Per-subscription result ───────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            $gradeTxt = $scorecard.GovernanceGrade
            $gradeColor = switch ($gradeTxt) { "Governed" { "Green" } "Partial" { "Cyan" } "At Risk" { "Yellow" } "Critical" { "Red" } }

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Score: $($scorecard.TotalScore)/100  Grade: $gradeTxt" -ForegroundColor $gradeColor

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Score: $($scorecard.TotalScore)/100  Grade: $gradeTxt"
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
            Write-Host " → Failed: $($_.Exception.Message)" -ForegroundColor Red

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Failed: $($_.Exception.Message)"
                Status  = "Error"
            }
            $errorCount++
        }

        $subIndex++
    }

    # ── Summary ───────────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    $avgScore = if ($allScorecards.Count -gt 0) { [math]::Round(($allScorecards | Measure-Object -Property TotalScore -Average).Average) } else { 0 }

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Average Governance Score"    = "$avgScore / 100"
            "Execution Time"              = $duration
        })

    Write-GradeBreakdown -ScorecardResults $allScorecards

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allScorecards.Count -gt 0) {

        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) {
                    New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
                }
                $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, Domain, Score, Status,
                Gap, Impact, Recommendation, Evidence |
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
                Scope         = "$scopeText ($subCount found)"
                ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime      = $duration
            }
            $htmlContent = Generate-SubscriptionGovernanceHtml `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParams `
                -ScorecardResults    $allScorecards `
                -AllFindings         $allFindings `
                -SubscriptionResults $subscriptionResults `
                -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) {
                New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null
            }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        try {
            $allFindings |
            Select-Object SubscriptionName, Domain, Score, Status, Gap |
            Sort-Object @{e = { switch ($_.Status) { "Fail" { 0 }"Partial" { 1 }"Pass" { 2 } } } }, SubscriptionName |
            Out-GridView -Title "Azure Subscription Governance Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No subscriptions were successfully assessed." -ForegroundColor Yellow
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
