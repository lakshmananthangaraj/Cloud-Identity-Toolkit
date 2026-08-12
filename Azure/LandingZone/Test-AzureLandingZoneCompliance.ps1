<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 12 August 2026
Modified-On     : 12 August 2026

.SYNOPSIS
    Validates Azure subscriptions against enterprise Landing Zone requirements across
    Management Groups, RBAC, Azure Policy, networking, logging, Defender for Cloud,
    tagging, and diagnostics — aligned to CAF, WAF, NIST CSF, and CIS Benchmarks.

.DESCRIPTION
    Test-AzureLandingZoneCompliance performs a structured compliance assessment of one
    or more Azure subscriptions against enterprise Landing Zone standards.

    Assessment domains covered:
        - Management Groups     : Hierarchy depth, CAF naming, subscription placement
        - RBAC                  : Owner count, custom role hygiene, PIM awareness
        - Azure Policy          : Initiative assignment, compliance state, exemption review
        - Networking            : VNet peering/VWAN, NSG flow logs, DDoS protection, UDR
        - Logging               : Diagnostic settings, Activity Log, Log Analytics workspace
        - Defender for Cloud    : Plan enablement (all plans), security score, auto-provisioning
        - Tagging               : Required tag presence on subscriptions and resource groups
        - Diagnostics           : Key resource diagnostic settings (KeyVault, Storage, etc.)

    Each finding is severity-rated (Critical / High / Medium / Low), mapped to a
    framework reference (CAF / WAF / NIST CSF / CIS Benchmark), and carries an
    evidence value and a remediation recommendation.

    Output options:
        - Always-on HTML report  : Full dashboard with dark/light toggle, stat cards,
                                   filterable findings table, and per-domain charts.
        - Optional CSV export    : Flat finding rows for SIEM ingestion or tracking.
        - Interactive Grid View  : For ad-hoc review (GUI sessions only).

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to assess.
    Ignored if -AllSubscriptions is also specified.

.PARAMETER RequiredTags
    String array of mandatory tag keys to validate on subscriptions and resource groups.
    Defaults to CAF standard tags: Environment, Owner, CostCenter, Application, CreatedBy.

.PARAMETER ExportToCsv
    Switch. Exports all findings to the path specified by -CsvPath.

.PARAMETER CsvPath
    File path for the CSV export and the HTML report (HTML shares the same base name
    with a .html extension).
    Default: C:\Temp\LandingZoneCompliance-Report.csv

.PARAMETER IncludeDomains
    String array limiting the assessment to specific domains. Valid values:
    ManagementGroups, RBAC, Policy, Networking, Logging, Defender, Tagging, Diagnostics.
    Default: all domains assessed.

.INPUTS
    None. Parameters only.

.OUTPUTS
    Always writes an HTML dashboard report. Optionally writes a CSV file.
    Displays results in an interactive Grid View window where a GUI is available.

.EXAMPLE
    Test-AzureLandingZoneCompliance -AllSubscriptions

.EXAMPLE
    Test-AzureLandingZoneCompliance -SubscriptionIds @("sub-id-1","sub-id-2") -ExportToCsv

.EXAMPLE
    Test-AzureLandingZoneCompliance -AllSubscriptions -RequiredTags @("Owner","CostCenter","Environment") -ExportToCsv -CsvPath "C:\Reports\LZ-Compliance.csv"

.EXAMPLE
    Test-AzureLandingZoneCompliance -AllSubscriptions -IncludeDomains @("RBAC","Policy","Defender")

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (12-Aug-2026) - Initial release. Full Landing Zone compliance assessment
                        across 8 domains; CAF, WAF, NIST CSF, CIS alignment;
                        HTML dashboard + CSV output.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts, Az.Resources, Az.Security, Az.Network, Az.Monitor,
       Az.PolicyInsights modules (installed automatically on consent if missing).
    2. Authenticated Azure session with Reader role at subscription level minimum.
    3. Microsoft.Authorization/roleAssignments/read and
       Microsoft.PolicyInsights/policyStates/read at subscription scope.
    4. Management Group Reader role for -ManagementGroups domain checks.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - PIM (Privileged Identity Management) active assignment detection requires
      Microsoft Graph; this version checks standard role assignments only.
    - Policy compliance state reflects the last evaluation cycle, not real-time.
    - Interactive Grid View requires a GUI-capable session; skipped gracefully
      in headless/CI environments.
    - Default -CsvPath is Windows-specific. Supply an explicit path on macOS/Linux.
    - VWAN hub checks require the Az.Network module v5.0+.

.LINK
    https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/
.LINK
    https://learn.microsoft.com/en-us/azure/architecture/framework/
.LINK
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit

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

Function Write-LZBanner {
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Landing Zone Compliance Validator v1.0" -Color White
    Write-CenteredText "CAF | WAF | NIST CSF | CIS Benchmarks" -Color DarkCyan
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-LZSection {
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

Function Write-LZProgressBar {
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
        $displayItem = if ($CurrentItem.Length -gt $maxLength) { $CurrentItem.Substring(0, $maxLength - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-DomainHeader {
    param([string]$Domain)
    Write-Host ""
    Write-Host "  ► Assessing: $Domain" -ForegroundColor Yellow
}

Function Write-LZSummary {
    param([hashtable]$Data)
    Write-Host ""
    Write-Host "  Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($key in $Data.Keys) {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(32) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-LZOutputFiles {
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
        Write-Host ("CSV Export").PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }
    if ($HtmlPath) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Dashboard").PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }
    if ($GridViewOpened) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("Grid View").PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": Opened in separate window" -ForegroundColor White
    }
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function New-LZFinding {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$Domain,
        [string]$CheckId,
        [string]$CheckName,
        [string]$Status,          # Pass / Fail / Warning / NotApplicable
        [string]$Severity,        # Critical / High / Medium / Low
        [string]$Framework,       # CAF / WAF / NIST / CIS
        [string]$FrameworkRef,    # e.g. CAF-LZ-001, CIS-1.1
        [string]$Evidence,
        [string]$Recommendation,
        [string]$ResourceId = ""
    )
    return [pscustomobject]@{
        SubscriptionName = $SubscriptionName
        SubscriptionId   = $SubscriptionId
        Domain           = $Domain
        CheckId          = $CheckId
        CheckName        = $CheckName
        Status           = $Status
        Severity         = $Severity
        Framework        = $Framework
        FrameworkRef     = $FrameworkRef
        Evidence         = $Evidence
        Recommendation   = $Recommendation
        ResourceId       = $ResourceId
    }
}

Function Get-SafePropertyValue {
    param(
        [object]$Object,
        [string]$PropertyName,
        [string]$Default = ""
    )
    if ($null -eq $Object) { return $Default }
    if ($Object.PSObject.Properties.Name -contains $PropertyName) {
        $val = $Object.$PropertyName
        if ($null -eq $val) { return $Default }
        return $val
    }
    return $Default
}

Function Ensure-RequiredModules {
    $required = @(
        "Az.Accounts",
        "Az.Resources",
        "Az.Security",
        "Az.Network",
        "Az.Monitor",
        "Az.PolicyInsights"
    )

    $missing = @()
    foreach ($mod in $required) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            $missing += $mod
        }
    }

    if ($missing.Count -gt 0) {
        Write-Host ""
        Write-Host "  ⚠ Missing modules: $($missing -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "  Install missing modules now? (Y/N)"
        if ($install -eq 'Y' -or $install -eq 'y') {
            foreach ($mod in $missing) {
                try {
                    Write-Host "  Installing $mod..." -ForegroundColor Cyan
                    Install-Module -Name $mod -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                    Write-Host "  ✓ $mod installed" -ForegroundColor Green
                }
                catch {
                    Write-Host "  ✗ Failed to install $mod : $_" -ForegroundColor Red
                    return $false
                }
            }
        }
        else {
            Write-Host "  Installation declined. Cannot proceed without required modules." -ForegroundColor Yellow
            return $false
        }
    }

    foreach ($mod in $required) {
        Import-Module $mod -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    return $true
}


#------------------------------------------------------------------------ [ Assessment Domain Functions ]

Function Test-ManagementGroupDomain {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$TenantId
    )

    $findings = @()

    Write-DomainHeader "Management Groups"

    try {
        # Retrieve all management groups visible to this account
        $allMGs = @(Get-AzManagementGroup -ErrorAction SilentlyContinue)

        # Check 1 — MG001: Management Groups exist (not just Tenant Root)
        $nonRootMGs = $allMGs | Where-Object { $_.DisplayName -notmatch "Tenant Root Group" }
        if ($nonRootMGs.Count -gt 0) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "ManagementGroups" -CheckId "MG001" -CheckName "Management Group hierarchy exists" `
                -Status "Pass" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-MG-001" `
                -Evidence "$($nonRootMGs.Count) management group(s) found" `
                -Recommendation "Maintain a Management Group hierarchy per CAF Enterprise Scale design."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "ManagementGroups" -CheckId "MG001" -CheckName "Management Group hierarchy exists" `
                -Status "Fail" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-MG-001" `
                -Evidence "Only Tenant Root Group found — no child Management Groups" `
                -Recommendation "Implement CAF Enterprise Scale Management Group hierarchy: Platform, Landing Zones, Sandbox, and Decommissioned groups."
        }

        # Check 2 — MG002: CAF-standard group names present
        $cafExpected = @("Platform", "Landing Zones", "Sandbox", "Decommissioned")
        $mgNames = $allMGs | ForEach-Object { $_.DisplayName }
        $cafFound = $cafExpected | Where-Object { $mgNames -contains $_ }
        $cafMissing = $cafExpected | Where-Object { $mgNames -notcontains $_ }

        if ($cafMissing.Count -eq 0) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "ManagementGroups" -CheckId "MG002" -CheckName "CAF standard Management Group names present" `
                -Status "Pass" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-MG-002" `
                -Evidence "All CAF standard groups found: $($cafFound -join ', ')" `
                -Recommendation "Maintain CAF standard Management Group naming."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "ManagementGroups" -CheckId "MG002" -CheckName "CAF standard Management Group names present" `
                -Status "Fail" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-MG-002" `
                -Evidence "Missing CAF standard groups: $($cafMissing -join ', ')" `
                -Recommendation "Create the missing Management Groups: $($cafMissing -join ', ')."
        }

        # Check 3 — MG003: Subscription is NOT at Tenant Root level
        $rootMG = $allMGs | Where-Object { $_.DisplayName -match "Tenant Root Group" } | Select-Object -First 1
        if ($rootMG) {
            try {
                $rootDetails = Get-AzManagementGroup -GroupId $rootMG.Name -Expand -Recurse -ErrorAction SilentlyContinue
                $rootChildren = @(Get-SafePropertyValue -Object $rootDetails -PropertyName "Children")
                $directSubAtRoot = $rootChildren | Where-Object { $_.Type -eq "/subscriptions" -and $_.Name -eq $SubscriptionId }

                if ($directSubAtRoot) {
                    $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                        -Domain "ManagementGroups" -CheckId "MG003" -CheckName "Subscription not placed at Tenant Root" `
                        -Status "Fail" -Severity "Critical" -Framework "CAF" -FrameworkRef "CAF-LZ-MG-003" `
                        -Evidence "Subscription is a direct child of Tenant Root Group" `
                        -Recommendation "Move this subscription into the appropriate child Management Group (Landing Zones or Platform)."
                }
                else {
                    $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                        -Domain "ManagementGroups" -CheckId "MG003" -CheckName "Subscription not placed at Tenant Root" `
                        -Status "Pass" -Severity "Critical" -Framework "CAF" -FrameworkRef "CAF-LZ-MG-003" `
                        -Evidence "Subscription is correctly placed under a child Management Group" `
                        -Recommendation "Maintain subscription placement in the appropriate Management Group."
                }
            }
            catch {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "ManagementGroups" -CheckId "MG003" -CheckName "Subscription not placed at Tenant Root" `
                    -Status "Warning" -Severity "Critical" -Framework "CAF" -FrameworkRef "CAF-LZ-MG-003" `
                    -Evidence "Could not determine subscription placement — insufficient permissions on Tenant Root Group" `
                    -Recommendation "Ensure Management Group Reader role at Tenant Root to validate placement."
            }
        }
    }
    catch {
        $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Domain "ManagementGroups" -CheckId "MG000" -CheckName "Management Group access" `
            -Status "Warning" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-MG-000" `
            -Evidence "Failed to retrieve Management Group data: $($_.Exception.Message)" `
            -Recommendation "Ensure the account has Management Group Reader role at Tenant Root level."
    }

    return $findings
}

Function Test-RBACDomain {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-DomainHeader "RBAC"

    try {
        $allAssignments = @(Get-AzRoleAssignment -ErrorAction Stop)

        # Check 1 — RBAC001: No more than 3 permanent Owners at subscription scope
        $ownerAssignments = $allAssignments | Where-Object {
            $_.RoleDefinitionName -eq "Owner" -and
            $_.Scope -match "^/subscriptions/[^/]+$"
        }
        $ownerCount = $ownerAssignments.Count

        if ($ownerCount -le 3) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "RBAC" -CheckId "RBAC001" -CheckName "Owner count at subscription scope <= 3" `
                -Status "Pass" -Severity "Critical" -Framework "CIS" -FrameworkRef "CIS-1.15" `
                -Evidence "$ownerCount Owner assignment(s) at subscription scope" `
                -Recommendation "Maintain 2–3 subscription Owners maximum. Use PIM for just-in-time access."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "RBAC" -CheckId "RBAC001" -CheckName "Owner count at subscription scope <= 3" `
                -Status "Fail" -Severity "Critical" -Framework "CIS" -FrameworkRef "CIS-1.15" `
                -Evidence "$ownerCount Owner assignments found at subscription scope (threshold: 3)" `
                -Recommendation "Reduce Owner assignments to 3 or fewer. Remove unnecessary Owners, transition to Contributor + specific roles, and enable PIM for eligible assignments."
        }

        # Check 2 — RBAC002: No guest/external users as Owners or Contributors
        $externalOwnerContrib = $allAssignments | Where-Object {
            ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor") -and
            ($_.SignInName -like "*#EXT#*" -or $_.ObjectType -eq "Unknown")
        }
        if ($externalOwnerContrib.Count -eq 0) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "RBAC" -CheckId "RBAC002" -CheckName "No external users as Owner or Contributor" `
                -Status "Pass" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-1.3" `
                -Evidence "No external/guest user Owner or Contributor assignments detected" `
                -Recommendation "Periodically review external user assignments and enforce least privilege."
        }
        else {
            $extNames = ($externalOwnerContrib | Select-Object -ExpandProperty SignInName) -join "; "
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "RBAC" -CheckId "RBAC002" -CheckName "No external users as Owner or Contributor" `
                -Status "Fail" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-1.3" `
                -Evidence "External user(s) with Owner/Contributor: $extNames" `
                -Recommendation "Remove or downgrade external user privileges. Use B2B guest access with limited roles and periodic access reviews."
        }

        # Check 3 — RBAC003: Custom role count within reasonable bounds
        $customRoles = @(Get-AzRoleDefinition -Custom -ErrorAction SilentlyContinue)
        if ($customRoles.Count -le 10) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "RBAC" -CheckId "RBAC003" -CheckName "Custom role proliferation within threshold" `
                -Status "Pass" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-RBAC-001" `
                -Evidence "$($customRoles.Count) custom role(s) found (threshold: 10)" `
                -Recommendation "Review custom roles for consolidation and document their purpose."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "RBAC" -CheckId "RBAC003" -CheckName "Custom role proliferation within threshold" `
                -Status "Fail" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-RBAC-001" `
                -Evidence "$($customRoles.Count) custom roles found (threshold: 10)" `
                -Recommendation "Consolidate and document custom roles. Prefer built-in roles where possible."
        }

        # Check 4 — RBAC004: Service principals / managed identities assigned to roles (not personal accounts for automation)
        $directUserOnCritical = $allAssignments | Where-Object {
            $_.ObjectType -eq "User" -and
            $_.RoleDefinitionName -eq "Contributor" -and
            $_.Scope -match "^/subscriptions/[^/]+$" -and
            $_.SignInName -notlike "*#EXT#*"
        }
        if ($directUserOnCritical.Count -le 5) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "RBAC" -CheckId "RBAC004" -CheckName "Contributor assignments at subscription scope are reviewed" `
                -Status "Pass" -Severity "Medium" -Framework "NIST" -FrameworkRef "NIST-AC-6" `
                -Evidence "$($directUserOnCritical.Count) user(s) assigned Contributor directly at subscription scope" `
                -Recommendation "Periodically review direct Contributor assignments. Prefer role assignments via groups."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "RBAC" -CheckId "RBAC004" -CheckName "Contributor assignments at subscription scope are reviewed" `
                -Status "Warning" -Severity "Medium" -Framework "NIST" -FrameworkRef "NIST-AC-6" `
                -Evidence "$($directUserOnCritical.Count) users with Contributor at subscription scope — consider group-based assignment" `
                -Recommendation "Assign roles via Entra ID groups rather than directly to individual users."
        }
    }
    catch {
        $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Domain "RBAC" -CheckId "RBAC000" -CheckName "RBAC data retrieval" `
            -Status "Warning" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-RBAC-000" `
            -Evidence "Failed to retrieve RBAC assignments: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Authorization/roleAssignments/read permission at subscription scope."
    }

    return $findings
}

Function Test-PolicyDomain {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-DomainHeader "Azure Policy"

    try {
        # Check 1 — POL001: At least one policy initiative assigned
        $initiatives = @(Get-AzPolicyAssignment -ErrorAction Stop)
        $initiativeAssignments = $initiatives | Where-Object { $_.PolicyDefinitionId -like "*/policySetDefinitions/*" }

        if ($initiativeAssignments.Count -gt 0) {
            $names = ($initiativeAssignments | Select-Object -ExpandProperty Name) -join "; "
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Policy" -CheckId "POL001" -CheckName "Policy initiative(s) assigned" `
                -Status "Pass" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-POL-001" `
                -Evidence "$($initiativeAssignments.Count) initiative(s) assigned: $names" `
                -Recommendation "Ensure initiatives include security baselines (MDfC ASC, CIS, NIST)."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Policy" -CheckId "POL001" -CheckName "Policy initiative(s) assigned" `
                -Status "Fail" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-POL-001" `
                -Evidence "No policy initiatives assigned at this subscription scope" `
                -Recommendation "Assign at least one security baseline initiative (e.g. Microsoft Cloud Security Benchmark, CIS Azure, or NIST SP 800-53)."
        }

        # Check 2 — POL002: Policy compliance state — non-compliant resource count
        try {
            $nonCompliant = @(Get-AzPolicyState -SubscriptionId $SubscriptionId -Filter "complianceState eq 'NonCompliant'" -ErrorAction SilentlyContinue)
            $nonCompliantCount = $nonCompliant.Count

            if ($nonCompliantCount -eq 0) {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Policy" -CheckId "POL002" -CheckName "Policy compliance state — non-compliant resources" `
                    -Status "Pass" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-CM-6" `
                    -Evidence "No non-compliant resources detected in last policy evaluation cycle" `
                    -Recommendation "Continue monitoring policy compliance state regularly."
            }
            elseif ($nonCompliantCount -le 20) {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Policy" -CheckId "POL002" -CheckName "Policy compliance state — non-compliant resources" `
                    -Status "Warning" -Severity "Medium" -Framework "NIST" -FrameworkRef "NIST-CM-6" `
                    -Evidence "$nonCompliantCount non-compliant resource(s) in last evaluation cycle" `
                    -Recommendation "Review and remediate non-compliant resources. Use Policy remediation tasks for automatic remediation."
            }
            else {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Policy" -CheckId "POL002" -CheckName "Policy compliance state — non-compliant resources" `
                    -Status "Fail" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-CM-6" `
                    -Evidence "$nonCompliantCount non-compliant resources — review required" `
                    -Recommendation "Immediately review non-compliant resources. Prioritise Critical and High policy definitions. Enable deny effects where appropriate."
            }
        }
        catch {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Policy" -CheckId "POL002" -CheckName "Policy compliance state — non-compliant resources" `
                -Status "Warning" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-CM-6" `
                -Evidence "Could not retrieve policy state: $($_.Exception.Message)" `
                -Recommendation "Ensure Microsoft.PolicyInsights/policyStates/read permission."
        }

        # Check 3 — POL003: Policy exemptions review
        try {
            $exemptions = @(Get-AzPolicyExemption -ErrorAction SilentlyContinue)
            if ($exemptions.Count -eq 0) {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Policy" -CheckId "POL003" -CheckName "Policy exemptions are minimal" `
                    -Status "Pass" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-POL-002" `
                    -Evidence "No policy exemptions found" `
                    -Recommendation "Maintain zero or minimal exemptions. Document any future exemptions with business justification."
            }
            else {
                $expiredExemptions = $exemptions | Where-Object {
                    $expiresOn = Get-SafePropertyValue -Object $_ -PropertyName "ExpiresOn"
                    $expiresOn -ne "" -and [datetime]$expiresOn -lt (Get-Date)
                }
                $status = if ($exemptions.Count -le 3 -and $expiredExemptions.Count -eq 0) { "Warning" } else { "Fail" }
                $severity = if ($expiredExemptions.Count -gt 0) { "High" } else { "Medium" }
                $evidence = "$($exemptions.Count) exemption(s) found"
                if ($expiredExemptions.Count -gt 0) { $evidence += "; $($expiredExemptions.Count) EXPIRED exemption(s) still in place" }

                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Policy" -CheckId "POL003" -CheckName "Policy exemptions are minimal" `
                    -Status $status -Severity $severity -Framework "CAF" -FrameworkRef "CAF-LZ-POL-002" `
                    -Evidence $evidence `
                    -Recommendation "Review all exemptions for continued business justification. Remove expired exemptions immediately."
            }
        }
        catch {
            # Non-critical — skip silently with a warning finding
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Policy" -CheckId "POL003" -CheckName "Policy exemptions are minimal" `
                -Status "Warning" -Severity "Low" -Framework "CAF" -FrameworkRef "CAF-LZ-POL-002" `
                -Evidence "Could not retrieve policy exemptions: $($_.Exception.Message)" `
                -Recommendation "Ensure read access to policy exemptions for a complete assessment."
        }
    }
    catch {
        $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Domain "Policy" -CheckId "POL000" -CheckName "Policy data retrieval" `
            -Status "Warning" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-POL-000" `
            -Evidence "Failed to retrieve policy assignments: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Authorization/policyAssignments/read permission."
    }

    return $findings
}

Function Test-NetworkingDomain {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-DomainHeader "Networking"

    try {
        $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop)

        # Check 1 — NET001: VNets exist
        if ($vnets.Count -gt 0) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Networking" -CheckId "NET001" -CheckName "Virtual Networks exist" `
                -Status "Pass" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-001" `
                -Evidence "$($vnets.Count) VNet(s) found" `
                -Recommendation "Ensure VNets use non-overlapping RFC1918 address spaces."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Networking" -CheckId "NET001" -CheckName "Virtual Networks exist" `
                -Status "Warning" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-001" `
                -Evidence "No VNets found in this subscription" `
                -Recommendation "If this is a workload subscription, deploy a VNet and connect it to the hub via peering or VWAN."
        }

        # Check 2 — NET002: VNet peering or VWAN connectivity (hub connectivity)
        $peeredVNets = $vnets | Where-Object {
            $peerings = Get-SafePropertyValue -Object $_ -PropertyName "VirtualNetworkPeerings"
            $peerings -and $peerings.Count -gt 0
        }

        # Also check for VWAN VHub connections
        try {
            $vhubConnections = @(Get-AzVirtualHubVnetConnection -ErrorAction SilentlyContinue 2>$null)
        }
        catch { $vhubConnections = @() }

        $hasHubConnectivity = ($peeredVNets.Count -gt 0 -or $vhubConnections.Count -gt 0)

        if ($hasHubConnectivity) {
            $evidence = if ($peeredVNets.Count -gt 0) { "$($peeredVNets.Count) peered VNet(s)" } else { "" }
            if ($vhubConnections.Count -gt 0) { $evidence += $(if ($evidence) { "; " }) + "$($vhubConnections.Count) VWAN hub connection(s)" }
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Networking" -CheckId "NET002" -CheckName "Hub connectivity (peering or VWAN)" `
                -Status "Pass" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-002" `
                -Evidence $evidence `
                -Recommendation "Validate hub-spoke routing via UDR and that traffic flows through the firewall."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Networking" -CheckId "NET002" -CheckName "Hub connectivity (peering or VWAN)" `
                -Status "Fail" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-002" `
                -Evidence "No VNet peering or VWAN connection found — subscription appears isolated" `
                -Recommendation "Connect spoke VNets to the hub via VNet peering (hub-spoke) or Virtual Hub connections (VWAN)."
        }

        # Check 3 — NET003: NSG flow logs enabled on all NSGs
        try {
            $nsgs = @(Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue)
            if ($nsgs.Count -gt 0) {
                $nsgsWithoutFlowLogs = @()
                foreach ($nsg in $nsgs) {
                    try {
                        $flowLog = Get-AzNetworkWatcherFlowLogStatus -NetworkWatcher (Get-AzNetworkWatcher -Location $nsg.Location -ErrorAction SilentlyContinue) -TargetResourceId $nsg.Id -ErrorAction SilentlyContinue
                        $enabled = Get-SafePropertyValue -Object $flowLog -PropertyName "Enabled" -Default "false"
                        if ($enabled -ne $true) { $nsgsWithoutFlowLogs += $nsg.Name }
                    }
                    catch { $nsgsWithoutFlowLogs += "$($nsg.Name) (check failed)" }
                }

                if ($nsgsWithoutFlowLogs.Count -eq 0) {
                    $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                        -Domain "Networking" -CheckId "NET003" -CheckName "NSG flow logs enabled" `
                        -Status "Pass" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AU-2" `
                        -Evidence "All $($nsgs.Count) NSG(s) have flow logs enabled" `
                        -Recommendation "Ensure flow logs are sent to Log Analytics via Traffic Analytics."
                }
                else {
                    $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                        -Domain "Networking" -CheckId "NET003" -CheckName "NSG flow logs enabled" `
                        -Status "Fail" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AU-2" `
                        -Evidence "NSGs without flow logs: $($nsgsWithoutFlowLogs -join '; ')" `
                        -Recommendation "Enable NSG flow logs (v2 recommended) for all NSGs and route to Log Analytics with Traffic Analytics enabled."
                }
            }
            else {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Networking" -CheckId "NET003" -CheckName "NSG flow logs enabled" `
                    -Status "Warning" -Severity "Medium" -Framework "NIST" -FrameworkRef "NIST-AU-2" `
                    -Evidence "No NSGs found in this subscription" `
                    -Recommendation "If workloads are deployed, ensure subnets are protected by NSGs with flow logging enabled."
            }
        }
        catch {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Networking" -CheckId "NET003" -CheckName "NSG flow logs enabled" `
                -Status "Warning" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AU-2" `
                -Evidence "Could not retrieve NSG or flow log data: $($_.Exception.Message)" `
                -Recommendation "Ensure Network Contributor or Reader role to check NSG flow logs."
        }

        # Check 4 — NET004: DDoS Protection standard
        $vnetWithDDoS = $vnets | Where-Object {
            $ddos = Get-SafePropertyValue -Object $_.DdosProtectionPlan -PropertyName "Id"
            $ddos -ne "" -or (Get-SafePropertyValue -Object $_ -PropertyName "EnableDdosProtection") -eq $true
        }

        if ($vnetWithDDoS.Count -gt 0 -or $vnets.Count -eq 0) {
            $evidence = if ($vnets.Count -eq 0) { "No VNets to assess" } else { "$($vnetWithDDoS.Count) of $($vnets.Count) VNet(s) have DDoS protection associated" }
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Networking" -CheckId "NET004" -CheckName "DDoS Protection configured" `
                -Status "Pass" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-RE-05" `
                -Evidence $evidence `
                -Recommendation "Confirm DDoS Network Protection is applied on the hub VNet."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Networking" -CheckId "NET004" -CheckName "DDoS Protection configured" `
                -Status "Fail" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-RE-05" `
                -Evidence "No VNets have DDoS Network Protection Plan associated" `
                -Recommendation "Associate an Azure DDoS Network Protection plan with hub VNets. Apply DDoS IP Protection on individual public IPs where Network Protection is not feasible."
        }

        # Check 5 — NET005: User-Defined Routes (UDR) present — traffic forced through firewall
        try {
            $routeTables = @(Get-AzRouteTable -ErrorAction SilentlyContinue)
            if ($routeTables.Count -gt 0) {
                $hasDefaultRoute = $routeTables | Where-Object {
                    $_.Routes | Where-Object { $_.AddressPrefix -eq "0.0.0.0/0" -and $_.NextHopType -eq "VirtualAppliance" }
                }

                if ($hasDefaultRoute) {
                    $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                        -Domain "Networking" -CheckId "NET005" -CheckName "Default route via UDR to firewall" `
                        -Status "Pass" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-003" `
                        -Evidence "$($routeTables.Count) route table(s) found; default 0.0.0.0/0 routed via Virtual Appliance" `
                        -Recommendation "Validate UDR association to all workload subnets and that next-hop IP is the firewall."
                }
                else {
                    $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                        -Domain "Networking" -CheckId "NET005" -CheckName "Default route via UDR to firewall" `
                        -Status "Warning" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-003" `
                        -Evidence "$($routeTables.Count) route table(s) found but no 0.0.0.0/0 → Virtual Appliance route detected" `
                        -Recommendation "Add a default route (0.0.0.0/0) pointing to the hub firewall IP in UDRs applied to workload subnets."
                }
            }
            else {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Networking" -CheckId "NET005" -CheckName "Default route via UDR to firewall" `
                    -Status "Warning" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-003" `
                    -Evidence "No route tables found — egress traffic may not be controlled" `
                    -Recommendation "Deploy route tables with a default route to the hub firewall on all spoke subnets."
            }
        }
        catch {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Networking" -CheckId "NET005" -CheckName "Default route via UDR to firewall" `
                -Status "Warning" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-003" `
                -Evidence "Could not retrieve route tables: $($_.Exception.Message)" `
                -Recommendation "Verify Network Reader permissions and retry."
        }
    }
    catch {
        $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Domain "Networking" -CheckId "NET000" -CheckName "Networking data retrieval" `
            -Status "Warning" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-000" `
            -Evidence "Failed to retrieve networking data: $($_.Exception.Message)" `
            -Recommendation "Ensure Network Reader permissions at subscription scope."
    }

    return $findings
}

Function Test-LoggingDomain {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-DomainHeader "Logging & Diagnostics"

    # Check 1 — LOG001: Activity Log diagnostic setting enabled
    try {
        $activityLogSettings = @(Get-AzDiagnosticSetting -ResourceId "/subscriptions/$SubscriptionId" -ErrorAction Stop)
        if ($activityLogSettings.Count -gt 0) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Logging" -CheckId "LOG001" -CheckName "Activity Log diagnostic setting enabled" `
                -Status "Pass" -Severity "Critical" -Framework "CIS" -FrameworkRef "CIS-5.1.2" `
                -Evidence "$($activityLogSettings.Count) Activity Log diagnostic setting(s) configured" `
                -Recommendation "Ensure all Activity Log categories (Administrative, Security, Alert, Policy) are captured."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Logging" -CheckId "LOG001" -CheckName "Activity Log diagnostic setting enabled" `
                -Status "Fail" -Severity "Critical" -Framework "CIS" -FrameworkRef "CIS-5.1.2" `
                -Evidence "No Activity Log diagnostic setting found for this subscription" `
                -Recommendation "Create an Activity Log diagnostic setting to send all categories to Log Analytics Workspace and/or Storage Account. This is a CIS Level 1 control."
        }
    }
    catch {
        $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Domain "Logging" -CheckId "LOG001" -CheckName "Activity Log diagnostic setting enabled" `
            -Status "Warning" -Severity "Critical" -Framework "CIS" -FrameworkRef "CIS-5.1.2" `
            -Evidence "Could not retrieve Activity Log diagnostic settings: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Insights/diagnosticSettings/read permission."
    }

    # Check 2 — LOG002: Log Analytics Workspace exists per subscription
    try {
        $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop)
        if ($workspaces.Count -gt 0) {
            $wsNames = ($workspaces | Select-Object -ExpandProperty Name) -join "; "
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Logging" -CheckId "LOG002" -CheckName "Log Analytics Workspace present" `
                -Status "Pass" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-LOG-001" `
                -Evidence "$($workspaces.Count) workspace(s) found: $wsNames" `
                -Recommendation "Ensure retention is set to at least 90 days per CIS recommendations (365 days recommended)."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Logging" -CheckId "LOG002" -CheckName "Log Analytics Workspace present" `
                -Status "Fail" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-LOG-001" `
                -Evidence "No Log Analytics Workspace found in this subscription" `
                -Recommendation "Deploy a Log Analytics Workspace per the per-subscription strategy. Configure at minimum 90-day retention."
        }

        # Check 3 — LOG003: LAW retention >= 90 days
        if ($workspaces.Count -gt 0) {
            $shortRetention = $workspaces | Where-Object { $_.retentionInDays -lt 90 }
            if ($shortRetention.Count -eq 0) {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Logging" -CheckId "LOG003" -CheckName "Log Analytics Workspace retention >= 90 days" `
                    -Status "Pass" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-5.2.1" `
                    -Evidence "All workspace(s) have retention >= 90 days" `
                    -Recommendation "Consider 365-day retention for security log data to satisfy audit trail requirements."
            }
            else {
                $shortNames = ($shortRetention | ForEach-Object { "$($_.Name) ($($_.retentionInDays)d)" }) -join "; "
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Logging" -CheckId "LOG003" -CheckName "Log Analytics Workspace retention >= 90 days" `
                    -Status "Fail" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-5.2.1" `
                    -Evidence "Workspace(s) below 90-day retention: $shortNames" `
                    -Recommendation "Increase workspace retention to at minimum 90 days. Extend to 365 days for security and audit workspaces."
            }
        }
    }
    catch {
        $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Domain "Logging" -CheckId "LOG002" -CheckName "Log Analytics Workspace present" `
            -Status "Warning" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-LZ-LOG-001" `
            -Evidence "Could not retrieve Log Analytics data: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.OperationalInsights/workspaces/read permission."
    }

    # Check 4 — LOG004: Activity Log alert for Create/Update policy assignment
    try {
        $activityAlerts = @(Get-AzActivityLogAlert -ErrorAction SilentlyContinue)
        $policyAlert = $activityAlerts | Where-Object {
            $_.ConditionAllOf | Where-Object {
                ($_.Field -eq "operationName" -and $_.Equals -like "*policyAssignments/write*") -or
                ($_.Field -eq "category" -and $_.Equals -eq "Policy")
            }
        }

        if ($policyAlert) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Logging" -CheckId "LOG004" -CheckName "Activity Log alert for policy changes" `
                -Status "Pass" -Severity "Medium" -Framework "CIS" -FrameworkRef "CIS-5.2.4" `
                -Evidence "Activity Log alert for policy assignment changes found" `
                -Recommendation "Ensure the alert action group notifies the security operations team."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Logging" -CheckId "LOG004" -CheckName "Activity Log alert for policy changes" `
                -Status "Fail" -Severity "Medium" -Framework "CIS" -FrameworkRef "CIS-5.2.4" `
                -Evidence "No Activity Log alert for policy assignment creation/modification" `
                -Recommendation "Create an Activity Log alert on Microsoft.Authorization/policyAssignments/write. Notify the security team via Action Group."
        }
    }
    catch {
        $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Domain "Logging" -CheckId "LOG004" -CheckName "Activity Log alert for policy changes" `
            -Status "Warning" -Severity "Medium" -Framework "CIS" -FrameworkRef "CIS-5.2.4" `
            -Evidence "Could not retrieve Activity Log alerts: $($_.Exception.Message)" `
            -Recommendation "Verify Microsoft.Insights/activityLogAlerts/read permission."
    }

    return $findings
}

Function Test-DefenderDomain {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-DomainHeader "Defender for Cloud"

    # Defender plan names to validate
    $expectedPlans = @(
        "VirtualMachines",
        "SqlServers",
        "AppServices",
        "StorageAccounts",
        "Containers",
        "KeyVaults",
        "Arm",
        "Dns",
        "SqlServerVirtualMachines",
        "OpenSourceRelationalDatabases"
    )

    try {
        $pricings = @(Get-AzSecurityPricing -ErrorAction Stop)
        $freeCount = 0
        $standardCount = 0

        foreach ($plan in $expectedPlans) {
            $planData = $pricings | Where-Object { $_.Name -eq $plan }
            if ($planData) {
                $pricingTier = Get-SafePropertyValue -Object $planData -PropertyName "PricingTier" -Default "Unknown"
                if ($pricingTier -eq "Standard" -or $pricingTier -eq "Free" -and $planData.SubPlan) {
                    $standardCount++
                }
                elseif ($pricingTier -eq "Free") {
                    $freeCount++
                    $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                        -Domain "Defender" -CheckId "DEF001-$plan" -CheckName "Defender plan enabled: $plan" `
                        -Status "Fail" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-2.1" `
                        -Evidence "Defender for $plan is on Free tier (not Standard/Defender plan)" `
                        -Recommendation "Enable Microsoft Defender for $plan (Standard tier). This provides threat detection, vulnerability assessment, and security alerts."
                }
            }
            else {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Defender" -CheckId "DEF001-$plan" -CheckName "Defender plan found: $plan" `
                    -Status "Warning" -Severity "Medium" -Framework "CIS" -FrameworkRef "CIS-2.1" `
                    -Evidence "Defender plan '$plan' not found in pricing list for this subscription" `
                    -Recommendation "Verify the plan name or enable Microsoft Defender for this resource type."
            }
        }

        # Summary finding
        $totalPlans = $expectedPlans.Count
        if ($standardCount -eq $totalPlans) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Defender" -CheckId "DEF002" -CheckName "All Defender plans on Standard tier" `
                -Status "Pass" -Severity "Critical" -Framework "NIST" -FrameworkRef "NIST-SI-3" `
                -Evidence "All $totalPlans Defender plans are on Standard tier" `
                -Recommendation "Review Defender for Cloud secure score and implement recommended remediations."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Defender" -CheckId "DEF002" -CheckName "All Defender plans on Standard tier" `
                -Status "Fail" -Severity "Critical" -Framework "NIST" -FrameworkRef "NIST-SI-3" `
                -Evidence "$standardCount of $totalPlans plans on Standard tier; $freeCount on Free tier" `
                -Recommendation "Enable all Microsoft Defender plans at Standard tier. Prioritise VMs, Storage, KeyVault, and Containers."
        }

        # Check auto-provisioning of monitoring agent
        try {
            $autoProvision = @(Get-AzSecurityAutoProvisioningSetting -ErrorAction SilentlyContinue)
            $mmaEnabled = $autoProvision | Where-Object { $_.Name -eq "mma" -and $_.AutoProvision -eq "On" }
            $amaEnabled = $autoProvision | Where-Object { $_.Name -like "*AzureMonitorAgent*" -and $_.AutoProvision -eq "On" }

            if ($mmaEnabled -or $amaEnabled) {
                $agent = if ($amaEnabled) { "Azure Monitor Agent (AMA)" } else { "MMA (Log Analytics agent)" }
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Defender" -CheckId "DEF003" -CheckName "Defender auto-provisioning enabled" `
                    -Status "Pass" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-2.14" `
                    -Evidence "Auto-provisioning enabled for $agent" `
                    -Recommendation "Prefer Azure Monitor Agent (AMA) over legacy MMA. Ensure workspace is correctly configured."
            }
            else {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Defender" -CheckId "DEF003" -CheckName "Defender auto-provisioning enabled" `
                    -Status "Fail" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-2.14" `
                    -Evidence "No Defender auto-provisioning settings are On" `
                    -Recommendation "Enable auto-provisioning of the Azure Monitor Agent in Defender for Cloud settings to ensure VM coverage."
            }
        }
        catch {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Defender" -CheckId "DEF003" -CheckName "Defender auto-provisioning enabled" `
                -Status "Warning" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-2.14" `
                -Evidence "Could not retrieve auto-provisioning settings: $($_.Exception.Message)" `
                -Recommendation "Ensure Microsoft.Security/autoProvisioningSettings/read permission."
        }
    }
    catch {
        $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Domain "Defender" -CheckId "DEF000" -CheckName "Defender data retrieval" `
            -Status "Warning" -Severity "Critical" -Framework "CIS" -FrameworkRef "CIS-2.1" `
            -Evidence "Failed to retrieve Defender for Cloud data: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Security/pricings/read permission at subscription scope."
    }

    return $findings
}

Function Test-TaggingDomain {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string[]]$RequiredTags
    )

    $findings = @()
    Write-DomainHeader "Tagging"

    try {
        # Check 1 — TAG001: Required tags on subscription
        $subTags = (Get-AzTag -ResourceId "/subscriptions/$SubscriptionId" -ErrorAction SilentlyContinue).Properties.TagsProperty
        if (-not $subTags) { $subTags = @{} }

        $missingSubTags = $RequiredTags | Where-Object { -not $subTags.ContainsKey($_) }

        if ($missingSubTags.Count -eq 0) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Tagging" -CheckId "TAG001" -CheckName "Required tags present on subscription" `
                -Status "Pass" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-TAG-001" `
                -Evidence "All required tags present on subscription: $($RequiredTags -join ', ')" `
                -Recommendation "Maintain required tags and keep values current."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Tagging" -CheckId "TAG001" -CheckName "Required tags present on subscription" `
                -Status "Fail" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-TAG-001" `
                -Evidence "Missing tags on subscription: $($missingSubTags -join ', ')" `
                -Recommendation "Apply all required tags to the subscription. Consider enforcing via Azure Policy (append or deny effect)."
        }

        # Check 2 — TAG002: Required tags on resource groups
        $resourceGroups = @(Get-AzResourceGroup -ErrorAction Stop)
        $rgsMissingTags = @()

        foreach ($rg in $resourceGroups) {
            $rgTags = $rg.Tags
            if (-not $rgTags) { $rgTags = @{} }
            $missingRgTags = $RequiredTags | Where-Object { -not $rgTags.ContainsKey($_) }
            if ($missingRgTags.Count -gt 0) {
                $rgsMissingTags += "$($rg.ResourceGroupName) (missing: $($missingRgTags -join ','))"
            }
        }

        if ($rgsMissingTags.Count -eq 0) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Tagging" -CheckId "TAG002" -CheckName "Required tags on all resource groups" `
                -Status "Pass" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-TAG-002" `
                -Evidence "All $($resourceGroups.Count) resource group(s) have required tags" `
                -Recommendation "Enforce tagging via Azure Policy to prevent future gaps."
        }
        else {
            $count = $rgsMissingTags.Count
            $sample = ($rgsMissingTags | Select-Object -First 5) -join "; "
            $more = if ($count -gt 5) { " (+$($count-5) more)" } else { "" }
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Tagging" -CheckId "TAG002" -CheckName "Required tags on all resource groups" `
                -Status "Fail" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-TAG-002" `
                -Evidence "$count resource group(s) missing required tags: $sample$more" `
                -Recommendation "Apply required tags to all resource groups. Enforce with Azure Policy 'Require a tag on resource groups' in deny mode."
        }

        # Check 3 — TAG003: No empty/null tag values on required tags
        $emptyValues = $RequiredTags | Where-Object {
            $subTags.ContainsKey($_) -and [string]::IsNullOrWhiteSpace($subTags[$_])
        }
        if ($emptyValues.Count -eq 0) {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Tagging" -CheckId "TAG003" -CheckName "Required tag values are non-empty" `
                -Status "Pass" -Severity "Low" -Framework "CAF" -FrameworkRef "CAF-LZ-TAG-003" `
                -Evidence "All required subscription tags have non-empty values" `
                -Recommendation "Validate tag values are meaningful (not placeholder text such as 'TBC' or 'N/A')."
        }
        else {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Tagging" -CheckId "TAG003" -CheckName "Required tag values are non-empty" `
                -Status "Warning" -Severity "Low" -Framework "CAF" -FrameworkRef "CAF-LZ-TAG-003" `
                -Evidence "Tags with empty values: $($emptyValues -join ', ')" `
                -Recommendation "Populate empty tag values. Consider Azure Policy with allowedValues to enforce valid entries."
        }
    }
    catch {
        $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Domain "Tagging" -CheckId "TAG000" -CheckName "Tagging data retrieval" `
            -Status "Warning" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-TAG-000" `
            -Evidence "Failed to retrieve tagging data: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Resources/resourceGroups/read and Microsoft.Resources/tags/read permissions."
    }

    return $findings
}

Function Test-DiagnosticsDomain {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-DomainHeader "Resource Diagnostics"

    # Key resource types to check for diagnostic settings
    $keyResourceTypes = @(
        @{ Type = "Microsoft.KeyVault/vaults"; CheckId = "DIAG001"; Label = "Key Vault" },
        @{ Type = "Microsoft.Storage/storageAccounts"; CheckId = "DIAG002"; Label = "Storage Account" },
        @{ Type = "Microsoft.Network/networkSecurityGroups"; CheckId = "DIAG003"; Label = "Network Security Group" },
        @{ Type = "Microsoft.Sql/servers/databases"; CheckId = "DIAG004"; Label = "SQL Database" }
    )

    foreach ($resourceTypeDef in $keyResourceTypes) {
        try {
            $resources = @(Get-AzResource -ResourceType $resourceTypeDef.Type -ErrorAction SilentlyContinue)
            if ($resources.Count -eq 0) {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Diagnostics" -CheckId $resourceTypeDef.CheckId -CheckName "Diagnostics: $($resourceTypeDef.Label)" `
                    -Status "NotApplicable" -Severity "Low" -Framework "NIST" -FrameworkRef "NIST-AU-2" `
                    -Evidence "No $($resourceTypeDef.Label) resources found in subscription" `
                    -Recommendation "No action required. Re-run if resources are added."
                continue
            }

            $missingDiag = @()
            foreach ($resource in $resources) {
                try {
                    $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $resource.ResourceId -ErrorAction SilentlyContinue)
                    if ($diagSettings.Count -eq 0) { $missingDiag += $resource.Name }
                }
                catch { $missingDiag += "$($resource.Name) (check failed)" }
            }

            if ($missingDiag.Count -eq 0) {
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Diagnostics" -CheckId $resourceTypeDef.CheckId -CheckName "Diagnostics: $($resourceTypeDef.Label)" `
                    -Status "Pass" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AU-2" `
                    -Evidence "All $($resources.Count) $($resourceTypeDef.Label) resource(s) have diagnostic settings" `
                    -Recommendation "Ensure logs are sent to Log Analytics and relevant log categories are enabled."
            }
            else {
                $sample = ($missingDiag | Select-Object -First 5) -join "; "
                $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Domain "Diagnostics" -CheckId $resourceTypeDef.CheckId -CheckName "Diagnostics: $($resourceTypeDef.Label)" `
                    -Status "Fail" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AU-2" `
                    -Evidence "$($missingDiag.Count) of $($resources.Count) $($resourceTypeDef.Label) resource(s) missing diagnostics: $sample" `
                    -Recommendation "Enable diagnostic settings on all $($resourceTypeDef.Label) resources. Send audit, request, and error logs to Log Analytics."
            }
        }
        catch {
            $findings += New-LZFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Domain "Diagnostics" -CheckId $resourceTypeDef.CheckId -CheckName "Diagnostics: $($resourceTypeDef.Label)" `
                -Status "Warning" -Severity "Medium" -Framework "NIST" -FrameworkRef "NIST-AU-2" `
                -Evidence "Failed to assess $($resourceTypeDef.Label) diagnostics: $($_.Exception.Message)" `
                -Recommendation "Ensure Microsoft.Insights/diagnosticSettings/read permission."
        }
    }

    return $findings
}


#------------------------------------------------------------------------ [ HTML Report Generator ]

Function ConvertTo-LZJsonSafe {
    param([string]$Value)
    return $Value `
        -replace '\\', '\\' `
        -replace '"', '\"' `
        -replace "`n", '\n' `
        -replace "`r", '' `
        -replace "`t", '\t' `
        -replace '<', '\u003c' `
        -replace '>', '\u003e' `
        -replace '\$', '\u0024'
}

Function Generate-LZHtmlReport {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$AllFindings,
        [string]$GeneratedAt
    )

    # ── Pre-compute statistics ──────────────────────────────────────────────────
    $total = @($AllFindings).Count
    $pass = @($AllFindings | Where-Object { $_.Status -eq "Pass" }).Count
    $fail = @($AllFindings | Where-Object { $_.Status -eq "Fail" }).Count
    $warning = @($AllFindings | Where-Object { $_.Status -eq "Warning" }).Count
    $na = @($AllFindings | Where-Object { $_.Status -eq "NotApplicable" }).Count
    $critical = @($AllFindings | Where-Object { $_.Severity -eq "Critical" -and $_.Status -eq "Fail" }).Count
    $high = @($AllFindings | Where-Object { $_.Severity -eq "High" -and $_.Status -eq "Fail" }).Count
    $medium = @($AllFindings | Where-Object { $_.Severity -eq "Medium" -and $_.Status -eq "Fail" }).Count
    $low = @($AllFindings | Where-Object { $_.Severity -eq "Low" -and $_.Status -eq "Fail" }).Count
    $scoreBase = if ($total -gt 0) { [math]::Round(($pass / $total) * 100) } else { 0 }

    # Domain breakdown
    $domains = $AllFindings | Select-Object -ExpandProperty Domain | Sort-Object -Unique
    $domainJsonParts = @()
    foreach ($domain in $domains) {
        $dFail = @($AllFindings | Where-Object { $_.Domain -eq $domain -and $_.Status -eq "Fail" }).Count
        $dPass = @($AllFindings | Where-Object { $_.Domain -eq $domain -and $_.Status -eq "Pass" }).Count
        $dWarn = @($AllFindings | Where-Object { $_.Domain -eq $domain -and $_.Status -eq "Warning" }).Count
        $domainJsonParts += "{""name"":""$(ConvertTo-LZJsonSafe $domain)"",""pass"":$dPass,""fail"":$dFail,""warn"":$dWarn}"
    }
    $domainJson = "[" + ($domainJsonParts -join ",") + "]"

    # Findings JSON
    $findingParts = @()
    foreach ($f in $AllFindings) {
        $findingParts += "{" +
        """sub"":""$(ConvertTo-LZJsonSafe $f.SubscriptionName)""," +
        """subId"":""$(ConvertTo-LZJsonSafe $f.SubscriptionId)""," +
        """domain"":""$(ConvertTo-LZJsonSafe $f.Domain)""," +
        """id"":""$(ConvertTo-LZJsonSafe $f.CheckId)""," +
        """name"":""$(ConvertTo-LZJsonSafe $f.CheckName)""," +
        """status"":""$(ConvertTo-LZJsonSafe $f.Status)""," +
        """sev"":""$(ConvertTo-LZJsonSafe $f.Severity)""," +
        """fw"":""$(ConvertTo-LZJsonSafe $f.Framework)""," +
        """ref"":""$(ConvertTo-LZJsonSafe $f.FrameworkRef)""," +
        """ev"":""$(ConvertTo-LZJsonSafe $f.Evidence)""," +
        """rec"":""$(ConvertTo-LZJsonSafe $f.Recommendation)""" +
        "}"
    }
    $findingsJson = "[" + ($findingParts -join ",") + "]"

    $subscriptions = ($AllFindings | Select-Object -ExpandProperty SubscriptionName | Sort-Object -Unique) -join ", "

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Azure Landing Zone Compliance Report</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;--border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;--green:#3fb950;--amber:#d29922;--red:#f85149;--critical:#ff4444;--text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;--mono:'JetBrains Mono','Consolas',monospace;--sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;--radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);}
body.light-theme{--bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;--border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;--green:#1a7f37;--amber:#b08000;--red:#cf222e;--critical:#cc0000;--text:#1f2328;--muted:#636c76;--muted2:#424a53;--shadow:0 4px 24px rgba(0,0,0,.12);}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;}
#sidebar{width:236px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;z-index:100;}
.logo-block{padding:20px 16px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent2));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:8px;}
.logo-title{font-size:13px;font-weight:600;color:var(--text);line-height:1.3;}
.logo-sub{font-size:10px;color:var(--muted);margin-top:2px;}
.version-badge{display:inline-block;font-size:9px;background:var(--surface3);border:1px solid var(--border);color:var(--muted2);border-radius:4px;padding:1px 5px;margin-top:4px;}
nav{flex:1;padding:12px 8px;overflow-y:auto;}
.nav-section{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;padding:8px 8px 4px;}
.nav-btn{display:flex;align-items:center;gap:8px;width:100%;padding:8px 10px;border-radius:var(--radius-sm);border:none;background:transparent;color:var(--muted2);font-size:12px;cursor:pointer;text-align:left;transition:all .15s;}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:rgba(56,139,253,.12);color:var(--accent);box-shadow:inset 3px 0 0 var(--accent);font-weight:600;}
.nav-btn .icon{font-size:15px;width:18px;text-align:center;}
.nav-count{margin-left:auto;font-size:10px;background:var(--surface3);color:var(--muted);border-radius:10px;padding:1px 6px;}
.sidebar-footer{padding:12px 16px;border-top:1px solid var(--border);font-size:10px;color:var(--muted);}
.theme-toggle{display:flex;align-items:center;gap:8px;margin-bottom:10px;}
.theme-toggle span{font-size:11px;color:var(--muted2);}
.toggle-pill{width:36px;height:18px;background:var(--surface3);border:1px solid var(--border);border-radius:9px;cursor:pointer;position:relative;transition:background .2s;}
.toggle-pill.on{background:var(--accent);}
.toggle-pill::after{content:'';width:12px;height:12px;background:var(--text);border-radius:50%;position:absolute;top:2px;left:2px;transition:left .2s;}
.toggle-pill.on::after{left:20px;}
#main{margin-left:236px;flex:1;padding:24px;min-height:100vh;}
.page{display:none;animation:fadeIn .2s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px);}to{opacity:1;transform:translateY(0);}}
.page-header{margin-bottom:24px;}
.page-title{font-size:22px;font-weight:500;color:var(--text);}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;border-top:3px solid var(--border);transition:transform .15s,box-shadow .15s;}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-critical{border-top-color:var(--critical);}
.stat-num{font-size:32px;font-weight:600;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.6px;}
.stat-card.c-blue .stat-num{color:var(--accent);}
.stat-card.c-cyan .stat-num{color:var(--accent2);}
.stat-card.c-green .stat-num{color:var(--green);}
.stat-card.c-amber .stat-num{color:var(--amber);}
.stat-card.c-red .stat-num{color:var(--red);}
.stat-card.c-purple .stat-num{color:var(--accent3);}
.stat-card.c-critical .stat-num{color:var(--critical);}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr;}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;}
.panel-title{font-size:14px;font-weight:600;color:var(--text);margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid var(--border);}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:10px;font-size:12px;}
.bar-label{width:130px;color:var(--muted2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);transition:width .6s ease;}
.bar-fill.green{background:var(--green);}
.bar-fill.amber{background:var(--amber);}
.bar-fill.red{background:var(--red);}
.bar-fill.critical{background:var(--critical);}
.bar-val{width:35px;text-align:right;color:var(--muted);font-family:var(--mono);font-size:11px;flex-shrink:0;}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;}
.search-wrap input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);padding:7px 10px 7px 32px;font-size:12px;}
.search-wrap input::placeholder{color:var(--muted);}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;}
select.filter-sel{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);padding:7px 10px;font-size:12px;cursor:pointer;}
.findings-table{width:100%;border-collapse:collapse;font-size:12px;}
.findings-table th{background:var(--surface2);color:var(--muted2);font-weight:600;padding:10px 12px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none;}
.findings-table th:hover{color:var(--text);}
.findings-table td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top;color:var(--muted2);}
.findings-table tr:hover td{background:var(--surface2);color:var(--text);}
.findings-table .td-name{color:var(--text);font-weight:500;}
.badge{display:inline-block;font-size:10px;font-weight:600;padding:2px 7px;border-radius:3px;letter-spacing:.3px;}
.badge-pass{background:rgba(63,185,80,.15);color:var(--green);}
.badge-fail{background:rgba(248,81,73,.15);color:var(--red);}
.badge-warning{background:rgba(210,153,34,.15);color:var(--amber);}
.badge-na{background:var(--surface3);color:var(--muted);}
.sev-critical{color:var(--critical);font-weight:700;}
.sev-high{color:var(--red);font-weight:600;}
.sev-medium{color:var(--amber);font-weight:600;}
.sev-low{color:var(--accent2);font-weight:500;}
.fw-badge{font-size:10px;background:var(--surface3);border:1px solid var(--border);color:var(--muted2);border-radius:3px;padding:1px 5px;}
.pagination{display:flex;align-items:center;gap:6px;margin-top:14px;justify-content:flex-end;font-size:12px;}
.pagination button{background:var(--surface2);border:1px solid var(--border);color:var(--muted2);padding:4px 10px;border-radius:var(--radius-sm);cursor:pointer;}
.pagination button:hover,.pagination button.active{background:var(--accent);color:#fff;border-color:var(--accent);}
.pagination button:disabled{opacity:.4;cursor:default;}
.pg-info{color:var(--muted);font-size:11px;}
#detailPanel{display:none;position:fixed;inset:0;z-index:200;background:rgba(0,0,0,.6);}
#detailPanel.open{display:flex;align-items:flex-start;justify-content:flex-end;}
#detailDrawer{width:520px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);min-height:100vh;overflow-y:auto;padding:24px;animation:slideIn .2s ease;}
@keyframes slideIn{from{transform:translateX(100%);}to{transform:translateX(0);}}
.drawer-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px;}
.drawer-title{font-size:15px;font-weight:600;color:var(--text);line-height:1.4;}
.drawer-close{background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;padding:0 4px;}
.drawer-close:hover{color:var(--text);}
.chip-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:18px;}
.chip{font-size:11px;padding:3px 8px;border-radius:12px;border:1px solid var(--border);color:var(--muted2);background:var(--surface2);}
.drawer-section{margin-bottom:16px;}
.drawer-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px;}
.drawer-val{font-size:13px;color:var(--muted2);line-height:1.6;background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px;border:1px solid var(--border);}
.drawer-rec{font-size:13px;color:var(--text);line-height:1.6;background:rgba(56,139,253,.08);border-radius:var(--radius-sm);padding:10px 12px;border:1px solid rgba(56,139,253,.2);}
.drawer-nav{display:flex;gap:8px;margin-top:20px;}
.drawer-nav button{flex:1;background:var(--surface2);border:1px solid var(--border);color:var(--muted2);padding:8px;border-radius:var(--radius-sm);cursor:pointer;font-size:12px;}
.drawer-nav button:hover{background:var(--surface3);color:var(--text);}
#toast{position:fixed;bottom:20px;right:20px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:10px 16px;border-radius:var(--radius);font-size:13px;z-index:999;opacity:0;transform:translateY(10px);transition:all .25s;pointer-events:none;}
#toast.show{opacity:1;transform:translateY(0);}
.score-ring-wrap{display:flex;justify-content:center;align-items:center;padding:10px 0;}
.score-ring-inner{position:relative;width:120px;height:120px;}
.score-ring-inner svg{transform:rotate(-90deg);}
.score-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.score-pct{font-size:26px;font-weight:600;font-family:var(--mono);color:var(--text);}
.score-sub{font-size:10px;color:var(--muted);margin-top:2px;}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px;}
.info-row{background:var(--surface2);border-radius:var(--radius-sm);padding:10px;border:1px solid var(--border);}
.info-key{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px;}
.info-val{color:var(--text);font-size:12px;word-break:break-all;}
@media(max-width:768px){#sidebar{transform:translateX(-100%);}#sidebar.open{transform:translateX(0);}#main{margin-left:0;padding:14px;}#menuToggle{display:flex!important;}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:150;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:6px 8px;cursor:pointer;color:var(--text);font-size:18px;}
</style>
</head>
<body>
<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">&#9776;</button>
<div id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">&#x1F6E1;</div>
    <div class="logo-title">Landing Zone Compliance</div>
    <div class="logo-sub">Azure Cloud Adoption Framework</div>
    <div class="version-badge">v1.0</div>
  </div>
  <nav>
    <div class="nav-section">Navigation</div>
    <button class="nav-btn active" onclick="showPage('pg-overview',this)"><span class="icon">&#x2302;</span> Overview <span class="nav-count" id="nc-overview"></span></button>
    <button class="nav-btn" onclick="showPage('pg-findings',this)"><span class="icon">&#x26A0;</span> All Findings <span class="nav-count" id="nc-findings"></span></button>
    <button class="nav-btn" onclick="showPage('pg-domains',this)"><span class="icon">&#x25A6;</span> By Domain</button>
    <button class="nav-btn" onclick="showPage('pg-info',this)"><span class="icon">&#x2139;</span> Session Info</button>
    <div class="nav-section">Export</div>
    <button class="nav-btn" onclick="exportCsv()"><span class="icon">&#x21E9;</span> Download CSV</button>
  </nav>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark</span>
      <div class="toggle-pill" id="themeToggle" onclick="toggleTheme()"></div>
      <span>Light</span>
    </div>
    <div>Generated __GENERATED_AT__</div>
    <div style="margin-top:4px;color:var(--muted)">Lakshmanan Thangaraj</div>
  </div>
</div>

<div id="main">

  <!-- OVERVIEW PAGE -->
  <div class="page active" id="pg-overview">
    <div class="page-header">
      <div class="page-title">Landing Zone Compliance Overview</div>
      <div class="page-sub">__SUBSCRIPTIONS__ &mdash; CAF &bull; WAF &bull; NIST CSF &bull; CIS Benchmarks</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-blue"><div class="stat-num" id="ov-total">__TOTAL__</div><div class="stat-label">Total Checks</div></div>
      <div class="stat-card c-green"><div class="stat-num" id="ov-pass">__PASS__</div><div class="stat-label">Passed</div></div>
      <div class="stat-card c-red"><div class="stat-num" id="ov-fail">__FAIL__</div><div class="stat-label">Failed</div></div>
      <div class="stat-card c-amber"><div class="stat-num" id="ov-warn">__WARN__</div><div class="stat-label">Warnings</div></div>
      <div class="stat-card c-critical"><div class="stat-num" id="ov-crit">__CRITICAL__</div><div class="stat-label">Critical Failures</div></div>
      <div class="stat-card c-purple"><div class="stat-num" id="ov-high">__HIGH__</div><div class="stat-label">High Failures</div></div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">Compliance Score</div>
        <div class="score-ring-wrap">
          <div class="score-ring-inner">
            <svg width="120" height="120" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="50" fill="none" stroke="var(--surface3)" stroke-width="12"/>
              <circle cx="60" cy="60" r="50" fill="none" stroke="var(--accent)" stroke-width="12"
                stroke-dasharray="__SCORE_DASH__ 314" stroke-linecap="round"/>
            </svg>
            <div class="score-center"><div class="score-pct">__SCORE_PCT__%</div><div class="score-sub">Pass Rate</div></div>
          </div>
        </div>
        <div style="text-align:center;margin-top:8px;font-size:12px;color:var(--muted)">__PASS__ of __TOTAL__ checks passed</div>
      </div>
      <div class="panel">
        <div class="panel-title">Domain Pass Rate</div>
        <div id="domain-bars"></div>
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">Failure Severity Breakdown</div>
        <div class="bar-row"><span class="bar-label">Critical</span><div class="bar-track"><div class="bar-fill critical" id="bfc"></div></div><span class="bar-val" id="bvc">__CRITICAL__</span></div>
        <div class="bar-row"><span class="bar-label">High</span><div class="bar-track"><div class="bar-fill red" id="bfh"></div></div><span class="bar-val" id="bvh">__HIGH__</span></div>
        <div class="bar-row"><span class="bar-label">Medium</span><div class="bar-track"><div class="bar-fill amber" id="bfm"></div></div><span class="bar-val" id="bvm">__MEDIUM__</span></div>
        <div class="bar-row"><span class="bar-label">Low</span><div class="bar-track"><div class="bar-fill" id="bfl"></div></div><span class="bar-val" id="bvl">__LOW__</span></div>
      </div>
      <div class="panel">
        <div class="panel-title">Quick Stats</div>
        <div style="display:grid;gap:8px;font-size:12px;">
          <div style="display:flex;justify-content:space-between;padding:8px;background:var(--surface2);border-radius:6px;"><span style="color:var(--muted)">Subscriptions assessed</span><strong>__SUB_COUNT__</strong></div>
          <div style="display:flex;justify-content:space-between;padding:8px;background:var(--surface2);border-radius:6px;"><span style="color:var(--muted)">Domains assessed</span><strong>__DOMAIN_COUNT__</strong></div>
          <div style="display:flex;justify-content:space-between;padding:8px;background:var(--surface2);border-radius:6px;"><span style="color:var(--muted)">Framework coverage</span><strong>CAF, WAF, NIST, CIS</strong></div>
          <div style="display:flex;justify-content:space-between;padding:8px;background:var(--surface2);border-radius:6px;"><span style="color:var(--muted)">Not applicable</span><strong>__NA__</strong></div>
          <div style="display:flex;justify-content:space-between;padding:8px;background:rgba(248,81,73,.08);border-radius:6px;border:1px solid rgba(248,81,73,.2);"><span style="color:var(--red)">&#x26A0; Critical items need immediate action</span><strong style="color:var(--red)">__CRITICAL__</strong></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ALL FINDINGS PAGE -->
  <div class="page" id="pg-findings">
    <div class="page-header">
      <div class="page-title">All Findings</div>
      <div class="page-sub">Click any row to view evidence and recommendation</div>
    </div>
    <div class="toolbar">
      <div class="search-wrap"><span class="search-icon">&#x2315;</span><input type="text" id="searchBox" placeholder="Search checks, domains, subscriptions..." oninput="applyFilters()"></div>
      <select class="filter-sel" id="fStatus" onchange="applyFilters()"><option value="">All Status</option><option>Pass</option><option>Fail</option><option>Warning</option><option>NotApplicable</option></select>
      <select class="filter-sel" id="fSev" onchange="applyFilters()"><option value="">All Severity</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>
      <select class="filter-sel" id="fDomain" onchange="applyFilters()"><option value="">All Domains</option></select>
      <select class="filter-sel" id="fFw" onchange="applyFilters()"><option value="">All Frameworks</option><option>CAF</option><option>WAF</option><option>NIST</option><option>CIS</option></select>
    </div>
    <div style="overflow-x:auto;">
      <table class="findings-table" id="findingsTable">
        <thead>
          <tr>
            <th onclick="sortTable('id')">Check ID</th>
            <th onclick="sortTable('name')">Check Name</th>
            <th onclick="sortTable('domain')">Domain</th>
            <th onclick="sortTable('status')">Status</th>
            <th onclick="sortTable('sev')">Severity</th>
            <th onclick="sortTable('fw')">Framework</th>
            <th onclick="sortTable('sub')">Subscription</th>
          </tr>
        </thead>
        <tbody id="findingsTbody"></tbody>
      </table>
    </div>
    <div class="pagination" id="pagination"></div>
  </div>

  <!-- BY DOMAIN PAGE -->
  <div class="page" id="pg-domains">
    <div class="page-header">
      <div class="page-title">Assessment by Domain</div>
      <div class="page-sub">Pass / Fail / Warning breakdown per assessment domain</div>
    </div>
    <div id="domainCards" style="display:grid;gap:16px;"></div>
  </div>

  <!-- SESSION INFO PAGE -->
  <div class="page" id="pg-info">
    <div class="page-header">
      <div class="page-title">Session Information</div>
      <div class="page-sub">Scan parameters and authentication context</div>
    </div>
    <div class="panel">
      <div class="panel-title">Session &amp; Scan Details</div>
      <div class="info-grid">
        <div class="info-row"><div class="info-key">Tenant ID</div><div class="info-val">__TENANT__</div></div>
        <div class="info-row"><div class="info-key">Account</div><div class="info-val">__ACCOUNT__</div></div>
        <div class="info-row"><div class="info-key">Environment</div><div class="info-val">__ENVIRONMENT__</div></div>
        <div class="info-row"><div class="info-key">Subscriptions</div><div class="info-val">__SUBSCRIPTIONS__</div></div>
        <div class="info-row"><div class="info-key">Domains Assessed</div><div class="info-val">__DOMAINS_ASSESSED__</div></div>
        <div class="info-row"><div class="info-key">Required Tags</div><div class="info-val">__REQUIRED_TAGS__</div></div>
        <div class="info-row"><div class="info-key">Generated At</div><div class="info-val">__GENERATED_AT__</div></div>
        <div class="info-row"><div class="info-key">Execution Time</div><div class="info-val">__EXEC_TIME__</div></div>
      </div>
    </div>
  </div>

</div><!-- #main -->

<!-- Detail Drawer -->
<div id="detailPanel" onclick="closeDrawer(event)">
  <div id="detailDrawer">
    <div class="drawer-header">
      <div class="drawer-title" id="drawerTitle">Finding Detail</div>
      <button class="drawer-close" onclick="closeDrawerDirect()">&#x2715;</button>
    </div>
    <div class="chip-row" id="drawerChips"></div>
    <div class="drawer-section"><div class="drawer-label">Evidence</div><div class="drawer-val" id="drawerEv"></div></div>
    <div class="drawer-section"><div class="drawer-label">Recommendation</div><div class="drawer-rec" id="drawerRec"></div></div>
    <div class="drawer-section"><div class="drawer-label">Subscription</div><div class="drawer-val" id="drawerSub"></div></div>
    <div class="drawer-section"><div class="drawer-label">Framework Reference</div><div class="drawer-val" id="drawerRef"></div></div>
    <div class="drawer-nav">
      <button onclick="navDetail(-1)">&#x2190; Previous</button>
      <button onclick="navDetail(1)">Next &#x2192;</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
var FINDINGS=__FINDINGS_JSON__;
var DOMAINS=__DOMAIN_JSON__;
var filtered=[],sortCol='',sortDir=1,currentPage=1,pageSize=25,detailIdx=-1,detailList=[];

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
  document.querySelectorAll('.nav-btn').forEach(function(b){b.classList.remove('active');});
  var el=document.getElementById(id);if(el)el.classList.add('active');
  if(btn)btn.classList.add('active');
  if(id==='pg-findings')renderTable();
  if(id==='pg-domains')renderDomains();
}

function toggleTheme(){
  var pill=document.getElementById('themeToggle');
  document.body.classList.toggle('light-theme');
  pill.classList.toggle('on');
}

function showToast(msg){
  var t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');
  setTimeout(function(){t.classList.remove('show');},2200);
}

function statusBadge(s){
  var map={'Pass':'badge-pass','Fail':'badge-fail','Warning':'badge-warning','NotApplicable':'badge-na'};
  return '<span class="badge '+(map[s]||'badge-na')+'">'+escH(s)+'</span>';
}
function sevBadge(s){
  var map={'Critical':'sev-critical','High':'sev-high','Medium':'sev-medium','Low':'sev-low'};
  return '<span class="'+(map[s]||'')+'">'+escH(s)+'</span>';
}

// Populate domain filter
(function(){
  var sel=document.getElementById('fDomain');
  DOMAINS.forEach(function(d){
    var opt=document.createElement('option');opt.value=d.name;opt.textContent=d.name;sel.appendChild(opt);
  });
})();

function applyFilters(){
  var q=document.getElementById('searchBox').value.toLowerCase();
  var fSt=document.getElementById('fStatus').value;
  var fSv=document.getElementById('fSev').value;
  var fDom=document.getElementById('fDomain').value;
  var fFw=document.getElementById('fFw').value;
  filtered=FINDINGS.filter(function(f){
    if(q&&!(f.name.toLowerCase().includes(q)||f.domain.toLowerCase().includes(q)||f.sub.toLowerCase().includes(q)||f.id.toLowerCase().includes(q)))return false;
    if(fSt&&f.status!==fSt)return false;
    if(fSv&&f.sev!==fSv)return false;
    if(fDom&&f.domain!==fDom)return false;
    if(fFw&&f.fw!==fFw)return false;
    return true;
  });
  currentPage=1;renderTable();
}

function sortTable(col){
  if(sortCol===col)sortDir*=-1;else{sortCol=col;sortDir=1;}
  renderTable();
}

function renderTable(){
  var data=filtered.length?filtered:FINDINGS;
  if(sortCol){data=data.slice().sort(function(a,b){return String(a[sortCol]).localeCompare(String(b[sortCol]))*sortDir;});}
  detailList=data;
  var start=(currentPage-1)*pageSize,end=Math.min(start+pageSize,data.length);
  var slice=data.slice(start,end);
  var html='';
  slice.forEach(function(f,i){
    html+='<tr style="cursor:pointer" onclick="openDetail('+(start+i)+')">';
    html+='<td style="font-family:var(--mono);font-size:11px;color:var(--muted)">'+escH(f.id)+'</td>';
    html+='<td class="td-name">'+escH(f.name)+'</td>';
    html+='<td><span class="fw-badge">'+escH(f.domain)+'</span></td>';
    html+='<td>'+statusBadge(f.status)+'</td>';
    html+='<td>'+sevBadge(f.sev)+'</td>';
    html+='<td><span class="fw-badge">'+escH(f.fw)+'</span></td>';
    html+='<td style="font-size:11px;color:var(--muted)">'+escH(f.sub)+'</td>';
    html+='</tr>';
  });
  document.getElementById('findingsTbody').innerHTML=html;
  renderPagination(data.length);
  var nc=document.getElementById('nc-findings');if(nc)nc.textContent=data.length;
}

function renderPagination(total){
  var pages=Math.ceil(total/pageSize),html='';
  var pg=document.getElementById('pagination');if(!pg)return;
  html+='<span class="pg-info">'+(((currentPage-1)*pageSize)+1)+'-'+Math.min(currentPage*pageSize,total)+' of '+total+'</span>';
  html+='<button onclick="goPage('+(currentPage-1)+')" '+(currentPage===1?'disabled':'')+'>&#x2190;</button>';
  for(var i=1;i<=pages;i++){
    if(i===1||i===pages||Math.abs(i-currentPage)<=1)html+='<button onclick="goPage('+i+')" class="'+(i===currentPage?'active':'')+'">'+i+'</button>';
    else if(Math.abs(i-currentPage)===2)html+='<span style="color:var(--muted);padding:0 4px">...</span>';
  }
  html+='<button onclick="goPage('+(currentPage+1)+')" '+(currentPage===pages?'disabled':'')+'>&#x2192;</button>';
  pg.innerHTML=html;
}

function goPage(n){var total=Math.ceil((filtered.length?filtered:FINDINGS).length/pageSize);if(n<1||n>total)return;currentPage=n;renderTable();}

function openDetail(idx){
  detailIdx=idx;var f=detailList[idx];if(!f)return;
  document.getElementById('drawerTitle').textContent=f.name;
  var chips='<span class="chip">'+escH(f.domain)+'</span>';
  chips+='<span class="chip">'+escH(f.fw)+'</span>';
  chips+='<span class="chip">'+escH(f.ref)+'</span>';
  chips+=statusBadge(f.status);chips+=' '+sevBadge(f.sev);
  document.getElementById('drawerChips').innerHTML=chips;
  document.getElementById('drawerEv').textContent=f.ev;
  document.getElementById('drawerRec').textContent=f.rec;
  document.getElementById('drawerSub').textContent=f.sub+' ('+f.subId+')';
  document.getElementById('drawerRef').textContent=f.fw+' — '+f.ref;
  document.getElementById('detailPanel').classList.add('open');
}

function navDetail(dir){
  var next=detailIdx+dir;
  if(next>=0&&next<detailList.length)openDetail(next);
}

function closeDrawer(e){if(e.target===document.getElementById('detailPanel'))closeDrawerDirect();}
function closeDrawerDirect(){document.getElementById('detailPanel').classList.remove('open');}

function renderDomains(){
  var container=document.getElementById('domainCards');container.innerHTML='';
  DOMAINS.forEach(function(d){
    var total=d.pass+d.fail+d.warn;
    var pct=total>0?Math.round((d.pass/total)*100):0;
    var card=document.createElement('div');card.className='panel';
    card.innerHTML='<div class="panel-title">'+escH(d.name)+'</div>'+
      '<div style="display:flex;gap:20px;align-items:center;">'+
      '<div style="flex:1"><div class="bar-row"><span class="bar-label">Pass</span><div class="bar-track"><div class="bar-fill green" style="width:'+Math.round((d.pass/Math.max(total,1))*100)+'%"></div></div><span class="bar-val">'+d.pass+'</span></div>'+
      '<div class="bar-row"><span class="bar-label">Fail</span><div class="bar-track"><div class="bar-fill red" style="width:'+Math.round((d.fail/Math.max(total,1))*100)+'%"></div></div><span class="bar-val">'+d.fail+'</span></div>'+
      '<div class="bar-row"><span class="bar-label">Warning</span><div class="bar-track"><div class="bar-fill amber" style="width:'+Math.round((d.warn/Math.max(total,1))*100)+'%"></div></div><span class="bar-val">'+d.warn+'</span></div></div>'+
      '<div style="text-align:center;min-width:70px;"><div style="font-size:28px;font-weight:700;font-family:var(--mono);color:'+(pct>=80?'var(--green)':pct>=50?'var(--amber)':'var(--red)')+'">'+pct+'%</div><div style="font-size:10px;color:var(--muted)">Pass rate</div></div></div>';
    container.appendChild(card);
  });
}

// Domain bars on overview
(function(){
  var container=document.getElementById('domain-bars');if(!container)return;
  var maxFail=Math.max.apply(null,DOMAINS.map(function(d){return d.fail+d.pass+d.warn;}));
  DOMAINS.forEach(function(d){
    var total=d.pass+d.fail+d.warn;
    var pct=total>0?Math.round((d.pass/total)*100):0;
    var color=pct>=80?'green':pct>=50?'amber':'red';
    var row=document.createElement('div');row.className='bar-row';
    row.innerHTML='<span class="bar-label">'+escH(d.name)+'</span>'+
      '<div class="bar-track"><div class="bar-fill '+color+'" style="width:'+pct+'%"></div></div>'+
      '<span class="bar-val">'+pct+'%</span>';
    container.appendChild(row);
  });
})();

// Severity bars animation
(function(){
  var maxFail=Math.max(__CRITICAL__,__HIGH__,__MEDIUM__,__LOW__,1);
  function setBar(id,val){
    var el=document.getElementById(id);
    if(el)setTimeout(function(){el.style.width=Math.round((val/maxFail)*100)+'%';},100);
  }
  setBar('bfc',__CRITICAL__);setBar('bfh',__HIGH__);setBar('bfm',__MEDIUM__);setBar('bfl',__LOW__);
})();

// Initialise table with all findings
applyFilters();

document.addEventListener('keydown',function(e){
  if(e.key==='Escape')closeDrawerDirect();
  if(e.key==='ArrowLeft')navDetail(-1);
  if(e.key==='ArrowRight')navDetail(1);
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){e.preventDefault();var s=document.getElementById('searchBox');if(s)s.focus();}
});

function exportCsv(){
  var rows=[['SubscriptionName','SubscriptionId','Domain','CheckId','CheckName','Status','Severity','Framework','FrameworkRef','Evidence','Recommendation']];
  FINDINGS.forEach(function(f){rows.push([f.sub,f.subId,f.domain,f.id,f.name,f.status,f.sev,f.fw,f.ref,f.ev,f.rec]);});
  var csv=rows.map(function(r){return r.map(function(c){return '"'+String(c||'').replace(/"/g,'""')+'"';}).join(',');}).join('\n');
  var blob=new Blob([csv],{type:'text/csv'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='LZ-Compliance-Export.csv';a.click();
  showToast('CSV exported');
}
</script>
</body>
</html>
'@

    # Token substitution
    $scoreDash = [math]::Round(($scoreBase / 100) * 314)
    $subCount = @($AllFindings | Select-Object -ExpandProperty SubscriptionName -Unique).Count
    $domCount = @($AllFindings | Select-Object -ExpandProperty Domain -Unique).Count

    $html = $html `
        -replace '__GENERATED_AT__', $GeneratedAt `
        -replace '__SUBSCRIPTIONS__', $subscriptions `
        -replace '__TOTAL__', $total `
        -replace '__PASS__', $pass `
        -replace '__FAIL__', $fail `
        -replace '__WARN__', $warning `
        -replace '__NA__', $na `
        -replace '__CRITICAL__', $critical `
        -replace '__HIGH__', $high `
        -replace '__MEDIUM__', $medium `
        -replace '__LOW__', $low `
        -replace '__SCORE_PCT__', $scoreBase `
        -replace '__SCORE_DASH__', $scoreDash `
        -replace '__SUB_COUNT__', $subCount `
        -replace '__DOMAIN_COUNT__', $domCount `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__DOMAINS_ASSESSED__', ($ScanParameters.Domains -join ', ') `
        -replace '__REQUIRED_TAGS__', ($ScanParameters.RequiredTags -join ', ') `
        -replace '__EXEC_TIME__', $ScanParameters.ExecutionTime `
        -replace '__FINDINGS_JSON__', $findingsJson `
        -replace '__DOMAIN_JSON__', $domainJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Test-AzureLandingZoneCompliance {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,
        [string[]]$SubscriptionIds,
        [string[]]$RequiredTags = @("Environment", "Owner", "CostCenter", "Application", "CreatedBy"),
        [switch]$ExportToCsv,
        [string]$CsvPath = "C:\Temp\LandingZoneCompliance-Report.csv",
        [ValidateSet("ManagementGroups", "RBAC", "Policy", "Networking", "Logging", "Defender", "Tagging", "Diagnostics")]
        [string[]]$IncludeDomains = @("ManagementGroups", "RBAC", "Policy", "Networking", "Logging", "Defender", "Tagging", "Diagnostics")
    )

    $startTime = Get-Date

    Write-LZBanner

    # Ensure required modules
    if (-not (Ensure-RequiredModules)) { return }

    # Authenticate if needed
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext) {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    # Resolve subscriptions
    if ($AllSubscriptions -or -not $SubscriptionIds) {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText = "All Subscriptions"
    }
    else {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count) requested)"
    }

    $subCount = $subscriptions.Count

    $sessionInfo = @{
        Tenant      = $currentContext.Tenant.Id
        Account     = $currentContext.Account.Id
        Environment = $currentContext.Environment.Name
    }

    # Display session info
    Write-LZSection -Title "Session Information" -Data @{
        "Tenant"      = $currentContext.Tenant.Id
        "Account"     = $currentContext.Account.Id
        "Environment" = $currentContext.Environment.Name
    }

    Write-LZSection -Title "Scan Parameters" -Data @{
        "Scope"         = "$scopeText ($subCount found)"
        "Domains"       = $IncludeDomains -join ", "
        "Required Tags" = $RequiredTags -join ", "
        "Export to CSV" = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Output Path"   = if ($ExportToCsv.IsPresent) { $CsvPath } else { "HTML only" }
    }

    Write-Host ""
    Write-Host "  Assessing Subscriptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $allFindings = @()
    $subIndex = 1

    foreach ($sub in $subscriptions) {
        Write-LZProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name
        Write-Host ""

        try {
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            if ($IncludeDomains -contains "ManagementGroups") {
                $allFindings += Test-ManagementGroupDomain -SubscriptionName $sub.Name -SubscriptionId $sub.Id -TenantId $currentContext.Tenant.Id
            }
            if ($IncludeDomains -contains "RBAC") {
                $allFindings += Test-RBACDomain -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }
            if ($IncludeDomains -contains "Policy") {
                $allFindings += Test-PolicyDomain -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }
            if ($IncludeDomains -contains "Networking") {
                $allFindings += Test-NetworkingDomain -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }
            if ($IncludeDomains -contains "Logging") {
                $allFindings += Test-LoggingDomain -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }
            if ($IncludeDomains -contains "Defender") {
                $allFindings += Test-DefenderDomain -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }
            if ($IncludeDomains -contains "Tagging") {
                $allFindings += Test-TaggingDomain -SubscriptionName $sub.Name -SubscriptionId $sub.Id -RequiredTags $RequiredTags
            }
            if ($IncludeDomains -contains "Diagnostics") {
                $allFindings += Test-DiagnosticsDomain -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }

            $subFindings = $allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id }
            $subFail = ($subFindings | Where-Object { $_.Status -eq "Fail" }).Count
            $subPass = ($subFindings | Where-Object { $_.Status -eq "Pass" }).Count

            Write-Host "  ✓ $($sub.Name.PadRight(45)) Pass: $subPass | Fail: $subFail" -ForegroundColor $(if ($subFail -gt 0) { "Yellow" } else { "Green" })
        }
        catch {
            Write-Host "  ✗ $($sub.Name) — Error: $($_.Exception.Message)" -ForegroundColor Red
        }

        $subIndex++
    }

    # Compute totals
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    $totalChecks = @($allFindings).Count
    $passCount = @($allFindings | Where-Object { $_.Status -eq "Pass" }).Count
    $failCount = @($allFindings | Where-Object { $_.Status -eq "Fail" }).Count
    $warnCount = @($allFindings | Where-Object { $_.Status -eq "Warning" }).Count
    $critCount = @($allFindings | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "Critical" }).Count
    $highCount = @($allFindings | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "High" }).Count
    $scoreBase = if ($totalChecks -gt 0) { [math]::Round(($passCount / $totalChecks) * 100) } else { 0 }

    Write-LZSummary -Data @{
        "Total Checks"      = $totalChecks
        "Passed"            = $passCount
        "Failed"            = $failCount
        "Warnings"          = $warnCount
        "Critical Failures" = $critCount
        "High Failures"     = $highCount
        "Compliance Score"  = "$scoreBase% ($passCount/$totalChecks checks passed)"
        "Execution Time"    = $duration
    }

    # Export CSV
    $csvExported = $false
    $htmlExported = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        if ($ExportToCsv) {
            try {
                $dir = Split-Path $CsvPath -Parent
                if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                $allFindings | Export-Csv -Path $CsvPath -NoTypeInformation -Force
                $csvExported = $true
            }
            catch { Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red }
        }

        # HTML Report
        try {
            $htmlPath = $CsvPath -replace '\.csv$', '.html'
            if (-not $htmlPath.EndsWith('.html')) { $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html') }

            $scanParams = @{
                Domains       = $IncludeDomains
                RequiredTags  = $RequiredTags
                ExecutionTime = $duration
            }

            $htmlContent = Generate-LZHtmlReport `
                -SessionInfo $sessionInfo `
                -ScanParameters $scanParams `
                -AllFindings $allFindings `
                -GeneratedAt (Get-Date -Format "dd MMM yyyy HH:mm:ss")

            $dir = Split-Path $htmlPath -Parent
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch { Write-Host "  ✗ HTML report failed: $_" -ForegroundColor Red }

        # Grid View
        $gridOpened = $false
        try {
            $allFindings | Out-GridView -Title "Landing Zone Compliance Findings"
            $gridOpened = $true
        }
        catch { Write-Host "  ⚠ Grid View not available in this session" -ForegroundColor Yellow }

        Write-LZOutputFiles `
            -CsvPath $(if ($csvExported) { $CsvPath } else { $null }) `
            -HtmlPath $(if ($htmlExported) { $htmlPath } else { $null }) `
            -GridViewOpened $gridOpened
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No findings collected. Verify module permissions and subscription access." -ForegroundColor Yellow
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
