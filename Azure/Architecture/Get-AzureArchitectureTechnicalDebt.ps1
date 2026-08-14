<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 14 August 2026
Modified-On     : 14 August 2026

.SYNOPSIS
    Identifies deviations from enterprise architecture standards and quantifies
    technical and security debt across one or more Azure subscriptions.

.DESCRIPTION
    Get-AzureArchitectureTechnicalDebt evaluates Azure resources against a built-in
    Enterprise Architecture Baseline across eight domains: Networking, Compute,
    Storage/Data, Identity/RBAC, Governance, Security, Resilience, and Operations.

    Each control has a Control ID, Category, Severity (Critical/High/Medium/Low),
    Weight, Detection Logic, and Remediation Guidance. The framework is designed
    for future externalization of controls to JSON/CSV without architectural change.

    Assessment layers (logically separated):
        1. Azure Data Collection  — Az module calls per resource type
        2. Control Evaluation     — each finding produced by a discrete control
        3. Scoring Engine         — weighted debt score per finding, category, subscription
        4. Results Aggregation    — structured PSCustomObject findings collection
        5. HTML Presentation      — Generate-TechnicalDebtHtml (presentation only)

    Default assessment outputs:
        - Overall Architecture Technical Debt Score (0–100, RAG rated)
        - Technical debt by category
        - Critical / High / Medium / Low finding counts
        - Resource-level findings with remediation guidance
        - Subscription-level and cross-subscription summary
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          detail drawer, category distribution, score ring, RAG indicators)

    Optional CSV export (-ExportToCsv) exports all findings to a flat file alongside
    the HTML dashboard.

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan.

.PARAMETER ExportToCsv
    Switch. Exports all architecture findings to the path given in -OutputPath
    (same base name, .csv extension). HTML dashboard is always generated.

.PARAMETER OutputPath
    Base path for all output files (HTML dashboard + optional CSV).
    HTML: same path with .html extension.
    CSV:  same path with .csv extension.
    Default: C:\Temp\AzureArchitectureTechnicalDebt-Report.html

.INPUTS
    None. Does not accept pipeline input.

.OUTPUTS
    None to the pipeline. Always writes an HTML dashboard to -OutputPath.
    Optionally writes a CSV when -ExportToCsv is specified.

.EXAMPLE
    Get-AzureArchitectureTechnicalDebt -AllSubscriptions

.EXAMPLE
    Get-AzureArchitectureTechnicalDebt -AllSubscriptions -ExportToCsv

.EXAMPLE
    Get-AzureArchitectureTechnicalDebt -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureArchitectureTechnicalDebt -AllSubscriptions -ExportToCsv -OutputPath "C:\Reports\TechDebt.html"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (14-Aug-2026) - Initial release. Eight-domain assessment covering
                            Networking, Compute, Storage/Data, Identity/RBAC,
                            Governance, Security, Resilience, and Operations.
                            Weighted debt scoring with RAG rating. CSV export
                            and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell modules: Az.Accounts, Az.Network, Az.Compute,
           Az.Storage, Az.Resources, Az.Security, Az.Monitor, Az.RecoveryServices.
           Installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at subscription scope.
        4. Microsoft.Security/assessments/read for Defender data (graceful fallback
           if unavailable — findings marked "Not Assessed").

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Management Group-scoped RBAC assignments are not enumerated when called
          at subscription context; only subscription-scope and below are assessed.
        - Get-AzRecoveryServicesVault can be slow in large environments.
        - Interactive Grid View requires a GUI session; skipped gracefully in
          headless/CI/Linux sessions. CSV/HTML output is unaffected.
        - Default -OutputPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -OutputPath on macOS/Linux PowerShell 7.
        - V1 covers major resource types for meaningful enterprise insight.
          Additional controls can be added per the extensible control framework
          without redesigning core architecture.

.LINK
    https://learn.microsoft.com/en-us/azure/architecture/framework/
    https://learn.microsoft.com/en-us/azure/well-architected/
    https://learn.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns
    https://learn.microsoft.com/en-us/azure/governance/

#>


#region ── [ Helper Functions — Console Output ] ──────────────────────────────

Function Write-CenteredText
{
    param(
        [string]$Text,
        [int]$Width    = 80,
        [string]$Color = "White"
    )
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-Banner
{
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Architecture Technical Debt Assessment v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-Section
{
    param(
        [string]$Title,
        [hashtable]$Data
    )
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys)
    {
        $value    = $Data[$key]
        $valColor = if ([string]::IsNullOrWhiteSpace($value)) { $value = "None"; "DarkGray" } else { "White" }
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-ScanProgress
{
    Write-Host ""
    Write-Host "  Scanning Subscriptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
}

Function Write-ProgressBar
{
    param(
        [int]$Current,
        [int]$Total,
        [string]$CurrentItem,
        [int]$BarWidth = 40
    )
    $percentage = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
    $completed  = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $remaining  = $BarWidth - $completed
    $bar        = ("█" * $completed) + ("░" * $remaining)

    Write-Host "`r" -NoNewline
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White

    if ($CurrentItem)
    {
        $maxLen      = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLen) { $CurrentItem.Substring(0, $maxLen - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-AssessmentSummary
{
    param([hashtable]$Data)
    Write-Host ""
    Write-Host "  Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys)
    {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(36) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-FindingsBySeverity
{
    param([array]$Findings)
    if ($Findings.Count -eq 0) { return }

    $critical = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $high     = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $medium   = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $low      = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count

    Write-Host ""
    Write-Host "  Findings by Severity" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Critical   : $critical" -ForegroundColor Red
    Write-Host "  High       : $high"     -ForegroundColor Yellow
    Write-Host "  Medium     : $medium"   -ForegroundColor DarkYellow
    Write-Host "  Low        : $low"      -ForegroundColor DarkGray
}

Function Write-OutputFiles
{
    param(
        [string]$CsvPath,
        [string]$HtmlPath,
        [bool]$GridViewOpened
    )
    Write-Host ""
    Write-Host "  Output Files" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    if ($CsvPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("CSV Export").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }
    if ($HtmlPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Dashboard").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }
    if ($GridViewOpened)
    {
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


#region ── [ Enterprise Architecture Baseline — Control Definitions ] ──────────

Function Get-ArchitectureControls
{
    # Returns the built-in Enterprise Architecture Baseline as a typed array.
    # Design note: this function is the single source of truth for all controls.
    # Future: replace with Import-ArchitectureControls reading from JSON/CSV.
    # Each control: ControlId, Category, Severity, Weight, ResourceType,
    #               Description, DetectionHint, RemediationGuidance

    return @(

        #── Networking ──────────────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId          = "NET-001"
            Category           = "Networking"
            Severity           = "High"
            Weight             = 8
            ResourceType       = "Microsoft.Network/virtualNetworks"
            Description        = "VNet has no NSG associations on any subnet"
            DetectionHint      = "VNet subnets without NetworkSecurityGroup"
            RemediationGuidance = "Associate an NSG with every subnet. NSGs provide Layer-4 traffic filtering and are the primary network micro-segmentation control. Subnets without NSGs allow unrestricted lateral movement."
        },
        [pscustomobject]@{
            ControlId          = "NET-002"
            Category           = "Networking"
            Severity           = "Critical"
            Weight             = 10
            ResourceType       = "Microsoft.Network/networkSecurityGroups"
            Description        = "NSG allows inbound RDP (3389) or SSH (22) from Internet (0.0.0.0/0 or *)"
            DetectionHint      = "NSG inbound rules with source * or 0.0.0.0/0 and port 3389 or 22"
            RemediationGuidance = "Remove open management port rules immediately. Use Azure Bastion for RDP/SSH access, or restrict source to known management CIDRs. Open management ports are among the most exploited attack surfaces in Azure."
        },
        [pscustomobject]@{
            ControlId          = "NET-003"
            Category           = "Networking"
            Severity           = "High"
            Weight             = 7
            ResourceType       = "Microsoft.Network/publicIPAddresses"
            Description        = "Public IP address is unattached (not associated with any resource)"
            DetectionHint      = "PublicIP with no IpConfiguration"
            RemediationGuidance = "Remove unattached Public IP addresses. Orphaned PIPs incur cost and expand the attack surface. Audit regularly and delete any that are no longer required."
        },
        [pscustomobject]@{
            ControlId          = "NET-004"
            Category           = "Networking"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Network/virtualNetworks"
            Description        = "VNet has no DDoS Protection Plan associated"
            DetectionHint      = "VNet without DdosProtectionPlan"
            RemediationGuidance = "Associate an Azure DDoS Protection Standard plan with production VNets. Basic protection covers volumetric attacks; Standard adds adaptive tuning, attack analytics, and SLA guarantees for enterprise workloads."
        },
        [pscustomobject]@{
            ControlId          = "NET-005"
            Category           = "Networking"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Network/networkSecurityGroups"
            Description        = "NSG has no diagnostic logs configured"
            DetectionHint      = "NSG without diagnostic settings"
            RemediationGuidance = "Enable NSG flow logs and send diagnostic logs to a Log Analytics Workspace. Flow log data is essential for network forensics, threat detection, and compliance audit trails."
        },

        #── Compute ─────────────────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId          = "CMP-001"
            Category           = "Compute"
            Severity           = "High"
            Weight             = 8
            ResourceType       = "Microsoft.Compute/virtualMachines"
            Description        = "VM uses unmanaged disks"
            DetectionHint      = "VM StorageProfile using VHD URIs instead of managed disks"
            RemediationGuidance = "Migrate all VM disks to Azure Managed Disks. Unmanaged disks require manual storage account management, do not support availability sets correctly, and lack role-based access control at disk level."
        },
        [pscustomobject]@{
            ControlId          = "CMP-002"
            Category           = "Compute"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Compute/disks"
            Description        = "Managed disk is unattached (orphaned)"
            DetectionHint      = "Disk with DiskState Unattached"
            RemediationGuidance = "Delete or snapshot unattached managed disks. Orphaned disks incur ongoing storage cost and may contain sensitive data that is no longer governed by a workload lifecycle."
        },
        [pscustomobject]@{
            ControlId          = "CMP-003"
            Category           = "Compute"
            Severity           = "Medium"
            Weight             = 6
            ResourceType       = "Microsoft.Compute/virtualMachines"
            Description        = "VM has no availability set or availability zone configured"
            DetectionHint      = "VM without AvailabilitySet and without zones"
            RemediationGuidance = "Deploy production VMs across Availability Zones or within Availability Sets. Single-instance VMs without zone or set configuration have no SLA guarantee for platform-level redundancy."
        },
        [pscustomobject]@{
            ControlId          = "CMP-004"
            Category           = "Compute"
            Severity           = "Low"
            Weight             = 3
            ResourceType       = "Microsoft.Compute/virtualMachines"
            Description        = "VM has no tags applied"
            DetectionHint      = "VM with empty Tags collection"
            RemediationGuidance = "Apply mandatory tags (e.g. Environment, Owner, CostCenter, Application) to all VMs. Tags are required for cost allocation, operational management, and automated governance enforcement."
        },
        [pscustomobject]@{
            ControlId          = "CMP-005"
            Category           = "Compute"
            Severity           = "High"
            Weight             = 7
            ResourceType       = "Microsoft.Compute/virtualMachines"
            Description        = "VM has no backup policy configured"
            DetectionHint      = "VM not protected by a Recovery Services vault"
            RemediationGuidance = "Enable Azure Backup for all production VMs and assign an appropriate backup policy. VMs without backup have no recovery point objective and cannot be restored after data loss or ransomware."
        },

        #── Storage / Data ───────────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId          = "STR-001"
            Category           = "Storage"
            Severity           = "Critical"
            Weight             = 10
            ResourceType       = "Microsoft.Storage/storageAccounts"
            Description        = "Storage account allows public blob access"
            DetectionHint      = "AllowBlobPublicAccess = true"
            RemediationGuidance = "Set AllowBlobPublicAccess to false on all storage accounts unless a specific public data use case is approved and documented. Public blob access is a leading cause of sensitive data exposure in Azure."
        },
        [pscustomobject]@{
            ControlId          = "STR-002"
            Category           = "Storage"
            Severity           = "High"
            Weight             = 8
            ResourceType       = "Microsoft.Storage/storageAccounts"
            Description        = "Storage account allows HTTP (non-HTTPS) traffic"
            DetectionHint      = "SupportsHttpsTrafficOnly = false"
            RemediationGuidance = "Enable 'Secure transfer required' on all storage accounts. HTTP traffic is unencrypted in transit and exposes data and SAS tokens to network interception."
        },
        [pscustomobject]@{
            ControlId          = "STR-003"
            Category           = "Storage"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Storage/storageAccounts"
            Description        = "Storage account does not have soft delete enabled for blobs"
            DetectionHint      = "BlobServiceProperties DeleteRetentionPolicy enabled = false"
            RemediationGuidance = "Enable blob soft delete with a minimum retention of 7 days (30 recommended for production). Soft delete provides a recovery window for accidental deletion and ransomware scenarios."
        },
        [pscustomobject]@{
            ControlId          = "STR-004"
            Category           = "Storage"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Storage/storageAccounts"
            Description        = "Storage account uses minimum TLS version below TLS 1.2"
            DetectionHint      = "MinimumTlsVersion is TLS1_0 or TLS1_1"
            RemediationGuidance = "Set MinimumTlsVersion to TLS1_2 on all storage accounts. TLS 1.0 and 1.1 contain known vulnerabilities and are deprecated by major compliance frameworks including PCI DSS and NIST."
        },
        [pscustomobject]@{
            ControlId          = "STR-005"
            Category           = "Storage"
            Severity           = "Low"
            Weight             = 3
            ResourceType       = "Microsoft.Storage/storageAccounts"
            Description        = "Storage account does not use a private endpoint"
            DetectionHint      = "No private endpoint connections on storage account"
            RemediationGuidance = "Where possible, use Private Endpoints to route storage traffic over the Azure backbone, eliminating public internet exposure. Prioritise storage accounts accessed from VNet-integrated workloads."
        },

        #── Identity / RBAC ──────────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId          = "IAM-001"
            Category           = "Identity"
            Severity           = "Critical"
            Weight             = 10
            ResourceType       = "Microsoft.Authorization/roleAssignments"
            Description        = "Subscription has direct user role assignments at Owner or Contributor scope"
            DetectionHint      = "RoleAssignment at subscription scope with Owner/Contributor for user principal type"
            RemediationGuidance = "Replace direct user Owner/Contributor assignments with group-based RBAC. Use PIM for privileged roles with just-in-time activation and approval workflows. Direct assignments bypass governance controls and auditability."
        },
        [pscustomobject]@{
            ControlId          = "IAM-002"
            Category           = "Identity"
            Severity           = "High"
            Weight             = 8
            ResourceType       = "Microsoft.Authorization/roleAssignments"
            Description        = "Guest user accounts (B2B) have privileged role assignments (Owner/Contributor)"
            DetectionHint      = "RoleAssignment with Owner or Contributor for guest user (UserType = Guest)"
            RemediationGuidance = "Remove Owner and Contributor role assignments from guest accounts. External identities should have the minimum required access using specific built-in or custom roles. Review all guest role assignments in Entra ID Privileged Identity Management."
        },
        [pscustomobject]@{
            ControlId          = "IAM-003"
            Category           = "Identity"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Authorization/roleAssignments"
            Description        = "Custom RBAC roles with broad wildcard (*) action permissions exist"
            DetectionHint      = "Custom role definitions with Actions containing '*'"
            RemediationGuidance = "Replace wildcard custom roles with granular action lists following least-privilege principles. Wildcard actions grant all current and future permissions in the provider namespace, violating zero-trust design."
        },

        #── Governance ───────────────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId          = "GOV-001"
            Category           = "Governance"
            Severity           = "High"
            Weight             = 7
            ResourceType       = "Microsoft.Resources/subscriptions"
            Description        = "Subscription has no resource locks applied at subscription or resource group level"
            DetectionHint      = "No management locks at subscription or RG scope"
            RemediationGuidance = "Apply CanNotDelete or ReadOnly locks to critical resource groups and subscriptions. Locks prevent accidental deletion and unauthorised modification of production resources outside of approved change processes."
        },
        [pscustomobject]@{
            ControlId          = "GOV-002"
            Category           = "Governance"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Resources/resourceGroups"
            Description        = "Resource groups with no tags applied"
            DetectionHint      = "ResourceGroup with empty Tags"
            RemediationGuidance = "Apply mandatory tags to all resource groups. Tags at resource group level drive cost allocation, operational automation, and compliance reporting across the Azure estate."
        },
        [pscustomobject]@{
            ControlId          = "GOV-003"
            Category           = "Governance"
            Severity           = "Low"
            Weight             = 3
            ResourceType       = "Microsoft.Resources/subscriptions"
            Description        = "Subscription has no assigned budget alerts"
            DetectionHint      = "No budget configured at subscription scope"
            RemediationGuidance = "Create budget alerts at subscription level with notification thresholds at 80% and 100% of expected spend. Budget alerts are the minimum financial governance control for any production subscription."
        },

        #── Security ─────────────────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId          = "SEC-001"
            Category           = "Security"
            Severity           = "Critical"
            Weight             = 10
            ResourceType       = "Microsoft.Security/pricings"
            Description        = "Microsoft Defender for Cloud is not enabled (Standard/Defender tier) for key resource types"
            DetectionHint      = "Defender pricing tier = Free for VirtualMachines, StorageAccounts, KeyVaults, SqlServers"
            RemediationGuidance = "Enable Defender for Cloud Standard tier for all critical resource types. The free tier provides only basic security posture; Standard adds threat detection, vulnerability assessment, and Defender for Endpoint integration."
        },
        [pscustomobject]@{
            ControlId          = "SEC-002"
            Category           = "Security"
            Severity           = "High"
            Weight             = 8
            ResourceType       = "Microsoft.KeyVault/vaults"
            Description        = "Key Vault does not have soft delete enabled"
            DetectionHint      = "KeyVault EnableSoftDelete = false or not set"
            RemediationGuidance = "Enable soft delete and purge protection on all Key Vaults. Without soft delete, deleted secrets, keys, and certificates cannot be recovered. Purge protection prevents permanent deletion during the retention window."
        },
        [pscustomobject]@{
            ControlId          = "SEC-003"
            Category           = "Security"
            Severity           = "High"
            Weight             = 7
            ResourceType       = "Microsoft.KeyVault/vaults"
            Description        = "Key Vault allows public network access without network rules"
            DetectionHint      = "KeyVault with PublicNetworkAccess Enabled and no virtual network rules"
            RemediationGuidance = "Restrict Key Vault network access using virtual network service endpoints or private endpoints. Limit public access to specific approved IP ranges where private connectivity is not yet feasible."
        },
        [pscustomobject]@{
            ControlId          = "SEC-004"
            Category           = "Security"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Security/securityContacts"
            Description        = "No security contact email configured in Microsoft Defender for Cloud"
            DetectionHint      = "No security contacts defined or email is empty"
            RemediationGuidance = "Configure a security contact email and phone number in Defender for Cloud settings. Security alerts and high-severity findings are notified to the security contact; without configuration, critical alerts may go unnoticed."
        },

        #── Resilience ───────────────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId          = "RES-001"
            Category           = "Resilience"
            Severity           = "High"
            Weight             = 8
            ResourceType       = "Microsoft.RecoveryServices/vaults"
            Description        = "No Recovery Services vault exists in the subscription"
            DetectionHint      = "Zero Recovery Services vaults in subscription"
            RemediationGuidance = "Create at least one Recovery Services vault and enroll critical VMs and workloads in backup policies. Without a vault, no Azure Backup or Site Recovery capabilities are available."
        },
        [pscustomobject]@{
            ControlId          = "RES-002"
            Category           = "Resilience"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Network/loadBalancers"
            Description        = "Load Balancer is using Basic SKU (not Standard)"
            DetectionHint      = "LoadBalancer Sku.Name = Basic"
            RemediationGuidance = "Migrate Basic SKU Load Balancers to Standard SKU. Basic LB will be retired and does not support Availability Zones, HTTPS health probes, or SLA guarantees required for production workloads."
        },
        [pscustomobject]@{
            ControlId          = "RES-003"
            Category           = "Resilience"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Network/publicIPAddresses"
            Description        = "Public IP address uses Basic SKU (not Standard)"
            DetectionHint      = "PublicIP Sku.Name = Basic"
            RemediationGuidance = "Migrate Basic SKU Public IPs to Standard SKU. Basic Public IPs are open by default (no NSG required), are not zone-redundant, and are scheduled for retirement. Standard provides zone redundancy and is closed by default."
        },

        #── Operations ───────────────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId          = "OPS-001"
            Category           = "Operations"
            Severity           = "High"
            Weight             = 7
            ResourceType       = "Microsoft.Insights/diagnosticSettings"
            Description        = "Key resources have no diagnostic settings configured"
            DetectionHint      = "VMs, Key Vaults, NSGs, Storage Accounts without diagnostic settings"
            RemediationGuidance = "Enable diagnostic settings and send logs to a Log Analytics Workspace for all key resource types. Diagnostic logs are required for security monitoring, incident response, compliance reporting, and operational insight."
        },
        [pscustomobject]@{
            ControlId          = "OPS-002"
            Category           = "Operations"
            Severity           = "Medium"
            Weight             = 5
            ResourceType       = "Microsoft.Insights/activityLogAlerts"
            Description        = "No Activity Log alerts configured for critical operations"
            DetectionHint      = "No activity log alert rules in subscription"
            RemediationGuidance = "Configure Activity Log alerts for critical operations: delete resource group, create/update policy assignment, modify role assignment, and security policy changes. These are the minimum operational awareness controls."
        },
        [pscustomobject]@{
            ControlId          = "OPS-003"
            Category           = "Operations"
            Severity           = "Low"
            Weight             = 3
            ResourceType       = "Microsoft.Resources/subscriptions"
            Description        = "No Log Analytics Workspace found in subscription"
            DetectionHint      = "Zero Log Analytics Workspaces in subscription"
            RemediationGuidance = "Create a centralised Log Analytics Workspace and route all diagnostic logs, security events, and platform logs to it. A shared workspace is the foundation for SIEM integration, monitoring, and operational analytics."
        }
    )
}

#endregion


#region ── [ Scoring Engine ] ──────────────────────────────────────────────────

Function Get-DebtScoreLabel
{
    param([int]$Score)
    if ($Score -le 20) { return "Critical" }
    elseif ($Score -le 40) { return "High" }
    elseif ($Score -le 65) { return "Medium" }
    elseif ($Score -le 85) { return "Low" }
    else { return "Healthy" }
}

Function Get-RagStatus
{
    param([int]$Score)
    if ($Score -le 40) { return "Red" }
    elseif ($Score -le 70) { return "Amber" }
    else { return "Green" }
}

Function Invoke-ScoringEngine
{
    param(
        [array]$Findings,
        [array]$Controls
    )

    # Maximum possible debt points = sum of all control weights × finding volume.
    # Score = 100 - normalized debt percentage, clamped to 0.
    # Each finding contributes its control Weight to the raw debt total.

    $totalWeight   = ($Controls | Measure-Object -Property Weight -Sum).Sum
    $rawDebt       = ($Findings | ForEach-Object { $_.Weight } | Measure-Object -Sum).Sum

    # Normalize to 0–100 (100 = zero findings, 0 = max possible debt)
    $maxPossible   = $totalWeight * 3   # assume max 3 findings per control for normalization
    $normalizedPct = [math]::Min(100, [math]::Round(($rawDebt / [math]::Max($maxPossible, 1)) * 100))
    $score         = [math]::Max(0, 100 - $normalizedPct)

    return @{
        Score      = $score
        RawDebt    = $rawDebt
        RagStatus  = Get-RagStatus -Score $score
        ScoreLabel = Get-DebtScoreLabel -Score $score
    }
}

Function Invoke-CategoryScoring
{
    param(
        [array]$Findings,
        [array]$Controls
    )

    $categories  = $Controls | Select-Object -ExpandProperty Category -Unique
    $categoryMap = @{}

    foreach ($cat in $categories)
    {
        $catControls = @($Controls | Where-Object { $_.Category -eq $cat })
        $catFindings = @($Findings | Where-Object { $_.Category -eq $cat })
        $catWeight   = ($catControls | Measure-Object -Property Weight -Sum).Sum
        $catDebt     = ($catFindings | ForEach-Object { $_.Weight } | Measure-Object -Sum).Sum
        $maxPossible = $catWeight * 3
        $normalized  = [math]::Min(100, [math]::Round(($catDebt / [math]::Max($maxPossible, 1)) * 100))
        $catScore    = [math]::Max(0, 100 - $normalized)

        $categoryMap[$cat] = @{
            Score        = $catScore
            RagStatus    = Get-RagStatus -Score $catScore
            FindingCount = $catFindings.Count
            DebtPoints   = $catDebt
            Critical     = @($catFindings | Where-Object { $_.Severity -eq "Critical" }).Count
            High         = @($catFindings | Where-Object { $_.Severity -eq "High" }).Count
            Medium       = @($catFindings | Where-Object { $_.Severity -eq "Medium" }).Count
            Low          = @($catFindings | Where-Object { $_.Severity -eq "Low" }).Count
        }
    }

    return $categoryMap
}

#endregion


#region ── [ Control Evaluators — Data Collection + Detection ] ────────────────

Function Test-NetworkingControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [array]$Controls
    )

    $findings = @()
    $netControls = @($Controls | Where-Object { $_.Category -eq "Networking" })

    # NET-001: VNet subnets without NSG
    try
    {
        $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop)
        foreach ($vnet in $vnets)
        {
            $unprotectedSubnets = @($vnet.Subnets | Where-Object {
                $_.Name -ne "AzureBastionSubnet" -and
                $_.Name -ne "GatewaySubnet" -and
                $null -eq $_.NetworkSecurityGroup
            })

            if ($unprotectedSubnets.Count -gt 0)
            {
                $ctrl = $netControls | Where-Object { $_.ControlId -eq "NET-001" }
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $vnet.Name `
                    -ResourceType "VirtualNetwork" `
                    -ResourceGroup $vnet.ResourceGroupName `
                    -Detail "Subnets without NSG: $($unprotectedSubnets.Name -join ', ')" `
                    -DebtPoints $ctrl.Weight
            }
        }
    }
    catch { Write-Verbose "NET-001: Could not retrieve VNets — $($_.Exception.Message)" }

    # NET-002: NSG with open management ports from Internet
    try
    {
        $nsgs = @(Get-AzNetworkSecurityGroup -ErrorAction Stop)
        foreach ($nsg in $nsgs)
        {
            $dangerousRules = @($nsg.SecurityRules | Where-Object {
                $_.Direction -eq "Inbound" -and
                $_.Access    -eq "Allow" -and
                ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "0.0.0.0/0" -or $_.SourceAddressPrefix -eq "Internet") -and
                ($_.DestinationPortRange -eq "3389" -or $_.DestinationPortRange -eq "22" -or
                 $_.DestinationPortRange -eq "*"    -or
                 ($_.DestinationPortRanges -and ($_.DestinationPortRanges -contains "3389" -or $_.DestinationPortRanges -contains "22")))
            })

            if ($dangerousRules.Count -gt 0)
            {
                $ctrl = $netControls | Where-Object { $_.ControlId -eq "NET-002" }
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $nsg.Name `
                    -ResourceType "NetworkSecurityGroup" `
                    -ResourceGroup $nsg.ResourceGroupName `
                    -Detail "Rules exposing management ports to Internet: $($dangerousRules.Name -join ', ')" `
                    -DebtPoints $ctrl.Weight
            }
        }

        # NET-005: NSG with no diagnostic settings (sample check — requires Az.Monitor)
        foreach ($nsg in $nsgs)
        {
            try
            {
                $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $nsg.Id -ErrorAction Stop)
                if ($diagSettings.Count -eq 0)
                {
                    $ctrl = $netControls | Where-Object { $_.ControlId -eq "NET-005" }
                    $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                        -SubscriptionName $SubscriptionName `
                        -ResourceName $nsg.Name `
                        -ResourceType "NetworkSecurityGroup" `
                        -ResourceGroup $nsg.ResourceGroupName `
                        -Detail "No diagnostic settings configured — NSG flow logs not captured" `
                        -DebtPoints $ctrl.Weight
                }
            }
            catch { Write-Verbose "NET-005: Could not retrieve diagnostic settings for $($nsg.Name)" }
        }
    }
    catch { Write-Verbose "NET-002/005: Could not retrieve NSGs — $($_.Exception.Message)" }

    # NET-003: Unattached Public IPs + NET-003-B: Basic SKU PIPs (RES-003 evaluated here for efficiency)
    try
    {
        $pips = @(Get-AzPublicIpAddress -ErrorAction Stop)
        $ctrl003 = $netControls | Where-Object { $_.ControlId -eq "NET-003" }
        $ctrl004 = $netControls | Where-Object { $_.ControlId -eq "NET-004" }

        foreach ($pip in $pips)
        {
            if ($null -eq $pip.IpConfiguration -and [string]::IsNullOrWhiteSpace($pip.IpConfiguration.Id))
            {
                $findings += New-Finding -Control $ctrl003 -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $pip.Name `
                    -ResourceType "PublicIPAddress" `
                    -ResourceGroup $pip.ResourceGroupName `
                    -Detail "Public IP ($($pip.PublicIpAllocationMethod)) has no associated resource" `
                    -DebtPoints $ctrl003.Weight
            }
        }

        # NET-004: VNets without DDoS protection
        $vnets2 = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)
        foreach ($vnet in $vnets2)
        {
            if ($null -eq $vnet.DdosProtectionPlan -or -not $vnet.EnableDdosProtection)
            {
                $findings += New-Finding -Control $ctrl004 -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $vnet.Name `
                    -ResourceType "VirtualNetwork" `
                    -ResourceGroup $vnet.ResourceGroupName `
                    -Detail "VNet has no DDoS Protection Plan — only Azure Basic DDoS protection active" `
                    -DebtPoints $ctrl004.Weight
            }
        }
    }
    catch { Write-Verbose "NET-003/004: Could not retrieve Public IPs or VNets — $($_.Exception.Message)" }

    return $findings
}

Function Test-ComputeControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [array]$Controls
    )

    $findings    = @()
    $cmpControls = @($Controls | Where-Object { $_.Category -eq "Compute" })

    try
    {
        $vms = @(Get-AzVM -ErrorAction Stop)

        # Get all protected VMs from Recovery Services vaults (for CMP-005)
        $protectedVmIds = @()
        try
        {
            $vaults = @(Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue)
            foreach ($vault in $vaults)
            {
                try
                {
                    Set-AzRecoveryServicesVaultContext -Vault $vault -ErrorAction SilentlyContinue
                    $items = @(Get-AzRecoveryServicesBackupItem -WorkloadType AzureVM -BackupManagementType AzureVM -ErrorAction SilentlyContinue)
                    $protectedVmIds += $items | ForEach-Object { $_.VirtualMachineId }
                }
                catch { Write-Verbose "CMP-005: Could not list backup items for vault $($vault.Name)" }
            }
        }
        catch { Write-Verbose "CMP-005: Could not retrieve Recovery Services vaults" }

        foreach ($vm in $vms)
        {
            # CMP-001: Unmanaged disks
            $hasManagedDisks = $null -ne $vm.StorageProfile.OsDisk.ManagedDisk
            if (-not $hasManagedDisks)
            {
                $ctrl = $cmpControls | Where-Object { $_.ControlId -eq "CMP-001" }
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $vm.Name `
                    -ResourceType "VirtualMachine" `
                    -ResourceGroup $vm.ResourceGroupName `
                    -Detail "OS disk uses unmanaged VHD — managed disk migration required" `
                    -DebtPoints $ctrl.Weight
            }

            # CMP-003: No availability set or zone
            $hasAvSet  = $null -ne $vm.AvailabilitySetReference
            $hasZones  = $null -ne $vm.Zones -and $vm.Zones.Count -gt 0
            if (-not $hasAvSet -and -not $hasZones)
            {
                $ctrl = $cmpControls | Where-Object { $_.ControlId -eq "CMP-003" }
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $vm.Name `
                    -ResourceType "VirtualMachine" `
                    -ResourceGroup $vm.ResourceGroupName `
                    -Detail "VM has no Availability Set or Availability Zone — no platform redundancy SLA" `
                    -DebtPoints $ctrl.Weight
            }

            # CMP-004: No tags
            if ($null -eq $vm.Tags -or $vm.Tags.Count -eq 0)
            {
                $ctrl = $cmpControls | Where-Object { $_.ControlId -eq "CMP-004" }
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $vm.Name `
                    -ResourceType "VirtualMachine" `
                    -ResourceGroup $vm.ResourceGroupName `
                    -Detail "VM has no tags — cannot be attributed to owner, cost center, or environment" `
                    -DebtPoints $ctrl.Weight
            }

            # CMP-005: No backup
            $isProtected = $protectedVmIds | Where-Object { $_ -like "*$($vm.Id)*" -or $_ -eq $vm.Id }
            if (-not $isProtected)
            {
                $ctrl = $cmpControls | Where-Object { $_.ControlId -eq "CMP-005" }
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $vm.Name `
                    -ResourceType "VirtualMachine" `
                    -ResourceGroup $vm.ResourceGroupName `
                    -Detail "VM is not enrolled in any Azure Backup policy — no recovery point available" `
                    -DebtPoints $ctrl.Weight
            }
        }
    }
    catch { Write-Verbose "Compute controls: Could not retrieve VMs — $($_.Exception.Message)" }

    # CMP-002: Orphaned managed disks
    try
    {
        $disks = @(Get-AzDisk -ErrorAction Stop | Where-Object { $_.DiskState -eq "Unattached" })
        $ctrl  = $cmpControls | Where-Object { $_.ControlId -eq "CMP-002" }
        foreach ($disk in $disks)
        {
            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $disk.Name `
                -ResourceType "ManagedDisk" `
                -ResourceGroup $disk.ResourceGroupName `
                -Detail "Disk state: Unattached. Size: $($disk.DiskSizeGB) GB. SKU: $($disk.Sku.Name)" `
                -DebtPoints $ctrl.Weight
        }
    }
    catch { Write-Verbose "CMP-002: Could not retrieve managed disks — $($_.Exception.Message)" }

    return $findings
}

Function Test-StorageControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [array]$Controls
    )

    $findings    = @()
    $strControls = @($Controls | Where-Object { $_.Category -eq "Storage" })

    try
    {
        $accounts = @(Get-AzStorageAccount -ErrorAction Stop)

        foreach ($sa in $accounts)
        {
            # STR-001: Public blob access
            if ($sa.AllowBlobPublicAccess -eq $true)
            {
                $ctrl = $strControls | Where-Object { $_.ControlId -eq "STR-001" }
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $sa.StorageAccountName `
                    -ResourceType "StorageAccount" `
                    -ResourceGroup $sa.ResourceGroupName `
                    -Detail "AllowBlobPublicAccess = true — any container can be made public" `
                    -DebtPoints $ctrl.Weight
            }

            # STR-002: HTTP allowed
            if ($sa.EnableHttpsTrafficOnly -eq $false)
            {
                $ctrl = $strControls | Where-Object { $_.ControlId -eq "STR-002" }
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $sa.StorageAccountName `
                    -ResourceType "StorageAccount" `
                    -ResourceGroup $sa.ResourceGroupName `
                    -Detail "Secure transfer (HTTPS only) is disabled — HTTP requests accepted" `
                    -DebtPoints $ctrl.Weight
            }

            # STR-004: TLS version below 1.2
            if ($sa.MinimumTlsVersion -eq "TLS1_0" -or $sa.MinimumTlsVersion -eq "TLS1_1")
            {
                $ctrl = $strControls | Where-Object { $_.ControlId -eq "STR-004" }
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $sa.StorageAccountName `
                    -ResourceType "StorageAccount" `
                    -ResourceGroup $sa.ResourceGroupName `
                    -Detail "Minimum TLS version: $($sa.MinimumTlsVersion) — deprecated protocol allowed" `
                    -DebtPoints $ctrl.Weight
            }

            # STR-005: No private endpoint
            if ($null -eq $sa.PrivateEndpointConnections -or $sa.PrivateEndpointConnections.Count -eq 0)
            {
                $ctrl = $strControls | Where-Object { $_.ControlId -eq "STR-005" }
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $sa.StorageAccountName `
                    -ResourceType "StorageAccount" `
                    -ResourceGroup $sa.ResourceGroupName `
                    -Detail "No private endpoint connections — storage accessible over public internet" `
                    -DebtPoints $ctrl.Weight
            }

            # STR-003: Blob soft delete
            try
            {
                $ctx        = New-AzStorageContext -StorageAccountName $sa.StorageAccountName -UseConnectedAccount -ErrorAction Stop
                $blobProps  = Get-AzStorageServiceProperty -ServiceType Blob -Context $ctx -ErrorAction Stop

                if (-not $blobProps.DeleteRetentionPolicy.Enabled)
                {
                    $ctrl = $strControls | Where-Object { $_.ControlId -eq "STR-003" }
                    $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                        -SubscriptionName $SubscriptionName `
                        -ResourceName $sa.StorageAccountName `
                        -ResourceType "StorageAccount" `
                        -ResourceGroup $sa.ResourceGroupName `
                        -Detail "Blob soft delete is disabled — no recovery window for deleted blobs" `
                        -DebtPoints $ctrl.Weight
                }
            }
            catch { Write-Verbose "STR-003: Could not retrieve blob properties for $($sa.StorageAccountName)" }
        }
    }
    catch { Write-Verbose "Storage controls: Could not retrieve storage accounts — $($_.Exception.Message)" }

    return $findings
}

Function Test-IdentityControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [array]$Controls
    )

    $findings    = @()
    $iamControls = @($Controls | Where-Object { $_.Category -eq "Identity" })

    # IAM-001: Direct user Owner/Contributor at subscription scope
    try
    {
        $scope       = "/subscriptions/$SubscriptionId"
        $assignments = @(Get-AzRoleAssignment -Scope $scope -ErrorAction Stop)
        $ctrl001     = $iamControls | Where-Object { $_.ControlId -eq "IAM-001" }
        $ctrl002     = $iamControls | Where-Object { $_.ControlId -eq "IAM-002" }

        $directPriv = @($assignments | Where-Object {
            $_.Scope        -eq $scope -and
            ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor") -and
            $_.ObjectType   -eq "User"
        })

        foreach ($a in $directPriv)
        {
            $findings += New-Finding -Control $ctrl001 -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $a.SignInName `
                -ResourceType "RoleAssignment" `
                -ResourceGroup "Subscription" `
                -Detail "User '$($a.SignInName)' has direct '$($a.RoleDefinitionName)' at subscription scope" `
                -DebtPoints $ctrl001.Weight
        }

        # IAM-002: Guest users with Owner/Contributor
        $guestPriv = @($assignments | Where-Object {
            ($_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Contributor") -and
            $_.SignInName -like "*#EXT#*"
        })

        foreach ($g in $guestPriv)
        {
            $findings += New-Finding -Control $ctrl002 -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $g.SignInName `
                -ResourceType "RoleAssignment" `
                -ResourceGroup "Subscription" `
                -Detail "Guest account '$($g.SignInName)' holds '$($g.RoleDefinitionName)' — privileged external access" `
                -DebtPoints $ctrl002.Weight
        }
    }
    catch { Write-Verbose "IAM-001/002: Could not retrieve role assignments — $($_.Exception.Message)" }

    # IAM-003: Custom roles with wildcard actions
    try
    {
        $customRoles  = @(Get-AzRoleDefinition -Custom -ErrorAction Stop)
        $ctrl003      = $iamControls | Where-Object { $_.ControlId -eq "IAM-003" }

        foreach ($role in $customRoles)
        {
            if ($role.Actions -contains "*")
            {
                $findings += New-Finding -Control $ctrl003 -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $role.Name `
                    -ResourceType "RoleDefinition" `
                    -ResourceGroup "Subscription" `
                    -Detail "Custom role '$($role.Name)' (ID: $($role.Id)) contains wildcard Actions — overprivileged by design" `
                    -DebtPoints $ctrl003.Weight
            }
        }
    }
    catch { Write-Verbose "IAM-003: Could not retrieve custom role definitions — $($_.Exception.Message)" }

    return $findings
}

Function Test-GovernanceControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [array]$Controls
    )

    $findings    = @()
    $govControls = @($Controls | Where-Object { $_.Category -eq "Governance" })

    # GOV-001: No management locks at subscription or RG level
    try
    {
        $locks = @(Get-AzResourceLock -ErrorAction Stop)
        if ($locks.Count -eq 0)
        {
            $ctrl = $govControls | Where-Object { $_.ControlId -eq "GOV-001" }
            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $SubscriptionName `
                -ResourceType "Subscription" `
                -ResourceGroup "Subscription" `
                -Detail "Zero management locks found — no protection against accidental deletion or modification" `
                -DebtPoints $ctrl.Weight
        }
    }
    catch { Write-Verbose "GOV-001: Could not retrieve resource locks — $($_.Exception.Message)" }

    # GOV-002: Resource groups without tags
    try
    {
        $rgs  = @(Get-AzResourceGroup -ErrorAction Stop)
        $ctrl = $govControls | Where-Object { $_.ControlId -eq "GOV-002" }

        foreach ($rg in $rgs)
        {
            if ($null -eq $rg.Tags -or $rg.Tags.Count -eq 0)
            {
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName $rg.ResourceGroupName `
                    -ResourceType "ResourceGroup" `
                    -ResourceGroup $rg.ResourceGroupName `
                    -Detail "Resource group has no tags — unattributable in cost and operational reporting" `
                    -DebtPoints $ctrl.Weight
            }
        }
    }
    catch { Write-Verbose "GOV-002: Could not retrieve resource groups — $($_.Exception.Message)" }

    # GOV-003: No budget alerts
    try
    {
        $budgets = @(Get-AzConsumptionBudget -ErrorAction Stop)
        if ($budgets.Count -eq 0)
        {
            $ctrl = $govControls | Where-Object { $_.ControlId -eq "GOV-003" }
            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $SubscriptionName `
                -ResourceType "Subscription" `
                -ResourceGroup "Subscription" `
                -Detail "No consumption budgets configured — no financial alert boundary defined" `
                -DebtPoints $ctrl.Weight
        }
    }
    catch { Write-Verbose "GOV-003: Could not retrieve budgets (may require Az.Billing) — $($_.Exception.Message)" }

    return $findings
}

Function Test-SecurityControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [array]$Controls
    )

    $findings    = @()
    $secControls = @($Controls | Where-Object { $_.Category -eq "Security" })

    # SEC-001: Defender for Cloud tiers
    try
    {
        $pricings      = @(Get-AzSecurityPricing -ErrorAction Stop)
        $keyPlanTypes  = @("VirtualMachines", "StorageAccounts", "KeyVaults", "SqlServers")
        $ctrl          = $secControls | Where-Object { $_.ControlId -eq "SEC-001" }

        foreach ($plan in $pricings | Where-Object { $keyPlanTypes -contains $_.Name })
        {
            if ($plan.PricingTier -eq "Free")
            {
                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName `
                    -ResourceName "Defender: $($plan.Name)" `
                    -ResourceType "DefenderPlan" `
                    -ResourceGroup "Subscription" `
                    -Detail "Defender for '$($plan.Name)' is on Free tier — no threat detection or vulnerability assessment" `
                    -DebtPoints $ctrl.Weight
            }
        }
    }
    catch { Write-Verbose "SEC-001: Could not retrieve Defender pricing tiers — $($_.Exception.Message)" }

    # SEC-002 / SEC-003: Key Vault soft delete and network rules
    try
    {
        $vaults  = @(Get-AzKeyVault -ErrorAction Stop)
        $ctrl002 = $secControls | Where-Object { $_.ControlId -eq "SEC-002" }
        $ctrl003 = $secControls | Where-Object { $_.ControlId -eq "SEC-003" }

        foreach ($kvRef in $vaults)
        {
            try
            {
                $kv = Get-AzKeyVault -VaultName $kvRef.VaultName -ResourceGroupName $kvRef.ResourceGroupName -ErrorAction Stop

                # SEC-002: Soft delete
                if (-not $kv.EnableSoftDelete)
                {
                    $findings += New-Finding -Control $ctrl002 -SubscriptionId $SubscriptionId `
                        -SubscriptionName $SubscriptionName `
                        -ResourceName $kv.VaultName `
                        -ResourceType "KeyVault" `
                        -ResourceGroup $kv.ResourceGroupName `
                        -Detail "Soft delete is disabled — deleted secrets/keys cannot be recovered" `
                        -DebtPoints $ctrl002.Weight
                }

                # SEC-003: Public network access without network rules
                $hasNetworkRules = ($null -ne $kv.NetworkAcls -and
                    ($kv.NetworkAcls.VirtualNetworkResourceIds.Count -gt 0 -or
                     $kv.NetworkAcls.IpAddressRanges.Count -gt 0))

                if ($kv.PublicNetworkAccess -eq "Enabled" -and -not $hasNetworkRules)
                {
                    $findings += New-Finding -Control $ctrl003 -SubscriptionId $SubscriptionId `
                        -SubscriptionName $SubscriptionName `
                        -ResourceName $kv.VaultName `
                        -ResourceType "KeyVault" `
                        -ResourceGroup $kv.ResourceGroupName `
                        -Detail "Public network access enabled with no virtual network rules or IP restrictions" `
                        -DebtPoints $ctrl003.Weight
                }
            }
            catch { Write-Verbose "SEC-002/003: Could not get Key Vault details for $($kvRef.VaultName)" }
        }
    }
    catch { Write-Verbose "SEC-002/003: Could not retrieve Key Vaults — $($_.Exception.Message)" }

    # SEC-004: Security contacts
    try
    {
        $contacts = @(Get-AzSecurityContact -ErrorAction Stop)
        if ($contacts.Count -eq 0 -or [string]::IsNullOrWhiteSpace(($contacts | Select-Object -First 1).Email))
        {
            $ctrl = $secControls | Where-Object { $_.ControlId -eq "SEC-004" }
            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $SubscriptionName `
                -ResourceType "Subscription" `
                -ResourceGroup "Subscription" `
                -Detail "No security contact email configured — critical Defender alerts will not be notified" `
                -DebtPoints $ctrl.Weight
        }
    }
    catch { Write-Verbose "SEC-004: Could not retrieve security contacts — $($_.Exception.Message)" }

    return $findings
}

Function Test-ResilienceControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [array]$Controls
    )

    $findings    = @()
    $resControls = @($Controls | Where-Object { $_.Category -eq "Resilience" })

    # RES-001: No Recovery Services vault
    try
    {
        $vaults = @(Get-AzRecoveryServicesVault -ErrorAction Stop)
        if ($vaults.Count -eq 0)
        {
            $ctrl = $resControls | Where-Object { $_.ControlId -eq "RES-001" }
            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $SubscriptionName `
                -ResourceType "Subscription" `
                -ResourceGroup "Subscription" `
                -Detail "No Recovery Services vault found — Azure Backup and Site Recovery unavailable" `
                -DebtPoints $ctrl.Weight
        }
    }
    catch { Write-Verbose "RES-001: Could not retrieve Recovery Services vaults — $($_.Exception.Message)" }

    # RES-002: Basic SKU Load Balancers
    try
    {
        $lbs  = @(Get-AzLoadBalancer -ErrorAction Stop | Where-Object { $_.Sku.Name -eq "Basic" })
        $ctrl = $resControls | Where-Object { $_.ControlId -eq "RES-002" }
        foreach ($lb in $lbs)
        {
            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $lb.Name `
                -ResourceType "LoadBalancer" `
                -ResourceGroup $lb.ResourceGroupName `
                -Detail "Load Balancer SKU is Basic — no zone redundancy, retirement pending" `
                -DebtPoints $ctrl.Weight
        }
    }
    catch { Write-Verbose "RES-002: Could not retrieve Load Balancers — $($_.Exception.Message)" }

    # RES-003: Basic SKU Public IPs
    try
    {
        $basicPips = @(Get-AzPublicIpAddress -ErrorAction Stop | Where-Object { $_.Sku.Name -eq "Basic" })
        $ctrl      = $resControls | Where-Object { $_.ControlId -eq "RES-003" }
        foreach ($pip in $basicPips)
        {
            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $pip.Name `
                -ResourceType "PublicIPAddress" `
                -ResourceGroup $pip.ResourceGroupName `
                -Detail "Public IP SKU is Basic — no zone redundancy, open by default, retirement pending" `
                -DebtPoints $ctrl.Weight
        }
    }
    catch { Write-Verbose "RES-003: Could not retrieve Public IPs — $($_.Exception.Message)" }

    return $findings
}

Function Test-OperationsControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [array]$Controls
    )

    $findings    = @()
    $opsControls = @($Controls | Where-Object { $_.Category -eq "Operations" })

    # OPS-002: No Activity Log alerts
    try
    {
        $alerts = @(Get-AzActivityLogAlert -ErrorAction Stop)
        if ($alerts.Count -eq 0)
        {
            $ctrl = $opsControls | Where-Object { $_.ControlId -eq "OPS-002" }
            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $SubscriptionName `
                -ResourceType "Subscription" `
                -ResourceGroup "Subscription" `
                -Detail "No Activity Log alert rules defined — critical Azure platform events go unnotified" `
                -DebtPoints $ctrl.Weight
        }
    }
    catch { Write-Verbose "OPS-002: Could not retrieve Activity Log alerts — $($_.Exception.Message)" }

    # OPS-003: No Log Analytics Workspace
    try
    {
        $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop)
        if ($workspaces.Count -eq 0)
        {
            $ctrl = $opsControls | Where-Object { $_.ControlId -eq "OPS-003" }
            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName `
                -ResourceName $SubscriptionName `
                -ResourceType "Subscription" `
                -ResourceGroup "Subscription" `
                -Detail "No Log Analytics Workspace — no centralised log collection or SIEM integration possible" `
                -DebtPoints $ctrl.Weight
        }
    }
    catch { Write-Verbose "OPS-003: Could not retrieve Log Analytics Workspaces — $($_.Exception.Message)" }

    # OPS-001: Key resources without diagnostic settings (VM sample)
    try
    {
        $vms  = @(Get-AzVM -ErrorAction SilentlyContinue)
        $ctrl = $opsControls | Where-Object { $_.ControlId -eq "OPS-001" }

        foreach ($vm in $vms)
        {
            try
            {
                $diag = @(Get-AzDiagnosticSetting -ResourceId $vm.Id -ErrorAction Stop)
                if ($diag.Count -eq 0)
                {
                    $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                        -SubscriptionName $SubscriptionName `
                        -ResourceName $vm.Name `
                        -ResourceType "VirtualMachine" `
                        -ResourceGroup $vm.ResourceGroupName `
                        -Detail "VM has no diagnostic settings — guest OS metrics and logs not collected" `
                        -DebtPoints $ctrl.Weight
                }
            }
            catch { Write-Verbose "OPS-001: Diagnostic settings check failed for VM $($vm.Name)" }
        }
    }
    catch { Write-Verbose "OPS-001: Could not retrieve VMs for diagnostic check" }

    return $findings
}

#endregion


#region ── [ Finding Factory ] ─────────────────────────────────────────────────

Function New-Finding
{
    param(
        [pscustomobject]$Control,
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceName,
        [string]$ResourceType,
        [string]$ResourceGroup,
        [string]$Detail,
        [int]$DebtPoints
    )

    return [pscustomobject]@{
        ControlId           = $Control.ControlId
        Category            = $Control.Category
        Severity            = $Control.Severity
        Weight              = $Control.Weight
        DebtPoints          = $DebtPoints
        SubscriptionId      = $SubscriptionId
        SubscriptionName    = $SubscriptionName
        ResourceName        = $ResourceName
        ResourceType        = $ResourceType
        ResourceGroup       = $ResourceGroup
        Description         = $Control.Description
        Detail              = $Detail
        RemediationGuidance = $Control.RemediationGuidance
    }
}

#endregion


#region ── [ HTML Presentation Layer ] ────────────────────────────────────────

Function EscHtml { param([string]$s); return $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\','\\\\' -replace "'","\'" -replace '"','\"' -replace "`n",' ' -replace "`r",' ' }

Function Get-SeverityBadgeClass
{
    param([string]$Severity)
    switch ($Severity)
    {
        "Critical" { return "badge-red" }
        "High"     { return "badge-amber" }
        "Medium"   { return "badge-blue" }
        "Low"      { return "badge-muted" }
        default    { return "" }
    }
}

Function Get-RagBadgeClass
{
    param([string]$Rag)
    switch ($Rag)
    {
        "Red"   { return "badge-red" }
        "Amber" { return "badge-amber" }
        "Green" { return "badge-green" }
        default { return "" }
    }
}

Function Generate-TechnicalDebtHtml
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [hashtable]$OverallScore,
        [hashtable]$CategoryScores,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [array]$Controls
    )

    $totalFindings = $Findings.Count
    $criticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount     = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount   = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount      = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $totalDebt     = $OverallScore.RawDebt
    $estateScore   = $OverallScore.Score
    $estateRag     = $OverallScore.RagStatus
    $scoreLabel    = $OverallScore.ScoreLabel

    $ragBadge       = Get-RagBadgeClass -Rag $estateRag
    $ringStroke     = [math]::Round(($estateScore / 100) * 251.2, 1)   # 2π × 40 ≈ 251.2
    $ringColorVar   = switch ($estateRag) { "Red" { "var(--red)" }; "Amber" { "var(--amber)" }; default { "var(--green)" } }

    # ── Finding table rows ────────────────────────────────────────────────────
    $findingRows = ""
    $findingJson = "["
    $idx         = 0

    foreach ($f in $Findings)
    {
        $sevCls   = Get-SeverityBadgeClass -Severity $f.Severity
        $shortRes = if ($f.ResourceName.Length -gt 34) { EscHtml($f.ResourceName.Substring(0,31) + "...") } else { EscHtml $f.ResourceName }
        $shortDsc = if ($f.Description.Length  -gt 52) { EscHtml($f.Description.Substring(0,49)  + "...") } else { EscHtml $f.Description }

        $findingRows += @"
          <tr onclick="showFindingDetail($idx)">
            <td><span class="ctrl-id">$(EscHtml $f.ControlId)</span></td>
            <td>$(EscHtml $f.Category)</td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td title="$(EscHtml $f.ResourceName)">$shortRes</td>
            <td>$(EscHtml $f.ResourceType)</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td><span class="debt-pts">+$($f.DebtPoints)</span></td>
            <td class="remediation-cell" title="$(EscHtml $f.RemediationGuidance)">$shortDsc</td>
          </tr>
"@

        $findingJson += "{" +
            """id"":""$(EscJ $f.ControlId)""," +
            """cat"":""$(EscJ $f.Category)""," +
            """sev"":""$(EscJ $f.Severity)""," +
            """res"":""$(EscJ $f.ResourceName)""," +
            """resType"":""$(EscJ $f.ResourceType)""," +
            """rg"":""$(EscJ $f.ResourceGroup)""," +
            """sub"":""$(EscJ $f.SubscriptionName)""," +
            """desc"":""$(EscJ $f.Description)""," +
            """detail"":""$(EscJ $f.Detail)""," +
            """remediation"":""$(EscJ $f.RemediationGuidance)""," +
            """debt"":$($f.DebtPoints)," +
            """weight"":$($f.Weight)" +
            "},"
        $idx++
    }
    $findingJson = $findingJson.TrimEnd(",") + "]"

    # ── Category rows ─────────────────────────────────────────────────────────
    $categoryRows    = ""
    $categoryBarRows = ""
    $categoryOrder   = @("Networking","Compute","Storage","Identity","Governance","Security","Resilience","Operations")

    foreach ($cat in $categoryOrder)
    {
        if (-not $CategoryScores.ContainsKey($cat)) { continue }
        $cs      = $CategoryScores[$cat]
        $ragCls  = Get-RagBadgeClass -Rag $cs.RagStatus
        $barPct  = $cs.Score

        $categoryRows += @"
          <tr>
            <td>$(EscHtml $cat)</td>
            <td><span class="badge $ragCls">$(EscHtml $cs.RagStatus)</span></td>
            <td class="score-cell">$($cs.Score)</td>
            <td>$($cs.FindingCount)</td>
            <td><span class="badge badge-red-xs">$($cs.Critical)</span> <span class="badge badge-amber-xs">$($cs.High)</span> <span class="badge badge-blue-xs">$($cs.Medium)</span> <span class="badge badge-muted-xs">$($cs.Low)</span></td>
            <td><span class="debt-pts">$($cs.DebtPoints)</span></td>
          </tr>
"@

        $barColor = switch ($cs.RagStatus) { "Red" { "var(--red)" }; "Amber" { "var(--amber)" }; default { "var(--green)" } }
        $categoryBarRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $cat)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$barPct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($cs.Score) / 100</span>
          </div>
"@
    }

    # ── Subscription result rows ───────────────────────────────────────────────
    $subRows = ""
    foreach ($s in $SubscriptionResults)
    {
        $icon    = switch ($s.Status) { "Success" { "✓" }; "Warning" { "⚠" }; "Error" { "✗" }; default { "•" } }
        $iconCls = switch ($s.Status) { "Success" { "c-green" }; "Warning" { "c-amber" }; "Error" { "c-red" }; default { "" } }
        $ragBadgeRow = if ($s.Rag) { "<span class='badge $(Get-RagBadgeClass -Rag $s.Rag)'>$($s.Rag)</span>" } else { "" }
        $subRows += @"
          <div class="sub-row">
            <span class="sub-icon $iconCls">$icon</span>
            <span class="sub-name">$(EscHtml $s.Name)</span>
            <span>$ragBadgeRow</span>
            <span class="sub-detail">Score: $($s.Score) | Findings: $($s.FindingCount) | $($s.Summary)</span>
          </div>
"@
    }

    # ── Control reference rows ────────────────────────────────────────────────
    $controlRows = ""
    foreach ($c in ($Controls | Sort-Object ControlId))
    {
        $sevCls = Get-SeverityBadgeClass -Severity $c.Severity
        $controlRows += @"
          <tr>
            <td><span class="ctrl-id">$(EscHtml $c.ControlId)</span></td>
            <td>$(EscHtml $c.Category)</td>
            <td><span class="badge $sevCls">$(EscHtml $c.Severity)</span></td>
            <td>$($c.Weight)</td>
            <td title="$(EscHtml $c.Description)">$(if ($c.Description.Length -gt 60) { EscHtml($c.Description.Substring(0,57)+"...") } else { EscHtml $c.Description })</td>
            <td style="font-size:11px;color:var(--muted2)">$(EscHtml $c.ResourceType)</td>
          </tr>
"@
    }

    # ── Severity distribution bar rows ────────────────────────────────────────
    $severityBarRows = @"
          <div class="bar-row">
            <span class="bar-label">Critical</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$(if($totalFindings -gt 0){[math]::Round($criticalCount/$totalFindings*100)}else{0})" style="background:var(--red)"></div></div>
            <span class="bar-pct">$criticalCount</span>
          </div>
          <div class="bar-row">
            <span class="bar-label">High</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$(if($totalFindings -gt 0){[math]::Round($highCount/$totalFindings*100)}else{0})" style="background:var(--amber)"></div></div>
            <span class="bar-pct">$highCount</span>
          </div>
          <div class="bar-row">
            <span class="bar-label">Medium</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$(if($totalFindings -gt 0){[math]::Round($mediumCount/$totalFindings*100)}else{0})" style="background:var(--accent)"></div></div>
            <span class="bar-pct">$mediumCount</span>
          </div>
          <div class="bar-row">
            <span class="bar-label">Low</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$(if($totalFindings -gt 0){[math]::Round($lowCount/$totalFindings*100)}else{0})" style="background:var(--muted)"></div></div>
            <span class="bar-pct">$lowCount</span>
          </div>
"@

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Architecture Technical Debt Dashboard</title>
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
  background:linear-gradient(135deg,var(--accent3),var(--red));
  display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{display:inline-block;margin-top:8px;padding:2px 8px;border-radius:20px;
  font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent);border:1px solid var(--border);}
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin-bottom:22px;}
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
.stat-card.c-muted{border-top-color:var(--muted);}
.stat-num{font-size:30px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.score-hero{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:24px;margin-bottom:22px;display:flex;align-items:center;gap:32px;flex-wrap:wrap;
}
.score-ring-wrap{position:relative;flex-shrink:0;}
.score-ring-wrap svg{transform:rotate(-90deg);}
.ring-track{fill:none;stroke:var(--surface3);stroke-width:8;}
.ring-fill{fill:none;stroke-width:8;stroke-linecap:round;
  stroke-dasharray:251.2;stroke-dashoffset:251.2;transition:stroke-dashoffset 1.2s ease;}
.score-label-inner{
  position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;
}
.score-num{font-size:26px;font-weight:700;font-family:var(--mono);line-height:1;}
.score-sub{font-size:10px;color:var(--muted);margin-top:2px;text-transform:uppercase;}
.score-details{flex:1;}
.score-title{font-size:18px;font-weight:700;margin-bottom:6px;}
.score-desc{font-size:13px;color:var(--muted2);margin-bottom:14px;line-height:1.6;}
.score-meta-row{display:flex;gap:12px;flex-wrap:wrap;}
.score-meta-item{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 14px;}
.score-meta-label{font-size:10px;color:var(--muted);text-transform:uppercase;margin-bottom:3px;}
.score-meta-val{font-size:13px;font-family:var(--mono);}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:100px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
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
.badge-green {background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-amber {background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-red   {background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-blue  {background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.badge-muted {background:var(--surface3);color:var(--muted2);border:1px solid var(--border);}
.badge-red-xs,.badge-amber-xs,.badge-blue-xs,.badge-muted-xs{
  display:inline-block;padding:1px 6px;border-radius:10px;font-size:10px;font-weight:600;margin:1px;}
.badge-red-xs  {background:rgba(248,81,73,.12);color:var(--red);}
.badge-amber-xs{background:rgba(210,153,34,.12);color:var(--amber);}
.badge-blue-xs {background:rgba(56,139,253,.12);color:var(--accent);}
.badge-muted-xs{background:var(--surface3);color:var(--muted2);}
.ctrl-id{font-family:var(--mono);font-size:11px;color:var(--accent2);font-weight:600;}
.debt-pts{font-family:var(--mono);font-size:11px;color:var(--red);font-weight:600;}
.score-cell{font-family:var(--mono);font-weight:700;}
.remediation-cell{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:help;}
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
.sub-name{flex:0 0 220px;font-size:13px;font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{
  position:fixed;right:0;top:0;bottom:0;width:480px;max-width:95vw;
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
.drawer-field-value{font-size:13px;word-break:break-word;line-height:1.6;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.remediation-box{background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--accent);
  border-radius:var(--radius-sm);padding:12px 14px;font-size:12px;line-height:1.7;color:var(--muted2);}
.debt-explain{background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.2);border-radius:var(--radius-sm);
  padding:10px 14px;font-size:12px;color:var(--red);font-family:var(--mono);}
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
  .score-hero{flex-direction:column;align-items:flex-start;}
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
    <div class="logo-title">Architecture Debt</div>
    <div class="logo-sub">Azure Technical Debt Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> Findings</button>
    <button class="nav-btn" onclick="showPage('categories',this)"><span class="nav-icon">📂</span> By Category</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">🗂️</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('controls',this)"><span class="nav-icon">📋</span> Control Library</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Azure Architecture Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Architecture Technical Debt Overview</div>
      <div class="page-sub">Enterprise architecture posture across __SUB_COUNT__ subscription(s) — __TOTAL_FINDINGS__ findings identified</div>
    </div>

    <!-- Score Hero -->
    <div class="score-hero">
      <div class="score-ring-wrap">
        <svg width="110" height="110" viewBox="0 0 110 110">
          <circle class="ring-track" cx="55" cy="55" r="40"/>
          <circle class="ring-fill" id="scoreRing" cx="55" cy="55" r="40" stroke="__RING_COLOR__"/>
        </svg>
        <div class="score-label-inner">
          <div class="score-num" style="color:__RING_COLOR__">__ESTATE_SCORE__</div>
          <div class="score-sub">/ 100</div>
        </div>
      </div>
      <div class="score-details">
        <div class="score-title">Overall Architecture Health: <span class="badge __RAG_BADGE_CLASS__">__ESTATE_RAG__</span> — __SCORE_LABEL__</div>
        <div class="score-desc">
          The estate score reflects the weighted technical debt across all assessed controls.
          A score of 100 means zero findings. Each finding deducts debt points proportional to its severity weight.
          Critical and High findings have the greatest impact and should be prioritised for remediation.
        </div>
        <div class="score-meta-row">
          <div class="score-meta-item"><div class="score-meta-label">Total Debt Points</div><div class="score-meta-val" style="color:var(--red)">__TOTAL_DEBT__</div></div>
          <div class="score-meta-item"><div class="score-meta-label">Total Findings</div><div class="score-meta-val">__TOTAL_FINDINGS__</div></div>
          <div class="score-meta-item"><div class="score-meta-label">Subscriptions</div><div class="score-meta-val">__SUB_COUNT__</div></div>
          <div class="score-meta-item"><div class="score-meta-label">Controls Evaluated</div><div class="score-meta-val">__CONTROL_COUNT__</div></div>
        </div>
      </div>
    </div>

    <!-- Severity Stats -->
    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High</div>
        <div class="stat-sub">Remediate within 30 days</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium</div>
        <div class="stat-sub">Planned remediation</div>
      </div>
      <div class="stat-card c-muted">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low</div>
        <div class="stat-sub">Best practice improvement</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__TOTAL_DEBT__</div>
        <div class="stat-label">Debt Points</div>
        <div class="stat-sub">Weighted severity total</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__TOTAL_FINDINGS__</div>
        <div class="stat-label">Total Findings</div>
        <div class="stat-sub">Across all categories</div>
      </div>
    </div>

    <!-- Charts -->
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📊 Findings by Severity</div>
        __SEVERITY_BAR_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🏛️ Health Score by Category</div>
        __CATEGORY_BAR_ROWS__
      </div>
    </div>
  </div>

  <!-- Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">All Findings</div>
      <div class="page-sub">Click any row for details, remediation guidance, and debt contribution. Sorted by severity.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search resource, control, description…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="filterCat" onchange="filterFindings()">
          <option value="">All Categories</option>
          <option value="Networking">Networking</option>
          <option value="Compute">Compute</option>
          <option value="Storage">Storage</option>
          <option value="Identity">Identity</option>
          <option value="Governance">Governance</option>
          <option value="Security">Security</option>
          <option value="Resilience">Resilience</option>
          <option value="Operations">Operations</option>
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
              <th onclick="sortFindings(0)">Control ID</th>
              <th onclick="sortFindings(1)">Category</th>
              <th onclick="sortFindings(2)">Severity</th>
              <th onclick="sortFindings(3)">Resource</th>
              <th onclick="sortFindings(4)">Type</th>
              <th onclick="sortFindings(5)">Subscription</th>
              <th onclick="sortFindings(6)">Debt Pts</th>
              <th>Description / Remediation</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- By Category -->
  <div id="page-categories" class="page">
    <div class="page-header">
      <div class="page-title">Technical Debt by Category</div>
      <div class="page-sub">Category-level aggregation of findings, scores, and debt contribution</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Category</th>
              <th>RAG Status</th>
              <th>Score</th>
              <th>Findings</th>
              <th>Severity Breakdown</th>
              <th>Debt Points</th>
            </tr>
          </thead>
          <tbody>__CATEGORY_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription technical debt score and finding summary</div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Subscriptions Assessed</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- Control Library -->
  <div id="page-controls" class="page">
    <div class="page-header">
      <div class="page-title">Enterprise Architecture Control Library</div>
      <div class="page-sub">Built-in controls used for this assessment. Controls are extensible to external JSON/CSV in future versions.</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Control ID</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Weight</th>
              <th>Description</th>
              <th>Resource Type</th>
            </tr>
          </thead>
          <tbody>__CONTROL_ROWS__</tbody>
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
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Subscriptions Scanned</div><div class="info-value">__SUB_COUNT__</div></div>
        <div class="info-card"><div class="info-label">Controls in Baseline</div><div class="info-value">__CONTROL_COUNT__</div></div>
        <div class="info-card"><div class="info-label">Estate Score</div><div class="info-value">__ESTATE_SCORE__ / 100 (__ESTATE_RAG__)</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">📐 Scoring Methodology</div>
      <p style="font-size:13px;color:var(--muted2);line-height:1.8;">
        Each finding contributes its control <strong>Weight</strong> (1–10) as raw debt points.
        The subscription score normalises total debt against maximum possible debt (sum of all control weights × 3 for normalization headroom).
        Score = 100 − (RawDebt / MaxPossible × 100), clamped to 0–100.
        Category scores apply the same formula within their control subset.
        RAG thresholds: <span style="color:var(--green)">Green ≥ 71</span>, <span style="color:var(--amber)">Amber 41–70</span>, <span style="color:var(--red)">Red ≤ 40</span>.
      </p>
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
const ALL_FINDINGS = __FINDING_JSON__;
let filtered = [...ALL_FINDINGS];
let findPage = 1, findPageSz = 25;
let findSortCol = -1, findSortAsc = true;
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

function filterFindings(){
  const q=document.getElementById('findSearch').value.toLowerCase();
  const s=document.getElementById('filterSev').value;
  const c=document.getElementById('filterCat').value;
  filtered=ALL_FINDINGS.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mS=!s||r.sev===s;
    const mC=!c||r.cat===c;
    return mQ&&mS&&mC;
  });
  findPage=1; renderFindings();
}

function changeFindPageSize(){
  findPageSz=parseInt(document.getElementById('pgSizeFind').value);
  findPage=1; renderFindings();
}

function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys=['id','cat','sev','res','resType','sub','debt'];
  const sevOrder={Critical:0,High:1,Medium:2,Low:3};
  filtered.sort((a,b)=>{
    if(col===2){
      const av=sevOrder[a.sev]??99, bv=sevOrder[b.sev]??99;
      return findSortAsc?av-bv:bv-av;
    }
    const k=keys[col]; const av=a[k]??'', bv=b[k]??'';
    return findSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                      :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderFindings();
}

function renderFindings(){
  const tbody=document.getElementById('findBody');
  const start=(findPage-1)*findPageSz;
  const slice=filtered.slice(start,start+findPageSz);
  const gi=idx=>ALL_FINDINGS.indexOf(filtered[idx+(findPage-1)*findPageSz]);
  tbody.innerHTML=slice.map((r,i)=>{
    const gi2=ALL_FINDINGS.indexOf(r);
    const sCls=r.sev==='Critical'?'badge-red':r.sev==='High'?'badge-amber':r.sev==='Medium'?'badge-blue':'badge-muted';
    const nm=r.res.length>34?r.res.substring(0,31)+'...':r.res;
    const ds=r.desc.length>52?r.desc.substring(0,49)+'...':r.desc;
    return `<tr onclick="showFindingDetail(${gi2})">
      <td><span class="ctrl-id">${escH(r.id)}</span></td>
      <td>${escH(r.cat)}</td>
      <td><span class="badge ${sCls}">${escH(r.sev)}</span></td>
      <td title="${escH(r.res)}">${escH(nm)}</td>
      <td>${escH(r.resType)}</td>
      <td>${escH(r.sub)}</td>
      <td><span class="debt-pts">+${r.debt}</span></td>
      <td class="remediation-cell" title="${escH(r.remediation)}">${escH(ds)}</td>
    </tr>`;
  }).join('');
  renderFindPg();
}

function renderFindPg(){
  const total=Math.ceil(filtered.length/findPageSz);
  const el=document.getElementById('findPagination');
  let h=`<span>${filtered.length} findings</span>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,findPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeFindPage(p){
  const total=Math.ceil(filtered.length/findPageSz);
  if(p<1||p>total)return;
  findPage=p; renderFindings();
}

function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=ALL_FINDINGS[idx];
  if(!r)return;
  const sCls=r.sev==='Critical'?'badge-red':r.sev==='High'?'badge-amber':r.sev==='Medium'?'badge-blue':'badge-muted';
  document.getElementById('drawerTitle').textContent=r.id+' — '+r.res;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${ALL_FINDINGS.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field">
      <div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sCls}">${escH(r.sev)}</span></div>
    </div>
    <div class="debt-explain">⚡ Debt Contribution: +${r.debt} points (Weight: ${r.weight}) — this finding adds ${r.debt} to the raw debt score</div>
    <div class="drawer-section">Finding Details</div>
    <div class="drawer-field"><div class="drawer-field-label">Category</div><div class="drawer-field-value">${escH(r.cat)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Control ID</div><div class="drawer-field-value" style="font-family:var(--mono);color:var(--accent2)">${escH(r.id)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Description</div><div class="drawer-field-value">${escH(r.desc)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Finding Detail</div><div class="drawer-field-value">${escH(r.detail)}</div></div>
    <div class="drawer-section">Resource</div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Name</div><div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.res)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Type</div><div class="drawer-field-value">${escH(r.resType)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div><div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-section">Remediation Guidance</div>
    <div class="remediation-box">${escH(r.remediation)}</div>
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
  if(next>=0&&next<ALL_FINDINGS.length) showFindingDetail(next);
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width=el.dataset.pct+'%';
    });
    const ring=document.getElementById('scoreRing');
    if(ring){
      const pct=parseFloat(ring.parentElement.querySelector('.score-num').textContent||0);
      ring.style.strokeDashoffset=(251.2-(251.2*pct/100)).toFixed(1);
    }
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

filterFindings();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__',   $GeneratedOn `
        -replace '__SUB_COUNT__',      ($SubscriptionResults.Count) `
        -replace '__TOTAL_FINDINGS__', $totalFindings `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__',     $highCount `
        -replace '__MEDIUM_COUNT__',   $mediumCount `
        -replace '__LOW_COUNT__',      $lowCount `
        -replace '__TOTAL_DEBT__',     $totalDebt `
        -replace '__ESTATE_SCORE__',   $estateScore `
        -replace '__ESTATE_RAG__',     $estateRag `
        -replace '__SCORE_LABEL__',    $scoreLabel `
        -replace '__RAG_BADGE_CLASS__',$ragBadge `
        -replace '__RING_COLOR__',     $ringColorVar `
        -replace '__CONTROL_COUNT__',  ($Controls.Count) `
        -replace '__SEVERITY_BAR_ROWS__', $severityBarRows `
        -replace '__CATEGORY_BAR_ROWS__', $categoryBarRows `
        -replace '__FINDING_ROWS__',   $findingRows `
        -replace '__CATEGORY_ROWS__',  $categoryRows `
        -replace '__CONTROL_ROWS__',   $controlRows `
        -replace '__SUB_ROWS__',       $subRows `
        -replace '__TENANT__',         $SessionInfo.Tenant `
        -replace '__ACCOUNT__',        $SessionInfo.Account `
        -replace '__ENVIRONMENT__',    $SessionInfo.Environment `
        -replace '__SCOPE__',          $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__',      $ScanParameters.ExecTime `
        -replace '__FINDING_JSON__',   $findingJson

    return $html
}

#endregion


#region ── [ Main Function ] ───────────────────────────────────────────────────

Function Get-AzureArchitectureTechnicalDebt
{
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = "C:\Temp\AzureArchitectureTechnicalDebt-Report.html"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts", "Az.Network", "Az.Compute",
        "Az.Storage", "Az.Resources", "Az.Security",
        "Az.Monitor", "Az.RecoveryServices", "Az.OperationalInsights"
    )

    $missingModules = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missingModules)
    {
        Write-Host "  ⚠ Missing Az modules: $($missingModules -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "  Install Az module now? (Y/N)"

        if ($install -match '^[Yy]$')
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
                return
            }
        }
        else
        {
            Write-Host ""
            Write-Host "  Installation declined. Cannot proceed without required Az modules." -ForegroundColor Yellow
            return
        }
    }

    # ── Authentication ────────────────────────────────────────────────────────
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx)
    {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $ctx = Get-AzContext
    }

    # ── Subscription resolution ───────────────────────────────────────────────
    if ($AllSubscriptions -or -not $SubscriptionIds)
    {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText     = "All Subscriptions"
    }
    else
    {
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
        "Scope"         = "$scopeText ($subCount found)"
        "Export to CSV" = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Output Path"   = $OutputPath
    }

    # ── Load controls ─────────────────────────────────────────────────────────
    $controls = Get-ArchitectureControls
    Write-Host ""
    Write-Host "  ✓ Loaded $($controls.Count) architecture controls across 8 domains" -ForegroundColor Green

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings         = @()
    $subscriptionResults = @()
    $successCount        = 0
    $errorCount          = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = ([math]::Max(
        ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum, 35
    ))

    $subIndex = 1

    foreach ($sub in $subscriptions)
    {
        try
        {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $subFindings = @()

            # ── Control domains ───────────────────────────────────────────
            $subFindings += Test-NetworkingControls  -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Controls $controls
            $subFindings += Test-ComputeControls     -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Controls $controls
            $subFindings += Test-StorageControls     -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Controls $controls
            $subFindings += Test-IdentityControls    -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Controls $controls
            $subFindings += Test-GovernanceControls  -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Controls $controls
            $subFindings += Test-SecurityControls    -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Controls $controls
            $subFindings += Test-ResilienceControls  -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Controls $controls
            $subFindings += Test-OperationsControls  -SubscriptionId $sub.Id -SubscriptionName $sub.Name -Controls $controls

            $allFindings += $subFindings

            # ── Per-subscription score ────────────────────────────────────
            $subScore   = Invoke-ScoringEngine -Findings $subFindings -Controls $controls
            $subCritical = @($subFindings | Where-Object { $_.Severity -eq "Critical" }).Count
            $subHigh     = @($subFindings | Where-Object { $_.Severity -eq "High" }).Count

            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Score: $($subScore.Score) ($($subScore.RagStatus)) | Findings: $($subFindings.Count) | Critical: $subCritical | High: $subHigh" -ForegroundColor White

            $subscriptionResults += @{
                Name        = $sub.Name
                Score       = $subScore.Score
                Rag         = $subScore.RagStatus
                FindingCount = $subFindings.Count
                Summary     = "Critical: $subCritical  High: $subHigh  Debt: $($subScore.RawDebt)"
                Status      = "Success"
            }
            $successCount++
        }
        catch
        {
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✗ " -NoNewline -ForegroundColor Red
            Write-Host $paddedName -NoNewline -ForegroundColor Red
            Write-Host " → Failed: $($_.Exception.Message)" -ForegroundColor Red

            $subscriptionResults += @{
                Name        = $sub.Name
                Score       = 0
                Rag         = "Red"
                FindingCount = 0
                Summary     = "Failed: $($_.Exception.Message)"
                Status      = "Error"
            }
            $errorCount++
        }

        $subIndex++
    }

    # ── Scoring ───────────────────────────────────────────────────────────────
    $overallScore   = Invoke-ScoringEngine   -Findings $allFindings -Controls $controls
    $categoryScores = Invoke-CategoryScoring -Findings $allFindings -Controls $controls

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime  = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-AssessmentSummary -Data ([ordered]@{
        "Subscriptions Scanned"    = $subCount
        "Successful"               = $successCount
        "Errors"                   = $errorCount
        "Total Findings"           = $allFindings.Count
        "Overall Estate Score"     = "$($overallScore.Score) / 100 ($($overallScore.RagStatus))"
        "Total Debt Points"        = $overallScore.RawDebt
        "Execution Time"           = $duration
    })

    Write-FindingsBySeverity -Findings $allFindings

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported    = $false
    $htmlExported   = $false
    $gridViewOpened = $false
    $csvPath        = ""

    if ($allFindings.Count -gt 0 -or $subscriptionResults.Count -gt 0)
    {
        # CSV export
        if ($ExportToCsv)
        {
            try
            {
                $csvPath = [System.IO.Path]::ChangeExtension($OutputPath, '.csv')
                $csvDir  = Split-Path -Parent $csvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object ControlId, Category, Severity, Weight, DebtPoints,
                    SubscriptionName, SubscriptionId, ResourceName, ResourceType, ResourceGroup,
                    Description, Detail, RemediationGuidance |
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

                $csvExported = $true
            }
            catch
            {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML dashboard
        try
        {
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

            # Sort findings: Critical → High → Medium → Low for table default order
            $severityOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3 }
            $sortedFindings = $allFindings | Sort-Object { $severityOrder[$_.Severity] }, ControlId

            $htmlContent = Generate-TechnicalDebtHtml `
                -SessionInfo          $sessionInfo `
                -ScanParameters       $scanParams `
                -Findings             $sortedFindings `
                -OverallScore         $overallScore `
                -CategoryScores       $categoryScores `
                -SubscriptionResults  $subscriptionResults `
                -GeneratedOn          (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -Controls             $controls

            $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch
        {
            Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        # Grid View
        try
        {
            $allFindings |
            Select-Object ControlId, Category, Severity, SubscriptionName, ResourceName,
                ResourceType, ResourceGroup, DebtPoints, Description |
            Out-GridView -Title "Azure Architecture Technical Debt Assessment"
            $gridViewOpened = $true
        }
        catch
        {
            Write-Verbose "Could not open Grid View (no GUI available)"
        }
    }
    else
    {
        Write-Host ""
        Write-Host "  ⚠ No findings or subscription data to report." -ForegroundColor Yellow
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened)
    {
        $outCsv  = if ($csvExported) { $csvPath } else { $null }
        $outHtml = if ($htmlExported) { $OutputPath } else { $null }
        Write-OutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
    }
    else
    {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}

#endregion
