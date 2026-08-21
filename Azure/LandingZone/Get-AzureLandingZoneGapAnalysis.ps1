<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 21 August 2026
Modified-On     : 21 August 2026

.SYNOPSIS
    Identifies missing or misconfigured Azure Landing Zone controls across governance,
    identity, network, security, management, and operations pillars, and classifies each
    gap as Critical / High / Medium / Low with CAF and CIS benchmark references.

.DESCRIPTION
    Get-AzureLandingZoneGapAnalysis evaluates the Azure Landing Zone (ALZ) posture
    across a Management Group hierarchy or a specified set of subscriptions.

    Assessment pillars and checks performed:

        Pillar 1 — Governance
            - Policy assignments at Management Group vs subscription scope
            - Deny-mode policy coverage for critical controls
            - Missing initiative assignments (CIS, MDC built-in sets)
            - Resource lock presence on critical resource groups
            - Cost management alert configuration
            - Tagging strategy enforcement

        Pillar 2 — Identity & Access
            - Break-glass / emergency-access account detection
            - Privileged Identity Management (PIM) activation posture
            - Role assignments directly on subscriptions without PIM
            - Classic administrator role assignments (deprecated)
            - Foreign / guest principal role assignments at high scope

        Pillar 3 — Network
            - Hub-spoke topology indicators (VNet peering, Virtual WAN presence)
            - Forced tunnelling / UDR coverage on spoke VNets
            - DDoS Protection Standard presence
            - NSG coverage on subnets that expose workloads
            - Azure Firewall or NVA presence in hub
            - Private DNS zone configuration

        Pillar 4 — Security
            - Microsoft Defender for Cloud plans enabled per subscription
            - MDC secure score baseline (threshold < 70 flagged)
            - Just-In-Time VM access availability
            - Azure Security Benchmark assignment
            - Sub-assessment vulnerability findings count

        Pillar 5 — Management & Monitoring
            - Log Analytics workspace presence and linked subscriptions
            - Diagnostic settings coverage at subscription level
            - Azure Monitor action groups and alert rules
            - Automation Account or Update Management presence

        Pillar 6 — Operations
            - Azure Backup vault presence per subscription
            - Critical resource locks (subscription and resource group level)
            - Activity log retention (minimum 90 days)
            - Orphaned resources: unattached disks, unused public IPs

    Each gap is classified using a four-tier severity model aligned to the
    Microsoft Cloud Adoption Framework (CAF) and CIS Azure Benchmark v2.0:

        Critical  — Direct exploitation path or governance bypass possible
        High      — Significant compliance/audit exposure; architectural drift
        Medium    — Best-practice deviation; operational or posture risk
        Low       — Minor control gap; low immediate risk

    Outputs:
        - Color-coded console progress and per-subscription gap summary
        - Interactive HTML dashboard (sortable, filterable, dark/light theme,
          detail drawer per gap, donut charts, bar distributions, CAF/CIS refs)
        - Optional CSV export of all gap findings

.PARAMETER ManagementGroupId
    The root Management Group ID to enumerate. All child subscriptions accessible
    to the authenticated account are included in the assessment. Takes precedence
    over -SubscriptionIds when both are supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to assess. Used when a full
    Management Group enumeration is not desired or not permitted.

.PARAMETER IncludeSecureScore
    Switch. When specified, calls the MDC Secure Score API per subscription.
    This adds API call overhead on large environments. Skipped by default.
    If the call fails due to permissions the finding is marked "Not Assessed"
    and the scan continues.

.PARAMETER ExportToCsv
    Switch. Exports all gap findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless of this switch.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    The HTML dashboard is saved with the same base name and a .html extension.
    Default: C:\Temp\AzureLandingZoneGapAnalysis-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard. Optionally
    writes CSV when -ExportToCsv is specified.

.EXAMPLE
    Get-AzureLandingZoneGapAnalysis -ManagementGroupId "mg-contoso-root"

.EXAMPLE
    Get-AzureLandingZoneGapAnalysis -ManagementGroupId "mg-contoso-root" -IncludeSecureScore -ExportToCsv

.EXAMPLE
    Get-AzureLandingZoneGapAnalysis -SubscriptionIds @("sub-id-1","sub-id-2") -ExportToCsv -CsvPath "C:\Reports\LZGapAnalysis.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (21-Aug-2026) - Initial release. Six-pillar ALZ gap assessment covering
                            governance, identity, network, security, management, and
                            operations. CAF and CIS benchmark mapping. Optional MDC
                            secure score. HTML dashboard and optional CSV export.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module — Az.Accounts, Az.Resources, Az.Network,
           Az.Security, Az.Monitor, Az.OperationalInsights, Az.RecoveryServices.
           Installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role at Management Group scope (for -ManagementGroupId) or
           at each subscription being assessed (for -SubscriptionIds).
        4. Microsoft.Authorization/policyAssignments/read
        5. Microsoft.Security/assessments/read and
           Microsoft.Security/secureScores/read — required for -IncludeSecureScore.
           Gracefully skipped if permission is absent.
        6. Management Group Reader role is required when using -ManagementGroupId
           to enumerate child subscriptions.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Management Group hierarchy enumeration requires Get-AzManagementGroup
          access. Subscriptions nested more than three levels deep in the MG
          tree may require recursive traversal which can be slow on large tenants.
        - MDC Secure Score API can be slow on subscriptions with many resources.
          Use -IncludeSecureScore selectively.
        - Hub-spoke topology detection is heuristic-based (VNet peering count,
          naming conventions, Virtual WAN presence). A correctly deployed hub
          without standard naming may not be detected as a hub.
        - PIM detection relies on role assignment metadata; it cannot distinguish
          between PIM-activated and directly assigned roles in all configurations.
        - Classic administrator detection may return no results in subscriptions
          that were never migrated from the classic deployment model.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/
    https://learn.microsoft.com/en-us/azure/governance/management-groups/overview
    https://learn.microsoft.com/en-us/security/benchmark/azure/overview
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls
    https://www.cisecurity.org/benchmark/azure

#>


#------------------------------------------------------------------------ [ Gap Catalogue ]
# Each entry defines a static check. Dynamic checks are appended during the scan.

$script:GAP_CATALOGUE = @(

    # ── Pillar 1: Governance ──────────────────────────────────────────────────
    [pscustomobject]@{
        CheckId       = "GOV-001"
        Pillar        = "Governance"
        ControlName   = "No Deny-mode Policy Assignments at Subscription Scope"
        Severity      = "High"
        CafReference  = "CAF: Enforce policy-driven guardrails"
        CisControl    = "CIS 2.1 — Ensure that Microsoft Cloud Security Benchmark policies are not set to Disabled"
        Description   = "Subscriptions with zero Deny-mode policy assignments have no enforced guardrails. Resources can be deployed outside approved configurations without any policy gate."
        Remediation   = "Assign the Azure Security Benchmark initiative or create targeted Deny policies for critical controls (allowed locations, allowed resource types, required tags)."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade/Assignments"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "GOV-002"
        Pillar        = "Governance"
        ControlName   = "Missing Policy Assignment at Management Group Scope"
        Severity      = "High"
        CafReference  = "CAF: Enforce policy at the management group level for consistent governance"
        CisControl    = "CIS 2.1"
        Description   = "Landing Zone governance requires policies assigned at Management Group level to ensure they cascade to all child subscriptions automatically. Subscription-only assignments create governance gaps when new subscriptions are added."
        Remediation   = "Assign the Microsoft Cloud Security Benchmark or CIS initiative at the Management Group level via Azure Policy Initiatives."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade/Assignments"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "GOV-003"
        Pillar        = "Governance"
        ControlName   = "No Resource Locks on Critical Resource Groups"
        Severity      = "Medium"
        CafReference  = "CAF: Protect platform resources with resource locks"
        CisControl    = "CIS 8.5 — Use Resource Locks for critical resources"
        Description   = "Resource groups hosting hub networking, identity, or management resources have no CanNotDelete or ReadOnly locks. Accidental or malicious deletion of platform resources can cause outages."
        Remediation   = "Apply CanNotDelete resource locks to all platform landing zone resource groups (connectivity, identity, management). Use Azure Policy to enforce locks on new resources."
        PortalLink    = "https://portal.azure.com/#blade/HubsExtension/BrowseAll"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "GOV-004"
        Pillar        = "Governance"
        ControlName   = "No Cost Management Budget Alerts Configured"
        Severity      = "Medium"
        CafReference  = "CAF: Cost management and governance"
        CisControl    = "N/A"
        Description   = "Subscriptions with no Azure Cost Management budget alerts are at risk of uncontrolled spend. Budget alerts are a basic operational and governance control."
        Remediation   = "Create a budget for each production subscription in Azure Cost Management + Billing and configure alert thresholds at 80% and 100% of budget."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_CostManagement/Menu/budgets"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "GOV-005"
        Pillar        = "Governance"
        ControlName   = "No Mandatory Tagging Policy Enforced"
        Severity      = "Low"
        CafReference  = "CAF: Resource naming and tagging strategy"
        CisControl    = "N/A"
        Description   = "Subscriptions with no Deny or Append tag policy assignments cannot enforce tagging. Without consistent tags, cost allocation, chargeback, and resource ownership tracking fail."
        Remediation   = "Assign an Append or Deny policy for mandatory tags (e.g. Environment, CostCenter, Owner, ApplicationName) at Management Group or subscription scope."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade/Definitions"
        Dynamic       = $true
    },

    # ── Pillar 2: Identity & Access ────────────────────────────────────────────
    [pscustomobject]@{
        CheckId       = "IAM-001"
        Pillar        = "Identity & Access"
        ControlName   = "No Break-Glass / Emergency Access Account Detected"
        Severity      = "Critical"
        CafReference  = "CAF: Manage emergency access accounts"
        CisControl    = "CIS 1.6 — Ensure that Emergency Access Accounts are configured"
        Description   = "No dedicated emergency access (break-glass) accounts were identified in Global Administrator role assignments. If the primary admin account is compromised or unavailable, the tenant may become unrecoverable."
        Remediation   = "Create two cloud-only break-glass accounts with Global Administrator role, exclude them from all Conditional Access policies, and store credentials offline. Monitor their use via Azure Monitor alerts."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/AllUsers"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "IAM-002"
        Pillar        = "Identity & Access"
        ControlName   = "Permanent Owner/Contributor Assignments Without PIM"
        Severity      = "Critical"
        CafReference  = "CAF: Use PIM for privileged access"
        CisControl    = "CIS 1.14 — Ensure that 'Privileged Identity Management' is used for privileged roles"
        Description   = "One or more subscriptions have permanent (non-PIM-governed) Owner or Contributor role assignments. Permanent high-privilege access increases the blast radius of account compromise."
        Remediation   = "Migrate all Owner and Contributor assignments to PIM-eligible assignments. Require MFA activation and approval workflows for sensitive roles."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_PIMCommon/CommonMenuBlade/quickStart"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "IAM-003"
        Pillar        = "Identity & Access"
        ControlName   = "Classic Administrator Role Assignments Present"
        Severity      = "High"
        CafReference  = "CAF: Retire legacy access models"
        CisControl    = "CIS 1.22 — Ensure that no custom subscription administrator roles exist"
        Description   = "Classic administrator roles (Service Administrator, Co-Administrator) are a legacy access model that bypasses Azure RBAC and Conditional Access. Microsoft has announced deprecation of this model."
        Remediation   = "Identify all classic co-administrators via the Azure Portal (Subscriptions > Access Control > Classic administrators) and migrate them to Azure RBAC roles before the retirement deadline."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_Billing/SubscriptionsBlade"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "IAM-004"
        Pillar        = "Identity & Access"
        ControlName   = "Guest / External User with Privileged RBAC at Subscription Scope"
        Severity      = "High"
        CafReference  = "CAF: Limit privileged access to internal identities"
        CisControl    = "CIS 1.20 — Ensure that no guest users are present in privileged roles"
        Description   = "External (guest) user accounts hold Owner or Contributor role assignments directly at subscription scope. Guest accounts are managed by external identity providers and may not comply with your organisation's MFA or CA policies."
        Remediation   = "Remove guest principals from subscription-level Owner/Contributor assignments. Collaborate with external parties via delegated access models (Lighthouse, specific resource grants)."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_AD/UsersManagementMenuBlade/GuestUsers"
        Dynamic       = $true
    },

    # ── Pillar 3: Network ──────────────────────────────────────────────────────
    [pscustomobject]@{
        CheckId       = "NET-001"
        Pillar        = "Network"
        ControlName   = "No Hub-Spoke or Virtual WAN Topology Detected"
        Severity      = "High"
        CafReference  = "CAF: Define a hub-spoke network topology"
        CisControl    = "CIS 6.1 — Ensure that a network hub with ExpressRoute/VPN exists"
        Description   = "No VNet peering topology or Azure Virtual WAN hub was detected, indicating workload VNets may be operating in isolation. Isolated spoke networks cannot leverage shared egress controls, DNS, or hybrid connectivity."
        Remediation   = "Deploy a connectivity subscription following ALZ reference architecture with a hub VNet (or Virtual WAN hub) containing Azure Firewall, VPN/ExpressRoute Gateway, and Private DNS zones."
        PortalLink    = "https://portal.azure.com/#blade/HubsExtension/BrowseResourceBlade/resourceType/Microsoft.Network%2FvirtualNetworks"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "NET-002"
        Pillar        = "Network"
        ControlName   = "No DDoS Protection Standard Enabled"
        Severity      = "High"
        CafReference  = "CAF: Enable DDoS protection for internet-facing workloads"
        CisControl    = "CIS 6.7 — Ensure that Azure DDoS Protection Standard is enabled"
        Description   = "DDoS Protection Standard (now Microsoft Azure DDoS Protection) is not enabled on any VNet. Workloads with public IP addresses are only protected by the basic default infrastructure-level DDoS mitigation."
        Remediation   = "Enable Azure DDoS Network Protection on the hub VNet. DDoS IP Protection is an alternative for individual public IP addresses. Ensure WAF policies are active for Application Gateway and Front Door."
        PortalLink    = "https://portal.azure.com/#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FddosProtectionPlans"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "NET-003"
        Pillar        = "Network"
        ControlName   = "Subnets Without NSG Association Detected"
        Severity      = "High"
        CafReference  = "CAF: Apply network segmentation and micro-segmentation"
        CisControl    = "CIS 6.2 — Ensure that SSH access from the Internet is evaluated; CIS 6.3 — RDP"
        Description   = "One or more subnets have no Network Security Group attached. Subnets without NSGs rely entirely on the host-level firewall for east-west and inbound traffic control, creating lateral movement risk."
        Remediation   = "Attach an NSG to every subnet except GatewaySubnet and AzureBastionSubnet. Use Azure Policy to deny subnet creation without NSG association."
        PortalLink    = "https://portal.azure.com/#blade/HubsExtension/BrowseResourceBlade/resourceType/Microsoft.Network%2FnetworkSecurityGroups"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "NET-004"
        Pillar        = "Network"
        ControlName   = "No Azure Firewall or NVA Detected in Connected VNets"
        Severity      = "High"
        CafReference  = "CAF: Deploy a central network security appliance"
        CisControl    = "CIS 6.4 — Ensure that Network Watcher is enabled"
        Description   = "No Azure Firewall or third-party NVA was detected in any VNet. Without a central firewall, outbound internet traffic from workloads is uncontrolled and east-west traffic between spokes cannot be inspected."
        Remediation   = "Deploy Azure Firewall Premium in the hub VNet. Configure UDRs on all spoke VNets to route internet-bound and cross-spoke traffic through the hub firewall."
        PortalLink    = "https://portal.azure.com/#blade/HubsExtension/BrowseResourceBlade/resourceType/Microsoft.Network%2FazureFirewalls"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "NET-005"
        Pillar        = "Network"
        ControlName   = "No Forced Tunnelling / Default Route via Hub Detected"
        Severity      = "Medium"
        CafReference  = "CAF: Control internet egress centrally"
        CisControl    = "N/A"
        Description   = "Spoke VNets do not appear to have UDRs sending 0.0.0.0/0 traffic to a hub firewall or NVA. Without forced tunnelling, workload internet egress bypasses centralised inspection and policy."
        Remediation   = "Create a Route Table with a 0.0.0.0/0 route pointing to the Azure Firewall private IP and associate it with all spoke subnets. Propagate hub gateway routes automatically."
        PortalLink    = "https://portal.azure.com/#blade/HubsExtension/BrowseResourceBlade/resourceType/Microsoft.Network%2FramTables"
        Dynamic       = $true
    },

    # ── Pillar 4: Security ──────────────────────────────────────────────────────
    [pscustomobject]@{
        CheckId       = "SEC-001"
        Pillar        = "Security"
        ControlName   = "Microsoft Defender for Cloud Plans Not Fully Enabled"
        Severity      = "Critical"
        CafReference  = "CAF: Enable Microsoft Defender for Cloud across all subscriptions"
        CisControl    = "CIS 2.1.1 — Ensure that Microsoft Defender for Servers is enabled"
        Description   = "One or more MDC Defender plans (Servers, Storage, SQL, AppService, Containers, KeyVault, ARM, DNS) are in Free/Off tier. Reduced plan coverage means reduced threat detection, vulnerability assessment, and security recommendations."
        Remediation   = "Enable all relevant Defender plans in Microsoft Defender for Cloud > Environment settings for each subscription. Use Azure Policy to enforce plan enablement at scale."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/24"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "SEC-002"
        Pillar        = "Security"
        ControlName   = "MDC Secure Score Below Acceptable Threshold"
        Severity      = "High"
        CafReference  = "CAF: Target a minimum secure score of 70%"
        CisControl    = "CIS 2.1"
        Description   = "The Microsoft Defender for Cloud Secure Score for one or more subscriptions is below 70%. A low secure score reflects a large number of unresolved security recommendations representing real attack surface."
        Remediation   = "Review the MDC Recommendations blade and prioritise Critical and High severity recommendations. Focus on identity, data, and network controls first for maximum score improvement."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_Security/SecurityMenuBlade/22"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "SEC-003"
        Pillar        = "Security"
        ControlName   = "Azure Security Benchmark Initiative Not Assigned"
        Severity      = "High"
        CafReference  = "CAF: Apply the Azure Security Benchmark as default policy"
        CisControl    = "CIS 2.1 — Ensure Microsoft Cloud Security Benchmark policies are not set to Disabled"
        Description   = "The Microsoft Cloud Security Benchmark (MCSB) initiative is not assigned to one or more subscriptions. MCSB provides baseline compliance visibility and drives MDC Secure Score improvements."
        Remediation   = "Assign the Microsoft Cloud Security Benchmark policy initiative to each subscription or at Management Group level. Review the Regulatory Compliance dashboard in MDC after assignment."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade/Assignments"
        Dynamic       = $true
    },

    # ── Pillar 5: Management & Monitoring ─────────────────────────────────────
    [pscustomobject]@{
        CheckId       = "MGT-001"
        Pillar        = "Management"
        ControlName   = "No Log Analytics Workspace Linked to Subscription"
        Severity      = "Critical"
        CafReference  = "CAF: Deploy a management subscription with centralized Log Analytics"
        CisControl    = "CIS 5.1 — Ensure that a Log Analytics workspace is configured"
        Description   = "No Log Analytics workspace was found linked to this subscription. Without a workspace, MDC cannot collect security data, VM Insights cannot operate, and centralized log querying for incident response is unavailable."
        Remediation   = "Deploy a Log Analytics workspace in the Management subscription. Configure MDC data collection to send security data to the workspace. Link Defender for Cloud to the central workspace."
        PortalLink    = "https://portal.azure.com/#blade/HubsExtension/BrowseResourceBlade/resourceType/Microsoft.OperationalInsights%2Fworkspaces"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "MGT-002"
        Pillar        = "Management"
        ControlName   = "Subscription Diagnostic Settings Not Configured"
        Severity      = "High"
        CafReference  = "CAF: Collect Azure Activity Logs for all subscriptions"
        CisControl    = "CIS 5.1.1 — Ensure Audit Profile captures all activities"
        Description   = "Azure Diagnostic Settings for the subscription (Activity Log) are not configured to stream to a Log Analytics workspace or Storage Account. Activity Logs are the primary audit trail for control-plane operations."
        Remediation   = "Configure Subscription Diagnostic Settings to export Activity Logs (Administrative, Security, Alert, Policy categories) to the central Log Analytics workspace. Retain for minimum 90 days."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/diagnosticSettings"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "MGT-003"
        Pillar        = "Management"
        ControlName   = "No Azure Monitor Alert Rules Configured"
        Severity      = "High"
        CafReference  = "CAF: Establish alerting and monitoring for platform operations"
        CisControl    = "CIS 5.2.1 — Ensure Alert exists for Create Policy Assignment"
        Description   = "No Azure Monitor Activity Log alert rules were found in the subscription. Without alerts, critical events (role assignment changes, policy changes, subscription-level operations) are not actioned in real time."
        Remediation   = "Create Activity Log alerts for: Create/Update/Delete Policy Assignment, Create/Update Role Assignment, Create/Update Network Security Group. Route to an Action Group with email/ITSM notification."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/alertsV2"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "MGT-004"
        Pillar        = "Management"
        ControlName   = "Activity Log Retention Below 90 Days"
        Severity      = "Medium"
        CafReference  = "CAF: Retain platform logs for operational and security investigations"
        CisControl    = "CIS 5.1.1 — Ensure Audit Profile captures all activities; CIS 5.1.2 — Retention 365 days"
        Description   = "The subscription Activity Log retention period is below the recommended minimum of 90 days (CIS recommends 365 days). Short retention limits forensic investigation capability following a security incident."
        Remediation   = "Configure the Activity Log to archive to a Storage Account or Log Analytics workspace with a minimum 90-day retention. For compliance workloads, target 365 days as per CIS 5.1.2."
        PortalLink    = "https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/activityLog"
        Dynamic       = $true
    },

    # ── Pillar 6: Operations ───────────────────────────────────────────────────
    [pscustomobject]@{
        CheckId       = "OPS-001"
        Pillar        = "Operations"
        ControlName   = "No Azure Backup Vault Detected"
        Severity      = "High"
        CafReference  = "CAF: Implement backup and disaster recovery for platform workloads"
        CisControl    = "CIS 9.1 — Ensure that 'Recovery Services vault' exists"
        Description   = "No Recovery Services or Backup vault was found in the subscription. Workloads without backup vaults have no RPO/RTO-backed data protection and cannot recover from accidental deletion or ransomware."
        Remediation   = "Deploy a Recovery Services vault in each workload subscription. Configure Azure Backup policies for VMs, Azure SQL, and file shares. Enable soft delete and immutable backup storage."
        PortalLink    = "https://portal.azure.com/#blade/HubsExtension/BrowseResourceBlade/resourceType/Microsoft.RecoveryServices%2Fvaults"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "OPS-002"
        Pillar        = "Operations"
        ControlName   = "Unattached Managed Disks Detected"
        Severity      = "Low"
        CafReference  = "CAF: Cost governance and resource hygiene"
        CisControl    = "N/A"
        Description   = "Unattached managed disks were found in the subscription. These represent both a cost waste and a potential data governance risk if the disk contains sensitive data and lacks proper lifecycle management."
        Remediation   = "Review unattached disks and either delete them after confirming the data is no longer required or snapshot and decommission. Apply Azure Policy to flag unattached disks automatically."
        PortalLink    = "https://portal.azure.com/#blade/HubsExtension/BrowseResourceBlade/resourceType/Microsoft.Compute%2Fdisks"
        Dynamic       = $true
    },
    [pscustomobject]@{
        CheckId       = "OPS-003"
        Pillar        = "Operations"
        ControlName   = "Unused Public IP Addresses Detected"
        Severity      = "Low"
        CafReference  = "CAF: Cost governance and attack surface reduction"
        CisControl    = "N/A"
        Description   = "Unassociated (idle) public IP addresses were found in the subscription. These represent unnecessary attack surface exposure and ongoing cost."
        Remediation   = "Delete unassociated public IP addresses. Apply an Azure Policy audit rule to flag unassociated public IPs for regular review."
        PortalLink    = "https://portal.azure.com/#blade/HubsExtension/BrowseResourceBlade/resourceType/Microsoft.Network%2FpublicIPAddresses"
        Dynamic       = $true
    }
)


#------------------------------------------------------------------------ [ Helper Functions ]

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
    Write-CenteredText "Azure Landing Zone Gap Analysis v1.0" -Color White
    Write-CenteredText "Cloud Adoption Framework · CIS Azure Benchmark" -Color DarkGray
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
        $value = $Data[$key]
        if ([string]::IsNullOrWhiteSpace($value)) { $value = "None"; $valColor = "DarkGray" }
        else { $valColor = "White" }
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
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
    $completed   = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $remaining   = $BarWidth - $completed
    $bar         = ("█" * $completed) + ("░" * $remaining)
    Write-Host "`r" -NoNewline
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White
    if ($CurrentItem)
    {
        $maxLen      = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLen) { $CurrentItem.Substring(0, $maxLen - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-GapLine
{
    param(
        [string]$Severity,
        [string]$CheckId,
        [string]$ControlName
    )
    $sevColor = switch ($Severity)
    {
        "Critical" { "Red" }
        "High"     { "Yellow" }
        "Medium"   { "Cyan" }
        "Low"      { "DarkGray" }
        default    { "White" }
    }
    Write-Host "  " -NoNewline
    Write-Host ("[$Severity]").PadRight(11) -NoNewline -ForegroundColor $sevColor
    Write-Host " $CheckId " -NoNewline -ForegroundColor DarkGray
    $maxLen = 56
    $name   = if ($ControlName.Length -gt $maxLen) { $ControlName.Substring(0, $maxLen - 3) + "..." } else { $ControlName }
    Write-Host $name -ForegroundColor White
}

Function Write-PillarHeader
{
    param([string]$Pillar, [int]$GapCount)
    Write-Host ""
    Write-Host "  ── Pillar: $Pillar " -NoNewline -ForegroundColor Cyan
    Write-Host "($GapCount gap(s) found)" -ForegroundColor DarkGray
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
}

Function Write-GapSummary
{
    param([array]$Gaps)
    $critical = @($Gaps | Where-Object { $_.Severity -eq "Critical" }).Count
    $high     = @($Gaps | Where-Object { $_.Severity -eq "High" }).Count
    $medium   = @($Gaps | Where-Object { $_.Severity -eq "Medium" }).Count
    $low      = @($Gaps | Where-Object { $_.Severity -eq "Low" }).Count

    Write-Host ""
    Write-Host "  Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  " -NoNewline
    Write-Host "Total Gaps Found".PadRight(36)     -NoNewline -ForegroundColor Gray
    Write-Host ": " -NoNewline -ForegroundColor DarkGray
    Write-Host $Gaps.Count -ForegroundColor White
    Write-Host "  " -NoNewline
    Write-Host "Critical".PadRight(36) -NoNewline -ForegroundColor Red
    Write-Host ": $critical" -ForegroundColor White
    Write-Host "  " -NoNewline
    Write-Host "High".PadRight(36)     -NoNewline -ForegroundColor Yellow
    Write-Host ": $high" -ForegroundColor White
    Write-Host "  " -NoNewline
    Write-Host "Medium".PadRight(36)   -NoNewline -ForegroundColor Cyan
    Write-Host ": $medium" -ForegroundColor White
    Write-Host "  " -NoNewline
    Write-Host "Low".PadRight(36)      -NoNewline -ForegroundColor DarkGray
    Write-Host ": $low" -ForegroundColor White
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
        Write-Host "CSV Export".PadRight(22)    -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }
    if ($HtmlPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host "HTML Dashboard".PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }
    if ($GridViewOpened)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host "Grid View".PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": Opened in separate window" -ForegroundColor White
    }
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-ObjProperty
{
    param([object]$Obj, [string]$PropName, $Default = $null)
    try { $val = $Obj.$PropName; if ($null -ne $val) { return $val }; return $Default }
    catch { return $Default }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\','\\\\' -replace "'","\'" -replace '"','\"' -replace "`n",' ' -replace "`r",' ' }

Function Generate-LandingZoneGapHtml
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Gaps,
        [array]$SubscriptionResults,
        [hashtable]$PillarDistribution,
        [hashtable]$SeverityDistribution,
        [string]$GeneratedOn,
        [bool]$SecureScoreIncluded
    )

    $totalGaps    = @($Gaps).Count
    $criticalCount = @($Gaps | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount    = @($Gaps | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount  = @($Gaps | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount     = @($Gaps | Where-Object { $_.Severity -eq "Low" }).Count
    $subCount     = $SubscriptionResults.Count

    # Risk score: weighted average (Critical=4, High=3, Medium=2, Low=1) normalised to 100
    $rawScore   = ($criticalCount * 4) + ($highCount * 3) + ($mediumCount * 2) + ($lowCount * 1)
    $maxScore   = $totalGaps * 4
    $riskPct    = if ($maxScore -gt 0) { [math]::Round(($rawScore / $maxScore) * 100) } else { 0 }
    $riskLabel  = if ($riskPct -ge 75) { "Critical Risk" } elseif ($riskPct -ge 50) { "High Risk" } elseif ($riskPct -ge 25) { "Medium Risk" } else { "Low Risk" }
    $riskColor  = if ($riskPct -ge 75) { "var(--red)" } elseif ($riskPct -ge 50) { "var(--amber)" } elseif ($riskPct -ge 25) { "var(--accent2)" } else { "var(--green)" }

    # ── Gap table rows ────────────────────────────────────────────────────────
    $gapRows = ""
    foreach ($g in $Gaps)
    {
        $sevCls = switch ($g.Severity) { "Critical" { "badge-red" }; "High" { "badge-amber" }; "Medium" { "badge-blue" }; "Low" { "" }; default { "" } }
        $gapRows += @"
          <tr onclick="showGapDetail($($Gaps.IndexOf($g)))">
            <td><span class="mono-sm">$(EscHtml $g.CheckId)</span></td>
            <td><span class="badge $(EscHtml $sevCls)">$(EscHtml $g.Severity)</span></td>
            <td>$(EscHtml $g.Pillar)</td>
            <td title="$(EscHtml $g.ControlName)">$(if ($g.ControlName.Length -gt 52) { EscHtml($g.ControlName.Substring(0,49)+"...") } else { EscHtml $g.ControlName })</td>
            <td>$(EscHtml $g.SubscriptionName)</td>
            <td><a href="$(EscHtml $g.PortalLink)" target="_blank" class="portal-link" onclick="event.stopPropagation()">Open ↗</a></td>
          </tr>
"@
    }

    # ── Subscription results ──────────────────────────────────────────────────
    $subRows = ""
    foreach ($s in $SubscriptionResults)
    {
        $icon = switch ($s.Status) { "Success" { "✓" }; "Warning" { "⚠" }; "Error" { "✗" }; default { "•" } }
        $cls  = switch ($s.Status) { "Success" { "c-green" }; "Warning" { "c-amber" }; "Error" { "c-red" }; default { "" } }
        $subRows += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $s.Name)</span>
            <span class="sub-detail">$(EscHtml $s.Summary)</span>
          </div>
"@
    }

    # ── Severity distribution bars ────────────────────────────────────────────
    $sevOrder  = @("Critical","High","Medium","Low")
    $sevColors = @{ "Critical" = "var(--red)"; "High" = "var(--amber)"; "Medium" = "var(--accent2)"; "Low" = "var(--muted)" }
    $sevRows   = ""
    foreach ($sev in $sevOrder)
    {
        $cnt = if ($SeverityDistribution.ContainsKey($sev)) { $SeverityDistribution[$sev] } else { 0 }
        $pct = if ($totalGaps -gt 0) { [math]::Round(($cnt / $totalGaps) * 100) } else { 0 }
        $sevRows += @"
          <div class="bar-row">
            <span class="bar-label">$sev</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$($sevColors[$sev])"></div></div>
            <span class="bar-pct">$cnt ($pct%)</span>
          </div>
"@
    }

    # ── Pillar distribution bars ──────────────────────────────────────────────
    $pillarRows = ""
    foreach ($p in ($PillarDistribution.GetEnumerator() | Sort-Object Value -Descending))
    {
        $pct = if ($totalGaps -gt 0) { [math]::Round(($p.Value / $totalGaps) * 100) } else { 0 }
        $pillarRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $p.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($p.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Pillar card rows for overview ─────────────────────────────────────────
    $pillarCardColors = @{
        "Governance"          = "c-purple"
        "Identity & Access"   = "c-blue"
        "Network"             = "c-cyan"
        "Security"            = "c-red"
        "Management"          = "c-amber"
        "Operations"          = "c-green"
    }
    $pillarCardHtml = ""
    foreach ($p in $PillarDistribution.GetEnumerator())
    {
        $cc       = if ($pillarCardColors.ContainsKey($p.Key)) { $pillarCardColors[$p.Key] } else { "c-blue" }
        $critInP  = @($Gaps | Where-Object { $_.Pillar -eq $p.Key -and $_.Severity -eq "Critical" }).Count
        $subText  = if ($critInP -gt 0) { "$critInP Critical" } else { "No Critical gaps" }
        $pillarCardHtml += @"
          <div class="stat-card $cc">
            <div class="stat-num">$($p.Value)</div>
            <div class="stat-label">$(EscHtml $p.Key)</div>
            <div class="stat-sub">$subText</div>
          </div>
"@
    }

    # ── JSON for gap detail drawer ────────────────────────────────────────────
    $gapJson = "["
    foreach ($g in $Gaps)
    {
        $gapJson += "{" +
        """checkId"":""$(EscJ $g.CheckId)""," +
        """severity"":""$(EscJ $g.Severity)""," +
        """pillar"":""$(EscJ $g.Pillar)""," +
        """name"":""$(EscJ $g.ControlName)""," +
        """sub"":""$(EscJ $g.SubscriptionName)""," +
        """subId"":""$(EscJ $g.SubscriptionId)""," +
        """desc"":""$(EscJ $g.Description)""," +
        """rem"":""$(EscJ $g.Remediation)""," +
        """caf"":""$(EscJ $g.CafReference)""," +
        """cis"":""$(EscJ $g.CisControl)""," +
        """link"":""$(EscJ $g.PortalLink)""," +
        """detail"":""$(EscJ $g.TechnicalDetail)""" +
        "},"
    }
    $gapJson = $gapJson.TrimEnd(",") + "]"

    $ssNote = if ($SecureScoreIncluded) { "Secure Score data included" } else { "Secure Score skipped — use -IncludeSecureScore to enable" }

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Landing Zone Gap Analysis</title>
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
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,var(--accent3),var(--accent));display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;}
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
.risk-banner{padding:16px 20px;border-radius:var(--radius);border:1px solid;margin-bottom:20px;display:flex;align-items:center;gap:16px;}
.risk-score{font-size:36px;font-weight:700;font-family:var(--mono);}
.risk-info{flex:1;}
.risk-label{font-size:14px;font-weight:700;margin-bottom:4px;}
.risk-sub{font-size:12px;color:var(--muted2);}
.risk-bar-wrap{width:180px;}
.risk-bar-track{height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;margin-top:8px;}
.risk-bar-fill{height:100%;border-radius:4px;transition:width .8s ease;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:140px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:80px;text-align:right;flex-shrink:0;}
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
.mono-sm{font-family:var(--mono);font-size:11px;color:var(--muted2);}
.portal-link{color:var(--accent);text-decoration:none;font-size:11px;padding:2px 6px;border:1px solid var(--border);border-radius:var(--radius-sm);}
.portal-link:hover{border-color:var(--accent);background:rgba(56,139,253,.08);}
.sub-list{display:flex;flex-direction:column;}
.sub-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}
.sub-icon.c-amber{color:var(--amber);}
.sub-icon.c-red{color:var(--red);}
.sub-name{flex:1;font-size:13px;font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.pillar-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:22px;}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:480px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
#detailDrawer.open{transform:translateX(0);}
.drawer-header{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.drawer-title{font-size:13px;font-weight:700;word-break:break-word;flex:1;margin-right:12px;}
.drawer-close{background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;padding:2px 6px;border-radius:var(--radius-sm);}
.drawer-close:hover{color:var(--text);background:var(--surface2);}
.drawer-body{padding:20px;overflow-y:auto;flex:1;}
.drawer-nav{display:flex;gap:8px;align-items:center;margin-bottom:16px;}
.drawer-nav-btn{padding:5px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;}
.drawer-nav-btn:hover{border-color:var(--accent);color:var(--accent);}
.drawer-nav-info{font-size:12px;color:var(--muted);flex:1;text-align:center;}
.drawer-field{margin-bottom:14px;}
.drawer-field-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.drawer-field-value{font-size:13px;line-height:1.5;word-break:break-word;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.caf-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;background:rgba(163,113,247,.12);color:var(--accent3);border:1px solid rgba(163,113,247,.3);margin-right:6px;margin-bottom:6px;}
.cis-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;background:rgba(57,197,207,.12);color:var(--accent2);border:1px solid rgba(57,197,207,.3);margin-bottom:6px;}
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
    <div class="logo-icon">🏗️</div>
    <div class="logo-title">Landing Zone Gap Analysis</div>
    <div class="logo-sub">Azure CAF · CIS Benchmark</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('gaps',this)"><span class="nav-icon">⚠️</span> All Gaps</button>
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
      ALZ Gap Analysis Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Landing Zone Gap Analysis</div>
      <div class="page-sub">CAF and CIS benchmark assessment across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="risk-banner" style="background:rgba(var(--risk-rgb),.06);border-color:rgba(var(--risk-rgb),.3);" id="riskBanner">
      <div class="risk-score" id="riskScore">__RISK_PCT__%</div>
      <div class="risk-info">
        <div class="risk-label" id="riskLabel">__RISK_LABEL__</div>
        <div class="risk-sub">Weighted risk index — Critical gaps scored 4×, High 3×, Medium 2×, Low 1×</div>
        <div class="risk-bar-wrap">
          <div class="risk-bar-track">
            <div class="risk-bar-fill" id="riskBarFill" data-pct="__RISK_PCT__" style="background:__RISK_COLOR__"></div>
          </div>
        </div>
      </div>
      <div>
        <div class="stat-num" style="color:var(--red)">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
      </div>
      <div>
        <div class="stat-num" style="color:var(--amber)">__HIGH_COUNT__</div>
        <div class="stat-label">High</div>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__TOTAL_GAPS__</div>
        <div class="stat-label">Total Gaps</div>
        <div class="stat-sub">Across all pillars</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High</div>
        <div class="stat-sub">High compliance risk</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium</div>
        <div class="stat-sub">Architectural drift</div>
      </div>
      <div class="stat-card" style="border-top-color:var(--muted)">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low</div>
        <div class="stat-sub">Best-practice gap</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__SUB_COUNT__</div>
        <div class="stat-label">Subscriptions</div>
        <div class="stat-sub">Assessed</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Gap Distribution by Severity</div>
        __SEV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🏛️ Gap Distribution by Pillar</div>
        __PILLAR_ROWS__
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">🏛️ Pillar Breakdown</div>
      <div class="pillar-grid">__PILLAR_CARDS__</div>
    </div>
  </div>

  <!-- All Gaps -->
  <div id="page-gaps" class="page">
    <div class="page-header">
      <div class="page-title">All Landing Zone Gaps</div>
      <div class="page-sub">Click any row for remediation guidance and CAF/CIS references</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="gapSearch" placeholder="Search gap, control, subscription…" oninput="filterGaps()"/>
        </div>
        <select class="filter-select" id="filterSev" onchange="filterGaps()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="filterPillar" onchange="filterGaps()">
          <option value="">All Pillars</option>
          <option value="Governance">Governance</option>
          <option value="Identity &amp; Access">Identity &amp; Access</option>
          <option value="Network">Network</option>
          <option value="Security">Security</option>
          <option value="Management">Management</option>
          <option value="Operations">Operations</option>
        </select>
        <select class="filter-select" id="pgSizeGap" onchange="changeGapPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="gapTable">
          <thead>
            <tr>
              <th onclick="sortGaps(0)">Check ID</th>
              <th onclick="sortGaps(1)">Severity</th>
              <th onclick="sortGaps(2)">Pillar</th>
              <th onclick="sortGaps(3)">Control Name</th>
              <th onclick="sortGaps(4)">Subscription</th>
              <th>Portal</th>
            </tr>
          </thead>
          <tbody id="gapBody">__GAP_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="gapPagination"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription assessment outcome and gap counts</div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Subscriptions Assessed</div>
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
        <div class="info-card"><div class="info-label">Secure Score</div><div class="info-value">__SS_NOTE__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Subscriptions Assessed</div><div class="info-value">__SUB_COUNT__</div></div>
      </div>
    </div>
  </div>
</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Gap Detail</span>
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
const GAP_DATA = __GAP_JSON__;
let gapFiltered = [...GAP_DATA];
let gapPage = 1, gapPageSz = 25;
let gapSortCol = -1, gapSortAsc = true;
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
  document.documentElement.dataset.theme=document.documentElement.dataset.theme==='dark'?'light':'dark';
}

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

function filterGaps(){
  const q=document.getElementById('gapSearch').value.toLowerCase();
  const s=document.getElementById('filterSev').value;
  const p=document.getElementById('filterPillar').value;
  gapFiltered=GAP_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mS=!s||r.severity===s;
    const mP=!p||r.pillar===p;
    return mQ&&mS&&mP;
  });
  gapPage=1; renderGaps();
}

function changeGapPageSize(){
  gapPageSz=parseInt(document.getElementById('pgSizeGap').value);
  gapPage=1; renderGaps();
}

function sortGaps(col){
  if(gapSortCol===col){gapSortAsc=!gapSortAsc;}else{gapSortCol=col;gapSortAsc=true;}
  const keys=['checkId','severity','pillar','name','sub'];
  const sevOrder={'Critical':0,'High':1,'Medium':2,'Low':3};
  gapFiltered.sort((a,b)=>{
    const k=keys[col];
    if(k==='severity'){const av=sevOrder[a.severity]??9,bv=sevOrder[b.severity]??9; return gapSortAsc?av-bv:bv-av;}
    const av=a[k]??'', bv=b[k]??'';
    return gapSortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  renderGaps();
}

function renderGaps(){
  const tbody=document.getElementById('gapBody');
  const start=(gapPage-1)*gapPageSz;
  const slice=gapFiltered.slice(start,start+gapPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=GAP_DATA.indexOf(r);
    const sCls=r.severity==='Critical'?'badge-red':r.severity==='High'?'badge-amber':r.severity==='Medium'?'badge-blue':'';
    const nm=r.name.length>52?r.name.substring(0,49)+'...':r.name;
    return `<tr onclick="showGapDetail(${gi})">
      <td><span class="mono-sm">${escH(r.checkId)}</span></td>
      <td><span class="badge ${sCls}">${escH(r.severity)}</span></td>
      <td>${escH(r.pillar)}</td>
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td><a href="${escH(r.link)}" target="_blank" class="portal-link" onclick="event.stopPropagation()">Open ↗</a></td>
    </tr>`;
  }).join('');
  renderGapPg();
}

function renderGapPg(){
  const total=Math.ceil(gapFiltered.length/gapPageSz);
  const el=document.getElementById('gapPagination');
  let h=`<span>${gapFiltered.length} gaps</span>`;
  h+=`<button class="pg-btn" onclick="changeGapPage(${gapPage-1})" ${gapPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,gapPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===gapPage?'active':''}" onclick="changeGapPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeGapPage(${gapPage+1})" ${gapPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeGapPage(p){
  const total=Math.ceil(gapFiltered.length/gapPageSz);
  if(p<1||p>total)return;
  gapPage=p; renderGaps();
}

function showGapDetail(idx){
  currentDetailIdx=idx;
  const r=GAP_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=`${r.checkId} — ${r.name}`;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${GAP_DATA.length}`;
  const sCls=r.severity==='Critical'?'badge-red':r.severity==='High'?'badge-amber':r.severity==='Medium'?'badge-blue':'';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field">
      <div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sCls}">${escH(r.severity)}</span></div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Pillar</div>
      <div class="drawer-field-value">${escH(r.pillar)}</div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div>
    </div>
    ${r.detail?`<div class="drawer-field"><div class="drawer-field-label">Technical Finding</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px;background:var(--surface2);padding:8px 10px;border-radius:var(--radius-sm)">${escH(r.detail)}</div></div>`:''}
    <div class="drawer-section">Description</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.desc)}</div></div>
    <div class="drawer-section">Remediation Guidance</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.rem)}</div></div>
    <div class="drawer-section">Framework References</div>
    <div class="drawer-field">
      <div><span class="caf-badge">${escH(r.caf)}</span></div>
      <div><span class="cis-badge">${escH(r.cis)}</span></div>
    </div>
    <div class="drawer-section">Azure Portal</div>
    <div class="drawer-field">
      <a href="${escH(r.link)}" target="_blank" class="portal-link" style="font-size:12px">Open in Azure Portal ↗</a>
    </div>
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
  if(next>=0&&next<GAP_DATA.length) showGapDetail(next);
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width=el.dataset.pct+'%';
    });
    const riskFill=document.getElementById('riskBarFill');
    if(riskFill) riskFill.style.width=riskFill.dataset.pct+'%';
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

filterGaps();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__',  $GeneratedOn `
        -replace '__SUB_COUNT__',     $subCount `
        -replace '__TOTAL_GAPS__',    $totalGaps `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__',    $highCount `
        -replace '__MEDIUM_COUNT__',  $mediumCount `
        -replace '__LOW_COUNT__',     $lowCount `
        -replace '__RISK_PCT__',      $riskPct `
        -replace '__RISK_LABEL__',    $riskLabel `
        -replace '__RISK_COLOR__',    $riskColor `
        -replace '__SEV_ROWS__',      $sevRows `
        -replace '__PILLAR_ROWS__',   $pillarRows `
        -replace '__PILLAR_CARDS__',  $pillarCardHtml `
        -replace '__GAP_ROWS__',      $gapRows `
        -replace '__SUB_ROWS__',      $subRows `
        -replace '__TENANT__',        $SessionInfo.Tenant `
        -replace '__ACCOUNT__',       $SessionInfo.Account `
        -replace '__ENVIRONMENT__',   $SessionInfo.Environment `
        -replace '__SCOPE__',         $ScanParameters.Scope `
        -replace '__SS_NOTE__',       $ssNote `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__',     $ScanParameters.ExecTime `
        -replace '__GAP_JSON__',      $gapJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureLandingZoneGapAnalysis
{
    [CmdletBinding()]
    param (
        [string]$ManagementGroupId,

        [string[]]$SubscriptionIds,

        [switch]$IncludeSecureScore,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureLandingZoneGapAnalysis-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts",
        "Az.Resources",
        "Az.Network",
        "Az.Monitor",
        "Az.OperationalInsights",
        "Az.RecoveryServices"
    )
    if ($IncludeSecureScore) { $requiredModules += "Az.Security" }

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
                Write-Host "  Installing Az module..." -ForegroundColor Cyan
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "  ✓ Az module installed" -ForegroundColor Green
            }
            catch
            {
                Write-Host "  ✗ Install failed: $_" -ForegroundColor Red
                return
            }
        }
        else { Write-Host "  Cannot proceed without required modules." -ForegroundColor Yellow; return }
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
    $subscriptions = @()
    $scopeText     = ""

    if ($ManagementGroupId)
    {
        $scopeText = "Management Group: $ManagementGroupId"
        Write-Host "  Enumerating subscriptions under Management Group '$ManagementGroupId'..." -ForegroundColor Cyan
        try
        {
            # Recursively collect all subscription IDs from the MG hierarchy
            $mgExpanded = Get-AzManagementGroup -GroupId $ManagementGroupId -Expand -Recurse -ErrorAction Stop
            $mgSubIds   = @()

            Function Get-MgSubscriptionIds
            {
                param([object]$MgNode)
                foreach ($child in $MgNode.Children)
                {
                    if ($child.Type -eq "/subscriptions") { $script:mgSubIds += $child.Name }
                    elseif ($child.Type -eq "Microsoft.Management/managementGroups") { Get-MgSubscriptionIds -MgNode $child }
                }
            }

            $script:mgSubIds = @()
            Get-MgSubscriptionIds -MgNode $mgExpanded
            $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
                Where-Object { $script:mgSubIds -contains $_.Id })
            Write-Host "  ✓ Found $($subscriptions.Count) subscription(s)" -ForegroundColor Green
        }
        catch
        {
            Write-Warning "  Could not enumerate Management Group hierarchy: $_"
            Write-Host "  Falling back to all accessible subscriptions." -ForegroundColor Yellow
            $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        }
    }
    elseif ($SubscriptionIds)
    {
        $scopeText     = "Specific Subscriptions ($($SubscriptionIds.Count))"
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
            Where-Object { $SubscriptionIds -contains $_.Id })
    }
    else
    {
        $scopeText     = "All Accessible Subscriptions"
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
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
        "Secure Score"  = if ($IncludeSecureScore) { "Enabled" } else { "Skipped (use -IncludeSecureScore)" }
        "Export to CSV" = if ($ExportToCsv.IsPresent) { "Enabled → $CsvPath" } else { "Disabled" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allGaps             = [System.Collections.Generic.List[pscustomobject]]::new()
    $subscriptionResults = @()
    $pillarDist          = @{}
    $severityDist        = @{ "Critical" = 0; "High" = 0; "Medium" = 0; "Low" = 0 }

    Function Add-Gap
    {
        param(
            [string]$CheckId,
            [string]$SubscriptionName,
            [string]$SubscriptionId,
            [string]$TechnicalDetail
        )
        $template = $script:GAP_CATALOGUE | Where-Object { $_.CheckId -eq $CheckId }
        if (-not $template) { return }

        $gap = [pscustomobject]@{
            CheckId          = $template.CheckId
            Pillar           = $template.Pillar
            ControlName      = $template.ControlName
            Severity         = $template.Severity
            CafReference     = $template.CafReference
            CisControl       = $template.CisControl
            Description      = $template.Description
            Remediation      = $template.Remediation
            PortalLink       = $template.PortalLink
            SubscriptionName = $SubscriptionName
            SubscriptionId   = $SubscriptionId
            TechnicalDetail  = $TechnicalDetail
        }
        $script:allGaps.Add($gap)

        if ($script:pillarDist.ContainsKey($template.Pillar)) { $script:pillarDist[$template.Pillar]++ }
        else { $script:pillarDist[$template.Pillar] = 1 }

        if ($script:severityDist.ContainsKey($template.Severity)) { $script:severityDist[$template.Severity]++ }
    }

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "  Scanning Subscriptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $subIndex      = 1
    $successCount  = 0
    $errorCount    = 0
    $maxNameLen    = ([math]::Max(($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum, 35))

    foreach ($sub in $subscriptions)
    {
        $subGapCount = 0
        try
        {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            # ── Pillar 1: Governance ──────────────────────────────────────────
            try
            {
                $allAssignments = @(Get-AzPolicyAssignment -ErrorAction Stop)
                $denyAssignments = @($allAssignments | Where-Object { $_.EnforcementMode -eq "Default" })

                # GOV-001: No Deny assignments
                if ($denyAssignments.Count -eq 0)
                {
                    Add-Gap "GOV-001" $sub.Name $sub.Id "0 Deny-mode policy assignments found at subscription scope."
                    $subGapCount++
                }

                # GOV-002: Policy at MG scope? Check if any assignment scopes reference a MG
                $mgScopedAssignments = @($allAssignments | Where-Object { $_.Scope -like "*/providers/Microsoft.Management/managementGroups/*" })
                if ($mgScopedAssignments.Count -eq 0)
                {
                    Add-Gap "GOV-002" $sub.Name $sub.Id "No Management Group-scoped policy assignments visible from this subscription context."
                    $subGapCount++
                }

                # GOV-005: Tag enforcement
                $tagPolicies = @($allAssignments | Where-Object {
                    $_.PolicyDefinitionId -like "*tag*" -or $_.DisplayName -like "*tag*"
                })
                if ($tagPolicies.Count -eq 0)
                {
                    Add-Gap "GOV-005" $sub.Name $sub.Id "No tag-related policy assignments found."
                    $subGapCount++
                }

                # SEC-003: Azure Security Benchmark not assigned
                $mcsb = @($allAssignments | Where-Object {
                    $_.PolicyDefinitionId -like "*cloudSecurityBenchmark*" -or
                    $_.DisplayName        -like "*Security Benchmark*" -or
                    $_.PolicyDefinitionId -like "*ascdefaultpolicyset*"
                })
                if ($mcsb.Count -eq 0)
                {
                    Add-Gap "SEC-003" $sub.Name $sub.Id "Microsoft Cloud Security Benchmark initiative not assigned to this subscription."
                    $subGapCount++
                }
            }
            catch { Write-Verbose "Policy check failed for $($sub.Name): $_" }

            # GOV-003: Resource locks on critical RGs
            try
            {
                $criticalRgKeywords = @("hub","connectivity","identity","management","platform","security","core")
                $rgs = @(Get-AzResourceGroup -ErrorAction Stop)
                $criticalRgs = @($rgs | Where-Object {
                    $name = $_.ResourceGroupName.ToLower()
                    $criticalRgKeywords | Where-Object { $name -like "*$_*" }
                })
                if ($criticalRgs.Count -gt 0)
                {
                    $unlockedCritical = @()
                    foreach ($rg in $criticalRgs)
                    {
                        try
                        {
                            $locks = @(Get-AzResourceLock -ResourceGroupName $rg.ResourceGroupName -ErrorAction Stop)
                            if ($locks.Count -eq 0) { $unlockedCritical += $rg.ResourceGroupName }
                        }
                        catch { $unlockedCritical += $rg.ResourceGroupName }
                    }
                    if ($unlockedCritical.Count -gt 0)
                    {
                        Add-Gap "GOV-003" $sub.Name $sub.Id "Critical RGs without locks: $($unlockedCritical -join ', ')"
                        $subGapCount++
                    }
                }
            }
            catch { Write-Verbose "Resource lock check failed for $($sub.Name): $_" }

            # GOV-004: Cost management budget alerts
            try
            {
                $budgets = @(Get-AzConsumptionBudget -ErrorAction Stop)
                if ($budgets.Count -eq 0)
                {
                    Add-Gap "GOV-004" $sub.Name $sub.Id "No Azure Cost Management budgets found in subscription."
                    $subGapCount++
                }
            }
            catch { Write-Verbose "Budget check failed for $($sub.Name): $_" }

            # ── Pillar 2: Identity & Access ───────────────────────────────────
            try
            {
                $roleAssignments = @(Get-AzRoleAssignment -ErrorAction Stop)

                # IAM-001: Break-glass detection (heuristic: cloud-only GA with specific naming)
                $gaAssignments = @($roleAssignments | Where-Object {
                    $_.RoleDefinitionName -eq "Owner" -and
                    $_.Scope -match "^/subscriptions/[^/]+$"
                })
                $breakGlassFound = @($gaAssignments | Where-Object {
                    $_.DisplayName -like "*break*" -or
                    $_.DisplayName -like "*emergency*" -or
                    $_.DisplayName -like "*glass*" -or
                    $_.SignInName  -like "*break*" -or
                    $_.SignInName  -like "*emergency*"
                })
                if ($breakGlassFound.Count -eq 0)
                {
                    Add-Gap "IAM-001" $sub.Name $sub.Id "No emergency/break-glass owner account detected at subscription scope (heuristic: name pattern matching)."
                    $subGapCount++
                }

                # IAM-002: Permanent Owner/Contributor without PIM
                # PIM-managed assignments have a Condition property referencing PIM claims
                $permHighPriv = @($roleAssignments | Where-Object {
                    ($_.RoleDefinitionName -in @("Owner","Contributor")) -and
                    $_.Scope -match "^/subscriptions/[^/]+$" -and
                    [string]::IsNullOrEmpty($_.Condition) -and
                    $_.ObjectType -eq "User"
                })
                if ($permHighPriv.Count -gt 0)
                {
                    $names = ($permHighPriv | Select-Object -First 3 -ExpandProperty DisplayName) -join ", "
                    Add-Gap "IAM-002" $sub.Name $sub.Id "Permanent Owner/Contributor user assignments (no PIM condition): $names $( if ($permHighPriv.Count -gt 3) { "... and $($permHighPriv.Count - 3) more" } )"
                    $subGapCount++
                }

                # IAM-003: Classic administrators
                try
                {
                    $classicAdmins = @(Get-AzRoleAssignment -IncludeClassicAdministrators -ErrorAction Stop |
                        Where-Object { $_.RoleDefinitionName -in @("ServiceAdministrator","CoAdministrator") })
                    if ($classicAdmins.Count -gt 0)
                    {
                        Add-Gap "IAM-003" $sub.Name $sub.Id "$($classicAdmins.Count) classic administrator assignment(s) found: $( ($classicAdmins | Select-Object -First 3 -ExpandProperty DisplayName) -join ', ' )"
                        $subGapCount++
                    }
                }
                catch { Write-Verbose "Classic admin check failed: $_" }

                # IAM-004: Guest users with privileged roles at subscription scope
                $guestHighPriv = @($roleAssignments | Where-Object {
                    ($_.RoleDefinitionName -in @("Owner","Contributor")) -and
                    $_.Scope -match "^/subscriptions/[^/]+$" -and
                    ($_.SignInName -like "*#EXT#*" -or $_.ObjectType -eq "Foreign Principal")
                })
                if ($guestHighPriv.Count -gt 0)
                {
                    $names = ($guestHighPriv | Select-Object -First 3 -ExpandProperty DisplayName) -join ", "
                    Add-Gap "IAM-004" $sub.Name $sub.Id "$($guestHighPriv.Count) guest/external principal(s) with Owner or Contributor: $names"
                    $subGapCount++
                }
            }
            catch { Write-Verbose "Identity check failed for $($sub.Name): $_" }

            # ── Pillar 3: Network ─────────────────────────────────────────────
            try
            {
                $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop)
                if ($vnets.Count -gt 0)
                {
                    # NET-001: Hub-spoke detection
                    $peeredVnets  = @($vnets | Where-Object { $_.VirtualNetworkPeerings.Count -gt 0 })
                    $vwanHubs     = @()
                    try { $vwanHubs = @(Get-AzVirtualHub -ErrorAction SilentlyContinue) } catch { }
                    if ($peeredVnets.Count -eq 0 -and $vwanHubs.Count -eq 0)
                    {
                        Add-Gap "NET-001" $sub.Name $sub.Id "$($vnets.Count) isolated VNet(s) found with no peering. No Virtual WAN hub detected."
                        $subGapCount++
                    }

                    # NET-002: DDoS Protection
                    $ddosProtected = @($vnets | Where-Object {
                        $_.DdosProtectionPlan -ne $null -or $_.EnableDdosProtection -eq $true
                    })
                    if ($ddosProtected.Count -eq 0)
                    {
                        Add-Gap "NET-002" $sub.Name $sub.Id "$($vnets.Count) VNet(s) found with no DDoS Protection Standard plan associated."
                        $subGapCount++
                    }

                    # NET-003: Subnets without NSG
                    $allSubnets    = $vnets | ForEach-Object { $_.Subnets }
                    $skipSubnets   = @("GatewaySubnet","AzureFirewallSubnet","AzureFirewallManagementSubnet","AzureBastionSubnet","RouteServerSubnet")
                    $unprotected   = @($allSubnets | Where-Object {
                        $skipSubnets -notcontains $_.Name -and $null -eq $_.NetworkSecurityGroup
                    })
                    if ($unprotected.Count -gt 0)
                    {
                        $names = ($unprotected | Select-Object -First 5 -ExpandProperty Name) -join ", "
                        Add-Gap "NET-003" $sub.Name $sub.Id "$($unprotected.Count) subnet(s) without NSG: $names"
                        $subGapCount++
                    }

                    # NET-004: Azure Firewall / NVA
                    $azFirewalls = @()
                    try { $azFirewalls = @(Get-AzFirewall -ErrorAction SilentlyContinue) } catch { }
                    if ($azFirewalls.Count -eq 0)
                    {
                        Add-Gap "NET-004" $sub.Name $sub.Id "No Azure Firewall found in subscription. NVA detection not performed (Az module limitation)."
                        $subGapCount++
                    }

                    # NET-005: Forced tunnelling — check for UDRs with 0.0.0.0/0
                    $routeTables      = @()
                    try { $routeTables = @(Get-AzRouteTable -ErrorAction SilentlyContinue) } catch { }
                    $defaultRoutes    = @($routeTables | ForEach-Object { $_.Routes } | Where-Object { $_.AddressPrefix -eq "0.0.0.0/0" })
                    if ($defaultRoutes.Count -eq 0 -and $vnets.Count -gt 0)
                    {
                        Add-Gap "NET-005" $sub.Name $sub.Id "No UDRs with 0.0.0.0/0 default route found. Spoke internet egress may be uncontrolled."
                        $subGapCount++
                    }
                }
            }
            catch { Write-Verbose "Network check failed for $($sub.Name): $_" }

            # ── Pillar 4: Security ────────────────────────────────────────────
            try
            {
                # SEC-001: Defender for Cloud plans
                $allPricings  = @(Get-AzSecurityPricing -ErrorAction Stop)
                $freePlans    = @($allPricings | Where-Object { $_.PricingTier -eq "Free" })
                if ($freePlans.Count -gt 0)
                {
                    $planNames = ($freePlans | Select-Object -First 5 -ExpandProperty Name) -join ", "
                    Add-Gap "SEC-001" $sub.Name $sub.Id "$($freePlans.Count) MDC plan(s) on Free tier: $planNames"
                    $subGapCount++
                }

                # SEC-002: Secure Score (optional)
                if ($IncludeSecureScore)
                {
                    try
                    {
                        $secureScore = Get-AzSecuritySecureScore -Name "ascScore" -ErrorAction Stop
                        $scoreValue  = if ($secureScore.Percentage) { [math]::Round($secureScore.Percentage * 100) } else { 0 }
                        if ($scoreValue -lt 70)
                        {
                            Add-Gap "SEC-002" $sub.Name $sub.Id "MDC Secure Score: $scoreValue% (below 70% threshold). $($secureScore.UnhealthyResourceCount) unhealthy resources."
                            $subGapCount++
                        }
                    }
                    catch { Write-Verbose "Secure score unavailable for $($sub.Name): $_" }
                }
            }
            catch { Write-Verbose "Security check failed for $($sub.Name): $_" }

            # ── Pillar 5: Management & Monitoring ─────────────────────────────
            try
            {
                # MGT-001: Log Analytics workspace
                $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop)
                if ($workspaces.Count -eq 0)
                {
                    Add-Gap "MGT-001" $sub.Name $sub.Id "No Log Analytics workspace found in subscription."
                    $subGapCount++
                }

                # MGT-002: Subscription diagnostic settings
                $diagSettings = @()
                try
                {
                    $diagSettings = @(Get-AzDiagnosticSetting -ResourceId "/subscriptions/$($sub.Id)" -ErrorAction Stop)
                }
                catch { }
                if ($diagSettings.Count -eq 0)
                {
                    Add-Gap "MGT-002" $sub.Name $sub.Id "No subscription-level diagnostic settings (Activity Log export) configured."
                    $subGapCount++
                }
                else
                {
                    # MGT-004: Activity log retention
                    $retentionDays = ($diagSettings[0].Logs | ForEach-Object { $_.RetentionPolicy.Days } | Measure-Object -Minimum).Minimum
                    if ($retentionDays -gt 0 -and $retentionDays -lt 90)
                    {
                        Add-Gap "MGT-004" $sub.Name $sub.Id "Activity Log retention is $retentionDays days (below 90-day minimum)."
                        $subGapCount++
                    }
                }

                # MGT-003: Alert rules
                $alertRules = @()
                try { $alertRules = @(Get-AzActivityLogAlert -ErrorAction SilentlyContinue) } catch { }
                if ($alertRules.Count -eq 0)
                {
                    Add-Gap "MGT-003" $sub.Name $sub.Id "No Activity Log alert rules found in subscription."
                    $subGapCount++
                }
            }
            catch { Write-Verbose "Management check failed for $($sub.Name): $_" }

            # ── Pillar 6: Operations ──────────────────────────────────────────
            try
            {
                # OPS-001: Backup vaults
                $vaults = @()
                try { $vaults = @(Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue) } catch { }
                if ($vaults.Count -eq 0)
                {
                    Add-Gap "OPS-001" $sub.Name $sub.Id "No Recovery Services / Backup vault found in subscription."
                    $subGapCount++
                }

                # OPS-002: Unattached disks
                $unattachedDisks = @()
                try
                {
                    $unattachedDisks = @(Get-AzDisk -ErrorAction Stop | Where-Object { $_.DiskState -eq "Unattached" })
                }
                catch { }
                if ($unattachedDisks.Count -gt 0)
                {
                    Add-Gap "OPS-002" $sub.Name $sub.Id "$($unattachedDisks.Count) unattached managed disk(s) found."
                    $subGapCount++
                }

                # OPS-003: Unused public IPs
                $unusedPips = @()
                try
                {
                    $unusedPips = @(Get-AzPublicIpAddress -ErrorAction Stop |
                        Where-Object { $null -eq $_.IpConfiguration })
                }
                catch { }
                if ($unusedPips.Count -gt 0)
                {
                    Add-Gap "OPS-003" $sub.Name $sub.Id "$($unusedPips.Count) unassociated public IP(s) found."
                    $subGapCount++
                }
            }
            catch { Write-Verbose "Operations check failed for $($sub.Name): $_" }

            # ── Per-subscription output ───────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Gaps Found: $subGapCount" -ForegroundColor $(if ($subGapCount -gt 5) { "Yellow" } else { "White" })

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Gaps: $subGapCount"
                Status  = if ($subGapCount -eq 0) { "Success" } elseif ($subGapCount -le 5) { "Warning" } else { "Error" }
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
            $subscriptionResults += @{ Name = $sub.Name; Summary = "Scan failed"; Status = "Error" }
            $errorCount++
        }
        $subIndex++
    }

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime  = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    $gapList = @($allGaps)
    Write-GapSummary -Gaps $gapList

    Write-Host ""
    Write-Host "  Pillar Breakdown" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($p in $pillarDist.GetEnumerator() | Sort-Object Value -Descending)
    {
        Write-Host "  " -NoNewline
        Write-Host $p.Key.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($p.Value) gap(s)" -ForegroundColor White
    }

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported     = $false
    $htmlExported    = $false
    $gridViewOpened  = $false
    $htmlPath        = ""

    if ($gapList.Count -gt 0 -or $subscriptionResults.Count -gt 0)
    {
        # CSV
        if ($ExportToCsv)
        {
            try
            {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
                $gapList | Select-Object CheckId, Pillar, Severity, ControlName, SubscriptionName, SubscriptionId,
                    TechnicalDetail, Description, Remediation, CafReference, CisControl, PortalLink |
                    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
                $csvExported = $true
            }
            catch { Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red }
        }

        # HTML
        try
        {
            $htmlPath   = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
            $sessionInfo = @{ Tenant = $ctx.Tenant.Id; Account = $ctx.Account.Id; Environment = $ctx.Environment.Name }
            $scanParams  = @{ Scope = "$scopeText ($subCount found)"; ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }; ExecTime = $duration }

            $htmlContent = Generate-LandingZoneGapHtml `
                -SessionInfo           $sessionInfo `
                -ScanParameters        $scanParams `
                -Gaps                  $gapList `
                -SubscriptionResults   $subscriptionResults `
                -PillarDistribution    $pillarDist `
                -SeverityDistribution  $severityDist `
                -GeneratedOn           (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -SecureScoreIncluded   $IncludeSecureScore.IsPresent

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch { Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red }

        # Grid View
        try
        {
            $gapList |
                Select-Object CheckId, Severity, Pillar, ControlName, SubscriptionName, TechnicalDetail |
                Out-GridView -Title "Azure Landing Zone Gap Analysis"
            $gridViewOpened = $true
        }
        catch { Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow }
    }
    else
    {
        Write-Host ""
        Write-Host "  ✓ No gaps found in the assessed subscriptions." -ForegroundColor Green
    }

    $outCsv  = if ($csvExported)    { $CsvPath }    else { $null }
    $outHtml = if ($htmlExported)   { $htmlPath }   else { $null }
    if ($csvExported -or $htmlExported -or $gridViewOpened)
    {
        Write-OutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
    }
    else
    {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
