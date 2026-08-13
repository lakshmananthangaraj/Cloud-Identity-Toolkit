<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 13 August 2026
Modified-On     : 13 August 2026

.SYNOPSIS
    Evaluates Azure resources against Microsoft Cloud Security Benchmark (MCSB)
    controls using direct resource inspection, Azure Policy, and optional
    Defender for Cloud integration.

.DESCRIPTION
    Get-AzureSecurityBaselineAssessment scans Azure resources across one or
    multiple subscriptions and evaluates each against a curated set of high-value
    security baseline controls aligned to the Microsoft Cloud Security Benchmark
    (MCSB). The framework is extensible to CIS Azure 2.0, NIST 800-53, and
    ISO 27001 control sets.

    Security domains assessed (initial release — 30 controls):
        Identity & Access       — Privileged roles, guest users, MFA indicators
        Network Security        — NSG exposure, RDP/SSH, public IPs, open ports
        Data Protection         — Encryption, TLS/HTTPS enforcement, Key Vault
        Logging & Monitoring    — Diagnostic settings, activity log alerts
        Storage Security        — Public blob access, HTTPS-only, secure transfer
        Compute Security        — Disk encryption, VM agent, unmanaged disks

    Assessment pipeline:
        Scope → Data Collection → Control Evaluation → Findings → Score → CSV + HTML

    Each finding carries:
        - Status   : Pass / Fail / Not Applicable / Not Assessed
        - Severity : Critical / High / Medium / Low / Informational
        - Evidence : machine-readable detail string
        - Remediation : actionable fix guidance
        - DataSource  : Direct / Policy / DefenderForCloud

    Defender for Cloud is optional — the script functions fully without it.
    The HTML dashboard is always generated. CSV export is always generated.

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ResourceGroupName
    Optional. Restricts the scan to a single resource group within each
    targeted subscription.

.PARAMETER ResourceType
    Optional. Restricts resource collection to a specific Azure resource
    provider namespace, e.g. "Microsoft.Storage", "Microsoft.Compute".

.PARAMETER IncludeDefenderForCloud
    Switch. When specified, the script attempts to pull Defender for Cloud
    assessment data (Get-AzSecurityAssessment) to supplement direct inspection
    findings. Skipped gracefully if the Az.Security module is unavailable or
    Defender plans are not enabled on a subscription.

.PARAMETER ControlIds
    Optional string array. When supplied, only controls whose ControlId matches
    are evaluated. Useful for targeted re-assessments (e.g. after remediation).
    Example: @("NET-001","NET-002","STG-001")

.PARAMETER Severity
    Optional filter. When supplied, only findings of the specified severity level
    or higher are included in the CSV and HTML output. Accepts:
    Critical, High, Medium, Low, Informational.

.PARAMETER CsvPath
    Path where the CSV export will be written.
    Default: C:\Temp\AzureSecurityBaseline-Report.csv
    The HTML dashboard is written alongside it at the same path with .html extension.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly. Always writes HTML dashboard and CSV. Optionally displays
    results in an interactive Grid View window where a GUI is available.

.EXAMPLE
    Get-AzureSecurityBaselineAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureSecurityBaselineAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureSecurityBaselineAssessment -AllSubscriptions -IncludeDefenderForCloud

.EXAMPLE
    Get-AzureSecurityBaselineAssessment -AllSubscriptions -ResourceGroupName "rg-prod-core"

.EXAMPLE
    Get-AzureSecurityBaselineAssessment -AllSubscriptions -ControlIds @("NET-001","STG-001") -Severity High

.EXAMPLE
    Get-AzureSecurityBaselineAssessment -AllSubscriptions -CsvPath "C:\Reports\SecurityBaseline.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (13-Aug-2026) - Initial release. 30 MCSB-aligned controls across
                            six security domains. Direct inspection primary,
                            Azure Policy supplemental, Defender for Cloud optional.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.Network,
           Az.Storage, Az.Compute, Az.KeyVault, Az.Monitor, Az.PolicyInsights)
           — installed automatically with user consent if not present.
        2. Az.Security module — required only when -IncludeDefenderForCloud is
           specified. Skipped gracefully if absent.
        3. Authenticated Azure session (Connect-AzAccount).
        4. Reader role (minimum) at subscription scope.
        5. Security Reader role recommended for Defender for Cloud data.

    ─────────────────────────────────────────────────────────────────────────────
    Extensibility — Adding New Baselines (CIS / NIST / ISO):
    ─────────────────────────────────────────────────────────────────────────────
        1. Add control definitions to Get-SecurityControlLibrary with the new
           Framework value (e.g. "CIS", "NIST").
        2. Add a corresponding Invoke-<Domain>Controls helper or extend existing
           ones to cover the new checks.
        3. No changes required to the pipeline, scoring, or HTML generation layer.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Management Group-scoped resources are not assessed.
        - MFA state cannot be read via Az module; IAM-related controls rely on
          role assignment inspection only.
        - Some controls (e.g. diagnostic settings) require the resource to have
          been active for at least one billing cycle to surface data.
        - Defender for Cloud data is subscription-scoped; resource-level mapping
          is best-effort via ResourceId matching.
        - Default -CsvPath is Windows-specific. Supply an explicit -CsvPath on
          macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/security/benchmark/azure/overview
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/security-policy-concept
    https://learn.microsoft.com/en-us/powershell/module/az.security/get-azsecurityassessment
    https://learn.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data

#>


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
    Write-CenteredText "Azure Security Baseline Assessment v1.0" -Color White
    Write-CenteredText "Microsoft Cloud Security Benchmark (MCSB)" -Color DarkCyan
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
        if ([string]::IsNullOrWhiteSpace($value))
        {
            $value    = "None"
            $valColor = "DarkGray"
        }
        else
        {
            $valColor = "White"
        }

        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(26) -NoNewline -ForegroundColor Gray
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

    $percentage  = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
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
        $displayItem = $(if ($CurrentItem.Length -gt $maxLen) { $CurrentItem.Substring(0, $maxLen - 3) + "..." } else { $CurrentItem })
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-Summary
{
    param([hashtable]$Data)

    Write-Host ""
    Write-Host "  Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys)
    {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(34) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-SeverityDistribution
{
    param(
        [int]$Critical,
        [int]$High,
        [int]$Medium,
        [int]$Low,
        [int]$Informational
    )

    $total = $Critical + $High + $Medium + $Low + $Informational
    if ($total -eq 0) { return }

    Write-Host ""
    Write-Host "  Severity Distribution (Fail findings)" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $items = [ordered]@{
        "Critical"      = @{ Count = $Critical;     Color = "Red"     }
        "High"          = @{ Count = $High;          Color = "Red"     }
        "Medium"        = @{ Count = $Medium;        Color = "Yellow"  }
        "Low"           = @{ Count = $Low;           Color = "Cyan"    }
        "Informational" = @{ Count = $Informational; Color = "Gray"    }
    }

    foreach ($label in $items.Keys)
    {
        $count = $items[$label].Count
        $pct   = [math]::Round(($count / $total) * 100)
        Write-Host "  " -NoNewline
        Write-Host $label.PadRight(20) -NoNewline -ForegroundColor $items[$label].Color
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$count findings ($pct%)" -ForegroundColor White
    }
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


#------------------------------------------------------------------------ [ Control Library ]

Function Get-SecurityControlLibrary
{
    <#
    .SYNOPSIS
        Returns the curated set of MCSB-aligned security controls.
    .DESCRIPTION
        Each control definition includes: ControlId, Domain, Title, Description,
        Severity, Framework, DataSource, and Remediation. Controls are evaluated
        by domain-specific Invoke-* functions. Add new controls here and
        implement the matching evaluation logic — no other changes required.
    #>

    return @(

        # ── Identity & Access ─────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId   = "IAM-001"
            Domain      = "Identity & Access"
            Title       = "No Owner role assigned to subscription"
            Description = "Subscriptions should not have external or guest accounts with Owner role."
            Severity    = "Critical"
            Framework   = "MCSB:PA-1"
            DataSource  = "Direct"
            Remediation = "Review Owner role assignments. Remove guest/external accounts. Use PIM for privileged access."
        },
        [pscustomobject]@{
            ControlId   = "IAM-002"
            Domain      = "Identity & Access"
            Title       = "No more than 3 subscription owners"
            Description = "Limit subscription owners to reduce blast radius of compromised accounts."
            Severity    = "High"
            Framework   = "MCSB:PA-1"
            DataSource  = "Direct"
            Remediation = "Reduce Owner role assignments to 3 or fewer per subscription. Use groups instead of individuals."
        },
        [pscustomobject]@{
            ControlId   = "IAM-003"
            Domain      = "Identity & Access"
            Title       = "Guest accounts with privileged roles"
            Description = "Guest (B2B) accounts should not hold privileged Azure RBAC roles."
            Severity    = "High"
            Framework   = "MCSB:PA-7"
            DataSource  = "Direct"
            Remediation = "Remove privileged role assignments from guest accounts. Use dedicated internal identities."
        },
        [pscustomobject]@{
            ControlId   = "IAM-004"
            Domain      = "Identity & Access"
            Title       = "Service principals with Owner role"
            Description = "Service principals with Owner role pose a significant privilege escalation risk."
            Severity    = "High"
            Framework   = "MCSB:PA-1"
            DataSource  = "Direct"
            Remediation = "Replace Owner-scoped service principals with least-privilege custom roles."
        },

        # ── Network Security ──────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId   = "NET-001"
            Domain      = "Network Security"
            Title       = "RDP port (3389) not exposed to internet"
            Description = "NSG rules allowing inbound RDP from Any/Internet source are high risk."
            Severity    = "Critical"
            Framework   = "MCSB:NS-1"
            DataSource  = "Direct"
            Remediation = "Remove NSG rules allowing TCP 3389 from 0.0.0.0/0 or Internet. Use Azure Bastion or Just-in-Time VM access."
        },
        [pscustomobject]@{
            ControlId   = "NET-002"
            Domain      = "Network Security"
            Title       = "SSH port (22) not exposed to internet"
            Description = "NSG rules allowing inbound SSH from Any/Internet source are high risk."
            Severity    = "Critical"
            Framework   = "MCSB:NS-1"
            DataSource  = "Direct"
            Remediation = "Remove NSG rules allowing TCP 22 from 0.0.0.0/0 or Internet. Use Azure Bastion or Just-in-Time VM access."
        },
        [pscustomobject]@{
            ControlId   = "NET-003"
            Domain      = "Network Security"
            Title       = "NSGs attached to subnets or NICs"
            Description = "All subnets should have an NSG associated to control traffic flow."
            Severity    = "High"
            Framework   = "MCSB:NS-1"
            DataSource  = "Direct"
            Remediation = "Associate an NSG with every subnet. Review subnets without NSG protection."
        },
        [pscustomobject]@{
            ControlId   = "NET-004"
            Domain      = "Network Security"
            Title       = "No unrestricted inbound on high-risk ports"
            Description = "Ports 445 (SMB), 1433 (SQL), 3306 (MySQL), 5432 (PostgreSQL) should not be open to Any."
            Severity    = "High"
            Framework   = "MCSB:NS-1"
            DataSource  = "Direct"
            Remediation = "Restrict inbound NSG rules for database and file-sharing ports to specific source IP ranges."
        },
        [pscustomobject]@{
            ControlId   = "NET-005"
            Domain      = "Network Security"
            Title       = "Public IP addresses inventory"
            Description = "Public IPs increase attack surface. Each should be intentional and documented."
            Severity    = "Medium"
            Framework   = "MCSB:NS-2"
            DataSource  = "Direct"
            Remediation = "Review all public IP resources. Remove unattached or unnecessary public IPs. Prefer private endpoints."
        },

        # ── Data Protection ───────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId   = "DAT-001"
            Domain      = "Data Protection"
            Title       = "Key Vault soft delete enabled"
            Description = "Soft delete protects against accidental or malicious deletion of Key Vault objects."
            Severity    = "High"
            Framework   = "MCSB:DP-3"
            DataSource  = "Direct"
            Remediation = "Enable soft delete on all Key Vaults. Set retention period to 90 days minimum."
        },
        [pscustomobject]@{
            ControlId   = "DAT-002"
            Domain      = "Data Protection"
            Title       = "Key Vault purge protection enabled"
            Description = "Purge protection prevents permanent deletion during the soft delete retention period."
            Severity    = "High"
            Framework   = "MCSB:DP-3"
            DataSource  = "Direct"
            Remediation = "Enable purge protection on all Key Vaults used for production secrets and keys."
        },
        [pscustomobject]@{
            ControlId   = "DAT-003"
            Domain      = "Data Protection"
            Title       = "Key Vault private endpoint configured"
            Description = "Key Vaults should be accessible via private endpoints, not public internet."
            Severity    = "Medium"
            Framework   = "MCSB:NS-3"
            DataSource  = "Direct"
            Remediation = "Configure private endpoints for Key Vaults. Disable public network access where possible."
        },
        [pscustomobject]@{
            ControlId   = "DAT-004"
            Domain      = "Data Protection"
            Title       = "SQL Server TDE enabled"
            Description = "Transparent Data Encryption (TDE) should be enabled on all SQL databases."
            Severity    = "High"
            Framework   = "MCSB:DP-4"
            DataSource  = "Direct"
            Remediation = "Enable TDE on all Azure SQL databases. Use customer-managed keys for higher compliance requirements."
        },
        [pscustomobject]@{
            ControlId   = "DAT-005"
            Domain      = "Data Protection"
            Title       = "SQL Server auditing enabled"
            Description = "SQL Server-level auditing should be enabled to track database activity."
            Severity    = "Medium"
            Framework   = "MCSB:LT-3"
            DataSource  = "Direct"
            Remediation = "Enable SQL Server auditing. Configure audit logs to Storage Account, Log Analytics, or Event Hub."
        },

        # ── Logging & Monitoring ──────────────────────────────────────────────
        [pscustomobject]@{
            ControlId   = "LOG-001"
            Domain      = "Logging & Monitoring"
            Title       = "Subscription activity log diagnostic setting"
            Description = "Activity log data should be exported to a Log Analytics workspace or Storage Account."
            Severity    = "High"
            Framework   = "MCSB:LT-1"
            DataSource  = "Direct"
            Remediation = "Create a diagnostic setting at subscription scope to export activity logs to Log Analytics."
        },
        [pscustomobject]@{
            ControlId   = "LOG-002"
            Domain      = "Logging & Monitoring"
            Title       = "Resource diagnostic settings configured"
            Description = "Key resources (VMs, Storage, Key Vault, NSG) should have diagnostic settings enabled."
            Severity    = "Medium"
            Framework   = "MCSB:LT-1"
            DataSource  = "Direct"
            Remediation = "Enable diagnostic settings on critical resources. Route logs to a centralized Log Analytics workspace."
        },
        [pscustomobject]@{
            ControlId   = "LOG-003"
            Domain      = "Logging & Monitoring"
            Title       = "Activity log alert for critical operations"
            Description = "Alerts should exist for: Create/Update Policy Assignment, Delete NSG, Create/Update Security Solution."
            Severity    = "Medium"
            Framework   = "MCSB:LT-2"
            DataSource  = "Direct"
            Remediation = "Create activity log alerts for critical management operations. Route to an Action Group with email/SMS."
        },

        # ── Storage Security ──────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId   = "STG-001"
            Domain      = "Storage Security"
            Title       = "Storage account public blob access disabled"
            Description = "Public blob access should be disabled unless explicitly required."
            Severity    = "High"
            Framework   = "MCSB:DP-2"
            DataSource  = "Direct"
            Remediation = "Set AllowBlobPublicAccess to false on all storage accounts. Use SAS tokens or AAD auth for access."
        },
        [pscustomobject]@{
            ControlId   = "STG-002"
            Domain      = "Storage Security"
            Title       = "Storage account HTTPS-only transfer enabled"
            Description = "Storage accounts must enforce HTTPS to prevent data interception in transit."
            Severity    = "High"
            Framework   = "MCSB:DP-1"
            DataSource  = "Direct"
            Remediation = "Enable 'Secure transfer required' (HTTPS-only) on all storage accounts."
        },
        [pscustomobject]@{
            ControlId   = "STG-003"
            Domain      = "Storage Security"
            Title       = "Storage account minimum TLS version 1.2"
            Description = "Storage accounts should enforce TLS 1.2 as the minimum version."
            Severity    = "Medium"
            Framework   = "MCSB:DP-1"
            DataSource  = "Direct"
            Remediation = "Set minimumTlsVersion to TLS1_2 on all storage accounts. Retire TLS 1.0 and 1.1."
        },
        [pscustomobject]@{
            ControlId   = "STG-004"
            Domain      = "Storage Security"
            Title       = "Storage account network access restricted"
            Description = "Storage accounts should restrict network access via firewall rules or private endpoints."
            Severity    = "Medium"
            Framework   = "MCSB:NS-3"
            DataSource  = "Direct"
            Remediation = "Configure storage account firewall to allow specific IP ranges or VNets. Use private endpoints for PaaS access."
        },
        [pscustomobject]@{
            ControlId   = "STG-005"
            Domain      = "Storage Security"
            Title       = "Storage account infrastructure encryption"
            Description = "Infrastructure encryption adds a second layer of encryption for storage data."
            Severity    = "Low"
            Framework   = "MCSB:DP-4"
            DataSource  = "Direct"
            Remediation = "Enable infrastructure encryption during storage account creation. Note: cannot be enabled post-creation."
        },

        # ── Compute Security ──────────────────────────────────────────────────
        [pscustomobject]@{
            ControlId   = "CMP-001"
            Domain      = "Compute Security"
            Title       = "VM OS disk encryption enabled"
            Description = "OS and data disks should be encrypted using Azure Disk Encryption or platform-managed keys."
            Severity    = "High"
            Framework   = "MCSB:DP-4"
            DataSource  = "Direct"
            Remediation = "Enable Azure Disk Encryption on all VM OS and data disks. Use customer-managed keys in Key Vault."
        },
        [pscustomobject]@{
            ControlId   = "CMP-002"
            Domain      = "Compute Security"
            Title       = "VMs using managed disks"
            Description = "Unmanaged disks lack built-in replication, snapshots, and access controls."
            Severity    = "Medium"
            Framework   = "MCSB:DP-4"
            DataSource  = "Direct"
            Remediation = "Migrate all VMs to managed disks. Unmanaged disks are a legacy pattern with reduced security controls."
        },
        [pscustomobject]@{
            ControlId   = "CMP-003"
            Domain      = "Compute Security"
            Title       = "VM agent installed and provisioned"
            Description = "The Azure VM agent is required for extension-based security tools and monitoring."
            Severity    = "Medium"
            Framework   = "MCSB:ES-1"
            DataSource  = "Direct"
            Remediation = "Ensure VM agent is installed and reporting Ready on all virtual machines."
        },
        [pscustomobject]@{
            ControlId   = "CMP-004"
            Domain      = "Compute Security"
            Title       = "VMs not exposed via public IP directly"
            Description = "VMs with public IPs are directly reachable from the internet."
            Severity    = "High"
            Framework   = "MCSB:NS-2"
            DataSource  = "Direct"
            Remediation = "Remove public IPs from VMs. Use Azure Bastion, VPN Gateway, or a load balancer for access."
        },
        [pscustomobject]@{
            ControlId   = "CMP-005"
            Domain      = "Compute Security"
            Title       = "VM extensions security review"
            Description = "Installed VM extensions should be from trusted publishers and serve documented purposes."
            Severity    = "Low"
            Framework   = "MCSB:ES-1"
            DataSource  = "Direct"
            Remediation = "Review all installed VM extensions. Remove unrecognised or legacy extensions. Prefer Microsoft-published extensions."
        }
    )
}


#------------------------------------------------------------------------ [ Control Evaluators ]

Function Invoke-IdentityAccessControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [array]$Controls
    )

    $findings = @()

    try
    {
        $roleAssignments = @(Get-AzRoleAssignment -ErrorAction Stop)

        # IAM-001 — Guest/External accounts with Owner role
        $ctrl = $Controls | Where-Object { $_.ControlId -eq "IAM-001" }
        if ($ctrl)
        {
            $guestOwners = $roleAssignments | Where-Object {
                $_.RoleDefinitionName -eq "Owner" -and
                ($_.SignInName -like "*#EXT#*" -or $_.ObjectType -eq "Unknown")
            }

            $status   = $(if (@($guestOwners).Count -eq 0) { "Pass" } else { "Fail" })
            $evidence = $(if (@($guestOwners).Count -eq 0) {
                "No external/guest accounts found with Owner role"
            } else {
                "Guest Owner accounts: " + (($guestOwners | Select-Object -ExpandProperty SignInName) -join "; ")
            })

            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName -ResourceId "/subscriptions/$SubscriptionId" `
                -ResourceName $SubscriptionName -ResourceType "Microsoft.Authorization/roleAssignments" `
                -Status $status -Evidence $evidence
        }

        # IAM-002 — More than 3 subscription Owners
        $ctrl = $Controls | Where-Object { $_.ControlId -eq "IAM-002" }
        if ($ctrl)
        {
            $ownerCount = @($roleAssignments | Where-Object { $_.RoleDefinitionName -eq "Owner" }).Count
            $status     = $(if ($ownerCount -le 3) { "Pass" } else { "Fail" })
            $evidence   = "Subscription has $ownerCount Owner role assignment(s)"

            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName -ResourceId "/subscriptions/$SubscriptionId" `
                -ResourceName $SubscriptionName -ResourceType "Microsoft.Authorization/roleAssignments" `
                -Status $status -Evidence $evidence
        }

        # IAM-003 — Guest accounts with any privileged role
        $ctrl = $Controls | Where-Object { $_.ControlId -eq "IAM-003" }
        if ($ctrl)
        {
            $privilegedRoles    = @("Owner","Contributor","User Access Administrator")
            $guestPrivileged    = $roleAssignments | Where-Object {
                $privilegedRoles -contains $_.RoleDefinitionName -and
                $_.SignInName -like "*#EXT#*"
            }

            $status   = $(if (@($guestPrivileged).Count -eq 0) { "Pass" } else { "Fail" })
            $evidence = $(if (@($guestPrivileged).Count -eq 0) {
                "No guest accounts found with privileged roles"
            } else {
                "$($guestPrivileged.Count) guest account(s) with privileged roles: " +
                (($guestPrivileged | ForEach-Object { "$($_.SignInName)=$($_.RoleDefinitionName)" }) -join "; ")
            })

            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName -ResourceId "/subscriptions/$SubscriptionId" `
                -ResourceName $SubscriptionName -ResourceType "Microsoft.Authorization/roleAssignments" `
                -Status $status -Evidence $evidence
        }

        # IAM-004 — Service principals with Owner
        $ctrl = $Controls | Where-Object { $_.ControlId -eq "IAM-004" }
        if ($ctrl)
        {
            $spOwners = $roleAssignments | Where-Object {
                $_.RoleDefinitionName -eq "Owner" -and $_.ObjectType -eq "ServicePrincipal"
            }

            $status   = $(if (@($spOwners).Count -eq 0) { "Pass" } else { "Fail" })
            $evidence = $(if (@($spOwners).Count -eq 0) {
                "No service principals found with Owner role"
            } else {
                "$(@($spOwners).Count) service principal(s) with Owner role: " +
                (($spOwners | Select-Object -ExpandProperty DisplayName) -join "; ")
            })

            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName -ResourceId "/subscriptions/$SubscriptionId" `
                -ResourceName $SubscriptionName -ResourceType "Microsoft.Authorization/roleAssignments" `
                -Status $status -Evidence $evidence
        }
    }
    catch
    {
        Write-Warning "  IAM controls: error collecting role assignments — $_"
    }

    return $findings
}

Function Invoke-NetworkSecurityControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName,
        [array]$Controls
    )

    $findings = @()

    try
    {
        $nsgParams = @{ ErrorAction = "Stop" }
        if ($ResourceGroupName) { $nsgParams["ResourceGroupName"] = $ResourceGroupName }
        $nsgs = @(Get-AzNetworkSecurityGroup @nsgParams)

        $dangerousSources = @("*", "0.0.0.0/0", "Internet", "Any")
        $highRiskPorts    = @(445, 1433, 3306, 5432, 27017)

        foreach ($nsg in $nsgs)
        {
            $inboundRules = $nsg.SecurityRules | Where-Object {
                $_.Direction -eq "Inbound" -and $_.Access -eq "Allow"
            }

            # NET-001 — RDP exposure
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "NET-001" }
            if ($ctrl)
            {
                $rdpRules = $inboundRules | Where-Object {
                    $dangerousSources -contains $_.SourceAddressPrefix -and
                    ($_.DestinationPortRange -eq "3389" -or $_.DestinationPortRange -eq "*" -or
                     $_.DestinationPortRanges -contains "3389")
                }

                $status   = $(if (@($rdpRules).Count -eq 0) { "Pass" } else { "Fail" })
                $evidence = $(if (@($rdpRules).Count -eq 0) {
                    "No RDP (3389) internet-exposed rules found"
                } else {
                    "RDP exposed rules: " + (($rdpRules | Select-Object -ExpandProperty Name) -join "; ")
                })

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $nsg.Id `
                    -ResourceName $nsg.Name -ResourceType "Microsoft.Network/networkSecurityGroups" `
                    -ResourceGroup $nsg.ResourceGroupName -Status $status -Evidence $evidence
            }

            # NET-002 — SSH exposure
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "NET-002" }
            if ($ctrl)
            {
                $sshRules = $inboundRules | Where-Object {
                    $dangerousSources -contains $_.SourceAddressPrefix -and
                    ($_.DestinationPortRange -eq "22" -or $_.DestinationPortRange -eq "*" -or
                     $_.DestinationPortRanges -contains "22")
                }

                $status   = $(if (@($sshRules).Count -eq 0) { "Pass" } else { "Fail" })
                $evidence = $(if (@($sshRules).Count -eq 0) {
                    "No SSH (22) internet-exposed rules found"
                } else {
                    "SSH exposed rules: " + (($sshRules | Select-Object -ExpandProperty Name) -join "; ")
                })

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $nsg.Id `
                    -ResourceName $nsg.Name -ResourceType "Microsoft.Network/networkSecurityGroups" `
                    -ResourceGroup $nsg.ResourceGroupName -Status $status -Evidence $evidence
            }

            # NET-004 — High-risk port exposure
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "NET-004" }
            if ($ctrl)
            {
                $riskyRules = $inboundRules | Where-Object {
                    $src = $_.SourceAddressPrefix
                    $dangerousSources -contains $src -and (
                        $_.DestinationPortRange -eq "*" -or
                        ($highRiskPorts | Where-Object { $_.ToString() -eq $_.DestinationPortRange }) -or
                        ($_.DestinationPortRanges | Where-Object { $highRiskPorts -contains [int]$_ })
                    )
                }

                $status   = $(if (@($riskyRules).Count -eq 0) { "Pass" } else { "Fail" })
                $evidence = $(if (@($riskyRules).Count -eq 0) {
                    "No high-risk ports exposed to internet"
                } else {
                    "High-risk port rules: " + (($riskyRules | ForEach-Object { "$($_.Name):$($_.DestinationPortRange)" }) -join "; ")
                })

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $nsg.Id `
                    -ResourceName $nsg.Name -ResourceType "Microsoft.Network/networkSecurityGroups" `
                    -ResourceGroup $nsg.ResourceGroupName -Status $status -Evidence $evidence
            }
        }

        # NET-003 — Subnets without NSG
        $ctrl = $Controls | Where-Object { $_.ControlId -eq "NET-003" }
        if ($ctrl)
        {
            $vnetParams = @{ ErrorAction = "Stop" }
            if ($ResourceGroupName) { $vnetParams["ResourceGroupName"] = $ResourceGroupName }
            $vnets = @(Get-AzVirtualNetwork @vnetParams)

            foreach ($vnet in $vnets)
            {
                $unprotectedSubnets = $vnet.Subnets | Where-Object {
                    $null -eq $_.NetworkSecurityGroup -and
                    $_.Name -notin @("GatewaySubnet","AzureBastionSubnet","AzureFirewallSubnet","RouteServerSubnet")
                }

                $status   = $(if (@($unprotectedSubnets).Count -eq 0) { "Pass" } else { "Fail" })
                $evidence = $(if (@($unprotectedSubnets).Count -eq 0) {
                    "All subnets in VNet '$($vnet.Name)' have NSGs assigned"
                } else {
                    "Subnets without NSG: " + (($unprotectedSubnets | Select-Object -ExpandProperty Name) -join "; ")
                })

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $vnet.Id `
                    -ResourceName $vnet.Name -ResourceType "Microsoft.Network/virtualNetworks" `
                    -ResourceGroup $vnet.ResourceGroupName -Status $status -Evidence $evidence
            }
        }

        # NET-005 — Public IP inventory
        $ctrl = $Controls | Where-Object { $_.ControlId -eq "NET-005" }
        if ($ctrl)
        {
            $pipParams = @{ ErrorAction = "Stop" }
            if ($ResourceGroupName) { $pipParams["ResourceGroupName"] = $ResourceGroupName }
            $publicIps = @(Get-AzPublicIpAddress @pipParams)

            $unattached = $publicIps | Where-Object { $null -eq $_.IpConfiguration }
            $status     = $(if (@($unattached).Count -eq 0) { "Pass" } else { "Fail" })
            $evidence   = "Total public IPs: $($publicIps.Count). Unattached: $(@($unattached).Count). " +
                          $(if (@($unattached).Count -gt 0) {
                            "Unattached: " + (($unattached | Select-Object -ExpandProperty Name) -join "; ")
                          } else { "All public IPs are attached to resources." })

            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName -ResourceId "/subscriptions/$SubscriptionId" `
                -ResourceName "$SubscriptionName (Public IPs)" -ResourceType "Microsoft.Network/publicIPAddresses" `
                -Status $status -Evidence $evidence
        }
    }
    catch
    {
        Write-Warning "  Network controls: error — $_"
    }

    return $findings
}

Function Invoke-DataProtectionControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName,
        [array]$Controls
    )

    $findings = @()

    try
    {
        # Key Vault controls
        $kvParams = @{ ErrorAction = "Stop" }
        if ($ResourceGroupName) { $kvParams["ResourceGroupName"] = $ResourceGroupName }
        $keyVaults = @(Get-AzKeyVault @kvParams)

        foreach ($kvRef in $keyVaults)
        {
            $kv = Get-AzKeyVault -VaultName $kvRef.VaultName -ResourceGroupName $kvRef.ResourceGroupName -ErrorAction SilentlyContinue
            if (-not $kv) { continue }

            # DAT-001 — Soft delete
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "DAT-001" }
            if ($ctrl)
            {
                $enabled  = $kv.EnableSoftDelete -eq $true
                $status   = $(if ($enabled) { "Pass" } else { "Fail" })
                $evidence = "Soft delete: $($(if ($enabled) { 'Enabled' } else { 'Disabled' })). " +
                            "Retention days: $($kv.SoftDeleteRetentionInDays)"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $kv.ResourceId `
                    -ResourceName $kv.VaultName -ResourceType "Microsoft.KeyVault/vaults" `
                    -ResourceGroup $kv.ResourceGroupName -Status $status -Evidence $evidence
            }

            # DAT-002 — Purge protection
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "DAT-002" }
            if ($ctrl)
            {
                $enabled  = $kv.EnablePurgeProtection -eq $true
                $status   = $(if ($enabled) { "Pass" } else { "Fail" })
                $evidence = "Purge protection: $($(if ($enabled) { 'Enabled' } else { 'Disabled' }))"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $kv.ResourceId `
                    -ResourceName $kv.VaultName -ResourceType "Microsoft.KeyVault/vaults" `
                    -ResourceGroup $kv.ResourceGroupName -Status $status -Evidence $evidence
            }

            # DAT-003 — Private endpoint
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "DAT-003" }
            if ($ctrl)
            {
                $hasPrivateEndpoint = @($kv.PrivateEndpointConnections).Count -gt 0
                $publicDisabled     = $kv.PublicNetworkAccess -eq "Disabled"
                $status             = $(if ($hasPrivateEndpoint -or $publicDisabled) { "Pass" } else { "Fail" })
                $evidence           = "Private endpoints: $(@($kv.PrivateEndpointConnections).Count). " +
                                      "Public network access: $($(if ($publicDisabled) { 'Disabled' } else { 'Enabled' }))"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $kv.ResourceId `
                    -ResourceName $kv.VaultName -ResourceType "Microsoft.KeyVault/vaults" `
                    -ResourceGroup $kv.ResourceGroupName -Status $status -Evidence $evidence
            }
        }

        # SQL Server controls
        $sqlParams = @{ ResourceType = "Microsoft.Sql/servers"; ErrorAction = "Stop" }
        if ($ResourceGroupName) { $sqlParams["ResourceGroupName"] = $ResourceGroupName }
        $sqlServers = @(Get-AzResource @sqlParams)

        foreach ($sqlRef in $sqlServers)
        {
            # DAT-004 — TDE (check all databases)
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "DAT-004" }
            if ($ctrl)
            {
                try
                {
                    $dbs = Get-AzSqlDatabase -ResourceGroupName $sqlRef.ResourceGroupName `
                                             -ServerName $sqlRef.Name -ErrorAction Stop |
                           Where-Object { $_.DatabaseName -ne "master" }

                    $nonEncrypted = @()
                    foreach ($db in $dbs)
                    {
                        $tde = Get-AzSqlDatabaseTransparentDataEncryption `
                                   -ResourceGroupName $sqlRef.ResourceGroupName `
                                   -ServerName $sqlRef.Name -DatabaseName $db.DatabaseName `
                                   -ErrorAction SilentlyContinue
                        if ($tde.State -ne "Enabled") { $nonEncrypted += $db.DatabaseName }
                    }

                    $status   = $(if (@($nonEncrypted).Count -eq 0) { "Pass" } else { "Fail" })
                    $evidence = $(if (@($nonEncrypted).Count -eq 0) {
                        "TDE enabled on all $(@($dbs).Count) database(s)"
                    } else {
                        "TDE disabled on: " + ($nonEncrypted -join "; ")
                    })

                    $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                        -SubscriptionName $SubscriptionName -ResourceId $sqlRef.ResourceId `
                        -ResourceName $sqlRef.Name -ResourceType "Microsoft.Sql/servers" `
                        -ResourceGroup $sqlRef.ResourceGroupName -Status $status -Evidence $evidence
                }
                catch { Write-Warning "  DAT-004: could not read TDE for $($sqlRef.Name) — $_" }
            }

            # DAT-005 — SQL Auditing
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "DAT-005" }
            if ($ctrl)
            {
                try
                {
                    $audit  = Get-AzSqlServerAudit -ResourceGroupName $sqlRef.ResourceGroupName `
                                                   -ServerName $sqlRef.Name -ErrorAction Stop
                    $enabled = $audit.BlobStorageTargetState -eq "Enabled" -or
                               $audit.LogAnalyticsTargetState -eq "Enabled" -or
                               $audit.EventHubTargetState -eq "Enabled"

                    $status   = $(if ($enabled) { "Pass" } else { "Fail" })
                    $evidence = "Blob: $($audit.BlobStorageTargetState). " +
                                "Log Analytics: $($audit.LogAnalyticsTargetState). " +
                                "Event Hub: $($audit.EventHubTargetState)"

                    $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                        -SubscriptionName $SubscriptionName -ResourceId $sqlRef.ResourceId `
                        -ResourceName $sqlRef.Name -ResourceType "Microsoft.Sql/servers" `
                        -ResourceGroup $sqlRef.ResourceGroupName -Status $status -Evidence $evidence
                }
                catch { Write-Warning "  DAT-005: could not read auditing for $($sqlRef.Name) — $_" }
            }
        }
    }
    catch
    {
        Write-Warning "  Data protection controls: error — $_"
    }

    return $findings
}

Function Invoke-LoggingMonitoringControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [array]$Controls
    )

    $findings = @()

    try
    {
        # LOG-001 — Subscription activity log diagnostic setting
        $ctrl = $Controls | Where-Object { $_.ControlId -eq "LOG-001" }
        if ($ctrl)
        {
            $diagSettings = @(Get-AzDiagnosticSetting -ResourceId "/subscriptions/$SubscriptionId" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
            $hasExport    = $diagSettings | Where-Object {
                $_.WorkspaceId -or $_.StorageAccountId -or $_.EventHubAuthorizationRuleId
            }

            $status   = $(if ($hasExport) { "Pass" } else { "Fail" })
            $evidence = $(if ($hasExport) {
                "$($diagSettings.Count) diagnostic setting(s) configured for subscription activity log"
            } else {
                "No diagnostic settings found exporting subscription activity log"
            })

            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName -ResourceId "/subscriptions/$SubscriptionId" `
                -ResourceName $SubscriptionName -ResourceType "Microsoft.Insights/diagnosticSettings" `
                -Status $status -Evidence $evidence
        }

        # LOG-003 — Activity log alerts
        $ctrl = $Controls | Where-Object { $_.ControlId -eq "LOG-003" }
        if ($ctrl)
        {
            $alerts = @(Get-AzActivityLogAlert -ErrorAction SilentlyContinue)
            $status   = $(if ($alerts.Count -gt 0) { "Pass" } else { "Fail" })
            $evidence = $(if ($alerts.Count -gt 0) {
                "$($alerts.Count) activity log alert(s) configured"
            } else {
                "No activity log alerts configured on this subscription"
            })

            $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                -SubscriptionName $SubscriptionName -ResourceId "/subscriptions/$SubscriptionId" `
                -ResourceName $SubscriptionName -ResourceType "Microsoft.Insights/activityLogAlerts" `
                -Status $status -Evidence $evidence
        }
    }
    catch
    {
        Write-Warning "  Logging controls: error — $_"
    }

    return $findings
}

Function Invoke-StorageSecurityControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName,
        [array]$Controls
    )

    $findings = @()

    try
    {
        $stgParams = @{ ErrorAction = "Stop" }
        if ($ResourceGroupName) { $stgParams["ResourceGroupName"] = $ResourceGroupName }
        $storageAccounts = @(Get-AzStorageAccount @stgParams)

        foreach ($sa in $storageAccounts)
        {
            # STG-001 — Public blob access
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "STG-001" }
            if ($ctrl)
            {
                $publicAccess = $sa.AllowBlobPublicAccess
                $status       = $(if ($publicAccess -eq $false) { "Pass" } else { "Fail" })
                $evidence     = "AllowBlobPublicAccess: $($(if ($publicAccess -eq $false) { 'Disabled' } else { 'Enabled or not set' }))"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $sa.Id `
                    -ResourceName $sa.StorageAccountName -ResourceType "Microsoft.Storage/storageAccounts" `
                    -ResourceGroup $sa.ResourceGroupName -Status $status -Evidence $evidence
            }

            # STG-002 — HTTPS only
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "STG-002" }
            if ($ctrl)
            {
                $httpsOnly = $sa.EnableHttpsTrafficOnly
                $status    = $(if ($httpsOnly) { "Pass" } else { "Fail" })
                $evidence  = "EnableHttpsTrafficOnly: $($(if ($httpsOnly) { 'Enabled' } else { 'Disabled' }))"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $sa.Id `
                    -ResourceName $sa.StorageAccountName -ResourceType "Microsoft.Storage/storageAccounts" `
                    -ResourceGroup $sa.ResourceGroupName -Status $status -Evidence $evidence
            }

            # STG-003 — Minimum TLS 1.2
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "STG-003" }
            if ($ctrl)
            {
                $tlsVersion = $sa.MinimumTlsVersion
                $status     = $(if ($tlsVersion -eq "TLS1_2") { "Pass" } else { "Fail" })
                $evidence   = "MinimumTlsVersion: $tlsVersion"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $sa.Id `
                    -ResourceName $sa.StorageAccountName -ResourceType "Microsoft.Storage/storageAccounts" `
                    -ResourceGroup $sa.ResourceGroupName -Status $status -Evidence $evidence
            }

            # STG-004 — Network access restriction
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "STG-004" }
            if ($ctrl)
            {
                $defaultAction = $sa.NetworkRuleSet.DefaultAction
                $restricted    = $defaultAction -eq "Deny"
                $status        = $(if ($restricted) { "Pass" } else { "Fail" })
                $evidence      = "Network DefaultAction: $defaultAction. " +
                                 "IP rules: $($sa.NetworkRuleSet.IpRules.Count). " +
                                 "VNet rules: $($sa.NetworkRuleSet.VirtualNetworkRules.Count)"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $sa.Id `
                    -ResourceName $sa.StorageAccountName -ResourceType "Microsoft.Storage/storageAccounts" `
                    -ResourceGroup $sa.ResourceGroupName -Status $status -Evidence $evidence
            }

            # STG-005 — Infrastructure encryption
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "STG-005" }
            if ($ctrl)
            {
                $infraEncrypt = $sa.Encryption.RequireInfrastructureEncryption
                $status       = $(if ($infraEncrypt -eq $true) { "Pass" } else { "Fail" })
                $evidence     = "RequireInfrastructureEncryption: $($(if ($infraEncrypt -eq $true) { 'Enabled' } else { 'Disabled or not set' }))"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $sa.Id `
                    -ResourceName $sa.StorageAccountName -ResourceType "Microsoft.Storage/storageAccounts" `
                    -ResourceGroup $sa.ResourceGroupName -Status $status -Evidence $evidence
            }
        }
    }
    catch
    {
        Write-Warning "  Storage controls: error — $_"
    }

    return $findings
}

Function Invoke-ComputeSecurityControls
{
    param(
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceGroupName,
        [array]$Controls
    )

    $findings = @()

    try
    {
        $vmParams = @{ ErrorAction = "Stop" }
        if ($ResourceGroupName) { $vmParams["ResourceGroupName"] = $ResourceGroupName }
        $vms = @(Get-AzVM @vmParams -Status)

        foreach ($vm in $vms)
        {
            # CMP-001 — OS disk encryption
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "CMP-001" }
            if ($ctrl)
            {
                $diskEncStatus = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName `
                                     -VMName $vm.Name -ErrorAction SilentlyContinue
                $osDiskEnc     = $diskEncStatus.OsVolumeEncrypted -eq "Encrypted"
                $status        = $(if ($osDiskEnc) { "Pass" } else { "Fail" })
                $evidence      = "OS disk encryption: $($diskEncStatus.OsVolumeEncrypted). " +
                                 "Data disk encryption: $($diskEncStatus.DataVolumesEncrypted)"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $vm.Id `
                    -ResourceName $vm.Name -ResourceType "Microsoft.Compute/virtualMachines" `
                    -ResourceGroup $vm.ResourceGroupName -Status $status -Evidence $evidence
            }

            # CMP-002 — Managed disks
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "CMP-002" }
            if ($ctrl)
            {
                $osDiskManaged   = $null -ne $vm.StorageProfile.OsDisk.ManagedDisk
                $dataDisksManaged = @($vm.StorageProfile.DataDisks | Where-Object { $null -eq $_.ManagedDisk }).Count -eq 0
                $allManaged       = $osDiskManaged -and $dataDisksManaged
                $status           = $(if ($allManaged) { "Pass" } else { "Fail" })
                $evidence         = "OS disk managed: $osDiskManaged. All data disks managed: $dataDisksManaged"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $vm.Id `
                    -ResourceName $vm.Name -ResourceType "Microsoft.Compute/virtualMachines" `
                    -ResourceGroup $vm.ResourceGroupName -Status $status -Evidence $evidence
            }

            # CMP-003 — VM agent
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "CMP-003" }
            if ($ctrl)
            {
                $agentStatus = ($vm.Extensions | Where-Object { $_.Type -like "*VMAgent*" }) -or
                               ($vm.VMAgent.Statuses | Where-Object { $_.Code -like "*ProvisioningState/succeeded*" })
                $vmStatus    = $vm.Statuses | Where-Object { $_.Code -like "PowerState/*" }
                $powerState  = $(if ($vmStatus) { $vmStatus.DisplayStatus } else { "Unknown" })

                if ($powerState -notlike "*running*")
                {
                    $status   = "Not Assessed"
                    $evidence = "VM is not running (state: $powerState). Agent status cannot be confirmed."
                }
                else
                {
                    $agentReady = $vm.VMAgent.Statuses | Where-Object { $_.Code -eq "ProvisioningState/succeeded" }
                    $status     = $(if ($agentReady) { "Pass" } else { "Fail" })
                    $evidence   = "VM Agent status: $($(if ($agentReady) { 'Ready' } else { 'Not ready or not installed' })). Power state: $powerState"
                }

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $vm.Id `
                    -ResourceName $vm.Name -ResourceType "Microsoft.Compute/virtualMachines" `
                    -ResourceGroup $vm.ResourceGroupName -Status $status -Evidence $evidence
            }

            # CMP-004 — VM not exposed via public IP
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "CMP-004" }
            if ($ctrl)
            {
                $hasPublicIp = $false
                foreach ($nic in $vm.NetworkProfile.NetworkInterfaces)
                {
                    $nicId      = $nic.Id
                    $nicRgName = (($nicId -split "/resourceGroups/")[1] -split "/")[0]
                    $nicName    = $nicId.Split("/")[-1]
                    $nicDetails = Get-AzNetworkInterface -Name $nicName -ResourceGroupName $nicRgName -ErrorAction SilentlyContinue
                    if ($nicDetails)
                    {
                        foreach ($ipConfig in $nicDetails.IpConfigurations)
                        {
                            if ($ipConfig.PublicIpAddress) { $hasPublicIp = $true; break }
                        }
                    }
                    if ($hasPublicIp) { break }
                }

                $status   = $(if (-not $hasPublicIp) { "Pass" } else { "Fail" })
                $evidence = "VM directly reachable via public IP: $($(if ($hasPublicIp) { 'Yes' } else { 'No' }))"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $vm.Id `
                    -ResourceName $vm.Name -ResourceType "Microsoft.Compute/virtualMachines" `
                    -ResourceGroup $vm.ResourceGroupName -Status $status -Evidence $evidence
            }

            # CMP-005 — VM extensions review (informational)
            $ctrl = $Controls | Where-Object { $_.ControlId -eq "CMP-005" }
            if ($ctrl)
            {
                $extensions  = $vm.Extensions
                $extNames    = $(if (@($extensions).Count -gt 0) { ($extensions | Select-Object -ExpandProperty Name) -join "; " } else { "None" })
                $status      = "Pass"   # Informational — flags for review, no binary fail
                $evidence    = "$(@($extensions).Count) extension(s) installed: $extNames"

                $findings += New-Finding -Control $ctrl -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceId $vm.Id `
                    -ResourceName $vm.Name -ResourceType "Microsoft.Compute/virtualMachines" `
                    -ResourceGroup $vm.ResourceGroupName -Status $status -Evidence $evidence
            }
        }
    }
    catch
    {
        Write-Warning "  Compute controls: error — $_"
    }

    return $findings
}


#------------------------------------------------------------------------ [ Finding Builder ]

Function New-Finding
{
    param(
        [pscustomobject]$Control,
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceId,
        [string]$ResourceName,
        [string]$ResourceType,
        [string]$ResourceGroup = "",
        [string]$Status,
        [string]$Evidence
    )

    return [pscustomobject]@{
        ControlId        = $Control.ControlId
        Domain           = $Control.Domain
        ControlTitle     = $Control.Title
        Severity         = $Control.Severity
        Framework        = $Control.Framework
        SubscriptionId   = $SubscriptionId
        SubscriptionName = $SubscriptionName
        ResourceGroup    = $ResourceGroup
        ResourceName     = $ResourceName
        ResourceType     = $ResourceType
        ResourceId       = $ResourceId
        Status           = $Status
        Evidence         = $Evidence
        Remediation      = $Control.Remediation
        DataSource       = $Control.DataSource
    }
}


#------------------------------------------------------------------------ [ Scoring ]

Function Get-SecurityScore
{
    param([array]$Findings)

    $assessed = $Findings | Where-Object { $_.Status -notin @("Not Applicable","Not Assessed") }
    $passed   = $assessed | Where-Object { $_.Status -eq "Pass" }

    if ($assessed.Count -eq 0) { return 0 }
    return [math]::Round(($passed.Count / $assessed.Count) * 100)
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml
{
    param([string]$s)
    return $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

Function EscJ
{
    param([string]$s)
    return $s -replace '\\','\\\\' -replace '"','\"' -replace "`r`n",'\n' -replace "`n",'\n' -replace "`t",'\t'
}

Function Generate-SecurityBaselineHtml
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$SubscriptionResults,
        [array]$AllFindings,
        [int]$SecurityScore,
        [hashtable]$SeverityCounts,
        [hashtable]$DomainCounts,
        [hashtable]$StatusCounts,
        [string]$GeneratedOn
    )

    # ── Score color ───────────────────────────────────────────────────────────
    $scoreColor = $(if ($SecurityScore -ge 80) { "#3fb950" }
                   elseif ($SecurityScore -ge 50) { "#d29922" }
                   else { "#f85149" })

    # ── SVG ring ──────────────────────────────────────────────────────────────
    $ringCirc = 339
    $ringDash = [math]::Round($SecurityScore / 100 * $ringCirc)
    $ringGap  = $ringCirc - $ringDash

    # ── Severity donut (Fail findings only) ───────────────────────────────────
    $donutTotal = $SeverityCounts.Critical + $SeverityCounts.High + $SeverityCounts.Medium + $SeverityCounts.Low
    $donutCirc  = 377
    $seg1Dash   = $(if ($donutTotal -gt 0) { [math]::Round($SeverityCounts.Critical / $donutTotal * $donutCirc) } else { 0 })
    $seg2Dash   = $(if ($donutTotal -gt 0) { [math]::Round($SeverityCounts.High     / $donutTotal * $donutCirc) } else { 0 })
    $seg3Dash   = $(if ($donutTotal -gt 0) { [math]::Round($SeverityCounts.Medium   / $donutTotal * $donutCirc) } else { 0 })
    $seg4Dash   = $(if ($donutTotal -gt 0) { [math]::Round($SeverityCounts.Low      / $donutTotal * $donutCirc) } else { 0 })
    $seg2Offset = $seg1Dash
    $seg3Offset = $seg1Dash + $seg2Dash
    $seg4Offset = $seg1Dash + $seg2Dash + $seg3Dash

    # ── Domain bar rows ───────────────────────────────────────────────────────
    $domainRows = ""
    $totalFindings = $AllFindings.Count
    foreach ($domain in ($DomainCounts.GetEnumerator() | Sort-Object { $_.Value.Fail } -Descending))
    {
        $pass    = $domain.Value.Pass
        $fail    = $domain.Value.Fail
        $total   = $pass + $fail
        $pct     = $(if ($total -gt 0) { [math]::Round(($pass / $total) * 100) } else { 0 })
        $barClr  = $(if ($pct -ge 80) { "var(--green)" } elseif ($pct -ge 50) { "var(--amber)" } else { "var(--red)" })
        $badge   = $(if ($pct -ge 80) { "badge-green" } elseif ($pct -ge 50) { "badge-amber" } else { "badge-red" })

        $domainRows += @"
            <div class="bar-row">
              <span class="bar-label">$($domain.Key)</span>
              <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barClr"></div></div>
              <span class="bar-pct"><span class="badge $badge">$pct%</span></span>
            </div>
"@
    }

    # ── Subscription rows ─────────────────────────────────────────────────────
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

    # ── Control detail table rows ─────────────────────────────────────────────
    $tableRows = ""
    $rowIndex  = 0
    foreach ($r in $AllFindings)
    {
        $statusCls  = switch ($r.Status) {
            "Pass"         { "badge-green" }
            "Fail"         { "badge-red"   }
            "Not Assessed" { "badge-blue"  }
            default        { "badge-amber" }
        }
        $severityCls = switch ($r.Severity) {
            "Critical"      { "sev-critical" }
            "High"          { "sev-high"     }
            "Medium"        { "sev-medium"   }
            "Low"           { "sev-low"      }
            default         { "sev-info"     }
        }

        $tableRows += @"
          <tr onclick="showDetail($rowIndex)">
            <td><span class="ctrl-id">$(EscHtml $r.ControlId)</span></td>
            <td>$(EscHtml $r.Domain)</td>
            <td title="$(EscHtml $r.ControlTitle)">$(EscHtml $(if ($r.ControlTitle.Length -gt 45) { $r.ControlTitle.Substring(0,42)+"..." } else { $r.ControlTitle }))</td>
            <td><span class="badge $statusCls">$($r.Status)</span></td>
            <td><span class="sev-badge $severityCls">$($r.Severity)</span></td>
            <td title="$(EscHtml $r.ResourceName)">$(EscHtml $(if ($r.ResourceName.Length -gt 28) { $r.ResourceName.Substring(0,25)+"..." } else { $r.ResourceName }))</td>
            <td>$(EscHtml $r.SubscriptionName)</td>
          </tr>
"@
        $rowIndex++
    }

    # ── Top risks rows (Fail + Critical/High) ─────────────────────────────────
    $topRisks    = $AllFindings | Where-Object { $_.Status -eq "Fail" -and $_.Severity -in @("Critical","High") } |
                   Select-Object -First 10
    $topRiskRows = ""
    foreach ($r in $topRisks)
    {
        $severityCls = switch ($r.Severity) { "Critical" { "sev-critical" }; "High" { "sev-high" }; default { "sev-medium" } }
        $topRiskRows += @"
            <div class="risk-row">
              <span class="sev-badge $severityCls">$($r.Severity)</span>
              <span class="risk-ctrl">$(EscHtml $r.ControlId)</span>
              <span class="risk-title">$(EscHtml $r.ControlTitle)</span>
              <span class="risk-resource muted">$(EscHtml $r.ResourceName)</span>
            </div>
"@
    }

    # ── JSON data ─────────────────────────────────────────────────────────────
    $jsonRows = "["
    foreach ($r in $AllFindings)
    {
        $jsonRows += "{" +
            """id"":""$(EscJ $r.ControlId)""," +
            """domain"":""$(EscJ $r.Domain)""," +
            """title"":""$(EscJ $r.ControlTitle)""," +
            """status"":""$(EscJ $r.Status)""," +
            """severity"":""$(EscJ $r.Severity)""," +
            """framework"":""$(EscJ $r.Framework)""," +
            """sub"":""$(EscJ $r.SubscriptionName)""," +
            """rg"":""$(EscJ $r.ResourceGroup)""," +
            """resource"":""$(EscJ $r.ResourceName)""," +
            """type"":""$(EscJ $r.ResourceType)""," +
            """evidence"":""$(EscJ $r.Evidence)""," +
            """remediation"":""$(EscJ $r.Remediation)""," +
            """datasource"":""$(EscJ $r.DataSource)""," +
            """resourceid"":""$(EscJ $r.ResourceId)""" +
        "},"
    }
    $jsonRows = $jsonRows.TrimEnd(",") + "]"

    # ── Full HTML ─────────────────────────────────────────────────────────────
    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Security Baseline Assessment</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;
  --border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;
  --green:#3fb950;--amber:#d29922;--red:#f85149;--purple:#a371f7;
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

/* ── Sidebar ── */
#sidebar{
  width:240px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;
  transition:transform .25s;
}
.logo-block{padding:22px 18px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:38px;height:38px;border-radius:8px;
  background:linear-gradient(135deg,var(--red),var(--accent3));
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
.theme-toggle{
  display:flex;align-items:center;justify-content:space-between;
  font-size:12px;color:var(--muted);margin-bottom:10px;
}
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

/* ── Main ── */
#main{margin-left:240px;padding:28px;width:calc(100% - 240px);min-height:100vh;}
.page{display:none;animation:fadeIn .2s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px);}to{opacity:1;transform:none;}}
.page-header{margin-bottom:22px;}
.page-title{font-size:22px;font-weight:700;color:var(--text);}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}

/* ── Stat cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin-bottom:22px;}
.stat-card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;cursor:default;
}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-num{font-size:30px;font-weight:700;font-family:var(--mono);color:var(--text);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}

/* ── Panels ── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:16px;display:flex;align-items:center;gap:8px;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}

/* ── Health ring ── */
.health-card{display:flex;align-items:center;gap:24px;}
.health-ring-wrap{position:relative;width:130px;height:130px;flex-shrink:0;}
.health-ring-wrap svg{width:100%;height:100%;}
.health-center-text{
  position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center;
}
.health-score{font-size:28px;font-weight:700;font-family:var(--mono);}
.health-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;}
.health-details{flex:1;}
.health-details h3{font-size:15px;font-weight:700;margin-bottom:10px;}
.health-mini-bar{height:6px;background:var(--surface3);border-radius:3px;overflow:hidden;margin-top:8px;}
.health-mini-fill{height:100%;border-radius:3px;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width 1s ease;}

/* ── Bar lists ── */
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:180px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:72px;text-align:right;flex-shrink:0;}

/* ── Donut ── */
.donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.legend-list{display:flex;flex-direction:column;gap:8px;}
.legend-item{display:flex;align-items:center;gap:10px;font-size:13px;cursor:pointer;}
.legend-item:hover{color:var(--text);}
.legend-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;}

/* ── Top risks ── */
.risk-row{
  display:flex;align-items:center;gap:10px;padding:9px 0;
  border-bottom:1px solid var(--border);flex-wrap:wrap;
}
.risk-row:last-child{border-bottom:none;}
.risk-ctrl{font-family:var(--mono);font-size:11px;color:var(--accent);width:60px;flex-shrink:0;}
.risk-title{font-size:13px;color:var(--text);flex:1;}
.risk-resource{font-size:11px;font-family:var(--mono);}
.muted{color:var(--muted);}

/* ── Table ── */
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
td{padding:9px 12px;border-bottom:1px solid var(--border);color:var(--text);vertical-align:middle;}
tr:hover td{background:var(--surface2);cursor:pointer;}
.ctrl-id{font-family:var(--mono);font-size:11px;color:var(--accent);}
.pagination{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:12px;color:var(--muted);flex-wrap:wrap;}
.pg-btn{
  padding:4px 10px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;
}
.pg-btn:hover{border-color:var(--accent);color:var(--accent);}
.pg-btn.active{background:var(--accent);color:#fff;border-color:var(--accent);}
.pg-btn:disabled{opacity:.4;cursor:not-allowed;}

/* ── Badges & severity ── */
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.sev-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:var(--mono);text-transform:uppercase;}
.sev-critical{background:rgba(248,81,73,.25);color:#ff6b6b;border:1px solid rgba(248,81,73,.4);}
.sev-high{background:rgba(210,153,34,.2);color:#e5a000;border:1px solid rgba(210,153,34,.35);}
.sev-medium{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.sev-low{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.25);}
.sev-info{background:var(--surface3);color:var(--muted2);border:1px solid var(--border);}

/* ── Category cards ── */
.cat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;}
.cat-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:16px;}
.cat-card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;}
.cat-card-title{font-size:13px;font-weight:700;color:var(--text);}
.cat-stats{display:flex;gap:12px;font-size:11px;margin-top:8px;}
.cat-stat{display:flex;align-items:center;gap:4px;}

/* ── Info cards ── */
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:4px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);color:var(--text);word-break:break-all;}
.info-value.muted{color:var(--muted);font-style:italic;}

/* ── Subscription rows ── */
.sub-list{display:flex;flex-direction:column;gap:0;}
.sub-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}
.sub-icon.c-amber{color:var(--amber);}
.sub-icon.c-red{color:var(--red);}
.sub-name{flex:1;font-size:13px;color:var(--text);font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}

/* ── Detail drawer ── */
#drawerBackdrop{
  display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;
}
#detailDrawer{
  position:fixed;right:0;top:0;bottom:0;width:460px;max-width:95vw;
  background:var(--surface);border-left:1px solid var(--border);
  z-index:201;display:flex;flex-direction:column;
  transform:translateX(100%);transition:transform .25s ease;overflow:hidden;
}
#detailDrawer.open{transform:translateX(0);}
.drawer-header{
  padding:18px 20px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;flex-shrink:0;
}
.drawer-title{font-size:14px;font-weight:700;color:var(--text);}
.drawer-close{
  background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;
  line-height:1;padding:2px 6px;border-radius:var(--radius-sm);
}
.drawer-close:hover{color:var(--text);background:var(--surface2);}
.drawer-body{padding:20px;overflow-y:auto;flex:1;}
.drawer-nav{display:flex;gap:8px;align-items:center;margin-bottom:16px;}
.drawer-nav-btn{
  padding:5px 12px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;
}
.drawer-nav-btn:hover{border-color:var(--accent);color:var(--accent);}
.drawer-nav-info{font-size:12px;color:var(--muted);flex:1;text-align:center;}
.drawer-field{margin-bottom:14px;}
.drawer-field-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.drawer-field-value{font-size:13px;color:var(--text);word-break:break-all;line-height:1.5;}
.drawer-section{font-size:12px;font-weight:700;color:var(--muted2);
  text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.evidence-box{
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:10px 12px;font-family:var(--mono);font-size:11px;color:var(--muted2);
  line-height:1.6;word-break:break-all;
}
.remediation-box{
  background:rgba(63,185,80,.05);border:1px solid rgba(63,185,80,.2);border-radius:var(--radius-sm);
  padding:10px 12px;font-size:12px;color:var(--text);line-height:1.6;
}

/* ── Toast ── */
#toast{
  position:fixed;bottom:24px;right:24px;padding:12px 18px;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);
  font-size:13px;color:var(--text);box-shadow:var(--shadow);
  opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:300;
}
#toast.show{opacity:1;transform:translateY(0);}

/* ── Responsive ── */
#menuToggle{display:none;}
@media(max-width:768px){
  #menuToggle{
    display:flex;align-items:center;justify-content:center;
    position:fixed;top:12px;left:12px;z-index:300;width:36px;height:36px;
    background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);
    cursor:pointer;font-size:18px;
  }
  #sidebar{transform:translateX(-100%);}
  #sidebar.open{transform:translateX(0);}
  #main{margin-left:0;width:100%;padding:16px;padding-top:56px;}
  .chart-grid{grid-template-columns:1fr;}
  .cat-grid{grid-template-columns:1fr;}
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

<!-- ── Sidebar ── -->
<nav id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🛡️</div>
    <div class="logo-title">Security Baseline</div>
    <div class="logo-sub">Azure MCSB Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('controls',this)"><span class="nav-icon">🔍</span> Control Detail</button>
    <button class="nav-btn" onclick="showPage('categories',this)"><span class="nav-icon">🗂️</span> Security Categories</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">📋</span> Subscription Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()" title="Toggle theme"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Azure Security Baseline Scanner
    </div>
  </div>
</nav>

<!-- ── Main ── -->
<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Security Baseline Overview</div>
      <div class="page-sub">MCSB assessment across __TOTAL_FINDINGS__ findings in __SUB_COUNT__ subscription(s) · __CONTROLS_ASSESSED__ controls evaluated</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_FINDINGS__</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__PASS_COUNT__</div>
        <div class="stat-label">Pass</div>
        <div class="stat-sub">Controls passing</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__FAIL_COUNT__</div>
        <div class="stat-label">Fail</div>
        <div class="stat-sub">Controls failing</div>
      </div>
      <div class="stat-card c-red" style="border-top-color:#ff6b6b">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">Immediate action</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High</div>
        <div class="stat-sub">Urgent action</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__SUB_COUNT__</div>
        <div class="stat-label">Subscriptions</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Security Score</div>
        <div class="health-card">
          <div class="health-ring-wrap">
            <svg viewBox="0 0 140 140" xmlns="http://www.w3.org/2000/svg">
              <circle cx="70" cy="70" r="54" fill="none" stroke="var(--surface3)" stroke-width="12"/>
              <circle cx="70" cy="70" r="54" fill="none" stroke="__SCORE_COLOR__" stroke-width="12"
                stroke-linecap="round" stroke-dasharray="__RING_DASH__ __RING_GAP__"
                stroke-dashoffset="85" transform="rotate(-90 70 70)"/>
            </svg>
            <div class="health-center-text">
              <span class="health-score" style="color:__SCORE_COLOR__">__SCORE__%</span>
              <span class="health-label">Score</span>
            </div>
          </div>
          <div class="health-details">
            <h3>Overall Security Score</h3>
            <p style="font-size:13px;color:var(--muted);">Percentage of assessed controls passing. Not Applicable and Not Assessed controls are excluded from scoring.</p>
            <div class="health-mini-bar"><div class="health-mini-fill" style="width:__SCORE__%"></div></div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-title">🍩 Severity Distribution (Fail findings)</div>
        <div class="donut-wrap">
          <svg width="130" height="130" viewBox="0 0 140 140">
            <circle cx="70" cy="70" r="60" fill="none" stroke="var(--surface3)" stroke-width="20"/>
            <circle cx="70" cy="70" r="60" fill="none" stroke="#ff6b6b" stroke-width="20"
              stroke-dasharray="__SEG1_DASH__ __DONUT_CIRC__" stroke-dashoffset="0"
              transform="rotate(-90 70 70)" opacity="0.9"/>
            <circle cx="70" cy="70" r="60" fill="none" stroke="var(--amber)" stroke-width="20"
              stroke-dasharray="__SEG2_DASH__ __DONUT_CIRC__" stroke-dashoffset="-__SEG2_OFFSET__"
              transform="rotate(-90 70 70)" opacity="0.9"/>
            <circle cx="70" cy="70" r="60" fill="none" stroke="var(--accent)" stroke-width="20"
              stroke-dasharray="__SEG3_DASH__ __DONUT_CIRC__" stroke-dashoffset="-__SEG3_OFFSET__"
              transform="rotate(-90 70 70)" opacity="0.9"/>
            <circle cx="70" cy="70" r="60" fill="none" stroke="var(--green)" stroke-width="20"
              stroke-dasharray="__SEG4_DASH__ __DONUT_CIRC__" stroke-dashoffset="-__SEG4_OFFSET__"
              transform="rotate(-90 70 70)" opacity="0.9"/>
          </svg>
          <div class="legend-list">
            <div class="legend-item"><div class="legend-dot" style="background:#ff6b6b"></div><span>Critical — __CRITICAL_COUNT__</span></div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--amber)"></div><span>High — __HIGH_COUNT__</span></div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--accent)"></div><span>Medium — __MEDIUM_COUNT__</span></div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--green)"></div><span>Low — __LOW_COUNT__</span></div>
          </div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">🔥 Top Risks — Critical &amp; High Fail Findings</div>
      __TOP_RISK_ROWS__
    </div>

    <div class="panel">
      <div class="panel-title">📊 Pass Rate by Security Domain</div>
      __DOMAIN_ROWS__
    </div>
  </div>

  <!-- Control Detail -->
  <div id="page-controls" class="page">
    <div class="page-header">
      <div class="page-title">Control Detail</div>
      <div class="page-sub">Click any row to inspect evidence and remediation guidance</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="tblSearch" placeholder="Search control, resource, subscription…" oninput="filterTable()"/>
        </div>
        <select class="filter-select" id="filterStatus" onchange="filterTable()">
          <option value="">All Statuses</option>
          <option value="Pass">Pass</option>
          <option value="Fail">Fail</option>
          <option value="Not Applicable">Not Applicable</option>
          <option value="Not Assessed">Not Assessed</option>
        </select>
        <select class="filter-select" id="filterSeverity" onchange="filterTable()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Informational">Informational</option>
        </select>
        <select class="filter-select" id="filterDomain" onchange="filterTable()">
          <option value="">All Domains</option>
          <option value="Identity &amp; Access">Identity &amp; Access</option>
          <option value="Network Security">Network Security</option>
          <option value="Data Protection">Data Protection</option>
          <option value="Logging &amp; Monitoring">Logging &amp; Monitoring</option>
          <option value="Storage Security">Storage Security</option>
          <option value="Compute Security">Compute Security</option>
        </select>
        <select class="filter-select" id="pgSize" onchange="changePageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="resTable">
          <thead>
            <tr>
              <th onclick="sortTable(0)">Control ID</th>
              <th onclick="sortTable(1)">Domain</th>
              <th onclick="sortTable(2)">Control Title</th>
              <th onclick="sortTable(3)">Status</th>
              <th onclick="sortTable(4)">Severity</th>
              <th onclick="sortTable(5)">Resource</th>
              <th onclick="sortTable(6)">Subscription</th>
            </tr>
          </thead>
          <tbody id="tblBody"></tbody>
        </table>
      </div>
      <div class="pagination" id="pagination"></div>
    </div>
  </div>

  <!-- Security Categories -->
  <div id="page-categories" class="page">
    <div class="page-header">
      <div class="page-title">Security Categories</div>
      <div class="page-sub">Pass/Fail breakdown by security domain</div>
    </div>
    <div class="cat-grid" id="catGrid"></div>
  </div>

  <!-- Subscription Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Results</div>
      <div class="page-sub">Per-subscription assessment summary</div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Subscriptions Assessed</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- Session Info -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Scan Parameters</div>
      <div class="page-sub">Authentication context and parameters used for this assessment</div>
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
        <div class="info-card"><div class="info-label">Resource Group Filter</div><div class="info-value __RG_MUTED__">__RG_FILTER__</div></div>
        <div class="info-card"><div class="info-label">Resource Type Filter</div><div class="info-value __RT_MUTED__">__RT_FILTER__</div></div>
        <div class="info-card"><div class="info-label">Defender for Cloud</div><div class="info-value">__DEFENDER_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Controls Evaluated</div><div class="info-value">__CONTROLS_ASSESSED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Subscriptions Scanned</div><div class="info-value">__SUB_COUNT__</div></div>
        <div class="info-card"><div class="info-label">Framework</div><div class="info-value">MCSB v1.0</div></div>
      </div>
    </div>
  </div>

</main>

<!-- ── Detail drawer ── -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Control Detail</span>
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
const DATA = __DATA_JSON__;
let filtered = [...DATA];
let currentPage = 1;
let pageSize = 25;
let sortCol = -1, sortAsc = true;
let currentDetailIdx = 0;

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// ── Navigation ──
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
  if(id==='categories') renderCategoryCards();
}

// ── Theme ──
function toggleTheme(){
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
}

// ── Toast ──
function showToast(msg){
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2500);
}

// ── Table ──
function filterTable(){
  const q  = document.getElementById('tblSearch').value.toLowerCase();
  const st = document.getElementById('filterStatus').value;
  const sv = document.getElementById('filterSeverity').value;
  const dm = document.getElementById('filterDomain').value;
  filtered = DATA.filter(r=>{
    const matchQ  = !q  || JSON.stringify(r).toLowerCase().includes(q);
    const matchSt = !st || r.status === st;
    const matchSv = !sv || r.severity === sv;
    const matchDm = !dm || r.domain === dm;
    return matchQ && matchSt && matchSv && matchDm;
  });
  currentPage = 1;
  renderTable();
}

function changePageSize(){
  pageSize = parseInt(document.getElementById('pgSize').value);
  currentPage = 1;
  renderTable();
}

function sortTable(col){
  if(sortCol===col){sortAsc=!sortAsc;}else{sortCol=col;sortAsc=true;}
  const keys=['id','domain','title','status','severity','resource','sub'];
  filtered.sort((a,b)=>{
    const av=a[keys[col]]??'', bv=b[keys[col]]??'';
    return sortAsc ? String(av).localeCompare(String(bv),undefined,{numeric:true})
                   : String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderTable();
}

function renderTable(){
  const tbody = document.getElementById('tblBody');
  const start = (currentPage-1)*pageSize;
  const slice = filtered.slice(start, start+pageSize);
  tbody.innerHTML = slice.map((r,i)=>{
    const globalIdx = DATA.indexOf(r);
    const sc  = r.status==='Pass'?'badge-green':r.status==='Fail'?'badge-red':r.status==='Not Assessed'?'badge-blue':'badge-amber';
    const svc = r.severity==='Critical'?'sev-critical':r.severity==='High'?'sev-high':r.severity==='Medium'?'sev-medium':r.severity==='Low'?'sev-low':'sev-info';
    const nm  = r.resource.length>28?r.resource.substring(0,25)+'...':r.resource;
    const tl  = r.title.length>45?r.title.substring(0,42)+'...':r.title;
    return `<tr onclick="showDetail(${globalIdx})">
      <td><span class="ctrl-id">${escH(r.id)}</span></td>
      <td>${escH(r.domain)}</td>
      <td title="${escH(r.title)}">${escH(tl)}</td>
      <td><span class="badge ${sc}">${escH(r.status)}</span></td>
      <td><span class="sev-badge ${svc}">${escH(r.severity)}</span></td>
      <td title="${escH(r.resource)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
    </tr>`;
  }).join('');
  renderPagination();
}

function renderPagination(){
  const total = Math.ceil(filtered.length/pageSize);
  const el    = document.getElementById('pagination');
  let html    = `<span>${filtered.length} findings</span>`;
  html += `<button class="pg-btn" onclick="changePage(${currentPage-1})" ${currentPage<=1?'disabled':''}>‹ Prev</button>`;
  const start = Math.max(1,currentPage-2), end = Math.min(total,start+4);
  for(let p=start;p<=end;p++){
    html += `<button class="pg-btn ${p===currentPage?'active':''}" onclick="changePage(${p})">${p}</button>`;
  }
  html += `<button class="pg-btn" onclick="changePage(${currentPage+1})" ${currentPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML = html;
}

function changePage(p){
  const total = Math.ceil(filtered.length/pageSize);
  if(p<1||p>total) return;
  currentPage = p;
  renderTable();
}

// ── Category cards ──
function renderCategoryCards(){
  const domains = {};
  DATA.forEach(r=>{
    if(!domains[r.domain]) domains[r.domain]={pass:0,fail:0,na:0,items:[]};
    if(r.status==='Pass') domains[r.domain].pass++;
    else if(r.status==='Fail') domains[r.domain].fail++;
    else domains[r.domain].na++;
    domains[r.domain].items.push(r);
  });

  const icons = {
    'Identity & Access':'🔑','Network Security':'🌐',
    'Data Protection':'🔒','Logging & Monitoring':'📋',
    'Storage Security':'🗄️','Compute Security':'💻'
  };

  const el = document.getElementById('catGrid');
  el.innerHTML = Object.entries(domains).sort((a,b)=>b[1].fail-a[1].fail).map(([name,d])=>{
    const total  = d.pass + d.fail;
    const pct    = total>0?Math.round(d.pass/total*100):0;
    const clr    = pct>=80?'var(--green)':pct>=50?'var(--amber)':'var(--red)';
    const badge  = pct>=80?'badge-green':pct>=50?'badge-amber':'badge-red';
    const icon   = icons[name]||'🛡️';
    const crits  = d.items.filter(r=>r.status==='Fail'&&r.severity==='Critical').length;
    const highs  = d.items.filter(r=>r.status==='Fail'&&r.severity==='High').length;
    return `<div class="cat-card">
      <div class="cat-card-header">
        <span class="cat-card-title">${icon} ${escH(name)}</span>
        <span class="badge ${badge}">${pct}%</span>
      </div>
      <div style="height:6px;background:var(--surface3);border-radius:3px;overflow:hidden;margin-bottom:10px;">
        <div style="height:100%;width:${pct}%;background:${clr};border-radius:3px;transition:width .8s ease;"></div>
      </div>
      <div class="cat-stats">
        <span class="cat-stat" style="color:var(--green)">✓ ${d.pass} Pass</span>
        <span class="cat-stat" style="color:var(--red)">✗ ${d.fail} Fail</span>
        ${crits>0?`<span class="sev-badge sev-critical">${crits} Critical</span>`:''}
        ${highs>0?`<span class="sev-badge sev-high">${highs} High</span>`:''}
      </div>
    </div>`;
  }).join('');
}

// ── Detail drawer ──
function showDetail(idx){
  currentDetailIdx = idx;
  const r = DATA[idx];
  if(!r) return;
  document.getElementById('drawerTitle').textContent = r.id + ' — ' + r.title;
  document.getElementById('drawerNavInfo').textContent = `${idx+1} of ${DATA.length}`;

  const sc  = r.status==='Pass'?'badge-green':r.status==='Fail'?'badge-red':r.status==='Not Assessed'?'badge-blue':'badge-amber';
  const svc = r.severity==='Critical'?'sev-critical':r.severity==='High'?'sev-high':r.severity==='Medium'?'sev-medium':r.severity==='Low'?'sev-low':'sev-info';

  document.getElementById('drawerContent').innerHTML = `
    <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;">
      <span class="badge ${sc}">${escH(r.status)}</span>
      <span class="sev-badge ${svc}">${escH(r.severity)}</span>
      <span style="font-size:11px;font-family:var(--mono);color:var(--muted);padding:3px 8px;background:var(--surface2);border-radius:4px;">${escH(r.framework)}</span>
    </div>
    <div class="drawer-field"><div class="drawer-field-label">Domain</div>
      <div class="drawer-field-value">${escH(r.domain)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Name</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.resource)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Type</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.type)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Data Source</div>
      <div class="drawer-field-value">${escH(r.datasource)}</div></div>
    <div class="drawer-section">Evidence</div>
    <div class="evidence-box">${escH(r.evidence)}</div>
    <div class="drawer-section">Remediation</div>
    <div class="remediation-box">${escH(r.remediation)}</div>
    <div class="drawer-section">Resource ID</div>
    <div class="evidence-box" style="font-size:10px;">${escH(r.resourceid)}</div>
  `;

  document.getElementById('drawerBackdrop').style.display = 'block';
  document.getElementById('detailDrawer').classList.add('open');
}

function closeDrawer(){
  document.getElementById('drawerBackdrop').style.display = 'none';
  document.getElementById('detailDrawer').classList.remove('open');
}

function navDetail(dir){
  const next = currentDetailIdx + dir;
  if(next >= 0 && next < DATA.length) showDetail(next);
}

// ── Bar animation ──
function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width = el.dataset.pct + '%';
    });
  });
}

// ── Keyboard shortcuts ──
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
  if(e.key==='/'){
    const s = document.getElementById('tblSearch');
    if(s){ e.preventDefault(); s.focus(); }
  }
});

// ── Init ──
filterTable();
animateBars();
</script>
</body>
</html>
'@

    # ── Token substitution ────────────────────────────────────────────────────
    $totalFindings     = @($AllFindings).Count
    $passCount         = @($AllFindings | Where-Object { $_.Status -eq "Pass" }).Count
    $failCount         = @($AllFindings | Where-Object { $_.Status -eq "Fail" }).Count
    $controlsAssessed  = @($AllFindings | Select-Object -ExpandProperty ControlId -Unique).Count

    $html = $html `
        -replace '__GENERATED_ON__',      $GeneratedOn `
        -replace '__TOTAL_FINDINGS__',    $totalFindings `
        -replace '__PASS_COUNT__',        $passCount `
        -replace '__FAIL_COUNT__',        $failCount `
        -replace '__CRITICAL_COUNT__',    $SeverityCounts.Critical `
        -replace '__HIGH_COUNT__',        $SeverityCounts.High `
        -replace '__MEDIUM_COUNT__',      $SeverityCounts.Medium `
        -replace '__LOW_COUNT__',         $SeverityCounts.Low `
        -replace '__SUB_COUNT__',         ($SubscriptionResults.Count) `
        -replace '__CONTROLS_ASSESSED__', $controlsAssessed `
        -replace '__SCORE__',             $SecurityScore `
        -replace '__SCORE_COLOR__',       $scoreColor `
        -replace '__RING_DASH__',         $ringDash `
        -replace '__RING_GAP__',          $ringGap `
        -replace '__SEG1_DASH__',         $seg1Dash `
        -replace '__SEG2_DASH__',         $seg2Dash `
        -replace '__SEG3_DASH__',         $seg3Dash `
        -replace '__SEG4_DASH__',         $seg4Dash `
        -replace '__DONUT_CIRC__',        $donutCirc `
        -replace '__SEG2_OFFSET__',       $seg2Offset `
        -replace '__SEG3_OFFSET__',       $seg3Offset `
        -replace '__SEG4_OFFSET__',       $seg4Offset `
        -replace '__TOP_RISK_ROWS__',     $topRiskRows `
        -replace '__DOMAIN_ROWS__',       $domainRows `
        -replace '__SUB_ROWS__',          $subRows `
        -replace '__TENANT__',            $SessionInfo.Tenant `
        -replace '__ACCOUNT__',           $SessionInfo.Account `
        -replace '__ENVIRONMENT__',       $SessionInfo.Environment `
        -replace '__SCOPE__',             $ScanParameters.Scope `
        -replace '__RG_FILTER__',         $(if ($ScanParameters.ResourceGroupName) { $ScanParameters.ResourceGroupName } else { "None" }) `
        -replace '__RG_MUTED__',          $(if ($ScanParameters.ResourceGroupName) { "" } else { "muted" }) `
        -replace '__RT_FILTER__',         $(if ($ScanParameters.ResourceType) { $ScanParameters.ResourceType } else { "None" }) `
        -replace '__RT_MUTED__',          $(if ($ScanParameters.ResourceType) { "" } else { "muted" }) `
        -replace '__DEFENDER_ENABLED__',  $ScanParameters.DefenderEnabled `
        -replace '__EXEC_TIME__',         $ScanParameters.ExecTime `
        -replace '__DATA_JSON__',         $jsonRows

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureSecurityBaselineAssessment
{
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [string]$ResourceGroupName,

        [string]$ResourceType,

        [switch]$IncludeDefenderForCloud,

        [string[]]$ControlIds,

        [ValidateSet("Critical","High","Medium","Low","Informational")]
        [string]$Severity,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureSecurityBaseline-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts","Az.Resources","Az.Network","Az.Storage",
                         "Az.Compute","Az.KeyVault","Az.Monitor","Az.PolicyInsights",
                         "Az.Sql","Az.Authorization")

    $missingModules = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_ ) }

    if ($missingModules)
    {
        Write-Host "  ⚠ Missing Az modules: $($missingModules -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "  Install missing modules now? (Y/N)"

        if ($install -match '^[Yy]$')
        {
            try
            {
                Write-Host ""
                Write-Host "  Installing Az module, please wait..." -ForegroundColor Cyan
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
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
            Write-Host "  Installation declined. Some controls may not be evaluated." -ForegroundColor Yellow
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
        $scopeText     = "Specific Subscriptions ($($SubscriptionIds.Count))"
    }

    $subCount = $subscriptions.Count

    # ── Load control library ──────────────────────────────────────────────────
    $allControls = Get-SecurityControlLibrary

    if ($ControlIds)
    {
        $allControls = $allControls | Where-Object { $ControlIds -contains $_.ControlId }
    }

    # ── Display session info ──────────────────────────────────────────────────
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Assessment Parameters" -Data @{
        "Scope"                 = "$scopeText ($subCount found)"
        "Resource Group"        = $(if ($ResourceGroupName) { $ResourceGroupName } else { "" })
        "Resource Type"         = $(if ($ResourceType)      { $ResourceType }      else { "" })
        "Controls to Evaluate"  = $allControls.Count
        "Severity Filter"       = $(if ($Severity) { $Severity } else { "All" })
        "Defender for Cloud"    = $(if ($IncludeDefenderForCloud.IsPresent) { "Enabled" } else { "Disabled" })
        "Control IDs Filter"    = $(if ($ControlIds) { $ControlIds -join ", " } else { "All" })
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings         = @()
    $subscriptionResults = @()
    $successCount        = 0
    $errorCount          = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = [math]::Max(
        ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
        35
    )

    $subIndex = 1

    foreach ($sub in $subscriptions)
    {
        try
        {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue `
                          -InformationAction SilentlyContinue | Out-Null

            $subFindings = @()

            # Domain evaluators
            $subFindings += Invoke-IdentityAccessControls `
                -SubscriptionId   $sub.Id `
                -SubscriptionName $sub.Name `
                -Controls         ($allControls | Where-Object { $_.Domain -eq "Identity & Access" })

            $subFindings += Invoke-NetworkSecurityControls `
                -SubscriptionId   $sub.Id `
                -SubscriptionName $sub.Name `
                -ResourceGroupName $ResourceGroupName `
                -Controls         ($allControls | Where-Object { $_.Domain -eq "Network Security" })

            $subFindings += Invoke-DataProtectionControls `
                -SubscriptionId   $sub.Id `
                -SubscriptionName $sub.Name `
                -ResourceGroupName $ResourceGroupName `
                -Controls         ($allControls | Where-Object { $_.Domain -eq "Data Protection" })

            $subFindings += Invoke-LoggingMonitoringControls `
                -SubscriptionId   $sub.Id `
                -SubscriptionName $sub.Name `
                -Controls         ($allControls | Where-Object { $_.Domain -eq "Logging & Monitoring" })

            $subFindings += Invoke-StorageSecurityControls `
                -SubscriptionId   $sub.Id `
                -SubscriptionName $sub.Name `
                -ResourceGroupName $ResourceGroupName `
                -Controls         ($allControls | Where-Object { $_.Domain -eq "Storage Security" })

            $subFindings += Invoke-ComputeSecurityControls `
                -SubscriptionId   $sub.Id `
                -SubscriptionName $sub.Name `
                -ResourceGroupName $ResourceGroupName `
                -Controls         ($allControls | Where-Object { $_.Domain -eq "Compute Security" })

            # Optional Defender for Cloud enrichment
            if ($IncludeDefenderForCloud.IsPresent)
            {
                try
                {
                    if (Get-Module -ListAvailable -Name Az.Security)
                    {
                        $dfcAssessments = @(Get-AzSecurityAssessment -ErrorAction Stop)
                        # Map DfC findings to existing controls by ControlId where possible
                        # This is an enrichment layer — extend as needed per control mapping
                        Write-Verbose "  DfC: $($dfcAssessments.Count) assessments retrieved for $($sub.Name)"
                    }
                    else
                    {
                        Write-Warning "  Az.Security module not available — Defender for Cloud enrichment skipped"
                    }
                }
                catch
                {
                    Write-Warning "  Defender for Cloud data unavailable for $($sub.Name): $_"
                }
            }

            $allFindings += $subFindings

            $subPass    = @($subFindings | Where-Object { $_.Status -eq "Pass" }).Count
            $subFail    = @($subFindings | Where-Object { $_.Status -eq "Fail" }).Count
            $subCrit    = @($subFindings | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "Critical" }).Count

            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($subFindings.Count) findings  |  Pass: $subPass  Fail: $subFail  Critical: $subCrit" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "$($subFindings.Count) findings | ✓$subPass ✗$subFail 🔴$subCrit Critical"
                Status  = $(if ($subCrit -gt 0) { "Warning" } else { "Success" })
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

    # ── Apply severity filter ─────────────────────────────────────────────────
    if ($Severity)
    {
        $severityOrder = @("Critical","High","Medium","Low","Informational")
        $cutoff        = $severityOrder.IndexOf($Severity)
        $allFindings   = $allFindings | Where-Object {
            $severityOrder.IndexOf($_.Severity) -le $cutoff
        }
    }

    # ── Score and distribution ────────────────────────────────────────────────
    $endTime       = Get-Date
    $duration      = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)
    $securityScore = Get-SecurityScore -Findings $allFindings

    $failFindings = $allFindings | Where-Object { $_.Status -eq "Fail" }
    $severityCounts = @{
        Critical      = @($failFindings | Where-Object { $_.Severity -eq "Critical" }).Count
        High          = @($failFindings | Where-Object { $_.Severity -eq "High" }).Count
        Medium        = @($failFindings | Where-Object { $_.Severity -eq "Medium" }).Count
        Low           = @($failFindings | Where-Object { $_.Severity -eq "Low" }).Count
        Informational = @($failFindings | Where-Object { $_.Severity -eq "Informational" }).Count
    }

    $domainCounts = @{}
    foreach ($f in $allFindings)
    {
        if (-not $domainCounts.ContainsKey($f.Domain)) { $domainCounts[$f.Domain] = @{ Pass = 0; Fail = 0 } }
        if ($f.Status -eq "Pass") { $domainCounts[$f.Domain].Pass++ }
        elseif ($f.Status -eq "Fail") { $domainCounts[$f.Domain].Fail++ }
    }

    # ── Console summary ───────────────────────────────────────────────────────
    Write-Summary -Data ([ordered]@{
        "Total Subscriptions Scanned" = $subCount
        "Successful"                  = $successCount
        "Errors"                      = $errorCount
        "Total Findings"              = @($allFindings).Count
        "Pass"                        = @($allFindings | Where-Object { $_.Status -eq "Pass" }).Count
        "Fail"                        = @($allFindings | Where-Object { $_.Status -eq "Fail" }).Count
        "Not Assessed"                = @($allFindings | Where-Object { $_.Status -eq "Not Assessed" }).Count
        "Security Score"              = "$securityScore%"
        "Execution Time"              = $duration
    })

    Write-SeverityDistribution `
        -Critical      $severityCounts.Critical `
        -High          $severityCounts.High `
        -Medium        $severityCounts.Medium `
        -Low           $severityCounts.Low `
        -Informational $severityCounts.Informational

    # ── CSV export (always) ───────────────────────────────────────────────────
    $csvExported  = $false
    $htmlExported = $false
    $htmlPath     = ""

    if ($allFindings.Count -gt 0)
    {
        try
        {
            $csvRows = $allFindings | Select-Object `
                ControlId, Domain, ControlTitle, Severity, Framework, `
                SubscriptionName, SubscriptionId, ResourceGroup, `
                ResourceName, ResourceType, ResourceId, `
                Status, Evidence, Remediation, DataSource

            $csvDir = Split-Path -Parent $CsvPath
            if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
            $csvRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
            $csvExported = $true
        }
        catch
        {
            Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
        }

        # HTML dashboard (always)
        try
        {
            $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')

            $sessionInfo = @{
                Tenant      = $ctx.Tenant.Id
                Account     = $ctx.Account.Id
                Environment = $ctx.Environment.Name
            }

            $scanParams = @{
                Scope             = "$scopeText ($subCount found)"
                ResourceGroupName = $ResourceGroupName
                ResourceType      = $ResourceType
                DefenderEnabled   = $(if ($IncludeDefenderForCloud.IsPresent) { "Enabled" } else { "Disabled" })
                ExecTime          = $duration
            }

            $htmlContent = Generate-SecurityBaselineHtml `
                -SessionInfo          $sessionInfo `
                -ScanParameters       $scanParams `
                -SubscriptionResults  $subscriptionResults `
                -AllFindings          $allFindings `
                -SecurityScore        $securityScore `
                -SeverityCounts       $severityCounts `
                -DomainCounts         $domainCounts `
                -StatusCounts         @{} `
                -GeneratedOn          (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch
        {
            Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        # Grid view (optional — graceful skip in headless sessions)
        $gridViewOpened = $false
        try
        {
            $allFindings |
                Select-Object ControlId, Domain, ControlTitle, Severity, Status, ResourceName, SubscriptionName |
                Out-GridView -Title "Azure Security Baseline Assessment"
            $gridViewOpened = $true
        }
        catch
        {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else
    {
        Write-Host ""
        Write-Host "  ⚠ No findings generated. Check subscription access and filters." -ForegroundColor Yellow
    }

    Write-OutputFiles `
        -CsvPath        $(if ($csvExported)  { $CsvPath  } else { $null }) `
        -HtmlPath       $(if ($htmlExported) { $htmlPath } else { $null }) `
        -GridViewOpened $gridViewOpened
}
