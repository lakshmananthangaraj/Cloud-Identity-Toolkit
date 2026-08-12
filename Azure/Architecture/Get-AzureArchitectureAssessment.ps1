<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 12 August 2026
Modified-On     : 12 August 2026

.SYNOPSIS
    Assesses Azure subscriptions and resources against enterprise architecture principles
    covering Identity, Networking, Security, Governance, Resilience, and Monitoring —
    aligned to CAF, WAF, NIST CSF, and CIS Benchmarks.

.DESCRIPTION
    Get-AzureArchitectureAssessment performs a structured architecture quality assessment
    across one or more Azure subscriptions. Each pillar maps directly to Azure Well-Architected
    Framework (WAF) design principles and is cross-referenced to CAF, NIST CSF, and CIS controls.

    Assessment pillars covered:
        - Identity       : Managed identities, MFA enforcement signal, legacy auth block,
                           privileged identity hygiene, service principal key expiry.
        - Networking     : Private endpoints, exposed public IPs, service endpoints,
                           DNS configuration, hub connectivity.
        - Security       : Key Vault hygiene, storage security, encryption at rest,
                           TLS configuration, just-in-time VM access signal.
        - Governance     : Resource locks, Blueprints/ARM/Bicep signals, subscription
                           resource limits, naming convention conformance.
        - Resilience     : Availability zones, backup vault, soft-delete, zone-redundant
                           storage, redundant public IP SKUs.
        - Monitoring     : Metric alerts, action groups, Log Analytics workspace health,
                           Azure Monitor coverage.

    Each finding is severity-rated (Critical / High / Medium / Low), mapped to a
    framework reference (WAF / CAF / NIST / CIS), and carries evidence and a
    remediation recommendation.

    Output options:
        - Always-on HTML report : Full dashboard with dark/light toggle, stat cards,
                                  filterable findings table, per-pillar charts.
        - Optional CSV export   : Flat finding rows for SIEM/tracking ingestion.
        - Interactive Grid View : For ad-hoc review (GUI sessions only).

.PARAMETER AllSubscriptions
    Switch. Assesses every subscription visible to the authenticated account.
    Default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to assess.
    Ignored if -AllSubscriptions is also specified.

.PARAMETER IncludePillars
    String array limiting the assessment to specific WAF pillars. Valid values:
    Identity, Networking, Security, Governance, Resilience, Monitoring.
    Default: all pillars assessed.

.PARAMETER ExportToCsv
    Switch. Exports all findings to the path specified by -CsvPath.

.PARAMETER CsvPath
    File path for the CSV export and the HTML report (HTML shares the same base
    name with a .html extension).
    Default: C:\Temp\AzureArchitectureAssessment-Report.csv

.INPUTS
    None. Parameters only.

.OUTPUTS
    Always writes an HTML dashboard report. Optionally writes a CSV file.
    Displays results in an interactive Grid View window where a GUI is available.

.EXAMPLE
    Get-AzureArchitectureAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureArchitectureAssessment -SubscriptionIds @("sub-id-1","sub-id-2") -ExportToCsv

.EXAMPLE
    Get-AzureArchitectureAssessment -AllSubscriptions -IncludePillars @("Security","Identity","Resilience")

.EXAMPLE
    Get-AzureArchitectureAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\ArchAssessment.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (12-Aug-2026) - Initial release. Full architecture assessment across 6 WAF
                        pillars; CAF, WAF, NIST CSF, CIS alignment;
                        HTML dashboard + CSV output.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts, Az.Resources, Az.Network, Az.Security, Az.KeyVault,
       Az.Storage, Az.Monitor, Az.RecoveryServices, Az.Compute modules
       (installed automatically on consent if missing).
    2. Authenticated Azure session with Reader role at subscription level minimum.
    3. Microsoft.Authorization/roleAssignments/read,
       Microsoft.Compute/virtualMachines/read,
       Microsoft.KeyVault/vaults/read,
       Microsoft.Storage/storageAccounts/read at subscription scope.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - MFA enforcement checks require Microsoft Graph API; this version assesses
      Conditional Access policy presence via Az module signals only.
    - JIT VM access detection checks Defender for Cloud JIT policy; full JIT
      status requires Microsoft.Security/jitNetworkAccessPolicies/read.
    - Interactive Grid View requires a GUI-capable session; skipped gracefully
      in headless/CI environments.
    - Default -CsvPath is Windows-specific. Supply an explicit path on macOS/Linux.

.LINK
    https://learn.microsoft.com/en-us/azure/well-architected/

.LINK
    https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/

.LINK
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CenteredText
{
    param(
        [string]$Text,
        [int]$Width = 80,
        [string]$Color = "White"
    )
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-ArchBanner
{
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Architecture Assessment v1.0" -Color White
    Write-CenteredText "WAF | CAF | NIST CSF | CIS Benchmarks" -Color DarkCyan
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-ArchSection
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
            $value = "None"
            $valueColor = "DarkGray"
        }
        else { $valueColor = "White" }
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valueColor
    }
}

Function Write-ArchProgressBar
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
        $max = 35
        $display = if ($CurrentItem.Length -gt $max) { $CurrentItem.Substring(0, $max - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $display -NoNewline -ForegroundColor Cyan
    }
}

Function Write-PillarHeader
{
    param([string]$Pillar)
    Write-Host ""
    Write-Host "  ► Assessing Pillar: $Pillar" -ForegroundColor Yellow
}

Function Write-ArchSummary
{
    param([hashtable]$Data)
    Write-Host ""
    Write-Host "  Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($key in $Data.Keys)
    {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(32) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-ArchOutputFiles
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
        Write-Host ("CSV Export").PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }
    if ($HtmlPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Dashboard").PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }
    if ($GridViewOpened)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("Grid View").PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": Opened in separate window" -ForegroundColor White
    }
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function New-ArchFinding
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$Pillar,
        [string]$CheckId,
        [string]$CheckName,
        [string]$Status,
        [string]$Severity,
        [string]$Framework,
        [string]$FrameworkRef,
        [string]$Evidence,
        [string]$Recommendation,
        [string]$ResourceId = ""
    )
    return [pscustomobject]@{
        SubscriptionName = $SubscriptionName
        SubscriptionId   = $SubscriptionId
        Pillar           = $Pillar
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

Function Get-SafeProperty
{
    param(
        [object]$Object,
        [string]$PropertyName,
        [string]$Default = ""
    )
    if ($null -eq $Object) { return $Default }
    if ($Object.PSObject.Properties.Name -contains $PropertyName)
    {
        $val = $Object.$PropertyName
        if ($null -eq $val) { return $Default }
        return $val
    }
    return $Default
}

Function Ensure-ArchModules
{
    $required = @(
        "Az.Accounts",
        "Az.Resources",
        "Az.Network",
        "Az.Security",
        "Az.KeyVault",
        "Az.Storage",
        "Az.Monitor",
        "Az.RecoveryServices",
        "Az.Compute"
    )

    $missing = @()
    foreach ($mod in $required)
    {
        if (-not (Get-Module -ListAvailable -Name $mod)) { $missing += $mod }
    }

    if ($missing.Count -gt 0)
    {
        Write-Host ""
        Write-Host "  ⚠ Missing modules: $($missing -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "  Install missing modules now? (Y/N)"
        if ($install -eq 'Y' -or $install -eq 'y')
        {
            foreach ($mod in $missing)
            {
                try
                {
                    Write-Host "  Installing $mod..." -ForegroundColor Cyan
                    Install-Module -Name $mod -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                    Write-Host "  ✓ $mod installed" -ForegroundColor Green
                }
                catch
                {
                    Write-Host "  ✗ Failed to install $mod : $_" -ForegroundColor Red
                    return $false
                }
            }
        }
        else
        {
            Write-Host "  Installation declined. Cannot proceed without required modules." -ForegroundColor Yellow
            return $false
        }
    }

    foreach ($mod in $required)
    {
        Import-Module $mod -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    return $true
}


#------------------------------------------------------------------------ [ Pillar Assessment Functions ]

Function Test-IdentityPillar
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-PillarHeader "Identity"

    # Check 1 — IDEN001: Managed identities in use (not service principal keys for Azure resources)
    try
    {
        $vms = @(Get-AzVM -ErrorAction SilentlyContinue)
        $vmsWithMI = $vms | Where-Object {
            $identity = Get-SafeProperty -Object $_ -PropertyName "Identity"
            $identity -and (Get-SafeProperty -Object $identity -PropertyName "Type") -match "SystemAssigned|UserAssigned"
        }

        if ($vms.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN001" -CheckName "Managed identities in use on VMs" `
                -Status "NotApplicable" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-SE-02" `
                -Evidence "No virtual machines found in this subscription" `
                -Recommendation "When deploying VMs, assign a System-assigned or User-assigned Managed Identity instead of storing credentials."
        }
        elseif ($vmsWithMI.Count -eq $vms.Count)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN001" -CheckName "Managed identities in use on VMs" `
                -Status "Pass" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-SE-02" `
                -Evidence "All $($vms.Count) VM(s) have managed identities assigned" `
                -Recommendation "Extend managed identity usage to other compute services (App Service, Function Apps, AKS)."
        }
        else
        {
            $withoutMI = $vms | Where-Object {
                $identity = Get-SafeProperty -Object $_ -PropertyName "Identity"
                -not $identity -or (Get-SafeProperty -Object $identity -PropertyName "Type") -notmatch "SystemAssigned|UserAssigned"
            }
            $names = ($withoutMI | Select-Object -First 5 | Select-Object -ExpandProperty Name) -join "; "
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN001" -CheckName "Managed identities in use on VMs" `
                -Status "Fail" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-SE-02" `
                -Evidence "$($withoutMI.Count) of $($vms.Count) VM(s) have no managed identity: $names" `
                -Recommendation "Assign System-assigned Managed Identity to VMs. Migrate from service principal credentials to managed identities for all Azure resource authentication."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Identity" -CheckId "IDEN001" -CheckName "Managed identities in use on VMs" `
            -Status "Warning" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-SE-02" `
            -Evidence "Could not retrieve VM data: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Compute/virtualMachines/read permission."
    }

    # Check 2 — IDEN002: Service principal key expiry hygiene
    try
    {
        $roleAssignments  = @(Get-AzRoleAssignment -ErrorAction SilentlyContinue)
        $spAssignments    = $roleAssignments | Where-Object { $_.ObjectType -eq "ServicePrincipal" }
        $spCount          = $spAssignments.Count

        if ($spCount -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN002" -CheckName "Service principal usage reviewed" `
                -Status "Pass" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-IDEN-002" `
                -Evidence "No service principal role assignments found at subscription scope" `
                -Recommendation "Continue preferring managed identities over service principals where possible."
        }
        else
        {
            $status = if ($spCount -le 10) { "Warning" } else { "Fail" }
            $severity = if ($spCount -gt 20) { "High" } else { "Medium" }
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN002" -CheckName "Service principal usage reviewed" `
                -Status $status -Severity $severity -Framework "CAF" -FrameworkRef "CAF-IDEN-002" `
                -Evidence "$spCount service principal(s) with role assignments at subscription scope" `
                -Recommendation "Audit all service principals. Replace with managed identities where possible. For remaining SPs, enforce certificate-based auth over client secrets and rotate secrets on schedule."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Identity" -CheckId "IDEN002" -CheckName "Service principal usage reviewed" `
            -Status "Warning" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-IDEN-002" `
            -Evidence "Could not retrieve role assignments: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Authorization/roleAssignments/read permission."
    }

    # Check 3 — IDEN003: No wildcard / Owner role to 'Everyone' or large groups at sub scope
    try
    {
        $allAssignments = @(Get-AzRoleAssignment -ErrorAction SilentlyContinue)
        $ownerAll = $allAssignments | Where-Object {
            $_.RoleDefinitionName -eq "Owner" -and
            $_.Scope -match "^/subscriptions/[^/]+$" -and
            ($_.DisplayName -match "All|Everyone|Global" -or $_.ObjectType -eq "Group")
        }

        if ($ownerAll.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN003" -CheckName "No broad Owner assignments to groups at subscription scope" `
                -Status "Pass" -Severity "Critical" -Framework "NIST" -FrameworkRef "NIST-AC-6" `
                -Evidence "No broad group-based Owner assignments detected at subscription scope" `
                -Recommendation "Periodically audit Owner assignments. Use PIM groups with approval workflows."
        }
        else
        {
            $names = ($ownerAll | Select-Object -ExpandProperty DisplayName) -join "; "
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN003" -CheckName "No broad Owner assignments to groups at subscription scope" `
                -Status "Fail" -Severity "Critical" -Framework "NIST" -FrameworkRef "NIST-AC-6" `
                -Evidence "Broad Owner group assignment(s) found: $names" `
                -Recommendation "Remove group-based Owner assignments at subscription scope. Use PIM with time-bound, approval-gated Owner activation. Assign narrower roles (Contributor + specific RPs) for day-to-day operations."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Identity" -CheckId "IDEN003" -CheckName "No broad Owner assignments to groups at subscription scope" `
            -Status "Warning" -Severity "Critical" -Framework "NIST" -FrameworkRef "NIST-AC-6" `
            -Evidence "Could not assess Owner assignments: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Authorization/roleAssignments/read permission."
    }

    # Check 4 — IDEN004: Conditional Access policies exist (signal via Security Contacts or MDfC)
    try
    {
        $securityContacts = @(Get-AzSecurityContact -ErrorAction SilentlyContinue)
        if ($securityContacts.Count -gt 0)
        {
            $email = ($securityContacts | Select-Object -ExpandProperty Email -First 1)
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN004" -CheckName "Security contact configured in Defender for Cloud" `
                -Status "Pass" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-1.18" `
                -Evidence "Security contact configured: $email" `
                -Recommendation "Ensure security contact email is actively monitored and receives Defender for Cloud alerts."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN004" -CheckName "Security contact configured in Defender for Cloud" `
                -Status "Fail" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-1.18" `
                -Evidence "No security contact configured in Defender for Cloud" `
                -Recommendation "Configure a security contact email and phone in Defender for Cloud. Enable 'Send email notification for high severity alerts' and 'Send email also to subscription owners'."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Identity" -CheckId "IDEN004" -CheckName "Security contact configured in Defender for Cloud" `
            -Status "Warning" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-1.18" `
            -Evidence "Could not retrieve security contacts: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Security/securityContacts/read permission."
    }

    # Check 5 — IDEN005: No deprecated classic administrators (co-administrators)
    try
    {
        $classicAdmins = @(Get-AzRoleAssignment -IncludeClassicAdministrators -ErrorAction SilentlyContinue |
            Where-Object { $_.RoleDefinitionName -match "CoAdministrator|ServiceAdministrator|AccountAdministrator" })
        if ($classicAdmins.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN005" -CheckName "No classic administrators present" `
                -Status "Pass" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-1.12" `
                -Evidence "No classic Co-Administrator, Service Administrator, or Account Administrator roles found" `
                -Recommendation "Continue using Azure RBAC exclusively. Classic administrator roles are deprecated."
        }
        else
        {
            $names = ($classicAdmins | Select-Object -ExpandProperty SignInName) -join "; "
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Identity" -CheckId "IDEN005" -CheckName "No classic administrators present" `
                -Status "Fail" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-1.12" `
                -Evidence "Classic administrator(s) found: $names" `
                -Recommendation "Remove all classic Co-Administrator, Service Administrator, and Account Administrator assignments. Migrate to Azure RBAC Owner/Contributor roles with PIM."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Identity" -CheckId "IDEN005" -CheckName "No classic administrators present" `
            -Status "Warning" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-1.12" `
            -Evidence "Could not check classic administrators: $($_.Exception.Message)" `
            -Recommendation "Run Get-AzRoleAssignment -IncludeClassicAdministrators manually to verify."
    }

    return $findings
}

Function Test-NetworkingPillar
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-PillarHeader "Networking"

    # Check 1 — NET001: Private endpoints in use (signal — any private endpoints found)
    try
    {
        $privateEndpoints = @(Get-AzPrivateEndpoint -ErrorAction SilentlyContinue)
        if ($privateEndpoints.Count -gt 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Networking" -CheckId "NET001" -CheckName "Private endpoints in use" `
                -Status "Pass" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-SE-06" `
                -Evidence "$($privateEndpoints.Count) private endpoint(s) found" `
                -Recommendation "Ensure all PaaS services (Storage, Key Vault, SQL, Event Hub) have private endpoints and public network access disabled."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Networking" -CheckId "NET001" -CheckName "Private endpoints in use" `
                -Status "Fail" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-SE-06" `
                -Evidence "No private endpoints found — PaaS services may be exposed over public internet" `
                -Recommendation "Deploy private endpoints for all PaaS services. Disable public network access on Key Vault, Storage, SQL, and other PaaS resources. Use Private DNS Zones for name resolution."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Networking" -CheckId "NET001" -CheckName "Private endpoints in use" `
            -Status "Warning" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-SE-06" `
            -Evidence "Could not retrieve private endpoints: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Network/privateEndpoints/read permission."
    }

    # Check 2 — NET002: Public IPs — count and SKU hygiene
    try
    {
        $publicIPs = @(Get-AzPublicIpAddress -ErrorAction SilentlyContinue)
        if ($publicIPs.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Networking" -CheckId "NET002" -CheckName "Public IP inventory reviewed" `
                -Status "Pass" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-SE-07" `
                -Evidence "No public IPs found in this subscription" `
                -Recommendation "Maintain minimal public IP exposure. Route internet traffic through Azure Firewall or Application Gateway."
        }
        else
        {
            $basicSku    = $publicIPs | Where-Object { $_.Sku.Name -eq "Basic" }
            $unattached  = $publicIPs | Where-Object {
                -not (Get-SafeProperty -Object $_.IpConfiguration -PropertyName "Id")
            }

            $issues = @()
            if ($basicSku.Count -gt 0)    { $issues += "$($basicSku.Count) Basic SKU (retire before Sep 2025 deadline)" }
            if ($unattached.Count -gt 0)  { $issues += "$($unattached.Count) unattached/unused IP(s)" }

            if ($issues.Count -eq 0)
            {
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Networking" -CheckId "NET002" -CheckName "Public IP inventory reviewed" `
                    -Status "Pass" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-SE-07" `
                    -Evidence "$($publicIPs.Count) public IP(s) found; all Standard SKU and attached" `
                    -Recommendation "Periodically audit public IP usage. Minimise exposure by routing via hub firewall or Application Gateway."
            }
            else
            {
                $severity = if ($basicSku.Count -gt 0) { "High" } else { "Low" }
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Networking" -CheckId "NET002" -CheckName "Public IP inventory reviewed" `
                    -Status "Fail" -Severity $severity -Framework "WAF" -FrameworkRef "WAF-SE-07" `
                    -Evidence "$($publicIPs.Count) public IP(s): $($issues -join '; ')" `
                    -Recommendation "Migrate Basic SKU IPs to Standard SKU immediately. Remove unattached IPs to reduce cost and attack surface."
        }
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Networking" -CheckId "NET002" -CheckName "Public IP inventory reviewed" `
            -Status "Warning" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-SE-07" `
            -Evidence "Could not retrieve public IPs: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Network/publicIPAddresses/read permission."
    }

    # Check 3 — NET003: Private DNS zones present for PaaS resolution
    try
    {
        $privateDnsZones = @(Get-AzPrivateDnsZone -ErrorAction SilentlyContinue)
        if ($privateDnsZones.Count -gt 0)
        {
            $zoneNames = ($privateDnsZones | Select-Object -First 5 | Select-Object -ExpandProperty Name) -join ", "
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Networking" -CheckId "NET003" -CheckName "Private DNS zones configured" `
                -Status "Pass" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-DNS-001" `
                -Evidence "$($privateDnsZones.Count) private DNS zone(s): $zoneNames" `
                -Recommendation "Ensure all private endpoints have corresponding privatelink DNS zones linked to the hub VNet."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Networking" -CheckId "NET003" -CheckName "Private DNS zones configured" `
                -Status "Warning" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-DNS-001" `
                -Evidence "No private DNS zones found in this subscription" `
                -Recommendation "Deploy privatelink.* DNS zones for each PaaS service with private endpoints. Link zones to hub and spoke VNets. Centralise DNS in hub subscription for enterprise-scale deployments."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Networking" -CheckId "NET003" -CheckName "Private DNS zones configured" `
            -Status "Warning" -Severity "Medium" -Framework "CAF" -FrameworkRef "CAF-LZ-NET-DNS-001" `
            -Evidence "Could not retrieve private DNS zones: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Network/privateDnsZones/read permission."
    }

    # Check 4 — NET004: Application Gateway or Azure Firewall present for internet-facing workloads
    try
    {
        $appGateways = @(Get-AzApplicationGateway -ErrorAction SilentlyContinue)
        $firewalls   = @(Get-AzFirewall -ErrorAction SilentlyContinue)
        $total       = $appGateways.Count + $firewalls.Count

        if ($total -gt 0)
        {
            $evidence = @()
            if ($firewalls.Count -gt 0)   { $evidence += "$($firewalls.Count) Azure Firewall(s)" }
            if ($appGateways.Count -gt 0) { $evidence += "$($appGateways.Count) Application Gateway(s)" }
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Networking" -CheckId "NET004" -CheckName "Firewall or Application Gateway present" `
                -Status "Pass" -Severity "Critical" -Framework "WAF" -FrameworkRef "WAF-SE-04" `
                -Evidence ($evidence -join "; ") `
                -Recommendation "Ensure WAF policy is attached to Application Gateway and Azure Firewall is in Forced Tunnel mode for all egress."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Networking" -CheckId "NET004" -CheckName "Firewall or Application Gateway present" `
                -Status "Warning" -Severity "Critical" -Framework "WAF" -FrameworkRef "WAF-SE-04" `
                -Evidence "No Azure Firewall or Application Gateway found in this subscription" `
                -Recommendation "If this is a hub or internet-facing subscription, deploy Azure Firewall Premium for egress and Application Gateway WAF v2 for ingress. If this is a spoke, verify firewall exists in hub."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Networking" -CheckId "NET004" -CheckName "Firewall or Application Gateway present" `
            -Status "Warning" -Severity "Critical" -Framework "WAF" -FrameworkRef "WAF-SE-04" `
            -Evidence "Could not retrieve firewall/gateway data: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Network/azureFirewalls/read and Microsoft.Network/applicationGateways/read permissions."
    }

    # Check 5 — NET005: VNet subnets have NSGs associated
    try
    {
        $vnets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)
        $subnetsWithoutNSG = @()
        foreach ($vnet in $vnets)
        {
            foreach ($subnet in $vnet.Subnets)
            {
                $subnetName = Get-SafeProperty -Object $subnet -PropertyName "Name"
                # Skip gateway and special subnets
                if ($subnetName -match "GatewaySubnet|AzureFirewallSubnet|AzureBastionSubnet|RouteServerSubnet") { continue }
                $nsg = Get-SafeProperty -Object $subnet -PropertyName "NetworkSecurityGroup"
                if (-not $nsg) { $subnetsWithoutNSG += "$($vnet.Name)/$subnetName" }
            }
        }

        if ($subnetsWithoutNSG.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Networking" -CheckId "NET005" -CheckName "All subnets have NSGs associated" `
                -Status "Pass" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-6.2" `
                -Evidence "All non-reserved subnets have NSGs associated" `
                -Recommendation "Regularly audit NSG rules and remove Any/Any allow rules. Use Azure Network Watcher to verify effective security rules."
        }
        else
        {
            $sample = ($subnetsWithoutNSG | Select-Object -First 5) -join "; "
            $more   = if ($subnetsWithoutNSG.Count -gt 5) { " (+$($subnetsWithoutNSG.Count - 5) more)" } else { "" }
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Networking" -CheckId "NET005" -CheckName "All subnets have NSGs associated" `
                -Status "Fail" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-6.2" `
                -Evidence "Subnets without NSGs: $sample$more" `
                -Recommendation "Associate an NSG with every workload subnet. Deny all inbound by default and allow only required traffic explicitly."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Networking" -CheckId "NET005" -CheckName "All subnets have NSGs associated" `
            -Status "Warning" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-6.2" `
            -Evidence "Could not retrieve VNet/subnet data: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Network/virtualNetworks/read and subnets/read permissions."
    }

    return $findings
}

Function Test-SecurityPillar
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-PillarHeader "Security"

    # Check 1 — SEC001: Key Vault soft-delete and purge protection enabled
    try
    {
        $kvs = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
        if ($kvs.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Security" -CheckId "SEC001" -CheckName "Key Vault soft-delete and purge protection" `
                -Status "NotApplicable" -Severity "Critical" -Framework "CIS" -FrameworkRef "CIS-8.4" `
                -Evidence "No Key Vaults found in this subscription" `
                -Recommendation "When deploying Key Vaults, enable soft-delete with 90-day retention and purge protection by default."
        }
        else
        {
            $missingProtection = @()
            foreach ($kv in $kvs)
            {
                try
                {
                    $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName -ErrorAction SilentlyContinue
                    $softDelete   = Get-SafeProperty -Object $kvDetail -PropertyName "EnableSoftDelete"
                    $purgeProtect = Get-SafeProperty -Object $kvDetail -PropertyName "EnablePurgeProtection"
                    if ($softDelete -ne $true -or $purgeProtect -ne $true)
                    {
                        $missing = @()
                        if ($softDelete -ne $true)   { $missing += "SoftDelete" }
                        if ($purgeProtect -ne $true) { $missing += "PurgeProtection" }
                        $missingProtection += "$($kv.VaultName) (missing: $($missing -join ','))"
                    }
                }
                catch { $missingProtection += "$($kv.VaultName) (detail check failed)" }
            }

            if ($missingProtection.Count -eq 0)
            {
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Security" -CheckId "SEC001" -CheckName "Key Vault soft-delete and purge protection" `
                    -Status "Pass" -Severity "Critical" -Framework "CIS" -FrameworkRef "CIS-8.4" `
                    -Evidence "All $($kvs.Count) Key Vault(s) have soft-delete and purge protection enabled" `
                    -Recommendation "Set soft-delete retention to 90 days. Review Key Vault access policies and prefer RBAC over vault access policies."
            }
            else
            {
                $sample = ($missingProtection | Select-Object -First 5) -join "; "
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Security" -CheckId "SEC001" -CheckName "Key Vault soft-delete and purge protection" `
                    -Status "Fail" -Severity "Critical" -Framework "CIS" -FrameworkRef "CIS-8.4" `
                    -Evidence "Key Vault(s) missing protection: $sample" `
                    -Recommendation "Enable soft-delete (90-day retention) and purge protection on all Key Vaults immediately. These settings are irreversible once enabled — test in non-production first."
            }
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Security" -CheckId "SEC001" -CheckName "Key Vault soft-delete and purge protection" `
            -Status "Warning" -Severity "Critical" -Framework "CIS" -FrameworkRef "CIS-8.4" `
            -Evidence "Could not retrieve Key Vault data: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.KeyVault/vaults/read permission."
    }

    # Check 2 — SEC002: Storage accounts — HTTPS only, minimum TLS 1.2, public access disabled
    try
    {
        $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
        if ($storageAccounts.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Security" -CheckId "SEC002" -CheckName "Storage account security configuration" `
                -Status "NotApplicable" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-3.1" `
                -Evidence "No storage accounts found in this subscription" `
                -Recommendation "When deploying storage accounts, enforce HTTPS-only, TLS 1.2 minimum, and disable public blob access by default."
        }
        else
        {
            $insecure = @()
            foreach ($sa in $storageAccounts)
            {
                $issues = @()
                $httpsOnly = Get-SafeProperty -Object $sa -PropertyName "EnableHttpsTrafficOnly"
                $minTls    = Get-SafeProperty -Object $sa -PropertyName "MinimumTlsVersion"
                $publicBlob = Get-SafeProperty -Object $sa -PropertyName "AllowBlobPublicAccess"
                if ($httpsOnly -ne $true)          { $issues += "HTTPS-only disabled" }
                if ($minTls -ne "TLS1_2")          { $issues += "TLS < 1.2 ($minTls)" }
                if ($publicBlob -eq $true)         { $issues += "Public blob access enabled" }
                if ($issues.Count -gt 0) { $insecure += "$($sa.StorageAccountName): $($issues -join ', ')" }
            }

            if ($insecure.Count -eq 0)
            {
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Security" -CheckId "SEC002" -CheckName "Storage account security configuration" `
                    -Status "Pass" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-3.1" `
                    -Evidence "All $($storageAccounts.Count) storage account(s) meet HTTPS-only, TLS 1.2, and public access requirements" `
                    -Recommendation "Enable storage account firewall with selected network access. Consider Defender for Storage for threat detection."
            }
            else
            {
                $sample = ($insecure | Select-Object -First 5) -join " | "
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Security" -CheckId "SEC002" -CheckName "Storage account security configuration" `
                    -Status "Fail" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-3.1" `
                    -Evidence "$($insecure.Count) of $($storageAccounts.Count) storage account(s) have issues: $sample" `
                    -Recommendation "Enable HTTPS-only traffic, set minimum TLS version to TLS 1.2, and disable public blob access on all storage accounts. Apply via Azure Policy in deny mode."
            }
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Security" -CheckId "SEC002" -CheckName "Storage account security configuration" `
            -Status "Warning" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-3.1" `
            -Evidence "Could not retrieve storage accounts: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Storage/storageAccounts/read permission."
    }

    # Check 3 — SEC003: Disk encryption enabled on VM OS disks
    try
    {
        $vms = @(Get-AzVM -ErrorAction SilentlyContinue)
        if ($vms.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Security" -CheckId "SEC003" -CheckName "VM disk encryption enabled" `
                -Status "NotApplicable" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-7.3" `
                -Evidence "No virtual machines found" `
                -Recommendation "When deploying VMs, use Azure Disk Encryption (ADE) or platform-managed encryption with customer-managed keys."
        }
        else
        {
            $unencrypted = @()
            foreach ($vm in $vms)
            {
                try
                {
                    $encStatus = Get-AzVmDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction SilentlyContinue
                    $osDiskStatus = Get-SafeProperty -Object $encStatus -PropertyName "OsVolumeEncryptionSettings"
                    $adeEnabled   = Get-SafeProperty -Object $osDiskStatus -PropertyName "Enabled"
                    if ($adeEnabled -ne $true) { $unencrypted += $vm.Name }
                }
                catch { $unencrypted += "$($vm.Name) (check failed)" }
            }

            if ($unencrypted.Count -eq 0)
            {
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Security" -CheckId "SEC003" -CheckName "VM disk encryption enabled" `
                    -Status "Pass" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-7.3" `
                    -Evidence "All $($vms.Count) VM(s) have disk encryption enabled" `
                    -Recommendation "Prefer customer-managed keys (CMK) in Key Vault for ADE. Enable double encryption for sensitive workloads."
            }
            else
            {
                $sample = ($unencrypted | Select-Object -First 5) -join "; "
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Security" -CheckId "SEC003" -CheckName "VM disk encryption enabled" `
                    -Status "Fail" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-7.3" `
                    -Evidence "$($unencrypted.Count) of $($vms.Count) VM(s) without disk encryption: $sample" `
                    -Recommendation "Enable Azure Disk Encryption on all VMs. Use a Key Vault per region for ADE key storage. Enforce via Azure Policy."
            }
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Security" -CheckId "SEC003" -CheckName "VM disk encryption enabled" `
            -Status "Warning" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-7.3" `
            -Evidence "Could not retrieve VM disk encryption status: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Compute/virtualMachines/read and Microsoft.Compute/disks/read permissions."
    }

    # Check 4 — SEC004: JIT VM access configured (via Defender for Cloud)
    try
    {
        $jitPolicies = @(Get-AzJitNetworkAccessPolicy -ErrorAction SilentlyContinue)
        $vms         = @(Get-AzVM -ErrorAction SilentlyContinue)

        if ($vms.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Security" -CheckId "SEC004" -CheckName "JIT VM access configured" `
                -Status "NotApplicable" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AC-17" `
                -Evidence "No virtual machines found" `
                -Recommendation "When deploying VMs, enable JIT VM access through Defender for Cloud."
        }
        elseif ($jitPolicies.Count -gt 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Security" -CheckId "SEC004" -CheckName "JIT VM access configured" `
                -Status "Pass" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AC-17" `
                -Evidence "$($jitPolicies.Count) JIT access policy(ies) configured across VMs" `
                -Recommendation "Ensure JIT covers all VMs with management ports (22, 3389, 5985). Set maximum request duration to 3 hours."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Security" -CheckId "SEC004" -CheckName "JIT VM access configured" `
                -Status "Fail" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AC-17" `
                -Evidence "No JIT VM access policies found — management ports may be permanently open" `
                -Recommendation "Enable JIT VM access in Defender for Cloud for all VMs. Block RDP (3389), SSH (22), and WinRM (5985/5986) permanently in NSGs. Use JIT or Azure Bastion for admin access."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Security" -CheckId "SEC004" -CheckName "JIT VM access configured" `
            -Status "Warning" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AC-17" `
            -Evidence "Could not retrieve JIT access policies: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Security/jitNetworkAccessPolicies/read permission."
    }

    return $findings
}

Function Test-GovernancePillar
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-PillarHeader "Governance"

    # Check 1 — GOV001: Resource locks on critical resource groups
    try
    {
        $locks = @(Get-AzResourceLock -ErrorAction SilentlyContinue)
        $rgs   = @(Get-AzResourceGroup -ErrorAction SilentlyContinue)

        if ($rgs.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Governance" -CheckId "GOV001" -CheckName "Resource locks on resource groups" `
                -Status "NotApplicable" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-GOV-LOCK-001" `
                -Evidence "No resource groups found in this subscription" `
                -Recommendation "Apply CanNotDelete or ReadOnly locks to production resource groups."
        }
        else
        {
            $lockedRgIds = $locks | Where-Object { $_.ResourceType -eq "Microsoft.Authorization/locks" -and $_.ResourceGroupName -and -not $_.ResourceName } |
                Select-Object -ExpandProperty ResourceGroupName -Unique
            $unlockedRgs = $rgs | Where-Object { $_.ResourceGroupName -notin $lockedRgIds }

            if ($unlockedRgs.Count -eq 0)
            {
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Governance" -CheckId "GOV001" -CheckName "Resource locks on resource groups" `
                    -Status "Pass" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-GOV-LOCK-001" `
                    -Evidence "All $($rgs.Count) resource group(s) have at least one resource lock" `
                    -Recommendation "Prefer CanNotDelete locks on production RGs; ReadOnly on shared platform RGs."
            }
            else
            {
                $pct = [math]::Round(($unlockedRgs.Count / $rgs.Count) * 100)
                $sample = ($unlockedRgs | Select-Object -First 5 | Select-Object -ExpandProperty ResourceGroupName) -join "; "
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Governance" -CheckId "GOV001" -CheckName "Resource locks on resource groups" `
                    -Status "Fail" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-GOV-LOCK-001" `
                    -Evidence "$($unlockedRgs.Count) of $($rgs.Count) RG(s) ($pct%) have no locks: $sample" `
                    -Recommendation "Apply CanNotDelete locks to all production resource groups. Enforce via Azure Policy (deny delete if no lock). Use ReadOnly locks on shared infrastructure RGs."
            }
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Governance" -CheckId "GOV001" -CheckName "Resource locks on resource groups" `
            -Status "Warning" -Severity "High" -Framework "CAF" -FrameworkRef "CAF-GOV-LOCK-001" `
            -Evidence "Could not retrieve resource locks: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Authorization/locks/read permission."
    }

    # Check 2 — GOV002: Subscription-level resource provider registrations are minimal
    try
    {
        $providers = @(Get-AzResourceProvider -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.RegistrationState -eq "Registered" })
        $nonMsProviders = $providers | Where-Object { $_.ProviderNamespace -notlike "Microsoft.*" }

        if ($nonMsProviders.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Governance" -CheckId "GOV002" -CheckName "Non-Microsoft resource providers reviewed" `
                -Status "Pass" -Severity "Low" -Framework "CAF" -FrameworkRef "CAF-GOV-002" `
                -Evidence "No non-Microsoft resource providers registered ($($providers.Count) total registered)" `
                -Recommendation "Periodically audit registered resource providers and unregister unused ones."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Governance" -CheckId "GOV002" -CheckName "Non-Microsoft resource providers reviewed" `
                -Status "Warning" -Severity "Low" -Framework "CAF" -FrameworkRef "CAF-GOV-002" `
                -Evidence "$($nonMsProviders.Count) non-Microsoft resource provider(s) registered" `
                -Recommendation "Audit non-Microsoft providers and unregister unused ones. Ensure marketplace agreement compliance for third-party providers."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Governance" -CheckId "GOV002" -CheckName "Non-Microsoft resource providers reviewed" `
            -Status "Warning" -Severity "Low" -Framework "CAF" -FrameworkRef "CAF-GOV-002" `
            -Evidence "Could not retrieve resource providers: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Resources/providers/read permission."
    }

    # Check 3 — GOV003: Naming convention conformance (resource groups)
    try
    {
        $rgs = @(Get-AzResourceGroup -ErrorAction SilentlyContinue)
        # CAF recommended pattern: <prefix>-<workload>-<env>-<region>-<instance>
        # We check for at least two hyphen-separated segments as a minimum signal
        $nonConformant = $rgs | Where-Object { $_.ResourceGroupName -notmatch "^[a-zA-Z0-9]+-[a-zA-Z0-9]+" }
        if ($nonConformant.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Governance" -CheckId "GOV003" -CheckName "Resource group naming convention (basic pattern)" `
                -Status "Pass" -Severity "Low" -Framework "CAF" -FrameworkRef "CAF-READY-NAME-001" `
                -Evidence "All $($rgs.Count) resource group(s) follow a hyphen-delimited naming pattern" `
                -Recommendation "Enforce full CAF naming: <prefix>-<workload>-<environment>-<region>-<instance> via Azure Policy."
        }
        else
        {
            $names = ($nonConformant | Select-Object -First 5 | Select-Object -ExpandProperty ResourceGroupName) -join "; "
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Governance" -CheckId "GOV003" -CheckName "Resource group naming convention (basic pattern)" `
                -Status "Warning" -Severity "Low" -Framework "CAF" -FrameworkRef "CAF-READY-NAME-001" `
                -Evidence "$($nonConformant.Count) RG(s) with non-standard naming: $names" `
                -Recommendation "Adopt and enforce CAF naming convention. Consider Azure Policy to audit resource names at creation time."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Governance" -CheckId "GOV003" -CheckName "Resource group naming convention (basic pattern)" `
            -Status "Warning" -Severity "Low" -Framework "CAF" -FrameworkRef "CAF-READY-NAME-001" `
            -Evidence "Could not retrieve resource groups: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Resources/resourceGroups/read permission."
    }

    # Check 4 — GOV004: Subscription budget/cost alert configured
    try
    {
        $budgets = @(Get-AzConsumptionBudget -ErrorAction SilentlyContinue)
        if ($budgets.Count -gt 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Governance" -CheckId "GOV004" -CheckName "Cost budget alert configured" `
                -Status "Pass" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-CO-04" `
                -Evidence "$($budgets.Count) budget(s) configured for this subscription" `
                -Recommendation "Ensure budget alerts notify the subscription owner and finance team. Set alert thresholds at 80% and 100% of budget."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Governance" -CheckId "GOV004" -CheckName "Cost budget alert configured" `
                -Status "Fail" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-CO-04" `
                -Evidence "No cost budget configured for this subscription" `
                -Recommendation "Create an Azure Consumption Budget with alert thresholds at 80% and 100%. Notify the subscription owner and finance stakeholder. Use Cost Management anomaly alerts for spike detection."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Governance" -CheckId "GOV004" -CheckName "Cost budget alert configured" `
            -Status "Warning" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-CO-04" `
            -Evidence "Could not retrieve budget data: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Consumption/budgets/read permission."
    }

    return $findings
}

Function Test-ResiliencePillar
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-PillarHeader "Resilience"

    # Check 1 — RES001: VMs deployed in Availability Zones or Availability Sets
    try
    {
        $vms = @(Get-AzVM -ErrorAction SilentlyContinue)
        if ($vms.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Resilience" -CheckId "RES001" -CheckName "VMs deployed with zone or set redundancy" `
                -Status "NotApplicable" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-RE-03" `
                -Evidence "No virtual machines found in this subscription" `
                -Recommendation "When deploying VMs, use Availability Zones (preferred) or Availability Sets for HA."
        }
        else
        {
            $noRedundancy = $vms | Where-Object {
                $zones = Get-SafeProperty -Object $_ -PropertyName "Zones"
                $avSet = Get-SafeProperty -Object $_.AvailabilitySetReference -PropertyName "Id"
                (-not $zones -or $zones.Count -eq 0) -and [string]::IsNullOrWhiteSpace($avSet)
            }

            if ($noRedundancy.Count -eq 0)
            {
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Resilience" -CheckId "RES001" -CheckName "VMs deployed with zone or set redundancy" `
                    -Status "Pass" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-RE-03" `
                    -Evidence "All $($vms.Count) VM(s) are in Availability Zones or Availability Sets" `
                    -Recommendation "Prefer Availability Zones over Availability Sets for zone-level fault isolation. Use zone-redundant load balancers."
            }
            else
            {
                $names = ($noRedundancy | Select-Object -First 5 | Select-Object -ExpandProperty Name) -join "; "
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Resilience" -CheckId "RES001" -CheckName "VMs deployed with zone or set redundancy" `
                    -Status "Fail" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-RE-03" `
                    -Evidence "$($noRedundancy.Count) of $($vms.Count) VM(s) have no zone/set redundancy: $names" `
                    -Recommendation "Redeploy VMs into Availability Zones. For VMs that cannot be moved, place them in Availability Sets. Use Azure Site Recovery for DR."
            }
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Resilience" -CheckId "RES001" -CheckName "VMs deployed with zone or set redundancy" `
            -Status "Warning" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-RE-03" `
            -Evidence "Could not retrieve VM data: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Compute/virtualMachines/read permission."
    }

    # Check 2 — RES002: Recovery Services Vault present with backup policies
    try
    {
        $rsvaults = @(Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue)
        if ($rsvaults.Count -gt 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Resilience" -CheckId "RES002" -CheckName "Recovery Services Vault present" `
                -Status "Pass" -Severity "Critical" -Framework "WAF" -FrameworkRef "WAF-RE-06" `
                -Evidence "$($rsvaults.Count) Recovery Services Vault(s) found" `
                -Recommendation "Verify backup policies cover all critical VMs and data sources. Test restore procedures quarterly. Enable soft-delete on the vault."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Resilience" -CheckId "RES002" -CheckName "Recovery Services Vault present" `
                -Status "Fail" -Severity "Critical" -Framework "WAF" -FrameworkRef "WAF-RE-06" `
                -Evidence "No Recovery Services Vault found in this subscription" `
                -Recommendation "Deploy a Recovery Services Vault and configure backup policies for all VMs, SQL databases, and file shares. Enable soft-delete (14–90 days) and cross-region restore."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Resilience" -CheckId "RES002" -CheckName "Recovery Services Vault present" `
            -Status "Warning" -Severity "Critical" -Framework "WAF" -FrameworkRef "WAF-RE-06" `
            -Evidence "Could not retrieve Recovery Services Vaults: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.RecoveryServices/vaults/read permission."
    }

    # Check 3 — RES003: Zone-redundant storage (ZRS/GZRS) on critical storage accounts
    try
    {
        $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
        if ($storageAccounts.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Resilience" -CheckId "RES003" -CheckName "Zone-redundant storage in use" `
                -Status "NotApplicable" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-RE-04" `
                -Evidence "No storage accounts found in this subscription" `
                -Recommendation "When deploying storage accounts, use ZRS or GZRS for zone-level redundancy."
        }
        else
        {
            $lrsAccounts = $storageAccounts | Where-Object { $_.Sku.Name -like "*LRS*" -and $_.Sku.Name -notlike "*GRS*" }
            if ($lrsAccounts.Count -eq 0)
            {
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Resilience" -CheckId "RES003" -CheckName "Zone-redundant storage in use" `
                    -Status "Pass" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-RE-04" `
                    -Evidence "All $($storageAccounts.Count) storage account(s) use zone-redundant or geo-redundant SKUs" `
                    -Recommendation "Prefer GZRS for mission-critical data requiring both zone and geo redundancy."
            }
            else
            {
                $lrsNames = ($lrsAccounts | Select-Object -First 5 | ForEach-Object { "$($_.StorageAccountName) ($($_.Sku.Name))" }) -join "; "
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Resilience" -CheckId "RES003" -CheckName "Zone-redundant storage in use" `
                    -Status "Warning" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-RE-04" `
                    -Evidence "$($lrsAccounts.Count) storage account(s) using LRS (single zone): $lrsNames" `
                    -Recommendation "Migrate LRS storage accounts to ZRS or GZRS for improved resilience. Prioritise storage accounts used for critical application data or backups."
            }
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Resilience" -CheckId "RES003" -CheckName "Zone-redundant storage in use" `
            -Status "Warning" -Severity "Medium" -Framework "WAF" -FrameworkRef "WAF-RE-04" `
            -Evidence "Could not retrieve storage account SKUs: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Storage/storageAccounts/read permission."
    }

    # Check 4 — RES004: Azure Backup soft-delete enabled on Recovery Services Vaults
    try
    {
        $rsvaults = @(Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue)
        if ($rsvaults.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Resilience" -CheckId "RES004" -CheckName "Backup vault soft-delete enabled" `
                -Status "NotApplicable" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-RE-07" `
                -Evidence "No Recovery Services Vaults to assess" `
                -Recommendation "When deploying Recovery Services Vaults, enable soft-delete immediately."
        }
        else
        {
            $vaultsWithoutSoftDelete = @()
            foreach ($vault in $rsvaults)
            {
                try
                {
                    Set-AzRecoveryServicesVaultContext -Vault $vault -ErrorAction SilentlyContinue | Out-Null
                    $props = Get-AzRecoveryServicesVaultProperty -ErrorAction SilentlyContinue
                    $sdState = Get-SafeProperty -Object $props -PropertyName "SoftDeleteFeatureState"
                    if ($sdState -ne "Enabled") { $vaultsWithoutSoftDelete += $vault.Name }
                }
                catch { $vaultsWithoutSoftDelete += "$($vault.Name) (check failed)" }
            }

            if ($vaultsWithoutSoftDelete.Count -eq 0)
            {
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Resilience" -CheckId "RES004" -CheckName "Backup vault soft-delete enabled" `
                    -Status "Pass" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-RE-07" `
                    -Evidence "All $($rsvaults.Count) Recovery Services Vault(s) have soft-delete enabled" `
                    -Recommendation "Set soft-delete retention to 14 days minimum. Enable Enhanced Soft Delete (always-on) for critical vaults."
            }
            else
            {
                $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Pillar "Resilience" -CheckId "RES004" -CheckName "Backup vault soft-delete enabled" `
                    -Status "Fail" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-RE-07" `
                    -Evidence "Vault(s) without soft-delete: $($vaultsWithoutSoftDelete -join '; ')" `
                    -Recommendation "Enable soft-delete on all Recovery Services Vaults immediately. Consider Enhanced Soft Delete (irreversible) for production vaults to prevent ransomware-driven backup deletion."
            }
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Resilience" -CheckId "RES004" -CheckName "Backup vault soft-delete enabled" `
            -Status "Warning" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-RE-07" `
            -Evidence "Could not retrieve vault soft-delete settings: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.RecoveryServices/vaults/backupconfig/read permission."
    }

    return $findings
}

Function Test-MonitoringPillar
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId
    )

    $findings = @()
    Write-PillarHeader "Monitoring"

    # Check 1 — MON001: Action groups configured
    try
    {
        $actionGroups = @(Get-AzActionGroup -ErrorAction SilentlyContinue)
        if ($actionGroups.Count -gt 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Monitoring" -CheckId "MON001" -CheckName "Action groups configured" `
                -Status "Pass" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-OE-06" `
                -Evidence "$($actionGroups.Count) action group(s) found" `
                -Recommendation "Ensure action groups are linked to all metric and activity log alerts. Include email, SMS, and ITSM webhook receivers."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Monitoring" -CheckId "MON001" -CheckName "Action groups configured" `
                -Status "Fail" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-OE-06" `
                -Evidence "No action groups found — alerts have no notification recipients" `
                -Recommendation "Create at least one action group with email/SMS receivers for the operations team. Add ITSM connector for incident management integration. Reference action groups from all alert rules."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Monitoring" -CheckId "MON001" -CheckName "Action groups configured" `
            -Status "Warning" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-OE-06" `
            -Evidence "Could not retrieve action groups: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Insights/actionGroups/read permission."
    }

    # Check 2 — MON002: Metric alert rules exist
    try
    {
        $metricAlerts = @(Get-AzMetricAlertRuleV2 -ErrorAction SilentlyContinue)
        if ($metricAlerts.Count -gt 0)
        {
            $enabledAlerts = $metricAlerts | Where-Object { $_.Enabled -eq $true }
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Monitoring" -CheckId "MON002" -CheckName "Metric alert rules configured" `
                -Status "Pass" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-OE-07" `
                -Evidence "$($metricAlerts.Count) metric alert rule(s) found; $($enabledAlerts.Count) enabled" `
                -Recommendation "Ensure alerts cover key signals: VM CPU > 90%, available memory < 10%, disk IOPS, and application response time."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Monitoring" -CheckId "MON002" -CheckName "Metric alert rules configured" `
                -Status "Fail" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-OE-07" `
                -Evidence "No metric alert rules found in this subscription" `
                -Recommendation "Create metric alerts for critical resources: VM CPU/Memory/Disk, Storage account availability, Key Vault availability. Set appropriate thresholds and link to action groups."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Monitoring" -CheckId "MON002" -CheckName "Metric alert rules configured" `
            -Status "Warning" -Severity "High" -Framework "WAF" -FrameworkRef "WAF-OE-07" `
            -Evidence "Could not retrieve metric alerts: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Insights/metricAlerts/read permission."
    }

    # Check 3 — MON003: Log Analytics Workspace linked to Defender for Cloud
    try
    {
        $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue)
        if ($workspaces.Count -gt 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Monitoring" -CheckId "MON003" -CheckName "Log Analytics Workspace present" `
                -Status "Pass" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AU-6" `
                -Evidence "$($workspaces.Count) Log Analytics Workspace(s) found" `
                -Recommendation "Ensure the workspace is linked to Defender for Cloud and receiving security event data. Enable Azure Monitor Container Insights and VM Insights."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Monitoring" -CheckId "MON003" -CheckName "Log Analytics Workspace present" `
                -Status "Fail" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AU-6" `
                -Evidence "No Log Analytics Workspace found — centralised log aggregation is absent" `
                -Recommendation "Deploy a Log Analytics Workspace. Configure Azure Monitor Agent (AMA) on all VMs. Enable Defender for Cloud integration. Set retention to minimum 90 days."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Monitoring" -CheckId "MON003" -CheckName "Log Analytics Workspace present" `
            -Status "Warning" -Severity "High" -Framework "NIST" -FrameworkRef "NIST-AU-6" `
            -Evidence "Could not retrieve Log Analytics workspaces: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.OperationalInsights/workspaces/read permission."
    }

    # Check 4 — MON004: Azure Monitor activity log alerts for critical operations
    try
    {
        $activityAlerts = @(Get-AzActivityLogAlert -ErrorAction SilentlyContinue)
        $criticalOps    = @(
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Security/securityPolicies/write",
            "Microsoft.Authorization/policyAssignments/write"
        )
        $coveredOps = @()
        foreach ($alert in $activityAlerts)
        {
            foreach ($cond in $alert.ConditionAllOf)
            {
                if ($cond.Field -eq "operationName" -and $criticalOps -contains $cond.Equals)
                {
                    $coveredOps += $cond.Equals
                }
            }
        }
        $missingOps = $criticalOps | Where-Object { $coveredOps -notcontains $_ }

        if ($missingOps.Count -eq 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Monitoring" -CheckId "MON004" -CheckName "Activity Log alerts for critical operations" `
                -Status "Pass" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-5.2" `
                -Evidence "Activity Log alerts cover RBAC changes, security policy writes, and policy assignment changes" `
                -Recommendation "Extend alerts to include: VM deallocate, SQL firewall changes, and Key Vault access policy changes."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Monitoring" -CheckId "MON004" -CheckName "Activity Log alerts for critical operations" `
                -Status "Fail" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-5.2" `
                -Evidence "Missing Activity Log alerts for: $($missingOps -join '; ')" `
                -Recommendation "Create Activity Log alerts for all critical operations: RBAC role assignments, security policy changes, policy assignments, and Key Vault access policy modifications."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Monitoring" -CheckId "MON004" -CheckName "Activity Log alerts for critical operations" `
            -Status "Warning" -Severity "High" -Framework "CIS" -FrameworkRef "CIS-5.2" `
            -Evidence "Could not retrieve Activity Log alerts: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Insights/activityLogAlerts/read permission."
    }

    # Check 5 — MON005: Azure Monitor Workbooks or Dashboards present (observability signal)
    try
    {
        $dashboards = @(Get-AzPortalDashboard -ErrorAction SilentlyContinue)
        if ($dashboards.Count -gt 0)
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Monitoring" -CheckId "MON005" -CheckName "Monitoring dashboards configured" `
                -Status "Pass" -Severity "Low" -Framework "WAF" -FrameworkRef "WAF-OE-08" `
                -Evidence "$($dashboards.Count) Azure portal dashboard(s) found" `
                -Recommendation "Ensure dashboards include key operational metrics: VM health, storage availability, network throughput, and alert state."
        }
        else
        {
            $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Pillar "Monitoring" -CheckId "MON005" -CheckName "Monitoring dashboards configured" `
                -Status "Warning" -Severity "Low" -Framework "WAF" -FrameworkRef "WAF-OE-08" `
                -Evidence "No Azure portal dashboards found" `
                -Recommendation "Create Azure Monitor Workbooks or portal dashboards covering infrastructure health, security posture, and cost. Share dashboards with the operations and security teams."
        }
    }
    catch
    {
        $findings += New-ArchFinding -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
            -Pillar "Monitoring" -CheckId "MON005" -CheckName "Monitoring dashboards configured" `
            -Status "Warning" -Severity "Low" -Framework "WAF" -FrameworkRef "WAF-OE-08" `
            -Evidence "Could not retrieve dashboards: $($_.Exception.Message)" `
            -Recommendation "Ensure Microsoft.Portal/dashboards/read permission."
    }

    return $findings
}


#------------------------------------------------------------------------ [ HTML Report Generator ]

Function ConvertTo-ArchJsonSafe
{
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

Function Generate-ArchHtmlReport
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$AllFindings,
        [string]$GeneratedAt
    )

    # ── Pre-compute statistics ──────────────────────────────────────────────────
    $total    = @($AllFindings).Count
    $pass     = @($AllFindings | Where-Object { $_.Status -eq "Pass"          }).Count
    $fail     = @($AllFindings | Where-Object { $_.Status -eq "Fail"          }).Count
    $warning  = @($AllFindings | Where-Object { $_.Status -eq "Warning"       }).Count
    $na       = @($AllFindings | Where-Object { $_.Status -eq "NotApplicable" }).Count
    $critical = @($AllFindings | Where-Object { $_.Severity -eq "Critical" -and $_.Status -eq "Fail" }).Count
    $high     = @($AllFindings | Where-Object { $_.Severity -eq "High"     -and $_.Status -eq "Fail" }).Count
    $medium   = @($AllFindings | Where-Object { $_.Severity -eq "Medium"   -and $_.Status -eq "Fail" }).Count
    $low      = @($AllFindings | Where-Object { $_.Severity -eq "Low"      -and $_.Status -eq "Fail" }).Count
    $scorePct = if ($total -gt 0) { [math]::Round(($pass / $total) * 100) } else { 0 }

    # Pillar breakdown
    $pillars = $AllFindings | Select-Object -ExpandProperty Pillar | Sort-Object -Unique
    $pillarJsonParts = @()
    foreach ($pillar in $pillars)
    {
        $pFail = @($AllFindings | Where-Object { $_.Pillar -eq $pillar -and $_.Status -eq "Fail"    }).Count
        $pPass = @($AllFindings | Where-Object { $_.Pillar -eq $pillar -and $_.Status -eq "Pass"    }).Count
        $pWarn = @($AllFindings | Where-Object { $_.Pillar -eq $pillar -and $_.Status -eq "Warning" }).Count
        $pillarJsonParts += "{""name"":""$(ConvertTo-ArchJsonSafe $pillar)"",""pass"":$pPass,""fail"":$pFail,""warn"":$pWarn}"
    }
    $pillarJson = "[" + ($pillarJsonParts -join ",") + "]"

    # Findings JSON
    $findingParts = @()
    foreach ($f in $AllFindings)
    {
        $findingParts += "{" +
            """sub"":""$(ConvertTo-ArchJsonSafe $f.SubscriptionName)""," +
            """subId"":""$(ConvertTo-ArchJsonSafe $f.SubscriptionId)""," +
            """pillar"":""$(ConvertTo-ArchJsonSafe $f.Pillar)""," +
            """id"":""$(ConvertTo-ArchJsonSafe $f.CheckId)""," +
            """name"":""$(ConvertTo-ArchJsonSafe $f.CheckName)""," +
            """status"":""$(ConvertTo-ArchJsonSafe $f.Status)""," +
            """sev"":""$(ConvertTo-ArchJsonSafe $f.Severity)""," +
            """fw"":""$(ConvertTo-ArchJsonSafe $f.Framework)""," +
            """ref"":""$(ConvertTo-ArchJsonSafe $f.FrameworkRef)""," +
            """ev"":""$(ConvertTo-ArchJsonSafe $f.Evidence)""," +
            """rec"":""$(ConvertTo-ArchJsonSafe $f.Recommendation)""" +
        "}"
    }
    $findingsJson = "[" + ($findingParts -join ",") + "]"

    $subscriptions = ($AllFindings | Select-Object -ExpandProperty SubscriptionName | Sort-Object -Unique) -join ", "
    $scoreDash     = [math]::Round(($scorePct / 100) * 314)
    $subCount      = @($AllFindings | Select-Object -ExpandProperty SubscriptionName -Unique).Count
    $pillarCount   = @($AllFindings | Select-Object -ExpandProperty Pillar           -Unique).Count

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Azure Architecture Assessment Report</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;--border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;--green:#3fb950;--amber:#d29922;--red:#f85149;--critical:#ff4444;--text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;--mono:'JetBrains Mono','Consolas',monospace;--sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;--radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);}
body.light-theme{--bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;--border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;--green:#1a7f37;--amber:#b08000;--red:#cf222e;--critical:#cc0000;--text:#1f2328;--muted:#636c76;--muted2:#424a53;--shadow:0 4px 24px rgba(0,0,0,.12);}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;}
#sidebar{width:236px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;z-index:100;}
.logo-block{padding:20px 16px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent3),var(--accent));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:8px;}
.logo-title{font-size:13px;font-weight:600;color:var(--text);line-height:1.3;}
.logo-sub{font-size:10px;color:var(--muted);margin-top:2px;}
.version-badge{display:inline-block;font-size:9px;background:var(--surface3);border:1px solid var(--border);color:var(--muted2);border-radius:4px;padding:1px 5px;margin-top:4px;}
nav{flex:1;padding:12px 8px;overflow-y:auto;}
.nav-section{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;padding:8px 8px 4px;}
.nav-btn{display:flex;align-items:center;gap:8px;width:100%;padding:8px 10px;border-radius:var(--radius-sm);border:none;background:transparent;color:var(--muted2);font-size:12px;cursor:pointer;text-align:left;transition:all .15s;}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:rgba(163,113,247,.12);color:var(--accent3);box-shadow:inset 3px 0 0 var(--accent3);font-weight:600;}
.nav-btn .icon{font-size:15px;width:18px;text-align:center;}
.nav-count{margin-left:auto;font-size:10px;background:var(--surface3);color:var(--muted);border-radius:10px;padding:1px 6px;}
.sidebar-footer{padding:12px 16px;border-top:1px solid var(--border);font-size:10px;color:var(--muted);}
.theme-toggle{display:flex;align-items:center;gap:8px;margin-bottom:10px;}
.theme-toggle span{font-size:11px;color:var(--muted2);}
.toggle-pill{width:36px;height:18px;background:var(--surface3);border:1px solid var(--border);border-radius:9px;cursor:pointer;position:relative;transition:background .2s;}
.toggle-pill.on{background:var(--accent3);}
.toggle-pill::after{content:'';width:12px;height:12px;background:var(--text);border-radius:50%;position:absolute;top:2px;left:2px;transition:left .2s;}
.toggle-pill.on::after{left:20px;}
#main{margin-left:236px;flex:1;padding:24px;min-height:100vh;}
.page{display:none;animation:fadeIn .2s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px);}to{opacity:1;transform:translateY(0);}}
.page-header{margin-bottom:24px;}
.page-title{font-size:22px;font-weight:500;color:var(--text);}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px;}
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
.bar-label{width:110px;color:var(--muted2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent3);transition:width .6s ease;}
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
.pagination button:hover,.pagination button.active{background:var(--accent3);color:#fff;border-color:var(--accent3);}
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
.drawer-rec{font-size:13px;color:var(--text);line-height:1.6;background:rgba(163,113,247,.08);border-radius:var(--radius-sm);padding:10px 12px;border:1px solid rgba(163,113,247,.2);}
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
.pillar-icon{font-size:20px;margin-right:8px;}
@media(max-width:768px){#sidebar{transform:translateX(-100%);}#sidebar.open{transform:translateX(0);}#main{margin-left:0;padding:14px;}#menuToggle{display:flex!important;}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:150;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:6px 8px;cursor:pointer;color:var(--text);font-size:18px;}
</style>
</head>
<body>
<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">&#9776;</button>
<div id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">&#x1F3DB;</div>
    <div class="logo-title">Architecture Assessment</div>
    <div class="logo-sub">Azure Well-Architected Framework</div>
    <div class="version-badge">v1.0</div>
  </div>
  <nav>
    <div class="nav-section">Navigation</div>
    <button class="nav-btn active" onclick="showPage('pg-overview',this)"><span class="icon">&#x2302;</span> Overview</button>
    <button class="nav-btn" onclick="showPage('pg-findings',this)"><span class="icon">&#x26A0;</span> All Findings <span class="nav-count" id="nc-findings"></span></button>
    <button class="nav-btn" onclick="showPage('pg-pillars',this)"><span class="icon">&#x25A6;</span> By Pillar</button>
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
      <div class="page-title">Architecture Assessment Overview</div>
      <div class="page-sub">__SUBSCRIPTIONS__ &mdash; WAF &bull; CAF &bull; NIST CSF &bull; CIS Benchmarks</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-blue"><div class="stat-num">__TOTAL__</div><div class="stat-label">Total Checks</div></div>
      <div class="stat-card c-green"><div class="stat-num">__PASS__</div><div class="stat-label">Passed</div></div>
      <div class="stat-card c-red"><div class="stat-num">__FAIL__</div><div class="stat-label">Failed</div></div>
      <div class="stat-card c-amber"><div class="stat-num">__WARN__</div><div class="stat-label">Warnings</div></div>
      <div class="stat-card c-critical"><div class="stat-num">__CRITICAL__</div><div class="stat-label">Critical Failures</div></div>
      <div class="stat-card c-purple"><div class="stat-num">__HIGH__</div><div class="stat-label">High Failures</div></div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">Architecture Score</div>
        <div class="score-ring-wrap">
          <div class="score-ring-inner">
            <svg width="120" height="120" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="50" fill="none" stroke="var(--surface3)" stroke-width="12"/>
              <circle cx="60" cy="60" r="50" fill="none" stroke="var(--accent3)" stroke-width="12"
                stroke-dasharray="__SCORE_DASH__ 314" stroke-linecap="round"/>
            </svg>
            <div class="score-center"><div class="score-pct">__SCORE_PCT__%</div><div class="score-sub">Pass Rate</div></div>
          </div>
        </div>
        <div style="text-align:center;margin-top:8px;font-size:12px;color:var(--muted)">__PASS__ of __TOTAL__ checks passed</div>
      </div>
      <div class="panel">
        <div class="panel-title">Pillar Pass Rate</div>
        <div id="pillar-bars"></div>
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">Failure Severity Breakdown</div>
        <div class="bar-row"><span class="bar-label">Critical</span><div class="bar-track"><div class="bar-fill critical" id="bfc"></div></div><span class="bar-val">__CRITICAL__</span></div>
        <div class="bar-row"><span class="bar-label">High</span><div class="bar-track"><div class="bar-fill red" id="bfh"></div></div><span class="bar-val">__HIGH__</span></div>
        <div class="bar-row"><span class="bar-label">Medium</span><div class="bar-track"><div class="bar-fill amber" id="bfm"></div></div><span class="bar-val">__MEDIUM__</span></div>
        <div class="bar-row"><span class="bar-label">Low</span><div class="bar-track"><div class="bar-fill" id="bfl"></div></div><span class="bar-val">__LOW__</span></div>
      </div>
      <div class="panel">
        <div class="panel-title">Quick Stats</div>
        <div style="display:grid;gap:8px;font-size:12px;">
          <div style="display:flex;justify-content:space-between;padding:8px;background:var(--surface2);border-radius:6px;"><span style="color:var(--muted)">Subscriptions assessed</span><strong>__SUB_COUNT__</strong></div>
          <div style="display:flex;justify-content:space-between;padding:8px;background:var(--surface2);border-radius:6px;"><span style="color:var(--muted)">Pillars assessed</span><strong>__PILLAR_COUNT__</strong></div>
          <div style="display:flex;justify-content:space-between;padding:8px;background:var(--surface2);border-radius:6px;"><span style="color:var(--muted)">Framework coverage</span><strong>WAF, CAF, NIST, CIS</strong></div>
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
      <div class="search-wrap"><span class="search-icon">&#x2315;</span><input type="text" id="searchBox" placeholder="Search checks, pillars, subscriptions..." oninput="applyFilters()"></div>
      <select class="filter-sel" id="fStatus" onchange="applyFilters()"><option value="">All Status</option><option>Pass</option><option>Fail</option><option>Warning</option><option>NotApplicable</option></select>
      <select class="filter-sel" id="fSev" onchange="applyFilters()"><option value="">All Severity</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>
      <select class="filter-sel" id="fPillar" onchange="applyFilters()"><option value="">All Pillars</option></select>
      <select class="filter-sel" id="fFw" onchange="applyFilters()"><option value="">All Frameworks</option><option>WAF</option><option>CAF</option><option>NIST</option><option>CIS</option></select>
    </div>
    <div style="overflow-x:auto;">
      <table class="findings-table" id="findingsTable">
        <thead>
          <tr>
            <th onclick="sortTable('id')">Check ID</th>
            <th onclick="sortTable('name')">Check Name</th>
            <th onclick="sortTable('pillar')">Pillar</th>
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

  <!-- BY PILLAR PAGE -->
  <div class="page" id="pg-pillars">
    <div class="page-header">
      <div class="page-title">Assessment by WAF Pillar</div>
      <div class="page-sub">Pass / Fail / Warning breakdown per architecture pillar</div>
    </div>
    <div id="pillarCards" style="display:grid;gap:16px;"></div>
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
        <div class="info-row"><div class="info-key">Pillars Assessed</div><div class="info-val">__PILLARS_ASSESSED__</div></div>
        <div class="info-row"><div class="info-key">Generated At</div><div class="info-val">__GENERATED_AT__</div></div>
        <div class="info-row"><div class="info-key">Execution Time</div><div class="info-val">__EXEC_TIME__</div></div>
        <div class="info-row"><div class="info-key">Frameworks</div><div class="info-val">WAF, CAF, NIST CSF, CIS Benchmarks</div></div>
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
var PILLARS=__PILLAR_JSON__;
var filtered=[],sortCol='',sortDir=1,currentPage=1,pageSize=25,detailIdx=-1,detailList=[];
var PILLAR_ICONS={Identity:'&#x1F464;',Networking:'&#x1F310;',Security:'&#x1F512;',Governance:'&#x1F4CB;',Resilience:'&#x267B;',Monitoring:'&#x1F4CA;'};

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
  document.querySelectorAll('.nav-btn').forEach(function(b){b.classList.remove('active');});
  var el=document.getElementById(id);if(el)el.classList.add('active');
  if(btn)btn.classList.add('active');
  if(id==='pg-findings')renderTable();
  if(id==='pg-pillars')renderPillars();
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

// Populate pillar filter
(function(){
  var sel=document.getElementById('fPillar');
  PILLARS.forEach(function(p){
    var opt=document.createElement('option');opt.value=p.name;opt.textContent=p.name;sel.appendChild(opt);
  });
})();

function applyFilters(){
  var q=document.getElementById('searchBox').value.toLowerCase();
  var fSt=document.getElementById('fStatus').value;
  var fSv=document.getElementById('fSev').value;
  var fPl=document.getElementById('fPillar').value;
  var fFw=document.getElementById('fFw').value;
  filtered=FINDINGS.filter(function(f){
    if(q&&!(f.name.toLowerCase().includes(q)||f.pillar.toLowerCase().includes(q)||f.sub.toLowerCase().includes(q)||f.id.toLowerCase().includes(q)))return false;
    if(fSt&&f.status!==fSt)return false;
    if(fSv&&f.sev!==fSv)return false;
    if(fPl&&f.pillar!==fPl)return false;
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
    html+='<td><span class="fw-badge">'+(PILLAR_ICONS[f.pillar]||'')+'&nbsp;'+escH(f.pillar)+'</span></td>';
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
  var chips='<span class="chip">'+(PILLAR_ICONS[f.pillar]||'')+' '+escH(f.pillar)+'</span>';
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

function navDetail(dir){var next=detailIdx+dir;if(next>=0&&next<detailList.length)openDetail(next);}
function closeDrawer(e){if(e.target===document.getElementById('detailPanel'))closeDrawerDirect();}
function closeDrawerDirect(){document.getElementById('detailPanel').classList.remove('open');}

function renderPillars(){
  var container=document.getElementById('pillarCards');container.innerHTML='';
  PILLARS.forEach(function(p){
    var total=p.pass+p.fail+p.warn;
    var pct=total>0?Math.round((p.pass/total)*100):0;
    var color=pct>=80?'var(--green)':pct>=50?'var(--amber)':'var(--red)';
    var card=document.createElement('div');card.className='panel';
    card.innerHTML='<div class="panel-title"><span class="pillar-icon">'+(PILLAR_ICONS[p.name]||'&#x25A6;')+'</span>'+escH(p.name)+' Pillar</div>'+
      '<div style="display:flex;gap:20px;align-items:center;">'+
      '<div style="flex:1">'+
      '<div class="bar-row"><span class="bar-label">Pass</span><div class="bar-track"><div class="bar-fill green" style="width:'+Math.round((p.pass/Math.max(total,1))*100)+'%"></div></div><span class="bar-val">'+p.pass+'</span></div>'+
      '<div class="bar-row"><span class="bar-label">Fail</span><div class="bar-track"><div class="bar-fill red" style="width:'+Math.round((p.fail/Math.max(total,1))*100)+'%"></div></div><span class="bar-val">'+p.fail+'</span></div>'+
      '<div class="bar-row"><span class="bar-label">Warning</span><div class="bar-track"><div class="bar-fill amber" style="width:'+Math.round((p.warn/Math.max(total,1))*100)+'%"></div></div><span class="bar-val">'+p.warn+'</span></div>'+
      '</div>'+
      '<div style="text-align:center;min-width:70px;">'+
      '<div style="font-size:28px;font-weight:700;font-family:var(--mono);color:'+color+'">'+pct+'%</div>'+
      '<div style="font-size:10px;color:var(--muted)">Pass rate</div>'+
      '<button onclick="filterByPillar(\''+escH(p.name)+'\')" style="margin-top:8px;font-size:10px;padding:4px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--muted2);cursor:pointer;">View findings</button>'+
      '</div></div>';
    container.appendChild(card);
  });
}

function filterByPillar(name){
  showPage('pg-findings',document.querySelector('.nav-btn:nth-child(2)'));
  document.getElementById('fPillar').value=name;
  applyFilters();
}

// Pillar bars on overview
(function(){
  var container=document.getElementById('pillar-bars');if(!container)return;
  PILLARS.forEach(function(p){
    var total=p.pass+p.fail+p.warn;
    var pct=total>0?Math.round((p.pass/total)*100):0;
    var color=pct>=80?'green':pct>=50?'amber':'red';
    var row=document.createElement('div');row.className='bar-row';
    row.innerHTML='<span class="bar-label">'+(PILLAR_ICONS[p.name]||'')+' '+escH(p.name)+'</span>'+
      '<div class="bar-track"><div class="bar-fill '+color+'" style="width:'+pct+'%"></div></div>'+
      '<span class="bar-val">'+pct+'%</span>';
    container.appendChild(row);
  });
})();

// Severity bars
(function(){
  var maxFail=Math.max(__CRITICAL__,__HIGH__,__MEDIUM__,__LOW__,1);
  function setBar(id,val){var el=document.getElementById(id);if(el)setTimeout(function(){el.style.width=Math.round((val/maxFail)*100)+'%';},100);}
  setBar('bfc',__CRITICAL__);setBar('bfh',__HIGH__);setBar('bfm',__MEDIUM__);setBar('bfl',__LOW__);
})();

applyFilters();

document.addEventListener('keydown',function(e){
  if(e.key==='Escape')closeDrawerDirect();
  if(e.key==='ArrowLeft')navDetail(-1);
  if(e.key==='ArrowRight')navDetail(1);
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){e.preventDefault();var s=document.getElementById('searchBox');if(s)s.focus();}
});

function exportCsv(){
  var rows=[['SubscriptionName','SubscriptionId','Pillar','CheckId','CheckName','Status','Severity','Framework','FrameworkRef','Evidence','Recommendation']];
  FINDINGS.forEach(function(f){rows.push([f.sub,f.subId,f.pillar,f.id,f.name,f.status,f.sev,f.fw,f.ref,f.ev,f.rec]);});
  var csv=rows.map(function(r){return r.map(function(c){return '"'+String(c||'').replace(/"/g,'""')+'"';}).join(',');}).join('\n');
  var blob=new Blob([csv],{type:'text/csv'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='Architecture-Assessment-Export.csv';a.click();
  showToast('CSV exported');
}
</script>
</body>
</html>
'@

    # Token substitution
    $html = $html `
        -replace '__GENERATED_AT__',    $GeneratedAt `
        -replace '__SUBSCRIPTIONS__',   $subscriptions `
        -replace '__TOTAL__',           $total `
        -replace '__PASS__',            $pass `
        -replace '__FAIL__',            $fail `
        -replace '__WARN__',            $warning `
        -replace '__NA__',              $na `
        -replace '__CRITICAL__',        $critical `
        -replace '__HIGH__',            $high `
        -replace '__MEDIUM__',          $medium `
        -replace '__LOW__',             $low `
        -replace '__SCORE_PCT__',       $scorePct `
        -replace '__SCORE_DASH__',      $scoreDash `
        -replace '__SUB_COUNT__',       $subCount `
        -replace '__PILLAR_COUNT__',    $pillarCount `
        -replace '__TENANT__',          $SessionInfo.Tenant `
        -replace '__ACCOUNT__',         $SessionInfo.Account `
        -replace '__ENVIRONMENT__',     $SessionInfo.Environment `
        -replace '__PILLARS_ASSESSED__', ($ScanParameters.Pillars -join ', ') `
        -replace '__EXEC_TIME__',       $ScanParameters.ExecutionTime `
        -replace '__FINDINGS_JSON__',   $findingsJson `
        -replace '__PILLAR_JSON__',     $pillarJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureArchitectureAssessment
{
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,
        [string[]]$SubscriptionIds,
        [ValidateSet("Identity","Networking","Security","Governance","Resilience","Monitoring")]
        [string[]]$IncludePillars = @("Identity","Networking","Security","Governance","Resilience","Monitoring"),
        [switch]$ExportToCsv,
        [string]$CsvPath = "C:\Temp\AzureArchitectureAssessment-Report.csv"
    )

    $startTime = Get-Date

    Write-ArchBanner

    # Ensure required modules
    # if (-not (Ensure-ArchModules)) { return }

    # Authenticate if needed
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext)
    {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    # Resolve subscriptions
    if ($AllSubscriptions -or -not $SubscriptionIds)
    {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText = "All Subscriptions"
    }
    else
    {
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
    Write-ArchSection -Title "Session Information" -Data @{
        "Tenant"      = $currentContext.Tenant.Id
        "Account"     = $currentContext.Account.Id
        "Environment" = $currentContext.Environment.Name
    }

    Write-ArchSection -Title "Assessment Parameters" -Data @{
        "Scope"          = "$scopeText ($subCount found)"
        "Pillars"        = $IncludePillars -join ", "
        "Export to CSV"  = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Output Path"    = if ($ExportToCsv.IsPresent) { $CsvPath } else { "HTML only" }
    }

    Write-Host ""
    Write-Host "  Assessing Subscriptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $allFindings = @()
    $subIndex    = 1

    foreach ($sub in $subscriptions)
    {
        Write-ArchProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name
        Write-Host ""

        try
        {
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            if ($IncludePillars -contains "Identity")
            {
                $allFindings += Test-IdentityPillar -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }
            if ($IncludePillars -contains "Networking")
            {
                $allFindings += Test-NetworkingPillar -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }
            if ($IncludePillars -contains "Security")
            {
                $allFindings += Test-SecurityPillar -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }
            if ($IncludePillars -contains "Governance")
            {
                $allFindings += Test-GovernancePillar -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }
            if ($IncludePillars -contains "Resilience")
            {
                $allFindings += Test-ResiliencePillar -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }
            if ($IncludePillars -contains "Monitoring")
            {
                $allFindings += Test-MonitoringPillar -SubscriptionName $sub.Name -SubscriptionId $sub.Id
            }

            $subFindings = $allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id }
            $subFail     = @($subFindings | Where-Object { $_.Status -eq "Fail"    }).Count
            $subPass     = @($subFindings | Where-Object { $_.Status -eq "Pass"    }).Count
            $subCrit     = @($subFindings | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "Critical" }).Count

            $color = if ($subCrit -gt 0) { "Red" } elseif ($subFail -gt 0) { "Yellow" } else { "Green" }
            Write-Host "  ✓ $($sub.Name.PadRight(42)) Pass: $subPass | Fail: $subFail | Critical: $subCrit" -ForegroundColor $color
        }
        catch
        {
            Write-Host "  ✗ $($sub.Name) — Error: $($_.Exception.Message)" -ForegroundColor Red
        }

        $subIndex++
    }

    # Compute totals
    $endTime  = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    $totalChecks = @($allFindings).Count
    $passCount   = @($allFindings | Where-Object { $_.Status -eq "Pass"    }).Count
    $failCount   = @($allFindings | Where-Object { $_.Status -eq "Fail"    }).Count
    $warnCount   = @($allFindings | Where-Object { $_.Status -eq "Warning" }).Count
    $critCount   = @($allFindings | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "Critical" }).Count
    $highCount   = @($allFindings | Where-Object { $_.Status -eq "Fail" -and $_.Severity -eq "High"     }).Count
    $scorePct    = if ($totalChecks -gt 0) { [math]::Round(($passCount / $totalChecks) * 100) } else { 0 }

    Write-ArchSummary -Data @{
        "Total Checks"          = $totalChecks
        "Passed"                = $passCount
        "Failed"                = $failCount
        "Warnings"              = $warnCount
        "Critical Failures"     = $critCount
        "High Failures"         = $highCount
        "Architecture Score"    = "$scorePct% ($passCount/$totalChecks checks passed)"
        "Execution Time"        = $duration
    }

    # Outputs
    $csvExported  = $false
    $htmlExported = $false
    $htmlPath     = ""

    if ($allFindings.Count -gt 0)
    {
        if ($ExportToCsv)
        {
            try
            {
                $dir = Split-Path $CsvPath -Parent
                if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                $allFindings | Export-Csv -Path $CsvPath -NoTypeInformation -Force
                $csvExported = $true
            }
            catch { Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red }
        }

        # HTML Report
        try
        {
            $htmlPath = $CsvPath -replace '\.csv$', '.html'
            if (-not $htmlPath.EndsWith('.html')) { $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html') }

            $scanParams = @{
                Pillars       = $IncludePillars
                ExecutionTime = $duration
            }

            $htmlContent = Generate-ArchHtmlReport `
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
        try
        {
            $allFindings | Out-GridView -Title "Azure Architecture Assessment Findings"
            $gridOpened = $true
        }
        catch { Write-Host "  ⚠ Grid View not available in this session" -ForegroundColor Yellow }

        Write-ArchOutputFiles `
            -CsvPath $(if ($csvExported) { $CsvPath } else { $null }) `
            -HtmlPath $(if ($htmlExported) { $htmlPath } else { $null }) `
            -GridViewOpened $gridOpened
    }
    else
    {
        Write-Host ""
        Write-Host "  ⚠ No findings collected. Verify module permissions and subscription access." -ForegroundColor Yellow
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
