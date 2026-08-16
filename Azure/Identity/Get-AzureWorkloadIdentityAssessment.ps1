<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 16 August 2026
Modified-On     : 16 August 2026

.SYNOPSIS
    Assesses Azure workload identity architecture — Managed Identity adoption versus
    secrets and Service Principal-based authentication — across compute, integration,
    and platform workloads, plus the Key Vault access model, identifying passwordless
    authentication gaps and providing actionable remediation guidance.

.DESCRIPTION
    Get-AzureWorkloadIdentityAssessment evaluates identity architecture posture across
    one or multiple subscriptions from a Cloud/Solution Architect perspective — the goal
    is to identify where workloads still depend on secrets, keys, or Service
    Principal credentials instead of Managed Identity, and to surface the concrete
    migration action for each gap.

    Default assessment (fast, ARM metadata only):
        - Managed Identity presence (SystemAssigned / UserAssigned / None) across
          App Service & Function Apps, VMs, VM Scale Sets, AKS, Container Apps,
          Logic Apps (Consumption), Automation Accounts, Data Factory, Synapse
          Workspaces, Container Registries, API Management, and App Configuration
        - Resource-specific secondary auth-surface checks:
            • Container Registry admin user (static credential) enabled
            • App Configuration local authentication (access keys) enabled
            • Automation Account legacy "Run As" connection (certificate-based SPN,
              deprecated by Microsoft in September 2023)
        - Key Vault access model: RBAC vs legacy access-policy, and whether each
          granted principal is a Managed Identity, an Application (SPN) registration,
          or a user/group — flags Application-type SPN access as a passwordless gap
        - Risk-rated findings (High / Medium / Low / Info) with a specific
          recommendation per finding, not just a pass/fail flag

    Optional deeper scans (each opt-in — they require elevated permissions or extra
    directory calls, so they are skipped by default for speed and least-privilege):
        - `-IncludeConfigurationScan`: reads App Service / Function App application
          settings and flags key-pattern setting names (connection strings, account
          keys, shared access signatures) that indicate credential-based access is
          still configured alongside — or instead of — a Managed Identity. Requires
          `Microsoft.Web/sites/config/list/action`. If denied, the finding is marked
          "Not Assessed / Warning" and the assessment continues.
        - `-IncludeServicePrincipalCredentials`: for every Application-type SPN found
          with Key Vault access, resolves its client secret / certificate credentials
          via Microsoft Entra ID and classifies expiry (Active / Expiring Soon /
          Expired / No Expiry Set). Requires directory read permission on
          Applications. If denied, the finding is marked "Not Assessed / Warning".

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of workload findings and Key Vault access findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          distribution panels, detail drawer)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER IncludeConfigurationScan
    Switch. When specified, retrieves App Service / Function App application
    settings and flags key-pattern setting names indicating credential-based
    (rather than identity-based) access. Disabled by default — this call requires
    elevated permission and reads configuration data. If it fails, the finding is
    marked "Not Assessed / Warning" and the scan continues.

.PARAMETER IncludeServicePrincipalCredentials
    Switch. When specified, resolves client secret / certificate expiry for every
    Application-type Service Principal found holding Key Vault access. Disabled by
    default — requires Microsoft Entra directory read permission. If it fails, the
    finding is marked "Not Assessed / Warning" and the scan continues.

.PARAMETER ExportToCsv
    Switch. If specified, exports workload identity findings and Key Vault access
    findings to CSV files derived from -CsvPath. The HTML dashboard is always
    generated regardless.

.PARAMETER CsvPath
    Path where the primary CSV export will be written when -ExportToCsv is
    specified. Also used to derive the Key Vault access CSV file name and the HTML
    dashboard file name (same path, different suffix/extension).
    Default: C:\Temp\AzureWorkloadIdentity-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes CSV files when -ExportToCsv
    is specified. Displays results in an interactive Grid View window where a GUI
    is available.

.EXAMPLE
    Get-AzureWorkloadIdentityAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureWorkloadIdentityAssessment -AllSubscriptions -IncludeConfigurationScan -IncludeServicePrincipalCredentials

.EXAMPLE
    Get-AzureWorkloadIdentityAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureWorkloadIdentityAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\WorkloadIdentity.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (16-Aug-2026) - Initial release. Managed Identity adoption assessment
                            across compute/integration/platform workloads, Key
                            Vault access-model evaluation, optional application
                            settings scan and Service Principal credential expiry
                            resolution. CSV export and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.KeyVault)
           — installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level for the default scan.
        4. Microsoft.Web/sites/config/list/action is required for
           -IncludeConfigurationScan. Without it, the finding is gracefully marked
           "Not Assessed / Warning" and assessment continues.
        5. Microsoft Entra ID directory read permission on Applications
           (e.g. Application.Read.All, or Directory Readers role) is required for
           -IncludeServicePrincipalCredentials. Without it, the finding is
           gracefully marked "Not Assessed / Warning" and assessment continues.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Resource coverage is limited to types that expose the ARM `identity`
          property via a generic resource GET (Get-AzResource -ExpandProperties).
          Legacy/classic resource types are not included.
        - Whether a principal is a Managed Identity or an Application (SPN)
          registration relies on the ServicePrincipalType attribute returned by
          Microsoft Entra ID. If that lookup fails or is denied, the principal is
          reported as "Unknown" rather than assumed compliant — never asserted as
          confirmed when indeterminate.
        - Key Vault evaluation covers the access-policy model and RBAC role
          assignments scoped to the vault; it does not evaluate network ACLs,
          firewall rules, or private endpoint configuration.
        - -IncludeConfigurationScan uses setting-name pattern matching (e.g.
          "ConnectionString", "AccountKey", "SharedAccessSignature", "Secret",
          "Password") to flag likely credential-based configuration; it cannot
          guarantee a setting is unused or that all credential patterns are caught.
        - Interactive Grid View requires a GUI-capable session. Skipped
          gracefully in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview
    https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
    https://learn.microsoft.com/en-us/azure/automation/automation-security-overview
    https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication

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
    Write-CenteredText "Azure Workload Identity Assessment v1.0" -Color White
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
            $valColor = "DarkGray"
        }
        else {
            $valColor = "White"
        }

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

Function Write-RiskBreakdown {
    param([hashtable]$Risk)

    if ($Risk.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Risk Severity Breakdown" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $colorMap = @{ "High" = "Red"; "Medium" = "Yellow"; "Low" = "Cyan"; "Info" = "Green" }
    $order = @("High", "Medium", "Low", "Info")

    foreach ($level in $order) {
        if (-not $Risk.ContainsKey($level)) { continue }
        $color = if ($colorMap.ContainsKey($level)) { $colorMap[$level] } else { "White" }
        Write-Host "  " -NoNewline
        Write-Host $level.PadRight(22) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($Risk[$level]) finding(s)" -ForegroundColor $color
    }
}

Function Write-KeyVaultSummary {
    param([array]$KeyVaultFindings)

    if ($KeyVaultFindings.Count -eq 0) { return }

    $mi = @($KeyVaultFindings | Where-Object { $_.PrincipalType -eq "ManagedIdentity" }).Count
    $app = @($KeyVaultFindings | Where-Object { $_.PrincipalType -eq "Application" }).Count
    $unknown = @($KeyVaultFindings | Where-Object { $_.PrincipalType -eq "Unknown" }).Count

    Write-Host ""
    Write-Host "  Key Vault Access Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Total Principal Grants     : $($KeyVaultFindings.Count)" -ForegroundColor White
    Write-Host "  Managed Identity (Compliant): $mi" -ForegroundColor Green
    Write-Host "  Application/SPN (Gap)      : $app" -ForegroundColor Red
    Write-Host "  Unknown / Not Confirmed    : $unknown" -ForegroundColor DarkGray
}

Function Write-OutputFiles {
    param(
        [string]$CsvPath,
        [string]$KvCsvPath,
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
        Write-Host ("Findings CSV").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }

    if ($KvCsvPath) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("Key Vault Access CSV").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $KvCsvPath" -ForegroundColor White
    }

    if ($HtmlPath) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Dashboard").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }

    if ($GridViewOpened) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
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

Function Get-ExpiryClassification {
    param([Nullable[datetime]]$ExpiresOn)

    if (-not $ExpiresOn) { return @{ Status = "No Expiry Set"; Date = "N/A" } }

    $daysLeft = ($ExpiresOn - (Get-Date)).Days
    $status = if ($daysLeft -lt 0) { "Expired" }
    elseif ($daysLeft -le 30) { "Expiring Soon" }
    else { "Active" }

    return @{ Status = $status; Date = $ExpiresOn.ToString("yyyy-MM-dd") }
}


#------------------------------------------------------------------------ [ Assessment Constants ]

$script:WorkloadResourceTypes = @(
    @{ Type = "Microsoft.Web/sites"; Category = "Compute"; Friendly = "App Service / Function App" }
    @{ Type = "Microsoft.Compute/virtualMachines"; Category = "Compute"; Friendly = "Virtual Machine" }
    @{ Type = "Microsoft.Compute/virtualMachineScaleSets"; Category = "Compute"; Friendly = "VM Scale Set" }
    @{ Type = "Microsoft.ContainerService/managedClusters"; Category = "Compute"; Friendly = "AKS Cluster" }
    @{ Type = "Microsoft.App/containerApps"; Category = "Compute"; Friendly = "Container App" }
    @{ Type = "Microsoft.Logic/workflows"; Category = "Integration"; Friendly = "Logic App (Consumption)" }
    @{ Type = "Microsoft.Automation/automationAccounts"; Category = "Integration"; Friendly = "Automation Account" }
    @{ Type = "Microsoft.DataFactory/factories"; Category = "Integration"; Friendly = "Data Factory" }
    @{ Type = "Microsoft.Synapse/workspaces"; Category = "Integration"; Friendly = "Synapse Workspace" }
    @{ Type = "Microsoft.ContainerRegistry/registries"; Category = "Platform"; Friendly = "Container Registry" }
    @{ Type = "Microsoft.ApiManagement/service"; Category = "Platform"; Friendly = "API Management" }
    @{ Type = "Microsoft.AppConfiguration/configurationStores"; Category = "Platform"; Friendly = "App Configuration" }
)

$script:CredentialPatterns = @(
    "ConnectionString", "AccountKey", "SharedAccessSignature", "SasToken",
    "ApiKey", "ClientSecret", "Secret", "Password", "AuthKey", "AccessKey"
)


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-WorkloadIdentityHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$KeyVaultFindings,
        [hashtable]$CategoryDistribution,
        [hashtable]$RiskDistribution,
        [hashtable]$GapDistribution,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [bool]$ConfigScanIncluded,
        [bool]$SpnCredentialsIncluded
    )

    $totalFindings = @($Findings).Count
    $totalResources = @($Findings | Select-Object -ExpandProperty ResourceId -Unique).Count
    $compliantCount = @($Findings | Where-Object { $_.GapCategory -eq "Compliant" }).Count
    $highCount = @($Findings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $noMiCount = @($Findings | Where-Object { $_.GapCategory -eq "No Managed Identity" }).Count

    $totalKv = @($KeyVaultFindings).Count
    $kvGapCount = @($KeyVaultFindings | Where-Object { $_.PrincipalType -eq "Application" }).Count
    $kvCompliantCount = @($KeyVaultFindings | Where-Object { $_.PrincipalType -eq "ManagedIdentity" }).Count

    $adoptionPct = if ($totalResources -gt 0) { [math]::Round(($compliantCount / [math]::Max($totalFindings, 1)) * 100) } else { 0 }

    $configScanBadgeText = if ($ConfigScanIncluded) { "Included" } else { "Skipped — use -IncludeConfigurationScan to enable" }
    $spnCredBadgeText = if ($SpnCredentialsIncluded) { "Included" } else { "Skipped — use -IncludeServicePrincipalCredentials to enable" }

    # ── Findings table rows ───────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $riskCls = switch ($f.RiskLevel) {
            "High" { "badge-red" }
            "Medium" { "badge-amber" }
            "Low" { "badge-blue" }
            default { "badge-green" }
        }
        $findingRows += @"
          <tr onclick="showFindingDetail($($Findings.IndexOf($f)))">
            <td title="$(EscHtml $f.ResourceName)">$(if ($f.ResourceName.Length -gt 34) { EscHtml($f.ResourceName.Substring(0,31)+"...") } else { EscHtml $f.ResourceName })</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$(EscHtml $f.ResourceTypeFriendly)</td>
            <td>$(EscHtml $f.IdentityType)</td>
            <td>$(EscHtml $f.GapCategory)</td>
            <td><span class="badge $riskCls">$(EscHtml $f.RiskLevel)</span></td>
          </tr>
"@
    }

    # ── Key Vault access table rows ───────────────────────────────────────────
    $kvRows = ""
    foreach ($k in $KeyVaultFindings) {
        $ptCls = switch ($k.PrincipalType) {
            "ManagedIdentity" { "badge-green" }
            "Application" { "badge-red" }
            default { "badge-amber" }
        }
        $kvRows += @"
          <tr>
            <td title="$(EscHtml $k.VaultName)">$(EscHtml $k.VaultName)</td>
            <td>$(EscHtml $k.SubscriptionName)</td>
            <td>$(EscHtml $k.AuthModel)</td>
            <td title="$(EscHtml $k.PrincipalName)">$(if ($k.PrincipalName.Length -gt 28) { EscHtml($k.PrincipalName.Substring(0,25)+"...") } else { EscHtml $k.PrincipalName })</td>
            <td><span class="badge $ptCls">$(EscHtml $k.PrincipalType)</span></td>
            <td>$(EscHtml $k.CredentialExpiryStatus)</td>
          </tr>
"@
    }

    # ── Subscription results ──────────────────────────────────────────────────
    $subRows = ""
    foreach ($s in $SubscriptionResults) {
        $icon = switch ($s.Status) { "Success" { "✓" }; "Warning" { "⚠" }; "Error" { "✗" }; default { "•" } }
        $cls = switch ($s.Status) { "Success" { "c-green" }; "Warning" { "c-amber" }; "Error" { "c-red" }; default { "" } }
        $subRows += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $s.Name)</span>
            <span class="sub-detail">$(EscHtml $s.Summary)</span>
          </div>
"@
    }

    # ── Category distribution bar rows ────────────────────────────────────────
    $catTotal = ($CategoryDistribution.Values | Measure-Object -Sum).Sum
    $catRows = ""
    foreach ($c in ($CategoryDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($catTotal -gt 0) { [math]::Round(($c.Value / $catTotal) * 100) } else { 0 }
        $catRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $c.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($c.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Risk distribution bar rows ────────────────────────────────────────────
    $riskTotal = ($RiskDistribution.Values | Measure-Object -Sum).Sum
    $riskRows = ""
    foreach ($r in ($RiskDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($riskTotal -gt 0) { [math]::Round(($r.Value / $riskTotal) * 100) } else { 0 }
        $barColor = switch ($r.Key) {
            "High" { "var(--red)" }
            "Medium" { "var(--amber)" }
            "Low" { "var(--accent)" }
            default { "var(--green)" }
        }
        $riskRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $r.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($r.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Gap category distribution bar rows ────────────────────────────────────
    $gapTotal = ($GapDistribution.Values | Measure-Object -Sum).Sum
    $gapRows = ""
    foreach ($g in ($GapDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($gapTotal -gt 0) { [math]::Round(($g.Value / $gapTotal) * 100) } else { 0 }
        $gapRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $g.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($g.Value) ($pct%)</span>
          </div>
"@
    }

    # ── JSON for findings detail drawer ───────────────────────────────────────
    $findingJson = "["
    foreach ($f in $Findings) {
        $findingJson += "{" +
        """name"":""$(EscJ $f.ResourceName)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """type"":""$(EscJ $f.ResourceTypeFriendly)""," +
        """category"":""$(EscJ $f.Category)""," +
        """identity"":""$(EscJ $f.IdentityType)""," +
        """uaCount"":$($f.UserAssignedCount)," +
        """gap"":""$(EscJ $f.GapCategory)""," +
        """risk"":""$(EscJ $f.RiskLevel)""," +
        """detail"":""$(EscJ $f.Detail)""," +
        """rec"":""$(EscJ $f.Recommendation)""," +
        """resId"":""$(EscJ $f.ResourceId)""" +
        "},"
    }
    $findingJson = $findingJson.TrimEnd(",") + "]"

    # ── JSON for Key Vault access table (search/filter, no drawer) ────────────
    $kvJsonLines = "["
    foreach ($k in $KeyVaultFindings) {
        $kvJsonLines += "{" +
        """vault"":""$(EscJ $k.VaultName)""," +
        """sub"":""$(EscJ $k.SubscriptionName)""," +
        """model"":""$(EscJ $k.AuthModel)""," +
        """principal"":""$(EscJ $k.PrincipalName)""," +
        """ptype"":""$(EscJ $k.PrincipalType)""," +
        """expiry"":""$(EscJ $k.CredentialExpiryStatus)""" +
        "},"
    }
    $kvJsonLines = $kvJsonLines.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Workload Identity Dashboard</title>
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
.chart-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:150px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
.cs-banner{display:flex;align-items:center;gap:10px;padding:12px 16px;border-radius:var(--radius-sm);
  font-size:13px;margin-bottom:18px;border:1px solid var(--border);background:var(--surface2);}
.cs-banner.included{border-color:rgba(63,185,80,.35);}
.cs-banner.skipped{border-color:rgba(210,153,34,.35);}
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
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 14px;}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.sub-list{display:flex;flex-direction:column;}
.sub-row{display:flex;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}
.sub-icon.c-amber{color:var(--amber);}
.sub-icon.c-red{color:var(--red);}
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
.drawer-field-value{font-size:13px;word-break:break-word;}
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
  .chart-grid,.chart-grid-3{grid-template-columns:1fr;}
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
    <div class="logo-title">Workload Identity</div>
    <div class="logo-sub">Azure Identity Architecture</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🧩</span> Workload Findings</button>
    <button class="nav-btn" onclick="showPage('keyvault',this)"><span class="nav-icon">🔑</span> Key Vault Access</button>
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
      Azure Workload Identity Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Workload Identity Overview</div>
      <div class="page-sub">Managed Identity adoption across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_FINDINGS__</div>
        <div class="stat-label">Findings</div>
        <div class="stat-sub">__TOTAL_RESOURCES__ resources scanned</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__ADOPTION_PCT__%</div>
        <div class="stat-label">MI Adoption Rate</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Risk</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium Risk</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__NO_MI_COUNT__</div>
        <div class="stat-label">No Managed Identity</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__KV_GAP_COUNT__</div>
        <div class="stat-label">Key Vault SPN Gaps</div>
        <div class="stat-sub">of __TOTAL_KV__ principal grants</div>
      </div>
    </div>

    <div class="cs-banner __CONFIG_BANNER_CLS__">
      <span>🛠️</span>
      <span><strong>Configuration Scan:</strong> __CONFIG_BANNER_TEXT__</span>
    </div>
    <div class="cs-banner __SPN_BANNER_CLS__">
      <span>🪪</span>
      <span><strong>Service Principal Credential Resolution:</strong> __SPN_BANNER_TEXT__</span>
    </div>

    <div class="chart-grid-3">
      <div class="panel">
        <div class="panel-title">🗂️ Category Distribution</div>
        __CAT_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">⚠️ Risk Severity Distribution</div>
        __RISK_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🧩 Gap Category Distribution</div>
        __GAP_ROWS__
      </div>
    </div>
  </div>

  <!-- Workload Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Workload Identity Findings</div>
      <div class="page-sub">Click any row for details and the specific remediation recommendation</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search resource, subscription…" oninput="filterFind()"/>
        </div>
        <select class="filter-select" id="filterRisk" onchange="filterFind()">
          <option value="">All Risk Levels</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>
        <select class="filter-select" id="pgSizeFind" onchange="changeFindPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="findTable">
          <thead>
            <tr>
              <th onclick="sortFind(0)">Resource Name</th>
              <th onclick="sortFind(1)">Subscription</th>
              <th onclick="sortFind(2)">Resource Type</th>
              <th onclick="sortFind(3)">Identity</th>
              <th onclick="sortFind(4)">Gap Category</th>
              <th onclick="sortFind(5)">Risk</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- Key Vault Access -->
  <div id="page-keyvault" class="page">
    <div class="page-header">
      <div class="page-title">Key Vault Access Model</div>
      <div class="page-sub">Principals granted Key Vault access — Application/SPN grants are passwordless gaps</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="kvSearch" placeholder="Search vault, principal…" oninput="filterKv()"/>
        </div>
        <select class="filter-select" id="filterPtype" onchange="filterKv()">
          <option value="">All Principal Types</option>
          <option value="ManagedIdentity">Managed Identity</option>
          <option value="Application">Application (SPN)</option>
          <option value="Unknown">Unknown</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="kvTable">
          <thead>
            <tr>
              <th>Vault</th>
              <th>Subscription</th>
              <th>Auth Model</th>
              <th>Principal</th>
              <th>Principal Type</th>
              <th>Credential Expiry</th>
            </tr>
          </thead>
          <tbody id="kvBody">__KV_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="kvPagination"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription workload identity assessment outcome</div>
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
        <div class="info-card"><div class="info-label">Configuration Scan</div><div class="info-value">__CONFIG_TEXT__</div></div>
        <div class="info-card"><div class="info-label">SPN Credential Resolution</div><div class="info-value">__SPN_TEXT__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
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
const FIND_DATA = __FINDING_JSON__;
let findFiltered = [...FIND_DATA];
let findPage = 1, findPageSz = 25;
let findSortCol = -1, findSortAsc = true;
let currentDetailIdx = 0;

const KV_DATA_RAW = `__KV_JSON_RAW__`;
let KV_DATA = [];
try{ KV_DATA = JSON.parse(KV_DATA_RAW); }catch(e){}
let kvFiltered = [...KV_DATA];
let kvPage = 1, kvPageSz = 25;

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

// ── Findings table ──────────────────────────────────────────────────────────
function filterFind(){
  const q=document.getElementById('findSearch').value.toLowerCase();
  const r=document.getElementById('filterRisk').value;
  findFiltered=FIND_DATA.filter(x=>{
    const mQ=!q||JSON.stringify(x).toLowerCase().includes(q);
    const mR=!r||x.risk===r;
    return mQ&&mR;
  });
  findPage=1; renderFind();
}

function changeFindPageSize(){
  findPageSz=parseInt(document.getElementById('pgSizeFind').value);
  findPage=1; renderFind();
}

function sortFind(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys=['name','sub','type','identity','gap','risk'];
  findFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    return findSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                      :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderFind();
}

function renderFind(){
  const tbody=document.getElementById('findBody');
  const start=(findPage-1)*findPageSz;
  const slice=findFiltered.slice(start,start+findPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=FIND_DATA.indexOf(r);
    const rCls=r.risk==='High'?'badge-red':r.risk==='Medium'?'badge-amber':r.risk==='Low'?'badge-blue':'badge-green';
    const nm=r.name.length>34?r.name.substring(0,31)+'...':r.name;
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td>${escH(r.type)}</td>
      <td>${escH(r.identity)}</td>
      <td>${escH(r.gap)}</td>
      <td><span class="badge ${rCls}">${escH(r.risk)}</span></td>
    </tr>`;
  }).join('');
  renderFindPg();
}

function renderFindPg(){
  const total=Math.ceil(findFiltered.length/findPageSz);
  const el=document.getElementById('findPagination');
  let h=`<span>${findFiltered.length} findings</span>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,findPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeFindPage(p){
  const total=Math.ceil(findFiltered.length/findPageSz);
  if(p<1||p>total)return;
  findPage=p; renderFind();
}

// ── Key Vault table ────────────────────────────────────────────────────────
function filterKv(){
  const q=document.getElementById('kvSearch').value.toLowerCase();
  const p=document.getElementById('filterPtype').value;
  kvFiltered=KV_DATA.filter(x=>{
    const mQ=!q||JSON.stringify(x).toLowerCase().includes(q);
    const mP=!p||x.ptype===p;
    return mQ&&mP;
  });
  kvPage=1; renderKv();
}

function renderKv(){
  const tbody=document.getElementById('kvBody');
  const start=(kvPage-1)*kvPageSz;
  const slice=kvFiltered.slice(start,start+kvPageSz);
  tbody.innerHTML=slice.map(r=>{
    const pCls=r.ptype==='ManagedIdentity'?'badge-green':r.ptype==='Application'?'badge-red':'badge-amber';
    const pn=r.principal.length>28?r.principal.substring(0,25)+'...':r.principal;
    return `<tr>
      <td title="${escH(r.vault)}">${escH(r.vault)}</td>
      <td>${escH(r.sub)}</td>
      <td>${escH(r.model)}</td>
      <td title="${escH(r.principal)}">${escH(pn)}</td>
      <td><span class="badge ${pCls}">${escH(r.ptype)}</span></td>
      <td>${escH(r.expiry)}</td>
    </tr>`;
  }).join('');
  renderKvPg();
}

function renderKvPg(){
  const total=Math.ceil(kvFiltered.length/kvPageSz);
  const el=document.getElementById('kvPagination');
  let h=`<span>${kvFiltered.length} access grants</span>`;
  h+=`<button class="pg-btn" onclick="changeKvPage(${kvPage-1})" ${kvPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,kvPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===kvPage?'active':''}" onclick="changeKvPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeKvPage(${kvPage+1})" ${kvPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeKvPage(p){
  const total=Math.ceil(kvFiltered.length/kvPageSz);
  if(p<1||p>total)return;
  kvPage=p; renderKv();
}

// ── Finding detail drawer ─────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=FIND_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FIND_DATA.length}`;
  const rCls=r.risk==='High'?'badge-red':r.risk==='Medium'?'badge-amber':r.risk==='Low'?'badge-blue':'badge-green';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Risk Level</div>
      <div class="drawer-field-value"><span class="badge ${rCls}">${escH(r.risk)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Type</div>
      <div class="drawer-field-value">${escH(r.type)} <span style="color:var(--muted)">(${escH(r.category)})</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Identity Configuration</div>
      <div class="drawer-field-value">${escH(r.identity)}${r.uaCount>0?` · ${r.uaCount} user-assigned`:''}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Gap Category</div>
      <div class="drawer-field-value">${escH(r.gap)}</div></div>
    <div class="drawer-section">Detail</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.detail)}</div></div>
    <div class="drawer-section">Recommendation</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.rec)}</div></div>
    <div class="drawer-section">Resource ID</div>
    <div class="drawer-field"><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.resId)}</div></div>
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
  if(next>=0&&next<FIND_DATA.length) showFindingDetail(next);
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
filterFind();
filterKv();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_FINDINGS__', $totalFindings `
        -replace '__TOTAL_RESOURCES__', $totalResources `
        -replace '__ADOPTION_PCT__', $adoptionPct `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MEDIUM_COUNT__', $mediumCount `
        -replace '__NO_MI_COUNT__', $noMiCount `
        -replace '__KV_GAP_COUNT__', $kvGapCount `
        -replace '__TOTAL_KV__', $totalKv `
        -replace '__CONFIG_BANNER_CLS__', $(if ($ConfigScanIncluded) { "included" } else { "skipped" }) `
        -replace '__CONFIG_BANNER_TEXT__', $configScanBadgeText `
        -replace '__SPN_BANNER_CLS__', $(if ($SpnCredentialsIncluded) { "included" } else { "skipped" }) `
        -replace '__SPN_BANNER_TEXT__', $spnCredBadgeText `
        -replace '__CAT_ROWS__', $catRows `
        -replace '__RISK_ROWS__', $riskRows `
        -replace '__GAP_ROWS__', $gapRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__KV_ROWS__', $kvRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__CONFIG_TEXT__', $configScanBadgeText `
        -replace '__SPN_TEXT__', $spnCredBadgeText `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FINDING_JSON__', $findingJson `
        -replace '__KV_JSON_RAW__', ($kvJsonLines -replace '`', '``')

    return $html
}


#------------------------------------------------------------------------ [ Assessment Helpers ]

Function Get-IdentityBaselineFinding {
    param(
        [object]$Resource,
        [hashtable]$TypeInfo,
        [object]$Sub
    )

    $identity = Get-ObjProperty -Obj $Resource -PropName 'Identity' -Default $null
    $idType = Get-ObjProperty -Obj $identity -PropName 'Type' -Default $null
    if ([string]::IsNullOrWhiteSpace($idType)) { $idType = "None" }

    $uaCount = 0
    $ua = Get-ObjProperty -Obj $identity -PropName 'UserAssignedIdentities' -Default $null
    if ($ua) {
        try { $uaCount = @($ua.PSObject.Properties).Count } catch { $uaCount = 0 }
    }

    $gapCategory = "Compliant"
    $riskLevel = "Info"
    $detail = "Managed Identity configured ($idType)."
    $recommendation = "No action required. Ensure downstream access (RBAC, Key Vault, storage) is granted to this identity rather than a stored credential."

    if ($idType -eq "None") {
        $gapCategory = "No Managed Identity"
        $riskLevel = "Medium"
        $detail = "No system-assigned or user-assigned Managed Identity is configured on this resource."
        $recommendation = "Enable a Managed Identity (system-assigned for a 1:1 lifecycle, or user-assigned if the identity must be shared/reused) and migrate any credential-based access (connection strings, client secrets, API keys) to identity-based RBAC."
    }

    return [pscustomobject]@{
        SubscriptionName     = $Sub.Name
        SubscriptionId       = $Sub.Id
        ResourceGroup        = (Get-ObjProperty -Obj $Resource -PropName 'ResourceGroupName' -Default "")
        Category             = $TypeInfo.Category
        ResourceTypeFriendly = $TypeInfo.Friendly
        ResourceType         = $TypeInfo.Type
        ResourceName         = (Get-ObjProperty -Obj $Resource -PropName 'Name' -Default "Unknown")
        IdentityType         = $idType
        UserAssignedCount    = $uaCount
        GapCategory          = $gapCategory
        RiskLevel            = $riskLevel
        Detail               = $detail
        Recommendation       = $recommendation
        ResourceId           = (Get-ObjProperty -Obj $Resource -PropName 'ResourceId' -Default "")
    }
}

Function New-Finding {
    param(
        [object]$Baseline,
        [string]$GapCategory,
        [string]$RiskLevel,
        [string]$Detail,
        [string]$Recommendation
    )
    $f = $Baseline.PSObject.Copy()
    $f.GapCategory = $GapCategory
    $f.RiskLevel = $RiskLevel
    $f.Detail = $Detail
    $f.Recommendation = $Recommendation
    return $f
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureWorkloadIdentityAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$IncludeConfigurationScan,

        [switch]$IncludeServicePrincipalCredentials,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureWorkloadIdentity-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.KeyVault")
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

    # ── Display session / params ──────────────────────────────────────────────
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"                  = "$scopeText ($subCount found)"
        "Configuration Scan"     = if ($IncludeConfigurationScan) { "Enabled (App Settings will be read)" } else { "Skipped (use -IncludeConfigurationScan to enable)" }
        "SPN Credential Resolve" = if ($IncludeServicePrincipalCredentials) { "Enabled (Entra directory reads)" } else { "Skipped (use -IncludeServicePrincipalCredentials to enable)" }
        "Export to CSV"          = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"            = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $allKeyVaultFindings = @()
    $subscriptionResults = @()
    $categoryDist = @{ "Compute" = 0; "Integration" = 0; "Platform" = 0 }
    $riskDist = @{ "High" = 0; "Medium" = 0; "Low" = 0; "Info" = 0 }
    $gapDist = @{}
    $successCount = 0
    $errorCount = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = ([math]::Max(
            ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
            35
        ))

    $subIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $subFindingCount = 0

            # ── Workload resource scan ────────────────────────────────────────
            foreach ($typeInfo in $script:WorkloadResourceTypes) {
                $resources = @()
                try {
                    $resources = @(Get-AzResource -ResourceType $typeInfo.Type -ExpandProperties -ErrorAction Stop)
                }
                catch {
                    Write-Verbose "  Could not enumerate $($typeInfo.Type) in $($sub.Name): $_"
                    continue
                }

                foreach ($res in $resources) {
                    $baseline = Get-IdentityBaselineFinding -Resource $res -TypeInfo $typeInfo -Sub $sub
                    $allFindings += $baseline
                    $subFindingCount++
                    $categoryDist[$typeInfo.Category] = $categoryDist[$typeInfo.Category] + 1

                    # ── Resource-specific secondary checks ──────────────────────────

                    # Container Registry — admin user (static credential) enabled
                    if ($typeInfo.Type -eq "Microsoft.ContainerRegistry/registries") {
                        $props = Get-ObjProperty -Obj $res -PropName 'Properties' -Default $null
                        $adminEnabled = Get-ObjProperty -Obj $props -PropName 'adminUserEnabled' -Default $false
                        if ($adminEnabled) {
                            $allFindings += New-Finding -Baseline $baseline `
                                -GapCategory "Admin User Enabled" -RiskLevel "Medium" `
                                -Detail "Registry admin user (static username/password credential) is enabled." `
                                -Recommendation "Disable the admin user and use Managed Identity + AcrPull/AcrPush RBAC for registry authentication."
                        }
                    }

                    # App Configuration — local authentication (access keys) enabled
                    if ($typeInfo.Type -eq "Microsoft.AppConfiguration/configurationStores") {
                        $props = Get-ObjProperty -Obj $res -PropName 'Properties' -Default $null
                        $disableLocalAuth = Get-ObjProperty -Obj $props -PropName 'disableLocalAuth' -Default $false
                        if (-not $disableLocalAuth) {
                            $allFindings += New-Finding -Baseline $baseline `
                                -GapCategory "Local Authentication Enabled" -RiskLevel "Medium" `
                                -Detail "Access-key based (local) authentication is still enabled on this App Configuration store." `
                                -Recommendation "Set disableLocalAuth to true and require Entra ID / Managed Identity-based access via RBAC (App Configuration Data Reader/Owner)."
                        }
                    }

                    # Automation Account — legacy Run As connection (certificate-based SPN)
                    if ($typeInfo.Type -eq "Microsoft.Automation/automationAccounts") {
                        try {
                            $runAsConn = Get-AzAutomationConnection -ResourceGroupName $baseline.ResourceGroup `
                                -AutomationAccountName $baseline.ResourceName -Name "AzureRunAsConnection" -ErrorAction Stop
                            if ($runAsConn) {
                                $allFindings += New-Finding -Baseline $baseline `
                                    -GapCategory "Legacy Run As Account" -RiskLevel "High" `
                                    -Detail "A legacy 'AzureRunAsConnection' (certificate-based Service Principal) is still configured. Run As accounts were deprecated by Microsoft in September 2023." `
                                    -Recommendation "Migrate all runbooks to the Automation Account's Managed Identity and remove the legacy Run As connection and its associated App Registration/certificate."
                            }
                        }
                        catch {
                            Write-Verbose "  No legacy Run As connection on $($baseline.ResourceName) (or insufficient permission): $_"
                        }
                    }

                    # App Service / Function App — application settings configuration scan (opt-in)
                    if ($typeInfo.Type -eq "Microsoft.Web/sites" -and $IncludeConfigurationScan) {
                        try {
                            $webApp = Get-AzWebApp -ResourceGroupName $baseline.ResourceGroup -Name $baseline.ResourceName -ErrorAction Stop
                            $appSettingNames = @()
                            if ($webApp.SiteConfig -and $webApp.SiteConfig.AppSettings) {
                                $appSettingNames = @($webApp.SiteConfig.AppSettings | ForEach-Object { $_.Name })
                            }
                            $matched = @($appSettingNames | Where-Object {
                                    $settingName = $_
                                    ($script:CredentialPatterns | Where-Object { $settingName -like "*$_*" }).Count -gt 0
                                })
                            if ($matched.Count -gt 0) {
                                $allFindings += New-Finding -Baseline $baseline `
                                    -GapCategory "Key-Based Configuration Detected" -RiskLevel "Medium" `
                                    -Detail "Application setting name(s) suggest credential-based configuration is present: $($matched -join ', ')." `
                                    -Recommendation "Review whether these settings can be replaced with Managed Identity-based access (e.g. DefaultAzureCredential, identity-based connection strings) instead of embedded keys/connection strings."
                            }
                        }
                        catch {
                            $allFindings += New-Finding -Baseline $baseline `
                                -GapCategory "Configuration Scan Not Assessed" -RiskLevel "Low" `
                                -Detail "Not Assessed / Warning: could not read application settings ($($_.Exception.Message))." `
                                -Recommendation "Grant Website Contributor (or equivalent list-config permission) to enable the configuration scan for this resource."
                        }
                    }
                }
            }

            # ── Key Vault access model ────────────────────────────────────────
            $vaults = @()
            try {
                $vaults = @(Get-AzKeyVault -ErrorAction Stop)
            }
            catch {
                Write-Verbose "  Could not enumerate Key Vaults in $($sub.Name): $_"
            }

            foreach ($vault in $vaults) {
                try {
                    $vaultDetail = Get-AzKeyVault -VaultName $vault.VaultName -ResourceGroupName $vault.ResourceGroupName -ErrorAction Stop
                }
                catch {
                    Write-Verbose "  Could not retrieve detail for vault $($vault.VaultName): $_"
                    continue
                }

                $rbacEnabled = Get-ObjProperty -Obj $vaultDetail -PropName 'EnableRbacAuthorization' -Default $false
                $authModel = if ($rbacEnabled) { "RBAC" } else { "Access Policy" }
                $principalsToEvaluate = @()

                if ($rbacEnabled) {
                    try {
                        $roleAssignments = @(Get-AzRoleAssignment -Scope $vaultDetail.ResourceId -ErrorAction Stop |
                            Where-Object { $_.RoleDefinitionName -like "*Key Vault*" -and $_.ObjectType -eq "ServicePrincipal" })
                        foreach ($ra in $roleAssignments) {
                            $principalsToEvaluate += @{ ObjectId = $ra.ObjectId; Permissions = $ra.RoleDefinitionName }
                        }
                    }
                    catch {
                        Write-Verbose "  Could not read RBAC role assignments for vault $($vault.VaultName): $_"
                    }
                }
                else {
                    $policies = Get-ObjProperty -Obj $vaultDetail -PropName 'AccessPolicies' -Default @()
                    foreach ($p in $policies) {
                        $permSummary = @()
                        if ($p.PermissionsToSecrets) { $permSummary += "Secrets:$($p.PermissionsToSecrets -join '/')" }
                        if ($p.PermissionsToKeys) { $permSummary += "Keys:$($p.PermissionsToKeys -join '/')" }
                        if ($p.PermissionsToCertificates) { $permSummary += "Certs:$($p.PermissionsToCertificates -join '/')" }
                        $principalsToEvaluate += @{ ObjectId = $p.ObjectId; Permissions = ($permSummary -join '; ') }
                    }
                }

                foreach ($p in $principalsToEvaluate) {
                    if ([string]::IsNullOrWhiteSpace($p.ObjectId)) { continue }

                    $spn = $null
                    try { $spn = Get-AzADServicePrincipal -ObjectId $p.ObjectId -ErrorAction Stop } catch { $spn = $null }

                    if (-not $spn) {
                        # Not a Service Principal (likely a user or group) — out of scope for workload identity gaps
                        continue
                    }

                    $spType = Get-ObjProperty -Obj $spn -PropName 'ServicePrincipalType' -Default "Unknown"
                    if ([string]::IsNullOrWhiteSpace($spType)) { $spType = "Unknown" }

                    $principalType = switch ($spType) {
                        "ManagedIdentity" { "ManagedIdentity" }
                        "Application" { "Application" }
                        default { "Unknown" }
                    }

                    $gapCategory = switch ($principalType) {
                        "ManagedIdentity" { "Compliant" }
                        "Application" { "Key Vault Access via Application SPN" }
                        default { "Principal Type Not Confirmed" }
                    }
                    $riskLevel = switch ($principalType) {
                        "ManagedIdentity" { "Info" }
                        "Application" { "High" }
                        default { "Low" }
                    }

                    $credExpiryStatus = "Not Assessed"
                    $credExpiryDate = "N/A"

                    if ($principalType -eq "Application" -and $IncludeServicePrincipalCredentials) {
                        try {
                            $appId = Get-ObjProperty -Obj $spn -PropName 'AppId' -Default $null
                            $creds = @(Get-AzADAppCredential -ApplicationId $appId -ErrorAction Stop)
                            $nextExpiry = $creds | Where-Object { $_.EndDateTime } | Sort-Object EndDateTime | Select-Object -First 1
                            if ($nextExpiry) {
                                $classification = Get-ExpiryClassification -ExpiresOn ([datetime]$nextExpiry.EndDateTime)
                                $credExpiryStatus = $classification.Status
                                $credExpiryDate = $classification.Date
                            }
                            else {
                                $credExpiryStatus = "No Expiry Set"
                            }
                        }
                        catch {
                            $credExpiryStatus = "Not Assessed / Warning"
                            Write-Verbose "  Could not resolve credential expiry for SPN $($spn.DisplayName): $_"
                        }
                    }
                    elseif ($principalType -ne "Application") {
                        $credExpiryStatus = "N/A"
                    }

                    $allKeyVaultFindings += [pscustomobject]@{
                        SubscriptionName       = $sub.Name
                        SubscriptionId         = $sub.Id
                        ResourceGroup          = $vault.ResourceGroupName
                        VaultName              = $vault.VaultName
                        AuthModel              = $authModel
                        PrincipalName          = (Get-ObjProperty -Obj $spn -PropName 'DisplayName' -Default "Unknown")
                        PrincipalType          = $principalType
                        GapCategory            = $gapCategory
                        RiskLevel              = $riskLevel
                        Permissions            = $p.Permissions
                        CredentialExpiryStatus = $credExpiryStatus
                        CredentialExpiryDate   = $credExpiryDate
                    }
                }
            }

            # ── Roll up distributions ──────────────────────────────────────────
            $subScopedFindings = @($allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id })
            foreach ($f in $subScopedFindings) {
                $riskDist[$f.RiskLevel] = ($riskDist[$f.RiskLevel] + 1)
                if (-not $gapDist.ContainsKey($f.GapCategory)) { $gapDist[$f.GapCategory] = 0 }
                $gapDist[$f.GapCategory] = $gapDist[$f.GapCategory] + 1
            }

            # ── Per-subscription result ───────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            $subVaultFindings = @($allKeyVaultFindings | Where-Object { $_.SubscriptionId -eq $sub.Id })

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Resources: $subFindingCount  KeyVault Grants: $($subVaultFindings.Count)" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Resources: $subFindingCount  KeyVault Grants: $($subVaultFindings.Count)"
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

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Total Findings"              = $allFindings.Count
            "Total Key Vault Grants"      = $allKeyVaultFindings.Count
            "Configuration Scan"          = if ($IncludeConfigurationScan) { "Yes" } else { "No (use -IncludeConfigurationScan)" }
            "SPN Credential Resolution"   = if ($IncludeServicePrincipalCredentials) { "Yes" } else { "No (use -IncludeServicePrincipalCredentials)" }
            "Execution Time"              = $duration
        })

    Write-RiskBreakdown    -Risk $riskDist
    Write-KeyVaultSummary  -KeyVaultFindings $allKeyVaultFindings

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""
    $kvCsvPath = ""

    if ($allFindings.Count -gt 0 -or $allKeyVaultFindings.Count -gt 0) {
        # CSV — findings + Key Vault access as two files
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $csvRows = $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, ResourceGroup, Category, ResourceTypeFriendly,
                ResourceName, IdentityType, UserAssignedCount, GapCategory, RiskLevel, Detail, Recommendation, ResourceId

                $csvRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                if ($allKeyVaultFindings.Count -gt 0) {
                    $kvCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "KeyVaultAccess.csv"
                    $allKeyVaultFindings | Export-Csv -Path $kvCsvPath -NoTypeInformation -Encoding UTF8
                }

                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML dashboard
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

            $htmlContent = Generate-WorkloadIdentityHtml `
                -SessionInfo             $sessionInfo `
                -ScanParameters          $scanParams `
                -Findings                $allFindings `
                -KeyVaultFindings        $allKeyVaultFindings `
                -CategoryDistribution    $categoryDist `
                -RiskDistribution        $riskDist `
                -GapDistribution         $gapDist `
                -SubscriptionResults     $subscriptionResults `
                -GeneratedOn             (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -ConfigScanIncluded      $IncludeConfigurationScan.IsPresent `
                -SpnCredentialsIncluded  $IncludeServicePrincipalCredentials.IsPresent

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        # Grid View
        try {
            $allFindings |
            Select-Object SubscriptionName, ResourceName, ResourceTypeFriendly, IdentityType, GapCategory, RiskLevel |
            Out-GridView -Title "Azure Workload Identity Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No in-scope workload resources or Key Vaults found in the targeted subscriptions." -ForegroundColor Yellow
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        $outCsv = if ($csvExported) { $CsvPath } else { $null }
        $outKvCsv = if ($csvExported -and $kvCsvPath) { $kvCsvPath } else { $null }
        $outHtml = if ($htmlExported) { $htmlPath } else { $null }
        Write-OutputFiles -CsvPath $outCsv -KvCsvPath $outKvCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
