<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 14 August 2025
Modified-On     : 14 August 2025

.SYNOPSIS
    Assesses the security configuration of Azure Key Vaults across one or more
    subscriptions and produces a weighted risk-rated report in CSV and HTML formats.

.DESCRIPTION
    The Get-AzureKeyVaultSecurityAssessment function inventories every Azure Key Vault
    visible to the authenticated account and evaluates eight security controls aligned
    to the CIS Azure Benchmark v2.0 and Microsoft Defender for Cloud recommendations.

    Each control carries a weight that reflects its real-world blast-radius:

        Control                                          Weight
        ───────────────────────────────────────────────  ──────
        Public network access enabled (no firewall)         3
        No private endpoint configured                      2
        Purge protection disabled                           3
        Soft delete disabled or retention < 7 days          2
        Using access policies instead of RBAC               2
        No diagnostic logging configured                    2
        No firewall rules (when public access is on)        1
        No managed-identity RBAC assignment on vault        1

    Overall risk rating is derived from the total weight of all failed controls:
        Critical  :  9 – 16
        High      :  5 –  8
        Medium    :  2 –  4
        Low       :  0 –  1

    The function supports:
        - Scanning all subscriptions in the tenant, or a specified list of IDs
        - Real-time progress tracking with a live progress bar and color-coded
          console status per subscription
        - Per-vault finding rows with individual control pass/fail columns
        - Optional CSV export of all vault findings
        - Always-on self-contained HTML report with Azure dark-theme design,
          summarizing session info, scan parameters, statistics, risk distribution,
          top-risk vaults, and subscription results
        - Interactive Grid View display of results (where a GUI is available)

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account/context.
    This is also the default behavior if -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan, instead of all
    subscriptions. Ignored if -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all vault findings to the path given in -CsvPath.
    An HTML report is generated regardless of whether this switch is used.

.PARAMETER CsvPath
    Path where the CSV export will be written if -ExportToCsv is specified. Also
    used to derive the HTML report file name (same path, .html extension).
    Default: C:\Temp\AzureKeyVaultSecurityAssessment-Report.csv

.INPUTS
    None. All input is supplied via parameters.

.OUTPUTS
    None directly to the pipeline. Always writes a self-contained HTML report
    alongside -CsvPath (or the default path). Optionally writes a CSV file if
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureKeyVaultSecurityAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureKeyVaultSecurityAssessment -SubscriptionIds @("sub-id-1", "sub-id-2")

.EXAMPLE
    Get-AzureKeyVaultSecurityAssessment -AllSubscriptions -ExportToCsv

.EXAMPLE
    Get-AzureKeyVaultSecurityAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Audits\KV-Report.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (14-Aug-2025)   - Initial release. Assesses RBAC mode, public network
                              access, firewall rules, private endpoints, purge
                              protection, soft delete, diagnostic logging, and
                              managed identity RBAC coverage. Weighted risk scoring
                              aligned to CIS Azure Benchmark v2.0 and Defender for
                              Cloud. CSV + self-contained HTML report output.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az.KeyVault module (Az.KeyVault 4.x+) — installed automatically on consent
        2. Az.Monitor module — required for Get-AzDiagnosticSetting
        3. Az.Accounts module — required for context and subscription resolution
        4. Authenticated Azure account with at minimum:
               Microsoft.KeyVault/vaults/read
               Microsoft.KeyVault/vaults/privateEndpointConnections/read
               microsoft.insights/diagnosticSettings/read
               Microsoft.Authorization/roleAssignments/read
           at the subscription level for each subscription scanned

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Interactive Grid View requires a GUI-capable PowerShell session (ISE or
          Microsoft.PowerShell.GraphicalTools on PS7). Skipped gracefully in
          headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. On macOS/Linux
          PowerShell 7, supply an explicit -CsvPath.
        - Diagnostic setting evaluation checks for at least one enabled log
          category; it does not validate which specific log categories are active.
        - Managed identity RBAC check counts ServicePrincipal assignments scoped
          to the vault resource path. It does not resolve whether the principal is
          a managed identity vs. a regular service principal.
        - If neither -AllSubscriptions nor -SubscriptionIds is supplied, the
          function defaults to scanning ALL subscriptions with no confirmation prompt.

.LINK
    https://learn.microsoft.com/en-us/azure/key-vault/general/security-features
    https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
    https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/key-vault-security-baseline

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-KvCenteredText {
    param(
        [string]$Text,
        [int]$Width = 80,
        [string]$Color = "White"
    )
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-KvBanner {
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-KvCenteredText "Azure Key Vault Security Assessment v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-KvSection {
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

Function Write-KvScanProgress {
    Write-Host ""
    Write-Host "  Scanning Subscriptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
}

Function Write-KvProgressBar {
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

Function Write-KvSummary {
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

Function Write-KvRiskDistribution {
    param(
        [hashtable]$RiskData,
        [int]$TotalVaults
    )

    if ($TotalVaults -eq 0) { return }

    Write-Host ""
    Write-Host "  Risk Rating Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $riskOrder = @("Critical", "High", "Medium", "Low")
    $riskColors = @{
        Critical = "Red"
        High     = "DarkYellow"
        Medium   = "Yellow"
        Low      = "Green"
    }

    foreach ($rating in $riskOrder) {
        $count = if ($RiskData.ContainsKey($rating)) { $RiskData[$rating] } else { 0 }
        $percent = [math]::Round(($count / $TotalVaults) * 100)
        $color = $riskColors[$rating]

        Write-Host "  " -NoNewline
        Write-Host $rating.PadRight(12) -NoNewline -ForegroundColor $color
        Write-Host ": $count vaults ($percent%)" -ForegroundColor White
    }
}

Function Write-KvTopRiskyVaults {
    param([array]$Vaults)

    if ($Vaults.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Top 5 Highest Risk Vaults" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $counter = 1
    foreach ($vault in ($Vaults | Sort-Object RiskScore -Descending | Select-Object -First 5)) {
        Write-Host "  " -NoNewline
        Write-Host "$counter. " -NoNewline -ForegroundColor Gray
        Write-Host $vault.VaultName.PadRight(36) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($vault.OverallRisk) (score: $($vault.RiskScore))" -ForegroundColor Cyan
        $counter++
    }
}

Function Write-KvTopFailedControls {
    param([hashtable]$ControlFailCounts)

    if ($ControlFailCounts.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Top Failed Controls" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $counter = 1
    foreach ($ctrl in ($ControlFailCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
        Write-Host "  " -NoNewline
        Write-Host "$counter. " -NoNewline -ForegroundColor Gray
        Write-Host $ctrl.Key.PadRight(46) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($ctrl.Value) vault(s) failing" -ForegroundColor Cyan
        $counter++
    }
}

Function Write-KvOutputFiles {
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


#------------------------------------------------------------------------ [ Risk Scoring Engine ]

# Control definitions — each entry carries a display name, weight, and the property
# on the findings object that holds the boolean fail result.
# Adding a new control in future: append an entry here and populate the matching
# property in the findings [pscustomobject] block inside the main scan loop.

$Script:KvControls = @(
    @{ Name = "Public Network Access (no firewall)"; Weight = 3; FailProperty = "PublicAccessNoFirewall" },
    @{ Name = "No Private Endpoint configured"; Weight = 2; FailProperty = "NoPrivateEndpoint" },
    @{ Name = "Purge Protection disabled"; Weight = 3; FailProperty = "PurgeProtectionDisabled" },
    @{ Name = "Soft Delete disabled / < 7 days"; Weight = 2; FailProperty = "SoftDeleteWeak" },
    @{ Name = "Access Policies (not RBAC)"; Weight = 2; FailProperty = "AccessPolicyMode" },
    @{ Name = "No Diagnostic Logging"; Weight = 2; FailProperty = "NoDiagnostics" },
    @{ Name = "No Firewall Rules (public on)"; Weight = 1; FailProperty = "NoFirewallRules" },
    @{ Name = "No Managed Identity RBAC"; Weight = 1; FailProperty = "NoManagedIdentityRbac" }
)

Function Get-KvRiskRating {
    param([int]$Score)

    if ($Score -ge 9) { return "Critical" }
    if ($Score -ge 5) { return "High" }
    if ($Score -ge 2) { return "Medium" }
    return "Low"
}

Function Get-KvRiskScore {
    param([pscustomobject]$Finding)

    $totalScore = 0

    foreach ($control in $Script:KvControls) {
        $failValue = $Finding.($control.FailProperty)
        if ($failValue -eq $true) {
            $totalScore += $control.Weight
        }
    }

    return $totalScore
}


#------------------------------------------------------------------------ [ HTML Report Generator ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-KvHtmlReport {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [hashtable]$ScanSummary,
        [array]$SubscriptionResults,
        [array]$AllFindings,
        [hashtable]$RiskDistribution,
        [hashtable]$ControlFailCounts,
        [int]$TotalVaults,
        [string]$CsvPath,
        [string]$HtmlPath,
        [bool]$GridViewOpened
    )

    $generatedOn = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    $riskOrder = @("Critical", "High", "Medium", "Low")
    $riskBadgeCls = @{ Critical = "badge-red"; High = "badge-amber"; Medium = "badge-purple"; Low = "badge-green" }
    $riskBarColor = @{ Critical = "var(--red)"; High = "var(--amber)"; Medium = "var(--accent3)"; Low = "var(--green)" }

    $criticalCount = if ($RiskDistribution.ContainsKey('Critical')) { $RiskDistribution['Critical'] } else { 0 }
    $highCount = if ($RiskDistribution.ContainsKey('High')) { $RiskDistribution['High'] } else { 0 }
    $mediumCount = if ($RiskDistribution.ContainsKey('Medium')) { $RiskDistribution['Medium'] } else { 0 }
    $lowCount = if ($RiskDistribution.ContainsKey('Low')) { $RiskDistribution['Low'] } else { 0 }

    # ── Risk distribution bar rows (reused on Overview + Risk & Controls tabs) ────
    $riskRows = ""
    foreach ($rating in $riskOrder) {
        $count = if ($RiskDistribution.ContainsKey($rating)) { $RiskDistribution[$rating] } else { 0 }
        $pct = if ($TotalVaults -gt 0) { [math]::Round(($count / $TotalVaults) * 100) } else { 0 }
        $riskRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $rating)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$($riskBarColor[$rating])"></div></div>
            <span class="bar-pct">$count ($pct%)</span>
          </div>
"@
    }

    # ── Control fail-count bar rows (full list — 8 controls) ──────────────────────
    $controlTotal = $TotalVaults
    $controlRowsFull = ""
    $controlRowsTop = ""
    $ctrlCounter = 0
    foreach ($ctrl in ($ControlFailCounts.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($controlTotal -gt 0) { [math]::Round(($ctrl.Value / $controlTotal) * 100) } else { 0 }
        $row = @"
          <div class="bar-row">
            <span class="bar-label" title="$(EscHtml $ctrl.Key)">$(EscHtml $ctrl.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($ctrl.Value) ($pct%)</span>
          </div>
"@
        $controlRowsFull += $row
        if ($ctrlCounter -lt 5) { $controlRowsTop += $row }
        $ctrlCounter++
    }

    # ── Top 5 riskiest vaults (reuses sub-row markup) ──────────────────────────────
    $topVaultsHtml = ""
    foreach ($v in ($AllFindings | Sort-Object RiskScore -Descending | Select-Object -First 5)) {
        $cls = switch ($v.OverallRisk) { "Critical" { "c-red" }; "High" { "c-amber" }; "Medium" { "c-purple" }; "Low" { "c-green" }; default { "" } }
        $icon = switch ($v.OverallRisk) { "Critical" { "🔴" }; "High" { "🟠" }; "Medium" { "🟣" }; "Low" { "🟢" }; default { "•" } }
        $topVaultsHtml += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $v.VaultName)</span>
            <span class="sub-detail">$(EscHtml $v.OverallRisk) — Score $($v.RiskScore) · $(EscHtml $v.SubscriptionName)</span>
          </div>
"@
    }

    # ── Vault findings table rows ───────────────────────────────────────────────────
    $findingRows = ""
    $findingsSorted = @($AllFindings | Sort-Object RiskScore -Descending)
    foreach ($f in $findingsSorted) {
        $idx = $findingsSorted.IndexOf($f)
        $failedCount = @($Script:KvControls | Where-Object { $f.($_.FailProperty) -eq $true }).Count
        $paBadge = if ($f.PublicNetworkAccess -eq "Enabled") { '<span class="badge badge-amber">Enabled</span>' } else { '<span class="badge badge-green">Disabled</span>' }
        $rbacBadge = if ($f.RBACEnabled) { '<span class="badge badge-green">RBAC</span>' } else { '<span class="badge badge-amber">Access Policy</span>' }
        $findingRows += @"
          <tr onclick="showVaultDetail($idx)">
            <td title="$(EscHtml $f.VaultName)">$(if ($f.VaultName.Length -gt 32) { EscHtml($f.VaultName.Substring(0,29)+"...") } else { EscHtml $f.VaultName })</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td><span class="badge $($riskBadgeCls[$f.OverallRisk])">$(EscHtml $f.OverallRisk)</span></td>
            <td style="text-align:center;font-family:var(--mono)">$($f.RiskScore)</td>
            <td>$paBadge</td>
            <td>$rbacBadge</td>
            <td style="text-align:center;font-family:var(--mono)">$failedCount / 8</td>
          </tr>
"@
    }

    # ── JSON for vault findings (table + detail drawer) ────────────────────────────
    $findingsJson = "["
    foreach ($f in $findingsSorted) {
        $controlsJson = "["
        foreach ($c in $Script:KvControls) {
            $fail = if ($f.($c.FailProperty) -eq $true) { "true" } else { "false" }
            $controlsJson += "{""n"":""$(EscJ $c.Name)"",""f"":$fail},"
        }
        $controlsJson = $controlsJson.TrimEnd(",") + "]"

        $softDelText = if ($f.SoftDeleteEnabled) { "Enabled ($($f.SoftDeleteRetentionDays) days retention)" } else { "Disabled" }

        $findingsJson += "{" +
        """name"":""$(EscJ $f.VaultName)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """sku"":""$(EscJ $f.SKU)""," +
        """loc"":""$(EscJ $f.Location)""," +
        """risk"":""$(EscJ $f.OverallRisk)""," +
        """score"":$($f.RiskScore)," +
        """pubAccess"":""$(EscJ $f.PublicNetworkAccess)""," +
        """fwCount"":$($f.FirewallRulesCount)," +
        """peCount"":$($f.PrivateEndpointCount)," +
        """purgeProt"":""$(if ($f.PurgeProtectionEnabled) { 'Enabled' } else { 'Disabled' })""," +
        """softDel"":""$(EscJ $softDelText)""," +
        """rbac"":""$(if ($f.RBACEnabled) { 'RBAC' } else { 'Access Policies' })""," +
        """diag"":""$(if ($f.DiagnosticsEnabled) { 'Enabled' } else { 'Disabled' })""," +
        """miRbac"":$($f.ManagedIdentityRbacCount)," +
        """controls"":$controlsJson" +
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
<title>Azure Key Vault Security Assessment</title>
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
.ctrl-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:6px 0;border-bottom:1px solid var(--border);font-size:12px;}
.ctrl-row:last-child{border-bottom:none;}
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
    <div class="logo-icon">🔐</div>
    <div class="logo-title">Key Vault Security</div>
    <div class="logo-sub">Azure Key Vault Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔑</span> Vault Findings</button>
    <button class="nav-btn" onclick="showPage('controls',this)"><span class="nav-icon">🎯</span> Risk & Controls</button>
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
      Azure Key Vault Security Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Key Vault Security Overview</div>
      <div class="page-sub">Vault security posture across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_VAULTS__</div>
        <div class="stat-label">Vaults Assessed</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical Risk</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Risk</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium Risk</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low Risk</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__SUB_COUNT__</div>
        <div class="stat-label">Subscriptions</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Risk Rating Distribution</div>
        __RISK_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">⚠️ Most Frequently Failed Controls</div>
        __CONTROL_ROWS_TOP__
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">🔴 Top 5 Highest Risk Vaults</div>
      <div class="sub-list">__TOP_VAULTS__</div>
    </div>
  </div>

  <!-- Vault Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Vault Findings</div>
      <div class="page-sub">Click any row for the full control breakdown. Sorted by risk score, highest first.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="vaultSearch" placeholder="Search vault, subscription…" oninput="filterVaults()"/>
        </div>
        <select class="filter-select" id="filterRisk" onchange="filterVaults()">
          <option value="">All Risk Ratings</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="pgSizeVault" onchange="changeVaultPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="vaultTable">
          <thead>
            <tr>
              <th onclick="sortVaults(0)">Vault Name</th>
              <th onclick="sortVaults(1)">Subscription</th>
              <th onclick="sortVaults(2)">Risk Rating</th>
              <th onclick="sortVaults(3)">Score</th>
              <th onclick="sortVaults(4)">Public Access</th>
              <th onclick="sortVaults(5)">Access Model</th>
              <th onclick="sortVaults(6)">Failed Controls</th>
            </tr>
          </thead>
          <tbody id="vaultBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="vaultPagination"></div>
    </div>
  </div>

  <!-- Risk & Controls -->
  <div id="page-controls" class="page">
    <div class="page-header">
      <div class="page-title">Risk & Control Analysis</div>
      <div class="page-sub">Full distribution of risk ratings and every control's fail rate across all assessed vaults</div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Risk Rating Distribution</div>
        __RISK_ROWS_2__
      </div>
      <div class="panel">
        <div class="panel-title">🛡️ Control Fail Counts (all 8)</div>
        __CONTROL_ROWS_FULL__
      </div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription vault assessment outcome</div>
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
    <span class="drawer-title" id="drawerTitle">Vault Detail</span>
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
const VAULT_DATA = __FINDINGS_JSON__;
let vaultFiltered = [...VAULT_DATA];
let vaultPage = 1, vaultPageSz = 25;
let vaultSortCol = -1, vaultSortAsc = true;
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

// ── Vault findings table ────────────────────────────────────────────────────────
const riskBadgeCls = {Critical:'badge-red',High:'badge-amber',Medium:'badge-purple',Low:'badge-green'};

function filterVaults(){
  const q=document.getElementById('vaultSearch').value.toLowerCase();
  const r=document.getElementById('filterRisk').value;
  vaultFiltered=VAULT_DATA.filter(v=>{
    const mQ=!q||JSON.stringify(v).toLowerCase().includes(q);
    const mR=!r||v.risk===r;
    return mQ&&mR;
  });
  vaultPage=1; renderVaults();
}

function changeVaultPageSize(){
  vaultPageSz=parseInt(document.getElementById('pgSizeVault').value);
  vaultPage=1; renderVaults();
}

function sortVaults(col){
  if(vaultSortCol===col){vaultSortAsc=!vaultSortAsc;}else{vaultSortCol=col;vaultSortAsc=true;}
  const keys=['name','sub','risk','score','pubAccess','rbac','failedCount'];
  vaultFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=k==='failedCount'?a.controls.filter(c=>c.f).length:(a[k]??'');
    const bv=k==='failedCount'?b.controls.filter(c=>c.f).length:(b[k]??'');
    return vaultSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                       :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderVaults();
}

function renderVaults(){
  const tbody=document.getElementById('vaultBody');
  const start=(vaultPage-1)*vaultPageSz;
  const slice=vaultFiltered.slice(start,start+vaultPageSz);
  tbody.innerHTML=slice.map(v=>{
    const gi=VAULT_DATA.indexOf(v);
    const nm=v.name.length>32?v.name.substring(0,29)+'...':v.name;
    const failedCount=v.controls.filter(c=>c.f).length;
    const paBadge=v.pubAccess==='Enabled'?'<span class="badge badge-amber">Enabled</span>':'<span class="badge badge-green">Disabled</span>';
    const rbacBadge=v.rbac==='RBAC'?'<span class="badge badge-green">RBAC</span>':'<span class="badge badge-amber">Access Policy</span>';
    return `<tr onclick="showVaultDetail(${gi})">
      <td title="${escH(v.name)}">${escH(nm)}</td>
      <td>${escH(v.sub)}</td>
      <td><span class="badge ${riskBadgeCls[v.risk]||''}">${escH(v.risk)}</span></td>
      <td style="text-align:center;font-family:var(--mono)">${v.score}</td>
      <td>${paBadge}</td>
      <td>${rbacBadge}</td>
      <td style="text-align:center;font-family:var(--mono)">${failedCount} / 8</td>
    </tr>`;
  }).join('');
  renderVaultPg();
}

function renderVaultPg(){
  const total=Math.ceil(vaultFiltered.length/vaultPageSz);
  const el=document.getElementById('vaultPagination');
  let h=`<span>${vaultFiltered.length} vaults</span>`;
  h+=`<button class="pg-btn" onclick="changeVaultPage(${vaultPage-1})" ${vaultPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,vaultPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===vaultPage?'active':''}" onclick="changeVaultPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeVaultPage(${vaultPage+1})" ${vaultPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeVaultPage(p){
  const total=Math.ceil(vaultFiltered.length/vaultPageSz);
  if(p<1||p>total)return;
  vaultPage=p; renderVaults();
}

// ── Vault detail drawer ─────────────────────────────────────────────────────────
function showVaultDetail(idx){
  currentDetailIdx=idx;
  const v=VAULT_DATA[idx];
  if(!v)return;
  document.getElementById('drawerTitle').textContent=v.name;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${VAULT_DATA.length}`;
  const ctrlRows=v.controls.map(c=>`
    <div class="ctrl-row">
      <span>${escH(c.n)}</span>
      <span class="badge ${c.f?'badge-red':'badge-green'}">${c.f?'FAIL':'PASS'}</span>
    </div>`).join('');
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Risk Rating</div>
      <div class="drawer-field-value"><span class="badge ${riskBadgeCls[v.risk]||''}">${escH(v.risk)}</span> — Score ${v.score}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(v.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(v.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Location / SKU</div>
      <div class="drawer-field-value">${escH(v.loc)} · ${escH(v.sku)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Public Network Access</div>
      <div class="drawer-field-value">${escH(v.pubAccess)} (${v.fwCount} firewall rule(s), ${v.peCount} private endpoint(s))</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Access Model</div>
      <div class="drawer-field-value">${escH(v.rbac)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Purge Protection / Soft Delete</div>
      <div class="drawer-field-value">${escH(v.purgeProt)} / ${escH(v.softDel)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Diagnostic Logging</div>
      <div class="drawer-field-value">${escH(v.diag)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Managed Identity RBAC Assignments</div>
      <div class="drawer-field-value">${v.miRbac}</div></div>
    <div class="drawer-section">Control Breakdown</div>
    ${ctrlRows}
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
  if(next>=0&&next<VAULT_DATA.length) showVaultDetail(next);
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
filterVaults();
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
        -replace '__TOTAL_VAULTS__', $TotalVaults `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MEDIUM_COUNT__', $mediumCount `
        -replace '__LOW_COUNT__', $lowCount `
        -replace '__RISK_ROWS_2__', $riskRows `
        -replace '__RISK_ROWS__', $riskRows `
        -replace '__CONTROL_ROWS_TOP__', $controlRowsTop `
        -replace '__CONTROL_ROWS_FULL__', $controlRowsFull `
        -replace '__TOP_VAULTS__', $topVaultsHtml `
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

Function Get-AzureKeyVaultSecurityAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,
        [string[]]$SubscriptionIds,
        [switch]$ExportToCsv,
        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureKeyVaultSecurityAssessment-Report.csv"
    )

    # Start timing
    $startTime = Get-Date

    # Display banner
    Write-KvBanner

    # ── Module check ─────────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.KeyVault", "Az.Monitor", "Az.Resources")

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

    # ── Session & parameter metadata for the HTML report ─────────────────────────
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
    Write-KvSection -Title "Session Information" -Data @{
        "Tenant"      = $currentContext.Tenant.Id
        "Account"     = $currentContext.Account.Id
        "Environment" = $currentContext.Environment.Name
    }

    Write-KvSection -Title "Scan Parameters" -Data @{
        "Scope"         = "$scopeText ($subscriptionCount found)"
        "Export to CSV" = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"   = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────────
    $allFindings = @()
    $subscriptionResults = @()
    $statistics = @{
        SuccessCount      = 0
        ErrorCount        = 0
        RiskDistribution  = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
        ControlFailCounts = @{}
    }

    # Pre-seed control fail counters
    foreach ($control in $Script:KvControls) {
        $statistics.ControlFailCounts[$control.Name] = 0
    }

    # ── Scan loop ─────────────────────────────────────────────────────────────────
    Write-KvScanProgress
    Write-KvProgressBar -Current 0 -Total $subscriptionCount -CurrentItem "Starting..."

    $maxNameLength = ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
    $maxNameLength = [math]::Max($maxNameLength, 35)
    $subscriptionIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-KvProgressBar -Current $subscriptionIndex -Total $subscriptionCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id `
                -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue | Out-Null

            # Retrieve all Key Vaults in this subscription
            $keyVaults = @(Get-AzKeyVault -WarningAction SilentlyContinue -ErrorAction SilentlyContinue)

            $vaultCount = 0

            foreach ($kvSummary in $keyVaults) {
                try {
                    # Fetch full vault details (required for network/protection properties)
                    $kv = Get-AzKeyVault -VaultName $kvSummary.VaultName `
                        -ResourceGroupName $kvSummary.ResourceGroupName `
                        -ErrorAction Stop

                    # ── Control 1: Public Network Access (weight 3) ───────────────
                    # Fail: PublicNetworkAccess is Enabled AND no IP rules in firewall
                    $publicAccessOn = ($kv.PublicNetworkAccess -eq "Enabled") -or
                    ($kv.NetworkAcls.DefaultAction -eq "Allow")
                    $hasFirewallRules = ($kv.NetworkAcls.IpRules.Count -gt 0) -or
                    ($kv.NetworkAcls.VirtualNetworkRules.Count -gt 0)
                    $publicAccessNoFirewall = $publicAccessOn -and (-not $hasFirewallRules)

                    # ── Control 2: No Private Endpoint (weight 2) ────────────────
                    $privateEpCount = 0
                    try {
                        $peConnections = $kv.PrivateEndpointConnections
                        $privateEpCount = if ($peConnections) { @($peConnections).Count } else { 0 }
                    }
                    catch { $privateEpCount = 0 }
                    $noPrivateEndpoint = ($privateEpCount -eq 0)

                    # ── Control 3: Purge Protection disabled (weight 3) ──────────
                    $purgeProtectionDisabled = ($kv.EnablePurgeProtection -ne $true)

                    # ── Control 4: Soft Delete weak (weight 2) ───────────────────
                    $softDeleteEnabled = ($kv.EnableSoftDelete -eq $true)
                    $retentionDays = if ($kv.SoftDeleteRetentionInDays) { [int]$kv.SoftDeleteRetentionInDays } else { 0 }
                    $softDeleteWeak = (-not $softDeleteEnabled) -or ($retentionDays -lt 7)

                    # ── Control 5: Access Policy mode instead of RBAC (weight 2) -
                    $accessPolicyMode = ($kv.EnableRbacAuthorization -ne $true)

                    # ── Control 6: No Diagnostic Logging (weight 2) ──────────────
                    $hasDiagnostics = $false
                    try {
                        $diagSettings = @(Get-AzDiagnosticSetting `
                                -ResourceId $kv.ResourceId `
                                -ErrorAction SilentlyContinue `
                                -WarningAction SilentlyContinue)

                        foreach ($ds in $diagSettings) {
                            $enabledLogs = $ds.Logs | Where-Object { $_.Enabled -eq $true }
                            if (@($enabledLogs).Count -gt 0) {
                                $hasDiagnostics = $true
                                break
                            }
                        }
                    }
                    catch { $hasDiagnostics = $false }
                    $noDiagnostics = (-not $hasDiagnostics)

                    # ── Control 7: No Firewall Rules when public access on (wt 1) -
                    $noFirewallRules = $publicAccessOn -and (-not $hasFirewallRules)

                    # ── Control 8: No Managed Identity RBAC on vault (weight 1) ──
                    $miAssignmentCount = 0
                    try {
                        $vaultAssignments = @(Get-AzRoleAssignment `
                                -Scope $kv.ResourceId `
                                -ErrorAction SilentlyContinue `
                                -WarningAction SilentlyContinue)

                        $miAssignmentCount = @($vaultAssignments |
                            Where-Object { $_.ObjectType -eq "ServicePrincipal" }).Count
                    }
                    catch { $miAssignmentCount = 0 }
                    $noManagedIdentityRbac = ($miAssignmentCount -eq 0)

                    # ── Build finding object ─────────────────────────────────────
                    $finding = [pscustomobject]@{
                        SubscriptionName         = $sub.Name
                        SubscriptionId           = $sub.Id
                        TenantId                 = $sub.TenantId
                        ResourceGroup            = $kv.ResourceGroupName
                        VaultName                = $kv.VaultName
                        Location                 = $kv.Location
                        SKU                      = $kv.Sku
                        RBACEnabled              = (-not $accessPolicyMode)
                        PublicNetworkAccess      = if ($publicAccessOn) { "Enabled" } else { "Disabled" }
                        FirewallRulesCount       = if ($hasFirewallRules) { $kv.NetworkAcls.IpRules.Count } else { 0 }
                        PrivateEndpointCount     = $privateEpCount
                        PurgeProtectionEnabled   = ($kv.EnablePurgeProtection -eq $true)
                        SoftDeleteEnabled        = $softDeleteEnabled
                        SoftDeleteRetentionDays  = $retentionDays
                        DiagnosticsEnabled       = $hasDiagnostics
                        ManagedIdentityRbacCount = $miAssignmentCount
                        # Control fail flags (used by risk engine)
                        PublicAccessNoFirewall   = $publicAccessNoFirewall
                        NoPrivateEndpoint        = $noPrivateEndpoint
                        PurgeProtectionDisabled  = $purgeProtectionDisabled
                        SoftDeleteWeak           = $softDeleteWeak
                        AccessPolicyMode         = $accessPolicyMode
                        NoDiagnostics            = $noDiagnostics
                        NoFirewallRules          = $noFirewallRules
                        NoManagedIdentityRbac    = $noManagedIdentityRbac
                        # Risk will be populated below
                        RiskScore                = 0
                        OverallRisk              = ""
                    }

                    # Compute risk score and rating
                    $score = Get-KvRiskScore -Finding $finding
                    $finding.RiskScore = $score
                    $finding.OverallRisk = Get-KvRiskRating -Score $score

                    # ── Update statistics ────────────────────────────────────────
                    if ($statistics.RiskDistribution.ContainsKey($finding.OverallRisk)) {
                        $statistics.RiskDistribution[$finding.OverallRisk]++
                    }

                    foreach ($control in $Script:KvControls) {
                        if ($finding.($control.FailProperty) -eq $true) {
                            $statistics.ControlFailCounts[$control.Name]++
                        }
                    }

                    $allFindings += $finding
                    $vaultCount++
                }
                catch {
                    Write-Verbose "  Skipping vault '$($kvSummary.VaultName)': $($_.Exception.Message)"
                }
            }

            # Clear progress line and display subscription result
            Write-Host "`r" -NoNewline
            Write-Host (" " * 120) -NoNewline
            Write-Host "`r" -NoNewline

            $paddedName = $sub.Name.PadRight($maxNameLength)

            Write-Host "  " -NoNewline
            if ($vaultCount -gt 0) {
                Write-Host "✓ " -NoNewline -ForegroundColor Green
                Write-Host $paddedName -NoNewline -ForegroundColor Green
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "$vaultCount vault(s) assessed" -ForegroundColor White
                $statistics.SuccessCount++
                $subscriptionResults += @{ Name = $sub.Name; Count = "$vaultCount vault(s) assessed"; Status = "Success" }
            }
            else {
                Write-Host "⚠ " -NoNewline -ForegroundColor Yellow
                Write-Host $paddedName -NoNewline -ForegroundColor Yellow
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "No Key Vaults found" -ForegroundColor DarkGray
                $statistics.SuccessCount++
                $subscriptionResults += @{ Name = $sub.Name; Count = "No Key Vaults found"; Status = "Warning" }
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

    # ── Scan summary for HTML ─────────────────────────────────────────────────────
    $scanSummary = @{
        TotalVaults          = $allFindings.Count
        SubscriptionsScanned = $subscriptionCount
        ExecutionTime        = $durationFormatted
    }

    # ── Console summary output ────────────────────────────────────────────────────
    Write-KvSummary -Data @{
        "Total Subscriptions Scanned" = $subscriptionCount
        "Successful"                  = $statistics.SuccessCount
        "Errors"                      = $statistics.ErrorCount
        "Total Vaults Assessed"       = $allFindings.Count
        "Critical Risk Vaults"        = $statistics.RiskDistribution["Critical"]
        "High Risk Vaults"            = $statistics.RiskDistribution["High"]
        "Medium Risk Vaults"          = $statistics.RiskDistribution["Medium"]
        "Low Risk Vaults"             = $statistics.RiskDistribution["Low"]
        "Execution Time"              = $durationFormatted
    }

    Write-KvRiskDistribution -RiskData $statistics.RiskDistribution -TotalVaults $allFindings.Count
    Write-KvTopRiskyVaults   -Vaults $allFindings
    Write-KvTopFailedControls -ControlFailCounts $statistics.ControlFailCounts

    # ── Output processing ─────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        # CSV export (optional)
        if ($ExportToCsv) {
            try {
                # Only export meaningful columns to CSV (omit internal fail-flag booleans)
                $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, TenantId, ResourceGroup, VaultName,
                Location, SKU, RBACEnabled, PublicNetworkAccess, FirewallRulesCount,
                PrivateEndpointCount, PurgeProtectionEnabled, SoftDeleteEnabled,
                SoftDeleteRetentionDays, DiagnosticsEnabled, ManagedIdentityRbacCount,
                RiskScore, OverallRisk |
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

            $htmlContent = Generate-KvHtmlReport `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParameters `
                -ScanSummary         $scanSummary `
                -SubscriptionResults $subscriptionResults `
                -AllFindings         $allFindings `
                -RiskDistribution    $statistics.RiskDistribution `
                -ControlFailCounts   $statistics.ControlFailCounts `
                -TotalVaults         $allFindings.Count `
                -CsvPath             $(if ($csvExported) { $CsvPath } else { $null }) `
                -HtmlPath            $htmlPath `
                -GridViewOpened      $false

            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML report generation failed: $_" -ForegroundColor Red
        }

        # Grid View (best-effort)
        try {
            $allFindings | Select-Object `
                VaultName, SubscriptionName, ResourceGroup, Location, OverallRisk, RiskScore,
            RBACEnabled, PublicNetworkAccess, FirewallRulesCount, PrivateEndpointCount,
            PurgeProtectionEnabled, SoftDeleteEnabled, SoftDeleteRetentionDays,
            DiagnosticsEnabled, ManagedIdentityRbacCount |
            Out-GridView -Title "Azure Key Vault Security Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View" -ForegroundColor Yellow
        }
    }

    # Display output file summary
    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        Write-KvOutputFiles `
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
