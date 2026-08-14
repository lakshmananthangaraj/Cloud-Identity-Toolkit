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

    $timestamp = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    # ── Subscription results rows ────────────────────────────────────────────────
    $subscriptionHtml = ""
    foreach ($sub in $SubscriptionResults) {
        $icon = switch ($sub.Status) {
            "Success" { "✓" }
            "Warning" { "⚠" }
            "Error" { "✗" }
            default { "•" }
        }
        $subscriptionHtml += @"
                    <div class="subscription-item">
                        <span class="status-icon">$icon</span>
                        <span class="subscription-name">$($sub.Name)</span>
                        <span class="assignment-count">$($sub.Count)</span>
                    </div>
"@
    }

    # ── Risk distribution bars ───────────────────────────────────────────────────
    $riskOrder = @("Critical", "High", "Medium", "Low")
    $riskColors = @{ Critical = "#f85149"; High = "#d29922"; Medium = "#e3b341"; Low = "#3fb950" }
    $riskDistributionHtml = ""
    foreach ($rating in $riskOrder) {
        $count = if ($RiskDistribution.ContainsKey($rating)) { $RiskDistribution[$rating] } else { 0 }
        $percent = if ($TotalVaults -gt 0) { [math]::Round(($count / $TotalVaults) * 100) } else { 0 }
        $color = $riskColors[$rating]
        $riskDistributionHtml += @"
                    <div class="distribution-item">
                        <div class="distribution-label">
                            <span style="color:$color;font-weight:600;">$rating</span>
                            <span>$count vault(s) — $percent%</span>
                        </div>
                        <div class="distribution-bar">
                            <div class="distribution-fill" style="width:$percent%;background:$color;"></div>
                        </div>
                    </div>
"@
    }

    # ── Top failed controls ──────────────────────────────────────────────────────
    $topControlsHtml = ""
    $counter = 1
    foreach ($ctrl in ($ControlFailCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8)) {
        $topControlsHtml += @"
                    <div class="top-item">
                        <div class="rank">$counter</div>
                        <div class="item-name">$($ctrl.Key)</div>
                        <div class="item-count">$($ctrl.Value) vault(s)</div>
                    </div>
"@
        $counter++
    }

    # ── Top 5 riskiest vaults ────────────────────────────────────────────────────
    $topVaultsHtml = ""
    $counter = 1
    foreach ($vault in ($AllFindings | Sort-Object RiskScore -Descending | Select-Object -First 5)) {
        $riskColor = $riskColors[$vault.OverallRisk]
        if (-not $riskColor) { $riskColor = "#7d8590" }
        $topVaultsHtml += @"
                    <div class="top-item">
                        <div class="rank">$counter</div>
                        <div class="item-name">$($vault.VaultName) <span style="font-size:11px;color:#7d8590;">($($vault.SubscriptionName))</span></div>
                        <div class="item-count" style="color:$riskColor;font-weight:700;">$($vault.OverallRisk) / $($vault.RiskScore)</div>
                    </div>
"@
        $counter++
    }

    # ── Findings table rows ──────────────────────────────────────────────────────
    $findingsTableHtml = ""
    foreach ($f in ($AllFindings | Sort-Object RiskScore -Descending)) {
        $riskColor = $riskColors[$f.OverallRisk]
        if (-not $riskColor) { $riskColor = "#7d8590" }

        $cell = {
            param($val)
            if ($val -eq $true) {
                '<span style="color:#f85149;font-weight:600;">FAIL</span>'
            }
            else {
                '<span style="color:#3fb950;">PASS</span>'
            }
        }

        $findingsTableHtml += @"
                    <tr>
                        <td>$($f.VaultName)</td>
                        <td style="font-size:11px;color:#7d8590;">$($f.SubscriptionName)</td>
                        <td>$($f.ResourceGroup)</td>
                        <td style="color:$riskColor;font-weight:700;">$($f.OverallRisk)</td>
                        <td style="text-align:center;">$($f.RiskScore)</td>
                        <td style="text-align:center;">$(& $cell $f.PublicAccessNoFirewall)</td>
                        <td style="text-align:center;">$(& $cell $f.PurgeProtectionDisabled)</td>
                        <td style="text-align:center;">$(& $cell $f.SoftDeleteWeak)</td>
                        <td style="text-align:center;">$(& $cell $f.NoPrivateEndpoint)</td>
                        <td style="text-align:center;">$(& $cell $f.AccessPolicyMode)</td>
                        <td style="text-align:center;">$(& $cell $f.NoDiagnostics)</td>
                        <td style="text-align:center;">$(& $cell $f.NoFirewallRules)</td>
                        <td style="text-align:center;">$(& $cell $f.NoManagedIdentityRbac)</td>
                    </tr>
"@
    }

    # ── Output files section ─────────────────────────────────────────────────────
    $outputFilesHtml = ""
    if ($CsvPath) {
        $outputFilesHtml += @"
                    <div class="output-item">
                        <div class="output-icon">✓</div>
                        <div class="output-details">
                            <div class="output-label">CSV Export</div>
                            <div class="output-value">$CsvPath</div>
                        </div>
                    </div>
"@
    }
    if ($HtmlPath) {
        $outputFilesHtml += @"
                    <div class="output-item">
                        <div class="output-icon">✓</div>
                        <div class="output-details">
                            <div class="output-label">HTML Report</div>
                            <div class="output-value">$HtmlPath</div>
                        </div>
                    </div>
"@
    }
    if ($GridViewOpened) {
        $outputFilesHtml += @"
                    <div class="output-item">
                        <div class="output-icon">✓</div>
                        <div class="output-details">
                            <div class="output-label">Grid View</div>
                            <div class="output-value">Opened in separate window</div>
                        </div>
                    </div>
"@
    }

    # ── Full HTML ────────────────────────────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Key Vault Security Assessment - Execution Report</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
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
        html { scroll-behavior:smooth; }
        body { font-family:var(--sans); background:var(--bg); color:var(--text); font-size:15px; line-height:1.6; min-height:100vh; transition:background .25s,color .25s; }
        .theme-btn { position:fixed; top:14px; right:18px; z-index:200; background:var(--surface2); border:1px solid var(--border); color:var(--muted2); font-family:var(--sans); font-size:12px; padding:6px 14px; border-radius:20px; cursor:pointer; transition:all .2s; }
        .theme-btn:hover { border-color:var(--accent); color:var(--accent); }
        .container { max-width:1400px; margin:0 auto; background:var(--surface); border-radius:var(--radius); box-shadow:var(--shadow); overflow:hidden; border:1px solid var(--border); }
        .header { background:linear-gradient(135deg,var(--accent) 0%,var(--accent2) 100%); color:#fff; padding:40px; text-align:center; }
        .header h1 { font-size:28px; margin-bottom:8px; font-weight:300; letter-spacing:1px; }
        .header .timestamp { font-size:13px; opacity:0.85; font-family:var(--mono); }
        .content { padding:28px 32px; }
        .section { margin-bottom:28px; }
        .section-title { font-size:18px; color:var(--accent); margin-bottom:18px; padding-bottom:8px; border-bottom:1px solid var(--border); font-weight:600; }
        .info-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; margin-bottom:16px; }
        .info-card { background:var(--surface2); padding:18px; border-radius:var(--radius-sm); border-left:4px solid var(--accent); }
        .info-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; }
        .info-value { font-size:15px; color:var(--text); font-weight:600; word-break:break-all; font-family:var(--mono); }
        .info-value.none { color:var(--muted); font-style:italic; }
        .stats-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:12px; margin-bottom:16px; }
        .stat-card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:15px 17px; position:relative; overflow:hidden; transition:transform .2s,border-color .2s; }
        .stat-card:hover { transform:translateY(-2px); border-color:var(--accent); }
        .stat-card.blue   { border-top:2px solid var(--accent); }
        .stat-card.red    { border-top:2px solid var(--red); }
        .stat-card.amber  { border-top:2px solid var(--amber); }
        .stat-card.green  { border-top:2px solid var(--green); }
        .stat-card.purple { border-top:2px solid var(--accent3); }
        .stat-number { font-size:25px; font-weight:700; color:var(--text); line-height:1; margin-bottom:4px; font-family:var(--mono); }
        .stat-label  { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; margin-top:4px; }
        .subscription-list { background:var(--surface2); padding:18px; border-radius:var(--radius-sm); max-height:380px; overflow-y:auto; border:1px solid var(--border); }
        .subscription-item { display:flex; align-items:center; padding:10px 0; border-bottom:1px solid var(--border); }
        .subscription-item:last-child { border-bottom:none; }
        .status-icon { width:22px; margin-right:14px; font-size:16px; }
        .subscription-name { flex:1; font-weight:500; color:var(--text); }
        .assignment-count { color:var(--accent); font-weight:600; font-size:13px; font-family:var(--mono); }
        .top-list { background:var(--surface2); padding:18px; border-radius:var(--radius-sm); border:1px solid var(--border); }
        .top-item { display:flex; align-items:center; padding:12px; margin-bottom:8px; background:var(--surface); border-radius:var(--radius-sm); border:1px solid var(--border); transition:border-color .2s; }
        .top-item:last-child { margin-bottom:0; }
        .top-item:hover { border-color:var(--accent); }
        .rank { width:30px; height:30px; background:linear-gradient(135deg,var(--accent),var(--accent3)); color:#fff; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:700; margin-right:14px; font-size:13px; flex-shrink:0; font-family:var(--mono); }
        .item-name { flex:1; font-weight:500; color:var(--text); font-size:13px; }
        .item-count { color:var(--accent2); font-weight:600; font-size:13px; white-space:nowrap; font-family:var(--mono); }
        .distribution { background:var(--surface2); padding:18px; border-radius:var(--radius-sm); border:1px solid var(--border); }
        .distribution-item { margin-bottom:18px; }
        .distribution-item:last-child { margin-bottom:0; }
        .distribution-label { display:flex; justify-content:space-between; margin-bottom:6px; font-size:13px; color:var(--text); }
        .distribution-bar { height:8px; background:var(--surface3); border-radius:4px; overflow:hidden; }
        .distribution-fill { height:100%; border-radius:4px; }
        .two-col { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
        .table-wrap { overflow-x:auto; background:var(--surface2); border-radius:var(--radius-sm); border:1px solid var(--border); }
        table { width:100%; border-collapse:collapse; font-size:12px; }
        th { background:var(--accent); color:#fff; padding:10px 12px; text-align:left; white-space:nowrap; font-weight:600; letter-spacing:.05em; font-family:var(--sans); }
        td { padding:8px 12px; border-bottom:1px solid var(--border); color:var(--text); vertical-align:middle; }
        tr:last-child td { border-bottom:none; }
        tr:hover td { background:var(--surface3); }
        .output-section { background:var(--surface2); padding:18px; border-radius:var(--radius-sm); border:1px solid var(--border); }
        .output-item { display:flex; align-items:center; padding:12px; margin-bottom:8px; background:var(--surface); border-radius:var(--radius-sm); border:1px solid var(--border); }
        .output-item:last-child { margin-bottom:0; }
        .output-icon { width:38px; height:38px; background:var(--green); color:#fff; border-radius:50%; display:flex; align-items:center; justify-content:center; margin-right:14px; font-size:18px; flex-shrink:0; }
        .output-details { flex:1; }
        .output-label { font-size:11px; color:var(--muted); margin-bottom:3px; text-transform:uppercase; letter-spacing:.05em; }
        .output-value { font-weight:600; color:var(--text); word-break:break-all; font-size:13px; font-family:var(--mono); }
        .footer { background:var(--bg); padding:18px; text-align:center; color:var(--muted); font-size:12px; border-top:1px solid var(--border); font-family:var(--mono); }
        @keyframes fadeIn { from{opacity:0;transform:translateY(5px)} to{opacity:1;transform:translateY(0)} }
        .content { animation:fadeIn .22s ease; }
        @media (max-width:900px) { .two-col { grid-template-columns:1fr; } }
        @media (max-width:768px) { .content { padding:16px; } .stat-number { font-size:20px; } }
        @media print { body { background:white; } .container { box-shadow:none; } .theme-btn { display:none; } }
    </style>
</head>
<body>
    <button class="theme-btn" onclick="document.body.classList.toggle('light-theme')">☀ / 🌙 Theme</button>
    <div class="container">

        <div class="header">
            <h1>🔐 Azure Key Vault Security Assessment</h1>
            <div class="timestamp">Execution Report — Generated on $timestamp</div>
        </div>

        <div class="content">

            <!-- Session Information -->
            <div class="section">
                <h2 class="section-title">📋 Session Information</h2>
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

            <!-- Scan Parameters -->
            <div class="section">
                <h2 class="section-title">⚙️ Scan Parameters</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <div class="info-label">Scope</div>
                        <div class="info-value">$($ScanParameters.Scope)</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">CSV Export</div>
                        <div class="info-value">$($ScanParameters.ExportEnabled)</div>
                    </div>
                    <div class="info-card">
                        <div class="info-label">Export Path</div>
                        <div class="info-value$(if ([string]::IsNullOrWhiteSpace($ScanParameters.ExportPath)) { ' none' })">$(if ($ScanParameters.ExportPath) { $ScanParameters.ExportPath } else { 'N/A' })</div>
                    </div>
                </div>
            </div>

            <!-- Summary Statistics -->
            <div class="section">
                <h2 class="section-title">📊 Scan Summary</h2>
                <div class="stats-grid">
                    <div class="stat-card blue">
                        <div class="stat-number">$($ScanSummary.TotalVaults)</div>
                        <div class="stat-label">Vaults Assessed</div>
                    </div>
                    <div class="stat-card red">
                        <div class="stat-number">$(if ($RiskDistribution.ContainsKey('Critical')) { $RiskDistribution['Critical'] } else { 0 })</div>
                        <div class="stat-label">Critical Risk</div>
                    </div>
                    <div class="stat-card amber">
                        <div class="stat-number">$(if ($RiskDistribution.ContainsKey('High')) { $RiskDistribution['High'] } else { 0 })</div>
                        <div class="stat-label">High Risk</div>
                    </div>
                    <div class="stat-card green">
                        <div class="stat-number">$(if ($RiskDistribution.ContainsKey('Low')) { $RiskDistribution['Low'] } else { 0 })</div>
                        <div class="stat-label">Low Risk</div>
                    </div>
                    <div class="stat-card purple">
                        <div class="stat-number">$($ScanSummary.SubscriptionsScanned)</div>
                        <div class="stat-label">Subscriptions</div>
                    </div>
                    <div class="stat-card blue">
                        <div class="stat-number">$($ScanSummary.ExecutionTime)</div>
                        <div class="stat-label">Execution Time</div>
                    </div>
                </div>
            </div>

            <!-- Risk Distribution + Top Failed Controls -->
            <div class="section">
                <h2 class="section-title">🎯 Risk & Control Analysis</h2>
                <div class="two-col">
                    <div>
                        <div class="section-title" style="font-size:14px;margin-bottom:12px;">Risk Rating Distribution</div>
                        <div class="distribution">
                            $riskDistributionHtml
                        </div>
                    </div>
                    <div>
                        <div class="section-title" style="font-size:14px;margin-bottom:12px;">Most Frequently Failed Controls</div>
                        <div class="top-list">
                            $topControlsHtml
                        </div>
                    </div>
                </div>
            </div>

            <!-- Top 5 Riskiest Vaults -->
            <div class="section">
                <h2 class="section-title">🔴 Top 5 Highest Risk Vaults</h2>
                <div class="top-list">
                    $topVaultsHtml
                </div>
            </div>

            <!-- Subscription Results -->
            <div class="section">
                <h2 class="section-title">🗂️ Subscription Results</h2>
                <div class="subscription-list">
                    $subscriptionHtml
                </div>
            </div>

            <!-- Full Findings Table -->
            <div class="section">
                <h2 class="section-title">📋 Full Vault Findings</h2>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Vault Name</th>
                                <th>Subscription</th>
                                <th>Resource Group</th>
                                <th>Risk Rating</th>
                                <th>Score</th>
                                <th>Public Access</th>
                                <th>Purge Prot.</th>
                                <th>Soft Delete</th>
                                <th>Private EP</th>
                                <th>Access Policy</th>
                                <th>Diagnostics</th>
                                <th>Firewall</th>
                                <th>MI RBAC</th>
                            </tr>
                        </thead>
                        <tbody>
                            $findingsTableHtml
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Output Files -->
            <div class="section">
                <h2 class="section-title">💾 Output Files</h2>
                <div class="output-section">
                    $outputFilesHtml
                </div>
            </div>

        </div><!-- /content -->

        <div class="footer">
            Generated by Azure Key Vault Security Assessment v1.0 &nbsp;|&nbsp;
            Controls aligned to CIS Azure Benchmark v2.0 &amp; Microsoft Defender for Cloud &nbsp;|&nbsp;
            PowerShell Script
        </div>

    </div><!-- /container -->
</body>
</html>
"@

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
