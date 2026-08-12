<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 12 August 2026
Modified-On     : 12 August 2026

.SYNOPSIS
    Correlates public IPs, NSGs, load balancers, application gateways, Azure Firewall,
    App Services, and Storage accounts to identify Azure resources with public accessibility.

.DESCRIPTION
    Get-AzurePublicExposureAssessment performs a structured public-exposure assessment
    across Azure subscriptions. For each subscription (and optional resource group scope),
    it collects and correlates:

        - Public IP addresses and their association to NICs, Load Balancers, App Gateways,
          Azure Firewall, and Bastion Hosts
        - Network Security Groups — inbound allow rules flagging broad sources
          (* / Internet / 0.0.0.0/0 / Any) on any port or protocol
        - Load Balancers — public frontend IP configuration detection
        - Application Gateways — public frontend IP, WAF mode, and tier detection
        - Azure Firewall — public IP and threat-intelligence mode detection
        - App Services (Web Apps / Function Apps) — public network access, HTTPS-only,
          custom domain presence, and outbound IP detection
        - Storage Accounts — public blob access flag and network access configuration
          (all-networks vs. firewall-restricted)

    Each resource is assessed using the moderate exposure definition: resources with
    public accessibility are reported together with the relevant security controls so
    that analysts can distinguish Publicly Accessible from Potentially Exposed /
    Requires Review.

    Output:
        - One row per resource with an ExposureReasons column listing all detected
          exposure indicators
        - Optional CSV export
        - Always-on interactive HTML report (dark-themed, self-contained) with sidebar
          navigation, sortable findings table, stat cards, distribution charts, and
          per-resource detail drawer
        - Interactive Grid View display (where a GUI is available)

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account/context.
    This is also the default behavior if -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan instead of all subscriptions.
    Ignored if -AllSubscriptions is also specified.

.PARAMETER ResourceGroupName
    Optional. Restricts the scan to a specific resource group within each subscription.
    Useful for targeted assessments of a known workload boundary.

.PARAMETER ExportToCsv
    Switch. If specified, exports all collected findings to the path given in -CsvPath.
    The HTML report is generated regardless of whether this switch is used.

.PARAMETER CsvPath
    Path where the CSV export will be written if -ExportToCsv is specified. The HTML
    report path is derived from this value by replacing the .csv extension with .html.
    Default: C:\Temp\AzurePublicExposureAssessment-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML report alongside -CsvPath
    (or the default path). Optionally writes a CSV file if -ExportToCsv is specified.
    Displays results in an interactive Grid View window where a GUI is available.

.EXAMPLE
    Get-AzurePublicExposureAssessment -AllSubscriptions

.EXAMPLE
    Get-AzurePublicExposureAssessment -SubscriptionIds @("SubscriptionID1") -ResourceGroupName "prod-rg"

.EXAMPLE
    Get-AzurePublicExposureAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Audits\Exposure.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (12-Aug-2026) - Initial release. Public IP correlation, NSG inbound-rule
                        analysis (broad-source flagging), Load Balancer and
                        Application Gateway public frontend detection, Azure Firewall
                        assessment, App Service public access and HTTPS checks,
                        Storage account blob access and firewall configuration checks.
                        Per-resource ExposureReasons column, CSV + interactive HTML
                        report, Grid View output.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts  — authentication and subscription enumeration
    2. Az.Network   — Public IPs, NSGs, Load Balancers, App Gateways, Azure Firewall
    3. Az.Websites  — App Services (Web Apps, Function Apps)
    4. Az.Storage   — Storage account public access and network configuration
    5. Az.Resources — resource group enumeration
       All modules are checked individually and installed (with user consent) if absent.
       Minimum permission: Reader at the subscription level.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Full effective-NSG-rule evaluation (Get-AzEffectiveNetworkSecurityRule) is
      not performed in V1. The script evaluates raw NSG rules; subnet-level and
      NIC-level rule precedence is not resolved. This is identified as a future
      enhancement.
    - Network-path reachability analysis (e.g., confirming a public IP is truly
      reachable through all intermediate controls) is out of scope for V1. The
      report uses the moderate exposure definition: public accessibility is flagged
      and security controls are reported separately.
    - Private Link endpoints and service endpoints are not evaluated in V1.
    - Interactive Grid View requires a GUI-capable session. In headless/CI/Linux
      sessions this step is skipped gracefully; CSV/HTML output is unaffected.
    - Default -CsvPath (C:\Temp\...) is a Windows-specific path. On macOS/Linux
      PowerShell 7, supply an explicit -CsvPath.
    - Azure Firewall Premium SKU additional controls (IDPS, TLS inspection) are
      not evaluated in V1.

.LINK
    https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices

.LINK
    https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview

.LINK
    https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security

.LINK
    https://learn.microsoft.com/en-us/azure/app-service/overview-security

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
    Write-CenteredText "Azure Public Exposure Assessment v1.0" -Color White
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
        $maxLength = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLength) {
            $CurrentItem.Substring(0, $maxLength - 3) + "..."
        }
        else { $CurrentItem }

        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-Summary {
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

Function Write-ExposureDistribution {
    param(
        [hashtable]$ExposureData,
        [int]$TotalResources
    )

    if ($TotalResources -eq 0) { return }

    Write-Host ""
    Write-Host "  Exposure Status Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $statusColors = @{
        "Publicly Accessible" = "Red"
        "Potentially Exposed" = "Yellow"
        "Requires Review"     = "Yellow"
        "Not Exposed"         = "Green"
    }

    foreach ($status in $ExposureData.Keys) {
        $count = $ExposureData[$status]
        $percent = [math]::Round(($count / $TotalResources) * 100)
        $color = if ($statusColors.ContainsKey($status)) { $statusColors[$status] } else { "White" }

        Write-Host "  " -NoNewline
        Write-Host $status.PadRight(28) -NoNewline -ForegroundColor $color
        Write-Host ": $count resources ($percent%)" -ForegroundColor White
    }
}

Function Write-ResourceTypeDistribution {
    param([hashtable]$ResourceTypes)

    if ($ResourceTypes.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Resource Type Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $counter = 1
    foreach ($item in ($ResourceTypes.GetEnumerator() | Sort-Object Value -Descending)) {
        Write-Host "  " -NoNewline
        Write-Host "$counter. " -NoNewline -ForegroundColor Gray
        Write-Host $item.Key.PadRight(36) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($item.Value) resource(s)" -ForegroundColor Cyan
        $counter++
    }
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


#------------------------------------------------------------------------ [ NSG Rule Analyser ]

Function Get-NsgBroadInboundRules {
    param([object]$Nsg)

    # Sources that represent broad / internet-wide access
    $broadSources = @("*", "Internet", "0.0.0.0/0", "Any", "0.0.0.0-255.255.255.255")

    $findings = @()

    foreach ($rule in $Nsg.SecurityRules) {
        if ($rule.Direction -ne "Inbound" -or $rule.Access -ne "Allow") { continue }

        $sourcePrefix = $rule.SourceAddressPrefix
        $sourcePrefixes = $rule.SourceAddressPrefixes

        $isBroad = ($broadSources -contains $sourcePrefix) -or
        ($sourcePrefixes | Where-Object { $broadSources -contains $_ })

        if ($isBroad) {
            $portDesc = if ($rule.DestinationPortRange) { $rule.DestinationPortRange }
            elseif ($rule.DestinationPortRanges) { $rule.DestinationPortRanges -join "," }
            else { "Any" }

            $findings += "Rule '$($rule.Name)': Allow $($rule.Protocol) from $sourcePrefix → port $portDesc (Priority $($rule.Priority))"
        }
    }

    # Also check default rules promoted by broad sources
    foreach ($rule in $Nsg.DefaultSecurityRules) {
        if ($rule.Direction -ne "Inbound" -or $rule.Access -ne "Allow") { continue }
        $sourcePrefix = $rule.SourceAddressPrefix

        if ($broadSources -contains $sourcePrefix) {
            $portDesc = if ($rule.DestinationPortRange) { $rule.DestinationPortRange } else { "Any" }
            $findings += "[Default] Rule '$($rule.Name)': Allow from $sourcePrefix → port $portDesc"
        }
    }

    return $findings
}


#------------------------------------------------------------------------ [ HTML Report Generator ]

Function Generate-ExposureHtmlReport {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [hashtable]$ScanSummary,
        [array]$SubscriptionResults,
        [hashtable]$ExposureDistribution,
        [hashtable]$ResourceTypeDistribution,
        [array]$AllFindings,
        [int]$TotalFindings,
        [string]$CsvPath,
        [string]$HtmlPath,
        [bool]$GridViewOpened
    )

    $timestamp = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    #---------------------------------------------------------------- Subscription rows
    $subscriptionRowsHtml = ""
    foreach ($sub in $SubscriptionResults) {
        $iconClass = switch ($sub.Status) {
            "Success" { "icon-success" }
            "Warning" { "icon-warn" }
            "Error" { "icon-error" }
            default { "icon-info" }
        }
        $icon = switch ($sub.Status) {
            "Success" { "✓" }
            "Warning" { "⚠" }
            "Error" { "✗" }
            default { "•" }
        }
        $subscriptionRowsHtml += @"
        <div class="sub-item">
            <span class="sub-icon $iconClass">$icon</span>
            <span class="sub-name">$([System.Web.HttpUtility]::HtmlEncode($sub.Name))</span>
            <span class="sub-count">$([System.Web.HttpUtility]::HtmlEncode($sub.Count))</span>
        </div>
"@
    }

    #---------------------------------------------------------------- Exposure stat counts
    $publicCount = if ($ExposureDistribution.ContainsKey("Publicly Accessible")) { $ExposureDistribution["Publicly Accessible"] }  else { 0 }
    $potentialCount = if ($ExposureDistribution.ContainsKey("Potentially Exposed")) { $ExposureDistribution["Potentially Exposed"] }  else { 0 }
    $reviewCount = if ($ExposureDistribution.ContainsKey("Requires Review")) { $ExposureDistribution["Requires Review"] }       else { 0 }
    $safeCount = if ($ExposureDistribution.ContainsKey("Not Exposed")) { $ExposureDistribution["Not Exposed"] }           else { 0 }

    #---------------------------------------------------------------- Exposure bar chart
    $exposureBarsHtml = ""
    $exposureColors = @{
        "Publicly Accessible" = "var(--red)"
        "Potentially Exposed" = "var(--amber)"
        "Requires Review"     = "var(--amber)"
        "Not Exposed"         = "var(--green)"
    }
    foreach ($status in @("Publicly Accessible", "Potentially Exposed", "Requires Review", "Not Exposed")) {
        $count = if ($ExposureDistribution.ContainsKey($status)) { $ExposureDistribution[$status] } else { 0 }
        $pct = if ($TotalFindings -gt 0) { [math]::Round(($count / $TotalFindings) * 100) } else { 0 }
        $color = $exposureColors[$status]
        $exposureBarsHtml += @"
        <div class="bar-row">
            <span class="bar-label">$status</span>
            <div class="bar-track">
                <div class="bar-fill" data-pct="$pct" style="background:$color;"></div>
            </div>
            <span class="bar-val">$count ($pct%)</span>
        </div>
"@
    }

    #---------------------------------------------------------------- Resource type bar chart
    $resourceTypeBarsHtml = ""
    foreach ($item in ($ResourceTypeDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($TotalFindings -gt 0) { [math]::Round(($item.Value / $TotalFindings) * 100) } else { 0 }
        $resourceTypeBarsHtml += @"
        <div class="bar-row">
            <span class="bar-label">$($item.Key)</span>
            <div class="bar-track">
                <div class="bar-fill" data-pct="$pct" style="background:var(--accent);"></div>
            </div>
            <span class="bar-val">$($item.Value) ($pct%)</span>
        </div>
"@
    }

    #---------------------------------------------------------------- Findings table rows
    $findingRowsHtml = ""
    $rowIndex = 0

    $exposureBadgeClass = @{
        "Publicly Accessible" = "badge-exposed"
        "Potentially Exposed" = "badge-potential"
        "Requires Review"     = "badge-review"
        "Not Exposed"         = "badge-safe"
    }

    foreach ($finding in $AllFindings) {
        $expClass = if ($exposureBadgeClass.ContainsKey($finding.ExposureStatus)) { $exposureBadgeClass[$finding.ExposureStatus] } else { "badge-review" }

        $safeName = [System.Web.HttpUtility]::HtmlEncode($finding.ResourceName)
        $safeRG = [System.Web.HttpUtility]::HtmlEncode($finding.ResourceGroup)
        $safeSub = [System.Web.HttpUtility]::HtmlEncode($finding.SubscriptionName)
        $safeType = [System.Web.HttpUtility]::HtmlEncode($finding.ResourceType)
        $safeStatus = [System.Web.HttpUtility]::HtmlEncode($finding.ExposureStatus)
        $safePublicIp = [System.Web.HttpUtility]::HtmlEncode($finding.PublicIpAddress)
        $safeReasons = [System.Web.HttpUtility]::HtmlEncode($finding.ExposureReasons)

        $findingRowsHtml += @"
        <tr class="finding-row"
            data-status="$safeStatus"
            data-type="$safeType"
            data-sub="$safeSub"
            data-name="$safeName"
            data-rg="$safeRG"
            data-publicip="$safePublicIp"
            data-reasons="$safeReasons"
            data-location="$([System.Web.HttpUtility]::HtmlEncode($finding.Location))"
            data-controls="$([System.Web.HttpUtility]::HtmlEncode($finding.SecurityControls))"
            data-subid="$([System.Web.HttpUtility]::HtmlEncode($finding.SubscriptionId))"
            data-index="$rowIndex">
            <td><span class="exp-badge $expClass">$safeStatus</span></td>
            <td class="mono-cell">$safeName</td>
            <td>$safeType</td>
            <td class="mono-cell">$safeRG</td>
            <td class="mono-cell">$safeSub</td>
            <td class="mono-cell">$safePublicIp</td>
            <td class="reasons-cell">$safeReasons</td>
        </tr>
"@
        $rowIndex++
    }

    #---------------------------------------------------------------- Output files HTML
    $outputFilesHtml = ""
    if ($CsvPath) {
        $outputFilesHtml += @"
        <div class="output-item"><span class="output-icon">✓</span>
            <div><div class="output-label">CSV Export</div>
            <div class="output-val">$([System.Web.HttpUtility]::HtmlEncode($CsvPath))</div></div>
        </div>
"@
    }
    if ($HtmlPath) {
        $outputFilesHtml += @"
        <div class="output-item"><span class="output-icon">✓</span>
            <div><div class="output-label">HTML Report</div>
            <div class="output-val">$([System.Web.HttpUtility]::HtmlEncode($HtmlPath))</div></div>
        </div>
"@
    }
    if ($GridViewOpened) {
        $outputFilesHtml += @"
        <div class="output-item"><span class="output-icon">✓</span>
            <div><div class="output-label">Grid View</div>
            <div class="output-val">Opened in separate window</div></div>
        </div>
"@
    }

    $rgFilterLabel = if ($ScanParameters.ResourceGroupFilter) { $ScanParameters.ResourceGroupFilter } else { "None (all resource groups)" }

    #---------------------------------------------------------------- Full HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Public Exposure Assessment — Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
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
        body { font-family:var(--sans); background:var(--bg); color:var(--text); min-height:100vh; display:flex; }

        /* ── Sidebar ── */
        #sidebar {
            width:236px; min-height:100vh; background:var(--surface);
            border-right:1px solid var(--border); position:fixed; top:0; left:0;
            display:flex; flex-direction:column; z-index:100;
        }
        .logo-block { padding:22px 18px 16px; border-bottom:1px solid var(--border); }
        .logo-icon { width:36px; height:36px; border-radius:8px; background:linear-gradient(135deg,var(--red),var(--amber)); display:flex; align-items:center; justify-content:center; font-size:18px; margin-bottom:10px; }
        .logo-title { font-size:13px; font-weight:700; color:var(--text); line-height:1.3; }
        .logo-sub   { font-size:11px; color:var(--muted); margin-top:2px; }
        .ver-badge  { display:inline-block; margin-top:8px; padding:2px 8px; background:var(--surface3); border:1px solid var(--border); border-radius:20px; font-size:10px; color:var(--muted2); font-family:var(--mono); }
        .nav-section { padding:12px 0; flex:1; }
        .nav-label   { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; padding:0 18px 6px; }
        .nav-btn { width:100%; display:flex; align-items:center; gap:10px; padding:9px 18px; background:none; border:none; color:var(--muted2); font-size:13px; font-family:var(--sans); cursor:pointer; text-align:left; border-left:3px solid transparent; transition:all .15s; }
        .nav-btn:hover  { background:var(--surface2); color:var(--text); }
        .nav-btn.active { background:var(--surface2); color:var(--accent); border-left-color:var(--accent); font-weight:600; }
        .nav-btn .nav-icon { font-size:15px; width:20px; text-align:center; }
        .sidebar-footer { padding:14px 18px; border-top:1px solid var(--border); font-size:11px; color:var(--muted); }
        .theme-toggle { display:flex; align-items:center; gap:8px; margin-bottom:10px; cursor:pointer; }
        .toggle-pill { width:36px; height:20px; background:var(--surface3); border-radius:10px; position:relative; transition:background .2s; border:1px solid var(--border); }
        .toggle-pill::after { content:''; width:14px; height:14px; border-radius:50%; background:var(--muted2); position:absolute; top:2px; left:2px; transition:all .2s; }
        body.light-theme .toggle-pill { background:var(--accent); }
        body.light-theme .toggle-pill::after { left:18px; background:#fff; }
        .toggle-label { font-size:11px; color:var(--muted); }

        /* ── Main ── */
        #main { margin-left:236px; flex:1; padding:28px 32px; min-width:0; }
        .page { display:none; animation:fadeIn .25s ease; }
        .page.active { display:block; }
        @keyframes fadeIn { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:none} }
        .page-header { margin-bottom:24px; }
        .page-title  { font-size:22px; font-weight:700; color:var(--text); }
        .page-sub    { font-size:13px; color:var(--muted); margin-top:4px; }

        /* ── Stat cards ── */
        .stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-bottom:24px; }
        .stat-card  { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:18px 16px; border-top:3px solid var(--accent); transition:box-shadow .2s; }
        .stat-card:hover { box-shadow:var(--shadow); }
        .stat-card.c-red    { border-top-color:var(--red); }
        .stat-card.c-amber  { border-top-color:var(--amber); }
        .stat-card.c-green  { border-top-color:var(--green); }
        .stat-card.c-cyan   { border-top-color:var(--accent2); }
        .stat-card.c-blue   { border-top-color:var(--accent); }
        .stat-num   { font-size:30px; font-weight:700; color:var(--text); line-height:1.1; }
        .stat-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.8px; margin-top:6px; }

        /* ── Panels ── */
        .panel { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:20px; margin-bottom:20px; }
        .panel-title { font-size:14px; font-weight:600; color:var(--text); margin-bottom:16px; }
        .chart-grid  { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px; }
        @media(max-width:900px){ .chart-grid{ grid-template-columns:1fr; } }

        /* ── Bar rows ── */
        .bar-row   { display:flex; align-items:center; gap:10px; margin-bottom:10px; font-size:13px; }
        .bar-label { width:160px; color:var(--muted2); flex-shrink:0; }
        .bar-track { flex:1; height:8px; background:var(--surface3); border-radius:4px; overflow:hidden; }
        .bar-fill  { height:100%; width:0; border-radius:4px; transition:width .6s ease; }
        .bar-val   { width:90px; text-align:right; font-size:12px; color:var(--muted); font-family:var(--mono); }

        /* ── Subscription list ── */
        .sub-list   { max-height:320px; overflow-y:auto; }
        .sub-item   { display:flex; align-items:center; gap:12px; padding:10px 0; border-bottom:1px solid var(--border); font-size:13px; }
        .sub-item:last-child { border-bottom:none; }
        .sub-icon   { width:22px; height:22px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:13px; font-weight:700; flex-shrink:0; }
        .icon-success { background:rgba(63,185,80,.15);  color:var(--green); }
        .icon-warn    { background:rgba(210,153,34,.15); color:var(--amber); }
        .icon-error   { background:rgba(248,81,73,.15);  color:var(--red); }
        .sub-name   { flex:1; color:var(--text); }
        .sub-count  { font-family:var(--mono); font-size:12px; color:var(--muted); }

        /* ── Info grid ── */
        .info-grid  { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:14px; }
        .info-card  { background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:14px 16px; }
        .info-label { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.8px; margin-bottom:6px; }
        .info-value { font-size:14px; color:var(--text); font-weight:600; word-break:break-all; }
        .info-value.none { color:var(--muted); font-style:italic; font-weight:400; }

        /* ── Findings table ── */
        .toolbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
        .search-wrap { position:relative; }
        .search-wrap input { background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:7px 12px 7px 32px; color:var(--text); font-size:13px; width:260px; }
        .search-wrap input:focus { outline:none; border-color:var(--accent); }
        .search-icon { position:absolute; left:10px; top:50%; transform:translateY(-50%); color:var(--muted); font-size:13px; }
        .filter-sel { background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:7px 10px; color:var(--text); font-size:13px; cursor:pointer; }
        .filter-sel:focus { outline:none; border-color:var(--accent); }
        .result-count { font-size:12px; color:var(--muted); margin-left:auto; font-family:var(--mono); }

        .table-wrap { overflow-x:auto; }
        table { width:100%; border-collapse:collapse; font-size:13px; }
        th { background:var(--surface2); color:var(--muted2); font-size:11px; text-transform:uppercase; letter-spacing:.6px; padding:10px 12px; text-align:left; border-bottom:1px solid var(--border); cursor:pointer; white-space:nowrap; user-select:none; }
        th:hover { color:var(--text); }
        th.sort-active { color:var(--accent); }
        .sort-arrow { font-size:9px; margin-left:4px; }
        td { padding:10px 12px; border-bottom:1px solid var(--border); vertical-align:top; }
        tr.finding-row:hover { background:var(--surface2); cursor:pointer; }
        .mono-cell    { font-family:var(--mono); font-size:12px; }
        .reasons-cell { font-size:12px; color:var(--muted2); max-width:280px; }

        /* ── Exposure / status badges ── */
        .exp-badge { display:inline-block; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:600; white-space:nowrap; }
        .badge-exposed   { background:rgba(248,81,73,.15);  color:var(--red);    border:1px solid rgba(248,81,73,.3); }
        .badge-potential { background:rgba(210,153,34,.15); color:var(--amber);  border:1px solid rgba(210,153,34,.3); }
        .badge-review    { background:rgba(210,153,34,.10); color:var(--amber);  border:1px solid rgba(210,153,34,.2); }
        .badge-safe      { background:rgba(63,185,80,.15);  color:var(--green);  border:1px solid rgba(63,185,80,.3); }

        /* ── Pagination ── */
        .pagination { display:flex; align-items:center; gap:6px; margin-top:14px; flex-wrap:wrap; }
        .pg-btn { background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:5px 10px; color:var(--text); font-size:12px; cursor:pointer; }
        .pg-btn:hover  { border-color:var(--accent); color:var(--accent); }
        .pg-btn.active { background:var(--accent); color:#fff; border-color:var(--accent); }
        .pg-info { font-size:12px; color:var(--muted); margin-left:auto; font-family:var(--mono); }

        /* ── Detail drawer ── */
        #detailBackdrop { display:none; position:fixed; inset:0; background:rgba(0,0,0,.5); z-index:200; }
        #detailDrawer { position:fixed; top:0; right:0; width:500px; max-width:100vw; height:100vh; background:var(--surface); border-left:1px solid var(--border); z-index:201; overflow-y:auto; padding:24px; transform:translateX(100%); transition:transform .25s ease; }
        #detailDrawer.open { transform:none; }
        .drawer-header  { display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:20px; }
        .drawer-title   { font-size:16px; font-weight:700; color:var(--text); }
        .drawer-close   { background:none; border:none; color:var(--muted); font-size:20px; cursor:pointer; padding:0 4px; }
        .drawer-nav     { display:flex; gap:8px; margin-bottom:20px; }
        .drawer-nav-btn { background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:5px 12px; color:var(--text); font-size:12px; cursor:pointer; }
        .drawer-nav-btn:hover { border-color:var(--accent); color:var(--accent); }
        .detail-section       { margin-bottom:18px; }
        .detail-section-title { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.8px; margin-bottom:8px; border-bottom:1px solid var(--border); padding-bottom:4px; }
        .detail-row  { display:flex; gap:8px; margin-bottom:8px; font-size:13px; }
        .detail-key  { width:150px; color:var(--muted2); flex-shrink:0; }
        .detail-val  { color:var(--text); font-family:var(--mono); font-size:12px; word-break:break-all; }
        .reasons-block { background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:10px 12px; font-size:12px; color:var(--muted2); white-space:pre-wrap; word-break:break-word; margin-top:6px; }

        /* ── Output files ── */
        .output-list  { display:flex; flex-direction:column; gap:10px; }
        .output-item  { display:flex; align-items:flex-start; gap:12px; background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:12px 14px; }
        .output-icon  { font-size:18px; color:var(--green); flex-shrink:0; }
        .output-label { font-size:11px; color:var(--muted); margin-bottom:2px; }
        .output-val   { font-family:var(--mono); font-size:12px; color:var(--text); word-break:break-all; }

        /* ── Toast ── */
        #toast { position:fixed; bottom:24px; right:24px; background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); padding:10px 16px; font-size:13px; color:var(--text); opacity:0; transform:translateY(12px); pointer-events:none; z-index:300; transition:all .25s; }
        #toast.show { opacity:1; transform:none; }

        /* ── Mobile ── */
        #menuToggle { display:none; position:fixed; top:12px; left:12px; z-index:150; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); padding:6px 10px; cursor:pointer; color:var(--text); font-size:16px; }
        @media(max-width:768px) { #sidebar{transform:translateX(-100%);transition:transform .25s;} #sidebar.open{transform:none;} #main{margin-left:0;padding:16px;} #menuToggle{display:block;} #detailDrawer{width:100vw;} }
        @media print { #sidebar{display:none;} #main{margin-left:0;} #detailBackdrop,#detailDrawer,#toast{display:none!important;} }
    </style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<!-- ═══ Sidebar ═══ -->
<nav id="sidebar">
    <div class="logo-block">
        <div class="logo-icon">🌐</div>
        <div class="logo-title">Azure Public Exposure Assessment</div>
        <div class="logo-sub">Network Security Analysis</div>
        <span class="ver-badge">v1.0</span>
    </div>
    <div class="nav-section">
        <div class="nav-label">Report Sections</div>
        <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
        <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> Findings</button>
        <button class="nav-btn" onclick="showPage('distributions',this)"><span class="nav-icon">📈</span> Distributions</button>
        <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">🗂️</span> Subscriptions</button>
        <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">ℹ️</span> Session Info</button>
        <button class="nav-btn" onclick="showPage('outputs',this)"><span class="nav-icon">📁</span> Output Files</button>
    </div>
    <div class="sidebar-footer">
        <div class="theme-toggle" onclick="toggleTheme()">
            <div class="toggle-pill"></div>
            <span class="toggle-label">Light theme</span>
        </div>
        <div>Generated $timestamp</div>
    </div>
</nav>

<!-- ═══ Main Content ═══ -->
<main id="main">

    <!-- ── Overview ── -->
    <div id="overview" class="page active">
        <div class="page-header">
            <div class="page-title">Public Exposure Assessment — Overview</div>
            <div class="page-sub">Resources assessed across $($ScanSummary.SubscriptionsScanned) subscription(s) &nbsp;·&nbsp; Completed in $($ScanSummary.ExecutionTime)</div>
        </div>
        <div class="stats-grid">
            <div class="stat-card c-blue">
                <div class="stat-num">$TotalFindings</div>
                <div class="stat-label">Total Resources Assessed</div>
            </div>
            <div class="stat-card c-red">
                <div class="stat-num">$publicCount</div>
                <div class="stat-label">Publicly Accessible</div>
            </div>
            <div class="stat-card c-amber">
                <div class="stat-num">$potentialCount</div>
                <div class="stat-label">Potentially Exposed</div>
            </div>
            <div class="stat-card c-amber">
                <div class="stat-num">$reviewCount</div>
                <div class="stat-label">Requires Review</div>
            </div>
            <div class="stat-card c-green">
                <div class="stat-num">$safeCount</div>
                <div class="stat-label">Not Exposed</div>
            </div>
            <div class="stat-card c-blue">
                <div class="stat-num">$($ScanSummary.NsgBroadRules)</div>
                <div class="stat-label">NSGs with Broad Rules</div>
            </div>
        </div>
        <div class="chart-grid">
            <div class="panel">
                <div class="panel-title">Exposure Status Distribution</div>
$exposureBarsHtml
            </div>
            <div class="panel">
                <div class="panel-title">Resource Type Distribution</div>
$resourceTypeBarsHtml
            </div>
        </div>
    </div>

    <!-- ── Findings ── -->
    <div id="findings" class="page">
        <div class="page-header">
            <div class="page-title">All Findings</div>
            <div class="page-sub">Click any row to open the detail drawer &nbsp;·&nbsp; Filter by exposure status or resource type</div>
        </div>
        <div class="panel">
            <div class="toolbar">
                <div class="search-wrap">
                    <span class="search-icon">🔎</span>
                    <input type="text" id="findingSearch" placeholder="Search resource name, IP, resource group…" oninput="applyFilters()">
                </div>
                <select class="filter-sel" id="statusFilter" onchange="applyFilters()">
                    <option value="">All Exposure Statuses</option>
                    <option value="Publicly Accessible">Publicly Accessible</option>
                    <option value="Potentially Exposed">Potentially Exposed</option>
                    <option value="Requires Review">Requires Review</option>
                    <option value="Not Exposed">Not Exposed</option>
                </select>
                <select class="filter-sel" id="typeFilter" onchange="applyFilters()">
                    <option value="">All Resource Types</option>
                    <option value="PublicIP">Public IP</option>
                    <option value="NSG">NSG</option>
                    <option value="LoadBalancer">Load Balancer</option>
                    <option value="ApplicationGateway">Application Gateway</option>
                    <option value="AzureFirewall">Azure Firewall</option>
                    <option value="AppService">App Service</option>
                    <option value="StorageAccount">Storage Account</option>
                </select>
                <span class="result-count" id="resultCount"></span>
            </div>
            <div class="table-wrap">
                <table id="findingsTable">
                    <thead>
                        <tr>
                            <th onclick="sortTable(0)" data-col="0">Status <span class="sort-arrow" id="sa0"></span></th>
                            <th onclick="sortTable(1)" data-col="1">Resource Name <span class="sort-arrow" id="sa1"></span></th>
                            <th onclick="sortTable(2)" data-col="2">Type <span class="sort-arrow" id="sa2"></span></th>
                            <th onclick="sortTable(3)" data-col="3">Resource Group <span class="sort-arrow" id="sa3"></span></th>
                            <th onclick="sortTable(4)" data-col="4">Subscription <span class="sort-arrow" id="sa4"></span></th>
                            <th onclick="sortTable(5)" data-col="5">Public IP <span class="sort-arrow" id="sa5"></span></th>
                            <th>Exposure Reasons</th>
                        </tr>
                    </thead>
                    <tbody id="findingsBody">
$findingRowsHtml
                    </tbody>
                </table>
            </div>
            <div class="pagination" id="pagination"></div>
            <div class="pg-info" id="pgInfo"></div>
        </div>
    </div>

    <!-- ── Distributions ── -->
    <div id="distributions" class="page">
        <div class="page-header">
            <div class="page-title">Distributions</div>
            <div class="page-sub">Exposure status and resource type breakdown</div>
        </div>
        <div class="chart-grid">
            <div class="panel">
                <div class="panel-title">Exposure Status Distribution</div>
$exposureBarsHtml
            </div>
            <div class="panel">
                <div class="panel-title">Resource Type Distribution</div>
$resourceTypeBarsHtml
            </div>
        </div>
    </div>

    <!-- ── Subscriptions ── -->
    <div id="subscriptions" class="page">
        <div class="page-header">
            <div class="page-title">Subscription Scan Results</div>
            <div class="page-sub">Per-subscription resource counts and scan status</div>
        </div>
        <div class="panel">
            <div class="sub-list">
$subscriptionRowsHtml
            </div>
        </div>
    </div>

    <!-- ── Session Info ── -->
    <div id="session" class="page">
        <div class="page-header">
            <div class="page-title">Session &amp; Scan Parameters</div>
            <div class="page-sub">Azure context and filters used during this assessment</div>
        </div>
        <div class="panel" style="margin-bottom:20px;">
            <div class="panel-title">Session Information</div>
            <div class="info-grid">
                <div class="info-card"><div class="info-label">Tenant ID</div><div class="info-value">$($SessionInfo.Tenant)</div></div>
                <div class="info-card"><div class="info-label">Account</div><div class="info-value">$($SessionInfo.Account)</div></div>
                <div class="info-card"><div class="info-label">Environment</div><div class="info-value">$($SessionInfo.Environment)</div></div>
            </div>
        </div>
        <div class="panel">
            <div class="panel-title">Scan Parameters</div>
            <div class="info-grid">
                <div class="info-card"><div class="info-label">Scope</div><div class="info-value">$($ScanParameters.Scope)</div></div>
                <div class="info-card"><div class="info-label">Resource Group Filter</div><div class="info-value$(if (-not $ScanParameters.ResourceGroupFilter) { ' none' })">$rgFilterLabel</div></div>
                <div class="info-card"><div class="info-label">Export to CSV</div><div class="info-value">$($ScanParameters.ExportEnabled)</div></div>
                <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">$($ScanSummary.ExecutionTime)</div></div>
            </div>
        </div>
    </div>

    <!-- ── Output Files ── -->
    <div id="outputs" class="page">
        <div class="page-header">
            <div class="page-title">Output Files</div>
            <div class="page-sub">Files generated during this assessment run</div>
        </div>
        <div class="panel">
            <div class="output-list">
$outputFilesHtml
            </div>
        </div>
    </div>

</main>

<!-- ═══ Detail Drawer ═══ -->
<div id="detailBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
    <div class="drawer-header">
        <div class="drawer-title" id="drawerTitle">Resource Detail</div>
        <button class="drawer-close" onclick="closeDrawer()">✕</button>
    </div>
    <div class="drawer-nav">
        <button class="drawer-nav-btn" onclick="navDrawer(-1)">← Previous</button>
        <button class="drawer-nav-btn" onclick="navDrawer(1)">Next →</button>
        <span id="drawerPos" style="font-size:12px;color:var(--muted);margin-left:auto;align-self:center;"></span>
    </div>
    <div id="drawerContent"></div>
</div>

<div id="toast"></div>

<script>
    function escH(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

    function toggleTheme(){
        document.body.classList.toggle('light-theme');
        localStorage.setItem('theme', document.body.classList.contains('light-theme') ? 'light' : 'dark');
    }
    (function(){ if(localStorage.getItem('theme')==='light') document.body.classList.add('light-theme'); })();

    function showPage(id, btn){
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(id).classList.add('active');
        if(btn) btn.classList.add('active');
        animateBars();
    }

    function animateBars(){
        requestAnimationFrame(function(){
            document.querySelectorAll('.bar-fill').forEach(function(el){
                el.style.width = (el.dataset.pct || 0) + '%';
            });
        });
    }
    window.addEventListener('load', animateBars);

    var allRows      = Array.from(document.querySelectorAll('#findingsBody tr.finding-row'));
    var filteredRows = allRows.slice();
    var currentPage  = 1;
    var pageSize     = 25;
    var sortCol      = -1;
    var sortAsc      = true;
    var currentDetailIndex = 0;

    function applyFilters(){
        var q      = document.getElementById('findingSearch').value.toLowerCase();
        var status = document.getElementById('statusFilter').value;
        var type   = document.getElementById('typeFilter').value;

        filteredRows = allRows.filter(function(row){
            var matchQ      = !q      || row.textContent.toLowerCase().includes(q);
            var matchStatus = !status || row.dataset.status === status;
            var matchType   = !type   || row.dataset.type   === type;
            return matchQ && matchStatus && matchType;
        });

        currentPage = 1;
        renderPage();
    }

    function renderPage(){
        var start = (currentPage - 1) * pageSize;
        var end   = start + pageSize;

        allRows.forEach(function(r){ r.style.display = 'none'; });
        filteredRows.slice(start, end).forEach(function(r){ r.style.display = ''; });

        document.getElementById('resultCount').textContent = filteredRows.length + ' resource(s)';
        renderPagination();
    }

    function renderPagination(){
        var total  = Math.ceil(filteredRows.length / pageSize);
        var pg     = document.getElementById('pagination');
        var pgInfo = document.getElementById('pgInfo');
        pg.innerHTML = '';

        if(total <= 1){ pgInfo.textContent = ''; return; }

        for(var i = 1; i <= total; i++){
            (function(page){
                var btn = document.createElement('button');
                btn.className = 'pg-btn' + (page === currentPage ? ' active' : '');
                btn.textContent = page;
                btn.onclick = function(){ currentPage = page; renderPage(); };
                pg.appendChild(btn);
            })(i);
        }
        var start = (currentPage-1)*pageSize + 1;
        var end   = Math.min(currentPage*pageSize, filteredRows.length);
        pgInfo.textContent = start + '–' + end + ' of ' + filteredRows.length;
    }

    function sortTable(col){
        if(sortCol === col){ sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
        document.querySelectorAll('.sort-arrow').forEach(function(a){ a.textContent = ''; });
        document.querySelectorAll('th').forEach(function(t){ t.classList.remove('sort-active'); });
        var th = document.querySelectorAll('th')[col];
        th.classList.add('sort-active');
        th.querySelector('.sort-arrow').textContent = sortAsc ? '▲' : '▼';

        var statusOrder = {'Publicly Accessible':0,'Potentially Exposed':1,'Requires Review':2,'Not Exposed':3};
        filteredRows.sort(function(a,b){
            var aText = a.cells[col] ? a.cells[col].textContent.trim() : '';
            var bText = b.cells[col] ? b.cells[col].textContent.trim() : '';
            if(col===0){ return sortAsc ? (statusOrder[aText]||9)-(statusOrder[bText]||9) : (statusOrder[bText]||9)-(statusOrder[aText]||9); }
            return sortAsc ? aText.localeCompare(bText) : bText.localeCompare(aText);
        });

        var body = document.getElementById('findingsBody');
        filteredRows.forEach(function(r){ body.appendChild(r); });
        allRows.filter(function(r){ return !filteredRows.includes(r); }).forEach(function(r){ body.appendChild(r); });
        currentPage = 1;
        renderPage();
    }

    allRows.forEach(function(row, idx){
        row.addEventListener('click', function(){ openDrawer(idx); });
    });

    function openDrawer(globalIdx){
        currentDetailIndex = filteredRows.findIndex(function(r){ return r === allRows[globalIdx]; });
        if(currentDetailIndex < 0) currentDetailIndex = 0;
        renderDrawer(currentDetailIndex);
        document.getElementById('detailBackdrop').style.display = 'block';
        document.getElementById('detailDrawer').classList.add('open');
    }

    function closeDrawer(){
        document.getElementById('detailBackdrop').style.display = 'none';
        document.getElementById('detailDrawer').classList.remove('open');
    }

    function navDrawer(dir){
        currentDetailIndex = Math.max(0, Math.min(filteredRows.length-1, currentDetailIndex+dir));
        renderDrawer(currentDetailIndex);
    }

    function renderDrawer(idx){
        var row = filteredRows[idx];
        if(!row) return;
        var d = row.dataset;
        var expBadgeMap = {'Publicly Accessible':'badge-exposed','Potentially Exposed':'badge-potential','Requires Review':'badge-review','Not Exposed':'badge-safe'};
        var expClass = expBadgeMap[d.status] || 'badge-review';

        document.getElementById('drawerTitle').textContent = escH(d.name) || 'Resource Detail';
        document.getElementById('drawerPos').textContent = (idx+1) + ' / ' + filteredRows.length;

        var publicIpRow  = d.publicip  ? '<div class="detail-row"><span class="detail-key">Public IP</span><span class="detail-val">' + escH(d.publicip)  + '</span></div>' : '';
        var controlsRow  = d.controls  ? '<div class="detail-row"><span class="detail-key">Security Controls</span><span class="detail-val">' + escH(d.controls) + '</span></div>' : '';
        var locationRow  = d.location  ? '<div class="detail-row"><span class="detail-key">Location</span><span class="detail-val">' + escH(d.location)  + '</span></div>' : '';

        document.getElementById('drawerContent').innerHTML =
            '<div class="detail-section">' +
                '<div class="detail-section-title">Exposure Status</div>' +
                '<div class="detail-row"><span class="detail-key">Status</span><span class="detail-val"><span class="exp-badge ' + expClass + '">' + escH(d.status) + '</span></span></div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-section-title">Resource Identity</div>' +
                '<div class="detail-row"><span class="detail-key">Resource Name</span><span class="detail-val">' + escH(d.name) + '</span></div>' +
                '<div class="detail-row"><span class="detail-key">Resource Type</span><span class="detail-val">' + escH(d.type) + '</span></div>' +
                '<div class="detail-row"><span class="detail-key">Resource Group</span><span class="detail-val">' + escH(d.rg) + '</span></div>' +
                locationRow +
                '<div class="detail-row"><span class="detail-key">Subscription</span><span class="detail-val">' + escH(d.sub) + '</span></div>' +
                '<div class="detail-row"><span class="detail-key">Subscription ID</span><span class="detail-val">' + escH(d.subid) + '</span></div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-section-title">Network Details</div>' +
                publicIpRow +
                controlsRow +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-section-title">Exposure Reasons</div>' +
                '<div class="reasons-block">' + escH(d.reasons) + '</div>' +
            '</div>';
    }

    document.addEventListener('keydown', function(e){
        if(e.key === 'Escape') closeDrawer();
        if(e.key === 'ArrowLeft'  && document.getElementById('detailDrawer').classList.contains('open')) navDrawer(-1);
        if(e.key === 'ArrowRight' && document.getElementById('detailDrawer').classList.contains('open')) navDrawer(1);
        if(e.key === '/' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)){
            e.preventDefault();
            var si = document.getElementById('findingSearch');
            if(si){ showPage('findings', document.querySelector('.nav-btn:nth-child(2)')); si.focus(); }
        }
    });

    function showToast(msg){
        var t = document.getElementById('toast');
        t.textContent = msg;
        t.classList.add('show');
        setTimeout(function(){ t.classList.remove('show'); }, 3000);
    }

    applyFilters();
</script>
</body>
</html>
"@

    return $html
}


#------------------------------------------------------------------------ [ Module Check Helper ]

Function Confirm-AzModulePresent {
    param(
        [string]$ModuleName,
        [bool]$Required = $true
    )

    if (Get-Module -ListAvailable -Name $ModuleName) {
        try {
            Import-Module $ModuleName -ErrorAction Stop
            return $true
        }
        catch {
            Write-Host "  ⚠ Failed to import $ModuleName`: $($_.Exception.Message)" -ForegroundColor Yellow
            return $false
        }
    }

    if ($Required) {
        Write-Host "  ⚠ $ModuleName not found" -ForegroundColor Yellow
        $install = Read-Host "  Install $ModuleName now? (Y/N)"

        if ($install -in @('Y', 'y')) {
            try {
                Write-Host "  Installing $ModuleName, please wait..." -ForegroundColor Cyan
                Install-Module -Name $ModuleName -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module $ModuleName -ErrorAction Stop
                Write-Host "  ✓ $ModuleName installed" -ForegroundColor Green
                return $true
            }
            catch {
                Write-Host "  ✗ Error installing $ModuleName`: $_" -ForegroundColor Red
                return $false
            }
        }
        else {
            Write-Host "  Installation declined. $ModuleName is required." -ForegroundColor Yellow
            return $false
        }
    }
    else {
        Write-Host "  ⚠ Optional module $ModuleName not found — related checks will be skipped." -ForegroundColor Yellow
        return $false
    }
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzurePublicExposureAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [string]$ResourceGroupName,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzurePublicExposureAssessment-Report.csv"
    )

    # Start timing
    $startTime = Get-Date

    # Display banner
    Write-Banner

    #---------------------------------------------------------------- Module checks
    $hasNetwork = Confirm-AzModulePresent -ModuleName "Az.Network"  -Required $true
    $hasWebsites = Confirm-AzModulePresent -ModuleName "Az.Websites" -Required $false
    $hasStorage = Confirm-AzModulePresent -ModuleName "Az.Storage"  -Required $false
    $hasResources = Confirm-AzModulePresent -ModuleName "Az.Resources" -Required $false

    if (-not $hasNetwork) {
        Write-Host "  ✗ Az.Network is required. Cannot continue." -ForegroundColor Red
        return
    }

    #---------------------------------------------------------------- Azure session
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue

    if (-not $currentContext) {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    #---------------------------------------------------------------- Subscriptions
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

    #---------------------------------------------------------------- Session / parameters for report
    $sessionInfo = @{
        Tenant      = $currentContext.Tenant.Id
        Account     = $currentContext.Account.Id
        Environment = $currentContext.Environment.Name
    }

    $scanParameters = @{
        Scope               = "$scopeText ($subscriptionCount found)"
        ResourceGroupFilter = $ResourceGroupName
        ExportEnabled       = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
    }

    #---------------------------------------------------------------- Display pre-scan info
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $currentContext.Tenant.Id
        "Account"     = $currentContext.Account.Id
        "Environment" = $currentContext.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"                 = "$scopeText ($subscriptionCount found)"
        "Resource Group Filter" = if ($ResourceGroupName) { $ResourceGroupName } else { "" }
        "Export to CSV"         = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"           = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
        "App Service Checks"    = if ($hasWebsites) { "Enabled" } else { "Skipped (Az.Websites absent)" }
        "Storage Checks"        = if ($hasStorage) { "Enabled" } else { "Skipped (Az.Storage absent)" }
    }

    #---------------------------------------------------------------- Initialise collections
    $allFindings = @()
    $subscriptionResults = @()

    $statistics = @{
        SuccessCount             = 0
        ErrorCount               = 0
        NsgBroadRules            = 0
        ExposureDistribution     = @{
            "Publicly Accessible" = 0
            "Potentially Exposed" = 0
            "Requires Review"     = 0
            "Not Exposed"         = 0
        }
        ResourceTypeDistribution = @{}
    }

    #---------------------------------------------------------------- Scan subscriptions
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subscriptionCount -CurrentItem "Starting..."

    $maxNameLength = ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
    $maxNameLength = [math]::Max($maxNameLength, 35)
    $subscriptionIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subscriptionIndex -Total $subscriptionCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id `
                -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue | Out-Null

            $subFindings = 0

            #-------------------------------------------------------- Helper: add finding
            $addFinding = {
                param(
                    [string]$ResourceName,
                    [string]$ResourceType,
                    [string]$ResourceGroup,
                    [string]$Location,
                    [string]$PublicIpAddress,
                    [string]$ExposureStatus,
                    [string]$ExposureReasons,
                    [string]$SecurityControls
                )

                $allFindings += [pscustomobject]@{
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    ResourceName     = $ResourceName
                    ResourceType     = $ResourceType
                    ResourceGroup    = $ResourceGroup
                    Location         = $Location
                    PublicIpAddress  = $PublicIpAddress
                    ExposureStatus   = $ExposureStatus
                    ExposureReasons  = $ExposureReasons
                    SecurityControls = $SecurityControls
                }

                if ($statistics.ExposureDistribution.ContainsKey($ExposureStatus)) {
                    $statistics.ExposureDistribution[$ExposureStatus]++
                }

                if ($statistics.ResourceTypeDistribution.ContainsKey($ResourceType)) {
                    $statistics.ResourceTypeDistribution[$ResourceType]++
                }
                else {
                    $statistics.ResourceTypeDistribution[$ResourceType] = 1
                }

                $script:subFindings++
            }

            #==================================================== Public IPs
            try {
                $pipParams = if ($ResourceGroupName) { @{ ResourceGroupName = $ResourceGroupName } } else { @{} }
                $publicIps = Get-AzPublicIpAddress @pipParams -ErrorAction Stop

                foreach ($pip in $publicIps) {
                    $associatedTo = ""
                    if ($pip.IpConfiguration) {
                        $associatedTo = "Associated: $($pip.IpConfiguration.Id)"
                    }

                    $exposureStatus = if ($pip.IpAddress -and $pip.IpAddress -ne "Not Assigned") { "Publicly Accessible" } else { "Not Exposed" }
                    $exposureReasons = if ($pip.IpAddress -and $pip.IpAddress -ne "Not Assigned") { "Public IP address assigned ($($pip.IpAddress))" } else { "No IP address assigned" }
                    $controls = "AllocationMethod=$($pip.PublicIpAllocationMethod); SKU=$($pip.Sku.Name)$(if ($associatedTo) { '; ' + $associatedTo })"

                    & $addFinding `
                        -ResourceName    $pip.Name `
                        -ResourceType    "PublicIP" `
                        -ResourceGroup   $pip.ResourceGroupName `
                        -Location        $pip.Location `
                        -PublicIpAddress (if ($pip.IpAddress -and $pip.IpAddress -ne "Not Assigned") { $pip.IpAddress } else { "" }) `
                        -ExposureStatus  $exposureStatus `
                        -ExposureReasons $exposureReasons `
                        -SecurityControls $controls
                }
            }
            catch {
                Write-Verbose "  PublicIP scan error in $($sub.Name): $($_.Exception.Message)"
            }

            #==================================================== NSGs
            try {
                $nsgParams = if ($ResourceGroupName) { @{ ResourceGroupName = $ResourceGroupName } } else { @{} }
                $nsgs = Get-AzNetworkSecurityGroup @nsgParams -ErrorAction Stop

                foreach ($nsg in $nsgs) {
                    $broadRules = Get-NsgBroadInboundRules -Nsg $nsg

                    if ($broadRules.Count -gt 0) {
                        $statistics.NsgBroadRules++
                        $reasonsText = $broadRules -join " | "
                        $exposureStatus = "Potentially Exposed"
                        $exposureReasons = "NSG has $($broadRules.Count) broad inbound allow rule(s): $reasonsText"
                    }
                    else {
                        $exposureStatus = "Not Exposed"
                        $exposureReasons = "No broad inbound allow rules detected"
                    }

                    $subnetCount = if ($nsg.Subnets) { $nsg.Subnets.Count } else { 0 }
                    $nicCount = if ($nsg.NetworkInterfaces) { $nsg.NetworkInterfaces.Count } else { 0 }
                    $controls = "Subnets=$subnetCount; NICs=$nicCount; Rules=$($nsg.SecurityRules.Count)"

                    & $addFinding `
                        -ResourceName    $nsg.Name `
                        -ResourceType    "NSG" `
                        -ResourceGroup   $nsg.ResourceGroupName `
                        -Location        $nsg.Location `
                        -PublicIpAddress "" `
                        -ExposureStatus  $exposureStatus `
                        -ExposureReasons $exposureReasons `
                        -SecurityControls $controls
                }
            }
            catch {
                Write-Verbose "  NSG scan error in $($sub.Name): $($_.Exception.Message)"
            }

            #==================================================== Load Balancers
            try {
                $lbParams = if ($ResourceGroupName) { @{ ResourceGroupName = $ResourceGroupName } } else { @{} }
                $lbs = Get-AzLoadBalancer @lbParams -ErrorAction Stop

                foreach ($lb in $lbs) {
                    $publicFrontends = $lb.FrontendIpConfigurations |
                    Where-Object { $_.PublicIpAddress -ne $null }

                    $reasons = @()
                    $publicIpDisplay = ""

                    foreach ($fe in $publicFrontends) {
                        $pipRef = $fe.PublicIpAddress.Id
                        $reasons += "Public frontend IP configuration: $($fe.Name)"
                        if ($pipRef -match "/publicIPAddresses/([^/]+)$") { $publicIpDisplay = $matches[1] }
                    }

                    $exposureStatus = if ($publicFrontends.Count -gt 0) { "Publicly Accessible" } else { "Not Exposed" }
                    $exposureReasons = if ($reasons.Count -gt 0) { $reasons -join " | " } else { "No public frontend IP configuration" }
                    $controls = "SKU=$($lb.Sku.Name); FrontendConfigs=$($lb.FrontendIpConfigurations.Count); Rules=$($lb.LoadBalancingRules.Count)"

                    & $addFinding `
                        -ResourceName    $lb.Name `
                        -ResourceType    "LoadBalancer" `
                        -ResourceGroup   $lb.ResourceGroupName `
                        -Location        $lb.Location `
                        -PublicIpAddress $publicIpDisplay `
                        -ExposureStatus  $exposureStatus `
                        -ExposureReasons $exposureReasons `
                        -SecurityControls $controls
                }
            }
            catch {
                Write-Verbose "  Load Balancer scan error in $($sub.Name): $($_.Exception.Message)"
            }

            #==================================================== Application Gateways
            try {
                $agParams = if ($ResourceGroupName) { @{ ResourceGroupName = $ResourceGroupName } } else { @{} }
                $appGws = Get-AzApplicationGateway @agParams -ErrorAction Stop

                foreach ($ag in $appGws) {
                    $publicFrontends = $ag.FrontendIPConfigurations |
                    Where-Object { $_.PublicIPAddress -ne $null }

                    $reasons = @()
                    $publicIpDisplay = ""

                    if ($publicFrontends.Count -gt 0) { $reasons += "Public frontend IP configuration present" }

                    $wafEnabled = $false
                    $wafMode = "N/A"

                    if ($ag.WebApplicationFirewallConfiguration) {
                        $wafEnabled = $ag.WebApplicationFirewallConfiguration.Enabled
                        $wafMode = $ag.WebApplicationFirewallConfiguration.FirewallMode
                        if (-not $wafEnabled) {
                            $reasons += "WAF is disabled"
                        }
                        elseif ($wafMode -eq "Detection") {
                            $reasons += "WAF is in Detection mode (not Prevention)"
                        }
                    }
                    elseif ($publicFrontends.Count -gt 0) {
                        $reasons += "No WAF configuration found"
                    }

                    $exposureStatus = switch ($true) {
                        ($publicFrontends.Count -gt 0 -and -not $wafEnabled) { "Publicly Accessible" }
                        ($publicFrontends.Count -gt 0 -and $wafMode -eq "Detection") { "Requires Review" }
                        ($publicFrontends.Count -gt 0) { "Publicly Accessible" }
                        default { "Not Exposed" }
                    }

                    $exposureReasons = if ($reasons.Count -gt 0) { $reasons -join " | " } else { "No public exposure detected" }
                    $controls = "SKU=$($ag.Sku.Name); Tier=$($ag.Sku.Tier); WAF=$wafEnabled; WAFMode=$wafMode"

                    & $addFinding `
                        -ResourceName    $ag.Name `
                        -ResourceType    "ApplicationGateway" `
                        -ResourceGroup   $ag.ResourceGroupName `
                        -Location        $ag.Location `
                        -PublicIpAddress $publicIpDisplay `
                        -ExposureStatus  $exposureStatus `
                        -ExposureReasons $exposureReasons `
                        -SecurityControls $controls
                }
            }
            catch {
                Write-Verbose "  Application Gateway scan error in $($sub.Name): $($_.Exception.Message)"
            }

            #==================================================== Azure Firewall
            try {
                $fwParams = if ($ResourceGroupName) { @{ ResourceGroupName = $ResourceGroupName } } else { @{} }
                $firewalls = Get-AzFirewall @fwParams -ErrorAction Stop

                foreach ($fw in $firewalls) {
                    $publicIpDisplay = ""
                    $reasons = @()

                    $publicIpConfigs = $fw.IpConfigurations | Where-Object { $_.PublicIpAddress -ne $null }
                    if ($publicIpConfigs.Count -gt 0) { $reasons += "Azure Firewall has $($publicIpConfigs.Count) public IP configuration(s)" }

                    # Threat intelligence mode
                    $threatIntelMode = if ($fw.ThreatIntelMode) { $fw.ThreatIntelMode } else { "Unknown" }
                    if ($threatIntelMode -eq "Alert") {
                        $reasons += "Threat Intelligence mode is Alert (not Deny)"
                    }
                    elseif ($threatIntelMode -eq "Off") {
                        $reasons += "Threat Intelligence is disabled"
                    }

                    $exposureStatus = if ($publicIpConfigs.Count -gt 0) { "Publicly Accessible" } else { "Not Exposed" }
                    $exposureReasons = if ($reasons.Count -gt 0) { $reasons -join " | " } else { "No public exposure detected" }
                    $controls = "SKU=$($fw.Sku.Tier); ThreatIntelMode=$threatIntelMode; PublicIPs=$($publicIpConfigs.Count)"

                    & $addFinding `
                        -ResourceName    $fw.Name `
                        -ResourceType    "AzureFirewall" `
                        -ResourceGroup   $fw.ResourceGroupName `
                        -Location        $fw.Location `
                        -PublicIpAddress $publicIpDisplay `
                        -ExposureStatus  $exposureStatus `
                        -ExposureReasons $exposureReasons `
                        -SecurityControls $controls
                }
            }
            catch {
                Write-Verbose "  Azure Firewall scan error in $($sub.Name): $($_.Exception.Message)"
            }

            #==================================================== App Services
            if ($hasWebsites) {
                try {
                    $webApps = if ($ResourceGroupName) {
                        Get-AzWebApp -ResourceGroupName $ResourceGroupName -ErrorAction Stop
                    }
                    else {
                        Get-AzWebApp -ErrorAction Stop
                    }

                    foreach ($app in $webApps) {
                        $reasons = @()
                        $controls = @()

                        # Public network access
                        $publicNetworkAccess = $app.SiteConfig.PublicNetworkAccess
                        if ($publicNetworkAccess -ne "Disabled") {
                            $reasons += "Public network access is enabled"
                        }

                        # HTTPS only
                        $httpsOnly = $app.HttpsOnly
                        if (-not $httpsOnly) {
                            $reasons += "HTTPS-only is not enforced (HTTP allowed)"
                        }
                        $controls += "HttpsOnly=$httpsOnly"

                        # Custom domains
                        $hostNames = $app.HostNames
                        $defaultDomain = $app.DefaultHostName
                        $controls += "DefaultDomain=$defaultDomain"

                        # Outbound IPs (informational)
                        $outboundIps = if ($app.OutboundIpAddresses) { $app.OutboundIpAddresses } else { "" }

                        $exposureStatus = switch ($true) {
                            ($publicNetworkAccess -ne "Disabled" -and -not $httpsOnly) { "Publicly Accessible" }
                            ($publicNetworkAccess -ne "Disabled") { "Publicly Accessible" }
                            default { "Not Exposed" }
                        }

                        $exposureReasons = if ($reasons.Count -gt 0) { $reasons -join " | " } else { "Public network access disabled" }
                        $controlsDisplay = $controls -join "; "

                        & $addFinding `
                            -ResourceName    $app.Name `
                            -ResourceType    "AppService" `
                            -ResourceGroup   $app.ResourceGroup `
                            -Location        $app.Location `
                            -PublicIpAddress $outboundIps `
                            -ExposureStatus  $exposureStatus `
                            -ExposureReasons $exposureReasons `
                            -SecurityControls $controlsDisplay
                    }
                }
                catch {
                    Write-Verbose "  App Service scan error in $($sub.Name): $($_.Exception.Message)"
                }
            }

            #==================================================== Storage Accounts
            if ($hasStorage) {
                try {
                    $storageAccounts = if ($ResourceGroupName) {
                        Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop
                    }
                    else {
                        Get-AzStorageAccount -ErrorAction Stop
                    }

                    foreach ($sa in $storageAccounts) {
                        $reasons = @()
                        $controls = @()

                        # Public blob access
                        $allowBlobPublicAccess = $sa.AllowBlobPublicAccess
                        if ($allowBlobPublicAccess -eq $true) {
                            $reasons += "Public blob access is enabled (AllowBlobPublicAccess=True)"
                        }
                        $controls += "AllowBlobPublicAccess=$allowBlobPublicAccess"

                        # Network access / firewall
                        $networkRuleDefaultAction = $sa.NetworkRuleSet.DefaultAction
                        if ($networkRuleDefaultAction -eq "Allow") {
                            $reasons += "Network firewall default action is Allow (accessible from all networks)"
                        }
                        $controls += "NetworkDefaultAction=$networkRuleDefaultAction"

                        # HTTPS-only
                        $supportsHttpsOnly = $sa.EnableHttpsTrafficOnly
                        if (-not $supportsHttpsOnly) {
                            $reasons += "HTTPS-only traffic is not enforced"
                        }
                        $controls += "HttpsOnly=$supportsHttpsOnly"

                        $exposureStatus = switch ($true) {
                            ($allowBlobPublicAccess -eq $true -and $networkRuleDefaultAction -eq "Allow") { "Publicly Accessible" }
                            ($allowBlobPublicAccess -eq $true -or $networkRuleDefaultAction -eq "Allow") { "Potentially Exposed" }
                            default { "Not Exposed" }
                        }

                        $exposureReasons = if ($reasons.Count -gt 0) { $reasons -join " | " } else { "No public exposure detected" }
                        $controlsDisplay = $controls -join "; "

                        & $addFinding `
                            -ResourceName    $sa.StorageAccountName `
                            -ResourceType    "StorageAccount" `
                            -ResourceGroup   $sa.ResourceGroupName `
                            -Location        $sa.PrimaryLocation `
                            -PublicIpAddress "" `
                            -ExposureStatus  $exposureStatus `
                            -ExposureReasons $exposureReasons `
                            -SecurityControls $controlsDisplay
                    }
                }
                catch {
                    Write-Verbose "  Storage Account scan error in $($sub.Name): $($_.Exception.Message)"
                }
            }

            #-------------------------------------------------------- Clear progress & display result
            Write-Host "`r" -NoNewline
            Write-Host (" " * 120) -NoNewline
            Write-Host "`r" -NoNewline

            $paddedName = $sub.Name.PadRight($maxNameLength)

            Write-Host "  " -NoNewline
            if ($subFindings -gt 0) {
                Write-Host "✓ " -NoNewline -ForegroundColor Green
                Write-Host $paddedName -NoNewline -ForegroundColor Green
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "$subFindings resources assessed" -ForegroundColor White
            }
            else {
                Write-Host "⚠ " -NoNewline -ForegroundColor Yellow
                Write-Host $paddedName -NoNewline -ForegroundColor Yellow
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "No resources found" -ForegroundColor DarkGray
            }

            $statistics.SuccessCount++
            $subscriptionResults += @{
                Name   = $sub.Name
                Count  = if ($subFindings -gt 0) { "$subFindings resources assessed" } else { "No resources found" }
                Status = if ($subFindings -gt 0) { "Success" } else { "Warning" }
            }
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
            $subscriptionResults += @{
                Name   = $sub.Name
                Count  = "Failed: $($_.Exception.Message)"
                Status = "Error"
            }
        }

        $subscriptionIndex++
    }

    #---------------------------------------------------------------- Duration
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration

    $totalFindings = $allFindings.Count

    $scanSummary = @{
        TotalResources       = $totalFindings
        SubscriptionsScanned = $subscriptionCount
        NsgBroadRules        = $statistics.NsgBroadRules
        ExecutionTime        = $durationFormatted
    }

    #---------------------------------------------------------------- Console summary
    Write-Summary -Data @{
        "Total Subscriptions Scanned" = $subscriptionCount
        "Successful"                  = $statistics.SuccessCount
        "Errors"                      = $statistics.ErrorCount
        "Total Resources Assessed"    = $totalFindings
        "Publicly Accessible"         = $statistics.ExposureDistribution["Publicly Accessible"]
        "Potentially Exposed"         = $statistics.ExposureDistribution["Potentially Exposed"]
        "Requires Review"             = $statistics.ExposureDistribution["Requires Review"]
        "Not Exposed"                 = $statistics.ExposureDistribution["Not Exposed"]
        "NSGs with Broad Rules"       = $statistics.NsgBroadRules
        "Execution Time"              = $durationFormatted
    }

    Write-ExposureDistribution  -ExposureData $statistics.ExposureDistribution -TotalResources $totalFindings
    Write-ResourceTypeDistribution -ResourceTypes $statistics.ResourceTypeDistribution

    #---------------------------------------------------------------- Output
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($totalFindings -gt 0) {
        # CSV export (optional)
        if ($ExportToCsv) {
            try {
                $safePath = $CsvPath -replace '\.\.', ''
                $allFindings | Export-Csv -Path $safePath -NoTypeInformation -Force
                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML report (always)
        try {
            $htmlPath = $CsvPath -replace '\.csv$', '.html'
            if (-not $htmlPath.EndsWith('.html')) {
                $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
            }

            $htmlContent = Generate-ExposureHtmlReport `
                -SessionInfo             $sessionInfo `
                -ScanParameters          $scanParameters `
                -ScanSummary             $scanSummary `
                -SubscriptionResults     $subscriptionResults `
                -ExposureDistribution    $statistics.ExposureDistribution `
                -ResourceTypeDistribution $statistics.ResourceTypeDistribution `
                -AllFindings             $allFindings `
                -TotalFindings           $totalFindings `
                -CsvPath                 $(if ($csvExported) { $CsvPath } else { $null }) `
                -HtmlPath                $htmlPath `
                -GridViewOpened          $false

            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML report generation failed: $_" -ForegroundColor Red
        }

        # Grid View
        try {
            $allFindings | Out-GridView -Title "Azure Public Exposure Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View" -ForegroundColor Yellow
        }
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        Write-OutputFiles `
            -CsvPath        $(if ($csvExported) { $CsvPath }  else { $null }) `
            -HtmlPath       $(if ($htmlExported) { $htmlPath } else { $null }) `
            -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
