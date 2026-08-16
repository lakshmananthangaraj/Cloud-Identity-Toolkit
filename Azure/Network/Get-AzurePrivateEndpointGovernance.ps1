<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 16 August 2026
Modified-On     : 16 August 2026

.SYNOPSIS
    Identifies sensitive PaaS services not using Private Endpoints where appropriate,
    and evaluates Private DNS integration — across one or more subscriptions — to
    support Zero Trust and private-by-default architecture, with optional CSV export
    and an interactive HTML dashboard.

.DESCRIPTION
    Get-AzurePrivateEndpointGovernance assesses the private connectivity posture of
    Azure PaaS services from an Enterprise Architect perspective. The assessment goes
    beyond listing Private Endpoints — it identifies where they are missing, where DNS
    integration is broken, and where public access is not disabled after PE deployment,
    all of which create real-world data exfiltration and lateral movement risks.

    Private Endpoint Coverage Assessment
        For each supported PaaS resource type, the script determines:
            - Is a Private Endpoint deployed for this resource?
            - Is public network access still enabled (open even with PE)?
            - Is the PE approval status 'Approved' or still 'Pending'?
            - Is the PE connected to the correct subscription's VNet?
        Assessed service types:
            Storage Accounts (blob, file, queue, table, dfs sub-resources)
            Key Vaults
            Azure SQL Servers (sqlServer sub-resource)
            Cosmos DB Accounts
            Azure Container Registries
            Azure Kubernetes Service (API server / management)
            App Service / Function Apps (sites sub-resource)
            Service Bus Namespaces
            Event Hub Namespaces
            Azure Cognitive Services / AI Services accounts

    Private DNS Integration Assessment
        For each Private Endpoint the script verifies:
            - Is a Private DNS Zone linked to the resource's VNet?
            - Does the DNS zone name follow the recommended
              privatelink.<service>.core.windows.net pattern?
            - Is the DNS zone group associated with the PE properly configured?
            - Are there competing public DNS resolution paths that could cause
              split-brain DNS (PE resolves to public IP instead of private IP)?

    Public Access Exposure After PE Deployment
        Resources with Private Endpoints but public access still enabled are flagged
        separately — PE deployment without public access restriction is a half-measure
        that leaves the resource reachable via its public FQDN.

    Architecture Findings
        - Resources in regions with no Private Endpoint support flagged informational
        - Resources where PE exists but is in a different subscription's VNet
          (cross-subscription PE — valid but noted for governance review)
        - Private DNS Zones not linked to any VNet (orphaned zones)
        - Private DNS Zones linked to VNets in different subscriptions than the PE
          resource (cross-subscription DNS — valid but needs governance documentation)

    For each finding the script records:
        - Resource (affected PaaS resource name and type)
        - Service Type (Storage | KeyVault | SQL | CosmosDB | ACR | AKS | AppService |
          ServiceBus | EventHub | AIServices)
        - Check (what is being evaluated)
        - Why (architectural reason Private Endpoint or DNS integration matters)
        - Current State (observed configuration)
        - Risk (what exposure exists without the control)
        - Severity (High / Medium / Low / Info)
        - Recommendation (specific, actionable remediation step)

    The script supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of all findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable findings
          table, service-type distribution, PE coverage summary, detail drawer)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzurePrivateEndpointGovernance-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzurePrivateEndpointGovernance -AllSubscriptions

.EXAMPLE
    Get-AzurePrivateEndpointGovernance -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzurePrivateEndpointGovernance -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\PEGovernance.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (16-Aug-2026) - Initial release. PE coverage assessment for Storage,
                            Key Vault, SQL, Cosmos DB, ACR, AKS, App Service,
                            Service Bus, Event Hub, and AI Services. Private DNS
                            integration and public access posture checks. CSV export
                            and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Network, Az.Storage, Az.KeyVault,
           Az.Sql, Az.CosmosDB, Az.ContainerRegistry, Az.Aks, Az.Websites,
           Az.ServiceBus, Az.EventHub, Az.CognitiveServices, Az.PrivateDns)
           — installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level.
        4. Microsoft.Network/privateEndpoints/read and
           Microsoft.Network/privateDnsZones/read at subscription scope.
        5. Resource-specific read permissions (e.g. Microsoft.Storage/storageAccounts/read)
           for each service type to be assessed.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - AKS Private Cluster detection uses the ApiServerAccessProfile property.
          Older AKS clusters (pre-1.20) may not expose this property consistently.
        - Azure Cognitive Services / AI Services public access property name varies
          between resource kinds. The script uses best-effort property detection.
        - Cross-subscription Private DNS Zone links cannot be detected within a
          single subscription scan — the linked PE will appear to have no zone if
          the DNS zone lives in a hub subscription not in scope.
        - App Service Private Endpoint detection uses site-level PE listing; some
          ASE (App Service Environment) deployments may be reported as having no PE
          since ASE provides VNet isolation through a different mechanism.
        - Interactive Grid View requires a GUI-capable session. Skipped gracefully
          in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview
    https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns
    https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints
    https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service
    https://learn.microsoft.com/en-us/azure/azure-sql/database/private-endpoint-overview

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
    Write-CenteredText "Azure Private Endpoint Governance Assessment v1.0" -Color White
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

Function Write-SeverityBreakdown {
    param([hashtable]$Severity)

    if ($Severity.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Severity Breakdown" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $colorMap = @{
        "High"   = "Red"
        "Medium" = "Yellow"
        "Low"    = "Green"
        "Info"   = "DarkGray"
    }

    foreach ($sev in @("High", "Medium", "Low", "Info")) {
        if ($Severity.ContainsKey($sev)) {
            $color = if ($colorMap.ContainsKey($sev)) { $colorMap[$sev] } else { "White" }
            Write-Host "  " -NoNewline
            Write-Host $sev.PadRight(22) -NoNewline -ForegroundColor $color
            Write-Host ": " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($Severity[$sev]) finding(s)" -ForegroundColor $color
        }
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
        Write-Host ("CSV Export").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
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

# ── Returns all Private Endpoint connections for a resource by ARM resource ID ─
Function Get-PrivateEndpointConnectionsForResource {
    param(
        [string]$ResourceId,
        [array]$AllPrivateEndpoints    # subscription-scope PE list from Get-AzPrivateEndpoint
    )

    $matches = @()
    foreach ($pe in $AllPrivateEndpoints) {
        foreach ($conn in $pe.PrivateLinkServiceConnections) {
            if ($conn.PrivateLinkServiceId -and
                $conn.PrivateLinkServiceId.ToLower() -eq $ResourceId.ToLower()) {
                $matches += $pe
                break
            }
        }
        # Also check manual connections
        foreach ($conn in $pe.ManualPrivateLinkServiceConnections) {
            if ($conn.PrivateLinkServiceId -and
                $conn.PrivateLinkServiceId.ToLower() -eq $ResourceId.ToLower()) {
                $matches += $pe
                break
            }
        }
    }
    return $matches
}

# ── Returns whether a PE has an approved connection ───────────────────────────
Function Get-PeApprovalStatus {
    param([object]$Pe)

    foreach ($conn in $Pe.PrivateLinkServiceConnections) {
        $state = Get-ObjProperty -Obj $conn.PrivateLinkServiceConnectionState -PropName 'Status' -Default "Unknown"
        if ($state -eq "Approved") { return "Approved" }
        if ($state -eq "Pending") { return "Pending" }
    }
    foreach ($conn in $Pe.ManualPrivateLinkServiceConnections) {
        $state = Get-ObjProperty -Obj $conn.PrivateLinkServiceConnectionState -PropName 'Status' -Default "Unknown"
        if ($state -eq "Approved") { return "Approved" }
        if ($state -eq "Pending") { return "Pending" }
    }
    return "Unknown"
}


#------------------------------------------------------------------------ [ Finding Builder ]

Function New-PeFinding {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$ResourceName,
        [string]$ResourceId,
        [string]$ServiceType,     # Storage | KeyVault | SQL | CosmosDB | ACR | AKS | AppService | ServiceBus | EventHub | AIServices
        [string]$CheckCategory,   # PE Coverage | DNS Integration | Public Access | Architecture
        [string]$CheckName,
        [string]$Why,
        [string]$CurrentState,
        [string]$Risk,
        [string]$Severity,        # High | Medium | Low | Info
        [string]$Recommendation
    )
    return [pscustomobject]@{
        SubscriptionName = $SubscriptionName
        SubscriptionId   = $SubscriptionId
        ResourceName     = $ResourceName
        ResourceId       = $ResourceId
        ServiceType      = $ServiceType
        CheckCategory    = $CheckCategory
        CheckName        = $CheckName
        Why              = $Why
        CurrentState     = $CurrentState
        Risk             = $Risk
        Severity         = $Severity
        Recommendation   = $Recommendation
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-PrivateEndpointHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [hashtable]$SeverityDistribution,
        [hashtable]$ServiceTypeDistribution,
        [hashtable]$CategoryDistribution,
        [hashtable]$CoverageSummary,
        [array]$SubscriptionResults,
        [string]$GeneratedOn
    )

    $totalFindings = @($Findings).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount = @($Findings | Where-Object { $_.Severity -eq "Info" }).Count

    # ── Finding table rows ────────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $sevCls = switch ($f.Severity) {
            "High" { "badge-red" }
            "Medium" { "badge-amber" }
            "Low" { "badge-green" }
            default { "badge-blue" }
        }
        $nameDisplay = if ($f.CheckName.Length -gt 40) { (EscHtml $f.CheckName.Substring(0, 37)) + "..." } else { EscHtml $f.CheckName }
        $findingRows += @"
          <tr onclick="showFindingDetail($($Findings.IndexOf($f)))">
            <td title="$(EscHtml $f.CheckName)">$nameDisplay</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$(EscHtml $f.ResourceName)</td>
            <td><span class="badge badge-blue">$(EscHtml $f.ServiceType)</span></td>
            <td><span class="badge badge-cyan">$(EscHtml $f.CheckCategory)</span></td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
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

    # ── Severity distribution bars ────────────────────────────────────────────
    $sevTotal = ($SeverityDistribution.Values | Measure-Object -Sum).Sum
    $sevRows = ""
    $sevColors = @{
        "High"   = "var(--red)"
        "Medium" = "var(--amber)"
        "Low"    = "var(--green)"
        "Info"   = "var(--muted)"
    }
    foreach ($sev in @("High", "Medium", "Low", "Info")) {
        if ($SeverityDistribution.ContainsKey($sev)) {
            $val = $SeverityDistribution[$sev]
            $pct = if ($sevTotal -gt 0) { [math]::Round(($val / $sevTotal) * 100) } else { 0 }
            $color = if ($sevColors.ContainsKey($sev)) { $sevColors[$sev] } else { "var(--accent)" }
            $sevRows += @"
          <div class="bar-row">
            <span class="bar-label">$sev</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$color"></div></div>
            <span class="bar-pct">$val ($pct%)</span>
          </div>
"@
        }
    }

    # ── Service type distribution bars ────────────────────────────────────────
    $svcTotal = ($ServiceTypeDistribution.Values | Measure-Object -Sum).Sum
    $svcRows = ""
    foreach ($svc in ($ServiceTypeDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($svcTotal -gt 0) { [math]::Round(($svc.Value / $svcTotal) * 100) } else { 0 }
        $svcRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $svc.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($svc.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Category distribution bars ────────────────────────────────────────────
    $catTotal = ($CategoryDistribution.Values | Measure-Object -Sum).Sum
    $catRows = ""
    $catColors = @{
        "PE Coverage"     = "var(--red)"
        "DNS Integration" = "var(--amber)"
        "Public Access"   = "var(--critical)"
        "Architecture"    = "var(--accent)"
    }
    foreach ($cat in ($CategoryDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($catTotal -gt 0) { [math]::Round(($cat.Value / $catTotal) * 100) } else { 0 }
        $color = if ($catColors.ContainsKey($cat.Key)) { $catColors[$cat.Key] } else { "var(--accent)" }
        $catRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $cat.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$color"></div></div>
            <span class="bar-pct">$($cat.Value) ($pct%)</span>
          </div>
"@
    }

    # ── PE Coverage summary cards ─────────────────────────────────────────────
    $covered = if ($CoverageSummary.ContainsKey("WithPE")) { $CoverageSummary["WithPE"] } else { 0 }
    $notCovered = if ($CoverageSummary.ContainsKey("WithoutPE")) { $CoverageSummary["WithoutPE"] } else { 0 }
    $publicOpen = if ($CoverageSummary.ContainsKey("PublicOpen")) { $CoverageSummary["PublicOpen"] } else { 0 }
    $dnsIssues = if ($CoverageSummary.ContainsKey("DnsIssues")) { $CoverageSummary["DnsIssues"] } else { 0 }

    # ── JSON for detail drawer ────────────────────────────────────────────────
    $findJson = "["
    foreach ($f in $Findings) {
        $findJson += "{" +
        """check"":""$(EscJ $f.CheckName)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """res"":""$(EscJ $f.ResourceName)""," +
        """resId"":""$(EscJ $f.ResourceId)""," +
        """svcType"":""$(EscJ $f.ServiceType)""," +
        """cat"":""$(EscJ $f.CheckCategory)""," +
        """sev"":""$(EscJ $f.Severity)""," +
        """why"":""$(EscJ $f.Why)""," +
        """state"":""$(EscJ $f.CurrentState)""," +
        """risk"":""$(EscJ $f.Risk)""," +
        """rec"":""$(EscJ $f.Recommendation)""" +
        "},"
    }
    $findJson = $findJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Private Endpoint Governance Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;
  --border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;
  --green:#3fb950;--amber:#d29922;--red:#f85149;--critical:#ff6b35;
  --text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);
}
html[data-theme="light"]{
  --bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;
  --border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;
  --green:#1a7f37;--amber:#b08000;--red:#cf222e;--critical:#c0392b;
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
  background:linear-gradient(135deg,var(--accent2),var(--accent3));
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px;}
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
.bar-label{font-size:12px;color:var(--muted2);width:140px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:80px;text-align:right;flex-shrink:0;}
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
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.badge-cyan{background:rgba(57,197,207,.15);color:var(--accent2);border:1px solid rgba(57,197,207,.3);}
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
.sub-name{flex:1;font-size:13px;font-weight:500;}
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
.drawer-field-value{font-size:13px;word-break:break-word;line-height:1.5;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
#toast{
  position:fixed;bottom:24px;right:24px;padding:12px 18px;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);
  font-size:13px;box-shadow:var(--shadow);
  opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:300;
}
#toast.show{opacity:1;transform:translateY(0);}
#menuToggle{display:none;}
@media(max-width:900px){.chart-grid-3{grid-template-columns:1fr 1fr;}}
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
    <div class="logo-icon">🔗</div>
    <div class="logo-title">Private Endpoint Governance</div>
    <div class="logo-sub">Zero Trust Network Architecture</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> All Findings</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">☁️</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Azure PE Governance Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Private Endpoint Governance Assessment</div>
      <div class="page-sub">PaaS connectivity, DNS integration, and public access posture across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_FINDINGS__</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Severity</div>
        <div class="stat-sub">Immediate action</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__INFO_COUNT__</div>
        <div class="stat-label">Info</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__SUB_COUNT__</div>
        <div class="stat-label">Subscriptions</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">🔗 PE Coverage Summary</div>
      <div class="stats-grid" style="margin-bottom:0">
        <div class="stat-card c-green" style="padding:14px">
          <div class="stat-num" style="font-size:24px">__COVERED__</div>
          <div class="stat-label">Resources with PE</div>
        </div>
        <div class="stat-card c-red" style="padding:14px">
          <div class="stat-num" style="font-size:24px">__NOT_COVERED__</div>
          <div class="stat-label">Resources without PE</div>
        </div>
        <div class="stat-card c-amber" style="padding:14px">
          <div class="stat-num" style="font-size:24px">__PUBLIC_OPEN__</div>
          <div class="stat-label">Public Access Still Open</div>
          <div class="stat-sub">PE deployed but public not disabled</div>
        </div>
        <div class="stat-card c-red" style="padding:14px">
          <div class="stat-num" style="font-size:24px">__DNS_ISSUES__</div>
          <div class="stat-label">DNS Integration Issues</div>
        </div>
      </div>
    </div>

    <div class="chart-grid-3">
      <div class="panel">
        <div class="panel-title">⚠️ Severity Distribution</div>
        __SEV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🏷️ By Service Type</div>
        __SVC_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">📂 By Check Category</div>
        __CAT_ROWS__
      </div>
    </div>
  </div>

  <!-- All Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">All Findings</div>
      <div class="page-sub">Click any row for detailed context — why it matters, current state, risk, and recommendation</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search check, resource, subscription…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterSvc" onchange="filterFindings()">
          <option value="">All Service Types</option>
          <option value="Storage">Storage</option>
          <option value="KeyVault">KeyVault</option>
          <option value="SQL">SQL</option>
          <option value="CosmosDB">CosmosDB</option>
          <option value="ACR">ACR</option>
          <option value="AKS">AKS</option>
          <option value="AppService">AppService</option>
          <option value="ServiceBus">ServiceBus</option>
          <option value="EventHub">EventHub</option>
          <option value="AIServices">AIServices</option>
        </select>
        <select class="filter-select" id="filterCat" onchange="filterFindings()">
          <option value="">All Categories</option>
          <option value="PE Coverage">PE Coverage</option>
          <option value="DNS Integration">DNS Integration</option>
          <option value="Public Access">Public Access</option>
          <option value="Architecture">Architecture</option>
        </select>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
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
              <th onclick="sortFindings(0)">Check</th>
              <th onclick="sortFindings(1)">Subscription</th>
              <th onclick="sortFindings(2)">Resource</th>
              <th onclick="sortFindings(3)">Service Type</th>
              <th onclick="sortFindings(4)">Category</th>
              <th onclick="sortFindings(5)">Severity</th>
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
      <div class="page-sub">Per-subscription Private Endpoint governance assessment outcome</div>
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
const FIND_DATA = __FIND_JSON__;
let findFiltered = [...FIND_DATA];
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
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Findings table ─────────────────────────────────────────────────────────
function filterFindings(){
  const q   = document.getElementById('findSearch').value.toLowerCase();
  const svc = document.getElementById('filterSvc').value;
  const cat = document.getElementById('filterCat').value;
  const sv  = document.getElementById('filterSev').value;
  findFiltered = FIND_DATA.filter(r=>{
    const mQ   = !q   || JSON.stringify(r).toLowerCase().includes(q);
    const mSvc = !svc || r.svcType === svc;
    const mCat = !cat || r.cat === cat;
    const mSv  = !sv  || r.sev === sv;
    return mQ && mSvc && mCat && mSv;
  });
  findPage = 1; renderFindings();
}

function changeFindPageSize(){
  findPageSz = parseInt(document.getElementById('pgSizeFind').value);
  findPage   = 1; renderFindings();
}

function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys = ['check','sub','res','svcType','cat','sev'];
  findFiltered.sort((a,b)=>{
    const k=keys[col];
    const av=a[k]??'', bv=b[k]??'';
    return findSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                      :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderFindings();
}

function renderFindings(){
  const tbody = document.getElementById('findBody');
  const start = (findPage-1)*findPageSz;
  const slice = findFiltered.slice(start, start+findPageSz);
  tbody.innerHTML = slice.map(r=>{
    const gi     = FIND_DATA.indexOf(r);
    const sevCls = r.sev==='High'?'badge-red':r.sev==='Medium'?'badge-amber':r.sev==='Low'?'badge-green':'badge-blue';
    const nm     = r.check.length>40?r.check.substring(0,37)+'...':r.check;
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.check)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td>${escH(r.res)}</td>
      <td><span class="badge badge-blue">${escH(r.svcType)}</span></td>
      <td><span class="badge badge-cyan">${escH(r.cat)}</span></td>
      <td><span class="badge ${sevCls}">${escH(r.sev)}</span></td>
    </tr>`;
  }).join('');
  renderFindPg();
}

function renderFindPg(){
  const total = Math.ceil(findFiltered.length/findPageSz);
  const el    = document.getElementById('findPagination');
  let h = `<span>${findFiltered.length} finding(s)</span>`;
  h += `<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,findPage-2), e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h += `<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML = h;
}

function changeFindPage(p){
  const total=Math.ceil(findFiltered.length/findPageSz);
  if(p<1||p>total)return;
  findPage=p; renderFindings();
}

// ── Finding detail drawer ──────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx = idx;
  const r = FIND_DATA[idx];
  if(!r) return;
  document.getElementById('drawerTitle').textContent = r.check;
  document.getElementById('drawerNavInfo').textContent = `${idx+1} of ${FIND_DATA.length}`;
  const sevCls = r.sev==='High'?'badge-red':r.sev==='Medium'?'badge-amber':r.sev==='Low'?'badge-green':'badge-blue';
  document.getElementById('drawerContent').innerHTML = `
    <div class="drawer-field"><div class="drawer-field-label">Service Type</div>
      <div class="drawer-field-value"><span class="badge badge-blue">${escH(r.svcType)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Check Category</div>
      <div class="drawer-field-value"><span class="badge badge-cyan">${escH(r.cat)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sevCls}">${escH(r.sev)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource</div>
      <div class="drawer-field-value">${escH(r.res)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource ID</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.resId)}</div></div>
    <div class="drawer-section">Why This Matters</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.why)}</div></div>
    <div class="drawer-section">Current State</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.state)}</div></div>
    <div class="drawer-section">Risk</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.risk)}</div></div>
    <div class="drawer-section">Recommendation</div>
    <div class="drawer-field"><div class="drawer-field-value">${escH(r.rec)}</div></div>
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

// ── Init ──────────────────────────────────────────────────────────────────
filterFindings();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_FINDINGS__', $totalFindings `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MEDIUM_COUNT__', $mediumCount `
        -replace '__LOW_COUNT__', $lowCount `
        -replace '__INFO_COUNT__', $infoCount `
        -replace '__COVERED__', $covered `
        -replace '__NOT_COVERED__', $notCovered `
        -replace '__PUBLIC_OPEN__', $publicOpen `
        -replace '__DNS_ISSUES__', $dnsIssues `
        -replace '__SEV_ROWS__', $sevRows `
        -replace '__SVC_ROWS__', $svcRows `
        -replace '__CAT_ROWS__', $catRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FIND_JSON__', $findJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzurePrivateEndpointGovernance {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzurePrivateEndpointGovernance-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts", "Az.Network", "Az.Storage", "Az.KeyVault",
        "Az.Sql", "Az.CosmosDB", "Az.ContainerRegistry",
        "Az.Aks", "Az.Websites", "Az.ServiceBus",
        "Az.EventHub", "Az.CognitiveServices", "Az.PrivateDns"
    )
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
        "Export Path"   = if ($ExportToCsv.IsPresent) { $CsvPath }  else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $subscriptionResults = @()
    $severityDist = @{ "High" = 0; "Medium" = 0; "Low" = 0; "Info" = 0 }
    $serviceTypeDist = @{}
    $categoryDist = @{
        "PE Coverage"     = 0
        "DNS Integration" = 0
        "Public Access"   = 0
        "Architecture"    = 0
    }
    $coverageSummary = @{
        "WithPE"     = 0
        "WithoutPE"  = 0
        "PublicOpen" = 0
        "DnsIssues"  = 0
    }
    $successCount = 0
    $errorCount = 0

    # ── Recommended Private DNS zone names per service ────────────────────────
    $recommendedDnsZones = @{
        "Storage"    = @("privatelink.blob.core.windows.net", "privatelink.file.core.windows.net",
            "privatelink.queue.core.windows.net", "privatelink.table.core.windows.net",
            "privatelink.dfs.core.windows.net")
        "KeyVault"   = @("privatelink.vaultcore.azure.net")
        "SQL"        = @("privatelink.database.windows.net")
        "CosmosDB"   = @("privatelink.documents.azure.com", "privatelink.mongo.cosmos.azure.com",
            "privatelink.cassandra.cosmos.azure.com", "privatelink.gremlin.cosmos.azure.com",
            "privatelink.table.cosmos.azure.com")
        "ACR"        = @("privatelink.azurecr.io")
        "AKS"        = @("privatelink.eastus.azmk8s.io")   # region-specific; reported informational
        "AppService" = @("privatelink.azurewebsites.net")
        "ServiceBus" = @("privatelink.servicebus.windows.net")
        "EventHub"   = @("privatelink.servicebus.windows.net")
        "AIServices" = @("privatelink.cognitiveservices.azure.com", "privatelink.openai.azure.com")
    }

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

            # ── Retrieve all Private Endpoints in subscription once ────────────
            $allPes = @()
            try {
                $allPes = @(Get-AzPrivateEndpoint -ErrorAction Stop)
            }
            catch {
                Write-Verbose "  Could not retrieve Private Endpoints for $($sub.Name): $_"
            }

            # ── Retrieve all Private DNS Zones ────────────────────────────────
            $allDnsZones = @()
            try {
                $allDnsZones = @(Get-AzPrivateDnsZone -ErrorAction Stop)
            }
            catch {
                Write-Verbose "  Could not retrieve Private DNS Zones for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # Helper: assess a single resource against PE and DNS posture
            # ────────────────────────────────────────────────────────────────────
            Function Invoke-PeAssessment {
                param(
                    [string]$ResourceName,
                    [string]$ResourceId,
                    [string]$ServiceType,
                    [bool]$PublicAccessEnabled,
                    [string]$PublicAccessNote,
                    [array]$AllPes,
                    [array]$AllDnsZones,
                    [string[]]$RecommendedZones,
                    [string]$SubscriptionName,
                    [string]$SubscriptionId
                )

                $findings = @()

                # Find matching PEs for this resource
                $resourcePes = @(Get-PrivateEndpointConnectionsForResource -ResourceId $ResourceId -AllPrivateEndpoints $AllPes)

                # ── Check A: No Private Endpoint at all ───────────────────────
                if ($resourcePes.Count -eq 0) {
                    $findings += New-PeFinding `
                        -SubscriptionName $SubscriptionName `
                        -SubscriptionId   $SubscriptionId `
                        -ResourceName     $ResourceName `
                        -ResourceId       $ResourceId `
                        -ServiceType      $ServiceType `
                        -CheckCategory    "PE Coverage" `
                        -CheckName        "$ServiceType — No Private Endpoint Deployed" `
                        -Why              "Private Endpoints eliminate public internet exposure of PaaS service endpoints by routing traffic through a private NIC in your VNet. Without a Private Endpoint, the service's data plane is accessible from the internet, subject only to authentication controls — a single credential compromise or token theft grants direct data access across the public internet." `
                        -CurrentState     "$ServiceType resource '$ResourceName' has no Private Endpoint connections. The service data plane is accessible via its public FQDN from any internet location." `
                        -Risk             "Data plane traffic (reads, writes, queries, key operations) traverses the internet rather than the Microsoft backbone. A compromised credential allows exfiltration of all data the identity can access from any location without requiring internal network access." `
                        -Severity         "High" `
                        -Recommendation   "Deploy a Private Endpoint for '$ResourceName' in the workload VNet. After PE deployment, disable public network access on the resource to enforce private-only data plane access. Create a Private DNS Zone ('$($RecommendedZones[0])') linked to the VNet, and associate the PE DNS zone group so that the private FQDN resolves to the PE NIC IP."

                    $script:coverageSummary["WithoutPE"]++
                }
                else {
                    $script:coverageSummary["WithPE"]++

                    # ── Check B: PE exists but connection not Approved ─────────
                    foreach ($pe in $resourcePes) {
                        $approvalStatus = Get-PeApprovalStatus -Pe $pe
                        if ($approvalStatus -eq "Pending") {
                            $findings += New-PeFinding `
                                -SubscriptionName $SubscriptionName `
                                -SubscriptionId   $SubscriptionId `
                                -ResourceName     "$ResourceName (PE: $($pe.Name))" `
                                -ResourceId       $pe.Id `
                                -ServiceType      $ServiceType `
                                -CheckCategory    "PE Coverage" `
                                -CheckName        "$ServiceType — Private Endpoint Connection Pending Approval" `
                                -Why              "A Private Endpoint in Pending state is not routing traffic to the resource — it is functionally equivalent to having no Private Endpoint. Until approved, data plane traffic continues to use the public endpoint." `
                                -CurrentState     "PE '$($pe.Name)' for '$ResourceName' has connection status 'Pending'. Traffic is not yet routed through this private endpoint." `
                                -Risk             "The resource continues to receive traffic via its public FQDN during the Pending window. If approval is delayed or missed, private connectivity never activates and the resource remains publicly exposed." `
                                -Severity         "Medium" `
                                -Recommendation   "Approve the Private Endpoint connection for '$ResourceName' from the resource's Networking > Private Endpoint connections blade. If the connection is no longer needed, remove it. Implement automated PE approval in your deployment pipeline to prevent pending states in production."
                        }
                    }

                    # ── Check C: Public access still enabled (half-deployed) ───
                    if ($PublicAccessEnabled) {
                        $findings += New-PeFinding `
                            -SubscriptionName $SubscriptionName `
                            -SubscriptionId   $SubscriptionId `
                            -ResourceName     $ResourceName `
                            -ResourceId       $ResourceId `
                            -ServiceType      $ServiceType `
                            -CheckCategory    "Public Access" `
                            -CheckName        "$ServiceType — Public Access Enabled Despite Private Endpoint" `
                            -Why              "Deploying a Private Endpoint while leaving public network access enabled is a half-measure. The resource is accessible via both the private endpoint (from the VNet) AND the public FQDN (from the internet). The public path completely negates the benefit of the Private Endpoint for threat actors targeting the service from the internet." `
                            -CurrentState     "$ServiceType resource '$ResourceName' has $($resourcePes.Count) Private Endpoint(s) deployed but public network access remains enabled. $PublicAccessNote" `
                            -Risk             "An attacker with valid credentials can access the resource directly from the internet via the public FQDN, bypassing all network controls. Conditional Access policies and firewall rules on the private path do not protect the public path." `
                            -Severity         "High" `
                            -Recommendation   "Disable public network access on '$ResourceName' after confirming all workloads access it via the Private Endpoint. Test connectivity from the VNet before disabling public access. Set 'publicNetworkAccess' to 'Disabled' or configure the network ACL default action to 'Deny' with no public IP rules."

                        $script:coverageSummary["PublicOpen"]++
                    }

                    # ── Check D: DNS Zone integration missing or incorrect ─────
                    $pe = $resourcePes[0]   # Assess first PE for DNS

                    # Check for DNS zone group on the PE
                    $hasDnsZoneGroup = $pe.PrivateDnsZoneConfigs -and $pe.PrivateDnsZoneConfigs.Count -gt 0

                    # Check whether recommended zone exists in subscription
                    $hasRecommendedZone = $false
                    $matchedZoneName = ""
                    foreach ($zone in $allDnsZones) {
                        foreach ($rec in $RecommendedZones) {
                            if ($zone.Name.ToLower() -like "*$($rec.ToLower())*" -or
                                $zone.Name.ToLower() -eq $rec.ToLower()) {
                                $hasRecommendedZone = $true
                                $matchedZoneName = $zone.Name
                                break
                            }
                        }
                        if ($hasRecommendedZone) { break }
                    }

                    if (-not $hasDnsZoneGroup -and -not $hasRecommendedZone) {
                        $findings += New-PeFinding `
                            -SubscriptionName $SubscriptionName `
                            -SubscriptionId   $SubscriptionId `
                            -ResourceName     "$ResourceName (PE: $($pe.Name))" `
                            -ResourceId       $pe.Id `
                            -ServiceType      $ServiceType `
                            -CheckCategory    "DNS Integration" `
                            -CheckName        "$ServiceType — Missing Private DNS Zone Integration" `
                            -Why              "Without Private DNS integration, the service's FQDN (e.g. mystorageaccount.blob.core.windows.net) continues to resolve to the public IP address even from inside the VNet. Clients connecting to the private FQDN will route traffic out to the internet, defeating the Private Endpoint entirely. Private DNS Zone integration is mandatory for Private Endpoints to function correctly for most services." `
                            -CurrentState     "PE '$($pe.Name)' for '$ResourceName' has no DNS Zone Group configured. No recommended Private DNS Zone found in subscription. Recommended zone name(s): $($RecommendedZones -join ', ')." `
                            -Risk             "DNS resolution from within the VNet returns the public IP of the service rather than the PE NIC private IP. All client connections from the VNet bypass the Private Endpoint and connect via the internet path, leaving the private endpoint functionally unused and the resource publicly exposed to VNet workloads." `
                            -Severity         "High" `
                            -Recommendation   "Create a Private DNS Zone named '$($RecommendedZones[0])' and link it to the VNet. Add a DNS Zone Group to the Private Endpoint '$($pe.Name)' referencing this zone. This will automatically create the A record for the resource's private IP. For hub-spoke topologies, create the zone in the hub subscription and link to all spoke VNets."

                        $script:coverageSummary["DnsIssues"]++
                    }
                    elseif (-not $hasDnsZoneGroup -and $hasRecommendedZone) {
                        $findings += New-PeFinding `
                            -SubscriptionName $SubscriptionName `
                            -SubscriptionId   $SubscriptionId `
                            -ResourceName     "$ResourceName (PE: $($pe.Name))" `
                            -ResourceId       $pe.Id `
                            -ServiceType      $ServiceType `
                            -CheckCategory    "DNS Integration" `
                            -CheckName        "$ServiceType — Private DNS Zone Exists but Not Linked to PE" `
                            -Why              "A Private DNS Zone exists in the subscription but is not associated with the Private Endpoint via a DNS Zone Group. The PE's A record may not be present in the zone, meaning DNS resolution may still return the public IP from within the VNet." `
                            -CurrentState     "PE '$($pe.Name)' for '$ResourceName' has no DNS Zone Group configured. Private DNS Zone '$matchedZoneName' found in subscription but not linked to this PE." `
                            -Risk             "Without the DNS Zone Group, the PE A record may not be automatically created or updated in the Private DNS Zone. Clients in the VNet may resolve to the public IP and route traffic externally." `
                            -Severity         "Medium" `
                            -Recommendation   "Add a DNS Zone Group to PE '$($pe.Name)' referencing the existing Private DNS Zone '$matchedZoneName'. Verify the A record for '$ResourceName' is created in the zone with the correct private IP address."

                        $script:coverageSummary["DnsIssues"]++
                    }
                }

                return $findings
            }

            # ────────────────────────────────────────────────────────────────────
            # S T O R A G E   A C C O U N T S
            # ────────────────────────────────────────────────────────────────────
            try {
                $storageAccounts = @(Get-AzStorageAccount -ErrorAction Stop)
                foreach ($sa in $storageAccounts) {
                    $publicEnabled = $sa.PublicNetworkAccess -ne "Disabled" -and
                    ($null -eq $sa.NetworkRuleSet -or $sa.NetworkRuleSet.DefaultAction -eq "Allow")
                    $publicNote = "PublicNetworkAccess: $($sa.PublicNetworkAccess); DefaultAction: $($sa.NetworkRuleSet.DefaultAction)"

                    $peFindings = Invoke-PeAssessment `
                        -ResourceName       $sa.StorageAccountName `
                        -ResourceId         $sa.Id `
                        -ServiceType        "Storage" `
                        -PublicAccessEnabled $publicEnabled `
                        -PublicAccessNote   $publicNote `
                        -AllPes             $allPes `
                        -AllDnsZones        $allDnsZones `
                        -RecommendedZones   $recommendedDnsZones["Storage"] `
                        -SubscriptionName   $sub.Name `
                        -SubscriptionId     $sub.Id

                    $allFindings += $peFindings
                    $subFindingCount += $peFindings.Count
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Storage Accounts for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # K E Y   V A U L T S
            # ────────────────────────────────────────────────────────────────────
            try {
                $keyVaults = @(Get-AzKeyVault -ErrorAction Stop)
                foreach ($kvRef in $keyVaults) {
                    try {
                        $kv = Get-AzKeyVault -VaultName $kvRef.VaultName -ResourceGroupName $kvRef.ResourceGroupName -ErrorAction Stop
                        $publicEnabled = $kv.PublicNetworkAccess -ne "Disabled" -and
                        ($null -eq $kv.NetworkAcls -or $kv.NetworkAcls.DefaultAction -eq "Allow")
                        $publicNote = "PublicNetworkAccess: $($kv.PublicNetworkAccess)"

                        $peFindings = Invoke-PeAssessment `
                            -ResourceName       $kv.VaultName `
                            -ResourceId         $kv.ResourceId `
                            -ServiceType        "KeyVault" `
                            -PublicAccessEnabled $publicEnabled `
                            -PublicAccessNote   $publicNote `
                            -AllPes             $allPes `
                            -AllDnsZones        $allDnsZones `
                            -RecommendedZones   $recommendedDnsZones["KeyVault"] `
                            -SubscriptionName   $sub.Name `
                            -SubscriptionId     $sub.Id

                        $allFindings += $peFindings
                        $subFindingCount += $peFindings.Count
                    }
                    catch {
                        Write-Verbose "  Could not retrieve Key Vault details for '$($kvRef.VaultName)': $_"
                    }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Key Vaults for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # A Z U R E   S Q L   S E R V E R S
            # ────────────────────────────────────────────────────────────────────
            try {
                $sqlServers = @(Get-AzSqlServer -ErrorAction Stop)
                foreach ($sql in $sqlServers) {
                    $publicEnabled = $sql.PublicNetworkAccess -ne "Disabled"
                    $publicNote = "PublicNetworkAccess: $($sql.PublicNetworkAccess)"

                    $peFindings = Invoke-PeAssessment `
                        -ResourceName       $sql.ServerName `
                        -ResourceId         $sql.ResourceId `
                        -ServiceType        "SQL" `
                        -PublicAccessEnabled $publicEnabled `
                        -PublicAccessNote   $publicNote `
                        -AllPes             $allPes `
                        -AllDnsZones        $allDnsZones `
                        -RecommendedZones   $recommendedDnsZones["SQL"] `
                        -SubscriptionName   $sub.Name `
                        -SubscriptionId     $sub.Id

                    $allFindings += $peFindings
                    $subFindingCount += $peFindings.Count
                }
            }
            catch {
                Write-Verbose "  Could not retrieve SQL Servers for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # C O S M O S   D B
            # ────────────────────────────────────────────────────────────────────
            try {
                $cosmosAccounts = @(Get-AzCosmosDBAccount -ErrorAction Stop)
                foreach ($cosmos in $cosmosAccounts) {
                    $publicEnabled = $cosmos.PublicNetworkAccess -ne "Disabled"
                    $publicNote = "PublicNetworkAccess: $($cosmos.PublicNetworkAccess)"

                    $peFindings = Invoke-PeAssessment `
                        -ResourceName       $cosmos.Name `
                        -ResourceId         $cosmos.Id `
                        -ServiceType        "CosmosDB" `
                        -PublicAccessEnabled $publicEnabled `
                        -PublicAccessNote   $publicNote `
                        -AllPes             $allPes `
                        -AllDnsZones        $allDnsZones `
                        -RecommendedZones   $recommendedDnsZones["CosmosDB"] `
                        -SubscriptionName   $sub.Name `
                        -SubscriptionId     $sub.Id

                    $allFindings += $peFindings
                    $subFindingCount += $peFindings.Count
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Cosmos DB accounts for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # A Z U R E   C O N T A I N E R   R E G I S T R I E S
            # ────────────────────────────────────────────────────────────────────
            try {
                $acrs = @(Get-AzContainerRegistry -ErrorAction Stop)
                foreach ($acr in $acrs) {
                    $publicEnabled = $acr.PublicNetworkAccess -ne "Disabled"
                    $publicNote = "PublicNetworkAccess: $($acr.PublicNetworkAccess); SKU: $($acr.SkuName)"

                    # PE only available on Premium SKU
                    if ($acr.SkuName -ne "Premium") {
                        $allFindings += New-PeFinding `
                            -SubscriptionName $sub.Name `
                            -SubscriptionId   $sub.Id `
                            -ResourceName     $acr.Name `
                            -ResourceId       $acr.Id `
                            -ServiceType      "ACR" `
                            -CheckCategory    "Architecture" `
                            -CheckName        "ACR — Premium SKU Required for Private Endpoint" `
                            -Why              "Azure Container Registry Private Endpoints are only available on the Premium SKU. Basic and Standard ACR SKUs use public endpoints for all registry operations (push, pull, authentication), exposing container image storage to internet-sourced access." `
                            -CurrentState     "ACR '$($acr.Name)' is on SKU '$($acr.SkuName)'. Private Endpoints are not available at this SKU tier." `
                            -Risk             "Container image push and pull operations are performed over the internet. Image content and layer metadata are exposed to traffic interception. Supply-chain attacks targeting the registry are feasible from internet-connected hosts." `
                            -Severity         "Medium" `
                            -Recommendation   "Upgrade '$($acr.Name)' to Premium SKU, then deploy a Private Endpoint and disable public network access. For cost-sensitive environments where Premium SKU is not justifiable, implement IP network rules to restrict access to known CI/CD agent IP ranges and deployment pipeline identities."
                        $subFindingCount++
                    }
                    else {
                        $peFindings = Invoke-PeAssessment `
                            -ResourceName       $acr.Name `
                            -ResourceId         $acr.Id `
                            -ServiceType        "ACR" `
                            -PublicAccessEnabled $publicEnabled `
                            -PublicAccessNote   $publicNote `
                            -AllPes             $allPes `
                            -AllDnsZones        $allDnsZones `
                            -RecommendedZones   $recommendedDnsZones["ACR"] `
                            -SubscriptionName   $sub.Name `
                            -SubscriptionId     $sub.Id

                        $allFindings += $peFindings
                        $subFindingCount += $peFindings.Count
                    }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve ACR registries for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # A K S   C L U S T E R S
            # ────────────────────────────────────────────────────────────────────
            try {
                $aksClusters = @(Get-AzAksCluster -ErrorAction Stop)
                foreach ($aks in $aksClusters) {
                    $apiAccess = Get-ObjProperty -Obj $aks -PropName 'ApiServerAccessProfile' -Default $null
                    $isPrivate = $false
                    $enablePrivate = $false

                    if ($apiAccess) {
                        $enablePrivate = Get-ObjProperty -Obj $apiAccess -PropName 'EnablePrivateCluster' -Default $false
                        $isPrivate = $enablePrivate -eq $true
                    }

                    if (-not $isPrivate) {
                        # Check whether API server is internet-accessible
                        $authorizedRanges = @(Get-ObjProperty -Obj $apiAccess -PropName 'AuthorizedIPRanges' -Default @())
                        $hasIpRanges = $authorizedRanges -and $authorizedRanges.Count -gt 0

                        $sevRating = if (-not $hasIpRanges) { "High" } else { "Medium" }
                        $stateNote = if ($hasIpRanges) { "Authorized IP ranges are configured ($($authorizedRanges.Count) range(s)) but the API server remains public." } else { "No authorized IP ranges configured — API server is open to all internet sources." }

                        $allFindings += New-PeFinding `
                            -SubscriptionName $sub.Name `
                            -SubscriptionId   $sub.Id `
                            -ResourceName     $aks.Name `
                            -ResourceId       $aks.Id `
                            -ServiceType      "AKS" `
                            -CheckCategory    "PE Coverage" `
                            -CheckName        "AKS — API Server Not Private (Public Cluster)" `
                            -Why              "The AKS API server is the control plane for the cluster — it processes all kubectl commands, CI/CD pipeline deployments, and workload scheduling. A public API server is reachable from the internet, creating a persistent high-value attack surface. Private clusters route API server traffic through a Private Endpoint within the VNet, eliminating internet exposure of the cluster control plane." `
                            -CurrentState     "AKS cluster '$($aks.Name)' is a public cluster (EnablePrivateCluster: $enablePrivate). $stateNote" `
                            -Risk             "A public AKS API server is subject to internet-based attack including credential spray against Service Account tokens, exploitation of Kubernetes API vulnerabilities, and unauthorized workload deployment by any actor with valid RBAC permissions from any internet location." `
                            -Severity         $sevRating `
                            -Recommendation   "For new clusters, enable Private Cluster mode during creation (EnablePrivateCluster=true). For existing public clusters, plan migration to private cluster — this requires cluster recreation. As an interim control, configure API server authorized IP ranges to restrict access to VPN/ExpressRoute egress IPs and CI/CD agent public IPs only."

                        $subFindingCount++
                        $coverageSummary["WithoutPE"]++
                    }
                    else {
                        $coverageSummary["WithPE"]++
                        # For private AKS clusters, check Private DNS Zone integration
                        $aksZone = $allDnsZones | Where-Object { $_.Name -like "*.privatelink.*azmk8s.io" -or $_.Name -like "*.private.eastus.azmk8s.io" }
                        if (-not $aksZone) {
                            $allFindings += New-PeFinding `
                                -SubscriptionName $sub.Name `
                                -SubscriptionId   $sub.Id `
                                -ResourceName     $aks.Name `
                                -ResourceId       $aks.Id `
                                -ServiceType      "AKS" `
                                -CheckCategory    "DNS Integration" `
                                -CheckName        "AKS Private Cluster — Private DNS Zone Not Found in Subscription" `
                                -Why              "AKS Private Clusters create a Private Endpoint for the API server and require a Private DNS Zone (e.g. privatelink.<region>.azmk8s.io) to resolve the API server FQDN to the PE private IP. Without this zone linked to the VNet, kubectl and workload tooling cannot reach the API server from within the VNet." `
                                -CurrentState     "AKS cluster '$($aks.Name)' is private but no matching Private DNS Zone (privatelink.*azmk8s.io) found in this subscription." `
                                -Risk             "If the Private DNS Zone is in a different subscription (hub) and not linked to the node pool VNet, nodes and workloads cannot resolve the API server. The zone may exist cross-subscription but is not visible in this scan scope." `
                                -Severity         "Info" `
                                -Recommendation   "Verify the AKS Private DNS Zone is present in the hub subscription and linked to all node pool VNets. For BYO DNS configurations, ensure the custom DNS zone resolves the API server FQDN to the PE private IP from all VNets that require kubectl access."

                            $subFindingCount++
                            $coverageSummary["DnsIssues"]++
                        }
                    }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve AKS clusters for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # A P P   S E R V I C E   /   F U N C T I O N   A P P S
            # ────────────────────────────────────────────────────────────────────
            try {
                $webApps = @(Get-AzWebApp -ErrorAction Stop)
                foreach ($app in $webApps) {
                    # Skip slots and ASE-hosted apps (different isolation model)
                    if ($app.Name -like "*__*") { continue }

                    $publicEnabled = $true   # Default assumption for App Service
                    $publicNote = "App Service public endpoint active (default unless VNet Integration + PE configured)"

                    try {
                        $appConfig = Get-AzWebApp -ResourceGroupName $app.ResourceGroup -Name $app.Name -ErrorAction Stop
                        # If the app has no VNet integration and no PE, it is public
                        $hasVnetInteg = $appConfig.SiteConfig -and $appConfig.VirtualNetworkSubnetId
                        if ($hasVnetInteg) { $publicEnabled = $false }
                    }
                    catch { }

                    $peFindings = Invoke-PeAssessment `
                        -ResourceName       $app.Name `
                        -ResourceId         $app.Id `
                        -ServiceType        "AppService" `
                        -PublicAccessEnabled $publicEnabled `
                        -PublicAccessNote   $publicNote `
                        -AllPes             $allPes `
                        -AllDnsZones        $allDnsZones `
                        -RecommendedZones   $recommendedDnsZones["AppService"] `
                        -SubscriptionName   $sub.Name `
                        -SubscriptionId     $sub.Id

                    $allFindings += $peFindings
                    $subFindingCount += $peFindings.Count
                }
            }
            catch {
                Write-Verbose "  Could not retrieve App Services for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # S E R V I C E   B U S
            # ────────────────────────────────────────────────────────────────────
            try {
                $sbNamespaces = @(Get-AzServiceBusNamespace -ErrorAction Stop)
                foreach ($sb in $sbNamespaces) {
                    $publicEnabled = $sb.PublicNetworkAccess -ne "Disabled"
                    $publicNote = "PublicNetworkAccess: $($sb.PublicNetworkAccess); SKU: $($sb.Sku.Name)"

                    if ($sb.Sku.Name -eq "Basic") {
                        $allFindings += New-PeFinding `
                            -SubscriptionName $sub.Name `
                            -SubscriptionId   $sub.Id `
                            -ResourceName     $sb.Name `
                            -ResourceId       $sb.Id `
                            -ServiceType      "ServiceBus" `
                            -CheckCategory    "Architecture" `
                            -CheckName        "Service Bus — Basic SKU Does Not Support Private Endpoints" `
                            -Why              "Azure Service Bus Private Endpoints require Standard or Premium SKU. Basic SKU namespaces are internet-accessible only, with no private network isolation option. For workloads processing sensitive messages, this represents a data-in-transit exposure risk." `
                            -CurrentState     "Service Bus namespace '$($sb.Name)' is on Basic SKU. Private Endpoints are not supported." `
                            -Risk             "Message broker traffic (send/receive) crosses the internet. Message payloads may contain sensitive business data that could be intercepted or targeted." `
                            -Severity         "Low" `
                            -Recommendation   "Upgrade to Standard or Premium SKU to enable Private Endpoint support. Premium SKU provides dedicated capacity, geo-disaster recovery, and the highest isolation for production workloads. After upgrade, deploy a Private Endpoint and disable public network access."
                        $subFindingCount++
                    }
                    else {
                        $peFindings = Invoke-PeAssessment `
                            -ResourceName       $sb.Name `
                            -ResourceId         $sb.Id `
                            -ServiceType        "ServiceBus" `
                            -PublicAccessEnabled $publicEnabled `
                            -PublicAccessNote   $publicNote `
                            -AllPes             $allPes `
                            -AllDnsZones        $allDnsZones `
                            -RecommendedZones   $recommendedDnsZones["ServiceBus"] `
                            -SubscriptionName   $sub.Name `
                            -SubscriptionId     $sub.Id

                        $allFindings += $peFindings
                        $subFindingCount += $peFindings.Count
                    }
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Service Bus namespaces for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # E V E N T   H U B
            # ────────────────────────────────────────────────────────────────────
            try {
                $ehNamespaces = @(Get-AzEventHubNamespace -ErrorAction Stop)
                foreach ($eh in $ehNamespaces) {
                    $publicEnabled = $eh.PublicNetworkAccess -ne "Disabled"
                    $publicNote = "PublicNetworkAccess: $($eh.PublicNetworkAccess)"

                    $peFindings = Invoke-PeAssessment `
                        -ResourceName       $eh.Name `
                        -ResourceId         $eh.Id `
                        -ServiceType        "EventHub" `
                        -PublicAccessEnabled $publicEnabled `
                        -PublicAccessNote   $publicNote `
                        -AllPes             $allPes `
                        -AllDnsZones        $allDnsZones `
                        -RecommendedZones   $recommendedDnsZones["EventHub"] `
                        -SubscriptionName   $sub.Name `
                        -SubscriptionId     $sub.Id

                    $allFindings += $peFindings
                    $subFindingCount += $peFindings.Count
                }
            }
            catch {
                Write-Verbose "  Could not retrieve Event Hub namespaces for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # A I   S E R V I C E S   /   C O G N I T I V E   S E R V I C E S
            # ────────────────────────────────────────────────────────────────────
            try {
                $aiAccounts = @(Get-AzCognitiveServicesAccount -ErrorAction Stop)
                foreach ($ai in $aiAccounts) {
                    $publicAccess = Get-ObjProperty -Obj $ai.Properties -PropName 'PublicNetworkAccess' -Default "Enabled"
                    $publicEnabled = $publicAccess -ne "Disabled"
                    $publicNote = "PublicNetworkAccess: $publicAccess; Kind: $($ai.Kind)"

                    $peFindings = Invoke-PeAssessment `
                        -ResourceName       $ai.AccountName `
                        -ResourceId         $ai.Id `
                        -ServiceType        "AIServices" `
                        -PublicAccessEnabled $publicEnabled `
                        -PublicAccessNote   $publicNote `
                        -AllPes             $allPes `
                        -AllDnsZones        $allDnsZones `
                        -RecommendedZones   $recommendedDnsZones["AIServices"] `
                        -SubscriptionName   $sub.Name `
                        -SubscriptionId     $sub.Id

                    $allFindings += $peFindings
                    $subFindingCount += $peFindings.Count
                }
            }
            catch {
                Write-Verbose "  Could not retrieve AI/Cognitive Services accounts for $($sub.Name): $_"
            }

            # ────────────────────────────────────────────────────────────────────
            # O R P H A N E D   P R I V A T E   D N S   Z O N E S
            # ────────────────────────────────────────────────────────────────────
            foreach ($zone in $allDnsZones) {
                try {
                    $vnetLinks = @(Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $zone.ResourceGroupName `
                            -ZoneName $zone.Name -ErrorAction Stop)

                    if ($vnetLinks.Count -eq 0) {
                        $allFindings += New-PeFinding `
                            -SubscriptionName $sub.Name `
                            -SubscriptionId   $sub.Id `
                            -ResourceName     $zone.Name `
                            -ResourceId       $zone.ResourceId `
                            -ServiceType      "DNS" `
                            -CheckCategory    "Architecture" `
                            -CheckName        "Private DNS Zone — No VNet Links (Orphaned Zone)" `
                            -Why              "A Private DNS Zone with no VNet links is not resolving any DNS queries for workloads. It exists as dead configuration that incurs cost but provides no DNS resolution — any Private Endpoints associated with it are not being resolved correctly by VNet-connected resources." `
                            -CurrentState     "Private DNS Zone '$($zone.Name)' has zero VNet links. No VNets will use this zone for DNS resolution." `
                            -Risk             "Private Endpoints associated with this unlinked zone will not resolve to private IPs from any VNet. DNS queries will fall through to the public resolver, returning the public IP and routing traffic via the internet path." `
                            -Severity         "Medium" `
                            -Recommendation   "Link '$($zone.Name)' to the relevant VNet(s) using a Private DNS VNet Link. Enable auto-registration if the zone is used for VM DNS. For hub-spoke topologies, link the zone in the hub subscription to all spoke VNets. Delete the zone if it is no longer required."

                        $subFindingCount++
                    }
                }
                catch {
                    Write-Verbose "  Could not retrieve VNet links for DNS Zone '$($zone.Name)': $_"
                }
            }

            # ── Per-subscription result ───────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "PEs: $($allPes.Count)  DNS Zones: $($allDnsZones.Count)  Findings: $subFindingCount" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "PEs: $($allPes.Count)  DNS Zones: $($allDnsZones.Count)  Findings: $subFindingCount"
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

    # ── Aggregate distributions ───────────────────────────────────────────────
    foreach ($f in $allFindings) {
        if ($severityDist.ContainsKey($f.Severity)) { $severityDist[$f.Severity]++ }

        if ($serviceTypeDist.ContainsKey($f.ServiceType)) { $serviceTypeDist[$f.ServiceType]++ }
        else { $serviceTypeDist[$f.ServiceType] = 1 }

        if ($categoryDist.ContainsKey($f.CheckCategory)) { $categoryDist[$f.CheckCategory]++ }
        else { $categoryDist[$f.CheckCategory] = 1 }
    }

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Total Findings"              = $allFindings.Count
            "High Severity"               = $severityDist["High"]
            "Medium Severity"             = $severityDist["Medium"]
            "Low Severity"                = $severityDist["Low"]
            "Informational"               = $severityDist["Info"]
            "Resources with PE"           = $coverageSummary["WithPE"]
            "Resources without PE"        = $coverageSummary["WithoutPE"]
            "Public Access Still Open"    = $coverageSummary["PublicOpen"]
            "DNS Integration Issues"      = $coverageSummary["DnsIssues"]
            "Execution Time"              = $duration
        })

    Write-SeverityBreakdown -Severity $severityDist

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
                $allFindings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
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

            $htmlContent = Generate-PrivateEndpointHtml `
                -SessionInfo              $sessionInfo `
                -ScanParameters           $scanParams `
                -Findings                 $allFindings `
                -SeverityDistribution     $severityDist `
                -ServiceTypeDistribution  $serviceTypeDist `
                -CategoryDistribution     $categoryDist `
                -CoverageSummary          $coverageSummary `
                -SubscriptionResults      $subscriptionResults `
                -GeneratedOn              (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch {
            Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        try {
            $allFindings |
            Select-Object SubscriptionName, ResourceName, ServiceType, CheckCategory, CheckName, Severity, Recommendation |
            Out-GridView -Title "Azure Private Endpoint Governance Assessment"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No PaaS resources found or no findings generated in the targeted subscriptions." -ForegroundColor Yellow
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
