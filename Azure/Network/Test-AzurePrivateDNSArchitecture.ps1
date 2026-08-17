<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 16 August 2026
Modified-On     : 16 August 2026

.SYNOPSIS
    Validates Azure Private DNS architecture — zones, virtual network links, Private
    Endpoint DNS integration, and hub-spoke name-resolution design — across one or
    more subscriptions, identifying Private Link and DNS design issues that would
    cause silent name-resolution failures.

.DESCRIPTION
    Test-AzurePrivateDNSArchitecture evaluates Private DNS and Private Link design
    from a Network/Cloud Architect perspective. Azure Private DNS zone resolution
    does NOT traverse VNet peering automatically — a VNet must have its own explicit
    virtual network link to a zone (or reach a DNS forwarder that does) for name
    resolution to work. This is the most common hub-spoke DNS design defect, and it
    is the central correlation this script performs: it collects zones, virtual
    network links, virtual networks, and Private Endpoints across every scanned
    subscription first, then cross-references them as one hub-spoke topology —
    rather than assessing each subscription in isolation.

    Default assessment:
        - Private DNS Zone inventory: record set count, virtual network link count,
          registration-enabled link count, naming convention compliance against the
          well-known `privatelink.*` zone names Microsoft documents per service
        - Orphaned zones (zero virtual network links) and zones with the identical
          name present in more than one subscription (split-brain resolution risk)
        - Virtual network inventory for any VNet that hosts at least one Private
          Endpoint: custom DNS server configuration, and — the key correlation —
          whether the VNet is directly linked to every zone its Private Endpoints
          depend on
        - Private Endpoint inventory: connection approval state, whether a DNS zone
          group is configured at all, whether the expected canonical zone (resolved
          from the endpoint's private-link `groupId`, e.g. `blob` →
          `privatelink.blob.core.windows.net`) exists anywhere in scope, and whether
          that zone is linked to the endpoint's own VNet
        - Risk-rated findings (High / Medium / Low / Info) with a specific
          recommendation per finding, not just a pass/fail flag

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds —
          hub-spoke correlation works across every subscription in scope, so a hub
          subscription holding the zones and spoke subscriptions holding the VNets
          and Private Endpoints are correlated correctly regardless of which
          subscription each lives in
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of zone, virtual network, and Private Endpoint findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          distribution panels, detail drawer)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied. For
    hub-spoke correlation to be meaningful, the scope must include both the
    subscription(s) hosting the Private DNS zones and the subscription(s) hosting
    the spoke virtual networks and Private Endpoints.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified. Must include the hub subscription for
    zone-to-VNet correlation to resolve correctly.

.PARAMETER ExportToCsv
    Switch. If specified, exports zone, virtual network, and Private Endpoint
    findings to CSV files derived from -CsvPath. The HTML dashboard is always
    generated regardless.

.PARAMETER CsvPath
    Path where the primary (zone) CSV export will be written when -ExportToCsv is
    specified. Also used to derive the virtual network and Private Endpoint CSV
    file names and the HTML dashboard file name (same path, different
    suffix/extension).
    Default: C:\Temp\AzurePrivateDNSArchitecture-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes CSV files when -ExportToCsv
    is specified. Displays results in an interactive Grid View window where a GUI
    is available.

.EXAMPLE
    Test-AzurePrivateDNSArchitecture -AllSubscriptions

.EXAMPLE
    Test-AzurePrivateDNSArchitecture -SubscriptionIds @("hub-sub-id","spoke-sub-id-1","spoke-sub-id-2")

.EXAMPLE
    Test-AzurePrivateDNSArchitecture -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\PrivateDns.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (16-Aug-2026) - Initial release. Multi-subscription hub-spoke Private
                            DNS zone / virtual network link / Private Endpoint
                            correlation, naming-convention validation, orphaned and
                            duplicate zone detection. CSV export and interactive
                            HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.Network,
           Az.PrivateDns) — installed automatically with user consent if not
           present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level across every
           subscription in scope, including the hub subscription hosting the
           Private DNS zones.
        4. For correlation to be meaningful, -AllSubscriptions or -SubscriptionIds
           must include both the hub subscription (zones) and every spoke
           subscription (virtual networks / Private Endpoints) in the topology
           being assessed.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The canonical `privatelink.*` zone-name map covers common PaaS services
          (Storage, Key Vault, SQL, Cosmos DB, App Service, Container Registry,
          Cognitive Services, Event/Service Bus, Redis, PostgreSQL/MySQL Flexible
          Server, Azure AI Search). A Private Endpoint `groupId` outside this map
          is reported as "Unmapped / Not Validated" rather than assumed correct or
          incorrect — never asserted as confirmed when indeterminate.
        - Azure Private DNS Resolver (hybrid/on-premises DNS forwarding) and custom
          DNS server chains are out of scope for this version; a VNet with custom
          DNS servers configured is flagged for manual verification rather than
          validated end-to-end.
        - Correlation is scoped to the subscriptions actually passed to
          -SubscriptionIds or visible under -AllSubscriptions. A hub subscription
          outside the authenticated account's visibility, or omitted from
          -SubscriptionIds, will make in-scope spoke VNets appear unlinked even if
          a link exists there.
        - VNet peering configuration itself is not evaluated — only whether a VNet
          has its own direct Private DNS zone virtual network link, since Private
          DNS resolution does not traverse peering automatically.
        - Interactive Grid View requires a GUI-capable session. Skipped
          gracefully in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/dns/private-dns-privatednszone
    https://learn.microsoft.com/en-us/azure/dns/private-dns-virtual-network-links
    https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns
    https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns-integration

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
  Write-CenteredText "Azure Private DNS Architecture Assessment v1.0" -Color White
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
  param([string]$Title = "Collecting Private DNS Inventory")
  Write-Host ""
  Write-Host "  $Title" -ForegroundColor Cyan
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

Function Write-OutputFiles {
  param(
    [string]$CsvPath,
    [string]$VNetCsvPath,
    [string]$PeCsvPath,
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
    Write-Host ("Zone Findings CSV").PadRight(24) -NoNewline -ForegroundColor Gray
    Write-Host ": $CsvPath" -ForegroundColor White
  }
  if ($VNetCsvPath) {
    Write-Host "  " -NoNewline
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host ("VNet Findings CSV").PadRight(24) -NoNewline -ForegroundColor Gray
    Write-Host ": $VNetCsvPath" -ForegroundColor White
  }
  if ($PeCsvPath) {
    Write-Host "  " -NoNewline
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host ("Private Endpoint CSV").PadRight(24) -NoNewline -ForegroundColor Gray
    Write-Host ": $PeCsvPath" -ForegroundColor White
  }
  if ($HtmlPath) {
    Write-Host "  " -NoNewline
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host ("HTML Dashboard").PadRight(24) -NoNewline -ForegroundColor Gray
    Write-Host ": $HtmlPath" -ForegroundColor White
  }
  if ($GridViewOpened) {
    Write-Host "  " -NoNewline
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host ("Grid View").PadRight(24) -NoNewline -ForegroundColor Gray
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


#------------------------------------------------------------------------ [ Assessment Constants ]

# groupId (lowercase, from a Private Endpoint's privateLinkServiceConnection) → canonical zone name.
# Not exhaustive — see Known Limitations. Region-specific zones (e.g. SQL Managed Instance) are
# intentionally omitted rather than guessed.
$script:PrivateLinkZoneMap = @{
  "blob"             = "privatelink.blob.core.windows.net"
  "blob_secondary"   = "privatelink.blob.core.windows.net"
  "table"            = "privatelink.table.core.windows.net"
  "queue"            = "privatelink.queue.core.windows.net"
  "file"             = "privatelink.file.core.windows.net"
  "web"              = "privatelink.web.core.windows.net"
  "dfs"              = "privatelink.dfs.core.windows.net"
  "vault"            = "privatelink.vaultcore.azure.net"
  "sqlserver"        = "privatelink.database.windows.net"
  "sites"            = "privatelink.azurewebsites.net"
  "registry"         = "privatelink.azurecr.io"
  "account"          = "privatelink.cognitiveservices.azure.com"
  "namespace"        = "privatelink.servicebus.windows.net"
  "rediscache"       = "privatelink.redis.cache.windows.net"
  "postgresqlserver" = "privatelink.postgres.database.azure.com"
  "mysqlserver"      = "privatelink.mysql.database.azure.com"
  "sql"              = "privatelink.documents.azure.com"
  "mongodb"          = "privatelink.mongo.cosmos.azure.com"
  "searchservice"    = "privatelink.search.windows.net"
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-PrivateDnsHtml {
  param(
    [hashtable]$SessionInfo,
    [hashtable]$ScanParameters,
    [array]$ZoneFindings,
    [array]$VNetFindings,
    [array]$PeFindings,
    [hashtable]$RiskDistribution,
    [hashtable]$GapDistribution,
    [array]$SubscriptionResults,
    [string]$GeneratedOn
  )

  $totalZones = @($ZoneFindings).Count
  $totalVNets = @($VNetFindings).Count
  $totalPe = @($PeFindings).Count

  $highCount = @($ZoneFindings + $VNetFindings + $PeFindings | Where-Object { $_.RiskLevel -eq "High" }).Count
  $mediumCount = @($ZoneFindings + $VNetFindings + $PeFindings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
  $orphanZoneCount = @($ZoneFindings | Where-Object { $_.GapCategory -eq "Orphaned Zone (No VNet Links)" }).Count
  $duplicateZoneCount = @($ZoneFindings | Where-Object { $_.GapCategory -eq "Duplicate Zone Name Across Subscriptions" }).Count
  $unlinkedVNetCount = @($VNetFindings | Where-Object { $_.GapCategory -like "*Not Directly Linked*" }).Count
  $peNoZoneGroupCount = @($PeFindings | Where-Object { $_.GapCategory -eq "No DNS Zone Group Configured" }).Count
  $peCompliantCount = @($PeFindings | Where-Object { $_.GapCategory -eq "Compliant" }).Count
  $peCompliancePct = if ($totalPe -gt 0) { [math]::Round(($peCompliantCount / $totalPe) * 100) } else { 0 }

  # ── Zone table rows ────────────────────────────────────────────────────────
  $zoneRows = ""
  foreach ($z in $ZoneFindings) {
    $riskCls = switch ($z.RiskLevel) { "High" { "badge-red" }; "Medium" { "badge-amber" }; "Low" { "badge-blue" }; default { "badge-green" } }
    $zoneRows += @"
          <tr onclick="showZoneDetail($($ZoneFindings.IndexOf($z)))">
            <td title="$(EscHtml $z.ZoneName)">$(if ($z.ZoneName.Length -gt 38) { EscHtml($z.ZoneName.Substring(0,35)+"...") } else { EscHtml $z.ZoneName })</td>
            <td>$(EscHtml $z.SubscriptionName)</td>
            <td>$($z.VNetLinkCount)</td>
            <td>$($z.RecordSetCount)</td>
            <td>$(EscHtml $z.GapCategory)</td>
            <td><span class="badge $riskCls">$(EscHtml $z.RiskLevel)</span></td>
          </tr>
"@
  }

  # ── VNet table rows ────────────────────────────────────────────────────────
  $vnetRows = ""
  foreach ($v in $VNetFindings) {
    $riskCls = switch ($v.RiskLevel) { "High" { "badge-red" }; "Medium" { "badge-amber" }; "Low" { "badge-blue" }; default { "badge-green" } }
    $vnetRows += @"
          <tr onclick="showVnetDetail($($VNetFindings.IndexOf($v)))">
            <td title="$(EscHtml $v.VNetName)">$(EscHtml $v.VNetName)</td>
            <td>$(EscHtml $v.SubscriptionName)</td>
            <td>$($v.PeCount)</td>
            <td>$(EscHtml $v.CustomDnsServers)</td>
            <td>$(EscHtml $v.GapCategory)</td>
            <td><span class="badge $riskCls">$(EscHtml $v.RiskLevel)</span></td>
          </tr>
"@
  }

  # ── Private Endpoint table rows ───────────────────────────────────────────
  $peRows = ""
  foreach ($p in $PeFindings) {
    $riskCls = switch ($p.RiskLevel) { "High" { "badge-red" }; "Medium" { "badge-amber" }; "Low" { "badge-blue" }; default { "badge-green" } }
    $peRows += @"
          <tr onclick="showPeDetail($($PeFindings.IndexOf($p)))">
            <td title="$(EscHtml $p.PeName)">$(if ($p.PeName.Length -gt 32) { EscHtml($p.PeName.Substring(0,29)+"...") } else { EscHtml $p.PeName })</td>
            <td>$(EscHtml $p.SubscriptionName)</td>
            <td>$(EscHtml $p.VNetName)</td>
            <td>$(EscHtml $p.GroupId)</td>
            <td>$(EscHtml $p.ConnectionStatus)</td>
            <td>$(EscHtml $p.GapCategory)</td>
            <td><span class="badge $riskCls">$(EscHtml $p.RiskLevel)</span></td>
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

  # ── Risk distribution bar rows ────────────────────────────────────────────
  $riskTotal = ($RiskDistribution.Values | Measure-Object -Sum).Sum
  $riskRows = ""
  foreach ($r in ($RiskDistribution.GetEnumerator() | Sort-Object Value -Descending)) {
    $pct = if ($riskTotal -gt 0) { [math]::Round(($r.Value / $riskTotal) * 100) } else { 0 }
    $barColor = switch ($r.Key) { "High" { "var(--red)" }; "Medium" { "var(--amber)" }; "Low" { "var(--accent)" }; default { "var(--green)" } }
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

  # ── JSON for detail drawers ───────────────────────────────────────────────
  $zoneJson = "["
  foreach ($z in $ZoneFindings) {
    $zoneJson += "{" +
    """name"":""$(EscJ $z.ZoneName)""," +
    """sub"":""$(EscJ $z.SubscriptionName)""," +
    """rg"":""$(EscJ $z.ResourceGroup)""," +
    """links"":$($z.VNetLinkCount)," +
    """records"":$($z.RecordSetCount)," +
    """naming"":""$(EscJ $z.NamingStatus)""," +
    """gap"":""$(EscJ $z.GapCategory)""," +
    """risk"":""$(EscJ $z.RiskLevel)""," +
    """detail"":""$(EscJ $z.Detail)""," +
    """rec"":""$(EscJ $z.Recommendation)""" +
    "},"
  }
  $zoneJson = $zoneJson.TrimEnd(",") + "]"

  $vnetJson = "["
  foreach ($v in $VNetFindings) {
    $vnetJson += "{" +
    """name"":""$(EscJ $v.VNetName)""," +
    """sub"":""$(EscJ $v.SubscriptionName)""," +
    """rg"":""$(EscJ $v.ResourceGroup)""," +
    """peCount"":$($v.PeCount)," +
    """dns"":""$(EscJ $v.CustomDnsServers)""," +
    """gap"":""$(EscJ $v.GapCategory)""," +
    """risk"":""$(EscJ $v.RiskLevel)""," +
    """detail"":""$(EscJ $v.Detail)""," +
    """rec"":""$(EscJ $v.Recommendation)""" +
    "},"
  }
  $vnetJson = $vnetJson.TrimEnd(",") + "]"

  $peJson = "["
  foreach ($p in $PeFindings) {
    $peJson += "{" +
    """name"":""$(EscJ $p.PeName)""," +
    """sub"":""$(EscJ $p.SubscriptionName)""," +
    """rg"":""$(EscJ $p.ResourceGroup)""," +
    """vnet"":""$(EscJ $p.VNetName)""," +
    """group"":""$(EscJ $p.GroupId)""," +
    """status"":""$(EscJ $p.ConnectionStatus)""," +
    """expectedZone"":""$(EscJ $p.ExpectedZoneName)""," +
    """gap"":""$(EscJ $p.GapCategory)""," +
    """risk"":""$(EscJ $p.RiskLevel)""," +
    """detail"":""$(EscJ $p.Detail)""," +
    """rec"":""$(EscJ $p.Recommendation)""" +
    "},"
  }
  $peJson = $peJson.TrimEnd(",") + "]"

  $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Private DNS Architecture Dashboard</title>
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
.bar-label{font-size:12px;color:var(--muted2);width:220px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
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
    <div class="logo-icon">🌐</div>
    <div class="logo-title">Private DNS Architecture</div>
    <div class="logo-sub">Hub-Spoke DNS Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('zones',this)"><span class="nav-icon">🗂️</span> DNS Zones</button>
    <button class="nav-btn" onclick="showPage('vnets',this)"><span class="nav-icon">🕸️</span> Virtual Networks</button>
    <button class="nav-btn" onclick="showPage('endpoints',this)"><span class="nav-icon">🔗</span> Private Endpoints</button>
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
      Azure Private DNS Architecture Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Private DNS Architecture Overview</div>
      <div class="page-sub">Hub-spoke correlation across __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_ZONES__</div>
        <div class="stat-label">DNS Zones</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__TOTAL_VNETS__</div>
        <div class="stat-label">VNets w/ Private Endpoints</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__TOTAL_PE__</div>
        <div class="stat-label">Private Endpoints</div>
        <div class="stat-sub">__PE_COMPLIANCE_PCT__% fully compliant</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Risk</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium Risk</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__ORPHAN_ZONE_COUNT__</div>
        <div class="stat-label">Orphaned Zones</div>
        <div class="stat-sub">__DUPLICATE_ZONE_COUNT__ duplicate name(s)</div>
      </div>
    </div>

    <div class="stats-grid" style="margin-bottom:18px;">
      <div class="stat-card c-red"><div class="stat-num">__UNLINKED_VNET_COUNT__</div><div class="stat-label">VNets Not Linked to Required Zone</div></div>
      <div class="stat-card c-red"><div class="stat-num">__PE_NO_ZONEGROUP_COUNT__</div><div class="stat-label">Private Endpoints w/o DNS Zone Group</div></div>
    </div>

    <div class="chart-grid">
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

  <!-- DNS Zones -->
  <div id="page-zones" class="page">
    <div class="page-header">
      <div class="page-title">Private DNS Zones</div>
      <div class="page-sub">Click any row for details. A zone with zero virtual network links cannot resolve names anywhere.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="zoneSearch" placeholder="Search zone, subscription…" oninput="filterZone()"/>
        </div>
        <select class="filter-select" id="filterZoneRisk" onchange="filterZone()">
          <option value="">All Risk Levels</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="zoneTable">
          <thead>
            <tr>
              <th onclick="sortZone(0)">Zone Name</th>
              <th onclick="sortZone(1)">Subscription</th>
              <th onclick="sortZone(2)">VNet Links</th>
              <th onclick="sortZone(3)">Record Sets</th>
              <th onclick="sortZone(4)">Gap Category</th>
              <th onclick="sortZone(5)">Risk</th>
            </tr>
          </thead>
          <tbody id="zoneBody">__ZONE_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="zonePagination"></div>
    </div>
  </div>

  <!-- Virtual Networks -->
  <div id="page-vnets" class="page">
    <div class="page-header">
      <div class="page-title">Virtual Networks (Hosting Private Endpoints)</div>
      <div class="page-sub">Private DNS resolution does not traverse VNet peering — each VNet needs its own zone link</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="vnetSearch" placeholder="Search VNet, subscription…" oninput="filterVnet()"/>
        </div>
      </div>
      <div class="tbl-wrap">
        <table id="vnetTable">
          <thead>
            <tr>
              <th onclick="sortVnet(0)">VNet Name</th>
              <th onclick="sortVnet(1)">Subscription</th>
              <th onclick="sortVnet(2)">Private Endpoints</th>
              <th onclick="sortVnet(3)">Custom DNS Servers</th>
              <th onclick="sortVnet(4)">Gap Category</th>
              <th onclick="sortVnet(5)">Risk</th>
            </tr>
          </thead>
          <tbody id="vnetBody">__VNET_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="vnetPagination"></div>
    </div>
  </div>

  <!-- Private Endpoints -->
  <div id="page-endpoints" class="page">
    <div class="page-header">
      <div class="page-title">Private Endpoints</div>
      <div class="page-sub">DNS zone-group integration status per Private Endpoint</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="peSearch" placeholder="Search endpoint, VNet…" oninput="filterPe()"/>
        </div>
        <select class="filter-select" id="filterPeRisk" onchange="filterPe()">
          <option value="">All Risk Levels</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="peTable">
          <thead>
            <tr>
              <th onclick="sortPe(0)">Endpoint Name</th>
              <th onclick="sortPe(1)">Subscription</th>
              <th onclick="sortPe(2)">VNet</th>
              <th onclick="sortPe(3)">Group ID</th>
              <th onclick="sortPe(4)">Connection</th>
              <th onclick="sortPe(5)">Gap Category</th>
              <th onclick="sortPe(6)">Risk</th>
            </tr>
          </thead>
          <tbody id="peBody">__PE_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="pePagination"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription Private DNS inventory collection outcome</div>
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
    <span class="drawer-title" id="drawerTitle">Detail</span>
    <button class="drawer-close" onclick="closeDrawer()">✕</button>
  </div>
  <div class="drawer-body">
    <div id="drawerContent"></div>
  </div>
</div>

<div id="toast"></div>

<script>
const ZONE_DATA = __ZONE_JSON__;
const VNET_DATA = __VNET_JSON__;
const PE_DATA = __PE_JSON__;
let zoneFiltered=[...ZONE_DATA], zonePage=1, zonePageSz=25, zoneSortCol=-1, zoneSortAsc=true;
let vnetFiltered=[...VNET_DATA], vnetPage=1, vnetPageSz=25, vnetSortCol=-1, vnetSortAsc=true;
let peFiltered=[...PE_DATA], pePage=1, pePageSz=25, peSortCol=-1, peSortAsc=true;

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

function riskCls(r){return r==='High'?'badge-red':r==='Medium'?'badge-amber':r==='Low'?'badge-blue':'badge-green';}

// ── Zones table ────────────────────────────────────────────────────────────
function filterZone(){
  const q=document.getElementById('zoneSearch').value.toLowerCase();
  const r=document.getElementById('filterZoneRisk').value;
  zoneFiltered=ZONE_DATA.filter(x=>{
    const mQ=!q||JSON.stringify(x).toLowerCase().includes(q);
    const mR=!r||x.risk===r;
    return mQ&&mR;
  });
  zonePage=1; renderZone();
}
function sortZone(col){
  if(zoneSortCol===col){zoneSortAsc=!zoneSortAsc;}else{zoneSortCol=col;zoneSortAsc=true;}
  const keys=['name','sub','links','records','gap','risk'];
  zoneFiltered.sort((a,b)=>{const k=keys[col];const av=a[k]??'',bv=b[k]??'';
    return zoneSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true}):String(bv).localeCompare(String(av),undefined,{numeric:true});});
  renderZone();
}
function renderZone(){
  const tbody=document.getElementById('zoneBody');
  const start=(zonePage-1)*zonePageSz;
  const slice=zoneFiltered.slice(start,start+zonePageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=ZONE_DATA.indexOf(r);
    const nm=r.name.length>38?r.name.substring(0,35)+'...':r.name;
    return `<tr onclick="showZoneDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td><td>${escH(r.sub)}</td><td>${r.links}</td><td>${r.records}</td>
      <td>${escH(r.gap)}</td><td><span class="badge ${riskCls(r.risk)}">${escH(r.risk)}</span></td></tr>`;
  }).join('');
  renderPg('zone',zoneFiltered,zonePage,zonePageSz,'zonePagination','changeZonePage');
}
function changeZonePage(p){const total=Math.ceil(zoneFiltered.length/zonePageSz);if(p<1||p>total)return;zonePage=p;renderZone();}

function showZoneDetail(idx){
  const r=ZONE_DATA[idx]; if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Risk Level</div><div class="drawer-field-value"><span class="badge ${riskCls(r.risk)}">${escH(r.risk)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div><div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Virtual Network Links</div><div class="drawer-field-value">${r.links}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Record Sets</div><div class="drawer-field-value">${r.records}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Naming Convention</div><div class="drawer-field-value">${escH(r.naming)}</div></div>
    <div class="drawer-section">Detail</div><div class="drawer-field"><div class="drawer-field-value">${escH(r.detail)}</div></div>
    <div class="drawer-section">Recommendation</div><div class="drawer-field"><div class="drawer-field-value">${escH(r.rec)}</div></div>`;
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}

// ── VNets table ────────────────────────────────────────────────────────────
function filterVnet(){
  const q=document.getElementById('vnetSearch').value.toLowerCase();
  vnetFiltered=VNET_DATA.filter(x=>!q||JSON.stringify(x).toLowerCase().includes(q));
  vnetPage=1; renderVnet();
}
function sortVnet(col){
  if(vnetSortCol===col){vnetSortAsc=!vnetSortAsc;}else{vnetSortCol=col;vnetSortAsc=true;}
  const keys=['name','sub','peCount','dns','gap','risk'];
  vnetFiltered.sort((a,b)=>{const k=keys[col];const av=a[k]??'',bv=b[k]??'';
    return vnetSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true}):String(bv).localeCompare(String(av),undefined,{numeric:true});});
  renderVnet();
}
function renderVnet(){
  const tbody=document.getElementById('vnetBody');
  const start=(vnetPage-1)*vnetPageSz;
  const slice=vnetFiltered.slice(start,start+vnetPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=VNET_DATA.indexOf(r);
    return `<tr onclick="showVnetDetail(${gi})">
      <td>${escH(r.name)}</td><td>${escH(r.sub)}</td><td>${r.peCount}</td><td>${escH(r.dns)}</td>
      <td>${escH(r.gap)}</td><td><span class="badge ${riskCls(r.risk)}">${escH(r.risk)}</span></td></tr>`;
  }).join('');
  renderPg('vnet',vnetFiltered,vnetPage,vnetPageSz,'vnetPagination','changeVnetPage');
}
function changeVnetPage(p){const total=Math.ceil(vnetFiltered.length/vnetPageSz);if(p<1||p>total)return;vnetPage=p;renderVnet();}

function showVnetDetail(idx){
  const r=VNET_DATA[idx]; if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Risk Level</div><div class="drawer-field-value"><span class="badge ${riskCls(r.risk)}">${escH(r.risk)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div><div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Private Endpoints Hosted</div><div class="drawer-field-value">${r.peCount}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Custom DNS Servers</div><div class="drawer-field-value">${escH(r.dns)}</div></div>
    <div class="drawer-section">Detail</div><div class="drawer-field"><div class="drawer-field-value">${escH(r.detail)}</div></div>
    <div class="drawer-section">Recommendation</div><div class="drawer-field"><div class="drawer-field-value">${escH(r.rec)}</div></div>`;
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}

// ── Private Endpoints table ───────────────────────────────────────────────
function filterPe(){
  const q=document.getElementById('peSearch').value.toLowerCase();
  const r=document.getElementById('filterPeRisk').value;
  peFiltered=PE_DATA.filter(x=>{
    const mQ=!q||JSON.stringify(x).toLowerCase().includes(q);
    const mR=!r||x.risk===r;
    return mQ&&mR;
  });
  pePage=1; renderPe();
}
function sortPe(col){
  if(peSortCol===col){peSortAsc=!peSortAsc;}else{peSortCol=col;peSortAsc=true;}
  const keys=['name','sub','vnet','group','status','gap','risk'];
  peFiltered.sort((a,b)=>{const k=keys[col];const av=a[k]??'',bv=b[k]??'';
    return peSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true}):String(bv).localeCompare(String(av),undefined,{numeric:true});});
  renderPe();
}
function renderPe(){
  const tbody=document.getElementById('peBody');
  const start=(pePage-1)*pePageSz;
  const slice=peFiltered.slice(start,start+pePageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=PE_DATA.indexOf(r);
    const nm=r.name.length>32?r.name.substring(0,29)+'...':r.name;
    return `<tr onclick="showPeDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td><td>${escH(r.sub)}</td><td>${escH(r.vnet)}</td><td>${escH(r.group)}</td>
      <td>${escH(r.status)}</td><td>${escH(r.gap)}</td><td><span class="badge ${riskCls(r.risk)}">${escH(r.risk)}</span></td></tr>`;
  }).join('');
  renderPg('pe',peFiltered,pePage,pePageSz,'pePagination','changePePage');
}
function changePePage(p){const total=Math.ceil(peFiltered.length/pePageSz);if(p<1||p>total)return;pePage=p;renderPe();}

function showPeDetail(idx){
  const r=PE_DATA[idx]; if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Risk Level</div><div class="drawer-field-value"><span class="badge ${riskCls(r.risk)}">${escH(r.risk)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div><div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Virtual Network</div><div class="drawer-field-value">${escH(r.vnet)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Private Link Group ID</div><div class="drawer-field-value">${escH(r.group)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Connection Status</div><div class="drawer-field-value">${escH(r.status)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Expected Canonical Zone</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.expectedZone)}</div></div>
    <div class="drawer-section">Detail</div><div class="drawer-field"><div class="drawer-field-value">${escH(r.detail)}</div></div>
    <div class="drawer-section">Recommendation</div><div class="drawer-field"><div class="drawer-field-value">${escH(r.rec)}</div></div>`;
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}

function closeDrawer(){
  document.getElementById('drawerBackdrop').style.display='none';
  document.getElementById('detailDrawer').classList.remove('open');
}

// ── Shared pagination renderer ────────────────────────────────────────────
function renderPg(prefix,filtered,page,pageSz,elId,fnName){
  const total=Math.ceil(filtered.length/pageSz);
  const el=document.getElementById(elId);
  let h=`<span>${filtered.length} item(s)</span>`;
  h+=`<button class="pg-btn" onclick="${fnName}(${page-1})" ${page<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,page-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===page?'active':''}" onclick="${fnName}(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="${fnName}(${page+1})" ${page>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{ el.style.width=el.dataset.pct+'%'; });
  });
}

document.addEventListener('keydown',e=>{ if(e.key==='Escape') closeDrawer(); });

// ── Init ─────────────────────────────────────────────────────────────────────
filterZone();
filterVnet();
filterPe();
animateBars();
</script>
</body>
</html>
'@

  $html = $html `
    -replace '__GENERATED_ON__', $GeneratedOn `
    -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
    -replace '__TOTAL_ZONES__', $totalZones `
    -replace '__TOTAL_VNETS__', $totalVNets `
    -replace '__TOTAL_PE__', $totalPe `
    -replace '__PE_COMPLIANCE_PCT__', $peCompliancePct `
    -replace '__HIGH_COUNT__', $highCount `
    -replace '__MEDIUM_COUNT__', $mediumCount `
    -replace '__ORPHAN_ZONE_COUNT__', $orphanZoneCount `
    -replace '__DUPLICATE_ZONE_COUNT__', $duplicateZoneCount `
    -replace '__UNLINKED_VNET_COUNT__', $unlinkedVNetCount `
    -replace '__PE_NO_ZONEGROUP_COUNT__', $peNoZoneGroupCount `
    -replace '__RISK_ROWS__', $riskRows `
    -replace '__GAP_ROWS__', $gapRows `
    -replace '__ZONE_ROWS__', $zoneRows `
    -replace '__VNET_ROWS__', $vnetRows `
    -replace '__PE_ROWS__', $peRows `
    -replace '__SUB_ROWS__', $subRows `
    -replace '__TENANT__', $SessionInfo.Tenant `
    -replace '__ACCOUNT__', $SessionInfo.Account `
    -replace '__ENVIRONMENT__', $SessionInfo.Environment `
    -replace '__SCOPE__', $ScanParameters.Scope `
    -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
    -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
    -replace '__ZONE_JSON__', $zoneJson `
    -replace '__VNET_JSON__', $vnetJson `
    -replace '__PE_JSON__', $peJson

  return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Test-AzurePrivateDNSArchitecture {
  [CmdletBinding(DefaultParameterSetName = 'AllSubscriptions')]
  param (
    # ── Scope ────────────────────────────────────────────────────────────
    [Parameter(ParameterSetName = 'AllSubscriptions')]
    [switch]$AllSubscriptions,

    [Parameter(ParameterSetName = 'SpecificSubscriptions', Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$SubscriptionIds,

    # ── Output ───────────────────────────────────────────────────────────
    [switch]$ExportToCsv,

    [ValidateNotNullOrEmpty()]
    [string]$CsvPath = "C:\Temp\AzurePrivateDNSArchitecture-Report.csv"
  )

  #-------------------------------------------------------------------- [ Init ]

  $startTime = Get-Date
  Write-Banner

  # ── Module check ─────────────────────────────────────────────────────────
  $requiredModules = @('Az.Accounts', 'Az.Resources', 'Az.Network', 'Az.PrivateDns')
  $missingModules = @()

  foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
      $missingModules += $mod
    }
  }

  if ($missingModules.Count -gt 0) {
    Write-Host ""
    Write-Host "  Required modules not found: $($missingModules -join ', ')" -ForegroundColor Yellow
    Write-Host "  Install them? This requires an elevated session." -ForegroundColor Gray
    Write-Host ""
    $answer = Read-Host "  Install missing modules now? [Y/N]"
    if ($answer -match '^[Yy]') {
      foreach ($mod in $missingModules) {
        Write-Host "  Installing $mod..." -ForegroundColor Cyan
        try {
          Install-Module -Name $mod -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
          Write-Host "  ✓ $mod installed." -ForegroundColor Green
        }
        catch {
          Write-Warning "  Failed to install $mod. Error: $_"
          Write-Host "  Aborting — install the module manually and re-run." -ForegroundColor Red
          return
        }
      }
    }
    else {
      Write-Host "  Aborting — install the required modules and re-run." -ForegroundColor Red
      return
    }
  }

  # ── Session check ────────────────────────────────────────────────────────
  $context = $null
  try {
    $context = Get-AzContext -ErrorAction Stop
  }
  catch { }

  if (-not $context -or -not $context.Account) {
    Write-Host ""
    Write-Host "  No active Azure session detected. Connecting..." -ForegroundColor Yellow
    try {
      Connect-AzAccount -ErrorAction Stop | Out-Null
      $context = Get-AzContext -ErrorAction Stop
    }
    catch {
      Write-Error "  Authentication failed: $_"
      return
    }
  }

  $sessionInfo = @{
    Tenant      = if ($context.Tenant.Id) { $context.Tenant.Id } else { "N/A" }
    Account     = if ($context.Account.Id) { $context.Account.Id } else { "N/A" }
    Environment = if ($context.Environment.Name) { $context.Environment.Name } else { "N/A" }
  }

  Write-Section -Title "Session Information" -Data ([ordered]@{
      "Account"     = $sessionInfo.Account
      "Tenant"      = $sessionInfo.Tenant
      "Environment" = $sessionInfo.Environment
    })

  # ── Resolve output paths ─────────────────────────────────────────────────
  $baseName = [System.IO.Path]::GetFileNameWithoutExtension($CsvPath)
  $baseDir = [System.IO.Path]::GetDirectoryName($CsvPath)
  if ([string]::IsNullOrWhiteSpace($baseDir)) { $baseDir = (Get-Location).Path }
  $vnetCsvPath = [System.IO.Path]::Combine($baseDir, "${baseName}-VNet.csv")
  $peCsvPath = [System.IO.Path]::Combine($baseDir, "${baseName}-PrivateEndpoints.csv")
  $htmlPath = [System.IO.Path]::Combine($baseDir, "${baseName}.html")

  if (-not (Test-Path $baseDir)) {
    try { New-Item -ItemType Directory -Path $baseDir -Force | Out-Null }
    catch {
      Write-Error "Cannot create output directory '$baseDir': $_"
      return
    }
  }

  # ── Resolve subscription list ─────────────────────────────────────────────
  $subscriptions = @()
  try {
    if ($PSCmdlet.ParameterSetName -eq 'SpecificSubscriptions') {
      foreach ($subId in $SubscriptionIds) {
        $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue
        if ($sub) { $subscriptions += $sub }
        else { Write-Warning "  Subscription '$subId' not found or not accessible — skipped." }
      }
    }
    else {
      $subscriptions = @(Get-AzSubscription -ErrorAction Stop |
        Where-Object { $_.State -eq 'Enabled' })
    }
  }
  catch {
    Write-Error "Failed to retrieve subscriptions: $_"
    return
  }

  if ($subscriptions.Count -eq 0) {
    Write-Warning "No accessible subscriptions found in scope. Exiting."
    return
  }

  $scopeLabel = if ($PSCmdlet.ParameterSetName -eq 'SpecificSubscriptions')
  { "Specific ($($subscriptions.Count) subscription(s))" }
  else
  { "All Subscriptions ($($subscriptions.Count) found)" }

  Write-Section -Title "Scan Parameters" -Data ([ordered]@{
      "Scope"          = $scopeLabel
      "Export to CSV"  = $ExportToCsv.IsPresent
      "CSV Path"       = $CsvPath
      "HTML Dashboard" = $htmlPath
    })

  #-------------------------------------------------------------------- [ Phase 1: Inventory Collection ]

  Write-ScanProgress -Title "Phase 1 — Collecting Private DNS Inventory Across Subscriptions"

  # Cross-subscription data stores — used for hub-spoke correlation in Phase 2
  $allZones = [System.Collections.Generic.List[hashtable]]::new()
  $allVNetLinks = [System.Collections.Generic.List[hashtable]]::new()
  $allVNetsWithPe = [System.Collections.Generic.List[hashtable]]::new()
  $allPrivateEndpoints = [System.Collections.Generic.List[hashtable]]::new()
  $subscriptionResults = [System.Collections.Generic.List[hashtable]]::new()

  $subTotal = $subscriptions.Count
  $subIdx = 0

  foreach ($sub in $subscriptions) {
    $subIdx++
    $subName = if ($sub.Name) { $sub.Name } else { $sub.Id }
    $subId = $sub.Id

    Write-ProgressBar -Current $subIdx -Total $subTotal -CurrentItem $subName

    $subResult = @{
      Name    = $subName
      Id      = $subId
      Status  = "Success"
      Summary = ""
      Zones   = 0
      VNets   = 0
      PEs     = 0
    }

    try {
      Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
    }
    catch {
      $subResult.Status = "Error"
      $subResult.Summary = "Cannot switch context: $_"
      $subscriptionResults.Add($subResult)
      Write-Warning "`n  ✗ Skipping '$subName': cannot set context."
      continue
    }

    # ── Private DNS Zones ─────────────────────────────────────────────────
    $zones = @()
    try {
      $zones = @(Get-AzPrivateDnsZone -ErrorAction Stop)
    }
    catch {
      Write-Verbose "  Could not enumerate Private DNS zones in '$subName': $_"
    }

    foreach ($zone in $zones) {
      $links = @()
      try {
        $links = @(Get-AzPrivateDnsVirtualNetworkLink `
            -ResourceGroupName $zone.ResourceGroupName `
            -ZoneName          $zone.Name `
            -ErrorAction       Stop)
      }
      catch {
        Write-Verbose "  Could not enumerate links for zone '$($zone.Name)': $_"
      }

      $recordSetCount = 0
      try {
        $recordSetCount = @(Get-AzPrivateDnsRecordSet `
            -ResourceGroupName $zone.ResourceGroupName `
            -ZoneName          $zone.Name `
            -ErrorAction       Stop |
          Where-Object { $_.Name -ne '@' }).Count
      }
      catch {
        Write-Verbose "  Could not enumerate record sets for '$($zone.Name)': $_"
      }

      $registrationLinks = @($links | Where-Object { $_.RegistrationEnabled -eq $true })

      $allZones.Add(@{
          ZoneName              = $zone.Name
          SubscriptionName      = $subName
          SubscriptionId        = $subId
          ResourceGroup         = $zone.ResourceGroupName
          VNetLinkCount         = $links.Count
          RecordSetCount        = $recordSetCount
          RegistrationEnabled   = $registrationLinks.Count -gt 0
          RegistrationLinkCount = $registrationLinks.Count
          LinkedVNetIds         = @($links | ForEach-Object {
              if ($_.VirtualNetworkId) { $_.VirtualNetworkId.ToLower() }
            })
        })

      foreach ($lnk in $links) {
        $allVNetLinks.Add(@{
            ZoneName            = $zone.Name
            ZoneSubId           = $subId
            VNetId              = if ($lnk.VirtualNetworkId) { $lnk.VirtualNetworkId.ToLower() } else { "" }
            RegistrationEnabled = $lnk.RegistrationEnabled
          })
      }

      $subResult.Zones++
    }

    # ── Virtual Networks hosting Private Endpoints ────────────────────────
    $allPeInSub = @()
    try {
      $allPeInSub = @(Get-AzPrivateEndpoint -ErrorAction Stop)
    }
    catch {
      Write-Verbose "  Could not enumerate Private Endpoints in '$subName': $_"
    }

    # Group PEs by VNet
    $peByVNet = @{}
    foreach ($pe in $allPeInSub) {
      $vnetId = ""
      try {
        # Subnet is /subscriptions/.../virtualNetworks/<name>/subnets/<name>
        $subnetId = $pe.Subnet.Id
        if ($subnetId) {
          $parts = $subnetId -split '/'
          $vIdx = [Array]::IndexOf($parts, 'virtualNetworks')
          if ($vIdx -ge 0) {
            # Reconstruct VNet resource ID (up to and including VNet name)
            $vnetId = ($parts[0..($vIdx + 1)] -join '/').ToLower()
          }
        }
      }
      catch { }

      if (-not $peByVNet.ContainsKey($vnetId)) { $peByVNet[$vnetId] = [System.Collections.Generic.List[object]]::new() }
      $peByVNet[$vnetId].Add($pe)
    }

    foreach ($vnetId in $peByVNet.Keys) {
      $pesInVNet = $peByVNet[$vnetId]
      $firstPe = $pesInVNet[0]

      # Retrieve the VNet to get custom DNS configuration
      $vnet = $null
      $dnsLabel = "Azure-Provided (Default)"
      $dnsServers = @()
      try {
        if ($vnetId) {
          $vnet = Get-AzResource -ResourceId ($peByVNet.Keys |
            Where-Object { $_ -eq $vnetId } |
            Select-Object -First 1) -ErrorAction SilentlyContinue

          if (-not $vnet) {
            # Parse subscription, RG and VNet name from ID to use Get-AzVirtualNetwork
            $parts = $vnetId -split '/'
            $vRgIdx = [Array]::IndexOf($parts, 'resourcegroups')
            $vNmIdx = [Array]::IndexOf($parts, 'virtualnetworks')
            if ($vRgIdx -ge 0 -and $vNmIdx -ge 0) {
              $vnetRg = $parts[$vRgIdx + 1]
              $vnetName = $parts[$vNmIdx + 1]
              $vnet = Get-AzVirtualNetwork -ResourceGroupName $vnetRg -Name $vnetName -ErrorAction SilentlyContinue
            }
          }

          if ($vnet -and $vnet.DhcpOptions -and $vnet.DhcpOptions.DnsServers -and $vnet.DhcpOptions.DnsServers.Count -gt 0) {
            $dnsServers = $vnet.DhcpOptions.DnsServers
            $dnsLabel = $dnsServers -join '; '
          }
        }
      }
      catch {
        Write-Verbose "  Could not retrieve VNet details for '$vnetId': $_"
      }

      $parts2 = $vnetId -split '/'
      $vNmIdx2 = [Array]::IndexOf($parts2, 'virtualnetworks')
      $vnetName = if ($vNmIdx2 -ge 0) { $parts2[$vNmIdx2 + 1] } else { $vnetId }
      $vRgIdx2 = [Array]::IndexOf($parts2, 'resourcegroups')
      $vnetRg = if ($vRgIdx2 -ge 0) { $parts2[$vRgIdx2 + 1] } else { "Unknown" }

      $allVNetsWithPe.Add(@{
          VNetId           = $vnetId
          VNetName         = $vnetName
          ResourceGroup    = $vnetRg
          SubscriptionName = $subName
          SubscriptionId   = $subId
          DnsServers       = $dnsServers
          CustomDnsLabel   = $dnsLabel
          PeCount          = $pesInVNet.Count
        })

      $subResult.VNets++
    }

    # ── Private Endpoints (detailed) ─────────────────────────────────────
    foreach ($pe in $allPeInSub) {
      $groupId = ""
      $connStatus = "Unknown"
      $hasZoneGroup = $false

      try {
        # groupId from first private-link service connection
        $conn = $pe.PrivateLinkServiceConnections | Select-Object -First 1
        if (-not $conn) { $conn = $pe.ManualPrivateLinkServiceConnections | Select-Object -First 1 }
        if ($conn) {
          $gids = $conn.GroupIds
          if ($gids -and $gids.Count -gt 0) { $groupId = $gids[0].ToLower() }
          $connStatus = if ($conn.PrivateLinkServiceConnectionState)
          { $conn.PrivateLinkServiceConnectionState.Status } else { "Unknown" }
        }
      }
      catch { Write-Verbose "  Could not parse PE connection: $($pe.Name) — $_" }

      try {
        $hasZoneGroup = ($pe.CustomDnsConfigs -and $pe.CustomDnsConfigs.Count -gt 0) -or
        ($pe.PrivateDnsZoneGroups -and $pe.PrivateDnsZoneGroups.Count -gt 0)
      }
      catch { }

      # Derive VNet ID
      $peVNetId = ""
      $peVNetName = "Unknown"
      try {
        $subnetId = $pe.Subnet.Id
        if ($subnetId) {
          $parts = $subnetId -split '/'
          $vIdx = [Array]::IndexOf($parts, 'virtualNetworks')
          if ($vIdx -ge 0) {
            $peVNetId = ($parts[0..($vIdx + 1)] -join '/').ToLower()
            $peVNetName = $parts[$vIdx + 1]
          }
        }
      }
      catch { }

      $expectedZone = if ($groupId -and $script:PrivateLinkZoneMap.ContainsKey($groupId))
      { $script:PrivateLinkZoneMap[$groupId] }
      else { "Unmapped / Not Validated" }

      $peRg = if ($pe.ResourceGroupName) { $pe.ResourceGroupName } else { "Unknown" }

      $allPrivateEndpoints.Add(@{
          PeName           = $pe.Name
          ResourceGroup    = $peRg
          SubscriptionName = $subName
          SubscriptionId   = $subId
          VNetId           = $peVNetId
          VNetName         = $peVNetName
          GroupId          = if ($groupId) { $groupId } else { "Unknown" }
          ConnectionStatus = $connStatus
          HasZoneGroup     = $hasZoneGroup
          ExpectedZoneName = $expectedZone
        })

      $subResult.PEs++
    }

    $subResult.Summary = "$($subResult.Zones) zone(s) | $($subResult.VNets) VNet(s) w/PE | $($subResult.PEs) PE(s)"
    $subscriptionResults.Add($subResult)
  }

  Write-Host ""  # newline after progress bar

  #-------------------------------------------------------------------- [ Phase 2: Cross-Subscription Correlation & Risk Rating ]

  Write-ScanProgress -Title "Phase 2 — Hub-Spoke Correlation and Risk Rating"

  # Build a lookup: zone name (lowercase) → list of zone records
  # Used to detect duplicate zone names across subscriptions
  $zonesByName = @{}
  foreach ($z in $allZones) {
    $key = $z.ZoneName.ToLower()
    if (-not $zonesByName.ContainsKey($key)) { $zonesByName[$key] = [System.Collections.Generic.List[hashtable]]::new() }
    $zonesByName[$key].Add($z)
  }

  # Build a lookup: VNet ID → list of zone names it is linked to
  $vnetToLinkedZones = @{}
  foreach ($lnk in $allVNetLinks) {
    $vid = $lnk.VNetId
    if (-not $vnetToLinkedZones.ContainsKey($vid)) { $vnetToLinkedZones[$vid] = [System.Collections.Generic.List[string]]::new() }
    $vnetToLinkedZones[$vid].Add($lnk.ZoneName.ToLower())
  }

  # ─────────────────────────────────────────────────────────────────────────
  # Well-known privatelink.* prefix — used for naming convention check
  $wellKnownPrefix = "privatelink."

  # Zone findings
  $zoneFindings = [System.Collections.Generic.List[hashtable]]::new()
  $riskDistribution = @{ "High" = 0; "Medium" = 0; "Low" = 0; "Info" = 0 }
  $gapDistribution = @{}

  foreach ($z in $allZones) {
    $gapCategory = ""
    $riskLevel = "Info"
    $detail = ""
    $recommendation = ""
    $namingStatus = ""

    # ── Naming convention check ───────────────────────────────────────────
    $nameLower = $z.ZoneName.ToLower()
    if ($nameLower.StartsWith($wellKnownPrefix)) {
      $namingStatus = "Compliant (privatelink.* prefix)"
    }
    elseif ($nameLower -like "*.privatelink.*") {
      $namingStatus = "Non-Standard (privatelink in non-prefix position)"
    }
    else {
      $namingStatus = "Non-Standard (not a privatelink.* zone)"
    }

    # ── Orphaned zone — zero VNet links ───────────────────────────────────
    if ($z.VNetLinkCount -eq 0) {
      $gapCategory = "Orphaned Zone (No VNet Links)"
      $riskLevel = "High"
      $detail = "Zone '$($z.ZoneName)' has zero virtual network links. No VNet can resolve names in this zone, making any Private Endpoint depending on it unreachable by FQDN. A zone with no links is operationally dead for Private Link scenarios."
      $recommendation = "Either link the zone to every VNet that hosts Private Endpoints expecting to use it, or delete the zone if it is no longer required to avoid accumulating orphaned resources that create confusion during incident response."
    }
    # ── Duplicate zone name across subscriptions ──────────────────────────
    elseif ($zonesByName[$z.ZoneName.ToLower()].Count -gt 1) {
      $gapCategory = "Duplicate Zone Name Across Subscriptions"
      $riskLevel = "High"
      $detail = "Zone name '$($z.ZoneName)' exists in $($zonesByName[$z.ZoneName.ToLower()].Count) subscriptions. DNS resolution is determined by which zone is linked to the resolving VNet. Split-brain DNS: two zones with the same name can hold conflicting records, causing Private Endpoints in different spokes to resolve to different IP addresses silently — a hard-to-diagnose connectivity fault."
      $recommendation = "Consolidate to a single authoritative zone per privatelink.* name, typically in the hub/connectivity subscription. Remove duplicate zones from spoke subscriptions and link the canonical hub zone to spoke VNets. Centralising the zone eliminates split-brain risk and simplifies DNS record lifecycle management."
    }
    # ── Registration-enabled links on a privatelink.* zone ────────────────
    elseif ($z.RegistrationEnabled -and $nameLower.StartsWith($wellKnownPrefix)) {
      $gapCategory = "Auto-Registration Enabled on Private Link Zone"
      $riskLevel = "Medium"
      $detail = "Zone '$($z.ZoneName)' has $($z.RegistrationLinkCount) virtual network link(s) with auto-registration enabled. Auto-registration is designed for VM hostname registration and should not be enabled on privatelink.* zones. It can pollute the zone with VM A-records, interfere with Private Endpoint records, and cause name collisions."
      $recommendation = "Disable auto-registration (RegistrationEnabled = false) on all virtual network links attached to this zone. Use a separate, non-privatelink zone for VM hostname auto-registration if that pattern is required. Private Endpoint DNS records must be managed explicitly or via DNS zone groups — not via auto-registration."
    }
    # ── Non-standard naming on a zone that has links and is actively used ─
    elseif (-not $nameLower.StartsWith($wellKnownPrefix) -and $z.VNetLinkCount -gt 0) {
      $gapCategory = "Non-Standard Zone Naming"
      $riskLevel = "Low"
      $detail = "Zone '$($z.ZoneName)' does not follow the canonical privatelink.* naming convention. Custom zone names are technically valid but break integration with Azure Policy DNS initiative (DeployIfNotExists policies expect the canonical zone name), may cause confusion, and are not automatically picked up by terraform-azurerm's private_dns_zone data sources."
      $recommendation = "Rename or replace the zone with the correct canonical name (e.g. privatelink.blob.core.windows.net for Storage blob). If the custom name is intentional (custom FQDN scenario), document the rationale and ensure the DNS zone group on every dependent Private Endpoint explicitly references this zone."
    }
    # ── Zone looks healthy ────────────────────────────────────────────────
    else {
      $gapCategory = "Compliant"
      $riskLevel = "Info"
      $detail = "Zone '$($z.ZoneName)' has $($z.VNetLinkCount) virtual network link(s), $($z.RecordSetCount) non-SOA/NS record set(s), and follows the privatelink.* naming convention. No issues detected from the data available in scope."
      $recommendation = "No immediate action required. Continue to monitor for orphaned record sets when Private Endpoints are decommissioned, and ensure that new spoke VNets are linked to this zone at provisioning time."
    }

    if (-not $riskDistribution.ContainsKey($riskLevel)) { $riskDistribution[$riskLevel] = 0 }
    $riskDistribution[$riskLevel]++
    if (-not $gapDistribution.ContainsKey($gapCategory)) { $gapDistribution[$gapCategory] = 0 }
    $gapDistribution[$gapCategory]++

    $zoneFindings.Add(@{
        ZoneName         = $z.ZoneName
        SubscriptionName = $z.SubscriptionName
        ResourceGroup    = $z.ResourceGroup
        VNetLinkCount    = $z.VNetLinkCount
        RecordSetCount   = $z.RecordSetCount
        NamingStatus     = $namingStatus
        GapCategory      = $gapCategory
        RiskLevel        = $riskLevel
        Detail           = $detail
        Recommendation   = $recommendation
      })
  }

  # ── VNet findings ─────────────────────────────────────────────────────────
  $vnetFindings = [System.Collections.Generic.List[hashtable]]::new()

  foreach ($v in $allVNetsWithPe) {
    $vid = $v.VNetId
    $gapCategory = ""
    $riskLevel = "Info"
    $detail = ""
    $recommendation = ""

    $linkedZones = if ($vnetToLinkedZones.ContainsKey($vid))
    { $vnetToLinkedZones[$vid] }
    else { [System.Collections.Generic.List[string]]::new() }

    # Determine which zones the PEs in this VNet expect
    $peExpectedZones = @($allPrivateEndpoints |
      Where-Object { $_.VNetId -eq $vid -and $_.ExpectedZoneName -ne "Unmapped / Not Validated" } |
      ForEach-Object { $_.ExpectedZoneName.ToLower() } |
      Sort-Object -Unique)

    # Zones expected by PEs that are not directly linked to this VNet
    $missingZones = @($peExpectedZones | Where-Object { $linkedZones -notcontains $_ })

    # Custom DNS servers present?
    $hasCustomDns = $v.DnsServers.Count -gt 0

    if ($missingZones.Count -gt 0 -and -not $hasCustomDns) {
      $gapCategory = "VNet Not Directly Linked to Required Zone(s)"
      $riskLevel = "High"
      $detail = "VNet '$($v.VNetName)' hosts $($v.PeCount) Private Endpoint(s) that depend on zone(s): $($missingZones -join '; '). None of these zones are directly linked to this VNet, and the VNet uses Azure-provided DNS (no custom DNS servers). Because Private DNS resolution does NOT traverse VNet peering, resources in this VNet will fail to resolve the Private Endpoint FQDNs and will fall back to public DNS, bypassing Private Link entirely."
      $recommendation = "Link the missing Private DNS zones to this VNet immediately: for each listed zone, create a virtual network link with RegistrationEnabled = false. If this is a spoke in a hub-spoke topology, the hub's Private DNS zones must be linked to every spoke VNet that needs to resolve them — peering alone is insufficient."
    }
    elseif ($missingZones.Count -gt 0 -and $hasCustomDns) {
      $gapCategory = "VNet Not Directly Linked to Required Zone(s) — Custom DNS (Manual Verify)"
      $riskLevel = "Medium"
      $detail = "VNet '$($v.VNetName)' hosts $($v.PeCount) Private Endpoint(s) that depend on zone(s): $($missingZones -join '; '). These zones are not directly linked, but the VNet uses custom DNS servers: $($v.CustomDnsLabel). Resolution may work if the custom DNS servers conditionally forward privatelink.* queries to Azure DNS (168.63.129.16) — or it may silently fail if they do not. This cannot be confirmed remotely."
      $recommendation = "Verify that the custom DNS servers ($($v.CustomDnsLabel)) have conditional forwarders for each required privatelink.* zone pointed to Azure DNS (168.63.129.16). If using Azure Private DNS Resolver, confirm inbound/outbound endpoint configuration. If using a third-party DNS (BIND, Windows DNS), confirm conditional forwarder zones are defined. Add direct zone links as a fallback if conditional forwarding is not configured."
    }
    elseif ($hasCustomDns -and $missingZones.Count -eq 0) {
      $gapCategory = "Custom DNS Configured — Zone Links Present (Manual Verify)"
      $riskLevel = "Low"
      $detail = "VNet '$($v.VNetName)' uses custom DNS servers ($($v.CustomDnsLabel)) and has direct virtual network links to all zones expected by its Private Endpoints. The direct zone links ensure Azure-native resolution would work, but the custom DNS servers may or may not be forwarding to Azure DNS (168.63.129.16). End-to-end resolution depends on the custom DNS configuration."
      $recommendation = "Confirm that the custom DNS servers forward or delegate privatelink.* queries to Azure DNS (168.63.129.16). If they do not, the zone links are functional but VMs using the custom DNS servers will still resolve via the custom DNS path, which may not reach Azure DNS. Ensure the resolution chain is consistent across all compute resources in the VNet."
    }
    else {
      $gapCategory = "Compliant"
      $riskLevel = "Info"
      $detail = "VNet '$($v.VNetName)' has direct virtual network links to all Private DNS zones required by its $($v.PeCount) Private Endpoint(s). No DNS resolution gaps detected in scope."
      $recommendation = "No immediate action required. Maintain governance by enforcing zone-link creation via Azure Policy (DeployIfNotExists) when new Private Endpoints are provisioned in this VNet."
    }

    if (-not $riskDistribution.ContainsKey($riskLevel)) { $riskDistribution[$riskLevel] = 0 }
    $riskDistribution[$riskLevel]++
    if (-not $gapDistribution.ContainsKey($gapCategory)) { $gapDistribution[$gapCategory] = 0 }
    $gapDistribution[$gapCategory]++

    $vnetFindings.Add(@{
        VNetName         = $v.VNetName
        VNetId           = $vid
        ResourceGroup    = $v.ResourceGroup
        SubscriptionName = $v.SubscriptionName
        PeCount          = $v.PeCount
        CustomDnsServers = $v.CustomDnsLabel
        GapCategory      = $gapCategory
        RiskLevel        = $riskLevel
        Detail           = $detail
        Recommendation   = $recommendation
      })
  }

  # ── Private Endpoint findings ─────────────────────────────────────────────
  $peFindings = [System.Collections.Generic.List[hashtable]]::new()

  foreach ($pe in $allPrivateEndpoints) {
    $gapCategory = ""
    $riskLevel = "Info"
    $detail = ""
    $recommendation = ""

    $expectedZoneLower = if ($pe.ExpectedZoneName -ne "Unmapped / Not Validated")
    { $pe.ExpectedZoneName.ToLower() } else { "" }

    # Is the expected zone linked to the PE's VNet?
    $zoneLinkedToVNet = $false
    if ($expectedZoneLower -and $vnetToLinkedZones.ContainsKey($pe.VNetId)) {
      $zoneLinkedToVNet = $vnetToLinkedZones[$pe.VNetId] -contains $expectedZoneLower
    }

    # Does the expected zone exist anywhere in scope?
    $zoneExistsInScope = $zonesByName.ContainsKey($expectedZoneLower)

    if ($pe.ConnectionStatus -notin @("Approved", "Connected")) {
      $gapCategory = "Connection Not Approved"
      $riskLevel = "High"
      $detail = "Private Endpoint '$($pe.PeName)' has connection status '$($pe.ConnectionStatus)'. An unapproved or disconnected Private Endpoint does not route traffic through the private network path. Any attempt to reach the linked service via this endpoint's private IP will fail."
      $recommendation = "Approve the Private Link connection for '$($pe.PeName)' from the service side. For manually approved connections, navigate to the target resource's Private Link settings and approve the pending connection. Automate approval via Azure Policy or Bicep/Terraform to prevent provisioning delays."
    }
    elseif (-not $pe.HasZoneGroup) {
      $gapCategory = "No DNS Zone Group Configured"
      $riskLevel = "High"
      $detail = "Private Endpoint '$($pe.PeName)' (group ID: '$($pe.GroupId)') has no DNS zone group configured. Without a zone group, Azure does not automatically register the endpoint's private IP address as an A record in the appropriate Private DNS zone. Name resolution will either return the public IP (bypassing Private Link) or fail, depending on whether public access to the target service is also disabled."
      $recommendation = "Configure a DNS zone group on this Private Endpoint referencing the canonical zone '$($pe.ExpectedZoneName)'. In Bicep/ARM, add a 'privateDnsZoneGroups' child resource. In Terraform, use a 'private_dns_zone_group' block on the 'azurerm_private_endpoint' resource. Ensure the referenced zone exists and is linked to the VNet hosting this endpoint."
    }
    elseif ($pe.ExpectedZoneName -eq "Unmapped / Not Validated") {
      $gapCategory = "GroupId Not in Known Zone Map"
      $riskLevel = "Low"
      $detail = "Private Endpoint '$($pe.PeName)' uses groupId '$($pe.GroupId)', which is not in the canonical privatelink.* zone map used by this script. This is not necessarily an error — newer or less common services may use groupIds not yet in the map. The endpoint has a zone group configured. Manual verification of the DNS zone name is required."
      $recommendation = "Confirm the correct Private DNS zone name for groupId '$($pe.GroupId)' from the Microsoft documentation (https://learn.microsoft.com/azure/private-link/private-endpoint-dns). Verify that the endpoint's zone group references the correct zone and that the zone is linked to VNet '$($pe.VNetName)'."
    }
    elseif (-not $zoneExistsInScope) {
      $gapCategory = "Expected Zone Not Found in Scope"
      $riskLevel = "High"
      $detail = "Private Endpoint '$($pe.PeName)' expects Private DNS zone '$($pe.ExpectedZoneName)' for groupId '$($pe.GroupId)', but this zone was not found in any subscription in scope. Either the zone has not been created, or it exists in a subscription outside the current scan scope. If the zone is absent, Private Endpoint DNS registration has nowhere to land."
      $recommendation = "Create zone '$($pe.ExpectedZoneName)' in the hub/connectivity subscription and link it to VNet '$($pe.VNetName)'. If the zone exists in a subscription outside the current scan scope, re-run with -AllSubscriptions or extend -SubscriptionIds to include the subscription hosting the zone, and link the zone to this VNet."
    }
    elseif (-not $zoneLinkedToVNet) {
      $gapCategory = "Expected Zone Exists But Not Linked to PE VNet"
      $riskLevel = "High"
      $detail = "Zone '$($pe.ExpectedZoneName)' exists in scope, but is not linked to VNet '$($pe.VNetName)' which hosts Private Endpoint '$($pe.PeName)'. Even with a DNS zone group on the endpoint, VMs in this VNet cannot resolve the FQDN to the private IP because the zone is not reachable from the VNet's DNS perspective. Private DNS does not traverse VNet peering."
      $recommendation = "Create a virtual network link from zone '$($pe.ExpectedZoneName)' to VNet '$($pe.VNetName)' with RegistrationEnabled = false. In hub-spoke designs, this is typically automated by Azure Policy (DeployIfNotExists on privateEndpoints). After linking, validate resolution from a VM in the VNet using 'Resolve-DnsName <fqdn>' and confirm it returns a 10.x.x.x private IP."
    }
    else {
      $gapCategory = "Compliant"
      $riskLevel = "Info"
      $detail = "Private Endpoint '$($pe.PeName)' (groupId: '$($pe.GroupId)') is approved/connected, has a DNS zone group, the expected zone '$($pe.ExpectedZoneName)' exists in scope, and the zone is linked to VNet '$($pe.VNetName)'. End-to-end DNS resolution architecture is complete for this endpoint."
      $recommendation = "No immediate action required. Validate periodically that the A record in zone '$($pe.ExpectedZoneName)' for this endpoint resolves correctly from all consumer VNets. Automate decommissioning — when this endpoint is deleted, ensure the DNS record and zone group are removed to avoid stale records."
    }

    if (-not $riskDistribution.ContainsKey($riskLevel)) { $riskDistribution[$riskLevel] = 0 }
    $riskDistribution[$riskLevel]++
    if (-not $gapDistribution.ContainsKey($gapCategory)) { $gapDistribution[$gapCategory] = 0 }
    $gapDistribution[$gapCategory]++

    $peFindings.Add(@{
        PeName           = $pe.PeName
        ResourceGroup    = $pe.ResourceGroup
        SubscriptionName = $pe.SubscriptionName
        VNetName         = $pe.VNetName
        GroupId          = $pe.GroupId
        ConnectionStatus = $pe.ConnectionStatus
        ExpectedZoneName = $pe.ExpectedZoneName
        GapCategory      = $gapCategory
        RiskLevel        = $riskLevel
        Detail           = $detail
        Recommendation   = $recommendation
      })
  }

  #-------------------------------------------------------------------- [ Phase 3: Outputs ]

  Write-ScanProgress -Title "Phase 3 — Generating Reports and Exports"

  $endTime = Get-Date
  $execTime = ($endTime - $startTime).ToString("mm\:ss")
  $genOn = $endTime.ToString("dd-MMM-yyyy HH:mm:ss UTC")

  $scanParameters = @{
    Scope         = $scopeLabel
    ExportEnabled = if ($ExportToCsv) { "Yes" } else { "No" }
    ExecTime      = $execTime
  }

  # ── HTML Dashboard ────────────────────────────────────────────────────────
  try {
    $htmlContent = Generate-PrivateDnsHtml `
      -SessionInfo          $sessionInfo `
      -ScanParameters       $scanParameters `
      -ZoneFindings         $zoneFindings.ToArray() `
      -VNetFindings         $vnetFindings.ToArray() `
      -PeFindings           $peFindings.ToArray() `
      -RiskDistribution     $riskDistribution `
      -GapDistribution      $gapDistribution `
      -SubscriptionResults  $subscriptionResults.ToArray() `
      -GeneratedOn          $genOn

    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
    Write-Verbose "HTML dashboard written: $htmlPath"
  }
  catch {
    Write-Warning "Failed to generate HTML dashboard: $_"
    $htmlPath = $null
  }

  # ── CSV Export ────────────────────────────────────────────────────────────
  $csvWritten = $false
  $vnetCsvWritten = $false
  $peCsvWritten = $false

  if ($ExportToCsv) {
    # Zone CSV
    try {
      $zoneFindings.ToArray() | Select-Object `
        ZoneName, SubscriptionName, ResourceGroup, VNetLinkCount, RecordSetCount,
      NamingStatus, GapCategory, RiskLevel, Detail, Recommendation |
      Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Force
      $csvWritten = $true
    }
    catch { Write-Warning "Failed to export Zone CSV: $_" }

    # VNet CSV
    try {
      $vnetFindings.ToArray() | Select-Object `
        VNetName, SubscriptionName, ResourceGroup, PeCount, CustomDnsServers,
      GapCategory, RiskLevel, Detail, Recommendation |
      Export-Csv -Path $vnetCsvPath -NoTypeInformation -Encoding UTF8 -Force
      $vnetCsvWritten = $true
    }
    catch { Write-Warning "Failed to export VNet CSV: $_" }

    # PE CSV
    try {
      $peFindings.ToArray() | Select-Object `
        PeName, SubscriptionName, ResourceGroup, VNetName, GroupId,
      ConnectionStatus, ExpectedZoneName, GapCategory, RiskLevel, Detail, Recommendation |
      Export-Csv -Path $peCsvPath -NoTypeInformation -Encoding UTF8 -Force
      $peCsvWritten = $true
    }
    catch { Write-Warning "Failed to export Private Endpoint CSV: $_" }
  }

  # ── Grid View ────────────────────────────────────────────────────────────
  $gridViewOpened = $false
  $allFindingsForGrid = @(
    $zoneFindings.ToArray() | Select-Object @{N = 'Type'; E = { 'Zone' } },
    @{N = 'Name'; E = { $_.ZoneName } }, @{N = 'Subscription'; E = { $_.SubscriptionName } },
    @{N = 'ResourceGroup'; E = { $_.ResourceGroup } }, GapCategory, RiskLevel, Recommendation

    $vnetFindings.ToArray() | Select-Object @{N = 'Type'; E = { 'VNet' } },
    @{N = 'Name'; E = { $_.VNetName } }, @{N = 'Subscription'; E = { $_.SubscriptionName } },
    @{N = 'ResourceGroup'; E = { $_.ResourceGroup } }, GapCategory, RiskLevel, Recommendation

    $peFindings.ToArray() | Select-Object @{N = 'Type'; E = { 'PrivateEndpoint' } },
    @{N = 'Name'; E = { $_.PeName } }, @{N = 'Subscription'; E = { $_.SubscriptionName } },
    @{N = 'ResourceGroup'; E = { $_.ResourceGroup } }, GapCategory, RiskLevel, Recommendation
  )

  try {
    if ($allFindingsForGrid.Count -gt 0 -and (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
      $allFindingsForGrid | Sort-Object RiskLevel, Type, Name |
      Out-GridView -Title "Azure Private DNS Architecture — Findings"
      $gridViewOpened = $true
    }
  }
  catch {
    Write-Verbose "Grid View not available in this session: $_"
  }

  #-------------------------------------------------------------------- [ Console Summary ]

  # Aggregate risk counts
  $highTotal = @($zoneFindings + $vnetFindings + $peFindings |
    Where-Object { $_.RiskLevel -eq "High" }).Count
  $medTotal = @($zoneFindings + $vnetFindings + $peFindings |
    Where-Object { $_.RiskLevel -eq "Medium" }).Count
  $lowTotal = @($zoneFindings + $vnetFindings + $peFindings |
    Where-Object { $_.RiskLevel -eq "Low" }).Count
  $infoTotal = @($zoneFindings + $vnetFindings + $peFindings |
    Where-Object { $_.RiskLevel -eq "Info" }).Count

  Write-Summary -Data ([ordered]@{
      "Subscriptions Scanned"        = $subTotal
      "Private DNS Zones Assessed"   = @($zoneFindings).Count
      "VNets with Private Endpoints" = @($vnetFindings).Count
      "Private Endpoints Assessed"   = @($peFindings).Count
      "Execution Time"               = "$execTime (mm:ss)"
    })

  Write-RiskBreakdown -Risk @{
    "High"   = $highTotal
    "Medium" = $medTotal
    "Low"    = $lowTotal
    "Info"   = $infoTotal
  }

  Write-OutputFiles `
    -CsvPath        $(if ($csvWritten) { $CsvPath }     else { $null }) `
    -VNetCsvPath    $(if ($vnetCsvWritten) { $vnetCsvPath } else { $null }) `
    -PeCsvPath      $(if ($peCsvWritten) { $peCsvPath }   else { $null }) `
    -HtmlPath       $(if ($htmlPath) { $htmlPath }    else { $null }) `
    -GridViewOpened $gridViewOpened

  # Return findings as objects for pipeline consumption
  return @{
    ZoneFindings = $zoneFindings.ToArray()
    VNetFindings = $vnetFindings.ToArray()
    PeFindings   = $peFindings.ToArray()
  }
}
