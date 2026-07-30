<#

Author       : Lakshmanan Thangaraj
Version      : 1.1
Created-On   : 30 July 2026
Modified-On  : 30 July 2026

.SYNOPSIS
    Reports Azure VNet peering relationships, configuration, and health across one or more subscriptions.

.DESCRIPTION
    Enumerates virtual networks and their peerings across the specified (or all accessible) Azure
    subscriptions, and produces a governance-style report covering peering status, gateway transit,
    remote gateway usage, forwarded traffic, virtual network access, cross-subscription/cross-region
    relationships, address space overlap, and sync status. Emits one row per directional peering
    object (Azure configures each side of a peering independently, so VNet A -> VNet B and
    VNet B -> VNet A can carry different settings; both are reported). Always exports CSV. Optionally
    also renders an interactive HTML dashboard when -GenerateHtmlDashboard is specified.

    Requires an existing authenticated Az context (Connect-AzAccount) with at least Reader access
    on every subscription in scope.

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account/context (in an
    'Enabled' state). This is also the default behavior if -SubscriptionId is not supplied.
    Takes precedence over -SubscriptionId if both are specified.

.PARAMETER SubscriptionId
    One or more Azure subscription GUIDs to scope the report to. Ignored if -AllSubscriptions
    is also specified. Cross-subscription peering detection requires the relevant subscriptions
    to be included in scope.

.PARAMETER OutputFolder
    Folder the CSV (and optional HTML) report will be written to. Must already exist. Defaults to the
    current working directory. Path-traversal sequences ('..') are rejected.

.PARAMETER GenerateHtmlDashboard
    When specified, also renders an interactive HTML dashboard alongside the CSV export.

.PARAMETER PassThru
    When specified, also returns the report objects to the pipeline in addition to writing files.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject (only when -PassThru is specified)
    Writes a CSV file, and optionally an HTML file, to -OutputFolder.

.EXAMPLE
    Get-AzureVNetPeeringReport -OutputFolder 'C:\Reports'
    Scans every accessible subscription and writes a CSV report to C:\Reports.

.EXAMPLE
    Get-AzureVNetPeeringReport -SubscriptionId '11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222' -OutputFolder 'C:\Reports' -GenerateHtmlDashboard
    Scans two named subscriptions (enabling accurate cross-subscription detection between them) and
    writes both a CSV report and an HTML dashboard.

.EXAMPLE
    $rows = Get-AzureVNetPeeringReport -OutputFolder 'C:\Reports' -PassThru
    $rows | Where-Object { $_.HealthSummary -like 'Critical*' }
    Runs the report, and also inspects only the peerings flagged Critical.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.1 (30-Jul-2026) - Enhanced on-screen console experience to match
                         Get-AzureRBACAssignments.ps1: added startup banner,
                         color-coded section headers, a custom progress bar with
                         per-subscription status lines, an end-of-run scan
                         summary, health/subscription distribution breakdowns,
                         and a unified output-files section. No changes to
                         peering enumeration, overlap detection, health-scoring,
                         or CSV/HTML export logic.
    1.0 (30-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts and Az.Network modules installed
    2. An active Az context (Connect-AzAccount) with Reader access on all in-scope subscriptions
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Address space overlap check evaluates IPv4 CIDR prefixes only; IPv6 prefixes are reported as
      "Not Evaluated" rather than assumed non-overlapping.
    - A remote VNet in a subscription outside of -SubscriptionId scope (and not independently
      resolvable via the signed-in identity's RBAC) will have its details reported as
      "Could not be confirmed" rather than omitted.
    - One row is emitted per directional peering object, not per peered pair - see .DESCRIPTION.

.LINK
    https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.network/get-azvirtualnetworkpeering

#>


Function Get-AzureVNetPeeringReport
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [switch]$AllSubscriptions,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string[]]$SubscriptionId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
                if ($_ -match '\.\.') {
                    throw "OutputFolder must not contain path-traversal sequences ('..')."
                }
                if (-not (Test-Path -Path $_ -PathType Container)) {
                    throw "OutputFolder '$_' does not exist. Create it first or pass a valid path."
                }
                $true
            })]
        [string]$OutputFolder = (Get-Location).Path,

        [Parameter(Mandatory = $false)]
        [switch]$GenerateHtmlDashboard,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    begin {
        #region Private helper functions
        # NOTE: these must be defined inside a named block (begin/process/end cannot be mixed
        # with loose top-level statements in an advanced function) - defining them here in
        # 'begin' keeps them available to 'process' and 'end' since all three share the same
        # function-local scope.

        Function ConvertTo-IPUInt32 {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [string]$IPAddress
            )

            $bytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
            if ([BitConverter]::IsLittleEndian) {
                [Array]::Reverse($bytes)
            }
            return [int64][BitConverter]::ToUInt32($bytes, 0)
        }

        Function Get-CidrRange {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [string]$Cidr
            )

            $parts = $Cidr.Trim().Split('/')
            if ($parts.Count -ne 2) {
                throw "Invalid IPv4 CIDR notation '$Cidr'."
            }

            [int64]$ipInt = ConvertTo-IPUInt32 -IPAddress $parts[0]
            [int]$prefix = [int]$parts[1]
            if ($prefix -lt 0 -or $prefix -gt 32) {
                throw "Invalid prefix length in '$Cidr'."
            }

            [int64]$fullMask = 0xFFFFFFFF
            [int64]$mask = if ($prefix -eq 0) { 0 } else { ($fullMask -shl (32 - $prefix)) -band $fullMask }
            [int64]$network = $ipInt -band $mask
            [int64]$wildcard = ($mask -bxor $fullMask) -band $fullMask
            [int64]$broadcast = $network -bor $wildcard

            [PSCustomObject]@{
                Start = $network
                End   = $broadcast
            }
        }

        Function Test-AddressSpaceOverlap {
            [CmdletBinding()]
            param (
                [string[]]$SpaceA,
                [string[]]$SpaceB
            )

            # Returns: 'Overlap Detected' | 'No Overlap' | 'Not Evaluated (IPv6 present)' | 'Could Not Be Confirmed'
            if (-not $SpaceA -or -not $SpaceB) {
                return 'Could Not Be Confirmed'
            }

            $ipv4A = $SpaceA | Where-Object { $_ -notmatch ':' }
            $ipv4B = $SpaceB | Where-Object { $_ -notmatch ':' }
            $hasIPv6 = (($SpaceA + $SpaceB) | Where-Object { $_ -match ':' }).Count -gt 0

            if (-not $ipv4A -or -not $ipv4B) {
                return 'Not Evaluated (IPv6 present)'
            }

            try {
                foreach ($a in $ipv4A) {
                    $rA = Get-CidrRange -Cidr $a
                    foreach ($b in $ipv4B) {
                        $rB = Get-CidrRange -Cidr $b
                        if ($rA.Start -le $rB.End -and $rB.Start -le $rA.End) {
                            return 'Overlap Detected'
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Address space overlap evaluation failed: $($_.Exception.Message)"
                return 'Could Not Be Confirmed'
            }

            if ($hasIPv6) {
                return 'No Overlap in IPv4 (IPv6 Not Evaluated)'
            }
            return 'No Overlap'
        }

        Function Resolve-RemoteVNetInfo {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [string]$RemoteResourceId,

                [Parameter(Mandatory = $true)]
                [hashtable]$VNetMap
            )

            $key = $RemoteResourceId.ToLowerInvariant()
            if ($VNetMap.ContainsKey($key)) {
                return $VNetMap[$key]
            }

            try {
                $remote = Get-AzVirtualNetwork -ResourceId $RemoteResourceId -ErrorAction Stop
                $subId = ($RemoteResourceId -split '/')[2]
                return [PSCustomObject]@{
                    Id                = $RemoteResourceId
                    Name              = $remote.Name
                    ResourceGroupName = $remote.ResourceGroupName
                    SubscriptionId    = $subId
                    SubscriptionName  = $null
                    Location          = $remote.Location
                    AddressSpace      = @($remote.AddressSpace.AddressPrefixes)
                }
            }
            catch {
                Write-Warning "Could not resolve remote virtual network '$RemoteResourceId': $($_.Exception.Message)"
                return $null
            }
        }

        Function ConvertTo-JsonSafeString {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $false)]
                [AllowNull()]
                [AllowEmptyString()]
                $Value
            )

            $s = if ($null -eq $Value) { '' } else { [string]$Value }
            $s = $s -replace '\\', '\\\\'
            $s = $s -replace '"', '\"'
            $s = $s -replace "`r`n", '\n'
            $s = $s -replace "`n", '\n'
            $s = $s -replace "`t", '\t'
            $s = $s -replace '<', '\u003c'
            $s = $s -replace '>', '\u003e'
            return $s
        }

        Function New-VNetPeeringDashboardHtml {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [object[]]$Rows,

                [Parameter(Mandatory = $true)]
                [string]$GeneratedOn
            )

            $total = $Rows.Count
            $healthy = @($Rows | Where-Object { $_.HealthSummary -eq 'Healthy' }).Count
            $warning = @($Rows | Where-Object { $_.HealthSummary -like 'Warning:*' }).Count
            $critical = @($Rows | Where-Object { $_.HealthSummary -like 'Critical:*' }).Count
            $crossSub = @($Rows | Where-Object { $_.CrossSubscription -eq $true }).Count
            $crossRegion = @($Rows | Where-Object { $_.CrossRegion -eq $true }).Count
            $overlaps = @($Rows | Where-Object { $_.AddressSpaceOverlapCheck -eq 'Overlap Detected' }).Count

            $subBreakdown = $Rows | Group-Object -Property Subscription | Sort-Object -Property Count -Descending |
            ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Count = $_.Count } }

            $rowJsonItems = foreach ($r in $Rows) {
                $vnetA = ConvertTo-JsonSafeString $r.VNetA
                $vnetB = ConvertTo-JsonSafeString $r.VNetB
                $status = ConvertTo-JsonSafeString $r.PeeringStatus
                $sync = ConvertTo-JsonSafeString $r.SyncStatus
                $rg = ConvertTo-JsonSafeString $r.ResourceGroup
                $subName = ConvertTo-JsonSafeString $r.Subscription
                $health = ConvertTo-JsonSafeString $r.HealthSummary
                $peerNm = ConvertTo-JsonSafeString $r.PeeringName
                $overlap = ConvertTo-JsonSafeString $r.AddressSpaceOverlapCheck
                $locA = ConvertTo-JsonSafeString $r.VNetALocation
                $locB = ConvertTo-JsonSafeString $r.VNetBLocation
                $subIdA = ConvertTo-JsonSafeString $r.VNetASubscriptionId
                $subIdB = ConvertTo-JsonSafeString $r.VNetBSubscriptionId

                $severity = if ($health -like 'Critical:*') { 'critical' } elseif ($health -like 'Warning:*') { 'warning' } else { 'healthy' }

                "{`"vnetA`":`"$vnetA`",`"vnetB`":`"$vnetB`",`"peeringName`":`"$peerNm`",`"status`":`"$status`",`"gatewayTransit`":$($r.GatewayTransit.ToString().ToLower()),`"useRemoteGateway`":$($r.UseRemoteGateway.ToString().ToLower()),`"forwardedTraffic`":$($r.ForwardedTraffic.ToString().ToLower()),`"vnetAccess`":$($r.VirtualNetworkAccess.ToString().ToLower()),`"crossSub`":$(if($r.CrossSubscription){'true'}else{'false'}),`"crossRegion`":$(if($r.CrossRegion){'true'}else{'false'}),`"overlap`":`"$overlap`",`"sync`":`"$sync`",`"rg`":`"$rg`",`"subscription`":`"$subName`",`"subIdA`":`"$subIdA`",`"subIdB`":`"$subIdB`",`"locA`":`"$locA`",`"locB`":`"$locB`",`"health`":`"$health`",`"severity`":`"$severity`"}"
            }
            $rowsJson = '[' + ($rowJsonItems -join ',') + ']'

            $subBreakdownJsonItems = foreach ($s in $subBreakdown) {
                $n = ConvertTo-JsonSafeString $s.Name
                "{`"name`":`"$n`",`"count`":$($s.Count)}"
            }
            $subBreakdownJson = '[' + ($subBreakdownJsonItems -join ',') + ']'

            $healthyPct = if ($total -gt 0) { [Math]::Round(($healthy / $total) * 100, 1) } else { 0 }

            $html = Get-VNetPeeringDashboardTemplate

            # Literal .Replace() (not the -replace regex operator) - JSON payloads can contain '$'
            # sequences that -replace would otherwise try to interpret as backreferences.
            $html = $html.Replace('__GENERATED_ON__', (ConvertTo-JsonSafeString $GeneratedOn))
            $html = $html.Replace('__TOTAL__', [string]$total)
            $html = $html.Replace('__HEALTHY__', [string]$healthy)
            $html = $html.Replace('__WARNING__', [string]$warning)
            $html = $html.Replace('__CRITICAL__', [string]$critical)
            $html = $html.Replace('__CROSSSUB__', [string]$crossSub)
            $html = $html.Replace('__CROSSREGION__', [string]$crossRegion)
            $html = $html.Replace('__OVERLAPS__', [string]$overlaps)
            $html = $html.Replace('__HEALTHYPCT__', [string]$healthyPct)
            $html = $html.Replace('__ROWS_JSON__', $rowsJson)
            $html = $html.Replace('__SUBBREAKDOWN_JSON__', $subBreakdownJson)

            return $html
        }

        Function Get-VNetPeeringDashboardTemplate {
            [CmdletBinding()]
            param ()

            @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure VNet Peering Report</title>
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
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:var(--sans); background:var(--bg); color:var(--text); min-height:100vh; transition:background .2s,color .2s; }
#sidebar { position:fixed; top:0; left:0; width:236px; height:100vh; background:var(--surface); border-right:1px solid var(--border); display:flex; flex-direction:column; padding:20px 16px; z-index:50; }
.logo-block { display:flex; align-items:center; gap:10px; margin-bottom:24px; }
.logo-tile { width:36px; height:36px; border-radius:8px; background:linear-gradient(135deg,var(--accent),var(--accent3)); display:flex; align-items:center; justify-content:center; font-size:18px; flex-shrink:0; }
.logo-text .t1 { font-weight:600; font-size:14px; line-height:1.2; }
.logo-text .t2 { font-size:11px; color:var(--muted); }
.nav-section { flex:1; display:flex; flex-direction:column; gap:4px; margin-top:8px; }
.nav-btn { display:flex; align-items:center; gap:10px; padding:9px 10px; border-radius:var(--radius-sm); border:none; background:transparent; color:var(--muted2); font-size:13px; cursor:pointer; text-align:left; border-left:3px solid transparent; font-family:var(--sans); }
.nav-btn:hover { background:var(--surface2); }
.nav-btn.active { background:var(--surface2); border-left:3px solid var(--accent); color:var(--text); font-weight:600; }
.theme-toggle { display:flex; align-items:center; justify-content:space-between; padding:8px 10px; background:var(--surface2); border-radius:var(--radius-sm); margin:12px 0; font-size:12px; }
.toggle-pill { width:36px; height:20px; border-radius:10px; background:var(--surface3); position:relative; cursor:pointer; border:1px solid var(--border); }
.toggle-pill::after { content:''; position:absolute; width:14px; height:14px; border-radius:50%; background:var(--accent); top:2px; left:2px; transition:left .15s; }
body.light-theme .toggle-pill::after { left:18px; }
.sidebar-footer { font-size:10px; color:var(--muted); border-top:1px solid var(--border); padding-top:10px; line-height:1.6; }
#main { margin-left:236px; padding:28px 32px; max-width:1400px; }
.page { display:none; animation:fadeIn .25s ease; }
.page.active { display:block; }
@keyframes fadeIn { from{opacity:0;transform:translateY(4px);} to{opacity:1;transform:translateY(0);} }
h1.page-title { font-size:20px; margin-bottom:4px; }
.page-sub { color:var(--muted); font-size:13px; margin-bottom:20px; }
.stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; margin-bottom:24px; }
.stat-card { background:var(--surface); border:1px solid var(--border); border-top:3px solid var(--border); border-radius:var(--radius); padding:16px; transition:transform .15s; }
.stat-card:hover { transform:translateY(-2px); }
.stat-card .n { font-size:26px; font-weight:700; font-family:var(--mono); }
.stat-card .l { font-size:12px; color:var(--muted); margin-top:4px; }
.stat-card.c-blue { border-top-color:var(--accent); }
.stat-card.c-cyan { border-top-color:var(--accent2); }
.stat-card.c-purple { border-top-color:var(--accent3); }
.stat-card.c-green { border-top-color:var(--green); }
.stat-card.c-amber { border-top-color:var(--amber); }
.stat-card.c-red { border-top-color:var(--red); }
.chart-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:20px; }
@media (max-width:900px) { .chart-grid { grid-template-columns:1fr; } #sidebar{transform:translateX(-100%);} #main{margin-left:0;} }
.panel { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:18px; }
.panel h3 { font-size:14px; margin-bottom:14px; }
#donutWrap { display:flex; align-items:center; gap:20px; }
.legend-list { display:flex; flex-direction:column; gap:8px; font-size:13px; }
.legend-item { display:flex; align-items:center; gap:8px; }
.legend-dot { width:10px; height:10px; border-radius:50%; flex-shrink:0; }
.bar-row { margin-bottom:10px; }
.bar-row .bar-head { display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px; color:var(--muted2); }
.bar-track { height:8px; background:var(--surface3); border-radius:4px; overflow:hidden; }
.bar-fill { height:100%; background:var(--accent); width:0; transition:width .6s ease; border-radius:4px; }
.toolbar { display:flex; gap:10px; margin-bottom:14px; flex-wrap:wrap; }
.search-wrap { position:relative; flex:1; min-width:200px; }
.search-wrap input { width:100%; padding:8px 12px 8px 30px; background:var(--surface2); border:1px solid var(--border); border-radius:var(--radius-sm); color:var(--text); font-size:13px; }
.search-wrap::before { content:'🔍'; position:absolute; left:9px; top:8px; font-size:12px; opacity:.6; }
select.page-size { background:var(--surface2); border:1px solid var(--border); color:var(--text); border-radius:var(--radius-sm); padding:8px; font-size:12px; }
table.peer-table { width:100%; border-collapse:collapse; font-size:12.5px; }
table.peer-table th { text-align:left; padding:9px 10px; border-bottom:1px solid var(--border); color:var(--muted2); cursor:pointer; white-space:nowrap; user-select:none; }
table.peer-table th.sort-active { color:var(--accent); }
table.peer-table td { padding:9px 10px; border-bottom:1px solid var(--border); font-family:var(--mono); white-space:nowrap; }
table.peer-table tbody tr { cursor:pointer; }
table.peer-table tbody tr:hover { background:var(--surface2); }
.badge { display:inline-block; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:600; }
.badge.healthy { background:rgba(63,185,80,.15); color:var(--green); }
.badge.warning { background:rgba(210,153,34,.15); color:var(--amber); }
.badge.critical { background:rgba(248,81,73,.15); color:var(--red); }
.badge.bool-true { background:rgba(56,139,253,.15); color:var(--accent); }
.badge.bool-false { background:var(--surface3); color:var(--muted); }
.pagination { display:flex; gap:6px; justify-content:flex-end; margin-top:14px; flex-wrap:wrap; }
.pagination button { background:var(--surface2); border:1px solid var(--border); color:var(--text); padding:6px 11px; border-radius:var(--radius-sm); font-size:12px; cursor:pointer; }
.pagination button.active { background:var(--accent); color:#fff; border-color:var(--accent); }
#detailPanel { position:fixed; inset:0; background:rgba(0,0,0,.5); display:none; z-index:100; }
#detailPanel.show { display:block; }
#detailDrawer { position:fixed; top:0; right:-420px; width:400px; height:100vh; background:var(--surface); border-left:1px solid var(--border); padding:22px; overflow-y:auto; transition:right .2s ease; }
#detailPanel.show #detailDrawer { right:0; }
.drawer-head { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
.drawer-close { background:none; border:none; color:var(--muted); font-size:20px; cursor:pointer; }
.chip-row { display:flex; flex-wrap:wrap; gap:6px; margin:10px 0 16px; }
.chip { background:var(--surface2); border:1px solid var(--border); border-radius:20px; padding:4px 10px; font-size:11px; }
.detail-field { margin-bottom:12px; }
.detail-field .k { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.03em; }
.detail-field .v { font-size:13px; font-family:var(--mono); margin-top:2px; }
.drawer-nav { display:flex; gap:8px; margin-top:20px; }
.drawer-nav button { flex:1; background:var(--surface2); border:1px solid var(--border); color:var(--text); padding:8px; border-radius:var(--radius-sm); cursor:pointer; }
#toast { position:fixed; bottom:20px; right:20px; background:var(--surface3); border:1px solid var(--border); padding:10px 16px; border-radius:var(--radius-sm); font-size:13px; opacity:0; transform:translateY(10px); transition:.2s; z-index:200; }
#toast.show { opacity:1; transform:translateY(0); }
#menuToggle { display:none; position:fixed; top:14px; left:14px; z-index:60; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); padding:8px 10px; color:var(--text); cursor:pointer; }
@media (max-width:768px) { #menuToggle{display:block;} #sidebar.open{transform:translateX(0);} }
</style>
</head>
<body>
<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>
<div id="sidebar">
  <div class="logo-block">
    <div class="logo-tile">🔗</div>
    <div class="logo-text"><div class="t1">VNet Peering Report</div><div class="t2">Cloud Identity Toolkit</div></div>
  </div>
  <div class="nav-section">
    <button class="nav-btn active" onclick="showPage('overview',this)">📊 Overview</button>
    <button class="nav-btn" onclick="showPage('peerings',this)">🔀 All Peerings</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)">🗂️ Subscriptions</button>
  </div>
  <div class="theme-toggle">
    <span>Theme</span>
    <div class="toggle-pill" onclick="toggleTheme()"></div>
  </div>
  <div class="sidebar-footer">
    Generated: __GENERATED_ON__<br>
    Shortcuts: <b>/</b> search · <b>Esc</b> close
  </div>
</div>

<div id="main">

  <div class="page active" id="page-overview">
    <h1 class="page-title">Overview</h1>
    <div class="page-sub">Azure VNet peering posture across the scanned subscription scope</div>
    <div class="stats-grid">
      <div class="stat-card c-blue"><div class="n">__TOTAL__</div><div class="l">Total Peerings</div></div>
      <div class="stat-card c-green"><div class="n">__HEALTHY__</div><div class="l">Healthy</div></div>
      <div class="stat-card c-amber"><div class="n">__WARNING__</div><div class="l">Warning</div></div>
      <div class="stat-card c-red"><div class="n">__CRITICAL__</div><div class="l">Critical</div></div>
      <div class="stat-card c-purple"><div class="n">__CROSSSUB__</div><div class="l">Cross-Subscription</div></div>
      <div class="stat-card c-cyan"><div class="n">__CROSSREGION__</div><div class="l">Cross-Region</div></div>
      <div class="stat-card c-red"><div class="n">__OVERLAPS__</div><div class="l">Address Overlaps</div></div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <h3>Health Breakdown</h3>
        <div id="donutWrap">
          <svg id="donutSvg" width="140" height="140" viewBox="0 0 140 140"></svg>
          <div class="legend-list" id="legendList"></div>
        </div>
      </div>
      <div class="panel">
        <h3>Peerings by Subscription</h3>
        <div id="subBarList"></div>
      </div>
    </div>
  </div>

  <div class="page" id="page-peerings">
    <h1 class="page-title">All Peerings</h1>
    <div class="page-sub">Every directional peering object found in scope</div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap"><input id="searchInput" type="text" placeholder="Search VNet, resource group, subscription..." oninput="renderTable()"></div>
        <select class="page-size" id="pageSizeSel" onchange="currentPage=1;renderTable()">
          <option value="10">10 / page</option>
          <option value="25" selected>25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div style="overflow-x:auto;">
      <table class="peer-table" id="peerTable">
        <thead><tr>
          <th onclick="sortBy('vnetA')">VNet A</th>
          <th onclick="sortBy('vnetB')">VNet B</th>
          <th onclick="sortBy('status')">Status</th>
          <th onclick="sortBy('sync')">Sync</th>
          <th onclick="sortBy('crossSub')">Cross-Sub</th>
          <th onclick="sortBy('crossRegion')">Cross-Region</th>
          <th onclick="sortBy('overlap')">Overlap</th>
          <th onclick="sortBy('subscription')">Subscription</th>
          <th onclick="sortBy('severity')">Health</th>
        </tr></thead>
        <tbody id="tableBody"></tbody>
      </table>
      </div>
      <div class="pagination" id="pagination"></div>
    </div>
  </div>

  <div class="page" id="page-subscriptions">
    <h1 class="page-title">Subscriptions</h1>
    <div class="page-sub">Peering volume grouped by owning subscription</div>
    <div class="panel">
      <div id="subBarListFull"></div>
    </div>
  </div>

</div>

<div id="detailPanel" onclick="if(event.target===this)closeDrawer()">
  <div id="detailDrawer">
    <div class="drawer-head">
      <h3 id="drawerTitle">Peering Detail</h3>
      <button class="drawer-close" onclick="closeDrawer()">×</button>
    </div>
    <div class="chip-row" id="drawerChips"></div>
    <div id="drawerFields"></div>
    <div class="drawer-nav">
      <button onclick="navDetail(-1)">← Prev</button>
      <button onclick="navDetail(1)">Next →</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
const ROWS = __ROWS_JSON__;
const SUB_BREAKDOWN = __SUBBREAKDOWN_JSON__;
let currentPage = 1;
let sortCol = null, sortDir = 1;
let filteredRows = ROWS.slice();
let currentDetailIndex = -1;

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  if (btn) btn.classList.add('active');
}

function toggleTheme() {
  document.body.classList.toggle('light-theme');
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2200);
}

function badgeBool(v) {
  return '<span class="badge '+(v?'bool-true':'bool-false')+'">'+(v?'Yes':'No')+'</span>';
}
function badgeSeverity(sev) {
  const label = sev==='critical'?'Critical':sev==='warning'?'Warning':'Healthy';
  return '<span class="badge '+sev+'">'+label+'</span>';
}

function renderDonut() {
  const counts = {healthy:0, warning:0, critical:0};
  ROWS.forEach(r=>counts[r.severity]++);
  const total = ROWS.length || 1;
  const colors = {healthy:'var(--green)', warning:'var(--amber)', critical:'var(--red)'};
  const order = ['healthy','warning','critical'];
  let offset = 0;
  const r = 55, cx = 70, cy = 70, circumference = 2*Math.PI*r;
  let svg = '<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="var(--surface3)" stroke-width="16"/>';
  order.forEach(key=>{
    const val = counts[key];
    if (val<=0) return;
    const frac = val/total;
    const len = frac*circumference;
    svg += '<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+colors[key]+'" stroke-width="16" '+
      'stroke-dasharray="'+len+' '+(circumference-len)+'" stroke-dashoffset="'+(-offset)+'" transform="rotate(-90 '+cx+' '+cy+')"/>';
    offset += len;
  });
  document.getElementById('donutSvg').innerHTML = svg;
  const legend = order.map(key=>{
    const label = key.charAt(0).toUpperCase()+key.slice(1);
    return '<div class="legend-item"><span class="legend-dot" style="background:'+colors[key]+'"></span>'+label+': '+counts[key]+'</div>';
  }).join('');
  document.getElementById('legendList').innerHTML = legend;
}

function renderSubBars(targetId, limit) {
  const items = limit ? SUB_BREAKDOWN.slice(0,limit) : SUB_BREAKDOWN;
  const max = Math.max.apply(null, items.map(i=>i.count).concat([1]));
  const html = items.map(i=>{
    const pct = Math.round((i.count/max)*100);
    return '<div class="bar-row"><div class="bar-head"><span>'+escH(i.name)+'</span><span>'+i.count+'</span></div>'+
      '<div class="bar-track"><div class="bar-fill" data-pct="'+pct+'"></div></div></div>';
  }).join('');
  document.getElementById(targetId).innerHTML = html;
  requestAnimationFrame(()=>{
    document.querySelectorAll('#'+targetId+' .bar-fill').forEach(el=>{ el.style.width = el.getAttribute('data-pct')+'%'; });
  });
}

function applyFilter() {
  const q = (document.getElementById('searchInput').value||'').toLowerCase();
  filteredRows = ROWS.filter(r=>{
    if (!q) return true;
    return (r.vnetA+' '+r.vnetB+' '+r.rg+' '+r.subscription+' '+r.peeringName).toLowerCase().includes(q);
  });
  if (sortCol) {
    filteredRows.sort((a,b)=>{
      let av=a[sortCol], bv=b[sortCol];
      if (typeof av==='boolean') { av=av?1:0; bv=bv?1:0; }
      if (av<bv) return -1*sortDir;
      if (av>bv) return 1*sortDir;
      return 0;
    });
  }
}

function sortBy(col) {
  if (sortCol===col) { sortDir*=-1; } else { sortCol=col; sortDir=1; }
  currentPage=1;
  renderTable();
}

function renderTable() {
  applyFilter();
  const pageSize = parseInt(document.getElementById('pageSizeSel').value,10);
  const totalPages = Math.max(1, Math.ceil(filteredRows.length/pageSize));
  if (currentPage>totalPages) currentPage=totalPages;
  const start = (currentPage-1)*pageSize;
  const pageRows = filteredRows.slice(start, start+pageSize);

  document.getElementById('tableBody').innerHTML = pageRows.map(r=>{
    const idx = ROWS.indexOf(r);
    return '<tr onclick="openDrawer('+idx+')">'+
      '<td>'+escH(r.vnetA)+'</td><td>'+escH(r.vnetB)+'</td><td>'+escH(r.status)+'</td><td>'+escH(r.sync)+'</td>'+
      '<td>'+badgeBool(r.crossSub)+'</td><td>'+badgeBool(r.crossRegion)+'</td><td>'+escH(r.overlap)+'</td>'+
      '<td>'+escH(r.subscription)+'</td><td>'+badgeSeverity(r.severity)+'</td></tr>';
  }).join('');

  document.querySelectorAll('.peer-table th').forEach(th=>th.classList.remove('sort-active'));

  const pag = document.getElementById('pagination');
  let pagHtml = '';
  for (let p=1;p<=totalPages;p++) {
    pagHtml += '<button class="'+(p===currentPage?'active':'')+'" onclick="currentPage='+p+';renderTable()">'+p+'</button>';
  }
  pag.innerHTML = pagHtml;
}

function openDrawer(idx) {
  currentDetailIndex = idx;
  const r = ROWS[idx];
  document.getElementById('drawerTitle').textContent = r.vnetA + ' → ' + r.vnetB;
  document.getElementById('drawerChips').innerHTML =
    '<span class="chip">'+escH(r.status)+'</span><span class="chip">'+escH(r.sync)+'</span><span class="chip">'+r.severity+'</span>';
  const fields = [
    ['Peering Name', r.peeringName], ['Resource Group', r.rg], ['Subscription', r.subscription],
    ['VNet A Location', r.locA], ['VNet B Location', r.locB],
    ['Gateway Transit', r.gatewayTransit?'Yes':'No'], ['Use Remote Gateway', r.useRemoteGateway?'Yes':'No'],
    ['Forwarded Traffic', r.forwardedTraffic?'Yes':'No'], ['Virtual Network Access', r.vnetAccess?'Yes':'No'],
    ['Cross Subscription', r.crossSub?'Yes':'No'], ['Cross Region', r.crossRegion?'Yes':'No'],
    ['Address Space Overlap', r.overlap], ['Health Summary', r.health]
  ];
  document.getElementById('drawerFields').innerHTML = fields.map(f=>
    '<div class="detail-field"><div class="k">'+f[0]+'</div><div class="v">'+escH(f[1])+'</div></div>').join('');
  document.getElementById('detailPanel').classList.add('show');
}
function closeDrawer() { document.getElementById('detailPanel').classList.remove('show'); }
function navDetail(dir) {
  if (currentDetailIndex<0) return;
  let next = currentDetailIndex+dir;
  if (next<0) next = ROWS.length-1;
  if (next>=ROWS.length) next = 0;
  openDrawer(next);
}

document.addEventListener('keydown', e=>{
  if (e.key==='Escape') closeDrawer();
  if (e.key==='/' && document.getElementById('page-peerings').classList.contains('active')) {
    e.preventDefault();
    document.getElementById('searchInput').focus();
  }
  if (document.getElementById('detailPanel').classList.contains('show')) {
    if (e.key==='ArrowLeft') navDetail(-1);
    if (e.key==='ArrowRight') navDetail(1);
  }
});

renderDonut();
renderSubBars('subBarList', 6);
renderSubBars('subBarListFull', null);
renderTable();
</script>
</body>
</html>
'@
        }

        #endregion

        #region Console UX helper functions (on-screen experience only - no report data logic here)

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
            Write-Host ("=" * 80) -ForegroundColor Cyan
            Write-CenteredText "Azure VNet Peering Report Scanner v1.1" -Color White
            Write-Host ("=" * 80) -ForegroundColor Cyan
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
            Write-Host ("-" * 76) -ForegroundColor DarkGray

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
                Write-Host $key.PadRight(18) -NoNewline -ForegroundColor Gray
                Write-Host ": " -NoNewline -ForegroundColor DarkGray
                Write-Host $value -ForegroundColor $valueColor
            }
        }

        Function Write-ScanProgressHeader {
            param([string]$Title)

            Write-Host ""
            Write-Host "  $Title" -ForegroundColor Cyan
            Write-Host "  " -NoNewline
            Write-Host ("-" * 76) -ForegroundColor DarkGray
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

            $bar = ("#" * $completed) + ("." * $remaining)

            Write-Host "`r" -NoNewline
            Write-Host ("  Progress: ") -NoNewline -ForegroundColor Gray
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

        Function Write-ProgressLineResult {
            param(
                [string]$Name,
                [int]$PadLength,
                [string]$Status,
                [string]$Message
            )

            Write-Host "`r" -NoNewline
            Write-Host (" " * 120) -NoNewline
            Write-Host "`r" -NoNewline

            $paddedName = $Name.PadRight($PadLength)

            Write-Host "  " -NoNewline
            switch ($Status) {
                "Success" { Write-Host "OK   " -NoNewline -ForegroundColor Green; $color = "Green" }
                "Warning" { Write-Host "WARN " -NoNewline -ForegroundColor Yellow; $color = "Yellow" }
                "Error" { Write-Host "FAIL " -NoNewline -ForegroundColor Red; $color = "Red" }
                default { Write-Host "..   " -NoNewline -ForegroundColor Gray; $color = "White" }
            }
            Write-Host $paddedName -NoNewline -ForegroundColor $color
            Write-Host " -> " -NoNewline -ForegroundColor DarkGray
            Write-Host $Message -ForegroundColor $(if ($Status -eq "Success") { "White" } else { $color })
        }

        Function Write-Summary {
            param(
                [hashtable]$Data
            )

            Write-Host ""
            Write-Host "  Scan Summary" -ForegroundColor Cyan
            Write-Host "  " -NoNewline
            Write-Host ("-" * 76) -ForegroundColor DarkGray

            foreach ($key in $Data.Keys) {
                Write-Host "  " -NoNewline
                Write-Host $key.PadRight(30) -NoNewline -ForegroundColor Gray
                Write-Host ": " -NoNewline -ForegroundColor DarkGray
                Write-Host $Data[$key] -ForegroundColor White
            }
        }

        Function Write-TopSubscriptions {
            param([array]$SubBreakdown)

            if (-not $SubBreakdown -or @($SubBreakdown).Count -eq 0) { return }

            Write-Host ""
            Write-Host "  Top 5 Subscriptions by Peering Count" -ForegroundColor Cyan
            Write-Host "  " -NoNewline
            Write-Host ("-" * 76) -ForegroundColor DarkGray

            $counter = 1
            foreach ($item in ($SubBreakdown | Select-Object -First 5)) {
                Write-Host "  " -NoNewline
                Write-Host "$counter. " -NoNewline -ForegroundColor Gray
                Write-Host $item.Name.PadRight(40) -NoNewline -ForegroundColor White
                Write-Host ": " -NoNewline -ForegroundColor DarkGray
                Write-Host "$($item.Count) peerings" -ForegroundColor Cyan
                $counter++
            }
        }

        Function Write-HealthDistribution {
            param(
                [int]$Healthy,
                [int]$Warning,
                [int]$Critical,
                [int]$Total
            )

            if ($Total -eq 0) { return }

            Write-Host ""
            Write-Host "  Health Distribution" -ForegroundColor Cyan
            Write-Host "  " -NoNewline
            Write-Host ("-" * 76) -ForegroundColor DarkGray

            $rows = @(
                @{ Label = "Healthy Peerings"; Count = $Healthy; Color = "Green" }
                @{ Label = "Warning Peerings"; Count = $Warning; Color = "Yellow" }
                @{ Label = "Critical Peerings"; Count = $Critical; Color = "Red" }
            )

            foreach ($row in $rows) {
                $percent = [math]::Round(($row.Count / $Total) * 100)
                Write-Host "  $($row.Label)".PadRight(37) -NoNewline
                Write-Host ": $percent% ($($row.Count))" -ForegroundColor $row.Color
            }
        }

        Function Write-OutputFiles {
            param(
                [string]$CsvPath,
                [string]$HtmlPath,
                [bool]$PassThruEnabled
            )

            Write-Host ""
            Write-Host "  Output Files" -ForegroundColor Cyan
            Write-Host "  " -NoNewline
            Write-Host ("-" * 76) -ForegroundColor DarkGray

            if ($CsvPath) {
                Write-Host "  " -NoNewline
                Write-Host "OK " -NoNewline -ForegroundColor Green
                Write-Host (("CSV Export").PadRight(20) + ": ") -NoNewline -ForegroundColor Gray
                Write-Host $CsvPath -ForegroundColor White
            }

            if ($HtmlPath) {
                Write-Host "  " -NoNewline
                Write-Host "OK " -NoNewline -ForegroundColor Green
                Write-Host (("HTML Dashboard").PadRight(20) + ": ") -NoNewline -ForegroundColor Gray
                Write-Host $HtmlPath -ForegroundColor White
            }

            if ($PassThruEnabled) {
                Write-Host "  " -NoNewline
                Write-Host "OK " -NoNewline -ForegroundColor Green
                Write-Host (("PassThru").PadRight(20) + ": ") -NoNewline -ForegroundColor Gray
                Write-Host "Report objects returned to pipeline" -ForegroundColor White
            }

            Write-Host ""
            Write-Host ("=" * 80) -ForegroundColor Cyan
            Write-Host ""
        }

        #endregion

        $startTime = Get-Date
        Write-Banner

        Write-Verbose "Checking for required modules..."
        foreach ($moduleName in @('Az.Accounts', 'Az.Network')) {
            if (-not (Get-Module -ListAvailable -Name $moduleName)) {
                throw "Required module '$moduleName' is not installed. Install it with: Install-Module $moduleName -Scope CurrentUser"
            }
        }

        $currentContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $currentContext) {
            throw "No active Az context found. Run Connect-AzAccount before calling Get-AzureVNetPeeringReport."
        }

        Write-Verbose "Resolving subscription scope..."
        try {
            $allAccessibleSubs = Get-AzSubscription -ErrorAction Stop
        }
        catch {
            throw "Failed to enumerate subscriptions: $($_.Exception.Message)"
        }

        if ($SubscriptionId) {
            $targetSubs = $allAccessibleSubs | Where-Object { $_.Id -in $SubscriptionId }
            $missing = $SubscriptionId | Where-Object { $_ -notin $targetSubs.Id }
            foreach ($missingId in $missing) {
                Write-Warning "Subscription '$missingId' was not found or is not accessible with the current account and will be skipped."
            }
        }
        else {
            $targetSubs = $allAccessibleSubs | Where-Object { $_.State -eq 'Enabled' }
        }

        if (-not $targetSubs -or @($targetSubs).Count -eq 0) {
            throw "No accessible, enabled subscriptions found in the resolved scope."
        }

        Write-Verbose "Subscription scope resolved: $(@($targetSubs).Count) subscription(s)."

        $scopeText = if ($SubscriptionId) { "Specific Subscriptions ($($SubscriptionId.Count) requested)" } else { "All Subscriptions" }

        Write-Section -Title "Session Information" -Data @{
            "Tenant"      = $currentContext.Tenant.Id
            "Account"     = $currentContext.Account.Id
            "Environment" = $currentContext.Environment.Name
        }

        Write-Section -Title "Scan Parameters" -Data @{
            "Scope"          = "$scopeText ($(@($targetSubs).Count) resolved)"
            "Output Folder"  = $OutputFolder
            "HTML Dashboard" = if ($GenerateHtmlDashboard.IsPresent) { "Enabled" } else { "Disabled" }
            "PassThru"       = if ($PassThru.IsPresent) { "Enabled" } else { "Disabled" }
        }
    }

    process {
        #region Inventory VNets across all in-scope subscriptions

        $vnetMap = @{}
        $subCounter = 0
        $subScanSuccessCount = 0
        $subScanErrorCount = 0

        Write-ScanProgressHeader -Title "Inventorying Virtual Networks"
        Write-ProgressBar -Current 0 -Total @($targetSubs).Count -CurrentItem "Starting..."

        $maxSubNameLength = ($targetSubs | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
        $maxSubNameLength = [math]::Max($maxSubNameLength, 35)

        foreach ($sub in $targetSubs) {
            $subCounter++
            Write-ProgressBar -Current $subCounter -Total @($targetSubs).Count -CurrentItem $sub.Name

            try {
                Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
                $vnets = Get-AzVirtualNetwork -ErrorAction Stop
            }
            catch {
                Write-ProgressLineResult -Name $sub.Name -PadLength $maxSubNameLength -Status "Error" -Message "Failed: $($_.Exception.Message)"
                $subScanErrorCount++
                Write-Warning "Skipping subscription '$($sub.Name)' ($($sub.Id)) - failed to enumerate virtual networks: $($_.Exception.Message)"
                continue
            }

            $vnetCountForSub = @($vnets).Count
            if ($vnetCountForSub -gt 0) {
                Write-ProgressLineResult -Name $sub.Name -PadLength $maxSubNameLength -Status "Success" -Message "$vnetCountForSub virtual network(s)"
            }
            else {
                Write-ProgressLineResult -Name $sub.Name -PadLength $maxSubNameLength -Status "Warning" -Message "No virtual networks"
            }
            $subScanSuccessCount++

            foreach ($vnet in $vnets) {
                try {
                    $peerings = @()
                    if ($vnet.VirtualNetworkPeerings) {
                        $peerings = @($vnet.VirtualNetworkPeerings)
                    }

                    $vnetMap[$vnet.Id.ToLowerInvariant()] = [PSCustomObject]@{
                        Id                = $vnet.Id
                        Name              = $vnet.Name
                        ResourceGroupName = $vnet.ResourceGroupName
                        SubscriptionId    = $sub.Id
                        SubscriptionName  = $sub.Name
                        Location          = $vnet.Location
                        AddressSpace      = @($vnet.AddressSpace.AddressPrefixes)
                        Peerings          = $peerings
                    }
                }
                catch {
                    Write-Warning "Skipping VNet '$($vnet.Name)' in subscription '$($sub.Name)' - $($_.Exception.Message)"
                    continue
                }
            }
        }
        Write-Verbose "Inventory complete: $($vnetMap.Count) virtual network(s) found across scope."

        #endregion

        #region Build per-peering rows

        $reportRows = New-Object System.Collections.Generic.List[object]
        $overlapCache = @{}
        $generatedOn = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $vnetCounter = 0

        Write-ScanProgressHeader -Title "Processing Peerings"
        Write-ProgressBar -Current 0 -Total ([Math]::Max($vnetMap.Count, 1)) -CurrentItem "Starting..."

        foreach ($vnetEntry in $vnetMap.Values) {
            $vnetCounter++
            Write-ProgressBar -Current $vnetCounter -Total ([Math]::Max($vnetMap.Count, 1)) -CurrentItem $vnetEntry.Name

            foreach ($peering in $vnetEntry.Peerings) {
                try {
                    $remoteId = $peering.RemoteVirtualNetwork.Id
                    if (-not $remoteId) {
                        Write-Warning "Peering '$($peering.Name)' on VNet '$($vnetEntry.Name)' has no remote virtual network reference and was skipped."
                        continue
                    }

                    $remote = Resolve-RemoteVNetInfo -RemoteResourceId $remoteId -VNetMap $vnetMap

                    $overlapResult = 'Could Not Be Confirmed'
                    if ($remote) {
                        $pairKey = @($vnetEntry.Id.ToLowerInvariant(), $remote.Id.ToLowerInvariant()) | Sort-Object
                        $pairKeyString = $pairKey -join '|'
                        if ($overlapCache.ContainsKey($pairKeyString)) {
                            $overlapResult = $overlapCache[$pairKeyString]
                        }
                        else {
                            $overlapResult = Test-AddressSpaceOverlap -SpaceA $vnetEntry.AddressSpace -SpaceB $remote.AddressSpace
                            $overlapCache[$pairKeyString] = $overlapResult
                        }
                    }

                    $crossSubscription = if ($remote) { [bool]($remote.SubscriptionId -ne $vnetEntry.SubscriptionId) } else { $null }
                    $crossRegion = if ($remote) { [bool]($remote.Location -ne $vnetEntry.Location) } else { $null }

                    $criticalReasons = New-Object System.Collections.Generic.List[string]
                    $warningReasons = New-Object System.Collections.Generic.List[string]

                    if ($peering.PeeringState -ne 'Connected') {
                        $criticalReasons.Add("Peering state is '$($peering.PeeringState)'")
                    }
                    if ($overlapResult -eq 'Overlap Detected') {
                        $criticalReasons.Add('Address space overlap detected')
                    }
                    if ($peering.PeeringSyncLevel -and $peering.PeeringSyncLevel -ne 'FullyInSync') {
                        $warningReasons.Add("Sync level is '$($peering.PeeringSyncLevel)'")
                    }
                    if ($overlapResult -eq 'Could Not Be Confirmed') {
                        $warningReasons.Add('Address space overlap could not be confirmed')
                    }
                    if (-not $remote) {
                        $warningReasons.Add('Remote virtual network details could not be confirmed')
                    }

                    $healthSummary = if ($criticalReasons.Count -gt 0) {
                        'Critical: ' + ($criticalReasons -join '; ')
                    }
                    elseif ($warningReasons.Count -gt 0) {
                        'Warning: ' + ($warningReasons -join '; ')
                    }
                    else {
                        'Healthy'
                    }

                    $row = [PSCustomObject][ordered]@{
                        VNetA                    = $vnetEntry.Name
                        VNetB                    = if ($remote) { $remote.Name } else { '(Could not be confirmed)' }
                        PeeringStatus            = $peering.PeeringState
                        GatewayTransit           = [bool]$peering.AllowGatewayTransit
                        UseRemoteGateway         = [bool]$peering.UseRemoteGateways
                        ForwardedTraffic         = [bool]$peering.AllowForwardedTraffic
                        VirtualNetworkAccess     = [bool]$peering.AllowVirtualNetworkAccess
                        CrossSubscription        = $crossSubscription
                        CrossRegion              = $crossRegion
                        AddressSpaceOverlapCheck = $overlapResult
                        SyncStatus               = $peering.PeeringSyncLevel
                        ResourceGroup            = $vnetEntry.ResourceGroupName
                        Subscription             = $vnetEntry.SubscriptionName
                        HealthSummary            = $healthSummary
                        PeeringName              = $peering.Name
                        VNetASubscriptionId      = $vnetEntry.SubscriptionId
                        VNetBSubscriptionId      = if ($remote) { $remote.SubscriptionId } else { $null }
                        VNetALocation            = $vnetEntry.Location
                        VNetBLocation            = if ($remote) { $remote.Location } else { $null }
                        PairKey                  = if ($remote) { ($pairKey -join '|') } else { $null }
                        GeneratedOn              = $generatedOn
                    }

                    $reportRows.Add($row)
                }
                catch {
                    Write-Warning "Failed to process peering '$($peering.Name)' on VNet '$($vnetEntry.Name)': $($_.Exception.Message)"
                    continue
                }
            }
        }
        Write-Host "`r" -NoNewline
        Write-Host (" " * 120) -NoNewline
        Write-Host "`r" -NoNewline
        Write-Host ""

        #endregion

        #region Second pass - flag asymmetric configuration between the two directions of a pair

        $pairGroups = $reportRows | Where-Object { $_.PairKey } | Group-Object -Property PairKey
        foreach ($group in $pairGroups) {
            if ($group.Group.Count -ne 2) {
                continue
            }
            $sideA = $group.Group[0]
            $sideB = $group.Group[1]

            $asymmetric = ($sideA.VirtualNetworkAccess -ne $sideB.VirtualNetworkAccess) -or
            ($sideA.ForwardedTraffic -ne $sideB.ForwardedTraffic)

            if ($asymmetric) {
                foreach ($side in @($sideA, $sideB)) {
                    if ($side.HealthSummary -eq 'Healthy') {
                        $side.HealthSummary = 'Warning: Asymmetric peering configuration between the two sides'
                    }
                    elseif ($side.HealthSummary -like 'Warning:*' -and $side.HealthSummary -notlike '*Asymmetric*') {
                        $side.HealthSummary += '; Asymmetric peering configuration between the two sides'
                    }
                }
            }
        }

        # Drop the internal PairKey helper column before export
        $finalRows = $reportRows | Select-Object -Property * -ExcludeProperty PairKey

        #endregion
    }

    end {
        $endTime = Get-Date
        $duration = $endTime - $startTime
        $durationFormatted = "{0:hh\:mm\:ss}" -f $duration

        if (-not $finalRows -or $finalRows.Count -eq 0) {
            Write-Warning "No VNet peerings were found in the resolved scope. No report was written."
            Write-Host ""
            Write-Host ("=" * 80) -ForegroundColor Cyan
            Write-Host ""
            return
        }

        # Aggregate stats for the on-screen summary (mirrors what the HTML dashboard already shows)
        $healthyCount = @($finalRows | Where-Object { $_.HealthSummary -eq 'Healthy' }).Count
        $warningCount = @($finalRows | Where-Object { $_.HealthSummary -like 'Warning:*' }).Count
        $criticalCount = @($finalRows | Where-Object { $_.HealthSummary -like 'Critical:*' }).Count
        $crossSubCount = @($finalRows | Where-Object { $_.CrossSubscription -eq $true }).Count
        $crossRegionCount = @($finalRows | Where-Object { $_.CrossRegion -eq $true }).Count
        $overlapCount = @($finalRows | Where-Object { $_.AddressSpaceOverlapCheck -eq 'Overlap Detected' }).Count

        $subBreakdown = $finalRows | Group-Object -Property Subscription | Sort-Object -Property Count -Descending |
        ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Count = $_.Count } }

        Write-Summary -Data @{
            "Subscriptions Scanned"       = @($targetSubs).Count
            "Subscriptions OK"            = $subScanSuccessCount
            "Subscriptions Failed"        = $subScanErrorCount
            "Virtual Networks Found"      = $vnetMap.Count
            "Total Peerings Found"        = $finalRows.Count
            "Cross-Subscription Peerings" = $crossSubCount
            "Cross-Region Peerings"       = $crossRegionCount
            "Address Overlaps Detected"   = $overlapCount
            "Execution Time"              = $durationFormatted
        }

        Write-HealthDistribution -Healthy $healthyCount -Warning $warningCount -Critical $criticalCount -Total $finalRows.Count

        Write-TopSubscriptions -SubBreakdown $subBreakdown

        $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
        $csvPath = Join-Path -Path $OutputFolder -ChildPath "VNetPeeringReport_$timestamp.csv"

        try {
            $finalRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
        }
        catch {
            throw "Failed to write CSV report to '$csvPath': $($_.Exception.Message)"
        }

        $htmlPath = $null
        if ($GenerateHtmlDashboard) {
            $htmlPath = Join-Path -Path $OutputFolder -ChildPath "VNetPeeringReport_$timestamp.html"
            try {
                $htmlContent = New-VNetPeeringDashboardHtml -Rows $finalRows -GeneratedOn $generatedOn
                $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            }
            catch {
                Write-Warning "CSV report succeeded, but HTML dashboard generation failed: $($_.Exception.Message)"
                $htmlPath = $null
            }
        }

        Write-OutputFiles -CsvPath $csvPath -HtmlPath $htmlPath -PassThruEnabled $PassThru.IsPresent

        if ($PassThru) {
            return $finalRows
        }
    }
}
