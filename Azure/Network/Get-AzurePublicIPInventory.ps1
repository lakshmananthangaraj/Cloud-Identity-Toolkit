<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 30 July 2026
Modified-On  : 30 July 2026

.SYNOPSIS
    Inventories every Azure Public IP address across one or more subscriptions,
    computes hygiene/usage flags for each, and produces a CSV export plus an
    optional modern, sidebar-navigation HTML dashboard.

.DESCRIPTION
    The Get-AzurePublicIPInventory function retrieves every Public IP address
    resource visible to the caller (optionally filtered by subscription and/or
    resource group) and normalizes it into a single inventory record covering:

        - Which resource (if any) the Public IP is attached to
        - Unassociated Public IPs (attached to nothing)
        - Unused Public IPs (unassociated, OR attached to a Network Interface
          that itself is not attached to any VM - see .NOTES)
        - Dynamic vs Static allocation method
        - Basic vs Standard SKU
        - DDoS Protection status (per-resource DdosSettings.ProtectionMode)
        - DNS name (FQDN / domain name label) presence
        - Idle Timeout configuration
        - Tag presence
        - Availability Zones
        - Internet-facing classification

    Every check requested by the team maps onto columns/flags in this single
    inventory record, so the CSV export (one row per Public IP) already answers
    "Unused", "Unassociated", "Dynamic", "Basic SKU", "No DDoS", "No DNS",
    "No Tags", "By Subscription", "By Resource Group", and "Internet-Facing"
    as filterable columns. The console summary and the optional HTML dashboard
    additionally roll these up into break-downs and a Usage Summary.

    The HTML dashboard is only generated when -GenerateHtmlDashboard is
    specified. It reuses the visual design system (dark/light theme toggle,
    fixed sidebar navigation, JetBrains Mono + Segoe UI type pairing, stat
    cards, panel/bar charts, searchable/sortable/paginated table, slide-in
    detail drawer, toast notifications) from the team's existing
    Generate-MyScriptDashboard.ps1 "golden" dashboard, re-themed for Public IP
    data instead of script metadata.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored if
    -AllSubscriptions is also specified.

.PARAMETER ResourceGroupNames
    Optional filter. Restricts the scan to Public IPs in the specified
    resource group(s).

.PARAMETER CsvPath
    Path where the Public IP inventory CSV will always be written (one row
    per Public IP, including all computed hygiene/usage columns).
    Default: C:\Temp\AzurePublicIPInventory-Report.csv

.PARAMETER HtmlPath
    Path where the HTML dashboard will be written if -GenerateHtmlDashboard is
    specified. Defaults to -CsvPath with a .html extension if not supplied.

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated
    account/context. This is also the default behavior if -SubscriptionIds is
    not supplied.

.PARAMETER GenerateHtmlDashboard
    Switch. If specified, generates the modern HTML dashboard in addition to
    the always-on CSV export. If omitted, only the CSV is produced.

.PARAMETER OpenDashboardInBrowser
    Switch. If specified together with -GenerateHtmlDashboard, opens the
    generated HTML file in the default browser once complete.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes a CSV inventory to -CsvPath.
    Writes an HTML dashboard to -HtmlPath only if -GenerateHtmlDashboard is
    specified.

.EXAMPLE
    Get-AzurePublicIPInventory -AllSubscriptions

.EXAMPLE
    Get-AzurePublicIPInventory -SubscriptionIds @("SubscriptionID1","SubscriptionID2") -ResourceGroupNames "rg-network-prod"

.EXAMPLE
    Get-AzurePublicIPInventory -AllSubscriptions -GenerateHtmlDashboard -OpenDashboardInBrowser

.EXAMPLE
    Get-AzurePublicIPInventory -AllSubscriptions -CsvPath "C:\Reports\PublicIPs.csv" -GenerateHtmlDashboard -HtmlPath "C:\Reports\PublicIPs.html"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (30-Jul-2026) - Initial release.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts and Az.Network modules (installed/imported automatically if
       missing, with user consent at the console prompt).
    2. Reader role (minimum) on each target subscription.

    ─────────────────────────────────────────────────────────────────────────────
    Definitions / Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - "Unassociated" = the Public IP has neither an IpConfiguration nor a
      NatGateway reference (attached to nothing at all).
    - "Unused" = Unassociated, OR attached to a Network Interface whose
      .VirtualMachine property is null (the NIC itself is not attached to any
      VM). This requires one additional Get-AzNetworkInterface call per
      distinct NIC-attached Public IP; results are cached per run to avoid
      duplicate lookups. Public IPs attached to Load Balancers, Application
      Gateways, Azure Firewalls, VPN/ExpressRoute Gateways, Bastion Hosts, or
      NAT Gateways are not further inspected for backend/child-resource
      activity (e.g., an empty Load Balancer backend pool) - only NIC-level
      "orphaned NIC" is checked. Flag these findings as directional and confirm
      manually before decommissioning.
    - "Attached Resource Type/Name" is derived from the ARM resource ID pattern
      in IpConfiguration.Id / NatGateway.Id (.../providers/Microsoft.Network/
      <resourceType>/<resourceName>/...). Nested child resources (e.g. a
      specific frontend IP configuration name) are not separately reported.
    - "DDoS Protection" reflects the per-resource DdosSettings.ProtectionMode
      value on the Public IP itself (Enabled/Disabled/VirtualNetworkInherited).
      It does NOT evaluate whether the parent virtual network has a Standard
      DDoS Network Protection Plan enabled at the VNet level, which is a
      separate, broader protection mechanism outside a Public IP resource's
      own properties.
    - "Idle Timeout not configured" flags only a null/missing
      IdleTimeoutInMinutes value. Azure applies a default of 4 minutes when a
      value isn't explicitly set at creation, so most Public IPs will show a
      populated value; this check catches the rare case where the property is
      absent from the returned object.
    - No creation-date/age field is available directly on the Public IP
      resource; determining "how long has this been unused" would require
      querying Azure Activity Log / Resource Graph history, which is out of
      scope for this version.
    - If neither -AllSubscriptions nor -SubscriptionIds is supplied, the
      function defaults to scanning ALL subscriptions visible to the current
      account with no additional confirmation prompt (matches existing toolkit
      convention).
    - Default -CsvPath / -HtmlPath (C:\Temp\...) are Windows-specific paths. On
      macOS/Linux PowerShell 7, supply explicit paths.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.network/get-azpublicipaddress
    
.LINK
    https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses

#>


#------------------------------------------------------------------------ [ Console Helper Functions ]

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
    Write-CenteredText "Azure Public IP Inventory v1.0" -Color White
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
        } else {
            $valueColor = "White"
        }
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valueColor
    }
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
        $displayItem = if ($CurrentItem.Length -gt $maxLength) { $CurrentItem.Substring(0, $maxLength - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-InventorySummary {
    param([array]$Records)

    $total = $Records.Count
    Write-Host ""
    Write-Host "  Public IP Usage Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    $rows = [ordered]@{
        "Total Public IPs"              = $total
        "Unassociated"                  = @($Records | Where-Object IsUnassociated).Count
        "Unused (incl. orphaned NICs)"  = @($Records | Where-Object IsUnused).Count
        "Dynamic Allocation"            = @($Records | Where-Object IsDynamic).Count
        "Basic SKU"                     = @($Records | Where-Object IsBasicSku).Count
        "Without DDoS Protection"       = @($Records | Where-Object { -not $_.HasDdosProtection }).Count
        "Without DNS Name"              = @($Records | Where-Object { -not $_.HasDnsName }).Count
        "Idle Timeout Not Configured"   = @($Records | Where-Object { -not $_.IdleTimeoutConfigured }).Count
        "Without Tags"                  = @($Records | Where-Object { -not $_.HasTags }).Count
        "Internet-Facing"               = @($Records | Where-Object IsInternetFacing).Count
    }

    foreach ($key in $rows.Keys) {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(32) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $rows[$key] -ForegroundColor White
    }
}

Function Write-OutputFiles {
    param(
        [string]$CsvPath,
        [string]$HtmlPath
    )
    Write-Host ""
    Write-Host "  Output Files" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    if ($CsvPath) {
        Write-Host "  " -NoNewline
        Write-Host "[OK] " -NoNewline -ForegroundColor Green
        Write-Host (("CSV Export").PadRight(20) + ": ") -NoNewline -ForegroundColor Gray
        Write-Host $CsvPath -ForegroundColor White
    }
    if ($HtmlPath) {
        Write-Host "  " -NoNewline
        Write-Host "[OK] " -NoNewline -ForegroundColor Green
        Write-Host (("HTML Dashboard").PadRight(20) + ": ") -NoNewline -ForegroundColor Gray
        Write-Host $HtmlPath -ForegroundColor White
    }
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-SafePropertyValue {
    param($Object, [string]$PropertyName)
    if ($Object.PSObject.Properties.Name -contains $PropertyName) {
        return $Object.$PropertyName
    }
    return $null
}

#------------------------------------------------------------------------ [ Normalization Helpers ]

Function Get-AttachedResourceInfo {
    <#
        Parses an IpConfiguration.Id or NatGateway.Id ARM resource ID into a
        friendly attached-resource type/name. Returns $null Type when neither
        reference is supplied (Unassociated).
    #>
    param(
        [string]$IpConfigurationId,
        [string]$NatGatewayId
    )

    $resourceId = if ($NatGatewayId) { $NatGatewayId } elseif ($IpConfigurationId) { $IpConfigurationId } else { $null }

    if (-not $resourceId) {
        return [pscustomobject]@{ Type = "None"; Name = $null; ParentResourceId = $null }
    }

    $typeMap = @{
        "networkInterfaces"        = "Network Interface"
        "loadBalancers"             = "Load Balancer"
        "applicationGateways"       = "Application Gateway"
        "azureFirewalls"            = "Azure Firewall"
        "natGateways"               = "NAT Gateway"
        "vpnGateways"               = "VPN Gateway"
        "virtualNetworkGateways"    = "VPN/ExpressRoute Gateway"
        "bastionHosts"              = "Bastion Host"
    }

    if ($resourceId -match '(?i)/providers/Microsoft\.Network/(?<type>[^/]+)/(?<name>[^/]+)') {
        $rawType = $Matches['type']
        $name = $Matches['name']
        $friendlyType = if ($typeMap.ContainsKey($rawType)) { $typeMap[$rawType] } else { $rawType }
        $parentId = $resourceId -replace '(?i)(/providers/Microsoft\.Network/[^/]+/[^/]+).*', '$1'
        return [pscustomobject]@{ Type = $friendlyType; Name = $name; ParentResourceId = $parentId }
    }

    return [pscustomobject]@{ Type = "Unknown"; Name = $null; ParentResourceId = $resourceId }
}

Function ConvertTo-NormalizedPublicIp {
    param(
        [Parameter(Mandatory)]$PublicIp,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SubscriptionName,
        [Parameter(Mandatory)][hashtable]$NicVmCache
    )

    # AFTER
    $ipConfigObj  = Get-SafePropertyValue -Object $PublicIp -PropertyName 'IpConfiguration'
    $natGwObj     = Get-SafePropertyValue -Object $PublicIp -PropertyName 'NatGateway'
    $ipConfigId   = if ($ipConfigObj) { $ipConfigObj.Id } else { $null }
    $natGatewayId = if ($natGwObj)    { $natGwObj.Id }    else { $null }
    $attached = Get-AttachedResourceInfo -IpConfigurationId $ipConfigId -NatGatewayId $natGatewayId

    $isUnassociated = ($attached.Type -eq "None")
    $isUnusedNic = $false

    if (-not $isUnassociated -and $attached.Type -eq "Network Interface" -and $attached.ParentResourceId) {
        if ($NicVmCache.ContainsKey($attached.ParentResourceId)) {
            $isUnusedNic = $NicVmCache[$attached.ParentResourceId]
        }
        else {
            try {
                $nic = Get-AzNetworkInterface -ResourceId $attached.ParentResourceId -ErrorAction Stop
                $unused = (-not $nic.VirtualMachine)
                $NicVmCache[$attached.ParentResourceId] = $unused
                $isUnusedNic = $unused
            }
            catch {
                $NicVmCache[$attached.ParentResourceId] = $false
                $isUnusedNic = $false
            }
        }
    }

    $tags = @{}
    if ($PublicIp.Tag) { foreach ($k in $PublicIp.Tag.Keys) { $tags[$k] = $PublicIp.Tag[$k] } }
    $tagsJoined = ($tags.Keys | ForEach-Object { "$_=$($tags[$_])" }) -join "; "

    $ddosObj  = Get-SafePropertyValue -Object $PublicIp -PropertyName 'DdosSettings'
    $ddosMode = if ($ddosObj -and $ddosObj.ProtectionMode) { $ddosObj.ProtectionMode } else { "Disabled" }
    $dnsLabel = if ($PublicIp.DnsSettings) { $PublicIp.DnsSettings.DomainNameLabel } else { $null }
    $fqdn = if ($PublicIp.DnsSettings) { $PublicIp.DnsSettings.Fqdn } else { $null }
    $reverseFqdn = $PublicIp.DnsSettings.ReverseFqdn

    $hasDns = -not ([string]::IsNullOrWhiteSpace($dnsLabel) -and [string]::IsNullOrWhiteSpace($fqdn))
    $idleConfigured = $null -ne $PublicIp.IdleTimeoutInMinutes
    $isDynamic = ($PublicIp.PublicIpAllocationMethod -eq "Dynamic")
    $isBasicSku = ($PublicIp.Sku.Name -eq "Basic")
    $hasDdos = ($ddosMode -eq "Enabled")
    $hasTags = ($tags.Count -gt 0)
    $isUnused = ($isUnassociated -or $isUnusedNic)
    $isInternetFacing = (-not $isUnassociated)

    $issueCount = @($isUnused, $isDynamic, $isBasicSku, (-not $hasDdos), (-not $hasDns), (-not $hasTags), (-not $idleConfigured)) |
        Where-Object { $_ -eq $true } | Measure-Object | Select-Object -ExpandProperty Count

    return [pscustomobject]@{
        SubscriptionId          = $SubscriptionId
        SubscriptionName        = $SubscriptionName
        ResourceGroupName       = $PublicIp.ResourceGroupName
        Name                    = $PublicIp.Name
        Location                = $PublicIp.Location
        Sku                     = $PublicIp.Sku.Name
        SkuTier                 = $PublicIp.Sku.Tier
        AllocationMethod        = $PublicIp.PublicIpAllocationMethod
        IPVersion               = $PublicIp.PublicIPAddressVersion
        IpAddress               = $PublicIp.IpAddress
        Zones                   = ($PublicIp.Zones -join ",")
        IdleTimeoutInMinutes    = $PublicIp.IdleTimeoutInMinutes
        DnsDomainNameLabel      = $dnsLabel
        Fqdn                    = $fqdn
        ReverseFqdn             = $reverseFqdn
        DdosProtectionMode      = $ddosMode
        Tags                    = $tagsJoined
        TagCount                = $tags.Count
        AttachedResourceType    = $attached.Type
        AttachedResourceName    = $attached.Name
        AttachedResourceId      = $attached.ParentResourceId
        IsUnassociated          = $isUnassociated
        IsUnused                = $isUnused
        IsDynamic               = $isDynamic
        IsBasicSku              = $isBasicSku
        HasDdosProtection       = $hasDdos
        HasDnsName              = $hasDns
        IdleTimeoutConfigured   = $idleConfigured
        HasTags                 = $hasTags
        IsInternetFacing        = $isInternetFacing
        IssueCount              = $issueCount
        ResourceId              = $PublicIp.Id
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function ConvertTo-SafeReplacementText {
    <#
        PowerShell's -replace operator treats '$' specially in the replacement
        argument (e.g. $1, $&, ${name}). To safely splice arbitrary generated
        HTML/JSON into a template via -replace, every literal '$' in that text
        must be doubled ('$$') so .NET's regex engine emits it back as a
        single literal '$' instead of trying to resolve a capture group.
    #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return $Text -replace '\$', '$$$$'
}

Function Get-PublicIpDashboardHtml {
    param(
        [Parameter(Mandatory)][array]$Records,
        [Parameter(Mandatory)][hashtable]$SessionInfo,
        [Parameter(Mandatory)][string]$ScopeText
    )

    $total          = [math]::Max(@($Records).Count, 1)
    $unassociated   = @($Records | Where-Object IsUnassociated).Count
    $unused         = @($Records | Where-Object IsUnused).Count
    $dynamic        = @($Records | Where-Object IsDynamic).Count
    $basicSku       = @($Records | Where-Object IsBasicSku).Count
    $noDdos         = @($Records | Where-Object { -not $_.HasDdosProtection }).Count
    $noDns          = @($Records | Where-Object { -not $_.HasDnsName }).Count
    $noTags         = @($Records | Where-Object { -not $_.HasTags }).Count
    $internetFacing = @($Records | Where-Object IsInternetFacing).Count
    $cleanCount     = @($Records | Where-Object { $_.IssueCount -eq 0 }).Count
    $hygieneScore   = [math]::Round(($cleanCount / $total) * 100)

    # -- Bar chart builder (server-rendered, no client JS required) --
    Function New-BarPanelHtml {
        param([array]$Groups, [string]$Color = "var(--accent)")
        $max = ($Groups | Measure-Object -Property Count -Maximum).Maximum
        if (-not $max) { $max = 1 }
        $rows = ""
        foreach ($g in ($Groups | Sort-Object Count -Descending | Select-Object -First 12)) {
            $pct = [math]::Round(($g.Count / $max) * 100)
            $rows += "<div class=`"bar-row`"><span class=`"bar-label`" title=`"$($g.Name)`">$($g.Name)</span><div class=`"bar-track`"><div class=`"bar-fill`" style=`"width:$pct%;background:$Color`"></div></div><span class=`"bar-count`">$($g.Count)</span></div>`n"
        }
        return $rows
    }

    $bySku = $Records | Group-Object Sku
    $byAllocation = $Records | Group-Object AllocationMethod
    $bySubscription = $Records | Group-Object SubscriptionName
    $byResourceGroup = $Records | Group-Object ResourceGroupName
    $byAttachedType = $Records | Group-Object AttachedResourceType

    $skuBarsHtml = New-BarPanelHtml -Groups $bySku -Color "var(--accent)"
    $allocationBarsHtml = New-BarPanelHtml -Groups $byAllocation -Color "var(--accent2)"
    $subscriptionBarsHtml = New-BarPanelHtml -Groups $bySubscription -Color "var(--accent3)"
    $resourceGroupBarsHtml = New-BarPanelHtml -Groups $byResourceGroup -Color "var(--green)"
    $attachedTypeBarsHtml = New-BarPanelHtml -Groups $byAttachedType -Color "var(--amber)"

    # -- Unused & Unassociated static list --
    $unusedRowsHtml = ""
    foreach ($r in ($Records | Where-Object IsUnused | Sort-Object SubscriptionName, ResourceGroupName, Name)) {
        $reason = if ($r.IsUnassociated) { "Unassociated" } else { "Attached to unused Network Interface" }
        $unusedRowsHtml += "<div class=`"top-list-row`" onclick=`"openDetail('$($r.Name -replace "'", "\'")')`"><span class=`"tl-rank`">!</span><span class=`"tl-name`" title=`"$($r.Name)`">$($r.Name)</span><span class=`"tl-val`">$reason &middot; $($r.ResourceGroupName)</span></div>`n"
    }
    if (-not $unusedRowsHtml) { $unusedRowsHtml = "<p style=`"color:var(--muted);font-size:12px`">No unused or unassociated Public IPs found.</p>" }

    # -- Internet-facing breakdown --
    $internetFacingHtml = ""
    foreach ($grp in ($Records | Where-Object IsInternetFacing | Group-Object AttachedResourceType)) {
        $items = ($grp.Group | Sort-Object AttachedResourceName | ForEach-Object {
            "<div class=`"top-list-row`" onclick=`"openDetail('$($_.Name -replace "'", "\'")')`"><span class=`"tl-rank`">&bull;</span><span class=`"tl-name`" title=`"$($_.AttachedResourceName)`">$($_.AttachedResourceName)</span><span class=`"tl-val`">$($_.IpAddress)</span></div>"
        }) -join "`n"
        $internetFacingHtml += "<div class=`"panel`" style=`"margin-bottom:16px`"><div class=`"section-title`">$($grp.Name) <span style=`"font-size:11px;color:var(--muted);font-weight:400`">($($grp.Count))</span></div>$items</div>`n"
    }
    if (-not $internetFacingHtml) { $internetFacingHtml = "<p style=`"color:var(--muted);font-size:12px`">No internet-facing resources found.</p>" }

    # -- Analytics coverage bars --
    $ddosCoveragePct = [math]::Round((@($Records | Where-Object HasDdosProtection).Count / $total) * 100)
    $dnsCoveragePct  = [math]::Round((@($Records | Where-Object HasDnsName).Count / $total) * 100)
    $tagCoveragePct  = [math]::Round((@($Records | Where-Object HasTags).Count / $total) * 100)
    $idleCoveragePct = [math]::Round((@($Records | Where-Object IdleTimeoutConfigured).Count / $total) * 100)

    # -- JSON payload for the client-side table/detail drawer --
    $projected = $Records | ForEach-Object {
        [pscustomobject]@{
            name        = $_.Name
            sub         = $_.SubscriptionName
            rg          = $_.ResourceGroupName
            location    = $_.Location
            sku         = $_.Sku
            tier        = $_.SkuTier
            allocation  = $_.AllocationMethod
            version     = $_.IPVersion
            ip          = $_.IpAddress
            zones       = $_.Zones
            idleTimeout = $_.IdleTimeoutInMinutes
            dnsLabel    = $_.DnsDomainNameLabel
            fqdn        = $_.Fqdn
            ddos        = $_.DdosProtectionMode
            tags        = $_.Tags
            tagCount    = $_.TagCount
            attType     = $_.AttachedResourceType
            attName     = $_.AttachedResourceName
            unassoc     = [bool]$_.IsUnassociated
            unused      = [bool]$_.IsUnused
            dynamic     = [bool]$_.IsDynamic
            basicSku    = [bool]$_.IsBasicSku
            hasDdos     = [bool]$_.HasDdosProtection
            hasDns      = [bool]$_.HasDnsName
            hasTags     = [bool]$_.HasTags
            internetFacing = [bool]$_.IsInternetFacing
            issueCount  = $_.IssueCount
        }
    }
    $ipsJson = (ConvertTo-Json -InputObject @($projected) -Depth 4 -Compress) -replace '</', '<\/'

    $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Public IP Inventory Dashboard</title>
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
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}

#sidebar{position:fixed;top:0;left:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text)}
.sidebar-logo p{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.version-badge{display:inline-block;margin-top:5px;background:rgba(56,139,253,.15);color:var(--accent);font-family:var(--mono);font-size:10px;padding:1px 8px;border-radius:20px;border:1px solid rgba(56,139,253,.3)}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13.5px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.nav-btn .nav-badge{margin-left:auto;background:var(--surface3);color:var(--muted2);font-family:var(--mono);font-size:11px;padding:1px 7px;border-radius:20px}
.nav-btn:hover{color:var(--text);background:var(--surface2)}
.nav-btn.active{color:var(--accent);background:rgba(56,139,253,.1)}
.nav-btn.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);border-radius:0 2px 2px 0}
.theme-toggle-wrap{padding:10px 14px;border-top:1px solid var(--border)}
.theme-toggle{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;transition:all .2s}
.theme-toggle:hover{border-color:var(--accent);color:var(--text)}
.toggle-pill{width:34px;height:18px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--muted2);transition:transform .2s,background .2s}
body.light-theme .toggle-pill{background:var(--accent)}
body.light-theme .toggle-pill::after{transform:translateX(16px);background:#fff}
.sidebar-footer{padding:10px 18px 12px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);font-family:var(--mono);line-height:1.6}
kbd{display:inline-block;padding:1px 5px;background:var(--surface3);border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:11px;color:var(--muted)}

#main{margin-left:236px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:24px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}

.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-card::after{content:'';position:absolute;top:-26px;right:-26px;width:68px;height:68px;border-radius:50%;background:radial-gradient(circle,rgba(59,130,246,.1),transparent 70%)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:25px;font-weight:700;color:var(--text);line-height:1}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}

.health-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;display:flex;align-items:center;gap:18px;margin-bottom:22px;flex-wrap:wrap}
.health-ring-wrap{position:relative;width:76px;height:76px;flex-shrink:0}
.health-ring-wrap svg{width:76px;height:76px}
.health-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.health-score-num{font-family:var(--mono);font-size:19px;font-weight:700;line-height:1}
.health-score-pct{font-size:9px;color:var(--muted)}
.health-info{flex:1;min-width:200px}
.health-info h3{font-size:14px;font-weight:700;margin-bottom:4px}
.health-info p{font-size:12px;color:var(--muted2)}
.health-bar-row{display:flex;align-items:center;gap:8px;margin-top:8px;font-size:12px}
.health-mini-bar{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.health-mini-fill{height:100%;border-radius:3px;transition:width 1s ease}

.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-family:var(--mono);font-size:11px;color:var(--muted2);width:120px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:34px;text-align:right;flex-shrink:0}

.top-list-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);cursor:pointer}
.top-list-row:last-child{border-bottom:none}
.top-list-row:hover .tl-name{color:var(--accent)}
.tl-rank{font-family:var(--mono);font-size:11px;color:var(--muted);width:20px;flex-shrink:0;text-align:center}
.tl-name{font-family:var(--mono);font-size:12px;color:var(--accent2);flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tl-val{font-family:var(--mono);font-size:11.5px;color:var(--muted);flex-shrink:0}

.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;padding:8px 11px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--accent)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:13px;flex-shrink:0}
.ips-table{width:100%;border-collapse:collapse}
.ips-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.ips-table thead th:hover{color:var(--text)}
.ips-table thead th.sort-active{color:var(--accent)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.ips-table tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.ips-table tbody tr:hover{background:var(--surface2)}
.ips-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13.5px}
.td-name{font-family:var(--mono);font-size:12.5px;color:var(--accent2);font-weight:600}
.td-meta{color:var(--muted);font-family:var(--mono);font-size:12px;white-space:nowrap}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-family:var(--sans);font-size:11px;font-weight:600;margin:1px 3px 1px 0}
.badge-ok{background:rgba(63,185,80,.15);color:var(--green)}
.badge-warn{background:rgba(210,153,34,.15);color:var(--amber)}
.badge-bad{background:rgba(248,81,73,.15);color:var(--red)}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}

#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(560px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:24px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
#detailClose{margin-left:auto;background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--red);color:#fff}
#detailContent{flex:1;overflow-y:auto}
.detail-header{margin-bottom:16px}
.detail-name{font-family:var(--mono);font-size:16px;color:var(--accent2);font-weight:600;word-break:break-all}
.detail-path{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:4px;word-break:break-all}
.detail-meta-row{display:flex;gap:9px;flex-wrap:wrap;margin:12px 0}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:12px;color:var(--muted2)}
.detail-section{margin-top:18px}
.detail-section-title{font-size:11.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:9px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.param-card{background:var(--surface2);border-radius:var(--radius-sm);padding:9px 12px;margin-bottom:5px;border:1px solid var(--border)}
.param-name{font-family:var(--mono);font-size:12.5px;color:var(--accent3)}
.param-desc{color:var(--muted2);font-size:12.5px;margin-top:3px}

#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}

::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

@media(max-width:768px){#sidebar{transform:translateX(-236px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">&#9776;</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">&#127760;</div>
    <h1>Public IP Inventory</h1>
    <p title="__SCOPETEXT__">__SCOPETEXT__</p>
    <span class="version-badge">v1.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">&#128202;</span> Overview</button>
    <button class="nav-btn" onclick="showPage('allips',this)"><span class="nav-icon">&#128196;</span> All Public IPs <span class="nav-badge">__TOTALCOUNT__</span></button>
    <button class="nav-btn" onclick="showPage('unused',this)"><span class="nav-icon">&#9888;</span> Unused &amp; Unassociated <span class="nav-badge">__UNUSEDCOUNT__</span></button>
    <button class="nav-btn" onclick="showPage('bysubscription',this)"><span class="nav-icon">&#127760;</span> By Subscription</button>
    <button class="nav-btn" onclick="showPage('byresourcegroup',this)"><span class="nav-icon">&#128193;</span> By Resource Group</button>
    <button class="nav-btn" onclick="showPage('internetfacing',this)"><span class="nav-icon">&#128225;</span> Internet-Facing</button>
    <button class="nav-btn" onclick="showPage('analytics',this)"><span class="nav-icon">&#128200;</span> Analytics</button>
  </div>
  <div class="theme-toggle-wrap">
    <button class="theme-toggle" onclick="toggleTheme()">
      <span id="themeIcon">&#127769;</span>
      <span id="themeLabel" style="flex:1;text-align:left">Dark Mode</span>
      <span class="toggle-pill"></span>
    </button>
  </div>
  <div class="sidebar-footer">
    Generated<br>__GENERATEDAT__<br>
    <span style="color:var(--accent2)">&#9000;</span> <kbd>/</kbd> search
  </div>
</nav>

<main id="main">

<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Public IP Usage Summary</div>
      <div class="page-subtitle">__SCOPETEXT__</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(false)">&#11015; Export CSV</button>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">&#127760;</div><div class="stat-value">__TOTALCOUNT__</div><div class="stat-label">Total Public IPs</div></div>
    <div class="stat-card c-red"><div class="stat-icon">&#10060;</div><div class="stat-value">__UNASSOCIATEDCOUNT__</div><div class="stat-label">Unassociated</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">&#9888;</div><div class="stat-value">__UNUSEDCOUNT__</div><div class="stat-label">Unused</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">&#128257;</div><div class="stat-value">__DYNAMICCOUNT__</div><div class="stat-label">Dynamic Allocation</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">&#127991;</div><div class="stat-value">__BASICSKUCOUNT__</div><div class="stat-label">Basic SKU</div></div>
    <div class="stat-card c-red"><div class="stat-icon">&#128737;</div><div class="stat-value">__NODDOSCOUNT__</div><div class="stat-label">No DDoS Protection</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">&#127991;</div><div class="stat-value">__NODNSCOUNT__</div><div class="stat-label">No DNS Name</div></div>
    <div class="stat-card c-green"><div class="stat-icon">&#128225;</div><div class="stat-value">__INTERNETFACINGCOUNT__</div><div class="stat-label">Internet-Facing</div></div>
  </div>

  <div class="health-card">
    <div class="health-ring-wrap">
      <svg viewBox="0 0 76 76">
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--surface3)" stroke-width="9"/>
        <circle cx="38" cy="38" r="30" fill="none" stroke="#3fb950" stroke-width="9"
          stroke-dasharray="188.5" stroke-dashoffset="__HEALTHOFFSET__" stroke-linecap="round"
          transform="rotate(-90 38 38)" id="healthArc" style="transition:stroke-dashoffset 1.2s ease"/>
      </svg>
      <div class="health-ring-center">
        <span class="health-score-num" style="color:#3fb950">__HYGIENESCORE__</span>
        <span class="health-score-pct">/ 100</span>
      </div>
    </div>
    <div class="health-info">
      <h3>Public IP Hygiene Score</h3>
      <p>Percentage of Public IPs with zero flagged issues (unused, dynamic, Basic SKU, no DDoS/DNS/Tags, or idle timeout missing)</p>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">&#128202; By SKU</div>
      __SKUBARS__
    </div>
    <div class="panel">
      <div class="section-title">&#128257; By Allocation Method</div>
      __ALLOCATIONBARS__
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">&#127760; Top Subscriptions by Count</div>
      __SUBSCRIPTIONBARS__
    </div>
    <div class="panel">
      <div class="section-title">&#128193; Top Resource Groups by Count</div>
      __RESOURCEGROUPBARS__
    </div>
  </div>
</section>

<section id="page-allips" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">All Public IPs</div>
      <div class="page-subtitle">Browse, filter and inspect every Public IP in scope</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(true)">&#11015; Export Filtered CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">&#128269;</span>
      <input type="text" id="tableSearch" placeholder="Search name, resource group, IP address... (press / to focus)" oninput="filterTable()"/>
    </div>
    <select id="skuFilter" onchange="filterTable()"><option value="">All SKUs</option></select>
    <select id="attTypeFilter" onchange="filterTable()"><option value="">All Attached Types</option></select>
    <select id="flagFilter" onchange="filterTable()">
      <option value="">All Public IPs</option>
      <option value="unassoc">Unassociated</option>
      <option value="unused">Unused</option>
      <option value="dynamic">Dynamic</option>
      <option value="basicSku">Basic SKU</option>
      <option value="noDdos">No DDoS Protection</option>
      <option value="noDns">No DNS Name</option>
      <option value="noTags">No Tags</option>
    </select>
    <span class="result-count" id="resultCount"></span>
  </div>
  <table class="ips-table">
    <thead><tr>
      <th onclick="sortByCol('name')" id="th-name">Name <span class="sort-arrow">&#8597;</span></th>
      <th onclick="sortByCol('sub')" id="th-sub">Subscription <span class="sort-arrow">&#8597;</span></th>
      <th>Resource Group</th>
      <th onclick="sortByCol('sku')" id="th-sku">SKU <span class="sort-arrow">&#8597;</span></th>
      <th>Allocation</th>
      <th>IP Address</th>
      <th>Attached To</th>
      <th>Flags</th>
    </tr></thead>
    <tbody id="ipsTableBody"></tbody>
  </table>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:12px">
    <span id="pageInfo" style="font-size:12px;color:var(--muted)"></span>
    <div class="pagination" id="pagination"></div>
  </div>
</section>

<section id="page-unused" class="page">
  <div class="page-header">
    <div><div class="page-title">Unused &amp; Unassociated Public IPs</div>
    <div class="page-subtitle">Candidates for cleanup - confirm before deleting</div></div>
  </div>
  <div class="panel">
    __UNUSEDROWS__
  </div>
</section>

<section id="page-bysubscription" class="page">
  <div class="page-header"><div><div class="page-title">By Subscription</div><div class="page-subtitle">Public IP count per subscription</div></div></div>
  <div class="panel">__SUBSCRIPTIONBARSFULL__</div>
</section>

<section id="page-byresourcegroup" class="page">
  <div class="page-header"><div><div class="page-title">By Resource Group</div><div class="page-subtitle">Public IP count per resource group</div></div></div>
  <div class="panel">__RESOURCEGROUPBARSFULL__</div>
</section>

<section id="page-internetfacing" class="page">
  <div class="page-header"><div><div class="page-title">Internet-Facing Resources</div><div class="page-subtitle">Resources reachable via an associated Public IP, grouped by resource type</div></div></div>
  __INTERNETFACINGHTML__
</section>

<section id="page-analytics" class="page">
  <div class="page-header"><div><div class="page-title">Analytics</div><div class="page-subtitle">Coverage across key hygiene checks</div></div></div>
  <div class="analytics-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px">
    <div class="panel">
      <div class="section-title">&#128737; DDoS Protection Coverage</div>
      <div class="bar-row"><span class="bar-label">Protected</span><div class="bar-track"><div class="bar-fill" style="width:__DDOSPCT__%;background:var(--green)"></div></div><span class="bar-count">__DDOSPCT__%</span></div>
    </div>
    <div class="panel">
      <div class="section-title">&#127991; DNS Name Coverage</div>
      <div class="bar-row"><span class="bar-label">Has DNS</span><div class="bar-track"><div class="bar-fill" style="width:__DNSPCT__%;background:var(--accent2)"></div></div><span class="bar-count">__DNSPCT__%</span></div>
    </div>
    <div class="panel">
      <div class="section-title">&#127991; Tag Coverage</div>
      <div class="bar-row"><span class="bar-label">Has Tags</span><div class="bar-track"><div class="bar-fill" style="width:__TAGPCT__%;background:var(--accent3)"></div></div><span class="bar-count">__TAGPCT__%</span></div>
    </div>
    <div class="panel">
      <div class="section-title">&#9201; Idle Timeout Configured</div>
      <div class="bar-row"><span class="bar-label">Configured</span><div class="bar-track"><div class="bar-fill" style="width:__IDLEPCT__%;background:var(--amber)"></div></div><span class="bar-count">__IDLEPCT__%</span></div>
    </div>
  </div>
  <div class="panel" style="margin-top:16px">
    <div class="section-title">&#128202; By Attached Resource Type</div>
    __ATTACHEDTYPEBARS__
  </div>
</section>

</main>

<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDetail()"></div>
  <div id="detailDrawer">
    <div class="detail-toolbar">
      <button class="btn" onclick="copyDetailName()">Copy Name</button>
      <button id="detailClose" onclick="closeDetail()">&times;</button>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<div id="toast"></div>

<script>
const IPS = __IPSJSON__;

function showPage(id, el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  if (el) el.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
}

function toggleTheme(){
  const isLight = document.body.classList.toggle('light-theme');
  document.getElementById('themeIcon').textContent = isLight ? '\u2600' : '\ud83c\udf19';
  document.getElementById('themeLabel').textContent = isLight ? 'Light Mode' : 'Dark Mode';
}

function showToast(msg){
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2200);
}

// -- Populate filter dropdowns --
(function initFilters(){
  const skus = [...new Set(IPS.map(i=>i.sku))].filter(Boolean).sort();
  const skuSel = document.getElementById('skuFilter');
  skus.forEach(s=>{ const o=document.createElement('option'); o.value=s; o.textContent=s; skuSel.appendChild(o); });

  const types = [...new Set(IPS.map(i=>i.attType))].filter(Boolean).sort();
  const typeSel = document.getElementById('attTypeFilter');
  types.forEach(t=>{ const o=document.createElement('option'); o.value=t; o.textContent=t; typeSel.appendChild(o); });
})();

// -- Table state --
let filteredIps = IPS.slice();
let currentPage = 1;
const pageSize = 25;
let sortCol = 'name', sortDir = 1;

function flagBadges(ip){
  let b = '';
  if (ip.unassoc) b += '<span class="badge badge-bad">Unassociated</span>';
  else if (ip.unused) b += '<span class="badge badge-bad">Unused</span>';
  if (ip.dynamic) b += '<span class="badge badge-warn">Dynamic</span>';
  if (ip.basicSku) b += '<span class="badge badge-warn">Basic SKU</span>';
  if (!ip.hasDdos) b += '<span class="badge badge-bad">No DDoS</span>';
  if (!ip.hasDns) b += '<span class="badge badge-warn">No DNS</span>';
  if (!ip.hasTags) b += '<span class="badge badge-warn">No Tags</span>';
  if (!b) b = '<span class="badge badge-ok">Clean</span>';
  return b;
}

function filterTable(){
  const q = (document.getElementById('tableSearch').value || '').toLowerCase();
  const sku = document.getElementById('skuFilter').value;
  const attType = document.getElementById('attTypeFilter').value;
  const flag = document.getElementById('flagFilter').value;

  filteredIps = IPS.filter(ip=>{
    if (q && !((ip.name||'').toLowerCase().includes(q) || (ip.rg||'').toLowerCase().includes(q) || (ip.ip||'').toLowerCase().includes(q))) return false;
    if (sku && ip.sku !== sku) return false;
    if (attType && ip.attType !== attType) return false;
    if (flag === 'unassoc' && !ip.unassoc) return false;
    if (flag === 'unused' && !ip.unused) return false;
    if (flag === 'dynamic' && !ip.dynamic) return false;
    if (flag === 'basicSku' && !ip.basicSku) return false;
    if (flag === 'noDdos' && ip.hasDdos) return false;
    if (flag === 'noDns' && ip.hasDns) return false;
    if (flag === 'noTags' && ip.hasTags) return false;
    return true;
  });

  sortFiltered();
  currentPage = 1;
  renderTable();
}

function sortFiltered(){
  filteredIps.sort((a,b)=>{
    let av = a[sortCol], bv = b[sortCol];
    if (typeof av === 'string') { av = av.toLowerCase(); bv = (bv||'').toLowerCase(); }
    if (av < bv) return -1*sortDir;
    if (av > bv) return 1*sortDir;
    return 0;
  });
}

function sortByCol(col){
  if (sortCol === col) sortDir *= -1; else { sortCol = col; sortDir = 1; }
  document.querySelectorAll('.ips-table th').forEach(th=>th.classList.remove('sort-active'));
  const th = document.getElementById('th-'+col);
  if (th) th.classList.add('sort-active');
  sortFiltered();
  renderTable();
}

function renderTable(){
  const start = (currentPage-1)*pageSize;
  const pageItems = filteredIps.slice(start, start+pageSize);
  document.getElementById('ipsTableBody').innerHTML = pageItems.map(ip=>`
    <tr onclick="openDetail('${escJ(ip.name)}')">
      <td class="td-name">${escH(ip.name)}</td>
      <td class="td-meta">${escH(ip.sub)}</td>
      <td class="td-meta">${escH(ip.rg)}</td>
      <td class="td-meta">${escH(ip.sku)}</td>
      <td class="td-meta">${escH(ip.allocation)}</td>
      <td class="td-meta">${escH(ip.ip||'-')}</td>
      <td class="td-meta">${escH(ip.attType)}${ip.attName?(' / '+escH(ip.attName)):''}</td>
      <td>${flagBadges(ip)}</td>
    </tr>`).join('');

  document.getElementById('resultCount').textContent = filteredIps.length + ' result' + (filteredIps.length!==1?'s':'');
  const totalPages = Math.max(1, Math.ceil(filteredIps.length/pageSize));
  document.getElementById('pageInfo').textContent = `Page ${currentPage} of ${totalPages}`;

  let pagBtns = '';
  pagBtns += `<button class="page-btn" onclick="gotoPage(${currentPage-1})" ${currentPage<=1?'disabled':''}>&laquo;</button>`;
  for (let p=1; p<=totalPages; p++){
    if (p===1 || p===totalPages || Math.abs(p-currentPage)<=2){
      pagBtns += `<button class="page-btn ${p===currentPage?'active':''}" onclick="gotoPage(${p})">${p}</button>`;
    } else if (Math.abs(p-currentPage)===3){
      pagBtns += `<span style="color:var(--muted)">&hellip;</span>`;
    }
  }
  pagBtns += `<button class="page-btn" onclick="gotoPage(${currentPage+1})" ${currentPage>=totalPages?'disabled':''}>&raquo;</button>`;
  document.getElementById('pagination').innerHTML = pagBtns;
}

function gotoPage(p){
  const totalPages = Math.max(1, Math.ceil(filteredIps.length/pageSize));
  if (p<1 || p>totalPages) return;
  currentPage = p;
  renderTable();
}

// -- Detail drawer --
function openDetail(name){
  const ip = IPS.find(x=>x.name===name);
  if (!ip) return;
  document.getElementById('detailContent').innerHTML = `
    <div class="detail-header">
      <div class="detail-name">${escH(ip.name)}</div>
      <div class="detail-path">${escH(ip.sub)} / ${escH(ip.rg)}</div>
    </div>
    <div class="detail-meta-row">
      <span class="detail-chip">${escH(ip.sku)} (${escH(ip.tier)})</span>
      <span class="detail-chip">${escH(ip.allocation)}</span>
      <span class="detail-chip">${escH(ip.version)}</span>
      <span class="detail-chip">${escH(ip.ip||'No IP assigned')}</span>
      <span class="detail-chip">Zones: ${escH(ip.zones||'None')}</span>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Attachment</div>
      <div class="param-card"><div class="param-name">${escH(ip.attType)}</div><div class="param-desc">${escH(ip.attName||'Not attached to any resource')}</div></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">DNS</div>
      <div class="param-card"><div class="param-name">${ip.hasDns?'Configured':'Not configured'}</div><div class="param-desc">${escH(ip.fqdn||ip.dnsLabel||'No DNS name set')}</div></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Security &amp; Config</div>
      <div class="param-card"><div class="param-name">DDoS Protection Mode</div><div class="param-desc">${escH(ip.ddos)}</div></div>
      <div class="param-card"><div class="param-name">Idle Timeout</div><div class="param-desc">${ip.idleTimeout!=null?(ip.idleTimeout+' minutes'):'Not configured'}</div></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Tags (${ip.tagCount})</div>
      <div class="param-card"><div class="param-desc">${escH(ip.tags||'No tags')}</div></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Flags</div>
      <div>${flagBadges(ip)}</div>
    </div>`;
  document.getElementById('detailPanel').classList.add('open');
  document.body.style.overflow='hidden';
}
function closeDetail(){ document.getElementById('detailPanel').classList.remove('open'); document.body.style.overflow=''; }
function copyDetailName(){
  const nameEl = document.querySelector('.detail-name');
  if (nameEl) copyText(nameEl.textContent);
}
function copyText(text){
  try { navigator.clipboard.writeText(text).then(()=>showToast('Copied to clipboard!')); }
  catch(e){ showToast('Copy not available'); }
}

// -- Export --
function exportCSV(filteredOnly){
  const data = filteredOnly ? filteredIps : IPS;
  const esc = v => `"${String(v==null?'':v).replace(/"/g,'""')}"`;
  const header = 'Name,Subscription,ResourceGroup,SKU,Allocation,IPAddress,AttachedType,AttachedName,DNS,Tags,Unassociated,Unused,Dynamic,BasicSku,HasDdos,HasDns,HasTags,InternetFacing';
  const rows = data.map(ip=>[esc(ip.name),esc(ip.sub),esc(ip.rg),esc(ip.sku),esc(ip.allocation),esc(ip.ip),esc(ip.attType),esc(ip.attName),esc(ip.fqdn||ip.dnsLabel),esc(ip.tags),ip.unassoc,ip.unused,ip.dynamic,ip.basicSku,ip.hasDdos,ip.hasDns,ip.hasTags,ip.internetFacing].join(','));
  const blob = new Blob([[header,...rows].join('\r\n')], {type:'text/csv'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'PublicIPInventory.csv'; a.click();
  URL.revokeObjectURL(url);
  showToast(`Exported ${data.length} Public IPs as CSV`);
}

// -- Keyboard shortcuts --
document.addEventListener('keydown', e=>{
  if (e.key === 'Escape') { closeDetail(); return; }
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'SELECT'){
    e.preventDefault();
    const inp = document.querySelector('.page.active input[type=text]');
    if (inp) inp.focus();
  }
});

function escH(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escJ(s){ return String(s==null?'':s).replace(/\\/g,'\\\\').replace(/'/g,"\\'"); }

sortFiltered();
renderTable();
</script>
</body>
</html>
'@

    $healthCircumference = 188.5
    $healthOffset = [math]::Round($healthCircumference * (1 - ($hygieneScore / 100)), 1)

    $html = $html `
        -replace '__SCOPETEXT__', (ConvertTo-SafeReplacementText $ScopeText) `
        -replace '__GENERATEDAT__', (ConvertTo-SafeReplacementText $generatedAt) `
        -replace '__TOTALCOUNT__', $Records.Count `
        -replace '__UNASSOCIATEDCOUNT__', $unassociated `
        -replace '__UNUSEDCOUNT__', $unused `
        -replace '__DYNAMICCOUNT__', $dynamic `
        -replace '__BASICSKUCOUNT__', $basicSku `
        -replace '__NODDOSCOUNT__', $noDdos `
        -replace '__NODNSCOUNT__', $noDns `
        -replace '__INTERNETFACINGCOUNT__', $internetFacing `
        -replace '__HYGIENESCORE__', $hygieneScore `
        -replace '__HEALTHOFFSET__', $healthOffset `
        -replace '__SKUBARS__', (ConvertTo-SafeReplacementText $skuBarsHtml) `
        -replace '__ALLOCATIONBARS__', (ConvertTo-SafeReplacementText $allocationBarsHtml) `
        -replace '__SUBSCRIPTIONBARSFULL__', (ConvertTo-SafeReplacementText $subscriptionBarsHtml) `
        -replace '__RESOURCEGROUPBARSFULL__', (ConvertTo-SafeReplacementText $resourceGroupBarsHtml) `
        -replace '__SUBSCRIPTIONBARS__', (ConvertTo-SafeReplacementText $subscriptionBarsHtml) `
        -replace '__RESOURCEGROUPBARS__', (ConvertTo-SafeReplacementText $resourceGroupBarsHtml) `
        -replace '__ATTACHEDTYPEBARS__', (ConvertTo-SafeReplacementText $attachedTypeBarsHtml) `
        -replace '__UNUSEDROWS__', (ConvertTo-SafeReplacementText $unusedRowsHtml) `
        -replace '__INTERNETFACINGHTML__', (ConvertTo-SafeReplacementText $internetFacingHtml) `
        -replace '__DDOSPCT__', $ddosCoveragePct `
        -replace '__DNSPCT__', $dnsCoveragePct `
        -replace '__TAGPCT__', $tagCoveragePct `
        -replace '__IDLEPCT__', $idleCoveragePct `
        -replace '__IPSJSON__', (ConvertTo-SafeReplacementText $ipsJson)

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzurePublicIPInventory
{
    [CmdletBinding()]
    param (
        [string[]]$SubscriptionIds,
        [string[]]$ResourceGroupNames,
        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzurePublicIPInventory-Report.csv",
        [string]$HtmlPath,
        [switch]$AllSubscriptions,
        [switch]$GenerateHtmlDashboard,
        [switch]$OpenDashboardInBrowser
    )

    $startTime = Get-Date
    Write-Banner

    foreach ($moduleName in @("Az.Accounts", "Az.Network")) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Host "  [!] $moduleName module not found" -ForegroundColor Yellow
            Write-Host ""
            $installModule = Read-Host "  Install now? (Y/N)"
            if ($installModule -eq 'Y' -or $installModule -eq 'y') {
                try {
                    Write-Host ""
                    Write-Host "  Installing $moduleName, please wait..." -ForegroundColor Cyan
                    Install-Module -Name $moduleName -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                    Import-Module $moduleName -ErrorAction Stop
                    Write-Host "  [OK] $moduleName installed successfully" -ForegroundColor Green
                }
                catch {
                    Write-Host "  [X] Error installing ${moduleName}: $_" -ForegroundColor Red
                    return
                }
            }
            else {
                Write-Host "  Installation declined. Cannot proceed without $moduleName." -ForegroundColor Yellow
                return
            }
        }
    }

    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext) {
        Write-Host "  [!] No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    if ($AllSubscriptions -or -not $SubscriptionIds) {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText = "All Subscriptions"
    }
    else {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count))"
    }
    $fullScopeText = "$scopeText ($($subscriptions.Count) found)"

    Write-Section -Title "Session Information" -Data @{
        "Tenant"  = $currentContext.Tenant.Id
        "Account" = $currentContext.Account.Id
    }
    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"                 = $fullScopeText
        "Resource Group Filter" = ($ResourceGroupNames -join ", ")
        "HTML Dashboard"        = if ($GenerateHtmlDashboard.IsPresent) { "Enabled" } else { "Disabled" }
    }

    $allRecords = @()
    $nicVmCache = @{}

    $subIndex = 0
    foreach ($sub in $subscriptions) {
        $subIndex++
        Write-ProgressBar -Current $subIndex -Total $subscriptions.Count -CurrentItem $sub.Name

        try {
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $publicIps = @(Get-AzPublicIpAddress -ErrorAction Stop)
            if ($ResourceGroupNames) {
                $publicIps = $publicIps | Where-Object { $ResourceGroupNames -contains $_.ResourceGroupName }
            }

            foreach ($pip in $publicIps) {
                try {
                    $allRecords += ConvertTo-NormalizedPublicIp -PublicIp $pip -SubscriptionId $sub.Id -SubscriptionName $sub.Name -NicVmCache $nicVmCache
                }
                catch {
                    Write-Warning "Failed to normalize Public IP '$($pip.Name)': $_"
                }
            }
        }
        catch {
            Write-Warning "Failed to scan subscription '$($sub.Name)': $_"
        }
    }
    Write-Host ""

    $endTime = Get-Date
    $durationFormatted = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-InventorySummary -Records $allRecords

    Write-Host ""
    Write-Host "  Scan Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray
    Write-Host "  Subscriptions Scanned".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($subscriptions.Count)" -ForegroundColor White
    Write-Host "  Public IPs Inventoried".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($allRecords.Count)" -ForegroundColor White
    Write-Host "  Execution Time".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $durationFormatted" -ForegroundColor White

    # -- CSV export (always on) --
    $csvExported = $false
    try {
        $allRecords | Export-Csv -Path $CsvPath -NoTypeInformation
        $csvExported = $true
    }
    catch {
        Write-Host "  [X] CSV export failed: $_" -ForegroundColor Red
    }

    # -- HTML dashboard (optional) --
    $htmlExported = $false
    $resolvedHtmlPath = $null
    if ($GenerateHtmlDashboard) {
        try {
            $resolvedHtmlPath = if ($HtmlPath) { $HtmlPath } else { [System.IO.Path]::ChangeExtension($CsvPath, '.html') }
            $sessionInfo = @{ Tenant = $currentContext.Tenant.Id; Account = $currentContext.Account.Id }
            $htmlContent = Get-PublicIpDashboardHtml -Records $allRecords -SessionInfo $sessionInfo -ScopeText $fullScopeText
            $htmlContent | Out-File -FilePath $resolvedHtmlPath -Encoding UTF8
            $htmlExported = $true
        }
        catch {
            Write-Host "  [X] HTML dashboard generation failed: $_" -ForegroundColor Red
        }
    }

    Write-OutputFiles -CsvPath $(if ($csvExported) { $CsvPath } else { $null }) -HtmlPath $(if ($htmlExported) { $resolvedHtmlPath } else { $null })

    if ($htmlExported -and $OpenDashboardInBrowser) {
        try { Start-Process $resolvedHtmlPath } catch { Write-Warning "Could not open dashboard in browser: $_" }
    }
}
