<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 29 July 2026
Modified-On  : 29 July 2026

.SYNOPSIS
    Analyzes Azure Firewall rules (Classic rule collections and Firewall Policy rule
    collection groups) across one or more subscriptions for hygiene, redundancy, and
    security-exposure issues, with CSV export and an auto-generated HTML findings report.

.DESCRIPTION
    The Get-AzureFirewallRules function inventories every Azure Firewall visible to the
    caller (Classic model and Firewall-Policy-based model, auto-detected per firewall) and
    runs a fixed set of hygiene / redundancy / security checks against the normalized rule
    set:

        - Duplicate rules (identical match criteria under a different name)
        - Overlapping rules (partial match-criteria overlap)
        - Shadowed rules (unreachable because an earlier, higher-precedence rule already
          matches a superset of the traffic)
        - Unused rules (best-effort; requires -LogAnalyticsWorkspaceId, otherwise reported
          as "Not Evaluated" rather than asserted as unused)
        - Disabled rules (Firewall Policy rule collections only; Classic model has no
          per-collection enable/disable state)
        - Expired temporary rules (derived from an "Owner" tag on the firewall/policy and
          a TEMP-<Owner>-<yyyyMMdd> rule-naming convention; see .NOTES)
        - Any-to-Any rules (source = Any AND destination = Any)
        - Internet-exposed management ports (RDP 3389, SSH 22, WinRM 5985/5986 reachable
          from an Internet-equivalent source)
        - Open high-risk ports (a fixed high-risk port list allowed from a broad source)
        - Allow rules with Any source / Any destination / Any port
        - Rules without a Description
        - Rules without a resolvable Owner
        - Empty rule collections
        - Duplicate collection priorities
        - Rule/collection priority conflicts (insufficient priority spacing)
        - Large port ranges (wider than -LargePortRangeThreshold ports)
        - Broad IP ranges (CIDR prefix shorter than -BroadIpPrefixThreshold)
        - Threat Intelligence mode (flags Off)
        - Diagnostic logging enabled (flags firewalls with no enabled diagnostic setting)

    Findings are written to the console (color-coded by severity), exported to CSV
    (optional), and always rendered into a self-contained Azure-themed HTML report.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored if -AllSubscriptions
    is also specified.

.PARAMETER ResourceGroupNames
    Optional filter. Restricts the scan to firewalls in the specified resource group(s).

.PARAMETER FirewallNames
    Optional filter. Restricts the scan to firewalls matching the specified name(s).

.PARAMETER CsvPath
    Path where the findings CSV export will be written if -ExportToCsv is specified. Also
    used to derive the HTML report's file name/location (same path, .html extension).
    Default: C:\Temp\AzureFirewallRules-Report.csv

.PARAMETER LogAnalyticsWorkspaceId
    Optional. Resource ID of a Log Analytics workspace receiving
    AzureFirewallNetworkRule / AzureFirewallApplicationRule diagnostic logs. If supplied,
    enables best-effort "Unused Rule" detection over the last -UnusedRuleLookbackDays days.
    If omitted, Unused Rule findings are reported as "Not Evaluated".

.PARAMETER UnusedRuleLookbackDays
    Number of days of Log Analytics data to consider for Unused Rule detection.
    Default: 30. Ignored if -LogAnalyticsWorkspaceId is not supplied.

.PARAMETER LargePortRangeThreshold
    A destination port range wider than this many ports is flagged as "Large Port Range".
    Default: 100.

.PARAMETER BroadIpPrefixThreshold
    A source or destination CIDR with a prefix length shorter than this value (i.e.
    covering more addresses) is flagged as "Broad IP Range". Default: 24 (a /16 is
    broader than /24 and would be flagged; a /28 would not).

.PARAMETER PriorityGapWarningThreshold
    Minimum recommended numeric gap between consecutive rule-collection priorities.
    Gaps smaller than this are flagged as a "Rule Priority Conflict" (maintenance risk).
    Default: 10.

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account/context.
    This is also the default behavior if -SubscriptionIds is not supplied.

.PARAMETER ExportToCsv
    Switch. If specified, exports all findings to the path given in -CsvPath. An HTML
    report is generated regardless of whether this switch is used.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML report alongside -CsvPath (or
    the default path). Optionally writes a CSV file if -ExportToCsv is specified.
    Displays findings in an interactive Grid View window where a GUI is available.

.EXAMPLE
    Get-AzureFirewallRules -AllSubscriptions

.EXAMPLE
    Get-AzureFirewallRules -SubscriptionIds @("SubscriptionID1","SubscriptionID2")

.EXAMPLE
    Get-AzureFirewallRules -AllSubscriptions -ResourceGroupNames "rg-network-prod" -FirewallNames "fw-hub-eastus"

.EXAMPLE
    Get-AzureFirewallRules -AllSubscriptions -LogAnalyticsWorkspaceId "/subscriptions/xxx/resourceGroups/rg-logs/providers/Microsoft.OperationalInsights/workspaces/law-hub" -UnusedRuleLookbackDays 60

.EXAMPLE
    Get-AzureFirewallRules -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\FirewallFindings.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (29-Jul-2026) - Initial release.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts and Az.Network modules (installed/imported automatically if
       missing, with user consent at the console prompt).
    2. Az.Monitor module if diagnostic-logging checks are to run against real
       diagnostic settings (attempted automatically; check is skipped gracefully
       if unavailable).
    3. Az.OperationalInsights module only if -LogAnalyticsWorkspaceId is supplied
       (used for best-effort Unused Rule detection).
    4. Reader role (minimum) on each target subscription; Log Analytics Reader on
       the workspace if -LogAnalyticsWorkspaceId is used.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Owner / Expiry derivation is heuristic, not a native Azure Firewall property.
      Owner resolution order per rule: (1) an "Owner" tag on the parent Firewall or
      Firewall Policy resource is used as the default owner for every rule on that
      firewall; (2) if the rule name matches the convention
      TEMP-<Owner>-<yyyyMMdd> (case-insensitive), the <Owner> token and the date
      override the tag-derived owner/expiry for that rule only. Rules matching
      neither are reported as "Owner: Could not be confirmed".
    - IP Groups, Service Tags, and FQDN Tags are NOT resolved to their underlying
      address/FQDN lists (would require additional API calls per group/tag and,
      for Service Tags, a point-in-time download). Rules referencing them are
      still inventoried and flagged for the checks that don't require resolution
      (missing description/owner, disabled state, etc.), but are excluded from
      automated Overlap/Shadow/Broad-IP-Range comparisons and separately called
      out as "Contains unresolved IP Group/Service Tag/FQDN Tag - manual review
      recommended".
    - IPv6 addresses are not resolved to numeric ranges for overlap/shadow/broad
      checks; IPv6 entries are inventoried but skipped in those specific checks
      and flagged as "Contains IPv6 - not evaluated for overlap".
    - Shadow/Overlap detection assumes standard Azure Firewall Policy evaluation
      order (DNAT, then Network, then Application; rule collection groups and
      rule collections evaluated in ascending priority order) and compares rules
      of the same rule type only. It is a heuristic based on match-criteria
      containment, not a packet-level simulation; flagged pairs should be
      manually confirmed before removing a rule.
    - Unused Rule detection requires -LogAnalyticsWorkspaceId and depends on the
      AzureFirewallNetworkRule / AzureFirewallApplicationRule diagnostic
      categories being enabled and populated for the lookback window. Without a
      workspace, or if a query fails, Unused Rule status is reported as
      "Not Evaluated" rather than asserted as unused, per team convention.
    - Firewall Policy parent/child (base policy) inheritance chains are not
      walked; only the rule collection groups directly attached to the policy
      referenced by the firewall are scanned.
    - If neither -AllSubscriptions nor -SubscriptionIds is supplied, the function
      defaults to scanning ALL subscriptions visible to the current account with
      no additional confirmation prompt (matches existing toolkit convention).
    - Interactive Grid View requires a GUI-capable session (Windows PowerShell
      ISE, or Microsoft.PowerShell.GraphicalTools on PS7). In headless/CI/Linux
      sessions this step is skipped gracefully; CSV/HTML output is unaffected.
    - Default -CsvPath (C:\Temp\...) is a Windows-specific path. On macOS/Linux
      PowerShell 7, supply an explicit -CsvPath.

.LINK
    https://learn.microsoft.com/en-us/azure/firewall/rule-processing
.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.network/get-azfirewall
.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.network/get-azfirewallpolicy

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
    Write-CenteredText "Azure Firewall Rule Analyzer v1.0" -Color White
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
        $displayItem = if ($CurrentItem.Length -gt $maxLength) {
            $CurrentItem.Substring(0, $maxLength - 3) + "..."
        } else {
            $CurrentItem
        }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-FindingsSummary {
    param([array]$Findings)

    $bySeverity = $Findings | Group-Object Severity

    Write-Host ""
    Write-Host "  Findings Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    foreach ($sevName in @("Critical", "High", "Medium", "Low", "Info")) {
        $grp = $bySeverity | Where-Object { $_.Name -eq $sevName }
        $count = if ($grp) { $grp.Count } else { 0 }
        $color = switch ($sevName) {
            "Critical" { "Red" }
            "High"     { "Red" }
            "Medium"   { "Yellow" }
            "Low"      { "Gray" }
            "Info"     { "DarkGray" }
        }
        Write-Host "  " -NoNewline
        Write-Host $sevName.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $count -ForegroundColor $color
    }
}

Function Write-FindingsByType {
    param([array]$Findings)

    Write-Host ""
    Write-Host "  Findings by Check" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    foreach ($grp in ($Findings | Group-Object FindingType | Sort-Object Count -Descending)) {
        Write-Host "  " -NoNewline
        Write-Host $grp.Name.PadRight(45) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($grp.Count)" -ForegroundColor Cyan
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
        Write-Host (("HTML Report").PadRight(20) + ": ") -NoNewline -ForegroundColor Gray
        Write-Host $HtmlPath -ForegroundColor White
    }

    if ($GridViewOpened) {
        Write-Host "  " -NoNewline
        Write-Host "[OK] " -NoNewline -ForegroundColor Green
        Write-Host (("Grid View").PadRight(20) + ": ") -NoNewline -ForegroundColor Gray
        Write-Host "Opened in separate window" -ForegroundColor White
    }

    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
}


#------------------------------------------------------------------------ [ Parsing / Normalization Helpers ]

Function Test-IsAnyValue {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return $Value.Trim() -in @("*", "any", "Any", "ANY")
}

Function Test-IsInternetEquivalent {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()
    return (Test-IsAnyValue $v) -or ($v -in @("0.0.0.0/0", "::/0", "Internet"))
}

Function Test-IsIPv4Cidr {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return $Value -match '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$'
}

Function ConvertTo-UInt32IP {
    param([Parameter(Mandatory)][string]$IpString)
    $ip = [System.Net.IPAddress]::Parse($IpString)
    $bytes = $ip.GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    return [BitConverter]::ToUInt32($bytes, 0)
}

Function Get-CidrRange {
    <#
        Returns @{ Start = [uint32]; End = [uint32]; Prefix = [int]; Resolved = $true }
        for a resolvable IPv4 literal/CIDR/Any value, or @{ Resolved = $false } for
        anything this function cannot safely resolve (IP Groups, Service Tags, FQDNs,
        IPv6, malformed input).
    #>
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @{ Resolved = $false; Reason = "Empty" }
    }

    $v = $Value.Trim()

    if (Test-IsInternetEquivalent $v) {
        return @{ Start = [uint32]0; End = [uint32]4294967295; Prefix = 0; Resolved = $true }
    }

    if (-not (Test-IsIPv4Cidr $v)) {
        return @{ Resolved = $false; Reason = "Unresolved (IP Group / Service Tag / FQDN / IPv6)" }
    }

    try {
        if ($v -match '^(?<ip>[\d\.]+)/(?<prefix>\d{1,2})$') {
            $ipPart = $Matches['ip']
            $prefix = [int]$Matches['prefix']
        } else {
            $ipPart = $v
            $prefix = 32
        }

        if ($prefix -lt 0 -or $prefix -gt 32) {
            return @{ Resolved = $false; Reason = "Invalid prefix" }
        }

        $baseValue = ConvertTo-UInt32IP -IpString $ipPart
        if ($prefix -eq 0) {
            $mask = [uint32]0
        } else {
            $mask = [uint32]([uint64]4294967295 -shl (32 - $prefix))
        }
        $start = $baseValue -band $mask
        $hostBits = 32 - $prefix
        $rangeSize = if ($hostBits -ge 32) { [uint64]4294967295 } else { ([uint64]1 -shl $hostBits) - 1 }
        $end = [uint32]([uint64]$start + $rangeSize)

        return @{ Start = [uint32]$start; End = $end; Prefix = $prefix; Resolved = $true }
    }
    catch {
        return @{ Resolved = $false; Reason = "Parse error: $_" }
    }
}

Function Test-CidrOverlap {
    param([hashtable]$RangeA, [hashtable]$RangeB)
    if (-not $RangeA.Resolved -or -not $RangeB.Resolved) { return $false }
    return -not (($RangeA.End -lt $RangeB.Start) -or ($RangeB.End -lt $RangeA.Start))
}

Function Test-CidrSuperset {
    <# Does RangeA fully contain RangeB? #>
    param([hashtable]$RangeA, [hashtable]$RangeB)
    if (-not $RangeA.Resolved -or -not $RangeB.Resolved) { return $false }
    return ($RangeA.Start -le $RangeB.Start) -and ($RangeA.End -ge $RangeB.End)
}

Function ConvertTo-PortRanges {
    <# Accepts an array of port strings ("80", "8080-8090", "*") and returns an array of @{Start;End} #>
    param([string[]]$Ports)

    $ranges = @()
    foreach ($p in $Ports) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $token = $p.Trim()
        if (Test-IsAnyValue $token) {
            $ranges += @{ Start = 0; End = 65535 }
        }
        elseif ($token -match '^(?<s>\d+)-(?<e>\d+)$') {
            $ranges += @{ Start = [int]$Matches['s']; End = [int]$Matches['e'] }
        }
        elseif ($token -match '^\d+$') {
            $ranges += @{ Start = [int]$token; End = [int]$token }
        }
    }
    return $ranges
}

Function Test-PortRangesOverlap {
    param([array]$RangesA, [array]$RangesB)
    foreach ($a in $RangesA) {
        foreach ($b in $RangesB) {
            if (-not (($a.End -lt $b.Start) -or ($b.End -lt $a.Start))) { return $true }
        }
    }
    return $false
}

Function Test-PortRangesSuperset {
    <# Does every range in RangesB fall inside at least one range in RangesA? #>
    param([array]$RangesA, [array]$RangesB)
    if ($RangesB.Count -eq 0) { return $false }
    foreach ($b in $RangesB) {
        $covered = $false
        foreach ($a in $RangesA) {
            if ($a.Start -le $b.Start -and $a.End -ge $b.End) { $covered = $true; break }
        }
        if (-not $covered) { return $false }
    }
    return $true
}

Function Get-RuleOwnerAndExpiry {
    <#
        Resolution order (see .NOTES "Known Limitations" in the main function's help):
          1. Rule name matches TEMP-<Owner>-<yyyyMMdd> (or yyyy-MM-dd) -> Owner + ExpiryDate
             from the name, regardless of tag.
          2. Otherwise, fall back to the "Owner" tag on the parent Firewall/Policy resource.
          3. Otherwise, Owner = $null (reported as "Could not be confirmed").
    #>
    param(
        [string]$RuleName,
        [hashtable]$ResourceTags
    )

    $result = [pscustomobject]@{
        Owner       = $null
        ExpiryDate  = $null
        IsTemporary = $false
    }

    if (-not [string]::IsNullOrWhiteSpace($RuleName) -and $RuleName -match '(?i)^TEMP[-_](?<owner>[A-Za-z0-9]+)[-_](?<date>\d{4}-?\d{2}-?\d{2})') {
        $result.IsTemporary = $true
        $result.Owner = $Matches['owner']
        $rawDate = $Matches['date'] -replace '-', ''
        try {
            $result.ExpiryDate = [datetime]::ParseExact($rawDate, "yyyyMMdd", $null)
        }
        catch {
            $result.ExpiryDate = $null
        }
        return $result
    }

    if ($ResourceTags) {
        $ownerKey = $ResourceTags.Keys | Where-Object { $_ -ieq "Owner" } | Select-Object -First 1
        if ($ownerKey) {
            $result.Owner = $ResourceTags[$ownerKey]
        }
    }

    return $result
}

Function Get-HighRiskPortMap {
    return [ordered]@{
        21    = "FTP"
        22    = "SSH"
        23    = "Telnet"
        135   = "RPC/DCOM"
        139   = "NetBIOS"
        445   = "SMB"
        1433  = "MSSQL"
        1434  = "MSSQL Browser"
        3306  = "MySQL"
        3389  = "RDP"
        5432  = "PostgreSQL"
        5900  = "VNC"
        5985  = "WinRM (HTTP)"
        5986  = "WinRM (HTTPS)"
        6379  = "Redis"
        9200  = "Elasticsearch"
        27017 = "MongoDB"
    }
}

Function Get-ManagementPortMap {
    return [ordered]@{
        22   = "SSH"
        3389 = "RDP"
        5985 = "WinRM (HTTP)"
        5986 = "WinRM (HTTPS)"
    }
}


#------------------------------------------------------------------------ [ Rule Normalization ]

Function ConvertTo-NormalizedRule {
    <#
        Produces one common-schema PSCustomObject per rule regardless of Classic vs
        Policy origin. See main function help for the full field list / conventions.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SubscriptionName,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$FirewallName,
        [Parameter(Mandatory)][string]$FirewallResourceId,
        [Parameter(Mandatory)][ValidateSet("Classic", "Policy")][string]$RuleModel,
        [string]$PolicyName,
        [string]$CollectionGroupName,
        [Nullable[int]]$CollectionGroupPriority,
        [Parameter(Mandatory)][string]$CollectionName,
        [Parameter(Mandatory)][int]$CollectionPriority,
        [Parameter(Mandatory)][string]$CollectionAction,
        [Parameter(Mandatory)][string]$CollectionState,
        [Parameter(Mandatory)][ValidateSet("Network", "Application", "Nat")][string]$RuleType,
        [Parameter(Mandatory)]$RawRule,
        [hashtable]$FirewallTags
    )

    $ruleName = $RawRule.Name
    $description = $RawRule.Description

    $protocols = @()
    if ($RawRule.Protocols) {
        foreach ($proto in $RawRule.Protocols) {
            if ($proto.PSObject.Properties.Name -contains "ProtocolType") {
                $protocols += $proto.ProtocolType
            } else {
                $protocols += [string]$proto
            }
        }
    }

    $sourceAddresses = @()
    if ($RawRule.SourceAddresses) { $sourceAddresses = @($RawRule.SourceAddresses) }
    $sourceIpGroups = @()
    if ($RawRule.SourceIpGroups) { $sourceIpGroups = @($RawRule.SourceIpGroups) }

    $destAddresses = @()
    if ($RawRule.DestinationAddresses) { $destAddresses = @($RawRule.DestinationAddresses) }
    $destIpGroups = @()
    if ($RawRule.DestinationIpGroups) { $destIpGroups = @($RawRule.DestinationIpGroups) }
    $destFqdns = @()
    if ($RawRule.DestinationFqdns) { $destFqdns = @($RawRule.DestinationFqdns) }

    $targetFqdns = @()
    if ($RawRule.TargetFqdns) { $targetFqdns = @($RawRule.TargetFqdns) }
    $fqdnTags = @()
    if ($RawRule.FqdnTags) { $fqdnTags = @($RawRule.FqdnTags) }

    $destPorts = @()
    if ($RawRule.DestinationPorts) { $destPorts = @($RawRule.DestinationPorts) }
    elseif ($RawRule.Protocols -and ($RawRule.Protocols[0].PSObject.Properties.Name -contains "Port")) {
        $destPorts = @($RawRule.Protocols | ForEach-Object { [string]$_.Port })
    }

    $translatedAddress = $RawRule.TranslatedAddress
    $translatedPort = $RawRule.TranslatedPort

    $ownerInfo = Get-RuleOwnerAndExpiry -RuleName $ruleName -ResourceTags $FirewallTags
    $isExpired = $false
    if ($ownerInfo.ExpiryDate -and $ownerInfo.ExpiryDate -lt (Get-Date).Date) {
        $isExpired = $true
    }

    return [pscustomobject]@{
        SubscriptionId          = $SubscriptionId
        SubscriptionName        = $SubscriptionName
        ResourceGroupName       = $ResourceGroupName
        FirewallName            = $FirewallName
        FirewallResourceId      = $FirewallResourceId
        RuleModel                = $RuleModel
        PolicyName               = $PolicyName
        CollectionGroupName      = $CollectionGroupName
        CollectionGroupPriority  = $CollectionGroupPriority
        CollectionName           = $CollectionName
        CollectionPriority       = $CollectionPriority
        CollectionAction         = $CollectionAction
        CollectionState          = $CollectionState
        RuleName                 = $ruleName
        RuleType                 = $RuleType
        Description              = $description
        Protocols                = $protocols
        SourceAddresses          = $sourceAddresses
        SourceIpGroups           = $sourceIpGroups
        DestinationAddresses     = $destAddresses
        DestinationIpGroups      = $destIpGroups
        DestinationFqdns         = $destFqdns
        TargetFqdns              = $targetFqdns
        FqdnTags                 = $fqdnTags
        DestinationPorts         = $destPorts
        TranslatedAddress        = $translatedAddress
        TranslatedPort           = $translatedPort
        Owner                    = $ownerInfo.Owner
        ExpiryDate               = $ownerInfo.ExpiryDate
        IsTemporary              = $ownerInfo.IsTemporary
        IsExpired                = $isExpired
        SortKey                  = "{0:D10}-{1:D10}" -f [int]($(if ($CollectionGroupPriority) { $CollectionGroupPriority } else { 0 })), $CollectionPriority
    }
}

Function Get-FirewallRuleInventory {
    <#
        Given one Az Firewall PSObject, returns @{ Rules = [array]; RuleModel; ThreatIntelMode;
        PolicyTags; FirewallTags } normalizing both Classic and Policy-based firewalls.
    #>
    param(
        [Parameter(Mandatory)]$Firewall,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SubscriptionName
    )

    $rules = @()
    $firewallTags = @{}
    if ($Firewall.Tag) {
        foreach ($k in $Firewall.Tag.Keys) { $firewallTags[$k] = $Firewall.Tag[$k] }
    }

    $threatIntelMode = $Firewall.ThreatIntelMode
    $ruleModel = "Classic"
    $policyName = $null

    if ($Firewall.FirewallPolicy -and $Firewall.FirewallPolicy.Id) {
        $ruleModel = "Policy"

        try {
            $policy = Get-AzFirewallPolicy -ResourceId $Firewall.FirewallPolicy.Id -ErrorAction Stop
            $policyName = $policy.Name
            if ($policy.ThreatIntelMode) { $threatIntelMode = $policy.ThreatIntelMode }

            if ($policy.Tag) {
                foreach ($k in $policy.Tag.Keys) {
                    if (-not $firewallTags.ContainsKey($k)) { $firewallTags[$k] = $policy.Tag[$k] }
                }
            }

            $ruleCollectionGroups = @()
            if ($policy.RuleCollectionGroups) {
                foreach ($rcgRef in $policy.RuleCollectionGroups) {
                    try {
                        $ruleCollectionGroups += Get-AzFirewallPolicyRuleCollectionGroup -ResourceId $rcgRef.Id -ErrorAction Stop
                    }
                    catch {
                        Write-Warning "Could not retrieve rule collection group '$($rcgRef.Id)': $_"
                    }
                }
            }

            foreach ($rcg in $ruleCollectionGroups) {
                $groupPriority = $rcg.Priority
                if (-not $rcg.RuleCollection -or $rcg.RuleCollection.Count -eq 0) {
                    # Empty rule collection group - captured separately as a "collection" style
                    # finding via the CollectionInventory list below (RuleCollection empty).
                    continue
                }
                foreach ($rc in $rcg.RuleCollection) {
                    $collectionAction = if ($rc.Action -and $rc.Action.Type) { $rc.Action.Type } else { "Unknown" }
                    $collectionState = if ($rc.RuleCollectionType) { $(if ($rc.PSObject.Properties.Name -contains "Priority") { "Enabled" } else { "Unknown" }) } else { "Unknown" }
                    # PSFirewallPolicyFilterRuleCollection exposes no direct enable flag in
                    # some Az.Network versions; where present, honor it explicitly:
                    if ($rc.PSObject.Properties.Name -contains "DisableRuleCollection" -and $rc.DisableRuleCollection) {
                        $collectionState = "Disabled"
                    } elseif ($rc.PSObject.Properties.Name -contains "DisableRuleCollection") {
                        $collectionState = "Enabled"
                    }

                    $ruleTypeForCollection = switch ($rc.RuleCollectionType) {
                        "FirewallPolicyFilterRuleCollection" {
                            if ($rc.Rule -and $rc.Rule.Count -gt 0) {
                                switch ($rc.Rule[0].RuleType) {
                                    "ApplicationRule" { "Application" }
                                    "NetworkRule"      { "Network" }
                                    default            { "Network" }
                                }
                            } else { "Network" }
                        }
                        "FirewallPolicyNatRuleCollection" { "Nat" }
                        default { "Network" }
                    }

                    if (-not $rc.Rule -or $rc.Rule.Count -eq 0) { continue }

                    foreach ($rawRule in $rc.Rule) {
                        $rules += ConvertTo-NormalizedRule -SubscriptionId $SubscriptionId `
                            -SubscriptionName $SubscriptionName -ResourceGroupName $Firewall.ResourceGroupName `
                            -FirewallName $Firewall.Name -FirewallResourceId $Firewall.Id `
                            -RuleModel "Policy" -PolicyName $policyName `
                            -CollectionGroupName $rcg.Name -CollectionGroupPriority $groupPriority `
                            -CollectionName $rc.Name -CollectionPriority $rc.Priority `
                            -CollectionAction $collectionAction -CollectionState $collectionState `
                            -RuleType $ruleTypeForCollection -RawRule $rawRule -FirewallTags $firewallTags
                    }
                }
            }
        }
        catch {
            Write-Warning "Could not retrieve Firewall Policy for '$($Firewall.Name)': $_"
        }
    }
    else {
        # Classic model - rule collections live directly on the firewall object.
        foreach ($rc in @($Firewall.NetworkRuleCollections)) {
            if (-not $rc) { continue }
            $collectionAction = if ($rc.Action -and $rc.Action.Type) { $rc.Action.Type } else { "Unknown" }
            if (-not $rc.Rules -or $rc.Rules.Count -eq 0) { continue }
            foreach ($rawRule in $rc.Rules) {
                $rules += ConvertTo-NormalizedRule -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceGroupName $Firewall.ResourceGroupName `
                    -FirewallName $Firewall.Name -FirewallResourceId $Firewall.Id `
                    -RuleModel "Classic" -PolicyName $null `
                    -CollectionGroupName $null -CollectionGroupPriority $null `
                    -CollectionName $rc.Name -CollectionPriority $rc.Priority `
                    -CollectionAction $collectionAction -CollectionState "N/A" `
                    -RuleType "Network" -RawRule $rawRule -FirewallTags $firewallTags
            }
        }
        foreach ($rc in @($Firewall.ApplicationRuleCollections)) {
            if (-not $rc) { continue }
            $collectionAction = if ($rc.Action -and $rc.Action.Type) { $rc.Action.Type } else { "Unknown" }
            if (-not $rc.Rules -or $rc.Rules.Count -eq 0) { continue }
            foreach ($rawRule in $rc.Rules) {
                $rules += ConvertTo-NormalizedRule -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceGroupName $Firewall.ResourceGroupName `
                    -FirewallName $Firewall.Name -FirewallResourceId $Firewall.Id `
                    -RuleModel "Classic" -PolicyName $null `
                    -CollectionGroupName $null -CollectionGroupPriority $null `
                    -CollectionName $rc.Name -CollectionPriority $rc.Priority `
                    -CollectionAction $collectionAction -CollectionState "N/A" `
                    -RuleType "Application" -RawRule $rawRule -FirewallTags $firewallTags
            }
        }
        foreach ($rc in @($Firewall.NatRuleCollections)) {
            if (-not $rc) { continue }
            $collectionAction = if ($rc.Action -and $rc.Action.Type) { $rc.Action.Type } else { "Unknown" }
            if (-not $rc.Rules -or $rc.Rules.Count -eq 0) { continue }
            foreach ($rawRule in $rc.Rules) {
                $rules += ConvertTo-NormalizedRule -SubscriptionId $SubscriptionId `
                    -SubscriptionName $SubscriptionName -ResourceGroupName $Firewall.ResourceGroupName `
                    -FirewallName $Firewall.Name -FirewallResourceId $Firewall.Id `
                    -RuleModel "Classic" -PolicyName $null `
                    -CollectionGroupName $null -CollectionGroupPriority $null `
                    -CollectionName $rc.Name -CollectionPriority $rc.Priority `
                    -CollectionAction $collectionAction -CollectionState "N/A" `
                    -RuleType "Nat" -RawRule $rawRule -FirewallTags $firewallTags
            }
        }
    }

    return [pscustomobject]@{
        Rules           = $rules
        RuleModel       = $ruleModel
        PolicyName      = $policyName
        ThreatIntelMode = $threatIntelMode
        FirewallTags    = $firewallTags
    }
}


#------------------------------------------------------------------------ [ Finding Helpers ]

Function New-Finding {
    param(
        [Parameter(Mandatory)][string]$FindingType,
        [Parameter(Mandatory)][ValidateSet("Critical", "High", "Medium", "Low", "Info")][string]$Severity,
        [string]$SubscriptionName,
        [string]$FirewallName,
        [string]$CollectionGroupName,
        [string]$CollectionName,
        [string]$RuleName,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Recommendation
    )

    return [pscustomobject]@{
        FindingType         = $FindingType
        Severity            = $Severity
        SubscriptionName    = $SubscriptionName
        FirewallName        = $FirewallName
        CollectionGroupName = $CollectionGroupName
        CollectionName      = $CollectionName
        RuleName            = $RuleName
        Detail              = $Detail
        Recommendation      = $Recommendation
    }
}

Function Get-RuleSourceKey {
    param($Rule)
    $addr = @($Rule.SourceAddresses | Sort-Object) -join ","
    $grp = @($Rule.SourceIpGroups | Sort-Object) -join ","
    return "$addr|$grp"
}

Function Get-RuleDestinationKey {
    param($Rule)
    $addr = @($Rule.DestinationAddresses | Sort-Object) -join ","
    $grp = @($Rule.DestinationIpGroups | Sort-Object) -join ","
    $fqdn = @($Rule.DestinationFqdns | Sort-Object) -join ","
    $tfqdn = @($Rule.TargetFqdns | Sort-Object) -join ","
    $tags = @($Rule.FqdnTags | Sort-Object) -join ","
    return "$addr|$grp|$fqdn|$tfqdn|$tags"
}

Function Get-RuleSignature {
    param($Rule)
    $proto = @($Rule.Protocols | Sort-Object) -join ","
    $ports = @($Rule.DestinationPorts | Sort-Object) -join ","
    $src = Get-RuleSourceKey -Rule $Rule
    $dst = Get-RuleDestinationKey -Rule $Rule
    return "$($Rule.RuleType)|$proto|$src|$dst|$ports|$($Rule.CollectionAction)"
}

Function Test-RuleHasUnresolvedReference {
    param($Rule)
    if ($Rule.SourceIpGroups.Count -gt 0 -or $Rule.DestinationIpGroups.Count -gt 0 -or $Rule.FqdnTags.Count -gt 0) { return $true }
    foreach ($a in (@($Rule.SourceAddresses) + @($Rule.DestinationAddresses))) {
        if ([string]::IsNullOrWhiteSpace($a)) { continue }
        if (-not (Test-IsIPv4Cidr $a) -and -not (Test-IsAnyValue $a) -and -not (Test-IsInternetEquivalent $a)) { return $true }
    }
    return $false
}

Function Invoke-DuplicateRuleCheck {
    param([array]$Rules)
    $findings = @()
    $byFirewall = $Rules | Group-Object FirewallName
    foreach ($fwGroup in $byFirewall) {
        $bySignature = $fwGroup.Group | Group-Object { Get-RuleSignature -Rule $_ }
        foreach ($sigGroup in ($bySignature | Where-Object { $_.Count -gt 1 })) {
            $names = ($sigGroup.Group | ForEach-Object { $_.RuleName }) -join ", "
            foreach ($r in $sigGroup.Group) {
                $findings += New-Finding -FindingType "Duplicate Rule" -Severity "Medium" `
                    -SubscriptionName $r.SubscriptionName -FirewallName $r.FirewallName `
                    -CollectionGroupName $r.CollectionGroupName -CollectionName $r.CollectionName -RuleName $r.RuleName `
                    -Detail "Identical match criteria to: $names" `
                    -Recommendation "Consolidate duplicate rules into a single rule to simplify maintenance."
            }
        }
    }
    return $findings
}

Function Invoke-OverlapAndShadowCheck {
    param([array]$Rules)
    $findings = @()
    $byFirewallAndType = $Rules | Group-Object FirewallName, RuleType

    foreach ($grp in $byFirewallAndType) {
        $ordered = $grp.Group | Sort-Object SortKey
        $count = $ordered.Count
        if ($count -lt 2) { continue }

        for ($i = 0; $i -lt $count; $i++) {
            $r1 = $ordered[$i]
            if ((Test-RuleHasUnresolvedReference $r1)) { continue }

            $r1SrcRanges = @($r1.SourceAddresses | ForEach-Object { Get-CidrRange $_ } | Where-Object { $_.Resolved })
            $r1DstRanges = @($r1.DestinationAddresses | ForEach-Object { Get-CidrRange $_ } | Where-Object { $_.Resolved })
            $r1Ports = ConvertTo-PortRanges -Ports $r1.DestinationPorts

            for ($j = $i + 1; $j -lt $count; $j++) {
                $r2 = $ordered[$j]
                if ($r1.RuleName -eq $r2.RuleName -and $r1.CollectionName -eq $r2.CollectionName) { continue }
                if ((Test-RuleHasUnresolvedReference $r2)) { continue }

                $protoOverlap = (@($r1.Protocols) -contains "Any") -or (@($r2.Protocols) -contains "Any") -or `
                    (@(Compare-Object $r1.Protocols $r2.Protocols -IncludeEqual -ExcludeDifferent).Count -gt 0)
                if (-not $protoOverlap) { continue }

                $r2SrcRanges = @($r2.SourceAddresses | ForEach-Object { Get-CidrRange $_ } | Where-Object { $_.Resolved })
                $r2DstRanges = @($r2.DestinationAddresses | ForEach-Object { Get-CidrRange $_ } | Where-Object { $_.Resolved })
                $r2Ports = ConvertTo-PortRanges -Ports $r2.DestinationPorts

                if ($r1SrcRanges.Count -eq 0 -or $r2SrcRanges.Count -eq 0) { continue }
                if (($r1.RuleType -ne "Application") -and ($r1DstRanges.Count -eq 0 -or $r2DstRanges.Count -eq 0)) { continue }

                $srcOverlaps = $false
                foreach ($a in $r1SrcRanges) { foreach ($b in $r2SrcRanges) { if (Test-CidrOverlap $a $b) { $srcOverlaps = $true } } }
                if (-not $srcOverlaps) { continue }

                $dstOverlaps = $true
                if ($r1.RuleType -ne "Application") {
                    $dstOverlaps = $false
                    foreach ($a in $r1DstRanges) { foreach ($b in $r2DstRanges) { if (Test-CidrOverlap $a $b) { $dstOverlaps = $true } } }
                }
                if (-not $dstOverlaps) { continue }

                $portOverlaps = Test-PortRangesOverlap -RangesA $r1Ports -RangesB $r2Ports
                if (-not $portOverlaps) { continue }

                # Determine containment direction for the Shadow check (r1 evaluated first)
                $srcSuperset = $false
                foreach ($a in $r1SrcRanges) { foreach ($b in $r2SrcRanges) { if (Test-CidrSuperset $a $b) { $srcSuperset = $true } } }

                $dstSuperset = $true
                if ($r1.RuleType -ne "Application") {
                    $dstSuperset = $false
                    foreach ($a in $r1DstRanges) { foreach ($b in $r2DstRanges) { if (Test-CidrSuperset $a $b) { $dstSuperset = $true } } }
                }

                $portSuperset = Test-PortRangesSuperset -RangesA $r1Ports -RangesB $r2Ports

                if ($srcSuperset -and $dstSuperset -and $portSuperset) {
                    $findings += New-Finding -FindingType "Shadowed Rule" -Severity "High" `
                        -SubscriptionName $r2.SubscriptionName -FirewallName $r2.FirewallName `
                        -CollectionGroupName $r2.CollectionGroupName -CollectionName $r2.CollectionName -RuleName $r2.RuleName `
                        -Detail "Fully shadowed by earlier-evaluated rule '$($r1.RuleName)' (collection '$($r1.CollectionName)', priority $($r1.CollectionPriority)); this rule can never match traffic." `
                        -Recommendation "Remove the shadowed rule, or re-order/re-scope the earlier rule so both are reachable."
                }
                else {
                    $findings += New-Finding -FindingType "Overlapping Rule" -Severity "Medium" `
                        -SubscriptionName $r1.SubscriptionName -FirewallName $r1.FirewallName `
                        -CollectionGroupName $r1.CollectionGroupName -CollectionName $r1.CollectionName -RuleName $r1.RuleName `
                        -Detail "Partial source/destination/port overlap with rule '$($r2.RuleName)' (collection '$($r2.CollectionName)'). Actions: $($r1.CollectionAction) vs $($r2.CollectionAction)." `
                        -Recommendation "Review both rules for consolidation; overlap can cause ambiguous or unintended matches."
                }
            }
        }
    }

    return $findings
}

Function Invoke-RuleLevelFindings {
    param(
        [array]$Rules,
        [int]$LargePortRangeThreshold,
        [int]$BroadIpPrefixThreshold
    )

    $findings = @()
    $mgmtPorts = Get-ManagementPortMap
    $highRiskPorts = Get-HighRiskPortMap

    foreach ($rule in $Rules) {

        $srcHasAny = @($rule.SourceAddresses) | Where-Object { Test-IsAnyValue $_ } | Select-Object -First 1
        $dstHasAny = (@($rule.DestinationAddresses) | Where-Object { Test-IsAnyValue $_ } | Select-Object -First 1) -or
                     (@($rule.TargetFqdns) | Where-Object { Test-IsAnyValue $_ } | Select-Object -First 1)
        $portsHasAny = @($rule.DestinationPorts) | Where-Object { Test-IsAnyValue $_ } | Select-Object -First 1

        $srcHasInternet = @($rule.SourceAddresses) | Where-Object { Test-IsInternetEquivalent $_ } | Select-Object -First 1

        # -- Any-to-Any --
        if ($srcHasAny -and $dstHasAny) {
            $sev = if ($rule.CollectionAction -eq "Allow") { "Critical" } else { "Low" }
            $findings += New-Finding -FindingType "Any-to-Any Rule" -Severity $sev `
                -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                -Detail "Source and destination both resolve to Any (Action: $($rule.CollectionAction))." `
                -Recommendation "Scope source and/or destination to the minimum required range."
        }

        # -- Allow with Any Source / Destination / Port --
        if ($rule.CollectionAction -eq "Allow") {
            if ($srcHasAny) {
                $findings += New-Finding -FindingType "Allow Rule - Any Source" -Severity "High" `
                    -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                    -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                    -Detail "Allow rule permits traffic from any source." `
                    -Recommendation "Restrict source to specific IP ranges or IP Groups."
            }
            if ($dstHasAny) {
                $findings += New-Finding -FindingType "Allow Rule - Any Destination" -Severity "High" `
                    -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                    -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                    -Detail "Allow rule permits traffic to any destination." `
                    -Recommendation "Restrict destination to specific IP ranges, FQDNs, or IP Groups."
            }
            if ($portsHasAny -and $rule.RuleType -ne "Application") {
                $findings += New-Finding -FindingType "Allow Rule - Any Port" -Severity "High" `
                    -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                    -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                    -Detail "Allow rule permits traffic on any destination port." `
                    -Recommendation "Restrict to the specific port(s) required."
            }
        }

        # -- Internet-exposed management ports --
        if ($rule.CollectionAction -eq "Allow" -and $srcHasInternet -and $rule.RuleType -ne "Application") {
            foreach ($portToken in @($rule.DestinationPorts)) {
                $ranges = ConvertTo-PortRanges -Ports @($portToken)
                foreach ($mgmtPort in $mgmtPorts.Keys) {
                    $hit = $ranges | Where-Object { $_.Start -le $mgmtPort -and $_.End -ge $mgmtPort }
                    if ($hit -or (Test-IsAnyValue $portToken)) {
                        $findings += New-Finding -FindingType "Internet-Exposed Management Port" -Severity "Critical" `
                            -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                            -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                            -Detail "$($mgmtPorts[$mgmtPort]) (port $mgmtPort) reachable from an Internet-equivalent source." `
                            -Recommendation "Remove Internet exposure; require VPN/Bastion/Private access for management ports."
                    }
                }
            }
        }

        # -- Open high-risk ports (broad source) --
        if ($rule.CollectionAction -eq "Allow" -and $rule.RuleType -ne "Application") {
            $broadSource = $srcHasAny -or $srcHasInternet -or (@($rule.SourceAddresses) | Where-Object {
                $r = Get-CidrRange $_
                $r.Resolved -and $r.Prefix -lt $BroadIpPrefixThreshold
            } | Select-Object -First 1)

            if ($broadSource) {
                foreach ($portToken in @($rule.DestinationPorts)) {
                    $ranges = ConvertTo-PortRanges -Ports @($portToken)
                    foreach ($riskPort in $highRiskPorts.Keys) {
                        if ($mgmtPorts.ContainsKey($riskPort)) { continue } # already covered above
                        $hit = $ranges | Where-Object { $_.Start -le $riskPort -and $_.End -ge $riskPort }
                        if ($hit -or (Test-IsAnyValue $portToken)) {
                            $findings += New-Finding -FindingType "Open High-Risk Port" -Severity "High" `
                                -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                                -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                                -Detail "$($highRiskPorts[$riskPort]) (port $riskPort) allowed from a broad source." `
                                -Recommendation "Restrict source to a narrow, known range for this service."
                        }
                    }
                }
            }
        }

        # -- Large port ranges --
        foreach ($portToken in @($rule.DestinationPorts)) {
            if ($portToken -match '^(?<s>\d+)-(?<e>\d+)$') {
                $width = [int]$Matches['e'] - [int]$Matches['s'] + 1
                if ($width -gt $LargePortRangeThreshold) {
                    $findings += New-Finding -FindingType "Large Port Range" -Severity "Medium" `
                        -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                        -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                        -Detail "Port range $portToken spans $width ports (threshold: $LargePortRangeThreshold)." `
                        -Recommendation "Narrow the port range to only what is required."
                }
            }
        }

        # -- Broad IP ranges --
        foreach ($addr in (@($rule.SourceAddresses) + @($rule.DestinationAddresses))) {
            if ([string]::IsNullOrWhiteSpace($addr) -or (Test-IsAnyValue $addr) -or (Test-IsInternetEquivalent $addr)) { continue }
            $range = Get-CidrRange $addr
            if ($range.Resolved -and $range.Prefix -lt $BroadIpPrefixThreshold) {
                $findings += New-Finding -FindingType "Broad IP Range" -Severity "Medium" `
                    -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                    -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                    -Detail "Address $addr uses a /$($range.Prefix) prefix (broader than the /$BroadIpPrefixThreshold threshold)." `
                    -Recommendation "Narrow the CIDR to the smallest range that covers the required hosts."
            }
        }

        # -- Rules without Description --
        if ([string]::IsNullOrWhiteSpace($rule.Description)) {
            $findings += New-Finding -FindingType "Missing Description" -Severity "Low" `
                -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                -Detail "Rule has no Description set." `
                -Recommendation "Add a description covering business justification and requestor."
        }

        # -- Rules without Owner --
        if ([string]::IsNullOrWhiteSpace($rule.Owner)) {
            $findings += New-Finding -FindingType "Missing Owner" -Severity "Low" `
                -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                -Detail "Owner could not be confirmed (no matching 'Owner' tag on the firewall/policy and no TEMP-<Owner>-<yyyyMMdd> naming match)." `
                -Recommendation "Tag the firewall/policy with an Owner, or adopt the TEMP-<Owner>-<yyyyMMdd> naming convention for temporary rules."
        }

        # -- Expired temporary rules --
        if ($rule.IsTemporary -and $rule.IsExpired) {
            $findings += New-Finding -FindingType "Expired Temporary Rule" -Severity "Critical" `
                -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                -Detail "Temporary rule expired on $($rule.ExpiryDate.ToString('yyyy-MM-dd')) and is still present/enabled." `
                -Recommendation "Remove the rule immediately, or renew it with an updated expiry date if still required."
        }

        # -- Disabled rules (Policy only) --
        if ($rule.CollectionState -eq "Disabled") {
            $findings += New-Finding -FindingType "Disabled Rule Collection" -Severity "Info" `
                -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                -Detail "Rule collection '$($rule.CollectionName)' is disabled." `
                -Recommendation "Remove if permanently unneeded; re-enable if still required."
        }

        # -- Unresolved reference note (informational) --
        if (Test-RuleHasUnresolvedReference $rule) {
            $findings += New-Finding -FindingType "Unresolved Reference" -Severity "Info" `
                -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                -Detail "Rule references an IP Group, Service Tag, FQDN Tag, or IPv6 address that was not resolved for overlap/shadow/broad-range analysis." `
                -Recommendation "Manually review this rule's effective address space."
        }
    }

    return $findings
}

Function Invoke-CollectionLevelFindings {
    param(
        [array]$Rules,
        [array]$EmptyCollectionRefs,
        [int]$PriorityGapWarningThreshold
    )

    $findings = @()

    # -- Empty rule collections (collections/groups with zero rules, gathered during inventory) --
    foreach ($ref in $EmptyCollectionRefs) {
        $findings += New-Finding -FindingType "Empty Rule Collection" -Severity "Low" `
            -SubscriptionName $ref.SubscriptionName -FirewallName $ref.FirewallName `
            -CollectionGroupName $ref.CollectionGroupName -CollectionName $ref.CollectionName -RuleName $null `
            # -Detail "Rule collection${(if ($ref.CollectionGroupName) { ' group' } else { '' })} '$($ref.CollectionName)' contains no rules." `
            -Detail "Rule collection$(if ($ref.CollectionGroupName) { ' group' } else { '' }) '$($ref.CollectionName)' contains no rules." `
            -Recommendation "Remove the empty collection or populate it with rules."
    }

    # -- Duplicate priorities / priority gap conflicts --
    $byFirewall = $Rules | Group-Object FirewallName
    foreach ($fwGroup in $byFirewall) {
        $collections = $fwGroup.Group | Select-Object FirewallName, SubscriptionName, CollectionGroupName, CollectionName, CollectionPriority -Unique

        $byPriority = $collections | Group-Object CollectionPriority
        foreach ($pGroup in ($byPriority | Where-Object { $_.Count -gt 1 })) {
            $names = ($pGroup.Group | ForEach-Object { $_.CollectionName }) -join ", "
            foreach ($c in $pGroup.Group) {
                $findings += New-Finding -FindingType "Duplicate Priority" -Severity "Medium" `
                    -SubscriptionName $c.SubscriptionName -FirewallName $c.FirewallName `
                    -CollectionGroupName $c.CollectionGroupName -CollectionName $c.CollectionName -RuleName $null `
                    -Detail "Priority $($pGroup.Name) is shared with: $names" `
                    -Recommendation "Assign each rule collection a unique priority to make evaluation order unambiguous."
            }
        }

        $sortedPriorities = $collections | Sort-Object CollectionPriority
        $prev = $null
        foreach ($c in $sortedPriorities) {
            if ($null -ne $prev -and ($c.CollectionPriority - $prev.CollectionPriority) -lt $PriorityGapWarningThreshold -and ($c.CollectionPriority - $prev.CollectionPriority) -ne 0) {
                $findings += New-Finding -FindingType "Rule Priority Conflict" -Severity "Low" `
                    -SubscriptionName $c.SubscriptionName -FirewallName $c.FirewallName `
                    -CollectionGroupName $c.CollectionGroupName -CollectionName $c.CollectionName -RuleName $null `
                    -Detail "Priority $($c.CollectionPriority) is only $($c.CollectionPriority - $prev.CollectionPriority) higher than '$($prev.CollectionName)' (priority $($prev.CollectionPriority)); threshold is $PriorityGapWarningThreshold." `
                    -Recommendation "Leave a wider priority gap between collections to allow future insertions without renumbering."
            }
            $prev = $c
        }
    }

    return $findings
}

Function Invoke-FirewallLevelFindings {
    param(
        [Parameter(Mandatory)]$Firewall,
        [Parameter(Mandatory)][string]$SubscriptionName,
        [string]$ThreatIntelMode
    )

    $findings = @()

    if ([string]::IsNullOrWhiteSpace($ThreatIntelMode) -or $ThreatIntelMode -eq "Off") {
        $findings += New-Finding -FindingType "Threat Intelligence Status" -Severity "High" `
            -SubscriptionName $SubscriptionName -FirewallName $Firewall.Name `
            -CollectionGroupName $null -CollectionName $null -RuleName $null `
            -Detail "Threat Intelligence mode is '$([string]::IsNullOrWhiteSpace($ThreatIntelMode) ? 'Off/Not Set' : $ThreatIntelMode)'." `
            -Recommendation "Enable Threat Intelligence in Alert or Deny mode."
    }

    try {
        $diagSettings = Get-AzDiagnosticSetting -ResourceId $Firewall.Id -ErrorAction Stop
        $hasEnabledLog = $false
        foreach ($setting in @($diagSettings)) {
            foreach ($log in @($setting.Log)) {
                if ($log.Enabled) { $hasEnabledLog = $true }
            }
            foreach ($log in @($setting.Logs)) {
                if ($log.Enabled) { $hasEnabledLog = $true }
            }
        }
        if (-not $diagSettings -or -not $hasEnabledLog) {
            $findings += New-Finding -FindingType "Diagnostic Logging Disabled" -Severity "High" `
                -SubscriptionName $SubscriptionName -FirewallName $Firewall.Name `
                -CollectionGroupName $null -CollectionName $null -RuleName $null `
                -Detail "No enabled diagnostic log category found for this firewall." `
                -Recommendation "Enable diagnostic logging (Network/Application/DNAT rule logs) to a Log Analytics workspace or Storage Account."
        }
    }
    catch {
        $findings += New-Finding -FindingType "Diagnostic Logging Disabled" -Severity "Info" `
            -SubscriptionName $SubscriptionName -FirewallName $Firewall.Name `
            -CollectionGroupName $null -CollectionName $null -RuleName $null `
            -Detail "Could not be confirmed - diagnostic settings query failed: $_" `
            -Recommendation "Verify diagnostic logging manually; Az.Monitor may be unavailable or permissions insufficient."
    }

    return $findings
}

Function Invoke-UnusedRuleCheck {
    param(
        [array]$Rules,
        [string]$LogAnalyticsWorkspaceId,
        [int]$LookbackDays
    )

    $findings = @()

    if ([string]::IsNullOrWhiteSpace($LogAnalyticsWorkspaceId)) {
        foreach ($rule in $Rules) {
            $findings += New-Finding -FindingType "Unused Rule" -Severity "Info" `
                -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                -Detail "Not Evaluated - no -LogAnalyticsWorkspaceId supplied." `
                -Recommendation "Re-run with -LogAnalyticsWorkspaceId to enable best-effort hit-count analysis."
        }
        return $findings
    }

    try {
        $workspaceId = ($LogAnalyticsWorkspaceId -split '/workspaces/')[-1]
        $query = @"
let lookback = ${LookbackDays}d;
AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where Category in ('AzureFirewallNetworkRule','AzureFirewallApplicationRule')
| where isnotempty(msg_s)
| project msg_s
"@
        $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $query -ErrorAction Stop
        $hitText = ($result.Results | ForEach-Object { $_.msg_s }) -join "`n"

        foreach ($rule in $Rules) {
            if ([string]::IsNullOrWhiteSpace($rule.RuleName)) { continue }
            if ($hitText -notmatch [regex]::Escape($rule.RuleName)) {
                $findings += New-Finding -FindingType "Unused Rule" -Severity "Low" `
                    -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                    -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                    -Detail "No matching hit found in AzureFirewall*Rule logs over the last $LookbackDays day(s)." `
                    -Recommendation "Confirm the rule is still required before removal; log retention/category coverage may affect accuracy."
            }
        }
    }
    catch {
        Write-Warning "Unused Rule log query failed, reporting as Not Evaluated: $_"
        foreach ($rule in $Rules) {
            $findings += New-Finding -FindingType "Unused Rule" -Severity "Info" `
                -SubscriptionName $rule.SubscriptionName -FirewallName $rule.FirewallName `
                -CollectionGroupName $rule.CollectionGroupName -CollectionName $rule.CollectionName -RuleName $rule.RuleName `
                -Detail "Not Evaluated - Log Analytics query failed: $_" `
                -Recommendation "Verify workspace ID, Az.OperationalInsights availability, and permissions."
        }
    }

    return $findings
}


#------------------------------------------------------------------------ [ HTML Report ]

Function Generate-HtmlReport {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$FirewallInventory,
        [string]$CsvPath,
        [string]$HtmlPath
    )

    $timestamp = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    $severityColor = @{
        Critical = "#d13438"
        High     = "#e81123"
        Medium   = "#ffb900"
        Low      = "#8a8886"
        Info     = "#0078D4"
    }

    $bySeverity = $Findings | Group-Object Severity
    $statCardsHtml = ""
    foreach ($sevName in @("Critical", "High", "Medium", "Low", "Info")) {
        $grp = $bySeverity | Where-Object { $_.Name -eq $sevName }
        $count = if ($grp) { $grp.Count } else { 0 }
        $statCardsHtml += @"
                    <div class="stat-card" style="background: $($severityColor[$sevName])">
                        <div class="stat-number">$count</div>
                        <div class="stat-label">$sevName</div>
                    </div>
"@
    }

    $firewallHtml = ""
    foreach ($fw in $FirewallInventory) {
        $firewallHtml += @"
                    <div class="subscription-item">
                        <span class="subscription-name">$($fw.FirewallName) <span style="color:#888;font-size:12px;">($($fw.RuleModel))</span></span>
                        <span class="assignment-count">$($fw.RuleCount) rules</span>
                    </div>
"@
    }

    $findingsHtml = ""
    foreach ($f in ($Findings | Sort-Object @{Expression = {
                switch ($_.Severity) { "Critical" {0} "High" {1} "Medium" {2} "Low" {3} default {4} }
            }}, FindingType)) {
        $color = $severityColor[$f.Severity]
        $ruleNameDisplay = if ($f.RuleName) { $f.RuleName } else { "(collection-level)" }
        $findingsHtml += @"
                    <div class="finding-item" style="border-left-color: $color;">
                        <div class="finding-header">
                            <span class="finding-badge" style="background: $color;">$($f.Severity)</span>
                            <span class="finding-type">$($f.FindingType)</span>
                        </div>
                        <div class="finding-location">$($f.FirewallName) &rsaquo; $($f.CollectionName) &rsaquo; $ruleNameDisplay</div>
                        <div class="finding-detail">$($f.Detail)</div>
                        <div class="finding-recommendation">Recommendation: $($f.Recommendation)</div>
                    </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Firewall Rule Analyzer - Findings Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #0078D4 0%, #50E6FF 100%); padding: 20px; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 10px 40px rgba(0, 120, 212, 0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #0078D4 0%, #50E6FF 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 32px; margin-bottom: 10px; font-weight: 300; letter-spacing: 1px; }
        .header .timestamp { font-size: 14px; opacity: 0.9; }
        .content { padding: 40px; }
        .section { margin-bottom: 40px; }
        .section-title { font-size: 20px; color: #0078D4; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #f0f0f0; font-weight: 600; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .info-card { background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #0078D4; }
        .info-label { font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
        .info-value { font-size: 18px; color: #333; font-weight: 600; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { color: white; padding: 25px; border-radius: 8px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.15); }
        .stat-number { font-size: 36px; font-weight: 700; margin-bottom: 8px; }
        .stat-label { font-size: 12px; opacity: 0.95; text-transform: uppercase; letter-spacing: 1px; }
        .subscription-list { background: #f8f9fa; padding: 20px; border-radius: 8px; max-height: 300px; overflow-y: auto; }
        .subscription-item { display: flex; align-items: center; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #e0e0e0; }
        .subscription-item:last-child { border-bottom: none; }
        .subscription-name { font-weight: 500; color: #333; }
        .assignment-count { color: #0078D4; font-weight: 600; }
        .findings-list { max-height: 700px; overflow-y: auto; }
        .finding-item { background: #f8f9fa; padding: 16px 20px; margin-bottom: 12px; border-radius: 6px; border-left: 4px solid #888; }
        .finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
        .finding-badge { color: white; font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 3px 10px; border-radius: 12px; letter-spacing: 0.5px; }
        .finding-type { font-weight: 600; color: #333; }
        .finding-location { font-size: 13px; color: #666; margin-bottom: 6px; }
        .finding-detail { font-size: 14px; color: #333; margin-bottom: 6px; }
        .finding-recommendation { font-size: 13px; color: #0078D4; font-style: italic; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #888; font-size: 12px; border-top: 1px solid #e0e0e0; }
        @media (max-width: 768px) { .container { margin: 10px; } .content { padding: 20px; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Azure Firewall Rule Analyzer</h1>
            <div class="timestamp">Findings Report - Generated on $timestamp</div>
        </div>

        <div class="content">
            <div class="section">
                <h2 class="section-title">Session Information</h2>
                <div class="info-grid">
                    <div class="info-card"><div class="info-label">Tenant ID</div><div class="info-value">$($SessionInfo.Tenant)</div></div>
                    <div class="info-card"><div class="info-label">Account</div><div class="info-value">$($SessionInfo.Account)</div></div>
                    <div class="info-card"><div class="info-label">Scope</div><div class="info-value">$($ScanParameters.Scope)</div></div>
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Findings Summary</h2>
                <div class="stats-grid">
$statCardsHtml
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Firewalls Scanned</h2>
                <div class="subscription-list">
$firewallHtml
                </div>
            </div>

            <div class="section">
                <h2 class="section-title">Findings</h2>
                <div class="findings-list">
$findingsHtml
                </div>
            </div>
        </div>

        <div class="footer">
            Generated by Azure Firewall Rule Analyzer v1.0 | Microsoft Azure | PowerShell Script
        </div>
    </div>
</body>
</html>
"@

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureFirewallRules
{
    [CmdletBinding()]
    param (
        [string[]]$SubscriptionIds,
        [string[]]$ResourceGroupNames,
        [string[]]$FirewallNames,
        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureFirewallRules-Report.csv",
        [string]$LogAnalyticsWorkspaceId,
        [ValidateRange(1, 365)]
        [int]$UnusedRuleLookbackDays = 30,
        [ValidateRange(1, 65535)]
        [int]$LargePortRangeThreshold = 100,
        [ValidateRange(0, 32)]
        [int]$BroadIpPrefixThreshold = 24,
        [ValidateRange(1, 1000)]
        [int]$PriorityGapWarningThreshold = 10,
        [switch]$AllSubscriptions,
        [switch]$ExportToCsv
    )

    $startTime = Get-Date
    Write-Banner

    # -- Module checks --
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
    # Az.Monitor is optional (diagnostic-setting check only); degrade gracefully if absent.
    $azMonitorAvailable = [bool](Get-Module -ListAvailable -Name Az.Monitor)
    if (-not $azMonitorAvailable) {
        Write-Warning "Az.Monitor module not found - Diagnostic Logging checks will be reported as 'Could not be confirmed'."
    }
    if ($LogAnalyticsWorkspaceId -and -not (Get-Module -ListAvailable -Name Az.OperationalInsights)) {
        Write-Warning "Az.OperationalInsights module not found - Unused Rule checks will be reported as 'Not Evaluated'."
        $LogAnalyticsWorkspaceId = $null
    }

    # -- Session --
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext) {
        Write-Host "  [!] No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    # -- Subscriptions --
    if ($AllSubscriptions -or -not $SubscriptionIds) {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText = "All Subscriptions"
    }
    else {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count))"
    }

    $sessionInfo = @{
        Tenant  = $currentContext.Tenant.Id
        Account = $currentContext.Account.Id
    }
    $scanParameters = @{
        Scope = "$scopeText ($($subscriptions.Count) found)"
    }

    Write-Section -Title "Session Information" -Data @{
        "Tenant"  = $currentContext.Tenant.Id
        "Account" = $currentContext.Account.Id
    }
    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"                 = "$scopeText ($($subscriptions.Count) found)"
        "Resource Group Filter" = ($ResourceGroupNames -join ", ")
        "Firewall Name Filter"  = ($FirewallNames -join ", ")
        "Unused Rule Detection" = if ($LogAnalyticsWorkspaceId) { "Enabled (last $UnusedRuleLookbackDays days)" } else { "Disabled (no workspace supplied)" }
        "Export to CSV"         = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
    }

    $allRules = @()
    $emptyCollectionRefs = @()
    $firewallInventory = @()
    $firewallLevelFindings = @()

    $subIndex = 0
    foreach ($sub in $subscriptions) {
        $subIndex++
        Write-ProgressBar -Current $subIndex -Total $subscriptions.Count -CurrentItem $sub.Name

        try {
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $firewalls = @(Get-AzFirewall -ErrorAction Stop)
            if ($ResourceGroupNames) {
                $firewalls = $firewalls | Where-Object { $ResourceGroupNames -contains $_.ResourceGroupName }
            }
            if ($FirewallNames) {
                $firewalls = $firewalls | Where-Object { $FirewallNames -contains $_.Name }
            }

            foreach ($fw in $firewalls) {
                try {
                    $inventory = Get-FirewallRuleInventory -Firewall $fw -SubscriptionId $sub.Id -SubscriptionName $sub.Name
                    $allRules += $inventory.Rules

                    $firewallInventory += [pscustomobject]@{
                        FirewallName = $fw.Name
                        RuleModel    = $inventory.RuleModel
                        RuleCount    = $inventory.Rules.Count
                    }

                    $firewallLevelFindings += Invoke-FirewallLevelFindings -Firewall $fw -SubscriptionName $sub.Name -ThreatIntelMode $inventory.ThreatIntelMode

                    # Empty classic collections (policy-side empties are handled inside inventory retrieval)
                    foreach ($rc in @($fw.NetworkRuleCollections) + @($fw.ApplicationRuleCollections) + @($fw.NatRuleCollections)) {
                        if ($rc -and (-not $rc.Rules -or $rc.Rules.Count -eq 0)) {
                            $emptyCollectionRefs += [pscustomobject]@{
                                SubscriptionName    = $sub.Name
                                FirewallName        = $fw.Name
                                CollectionGroupName = $null
                                CollectionName      = $rc.Name
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to inventory firewall '$($fw.Name)': $_"
                }
            }
        }
        catch {
            Write-Warning "Failed to scan subscription '$($sub.Name)': $_"
        }
    }
    Write-Host ""

    # -- Run checks --
    Write-Host ""
    Write-Host "  Running rule analysis checks..." -ForegroundColor Cyan

    $allFindings = @()
    $allFindings += $firewallLevelFindings
    $allFindings += Invoke-DuplicateRuleCheck -Rules $allRules
    $allFindings += Invoke-OverlapAndShadowCheck -Rules $allRules
    $allFindings += Invoke-RuleLevelFindings -Rules $allRules -LargePortRangeThreshold $LargePortRangeThreshold -BroadIpPrefixThreshold $BroadIpPrefixThreshold
    $allFindings += Invoke-CollectionLevelFindings -Rules $allRules -EmptyCollectionRefs $emptyCollectionRefs -PriorityGapWarningThreshold $PriorityGapWarningThreshold
    $allFindings += Invoke-UnusedRuleCheck -Rules $allRules -LogAnalyticsWorkspaceId $LogAnalyticsWorkspaceId -LookbackDays $UnusedRuleLookbackDays

    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration

    Write-FindingsSummary -Findings $allFindings
    Write-FindingsByType -Findings $allFindings

    Write-Host ""
    Write-Host "  Scan Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray
    Write-Host "  Firewalls Scanned".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($firewallInventory.Count)" -ForegroundColor White
    Write-Host "  Rules Inventoried".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($allRules.Count)" -ForegroundColor White
    Write-Host "  Total Findings".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($allFindings.Count)" -ForegroundColor White
    Write-Host "  Execution Time".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $durationFormatted" -ForegroundColor White

    # -- Output --
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($ExportToCsv) {
        try {
            $allFindings | Export-Csv -Path $CsvPath -NoTypeInformation
            $csvExported = $true
        }
        catch {
            Write-Host "  [X] CSV export failed: $_" -ForegroundColor Red
        }
    }

    try {
        $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
        $htmlContent = Generate-HtmlReport -SessionInfo $sessionInfo -ScanParameters $scanParameters `
            -Findings $allFindings -FirewallInventory $firewallInventory -CsvPath $CsvPath -HtmlPath $htmlPath
        $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
        $htmlExported = $true
    }
    catch {
        Write-Host "  [X] HTML report generation failed: $_" -ForegroundColor Red
    }

    try {
        $allFindings | Out-GridView -Title "Azure Firewall Rule Findings"
        $gridViewOpened = $true
    }
    catch {
        Write-Host "  [!] Could not open Grid View" -ForegroundColor Yellow
    }

    Write-OutputFiles -CsvPath $(if ($csvExported) { $CsvPath } else { $null }) `
        -HtmlPath $(if ($htmlExported) { $htmlPath } else { $null }) `
        -GridViewOpened $gridViewOpened
}
