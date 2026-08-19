<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 19 August 2026
Modified-On     : 19 August 2026

.SYNOPSIS
    Assesses Azure Network Security Group (NSG) rules across one or more subscriptions,
    detecting unrestricted access, overly permissive rules, broad CIDRs, excessive port
    ranges, shadowed rules, and unassociated NSGs, with optional association enrichment,
    CSV export, and an interactive HTML dashboard.

.DESCRIPTION
    Get-AzureNSGSecurityAssessment evaluates the security posture of every NSG found
    across one or multiple Azure subscriptions.

    Default assessment (structure and rule analysis):
        - Unrestricted inbound SSH (port 22) from Any/Internet          → Critical
        - Unrestricted inbound RDP (port 3389) from Any/Internet        → Critical
        - Any-to-Any Allow rules (source *, dest *, any port)           → Critical
        - Broad source CIDR (/8 or wider) on Allow rules                → High
        - Excessive port range (>100 ports wide) on Allow rules         → High
        - Unrestricted outbound to Internet (Any destination)           → High
        - Shadowed / conflicting rules (lower-priority Allow overridden
          by a higher-priority Deny for the same traffic)               → Medium
        - Unused / unassociated NSGs (not attached to any subnet
          or NIC)                                                        → Informational

    Severity taxonomy:  Critical | High | Medium | Low | Informational

    Optional enrichment (-IncludeAssociations switch):
        - Calls Get-AzNetworkSecurityGroup with full detail to resolve
          which subnets and NICs each NSG is attached to.
        - If the call fails or permission is insufficient, the
          association columns are marked "Not Assessed / Warning"
          and the scan continues without interruption.

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and colour-coded per-subscription output
        - Severity-weighted risk summary at the console on completion
        - Optional CSV export of all rule-level findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable
          filterable findings table, NSG inventory tab, detail drawer,
          donut risk chart, bar distributions)
        - Interactive Grid View of findings where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER IncludeAssociations
    Switch. When specified, resolves subnet and NIC associations for each
    NSG, enabling accurate detection of unassociated (orphaned) NSGs and
    enriching the inventory view with attachment context. Adds additional
    API calls per NSG. If resolution fails, columns are marked
    "Not Assessed / Warning" and the scan continues.

.PARAMETER ExportToCsv
    Switch. If specified, exports all NSG rule findings to the path given
    in -CsvPath. The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    The HTML dashboard is always written to the same path with a .html extension.
    Default: C:\Temp\AzureNSGSecurityAssessment.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays findings in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureNSGSecurityAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureNSGSecurityAssessment -AllSubscriptions -IncludeAssociations

.EXAMPLE
    Get-AzureNSGSecurityAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureNSGSecurityAssessment -AllSubscriptions -IncludeAssociations -ExportToCsv -CsvPath "C:\Reports\NSGAssessment.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (19-Aug-2026) - Initial release. Rule-level findings for Critical,
                            High, Medium, and Informational severity. NSG
                            inventory roll-up. Optional association enrichment
                            via -IncludeAssociations. CSV export and interactive
                            HTML dashboard with dark/light theme.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Network)
           — installed automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level.
        4. Microsoft.Network/networkSecurityGroups/read permission required.
        5. -IncludeAssociations requires the same Reader-level permission;
           no additional role is needed beyond what the default scan requires.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Only user-defined security rules are evaluated. Azure default rules
          (AllowVnetInBound, DenyAllInBound, etc.) are excluded from findings
          as they are platform-managed and cannot be removed.
        - Shadowed-rule detection operates within each NSG in isolation.
          Cross-NSG effective rule analysis requires -IncludeEffectiveRules
          (deferred to a future version).
        - Broad CIDR detection uses the source address prefix mask. It does not
          resolve ASGs (Application Security Groups) or Service Tags to CIDRs.
        - Interactive Grid View requires a GUI-capable session. Skipped
          gracefully in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Port range width is computed from the first range token when a rule
          specifies multiple comma-separated port ranges.

.LINK
    https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview
    https://learn.microsoft.com/en-us/powershell/module/az.network/get-aznetworksecuritygroup
    https://learn.microsoft.com/en-us/azure/virtual-network/diagnose-network-traffic-filter-problem
    https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices

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
    Write-CenteredText "Azure NSG Security Assessment v1.0" -Color White
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
        Write-Host ": "             -NoNewline -ForegroundColor DarkGray
        Write-Host $value                       -ForegroundColor $valColor
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
    Write-Host "  Progress: "  -NoNewline -ForegroundColor Gray
    Write-Host $bar            -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White

    if ($CurrentItem) {
        $maxLen = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLen) { $CurrentItem.Substring(0, $maxLen - 3) + "..." } else { $CurrentItem }
        Write-Host " | "        -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: "  -NoNewline -ForegroundColor Gray
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
        Write-Host ": "             -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key]                  -ForegroundColor White
    }
}

Function Write-SeverityBreakdown {
    param([array]$Findings)

    if ($Findings.Count -eq 0) { return }

    $critCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $medCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount = @($Findings | Where-Object { $_.Severity -eq "Informational" }).Count

    Write-Host ""
    Write-Host "  Severity Breakdown" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Total Findings        : $($Findings.Count)"  -ForegroundColor White
    Write-Host "  Critical              : $critCount"           -ForegroundColor Red
    Write-Host "  High                  : $highCount"           -ForegroundColor DarkYellow
    Write-Host "  Medium                : $medCount"            -ForegroundColor Yellow
    Write-Host "  Low                   : $lowCount"            -ForegroundColor Cyan
    Write-Host "  Informational         : $infoCount"           -ForegroundColor DarkGray
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


#------------------------------------------------------------------ [ NSG Detection Helpers ]

# Returns $true if the address prefix represents an unrestricted source/destination.
Function Test-IsUnrestricted {
    param([string]$Prefix)
    return ($Prefix -in @("*", "Any", "Internet", "0.0.0.0/0"))
}

# Returns $true if the CIDR is /8 or broader (i.e., very large address space).
Function Test-IsBroadCidr {
    param([string]$Prefix)

    if ([string]::IsNullOrWhiteSpace($Prefix)) { return $false }
    if ($Prefix -in @("*", "Any", "Internet")) { return $false }   # handled separately

    try {
        if ($Prefix -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$") {
            $mask = [int]$Matches[2]
            return ($mask -le 8 -and $mask -ge 0)
        }
    }
    catch { }

    return $false
}

# Returns the number of ports covered by a port-spec string.
# Handles "*", single ports, and ranges like "1024-65535".
# For comma-separated lists, evaluates only the widest single token.
Function Get-PortRangeWidth {
    param([string]$PortSpec)

    if ([string]::IsNullOrWhiteSpace($PortSpec)) { return 0 }
    if ($PortSpec -eq "*") { return 65535 }

    $maxWidth = 0
    $tokens = $PortSpec -split ","

    foreach ($token in $tokens) {
        $token = $token.Trim()
        if ($token -eq "*") {
            return 65535
        }
        elseif ($token -match "^(\d+)-(\d+)$") {
            $width = [int]$Matches[2] - [int]$Matches[1] + 1
            if ($width -gt $maxWidth) { $maxWidth = $width }
        }
        elseif ($token -match "^\d+$") {
            if (1 -gt $maxWidth) { $maxWidth = 1 }
        }
    }

    return $maxWidth
}

# Returns $true if the port spec covers the target port.
Function Test-PortInRange {
    param(
        [string]$PortSpec,
        [int]$TargetPort
    )

    if ([string]::IsNullOrWhiteSpace($PortSpec)) { return $false }
    if ($PortSpec -eq "*") { return $true }

    foreach ($token in ($PortSpec -split ",")) {
        $token = $token.Trim()
        if ($token -eq "*") { return $true }

        if ($token -match "^(\d+)-(\d+)$") {
            if ($TargetPort -ge [int]$Matches[1] -and $TargetPort -le [int]$Matches[2]) { return $true }
        }
        elseif ($token -match "^\d+$") {
            if ([int]$token -eq $TargetPort) { return $true }
        }
    }

    return $false
}

# Detects rules that are shadowed by a higher-priority Deny rule covering
# the same direction, protocol, and traffic pattern within the same NSG.
# Returns an array of [AllowRuleName, DenyRuleName] pairs.
Function Get-ShadowedRules {
    param([array]$Rules)

    $shadowed = @()

    # Separate user-defined rules (exclude Azure defaults) by direction
    $userRules = $Rules | Where-Object { $_.RuleType -ne "Default" -or $_.Name -notlike "Default*" }

    $inboundRules = @($userRules | Where-Object { $_.Direction -eq "Inbound" } | Sort-Object Priority)
    $outboundRules = @($userRules | Where-Object { $_.Direction -eq "Outbound" } | Sort-Object Priority)

    foreach ($dirRules in @($inboundRules, $outboundRules)) {
        for ($i = 0; $i -lt $dirRules.Count; $i++) {
            $allow = $dirRules[$i]
            if ($allow.Access -ne "Allow") { continue }

            for ($j = 0; $j -lt $dirRules.Count; $j++) {
                $deny = $dirRules[$j]
                if ($deny.Access -ne "Deny") { continue }
                if ($deny.Priority -ge $allow.Priority) { continue }   # deny must be higher priority (lower number)

                # Check protocol overlap
                $protoMatch = ($deny.Protocol -eq "*" -or $allow.Protocol -eq "*" -or
                    $deny.Protocol -eq $allow.Protocol)

                if (-not $protoMatch) { continue }

                # Check address overlap (simplified: both must be wildcard or identical)
                $srcMatch = (
                    (Test-IsUnrestricted $deny.SourceAddressPrefix) -or
                    ($deny.SourceAddressPrefix -eq $allow.SourceAddressPrefix)
                )
                $dstMatch = (
                    (Test-IsUnrestricted $deny.DestinationAddressPrefix) -or
                    ($deny.DestinationAddressPrefix -eq $allow.DestinationAddressPrefix)
                )

                if (-not ($srcMatch -and $dstMatch)) { continue }

                # Check port overlap (deny port must cover allow port)
                $allowPorts = $allow.DestinationPortRange
                $denyPorts = $deny.DestinationPortRange

                $portsOverlap = $false
                if ($denyPorts -eq "*" -or $allowPorts -eq "*") {
                    $portsOverlap = $true
                }
                else {
                    foreach ($token in ($allowPorts -split ",")) {
                        $token = $token.Trim()
                        if ($token -match "^(\d+)-(\d+)$") {
                            $low = [int]$Matches[1]
                            $high = [int]$Matches[2]
                            # Check if the midpoint of the allow range falls in the deny range
                            $mid = [math]::Floor(($low + $high) / 2)
                            if (Test-PortInRange -PortSpec $denyPorts -TargetPort $mid) { $portsOverlap = $true; break }
                        }
                        elseif ($token -match "^\d+$") {
                            if (Test-PortInRange -PortSpec $denyPorts -TargetPort ([int]$token)) { $portsOverlap = $true; break }
                        }
                    }
                }

                if ($portsOverlap) {
                    $shadowed += [pscustomobject]@{
                        AllowRuleName = $allow.Name
                        DenyRuleName  = $deny.Name
                        AllowPriority = $allow.Priority
                        DenyPriority  = $deny.Priority
                    }
                    break   # one shadowing deny per allow rule is sufficient to flag it
                }
            }
        }
    }

    return $shadowed
}

# Core finding evaluator for a single NSG security rule.
# Returns zero or more [pscustomobject] findings.
Function Get-RuleFindings {
    param(
        [object]$Rule,
        [string]$NsgName,
        [string]$NsgId,
        [string]$ResourceGroup,
        [string]$Location,
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [array]$ShadowedPairs          # output of Get-ShadowedRules for this NSG
    )

    $findings = @()

    # Skip Azure platform default rules entirely
    if ($Rule.Name -like "AllowVnet*" -or
        $Rule.Name -like "AllowAzure*" -or
        $Rule.Name -like "DenyAllIn*" -or
        $Rule.Name -like "AllowInternet*" -or
        $Rule.Name -like "DenyAll*") {
        return $findings
    }

    $access = $Rule.Access
    $direction = $Rule.Direction
    $srcPrefix = if ($Rule.SourceAddressPrefix) { $Rule.SourceAddressPrefix }      else { "" }
    $dstPrefix = if ($Rule.DestinationAddressPrefix) { $Rule.DestinationAddressPrefix } else { "" }
    $dstPort = if ($Rule.DestinationPortRange) { $Rule.DestinationPortRange }     else { "" }
    $srcPort = if ($Rule.SourcePortRange) { $Rule.SourcePortRange }          else { "" }
    $protocol = if ($Rule.Protocol) { $Rule.Protocol }                 else { "*" }
    $priority = if ($Rule.Priority) { $Rule.Priority }                 else { 0 }

    # Helper closure to build a finding object
    $newFinding = {
        param($Severity, $FindingType, $Description, $Recommendation)
        [pscustomobject]@{
            SubscriptionName  = $SubscriptionName
            SubscriptionId    = $SubscriptionId
            ResourceGroup     = $ResourceGroup
            NsgName           = $NsgName
            NsgId             = $NsgId
            Location          = $Location
            RuleName          = $Rule.Name
            Priority          = $priority
            Direction         = $direction
            Access            = $access
            Protocol          = $protocol
            SourcePrefix      = $srcPrefix
            DestinationPrefix = $dstPrefix
            DestinationPort   = $dstPort
            Severity          = $Severity
            FindingType       = $FindingType
            Description       = $Description
            Recommendation    = $Recommendation
        }
    }

    # ── CHECK 1 : Unrestricted inbound SSH ───────────────────────────────────
    if ($access -eq "Allow" -and $direction -eq "Inbound" -and
        (Test-IsUnrestricted $srcPrefix) -and
        (Test-PortInRange -PortSpec $dstPort -TargetPort 22)) {
        $findings += & $newFinding `
            -Severity       "Critical" `
            -FindingType    "Unrestricted Inbound SSH" `
            -Description    "Rule '$($Rule.Name)' (priority $priority) allows inbound SSH (port 22) from any source ('$srcPrefix'). This exposes the resource to brute-force and credential-spray attacks from the public Internet." `
            -Recommendation "Restrict the source address prefix to specific trusted IP ranges or use Azure Bastion / JIT VM Access instead of exposing port 22 directly."
    }

    # ── CHECK 2 : Unrestricted inbound RDP ───────────────────────────────────
    if ($access -eq "Allow" -and $direction -eq "Inbound" -and
        (Test-IsUnrestricted $srcPrefix) -and
        (Test-PortInRange -PortSpec $dstPort -TargetPort 3389)) {
        $findings += & $newFinding `
            -Severity       "Critical" `
            -FindingType    "Unrestricted Inbound RDP" `
            -Description    "Rule '$($Rule.Name)' (priority $priority) allows inbound RDP (port 3389) from any source ('$srcPrefix'). RDP exposed to the Internet is one of the leading ransomware entry vectors." `
            -Recommendation "Remove public RDP access immediately. Use Azure Bastion, JIT VM Access (Microsoft Defender for Cloud), or a site-to-site VPN. Restrict source to known management IP ranges if direct RDP is unavoidable."
    }

    # ── CHECK 3 : Any-to-Any Allow rule ──────────────────────────────────────
    if ($access -eq "Allow" -and
        (Test-IsUnrestricted $srcPrefix) -and
        (Test-IsUnrestricted $dstPrefix) -and
        ($dstPort -eq "*" -or $dstPort -eq "Any")) {
        $findings += & $newFinding `
            -Severity       "Critical" `
            -FindingType    "Any-to-Any Allow Rule" `
            -Description    "Rule '$($Rule.Name)' (priority $priority) permits all traffic in the '$direction' direction from any source to any destination on all ports. This effectively disables the NSG as a security control." `
            -Recommendation "Remove or replace this rule with specific allow rules for required traffic flows only. Apply least-privilege principles: define explicit source/destination prefixes and port ranges."
    }

    # ── CHECK 4 : Broad CIDR (/8 or wider) ───────────────────────────────────
    if ($access -eq "Allow" -and (Test-IsBroadCidr $srcPrefix)) {
        $mask = if ($srcPrefix -match "/(\d+)$") { $Matches[1] } else { "?" }
        $findings += & $newFinding `
            -Severity       "High" `
            -FindingType    "Broad Source CIDR" `
            -Description    "Rule '$($Rule.Name)' (priority $priority) allows traffic from a very large address block ('$srcPrefix', /$mask mask covers $(
                if ($mask -le 8) { [math]::Pow(2, 32 - [int]$mask) } else { 'many' }
            ) addresses). This significantly widens the attack surface beyond operational requirements." `
            -Recommendation "Narrow the source address prefix to the smallest range that satisfies the business requirement. Prefer /24 or smaller for operational subnets. Document justification for any prefix broader than /16."
    }

    # ── CHECK 5 : Excessive port range (>100 ports) ───────────────────────────
    if ($access -eq "Allow") {
        $portWidth = Get-PortRangeWidth -PortSpec $dstPort
        if ($portWidth -gt 100) {
            $findings += & $newFinding `
                -Severity       "High" `
                -FindingType    "Excessive Port Range" `
                -Description    "Rule '$($Rule.Name)' (priority $priority) allows $direction traffic across $portWidth ports ('$dstPort'). Wide port ranges expose unintended services and complicate security monitoring." `
                -Recommendation "Define explicit individual ports or narrow ranges (e.g., 8080-8090) corresponding to actual application requirements. Audit which services genuinely need each port and remove unused entries."
        }
    }

    # ── CHECK 6 : Unrestricted outbound to Internet ───────────────────────────
    if ($access -eq "Allow" -and $direction -eq "Outbound" -and
        ($dstPrefix -in @("*", "Any", "Internet", "0.0.0.0/0")) -and
        ($dstPort -eq "*" -or $dstPort -eq "Any")) {
        $findings += & $newFinding `
            -Severity       "High" `
            -FindingType    "Unrestricted Outbound to Internet" `
            -Description    "Rule '$($Rule.Name)' (priority $priority) permits unrestricted outbound traffic to the Internet on all ports. This can facilitate data exfiltration, command-and-control communication, and lateral movement to external resources." `
            -Recommendation "Restrict outbound rules to specific destination service tags (e.g., Storage, AzureMonitor) or IP ranges. Use Azure Firewall or NVA for egress filtering. Consider an explicit DenyAll outbound rule as the default, with selective Allow rules above it."
    }

    # ── CHECK 7 : Shadowed / conflicting rule ─────────────────────────────────
    $isShadowed = $ShadowedPairs | Where-Object { $_.AllowRuleName -eq $Rule.Name }
    if ($isShadowed) {
        $denyRuleName = $isShadowed.DenyRuleName
        $denyPriority = $isShadowed.DenyPriority
        $findings += & $newFinding `
            -Severity       "Medium" `
            -FindingType    "Shadowed Allow Rule" `
            -Description    "Rule '$($Rule.Name)' (Allow, priority $priority) is overridden by a higher-priority Deny rule '$denyRuleName' (priority $denyPriority) that covers the same traffic. The Allow rule has no effect and represents configuration drift or a misunderstood change." `
            -Recommendation "Review the intent of both rules. If the Allow was intentional, either remove the conflicting Deny rule or raise the Allow rule priority above the Deny. If the Deny is correct, remove the redundant Allow rule to reduce rule sprawl and confusion."
    }

    return $findings
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-NSGSecurityHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$NsgInventory,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [bool]$AssociationsIncluded
    )

    # ── Aggregate counts ──────────────────────────────────────────────────────
    $totalFindings = @($Findings).Count
    $totalNsgs = @($NsgInventory).Count
    $critCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $medCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount = @($Findings | Where-Object { $_.Severity -eq "Informational" }).Count
    $unassocCount = @($NsgInventory | Where-Object { $_.AssociationStatus -eq "Unassociated" }).Count
    $cleanNsgCount = @($NsgInventory | Where-Object { $_.MaxSeverity -eq "Clean" }).Count

    $assocBadge = if ($AssociationsIncluded) {
        '<span class="badge badge-green">✓ Included</span>'
    }
    else {
        '<span class="badge badge-amber">⚠ Skipped (use -IncludeAssociations)</span>'
    }
    $assocText = if ($AssociationsIncluded) { "Included" } else { "Skipped — use -IncludeAssociations to enable" }

    # ── Severity distribution bar rows ───────────────────────────────────────
    $sevCounts = [ordered]@{
        "Critical"      = $critCount
        "High"          = $highCount
        "Medium"        = $medCount
        "Low"           = $lowCount
        "Informational" = $infoCount
    }
    $sevColors = @{
        "Critical"      = "var(--red)"
        "High"          = "var(--amber)"
        "Medium"        = "#d4a017"
        "Low"           = "var(--accent2)"
        "Informational" = "var(--muted)"
    }
    $sevRows = ""
    foreach ($sev in $sevCounts.GetEnumerator()) {
        $pct = if ($totalFindings -gt 0) { [math]::Round(($sev.Value / $totalFindings) * 100) } else { 0 }
        $barClr = $sevColors[$sev.Key]
        $sevRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $sev.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barClr"></div></div>
            <span class="bar-pct">$($sev.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Finding type distribution bar rows ────────────────────────────────────
    $typeGroups = $Findings | Group-Object FindingType | Sort-Object Count -Descending
    $typeRows = ""
    foreach ($grp in $typeGroups) {
        $pct = if ($totalFindings -gt 0) { [math]::Round(($grp.Count / $totalFindings) * 100) } else { 0 }
        $typeRows += @"
          <div class="bar-row">
            <span class="bar-label" title="$(EscHtml $grp.Name)">$(if ($grp.Name.Length -gt 28) { EscHtml($grp.Name.Substring(0,25)+"...") } else { EscHtml $grp.Name })</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($grp.Count) ($pct%)</span>
          </div>
"@
    }

    # ── Findings table rows ───────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $sevCls = switch ($f.Severity) {
            "Critical" { "badge-red" }
            "High" { "badge-amber" }
            "Medium" { "badge-amber" }
            "Low" { "badge-blue" }
            "Informational" { "badge-muted" }
            default { "" }
        }
        $dirIcon = if ($f.Direction -eq "Inbound") { "⬇" } else { "⬆" }
        $nsgShort = if ($f.NsgName.Length -gt 28) { EscHtml($f.NsgName.Substring(0, 25) + "...") } else { EscHtml $f.NsgName }
        $ruleShort = if ($f.RuleName.Length -gt 28) { EscHtml($f.RuleName.Substring(0, 25) + "...") } else { EscHtml $f.RuleName }

        $findingRows += @"
          <tr onclick="showFindingDetail('$(EscHtml(EscJ $f.RuleName))', '$(EscHtml(EscJ $f.NsgName))')">
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td title="$(EscHtml $f.FindingType)">$(EscHtml $f.FindingType)</td>
            <td title="$(EscHtml $f.NsgName)">$nsgShort</td>
            <td title="$(EscHtml $f.RuleName)">$ruleShort</td>
            <td><span class="dir-badge">$dirIcon $(EscHtml $f.Direction)</span></td>
            <td>$(EscHtml $f.Access)</td>
            <td style="font-family:var(--mono);font-size:11px">$($f.Priority)</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
          </tr>
"@
    }

    # ── NSG Inventory table rows ──────────────────────────────────────────────
    $nsgRows = ""
    foreach ($n in $NsgInventory) {
        $maxSevCls = switch ($n.MaxSeverity) {
            "Critical" { "badge-red" }
            "High" { "badge-amber" }
            "Medium" { "badge-amber" }
            "Low" { "badge-blue" }
            "Informational" { "badge-muted" }
            "Clean" { "badge-green" }
            default { "" }
        }
        $assocCls = switch ($n.AssociationStatus) {
            "Associated" { "badge-green" }
            "Unassociated" { "badge-amber" }
            default { "" }
        }
        $nsgNameShort = if ($n.NsgName.Length -gt 32) { EscHtml($n.NsgName.Substring(0, 29) + "...") } else { EscHtml $n.NsgName }

        $nsgRows += @"
          <tr>
            <td title="$(EscHtml $n.NsgName)">$nsgNameShort</td>
            <td>$(EscHtml $n.ResourceGroup)</td>
            <td>$(EscHtml $n.Location)</td>
            <td>$(EscHtml $n.SubscriptionName)</td>
            <td>$($n.RuleCount)</td>
            <td>$($n.FindingCount)</td>
            <td><span class="badge $maxSevCls">$(EscHtml $n.MaxSeverity)</span></td>
            <td><span class="badge $assocCls">$(EscHtml $n.AssociationStatus)</span></td>
          </tr>
"@
    }

    # ── Subscription results panel ────────────────────────────────────────────
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

    # ── JSON for findings detail drawer ───────────────────────────────────────
    $findingsJson = "["
    foreach ($f in $Findings) {
        $findingsJson += "{" +
        """severity"":""$(EscJ $f.Severity)""," +
        """findingType"":""$(EscJ $f.FindingType)""," +
        """nsg"":""$(EscJ $f.NsgName)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """location"":""$(EscJ $f.Location)""," +
        """rule"":""$(EscJ $f.RuleName)""," +
        """priority"":$($f.Priority)," +
        """direction"":""$(EscJ $f.Direction)""," +
        """access"":""$(EscJ $f.Access)""," +
        """protocol"":""$(EscJ $f.Protocol)""," +
        """srcPrefix"":""$(EscJ $f.SourcePrefix)""," +
        """dstPrefix"":""$(EscJ $f.DestinationPrefix)""," +
        """dstPort"":""$(EscJ $f.DestinationPort)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """description"":""$(EscJ $f.Description)""," +
        """recommendation"":""$(EscJ $f.Recommendation)""" +
        "},"
    }
    $findingsJson = $findingsJson.TrimEnd(",") + "]"

    # ── Donut SVG data ─────────────────────────────────────────────────────────
    # We inject counts; JS builds the SVG at runtime for flexibility
    $donutData = "{" +
    """critical"":$critCount," +
    """high"":$highCount," +
    """medium"":$medCount," +
    """low"":$lowCount," +
    """informational"":$infoCount" +
    "}"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure NSG Security Assessment Dashboard</title>
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
  background:linear-gradient(135deg,var(--red),var(--amber));
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin-bottom:22px;}
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
.stat-card.c-muted{border-top-color:var(--muted);}
.stat-num{font-size:30px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:150px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
.donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.legend-list{display:flex;flex-direction:column;gap:10px;}
.legend-item{display:flex;align-items:center;gap:10px;font-size:13px;}
.legend-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;}
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
.badge-muted{background:rgba(125,133,144,.12);color:var(--muted);border:1px solid rgba(125,133,144,.25);}
.dir-badge{font-size:11px;color:var(--muted2);}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.assoc-banner{
  padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:16px;
  display:flex;align-items:center;gap:10px;font-size:13px;
}
.assoc-banner.included{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.3);color:var(--green);}
.assoc-banner.skipped{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3);color:var(--amber);}
.risk-banner{
  padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:16px;
  display:flex;align-items:center;gap:10px;font-size:13px;
}
.risk-banner.critical{background:rgba(248,81,73,.1);border-color:rgba(248,81,73,.4);color:var(--red);}
.risk-banner.high{background:rgba(210,153,34,.1);border-color:rgba(210,153,34,.4);color:var(--amber);}
.risk-banner.clean{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.3);color:var(--green);}
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
.drawer-field-value{font-size:13px;word-break:break-all;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.drawer-desc{font-size:13px;color:var(--muted2);line-height:1.6;margin-bottom:12px;}
.drawer-rec{
  font-size:13px;color:var(--text);line-height:1.6;
  background:var(--surface2);border-left:3px solid var(--accent);
  padding:10px 14px;border-radius:0 var(--radius-sm) var(--radius-sm) 0;
}
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
    <div class="logo-icon">🛡</div>
    <div class="logo-title">NSG Security Assessment</div>
    <div class="logo-sub">Azure Network Security</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> Findings</button>
    <button class="nav-btn" onclick="showPage('inventory',this)"><span class="nav-icon">📋</span> NSG Inventory</button>
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
      Azure NSG Security Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- ═══ OVERVIEW ═══ -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">NSG Security Overview</div>
      <div class="page-sub">Network Security Group posture across __SUB_COUNT__ subscription(s) · __TOTAL_NSGS__ NSGs assessed</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRIT_COUNT__</div>
        <div class="stat-label">Critical Findings</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Findings</div>
        <div class="stat-sub">Address within 24–72 hours</div>
      </div>
      <div class="stat-card c-amber" style="border-top-color:#d4a017">
        <div class="stat-num">__MED_COUNT__</div>
        <div class="stat-label">Medium Findings</div>
        <div class="stat-sub">Address within sprint</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low Findings</div>
      </div>
      <div class="stat-card c-muted">
        <div class="stat-num">__INFO_COUNT__</div>
        <div class="stat-label">Informational</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__CLEAN_COUNT__</div>
        <div class="stat-label">Clean NSGs</div>
        <div class="stat-sub">No findings detected</div>
      </div>
    </div>

    <div class="assoc-banner __ASSOC_BANNER_CLS__">
      <span>🔗</span>
      <span><strong>Association Enrichment:</strong> __ASSOC_TEXT__</span>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Findings by Severity</div>
        <div class="donut-wrap">
          <canvas id="donutCanvas" width="160" height="160" style="flex-shrink:0;"></canvas>
          <div class="legend-list" id="donutLegend"></div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">📋 Severity Distribution</div>
        __SEV_ROWS__
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">🔎 Finding Type Breakdown</div>
      __TYPE_ROWS__
    </div>

    <div class="panel">
      <div class="panel-title">⚡ Risk Guidance</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;font-size:13px;">
        <div class="info-card">
          <div class="info-label">🔴 Critical — Act Immediately</div>
          <div style="font-size:12px;color:var(--muted2);line-height:1.6;margin-top:4px;">Unrestricted SSH/RDP or Any-to-Any Allow rules. Remove or restrict now. Every hour of exposure is a breach opportunity.</div>
        </div>
        <div class="info-card">
          <div class="info-label">🟠 High — Address Within 72 Hours</div>
          <div style="font-size:12px;color:var(--muted2);line-height:1.6;margin-top:4px;">Broad CIDRs, excessive port ranges, unrestricted outbound. These significantly widen the attack surface and enable exfiltration paths.</div>
        </div>
        <div class="info-card">
          <div class="info-label">🟡 Medium — Address in Sprint</div>
          <div style="font-size:12px;color:var(--muted2);line-height:1.6;margin-top:4px;">Shadowed rules indicate configuration drift or misunderstood changes. Resolve during next change window to reduce rule sprawl.</div>
        </div>
        <div class="info-card">
          <div class="info-label">⬜ Informational — Track and Plan</div>
          <div style="font-size:12px;color:var(--muted2);line-height:1.6;margin-top:4px;">Unassociated NSGs add cost and management overhead. Review ownership and decommission if unused. No active traffic risk.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ═══ FINDINGS ═══ -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Security Findings</div>
      <div class="page-sub">Rule-level findings · Click any row for full detail and remediation guidance</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search NSG, rule, finding type…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Informational">Informational</option>
        </select>
        <select class="filter-select" id="filterDir" onchange="filterFindings()">
          <option value="">All Directions</option>
          <option value="Inbound">Inbound</option>
          <option value="Outbound">Outbound</option>
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
              <th onclick="sortFindings(0)">Severity</th>
              <th onclick="sortFindings(1)">Finding Type</th>
              <th onclick="sortFindings(2)">NSG Name</th>
              <th onclick="sortFindings(3)">Rule Name</th>
              <th onclick="sortFindings(4)">Direction</th>
              <th onclick="sortFindings(5)">Access</th>
              <th onclick="sortFindings(6)">Priority</th>
              <th onclick="sortFindings(7)">Subscription</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- ═══ NSG INVENTORY ═══ -->
  <div id="page-inventory" class="page">
    <div class="page-header">
      <div class="page-title">NSG Inventory</div>
      <div class="page-sub">All NSGs assessed · Rolled-up risk rating and association status per NSG</div>
    </div>
    <div class="assoc-banner __ASSOC_BANNER_CLS__">
      <span>🔗</span>
      <span><strong>Association Data:</strong> __ASSOC_TEXT__</span>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="nsgSearch" placeholder="Search NSG name, resource group…" oninput="filterNsgs()"/>
        </div>
        <select class="filter-select" id="filterMaxSev" onchange="filterNsgs()">
          <option value="">All Risk Levels</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Informational">Informational</option>
          <option value="Clean">Clean</option>
        </select>
        <select class="filter-select" id="filterAssoc" onchange="filterNsgs()">
          <option value="">All Association</option>
          <option value="Associated">Associated</option>
          <option value="Unassociated">Unassociated</option>
          <option value="Not Assessed">Not Assessed</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="nsgTable">
          <thead>
            <tr>
              <th onclick="sortNsgs(0)">NSG Name</th>
              <th onclick="sortNsgs(1)">Resource Group</th>
              <th onclick="sortNsgs(2)">Location</th>
              <th onclick="sortNsgs(3)">Subscription</th>
              <th onclick="sortNsgs(4)">Rules</th>
              <th onclick="sortNsgs(5)">Findings</th>
              <th onclick="sortNsgs(6)">Max Severity</th>
              <th onclick="sortNsgs(7)">Association</th>
            </tr>
          </thead>
          <tbody id="nsgBody">__NSG_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="nsgPagination"></div>
    </div>
  </div>

  <!-- ═══ SCAN RESULTS ═══ -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription NSG assessment outcome</div>
    </div>
    <div class="panel">
      <div class="panel-title">☁️ Subscriptions Scanned</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- ═══ SESSION ═══ -->
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
        <div class="info-card"><div class="info-label">Associations</div><div class="info-value">__ASSOC_PARAM_TEXT__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Subscriptions Scanned</div><div class="info-value">__SUB_COUNT__</div></div>
        <div class="info-card"><div class="info-label">Total NSGs Found</div><div class="info-value">__TOTAL_NSGS__</div></div>
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
const FINDINGS_DATA = __FINDINGS_JSON__;
const DONUT_DATA    = __DONUT_DATA__;

let findFiltered = [...FINDINGS_DATA];
let findPage = 1, findPageSz = 25;
let findSortCol = -1, findSortAsc = true;
let currentDetailIdx = 0;

// ── NSG inventory (built client-side from findings for simplicity) ────────────
const NSG_ROWS_HTML = document.getElementById('nsgBody').innerHTML;
let nsgPage = 1, nsgPageSz = 25;
let nsgSortCol = -1, nsgSortAsc = true;
let nsgAllRows = [];

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
  drawDonut();
}

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Donut chart ───────────────────────────────────────────────────────────────
function drawDonut(){
  const canvas = document.getElementById('donutCanvas');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  const isDark = document.documentElement.dataset.theme !== 'light';

  const colors = {
    critical:'#f85149', high:'#d29922', medium:'#d4a017',
    low:'#388bfd', informational: isDark ? '#484f58' : '#8c959f'
  };
  const labels = ['Critical','High','Medium','Low','Informational'];
  const vals   = [DONUT_DATA.critical, DONUT_DATA.high, DONUT_DATA.medium, DONUT_DATA.low, DONUT_DATA.informational];
  const clrs   = [colors.critical, colors.high, colors.medium, colors.low, colors.informational];

  const total = vals.reduce((a,b)=>a+b,0);
  const cx=80, cy=80, r=65, inner=42;
  ctx.clearRect(0,0,160,160);

  if(total===0){
    ctx.beginPath(); ctx.arc(cx,cy,r,0,Math.PI*2);
    ctx.strokeStyle=isDark?'#30363d':'#d0d7de'; ctx.lineWidth=23; ctx.stroke();
  } else {
    let start = -Math.PI/2;
    vals.forEach((v,i)=>{
      if(v===0) return;
      const slice = (v/total)*Math.PI*2;
      ctx.beginPath(); ctx.moveTo(cx,cy);
      ctx.arc(cx,cy,r,start,start+slice);
      ctx.fillStyle=clrs[i]; ctx.fill();
      start+=slice;
    });
    // inner cutout
    ctx.beginPath(); ctx.arc(cx,cy,inner,0,Math.PI*2);
    ctx.fillStyle=isDark?'#161b22':'#fff'; ctx.fill();
    // total label
    ctx.fillStyle=isDark?'#e6edf3':'#1f2328';
    ctx.font='bold 18px monospace'; ctx.textAlign='center'; ctx.textBaseline='middle';
    ctx.fillText(total, cx, cy-8);
    ctx.font='10px sans-serif'; ctx.fillStyle=isDark?'#7d8590':'#636c76';
    ctx.fillText('findings', cx, cy+10);
  }

  // Legend
  const legend = document.getElementById('donutLegend');
  legend.innerHTML = labels.map((l,i)=>`
    <div class="legend-item">
      <span class="legend-dot" style="background:${clrs[i]}"></span>
      <span>${l}: <strong>${vals[i]}</strong></span>
    </div>`).join('');
}

// ── Findings table ────────────────────────────────────────────────────────────
const sevOrder = {Critical:0, High:1, Medium:2, Low:3, Informational:4};

function filterFindings(){
  const q  = document.getElementById('findSearch').value.toLowerCase();
  const sv = document.getElementById('filterSev').value;
  const dr = document.getElementById('filterDir').value;
  findFiltered = FINDINGS_DATA.filter(r=>{
    const mQ  = !q  || JSON.stringify(r).toLowerCase().includes(q);
    const mSv = !sv || r.severity === sv;
    const mDr = !dr || r.direction === dr;
    return mQ && mSv && mDr;
  });
  findPage = 1; renderFindings();
}

function changeFindPageSize(){
  findPageSz = parseInt(document.getElementById('pgSizeFind').value);
  findPage = 1; renderFindings();
}

function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys = ['severity','findingType','nsg','rule','direction','access','priority','sub'];
  findFiltered.sort((a,b)=>{
    const k=keys[col];
    if(k==='severity'){
      const av=sevOrder[a[k]]??9, bv=sevOrder[b[k]]??9;
      return findSortAsc ? av-bv : bv-av;
    }
    if(k==='priority'){
      return findSortAsc ? (a[k]??0)-(b[k]??0) : (b[k]??0)-(a[k]??0);
    }
    const av=String(a[k]??''), bv=String(b[k]??'');
    return findSortAsc ? av.localeCompare(bv,undefined,{numeric:true})
                       : bv.localeCompare(av,undefined,{numeric:true});
  });
  renderFindings();
}

function renderFindings(){
  const tbody = document.getElementById('findBody');
  const start = (findPage-1)*findPageSz;
  const slice = findFiltered.slice(start, start+findPageSz);
  tbody.innerHTML = slice.map(r=>{
    const gi = FINDINGS_DATA.indexOf(r);
    const sevCls = r.severity==='Critical'?'badge-red':r.severity==='High'?'badge-amber':
                   r.severity==='Medium'?'badge-amber':r.severity==='Low'?'badge-blue':'badge-muted';
    const dirIcon = r.direction==='Inbound'?'⬇':'⬆';
    const nm  = r.nsg.length>28  ? r.nsg.substring(0,25)+'...' : r.nsg;
    const rl  = r.rule.length>28 ? r.rule.substring(0,25)+'...' : r.rule;
    return `<tr onclick="showFindingDetail(${gi})">
      <td><span class="badge ${sevCls}">${escH(r.severity)}</span></td>
      <td>${escH(r.findingType)}</td>
      <td title="${escH(r.nsg)}">${escH(nm)}</td>
      <td title="${escH(r.rule)}">${escH(rl)}</td>
      <td><span class="dir-badge">${dirIcon} ${escH(r.direction)}</span></td>
      <td>${escH(r.access)}</td>
      <td style="font-family:var(--mono);font-size:11px">${r.priority}</td>
      <td>${escH(r.sub)}</td>
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
  if(p<1||p>total) return;
  findPage=p; renderFindings();
}

// ── NSG Inventory table ───────────────────────────────────────────────────────
function filterNsgs(){
  const q    = document.getElementById('nsgSearch').value.toLowerCase();
  const ms   = document.getElementById('filterMaxSev').value;
  const asc  = document.getElementById('filterAssoc').value;
  const rows = document.querySelectorAll('#nsgBody tr');
  rows.forEach(row=>{
    const text    = row.textContent.toLowerCase();
    const maxSevEl = row.querySelector('td:nth-child(7) .badge');
    const assocEl  = row.querySelector('td:nth-child(8) .badge');
    const maxSevV  = maxSevEl ? maxSevEl.textContent.trim() : '';
    const assocV   = assocEl  ? assocEl.textContent.trim()  : '';
    const mQ  = !q   || text.includes(q);
    const mMs = !ms  || maxSevV === ms;
    const mAc = !asc || assocV  === asc || (!assocEl && asc === 'Not Assessed');
    row.style.display = (mQ && mMs && mAc) ? '' : 'none';
  });
}

function sortNsgs(col){
  const tbody = document.getElementById('nsgBody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  const asc   = nsgSortCol===col ? !(nsgSortAsc) : true;
  nsgSortCol  = col; nsgSortAsc = asc;

  rows.sort((a,b)=>{
    const av = a.querySelectorAll('td')[col]?.textContent.trim() ?? '';
    const bv = b.querySelectorAll('td')[col]?.textContent.trim() ?? '';
    if(col===4||col===5){ return asc ? parseInt(av||0)-parseInt(bv||0) : parseInt(bv||0)-parseInt(av||0); }
    if(col===6){
      const so={Critical:0,High:1,Medium:2,Low:3,Informational:4,Clean:5};
      return asc ? (so[av]??9)-(so[bv]??9) : (so[bv]??9)-(so[av]??9);
    }
    return asc ? av.localeCompare(bv,undefined,{numeric:true}) : bv.localeCompare(av,undefined,{numeric:true});
  });
  rows.forEach(r=>tbody.appendChild(r));
}

// ── Detail drawer ─────────────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx = idx;
  const r = FINDINGS_DATA[idx];
  if(!r) return;
  const sevCls = r.severity==='Critical'?'badge-red':r.severity==='High'?'badge-amber':
                 r.severity==='Medium'?'badge-amber':r.severity==='Low'?'badge-blue':'badge-muted';
  document.getElementById('drawerTitle').textContent = r.findingType;
  document.getElementById('drawerNavInfo').textContent = `${idx+1} of ${FINDINGS_DATA.length}`;
  document.getElementById('drawerContent').innerHTML = `
    <div class="drawer-field">
      <div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sevCls}">${escH(r.severity)}</span></div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">NSG Name</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.nsg)}</div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)}</div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Location</div>
      <div class="drawer-field-value">${escH(r.location)}</div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div>
    </div>
    <div class="drawer-section">Rule Details</div>
    <div class="drawer-field">
      <div class="drawer-field-label">Rule Name</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.rule)}</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px;">
      <div><div class="drawer-field-label">Priority</div><div class="drawer-field-value" style="font-family:var(--mono)">${r.priority}</div></div>
      <div><div class="drawer-field-label">Access</div><div class="drawer-field-value">${escH(r.access)}</div></div>
      <div><div class="drawer-field-label">Direction</div><div class="drawer-field-value">${escH(r.direction)}</div></div>
      <div><div class="drawer-field-label">Protocol</div><div class="drawer-field-value">${escH(r.protocol)}</div></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px;">
      <div><div class="drawer-field-label">Source Prefix</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.srcPrefix)}</div></div>
      <div><div class="drawer-field-label">Destination Prefix</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.dstPrefix)}</div></div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Destination Port(s)</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.dstPort)}</div>
    </div>
    <div class="drawer-section">Finding Detail</div>
    <div class="drawer-desc">${escH(r.description)}</div>
    <div class="drawer-section">Remediation</div>
    <div class="drawer-rec">${escH(r.recommendation)}</div>
  `;
  document.getElementById('drawerBackdrop').style.display = 'block';
  document.getElementById('detailDrawer').classList.add('open');
}

function closeDrawer(){
  document.getElementById('drawerBackdrop').style.display = 'none';
  document.getElementById('detailDrawer').classList.remove('open');
}

function navDetail(dir){
  const next = currentDetailIdx + dir;
  if(next >= 0 && next < FINDINGS_DATA.length) showFindingDetail(next);
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width = el.dataset.pct + '%';
    });
  });
}

document.addEventListener('keydown', e=>{
  if(e.key==='Escape')     closeDrawer();
  if(e.key==='ArrowLeft')  navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

// ── Init ──────────────────────────────────────────────────────────────────────
filterFindings();
drawDonut();
animateBars();
</script>
</body>
</html>
'@

    # ── Token substitution ────────────────────────────────────────────────────
    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_NSGS__', $totalNsgs `
        -replace '__CRIT_COUNT__', $critCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MED_COUNT__', $medCount `
        -replace '__LOW_COUNT__', $lowCount `
        -replace '__INFO_COUNT__', $infoCount `
        -replace '__CLEAN_COUNT__', $cleanNsgCount `
        -replace '__ASSOC_BANNER_CLS__', $(if ($AssociationsIncluded) { "included" } else { "skipped" }) `
        -replace '__ASSOC_TEXT__', $assocText `
        -replace '__ASSOC_PARAM_TEXT__', $assocText `
        -replace '__SEV_ROWS__', $sevRows `
        -replace '__TYPE_ROWS__', $typeRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__NSG_ROWS__', $nsgRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FINDINGS_JSON__', $findingsJson `
        -replace '__DONUT_DATA__', $donutData

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureNSGSecurityAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$IncludeAssociations,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureNSGSecurityAssessment.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Network")
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

    if ($subCount -eq 0) {
        Write-Host "  ✗ No subscriptions found for the authenticated account." -ForegroundColor Red
        return
    }

    # ── Display session / params ──────────────────────────────────────────────
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data ([ordered]@{
            "Scope"                = "$scopeText ($subCount found)"
            "Include Associations" = if ($IncludeAssociations) { "Enabled" } else { "Disabled (use -IncludeAssociations)" }
            "Export to CSV"        = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
            "Export Path"          = if ($ExportToCsv.IsPresent) { $CsvPath }  else { "" }
        })

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $allNsgInventory = @()
    $subscriptionResults = @()
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

            # ── Retrieve all NSGs in this subscription ─────────────────────
            $nsgs = @()
            try {
                $nsgs = @(Get-AzNetworkSecurityGroup -ErrorAction Stop)
            }
            catch {
                Write-Warning "  Could not retrieve NSGs for '$($sub.Name)': $_"
            }

            $subFindingCount = 0
            $subNsgCount = $nsgs.Count

            foreach ($nsg in $nsgs) {
                $nsgName = $nsg.Name
                $nsgId = $nsg.Id
                $rg = $nsg.ResourceGroupName
                $loc = $nsg.Location

                # ── Association status ─────────────────────────────────────
                $assocStatus = "Not Assessed"
                $subnetAssocs = @()
                $nicAssocs = @()

                if ($IncludeAssociations) {
                    try {
                        # Subnets
                        if ($nsg.Subnets -and $nsg.Subnets.Count -gt 0) {
                            $subnetAssocs = @($nsg.Subnets | ForEach-Object { ($_.Id -split "/")[-1] })
                        }

                        # NICs
                        if ($nsg.NetworkInterfaces -and $nsg.NetworkInterfaces.Count -gt 0) {
                            $nicAssocs = @($nsg.NetworkInterfaces | ForEach-Object { ($_.Id -split "/")[-1] })
                        }

                        if ($subnetAssocs.Count -eq 0 -and $nicAssocs.Count -eq 0) {
                            $assocStatus = "Unassociated"
                        }
                        else {
                            $assocStatus = "Associated"
                        }
                    }
                    catch {
                        $assocStatus = "Not Assessed"
                        Write-Verbose "  Could not resolve associations for NSG '$nsgName': $_"
                    }
                }

                # ── Collect user-defined rules (exclude Azure defaults) ────
                $userRules = @($nsg.SecurityRules | Where-Object {
                        $_.Name -notlike "AllowVnet*" -and
                        $_.Name -notlike "AllowAzure*" -and
                        $_.Name -notlike "DenyAllIn*" -and
                        $_.Name -notlike "AllowInternet*" -and
                        $_.Name -notlike "DenyAll*"
                    })

                # ── Shadowed rule detection ────────────────────────────────
                $shadowedPairs = @()
                if ($userRules.Count -gt 1) {
                    $shadowedPairs = @(Get-ShadowedRules -Rules $userRules)
                }

                # ── Evaluate each rule for findings ───────────────────────
                $nsgFindings = @()

                foreach ($rule in $userRules) {
                    $ruleFindings = @(Get-RuleFindings `
                            -Rule             $rule `
                            -NsgName          $nsgName `
                            -NsgId            $nsgId `
                            -ResourceGroup    $rg `
                            -Location         $loc `
                            -SubscriptionName $sub.Name `
                            -SubscriptionId   $sub.Id `
                            -ShadowedPairs    $shadowedPairs)

                    $nsgFindings += $ruleFindings
                }

                # ── Unassociated NSG finding ───────────────────────────────
                if ($IncludeAssociations -and $assocStatus -eq "Unassociated") {
                    $nsgFindings += [pscustomobject]@{
                        SubscriptionName  = $sub.Name
                        SubscriptionId    = $sub.Id
                        ResourceGroup     = $rg
                        NsgName           = $nsgName
                        NsgId             = $nsgId
                        Location          = $loc
                        RuleName          = "N/A (NSG level)"
                        Priority          = 0
                        Direction         = "N/A"
                        Access            = "N/A"
                        Protocol          = "N/A"
                        SourcePrefix      = "N/A"
                        DestinationPrefix = "N/A"
                        DestinationPort   = "N/A"
                        Severity          = "Informational"
                        FindingType       = "Unassociated NSG"
                        Description       = "NSG '$nsgName' in resource group '$rg' is not associated with any subnet or network interface. Unassociated NSGs provide no security value, incur management overhead, and may represent abandoned resources from decommissioned workloads."
                        Recommendation    = "Review the NSG with the owning team. If the workload it was created for is decommissioned, delete the NSG to reduce management surface. If it is reserved for future use, tag it with the intended workload and owner so it can be tracked."
                    }
                }

                $allFindings += $nsgFindings
                $subFindingCount += $nsgFindings.Count

                # ── NSG-level inventory roll-up ────────────────────────────
                $severityOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3; "Informational" = 4 }
                $maxSeverity = "Clean"

                if ($nsgFindings.Count -gt 0) {
                    $topFinding = $nsgFindings |
                    Sort-Object { $severityOrder[$_.Severity] } |
                    Select-Object -First 1
                    $maxSeverity = $topFinding.Severity
                }

                $allNsgInventory += [pscustomobject]@{
                    SubscriptionName   = $sub.Name
                    SubscriptionId     = $sub.Id
                    ResourceGroup      = $rg
                    NsgName            = $nsgName
                    NsgId              = $nsgId
                    Location           = $loc
                    RuleCount          = $userRules.Count
                    FindingCount       = $nsgFindings.Count
                    MaxSeverity        = $maxSeverity
                    AssociationStatus  = $assocStatus
                    SubnetAssociations = ($subnetAssocs -join "; ")
                    NicAssociations    = ($nicAssocs -join "; ")
                }
            }

            # ── Per-subscription result ────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "NSGs: $subNsgCount  Findings: $subFindingCount" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "NSGs: $subNsgCount  Findings: $subFindingCount"
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

    $critCount = @($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($allFindings | Where-Object { $_.Severity -eq "High" }).Count
    $medCount = @($allFindings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($allFindings | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount = @($allFindings | Where-Object { $_.Severity -eq "Informational" }).Count

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Total NSGs Assessed"         = $allNsgInventory.Count
            "Total Findings"              = $allFindings.Count
            "  Critical"                  = $critCount
            "  High"                      = $highCount
            "  Medium"                    = $medCount
            "  Low"                       = $lowCount
            "  Informational"             = $infoCount
            "Associations Assessed"       = if ($IncludeAssociations) { "Yes" } else { "No (use -IncludeAssociations)" }
            "Execution Time"              = $duration
        })

    Write-SeverityBreakdown -Findings $allFindings

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')

    if ($allFindings.Count -gt 0 -or $allNsgInventory.Count -gt 0) {
        # CSV
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, ResourceGroup, NsgName, NsgId, Location,
                RuleName, Priority, Direction, Access, Protocol,
                SourcePrefix, DestinationPrefix, DestinationPort,
                Severity, FindingType, Description, Recommendation |
                Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                # Inventory as a companion CSV
                $invCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "Inventory.csv"
                $allNsgInventory | Select-Object `
                    SubscriptionName, SubscriptionId, ResourceGroup, NsgName, Location,
                RuleCount, FindingCount, MaxSeverity, AssociationStatus,
                SubnetAssociations, NicAssociations |
                Export-Csv -Path $invCsvPath -NoTypeInformation -Encoding UTF8

                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML dashboard
        try {
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

            $htmlContent = Generate-NSGSecurityHtml `
                -SessionInfo           $sessionInfo `
                -ScanParameters        $scanParams `
                -Findings              $allFindings `
                -NsgInventory          $allNsgInventory `
                -SubscriptionResults   $subscriptionResults `
                -GeneratedOn           (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -AssociationsIncluded  $IncludeAssociations.IsPresent

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
            Select-Object SubscriptionName, NsgName, RuleName, Direction, Priority,
            Severity, FindingType, SourcePrefix, DestinationPort |
            Out-GridView -Title "Azure NSG Security Assessment — Findings"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No NSGs found in the targeted subscriptions." -ForegroundColor Yellow
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
