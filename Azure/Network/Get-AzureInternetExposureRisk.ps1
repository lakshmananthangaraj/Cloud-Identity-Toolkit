<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 17 August 2026
Modified-On     : 17 August 2026

.SYNOPSIS
    Identifies publicly exposed Azure resources, classifies exposure risk by service
    type, security controls, and business criticality, and produces an interactive
    HTML dashboard with prioritised remediation guidance across one or more subscriptions.

.DESCRIPTION
    Get-AzureInternetExposureRisk discovers and analyses internet-facing Azure
    resources using the flow: Network Discovery → Exposure Assessment → Security
    Control Correlation → Risk Determination → Business Impact → Prioritised
    Recommendation.

    The script assesses the following resource types (modular / extensible):

        Virtual Machines
            - Direct NIC-level public IP assignment
            - Indirect exposure via Load Balancer frontend → backend pool membership
            - Indirect exposure via Application Gateway backend pool membership
            - JIT VM access status (requires Defender for Cloud)
            - Azure Bastion availability in the same VNet
            - Defender for Servers plan coverage
            - NSG association and management-port exposure analysis

        Public Load Balancers
            - Frontend IP → inbound NAT rule → backend port mapping
            - Backend pool member enumeration
            - Health probe exposure and open rule assessment

        Application Gateways
            - WAF enablement and mode (Detection vs Prevention)
            - Backend pool composition and HTTP/HTTPS listener analysis
            - SSL termination and end-to-end TLS assessment

        Azure Kubernetes Service (AKS)
            - Public API server exposure
            - Authorised IP ranges configuration
            - Public LoadBalancer services via Node Resource Group detection

        App Services and Function Apps
            - Default public endpoint availability
            - Network restrictions / Access Restriction rules
            - VNet Integration status

        Azure SQL Servers
            - Public endpoint status
            - Firewall rules (allow Azure services, broad CIDRs)

        Storage Accounts
            - Public blob access
            - Network ACL default action and IP rules

        API Management
            - Deployment type (External / Internal / Consumption)
            - Network type and public IP assignment

        Azure Container Registry (ACR)
            - Public network access and network restrictions

        Azure Front Door
            - Presence as a CDN/WAF layer (informational posture signal)

    For each exposed resource the script records:

        ResourceName          : Azure resource name
        ResourceType          : Service category
        ResourceGroup         : Resource group
        SubscriptionName      : Subscription
        PublicIP / Endpoint   : Public address or FQDN
        ExposureType          : Direct-PublicIP | LB-NAT | AppGW-Backend | PublicEndpoint
        ExposedPorts          : Ports/protocols directly accessible from the internet
        SecurityControls      : Comma-delimited list of active controls (WAF, JIT, Bastion, etc.)
        MissingControls       : Controls expected but not found
        Severity              : Critical / High / Medium / Low / Informational
        BusinessCriticality   : tag-derived or heuristic value (Critical/High/Medium/Low/Unknown)
        BusinessImpact        : Human-readable impact statement
        Recommendation        : Prioritised, actionable remediation step
        DDoSProtected         : Whether the VNet has DDoS Protection Standard

    The script supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Tag-based business criticality (configurable tag name via -CriticalityTagName)
        - Tag-based exclusions with separate governance reporting (-ExcludeTagName/-ExcludeTagValue)
        - FastMode switch to skip expensive per-resource calls for large environments
        - Real-time progress bar and colour-coded per-subscription output
        - Optional CSV export of all findings + separate excluded-resources CSV
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          severity distribution, service type breakdown, detail drawer with full context)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan.

.PARAMETER CriticalityTagName
    Name of the Azure resource tag used to derive business criticality.
    Default: "Criticality". Accepted values in tag: Critical, High, Medium, Low.

.PARAMETER ExcludeTagName
    Tag name used to identify resources that should be excluded from risk findings
    (e.g. an approved security exception tag). Excluded resources are still reported
    in a separate governance section and optional CSV.

.PARAMETER ExcludeTagValue
    The tag value that, when combined with -ExcludeTagName, marks a resource as
    excluded. Default: "SecurityException".

.PARAMETER FastMode
    Switch. Skips expensive per-resource API calls: JIT VM access status,
    effective security rule evaluation, and per-NIC Defender for Endpoint checks.
    Recommended for environments with hundreds of subscriptions or thousands of VMs.

.PARAMETER ExportToCsv
    Switch. Exports all findings to -CsvPath and excluded resources to a
    companion CSV with the same base name plus "Exclusions" suffix.

.PARAMETER CsvPath
    Output path for the CSV export and (derived) HTML dashboard.
    Default: C:\Temp\AzureInternetExposureRisk-Report.csv

.INPUTS
    None.

.OUTPUTS
    HTML dashboard always written alongside -CsvPath. Optional CSV export.
    Optional Grid View where a GUI session is available.

.EXAMPLE
    Get-AzureInternetExposureRisk -AllSubscriptions

.EXAMPLE
    Get-AzureInternetExposureRisk -AllSubscriptions -FastMode -ExportToCsv

.EXAMPLE
    Get-AzureInternetExposureRisk -SubscriptionIds @("sub-1","sub-2") `
        -CriticalityTagName "Environment" -ExcludeTagName "SkipScan" -ExcludeTagValue "True"

.EXAMPLE
    Get-AzureInternetExposureRisk -AllSubscriptions -ExportToCsv `
        -CsvPath "C:\Reports\InternetExposure.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (17-Aug-2026) - Initial release. Full enterprise exposure assessment
                            covering VMs (direct + LB + AppGW), AKS, App Service,
                            SQL, Storage, APIM, ACR, Front Door. Tag-based
                            criticality, exclusions, DDoS coverage, WAF, JIT,
                            Bastion, and Defender posture. FastMode, CSV export,
                            HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell modules: Az.Accounts, Az.Network, Az.Compute, Az.Security,
           Az.Websites, Az.Sql, Az.Storage, Az.Aks, Az.ApiManagement,
           Az.ContainerRegistry — installed automatically with user consent.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role at subscription scope (minimum).
        4. Security Reader for Defender for Cloud / JIT status.
        5. -FastMode skips JIT/Defender calls that need Security Reader.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - AKS LoadBalancer service discovery enumerates the node resource group;
          this may require additional permissions on the MC_ resource group.
        - Indirect VM exposure through Load Balancers / Application Gateways
          requires cross-referencing backend pools which adds API calls per LB/AppGW.
        - API Management Consumption tier does not expose a public IP directly;
          it is classified as PublicEndpoint with lower severity.
        - Azure Front Door is assessed for WAF posture only; origin exposure
          analysis (whether origins are appropriately protected) is out of scope.
        - Interactive Grid View requires a GUI session. Skipped gracefully in
          headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          path on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices
    https://learn.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-overview
    https://learn.microsoft.com/en-us/azure/bastion/bastion-overview
    https://learn.microsoft.com/en-us/azure/web-application-firewall/overview

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CenteredText {
    param([string]$Text, [int]$Width = 80, [string]$Color = "White")
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Internet Exposure Risk Assessment v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-Section {
    param([string]$Title, [hashtable]$Data)
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($key in $Data.Keys) {
        $value = $Data[$key]
        if ([string]::IsNullOrWhiteSpace($value)) { $value = "None"; $valColor = "DarkGray" }
        else { $valColor = "White" }
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
    param([int]$Current, [int]$Total, [string]$CurrentItem, [int]$BarWidth = 40)
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
    param([hashtable]$Dist)
    if ($Dist.Count -eq 0) { return }
    Write-Host ""
    Write-Host "  Severity Breakdown" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    $colorMap = @{ Critical = "Red"; High = "Red"; Medium = "Yellow"; Low = "Green"; Informational = "DarkGray" }
    foreach ($key in @("Critical", "High", "Medium", "Low", "Informational")) {
        if ($Dist.ContainsKey($key)) {
            $c = if ($colorMap.ContainsKey($key)) { $colorMap[$key] } else { "White" }
            Write-Host "  " -NoNewline
            Write-Host $key.PadRight(22) -NoNewline -ForegroundColor $c
            Write-Host ": " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($Dist[$key]) finding(s)" -ForegroundColor $c
        }
    }
}

Function Write-OutputFiles {
    param([string]$CsvPath, [string]$HtmlPath, [bool]$GridViewOpened)
    Write-Host ""
    Write-Host "  Output Files" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    if ($CsvPath) { Write-Host "  "; Write-Host "✓ " -NoNewline -ForegroundColor Green; Write-Host ("CSV Export").PadRight(22) -NoNewline -ForegroundColor Gray; Write-Host ": $CsvPath" -ForegroundColor White }
    if ($HtmlPath) { Write-Host "  "; Write-Host "✓ " -NoNewline -ForegroundColor Green; Write-Host ("HTML Dashboard").PadRight(22) -NoNewline -ForegroundColor Gray; Write-Host ": $HtmlPath" -ForegroundColor White }
    if ($GridViewOpened) { Write-Host "  "; Write-Host "✓ " -NoNewline -ForegroundColor Green; Write-Host ("Grid View").PadRight(22) -NoNewline -ForegroundColor Gray; Write-Host ": Opened in separate window" -ForegroundColor White }
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-ObjProperty {
    param([object]$Obj, [string]$PropName, $Default = $null)
    try { $val = $Obj.$PropName; if ($null -ne $val) { return $val }; return $Default }
    catch { return $Default }
}

# ── Risk helpers ──────────────────────────────────────────────────────────────

Function Get-CriticalityFromTags {
    param([hashtable]$Tags, [string]$TagName)
    if (-not $Tags -or -not $Tags.ContainsKey($TagName)) { return "Unknown" }
    $v = $Tags[$TagName].Trim()
    switch -Wildcard ($v.ToLower()) {
        "critical" { return "Critical" }
        "high" { return "High" }
        "medium" { return "Medium" }
        "low" { return "Low" }
        default { return "Unknown" }
    }
}

Function Get-HeuristicCriticality {
    param([string]$ResourceType)
    switch ($ResourceType) {
        "VirtualMachine" { return "High" }
        "SQLServer" { return "Critical" }
        "StorageAccount" { return "High" }
        "KeyVault" { return "Critical" }
        "AKSCluster" { return "High" }
        "ApplicationGateway" { return "High" }
        "LoadBalancer" { return "Medium" }
        "AppService" { return "Medium" }
        "FunctionApp" { return "Medium" }
        "APIManagement" { return "High" }
        "ContainerRegistry" { return "High" }
        "FrontDoor" { return "Medium" }
        default { return "Unknown" }
    }
}

Function Get-BusinessImpact {
    param([string]$Severity, [string]$ResourceType, [string]$ExposedPorts)
    $portNote = if ($ExposedPorts -match "3389|22|5985|5986|23") { " Management port ($($Matches[0])) exposure enables direct remote code execution." } else { "" }
    switch ($Severity) {
        "Critical" { return "Unrestricted internet access to $ResourceType.$portNote Exploitation can result in full resource compromise, data breach, ransomware deployment, or lateral movement across the network." }
        "High" { return "Internet-exposed $ResourceType with insufficient access controls.$portNote Successful exploitation risks data exfiltration, service disruption, and compliance violations (PCI-DSS, GDPR, ISO 27001)." }
        "Medium" { return "Internet-facing $ResourceType with partial controls. Risk of targeted attack if controls are bypassed or misconfigured. May violate least-privilege network access principles." }
        "Low" { return "Managed internet exposure with controls in place. Ongoing monitoring recommended to detect configuration drift." }
        default { return "Internet-facing $ResourceType. Review exposure and verify controls are appropriate for the security classification of this workload." }
    }
}

Function Test-IsManagementPort {
    param([string]$Port)
    return ($Port -match "^(3389|22|5985|5986|23|21|445|1433|3306|5432|6379|27017|9200|9300)$")
}

Function Test-ResourceExcluded {
    param([hashtable]$Tags, [string]$ExcludeTagName, [string]$ExcludeTagValue)
    if (-not $Tags -or [string]::IsNullOrWhiteSpace($ExcludeTagName)) { return $false }
    if ($Tags.ContainsKey($ExcludeTagName) -and $Tags[$ExcludeTagName] -eq $ExcludeTagValue) { return $true }
    return $false
}


#------------------------------------------------------------------------ [ Finding Builder ]

Function New-ExposureFinding {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$ResourceName,
        [string]$ResourceType,
        [string]$ResourceGroup,
        [string]$Region,
        [string]$PublicEndpoint,
        [string]$ExposureType,
        [string]$ExposedPorts,
        [string]$SecurityControls,
        [string]$MissingControls,
        [string]$Severity,
        [string]$BusinessCriticality,
        [string]$BusinessImpact,
        [string]$Recommendation,
        [string]$DDoSProtected,
        [bool]$IsExcluded = $false,
        [string]$ExclusionReason = ""
    )
    return [pscustomobject]@{
        SubscriptionName    = $SubscriptionName
        SubscriptionId      = $SubscriptionId
        ResourceName        = $ResourceName
        ResourceType        = $ResourceType
        ResourceGroup       = $ResourceGroup
        Region              = $Region
        PublicEndpoint      = $PublicEndpoint
        ExposureType        = $ExposureType
        ExposedPorts        = $ExposedPorts
        SecurityControls    = $SecurityControls
        MissingControls     = $MissingControls
        Severity            = $Severity
        BusinessCriticality = $BusinessCriticality
        BusinessImpact      = $BusinessImpact
        Recommendation      = $Recommendation
        DDoSProtected       = $DDoSProtected
        IsExcluded          = $IsExcluded
        ExclusionReason     = $ExclusionReason
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-InternetExposureHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$ExcludedFindings,
        [hashtable]$SeverityDist,
        [hashtable]$ServiceTypeDist,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [bool]$FastMode
    )

    $totalFindings = @($Findings).Count
    $criticalCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $infoCount = @($Findings | Where-Object { $_.Severity -eq "Informational" }).Count
    $excludedCount = @($ExcludedFindings).Count
    $critHighFindings = @($Findings | Where-Object { $_.Severity -in @("Critical", "High") })

    $fastModeBadge = if ($FastMode) {
        '<span class="badge badge-amber">⚡ FastMode — some per-resource checks skipped</span>'
    }
    else {
        '<span class="badge badge-green">✓ Full Assessment</span>'
    }
    $fastModeText = if ($FastMode) { "FastMode (JIT/Defender checks skipped)" } else { "Full Assessment" }

    # ── Finding rows (all findings table) ───────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $sevCls = switch ($f.Severity) {
            "Critical" { "badge-critical" }
            "High" { "badge-red" }
            "Medium" { "badge-amber" }
            "Low" { "badge-green" }
            default { "badge-blue" }
        }
        $critCls = switch ($f.BusinessCriticality) {
            "Critical" { "badge-critical" }; "High" { "badge-red" }
            "Medium" { "badge-amber" }; "Low" { "badge-green" }
            default { "" }
        }
        $nmDisp = if ($f.ResourceName.Length -gt 32) { (EscHtml $f.ResourceName.Substring(0, 29)) + "..." } else { EscHtml $f.ResourceName }
        $epDisp = if ($f.PublicEndpoint.Length -gt 28) { (EscHtml $f.PublicEndpoint.Substring(0, 25)) + "..." } else { EscHtml $f.PublicEndpoint }
        $ddosBadge = if ($f.DDoSProtected -eq "Yes") { '<span class="badge badge-green">✓</span>' }
        elseif ($f.DDoSProtected -eq "No") { '<span class="badge badge-red">✗</span>' }
        else { '<span class="badge" style="background:var(--surface3);color:var(--muted)">—</span>' }
        $findingRows += @"
          <tr onclick="showFindingDetail($($Findings.IndexOf($f)))">
            <td title="$(EscHtml $f.ResourceName)">$nmDisp</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$(EscHtml $f.ResourceType)</td>
            <td title="$(EscHtml $f.PublicEndpoint)">$epDisp</td>
            <td>$(EscHtml $f.ExposureType)</td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td><span class="badge $critCls">$(EscHtml $f.BusinessCriticality)</span></td>
            <td>$ddosBadge</td>
          </tr>
"@
    }

    # ── Critical/High findings rows ───────────────────────────────────────────
    $critHighRows = ""
    foreach ($f in $critHighFindings) {
        $sevCls = if ($f.Severity -eq "Critical") { "badge-critical" } else { "badge-red" }
        $nmDisp = if ($f.ResourceName.Length -gt 28) { (EscHtml $f.ResourceName.Substring(0, 25)) + "..." } else { EscHtml $f.ResourceName }
        $critHighRows += @"
          <tr onclick="showFindingDetail($($Findings.IndexOf($f)))">
            <td title="$(EscHtml $f.ResourceName)">$nmDisp</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$(EscHtml $f.ResourceType)</td>
            <td>$(EscHtml $f.ExposedPorts)</td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td title="$(EscHtml $f.Recommendation)">$(if ($f.Recommendation.Length -gt 60) { (EscHtml $f.Recommendation.Substring(0,57)) + "..." } else { EscHtml $f.Recommendation })</td>
          </tr>
"@
    }
    if (-not $critHighRows) { $critHighRows = '<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:20px">No Critical or High findings — good posture</td></tr>' }

    # ── Excluded rows ─────────────────────────────────────────────────────────
    $excludedRows = ""
    foreach ($e in $ExcludedFindings) {
        $excludedRows += @"
          <tr>
            <td>$(EscHtml $e.ResourceName)</td>
            <td>$(EscHtml $e.SubscriptionName)</td>
            <td>$(EscHtml $e.ResourceType)</td>
            <td>$(EscHtml $e.ExclusionReason)</td>
          </tr>
"@
    }
    if (-not $excludedRows) { $excludedRows = '<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">No excluded resources in this scan</td></tr>' }

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
    $sevTotal = ($SeverityDist.Values | Measure-Object -Sum).Sum
    $sevRows = ""
    $sevBarColors = @{ Critical = "var(--critical)"; High = "var(--red)"; Medium = "var(--amber)"; Low = "var(--green)"; Informational = "var(--muted)" }
    foreach ($key in @("Critical", "High", "Medium", "Low", "Informational")) {
        if ($SeverityDist.ContainsKey($key)) {
            $pct = if ($sevTotal -gt 0) { [math]::Round(($SeverityDist[$key] / $sevTotal) * 100) } else { 0 }
            $color = if ($sevBarColors.ContainsKey($key)) { $sevBarColors[$key] } else { "var(--accent)" }
            $sevRows += @"
          <div class="bar-row">
            <span class="bar-label">$key</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$color"></div></div>
            <span class="bar-pct">$($SeverityDist[$key]) ($pct%)</span>
          </div>
"@
        }
    }

    # ── Service type distribution bars ────────────────────────────────────────
    $svcTotal = ($ServiceTypeDist.Values | Measure-Object -Sum).Sum
    $svcRows = ""
    foreach ($s in ($ServiceTypeDist.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($svcTotal -gt 0) { [math]::Round(($s.Value / $svcTotal) * 100) } else { 0 }
        $svcRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $s.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($s.Value) ($pct%)</span>
          </div>
"@
    }

    # ── JSON for detail drawer ────────────────────────────────────────────────
    $findJson = "["
    foreach ($f in $Findings) {
        $findJson += "{" +
        """nm"":""$(EscJ $f.ResourceName)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """rt"":""$(EscJ $f.ResourceType)""," +
        """region"":""$(EscJ $f.Region)""," +
        """ep"":""$(EscJ $f.PublicEndpoint)""," +
        """expType"":""$(EscJ $f.ExposureType)""," +
        """ports"":""$(EscJ $f.ExposedPorts)""," +
        """controls"":""$(EscJ $f.SecurityControls)""," +
        """missing"":""$(EscJ $f.MissingControls)""," +
        """sev"":""$(EscJ $f.Severity)""," +
        """crit"":""$(EscJ $f.BusinessCriticality)""," +
        """impact"":""$(EscJ $f.BusinessImpact)""," +
        """rec"":""$(EscJ $f.Recommendation)""," +
        """ddos"":""$(EscJ $f.DDoSProtected)""" +
        "},"
    }
    $findJson = $findJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Internet Exposure Risk Assessment</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;
  --border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;
  --green:#3fb950;--amber:#d29922;--red:#f85149;--critical:#ff5a5f;
  --text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);
}
html[data-theme="light"]{
  --bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;
  --border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;
  --green:#1a7f37;--amber:#b08000;--red:#cf222e;--critical:#b91c1c;
  --text:#1f2328;--muted:#636c76;--muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;}
#sidebar{width:240px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:transform .25s;}
.logo-block{padding:22px 18px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,var(--critical),var(--red));display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{display:inline-block;margin-top:8px;padding:2px 8px;border-radius:20px;font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent);border:1px solid var(--border);}
.nav-section{padding:14px 10px;flex:1;}
.nav-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;padding:0 8px;margin-bottom:6px;}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 12px;border:none;background:transparent;color:var(--muted2);font-size:13px;border-radius:var(--radius-sm);cursor:pointer;text-align:left;transition:background .15s,color .15s;position:relative;margin-bottom:2px;}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:var(--surface3);color:var(--accent);font-weight:600;}
.nav-btn.active::before{content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;background:var(--accent);border-radius:0 3px 3px 0;}
.nav-icon{font-size:16px;width:20px;text-align:center;}
.sidebar-footer{padding:14px 16px;border-top:1px solid var(--border);}
.theme-toggle{display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:10px;}
.toggle-pill{width:40px;height:22px;border-radius:11px;border:none;cursor:pointer;background:var(--surface3);position:relative;transition:background .2s;}
.toggle-pill::after{content:'';position:absolute;top:3px;left:3px;width:16px;height:16px;border-radius:50%;background:var(--accent);transition:transform .2s;}
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
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;cursor:default;}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-card.c-critical{border-top-color:var(--critical);}
.stat-num{font-size:30px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:140px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;}
.search-wrap input{width:100%;padding:8px 12px 8px 34px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;outline:none;}
.search-wrap input:focus{border-color:var(--accent);}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:14px;}
.filter-select{padding:7px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:12px;cursor:pointer;}
.tbl-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{padding:10px 12px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);background:var(--surface2);border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap;user-select:none;}
th:hover{color:var(--text);}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:middle;}
tr:hover td{background:var(--surface2);cursor:pointer;}
.pagination{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:12px;color:var(--muted);flex-wrap:wrap;}
.pg-btn{padding:4px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;}
.pg-btn:hover{border-color:var(--accent);color:var(--accent);}
.pg-btn.active{background:var(--accent);color:#fff;border-color:var(--accent);}
.pg-btn:disabled{opacity:.4;cursor:not-allowed;}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-critical{background:rgba(255,90,95,.18);color:var(--critical);border:1px solid rgba(255,90,95,.35);}
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.fm-banner{padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:16px;display:flex;align-items:center;gap:10px;font-size:13px;}
.fm-banner.full{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.3);color:var(--green);}
.fm-banner.fast{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3);color:var(--amber);}
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
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:460px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
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
.drawer-field-value{font-size:13px;word-break:break-all;line-height:1.6;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.control-tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-family:var(--mono);background:var(--surface3);color:var(--accent2);margin:2px;border:1px solid var(--border);}
.missing-tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-family:var(--mono);background:rgba(248,81,73,.08);color:var(--red);margin:2px;border:1px solid rgba(248,81,73,.2);}
#toast{position:fixed;bottom:24px;right:24px;padding:12px 18px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);font-size:13px;box-shadow:var(--shadow);opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:300;}
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
    <div class="logo-title">Internet Exposure Risk</div>
    <div class="logo-sub">Azure Network Security</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('exposed',this)"><span class="nav-icon">🔓</span> Exposed Resources</button>
    <button class="nav-btn" onclick="showPage('crithigh',this)"><span class="nav-icon">🚨</span> Critical / High</button>
    <button class="nav-btn" onclick="showPage('byservice',this)"><span class="nav-icon">🏷️</span> By Service Type</button>
    <button class="nav-btn" onclick="showPage('excluded',this)"><span class="nav-icon">🚫</span> Exclusions</button>
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
      Azure Internet Exposure Risk
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Internet Exposure Risk Assessment</div>
      <div class="page-sub">Public attack surface across __SUB_COUNT__ subscription(s) · __TOTAL_FINDINGS__ exposed resource(s) identified</div>
    </div>

    <div class="fm-banner __FM_CLS__">
      <span>⚡</span>
      <span><strong>Assessment Mode:</strong> __FM_TEXT__</span>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-critical">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High</div>
        <div class="stat-sub">Remediate within 24–48h</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__INFO_COUNT__</div>
        <div class="stat-label">Informational</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__EXCLUDED_COUNT__</div>
        <div class="stat-label">Excluded</div>
        <div class="stat-sub">Security exceptions</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">⚠️ Severity Distribution</div>
        __SEV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🏷️ Exposed Resources by Service Type</div>
        __SVC_ROWS__
      </div>
    </div>
  </div>

  <!-- Exposed Resources (all) -->
  <div id="page-exposed" class="page">
    <div class="page-header">
      <div class="page-title">Exposed Resources</div>
      <div class="page-sub">All internet-facing resources with full exposure and control context. Click a row for details.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="expSearch" placeholder="Search resource, subscription, endpoint…" oninput="filterExp()"/>
        </div>
        <select class="filter-select" id="filterExpSev" onchange="filterExp()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Informational">Informational</option>
        </select>
        <select class="filter-select" id="filterExpType" onchange="filterExp()">
          <option value="">All Service Types</option>
          <option value="VirtualMachine">Virtual Machine</option>
          <option value="LoadBalancer">Load Balancer</option>
          <option value="ApplicationGateway">Application Gateway</option>
          <option value="AKSCluster">AKS Cluster</option>
          <option value="AppService">App Service</option>
          <option value="FunctionApp">Function App</option>
          <option value="SQLServer">SQL Server</option>
          <option value="StorageAccount">Storage Account</option>
          <option value="APIManagement">API Management</option>
          <option value="ContainerRegistry">Container Registry</option>
        </select>
        <select class="filter-select" id="pgSizeExp" onchange="changeExpPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="expTable">
          <thead>
            <tr>
              <th onclick="sortExp(0)">Resource</th>
              <th onclick="sortExp(1)">Subscription</th>
              <th onclick="sortExp(2)">Type</th>
              <th onclick="sortExp(3)">Public Endpoint</th>
              <th onclick="sortExp(4)">Exposure Type</th>
              <th onclick="sortExp(5)">Severity</th>
              <th onclick="sortExp(6)">Criticality</th>
              <th>DDoS</th>
            </tr>
          </thead>
          <tbody id="expBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="expPagination"></div>
    </div>
  </div>

  <!-- Critical / High page -->
  <div id="page-crithigh" class="page">
    <div class="page-header">
      <div class="page-title">Critical &amp; High Findings</div>
      <div class="page-sub">Prioritised remediation list — address these first to reduce the most significant attack surface.</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Resource</th>
              <th>Subscription</th>
              <th>Type</th>
              <th>Exposed Ports</th>
              <th>Severity</th>
              <th>Top Recommendation</th>
            </tr>
          </thead>
          <tbody>__CRIT_HIGH_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- By Service Type page -->
  <div id="page-byservice" class="page">
    <div class="page-header">
      <div class="page-title">By Service Type</div>
      <div class="page-sub">Exposure distribution and severity breakdown by Azure service category.</div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📊 Severity Distribution</div>
        __SEV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🏷️ Findings by Service Type</div>
        __SVC_ROWS__
      </div>
    </div>
  </div>

  <!-- Exclusions page -->
  <div id="page-excluded" class="page">
    <div class="page-header">
      <div class="page-title">Excluded Resources (Security Exceptions)</div>
      <div class="page-sub">Resources matching the exclusion tag are excluded from risk findings but listed here for governance and audit purposes.</div>
    </div>
    <div class="panel">
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Resource</th>
              <th>Subscription</th>
              <th>Type</th>
              <th>Exclusion Reason</th>
            </tr>
          </thead>
          <tbody>__EXCLUDED_ROWS__</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription exposure assessment outcome</div>
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
      <div class="page-sub">Authentication context and scan configuration</div>
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
        <div class="info-card"><div class="info-label">Assessment Mode</div><div class="info-value">__FM_TEXT__</div></div>
        <div class="info-card"><div class="info-label">Criticality Tag</div><div class="info-value">__CRIT_TAG__</div></div>
        <div class="info-card"><div class="info-label">Exclusion Tag</div><div class="info-value">__EXCL_TAG__</div></div>
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
    <span class="drawer-title" id="drawerTitle">Resource Detail</span>
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
let expFiltered = [...FIND_DATA];
let expPage = 1, expPageSz = 25;
let expSortCol = -1, expSortAsc = true;
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
  const r=document.documentElement;
  r.dataset.theme=r.dataset.theme==='dark'?'light':'dark';
}

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Exposed Resources table ───────────────────────────────────────────────────
function filterExp(){
  const q=document.getElementById('expSearch').value.toLowerCase();
  const s=document.getElementById('filterExpSev').value;
  const t=document.getElementById('filterExpType').value;
  expFiltered=FIND_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mS=!s||r.sev===s;
    const mT=!t||r.rt===t;
    return mQ&&mS&&mT;
  });
  expPage=1; renderExp();
}

function changeExpPageSize(){
  expPageSz=parseInt(document.getElementById('pgSizeExp').value);
  expPage=1; renderExp();
}

function sortExp(col){
  if(expSortCol===col){expSortAsc=!expSortAsc;}else{expSortCol=col;expSortAsc=true;}
  const keys=['nm','sub','rt','ep','expType','sev','crit','ddos'];
  expFiltered.sort((a,b)=>{
    const k=keys[col]; const av=a[k]??'', bv=b[k]??'';
    return expSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                     :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderExp();
}

function renderExp(){
  const tbody=document.getElementById('expBody');
  const start=(expPage-1)*expPageSz;
  const slice=expFiltered.slice(start,start+expPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=FIND_DATA.indexOf(r);
    const sCls=r.sev==='Critical'?'badge-critical':r.sev==='High'?'badge-red':r.sev==='Medium'?'badge-amber':r.sev==='Low'?'badge-green':'badge-blue';
    const cCls=r.crit==='Critical'?'badge-critical':r.crit==='High'?'badge-red':r.crit==='Medium'?'badge-amber':r.crit==='Low'?'badge-green':'';
    const nm=r.nm.length>30?r.nm.substring(0,27)+'...':r.nm;
    const ep=r.ep.length>25?r.ep.substring(0,22)+'...':r.ep;
    const ddos=r.ddos==='Yes'?'<span class="badge badge-green">✓</span>':r.ddos==='No'?'<span class="badge badge-red">✗</span>':'<span style="color:var(--muted)">—</span>';
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.nm)}">${escH(nm)}</td>
      <td>${escH(r.sub)}</td>
      <td>${escH(r.rt)}</td>
      <td title="${escH(r.ep)}">${escH(ep)}</td>
      <td>${escH(r.expType)}</td>
      <td><span class="badge ${sCls}">${escH(r.sev)}</span></td>
      <td><span class="badge ${cCls}">${escH(r.crit)}</span></td>
      <td>${ddos}</td>
    </tr>`;
  }).join('');
  renderExpPg();
}

function renderExpPg(){
  const total=Math.ceil(expFiltered.length/expPageSz);
  const el=document.getElementById('expPagination');
  let h=`<span>${expFiltered.length} resource(s)</span>`;
  h+=`<button class="pg-btn" onclick="changeExpPage(${expPage-1})" ${expPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,expPage-2), e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===expPage?'active':''}" onclick="changeExpPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeExpPage(${expPage+1})" ${expPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeExpPage(p){
  const total=Math.ceil(expFiltered.length/expPageSz);
  if(p<1||p>total)return;
  expPage=p; renderExp();
}

// ── Detail drawer ─────────────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx=idx;
  const r=FIND_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.nm;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FIND_DATA.length}`;
  const sCls=r.sev==='Critical'?'badge-critical':r.sev==='High'?'badge-red':r.sev==='Medium'?'badge-amber':r.sev==='Low'?'badge-green':'badge-blue';
  const cCls=r.crit==='Critical'?'badge-critical':r.crit==='High'?'badge-red':r.crit==='Medium'?'badge-amber':r.crit==='Low'?'badge-green':'';
  const ctrlTags = r.controls ? r.controls.split(',').map(c=>`<span class="control-tag">${escH(c.trim())}</span>`).join(' ') : '<span style="color:var(--muted)">None detected</span>';
  const missTags = r.missing  ? r.missing.split(',').map(c=>`<span class="missing-tag">${escH(c.trim())}</span>`).join(' ')  : '<span style="color:var(--muted)">—</span>';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sCls}">${escH(r.sev)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Business Criticality</div>
      <div class="drawer-field-value"><span class="badge ${cCls}">${escH(r.crit)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Type</div>
      <div class="drawer-field-value">${escH(r.rt)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Region</div>
      <div class="drawer-field-value">${escH(r.region)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Public Endpoint</div>
      <div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.ep)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Exposure Type</div>
      <div class="drawer-field-value">${escH(r.expType)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Exposed Ports / Protocols</div>
      <div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.ports)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">DDoS Protection</div>
      <div class="drawer-field-value">${escH(r.ddos)}</div></div>
    <div class="drawer-section">Security Controls</div>
    <div class="drawer-field"><div class="drawer-field-label">Active Controls</div>
      <div class="drawer-field-value">${ctrlTags}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Missing Controls</div>
      <div class="drawer-field-value">${missTags}</div></div>
    <div class="drawer-section">Business Impact</div>
    <div class="drawer-field"><div class="drawer-field-value" style="line-height:1.6">${escH(r.impact)}</div></div>
    <div class="drawer-section">Recommendation</div>
    <div class="drawer-field"><div class="drawer-field-value" style="line-height:1.6">${escH(r.rec)}</div></div>
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

filterExp();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_FINDINGS__', $totalFindings `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MEDIUM_COUNT__', $mediumCount `
        -replace '__LOW_COUNT__', $lowCount `
        -replace '__INFO_COUNT__', $infoCount `
        -replace '__EXCLUDED_COUNT__', $excludedCount `
        -replace '__FM_CLS__', $(if ($FastMode) { "fast" } else { "full" }) `
        -replace '__FM_TEXT__', $fastModeText `
        -replace '__SEV_ROWS__', $sevRows `
        -replace '__SVC_ROWS__', $svcRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__CRIT_HIGH_ROWS__', $critHighRows `
        -replace '__EXCLUDED_ROWS__', $excludedRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__CRIT_TAG__', $ScanParameters.CriticalityTagName `
        -replace '__EXCL_TAG__', $ScanParameters.ExcludeTag `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FIND_JSON__', $findJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureInternetExposureRisk {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,
        [string[]]$SubscriptionIds,

        [ValidateNotNullOrEmpty()]
        [string]$CriticalityTagName = "Criticality",

        [string]$ExcludeTagName = "",
        [string]$ExcludeTagValue = "SecurityException",

        [switch]$FastMode,
        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureInternetExposureRisk-Report.csv"
    )

    $startTime = Get-Date
    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts", "Az.Network", "Az.Compute", "Az.Websites",
        "Az.Sql", "Az.Storage", "Az.Aks", "Az.ApiManagement", "Az.ContainerRegistry"
    )
    if (-not $FastMode) { $requiredModules += "Az.Security" }

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
        "Scope"           = "$scopeText ($subCount found)"
        "Assessment Mode" = if ($FastMode) { "FastMode (JIT/Defender checks skipped)" } else { "Full Assessment" }
        "Criticality Tag" = $CriticalityTagName
        "Exclusion Tag"   = if ($ExcludeTagName) { "$ExcludeTagName=$ExcludeTagValue" } else { "Not configured" }
        "Export to CSV"   = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"     = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $excludedFindings = @()
    $subscriptionResults = @()
    $severityDist = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
    $serviceTypeDist = @{}
    $successCount = 0
    $errorCount = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = ([math]::Max(
            ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum, 35
        ))

    $subIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $subExposedCount = 0
            $subExcludedCount = 0

            # ── Pre-fetch subscription-wide resources used across assessments ─────
            # Public IPs (needed for VM, LB, AppGW, APIM)
            $allPublicIps = @()
            try { $allPublicIps = @(Get-AzPublicIpAddress -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve public IPs for $($sub.Name): $_" }

            # VNets (for DDoS and Bastion checks)
            $allVnets = @()
            try { $allVnets = @(Get-AzVirtualNetwork -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve VNets for $($sub.Name): $_" }

            # NSGs (for VM inbound rule checks)
            $allNsgs = @()
            try { $allNsgs = @(Get-AzNetworkSecurityGroup -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve NSGs for $($sub.Name): $_" }

            # Bastions
            $allBastions = @()
            try { $allBastions = @(Get-AzBastion -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve Bastions for $($sub.Name): $_" }

            # DDoS-protected VNet IDs
            $ddosProtectedVnetIds = @($allVnets | Where-Object {
                    $_.DdosProtectionPlan -or ($_.EnableDdosProtection -eq $true)
                } | ForEach-Object { $_.Id.ToLower() })

            # Load Balancers
            $allLbs = @()
            try { $allLbs = @(Get-AzLoadBalancer -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve Load Balancers for $($sub.Name): $_" }

            # Application Gateways
            $allAppGws = @()
            try { $allAppGws = @(Get-AzApplicationGateway -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve Application Gateways for $($sub.Name): $_" }

            # JIT policies (only in full mode)
            $jitPolicies = @()
            if (-not $FastMode) {
                try { $jitPolicies = @(Get-AzJitNetworkAccessPolicy -ErrorAction Stop) }
                catch { Write-Verbose "  JIT policies unavailable for $($sub.Name): $_" }
            }

            # Defender for Servers plan
            $defenderServersEnabled = $false
            if (-not $FastMode) {
                try {
                    $pricings = @(Get-AzSecurityPricing -ErrorAction Stop)
                    $serverPricing = $pricings | Where-Object { $_.Name -in @("VirtualMachines", "Servers") }
                    $defenderServersEnabled = ($null -ne $serverPricing -and $serverPricing.PricingTier -eq "Standard")
                }
                catch { Write-Verbose "  Defender pricing unavailable for $($sub.Name): $_" }
            }

            # ── Helper: VNet DDoS check ───────────────────────────────────────────
            Function Get-DDoSStatus {
                param([string]$VNetId)
                if ([string]::IsNullOrWhiteSpace($VNetId)) { return "Unable to Assess" }
                if ($ddosProtectedVnetIds -contains $VNetId.ToLower()) { return "Yes" }
                return "No"
            }

            # ── Helper: NSG inbound exposure analysis ─────────────────────────────
            Function Get-NsgInboundExposure {
                param([string]$NsgId)
                if ([string]::IsNullOrWhiteSpace($NsgId)) { return @{ Ports = "NSG not found"; HasInternet = $false; IsPermissive = $false } }
                $nsg = $allNsgs | Where-Object { $_.Id -eq $NsgId }
                if (-not $nsg) { return @{ Ports = "NSG not found"; HasInternet = $false; IsPermissive = $false } }

                $internetRules = @($nsg.SecurityRules | Where-Object {
                        $_.Direction -eq "Inbound" -and
                        $_.Access -eq "Allow" -and
                        ($_.SourceAddressPrefix -in @("*", "Internet", "0.0.0.0/0", "Any"))
                    })

                if ($internetRules.Count -eq 0) { return @{ Ports = "No internet inbound rules"; HasInternet = $false; IsPermissive = $false } }

                $portList = @()
                $hasWildcard = $false
                foreach ($r in $internetRules) {
                    if ($r.DestinationPortRange -eq "*") { $hasWildcard = $true; $portList += "Any" }
                    else { $portList += $r.DestinationPortRange }
                    foreach ($pr in $r.DestinationPortRanges) {
                        if ($pr -eq "*") { $hasWildcard = $true; $portList += "Any" }
                        else { $portList += $pr }
                    }
                }

                $uniquePorts = ($portList | Sort-Object -Unique) -join ", "
                return @{
                    Ports        = $uniquePorts
                    HasInternet  = $true
                    IsPermissive = $hasWildcard
                }
            }

            # ── Helper: Bastion in VNet ───────────────────────────────────────────
            Function Test-BastionInVNet {
                param([string]$VNetId)
                foreach ($bastion in $allBastions) {
                    $bastionVnetId = ""
                    try {
                        $subnetId = $bastion.IpConfigurations[0].Subnet.Id
                        # VNet ID = everything up to /subnets/
                        $bastionVnetId = ($subnetId -replace "/subnets/[^/]+$", "")
                    }
                    catch {}
                    if ($bastionVnetId -and $bastionVnetId.ToLower() -eq $VNetId.ToLower()) { return $true }
                }
                return $false
            }

            # ─────────────────────────────────────────────────────────────────────
            # ASSESSMENT MODULE 1: VIRTUAL MACHINES
            # ─────────────────────────────────────────────────────────────────────
            $vms = @()
            try { $vms = @(Get-AzVM -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve VMs for $($sub.Name): $_" }

            foreach ($vm in $vms) {
                # Tag-based exclusion
                if (Test-ResourceExcluded -Tags $vm.Tags -ExcludeTagName $ExcludeTagName -ExcludeTagValue $ExcludeTagValue) {
                    $excludedFindings += New-ExposureFinding `
                        -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -ResourceName $vm.Name -ResourceType "VirtualMachine" `
                        -ResourceGroup $vm.ResourceGroupName -Region $vm.Location `
                        -PublicEndpoint "" -ExposureType "" -ExposedPorts "" `
                        -SecurityControls "" -MissingControls "" `
                        -Severity "" -BusinessCriticality "" -BusinessImpact "" -Recommendation "" `
                        -DDoSProtected "" -IsExcluded $true `
                        -ExclusionReason "$ExcludeTagName=$ExcludeTagValue"
                    $subExcludedCount++
                    continue
                }

                # Enumerate NICs
                $nicIds = @($vm.NetworkProfile.NetworkInterfaces | ForEach-Object { $_.Id })

                foreach ($nicId in $nicIds) {
                    $nic = $null
                    try {
                        $nicName = ($nicId -split "/")[-1]
                        $nicRg = ($nicId -split "/resourceGroups/")[1] -split "/" | Select-Object -First 1
                        $nic = Get-AzNetworkInterface -Name $nicName -ResourceGroupName $nicRg -ErrorAction Stop
                    }
                    catch { continue }

                    $nicPublicIpId = $null
                    $publicIpAddr = ""
                    foreach ($ipCfg in $nic.IpConfigurations) {
                        if ($ipCfg.PublicIpAddress) {
                            $nicPublicIpId = $ipCfg.PublicIpAddress.Id
                            break
                        }
                    }

                    # Skip if no public IP on this NIC — will still check via LB below
                    if (-not $nicPublicIpId) { continue }

                    $pip = $allPublicIps | Where-Object { $_.Id -eq $nicPublicIpId }
                    if ($pip) { $publicIpAddr = if ($pip.IpAddress -ne "Not Assigned") { $pip.IpAddress } else { "$($pip.Name) (not assigned)" } }

                    # DDoS
                    $vnetId = ""
                    $subnetId = $nic.IpConfigurations[0].Subnet.Id
                    if ($subnetId) { $vnetId = ($subnetId -replace "/subnets/[^/]+$", "") }
                    $ddosStatus = Get-DDoSStatus -VNetId $vnetId

                    # NSG (NIC-level first, then subnet-level)
                    $nsgId = ""
                    if ($nic.NetworkSecurityGroup) { $nsgId = $nic.NetworkSecurityGroup.Id }
                    if (-not $nsgId) {
                        # Try subnet NSG
                        try {
                            if ($subnetId) {
                                $subnetName = ($subnetId -split "/subnets/")[1]
                                $vnetName = ($vnetId -split "/virtualNetworks/")[1]
                                $vnetRg = ($vnetId -split "/resourceGroups/")[1] -split "/" | Select-Object -First 1
                                $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $vnetRg -ErrorAction SilentlyContinue
                                if ($vnet) {
                                    $subnet = $vnet.Subnets | Where-Object { $_.Name -eq $subnetName }
                                    if ($subnet -and $subnet.NetworkSecurityGroup) { $nsgId = $subnet.NetworkSecurityGroup.Id }
                                }
                            }
                        }
                        catch {}
                    }

                    $nsgExposure = Get-NsgInboundExposure -NsgId $nsgId

                    # JIT
                    $jitEnabled = "Unable to Assess"
                    if (-not $FastMode) {
                        $vmJit = $jitPolicies | Where-Object {
                            $_.VirtualMachines | Where-Object { $_.Id -eq $vm.Id }
                        }
                        $jitEnabled = if ($vmJit) { "JIT-Enabled" } else { "No JIT" }
                    }

                    # Bastion
                    $bastionPresent = Test-BastionInVNet -VNetId $vnetId

                    # Criticality
                    $tagCrit = Get-CriticalityFromTags -Tags $vm.Tags -TagName $CriticalityTagName
                    $criticality = if ($tagCrit -ne "Unknown") { $tagCrit } else { Get-HeuristicCriticality -ResourceType "VirtualMachine" }

                    # Security Controls / Missing
                    $activeControls = @()
                    $missingControls = @()
                    if ($nsgId) { $activeControls += "NSG" } else { $missingControls += "NSG" }
                    if ($bastionPresent) { $activeControls += "Bastion" } else { $missingControls += "Bastion" }
                    if (-not $FastMode) {
                        if ($jitEnabled -eq "JIT-Enabled") { $activeControls += "JIT" } else { $missingControls += "JIT" }
                        if ($defenderServersEnabled) { $activeControls += "Defender-Servers" } else { $missingControls += "Defender-Servers" }
                    }
                    if ($ddosStatus -eq "Yes") { $activeControls += "DDoS-Std" } else { $missingControls += "DDoS-Std" }

                    # Severity
                    $severity = "Medium"
                    if ($nsgExposure.IsPermissive -and $nsgExposure.HasInternet) { $severity = "Critical" }
                    elseif ($nsgExposure.Ports -match "3389|22|5985|5986") {
                        $severity = if ($criticality -in @("Critical", "High")) { "Critical" } else { "High" }
                    }
                    elseif ($nsgExposure.HasInternet) { $severity = "High" }
                    elseif ($missingControls.Count -ge 3) { $severity = "High" }

                    $portDisplay = if ($nsgExposure.Ports) { $nsgExposure.Ports } else { "Unable to Assess" }

                    $finding = New-ExposureFinding `
                        -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -ResourceName $vm.Name -ResourceType "VirtualMachine" `
                        -ResourceGroup $vm.ResourceGroupName -Region $vm.Location `
                        -PublicEndpoint $publicIpAddr -ExposureType "Direct-PublicIP" `
                        -ExposedPorts $portDisplay `
                        -SecurityControls ($activeControls -join ", ") `
                        -MissingControls ($missingControls -join ", ") `
                        -Severity $severity -BusinessCriticality $criticality `
                        -BusinessImpact (Get-BusinessImpact -Severity $severity -ResourceType "VirtualMachine" -ExposedPorts $portDisplay) `
                        -Recommendation (Get-VMRecommendation -Severity $severity -NSGExposure $nsgExposure -Bastion $bastionPresent -JIT $jitEnabled) `
                        -DDoSProtected $ddosStatus

                    $allFindings += $finding
                    $subExposedCount++
                }
            }

            # ── VM via Load Balancer (indirect exposure) ──────────────────────────
            $publicLbs = @($allLbs | Where-Object {
                    $_.FrontendIpConfigurations | Where-Object { $_.PublicIpAddress }
                })

            foreach ($lb in $publicLbs) {
                foreach ($feIp in ($lb.FrontendIpConfigurations | Where-Object { $_.PublicIpAddress })) {
                    $pip = $allPublicIps | Where-Object { $_.Id -eq $feIp.PublicIpAddress.Id }
                    $publicAddr = if ($pip -and $pip.IpAddress -ne "Not Assigned") { $pip.IpAddress } else { "$($lb.Name)-frontend" }

                    # Inbound NAT rules → exposed ports
                    $exposedPorts = @()
                    foreach ($rule in $lb.InboundNatRules) {
                        if ($rule.BackendPort) { $exposedPorts += "$($rule.Protocol)/$($rule.BackendPort)" }
                    }
                    foreach ($rule in $lb.LoadBalancingRules) {
                        if ($rule.BackendPort) { $exposedPorts += "$($rule.Protocol)/$($rule.BackendPort)" }
                    }
                    $portDisplay = if ($exposedPorts) { ($exposedPorts | Sort-Object -Unique) -join ", " } else { "All (health probe only)" }

                    # Backend VMs
                    $backendVmNames = @()
                    foreach ($pool in $lb.BackendAddressPools) {
                        foreach ($bAddr in $pool.BackendIpConfigurations) {
                            if ($bAddr.Id) {
                                $backendNicId = ($bAddr.Id -replace "/ipConfigurations/.*$", "")
                                $backendNicName = ($backendNicId -split "/")[-1]
                                $backendVmNames += $backendNicName
                            }
                        }
                    }

                    $criticality = "High"
                    $severity = if ($portDisplay -match "3389|22") { "Critical" } else { "High" }
                    $hasMgmtPort = $portDisplay -match "3389|22|5985|5986"

                    # DDoS (use LB's resource group VNet — best effort)
                    $lbVnetId = ""
                    $ddosStatus = "Unable to Assess"
                    try {
                        # Attempt to find VNet via backend pool subnet
                        foreach ($pool in $lb.BackendAddressPools) {
                            foreach ($bAddr in ($pool.BackendIpConfigurations | Select-Object -First 1)) {
                                if ($bAddr.Id -and $bAddr.Id -match "/subnets/") {
                                    $lbVnetId = ($bAddr.Id -replace "/subnets/[^/]+/.*$", "") -replace "/subnets/.*$", ""
                                    break
                                }
                            }
                            if ($lbVnetId) { break }
                        }
                        if ($lbVnetId) { $ddosStatus = Get-DDoSStatus -VNetId $lbVnetId }
                    }
                    catch {}

                    $activeControls = @()
                    $missingControls = @()
                    if ($ddosStatus -eq "Yes") { $activeControls += "DDoS-Std" } else { $missingControls += "DDoS-Std" }
                    if (-not $FastMode -and $defenderServersEnabled) { $activeControls += "Defender-Servers" }
                    elseif (-not $FastMode) { $missingControls += "Defender-Servers" }

                    $backendNote = if ($backendVmNames) { " (Backend: $($backendVmNames[0..2] -join ', ')$(if ($backendVmNames.Count -gt 3) {', ...'}))" } else { "" }

                    $finding = New-ExposureFinding `
                        -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -ResourceName "$($lb.Name)$backendNote" -ResourceType "LoadBalancer" `
                        -ResourceGroup $lb.ResourceGroupName -Region $lb.Location `
                        -PublicEndpoint $publicAddr -ExposureType "LB-PublicFrontend" `
                        -ExposedPorts $portDisplay `
                        -SecurityControls ($activeControls -join ", ") `
                        -MissingControls ($missingControls -join ", ") `
                        -Severity $severity -BusinessCriticality $criticality `
                        -BusinessImpact (Get-BusinessImpact -Severity $severity -ResourceType "LoadBalancer" -ExposedPorts $portDisplay) `
                        -Recommendation (Get-LBRecommendation -Severity $severity -HasMgmtPort $hasMgmtPort) `
                        -DDoSProtected $ddosStatus

                    $allFindings += $finding
                    $subExposedCount++
                }
            }

            # ─────────────────────────────────────────────────────────────────────
            # ASSESSMENT MODULE 2: APPLICATION GATEWAY
            # ─────────────────────────────────────────────────────────────────────
            foreach ($agw in $allAppGws) {
                $pip = $allPublicIps | Where-Object { $_.Id -eq ($agw.FrontendIPConfigurations | Where-Object { $_.PublicIPAddress } | Select-Object -First 1 | ForEach-Object { $_.PublicIPAddress.Id }) }
                $pubAddr = if ($pip -and $pip.IpAddress -ne "Not Assigned") { $pip.IpAddress } else { "$($agw.Name)-frontend" }

                # WAF check
                $wafEnabled = $agw.WebApplicationFirewallConfiguration -and $agw.WebApplicationFirewallConfiguration.Enabled
                $wafMode = if ($wafEnabled) { $agw.WebApplicationFirewallConfiguration.FirewallMode } else { "Disabled" }
                $tlsMinProto = $agw.SslPolicy.MinProtocolVersion

                $activeControls = @()
                $missingControls = @()
                if ($wafEnabled -and $wafMode -eq "Prevention") { $activeControls += "WAF-Prevention" }
                elseif ($wafEnabled) { $activeControls += "WAF-Detection"; $missingControls += "WAF-Prevention" }
                else { $missingControls += "WAF" }
                if ($tlsMinProto -in @("TLSv1_2", "TLSv1_3")) { $activeControls += "TLS1.2+" }
                else { $missingControls += "TLS1.2+" }

                $criticality = Get-HeuristicCriticality -ResourceType "ApplicationGateway"
                $severity = if (-not $wafEnabled) { "High" }
                elseif ($wafMode -ne "Prevention") { "Medium" }
                else { "Low" }

                $tagCrit = Get-CriticalityFromTags -Tags $agw.Tags -TagName $CriticalityTagName
                if ($tagCrit -ne "Unknown") { $criticality = $tagCrit }

                # DDoS
                $agwVnetId = ""
                try {
                    $agwSubnetId = $agw.GatewayIPConfigurations[0].Subnet.Id
                    if ($agwSubnetId) { $agwVnetId = ($agwSubnetId -replace "/subnets/[^/]+$", "") }
                }
                catch {}
                $ddosStatus = Get-DDoSStatus -VNetId $agwVnetId

                $finding = New-ExposureFinding `
                    -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                    -ResourceName $agw.Name -ResourceType "ApplicationGateway" `
                    -ResourceGroup $agw.ResourceGroupName -Region $agw.Location `
                    -PublicEndpoint $pubAddr -ExposureType "AppGW-PublicFrontend" `
                    -ExposedPorts "HTTP/80, HTTPS/443 (listeners)" `
                    -SecurityControls ($activeControls -join ", ") `
                    -MissingControls ($missingControls -join ", ") `
                    -Severity $severity -BusinessCriticality $criticality `
                    -BusinessImpact (Get-BusinessImpact -Severity $severity -ResourceType "ApplicationGateway" -ExposedPorts "HTTP/HTTPS") `
                    -Recommendation (Get-AppGWRecommendation -WAFEnabled $wafEnabled -WAFMode $wafMode) `
                    -DDoSProtected $ddosStatus

                $allFindings += $finding
                $subExposedCount++
            }

            # ─────────────────────────────────────────────────────────────────────
            # ASSESSMENT MODULE 3: AKS CLUSTERS
            # ─────────────────────────────────────────────────────────────────────
            $aksClusters = @()
            try { $aksClusters = @(Get-AzAksCluster -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve AKS clusters for $($sub.Name): $_" }

            foreach ($aks in $aksClusters) {
                if (Test-ResourceExcluded -Tags $aks.Tags -ExcludeTagName $ExcludeTagName -ExcludeTagValue $ExcludeTagValue) {
                    $excludedFindings += New-ExposureFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -ResourceName $aks.Name -ResourceType "AKSCluster" -ResourceGroup $aks.ResourceGroupName `
                        -Region $aks.Location -PublicEndpoint "" -ExposureType "" -ExposedPorts "" `
                        -SecurityControls "" -MissingControls "" -Severity "" -BusinessCriticality "" `
                        -BusinessImpact "" -Recommendation "" -DDoSProtected "" -IsExcluded $true `
                        -ExclusionReason "$ExcludeTagName=$ExcludeTagValue"
                    $subExcludedCount++; continue
                }

                $apiAccess = Get-ObjProperty -Obj $aks -PropName 'ApiServerAccessProfile' -Default $null
                $isPrivate = Get-ObjProperty -Obj $apiAccess -PropName 'EnablePrivateCluster' -Default $false
                $authorisedIPs = @(Get-ObjProperty -Obj $apiAccess -PropName 'AuthorizedIPRanges' -Default @())
                $fqdn = Get-ObjProperty -Obj $aks -PropName 'Fqdn' -Default "$($aks.Name).api"

                $tagCrit = Get-CriticalityFromTags -Tags $aks.Tags -TagName $CriticalityTagName
                $criticality = if ($tagCrit -ne "Unknown") { $tagCrit } else { Get-HeuristicCriticality -ResourceType "AKSCluster" }

                if (-not $isPrivate) {
                    $activeControls = @()
                    $missingControls = @("Private-Cluster")
                    $hasIPRestrict = $authorisedIPs.Count -gt 0

                    if ($hasIPRestrict) { $activeControls += "Authorised-IP-Ranges" }
                    else { $missingControls += "Authorised-IP-Ranges" }

                    $severity = if (-not $hasIPRestrict) { "Critical" } else { "High" }

                    $ipNote = if ($hasIPRestrict) { " ($($authorisedIPs.Count) authorised IP range(s))" } else { " (no IP restrictions)" }

                    $finding = New-ExposureFinding `
                        -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -ResourceName $aks.Name -ResourceType "AKSCluster" `
                        -ResourceGroup $aks.ResourceGroupName -Region $aks.Location `
                        -PublicEndpoint "$fqdn$ipNote" -ExposureType "PublicAPIServer" `
                        -ExposedPorts "HTTPS/443 (Kubernetes API)" `
                        -SecurityControls ($activeControls -join ", ") `
                        -MissingControls ($missingControls -join ", ") `
                        -Severity $severity -BusinessCriticality $criticality `
                        -BusinessImpact (Get-BusinessImpact -Severity $severity -ResourceType "AKSCluster" -ExposedPorts "HTTPS/443") `
                        -Recommendation (Get-AKSRecommendation -HasIPRestrict $hasIPRestrict) `
                        -DDoSProtected "Unable to Assess"

                    $allFindings += $finding
                    $subExposedCount++
                }
            }

            # ─────────────────────────────────────────────────────────────────────
            # ASSESSMENT MODULE 4: APP SERVICE / FUNCTION APPS
            # ─────────────────────────────────────────────────────────────────────
            $webApps = @()
            try { $webApps = @(Get-AzWebApp -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve App Services for $($sub.Name): $_" }

            foreach ($app in $webApps) {
                if (Test-ResourceExcluded -Tags $app.Tags -ExcludeTagName $ExcludeTagName -ExcludeTagValue $ExcludeTagValue) {
                    $excludedFindings += New-ExposureFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -ResourceName $app.Name -ResourceType "AppService" -ResourceGroup $app.ResourceGroup `
                        -Region $app.Location -PublicEndpoint "" -ExposureType "" -ExposedPorts "" `
                        -SecurityControls "" -MissingControls "" -Severity "" -BusinessCriticality "" `
                        -BusinessImpact "" -Recommendation "" -DDoSProtected "" -IsExcluded $true `
                        -ExclusionReason "$ExcludeTagName=$ExcludeTagValue"
                    $subExcludedCount++; continue
                }

                $resType = if ($app.Kind -like "*functionapp*") { "FunctionApp" } else { "AppService" }
                $defaultUrl = "https://$($app.DefaultHostName)"

                # Access restrictions
                $restrictionRules = @()
                try {
                    $appConfig = Get-AzWebAppConfiguration -ResourceGroupName $app.ResourceGroup -Name $app.Name -ErrorAction Stop
                    $restrictionRules = @($appConfig.IpSecurityRestrictions | Where-Object { $_.Action -eq "Allow" -and $_.IpAddress -ne "Any" })
                }
                catch {}

                $hasRestrictions = $restrictionRules.Count -gt 0
                $hasVnetInteg = -not [string]::IsNullOrWhiteSpace($app.VirtualNetworkSubnetId)
                $httpsOnly = $app.HttpsOnly

                $activeControls = @()
                $missingControls = @()
                if ($hasRestrictions) { $activeControls += "IP-Restrictions" } else { $missingControls += "IP-Restrictions" }
                if ($hasVnetInteg) { $activeControls += "VNet-Integration" } else { $missingControls += "VNet-Integration" }
                if ($httpsOnly) { $activeControls += "HTTPS-Only" }       else { $missingControls += "HTTPS-Only" }

                $tagCrit = Get-CriticalityFromTags -Tags $app.Tags -TagName $CriticalityTagName
                $criticality = if ($tagCrit -ne "Unknown") { $tagCrit } else { Get-HeuristicCriticality -ResourceType $resType }

                $severity = if (-not $hasRestrictions -and -not $hasVnetInteg -and $criticality -in @("Critical", "High")) { "High" }
                elseif (-not $hasRestrictions -and -not $hasVnetInteg) { "Medium" }
                elseif (-not $hasRestrictions) { "Medium" }
                else { "Low" }

                $finding = New-ExposureFinding `
                    -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                    -ResourceName $app.Name -ResourceType $resType `
                    -ResourceGroup $app.ResourceGroup -Region $app.Location `
                    -PublicEndpoint $defaultUrl -ExposureType "PublicEndpoint" `
                    -ExposedPorts "HTTP/80, HTTPS/443" `
                    -SecurityControls ($activeControls -join ", ") `
                    -MissingControls ($missingControls -join ", ") `
                    -Severity $severity -BusinessCriticality $criticality `
                    -BusinessImpact (Get-BusinessImpact -Severity $severity -ResourceType $resType -ExposedPorts "HTTP/HTTPS") `
                    -Recommendation (Get-AppServiceRecommendation -HasRestrictions $hasRestrictions -HasVNetInteg $hasVnetInteg -HttpsOnly $httpsOnly) `
                    -DDoSProtected "N/A (PaaS managed)"

                $allFindings += $finding
                $subExposedCount++
            }

            # ─────────────────────────────────────────────────────────────────────
            # ASSESSMENT MODULE 5: AZURE SQL SERVERS
            # ─────────────────────────────────────────────────────────────────────
            $sqlServers = @()
            try { $sqlServers = @(Get-AzSqlServer -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve SQL Servers for $($sub.Name): $_" }

            foreach ($sql in $sqlServers) {
                if (Test-ResourceExcluded -Tags $sql.Tags -ExcludeTagName $ExcludeTagName -ExcludeTagValue $ExcludeTagValue) {
                    $excludedFindings += New-ExposureFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -ResourceName $sql.ServerName -ResourceType "SQLServer" -ResourceGroup $sql.ResourceGroupName `
                        -Region $sql.Location -PublicEndpoint "" -ExposureType "" -ExposedPorts "" `
                        -SecurityControls "" -MissingControls "" -Severity "" -BusinessCriticality "" `
                        -BusinessImpact "" -Recommendation "" -DDoSProtected "" -IsExcluded $true `
                        -ExclusionReason "$ExcludeTagName=$ExcludeTagValue"
                    $subExcludedCount++; continue
                }

                if ($sql.PublicNetworkAccess -eq "Disabled") { continue }

                # Firewall rules
                $fwRules = @()
                try { $fwRules = @(Get-AzSqlServerFirewallRule -ServerName $sql.ServerName -ResourceGroupName $sql.ResourceGroupName -ErrorAction Stop) }
                catch {}

                $allowsAzureServices = $fwRules | Where-Object { $_.FirewallRuleName -eq "AllowAllWindowsAzureIps" -and $_.StartIpAddress -eq "0.0.0.0" }
                $broadRules = $fwRules | Where-Object {
                    $_.StartIpAddress -and $_.EndIpAddress -and
                    $_.StartIpAddress -ne $_.EndIpAddress -and
                    $_.StartIpAddress -ne "0.0.0.0"
                }
                $openRules = $fwRules | Where-Object { $_.StartIpAddress -eq "0.0.0.0" -and $_.EndIpAddress -eq "255.255.255.255" }

                $activeControls = @()
                $missingControls = @()
                if ($fwRules.Count -gt 0) { $activeControls += "SQL-Firewall-Rules" } else { $missingControls += "SQL-Firewall-Rules" }
                if ($allowsAzureServices) { $missingControls += "Disable-Azure-Services-Rule" }

                $tagCrit = Get-CriticalityFromTags -Tags $sql.Tags -TagName $CriticalityTagName
                $criticality = if ($tagCrit -ne "Unknown") { $tagCrit } else { Get-HeuristicCriticality -ResourceType "SQLServer" }

                $severity = if ($openRules) { "Critical" }
                elseif ($allowsAzureServices) { "High" }
                elseif ($broadRules) { "Medium" }
                elseif ($fwRules.Count -eq 0) { "Critical" }
                else { "Low" }

                $fwNote = "Rules: $($fwRules.Count)"
                if ($openRules) { $fwNote += " (OPEN 0.0.0.0-255.255.255.255)" }
                if ($allowsAzureServices) { $fwNote += " (Allow Azure Services)" }

                $finding = New-ExposureFinding `
                    -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                    -ResourceName $sql.ServerName -ResourceType "SQLServer" `
                    -ResourceGroup $sql.ResourceGroupName -Region $sql.Location `
                    -PublicEndpoint "$($sql.FullyQualifiedDomainName):1433" `
                    -ExposureType "PublicEndpoint" -ExposedPorts "SQL/1433 — $fwNote" `
                    -SecurityControls ($activeControls -join ", ") `
                    -MissingControls ($missingControls -join ", ") `
                    -Severity $severity -BusinessCriticality $criticality `
                    -BusinessImpact (Get-BusinessImpact -Severity $severity -ResourceType "SQLServer" -ExposedPorts "SQL/1433") `
                    -Recommendation (Get-SQLRecommendation -OpenRules ([bool]$openRules) -AllowAzureServices ([bool]$allowsAzureServices) -BroadRules ([bool]$broadRules)) `
                    -DDoSProtected "N/A (PaaS managed)"

                $allFindings += $finding
                $subExposedCount++
            }

            # ─────────────────────────────────────────────────────────────────────
            # ASSESSMENT MODULE 6: STORAGE ACCOUNTS
            # ─────────────────────────────────────────────────────────────────────
            $storageAccounts = @()
            try { $storageAccounts = @(Get-AzStorageAccount -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve Storage Accounts for $($sub.Name): $_" }

            foreach ($sa in $storageAccounts) {
                if (Test-ResourceExcluded -Tags $sa.Tags -ExcludeTagName $ExcludeTagName -ExcludeTagValue $ExcludeTagValue) {
                    $excludedFindings += New-ExposureFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -ResourceName $sa.StorageAccountName -ResourceType "StorageAccount" -ResourceGroup $sa.ResourceGroupName `
                        -Region $sa.Location -PublicEndpoint "" -ExposureType "" -ExposedPorts "" `
                        -SecurityControls "" -MissingControls "" -Severity "" -BusinessCriticality "" `
                        -BusinessImpact "" -Recommendation "" -DDoSProtected "" -IsExcluded $true `
                        -ExclusionReason "$ExcludeTagName=$ExcludeTagValue"
                    $subExcludedCount++; continue
                }

                $publicNetAccess = $sa.PublicNetworkAccess
                $networkRuleSet = $sa.NetworkRuleSet
                $defaultAction = if ($networkRuleSet) { $networkRuleSet.DefaultAction } else { "Allow" }
                $allowBlob = $sa.AllowBlobPublicAccess
                $httpsOnly = $sa.EnableHttpsTrafficOnly

                # Skip if fully locked down
                if ($publicNetAccess -eq "Disabled") { continue }

                $isOpen = ($defaultAction -eq "Allow")
                $isBlobOpen = ($allowBlob -eq $true)

                $activeControls = @()
                $missingControls = @()
                if (-not $isOpen) { $activeControls += "Network-ACL" } else { $missingControls += "Network-ACL" }
                if (-not $isBlobOpen) { $activeControls += "BlobPublicAccess-Disabled" } else { $missingControls += "BlobPublicAccess-Disabled" }
                if ($httpsOnly) { $activeControls += "HTTPS-Only" } else { $missingControls += "HTTPS-Only" }

                $tagCrit = Get-CriticalityFromTags -Tags $sa.Tags -TagName $CriticalityTagName
                $criticality = if ($tagCrit -ne "Unknown") { $tagCrit } else { Get-HeuristicCriticality -ResourceType "StorageAccount" }

                $severity = if ($isOpen -and $isBlobOpen) { "Critical" }
                elseif ($isOpen) { "High" }
                elseif ($isBlobOpen) { "Medium" }
                else { "Low" }

                $endpoint = "https://$($sa.StorageAccountName).blob.core.windows.net"
                $portNote = "HTTPS/443 (blob"
                if ($isOpen) { $portNote += ", open ACL" }
                if ($isBlobOpen) { $portNote += ", public container access" }
                $portNote += ")"

                $finding = New-ExposureFinding `
                    -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                    -ResourceName $sa.StorageAccountName -ResourceType "StorageAccount" `
                    -ResourceGroup $sa.ResourceGroupName -Region $sa.Location `
                    -PublicEndpoint $endpoint -ExposureType "PublicEndpoint" `
                    -ExposedPorts $portNote `
                    -SecurityControls ($activeControls -join ", ") `
                    -MissingControls ($missingControls -join ", ") `
                    -Severity $severity -BusinessCriticality $criticality `
                    -BusinessImpact (Get-BusinessImpact -Severity $severity -ResourceType "StorageAccount" -ExposedPorts "HTTPS/443") `
                    -Recommendation (Get-StorageRecommendation -IsOpen $isOpen -IsBlobOpen $isBlobOpen -HttpsOnly $httpsOnly) `
                    -DDoSProtected "N/A (PaaS managed)"

                $allFindings += $finding
                $subExposedCount++
            }

            # ─────────────────────────────────────────────────────────────────────
            # ASSESSMENT MODULE 7: API MANAGEMENT
            # ─────────────────────────────────────────────────────────────────────
            $apimInstances = @()
            try { $apimInstances = @(Get-AzApiManagement -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve API Management for $($sub.Name): $_" }

            foreach ($apim in $apimInstances) {
                if (Test-ResourceExcluded -Tags $apim.Tags -ExcludeTagName $ExcludeTagName -ExcludeTagValue $ExcludeTagValue) {
                    $excludedFindings += New-ExposureFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -ResourceName $apim.Name -ResourceType "APIManagement" -ResourceGroup $apim.ResourceGroupName `
                        -Region $apim.Location -PublicEndpoint "" -ExposureType "" -ExposedPorts "" `
                        -SecurityControls "" -MissingControls "" -Severity "" -BusinessCriticality "" `
                        -BusinessImpact "" -Recommendation "" -DDoSProtected "" -IsExcluded $true `
                        -ExclusionReason "$ExcludeTagName=$ExcludeTagValue"
                    $subExcludedCount++; continue
                }

                $networkType = Get-ObjProperty -Obj $apim -PropName 'VpnType' -Default "None"
                if ($networkType -eq "Internal") { continue }  # Internal only — not internet-exposed

                $gatewayUrl = Get-ObjProperty -Obj $apim -PropName 'GatewayUrl' -Default "$($apim.Name).azure-api.net"
                $publicIpId = Get-ObjProperty -Obj $apim -PropName 'PublicIpAddressId' -Default ""
                $pip = if ($publicIpId) { $allPublicIps | Where-Object { $_.Id -eq $publicIpId } } else { $null }
                $pubAddr = if ($pip -and $pip.IpAddress -ne "Not Assigned") { "$($pip.IpAddress) ($gatewayUrl)" } else { $gatewayUrl }

                $activeControls = @()
                $missingControls = @()
                if ($networkType -eq "External") { $activeControls += "VNet-External" }
                else { $missingControls += "VNet-Integration" }

                # Check for custom policies / auth — best effort from known properties
                $tagCrit = Get-CriticalityFromTags -Tags $apim.Tags -TagName $CriticalityTagName
                $criticality = if ($tagCrit -ne "Unknown") { $tagCrit } else { Get-HeuristicCriticality -ResourceType "APIManagement" }
                $severity = if ($networkType -eq "None") { "Medium" } else { "Low" }

                $finding = New-ExposureFinding `
                    -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                    -ResourceName $apim.Name -ResourceType "APIManagement" `
                    -ResourceGroup $apim.ResourceGroupName -Region $apim.Location `
                    -PublicEndpoint $pubAddr -ExposureType "PublicEndpoint" `
                    -ExposedPorts "HTTP/80, HTTPS/443 (API Gateway)" `
                    -SecurityControls ($activeControls -join ", ") `
                    -MissingControls ($missingControls -join ", ") `
                    -Severity $severity -BusinessCriticality $criticality `
                    -BusinessImpact (Get-BusinessImpact -Severity $severity -ResourceType "APIManagement" -ExposedPorts "HTTP/HTTPS") `
                    -Recommendation "Deploy APIM in External VNet mode to restrict management plane access. Enforce subscription keys, OAuth 2.0, or mutual TLS on all APIs. Enable APIM developer portal IP restrictions. Place Azure Front Door or Application Gateway with WAF in front of the APIM gateway for DDoS and OWASP protection." `
                    -DDoSProtected "Unable to Assess"

                $allFindings += $finding
                $subExposedCount++
            }

            # ─────────────────────────────────────────────────────────────────────
            # ASSESSMENT MODULE 8: AZURE CONTAINER REGISTRY
            # ─────────────────────────────────────────────────────────────────────
            $acrs = @()
            try { $acrs = @(Get-AzContainerRegistry -ErrorAction Stop) }
            catch { Write-Verbose "  Could not retrieve ACRs for $($sub.Name): $_" }

            foreach ($acr in $acrs) {
                if (Test-ResourceExcluded -Tags $acr.Tags -ExcludeTagName $ExcludeTagName -ExcludeTagValue $ExcludeTagValue) {
                    $excludedFindings += New-ExposureFinding -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                        -ResourceName $acr.Name -ResourceType "ContainerRegistry" -ResourceGroup $acr.ResourceGroupName `
                        -Region $acr.Location -PublicEndpoint "" -ExposureType "" -ExposedPorts "" `
                        -SecurityControls "" -MissingControls "" -Severity "" -BusinessCriticality "" `
                        -BusinessImpact "" -Recommendation "" -DDoSProtected "" -IsExcluded $true `
                        -ExclusionReason "$ExcludeTagName=$ExcludeTagValue"
                    $subExcludedCount++; continue
                }

                if ($acr.PublicNetworkAccess -eq "Disabled") { continue }

                $networkRuleSet = Get-ObjProperty -Obj $acr -PropName 'NetworkRuleSet' -Default $null
                $defaultAction = if ($networkRuleSet) { Get-ObjProperty -Obj $networkRuleSet -PropName 'DefaultAction' -Default "Allow" } else { "Allow" }
                $isOpen = ($defaultAction -eq "Allow")

                $tagCrit = Get-CriticalityFromTags -Tags $acr.Tags -TagName $CriticalityTagName
                $criticality = if ($tagCrit -ne "Unknown") { $tagCrit } else { Get-HeuristicCriticality -ResourceType "ContainerRegistry" }
                $severity = if ($isOpen) { "High" } else { "Medium" }

                $activeControls = if (-not $isOpen) { @("Network-ACL") } else { @() }
                $missingControls = if ($isOpen) { @("Network-ACL") } else { @() }

                $finding = New-ExposureFinding `
                    -SubscriptionName $sub.Name -SubscriptionId $sub.Id `
                    -ResourceName $acr.Name -ResourceType "ContainerRegistry" `
                    -ResourceGroup $acr.ResourceGroupName -Region $acr.Location `
                    -PublicEndpoint "$($acr.Name).azurecr.io" -ExposureType "PublicEndpoint" `
                    -ExposedPorts "HTTPS/443 (registry API)" `
                    -SecurityControls ($activeControls -join ", ") `
                    -MissingControls ($missingControls -join ", ") `
                    -Severity $severity -BusinessCriticality $criticality `
                    -BusinessImpact (Get-BusinessImpact -Severity $severity -ResourceType "ContainerRegistry" -ExposedPorts "HTTPS/443") `
                    -Recommendation "Restrict ACR public network access with IP network rules scoped to CI/CD agent IPs and known deployment subnets. Deploy a Private Endpoint for ACR and disable public access entirely for production registries. Enable Azure Defender for container registries to scan pushed images for vulnerabilities." `
                    -DDoSProtected "N/A (PaaS managed)"

                $allFindings += $finding
                $subExposedCount++
            }

            # ── Per-subscription result ───────────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Exposed: $subExposedCount  Excluded: $subExcludedCount" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Exposed: $subExposedCount  Excluded: $subExcludedCount"
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
        if ($serviceTypeDist.ContainsKey($f.ResourceType)) { $serviceTypeDist[$f.ResourceType]++ }
        else { $serviceTypeDist[$f.ResourceType] = 1 }
    }

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Total Exposed Resources"     = $allFindings.Count
            "Critical"                    = $severityDist["Critical"]
            "High"                        = $severityDist["High"]
            "Medium"                      = $severityDist["Medium"]
            "Low"                         = $severityDist["Low"]
            "Informational"               = $severityDist["Informational"]
            "Excluded Resources"          = $excludedFindings.Count
            "Assessment Mode"             = if ($FastMode) { "FastMode" } else { "Full Assessment" }
            "Execution Time"              = $duration
        })

    Write-SeverityBreakdown -Dist $severityDist

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0 -or $excludedFindings.Count -gt 0) {
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
                $allFindings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
                if ($excludedFindings.Count -gt 0) {
                    $exclCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "Exclusions.csv"
                    $excludedFindings | Export-Csv -Path $exclCsvPath -NoTypeInformation -Encoding UTF8
                }
                $csvExported = $true
            }
            catch { Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red }
        }

        try {
            $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
            $sessionInfo = @{ Tenant = $ctx.Tenant.Id; Account = $ctx.Account.Id; Environment = $ctx.Environment.Name }
            $scanParams = @{
                Scope              = "$scopeText ($subCount found)"
                ExportEnabled      = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime           = $duration
                CriticalityTagName = $CriticalityTagName
                ExcludeTag         = if ($ExcludeTagName) { "$ExcludeTagName=$ExcludeTagValue" } else { "Not configured" }
            }
            $htmlContent = Generate-InternetExposureHtml `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParams `
                -Findings            $allFindings `
                -ExcludedFindings    $excludedFindings `
                -SeverityDist        $severityDist `
                -ServiceTypeDist     $serviceTypeDist `
                -SubscriptionResults $subscriptionResults `
                -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -FastMode            $FastMode.IsPresent

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch { Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red }

        try {
            $allFindings | Select-Object SubscriptionName, ResourceName, ResourceType, PublicEndpoint,
            ExposureType, ExposedPorts, Severity, BusinessCriticality, MissingControls, DDoSProtected |
            Out-GridView -Title "Azure Internet Exposure Risk Assessment"
            $gridViewOpened = $true
        }
        catch { Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow }
    }
    else {
        Write-Host ""
        Write-Host "  ✓ No internet-exposed resources identified in the targeted subscriptions." -ForegroundColor Green
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        $outputCsvPath = if ($csvExported) { $CsvPath } else { $null }
        $outputHtmlPath = if ($htmlExported) { $htmlPath } else { $null }

        Write-OutputFiles `
            -CsvPath $outputCsvPath `
            -HtmlPath $outputHtmlPath `
            -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}


#------------------------------------------------------------------------ [ Recommendation Builders ]

Function Get-VMRecommendation {
    param([string]$Severity, $NSGExposure, [bool]$Bastion, [string]$JIT)
    if ($NSGExposure.IsPermissive) {
        return "URGENT: Remove any/any inbound internet Allow rules from the NSG. Restrict inbound access to specific source IPs and required ports only. Deploy Azure Bastion for RDP/SSH access and enable JIT VM access via Defender for Cloud to eliminate standing management port exposure."
    }
    if ($NSGExposure.Ports -match "3389|22") {
        return "Remove direct RDP/SSH internet exposure immediately. Deploy Azure Bastion in the VNet for browser-based management access without a public IP. Enable JIT VM access in Defender for Cloud to create time-limited, IP-restricted access windows. Update NSG to deny all inbound management traffic from Internet."
    }
    if (-not $Bastion) {
        return "Deploy Azure Bastion in the VNet to provide secure, agentless RDP/SSH without requiring a public IP or open management ports. Remove the VM's public IP once Bastion is operational. Confirm NSG rules are scoped to minimum required inbound traffic only."
    }
    return "Review and minimise NSG inbound rules. Verify public IP is required (vs. using Load Balancer or Application Gateway). Enable Defender for Servers for endpoint detection. Ensure DDoS Protection Standard is enabled on the VNet."
}

Function Get-LBRecommendation {
    param([string]$Severity, [bool]$HasMgmtPort)
    if ($HasMgmtPort) {
        return "URGENT: Load Balancer is exposing management ports (RDP/SSH) to the internet. Remove NAT rules for management ports. Deploy Azure Bastion for management access. Use JIT VM access via Defender for Cloud for time-limited, IP-restricted management access."
    }
    return "Review Load Balancer inbound NAT and load balancing rules. Restrict source addresses to known client IP ranges where possible. Enable DDoS Protection Standard on the VNet. Consider placing an Application Gateway with WAF in front of web workloads behind this Load Balancer."
}

Function Get-AppGWRecommendation {
    param([bool]$WAFEnabled, [string]$WAFMode)
    if (-not $WAFEnabled) {
        return "Enable Web Application Firewall (WAF v2) on the Application Gateway in Prevention mode. Apply OWASP Core Rule Set 3.2+. Enable bot protection. Integrate with Microsoft Sentinel for WAF alert correlation. Enable DDoS Protection Standard on the Application Gateway VNet."
    }
    if ($WAFMode -ne "Prevention") {
        return "Switch WAF from Detection to Prevention mode after validating rule baselines. Tune exclusions for false positives rather than keeping WAF in passive mode. Enable custom WAF rules for application-specific threats. Review WAF logs in Azure Monitor."
    }
    return "WAF is active in Prevention mode — good posture. Continue to review WAF rule exclusions quarterly. Enable Diagnostic Settings to route WAF logs to Log Analytics. Validate TLS minimum version is 1.2 or higher."
}

Function Get-AKSRecommendation {
    param([bool]$HasIPRestrict)
    if (-not $HasIPRestrict) {
        return "URGENT: AKS API server is internet-exposed with no IP restrictions. Immediately configure Authorised IP Ranges to restrict API server access to known management IPs (VPN, jump host, CI/CD agents). Plan migration to a Private Cluster (requires cluster recreation). Enable Kubernetes RBAC and Azure AD integration to ensure authentication controls exist."
    }
    return "Configure authorised IP ranges for AKS API server access and plan migration to Private Cluster for long-term isolation. Ensure authorised ranges do not include overly broad CIDRs. Enable Microsoft Defender for Containers. Implement network policies to control pod-to-pod traffic."
}

Function Get-AppServiceRecommendation {
    param([bool]$HasRestrictions, [bool]$HasVNetInteg, [bool]$HttpsOnly)
    if (-not $HasRestrictions -and -not $HasVNetInteg) {
        return "Configure Access Restriction rules on the App Service to allow only required source IPs or deploy VNet Integration to route traffic through the private network. Place an Application Gateway with WAF or Azure Front Door with WAF in front of public-facing App Services. Enforce HTTPS-only to eliminate HTTP access."
    }
    if (-not $HttpsOnly) {
        return "Enable HTTPS-only on the App Service to enforce encrypted transport. Review existing Access Restriction rules for overly broad source IP ranges. Consider VNet Integration for backend services that do not require public internet access."
    }
    return "Good base controls in place. Review Access Restriction rules for IP drift. Consider deploying a Private Endpoint for App Services that serve internal workloads. Enable Defender for App Service for runtime threat detection."
}

Function Get-SQLRecommendation {
    param([bool]$OpenRules, [bool]$AllowAzureServices, [bool]$BroadRules)
    if ($OpenRules) {
        return "CRITICAL: SQL Server firewall has an open rule (0.0.0.0 - 255.255.255.255) allowing connections from any internet source. Remove this rule immediately. Replace with specific IP rules scoped to known application and management IPs. Enable Azure AD authentication and disable SQL authentication where possible."
    }
    if ($AllowAzureServices) {
        return "Remove the 'Allow Azure Services' firewall rule (0.0.0.0/0.0.0.0) as it allows any Azure-hosted service — including from other tenants — to connect. Replace with specific Virtual Network Rules using service endpoints or deploy a Private Endpoint and disable public network access entirely."
    }
    if ($BroadRules) {
        return "Tighten SQL Server firewall rules to specific IP addresses rather than broad ranges. Deploy a Private Endpoint for SQL and disable public network access for workloads that access SQL from Azure-only. Enable Microsoft Defender for SQL for threat detection and audit logging."
    }
    return "Enable Private Endpoint for SQL Server, disable public network access, and migrate application connection strings to the private endpoint FQDN. Enable Transparent Data Encryption, Microsoft Defender for SQL, and SQL Audit logging to a storage account or Log Analytics."
}

Function Get-StorageRecommendation {
    param([bool]$IsOpen, [bool]$IsBlobOpen, [bool]$HttpsOnly)
    if ($IsOpen -and $IsBlobOpen) {
        return "CRITICAL: Storage account has open network ACLs (default Allow) AND public blob container access enabled. Disable public blob access immediately. Restrict network access to specific VNets and IP ranges. Deploy a Private Endpoint for blob/file access from Azure workloads. Enable soft delete and versioning to protect against data destruction."
    }
    if ($IsOpen) {
        return "Restrict network ACL default action to Deny and add explicit VNet subnet rules and IP rules for required access. Deploy a Private Endpoint for storage access from Azure compute. Audit storage access logs via Azure Monitor to identify unexpected access patterns."
    }
    if ($IsBlobOpen) {
        return "Disable public blob container access at the storage account level — this overrides any individual container settings. Ensure applications use SAS tokens or managed identity authentication rather than anonymous blob access. Audit all containers for anonymous access currently in use."
    }
    return "Enable HTTPS-only traffic enforcement. Review network ACL rules for IP drift and VNet rule hygiene. Enable Azure Defender for Storage for anomaly detection and malware scanning of uploaded blobs."
}
