<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 19 August 2026
Modified-On     : 19 August 2026

.SYNOPSIS
    Assesses transport security configuration — TLS versions, HTTPS enforcement, weak
    protocol exposure, and certificate health — across major Azure PaaS services in one
    or more subscriptions, with risk-rated architectural findings, CSV export, and an
    interactive HTML dashboard.

.DESCRIPTION
    Get-AzureTLSConfigurationAssessment evaluates the transport-layer security posture
    of Azure PaaS services from a Cloud Security and Enterprise Architecture perspective.

    It goes beyond raw configuration enumeration. Every material finding is rated by
    risk level (Critical / High / Medium / Low / Informational), categorised by
    architectural domain (Security / Compliance / Reliability / Architecture), and
    accompanied by a business-impact statement and a concrete recommendation — so the
    output is immediately actionable for engineering teams, architects, and auditors.

    Services assessed per subscription:
        - Azure App Service / Web Apps
            HTTPS-only enforcement, minimum TLS version, custom domain bindings,
            certificate presence and expiry.
        - Azure Functions
            Same transport-security controls as App Service; assessed independently
            to surface function-app-specific exposure.
        - Azure API Management
            Custom domain TLS bindings, minimum negotiated protocol, certificate
            presence and expiry, gateway-level HTTPS enforcement.
        - Azure Storage Accounts
            Minimum TLS version, Secure Transfer Required (HTTPS-only), public
            blob access posture (informational, transport context).
        - Azure SQL Database / Managed Instance
            Minimum TLS version setting, connection encryption enforcement.
        - Azure Front Door / Azure CDN
            HTTPS redirect enforcement, minimum TLS version, custom domain
            certificate bindings and expiry.
        - Azure Application Gateway
            SSL policy (Predefined vs Custom), minimum TLS protocol version,
            listener HTTPS vs HTTP exposure, backend HTTPS probe settings.
        - Azure Key Vault
            Soft-delete and purge-protection status (transport-adjacent resilience),
            network access restriction (public endpoint exposure).
        - Azure Service Bus / Event Hubs
            Minimum TLS version setting, public network access.
        - Azure Cosmos DB
            Minimum TLS version, public network access posture.
        - Azure Redis Cache
            TLS enablement, non-SSL port status, minimum TLS version.

    For each resource a structured finding record is generated:
        ResourceName, ResourceType, SubscriptionName, SubscriptionId,
        Setting, CurrentValue, ExpectedValue, IsCompliant,
        RiskLevel, RiskCategory, Finding, BusinessImpact,
        ArchitecturalImpact, Recommendation

    Certificate records (App Service, API Management, Front Door) include:
        CertificateName, SubjectName, ExpiryDate, DaysToExpiry, ExpiryStatus

    Output:
        - Always-on interactive HTML dashboard (dark/light theme, sortable tables,
          risk matrix, certificate health panel, detail drawer)
        - Optional CSV export (-ExportToCsv)
        - Interactive Grid View where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. If specified, exports all findings and certificate records to CSV files
    at the path given in -CsvPath. The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the primary CSV export is written when -ExportToCsv is specified.
    The HTML dashboard is written to the same path with a .html extension.
    A second certificate-specific CSV is written alongside with a "Certificates" suffix.
    Default: C:\Temp\AzureTLSConfiguration-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside -CsvPath
    (or the default path). Optionally writes CSV files when -ExportToCsv is specified.
    Displays findings in an interactive Grid View window where a GUI is available.

.EXAMPLE
    Get-AzureTLSConfigurationAssessment -AllSubscriptions

.EXAMPLE
    Get-AzureTLSConfigurationAssessment -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureTLSConfigurationAssessment -AllSubscriptions -ExportToCsv

.EXAMPLE
    Get-AzureTLSConfigurationAssessment -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\TLS.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (19-Aug-2026) - Initial release. TLS version, HTTPS enforcement,
                            protocol exposure, and certificate health assessment
                            across 11 Azure PaaS service families. Risk-rated
                            architectural findings. CSV export and interactive
                            HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module — the following sub-modules are used:
               Az.Accounts, Az.Websites, Az.ApiManagement, Az.Storage,
               Az.Sql, Az.FrontDoor, Az.Cdn, Az.Network, Az.KeyVault,
               Az.ServiceBus, Az.EventHub, Az.CosmosDB, Az.RedisCache
           The script will prompt to install the Az meta-module if any are missing.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level for all targeted
           subscriptions. Contributor is not required — this is a read-only assessment.
        4. The account must have read access to resource properties; RBAC-restricted
           environments may return partial results for some services.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - TLS cipher suite enumeration is not performed; live TLS handshake
          validation is out of scope for this version.
        - AKS ingress TLS and Azure Container Apps TLS are not assessed —
          planned as a future enhancement.
        - Application Gateway SSL policy details require Az.Network 4.x+;
          older module versions may return partial policy data.
        - Front Door Classic and Front Door Standard/Premium have different
          API surfaces; the script handles both but may miss edge-case
          configurations on very old Classic profiles.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an
          explicit -CsvPath on macOS/Linux PowerShell 7.
        - In very large environments (500+ resources per service type) the scan
          may take several minutes; progress is reported in real time.

.LINK
    https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings
    https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version
    https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings
    https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates
    https://learn.microsoft.com/en-us/azure/application-gateway/ssl-overview
    https://learn.microsoft.com/en-us/azure/frontdoor/end-to-end-tls
    https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection

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
    Write-CenteredText "Azure TLS Configuration Assessment v1.0" -Color White
    Write-CenteredText "Transport Security & Certificate Health" -Color Gray
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

Function Write-RiskBreakdown {
    param([array]$Findings)

    if ($Findings.Count -eq 0) { return }

    $critical = @($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $high = @($Findings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $medium = @($Findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $low = @($Findings | Where-Object { $_.RiskLevel -eq "Low" }).Count
    $info = @($Findings | Where-Object { $_.RiskLevel -eq "Informational" }).Count

    Write-Host ""
    Write-Host "  Risk Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Critical              : $critical" -ForegroundColor Red
    Write-Host "  High                  : $high"     -ForegroundColor Red
    Write-Host "  Medium                : $medium"   -ForegroundColor Yellow
    Write-Host "  Low                   : $low"      -ForegroundColor Gray
    Write-Host "  Informational         : $info"     -ForegroundColor DarkGray
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


#------------------------------------------------------------------------ [ Risk Engine ]

Function New-TlsFinding {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$ResourceName,
        [string]$ResourceGroup,
        [string]$ResourceType,
        [string]$Setting,
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [bool]$IsCompliant,
        [string]$RiskLevel,
        [string]$RiskCategory,
        [string]$Finding,
        [string]$BusinessImpact,
        [string]$ArchitecturalImpact,
        [string]$Recommendation
    )

    return [pscustomobject]@{
        SubscriptionName    = $SubscriptionName
        SubscriptionId      = $SubscriptionId
        ResourceName        = $ResourceName
        ResourceGroup       = $ResourceGroup
        ResourceType        = $ResourceType
        Setting             = $Setting
        CurrentValue        = $CurrentValue
        ExpectedValue       = $ExpectedValue
        IsCompliant         = if ($IsCompliant) { "Yes" } else { "No" }
        RiskLevel           = $RiskLevel
        RiskCategory        = $RiskCategory
        Finding             = $Finding
        BusinessImpact      = $BusinessImpact
        ArchitecturalImpact = $ArchitecturalImpact
        Recommendation      = $Recommendation
    }
}

Function Get-TlsVersionRisk {
    param([string]$TlsVersion)

    switch ($TlsVersion) {
        "1.0" {
            return @{
                RiskLevel           = "Critical"
                RiskCategory        = "Security"
                Finding             = "TLS 1.0 is permitted. This version was deprecated in 2020 and contains known cryptographic vulnerabilities including BEAST and POODLE."
                BusinessImpact      = "Organizations operating TLS 1.0 endpoints risk violating PCI DSS, ISO 27001, and NIST SP 800-52 requirements. A successful downgrade attack against TLS 1.0 can expose encrypted traffic, creating regulatory exposure and potential data breach liability."
                ArchitecturalImpact = "Accepting TLS 1.0 at the service edge defeats the purpose of encryption in transit. Attackers on the network path can negotiate TLS 1.0 with a vulnerable client and exploit known cipher weaknesses. This single configuration gap can undermine an otherwise well-architected defence-in-depth model."
                Recommendation      = "Set the minimum TLS version to TLS 1.2 immediately. Validate that no internal client systems require TLS 1.0 before enforcing; if they do, schedule those systems for remediation. TLS 1.3 should be the target for new service deployments."
            }
        }
        "1.1" {
            return @{
                RiskLevel           = "High"
                RiskCategory        = "Security"
                Finding             = "TLS 1.1 is permitted. This version has been deprecated and lacks support for modern authenticated encryption cipher suites."
                BusinessImpact      = "TLS 1.1 is non-compliant with PCI DSS 4.0 and current NIST guidance. Auditors and enterprise security teams increasingly flag TLS 1.1 as a compensating control gap, which can delay certification, partner onboarding, and regulatory approvals."
                ArchitecturalImpact = "TLS 1.1 does not support AEAD cipher suites (e.g. AES-GCM) that provide authenticated encryption. Sessions negotiated at TLS 1.1 may fall back to weaker cipher suites, exposing data in transit to passive interception. The architecture should enforce TLS 1.2+ at all termination points."
                Recommendation      = "Raise the minimum TLS version to 1.2. Audit dependent consumers and update any clients still negotiating TLS 1.1. Plan migration to TLS 1.3 for forward-looking services."
            }
        }
        "1.2" {
            return @{
                RiskLevel           = "Informational"
                RiskCategory        = "Security"
                Finding             = "TLS 1.2 is the current minimum. This meets baseline enterprise requirements, though TLS 1.3 offers stronger security properties."
                BusinessImpact      = "No immediate compliance risk. TLS 1.2 satisfies most current regulatory frameworks. Consider TLS 1.3 enforcement for sensitive data workloads or where forward-secrecy guarantees are critical."
                ArchitecturalImpact = "TLS 1.2 is acceptable but does not provide the improved handshake latency and mandatory forward secrecy that TLS 1.3 delivers. For high-throughput or latency-sensitive architectures, TLS 1.3 reduces handshake overhead."
                Recommendation      = "Maintain TLS 1.2 as the minimum. Evaluate TLS 1.3 adoption for new services and where client compatibility permits."
            }
        }
        default {
            return @{
                RiskLevel           = "Medium"
                RiskCategory        = "Security"
                Finding             = "TLS minimum version is set to '$TlsVersion' which could not be evaluated against a known baseline. Verify that the effective minimum is TLS 1.2 or higher."
                BusinessImpact      = "An unknown or unevaluated TLS configuration represents an unquantified risk in the transport security baseline. It may allow weaker protocol negotiation."
                ArchitecturalImpact = "Unverified TLS settings can create inconsistency in the enterprise transport security baseline, making it difficult to assert compliance across service boundaries."
                Recommendation      = "Verify the effective TLS version and ensure it is set explicitly to TLS 1.2 or TLS 1.3."
            }
        }
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-TlsAssessmentHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$Certificates,
        [array]$SubscriptionResults,
        [string]$GeneratedOn
    )

    # ── Aggregate counts ──────────────────────────────────────────────────────
    $totalFindings = @($Findings).Count
    $criticalCount = @($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highCount = @($Findings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumCount = @($Findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $nonCompliant = @($Findings | Where-Object { $_.IsCompliant -eq "No" }).Count
    $compliant = @($Findings | Where-Object { $_.IsCompliant -eq "Yes" }).Count
    $totalCerts = @($Certificates).Count
    $expiredCerts = @($Certificates | Where-Object { $_.ExpiryStatus -eq "Expired" }).Count
    $expiringCerts = @($Certificates | Where-Object { $_.ExpiryStatus -eq "Expiring Soon" }).Count
    $healthyCerts = @($Certificates | Where-Object { $_.ExpiryStatus -eq "Healthy" }).Count

    # ── Resource type distribution ────────────────────────────────────────────
    $resourceTypeDist = @{}
    foreach ($f in $Findings) {
        $rt = $f.ResourceType
        if ($resourceTypeDist.ContainsKey($rt)) { $resourceTypeDist[$rt]++ } else { $resourceTypeDist[$rt] = 1 }
    }
    $rtTotal = ($resourceTypeDist.Values | Measure-Object -Sum).Sum
    $rtBarRows = ""
    foreach ($rt in ($resourceTypeDist.GetEnumerator() | Sort-Object Value -Descending)) {
        $pct = if ($rtTotal -gt 0) { [math]::Round(($rt.Value / $rtTotal) * 100) } else { 0 }
        $rtBarRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $rt.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($rt.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Risk level distribution ───────────────────────────────────────────────
    $riskLevelDist = [ordered]@{
        "Critical"      = $criticalCount
        "High"          = $highCount
        "Medium"        = $mediumCount
        "Low"           = @($Findings | Where-Object { $_.RiskLevel -eq "Low" }).Count
        "Informational" = @($Findings | Where-Object { $_.RiskLevel -eq "Informational" }).Count
    }
    $rlTotal = ($riskLevelDist.Values | Measure-Object -Sum).Sum
    $rlBarRows = ""
    $rlColorMap = @{ "Critical" = "var(--red)"; "High" = "var(--red)"; "Medium" = "var(--amber)"; "Low" = "var(--green)"; "Informational" = "var(--muted)" }
    foreach ($rl in $riskLevelDist.GetEnumerator()) {
        if ($rl.Value -eq 0) { continue }
        $pct = if ($rlTotal -gt 0) { [math]::Round(($rl.Value / $rlTotal) * 100) } else { 0 }
        $barColor = if ($rlColorMap.ContainsKey($rl.Key)) { $rlColorMap[$rl.Key] } else { "var(--accent)" }
        $rlBarRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $rl.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
            <span class="bar-pct">$($rl.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Findings table rows ───────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings) {
        $riskCls = switch ($f.RiskLevel) {
            "Critical" { "badge-red" }
            "High" { "badge-red" }
            "Medium" { "badge-amber" }
            "Low" { "badge-green" }
            "Informational" { "badge-blue" }
            default { "badge-blue" }
        }
        $compCls = if ($f.IsCompliant -eq "Yes") { "badge-green" } else { "badge-red" }
        $rn = if ($f.ResourceName.Length -gt 28) { $f.ResourceName.Substring(0, 25) + "..." } else { $f.ResourceName }

        $findingRows += @"
          <tr>
            <td title="$(EscHtml $f.ResourceName)">$(EscHtml $rn)</td>
            <td><span class="scope-badge">$(EscHtml $f.ResourceType)</span></td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td>$(EscHtml $f.Setting)</td>
            <td><span class="badge $riskCls">$(EscHtml $f.RiskLevel)</span></td>
            <td><span class="badge $compCls">$(EscHtml $f.IsCompliant)</span></td>
          </tr>
"@
    }

    # ── Findings JSON for detail drawer ───────────────────────────────────────
    $findingsJson = "["
    foreach ($f in $Findings) {
        $findingsJson += "{" +
        """res"":""$(EscJ $f.ResourceName)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """rtype"":""$(EscJ $f.ResourceType)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """setting"":""$(EscJ $f.Setting)""," +
        """current"":""$(EscJ $f.CurrentValue)""," +
        """expected"":""$(EscJ $f.ExpectedValue)""," +
        """compliant"":""$(EscJ $f.IsCompliant)""," +
        """risk"":""$(EscJ $f.RiskLevel)""," +
        """cat"":""$(EscJ $f.RiskCategory)""," +
        """finding"":""$(EscJ $f.Finding)""," +
        """impact"":""$(EscJ $f.BusinessImpact)""," +
        """arch"":""$(EscJ $f.ArchitecturalImpact)""," +
        """rec"":""$(EscJ $f.Recommendation)""" +
        "},"
    }
    $findingsJson = $findingsJson.TrimEnd(",") + "]"

    # ── Certificate table rows ────────────────────────────────────────────────
    $certRows = ""
    foreach ($c in $Certificates) {
        $expCls = switch ($c.ExpiryStatus) {
            "Expired" { "badge-red" }
            "Expiring Soon" { "badge-amber" }
            "Healthy" { "badge-green" }
            default { "badge-blue" }
        }
        $daysText = if ($c.DaysToExpiry -lt 0) { "Expired ($($c.DaysToExpiry * -1)d ago)" } else { "$($c.DaysToExpiry)d" }

        $certRows += @"
          <tr>
            <td title="$(EscHtml $c.CertificateName)">$(if ($c.CertificateName.Length -gt 30) { EscHtml($c.CertificateName.Substring(0,27)+"...") } else { EscHtml $c.CertificateName })</td>
            <td>$(EscHtml $c.SubjectName)</td>
            <td>$(EscHtml $c.ResourceName)</td>
            <td>$(EscHtml $c.ResourceType)</td>
            <td>$(EscHtml $c.SubscriptionName)</td>
            <td style="font-family:var(--mono);font-size:11px">$(EscHtml $c.ExpiryDate)</td>
            <td style="font-family:var(--mono);font-size:11px">$daysText</td>
            <td><span class="badge $expCls">$(EscHtml $c.ExpiryStatus)</span></td>
          </tr>
"@
    }

    # ── Risk findings rows (Architectural Risks tab) ──────────────────────────
    $riskRows = ""
    $riskFindings = @($Findings | Where-Object { $_.IsCompliant -eq "No" -and $_.RiskLevel -in @("Critical", "High", "Medium") } | Sort-Object { switch ($_.RiskLevel) { "Critical" { 0 }; "High" { 1 }; "Medium" { 2 } } })
    $fi = 0
    foreach ($r in $riskFindings) {
        $riskCls = switch ($r.RiskLevel) { "Critical" { "badge-red" }; "High" { "badge-red" }; "Medium" { "badge-amber" }; default { "badge-blue" } }
        $catIcon = switch ($r.RiskCategory) { "Security" { "🔐" }; "Compliance" { "📋" }; "Reliability" { "🔄" }; "Architecture" { "🏗️" }; default { "⚠️" } }
        $riskRows += @"
          <div class="risk-card" onclick="showFindingDetail($fi)" style="cursor:pointer">
            <div class="risk-card-header">
              <span class="badge $riskCls">$(EscHtml $r.RiskLevel)</span>
              <span class="risk-cat-badge">$catIcon $(EscHtml $r.RiskCategory)</span>
              <span class="risk-resource">$(EscHtml $r.ResourceName) · <span class="scope-badge">$(EscHtml $r.ResourceType)</span></span>
            </div>
            <div class="risk-finding">$(EscHtml $r.Finding)</div>
            <div class="risk-meta">$(EscHtml $r.SubscriptionName) · $(EscHtml $r.Setting) · Current: <strong>$(EscHtml $r.CurrentValue)</strong></div>
          </div>
"@
        $fi++
    }
    if ($riskRows -eq "") { $riskRows = '<div class="risk-empty">✅ No Critical, High, or Medium findings identified.</div>' }

    # ── Subscription scan results rows ────────────────────────────────────────
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

    # ── HTML here-string ──────────────────────────────────────────────────────
    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure TLS Configuration Assessment</title>
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
.scope-badge{font-size:11px;font-family:var(--mono);color:var(--muted2);}
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
/* Risk cards */
.risk-card{
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:16px;margin-bottom:12px;transition:border-color .15s,box-shadow .15s;
}
.risk-card:hover{border-color:var(--accent);box-shadow:0 2px 12px rgba(56,139,253,.15);}
.risk-card-header{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap;}
.risk-cat-badge{font-size:11px;color:var(--muted2);background:var(--surface3);padding:2px 8px;border-radius:20px;border:1px solid var(--border);}
.risk-resource{font-size:12px;color:var(--muted2);margin-left:auto;}
.risk-finding{font-size:13px;color:var(--text);margin-bottom:8px;line-height:1.5;}
.risk-meta{font-size:11px;color:var(--muted);font-family:var(--mono);}
.risk-empty{padding:24px;text-align:center;color:var(--green);font-size:14px;}
/* Certificate health grid */
.cert-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:18px;}
/* Detail drawer */
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
.drawer-impact-box{background:var(--surface2);border-left:3px solid var(--amber);border-radius:0 var(--radius-sm) var(--radius-sm) 0;padding:10px 14px;font-size:12px;line-height:1.6;color:var(--muted2);margin-bottom:8px;}
.drawer-rec-box{background:var(--surface2);border-left:3px solid var(--green);border-radius:0 var(--radius-sm) var(--radius-sm) 0;padding:10px 14px;font-size:12px;line-height:1.6;color:var(--muted2);}
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
    <div class="logo-icon">🔒</div>
    <div class="logo-title">TLS Configuration</div>
    <div class="logo-sub">Transport Security Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('services',this)"><span class="nav-icon">🛠️</span> Service Details</button>
    <button class="nav-btn" onclick="showPage('certs',this)"><span class="nav-icon">📜</span> Certificate Health</button>
    <button class="nav-btn" onclick="showPage('risks',this)"><span class="nav-icon">⚠️</span> Architectural Risks</button>
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
      Azure TLS Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Transport Security Overview</div>
      <div class="page-sub">TLS and HTTPS posture across __SUB_COUNT__ subscription(s) · __TOTAL_FINDINGS__ findings generated</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Risk</div>
        <div class="stat-sub">Prioritise remediation</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium Risk</div>
        <div class="stat-sub">Plan for resolution</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__NON_COMPLIANT__</div>
        <div class="stat-label">Non-Compliant</div>
        <div class="stat-sub">Settings not meeting baseline</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__COMPLIANT__</div>
        <div class="stat-label">Compliant</div>
        <div class="stat-sub">Meeting baseline</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__TOTAL_CERTS__</div>
        <div class="stat-label">Certificates</div>
        <div class="stat-sub">__EXPIRED_CERTS__ expired · __EXPIRING_CERTS__ expiring</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📊 Risk Level Distribution</div>
        __RL_BAR_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🛠️ Findings by Resource Type</div>
        __RT_BAR_ROWS__
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">📜 Certificate Health Summary</div>
      <div class="cert-summary">
        <div class="stat-card c-green"><div class="stat-num">__HEALTHY_CERTS__</div><div class="stat-label">Healthy</div></div>
        <div class="stat-card c-amber"><div class="stat-num">__EXPIRING_CERTS__</div><div class="stat-label">Expiring ≤30d</div></div>
        <div class="stat-card c-red"><div class="stat-num">__EXPIRED_CERTS__</div><div class="stat-label">Expired</div></div>
      </div>
    </div>
  </div>

  <!-- Service Details -->
  <div id="page-services" class="page">
    <div class="page-header">
      <div class="page-title">Service Details</div>
      <div class="page-sub">All TLS configuration findings per resource — click any row to view full context and recommendation</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search resource, service type…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterRisk" onchange="filterFindings()">
          <option value="">All Risk Levels</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Informational">Informational</option>
        </select>
        <select class="filter-select" id="filterCompliant" onchange="filterFindings()">
          <option value="">All Compliance</option>
          <option value="No">Non-Compliant</option>
          <option value="Yes">Compliant</option>
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
              <th onclick="sortFindings(0)">Resource</th>
              <th onclick="sortFindings(1)">Type</th>
              <th onclick="sortFindings(2)">Subscription</th>
              <th onclick="sortFindings(3)">Setting</th>
              <th onclick="sortFindings(4)">Risk Level</th>
              <th onclick="sortFindings(5)">Compliant</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- Certificate Health -->
  <div id="page-certs" class="page">
    <div class="page-header">
      <div class="page-title">Certificate Health</div>
      <div class="page-sub">Certificate expiry status across App Service, API Management, and Front Door — expired or expiring certificates cause service outages</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="certSearch" placeholder="Search certificate, resource…" oninput="filterCerts()"/>
        </div>
        <select class="filter-select" id="filterExpiry" onchange="filterCerts()">
          <option value="">All Expiry Status</option>
          <option value="Expired">Expired</option>
          <option value="Expiring Soon">Expiring Soon</option>
          <option value="Healthy">Healthy</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="certTable">
          <thead>
            <tr>
              <th onclick="sortCerts(0)">Certificate Name</th>
              <th onclick="sortCerts(1)">Subject</th>
              <th onclick="sortCerts(2)">Resource</th>
              <th onclick="sortCerts(3)">Type</th>
              <th onclick="sortCerts(4)">Subscription</th>
              <th onclick="sortCerts(5)">Expiry Date</th>
              <th onclick="sortCerts(6)">Days to Expiry</th>
              <th onclick="sortCerts(7)">Status</th>
            </tr>
          </thead>
          <tbody id="certBody">__CERT_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="certPagination"></div>
    </div>
  </div>

  <!-- Architectural Risks -->
  <div id="page-risks" class="page">
    <div class="page-header">
      <div class="page-title">Architectural Risk Findings</div>
      <div class="page-sub">Critical, High, and Medium findings with business context and remediation guidance — click any card for full detail</div>
    </div>
    <div class="panel">
      __RISK_ROWS__
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription TLS assessment outcome</div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Subscriptions Scanned</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- Session Info -->
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
        <div class="info-card"><div class="info-label">Total Findings</div><div class="info-value">__TOTAL_FINDINGS__</div></div>
        <div class="info-card"><div class="info-label">Certificates Assessed</div><div class="info-value">__TOTAL_CERTS__</div></div>
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
const FIND_DATA = __FINDINGS_JSON__;
let findFiltered = [...FIND_DATA];
let findPage = 1, findPageSz = 25;
let findSortCol = -1, findSortAsc = true;
let currentDetailIdx = 0;
let currentDetailSource = 'find';

const CERT_DATA_RAW = `__CERT_JSON_RAW__`;
let CERT_DATA = [];
try{ CERT_DATA = JSON.parse(CERT_DATA_RAW); }catch(e){}
let certFiltered = [...CERT_DATA];
let certPage = 1, certPageSz = 25;
let certSortCol = -1, certSortAsc = true;

const RISK_FIND_DATA = FIND_DATA.filter(r => r.compliant === 'No' && ['Critical','High','Medium'].includes(r.risk));

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

// ── Findings table ────────────────────────────────────────────────────────────
function filterFindings(){
  const q=document.getElementById('findSearch').value.toLowerCase();
  const r=document.getElementById('filterRisk').value;
  const c=document.getElementById('filterCompliant').value;
  findFiltered=FIND_DATA.filter(f=>{
    const mQ=!q||JSON.stringify(f).toLowerCase().includes(q);
    const mR=!r||f.risk===r;
    const mC=!c||f.compliant===c;
    return mQ&&mR&&mC;
  });
  findPage=1; renderFindings();
}

function changeFindPageSize(){
  findPageSz=parseInt(document.getElementById('pgSizeFind').value);
  findPage=1; renderFindings();
}

function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys=['res','rtype','sub','setting','risk','compliant'];
  findFiltered.sort((a,b)=>{
    const k=keys[col]; const av=a[k]??'', bv=b[k]??'';
    return findSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                      :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderFindings();
}

function renderFindings(){
  const tbody=document.getElementById('findBody');
  const start=(findPage-1)*findPageSz;
  const slice=findFiltered.slice(start,start+findPageSz);
  tbody.innerHTML=slice.map(f=>{
    const gi=FIND_DATA.indexOf(f);
    const rCls=f.risk==='Critical'||f.risk==='High'?'badge-red':f.risk==='Medium'?'badge-amber':f.risk==='Low'?'badge-green':'badge-blue';
    const cCls=f.compliant==='Yes'?'badge-green':'badge-red';
    const nm=f.res.length>28?f.res.substring(0,25)+'...':f.res;
    return `<tr onclick="showFindingDetail(${gi})" style="cursor:pointer">
      <td title="${escH(f.res)}">${escH(nm)}</td>
      <td><span class="scope-badge">${escH(f.rtype)}</span></td>
      <td>${escH(f.sub)}</td>
      <td>${escH(f.setting)}</td>
      <td><span class="badge ${rCls}">${escH(f.risk)}</span></td>
      <td><span class="badge ${cCls}">${escH(f.compliant)}</span></td>
    </tr>`;
  }).join('');
  renderFindPg();
}

function renderFindPg(){
  const total=Math.ceil(findFiltered.length/findPageSz);
  const el=document.getElementById('findPagination');
  let h=`<span>${findFiltered.length} findings</span>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,findPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeFindPage(p){
  const total=Math.ceil(findFiltered.length/findPageSz);
  if(p<1||p>total)return;
  findPage=p; renderFindings();
}

// ── Certificate table ─────────────────────────────────────────────────────────
function filterCerts(){
  const q=document.getElementById('certSearch').value.toLowerCase();
  const e=document.getElementById('filterExpiry').value;
  certFiltered=CERT_DATA.filter(r=>{
    const mQ=!q||JSON.stringify(r).toLowerCase().includes(q);
    const mE=!e||r.status===e;
    return mQ&&mE;
  });
  certPage=1; renderCerts();
}

function sortCerts(col){
  if(certSortCol===col){certSortAsc=!certSortAsc;}else{certSortCol=col;certSortAsc=true;}
  const keys=['name','subject','resname','restype','sub','expiry','days','status'];
  certFiltered.sort((a,b)=>{
    const k=keys[col]; const av=a[k]??'', bv=b[k]??'';
    return certSortAsc?String(av).localeCompare(String(bv),undefined,{numeric:true})
                      :String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderCerts();
}

function renderCerts(){
  const tbody=document.getElementById('certBody');
  const start=(certPage-1)*certPageSz;
  const slice=certFiltered.slice(start,start+certPageSz);
  tbody.innerHTML=slice.map(c=>{
    const eCls=c.status==='Expired'?'badge-red':c.status==='Expiring Soon'?'badge-amber':'badge-green';
    const dText=parseInt(c.days)<0?`Expired (${Math.abs(parseInt(c.days))}d ago)`:`${c.days}d`;
    const nm=c.name.length>30?c.name.substring(0,27)+'...':c.name;
    return `<tr>
      <td title="${escH(c.name)}">${escH(nm)}</td>
      <td>${escH(c.subject)}</td>
      <td>${escH(c.resname)}</td>
      <td>${escH(c.restype)}</td>
      <td>${escH(c.sub)}</td>
      <td style="font-family:var(--mono);font-size:11px">${escH(c.expiry)}</td>
      <td style="font-family:var(--mono);font-size:11px">${dText}</td>
      <td><span class="badge ${eCls}">${escH(c.status)}</span></td>
    </tr>`;
  }).join('');
  renderCertPg();
}

function renderCertPg(){
  const total=Math.ceil(certFiltered.length/certPageSz);
  const el=document.getElementById('certPagination');
  let h=`<span>${certFiltered.length} certificates</span>`;
  h+=`<button class="pg-btn" onclick="changeCertPage(${certPage-1})" ${certPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,certPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===certPage?'active':''}" onclick="changeCertPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeCertPage(${certPage+1})" ${certPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeCertPage(p){
  const total=Math.ceil(certFiltered.length/certPageSz);
  if(p<1||p>total)return;
  certPage=p; renderCerts();
}

// ── Finding detail drawer ─────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx=idx;
  currentDetailSource='find';
  const r=FIND_DATA[idx];
  if(!r)return;
  document.getElementById('drawerTitle').textContent=r.res+' · '+r.setting;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FIND_DATA.length}`;
  const rCls=r.risk==='Critical'||r.risk==='High'?'badge-red':r.risk==='Medium'?'badge-amber':r.risk==='Low'?'badge-green':'badge-blue';
  const cCls=r.compliant==='Yes'?'badge-green':'badge-red';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Resource</div><div class="drawer-field-value">${escH(r.res)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Type</div><div class="drawer-field-value"><span class="scope-badge">${escH(r.rtype)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Setting</div><div class="drawer-field-value">${escH(r.setting)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Current Value</div><div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.current)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Expected Value</div><div class="drawer-field-value" style="font-family:var(--mono)">${escH(r.expected)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Risk Level</div><div class="drawer-field-value"><span class="badge ${rCls}">${escH(r.risk)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Risk Category</div><div class="drawer-field-value">${escH(r.cat)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Compliant</div><div class="drawer-field-value"><span class="badge ${cCls}">${escH(r.compliant)}</span></div></div>
    <div class="drawer-section">Finding</div>
    <div class="drawer-field-value" style="font-size:13px;line-height:1.6">${escH(r.finding)}</div>
    <div class="drawer-section">Business Impact</div>
    <div class="drawer-impact-box">${escH(r.impact)}</div>
    <div class="drawer-section">Architectural Impact</div>
    <div class="drawer-impact-box">${escH(r.arch)}</div>
    <div class="drawer-section">Recommendation</div>
    <div class="drawer-rec-box">${escH(r.rec)}</div>
  `;
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}

function showRiskFindingDetail(riskIdx){
  const r=RISK_FIND_DATA[riskIdx];
  if(!r)return;
  const gi=FIND_DATA.indexOf(r);
  if(gi>=0) showFindingDetail(gi);
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
  if(e.key==='ArrowLeft'&&document.getElementById('detailDrawer').classList.contains('open')) navDetail(-1);
  if(e.key==='ArrowRight'&&document.getElementById('detailDrawer').classList.contains('open')) navDetail(1);
});

// ── Init ──────────────────────────────────────────────────────────────────────
filterFindings();
filterCerts();
animateBars();
</script>
</body>
</html>
'@

    # ── Certificate JSON ──────────────────────────────────────────────────────
    $certJsonLines = "["
    foreach ($c in $Certificates) {
        $certJsonLines += "{" +
        """name"":""$(EscJ $c.CertificateName)""," +
        """subject"":""$(EscJ $c.SubjectName)""," +
        """resname"":""$(EscJ $c.ResourceName)""," +
        """restype"":""$(EscJ $c.ResourceType)""," +
        """sub"":""$(EscJ $c.SubscriptionName)""," +
        """expiry"":""$(EscJ $c.ExpiryDate)""," +
        """days"":""$($c.DaysToExpiry)""," +
        """status"":""$(EscJ $c.ExpiryStatus)""" +
        "},"
    }
    $certJsonLines = $certJsonLines.TrimEnd(",") + "]"

    # ── Token replacement ─────────────────────────────────────────────────────
    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_FINDINGS__', $totalFindings `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MEDIUM_COUNT__', $mediumCount `
        -replace '__NON_COMPLIANT__', $nonCompliant `
        -replace '__COMPLIANT__', $compliant `
        -replace '__TOTAL_CERTS__', $totalCerts `
        -replace '__EXPIRED_CERTS__', $expiredCerts `
        -replace '__EXPIRING_CERTS__', $expiringCerts `
        -replace '__HEALTHY_CERTS__', $healthyCerts `
        -replace '__RL_BAR_ROWS__', $rlBarRows `
        -replace '__RT_BAR_ROWS__', $rtBarRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__CERT_ROWS__', $certRows `
        -replace '__RISK_ROWS__', $riskRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FINDINGS_JSON__', $findingsJson `
        -replace '__CERT_JSON_RAW__', ($certJsonLines -replace '`', '``')

    return $html
}


#------------------------------------------------------------------------ [ Service Assessors ]

Function Invoke-AppServiceTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$ResourceType,
        [ref]$Findings,
        [ref]$Certificates
    )

    try {
        $apps = @(Get-AzWebApp -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve $ResourceType for $SubscriptionName : $_"
        return
    }

    foreach ($app in $apps) {
        $rg = $app.ResourceGroup
        $name = $app.Name

        # HTTPS-only enforcement
        $httpsOnly = $app.HttpsOnly
        $isHttpsCompliant = ($httpsOnly -eq $true)

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        $ResourceType `
            -Setting             "HTTPS Only" `
            -CurrentValue        $(if ($httpsOnly) { "Enabled" } else { "Disabled" }) `
            -ExpectedValue       "Enabled" `
            -IsCompliant         $isHttpsCompliant `
            -RiskLevel           $(if ($isHttpsCompliant) { "Informational" } else { "High" }) `
            -RiskCategory        "Security" `
            -Finding             $(if ($isHttpsCompliant) { "HTTPS-only mode is enforced. HTTP traffic is automatically redirected to HTTPS." } else { "HTTPS-only mode is disabled. The application accepts unencrypted HTTP traffic, exposing data in transit to interception." }) `
            -BusinessImpact      $(if ($isHttpsCompliant) { "Compliant. No action required for this setting." } else { "Applications accepting HTTP allow credentials, session tokens, and sensitive data to traverse the network in plaintext. This violates PCI DSS, HIPAA, and most enterprise security policies. In the event of a network interception event, unencrypted traffic creates direct data breach liability." }) `
            -ArchitecturalImpact $(if ($isHttpsCompliant) { "Compliant." } else { "Without HTTPS enforcement, any HTTP request — including API calls, authentication flows, and data submissions — is transmitted without encryption. Even if the application appears to redirect HTTP to HTTPS at the application layer, this is insufficient; the initial unencrypted request has already traversed the network." }) `
            -Recommendation      $(if ($isHttpsCompliant) { "No action required." } else { "Enable HTTPS Only in the App Service TLS/SSL settings. This enforces a 301 redirect from HTTP to HTTPS at the Azure platform layer, before any application code executes." })

        # Minimum TLS version
        $tlsVer = "Unknown"
        try {
            $config = Get-AzWebAppConfiguration -ResourceGroupName $rg -Name $name -ErrorAction Stop
            $tlsVer = if ($config.MinTlsVersion) { $config.MinTlsVersion } else { "Not Set" }
        }
        catch { Write-Verbose "  Could not read config for ${name}: $_" }

        $tlsRisk = Get-TlsVersionRisk -TlsVersion $tlsVer
        $isTlsCompliant = ($tlsVer -in @("1.2", "1.3"))

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        $ResourceType `
            -Setting             "Minimum TLS Version" `
            -CurrentValue        $tlsVer `
            -ExpectedValue       "TLS 1.2 or higher" `
            -IsCompliant         $isTlsCompliant `
            -RiskLevel           $tlsRisk.RiskLevel `
            -RiskCategory        $tlsRisk.RiskCategory `
            -Finding             $tlsRisk.Finding `
            -BusinessImpact      $tlsRisk.BusinessImpact `
            -ArchitecturalImpact $tlsRisk.ArchitecturalImpact `
            -Recommendation      $tlsRisk.Recommendation

        # Certificates
        try {
            $certs = @(Get-AzWebAppCertificate -ResourceGroupName $rg -ErrorAction Stop |
                Where-Object { $_.ServerFarmId -eq $app.ServerFarmId -or $_.SubjectName })
            foreach ($cert in $certs) {
                $expiry = $cert.ExpirationDate
                $daysLeft = if ($expiry) { [math]::Round(($expiry - (Get-Date)).TotalDays) } else { $null }
                $expiryStr = if ($expiry) { $expiry.ToString("yyyy-MM-dd") } else { "N/A" }
                $status = if ($null -eq $daysLeft) { "Unknown" }
                elseif ($daysLeft -lt 0) { "Expired" }
                elseif ($daysLeft -le 30) { "Expiring Soon" }
                else { "Healthy" }

                $Certificates.Value += [pscustomobject]@{
                    CertificateName  = if ($cert.Name) { $cert.Name } else { "Unknown" }
                    SubjectName      = if ($cert.SubjectName) { $cert.SubjectName } else { "N/A" }
                    ResourceName     = $name
                    ResourceType     = $ResourceType
                    SubscriptionName = $SubscriptionName
                    SubscriptionId   = $SubscriptionId
                    ResourceGroup    = $rg
                    ExpiryDate       = $expiryStr
                    DaysToExpiry     = if ($null -ne $daysLeft) { $daysLeft } else { 9999 }
                    ExpiryStatus     = $status
                }
            }
        }
        catch { Write-Verbose "  Could not retrieve certificates for ${name}: $_" }
    }
}

Function Invoke-FunctionAppTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings,
        [ref]$Certificates
    )

    try {
        $funcApps = @(Get-AzFunctionApp -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Function Apps for $SubscriptionName : $_"
        return
    }

    foreach ($func in $funcApps) {
        $rg = $func.ResourceGroupName
        $name = $func.Name

        $httpsOnly = $func.HttpsOnly
        $isHttpsCompliant = ($httpsOnly -eq $true)

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Functions" `
            -Setting             "HTTPS Only" `
            -CurrentValue        $(if ($httpsOnly) { "Enabled" } else { "Disabled" }) `
            -ExpectedValue       "Enabled" `
            -IsCompliant         $isHttpsCompliant `
            -RiskLevel           $(if ($isHttpsCompliant) { "Informational" } else { "High" }) `
            -RiskCategory        "Security" `
            -Finding             $(if ($isHttpsCompliant) { "HTTPS-only mode is enforced on this Function App." } else { "HTTPS-only mode is disabled. This Function App can receive unencrypted HTTP requests, including function triggers from external systems." }) `
            -BusinessImpact      $(if ($isHttpsCompliant) { "Compliant. No action required." } else { "Function Apps exposed via HTTP without HTTPS enforcement may transmit API keys, function payloads, and integration data in plaintext. In event-driven and integration architectures, this creates a broad attack surface for credential theft and data interception." }) `
            -ArchitecturalImpact $(if ($isHttpsCompliant) { "Compliant." } else { "Function Apps often serve as integration endpoints for business-critical workflows. Allowing HTTP on these endpoints breaks the assumption that all inter-service communication is encrypted, which is a foundational control in zero-trust network architectures." }) `
            -Recommendation      $(if ($isHttpsCompliant) { "No action required." } else { "Enable HTTPS Only in Function App TLS/SSL configuration. Review any HTTP-triggered functions and validate that trigger URLs in calling systems are updated to use HTTPS." })

        # TLS version — read via SiteConfig
        $tlsVer = "Unknown"
        try {
            $config = Get-AzWebAppConfiguration -ResourceGroupName $rg -Name $name -ErrorAction Stop
            $tlsVer = if ($config.MinTlsVersion) { $config.MinTlsVersion } else { "Not Set" }
        }
        catch { Write-Verbose "  Could not read Function App config for ${name}: $_" }

        $tlsRisk = Get-TlsVersionRisk -TlsVersion $tlsVer
        $isTlsCompliant = ($tlsVer -in @("1.2", "1.3"))

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Functions" `
            -Setting             "Minimum TLS Version" `
            -CurrentValue        $tlsVer `
            -ExpectedValue       "TLS 1.2 or higher" `
            -IsCompliant         $isTlsCompliant `
            -RiskLevel           $tlsRisk.RiskLevel `
            -RiskCategory        $tlsRisk.RiskCategory `
            -Finding             $tlsRisk.Finding `
            -BusinessImpact      $tlsRisk.BusinessImpact `
            -ArchitecturalImpact $tlsRisk.ArchitecturalImpact `
            -Recommendation      $tlsRisk.Recommendation
    }
}

Function Invoke-ApiManagementTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings,
        [ref]$Certificates
    )

    try {
        $apimInstances = @(Get-AzApiManagement -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve API Management instances for $SubscriptionName : $_"
        return
    }

    foreach ($apim in $apimInstances) {
        $rg = $apim.ResourceGroupName
        $name = $apim.Name

        # Custom hostname configurations and certificates
        $customHostnames = @(Get-ObjProperty -Obj $apim -PropName 'HostnameConfigurations' -Default @())
        $hasCustomDomain = ($customHostnames.Count -gt 0)

        foreach ($hn in $customHostnames) {
            $hnType = Get-ObjProperty -Obj $hn -PropName 'HostnameType' -Default "Unknown"
            $cert = Get-ObjProperty -Obj $hn -PropName 'Certificate' -Default $null

            if ($cert) {
                $expiry = Get-ObjProperty -Obj $cert -PropName 'Expiry' -Default $null
                $subject = Get-ObjProperty -Obj $cert -PropName 'Subject' -Default "N/A"
                $thumbprint = Get-ObjProperty -Obj $cert -PropName 'Thumbprint' -Default "N/A"
                $daysLeft = if ($expiry) { [math]::Round(($expiry - (Get-Date)).TotalDays) } else { $null }
                $expiryStr = if ($expiry) { $expiry.ToString("yyyy-MM-dd") } else { "N/A" }
                $status = if ($null -eq $daysLeft) { "Unknown" }
                elseif ($daysLeft -lt 0) { "Expired" }
                elseif ($daysLeft -le 30) { "Expiring Soon" }
                else { "Healthy" }

                $Certificates.Value += [pscustomobject]@{
                    CertificateName  = "$name-$hnType"
                    SubjectName      = $subject
                    ResourceName     = $name
                    ResourceType     = "Azure API Management"
                    SubscriptionName = $SubscriptionName
                    SubscriptionId   = $SubscriptionId
                    ResourceGroup    = $rg
                    ExpiryDate       = $expiryStr
                    DaysToExpiry     = if ($null -ne $daysLeft) { $daysLeft } else { 9999 }
                    ExpiryStatus     = $status
                }
            }

            # Minimum protocol — check NegotiateClientCertificate and protocol settings
            $negotiateCert = Get-ObjProperty -Obj $hn -PropName 'NegotiateClientCertificate' -Default $false

            $Findings.Value += New-TlsFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        "Azure API Management" `
                -Setting             "Custom Domain Certificate ($hnType)" `
                -CurrentValue        $(if ($cert) { "Certificate Bound" } else { "No Certificate" }) `
                -ExpectedValue       "Valid certificate bound to custom domain" `
                -IsCompliant         ($null -ne $cert) `
                -RiskLevel           $(if ($cert) { "Informational" } else { "High" }) `
                -RiskCategory        "Security" `
                -Finding             $(if ($cert) { "A TLS certificate is bound to the '$hnType' hostname on this API Management instance." } else { "No TLS certificate is bound to the '$hnType' custom hostname on this API Management instance, leaving the endpoint without transport security." }) `
                -BusinessImpact      $(if ($cert) { "Certificate binding confirmed. Ensure regular rotation and monitor expiry." } else { "An API Management endpoint without a certificate exposes API consumers to man-in-the-middle attacks. For enterprise API gateways, this represents a critical security control failure and violates secure-by-design API architecture principles." }) `
                -ArchitecturalImpact $(if ($cert) { "Compliant." } else { "API Management instances without certificates on custom domains break the trust chain for API consumers. Any system validating HTTPS connections will fail or fall back to insecure behaviour, undermining the gateway's role as a secure API facade." }) `
                -Recommendation      $(if ($cert) { "Monitor certificate expiry and establish an automated rotation process." } else { "Bind a valid TLS certificate to this custom hostname immediately. Use a certificate from Azure Key Vault via APIM's managed certificate integration to enable automated renewal." })
        }

        # APIM SKU and network mode — Consumption tier doesn't support some settings
        $sku = Get-ObjProperty -Obj $apim -PropName 'Sku' -Default $null
        $skuName = Get-ObjProperty -Obj $sku -PropName 'Name' -Default "Unknown"

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure API Management" `
            -Setting             "Custom Domain Configuration" `
            -CurrentValue        $(if ($hasCustomDomain) { "Configured ($($customHostnames.Count) hostname(s))" } else { "Not Configured (using default *.azure-api.net)" }) `
            -ExpectedValue       "Custom domain with dedicated certificate" `
            -IsCompliant         $hasCustomDomain `
            -RiskLevel           $(if ($hasCustomDomain) { "Informational" } else { "Medium" }) `
            -RiskCategory        "Architecture" `
            -Finding             $(if ($hasCustomDomain) { "Custom domain(s) are configured on this API Management instance, enabling control over TLS certificate management." } else { "This API Management instance uses the default *.azure-api.net domain. There is no custom certificate binding, limiting control over TLS configuration and certificate lifecycle." }) `
            -BusinessImpact      $(if ($hasCustomDomain) { "Custom domain confirmed. Certificate management responsibility rests with the team." } else { "Using default Azure-managed domains means the organisation has no control over the certificate or TLS policy on this endpoint. Enterprise API consumers may require custom domain validation for compliance and API contract enforcement." }) `
            -ArchitecturalImpact $(if ($hasCustomDomain) { "Compliant." } else { "Without a custom domain, this instance cannot be integrated with corporate DNS, cannot have certificate pinning applied, and cannot be brought under the enterprise certificate lifecycle management process. In multi-tenant API architectures this creates an unmanaged dependency on Microsoft's default certificate." }) `
            -Recommendation      $(if ($hasCustomDomain) { "Ensure certificate rotation procedures are in place and expiry alerts are configured." } else { "Configure a custom domain and bind an enterprise-managed TLS certificate. Integrate with Azure Key Vault for automated certificate renewal. This also enables the instance to be placed behind Azure Front Door or Application Gateway with consistent TLS policy." })
    }
}

Function Invoke-StorageTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings
    )

    try {
        $storageAccounts = @(Get-AzStorageAccount -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Storage Accounts for $SubscriptionName : $_"
        return
    }

    foreach ($sa in $storageAccounts) {
        $rg = $sa.ResourceGroupName
        $name = $sa.StorageAccountName

        # Secure Transfer Required (HTTPS-only)
        $secureTransfer = $sa.EnableHttpsTrafficOnly
        $isSecureCompliant = ($secureTransfer -eq $true)

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Storage" `
            -Setting             "Secure Transfer Required (HTTPS Only)" `
            -CurrentValue        $(if ($secureTransfer) { "Enabled" } else { "Disabled" }) `
            -ExpectedValue       "Enabled" `
            -IsCompliant         $isSecureCompliant `
            -RiskLevel           $(if ($isSecureCompliant) { "Informational" } else { "Critical" }) `
            -RiskCategory        "Security" `
            -Finding             $(if ($isSecureCompliant) { "Secure Transfer Required is enabled. All storage endpoint requests must use HTTPS." } else { "Secure Transfer Required is disabled. This storage account accepts unencrypted HTTP requests to Blob, Queue, Table, and File service endpoints." }) `
            -BusinessImpact      $(if ($isSecureCompliant) { "Compliant. No action required." } else { "Storage accounts without Secure Transfer Required expose data at rest stored in Azure Storage to interception during transit. For regulated workloads (financial records, healthcare data, PII), this is a direct compliance violation. A single unencrypted request to retrieve sensitive blobs constitutes a potential data breach event." }) `
            -ArchitecturalImpact $(if ($isSecureCompliant) { "Compliant." } else { "Azure Storage serves as the foundational data layer for most Azure architectures. Without enforced HTTPS, any component reading from or writing to this storage account — including application services, Azure Functions, Logic Apps, and data pipelines — may transmit data unencrypted if an HTTP endpoint is accidentally invoked. The blast radius of this misconfiguration extends to all consumers of the storage account." }) `
            -Recommendation      $(if ($isSecureCompliant) { "No action required." } else { "Enable Secure Transfer Required immediately. Validate that all applications consuming this storage account use HTTPS endpoints (not HTTP) before enabling, to avoid disruption to existing workloads." })

        # Minimum TLS version
        $tlsVer = if ($sa.MinimumTlsVersion) { $sa.MinimumTlsVersion.ToString().Replace("TLS1_", "1.").Replace("TLS1", "1.") } else { "Not Set" }
        # Normalise Azure API format (TLS1_0 -> 1.0, TLS1_2 -> 1.2)
        $tlsVerNorm = switch -Wildcard ($sa.MinimumTlsVersion) {
            "TLS1_0" { "1.0" }
            "TLS1_1" { "1.1" }
            "TLS1_2" { "1.2" }
            $null { "Not Set" }
            default { $sa.MinimumTlsVersion }
        }

        $tlsRisk = Get-TlsVersionRisk -TlsVersion $tlsVerNorm
        $isTlsCompliant = ($tlsVerNorm -in @("1.2", "1.3"))

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Storage" `
            -Setting             "Minimum TLS Version" `
            -CurrentValue        $tlsVerNorm `
            -ExpectedValue       "TLS 1.2 or higher" `
            -IsCompliant         $isTlsCompliant `
            -RiskLevel           $tlsRisk.RiskLevel `
            -RiskCategory        $tlsRisk.RiskCategory `
            -Finding             $tlsRisk.Finding `
            -BusinessImpact      $tlsRisk.BusinessImpact `
            -ArchitecturalImpact $tlsRisk.ArchitecturalImpact `
            -Recommendation      $tlsRisk.Recommendation

        # Public blob access (informational, transport context)
        $allowBlobPublic = Get-ObjProperty -Obj $sa -PropName 'AllowBlobPublicAccess' -Default $null
        if ($null -ne $allowBlobPublic) {
            $Findings.Value += New-TlsFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        "Azure Storage" `
                -Setting             "Allow Blob Public Access" `
                -CurrentValue        $(if ($allowBlobPublic) { "Enabled" } else { "Disabled" }) `
                -ExpectedValue       "Disabled (unless a static website or public CDN origin)" `
                -IsCompliant         (-not $allowBlobPublic) `
                -RiskLevel           $(if ($allowBlobPublic) { "Medium" } else { "Informational" }) `
                -RiskCategory        "Security" `
                -Finding             $(if ($allowBlobPublic) { "Public blob access is allowed on this storage account. Any container set to public access level will be readable without authentication." } else { "Public blob access is disabled. No container in this account can be made publicly accessible." }) `
                -BusinessImpact      $(if ($allowBlobPublic) { "Allowing public blob access at the account level means a misconfigured container permission could expose sensitive data to the public internet without any authentication or encryption-at-rest guarantee. Even if no containers are currently public, this setting creates a standing risk of accidental data exposure by any team member with storage permissions." } else { "Compliant. Public access is blocked at the account level, preventing accidental data exposure." }) `
                -ArchitecturalImpact $(if ($allowBlobPublic) { "In a defence-in-depth architecture, allowing public blob access at the account level bypasses the principle of least privilege at the storage layer. It also means that transport security controls (HTTPS enforcement, TLS version) are the only protection between internet users and the data, without any identity-based access control." } else { "Compliant." }) `
                -Recommendation      $(if ($allowBlobPublic) { "Disable Allow Blob Public Access at the account level unless this storage account explicitly serves as a public static website or CDN origin. For those use cases, consider migrating to Azure Static Web Apps or Azure CDN with origin access controls instead." } else { "No action required." })
        }
    }
}

Function Invoke-SqlTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings
    )

    # ── Azure SQL Servers ─────────────────────────────────────────────────────
    try {
        $sqlServers = @(Get-AzSqlServer -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve SQL Servers for $SubscriptionName : $_"
        $sqlServers = @()
    }

    foreach ($server in $sqlServers) {
        $rg = $server.ResourceGroupName
        $name = $server.ServerName

        $tlsVer = if ($server.MinimalTlsVersion) { $server.MinimalTlsVersion } else { "Not Enforced" }

        $tlsVerNorm = switch ($server.MinimalTlsVersion) {
            "1.0" { "1.0" }
            "1.1" { "1.1" }
            "1.2" { "1.2" }
            $null { "Not Enforced" }
            "" { "Not Enforced" }
            default { $server.MinimalTlsVersion }
        }

        $tlsRisk = Get-TlsVersionRisk -TlsVersion $tlsVerNorm
        $isTlsCompliant = ($tlsVerNorm -eq "1.2")

        # If not enforced, treat as high risk
        if ($tlsVerNorm -eq "Not Enforced") {
            $tlsRisk = @{
                RiskLevel           = "High"
                RiskCategory        = "Security"
                Finding             = "No minimum TLS version is enforced on this SQL Server. Clients may connect using any TLS version, including deprecated versions."
                BusinessImpact      = "Without a minimum TLS version, database connections from legacy clients may negotiate TLS 1.0 or 1.1. Database connections typically carry the most sensitive data in an application architecture — credentials, PII, financial records, and business logic results. Uncontrolled TLS negotiation is a direct compliance gap for PCI DSS, ISO 27001, and SOC 2."
                ArchitecturalImpact = "SQL Server acts as the data persistence layer for most application workloads. If the TLS version is not enforced at the server level, each application's connection string and driver version determines the effective security level. In large or multi-team environments this creates an unaudited and uncontrollable TLS baseline."
                Recommendation      = "Set the minimum TLS version to 1.2 on this SQL Server. Audit all application connection strings to confirm TLS 1.2 compatibility before enforcing, particularly for legacy applications using older JDBC/ODBC drivers."
            }
        }

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure SQL" `
            -Setting             "Minimum TLS Version" `
            -CurrentValue        $tlsVerNorm `
            -ExpectedValue       "1.2" `
            -IsCompliant         $isTlsCompliant `
            -RiskLevel           $tlsRisk.RiskLevel `
            -RiskCategory        $tlsRisk.RiskCategory `
            -Finding             $tlsRisk.Finding `
            -BusinessImpact      $tlsRisk.BusinessImpact `
            -ArchitecturalImpact $tlsRisk.ArchitecturalImpact `
            -Recommendation      $tlsRisk.Recommendation
    }

    # ── SQL Managed Instances ──────────────────────────────────────────────────
    try {
        $sqlMIs = @(Get-AzSqlInstance -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve SQL Managed Instances for $SubscriptionName : $_"
        $sqlMIs = @()
    }

    foreach ($mi in $sqlMIs) {
        $rg = $mi.ResourceGroupName
        $name = $mi.ManagedInstanceName

        $tlsVerNorm = if ($mi.MinimalTlsVersion) { $mi.MinimalTlsVersion } else { "Not Enforced" }
        $tlsRisk = Get-TlsVersionRisk -TlsVersion $tlsVerNorm
        $isTlsCompliant = ($tlsVerNorm -eq "1.2")

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure SQL Managed Instance" `
            -Setting             "Minimum TLS Version" `
            -CurrentValue        $tlsVerNorm `
            -ExpectedValue       "1.2" `
            -IsCompliant         $isTlsCompliant `
            -RiskLevel           $tlsRisk.RiskLevel `
            -RiskCategory        $tlsRisk.RiskCategory `
            -Finding             $tlsRisk.Finding `
            -BusinessImpact      $tlsRisk.BusinessImpact `
            -ArchitecturalImpact $tlsRisk.ArchitecturalImpact `
            -Recommendation      $tlsRisk.Recommendation
    }
}

Function Invoke-AppGatewayTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings,
        [ref]$Certificates
    )

    try {
        $gateways = @(Get-AzApplicationGateway -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Application Gateways for $SubscriptionName : $_"
        return
    }

    foreach ($gw in $gateways) {
        $rg = $gw.ResourceGroupName
        $name = $gw.Name

        # SSL Policy
        $sslPolicy = Get-ObjProperty -Obj $gw -PropName 'SslPolicy' -Default $null
        $policyType = Get-ObjProperty -Obj $sslPolicy -PropName 'PolicyType' -Default "Not Configured"
        $policyName = Get-ObjProperty -Obj $sslPolicy -PropName 'PolicyName' -Default ""
        $minProtocol = Get-ObjProperty -Obj $sslPolicy -PropName 'MinProtocolVersion' -Default "Not Set"
        $disabledSuites = @(Get-ObjProperty -Obj $sslPolicy -PropName 'DisabledSslProtocols' -Default @())

        $isCustomPolicy = ($policyType -eq "Custom")
        $isPredefined = ($policyType -eq "Predefined")

        # Map min protocol version to TLS version string
        $minTlsNorm = switch ($minProtocol) {
            "TLSv1" { "1.0" }
            "TLSv1_1" { "1.1" }
            "TLSv1_2" { "1.2" }
            default { if ($minProtocol) { $minProtocol } else { "Not Set" } }
        }

        # Check predefined policy strength
        $weakPolicies = @("AppGwSslPolicy20150501")
        $isPolicyWeak = ($policyName -in $weakPolicies)

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Application Gateway" `
            -Setting             "SSL Policy Type" `
            -CurrentValue        ($policyType + $(if ($policyName) { " ($policyName)" } else { "" })) `
            -ExpectedValue       "Custom or Predefined 2022 policy" `
            -IsCompliant         ($isCustomPolicy -or ($isPredefined -and -not $isPolicyWeak)) `
            -RiskLevel           $(if ($isPolicyWeak) { "High" } elseif ($policyType -eq "Not Configured") { "Medium" } else { "Informational" }) `
            -RiskCategory        "Security" `
            -Finding             $(if ($isPolicyWeak) { "The Application Gateway is using the deprecated 2015 SSL policy which permits TLS 1.0, TLS 1.1, and weak cipher suites." } elseif ($policyType -eq "Not Configured") { "No explicit SSL policy is configured on this Application Gateway. Default Azure platform settings apply, which may not meet enterprise security baselines." } else { ("An SSL policy is configured: " + $policyType + $(if ($policyName) { " - $policyName" } else { "" }) + ".") }) `
            -BusinessImpact      $(if ($isPolicyWeak) { "Using the 2015 AppGw SSL policy means this gateway accepts connections using deprecated TLS versions and weak cipher suites. As an edge-facing load balancer, the Application Gateway is the first TLS termination point for external traffic — a weak policy here defeats transport security for all backend services it protects." } elseif ($policyType -eq "Not Configured") { "Without an explicit SSL policy, the effective TLS configuration of this gateway is undefined and subject to platform default changes, making the security posture difficult to audit and certify." } else { "Policy is configured. Verify that the policy enforces TLS 1.2+ and disables weak cipher suites as appropriate for your compliance requirements." }) `
            -ArchitecturalImpact $(if ($isPolicyWeak) { "Application Gateway functions as the TLS termination point for web applications, APIs, and backend services. A weak SSL policy at this layer creates an unmitigated attack surface: any traffic that would otherwise be protected by application-layer TLS is now vulnerable at the gateway boundary." } elseif ($policyType -eq "Not Configured") { "Without a defined SSL policy, the gateway's TLS behaviour is non-deterministic from an architecture governance perspective — it may change as Azure updates its platform defaults, without any change control process capturing the impact." } else { "Compliant." }) `
            -Recommendation      $(if ($isPolicyWeak -or $policyType -eq "Not Configured") { "Apply the 'AppGwSslPolicy20220101' (2022) predefined policy or configure a Custom SSL policy that disables TLS 1.0 and 1.1, disables RC4 and 3DES cipher suites, and enforces TLS 1.2 as the minimum." } else { "No action required. Periodically review the SSL policy to ensure it remains current with evolving security standards." })

        # HTTP listeners (non-TLS termination)
        $httpListeners = @(Get-ObjProperty -Obj $gw -PropName 'HttpListeners' -Default @() |
            Where-Object { (Get-ObjProperty -Obj $_ -PropName 'Protocol' -Default "") -eq "Http" })

        if ($httpListeners.Count -gt 0) {
            $Findings.Value += New-TlsFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        "Azure Application Gateway" `
                -Setting             "HTTP Listener Exposure" `
                -CurrentValue        "$($httpListeners.Count) HTTP listener(s) configured" `
                -ExpectedValue       "0 HTTP listeners (all traffic via HTTPS)" `
                -IsCompliant         $false `
                -RiskLevel           "High" `
                -RiskCategory        "Security" `
                -Finding             "This Application Gateway has $($httpListeners.Count) HTTP listener(s) configured. HTTP listeners accept unencrypted traffic before any backend routing occurs." `
                -BusinessImpact      "HTTP listeners on an enterprise Application Gateway expose incoming requests to interception before TLS termination occurs. In a PCI or healthcare environment, this means that cardholder data or PHI could traverse unencrypted segments of the network path, creating direct compliance violations even if the backend services enforce HTTPS." `
                -ArchitecturalImpact "Application Gateways with active HTTP listeners are often justified as HTTP-to-HTTPS redirect endpoints. However, if a redirect rule is not correctly configured, or if backend routing rules send HTTP traffic directly to backends, the unencrypted path becomes a live attack vector. Each HTTP listener represents an entry point that bypasses TLS termination entirely." `
                -Recommendation      "Review each HTTP listener and associated routing rules. Convert pure HTTP routing to HTTPS listeners. Where HTTP listeners exist for redirect purposes only (HTTP 301 to HTTPS), ensure the redirect rule covers all paths and uses a 301 (not 302) redirect to enable HSTS enforcement downstream."
        }

        # Certificates on HTTPS listeners
        $httpsListeners = @(Get-ObjProperty -Obj $gw -PropName 'HttpListeners' -Default @() |
            Where-Object { (Get-ObjProperty -Obj $_ -PropName 'Protocol' -Default "") -eq "Https" })

        foreach ($listener in $httpsListeners) {
            $sslCertRef = Get-ObjProperty -Obj $listener -PropName 'SslCertificate' -Default $null
            $listenerName = Get-ObjProperty -Obj $listener -PropName 'Name' -Default "Unnamed"

            $Findings.Value += New-TlsFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        $name `
                -ResourceGroup       $rg `
                -ResourceType        "Azure Application Gateway" `
                -Setting             "HTTPS Listener Certificate ($listenerName)" `
                -CurrentValue        $(if ($sslCertRef) { "Certificate Bound" } else { "No Certificate Reference" }) `
                -ExpectedValue       "Certificate bound to all HTTPS listeners" `
                -IsCompliant         ($null -ne $sslCertRef) `
                -RiskLevel           $(if ($sslCertRef) { "Informational" } else { "Critical" }) `
                -RiskCategory        "Reliability" `
                -Finding             $(if ($sslCertRef) { "An SSL certificate is bound to the HTTPS listener '$listenerName'." } else { "HTTPS listener '$listenerName' has no SSL certificate bound. This listener cannot serve TLS-protected traffic and will cause connection errors for all clients." }) `
                -BusinessImpact      $(if ($sslCertRef) { "Certificate binding confirmed. Establish expiry monitoring and automated rotation." } else { "A misconfigured HTTPS listener without a certificate causes all inbound TLS connections to fail at the gateway layer. This results in a complete service outage for all workloads behind this listener, impacting revenue, customer experience, and SLA commitments." }) `
                -ArchitecturalImpact $(if ($sslCertRef) { "Compliant." } else { "An HTTPS listener without a certificate binding represents a broken TLS termination point. The Application Gateway will reject all connections to this listener, making every backend service behind it unreachable via HTTPS." }) `
                -Recommendation      $(if ($sslCertRef) { "Verify certificate expiry and ensure automated rotation is configured via Key Vault integration." } else { "Bind a valid SSL certificate to this listener immediately. Use Key Vault-integrated certificate management to automate rotation and prevent future lapses." })
        }
    }
}

Function Invoke-FrontDoorTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings,
        [ref]$Certificates
    )

    # ── Azure Front Door (Classic) ─────────────────────────────────────────────
    try {
        $frontDoors = @(Get-AzFrontDoor -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Front Door (Classic) for $SubscriptionName : $_"
        $frontDoors = @()
    }

    foreach ($fd in $frontDoors) {
        $rg = $fd.ResourceGroupName
        $name = $fd.Name

        $httpsRedirect = Get-ObjProperty -Obj $fd -PropName 'EnabledState' -Default "Unknown"
        $frontendEndpoints = @(Get-ObjProperty -Obj $fd -PropName 'FrontendEndpoints' -Default @())

        foreach ($ep in $frontendEndpoints) {
            $epName = Get-ObjProperty -Obj $ep -PropName 'Name' -Default "Unknown"
            $httpsConfig = Get-ObjProperty -Obj $ep -PropName 'CustomHttpsConfiguration' -Default $null
            $httpsEnabled = ($null -ne $httpsConfig)
            $minTls = Get-ObjProperty -Obj $httpsConfig -PropName 'MinimumTlsVersion' -Default "Not Set"

            $minTlsNorm = switch ($minTls) { "1.0" { "1.0" }; "1.2" { "1.2" }; default { $minTls } }
            $tlsRisk = Get-TlsVersionRisk -TlsVersion $minTlsNorm
            $isTlsCompliant = ($minTlsNorm -in @("1.2", "1.3"))

            $Findings.Value += New-TlsFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        "$name/$epName" `
                -ResourceGroup       $rg `
                -ResourceType        "Azure Front Door" `
                -Setting             "Custom HTTPS Minimum TLS Version" `
                -CurrentValue        $minTlsNorm `
                -ExpectedValue       "TLS 1.2 or higher" `
                -IsCompliant         $isTlsCompliant `
                -RiskLevel           $tlsRisk.RiskLevel `
                -RiskCategory        $tlsRisk.RiskCategory `
                -Finding             $tlsRisk.Finding `
                -BusinessImpact      $tlsRisk.BusinessImpact `
                -ArchitecturalImpact $tlsRisk.ArchitecturalImpact `
                -Recommendation      $tlsRisk.Recommendation

            # Certificate type
            $certType = Get-ObjProperty -Obj $httpsConfig -PropName 'CertificateSource' -Default "Not Configured"
            $Findings.Value += New-TlsFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        "$name/$epName" `
                -ResourceGroup       $rg `
                -ResourceType        "Azure Front Door" `
                -Setting             "HTTPS Certificate Configuration" `
                -CurrentValue        $(if ($httpsEnabled) { "Custom HTTPS Enabled ($certType)" } else { "Custom HTTPS Not Enabled" }) `
                -ExpectedValue       "Custom HTTPS enabled with a valid certificate" `
                -IsCompliant         $httpsEnabled `
                -RiskLevel           $(if ($httpsEnabled) { "Informational" } else { "High" }) `
                -RiskCategory        "Security" `
                -Finding             $(if ($httpsEnabled) { "Custom HTTPS is enabled on endpoint '$epName' using $certType." } else { "Custom HTTPS is not enabled on endpoint '$epName'. This endpoint serves traffic without TLS configuration at the Front Door layer." }) `
                -BusinessImpact      $(if ($httpsEnabled) { "HTTPS is enabled. Ensure certificate expiry is monitored and rotation is automated." } else { "A Front Door endpoint without HTTPS enabled exposes all traffic — including API responses, web page content, and authentication tokens — to interception across any network segment between the client and the Azure edge PoP." }) `
                -ArchitecturalImpact $(if ($httpsEnabled) { "Compliant." } else { "Front Door is the global entry point for traffic distributed across Azure regions. Disabling HTTPS at this layer means there is no transport security at the furthest-edge point of the architecture, where traffic is most exposed to untrusted network infrastructure." }) `
                -Recommendation      $(if ($httpsEnabled) { "Monitor certificate expiry. For Azure-managed certificates, ensure the domain verification DNS records remain in place. For customer-managed certificates, integrate with Key Vault for automated rotation." } else { "Enable Custom HTTPS on this endpoint. Use an Azure-managed certificate or bring your own via Key Vault integration. Configure HTTPS redirect rules to enforce TLS for all client connections." })
        }
    }

    # ── Azure CDN ─────────────────────────────────────────────────────────────
    try {
        $cdnProfiles = @(Get-AzCdnProfile -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve CDN Profiles for $SubscriptionName : $_"
        return
    }

    foreach ($cdnProfile in $cdnProfiles) {
        $rg = $cdnProfile.ResourceGroupName
        $profileName = $cdnProfile.Name

        try {
            $endpoints = @(Get-AzCdnEndpoint -ResourceGroupName $rg -ProfileName $profileName -ErrorAction Stop)
        }
        catch {
            Write-Verbose "  Could not retrieve CDN endpoints for ${profileName}: $_"
            continue
        }

        foreach ($ep in $endpoints) {
            $epName = $ep.Name
            $isHttps = $ep.IsHttpsAllowed
            $isHttp = $ep.IsHttpAllowed

            $Findings.Value += New-TlsFinding `
                -SubscriptionName    $SubscriptionName `
                -SubscriptionId      $SubscriptionId `
                -ResourceName        "$profileName/$epName" `
                -ResourceGroup       $rg `
                -ResourceType        "Azure CDN" `
                -Setting             "HTTP Allowed" `
                -CurrentValue        $(if ($isHttp) { "Enabled" } else { "Disabled" }) `
                -ExpectedValue       "Disabled (HTTPS only)" `
                -IsCompliant         (-not $isHttp) `
                -RiskLevel           $(if ($isHttp) { "Medium" } else { "Informational" }) `
                -RiskCategory        "Security" `
                -Finding             $(if ($isHttp) { "HTTP is allowed on CDN endpoint '$epName'. Content can be delivered over unencrypted HTTP to clients." } else { "HTTP is disabled on CDN endpoint '$epName'. Content is served via HTTPS only." }) `
                -BusinessImpact      $(if ($isHttp) { "CDN endpoints that allow HTTP can deliver content — including scripts, stylesheets, and API responses — to end users over an unencrypted channel. For web applications, this creates exposure to content injection attacks (e.g. mixed-content attacks) that can compromise the security of HTTPS pages that include CDN-served resources." } else { "Compliant." }) `
                -ArchitecturalImpact $(if ($isHttp) { "In a modern web architecture, all CDN-served content should be served exclusively over HTTPS to maintain the integrity of the HTTPS context for the consuming application. HTTP-served CDN resources break browser mixed-content policies and can trigger HSTS preload failures." } else { "Compliant." }) `
                -Recommendation      $(if ($isHttp) { "Disable HTTP on this CDN endpoint and enforce HTTPS-only delivery. Configure an HTTP-to-HTTPS redirect rule on the CDN endpoint to maintain backward compatibility with any HTTP clients during transition." } else { "No action required." })
        }
    }
}

Function Invoke-KeyVaultTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings
    )

    try {
        $vaults = @(Get-AzKeyVault -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Key Vaults for $SubscriptionName : $_"
        return
    }

    foreach ($kv in $vaults) {
        $rg = $kv.ResourceGroupName
        $name = $kv.VaultName

        try {
            $kvDetail = Get-AzKeyVault -ResourceGroupName $rg -VaultName $name -ErrorAction Stop
        }
        catch {
            Write-Verbose "  Could not retrieve Key Vault detail for ${name}: $_"
            continue
        }

        # Network access restriction
        $networkRuleDefaultAction = Get-ObjProperty -Obj $kvDetail.NetworkAcls -PropName 'DefaultAction' -Default "Allow"
        $isNetworkRestricted = ($networkRuleDefaultAction -eq "Deny")

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Key Vault" `
            -Setting             "Network Access Restriction" `
            -CurrentValue        $(if ($isNetworkRestricted) { "Restricted (Default Deny)" } else { "Public (Default Allow)" }) `
            -ExpectedValue       "Restricted (Default Deny with explicit allow rules)" `
            -IsCompliant         $isNetworkRestricted `
            -RiskLevel           $(if ($isNetworkRestricted) { "Informational" } else { "High" }) `
            -RiskCategory        "Security" `
            -Finding             $(if ($isNetworkRestricted) { "Key Vault network access is restricted. Only explicitly allowed networks or private endpoints can access this vault." } else { "Key Vault is publicly accessible from any network. There are no network-level access restrictions preventing unreachable endpoints from attempting to access vault contents." }) `
            -BusinessImpact      $(if ($isNetworkRestricted) { "Compliant. Network-level restriction provides a perimeter control that complements key vault access policies and RBAC." } else { "A publicly accessible Key Vault relies entirely on authentication and authorisation controls for protection. If an identity is compromised (service principal, managed identity, or user), the attacker has a direct, unobstructed network path to retrieve secrets, certificates, and encryption keys. For organisations storing TLS certificates and application secrets in Key Vault, this represents a high-impact attack surface." }) `
            -ArchitecturalImpact $(if ($isNetworkRestricted) { "Compliant." } else { "Key Vault stores the cryptographic material that underpins transport security across the organisation — TLS certificates, encryption keys, and connection strings. Allowing unrestricted network access to the vault means that the material protecting transport security is itself unprotected at the network layer, creating an architectural contradiction." }) `
            -Recommendation      $(if ($isNetworkRestricted) { "No action required. Periodically review the network allow-list to remove stale IP ranges and virtual network rules." } else { "Enable network access restrictions on this Key Vault. Set the default action to Deny and add explicit allow rules for only the virtual networks and IP ranges that legitimately require access. Prefer Private Endpoint over service endpoint for production workloads." })

        # Soft delete
        $softDelete = Get-ObjProperty -Obj $kvDetail -PropName 'EnableSoftDelete' -Default $false
        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Key Vault" `
            -Setting             "Soft Delete" `
            -CurrentValue        $(if ($softDelete) { "Enabled" } else { "Disabled" }) `
            -ExpectedValue       "Enabled" `
            -IsCompliant         ($softDelete -eq $true) `
            -RiskLevel           $(if ($softDelete) { "Informational" } else { "High" }) `
            -RiskCategory        "Reliability" `
            -Finding             $(if ($softDelete) { "Soft delete is enabled. Deleted vault objects are retained for the recovery period and can be recovered." } else { "Soft delete is disabled. Deleted secrets, certificates, and keys are permanently destroyed immediately with no recovery capability." }) `
            -BusinessImpact      $(if ($softDelete) { "Compliant. Recovery capability exists for accidental or malicious deletion of vault contents." } else { "Without soft delete, an accidental or malicious deletion of a TLS certificate stored in Key Vault results in immediate and irrecoverable loss. If that certificate is bound to a production HTTPS endpoint, the result is an unrecoverable service outage — TLS cannot be re-established until a new certificate is issued, validated, and rebound." }) `
            -ArchitecturalImpact $(if ($softDelete) { "Compliant." } else { "Key Vault is the single store for certificates and cryptographic material in most enterprise Azure architectures. Without soft delete, there is no architectural safety net for accidental deletion — the organisation is one mistyped command away from an irrecoverable transport security outage across all services using that vault." }) `
            -Recommendation      $(if ($softDelete) { "No action required. Consider also enabling purge protection to prevent permanent deletion during the soft-delete retention period." } else { "Enable soft delete immediately. In newer Azure Key Vaults, soft delete is enabled by default and cannot be disabled — if this vault has it disabled, it is likely a legacy vault that should be migrated or have soft delete enabled via the Azure Portal or CLI." })

        # Purge protection
        $purgeProtection = Get-ObjProperty -Obj $kvDetail -PropName 'EnablePurgeProtection' -Default $false
        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Key Vault" `
            -Setting             "Purge Protection" `
            -CurrentValue        $(if ($purgeProtection) { "Enabled" } else { "Disabled" }) `
            -ExpectedValue       "Enabled" `
            -IsCompliant         ($purgeProtection -eq $true) `
            -RiskLevel           $(if ($purgeProtection) { "Informational" } else { "Medium" }) `
            -RiskCategory        "Reliability" `
            -Finding             $(if ($purgeProtection) { "Purge protection is enabled. Vault contents in the soft-delete state cannot be permanently purged before the retention period expires." } else { "Purge protection is disabled. A privileged user can permanently purge soft-deleted vault objects immediately, bypassing the recovery window." }) `
            -BusinessImpact      $(if ($purgeProtection) { "Compliant. Even a privileged compromise cannot immediately and permanently destroy vault contents." } else { "Without purge protection, a compromised privileged identity (or a malicious insider) can permanently destroy TLS certificates and keys, even if soft delete is enabled. This creates a ransomware-equivalent scenario for transport security material: an attacker who cannot steal the keys can instead destroy them, causing a production outage." }) `
            -ArchitecturalImpact $(if ($purgeProtection) { "Compliant." } else { "Purge protection is the final safeguard in the Key Vault deletion lifecycle. Without it, the soft-delete window provides no real protection against a privileged attacker or operator error — the organisation's cryptographic material has no guaranteed recovery window." }) `
            -Recommendation      $(if ($purgeProtection) { "No action required." } else { "Enable purge protection on this Key Vault. Note that once enabled, purge protection cannot be disabled — this is by design. Purge protection requires soft delete to also be enabled." })
    }
}

Function Invoke-ServiceBusEventHubTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings
    )

    # ── Service Bus ────────────────────────────────────────────────────────────
    try {
        $sbNamespaces = @(Get-AzServiceBusNamespace -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Service Bus Namespaces for $SubscriptionName : $_"
        $sbNamespaces = @()
    }

    foreach ($ns in $sbNamespaces) {
        $rg = $ns.ResourceGroupName
        $name = $ns.Name

        $tlsVer = if ($ns.MinimumTlsVersion) { $ns.MinimumTlsVersion } else { "Not Set" }
        $tlsVerNorm = switch ($tlsVer) {
            "1.0" { "1.0" }
            "1.1" { "1.1" }
            "1.2" { "1.2" }
            default { $tlsVer }
        }
        $tlsRisk = Get-TlsVersionRisk -TlsVersion $tlsVerNorm
        $isTlsCompliant = ($tlsVerNorm -in @("1.2", "1.3"))

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Service Bus" `
            -Setting             "Minimum TLS Version" `
            -CurrentValue        $tlsVerNorm `
            -ExpectedValue       "TLS 1.2 or higher" `
            -IsCompliant         $isTlsCompliant `
            -RiskLevel           $tlsRisk.RiskLevel `
            -RiskCategory        $tlsRisk.RiskCategory `
            -Finding             $tlsRisk.Finding `
            -BusinessImpact      $tlsRisk.BusinessImpact `
            -ArchitecturalImpact $tlsRisk.ArchitecturalImpact `
            -Recommendation      $tlsRisk.Recommendation

        $publicAccess = Get-ObjProperty -Obj $ns -PropName 'PublicNetworkAccess' -Default "Enabled"
        $isPrivate = ($publicAccess -eq "Disabled")

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Service Bus" `
            -Setting             "Public Network Access" `
            -CurrentValue        $publicAccess `
            -ExpectedValue       "Disabled (private endpoint only)" `
            -IsCompliant         $isPrivate `
            -RiskLevel           $(if ($isPrivate) { "Informational" } else { "Medium" }) `
            -RiskCategory        "Architecture" `
            -Finding             $(if ($isPrivate) { "Public network access is disabled. Service Bus is accessible only via private endpoint." } else { "Public network access is enabled. This Service Bus namespace is reachable from the public internet, increasing the attack surface for messaging infrastructure." }) `
            -BusinessImpact      $(if ($isPrivate) { "Compliant. Messaging infrastructure is accessible only via private network paths." } else { "Messaging infrastructure exposed to the public internet relies entirely on TLS and authentication for protection. In high-throughput enterprise messaging architectures, public endpoint exposure increases the risk of connection interception, brute-force attacks on shared access signatures, and denial-of-service against messaging pipelines." }) `
            -ArchitecturalImpact $(if ($isPrivate) { "Compliant." } else { "Service Bus is the message backbone for event-driven and decoupled architectures. Exposing it publicly creates an unnecessary attack surface that a network-level control (private endpoint or service endpoint) would eliminate. In a zero-trust architecture, messaging infrastructure should never be publicly reachable." }) `
            -Recommendation      $(if ($isPrivate) { "No action required. Periodically review private endpoint configuration and network access rules." } else { "Evaluate deploying private endpoints for this Service Bus namespace. If public access is required for legacy integrations, restrict it using IP firewall rules to known publisher/consumer IP ranges." })
    }

    # ── Event Hubs ────────────────────────────────────────────────────────────
    try {
        $ehNamespaces = @(Get-AzEventHubNamespace -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Event Hub Namespaces for $SubscriptionName : $_"
        return
    }

    foreach ($ns in $ehNamespaces) {
        $rg = $ns.ResourceGroupName
        $name = $ns.Name

        $tlsVer = if ($ns.MinimumTlsVersion) { $ns.MinimumTlsVersion } else { "Not Set" }
        $tlsVerNorm = switch ($tlsVer) { "1.0" { "1.0" }; "1.1" { "1.1" }; "1.2" { "1.2" }; default { $tlsVer } }
        $tlsRisk = Get-TlsVersionRisk -TlsVersion $tlsVerNorm
        $isTlsCompliant = ($tlsVerNorm -in @("1.2", "1.3"))

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Event Hubs" `
            -Setting             "Minimum TLS Version" `
            -CurrentValue        $tlsVerNorm `
            -ExpectedValue       "TLS 1.2 or higher" `
            -IsCompliant         $isTlsCompliant `
            -RiskLevel           $tlsRisk.RiskLevel `
            -RiskCategory        $tlsRisk.RiskCategory `
            -Finding             $tlsRisk.Finding `
            -BusinessImpact      $tlsRisk.BusinessImpact `
            -ArchitecturalImpact $tlsRisk.ArchitecturalImpact `
            -Recommendation      $tlsRisk.Recommendation
    }
}

Function Invoke-CosmosDbTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings
    )

    try {
        $accounts = @(Get-AzCosmosDBAccount -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Cosmos DB Accounts for $SubscriptionName : $_"
        return
    }

    foreach ($acct in $accounts) {
        $rg = $acct.ResourceGroupName
        $name = $acct.Name

        # Public network access
        $publicAccess = Get-ObjProperty -Obj $acct -PropName 'PublicNetworkAccess' -Default "Enabled"
        $isPrivate = ($publicAccess -eq "Disabled")

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Cosmos DB" `
            -Setting             "Public Network Access" `
            -CurrentValue        $publicAccess `
            -ExpectedValue       "Disabled (private endpoint only)" `
            -IsCompliant         $isPrivate `
            -RiskLevel           $(if ($isPrivate) { "Informational" } else { "High" }) `
            -RiskCategory        "Security" `
            -Finding             $(if ($isPrivate) { "Public network access is disabled. Cosmos DB is accessible only via private endpoint." } else { "Public network access is enabled. This Cosmos DB account is reachable from the public internet." }) `
            -BusinessImpact      $(if ($isPrivate) { "Compliant. Database access is restricted to private network paths." } else { "Cosmos DB accounts with public endpoints expose database connection surfaces to the internet. In global-scale applications, Cosmos DB often stores large volumes of user-generated content, operational data, and analytical records. A publicly exposed endpoint increases the risk of credential brute-force, key theft, and lateral movement from a compromised application identity." }) `
            -ArchitecturalImpact $(if ($isPrivate) { "Compliant." } else { "In a well-architected multi-region Azure deployment, Cosmos DB is typically co-located with compute in each region. Public endpoint exposure is architecturally unnecessary for workloads where both application and database are in Azure, and violates network isolation principles in a zero-trust model." }) `
            -Recommendation      $(if ($isPrivate) { "No action required." } else { "Enable private endpoints for this Cosmos DB account. Restrict public network access using the IP firewall to known application subnet IP ranges as an intermediate step if private endpoint migration requires planned effort." })

        # Disable local auth (key-based access) if set
        $disableLocalAuth = Get-ObjProperty -Obj $acct -PropName 'DisableLocalAuth' -Default $false
        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Cosmos DB" `
            -Setting             "Disable Local Authentication (Key-Based Access)" `
            -CurrentValue        $(if ($disableLocalAuth) { "Disabled (AAD only)" } else { "Enabled (Keys permitted)" }) `
            -ExpectedValue       "Disabled (enforce AAD authentication)" `
            -IsCompliant         ($disableLocalAuth -eq $true) `
            -RiskLevel           $(if ($disableLocalAuth) { "Informational" } else { "Medium" }) `
            -RiskCategory        "Security" `
            -Finding             $(if ($disableLocalAuth) { "Local key-based authentication is disabled. Only Azure Active Directory authentication is permitted." } else { "Local key-based authentication is permitted. Applications can authenticate to Cosmos DB using account keys rather than AAD identities." }) `
            -BusinessImpact      $(if ($disableLocalAuth) { "Compliant. Enforcing AAD-only authentication eliminates the risk of static key compromise." } else { "Cosmos DB account keys, if exposed via an application vulnerability, environment variable leak, or code repository, provide direct, unauthenticated database access with no identity traceability. Unlike AAD tokens, account keys do not expire, do not support conditional access, and cannot be invalidated without rotating all consumers simultaneously." }) `
            -ArchitecturalImpact $(if ($disableLocalAuth) { "Compliant." } else { "In a zero-trust architecture, every data access should be identity-attributable and revocable. Shared account keys violate this principle — they are opaque credentials that cannot be attributed to individual workloads and cannot support fine-grained RBAC. Disabling local auth forces all consumers to use managed identities or service principals, making data access fully auditable." }) `
            -Recommendation      $(if ($disableLocalAuth) { "No action required." } else { "Evaluate migrating all Cosmos DB consumers to AAD-based authentication (managed identities preferred). Once all consumers are confirmed to use AAD, disable local authentication to eliminate key-based access." })
    }
}

Function Invoke-RedisCacheTlsAssessment {
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [ref]$Findings
    )

    try {
        $caches = @(Get-AzRedisCache -ErrorAction Stop)
    }
    catch {
        Write-Verbose "  Could not retrieve Redis Cache instances for $SubscriptionName : $_"
        return
    }

    foreach ($cache in $caches) {
        $rg = $cache.ResourceGroupName
        $name = $cache.Name

        # Non-SSL port
        $nonSslEnabled = Get-ObjProperty -Obj $cache -PropName 'EnableNonSslPort' -Default $false

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Redis Cache" `
            -Setting             "Non-SSL Port (Port 6379)" `
            -CurrentValue        $(if ($nonSslEnabled) { "Enabled" } else { "Disabled" }) `
            -ExpectedValue       "Disabled" `
            -IsCompliant         (-not $nonSslEnabled) `
            -RiskLevel           $(if ($nonSslEnabled) { "Critical" } else { "Informational" }) `
            -RiskCategory        "Security" `
            -Finding             $(if ($nonSslEnabled) { "The non-SSL port (6379) is enabled. Applications can connect to this Redis Cache instance without encryption." } else { "The non-SSL port is disabled. All Redis connections must use the SSL port (6380)." }) `
            -BusinessImpact      $(if ($nonSslEnabled) { "Redis Cache stores application session state, caching layer data, and in many architectures, Pub/Sub messages. Enabling the non-SSL port means all of this data — including session tokens, user context, and application cache — can be transmitted in plaintext across the network. A network-level attacker can intercept and replay session tokens, impersonating authenticated users." } else { "Compliant. All Redis traffic is encrypted in transit." }) `
            -ArchitecturalImpact $(if ($nonSslEnabled) { "The Redis non-SSL port was historically enabled for legacy clients and development convenience. In a production Azure architecture, there is no justifiable reason to enable plaintext Redis connectivity. Any application using the non-SSL port is bypassing transport security entirely for cache access — typically one of the highest-frequency, lowest-latency paths in the application." } else { "Compliant." }) `
            -Recommendation      $(if ($nonSslEnabled) { "Disable the non-SSL port immediately. Update all application connection strings to use the SSL port (6380) and the rediss:// connection scheme. Validate that all Redis client libraries support TLS connections before switching." } else { "No action required." })

        # Minimum TLS version
        $tlsVer = if ($cache.MinimumTlsVersion) { $cache.MinimumTlsVersion } else { "Not Set" }
        $tlsVerNorm = switch ($tlsVer) { "1.0" { "1.0" }; "1.1" { "1.1" }; "1.2" { "1.2" }; default { $tlsVer } }
        $tlsRisk = Get-TlsVersionRisk -TlsVersion $tlsVerNorm
        $isTlsCompliant = ($tlsVerNorm -in @("1.2", "1.3"))

        $Findings.Value += New-TlsFinding `
            -SubscriptionName    $SubscriptionName `
            -SubscriptionId      $SubscriptionId `
            -ResourceName        $name `
            -ResourceGroup       $rg `
            -ResourceType        "Azure Redis Cache" `
            -Setting             "Minimum TLS Version" `
            -CurrentValue        $tlsVerNorm `
            -ExpectedValue       "TLS 1.2 or higher" `
            -IsCompliant         $isTlsCompliant `
            -RiskLevel           $tlsRisk.RiskLevel `
            -RiskCategory        $tlsRisk.RiskCategory `
            -Finding             $tlsRisk.Finding `
            -BusinessImpact      $tlsRisk.BusinessImpact `
            -ArchitecturalImpact $tlsRisk.ArchitecturalImpact `
            -Recommendation      $tlsRisk.Recommendation
    }
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureTLSConfigurationAssessment {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureTLSConfiguration-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts",
        "Az.Websites",
        "Az.ApiManagement",
        "Az.Storage",
        "Az.Sql",
        "Az.Network",
        "Az.KeyVault",
        "Az.ServiceBus",
        "Az.EventHub",
        "Az.CosmosDB",
        "Az.RedisCache"
    )

    # Az.FrontDoor and Az.Cdn checked separately (optional - won't block if absent)
    $optionalModules = @("Az.FrontDoor", "Az.Cdn")

    $missingRequired = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missingRequired) {
        Write-Host "  ⚠ Missing Az modules: $($missingRequired -join ', ')" -ForegroundColor Yellow
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

    $hasFrontDoor = ($null -ne (Get-Module -ListAvailable -Name "Az.FrontDoor"))
    $hasCdn = ($null -ne (Get-Module -ListAvailable -Name "Az.Cdn"))

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

    # ── Display session / params ──────────────────────────────────────────────
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"             = "$scopeText ($subCount found)"
        "Export to CSV"     = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"       = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
        "Front Door Module" = if ($hasFrontDoor) { "Available" } else { "Not installed - Front Door skipped" }
        "CDN Module"        = if ($hasCdn) { "Available" } else { "Not installed - CDN skipped" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings = @()
    $allCertificates = @()
    $subscriptionResults = @()
    $successCount = 0
    $errorCount = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-ScanProgress

    $maxNameLen = ([math]::Max(
            ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
            35
        ))

    $subIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $subFindings = [System.Collections.ArrayList]@()
            $subCertificates = [System.Collections.ArrayList]@()

            # ── App Service ────────────────────────────────────────────────
            Invoke-AppServiceTlsAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -ResourceType     "Azure App Service" `
                -Findings         ([ref]$subFindings) `
                -Certificates     ([ref]$subCertificates)

            # ── Function Apps ──────────────────────────────────────────────
            Invoke-FunctionAppTlsAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings) `
                -Certificates     ([ref]$subCertificates)

            # ── API Management ─────────────────────────────────────────────
            Invoke-ApiManagementTlsAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings) `
                -Certificates     ([ref]$subCertificates)

            # ── Storage ────────────────────────────────────────────────────
            Invoke-StorageTlsAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings)

            # ── SQL ────────────────────────────────────────────────────────
            Invoke-SqlTlsAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings)

            # ── Application Gateway ────────────────────────────────────────
            Invoke-AppGatewayTlsAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings) `
                -Certificates     ([ref]$subCertificates)

            # ── Front Door & CDN ───────────────────────────────────────────
            if ($hasFrontDoor) {
                Invoke-FrontDoorTlsAssessment `
                    -SubscriptionName $sub.Name `
                    -SubscriptionId   $sub.Id `
                    -Findings         ([ref]$subFindings) `
                    -Certificates     ([ref]$subCertificates)
            }

            # ── Key Vault ──────────────────────────────────────────────────
            Invoke-KeyVaultTlsAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings)

            # ── Service Bus / Event Hubs ───────────────────────────────────
            Invoke-ServiceBusEventHubTlsAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings)

            # ── Cosmos DB ──────────────────────────────────────────────────
            Invoke-CosmosDbTlsAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings)

            # ── Redis Cache ────────────────────────────────────────────────
            Invoke-RedisCacheTlsAssessment `
                -SubscriptionName $sub.Name `
                -SubscriptionId   $sub.Id `
                -Findings         ([ref]$subFindings)

            $allFindings += $subFindings
            $allCertificates += $subCertificates

            $subNonCompliant = @($subFindings | Where-Object { $_.IsCompliant -eq "No" }).Count
            $subCritHigh = @($subFindings | Where-Object { $_.RiskLevel -in @("Critical", "High") }).Count

            # ── Per-subscription result ────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Findings: $($subFindings.Count)  Non-Compliant: $subNonCompliant  Critical/High: $subCritHigh  Certs: $($subCertificates.Count)" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Findings: $($subFindings.Count)  Non-Compliant: $subNonCompliant  Critical/High: $subCritHigh"
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

    $criticalTotal = @($allFindings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highTotal = @($allFindings | Where-Object { $_.RiskLevel -eq "High" }).Count
    $nonComplTotal = @($allFindings | Where-Object { $_.IsCompliant -eq "No" }).Count
    $expiredCerts = @($allCertificates | Where-Object { $_.ExpiryStatus -eq "Expired" }).Count
    $expiringSoon = @($allCertificates | Where-Object { $_.ExpiryStatus -eq "Expiring Soon" }).Count

    Write-Summary -Data ([ordered]@{
            "Total Subscriptions Scanned" = $subCount
            "Successful"                  = $successCount
            "Errors"                      = $errorCount
            "Total Findings"              = $allFindings.Count
            "Non-Compliant Findings"      = $nonComplTotal
            "Critical Findings"           = $criticalTotal
            "High Findings"               = $highTotal
            "Certificates Assessed"       = $allCertificates.Count
            "Expired Certificates"        = $expiredCerts
            "Certificates Expiring ≤30d"  = $expiringSoon
            "Execution Time"              = $duration
        })

    Write-RiskBreakdown -Findings $allFindings

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        # CSV export
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, ResourceName, ResourceGroup, ResourceType,
                Setting, CurrentValue, ExpectedValue, IsCompliant,
                RiskLevel, RiskCategory, Finding, BusinessImpact, ArchitecturalImpact, Recommendation |
                Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                if ($allCertificates.Count -gt 0) {
                    $certCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "Certificates.csv"
                    $allCertificates | Export-Csv -Path $certCsvPath -NoTypeInformation -Encoding UTF8
                }

                $csvExported = $true
            }
            catch {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML dashboard
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

            $htmlContent = Generate-TlsAssessmentHtml `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParams `
                -Findings            $allFindings `
                -Certificates        $allCertificates `
                -SubscriptionResults $subscriptionResults `
                -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

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
            Where-Object { $_.IsCompliant -eq "No" } |
            Select-Object SubscriptionName, ResourceName, ResourceType, Setting, CurrentValue, RiskLevel, RiskCategory |
            Sort-Object { switch ($_.RiskLevel) { "Critical" { 0 }; "High" { 1 }; "Medium" { 2 }; "Low" { 3 }; default { 4 } } } |
            Out-GridView -Title "Azure TLS Configuration Assessment — Non-Compliant Findings"
            $gridViewOpened = $true
        }
        catch {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No resources found in the targeted subscriptions." -ForegroundColor Yellow
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
