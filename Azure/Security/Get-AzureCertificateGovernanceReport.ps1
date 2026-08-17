<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Inventories and risk-assesses certificates across Azure Key Vault, Application
    Gateway, and App Service; identifies expiry, cryptographic, and configuration
    risks; exports findings to CSV and an interactive HTML governance dashboard.

.DESCRIPTION
    Get-AzureCertificateGovernanceReport addresses a critical enterprise security
    problem: certificate-related outages and vulnerabilities caused by unmanaged
    certificate sprawl. At scale, manually tracking certificate health across
    Key Vault, Application Gateway listeners, and App Service custom domains is
    operationally impossible without automated tooling.

    This script provides:

    ASSESSMENT SCOPE
        Key Vault Certificates:
          - Expiry date and days remaining — tiered to Critical/High/Medium/Low
          - Cryptographic algorithm: RSA vs EC; minimum key size (2048-bit threshold)
          - Self-signed vs CA-issued detection (trust chain risk)
          - Auto-renewal policy: enabled/disabled, renewal threshold, issuer type
          - Certificate version count (sprawl signal)

        Application Gateway SSL Certificates:
          - Listener-bound SSL certificates and associated expiry dates
          - Key size and algorithm (where available from the binding metadata)
          - Self-signed vs trusted CA — critical distinction for external-facing services
          - SSL Policy: Predefined (AppGwSslPolicy20220101S = current) vs legacy or none
          - TLS protocol minimum (cross-referenced to TLS assessment)

        App Service / Function App TLS Bindings:
          - Custom domain TLS bindings and associated certificate expiry
          - Binding type: SNI SSL (correct) vs IP-Based SSL (legacy, costly)
          - Certificate source: Azure-managed (free cert with auto-renewal) vs
            uploaded/Key Vault-linked (requires manual or automated renewal tracking)
          - HTTPS-only enforcement state per app

    RISK MODEL (per certificate finding)
        Critical  — Expired; expiry within 7 days; key size < 2048 bits;
                    self-signed on internet-facing resource; SSL 3.0 / TLS 1.0 binding
        High      — Expiry within 8–30 days; no auto-renewal configured on Key Vault cert;
                    weak cryptographic algorithm (MD5, SHA-1 based); legacy SSL policy
        Medium    — Expiry within 31–90 days; no lifecycle policy; key size = 2048
                    (adequate but not recommended for new certificates); IP-based binding
        Low       — Expiry within 91–180 days; informational gaps; opportunities to
                    improve posture without immediate risk

    BUSINESS IMPACT GUIDANCE
        Each finding includes: Resource → Risk → Business Impact → Recommendation
        Examples: outage probability, compliance exposure (PCI-DSS, NIST, ISO 27001),
        remediation effort and approach (auto-renewal, Key Vault integration, policy).

    OUTPUTS
        - Real-time progress with colour-coded per-subscription results
        - Interactive HTML dashboard: Overview, Key Vault, App Gateway, App Service,
          All Findings (filterable/sortable), Scan Results, Session Info
        - Optional CSV export of all certificate findings

.PARAMETER AllSubscriptions
    Switch. Scans every enabled subscription visible to the authenticated account.
    This is the default when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to assess. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. Exports all certificate findings to -CsvPath. The HTML dashboard is
    always generated regardless of this switch.

.PARAMETER CsvPath
    Destination path for the CSV export. The HTML dashboard uses the same path
    with a .html extension.
    Default: C:\Temp\AzureCertificateGovernance-Report.csv

.PARAMETER ExpiryWarningDays
    Number of days ahead to flag certificates as expiring. Findings with fewer
    than this many days remaining receive at minimum a Medium risk rating.
    Default: 90

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    Always writes an HTML dashboard. Optionally writes a CSV when -ExportToCsv
    is specified. Displays results in an Out-GridView window when GUI is available.

.EXAMPLE
    Get-AzureCertificateGovernanceReport -AllSubscriptions

.EXAMPLE
    Get-AzureCertificateGovernanceReport -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureCertificateGovernanceReport -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\CertGov.csv"

.EXAMPLE
    Get-AzureCertificateGovernanceReport -AllSubscriptions -ExportToCsv -ExpiryWarningDays 180

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Key Vault, Application Gateway, and
                            App Service certificate inventory and risk assessment.
                            Expiry, cryptographic, and configuration risk model.
                            CSV export and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.KeyVault,
           Az.Network, Az.Websites) — installed automatically with user consent.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role at subscription scope (minimum).
        4. Key Vault Certificates Reader (Microsoft.KeyVault/vaults/certificates/read)
           for certificate metadata. Certificate values/secrets are NOT read.
        5. Key Vault access policy or RBAC: Key Vault Certificate User or
           Key Vault Reader on each vault. RBAC-enabled vaults require
           "Key Vault Certificate User" or higher.
        6. Microsoft.Network/applicationGateways/read for App Gateway assessment.
        7. Microsoft.Web/sites/read for App Service assessment.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Certificate private keys and secret values are NOT accessed; only
          certificate metadata (subject, expiry, algorithm, issuer) is read.
        - Application Gateway SSL certificate details (expiry, key size) are
          available via ARM properties only when the certificate data is embedded.
          Key Vault-linked AGW certificates return limited metadata without a
          separate Key Vault lookup, which this script performs automatically.
        - App Service free managed certificates do not expose full X.509 metadata
          through the ARM API; expiry date and domain are reported where available.
        - Get-AzKeyVaultCertificate returns versions only for vaults where the
          caller has the relevant Key Vault access policy or RBAC role. Vaults
          without access are skipped with a warning, not an error.
        - Interactive Grid View requires a GUI session. Gracefully skipped in
          headless/CI/Linux environments; CSV and HTML output are unaffected.
        - Default -CsvPath is Windows-specific. Supply an explicit path on
          macOS or Linux PowerShell 7+.

.LINK
    https://learn.microsoft.com/en-us/azure/key-vault/certificates/about-certificates
    https://learn.microsoft.com/en-us/azure/application-gateway/ssl-overview
    https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-certificate
    https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios

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
  Write-CenteredText "Azure Certificate Governance Report v1.0" -Color White
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
  param(
    [int]$Current,
    [int]$Total,
    [string]$CurrentItem,
    [int]$BarWidth = 40
  )
  $percentage = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
  $completed  = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
  $remaining  = $BarWidth - $completed
  $bar        = ("█" * $completed) + ("░" * $remaining)
  Write-Host "`r" -NoNewline
  Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
  Write-Host $bar -NoNewline -ForegroundColor Cyan
  Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White
  if ($CurrentItem) {
    $maxLen      = 35
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

Function Write-RiskSummary {
  param([array]$Findings)
  if ($Findings.Count -eq 0) { return }
  $c = @($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
  $h = @($Findings | Where-Object { $_.RiskLevel -eq "High"     }).Count
  $m = @($Findings | Where-Object { $_.RiskLevel -eq "Medium"   }).Count
  $l = @($Findings | Where-Object { $_.RiskLevel -eq "Low"      }).Count
  Write-Host ""
  Write-Host "  Risk Level Summary" -ForegroundColor Cyan
  Write-Host "  " -NoNewline
  Write-Host ("─" * 76) -ForegroundColor DarkGray
  Write-Host "  Critical".PadRight(22) -NoNewline -ForegroundColor Gray
  Write-Host ": $c" -ForegroundColor Red
  Write-Host "  High    ".PadRight(22) -NoNewline -ForegroundColor Gray
  Write-Host ": $h" -ForegroundColor Yellow
  Write-Host "  Medium  ".PadRight(22) -NoNewline -ForegroundColor Gray
  Write-Host ": $m" -ForegroundColor DarkYellow
  Write-Host "  Low     ".PadRight(22) -NoNewline -ForegroundColor Gray
  Write-Host ": $l" -ForegroundColor White
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
    Write-Host "  ✓ " -NoNewline -ForegroundColor Green
    Write-Host ("CSV Export").PadRight(22) -NoNewline -ForegroundColor Gray
    Write-Host ": $CsvPath" -ForegroundColor White
  }
  if ($HtmlPath) {
    Write-Host "  ✓ " -NoNewline -ForegroundColor Green
    Write-Host ("HTML Dashboard").PadRight(22) -NoNewline -ForegroundColor Gray
    Write-Host ": $HtmlPath" -ForegroundColor White
  }
  if ($GridViewOpened) {
    Write-Host "  ✓ " -NoNewline -ForegroundColor Green
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

Function Get-CertRiskLevel {
  param(
    [int]$DaysRemaining,
    [string]$Algorithm,
    [int]$KeySize,
    [bool]$IsSelfSigned,
    [bool]$IsInternetFacing,
    [bool]$AutoRenewalEnabled,
    [int]$ExpiryWarningDays
  )

  # Expired or imminent expiry is always Critical
  if ($DaysRemaining -lt 0)  { return "Critical" }
  if ($DaysRemaining -le 7)  { return "Critical" }

  # Self-signed on internet-facing = Critical
  if ($IsSelfSigned -and $IsInternetFacing) { return "Critical" }

  # Weak key size = Critical
  if ($KeySize -gt 0 -and $KeySize -lt 2048) { return "Critical" }

  # Expiring 8-30 days
  if ($DaysRemaining -le 30) {
    # Upgrade severity if no auto-renewal
    if (-not $AutoRenewalEnabled) { return "High" }
    return "High"
  }

  # Self-signed not on internet-facing = High
  if ($IsSelfSigned) { return "High" }

  # No auto-renewal and within warning window = High
  if (-not $AutoRenewalEnabled -and $DaysRemaining -le 60) { return "High" }

  # SHA-1 or MD5 based signature = High
  if ($Algorithm -match "SHA1|MD5|sha1|md5") { return "High" }

  # Expiring 31-90 days
  if ($DaysRemaining -le 90) { return "Medium" }

  # Within warning window but not critical/high
  if ($DaysRemaining -le $ExpiryWarningDays) { return "Medium" }

  return "Low"
}

Function Get-CertImpactAndRecommendation {
  param(
    [string]$RiskLevel,
    [int]$DaysRemaining,
    [bool]$IsSelfSigned,
    [bool]$AutoRenewalEnabled,
    [string]$CertSource,
    [string]$ResourceType,
    [int]$KeySize
  )

  $impact = ""
  $recommendation = ""

  switch ($RiskLevel) {
    "Critical" {
      if ($DaysRemaining -lt 0) {
        $impact = "CERTIFICATE EXPIRED. Service disruption is active or imminent. Clients will receive TLS errors and connections will be refused. This causes direct revenue loss, SLA breach, customer trust damage, and potential compliance violations (PCI-DSS 6.5, ISO 27001 A.10.1)."
        $recommendation = "Renew or replace the certificate immediately. If using Key Vault, trigger manual renewal or update the certificate. For App Gateway, upload the new certificate and update the listener binding. For App Service, replace the binding. Implement auto-renewal to prevent recurrence."
      }
      elseif ($DaysRemaining -le 7) {
        $impact = "Certificate expires in $DaysRemaining day(s). Imminent service disruption will cause TLS handshake failures, customer-facing errors, and potential compliance violation. MTTR for emergency certificate replacement is typically 2-8 hours including change management."
        $recommendation = "Treat as P1 incident. Initiate emergency renewal immediately. Do not wait for scheduled maintenance windows. Escalate to certificate owner and service owner. Enable auto-renewal to prevent recurrence."
      }
      elseif ($IsSelfSigned) {
        $impact = "Self-signed certificate on internet-facing service. Browsers and clients will display security warnings or refuse connections. Cannot be validated by a trusted CA chain — vulnerable to MITM attacks. Non-compliant with PCI-DSS requirement for trusted certificates on internet-facing services."
        $recommendation = "Replace with a certificate issued by a trusted CA (ideally using Azure Key Vault with DigiCert, GlobalSign, or Let's Encrypt integration). Self-signed certificates are acceptable only in isolated internal/dev environments."
      }
      elseif ($KeySize -gt 0 -and $KeySize -lt 2048) {
        $impact = "Key size $($KeySize)-bit is cryptographically weak and no longer acceptable by modern standards (NIST SP 800-131A, PCI-DSS). Vulnerable to factorisation attacks. Modern tooling can break <1024-bit RSA keys. NIST has deprecated <2048-bit since 2011."
        $recommendation = "Replace immediately with minimum 2048-bit RSA (4096-bit recommended for new certificates with >2 year lifetime) or equivalent EC key (P-256 or P-384). Re-key through Key Vault or CSR replacement."
      }
      else {
        $impact = "Critical certificate risk requires immediate attention to prevent service disruption and security exposure."
        $recommendation = "Investigate and remediate immediately. Contact the certificate owner and service team."
      }
    }
    "High" {
      if ($DaysRemaining -le 30) {
        $impact = "Certificate expires in $DaysRemaining day(s). Standard change management timelines may be insufficient. Lead time for CSR signing, approval, upload, and binding updates in enterprise environments is typically 5-15 business days."
        $recommendation = "Initiate renewal immediately. If Key Vault auto-renewal is not configured, raise a certificate renewal request with your CA now. If using Let's Encrypt or ACME, verify automation is functioning correctly."
      }
      elseif (-not $AutoRenewalEnabled) {
        $impact = "No auto-renewal configured. Certificate will expire without intervention. In enterprise environments with manual approval processes, renewal lead time frequently exceeds 30 days, creating outage risk."
        $recommendation = "Enable auto-renewal in Key Vault certificate policy (recommended: renew at 80% of lifetime). Configure the issuer in Key Vault for DigiCert or GlobalSign for fully automated issuance. Alternatively configure ACMEv2/Let's Encrypt for 90-day certificates."
      }
      elseif ($IsSelfSigned) {
        $impact = "Self-signed certificate in use. While not internet-facing, self-signed certificates create trust chain issues, prevent mutual TLS verification, and are flagged by security scanners. Cannot be validated by monitoring tools or WAFs."
        $recommendation = "Replace with an internally-trusted certificate issued by your organisation's internal CA, or migrate to a Key Vault-managed certificate with an integrated CA issuer."
      }
      else {
        $impact = "High certificate risk may cause service disruption or security exposure if not addressed promptly."
        $recommendation = "Schedule remediation within 30 days. Review certificate lifecycle policy and implement auto-renewal where possible."
      }
    }
    "Medium" {
      if ($DaysRemaining -le 90) {
        $impact = "Certificate expires in $DaysRemaining day(s). Renewal should be planned within the next sprint or change cycle to avoid escalation to High/Critical risk."
        $recommendation = "Schedule renewal in the next change window. If auto-renewal is available, verify it is configured and functioning. Test renewal process in a non-production environment first."
      }
      else {
        $impact = "Certificate configuration has a medium-severity gap that does not pose immediate risk but reduces overall security posture."
        $recommendation = "Address in the next quarterly certificate governance review. Consider moving to automated renewal and Key Vault integration for improved lifecycle management."
      }
    }
    default {
      $impact = "Certificate is within governance thresholds but should be included in routine review cycles."
      $recommendation = "No immediate action required. Include in next quarterly certificate inventory review. Consider enabling Key Vault auto-renewal if not already configured."
    }
  }

  return @{ Impact = $impact; Recommendation = $recommendation }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\','\\\\' -replace "'","\'" -replace '"','\"' -replace "`n",' ' -replace "`r",' ' }

Function Generate-CertGovernanceHtml {
  param(
    [hashtable]$SessionInfo,
    [hashtable]$ScanParameters,
    [array]$AllFindings,
    [array]$SubscriptionResults,
    [string]$GeneratedOn
  )

  # ── Aggregate stats ───────────────────────────────────────────────────────
  $totalCerts   = $AllFindings.Count
  $criticalCnt  = @($AllFindings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
  $highCnt      = @($AllFindings | Where-Object { $_.RiskLevel -eq "High"     }).Count
  $mediumCnt    = @($AllFindings | Where-Object { $_.RiskLevel -eq "Medium"   }).Count
  $lowCnt       = @($AllFindings | Where-Object { $_.RiskLevel -eq "Low"      }).Count
  $expiredCnt   = @($AllFindings | Where-Object { $_.DaysRemaining -lt 0 }).Count
  $exp7Cnt      = @($AllFindings | Where-Object { $_.DaysRemaining -ge 0 -and $_.DaysRemaining -le 7  }).Count
  $exp30Cnt     = @($AllFindings | Where-Object { $_.DaysRemaining -gt 7 -and $_.DaysRemaining -le 30 }).Count
  $selfSignedCnt= @($AllFindings | Where-Object { $_.IsSelfSigned -eq $true }).Count
  $noAutoRenew  = @($AllFindings | Where-Object { $_.AutoRenewalEnabled -eq $false -and $_.Source -eq "KeyVault" }).Count

  $kvFindings   = @($AllFindings | Where-Object { $_.Source -eq "KeyVault"    })
  $agwFindings  = @($AllFindings | Where-Object { $_.Source -eq "AppGateway"  })
  $appFindings  = @($AllFindings | Where-Object { $_.Source -eq "AppService"  })

  # ── Risk donut segments ───────────────────────────────────────────────────
  $donutSegments = ""
  if ($totalCerts -gt 0) {
    $donutData = @(
      @{ label = "Critical"; count = $criticalCnt; color = "var(--red)"   }
      @{ label = "High";     count = $highCnt;     color = "var(--amber)" }
      @{ label = "Medium";   count = $mediumCnt;   color = "#d29922"      }
      @{ label = "Low";      count = $lowCnt;      color = "var(--green)" }
    )
    $cx = 54; $cy = 54; $r = 48; $circumference = 2 * [math]::PI * $r
    $offset = 0
    foreach ($seg in $donutData) {
      if ($seg.count -gt 0) {
        $arc  = $circumference * ($seg.count / $totalCerts)
        $dash = [math]::Round($arc, 2)
        $gap  = [math]::Round($circumference - $arc, 2)
        $off  = [math]::Round(-$offset, 2)
        $donutSegments += "<circle r='$r' cx='$cx' cy='$cy' fill='transparent' stroke='$($seg.color)' stroke-width='16' stroke-dasharray='$dash $gap' stroke-dashoffset='$off'/>"
        $offset += $arc
      }
    }
  }

  # ── Distribution bar rows ─────────────────────────────────────────────────
  Function Get-BarRows {
    param([array]$Data, [int]$Total)
    $rows = ""
    foreach ($d in $Data) {
      $pct = if ($Total -gt 0) { [math]::Round(($d.Count / $Total) * 100) } else { 0 }
      $rows += "<div class='bar-row'><span class='bar-label'>$(EscHtml $d.Label)</span><div class='bar-track'><div class='bar-fill' data-pct='$pct' style='background:$(EscHtml $d.Color)'></div></div><span class='bar-pct'>$($d.Count) ($pct%)</span></div>"
    }
    return $rows
  }

  $riskBarRows = Get-BarRows -Total $totalCerts -Data @(
    @{ Label = "Critical"; Count = $criticalCnt; Color = "var(--red)"   }
    @{ Label = "High";     Count = $highCnt;     Color = "var(--amber)" }
    @{ Label = "Medium";   Count = $mediumCnt;   Color = "var(--accent)" }
    @{ Label = "Low";      Count = $lowCnt;      Color = "var(--green)" }
  )

  $sourceBarRows = Get-BarRows -Total $totalCerts -Data @(
    @{ Label = "Key Vault";     Count = $kvFindings.Count;  Color = "var(--accent3)" }
    @{ Label = "App Gateway";   Count = $agwFindings.Count; Color = "var(--accent2)" }
    @{ Label = "App Service";   Count = $appFindings.Count; Color = "var(--accent)"  }
  )

  # ── Table rows helper ─────────────────────────────────────────────────────
  Function Get-FindingTableRows {
    param([array]$Findings)
    $rows = ""
    $idx  = 0
    foreach ($f in ($Findings | Sort-Object RiskOrder, DaysRemaining)) {
      $riskCls = switch ($f.RiskLevel) {
        "Critical" { "badge-red"   }
        "High"     { "badge-amber" }
        "Medium"   { "badge-blue"  }
        default    { "badge-green" }
      }
      $daysDisp = if ($f.DaysRemaining -lt 0) { "EXPIRED ($([math]::Abs($f.DaysRemaining))d ago)" }
                  elseif ($f.DaysRemaining -eq 9999) { "No expiry" }
                  else { "$($f.DaysRemaining)d" }
      $daysColor = if ($f.DaysRemaining -lt 0) { "style='color:var(--red);font-weight:700'" }
                   elseif ($f.DaysRemaining -le 30) { "style='color:var(--amber);font-weight:700'" }
                   else { "" }
      $nameDisp = if ($f.CertificateName.Length -gt 30) { EscHtml($f.CertificateName.Substring(0,27) + "...") } else { EscHtml $f.CertificateName }
      $resDisp  = if ($f.ResourceName.Length -gt 28)    { EscHtml($f.ResourceName.Substring(0,25)    + "...") } else { EscHtml $f.ResourceName    }
      $rows += "<tr onclick='showDetail($($f.GlobalIndex))'><td><span class='badge $riskCls'>$(EscHtml $f.RiskLevel)</span></td><td title='$(EscHtml $f.CertificateName)'>$nameDisp</td><td title='$(EscHtml $f.ResourceName)'>$resDisp</td><td>$(EscHtml $f.SubscriptionName)</td><td $daysColor>$daysDisp</td><td>$(EscHtml $f.ExpiryDate)</td><td>$(EscHtml $f.Algorithm)</td><td>$(if($f.KeySize -gt 0){$f.KeySize}else{'—'})</td><td>$(if($f.IsSelfSigned){'<span class=''badge badge-amber''>Self-signed</span>'}else{'CA'})</td></tr>"
      $idx++
    }
    return $rows
  }

  $allFindingRows  = Get-FindingTableRows -Findings $AllFindings
  $kvFindingRows   = Get-FindingTableRows -Findings $kvFindings
  $agwFindingRows  = Get-FindingTableRows -Findings $agwFindings
  $appFindingRows  = Get-FindingTableRows -Findings $appFindings

  # ── Subscription results ──────────────────────────────────────────────────
  $subRows = ""
  foreach ($s in $SubscriptionResults) {
    $icon = switch ($s.Status) { "Success" { "✓" }; "Warning" { "⚠" }; "Error" { "✗" }; default { "•" } }
    $cls  = switch ($s.Status) { "Success" { "c-green" }; "Warning" { "c-amber" }; "Error" { "c-red" }; default { "" } }
    $subRows += "<div class='sub-row'><span class='sub-icon $cls'>$icon</span><span class='sub-name'>$(EscHtml $s.Name)</span><span class='sub-detail'>$(EscHtml $s.Summary)</span></div>"
  }

  # ── Detail drawer JSON ────────────────────────────────────────────────────
  $detailJson = "["
  foreach ($f in ($AllFindings | Sort-Object GlobalIndex)) {
    $detailJson += "{" +
      """idx"":$($f.GlobalIndex)," +
      """risk"":""$(EscJ $f.RiskLevel)""," +
      """name"":""$(EscJ $f.CertificateName)""," +
      """resource"":""$(EscJ $f.ResourceName)""," +
      """resourceType"":""$(EscJ $f.ResourceType)""," +
      """source"":""$(EscJ $f.Source)""," +
      """sub"":""$(EscJ $f.SubscriptionName)""," +
      """subId"":""$(EscJ $f.SubscriptionId)""," +
      """rg"":""$(EscJ $f.ResourceGroup)""," +
      """expiry"":""$(EscJ $f.ExpiryDate)""," +
      """days"":$($f.DaysRemaining)," +
      """alg"":""$(EscJ $f.Algorithm)""," +
      """keySize"":$($f.KeySize)," +
      """selfSigned"":$(if($f.IsSelfSigned){'true'}else{'false'})," +
      """autoRenew"":$(if($f.AutoRenewalEnabled){'true'}else{'false'})," +
      """issuer"":""$(EscJ $f.Issuer)""," +
      """subject"":""$(EscJ $f.Subject)""," +
      """thumbprint"":""$(EscJ $f.Thumbprint)""," +
      """impact"":""$(EscJ $f.Impact)""," +
      """recommendation"":""$(EscJ $f.Recommendation)""" +
      "},"
  }
  $detailJson = $detailJson.TrimEnd(",") + "]"

  $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Certificate Governance Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;--border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;--green:#3fb950;--amber:#d29922;--red:#f85149;--text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;--mono:'JetBrains Mono','Consolas','Courier New',monospace;--sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;--radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);}
html[data-theme="light"]{--bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;--border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;--green:#1a7f37;--amber:#b08000;--red:#cf222e;--text:#1f2328;--muted:#636c76;--muted2:#424a53;--shadow:0 4px 24px rgba(0,0,0,.12);}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;}
#sidebar{width:240px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:transform .25s;}
.logo-block{padding:22px 18px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:22px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;cursor:default;}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-red{border-top-color:var(--red);}.stat-card.c-amber{border-top-color:var(--amber);}.stat-card.c-blue{border-top-color:var(--accent);}.stat-card.c-green{border-top-color:var(--green);}.stat-card.c-purple{border-top-color:var(--accent3);}.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-num{font-size:28px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:13px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:130px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
.donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.legend-list{display:flex;flex-direction:column;gap:8px;}
.legend-item{display:flex;align-items:center;gap:10px;font-size:13px;}
.legend-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;}
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
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.sub-list{display:flex;flex-direction:column;}
.sub-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}.sub-icon.c-amber{color:var(--amber);}.sub-icon.c-red{color:var(--red);}
.sub-name{flex:1;font-size:13px;font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:480px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
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
.drawer-field-value{font-size:13px;word-break:break-all;line-height:1.5;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.impact-box{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.25);border-radius:var(--radius-sm);padding:12px;font-size:12px;line-height:1.6;margin-bottom:10px;}
.rec-box{background:rgba(56,139,253,.08);border:1px solid rgba(56,139,253,.25);border-radius:var(--radius-sm);padding:12px;font-size:12px;line-height:1.6;}
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
    <div class="logo-icon">🔐</div>
    <div class="logo-title">Certificate Governance</div>
    <div class="logo-sub">Azure Certificate Report</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('all',this)"><span class="nav-icon">📋</span> All Findings</button>
    <button class="nav-btn" onclick="showPage('kv',this)"><span class="nav-icon">🏛️</span> Key Vault</button>
    <button class="nav-btn" onclick="showPage('agw',this)"><span class="nav-icon">🌐</span> App Gateway</button>
    <button class="nav-btn" onclick="showPage('app',this)"><span class="nav-icon">⚡</span> App Service</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">🔍</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle"><span>Dark mode</span><button class="toggle-pill" onclick="toggleTheme()"></button></div>
    <div class="footer-meta">Generated: __GENERATED_ON__<br/>Azure Certificate Governance</div>
  </div>
</nav>
<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Certificate Governance Overview</div>
      <div class="page-sub">Certificate posture across __SUB_COUNT__ subscription(s) — __TOTAL_CERTS__ certificate(s) assessed</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-red"><div class="stat-num">__CRITICAL_CNT__</div><div class="stat-label">Critical</div><div class="stat-sub">Expired or expiring ≤7d</div></div>
      <div class="stat-card c-amber"><div class="stat-num">__HIGH_CNT__</div><div class="stat-label">High</div><div class="stat-sub">Expiring 8–30d / no auto-renew</div></div>
      <div class="stat-card c-blue"><div class="stat-num">__MEDIUM_CNT__</div><div class="stat-label">Medium</div><div class="stat-sub">Expiring 31–90d</div></div>
      <div class="stat-card c-green"><div class="stat-num">__LOW_CNT__</div><div class="stat-label">Low</div><div class="stat-sub">Expiring 91–180d</div></div>
      <div class="stat-card c-red"><div class="stat-num">__EXPIRED_CNT__</div><div class="stat-label">Expired</div><div class="stat-sub">Already past expiry</div></div>
      <div class="stat-card c-amber"><div class="stat-num">__EXP7_CNT__</div><div class="stat-label">≤7 Days</div><div class="stat-sub">Imminent expiry</div></div>
      <div class="stat-card c-amber"><div class="stat-num">__SELF_SIGNED_CNT__</div><div class="stat-label">Self-signed</div><div class="stat-sub">No trusted CA chain</div></div>
      <div class="stat-card c-purple"><div class="stat-num">__NO_AUTO_RENEW__</div><div class="stat-label">No Auto-Renew</div><div class="stat-sub">Key Vault certs only</div></div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Risk Distribution</div>
        <div class="donut-wrap">
          <svg viewBox="0 0 108 108" width="120" height="120" style="transform:rotate(-90deg);flex-shrink:0">
            <circle r="48" cx="54" cy="54" fill="transparent" stroke="var(--surface3)" stroke-width="16"/>
            __DONUT_SEGMENTS__
          </svg>
          <div class="legend-list">
            <div class="legend-item"><span class="legend-dot" style="background:var(--red)"></span><span>Critical</span><span style="margin-left:auto;font-family:var(--mono);font-weight:700">__CRITICAL_CNT__</span></div>
            <div class="legend-item"><span class="legend-dot" style="background:var(--amber)"></span><span>High</span><span style="margin-left:auto;font-family:var(--mono);font-weight:700">__HIGH_CNT__</span></div>
            <div class="legend-item"><span class="legend-dot" style="background:var(--accent)"></span><span>Medium</span><span style="margin-left:auto;font-family:var(--mono);font-weight:700">__MEDIUM_CNT__</span></div>
            <div class="legend-item"><span class="legend-dot" style="background:var(--green)"></span><span>Low</span><span style="margin-left:auto;font-family:var(--mono);font-weight:700">__LOW_CNT__</span></div>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">🏷️ By Source</div>
        __SOURCE_BAR_ROWS__
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">📊 Risk Level Breakdown</div>
      __RISK_BAR_ROWS__
    </div>
  </div>

  <!-- All Findings -->
  <div id="page-all" class="page">
    <div class="page-header"><div class="page-title">All Certificate Findings</div><div class="page-sub">All certificates across all sources, sorted by risk. Click any row for details.</div></div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap"><span class="search-icon">🔍</span><input type="text" id="allSearch" placeholder="Search name, resource, subscription…" oninput="filterTable('all')"/></div>
        <select class="filter-select" id="allRiskFilter" onchange="filterTable('all')"><option value="">All Risks</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option></select>
        <select class="filter-select" id="allSourceFilter" onchange="filterTable('all')"><option value="">All Sources</option><option value="KeyVault">Key Vault</option><option value="AppGateway">App Gateway</option><option value="AppService">App Service</option></select>
        <select class="filter-select" id="allPageSz" onchange="changePageSize('all')"><option value="20">20/page</option><option value="50">50/page</option><option value="100">100/page</option></select>
      </div>
      <div class="tbl-wrap"><table><thead><tr><th>Risk</th><th>Certificate</th><th>Resource</th><th>Subscription</th><th>Days Left</th><th>Expiry Date</th><th>Algorithm</th><th>Key Size</th><th>Trust</th></tr></thead><tbody id="allBody">__ALL_ROWS__</tbody></table></div>
      <div class="pagination" id="allPagination"></div>
    </div>
  </div>

  <!-- Key Vault -->
  <div id="page-kv" class="page">
    <div class="page-header"><div class="page-title">Key Vault Certificates</div><div class="page-sub">Certificate governance findings from Azure Key Vault. Click any row for details.</div></div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap"><span class="search-icon">🔍</span><input type="text" id="kvSearch" placeholder="Search certificate or vault name…" oninput="filterTable('kv')"/></div>
        <select class="filter-select" id="kvRiskFilter" onchange="filterTable('kv')"><option value="">All Risks</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option></select>
      </div>
      <div class="tbl-wrap"><table><thead><tr><th>Risk</th><th>Certificate</th><th>Resource</th><th>Subscription</th><th>Days Left</th><th>Expiry Date</th><th>Algorithm</th><th>Key Size</th><th>Trust</th></tr></thead><tbody id="kvBody">__KV_ROWS__</tbody></table></div>
      <div class="pagination" id="kvPagination"></div>
    </div>
  </div>

  <!-- App Gateway -->
  <div id="page-agw" class="page">
    <div class="page-header"><div class="page-title">Application Gateway Certificates</div><div class="page-sub">SSL certificate findings from Azure Application Gateway listeners. Click any row for details.</div></div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap"><span class="search-icon">🔍</span><input type="text" id="agwSearch" placeholder="Search certificate or gateway name…" oninput="filterTable('agw')"/></div>
        <select class="filter-select" id="agwRiskFilter" onchange="filterTable('agw')"><option value="">All Risks</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option></select>
      </div>
      <div class="tbl-wrap"><table><thead><tr><th>Risk</th><th>Certificate</th><th>Resource</th><th>Subscription</th><th>Days Left</th><th>Expiry Date</th><th>Algorithm</th><th>Key Size</th><th>Trust</th></tr></thead><tbody id="agwBody">__AGW_ROWS__</tbody></table></div>
      <div class="pagination" id="agwPagination"></div>
    </div>
  </div>

  <!-- App Service -->
  <div id="page-app" class="page">
    <div class="page-header"><div class="page-title">App Service Certificates</div><div class="page-sub">TLS binding certificate findings from App Service and Function Apps. Click any row for details.</div></div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap"><span class="search-icon">🔍</span><input type="text" id="appSearch" placeholder="Search certificate or app name…" oninput="filterTable('app')"/></div>
        <select class="filter-select" id="appRiskFilter" onchange="filterTable('app')"><option value="">All Risks</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option></select>
      </div>
      <div class="tbl-wrap"><table><thead><tr><th>Risk</th><th>Certificate</th><th>Resource</th><th>Subscription</th><th>Days Left</th><th>Expiry Date</th><th>Algorithm</th><th>Key Size</th><th>Trust</th></tr></thead><tbody id="appBody">__APP_ROWS__</tbody></table></div>
      <div class="pagination" id="appPagination"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header"><div class="page-title">Subscription Scan Results</div><div class="page-sub">Per-subscription scan outcome and certificate counts.</div></div>
    <div class="panel"><div class="sub-list">__SUB_ROWS__</div></div>
  </div>

  <!-- Session Info -->
  <div id="page-session" class="page">
    <div class="page-header"><div class="page-title">Session &amp; Scan Parameters</div></div>
    <div class="panel">
      <div class="panel-title">🔐 Session Information</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Tenant</div><div class="info-value">__TENANT__</div></div>
        <div class="info-card"><div class="info-label">Account</div><div class="info-value">__ACCOUNT__</div></div>
        <div class="info-card"><div class="info-label">Environment</div><div class="info-value">__ENVIRONMENT__</div></div>
        <div class="info-card"><div class="info-label">Generated</div><div class="info-value">__GENERATED_ON__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">⚙️ Scan Parameters</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Scope</div><div class="info-value">__SCOPE__</div></div>
        <div class="info-card"><div class="info-label">Expiry Warning (days)</div><div class="info-value">__EXPIRY_DAYS__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
      </div>
    </div>
  </div>
</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Certificate Detail</span>
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
const DETAIL_DATA = __DETAIL_JSON__;
const RISK_ORDER  = {Critical:0,High:1,Medium:2,Low:3};

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// ── Page navigation ─────────────────────────────────────────────────────────
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
}
function toggleTheme(){document.documentElement.dataset.theme=document.documentElement.dataset.theme==='dark'?'light':'dark';}

// ── Table state per tab ─────────────────────────────────────────────────────
const tabState={
  all:{page:1,pageSize:20,sortCol:'risk',sortAsc:true,filtered:[]},
  kv: {page:1,pageSize:20,sortCol:'risk',sortAsc:true,filtered:[]},
  agw:{page:1,pageSize:20,sortCol:'risk',sortAsc:true,filtered:[]},
  app:{page:1,pageSize:20,sortCol:'risk',sortAsc:true,filtered:[]}
};

// Pre-parse the table rows from server-rendered HTML into JS arrays
const ROWS={};
['all','kv','agw','app'].forEach(tab=>{
  ROWS[tab]=Array.from(document.getElementById(tab+'Body').querySelectorAll('tr')).map(tr=>({
    el:tr,
    risk:tr.querySelector('td:nth-child(1)')?.textContent.trim()||'',
    name:tr.querySelector('td:nth-child(2)')?.textContent.trim()||'',
    resource:tr.querySelector('td:nth-child(3)')?.textContent.trim()||'',
    sub:tr.querySelector('td:nth-child(4)')?.textContent.trim()||'',
    days:parseInt(tr.querySelector('td:nth-child(5)')?.getAttribute('data-days')||'9999'),
    source:tr.getAttribute('data-source')||''
  }));
  tabState[tab].filtered=[...ROWS[tab]];
});

function filterTable(tab){
  const q=(document.getElementById(tab+'Search')?.value||'').toLowerCase();
  const r=(document.getElementById(tab+'RiskFilter')?.value||'');
  const s=(document.getElementById(tab+'SourceFilter')?.value||'');
  tabState[tab].filtered=ROWS[tab].filter(row=>{
    const mQ=!q||row.name.toLowerCase().includes(q)||row.resource.toLowerCase().includes(q)||row.sub.toLowerCase().includes(q);
    const mR=!r||row.risk===r;
    const mS=!s||row.source===s;
    return mQ&&mR&&mS;
  });
  tabState[tab].page=1;
  renderTable(tab);
}

function changePageSize(tab){
  const el=document.getElementById(tab+'PageSz');
  if(el) tabState[tab].pageSize=parseInt(el.value);
  tabState[tab].page=1;
  renderTable(tab);
}

function renderTable(tab){
  const st=tabState[tab];
  const tbody=document.getElementById(tab+'Body');
  const start=(st.page-1)*st.pageSize;
  const slice=st.filtered.slice(start,start+st.pageSize);
  tbody.innerHTML='';
  slice.forEach(r=>tbody.appendChild(r.el));
  renderPagination(tab);
}

function renderPagination(tab){
  const st=tabState[tab];
  const total=Math.ceil(st.filtered.length/st.pageSize);
  const el=document.getElementById(tab+'Pagination');
  if(!el)return;
  let h=`<span>${st.filtered.length} record(s)</span>`;
  h+=`<button class="pg-btn" onclick="changePage('${tab}',${st.page-1})" ${st.page<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,st.page-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===st.page?'active':''}" onclick="changePage('${tab}',${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changePage('${tab}',${st.page+1})" ${st.page>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changePage(tab,p){
  const st=tabState[tab];
  const total=Math.ceil(st.filtered.length/st.pageSize);
  if(p<1||p>total)return;
  st.page=p;renderTable(tab);
}

// ── Detail drawer ────────────────────────────────────────────────────────────
let currentDetailIdx=0;
let currentDetailList=[];

function showDetail(globalIdx){
  const r=DETAIL_DATA.find(d=>d.idx===globalIdx);
  if(!r)return;
  currentDetailIdx=globalIdx;
  currentDetailList=DETAIL_DATA;
  renderDrawer(r);
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}

function renderDrawer(r){
  document.getElementById('drawerTitle').textContent=r.name;
  const pos=DETAIL_DATA.findIndex(d=>d.idx===r.idx)+1;
  document.getElementById('drawerNavInfo').textContent=`${pos} of ${DETAIL_DATA.length}`;
  const riskCls=r.risk==='Critical'?'badge-red':r.risk==='High'?'badge-amber':r.risk==='Medium'?'badge-blue':'badge-green';
  const daysDisp=r.days<0?`EXPIRED (${Math.abs(r.days)}d ago)`:r.days===9999?'No expiry set':`${r.days} day(s)`;
  const daysColor=r.days<0?'var(--red)':r.days<=30?'var(--amber)':'var(--text)';
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Risk Level</div><div class="drawer-field-value"><span class="badge ${riskCls}">${escH(r.risk)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Source</div><div class="drawer-field-value">${escH(r.source)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource</div><div class="drawer-field-value">${escH(r.resource)} (${escH(r.resourceType)})</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div><div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div><div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-section">Certificate Details</div>
    <div class="drawer-field"><div class="drawer-field-label">Subject</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.subject)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Issuer</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.issuer)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Thumbprint</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.thumbprint)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Algorithm</div><div class="drawer-field-value">${escH(r.alg)||'—'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Key Size</div><div class="drawer-field-value">${r.keySize>0?r.keySize+' bits':'Not available'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Trust Type</div><div class="drawer-field-value">${r.selfSigned?'<span class="badge badge-amber">Self-signed</span>':'CA-Issued'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Auto-Renewal</div><div class="drawer-field-value">${r.source==='KeyVault'?(r.autoRenew?'<span class="badge badge-green">Enabled</span>':'<span class="badge badge-red">Disabled</span>'):'N/A'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Expiry Date</div><div class="drawer-field-value">${escH(r.expiry)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Days Remaining</div><div class="drawer-field-value" style="font-weight:700;color:${daysColor}">${daysDisp}</div></div>
    <div class="drawer-section">Business Impact</div>
    <div class="impact-box">${escH(r.impact)}</div>
    <div class="drawer-section">Recommendation</div>
    <div class="rec-box">${escH(r.recommendation)}</div>
  `;
}

function closeDrawer(){
  document.getElementById('drawerBackdrop').style.display='none';
  document.getElementById('detailDrawer').classList.remove('open');
}

function navDetail(dir){
  const cur=currentDetailList.findIndex(d=>d.idx===currentDetailIdx);
  const next=cur+dir;
  if(next>=0&&next<currentDetailList.length){
    currentDetailIdx=currentDetailList[next].idx;
    renderDrawer(currentDetailList[next]);
  }
}

function showToast(msg){
  const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{el.style.width=el.dataset.pct+'%';});
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

// ── Init ────────────────────────────────────────────────────────────────────
['all','kv','agw','app'].forEach(tab=>{renderTable(tab);});
animateBars();
</script>
</body>
</html>
'@

  $html = $html `
    -replace '__GENERATED_ON__',   $GeneratedOn `
    -replace '__SUB_COUNT__',      ($SubscriptionResults.Count) `
    -replace '__TOTAL_CERTS__',    $totalCerts `
    -replace '__CRITICAL_CNT__',   $criticalCnt `
    -replace '__HIGH_CNT__',       $highCnt `
    -replace '__MEDIUM_CNT__',     $mediumCnt `
    -replace '__LOW_CNT__',        $lowCnt `
    -replace '__EXPIRED_CNT__',    $expiredCnt `
    -replace '__EXP7_CNT__',       $exp7Cnt `
    -replace '__SELF_SIGNED_CNT__',$selfSignedCnt `
    -replace '__NO_AUTO_RENEW__',  $noAutoRenew `
    -replace '__DONUT_SEGMENTS__', $donutSegments `
    -replace '__SOURCE_BAR_ROWS__',$sourceBarRows `
    -replace '__RISK_BAR_ROWS__',  $riskBarRows `
    -replace '__ALL_ROWS__',       $allFindingRows `
    -replace '__KV_ROWS__',        $kvFindingRows `
    -replace '__AGW_ROWS__',       $agwFindingRows `
    -replace '__APP_ROWS__',       $appFindingRows `
    -replace '__SUB_ROWS__',       $subRows `
    -replace '__TENANT__',         $SessionInfo.Tenant `
    -replace '__ACCOUNT__',        $SessionInfo.Account `
    -replace '__ENVIRONMENT__',    $SessionInfo.Environment `
    -replace '__SCOPE__',          $ScanParameters.Scope `
    -replace '__EXPIRY_DAYS__',    $ScanParameters.ExpiryWarningDays `
    -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
    -replace '__EXEC_TIME__',      $ScanParameters.ExecTime `
    -replace '__DETAIL_JSON__',    $detailJson

  return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureCertificateGovernanceReport {
  [CmdletBinding()]
  param (
    [switch]$AllSubscriptions,

    [string[]]$SubscriptionIds,

    [switch]$ExportToCsv,

    [ValidateNotNullOrEmpty()]
    [string]$CsvPath = "C:\Temp\AzureCertificateGovernance-Report.csv",

    [ValidateRange(1, 730)]
    [int]$ExpiryWarningDays = 90
  )

  $startTime = Get-Date
  Write-Banner

  # ── Module check ──────────────────────────────────────────────────────────
  $requiredModules = @("Az.Accounts", "Az.Resources", "Az.KeyVault", "Az.Network", "Az.Websites")
  $missingModules  = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

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
    $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' })
    $scopeText = "All Subscriptions"
  }
  else {
    $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
      Where-Object { $SubscriptionIds -contains $_.Id })
    $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count))"
  }

  $subCount = $subscriptions.Count

  Write-Section -Title "Session Information" -Data @{
    "Tenant"              = $ctx.Tenant.Id
    "Account"             = $ctx.Account.Id
    "Environment"         = $ctx.Environment.Name
  }

  Write-Section -Title "Scan Parameters" -Data @{
    "Scope"               = "$scopeText ($subCount found)"
    "Expiry Warning Days" = "$ExpiryWarningDays days"
    "Export to CSV"       = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
    "Export Path"         = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
  }

  # ── Collections ───────────────────────────────────────────────────────────
  $allFindings         = @()
  $subscriptionResults = @()
  $globalIndex         = 0
  $successCount        = 0
  $errorCount          = 0
  $now                 = Get-Date

  # ── Scan ──────────────────────────────────────────────────────────────────
  Write-ScanProgress
  Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

  $maxNameLen = [math]::Max(
    ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum, 35)

  $subIndex = 1

  foreach ($sub in $subscriptions) {
    try {
      Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name
      Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

      $subCertCount = 0

      # ================================================================
      # SOURCE 1: Key Vault Certificates
      # ================================================================
      try {
        $vaults = @(Get-AzKeyVault -WarningAction SilentlyContinue -ErrorAction Stop)
        foreach ($vault in $vaults) {
          try {
            $kvCerts = @(Get-AzKeyVaultCertificate -VaultName $vault.VaultName -ErrorAction Stop)
            foreach ($kvc in $kvCerts) {
              try {
                # Get full certificate details
                $certDetail = Get-AzKeyVaultCertificate -VaultName $vault.VaultName -Name $kvc.Name -ErrorAction Stop

                $expiryDate    = "Unknown"
                $daysRemaining = 9999
                $algorithm     = "Unknown"
                $keySize       = 0
                $subject       = ""
                $issuer        = ""
                $thumbprint    = ""
                $isSelfSigned  = $false
                $autoRenew     = $false

                # Expiry
                try {
                  if ($certDetail.Expires) {
                    $expiryDate    = $certDetail.Expires.ToString("yyyy-MM-dd")
                    $daysRemaining = [math]::Floor(($certDetail.Expires - $now).TotalDays)
                  }
                }
                catch { }

                # Cryptographic details
                try {
                  if ($certDetail.Certificate) {
                    $x509           = $certDetail.Certificate
                    $algorithm      = $x509.SignatureAlgorithm.FriendlyName
                    $subject        = $x509.Subject
                    $issuer         = $x509.Issuer
                    $thumbprint     = $x509.Thumbprint
                    $isSelfSigned   = ($x509.Subject -eq $x509.Issuer)

                    # Key size (best-effort — RSA only via PublicKey)
                    try {
                      $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($x509)
                      if ($rsa) { $keySize = $rsa.KeySize }
                    }
                    catch {
                      # EC or other key type — key size not extractable via RSA method
                      if ($x509.PublicKey.Key -is [System.Security.Cryptography.ECDsa]) {
                        $keySize = $x509.PublicKey.Key.KeySize
                      }
                    }
                  }
                }
                catch { Write-Verbose "  Could not read X509 for $($kvc.Name): $_" }

                # Auto-renewal policy
                try {
                  $policy = Get-AzKeyVaultCertificatePolicy -VaultName $vault.VaultName -Name $kvc.Name -ErrorAction Stop
                  $autoRenew = ($null -ne $policy -and $policy.RenewAtPercentageLifetime -gt 0)
                }
                catch { }

                $riskLevel = Get-CertRiskLevel -DaysRemaining $daysRemaining -Algorithm $algorithm `
                  -KeySize $keySize -IsSelfSigned $isSelfSigned -IsInternetFacing $false `
                  -AutoRenewalEnabled $autoRenew -ExpiryWarningDays $ExpiryWarningDays

                $impactRec = Get-CertImpactAndRecommendation -RiskLevel $riskLevel `
                  -DaysRemaining $daysRemaining -IsSelfSigned $isSelfSigned `
                  -AutoRenewalEnabled $autoRenew -CertSource "KeyVault" `
                  -ResourceType "Key Vault" -KeySize $keySize

                $finding = [pscustomobject]@{
                  GlobalIndex        = $globalIndex
                  RiskLevel          = $riskLevel
                  RiskOrder          = @{ Critical=0; High=1; Medium=2; Low=3 }[$riskLevel]
                  Source             = "KeyVault"
                  SubscriptionName   = $sub.Name
                  SubscriptionId     = $sub.Id
                  ResourceGroup      = $vault.ResourceGroupName
                  ResourceName       = $vault.VaultName
                  ResourceType       = "Microsoft.KeyVault/vaults"
                  CertificateName    = $kvc.Name
                  ExpiryDate         = $expiryDate
                  DaysRemaining      = $daysRemaining
                  Algorithm          = $algorithm
                  KeySize            = $keySize
                  IsSelfSigned       = $isSelfSigned
                  AutoRenewalEnabled = $autoRenew
                  Subject            = $subject
                  Issuer             = $issuer
                  Thumbprint         = $thumbprint
                  Impact             = $impactRec.Impact
                  Recommendation     = $impactRec.Recommendation
                }
                $allFindings += $finding
                $globalIndex++
                $subCertCount++
              }
              catch {
                Write-Verbose "  Could not assess cert '$($kvc.Name)' in vault '$($vault.VaultName)': $_"
              }
            }
          }
          catch {
            Write-Warning "  Access denied or error reading vault '$($vault.VaultName)': $_"
          }
        }
      }
      catch {
        Write-Verbose "  Could not enumerate Key Vaults for $($sub.Name): $_"
      }

      # ================================================================
      # SOURCE 2: Application Gateway SSL Certificates
      # ================================================================
      try {
        $gateways = @(Get-AzApplicationGateway -ErrorAction Stop)
        foreach ($gw in $gateways) {
          # Check SSL Policy
          $sslPolicyName = "Not Configured"
          $sslPolicyType = "None"
          try {
            if ($gw.SslPolicy) {
              $sslPolicyName = if ($gw.SslPolicy.PolicyName) { $gw.SslPolicy.PolicyName } else { "Custom" }
              $sslPolicyType = if ($gw.SslPolicy.PolicyType) { $gw.SslPolicy.PolicyType } else { "Unknown" }
            }
          }
          catch { }

          $isLegacySslPolicy = ($sslPolicyType -eq "None" -or $sslPolicyName -notmatch "20220101")

          # Iterate SSL certificates on the gateway
          $sslCerts = @(Get-ObjProperty -Obj $gw -PropName 'SslCertificates' -Default @())
          foreach ($sslCert in $sslCerts) {
            $expiryDate    = "Unknown"
            $daysRemaining = 9999
            $algorithm     = "Unknown"
            $keySize       = 0
            $subject       = ""
            $issuer        = ""
            $thumbprint    = ""
            $isSelfSigned  = $false

            # Try to parse embedded cert data
            try {
              $certData = Get-ObjProperty -Obj $sslCert.Properties -PropName 'publicCertData' -Default $null
              if ($certData) {
                $certBytes = [System.Convert]::FromBase64String($certData)
                $x509      = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 ($certBytes, $null)
                $expiryDate    = $x509.NotAfter.ToString("yyyy-MM-dd")
                $daysRemaining = [math]::Floor(($x509.NotAfter - $now).TotalDays)
                $algorithm     = $x509.SignatureAlgorithm.FriendlyName
                $subject       = $x509.Subject
                $issuer        = $x509.Issuer
                $thumbprint    = $x509.Thumbprint
                $isSelfSigned  = ($x509.Subject -eq $x509.Issuer)
                try {
                  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($x509)
                  if ($rsa) { $keySize = $rsa.KeySize }
                }
                catch { }
              }
            }
            catch {
              # If no embedded data, check for Key Vault reference
              try {
                $kvSecretId = Get-ObjProperty -Obj $sslCert.Properties -PropName 'keyVaultSecretId' -Default $null
                if ($kvSecretId) {
                  # Try to extract vault name and cert name from the secret ID URI
                  if ($kvSecretId -match "https://([^.]+)\.vault\.azure\.net/secrets/([^/]+)") {
                    $refVaultName = $Matches[1]
                    $refCertName  = $Matches[2]
                    try {
                      $refCert = Get-AzKeyVaultCertificate -VaultName $refVaultName -Name $refCertName -ErrorAction Stop
                      if ($refCert.Expires) {
                        $expiryDate    = $refCert.Expires.ToString("yyyy-MM-dd")
                        $daysRemaining = [math]::Floor(($refCert.Expires - $now).TotalDays)
                      }
                      if ($refCert.Certificate) {
                        $algorithm    = $refCert.Certificate.SignatureAlgorithm.FriendlyName
                        $subject      = $refCert.Certificate.Subject
                        $issuer       = $refCert.Certificate.Issuer
                        $thumbprint   = $refCert.Certificate.Thumbprint
                        $isSelfSigned = ($refCert.Certificate.Subject -eq $refCert.Certificate.Issuer)
                      }
                    }
                    catch { Write-Verbose "  Could not read KV cert reference '$refCertName' from '$refVaultName': $_" }
                  }
                }
              }
              catch { }
            }

            $certName = if ($sslCert.Name) { $sslCert.Name } else { "UnnamedCert" }

            # AGW certs are internet-facing by nature
            $riskLevel = Get-CertRiskLevel -DaysRemaining $daysRemaining -Algorithm $algorithm `
              -KeySize $keySize -IsSelfSigned $isSelfSigned -IsInternetFacing $true `
              -AutoRenewalEnabled $false -ExpiryWarningDays $ExpiryWarningDays

            # Elevate risk if legacy SSL policy
            if ($isLegacySslPolicy -and $riskLevel -eq "Low")    { $riskLevel = "Medium" }
            if ($isLegacySslPolicy -and $riskLevel -eq "Medium")  { $riskLevel = "High" }

            $impactRec = Get-CertImpactAndRecommendation -RiskLevel $riskLevel `
              -DaysRemaining $daysRemaining -IsSelfSigned $isSelfSigned `
              -AutoRenewalEnabled $false -CertSource "AppGateway" `
              -ResourceType "Application Gateway" -KeySize $keySize

            $finding = [pscustomobject]@{
              GlobalIndex        = $globalIndex
              RiskLevel          = $riskLevel
              RiskOrder          = @{ Critical=0; High=1; Medium=2; Low=3 }[$riskLevel]
              Source             = "AppGateway"
              SubscriptionName   = $sub.Name
              SubscriptionId     = $sub.Id
              ResourceGroup      = $gw.ResourceGroupName
              ResourceName       = $gw.Name
              ResourceType       = "Microsoft.Network/applicationGateways"
              CertificateName    = $certName
              ExpiryDate         = $expiryDate
              DaysRemaining      = $daysRemaining
              Algorithm          = $algorithm
              KeySize            = $keySize
              IsSelfSigned       = $isSelfSigned
              AutoRenewalEnabled = $false
              Subject            = $subject
              Issuer             = $issuer
              Thumbprint         = $thumbprint
              Impact             = $impactRec.Impact
              Recommendation     = $impactRec.Recommendation
            }
            $allFindings += $finding
            $globalIndex++
            $subCertCount++
          }
        }
      }
      catch {
        Write-Verbose "  Could not enumerate Application Gateways for $($sub.Name): $_"
      }

      # ================================================================
      # SOURCE 3: App Service / Function App TLS Bindings
      # ================================================================
      try {
        $webApps = @(Get-AzWebApp -ErrorAction Stop)
        foreach ($app in $webApps) {
          try {
            $hostNameSslStates = @(Get-ObjProperty -Obj $app -PropName 'HostNameSslStates' -Default @())
            foreach ($binding in $hostNameSslStates) {
              $sslState = Get-ObjProperty -Obj $binding -PropName 'SslState' -Default "Disabled"
              if ($sslState -eq "Disabled") { continue }

              $thumbprint    = Get-ObjProperty -Obj $binding -PropName 'Thumbprint' -Default ""
              $hostName      = Get-ObjProperty -Obj $binding -PropName 'Name' -Default $app.Name
              $expiryDate    = "Unknown"
              $daysRemaining = 9999
              $algorithm     = "Unknown"
              $keySize       = 0
              $subject       = $hostName
              $issuer        = "Unknown"
              $isSelfSigned  = $false

              # Look up the certificate by thumbprint
              if ($thumbprint) {
                try {
                  $appCert = Get-AzWebAppCertificate -ResourceGroupName $app.ResourceGroup -Thumbprint $thumbprint -ErrorAction Stop
                  if ($appCert) {
                    if ($appCert.ExpirationDate) {
                      $expiryDate    = $appCert.ExpirationDate.ToString("yyyy-MM-dd")
                      $daysRemaining = [math]::Floor(($appCert.ExpirationDate - $now).TotalDays)
                    }
                    $subject = Get-ObjProperty -Obj $appCert -PropName 'SubjectName' -Default $hostName
                    $issuer  = Get-ObjProperty -Obj $appCert -PropName 'Issuer'      -Default "Unknown"
                    # Basic self-signed heuristic for app certs
                    $isSelfSigned = ($issuer -match "Self" -or $subject -eq $issuer)
                  }
                }
                catch { Write-Verbose "  Could not look up app cert by thumbprint '$thumbprint' for '$($app.Name)': $_" }
              }

              $riskLevel = Get-CertRiskLevel -DaysRemaining $daysRemaining -Algorithm $algorithm `
                -KeySize $keySize -IsSelfSigned $isSelfSigned -IsInternetFacing $true `
                -AutoRenewalEnabled $false -ExpiryWarningDays $ExpiryWarningDays

              $impactRec = Get-CertImpactAndRecommendation -RiskLevel $riskLevel `
                -DaysRemaining $daysRemaining -IsSelfSigned $isSelfSigned `
                -AutoRenewalEnabled $false -CertSource "AppService" `
                -ResourceType "App Service" -KeySize $keySize

              $finding = [pscustomobject]@{
                GlobalIndex        = $globalIndex
                RiskLevel          = $riskLevel
                RiskOrder          = @{ Critical=0; High=1; Medium=2; Low=3 }[$riskLevel]
                Source             = "AppService"
                SubscriptionName   = $sub.Name
                SubscriptionId     = $sub.Id
                ResourceGroup      = $app.ResourceGroup
                ResourceName       = $app.Name
                ResourceType       = "Microsoft.Web/sites"
                CertificateName    = $hostName
                ExpiryDate         = $expiryDate
                DaysRemaining      = $daysRemaining
                Algorithm          = $algorithm
                KeySize            = $keySize
                IsSelfSigned       = $isSelfSigned
                AutoRenewalEnabled = $false
                Subject            = $subject
                Issuer             = $issuer
                Thumbprint         = $thumbprint
                Impact             = $impactRec.Impact
                Recommendation     = $impactRec.Recommendation
              }
              $allFindings += $finding
              $globalIndex++
              $subCertCount++
            }
          }
          catch {
            Write-Verbose "  Could not assess App Service '$($app.Name)': $_"
          }
        }
      }
      catch {
        Write-Verbose "  Could not enumerate App Services for $($sub.Name): $_"
      }

      # ── Per-subscription result ───────────────────────────────────────
      Write-Host "`r$(' ' * 120)`r" -NoNewline
      $paddedName = $sub.Name.PadRight($maxNameLen)

      $critCount = @($allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id -and $_.RiskLevel -eq "Critical" }).Count
      $highCount  = @($allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id -and $_.RiskLevel -eq "High"     }).Count

      Write-Host "  " -NoNewline
      Write-Host "✓ " -NoNewline -ForegroundColor Green
      Write-Host $paddedName -NoNewline -ForegroundColor Green
      Write-Host " → " -NoNewline -ForegroundColor DarkGray
      Write-Host "Certs: $subCertCount  Critical: $critCount  High: $highCount" -ForegroundColor White

      $subscriptionResults += @{
        Name    = $sub.Name
        Summary = "Certificates: $subCertCount  Critical: $critCount  High: $highCount"
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

  # ── Summary ───────────────────────────────────────────────────────────────
  $endTime  = Get-Date
  $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

  Write-Summary -Data ([ordered]@{
    "Total Subscriptions Scanned" = $subCount
    "Successful"                  = $successCount
    "Errors"                      = $errorCount
    "Total Certificates Found"    = $allFindings.Count
    "Expiry Warning Threshold"    = "$ExpiryWarningDays days"
    "Execution Time"              = $duration
  })

  Write-RiskSummary -Findings $allFindings

  # ── Output files ──────────────────────────────────────────────────────────
  $csvExported    = $false
  $htmlExported   = $false
  $gridViewOpened = $false
  $htmlPath       = ""

  if ($allFindings.Count -gt 0) {
    if ($ExportToCsv) {
      try {
        $csvDir = Split-Path -Parent $CsvPath
        if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

        $allFindings | Select-Object `
          RiskLevel, Source, SubscriptionName, SubscriptionId, ResourceGroup,
          ResourceName, ResourceType, CertificateName, ExpiryDate, DaysRemaining,
          Algorithm, KeySize, IsSelfSigned, AutoRenewalEnabled, Subject, Issuer,
          Thumbprint, Impact, Recommendation |
          Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

        $csvExported = $true
      }
      catch { Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red }
    }

    try {
      $htmlPath    = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
      $sessionInfo = @{ Tenant = $ctx.Tenant.Id; Account = $ctx.Account.Id; Environment = $ctx.Environment.Name }
      $scanParams  = @{
        Scope            = "$scopeText ($subCount found)"
        ExpiryWarningDays = "$ExpiryWarningDays"
        ExportEnabled    = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        ExecTime         = $duration
      }

      $htmlContent = Generate-CertGovernanceHtml `
        -SessionInfo         $sessionInfo `
        -ScanParameters      $scanParams `
        -AllFindings         $allFindings `
        -SubscriptionResults $subscriptionResults `
        -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

      $htmlDir = Split-Path -Parent $htmlPath
      if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
      $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
      $htmlExported = $true
    }
    catch { Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red }

    try {
      $allFindings | Select-Object RiskLevel, Source, CertificateName, ResourceName,
        SubscriptionName, ExpiryDate, DaysRemaining, Algorithm, KeySize, IsSelfSigned,
        AutoRenewalEnabled | Sort-Object RiskOrder, DaysRemaining |
        Out-GridView -Title "Azure Certificate Governance Report"
      $gridViewOpened = $true
    }
    catch { Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow }
  }
  else {
    Write-Host ""
    Write-Host "  ⚠ No certificate data found in the targeted subscriptions." -ForegroundColor Yellow
  }

  if ($csvExported -or $htmlExported -or $gridViewOpened) {
    $outCsv  = if ($csvExported)  { $CsvPath  } else { $null }
    $outHtml = if ($htmlExported) { $htmlPath } else { $null }
    Write-OutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
  }
  else {
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
  }
}
