<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 17 June 2026
Modified-On  : 17 June 2026

.SYNOPSIS
  Entra ID Application Proxy — Zero Trust Security Dashboard Generator.

.DESCRIPTION
  Reads a CSV export produced by Get-AppProxyApplications (or any CSV with the
  standard Application Proxy schema) and generates a modern, single-file HTML
  dashboard that scores every application against a 2026 Zero Trust model,
  surfaces prioritized recommendations, and visualizes the whole estate in a
  story-telling layout, in the same visual language as the PS Script Library
  Dashboard template:

    • Overview          – Zero Trust score, exposure bar, defense layer stack,
                            KPIs, recently changed apps, top risk apps
    • All Apps          – searchable / filterable / sortable inventory table with
                            mini score bars, page-size selector, CSV/JSON export
    • Security Findings – every finding grouped by severity, with affected apps
    • Recommendations   – prioritized, exportable remediation plan
    • Explorer          – apps grouped by auth type / app type / SSO mode
    • Analytics         – score distribution, control coverage, trend callouts
    • Raw Data          – every captured field, per app, for audit / export

  Zero Trust scoring model (2026, 7 factors, 100 points):
      Azure AD Pre-Authentication      30 pts  (critical)
      Backend Certificate Validation   20 pts  (critical)
      Secure Cookie                    15 pts  (high)
      HTTP-Only Cookie                 15 pts  (high)
      ZTNA Client Access               10 pts  (modern)
      State Session Management          5 pts  (medium)
      OAuth Flow Security (no implicit) 5 pts  (modern)

.PARAMETER CsvPath
  Path to the CSV export of Application Proxy configurations.
  Must be a valid, existing file path. Typically the output of
  Get-AppProxyApplications run with -exportFormat CSV.

.PARAMETER OutputPath
  Full path where the generated HTML dashboard file will be saved.
  Defaults to "$env:TEMP\AppProxySecurityDashboard.html" when not specified.

.PARAMETER OpenBrowser
  If specified, automatically opens the generated dashboard in the system's
  default web browser immediately after generation.

.PARAMETER TenantName
  Optional friendly label displayed in the dashboard sidebar.
  Typically your tenant's primary domain (e.g. contoso.onmicrosoft.com).
  Defaults to the CSV filename when not provided.

.INPUTS
  None. This script does not accept pipeline input.
  The input data is read from the CSV file specified by -CsvPath.

.OUTPUTS
  System.String
  The path to the generated HTML dashboard file written to disk.
  The HTML file is self-contained (no external dependencies beyond Google Fonts)
  and can be shared or opened offline.

.EXAMPLE
  Generate-AppProxySecurityDashboard -CsvPath "C:\Reports\AppProxyConfigs.csv" -OpenBrowser

  Generates the dashboard from the specified CSV and opens it in the default browser.

.EXAMPLE
  Generate-AppProxySecurityDashboard -CsvPath "C:\Reports\AppProxyConfigs.csv" `
      -OutputPath "C:\Reports\Dashboard.html" -TenantName "contoso.onmicrosoft.com"

  Generates the dashboard to a custom output path with a friendly tenant label
  shown in the sidebar.

.EXAMPLE
  Generate-AppProxySecurityDashboard `
      -CsvPath "C:\Reports\AppProxyConfigs.csv" `
      -OutputPath "C:\Reports\AppProxyDashboard.html" `
      -TenantName "vmaslab.onmicrosoft.com" `
      -OpenBrowser

  Full example — custom output path, tenant label, and auto-open in browser.

.NOTES
  ─────────────────────────────────────────────────────────────────────────────
  Version History:
  ─────────────────────────────────────────────────────────────────────────────
  1.0 (17-Jun-2026) - Initial release.

  ─────────────────────────────────────────────────────────────────────────────
  Pre-Requisites:
  ─────────────────────────────────────────────────────────────────────────────
  1. PowerShell 5.1 or later.
  2. A CSV file exported by Get-AppProxyApplications (available in the same
    ApplicationProxy folder of this toolkit) using -exportFormat CSV.
    Any CSV that conforms to the standard Application Proxy schema is accepted.
  3. Internet access is required at dashboard view time for Google Fonts
    (JetBrains Mono, Inter). The HTML logic itself runs fully offline.

  ─────────────────────────────────────────────────────────────────────────────
  Known Limitations:
  ─────────────────────────────────────────────────────────────────────────────
  - The dashboard is generated from a point-in-time CSV snapshot. It does not
    connect to Microsoft Graph or reflect live configuration changes.
  - Column names in the input CSV must match the schema produced by
    Get-AppProxyApplications. Custom or renamed columns will be silently ignored
    during scoring, resulting in lower scores than the actual configuration warrants.
  - The single-file HTML output embeds all app data as a JavaScript literal.
    For estates with a very large number of applications (500+), file size and
    initial browser render time may increase noticeably.
  - Google Fonts are loaded from an external CDN. In air-gapped or restricted
    network environments the dashboard renders correctly but falls back to
    system fonts.

.LINK
  https://learn.microsoft.com/en-us/entra/identity/app-proxy/application-proxy

.LINK
  https://learn.microsoft.com/en-us/entra/identity/app-proxy/application-proxy-security

.LINK
  https://learn.microsoft.com/en-us/security/zero-trust/

#>


Function Generate-AppProxySecurityDashboard
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [string]$OutputPath = "$env:TEMP\AppProxySecurityDashboard.html",

    [switch]$OpenBrowser,

    [string]$TenantName = ''
  )

  #region ── Scoring Engine (2026 Zero Trust) ───────────────────────────────────

  function Get-AppProxySecurityFindings {
    param([PSCustomObject]$App)

    $toBool = {
      param($v)
      if ($null -eq $v) { return $false }
      if ($v -is [bool]) { return $v }
      return ([string]$v).Trim().ToLower() -eq 'true'
    }

    $result = [ordered]@{
      Name           = $App.DisplayName
      AppId          = $App.ApplicationId
      Score          = 0
      Classification = 'Critical'
      Enabled        = & $toBool $App.isOnPremPublishingEnabled
      Findings       = @()
      Factors        = [ordered]@{}
    }

    if (-not $result.Enabled) {
      $result.Score = 0
      $result.Classification = 'Critical'
      $result.Findings += [PSCustomObject]@{
        Id       = 'AppProxyDisabled'
        Severity = 'Critical'
        Title    = 'Application Proxy not enabled'
        Detail   = 'This application is present in the export but does not have on-premises publishing enabled.'
        Points   = 0
      }
      return [PSCustomObject]$result
    }

    # 1. Azure AD Pre-Authentication — 30 pts — CRITICAL
    $preAuth = ([string]$App.externalAuthenticationType) -eq 'aadPreAuthentication'
    $result.Factors['PreAuth'] = @{ Pass = $preAuth; Points = if ($preAuth) { 30 } else { 0 }; Max = 30 }
    if ($preAuth) { $result.Score += 30 }
    else {
      $result.Findings += [PSCustomObject]@{
        Id       = 'PassthroughAuth'
        Severity = 'Critical'
        Title    = 'Passthrough authentication enabled'
        Detail   = 'No Azure AD pre-authentication. Conditional Access, MFA, and risk-based policies cannot be enforced — anonymous attacks reach the connector directly.'
        Points   = -30
      }
    }

    # 2. Backend Certificate Validation — 20 pts — CRITICAL
    $certValid = & $toBool $App.isBackendCertificateValidationEnabled
    $result.Factors['CertValidation'] = @{ Pass = $certValid; Points = if ($certValid) { 20 } else { 0 }; Max = 20 }
    if ($certValid) { $result.Score += 20 }
    else {
      $result.Findings += [PSCustomObject]@{
        Id       = 'NoCertValidation'
        Severity = 'Critical'
        Title    = 'Backend certificate validation disabled'
        Detail   = 'The connector does not validate the backend TLS certificate, leaving the internal hop vulnerable to man-in-the-middle interception.'
        Points   = -20
      }
    }

    # 3. Secure Cookie — 15 pts — HIGH
    $secureCookie = & $toBool $App.isSecureCookieEnabled
    $result.Factors['SecureCookie'] = @{ Pass = $secureCookie; Points = if ($secureCookie) { 15 } else { 0 }; Max = 15 }
    if ($secureCookie) { $result.Score += 15 }
    else {
      $result.Findings += [PSCustomObject]@{
        Id       = 'NoSecureCookie'
        Severity = 'High'
        Title    = 'Secure cookie flag disabled'
        Detail   = 'Session cookies may be transmitted over non-HTTPS connections, exposing them to network interception.'
        Points   = -15
      }
    }

    # 4. HTTP-Only Cookie — 15 pts — HIGH
    $httpOnly = & $toBool $App.isHttpOnlyCookieEnabled
    $result.Factors['HttpOnlyCookie'] = @{ Pass = $httpOnly; Points = if ($httpOnly) { 15 } else { 0 }; Max = 15 }
    if ($httpOnly) { $result.Score += 15 }
    else {
      $result.Findings += [PSCustomObject]@{
        Id       = 'NoHttpOnlyCookie'
        Severity = 'High'
        Title    = 'HTTP-only cookie flag disabled'
        Detail   = 'Session cookies are readable by client-side script, increasing exposure to cross-site scripting (XSS) token theft.'
        Points   = -15
      }
    }

    # 5. ZTNA Client Access — 10 pts — MEDIUM
    $ztna = & $toBool $App.isAccessibleViaZTNAClient
    $result.Factors['ZTNA'] = @{ Pass = $ztna; Points = if ($ztna) { 10 } else { 0 }; Max = 10 }
    if ($ztna) { $result.Score += 10 }
    else {
      $result.Findings += [PSCustomObject]@{
        Id       = 'NoZTNA'
        Severity = 'Medium'
        Title    = 'Not accessible via Zero Trust Network Access client'
        Detail   = 'App is not enrolled for Global Secure Access / ZTNA client connectivity, the modern replacement path for legacy network-level access.'
        Points   = -10
      }
    }

    # 6. State Session Management — 5 pts — MEDIUM
    $stateSession = & $toBool $App.isStateSessionEnabled
    $result.Factors['StateSession'] = @{ Pass = $stateSession; Points = if ($stateSession) { 5 } else { 0 }; Max = 5 }
    if ($stateSession) { $result.Score += 5 }
    else {
      $result.Findings += [PSCustomObject]@{
        Id       = 'NoStateSession'
        Severity = 'Low'
        Title    = 'State session management disabled'
        Detail   = 'Session state is not tracked at the proxy layer, which can affect session integrity and timeout enforcement.'
        Points   = -5
      }
    }

    # 7. OAuth Flow Security (no legacy implicit grant) — 5 pts — MEDIUM
    $implicitId = & $toBool $App.'implicitGrantSettings-enableIdTokenIssuance'
    $implicitTok = & $toBool $App.'implicitGrantSettings-enableAccessTokenIssuance'
    $noImplicit = (-not $implicitId) -and (-not $implicitTok)
    $result.Factors['OAuthFlow'] = @{ Pass = $noImplicit; Points = if ($noImplicit) { 5 } else { 0 }; Max = 5 }
    if ($noImplicit) { $result.Score += 5 }
    else {
      $result.Findings += [PSCustomObject]@{
        Id       = 'ImplicitGrant'
        Severity = 'Medium'
        Title    = 'Legacy OAuth implicit grant enabled'
        Detail   = 'Tokens are issued via the deprecated implicit flow rather than authorization code + PKCE, increasing token leakage risk.'
        Points   = -5
      }
    }

    if ($result.Score -ge 90) { $result.Classification = 'Excellent' }
    elseif ($result.Score -ge 70) { $result.Classification = 'Good' }
    elseif ($result.Score -ge 50) { $result.Classification = 'NeedsAttention' }
    else { $result.Classification = 'Critical' }

    return [PSCustomObject]$result
  }

  function ConvertTo-JsonSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $Text `
      -replace '\\', '\\' `
      -replace '"', '\"' `
      -replace "`r`n", '\n' `
      -replace "`n", '\n' `
      -replace "`r", '\n' `
      -replace "`t", '\t'
  }

  function ConvertTo-JsArrayLiteral {
    param([string[]]$Items)
    if (-not $Items -or $Items.Count -eq 0) { return '' }
    ($Items | ForEach-Object { '"' + (ConvertTo-JsonSafe $_) + '"' }) -join ','
  }

  #endregion

  #region ── Data Collection ────────────────────────────────────────────────────

  Write-Host ""
  Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
  Write-Host "║   Entra ID App Proxy — Zero Trust Security Dashboard v1.0    ║" -ForegroundColor Cyan
  Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "  📁  Importing CSV: $CsvPath" -ForegroundColor Cyan

  try {
    $rawApps = Import-Csv -Path $CsvPath -ErrorAction Stop
  }
  catch {
    Write-Error "Failed to import CSV '$CsvPath': $_"
    exit 1
  }

  if (@($rawApps).Count -eq 0) {
    Write-Warning "No rows found in '$CsvPath'."
    exit 0
  }

  Write-Host "  ✓  Loaded $($rawApps.Count) applications — scoring against 2026 Zero Trust model…" -ForegroundColor Green

  $scored = foreach ($app in $rawApps) {
    $finding = Get-AppProxySecurityFindings -App $app
    [PSCustomObject]@{
      Raw     = $app
      Finding = $finding
    }
  }

  $totalApps = $scored.Count
  $avgScore = if ($totalApps -gt 0) { [math]::Round((($scored | ForEach-Object { $_.Finding.Score } | Measure-Object -Sum).Sum) / $totalApps) } else { 0 }
  $excellentCount = @($scored | Where-Object { $_.Finding.Classification -eq 'Excellent' }).Count
  $goodCount = @($scored | Where-Object { $_.Finding.Classification -eq 'Good' }).Count
  $attentionCount = @($scored | Where-Object { $_.Finding.Classification -eq 'NeedsAttention' }).Count
  $criticalCount = @($scored | Where-Object { $_.Finding.Classification -eq 'Critical' }).Count
  $disabledCount = @($scored | Where-Object { -not $_.Finding.Enabled }).Count

  $allFindings = $scored | ForEach-Object { $_.Finding.Findings }
  $criticalFindings = @($allFindings | Where-Object { $_.Severity -eq 'Critical' })
  $highFindings = @($allFindings | Where-Object { $_.Severity -eq 'High' })
  $mediumFindings = @($allFindings | Where-Object { $_.Severity -eq 'Medium' })
  $lowFindings = @($allFindings | Where-Object { $_.Severity -eq 'Low' })

  $factorOrder = @('PreAuth', 'CertValidation', 'SecureCookie', 'HttpOnlyCookie', 'ZTNA', 'StateSession', 'OAuthFlow')
  $factorMeta = @{
    PreAuth        = @{ Label = 'Azure AD Pre-Authentication'; Max = 30; Severity = 'Critical' }
    CertValidation = @{ Label = 'Backend Certificate Validation'; Max = 20; Severity = 'Critical' }
    SecureCookie   = @{ Label = 'Secure Cookie'; Max = 15; Severity = 'High' }
    HttpOnlyCookie = @{ Label = 'HTTP-Only Cookie'; Max = 15; Severity = 'High' }
    ZTNA           = @{ Label = 'ZTNA Client Access'; Max = 10; Severity = 'Medium' }
    StateSession   = @{ Label = 'State Session Management'; Max = 5; Severity = 'Low' }
    OAuthFlow      = @{ Label = 'OAuth Flow Security'; Max = 5; Severity = 'Medium' }
  }

  $enabledApps = @($scored | Where-Object { $_.Finding.Enabled })
  $factorStats = foreach ($key in $factorOrder) {
    $passCount = @($enabledApps | Where-Object { $_.Finding.Factors[$key].Pass }).Count
    $pct = if ($enabledApps.Count -gt 0) { [math]::Round(($passCount / $enabledApps.Count) * 100) } else { 0 }
    [PSCustomObject]@{
      Key      = $key
      Label    = $factorMeta[$key].Label
      Max      = $factorMeta[$key].Max
      Severity = $factorMeta[$key].Severity
      Pass     = $passCount
      Total    = $enabledApps.Count
      Pct      = $pct
    }
  }

  function Get-SsoMode {
    param($SsoJson)
    if (-not $SsoJson) { return 'none' }
    try {
      $parsed = $SsoJson | ConvertFrom-Json -ErrorAction Stop
      if ($parsed.singleSignOnMode) { return $parsed.singleSignOnMode }
      return 'none'
    }
    catch { return 'unknown' }
  }

  $authTypeGroups = $scored | Group-Object { if ($_.Raw.externalAuthenticationType) { $_.Raw.externalAuthenticationType } else { 'unspecified' } } | Sort-Object Count -Descending
  $appTypeGroups = $scored | Group-Object { if ($_.Raw.applicationType) { $_.Raw.applicationType } else { 'unspecified' } } | Sort-Object Count -Descending
  $ssoModeGroups = $scored | Group-Object { Get-SsoMode $_.Raw.singleSignOnSettings } | Sort-Object Count -Descending

  $tenantDisplay = if ($TenantName) { $TenantName } else { (Split-Path $CsvPath -Leaf) }
  $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')

  Write-Host "  ✓  Scoring complete." -ForegroundColor Green
  Write-Host ""
  Write-Host "  📊  Apps scored        : $totalApps" -ForegroundColor White
  Write-Host "  💯  Average score      : $avgScore / 100" -ForegroundColor White
  Write-Host "  🔴  Critical findings  : $($criticalFindings.Count)" -ForegroundColor $(if ($criticalFindings.Count -eq 0) { 'Green' }else { 'Red' })
  Write-Host "  🟠  High findings      : $($highFindings.Count)" -ForegroundColor $(if ($highFindings.Count -eq 0) { 'Green' }else { 'Yellow' })
  Write-Host ""

  #endregion

  #region ── JSON Data Blobs ────────────────────────────────────────────────────

  $appsJson = ($scored | ForEach-Object {
      $raw = $_.Raw
      $f = $_.Finding

      $findingsJson = ($f.Findings | ForEach-Object {
          "{`"id`":`"$(ConvertTo-JsonSafe $_.Id)`",`"severity`":`"$(ConvertTo-JsonSafe $_.Severity)`",`"title`":`"$(ConvertTo-JsonSafe $_.Title)`",`"detail`":`"$(ConvertTo-JsonSafe $_.Detail)`",`"points`":$($_.Points)}"
        }) -join ','

      $factorsJson = ($factorOrder | ForEach-Object {
          $fac = $f.Factors[$_]
          if ($fac) {
            "`"$_`":{`"pass`":$(if($fac.Pass){'true'}else{'false'}),`"points`":$($fac.Points),`"max`":$($fac.Max)}"
          }
        }) -join ','

      $ssoMode = Get-SsoMode $raw.singleSignOnSettings

      "{" +
      "`"name`":`"$(ConvertTo-JsonSafe $raw.DisplayName)`"," +
      "`"appId`":`"$(ConvertTo-JsonSafe $raw.ApplicationId)`"," +
      "`"objectId`":`"$(ConvertTo-JsonSafe $raw.'Object-Id')`"," +
      "`"publisherDomain`":`"$(ConvertTo-JsonSafe $raw.publisherDomain)`"," +
      "`"signInAudience`":`"$(ConvertTo-JsonSafe $raw.signInAudience)`"," +
      "`"externalUrl`":`"$(ConvertTo-JsonSafe $raw.externalUrl)`"," +
      "`"internalUrl`":`"$(ConvertTo-JsonSafe $raw.internalUrl)`"," +
      "`"homePageUrl`":`"$(ConvertTo-JsonSafe $raw.homePageUrl)`"," +
      "`"logoutUrl`":`"$(ConvertTo-JsonSafe $raw.logoutUrl)`"," +
      "`"authType`":`"$(ConvertTo-JsonSafe $raw.externalAuthenticationType)`"," +
      "`"appType`":`"$(ConvertTo-JsonSafe $raw.applicationType)`"," +
      "`"ssoMode`":`"$(ConvertTo-JsonSafe $ssoMode)`"," +
      "`"serverTimeout`":`"$(ConvertTo-JsonSafe $raw.applicationServerTimeout)`"," +
      "`"score`":$($f.Score)," +
      "`"classification`":`"$($f.Classification)`"," +
      "`"enabled`":$(if($f.Enabled){'true'}else{'false'})," +
      "`"findings`":[$findingsJson]," +
      "`"factors`":{$factorsJson}," +
      "`"secureCookie`":$(if((([string]$raw.isSecureCookieEnabled).Trim().ToLower() -eq 'true')){'true'}else{'false'})," +
      "`"httpOnlyCookie`":$(if((([string]$raw.isHttpOnlyCookieEnabled).Trim().ToLower() -eq 'true')){'true'}else{'false'})," +
      "`"persistentCookie`":$(if((([string]$raw.isPersistentCookieEnabled).Trim().ToLower() -eq 'true')){'true'}else{'false'})," +
      "`"ztna`":$(if((([string]$raw.isAccessibleViaZTNAClient).Trim().ToLower() -eq 'true')){'true'}else{'false'})," +
      "`"certValidation`":$(if((([string]$raw.isBackendCertificateValidationEnabled).Trim().ToLower() -eq 'true')){'true'}else{'false'})," +
      "`"translateHostHeader`":$(if((([string]$raw.isTranslateHostHeaderEnabled).Trim().ToLower() -eq 'true')){'true'}else{'false'})," +
      "`"translateLinks`":$(if((([string]$raw.isTranslateLinksInBodyEnabled).Trim().ToLower() -eq 'true')){'true'}else{'false'})," +
      "`"stateSession`":$(if((([string]$raw.isStateSessionEnabled).Trim().ToLower() -eq 'true')){'true'}else{'false'})," +
      "`"dnsResolution`":$(if((([string]$raw.isDnsResolutionEnabled).Trim().ToLower() -eq 'true')){'true'}else{'false'})" +
      "}"
    }) -join ','

  $factorStatsJson = ($factorStats | ForEach-Object {
      "{`"key`":`"$($_.Key)`",`"label`":`"$(ConvertTo-JsonSafe $_.Label)`",`"max`":$($_.Max),`"severity`":`"$($_.Severity)`",`"pass`":$($_.Pass),`"total`":$($_.Total),`"pct`":$($_.Pct)}"
    }) -join ','

  $authTypeJson = ($authTypeGroups | ForEach-Object { "{`"label`":`"$(ConvertTo-JsonSafe $_.Name)`",`"count`":$($_.Count)}" }) -join ','
  $appTypeJson = ($appTypeGroups  | ForEach-Object { "{`"label`":`"$(ConvertTo-JsonSafe $_.Name)`",`"count`":$($_.Count)}" }) -join ','
  $ssoModeJson = ($ssoModeGroups  | ForEach-Object { "{`"label`":`"$(ConvertTo-JsonSafe $_.Name)`",`"count`":$($_.Count)}" }) -join ','

  $csvColumns = if ($rawApps.Count -gt 0) { $rawApps[0].PSObject.Properties.Name } else { @() }
  $rawColumnsJson = ConvertTo-JsArrayLiteral -Items $csvColumns
  $rawRowsJson = ($rawApps | ForEach-Object {
      $row = $_
      $cells = ($csvColumns | ForEach-Object { "`"$(ConvertTo-JsonSafe $row.$_)`"" }) -join ','
      "[$cells]"
    }) -join ','

  #endregion

  #region ── HTML Dashboard ─────────────────────────────────────────────────────

  $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>App Proxy Zero Trust Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
:root {
  --bg:#0d1117; --surface:#161b22; --surface2:#1c2333; --surface3:#243048;
  --border:#30363d; --border-soft:#1e2840;
  --trust:#2dd4bf; --trust-dim:rgba(45,212,191,.1);
  --risk:#fb7185; --risk-dim:rgba(251,113,133,.1);
  --warn:#fbbf24; --warn-dim:rgba(251,191,36,.1);
  --good:#34d399; --good-dim:rgba(52,211,153,.1);
  --info:#60a5fa; --info-dim:rgba(96,165,250,.1);
  --purple:#a78bfa; --purple-dim:rgba(167,139,250,.1);
  --text:#e6edf3; --muted:#7d8590; --muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Inter','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px; --radius-sm:6px; --shadow:0 4px 24px rgba(0,0,0,.5);
}
body.light-theme {
  --bg:#f6f8fa; --surface:#fff; --surface2:#f0f3f6; --surface3:#e4e9ef;
  --border:#d0d7de; --border-soft:#e2e8f0;
  --trust:#0f9c8c; --trust-dim:rgba(15,156,140,.1);
  --risk:#cf222e; --risk-dim:rgba(207,34,46,.08);
  --warn:#b08000; --warn-dim:rgba(176,128,0,.08);
  --good:#1a7f37; --good-dim:rgba(26,127,55,.08);
  --info:#0969da; --info-dim:rgba(9,105,218,.08);
  --purple:#7c3aed; --purple-dim:rgba(124,58,237,.08);
  --text:#1f2328; --muted:#636c76; --muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14.5px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}

/* ── Sidebar ── */
#sidebar{position:fixed;top:0;left:0;bottom:0;width:240px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,var(--trust),#0f7c6e);display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:10px;position:relative}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text);letter-spacing:-.01em}
.sidebar-logo p{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tenant-badge{display:inline-block;margin-top:6px;background:var(--trust-dim);color:var(--trust);font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:20px;border:1px solid rgba(45,212,191,.3)}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13.5px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:14px;width:20px;text-align:center;flex-shrink:0}
.nav-btn .nav-badge{margin-left:auto;background:var(--surface3);color:var(--muted2);font-family:var(--mono);font-size:10.5px;padding:1px 7px;border-radius:20px}
.nav-btn .nav-badge.risk{background:var(--risk-dim);color:var(--risk)}
.nav-btn:hover{color:var(--text);background:var(--surface2)}
.nav-btn.active{color:var(--trust);background:var(--trust-dim)}
.nav-btn.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--trust);border-radius:0 2px 2px 0}
.theme-toggle-wrap{padding:10px 14px;border-top:1px solid var(--border)}
.theme-toggle{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;transition:all .2s}
.theme-toggle:hover{border-color:var(--trust);color:var(--text)}
.toggle-pill{width:34px;height:18px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--muted2);transition:transform .2s,background .2s}
body.light-theme .toggle-pill{background:var(--trust)}
body.light-theme .toggle-pill::after{transform:translateX(16px);background:#fff}
.sidebar-footer{padding:10px 18px 12px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);font-family:var(--mono);line-height:1.6}
kbd{display:inline-block;padding:1px 5px;background:var(--surface3);border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:10.5px;color:var(--muted)}

/* ── Main ── */
#main{margin-left:240px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:22px;font-weight:700;color:var(--text);letter-spacing:-.01em}
.page-subtitle{color:var(--muted);font-size:12.5px;margin-top:3px}

.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:12.5px;font-family:var(--sans);font-weight:500;cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--trust);color:var(--trust);background:var(--trust-dim)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

/* ── ZT Hero ── */
.zt-hero{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px 26px;margin-bottom:22px;display:flex;gap:28px;align-items:center;flex-wrap:wrap;position:relative;overflow:hidden}
.zt-hero::before{content:'';position:absolute;top:-60px;right:-60px;width:220px;height:220px;border-radius:50%;background:radial-gradient(circle,var(--trust-dim),transparent 70%);pointer-events:none}
.zt-gauge-wrap{position:relative;width:144px;height:144px;flex-shrink:0}
.zt-gauge-wrap svg{width:144px;height:144px}
.zt-gauge-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.zt-score-num{font-size:38px;font-weight:700;line-height:1;font-family:var(--mono)}
.zt-score-max{font-size:10.5px;color:var(--muted);margin-top:2px}
.zt-info{flex:1;min-width:240px}
.zt-info h2{font-size:17px;font-weight:700;margin-bottom:5px}
.zt-info p{color:var(--muted2);font-size:13px;max-width:520px}
.zt-rating-chip{display:inline-flex;align-items:center;gap:6px;margin-top:9px;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;font-family:var(--mono)}
.exposure-row{margin-top:16px;max-width:540px}
.exposure-label{font-size:11px;color:var(--muted);margin-bottom:5px}
.exposure-bar{display:flex;height:12px;border-radius:6px;overflow:hidden;gap:1px}
.exposure-seg{height:100%;transition:width 1s cubic-bezier(.4,0,.2,1);min-width:2px}
.exposure-legend{display:flex;gap:14px;margin-top:8px;flex-wrap:wrap;font-size:11.5px;color:var(--muted2)}
.exposure-legend span{display:inline-flex;align-items:center;gap:5px}
.exposure-dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0}

/* ── Stat cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:22px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px)}
.stat-icon{font-size:19px;margin-bottom:8px}
.stat-value{font-size:26px;font-weight:700;color:var(--text);line-height:1;font-family:var(--mono)}
.stat-label{color:var(--muted);font-size:11.5px;margin-top:4px}
.stat-card.c-trust{border-top:2px solid var(--trust)}
.stat-card.c-good{border-top:2px solid var(--good)}
.stat-card.c-warn{border-top:2px solid var(--warn)}
.stat-card.c-risk{border-top:2px solid var(--risk)}
.stat-card.c-info{border-top:2px solid var(--info)}
.stat-card.c-purple{border-top:2px solid var(--purple)}

/* ── Defense Layer Stack ── */
.layer-stack-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px 22px;margin-bottom:22px}
.layer-stack-head{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:3px;flex-wrap:wrap;gap:8px}
.layer-stack-head h3{font-size:15px;font-weight:700}
.layer-stack-sub{font-size:11.5px;color:var(--muted);margin-bottom:16px}
.layer-row{display:grid;grid-template-columns:40px 200px 1fr 54px;align-items:center;gap:12px;margin-bottom:9px;cursor:pointer;padding:5px 6px;border-radius:var(--radius-sm);transition:background .15s}
.layer-row:hover{background:var(--surface2)}
.layer-weight{font-family:var(--mono);font-size:10.5px;color:var(--muted);text-align:center;background:var(--surface3);border-radius:5px;padding:3px 2px;line-height:1.3}
.layer-label{font-size:12.5px;color:var(--muted2);font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.layer-track{height:14px;background:var(--surface3);border-radius:7px;overflow:hidden;position:relative}
.layer-fill{height:100%;border-radius:7px;transition:width 1.1s cubic-bezier(.4,0,.2,1)}
.layer-pct{font-family:var(--mono);font-size:12px;color:var(--muted2);text-align:right;white-space:nowrap}

/* ── Panels & charts ── */
.section-title{font-size:14.5px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:8px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:920px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.list-row{display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid var(--border-soft);cursor:pointer}
.list-row:last-child{border-bottom:none}
.list-row:hover .lr-name{color:var(--trust)}
.lr-name{font-family:var(--mono);font-size:12.5px;color:var(--muted2);flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:500}
.score-pill{font-family:var(--mono);font-size:11px;padding:2px 9px;border-radius:20px;font-weight:700;flex-shrink:0}

/* ── Classification color tokens ── */
.cls-Excellent{color:var(--good)}
.bg-Excellent{background:var(--good-dim);border:1px solid rgba(52,211,153,.3)}
.cls-Good{color:var(--trust)}
.bg-Good{background:var(--trust-dim);border:1px solid rgba(45,212,191,.3)}
.cls-NeedsAttention{color:var(--warn)}
.bg-NeedsAttention{background:var(--warn-dim);border:1px solid rgba(251,191,36,.3)}
.cls-Critical{color:var(--risk)}
.bg-Critical{background:var(--risk-dim);border:1px solid rgba(251,113,133,.3)}
.sev-Critical{color:var(--risk)}
.sev-High{color:var(--risk)}
.sev-Medium{color:var(--warn)}
.sev-Low{color:var(--info)}

/* ── Table ── */
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:13.5px;padding:8px 11px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--trust)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:12.5px;flex-shrink:0}
.apps-table{width:100%;border-collapse:collapse}
.apps-table thead th{text-align:left;font-family:var(--sans);font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.apps-table thead th:hover{color:var(--text)}
.apps-table thead th.sort-active{color:var(--trust)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.apps-table tbody tr{border-bottom:1px solid var(--border-soft);cursor:pointer;transition:background .15s}
.apps-table tbody tr:hover{background:var(--surface2)}
.apps-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13px}
.td-name{font-family:var(--mono);font-size:12.5px;color:var(--text);font-weight:600}
.td-meta{color:var(--muted);font-family:var(--mono);font-size:11.5px;white-space:nowrap}
.auth-badge{display:inline-block;padding:2px 9px;border-radius:20px;font-family:var(--mono);font-size:10.5px;font-weight:500}
.score-bar-mini{width:60px;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden;display:inline-block;vertical-align:middle;margin-right:6px}
.score-bar-mini-fill{height:100%;border-radius:3px}
.bool-dot{display:inline-block;width:7px;height:7px;border-radius:50%}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--trust);color:var(--trust)}
.page-btn.active{background:var(--trust);border-color:var(--trust);color:#0a2e29}
.page-btn:disabled{opacity:.35;cursor:default}

/* ── Detail Drawer ── */
#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(680px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:24px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
#detailPrevBtn,#detailNextBtn{padding:6px 12px;font-size:12px}
#detailClose{margin-left:auto;background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--risk);color:#fff}
#detailContent{flex:1;overflow-y:auto}
.detail-app-header{margin-bottom:18px;display:flex;align-items:flex-start;gap:16px}
.detail-score-wrap{flex-shrink:0;width:68px;height:68px;position:relative}
.detail-score-wrap svg{width:68px;height:68px}
.detail-score-center{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-weight:700;font-size:16px}
.detail-app-name{font-size:16px;font-weight:700;color:var(--text);word-break:break-word}
.detail-app-id{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:4px;word-break:break-all}
.detail-meta-row{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:11.5px;color:var(--muted2);font-family:var(--mono)}
.detail-section{margin-top:18px}
.detail-section-title{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:9px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.finding-card{border-radius:var(--radius-sm);padding:10px 13px;margin-bottom:7px;border:1px solid var(--border)}
.finding-head{display:flex;align-items:flex-start;gap:9px;margin-bottom:4px}
.finding-sev-badge{font-family:var(--mono);font-size:10px;padding:2px 7px;border-radius:10px;font-weight:700;flex-shrink:0;margin-top:2px}
.finding-title{font-size:13px;font-weight:600;flex:1}
.finding-points{font-family:var(--mono);font-size:11.5px;font-weight:700;flex-shrink:0;white-space:nowrap}
.finding-detail{font-size:12.5px;color:var(--muted2);line-height:1.55;margin-top:2px}
.factor-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:4px}
.factor-chip{display:flex;align-items:center;gap:7px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;font-size:11.5px}
.factor-chip .fc-icon{font-size:13px;flex-shrink:0}
.factor-chip .fc-label{flex:1;color:var(--muted2);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.url-row{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border-soft)}
.url-row:last-child{border-bottom:none}
.url-label{font-size:11px;color:var(--muted);width:100px;flex-shrink:0}
.url-val{font-family:var(--mono);font-size:11.5px;color:var(--trust);flex:1;word-break:break-all}

/* ── Findings page ── */
.severity-section{margin-bottom:24px}
.severity-head{display:flex;align-items:center;gap:10px;margin-bottom:13px}
.severity-badge{font-family:var(--mono);font-size:11px;padding:4px 12px;border-radius:20px;font-weight:700;letter-spacing:.03em}
.severity-count{font-size:12.5px;color:var(--muted)}
.finding-group{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;margin-bottom:10px}
.finding-group-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap}
.finding-group-title{font-size:14px;font-weight:600}
.finding-group-desc{font-size:12.5px;color:var(--muted2);margin-top:5px;max-width:600px;line-height:1.55}
.finding-group-impact{font-family:var(--mono);font-size:11.5px;font-weight:700;flex-shrink:0;white-space:nowrap}
.affected-apps-toggle{font-size:12px;color:var(--trust);cursor:pointer;margin-top:11px;display:inline-flex;align-items:center;gap:5px;user-select:none}
.affected-apps-list{display:none;flex-wrap:wrap;gap:6px;margin-top:9px}
.affected-apps-list.open{display:flex}
.affected-app-chip{font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:3px 9px;cursor:pointer;transition:all .15s}
.affected-app-chip:hover{border-color:var(--trust);color:var(--trust)}

/* ── Recommendations ── */
.reco-card{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--border);border-radius:var(--radius);padding:18px 20px;margin-bottom:12px;transition:border-color .2s}
.reco-card.pri-Critical{border-left-color:var(--risk)}
.reco-card.pri-High{border-left-color:var(--risk)}
.reco-card.pri-Medium{border-left-color:var(--warn)}
.reco-card.pri-Low{border-left-color:var(--info)}
.reco-rank{font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:5px;display:flex;align-items:center;gap:8px}
.reco-sev-dot{width:7px;height:7px;border-radius:50%;display:inline-block;flex-shrink:0}
.reco-title{font-size:14.5px;font-weight:700;margin-bottom:6px}
.reco-desc{font-size:12.5px;color:var(--muted2);line-height:1.6;margin-bottom:12px}
.reco-meta{display:flex;gap:9px;flex-wrap:wrap;margin-bottom:10px}
.reco-meta-chip{font-size:11px;font-family:var(--mono);background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;color:var(--muted2)}
.reco-action{background:var(--trust-dim);border:1px solid rgba(45,212,191,.3);border-radius:var(--radius-sm);padding:10px 13px;font-size:12.5px;color:var(--trust);line-height:1.6}
.reco-action code{font-family:var(--mono);font-size:11.5px;background:rgba(45,212,191,.08);padding:1px 5px;border-radius:3px}

/* ── Explorer ── */
.explorer-tabs{display:flex;gap:6px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:3px;width:fit-content;margin-bottom:18px}
.explorer-tab{padding:6px 15px;border-radius:5px;font-size:13px;cursor:pointer;color:var(--muted2);transition:all .15s;font-weight:500;border:none;background:none;font-family:var(--sans)}
.explorer-tab.active{background:var(--trust);color:#0a2e29}
.facet-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px}
.facet-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;transition:border-color .2s}
.facet-card:hover{border-color:var(--trust)}
.facet-card-head{display:flex;align-items:center;justify-content:space-between;padding:12px 15px;border-bottom:1px solid var(--border);background:var(--surface2)}
.facet-card-head .fname{font-family:var(--mono);font-size:13px;font-weight:600}
.facet-card-head .fcount{font-size:11px;background:var(--surface3);border-radius:20px;padding:2px 8px;color:var(--muted2)}
.facet-apps{padding:5px 7px;max-height:260px;overflow-y:auto}
.facet-app-row{display:flex;align-items:center;gap:8px;padding:7px 8px;border-radius:var(--radius-sm);cursor:pointer;transition:background .15s}
.facet-app-row:hover{background:var(--surface2)}
.facet-app-name{font-family:var(--mono);font-size:12px;color:var(--muted2);flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* ── Analytics ── */
.analytics-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;margin-bottom:18px}
.analytics-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.bucket-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.bucket-label{font-size:12px;color:var(--muted2);width:90px;flex-shrink:0;font-family:var(--mono)}
.bucket-bar{flex:1;height:16px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bucket-fill{height:100%;border-radius:4px;transition:width .9s ease}
.bucket-count{font-family:var(--mono);font-size:11.5px;color:var(--muted);width:24px;text-align:right;flex-shrink:0}
.coverage-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.coverage-label{font-size:12px;color:var(--muted2);width:160px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.coverage-bar{flex:1;height:10px;background:var(--surface3);border-radius:5px;overflow:hidden}
.coverage-fill{height:100%;border-radius:5px;transition:width .9s ease}
.coverage-pct{font-family:var(--mono);font-size:11.5px;color:var(--muted);width:85px;text-align:right;flex-shrink:0}
.callout{background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--info);border-radius:var(--radius-sm);padding:12px 15px;margin-bottom:10px;font-size:12.5px;color:var(--muted2);line-height:1.65}
.callout strong{color:var(--text)}
.callout.warn{border-left-color:var(--warn)}
.callout.risk{border-left-color:var(--risk)}
.callout.good{border-left-color:var(--good)}

/* ── Raw Data ── */
.raw-table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius)}
.raw-table{border-collapse:collapse;font-family:var(--mono);font-size:11px;white-space:nowrap;width:100%;min-width:100%}
.raw-table thead th{position:sticky;top:0;background:var(--surface2);text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);color:var(--muted);font-weight:600;z-index:2}
.raw-table tbody td{padding:8px 12px;border-bottom:1px solid var(--border-soft);color:var(--muted2)}
.raw-table tbody tr:hover{background:var(--surface2)}
.raw-table tbody td:first-child{position:sticky;left:0;background:var(--surface);color:var(--text);font-weight:600;border-right:1px solid var(--border)}
.raw-table tbody tr:hover td:first-child{background:var(--surface2)}

/* ── Toast ── */
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}

::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

@media(max-width:768px){#sidebar{transform:translateX(-240px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px}#menuToggle{display:flex}.chart-grid{grid-template-columns:1fr}.layer-row{grid-template-columns:36px 1fr 44px;}.layer-track{display:none}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🛡</div>
    <h1>App Proxy Zero Trust</h1>
    <p title="__TENANTDISPLAY__">__TENANTDISPLAY__</p>
    <span class="tenant-badge">2026 ZT Model · v1.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">◈</span> Overview
    </button>
    <button class="nav-btn" onclick="showPage('apps',this)">
      <span class="nav-icon">▤</span> All Apps
      <span class="nav-badge">__APPCOUNT__</span>
    </button>
    <button class="nav-btn" onclick="showPage('findings',this)">
      <span class="nav-icon">⚠</span> Security Findings
      <span class="nav-badge risk" id="findingsBadge">0</span>
    </button>
    <button class="nav-btn" onclick="showPage('recommendations',this)">
      <span class="nav-icon">✓</span> Recommendations
    </button>
    <button class="nav-btn" onclick="showPage('explorer',this)">
      <span class="nav-icon">⊞</span> Explorer
    </button>
    <button class="nav-btn" onclick="showPage('analytics',this)">
      <span class="nav-icon">▣</span> Analytics
    </button>
    <button class="nav-btn" onclick="showPage('rawdata',this)">
      <span class="nav-icon">▦</span> Raw Data
    </button>
  </div>
  <div class="theme-toggle-wrap">
    <button class="theme-toggle" onclick="toggleTheme()">
      <span id="themeIcon">🌙</span>
      <span id="themeLabel" style="flex:1;text-align:left">Dark Mode</span>
      <span class="toggle-pill"></span>
    </button>
  </div>
  <div class="sidebar-footer">
    Generated<br>__GENERATEDAT__<br>
    <span style="color:var(--trust)">⌨</span> <kbd>/</kbd> search &nbsp; <kbd>Esc</kbd> close
  </div>
</nav>

<main id="main">

<!-- ════════════════════════ OVERVIEW ════════════════════════ -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Zero Trust Posture Overview</div>
      <div class="page-subtitle">How your Application Proxy estate stacks up against the 2026 Zero Trust model</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(false)">⬇ Export CSV</button>
      <button class="btn" onclick="exportJSON(false)">⬇ Export JSON</button>
    </div>
  </div>

  <div class="zt-hero">
    <div class="zt-gauge-wrap">
      <svg viewBox="0 0 144 144">
        <circle cx="72" cy="72" r="58" fill="none" stroke="var(--surface3)" stroke-width="12"/>
        <circle cx="72" cy="72" r="58" fill="none" stroke="var(--trust)" stroke-width="12"
          stroke-dasharray="364" stroke-dashoffset="364" stroke-linecap="round"
          transform="rotate(-90 72 72)" id="ztArc" style="transition:stroke-dashoffset 1.3s cubic-bezier(.4,0,.2,1)"/>
      </svg>
      <div class="zt-gauge-center">
        <span class="zt-score-num" id="ztScoreNum">0</span>
        <span class="zt-score-max">/ 100</span>
      </div>
    </div>
    <div class="zt-info">
      <h2>Average Zero Trust Score</h2>
      <p id="ztSummaryText">Evaluating your Application Proxy estate…</p>
      <span class="zt-rating-chip" id="ztRatingChip">—</span>
      <div class="exposure-row">
        <div class="exposure-label">App classification breakdown</div>
        <div class="exposure-bar" id="exposureBar"></div>
        <div class="exposure-legend" id="exposureLegend"></div>
      </div>
    </div>
  </div>

  <div class="stats-grid" id="overviewStats"></div>

  <div class="layer-stack-panel">
    <div class="layer-stack-head">
      <h3>🛡 Defense Layer Stack</h3>
      <span style="font-size:11.5px;color:var(--muted)">org-wide compliance per control · ordered by weight</span>
    </div>
    <div class="layer-stack-sub">Each layer represents a Zero Trust control — click any row to jump to affected apps</div>
    <div id="layerStack"></div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🔴 Top Risk Apps <span style="font-size:11px;color:var(--muted);font-weight:400">(lowest scores)</span></div>
      <div id="topRiskList"></div>
    </div>
    <div class="panel">
      <div class="section-title">🏆 Top Secure Apps <span style="font-size:11px;color:var(--muted);font-weight:400">(highest scores)</span></div>
      <div id="topSecureList"></div>
    </div>
  </div>
</section>

<!-- ════════════════════════ ALL APPS ════════════════════════ -->
<section id="page-apps" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">All Applications</div>
      <div class="page-subtitle">Browse, filter, and inspect every published app and its Zero Trust score</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(true)">⬇ Export Filtered CSV</button>
      <button class="btn" onclick="exportJSON(true)">⬇ Export Filtered JSON</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="tableSearch" placeholder="Search name, auth type, SSO mode… (press / to focus)" oninput="filterTable()"/>
    </div>
    <select id="classFilter" onchange="filterTable()">
      <option value="">All Classifications</option>
      <option value="Excellent">✅ Excellent</option>
      <option value="Good">🟢 Good</option>
      <option value="NeedsAttention">🟡 Needs Attention</option>
      <option value="Critical">🔴 Critical</option>
    </select>
    <select id="authFilter" onchange="filterTable()"><option value="">All Auth Types</option></select>
    <select id="sortSelect" onchange="filterTable()">
      <option value="score-asc">Lowest Score First</option>
      <option value="score-desc">Highest Score First</option>
      <option value="name-asc">Name A→Z</option>
      <option value="name-desc">Name Z→A</option>
    </select>
    <div style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)">
      Show <select id="pageSizeSelect" onchange="changePageSize()" style="padding:5px 8px;font-size:12px;margin-left:4px"><option>20</option><option>50</option><option>100</option></select>
    </div>
    <span class="result-count" id="resultCount"></span>
  </div>
  <table class="apps-table">
    <thead><tr>
      <th onclick="sortByCol('name')" id="th-name">Application <span class="sort-arrow">↕</span></th>
      <th onclick="sortByCol('score')" id="th-score">Score <span class="sort-arrow">↕</span></th>
      <th>Classification</th>
      <th>Auth Type</th>
      <th>SSO Mode</th>
      <th title="ZTNA Client">ZTNA</th>
      <th>Findings</th>
    </tr></thead>
    <tbody id="appsTableBody"></tbody>
  </table>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:12px">
    <span id="pageInfo" style="font-size:12px;color:var(--muted)"></span>
    <div class="pagination" id="pagination"></div>
  </div>
</section>

<!-- ════════════════════════ SECURITY FINDINGS ════════════════════════ -->
<section id="page-findings" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Security Findings</div>
      <div class="page-subtitle">Every control gap across your estate, grouped by severity — click any app chip to open its detail</div>
    </div>
  </div>
  <div id="findingsContainer"></div>
</section>

<!-- ════════════════════════ RECOMMENDATIONS ════════════════════════ -->
<section id="page-recommendations" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Prioritized Recommendations</div>
      <div class="page-subtitle">A remediation plan ranked by risk reduction — tackle Critical items first for maximum impact</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportRecommendationsCSV()">⬇ Export Plan as CSV</button>
    </div>
  </div>
  <div id="recommendationsContainer"></div>
</section>

<!-- ════════════════════════ EXPLORER ════════════════════════ -->
<section id="page-explorer" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Application Explorer</div>
      <div class="page-subtitle">Browse apps grouped by authentication type, application type, or SSO mode</div>
    </div>
  </div>
  <div class="explorer-tabs">
    <button class="explorer-tab active" data-group="auth" onclick="setExplorerGroup(this)">Auth Type</button>
    <button class="explorer-tab" data-group="apptype" onclick="setExplorerGroup(this)">App Type</button>
    <button class="explorer-tab" data-group="sso" onclick="setExplorerGroup(this)">SSO Mode</button>
  </div>
  <div class="facet-grid" id="facetGrid"></div>
</section>

<!-- ════════════════════════ ANALYTICS ════════════════════════ -->
<section id="page-analytics" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Analytics</div>
      <div class="page-subtitle">Score distribution, control coverage, and Zero Trust context for your estate</div>
    </div>
  </div>
  <div class="analytics-grid">
    <div class="analytics-panel">
      <div class="section-title">📊 Score Distribution</div>
      <div id="scoreDistribution"></div>
    </div>
    <div class="analytics-panel">
      <div class="section-title">🛡 Control Coverage</div>
      <div id="controlCoverage"></div>
    </div>
  </div>
  <div class="analytics-grid">
    <div class="analytics-panel">
      <div class="section-title">🔐 Authentication Breakdown</div>
      <div id="authBreakdown"></div>
    </div>
    <div class="analytics-panel">
      <div class="section-title">🔗 SSO Mode Breakdown</div>
      <div id="ssoBreakdown"></div>
    </div>
  </div>
  <div class="panel">
    <div class="section-title">📡 2026 Zero Trust Guidance</div>
    <div id="ztCallouts"></div>
  </div>
</section>

<!-- ════════════════════════ RAW DATA ════════════════════════ -->
<section id="page-rawdata" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Raw Data</div>
      <div class="page-subtitle">Every field captured in the source CSV, unmodified, for audit and export</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportRawCSV()">⬇ Export Raw CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="rawSearch" placeholder="Search raw data…" oninput="filterRawTable()"/>
    </div>
    <span class="result-count" id="rawResultCount"></span>
  </div>
  <div class="raw-table-wrap">
    <table class="raw-table" id="rawTable"></table>
  </div>
</section>

</main>

<!-- ════════════ DETAIL DRAWER ════════════ -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDetail()"></div>
  <div id="detailDrawer">
    <div class="detail-toolbar">
      <button class="btn" id="detailPrevBtn" onclick="navigateDetail(-1)">‹ Prev</button>
      <button class="btn" id="detailNextBtn" onclick="navigateDetail(1)">Next ›</button>
      <button class="btn" onclick="copyDetailName()">📋 Copy Name</button>
      <button id="detailClose" onclick="closeDetail()" title="Close (Esc)">✕</button>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<div id="toast"><span id="toastIcon">✅</span><span id="toastMsg">Done</span></div>

<script>
// ════════════════════════════════════════════════════════════════
//  DATA
// ════════════════════════════════════════════════════════════════
const APPS         = [__APPS_JSON__];
const FACTOR_STATS = [__FACTOR_STATS_JSON__];
const AUTH_TYPES   = [__AUTH_TYPE_JSON__];
const APP_TYPES    = [__APP_TYPE_JSON__];
const SSO_MODES    = [__SSO_MODE_JSON__];
const RAW_COLUMNS  = [__RAW_COLUMNS_JSON__];
const RAW_ROWS     = [__RAW_ROWS_JSON__];
const AVG_SCORE    = __AVGSCORE__;
const TOTAL_APPS   = __APPCOUNT__;

// ════════════════════════════════════════════════════════════════
//  UTILS
// ════════════════════════════════════════════════════════════════
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

let _toastT;
function showToast(msg,icon='✅'){
  document.getElementById('toastMsg').textContent=msg;
  document.getElementById('toastIcon').textContent=icon;
  const el=document.getElementById('toast');
  el.classList.add('show');
  clearTimeout(_toastT);
  _toastT=setTimeout(()=>el.classList.remove('show'),2600);
}

function toggleTheme(){
  const light=document.body.classList.toggle('light-theme');
  document.getElementById('themeIcon').textContent=light?'☀️':'🌙';
  document.getElementById('themeLabel').textContent=light?'Light Mode':'Dark Mode';
  try{localStorage.setItem('appdash-theme',light?'light':'dark');}catch(e){}
}
(function(){
  try{if(localStorage.getItem('appdash-theme')==='light'){
    document.body.classList.add('light-theme');
    document.getElementById('themeIcon').textContent='☀️';
    document.getElementById('themeLabel').textContent='Light Mode';
  }}catch(e){}
})();

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn) btn.classList.add('active');
}

function scoreColor(s){
  if(s>=90) return 'var(--good)';
  if(s>=70) return 'var(--trust)';
  if(s>=50) return 'var(--warn)';
  return 'var(--risk)';
}

function clsLabel(c){
  return {Excellent:'Excellent',Good:'Good',NeedsAttention:'Needs Attention',Critical:'Critical'}[c]||c;
}

function authBadgeColor(t){
  if(!t) return 'var(--muted)';
  if(t==='aadPreAuthentication') return 'var(--good)';
  if(t==='passthru'||t==='passthrough') return 'var(--risk)';
  return 'var(--warn)';
}

function miniScoreBar(score){
  const col=scoreColor(score);
  return `<span class="score-bar-mini"><span class="score-bar-mini-fill" style="width:${score}%;background:${col}"></span></span><span style="font-family:var(--mono);font-size:11.5px;color:${col};font-weight:700">${score}</span>`;
}

// ════════════════════════════════════════════════════════════════
//  OVERVIEW
// ════════════════════════════════════════════════════════════════
(function buildOverview(){
  const score = AVG_SCORE;
  const arc   = document.getElementById('ztArc');
  const num   = document.getElementById('ztScoreNum');
  const circ  = 2*Math.PI*58; // 364.4
  const col   = scoreColor(score);
  arc.style.stroke=col; num.style.color=col;
  requestAnimationFrame(()=>requestAnimationFrame(()=>{
    arc.style.strokeDashoffset = circ*(1-score/100);
  }));

  const excellent = APPS.filter(a=>a.classification==='Excellent').length;
  const good      = APPS.filter(a=>a.classification==='Good').length;
  const attn      = APPS.filter(a=>a.classification==='NeedsAttention').length;
  const crit      = APPS.filter(a=>a.classification==='Critical').length;
  const allCritFnd = APPS.reduce((s,a)=>s+a.findings.filter(f=>f.severity==='Critical').length,0);
  const allHighFnd = APPS.reduce((s,a)=>s+a.findings.filter(f=>f.severity==='High').length,0);
  const ztnaCount  = APPS.filter(a=>a.ztna).length;

  // Summary text
  const summary = score>=90
    ? 'Your estate has excellent Zero Trust coverage. Maintain controls and review any new apps immediately on publish.'
    : score>=70
      ? 'Your estate is in good shape but has room to improve. Review the Recommendations tab for quick wins.'
      : score>=50
        ? 'Several controls are missing across your estate. Prioritize Critical and High findings in the Recommendations tab.'
        : 'Your estate has significant Zero Trust gaps. Immediate remediation is recommended — start with the Recommendations tab.';
  document.getElementById('ztSummaryText').textContent=summary;

  const chip=document.getElementById('ztRatingChip');
  const chipMeta={Excellent:{col:'var(--good)',dim:'var(--good-dim)',lbl:'Excellent'},Good:{col:'var(--trust)',dim:'var(--trust-dim)',lbl:'Good'},NeedsAttention:{col:'var(--warn)',dim:'var(--warn-dim)',lbl:'Needs Attention'},Critical:{col:'var(--risk)',dim:'var(--risk-dim)',lbl:'Critical'}};
  const cls=score>=90?'Excellent':score>=70?'Good':score>=50?'NeedsAttention':'Critical';
  const cm=chipMeta[cls];
  chip.style.background=cm.dim; chip.style.color=cm.col;
  chip.style.border=`1px solid ${cm.col}55`; chip.textContent=cm.lbl;

  // Exposure bar
  const exposureBar=document.getElementById('exposureBar');
  const segments=[
    {count:excellent,col:'var(--good)',lbl:'Excellent'},
    {count:good,col:'var(--trust)',lbl:'Good'},
    {count:attn,col:'var(--warn)',lbl:'Needs Attention'},
    {count:crit,col:'var(--risk)',lbl:'Critical'}
  ];
  segments.forEach(seg=>{
    const pct=TOTAL_APPS>0?Math.round((seg.count/TOTAL_APPS)*100):0;
    if(pct>0){
      const div=document.createElement('div');
      div.className='exposure-seg';
      div.style.cssText=`width:0%;background:${seg.col}`;
      div.dataset.pct=pct;
      exposureBar.appendChild(div);
    }
  });
  requestAnimationFrame(()=>requestAnimationFrame(()=>{
    exposureBar.querySelectorAll('.exposure-seg').forEach(el=>{el.style.width=el.dataset.pct+'%';});
  }));
  const legend=document.getElementById('exposureLegend');
  segments.forEach(seg=>{
    if(seg.count>0) legend.innerHTML+=`<span><span class="exposure-dot" style="background:${seg.col}"></span>${seg.lbl}: ${seg.count}</span>`;
  });

  // Stat cards
  const statsData=[
    {icon:'📦',val:TOTAL_APPS,lbl:'Total Apps',cls:'c-trust'},
    {icon:'✅',val:excellent+good,lbl:'Secure Apps (≥70)',cls:'c-good'},
    {icon:'⚠',val:attn,lbl:'Needs Attention',cls:'c-warn'},
    {icon:'🔴',val:crit,lbl:'Critical Risk',cls:'c-risk'},
    {icon:'🔒',val:allCritFnd,lbl:'Critical Findings',cls:'c-risk'},
    {icon:'🟠',val:allHighFnd,lbl:'High Findings',cls:'c-warn'},
    {icon:'🌐',val:ztnaCount,lbl:'ZTNA Enrolled',cls:'c-info'},
    {icon:'💯',val:AVG_SCORE,lbl:'Avg ZT Score',cls:'c-trust'}
  ];
  const grid=document.getElementById('overviewStats');
  statsData.forEach(s=>{
    grid.innerHTML+=`<div class="stat-card ${s.cls}"><div class="stat-icon">${s.icon}</div><div class="stat-value">${s.val}</div><div class="stat-label">${s.lbl}</div></div>`;
  });
  document.getElementById('findingsBadge').textContent=allCritFnd+allHighFnd;

  // Defense Layer Stack
  const sevColors={Critical:'var(--risk)',High:'var(--risk)',Medium:'var(--warn)',Low:'var(--info)',Modern:'var(--trust)'};
  const layerStack=document.getElementById('layerStack');
  FACTOR_STATS.forEach(f=>{
    const col=f.pct>=80?'var(--good)':f.pct>=50?'var(--warn)':'var(--risk)';
    layerStack.innerHTML+=`
      <div class="layer-row" onclick="jumpToFactor('${escJ(f.key)}')">
        <div class="layer-weight">${f.max}<br>pts</div>
        <div class="layer-label" title="${escH(f.label)}">${escH(f.label)}</div>
        <div class="layer-track"><div class="layer-fill" style="width:0%;background:${col}" data-pct="${f.pct}"></div></div>
        <div class="layer-pct" style="color:${col}">${f.pct}%</div>
      </div>`;
  });
  requestAnimationFrame(()=>requestAnimationFrame(()=>{
    document.querySelectorAll('.layer-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';});
  }));

  // Top risk / top secure
  const sorted=[...APPS].sort((a,b)=>a.score-b.score);
  const riskEl=document.getElementById('topRiskList');
  sorted.slice(0,8).forEach(a=>{
    const col=scoreColor(a.score);
    riskEl.innerHTML+=`<div class="list-row" onclick="openDetail('${escJ(a.name)}')">${miniScoreBar(a.score)}<span class="lr-name" style="margin-left:6px">${escH(a.name)}</span><span class="score-pill" style="color:${col};background:${col}22">${clsLabel(a.classification)}</span></div>`;
  });

  const secureEl=document.getElementById('topSecureList');
  [...APPS].sort((a,b)=>b.score-a.score).slice(0,8).forEach(a=>{
    const col=scoreColor(a.score);
    secureEl.innerHTML+=`<div class="list-row" onclick="openDetail('${escJ(a.name)}')">${miniScoreBar(a.score)}<span class="lr-name" style="margin-left:6px">${escH(a.name)}</span><span class="score-pill" style="color:${col};background:${col}22">${clsLabel(a.classification)}</span></div>`;
  });
})();

function jumpToFactor(key){
  const factorToFindingId={PreAuth:'PassthroughAuth',CertValidation:'NoCertValidation',SecureCookie:'NoSecureCookie',HttpOnlyCookie:'NoHttpOnlyCookie',ZTNA:'NoZTNA',StateSession:'NoStateSession',OAuthFlow:'ImplicitGrant'};
  showPage('findings', document.querySelectorAll('.nav-btn')[2]);
  setTimeout(()=>{
    const fid=factorToFindingId[key];
    if(fid){
      const el=document.getElementById('fg-'+fid);
      if(el) el.scrollIntoView({behavior:'smooth',block:'center'});
    }
  },100);
}

// ════════════════════════════════════════════════════════════════
//  ALL APPS TABLE
// ════════════════════════════════════════════════════════════════
let PAGE_SIZE=20, filteredApps=[...APPS], currentPage=1, currentSort='score-asc';

(function initTable(){
  const sel=document.getElementById('authFilter');
  AUTH_TYPES.forEach(a=>{
    const o=document.createElement('option');
    o.value=a.label; o.textContent=`${a.label} (${a.count})`;
    sel.appendChild(o);
  });
  filterTable();
})();

function changePageSize(){PAGE_SIZE=parseInt(document.getElementById('pageSizeSelect').value);currentPage=1;renderTable();}

function sortByCol(col){
  const map={name:'name-asc',score:'score-asc'};
  const flip={asc:'desc',desc:'asc'};
  if(currentSort.startsWith(col)){const d=flip[currentSort.endsWith('asc')?'asc':'desc'];currentSort=col+'-'+d;}
  else{currentSort=map[col]||col+'-asc';}
  document.getElementById('sortSelect').value=currentSort;
  document.querySelectorAll('.apps-table thead th').forEach(t=>t.classList.remove('sort-active'));
  const th=document.getElementById('th-'+col);
  if(th){th.classList.add('sort-active');th.querySelector('.sort-arrow').textContent=currentSort.endsWith('asc')?'↑':'↓';}
  filterTable();
}

function filterTable(){
  const q=document.getElementById('tableSearch').value.toLowerCase().trim();
  const cls=document.getElementById('classFilter').value;
  const auth=document.getElementById('authFilter').value;
  currentSort=document.getElementById('sortSelect').value;
  filteredApps=APPS.filter(a=>{
    const mQ=!q||(a.name||'').toLowerCase().includes(q)||(a.authType||'').toLowerCase().includes(q)||(a.ssoMode||'').toLowerCase().includes(q)||(a.appType||'').toLowerCase().includes(q);
    const mC=!cls||a.classification===cls;
    const mA=!auth||a.authType===auth;
    return mQ&&mC&&mA;
  });
  const sorts={'score-asc':(a,b)=>a.score-b.score,'score-desc':(a,b)=>b.score-a.score,'name-asc':(a,b)=>(a.name||'').localeCompare(b.name||''),'name-desc':(a,b)=>(b.name||'').localeCompare(a.name||'')};
  if(sorts[currentSort]) filteredApps.sort(sorts[currentSort]);
  currentPage=1; renderTable();
}

function renderTable(){
  const start=(currentPage-1)*PAGE_SIZE;
  const slice=filteredApps.slice(start,start+PAGE_SIZE);
  document.getElementById('resultCount').textContent=`${filteredApps.length} of ${APPS.length}`;
  document.getElementById('pageInfo').textContent=`Showing ${start+1}–${Math.min(start+PAGE_SIZE,filteredApps.length)} of ${filteredApps.length}`;
  const authCol=t=>{
    if(!t) return 'var(--muted)';
    if(t==='aadPreAuthentication') return 'var(--good)';
    if(t==='passthru'||t==='passthrough') return 'var(--risk)';
    return 'var(--warn)';
  };
  document.getElementById('appsTableBody').innerHTML=slice.map((a,i)=>{
    const col=scoreColor(a.score);
    const acol=authCol(a.authType);
    const cntCrit=a.findings.filter(f=>f.severity==='Critical'||f.severity==='High').length;
    const cntAll=a.findings.length;
    return `<tr onclick="openDetailFromList(${start+i})">
      <td class="td-name">${escH(a.name)}</td>
      <td><div style="display:flex;align-items:center">${miniScoreBar(a.score)}</div></td>
      <td><span class="score-pill cls-${a.classification} bg-${a.classification}" style="font-size:11px;padding:2px 9px;border-radius:20px;font-family:var(--mono);font-weight:600">${clsLabel(a.classification)}</span></td>
      <td><span class="auth-badge" style="background:${acol}22;color:${acol};border:1px solid ${acol}44">${escH(a.authType||'—')}</span></td>
      <td class="td-meta">${escH(a.ssoMode||'none')}</td>
      <td><span class="bool-dot" style="background:${a.ztna?'var(--good)':'var(--muted)'}"></span></td>
      <td class="td-meta">${cntCrit>0?`<span style="color:var(--risk)">${cntCrit} critical/high</span>`:''}${cntAll>cntCrit?` <span style="color:var(--muted)">${cntAll-cntCrit} other</span>`:''}</td>
    </tr>`;
  }).join('');
  renderPagination();
}

function renderPagination(){
  const total=Math.ceil(filteredApps.length/PAGE_SIZE);
  const el=document.getElementById('pagination');
  if(total<=1){el.innerHTML='';return;}
  let h=`<button class="page-btn" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>‹</button>`;
  for(let i=1;i<=total;i++){
    if(i===1||i===total||Math.abs(i-currentPage)<=1) h+=`<button class="page-btn ${i===currentPage?'active':''}" onclick="goPage(${i})">${i}</button>`;
    else if(Math.abs(i-currentPage)===2) h+=`<span style="color:var(--muted);padding:0 4px">…</span>`;
  }
  h+=`<button class="page-btn" onclick="goPage(${currentPage+1})" ${currentPage===total?'disabled':''}>›</button>`;
  el.innerHTML=h;
}

function goPage(p){
  const total=Math.ceil(filteredApps.length/PAGE_SIZE);
  if(p<1||p>total) return;
  currentPage=p; renderTable();
}

// ════════════════════════════════════════════════════════════════
//  SECURITY FINDINGS
// ════════════════════════════════════════════════════════════════
(function buildFindings(){
  // Aggregate all unique finding types across all apps
  const findingMap={};
  APPS.forEach(app=>{
    app.findings.forEach(f=>{
      if(!findingMap[f.id]){
        findingMap[f.id]={id:f.id,severity:f.severity,title:f.title,detail:f.detail,points:f.points,apps:[]};
      }
      findingMap[f.id].apps.push(app.name);
    });
  });

  const severityOrder=['Critical','High','Medium','Low'];
  const sevColors={Critical:'var(--risk)',High:'var(--risk)',Medium:'var(--warn)',Low:'var(--info)'};
  const sevDimColors={Critical:'var(--risk-dim)',High:'var(--risk-dim)',Medium:'var(--warn-dim)',Low:'var(--info-dim)'};
  const container=document.getElementById('findingsContainer');

  severityOrder.forEach(sev=>{
    const grouped=Object.values(findingMap).filter(f=>f.severity===sev);
    if(!grouped.length) return;
    const col=sevColors[sev];
    let html=`<div class="severity-section">
      <div class="severity-head">
        <span class="severity-badge" style="background:${sevDimColors[sev]};color:${col};border:1px solid ${col}44">${sev}</span>
        <span class="severity-count">${grouped.length} finding type${grouped.length!==1?'s':''} affecting ${grouped.reduce((s,f)=>s+f.apps.length,0)} app instance${grouped.reduce((s,f)=>s+f.apps.length,0)!==1?'s':''}</span>
      </div>`;
    grouped.forEach(f=>{
      html+=`<div class="finding-group" id="fg-${escH(f.id)}">
        <div class="finding-group-head">
          <div>
            <div class="finding-group-title">${escH(f.title)}</div>
            <div class="finding-group-desc">${escH(f.detail)}</div>
            <div class="affected-apps-toggle" onclick="toggleAffected(this)">▸ Show affected apps (${f.apps.length})</div>
            <div class="affected-apps-list">
              ${f.apps.map(n=>`<span class="affected-app-chip" onclick="openDetail('${escJ(n)}')">${escH(n)}</span>`).join('')}
            </div>
          </div>
          <div class="finding-group-impact" style="color:${col}">${f.apps.length} app${f.apps.length!==1?'s':''}</div>
        </div>
      </div>`;
    });
    html+=`</div>`;
    container.innerHTML+=html;
  });

  if(!Object.keys(findingMap).length){
    container.innerHTML='<div style="text-align:center;padding:48px;color:var(--good)"><div style="font-size:36px;margin-bottom:12px">✅</div><div style="font-size:16px;font-weight:700">No findings detected!</div><div style="color:var(--muted);margin-top:6px;font-size:13px">All applications pass all Zero Trust controls.</div></div>';
  }
})();

function toggleAffected(btn){
  const list=btn.nextElementSibling;
  list.classList.toggle('open');
  btn.textContent=list.classList.contains('open')
    ?btn.textContent.replace('▸','▾').replace('Show','Hide')
    :btn.textContent.replace('▾','▸').replace('Hide','Show');
}

// ════════════════════════════════════════════════════════════════
//  RECOMMENDATIONS
// ════════════════════════════════════════════════════════════════
(function buildRecommendations(){
  const recos=[
    {
      id:'PassthroughAuth', severity:'Critical', priority:1,
      title:'Enable Azure AD Pre-Authentication on all apps',
      risk:'Apps using passthrough authentication bypass Azure AD entirely — Conditional Access, MFA, and risk-based sign-in policies have no effect. Attackers can attempt to reach the connector directly.',
      action:'In the Azure portal → Enterprise Applications → select each affected app → Application Proxy → set Authentication to Azure Active Directory.',
      cmdlet:'Set-AzureADApplicationProxyApplication -ObjectId <ObjectId> -ExternalAuthenticationType AadPreAuthentication',
      effort:'Low',scoreImpact:30
    },
    {
      id:'NoCertValidation', severity:'Critical', priority:2,
      title:'Enable backend certificate validation on all apps',
      risk:'Without certificate validation the connector cannot detect a man-in-the-middle attack on the internal network leg. Traffic between connector and backend server travels without TLS integrity.',
      action:'In Application Proxy settings for each app, enable "Validate backend SSL certificate". Ensure the backend server presents a valid, trusted TLS certificate.',
      cmdlet:'Set-AzureADApplicationProxyApplication -ObjectId <ObjectId> -IsBackendCertificateValidationEnabled $true',
      effort:'Medium',scoreImpact:20
    },
    {
      id:'NoSecureCookie', severity:'High', priority:3,
      title:'Enable Secure cookie flag on all apps',
      risk:'Without the Secure flag, session cookies can be sent over plain HTTP connections. This is exploitable on mixed-content pages or when a user navigates over an unencrypted network.',
      action:'In Application Proxy settings → enable "Use HTTP-Only Cookie" and "Use Secure Cookie".',
      cmdlet:'Set-AzureADApplicationProxyApplication -ObjectId <ObjectId> -IsSecureCookieEnabled $true',
      effort:'Low',scoreImpact:15
    },
    {
      id:'NoHttpOnlyCookie', severity:'High', priority:4,
      title:'Enable HTTP-Only cookie flag on all apps',
      risk:'Session cookies without the HttpOnly flag are accessible to JavaScript running on the page. Successful XSS attacks can steal session tokens silently.',
      action:'In Application Proxy settings → enable "Use HTTP-Only Cookie".',
      cmdlet:'Set-AzureADApplicationProxyApplication -ObjectId <ObjectId> -IsHttpOnlyCookieEnabled $true',
      effort:'Low',scoreImpact:15
    },
    {
      id:'NoZTNA', severity:'Medium', priority:5,
      title:'Enrol apps in Global Secure Access (ZTNA)',
      risk:'Apps not enrolled in Global Secure Access fall back to legacy VPN or direct internet exposure. ZTNA provides per-session, identity-aware access with continuous evaluation — the 2026 ZT standard for app access.',
      action:'In the Azure portal → Global Secure Access → Applications → Enterprise Apps → add each affected app and assign the Quick Access or Custom App profile.',
      cmdlet:null,
      effort:'High',scoreImpact:10
    },
    {
      id:'ImplicitGrant', severity:'Medium', priority:6,
      title:'Disable legacy OAuth implicit grant flow',
      risk:'The implicit grant flow returns tokens directly in the URL fragment, which can be logged by proxies or browser history. The 2023+ security guidance mandates authorization code + PKCE instead.',
      action:'In Azure AD App Registrations → Authentication → disable "ID tokens (used for implicit and hybrid flows)" and "Access tokens (used for implicit flows)".',
      cmdlet:null,
      effort:'Low',scoreImpact:5
    },
    {
      id:'NoStateSession', severity:'Low', priority:7,
      title:'Enable state session management',
      risk:'Without state session tracking, the Application Proxy cannot enforce idle session timeouts at the proxy layer, potentially leaving sessions active beyond their intended lifetime.',
      action:'In Application Proxy advanced settings for each app, enable state session management.',
      cmdlet:'Set-AzureADApplicationProxyApplication -ObjectId <ObjectId> -IsStateSessionEnabled $true',
      effort:'Low',scoreImpact:5
    }
  ];

  // Only include recommendations where at least one app has the finding
  const findingIds=new Set(APPS.flatMap(a=>a.findings.map(f=>f.id)));
  const active=recos.filter(r=>findingIds.has(r.id));

  const container=document.getElementById('recommendationsContainer');
  if(!active.length){
    container.innerHTML='<div style="text-align:center;padding:48px;color:var(--good)"><div style="font-size:36px;margin-bottom:12px">🏆</div><div style="font-size:16px;font-weight:700">All checks passed!</div><div style="color:var(--muted);margin-top:6px;font-size:13px">No remediation actions are needed at this time.</div></div>';
    return;
  }

  const sevCol={Critical:'var(--risk)',High:'var(--risk)',Medium:'var(--warn)',Low:'var(--info)'};
  active.forEach((r,i)=>{
    const affectedApps=APPS.filter(a=>a.findings.some(f=>f.id===r.id));
    const col=sevCol[r.severity]||'var(--muted)';
    container.innerHTML+=`
    <div class="reco-card pri-${r.severity}">
      <div class="reco-rank">
        <span class="reco-sev-dot" style="background:${col}"></span>
        Priority ${i+1} · ${r.severity}
      </div>
      <div class="reco-title">${escH(r.title)}</div>
      <div class="reco-desc">${escH(r.risk)}</div>
      <div class="reco-meta">
        <span class="reco-meta-chip" style="color:${col}">⚡ +${r.scoreImpact} pts per app</span>
        <span class="reco-meta-chip">🛠 Effort: ${r.effort}</span>
        <span class="reco-meta-chip">📦 ${affectedApps.length} app${affectedApps.length!==1?'s':''} affected</span>
      </div>
      <div class="reco-action">
        <strong>How to fix: </strong>${escH(r.action)}
        ${r.cmdlet?`<br><br><strong>PowerShell: </strong><code>${escH(r.cmdlet)}</code>`:''}
      </div>
    </div>`;
  });

  // Store for CSV export
  window._recos=active.map(r=>({...r,affectedCount:APPS.filter(a=>a.findings.some(f=>f.id===r.id)).length}));
})();

// ════════════════════════════════════════════════════════════════
//  EXPLORER
// ════════════════════════════════════════════════════════════════
let explorerGroup='auth';

function setExplorerGroup(btn){
  document.querySelectorAll('.explorer-tab').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  explorerGroup=btn.dataset.group;
  buildExplorer();
}

function buildExplorer(){
  const grid=document.getElementById('facetGrid');
  grid.innerHTML='';
  let groups;
  if(explorerGroup==='auth')    groups=AUTH_TYPES.map(g=>({label:g.label,apps:APPS.filter(a=>a.authType===g.label)}));
  else if(explorerGroup==='apptype') groups=APP_TYPES.map(g=>({label:g.label,apps:APPS.filter(a=>a.appType===g.label)}));
  else groups=SSO_MODES.map(g=>({label:g.label,apps:APPS.filter(a=>a.ssoMode===g.label)}));

  groups.forEach(g=>{
    if(!g.apps.length) return;
    const avgSc=Math.round(g.apps.reduce((s,a)=>s+a.score,0)/g.apps.length);
    const col=scoreColor(avgSc);
    grid.innerHTML+=`<div class="facet-card">
      <div class="facet-card-head" style="border-left:3px solid ${col}">
        <span class="fname" style="color:${col}">${escH(g.label)}</span>
        <span class="fcount">${g.apps.length} app${g.apps.length!==1?'s':''} · avg ${avgSc}</span>
      </div>
      <div class="facet-apps">
        ${g.apps.sort((a,b)=>a.score-b.score).map(a=>`
          <div class="facet-app-row" onclick="openDetail('${escJ(a.name)}')">
            ${miniScoreBar(a.score)}
            <span class="facet-app-name" title="${escH(a.name)}" style="margin-left:6px">${escH(a.name)}</span>
          </div>`).join('')}
      </div>
    </div>`;
  });
}
buildExplorer();

// ════════════════════════════════════════════════════════════════
//  ANALYTICS
// ════════════════════════════════════════════════════════════════
(function buildAnalytics(){
  // Score distribution
  const buckets=[
    {l:'90–100 (Excellent)',fn:a=>a.score>=90,col:'var(--good)'},
    {l:'70–89 (Good)',fn:a=>a.score>=70&&a.score<90,col:'var(--trust)'},
    {l:'50–69 (Attention)',fn:a=>a.score>=50&&a.score<70,col:'var(--warn)'},
    {l:'0–49 (Critical)',fn:a=>a.score<50,col:'var(--risk)'}
  ];
  const bMax=Math.max(...buckets.map(b=>APPS.filter(b.fn).length),1);
  let sdHtml='';
  buckets.forEach(b=>{
    const cnt=APPS.filter(b.fn).length;
    const pct=Math.round((cnt/bMax)*100);
    sdHtml+=`<div class="bucket-row"><span class="bucket-label">${b.l}</span><div class="bucket-bar"><div class="bucket-fill" data-pct="${pct}" style="width:0%;background:${b.col}"></div></div><span class="bucket-count">${cnt}</span></div>`;
  });
  document.getElementById('scoreDistribution').innerHTML=sdHtml;

  // Control coverage
  let ccHtml='';
  FACTOR_STATS.forEach(f=>{
    const col=f.pct>=80?'var(--good)':f.pct>=50?'var(--warn)':'var(--risk)';
    ccHtml+=`<div class="coverage-row"><span class="coverage-label" title="${escH(f.label)}">${escH(f.label)}</span><div class="coverage-bar"><div class="coverage-fill" data-pct="${f.pct}" style="width:0%;background:${col}"></div></div><span class="coverage-pct" style="color:${col}">${f.pass}/${f.total} (${f.pct}%)</span></div>`;
  });
  document.getElementById('controlCoverage').innerHTML=ccHtml;

  // Auth breakdown
  let abHtml='';
  const abMax=Math.max(...AUTH_TYPES.map(a=>a.count),1);
  const abCols=['var(--good)','var(--warn)','var(--trust)','var(--info)','var(--purple)'];
  AUTH_TYPES.forEach((a,i)=>{
    const pct=Math.round((a.count/abMax)*100);
    abHtml+=`<div class="bucket-row"><span class="bucket-label">${escH(a.label)}</span><div class="bucket-bar"><div class="bucket-fill" data-pct="${pct}" style="width:0%;background:${abCols[i%abCols.length]}"></div></div><span class="bucket-count">${a.count}</span></div>`;
  });
  document.getElementById('authBreakdown').innerHTML=abHtml;

  // SSO breakdown
  let sbHtml='';
  const sbMax=Math.max(...SSO_MODES.map(a=>a.count),1);
  SSO_MODES.forEach((a,i)=>{
    const pct=Math.round((a.count/sbMax)*100);
    sbHtml+=`<div class="bucket-row"><span class="bucket-label">${escH(a.label)}</span><div class="bucket-bar"><div class="bucket-fill" data-pct="${pct}" style="width:0%;background:${abCols[i%abCols.length]}"></div></div><span class="bucket-count">${a.count}</span></div>`;
  });
  document.getElementById('ssoBreakdown').innerHTML=sbHtml;

  // Animate all bars
  requestAnimationFrame(()=>requestAnimationFrame(()=>{
    document.querySelectorAll('.bucket-fill,.coverage-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';});
  }));

  // ZT Callouts
  const preAuthPct=FACTOR_STATS.find(f=>f.key==='PreAuth')?.pct||0;
  const certPct=FACTOR_STATS.find(f=>f.key==='CertValidation')?.pct||0;
  const ztnaPct=FACTOR_STATS.find(f=>f.key==='ZTNA')?.pct||0;
  const cookiePct=FACTOR_STATS.find(f=>f.key==='SecureCookie')?.pct||0;

  let callouts='';
  callouts+=`<div class="callout ${preAuthPct<100?'risk':'good'}"><strong>Azure AD Pre-Authentication: ${preAuthPct}% compliance.</strong> ${preAuthPct===100?'All apps enforce AAD pre-authentication — Conditional Access and MFA are effective across the board.':'Apps using passthrough authentication are the highest-priority risk. Conditional Access, MFA, and sign-in risk policies are completely bypassed for these apps.'}</div>`;
  callouts+=`<div class="callout ${certPct<100?'risk':'good'}"><strong>Backend TLS Certificate Validation: ${certPct}% compliance.</strong> ${certPct===100?'All internal connections validate backend certificates, protecting against internal MITM attacks.':'The connector-to-backend TLS path is unvalidated for some apps. Combined with passthrough auth, this creates an exploitable chain.'}</div>`;
  callouts+=`<div class="callout ${ztnaPct<50?'warn':'good'}"><strong>Global Secure Access (ZTNA) Enrollment: ${ztnaPct}% of apps.</strong> Microsoft recommends migrating from Application Proxy to Global Secure Access for a modern, identity-aware access model with continuous evaluation. Apps not enrolled continue to work but miss per-session risk controls.</div>`;
  callouts+=`<div class="callout ${cookiePct<100?'warn':'good'}"><strong>Session Cookie Hygiene: ${cookiePct}% Secure-flag compliance.</strong> Cookie flags are a low-effort, high-value control. Both Secure and HttpOnly should be enabled on every app — it is a one-click change per app with no user-visible impact.</div>`;
  callouts+=`<div class="callout"><strong>2026 Zero Trust Application Access Model.</strong> The scoring model rewards: identity-based pre-auth (30 pts), transport security (20 pts), session hygiene (30 pts combined), and modern access evolution (15 pts). Any app scoring below 50 has multiple critical gaps and should be prioritized for immediate remediation.</div>`;
  document.getElementById('ztCallouts').innerHTML=callouts;
})();

// ════════════════════════════════════════════════════════════════
//  RAW DATA TABLE
// ════════════════════════════════════════════════════════════════
let filteredRawRows=[...RAW_ROWS];

(function buildRawTable(){
  renderRawTable();
})();

function filterRawTable(){
  const q=document.getElementById('rawSearch').value.toLowerCase().trim();
  if(!q){filteredRawRows=[...RAW_ROWS];}
  else{filteredRawRows=RAW_ROWS.filter(row=>row.some(cell=>String(cell).toLowerCase().includes(q)));}
  document.getElementById('rawResultCount').textContent=`${filteredRawRows.length} of ${RAW_ROWS.length}`;
  renderRawTable();
}

function renderRawTable(){
  const t=document.getElementById('rawTable');
  t.innerHTML='<thead><tr>'+RAW_COLUMNS.map(c=>`<th>${escH(c)}</th>`).join('')+'</tr></thead>'
    +'<tbody>'+filteredRawRows.map(row=>`<tr>${row.map(c=>`<td>${escH(c)}</td>`).join('')}</tr>`).join('')+'</tbody>';
  document.getElementById('rawResultCount').textContent=`${filteredRawRows.length} of ${RAW_ROWS.length}`;
}

// ════════════════════════════════════════════════════════════════
//  DETAIL DRAWER
// ════════════════════════════════════════════════════════════════
let currentDetailIndex=-1, detailList=APPS;

function openDetailFromList(idx){detailList=filteredApps;currentDetailIndex=idx;_renderDetail(detailList[idx]);}
function openDetail(name){const idx=APPS.findIndex(x=>x.name===name);detailList=APPS;currentDetailIndex=idx;if(idx>=0)_renderDetail(APPS[idx]);}
function navigateDetail(dir){const ni=currentDetailIndex+dir;if(ni<0||ni>=detailList.length)return;currentDetailIndex=ni;_renderDetail(detailList[ni]);}

function _renderDetail(a){
  if(!a) return;
  document.getElementById('detailPrevBtn').disabled=currentDetailIndex<=0;
  document.getElementById('detailNextBtn').disabled=currentDetailIndex>=detailList.length-1;

  const scoreCol=scoreColor(a.score);
  const circ=2*Math.PI*26; // r=26 → 163.4

  // Factor grid
  const factorLabels={PreAuth:'AAD Pre-Auth',CertValidation:'Cert Validation',SecureCookie:'Secure Cookie',HttpOnlyCookie:'HttpOnly Cookie',ZTNA:'ZTNA Client',StateSession:'State Session',OAuthFlow:'OAuth Flow'};
  const factorGridHtml=Object.entries(a.factors).map(([k,v])=>{
    const icon=v.pass?'✅':'❌';
    return `<div class="factor-chip"><span class="fc-icon">${icon}</span><span class="fc-label" title="${escH(factorLabels[k]||k)}">${escH(factorLabels[k]||k)}</span><span style="font-family:var(--mono);font-size:11px;color:${v.pass?'var(--good)':'var(--risk)'};font-weight:700">${v.points}/${v.max}</span></div>`;
  }).join('');

  // Findings
  const findingsHtml=a.findings.length
    ? a.findings.map(f=>{
        const fc={Critical:'var(--risk)',High:'var(--risk)',Medium:'var(--warn)',Low:'var(--info)'}[f.severity]||'var(--muted)';
        return `<div class="finding-card" style="border-color:${fc}44;background:${fc}0a">
          <div class="finding-head">
            <span class="finding-sev-badge" style="background:${fc}22;color:${fc}">${f.severity}</span>
            <span class="finding-title">${escH(f.title)}</span>
            <span class="finding-points" style="color:${fc}">${f.points} pts</span>
          </div>
          <div class="finding-detail">${escH(f.detail)}</div>
        </div>`;
      }).join('')
    : '<div style="color:var(--good);font-size:13px;padding:8px 0">✅ No findings — this app passes all Zero Trust controls.</div>';

  // URLs
  const urlRows=[
    {l:'External URL',v:a.externalUrl},{l:'Internal URL',v:a.internalUrl},
    {l:'Home Page',v:a.homePageUrl},{l:'Logout URL',v:a.logoutUrl}
  ].filter(r=>r.v).map(r=>`<div class="url-row"><span class="url-label">${r.l}</span><span class="url-val">${escH(r.v)}</span></div>`).join('');

  document.getElementById('detailContent').innerHTML=`
    <div class="detail-app-header">
      <div class="detail-score-wrap">
        <svg viewBox="0 0 68 68">
          <circle cx="34" cy="34" r="26" fill="none" stroke="var(--surface3)" stroke-width="8"/>
          <circle cx="34" cy="34" r="26" fill="none" stroke="${scoreCol}" stroke-width="8"
            stroke-dasharray="${circ}" stroke-dashoffset="${circ*(1-a.score/100)}"
            stroke-linecap="round" transform="rotate(-90 34 34)"/>
        </svg>
        <div class="detail-score-center" style="color:${scoreCol}">${a.score}</div>
      </div>
      <div>
        <div class="detail-app-name">${escH(a.name)}</div>
        <div class="detail-app-id">App ID: ${escH(a.appId)}</div>
        <div class="detail-app-id">Object ID: ${escH(a.objectId)}</div>
      </div>
    </div>
    <div class="detail-meta-row">
      <span class="score-pill cls-${a.classification} bg-${a.classification}" style="font-family:var(--mono);font-size:11px;padding:3px 10px;border-radius:20px;font-weight:700">${clsLabel(a.classification)}</span>
      <span class="detail-chip">Auth: ${escH(a.authType||'—')}</span>
      <span class="detail-chip">SSO: ${escH(a.ssoMode||'none')}</span>
      <span class="detail-chip">${a.enabled?'✅ Enabled':'⚠ Disabled'}</span>
      <span class="detail-chip">${a.ztna?'🌐 ZTNA':'No ZTNA'}</span>
      <span class="detail-chip">Timeout: ${escH(a.serverTimeout||'Default')}</span>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Zero Trust Factors</div>
      <div class="factor-grid">${factorGridHtml}</div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Security Findings (${a.findings.length})</div>
      ${findingsHtml}
    </div>

    ${urlRows?`<div class="detail-section"><div class="detail-section-title">URLs</div>${urlRows}</div>`:''}

    <div class="detail-section">
      <div class="detail-section-title">Cookie & Session Configuration</div>
      <div class="factor-grid">
        <div class="factor-chip"><span class="fc-icon">${a.secureCookie?'✅':'❌'}</span><span class="fc-label">Secure Cookie</span></div>
        <div class="factor-chip"><span class="fc-icon">${a.httpOnlyCookie?'✅':'❌'}</span><span class="fc-label">HttpOnly Cookie</span></div>
        <div class="factor-chip"><span class="fc-icon">${a.persistentCookie?'✅':'❌'}</span><span class="fc-label">Persistent Cookie</span></div>
        <div class="factor-chip"><span class="fc-icon">${a.stateSession?'✅':'❌'}</span><span class="fc-label">State Session</span></div>
        <div class="factor-chip"><span class="fc-icon">${a.translateHostHeader?'✅':'❌'}</span><span class="fc-label">Translate Host Header</span></div>
        <div class="factor-chip"><span class="fc-icon">${a.translateLinks?'✅':'❌'}</span><span class="fc-label">Translate Links in Body</span></div>
        <div class="factor-chip"><span class="fc-icon">${a.dnsResolution?'✅':'❌'}</span><span class="fc-label">DNS Resolution</span></div>
      </div>
    </div>`;

  document.getElementById('detailPanel').classList.add('open');
  document.body.style.overflow='hidden';
  document.getElementById('detailContent').scrollTo(0,0);
}

function closeDetail(){document.getElementById('detailPanel').classList.remove('open');document.body.style.overflow='';}
function copyDetailName(){if(currentDetailIndex>=0&&detailList[currentDetailIndex])copyText(detailList[currentDetailIndex].name);}
function copyText(text){
  try{navigator.clipboard.writeText(text).then(()=>showToast('Copied to clipboard!'));}
  catch(e){showToast('Copy not available','⚠');}
}

// ════════════════════════════════════════════════════════════════
//  EXPORTS
// ════════════════════════════════════════════════════════════════
function exportCSV(filtered){
  const data=filtered?filteredApps:APPS;
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const header='Name,AppId,ObjectId,AuthType,SSOMode,AppType,Score,Classification,Enabled,ZTNA,SecureCookie,HttpOnlyCookie,CertValidation,Findings,ExternalUrl,InternalUrl';
  const rows=data.map(a=>[
    esc(a.name),esc(a.appId),esc(a.objectId),esc(a.authType),esc(a.ssoMode),esc(a.appType),
    a.score,esc(a.classification),a.enabled,a.ztna,a.secureCookie,a.httpOnlyCookie,a.certValidation,
    a.findings.length,esc(a.externalUrl),esc(a.internalUrl)
  ].join(','));
  dlFile([header,...rows].join('\r\n'),'AppProxyZeroTrust.csv','text/csv');
  showToast(`Exported ${data.length} apps as CSV`);
}

function exportJSON(filtered){
  const data=filtered?filteredApps:APPS;
  dlFile(JSON.stringify(data,null,2),'AppProxyZeroTrust.json','application/json');
  showToast(`Exported ${data.length} apps as JSON`);
}

function exportRawCSV(){
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const header=RAW_COLUMNS.map(c=>esc(c)).join(',');
  const rows=filteredRawRows.map(row=>row.map(c=>esc(c)).join(','));
  dlFile([header,...rows].join('\r\n'),'AppProxyRawData.csv','text/csv');
  showToast(`Exported ${filteredRawRows.length} rows as CSV`);
}

function exportRecommendationsCSV(){
  const recos=window._recos||[];
  if(!recos.length){showToast('No recommendations to export','ℹ');return;}
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const header='Priority,Severity,Title,Risk,Action,Effort,ScoreImpact,AffectedApps';
  const rows=recos.map((r,i)=>[i+1,esc(r.severity),esc(r.title),esc(r.risk),esc(r.action),esc(r.effort),r.scoreImpact,r.affectedCount].join(','));
  dlFile([header,...rows].join('\r\n'),'AppProxyRecommendations.csv','text/csv');
  showToast('Recommendations plan exported');
}

function dlFile(content,name,type){
  const b=new Blob([content],{type});
  const u=URL.createObjectURL(b);
  const a=document.createElement('a');
  a.href=u; a.download=name; a.click();
  URL.revokeObjectURL(u);
}

// ════════════════════════════════════════════════════════════════
//  KEYBOARD SHORTCUTS
// ════════════════════════════════════════════════════════════════
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closeDetail();return;}
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'&&document.activeElement.tagName!=='SELECT'){
    e.preventDefault();
    const inp=document.querySelector('.page.active input[type=text]');
    if(inp) inp.focus();
  }
  if(document.getElementById('detailPanel').classList.contains('open')){
    if(e.key==='ArrowLeft')  navigateDetail(-1);
    if(e.key==='ArrowRight') navigateDetail(1);
  }
});
</script>
</body>
</html>
'@

  #endregion

  #region ── Token Replacement ──────────────────────────────────────────────────

  $html = $html `
    -replace '__TENANTDISPLAY__', (ConvertTo-JsonSafe $tenantDisplay) `
    -replace '__APPCOUNT__', $totalApps `
    -replace '__AVGSCORE__', $avgScore `
    -replace '__GENERATEDAT__', $generatedAt `
    -replace '__APPS_JSON__', $appsJson `
    -replace '__FACTOR_STATS_JSON__', $factorStatsJson `
    -replace '__AUTH_TYPE_JSON__', $authTypeJson `
    -replace '__APP_TYPE_JSON__', $appTypeJson `
    -replace '__SSO_MODE_JSON__', $ssoModeJson `
    -replace '__RAW_COLUMNS_JSON__', $rawColumnsJson `
    -replace '__RAW_ROWS_JSON__', $rawRowsJson

  #endregion

  #region ── Output ─────────────────────────────────────────────────────────────

  $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

  $fileSizeKB = [math]::Round((Get-Item $OutputPath).Length / 1KB, 1)

  Write-Host ""
  Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
  Write-Host "║   ✅  App Proxy Zero Trust Dashboard — generated!            ║" -ForegroundColor Cyan
  Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "  📊  Apps indexed      : $totalApps"                                                     -ForegroundColor White
  Write-Host "  💯  Average ZT score  : $avgScore / 100"                                                -ForegroundColor White
  Write-Host "  ✅  Excellent / Good  : $excellentCount / $goodCount"                                   -ForegroundColor White
  Write-Host "  ⚠   Needs Attention   : $attentionCount"                                                -ForegroundColor Yellow
  Write-Host "  🔴  Critical risk     : $criticalCount"                                                 -ForegroundColor $(if ($criticalCount -eq 0) { 'Green' }else { 'Red' })
  Write-Host "  🔒  Critical findings : $($criticalFindings.Count)"                                     -ForegroundColor $(if ($criticalFindings.Count -eq 0) { 'Green' }else { 'Red' })
  Write-Host "  🟠  High findings     : $($highFindings.Count)"                                         -ForegroundColor $(if ($highFindings.Count -eq 0) { 'Green' }else { 'Yellow' })
  Write-Host "  📁  Output file       : $OutputPath ($fileSizeKB KB)"                                   -ForegroundColor White
  Write-Host ""

  if ($OpenBrowser) {
    Write-Host "  🌐  Opening in browser…" -ForegroundColor Green
    Start-Process $OutputPath
  }

  #endregion
}
