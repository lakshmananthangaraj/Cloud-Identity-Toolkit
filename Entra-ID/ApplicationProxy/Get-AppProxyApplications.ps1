<#

Author          : Lakshmanan Thangaraj
Version         : 2.4
Created-On      : 30 July 2024
Modified-On     : 24 July 2026

.SYNOPSIS
    Scans Entra ID for applications configured with Application Proxy, analyzes
    security posture using 2026 Zero Trust standards, and generates comprehensive
    reports (CSV, JSON, HTML).

.DESCRIPTION
    This function retrieves all applications from Entra ID (Microsoft Graph beta
    endpoint) and checks each for Application Proxy configuration. It extracts
    detailed proxy settings (external/internal URLs, authentication type, cookie
    flags, certificate validation, ZTNA compliance, etc.) and calculates a
    security score based on a 7‑factor model.

    The tool supports both direct bearer token and client credentials (app‑only)
    authentication, with automatic token renewal during long‑running sequential
    scans. It can process applications in parallel (PowerShell 7+) for large
    environments, dramatically reducing execution time.

    Outputs include:
        - CSV file (tabular data)
        - JSON file (structured data)
        - HTML report (visual dashboard with security insights and recommendations)

    Security scoring is based on:
        - Backend Certificate Validation (25 pts)
        - Azure AD Pre‑Authentication (25 pts)
        - Secure Cookie (15 pts)
        - HTTP‑Only Cookie (15 pts)
        - ZTNA Client Access (10 pts)
        - Session State Management (5 pts)
        - OAuth Flow Security (implicit grant detection) (5 pts)

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required when using the DirectToken parameter set.
    Required permission: Application.Read.All

.PARAMETER ClientId
    The Application (client) ID of the Azure AD app registration.
    Required when using the ClientCredentials parameter set.

.PARAMETER ClientSecret
    The client secret associated with the Azure AD app registration, supplied
    as a SecureString. Example:
        $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    Required when using the ClientCredentials parameter set.

.PARAMETER TenantId
    The Directory (tenant) ID of the Entra ID tenant to query.
    Required when using the ClientCredentials parameter set.

.PARAMETER exportFormat
    Specifies the export format for the report. Valid values:
        None   - No CSV/JSON export (HTML is still generated)
        CSV    - Export to CSV only
        JSON   - Export to JSON only
        Both   - Export to both CSV and JSON
    Default: None

.PARAMETER exportPath
    Full path (without extension) where the report files will be saved.
    If not specified, a timestamped path under C:\Temp\AppProxyConfigs_<timestamp>
    is auto‑generated.

.PARAMETER DisableParallel
    If set, disables parallel processing and forces sequential mode.
    Recommended for environments where API throttling is a concern or when
    you need deterministic, step‑by‑step output.

.PARAMETER ThrottleLimit
    Number of parallel threads to use when parallel mode is active.
    Default: 10. Values above 15 may cause throttling and missed results.
    Recommended range: 5–10 for reliability.

.PARAMETER ShowHelp
    Displays a friendly, plain‑language usage guide and exits immediately.
    No authentication is attempted and no other parameters are required
    when this switch is used.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
        An array of custom objects containing the Application Proxy details
        for each proxy‑enabled application. Also exports files to disk.

.EXAMPLE
    $token = (Get-MgContext).AccessToken
    Get-AppProxyApplications -AccessToken $token

    Runs a basic scan using a direct token, without exporting CSV/JSON.

.EXAMPLE
    $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    Get-AppProxyApplications -ClientId "8ad5d2f5-xxxx" -ClientSecret $secret -TenantId "f4310b4f-xxxx" -exportFormat Both

    Scans using client credentials and exports both CSV and JSON reports.

.EXAMPLE
    Get-AppProxyApplications -AccessToken $token -exportFormat CSV -exportPath "D:\Reports\AppProxyScan"

    Exports CSV report to a custom location.

.EXAMPLE
    Get-AppProxyApplications -AccessToken $token -DisableParallel -ThrottleLimit 5 -exportFormat JSON

    Runs in sequential mode with reduced thread count (only relevant if parallel
    were enabled, but -DisableParallel forces sequential anyway).

.EXAMPLE
    Get-AppProxyApplications -ShowHelp

    Displays the friendly usage guide and exits.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (30-Jul-2024)  - Initial release.
        2.0 (03-Mar-2026)  - Added parallel processing, modern UI, HTML reports.
        2.1 (03-Mar-2026)  - White-themed HTML, detailed step display, enhanced
                                documentation.
        2.2 (04-Mar-2026)  - JWT token decoding for dynamic tenant information.
                            - Recommended max ThrottleLimit: 10.
        2.3 (04-Mar-2026)  - Integrated 2026 security scoring model:
                                • 7‑factor security scoring (100 points)
                                • Zero Trust Network Access compliance
                                • Modern OAuth flow validation
                                • Console security insights
                                • Enhanced HTML with category scores
                                • Detailed findings & recommendations
        2.4 (24-Jul-2026)  - Added client credentials authentication
                                (ClientId, ClientSecret, TenantId parameters).
                            - Added -ShowHelp switch for friendly usage guide.
                            - Added SecureString handling for ClientSecret.
                            - Added automatic token renewal during sequential scans.
                            - Updated documentation to standard template.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Azure AD App Registration with admin-consented API permission:
                Application.Read.All (Application)

        2. When using client credentials, the app registration must have
            a client secret configured.

        3. PowerShell 5.1 or later (PowerShell 7+ recommended for parallel
            processing).

    ─────────────────────────────────────────────────────────────────────────────
    Functions:
    ─────────────────────────────────────────────────────────────────────────────
        Show-FriendlyHelp
            Prints a plain‑language usage guide (parameters, examples,
            prerequisites) via Write‑Host and exits.

        Connect-EntraID
            Authenticates to Microsoft Graph using client credentials flow
            and returns a bearer token. Stores credentials and refresh interval
            in global variables for automatic renewal.

        RequestAccessToken / ShouldRenewToken / RenewTokenIfNeeded
            Internal helpers that manage token lifecycle for client‑credentials
            authentication during sequential scans.

        Get-TenantDetails
            Retrieves tenant display name and primary domain from Graph API
            for use in reports.

        Calculate-SecurityScore-2026
            Implements the 7‑factor security scoring model and returns a
            hashtable with overall score, category breakdown, and detailed
            findings.

        Show-SecurityInsights
            Displays security score, classification, and top issues in the
            console during the scan.

        Generate-HtmlReport
            Produces a modern HTML dashboard with all security insights,
            category scores, and recommendations.

        Write-CenteredText, Write-Banner, Write-Section, Write-StageHeader,
        Write-ProgressBar
            UI helpers for consistent, colorful console output.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  →  If -ShowHelp was supplied, print the friendly guide and exit.
        Step 1  →  Authenticate (direct token or client credentials).
        Step 2  →  Discover all applications (paginated Graph API calls).
        Step 3  →  Analyze each application for App Proxy settings
                    (parallel or sequential).
        Step 4  →  Calculate 2026 security score and display insights.
        Step 5  →  Generate reports (CSV, JSON, HTML) as requested.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The script uses the /beta Graph API endpoint. Beta endpoints are
            subject to change and are not recommended for production without
            monitoring for breaking changes.
        - In parallel mode, token renewal is not supported because each thread
            uses a copy of the initial token. For extremely long runs (> 1 hour),
            use sequential mode (-DisableParallel) with client credentials
            to benefit from automatic renewal.
        - Setting ThrottleLimit too high (> 15) may trigger API throttling
            (HTTP 429) and result in incomplete data. The recommended value is 10.
        - The client secret is marshaled to plaintext in memory for the brief
            moment required to build the OAuth token request body. This is
            inherent to the client‑credentials grant type, not a script shortcut.

.LINK
    Microsoft Graph API - List Applications
    https://learn.microsoft.com/en-us/graph/api/application-list

.LINK
    Microsoft Graph API - Application resource type
    https://learn.microsoft.com/en-us/graph/api/resources/application

.LINK
    Application Proxy documentation
    https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/

#>


# ─────────────────────────────────────────────────────────────────────────────
# Friendly Help
# ─────────────────────────────────────────────────────────────────────────────

Function Show-FriendlyHelp 
{
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║            Entra ID — Application Proxy Scanner              ║" -ForegroundColor Cyan
    Write-Host "  ║                    Version 2.4  |  Help                      ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this script does:" -ForegroundColor Yellow
    Write-Host "    Scans Entra ID for applications with Application Proxy configured,"
    Write-Host "    analyzes security posture (2026 Zero Trust standards), and generates"
    Write-Host "    comprehensive reports (CSV, JSON, HTML)."
    Write-Host ""
    Write-Host "  Authentication options:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Option A - Direct Bearer Token:" -ForegroundColor Cyan
    Write-Host "    -AccessToken    Access token with Application.Read.All permission"
    Write-Host ""
    Write-Host "  Option B - Client Credentials Flow:" -ForegroundColor Cyan
    Write-Host "    -ClientId       Application (client) ID of your Azure AD app registration"
    Write-Host "    -ClientSecret   The app's client secret, as a SecureString (see example)"
    Write-Host "    -TenantId       Directory (tenant) ID of the Entra ID tenant"
    Write-Host ""
    Write-Host "  Other parameters:" -ForegroundColor Yellow
    Write-Host "    -exportFormat   None, CSV, JSON, Both (default: None)"
    Write-Host "    -exportPath     Custom path for export files (auto-generated if not specified)"
    Write-Host "    -DisableParallel Disable parallel processing (use sequential)"
    Write-Host "    -ThrottleLimit  Number of parallel threads (default: 10)"
    Write-Host "    -ShowHelp       Shows this guide and exits"
    Write-Host ""
    Write-Host "  Before you run it:" -ForegroundColor Yellow
    Write-Host "    1. Your app registration needs this Graph API Application permission,"
    Write-Host "       admin-consented: Application.Read.All"
    Write-Host ""
    Write-Host "  Example (Client Credentials):" -ForegroundColor Yellow
    Write-Host '    $secret = Read-Host -Prompt "Client secret" -AsSecureString'
    Write-Host '    Get-AppProxyApplications -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" -exportFormat Both'
    Write-Host ""
    Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
    Write-Host "     Get-Help Get-AppProxyApplications -Full"
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Token Renewal Helpers (for client credentials)
# ─────────────────────────────────────────────────────────────────────────────

Function RequestAccessToken
{
    $tokenEndpoint = "https://login.microsoftonline.com/$global:TenantId/oauth2/v2.0/token"

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($global:ClientSecretSecure)
    Try {
        $plainClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        $tokenRequestBody = @{
            client_id     = $global:ClientId
            client_secret = $plainClientSecret
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "client_credentials"
        }
        $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $tokenRequestBody
        $global:accessToken = $tokenResponse.access_token
        $global:tokenExpirationTime = (Get-Date).AddSeconds($tokenResponse.expires_in)
    }
    Finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $plainClientSecret = $null
        $tokenRequestBody = $null
    }
}

Function ShouldRenewToken
{
    if (!$global:accessToken -or !$global:tokenExpirationTime) {
        return $true
    }
    $timeToExpire = ($global:tokenExpirationTime - (Get-Date)).TotalMinutes
    return ($timeToExpire -lt $global:RefreshIntervalInMinutes)
}

Function RenewTokenIfNeeded
{
    if (ShouldRenewToken) {
        Write-Host ""
        Write-Host "Refreshing Graph access token..." -ForegroundColor Yellow
        RequestAccessToken
        Write-Host "Token refreshed successfully." -ForegroundColor Green
    }
}

Function Connect-EntraID
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$ClientSecret,

        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [int]$RefreshInterval = 15
    )

    # Store globals for renewal
    $global:ClientId = $ClientId
    $global:ClientSecretSecure = $ClientSecret
    $global:TenantId = $TenantId
    $global:RefreshIntervalInMinutes = $RefreshInterval

    $global:accessToken = $null
    $global:tokenExpirationTime = $null

    RequestAccessToken
    return $global:accessToken
}

# ─────────────────────────────────────────────────────────────────────────────
# Existing Helper Functions (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

Function Write-CenteredText
{
    param([string]$Text, [int]$Width = 80, [string]$Color = "White")
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-Banner
{
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Entra ID Application Proxy Scanner v2.4" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-Section
{
    param([string]$Title, [hashtable]$Data)
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($key in $Data.Keys) {
        $value = $Data[$key]
        if ([string]::IsNullOrWhiteSpace($value)) { $value = "None"; $valueColor = "DarkGray" }
        else { $valueColor = "White" }
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valueColor
    }
}

Function Write-StageHeader
{
    param([int]$StageNumber, [string]$StageTitle, [string]$Description)
    Write-Host ""
    Write-Host ("─" * 80) -ForegroundColor DarkGray
    Write-Host "  STAGE $($StageNumber): " -NoNewline -ForegroundColor Cyan
    Write-Host $StageTitle -ForegroundColor White
    if ($Description) {
        Write-Host "  $Description" -ForegroundColor Gray
    }
    Write-Host ""
}

Function Write-ProgressBar
{
    param([int]$Current, [int]$Total, [string]$CurrentItem, [int]$BarWidth = 40)
    $percentage = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
    $completed = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $remaining = $BarWidth - $completed
    $bar = ("█" * $completed) + ("░" * $remaining)
    Write-Host "`r" -NoNewline
    Write-Host ("  Progress: ") -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White
    if ($CurrentItem) {
        $maxLength = 30
        $displayItem = if ($CurrentItem.Length -gt $maxLength) { $CurrentItem.Substring(0, $maxLength - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Get-TenantDetails
{
    param ([string]$AccessToken)
    $tenantEndpoint = "https://graph.microsoft.com/beta/organization"
    $headers = @{ "Authorization" = "Bearer $AccessToken" }
    Try {
        $tenantResponse = Invoke-RestMethod -Uri $tenantEndpoint -Headers $headers -Method Get -ErrorAction Stop
        $tenantId = $tenantResponse.value.id
        $tenantName = $tenantResponse.value.displayName
        $primaryDomain = ($tenantResponse.value.verifiedDomains | Where-Object { $_.isDefault -eq $true }).name
        $createDate = $tenantResponse.value.createdDateTime
        $technicalNotificationMails = $tenantResponse.value.technicalNotificationMails
        $country = $tenantResponse.value.country
        $countryCode = $tenantResponse.value.countryLetterCode
        $tenantType = $tenantResponse.value.tenantType
        $verifiedDomainNames = $tenantResponse.value.verifiedDomains.name -join " ; "
        $verifiedDomainTypes = $tenantResponse.value.verifiedDomains.type -join " ; "
        return [PSCustomObject]@{
            TenantId            = $tenantId
            TenantName          = $tenantName
            TenantPrimaryDomain = $primaryDomain
            'Technical Contact' = $technicalNotificationMails
            'Created Date'      = $createDate
            Country             = $country
            CountryCode         = $countryCode
            TenantType          = $tenantType
            VerifiedDomainsName = $verifiedDomainNames
            VerifiedDomainsType = $verifiedDomainTypes
        }
    }
    Catch {
        Write-Error "Failed to retrieve tenant details. Details: $_"
        return $null
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Security Scoring Functions (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

Function Calculate-SecurityScore-2026
{
    param([array]$ProxyApps)
    if (-not $ProxyApps -or @($ProxyApps).Count -eq 0) {
        return @{
            Score = 0
            Excellent = 0
            Good = 0
            NeedsAttention = 0
            Critical = 0
            TotalApps = 0
            CategoryScores = @{}
            ValidationWarnings = @()
            DetailedFindings = @{
                InvalidApps = @()
                PassthroughAuth = @()
                NoCertValidation = @()
                ImplicitGrantEnabled = @()
                NoZTNA = @()
                NoSecureCookie = @()
                NoHttpOnlyCookie = @()
            }
        }
    }
    $excellent = 0; $good = 0; $needsAttention = 0; $critical = 0
    $validationWarnings = @()
    $detailedFindings = @{
        InvalidApps = @()
        PassthroughAuth = @()
        NoCertValidation = @()
        ImplicitGrantEnabled = @()
        NoZTNA = @()
        NoSecureCookie = @()
        NoHttpOnlyCookie = @()
    }
    $categoryTotals = @{
        'Backend Cert Validation' = 0
        'Azure AD Pre-Auth' = 0
        'Secure Cookie' = 0
        'HTTP-Only Cookie' = 0
        'ZTNA Compliance' = 0
        'Session Management' = 0
        'OAuth Flow Security' = 0
    }
    foreach ($app in $ProxyApps) {
        $score = 0
        $appName = $app.DisplayName
        if ($app.'isOnPremPublishingEnabled' -ne $true) {
            $validationWarnings += "⚠️ $appName - App Proxy not enabled"
            $detailedFindings.InvalidApps += $appName
            $critical++
            continue
        }
        if ($app.'isBackendCertificateValidationEnabled' -eq $true) {
            $score += 25
            $categoryTotals.'Backend Cert Validation' += 25
        } else {
            $detailedFindings.NoCertValidation += $appName
        }
        if ($app.'externalAuthenticationType' -eq 'aadPreAuthentication') {
            $score += 25
            $categoryTotals.'Azure AD Pre-Auth' += 25
        } else {
            $detailedFindings.PassthroughAuth += $appName
        }
        if ($app.'isSecureCookieEnabled' -eq $true) {
            $score += 15
            $categoryTotals.'Secure Cookie' += 15
        } else {
            $detailedFindings.NoSecureCookie += $appName
        }
        if ($app.'isHttpOnlyCookieEnabled' -eq $true) {
            $score += 15
            $categoryTotals.'HTTP-Only Cookie' += 15
        } else {
            $detailedFindings.NoHttpOnlyCookie += $appName
        }
        if ($app.'isAccessibleViaZTNAClient' -eq $true) {
            $score += 10
            $categoryTotals.'ZTNA Compliance' += 10
        } else {
            $detailedFindings.NoZTNA += $appName
        }
        if ($app.'isStateSessionEnabled' -eq $true) {
            $score += 5
            $categoryTotals.'Session Management' += 5
        }
        $implicitTokenEnabled = $app.'implicitGrantSettings-enableIdTokenIssuance' -eq $true
        $implicitAccessEnabled = $app.'implicitGrantSettings-enableAccessTokenIssuance' -eq $true
        if (-not $implicitTokenEnabled -and -not $implicitAccessEnabled) {
            $score += 5
            $categoryTotals.'OAuth Flow Security' += 5
        } else {
            $detailedFindings.ImplicitGrantEnabled += $appName
        }
        if ($score -ge 90) { $excellent++ }
        elseif ($score -ge 70) { $good++ }
        elseif ($score -ge 50) { $needsAttention++ }
        else { $critical++ }
    }
    $totalApps = $excellent + $good + $needsAttention + $critical
    if ($totalApps -gt 0) {
        $overallScore = [math]::Round((
            ($excellent * 100) +
            ($good * 80) +
            ($needsAttention * 60) +
            ($critical * 30)
        ) / $totalApps)
    } else {
        $overallScore = 0
    }
    $categoryAverages = @{}
    $categoryMaxScores = @{
        'Backend Cert Validation' = 25
        'Azure AD Pre-Auth' = 25
        'Secure Cookie' = 15
        'HTTP-Only Cookie' = 15
        'ZTNA Compliance' = 10
        'Session Management' = 5
        'OAuth Flow Security' = 5
    }
    foreach ($category in $categoryTotals.Keys) {
        if ($totalApps -gt 0) {
            $avgScore = $categoryTotals[$category] / $totalApps
            $maxScore = $categoryMaxScores[$category]
            $percentage = [math]::Round(($avgScore / $maxScore) * 100, 1)
            $categoryAverages[$category] = @{
                Average = [math]::Round($avgScore, 1)
                Max = $maxScore
                Percentage = $percentage
            }
        }
    }
    return @{
        Score = $overallScore
        Excellent = $excellent
        Good = $good
        NeedsAttention = $needsAttention
        Critical = $critical
        TotalApps = $totalApps
        CategoryScores = $categoryAverages
        ValidationWarnings = $validationWarnings
        DetailedFindings = $detailedFindings
    }
}


Function Show-SecurityInsights
{
    param([hashtable]$SecurityScore)
    if ($SecurityScore.TotalApps -eq 0) { return }
    Write-Host ""
    Write-Host "  Overall Security Score: " -NoNewline -ForegroundColor Gray
    $scoreColor = if ($SecurityScore.Score -ge 90) { "Green" }
                  elseif ($SecurityScore.Score -ge 70) { "Yellow" }
                  elseif ($SecurityScore.Score -ge 50) { "DarkYellow" }
                  else { "Red" }
    Write-Host "$($SecurityScore.Score)/100" -ForegroundColor $scoreColor
    $rating = if ($SecurityScore.Score -ge 90) { "Excellent - Fully Compliant" }
              elseif ($SecurityScore.Score -ge 70) { "Good - Minor Improvements" }
              elseif ($SecurityScore.Score -ge 50) { "Needs Attention - Security Gaps" }
              else { "Critical - Immediate Action Required" }
    Write-Host "  Rating: $rating" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Application Security Classification:" -ForegroundColor Cyan
    $totalApps = $SecurityScore.TotalApps
    Write-Host "    Excellent (90-100)     : " -NoNewline -ForegroundColor Gray
    Write-Host "$($SecurityScore.Excellent) apps " -NoNewline -ForegroundColor Green
    if ($totalApps -gt 0) {
        Write-Host "($([math]::Round(($SecurityScore.Excellent / $totalApps) * 100, 1))%)" -ForegroundColor DarkGray
    } else { Write-Host "" }
    Write-Host "    Good (70-89)           : " -NoNewline -ForegroundColor Gray
    Write-Host "$($SecurityScore.Good) apps " -NoNewline -ForegroundColor Yellow
    if ($totalApps -gt 0) {
        Write-Host "($([math]::Round(($SecurityScore.Good / $totalApps) * 100, 1))%)" -ForegroundColor DarkGray
    } else { Write-Host "" }
    Write-Host "    Needs Attention (50-69): " -NoNewline -ForegroundColor Gray
    Write-Host "$($SecurityScore.NeedsAttention) apps " -NoNewline -ForegroundColor DarkYellow
    if ($totalApps -gt 0) {
        Write-Host "($([math]::Round(($SecurityScore.NeedsAttention / $totalApps) * 100, 1))%)" -ForegroundColor DarkGray
    } else { Write-Host "" }
    Write-Host "    Critical Risk (<50)    : " -NoNewline -ForegroundColor Gray
    Write-Host "$($SecurityScore.Critical) apps " -NoNewline -ForegroundColor Red
    if ($totalApps -gt 0) {
        Write-Host "($([math]::Round(($SecurityScore.Critical / $totalApps) * 100, 1))%)" -ForegroundColor DarkGray
    } else { Write-Host "" }
    Write-Host ""
    $findings = $SecurityScore.DetailedFindings
    $issues = @()
    if ($findings.PassthroughAuth.Count -gt 0) {
        $issues += [PSCustomObject]@{
            Priority = "CRITICAL"
            Issue = "Passthrough Authentication"
            Count = $findings.PassthroughAuth.Count
            Impact = "-25 pts/app"
        }
    }
    if ($findings.NoCertValidation.Count -gt 0) {
        $issues += [PSCustomObject]@{
            Priority = "CRITICAL"
            Issue = "No Certificate Validation"
            Count = $findings.NoCertValidation.Count
            Impact = "-25 pts/app"
        }
    }
    if ($findings.NoZTNA.Count -gt 0) {
        $issues += [PSCustomObject]@{
            Priority = "MEDIUM"
            Issue = "No Zero Trust Access"
            Count = $findings.NoZTNA.Count
            Impact = "-10 pts/app"
        }
    }
    if ($issues.Count -gt 0) {
        Write-Host "  Top Security Issues:" -ForegroundColor Cyan
        $topIssues = $issues | Sort-Object Count -Descending | Select-Object -First 3
        foreach ($issue in $topIssues) {
            $color = if ($issue.Priority -eq "CRITICAL") { "Red" } else { "Yellow" }
            Write-Host "    • " -NoNewline -ForegroundColor Gray
            Write-Host "$($issue.Issue): " -NoNewline -ForegroundColor $color
            Write-Host "$($issue.Count) apps " -NoNewline -ForegroundColor White
            Write-Host "($($issue.Impact))" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}


Function Generate-HtmlReport
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanSummary,
        [array]$ProxyApps,
        [hashtable]$SecurityScore,
        [string]$CsvPath,
        [string]$JsonPath,
        [string]$HtmlPath
    )
    $timestamp = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"
    $score = $SecurityScore.Score
    $excellent = $SecurityScore.Excellent
    $good = $SecurityScore.Good
    $needsAttention = $SecurityScore.NeedsAttention
    $critical = $SecurityScore.Critical

    # ---- Compute additional KPIs ----
    $totalProxy = @($ProxyApps).Count
    $secureCookieCount = @($ProxyApps | Where-Object { $_.'isSecureCookieEnabled' -eq $true }).Count
    $httpOnlyCount = @($ProxyApps | Where-Object { $_.'isHttpOnlyCookieEnabled' -eq $true }).Count
    $certValidationCount = @($ProxyApps | Where-Object { $_.'isBackendCertificateValidationEnabled' -eq $true }).Count
    $preAuthCount = @($ProxyApps | Where-Object { $_.'externalAuthenticationType' -eq 'aadPreAuthentication' }).Count
    $ztnaCount = @($ProxyApps | Where-Object { $_.'isAccessibleViaZTNAClient' -eq $true }).Count

    # Helper function to get percentage and status text
    function Get-PercentageStatus {
        param($count, $total)
        if ($total -eq 0) { return @{Pct=0; Status="N/A"; Color="var(--text-secondary)"} }
        $pct = [math]::Round(($count / $total) * 100)
        if ($pct -ge 80) { $status = "✅ Good"; $color = "var(--success)" }
        elseif ($pct -ge 50) { $status = "⚠️ Needs Improvement"; $color = "var(--warning)" }
        else { $status = "❌ Poor"; $color = "var(--danger)" }
        return @{Pct=$pct; Status=$status; Color=$color}
    }
    $sC = Get-PercentageStatus $secureCookieCount $totalProxy
    $hC = Get-PercentageStatus $httpOnlyCount $totalProxy
    $vC = Get-PercentageStatus $certValidationCount $totalProxy
    $pA = Get-PercentageStatus $preAuthCount $totalProxy
    $zN = Get-PercentageStatus $ztnaCount $totalProxy

    # Sample apps (top 10)
    $sampleAppsHtml = ""
    $sampleCount = [math]::Min(10, @($ProxyApps).Count)
    for ($i = 0; $i -lt $sampleCount; $i++) {
        $app = $ProxyApps[$i]
        $sampleAppsHtml += "<tr><td><span class='badge proxy'>PROXY</span></td><td class='app-name'>$($app.DisplayName)</td><td class='app-url'>$($app.externalUrl)</td><td class='app-url'>$($app.internalUrl)</td></tr>"
    }

    # Category scores (progress bars)
    $categoryHtml = ""
    if ($SecurityScore.CategoryScores.Count -gt 0) {
        foreach ($category in $SecurityScore.CategoryScores.Keys | Sort-Object { $SecurityScore.CategoryScores[$_].Max } -Descending) {
            $catData = $SecurityScore.CategoryScores[$category]
            $percentage = $catData.Percentage
            $categoryHtml += @"
            <div class="progress-item">
                <div class="progress-label">
                    <span>$category</span>
                    <span>$percentage%</span>
                </div>
                <div class="progress-track">
                    <div class="progress-fill" style="width:$percentage%;"></div>
                </div>
            </div>
"@
        }
    }

    # Recommendations
    $recommendationsHtml = ""
    $findings = $SecurityScore.DetailedFindings
	if ($null -eq $findings) { $findings = @{ PassthroughAuth=@(); NoCertValidation=@(); ImplicitGrantEnabled=@(); NoZTNA=@() } }
    if ($findings.PassthroughAuth.Count -gt 0) {
        $recommendationsHtml += @"
        <div class="recommendation critical">
            <div class="rec-icon">🔴</div>
            <div class="rec-content">
                <div class="rec-title">Enable Azure AD Pre‑Authentication</div>
                <div class="rec-desc">$($findings.PassthroughAuth.Count) applications use passthrough authentication — this bypasses critical security checks. Enable Azure AD pre‑authentication to enforce conditional access policies.</div>
            </div>
        </div>
"@
    }
    if ($findings.NoCertValidation.Count -gt 0) {
        $recommendationsHtml += @"
        <div class="recommendation critical">
            <div class="rec-icon">🔴</div>
            <div class="rec-content">
                <div class="rec-title">Enable Backend Certificate Validation</div>
                <div class="rec-desc">$($findings.NoCertValidation.Count) applications have disabled certificate validation — at risk of Man‑in‑the‑Middle attacks. Enable validation to secure backend communication.</div>
            </div>
        </div>
"@
    }
    if ($findings.ImplicitGrantEnabled.Count -gt 0) {
        $recommendationsHtml += @"
        <div class="recommendation warning">
            <div class="rec-icon">⚠️</div>
            <div class="rec-content">
                <div class="rec-title">Migrate from Implicit Grant Flow</div>
                <div class="rec-desc">$($findings.ImplicitGrantEnabled.Count) applications still use the legacy implicit grant. Switch to Authorization Code + PKCE for more secure OAuth flows.</div>
            </div>
        </div>
"@
    }
    if ($findings.NoZTNA.Count -gt 0) {
        $recommendationsHtml += @"
        <div class="recommendation warning">
            <div class="rec-icon">⚠️</div>
            <div class="rec-content">
                <div class="rec-title">Enable Zero Trust Network Access</div>
                <div class="rec-desc">$($findings.NoZTNA.Count) applications are not ZTNA‑compliant. Enable `isAccessibleViaZTNAClient` to align with Zero Trust principles.</div>
            </div>
        </div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Entra ID Application Proxy Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap" rel="stylesheet">
    <style>
        /* -------- CSS Variables (Dark default) -------- */
        :root {
            --bg: #0d1117;
            --surface: #161b22;
            --surface2: #1c2333;
            --surface3: #243048;
            --border: #30363d;
            --primary: #2f81f7;
            --primary-light: #58a6ff;
            --success: #3fb950;
            --warning: #d29922;
            --danger: #f85149;
            --text: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #484f58;
            --radius: 12px;
            --shadow: 0 8px 24px rgba(0,0,0,0.6);
            --transition: 0.3s ease;
        }
        /* -------- Light Theme -------- */
        body.light-theme {
            --bg: #f6f8fa;
            --surface: #ffffff;
            --surface2: #f0f3f6;
            --surface3: #e4e9ef;
            --border: #d0d7de;
            --text: #1f2328;
            --text-secondary: #636c76;
            --text-muted: #8b949e;
            --shadow: 0 8px 24px rgba(0,0,0,0.12);
        }
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background: var(--bg);
            color: var(--text);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            font-size: 15px;
            line-height: 1.6;
            padding: 24px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background var(--transition), color var(--transition);
        }
        .container {
            max-width: 1300px;
            width: 100%;
            background: var(--surface);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
            overflow: hidden;
            transition: background var(--transition), border-color var(--transition);
        }
        /* -------- Header -------- */
        .header {
            background: linear-gradient(145deg, var(--surface), var(--surface2));
            padding: 24px 48px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            transition: background var(--transition);
        }
        .header-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .header-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--primary), #1f6feb);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: white;
            flex-shrink: 0;
        }
        .header h1 {
            font-size: 28px;
            font-weight: 600;
            letter-spacing: -0.4px;
            color: var(--text);
        }
        .header h1 span {
            color: var(--primary-light);
        }
        .header .sub {
            font-size: 14px;
            color: var(--text-secondary);
            margin-top: 2px;
        }
        .header-actions {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }
        .header .timestamp {
            font-size: 13px;
            color: var(--text-secondary);
            background: var(--surface2);
            padding: 6px 14px;
            border-radius: 20px;
            border: 1px solid var(--border);
            white-space: nowrap;
            transition: background var(--transition), border-color var(--transition);
        }
        .theme-toggle {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: 30px;
            padding: 6px 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            color: var(--text-secondary);
            transition: all var(--transition);
            font-family: 'Inter', sans-serif;
        }
        .theme-toggle:hover {
            border-color: var(--primary);
            color: var(--text);
        }
        .theme-toggle .icon { font-size: 18px; }
        /* -------- Content -------- */
        .content {
            padding: 40px 48px;
        }
        .section {
            margin-bottom: 48px;
        }
        .section-title {
            font-size: 20px;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            letter-spacing: -0.2px;
        }
        .section-title .icon {
            font-size: 22px;
        }
        .section-title::after {
            content: '';
            flex: 1;
            height: 1px;
            background: var(--border);
            margin-left: 16px;
        }

        /* Cards */
        .grid-4 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
        }
        .grid-5 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
        }
        .grid-3 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
        }
        .stat-card {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px 16px;
            text-align: center;
            transition: transform 0.2s, border-color 0.2s, background var(--transition);
        }
        .stat-card:hover {
            transform: translateY(-3px);
            border-color: var(--primary);
        }
        .stat-card .number {
            font-size: 32px;
            font-weight: 700;
            color: var(--primary-light);
            line-height: 1.2;
        }
        .stat-card .label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-secondary);
            margin-top: 6px;
        }
        .stat-card .icon-big {
            font-size: 28px;
            margin-bottom: 6px;
            display: block;
        }
        .stat-card .sub-status {
            font-size: 13px;
            margin-top: 6px;
            font-weight: 500;
        }

        /* Security Score */
        .score-wrap {
            display: flex;
            align-items: center;
            gap: 32px;
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px 32px;
            flex-wrap: wrap;
            transition: background var(--transition), border-color var(--transition);
        }
        .score-ring {
            position: relative;
            width: 120px;
            height: 120px;
            flex-shrink: 0;
        }
        .score-ring svg {
            width: 120px;
            height: 120px;
            transform: rotate(-90deg);
        }
        .score-ring .bg {
            fill: none;
            stroke: var(--border);
            stroke-width: 10;
        }
        .score-ring .progress {
            fill: none;
            stroke: var(--primary);
            stroke-width: 10;
            stroke-linecap: round;
            stroke-dasharray: 314.16;
            stroke-dashoffset: 314.16;
            transition: stroke-dashoffset 1s ease;
        }
        .score-ring .center {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }
        .score-ring .center .num {
            font-size: 36px;
            font-weight: 700;
            color: var(--text);
            line-height: 1;
        }
        .score-ring .center .label {
            font-size: 12px;
            color: var(--text-secondary);
        }
        .score-meta {
            flex: 1;
        }
        .score-meta .rating {
            font-size: 22px;
            font-weight: 600;
            color: var(--text);
        }
        .score-meta .desc {
            color: var(--text-secondary);
            font-size: 14px;
            margin-top: 4px;
        }
        .score-meta .sub-metrics {
            display: flex;
            gap: 24px;
            margin-top: 12px;
            flex-wrap: wrap;
        }
        .score-meta .sub-metrics span {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 14px;
            color: var(--text-secondary);
        }
        .dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 4px;
        }
        .dot.green { background: var(--success); }
        .dot.yellow { background: var(--warning); }
        .dot.red { background: var(--danger); }

        /* Category progress */
        .progress-item {
            margin-bottom: 14px;
        }
        .progress-label {
            display: flex;
            justify-content: space-between;
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: 4px;
        }
        .progress-track {
            height: 8px;
            background: var(--border);
            border-radius: 6px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), #1f6feb);
            border-radius: 6px;
            width: 0%;
            transition: width 0.8s ease;
        }

        /* Recommendations */
        .rec-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .recommendation {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 16px 20px;
            display: flex;
            align-items: flex-start;
            gap: 14px;
            border-left: 4px solid var(--border);
            transition: border-color 0.2s, background var(--transition);
        }
        .recommendation.critical { border-left-color: var(--danger); }
        .recommendation.warning { border-left-color: var(--warning); }
        .rec-icon { font-size: 22px; flex-shrink: 0; line-height: 1.4; }
        .rec-content { flex: 1; }
        .rec-title { font-weight: 600; color: var(--text); font-size: 15px; }
        .rec-desc { font-size: 14px; color: var(--text-secondary); margin-top: 4px; }

        /* App table */
        .table-wrap {
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow: auto;
            max-height: 400px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }
        table th {
            text-align: left;
            padding: 12px 16px;
            background: var(--surface2);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 2;
            background: var(--surface);
        }
        table td {
            padding: 10px 16px;
            border-bottom: 1px solid var(--border);
            color: var(--text);
        }
        table tbody tr:hover {
            background: var(--surface2);
        }
        .badge {
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            display: inline-block;
        }
        .badge.proxy {
            background: #2ea04344;
            color: var(--success);
        }
        .app-name {
            font-weight: 500;
            color: var(--text);
        }
        .app-url {
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            word-break: break-all;
            max-width: 200px;
        }

        /* Output files */
        .output-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .output-item {
            display: flex;
            align-items: center;
            gap: 12px;
            background: var(--surface2);
            padding: 12px 18px;
            border-radius: var(--radius);
            border: 1px solid var(--border);
            transition: background var(--transition), border-color var(--transition);
        }
        .output-item .icon {
            font-size: 20px;
            flex-shrink: 0;
        }
        .output-item .label {
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.04em;
            min-width: 80px;
        }
        .output-item .path {
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: var(--text);
            word-break: break-all;
        }

        /* Footer */
        .footer {
            background: var(--surface);
            border-top: 1px solid var(--border);
            padding: 16px 48px;
            text-align: center;
            font-size: 13px;
            color: var(--text-secondary);
            transition: background var(--transition), border-color var(--transition);
        }
        .footer strong {
            color: var(--primary-light);
        }

        /* Responsive */
        @media (max-width: 768px) {
            .header { flex-direction: column; align-items: flex-start; padding: 24px; }
            .header-actions { width: 100%; justify-content: flex-start; }
            .content { padding: 24px; }
            .score-wrap { flex-direction: column; align-items: center; text-align: center; }
            .score-meta .sub-metrics { justify-content: center; }
            .grid-4, .grid-5, .grid-3 { grid-template-columns: 1fr 1fr; }
        }
        @media (max-width: 480px) {
            .grid-4, .grid-5, .grid-3 { grid-template-columns: 1fr; }
            .header h1 { font-size: 22px; }
        }
        /* Print */
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; border: 1px solid #ddd; }
            .stat-card:hover { transform: none; }
            .table-wrap { max-height: none; }
            .theme-toggle { display: none; }
        }
    </style>
</head>
<body>
<div class="container">
    <!-- Header -->
    <div class="header">
        <div class="header-left">
            <div class="header-icon">🔐</div>
            <div>
                <h1>Entra ID <span>App Proxy</span> Report</h1>
                <div class="sub">2026 Zero Trust Security Analysis</div>
            </div>
        </div>
        <div class="header-actions">
            <div class="timestamp">📅 $timestamp</div>
            <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()">
                <span class="icon" id="themeIcon">🌙</span>
                <span id="themeLabel">Dark</span>
            </button>
        </div>
    </div>

    <!-- Content -->
    <div class="content">
        <!-- Session Info -->
        <div class="section">
            <div class="section-title"><span class="icon">📋</span> Session</div>
            <div class="grid-3">
                <div class="stat-card"><div class="icon-big">🏢</div><div class="number" style="font-size:18px;">$($SessionInfo.Tenant)</div><div class="label">Tenant</div></div>
                <div class="stat-card"><div class="icon-big">📅</div><div class="number" style="font-size:18px;">$($SessionInfo.ScanDate)</div><div class="label">Scan Date</div></div>
                <div class="stat-card"><div class="icon-big">📤</div><div class="number" style="font-size:18px;">$($SessionInfo.ExportFormat)</div><div class="label">Export Format</div></div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <div class="section-title"><span class="icon">📊</span> Executive Summary</div>
            <div class="grid-4">
                <div class="stat-card"><div class="icon-big">📄</div><div class="number">$($ScanSummary.TotalApps)</div><div class="label">Total Apps</div></div>
                <div class="stat-card"><div class="icon-big">✅</div><div class="number">$($ScanSummary.ProxyApps)</div><div class="label">Proxy Enabled</div></div>
                <div class="stat-card"><div class="icon-big">🚫</div><div class="number">$($ScanSummary.NonProxyApps)</div><div class="label">No Proxy</div></div>
                <div class="stat-card"><div class="icon-big">📈</div><div class="number">$($ScanSummary.ProxyPercentage)%</div><div class="label">Adoption</div></div>
                <div class="stat-card"><div class="icon-big">⏱️</div><div class="number">$($ScanSummary.ExecutionTime)</div><div class="label">Execution Time</div></div>
            </div>
        </div>

        <!-- Security Score -->
        <div class="section">
            <div class="section-title"><span class="icon">🛡️</span> Security Score</div>
            <div class="score-wrap">
                <div class="score-ring">
                    <svg viewBox="0 0 120 120">
                        <circle class="bg" cx="60" cy="60" r="50" />
                        <circle class="progress" id="scoreCircle" cx="60" cy="60" r="50" />
                    </svg>
                    <div class="center">
                        <div class="num">$score</div>
                        <div class="label">/ 100</div>
                    </div>
                </div>
                <div class="score-meta">
                    <div class="rating">
                        $(
                            if ($score -ge 90) { "✅ Excellent" }
                            elseif ($score -ge 70) { "👍 Good" }
                            elseif ($score -ge 50) { "⚠️ Needs Attention" }
                            else { "❌ Critical Risk" }
                        )
                    </div>
                    <div class="desc">Overall security posture based on 7‑factor Zero Trust model</div>
                    <div class="sub-metrics">
                        <span><span class="dot green"></span> Excellent: $excellent</span>
                        <span><span class="dot yellow"></span> Good: $good</span>
                        <span><span class="dot red"></span> Needs Attention: $needsAttention</span>
                        <span style="color:var(--danger);">Critical: $critical</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Security Highlights (new KPI section) -->
        <div class="section">
            <div class="section-title"><span class="icon">✨</span> Security Highlights</div>
            <div class="grid-5">
                <div class="stat-card">
                    <div class="icon-big">🔒</div>
                    <div class="number">$secureCookieCount / $totalProxy</div>
                    <div class="label">Secure Cookies</div>
                    <div class="sub-status" style="color:$($sC.Color);">$($sC.Status)</div>
                </div>
                <div class="stat-card">
                    <div class="icon-big">🍪</div>
                    <div class="number">$httpOnlyCount / $totalProxy</div>
                    <div class="label">HTTP‑Only Cookies</div>
                    <div class="sub-status" style="color:$($hC.Color);">$($hC.Status)</div>
                </div>
                <div class="stat-card">
                    <div class="icon-big">🔐</div>
                    <div class="number">$certValidationCount / $totalProxy</div>
                    <div class="label">Cert Validation</div>
                    <div class="sub-status" style="color:$($vC.Color);">$($vC.Status)</div>
                </div>
                <div class="stat-card">
                    <div class="icon-big">🛡️</div>
                    <div class="number">$preAuthCount / $totalProxy</div>
                    <div class="label">Pre‑Auth Enabled</div>
                    <div class="sub-status" style="color:$($pA.Color);">$($pA.Status)</div>
                </div>
                <div class="stat-card">
                    <div class="icon-big">🌐</div>
                    <div class="number">$ztnaCount / $totalProxy</div>
                    <div class="label">ZTNA Compliant</div>
                    <div class="sub-status" style="color:$($zN.Color);">$($zN.Status)</div>
                </div>
            </div>
        </div>

        <!-- Category Scores -->
        <div class="section">
            <div class="section-title"><span class="icon">📈</span> Category Scores</div>
            $categoryHtml
        </div>

        <!-- Recommendations -->
        $(if($recommendationsHtml){"<div class='section'><div class='section-title'><span class='icon'>💡</span> Recommendations</div><div class='rec-list'>$recommendationsHtml</div></div>"})

        <!-- Applications -->
        <div class="section">
            <div class="section-title"><span class="icon">📱</span> Top 10 Proxy Apps</div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Status</th><th>Name</th><th>External URL</th><th>Internal URL</th></tr></thead>
                    <tbody>
                        $sampleAppsHtml
                        $(if (@($ProxyApps).Count -gt 10) {"<tr><td colspan='4' style='text-align:center;color:var(--text-secondary);font-style:italic;'>… and $(@($ProxyApps).Count - 10) more</td></tr>"})
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Output Files -->
        <div class="section">
            <div class="section-title"><span class="icon">📁</span> Output Files</div>
            <div class="output-list">
                $(if($CsvPath){"<div class='output-item'><span class='icon'>📄</span><span class='label'>CSV</span><span class='path'>$CsvPath</span></div>"})
                $(if($JsonPath){"<div class='output-item'><span class='icon'>📄</span><span class='label'>JSON</span><span class='path'>$JsonPath</span></div>"})
                <div class='output-item'><span class='icon'>🌐</span><span class='label'>HTML</span><span class='path'>$HtmlPath</span></div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        <strong>Entra ID Application Proxy Scanner v2.4</strong> &bull; 2026 Zero Trust Standards &bull; Microsoft Azure &bull; PowerShell
    </div>
</div>

<script>
    // ---- Theme Toggle ----
    function toggleTheme() {
        const body = document.body;
        const isLight = body.classList.toggle('light-theme');
        const icon = document.getElementById('themeIcon');
        const label = document.getElementById('themeLabel');
        if (isLight) {
            icon.textContent = '☀️';
            label.textContent = 'Light';
        } else {
            icon.textContent = '🌙';
            label.textContent = 'Dark';
        }
        try { localStorage.setItem('ps-proxy-theme', isLight ? 'light' : 'dark'); } catch(e) {}
    }

    // Restore saved theme
    (function() {
        try {
            const saved = localStorage.getItem('ps-proxy-theme');
            if (saved === 'light') {
                document.body.classList.add('light-theme');
                document.getElementById('themeIcon').textContent = '☀️';
                document.getElementById('themeLabel').textContent = 'Light';
            }
        } catch(e) {}
    })();

    // ---- Animate score ring ----
    (function() {
        const circle = document.getElementById('scoreCircle');
        const score = $score;
        const circumference = 2 * Math.PI * 50;
        const offset = circumference - (score / 100) * circumference;
        setTimeout(() => {
            circle.style.strokeDashoffset = offset;
        }, 200);
        // Set color based on score
        if (score >= 70) {
            circle.style.stroke = '#3fb950';
        } else if (score >= 50) {
            circle.style.stroke = '#d29922';
        } else {
            circle.style.stroke = '#f85149';
        }
    })();

    // ---- Animate progress bars ----
    document.querySelectorAll('.progress-fill').forEach(el => {
        const width = el.style.width;
        el.style.width = '0%';
        setTimeout(() => {
            el.style.width = width;
        }, 300);
    });
</script>
</body>
</html>
"@
    return $html
}

# ─────────────────────────────────────────────────────────────────────────────
# Main Function (with added authentication)
# ─────────────────────────────────────────────────────────────────────────────

Function Get-AppProxyApplications
{
    [CmdletBinding(DefaultParameterSetName = 'DirectToken')]
    param(
        # Direct Token
        [Parameter(Mandatory = $true, ParameterSetName = 'DirectToken')]
        [string]$AccessToken,

        # Client Credentials
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredentials')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredentials')]
        [System.Security.SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredentials')]
        [string]$TenantId,

        # Common parameters
        [ValidateSet('None','CSV','JSON','Both',IgnoreCase=$true)]
        [string]$exportFormat = 'None',

        [string]$exportPath = '',

        [switch]$DisableParallel,

        [int]$ThrottleLimit = 10,

        # Help
        [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
        [switch]$ShowHelp
    )

    # If ShowHelp, display friendly guide and exit
    if ($ShowHelp) {
        Show-FriendlyHelp
        return
    }

    # ─── Authentication ────────────────────────────────────────────────
    $effectiveToken = $null
    $usingClientCredentials = $false
    if ($PSCmdlet.ParameterSetName -eq 'ClientCredentials') {
        Write-Host "  ⏳ Requesting access token via client credentials..." -ForegroundColor Yellow
        $effectiveToken = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId
        if (-not $effectiveToken) {
            Write-Error "Failed to obtain access token. Please check your credentials."
            return
        }
        Write-Host "  ✅ Authentication successful" -ForegroundColor Green
        $usingClientCredentials = $true
    } else {
        $effectiveToken = $AccessToken
    }

    # ─── Start scan (original logic, with token renewal added in loops) ───
    $startTime = Get-Date
    $currentDateTime = Get-Date -Format "yyyyMMdd-HHmmss"
    Write-Banner

    if ($exportFormat -ne 'None' -and -not $exportPath) {
        $exportPath = "C:\Temp\AppProxyConfigs_$currentDateTime"
    }

    $tenantInfo = Get-TenantDetails -AccessToken $effectiveToken
    $sessionInfo = @{
        Tenant = "$($tenantInfo.TenantName) ($($tenantInfo.TenantId))"
        ScanDate = Get-Date -Format "MMM dd, yyyy"
        ExportFormat = $exportFormat
    }

    if ($ThrottleLimit -gt 10 -and -not $DisableParallel) {
        Write-Host ""
        Write-Host "  ⚠ WARNING: ThrottleLimit > 10 may cause API throttling and missing results!" -ForegroundColor Yellow
        Write-Host "  Recommended: Use ThrottleLimit 5-10 for reliable results" -ForegroundColor Yellow
        Write-Host "  For critical audits: Use -DisableParallel for 100% accuracy" -ForegroundColor Yellow
        Write-Host ""
        Start-Sleep -Seconds 2
    }

    Write-Section -Title "Configuration" -Data @{
        "Export Format"   = $exportFormat
        "Export Path"     = if ($exportPath) { $exportPath } else { "Not specified" }
        "Parallel Mode"   = if (-not $DisableParallel) { "Enabled ($ThrottleLimit threads)" } else { "Disabled" }
        "PowerShell Ver"  = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
        "Auth Method"     = if ($usingClientCredentials) { "Client Credentials" } else { "Direct Token" }
    }

    # ─── STAGE 1: Discover All Applications ──────────────────────────
    Write-StageHeader -StageNumber 1 -StageTitle "Discovering Applications" -Description "Fetching all applications from Entra ID using Microsoft Graph API"

    $allApps = New-Object System.Collections.ArrayList
    $uri = "https://graph.microsoft.com/beta/applications?`$top=800&`$select=id,appId,displayName&`$count=true"
    $headers = @{ "Authorization" = "Bearer $effectiveToken"; "ConsistencyLevel" = "eventual" }

    Write-Host "  " -NoNewline
    Write-Host "⟳ " -NoNewline -ForegroundColor Cyan
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Gray

    Write-ProgressBar -Current 0 -Total 100 -CurrentItem "Initializing..."

    do {
        # Renew token if using client credentials and sequential (do it here before each page)
        if ($usingClientCredentials) {
            RenewTokenIfNeeded
            $effectiveToken = $global:accessToken
            $headers["Authorization"] = "Bearer $effectiveToken"
        }

        try {
            $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            $AppsData = $partialData.Content | ConvertFrom-Json

            foreach ($app in $AppsData.value) {
                $null = $allApps.Add($app)
            }

            if ($AppsData.PSObject.Properties.Name -contains "@odata.nextLink") {
                $uri = $AppsData.'@odata.nextLink'
            } else {
                $uri = $null
            }
        }
        catch {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 429) {
                $sleepTime = $_.Exception.Response.Headers["Retry-After"]
                Write-Host "`r  ⚠ API throttling detected. Waiting $sleepTime seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $sleepTime
            } else {
                Write-Host "`r  ✗ Error connecting to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
                return
            }
        }
    } while ($uri)

    Write-Host "`r" -NoNewline
    Write-Host (" " * 120) -NoNewline
    Write-Host "`r  " -NoNewline
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host "Successfully retrieved " -NoNewline -ForegroundColor Green
    Write-Host $allApps.Count -NoNewline -ForegroundColor White
    Write-Host " applications from Entra ID" -ForegroundColor Green

    # ─── STAGE 2: Analyze App Proxy Configurations ──────────────────
    Write-StageHeader -StageNumber 2 -StageTitle "Analyzing Application Proxy Configurations" -Description "Checking each application for Application Proxy settings"

    $psVersion = $PSVersionTable.PSVersion.Major
    $useParallel = (-not $DisableParallel) -and ($allApps.Count -ge 50) -and ($psVersion -ge 7)

    if ($useParallel) {
        Write-Host "  " -NoNewline
        Write-Host "⚡ " -NoNewline -ForegroundColor Cyan
        Write-Host "Using parallel processing mode (" -NoNewline -ForegroundColor Gray
        Write-Host "$ThrottleLimit threads" -NoNewline -ForegroundColor White
        Write-Host ")" -ForegroundColor Gray
    } else {
        Write-Host "  " -NoNewline
        Write-Host "⟳ " -NoNewline -ForegroundColor Cyan
        if ($psVersion -lt 7) {
            Write-Host "Using sequential mode (PowerShell 7+ required for parallel)" -ForegroundColor Gray
        } else {
            Write-Host "Using sequential mode (parallel disabled or < 50 apps)" -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-ProgressBar -Current 0 -Total $allApps.Count -CurrentItem "Starting analysis..."

    $formattedApps = @()

    if ($useParallel) {
        # For parallel, we get a fresh token now (if using client credentials) and pass it
        if ($usingClientCredentials) {
            RenewTokenIfNeeded
            $effectiveToken = $global:accessToken
        }
        $results = $allApps | ForEach-Object -Parallel {
            $app = $_
            $token = $using:effectiveToken
            $headers = @{ "Authorization" = "Bearer $token" }
            try {
                $appDetail = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/applications/$($app.id)?`$select=id,appId,displayName,publisherDomain,signInAudience,web,onPremisesPublishing" -Headers $headers -Method Get
                if ($appDetail.onPremisesPublishing -ne $null) {
                    [PSCustomObject]@{
                        Success                                              = $true
                        'Object-Id'                                          = $appDetail.id
                        'ApplicationId'                                      = $appDetail.appId
                        'DisplayName'                                        = $appDetail.displayName
                        'publisherDomain'                                    = $appDetail.publisherDomain
                        'signInAudience'                                     = $appDetail.signInAudience
                        'redirectUris'                                       = $appDetail.web.redirectUris -join ", "
                        'homePageUrl'                                        = $appDetail.web.homePageUrl
                        'logoutUrl'                                          = $appDetail.web.logoutUrl
                        'externalUrl'                                        = $appDetail.onPremisesPublishing.externalUrl
                        'internalUrl'                                        = $appDetail.onPremisesPublishing.internalUrl
                        'alternateUrl'                                       = $appDetail.onPremisesPublishing.alternateUrl
                        'externalAuthenticationType'                         = $appDetail.onPremisesPublishing.externalAuthenticationType
                        'implicitGrantSettings-enableIdTokenIssuance'        = $appDetail.web.implicitGrantSettings.enableIdTokenIssuance
                        'implicitGrantSettings-enableAccessTokenIssuance'    = $appDetail.web.implicitGrantSettings.enableAccessTokenIssuance
                        'isOnPremPublishingEnabled'                          = $appDetail.onPremisesPublishing.isOnPremPublishingEnabled
                        'isTranslateHostHeaderEnabled'                       = $appDetail.onPremisesPublishing.isTranslateHostHeaderEnabled
                        'isTranslateLinksInBodyEnabled'                      = $appDetail.onPremisesPublishing.isTranslateLinksInBodyEnabled
                        'isHttpOnlyCookieEnabled'                            = $appDetail.onPremisesPublishing.isHttpOnlyCookieEnabled
                        'isSecureCookieEnabled'                              = $appDetail.onPremisesPublishing.isSecureCookieEnabled
                        'isPersistentCookieEnabled'                          = $appDetail.onPremisesPublishing.isPersistentCookieEnabled
                        'isBackendCertificateValidationEnabled'              = $appDetail.onPremisesPublishing.isBackendCertificateValidationEnabled
                        'applicationServerTimeout'                           = $appDetail.onPremisesPublishing.applicationServerTimeout
                        'applicationType'                                    = $appDetail.onPremisesPublishing.applicationType
                        'useAlternateUrlForTranslationAndRedirect'           = $appDetail.onPremisesPublishing.useAlternateUrlForTranslationAndRedirect
                        'isStateSessionEnabled'                              = $appDetail.onPremisesPublishing.isStateSessionEnabled
                        'isAccessibleViaZTNAClient'                          = $appDetail.onPremisesPublishing.isAccessibleViaZTNAClient
                        'isDnsResolutionEnabled'                             = $appDetail.onPremisesPublishing.isDnsResolutionEnabled
                        'verifiedCustomDomainCertificatesMetadata'           = $appDetail.onPremisesPublishing.verifiedCustomDomainCertificatesMetadata
                        'verifiedCustomDomainKeyCredential'                  = $appDetail.onPremisesPublishing.verifiedCustomDomainKeyCredential
                        'verifiedCustomDomainPasswordCredential'             = $appDetail.onPremisesPublishing.verifiedCustomDomainPasswordCredential
                        'segmentsConfiguration'                              = $appDetail.onPremisesPublishing.segmentsConfiguration
                        'singleSignOnSettings'                               = $appDetail.onPremisesPublishing.singleSignOnSettings | ConvertTo-Json -Compress
                        'onPremisesApplicationSegments'                      = $appDetail.onPremisesPublishing.onPremisesApplicationSegments
                    }
                }
            } catch { }
        } -ThrottleLimit $ThrottleLimit

        $processedCount = 0
        foreach ($result in $results) {
            $processedCount++
            if ($result.Success) {
                $formattedApps += $result
                if ($processedCount % 50 -eq 0 -or $processedCount -eq $allApps.Count) {
                    Write-ProgressBar -Current $processedCount -Total $allApps.Count -CurrentItem "Found: $($formattedApps.Count) proxy apps"
                }
            }
        }
    } else {
        # Sequential mode with token renewal
        $currentIndex = 0
        foreach ($app in $allApps) {
            $currentIndex++
            if ($currentIndex % 10 -eq 0 -or $currentIndex -eq $allApps.Count) {
                Write-ProgressBar -Current $currentIndex -Total $allApps.Count -CurrentItem $app.displayName
            }

            # Renew token if using client credentials
            if ($usingClientCredentials) {
                RenewTokenIfNeeded
                $effectiveToken = $global:accessToken
                $headers["Authorization"] = "Bearer $effectiveToken"
            }

            try {
                $appDetail = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/applications/$($app.id)?`$select=id,appId,displayName,publisherDomain,signInAudience,web,onPremisesPublishing" -Headers $headers -Method Get
                if ($appDetail.onPremisesPublishing -ne $null) {
                    $formattedApp = [PSCustomObject]@{
                        'Object-Id'                                          = $appDetail.id
                        'ApplicationId'                                      = $appDetail.appId
                        'DisplayName'                                        = $appDetail.displayName
                        'publisherDomain'                                    = $appDetail.publisherDomain
                        'signInAudience'                                     = $appDetail.signInAudience
                        'redirectUris'                                       = $appDetail.web.redirectUris -join ", "
                        'homePageUrl'                                        = $appDetail.web.homePageUrl
                        'logoutUrl'                                          = $appDetail.web.logoutUrl
                        'externalUrl'                                        = $appDetail.onPremisesPublishing.externalUrl
                        'internalUrl'                                        = $appDetail.onPremisesPublishing.internalUrl
                        'alternateUrl'                                       = $appDetail.onPremisesPublishing.alternateUrl
                        'externalAuthenticationType'                         = $appDetail.onPremisesPublishing.externalAuthenticationType
                        'implicitGrantSettings-enableIdTokenIssuance'        = $appDetail.web.implicitGrantSettings.enableIdTokenIssuance
                        'implicitGrantSettings-enableAccessTokenIssuance'    = $appDetail.web.implicitGrantSettings.enableAccessTokenIssuance
                        'isOnPremPublishingEnabled'                          = $appDetail.onPremisesPublishing.isOnPremPublishingEnabled
                        'isTranslateHostHeaderEnabled'                       = $appDetail.onPremisesPublishing.isTranslateHostHeaderEnabled
                        'isTranslateLinksInBodyEnabled'                      = $appDetail.onPremisesPublishing.isTranslateLinksInBodyEnabled
                        'isHttpOnlyCookieEnabled'                            = $appDetail.onPremisesPublishing.isHttpOnlyCookieEnabled
                        'isSecureCookieEnabled'                              = $appDetail.onPremisesPublishing.isSecureCookieEnabled
                        'isPersistentCookieEnabled'                          = $appDetail.onPremisesPublishing.isPersistentCookieEnabled
                        'isBackendCertificateValidationEnabled'              = $appDetail.onPremisesPublishing.isBackendCertificateValidationEnabled
                        'applicationServerTimeout'                           = $appDetail.onPremisesPublishing.applicationServerTimeout
                        'applicationType'                                    = $appDetail.onPremisesPublishing.applicationType
                        'useAlternateUrlForTranslationAndRedirect'           = $appDetail.onPremisesPublishing.useAlternateUrlForTranslationAndRedirect
                        'isStateSessionEnabled'                              = $appDetail.onPremisesPublishing.isStateSessionEnabled
                        'isAccessibleViaZTNAClient'                          = $appDetail.onPremisesPublishing.isAccessibleViaZTNAClient
                        'isDnsResolutionEnabled'                             = $appDetail.onPremisesPublishing.isDnsResolutionEnabled
                        'verifiedCustomDomainCertificatesMetadata'           = $appDetail.onPremisesPublishing.verifiedCustomDomainCertificatesMetadata
                        'verifiedCustomDomainKeyCredential'                  = $appDetail.onPremisesPublishing.verifiedCustomDomainKeyCredential
                        'verifiedCustomDomainPasswordCredential'             = $appDetail.onPremisesPublishing.verifiedCustomDomainPasswordCredential
                        'segmentsConfiguration'                              = $appDetail.onPremisesPublishing.segmentsConfiguration
                        'singleSignOnSettings'                               = $appDetail.onPremisesPublishing.singleSignOnSettings | ConvertTo-Json -Compress
                        'onPremisesApplicationSegments'                      = $appDetail.onPremisesPublishing.onPremisesApplicationSegments
                    }
                    $formattedApps += $formattedApp
                }
            } catch { }
        }
    }

    Write-Host "`r" -NoNewline
    Write-Host (" " * 120) -NoNewline
    Write-Host "`r  " -NoNewline
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host "Analysis complete: Found " -NoNewline -ForegroundColor Green
    Write-Host $formattedApps.Count -NoNewline -ForegroundColor White
    Write-Host " applications with Application Proxy configured" -ForegroundColor Green

    # ─── STAGE 3: Calculate 2026 Security Score ──────────────────────
    Write-StageHeader -StageNumber 3 -StageTitle "Calculating Security Score (2026 Standards)" -Description "Analyzing security compliance using Zero Trust principles"

    Write-Host "  " -NoNewline
    Write-Host "⟳ " -NoNewline -ForegroundColor Cyan
    Write-Host "Analyzing security configurations..." -ForegroundColor Gray

    $securityScore = Calculate-SecurityScore-2026 -ProxyApps $formattedApps

    Write-Host "  " -NoNewline
    Write-Host "✓ " -NoNewline -ForegroundColor Green
    Write-Host "Security analysis completed" -ForegroundColor Green

    Show-SecurityInsights -SecurityScore $securityScore

    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationFormatted = "{0:hh\:mm\:ss}" -f $duration

    $scanSummary = @{
        TotalApps = $allApps.Count
        ProxyApps = $formattedApps.Count
        NonProxyApps = $allApps.Count - $formattedApps.Count
        ProxyPercentage = if ($allApps.Count -gt 0) { [math]::Round(($formattedApps.Count / $allApps.Count) * 100) } else { 0 }
        ExecutionTime = $durationFormatted
    }

    # ─── STAGE 4: Generate Reports ──────────────────────────────────
    Write-StageHeader -StageNumber 4 -StageTitle "Generating Reports" -Description "Creating export files and HTML report"

    $csvPath = $null; $jsonPath = $null; $htmlPath = $null

    if ($exportFormat -ne 'None' -and $formattedApps.Count -gt 0) {
        if ($exportFormat -eq 'CSV' -or $exportFormat -eq 'Both') {
            Write-Host "  " -NoNewline
            Write-Host "⟳ " -NoNewline -ForegroundColor Cyan
            Write-Host "Exporting to CSV format..." -ForegroundColor Gray
            $csvPath = "$exportPath.csv"
            $formattedApps | Export-Csv -Path $csvPath -NoTypeInformation
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host "CSV exported: " -NoNewline -ForegroundColor Gray
            Write-Host $csvPath -ForegroundColor White
        }
        if ($exportFormat -eq 'JSON' -or $exportFormat -eq 'Both') {
            Write-Host "  " -NoNewline
            Write-Host "⟳ " -NoNewline -ForegroundColor Cyan
            Write-Host "Exporting to JSON format..." -ForegroundColor Gray
            $jsonPath = "$exportPath.json"
            $formattedApps | ConvertTo-Json -Depth 3 | Set-Content -Path $jsonPath
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host "JSON exported: " -NoNewline -ForegroundColor Gray
            Write-Host $jsonPath -ForegroundColor White
        }
    }

    if ($formattedApps.Count -gt 0) {
        try {
            Write-Host "  " -NoNewline
            Write-Host "⟳ " -NoNewline -ForegroundColor Cyan
            Write-Host "Generating HTML report with insights..." -ForegroundColor Gray

            $htmlPath = if ($exportPath) { "$exportPath.html" } else { "C:\Temp\AppProxyReport_$currentDateTime.html" }
            $htmlContent = Generate-HtmlReport -SessionInfo $sessionInfo -ScanSummary $scanSummary -ProxyApps $formattedApps -SecurityScore $securityScore -CsvPath $csvPath -JsonPath $jsonPath -HtmlPath $htmlPath
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8

            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host "HTML report generated: " -NoNewline -ForegroundColor Gray
            Write-Host $htmlPath -ForegroundColor White
        } catch {
            Write-Host "  " -NoNewline
            Write-Host "✗ " -NoNewline -ForegroundColor Red
            Write-Host "HTML report generation failed: $_" -ForegroundColor Red
        }
    }

    # ─── Final Summary ───────────────────────────────────────────────
    Write-Host ""
    Write-Host ("-" * 80) -ForegroundColor Cyan
    Write-CenteredText "Scan Complete" -Color Green
    Write-Host ("-" * 80) -ForegroundColor Cyan

    Write-Section -Title "Execution Summary" -Data @{
        "Total Applications"  = $scanSummary.TotalApps
        "Proxy Enabled"       = $scanSummary.ProxyApps
        "No Proxy Config"     = $scanSummary.NonProxyApps
        "Proxy Adoption Rate" = "$($scanSummary.ProxyPercentage)%"
        "Security Score"      = "$($securityScore.Score)/100"
        "Execution Time"      = $scanSummary.ExecutionTime
        "Processing Mode"     = if ($useParallel) { "Parallel ($ThrottleLimit threads)" } else { "Sequential" }
    }

    Write-Host ""
    Write-Host ("-" * 80) -ForegroundColor Cyan
    Write-Host ""

    # Return results (optional)
    # return $formattedApps
}
