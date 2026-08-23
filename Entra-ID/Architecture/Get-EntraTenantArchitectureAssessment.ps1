<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 22 August 2026
Modified-On  : 22 August 2026

.SYNOPSIS
    Assesses the Entra ID tenant against an enterprise reference architecture and
    produces a maturity-rated, gap-analysed, risk-prioritised assessment report.

.DESCRIPTION
    This script connects to Microsoft Graph (BYOT or Client Credentials) and evaluates
    the Entra ID tenant across ten architectural domains aligned to the Microsoft Identity
    Reference Architecture and Zero Trust principles:

        Domain 1  — Administrative Boundaries & Tenant Hygiene
        Domain 2  — Privileged Access & PIM
        Domain 3  — Authentication Strength & MFA Coverage
        Domain 4  — Conditional Access Architecture
        Domain 5  — Application Governance & App Registrations
        Domain 6  — Workload Identities (Managed Identities vs Secrets)
        Domain 7  — External Identities & B2B Governance
        Domain 8  — Emergency Access & Break-Glass Architecture
        Domain 9  — Monitoring, Alerting & Security Logging
        Domain 10 — Identity Governance (Lifecycle, Entitlement, Reviews)

    For each domain the script follows this architectural thinking model:

        Evidence → Current State → Gap/Risk → Target State → Recommendation → Roadmap

    Maturity levels are assigned using a five-stage model:
        1 - Initial      : Ad-hoc, undocumented, reactive
        2 - Developing   : Partial controls, inconsistently applied
        3 - Defined      : Controls exist and are documented but not fully enforced
        4 - Managed      : Consistently enforced, measured, and reviewed
        5 - Optimised    : Continuously improved, automated, Zero Trust-aligned

    Findings are prioritised by:
        - Business impact (data exfiltration, compliance, operational risk)
        - Security risk severity (Critical / High / Medium / Low)
        - Blast radius (tenant-wide vs scoped)
        - Privilege exposure (admin plane vs data plane)

    Output:
        - HTML interactive dashboard (light/dark theme, tabbed by domain)
        - JSON assessment export (machine-readable, CI/CD integrable)

.PARAMETER TenantId
    The Directory (tenant) ID of the Entra ID tenant to assess.

.PARAMETER ClientId
    The Application (client) ID of the app registration used for Client Credentials
    authentication. Required when -AuthMode is ClientCredentials.

.PARAMETER ClientSecret
    The client secret as a SecureString. Required when -AuthMode is ClientCredentials.

.PARAMETER AccessToken
    A pre-obtained bearer token (BYOT — Bring Your Own Token). Use when the caller
    already has a valid Graph token (e.g., from az account get-access-token or a
    pipeline step). Mutually exclusive with -ClientId / -ClientSecret.

.PARAMETER AuthMode
    Authentication mode. Accepted values: ClientCredentials, BYOT.
    Default: ClientCredentials.

.PARAMETER OutputPath
    Directory where the HTML and JSON reports will be written.
    Default: C:\Temp\EntraTenantAssessment

.PARAMETER ShowHelp
    Displays a plain-language usage guide and exits immediately.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        HTML dashboard: <OutputPath>\EntraTenantArchitectureAssessment_<timestamp>.html
        JSON export   : <OutputPath>\EntraTenantArchitectureAssessment_<timestamp>.json

.EXAMPLE
    Get-EntraTenantArchitectureAssessment -ShowHelp

    Displays the friendly usage guide and exits.

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraTenantArchitectureAssessment `
        -AuthMode ClientCredentials `
        -ClientId  "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId "f4310b4f-xxxx"

    Full assessment using app-only Client Credentials auth.

.EXAMPLE
    $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    Get-EntraTenantArchitectureAssessment `
        -AuthMode BYOT `
        -AccessToken $token `
        -TenantId "f4310b4f-xxxx"

    Full assessment using a pre-obtained bearer token (BYOT).

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraTenantArchitectureAssessment `
        -AuthMode ClientCredentials `
        -ClientId  "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId "f4310b4f-xxxx" `
        -OutputPath "D:\Reports\EntraAssessment"

    Assessment with custom output directory.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (22-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. App Registration (Client Credentials mode) with admin-consented
           Application permissions:
               Directory.Read.All              (tenant info, roles, groups, devices)
               Policy.Read.All                 (Conditional Access, auth methods policy)
               Application.Read.All            (app registrations, service principals)
               AuditLog.Read.All               (sign-in activity, audit logs)
               RoleManagement.Read.Directory   (PIM, role definitions, assignments)
               IdentityRiskyUser.Read.All      (Identity Protection risk state)
               UserAuthenticationMethod.Read.All (MFA registration coverage)
               Reports.Read.All                (usage/activity reports)
               AccessReview.Read.All           (access reviews, access review definitions)

        2. BYOT mode: the delegated or application token must carry the same
           scopes as above. Delegated tokens require the caller to be a
           Global Reader or Security Reader.

        3. Entra ID P1 minimum. P2 required for:
               - PIM eligible role detection
               - Identity Protection risk users
               - Access Review data

        4. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  → Show help and exit if -ShowHelp
        Step 1  → Authenticate (BYOT or Client Credentials)
        Step 2  → Collect tenant baseline (org, licenses, domains)
        Step 3  → Run domain assessments 1–10 in parallel logical groups
        Step 4  → Score domains, compute overall maturity
        Step 5  → Build prioritised finding list with recommendations
        Step 6  → Generate roadmap (30/60/90-day + strategic)
        Step 7  → Export HTML dashboard + JSON

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the /beta Graph endpoint. Beta APIs are subject to change.
        - PIM and Identity Protection data require Entra ID P2. Assessments for
          those domains gracefully degrade to "Insufficient Data" when P2 is absent.
        - Conditional Access evaluation is configuration-based; it does not simulate
          runtime policy evaluation against real sign-in sessions.
        - Azure RBAC, PIM for Groups, and SaaS app-level admin roles are out of scope.
        - Large tenants (>50 000 users) may experience longer run times due to
          Graph pagination across multiple domains.

.LINK
    https://learn.microsoft.com/en-us/entra/architecture/
.LINK
    https://learn.microsoft.com/en-us/security/zero-trust/
.LINK
    https://learn.microsoft.com/en-us/graph/api/overview

#>


Function Get-EntraTenantArchitectureAssessment {
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
        [Parameter(Mandatory = $true, ParameterSetName = "BYOT")]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
        [System.Security.SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = "BYOT")]
        [string]$AccessToken,

        [Parameter(ParameterSetName = "ClientCredentials")]
        [Parameter(ParameterSetName = "BYOT")]
        [ValidateSet("ClientCredentials", "BYOT")]
        [string]$AuthMode = "ClientCredentials",

        [Parameter(ParameterSetName = "ClientCredentials")]
        [Parameter(ParameterSetName = "BYOT")]
        [string]$OutputPath = "C:\Temp\EntraTenantAssessment",

        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    #region ── Friendly Help ──────────────────────────────────────────────────────

    Function Show-FriendlyHelp {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║    Entra ID Tenant Architecture Assessment  v1.0             ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  PURPOSE" -ForegroundColor Yellow
        Write-Host "    Assesses your Entra ID tenant against an enterprise reference"
        Write-Host "    architecture across 10 domains. Identifies gaps, assigns maturity"
        Write-Host "    levels, and produces a prioritised roadmap."
        Write-Host ""
        Write-Host "  AUTHENTICATION" -ForegroundColor Yellow
        Write-Host "    Client Credentials (app-only):"
        Write-Host '      $secret = Read-Host "Client secret" -AsSecureString'
        Write-Host '      Get-EntraTenantArchitectureAssessment \'
        Write-Host '          -AuthMode ClientCredentials \'
        Write-Host '          -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "    BYOT (Bring Your Own Token):"
        Write-Host '      $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken'
        Write-Host '      Get-EntraTenantArchitectureAssessment \'
        Write-Host '          -AuthMode BYOT -AccessToken $token -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "  REQUIRED APP PERMISSIONS (Application, admin-consented)" -ForegroundColor Yellow
        Write-Host "    Directory.Read.All, Policy.Read.All, Application.Read.All,"
        Write-Host "    AuditLog.Read.All, RoleManagement.Read.Directory,"
        Write-Host "    IdentityRiskyUser.Read.All, UserAuthenticationMethod.Read.All,"
        Write-Host "    Reports.Read.All"
        Write-Host ""
        Write-Host "  LICENSE REQUIREMENTS" -ForegroundColor Yellow
        Write-Host "    P1 minimum. P2 required for PIM eligible roles and Identity Protection."
        Write-Host ""
        Write-Host "  For full documentation: Get-Help Get-EntraTenantArchitectureAssessment -Full"
        Write-Host ""
    }

    if ($ShowHelp) {
        Show-FriendlyHelp
        return
    }

    #endregion

    #region ── Token Management (Client Credentials) ─────────────────────────────

    # These three functions mirror the pattern from Get-EntraID-MFARegistrationReport.ps1
    # and must live at script scope so RenewTokenIfNeeded survives outside Connect-EntraID.

    Function RequestAccessToken {
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
            $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $tokenRequestBody -ErrorAction Stop
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


    Function ShouldRenewToken {
        if (-not $global:accessToken -or -not $global:tokenExpirationTime) { return $true }
        $timeToExpire = ($global:tokenExpirationTime - (Get-Date)).TotalMinutes
        return ($timeToExpire -lt $global:RefreshIntervalInMinutes)
    }


    Function RenewTokenIfNeeded {
        # BYOT tokens are not managed — caller owns lifecycle
        if ($global:AuthMode -eq "BYOT") { return }

        if (ShouldRenewToken) {
            Write-Host "  🔄 Refreshing Graph access token..." -ForegroundColor Yellow
            RequestAccessToken
            Write-Host "  ✅ Token refreshed." -ForegroundColor Green
        }
    }


    Function Connect-EntraID {
        param (
            [Parameter(Mandatory = $true)]  [string]$ClientId,
            [Parameter(Mandatory = $true)]  [System.Security.SecureString]$ClientSecret,
            [Parameter(Mandatory = $true)]  [string]$TenantId,
            [int]$RefreshInterval = 15
        )

        Try {
            $global:accessToken = $null
            $global:tokenExpirationTime = $null
            $global:RefreshIntervalInMinutes = $RefreshInterval
            $global:TenantId = $TenantId
            $global:ClientId = $ClientId
            $global:ClientSecretSecure = $ClientSecret

            RequestAccessToken
            return $global:accessToken
        }
        Catch {
            Write-Error "Failed to authenticate to Entra ID: $_"
            return $null
        }
    }

    Function Test-GraphTokenPermissions {
        param (
            [string]$AccessToken,
            [string[]]$RequiredPermissions
        )

        try {
            $tokenParts = $AccessToken.Split(".")

            if ($tokenParts.Count -ne 3) {
                return @{
                    Valid              = $false
                    MissingPermissions = $RequiredPermissions
                }
            }

            $payload = $tokenParts[1].Replace("-", "+").Replace("_", "/")

            switch ($payload.Length % 4) {
                2 { $payload += "==" }
                3 { $payload += "=" }
            }

            $claims = [System.Text.Encoding]::UTF8.GetString(
                [Convert]::FromBase64String($payload)
            ) | ConvertFrom-Json

            $tokenPermissions = @()

            if ($claims.scp) {
                $tokenPermissions += $claims.scp -split " "
            }

            if ($claims.roles) {
                $tokenPermissions += @($claims.roles)
            }

            $missingPermissions = @(
                $RequiredPermissions | Where-Object {
                    $_ -notin $tokenPermissions
                }
            )

            return @{
                Valid              = ($missingPermissions.Count -eq 0)
                MissingPermissions = $missingPermissions
            }
        }
        catch {
            return @{
                Valid              = $false
                MissingPermissions = $RequiredPermissions
            }
        }
    }

    #endregion

    #region ── Graph API Helper ───────────────────────────────────────────────────

    Function Invoke-GraphRequest {
        <#
    .SYNOPSIS
        Thin wrapper around Invoke-RestMethod for Graph API calls.
        Handles 429 throttling, token refresh, and consistent error handling.
        Returns the parsed response object or $null on non-retriable failure.
    #>
        param (
            [Parameter(Mandatory = $true)]  [string]$Uri,
            [string]$Method = "GET",
            [hashtable]$Body = $null,
            [int]$MaxRetries = 5
        )

        $retries = 0
        do {
            RenewTokenIfNeeded

            $headers = @{
                "Authorization"    = "Bearer $global:accessToken"
                "ConsistencyLevel" = "eventual"
            }

            Try {
                $invokeParams = @{
                    Uri         = $Uri
                    Headers     = $headers
                    Method      = $Method
                    ErrorAction = "Stop"
                }
                if ($Body) { $invokeParams["Body"] = ($Body | ConvertTo-Json -Depth 10); $headers["Content-Type"] = "application/json" }

                $response = Invoke-RestMethod @invokeParams
                return $response
            }
            Catch {
                $statusCode = $_.Exception.Response.StatusCode.value__

                if ($statusCode -eq 429) {
                    $retryAfter = 30
                    Try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } Catch {}
                    Write-Host "  ⏳ Throttled (429). Waiting $retryAfter seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $retryAfter
                    $retries++
                }
                elseif ($statusCode -eq 403) {
                    Write-Verbose "  ⚠ 403 Forbidden on $Uri — permission not granted or feature requires higher license."
                    return $null
                }
                elseif ($statusCode -eq 404) {
                    Write-Verbose "  ⚠ 404 Not Found on $Uri"
                    return $null
                }
                else {
                    Write-Warning "  Graph call failed [$statusCode] → $Uri | $_"
                    return $null
                }
            }
        } while ($retries -le $MaxRetries)

        Write-Warning "  Max retries exceeded for: $Uri"
        return $null
    }


    Function Get-GraphPagedResults {
        <#
    .SYNOPSIS
        Follows @odata.nextLink pagination and returns a flat array of all .value items.
    #>
        param (
            [Parameter(Mandatory = $true)]  [string]$Uri,
            [int]$MaxPages = 200
        )

        $allItems = New-Object System.Collections.ArrayList
        $nextUri = $Uri
        $pages = 0

        do {
            $response = Invoke-GraphRequest -Uri $nextUri
            if (-not $response) { break }

            if ($response.PSObject.Properties["value"]) {
                foreach ($item in $response.value) { $null = $allItems.Add($item) }
            }
            else {
                $null = $allItems.Add($response)
            }

            $nextUri = if ($response.PSObject.Properties["@odata.nextLink"]) { $response."@odata.nextLink" } else { $null }
            $pages++
        }
        while ($nextUri -and $pages -lt $MaxPages)

        return $allItems
    }

    #endregion

    #region ── Maturity Model & Scoring ──────────────────────────────────────────

    # Maturity levels: 1=Initial, 2=Developing, 3=Defined, 4=Managed, 5=Optimised
    $script:MaturityLabels = @{
        1 = "Initial"
        2 = "Developing"
        3 = "Defined"
        4 = "Managed"
        5 = "Optimised"
    }

    $script:MaturityColors = @{
        1 = "#f85149"   # red
        2 = "#d29922"   # amber
        3 = "#388bfd"   # blue
        4 = "#39c5cf"   # cyan
        5 = "#3fb950"   # green
    }

    $script:RiskColors = @{
        "Critical" = "#f85149"
        "High"     = "#d29922"
        "Medium"   = "#388bfd"
        "Low"      = "#3fb950"
        "Info"     = "#7d8590"
    }

    # Global assessment store
    $script:Domains = [System.Collections.ArrayList]::new()
    $script:Findings = [System.Collections.ArrayList]::new()
    $script:Roadmap = [System.Collections.ArrayList]::new()


    Function Add-Finding {
        <#
    .SYNOPSIS
        Records a single architectural finding into the global findings list.
    #>
        param (
            [string]$DomainId,
            [string]$DomainName,
            [string]$CheckId,
            [string]$Title,
            [string]$Evidence,
            [string]$CurrentState,
            [string]$Gap,
            [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
            [string]$Risk,
            [string]$BusinessImpact,
            [string]$TargetState,
            [string]$Recommendation,
            [ValidateSet("0-30 Days", "31-60 Days", "61-90 Days", "Strategic")]
            [string]$RoadmapPhase,
            [int]$MaturityContribution = 0  # points contributed to domain score
        )

        $null = $script:Findings.Add([PSCustomObject]@{
                DomainId             = $DomainId
                DomainName           = $DomainName
                CheckId              = $CheckId
                Title                = $Title
                Evidence             = $Evidence
                CurrentState         = $CurrentState
                Gap                  = $Gap
                Risk                 = $Risk
                BusinessImpact       = $BusinessImpact
                TargetState          = $TargetState
                Recommendation       = $Recommendation
                RoadmapPhase         = $RoadmapPhase
                MaturityContribution = $MaturityContribution
            })
    }


    Function Set-DomainResult {
        param (
            [string]$Id,
            [string]$Name,
            [string]$Icon,
            [int]$MaturityScore,         # 1–5
            [string]$CurrentStateSummary,
            [string]$TargetStateSummary,
            [int]$CriticalCount,
            [int]$HighCount,
            [int]$MediumCount,
            [int]$LowCount,
            [string]$DataQuality = "Full" # Full | Partial | Insufficient
        )

        $label = $script:MaturityLabels[$MaturityScore]
        $color = $script:MaturityColors[$MaturityScore]

        $null = $script:Domains.Add([PSCustomObject]@{
                Id                  = $Id
                Name                = $Name
                Icon                = $Icon
                MaturityScore       = $MaturityScore
                MaturityLabel       = $label
                MaturityColor       = $color
                CurrentStateSummary = $CurrentStateSummary
                TargetStateSummary  = $TargetStateSummary
                CriticalCount       = $CriticalCount
                HighCount           = $HighCount
                MediumCount         = $MediumCount
                LowCount            = $LowCount
                DataQuality         = $DataQuality
            })
    }


    Function Get-OverallMaturityScore {
        if ($script:Domains.Count -eq 0) { return 1 }
        $avg = ($script:Domains | Measure-Object -Property MaturityScore -Average).Average
        return [Math]::Round($avg, 1)
    }

    #endregion

    #region ── Domain 1: Administrative Boundaries & Tenant Hygiene ──────────────

    Function Invoke-Domain1-AdminBoundaries {
        param ([PSCustomObject]$TenantInfo)

        Write-Host "  📐 D1: Administrative Boundaries & Tenant Hygiene..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 1.1: Custom domains configured ─────────────────────────────────
        $domains = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/domains"
        $verifiedDomains = @($domains | Where-Object { $_.isVerified -eq $true })
        $defaultOnmicrosoft = @($domains | Where-Object { $_.id -like "*.onmicrosoft.com" })

        if ($verifiedDomains.Count -gt 1) {
            $maturityPoints += 3
            Add-Finding -DomainId "D1" -DomainName "Admin Boundaries" -CheckId "D1.1" `
                -Title "Custom Domain Configured" `
                -Evidence "$($verifiedDomains.Count) verified domain(s): $(($verifiedDomains.id | Select-Object -First 3) -join ', ')" `
                -CurrentState "Custom domains are verified and in use." `
                -Gap "None identified." `
                -Risk "Info" -BusinessImpact "Low — domain configuration is healthy." `
                -TargetState "Maintain verified domain hygiene; remove unused domains." `
                -Recommendation "Periodically audit verified domains. Remove stale or test domains to reduce attack surface." `
                -RoadmapPhase "Strategic" -MaturityContribution 3
        }
        else {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Admin Boundaries" -CheckId "D1.1" `
                -Title "No Custom Domain Verified — Using .onmicrosoft.com Only" `
                -Evidence "Verified domains: $($verifiedDomains.Count). Default: $($defaultOnmicrosoft[0].id)" `
                -CurrentState "Tenant is operating on the default .onmicrosoft.com domain only." `
                -Gap "No corporate domain verified — impacts identity branding, email routing, and Zero Trust UPN standards." `
                -Risk "Medium" -BusinessImpact "User UPNs use a Microsoft-managed namespace, impeding corporate identity consistency and SSO trust." `
                -TargetState "Verify at least one corporate domain. Configure custom UPN suffix." `
                -Recommendation "Add and verify corporate domain(s) in Entra ID → Custom Domain Names. Update user UPNs to corporate namespace." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }

        # ── Check 1.2: Stale guest accounts ──────────────────────────────────────
        $cutoffDate = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddT00:00:00Z")
        $guestUri = "https://graph.microsoft.com/beta/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName,createdDateTime,signInActivity&`$count=true&`$top=100"
        $guests = Get-GraphPagedResults -Uri $guestUri
        $totalGuests = $guests.Count

        $staleGuests = @($guests | Where-Object {
                $lastSign = if ($_.PSObject.Properties["signInActivity"] -and $_.signInActivity) { $_.signInActivity.lastSignInDateTime } else { $null }
                (-not $lastSign) -or ([datetime]$lastSign -lt [datetime]$cutoffDate)
            })

        $staleGuestPct = if ($totalGuests -gt 0) { [Math]::Round(($staleGuests.Count / $totalGuests) * 100, 0) } else { 0 }

        if ($staleGuestPct -ge 40) {
            $high++
            $maturityPoints += 1
            $risk = "High"
            $phase = "0-30 Days"
        }
        elseif ($staleGuestPct -ge 20) {
            $medium++
            $maturityPoints += 2
            $risk = "Medium"
            $phase = "31-60 Days"
        }
        else {
            $maturityPoints += 4
            $risk = "Info"
            $phase = "Strategic"
        }

        Add-Finding -DomainId "D1" -DomainName "Admin Boundaries" -CheckId "D1.2" `
            -Title "Stale Guest Accounts ($staleGuestPct% inactive >90 days)" `
            -Evidence "Total guests: $totalGuests | Inactive >90 days: $($staleGuests.Count) ($staleGuestPct%)" `
            -CurrentState "$staleGuestPct% of guest accounts show no sign-in activity in the past 90 days." `
            -Gap "Stale external identities accumulate residual access rights. B2B lifecycle governance is absent or manual." `
            -Risk $risk `
            -BusinessImpact "External accounts with stale access increase data exfiltration risk and expand the external attack surface." `
            -TargetState "Zero stale guest accounts. Automated lifecycle with access reviews at 30/60/90-day cadence." `
            -Recommendation "Implement Entra ID Access Reviews for guests (P2). Enable Guest User Expiration Policy. Define and automate B2B offboarding." `
            -RoadmapPhase $phase -MaturityContribution ($maturityPoints[-1])

        # ── Check 1.3: Self-service group management ──────────────────────────────
        $groupSettings = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groupSettings"
        $ssgmEnabled = $false
        if ($groupSettings -and $groupSettings.value) {
            $gcSetting = $groupSettings.value | Where-Object { $_.displayName -eq "Group.Unified" }
            if ($gcSetting) {
                $selfSetting = $gcSetting.values | Where-Object { $_.name -eq "EnableSelfService" }
                $ssgmEnabled = ($selfSetting -and $selfSetting.value -eq "true")
            }
        }

        if (-not $ssgmEnabled) {
            $maturityPoints += 3
            Add-Finding -DomainId "D1" -DomainName "Admin Boundaries" -CheckId "D1.3" `
                -Title "Self-Service Group Management is Disabled" `
                -Evidence "Group.Unified EnableSelfService: $ssgmEnabled" `
                -CurrentState "Self-service group creation is restricted to administrators." `
                -Gap "None — this is the secure default." `
                -Risk "Info" -BusinessImpact "Low — administrative control over group sprawl is maintained." `
                -TargetState "Maintain restriction. Enable SSPM only for governed scope with naming policy and expiration." `
                -Recommendation "If enabling SSPM, pair with M365 Group Naming Policy and Expiration Policy (P1). Govern via Entitlement Management access packages." `
                -RoadmapPhase "Strategic" -MaturityContribution 3
        }
        else {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Admin Boundaries" -CheckId "D1.3" `
                -Title "Self-Service Group Management Enabled Without Confirmed Governance" `
                -Evidence "Group.Unified EnableSelfService: true" `
                -CurrentState "Any user can create Microsoft 365 Groups and Teams without administrative approval." `
                -Gap "Group sprawl, inconsistent naming, orphaned groups, and unmanaged access grants accumulate without lifecycle controls." `
                -Risk "Medium" -BusinessImpact "Uncontrolled group membership grants implicit resource access (SharePoint, Teams, mailboxes), creating data governance and compliance risk." `
                -TargetState "Self-service group creation restricted by policy. All groups subject to Naming Policy + Expiration Policy + Access Reviews." `
                -Recommendation "Configure M365 Group Naming Policy. Enable Group Expiration Policy (P1). Consider restricting creation to a security group of approved requestors." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }

        # ── Check 1.4: Tenant-level security defaults vs Conditional Access ───────
        $secDefaults = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy"
        $secDefaultsEnabled = ($secDefaults -and $secDefaults.isEnabled -eq $true)

        $caPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $enabledCAPolicies = @($caPolicies | Where-Object { $_.state -eq "enabled" })

        if ($secDefaultsEnabled -and $enabledCAPolicies.Count -gt 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D1" -DomainName "Admin Boundaries" -CheckId "D1.4" `
                -Title "Security Defaults AND Conditional Access Policies Are Both Enabled" `
                -Evidence "Security Defaults: Enabled | Enabled CA Policies: $($enabledCAPolicies.Count)" `
                -CurrentState "Security Defaults and custom Conditional Access policies are simultaneously active — a conflicting configuration." `
                -Gap "Security Defaults and Conditional Access are mutually exclusive. Simultaneous enablement is an unsupported configuration that can cause unexpected access blocks or bypass CA policy intent." `
                -Risk "High" `
                -BusinessImpact "Unpredictable authentication behaviour for all users. CA policy architecture is undermined by opaque Security Defaults controls." `
                -TargetState "Security Defaults disabled. All authentication policy implemented exclusively via Conditional Access." `
                -Recommendation "Disable Security Defaults (Entra Portal → Properties → Security Defaults). Verify existing CA policies cover MFA-for-all, block legacy auth, and admin protection before disabling." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($secDefaultsEnabled) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Admin Boundaries" -CheckId "D1.4" `
                -Title "Security Defaults Active — No Custom Conditional Access Architecture" `
                -Evidence "Security Defaults: Enabled | Enabled CA Policies: 0" `
                -CurrentState "Tenant relies on Microsoft Security Defaults for baseline authentication policy." `
                -Gap "Security Defaults apply a one-size-fits-all MFA policy with no granularity for named locations, device compliance, application risk, or privileged access differentiation." `
                -Risk "Medium" -BusinessImpact "Inability to implement risk-based, location-aware, or device-compliance-gated authentication. Blocks enterprise authentication scenarios." `
                -TargetState "Security Defaults disabled. A complete Conditional Access policy stack implemented (P1 minimum)." `
                -Recommendation "Design and deploy a CA policy baseline (MFA for all users, MFA for admins, block legacy auth, require compliant device for sensitive apps). Then disable Security Defaults." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D1" -DomainName "Admin Boundaries" -CheckId "D1.4" `
                -Title "Security Defaults Disabled — Conditional Access Architecture in Place" `
                -Evidence "Security Defaults: Disabled | Enabled CA Policies: $($enabledCAPolicies.Count)" `
                -CurrentState "Security Defaults are disabled and $($enabledCAPolicies.Count) Conditional Access policies are managing authentication." `
                -Gap "Conditional Access policies require periodic review for completeness and coverage gaps." `
                -Risk "Info" -BusinessImpact "Low — baseline security architecture is correctly positioned." `
                -TargetState "Maintain and mature CA policy set with Named Locations, Authentication Strengths, and Continuous Access Evaluation." `
                -Recommendation "Audit CA policies for coverage gaps (see Domain 4 assessment). Enable Continuous Access Evaluation (CAE) for supported applications." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D1" -Name "Administrative Boundaries" -Icon "🏛️" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Tenant hygiene and administrative boundaries assessed. $high high-risk and $medium medium-risk findings identified." `
            -TargetStateSummary "All corporate domains verified. Zero stale guests via automated lifecycle. No group sprawl. CA-driven policy architecture." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 2: Privileged Access & PIM ─────────────────────────────────

    Function Invoke-Domain2-PrivilegedAccess {
        Write-Host "  👑 D2: Privileged Access & PIM..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 2.1: Global Admins count ───────────────────────────────────────
        $gaRoleId = $null
        $roleDefs = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn"
        $gaRoleDef = $roleDefs | Where-Object { $_.displayName -eq "Global Administrator" }
        if ($gaRoleDef) { $gaRoleId = $gaRoleDef.id }

        $gaCount = 0
        if ($gaRoleId) {
            $gaAssignments = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=roleDefinitionId eq '$gaRoleId'&`$select=principalId,roleDefinitionId"
            $gaCount = ($gaAssignments | Select-Object -ExpandProperty principalId -Unique).Count
        }

        if ($gaCount -eq 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D2" -DomainName "Privileged Access" -CheckId "D2.1" `
                -Title "No Active Global Administrators Detected" `
                -Evidence "Active Global Admin assignments: $gaCount" `
                -CurrentState "No active Global Administrator role assignments detected via PIM schedules." `
                -Gap "Possible data gap (P2 PIM required), or tenant has no active GA assignments (unusual)." `
                -Risk "Critical" -BusinessImpact "If accurate, the tenant cannot be administered. If a data gap, PIM eligible-only tenants need verification." `
                -TargetState "2–4 active Global Admins for resilience. Remaining admins PIM-eligible only." `
                -Recommendation "Verify PIM eligible GA assignments. Ensure 2–4 active cloud-only GA accounts exist for break-glass scenarios." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($gaCount -le 2) {
            $low++
            $maturityPoints += 3
            Add-Finding -DomainId "D2" -DomainName "Privileged Access" -CheckId "D2.1" `
                -Title "Global Administrator Count is Within Target Range ($gaCount)" `
                -Evidence "Active Global Admin assignments (unique principals): $gaCount" `
                -CurrentState "$gaCount active Global Administrator(s). Microsoft recommends 2–4." `
                -Gap "Low GA count is positive — monitor for single-point-of-recovery risk." `
                -Risk "Low" -BusinessImpact "Low — within recommended range. Ensure break-glass accounts cover emergency access." `
                -TargetState "2–4 active GA accounts (cloud-only, MFA-enforced). All other privileged access via Just-In-Time PIM." `
                -Recommendation "Confirm at least 2 active GA accounts for resilience. All non-break-glass admin activity should use PIM-eligible Just-In-Time activation." `
                -RoadmapPhase "Strategic" -MaturityContribution 3
        }
        elseif ($gaCount -le 5) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Privileged Access" -CheckId "D2.1" `
                -Title "Global Administrator Count Elevated ($gaCount Active)" `
                -Evidence "Active Global Admin assignments (unique principals): $gaCount" `
                -CurrentState "$gaCount active Global Administrator(s). Microsoft recommends ≤4 active." `
                -Gap "Excess permanent GA assignments increase blast radius. Each account is a high-value target." `
                -Risk "Medium" -BusinessImpact "Each Global Administrator account, if compromised, can modify any tenant setting, elevate any identity, and exfiltrate all directory data." `
                -TargetState "≤4 active GA accounts (cloud-only, MFA). All other privileged work via least-privilege roles and PIM JIT." `
                -Recommendation "Identify and convert excess GA accounts to PIM-eligible. Assign least-privilege roles (e.g. User Admin, Exchange Admin) for routine tasks." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D2" -DomainName "Privileged Access" -CheckId "D2.1" `
                -Title "Excessive Global Administrators — $gaCount Active Permanent Assignments" `
                -Evidence "Active Global Admin assignments (unique principals): $gaCount" `
                -CurrentState "$gaCount accounts permanently hold Global Administrator. This is significantly above the recommended ≤4." `
                -Gap "Privilege sprawl at the highest permission level. Violates principle of least privilege and Zero Trust." `
                -Risk "High" -BusinessImpact "Massive blast radius. A single compromised GA credential enables complete tenant takeover, AAD backdooring, and irreversible configuration changes." `
                -TargetState "≤4 active GA accounts. All excess converted to PIM-eligible with approval workflow, MFA on activation, justification required." `
                -Recommendation "Emergency review of all GA assignments. Remove all except 2–4 (break-glass + operational). Convert remainder to PIM-eligible with time-limited activation and approval." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }

        # ── Check 2.2: Privileged users with no MFA ───────────────────────────────
        $privilegedRoleDefs = @($roleDefs | Where-Object { $_.isBuiltIn -eq $true -and $_.displayName -ne "Directory Synchronization Accounts" })
        $activeAssignments = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$select=principalId,roleDefinitionId"

        # Collect unique privileged principals
        # $privilegedPrincipalIds = @($activeAssignments | Select-Object -ExpandProperty principalId -Unique)
        $privilegedPrincipalIds = @($activeAssignments | ForEach-Object { $_["principalId"] } | Where-Object { $_ } | Select-Object -Unique)

        $mfaRegistrationUri = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails?`$top=500"
        $mfaRegistrations = Get-GraphPagedResults -Uri $mfaRegistrationUri
        $mfaRegisteredIds = @($mfaRegistrations | Where-Object { $_.isMfaRegistered -eq $true } | Select-Object -ExpandProperty id -Unique)

        $privNoMfa = @($privilegedPrincipalIds | Where-Object { $_ -notin $mfaRegisteredIds })
        $privNoMfaPct = if ($privilegedPrincipalIds.Count -gt 0) { [Math]::Round(($privNoMfa.Count / $privilegedPrincipalIds.Count) * 100, 0) } else { 0 }

        if ($privNoMfa.Count -gt 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D2" -DomainName "Privileged Access" -CheckId "D2.2" `
                -Title "Privileged Users Without MFA — $($privNoMfa.Count) Account(s) ($privNoMfaPct%)" `
                -Evidence "Total privileged principals: $($privilegedPrincipalIds.Count) | Without MFA: $($privNoMfa.Count)" `
                -CurrentState "$($privNoMfa.Count) account(s) with active directory role assignments have no registered MFA method." `
                -Gap "Privileged accounts reachable via password-only authentication. Violates Zero Trust and CISA MFA guidance for privileged access." `
                -Risk "Critical" `
                -BusinessImpact "Any compromised admin credential without MFA enables immediate, unrestricted privileged access. Single most exploited vector in Entra ID breaches." `
                -TargetState "100% MFA registration for all privileged identities. Phishing-resistant MFA (FIDO2/CBA) for Global Admins and Tier 0 roles." `
                -Recommendation "Immediately enforce MFA for all privileged accounts via Conditional Access. Target phishing-resistant methods (FIDO2, WHfB, CBA) for highest-privilege roles. Use TAP for onboarding." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D2" -DomainName "Privileged Access" -CheckId "D2.2" `
                -Title "All Detected Privileged Users Have MFA Registered" `
                -Evidence "Privileged principals: $($privilegedPrincipalIds.Count) | Without MFA: 0" `
                -CurrentState "All active role-holders have at least one MFA method registered." `
                -Gap "Verify MFA method strength — SMS/voice does not meet phishing-resistant standard for Tier 0." `
                -Risk "Info" -BusinessImpact "Low — MFA coverage is confirmed. Uplift opportunity: enforce phishing-resistant MFA for GA and security-sensitive roles." `
                -TargetState "Phishing-resistant MFA (FIDO2 or CBA) required for all Tier 0 and Tier 1 privileged roles." `
                -Recommendation "Review MFA methods for GA and Global Reader accounts. Create a CA Authentication Strength policy requiring FIDO2 or CBA for high-privilege access." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 4
        }

        # ── Check 2.3: Permanent privileged assignments (PIM JIT adoption) ────────
        $eligibleAssignments = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances?`$select=principalId,roleDefinitionId"
        $eligibleCount = $eligibleAssignments.Count
        $activePrivCount = $activeAssignments.Count
        $pimAdoptionPct = if (($activePrivCount + $eligibleCount) -gt 0) { [Math]::Round(($eligibleCount / ($activePrivCount + $eligibleCount)) * 100, 0) } else { 0 }

        if ($eligibleCount -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D2" -DomainName "Privileged Access" -CheckId "D2.3" `
                -Title "No PIM Just-In-Time Eligible Assignments — All Privileges Are Permanent" `
                -Evidence "Active permanent assignments: $activePrivCount | PIM eligible: $eligibleCount (0%)" `
                -CurrentState "All privileged role assignments are permanent standing access. PIM is not in use for JIT activation." `
                -Gap "Zero JIT adoption. All privileged accounts maintain 24/7 access to administrative capabilities even outside working hours." `
                -Risk "High" `
                -BusinessImpact "Permanent privileged access dramatically increases attack window. Compromised accounts can be exploited at any time without time-boxing. Violates Zero Trust time-of-access principles." `
                -TargetState "≥80% of privileged assignments converted to PIM-eligible JIT. Permanent access limited to break-glass accounts only." `
                -Recommendation "Enable Entra ID PIM (P2). Convert role assignments to PIM-eligible. Define activation policy: max 4-hour windows, MFA on activation, justification required, approval for Global Admin." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($pimAdoptionPct -lt 50) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Privileged Access" -CheckId "D2.3" `
                -Title "PIM Partially Adopted — $pimAdoptionPct% of Privileged Assignments Are JIT-Eligible" `
                -Evidence "Active permanent: $activePrivCount | PIM eligible: $eligibleCount ($pimAdoptionPct%)" `
                -CurrentState "PIM is in use but $($100 - $pimAdoptionPct)% of privileged assignments remain as permanent standing access." `
                -Gap "Partial JIT coverage leaves a significant privileged surface exposed permanently." `
                -Risk "Medium" -BusinessImpact "Remaining permanent assignments extend the attack window and reduce the value of the PIM investment." `
                -TargetState "≥90% PIM-eligible. Permanent assignments limited to ≤4 Global Admin break-glass accounts." `
                -Recommendation "Inventory remaining permanent assignments. Prioritise conversion of high-privilege roles (GA, Privileged Role Admin, Security Admin). Define activation SLA to reduce friction." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D2" -DomainName "Privileged Access" -CheckId "D2.3" `
                -Title "PIM JIT Adopted — $pimAdoptionPct% Eligible Assignments" `
                -Evidence "Active permanent: $activePrivCount | PIM eligible: $eligibleCount ($pimAdoptionPct%)" `
                -CurrentState "$pimAdoptionPct% of privileged assignments use PIM JIT activation. Standing access is significantly reduced." `
                -Gap "Ensure activation policies are tight (max 4h, approval for GA, justification). Review alert rules for suspicious activation patterns." `
                -Risk "Info" -BusinessImpact "Low — JIT adoption is strong. Focus on activation policy tightening and PIM access reviews." `
                -TargetState "100% JIT for non-break-glass accounts. Activation alerts integrated with SIEM. Monthly PIM access reviews." `
                -Recommendation "Audit PIM activation policies. Enable PIM alerts (suspicious elevation, role outside business hours). Schedule quarterly PIM access reviews." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D2" -Name "Privileged Access & PIM" -Icon "👑" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Privileged access posture assessed. $critical critical, $high high, $medium medium findings. PIM JIT adoption: $pimAdoptionPct%." `
            -TargetStateSummary "≤4 permanent GA accounts. 100% PIM JIT for all other privileged roles. Phishing-resistant MFA enforced for all admins." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 3: Authentication Strength & MFA Coverage ──────────────────

    Function Invoke-Domain3-Authentication {
        Write-Host "  🔐 D3: Authentication Strength & MFA Coverage..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 3.1: Overall MFA registration ──────────────────────────────────
        $mfaUri = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails?`$top=500"
        $mfaData = Get-GraphPagedResults -Uri $mfaUri
        $totalMfa = $mfaData.Count

        $mfaRegistered = @($mfaData | Where-Object { $_.isMfaRegistered -eq $true })
        $mfaCapable = @($mfaData | Where-Object { $_.isMfaCapable -eq $true })
        $sspr = @($mfaData | Where-Object { $_.isSsprRegistered -eq $true })
        $mfaRegPct = if ($totalMfa -gt 0) { [Math]::Round(($mfaRegistered.Count / $totalMfa) * 100, 0) } else { 0 }

        if ($mfaRegPct -lt 50) {
            $critical++
            $maturityPoints += 1
            $mfaRisk = "Critical"; $mfaPhase = "0-30 Days"
        }
        elseif ($mfaRegPct -lt 80) {
            $high++
            $maturityPoints += 2
            $mfaRisk = "High"; $mfaPhase = "0-30 Days"
        }
        elseif ($mfaRegPct -lt 95) {
            $medium++
            $maturityPoints += 3
            $mfaRisk = "Medium"; $mfaPhase = "31-60 Days"
        }
        else {
            $maturityPoints += 4
            $mfaRisk = "Info"; $mfaPhase = "Strategic"
        }

        Add-Finding -DomainId "D3" -DomainName "Authentication" -CheckId "D3.1" `
            -Title "MFA Registration Coverage: $mfaRegPct% ($($mfaRegistered.Count) / $totalMfa users)" `
            -Evidence "Total users: $totalMfa | MFA Registered: $($mfaRegistered.Count) ($mfaRegPct%) | MFA Capable: $($mfaCapable.Count) | SSPR Registered: $($sspr.Count)" `
            -CurrentState "$mfaRegPct% of user accounts have at least one MFA method registered." `
            -Gap "$(100 - $mfaRegPct)% of accounts are reachable via password-only authentication — the primary Entra ID attack vector." `
            -Risk $mfaRisk `
            -BusinessImpact "Unregistered accounts represent the highest-probability entry point for credential-stuffing, phishing, and password spray attacks." `
            -TargetState "100% MFA registration enforced via CA policy. Phishing-resistant methods (FIDO2, WHfB, CBA) the default for all users." `
            -Recommendation "Run MFA registration campaign. Enable Entra ID MFA Registration Campaign (nudge unregistered users at sign-in). Block unregistered users from accessing apps via CA. Set deadline for 100% compliance." `
            -RoadmapPhase $mfaPhase -MaturityContribution ($maturityPoints[-1])

        # ── Check 3.2: Legacy authentication protocols ────────────────────────────
        $legacyCABlock = $false
        $caPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        foreach ($policy in ($caPolicies | Where-Object { $_.state -eq "enabled" })) {
            $conds = $policy.conditions
            if ($conds.clientAppTypes -contains "exchangeActiveSync" -or $conds.clientAppTypes -contains "other") {
                if ($policy.grantControls -and $policy.grantControls.builtInControls -contains "block") { $legacyCABlock = $true }
            }
        }

        if (-not $legacyCABlock) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D3" -DomainName "Authentication" -CheckId "D3.2" `
                -Title "No Conditional Access Policy Blocking Legacy Authentication" `
                -Evidence "Scanned $($caPolicies.Count) CA policies. No policy found blocking exchangeActiveSync or 'other' client app types with Block control." `
                -CurrentState "Legacy authentication protocols (SMTP AUTH, POP3, IMAP, Basic Auth) are not explicitly blocked by Conditional Access." `
                -Gap "Legacy protocols bypass MFA entirely by design. MFA policies have no effect on legacy authentication flows." `
                -Risk "High" `
                -BusinessImpact "Password spray and credential-stuffing attacks exclusively use legacy auth endpoints precisely because they bypass MFA. This is the #1 account compromise vector in M365 tenants." `
                -TargetState "All legacy authentication blocked at the CA layer for all users and all apps, with no exceptions except explicitly approved service accounts." `
                -Recommendation "Create a CA policy: All Users, All Cloud Apps, Client App = Exchange ActiveSync + Other → Block. Test with report-only mode first. Identify service accounts using legacy auth via Sign-In logs filtered by Legacy Auth Protocols." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D3" -DomainName "Authentication" -CheckId "D3.2" `
                -Title "Legacy Authentication Blocked via Conditional Access" `
                -Evidence "A CA policy with block grant controls on legacy client app types was detected." `
                -CurrentState "Legacy authentication protocols are blocked via Conditional Access." `
                -Gap "Verify there are no exceptions or named-exclusion groups that inadvertently re-open legacy auth for users." `
                -Risk "Info" -BusinessImpact "Low — legacy auth block is in place. Audit exclusion groups regularly." `
                -TargetState "Zero exceptions to legacy auth block. All service accounts migrated to OAuth/modern auth." `
                -Recommendation "Quarterly review of CA exclusion groups. Monitor Sign-In logs for legacy auth attempts originating from excluded accounts." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 3.3: Authentication Methods Policy (Entra ID-managed) ──────────
        $authMethodsPolicy = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy"
        $fido2Method = $null
        $msAuthMethod = $null
        $smsMethod = $null
        $voiceMethod = $null

        if ($authMethodsPolicy -and $authMethodsPolicy.authenticationMethodConfigurations) {
            foreach ($method in $authMethodsPolicy.authenticationMethodConfigurations) {
                switch ($method."@odata.type") {
                    "#microsoft.graph.fido2AuthenticationMethodConfiguration" { $fido2Method = $method }
                    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration" { $msAuthMethod = $method }
                    "#microsoft.graph.smsAuthenticationMethodConfiguration" { $smsMethod = $method }
                    "#microsoft.graph.voiceAuthenticationMethodConfiguration" { $voiceMethod = $method }
                }
            }
        }

        $fido2Enabled = ($fido2Method -and $fido2Method.state -eq "enabled")
        $smsEnabled = ($smsMethod -and $smsMethod.state -eq "enabled")
        $voiceEnabled = ($voiceMethod -and $voiceMethod.state -eq "enabled")

        if (-not $fido2Enabled) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D3" -DomainName "Authentication" -CheckId "D3.3" `
                -Title "FIDO2 / Phishing-Resistant Authentication Not Enabled" `
                -Evidence "FIDO2 State: $(if ($fido2Method) { $fido2Method.state } else { 'not configured' }) | SMS: $(if ($smsEnabled){'enabled'}else{'disabled'}) | Voice: $(if ($voiceEnabled){'enabled'}else{'disabled'})" `
                -CurrentState "FIDO2 security key authentication is not enabled as an authentication method for users." `
                -Gap "No phishing-resistant MFA option available. All current MFA methods (SMS, Authenticator push) are vulnerable to real-time phishing attacks." `
                -Risk "Medium" -BusinessImpact "Without phishing-resistant options, even MFA-registered users remain vulnerable to adversary-in-the-middle (AiTM) attacks. AiTM phishing kits can bypass Authenticator push notifications." `
                -TargetState "FIDO2 enabled for all users. FIDO2 or CBA required via Authentication Strength CA policy for GA and Tier 0 roles." `
                -Recommendation "Enable FIDO2 in Authentication Methods Policy (scoped to pilot group, then all users). Create a CA Authentication Strength requiring phishing-resistant MFA for privileged roles and sensitive apps." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D3" -DomainName "Authentication" -CheckId "D3.3" `
                -Title "FIDO2 Phishing-Resistant Authentication is Enabled" `
                -Evidence "FIDO2 State: enabled" `
                -CurrentState "FIDO2 authentication is enabled for users — the highest-assurance authentication method available." `
                -Gap "Verify FIDO2 is targeted at privileged users and enforced via Authentication Strength CA policy, not just available." `
                -Risk "Info" -BusinessImpact "Low — excellent authentication posture. Focus on enforcing usage via CA Authentication Strength." `
                -TargetState "FIDO2 or CBA enforced for all GA and Tier 0 roles via CA Authentication Strength. Usage metrics monitored." `
                -Recommendation "Create Authentication Strength requiring Passwordless (FIDO2/WHfB/CBA) and apply it to a CA policy scoped to high-privilege roles and sensitive enterprise apps." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        if ($smsEnabled -or $voiceEnabled) {
            $low++
            $maturityPoints += 2
            Add-Finding -DomainId "D3" -DomainName "Authentication" -CheckId "D3.3b" `
                -Title "SMS / Voice MFA Enabled — Vulnerable to SIM-Swap and SS7 Attacks" `
                -Evidence "SMS OTP: $(if ($smsEnabled){'enabled'}else{'disabled'}) | Voice OTP: $(if ($voiceEnabled){'enabled'}else{'disabled'})" `
                -CurrentState "SMS and/or Voice one-time codes are available as authentication methods." `
                -Gap "SMS and voice OTP are the weakest MFA factors. Vulnerable to SIM-swap fraud, SS7 interception, and real-time phishing." `
                -Risk "Low" -BusinessImpact "For standard users the risk is low-medium; for privileged users SMS/voice OTP is insufficient and should be replaced with phishing-resistant methods." `
                -TargetState "SMS/Voice disabled or deprecated for all users. Microsoft Authenticator (passwordless) or FIDO2 as minimum standard." `
                -Recommendation "Plan deprecation of SMS/voice OTP. Run a migration campaign to Authenticator app (tap-to-approve, not OTP). Disable once adoption >95%." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D3" -Name "Authentication & MFA" -Icon "🔐" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "MFA coverage: $mfaRegPct%. Legacy auth block: $(if ($legacyCABlock){'✓'}else{'✗'}). FIDO2: $(if ($fido2Enabled){'✓'}else{'✗'})." `
            -TargetStateSummary "100% MFA. Legacy auth fully blocked. Phishing-resistant MFA enforced for admins and sensitive apps via Authentication Strength." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 4: Conditional Access Architecture ─────────────────────────

    Function Invoke-Domain4-ConditionalAccess {
        Write-Host "  🚦 D4: Conditional Access Architecture..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $caPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $enabledCA = @($caPolicies | Where-Object { $_.state -eq "enabled" })
        $reportOnlyCA = @($caPolicies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" })
        $disabledCA = @($caPolicies | Where-Object { $_.state -eq "disabled" })

        # ── Check 4.1: CA policy count and coverage ───────────────────────────────
        if ($enabledCA.Count -eq 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D4" -DomainName "Conditional Access" -CheckId "D4.1" `
                -Title "No Enabled Conditional Access Policies — Zero Trust Authentication Architecture Absent" `
                -Evidence "Enabled CA policies: 0 | Report-only: $($reportOnlyCA.Count) | Disabled: $($disabledCA.Count) | Total: $($caPolicies.Count)" `
                -CurrentState "No Conditional Access policies are in the Enabled state." `
                -Gap "Entire authentication flow is ungoverned. No device compliance, no location awareness, no sign-in risk controls, no MFA enforcement, no legacy auth block." `
                -Risk "Critical" -BusinessImpact "Any valid credential pair grants access from any location, device, and protocol. This represents the maximum authentication attack surface." `
                -TargetState "A baseline CA policy stack covering: MFA for all users, MFA for admins (stronger), block legacy auth, require compliant device for sensitive apps, block risky sign-ins." `
                -Recommendation "Implement the Microsoft CA policy baseline immediately. Start in Report-Only mode. Enable within 7 days. Sequence: (1) block legacy auth, (2) MFA for all users, (3) admin protection, (4) risky sign-in block." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 3

            # ── Check 4.2: All Users exclusions (risky pattern) ──────────────────
            $broadExclusionPolicies = @($enabledCA | Where-Object {
                    $_.conditions.users.includeUsers -contains "All" -and
                    (($_.conditions.users.excludeGroups | Measure-Object).Count -gt 3 -or
                    ($_.conditions.users.excludeUsers  | Measure-Object).Count -gt 5)
                })

            if ($broadExclusionPolicies.Count -gt 0) {
                $medium++
                $maturityPoints += 2
                Add-Finding -DomainId "D4" -DomainName "Conditional Access" -CheckId "D4.2" `
                    -Title "CA Policies with 'All Users' Scope Have Broad Exclusions ($($broadExclusionPolicies.Count) policies)" `
                    -Evidence "Policies with All Users + >3 excluded groups or >5 excluded users: $($broadExclusionPolicies.Count)" `
                    -CurrentState "Several CA policies targeting All Users have large exclusion sets that materially reduce coverage." `
                    -Gap "Exclusions are the primary bypass mechanism for CA policy. Large exclusion groups create shadow populations outside authentication controls." `
                    -Risk "Medium" -BusinessImpact "Users in exclusion groups bypass MFA, device compliance, and risk controls — creating high-value targets for credential attacks." `
                    -TargetState "Exclusion groups governed, time-limited, and access-reviewed. Break-glass accounts are the only long-term exclusion." `
                    -Recommendation "Audit all CA exclusion groups. Remove stale members. Implement access reviews on exclusion groups (P2). Use Entra ID Named Exclusions Report." `
                    -RoadmapPhase "31-60 Days" -MaturityContribution 2
            }
            else {
                $maturityPoints += 4
            }

            # ── Check 4.3: Report-only policies not yet promoted ──────────────────
            if ($reportOnlyCA.Count -gt $enabledCA.Count) {
                $low++
                $maturityPoints += 2
                Add-Finding -DomainId "D4" -DomainName "Conditional Access" -CheckId "D4.3" `
                    -Title "More CA Policies in Report-Only Than Enabled ($($reportOnlyCA.Count) vs $($enabledCA.Count))" `
                    -Evidence "Enabled: $($enabledCA.Count) | Report-only: $($reportOnlyCA.Count) | Disabled: $($disabledCA.Count)" `
                    -CurrentState "A larger proportion of CA policies are in report-only mode than are actively enforced." `
                    -Gap "Report-only policies provide visibility but no protection. Users are not subject to the controls being evaluated." `
                    -Risk "Low" -BusinessImpact "Intended authentication controls are visible in logs but not applied — a false sense of security during extended report-only phases." `
                    -TargetState "All baseline CA policies promoted to Enabled within 30 days of creation. Report-only used only for active impact analysis of new policies." `
                    -Recommendation "Review report-only policies. For each, assess impact (Insights & Reporting workbook). Promote to Enabled. Set a governance rule: report-only policies must be resolved within 30 days." `
                    -RoadmapPhase "31-60 Days" -MaturityContribution 2
            }
            else {
                $maturityPoints += 4
            }

            # ── Check 4.4: Named Locations defined ───────────────────────────────
            $namedLocations = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations"
            if ($namedLocations.Count -eq 0) {
                $medium++
                $maturityPoints += 2
                Add-Finding -DomainId "D4" -DomainName "Conditional Access" -CheckId "D4.4" `
                    -Title "No Named Locations Defined — Location-Aware Access Policy Not Possible" `
                    -Evidence "Named Locations configured: 0" `
                    -CurrentState "No Named Locations (trusted IP ranges or countries) are defined in Conditional Access." `
                    -Gap "Without Named Locations, CA policies cannot distinguish corporate network access from external access, or trusted from untrusted geographies." `
                    -Risk "Medium" -BusinessImpact "Cannot implement location-based policy: no travel anomaly detection, no country-block for high-risk geographies, no trusted-network MFA exclusion." `
                    -TargetState "Corporate IP ranges defined as Trusted Named Locations. Country/region allowlist or denylist policies active for sensitive applications." `
                    -Recommendation "Define Trusted Named Locations for corporate networks. Create a CA policy blocking access from high-risk countries (OFAC, known threat actor origins). Use Continuous Access Evaluation for real-time location signals." `
                    -RoadmapPhase "31-60 Days" -MaturityContribution 2
            }
            else {
                $maturityPoints += 4
                Add-Finding -DomainId "D4" -DomainName "Conditional Access" -CheckId "D4.4" `
                    -Title "Named Locations Configured ($($namedLocations.Count) location(s))" `
                    -Evidence "Named Locations: $($namedLocations.Count)" `
                    -CurrentState "$($namedLocations.Count) Named Location(s) defined — enabling location-aware CA policies." `
                    -Gap "Ensure Named Locations include all corporate egress IPs. Review country-based policies for comprehensiveness." `
                    -Risk "Info" -BusinessImpact "Low — location-awareness is in place. Keep IP ranges current as corporate network changes." `
                    -TargetState "All corporate egress IPs documented. Country-based block policy for OFAC and high-risk regions active." `
                    -Recommendation "Set a quarterly review cadence for Named Location IP accuracy. Add country-based restrictions for apps handling sensitive data." `
                    -RoadmapPhase "Strategic" -MaturityContribution 4
            }

            Add-Finding -DomainId "D4" -DomainName "Conditional Access" -CheckId "D4.1" `
                -Title "Conditional Access Architecture Present ($($enabledCA.Count) Enabled Policies)" `
                -Evidence "Enabled: $($enabledCA.Count) | Report-only: $($reportOnlyCA.Count) | Disabled: $($disabledCA.Count) | Named Locations: $($namedLocations.Count)" `
                -CurrentState "$($enabledCA.Count) Conditional Access policies are actively enforced." `
                -Gap "Coverage completeness (all users, all apps, all risk levels) requires domain-specific review." `
                -Risk "Info" -BusinessImpact "CA architecture foundation is present. Maturity depends on coverage completeness and policy specificity." `
                -TargetState "Full CA policy stack: MFA all users, admin MFA + device, legacy auth block, risky sign-in block, sensitive app device compliance, location-aware policies." `
                -Recommendation "Use the CA policy gap analysis checklist: (1) MFA for all, (2) block legacy auth, (3) admin protection, (4) risky sign-in, (5) device compliance, (6) location-based, (7) app protection." `
                -RoadmapPhase "Strategic" -MaturityContribution 3
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D4" -Name "Conditional Access" -Icon "🚦" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "CA architecture: $($enabledCA.Count) enabled, $($reportOnlyCA.Count) report-only policies. Named Locations: $($namedLocations.Count)." `
            -TargetStateSummary "Complete CA baseline enforced. All users, all apps, risk-based controls. Named locations, authentication strengths, CAE enabled." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 5: Application Governance ──────────────────────────────────

    Function Invoke-Domain5-AppGovernance {
        Write-Host "  📱 D5: Application Governance & App Registrations..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $appRegs = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/applications?`$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials,signInAudience,requiredResourceAccess&`$top=100"
        $spns = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,appId,displayName,appRoleAssignmentRequired,passwordCredentials,keyCredentials,publisherName,verifiedPublisher&`$top=100"

        $totalApps = $appRegs.Count
        $totalSPNs = $spns.Count

        # ── Check 5.1: Apps with expiring or expired secrets ──────────────────────
        $today = Get-Date
        $warn30 = $today.AddDays(30)
        $appsExpiredSecret = @()
        $appsExpiringSecret = @()

        foreach ($app in $appRegs) {
            foreach ($cred in $app.passwordCredentials) {
                if ($cred.endDateTime) {
                    $expiry = [datetime]$cred.endDateTime
                    if ($expiry -lt $today) { $appsExpiredSecret += $app.displayName; break }
                    elseif ($expiry -lt $warn30) { $appsExpiringSecret += $app.displayName; break }
                }
            }
        }

        if ($appsExpiredSecret.Count -gt 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D5" -DomainName "App Governance" -CheckId "D5.1a" `
                -Title "App Registrations with Expired Client Secrets ($($appsExpiredSecret.Count))" `
                -Evidence "Apps with expired secrets: $($appsExpiredSecret.Count) of $totalApps | Sample: $(($appsExpiredSecret | Select-Object -First 3) -join ', ')" `
                -CurrentState "$($appsExpiredSecret.Count) application registration(s) have expired client secrets — these apps will fail authentication." `
                -Gap "Expired secrets indicate absent credential lifecycle management. Apps are either broken or using undocumented alternative credentials." `
                -Risk "High" -BusinessImpact "Broken app authentications cause service disruptions. Undocumented workaround credentials represent an uncontrolled privileged access vector." `
                -TargetState "Zero expired credentials. All secret expiry dates tracked in a credential registry. 30-day renewal alerts automated." `
                -Recommendation "Audit all expired credentials. Migrate apps to Managed Identity or Federated Credentials (Workload Identity Federation) where possible. For remaining secrets, automate renewal via Key Vault." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }

        if ($appsExpiringSecret.Count -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D5" -DomainName "App Governance" -CheckId "D5.1b" `
                -Title "App Registrations with Secrets Expiring Within 30 Days ($($appsExpiringSecret.Count))" `
                -Evidence "Apps expiring <30 days: $($appsExpiringSecret.Count) | Sample: $(($appsExpiringSecret | Select-Object -First 3) -join ', ')" `
                -CurrentState "$($appsExpiringSecret.Count) app(s) have client secrets expiring within 30 days — requiring immediate renewal to prevent service disruption." `
                -Gap "Imminent credential expiry with no automated rotation in place." `
                -Risk "Medium" -BusinessImpact "Service disruption within 30 days if credentials are not renewed. Emergency renewal processes are error-prone and costly." `
                -TargetState "Automated credential rotation. 90-day advance alerts. Phased migration to Managed Identity / Workload Identity Federation." `
                -Recommendation "Renew expiring secrets immediately. Start migration planning to Managed Identity for applicable workloads. Configure Azure Monitor alerts for credential expiry." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }

        if ($appsExpiredSecret.Count -eq 0 -and $appsExpiringSecret.Count -eq 0) {
            $maturityPoints += 4
            Add-Finding -DomainId "D5" -DomainName "App Governance" -CheckId "D5.1" `
                -Title "No Expired or Imminently Expiring App Secrets Detected" `
                -Evidence "Apps with expired secrets: 0 | Apps expiring <30 days: 0 | Total app registrations: $totalApps" `
                -CurrentState "No credential expiry issues detected across $totalApps app registrations." `
                -Gap "Validate that all apps have credentials registered — some may have no credentials (relying on other auth mechanisms)." `
                -Risk "Info" -BusinessImpact "Low — credential health appears good. Implement proactive monitoring to maintain this posture." `
                -TargetState "Automated expiry monitoring. Migration to Managed Identity / Workload Identity Federation for all applicable apps." `
                -Recommendation "Enable Azure Monitor credential expiry alerts. Target progressive migration to Managed Identity and Workload Identity Federation over next 2 quarters." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 5.2: Apps with multi-tenant sign-in audience ────────────────────
        $multiTenantApps = @($appRegs | Where-Object { $_.signInAudience -ne "AzureADMyOrg" })

        if ($multiTenantApps.Count -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D5" -DomainName "App Governance" -CheckId "D5.2" `
                -Title "Multi-Tenant or Public-Audience App Registrations Detected ($($multiTenantApps.Count))" `
                -Evidence "Multi-tenant/public apps: $($multiTenantApps.Count) of $totalApps | Sign-in audiences: $(($multiTenantApps.signInAudience | Sort-Object -Unique) -join ', ')" `
                -CurrentState "$($multiTenantApps.Count) app registration(s) allow sign-in from external tenants or personal Microsoft accounts." `
                -Gap "Multi-tenant apps create implicit trust across tenant boundaries. Personal MSA-enabled apps expose the tenant to consumer identity risks." `
                -Risk "Medium" -BusinessImpact "External users from any tenant can authenticate to multi-tenant apps. If app permissions are broad, this enables data exfiltration across tenant boundaries." `
                -TargetState "All internal apps scoped to AzureADMyOrg. Multi-tenant apps explicitly documented, business-justified, and subject to enhanced CA controls (Tenant Restrictions v2)." `
                -Recommendation "Audit multi-tenant apps. For each: confirm business justification. If unjustified, convert to AzureADMyOrg. Implement Tenant Restrictions v2 to control cross-tenant app access." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D5" -DomainName "App Governance" -CheckId "D5.2" `
                -Title "All App Registrations Scoped to Home Tenant (AzureADMyOrg)" `
                -Evidence "Multi-tenant/public apps: 0 | All $totalApps apps are AzureADMyOrg" `
                -CurrentState "All app registrations restrict sign-in to the home tenant only." `
                -Gap "Good default posture. Verify business applications that legitimately need B2B access use the correct audience configuration." `
                -Risk "Info" -BusinessImpact "Low — app trust boundaries are correctly enforced." `
                -TargetState "Maintain single-tenant posture. Any multi-tenant apps require Security Review Board approval and Tenant Restrictions v2 controls." `
                -Recommendation "Document the approved app registration governance policy. Require security review for any future multi-tenant app request." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 5.3: High-permission app registrations ──────────────────────────
        $sensitivePermissions = @(
            "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", # Application.ReadWrite.All
            "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8", # RoleManagement.ReadWrite.Directory
            "62a82d76-70ea-41e2-9197-370581804d09", # Group.ReadWrite.All
            "741f803b-c850-494e-b5df-cde7c675a1ca"  # User.ReadWrite.All
        )

        $highPermApps = @($appRegs | Where-Object {
                $_.requiredResourceAccess | ForEach-Object {
                    foreach ($access in $_.resourceAccess) {
                        if ($access.id -in $sensitivePermissions -and $access.type -eq "Role") { return $true }
                    }
                }
            })

        if ($highPermApps.Count -gt 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D5" -DomainName "App Governance" -CheckId "D5.3" `
                -Title "App Registrations with Highly Privileged Graph Permissions ($($highPermApps.Count))" `
                -Evidence "Apps with tenant-wide write permissions (Application.ReadWrite.All, RoleManagement.ReadWrite.Directory, etc.): $($highPermApps.Count) | Names: $(($highPermApps.displayName | Select-Object -First 3) -join ', ')" `
                -CurrentState "$($highPermApps.Count) app registration(s) have requested highly privileged Microsoft Graph Application permissions." `
                -Gap "Application-level Graph permissions are non-interactive and always active — there is no MFA or user approval at runtime. Tenant-wide write permissions are equivalent to global admin for the covered resources." `
                -Risk "High" `
                -BusinessImpact "A compromised app secret for these applications enables full directory manipulation, role assignment changes, and user/group write operations without any human interaction." `
                -TargetState "All high-permission app registrations documented with business justification. Secrets replaced with Managed Identity or Federated Credentials. Quarterly access reviews." `
                -Recommendation "For each high-permission app: (1) confirm business justification, (2) scope to minimum required, (3) replace secrets with Managed Identity/Federated Credentials, (4) enable Microsoft Entra Workload Identity Protection alerts." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D5" -Name "Application Governance" -Icon "📱" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "App registrations: $totalApps. Service principals: $totalSPNs. Expired/expiring secrets: $($appsExpiredSecret.Count + $appsExpiringSecret.Count)." `
            -TargetStateSummary "Zero expired secrets. All apps single-tenant. High-perm apps on Managed Identity/WIF. App inventory and access reviews active." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 6: Workload Identities ─────────────────────────────────────

    Function Invoke-Domain6-WorkloadIdentities {
        Write-Host "  ⚙️  D6: Workload Identities (Managed Identity vs Secrets)..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 6.1: Service Principals with active secrets ─────────────────────
        $spns = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,appId,displayName,passwordCredentials,keyCredentials,servicePrincipalType&`$top=100"
        $spnsWithSecrets = @($spns | Where-Object { $_.servicePrincipalType -ne "ManagedIdentity" -and $_.passwordCredentials.Count -gt 0 })
        $managedIdentities = @($spns | Where-Object { $_.servicePrincipalType -eq "ManagedIdentity" })
        $totalSPNs = $spns.Count

        $secretRatio = if ($totalSPNs -gt 0) { [Math]::Round(($spnsWithSecrets.Count / $totalSPNs) * 100, 0) } else { 0 }
        $miRatio = if ($totalSPNs -gt 0) { [Math]::Round(($managedIdentities.Count / $totalSPNs) * 100, 0) } else { 0 }

        Add-Finding -DomainId "D6" -DomainName "Workload Identities" -CheckId "D6.1" `
            -Title "Workload Identity Composition: $miRatio% Managed Identity vs $secretRatio% Secret-Based" `
            -Evidence "Total SPNs: $totalSPNs | Managed Identities: $($managedIdentities.Count) ($miRatio%) | SPNs with secrets: $($spnsWithSecrets.Count) ($secretRatio%)" `
            -CurrentState "$secretRatio% of workload identities use client secrets (passwords) for authentication. $miRatio% use Managed Identity (secretless)." `
            -Gap "Secret-based workload authentication requires credential lifecycle management, rotation, and vault storage — all failure points. Managed Identity eliminates these risks entirely." `
            -Risk $(if ($secretRatio -ge 60) { "High" } elseif ($secretRatio -ge 30) { "Medium" } else { "Low" }) `
            -BusinessImpact "Every workload secret is a potential breach vector. Secrets stored in app configs, environment variables, or key vaults represent credential exfiltration risk. Unrotated secrets are the primary workload compromise mechanism." `
            -TargetState "≥80% of workload authentication via Managed Identity. Remaining 20% use Workload Identity Federation (OIDC) with zero long-lived secrets." `
            -Recommendation "Inventory all SPNs with secrets by workload type. Prioritise Azure-hosted workloads for Managed Identity migration. For non-Azure workloads, implement Workload Identity Federation. Target: zero long-lived secrets within 6 months." `
            -RoadmapPhase $(if ($secretRatio -ge 60) { "0-30 Days" } elseif ($secretRatio -ge 30) { "31-60 Days" } else { "Strategic" }) `
            -MaturityContribution $(if ($secretRatio -ge 60) { 1 } elseif ($secretRatio -ge 30) { 2 } else { 4 })

        if ($secretRatio -ge 60) { $high++ }
        elseif ($secretRatio -ge 30) { $medium++ }
        else { $low++ }
        $maturityPoints += $(if ($secretRatio -ge 60) { 1 } elseif ($secretRatio -ge 30) { 2 } else { 4 })

        # ── Check 6.2: Long-lived secrets (>1 year) ───────────────────────────────
        $longLivedSecrets = 0
        foreach ($spn in $spnsWithSecrets) {
            foreach ($cred in $spn.passwordCredentials) {
                if ($cred.startDateTime -and $cred.endDateTime) {
                    $lifetime = ([datetime]$cred.endDateTime - [datetime]$cred.startDateTime).TotalDays
                    if ($lifetime -gt 365) { $longLivedSecrets++; break }
                }
            }
        }

        if ($longLivedSecrets -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D6" -DomainName "Workload Identities" -CheckId "D6.2" `
                -Title "Long-Lived Workload Secrets Detected ($longLivedSecrets SPNs with >1-Year Secrets)" `
                -Evidence "SPNs with credential validity >365 days: $longLivedSecrets" `
                -CurrentState "$longLivedSecrets workload identity/ies have client secrets with a lifetime exceeding 1 year." `
                -Gap "Long-lived secrets extend the exploitation window after compromise. Secrets that are never rotated accumulate operational risk. Many compliance frameworks (NIST 800-63) mandate shorter credential lifetimes." `
                -Risk "Medium" -BusinessImpact "A compromised long-lived secret provides an extended, undetected access window. Without rotation, a breach may not be discoverable until the credential is used maliciously." `
                -TargetState "Maximum secret lifetime: 90 days. Automated rotation via Azure Key Vault. Zero secrets with lifetime >1 year." `
                -Recommendation "Set organization policy: max secret lifetime 90 days. Implement Azure Key Vault secret rotation (automatic rotation for supported services). Migrate to Managed Identity as the permanent solution." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D6" -DomainName "Workload Identities" -CheckId "D6.2" `
                -Title "No Long-Lived Workload Secrets Detected (>1 Year)" `
                -Evidence "SPNs with >365-day credential lifetime: 0" `
                -CurrentState "No workload identities with excessively long-lived secrets detected." `
                -Gap "Good posture. Continue monitoring and reduce max lifetime to 90 days as the target standard." `
                -Risk "Info" -BusinessImpact "Low — secret lifetime hygiene is acceptable. Tighten to 90-day maximum." `
                -TargetState "Organization policy: maximum 90-day secret lifetime. Automated rotation and migration to Managed Identity." `
                -Recommendation "Adopt an org-wide secret lifetime policy (90 days max). Publish Managed Identity migration guidance for development teams." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D6" -Name "Workload Identities" -Icon "⚙️" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Total workload identities: $totalSPNs. Managed Identity: $miRatio%. Secret-based: $secretRatio%. Long-lived secrets: $longLivedSecrets." `
            -TargetStateSummary "≥80% Managed Identity. Workload Identity Federation for non-Azure. Zero long-lived secrets. 90-day max lifetime policy." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 7: External Identities & B2B ───────────────────────────────

    Function Invoke-Domain7-ExternalIdentities {
        Write-Host "  🌐 D7: External Identities & B2B Governance..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 7.1: Cross-tenant access settings ───────────────────────────────
        $xTenantDefault = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/default"
        $xTenantPartners = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners"

        $b2bInboundAllowAll = $false
        $b2bOutboundAllowAll = $false

        if ($xTenantDefault) {
            $b2bInboundAllowAll = ($xTenantDefault.b2bCollaborationInbound -and $xTenantDefault.b2bCollaborationInbound.usersAndGroups.accessType -eq "allowed")
            $b2bOutboundAllowAll = ($xTenantDefault.b2bCollaborationOutbound -and $xTenantDefault.b2bCollaborationOutbound.usersAndGroups.accessType -eq "allowed")
        }

        if ($b2bInboundAllowAll -and $xTenantPartners.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D7" -DomainName "External Identities" -CheckId "D7.1" `
                -Title "Cross-Tenant Access: Default Policy Allows All Inbound B2B — No Partner-Specific Controls" `
                -Evidence "Default inbound B2B: Allowed for all | Configured partner policies: $($xTenantPartners.Count)" `
                -CurrentState "The default cross-tenant access policy allows inbound B2B collaboration from any external tenant with no restrictions." `
                -Gap "Any external user can be invited from any tenant. No tenant allowlist, no trust relationship model, no partner-specific MFA trust or device compliance requirements." `
                -Risk "High" -BusinessImpact "Unrestricted B2B inbound allows social-engineering-driven invitation from compromised or malicious tenants. Enables data exfiltration via guest access to SharePoint/Teams." `
                -TargetState "Default inbound B2B restricted. Partner-specific policies for approved organisations. MFA and device compliance claims honoured only from trusted partners." `
                -Recommendation "Define a B2B governance policy: approved partner list, tenant allowlist. Enable Cross-Tenant Access partner policies for approved partners. Restrict default to Block for unapproved tenants." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 3
            Add-Finding -DomainId "D7" -DomainName "External Identities" -CheckId "D7.1" `
                -Title "Cross-Tenant Access Policy Configured ($($xTenantPartners.Count) partner policies)" `
                -Evidence "Configured partner policies: $($xTenantPartners.Count) | Default inbound: $(if ($b2bInboundAllowAll){'Allowed'}else{'Restricted/Blocked'})" `
                -CurrentState "Cross-tenant access policy has $($xTenantPartners.Count) partner-specific configuration(s)." `
                -Gap "Review whether all active B2B partners have explicit policies. Verify MFA trust and device compliance claim settings per partner." `
                -Risk "Info" -BusinessImpact "Low — cross-tenant access architecture is present. Maintain partner policy completeness." `
                -TargetState "All active B2B partners with explicit policies. MFA trust and compliant device claims honoured for Entra ID-joined partner devices." `
                -Recommendation "Audit partner policies vs active B2B collaborations. Define MFA trust settings per partner tier. Enable automatic B2B access review cadence." `
                -RoadmapPhase "Strategic" -MaturityContribution 3
        }

        # ── Check 7.2: External collaboration settings ────────────────────────────
        $extCollabSettings = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy"
        $guestInviteRole = if ($extCollabSettings) { $extCollabSettings.allowInvitesFrom } else { "Unknown" }

        if ($guestInviteRole -eq "everyone" -or $guestInviteRole -eq "adminsAndGuestInviters") {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D7" -DomainName "External Identities" -CheckId "D7.2" `
                -Title "Guest Invite Permissions Are Broad — '$guestInviteRole' Can Invite Guests" `
                -Evidence "allowInvitesFrom: $guestInviteRole" `
                -CurrentState "Guest invitations can be sent by: '$guestInviteRole' — broader than administrator-only." `
                -Gap "Non-admin users sending B2B invitations bypasses centralised guest identity governance. Invited users may receive access before security and compliance vetting." `
                -Risk "Medium" -BusinessImpact "Ungoverned guest invitations lead to untracked external access, compliance audit failures, and data access by unvetted external parties." `
                -TargetState "Guest invitation restricted to Administrators and Guest Inviters role only (allowInvitesFrom = adminsAndGuestInviters). Invitation workflow with approval for self-service." `
                -Recommendation "Set External Collaboration Settings → Guest Invite Policy to 'Only admins and Guest Inviters can invite'. Implement Entitlement Management access packages (P2) for governed self-service B2B access." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D7" -DomainName "External Identities" -CheckId "D7.2" `
                -Title "Guest Invitation Permissions Are Restricted ($guestInviteRole)" `
                -Evidence "allowInvitesFrom: $guestInviteRole" `
                -CurrentState "Guest invitations are restricted to administrators or a specific governance role." `
                -Gap "Verify the Guest Inviters role membership is managed and current." `
                -Risk "Info" -BusinessImpact "Low — guest lifecycle governance is appropriately restricted." `
                -TargetState "Administrator-only invitation with Entitlement Management access packages for self-service governed B2B access." `
                -Recommendation "Review Guest Inviters role membership. Implement Entitlement Management access packages for all B2B collaboration scenarios." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D7" -Name "External Identities" -Icon "🌐" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Partner policies: $($xTenantPartners.Count). Inbound B2B: $(if ($b2bInboundAllowAll){'Open'}else{'Restricted'}). Invite policy: $guestInviteRole." `
            -TargetStateSummary "Partner-specific cross-tenant access policies. Admin-only invitations. Entitlement Management packages for governed B2B access." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 8: Emergency Access & Break-Glass ──────────────────────────

    Function Invoke-Domain8-EmergencyAccess {
        Write-Host "  🆘 D8: Emergency Access & Break-Glass Architecture..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 8.1: Break-glass account pattern detection ─────────────────────
        $allUsers = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/users?`$select=id,displayName,userPrincipalName,accountEnabled,signInActivity&`$top=100"
        $breakGlassPattern = "break.?glass|emergency|breakglass|bg\-admin|emergency.?admin|crisis|bg[0-9]"
        $bgAccounts = @($allUsers | Where-Object { $_.userPrincipalName -match $breakGlassPattern -or $_.displayName -match $breakGlassPattern })

        if ($bgAccounts.Count -lt 2) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D8" -DomainName "Emergency Access" -CheckId "D8.1" `
                -Title "Insufficient Break-Glass Accounts Detected ($($bgAccounts.Count) — Minimum 2 Required)" `
                -Evidence "Accounts matching break-glass naming patterns: $($bgAccounts.Count) | Pattern: break-glass, emergency, bg-admin, etc." `
                -CurrentState "Fewer than 2 break-glass emergency access accounts were identified by naming convention." `
                -Gap "Without 2+ verified break-glass accounts, a CA policy lockout, a Conditional Access misconfiguration, or a PIM outage could prevent ALL administrative access to the tenant." `
                -Risk "Critical" `
                -BusinessImpact "Loss of administrative access to the Entra ID tenant. Cannot remediate incidents, reset credentials, modify CA policies, or respond to security events. Recovery requires Microsoft Support (slow and costly)." `
                -TargetState "2 break-glass accounts: cloud-only, no MFA requirement, excluded from ALL CA policies, Global Admin permanent (no PIM). Both accounts in a monitoring alert group. Tested quarterly." `
                -Recommendation "Create 2 break-glass accounts immediately. Name consistently (e.g. bg-admin01@tenant.onmicrosoft.com). Exclude from all CA policies. Assign permanent Global Admin. Store credentials in secure offline vault. Set usage alerts." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            # Verify break-glass are excluded from CA policies
            $caPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
            $enabledCA = @($caPolicies | Where-Object { $_.state -eq "enabled" })

            $bgIds = $bgAccounts.id
            $bgExcludedCA = 0
            foreach ($policy in $enabledCA) {
                $excludedUsers = $policy.conditions.users.excludeUsers
                $bgInExclusions = $bgIds | Where-Object { $_ -in $excludedUsers }
                if ($bgInExclusions.Count -eq $bgIds.Count) { $bgExcludedCA++ }
            }

            $allExcluded = ($bgExcludedCA -eq $enabledCA.Count)

            if (-not $allExcluded) {
                $high++
                $maturityPoints += 2
                Add-Finding -DomainId "D8" -DomainName "Emergency Access" -CheckId "D8.1" `
                    -Title "Break-Glass Accounts Detected But Not Fully Excluded From All CA Policies" `
                    -Evidence "Break-glass accounts found: $($bgAccounts.Count) | Enabled CA policies: $($enabledCA.Count) | Policies fully excluding all BG accounts: $bgExcludedCA" `
                    -CurrentState "$($bgAccounts.Count) break-glass account(s) found, but they are not excluded from all enabled CA policies." `
                    -Gap "CA policies that apply to break-glass accounts can block emergency access — defeating their purpose during an incident." `
                    -Risk "High" -BusinessImpact "Break-glass accounts that are subject to MFA, device compliance, or location requirements may be inaccessible during the exact incident conditions when they are needed." `
                    -TargetState "Both break-glass accounts explicitly excluded from ALL CA policies. Monitored for any usage (alert immediately). Credentials tested quarterly." `
                    -Recommendation "For each enabled CA policy, verify break-glass accounts are in the Excluded Users list. Script this exclusion verification as a recurring check." `
                    -RoadmapPhase "0-30 Days" -MaturityContribution 2
            }
            else {
                $maturityPoints += 5
                Add-Finding -DomainId "D8" -DomainName "Emergency Access" -CheckId "D8.1" `
                    -Title "Break-Glass Accounts Present and Excluded From All CA Policies" `
                    -Evidence "Break-glass accounts: $($bgAccounts.Count) | Excluded from all $($enabledCA.Count) enabled CA policies: Yes" `
                    -CurrentState "$($bgAccounts.Count) break-glass account(s) are correctly excluded from all Conditional Access policies." `
                    -Gap "Verify accounts have permanent Global Admin (not PIM-eligible only) and credentials are stored offline and tested quarterly." `
                    -Risk "Info" -BusinessImpact "Low — break-glass architecture is correctly implemented." `
                    -TargetState "Quarterly break-glass credential test. Usage alerting active. Stored in offline vault. Documented in runbook." `
                    -Recommendation "Set a calendar reminder for quarterly break-glass account testing (sign-in to portal, verify access, re-secure). Create an Azure Monitor sign-in alert for any break-glass account usage." `
                    -RoadmapPhase "Strategic" -MaturityContribution 5
            }
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D8" -Name "Emergency Access" -Icon "🆘" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Break-glass accounts (naming pattern): $($bgAccounts.Count). Minimum required: 2." `
            -TargetStateSummary "2 break-glass accounts. Cloud-only. Permanent GA. Excluded from all CA. Offline credential vault. Quarterly tested." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 9: Monitoring & Security Logging ───────────────────────────

    Function Invoke-Domain9-Monitoring {
        Write-Host "  📊 D9: Monitoring, Alerting & Security Logging..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 9.1: Diagnostic settings (sign-in + audit logs) ─────────────────
        $diagSettings = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/auditLogs/signIns?`$top=1"
        $auditLogs = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$top=1"

        $signInLogsAccessible = ($diagSettings -ne $null)
        $auditLogsAccessible = ($auditLogs -ne $null)

        if (-not $signInLogsAccessible -or -not $auditLogsAccessible) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D9" -DomainName "Monitoring" -CheckId "D9.1" `
                -Title "Entra ID Audit or Sign-In Logs Not Accessible" `
                -Evidence "Sign-in logs API accessible: $signInLogsAccessible | Audit logs API accessible: $auditLogsAccessible" `
                -CurrentState "Entra ID log APIs returned no data — logs may not be routed to a SIEM or Log Analytics workspace, or the assessment app lacks permissions." `
                -Gap "Without accessible audit and sign-in logs, threat detection, incident investigation, and compliance reporting are not possible." `
                -Risk "High" -BusinessImpact "Zero visibility into authentication events, directory changes, and privilege escalation. Post-breach investigation impossible. Compliance (ISO 27001, SOC 2, GDPR) requires evidence of log collection and retention." `
                -TargetState "Entra ID Sign-In, Audit, and Identity Protection logs streamed to Microsoft Sentinel or Log Analytics. Minimum 90-day online retention, 1-year archive. SIEM alerts active." `
                -Recommendation "Configure Entra ID Diagnostic Settings to send all log categories to Log Analytics / Sentinel. Validate with the Entra ID workbook. Set up Microsoft Sentinel Identity threat detection rules." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 3
            Add-Finding -DomainId "D9" -DomainName "Monitoring" -CheckId "D9.1" `
                -Title "Entra ID Audit and Sign-In Logs Are Accessible" `
                -Evidence "Sign-in logs accessible: Yes | Audit logs accessible: Yes" `
                -CurrentState "Entra ID Sign-In and Audit log APIs are accessible — logs are being generated and retained within Graph API range (30 days)." `
                -Gap "API accessibility confirms log generation but not external SIEM routing, long-term retention, or active alerting." `
                -Risk "Info" -BusinessImpact "Low — logs exist. Confirm routing to SIEM, retention policy, and alert rules." `
                -TargetState "Logs routed to Sentinel. 12-month retention. UEBA enabled. Privileged action alerts active within 5-minute SLA." `
                -Recommendation "Verify Diagnostic Settings for Entra ID are configured to export to Log Analytics. Enable Microsoft Sentinel UEBA. Activate Identity threat detection analytic rules." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 3
        }

        # ── Check 9.2: Identity Protection risk users ─────────────────────────────
        $riskyUsers = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'&`$select=id,userDisplayName,riskLevel,riskDetail,riskLastUpdatedDateTime&`$top=100"

        if ($riskyUsers -eq $null) {
            $maturityPoints += 2
            Add-Finding -DomainId "D9" -DomainName "Monitoring" -CheckId "D9.2" `
                -Title "Identity Protection Risk Data Unavailable (P2 Required)" `
                -Evidence "riskyUsers API returned null — Entra ID P2 likely not licensed." `
                -CurrentState "Identity Protection risk data is not available. Tenant may not have Entra ID P2 license." `
                -Gap "Without Identity Protection, there is no automated risk scoring for compromised credentials, impossible travel, or anomalous sign-in patterns." `
                -Risk "Medium" -BusinessImpact "Zero automated identity risk detection. Compromised accounts remain active until manually identified. P2 is the investment point for automated identity threat response." `
                -TargetState "Entra ID P2 licensed. Identity Protection enabled with automated risk remediation (force MFA or block on High risk)." `
                -Recommendation "Evaluate Entra ID P2 or Microsoft 365 E5 licensing. Enable Identity Protection. Create Risk-Based CA policies (High user risk → password reset, High sign-in risk → MFA)." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
            $medium++
        }
        elseif ($riskyUsers.Count -gt 0) {
            $criticalRisk = @($riskyUsers | Where-Object { $_.riskLevel -eq "high" })
            if ($criticalRisk.Count -gt 0) {
                $critical++
                $maturityPoints += 1
            }
            else { $high++; $maturityPoints += 2 }

            Add-Finding -DomainId "D9" -DomainName "Monitoring" -CheckId "D9.2" `
                -Title "$($riskyUsers.Count) At-Risk Users in Identity Protection ($(($criticalRisk).Count) High Risk)" `
                -Evidence "Total at-risk users: $($riskyUsers.Count) | High risk: $($criticalRisk.Count) | Medium risk: $($riskyUsers.Count - $criticalRisk.Count)" `
                -CurrentState "Identity Protection has flagged $($riskyUsers.Count) user account(s) as actively at-risk." `
                -Gap "At-risk users have suspected compromised credentials or anomalous behaviour patterns. Unaddressed risky users represent active, ongoing threats." `
                -Risk $(if ($criticalRisk.Count -gt 0) { "Critical" } else { "High" }) `
                -BusinessImpact "Accounts flagged at High risk by Identity Protection have a high probability of credential compromise. Immediate investigation and remediation is required to prevent data breach." `
                -TargetState "Zero unaddressed at-risk users. Automated risk remediation via CA Risk-Based policies. Risk dismissed only after confirmed remediation." `
                -Recommendation "Immediately investigate all High-risk users. Force password reset and MFA registration. Deploy CA Risk-Based policies to automate future remediation: (High user risk → require secure password reset), (High sign-in risk → block)." `
                -RoadmapPhase "0-30 Days" -MaturityContribution ($maturityPoints[-1])
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D9" -DomainName "Monitoring" -CheckId "D9.2" `
                -Title "No At-Risk Users Detected in Identity Protection" `
                -Evidence "At-risk users: 0 (Identity Protection accessible — P2 licensed)" `
                -CurrentState "Identity Protection is accessible and reports zero at-risk users." `
                -Gap "Maintain vigilance. Zero at-risk users reflects current state — not a permanent guarantee." `
                -Risk "Info" -BusinessImpact "Low — good identity risk posture. Maintain risk-based CA policies for automated future remediation." `
                -TargetState "Zero at-risk users maintained via automated risk-based CA policies. Weekly risk report review." `
                -Recommendation "Confirm CA risk-based policies are active (not just report-only). Set up weekly risk summary email to Security team." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D9" -Name "Monitoring & Logging" -Icon "📊" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Sign-in logs: $(if ($signInLogsAccessible){'Accessible'}else{'Not accessible'}). At-risk users: $(if ($riskyUsers) { $riskyUsers.Count } else { 'N/A (P2)'})." `
            -TargetStateSummary "All logs in Sentinel. 12-month retention. UEBA active. Risk-based CA policies automating remediation. Zero unaddressed risky users." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 10: Identity Governance ────────────────────────────────────

    Function Invoke-Domain10-Governance {
        Write-Host "  🏛️  D10: Identity Governance (Lifecycle & Reviews)..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 10.1: Stale user accounts (no sign-in > 90 days) ───────────────
        $cutoff = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddT00:00:00Z")
        $allUsers = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/users?`$select=id,displayName,userPrincipalName,accountEnabled,signInActivity,createdDateTime,userType&`$filter=accountEnabled eq true and userType eq 'Member'&`$top=100"

        $staleUsers = @($allUsers | Where-Object {
                $lastSign = if ($_.PSObject.Properties["signInActivity"] -and $_.signInActivity) { $_.signInActivity.lastSignInDateTime } else { $null }
                $created = $_.createdDateTime
                # Exclude brand new accounts (< 30 days)
                $isNew = ($created -and ([datetime]$created) -gt (Get-Date).AddDays(-30))
                (-not $isNew) -and ((-not $lastSign) -or ([datetime]$lastSign -lt [datetime]$cutoff))
            })

        $totalMembers = $allUsers.Count
        $stalePct = if ($totalMembers -gt 0) { [Math]::Round(($staleUsers.Count / $totalMembers) * 100, 0) } else { 0 }
        $enabledStale = @($staleUsers | Where-Object { $_.accountEnabled -eq $true })

        if ($stalePct -ge 30) {
            $high++
            $maturityPoints += 1
            $risk = "High"; $phase = "0-30 Days"
        }
        elseif ($stalePct -ge 15) {
            $medium++
            $maturityPoints += 2
            $risk = "Medium"; $phase = "31-60 Days"
        }
        else {
            $maturityPoints += 4
            $risk = "Info"; $phase = "Strategic"
        }

        Add-Finding -DomainId "D10" -DomainName "Governance" -CheckId "D10.1" `
            -Title "Stale Member Accounts — $($enabledStale.Count) Enabled Users with No Sign-In >90 Days ($stalePct%)" `
            -Evidence "Total enabled members: $totalMembers | Inactive >90 days (enabled): $($enabledStale.Count) ($stalePct%)" `
            -CurrentState "$stalePct% of enabled member accounts show no sign-in activity in 90+ days and are still enabled." `
            -Gap "Stale accounts represent an identity hygiene failure. Departed or inactive users retain access entitlements beyond their active employment period." `
            -Risk $risk -BusinessImpact "Stale accounts are primary targets for account takeover via password spray. They often retain resource access (SharePoint, Teams) from previous roles, violating least privilege and creating compliance gaps." `
            -TargetState "Zero stale enabled accounts. HR-driven lifecycle: account disabled on day of departure, deleted after 30-day retention. Automated via Lifecycle Workflows." `
            -Recommendation "Implement Entra ID Lifecycle Workflows (P2) or Logic Apps for HR-triggered deprovisioning. Audit and disable all stale accounts. Define 30-day disable → 30-day delete policy for leavers." `
            -RoadmapPhase $phase -MaturityContribution ($maturityPoints[-1])

        # ── Check 10.2: Accounts without manager (governance gap) ────────────────
        $noManagerUri = "https://graph.microsoft.com/beta/users?`$select=id,displayName,accountEnabled&`$filter=accountEnabled eq true and userType eq 'Member'&`$top=100"
        # Note: Graph does not filter directly on manager absence — we use a known workaround
        # Sample up to 200 users and check manager in bulk via separate call if affordable
        $managerlessCount = 0
        # $sampleUsers = Get-GraphPagedResults -Uri ($noManagerUri + "&`$top=200")
        $sampleUsers = Get-GraphPagedResults -Uri $noManagerUri
        $sampleCount = [Math]::Min($sampleUsers.Count, 50)  # Limit API calls for large tenants

        # foreach ($u in ($sampleUsers | Select-Object -First $sampleCount)) {
        #     # $mgr = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/users/$($u.id)/manager"
        #     $mgr = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/users/$($u["id"])/manager"
        #     if (-not $mgr) { $managerlessCount++ }
        # }

        foreach ($u in ($sampleUsers | Select-Object -First $sampleCount)) {
            $userId = $u["id"]   # or $u.id if you've confirmed it's a PSObject
            if ([string]::IsNullOrWhiteSpace($userId)) { 
                continue   # skip this user – no ID to query
            }

            try {
                $mgr = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/users/$userId/manager" -ErrorAction Stop
                # manager exists – do nothing
            }
            catch {
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 404) {
                    $managerlessCount++   # no manager assigned
                }
                else {
                    Write-Warning "Error fetching manager for $userId : $($_.Exception.Message)"
                }
            }
        }

        $managerlessPct = if ($sampleCount -gt 0) { [Math]::Round(($managerlessCount / $sampleCount) * 100, 0) } else { 0 }

        if ($managerlessPct -ge 40) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D10" -DomainName "Governance" -CheckId "D10.2" `
                -Title "High Proportion of Users Without Manager Assignment (~$managerlessPct% of sampled)" `
                -Evidence "Sampled $sampleCount accounts | Without manager: $managerlessCount (~$managerlessPct%)" `
                -CurrentState "~$managerlessPct% of a sampled user population have no manager assigned in Entra ID." `
                -Gap "Manager assignments are required for Access Reviews, Lifecycle Workflows, approval chains, and governance workflows. Missing managers orphan accounts and break delegation chains." `
                -Risk "Medium" -BusinessImpact "Access Reviews and entitlement approvals require a valid reviewer chain. Orphan accounts without managers cannot be reviewed or approved — excluding them from governance controls." `
                -TargetState "100% of active member accounts have a valid manager. Manager attribute synced from HR source of truth via Entra ID provisioning." `
                -Recommendation "Sync manager attribute from HR system via API-driven provisioning or on-premises HR sync. Audit and bulk-update missing manager attributes. This is a pre-requisite for Access Reviews and Lifecycle Workflows." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D10" -DomainName "Governance" -CheckId "D10.2" `
                -Title "Manager Assignment Coverage Appears Adequate (~$managerlessPct% Without Manager — Sample)" `
                -Evidence "Sampled $sampleCount accounts | Without manager: $managerlessCount (~$managerlessPct%)" `
                -CurrentState "Manager assignment coverage is within acceptable range based on sample." `
                -Gap "Note: based on a sample of $sampleCount users. Full tenant analysis recommended for large environments." `
                -Risk "Info" -BusinessImpact "Low — manager attribute coverage supports governance workflows." `
                -TargetState "100% manager assignment, synced from HR system. Validated monthly via Lifecycle Workflow data." `
                -Recommendation "Validate manager attribute accuracy in HR system sync. Target 100% coverage as a prerequisite for Lifecycle Workflows and Access Reviews." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 10.3: Access Reviews (P2 feature) ───────────────────────────────
        $accessReviews = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions?`$top=20"

        if ($accessReviews -eq $null) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D10" -DomainName "Governance" -CheckId "D10.3" `
                -Title "Access Reviews Not Available (Entra ID P2 Required)" `
                -Evidence "Access Reviews API returned null — P2 may not be licensed." `
                -CurrentState "Access Reviews feature is not available — likely due to absence of Entra ID P2 license." `
                -Gap "Without Access Reviews, privileged role entitlements, group memberships, and guest access are never periodically certified — a key compliance requirement." `
                -Risk "Medium" -BusinessImpact "No evidence of entitlement certification for auditors. Accumulated excessive access over time. Non-compliance with SOC 2, ISO 27001, and regulatory access control requirements." `
                -TargetState "Entra ID P2 licensed. Quarterly access reviews for privileged roles. Semi-annual reviews for sensitive group memberships. Annual reviews for all guest users." `
                -Recommendation "Invest in Entra ID P2 or M365 E5. Configure Access Reviews for: (1) PIM privileged roles, (2) security groups with sensitive app access, (3) guest user B2B access." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        elseif ($accessReviews.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D10" -DomainName "Governance" -CheckId "D10.3" `
                -Title "No Access Reviews Configured — Entitlement Certification Absent" `
                -Evidence "Active Access Review definitions: 0 (P2 appears licensed — API accessible)" `
                -CurrentState "Access Reviews (P2) is licensed but no review definitions have been configured." `
                -Gap "Privileged roles, sensitive group memberships, and guest access are never certified. Accumulated excessive access is invisible to governance." `
                -Risk "High" -BusinessImpact "Compliance gap: SOC 2, ISO 27001, and regulatory frameworks require periodic access certification. Without reviews, accumulated privilege and stale access cannot be evidenced or remediated." `
                -TargetState "Quarterly PIM access reviews. Semi-annual group membership reviews. Annual guest access reviews. All auto-approved decisions require 30-day review period." `
                -Recommendation "Configure Access Reviews immediately: (1) PIM role reviews (quarterly, reviewer = admin manager), (2) sensitive group reviews (semi-annual), (3) guest access reviews (annual). Integrate with Microsoft Entra Identity Governance dashboard." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $activeReviews = @($accessReviews | Where-Object { $_.status -eq "active" -or $_.status -eq "inProgress" })
            $completedReviews = @($accessReviews | Where-Object { $_.status -eq "completed" })
            $maturityPoints += 4
            Add-Finding -DomainId "D10" -DomainName "Governance" -CheckId "D10.3" `
                -Title "Access Reviews Configured ($($accessReviews.Count) definitions — $($activeReviews.Count) active)" `
                -Evidence "Total review definitions: $($accessReviews.Count) | Active/In-progress: $($activeReviews.Count) | Completed: $($completedReviews.Count)" `
                -CurrentState "Access Reviews are configured and in operation." `
                -Gap "Verify reviews cover all critical scope: PIM roles, sensitive groups, and all guest accounts. Check reviewer participation rates." `
                -Risk "Info" -BusinessImpact "Low — governance controls are in place. Focus on review quality and coverage completeness." `
                -TargetState "100% coverage of PIM roles, sensitive apps, and guests. >90% reviewer participation. Auto-remove decisions applied within 14 days." `
                -Recommendation "Audit access review scope completeness. Add reviews for any scope not yet covered. Monitor reviewer participation rates in Entra ID Governance insights." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D10" -Name "Identity Governance" -Icon "🏛️" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Stale accounts: $stalePct%. Access Reviews: $(if ($accessReviews) { $accessReviews.Count } else {'Unavailable (P2)'}) definitions. Manager coverage: ~$(100 - $managerlessPct)%." `
            -TargetStateSummary "HR-driven lifecycle. Zero stale accounts. Access Reviews for all privileged roles, groups, guests. 100% manager assignment." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── HTML Dashboard Generation ─────────────────────────────────────────

    Function ConvertTo-JsonSafe {
        param ([string]$s)
        return $s -replace '\\', '\\' -replace '"', '\"' -replace "`r", '' -replace "`n", '\n' -replace "`t", '\t' -replace '<', '\u003c' -replace '>', '\u003e' -replace '\$', '\u0024'
    }


    Function Build-FindingsJson {
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.Append("[")
        $first = $true
        foreach ($f in $script:Findings) {
            if (-not $first) { $null = $sb.Append(",") }
            $first = $false
            $null = $sb.Append("{")
            $null = $sb.Append("""domainId"":""$(ConvertTo-JsonSafe $f.DomainId)"",")
            $null = $sb.Append("""domainName"":""$(ConvertTo-JsonSafe $f.DomainName)"",")
            $null = $sb.Append("""checkId"":""$(ConvertTo-JsonSafe $f.CheckId)"",")
            $null = $sb.Append("""title"":""$(ConvertTo-JsonSafe $f.Title)"",")
            $null = $sb.Append("""evidence"":""$(ConvertTo-JsonSafe $f.Evidence)"",")
            $null = $sb.Append("""currentState"":""$(ConvertTo-JsonSafe $f.CurrentState)"",")
            $null = $sb.Append("""gap"":""$(ConvertTo-JsonSafe $f.Gap)"",")
            $null = $sb.Append("""risk"":""$(ConvertTo-JsonSafe $f.Risk)"",")
            $null = $sb.Append("""businessImpact"":""$(ConvertTo-JsonSafe $f.BusinessImpact)"",")
            $null = $sb.Append("""targetState"":""$(ConvertTo-JsonSafe $f.TargetState)"",")
            $null = $sb.Append("""recommendation"":""$(ConvertTo-JsonSafe $f.Recommendation)"",")
            $null = $sb.Append("""roadmapPhase"":""$(ConvertTo-JsonSafe $f.RoadmapPhase)""")
            $null = $sb.Append("}")
        }
        $null = $sb.Append("]")
        return $sb.ToString()
    }


    Function Build-DomainsJson {
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.Append("[")
        $first = $true
        foreach ($d in $script:Domains) {
            if (-not $first) { $null = $sb.Append(",") }
            $first = $false
            $null = $sb.Append("{")
            $null = $sb.Append("""id"":""$(ConvertTo-JsonSafe $d.Id)"",")
            $null = $sb.Append("""name"":""$(ConvertTo-JsonSafe $d.Name)"",")
            $null = $sb.Append("""icon"":""$(ConvertTo-JsonSafe $d.Icon)"",")
            $null = $sb.Append("""maturityScore"":$($d.MaturityScore),")
            $null = $sb.Append("""maturityLabel"":""$(ConvertTo-JsonSafe $d.MaturityLabel)"",")
            $null = $sb.Append("""maturityColor"":""$(ConvertTo-JsonSafe $d.MaturityColor)"",")
            $null = $sb.Append("""currentStateSummary"":""$(ConvertTo-JsonSafe $d.CurrentStateSummary)"",")
            $null = $sb.Append("""targetStateSummary"":""$(ConvertTo-JsonSafe $d.TargetStateSummary)"",")
            $null = $sb.Append("""critical"":$($d.CriticalCount),")
            $null = $sb.Append("""high"":$($d.HighCount),")
            $null = $sb.Append("""medium"":$($d.MediumCount),")
            $null = $sb.Append("""low"":$($d.LowCount)")
            $null = $sb.Append("}")
        }
        $null = $sb.Append("]")
        return $sb.ToString()
    }


    Function Generate-HtmlDashboard {
        param (
            [string]$TenantName,
            [string]$TenantId,
            [double]$OverallMaturity,
            [string]$AssessmentDate,
            [string]$DomainsJson,
            [string]$FindingsJson,
            [string]$OutputFilePath
        )

        $overallLabel = $script:MaturityLabels[[int][Math]::Round($OverallMaturity)]
        if (-not $overallLabel) { $overallLabel = "Initial" }

        $totalCritical = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
        $totalHigh = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
        $totalMedium = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count
        $totalLow = ($script:Findings | Where-Object { $_.Risk -eq "Low" }).Count
        $totalFindings = $script:Findings.Count

        $ringPct = [int]([Math]::Round(($OverallMaturity / 5) * 100, 0))
        $ringR = 54
        $ringCirc = [Math]::Round(2 * [Math]::PI * $ringR, 1)
        $ringDash = [Math]::Round($ringCirc * ($ringPct / 100), 1)
        $ringGap = [Math]::Round($ringCirc - $ringDash, 1)

        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entra ID Architecture Assessment — __TENANT_NAME__</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;
  --border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;
  --green:#3fb950;--amber:#d29922;--red:#f85149;
  --text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);
}
body.light-theme{
  --bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;
  --border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;
  --green:#1a7f37;--amber:#b08000;--red:#cf222e;
  --text:#1f2328;--muted:#636c76;--muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}
a{color:var(--accent);text-decoration:none}

/* ── Sidebar ── */
#sidebar{position:fixed;left:0;top:0;width:240px;height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;overflow-y:auto}
.logo-block{padding:20px 16px 16px;border-bottom:1px solid var(--border)}
.logo-icon{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#388bfd,#a371f7);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3}
.logo-sub{font-size:10px;color:var(--muted);margin-top:3px}
.ver-badge{display:inline-block;font-size:9px;background:var(--surface3);color:var(--accent);padding:2px 7px;border-radius:20px;margin-top:6px;font-family:var(--mono)}
nav{flex:1;padding:10px 8px}
.nav-section{font-size:9px;font-weight:700;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;padding:10px 10px 4px}
.nav-btn{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:var(--radius-sm);cursor:pointer;font-size:12px;color:var(--muted2);margin-bottom:2px;transition:all .15s;border:none;background:none;width:100%;text-align:left}
.nav-btn:hover{background:var(--surface2);color:var(--text)}
.nav-btn.active{background:rgba(56,139,253,.12);color:var(--accent);border-left:3px solid var(--accent);font-weight:600}
.nav-btn .nav-icon{font-size:14px;width:18px;text-align:center}
.theme-toggle{padding:12px 16px;border-top:1px solid var(--border)}
.theme-pill{display:flex;background:var(--surface2);border-radius:20px;padding:3px}
.theme-opt{flex:1;padding:5px;text-align:center;font-size:11px;border-radius:16px;cursor:pointer;transition:all .2s;color:var(--muted)}
.theme-opt.active{background:var(--accent);color:#fff;font-weight:600}
.sidebar-footer{padding:10px 14px;font-size:10px;color:var(--muted);border-top:1px solid var(--border)}
.kbd{background:var(--surface3);padding:1px 5px;border-radius:3px;font-family:var(--mono);font-size:9px}

/* ── Main ── */
#main{margin-left:240px;padding:28px}
.page{display:none;animation:fadeIn .25s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:24px}
.page-header h1{font-size:22px;font-weight:700}
.page-header p{color:var(--muted);font-size:13px;margin-top:4px}

/* ── Stat Cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;border-top:3px solid;transition:transform .15s,box-shadow .15s}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.stat-card.c-blue{border-top-color:var(--accent)}
.stat-card.c-cyan{border-top-color:var(--accent2)}
.stat-card.c-purple{border-top-color:var(--accent3)}
.stat-card.c-green{border-top-color:var(--green)}
.stat-card.c-amber{border-top-color:var(--amber)}
.stat-card.c-red{border-top-color:var(--red)}
.stat-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.stat-value{font-size:28px;font-weight:700;font-family:var(--mono)}
.stat-sub{font-size:11px;color:var(--muted);margin-top:4px}

/* ── Overall Maturity Ring ── */
.health-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;display:flex;align-items:center;gap:24px;margin-bottom:24px}
.health-ring-wrap{position:relative;width:128px;height:128px;flex-shrink:0}
.health-ring-wrap svg{transform:rotate(-90deg)}
.health-ring-bg{stroke:var(--surface3);stroke-width:10;fill:none}
.health-ring-fill{stroke-width:10;fill:none;stroke-linecap:round;transition:stroke-dasharray 1.2s cubic-bezier(.4,0,.2,1)}
.ring-label{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}
.ring-val{font-size:26px;font-weight:700;font-family:var(--mono)}
.ring-sub{font-size:9px;color:var(--muted);margin-top:1px}
.health-info{flex:1}
.health-info h2{font-size:18px;font-weight:700;margin-bottom:4px}
.health-info p{font-size:13px;color:var(--muted2);line-height:1.5}
.maturity-scale{display:flex;gap:6px;margin-top:12px;flex-wrap:wrap}
.ms-pill{font-size:10px;padding:3px 10px;border-radius:20px;border:1px solid var(--border);color:var(--muted)}
.ms-pill.active{font-weight:700;border-color:currentColor}

/* ── Panels ── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.panel-title{font-size:14px;font-weight:700}
.panel-badge{font-size:10px;padding:2px 9px;border-radius:20px;background:var(--surface3);color:var(--muted);font-family:var(--mono)}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}

/* ── Domain Cards ── */
.domain-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px;margin-bottom:24px}
.domain-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;cursor:pointer;transition:all .2s;border-left:4px solid}
.domain-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.domain-card-header{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.domain-icon{font-size:20px}
.domain-name{font-size:13px;font-weight:700;flex:1}
.maturity-badge{font-size:10px;font-weight:700;padding:3px 9px;border-radius:20px;background:rgba(255,255,255,.08)}
.domain-score-bar{height:4px;background:var(--surface3);border-radius:2px;margin-bottom:10px}
.domain-score-fill{height:100%;border-radius:2px;transition:width 1s ease}
.domain-risk-chips{display:flex;gap:6px;flex-wrap:wrap}
.risk-chip{font-size:10px;padding:2px 8px;border-radius:12px;font-weight:600;font-family:var(--mono)}
.rc-critical{background:rgba(248,81,73,.15);color:#f85149}
.rc-high    {background:rgba(210,153,34,.15);color:#d29922}
.rc-medium  {background:rgba(56,139,253,.15);color:#388bfd}
.rc-low     {background:rgba(63,185,80,.15);color:#3fb950}
.rc-info    {background:rgba(125,133,144,.15);color:#7d8590}

/* ── Findings Table ── */
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.search-wrap{position:relative;flex:1;min-width:200px}
.search-wrap input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px 7px 32px;color:var(--text);font-size:12px;font-family:var(--sans)}
.search-wrap input:focus{outline:none;border-color:var(--accent)}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
.filter-pills{display:flex;gap:6px;flex-wrap:wrap}
.fpill{font-size:11px;padding:4px 11px;border-radius:20px;cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted);transition:all .15s}
.fpill.active{font-weight:700}
.fpill-all.active   {background:var(--accent);color:#fff;border-color:var(--accent)}
.fpill-crit.active  {background:var(--red);color:#fff;border-color:var(--red)}
.fpill-high.active  {background:var(--amber);color:#fff;border-color:var(--amber)}
.fpill-medium.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.fpill-low.active   {background:var(--green);color:#fff;border-color:var(--green)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:var(--text)}
.sort-arrow{font-size:9px;margin-left:3px;opacity:.5}
.sort-active .sort-arrow{opacity:1;color:var(--accent)}
td{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:top;line-height:1.4}
tr:hover td{background:var(--surface2)}
.risk-badge{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:12px;font-family:var(--mono)}
.rb-Critical{background:rgba(248,81,73,.18);color:#f85149}
.rb-High    {background:rgba(210,153,34,.18);color:#d29922}
.rb-Medium  {background:rgba(56,139,253,.18);color:#388bfd}
.rb-Low     {background:rgba(63,185,80,.18);color:#3fb950}
.rb-Info    {background:rgba(125,133,144,.18);color:#7d8590}
.phase-badge{font-size:10px;padding:2px 8px;border-radius:12px;background:var(--surface3);color:var(--muted);font-family:var(--mono);white-space:nowrap}
.domain-tag{font-size:10px;padding:2px 7px;border-radius:12px;background:rgba(163,113,247,.12);color:var(--accent3);font-family:var(--mono)}

/* ── Pagination ── */
.pagination{display:flex;align-items:center;gap:6px;margin-top:14px;flex-wrap:wrap}
.pg-btn{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 10px;cursor:pointer;font-size:12px;color:var(--text);font-family:var(--sans)}
.pg-btn:hover{background:var(--surface3)}
.pg-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.pg-info{font-size:11px;color:var(--muted);margin-left:8px}

/* ── Detail Drawer ── */
#detailPanel{position:fixed;inset:0;z-index:999;pointer-events:none}
#detailPanel.open{pointer-events:all}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.55);opacity:0;transition:opacity .25s}
#detailPanel.open #detailBackdrop{opacity:1}
#detailDrawer{position:absolute;right:0;top:0;height:100%;width:520px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);padding:24px;overflow-y:auto;transform:translateX(100%);transition:transform .3s cubic-bezier(.4,0,.2,1)}
#detailPanel.open #detailDrawer{transform:none}
.drawer-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px}
.drawer-title{font-size:15px;font-weight:700;line-height:1.4;flex:1;margin-right:12px}
.drawer-close{background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;padding:0;line-height:1}
.drawer-close:hover{color:var(--text)}
.drawer-chips{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:16px}
.drawer-section{margin-bottom:14px}
.drawer-label{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:5px;font-weight:700}
.drawer-value{font-size:12px;line-height:1.55;color:var(--muted2);background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px;border:1px solid var(--border)}
.drawer-nav{display:flex;gap:8px;margin-top:16px;padding-top:16px;border-top:1px solid var(--border)}
.drawer-nav button{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 14px;cursor:pointer;font-size:12px;color:var(--text);font-family:var(--sans)}
.drawer-nav button:hover{background:var(--surface3)}
.drawer-count{font-size:11px;color:var(--muted);margin-left:auto;align-self:center}

/* ── Roadmap ── */
.roadmap-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.roadmap-col{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px}
.roadmap-col-header{display:flex;align-items:center;gap:8px;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.roadmap-col-label{font-size:12px;font-weight:700}
.roadmap-count{font-size:11px;font-family:var(--mono);background:var(--surface3);padding:2px 8px;border-radius:20px;color:var(--muted)}
.roadmap-item{margin-bottom:10px;padding:10px;background:var(--surface2);border-radius:var(--radius-sm);border:1px solid var(--border);cursor:pointer;transition:all .15s}
.roadmap-item:hover{border-color:var(--accent);background:var(--surface3)}
.roadmap-item-title{font-size:11px;font-weight:600;line-height:1.4;margin-bottom:5px}
.roadmap-item-meta{display:flex;gap:5px;flex-wrap:wrap}

/* ── Toast ── */
#toast{position:fixed;bottom:20px;right:20px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 16px;font-size:12px;z-index:9999;transform:translateY(12px);opacity:0;transition:all .25s;pointer-events:none;box-shadow:var(--shadow)}
#toast.show{transform:none;opacity:1}

/* ── Hamburger (mobile) ── */
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;font-size:18px;color:var(--text)}
@media(max-width:768px){
  #menuToggle{display:block}
  #sidebar{transform:translateX(-100%);transition:transform .25s}
  #sidebar.open{transform:none}
  #main{margin-left:0;padding:16px;padding-top:52px}
  .chart-grid{grid-template-columns:1fr}
}

/* ── Bar list ── */
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.bar-label{font-size:11px;color:var(--muted2);width:120px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.bar-fill{height:100%;border-radius:3px;width:0;transition:width 1s ease}
.bar-val{font-size:10px;color:var(--muted);font-family:var(--mono);width:24px;text-align:right}

/* ── Target / Arch note ── */
.arch-note{background:linear-gradient(135deg,rgba(56,139,253,.08),rgba(163,113,247,.08));border:1px solid rgba(56,139,253,.2);border-radius:var(--radius);padding:14px 16px;margin-bottom:14px;font-size:12px;line-height:1.6;color:var(--muted2)}
.arch-note strong{color:var(--accent)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<!-- ── Sidebar ── -->
<div id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🏛️</div>
    <div class="logo-title">Entra ID Architecture<br>Assessment</div>
    <div class="logo-sub">Enterprise Identity Review</div>
    <div class="ver-badge">v1.0 · __ASSESSMENT_DATE__</div>
  </div>

  <nav>
    <div class="nav-section">Assessment</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span>Overview</button>
    <button class="nav-btn" onclick="showPage('domains',this)"><span class="nav-icon">🗂️</span>Domain Results</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span>Findings</button>
    <button class="nav-btn" onclick="showPage('roadmap',this)"><span class="nav-icon">🗺️</span>Roadmap</button>
    <div class="nav-section">Details</div>
    <button class="nav-btn" onclick="showPage('architecture',this)"><span class="nav-icon">🎯</span>Architecture Model</button>
  </nav>

  <div class="theme-toggle">
    <div class="theme-pill">
      <div class="theme-opt active" id="theme-dark"  onclick="setTheme('dark')">🌙 Dark</div>
      <div class="theme-opt"        id="theme-light" onclick="setTheme('light')">☀️ Light</div>
    </div>
  </div>

  <div class="sidebar-footer">
    Tenant: __TENANT_NAME__<br>
    ID: <span style="font-family:var(--mono);font-size:9px">__TENANT_ID__</span><br><br>
    <span class="kbd">Esc</span> close drawer &nbsp;
    <span class="kbd">/</span> search
  </div>
</div>

<!-- ── Main ── -->
<div id="main">

  <!-- ══ Overview ══════════════════════════════════════════════════════════ -->
  <div class="page active" id="page-overview">
    <div class="page-header">
      <h1>🏛️ Entra ID Architecture Assessment</h1>
      <p>Tenant: <strong>__TENANT_NAME__</strong> &nbsp;·&nbsp; Assessment date: __ASSESSMENT_DATE__ &nbsp;·&nbsp; Total findings: __TOTAL_FINDINGS__</p>
    </div>

    <!-- Maturity Ring -->
    <div class="health-card">
      <div class="health-ring-wrap">
        <svg viewBox="0 0 128 128" width="128" height="128">
          <circle class="health-ring-bg" cx="64" cy="64" r="54"/>
          <circle class="health-ring-fill" id="ringFill" cx="64" cy="64" r="54"
            stroke="__RING_COLOR__"
            stroke-dasharray="__RING_DASH__ __RING_GAP__"/>
        </svg>
        <div class="ring-label">
          <div class="ring-val" style="color:__RING_COLOR__">__OVERALL_SCORE__</div>
          <div class="ring-sub">/ 5.0</div>
        </div>
      </div>
      <div class="health-info">
        <h2>Overall Maturity: __OVERALL_LABEL__</h2>
        <p>Your Entra ID tenant architecture has been assessed across 10 domains against the Microsoft Identity Reference Architecture and Zero Trust principles. The overall maturity score represents the weighted average across all domains.</p>
        <div class="maturity-scale">
          <div class="ms-pill" style="color:#f85149;border-color:#f85149">1 · Initial</div>
          <div class="ms-pill" style="color:#d29922;border-color:#d29922">2 · Developing</div>
          <div class="ms-pill" style="color:#388bfd;border-color:#388bfd">3 · Defined</div>
          <div class="ms-pill" style="color:#39c5cf;border-color:#39c5cf">4 · Managed</div>
          <div class="ms-pill" style="color:#3fb950;border-color:#3fb950">5 · Optimised</div>
        </div>
      </div>
    </div>

    <!-- Risk Summary Cards -->
    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-label">Critical Findings</div>
        <div class="stat-value" style="color:var(--red)">__TOTAL_CRITICAL__</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-label">High Findings</div>
        <div class="stat-value" style="color:var(--amber)">__TOTAL_HIGH__</div>
        <div class="stat-sub">Address within 30 days</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-label">Medium Findings</div>
        <div class="stat-value" style="color:var(--accent)">__TOTAL_MEDIUM__</div>
        <div class="stat-sub">Address within 60 days</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-label">Low / Info</div>
        <div class="stat-value" style="color:var(--green)">__TOTAL_LOW__</div>
        <div class="stat-sub">Strategic improvements</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-label">Domains Assessed</div>
        <div class="stat-value" style="color:var(--accent3)">10</div>
        <div class="stat-sub">Identity architecture domains</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-label">Total Findings</div>
        <div class="stat-value" style="color:var(--accent2)">__TOTAL_FINDINGS__</div>
        <div class="stat-sub">Evidence-based checks</div>
      </div>
    </div>

    <!-- Domain Maturity Bars -->
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-header"><span class="panel-title">Domain Maturity Scores</span></div>
        <div id="domainBars"></div>
      </div>
      <div class="panel">
        <div class="panel-header"><span class="panel-title">Risk Distribution by Domain</span></div>
        <div id="riskMatrix"></div>
      </div>
    </div>

    <!-- Arch note -->
    <div class="arch-note">
      <strong>Architecture Assessment Model</strong> — This report follows the pattern:
      <em>Business Problem → Current State → Gap/Risk → Target State → Transition → Success Metrics</em>.
      Maturity levels range from <strong>1 (Initial)</strong> through <strong>5 (Optimised)</strong>.
      Findings are prioritised by business impact, blast radius, and privilege exposure — not merely by configuration deviation.
    </div>
  </div>

  <!-- ══ Domain Results ════════════════════════════════════════════════════ -->
  <div class="page" id="page-domains">
    <div class="page-header">
      <h1>🗂️ Domain Results</h1>
      <p>Architecture maturity by domain. Click a domain card to explore findings for that domain.</p>
    </div>
    <div class="domain-grid" id="domainGrid"></div>
  </div>

  <!-- ══ Findings ══════════════════════════════════════════════════════════ -->
  <div class="page" id="page-findings">
    <div class="page-header">
      <h1>🔍 Findings</h1>
      <p>All evidence-based architecture findings, searchable and filterable. Click any row for full detail.</p>
    </div>

    <div class="toolbar">
      <div class="search-wrap">
        <span class="search-icon">🔍</span>
        <input type="text" id="findSearch" placeholder="Search findings..." oninput="filterFindings()">
      </div>
      <div class="filter-pills">
        <div class="fpill fpill-all active"    onclick="setRiskFilter('All',this)">All</div>
        <div class="fpill fpill-crit"           onclick="setRiskFilter('Critical',this)">🔴 Critical</div>
        <div class="fpill fpill-high"           onclick="setRiskFilter('High',this)">🟠 High</div>
        <div class="fpill fpill-medium"         onclick="setRiskFilter('Medium',this)">🔵 Medium</div>
        <div class="fpill fpill-low"            onclick="setRiskFilter('Low',this)">🟢 Low/Info</div>
      </div>
      <button class="pg-btn" onclick="exportFindingsCSV()" style="white-space:nowrap">⬇ Export CSV</button>
    </div>

    <div class="panel" style="padding:0;overflow:hidden">
      <table id="findingsTable">
        <thead>
          <tr>
            <th onclick="sortFindings('risk')" id="th-risk">Risk <span class="sort-arrow">↕</span></th>
            <th onclick="sortFindings('domainName')" id="th-domain">Domain <span class="sort-arrow">↕</span></th>
            <th onclick="sortFindings('title')" id="th-title">Finding <span class="sort-arrow">↕</span></th>
            <th onclick="sortFindings('roadmapPhase')" id="th-phase">Phase <span class="sort-arrow">↕</span></th>
          </tr>
        </thead>
        <tbody id="findingsTbody"></tbody>
      </table>
    </div>
    <div class="pagination" id="findingsPagination"></div>
  </div>

  <!-- ══ Roadmap ═══════════════════════════════════════════════════════════ -->
  <div class="page" id="page-roadmap">
    <div class="page-header">
      <h1>🗺️ Remediation Roadmap</h1>
      <p>Prioritised action plan based on business impact, risk severity, and architectural dependencies.</p>
    </div>

    <div class="arch-note">
      <strong>Roadmap principle:</strong> Findings are sequenced by security risk reduction and architectural dependency, not just severity. Foundational controls (legacy auth block, break-glass) are placed in 0–30 days regardless of individual finding risk, because they unlock all downstream security investments.
    </div>

    <div class="roadmap-grid" id="roadmapGrid"></div>
  </div>

  <!-- ══ Architecture Model ════════════════════════════════════════════════ -->
  <div class="page" id="page-architecture">
    <div class="page-header">
      <h1>🎯 Architecture Model</h1>
      <p>Reference architecture, maturity model definition, and assessment methodology.</p>
    </div>

    <div class="panel">
      <div class="panel-header"><span class="panel-title">Five-Stage Identity Architecture Maturity Model</span></div>
      <div style="display:grid;gap:12px">
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #f85149">
          <div style="font-size:24px;font-weight:900;color:#f85149;font-family:var(--mono)">1</div>
          <div><div style="font-weight:700;margin-bottom:3px">Initial</div><div style="font-size:12px;color:var(--muted2)">Ad-hoc, undocumented, reactive. Identity controls exist by accident not design. No policy, no process, no measurement. Security incidents drive all changes.</div></div>
        </div>
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #d29922">
          <div style="font-size:24px;font-weight:900;color:#d29922;font-family:var(--mono)">2</div>
          <div><div style="font-weight:700;margin-bottom:3px">Developing</div><div style="font-size:12px;color:var(--muted2)">Partial controls inconsistently applied. Key protections (MFA, CA) exist for some users or apps but not all. Manual processes dominate. Growing awareness but not yet architecture.</div></div>
        </div>
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #388bfd">
          <div style="font-size:24px;font-weight:900;color:#388bfd;font-family:var(--mono)">3</div>
          <div><div style="font-weight:700;margin-bottom:3px">Defined</div><div style="font-size:12px;color:var(--muted2)">Controls exist, are documented, and are applied consistently for core scenarios. Policies are in place. Conditional Access baseline enforced. PIM adopted for some roles. Not yet measured or continuously validated.</div></div>
        </div>
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #39c5cf">
          <div style="font-size:24px;font-weight:900;color:#39c5cf;font-family:var(--mono)">4</div>
          <div><div style="font-weight:700;margin-bottom:3px">Managed</div><div style="font-size:12px;color:var(--muted2)">Consistently enforced, measured, and reviewed. Controls cover all users, apps, and risk scenarios. Access reviews active. Logs in SIEM. Metrics tracked. Governance integrated with business processes. Deviations detected automatically.</div></div>
        </div>
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #3fb950">
          <div style="font-size:24px;font-weight:900;color:#3fb950;font-family:var(--mono)">5</div>
          <div><div style="font-weight:700;margin-bottom:3px">Optimised</div><div style="font-size:12px;color:var(--muted2)">Continuously improved, automated, and Zero Trust-aligned. Phishing-resistant MFA universal. PIM JIT 100%. Workload Identity Federation standard. ML-driven risk detection. Identity governance fully automated via Lifecycle Workflows and Entitlement Management.</div></div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><span class="panel-title">Assessment Domains & Scope</span></div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px" id="archDomainList"></div>
    </div>

    <div class="panel">
      <div class="panel-header"><span class="panel-title">Assessment Methodology</span></div>
      <div style="font-size:12px;color:var(--muted2);line-height:1.7">
        <p style="margin-bottom:10px">Each check follows the architectural thinking model: <strong style="color:var(--text)">Evidence → Current State → Gap/Risk → Target State → Recommendation → Roadmap Phase</strong></p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Evidence:</strong> Raw data retrieved from Microsoft Graph API — configuration values, counts, policy states.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Current State:</strong> Interpretation of the evidence in architectural terms — what is true about the tenant today.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Gap:</strong> The delta between current state and the enterprise reference architecture target.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Risk Rating:</strong> Prioritised by business impact, blast radius (tenant-wide vs scoped), privilege exposure, and probability of exploitation.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Target State:</strong> The architectural end-state aligned to Zero Trust and Microsoft Identity Reference Architecture.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Recommendation:</strong> Actionable, technology-specific remediation steps.</p>
        <p><strong style="color:var(--text)">Roadmap Phase:</strong> Sequenced by dependency and risk reduction: 0–30 days (critical/foundational), 31–60 days (high/structural), 61–90 days (medium/operational), Strategic (continuous improvement).</p>
      </div>
    </div>
  </div>

</div><!-- /#main -->

<!-- ── Detail Drawer ── -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDrawer()"></div>
  <div id="detailDrawer">
    <div class="drawer-header">
      <div class="drawer-title" id="drawerTitle"></div>
      <button class="drawer-close" onclick="closeDrawer()">✕</button>
    </div>
    <div class="drawer-chips" id="drawerChips"></div>
    <div class="drawer-section"><div class="drawer-label">Evidence</div><div class="drawer-value" id="drawerEvidence"></div></div>
    <div class="drawer-section"><div class="drawer-label">Current State</div><div class="drawer-value" id="drawerCurrentState"></div></div>
    <div class="drawer-section"><div class="drawer-label">Gap / Risk</div><div class="drawer-value" id="drawerGap"></div></div>
    <div class="drawer-section"><div class="drawer-label">Business Impact</div><div class="drawer-value" id="drawerImpact"></div></div>
    <div class="drawer-section"><div class="drawer-label">Target State</div><div class="drawer-value" id="drawerTarget"></div></div>
    <div class="drawer-section"><div class="drawer-label">Recommendation</div><div class="drawer-value" id="drawerRec"></div></div>
    <div class="drawer-section"><div class="drawer-label">Roadmap Phase</div><div class="drawer-value" id="drawerPhase"></div></div>
    <div class="drawer-nav">
      <button onclick="navDrawer(-1)">← Previous</button>
      <button onclick="navDrawer(1)">Next →</button>
      <div class="drawer-count" id="drawerCount"></div>
    </div>
  </div>
</div>

<!-- ── Toast ── -->
<div id="toast"></div>

<script>
// ── Data ─────────────────────────────────────────────────────────────────────
const DOMAINS   = __DOMAINS_JSON__;
const FINDINGS  = __FINDINGS_JSON__;

// ── Utilities ─────────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
function showToast(msg,icon='✅'){const t=document.getElementById('toast');t.textContent=(icon?icon+' ':'')+msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800);}

// ── Navigation ────────────────────────────────────────────────────────────────
function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn) btn.classList.add('active');
  if(id==='findings') setTimeout(renderFindingsTable,50);
  if(id==='roadmap')  renderRoadmap();
  if(id==='domains')  renderDomainGrid();
  if(id==='architecture') renderArchDomainList();
}

// ── Theme ─────────────────────────────────────────────────────────────────────
function setTheme(t){
  document.body.classList.toggle('light-theme',t==='light');
  document.getElementById('theme-dark').classList.toggle('active',t==='dark');
  document.getElementById('theme-light').classList.toggle('active',t==='light');
  localStorage.setItem('ea-theme',t);
}
(function(){const t=localStorage.getItem('ea-theme');if(t)setTheme(t);})();

// ── Overview ─────────────────────────────────────────────────────────────────
(function renderOverview(){
  // Domain bars
  const barContainer = document.getElementById('domainBars');
  DOMAINS.forEach(d=>{
    const pct = (d.maturityScore/5)*100;
    barContainer.innerHTML += `<div class="bar-row">
      <div class="bar-label" title="${escH(d.name)}">${escH(d.icon)} ${escH(d.name)}</div>
      <div class="bar-track"><div class="bar-fill" data-pct="${pct}" style="background:${escH(d.maturityColor)}"></div></div>
      <div class="bar-val">${d.maturityScore}</div>
    </div>`;
  });

  // Risk matrix
  const rmContainer = document.getElementById('riskMatrix');
  DOMAINS.forEach(d=>{
    const total = d.critical+d.high+d.medium+d.low;
    rmContainer.innerHTML += `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:11px">
      <span style="width:20px;text-align:center">${escH(d.icon)}</span>
      <span style="width:110px;color:var(--muted2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escH(d.name)}</span>
      <div style="display:flex;gap:3px">
        ${d.critical>0?`<span class="risk-chip rc-critical">${d.critical}C</span>`:''}
        ${d.high>0    ?`<span class="risk-chip rc-high">${d.high}H</span>`:''}
        ${d.medium>0  ?`<span class="risk-chip rc-medium">${d.medium}M</span>`:''}
        ${d.low>0     ?`<span class="risk-chip rc-low">${d.low}L</span>`:''}
        ${total===0   ?`<span class="risk-chip rc-info">✓</span>`:''}
      </div>
    </div>`;
  });

  // Animate bars
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width = el.getAttribute('data-pct')+'%';
    });
  });
})();

// ── Domain Grid ───────────────────────────────────────────────────────────────
function renderDomainGrid(){
  const grid = document.getElementById('domainGrid');
  if(grid.innerHTML) return;
  DOMAINS.forEach(d=>{
    const pct = (d.maturityScore/5)*100;
    grid.innerHTML += `<div class="domain-card" style="border-left-color:${escH(d.maturityColor)}" onclick="openDomainFindings('${escH(d.id)}')">
      <div class="domain-card-header">
        <span class="domain-icon">${escH(d.icon)}</span>
        <span class="domain-name">${escH(d.name)}</span>
        <span class="maturity-badge" style="color:${escH(d.maturityColor)};border:1px solid ${escH(d.maturityColor)}">${d.maturityScore} ${escH(d.maturityLabel)}</span>
      </div>
      <div class="domain-score-bar"><div class="domain-score-fill" style="width:${pct}%;background:${escH(d.maturityColor)}"></div></div>
      <div style="font-size:11px;color:var(--muted2);margin-bottom:10px;line-height:1.4">${escH(d.currentStateSummary)}</div>
      <div class="domain-risk-chips">
        ${d.critical>0?`<span class="risk-chip rc-critical">${d.critical} Critical</span>`:''}
        ${d.high>0    ?`<span class="risk-chip rc-high">${d.high} High</span>`:''}
        ${d.medium>0  ?`<span class="risk-chip rc-medium">${d.medium} Medium</span>`:''}
        ${d.low>0     ?`<span class="risk-chip rc-low">${d.low} Low</span>`:''}
        ${(d.critical+d.high+d.medium+d.low)===0?`<span class="risk-chip rc-info">✓ No gaps</span>`:''}
      </div>
    </div>`;
  });
}
function openDomainFindings(domainId){
  domainFilter = domainId;
  showPage('findings', document.querySelector('.nav-btn:nth-child(4)'));
  setTimeout(()=>{
    filteredFindings = FINDINGS.filter(f=>f.domainId===domainId);
    findingsPage=0;
    renderFindingsTable();
  },80);
}

// ── Findings Table ────────────────────────────────────────────────────────────
let filteredFindings = [...FINDINGS];
let findingsPage = 0;
const PAGE_SIZE  = 15;
let sortCol = 'risk';
let sortDir = 1;
let riskFilter = 'All';
let domainFilter = null;

const RISK_ORDER = {Critical:0,High:1,Medium:2,Low:3,Info:4};

function setRiskFilter(r, el){
  riskFilter = r;
  domainFilter = null;
  document.querySelectorAll('.fpill').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  filterFindings();
}
function filterFindings(){
  const q = (document.getElementById('findSearch').value||'').toLowerCase();
  filteredFindings = FINDINGS.filter(f=>{
    const rMatch = riskFilter==='All'||(riskFilter==='Low'?f.risk==='Low'||f.risk==='Info':f.risk===riskFilter);
    const dMatch = !domainFilter || f.domainId===domainFilter;
    const qMatch = !q || f.title.toLowerCase().includes(q)||f.domainName.toLowerCase().includes(q)||f.checkId.toLowerCase().includes(q);
    return rMatch && dMatch && qMatch;
  });
  sortFindingsData();
  findingsPage=0;
  renderFindingsTable();
}
function sortFindings(col){
  if(sortCol===col){sortDir*=-1;}else{sortCol=col;sortDir=1;}
  document.querySelectorAll('th[id^="th-"]').forEach(t=>t.classList.remove('sort-active'));
  document.getElementById('th-'+col).classList.add('sort-active');
  sortFindingsData();
  renderFindingsTable();
}
function sortFindingsData(){
  filteredFindings.sort((a,b)=>{
    let av=a[sortCol]||'', bv=b[sortCol]||'';
    if(sortCol==='risk'){av=RISK_ORDER[a.risk]??9;bv=RISK_ORDER[b.risk]??9;return sortDir*(av-bv);}
    if(sortCol==='roadmapPhase'){const ord={'0-30 Days':0,'31-60 Days':1,'61-90 Days':2,'Strategic':3};av=ord[av]??9;bv=ord[bv]??9;return sortDir*(av-bv);}
    return sortDir*String(av).localeCompare(String(bv));
  });
}
function renderFindingsTable(){
  sortFindingsData();
  const tbody = document.getElementById('findingsTbody');
  const start = findingsPage*PAGE_SIZE;
  const slice = filteredFindings.slice(start,start+PAGE_SIZE);
  tbody.innerHTML = slice.map((f,i)=>`<tr onclick="openFinding(${start+i})" style="cursor:pointer">
    <td><span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span></td>
    <td><span class="domain-tag">${escH(f.domainId)}</span> <span style="font-size:10px;color:var(--muted)">${escH(f.domainName)}</span></td>
    <td style="max-width:340px">${escH(f.title)}</td>
    <td><span class="phase-badge">${escH(f.roadmapPhase)}</span></td>
  </tr>`).join('');

  // Pagination
  const totalPages = Math.ceil(filteredFindings.length/PAGE_SIZE);
  const pg = document.getElementById('findingsPagination');
  let html = '';
  if(totalPages>1){
    html += `<button class="pg-btn" onclick="goPage(${findingsPage-1})" ${findingsPage===0?'disabled':''}>‹</button>`;
    for(let p=0;p<totalPages;p++){html+=`<button class="pg-btn${p===findingsPage?' active':''}" onclick="goPage(${p})">${p+1}</button>`;}
    html += `<button class="pg-btn" onclick="goPage(${findingsPage+1})" ${findingsPage===totalPages-1?'disabled':''}>›</button>`;
  }
  html += `<span class="pg-info">${filteredFindings.length} finding${filteredFindings.length!==1?'s':''}</span>`;
  pg.innerHTML = html;
}
function goPage(p){
  const totalPages=Math.ceil(filteredFindings.length/PAGE_SIZE);
  if(p<0||p>=totalPages)return;
  findingsPage=p;
  renderFindingsTable();
}

// ── Detail Drawer ─────────────────────────────────────────────────────────────
let currentDrawerIndex = -1;
let drawerList = [];

function openFinding(idx){
  drawerList = filteredFindings;
  currentDrawerIndex = idx;
  populateDrawer(drawerList[idx]);
  document.getElementById('detailPanel').classList.add('open');
}
function populateDrawer(f){
  if(!f) return;
  const rCol = {Critical:'#f85149',High:'#d29922',Medium:'#388bfd',Low:'#3fb950',Info:'#7d8590'}[f.risk]||'#7d8590';
  const phaseColors={'0-30 Days':'#f85149','31-60 Days':'#d29922','61-90 Days':'#388bfd','Strategic':'#3fb950'};
  document.getElementById('drawerTitle').textContent = f.title;
  document.getElementById('drawerChips').innerHTML =
    `<span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span>`+
    `<span class="domain-tag">${escH(f.domainId)} · ${escH(f.domainName)}</span>`+
    `<span style="font-size:10px;padding:2px 8px;border-radius:12px;background:rgba(255,255,255,.06);color:${phaseColors[f.roadmapPhase]||'var(--muted)'};font-family:var(--mono)">${escH(f.roadmapPhase)}</span>`+
    `<span style="font-size:10px;color:var(--muted);font-family:var(--mono)">${escH(f.checkId)}</span>`;
  document.getElementById('drawerEvidence').textContent     = f.evidence;
  document.getElementById('drawerCurrentState').textContent = f.currentState;
  document.getElementById('drawerGap').textContent          = f.gap;
  document.getElementById('drawerImpact').textContent       = f.businessImpact;
  document.getElementById('drawerTarget').textContent       = f.targetState;
  document.getElementById('drawerRec').textContent          = f.recommendation;
  document.getElementById('drawerPhase').textContent        = f.roadmapPhase;
  document.getElementById('drawerCount').textContent        = `${currentDrawerIndex+1} / ${drawerList.length}`;
}
function navDrawer(dir){
  const next=currentDrawerIndex+dir;
  if(next<0||next>=drawerList.length)return;
  currentDrawerIndex=next;
  populateDrawer(drawerList[currentDrawerIndex]);
}
function closeDrawer(){document.getElementById('detailPanel').classList.remove('open');}

// ── Roadmap ───────────────────────────────────────────────────────────────────
function renderRoadmap(){
  const grid=document.getElementById('roadmapGrid');
  if(grid.innerHTML) return;
  const phases=['0-30 Days','31-60 Days','61-90 Days','Strategic'];
  const phaseIcons={'0-30 Days':'🚨','31-60 Days':'⚡','61-90 Days':'📈','Strategic':'🎯'};
  const phaseColors={'0-30 Days':'var(--red)','31-60 Days':'var(--amber)','61-90 Days':'var(--accent)','Strategic':'var(--green)'};
  phases.forEach(phase=>{
    const items=FINDINGS.filter(f=>f.roadmapPhase===phase&&f.risk!=='Info');
    const col=document.createElement('div');col.className='roadmap-col';
    col.innerHTML=`<div class="roadmap-col-header">
      <span style="font-size:18px">${phaseIcons[phase]}</span>
      <span class="roadmap-col-label" style="color:${phaseColors[phase]}">${escH(phase)}</span>
      <span class="roadmap-count">${items.length}</span>
    </div>`;
    items.forEach((f,i)=>{
      const rCol={Critical:'var(--red)',High:'var(--amber)',Medium:'var(--accent)',Low:'var(--green)'}[f.risk]||'var(--muted)';
      const idx=FINDINGS.indexOf(f);
      col.innerHTML+=`<div class="roadmap-item" onclick="openFinding(${idx})">
        <div class="roadmap-item-title">${escH(f.title)}</div>
        <div class="roadmap-item-meta">
          <span class="risk-badge rb-${escH(f.risk)}" style="font-size:9px">${escH(f.risk)}</span>
          <span class="domain-tag" style="font-size:9px">${escH(f.domainId)}</span>
        </div>
      </div>`;
    });
    grid.appendChild(col);
  });
}

// ── Architecture Domain List ──────────────────────────────────────────────────
function renderArchDomainList(){
  const c=document.getElementById('archDomainList');
  if(c.innerHTML) return;
  DOMAINS.forEach(d=>{
    c.innerHTML+=`<div style="padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:3px solid ${escH(d.maturityColor)}">
      <div style="font-size:13px;font-weight:700;margin-bottom:4px">${escH(d.icon)} ${escH(d.name)}</div>
      <div style="font-size:11px;color:var(--muted2);margin-bottom:6px">${escH(d.currentStateSummary)}</div>
      <div style="font-size:10px;color:var(--accent);font-style:italic">Target: ${escH(d.targetStateSummary)}</div>
    </div>`;
  });
}

// ── CSV Export ────────────────────────────────────────────────────────────────
function exportFindingsCSV(){
  const fields=['domainId','domainName','checkId','title','risk','roadmapPhase','evidence','currentState','gap','businessImpact','targetState','recommendation'];
  const header=fields.join(',');
  const rows=filteredFindings.map(f=>fields.map(k=>'"'+(String(f[k]||'')).replace(/"/g,'""')+'"').join(','));
  const csv=[header,...rows].join('\r\n');
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download='EntraArchitectureFindings.csv';
  a.click();
  showToast('Findings exported as CSV');
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='/'&&!e.target.matches('input')){
    e.preventDefault();
    const s=document.getElementById('findSearch');if(s)s.focus();
  }
  if(document.getElementById('detailPanel').classList.contains('open')){
    if(e.key==='ArrowLeft') navDrawer(-1);
    if(e.key==='ArrowRight') navDrawer(1);
  }
});

// ── Initial sort ──────────────────────────────────────────────────────────────
filterFindings();
</script>
</body>
</html>
'@

        # ── Inject data ───────────────────────────────────────────────────────────
        $ringColorForScore = $script:MaturityColors[[int][Math]::Round($OverallMaturity)]
        if (-not $ringColorForScore) { $ringColorForScore = "#f85149" }

        $html = $html `
            -replace '__TENANT_NAME__', $TenantName `
            -replace '__TENANT_ID__', $TenantId `
            -replace '__ASSESSMENT_DATE__', $AssessmentDate `
            -replace '__OVERALL_SCORE__', $OverallMaturity `
            -replace '__OVERALL_LABEL__', $overallLabel `
            -replace '__TOTAL_CRITICAL__', $totalCritical `
            -replace '__TOTAL_HIGH__', $totalHigh `
            -replace '__TOTAL_MEDIUM__', $totalMedium `
            -replace '__TOTAL_LOW__', ($totalLow + ($script:Findings | Where-Object { $_.Risk -eq "Info" }).Count) `
            -replace '__TOTAL_FINDINGS__', $totalFindings `
            -replace '__RING_COLOR__', $ringColorForScore `
            -replace '__RING_DASH__', $ringDash `
            -replace '__RING_GAP__', $ringGap `
            -replace '__DOMAINS_JSON__', $DomainsJson `
            -replace '__FINDINGS_JSON__', $FindingsJson

        $html | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
    }

    #endregion

    #region ── JSON Export ────────────────────────────────────────────────────────

    Function Export-AssessmentJson {
        param (
            [string]$TenantName,
            [string]$TenantId,
            [double]$OverallMaturity,
            [string]$AssessmentDate,
            [string]$OutputFilePath
        )

        $exportObj = [PSCustomObject]@{
            schemaVersion    = "1.0"
            assessmentTool   = "Get-EntraTenantArchitectureAssessment"
            assessmentDate   = $AssessmentDate
            tenantName       = $TenantName
            tenantId         = $TenantId
            overallMaturity  = $OverallMaturity
            overallLabel     = $script:MaturityLabels[[int][Math]::Round($OverallMaturity)]
            totalFindings    = $script:Findings.Count
            criticalFindings = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
            highFindings     = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
            mediumFindings   = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count
            domains          = $script:Domains
            findings         = $script:Findings
        }

        $exportObj | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
    }

    #endregion

    #region ── Script Execution ───────────────────────────────────────────────────

    Clear-Host

    # ── Banner ────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║      Entra ID Tenant Architecture Assessment  v1.0           ║" -ForegroundColor Cyan
    Write-Host "  ║      Enterprise Identity Architecture Review                 ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $scriptStartTime = Get-Date
    Write-Host "  🕐 Started  : $($scriptStartTime.ToString('dd-MMM-yyyy  hh:mm:ss tt'))" -ForegroundColor Gray
    Write-Host "  📂 Output   : $OutputPath" -ForegroundColor Gray
    Write-Host "  🔑 Auth Mode: $($PSCmdlet.ParameterSetName)" -ForegroundColor Gray
    Write-Host ""

    # ── Ensure output path exists ─────────────────────────────────────────────────
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Host "  📁 Created output directory: $OutputPath" -ForegroundColor Gray
    }

    # ── Step 1: Authentication ────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 1  ›  Authenticating to Entra ID                     │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $global:AuthMode = $PSCmdlet.ParameterSetName

    if ($global:AuthMode -eq "ClientCredentials") {
        Write-Host "  ⏳ Requesting access token (Client Credentials)..." -ForegroundColor Yellow
        $token = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId -RefreshInterval 15

        if (-not $token) {
            Write-Error "  ✖ Failed to obtain access token. Verify ClientId, ClientSecret, and TenantId."
            return
        }
        $global:accessToken = $token
        $global:TenantId = $TenantId
        Write-Host "  ✅ Client Credentials authentication successful." -ForegroundColor Green
    }
    else {
        # BYOT
        Write-Host "  ⏳ Using provided access token (BYOT)..." -ForegroundColor Yellow
        $global:accessToken = $AccessToken
        $global:TenantId = $TenantId
        Write-Host "  ✅ BYOT token accepted." -ForegroundColor Green
    }

    Write-Host ""

    # ── Step 1.1: Validate Required Graph Permissions ─────────────────────────────
    Write-Host "  🔍 Validating required Microsoft Graph permissions..." -ForegroundColor Yellow

    $requiredGraphPermissions = @(
        "Directory.Read.All"
        "Policy.Read.All"
        "Application.Read.All"
        "AuditLog.Read.All"
        "RoleManagement.Read.Directory"
        "IdentityRiskyUser.Read.All"
        "UserAuthenticationMethod.Read.All"
        "Reports.Read.All"
        "AccessReview.Read.All"
    )

    $permissionCheck = Test-GraphTokenPermissions `
        -AccessToken $global:accessToken `
        -RequiredPermissions $requiredGraphPermissions

    if (-not $permissionCheck.Valid) {
        Write-Host ""
        Write-Host "  ⚠️  Warning: Some required Microsoft Graph permissions are missing." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Missing permissions:" -ForegroundColor Yellow

        foreach ($permission in $permissionCheck.MissingPermissions) {
            Write-Host "    • $permission" -ForegroundColor Yellow
        }

        Write-Host ""
        Write-Host "  Assessment will continue with the available permissions." -ForegroundColor Yellow
        Write-Host "  Some assessment values or findings may not be available." -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host "  ✅ All required Microsoft Graph permissions validated." -ForegroundColor Green
    }

    Write-Host ""

    # ── Step 2: Collect Tenant Baseline ──────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 2  ›  Collecting Tenant Baseline                     │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  ⏳ Retrieving tenant organisation data..." -ForegroundColor Yellow

    $orgData = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/organization?`$select=id,displayName,verifiedDomains,assignedPlans,createdDateTime"
    $tenantName = "Unknown"
    if ($orgData -and $orgData.value -and $orgData.value.Count -gt 0) {
        $tenantName = $orgData.value[0].displayName
    }
    elseif ($orgData -and $orgData.displayName) {
        $tenantName = $orgData.displayName
    }

    Write-Host "  ✅ Tenant: $tenantName ($TenantId)" -ForegroundColor Green
    Write-Host ""

    # ── Step 3: Domain Assessments ───────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 3  ›  Running Domain Assessments (10 Domains)        │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $tenantInfoObj = [PSCustomObject]@{ TenantName = $tenantName; TenantId = $TenantId }

    Invoke-Domain1-AdminBoundaries  -TenantInfo $tenantInfoObj
    Invoke-Domain2-PrivilegedAccess
    Invoke-Domain3-Authentication
    Invoke-Domain4-ConditionalAccess
    Invoke-Domain5-AppGovernance
    Invoke-Domain6-WorkloadIdentities
    Invoke-Domain7-ExternalIdentities
    Invoke-Domain8-EmergencyAccess
    Invoke-Domain9-Monitoring
    Invoke-Domain10-Governance

    Write-Host ""
    Write-Host "  ✅ All 10 domain assessments complete." -ForegroundColor Green
    Write-Host ""

    # ── Step 4: Score ─────────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 4  ›  Computing Overall Maturity Score               │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $overallMaturity = Get-OverallMaturityScore
    $overallLabel = $script:MaturityLabels[[int][Math]::Round($overallMaturity)]
    $totalCritical = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
    $totalHigh = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
    $totalMedium = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count

    Write-Host "  📊 Overall Maturity: $overallMaturity / 5.0 ($overallLabel)" -ForegroundColor Cyan
    Write-Host "  🔴 Critical: $totalCritical  |  🟠 High: $totalHigh  |  🔵 Medium: $totalMedium" -ForegroundColor Gray
    Write-Host ""

    # ── Step 5: Export ─────────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 5  ›  Generating Reports                             │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $htmlPath = Join-Path $OutputPath "EntraTenantArchitectureAssessment_$timestamp.html"
    $jsonPath = Join-Path $OutputPath "EntraTenantArchitectureAssessment_$timestamp.json"
    $assessDate = (Get-Date).ToString("dd MMM yyyy HH:mm")

    Write-Host "  ⏳ Building HTML dashboard..." -ForegroundColor Yellow
    $domainsJson = Build-DomainsJson
    $findingsJson = Build-FindingsJson

    Generate-HtmlDashboard `
        -TenantName    $tenantName `
        -TenantId      $TenantId `
        -OverallMaturity $overallMaturity `
        -AssessmentDate $assessDate `
        -DomainsJson   $domainsJson `
        -FindingsJson  $findingsJson `
        -OutputFilePath $htmlPath

    Write-Host "  ✅ HTML dashboard written → $htmlPath" -ForegroundColor Green

    Write-Host "  ⏳ Exporting JSON assessment..." -ForegroundColor Yellow
    Export-AssessmentJson `
        -TenantName    $tenantName `
        -TenantId      $TenantId `
        -OverallMaturity $overallMaturity `
        -AssessmentDate $assessDate `
        -OutputFilePath $jsonPath

    Write-Host "  ✅ JSON export written → $jsonPath" -ForegroundColor Green
    Write-Host ""

    # ── Execution Summary ─────────────────────────────────────────────────────────
    $scriptEndTime = Get-Date
    $executionTime = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime

    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                    ASSESSMENT SUMMARY                        ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  🏛️  Tenant                : $($tenantName.PadRight(30))║" -ForegroundColor White
    Write-Host "  ║  📊 Overall Maturity       : $("$overallMaturity / 5.0 ($overallLabel)".PadRight(30))║" -ForegroundColor Cyan
    Write-Host "  ║  🔴 Critical Findings      : $($totalCritical.ToString().PadRight(30))║" -ForegroundColor Red
    Write-Host "  ║  🟠 High Findings          : $($totalHigh.ToString().PadRight(30))║" -ForegroundColor Yellow
    Write-Host "  ║  🔵 Medium Findings        : $($totalMedium.ToString().PadRight(30))║" -ForegroundColor Blue
    Write-Host "  ║  📋 Total Findings         : $(($script:Findings.Count).ToString().PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  🕐 Started               : $($scriptStartTime.ToString('hh:mm:ss tt').PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  🕑 Ended                 : $($scriptEndTime.ToString('hh:mm:ss tt').PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  ⏱️ Duration               : $($executionTime.ToString('hh\:mm\:ss').PadRight(30))║" -ForegroundColor Yellow
    Write-Host "  ║  🌐 HTML Dashboard        : $(('...' + $htmlPath.Substring([Math]::Max(0,$htmlPath.Length-27))).PadRight(30))║" -ForegroundColor Green
    Write-Host "  ║  📄 JSON Export           : $(('...' + $jsonPath.Substring([Math]::Max(0,$jsonPath.Length-27))).PadRight(30))║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    #endregion
}
