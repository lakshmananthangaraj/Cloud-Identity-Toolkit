<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 23 August 2026
Modified-On  : 23 August 2026

.SYNOPSIS
    Assesses the Microsoft 365 tenant across the five Zero Trust pillars — Identity,
    Devices, Network, Data, and Applications — and produces pillar-level maturity
    scores with a board-ready risk narrative and actionable roadmap.

.DESCRIPTION
    This script connects to Microsoft Graph (BYOT or Client Credentials) and evaluates
    the tenant's Zero Trust readiness across the five foundational pillars defined in
    the Microsoft Zero Trust Framework:

        Pillar 1  — Identity        : MFA coverage, phishing-resistant auth, Conditional
                                      Access breadth, PIM coverage, risky users, and
                                      legacy authentication posture.

        Pillar 2  — Devices         : Device compliance policies, Intune enrolment
                                      coverage, Conditional Access device enforcement,
                                      Autopilot readiness, and stale device hygiene.

        Pillar 3  — Network         : Named locations defined, location-based CA controls,
                                      MCAS/Defender for Cloud Apps signals, continuous
                                      access evaluation, and network segmentation signals.

        Pillar 4  — Data            : Sensitivity labels published, DLP policies active,
                                      information protection coverage, privileged data
                                      access posture, and data governance signals.

        Pillar 5  — Applications    : Application permission hygiene (high-privilege app
                                      consent), OAuth app risk, app Conditional Access
                                      coverage, admin consent workflow, and service
                                      principal secret/credential hygiene.

    For each pillar the script follows this architectural thinking model:

        Context → Current State → Gaps & Risks → Target State → Transition
        Recommendations → Success Measures

    Maturity levels are assigned using a five-stage model:
        1 - Initial      : Ad-hoc, undocumented, reactive
        2 - Developing   : Partial controls, inconsistently applied
        3 - Defined      : Controls exist and documented but not fully enforced
        4 - Managed      : Consistently enforced, measured, and reviewed
        5 - Optimised    : Continuously improved, automated, Zero Trust-aligned

    Findings are prioritised by:
        - Business impact (data exfiltration, compliance, operational risk)
        - Security risk severity (Critical / High / Medium / Low)
        - Blast radius (tenant-wide vs scoped)
        - Privilege exposure (admin plane vs data plane)

    Output:
        - HTML interactive dashboard (light/dark theme, tabbed by pillar)
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
    Default: C:\Temp\ZeroTrustAssessment

.PARAMETER ShowHelp
    Displays a plain-language usage guide and exits immediately.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        HTML dashboard: <OutputPath>\ZeroTrustReadinessAssessment_<timestamp>.html
        JSON export   : <OutputPath>\ZeroTrustReadinessAssessment_<timestamp>.json

.EXAMPLE
    Invoke-ZeroTrustReadinessAssessment -ShowHelp

    Displays the friendly usage guide and exits.

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Invoke-ZeroTrustReadinessAssessment `
        -AuthMode     ClientCredentials `
        -ClientId     "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId     "f4310b4f-xxxx"

    Full Zero Trust assessment using app-only Client Credentials auth.

.EXAMPLE
    $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    Invoke-ZeroTrustReadinessAssessment `
        -AuthMode    BYOT `
        -AccessToken $token `
        -TenantId    "f4310b4f-xxxx"

    Full assessment using a pre-obtained bearer token (BYOT).

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Invoke-ZeroTrustReadinessAssessment `
        -AuthMode     ClientCredentials `
        -ClientId     "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId     "f4310b4f-xxxx" `
        -OutputPath   "D:\Reports\ZeroTrust"

    Assessment with a custom output directory.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (23-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. App Registration (Client Credentials mode) with admin-consented
           Application permissions:
               Directory.Read.All              (users, groups, devices, org)
               Policy.Read.All                 (Conditional Access, auth methods, DLP)
               Application.Read.All            (app registrations, service principals, OAuth)
               AuditLog.Read.All               (sign-in activity, audit logs)
               RoleManagement.Read.Directory   (PIM, role definitions, assignments)
               IdentityRiskyUser.Read.All      (Identity Protection risk state)
               UserAuthenticationMethod.Read.All (MFA registration coverage)
               DeviceManagementConfiguration.Read.All  (Intune compliance policies)
               DeviceManagementManagedDevices.Read.All (Intune device inventory)
               InformationProtectionPolicy.Read.All    (sensitivity labels, DLP policies)

        2. BYOT mode: the delegated or application token must carry the same
           scopes as above. Delegated tokens require the caller to be at minimum
           a Global Reader or Security Reader.

        3. Entra ID P1 minimum. P2 required for:
               - PIM eligible role detection
               - Identity Protection risky user data
               - Continuous Access Evaluation policy data

        4. Microsoft Intune licensed for Device pillar full coverage.
           Microsoft Purview Information Protection licensed for Data pillar.

        5. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  → Show help and exit if -ShowHelp
        Step 1  → Authenticate (BYOT or Client Credentials) + validate permissions
        Step 2  → Collect tenant baseline (org, licenses, domains)
        Step 3  → Run pillar assessments (Identity, Devices, Network, Data, Applications)
        Step 4  → Score pillars, compute overall Zero Trust readiness
        Step 5  → Build prioritised finding list with recommendations
        Step 6  → Generate roadmap (30/60/90-day + strategic)
        Step 7  → Export HTML dashboard + JSON

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the /beta Graph endpoint for several capabilities. Beta APIs are
          subject to change.
        - PIM and Identity Protection data require Entra ID P2. Pillar checks for
          those features degrade gracefully to "Insufficient Data" when P2 is absent.
        - Conditional Access evaluation is configuration-based; it does not simulate
          runtime policy evaluation against real sign-in sessions.
        - DLP and sensitivity label checks depend on Purview / MIP licensing.
          Missing license results in graceful degradation, not script failure.
        - Device compliance checks require Intune enrollment and appropriate licensing.
          Tenants without Intune will receive partial scores for the Devices pillar.
        - Large tenants (>50 000 users/devices) may experience longer run times due
          to Graph pagination across multiple pillars.
        - Network pillar checks are indicator-based (named locations, MCAS signals)
          and do not inspect actual network infrastructure or firewall configuration.

.LINK
    https://learn.microsoft.com/en-us/security/zero-trust/
.LINK
    https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-overview
.LINK
    https://learn.microsoft.com/en-us/graph/api/overview
.LINK
    https://learn.microsoft.com/en-us/microsoft-365/compliance/information-protection

#>


Function Invoke-ZeroTrustReadinessAssessment {
    [CmdletBinding(DefaultParameterSetName = "ClientCredentials")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
        [Parameter(Mandatory = $true, ParameterSetName = "BYOT")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
        [System.Security.SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = "BYOT")]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(ParameterSetName = "ClientCredentials")]
        [Parameter(ParameterSetName = "BYOT")]
        [ValidateSet("ClientCredentials", "BYOT")]
        [string]$AuthMode = "ClientCredentials",

        [Parameter(ParameterSetName = "ClientCredentials")]
        [Parameter(ParameterSetName = "BYOT")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = "C:\Temp\ZeroTrustAssessment",

        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    #region ── Friendly Help ──────────────────────────────────────────────────────

    Function Show-FriendlyHelp {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║    Zero Trust Readiness Assessment  v1.0                     ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  PURPOSE" -ForegroundColor Yellow
        Write-Host "    Assesses your tenant across the five Zero Trust pillars:"
        Write-Host "    Identity, Devices, Network, Data, and Applications."
        Write-Host "    Produces pillar maturity scores and a board-ready risk narrative."
        Write-Host ""
        Write-Host "  AUTHENTICATION" -ForegroundColor Yellow
        Write-Host "    Client Credentials (app-only):"
        Write-Host '      $secret = Read-Host "Client secret" -AsSecureString'
        Write-Host '      Invoke-ZeroTrustReadinessAssessment \'
        Write-Host '          -AuthMode ClientCredentials \'
        Write-Host '          -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "    BYOT (Bring Your Own Token):"
        Write-Host '      $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken'
        Write-Host '      Invoke-ZeroTrustReadinessAssessment \'
        Write-Host '          -AuthMode BYOT -AccessToken $token -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "  REQUIRED APP PERMISSIONS (Application, admin-consented)" -ForegroundColor Yellow
        Write-Host "    Directory.Read.All, Policy.Read.All, Application.Read.All,"
        Write-Host "    AuditLog.Read.All, RoleManagement.Read.Directory,"
        Write-Host "    IdentityRiskyUser.Read.All, UserAuthenticationMethod.Read.All,"
        Write-Host "    DeviceManagementConfiguration.Read.All,"
        Write-Host "    DeviceManagementManagedDevices.Read.All,"
        Write-Host "    InformationProtectionPolicy.Read.All"
        Write-Host ""
        Write-Host "  LICENSE REQUIREMENTS" -ForegroundColor Yellow
        Write-Host "    P1 minimum. P2 required for PIM eligible roles and Identity Protection."
        Write-Host "    Intune required for Device pillar. Purview/MIP for Data pillar."
        Write-Host ""
        Write-Host "  For full documentation: Get-Help Invoke-ZeroTrustReadinessAssessment -Full"
        Write-Host ""
    }

    if ($ShowHelp) {
        Show-FriendlyHelp
        return
    }

    #endregion

    #region ── Token Management (Client Credentials) ─────────────────────────────

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

        Try {
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
            if ($claims.scp) { $tokenPermissions += $claims.scp -split " " }
            if ($claims.roles) { $tokenPermissions += @($claims.roles) }

            $missingPermissions = @(
                $RequiredPermissions | Where-Object { $_ -notin $tokenPermissions }
            )

            return @{
                Valid              = ($missingPermissions.Count -eq 0)
                MissingPermissions = $missingPermissions
            }
        }
        Catch {
            return @{
                Valid              = $false
                MissingPermissions = $RequiredPermissions
            }
        }
    }

    #endregion

    #region ── Graph API Helper ───────────────────────────────────────────────────

    Function Invoke-GraphRequest {
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
                if ($Body) {
                    $invokeParams["Body"] = ($Body | ConvertTo-Json -Depth 10)
                    $headers["Content-Type"] = "application/json"
                }

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

    $script:MaturityLabels = @{
        1 = "Initial"
        2 = "Developing"
        3 = "Defined"
        4 = "Managed"
        5 = "Optimised"
    }

    $script:MaturityColors = @{
        1 = "#f85149"
        2 = "#d29922"
        3 = "#388bfd"
        4 = "#39c5cf"
        5 = "#3fb950"
    }

    $script:PillarColors = @{
        "P1" = "#388bfd"
        "P2" = "#39c5cf"
        "P3" = "#a371f7"
        "P4" = "#3fb950"
        "P5" = "#d29922"
    }

    # Global assessment store
    $script:Pillars = [System.Collections.ArrayList]::new()
    $script:Findings = [System.Collections.ArrayList]::new()


    Function Add-Finding {
        param (
            [string]$PillarId,
            [string]$PillarName,
            [string]$CheckId,
            [string]$Title,
            [string]$Context,
            [string]$CurrentState,
            [string]$GapAndRisk,
            [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
            [string]$Risk,
            [string]$BusinessImpact,
            [string]$TargetState,
            [string]$TransitionRecommendation,
            [string]$SuccessMeasure,
            [ValidateSet("0-30 Days", "31-60 Days", "61-90 Days", "Strategic")]
            [string]$RoadmapPhase,
            [int]$MaturityContribution = 0
        )

        $null = $script:Findings.Add([PSCustomObject]@{
                PillarId                 = $PillarId
                PillarName               = $PillarName
                CheckId                  = $CheckId
                Title                    = $Title
                Context                  = $Context
                CurrentState             = $CurrentState
                GapAndRisk               = $GapAndRisk
                Risk                     = $Risk
                BusinessImpact           = $BusinessImpact
                TargetState              = $TargetState
                TransitionRecommendation = $TransitionRecommendation
                SuccessMeasure           = $SuccessMeasure
                RoadmapPhase             = $RoadmapPhase
                MaturityContribution     = $MaturityContribution
            })
    }


    Function Set-PillarResult {
        param (
            [string]$Id,
            [string]$Name,
            [string]$Icon,
            [string]$ZtPrinciple,
            [int]$MaturityScore,
            [string]$CurrentStateSummary,
            [string]$TargetStateSummary,
            [int]$CriticalCount,
            [int]$HighCount,
            [int]$MediumCount,
            [int]$LowCount,
            [string]$DataQuality = "Full"
        )

        $label = $script:MaturityLabels[$MaturityScore]
        $color = $script:MaturityColors[$MaturityScore]

        $null = $script:Pillars.Add([PSCustomObject]@{
                Id                  = $Id
                Name                = $Name
                Icon                = $Icon
                ZtPrinciple         = $ZtPrinciple
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


    Function Get-OverallReadinessScore {
        if ($script:Pillars.Count -eq 0) { return 1 }
        $avg = ($script:Pillars | Measure-Object -Property MaturityScore -Average).Average
        return [Math]::Round($avg, 1)
    }

    #endregion

    #region ── Pillar 1: Identity ─────────────────────────────────────────────────

    Function Invoke-Pillar1-Identity {
        Write-Host "  🪪 P1: Identity..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 1.1: MFA Registration Coverage ──────────────────────────────────
        $mfaUri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails?`$top=500"
        $mfaData = Get-GraphPagedResults -Uri $mfaUri

        $totalUsers = 0
        $mfaRegistered = 0
        $mfaCapable = 0
        $passwordlessReg = 0

        if ($mfaData -and $mfaData.Count -gt 0) {
            $totalUsers = $mfaData.Count
            $mfaRegistered = @($mfaData | Where-Object { $_.isMfaRegistered -eq $true }).Count
            $mfaCapable = @($mfaData | Where-Object { $_.isMfaCapable -eq $true }).Count
            $passwordlessReg = @($mfaData | Where-Object { $_.isPasswordlessCapable -eq $true }).Count
        }

        $mfaRegPct = if ($totalUsers -gt 0) { [Math]::Round(($mfaRegistered / $totalUsers) * 100, 0) } else { 0 }
        $passwordlessPct = if ($totalUsers -gt 0) { [Math]::Round(($passwordlessReg / $totalUsers) * 100, 0) } else { 0 }

        if ($mfaRegPct -lt 50) {
            $critical++; $maturityPoints += 1
            $mfaRisk = "Critical"; $mfaPhase = "0-30 Days"
        }
        elseif ($mfaRegPct -lt 80) {
            $high++; $maturityPoints += 2
            $mfaRisk = "High"; $mfaPhase = "0-30 Days"
        }
        elseif ($mfaRegPct -lt 95) {
            $medium++; $maturityPoints += 3
            $mfaRisk = "Medium"; $mfaPhase = "31-60 Days"
        }
        else {
            $maturityPoints += 4
            $mfaRisk = "Info"; $mfaPhase = "Strategic"
        }

        Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.1" `
            -Title "MFA Registration Coverage: $mfaRegPct% ($mfaRegistered / $totalUsers users)" `
            -Context "MFA is the single most effective control against credential-based attacks. Without it, all other Zero Trust controls are undermined — an attacker with stolen credentials can bypass device, network, and app controls." `
            -CurrentState "$mfaRegPct% of user accounts have at least one MFA method registered. $passwordlessPct% are passwordless-capable." `
            -GapAndRisk "$(100 - $mfaRegPct)% of accounts remain reachable via password-only authentication — the primary entry point for credential stuffing, phishing, and password spray." `
            -Risk $mfaRisk `
            -BusinessImpact "Unregistered accounts represent the highest-probability entry point for account takeover. A single compromised account in the Identity control plane can result in lateral movement across all M365 workloads." `
            -TargetState "100% MFA registration enforced via Conditional Access. Phishing-resistant methods (FIDO2, WHfB, CBA) as the default for all privileged users." `
            -TransitionRecommendation "1) Enable MFA Registration Campaign (nudge at sign-in). 2) Create CA policy blocking unregistered users. 3) Set 30-day deadline for 100% compliance. 4) Pilot FIDO2/WHfB for power users before broad rollout." `
            -SuccessMeasure "MFA registration rate >98% measured weekly. Zero successful password-only sign-ins for member accounts. Passwordless adoption >30% within 90 days." `
            -RoadmapPhase $mfaPhase -MaturityContribution ($maturityPoints[-1])

        # ── Check 1.2: Phishing-Resistant Authentication (FIDO2 / WHfB) ──────────
        $authMethodsPolicy = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy"
        $fido2Enabled = $false
        $smsEnabled = $false

        if ($authMethodsPolicy -and $authMethodsPolicy.authenticationMethodConfigurations) {
            foreach ($method in $authMethodsPolicy.authenticationMethodConfigurations) {
                switch ($method."@odata.type") {
                    "#microsoft.graph.fido2AuthenticationMethodConfiguration" { $fido2Enabled = ($method.state -eq "enabled") }
                    "#microsoft.graph.smsAuthenticationMethodConfiguration" { $smsEnabled = ($method.state -eq "enabled") }
                }
            }
        }

        if (-not $fido2Enabled) {
            $medium++; $maturityPoints += 2
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.2" `
                -Title "Phishing-Resistant Authentication (FIDO2) Not Enabled" `
                -Context "Adversary-in-the-Middle (AiTM) phishing kits can bypass push-notification and OTP MFA in real time. Phishing-resistant methods — FIDO2, Windows Hello for Business, Certificate-Based Auth — are bound to device and origin, making AiTM technically impossible." `
                -CurrentState "FIDO2 security key authentication is not enabled. Authenticator push and/or OTP methods are the strongest available." `
                -GapAndRisk "All current MFA methods remain susceptible to AiTM phishing toolkits (Evilginx, Modlishka). Privileged administrators and C-suite users are at highest risk." `
                -Risk "Medium" `
                -BusinessImpact "AiTM phishing campaigns targeting Microsoft 365 are common and increasing. Without phishing-resistant options, even MFA-compliant users can be compromised in a single attack." `
                -TargetState "FIDO2 and Windows Hello for Business enabled. Phishing-resistant MFA enforced via CA Authentication Strength for all privileged roles and sensitive applications." `
                -TransitionRecommendation "1) Enable FIDO2 in Authentication Methods Policy (pilot group first). 2) Deploy WHfB via Intune for domain-joined devices. 3) Create CA Authentication Strength policy requiring Passwordless for GA and high-value roles." `
                -SuccessMeasure "Phishing-resistant method adoption >25% within 90 days. FIDO2/WHfB enforced for all Global Admins within 30 days. AiTM-susceptible sign-ins trending to zero." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.2" `
                -Title "Phishing-Resistant Authentication (FIDO2) is Enabled" `
                -Context "Phishing-resistant authentication eliminates AiTM attack feasibility." `
                -CurrentState "FIDO2 is enabled. Verify it is enforced via CA Authentication Strength, not merely available." `
                -GapAndRisk "Availability alone does not enforce phishing-resistant MFA. Without a CA Authentication Strength policy, users may fall back to weaker methods." `
                -Risk "Info" `
                -BusinessImpact "Low — excellent authentication posture. Focus on enforcing usage via CA Authentication Strength and monitoring adoption metrics." `
                -TargetState "FIDO2 or CBA enforced for all GA and Tier 0 roles via CA Authentication Strength. Passwordless usage >50%." `
                -TransitionRecommendation "Create Authentication Strength requiring Passwordless (FIDO2/WHfB/CBA) and apply it via a CA policy scoped to privileged roles and sensitive apps." `
                -SuccessMeasure "100% of Global Admins authenticating via phishing-resistant method. Passwordless sign-in rate tracked monthly in Entra ID usage reports." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 1.3: Conditional Access — MFA for All Users ─────────────────────
        $caPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $enabledCaPolicies = @($caPolicies | Where-Object { $_.state -eq "enabled" })

        $caRequiresMfaAllUsers = $false
        $caBlocksLegacyAuth = $false
        $caHasDeviceCompliance = $false
        $caHasHighRiskPolicy = $false
        $caReportOnlyCount = @($caPolicies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }).Count

        foreach ($policy in $enabledCaPolicies) {
            $conds = $policy.conditions
            $grant = $policy.grantControls
            $allUsers = ($conds.users.includeUsers -contains "All")

            if ($allUsers -and $grant -and $grant.builtInControls -contains "mfa") { $caRequiresMfaAllUsers = $true }
            if ($conds.clientAppTypes -contains "exchangeActiveSync" -or $conds.clientAppTypes -contains "other") {
                if ($grant -and $grant.builtInControls -contains "block") { $caBlocksLegacyAuth = $true }
            }
            if ($grant -and $grant.builtInControls -contains "compliantDevice") { $caHasDeviceCompliance = $true }
            if ($conds.userRiskLevels -contains "high" -or $conds.signInRiskLevels -contains "high") { $caHasHighRiskPolicy = $true }
        }

        if (-not $caRequiresMfaAllUsers) {
            $high++; $maturityPoints += 2
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.3" `
                -Title "No Conditional Access Policy Requiring MFA for All Users" `
                -Context "Conditional Access is the Zero Trust policy engine for identity. Without a baseline MFA-for-all policy, MFA enforcement is inconsistent — individual user registration does not guarantee sign-ins are challenged." `
                -CurrentState "No enabled CA policy found requiring MFA for All Users across All Cloud Apps. Report-only policies detected: $caReportOnlyCount." `
                -GapAndRisk "MFA registration without CA enforcement is voluntary — users with registered methods can still sign in without being challenged. Attackers can exploit inconsistent enforcement windows." `
                -Risk "High" `
                -BusinessImpact "Without a CA MFA-for-all baseline, MFA registration metrics are misleading. An attacker with stolen credentials can sign in successfully during enforcement gaps, particularly from new or non-compliant devices." `
                -TargetState "A baseline CA policy: All Users, All Cloud Apps, Require MFA (or stronger). Privileged roles require CA Authentication Strength (phishing-resistant). Break-glass accounts explicitly excluded." `
                -TransitionRecommendation "1) Deploy CA policy in report-only mode with MFA requirement for All Users / All Apps. 2) Monitor sign-in logs for impact. 3) Promote to enforce mode after 2-week observation. 4) Exclude break-glass accounts explicitly." `
                -SuccessMeasure "100% of non-excluded sign-ins challenged with MFA. Zero MFA-bypass sign-in events. Conditional Access coverage reported monthly via Entra ID Workbooks." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.3" `
                -Title "Conditional Access Policy Requiring MFA for All Users Detected" `
                -Context "Baseline CA MFA enforcement is the foundation of Zero Trust Identity." `
                -CurrentState "An enabled CA policy requiring MFA for All Users is in place. Legacy auth block: $caBlocksLegacyAuth. Device compliance required: $caHasDeviceCompliance. Report-only policies: $caReportOnlyCount." `
                -GapAndRisk "Validate exclusion groups are minimal and reviewed quarterly. Report-only policies should be promoted to enforced mode." `
                -Risk "Info" `
                -BusinessImpact "Low — strong CA baseline in place. Harden by layering Authentication Strength for privileged roles." `
                -TargetState "Named Location + Compliant Device added as CA conditions. Authentication Strength enforced for privileged roles. Zero report-only policies older than 60 days." `
                -TransitionRecommendation "Promote all report-only policies to enforce mode. Add Authentication Strength policy for privileged roles. Review CA exclusion groups quarterly." `
                -SuccessMeasure "Zero report-only CA policies >60 days old. CA exclusion group size <2% of user population. All sign-ins policy-matched in Entra ID sign-in logs." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 1.4: Legacy Authentication Block ────────────────────────────────
        if (-not $caBlocksLegacyAuth) {
            $high++; $maturityPoints += 1
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.4" `
                -Title "No Conditional Access Policy Blocking Legacy Authentication" `
                -Context "Legacy authentication protocols (SMTP AUTH, POP3, IMAP, Basic Auth) predate MFA entirely. Any MFA policy — however strict — has zero effect on sign-in attempts using legacy protocols." `
                -CurrentState "Scanned $($caPolicies.Count) CA policies. No policy detected blocking exchangeActiveSync or 'other' client app types with a Block grant control." `
                -GapAndRisk "Password spray and credential-stuffing attack tools exclusively target legacy auth endpoints because MFA cannot intercept them. This is the number-one initial access vector in Microsoft 365 tenant compromises." `
                -Risk "High" `
                -BusinessImpact "Legacy auth bypass is the root cause of the majority of Microsoft 365 account compromises. Even a single service account using legacy auth provides an unguarded entry point for mass credential attacks." `
                -TargetState "A CA policy blocking All Users, All Apps on client app types = Exchange ActiveSync + Other. Zero exceptions. Service accounts migrated to OAuth/modern auth." `
                -TransitionRecommendation "1) Filter Sign-In logs for Legacy Auth Protocols to identify users and apps still using legacy auth. 2) Migrate or replace identified legacy auth usage. 3) Deploy CA block in report-only, then enforce after 2 weeks." `
                -SuccessMeasure "Zero successful legacy authentication sign-ins. Legacy auth attempts trend to zero within 30 days of enforcement. Residual attempts monitored via Sentinel or Entra ID workbooks." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.4" `
                -Title "Legacy Authentication Blocked via Conditional Access" `
                -Context "Legacy auth block is a mandatory Zero Trust baseline." `
                -CurrentState "A CA policy with Block grant controls on legacy client app types (exchangeActiveSync / other) is in place and enforced." `
                -GapAndRisk "Verify CA exclusion groups do not inadvertently re-open legacy auth for any user. Monitor Sign-In logs for any residual legacy auth attempts." `
                -Risk "Info" `
                -BusinessImpact "Low — legacy auth blocked. Monitor for exceptions and ensure no service account bypasses the policy." `
                -TargetState "Zero exceptions to legacy auth block. Residual attempts alert-generating in Sentinel or Defender for Identity." `
                -TransitionRecommendation "Quarterly review of CA exclusion groups. Sign-in log alert rule for any successful legacy auth attempt." `
                -SuccessMeasure "Zero successful legacy auth sign-ins per month. Exclusion group membership <5 accounts, all documented and reviewed quarterly." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 1.5: PIM Coverage for Privileged Roles ──────────────────────────
        $pimAssignments = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?`$top=100"
        $permanentAdmins = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?`$filter=directoryScopeId eq '/'&`$top=200"
        $roleDefinitions = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?`$top=200"

        $roleDefinitionLookup = @{}

        foreach ($roleDefinition in @($roleDefinitions)) {
            if ($roleDefinition.id) {
                $roleDefinitionLookup[$roleDefinition.id] = $roleDefinition.displayName
            }
        }

        $pimEligibleCount = if ($pimAssignments) { $pimAssignments.Count } else { 0 }
        $permanentCount = if ($permanentAdmins) {
            @($permanentAdmins | Where-Object {
                    $roleDefinitionLookup.ContainsKey($_.roleDefinitionId)
                }).Count
        }
        else {
            0
        }

        # Identify permanent Global Admins (highest risk permanent assignments)
        $permanentGAs = @($permanentAdmins | Where-Object {
                $roleDefinitionLookup[$_.roleDefinitionId] -eq "Global Administrator"
            })

        if ($permanentGAs.Count -gt 5 -or ($pimEligibleCount -eq 0 -and $permanentCount -gt 0)) {
            $high++; $maturityPoints += 1
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.5" `
                -Title "Privileged Roles Permanently Assigned — PIM Eligible Assignments Insufficient (Global Admins: $($permanentGAs.Count) permanent)" `
                -Context "Zero Trust Identity requires that no one is permanently trusted, including admins. Privileged Identity Management enforces just-in-time access, requiring justification, approval, and MFA re-authentication before privileged roles activate." `
                -CurrentState "Permanent Global Admins: $($permanentGAs.Count). PIM eligible role assignments detected: $pimEligibleCount." `
                -GapAndRisk "Permanently assigned privileged roles mean that a compromised admin account is immediately and fully privileged with no time-limited exposure window. Standing privilege is the primary lateral movement enabler after initial admin account compromise." `
                -Risk "High" `
                -BusinessImpact "A compromised Global Administrator with standing access can exfiltrate all data, disable all security controls, and establish persistence within minutes. PIM reduces blast radius to the activation window (typically 1-4 hours)." `
                -TargetState "Zero permanent Global Administrators (maximum 2 break-glass exclusions). All privileged roles via PIM eligible assignments. Activation requires MFA + justification. Global Admin activations require approval." `
                -TransitionRecommendation "1) Audit all permanent role assignments. 2) Convert all non-break-glass GA assignments to PIM eligible. 3) Configure Global Admin to require approval. 4) Set maximum activation duration to 4 hours. 5) Enable PIM alerts for suspicious activations." `
                -SuccessMeasure "Permanent Global Admin count ≤2 (break-glass only). PIM activation audit rate 100%. Average activation duration <2 hours. PIM alert response time <15 minutes." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($pimEligibleCount -gt 0) {
            $maturityPoints += 4
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.5" `
                -Title "PIM Eligible Assignments Active ($pimEligibleCount eligible; $($permanentGAs.Count) permanent GAs)" `
                -Context "PIM is the just-in-time access control for Zero Trust privileged access." `
                -CurrentState "PIM eligible role assignments: $pimEligibleCount. Permanent Global Admins: $($permanentGAs.Count)." `
                -GapAndRisk "Ensure permanent GA count is ≤2 (break-glass). Review PIM activation policies — duration, approval, and MFA requirements — for all Tier 0 roles." `
                -Risk "Info" `
                -BusinessImpact "Low — PIM is in use. Optimise activation requirements and alert on anomalous activations." `
                -TargetState "All high-privilege roles via PIM eligible only. Global Admin activation requires approval and MFA. Alerts configured for off-hours or bulk activations." `
                -TransitionRecommendation "Review PIM policies for all Tier 0 roles. Add approval requirement for Global Administrator. Configure PIM alerts and integrate with Sentinel." `
                -SuccessMeasure "Permanent GA count maintained at ≤2. PIM activation rate 100% for Tier 0 roles. Alert-to-response time <15 minutes." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }
        else {
            $medium++; $maturityPoints += 2
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.5" `
                -Title "PIM Status Could Not Be Confirmed — Entra ID P2 May Not Be Licensed" `
                -Context "PIM requires Entra ID P2 licensing." `
                -CurrentState "PIM eligible role schedule API returned no data. P2 licensing may be absent. Permanent admins detected: $permanentCount." `
                -GapAndRisk "Without PIM, all privileged role assignments are permanent — there is no just-in-time model. Standing privilege is the single largest blast radius amplifier." `
                -Risk "Medium" `
                -BusinessImpact "Without P2 and PIM, privileged users have standing access to all administrative capabilities. Compromise of any admin account results in immediate and unlimited privilege." `
                -TargetState "Entra ID P2 licensed. PIM enabled for all Directory roles. Zero permanent Global Admins except break-glass." `
                -TransitionRecommendation "Evaluate Entra ID P2 or M365 E5. Implement PIM for all privileged directory roles as a priority post-licensing." `
                -SuccessMeasure "PIM enabled for 100% of directory roles. Zero permanent GA assignments (except 2 break-glass). PIM audit logs integrated with Sentinel." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }

        # ── Check 1.6: Identity Protection — Risky Users ──────────────────────────
        $riskyUsers = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identityProtection/riskyUsers?`$filter=riskState ne 'dismissed' and riskState ne 'remediated'&`$top=100"

        if ($null -eq $riskyUsers) {
            $medium++; $maturityPoints += 2
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.6" `
                -Title "Identity Protection Risk Data Unavailable — Entra ID P2 Required" `
                -Context "Entra ID Identity Protection provides real-time machine-learning risk signals for every sign-in and user, including impossible travel, leaked credentials, anomalous token usage, and password spray detection." `
                -CurrentState "riskyUsers API returned null — Entra ID P2 appears not licensed for this tenant." `
                -GapAndRisk "Without Identity Protection, there is no automated risk scoring. Compromised accounts remain active and undetected until manually identified — typically after damage has occurred." `
                -Risk "Medium" `
                -BusinessImpact "Zero automated identity risk detection. The average time to detect a credential compromise without Identity Protection is measured in weeks. P2 compresses this to hours with automated remediation." `
                -TargetState "Entra ID P2 licensed. Identity Protection enabled. Risk-based CA policies auto-remediating High user risk (force password reset) and High sign-in risk (block)." `
                -TransitionRecommendation "Evaluate Entra ID P2 or M365 E5 licensing. Enable Identity Protection. Create Risk-Based CA policies for both user and sign-in risk at High threshold." `
                -SuccessMeasure "Identity Protection active. Zero unaddressed High-risk users older than 24 hours. Risk-based CA policies automated and measured monthly." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        elseif ($riskyUsers.Count -gt 0) {
            $highRiskUsers = @($riskyUsers | Where-Object { $_.riskLevel -eq "high" })
            if ($highRiskUsers.Count -gt 0) {
                $critical++; $maturityPoints += 1
                Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.6" `
                    -Title "$($riskyUsers.Count) At-Risk Users Detected — $($highRiskUsers.Count) at High Risk Requiring Immediate Action" `
                    -Context "Identity Protection's High risk classification indicates a high-confidence probability of credential compromise." `
                    -CurrentState "Identity Protection has flagged $($riskyUsers.Count) user account(s) as at-risk. High risk: $($highRiskUsers.Count)." `
                    -GapAndRisk "High-risk users represent active, in-progress threat actors. Unaddressed high-risk accounts allow threat actors to maintain persistence and conduct lateral movement undetected." `
                    -Risk "Critical" `
                    -BusinessImpact "High-risk accounts flagged by Identity Protection have a statistically high probability of active credential compromise. Immediate investigation and remediation is required to prevent data breach and lateral movement." `
                    -TargetState "Zero unaddressed at-risk users. Automated risk remediation via CA Risk-Based policies. Risk dismissed only after confirmed remediation and credential reset." `
                    -TransitionRecommendation "1) Immediately investigate all High-risk users — force password reset and MFA re-registration. 2) Deploy CA: High User Risk → Require Secure Password Reset. 3) Deploy CA: High Sign-in Risk → Block. 4) Integrate risk alerts with Sentinel." `
                    -SuccessMeasure "Zero High-risk users unaddressed >24 hours. Risk-based CA policies automated. Mean time to remediate at-risk users <4 hours." `
                    -RoadmapPhase "0-30 Days" -MaturityContribution 1
            }
            else {
                $high++; $maturityPoints += 2
                Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.6" `
                    -Title "$($riskyUsers.Count) At-Risk Users Detected (Medium Risk — No High Risk Currently)" `
                    -Context "Identity Protection medium-risk signals indicate suspicious but not yet confirmed compromise." `
                    -CurrentState "At-risk users: $($riskyUsers.Count). Risk level: Medium. No High-risk users currently detected." `
                    -GapAndRisk "Medium-risk users can escalate to High-risk rapidly. Without automated risk-based policies, escalation goes undetected until manual review." `
                    -Risk "High" `
                    -BusinessImpact "Medium-risk accounts indicate active suspicious behaviour. Without automated remediation policies, these accounts may remain active throughout a compromise chain." `
                    -TargetState "Zero unaddressed at-risk users. Risk-based CA policies automating remediation at both Medium and High thresholds." `
                    -TransitionRecommendation "1) Review and remediate all medium-risk users. 2) Deploy CA Risk-Based policies at High threshold as a minimum. 3) Evaluate adding Medium sign-in risk policy requiring MFA step-up." `
                    -SuccessMeasure "Zero at-risk users unaddressed >48 hours. Mean time to detect and remediate <8 hours. Risk alerts integrated with security operations." `
                    -RoadmapPhase "31-60 Days" -MaturityContribution 2
            }
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P1" -PillarName "Identity" -CheckId "P1.6" `
                -Title "No At-Risk Users Detected — Identity Protection Active and Clear" `
                -Context "Zero at-risk users in Identity Protection is the target Zero Trust identity posture." `
                -CurrentState "Identity Protection accessible and reports zero at-risk users. Automated risk remediation policies should be validated." `
                -GapAndRisk "Verify risk-based CA policies are enforced (not report-only). Zero at-risk users reflects current state — not a permanent guarantee without automated response." `
                -Risk "Info" `
                -BusinessImpact "Low — excellent identity risk posture. Maintain risk-based CA policies for automated future remediation." `
                -TargetState "Zero at-risk users maintained via automated risk-based CA policies. Weekly risk report review by Security Operations." `
                -TransitionRecommendation "Confirm CA risk-based policies are in enforce mode. Set up weekly risk summary report to Security team. Integrate Identity Protection alerts with Sentinel." `
                -SuccessMeasure "Zero at-risk users unaddressed >24 hours across all months. Risk-based CA policy coverage validated quarterly." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute pillar maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $pillarMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-PillarResult -Id "P1" -Name "Identity" -Icon "🪪" `
            -ZtPrinciple "Verify explicitly — validate identity with strong authentication on every access attempt." `
            -MaturityScore $pillarMaturity `
            -CurrentStateSummary "MFA coverage: $mfaRegPct%. FIDO2: $fido2Enabled. CA MFA-for-all: $caRequiresMfaAllUsers. Legacy auth blocked: $caBlocksLegacyAuth. PIM eligible: $pimEligibleCount." `
            -TargetStateSummary "100% MFA. Phishing-resistant auth for all privileged roles. CA baseline enforced. Zero permanent admins. Risk-based CA automated." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Pillar 2: Devices ──────────────────────────────────────────────────

    Function Invoke-Pillar2-Devices {
        Write-Host "  💻 P2: Devices..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 2.1: Intune Compliance Policy Coverage ──────────────────────────
        $compliancePolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$top=50"
        $compliancePolicyCount = if ($compliancePolicies) { $compliancePolicies.Count } else { 0 }

        # ── Check 2.2: Managed Device Count and Compliance Rate ───────────────────
        $managedDevices = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=id,deviceName,complianceState,managedDeviceOwnerType,operatingSystem,lastSyncDateTime&`$top=500"

        $totalDevices = 0
        $compliantDevices = 0
        $nonCompliantCount = 0
        $staleDevices = 0

        if ($managedDevices -and $managedDevices.Count -gt 0) {
            $totalDevices = $managedDevices.Count
            $compliantDevices = @($managedDevices | Where-Object { $_.complianceState -eq "compliant" }).Count
            $nonCompliantCount = @($managedDevices | Where-Object { $_.complianceState -eq "noncompliant" }).Count
            $cutoff = (Get-Date).AddDays(-30)
            $staleDevices = @($managedDevices | Where-Object {
                    $ls = $_.lastSyncDateTime
                    $ls -and ([datetime]$ls -lt $cutoff)
                }).Count
        }

        $complianceRate = if ($totalDevices -gt 0) { [Math]::Round(($compliantDevices / $totalDevices) * 100, 0) } else { 0 }

        if ($compliancePolicyCount -eq 0 -or ($null -eq $managedDevices)) {
            $high++; $maturityPoints += 1
            Add-Finding -PillarId "P2" -PillarName "Devices" -CheckId "P2.1" `
                -Title "No Intune Device Compliance Policies Detected or Intune Not Deployed" `
                -Context "Zero Trust Devices requires that every device accessing corporate resources is verified as healthy and compliant before access is granted. Without compliance policies, the device pillar is entirely absent." `
                -CurrentState "Intune device compliance policies: $compliancePolicyCount. Managed devices: $totalDevices." `
                -GapAndRisk "Without device compliance policies, any device — personal, unmanaged, or compromised — can access all corporate resources. Conditional Access device conditions cannot function without compliance data." `
                -Risk "High" `
                -BusinessImpact "Unmanaged devices are the second-most-common initial access vector after credential theft. Data exfiltration from personal devices with no endpoint protection or DLP policies is undetectable and unpreventable." `
                -TargetState "All corporate-owned and BYOD devices enrolled in Intune. Compliance policies defined for all OS platforms. CA policy requiring compliant device for all apps." `
                -TransitionRecommendation "1) Deploy Intune. 2) Define compliance policies for Windows, macOS, iOS, Android. 3) Enrol corporate devices. 4) Add compliant device requirement to CA. 5) Define BYOD app protection policies." `
                -SuccessMeasure "Device enrolment rate >90% for corporate assets. Compliance rate >95%. CA compliant-device requirement enforced for all sensitive apps." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        elseif ($complianceRate -lt 70) {
            $high++; $maturityPoints += 2
            Add-Finding -PillarId "P2" -PillarName "Devices" -CheckId "P2.1" `
                -Title "Low Device Compliance Rate: $complianceRate% ($compliantDevices / $totalDevices compliant; $nonCompliantCount non-compliant)" `
                -Context "Device compliance is the trust signal Conditional Access uses to gate resource access." `
                -CurrentState "Compliance policies: $compliancePolicyCount. Total managed devices: $totalDevices. Compliant: $compliantDevices ($complianceRate%). Non-compliant: $nonCompliantCount. Stale (>30d sync): $staleDevices." `
                -GapAndRisk "A low compliance rate means that a significant proportion of devices accessing corporate resources have not met minimum security standards. Without CA device enforcement, non-compliant devices retain full access." `
                -Risk "High" `
                -BusinessImpact "Non-compliant devices (out-of-date OS, no disk encryption, no AV) represent the weakest link in the security chain. A single unpatched device on the corporate network can be the entry point for ransomware." `
                -TargetState "Device compliance rate >95%. Non-compliant devices blocked from sensitive app access via CA. Remediation workflow automated via Intune." `
                -TransitionRecommendation "1) Review non-compliant devices and root-cause their failure reason. 2) Triage devices into: remediate, retire, or exclude. 3) Add CA compliant-device requirement for sensitive apps. 4) Enable auto-remediation for common policy items." `
                -SuccessMeasure "Compliance rate >95% within 60 days. Non-compliant device count tracked and reviewed weekly. Mean time to remediate non-compliant device <48 hours." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P2" -PillarName "Devices" -CheckId "P2.1" `
                -Title "Device Compliance Rate: $complianceRate% — Good Posture ($compliantDevices / $totalDevices compliant)" `
                -Context "High device compliance rate is a strong Zero Trust device control signal." `
                -CurrentState "Compliance policies: $compliancePolicyCount. Managed devices: $totalDevices. Compliant: $compliantDevices ($complianceRate%). Stale (>30d sync): $staleDevices." `
                -GapAndRisk "Stale devices ($staleDevices) may have drifted from compliance. Ensure CA compliant-device requirement is enforced — not just monitoring." `
                -Risk "Info" `
                -BusinessImpact "Low — good device compliance posture. Focus on enforcing CA device conditions and managing stale device hygiene." `
                -TargetState "Compliance rate >98%. Stale devices auto-retired. CA compliant-device required for all sensitive apps." `
                -TransitionRecommendation "Retire stale devices ($staleDevices). Enforce CA compliant-device for all enterprise apps. Add Windows Hello for Business policy to move toward passwordless." `
                -SuccessMeasure "Compliance rate >98% month-over-month. Stale device count <2% of fleet. Zero non-compliant devices with access to sensitive data apps." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 2.3: CA Device Compliance Enforcement ───────────────────────────
        $caPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $caDeviceRequired = $false
        foreach ($policy in ($caPolicies | Where-Object { $_.state -eq "enabled" })) {
            if ($policy.grantControls -and $policy.grantControls.builtInControls -contains "compliantDevice") {
                $caDeviceRequired = $true
                break
            }
        }

        if (-not $caDeviceRequired) {
            $high++; $maturityPoints += 1
            Add-Finding -PillarId "P2" -PillarName "Devices" -CheckId "P2.3" `
                -Title "Conditional Access Does Not Require Device Compliance for Resource Access" `
                -Context "Without CA enforcing compliant device as a grant condition, Intune compliance policies are advisory-only — they signal state but do not gate access." `
                -CurrentState "No enabled CA policy found requiring compliantDevice grant control." `
                -GapAndRisk "Intune compliance policies without CA enforcement have no access control effect. Non-compliant and unmanaged devices retain full access to all applications — including email, SharePoint, and Teams." `
                -Risk "High" `
                -BusinessImpact "Device compliance data is collected but not enforced. This is the equivalent of a security checkpoint that records visitors but does not require ID. Access control is illusory." `
                -TargetState "CA policy requiring compliantDevice (or Hybrid Azure AD Join) for all cloud apps. Unmanaged device access restricted to app-protection-policy-enrolled BYOD via CA App Enforced Restrictions." `
                -TransitionRecommendation "1) Deploy CA policy: All Users, Sensitive Apps → Require compliant device. 2) Deploy in report-only mode first — monitor for impact. 3) Add App Protection Policy for BYOD users. 4) Enforce after 2-week observation period." `
                -SuccessMeasure "CA device compliance requirement active for all sensitive apps. Zero non-compliant devices with access to sensitive data. BYOD access governed via App Protection Policies." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P2" -PillarName "Devices" -CheckId "P2.3" `
                -Title "Conditional Access Enforces Device Compliance for Resource Access" `
                -Context "CA device enforcement converts Intune compliance data into an active access control gate." `
                -CurrentState "At least one enabled CA policy requiring compliantDevice grant control is in place." `
                -GapAndRisk "Verify CA scope covers all sensitive applications. Ensure BYOD is handled via App Protection Policies, not excluded from the policy scope." `
                -Risk "Info" `
                -BusinessImpact "Low — CA device enforcement is in place. Expand coverage to all apps and ensure BYOD App Protection Policy coverage." `
                -TargetState "CA compliant-device required for all enterprise apps. App Protection Policies covering all BYOD access patterns." `
                -TransitionRecommendation "Audit CA policy scope — confirm all sensitive apps are in scope. Add App Protection Policy requirement for BYOD access pattern via CA." `
                -SuccessMeasure "100% of sensitive app access gated by compliant-device or App Protection Policy. Unmanaged device access rate trending to zero." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 2.4: Autopilot / Intune Enrolment Method ───────────────────────
        $autopilotDevices = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$top=50"
        $autopilotCount = if ($autopilotDevices) { $autopilotDevices.Count } else { 0 }

        if ($autopilotCount -eq 0) {
            $low++; $maturityPoints += 2
            Add-Finding -PillarId "P2" -PillarName "Devices" -CheckId "P2.4" `
                -Title "No Windows Autopilot Devices Registered — Modern Device Provisioning Absent" `
                -Context "Windows Autopilot is the Zero Trust device provisioning model. It ensures every new device is enrolled, configured, and compliant before any user logs in for the first time — eliminating the image-and-deploy era security gaps." `
                -CurrentState "Windows Autopilot device identities: $autopilotCount. Devices may be joined manually or via traditional imaging." `
                -GapAndRisk "Manual or image-based provisioning introduces configuration drift, inconsistent security baselines, and delays in enforcement of compliance policies. Devices may be used before Intune enrolment completes." `
                -Risk "Low" `
                -BusinessImpact "Without Autopilot, new employee device deployment is slower, error-prone, and creates windows where devices operate outside compliance scope. Shadow IT device usage increases." `
                -TargetState "All new Windows devices provisioned via Autopilot. Zero-touch deployment with compliant Intune enrolment completed before first user sign-in." `
                -TransitionRecommendation "Register all new hardware purchases with Autopilot via reseller or manual CSV upload. Define Autopilot deployment profiles. Configure Enrolment Status Page to block device use until Intune provisioning completes." `
                -SuccessMeasure "100% of new Windows devices provisioned via Autopilot. Zero manual domain-join provisioning for new devices. Enrolment Status Page active on all Autopilot profiles." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P2" -PillarName "Devices" -CheckId "P2.4" `
                -Title "Windows Autopilot Devices Registered ($autopilotCount devices)" `
                -Context "Autopilot deployment is the Zero Trust modern device provisioning standard." `
                -CurrentState "Windows Autopilot registered devices: $autopilotCount. Modern provisioning is in use." `
                -GapAndRisk "Ensure Autopilot profiles include Enrolment Status Page (block use until provisioning completes) and Self-Deploying mode for shared devices." `
                -Risk "Info" `
                -BusinessImpact "Low — Autopilot in use. Extend to all new device purchases and ensure ESP blocks access until compliance is confirmed." `
                -TargetState "All new Windows devices via Autopilot. ESP active on all profiles. Self-Deploying mode for kiosk/shared devices." `
                -TransitionRecommendation "Audit Autopilot profiles — ensure ESP is enabled and required. Add Self-Deploying profile for shared/kiosk devices. Measure enrolment success rate." `
                -SuccessMeasure "100% of new Windows devices provisioned via Autopilot. Enrolment success rate >98%. Zero out-of-compliance devices in first 24 hours post-provisioning." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute pillar maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $pillarMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-PillarResult -Id "P2" -Name "Devices" -Icon "💻" `
            -ZtPrinciple "Verify endpoints — grant access only from healthy, compliant, managed devices." `
            -MaturityScore $pillarMaturity `
            -CurrentStateSummary "Managed devices: $totalDevices. Compliance rate: $complianceRate%. CA device enforcement: $caDeviceRequired. Autopilot: $autopilotCount devices." `
            -TargetStateSummary "All devices Intune-managed. Compliance >98%. CA enforces compliant device for all apps. All new devices via Autopilot." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Pillar 3: Network ──────────────────────────────────────────────────

    Function Invoke-Pillar3-Network {
        Write-Host "  🌐 P3: Network..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 3.1: Named Locations Defined ────────────────────────────────────
        $namedLocations = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations?`$top=50"
        $ipNamedLocs = @($namedLocations | Where-Object { $_."@odata.type" -eq "#microsoft.graph.ipNamedLocation" })
        $countryLocs = @($namedLocations | Where-Object { $_."@odata.type" -eq "#microsoft.graph.countryNamedLocation" })

        if ($namedLocations.Count -eq 0) {
            $medium++; $maturityPoints += 1
            Add-Finding -PillarId "P3" -PillarName "Network" -CheckId "P3.1" `
                -Title "No Named Locations Defined — Network Context Absent from CA Policies" `
                -Context "Zero Trust Network control requires that access decisions are location-aware. Named Locations allow CA policies to treat known corporate networks differently from unknown or high-risk networks — enabling stricter controls for off-network access." `
                -CurrentState "Named locations (IP): $($ipNamedLocs.Count). Country-based locations: $($countryLocs.Count)." `
                -GapAndRisk "Without named locations, CA policies cannot differentiate between sign-ins from trusted corporate IP ranges and anonymous proxies, Tor exit nodes, or high-risk countries. Location-based access controls are entirely absent." `
                -Risk "Medium" `
                -BusinessImpact "Location context is a key Zero Trust signal. Without it, CA policies cannot detect geographically impossible sign-ins as anomalous, and cannot apply stricter controls to off-premises access patterns." `
                -TargetState "Corporate IP ranges defined as trusted named locations. Country allowlist/blocklist defined. CA policies using location context to apply step-up authentication for off-network access." `
                -TransitionRecommendation "1) Define corporate public IP ranges as trusted named locations. 2) Define country-based locations for blocklist. 3) Create CA policy requiring step-up MFA from non-trusted locations." `
                -SuccessMeasure "Named IP locations cover all corporate egress points. Country blocklist defined. CA location-based policies active and reducing risk score for trusted-network sign-ins." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        elseif ($ipNamedLocs.Count -gt 0) {
            $maturityPoints += 3
            Add-Finding -PillarId "P3" -PillarName "Network" -CheckId "P3.1" `
                -Title "Named Locations Configured ($($namedLocations.Count) total; $($ipNamedLocs.Count) IP-based; $($countryLocs.Count) country-based)" `
                -Context "Named locations provide network context for CA policy decisions." `
                -CurrentState "IP-based locations: $($ipNamedLocs.Count). Country-based locations: $($countryLocs.Count). Total: $($namedLocations.Count)." `
                -GapAndRisk "Verify named locations are used in at least one active CA policy. Locations defined but unused provide no access control benefit." `
                -Risk "Info" `
                -BusinessImpact "Low — network context is available. Ensure CA policies leverage it to apply stricter authentication from untrusted locations." `
                -TargetState "All corporate IP ranges in trusted named locations. Country blocklist for high-risk regions. CA policies enforcing step-up from non-trusted locations." `
                -TransitionRecommendation "Audit CA policies to confirm named locations are referenced as conditions. Ensure Trusted IPs are marked as trusted. Add country blocklist for regions outside operational geography." `
                -SuccessMeasure "All corporate egress IP ranges in named locations. CA step-up policy active for non-trusted-location sign-ins. Sign-in logs showing location-based CA evaluation." `
                -RoadmapPhase "Strategic" -MaturityContribution 3
        }
        else {
            $low++; $maturityPoints += 2
            Add-Finding -PillarId "P3" -PillarName "Network" -CheckId "P3.1" `
                -Title "Named Locations Exist But No IP-Based Corporate Network Locations Defined" `
                -Context "Country-based locations exist but IP-based trusted corporate network locations are absent." `
                -CurrentState "Country-based named locations: $($countryLocs.Count). IP-based named locations: 0." `
                -GapAndRisk "Without IP-based trusted locations, CA cannot differentiate on-premises from remote access — a key signal for applying appropriate authentication requirements." `
                -Risk "Low" `
                -BusinessImpact "Moderate — country context is available but corporate network trust context is absent. CA policies cannot apply reduced friction for corporate network access." `
                -TargetState "Corporate public IP ranges defined as IP-based trusted named locations. CA policies using both IP and country context." `
                -TransitionRecommendation "Define corporate public egress IP ranges as IP-based named locations marked as trusted. Reference these in CA policies." `
                -SuccessMeasure "All corporate egress IPs in trusted named locations. CA location conditions leveraging IP context for step-up decisions." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }

        # ── Check 3.2: CA Location-Based Controls in Use ──────────────────────────
        $caPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $caUsesLocation = $false
        $caBlocksHighRiskCountries = $false

        foreach ($policy in ($caPolicies | Where-Object { $_.state -eq "enabled" })) {
            $conds = $policy.conditions
            if ($conds.locations -and ($conds.locations.includeLocations.Count -gt 0 -or $conds.locations.excludeLocations.Count -gt 0)) {
                $caUsesLocation = $true
                if ($policy.grantControls -and $policy.grantControls.builtInControls -contains "block") {
                    $caBlocksHighRiskCountries = $true
                }
            }
        }

        if (-not $caUsesLocation) {
            $medium++; $maturityPoints += 2
            Add-Finding -PillarId "P3" -PillarName "Network" -CheckId "P3.2" `
                -Title "No Conditional Access Policies Using Location Conditions" `
                -Context "Network context without CA enforcement produces no security benefit." `
                -CurrentState "No enabled CA policies found using location conditions. Named locations defined: $($namedLocations.Count) but unused in CA policy logic." `
                -GapAndRisk "Named locations that are not referenced in any CA policy provide zero access control benefit. Sign-ins from any location are treated identically regardless of risk." `
                -Risk "Medium" `
                -BusinessImpact "Location context is a high-value Zero Trust signal. Without location-based CA policies, the organisation is blind to impossible travel, access from sanctioned/restricted countries, and geographic anomalies." `
                -TargetState "CA policies leveraging location conditions for step-up authentication from untrusted locations and blocking sign-ins from high-risk countries." `
                -TransitionRecommendation "1) Create CA policy: All Users, exclude Trusted IPs → Require MFA step-up (step-up from non-trusted locations). 2) Create CA block policy for high-risk country named locations." `
                -SuccessMeasure "CA location-based policies active and evaluated on >90% of sign-ins. Off-network sign-ins require step-up MFA. High-risk country sign-ins blocked." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P3" -PillarName "Network" -CheckId "P3.2" `
                -Title "Conditional Access Policies Using Location Conditions — Network Context Active" `
                -Context "Location-based CA policies convert network context into active access controls." `
                -CurrentState "CA policies with location conditions: active. High-risk country block: $caBlocksHighRiskCountries." `
                -GapAndRisk "Validate location conditions cover all access patterns — remote work, VPN, mobile access, cloud-only apps." `
                -Risk "Info" `
                -BusinessImpact "Low — network location is an active CA signal. Ensure step-up requirements apply consistently across all access channels." `
                -TargetState "All access from non-trusted locations requires step-up MFA. High-risk country sign-ins blocked. Global Secure Access integrated for network telemetry." `
                -TransitionRecommendation "Evaluate Microsoft Entra Global Secure Access / Private Access for network micro-segmentation. Add country block for non-operational geographies." `
                -SuccessMeasure "100% of non-trusted-location sign-ins challenged with step-up MFA. Country block active for high-risk regions. Global Secure Access telemetry integrated with Sentinel." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 3.3: Continuous Access Evaluation ───────────────────────────────
        $caePolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"

        # CAE is enabled by default for Conditional Access.
        # We therefore look specifically for an enabled CA policy that
        # explicitly disables CAE.

        $caeSignal = $true
        $caeExplicitlyDisabled = $false
        $caeDisablePolicies = @()

        foreach ($policy in @($caePolicies | Where-Object { $_.state -eq "enabled" })) {

            $caeControl = $policy.sessionControls.continuousAccessEvaluation

            if ($caeControl -and $caeControl.mode -eq "disabled") {

                $caeExplicitlyDisabled = $true

                $caeDisablePolicies += [PSCustomObject]@{
                    DisplayName = $policy.displayName
                    Id          = $policy.id
                }
            }
        }

        # CAE is automatically enabled unless explicitly disabled
        # by an applicable Conditional Access policy.
        if ($caeExplicitlyDisabled) {
            $caeSignal = $false
        }

        if ($caeExplicitlyDisabled) {

            $medium++
            $maturityPoints += 2

            $disabledPolicyNames = ($caeDisablePolicies.DisplayName -join ", ")

            Add-Finding -PillarId "P3" -PillarName "Network" -CheckId "P3.3" `
                -Title "Continuous Access Evaluation Explicitly Disabled" `
                -Context "Continuous Access Evaluation (CAE) provides near-real-time evaluation of critical security events and supported Conditional Access policy changes." `
                -CurrentState "CAE is explicitly disabled by the following enabled Conditional Access policy or policies: $disabledPolicyNames." `
                -GapAndRisk "Explicitly disabling CAE increases the period during which supported resource providers may continue honoring otherwise valid access tokens after critical security or Conditional Access changes." `
                -Risk "Medium" `
                -BusinessImpact "Delayed enforcement following account compromise, password reset, user disablement, or other critical security events can increase the session persistence window available to an attacker." `
                -TargetState "CAE remains enabled for supported workloads and user populations unless a documented business exception exists." `
                -TransitionRecommendation "Review the Conditional Access policies explicitly disabling CAE. Remove the Disable session control unless a documented exception is required. Validate CAE behavior for supported workloads after the change." `
                -SuccessMeasure "No unnecessary Conditional Access policies explicitly disable CAE. CAE remains active for supported workloads and critical events are enforced near real time." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {

            $maturityPoints += 4

            Add-Finding -PillarId "P3" -PillarName "Network" -CheckId "P3.3" `
                -Title "Continuous Access Evaluation Active by Default" `
                -Context "Continuous Access Evaluation (CAE) provides near-real-time evaluation of critical security events and supported Conditional Access policy changes." `
                -CurrentState "No enabled Conditional Access policy was detected that explicitly disables Continuous Access Evaluation. CAE is therefore treated as enabled by the current Microsoft Entra Conditional Access model." `
                -GapAndRisk "Standard CAE does not automatically mean Strict Location Enforcement is enabled. Strict Location Enforcement is a separate CAE capability and should be evaluated independently for sensitive workloads." `
                -Risk "Info" `
                -BusinessImpact "Low — CAE is not explicitly disabled. Additional protection can be achieved through appropriate Conditional Access location controls and Strict Location Enforcement where supported and suitable." `
                -TargetState "CAE active for supported workloads. Strict Location Enforcement enabled for applicable sensitive workloads where network egress paths are known and controlled." `
                -TransitionRecommendation "Review Conditional Access session controls and evaluate Strict Location Enforcement for appropriate sensitive workloads. Validate resource-observed IP addresses before broad deployment." `
                -SuccessMeasure "CAE is not unnecessarily disabled. Supported workloads enforce critical events near real time. Strict Location Enforcement is validated for applicable sensitive workloads." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute pillar maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $pillarMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-PillarResult -Id "P3" -Name "Network" -Icon "🌐" `
            -ZtPrinciple "Assume breach on the network — encrypt all traffic, minimise lateral movement radius, and verify all network access requests." `
            -MaturityScore $pillarMaturity `
            -CurrentStateSummary "Named locations: $($namedLocations.Count). CA location policies: $caUsesLocation. Country block: $caBlocksHighRiskCountries. CAE active: $caeSignal. CAE explicitly disabled: $caeExplicitlyDisabled." `
            -TargetStateSummary "All corporate IP ranges trusted. CA step-up from non-trusted locations. Country blocklist for high-risk regions. CAE strict enforcement. Global Secure Access deployed." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Pillar 4: Data ─────────────────────────────────────────────────────

    Function Invoke-Pillar4-Data {
        Write-Host "  🗄️ P4: Data..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 4.1: Sensitivity Labels Published ───────────────────────────────
        $labelPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/informationProtection/policy/labels?`$top=50"
        $labelCount = if ($labelPolicies) { $labelPolicies.Count } else { 0 }

        if ($null -eq $labelPolicies) {
            $high++; $maturityPoints += 1
            Add-Finding -PillarId "P4" -PillarName "Data" -CheckId "P4.1" `
                -Title "Sensitivity Labels API Unavailable — Microsoft Purview / MIP Licensing May Be Required" `
                -Context "Data classification via sensitivity labels is the foundation of Zero Trust Data. Without labels, there is no consistent way to understand data sensitivity, apply access controls, or enforce data loss prevention — all corporate data is treated equally regardless of sensitivity." `
                -CurrentState "Information Protection label policy API returned null. Microsoft Purview Information Protection (formerly MIP) licensing may be absent." `
                -GapAndRisk "Without sensitivity labels, data is unclassified. There is no basis for automated data loss prevention, access restrictions, or regulatory compliance enforcement based on data sensitivity." `
                -Risk "High" `
                -BusinessImpact "Unclassified data environments cannot demonstrate GDPR, ISO 27001, or SOC 2 data handling compliance. Sensitive data (PII, financial, IP) has no protection envelope — it can be shared, downloaded, and forwarded without restriction." `
                -TargetState "Microsoft Purview licensed. Sensitivity labels defined for all data classification tiers (Public, Internal, Confidential, Highly Confidential). Labels published to all users." `
                -TransitionRecommendation "1) Evaluate Microsoft Purview Information Protection licensing (included in M365 E3/E5). 2) Define label taxonomy aligned to data classification policy. 3) Publish labels to all users via policy. 4) Enable auto-labelling for known sensitive data patterns." `
                -SuccessMeasure "Sensitivity labels defined for all classification tiers. Label adoption rate >60% within 90 days. Auto-labelling policy active for sensitive data patterns (PII, financial)." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        elseif ($labelCount -eq 0) {
            $high++; $maturityPoints += 1
            Add-Finding -PillarId "P4" -PillarName "Data" -CheckId "P4.1" `
                -Title "No Sensitivity Labels Defined — Data Classification Absent" `
                -Context "Microsoft Purview is accessible but no labels are defined." `
                -CurrentState "Information Protection label count: 0. Purview API accessible — licensing appears present." `
                -GapAndRisk "Purview licensing is available but the data classification framework has not been built. All data remains unclassified and unprotected by information protection controls." `
                -Risk "High" `
                -BusinessImpact "Absence of sensitivity labels means no DLP policies can be label-scoped, no access restrictions based on sensitivity, and no regulatory compliance reporting on classified data handling." `
                -TargetState "Full label taxonomy published. Labels applied to all new documents. Mandatory labelling enabled for Office apps and SharePoint. Auto-labelling for sensitive content patterns." `
                -TransitionRecommendation "1) Define label taxonomy (minimum: Public, Internal, Confidential, Highly Confidential). 2) Publish via label policy to all users. 3) Enable mandatory labelling in Office apps. 4) Create auto-labelling policies for PII and financial data." `
                -SuccessMeasure "Label taxonomy defined and published. >60% of new Office documents labelled within 60 days. Auto-labelling covering known sensitive content patterns." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P4" -PillarName "Data" -CheckId "P4.1" `
                -Title "Sensitivity Labels Defined ($labelCount labels configured)" `
                -Context "Sensitivity labels are the cornerstone of the Zero Trust Data pillar." `
                -CurrentState "Information Protection labels: $labelCount. Labels are available for classification." `
                -GapAndRisk "Verify labels are published to all users, mandatory labelling is enabled, and auto-labelling policies cover sensitive content patterns. Labels defined but not published or enforced provide no protection." `
                -Risk "Info" `
                -BusinessImpact "Low — label framework is in place. Focus on adoption rate, mandatory labelling enforcement, and auto-labelling coverage." `
                -TargetState "Labels published to 100% of users. Mandatory labelling for Office apps. Auto-labelling for PII, financial, and IP content patterns. Labels driving DLP policy conditions." `
                -TransitionRecommendation "Enable mandatory labelling in Office apps and SharePoint. Build auto-labelling policies. Use labels as DLP conditions. Track label adoption via Content Explorer in Purview." `
                -SuccessMeasure "Label adoption >80% for new Office files. Auto-labelling covering all known sensitive content patterns. DLP policies scoped to Confidential+ labels." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 4.2: DLP Policies Active ────────────────────────────────────────
        $dlpPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/informationProtection/dataLossPreventionPolicies?`$top=50"
        $dlpCount = if ($dlpPolicies) { $dlpPolicies.Count } else { 0 }

        # Also try beta endpoint for compliance DLP
        $dlpAvailable = ($null -ne $dlpPolicies)

        if ($null -eq $dlpPolicies) {
            $high++; $maturityPoints += 1
            Add-Finding -PillarId "P4" -PillarName "Data" -CheckId "P4.2" `
                -Title "DLP Policy Data Unavailable — Purview DLP May Not Be Licensed or Configured" `
                -Context "Data Loss Prevention policies are the enforcement layer that prevents sensitive data from leaving the organisation's control boundary." `
                -CurrentState "DLP policy API returned null. Microsoft Purview DLP may not be licensed, or the API scope is insufficient." `
                -GapAndRisk "Without DLP policies, sensitive data — credit card numbers, health records, PII, intellectual property — can be exfiltrated via email, Teams messages, SharePoint links, and USB drives without any detection or blocking." `
                -Risk "High" `
                -BusinessImpact "Data exfiltration is the highest-financial-impact outcome of a security breach. Without DLP, there is no technical control preventing an insider or compromised account from exfiltrating sensitive data en masse." `
                -TargetState "DLP policies active across Email, Teams, SharePoint, and OneDrive. Policies scoped to regulatory categories (PII, PCI, PHI). Sensitive label-based policies enforcing encryption and blocking external sharing." `
                -TransitionRecommendation "1) Confirm Purview DLP licensing (M365 E3 includes basic DLP). 2) Start with regulatory templates (GDPR, PCI DSS, HIPAA). 3) Deploy in audit mode first. 4) Promote to block mode after impact review." `
                -SuccessMeasure "DLP policies active across all M365 workloads. Zero undetected sensitive data exfiltration events. DLP match volume trending down as labelling improves." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        elseif ($dlpCount -eq 0) {
            $high++; $maturityPoints += 1
            Add-Finding -PillarId "P4" -PillarName "Data" -CheckId "P4.2" `
                -Title "No DLP Policies Configured — Data Exfiltration Controls Absent" `
                -Context "DLP licensing is present but no policies have been created." `
                -CurrentState "DLP policy count: 0. Purview DLP API accessible." `
                -GapAndRisk "Purview DLP is licensed but not configured. Sensitive data can be shared externally, emailed to personal accounts, or downloaded to unmanaged devices without detection or blocking." `
                -Risk "High" `
                -BusinessImpact "An unconfigured DLP environment is equivalent to a physical office with no document shredders, file locks, or copying restrictions. Any employee or compromised account can copy and exfiltrate unlimited sensitive data." `
                -TargetState "DLP policies active for all major regulatory categories. Email, Teams, SharePoint, and OneDrive all in scope. Block mode for high-confidence sensitive data matches." `
                -TransitionRecommendation "1) Create DLP policies using built-in regulatory templates (GDPR, UK PII, PCI DSS). 2) Deploy in audit mode first — review matches. 3) Tighten policies and promote to block mode. 4) Add sensitivity label-based conditions." `
                -SuccessMeasure "DLP policies active for all M365 workloads. >500 DLP policy matches reviewed and tuned within 30 days. Exfiltration events blocked and alerted within Purview Compliance portal." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P4" -PillarName "Data" -CheckId "P4.2" `
                -Title "DLP Policies Configured ($dlpCount policies active)" `
                -Context "Active DLP policies enforce data loss prevention controls across M365 workloads." `
                -CurrentState "DLP policies: $dlpCount. Active data exfiltration controls are in place." `
                -GapAndRisk "Validate DLP policies are in block (not audit-only) mode for high-confidence matches. Ensure all M365 workloads are in scope — email, Teams, SharePoint, OneDrive, and endpoint (if Defender for Endpoint deployed)." `
                -Risk "Info" `
                -BusinessImpact "Low — DLP controls are in place. Harden by ensuring block mode and expanding to endpoint DLP." `
                -TargetState "All DLP policies in block mode for high-confidence matches. Endpoint DLP active. Sensitivity label-based DLP conditions enforcing label-driven controls." `
                -TransitionRecommendation "Audit DLP policy modes — promote audit-only policies to block. Add endpoint DLP for Defender for Endpoint devices. Review DLP match reports monthly in Purview." `
                -SuccessMeasure "Zero DLP policies remaining in audit-only mode for >90 days. Endpoint DLP active for all managed Windows devices. DLP incident volume and false positive rate tracked monthly." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 4.3: Sharing Settings — SharePoint External Sharing ─────────────
        $sharepointSvc = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/admin/sharepoint/settings"
        $externalSharing = "Unknown"

        if ($sharepointSvc -and $sharepointSvc.sharingCapability) {
            $externalSharing = $sharepointSvc.sharingCapability
        }

        if ($externalSharing -eq "ExternalUserAndGuestSharing" -or $externalSharing -eq "ExistingExternalUserSharingOnly") {
            $medium++; $maturityPoints += 2
            Add-Finding -PillarId "P4" -PillarName "Data" -CheckId "P4.3" `
                -Title "SharePoint External Sharing Permissive — Anyone Links Enabled or Guest Sharing Active" `
                -Context "SharePoint external sharing controls are the primary data boundary for M365 collaboration. Permissive sharing settings create an uncontrolled data egress channel outside all DLP and sensitivity label protections." `
                -CurrentState "SharePoint external sharing capability: $externalSharing. Anyone links or guest sharing may be active — data can be shared outside the organisation without recipient identity verification." `
                -GapAndRisk "Anyone links bypass all Conditional Access and identity controls — any person with the link can access the shared data regardless of their device, location, or MFA status. This is a direct violation of Zero Trust principles." `
                -Risk "Medium" `
                -BusinessImpact "A single Anyone link to a confidential document shared in an email thread or posted publicly provides unconstrained access to the shared data. Data shared via Anyone links is effectively public." `
                -TargetState "External sharing restricted to Existing Guests or New and Existing Guests with expiry enforced. Anyone links disabled. Sensitivity label-enforced sharing restrictions for Confidential+ content." `
                -TransitionRecommendation "1) In SharePoint admin centre, set external sharing to 'New and existing guests' as maximum. 2) Disable Anyone links at tenant level. 3) Enforce link expiry (30 days maximum). 4) Configure sensitivity labels to restrict sharing for Confidential+ labels." `
                -SuccessMeasure "Anyone links disabled. Maximum external sharing = authenticated guests. Sharing link expiry ≤30 days enforced. External sharing events monitored and alerted via Purview Audit." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        elseif ($externalSharing -eq "Unknown") {
            $low++; $maturityPoints += 2
            Add-Finding -PillarId "P4" -PillarName "Data" -CheckId "P4.3" `
                -Title "SharePoint External Sharing Configuration Could Not Be Retrieved" `
                -Context "SharePoint sharing settings are a critical data boundary control." `
                -CurrentState "SharePoint settings API returned no sharing capability data. The API may require SharePoint admin scope." `
                -GapAndRisk "SharePoint external sharing posture is unverified. If Anyone links are enabled, they represent an uncontrolled data egress channel that bypasses all identity and device controls." `
                -Risk "Low" `
                -BusinessImpact "Unverified external sharing posture means data boundary controls cannot be confirmed. Recommend manual validation in SharePoint admin centre." `
                -TargetState "External sharing restricted to authenticated guests. Anyone links disabled. Sharing expiry enforced." `
                -TransitionRecommendation "Manually verify external sharing settings in SharePoint admin centre. Disable Anyone links and set maximum sharing to authenticated guests." `
                -SuccessMeasure "SharePoint external sharing settings reviewed and restricted. Anyone links disabled and confirmed via SharePoint admin centre." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P4" -PillarName "Data" -CheckId "P4.3" `
                -Title "SharePoint External Sharing Restricted — Sharing Posture is Controlled" `
                -Context "Restricted external sharing settings maintain the data boundary." `
                -CurrentState "SharePoint external sharing: $externalSharing. Sharing is restricted to authenticated identities." `
                -GapAndRisk "Validate that link expiry is enforced and sensitivity labels restrict sharing for Confidential+ content. Sharing to authenticated guests without expiry still creates stale access." `
                -Risk "Info" `
                -BusinessImpact "Low — sharing controls are in place. Harden with link expiry and sensitivity label-enforced sharing restrictions." `
                -TargetState "Sharing link expiry ≤30 days enforced. Sensitivity labels restricting Confidential+ content sharing. External sharing monitored in Purview Audit." `
                -TransitionRecommendation "Enable link expiry enforcement (30 days). Configure sensitivity label protection for Confidential and Highly Confidential to block external sharing. Monitor sharing events monthly." `
                -SuccessMeasure "All sharing links expire ≤30 days. Confidential+ content sharing blocked to external parties. Sharing anomalies alerted via Purview Audit and Sentinel." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute pillar maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $pillarMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-PillarResult -Id "P4" -Name "Data" -Icon "🗄️" `
            -ZtPrinciple "Protect data — classify, label, and protect all data at rest and in transit regardless of where it lives." `
            -MaturityScore $pillarMaturity `
            -CurrentStateSummary "Sensitivity labels: $labelCount. DLP policies: $dlpCount. External sharing: $externalSharing." `
            -TargetStateSummary "Full label taxonomy published. DLP active across all workloads in block mode. Anyone links disabled. Auto-labelling for sensitive content. Endpoint DLP active." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Pillar 5: Applications ────────────────────────────────────────────

    Function Invoke-Pillar5-Applications {
        Write-Host "  📱 P5: Applications..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 5.1: High-Privilege OAuth App Permissions ───────────────────────
        $servicePrincipals = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,displayName,appId,appRoleAssignments&`$top=200"

        $highPrivilegeApps = [System.Collections.ArrayList]::new()

        $dangerousPermissions = @(
            "RoleManagement.ReadWrite.Directory",
            "Directory.ReadWrite.All",
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Application.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
            "DelegatedPermissionGrant.ReadWrite.All",
            "Domain.ReadWrite.All",
            "Policy.ReadWrite.All"
        )

        if ($servicePrincipals -and $servicePrincipals.Count -gt 0) {
            foreach ($sp in $servicePrincipals) {
                $appRoles = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)/appRoleAssignments?`$top=50"
                if ($appRoles -and $appRoles.Count -gt 0) {
                    foreach ($role in $appRoles) {
                        # Permission name is not directly in appRoleAssignments; flag apps with broad Graph SP targets
                        if ($role.resourceDisplayName -eq "Microsoft Graph" -and $role.principalId -eq $sp.id) {
                            $null = $highPrivilegeApps.Add($sp.displayName)
                            break
                        }
                    }
                }
            }
        }

        $appsWithGraphAccess = $highPrivilegeApps.Count
        $totalSPs = if ($servicePrincipals) { $servicePrincipals.Count } else { 0 }

        if ($appsWithGraphAccess -gt 20) {
            $high++; $maturityPoints += 1
            Add-Finding -PillarId "P5" -PillarName "Applications" -CheckId "P5.1" `
                -Title "High Number of Applications with Direct Microsoft Graph Permissions ($appsWithGraphAccess apps — $totalSPs total service principals)" `
                -Context "Application permissions are the highest-risk OAuth grant type. They operate without user context, are permanently effective, and often carry privileges that equal or exceed a Global Administrator's capabilities." `
                -CurrentState "Service principals with direct Graph API access: $appsWithGraphAccess of $totalSPs total. High-privilege Graph permissions may include Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, and similar." `
                -GapAndRisk "Applications with high-privilege application permissions are high-value targets for attackers. A compromised application client secret or certificate grants persistent, user-independent, tenant-wide access matching the permission scope." `
                -Risk "High" `
                -BusinessImpact "Compromised application with Directory.ReadWrite.All or RoleManagement.ReadWrite.Directory effectively equates to a compromised Global Administrator — the highest possible blast radius. Application credential theft is a primary target for supply chain attacks." `
                -TargetState "All application permissions reviewed and minimised to least privilege. High-privilege applications require approval workflow. Application credentials (secrets/certs) rotated quarterly. App permissions reviewed in quarterly access reviews." `
                -TransitionRecommendation "1) Audit all service principals with application permissions via Microsoft Graph Explorer. 2) Remove unused or overprivileged applications. 3) Replace high-privilege permissions with scoped alternatives where possible. 4) Implement quarterly app permission access reviews." `
                -SuccessMeasure "Zero applications with unnecessary high-privilege permissions. App permission review completed quarterly. Application secret age <90 days for all active apps. App permissions monitored via Defender for Cloud Apps or Sentinel." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 3
            Add-Finding -PillarId "P5" -PillarName "Applications" -CheckId "P5.1" `
                -Title "Application Graph Permission Volume Within Expected Range ($appsWithGraphAccess apps with Graph access of $totalSPs total)" `
                -Context "Application permission hygiene is a key Zero Trust Applications control." `
                -CurrentState "Service principals with direct Graph API access: $appsWithGraphAccess of $totalSPs total. Volume is within an expected range for a typical M365 tenant." `
                -GapAndRisk "Validate specific permissions granted — volume alone does not confirm least privilege. Review for any RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All, or Application.ReadWrite.All grants." `
                -Risk "Info" `
                -BusinessImpact "Low — app permission volume is manageable. Conduct a targeted review of highest-privilege grants." `
                -TargetState "All app permissions reviewed and minimised. Quarterly access reviews for application permissions. App credential rotation enforced." `
                -TransitionRecommendation "Use Microsoft Entra workbooks / App Governance to review specific permissions granted. Flag any application with Tier 0 equivalent permissions for immediate review." `
                -SuccessMeasure "Application permission inventory complete. Zero unreviewed high-privilege app permissions. App credential rotation policy enforced with alerts for approaching expiry." `
                -RoadmapPhase "Strategic" -MaturityContribution 3
        }

        # ── Check 5.2: Admin Consent Workflow ─────────────────────────────────────
        $consentSettings = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/adminConsentRequestPolicy"
        $consentWorkflowEnabled = $false

        if ($consentSettings -and $consentSettings.isEnabled -eq $true) {
            $consentWorkflowEnabled = $true
        }

        if (-not $consentWorkflowEnabled) {
            $high++; $maturityPoints += 1
            Add-Finding -PillarId "P5" -PillarName "Applications" -CheckId "P5.2" `
                -Title "Admin Consent Workflow Not Enabled — Users May Bypass App Permission Governance" `
                -Context "Without an admin consent workflow, users who are denied consent for an application have no governed escalation path. Alternatively, if user consent is enabled without controls, users can grant low-privilege application permissions independently — creating uncontrolled app sprawl." `
                -CurrentState "Admin consent request policy: disabled or not configured. User-initiated application consent escalation path is absent." `
                -GapAndRisk "Without a consent workflow, two risks emerge: (1) users are blocked with no governed alternative, driving shadow IT; (2) if user consent is enabled broadly, application permissions accumulate without oversight — every user-consented OAuth app is a potential supply-chain risk." `
                -Risk "High" `
                -BusinessImpact "OAuth app consent is a primary phishing vector. Consent phishing campaigns (illicit consent grant attacks) trick users into consenting to malicious OAuth applications that then have persistent read access to email, calendars, and files — without any password being compromised." `
                -TargetState "Admin consent workflow enabled. User consent restricted to verified publisher apps only (or disabled entirely). All admin consent requests reviewed within 48 hours. Consent phishing detection active via Defender for Cloud Apps." `
                -TransitionRecommendation "1) Enable Admin Consent Workflow in Entra ID (Enterprise Apps → User Settings → Admin consent requests). 2) Restrict user consent to 'Allow user consent for apps from verified publishers only'. 3) Configure reviewers and SLA for consent requests. 4) Enable consent anomaly detection in Defender for Cloud Apps." `
                -SuccessMeasure "Admin consent workflow active with defined reviewers. Zero unreviewed consent requests >48 hours. User consent restricted to verified publishers. Consent phishing attempts detected and blocked." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P5" -PillarName "Applications" -CheckId "P5.2" `
                -Title "Admin Consent Workflow Enabled — Application Permission Governance in Place" `
                -Context "Admin consent workflow ensures application permission grants are reviewed and approved." `
                -CurrentState "Admin consent request policy: enabled. Application permission governance workflow is active." `
                -GapAndRisk "Validate that user consent is restricted to verified publishers only. Ensure consent request SLA is ≤48 hours. Monitor for consent phishing via Defender for Cloud Apps." `
                -Risk "Info" `
                -BusinessImpact "Low — consent governance is in place. Harden by restricting user consent scope and adding Defender for Cloud Apps consent anomaly detection." `
                -TargetState "User consent restricted to verified publishers. Admin consent SLA ≤48 hours. Consent phishing detection active. Quarterly review of all consented application permissions." `
                -TransitionRecommendation "Restrict user consent to verified publishers only. Ensure Defender for Cloud Apps app governance is enabled for OAuth app monitoring. Schedule quarterly app permission reviews." `
                -SuccessMeasure "User consent restricted to verified publishers. Zero unreviewed consent requests >48 hours. OAuth app governance active with anomaly detection." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 5.3: Application Secret Hygiene (Long-Lived Credentials) ────────
        $appRegistrations = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/applications?`$select=id,displayName,passwordCredentials,keyCredentials&`$top=100"

        $staleSecretApps = 0
        $longLivedSecretApps = 0
        $totalApps = if ($appRegistrations) { $appRegistrations.Count } else { 0 }

        if ($appRegistrations -and $appRegistrations.Count -gt 0) {
            $cutoffDate = (Get-Date).AddDays(-365)
            $thresholdDate = (Get-Date).AddDays(365)

            foreach ($app in $appRegistrations) {
                $hasStaleSecret = $false
                $hasLongLived = $false

                if ($app.passwordCredentials) {
                    foreach ($cred in $app.passwordCredentials) {
                        if ($cred.endDateTime -and ([datetime]$cred.endDateTime) -lt [datetime]$cutoffDate.ToString("yyyy-MM-dd")) {
                            $hasStaleSecret = $true
                        }
                        if ($cred.endDateTime -and ([datetime]$cred.endDateTime) -gt [datetime]$thresholdDate.ToString("yyyy-MM-dd")) {
                            $hasLongLived = $true
                        }
                    }
                }

                if ($hasStaleSecret) { $staleSecretApps++ }
                if ($hasLongLived) { $longLivedSecretApps++ }
            }
        }

        if ($longLivedSecretApps -gt 0 -or $staleSecretApps -gt 0) {
            $risk = if ($longLivedSecretApps -gt 10 -or $staleSecretApps -gt 5) { "High" } else { "Medium" }
            if ($risk -eq "High") { $high++; $maturityPoints += 1 } else { $medium++; $maturityPoints += 2 }

            Add-Finding -PillarId "P5" -PillarName "Applications" -CheckId "P5.3" `
                -Title "Application Credential Hygiene Issues Detected — $longLivedSecretApps Apps with Long-Lived Secrets; $staleSecretApps with Expired Secrets" `
                -Context "Application client secrets and certificates are the credentials of workload identities. Long-lived secrets (>1 year expiry) and expired-but-present secrets both represent credential hygiene failures that increase the window of opportunity for credential theft and misuse." `
                -CurrentState "Total app registrations: $totalApps. Apps with secrets expiring >1 year from now (long-lived): $longLivedSecretApps. Apps with secrets already expired (stale): $staleSecretApps." `
                -GapAndRisk "Long-lived secrets that are leaked or compromised provide an extended window of exploitation — potentially years. Expired but retained secrets indicate poor lifecycle management, and may still be in use by applications that will break silently." `
                -Risk $risk `
                -BusinessImpact "Application secret compromise is a major supply chain attack vector. Long-lived, infrequently rotated secrets are high-value targets in source code leaks, CI/CD pipeline breaches, and key vault misconfigurations." `
                -TargetState "All application secrets expire ≤365 days. Automated rotation configured for critical applications. Workload identities migrated to Managed Identities where possible (secrets eliminated entirely). Federated credentials for GitHub/Azure DevOps workloads." `
                -TransitionRecommendation "1) Inventory all apps with secrets >365-day expiry. 2) Reduce expiry to 90-365 days maximum. 3) Migrate critical apps to Managed Identities (eliminates secrets entirely). 4) Use Federated Credentials for CI/CD pipelines. 5) Alert on secrets approaching expiry via Azure Monitor or Logic Apps." `
                -SuccessMeasure "Zero application secrets with expiry >365 days. Zero expired secrets retained on active apps. Managed Identity adoption >40% of internal workloads. Secret rotation alerts automated." `
                -RoadmapPhase "31-60 Days" -MaturityContribution ($maturityPoints[-1])
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P5" -PillarName "Applications" -CheckId "P5.3" `
                -Title "Application Secret Hygiene — No Long-Lived or Expired Secrets Detected in Sample" `
                -Context "Clean application credential hygiene reduces workload identity attack surface." `
                -CurrentState "Total apps reviewed: $totalApps. Long-lived secrets (>1yr): $longLivedSecretApps. Expired secrets: $staleSecretApps." `
                -GapAndRisk "Note: this check samples available app registrations. Verify manually for any CI/CD or third-party connected apps not surfaced via Graph. Consider Managed Identity migration for all applicable workloads." `
                -Risk "Info" `
                -BusinessImpact "Low — credential hygiene appears good. Formalise rotation policy and migrate to Managed Identities to fully eliminate secret risk." `
                -TargetState "100% of apps with secrets ≤365-day expiry. Managed Identities for all Azure-hosted workloads. Federated credentials for CI/CD. Secret expiry alerts automated." `
                -TransitionRecommendation "Formalise secret rotation policy (90-day target). Review all apps for Managed Identity eligibility. Implement Federated Credentials for GitHub Actions and Azure DevOps pipelines." `
                -SuccessMeasure "Secret rotation policy documented and enforced. Managed Identity adoption measured quarterly. Zero secrets with expiry >365 days maintained over time." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 5.4: CA Coverage for Applications ───────────────────────────────
        $caPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $enabledPolicies = @($caPolicies | Where-Object { $_.state -eq "enabled" })
        $allAppsCACount = @($enabledPolicies | Where-Object {
                $_.conditions.applications.includeApplications -contains "All"
            }).Count

        if ($allAppsCACount -eq 0) {
            $medium++; $maturityPoints += 2
            Add-Finding -PillarId "P5" -PillarName "Applications" -CheckId "P5.4" `
                -Title "No Conditional Access Policies Scoped to All Cloud Applications" `
                -Context "Zero Trust Applications requires that CA policy is the consistent enforcement layer across all applications — not a per-app opt-in. Application-specific CA gaps allow users to access ungoverned apps without MFA, compliant devices, or location checks." `
                -CurrentState "Enabled CA policies scoped to All Cloud Apps: $allAppsCACount. Total enabled CA policies: $($enabledPolicies.Count). Individual applications may have policies but a consistent baseline is absent." `
                -GapAndRisk "Applications without CA policy coverage can be accessed by any authenticated user regardless of MFA status, device compliance, or location — entirely bypassing Zero Trust controls configured for other apps." `
                -Risk "Medium" `
                -BusinessImpact "A CA gap for any application is a complete bypass of all authentication strength and device requirements. Attackers specifically target apps that are not in CA scope to exploit weaker authentication paths." `
                -TargetState "At least one CA policy scoped to All Cloud Apps enforcing MFA baseline for all users. Additional policies layering device compliance, location, and authentication strength for sensitive apps." `
                -TransitionRecommendation "1) Create baseline CA policy: All Users, All Cloud Apps → Require MFA. 2) This single policy closes the application CA coverage gap. 3) Layer additional policies for privileged apps and sensitive workloads." `
                -SuccessMeasure "At least one CA policy covering All Cloud Apps for all users. CA policy match rate >99% for all sign-ins via Entra ID sign-in workbooks." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -PillarId "P5" -PillarName "Applications" -CheckId "P5.4" `
                -Title "Conditional Access Policies Cover All Cloud Applications ($allAppsCACount baseline policies)" `
                -Context "All-Apps CA coverage ensures no application is an ungoverned access path." `
                -CurrentState "CA policies scoped to All Cloud Apps: $allAppsCACount. Total enabled CA policies: $($enabledPolicies.Count)." `
                -GapAndRisk "Validate that all-apps policies are not circumvented by large exclusion groups. Layer application-specific policies for sensitive apps requiring stronger authentication." `
                -Risk "Info" `
                -BusinessImpact "Low — all-apps CA coverage is in place. Harden with authentication strength for sensitive app categories and monitor exclusion group size." `
                -TargetState "All-Apps CA policies with minimal exclusions. Sensitive apps (Finance, HR, Code repositories) requiring Authentication Strength. CA sign-in coverage >99%." `
                -TransitionRecommendation "Audit exclusion groups for all-apps CA policies. Add Authentication Strength policy for sensitive application categories. Monitor CA coverage in Entra ID sign-in workbooks monthly." `
                -SuccessMeasure "CA all-apps exclusion groups <2% of user population. CA sign-in match rate >99%. Sensitive app access requiring phishing-resistant auth within 90 days." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute pillar maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $pillarMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-PillarResult -Id "P5" -Name "Applications" -Icon "📱" `
            -ZtPrinciple "Control access to applications — enforce least privilege for all app permissions and govern all OAuth consent." `
            -MaturityScore $pillarMaturity `
            -CurrentStateSummary "Total apps: $totalApps. Apps with Graph access: $appsWithGraphAccess. Admin consent workflow: $consentWorkflowEnabled. Long-lived secrets: $longLivedSecretApps. CA all-apps coverage: $allAppsCACount policies." `
            -TargetStateSummary "All app permissions reviewed. Consent workflow active. Secrets <90 days. Managed Identities for all Azure workloads. CA covers all apps with authentication strength for sensitive apps." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── JSON Builders ─────────────────────────────────────────────────────

    Function ConvertTo-JsonSafe {
        param ([string]$s)
        return $s -replace '\\', '\\' -replace '"', '\"' -replace "`r", '' -replace "`n", '\n' -replace "`t", '\t' -replace '<', '\u003c' -replace '>', '\u003e' -replace '\$', '\u0024'
    }


    Function Build-PillarsJson {
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.Append("[")
        $first = $true
        foreach ($p in $script:Pillars) {
            if (-not $first) { $null = $sb.Append(",") }
            $first = $false
            $null = $sb.Append("{")
            $null = $sb.Append("""id"":""$(ConvertTo-JsonSafe $p.Id)"",")
            $null = $sb.Append("""name"":""$(ConvertTo-JsonSafe $p.Name)"",")
            $null = $sb.Append("""icon"":""$(ConvertTo-JsonSafe $p.Icon)"",")
            $null = $sb.Append("""ztPrinciple"":""$(ConvertTo-JsonSafe $p.ZtPrinciple)"",")
            $null = $sb.Append("""maturityScore"":$($p.MaturityScore),")
            $null = $sb.Append("""maturityLabel"":""$(ConvertTo-JsonSafe $p.MaturityLabel)"",")
            $null = $sb.Append("""maturityColor"":""$(ConvertTo-JsonSafe $p.MaturityColor)"",")
            $null = $sb.Append("""currentStateSummary"":""$(ConvertTo-JsonSafe $p.CurrentStateSummary)"",")
            $null = $sb.Append("""targetStateSummary"":""$(ConvertTo-JsonSafe $p.TargetStateSummary)"",")
            $null = $sb.Append("""critical"":$($p.CriticalCount),")
            $null = $sb.Append("""high"":$($p.HighCount),")
            $null = $sb.Append("""medium"":$($p.MediumCount),")
            $null = $sb.Append("""low"":$($p.LowCount)")
            $null = $sb.Append("}")
        }
        $null = $sb.Append("]")
        return $sb.ToString()
    }


    Function Build-FindingsJson {
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.Append("[")
        $first = $true
        foreach ($f in $script:Findings) {
            if (-not $first) { $null = $sb.Append(",") }
            $first = $false
            $null = $sb.Append("{")
            $null = $sb.Append("""pillarId"":""$(ConvertTo-JsonSafe $f.PillarId)"",")
            $null = $sb.Append("""pillarName"":""$(ConvertTo-JsonSafe $f.PillarName)"",")
            $null = $sb.Append("""checkId"":""$(ConvertTo-JsonSafe $f.CheckId)"",")
            $null = $sb.Append("""title"":""$(ConvertTo-JsonSafe $f.Title)"",")
            $null = $sb.Append("""context"":""$(ConvertTo-JsonSafe $f.Context)"",")
            $null = $sb.Append("""currentState"":""$(ConvertTo-JsonSafe $f.CurrentState)"",")
            $null = $sb.Append("""gapAndRisk"":""$(ConvertTo-JsonSafe $f.GapAndRisk)"",")
            $null = $sb.Append("""risk"":""$(ConvertTo-JsonSafe $f.Risk)"",")
            $null = $sb.Append("""businessImpact"":""$(ConvertTo-JsonSafe $f.BusinessImpact)"",")
            $null = $sb.Append("""targetState"":""$(ConvertTo-JsonSafe $f.TargetState)"",")
            $null = $sb.Append("""transitionRecommendation"":""$(ConvertTo-JsonSafe $f.TransitionRecommendation)"",")
            $null = $sb.Append("""successMeasure"":""$(ConvertTo-JsonSafe $f.SuccessMeasure)"",")
            $null = $sb.Append("""roadmapPhase"":""$(ConvertTo-JsonSafe $f.RoadmapPhase)""")
            $null = $sb.Append("}")
        }
        $null = $sb.Append("]")
        return $sb.ToString()
    }

    #endregion

    #region ── HTML Dashboard Generation ─────────────────────────────────────────

    Function Generate-HtmlDashboard {
        param (
            [string]$TenantName,
            [string]$TenantId,
            [double]$OverallScore,
            [string]$AssessmentDate,
            [string]$PillarsJson,
            [string]$FindingsJson,
            [string]$OutputFilePath
        )

        $overallLabel = $script:MaturityLabels[[int][Math]::Round($OverallScore)]
        if (-not $overallLabel) { $overallLabel = "Initial" }

        $totalCritical = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
        $totalHigh = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
        $totalMedium = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count
        $totalLow = ($script:Findings | Where-Object { $_.Risk -eq "Low" -or $_.Risk -eq "Info" }).Count
        $totalFindings = $script:Findings.Count

        $ringPct = [int]([Math]::Round(($OverallScore / 5) * 100, 0))
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
<title>Zero Trust Readiness Assessment — __TENANT_NAME__</title>
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

/* ── Overall Readiness Ring ── */
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

/* ── Pillar Cards ── */
.pillar-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-bottom:24px}
.pillar-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;cursor:pointer;transition:all .2s;border-left:4px solid}
.pillar-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.pillar-card-header{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.pillar-icon{font-size:22px}
.pillar-name{font-size:13px;font-weight:700;flex:1}
.maturity-badge{font-size:10px;font-weight:700;padding:3px 9px;border-radius:20px;background:rgba(255,255,255,.08)}
.pillar-score-bar{height:4px;background:var(--surface3);border-radius:2px;margin-bottom:8px}
.pillar-score-fill{height:100%;border-radius:2px;transition:width 1s ease}
.pillar-zt{font-size:10px;color:var(--muted);font-style:italic;margin-bottom:8px;line-height:1.4}
.pillar-risk-chips{display:flex;gap:6px;flex-wrap:wrap}
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
.pillar-tag{font-size:10px;padding:2px 7px;border-radius:12px;background:rgba(163,113,247,.12);color:var(--accent3);font-family:var(--mono)}

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
#detailDrawer{position:absolute;right:0;top:0;height:100%;width:560px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);padding:24px;overflow-y:auto;transform:translateX(100%);transition:transform .3s cubic-bezier(.4,0,.2,1)}
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

/* ── Bar list ── */
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.bar-label{font-size:11px;color:var(--muted2);width:130px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.bar-fill{height:100%;border-radius:3px;width:0;transition:width 1s ease}
.bar-val{font-size:10px;color:var(--muted);font-family:var(--mono);width:24px;text-align:right}

/* ── ZT Arch note ── */
.zt-principle-box{background:linear-gradient(135deg,rgba(56,139,253,.08),rgba(163,113,247,.08));border:1px solid rgba(56,139,253,.2);border-radius:var(--radius);padding:14px 16px;margin-bottom:14px;font-size:12px;line-height:1.6;color:var(--muted2)}
.zt-principle-box strong{color:var(--accent)}

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
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<!-- ── Sidebar ── -->
<div id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🛡️</div>
    <div class="logo-title">Zero Trust Readiness<br>Assessment</div>
    <div class="logo-sub">Five-Pillar Enterprise Review</div>
    <div class="ver-badge">v1.0 · __ASSESSMENT_DATE__</div>
  </div>

  <nav>
    <div class="nav-section">Assessment</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span>Overview</button>
    <button class="nav-btn" onclick="showPage('pillars',this)"><span class="nav-icon">🗂️</span>Pillar Results</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span>Findings</button>
    <button class="nav-btn" onclick="showPage('roadmap',this)"><span class="nav-icon">🗺️</span>Roadmap</button>
    <div class="nav-section">Framework</div>
    <button class="nav-btn" onclick="showPage('framework',this)"><span class="nav-icon">🎯</span>ZT Framework</button>
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
      <h1>🛡️ Zero Trust Readiness Assessment</h1>
      <p>Tenant: <strong>__TENANT_NAME__</strong> &nbsp;·&nbsp; Assessment date: __ASSESSMENT_DATE__ &nbsp;·&nbsp; Total findings: __TOTAL_FINDINGS__</p>
    </div>

    <!-- Readiness Ring -->
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
        <h2>Zero Trust Readiness: __OVERALL_LABEL__</h2>
        <p>This assessment measures the organisation's readiness across the five Zero Trust pillars — Identity, Devices, Network, Data, and Applications — using the Microsoft Zero Trust Framework as the reference architecture. Evidence is drawn directly from the tenant configuration via Microsoft Graph.</p>
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
        <div class="stat-label">Pillars Assessed</div>
        <div class="stat-value" style="color:var(--accent3)">5</div>
        <div class="stat-sub">Zero Trust framework pillars</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-label">Total Findings</div>
        <div class="stat-value" style="color:var(--accent2)">__TOTAL_FINDINGS__</div>
        <div class="stat-sub">Evidence-based checks</div>
      </div>
    </div>

    <!-- Pillar Score Bars + Risk Distribution -->
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-header"><span class="panel-title">Pillar Maturity Scores</span></div>
        <div id="pillarBars"></div>
      </div>
      <div class="panel">
        <div class="panel-header"><span class="panel-title">Risk Distribution by Pillar</span></div>
        <div id="riskMatrix"></div>
      </div>
    </div>

    <!-- ZT Framework note -->
    <div class="zt-principle-box">
      <strong>Zero Trust Architecture Model</strong> — This report assesses the three core Zero Trust principles:
      <em>Verify Explicitly</em> (Identity &amp; Devices), <em>Use Least Privilege Access</em> (Data &amp; Applications), and <em>Assume Breach</em> (Network).
      Each finding follows the pattern: <strong>Context → Current State → Gaps &amp; Risks → Target State → Transition → Success Measures</strong>.
    </div>
  </div>

  <!-- ══ Pillar Results ════════════════════════════════════════════════════ -->
  <div class="page" id="page-pillars">
    <div class="page-header">
      <h1>🗂️ Pillar Results</h1>
      <p>Zero Trust maturity by pillar. Click a pillar card to explore its findings.</p>
    </div>
    <div class="pillar-grid" id="pillarGrid"></div>
  </div>

  <!-- ══ Findings ══════════════════════════════════════════════════════════ -->
  <div class="page" id="page-findings">
    <div class="page-header">
      <h1>🔍 Findings</h1>
      <p>All evidence-based Zero Trust findings, searchable and filterable. Click any row for full architectural detail.</p>
    </div>

    <div class="toolbar">
      <div class="search-wrap">
        <span class="search-icon">🔍</span>
        <input type="text" id="findSearch" placeholder="Search findings…" oninput="filterFindings()">
      </div>
      <div class="filter-pills">
        <button class="fpill fpill-all active"    onclick="setRiskFilter('All',this)">All</button>
        <button class="fpill fpill-crit"          onclick="setRiskFilter('Critical',this)">🔴 Critical</button>
        <button class="fpill fpill-high"          onclick="setRiskFilter('High',this)">🟠 High</button>
        <button class="fpill fpill-medium"        onclick="setRiskFilter('Medium',this)">🔵 Medium</button>
        <button class="fpill fpill-low"           onclick="setRiskFilter('Low',this)">🟢 Low</button>
      </div>
      <button onclick="exportFindingsCSV()" style="font-size:11px;padding:6px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--text);font-family:var(--sans)">⬇ Export CSV</button>
    </div>

    <div class="panel" style="padding:0">
      <table>
        <thead>
          <tr>
            <th id="th-risk"         onclick="sortFindings('risk')">Risk <span class="sort-arrow">↕</span></th>
            <th id="th-pillarId"     onclick="sortFindings('pillarId')">Pillar <span class="sort-arrow">↕</span></th>
            <th id="th-title"        onclick="sortFindings('title')">Finding <span class="sort-arrow">↕</span></th>
            <th id="th-roadmapPhase" onclick="sortFindings('roadmapPhase')">Phase <span class="sort-arrow">↕</span></th>
          </tr>
        </thead>
        <tbody id="findingsTbody"></tbody>
      </table>
      <div class="pagination" id="findingsPagination" style="padding:10px 14px"></div>
    </div>
  </div>

  <!-- ══ Roadmap ════════════════════════════════════════════════════════════ -->
  <div class="page" id="page-roadmap">
    <div class="page-header">
      <h1>🗺️ Zero Trust Transition Roadmap</h1>
      <p>Prioritised actions organised by implementation phase. Click any item to view the full architectural recommendation.</p>
    </div>
    <div class="roadmap-grid" id="roadmapGrid"></div>
  </div>

  <!-- ══ ZT Framework ═══════════════════════════════════════════════════════ -->
  <div class="page" id="page-framework">
    <div class="page-header">
      <h1>🎯 Zero Trust Framework — Current vs Target</h1>
      <p>Current state and target architecture for each Zero Trust pillar, with the governing principle.</p>
    </div>
    <div id="frameworkPillarList"></div>
  </div>

</div>

<!-- ── Detail Drawer ── -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDrawer()"></div>
  <div id="detailDrawer">
    <div class="drawer-header">
      <div class="drawer-title" id="drawerTitle"></div>
      <button class="drawer-close" onclick="closeDrawer()">✕</button>
    </div>
    <div class="drawer-chips" id="drawerChips"></div>
    <div class="drawer-section"><div class="drawer-label">Context — Why This Matters</div><div class="drawer-value" id="drawerContext"></div></div>
    <div class="drawer-section"><div class="drawer-label">Current State</div><div class="drawer-value" id="drawerCurrentState"></div></div>
    <div class="drawer-section"><div class="drawer-label">Gaps &amp; Risks</div><div class="drawer-value" id="drawerGapAndRisk"></div></div>
    <div class="drawer-section"><div class="drawer-label">Business Impact</div><div class="drawer-value" id="drawerImpact"></div></div>
    <div class="drawer-section"><div class="drawer-label">Target State</div><div class="drawer-value" id="drawerTarget"></div></div>
    <div class="drawer-section"><div class="drawer-label">Transition Recommendations</div><div class="drawer-value" id="drawerRec"></div></div>
    <div class="drawer-section"><div class="drawer-label">Success Measures</div><div class="drawer-value" id="drawerSuccess"></div></div>
    <div class="drawer-section"><div class="drawer-label">Roadmap Phase</div><div class="drawer-value" id="drawerPhase"></div></div>
    <div class="drawer-nav">
      <button onclick="navDrawer(-1)">← Prev</button>
      <button onclick="navDrawer(1)">Next →</button>
      <div class="drawer-count" id="drawerCount"></div>
    </div>
  </div>
</div>

<!-- ── Toast ── -->
<div id="toast"></div>

<script>
// ── Data ─────────────────────────────────────────────────────────────────────
const PILLARS  = __PILLARS_JSON__;
const FINDINGS = __FINDINGS_JSON__;

// ── Utilities ────────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
function showToast(msg,icon='✅'){const t=document.getElementById('toast');t.textContent=(icon?icon+' ':'')+msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800);}

// ── Navigation ───────────────────────────────────────────────────────────────
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn) btn.classList.add('active');
  if(id==='findings')  setTimeout(renderFindingsTable,50);
  if(id==='roadmap')   renderRoadmap();
  if(id==='pillars')   renderPillarGrid();
  if(id==='framework') renderFrameworkList();
}

// ── Theme ────────────────────────────────────────────────────────────────────
function setTheme(t){
  document.body.classList.toggle('light-theme',t==='light');
  document.getElementById('theme-dark').classList.toggle('active',t==='dark');
  document.getElementById('theme-light').classList.toggle('active',t==='light');
  localStorage.setItem('zt-theme',t);
}
(function(){const t=localStorage.getItem('zt-theme');if(t)setTheme(t);})();

// ── Overview ─────────────────────────────────────────────────────────────────
(function renderOverview(){
  const barContainer=document.getElementById('pillarBars');
  PILLARS.forEach(p=>{
    const pct=(p.maturityScore/5)*100;
    barContainer.innerHTML+=`<div class="bar-row">
      <div class="bar-label" title="${escH(p.name)}">${escH(p.icon)} ${escH(p.name)}</div>
      <div class="bar-track"><div class="bar-fill" data-pct="${pct}" style="background:${escH(p.maturityColor)}"></div></div>
      <div class="bar-val">${p.maturityScore}</div>
    </div>`;
  });

  const rmContainer=document.getElementById('riskMatrix');
  PILLARS.forEach(p=>{
    rmContainer.innerHTML+=`<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:11px">
      <span style="width:20px;text-align:center">${escH(p.icon)}</span>
      <span style="width:110px;color:var(--muted2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escH(p.name)}</span>
      <div style="display:flex;gap:3px">
        ${p.critical>0?`<span class="risk-chip rc-critical">${p.critical}C</span>`:''}
        ${p.high>0    ?`<span class="risk-chip rc-high">${p.high}H</span>`:''}
        ${p.medium>0  ?`<span class="risk-chip rc-medium">${p.medium}M</span>`:''}
        ${p.low>0     ?`<span class="risk-chip rc-low">${p.low}L</span>`:''}
        ${(p.critical+p.high+p.medium+p.low)===0?`<span class="risk-chip rc-info">✓</span>`:''}
      </div>
    </div>`;
  });

  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width=el.getAttribute('data-pct')+'%';
    });
  });
})();

// ── Pillar Grid ───────────────────────────────────────────────────────────────
function renderPillarGrid(){
  const grid=document.getElementById('pillarGrid');
  if(grid.innerHTML) return;
  PILLARS.forEach(p=>{
    const pct=(p.maturityScore/5)*100;
    grid.innerHTML+=`<div class="pillar-card" style="border-left-color:${escH(p.maturityColor)}" onclick="openPillarFindings('${escH(p.id)}')">
      <div class="pillar-card-header">
        <span class="pillar-icon">${escH(p.icon)}</span>
        <span class="pillar-name">${escH(p.name)}</span>
        <span class="maturity-badge" style="color:${escH(p.maturityColor)};border:1px solid ${escH(p.maturityColor)}">${p.maturityScore} ${escH(p.maturityLabel)}</span>
      </div>
      <div class="pillar-score-bar"><div class="pillar-score-fill" style="width:${pct}%;background:${escH(p.maturityColor)}"></div></div>
      <div class="pillar-zt">${escH(p.ztPrinciple)}</div>
      <div style="font-size:11px;color:var(--muted2);margin-bottom:10px;line-height:1.4">${escH(p.currentStateSummary)}</div>
      <div class="pillar-risk-chips">
        ${p.critical>0?`<span class="risk-chip rc-critical">${p.critical} Critical</span>`:''}
        ${p.high>0    ?`<span class="risk-chip rc-high">${p.high} High</span>`:''}
        ${p.medium>0  ?`<span class="risk-chip rc-medium">${p.medium} Medium</span>`:''}
        ${p.low>0     ?`<span class="risk-chip rc-low">${p.low} Low</span>`:''}
        ${(p.critical+p.high+p.medium+p.low)===0?`<span class="risk-chip rc-info">✓ No gaps</span>`:''}
      </div>
    </div>`;
  });
}
function openPillarFindings(pillarId){
  pillarFilter=pillarId;
  showPage('findings',document.querySelector('.nav-btn:nth-child(4)'));
  setTimeout(()=>{
    filteredFindings=FINDINGS.filter(f=>f.pillarId===pillarId);
    findingsPage=0;
    renderFindingsTable();
  },80);
}

// ── Findings Table ────────────────────────────────────────────────────────────
let filteredFindings=[...FINDINGS];
let findingsPage=0;
const PAGE_SIZE=15;
let sortCol='risk';
let sortDir=1;
let riskFilter='All';
let pillarFilter=null;
const RISK_ORDER={Critical:0,High:1,Medium:2,Low:3,Info:4};

function setRiskFilter(r,el){
  riskFilter=r;
  pillarFilter=null;
  document.querySelectorAll('.fpill').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  filterFindings();
}
function filterFindings(){
  const q=(document.getElementById('findSearch').value||'').toLowerCase();
  filteredFindings=FINDINGS.filter(f=>{
    const rMatch=riskFilter==='All'||(riskFilter==='Low'?f.risk==='Low'||f.risk==='Info':f.risk===riskFilter);
    const pMatch=!pillarFilter||f.pillarId===pillarFilter;
    const qMatch=!q||f.title.toLowerCase().includes(q)||f.pillarName.toLowerCase().includes(q)||f.checkId.toLowerCase().includes(q);
    return rMatch&&pMatch&&qMatch;
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
    let av=a[sortCol]||'',bv=b[sortCol]||'';
    if(sortCol==='risk'){av=RISK_ORDER[a.risk]??9;bv=RISK_ORDER[b.risk]??9;return sortDir*(av-bv);}
    if(sortCol==='roadmapPhase'){const ord={'0-30 Days':0,'31-60 Days':1,'61-90 Days':2,'Strategic':3};av=ord[av]??9;bv=ord[bv]??9;return sortDir*(av-bv);}
    return sortDir*String(av).localeCompare(String(bv));
  });
}
function renderFindingsTable(){
  sortFindingsData();
  const tbody=document.getElementById('findingsTbody');
  const start=findingsPage*PAGE_SIZE;
  const slice=filteredFindings.slice(start,start+PAGE_SIZE);
  tbody.innerHTML=slice.map((f,i)=>`<tr onclick="openFinding(${start+i})" style="cursor:pointer">
    <td><span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span></td>
    <td><span class="pillar-tag">${escH(f.pillarId)}</span> <span style="font-size:10px;color:var(--muted)">${escH(f.pillarName)}</span></td>
    <td style="max-width:360px">${escH(f.title)}</td>
    <td><span class="phase-badge">${escH(f.roadmapPhase)}</span></td>
  </tr>`).join('');

  const totalPages=Math.ceil(filteredFindings.length/PAGE_SIZE);
  const pg=document.getElementById('findingsPagination');
  let html='';
  if(totalPages>1){
    html+=`<button class="pg-btn" onclick="goPage(${findingsPage-1})" ${findingsPage===0?'disabled':''}>‹</button>`;
    for(let p=0;p<totalPages;p++){html+=`<button class="pg-btn${p===findingsPage?' active':''}" onclick="goPage(${p})">${p+1}</button>`;}
    html+=`<button class="pg-btn" onclick="goPage(${findingsPage+1})" ${findingsPage===totalPages-1?'disabled':''}>›</button>`;
  }
  html+=`<span class="pg-info">${filteredFindings.length} finding${filteredFindings.length!==1?'s':''}</span>`;
  pg.innerHTML=html;
}
function goPage(p){
  const totalPages=Math.ceil(filteredFindings.length/PAGE_SIZE);
  if(p<0||p>=totalPages) return;
  findingsPage=p;
  renderFindingsTable();
}

// ── Detail Drawer ─────────────────────────────────────────────────────────────
let currentDrawerIndex=-1;
let drawerList=[];

function openFinding(idx){
  drawerList=filteredFindings;
  currentDrawerIndex=idx;
  populateDrawer(drawerList[idx]);
  document.getElementById('detailPanel').classList.add('open');
}
function populateDrawer(f){
  if(!f) return;
  const phaseColors={'0-30 Days':'#f85149','31-60 Days':'#d29922','61-90 Days':'#388bfd','Strategic':'#3fb950'};
  document.getElementById('drawerTitle').textContent=f.title;
  document.getElementById('drawerChips').innerHTML=
    `<span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span>`+
    `<span class="pillar-tag">${escH(f.pillarId)} · ${escH(f.pillarName)}</span>`+
    `<span style="font-size:10px;padding:2px 8px;border-radius:12px;background:rgba(255,255,255,.06);color:${phaseColors[f.roadmapPhase]||'var(--muted)'};font-family:var(--mono)">${escH(f.roadmapPhase)}</span>`+
    `<span style="font-size:10px;color:var(--muted);font-family:var(--mono)">${escH(f.checkId)}</span>`;
  document.getElementById('drawerContext').textContent     = f.context;
  document.getElementById('drawerCurrentState').textContent= f.currentState;
  document.getElementById('drawerGapAndRisk').textContent  = f.gapAndRisk;
  document.getElementById('drawerImpact').textContent      = f.businessImpact;
  document.getElementById('drawerTarget').textContent      = f.targetState;
  document.getElementById('drawerRec').textContent         = f.transitionRecommendation;
  document.getElementById('drawerSuccess').textContent     = f.successMeasure;
  document.getElementById('drawerPhase').textContent       = f.roadmapPhase;
  document.getElementById('drawerCount').textContent       = `${currentDrawerIndex+1} / ${drawerList.length}`;
}
function navDrawer(dir){
  const next=currentDrawerIndex+dir;
  if(next<0||next>=drawerList.length) return;
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
    items.forEach((f)=>{
      const idx=FINDINGS.indexOf(f);
      col.innerHTML+=`<div class="roadmap-item" onclick="openFinding(${idx})">
        <div class="roadmap-item-title">${escH(f.title)}</div>
        <div class="roadmap-item-meta">
          <span class="risk-badge rb-${escH(f.risk)}" style="font-size:9px">${escH(f.risk)}</span>
          <span class="pillar-tag" style="font-size:9px">${escH(f.pillarId)}</span>
        </div>
      </div>`;
    });
    grid.appendChild(col);
  });
}

// ── ZT Framework List ─────────────────────────────────────────────────────────
function renderFrameworkList(){
  const c=document.getElementById('frameworkPillarList');
  if(c.innerHTML) return;
  PILLARS.forEach(p=>{
    c.innerHTML+=`<div style="margin-bottom:16px;padding:16px;background:var(--surface);border-radius:var(--radius);border:1px solid var(--border);border-left:4px solid ${escH(p.maturityColor)}">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <span style="font-size:20px">${escH(p.icon)}</span>
        <span style="font-size:14px;font-weight:700">${escH(p.name)}</span>
        <span style="font-size:10px;padding:2px 9px;border-radius:20px;color:${escH(p.maturityColor)};border:1px solid ${escH(p.maturityColor)};font-family:var(--mono)">${p.maturityScore} ${escH(p.maturityLabel)}</span>
      </div>
      <div style="font-size:11px;color:var(--accent3);font-style:italic;margin-bottom:8px">${escH(p.ztPrinciple)}</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:10px">
        <div>
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:5px;font-weight:700">Current State</div>
          <div style="font-size:12px;color:var(--muted2);background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px;border:1px solid var(--border);line-height:1.5">${escH(p.currentStateSummary)}</div>
        </div>
        <div>
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--accent);margin-bottom:5px;font-weight:700">Target State</div>
          <div style="font-size:12px;color:var(--muted2);background:rgba(56,139,253,.06);border-radius:var(--radius-sm);padding:10px 12px;border:1px solid rgba(56,139,253,.2);line-height:1.5">${escH(p.targetStateSummary)}</div>
        </div>
      </div>
    </div>`;
  });
}

// ── CSV Export ────────────────────────────────────────────────────────────────
function exportFindingsCSV(){
  const fields=['pillarId','pillarName','checkId','title','risk','roadmapPhase','context','currentState','gapAndRisk','businessImpact','targetState','transitionRecommendation','successMeasure'];
  const header=fields.join(',');
  const rows=filteredFindings.map(f=>fields.map(k=>'"'+(String(f[k]||'')).replace(/"/g,'""')+'"').join(','));
  const csv=[header,...rows].join('\r\n');
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download='ZeroTrustFindings.csv';
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
    if(e.key==='ArrowLeft')  navDrawer(-1);
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
        $ringColorForScore = $script:MaturityColors[[int][Math]::Round($OverallScore)]
        if (-not $ringColorForScore) { $ringColorForScore = "#f85149" }

        $html = $html `
            -replace '__TENANT_NAME__', $TenantName `
            -replace '__TENANT_ID__', $TenantId `
            -replace '__ASSESSMENT_DATE__', $AssessmentDate `
            -replace '__OVERALL_SCORE__', $OverallScore `
            -replace '__OVERALL_LABEL__', $overallLabel `
            -replace '__TOTAL_CRITICAL__', $totalCritical `
            -replace '__TOTAL_HIGH__', $totalHigh `
            -replace '__TOTAL_MEDIUM__', $totalMedium `
            -replace '__TOTAL_LOW__', $totalLow `
            -replace '__TOTAL_FINDINGS__', $totalFindings `
            -replace '__RING_COLOR__', $ringColorForScore `
            -replace '__RING_DASH__', $ringDash `
            -replace '__RING_GAP__', $ringGap `
            -replace '__PILLARS_JSON__', $PillarsJson `
            -replace '__FINDINGS_JSON__', $FindingsJson

        $html | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
    }

    #endregion

    #region ── JSON Export ────────────────────────────────────────────────────────

    Function Export-AssessmentJson {
        param (
            [string]$TenantName,
            [string]$TenantId,
            [double]$OverallScore,
            [string]$AssessmentDate,
            [string]$OutputFilePath
        )

        $exportObj = [PSCustomObject]@{
            schemaVersion    = "1.0"
            assessmentTool   = "Invoke-ZeroTrustReadinessAssessment"
            assessmentDate   = $AssessmentDate
            tenantName       = $TenantName
            tenantId         = $TenantId
            overallScore     = $OverallScore
            overallLabel     = $script:MaturityLabels[[int][Math]::Round($OverallScore)]
            totalFindings    = $script:Findings.Count
            criticalFindings = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
            highFindings     = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
            mediumFindings   = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count
            pillars          = $script:Pillars
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
    Write-Host "  ║      Zero Trust Readiness Assessment  v1.0                   ║" -ForegroundColor Cyan
    Write-Host "  ║      Five-Pillar Enterprise Security Posture Review          ║" -ForegroundColor Cyan
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
    Write-Host "  │   STEP 1  ›  Authenticating to Microsoft Graph              │" -ForegroundColor DarkCyan
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
        "DeviceManagementConfiguration.Read.All"
        "DeviceManagementManagedDevices.Read.All"
        "InformationProtectionPolicy.Read.All"
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
        Write-Host "  Assessment will continue with available permissions." -ForegroundColor Yellow
        Write-Host "  Some pillar checks may return partial or insufficient data." -ForegroundColor Yellow
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

    # ── Step 3: Pillar Assessments ────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 3  ›  Running Five-Pillar Zero Trust Assessment      │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    Invoke-Pillar1-Identity
    Invoke-Pillar2-Devices
    Invoke-Pillar3-Network
    Invoke-Pillar4-Data
    Invoke-Pillar5-Applications

    Write-Host ""
    Write-Host "  ✅ All five pillar assessments complete." -ForegroundColor Green
    Write-Host ""

    # ── Step 4: Score ─────────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 4  ›  Computing Overall Zero Trust Readiness Score    │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $overallScore = Get-OverallReadinessScore
    $overallLabel = $script:MaturityLabels[[int][Math]::Round($overallScore)]
    $totalCritical = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
    $totalHigh = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
    $totalMedium = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count

    Write-Host "  📊 Overall ZT Readiness: $overallScore / 5.0 ($overallLabel)" -ForegroundColor Cyan
    Write-Host "  🔴 Critical: $totalCritical  |  🟠 High: $totalHigh  |  🔵 Medium: $totalMedium" -ForegroundColor Gray
    Write-Host ""

    # ── Step 5: Export ─────────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 5  ›  Generating Reports                             │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $htmlPath = Join-Path $OutputPath "ZeroTrustReadinessAssessment_$timestamp.html"
    $jsonPath = Join-Path $OutputPath "ZeroTrustReadinessAssessment_$timestamp.json"
    $assessDate = (Get-Date).ToString("dd MMM yyyy HH:mm")

    Write-Host "  ⏳ Building HTML dashboard..." -ForegroundColor Yellow
    $pillarsJson = Build-PillarsJson
    $findingsJson = Build-FindingsJson

    Generate-HtmlDashboard `
        -TenantName    $tenantName `
        -TenantId      $TenantId `
        -OverallScore  $overallScore `
        -AssessmentDate $assessDate `
        -PillarsJson   $pillarsJson `
        -FindingsJson  $findingsJson `
        -OutputFilePath $htmlPath

    Write-Host "  ✅ HTML dashboard written → $htmlPath" -ForegroundColor Green

    Write-Host "  ⏳ Exporting JSON assessment..." -ForegroundColor Yellow
    Export-AssessmentJson `
        -TenantName    $tenantName `
        -TenantId      $TenantId `
        -OverallScore  $overallScore `
        -AssessmentDate $assessDate `
        -OutputFilePath $jsonPath

    Write-Host "  ✅ JSON export written → $jsonPath" -ForegroundColor Green
    Write-Host ""

    # ── Execution Summary ─────────────────────────────────────────────────────────
    $scriptEndTime = Get-Date
    $executionTime = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime

    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║              ZERO TRUST ASSESSMENT SUMMARY                   ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  🏛️ Tenant              : $($tenantName.PadRight(32))║" -ForegroundColor White
    Write-Host "  ║  🛡️ ZT Readiness        : $("$overallScore / 5.0 ($overallLabel)".PadRight(32))║" -ForegroundColor Cyan
    Write-Host "  ║  🔴 Critical Findings   : $($totalCritical.ToString().PadRight(32))║" -ForegroundColor Red
    Write-Host "  ║  🟠 High Findings       : $($totalHigh.ToString().PadRight(32))║" -ForegroundColor Yellow
    Write-Host "  ║  🔵 Medium Findings     : $($totalMedium.ToString().PadRight(32))║" -ForegroundColor Blue
    Write-Host "  ║  📋 Total Findings      : $(($script:Findings.Count).ToString().PadRight(32))║" -ForegroundColor Gray
    Write-Host "  ║  🕐 Started             : $($scriptStartTime.ToString('hh:mm:ss tt').PadRight(32))║" -ForegroundColor Gray
    Write-Host "  ║  🕑 Ended               : $($scriptEndTime.ToString('hh:mm:ss tt').PadRight(32))║" -ForegroundColor Gray
    Write-Host "  ║  ⏱️ Duration            : $($executionTime.ToString('hh\:mm\:ss').PadRight(32))║" -ForegroundColor Yellow
    Write-Host "  ║  🌐 HTML Dashboard      : $(('...' + $htmlPath.Substring([Math]::Max(0,$htmlPath.Length-29))).PadRight(32))║" -ForegroundColor Green
    Write-Host "  ║  📄 JSON Export         : $(('...' + $jsonPath.Substring([Math]::Max(0,$jsonPath.Length-29))).PadRight(32))║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    #endregion
}
