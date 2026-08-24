<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 24 August 2026
Modified-On  : 24 August 2026

.SYNOPSIS
    Assesses the Conditional Access architecture at an enterprise level and produces a
    maturity-rated, gap-analysed, risk-prioritised architecture assessment report.

.DESCRIPTION
    This script connects to Microsoft Graph (BYOT or Client Credentials) and evaluates
    the Conditional Access policy landscape across eight architectural domains, moving
    well beyond raw policy reporting to deliver an architect-level assessment:

        Domain 1  — Policy Coverage & Baseline Architecture
        Domain 2  — Policy Coherence, Overlaps & Conflicts
        Domain 3  — Exclusion Governance & Shadow Populations
        Domain 4  — Privileged Identity Protection
        Domain 5  — Emergency Access & Break-Glass Coverage
        Domain 6  — Authentication Strength & Risk Controls
        Domain 7  — Device & Application Compliance Controls
        Domain 8  — Policy Sprawl & Operational Manageability

    For each domain, the script follows this architectural thinking model:

        Context → Current State → Gap/Risk → Target State → Transition Recommendation → Success Measures

    The assessment answers the following architectural questions:
        - Is the CA policy model coherent and intentional?
        - Are policies overlapping or creating contradictory outcomes?
        - Where are the important control gaps?
        - Are exclusions creating unintended security exposure?
        - How well are privileged and emergency identities protected?
        - Is the policy landscape becoming difficult to manage and maintain?
        - What should the target architecture look like?
        - What changes should be prioritised, and why?

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
        - HTML interactive architecture assessment dashboard (light/dark theme)
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
    Default: C:\Temp\EntraCAAssessment

.PARAMETER ShowHelp
    Displays a plain-language usage guide and exits immediately.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        HTML dashboard: <OutputPath>\EntraCAArchitectureAssessment_<timestamp>.html
        JSON export   : <OutputPath>\EntraCAArchitectureAssessment_<timestamp>.json

.EXAMPLE
    Get-EntraConditionalAccessArchitectureAssessment -ShowHelp

    Displays the friendly usage guide and exits.

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraConditionalAccessArchitectureAssessment `
        -AuthMode ClientCredentials `
        -ClientId  "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId "f4310b4f-xxxx"

    Full CA architecture assessment using app-only Client Credentials auth.

.EXAMPLE
    $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    Get-EntraConditionalAccessArchitectureAssessment `
        -AuthMode BYOT `
        -AccessToken $token `
        -TenantId "f4310b4f-xxxx"

    Full CA architecture assessment using a pre-obtained bearer token (BYOT).

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraConditionalAccessArchitectureAssessment `
        -AuthMode ClientCredentials `
        -ClientId  "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId "f4310b4f-xxxx" `
        -OutputPath "D:\Reports\CAAssessment"

    Assessment with custom output directory.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (24-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. App Registration (Client Credentials mode) with admin-consented
           Application permissions:
               Policy.Read.All                 (Conditional Access policies, named locations)
               Directory.Read.All              (users, groups, roles, service principals)
               RoleManagement.Read.Directory   (PIM, role definitions, assignments)
               Application.Read.All            (service principals for app-based conditions)
               AuditLog.Read.All               (sign-in logs for CA impact analysis)

        2. BYOT mode: the delegated or application token must carry the same
           scopes as above. Delegated tokens require the caller to be at minimum
           a Global Reader or Conditional Access Administrator (read-only).

        3. Entra ID P1 minimum. P2 required for:
               - PIM eligible role detection (Domain 4)
               - Risk-based CA policy analysis (Domain 6)

        4. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  → Show help and exit if -ShowHelp
        Step 1  → Authenticate (BYOT or Client Credentials)
        Step 2  → Collect CA baseline data (policies, named locations, auth strengths)
        Step 3  → Run domain assessments 1–8
        Step 4  → Score domains, compute overall maturity
        Step 5  → Build prioritised finding list with recommendations
        Step 6  → Export HTML dashboard + JSON

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the /beta Graph endpoint. Beta APIs are subject to change.
        - PIM and Identity Protection data require Entra ID P2. Domains relying
          on these gracefully degrade to "Insufficient Data" when P2 is absent.
        - Policy evaluation is configuration-based. This script does not simulate
          runtime policy evaluation against real sign-in sessions.
        - Sign-in log analysis requires AuditLog.Read.All and is limited to the
          last 30 days of available log data.
        - Group membership transitive expansion is not performed due to Graph API
          cost — exclusion analysis is based on direct group references only.

.LINK
    https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview
.LINK
    https://learn.microsoft.com/en-us/entra/architecture/
.LINK
    https://learn.microsoft.com/en-us/security/zero-trust/
.LINK
    https://learn.microsoft.com/en-us/graph/api/overview

#>


Function Get-EntraConditionalAccessArchitectureAssessment {
    [CmdletBinding(DefaultParameterSetName = "ClientCredentials")]
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
        [string]$OutputPath = "C:\Temp\EntraCAAssessment",

        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    #region ── Friendly Help ──────────────────────────────────────────────────────

    Function Show-FriendlyHelp {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║    Entra ID Conditional Access Architecture Assessment v1.0  ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  PURPOSE" -ForegroundColor Yellow
        Write-Host "    Assesses your Conditional Access architecture across 8 domains."
        Write-Host "    Identifies overlaps, conflicts, gaps, exclusion risks, and policy"
        Write-Host "    sprawl. Produces a prioritised architecture and security roadmap."
        Write-Host ""
        Write-Host "  AUTHENTICATION" -ForegroundColor Yellow
        Write-Host "    Client Credentials (app-only):"
        Write-Host '      $secret = Read-Host "Client secret" -AsSecureString'
        Write-Host '      Get-EntraConditionalAccessArchitectureAssessment \'
        Write-Host '          -AuthMode ClientCredentials \'
        Write-Host '          -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "    BYOT (Bring Your Own Token):"
        Write-Host '      $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken'
        Write-Host '      Get-EntraConditionalAccessArchitectureAssessment \'
        Write-Host '          -AuthMode BYOT -AccessToken $token -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "  REQUIRED APP PERMISSIONS (Application, admin-consented)" -ForegroundColor Yellow
        Write-Host "    Policy.Read.All, Directory.Read.All,"
        Write-Host "    RoleManagement.Read.Directory, Application.Read.All,"
        Write-Host "    AuditLog.Read.All"
        Write-Host ""
        Write-Host "  LICENSE REQUIREMENTS" -ForegroundColor Yellow
        Write-Host "    P1 minimum. P2 required for PIM eligible roles and risk-based CA analysis."
        Write-Host ""
        Write-Host "  For full documentation: Get-Help Get-EntraConditionalAccessArchitectureAssessment -Full"
        Write-Host ""
    }

    if ($ShowHelp) {
        Show-FriendlyHelp
        return
    }

    #endregion

    #region ── Token Management ───────────────────────────────────────────────────

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
        Catch {
            return @{
                Valid              = $false
                MissingPermissions = $RequiredPermissions
            }
        }
    }

    #endregion

    #region ── Graph API Helpers ──────────────────────────────────────────────────

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

    $script:RiskColors = @{
        "Critical" = "#f85149"
        "High"     = "#d29922"
        "Medium"   = "#388bfd"
        "Low"      = "#3fb950"
        "Info"     = "#7d8590"
    }

    $script:Domains = [System.Collections.ArrayList]::new()
    $script:Findings = [System.Collections.ArrayList]::new()


    Function Add-Finding {
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
            [string]$SuccessMeasure,
            [ValidateSet("0-30 Days", "31-60 Days", "61-90 Days", "Strategic")]
            [string]$RoadmapPhase,
            [int]$MaturityContribution = 0
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
                SuccessMeasure       = $SuccessMeasure
                RoadmapPhase         = $RoadmapPhase
                MaturityContribution = $MaturityContribution
            })
    }


    Function Set-DomainResult {
        param (
            [string]$Id,
            [string]$Name,
            [string]$Icon,
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

    #region ── CA Baseline Data Collection ───────────────────────────────────────

    Function Get-CABaselineData {
        Write-Host "  📥 Collecting Conditional Access baseline data..." -ForegroundColor Yellow

        # All CA policies
        $script:AllCAPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $script:EnabledPolicies = @($script:AllCAPolicies | Where-Object { $_.state -eq "enabled" })
        $script:ReportOnlyPolicies = @($script:AllCAPolicies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" })
        $script:DisabledPolicies = @($script:AllCAPolicies | Where-Object { $_.state -eq "disabled" })

        # Named locations
        $script:NamedLocations = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations"

        # Authentication strength policies
        $authStrengthData = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/authenticationStrengthPolicies"
        $script:AuthStrengths = if ($authStrengthData -and $authStrengthData.value) { $authStrengthData.value } else { @() }

        # Roles (for privileged identity analysis)
        $script:PrivilegedRoles = @(
            "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
            "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", # Application Administrator
            "c4e39bd9-1100-46d3-8c65-fb160da0071f", # Authentication Administrator
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", # Privileged Authentication Administrator
            "b0f54661-2d74-4c50-afa3-1ec803f12efe", # Billing Administrator
            "729827e3-9c14-49f7-bb1b-9608f156bbb8", # Helpdesk Administrator
            "966707d0-3269-4727-9be2-8c3a10f19b9d", # Password Administrator
            "69091246-20e8-4a56-aa4d-066075b2a7a8"  # Teams Administrator
        )

        # Break-glass / emergency accounts (accounts excluded from CA policies broadly)
        # We discover these by analysing patterns, not a dedicated API

        # Groups for cross-referencing
        $script:GroupCache = @{}

        Write-Host "  ✅ Baseline collected — $($script:AllCAPolicies.Count) total CA policies ($($script:EnabledPolicies.Count) enabled, $($script:ReportOnlyPolicies.Count) report-only, $($script:DisabledPolicies.Count) disabled)" -ForegroundColor Green
        Write-Host "  ✅ Named Locations: $($script:NamedLocations.Count) | Authentication Strengths: $($script:AuthStrengths.Count)" -ForegroundColor Green
        Write-Host ""
    }


    Function Resolve-GroupDisplayName {
        param ([string]$GroupId)
        if (-not $GroupId) { return $GroupId }
        if ($script:GroupCache.ContainsKey($GroupId)) { return $script:GroupCache[$GroupId] }

        Try {
            $grp = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/groups/$GroupId`?`$select=id,displayName"
            $name = if ($grp -and $grp.displayName) { $grp.displayName } else { $GroupId }
            $script:GroupCache[$GroupId] = $name
            return $name
        }
        Catch {
            $script:GroupCache[$GroupId] = $GroupId
            return $GroupId
        }
    }

    #endregion

    #region ── Domain 1: Policy Coverage & Baseline Architecture ─────────────────

    Function Invoke-Domain1-PolicyCoverage {
        Write-Host "  🏗️ D1: Policy Coverage & Baseline Architecture..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $enabled = $script:EnabledPolicies
        $reportOnly = $script:ReportOnlyPolicies
        $disabled = $script:DisabledPolicies

        # ── Check 1.1: No CA policies at all ─────────────────────────────────────
        if ($enabled.Count -eq 0 -and $reportOnly.Count -eq 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D1" -DomainName "Policy Coverage" -CheckId "D1.1" `
                -Title "No Conditional Access Policies Exist — Zero Trust Authentication Architecture Absent" `
                -Evidence "Total CA policies: $($script:AllCAPolicies.Count) | Enabled: 0 | Report-only: 0 | Disabled: $($disabled.Count)" `
                -CurrentState "The tenant has no Conditional Access policies in any state. Authentication is entirely ungoverned." `
                -Gap "No authentication controls exist. Every sign-in from any location, device, or protocol succeeds with valid credentials alone." `
                -Risk "Critical" `
                -BusinessImpact "Maximum authentication attack surface. Any valid credential pair grants unrestricted access to all cloud resources from any location, device, or protocol — including legacy auth endpoints that bypass all modern controls." `
                -TargetState "A baseline CA policy stack covering: MFA for all users, MFA for admins with higher strength, legacy auth block, compliant device for sensitive apps, risk-based sign-in block." `
                -Recommendation "Implement the Microsoft CA baseline template immediately. Deploy all policies in Report-Only first, validate impact using Insights & Reporting, then enable. Sequence: (1) block legacy auth, (2) MFA for all users, (3) admin protection, (4) risky sign-in block, (5) device compliance." `
                -SuccessMeasure "All five baseline policies enabled within 30 days. Zero legacy auth sign-ins in Sign-In logs. 100% MFA challenge rate for interactive sign-ins." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1

            Set-DomainResult -Id "D1" -Name "Policy Coverage" -Icon "🏗️" `
                -MaturityScore 1 `
                -CurrentStateSummary "No CA policies exist. Entire authentication layer is ungoverned." `
                -TargetStateSummary "Full CA baseline: MFA all users, admin protection, legacy auth block, risk controls, device compliance." `
                -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
            return
        }

        # ── Check 1.2: Only report-only policies, none enabled ────────────────────
        if ($enabled.Count -eq 0 -and $reportOnly.Count -gt 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D1" -DomainName "Policy Coverage" -CheckId "D1.1b" `
                -Title "CA Policies Exist Only in Report-Only Mode — No Active Enforcement ($($reportOnly.Count) policies)" `
                -Evidence "Enabled: 0 | Report-only: $($reportOnly.Count) | Disabled: $($disabled.Count)" `
                -CurrentState "All CA policies are in report-only (monitoring) mode. No policies are actively enforcing controls." `
                -Gap "Report-only policies provide telemetry but no protection. Every sign-in from any device or location succeeds without any authentication challenge." `
                -Risk "Critical" `
                -BusinessImpact "Identical risk exposure to having no CA policies. Report-only mode is an assessment phase, not a security control — all access paths remain open." `
                -TargetState "All baseline policies promoted to Enabled. Report-only used only for short-duration impact assessment of new policies before promotion." `
                -Recommendation "Promote report-only policies to Enabled after reviewing impact in CA Insights & Reporting workbook. Prioritise blocking legacy auth and requiring MFA for all users. Set a 30-day deadline for each report-only policy." `
                -SuccessMeasure "All baseline policies enabled. Report-only count = 0. Zero unprotected sign-in paths in Insights workbook." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 3
        }

        # ── Check 1.3: Baseline coverage — MFA for all users ─────────────────────
        $mfaAllUsersPolicy = $enabled | Where-Object {
            ($_.conditions.users.includeUsers -contains "All" -or
            $_.conditions.users.includeUsers -contains "GuestsOrExternalUsers") -and
            ($_.conditions.applications.includeApplications -contains "All" -or
            $_.conditions.applications.includeApplications.Count -gt 3) -and
            $_.grantControls -and
            ($_.grantControls.builtInControls -contains "mfa" -or
            $_.grantControls.authenticationStrength -ne $null)
        }

        if ($mfaAllUsersPolicy.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D1" -DomainName "Policy Coverage" -CheckId "D1.2" `
                -Title "No CA Policy Requiring MFA for All Users on All Cloud Apps" `
                -Evidence "Enabled policies with All Users scope + MFA grant: 0 of $($enabled.Count) enabled policies" `
                -CurrentState "No enabled CA policy enforces MFA across all users and all cloud applications. MFA may be enforced selectively or not at all." `
                -Gap "Users without an MFA-requiring CA policy can authenticate using credentials only. This is the primary mechanism by which credential-stuffing and phishing attacks succeed in cloud environments." `
                -Risk "High" `
                -BusinessImpact "Without universal MFA enforcement, the credential attack surface covers every user account in the tenant. A single compromised password enables full account takeover. This gap represents the highest-frequency Entra ID attack vector." `
                -TargetState "A single CA policy scoped to All Users → All Cloud Apps → Require MFA (or Authentication Strength: Multifactor authentication) as the foundational control. All other policies build on this baseline." `
                -Recommendation "Create a CA policy: All Users → All Cloud Apps → Grant: Require MFA. Exclude break-glass accounts only. Deploy in report-only first, then enable. If a more specific MFA policy exists, ensure it covers 100% of the user population without gaps." `
                -SuccessMeasure "100% of interactive sign-ins challenged with MFA. Zero MFA bypass in Insights workbook. MFA registration report >99%." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D1" -DomainName "Policy Coverage" -CheckId "D1.2" `
                -Title "MFA for All Users Policy Present ($($mfaAllUsersPolicy.Count) matching polic$(if($mfaAllUsersPolicy.Count -eq 1){'y'}else{'ies'}))" `
                -Evidence "Policies with All-Users MFA coverage: $($mfaAllUsersPolicy.Count) | Policy names: $(($mfaAllUsersPolicy.displayName | Select-Object -First 2) -join ', ')" `
                -CurrentState "At least one enabled CA policy enforces MFA for all users across cloud applications." `
                -Gap "Validate that exclusion groups on this policy are minimal, governed, and time-limited. A broad exclusion list creates a shadow population outside MFA control." `
                -Risk "Info" `
                -BusinessImpact "Low — MFA baseline is enforced. Monitor exclusion group membership and ensure break-glass accounts are the only long-term exclusions." `
                -TargetState "MFA for all users active with zero business-user exclusions. Break-glass accounts excluded and separately monitored. Authentication Strength policy preferred over basic MFA grant." `
                -Recommendation "Audit exclusion groups on this policy quarterly. Migrate from basic MFA grant to Authentication Strength for stronger assurance. Consider Require MFA + Require authentication strength layering for sensitive apps." `
                -SuccessMeasure "Exclusion group membership <5 accounts (break-glass only). Authentication Strength adopted. CA Insights shows <0.1% MFA bypass rate." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 1.4: Legacy authentication block ────────────────────────────────
        $legacyBlockPolicy = $enabled | Where-Object {
            ($_.conditions.clientAppTypes -contains "exchangeActiveSync" -or
            $_.conditions.clientAppTypes -contains "other") -and
            $_.grantControls -and
            $_.grantControls.builtInControls -contains "block"
        }

        if ($legacyBlockPolicy.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D1" -DomainName "Policy Coverage" -CheckId "D1.3" `
                -Title "No CA Policy Blocking Legacy Authentication Protocols" `
                -Evidence "Enabled CA policies blocking exchangeActiveSync or 'other' client app types: 0" `
                -CurrentState "Legacy authentication protocols (SMTP AUTH, POP3, IMAP, Basic Auth, EAS) are not blocked by Conditional Access." `
                -Gap "Legacy protocols inherently bypass MFA by design. All MFA CA policies are ineffective against legacy auth sign-ins. This is a fundamental architectural gap that nullifies MFA controls for users who have legacy clients." `
                -Risk "High" `
                -BusinessImpact "Password spray and credential-stuffing attack toolkits specifically target legacy authentication endpoints because they bypass all modern authentication controls including MFA. This is the #1 initial access vector in M365 environments." `
                -TargetState "All legacy authentication blocked tenant-wide with no exceptions for standard users. Service accounts that require legacy auth identified, documented, and isolated via named locations or IP restrictions." `
                -Recommendation "Create CA policy: All Users → All Cloud Apps → Client apps: Exchange ActiveSync + Other → Block. Deploy in report-only for 7 days to identify impacted accounts. Review Sign-In logs filtered by 'Legacy Authentication Protocols'. Enable after validating service account impacts." `
                -SuccessMeasure "Zero legacy auth sign-ins in Sign-In logs (excluding explicitly approved service accounts). No CA policy allows legacy auth for standard users." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D1" -DomainName "Policy Coverage" -CheckId "D1.3" `
                -Title "Legacy Authentication Blocked via CA Policy ($($legacyBlockPolicy.Count) polic$(if($legacyBlockPolicy.Count -eq 1){'y'}else{'ies'}))" `
                -Evidence "Policies blocking legacy auth client app types: $($legacyBlockPolicy.Count) | Names: $(($legacyBlockPolicy.displayName | Select-Object -First 2) -join ', ')" `
                -CurrentState "Legacy authentication is blocked by Conditional Access." `
                -Gap "Verify: no exclusion groups inadvertently re-open legacy auth for users, and the block covers both 'exchangeActiveSync' and 'other' client app types." `
                -Risk "Info" `
                -BusinessImpact "Low — legacy auth block is a critical baseline control that is in place. Focus on ensuring no exceptions exist for standard users." `
                -TargetState "Zero legacy auth sign-ins tenant-wide. All service accounts requiring legacy auth migrated to OAuth / modern authentication." `
                -Recommendation "Quarterly review of exclusion groups on this policy. Monitor Sign-In logs for legacy auth attempts from excluded accounts. Plan migration of any legacy service accounts to OAuth 2.0." `
                -SuccessMeasure "Legacy auth sign-in count = 0 in monthly Sign-In log export. All service accounts on OAuth." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 1.5: Admin-specific MFA/protection policy ───────────────────────
        $adminProtectionPolicy = $enabled | Where-Object {
            ($_.conditions.users.includeRoles -and $_.conditions.users.includeRoles.Count -gt 0) -and
            $_.grantControls -and
            ($_.grantControls.builtInControls -contains "mfa" -or
            $_.grantControls.authenticationStrength -ne $null -or
            $_.grantControls.builtInControls -contains "compliantDevice")
        }

        if ($adminProtectionPolicy.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D1" -DomainName "Policy Coverage" -CheckId "D1.4" `
                -Title "No CA Policy Specifically Protecting Privileged / Admin Roles" `
                -Evidence "Enabled CA policies scoped to directory roles with MFA or device compliance: 0" `
                -CurrentState "No CA policy applies differentiated controls to privileged roles. Administrators receive the same authentication requirements as standard users (if any MFA policy exists at all)." `
                -Gap "Privileged roles represent the highest-value targets in any identity attack. They should face stronger authentication requirements than standard users — phishing-resistant MFA, compliant device, session controls. Without differentiated admin protection, a compromised admin credential equals full tenant compromise." `
                -Risk "High" `
                -BusinessImpact "Global Administrator, Privileged Role Administrator, and equivalent roles provide complete control of the Entra ID tenant, all Azure subscriptions, and all M365 data. A single compromised admin session enables irreversible tenant takeover including disabling all security controls." `
                -TargetState "A CA policy scoped to all privileged roles requiring: (1) phishing-resistant MFA (Authentication Strength), (2) compliant or Hybrid Azure AD joined device, (3) no persistent browser session, (4) sign-in frequency of 1 hour, (5) Sign-in risk block at Medium+." `
                -Recommendation "Create a CA policy targeting all privileged role IDs (Global Admin, Priv Role Admin, Security Admin, Auth Admin, Application Admin, etc.). Apply Authentication Strength requiring phishing-resistant MFA (FIDO2/WHfB/CBA). Add compliant device requirement. Set sign-in frequency to 1 hour. Exclude break-glass accounts." `
                -SuccessMeasure "All privileged role sign-ins use phishing-resistant MFA. Zero admin sign-ins from non-compliant devices. Admin session frequency enforced at 1 hour." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            $adminPolicyNames = ($adminProtectionPolicy.displayName | Select-Object -First 2) -join ', '
            Add-Finding -DomainId "D1" -DomainName "Policy Coverage" -CheckId "D1.4" `
                -Title "Admin Protection CA Policy Present ($($adminProtectionPolicy.Count) polic$(if($adminProtectionPolicy.Count -eq 1){'y'}else{'ies'}))" `
                -Evidence "Policies targeting directory roles with controls: $($adminProtectionPolicy.Count) | Sample: $adminPolicyNames" `
                -CurrentState "At least one CA policy applies authentication controls specifically to privileged directory roles." `
                -Gap "Validate: (1) all critical admin roles are included, (2) Authentication Strength is phishing-resistant (not basic MFA), (3) device compliance is required, (4) session controls (sign-in frequency, no persistent browser) are applied." `
                -Risk "Info" `
                -BusinessImpact "Low when configured correctly. Degraded if only basic MFA is applied rather than phishing-resistant MFA — admin accounts remain vulnerable to AiTM attacks." `
                -TargetState "Phishing-resistant MFA + compliant device + 1-hour session frequency for all privileged roles. No exceptions except break-glass accounts (monitored separately)." `
                -Recommendation "Verify Authentication Strength is set to Phishing-resistant MFA (not general MFA). Add compliant device requirement. Enable CAE (Continuous Access Evaluation) for admin sign-in sessions. Confirm all 10 critical admin role IDs are included." `
                -SuccessMeasure "Admin Insights workbook shows zero basic MFA challenges for admin roles. All admin sign-ins from compliant devices." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 1.6: Sign-in risk policy ───────────────────────────────────────
        $riskPolicy = $enabled | Where-Object {
            $_.conditions.signInRiskLevels -and $_.conditions.signInRiskLevels.Count -gt 0 -and
            $_.grantControls -and
            ($_.grantControls.builtInControls -contains "mfa" -or
            $_.grantControls.builtInControls -contains "block")
        }

        if ($riskPolicy.Count -eq 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Policy Coverage" -CheckId "D1.5" `
                -Title "No Risk-Based CA Policy for Risky Sign-Ins (Entra ID P2 / Identity Protection)" `
                -Evidence "Enabled CA policies with signInRiskLevels condition: 0" `
                -CurrentState "No CA policy evaluates or responds to Microsoft's real-time sign-in risk signal. Sign-ins flagged as risky by Identity Protection are not challenged or blocked." `
                -Gap "Without risk-based CA, compromised credentials being used from anomalous locations or by known threat actor infrastructure proceed unimpeded. The identity protection signal is available but not wired to any enforcement policy." `
                -Risk "Medium" `
                -BusinessImpact "Impossible travel, atypical location, and malicious IP sign-ins are detected by Identity Protection but not acted upon. Threat actor sessions that trigger risk detections continue uninterrupted, extending breach windows." `
                -TargetState "Risk-based CA policies: (1) High sign-in risk → Block access (or require MFA + password change), (2) Medium sign-in risk → Require MFA, (3) High user risk → Require secure password change." `
                -Recommendation "Create two CA policies: (1) High/Medium sign-in risk → All Users → Require MFA. (2) High user risk → Require secure password change. Requires Entra ID P2 / Identity Protection. If P2 is not licensed, evaluate Microsoft 365 E5 Security Add-on." `
                -SuccessMeasure "All high-risk sign-ins blocked or MFA-challenged. Identity Protection risky users remediated within 24 hours. Risk detection trends decreasing quarter-on-quarter." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D1" -DomainName "Policy Coverage" -CheckId "D1.5" `
                -Title "Risk-Based CA Policies Present ($($riskPolicy.Count) polic$(if($riskPolicy.Count -eq 1){'y'}else{'ies'}))" `
                -Evidence "Policies with sign-in risk conditions: $($riskPolicy.Count) | Names: $(($riskPolicy.displayName | Select-Object -First 2) -join ', ')" `
                -CurrentState "Sign-in risk-based CA policies are active — the Identity Protection signal is wired to enforcement." `
                -Gap "Verify coverage: (1) both high AND medium risk levels are addressed, (2) user risk policies also exist (separate from sign-in risk), (3) block (not just MFA) is applied for high risk." `
                -Risk "Info" `
                -BusinessImpact "Low when coverage is complete. Degraded if only medium risk is addressed or if MFA (not block) is the response to high risk — attackers with stolen session tokens may satisfy MFA." `
                -TargetState "High sign-in risk → Block. Medium sign-in risk → Require MFA. High user risk → Require secure password change. All risk detections automatically remediated." `
                -Recommendation "Review risk policy coverage in Identity Protection dashboard. Ensure high risk maps to Block (not just MFA). Enable CAE for real-time risk token revocation. Review risky user report weekly." `
                -SuccessMeasure "Risk policy coverage report shows High+Medium sign-in risk handled. Average time-to-remediation for risky users <24 hours." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        $legacyStatus = if ($legacyBlockPolicy.Count -gt 0) { "✓" } else { "✗" }
        $mfaStatus = if ($mfaAllUsersPolicy.Count -gt 0) { "✓" } else { "✗" }
        $adminStatus = if ($adminProtectionPolicy.Count -gt 0) { "✓" } else { "✗" }
        $riskStatus = if ($riskPolicy.Count -gt 0) { "✓" } else { "✗" }

        Set-DomainResult -Id "D1" -Name "Policy Coverage" -Icon "🏗️" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Enabled: $($enabled.Count). MFA all users: $mfaStatus. Legacy block: $legacyStatus. Admin protection: $adminStatus. Risk-based: $riskStatus." `
            -TargetStateSummary "Full CA baseline: MFA all users, admin phishing-resistant, legacy blocked, risk-based controls, device compliance all active." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 2: Policy Coherence, Overlaps & Conflicts ──────────────────

    Function Invoke-Domain2-CoherenceAndConflicts {
        Write-Host "  🔀 D2: Policy Coherence, Overlaps & Conflicts..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $enabled = $script:EnabledPolicies

        if ($enabled.Count -eq 0) {
            $maturityPoints += 1
            Set-DomainResult -Id "D2" -Name "Coherence & Conflicts" -Icon "🔀" `
                -MaturityScore 1 `
                -CurrentStateSummary "No enabled CA policies exist. Coherence analysis cannot be performed." `
                -TargetStateSummary "Intentional, non-overlapping policy architecture with documented scope for each policy and no contradictory outcomes." `
                -CriticalCount 0 -HighCount 0 -MediumCount 0 -LowCount 0
            return
        }

        # ── Check 2.1: Overlapping all-users + all-apps policies with different controls ─
        $broadPolicies = @($enabled | Where-Object {
                $_.conditions.users.includeUsers -contains "All" -and
                ($_.conditions.applications.includeApplications -contains "All" -or
                $_.conditions.applications.includeApplications.Count -eq 0)
            })

        if ($broadPolicies.Count -ge 3) {
            # Check if they have contradictory or redundant controls
            $blockPolicies = @($broadPolicies | Where-Object { $_.grantControls -and $_.grantControls.builtInControls -contains "block" })
            $mfaPolicies = @($broadPolicies | Where-Object { $_.grantControls -and $_.grantControls.builtInControls -contains "mfa" })
            $sessionPolicies = @($broadPolicies | Where-Object { $_.sessionControls -and $_.sessionControls -ne $null })

            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Coherence & Conflicts" -CheckId "D2.1" `
                -Title "Multiple Broad Policies (All Users + All Apps) May Create Overlapping or Redundant Controls ($($broadPolicies.Count) policies)" `
                -Evidence "Policies targeting All Users + All/broad apps: $($broadPolicies.Count) | Block-scoped: $($blockPolicies.Count) | MFA-grant: $($mfaPolicies.Count) | Session-controls: $($sessionPolicies.Count) | Policy names: $(($broadPolicies.displayName | Select-Object -First 4) -join '; ')" `
                -CurrentState "Multiple CA policies are scoped to All Users with broad application coverage. In this configuration, the most restrictive control that matches a sign-in context applies — but multiple overlapping policies create complexity that is difficult to reason about, audit, or troubleshoot." `
                -Gap "Policy sprawl at broad scope increases the risk of unintended outcomes: exclusions on one broad policy may not align with exclusions on another, sign-in failure investigations are harder, and grant control layering may be redundant or contradictory." `
                -Risk "Medium" `
                -BusinessImpact "Architectural complexity creates operational risk: unintended access denials, exclusion mismatches between overlapping policies, and difficulty predicting effective policy outcomes during changes. Troubleshooting sign-in failures in overlapping policy stacks takes significantly longer." `
                -TargetState "Intentional layered CA architecture: one foundational policy per control type, with narrower app-specific or role-specific policies layered on top. Every policy has a single clear purpose, documented scope, and no redundant overlap." `
                -Recommendation "Document the intended purpose of each broad policy. Consolidate redundant controls into single policies per purpose. Use the CA What-If tool to validate effective policy outcomes per user/app combination. Consider implementing the Microsoft CA framework: Foundation + App-specific + Role-specific layers." `
                -SuccessMeasure "Each enabled CA policy has a documented purpose. No two policies apply the same control to the same user/app scope. CA architecture diagram exists and is reviewed quarterly." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        elseif ($broadPolicies.Count -ge 1) {
            $maturityPoints += 3
        }
        else {
            $maturityPoints += 2
        }

        # ── Check 2.2: Conflicting grant controls (block vs allow for same scope) ─
        # Detect policies where one blocks and another allows for potentially same users
        $allUserBlockPolicies = @($enabled | Where-Object {
                $_.conditions.users.includeUsers -contains "All" -and
                $_.grantControls -and
                $_.grantControls.builtInControls -contains "block"
            })

        $allUserAllowPolicies = @($enabled | Where-Object {
                $_.conditions.users.includeUsers -contains "All" -and
                $_.grantControls -and
                -not ($_.grantControls.builtInControls -contains "block")
            })

        # If block policies exist AND allow policies have fewer exclusions, they likely conflict
        $potentialConflicts = 0
        foreach ($blockPol in $allUserBlockPolicies) {
            $blockExclusions = @($blockPol.conditions.users.excludeUsers) + @($blockPol.conditions.users.excludeGroups)
            $blockApps = $blockPol.conditions.applications.includeApplications

            foreach ($allowPol in $allUserAllowPolicies) {
                $allowExclusions = @($allowPol.conditions.users.excludeUsers) + @($allowPol.conditions.users.excludeGroups)
                $allowApps = $allowPol.conditions.applications.includeApplications

                # Same app scope and different exclusion sets = potential conflict
                if (($blockApps -contains "All" -or $allowApps -contains "All") -and
                    ($blockExclusions.Count -ne $allowExclusions.Count)) {
                    $potentialConflicts++
                }
            }
        }

        if ($potentialConflicts -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Coherence & Conflicts" -CheckId "D2.2" `
                -Title "Potential Policy Conflicts Detected — Block and Allow Policies with Inconsistent Exclusions ($potentialConflicts potential conflict(s))" `
                -Evidence "All-user block policies: $($allUserBlockPolicies.Count) | All-user allow/grant policies: $($allUserAllowPolicies.Count) | Potential scope conflicts: $potentialConflicts" `
                -CurrentState "Block and grant (allow with conditions) policies targeting all users have inconsistent exclusion sets, creating potential outcomes that may not match the intended architecture." `
                -Gap "Inconsistent exclusion sets between block and grant policies can result in users being excluded from a block policy but not from a grant policy (or vice versa), creating access paths or denials that are unintentional. The effective policy for any sign-in is the union of all matching policies — mismatched exclusions are the primary source of unintended access." `
                -Risk "Medium" `
                -BusinessImpact "Exclusion mismatches can allow privileged users to bypass block controls, or inadvertently block service accounts that should have been excluded from enforcement. Both outcomes represent security or operational incidents." `
                -TargetState "All block and grant policies targeting the same user population have aligned exclusion sets. A shared exclusion group (e.g., CA-Exclusion-BreakGlass) is used consistently across all baseline policies." `
                -Recommendation "Audit exclusion sets across all broad policies. Create a shared CA exclusion group containing only break-glass accounts. Apply this group consistently as the exclusion on all baseline CA policies. Use the CA What-If tool to validate outcomes per user." `
                -SuccessMeasure "All baseline CA policies reference the same exclusion group. CA What-If validates consistent outcomes for test users. No ad-hoc per-policy exclusion lists." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
        }

        # ── Check 2.3: Report-only count vs enabled ratio ─────────────────────────
        $reportOnly = $script:ReportOnlyPolicies
        if ($reportOnly.Count -gt 0) {
            $staleCandidates = $reportOnly.Count
            if ($staleCandidates -gt $enabled.Count) {
                $medium++
                $maturityPoints += 2
                $risk = "Medium"; $phase = "31-60 Days"
                $gap = "More policies in report-only than enabled suggests systemic hesitancy to enforce — policies are evaluated but never committed."
            }
            else {
                $low++
                $maturityPoints += 3
                $risk = "Low"; $phase = "61-90 Days"
                $gap = "Some policies remain in report-only. Review and promote or remove within 30 days of creation."
            }

            Add-Finding -DomainId "D2" -DomainName "Coherence & Conflicts" -CheckId "D2.3" `
                -Title "Report-Only Policies Not Yet Promoted to Enforcement ($($reportOnly.Count) polic$(if($reportOnly.Count -eq 1){'y'}else{'ies'}))" `
                -Evidence "Enabled: $($enabled.Count) | Report-only: $($reportOnly.Count) | Report-only names: $(($reportOnly.displayName | Select-Object -First 3) -join '; ')" `
                -CurrentState "$($reportOnly.Count) CA polic$(if($reportOnly.Count -eq 1){'y is'}else{'ies are'}) in report-only mode — controls are assessed but not enforced." `
                -Gap $gap `
                -Risk $risk `
                -BusinessImpact "Controls visible in report-only mode give a false sense of security coverage. Users in scope of report-only policies are unprotected — the policy provides log data but no access control." `
                -TargetState "Report-only used only for short-duration (7–14 day) impact assessment before enabling. No policy remains in report-only for more than 30 days. A governance process enforces promotion deadlines." `
                -Recommendation "For each report-only policy: (1) open CA Insights & Reporting, (2) review expected vs actual impact, (3) promote to Enabled or document the reason for deferral. Create a governance rule: report-only policies require promotion decision within 30 days." `
                -SuccessMeasure "Report-only policy count = 0 (or only newly created policies <14 days old). All promoted policies have an impact review record." `
                -RoadmapPhase $phase -MaturityContribution ($maturityPoints[-1])
        }
        else {
            $maturityPoints += 4
        }

        # ── Check 2.4: Policy naming and documentation quality ────────────────────
        $poorlyNamedPolicies = @($enabled | Where-Object {
                $_.displayName -match "^(Policy \d+|Test|CA\d+|Untitled|New policy|Copy of)" -or
                $_.displayName.Length -lt 10
            })

        if ($poorlyNamedPolicies.Count -gt 0) {
            $low++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Coherence & Conflicts" -CheckId "D2.4" `
                -Title "CA Policies with Generic or Undescriptive Names Detected ($($poorlyNamedPolicies.Count))" `
                -Evidence "Policies with unclear names: $($poorlyNamedPolicies.Count) | Sample names: $(($poorlyNamedPolicies.displayName | Select-Object -First 3) -join '; ')" `
                -CurrentState "$($poorlyNamedPolicies.Count) CA polic$(if($poorlyNamedPolicies.Count -eq 1){'y has a'}else{'ies have'}) generic or test-like name$(if($poorlyNamedPolicies.Count -gt 1){'s'}) suggesting undocumented or experimental policies that may have been left active." `
                -Gap "Poorly named policies indicate absent policy governance. Without clear names describing purpose, scope, and author, policies cannot be audited, understood, or maintained effectively — increasing the risk of accidental modification or the policy persisting beyond its intended lifecycle." `
                -Risk "Low" `
                -BusinessImpact "Operational risk: unclear policy names increase the probability of incorrect modification or deletion during incident response or change management, when decisions need to be made quickly." `
                -TargetState "All CA policies follow a naming convention that encodes: purpose, scope, controls, and sequence. Example: CA-001-AllUsers-AllApps-RequireMFA, CA-004-Admins-AllApps-RequirePhishingResistantMFA-CompliantDevice." `
                -Recommendation "Adopt a CA naming convention standard. Rename all existing policies. Remove or promote test/experimental policies. Include policy intent in the Description field (CA policies support a description property)." `
                -SuccessMeasure "100% of CA policies follow naming convention. Zero test or undescriptive policy names. CA policy inventory document maintained and version-controlled." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
        }

        # ── Check 2.5: Disabled policies accumulation (sprawl indicator) ──────────
        $disabled = $script:DisabledPolicies
        if ($disabled.Count -gt ($enabled.Count * 0.5) -and $disabled.Count -gt 5) {
            $low++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Coherence & Conflicts" -CheckId "D2.5" `
                -Title "High Number of Disabled CA Policies Indicates Policy Sprawl ($($disabled.Count) disabled)" `
                -Evidence "Disabled policies: $($disabled.Count) | Enabled policies: $($enabled.Count) | Ratio: $([Math]::Round($disabled.Count / [Math]::Max($enabled.Count,1), 1)):1 disabled-to-enabled" `
                -CurrentState "$($disabled.Count) CA policies are disabled but not deleted — representing accumulated draft, test, or superseded policies." `
                -Gap "Disabled policies are not enforced but contribute to policy landscape complexity. They may be re-enabled accidentally, create confusion during audits, and represent undocumented historical intent." `
                -Risk "Low" `
                -BusinessImpact "Operational risk: disabled policies may be re-enabled during incident response without understanding their current configuration or scope. Audit confusion: external auditors may flag disabled policies without understanding their lifecycle status." `
                -TargetState "No disabled policies remain in the tenant for more than 90 days. Superseded policies are deleted, not disabled. Only policies actively undergoing configuration review are in disabled state." `
                -Recommendation "Review all disabled policies. Delete those that are superseded or no longer needed. For policies that represent pending work, document their status in the policy Description field with a planned enable/delete date. Set a 90-day policy hygiene review cadence." `
                -SuccessMeasure "Disabled policy count <3. All disabled policies have a documented rationale and owner. Annual CA policy hygiene review completed." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D2" -Name "Coherence & Conflicts" -Icon "🔀" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Total policies: $($script:AllCAPolicies.Count). Broad overlaps: $(if($broadPolicies.Count -ge 3){'detected'}else{'minimal'}). Report-only pending: $($reportOnly.Count). Disabled: $($disabled.Count)." `
            -TargetStateSummary "Intentional layered architecture. One policy per purpose. Consistent exclusions. No report-only backlog. Clean disabled-policy hygiene." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 3: Exclusion Governance & Shadow Populations ───────────────

    Function Invoke-Domain3-ExclusionGovernance {
        Write-Host "  👥 D3: Exclusion Governance & Shadow Populations..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $enabled = $script:EnabledPolicies

        if ($enabled.Count -eq 0) {
            $maturityPoints += 1
            Set-DomainResult -Id "D3" -Name "Exclusion Governance" -Icon "👥" `
                -MaturityScore 1 `
                -CurrentStateSummary "No enabled CA policies — exclusion analysis not applicable." `
                -TargetStateSummary "Minimal, governed, time-limited exclusions. Break-glass accounts are the only permanent exclusions." `
                -CriticalCount 0 -HighCount 0 -MediumCount 0 -LowCount 0
            return
        }

        # ── Check 3.1: Policies with large exclusion user counts ─────────────────
        $broadUserExclusionPolicies = @($enabled | Where-Object {
                ($_.conditions.users.excludeUsers | Measure-Object).Count -gt 5
            })

        if ($broadUserExclusionPolicies.Count -gt 0) {
            $high++
            $maturityPoints += 1
            $exampleNames = ($broadUserExclusionPolicies.displayName | Select-Object -First 3) -join '; '
            $totalExcludedUsers = ($broadUserExclusionPolicies | ForEach-Object { $_.conditions.users.excludeUsers.Count } | Measure-Object -Sum).Sum

            Add-Finding -DomainId "D3" -DomainName "Exclusion Governance" -CheckId "D3.1" `
                -Title "CA Policies with Large Per-User Exclusion Lists Detected ($($broadUserExclusionPolicies.Count) polic$(if($broadUserExclusionPolicies.Count -eq 1){'y'}else{'ies'}), ~$totalExcludedUsers excluded users)" `
                -Evidence "Policies with >5 directly excluded users: $($broadUserExclusionPolicies.Count) | Approx. total excluded users: $totalExcludedUsers | Sample policies: $exampleNames" `
                -CurrentState "$($broadUserExclusionPolicies.Count) CA polic$(if($broadUserExclusionPolicies.Count -eq 1){'y has'}else{'ies have'}) large per-user exclusion lists — individual user IDs are directly excluded rather than managed through a governed exclusion group." `
                -Gap "Direct per-user exclusions are unmanageable at scale, not auditable in bulk, not governed by access reviews, and create a shadow population outside authentication controls. Each excluded user represents an uncontrolled access path that grows silently over time." `
                -Risk "High" `
                -BusinessImpact "Every directly excluded user represents a credential attack target with no MFA, device, or location-based protection. These accounts are the highest-value targets for credential attacks because they lack the controls applied to the rest of the user population." `
                -TargetState "Zero direct per-user exclusions. All exclusions managed through a documented, access-reviewed exclusion group. Break-glass accounts in a dedicated emergency-access group with separate monitoring." `
                -Recommendation "Convert all direct user exclusions to group-based exclusions. Create a CA-Exclusion-Emergency group for break-glass accounts. Enable Access Reviews on all exclusion groups (quarterly). Require manager approval and time-bounded justification for any exclusion addition." `
                -SuccessMeasure "Zero direct per-user exclusions on any enabled policy. Exclusion group membership <5 (break-glass only). Access reviews configured and completed quarterly." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
        }

        # ── Check 3.2: Policies with large exclusion group counts ─────────────────
        $broadGroupExclusionPolicies = @($enabled | Where-Object {
                ($_.conditions.users.excludeGroups | Measure-Object).Count -gt 3
            })

        if ($broadGroupExclusionPolicies.Count -gt 0) {
            $medium++
            $maturityPoints += 2
            $maxGroupExclusions = ($broadGroupExclusionPolicies | ForEach-Object { $_.conditions.users.excludeGroups.Count } | Measure-Object -Maximum).Maximum

            Add-Finding -DomainId "D3" -DomainName "Exclusion Governance" -CheckId "D3.2" `
                -Title "CA Policies with Multiple Exclusion Groups ($($broadGroupExclusionPolicies.Count) polic$(if($broadGroupExclusionPolicies.Count -eq 1){'y'}else{'ies'}), max $maxGroupExclusions groups per policy)" `
                -Evidence "Policies with >3 exclusion groups: $($broadGroupExclusionPolicies.Count) | Max exclusion groups on a single policy: $maxGroupExclusions | Sample policies: $(($broadGroupExclusionPolicies.displayName | Select-Object -First 3) -join '; ')" `
                -CurrentState "Multiple CA policies have more than 3 exclusion groups — indicating ad-hoc exclusion accumulation over time without consolidation or governance." `
                -Gap "Multiple exclusion groups on a single policy are a classic sprawl pattern: each group was added to resolve an operational issue without rationalising existing exclusions. Without transitive membership analysis, it is impossible to know the total population excluded from the policy." `
                -Risk "Medium" `
                -BusinessImpact "The cumulative membership of multiple exclusion groups likely exceeds what was intended at policy creation time. The effective excluded population is a blind spot — these users bypass policy controls without visibility." `
                -TargetState "Maximum 2 exclusion groups per policy: (1) CA-Exclusion-Emergency (break-glass accounts), (2) CA-Exclusion-ServiceAccounts-[PolicyName] where applicable. All other users covered." `
                -Recommendation "Audit the membership of all exclusion groups across all policies. Consolidate where possible. Remove groups whose members should no longer be excluded. For service accounts, evaluate whether workload identity or app-based exclusions are more appropriate." `
                -SuccessMeasure "Maximum 2 exclusion groups per policy. All exclusion groups have named owners and access reviews configured. Total excluded population <1% of total users." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
        }

        # ── Check 3.3: Policies targeting all users but excluding all users via role/group ─
        # An indicator: all-user policy with very broad group exclusion suggesting policy is effectively empty
        $potentiallyVoidPolicies = @($enabled | Where-Object {
                $_.conditions.users.includeUsers -contains "All" -and
                ($_.conditions.users.excludeGroups | Measure-Object).Count -ge 5 -and
                ($_.conditions.users.excludeUsers | Measure-Object).Count -ge 3
            })

        if ($potentiallyVoidPolicies.Count -gt 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D3" -DomainName "Exclusion Governance" -CheckId "D3.3" `
                -Title "CA Policies That May Be Effectively Void Due to Excessive Exclusions ($($potentiallyVoidPolicies.Count) polic$(if($potentiallyVoidPolicies.Count -eq 1){'y'}else{'ies'}))" `
                -Evidence "Policies with All Users + 5+ exclusion groups + 3+ excluded users: $($potentiallyVoidPolicies.Count) | Names: $(($potentiallyVoidPolicies.displayName | Select-Object -First 2) -join '; ')" `
                -CurrentState "One or more CA policies are scoped to All Users but carry so many exclusions that a significant proportion (potentially all) users may be excluded from the policy's control." `
                -Gap "A policy that appears to cover All Users but excludes most of them provides false assurance of coverage. This is one of the most dangerous CA architecture anti-patterns: the policy appears active and generates logs, but the control is not applied to the intended population." `
                -Risk "High" `
                -BusinessImpact "If the excluded population covers most users, the policy's intended security control (MFA, device compliance, block) is applied to only a fraction of the user base. The blast radius of a credential compromise affecting excluded users is unrestricted." `
                -TargetState "Use the CA What-If tool to determine the effective policy outcome for a representative sample of users. Policies that cover fewer than 90% of users due to exclusions should be rearchitected or replaced." `
                -Recommendation "For each flagged policy: (1) run CA What-If for 10 diverse user accounts, (2) analyse Insights & Reporting for the policy's actual coverage rate, (3) remove unjustified exclusions, (4) replace per-user/group exclusions with break-glass group only." `
                -SuccessMeasure "CA Insights shows >99% of users covered by each baseline policy. What-If tool confirms intended outcome for all user types." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
        }

        # ── Check 3.4: Exclusion groups with no access review (governance gap) ────
        # We look at all unique exclusion groups and check if access reviews exist
        $allExclusionGroupIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($pol in $enabled) {
            foreach ($gid in $pol.conditions.users.excludeGroups) {
                $null = $allExclusionGroupIds.Add($gid)
            }
        }

        $totalExclusionGroups = $allExclusionGroupIds.Count

        $accessReviews = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions?`$top=50"
        $accessReviewsConfigured = if ($accessReviews -eq $null) { $false } else { $accessReviews.Count -gt 0 }

        if ($totalExclusionGroups -gt 0 -and -not $accessReviewsConfigured) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D3" -DomainName "Exclusion Governance" -CheckId "D3.4" `
                -Title "CA Exclusion Groups Have No Access Reviews Configured — Exclusion Lifecycle Governance Absent" `
                -Evidence "Unique exclusion groups across all enabled CA policies: $totalExclusionGroups | Access reviews configured in tenant: $(if($accessReviews -eq $null){'P2 not available'}else{$accessReviews.Count})" `
                -CurrentState "$totalExclusionGroups unique group$(if($totalExclusionGroups -ne 1){'s are'} else{' is'}) used as CA policy exclusions. No access review definitions are configured to certify membership of these groups on a periodic basis." `
                -Gap "Without periodic access reviews, exclusion group membership grows unchecked. Members who were added for a time-limited reason (e.g., testing, migration, incident response) remain permanently excluded from CA controls, accumulating a shadow population outside authentication governance." `
                -Risk "Medium" `
                -BusinessImpact "Stale exclusion group members maintain unrestricted access with no authentication controls for indefinite periods. The excluded population increases over time, widening the unprotected attack surface with each new addition." `
                -TargetState "Quarterly access reviews on all CA exclusion groups. Each review requires manager certification. Automated removal of users whose review is not completed (deny-by-default). Entra ID P2 required for Access Reviews." `
                -Recommendation "Configure Access Reviews for all CA exclusion groups: quarterly cadence, reviewer = group owner + manager, auto-remove on review failure. If P2 is unavailable, implement a manual review process via a recurring task or ServiceNow ticket workflow." `
                -SuccessMeasure "Access reviews configured on all exclusion groups. 100% review completion rate. Exclusion group membership trends flat or decreasing quarter-on-quarter." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        elseif ($totalExclusionGroups -gt 0 -and $accessReviewsConfigured) {
            $maturityPoints += 4
            Add-Finding -DomainId "D3" -DomainName "Exclusion Governance" -CheckId "D3.4" `
                -Title "Access Reviews Active — Exclusion Governance Framework Present" `
                -Evidence "Unique exclusion groups: $totalExclusionGroups | Access reviews in tenant: $($accessReviews.Count)" `
                -CurrentState "Access reviews are configured in the tenant. Exclusion group membership certification is in place." `
                -Gap "Verify: access reviews are specifically configured for CA exclusion groups (not just general group reviews). Confirm review cadence is quarterly or more frequent for security-critical exclusion groups." `
                -Risk "Info" `
                -BusinessImpact "Low — governance framework is in place. Effectiveness depends on review completion rates and scope." `
                -TargetState "Access reviews scoped specifically to all CA exclusion groups. Quarterly cadence. Auto-remove on review failure. Declining exclusion group membership trend." `
                -Recommendation "Confirm CA exclusion groups are included in access review scope. Check completion rates in the Access Reviews dashboard. Set target: 100% completion, 0 stale members." `
                -SuccessMeasure "Access review completion rate >95%. Exclusion group membership flat or decreasing. No member older than 90 days without a valid justification." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }
        else {
            $maturityPoints += 5
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D3" -Name "Exclusion Governance" -Icon "👥" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Total exclusion groups across policies: $totalExclusionGroups. Large per-user exclusions: $($broadUserExclusionPolicies.Count) policies. Potentially void policies: $($potentiallyVoidPolicies.Count). Access reviews: $(if($accessReviewsConfigured){'✓'}else{'✗'})." `
            -TargetStateSummary "Zero per-user exclusions. Max 2 groups per policy. Quarterly access reviews on all exclusion groups. Break-glass only as permanent exclusion." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 4: Privileged Identity Protection ──────────────────────────

    Function Invoke-Domain4-PrivilegedIdentityProtection {
        Write-Host "  👑 D4: Privileged Identity Protection..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $enabled = $script:EnabledPolicies

        # ── Collect privileged role assignments ───────────────────────────────────
        $globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
        $privRoleAdminId = "e8611ab8-c189-46e8-94e1-60213ab1f814"
        $secAdminId = "194ae4cb-b126-40b2-bd5b-6091b380977d"
        $authAdminId = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
        $privAuthAdminId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"

        $criticalAdminRoles = @($globalAdminRoleId, $privRoleAdminId, $secAdminId, $authAdminId, $privAuthAdminId)

        # Get active (permanent) role assignments
        $activeAdminAssignments = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$globalAdminRoleId'&`$select=id,principalId,roleDefinitionId,directoryScopeId&`$top=50"
        $gaCount = $activeAdminAssignments.Count

        # PIM eligible assignments
        $pimAssignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?`$select=id,principalId,roleDefinitionId,status&`$top=100"
        $pimAvailable = ($pimAssignments -ne $null)
        $pimEligibleGA = if ($pimAvailable -and $pimAssignments.value) {
            @($pimAssignments.value | Where-Object { $_.roleDefinitionId -eq $globalAdminRoleId })
        }
        else { @() }

        # ── Check 4.1: CA policy covering admin roles with phishing-resistant MFA ─
        $adminCAPhishingResistant = @($enabled | Where-Object {
                $_.conditions.users.includeRoles -and
                ($_.conditions.users.includeRoles | Where-Object { $_ -in $criticalAdminRoles }).Count -gt 0 -and
                $_.grantControls -and
                $_.grantControls.authenticationStrength -ne $null
            })

        $adminCABasicMFA = @($enabled | Where-Object {
                $_.conditions.users.includeRoles -and
                ($_.conditions.users.includeRoles | Where-Object { $_ -in $criticalAdminRoles }).Count -gt 0 -and
                $_.grantControls -and
                $_.grantControls.builtInControls -contains "mfa" -and
                $_.grantControls.authenticationStrength -eq $null
            })

        if ($adminCAPhishingResistant.Count -eq 0 -and $adminCABasicMFA.Count -eq 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D4" -DomainName "Privileged Identity" -CheckId "D4.1" `
                -Title "No CA Policy Enforcing Authentication Controls on Critical Admin Roles" `
                -Evidence "Enabled CA policies targeting critical admin roles (GA, PRA, SecAdmin, AuthAdmin) with any MFA control: 0 | Global Admin active assignments: $gaCount" `
                -CurrentState "None of the critical privileged roles (Global Administrator, Privileged Role Administrator, Security Administrator, Authentication Administrator) are targeted by a CA policy requiring elevated authentication." `
                -Gap "The most privileged identities in the tenant receive no differentiated authentication protection. Any valid credential pair grants access to Global Administrator functions without MFA challenge, device check, or session controls." `
                -Risk "Critical" `
                -BusinessImpact "Global Administrator, Privileged Role Administrator, and Security Administrator accounts provide complete control of the tenant. A single compromised privileged credential enables irreversible tenant takeover: disabling all security policies, creating new admin accounts, accessing all data, removing all MFA — with no authentication barrier beyond the initial password." `
                -TargetState "A CA policy targeting all critical privileged role IDs requiring: phishing-resistant MFA (Authentication Strength), compliant or HAADJ device, 1-hour sign-in frequency, no persistent browser session. PIM used for just-in-time activation with approval." `
                -Recommendation "IMMEDIATE: Create CA policy targeting Global Admin, Privileged Role Admin, Security Admin, Auth Admin, Privileged Auth Admin roles. Apply Authentication Strength: Phishing-resistant MFA (FIDO2/WHfB/CBA). Add: require compliant device, sign-in frequency 1 hour. Exclude break-glass accounts only." `
                -SuccessMeasure "All critical admin sign-ins use phishing-resistant MFA. Zero admin sign-ins from non-compliant devices. PIM activated for all permanent admin roles." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($adminCABasicMFA.Count -gt 0 -and $adminCAPhishingResistant.Count -eq 0) {
            $high++
            $maturityPoints += 2
            Add-Finding -DomainId "D4" -DomainName "Privileged Identity" -CheckId "D4.1" `
                -Title "Admin CA Policy Uses Basic MFA — Not Phishing-Resistant Authentication Strength" `
                -Evidence "Admin-targeted policies with basic MFA: $($adminCABasicMFA.Count) | Admin-targeted policies with Authentication Strength: 0 | Sample: $(($adminCABasicMFA.displayName | Select-Object -First 2) -join ', ')" `
                -CurrentState "CA policies target privileged roles and require MFA, but use the basic MFA grant control rather than a phishing-resistant Authentication Strength policy." `
                -Gap "Basic MFA (Authenticator push, TOTP, SMS) is vulnerable to adversary-in-the-middle (AiTM) phishing attacks. Phishing kits targeting M365 (e.g., Evilginx2) can proxy MFA challenges in real time, stealing session tokens even when MFA is completed. Privileged role accounts must use phishing-resistant methods." `
                -Risk "High" `
                -BusinessImpact "Admin accounts protected by basic MFA remain vulnerable to AiTM phishing attacks. An attacker using a phishing kit can bypass Authenticator push notifications and obtain a valid admin session token. The blast radius of a compromised admin session is tenant-wide." `
                -TargetState "All admin CA policies use Authentication Strength: Phishing-resistant MFA (FIDO2, Windows Hello for Business, Certificate-Based Authentication). No admin role relies on basic MFA as the authentication challenge." `
                -Recommendation "Upgrade admin CA policy: change grant control from 'Require MFA' to 'Require authentication strength' and select 'Phishing-resistant MFA'. Ensure all admins have FIDO2 keys or WHfB enrolled. Consider CBA for government/regulated environments." `
                -SuccessMeasure "Zero admin sign-ins using TOTP or push-notification MFA. All admin sign-ins in logs show phishing-resistant authentication method. FIDO2/WHfB enrollment >95% for admin accounts." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 5
            Add-Finding -DomainId "D4" -DomainName "Privileged Identity" -CheckId "D4.1" `
                -Title "Phishing-Resistant Authentication Strength Required for Admin Roles" `
                -Evidence "Admin-targeted CA policies with Authentication Strength: $($adminCAPhishingResistant.Count) | Names: $(($adminCAPhishingResistant.displayName | Select-Object -First 2) -join ', ')" `
                -CurrentState "CA policies targeting critical admin roles require a phishing-resistant Authentication Strength — the highest-assurance authentication posture." `
                -Gap "Verify: (1) all 10 critical role IDs are included, (2) no broad exclusion groups undermine coverage, (3) device compliance is also required (not just authentication strength), (4) session frequency controls are applied." `
                -Risk "Info" `
                -BusinessImpact "Excellent privileged authentication posture. Phishing-resistant MFA eliminates AiTM attack risk for admin accounts. Maintain and verify coverage completeness." `
                -TargetState "100% of admin sign-ins using phishing-resistant MFA. All admin roles included. Compliant device also required. Session frequency: 1 hour." `
                -Recommendation "Verify all critical role IDs are included in the CA policy conditions. Add compliant device requirement alongside authentication strength. Enable CAE for privileged sessions for real-time revocation." `
                -SuccessMeasure "CA Insights shows zero basic MFA challenges for admin roles. Admin sign-in logs show only phishing-resistant authentication methods. No admin exceptions." `
                -RoadmapPhase "Strategic" -MaturityContribution 5
        }

        # ── Check 4.2: PIM vs permanent admin assignments ─────────────────────────
        if ($gaCount -gt 5) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D4" -DomainName "Privileged Identity" -CheckId "D4.2" `
                -Title "Excessive Permanent Global Administrator Assignments ($gaCount accounts)" `
                -Evidence "Permanent (active) Global Administrator assignments: $gaCount | PIM-eligible GA assignments: $($pimEligibleGA.Count)" `
                -CurrentState "$gaCount accounts hold permanent Global Administrator role assignments — active at all times without requiring activation or justification." `
                -Gap "Global Administrator is the highest-privilege role in Entra ID. Permanent assignments create persistent high-value targets. The Microsoft recommendation is a maximum of 2–4 permanent break-glass GA accounts, with all operational admin access managed through PIM just-in-time activation." `
                -Risk "Critical" `
                -BusinessImpact "Each permanent Global Administrator account represents a persistent credential attack target with unlimited tenant-wide blast radius. Compromise of any of these accounts enables full tenant takeover without any activation or approval barrier." `
                -TargetState "Maximum 2 permanent Global Administrator accounts (break-glass/emergency access). All other admin access via PIM eligible assignments with approval workflow, justification, and time-bound activation (max 8 hours). Target: zero standing privilege for all operational admins." `
                -Recommendation "Implement PIM for all privileged roles immediately. Convert permanent GA assignments to PIM-eligible. Leave only 2 break-glass accounts as permanent GA. Require MFA + justification for PIM activation. Set maximum activation duration to 8 hours. Enable PIM alerts for permanent assignment creation." `
                -SuccessMeasure "Permanent GA count ≤2. All operational admin access via PIM. PIM activation requires MFA + written justification. Admin action audit trail 100% complete." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($gaCount -gt 2) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D4" -DomainName "Privileged Identity" -CheckId "D4.2" `
                -Title "Above-Recommended Permanent Global Administrator Count ($gaCount accounts)" `
                -Evidence "Permanent GA assignments: $gaCount | PIM-eligible GA: $($pimEligibleGA.Count) | Microsoft recommended maximum: 2-4" `
                -CurrentState "$gaCount accounts hold permanent Global Administrator assignments — above the recommended 2–4 maximum for break-glass accounts." `
                -Gap "Exceeding the recommended permanent GA count extends the persistent attack surface for the highest-privilege role. Each account above the minimum represents unnecessary standing privilege." `
                -Risk "Medium" `
                -BusinessImpact "Moderate — the count is above recommended but not at critical level. Each additional permanent GA account extends the persistent attack surface and the number of credentials that must be monitored and protected." `
                -TargetState "≤2 permanent GA accounts (break-glass). All others converted to PIM-eligible. Permanent GA accounts stored in secure vault with hardware MFA." `
                -Recommendation "Identify which GA accounts are operational (should become PIM-eligible) vs break-glass (can remain permanent). Convert operational GAs to PIM. Document and vault break-glass account credentials with hardware FIDO2 keys." `
                -SuccessMeasure "Permanent GA count ≤2. PIM-eligible GA count covers all operational admin needs. Break-glass credential access logged and alerted." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 5
            Add-Finding -DomainId "D4" -DomainName "Privileged Identity" -CheckId "D4.2" `
                -Title "Global Administrator Count Within Recommended Range ($gaCount accounts)" `
                -Evidence "Permanent GA assignments: $gaCount | PIM-eligible GA: $($pimEligibleGA.Count)" `
                -CurrentState "$gaCount permanent Global Administrator account(s) — within the recommended 2–4 maximum for break-glass accounts." `
                -Gap "Ensure these accounts are true break-glass accounts: vaulted credentials, hardware FIDO2 keys, monitored for activation, excluded from standard CA policies but tracked by alerting." `
                -Risk "Info" `
                -BusinessImpact "Low — GA count is well-governed. Maintain rigor: credential storage, activation monitoring, and regular testing of break-glass procedures." `
                -TargetState "Break-glass accounts tested quarterly. Credentials in Azure Key Vault or PAW-secured vault. Any GA activation triggers immediate Security Operations alert." `
                -Recommendation "Schedule quarterly break-glass account test procedure. Ensure hardware FIDO2 keys are registered. Configure Azure Monitor / Sentinel alert for any GA role activation. Review access logs monthly." `
                -SuccessMeasure "Break-glass test completed quarterly with documented evidence. GA activation alerts tested and confirmed working. No unexpected GA activations in last 90 days." `
                -RoadmapPhase "Strategic" -MaturityContribution 5
        }

        # ── Check 4.3: Admin session controls (sign-in frequency / persistent session) ─
        $adminSessionControls = @($enabled | Where-Object {
                $_.conditions.users.includeRoles -and
                $_.conditions.users.includeRoles.Count -gt 0 -and
                $_.sessionControls -and
                ($_.sessionControls.signInFrequency -ne $null -or
                $_.sessionControls.persistentBrowser -ne $null)
            })

        if ($adminSessionControls.Count -eq 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D4" -DomainName "Privileged Identity" -CheckId "D4.3" `
                -Title "No CA Session Controls Applied to Admin Roles (Sign-in Frequency / Persistent Browser)" `
                -Evidence "Admin-scoped CA policies with session controls: 0" `
                -CurrentState "No CA policy applies session lifetime controls (sign-in frequency or persistent browser restrictions) to privileged roles. Admin sessions persist indefinitely once authenticated." `
                -Gap "Without session frequency controls, a stolen admin session token remains valid until expiry (typically 24 hours for access tokens, longer for refresh tokens). Continuous Access Evaluation (CAE) alone is insufficient without explicit session policies for privileged roles." `
                -Risk "Medium" `
                -BusinessImpact "A stolen admin session token remains usable for the full token lifetime — typically 1–24 hours for access tokens. Without sign-in frequency enforcement, there is no mechanism to force re-authentication of compromised admin sessions within a reasonable time window." `
                -TargetState "Admin CA policy with: sign-in frequency = 1 hour, persistent browser = never (admin roles). Continuous Access Evaluation enabled for admin sessions." `
                -Recommendation "Add session controls to the admin CA policy: signInFrequency → 1 hour, persistentBrowserSession → never for admin roles. Enable CAE for services that support it (Exchange, SharePoint, Teams). This limits stolen session token validity to 1 hour maximum." `
                -SuccessMeasure "Admin session frequency enforced at 1 hour. CA Insights shows no admin persistent sessions. CAE coverage = 100% for supported services." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        $adminProtected = if ($adminCAPhishingResistant.Count -gt 0) { "phishing-resistant ✓" } elseif ($adminCABasicMFA.Count -gt 0) { "basic MFA only" } else { "none ✗" }

        Set-DomainResult -Id "D4" -Name "Privileged Identity" -Icon "👑" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Permanent GAs: $gaCount. Admin CA protection: $adminProtected. Session controls on admins: $(if($adminSessionControls.Count -gt 0){'✓'}else{'✗'}). PIM available: $(if($pimAvailable){'✓'}else{'✗'})." `
            -TargetStateSummary "≤2 permanent GAs. Phishing-resistant MFA + compliant device for all admin roles. 1-hour session frequency. PIM just-in-time for all operational admins." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 5: Emergency Access & Break-Glass Coverage ─────────────────

    Function Invoke-Domain5-EmergencyAccess {
        Write-Host "  🆘 D5: Emergency Access & Break-Glass Coverage..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $enabled = $script:EnabledPolicies

        # ── Identify break-glass account candidates ────────────────────────────────
        # Heuristics: accounts excluded from ALL or most broad all-users CA policies
        # that also have Global Administrator assignment

        $globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
        $gaAssignments = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$globalAdminRoleId'&`$select=id,principalId&`$top=50"
        $gaPrincipalIds = @($gaAssignments | ForEach-Object { $_.principalId })

        $allUsersPolicies = @($enabled | Where-Object { $_.conditions.users.includeUsers -contains "All" })

        # Find users excluded from all broad policies (break-glass pattern)
        $candidateBreakGlassUsers = @()
        if ($allUsersPolicies.Count -gt 0 -and $gaPrincipalIds.Count -gt 0) {
            foreach ($gaId in $gaPrincipalIds) {
                $excludedFromAll = $true
                foreach ($pol in $allUsersPolicies) {
                    if ($pol.conditions.users.excludeUsers -notcontains $gaId) {
                        $excludedFromAll = $false
                        break
                    }
                }
                if ($excludedFromAll) { $candidateBreakGlassUsers += $gaId }
            }
        }

        $breakGlassCount = $candidateBreakGlassUsers.Count

        # ── Check 5.1: Are break-glass accounts excluded from all CA policies? ─────
        if ($allUsersPolicies.Count -gt 0 -and $breakGlassCount -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D5" -DomainName "Emergency Access" -CheckId "D5.1" `
                -Title "No Break-Glass Accounts Detected as Excluded from All CA Policies" `
                -Evidence "All-users CA policies: $($allUsersPolicies.Count) | GA accounts meeting break-glass exclusion pattern: 0 | Total GA assignments: $($gaPrincipalIds.Count)" `
                -CurrentState "No account appears to be consistently excluded from all broad CA policies with Global Administrator access — the pattern expected for emergency break-glass accounts." `
                -Gap "Every enabled CA policy covering all users may block access during a CA failure, conditional access policy misconfiguration, or authentication service disruption. Without accounts excluded from CA policies, a misconfigured policy could lock out all administrators — including those needed to fix the misconfiguration." `
                -Risk "High" `
                -BusinessImpact "A CA policy misconfiguration that blocks all users has locked administrators out of tenants with no break-glass recovery path. Recovery in this scenario requires Microsoft Support intervention, which can take 24–72 hours — an unacceptable business continuity risk." `
                -TargetState "Two break-glass accounts: permanently excluded from all CA policies, permanently assigned Global Administrator, credentials stored offline in sealed physical vault, hardware FIDO2 keys registered, sign-ins alerted to SOC within 5 minutes." `
                -Recommendation "Create two cloud-only (no sync) Global Administrator accounts with long random passwords (30+ chars). Exclude them from all CA policies. Store credentials in sealed physical envelopes in two physically separate locations. Register FIDO2 hardware keys. Configure Azure Monitor alerts on any sign-in from these accounts." `
                -SuccessMeasure "Two break-glass accounts exist, both excluded from all CA policies. Alert fires within 5 minutes of any sign-in. Credential access procedure tested semi-annually. No sign-ins from these accounts in the last 90 days (except planned tests)." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($breakGlassCount -eq 1) {
            $medium++
            $maturityPoints += 3
            Add-Finding -DomainId "D5" -DomainName "Emergency Access" -CheckId "D5.1" `
                -Title "Only One Break-Glass Account Detected — Two Are Required for Resilience" `
                -Evidence "Accounts excluded from all CA policies with GA role: $breakGlassCount | Recommended minimum: 2" `
                -CurrentState "One account matches the break-glass pattern (excluded from all CA policies, has GA role). Two are required for resilience — if the single account's credentials are inaccessible (vault failure, key damage), there is no fallback." `
                -Gap "A single break-glass account is a single point of failure in the emergency access architecture. Both the account credentials and the FIDO2 key must remain accessible in separate locations for true resilience." `
                -Risk "Medium" `
                -BusinessImpact "If the single break-glass account is unavailable (credentials damaged, FIDO2 key lost, account locked), there is no alternative path to recover from a total CA lockout without Microsoft Support intervention." `
                -TargetState "Two break-glass accounts in separate account configurations, stored in geographically separate locations, tested independently." `
                -Recommendation "Create a second break-glass account with identical configuration (cloud-only GA, excluded from all CA policies, separate FIDO2 key, stored in separate physical location). Test both accounts semi-annually." `
                -SuccessMeasure "Two break-glass accounts confirmed. Both excluded from all CA policies. Both credentials and FIDO2 keys accessible from separate physical vaults. Independent test of each account completed within 180 days." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 3
        }
        elseif ($breakGlassCount -ge 2) {
            $maturityPoints += 5
            Add-Finding -DomainId "D5" -DomainName "Emergency Access" -CheckId "D5.1" `
                -Title "Break-Glass Account Architecture Present ($breakGlassCount accounts excluded from all CA policies)" `
                -Evidence "Accounts matching break-glass pattern (GA role + excluded from all all-users policies): $breakGlassCount" `
                -CurrentState "$breakGlassCount accounts are excluded from all broad CA policies and hold Global Administrator role — consistent with a properly configured break-glass architecture." `
                -Gap "Configuration is correct. Operational verification is the outstanding risk: (1) are credentials stored offline in sealed vaults, (2) are FIDO2 keys registered and accessible, (3) is there a real-time alert on any sign-in from these accounts?" `
                -Risk "Info" `
                -BusinessImpact "Low when operational procedures are in place. Break-glass architecture is only effective if credentials can actually be retrieved and used when needed — and if unauthorized use is detected immediately." `
                -TargetState "Break-glass accounts tested semi-annually with documented results. Credentials in separate physical vaults. FIDO2 keys stored alongside credentials. Azure Monitor alert fires within 5 minutes of any sign-in." `
                -Recommendation "Verify operational readiness: retrieve and test break-glass procedure (without actually accessing production resources). Confirm alert configuration. Rotate credentials annually. Document break-glass procedure in a runbook accessible outside the tenant." `
                -SuccessMeasure "Break-glass sign-in alert confirmed working. Credential retrieval test completed semi-annually. No unplanned sign-ins from break-glass accounts in last 90 days." `
                -RoadmapPhase "Strategic" -MaturityContribution 5
        }

        # ── Check 5.2: Break-glass accounts not subject to MFA CA policies ─────────
        # Are break-glass accounts in MFA policies (they should be excluded)
        $mfaPolicies = @($enabled | Where-Object {
                $_.grantControls -and $_.grantControls.builtInControls -contains "mfa"
            })

        $bgInMfaPolicy = 0
        foreach ($bgId in $candidateBreakGlassUsers) {
            foreach ($pol in $mfaPolicies) {
                if ($pol.conditions.users.includeUsers -contains "All" -and
                    $pol.conditions.users.excludeUsers -notcontains $bgId) {
                    $bgInMfaPolicy++
                    break
                }
            }
        }

        if ($candidateBreakGlassUsers.Count -gt 0 -and $bgInMfaPolicy -gt 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D5" -DomainName "Emergency Access" -CheckId "D5.2" `
                -Title "Break-Glass Accounts May Be Subject to MFA CA Policies — Emergency Access Risk" `
                -Evidence "Break-glass candidates subject to MFA CA policies: $bgInMfaPolicy" `
                -CurrentState "Break-glass accounts appear to be within scope of MFA-enforcing CA policies. If the tenant's MFA or authentication service is impaired, break-glass accounts would also be blocked." `
                -Gap "Break-glass accounts must be excluded from all CA policies — including MFA policies — because their purpose is to provide access when the normal authentication infrastructure (including MFA services) may be unavailable or misconfigured." `
                -Risk "High" `
                -BusinessImpact "If MFA service is impaired during an incident, break-glass accounts subject to MFA CA policies cannot authenticate. This defeats the purpose of the break-glass architecture at exactly the moment it is needed most." `
                -TargetState "Break-glass accounts excluded from ALL enabled CA policies without exception. Their security relies on very long passwords, hardware FIDO2 keys, and physical credential storage — not CA policy controls." `
                -Recommendation "Audit all CA policies. Confirm both break-glass accounts are in the exclusion list of every enabled policy. Create a dedicated CA-Exclusion-BreakGlass group and add it to every policy's exclusion list." `
                -SuccessMeasure "CA What-If tool shows 'Not applied — excluded' for break-glass accounts against all CA policies. Manual verification of exclusion confirmed quarterly." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($candidateBreakGlassUsers.Count -ge 2) {
            $maturityPoints += 4
        }

        # ── Check 5.3: Named location for corporate network (CA continuity) ────────
        $trustedLocations = @($script:NamedLocations | Where-Object { $_.isTrusted -eq $true })

        if ($trustedLocations.Count -eq 0 -and $script:EnabledPolicies.Count -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D5" -DomainName "Emergency Access" -CheckId "D5.3" `
                -Title "No Trusted Named Locations Defined — Location-Based Emergency Fallback Unavailable" `
                -Evidence "Trusted Named Locations: 0 | Total Named Locations: $($script:NamedLocations.Count)" `
                -CurrentState "No IP-based Trusted Named Locations are defined in Conditional Access. CA policies cannot distinguish between corporate network and external access." `
                -Gap "Without trusted locations, it is not possible to create location-based emergency access policies (e.g., allow admin access from corporate network with step-up MFA as a fallback during authentication service disruption). Location-aware policies are also required for Zero Trust maturity." `
                -Risk "Medium" `
                -BusinessImpact "During authentication service incidents, location-based fallback policies are unavailable. Additionally, users traveling to high-risk geographies cannot be identified or challenged by location-aware CA controls." `
                -TargetState "All corporate egress IP ranges defined as Trusted Named Locations. Country-based block policies active for high-risk geographies. Location signals used in risk-based CA policies." `
                -Recommendation "Define corporate egress IP ranges as Trusted Named Locations (mark as trusted). Create a CA policy blocking access from OFAC-listed countries and known high-risk geographies. Enable Continuous Access Evaluation for location token binding." `
                -SuccessMeasure "All corporate IP ranges in Trusted Named Locations. Country-block policy active. Location changes detected and challenged within 1 hour (CAE)." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D5" -Name "Emergency Access" -Icon "🆘" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Break-glass candidates detected: $breakGlassCount. Trusted named locations: $($trustedLocations.Count). BG in MFA policy scope: $bgInMfaPolicy." `
            -TargetStateSummary "2 break-glass accounts excluded from all CA policies. FIDO2 keys + vaulted credentials. Trusted locations defined. Real-time activation alerts." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 6: Authentication Strength & Risk Controls ─────────────────

    Function Invoke-Domain6-AuthStrengthAndRisk {
        Write-Host "  🔐 D6: Authentication Strength & Risk Controls..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $enabled = $script:EnabledPolicies
        $authStrengths = $script:AuthStrengths

        # ── Check 6.1: Authentication Strengths in use ────────────────────────────
        $policiesUsingAuthStrength = @($enabled | Where-Object {
                $_.grantControls -and $_.grantControls.authenticationStrength -ne $null
            })

        if ($policiesUsingAuthStrength.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D6" -DomainName "Auth Strength & Risk" -CheckId "D6.1" `
                -Title "Authentication Strength Policies Not Used — All CA Grants Use Legacy MFA Grant" `
                -Evidence "CA policies using Authentication Strength: 0 | CA policies using basic MFA grant: $(($enabled | Where-Object {$_.grantControls -and $_.grantControls.builtInControls -contains 'mfa'}).Count) | Custom authentication strengths defined: $($authStrengths.Count)" `
                -CurrentState "No CA policy uses the Authentication Strength grant control. All MFA enforcement uses the legacy 'Require MFA' built-in control, which accepts any registered MFA method — including SMS OTP and voice calls." `
                -Gap "The 'Require MFA' grant control accepts any registered method: push notification, SMS OTP, voice call, TOTP. This means a user who has only registered SMS as their MFA method satisfies the MFA requirement with the weakest possible factor. Authentication Strength allows specifying required method types — a critical capability for differentiated security levels." `
                -Risk "High" `
                -BusinessImpact "Users satisfying MFA with SMS OTP or voice calls remain vulnerable to SIM-swap fraud and SS7 interception. Users satisfying MFA with Authenticator push remain vulnerable to push fatigue and AiTM attacks. Authentication Strength is the mechanism to enforce stronger methods selectively." `
                -TargetState "All CA policies use Authentication Strength rather than basic MFA grant. At minimum: standard users → Multifactor Authentication strength, admin roles → Phishing-resistant MFA strength. Custom strengths defined for sensitive application scenarios." `
                -Recommendation "Create or use built-in Authentication Strengths: (1) 'Multifactor authentication' for standard users, (2) 'Phishing-resistant MFA' for admin roles, (3) custom strength for sensitive apps requiring hardware key or CBA. Update all CA policies to use authenticationStrength instead of builtInControls MFA." `
                -SuccessMeasure "Zero CA policies using basic MFA grant. 100% use Authentication Strength. Admin policies use phishing-resistant strength. CA Insights shows method distribution moving toward stronger methods." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        elseif ($policiesUsingAuthStrength.Count -lt $enabled.Count / 2) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D6" -DomainName "Auth Strength & Risk" -CheckId "D6.1" `
                -Title "Authentication Strength Partially Adopted — $($policiesUsingAuthStrength.Count) of $($enabled.Count) Enabled Policies Use It" `
                -Evidence "Policies using Authentication Strength: $($policiesUsingAuthStrength.Count) | Policies using basic MFA grant: $(($enabled | Where-Object {$_.grantControls -and $_.grantControls.builtInControls -contains 'mfa'}).Count)" `
                -CurrentState "Authentication Strength is in use for some CA policies, but the majority still use the basic MFA grant control — creating an inconsistent and partially upgraded authentication assurance posture." `
                -Gap "Mixed use of Authentication Strength and basic MFA grant creates complexity in assurance reasoning. Users can satisfy MFA requirements via different mechanisms depending on which policy applies to their sign-in — making overall authentication assurance difficult to characterise and govern." `
                -Risk "Medium" `
                -BusinessImpact "The effective authentication assurance level is determined by whichever policy applies to each sign-in. Users covered by basic MFA policies may satisfy requirements with weaker methods even if stronger methods are available to them." `
                -TargetState "100% of CA policies that require MFA use Authentication Strength. All basic MFA grants replaced. Admin policies use phishing-resistant strength." `
                -Recommendation "Complete the migration: for each CA policy using basic MFA grant, create or assign an appropriate Authentication Strength. Prioritise admin-scoped policies first, then all-user policies." `
                -SuccessMeasure "100% of MFA-requiring CA policies use Authentication Strength. Method distribution in Sign-In logs shows increasing phishing-resistant method adoption." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D6" -DomainName "Auth Strength & Risk" -CheckId "D6.1" `
                -Title "Authentication Strength Widely Adopted ($($policiesUsingAuthStrength.Count) of $($enabled.Count) CA Policies)" `
                -Evidence "Policies using Authentication Strength: $($policiesUsingAuthStrength.Count) | Basic MFA grant policies: $(($enabled | Where-Object {$_.grantControls -and $_.grantControls.builtInControls -contains 'mfa'}).Count)" `
                -CurrentState "The majority of CA policies use Authentication Strength — demonstrating a mature, differentiated authentication assurance posture." `
                -Gap "Complete migration to Authentication Strength for all remaining basic MFA policies. Verify that custom strength definitions reflect current method availability and organisational requirements." `
                -Risk "Info" `
                -BusinessImpact "Excellent authentication maturity. Focus on completing full adoption and reviewing custom strength definitions against evolving threat landscape." `
                -TargetState "100% Authentication Strength adoption. Custom strengths reviewed annually. Admin roles on phishing-resistant. General users on multifactor authentication strength minimum." `
                -Recommendation "Complete remaining migration to Authentication Strength. Review custom strength definitions annually. Monitor method adoption in Sign-In logs to confirm users are registering and using stronger methods." `
                -SuccessMeasure "100% Authentication Strength adoption. Sign-In logs show phishing-resistant methods for >50% of admin sign-ins and >20% of all sign-ins." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 6.2: User risk policy (distinct from sign-in risk) ─────────────
        $userRiskPolicy = @($enabled | Where-Object {
                $_.conditions.userRiskLevels -and $_.conditions.userRiskLevels.Count -gt 0
            })

        if ($userRiskPolicy.Count -eq 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D6" -DomainName "Auth Strength & Risk" -CheckId "D6.2" `
                -Title "No User Risk CA Policy — Compromised Account Indicators Not Acted Upon" `
                -Evidence "Enabled CA policies with userRiskLevels condition: 0" `
                -CurrentState "No CA policy responds to user risk levels (compromised credential signals from Identity Protection). Users flagged as high-risk due to leaked credentials or anomalous behaviour receive no additional authentication challenge." `
                -Gap "User risk is distinct from sign-in risk. A user flagged as high-risk has indicators suggesting their credentials are compromised (e.g., credentials found in breach data). Without a user risk policy, a compromised account continues operating normally indefinitely." `
                -Risk "Medium" `
                -BusinessImpact "Compromised accounts detected by Identity Protection remain fully active. The attacker continues to have access while the risk state is ignored. Mean time to detection has no corresponding mean time to containment." `
                -TargetState "CA policy: High user risk → Require secure password change (or Block for admin roles). This forces the user to set a new password before continuing, which invalidates the compromised credential." `
                -Recommendation "Create a CA policy: All Users → All Cloud Apps → User risk: High → Grant: Require password change. For admin roles: High user risk → Block (require manual remediation via PIM). Requires Entra ID P2." `
                -SuccessMeasure "High-risk users automatically prompted for password change. User risk remediation time <24 hours. Zero high-risk admin accounts in Identity Protection dashboard." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
        }

        # ── Check 6.3: Continuous Access Evaluation (CAE) enablement ─────────────
        $caePolicies = @($enabled | Where-Object {
                $_.sessionControls -and
                $_.sessionControls.continuousAccessEvaluation -ne $null -and
                $_.sessionControls.continuousAccessEvaluation.mode -eq "strictEnforcement"
            })

        # CAE also works as a tenant-level default — check tenant default
        $tenantCaePolicy = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/defaultAppManagementPolicy"

        if ($caePolicies.Count -eq 0) {
            $low++
            $maturityPoints += 3
            Add-Finding -DomainId "D6" -DomainName "Auth Strength & Risk" -CheckId "D6.3" `
                -Title "Continuous Access Evaluation (CAE) Strict Enforcement Not Configured via CA" `
                -Evidence "CA policies with CAE strict enforcement session control: 0" `
                -CurrentState "No CA policy explicitly configures Continuous Access Evaluation in strict enforcement mode. CAE may be active at tenant default level but is not explicitly governed via CA policy." `
                -Gap "CAE provides near-real-time revocation of access tokens when critical events occur (password change, account disable, location change, risk elevation). Without explicit CA configuration of CAE strict mode, token lifetimes are governed by default values rather than policy-mandated enforcement." `
                -Risk "Low" `
                -BusinessImpact "During a compromise event, access token revocation may take up to 1 hour (default token lifetime) rather than minutes (CAE strict mode). For admin sessions, this window is unacceptable." `
                -TargetState "CAE strict enforcement configured via CA policy for all services that support it. Admin sessions re-evaluated continuously. Location changes prompt immediate re-authentication." `
                -Recommendation "Add CAE strict enforcement session control to admin CA policies. Enable CAE tenant-wide via Continuous Access Evaluation settings. For services that support CAE (Exchange, SharePoint, Teams), verify CAE is producing critical event signals." `
                -SuccessMeasure "CAE strict enforcement active on admin sessions. Token revocation happens within minutes of account disable or password change. CAE coverage = 100% for supported workloads." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 3
        }
        else {
            $maturityPoints += 5
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D6" -Name "Auth Strength & Risk" -Icon "🔐" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Auth Strength adopted: $($policiesUsingAuthStrength.Count) policies. User risk policies: $($userRiskPolicy.Count). CAE strict mode: $(if($caePolicies.Count -gt 0){'✓'}else{'not explicit'})." `
            -TargetStateSummary "100% Auth Strength adoption. User risk → password change. Sign-in risk → block/MFA. CAE strict mode for all admin and sensitive sessions." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 7: Device & Application Compliance Controls ────────────────

    Function Invoke-Domain7-DeviceAndAppCompliance {
        Write-Host "  💻 D7: Device & Application Compliance Controls..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $enabled = $script:EnabledPolicies

        # ── Check 7.1: Device compliance / HAADJ requirement for sensitive apps ────
        $deviceCompliancePolicies = @($enabled | Where-Object {
                $_.grantControls -and
                ($_.grantControls.builtInControls -contains "compliantDevice" -or
                $_.grantControls.builtInControls -contains "domainJoinedDevice")
            })

        if ($deviceCompliancePolicies.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D7" -DomainName "Device & App Compliance" -CheckId "D7.1" `
                -Title "No CA Policy Requiring Device Compliance or Hybrid Azure AD Join" `
                -Evidence "Enabled CA policies requiring compliantDevice or domainJoinedDevice: 0 of $($enabled.Count)" `
                -CurrentState "No CA policy enforces a device compliance or domain-join requirement on any application. Users can access corporate resources from any device — personal, unmanaged, or compromised." `
                -Gap "Without device compliance requirements, corporate data can be accessed from BYOD devices with no endpoint protection, outdated OS, no disk encryption, and no MDM visibility. The identity (user + MFA) is the only control — device trust is entirely absent." `
                -Risk "High" `
                -BusinessImpact "Unmanaged devices accessing corporate data create exfiltration paths that are invisible to the organisation. Compromised personal devices bypass all MDM-based data loss prevention controls. Data downloaded to unmanaged devices is out of corporate governance reach." `
                -TargetState "A CA policy requiring compliant device (via Intune) or Hybrid AADJ for all corporate data applications. BYOD allowed only with approved App Protection Policies (MAM) and conditional access app control for unmanaged devices." `
                -Recommendation "Create device compliance CA policies: (1) Corp-managed apps → Require compliant device, (2) BYOD/personal devices → Require app protection policy. Ensure Intune compliance policies are defined before enabling this CA policy. Start with report-only to assess impact." `
                -SuccessMeasure "Zero sign-ins to corporate apps from non-compliant devices (except MAM-managed mobile). Intune compliance coverage >95% of corporate-owned devices. Device compliance rate trending upward." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        elseif ($deviceCompliancePolicies.Count -eq 1) {
            $medium++
            $maturityPoints += 3
            Add-Finding -DomainId "D7" -DomainName "Device & App Compliance" -CheckId "D7.1" `
                -Title "Device Compliance CA Policy Present but Limited Coverage ($($deviceCompliancePolicies.Count) policy)" `
                -Evidence "Device compliance/HAADJ policies: $($deviceCompliancePolicies.Count) | App scope: $(($deviceCompliancePolicies[0].conditions.applications.includeApplications | Select-Object -First 3) -join ', ')" `
                -CurrentState "One CA policy enforces device compliance, but coverage may be limited to specific apps rather than all corporate resources." `
                -Gap "Device compliance enforced for some apps but not all creates an inconsistent device trust model. Users and attackers can identify which apps lack device enforcement and target them specifically." `
                -Risk "Medium" `
                -BusinessImpact "Apps outside device compliance scope are accessible from unmanaged devices. This creates differentiated risk — some corporate data is device-governed, while other data is accessible from any device." `
                -TargetState "Device compliance required for all corporate applications. Exceptions only for specific BYOD/MAM scenarios with compensating controls (App Protection Policy + MCAS session policy)." `
                -Recommendation "Extend device compliance requirement to all corporate apps. Use app-group targeting to include all Microsoft 365 apps and registered enterprise applications. Create a MAM policy for BYOD scenarios as an alternative compliance path." `
                -SuccessMeasure "Device compliance enforced for all corporate applications. BYOD access only via MAM. Unmanaged device sign-in count trending to zero." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 3
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D7" -DomainName "Device & App Compliance" -CheckId "D7.1" `
                -Title "Device Compliance CA Policies Present ($($deviceCompliancePolicies.Count) policies)" `
                -Evidence "Policies requiring device compliance or HAADJ: $($deviceCompliancePolicies.Count) | Sample: $(($deviceCompliancePolicies.displayName | Select-Object -First 2) -join ', ')" `
                -CurrentState "Multiple CA policies enforce device compliance requirements across different application and user scopes." `
                -Gap "Verify complete coverage: use CA Insights to confirm all corporate apps are covered by device requirements. Check for gaps in the app-scoping that may allow access from non-compliant devices." `
                -Risk "Info" `
                -BusinessImpact "Low — device trust is enforced. Focus on coverage completeness and ensuring Intune compliance policies reflect current security requirements." `
                -TargetState "Device compliance required for all corporate apps. Intune compliance policies current. BYOD via MAM + session policy only. Device health attestation enabled." `
                -Recommendation "Review device compliance coverage in CA Insights. Ensure Intune compliance policies are up to date. Consider enabling health attestation requirements in compliance policy." `
                -SuccessMeasure "CA Insights shows device compliance enforced for all corporate app sign-ins. Non-compliant device sign-in count = 0. Intune compliance rate >98%." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 7.2: App protection policy (MAM) for unmanaged / mobile ─────────
        $appProtectionPolicies = @($enabled | Where-Object {
                $_.grantControls -and
                $_.grantControls.builtInControls -contains "approvedApplication"
            })

        if ($appProtectionPolicies.Count -eq 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D7" -DomainName "Device & App Compliance" -CheckId "D7.2" `
                -Title "No App Protection Policy (MAM) CA Requirement for Unmanaged / BYOD Devices" `
                -Evidence "Enabled CA policies requiring approvedApplication (app protection / MAM): 0" `
                -CurrentState "No CA policy requires approved (Intune App Protection Policy-managed) applications on unmanaged devices. BYOD users can use native mail, browser, or third-party apps to access corporate data without any container or DLP controls." `
                -Gap "Without App Protection Policy requirements, corporate data accessed on BYOD devices is stored in the device's native application containers without encryption, selective wipe capability, or data leakage prevention controls." `
                -Risk "Medium" `
                -BusinessImpact "Corporate email, files, and Teams messages accessed from personal devices on native apps are stored outside the organisation's DLP and data governance controls. Selective corporate wipe is not possible without MAM enrollment." `
                -TargetState "CA policy for mobile/BYOD: Require approved application OR require app protection policy. Intune App Protection Policies deployed for iOS and Android covering all data-handling apps." `
                -Recommendation "Create a CA policy targeting mobile platforms (iOS, Android) → All Cloud Apps → Require approved app (Outlook, Teams, Edge). Deploy Intune App Protection Policies. Enable App-conditional access (MCAS/Defender for Cloud Apps) for session-level controls on unmanaged devices." `
                -SuccessMeasure "Zero BYOD access to corporate data via non-MAM-managed apps. Selective wipe capability confirmed for all enrolled BYOD devices. DLP policies applied to MAM-managed apps." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
        }

        # ── Check 7.3: App-conditional access / session controls (MCAS/Defender) ──
        $sessionControlPolicies = @($enabled | Where-Object {
                $_.sessionControls -and
                $_.sessionControls.applicationEnforcedRestrictions -ne $null
            })

        $cloudAppSecurityPolicies = @($enabled | Where-Object {
                $_.sessionControls -and
                $_.sessionControls.cloudAppSecurity -ne $null
            })

        $totalSessionPolicies = $sessionControlPolicies.Count + $cloudAppSecurityPolicies.Count

        if ($totalSessionPolicies -eq 0) {
            $low++
            $maturityPoints += 3
            Add-Finding -DomainId "D7" -DomainName "Device & App Compliance" -CheckId "D7.3" `
                -Title "No App-Conditional Access or Microsoft Defender for Cloud Apps Session Controls" `
                -Evidence "Policies with application-enforced restrictions: $($sessionControlPolicies.Count) | Policies with Cloud App Security session control: $($cloudAppSecurityPolicies.Count)" `
                -CurrentState "No CA policy uses application-enforced restrictions or Defender for Cloud Apps session controls. Once users authenticate, their session has unrestricted access to application features and data." `
                -Gap "Without session-level controls, authentication governs access but cannot control what users do within applications — downloading, printing, copying sensitive data, or forwarding to external recipients are all ungoverned for unmanaged-device sessions." `
                -Risk "Low" `
                -BusinessImpact "For unmanaged devices in particular, session controls are the last line of defense against data exfiltration. Without them, a user on a personal device can download all SharePoint content with no DLP intervention." `
                -TargetState "MCAS/Defender for Cloud Apps session policies for unmanaged devices: block download of sensitive data, block print/copy of classified content, restrict forwarding. Application-enforced restrictions for SharePoint (read-only on unmanaged devices)." `
                -Recommendation "Enable Defender for Cloud Apps (M365 E5 / Defender add-on). Create CA policy with Cloud App Security session control for unmanaged devices → sensitive apps. Configure session policy: block download of sensitive files, allow read-only. Enable SharePoint application-enforced restrictions." `
                -SuccessMeasure "MCAS session policies active for all sensitive app + unmanaged device combinations. Download block rate confirms policy effectiveness. DLP alerts from MCAS configured and monitored." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 3
        }
        else {
            $maturityPoints += 5
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D7" -Name "Device & App Compliance" -Icon "💻" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Device compliance policies: $($deviceCompliancePolicies.Count). MAM/approved app policies: $($appProtectionPolicies.Count). Session control policies: $totalSessionPolicies." `
            -TargetStateSummary "Device compliance for all corporate apps. MAM for BYOD. Session controls for unmanaged devices. App-enforced restrictions for SharePoint." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 8: Policy Sprawl & Operational Manageability ───────────────

    Function Invoke-Domain8-PolicySprawlAndManageability {
        Write-Host "  📊 D8: Policy Sprawl & Operational Manageability..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $all = $script:AllCAPolicies
        $enabled = $script:EnabledPolicies
        $disabled = $script:DisabledPolicies
        $reportOnly = $script:ReportOnlyPolicies

        # ── Check 8.1: Total policy count (sprawl threshold) ──────────────────────
        $totalCount = $all.Count

        if ($totalCount -gt 50) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D8" -DomainName "Sprawl & Manageability" -CheckId "D8.1" `
                -Title "CA Policy Sprawl Detected — $totalCount Total Policies Exceeds Manageable Threshold" `
                -Evidence "Total CA policies (all states): $totalCount | Enabled: $($enabled.Count) | Report-only: $($reportOnly.Count) | Disabled: $($disabled.Count)" `
                -CurrentState "$totalCount Conditional Access policies exist across all states. Policy landscapes above 50 policies indicate accumulated policy debt — incremental additions without rationalisation or decommissioning." `
                -Gap "Excessive policy counts create significant governance risk: policy interaction prediction becomes unreliable, troubleshooting requires evaluating dozens of potential matches, audits are time-consuming, and change management risk increases with each policy interaction." `
                -Risk "High" `
                -BusinessImpact "Policy sprawl is both a security and operational risk. Security: unintended access due to policy interaction complexity. Operational: incident response takes longer when sign-in failures require evaluating 50+ policies. Engineering: change management risk increases exponentially with policy count." `
                -TargetState "CA policy count <25 for most enterprises. Achieved through policy consolidation: one policy per distinct purpose, workload-specific policies replacing per-app policies, group-based policies replacing per-user policies. Regular policy hygiene reviews." `
                -Recommendation "Conduct a CA policy consolidation workshop. Map each policy to its business purpose. Identify policies with identical or highly overlapping scope that can be merged. Archive (delete) disabled policies that are superseded. Target: <25 enabled policies covering the same security outcomes." `
                -SuccessMeasure "Total enabled CA policies <25. Policy consolidation ratio: each policy covers a distinct security scenario. Annual policy review produces net reduction or stable count with documented justification for each policy." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 1
        }
        elseif ($totalCount -gt 25) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D8" -DomainName "Sprawl & Manageability" -CheckId "D8.1" `
                -Title "CA Policy Count Above Recommended Baseline ($totalCount total policies)" `
                -Evidence "Total policies: $totalCount | Enabled: $($enabled.Count) | Report-only: $($reportOnly.Count) | Disabled: $($disabled.Count)" `
                -CurrentState "$totalCount total CA policies — approaching the threshold where policy interaction complexity becomes a governance challenge." `
                -Gap "Policy count in the 25–50 range indicates growth without consolidation. While manageable today, without active policy governance the count will continue increasing, making the landscape progressively harder to reason about and change safely." `
                -Risk "Medium" `
                -BusinessImpact "At this scale, policy interaction analysis requires dedicated tooling (CA Insights, What-If tool). Change management processes need formalisation to prevent unintended policy conflicts during modifications." `
                -TargetState "Policy count stabilised below 25 enabled policies. Each policy has a documented owner, purpose, scope, and review date. Annual policy hygiene review maintains the target count." `
                -Recommendation "Document the purpose of each enabled policy. Identify consolidation opportunities. Delete disabled policies older than 90 days. Set a 25-policy target and a formal review process for any net addition." `
                -SuccessMeasure "Policy count below 25. Policy inventory document current. Annual review completed. No net policy increase without corresponding consolidation." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D8" -DomainName "Sprawl & Manageability" -CheckId "D8.1" `
                -Title "CA Policy Count Within Manageable Range ($totalCount total policies)" `
                -Evidence "Total policies: $totalCount | Enabled: $($enabled.Count) | Report-only: $($reportOnly.Count) | Disabled: $($disabled.Count)" `
                -CurrentState "$totalCount total CA policies — within a manageable range for a well-governed CA architecture." `
                -Gap "Maintain discipline to prevent policy sprawl as requirements evolve. Each new policy should have a clear justification and, where possible, should consolidate rather than add." `
                -Risk "Info" `
                -BusinessImpact "Low — policy count is manageable. Establish governance now to maintain this posture as the environment grows." `
                -TargetState "Policy count remains below 25. Policy inventory maintained. Annual review process established. New policies require documented justification." `
                -Recommendation "Document a CA governance policy: minimum required information for any new policy (purpose, scope, owner, review date, expiry if temporary). Review annually. Monitor count monthly via audit log alerts." `
                -SuccessMeasure "Policy count stable year-on-year. Policy inventory document current. No undocumented policies. Annual review completed." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 8.2: Named locations coverage ──────────────────────────────────
        $namedLocations = $script:NamedLocations
        $ipBasedLocations = @($namedLocations | Where-Object { $_."@odata.type" -like "*ipNamedLocation*" })
        $countryBasedLocations = @($namedLocations | Where-Object { $_."@odata.type" -like "*countryNamedLocation*" })

        if ($namedLocations.Count -eq 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D8" -DomainName "Sprawl & Manageability" -CheckId "D8.2" `
                -Title "No Named Locations Defined — Location-Aware CA Policy Architecture Unavailable" `
                -Evidence "Named Locations (total): 0 | IP-based: 0 | Country-based: 0" `
                -CurrentState "No Named Locations (trusted IP ranges or country sets) are defined. CA policies cannot distinguish corporate vs external access, or trusted vs untrusted geographies." `
                -Gap "Without Named Locations, the CA policy set cannot implement: network-based step-up authentication, travel anomaly detection, country-based access restrictions, or trusted corporate network exemptions." `
                -Risk "Medium" `
                -BusinessImpact "Location intelligence is unavailable for CA policy decisions. Sign-ins from sanctioned-country threat actors, impossible travel scenarios, and off-network risky locations cannot be differentiated from normal corporate access." `
                -TargetState "Corporate egress IPs defined as Trusted Named Locations. A country-based Named Location covering OFAC-listed and high-risk geographies. Location conditions used in risk and device compliance policies." `
                -Recommendation "Step 1: Define corporate egress IP ranges as IP-based Trusted Named Locations. Step 2: Create a country-based Named Location for high-risk/blocked countries. Step 3: Create CA policy blocking access from blocked-country location for all corporate apps." `
                -SuccessMeasure "All corporate egress IPs in Trusted Named Locations (updated quarterly). Country block policy active. Location change detection via CAE working for supported services." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        elseif ($ipBasedLocations.Count -gt 0 -and $countryBasedLocations.Count -eq 0) {
            $low++
            $maturityPoints += 3
            Add-Finding -DomainId "D8" -DomainName "Sprawl & Manageability" -CheckId "D8.2" `
                -Title "IP-Based Named Locations Defined but No Country-Based Locations" `
                -Evidence "IP-based Named Locations: $($ipBasedLocations.Count) | Country-based Named Locations: 0" `
                -CurrentState "Corporate IP ranges are defined as Named Locations, but no country-based locations exist to enable geography-based CA policies." `
                -Gap "IP-based trusted locations provide network-aware CA policies, but without country-based locations, geography-based access restrictions (high-risk country blocks, OFAC compliance) are not implementable." `
                -Risk "Low" `
                -BusinessImpact "Access from high-risk or sanctioned geographies is not automatically restricted. Threat actors operating from countries with high attack traffic are not differentiated from normal users." `
                -TargetState "Country-based Named Location covering restricted geographies. CA policy blocking access from these countries for all corporate apps. Exception process for legitimate business travel." `
                -Recommendation "Create a country-based Named Location grouping OFAC-listed countries and geographies associated with high attack volumes. Apply a CA Block policy for all apps against this location. Provide a travel exception process via temporary group exclusion with management approval." `
                -SuccessMeasure "Country-based block policy active. Sign-In logs show zero successful authentications from blocked countries. Exception process tested and documented." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 3
        }
        else {
            $maturityPoints += 5
        }

        # ── Check 8.3: CA policy without any conditions (applies to all sign-ins) ─
        # A policy with no application, user, or location constraints is a blunt instrument
        $unconditionalPolicies = @($enabled | Where-Object {
                (-not $_.conditions.applications.includeApplications -or
                $_.conditions.applications.includeApplications -contains "All" -or
                $_.conditions.applications.includeApplications.Count -eq 0) -and
                (-not $_.conditions.users.includeUsers -or
                $_.conditions.users.includeUsers -contains "All") -and
                (-not $_.conditions.locations) -and
                (-not $_.conditions.platforms) -and
                (-not $_.conditions.clientAppTypes -or
                $_.conditions.clientAppTypes -contains "all")
            })

        if ($unconditionalPolicies.Count -gt 2) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D8" -DomainName "Sprawl & Manageability" -CheckId "D8.3" `
                -Title "Multiple Unconditional (Catch-All) CA Policies — Architectural Bluntness Risk ($($unconditionalPolicies.Count))" `
                -Evidence "Enabled policies with no location, platform, or client-app conditions: $($unconditionalPolicies.Count) | Names: $(($unconditionalPolicies.displayName | Select-Object -First 3) -join '; ')" `
                -CurrentState "$($unconditionalPolicies.Count) CA policies apply to all users, all apps, all platforms, all locations, and all client app types with no additional conditions. These are maximum-breadth policies that offer no contextual differentiation." `
                -Gap "Multiple catch-all policies suggest the CA architecture is based on blunt-instrument controls rather than contextual, risk-proportionate enforcement. This pattern makes it difficult to implement nuanced access decisions (step-up for high-risk contexts, reduced friction for low-risk contexts)." `
                -Risk "Medium" `
                -BusinessImpact "Blunt policies create a binary access model (allow/deny with MFA) rather than a risk-proportionate model. This can result in over-restriction in low-risk scenarios (user frustration, shadow IT) or under-restriction where additional context should trigger stronger controls." `
                -TargetState "CA policies use contextual conditions to right-size controls: stronger authentication for high-risk contexts (external network, admin roles, sensitive apps), reduced friction for low-risk contexts (trusted network, compliant device)." `
                -Recommendation "Evolve from catch-all to contextual CA architecture: (1) add platform conditions to differentiate mobile vs desktop, (2) add location conditions to differentiate trusted vs untrusted networks, (3) create app-specific policies for sensitive workloads with higher assurance requirements." `
                -SuccessMeasure "All CA policies include at least one condition beyond users/apps. Risk-proportionate architecture demonstrated by varying authentication requirements based on context. User friction data shows improvement." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D8" -Name "Sprawl & Manageability" -Icon "📊" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Total policies: $totalCount (enabled: $($enabled.Count), report-only: $($reportOnly.Count), disabled: $($disabled.Count)). Named locations: $($namedLocations.Count). Unconditional policies: $($unconditionalPolicies.Count)." `
            -TargetStateSummary "<25 enabled policies. IP + country named locations active. Contextual, risk-proportionate policy architecture. Annual policy hygiene reviews." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion
    
    #region ── JSON Serialisation Helpers ────────────────────────────────────────

    Function ConvertTo-JsonSafeString {
        param ([string]$Value)
        if (-not $Value) { return "" }
        $Value = $Value.Replace("\", "\\")
        $Value = $Value.Replace('"', '\"')
        $Value = $Value.Replace("`r`n", " ").Replace("`n", " ").Replace("`r", " ")
        $Value = $Value.Replace("`t", " ")
        $Value = $Value.Replace("<", "\u003c").Replace(">", "\u003e")
        $Value = $Value.Replace("$", "\u0024")
        return $Value
    }


    Function Build-DomainsJson {
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.Append("[")
        $first = $true

        foreach ($d in $script:Domains) {
            if (-not $first) { $null = $sb.Append(",") }
            $first = $false
            $null = $sb.Append("{")
            $null = $sb.Append("""id"":""$(ConvertTo-JsonSafeString $d.Id)"",")
            $null = $sb.Append("""name"":""$(ConvertTo-JsonSafeString $d.Name)"",")
            $null = $sb.Append("""icon"":""$(ConvertTo-JsonSafeString $d.Icon)"",")
            $null = $sb.Append("""maturityScore"":$($d.MaturityScore),")
            $null = $sb.Append("""maturityLabel"":""$(ConvertTo-JsonSafeString $d.MaturityLabel)"",")
            $null = $sb.Append("""maturityColor"":""$(ConvertTo-JsonSafeString $d.MaturityColor)"",")
            $null = $sb.Append("""currentStateSummary"":""$(ConvertTo-JsonSafeString $d.CurrentStateSummary)"",")
            $null = $sb.Append("""targetStateSummary"":""$(ConvertTo-JsonSafeString $d.TargetStateSummary)"",")
            $null = $sb.Append("""critical"":$($d.CriticalCount),")
            $null = $sb.Append("""high"":$($d.HighCount),")
            $null = $sb.Append("""medium"":$($d.MediumCount),")
            $null = $sb.Append("""low"":$($d.LowCount),")
            $null = $sb.Append("""dataQuality"":""$(ConvertTo-JsonSafeString $d.DataQuality)""")
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
            $null = $sb.Append("""domainId"":""$(ConvertTo-JsonSafeString $f.DomainId)"",")
            $null = $sb.Append("""domainName"":""$(ConvertTo-JsonSafeString $f.DomainName)"",")
            $null = $sb.Append("""checkId"":""$(ConvertTo-JsonSafeString $f.CheckId)"",")
            $null = $sb.Append("""title"":""$(ConvertTo-JsonSafeString $f.Title)"",")
            $null = $sb.Append("""evidence"":""$(ConvertTo-JsonSafeString $f.Evidence)"",")
            $null = $sb.Append("""currentState"":""$(ConvertTo-JsonSafeString $f.CurrentState)"",")
            $null = $sb.Append("""gap"":""$(ConvertTo-JsonSafeString $f.Gap)"",")
            $null = $sb.Append("""risk"":""$(ConvertTo-JsonSafeString $f.Risk)"",")
            $null = $sb.Append("""businessImpact"":""$(ConvertTo-JsonSafeString $f.BusinessImpact)"",")
            $null = $sb.Append("""targetState"":""$(ConvertTo-JsonSafeString $f.TargetState)"",")
            $null = $sb.Append("""recommendation"":""$(ConvertTo-JsonSafeString $f.Recommendation)"",")
            $null = $sb.Append("""successMeasure"":""$(ConvertTo-JsonSafeString $f.SuccessMeasure)"",")
            $null = $sb.Append("""roadmapPhase"":""$(ConvertTo-JsonSafeString $f.RoadmapPhase)""")
            $null = $sb.Append("}")
        }

        $null = $sb.Append("]")
        return $sb.ToString()
    }

    #endregion

    #region ── HTML Dashboard ────────────────────────────────────────────────────

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
        $ringColorForScore = $script:MaturityColors[[int][Math]::Round($OverallMaturity)]
        if (-not $ringColorForScore) { $ringColorForScore = "#f85149" }

        $circumference = [Math]::Round(2 * [Math]::PI * 54, 2)   # r=54
        $fillPct = $OverallMaturity / 5.0
        $ringDash = [Math]::Round($circumference * $fillPct, 2)
        $ringGap = [Math]::Round($circumference * (1 - $fillPct), 2)

        $totalCritical = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
        $totalHigh = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
        $totalMedium = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count
        $totalLow = ($script:Findings | Where-Object { $_.Risk -eq "Low" -or $_.Risk -eq "Info" }).Count
        $totalFindings = $script:Findings.Count

        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CA Architecture Assessment — __TENANT_NAME__</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
/* ── Variables ── */
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
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;font-size:13px}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
/* ── Layout ── */
#sidebar{position:fixed;left:0;top:0;width:236px;height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;overflow-y:auto}
#main{margin-left:236px;padding:24px;min-height:100vh}
.page{display:none}.page.active{display:block;animation:fadeIn .25s ease}
/* ── Sidebar ── */
.logo-block{padding:20px 16px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,#1f4ebe,#a371f7);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:8px}
.logo-title{font-size:12px;font-weight:700;line-height:1.4;color:var(--text)}
.logo-sub{font-size:10px;color:var(--muted);margin-top:2px}
.ver-badge{font-size:9px;color:var(--muted);font-family:var(--mono);margin-top:6px;background:var(--surface2);border:1px solid var(--border);padding:2px 7px;border-radius:20px;display:inline-block}
nav{flex:1;padding:12px 8px}
.nav-section{font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);padding:8px 8px 4px;font-weight:700}
.nav-btn{display:flex;align-items:center;gap:8px;width:100%;background:none;border:none;color:var(--muted2);padding:7px 10px;border-radius:var(--radius-sm);cursor:pointer;font-size:12px;font-family:var(--sans);text-align:left;transition:all .15s}
.nav-btn:hover{background:var(--surface2);color:var(--text)}
.nav-btn.active{background:rgba(56,139,253,.12);color:var(--accent);border-left:3px solid var(--accent);padding-left:7px;font-weight:700}
.nav-icon{font-size:14px;width:18px;text-align:center}
.theme-toggle{padding:12px 16px;border-top:1px solid var(--border)}
.theme-pill{display:flex;background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:2px}
.theme-opt{flex:1;text-align:center;padding:4px 8px;border-radius:16px;cursor:pointer;font-size:11px;color:var(--muted);transition:all .15s}
.theme-opt.active{background:var(--accent);color:#fff;font-weight:700}
.sidebar-footer{padding:10px 16px 16px;font-size:10px;color:var(--muted);line-height:1.6;border-top:1px solid var(--border)}
.kbd{background:var(--surface3);border:1px solid var(--border);border-radius:3px;padding:1px 5px;font-family:var(--mono);font-size:9px}
/* ── Page Header ── */
.page-header{margin-bottom:20px}
.page-header h1{font-size:20px;font-weight:700;margin-bottom:4px}
.page-header p{font-size:12px;color:var(--muted2)}
/* ── Health Card ── */
.health-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px 24px;display:flex;align-items:center;gap:24px;margin-bottom:20px}
.health-ring-wrap{position:relative;flex-shrink:0}
.health-ring-bg{fill:none;stroke:var(--surface3);stroke-width:10}
.health-ring-fill{fill:none;stroke-width:10;stroke-linecap:round;transform:rotate(-90deg);transform-origin:50% 50%;transition:stroke-dasharray 1.2s ease}
.ring-label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring-val{font-size:24px;font-weight:700;font-family:var(--mono);line-height:1}
.ring-sub{font-size:11px;color:var(--muted)}
.health-info h2{font-size:17px;font-weight:700;margin-bottom:6px}
.health-info p{font-size:12px;color:var(--muted2);line-height:1.6;margin-bottom:10px}
.maturity-scale{display:flex;gap:6px;flex-wrap:wrap}
.ms-pill{font-size:10px;padding:3px 10px;border-radius:20px;border:1px solid;font-weight:600;font-family:var(--mono)}
/* ── Stats Grid ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-top:3px solid;border-radius:var(--radius);padding:14px 16px;transition:transform .2s}
.stat-card:hover{transform:translateY(-2px)}
.c-red   {border-top-color:var(--red)}
.c-amber {border-top-color:var(--amber)}
.c-blue  {border-top-color:var(--accent)}
.c-green {border-top-color:var(--green)}
.c-purple{border-top-color:var(--accent3)}
.c-cyan  {border-top-color:var(--accent2)}
.stat-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.stat-value{font-size:26px;font-weight:700;font-family:var(--mono);line-height:1;margin-bottom:4px}
.stat-sub{font-size:10px;color:var(--muted)}
/* ── Panels ── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:16px}
.panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.panel-title{font-size:13px;font-weight:700}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
/* ── Domain Cards ── */
.domain-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px;margin-bottom:20px}
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
#detailDrawer{position:absolute;right:0;top:0;height:100%;width:540px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);padding:24px;overflow-y:auto;transform:translateX(100%);transition:transform .3s cubic-bezier(.4,0,.2,1)}
#detailPanel.open #detailDrawer{transform:none}
.drawer-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px}
.drawer-title{font-size:15px;font-weight:700;line-height:1.4;flex:1;margin-right:12px}
.drawer-close{background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;padding:0;line-height:1}
.drawer-close:hover{color:var(--text)}
.drawer-chips{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:16px}
.drawer-section{margin-bottom:14px}
.drawer-label{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:5px;font-weight:700}
.drawer-value{font-size:12px;line-height:1.6;color:var(--muted2);background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px;border:1px solid var(--border)}
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
/* ── Arch note ── */
.arch-note{background:linear-gradient(135deg,rgba(56,139,253,.08),rgba(163,113,247,.08));border:1px solid rgba(56,139,253,.2);border-radius:var(--radius);padding:14px 16px;margin-bottom:14px;font-size:12px;line-height:1.6;color:var(--muted2)}
.arch-note strong{color:var(--accent)}
/* ── Target State panel ── */
.target-card{background:linear-gradient(135deg,rgba(63,185,80,.06),rgba(57,197,207,.06));border:1px solid rgba(63,185,80,.2);border-radius:var(--radius);padding:14px 16px;margin-bottom:10px}
.target-card h4{font-size:11px;color:var(--green);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px}
.target-card p{font-size:12px;color:var(--muted2);line-height:1.6}
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
    <div class="logo-icon">🚦</div>
    <div class="logo-title">Conditional Access<br>Architecture Assessment</div>
    <div class="logo-sub">Enterprise CA Architecture Review</div>
    <div class="ver-badge">v1.0 · __ASSESSMENT_DATE__</div>
  </div>

  <nav>
    <div class="nav-section">Assessment</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span>Overview</button>
    <button class="nav-btn" onclick="showPage('domains',this)"><span class="nav-icon">🗂️</span>Domain Results</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span>Findings</button>
    <button class="nav-btn" onclick="showPage('roadmap',this)"><span class="nav-icon">🗺️</span>Roadmap</button>
    <div class="nav-section">Architecture</div>
    <button class="nav-btn" onclick="showPage('target',this)"><span class="nav-icon">🎯</span>Target Architecture</button>
    <button class="nav-btn" onclick="showPage('model',this)"><span class="nav-icon">📐</span>Assessment Model</button>
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
    <span class="kbd">/</span> search &nbsp;
    <span class="kbd">←→</span> navigate
  </div>
</div>

<!-- ── Main ── -->
<div id="main">

  <!-- ══ Overview ══════════════════════════════════════════════════════════ -->
  <div class="page active" id="page-overview">
    <div class="page-header">
      <h1>🚦 Conditional Access Architecture Assessment</h1>
      <p>Tenant: <strong>__TENANT_NAME__</strong> &nbsp;·&nbsp; Assessed: __ASSESSMENT_DATE__ &nbsp;·&nbsp; Total findings: __TOTAL_FINDINGS__</p>
    </div>

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
        <h2>CA Architecture Maturity: __OVERALL_LABEL__</h2>
        <p>The Conditional Access policy landscape has been assessed across 8 architectural domains. This assessment evaluates policy coherence, exclusion governance, privileged identity protection, emergency access, authentication strength, device compliance, and operational manageability — not simply the count of policies.</p>
        <div class="maturity-scale">
          <div class="ms-pill" style="color:#f85149;border-color:#f85149">1 · Initial</div>
          <div class="ms-pill" style="color:#d29922;border-color:#d29922">2 · Developing</div>
          <div class="ms-pill" style="color:#388bfd;border-color:#388bfd">3 · Defined</div>
          <div class="ms-pill" style="color:#39c5cf;border-color:#39c5cf">4 · Managed</div>
          <div class="ms-pill" style="color:#3fb950;border-color:#3fb950">5 · Optimised</div>
        </div>
      </div>
    </div>

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
        <div class="stat-value" style="color:var(--accent3)">8</div>
        <div class="stat-sub">CA architecture domains</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-label">Total Findings</div>
        <div class="stat-value" style="color:var(--accent2)">__TOTAL_FINDINGS__</div>
        <div class="stat-sub">Evidence-based checks</div>
      </div>
    </div>

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

    <div class="arch-note">
      <strong>Architecture Assessment Model</strong> — This report follows the pattern:
      <em>Context → Current State → Gap/Risk → Target State → Transition Recommendation → Success Measures</em>.
      Maturity levels range from <strong>1 (Initial)</strong> through <strong>5 (Optimised)</strong>.
      Findings are prioritised by business impact, blast radius, and privilege exposure — not by configuration deviation alone.
      Where applicable, relationships between identities, groups, roles, applications and policies are considered to identify access paths and blast-radius implications.
    </div>
  </div>

  <!-- ══ Domain Results ════════════════════════════════════════════════════ -->
  <div class="page" id="page-domains">
    <div class="page-header">
      <h1>🗂️ Domain Results</h1>
      <p>Maturity scores and finding counts per CA architecture domain. Click a domain card to view its findings.</p>
    </div>
    <div class="domain-grid" id="domainGrid"></div>
  </div>

  <!-- ══ Findings ══════════════════════════════════════════════════════════ -->
  <div class="page" id="page-findings">
    <div class="page-header">
      <h1>🔍 Findings</h1>
      <p>All evidence-based architectural findings. Click any row to view the full detail, gap analysis, and recommendation.</p>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input id="findSearch" type="text" placeholder="Search findings..." oninput="filterFindings()">
        </div>
        <div class="filter-pills">
          <span class="fpill fpill-all active"    onclick="setRiskFilter('All',this)">All</span>
          <span class="fpill fpill-crit"          onclick="setRiskFilter('Critical',this)">🔴 Critical</span>
          <span class="fpill fpill-high"          onclick="setRiskFilter('High',this)">🟠 High</span>
          <span class="fpill fpill-medium"        onclick="setRiskFilter('Medium',this)">🔵 Medium</span>
          <span class="fpill fpill-low"           onclick="setRiskFilter('Low',this)">🟢 Low/Info</span>
        </div>
        <button class="fpill" onclick="exportFindingsCSV()">⬇ Export CSV</button>
        <button class="fpill" onclick="clearDomainFilter()" id="clearDomainBtn" style="display:none">✕ Clear Domain Filter</button>
      </div>
      <table>
        <thead>
          <tr>
            <th id="th-risk"         onclick="sortFindings('risk')">Risk <span class="sort-arrow">↕</span></th>
            <th id="th-domainId"     onclick="sortFindings('domainId')">Domain <span class="sort-arrow">↕</span></th>
            <th id="th-title"        onclick="sortFindings('title')">Finding <span class="sort-arrow">↕</span></th>
            <th id="th-roadmapPhase" onclick="sortFindings('roadmapPhase')">Phase <span class="sort-arrow">↕</span></th>
          </tr>
        </thead>
        <tbody id="findingsTbody"></tbody>
      </table>
      <div class="pagination" id="findingsPagination"></div>
    </div>
  </div>

  <!-- ══ Roadmap ═══════════════════════════════════════════════════════════ -->
  <div class="page" id="page-roadmap">
    <div class="page-header">
      <h1>🗺️ Transition Roadmap</h1>
      <p>Findings sequenced by dependency and risk reduction impact. Click any item to view its full detail and recommendation.</p>
    </div>
    <div class="roadmap-grid" id="roadmapGrid"></div>
  </div>

  <!-- ══ Target Architecture ═══════════════════════════════════════════════ -->
  <div class="page" id="page-target">
    <div class="page-header">
      <h1>🎯 Target Architecture</h1>
      <p>The target state for each CA architecture domain, derived from Microsoft Identity Reference Architecture and Zero Trust principles.</p>
    </div>
    <div class="arch-note">
      <strong>Zero Trust CA Target Architecture</strong> — The target CA policy model is: <em>one policy per distinct security scenario</em>, with contextual conditions (user role, device state, location, app sensitivity, risk level) driving proportionate authentication requirements. No standing privilege. No permanent exclusions (except break-glass). All controls evidence-based, access-reviewed, and continuously monitored.
    </div>
    <div id="targetDomainList" style="display:grid;gap:12px"></div>
  </div>

  <!-- ══ Assessment Model ═══════════════════════════════════════════════════ -->
  <div class="page" id="page-model">
    <div class="page-header">
      <h1>📐 Assessment Model</h1>
      <p>How this assessment was conducted, what it measures, and how to interpret the findings.</p>
    </div>
    <div class="panel">
      <div class="panel-header"><span class="panel-title">Architectural Thinking Model</span></div>
      <p style="font-size:12px;color:var(--muted2);line-height:1.7;margin-bottom:12px">
        Each check follows: <strong style="color:var(--text)">Context → Current State → Gap/Risk → Target State → Transition Recommendation → Success Measures</strong>
      </p>
      <p style="font-size:12px;color:var(--muted2);line-height:1.7;margin-bottom:10px"><strong style="color:var(--text)">Evidence:</strong> Raw data retrieved from Microsoft Graph API — policy configurations, named locations, authentication strengths, role assignments.</p>
      <p style="font-size:12px;color:var(--muted2);line-height:1.7;margin-bottom:10px"><strong style="color:var(--text)">Current State:</strong> Architectural interpretation of the evidence — what is true about the CA posture today.</p>
      <p style="font-size:12px;color:var(--muted2);line-height:1.7;margin-bottom:10px"><strong style="color:var(--text)">Gap/Risk:</strong> The delta between current state and the Zero Trust target architecture — not just a configuration deviation.</p>
      <p style="font-size:12px;color:var(--muted2);line-height:1.7;margin-bottom:10px"><strong style="color:var(--text)">Business Impact:</strong> Risk prioritised by business consequence, blast radius (tenant-wide vs scoped), and privilege exposure — not merely by policy count or deviation score.</p>
      <p style="font-size:12px;color:var(--muted2);line-height:1.7;margin-bottom:10px"><strong style="color:var(--text)">Target State:</strong> The architectural end-state aligned to Microsoft Identity Reference Architecture and Zero Trust principles.</p>
      <p style="font-size:12px;color:var(--muted2);line-height:1.7;margin-bottom:10px"><strong style="color:var(--text)">Recommendation:</strong> Actionable, technology-specific remediation with implementation sequence.</p>
      <p style="font-size:12px;color:var(--muted2);line-height:1.7;margin-bottom:10px"><strong style="color:var(--text)">Success Measures:</strong> Quantifiable indicators confirming the recommendation was implemented and is effective.</p>
      <p style="font-size:12px;color:var(--muted2);line-height:1.7"><strong style="color:var(--text)">Roadmap Phase:</strong> Sequenced by dependency and risk reduction: 0–30 days (critical/foundational), 31–60 days (high/structural), 61–90 days (medium/operational), Strategic (continuous improvement).</p>
    </div>
    <div class="panel">
      <div class="panel-header"><span class="panel-title">8 Assessment Domains</span></div>
      <div id="modelDomainList" style="display:grid;gap:10px"></div>
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
    <div class="drawer-section"><div class="drawer-label">Gap / Architectural Risk</div><div class="drawer-value" id="drawerGap"></div></div>
    <div class="drawer-section"><div class="drawer-label">Business Impact</div><div class="drawer-value" id="drawerImpact"></div></div>
    <div class="drawer-section"><div class="drawer-label">Target State</div><div class="drawer-value" id="drawerTarget"></div></div>
    <div class="drawer-section"><div class="drawer-label">Recommendation</div><div class="drawer-value" id="drawerRec"></div></div>
    <div class="drawer-section"><div class="drawer-label">Success Measures</div><div class="drawer-value" id="drawerSuccess"></div></div>
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
const DOMAINS  = __DOMAINS_JSON__;
const FINDINGS = __FINDINGS_JSON__;

// ── Utilities ─────────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
function showToast(msg,icon='✅'){const t=document.getElementById('toast');t.textContent=(icon?icon+' ':'')+msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800);}

// ── Navigation ────────────────────────────────────────────────────────────────
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn) btn.classList.add('active');
  if(id==='findings')  setTimeout(renderFindingsTable,50);
  if(id==='roadmap')   renderRoadmap();
  if(id==='domains')   renderDomainGrid();
  if(id==='target')    renderTargetArchitecture();
  if(id==='model')     renderModelDomainList();
}

// ── Theme ─────────────────────────────────────────────────────────────────────
function setTheme(t){
  document.body.classList.toggle('light-theme',t==='light');
  document.getElementById('theme-dark').classList.toggle('active',t==='dark');
  document.getElementById('theme-light').classList.toggle('active',t==='light');
  localStorage.setItem('ca-assess-theme',t);
}
(function(){const t=localStorage.getItem('ca-assess-theme');if(t)setTheme(t);})();

// ── Overview ─────────────────────────────────────────────────────────────────
(function renderOverview(){
  const barContainer=document.getElementById('domainBars');
  DOMAINS.forEach(d=>{
    const pct=(d.maturityScore/5)*100;
    barContainer.innerHTML+=`<div class="bar-row">
      <div class="bar-label" title="${escH(d.name)}">${escH(d.icon)} ${escH(d.name)}</div>
      <div class="bar-track"><div class="bar-fill" data-pct="${pct}" style="background:${escH(d.maturityColor)}"></div></div>
      <div class="bar-val">${d.maturityScore}</div>
    </div>`;
  });
  const rmContainer=document.getElementById('riskMatrix');
  DOMAINS.forEach(d=>{
    const total=d.critical+d.high+d.medium+d.low;
    rmContainer.innerHTML+=`<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:11px">
      <span style="width:20px;text-align:center">${escH(d.icon)}</span>
      <span style="width:120px;color:var(--muted2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escH(d.name)}</span>
      <div style="display:flex;gap:3px">
        ${d.critical>0?`<span class="risk-chip rc-critical">${d.critical}C</span>`:''}
        ${d.high>0    ?`<span class="risk-chip rc-high">${d.high}H</span>`:''}
        ${d.medium>0  ?`<span class="risk-chip rc-medium">${d.medium}M</span>`:''}
        ${d.low>0     ?`<span class="risk-chip rc-low">${d.low}L</span>`:''}
        ${total===0   ?`<span class="risk-chip rc-info">✓</span>`:''}
      </div>
    </div>`;
  });
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width=el.getAttribute('data-pct')+'%';
    });
  });
})();

// ── Domain Grid ───────────────────────────────────────────────────────────────
function renderDomainGrid(){
  const grid=document.getElementById('domainGrid');
  if(grid.innerHTML) return;
  DOMAINS.forEach(d=>{
    const pct=(d.maturityScore/5)*100;
    grid.innerHTML+=`<div class="domain-card" style="border-left-color:${escH(d.maturityColor)}" onclick="openDomainFindings('${escJ(d.id)}')">
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
  domainFilter=domainId;
  showPage('findings',document.querySelectorAll('.nav-btn')[2]);
  document.getElementById('clearDomainBtn').style.display='';
  setTimeout(()=>{
    filteredFindings=FINDINGS.filter(f=>f.domainId===domainId);
    findingsPage=0;
    renderFindingsTable();
  },80);
}
function clearDomainFilter(){
  domainFilter=null;
  document.getElementById('clearDomainBtn').style.display='none';
  filterFindings();
}

// ── Findings Table ────────────────────────────────────────────────────────────
let filteredFindings=[...FINDINGS];
let findingsPage=0;
const PAGE_SIZE=15;
let sortCol='risk';
let sortDir=1;
let riskFilter='All';
let domainFilter=null;
const RISK_ORDER={Critical:0,High:1,Medium:2,Low:3,Info:4};

function setRiskFilter(r,el){
  riskFilter=r;
  domainFilter=null;
  document.getElementById('clearDomainBtn').style.display='none';
  document.querySelectorAll('.fpill').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  filterFindings();
}
function filterFindings(){
  const q=(document.getElementById('findSearch').value||'').toLowerCase();
  filteredFindings=FINDINGS.filter(f=>{
    const rMatch=riskFilter==='All'||(riskFilter==='Low'?f.risk==='Low'||f.risk==='Info':f.risk===riskFilter);
    const dMatch=!domainFilter||f.domainId===domainFilter;
    const qMatch=!q||f.title.toLowerCase().includes(q)||f.domainName.toLowerCase().includes(q)||f.checkId.toLowerCase().includes(q)||f.recommendation.toLowerCase().includes(q);
    return rMatch&&dMatch&&qMatch;
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
    <td><span class="domain-tag">${escH(f.domainId)}</span> <span style="font-size:10px;color:var(--muted)">${escH(f.domainName)}</span></td>
    <td style="max-width:340px">${escH(f.title)}</td>
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
    `<span class="domain-tag">${escH(f.domainId)} · ${escH(f.domainName)}</span>`+
    `<span style="font-size:10px;padding:2px 8px;border-radius:12px;background:rgba(255,255,255,.06);color:${phaseColors[f.roadmapPhase]||'var(--muted)'};font-family:var(--mono)">${escH(f.roadmapPhase)}</span>`+
    `<span style="font-size:10px;color:var(--muted);font-family:var(--mono)">${escH(f.checkId)}</span>`;
  document.getElementById('drawerEvidence').textContent    =f.evidence;
  document.getElementById('drawerCurrentState').textContent=f.currentState;
  document.getElementById('drawerGap').textContent         =f.gap;
  document.getElementById('drawerImpact').textContent      =f.businessImpact;
  document.getElementById('drawerTarget').textContent      =f.targetState;
  document.getElementById('drawerRec').textContent         =f.recommendation;
  document.getElementById('drawerSuccess').textContent     =f.successMeasure||'—';
  document.getElementById('drawerPhase').textContent       =f.roadmapPhase;
  document.getElementById('drawerCount').textContent       =`${currentDrawerIndex+1} / ${drawerList.length}`;
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
    const col=document.createElement('div');
    col.className='roadmap-col';
    col.innerHTML=`<div class="roadmap-col-header">
      <span style="font-size:18px">${phaseIcons[phase]}</span>
      <span class="roadmap-col-label" style="color:${phaseColors[phase]}">${escH(phase)}</span>
      <span class="roadmap-count">${items.length}</span>
    </div>`;
    items.forEach(f=>{
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

// ── Target Architecture ───────────────────────────────────────────────────────
function renderTargetArchitecture(){
  const c=document.getElementById('targetDomainList');
  if(c.innerHTML) return;
  DOMAINS.forEach(d=>{
    c.innerHTML+=`<div class="target-card">
      <h4>${escH(d.icon)} ${escH(d.name)}</h4>
      <p><strong style="color:var(--muted2)">Current:</strong> ${escH(d.currentStateSummary)}</p>
      <p style="margin-top:6px"><strong style="color:var(--green)">Target:</strong> ${escH(d.targetStateSummary)}</p>
    </div>`;
  });
}

// ── Model Domain List ─────────────────────────────────────────────────────────
function renderModelDomainList(){
  const c=document.getElementById('modelDomainList');
  if(c.innerHTML) return;
  DOMAINS.forEach(d=>{
    c.innerHTML+=`<div style="padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:3px solid ${escH(d.maturityColor)}">
      <div style="font-size:13px;font-weight:700;margin-bottom:4px">${escH(d.icon)} ${escH(d.name)}</div>
      <div style="font-size:11px;color:var(--muted2)">${escH(d.currentStateSummary)}</div>
    </div>`;
  });
}

// ── CSV Export ────────────────────────────────────────────────────────────────
function exportFindingsCSV(){
  const fields=['domainId','domainName','checkId','title','risk','roadmapPhase','evidence','currentState','gap','businessImpact','targetState','recommendation','successMeasure'];
  const header=fields.join(',');
  const rows=filteredFindings.map(f=>fields.map(k=>'"'+(String(f[k]||'')).replace(/"/g,'""')+'"').join(','));
  const csv=[header,...rows].join('\r\n');
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download='EntraCAArchitectureFindings.csv';
  a.click();
  showToast('Findings exported as CSV');
}

// ── Keyboard Shortcuts ────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='/'&&!e.target.matches('input')){
    e.preventDefault();
    const s=document.getElementById('findSearch');
    if(s){showPage('findings',document.querySelectorAll('.nav-btn')[2]);s.focus();}
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

        $html = $html `
            -replace '__TENANT_NAME__', $TenantName `
            -replace '__TENANT_ID__', $TenantId `
            -replace '__ASSESSMENT_DATE__', $AssessmentDate `
            -replace '__OVERALL_SCORE__', $OverallMaturity `
            -replace '__OVERALL_LABEL__', $overallLabel `
            -replace '__TOTAL_CRITICAL__', $totalCritical `
            -replace '__TOTAL_HIGH__', $totalHigh `
            -replace '__TOTAL_MEDIUM__', $totalMedium `
            -replace '__TOTAL_LOW__', $totalLow `
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
            assessmentTool   = "Get-EntraConditionalAccessArchitectureAssessment"
            assessmentDate   = $AssessmentDate
            tenantName       = $TenantName
            tenantId         = $TenantId
            overallMaturity  = $OverallMaturity
            overallLabel     = $script:MaturityLabels[[int][Math]::Round($OverallMaturity)]
            totalFindings    = $script:Findings.Count
            criticalFindings = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
            highFindings     = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
            mediumFindings   = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count
            lowFindings      = ($script:Findings | Where-Object { $_.Risk -eq "Low" }).Count
            caPolicy         = [PSCustomObject]@{
                total          = $script:AllCAPolicies.Count
                enabled        = $script:EnabledPolicies.Count
                reportOnly     = $script:ReportOnlyPolicies.Count
                disabled       = $script:DisabledPolicies.Count
                namedLocations = $script:NamedLocations.Count
                authStrengths  = $script:AuthStrengths.Count
            }
            domains          = $script:Domains
            findings         = $script:Findings
        }

        $exportObj | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
    }

    #endregion

    #region ── Script Execution ───────────────────────────────────────────────────

    Clear-Host

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   Entra ID Conditional Access Architecture Assessment v1.0   ║" -ForegroundColor Cyan
    Write-Host "  ║   Enterprise CA Architecture Review                          ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $scriptStartTime = Get-Date
    Write-Host "  🕐 Started  : $($scriptStartTime.ToString('dd-MMM-yyyy  hh:mm:ss tt'))" -ForegroundColor Gray
    Write-Host "  📂 Output   : $OutputPath" -ForegroundColor Gray
    Write-Host "  🔑 Auth Mode: $($PSCmdlet.ParameterSetName)" -ForegroundColor Gray
    Write-Host ""

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
        Write-Host "  ⏳ Using provided access token (BYOT)..." -ForegroundColor Yellow
        $global:accessToken = $AccessToken
        $global:TenantId = $TenantId
        Write-Host "  ✅ BYOT token accepted." -ForegroundColor Green
    }

    Write-Host ""

    # ── Step 1.1: Validate permissions ───────────────────────────────────────────
    Write-Host "  🔍 Validating required Microsoft Graph permissions..." -ForegroundColor Yellow

    $requiredGraphPermissions = @(
        "Policy.Read.All"
        "Directory.Read.All"
        "RoleManagement.Read.Directory"
        "Application.Read.All"
        "AuditLog.Read.All"
    )

    $permissionCheck = Test-GraphTokenPermissions `
        -AccessToken $global:accessToken `
        -RequiredPermissions $requiredGraphPermissions

    if (-not $permissionCheck.Valid) {
        Write-Host ""
        Write-Host "  ⚠️  Warning: Some required Microsoft Graph permissions are missing." -ForegroundColor Yellow
        foreach ($permission in $permissionCheck.MissingPermissions) {
            Write-Host "    • $permission" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  Assessment will continue with available permissions." -ForegroundColor Yellow
        Write-Host "  Some findings may show as 'Insufficient Data'." -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host "  ✅ All required Microsoft Graph permissions validated." -ForegroundColor Green
    }

    Write-Host ""

    # ── Step 2: Collect Tenant Baseline ──────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 2  ›  Collecting CA Baseline Data                    │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $orgData = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/organization?`$select=id,displayName,verifiedDomains,createdDateTime"
    $tenantName = "Unknown"
    if ($orgData -and $orgData.value -and $orgData.value.Count -gt 0) { $tenantName = $orgData.value[0].displayName }
    elseif ($orgData -and $orgData.displayName) { $tenantName = $orgData.displayName }

    Write-Host "  ✅ Tenant: $tenantName ($TenantId)" -ForegroundColor Green
    Write-Host ""

    Get-CABaselineData

    # ── Step 3: Domain Assessments ───────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 3  ›  Running Domain Assessments (8 Domains)         │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    Invoke-Domain1-PolicyCoverage
    Invoke-Domain2-CoherenceAndConflicts
    Invoke-Domain3-ExclusionGovernance
    Invoke-Domain4-PrivilegedIdentityProtection
    Invoke-Domain5-EmergencyAccess
    Invoke-Domain6-AuthStrengthAndRisk
    Invoke-Domain7-DeviceAndAppCompliance
    Invoke-Domain8-PolicySprawlAndManageability

    Write-Host ""
    Write-Host "  ✅ All 8 domain assessments complete." -ForegroundColor Green
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

    Write-Host "  📊 Overall CA Maturity: $overallMaturity / 5.0 ($overallLabel)" -ForegroundColor Cyan
    Write-Host "  🔴 Critical: $totalCritical  |  🟠 High: $totalHigh  |  🔵 Medium: $totalMedium" -ForegroundColor Gray
    Write-Host ""

    # ── Step 5: Export ─────────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 5  ›  Generating Reports                             │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $htmlPath = Join-Path $OutputPath "EntraCAArchitectureAssessment_$timestamp.html"
    $jsonPath = Join-Path $OutputPath "EntraCAArchitectureAssessment_$timestamp.json"
    $assessDate = (Get-Date).ToString("dd MMM yyyy HH:mm")

    Write-Host "  ⏳ Building HTML dashboard..." -ForegroundColor Yellow
    $domainsJson = Build-DomainsJson
    $findingsJson = Build-FindingsJson

    Generate-HtmlDashboard `
        -TenantName      $tenantName `
        -TenantId        $TenantId `
        -OverallMaturity $overallMaturity `
        -AssessmentDate  $assessDate `
        -DomainsJson     $domainsJson `
        -FindingsJson    $findingsJson `
        -OutputFilePath  $htmlPath

    Write-Host "  ✅ HTML dashboard written → $htmlPath" -ForegroundColor Green

    Write-Host "  ⏳ Exporting JSON assessment..." -ForegroundColor Yellow
    Export-AssessmentJson `
        -TenantName      $tenantName `
        -TenantId        $TenantId `
        -OverallMaturity $overallMaturity `
        -AssessmentDate  $assessDate `
        -OutputFilePath  $jsonPath

    Write-Host "  ✅ JSON export written → $jsonPath" -ForegroundColor Green
    Write-Host ""

    # ── Execution Summary ─────────────────────────────────────────────────────────
    $scriptEndTime = Get-Date
    $executionTime = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime

    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║              CA ARCHITECTURE ASSESSMENT SUMMARY              ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  🏛️  Tenant                : $($tenantName.PadRight(30))║" -ForegroundColor White
    Write-Host "  ║  📊 Overall CA Maturity    : $("$overallMaturity / 5.0 ($overallLabel)".PadRight(30))║" -ForegroundColor Cyan
    Write-Host "  ║  🔴 Critical Findings      : $($totalCritical.ToString().PadRight(30))║" -ForegroundColor Red
    Write-Host "  ║  🟠 High Findings          : $($totalHigh.ToString().PadRight(30))║" -ForegroundColor Yellow
    Write-Host "  ║  🔵 Medium Findings        : $($totalMedium.ToString().PadRight(30))║" -ForegroundColor Blue
    Write-Host "  ║  📋 Total Findings         : $(($script:Findings.Count).ToString().PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  🚦 CA Policies (Enabled)  : $($script:EnabledPolicies.Count.ToString().PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  🗺️  Named Locations        : $($script:NamedLocations.Count.ToString().PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  🕐 Started               : $($scriptStartTime.ToString('hh:mm:ss tt').PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  🕑 Ended                 : $($scriptEndTime.ToString('hh:mm:ss tt').PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  ⏱️ Duration               : $($executionTime.ToString('hh\:mm\:ss').PadRight(30))║" -ForegroundColor Yellow
    Write-Host "  ║  🌐 HTML Dashboard        : $(('...' + $htmlPath.Substring([Math]::Max(0,$htmlPath.Length-27))).PadRight(30))║" -ForegroundColor Green
    Write-Host "  ║  📄 JSON Export           : $(('...' + $jsonPath.Substring([Math]::Max(0,$jsonPath.Length-27))).PadRight(30))║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    #endregion
}
