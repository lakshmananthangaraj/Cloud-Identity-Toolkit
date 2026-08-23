<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 23 August 2026
Modified-On  : 23 August 2026

.SYNOPSIS
    Evaluates the guest/B2B external identity architecture based on trust relationships,
    external domains, cross-tenant access, lifecycle governance, ownership, access packages,
    and sensitive-resource exposure.

.DESCRIPTION
    This script connects to Microsoft Graph (BYOT or Client Credentials) and evaluates
    the organisation's external identity and B2B trust architecture across eight
    focused assessment domains:

        Domain 1  — Trust Boundary Design & Cross-Tenant Access Policy
        Domain 2  — External Collaboration Settings & Invitation Governance
        Domain 3  — Guest Lifecycle & Stale Identity Accumulation
        Domain 4  — B2B Conditional Access & Authentication Strength
        Domain 5  — Entitlement Management & Access Package Governance
        Domain 6  — Sensitive Resource Exposure to External Identities
        Domain 7  — Guest Ownership, Sponsorship & Accountability
        Domain 8  — External Identity Monitoring & Anomaly Detection

    For each domain the script follows the architectural thinking model:

        Context → Current State → Gap & Risk → Target State → Transition Recommendation → Success Measure

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
        - External trust exposure (partner plane vs data plane)

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
    Default: C:\Temp\EntraExternalIdentityAssessment

.PARAMETER ShowHelp
    Displays a plain-language usage guide and exits immediately.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        HTML dashboard: <OutputPath>\EntraExternalIdentityTrustAssessment_<timestamp>.html
        JSON export   : <OutputPath>\EntraExternalIdentityTrustAssessment_<timestamp>.json

.EXAMPLE
    Get-EntraExternalIdentityTrustAssessment -ShowHelp

    Displays the friendly usage guide and exits.

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraExternalIdentityTrustAssessment `
        -AuthMode ClientCredentials `
        -ClientId  "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId "f4310b4f-xxxx"

    Full assessment using app-only Client Credentials auth.

.EXAMPLE
    $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    Get-EntraExternalIdentityTrustAssessment `
        -AuthMode BYOT `
        -AccessToken $token `
        -TenantId "f4310b4f-xxxx"

    Full assessment using a pre-obtained bearer token (BYOT).

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraExternalIdentityTrustAssessment `
        -AuthMode ClientCredentials `
        -ClientId  "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId "f4310b4f-xxxx" `
        -OutputPath "D:\Reports\B2BAssessment"

    Assessment with custom output directory.

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
               Directory.Read.All                   (users, groups, domains, tenant info)
               Policy.Read.All                      (Conditional Access, auth methods, cross-tenant)
               CrossTenantInformation.ReadBasic.All (cross-tenant access partner data)
               EntitlementManagement.Read.All       (access packages, catalogs, assignments)
               AuditLog.Read.All                    (sign-in activity, audit logs)
               RoleManagement.Read.Directory        (role assignments, PIM)
               Reports.Read.All                     (usage and activity reports)
               AccessReview.Read.All                (access review definitions and instances)
               Application.Read.All                 (app registrations, service principals)

        2. BYOT mode: the delegated or application token must carry the same
           scopes as above. Delegated tokens require the caller to be a
           Global Reader or Security Reader.

        3. Entra ID P1 minimum. P2 required for:
               - Entitlement Management (access packages)
               - Access Reviews for guest certification
               - Identity Protection risk data for guests

        4. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  → Show help and exit if -ShowHelp
        Step 1  → Authenticate (BYOT or Client Credentials)
        Step 1.1→ Validate required Graph permissions
        Step 2  → Collect tenant baseline (org, licenses, guest count)
        Step 3  → Run domain assessments 1–8
        Step 4  → Score domains, compute overall maturity
        Step 5  → Generate HTML dashboard + JSON export

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the /beta Graph endpoint. Beta APIs are subject to change.
        - Entitlement Management and Access Review data require Entra ID P2.
          Assessments for those domains gracefully degrade to "Insufficient Data".
        - Cross-tenant access policy evaluation is configuration-based; it does
          not simulate runtime B2B collaboration flows.
        - Partner-specific trust evaluation is limited to what Graph exposes —
          per-partner MFA trust settings require /beta and may change.
        - Large tenants (>10 000 guests) may experience longer run times due to
          Graph pagination.
        - Sensitive role and group exposure checks use known naming patterns and
          direct role assignment data; PIM-eligible-only assignments without
          active activation are counted as lower exposure.

.LINK
    https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b
.LINK
    https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview
.LINK
    https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview
.LINK
    https://learn.microsoft.com/en-us/graph/api/overview

#>


Function Get-EntraExternalIdentityTrustAssessment {
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
        [string]$OutputPath = "C:\Temp\EntraExternalIdentityAssessment",

        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    #region ── Friendly Help ──────────────────────────────────────────────────────

    Function Show-FriendlyHelp {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║   Entra External Identity Trust Assessment  v1.0             ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  PURPOSE" -ForegroundColor Yellow
        Write-Host "    Evaluates your B2B and guest identity architecture across 8 domains."
        Write-Host "    Assesses trust relationships, external domains, cross-tenant access,"
        Write-Host "    lifecycle governance, access packages, and sensitive-resource exposure."
        Write-Host ""
        Write-Host "  AUTHENTICATION" -ForegroundColor Yellow
        Write-Host "    Client Credentials (app-only):"
        Write-Host '      $secret = Read-Host "Client secret" -AsSecureString'
        Write-Host '      Get-EntraExternalIdentityTrustAssessment \'
        Write-Host '          -AuthMode ClientCredentials \'
        Write-Host '          -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "    BYOT (Bring Your Own Token):"
        Write-Host '      $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken'
        Write-Host '      Get-EntraExternalIdentityTrustAssessment \'
        Write-Host '          -AuthMode BYOT -AccessToken $token -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "  REQUIRED APP PERMISSIONS (Application, admin-consented)" -ForegroundColor Yellow
        Write-Host "    Directory.Read.All, Policy.Read.All, CrossTenantInformation.ReadBasic.All,"
        Write-Host "    EntitlementManagement.Read.All, AuditLog.Read.All,"
        Write-Host "    RoleManagement.Read.Directory, Reports.Read.All,"
        Write-Host "    AccessReview.Read.All, Application.Read.All"
        Write-Host ""
        Write-Host "  LICENSE REQUIREMENTS" -ForegroundColor Yellow
        Write-Host "    P1 minimum. P2 required for Entitlement Management and Access Reviews."
        Write-Host ""
        Write-Host "  For full documentation: Get-Help Get-EntraExternalIdentityTrustAssessment -Full"
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

    $script:Domains = [System.Collections.ArrayList]::new()
    $script:Findings = [System.Collections.ArrayList]::new()


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

    #region ── Domain 1: Trust Boundary Design & Cross-Tenant Access Policy ───────

    Function Invoke-Domain1-TrustBoundary {
        Write-Host "  🛡️ D1: Trust Boundary Design & Cross-Tenant Access Policy..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 1.1: Default cross-tenant access policy (inbound) ───────────────
        $xTenantDefault = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/default"
        $xTenantPartners = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners"

        $b2bInboundAllowAll = $false
        $b2bOutboundAllowAll = $false
        $b2bDirectConnectIn = $false

        if ($xTenantDefault) {
            $inboundPolicy = $xTenantDefault.b2bCollaborationInbound
            $outboundPolicy = $xTenantDefault.b2bCollaborationOutbound
            $b2bInboundAllowAll = ($inboundPolicy -and $inboundPolicy.usersAndGroups.accessType -eq "allowed")
            $b2bOutboundAllowAll = ($outboundPolicy -and $outboundPolicy.usersAndGroups.accessType -eq "allowed")

            $dcInbound = $xTenantDefault.b2bDirectConnectInbound
            $b2bDirectConnectIn = ($dcInbound -and $dcInbound.usersAndGroups.accessType -eq "allowed")
        }

        $partnerCount = $xTenantPartners.Count

        if ($b2bInboundAllowAll -and $partnerCount -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D1" -DomainName "Trust Boundary" -CheckId "D1.1" `
                -Title "Default Cross-Tenant Access Is Open — No Partner-Specific Trust Policies Defined" `
                -Evidence "Default inbound B2B: Allowed for all tenants | Partner-specific policies: $partnerCount" `
                -CurrentState "The default cross-tenant access policy allows inbound B2B collaboration from any external Entra ID tenant without restriction." `
                -Gap "No tenant allowlist, no partner trust tiers, no per-partner MFA or device compliance trust. Any external user from any tenant can be invited with no vetting at the policy layer." `
                -Risk "High" `
                -BusinessImpact "Unrestricted inbound B2B enables social-engineering-based invitation from compromised or adversarial tenants. Allows data exfiltration via guest access to SharePoint, Teams, and enterprise apps with no partner accountability." `
                -TargetState "Default inbound B2B set to block. Per-partner explicit trust policies for each approved organisation. Trust tiers defined: Tier 1 (full trust — MFA/device honoured), Tier 2 (partial trust — re-authenticate), Tier 3 (restricted — limited resource access)." `
                -Recommendation "Define a B2B partner governance framework with an approved tenant allowlist. Configure Cross-Tenant Access partner policies for each approved partner. Set default inbound policy to Block. For Tier 1 partners (Entra ID-joined), enable MFA and compliant device claim trust to avoid double-MFA friction." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        elseif ($b2bInboundAllowAll -and $partnerCount -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Trust Boundary" -CheckId "D1.1" `
                -Title "Default Cross-Tenant Access Is Open Despite $partnerCount Partner-Specific Policies" `
                -Evidence "Default inbound B2B: Allowed for all | Partner-specific policies: $partnerCount" `
                -CurrentState "$partnerCount partner-specific policies are configured, but the default cross-tenant access policy remains open, allowing any unlisted tenant." `
                -Gap "The open default acts as a catch-all that bypasses the partner governance model. Tenants without explicit policies inherit open access." `
                -Risk "Medium" `
                -BusinessImpact "Any tenant not in the partner list still gets full default access — the partner policy model is incomplete without a deny-default." `
                -TargetState "Default inbound B2B: Block. All approved partners receive explicit allow policies. Unknown tenants are blocked by default." `
                -Recommendation "Change the default cross-tenant access policy inbound to Block. Ensure all active B2B partner organisations have explicit allow policies configured before switching to deny-default to avoid disruption." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D1" -DomainName "Trust Boundary" -CheckId "D1.1" `
                -Title "Cross-Tenant Access Policy Is Restricted — $partnerCount Partner-Specific Policies Active" `
                -Evidence "Default inbound B2B: Restricted/Blocked | Partner-specific policies: $partnerCount" `
                -CurrentState "The default cross-tenant access policy restricts or blocks inbound B2B. $partnerCount partner-specific trust policies are configured." `
                -Gap "Verify all active B2B partner organisations are represented in partner policies. Ensure MFA and device trust settings reflect partner tier classifications." `
                -Risk "Info" `
                -BusinessImpact "Low — trust boundary architecture is appropriately restrictive. Focus on completeness and tier classification." `
                -TargetState "All active B2B partner organisations with explicit partner policies. Trust tiers documented and reviewed quarterly." `
                -Recommendation "Run quarterly audit comparing active guest domains (from guest UPN suffixes) against configured partner policies. Identify guests from tenants without an explicit policy and remediate." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 1.2: Direct Connect (Teams Shared Channels) exposure ────────────
        if ($b2bDirectConnectIn) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Trust Boundary" -CheckId "D1.2" `
                -Title "B2B Direct Connect (Teams Shared Channels) Inbound Access Is Enabled" `
                -Evidence "Default b2bDirectConnectInbound: Allowed" `
                -CurrentState "B2B Direct Connect is enabled inbound, allowing external users from other tenants to access Teams Shared Channels without a formal guest account being provisioned." `
                -Gap "Direct Connect bypasses the standard guest provisioning lifecycle — no guest account is created, no access reviews apply, no per-user lifecycle governance. External users interact with internal Teams data without an auditable identity footprint." `
                -Risk "Medium" `
                -BusinessImpact "Teams Shared Channel participants from external tenants can access shared documents, chats, and tab apps. Data shared via Direct Connect may not be captured by DLP policies that rely on guest account identity." `
                -TargetState "Direct Connect restricted to explicitly approved partner tenants only. Default Direct Connect inbound blocked. Per-partner Direct Connect enabled where Teams collaboration is formally approved." `
                -Recommendation "Restrict B2B Direct Connect to specific approved partner tenants via Cross-Tenant Access partner policies. Set default b2bDirectConnectInbound to Block. Document which Teams workspaces have Shared Channel collaboration and ensure they are in scope for Purview DLP policies." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D1" -DomainName "Trust Boundary" -CheckId "D1.2" `
                -Title "B2B Direct Connect (Teams Shared Channels) Inbound Is Restricted" `
                -Evidence "Default b2bDirectConnectInbound: Not enabled or restricted" `
                -CurrentState "B2B Direct Connect inbound is not broadly enabled — Teams Shared Channel access from external tenants requires an explicit partner policy." `
                -Gap "Confirm whether Direct Connect is intentionally off or if it has been enabled per-partner and verify those partners are documented." `
                -Risk "Info" `
                -BusinessImpact "Low — Direct Connect access is controlled. Validate per-partner configurations annually." `
                -TargetState "Direct Connect only enabled for formally approved partner tenants. Shared Channel usage logged and reviewed." `
                -Recommendation "Maintain an inventory of partner-level Direct Connect permissions. Review annually as part of the B2B partner governance cycle." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 1.3: Outbound data exfiltration risk (unrestricted outbound) ────
        if ($b2bOutboundAllowAll) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Trust Boundary" -CheckId "D1.3" `
                -Title "Default Cross-Tenant Outbound Access Is Unrestricted — Data Exfiltration Risk" `
                -Evidence "Default outbound B2B: Allowed for all external tenants" `
                -CurrentState "Internal member users can collaborate outbound into any external tenant without restriction at the cross-tenant policy layer." `
                -Gap "Unrestricted outbound allows internal users (and their data access) to flow into competitor or unvetted tenants via external Teams meetings, SharePoint guest links, or external app invitations without any policy gate." `
                -Risk "Medium" `
                -BusinessImpact "Sensitive data held by internal users can be shared into external tenants outside corporate control. Insider threat and accidental data exfiltration risk is elevated when no outbound trust policy exists." `
                -TargetState "Outbound collaboration restricted to approved partner tenants. Default outbound set to block or to specific allowed application types only." `
                -Recommendation "Define an outbound collaboration policy. Restrict default outbound to approved applications only (e.g., allow Teams chat with specific partners, block SharePoint sharing to unapproved tenants). Implement Microsoft Purview Information Protection labels to restrict exfiltration at the content layer as a complementary control." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D1" -DomainName "Trust Boundary" -CheckId "D1.3" `
                -Title "Cross-Tenant Outbound Access Is Restricted" `
                -Evidence "Default outbound B2B: Restricted" `
                -CurrentState "Default outbound cross-tenant access is not openly permitted — outbound collaboration requires explicit approval at the policy layer." `
                -Gap "Confirm outbound restrictions are intentional and not a misconfiguration. Verify key partner outbound flows are functioning as expected." `
                -Risk "Info" `
                -BusinessImpact "Low — outbound trust boundary is governed. Document and maintain outbound partner policy inventory." `
                -TargetState "All outbound collaboration governed by partner-specific policies with annual review. Zero unmanaged outbound data flows." `
                -Recommendation "Document outbound B2B collaboration scenarios per partner. Run a semi-annual audit of outbound guest sign-ins to identify unintended collaboration patterns." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D1" -Name "Trust Boundary" -Icon "🛡️" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Partner policies: $partnerCount. Default inbound: $(if ($b2bInboundAllowAll){'Open — all tenants'}else{'Restricted/Blocked'}). Direct Connect: $(if ($b2bDirectConnectIn){'Enabled'}else{'Restricted'})." `
            -TargetStateSummary "Deny-default cross-tenant access. Per-partner trust policies with tiered MFA/device trust. Direct Connect only for formally approved partners." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 2: External Collaboration Settings & Invitation Governance ──

    Function Invoke-Domain2-InvitationGovernance {
        Write-Host "  📨 D2: External Collaboration Settings & Invitation Governance..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 2.1: Guest invite permissions ───────────────────────────────────
        $authPolicy = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy"
        $guestInviteRole = if ($authPolicy) { $authPolicy.allowInvitesFrom } else { "unknown" }

        switch ($guestInviteRole) {
            "everyone" {
                $high++
                $maturityPoints += 1
                Add-Finding -DomainId "D2" -DomainName "Invitation Governance" -CheckId "D2.1" `
                    -Title "Any User Can Invite External Guests — Zero Invitation Governance" `
                    -Evidence "allowInvitesFrom: $guestInviteRole" `
                    -CurrentState "Any internal user, including guests themselves, can invite new external users into the tenant." `
                    -Gap "Invitation is entirely ungoverned. No approval workflow, no identity vetting, no legal or security review before a new external identity gains access. Guest-invited-guests creates untracked chain invitations." `
                    -Risk "High" `
                    -BusinessImpact "Ungoverned invitations result in an uncontrolled external identity population. External parties gain access before security, NDA, or compliance checks. Creates material risk of data loss, regulatory violations, and insider threat enablement via supply chain." `
                    -TargetState "Guest invitation restricted to Administrators and designated Guest Inviter role holders only. All B2B access provisioned via Entitlement Management access packages with approval and terms-of-use acceptance." `
                    -Recommendation "Set External Collaboration Settings → Guest Invite Restrictions to 'Only admins and users with the Guest Inviter role can invite'. Implement Entitlement Management access packages as the sanctioned self-service B2B channel. Define an Invitation SLA and formal vetting checklist." `
                    -RoadmapPhase "0-30 Days" -MaturityContribution 1
            }
            "adminsAndGuestInviters" {
                $medium++
                $maturityPoints += 2
                Add-Finding -DomainId "D2" -DomainName "Invitation Governance" -CheckId "D2.1" `
                    -Title "Guest Invitations Permitted for Admins and Guest Inviter Role — Moderate Governance Gap" `
                    -Evidence "allowInvitesFrom: $guestInviteRole" `
                    -CurrentState "Admins and members of the Guest Inviter role can invite guests. Members can invite too if the setting is at this level." `
                    -Gap "The Guest Inviter role may be assigned broadly without governance. No structured approval workflow for invitations outside Entitlement Management." `
                    -Risk "Medium" `
                    -BusinessImpact "Guest Inviter role membership may exceed intended scope. Invitations occur outside a governed workflow, leaving no approval audit trail for compliance." `
                    -TargetState "Invitation restricted to admins only. All B2B access via Entitlement Management access packages with requester, approver, and sponsor identity fields completed." `
                    -Recommendation "Audit Guest Inviter role membership and reduce to least-privilege. Migrate all B2B access scenarios to Entitlement Management access packages. Set invitation policy to 'Only admins' once access package coverage is complete." `
                    -RoadmapPhase "31-60 Days" -MaturityContribution 2
            }
            default {
                $maturityPoints += 4
                Add-Finding -DomainId "D2" -DomainName "Invitation Governance" -CheckId "D2.1" `
                    -Title "Guest Invitation Permissions Are Appropriately Restricted ($guestInviteRole)" `
                    -Evidence "allowInvitesFrom: $guestInviteRole" `
                    -CurrentState "Guest invitations are restricted to administrators or a tightly scoped governance role." `
                    -Gap "Verify the Guest Inviter role membership is current. Confirm Entitlement Management access packages are the primary B2B access channel." `
                    -Risk "Info" `
                    -BusinessImpact "Low — invitation governance is appropriately restrictive. Maintain and audit role assignments quarterly." `
                    -TargetState "All B2B invitations via Entitlement Management only. Zero direct ad-hoc invitations outside the governed workflow." `
                    -Recommendation "Conduct quarterly review of Guest Inviter role membership. Validate all active guest invitations have a corresponding access package assignment as the source of record." `
                    -RoadmapPhase "Strategic" -MaturityContribution 4
            }
        }

        # ── Check 2.2: Guest user restrictions (permissions level) ─────────────────
        $guestUserRole = if ($authPolicy) { $authPolicy.guestUserRoleId } else { $null }

        # Known GUIDs: 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Restricted guest, a0b1b346-4d3e-4e8b-98f8-753987be4970 = Guest user, 2af84b1e-32c8-42b7-82bc-daa82404023b = Most restricted
        $restrictedGuestGuid = "10dae51f-b6af-4016-8d66-8c2a99b929b3"
        $mostRestrictedGuid = "2af84b1e-32c8-42b7-82bc-daa82404023b"
        $standardGuestGuid = "a0b1b346-4d3e-4e8b-98f8-753987be4970"

        if ($guestUserRole -eq $standardGuestGuid -or -not $guestUserRole) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Invitation Governance" -CheckId "D2.2" `
                -Title "Guest User Permissions Set to Standard Level — Excessive Directory Read Access" `
                -Evidence "guestUserRoleId: $(if ($guestUserRole) { $guestUserRole } else { 'Default (same as members)' })" `
                -CurrentState "Guest users have the standard guest permission level, which allows enumeration of other users, groups, and directory objects via the Graph API." `
                -Gap "Standard guest permissions allow a compromised or malicious guest to enumerate the entire user directory, identify privileged accounts, discover group memberships, and map the internal identity topology — a significant reconnaissance capability." `
                -Risk "Medium" `
                -BusinessImpact "A guest account used in an attack can enumerate internal identities and groups, facilitating targeted phishing of privileged users and lateral movement planning within the tenant." `
                -TargetState "Guest user permissions set to 'Restricted guest user' (limited enumeration) as the organisational baseline. Most restrictive setting applied where possible without breaking governed B2B flows." `
                -Recommendation "Navigate to Entra ID → External Identities → External Collaboration Settings → Guest user access. Set to 'Guest users have limited access to properties and memberships of directory objects'. This limits enumeration while preserving collaboration functionality for governed guests." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $permLevel = if ($guestUserRole -eq $mostRestrictedGuid) { "Most Restricted" } elseif ($guestUserRole -eq $restrictedGuestGuid) { "Restricted Guest" } else { "Custom ($guestUserRole)" }
            $maturityPoints += 4
            Add-Finding -DomainId "D2" -DomainName "Invitation Governance" -CheckId "D2.2" `
                -Title "Guest User Permissions Are Appropriately Restricted ($permLevel)" `
                -Evidence "guestUserRoleId: $guestUserRole ($permLevel)" `
                -CurrentState "Guest user directory enumeration permissions are restricted — guests cannot enumerate internal users, groups, or directory objects beyond their own profile." `
                -Gap "Validate that restricted permissions do not break required B2B collaboration flows (e.g., sharing to specific groups by name). Document any exceptions where standard permissions are needed." `
                -Risk "Info" `
                -BusinessImpact "Low — directory enumeration by external identities is correctly restricted." `
                -TargetState "Maintain restricted guest permissions. Monitor for any tickets or feedback indicating broken B2B scenarios that might lead to rollback pressure." `
                -Recommendation "Review annually to confirm the restricted setting has not been changed. Run 'What can guests see?' tests after any Entra ID policy update." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 2.3: External domain allow/block list ───────────────────────────
        $domainRestrictions = if ($authPolicy) { $authPolicy.allowedToSignUpEmailBasedSubscriptions } else { $null }
        $b2bAllowedDomains = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/default" 
        $allowlistConfigured = ($xTenantPartners -and $xTenantPartners.Count -gt 0)

        # Check if external collaboration domains have explicit allow/blocklist
        $extCollabPolicy = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/b2cAuthenticationMethodsPolicy"
        $hasAllowBlockList = $false

        # Check authorization policy for domain allowlist/blocklist (invitedUserEmailAddressAllowedDomains)
        if ($authPolicy -and $authPolicy.PSObject.Properties["allowedToInviteExternalUsers"]) {
            $hasAllowBlockList = $true
        }

        if (-not $allowlistConfigured) {
            $low++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Invitation Governance" -CheckId "D2.3" `
                -Title "No External Domain Allowlist Configured — All Domains Implicitly Permitted" `
                -Evidence "Cross-tenant partner policies (acting as domain trust controls): $($xTenantPartners.Count)" `
                -CurrentState "No partner-specific cross-tenant access policies are configured to act as a domain-level allowlist. Invitation can be extended to users from any external domain." `
                -Gap "Without a domain allowlist, invitations to personal email domains (gmail.com, hotmail.com, yahoo.com), competitor domains, or sanctioned-entity domains are not blocked at the policy layer." `
                -Risk "Low" `
                -BusinessImpact "Business and personal email domains are indistinguishable at the invitation layer. Invitations to personal addresses may violate data classification policies and introduce personal-account security risk (weak passwords, no MFA requirements)." `
                -TargetState "Domain allowlist configured covering all approved partner domains. Personal email domains (gmail, hotmail, yahoo, outlook.com personal) blocked by policy. Non-corporate domains require explicit approval." `
                -Recommendation "In External Collaboration Settings, configure the allowed domains list to include only approved partner corporate domains. Alternatively, use the blocked domains list to exclude personal email providers. Review and update the list quarterly as partnerships change." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D2" -DomainName "Invitation Governance" -CheckId "D2.3" `
                -Title "External Domain Trust Scope Is Governed via $($xTenantPartners.Count) Partner Policies" `
                -Evidence "Cross-tenant partner policies: $($xTenantPartners.Count) | Default inbound: $(if ($b2bInboundAllowAll){'Open'}else{'Restricted'})" `
                -CurrentState "Cross-tenant access partner policies provide domain-level trust scope governance for $($xTenantPartners.Count) partner organisations." `
                -Gap "Verify the partner policy list is current. Check for guests from domains not in the partner list — these may indicate policy gaps." `
                -Risk "Info" `
                -BusinessImpact "Low — domain trust scope is controlled. Maintain partner list completeness." `
                -TargetState "100% of active guest domains covered by partner policies. Zero guests from unlisted domains." `
                -Recommendation "Monthly query: identify unique guest UPN domain suffixes and compare against partner policy list. Any new domain not in the list should trigger a review and formal partner onboarding." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D2" -Name "Invitation Governance" -Icon "📨" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Invite policy: $guestInviteRole. Guest permissions: $(if ($guestUserRole -eq $standardGuestGuid -or -not $guestUserRole){'Standard (excessive)'}else{'Restricted'}). Partner domain policies: $partnerCount." `
            -TargetStateSummary "Admin-only invitations. Restricted guest permissions. Domain allowlist configured. All B2B access via Entitlement Management access packages." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 3: Guest Lifecycle & Stale Identity Accumulation ───────────

    Function Invoke-Domain3-GuestLifecycle {
        Write-Host "  ♻️ D3: Guest Lifecycle & Stale Identity Accumulation..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Collect all guest accounts ────────────────────────────────────────────
        $guestUri = "https://graph.microsoft.com/beta/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName,createdDateTime,signInActivity,externalUserState,accountEnabled,mail&`$count=true&`$top=100"
        $guests = Get-GraphPagedResults -Uri $guestUri
        $totalGuests = $guests.Count

        $cutoff90 = (Get-Date).AddDays(-90)
        $cutoff180 = (Get-Date).AddDays(-180)
        $cutoff365 = (Get-Date).AddDays(-365)

        $stale90 = @($guests | Where-Object {
                $ls = if ($_.PSObject.Properties["signInActivity"] -and $_.signInActivity) { $_.signInActivity.lastSignInDateTime } else { $null }
                (-not $ls) -or ([datetime]$ls -lt $cutoff90)
            })

        $stale180 = @($guests | Where-Object {
                $ls = if ($_.PSObject.Properties["signInActivity"] -and $_.signInActivity) { $_.signInActivity.lastSignInDateTime } else { $null }
                (-not $ls) -or ([datetime]$ls -lt $cutoff180)
            })

        $neverSignedIn = @($guests | Where-Object {
                -not ($_.PSObject.Properties["signInActivity"] -and $_.signInActivity -and $_.signInActivity.lastSignInDateTime)
            })

        $pendingAcceptance = @($guests | Where-Object { $_.externalUserState -eq "PendingAcceptance" })
        $disabled = @($guests | Where-Object { $_.accountEnabled -eq $false })

        $stale90Pct = if ($totalGuests -gt 0) { [Math]::Round(($stale90.Count / $totalGuests) * 100, 0) } else { 0 }

        # ── Check 3.1: Stale guest population ────────────────────────────────────
        if ($stale90Pct -ge 50) {
            $critical++
            $maturityPoints += 1
            $staleRisk = "Critical"; $stalePhase = "0-30 Days"
        }
        elseif ($stale90Pct -ge 30) {
            $high++
            $maturityPoints += 2
            $staleRisk = "High"; $stalePhase = "0-30 Days"
        }
        elseif ($stale90Pct -ge 15) {
            $medium++
            $maturityPoints += 3
            $staleRisk = "Medium"; $stalePhase = "31-60 Days"
        }
        else {
            $maturityPoints += 4
            $staleRisk = "Info"; $stalePhase = "Strategic"
        }

        Add-Finding -DomainId "D3" -DomainName "Guest Lifecycle" -CheckId "D3.1" `
            -Title "Guest Stale Identity Rate: $stale90Pct% Inactive >90 Days ($($stale90.Count) of $totalGuests guests)" `
            -Evidence "Total guests: $totalGuests | Inactive >90d: $($stale90.Count) ($stale90Pct%) | Inactive >180d: $($stale180.Count) | Never signed in: $($neverSignedIn.Count) | Pending acceptance: $($pendingAcceptance.Count) | Disabled: $($disabled.Count)" `
            -CurrentState "$stale90Pct% of guest accounts have had no successful sign-in within the past 90 days. $($neverSignedIn.Count) guests have never signed in since invitation." `
            -Gap "Stale guest accounts retain all access entitlements assigned at invitation — group memberships, app role assignments, SharePoint access. Without lifecycle governance, these become permanently dormant accounts with residual access rights, invisible to business owners." `
            -Risk $staleRisk `
            -BusinessImpact "Each stale guest account is a dormant attack surface. If the external user's home tenant is compromised, or if the user is no longer affiliated with the partner, that account retains access to enterprise data indefinitely. Accumulation of stale guests also inflates license consumption and complicates compliance audits." `
            -TargetState "Zero stale guest accounts >90 days without access review certification. Automated lifecycle: 90-day inactivity triggers review → uncertified guests deactivated at 120 days → deleted at 150 days. Never-signed-in accounts provisioned via access packages with automatic expiry." `
            -Recommendation "1. Implement Entra ID Access Reviews (P2) for guest certification on a 90-day cadence. 2. Enable guest account expiration policies. 3. Build a Lifecycle Workflow or Logic App to automate the disable-then-delete sequence. 4. Assign each guest a named internal sponsor accountable for the relationship." `
            -RoadmapPhase $stalePhase -MaturityContribution ($maturityPoints[-1])

        # ── Check 3.2: Never-signed-in guests (invitation hygiene) ─────────────────
        $neverPct = if ($totalGuests -gt 0) { [Math]::Round(($neverSignedIn.Count / $totalGuests) * 100, 0) } else { 0 }

        if ($neverPct -ge 20) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D3" -DomainName "Guest Lifecycle" -CheckId "D3.2" `
                -Title "High Volume of Never-Signed-In Guests ($neverPct% — $($neverSignedIn.Count) Accounts)" `
                -Evidence "Never signed in: $($neverSignedIn.Count) ($neverPct% of all guests) | Pending acceptance: $($pendingAcceptance.Count)" `
                -CurrentState "$($neverSignedIn.Count) guest accounts ($neverPct%) have never completed a sign-in since being invited. $($pendingAcceptance.Count) are still in PendingAcceptance state." `
                -Gap "Never-signed-in guests indicate broken invitation workflows, employee turnover on the external side, or test/provisional invitations that were never cleaned up. PendingAcceptance accounts have already consumed a guest slot but provide no collaboration value." `
                -Risk "High" `
                -BusinessImpact "Never-signed-in accounts may still have group memberships and entitlements assigned (particularly if provisioned via access packages). They represent zero-value identities consuming entitlement slots and creating a misleading picture of the partner relationship." `
                -TargetState "Zero never-signed-in guest accounts older than 30 days. Invitation expiry enforced: invitations not redeemed within 30 days trigger automatic removal. Access packages configured with activation requirements." `
                -Recommendation "1. Delete all PendingAcceptance accounts older than 30 days immediately. 2. Configure invitation link expiry in External Collaboration Settings. 3. Build an automated process to revoke unredeemed invitations. 4. For access packages, enable access package assignment expiry so unredeemed access expires automatically." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($neverPct -ge 5) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D3" -DomainName "Guest Lifecycle" -CheckId "D3.2" `
                -Title "Moderate Volume of Never-Signed-In Guests ($neverPct% — $($neverSignedIn.Count) Accounts)" `
                -Evidence "Never signed in: $($neverSignedIn.Count) ($neverPct%) | Pending acceptance: $($pendingAcceptance.Count)" `
                -CurrentState "$($neverSignedIn.Count) guest accounts have never signed in." `
                -Gap "Moderate accumulation of unredeemed invitations indicates invitation workflow hygiene issues. Without a cleanup process, these will continue to accumulate." `
                -Risk "Medium" `
                -BusinessImpact "Moderate — unredeemed accounts inflate the guest population count and create governance overhead." `
                -TargetState "Zero never-signed-in accounts older than 30 days. Automated cleanup process for unredeemed invitations." `
                -Recommendation "Run a one-time cleanup of PendingAcceptance accounts older than 30 days. Implement automated monthly cleanup via Logic App or PowerShell scheduled task querying sign-in activity." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D3" -DomainName "Guest Lifecycle" -CheckId "D3.2" `
                -Title "Invitation Redemption Rate Is Healthy ($neverPct% Never Signed In)" `
                -Evidence "Never signed in: $($neverSignedIn.Count) ($neverPct%) | Total guests: $totalGuests" `
                -CurrentState "The proportion of never-signed-in guests is within an acceptable threshold, indicating healthy invitation hygiene." `
                -Gap "Maintain the current discipline and automate removal to prevent future accumulation." `
                -Risk "Info" `
                -BusinessImpact "Low — invitation redemption is healthy." `
                -TargetState "Automated cleanup of unredeemed invitations at 30 days. Access package assignment expiry covers the majority of B2B provisioning." `
                -Recommendation "Formalise the invitation cleanup cadence as a monthly automated job. Report on unredeemed invitation trends in the B2B governance dashboard." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 3.3: Guest expiration policy ────────────────────────────────────
        $orgSettings = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groupSettings"
        $guestExpiryEnabled = $false
        $guestExpiryDays = 0

        if ($orgSettings -and $orgSettings.value) {

            $unifiedSettings = $orgSettings.value |
            Where-Object { $_.displayName -eq "Group.Unified" }

            if ($unifiedSettings) {

                $expirySetting = $unifiedSettings.values |
                Where-Object { $_.name -eq "Group.Unified.GuestExpiryDays" }

                if ($expirySetting) {
                    $guestExpiryDays = [int]$expirySetting.value
                    $guestExpiryEnabled = $guestExpiryDays -gt 0
                }
            }
        }

        if (-not $guestExpiryEnabled) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D3" -DomainName "Guest Lifecycle" -CheckId "D3.3" `
                -Title "No Guest Account Expiration Policy Detected — Guests Persist Indefinitely" `
                -Evidence "Guest Expiration: $(if ($guestExpiryEnabled) { "Enabled ($guestExpiryDays days)" } else { "Not detected" })" `
                -CurrentState "Guest expiration policy detected: $guestExpiryEnabled. Configured expiration period: $guestExpiryDays days." `
                -Gap "Without expiration, the guest population grows monotonically with each new partnership or project. Accounts outlive the business relationship by months or years, creating accumulating residual access risk." `
                -Risk "High" `
                -BusinessImpact "Every guest account that outlives its business purpose represents a live attack surface attached to a relationship that no longer requires it. In regulated industries, persistent unreviewed external accounts are a direct compliance finding." `
                -TargetState "All guest accounts have a maximum lifetime of 365 days with renewal requiring access review certification. Access packages automatically expire guest assignments at project/engagement end." `
                -Recommendation "1. Configure guest expiration policy: navigate to Entra ID → External Identities → External Collaboration Settings → Guest expiration. 2. Use Entitlement Management access packages with built-in expiry dates for all project-based B2B access. 3. Implement Access Reviews (P2) with auto-remove for uncertified guests as a compensating control." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D3" -DomainName "Guest Lifecycle" -CheckId "D3.3" `
                -Title "Guest Account Expiration Policy Is Configured" `
                -Evidence "External Identities Policy: Accessible | Guest expiry controls present" `
                -CurrentState "Guest account expiration controls are configured, limiting the indefinite accumulation of external identities." `
                -Gap "Verify expiration periods align with business relationship durations. Confirm expired accounts are promptly disabled and then deleted within policy timelines." `
                -Risk "Info" `
                -BusinessImpact "Low — expiration controls are in place. Focus on ensuring all access package-based guests also have explicit expiry dates." `
                -TargetState "All guests have explicit expiry dates driven by access package assignment end dates. No guests without a defined end date." `
                -Recommendation "Ensure all new B2B access provisioned via access packages has a defined end date matching the project/engagement timeline. Review guest expiry data monthly to confirm the policy is functioning." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D3" -Name "Guest Lifecycle" -Icon "♻️" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Total guests: $totalGuests. Stale >90d: $($stale90.Count) ($stale90Pct%). Never signed in: $($neverSignedIn.Count). Pending acceptance: $($pendingAcceptance.Count)." `
            -TargetStateSummary "Zero stale guests >90d. Automated lifecycle with disable at 120d, delete at 150d. All access via expiring access packages. Access Reviews quarterly." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 4: B2B Conditional Access & Authentication Strength ─────────

    Function Invoke-Domain4-B2BConditionalAccess {
        Write-Host "  🔐 D4: B2B Conditional Access & Authentication Strength..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $caPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $enabledCA = @($caPolicies | Where-Object { $_.state -eq "enabled" })

        # ── Check 4.1: CA policy targeting guests ─────────────────────────────────
        $guestTargetedCA = @($enabledCA | Where-Object {
                $users = $_.conditions.users
                ($users.includeGuestsOrExternalUsers -and $users.includeGuestsOrExternalUsers.Count -gt 0) -or
                ($users.includeUsers -contains "GuestsOrExternalUsers")
            })

        if ($guestTargetedCA.Count -eq 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D4" -DomainName "B2B Conditional Access" -CheckId "D4.1" `
                -Title "No Conditional Access Policies Explicitly Target Guest / External Users" `
                -Evidence "Enabled CA policies: $($enabledCA.Count) | Policies scoped to guests or external users: $($guestTargetedCA.Count)" `
                -CurrentState "None of the $($enabledCA.Count) enabled Conditional Access policies explicitly target guest or external user identities." `
                -Gap "Guests may be included in broad 'All Users' policies, but this is often inconsistent due to guest exclusions. Without explicit guest-targeted CA policies, authentication requirements for external identities are undefined, unverifiable, and unenforced at the architectural level." `
                -Risk "Critical" `
                -BusinessImpact "External identities accessing enterprise applications operate without defined authentication strength, device compliance, or location requirements. A compromised guest account faces no access policy enforcement — full app access is available from any device, any location, with a single credential factor if MFA was not enforced at invitation." `
                -TargetState "At minimum 3 CA policies explicitly scoped to guests: (1) MFA required for all guests, (2) Terms of Use acceptance required for regulated app access, (3) Named Location restriction for high-risk guests. Progressively: guest CA policies aligned with partner trust tier." `
                -Recommendation "Create a dedicated CA policy: Scope = Guests/External Users, All Cloud Apps, Grant = Require MFA. This is the non-negotiable baseline. Layer additional policies: Terms of Use for data-room access, Location restrictions for sensitive apps, Risk-based sign-in controls if Identity Protection is licensed." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($guestTargetedCA.Count -lt 3) {
            $high++
            $maturityPoints += 2
            Add-Finding -DomainId "D4" -DomainName "B2B Conditional Access" -CheckId "D4.1" `
                -Title "Minimal Guest-Targeted CA Coverage — Only $($guestTargetedCA.Count) Policy/Policies for External Identities" `
                -Evidence "Enabled CA policies: $($enabledCA.Count) | Policies scoped to guests: $($guestTargetedCA.Count)" `
                -CurrentState "Only $($guestTargetedCA.Count) Conditional Access policy/policies explicitly target guest identities — insufficient for a layered external identity security posture." `
                -Gap "A single guest CA policy provides only one enforcement layer. Without layered policies (MFA + device + location + risk), gaps in guest access control exist for specific scenarios." `
                -Risk "High" `
                -BusinessImpact "Gaps in guest CA coverage mean external identities can access enterprise apps in scenarios not covered by the single policy — e.g., from unmanaged devices, from anonymous proxies, or using inherited claims from home tenants without re-authentication." `
                -TargetState "Minimum: MFA required (all guests, all apps), Terms of Use (regulated apps), Named Location restriction (sensitive apps). Extended: Authentication Strength policy for privileged resource access by guests." `
                -Recommendation "Expand guest CA coverage to at least 3 policies. Add: (1) Named Location restriction for sensitive app access, (2) Terms of Use acceptance for compliance-regulated resources, (3) Session control policies (sign-in frequency, no persistent browser) for guest sessions." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D4" -DomainName "B2B Conditional Access" -CheckId "D4.1" `
                -Title "Adequate Guest-Targeted CA Policy Coverage — $($guestTargetedCA.Count) Policies Active" `
                -Evidence "Enabled CA policies: $($enabledCA.Count) | Guest-targeted policies: $($guestTargetedCA.Count)" `
                -CurrentState "$($guestTargetedCA.Count) CA policies explicitly target guest/external user identities." `
                -Gap "Review whether guest CA policies are scoped to all relevant cloud apps or whether specific app gaps exist. Confirm MFA, Terms of Use, session controls, and Location restrictions are all represented." `
                -Risk "Info" `
                -BusinessImpact "Low — CA policy coverage for guests is adequate. Focus on gap analysis and ensuring new apps are in scope." `
                -TargetState "All guest CA policies in Managed state: scoped, documented, with named exclusion groups audited quarterly. New app onboarding checklist includes guest CA policy scope review." `
                -Recommendation "Conduct semi-annual guest CA policy review: verify each policy's scope, exclusion groups, and test sign-in logs for guest sessions not covered by any policy. Target: zero guest sign-ins without at least one CA policy applied." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 4.2: MFA enforcement for guests ──────────────────────────────────
        $mfaEnforcedForGuests = @($guestTargetedCA | Where-Object {
                $gc = $_.grantControls
                $gc -and ($gc.builtInControls -contains "mfa" -or ($gc.authenticationStrength -and $gc.authenticationStrength.id))
            })

        if ($mfaEnforcedForGuests.Count -eq 0 -and $guestTargetedCA.Count -gt 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D4" -DomainName "B2B Conditional Access" -CheckId "D4.2" `
                -Title "Guest-Targeted CA Policies Exist But Do Not Enforce MFA — Critical Authentication Gap" `
                -Evidence "Guest-targeted CA policies: $($guestTargetedCA.Count) | With MFA enforcement: $($mfaEnforcedForGuests.Count)" `
                -CurrentState "CA policies exist targeting guests, but none enforce MFA or an authentication strength requirement as a grant control." `
                -Gap "Existing guest CA policies enforce non-authentication controls (e.g., Terms of Use, session limits) without the foundational MFA requirement. Guest access can proceed with a single credential factor." `
                -Risk "Critical" `
                -BusinessImpact "Guests accessing enterprise apps with only a password are the highest-risk scenario for credential compromise. Without MFA enforcement, phished or brute-forced guest credentials give immediate application access." `
                -TargetState "All guest CA policies that grant access to applications enforce MFA as the minimum grant control. High-value app access requires Authentication Strength (phishing-resistant MFA)." `
                -Recommendation "Add 'Require multi-factor authentication' as a grant control to all existing guest-targeted CA policies immediately. Layer an Authentication Strength policy for privileged resource access by guests (e.g., power users, project sponsors with data room access)." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($mfaEnforcedForGuests.Count -gt 0) {
            $maturityPoints += 4
            Add-Finding -DomainId "D4" -DomainName "B2B Conditional Access" -CheckId "D4.2" `
                -Title "MFA Enforced for Guests via $($mfaEnforcedForGuests.Count) CA Policy/Policies" `
                -Evidence "Guest CA policies with MFA grant: $($mfaEnforcedForGuests.Count) | Authentication Strength policies: $(@($mfaEnforcedForGuests | Where-Object { $_.grantControls.authenticationStrength }).Count)" `
                -CurrentState "MFA or authentication strength is enforced for guest sign-ins via $($mfaEnforcedForGuests.Count) CA policy/policies." `
                -Gap "Verify MFA is honoured from the guest's home tenant where trust is established (check Cross-Tenant Access → MFA trust settings) to avoid double-MFA friction for trusted partners." `
                -Risk "Info" `
                -BusinessImpact "Low — MFA enforcement for guests is in place. Optimise partner trust settings to balance security and user experience." `
                -TargetState "MFA enforced for all guests via CA. Trusted partner MFA claims honoured to avoid re-authentication friction. Authentication Strength (phishing-resistant) required for guests accessing sensitive applications." `
                -Recommendation "Review Cross-Tenant Access per-partner MFA trust settings: enable 'Trust MFA from partner tenants' for Tier 1 (fully trusted) partners with Entra ID MFA. Apply Authentication Strength CA policy for any guest accessing executive data rooms, M&A workspaces, or security-sensitive apps." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }
        else {
            $maturityPoints += 1
            # No guest CA policies at all - already captured in D4.1
        }

        # ── Check 4.3: Guest session controls ─────────────────────────────────────
        $sessionControlledGuests = @($guestTargetedCA | Where-Object {
                $sc = $_.sessionControls
                $sc -and ($sc.signInFrequency -or $sc.persistentBrowser)
            })

        if ($sessionControlledGuests.Count -eq 0 -and $guestTargetedCA.Count -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D4" -DomainName "B2B Conditional Access" -CheckId "D4.3" `
                -Title "No Session Controls Applied to Guest Identities — Persistent Sessions Risk" `
                -Evidence "Guest CA policies: $($guestTargetedCA.Count) | With session controls (sign-in frequency / persistent browser): $($sessionControlledGuests.Count)" `
                -CurrentState "None of the guest-targeted CA policies enforce session controls such as sign-in frequency or browser session persistence restrictions." `
                -Gap "Without session controls, a guest authenticates once and maintains a long-lived browser session. If a guest device is compromised or shared, the session token provides extended access. This is particularly risky for guests using personal unmanaged devices." `
                -Risk "Medium" `
                -BusinessImpact "Persistent guest sessions on unmanaged devices extend the window of risk after a device compromise. A stolen browser session token from a guest's personal device provides full app access without any re-authentication challenge." `
                -TargetState "Guest sessions limited to 8 hours sign-in frequency. Browser sessions set to non-persistent. High-sensitivity app access requires re-authentication each session." `
                -Recommendation "Add session controls to guest CA policies: Set 'Sign-in frequency' to 8 hours for general app access, 1 hour for sensitive apps. Set 'Persistent browser session' to 'Never persistent' for all guest sessions. These controls are especially important for unmanaged device guests." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D4" -DomainName "B2B Conditional Access" -CheckId "D4.3" `
                -Title "Session Controls Applied to Guest Identities ($($sessionControlledGuests.Count) Policies)" `
                -Evidence "Guest CA policies with session controls: $($sessionControlledGuests.Count)" `
                -CurrentState "Session controls are applied to guest CA policies, limiting session persistence and requiring re-authentication at defined intervals." `
                -Gap "Verify session frequency aligns with data sensitivity. High-sensitivity workspaces should enforce shorter re-authentication intervals than general collaboration." `
                -Risk "Info" `
                -BusinessImpact "Low — session controls are in place. Fine-tune by app sensitivity tier." `
                -TargetState "Tiered session controls: 1-hour frequency for sensitive apps, 8-hour for general collaboration apps. Non-persistent browser sessions enforced for all guest access." `
                -Recommendation "Map guest CA session policies to application sensitivity classification. Confirm the highest-sensitivity apps (financial models, M&A data rooms, IP repositories) have 1-hour sign-in frequency enforced." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D4" -Name "B2B Conditional Access" -Icon "🔐" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Total enabled CA policies: $($enabledCA.Count). Guest-targeted: $($guestTargetedCA.Count). With MFA: $($mfaEnforcedForGuests.Count). With session controls: $($sessionControlledGuests.Count)." `
            -TargetStateSummary "Dedicated guest CA stack: MFA enforced, session controls active, location restrictions for sensitive apps, partner MFA trust configured. Authentication Strength for privileged resource access." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 5: Entitlement Management & Access Package Governance ───────

    Function Invoke-Domain5-EntitlementManagement {
        Write-Host "  📦 D5: Entitlement Management & Access Package Governance..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 5.1: Entitlement Management availability and usage ──────────────
        $catalogs = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackageCatalogs"
        $accessPackages = $null
        $totalPackages = 0
        $externalPackages = 0

        if ($catalogs -eq $null) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D5" -DomainName "Entitlement Management" -CheckId "D5.1" `
                -Title "Entitlement Management Not Available — B2B Access Lacks Governed Provisioning Channel" `
                -Evidence "Access Package Catalogs API returned null — Entra ID P2 / Identity Governance may not be licensed." `
                -CurrentState "Entitlement Management is not available — likely due to missing Entra ID P2 or Microsoft Entra ID Governance license." `
                -Gap "Without Entitlement Management, all B2B access is provisioned through ad-hoc direct invitation with no workflow, approval, expiry, or audit trail. There is no governed self-service mechanism for external access requests." `
                -Risk "High" `
                -BusinessImpact "B2B access is entirely ungoverned at the provisioning level. No approval chain, no defined access scope, no expiry, no renewal certification. This creates a continuously growing set of external entitlements with no accountability structure." `
                -TargetState "Entra ID P2 or Microsoft Entra ID Governance licensed. Entitlement Management access packages as the sole provisioning channel for all B2B access. Direct invitation only for emergency scenarios with mandatory access package catch-up." `
                -Recommendation "Invest in Entra ID P2 or Microsoft Entra ID Governance. Entitlement Management is the enterprise-grade solution for governed B2B access provisioning and should be the first identity governance investment for organisations with significant external collaboration." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        elseif ($catalogs.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D5" -DomainName "Entitlement Management" -CheckId "D5.1" `
                -Title "Entitlement Management Licensed But No Access Package Catalogs Configured" `
                -Evidence "Catalogs: 0 | Access packages: 0 (P2 appears licensed — API accessible)" `
                -CurrentState "Entitlement Management (P2) is licensed and accessible, but no access package catalogs or packages have been configured." `
                -Gap "P2 is available but the governance tooling is not being used. B2B access continues via ad-hoc invitation rather than governed access packages. The investment in P2 licensing is not delivering its intended governance value." `
                -Risk "High" `
                -BusinessImpact "The organisation is paying for enterprise identity governance capabilities but operating at the same unmanaged level as a P1 tenant. All the risks of ungoverned B2B access persist despite having the tools to address them." `
                -TargetState "At minimum 1 catalog and 5 access packages covering the top B2B collaboration scenarios within 30 days. Full migration of all B2B provisioning to access packages within 90 days." `
                -Recommendation "Immediately create an initial External Access catalog. Identify the top 5 B2B collaboration scenarios (e.g., vendor project access, partner data room, audit firm read-only, consultant tool access, customer advisory board) and create access packages for each. Migrate existing guest invitations to access packages as part of a guest remediation sprint." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $accessPackages = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackages"
            $totalPackages = $accessPackages.Count
            $externalPackages = @($accessPackages | Where-Object { $_.isHidden -eq $false }).Count

            if ($totalPackages -lt 5) {
                $medium++
                $maturityPoints += 2
                Add-Finding -DomainId "D5" -DomainName "Entitlement Management" -CheckId "D5.1" `
                    -Title "Very Limited Access Package Coverage — Only $totalPackages Package(s) Configured" `
                    -Evidence "Catalogs: $($catalogs.Count) | Total access packages: $totalPackages | Externally visible: $externalPackages" `
                    -CurrentState "Entitlement Management is configured with $($catalogs.Count) catalog(s) and $totalPackages access package(s). Coverage is minimal for an enterprise B2B environment." `
                    -Gap "With $totalPackages access packages, the majority of B2B collaboration scenarios are likely still handled via ad-hoc invitation rather than governed packages. Incomplete coverage means ungoverned access continues alongside the governed channel." `
                    -Risk "Medium" `
                    -BusinessImpact "Partial Entitlement Management adoption creates a two-tier B2B governance model: some guests have governed, auditable access; others have ungoverned direct-invitation access. This inconsistency is a compliance audit risk." `
                    -TargetState "All B2B collaboration scenarios covered by access packages. Minimum: 1 package per significant B2B partner programme, plus packages for role-based access (read-only, contributor, admin) per resource." `
                    -Recommendation "Conduct a B2B scenario mapping exercise: document all active external collaboration use cases. Create access packages for each scenario. Set a policy: all new B2B access must be provisioned via access packages — no direct invitations except emergency." `
                    -RoadmapPhase "31-60 Days" -MaturityContribution 2
            }
            else {
                $maturityPoints += 4
                Add-Finding -DomainId "D5" -DomainName "Entitlement Management" -CheckId "D5.1" `
                    -Title "Entitlement Management in Use — $totalPackages Access Packages Across $($catalogs.Count) Catalog(s)" `
                    -Evidence "Catalogs: $($catalogs.Count) | Total access packages: $totalPackages | Externally visible: $externalPackages" `
                    -CurrentState "Entitlement Management is actively used with $totalPackages access packages, providing a governed provisioning channel for B2B access." `
                    -Gap "Verify all access packages have defined expiry policies, approver chains, and access review schedules. Confirm all active B2B guests have a corresponding access package assignment as the access source." `
                    -Risk "Info" `
                    -BusinessImpact "Low — Entitlement Management is operational. Focus on coverage completeness and package hygiene." `
                    -TargetState "100% of B2B access provisioned via access packages. All packages with defined expiry, approver SLAs, and access reviews. Package health score tracked monthly." `
                    -Recommendation "Audit active guest accounts to identify those without a corresponding access package assignment — these are governance gaps. Ensure each package has: at minimum 2 approvers, a defined access duration, and a linked access review." `
                    -RoadmapPhase "Strategic" -MaturityContribution 4
            }
        }

        # ── Check 5.2: Access package expiry and review configuration ─────────────
        if ($accessPackages -and $totalPackages -gt 0) {
            $packagesWithExpiry = 0
            foreach ($pkg in $accessPackages) {
                $assignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackages/$($pkg.id)/assignmentPolicies"
                if ($assignments -and $assignments.value) {
                    foreach ($policy in $assignments.value) {
                        if ($policy.expiration -and $policy.expiration.type -ne "noExpiration") {
                            $packagesWithExpiry++
                            break
                        }
                    }
                }
            }

            $expiryPct = if ($totalPackages -gt 0) { [Math]::Round(($packagesWithExpiry / $totalPackages) * 100, 0) } else { 0 }

            if ($expiryPct -lt 50) {
                $high++
                $maturityPoints += 1
                Add-Finding -DomainId "D5" -DomainName "Entitlement Management" -CheckId "D5.2" `
                    -Title "Only $expiryPct% of Access Packages Have Expiry-Based Assignment Policies" `
                    -Evidence "Access packages checked: $totalPackages | With at least one expiry-based policy: $packagesWithExpiry ($expiryPct%)" `
                    -CurrentState "$expiryPct% of access packages are configured with assignment policies that enforce access expiry. The remainder allow indefinite access assignment." `
                    -Gap "Access packages without expiry allow external identities to retain access indefinitely unless manually revoked. This defeats the lifecycle governance purpose of Entitlement Management." `
                    -Risk "High" `
                    -BusinessImpact "External users with indefinite access package assignments accumulate access rights that outlive their business purpose, replicating the same problem Entitlement Management was deployed to solve." `
                    -TargetState "100% of access packages with B2B guest access have assignment policies enforcing expiry. Default expiry period matches engagement duration. Renewal requires active access review approval." `
                    -Recommendation "Review all access packages and add expiry-enforced assignment policies. Set default expiry to 365 days. Configure renewal policies to require access review approval rather than auto-renewal. Prioritise packages with external user policies first." `
                    -RoadmapPhase "0-30 Days" -MaturityContribution 1
            }
            else {
                $maturityPoints += 4
                Add-Finding -DomainId "D5" -DomainName "Entitlement Management" -CheckId "D5.2" `
                    -Title "$expiryPct% of Access Packages Have Expiry-Based Assignment Policies" `
                    -Evidence "Access packages with expiry policy: $packagesWithExpiry of $totalPackages ($expiryPct%)" `
                    -CurrentState "Majority of access packages enforce assignment expiry, providing lifecycle governance for external identities." `
                    -Gap "Identify the remaining $((100 - $expiryPct))% of packages without expiry policies and remediate. No access package should allow indefinite external access." `
                    -Risk "Info" `
                    -BusinessImpact "Low — access package expiry governance is largely in place." `
                    -TargetState "100% of external-facing access packages with expiry policies. Expiry periods aligned to engagement type (project-based vs. ongoing partnership)." `
                    -Recommendation "Achieve 100% expiry policy coverage. Set access package creation standards that make expiry configuration mandatory during the package design process." `
                    -RoadmapPhase "Strategic" -MaturityContribution 4
            }
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D5" -Name "Entitlement Management" -Icon "📦" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Catalogs: $(if ($catalogs) { $catalogs.Count } else { 'N/A (unlicensed)' }). Access packages: $totalPackages. Externally visible: $externalPackages." `
            -TargetStateSummary "All B2B access via access packages. 100% with expiry policies. All packages with approver chains and access reviews. No direct ad-hoc invitations." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 6: Sensitive Resource Exposure to External Identities ────────

    Function Invoke-Domain6-SensitiveResourceExposure {
        Write-Host "  🔍 D6: Sensitive Resource Exposure to External Identities..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 6.1: Guests with privileged directory roles ─────────────────────
        $privilegedRoleIds = @(
            "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
            "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
            "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
            "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
            "966707d0-3269-4727-9be2-8c3a10f19b9d",  # Password Administrator
            "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"   # Privileged Authentication Administrator
        )

        $guestsInPrivilegedRoles = 0
        $privilegedGuestRoleDetails = @()

        foreach ($roleId in $privilegedRoleIds) {
            $roleMembers = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/directoryRoles?`$filter=roleTemplateId eq '$roleId'"
            if ($roleMembers -and $roleMembers.value -and $roleMembers.value.Count -gt 0) {
                $roleObj = $roleMembers.value[0]
                $members = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/directoryRoles/$($roleObj.id)/members"
                $guestMembers = @($members | Where-Object { $_.userType -eq "Guest" -or $_.userPrincipalName -like "*#EXT#*" })
                if ($guestMembers.Count -gt 0) {
                    $guestsInPrivilegedRoles += $guestMembers.Count
                    $privilegedGuestRoleDetails += "$($roleObj.displayName): $($guestMembers.Count) guest(s)"
                }
            }
        }

        if ($guestsInPrivilegedRoles -gt 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D6" -DomainName "Sensitive Exposure" -CheckId "D6.1" `
                -Title "External Identities Detected in Privileged Directory Roles — Critical Trust Violation" `
                -Evidence "Guests in privileged roles: $guestsInPrivilegedRoles | Roles affected: $($privilegedGuestRoleDetails -join '; ')" `
                -CurrentState "$guestsInPrivilegedRoles external identity/identities hold one or more privileged directory roles: $($privilegedGuestRoleDetails -join ', ')." `
                -Gap "External identities in privileged roles represent a fundamental trust boundary violation. Admin-plane access is being extended to identities outside the organisation's control. The home tenant's security posture, MFA configuration, and account governance directly affect the organisation's admin-plane integrity." `
                -Risk "Critical" `
                -BusinessImpact "A guest in a privileged role can modify tenant configuration, grant permissions to applications, create users, reset passwords, and undermine all other security controls. If the guest's home tenant is compromised, the organisation's admin plane is immediately accessible to the attacker." `
                -TargetState "Zero external identities in any Entra ID privileged role. All privileged access performed by internal identities only. For partner organisations requiring admin assistance, use the Lighthouse model or time-limited Just-In-Time access via PIM with internal sponsorship." `
                -Recommendation "IMMEDIATE ACTION: Remove all guest accounts from privileged roles NOW. For partner engineers who require elevated access, provision a separate internal service account (Member type) with PIM-managed temporary assignment, sponsored by an internal admin. Document and require executive sign-off for any future exception." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 5
            Add-Finding -DomainId "D6" -DomainName "Sensitive Exposure" -CheckId "D6.1" `
                -Title "No External Identities Detected in Privileged Directory Roles" `
                -Evidence "Guests in privileged roles across $($privilegedRoleIds.Count) checked roles: 0" `
                -CurrentState "No guest accounts are present in the assessed privileged directory roles." `
                -Gap "Verify this check is complete by confirming PIM-eligible role assignments (not just active) are also reviewed for guest accounts. PIM-eligible assignments are not captured in this check." `
                -Risk "Info" `
                -BusinessImpact "Low — privileged role membership is clean for external identities at this time." `
                -TargetState "Zero external identities in privileged roles, including PIM-eligible assignments. Alerting in place to detect any future guest privileged role assignment." `
                -Recommendation "Configure an Azure Monitor or Microsoft Sentinel alert rule: trigger when any guest account receives a privileged role assignment (active or eligible). This ensures the clean posture is maintained automatically going forward." `
                -RoadmapPhase "Strategic" -MaturityContribution 5
        }

        # ── Check 6.2: Guests in security-sensitive groups ────────────────────────
        $sensitiveGroupPatterns = @("admin", "security", "azure", "privileged", "global", "it-ops", "core-team", "executive", "vip", "c-suite", "leadership", "board", "finance-lead", "payroll-admin", "hr-admin", "data-owner")
        $sensitiveGroups = @()
        $allGroups = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/groups?`$select=id,displayName,groupTypes,securityEnabled,membershipRule&`$top=100"

        foreach ($pattern in $sensitiveGroupPatterns) {
            $matched = @($allGroups | Where-Object { $_.displayName -match $pattern -and $_.securityEnabled -eq $true })
            if ($matched.Count -gt 0) { $sensitiveGroups += $matched }
        }

        $sensitiveGroups = @($sensitiveGroups | Select-Object -Unique -Property id, displayName, securityEnabled)
        $guestGroupCount = 0
        $affectedGroups = @()

        foreach ($grp in ($sensitiveGroups | Select-Object -First 20)) {
            $grpId = $grp.id
            if ([string]::IsNullOrWhiteSpace($grpId)) { continue }
            $grpMembers = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/groups/$grpId/members?`$select=id,displayName,userType,userPrincipalName"
            $guestMembersInGrp = @($grpMembers | Where-Object { $_.userType -eq "Guest" -or $_.userPrincipalName -like "*#EXT#*" })
            if ($guestMembersInGrp.Count -gt 0) {
                $guestGroupCount += $guestMembersInGrp.Count
                $affectedGroups += "$($grp.displayName) ($($guestMembersInGrp.Count) guest(s))"
            }
        }

        if ($guestGroupCount -gt 0) {
            $high++
            $maturityPoints += 2
            Add-Finding -DomainId "D6" -DomainName "Sensitive Exposure" -CheckId "D6.2" `
                -Title "External Identities Found in Security-Sensitive Groups ($guestGroupCount Guest(s))" `
                -Evidence "Sensitive security groups checked: $($sensitiveGroups.Count) | Groups with guest members: $($affectedGroups.Count) | Total guest members in sensitive groups: $guestGroupCount | Affected: $(($affectedGroups | Select-Object -First 5) -join '; ')" `
                -CurrentState "$guestGroupCount external identity/identities are members of security-sensitive groups identified by naming pattern: $($affectedGroups -join ', ')." `
                -Gap "Security groups controlling access to sensitive resources, admin tooling, or privileged workflows contain external identities. Membership in these groups was likely added without considering the external access implications." `
                -Risk "High" `
                -BusinessImpact "External identities in security-sensitive groups inherit all resource and application access granted to the group. This may grant access to internal tools, SharePoint admin sites, Azure RBAC resources, or application admin panels far beyond what the original B2B use case intended." `
                -TargetState "Zero external identities in any security group not explicitly designed for B2B access. External access governed exclusively via dedicated B2B-scoped groups assigned through Entitlement Management access packages." `
                -Recommendation "Audit all affected groups and remove guest members. Replace with dedicated B2B access groups (e.g., 'ext-vendor-read', 'partner-project-contributors') scoped to only the resources required. Govern these B2B access groups exclusively through Entitlement Management access packages." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D6" -DomainName "Sensitive Exposure" -CheckId "D6.2" `
                -Title "No External Identities Detected in Assessed Security-Sensitive Groups" `
                -Evidence "Sensitive groups assessed: $($sensitiveGroups.Count) | Groups with guest members: 0" `
                -CurrentState "No guest accounts found in the security-sensitive groups assessed by naming pattern." `
                -Gap "This check uses naming patterns — groups with non-standard naming that control sensitive access may not be assessed. A full access model review is recommended." `
                -Risk "Info" `
                -BusinessImpact "Low — sensitive group membership appears clean for external identities in the assessed scope." `
                -TargetState "A formal external access model defines which groups can contain external identities. All other security groups block external membership via group policy or access review gate." `
                -Recommendation "Extend this check with a formal data access classification review: identify all groups controlling access to sensitive data classifications (Confidential, Highly Confidential) and verify no external identities are members." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 6.3: Apps with guest service principal access ───────────────────
        $appRoleAssignmentsToGuests = 0
        $guestAppList = @()

        # Sample app role assignments for guest users
        $guestSample = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName&`$top=50"

        foreach ($guest in ($guestSample | Select-Object -First 30)) {
            $guestId = $guest.id
            if ([string]::IsNullOrWhiteSpace($guestId)) { continue }
            $appRoles = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/users/$guestId/appRoleAssignments"
            if ($appRoles -and $appRoles.value -and $appRoles.value.Count -gt 0) {
                $appRoleAssignmentsToGuests += $appRoles.value.Count
                foreach ($role in $appRoles.value) {
                    if ($guestAppList -notcontains $role.resourceDisplayName) {
                        $guestAppList += $role.resourceDisplayName
                    }
                }
            }
        }

        if ($appRoleAssignmentsToGuests -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D6" -DomainName "Sensitive Exposure" -CheckId "D6.3" `
                -Title "External Identities Have Direct App Role Assignments ($appRoleAssignmentsToGuests Assignment(s) Across Sampled Guests)" `
                -Evidence "Sampled guest accounts: $([Math]::Min($guestSample.Count, 30)) | App role assignments found: $appRoleAssignmentsToGuests | Apps with guest role assignments: $(($guestAppList | Select-Object -First 5) -join ', ')$(if ($guestAppList.Count -gt 5){' ...'})" `
                -CurrentState "External identities have direct application role assignments, granting access to enterprise applications at the role level." `
                -Gap "Direct app role assignments to guests bypass the Entitlement Management governance layer. These assignments are not tracked in access packages, have no expiry, and are not included in access reviews unless explicitly configured." `
                -Risk "Medium" `
                -BusinessImpact "Application role assignments to guests may grant access beyond what the business relationship requires. Without an access review, these assignments persist indefinitely and are invisible to the business owners of those applications." `
                -TargetState "Zero direct app role assignments to external identities. All guest application access provisioned via Entitlement Management access packages that include the app role assignment as a resource." `
                -Recommendation "Migrate all direct app role assignments to guests into Entitlement Management access packages. Configure Access Reviews for each affected application to certify existing external access. Set app provisioning policy to block direct assignment to guest accounts." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D6" -DomainName "Sensitive Exposure" -CheckId "D6.3" `
                -Title "No Direct App Role Assignments to External Identities Detected (Sampled)" `
                -Evidence "Sampled guest accounts: $([Math]::Min($guestSample.Count, 30)) | Direct app role assignments: 0" `
                -CurrentState "In the sampled guest population, no direct application role assignments were detected." `
                -Gap "This check is based on a sample. Full tenant validation recommended. Also check enterprise application assignments via group membership (indirect app access)." `
                -Risk "Info" `
                -BusinessImpact "Low — direct app role exposure for sampled guests appears controlled." `
                -TargetState "Formal app access model for external identities. All app access via Entitlement Management. Quarterly app access review covering all external identities." `
                -Recommendation "Conduct a full tenant audit of app role assignments to guest accounts using Graph API: query /users?filter=userType eq 'Guest' and iterate /appRoleAssignments. Include in quarterly access review scope." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D6" -Name "Sensitive Exposure" -Icon "🔍" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Guests in privileged roles: $guestsInPrivilegedRoles. Guests in sensitive groups: $guestGroupCount. Direct app role assignments (sampled): $appRoleAssignmentsToGuests." `
            -TargetStateSummary "Zero guests in privileged roles. Zero guests in non-B2B security groups. All app access via Entitlement Management. Quarterly access reviews for all external entitlements." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 7: Guest Ownership, Sponsorship & Accountability ────────────

    Function Invoke-Domain7-GuestOwnership {
        Write-Host "  👤 D7: Guest Ownership, Sponsorship & Accountability..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 7.1: Guest accounts with no manager / sponsor ───────────────────
        $guestPopulation = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName,createdDateTime&`$top=50"
        $sampleSize = [Math]::Min($guestPopulation.Count, 40)
        $sponsorlessGuests = 0

        foreach ($guest in ($guestPopulation | Select-Object -First $sampleSize)) {
            $guestId = $guest.id
            if ([string]::IsNullOrWhiteSpace($guestId)) { continue }

            try {
                $manager = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/users/$guestId/manager" -ErrorAction Stop
            }
            catch {
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 404) {
                    $sponsorlessGuests++
                }
            }
        }

        $sponsorlessPct = if ($sampleSize -gt 0) { [Math]::Round(($sponsorlessGuests / $sampleSize) * 100, 0) } else { 0 }

        if ($sponsorlessPct -ge 60) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D7" -DomainName "Guest Ownership" -CheckId "D7.1" `
                -Title "High Proportion of Unsponsored Guest Accounts ($sponsorlessPct% Without Internal Manager/Sponsor)" `
                -Evidence "Sampled guests: $sampleSize | Without internal manager/sponsor: $sponsorlessGuests ($sponsorlessPct%)" `
                -CurrentState "~$sponsorlessPct% of sampled guest accounts have no internal manager attribute set — indicating no named internal sponsor accountable for the external relationship." `
                -Gap "Without a named sponsor, there is no internal accountability for each guest's access. When access reviews require a reviewer decision, sponsorless guests are either auto-denied (removing productive access) or skip the review (allowing accumulation). Neither outcome is governed." `
                -Risk "High" `
                -BusinessImpact "Sponsorless guest accounts cannot be meaningfully certified in Access Reviews. This breaks the accountability chain: no one internally owns the relationship, no one answers for the guest's continued access, and no one is notified when the business purpose ends." `
                -TargetState "100% of guest accounts have a named internal sponsor (manager attribute). Sponsor is a business owner, not IT. Sponsor receives access review decisions and lifecycle notifications. Sponsor change triggers re-certification." `
                -Recommendation "1. Define a Sponsor Model: every guest account must have a named business sponsor. 2. Update all existing guests: set the manager attribute to the sponsor's Entra ID object. 3. Include sponsor assignment as a mandatory step in Entitlement Management access package request workflows. 4. Configure Access Reviews to send review decisions to the sponsor." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($sponsorlessPct -ge 30) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D7" -DomainName "Guest Ownership" -CheckId "D7.1" `
                -Title "Moderate Sponsorship Gap — $sponsorlessPct% of Sampled Guests Without Internal Manager" `
                -Evidence "Sampled guests: $sampleSize | Without internal manager/sponsor: $sponsorlessGuests ($sponsorlessPct%)" `
                -CurrentState "~$sponsorlessPct% of sampled guests have no manager attribute — indicating partial sponsorship adoption." `
                -Gap "A significant proportion of guests lack a named sponsor. Access reviews for these accounts cannot be delegated to a business owner." `
                -Risk "Medium" `
                -BusinessImpact "Partial sponsorship model creates inconsistent accountability. Sponsored guests are governed; unsponsored guests accumulate without accountability." `
                -TargetState "100% of guest accounts with a named business sponsor. Sponsor assignment automated at invitation/access package request." `
                -Recommendation "Audit all guest accounts without a manager attribute. Assign sponsors based on the team/project that originally invited or benefits from each guest's access. Build sponsor assignment into all future invitation workflows." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D7" -DomainName "Guest Ownership" -CheckId "D7.1" `
                -Title "Guest Sponsorship Coverage Is Good ($sponsorlessPct% Without Sponsor — Sample)" `
                -Evidence "Sampled guests: $sampleSize | Without sponsor: $sponsorlessGuests ($sponsorlessPct%)" `
                -CurrentState "A majority of sampled guests have a named internal sponsor (manager attribute) assigned." `
                -Gap "Validate that sponsor assignments are current — sponsors may have left the organisation, making their guests effectively orphaned despite having a manager entry." `
                -Risk "Info" `
                -BusinessImpact "Low — sponsorship coverage is adequate. Maintain accuracy of sponsor assignments." `
                -TargetState "100% sponsor coverage with active, employed sponsors. Automated re-sponsorship triggered when a sponsor leaves the organisation." `
                -Recommendation "Add a Lifecycle Workflow trigger: when a manager (sponsor) leaves, notify their manager and require re-sponsorship of all associated guests within 14 days, or auto-disable the guests pending re-assignment." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 7.2: Guest access reviews ───────────────────────────────────────
        $guestAccessReviews = $null
        $guestReviewCount = 0

        Try {
            $allReviews = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions?`$top=20"
            if ($allReviews) {
                $guestAccessReviews = @($allReviews | Where-Object {
                        ($_.scope.query -like "*Guest*") -or
                        ($_.scope.principalScopes -and $_.scope.principalScopes.Count -gt 0 -and ($_.scope.principalScopes | Where-Object { $_.query -like "*Guest*" }))
                    })
                $guestReviewCount = $guestAccessReviews.Count
            }
        }
        Catch {
            Write-Verbose "  ⚠ Access Reviews API not accessible — P2 may not be licensed."
            $guestAccessReviews = $null
        }

        if ($null -eq $guestAccessReviews) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D7" -DomainName "Guest Ownership" -CheckId "D7.2" `
                -Title "Guest Access Reviews Not Available — Entra ID P2 May Not Be Licensed" `
                -Evidence "Access Reviews API not accessible — likely unlicensed for P2 features" `
                -CurrentState "Access Reviews feature is not available, or the token lacks AccessReview.Read.All permission. Guest access cannot be formally certified on a periodic cadence." `
                -Gap "Without Access Reviews, no mechanism exists to periodically certify that each guest's access is still business-justified. Access accumulates without a formal accountability check." `
                -Risk "High" `
                -BusinessImpact "Compliance frameworks (SOC 2, ISO 27001, NIST, GDPR) require periodic access certification for third-party access. Without Access Reviews, there is no auditable evidence of periodic external access certification — a direct audit finding." `
                -TargetState "Entra ID P2 licensed. Quarterly guest access reviews configured. Reviewer = guest sponsor. Auto-remove action applied to uncertified guests after 14-day grace period." `
                -Recommendation "License Entra ID P2 or Microsoft Entra ID Governance. Access Reviews for guest certification is one of the highest-value P2 features for B2B governance. Configure reviews immediately upon licensing." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        elseif ($guestReviewCount -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D7" -DomainName "Guest Ownership" -CheckId "D7.2" `
                -Title "No Guest-Specific Access Reviews Configured Despite P2 Being Licensed" `
                -Evidence "Total access review definitions: $($allReviews.Count) | Guest-scoped definitions: 0" `
                -CurrentState "P2 Access Reviews are available ($($allReviews.Count) total definitions configured), but no access reviews are specifically scoped to guest or external user accounts." `
                -Gap "External identities are not subject to periodic access certification. Without guest-specific reviews, the external identity population is never formally certified by a business owner, regardless of how long the guest has been in the tenant." `
                -Risk "High" `
                -BusinessImpact "No auditable evidence of periodic external access certification. Continued accumulation of uncertified external access. Direct compliance gap for any framework requiring third-party access reviews." `
                -TargetState "Quarterly guest access reviews scoped to all guest accounts. Reviewer = guest sponsor / business owner. Auto-remove action for uncertified access. Annual review of all external-facing access packages." `
                -Recommendation "Create a guest access review immediately: Scope = All guest users, Reviewer = Manager (sponsor), Recurrence = Quarterly, Action on non-response = Deny access. This is a 30-minute configuration with immediate compliance value." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D7" -DomainName "Guest Ownership" -CheckId "D7.2" `
                -Title "Guest Access Reviews Active — $guestReviewCount Guest-Scoped Review Definition(s) Configured" `
                -Evidence "Total access review definitions: $($allReviews.Count) | Guest-scoped: $guestReviewCount" `
                -CurrentState "$guestReviewCount access review definition(s) are scoped to guest or external user accounts." `
                -Gap "Verify that all active guest accounts are in scope of at least one review, that reviewers are business sponsors (not IT), and that auto-remove is configured for uncertified access." `
                -Risk "Info" `
                -BusinessImpact "Low — guest access reviews are configured. Focus on review quality, completion rates, and scope completeness." `
                -TargetState "100% of guest accounts covered by at least one access review. >90% reviewer completion rate. Auto-remove applied within 14 days of review close for uncertified access." `
                -Recommendation "Report on access review completion rates monthly. Escalate to business owner managers when reviewer participation is below 80%. Consider automated reminders to sponsors before review due dates." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D7" -Name "Guest Ownership" -Icon "👤" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Sponsorship (sample): $((100 - $sponsorlessPct))% with sponsor. Guest access reviews: $guestReviewCount definition(s). Total guest population: $($guestPopulation.Count)." `
            -TargetStateSummary "100% of guests with named business sponsors. Quarterly access reviews with auto-remove. Sponsor lifecycle triggers automated re-certification when sponsor leaves." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 8: External Identity Monitoring & Anomaly Detection ──────────

    Function Invoke-Domain8-ExternalMonitoring {
        Write-Host "  📡 D8: External Identity Monitoring & Anomaly Detection..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 8.1: Risky guest sign-ins or risky guest users (Identity Protection) ─
        $riskyGuests = $null
        $riskyGuestCount = 0

        Try {
            $riskyUsers = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'&`$top=50"
            if ($riskyUsers) {
                $riskyGuests = @($riskyUsers | Where-Object { $_.userPrincipalName -like "*#EXT#*" })
                $riskyGuestCount = $riskyGuests.Count
            }
        }
        Catch {
            Write-Verbose "  ⚠ Identity Protection risky users API not accessible."
            $riskyGuests = $null
        }

        if ($null -eq $riskyGuests) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D8" -DomainName "External Monitoring" -CheckId "D8.1" `
                -Title "Identity Protection Risk Data for Guests Not Available — P2 License or Permission Missing" `
                -Evidence "IdentityProtection riskyUsers API: not accessible" `
                -CurrentState "Entra ID Identity Protection risk signals for guest accounts are not available — either P2 is not licensed or the assessment token lacks IdentityRiskyUser.Read.All permission." `
                -Gap "Without Identity Protection, risky guest sign-ins (leaked credentials from the home tenant, sign-in risk events, impossible travel) are invisible to the organisation. Compromised guest accounts can operate without triggering any detection." `
                -Risk "Medium" `
                -BusinessImpact "A compromised guest account from a partner whose credentials have been leaked (e.g., in a public breach) will not trigger any alert in the tenant. The attacker can access shared resources unchallenged until detected by other means." `
                -TargetState "Identity Protection P2 licensed. Risky sign-in alerts configured for guest accounts. Risk-based CA policy blocks sign-ins from risky guests until risk is remediated." `
                -Recommendation "License Entra ID P2 for Identity Protection. Configure a CA risk policy: if user risk = High or sign-in risk = High → block access and require admin review. Extend this to guest identities specifically." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        elseif ($riskyGuestCount -gt 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D8" -DomainName "External Monitoring" -CheckId "D8.1" `
                -Title "Active Risky Guest Identities Detected — $riskyGuestCount Guest(s) at Risk" `
                -Evidence "Risky guest users at riskState = atRisk: $riskyGuestCount | Sample UPNs: $(($riskyGuests | Select-Object -First 3 | ForEach-Object { $_.userPrincipalName }) -join ', ')" `
                -CurrentState "$riskyGuestCount guest account(s) currently have an active risk state in Entra ID Identity Protection." `
                -Gap "Risky guest accounts are accessing or have accessed enterprise resources while flagged as compromised or at-risk by Identity Protection. Risk remediation actions have not been taken for these accounts." `
                -Risk "Critical" `
                -BusinessImpact "An at-risk guest account that has not been disabled represents an active potential breach vector. The risk signal means Identity Protection has detected a compromise indicator (e.g., leaked credentials, impossible travel, anonymous IP) for that external identity." `
                -TargetState "Zero guest accounts in atRisk state with active access. Risk-based CA policy automatically blocks risky guest sign-ins. Sponsor notified immediately when a guest account is flagged at-risk. Risk remediated within 4 hours or account disabled." `
                -Recommendation "IMMEDIATE: Disable all guest accounts with riskState = atRisk until the risk is investigated and remediated. Notify the account sponsor. Configure a CA policy: User risk = High → block access for guests. Establish an incident response playbook for compromised guest accounts." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D8" -DomainName "External Monitoring" -CheckId "D8.1" `
                -Title "No Currently At-Risk Guest Identities Detected" `
                -Evidence "Risky guest users at riskState = atRisk: 0" `
                -CurrentState "Identity Protection is accessible and no guest accounts are currently flagged as at-risk." `
                -Gap "Verify that a risk-based CA policy for guests is active to ensure future risk events automatically block access without requiring manual intervention." `
                -Risk "Info" `
                -BusinessImpact "Low — no active guest risk events detected." `
                -TargetState "Proactive risk-based CA: any guest with user risk = High is automatically blocked until admin review. Risk events trigger sponsor notification within 30 minutes." `
                -Recommendation "Configure a risk-based CA policy targeting guests: User Risk = High → Block access. Configure alert notifications to guest sponsors when their guest account triggers a risk event. Test with a simulated risky sign-in." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 8.2: Diagnostic settings — guest sign-in logging ────────────────
        $diagnosticSettings = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=userType eq 'Guest'&`$top=5"
        $guestSignInLogsAvailable = ($diagnosticSettings -ne $null -and $diagnosticSettings.value -ne $null)

        if (-not $guestSignInLogsAvailable) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D8" -DomainName "External Monitoring" -CheckId "D8.2" `
                -Title "Guest Sign-In Logs Are Not Accessible — External Activity Is Unmonitored" `
                -Evidence "Guest sign-in log query returned null or empty — AuditLog.Read.All permission may be missing or logs not routed to a SIEM." `
                -CurrentState "Guest sign-in logs cannot be accessed via the assessment token. External identity authentication activity is not visible for monitoring or forensic investigation." `
                -Gap "Without sign-in log access for guests, there is no visibility into authentication patterns, failed attempts, impossible travel, or access from unexpected locations for external identities." `
                -Risk "High" `
                -BusinessImpact "Zero forensic capability for external identity incidents. Post-incident investigation is impossible without log history. Compliance frameworks require audit log retention — absence of logs is a direct finding." `
                -TargetState "Guest sign-in logs retained for minimum 90 days in Entra ID (P1+). Logs streamed to SIEM (Sentinel, Splunk, or equivalent). Custom detection rules for guest anomalies: impossible travel, first-seen country, off-hours access to sensitive apps." `
                -Recommendation "1. Ensure Diagnostic Settings stream Entra ID sign-in logs to a Log Analytics Workspace or SIEM. 2. Build guest-specific detection rules: new country access, sign-ins outside business hours, access from Tor/anonymous proxies. 3. Configure a Microsoft Sentinel workbook for external identity monitoring or use the Entra ID Workbooks → B2B tab." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            $recentGuestSignIns = if ($diagnosticSettings.value) { $diagnosticSettings.value.Count } else { 0 }
            Add-Finding -DomainId "D8" -DomainName "External Monitoring" -CheckId "D8.2" `
                -Title "Guest Sign-In Logs Are Accessible — External Activity Is Auditable" `
                -Evidence "Recent guest sign-in log entries accessible: $recentGuestSignIns | AuditLog.Read.All: confirmed" `
                -CurrentState "Guest sign-in logs are accessible, confirming audit log collection is operational for external identities." `
                -Gap "Log accessibility confirms collection — verify logs are streamed to a SIEM with active detection rules specifically for guest anomalies. Static logs without active detection provide forensic value but no proactive protection." `
                -Risk "Info" `
                -BusinessImpact "Low — sign-in log collection is operational. Invest in active detection to convert log data into protection." `
                -TargetState "Guest sign-in logs streaming to SIEM with active detection rules. Monthly B2B sign-in trend report reviewed by security team. Alert within 15 minutes of anomalous guest activity." `
                -Recommendation "Build three guest-specific detection rules in your SIEM: (1) Guest sign-in from new country (alert). (2) Guest accessing sensitive app outside agreed hours (alert). (3) Guest sign-in failure rate >10 in 5 minutes (block + alert). Use Entra ID Workbooks for baseline reporting." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 8.3: Guest-specific audit trail (invitation and access changes) ──
        $guestAuditUri = "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$filter=targetResources/any(t:t/type eq 'User')&`$top=50"
        $guestAuditLogs = Invoke-GraphRequest -Uri $guestAuditUri

        $guestAuditGuestLogs = @()

        if ($guestAuditLogs -and $guestAuditLogs.value) {
            $guestAuditGuestLogs = @(
                $guestAuditLogs.value | Where-Object {
                    $_.initiatedBy.user.userPrincipalName -and
                    $_.initiatedBy.user.userPrincipalName -match "#EXT#"
                }
            )
        }

        $guestAuditAvailable = ($guestAuditGuestLogs.Count -gt 0)

        if (-not $guestAuditAvailable) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D8" -DomainName "External Monitoring" -CheckId "D8.3" `
                -Title "Guest-Initiated Directory Audit Logs Not Accessible or No Guest Activity Logged" `
                -Evidence "Guest-initiated directory audit events detected: $($guestAuditGuestLogs.Count)." `
                -CurrentState "Directory audit logs filtered for guest-initiated actions are not returning results — either no recent guest activity was captured or the logs are not accessible." `
                -Gap "Guest-initiated directory actions (user invitations, group membership changes, app consent) are a critical audit trail for detecting insider threat from external parties. Without this data, guest privilege escalation attempts may go undetected." `
                -Risk "Medium" `
                -BusinessImpact "Guest-initiated privilege escalation, self-service group joining, or app consent grants are invisible without directory audit logs. These are the most common internal lateral movement vectors exploited by compromised guest accounts." `
                -TargetState "Directory audit logs for all guest-initiated actions retained and queryable. SIEM alert for: guest adding themselves to a group, guest consenting to an application, guest inviting another guest." `
                -Recommendation "Confirm Diagnostic Settings route both SignInLogs and AuditLogs to Log Analytics or SIEM. Build detection: any guest account initiating a group membership change or application consent grant triggers an immediate alert." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D8" -DomainName "External Monitoring" -CheckId "D8.3" `
                -Title "Guest-Initiated Directory Audit Logs Are Accessible" `
                -Evidence "Guest-initiated directory audit events detected: $($guestAuditGuestLogs.Count)." `
                -CurrentState "Directory audit logs capturing guest-initiated directory actions are accessible and populated." `
                -Gap "Log availability confirms collection — ensure active detection rules are built to alert on anomalous guest-initiated actions." `
                -Risk "Info" `
                -BusinessImpact "Low — audit trail is in place. Build detection rules to operationalise the log data." `
                -TargetState "Active detection on guest-initiated directory changes. Automated response: guest-initiated group add triggers sponsor notification and 24-hour review window before taking effect." `
                -Recommendation "Implement a SIEM detection rule: any guest initiating a group membership change or application permission grant triggers a Priority-1 alert for the security team and the guest's sponsor." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D8" -Name "External Monitoring" -Icon "📡" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Risky guests: $riskyGuestCount. Sign-in logs: $(if ($guestSignInLogsAvailable){'Accessible'}else{'Not accessible'}). Directory audit API: $(if ($guestAuditApiAvailable){'Accessible'}else{'Not accessible'}). Guest audit events detected: $($guestAuditGuestLogs.Count)." `
            -TargetStateSummary "Identity Protection for guests. Sign-in + audit logs in SIEM. Active guest anomaly detections. Risky guest auto-block CA policy. 15-minute alert SLA for guest anomalies." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── JSON & HTML Serialisation Helpers ──────────────────────────────────

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

    #endregion

    #region ── HTML Dashboard Generation ─────────────────────────────────────────

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
        $totalInfo = ($script:Findings | Where-Object { $_.Risk -eq "Info" }).Count
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
<title>B2B External Identity Trust Assessment — __TENANT_NAME__</title>
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
.logo-icon{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#39c5cf,#a371f7);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3}
.logo-sub{font-size:10px;color:var(--muted);margin-top:3px}
.ver-badge{display:inline-block;font-size:9px;background:var(--surface3);color:var(--accent2);padding:2px 7px;border-radius:20px;margin-top:6px;font-family:var(--mono)}
nav{flex:1;padding:10px 8px}
.nav-section{font-size:9px;font-weight:700;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;padding:10px 10px 4px}
.nav-btn{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:var(--radius-sm);cursor:pointer;font-size:12px;color:var(--muted2);margin-bottom:2px;transition:all .15s;border:none;background:none;width:100%;text-align:left}
.nav-btn:hover{background:var(--surface2);color:var(--text)}
.nav-btn.active{background:rgba(57,197,207,.10);color:var(--accent2);border-left:3px solid var(--accent2);font-weight:600}
.nav-btn .nav-icon{font-size:14px;width:18px;text-align:center}
.theme-toggle{padding:12px 16px;border-top:1px solid var(--border)}
.theme-pill{display:flex;background:var(--surface2);border-radius:20px;padding:3px}
.theme-opt{flex:1;padding:5px;text-align:center;font-size:11px;border-radius:16px;cursor:pointer;transition:all .2s;color:var(--muted)}
.theme-opt.active{background:var(--accent2);color:#fff;font-weight:600}
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
.search-wrap input:focus{outline:none;border-color:var(--accent2)}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
.filter-pills{display:flex;gap:6px;flex-wrap:wrap}
.fpill{font-size:11px;padding:4px 11px;border-radius:20px;cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted);transition:all .15s}
.fpill.active{font-weight:700}
.fpill-all.active   {background:var(--accent2);color:#fff;border-color:var(--accent2)}
.fpill-crit.active  {background:var(--red);color:#fff;border-color:var(--red)}
.fpill-high.active  {background:var(--amber);color:#fff;border-color:var(--amber)}
.fpill-medium.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.fpill-low.active   {background:var(--green);color:#fff;border-color:var(--green)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:var(--text)}
.sort-arrow{font-size:9px;margin-left:3px;opacity:.5}
.sort-active .sort-arrow{opacity:1;color:var(--accent2)}
td{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:top;line-height:1.4}
tr:hover td{background:var(--surface2)}
.risk-badge{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:12px;font-family:var(--mono)}
.rb-Critical{background:rgba(248,81,73,.18);color:#f85149}
.rb-High    {background:rgba(210,153,34,.18);color:#d29922}
.rb-Medium  {background:rgba(56,139,253,.18);color:#388bfd}
.rb-Low     {background:rgba(63,185,80,.18);color:#3fb950}
.rb-Info    {background:rgba(125,133,144,.18);color:#7d8590}
.phase-badge{font-size:10px;padding:2px 8px;border-radius:12px;background:var(--surface3);color:var(--muted);font-family:var(--mono);white-space:nowrap}
.domain-tag{font-size:10px;padding:2px 7px;border-radius:12px;background:rgba(57,197,207,.12);color:var(--accent2);font-family:var(--mono)}

/* ── Pagination ── */
.pagination{display:flex;align-items:center;gap:6px;margin-top:14px;flex-wrap:wrap}
.pg-btn{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 10px;cursor:pointer;font-size:12px;color:var(--text);font-family:var(--sans)}
.pg-btn:hover{background:var(--surface3)}
.pg-btn.active{background:var(--accent2);color:#fff;border-color:var(--accent2)}
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
.roadmap-item:hover{border-color:var(--accent2);background:var(--surface3)}
.roadmap-item-title{font-size:11px;font-weight:600;line-height:1.4;margin-bottom:5px}
.roadmap-item-meta{display:flex;gap:5px;flex-wrap:wrap}

/* ── Toast ── */
#toast{position:fixed;bottom:20px;right:20px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 16px;font-size:12px;z-index:9999;transform:translateY(12px);opacity:0;transition:all .25s;pointer-events:none;box-shadow:var(--shadow)}
#toast.show{transform:none;opacity:1}

/* ── Hamburger (mobile) ── */
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;font-size:18px;color:var(--text)}
@media(max-width:768px){
  #sidebar{transform:translateX(-100%);transition:transform .3s}
  #sidebar.open{transform:none}
  #main{margin-left:0;padding:16px;padding-top:54px}
  #menuToggle{display:block}
}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<div id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🌐</div>
    <div class="logo-title">B2B External Identity<br>Trust Assessment</div>
    <div class="logo-sub">__TENANT_NAME__</div>
    <span class="ver-badge">v1.0</span>
  </div>
  <nav>
    <div class="nav-section">Assessment</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">🏠</span>Overview</button>
    <button class="nav-btn" onclick="showPage('domains',this)"><span class="nav-icon">🗺️</span>Trust Domains</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔎</span>Findings</button>
    <button class="nav-btn" onclick="showPage('roadmap',this)"><span class="nav-icon">📅</span>Remediation Roadmap</button>
    <div class="nav-section">Export</div>
    <button class="nav-btn" onclick="exportFindingsCSV()"><span class="nav-icon">📥</span>Export CSV</button>
  </nav>
  <div class="theme-toggle">
    <div class="theme-pill">
      <div class="theme-opt active" id="thDark"  onclick="setTheme('dark')">🌙 Dark</div>
      <div class="theme-opt"        id="thLight" onclick="setTheme('light')">☀️ Light</div>
    </div>
  </div>
  <div class="sidebar-footer">
    Generated: __ASSESSMENT_DATE__<br>
    Tenant: <span style="font-family:var(--mono);font-size:9px">__TENANT_ID__</span><br><br>
    <span class="kbd">Esc</span> Close drawer &nbsp;
    <span class="kbd">/</span> Search &nbsp;
    <span class="kbd">←→</span> Navigate
  </div>
</div>

<div id="main">

  <!-- ══ OVERVIEW PAGE ══════════════════════════════════════════════════════ -->
  <div class="page active" id="page-overview">
    <div class="page-header">
      <h1>🌐 B2B External Identity Trust Assessment</h1>
      <p>Enterprise digital trust-boundary analysis for <strong>__TENANT_NAME__</strong> &mdash; evaluated across 8 architectural domains.</p>
    </div>

    <!-- Maturity Ring -->
    <div class="health-card">
      <div class="health-ring-wrap">
        <svg width="128" height="128" viewBox="0 0 128 128">
          <circle class="health-ring-bg" cx="64" cy="64" r="54"/>
          <circle class="health-ring-fill" cx="64" cy="64" r="54"
            stroke="__RING_COLOR__"
            stroke-dasharray="__RING_DASH__ __RING_GAP__"/>
        </svg>
        <div class="ring-label">
          <div class="ring-val" style="color:__RING_COLOR__">__OVERALL_SCORE__</div>
          <div class="ring-sub">/ 5.0</div>
        </div>
      </div>
      <div class="health-info">
        <h2>External Identity Maturity: <span style="color:__RING_COLOR__">__OVERALL_LABEL__</span></h2>
        <p>Your B2B and guest identity architecture has been assessed across trust boundary design, invitation governance, guest lifecycle, conditional access, entitlement management, sensitive resource exposure, ownership accountability, and monitoring capability.</p>
        <div class="maturity-scale">
          <span class="ms-pill" style="color:#f85149;border-color:#f85149">1 — Initial</span>
          <span class="ms-pill" style="color:#d29922;border-color:#d29922">2 — Developing</span>
          <span class="ms-pill" style="color:#388bfd;border-color:#388bfd">3 — Defined</span>
          <span class="ms-pill" style="color:#39c5cf;border-color:#39c5cf">4 — Managed</span>
          <span class="ms-pill" style="color:#3fb950;border-color:#3fb950">5 — Optimised</span>
        </div>
      </div>
    </div>

    <!-- Key Metrics -->
    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-label">Critical Findings</div>
        <div class="stat-value" style="color:var(--red)">__TOTAL_CRITICAL__</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-label">High Findings</div>
        <div class="stat-value" style="color:var(--amber)">__TOTAL_HIGH__</div>
        <div class="stat-sub">Remediate within 30 days</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-label">Medium Findings</div>
        <div class="stat-value" style="color:var(--accent)">__TOTAL_MEDIUM__</div>
        <div class="stat-sub">Address within 60 days</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-label">Low / Info</div>
        <div class="stat-value" style="color:var(--green)">__TOTAL_LOW__</div>
        <div class="stat-sub">Monitor and optimise</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-label">Trust Domains</div>
        <div class="stat-value" style="color:var(--accent2)">8</div>
        <div class="stat-sub">Architectural domains assessed</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-label">Total Findings</div>
        <div class="stat-value" style="color:var(--accent3)">__TOTAL_FINDINGS__</div>
        <div class="stat-sub">Across all domains</div>
      </div>
    </div>

    <!-- Domain Overview -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Trust Domain Summary</span>
        <span class="panel-badge" id="domainSummaryBadge">8 domains</span>
      </div>
      <div class="domain-grid" id="overviewDomainGrid"></div>
    </div>

    <!-- Risk Distribution -->
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Finding Risk Distribution</span>
          <span class="panel-badge">by severity</span>
        </div>
        <div id="riskBars"></div>
      </div>
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Domain Maturity Breakdown</span>
          <span class="panel-badge">score per domain</span>
        </div>
        <div id="maturityBars"></div>
      </div>
    </div>

    <!-- Architectural Context -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Why External Identity Trust Architecture Matters</span>
        <span class="panel-badge">business context</span>
      </div>
      <div style="font-size:12px;line-height:1.75;color:var(--muted2)">
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Problem Statement:</strong> External identities represent the enterprise's digital trust boundary with its ecosystem — partners, vendors, customers, auditors, and contractors. Each guest account is a controlled bridge between two security perimeters. When that bridge is unmanaged, it becomes an unmonitored attack corridor.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Business Risk:</strong> The most common enterprise data breach scenarios involve external identities: compromised vendor credentials, overprivileged partner access, stale guest accounts from concluded engagements, and ungoverned direct invitations that bypass security review. These are not theoretical — they are the documented patterns behind major M365 breaches.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Regulatory Exposure:</strong> GDPR, ISO 27001, SOC 2, NIST 800-53, and PCI DSS all require controls over third-party access to systems containing regulated data. Absence of periodic access certification for external identities, lack of access controls at the invitation layer, and missing audit logs are common audit findings in these frameworks.</p>
        <p><strong style="color:var(--text)">Target Architecture:</strong> A mature external identity trust architecture implements: deny-default cross-tenant access with partner-specific trust tiers; governed invitation with approval workflow and Terms of Use; automated lifecycle with expiry, reviews, and disability on inactivity; layered Conditional Access for guest identities; Entitlement Management as the sole provisioning channel; and continuous monitoring with anomaly detection — all aligned with Microsoft Zero Trust principles.</p>
      </div>
    </div>
  </div>

  <!-- ══ DOMAINS PAGE ═══════════════════════════════════════════════════════ -->
  <div class="page" id="page-domains">
    <div class="page-header">
      <h1>🗺️ Trust Domain Detail</h1>
      <p>Current state, gaps, and target state for each of the 8 external identity architectural domains.</p>
    </div>
    <div id="domainDetailList"></div>
  </div>

  <!-- ══ FINDINGS PAGE ══════════════════════════════════════════════════════ -->
  <div class="page" id="page-findings">
    <div class="page-header">
      <h1>🔎 Assessment Findings</h1>
      <p>All findings from the B2B trust assessment, prioritised by risk and business impact. Click any row to view details.</p>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input id="findSearch" type="text" placeholder="Search findings, domains, check IDs…" oninput="filterFindings()">
        </div>
        <div class="filter-pills">
          <span class="fpill fpill-all active"    onclick="setRiskFilter('all',this)">All</span>
          <span class="fpill fpill-crit"           onclick="setRiskFilter('Critical',this)">🔴 Critical</span>
          <span class="fpill fpill-high"           onclick="setRiskFilter('High',this)">🟠 High</span>
          <span class="fpill fpill-medium"         onclick="setRiskFilter('Medium',this)">🔵 Medium</span>
          <span class="fpill fpill-low"            onclick="setRiskFilter('Low',this)">🟢 Low/Info</span>
        </div>
      </div>
      <div style="overflow-x:auto">
        <table id="findingsTable">
          <thead>
            <tr>
              <th onclick="sortFindings('checkId')">Check <span class="sort-arrow">↕</span></th>
              <th onclick="sortFindings('title')">Finding <span class="sort-arrow">↕</span></th>
              <th onclick="sortFindings('risk')">Risk <span class="sort-arrow">↕</span></th>
              <th onclick="sortFindings('domainName')">Domain <span class="sort-arrow">↕</span></th>
              <th onclick="sortFindings('roadmapPhase')">Phase <span class="sort-arrow">↕</span></th>
            </tr>
          </thead>
          <tbody id="findingsBody"></tbody>
        </table>
      </div>
      <div class="pagination" id="findingsPagination"></div>
      <div class="pg-info" id="findingsInfo"></div>
    </div>
  </div>

  <!-- ══ ROADMAP PAGE ════════════════════════════════════════════════════════ -->
  <div class="page" id="page-roadmap">
    <div class="page-header">
      <h1>📅 Remediation Roadmap</h1>
      <p>Prioritised remediation plan organised by time horizon. Start with 0–30 Day actions to address the highest-risk gaps.</p>
    </div>
    <div class="roadmap-grid" id="roadmapGrid"></div>
  </div>

</div>

<!-- Detail Drawer -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDrawer()"></div>
  <div id="detailDrawer">
    <div class="drawer-header">
      <div class="drawer-title" id="drawerTitle"></div>
      <button class="drawer-close" onclick="closeDrawer()">✕</button>
    </div>
    <div class="drawer-chips" id="drawerChips"></div>
    <div class="drawer-section">
      <div class="drawer-label">Evidence</div>
      <div class="drawer-value" id="drawerEvidence"></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-label">Current State</div>
      <div class="drawer-value" id="drawerCurrentState"></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-label">Gap &amp; Risk</div>
      <div class="drawer-value" id="drawerGap"></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-label">Business Impact</div>
      <div class="drawer-value" id="drawerBusinessImpact"></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-label">Target State</div>
      <div class="drawer-value" id="drawerTargetState"></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-label">Recommendation</div>
      <div class="drawer-value" id="drawerRecommendation"></div>
    </div>
    <div class="drawer-nav">
      <button onclick="navDrawer(-1)">← Previous</button>
      <button onclick="navDrawer(1)">Next →</button>
      <span class="drawer-count" id="drawerCount"></span>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
// ── Data ──────────────────────────────────────────────────────────────────────
const DOMAINS   = __DOMAINS_JSON__;
const FINDINGS  = __FINDINGS_JSON__;

// ── Escape helpers ────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

// ── Theme ─────────────────────────────────────────────────────────────────────
function setTheme(t){
  document.body.classList.toggle('light-theme',t==='light');
  document.getElementById('thDark').classList.toggle('active',t==='dark');
  document.getElementById('thLight').classList.toggle('active',t==='light');
}

// ── Navigation ────────────────────────────────────────────────────────────────
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn) btn.classList.add('active');
  if(id==='roadmap') renderRoadmap();
  if(id==='domains') renderDomainDetail();
  if(id==='overview') renderOverview();
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Overview ──────────────────────────────────────────────────────────────────
function renderOverview(){
  renderDomainCards('overviewDomainGrid');
  renderRiskBars();
  renderMaturityBars();
}

function renderDomainCards(containerId){
  const c=document.getElementById(containerId);
  if(c.innerHTML) return;
  DOMAINS.forEach(d=>{
    const pct=Math.round((d.maturityScore/5)*100);
    c.innerHTML+=`<div class="domain-card" style="border-left-color:${escH(d.maturityColor)}" onclick="showDomainFindingsFromCard('${escH(d.id)}')">
      <div class="domain-card-header">
        <span class="domain-icon">${escH(d.icon)}</span>
        <span class="domain-name">${escH(d.name)}</span>
        <span class="maturity-badge" style="color:${escH(d.maturityColor)}">${escH(d.maturityLabel)}</span>
      </div>
      <div class="domain-score-bar">
        <div class="domain-score-fill" style="width:${pct}%;background:${escH(d.maturityColor)}"></div>
      </div>
      <div class="domain-risk-chips">
        ${d.critical>0?`<span class="risk-chip rc-critical">🔴 ${d.critical}C</span>`:''}
        ${d.high>0?`<span class="risk-chip rc-high">🟠 ${d.high}H</span>`:''}
        ${d.medium>0?`<span class="risk-chip rc-medium">🔵 ${d.medium}M</span>`:''}
        ${d.low>0?`<span class="risk-chip rc-low">🟢 ${d.low}L</span>`:''}
      </div>
    </div>`;
  });
}

function showDomainFindingsFromCard(domainId){
  showPage('findings', document.querySelector('.nav-btn:nth-child(3)'));
  currentRiskFilter='all';
  document.querySelectorAll('.fpill').forEach(p=>p.classList.remove('active'));
  document.querySelector('.fpill-all').classList.add('active');
  document.getElementById('findSearch').value='D'+domainId.replace('D','')+'.';
  filterFindings();
}

function renderRiskBars(){
  const c=document.getElementById('riskBars');
  if(c.innerHTML) return;
  const counts={Critical:0,High:0,Medium:0,Low:0,Info:0};
  FINDINGS.forEach(f=>{ if(counts[f.risk]!==undefined) counts[f.risk]++; });
  const total=FINDINGS.length||1;
  const cols={Critical:'var(--red)',High:'var(--amber)',Medium:'var(--accent)',Low:'var(--green)',Info:'var(--muted)'};
  Object.entries(counts).forEach(([k,v])=>{
    const pct=Math.round((v/total)*100);
    c.innerHTML+=`<div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px">
        <span style="color:${cols[k]}">${escH(k)}</span>
        <span style="color:var(--muted);font-family:var(--mono)">${v} (${pct}%)</span>
      </div>
      <div class="bar-track" style="height:6px;background:var(--surface3);border-radius:3px">
        <div class="bar-fill" style="height:100%;width:0%;background:${cols[k]};border-radius:3px;transition:width 1s ease" data-pct="${pct}"></div>
      </div>
    </div>`;
  });
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill').forEach(b=>{b.style.width=b.dataset.pct+'%';});
  });
}

function renderMaturityBars(){
  const c=document.getElementById('maturityBars');
  if(c.innerHTML) return;
  DOMAINS.forEach(d=>{
    const pct=Math.round((d.maturityScore/5)*100);
    c.innerHTML+=`<div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px">
        <span>${escH(d.icon)} ${escH(d.name)}</span>
        <span style="color:${escH(d.maturityColor)};font-family:var(--mono)">${d.maturityScore}/5 ${escH(d.maturityLabel)}</span>
      </div>
      <div style="height:6px;background:var(--surface3);border-radius:3px">
        <div class="bar-fill" style="height:100%;width:0%;background:${escH(d.maturityColor)};border-radius:3px;transition:width 1s ease" data-pct="${pct}"></div>
      </div>
    </div>`;
  });
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill').forEach(b=>{b.style.width=b.dataset.pct+'%';});
  });
}

// ── Domain Detail ──────────────────────────────────────────────────────────────
function renderDomainDetail(){
  const c=document.getElementById('domainDetailList');
  if(c.innerHTML) return;
  DOMAINS.forEach(d=>{
    const domFindings=FINDINGS.filter(f=>f.domainId===d.id&&f.risk!=='Info');
    const dominated = FINDINGS.filter(f=>f.domainId===d.id);
    c.innerHTML+=`<div class="panel" style="border-left:4px solid ${escH(d.maturityColor)}">
      <div class="panel-header">
        <span class="panel-title">${escH(d.icon)} ${escH(d.id)}: ${escH(d.name)}</span>
        <span class="maturity-badge" style="color:${escH(d.maturityColor)};background:rgba(0,0,0,.2);padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700">${d.maturityScore}/5 — ${escH(d.maturityLabel)}</span>
      </div>
      <div class="chart-grid" style="margin-bottom:12px">
        <div>
          <div class="drawer-label" style="margin-bottom:6px">Current State</div>
          <div class="drawer-value">${escH(d.currentStateSummary)}</div>
        </div>
        <div>
          <div class="drawer-label" style="margin-bottom:6px">Target State</div>
          <div class="drawer-value" style="border-color:${escH(d.maturityColor)}">${escH(d.targetStateSummary)}</div>
        </div>
      </div>
      <div style="font-size:11px;color:var(--muted);margin-bottom:8px">${dominated.length} finding(s) | ${domFindings.filter(f=>f.risk==='Critical').length} Critical &bull; ${domFindings.filter(f=>f.risk==='High').length} High &bull; ${domFindings.filter(f=>f.risk==='Medium').length} Medium</div>
      ${domFindings.length>0?`<div style="display:flex;flex-wrap:wrap;gap:6px">${domFindings.slice(0,5).map((f,i)=>{
        const idx=FINDINGS.indexOf(f);
        return `<span onclick="openFinding(${idx})" style="cursor:pointer;font-size:11px;padding:4px 10px;border-radius:20px;background:rgba(0,0,0,.2);border:1px solid var(--border);color:var(--muted2)">${escH(f.checkId)}: ${escH(f.title.substring(0,50))}${f.title.length>50?'…':''}</span>`;
      }).join('')}${domFindings.length>5?`<span style="font-size:11px;color:var(--muted);align-self:center">+${domFindings.length-5} more</span>`:''}
      </div>`:''}</div>`;
  });
}

// ── Findings Table ────────────────────────────────────────────────────────────
let filteredFindings=[...FINDINGS];
let currentRiskFilter='all';
let currentSort={col:'',dir:1};
let currentPage=1;
const PAGE_SIZE=15;

function setRiskFilter(risk,el){
  currentRiskFilter=risk;
  document.querySelectorAll('.fpill').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  currentPage=1;
  filterFindings();
}

function filterFindings(){
  const q=(document.getElementById('findSearch').value||'').toLowerCase();
  filteredFindings=FINDINGS.filter(f=>{
    const riskMatch = currentRiskFilter==='all'
      ? true
      : currentRiskFilter==='Low'
        ? f.risk==='Low'||f.risk==='Info'
        : f.risk===currentRiskFilter;
    const textMatch = !q || [f.checkId,f.title,f.domainName,f.evidence,f.recommendation].some(v=>String(v||'').toLowerCase().includes(q));
    return riskMatch && textMatch;
  });
  if(currentSort.col) filteredFindings.sort((a,b)=>String(a[currentSort.col]||'').localeCompare(String(b[currentSort.col]||''))*currentSort.dir);
  renderFindingsPage();
}

function sortFindings(col){
  currentSort.dir = currentSort.col===col ? -currentSort.dir : 1;
  currentSort.col = col;
  filterFindings();
}

function renderFindingsPage(){
  const body=document.getElementById('findingsBody');
  const start=(currentPage-1)*PAGE_SIZE;
  const slice=filteredFindings.slice(start,start+PAGE_SIZE);
  body.innerHTML=slice.map((f,i)=>{
    const idx=FINDINGS.indexOf(f);
    return `<tr onclick="openFinding(${idx})" style="cursor:pointer">
      <td><span class="domain-tag">${escH(f.checkId)}</span></td>
      <td style="max-width:320px">${escH(f.title)}</td>
      <td><span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span></td>
      <td style="color:var(--muted2)">${escH(f.domainName)}</td>
      <td><span class="phase-badge">${escH(f.roadmapPhase)}</span></td>
    </tr>`;
  }).join('');
  renderPagination();
  document.getElementById('findingsInfo').textContent=`Showing ${start+1}–${Math.min(start+PAGE_SIZE,filteredFindings.length)} of ${filteredFindings.length} finding(s)`;
}

function renderPagination(){
  const total=Math.ceil(filteredFindings.length/PAGE_SIZE);
  const pg=document.getElementById('findingsPagination');
  pg.innerHTML='';
  if(total<=1) return;
  const addBtn=(label,page,active)=>{
    const b=document.createElement('button');
    b.className='pg-btn'+(active?' active':'');
    b.textContent=label;
    b.onclick=()=>{currentPage=page;renderFindingsPage();};
    pg.appendChild(b);
  };
  if(currentPage>1) addBtn('←',currentPage-1,false);
  for(let i=1;i<=total;i++){
    if(i===1||i===total||Math.abs(i-currentPage)<=1) addBtn(i,i,i===currentPage);
    else if(Math.abs(i-currentPage)===2){const s=document.createElement('span');s.textContent='…';s.style.cssText='padding:0 4px;color:var(--muted)';pg.appendChild(s);}
  }
  if(currentPage<total) addBtn('→',currentPage+1,false);
}

// ── Detail Drawer ──────────────────────────────────────────────────────────────
let drawerList=[];
let currentDrawerIndex=0;

function openFinding(idx){
  drawerList=filteredFindings;
  const f=FINDINGS[idx];
  currentDrawerIndex=drawerList.indexOf(f);
  if(currentDrawerIndex===-1){drawerList=[...FINDINGS];currentDrawerIndex=idx;}
  populateDrawer(f);
  document.getElementById('detailPanel').classList.add('open');
}

function populateDrawer(f){
  document.getElementById('drawerTitle').textContent=f.title;
  document.getElementById('drawerEvidence').textContent=f.evidence;
  document.getElementById('drawerCurrentState').textContent=f.currentState;
  document.getElementById('drawerGap').textContent=f.gap;
  document.getElementById('drawerBusinessImpact').textContent=f.businessImpact;
  document.getElementById('drawerTargetState').textContent=f.targetState;
  document.getElementById('drawerRecommendation').textContent=f.recommendation;
  document.getElementById('drawerChips').innerHTML=`
    <span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span>
    <span class="domain-tag">${escH(f.checkId)}</span>
    <span class="domain-tag" style="background:rgba(163,113,247,.12);color:var(--accent3)">${escH(f.domainName)}</span>
    <span class="phase-badge">${escH(f.roadmapPhase)}</span>`;
  document.getElementById('drawerCount').textContent=`${currentDrawerIndex+1} / ${drawerList.length}`;
}

function navDrawer(dir){
  const next=currentDrawerIndex+dir;
  if(next<0||next>=drawerList.length) return;
  currentDrawerIndex=next;
  populateDrawer(drawerList[currentDrawerIndex]);
}
function closeDrawer(){document.getElementById('detailPanel').classList.remove('open');}

// ── Roadmap ────────────────────────────────────────────────────────────────────
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

// ── CSV Export ─────────────────────────────────────────────────────────────────
function exportFindingsCSV(){
  const fields=['domainId','domainName','checkId','title','risk','roadmapPhase','evidence','currentState','gap','businessImpact','targetState','recommendation'];
  const header=fields.join(',');
  const rows=filteredFindings.map(f=>fields.map(k=>'"'+(String(f[k]||'')).replace(/"/g,'""')+'"').join(','));
  const csv=[header,...rows].join('\r\n');
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download='B2BTrustAssessmentFindings.csv';
  a.click();
  showToast('Findings exported as CSV ✓');
}

// ── Keyboard shortcuts ──────────────────────────────────────────────────────────
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

// ── Initial render ──────────────────────────────────────────────────────────────
renderOverview();
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
            -replace '__TOTAL_LOW__', ($totalLow + $totalInfo) `
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
            assessmentTool   = "Get-EntraExternalIdentityTrustAssessment"
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

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   Entra External Identity Trust Assessment  v1.0             ║" -ForegroundColor Cyan
    Write-Host "  ║   B2B & Guest Identity Architecture Review                   ║" -ForegroundColor Cyan
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

    # ── Step 1: Authentication ─────────────────────────────────────────────────
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

    # ── Step 1.1: Validate Permissions ────────────────────────────────────────
    Write-Host "  🔍 Validating required Microsoft Graph permissions..." -ForegroundColor Yellow

    $requiredGraphPermissions = @(
        "Directory.Read.All"
        "Policy.Read.All"
        "EntitlementManagement.Read.All"
        "AuditLog.Read.All"
        "RoleManagement.Read.Directory"
        "Reports.Read.All"
        "AccessReview.Read.All"
        "Application.Read.All"
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
        Write-Host "  Some findings may reflect insufficient data rather than a secure state." -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host "  ✅ All required Microsoft Graph permissions validated." -ForegroundColor Green
    }

    Write-Host ""

    # ── Step 2: Collect Tenant Baseline ────────────────────────────────────────
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

    # ── Step 3: Domain Assessments ─────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 3  ›  Running Domain Assessments (8 Domains)         │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    # Shared variables needed across domains — pre-populate
    $partnerCount = 0
    $b2bInboundAllowAll = $false
    $xTenantPartners = @()

    $xTenantDefault = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/default"
    $xTenantPartners = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners"
    $partnerCount = if ($xTenantPartners) { $xTenantPartners.Count } else { 0 }

    if ($xTenantDefault) {
        $b2bInboundAllowAll = ($xTenantDefault.b2bCollaborationInbound -and
            $xTenantDefault.b2bCollaborationInbound.usersAndGroups.accessType -eq "allowed")
    }

    Invoke-Domain1-TrustBoundary
    Invoke-Domain2-InvitationGovernance
    Invoke-Domain3-GuestLifecycle
    Invoke-Domain4-B2BConditionalAccess
    Invoke-Domain5-EntitlementManagement
    Invoke-Domain6-SensitiveResourceExposure
    Invoke-Domain7-GuestOwnership
    Invoke-Domain8-ExternalMonitoring

    Write-Host ""
    Write-Host "  ✅ All 8 domain assessments complete." -ForegroundColor Green
    Write-Host ""

    # ── Step 4: Score ──────────────────────────────────────────────────────────
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

    # ── Step 5: Export ─────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 5  ›  Generating Reports                             │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $htmlPath = Join-Path $OutputPath "EntraExternalIdentityTrustAssessment_$timestamp.html"
    $jsonPath = Join-Path $OutputPath "EntraExternalIdentityTrustAssessment_$timestamp.json"
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

    # ── Execution Summary ──────────────────────────────────────────────────────
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
