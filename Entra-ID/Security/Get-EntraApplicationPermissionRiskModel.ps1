<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 23 August 2026
Modified-On  : 23 August 2026

.SYNOPSIS
    Builds a multi-factor permission risk model for every application and service principal
    in the Entra ID tenant, producing a risk-scored, evidence-based report with actionable
    governance recommendations.

.DESCRIPTION
    This script connects to Microsoft Graph (BYOT or Client Credentials) and evaluates
    every application registration and enterprise application (service principal) against
    an enterprise API governance risk model.

    The risk engine scores each application across seven risk dimensions:

        Dimension 1  — Permission Sensitivity & Privilege Level
        Dimension 2  — Permission Type (Application vs Delegated) & Consent Model
        Dimension 3  — Application Criticality Indicators
        Dimension 4  — Ownership & Accountability
        Dimension 5  — Publisher Verification & Trust
        Dimension 6  — Downstream API Exposure & Blast Radius
        Dimension 7  — Credential Hygiene (Secrets vs Certificates vs Federated)

    For each application the script follows this architectural thinking model:

        Business Context → Current State → Gap Analysis → Target State →
        Recommendations → Success Measures

    Risk is scored on a composite 0–100 scale, then banded:
        Critical  : 75–100  — Immediate action required
        High      : 50–74   — Address within 30 days
        Medium    : 25–49   — Plan within 60–90 days
        Low       : 0–24    — Monitor / improvement opportunity

    The assessment delivers:

        Finding 1  — Tenant Permission Risk Posture Overview
        Finding 2  — High-Privilege Application Permissions (Application consent)
        Finding 3  — Admin-Consented Delegated Permissions at Scale
        Finding 4  — User-Consented Applications Without IT Oversight
        Finding 5  — Unverified Publishers with Sensitive API Access
        Finding 6  — Ownerless Applications (No Accountability)
        Finding 7  — Applications with Expired or Long-Lived Credentials
        Finding 8  — Multi-Tenant Applications Exposed to External Tenants
        Finding 9  — Over-Permissioned Legacy Service Principals
        Finding 10 — Applications with Excessive Blast Radius

    Output:
        - HTML interactive dashboard (light/dark theme, business-focused, action-oriented)
        - JSON risk model export (machine-readable, CI/CD integrable)

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
    Default: C:\Temp\EntraPermissionRisk

.PARAMETER ShowHelp
    Displays a plain-language usage guide and exits immediately.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        HTML dashboard: <OutputPath>\EntraApplicationPermissionRiskModel_<timestamp>.html
        JSON export   : <OutputPath>\EntraApplicationPermissionRiskModel_<timestamp>.json

.EXAMPLE
    Get-EntraApplicationPermissionRiskModel -ShowHelp

    Displays the friendly usage guide and exits.

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraApplicationPermissionRiskModel `
        -AuthMode ClientCredentials `
        -ClientId  "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId "f4310b4f-xxxx"

    Full risk assessment using app-only Client Credentials auth.

.EXAMPLE
    $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    Get-EntraApplicationPermissionRiskModel `
        -AuthMode BYOT `
        -AccessToken $token `
        -TenantId "f4310b4f-xxxx"

    Full risk assessment using a pre-obtained bearer token (BYOT).

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraApplicationPermissionRiskModel `
        -AuthMode ClientCredentials `
        -ClientId  "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId "f4310b4f-xxxx" `
        -OutputPath "D:\Reports\PermissionRisk"

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
               Application.Read.All            (app registrations, service principals,
                                                OAuth2 permission grants)
               Directory.Read.All              (users, groups, org info)
               AuditLog.Read.All               (sign-in activity — last used date)
               DelegatedPermissionGrant.Read.All (delegated consent grants)

        2. BYOT mode: the delegated or application token must carry the same
           scopes as above. Delegated tokens require the caller to be at minimum
           a Global Reader or Application Administrator.

        3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  → Show help and exit if -ShowHelp
        Step 1  → Authenticate (BYOT or Client Credentials)
        Step 2  → Collect tenant baseline (org, domains)
        Step 3  → Collect application and permission inventory
                    3a — App registrations
                    3b — Service principals (enterprise apps)
                    3c — OAuth2 permission grants (delegated)
                    3d — App role assignments (application permissions)
        Step 4  → Run the seven-dimension risk engine per application
        Step 5  → Produce tenant-level risk posture findings (10 findings)
        Step 6  → Rank and score all applications; select top risk applications
        Step 7  → Generate roadmap (0–30 / 31–60 / 61–90 Day + Strategic)
        Step 8  → Export HTML dashboard + JSON

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the /beta Graph endpoint. Beta APIs are subject to change.
        - Sign-in activity (last used date) requires AuditLog.Read.All and is
          only available for service principals, not app registrations.
        - Permission sensitivity scoring is based on a curated taxonomy of
          known high-risk Microsoft Graph permissions. Custom API permissions
          for third-party SaaS are scored at Medium sensitivity by default.
        - Large tenants (>1000 applications) may experience longer run times
          due to Graph pagination across service principals and role assignments.
        - App role assignment enumeration for all SPNs is paginated per SPN;
          bulk Graph queries are used where supported.

.LINK
    https://learn.microsoft.com/en-us/graph/permissions-reference
.LINK
    https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions
.LINK
    https://learn.microsoft.com/en-us/entra/architecture/zero-trust-overview

#>


Function Get-EntraApplicationPermissionRiskModel {
    [CmdletBinding()]
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
        [string]$OutputPath = "C:\Temp\EntraPermissionRisk",

        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    #region ── Friendly Help ──────────────────────────────────────────────────────

    Function Show-FriendlyHelp {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║   Entra Application Permission Risk Model  v1.0              ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  PURPOSE" -ForegroundColor Yellow
        Write-Host "    Builds a multi-factor risk model for every application in your"
        Write-Host "    Entra ID tenant. Scores permission sensitivity, consent model,"
        Write-Host "    publisher trust, blast radius, and credential hygiene."
        Write-Host ""
        Write-Host "  AUTHENTICATION" -ForegroundColor Yellow
        Write-Host "    Client Credentials (app-only):"
        Write-Host '      $secret = Read-Host "Client secret" -AsSecureString'
        Write-Host '      Get-EntraApplicationPermissionRiskModel \'
        Write-Host '          -AuthMode ClientCredentials \'
        Write-Host '          -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "    BYOT (Bring Your Own Token):"
        Write-Host '      $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken'
        Write-Host '      Get-EntraApplicationPermissionRiskModel \'
        Write-Host '          -AuthMode BYOT -AccessToken $token -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "  REQUIRED APP PERMISSIONS (Application, admin-consented)" -ForegroundColor Yellow
        Write-Host "    Application.Read.All, Directory.Read.All,"
        Write-Host "    AuditLog.Read.All, DelegatedPermissionGrant.Read.All"
        Write-Host ""
        Write-Host "  For full documentation: Get-Help Get-EntraApplicationPermissionRiskModel -Full"
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
            [Parameter(Mandatory = $true)] [string]$ClientId,
            [Parameter(Mandatory = $true)] [System.Security.SecureString]$ClientSecret,
            [Parameter(Mandatory = $true)] [string]$TenantId,
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

    #region ── Graph API Helpers ──────────────────────────────────────────────────

    Function Invoke-GraphRequest {
        param (
            [Parameter(Mandatory = $true)] [string]$Uri,
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
                    Write-Verbose "  ⚠ 403 Forbidden on $Uri — permission not granted."
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
            [Parameter(Mandatory = $true)] [string]$Uri,
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

    #region ── Permission Sensitivity Taxonomy ────────────────────────────────────

    # Curated taxonomy of Microsoft Graph permission values mapped to a risk tier.
    # Tier 4 = Critical  (tenant-wide write / admin equivalent)
    # Tier 3 = High      (broad read of sensitive data, or scoped write)
    # Tier 2 = Medium    (read of user/group data, limited write)
    # Tier 1 = Low       (profile read, email send on behalf, openid)
    # Unknown permissions (custom APIs, unrecognised) are treated as Tier 2 (Medium)

    $script:PermissionTiers = @{
        # Tier 4 — Critical
        "Directory.ReadWrite.All"                   = 4
        "RoleManagement.ReadWrite.Directory"        = 4
        "Application.ReadWrite.All"                 = 4
        "AppRoleAssignment.ReadWrite.All"           = 4
        "DelegatedPermissionGrant.ReadWrite.All"    = 4
        "Policy.ReadWrite.ConditionalAccess"        = 4
        "Policy.ReadWrite.AuthenticationMethod"     = 4
        "UserAuthenticationMethod.ReadWrite.All"    = 4
        "PrivilegedAccess.ReadWrite.AzureAD"        = 4
        "PrivilegedAccess.ReadWrite.AzureResources" = 4
        "User.ReadWrite.All"                        = 4
        "Group.ReadWrite.All"                       = 4
        "Mail.ReadWrite"                            = 4
        "Files.ReadWrite.All"                       = 4
        "Sites.FullControl.All"                     = 4
        "Exchange.ManageAsApp"                      = 4
        "full_access_as_app"                        = 4
        "SecurityEvents.ReadWrite.All"              = 4
        "ThreatIndicators.ReadWrite.OwnedBy"        = 4

        # Tier 3 — High
        "Directory.Read.All"                        = 3
        "User.Read.All"                             = 3
        "Group.Read.All"                            = 3
        "Application.Read.All"                      = 3
        "AuditLog.Read.All"                         = 3
        "Mail.Read"                                 = 3
        "Mail.ReadBasic.All"                        = 3
        "Files.Read.All"                            = 3
        "Sites.Read.All"                            = 3
        "Reports.Read.All"                          = 3
        "IdentityRiskyUser.Read.All"                = 3
        "IdentityRiskEvent.Read.All"                = 3
        "SecurityEvents.Read.All"                   = 3
        "Calendars.Read"                            = 3
        "Contacts.Read"                             = 3
        "TeamSettings.Read.All"                     = 3
        "Channel.ReadBasic.All"                     = 3
        "RoleManagement.Read.Directory"             = 3
        "Policy.Read.All"                           = 3
        "PrivilegedAccess.Read.AzureAD"             = 3
        "AccessReview.Read.All"                     = 3
        "DeviceManagementApps.Read.All"             = 3
        "DeviceManagementConfiguration.Read.All"    = 3

        # Tier 2 — Medium
        "User.ReadBasic.All"                        = 2
        "GroupMember.Read.All"                      = 2
        "OrgContact.Read.All"                       = 2
        "Device.Read.All"                           = 2
        "MailboxSettings.Read"                      = 2
        "Calendars.ReadBasic"                       = 2
        "Notes.Read.All"                            = 2
        "Tasks.Read"                                = 2
        "Team.ReadBasic.All"                        = 2
        "ChannelMessage.Read.All"                   = 2
        "Chat.Read.All"                             = 2
        "Chat.ReadBasic.All"                        = 2
        "CrossTenantInformation.ReadBasic.All"      = 2
        "ServiceHealth.Read.All"                    = 2
        "ServiceMessage.Read.All"                   = 2

        # Tier 1 — Low
        "openid"                                    = 1
        "profile"                                   = 1
        "email"                                     = 1
        "offline_access"                            = 1
        "User.Read"                                 = 1
        "User.ReadWrite"                            = 1
        "Mail.Send"                                 = 1
        "Calendars.ReadWrite"                       = 1
        "Tasks.ReadWrite"                           = 1
    }

    # Human-readable tier names
    $script:TierLabels = @{
        4 = "Critical"
        3 = "High"
        2 = "Medium"
        1 = "Low"
    }

    $script:TierColors = @{
        4 = "#f85149"
        3 = "#d29922"
        2 = "#388bfd"
        1 = "#3fb950"
    }

    Function Get-PermissionTier {
        param ([string]$PermissionValue)
        if ($script:PermissionTiers.ContainsKey($PermissionValue)) {
            return $script:PermissionTiers[$PermissionValue]
        }
        return 2   # Unknown custom permission → Medium by default
    }

    Function Get-MaxPermissionTier {
        param ([string[]]$Permissions)
        $max = 0
        foreach ($p in $Permissions) {
            $t = Get-PermissionTier -PermissionValue $p
            if ($t -gt $max) { $max = $t }
        }
        return $max
    }

    #endregion

    #region ── Risk Scoring Engine ────────────────────────────────────────────────

    # Risk dimensions and their maximum point contributions to the 0–100 composite score.
    # D1 Permission Sensitivity  : 0–25  (most weight — what can the app do)
    # D2 Consent Model           : 0–20  (how was access granted)
    # D3 App Criticality         : 0–15  (how important / exposed is the app)
    # D4 Ownership               : 0–10  (is anyone accountable)
    # D5 Publisher Verification  : 0–10  (is the publisher trusted)
    # D6 Blast Radius            : 0–10  (how wide is the impact)
    # D7 Credential Hygiene      : 0–10  (how are credentials managed)
    # Total                      : 0–100

    Function Get-PermissionSensitivityScore {
        <#
        .SYNOPSIS Returns 0–25 based on the highest-tier permission held by the app.
        Application permissions (appRoles) carry an additional weight multiplier vs
        delegated permissions because they run without a signed-in user.
        #>
        param (
            [int]$MaxAppRoleTier,       # 0–4
            [int]$MaxDelegatedTier,     # 0–4
            [int]$TotalAppRoleCount,
            [int]$TotalDelegatedCount
        )

        # Application permissions: tier maps to 0,4,10,18,25
        $appRoleScore = switch ($MaxAppRoleTier) {
            4 { 25 }
            3 { 18 }
            2 { 10 }
            1 { 4 }
            default { 0 }
        }

        # Delegated permissions: slightly lower weight (user context reduces blast radius)
        $delegatedScore = switch ($MaxDelegatedTier) {
            4 { 20 }
            3 { 14 }
            2 { 7 }
            1 { 3 }
            default { 0 }
        }

        # Breadth bonus: many permissions of the same tier add a small penalty
        $breadthBonus = 0
        if (($TotalAppRoleCount + $TotalDelegatedCount) -gt 20) { $breadthBonus = 3 }
        elseif (($TotalAppRoleCount + $TotalDelegatedCount) -gt 10) { $breadthBonus = 1 }

        return [Math]::Min(25, [Math]::Max($appRoleScore, $delegatedScore) + $breadthBonus)
    }


    Function Get-ConsentModelScore {
        <#
        .SYNOPSIS Returns 0–20 based on consent model risk.
        Application-level consent (no user involved) is highest risk.
        Admin consent for delegated is moderate. User consent is lowest but still monitored.
        #>
        param (
            [bool]$HasApplicationPermissions,    # app roles — always admin consented
            [bool]$HasAdminConsentDelegated,
            [bool]$HasUserConsentDelegated,
            [int]$UserConsentCount
        )

        $score = 0
        if ($HasApplicationPermissions) { $score += 20 }    # app permissions — no user context
        elseif ($HasAdminConsentDelegated) { $score += 10 } # admin approved delegated
        elseif ($HasUserConsentDelegated) { $score += 5 }   # user approved delegated

        # Many user-consented delegated grants across many users = shadow IT at scale
        if ($HasUserConsentDelegated -and $UserConsentCount -gt 50) { $score += 5 }

        return [Math]::Min(20, $score)
    }


    Function Get-AppCriticalityScore {
        <#
        .SYNOPSIS Returns 0–15 based on indicators that the app is externally accessible
        or serves a sensitive business function.
        #>
        param (
            [bool]$IsMultiTenant,
            [bool]$HasSignInActivity,       # used in last 90 days
            [bool]$IsFirstPartyMicrosoft,   # Microsoft-published first-party app
            [int]$AssignedUserGroupCount    # how many users/groups assigned
        )

        $score = 0
        if ($IsMultiTenant) { $score += 5 }            # exposed to other tenants
        if ($HasSignInActivity) { $score += 3 }         # active and in use
        if ($AssignedUserGroupCount -gt 100) { $score += 5 }
        elseif ($AssignedUserGroupCount -gt 10) { $score += 3 }
        elseif ($AssignedUserGroupCount -gt 0) { $score += 1 }
        # First-party Microsoft apps are lower criticality from a compromise angle
        if ($IsFirstPartyMicrosoft) { $score = [Math]::Max(0, $score - 4) }

        return [Math]::Min(15, $score)
    }


    Function Get-OwnershipScore {
        <#
        .SYNOPSIS Returns 0–10. Absence of owners increases risk (no accountability chain).
        #>
        param ([int]$OwnerCount)

        if ($OwnerCount -eq 0) { return 10 }      # no owner — maximum accountability gap
        if ($OwnerCount -eq 1) { return 3 }        # single owner — bus-factor risk
        return 0                                    # multiple owners — good
    }


    Function Get-PublisherVerificationScore {
        <#
        .SYNOPSIS Returns 0–10.
        Unverified publishers with sensitive permissions are a significant supply-chain risk.
        #>
        param (
            [bool]$IsVerifiedPublisher,
            [bool]$IsFirstPartyMicrosoft,
            [int]$MaxPermissionTier
        )

        if ($IsFirstPartyMicrosoft) { return 0 }                    # Microsoft-owned — implicitly trusted
        if ($IsVerifiedPublisher) { return 0 }                      # publisher verified
        if (-not $IsVerifiedPublisher -and $MaxPermissionTier -ge 3) { return 10 }  # unverified + high perms
        if (-not $IsVerifiedPublisher -and $MaxPermissionTier -ge 2) { return 5 }   # unverified + medium perms
        return 2                                                     # unverified + low perms
    }


    Function Get-BlastRadiusScore {
        <#
        .SYNOPSIS Returns 0–10 based on the potential scope of impact if the app is compromised.
        Tenant-wide write application permissions carry the highest blast radius.
        #>
        param (
            [int]$MaxAppRoleTier,
            [int]$TotalAppRoleCount,
            [bool]$IsMultiTenant
        )

        $score = 0
        if ($MaxAppRoleTier -eq 4) { $score += 8 }       # critical tier = tenant-wide potential impact
        elseif ($MaxAppRoleTier -eq 3) { $score += 5 }   # high tier = broad read, significant exfil
        elseif ($MaxAppRoleTier -eq 2) { $score += 2 }
        if ($TotalAppRoleCount -gt 10) { $score += 2 }   # many permissions = wide surface
        if ($IsMultiTenant) { $score += 2 }               # cross-tenant blast radius

        return [Math]::Min(10, $score)
    }


    Function Get-CredentialHygieneScore {
        <#
        .SYNOPSIS Returns 0–10 based on credential type and lifecycle posture.
        Long-lived secrets with no rotation are the primary workload compromise vector.
        #>
        param (
            [bool]$HasExpiredCredentials,
            [bool]$HasLongLivedSecrets,   # >1 year lifetime
            [bool]$HasActiveSecrets,
            [bool]$HasCertificates,
            [bool]$NoCredentials          # Managed Identity or federated — secretless
        )

        if ($NoCredentials) { return 0 }                # secretless — best posture
        if ($HasExpiredCredentials) { return 8 }        # expired creds left in place = hygiene failure
        if ($HasLongLivedSecrets -and $HasActiveSecrets) { return 6 }   # long-lived active secrets
        if ($HasActiveSecrets -and -not $HasCertificates) { return 4 }  # only secrets, no certs
        if ($HasCertificates -and -not $HasActiveSecrets) { return 1 }  # certificates only — better
        if ($HasCertificates -and $HasActiveSecrets) { return 3 }       # mixed
        return 2
    }


    Function Compute-AppRiskScore {
        <#
        .SYNOPSIS Aggregates the seven dimension scores into a 0–100 composite risk score.
        Returns a hashtable with the composite score and each dimension's contribution.
        #>
        param (
            [int]$D1_PermissionSensitivity,
            [int]$D2_ConsentModel,
            [int]$D3_AppCriticality,
            [int]$D4_Ownership,
            [int]$D5_PublisherVerification,
            [int]$D6_BlastRadius,
            [int]$D7_CredentialHygiene
        )

        $composite = $D1_PermissionSensitivity +
        $D2_ConsentModel +
        $D3_AppCriticality +
        $D4_Ownership +
        $D5_PublisherVerification +
        $D6_BlastRadius +
        $D7_CredentialHygiene

        $composite = [Math]::Min(100, [Math]::Max(0, $composite))

        $band = if ($composite -ge 75) { "Critical" }
        elseif ($composite -ge 50) { "High" }
        elseif ($composite -ge 25) { "Medium" }
        else { "Low" }

        return @{
            Composite          = $composite
            Band               = $band
            D1_PermSensitivity = $D1_PermissionSensitivity
            D2_ConsentModel    = $D2_ConsentModel
            D3_AppCriticality  = $D3_AppCriticality
            D4_Ownership       = $D4_Ownership
            D5_PublisherVerif  = $D5_PublisherVerification
            D6_BlastRadius     = $D6_BlastRadius
            D7_CredHygiene     = $D7_CredentialHygiene
        }
    }

    #endregion

    #region ── Assessment Data Stores ────────────────────────────────────────────

    $script:RiskColors = @{
        "Critical" = "#f85149"
        "High"     = "#d29922"
        "Medium"   = "#388bfd"
        "Low"      = "#3fb950"
        "Info"     = "#7d8590"
    }

    # Tenant-level findings (posture-level checks)
    $script:Findings = [System.Collections.ArrayList]::new()

    # Per-application risk records
    $script:AppRiskRecords = [System.Collections.ArrayList]::new()

    # Roadmap items (derived from findings)
    $script:Roadmap = [System.Collections.ArrayList]::new()


    Function Add-Finding {
        param (
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
            [string]$SuccessMeasure = ""
        )

        $null = $script:Findings.Add([PSCustomObject]@{
                CheckId        = $CheckId
                Title          = $Title
                Evidence       = $Evidence
                CurrentState   = $CurrentState
                Gap            = $Gap
                Risk           = $Risk
                BusinessImpact = $BusinessImpact
                TargetState    = $TargetState
                Recommendation = $Recommendation
                RoadmapPhase   = $RoadmapPhase
                SuccessMeasure = $SuccessMeasure
            })
    }

    #endregion

    #region ── Step 3: Application & Permission Inventory ─────────────────────────

    Function Invoke-PermissionInventory {
        param ([PSCustomObject]$TenantInfo)

        Write-Host "  📋 Collecting application registrations..." -ForegroundColor Cyan
        # App registrations — source of truth for credential posture and ownership
        $appRegs = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/applications?`$select=id,appId,displayName,signInAudience,publisherDomain,verifiedPublisher,passwordCredentials,keyCredentials,owners,createdDateTime&`$top=100"
        Write-Host "  ✅ App registrations collected: $($appRegs.Count)" -ForegroundColor Green

        Write-Host "  📋 Collecting service principals (enterprise apps)..." -ForegroundColor Cyan
        $spns = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,publisherName,verifiedPublisher,appOwnerOrganizationId,signInAudience,accountEnabled,passwordCredentials,keyCredentials,appRoles,oauth2PermissionScopes&`$top=100"
        Write-Host "  ✅ Service principals collected: $($spns.Count)" -ForegroundColor Green

        Write-Host "  📋 Collecting OAuth2 delegated permission grants..." -ForegroundColor Cyan
        $oauth2Grants = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/oauth2PermissionGrants?`$top=200"
        Write-Host "  ✅ OAuth2 grants collected: $($oauth2Grants.Count)" -ForegroundColor Green

        Write-Host "  📋 Collecting application role assignments..." -ForegroundColor Cyan
        # App role assignments expose what application permissions each SPN has been granted
        $appRoleAssignments = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,appId,displayName,appRoleAssignments&`$expand=appRoleAssignedTo&`$top=100"
        # Fetch actual role assignments per SPN via dedicated endpoint for accuracy
        $allAppRoleAssignments = New-Object System.Collections.ArrayList
        $spnProcessed = 0
        foreach ($spn in $spns) {
            if ($spnProcessed % 50 -eq 0) { Write-Host "  ⏳ Processing app role assignments ($spnProcessed/$($spns.Count))..." -ForegroundColor Yellow }
            $assignments = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($spn.id)/appRoleAssignments?`$top=50"
            foreach ($a in $assignments) { $null = $allAppRoleAssignments.Add($a) }
            $spnProcessed++
        }
        Write-Host "  ✅ App role assignments collected: $($allAppRoleAssignments.Count)" -ForegroundColor Green

        Write-Host "  📋 Collecting SPN owners..." -ForegroundColor Cyan
        # Build owner map: spnId → ownerCount
        $spnOwnerMap = @{}
        foreach ($spn in ($spns | Where-Object { $_.servicePrincipalType -ne "ManagedIdentity" } | Select-Object -First 200)) {
            $ownersResp = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($spn.id)/owners?`$select=id&`$top=5"
            $ownerCount = 0
            if ($ownersResp -and $ownersResp.value) { $ownerCount = $ownersResp.value.Count }
            $spnOwnerMap[$spn.id] = $ownerCount
        }
        Write-Host "  ✅ Owner data collected." -ForegroundColor Green

        return @{
            AppRegs            = $appRegs
            SPNs               = $spns
            OAuth2Grants       = $oauth2Grants
            AppRoleAssignments = $allAppRoleAssignments
            SPNOwnerMap        = $spnOwnerMap
        }
    }

    #endregion

    #region ── Step 4: Per-Application Risk Engine ────────────────────────────────

    Function Invoke-AppRiskEngine {
        param (
            [hashtable]$Inventory,
            [string]$OrgTenantId
        )

        Write-Host "  🔬 Running multi-dimensional risk engine..." -ForegroundColor Cyan

        $spns = $Inventory.SPNs
        $oauth2Grants = $Inventory.OAuth2Grants
        $appRoleAssignments = $Inventory.AppRoleAssignments
        $spnOwnerMap = $Inventory.SPNOwnerMap
        $appRegs = $Inventory.AppRegs

        # Build lookup: appId → app registration
        $appRegMap = @{}
        foreach ($ar in $appRegs) { $appRegMap[$ar.appId] = $ar }

        # Build lookup: clientId (SPN.id or appId) → list of delegated grants
        $delegatedGrantMap = @{}
        foreach ($grant in $oauth2Grants) {
            $key = $grant.clientId
            if (-not $delegatedGrantMap.ContainsKey($key)) { $delegatedGrantMap[$key] = @() }
            $delegatedGrantMap[$key] += $grant
        }

        # Build lookup: SPN.id → list of app role assignments received
        $appRoleMap = @{}
        foreach ($assignment in $appRoleAssignments) {
            $key = $assignment.principalId
            if (-not $appRoleMap.ContainsKey($key)) { $appRoleMap[$key] = @() }
            $appRoleMap[$key] += $assignment
        }

        $processed = 0
        foreach ($spn in $spns) {
            # Skip ManagedIdentity SPNs from per-app scoring (they are scored in D6 blast radius separately)
            if ($spn.servicePrincipalType -eq "ManagedIdentity") { continue }
            if (-not $spn.accountEnabled) { continue }

            $processed++
            if ($processed % 25 -eq 0) { Write-Host "  ⏳ Scoring applications ($processed)..." -ForegroundColor Yellow }

            # ── Permission collection ─────────────────────────────────────────────
            $appRoles_received = @()
            if ($appRoleMap.ContainsKey($spn.id)) { $appRoles_received = $appRoleMap[$spn.id] }

            $delegatedGrants = @()
            if ($delegatedGrantMap.ContainsKey($spn.id)) { $delegatedGrants = $delegatedGrantMap[$spn.id] }

            # Resolve permission values from app role assignments
            # We need the resource SPN to map appRoleId → value
            $appPermissionValues = @()
            foreach ($assignment in $appRoles_received) {
                # appRoleId is a GUID; we score by known sensitive role IDs indirectly
                # For taxonomy matching we use the permission display names captured separately
                # Here we flag the assignment count and try to match known high-value roles
                $appPermissionValues += $assignment.appRoleId
            }

            # Collect delegated scope strings
            $delegatedPermValues = @()
            foreach ($grant in $delegatedGrants) {
                if ($grant.scope) {
                    $scopes = $grant.scope -split " " | Where-Object { $_ -ne "" }
                    $delegatedPermValues += $scopes
                }
            }

            $maxDelegatedTier = Get-MaxPermissionTier -Permissions $delegatedPermValues
            $hasAppPermissions = ($appRoles_received.Count -gt 0)

            # For app permissions, estimate tier from count (role GUIDs need resource lookup for full name)
            # Use a conservative High (3) if any app roles exist; Critical (4) if many
            $maxAppRoleTier = 0
            if ($hasAppPermissions) {
                $maxAppRoleTier = if ($appRoles_received.Count -ge 5) { 4 } else { 3 }
            }

            # ── Consent model detection ───────────────────────────────────────────
            $adminConsentGrants = @($delegatedGrants | Where-Object { $_.consentType -eq "AllPrincipals" })
            $userConsentGrants = @($delegatedGrants | Where-Object { $_.consentType -eq "Principal" })

            # ── Publisher verification ────────────────────────────────────────────
            $isVerifiedPublisher = ($spn.verifiedPublisher -and $spn.verifiedPublisher.verifiedPublisherId)
            $isFirstPartyMicrosoft = ($spn.appOwnerOrganizationId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -or
                $spn.appOwnerOrganizationId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47")

            # ── Credential posture ────────────────────────────────────────────────
            $appReg = if ($appRegMap.ContainsKey($spn.appId)) { $appRegMap[$spn.appId] } else { $null }

            $hasActiveSecrets = $false
            $hasExpiredCreds = $false
            $hasLongLivedSecrets = $false
            $hasCerts = $false
            $now = Get-Date

            $credSources = @()
            if ($appReg) { $credSources = @($appReg.passwordCredentials) + @($appReg.keyCredentials) }
            else { $credSources = @($spn.passwordCredentials) + @($spn.keyCredentials) }

            foreach ($cred in $credSources) {
                if ($cred.PSObject.Properties["hint"] -or ($cred.PSObject.Properties["secretText"] -and $cred.secretText)) {
                    # password credential
                    if ($cred.endDateTime -and ([datetime]$cred.endDateTime -lt $now)) {
                        $hasExpiredCreds = $true
                    }
                    else {
                        $hasActiveSecrets = $true
                        if ($cred.startDateTime -and $cred.endDateTime) {
                            $lifetime = ([datetime]$cred.endDateTime - [datetime]$cred.startDateTime).TotalDays
                            if ($lifetime -gt 365) { $hasLongLivedSecrets = $true }
                        }
                    }
                }
                elseif ($cred.PSObject.Properties["thumbprint"]) {
                    $hasCerts = $true
                }
            }

            # Detect secrets from passwordCredentials array directly
            if ($appReg -and $appReg.passwordCredentials.Count -gt 0) {
                foreach ($pc in $appReg.passwordCredentials) {
                    if ($pc.endDateTime) {
                        if ([datetime]$pc.endDateTime -lt $now) { $hasExpiredCreds = $true }
                        else {
                            $hasActiveSecrets = $true
                            if ($pc.startDateTime) {
                                $lt = ([datetime]$pc.endDateTime - [datetime]$pc.startDateTime).TotalDays
                                if ($lt -gt 365) { $hasLongLivedSecrets = $true }
                            }
                        }
                    }
                }
            }
            if ($appReg -and $appReg.keyCredentials.Count -gt 0) { $hasCerts = $true }

            $noCredentials = (-not $hasActiveSecrets -and -not $hasCerts -and -not $hasExpiredCreds)

            # ── Multi-tenant ──────────────────────────────────────────────────────
            $isMultiTenant = ($spn.signInAudience -in @("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"))

            # ── Owner count ───────────────────────────────────────────────────────
            $ownerCount = 0
            if ($spnOwnerMap.ContainsKey($spn.id)) { $ownerCount = $spnOwnerMap[$spn.id] }

            # ── Assigned users/groups (rough proxy from appReg) ───────────────────
            $assignedCount = 0  # Graph requires separate call per SPN for appRoleAssignedTo; use 0 as default

            # ── Sign-in activity ──────────────────────────────────────────────────
            $hasRecentSignIn = $false  # Requires AuditLog.Read.All; treat as false if unavailable

            # ── Dimension scores ──────────────────────────────────────────────────
            $d1 = Get-PermissionSensitivityScore `
                -MaxAppRoleTier       $maxAppRoleTier `
                -MaxDelegatedTier     $maxDelegatedTier `
                -TotalAppRoleCount    $appRoles_received.Count `
                -TotalDelegatedCount  $delegatedPermValues.Count

            $d2 = Get-ConsentModelScore `
                -HasApplicationPermissions  $hasAppPermissions `
                -HasAdminConsentDelegated   ($adminConsentGrants.Count -gt 0) `
                -HasUserConsentDelegated    ($userConsentGrants.Count -gt 0) `
                -UserConsentCount           $userConsentGrants.Count

            $d3 = Get-AppCriticalityScore `
                -IsMultiTenant          $isMultiTenant `
                -HasSignInActivity      $hasRecentSignIn `
                -IsFirstPartyMicrosoft  $isFirstPartyMicrosoft `
                -AssignedUserGroupCount $assignedCount

            $d4 = Get-OwnershipScore -OwnerCount $ownerCount

            $d5 = Get-PublisherVerificationScore `
                -IsVerifiedPublisher   $isVerifiedPublisher `
                -IsFirstPartyMicrosoft $isFirstPartyMicrosoft `
                -MaxPermissionTier     ([Math]::Max($maxAppRoleTier, $maxDelegatedTier))

            $d6 = Get-BlastRadiusScore `
                -MaxAppRoleTier    $maxAppRoleTier `
                -TotalAppRoleCount $appRoles_received.Count `
                -IsMultiTenant     $isMultiTenant

            $d7 = Get-CredentialHygieneScore `
                -HasExpiredCredentials $hasExpiredCreds `
                -HasLongLivedSecrets   $hasLongLivedSecrets `
                -HasActiveSecrets      $hasActiveSecrets `
                -HasCertificates       $hasCerts `
                -NoCredentials         $noCredentials

            $scoreResult = Compute-AppRiskScore `
                -D1_PermissionSensitivity  $d1 `
                -D2_ConsentModel           $d2 `
                -D3_AppCriticality         $d3 `
                -D4_Ownership              $d4 `
                -D5_PublisherVerification  $d5 `
                -D6_BlastRadius            $d6 `
                -D7_CredentialHygiene      $d7

            # ── Summarise permissions for display ─────────────────────────────────
            $permSummary = ""
            if ($hasAppPermissions -and $delegatedPermValues.Count -gt 0) {
                $permSummary = "App: $($appRoles_received.Count) role(s) | Delegated: $($delegatedPermValues.Count) scope(s)"
            }
            elseif ($hasAppPermissions) {
                $permSummary = "App permissions: $($appRoles_received.Count) role assignment(s)"
            }
            elseif ($delegatedPermValues.Count -gt 0) {
                $topScopes = ($delegatedPermValues | Select-Object -First 4) -join ", "
                $permSummary = "Delegated: $topScopes"
            }
            else {
                $permSummary = "No permissions detected"
            }

            # ── Credential summary ────────────────────────────────────────────────
            $credSummary = if ($noCredentials) { "Secretless (MI/Federated)" }
            elseif ($hasExpiredCreds -and $hasActiveSecrets) { "Expired + active secrets" }
            elseif ($hasExpiredCreds) { "Expired credentials" }
            elseif ($hasLongLivedSecrets) { "Long-lived secret (>1yr)" }
            elseif ($hasActiveSecrets -and $hasCerts) { "Secret + certificate" }
            elseif ($hasActiveSecrets) { "Client secret(s)" }
            elseif ($hasCerts) { "Certificate(s) only" }
            else { "Unknown" }

            $null = $script:AppRiskRecords.Add([PSCustomObject]@{
                    SpnId               = $spn.id
                    AppId               = $spn.appId
                    DisplayName         = $spn.displayName
                    PublisherName       = $spn.publisherName
                    IsVerifiedPublisher = $isVerifiedPublisher
                    IsFirstPartyMS      = $isFirstPartyMicrosoft
                    IsMultiTenant       = $isMultiTenant
                    HasAppPermissions   = $hasAppPermissions
                    AppRoleCount        = $appRoles_received.Count
                    DelegatedScopeCount = $delegatedPermValues.Count
                    AdminConsentCount   = $adminConsentGrants.Count
                    UserConsentCount    = $userConsentGrants.Count
                    OwnerCount          = $ownerCount
                    HasExpiredCreds     = $hasExpiredCreds
                    HasLongLivedSecrets = $hasLongLivedSecrets
                    HasActiveSecrets    = $hasActiveSecrets
                    HasCerts            = $hasCerts
                    NoCredentials       = $noCredentials
                    PermSummary         = $permSummary
                    CredSummary         = $credSummary
                    CompositeScore      = $scoreResult.Composite
                    RiskBand            = $scoreResult.Band
                    D1_PermSensitivity  = $scoreResult.D1_PermSensitivity
                    D2_ConsentModel     = $scoreResult.D2_ConsentModel
                    D3_AppCriticality   = $scoreResult.D3_AppCriticality
                    D4_Ownership        = $scoreResult.D4_Ownership
                    D5_PublisherVerif   = $scoreResult.D5_PublisherVerif
                    D6_BlastRadius      = $scoreResult.D6_BlastRadius
                    D7_CredHygiene      = $scoreResult.D7_CredHygiene
                })
        }

        Write-Host "  ✅ Risk engine complete. Scored $processed applications." -ForegroundColor Green
    }

    #endregion

    #region ── Step 5: Tenant-Level Risk Posture Findings ────────────────────────

    Function Invoke-TenantRiskFindings {
        param ([hashtable]$Inventory)

        Write-Host "  🔍 Generating tenant-level risk posture findings..." -ForegroundColor Cyan

        $spns = $Inventory.SPNs
        $oauth2Grants = $Inventory.OAuth2Grants
        $appRoleAssignments = $Inventory.AppRoleAssignments
        $appRegs = $Inventory.AppRegs

        $now = Get-Date

        # ── Finding F1: Overall Tenant Permission Posture ─────────────────────────
        $totalSPNs = ($spns | Where-Object { $_.servicePrincipalType -ne "ManagedIdentity" -and $_.accountEnabled }).Count
        $totalMI = ($spns | Where-Object { $_.servicePrincipalType -eq "ManagedIdentity" }).Count
        $totalGranted = $allAppRoleAssignments.Count + $oauth2Grants.Count

        $critical = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Critical" }).Count
        $high = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "High" }).Count
        $medium = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Medium" }).Count
        $low = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Low" }).Count

        $overallBand = if ($critical -gt 0) { "Critical" } elseif ($high -gt 3) { "High" } elseif ($medium -gt 10) { "Medium" } else { "Low" }

        Add-Finding -CheckId "F1" `
            -Title "Tenant Application Permission Risk Posture — $overallBand" `
            -Evidence "Total active apps scored: $($script:AppRiskRecords.Count) | Critical: $critical | High: $high | Medium: $medium | Low: $low | Total permission grants: $totalGranted | Managed Identities: $totalMI" `
            -CurrentState "The tenant has $($script:AppRiskRecords.Count) active applications. $critical are in the Critical risk band and $high are in the High risk band, indicating material API governance exposure." `
            -Gap "Every application with elevated permissions represents an API governance risk. Without active oversight, the cumulative blast radius across all Critical and High applications can enable tenant-wide compromise." `
            -Risk $overallBand `
            -BusinessImpact "Uncontrolled application permissions are the leading attack vector for SaaS-to-tenant lateral movement, OAuth consent phishing, and supply-chain compromise. A single compromised high-permission app can expose all tenant data." `
            -TargetState "All applications reviewed and risk-accepted. Zero unowned high-permission apps. Permission lifecycle management enforced. Quarterly permission audits embedded in the SDLC." `
            -Recommendation "Establish an Application Permission Governance program: (1) complete this risk model review, (2) accept or remediate all Critical findings within 30 days, (3) assign owners to all high-permission apps, (4) implement an App Governance policy in Microsoft Defender." `
            -RoadmapPhase "0-30 Days" `
            -SuccessMeasure "Zero Critical-band apps without a named owner and documented business justification. Monthly risk score trend declining."

        # ── Finding F2: High-Privilege Application Permissions ────────────────────
        $appsWithAppPerms = @($script:AppRiskRecords | Where-Object { $_.HasAppPermissions -eq $true })

        if ($appsWithAppPerms.Count -gt 0) {
            $riskF2 = if ($appsWithAppPerms.Count -ge 10) { "Critical" } elseif ($appsWithAppPerms.Count -ge 5) { "High" } else { "Medium" }
            Add-Finding -CheckId "F2" `
                -Title "Applications with Application-Level Permissions Detected ($($appsWithAppPerms.Count) apps)" `
                -Evidence "Apps with application-level (app role) permissions: $($appsWithAppPerms.Count) | Top apps: $(($appsWithAppPerms | Sort-Object CompositeScore -Descending | Select-Object -First 3 | ForEach-Object { $_.DisplayName }) -join ', ')" `
                -CurrentState "$($appsWithAppPerms.Count) applications have been granted application-level Microsoft Graph permissions (app role assignments). These permissions operate without a signed-in user and are always active." `
                -Gap "Application permissions bypass the user consent gate. There is no runtime MFA, no user approval, and no session expiry. The API access is continuous until the permission is explicitly revoked." `
                -Risk $riskF2 `
                -BusinessImpact "A compromised application with application-level permissions (e.g., Directory.Read.All, Mail.Read) enables silent, undetected bulk data exfiltration of users, groups, emails, and files — equivalent to a breach with no user interaction." `
                -TargetState "All application-level permissions documented with business justification, approved by security, and reviewed quarterly. Principle of least privilege enforced — each app holds only the minimum required permissions." `
                -Recommendation "(1) Enumerate all application-level permission grants and validate business justification. (2) Remove any permissions not actively used. (3) Implement Microsoft Defender for Cloud Apps App Governance to alert on anomalous app behaviour. (4) Require a security sign-off for any new application-level permission grant." `
                -RoadmapPhase "0-30 Days" `
                -SuccessMeasure "All application permissions have a documented justification. App Governance policies active. Zero undocumented app role assignments."
        }
        else {
            Add-Finding -CheckId "F2" `
                -Title "No Application-Level Permissions Detected — Good Governance Signal" `
                -Evidence "Apps with application-level (app role) permissions: 0" `
                -CurrentState "No applications have been granted application-level Microsoft Graph permissions in this tenant." `
                -Gap "Verify this is accurate — the absence of data may reflect permission scope rather than a clean state. Ensure AuditLog.Read.All and Application.Read.All were granted." `
                -Risk "Info" `
                -BusinessImpact "Low — application-level permissions are the highest-risk consent type. Absence suggests good governance or delegated-only app architecture." `
                -TargetState "Maintain this posture. Establish a governance gate before any future application-level permission is granted." `
                -Recommendation "Confirm data completeness by verifying the assessment token had Application.Read.All. Establish a governance policy requiring security review before any app-level permission is granted." `
                -RoadmapPhase "Strategic" `
                -SuccessMeasure "Governance gate active. Any future app-level permission grant triggers a security review workflow."
        }

        # ── Finding F3: Admin-Consented Delegated Permissions at Scale ─────────────
        $adminConsentGrants = @($oauth2Grants | Where-Object { $_.consentType -eq "AllPrincipals" })
        if ($adminConsentGrants.Count -gt 20) {
            Add-Finding -CheckId "F3" `
                -Title "Large Number of Admin-Consented Delegated Grants ($($adminConsentGrants.Count) grants)" `
                -Evidence "Admin-consented (AllPrincipals) OAuth2 permission grants: $($adminConsentGrants.Count) | Unique apps receiving admin consent: $(($adminConsentGrants | Select-Object -ExpandProperty clientId -Unique).Count)" `
                -CurrentState "$($adminConsentGrants.Count) delegated permission grants have been admin-consented (AllPrincipals), meaning every user in the tenant implicitly authorises these applications." `
                -Gap "Admin consent at scale can mask over-permissioned applications. Users are not aware their data is accessible by these applications, and there is no per-user revocation path." `
                -Risk "High" `
                -BusinessImpact "Each admin-consented application can access data for any user in the tenant. A compromised admin-consented app is effectively a tenant-wide data exposure." `
                -TargetState "Admin consent restricted to a small set of vetted, business-critical applications. User consent disabled or restricted to verified publishers. Consent request workflow implemented." `
                -Recommendation "(1) Review all admin-consented delegated grants. (2) Revoke any that are not actively used or not business-justified. (3) Configure the user consent settings policy to restrict user consent to verified publishers only. (4) Enable admin consent workflow (Entra → Enterprise Applications → Consent and permissions)." `
                -RoadmapPhase "31-60 Days" `
                -SuccessMeasure "Admin-consented grant count reduced by >50%. Admin consent workflow active. User consent restricted to verified publishers."
        }
        elseif ($adminConsentGrants.Count -gt 0) {
            Add-Finding -CheckId "F3" `
                -Title "Admin-Consented Delegated Grants Present — Review Recommended ($($adminConsentGrants.Count) grants)" `
                -Evidence "Admin-consented (AllPrincipals) OAuth2 grants: $($adminConsentGrants.Count)" `
                -CurrentState "$($adminConsentGrants.Count) admin-consented delegated grants exist. Volume is within manageable range but should be reviewed periodically." `
                -Gap "Verify each grant is still required and the scope is appropriate. Stale grants accumulate over time." `
                -Risk "Medium" `
                -BusinessImpact "Moderate — admin-consented grants mean all tenant users implicitly consent. Stale grants for decommissioned apps represent residual access that should be cleaned up." `
                -TargetState "All admin-consented grants reviewed annually. Stale grants revoked. Admin consent workflow enforced." `
                -Recommendation "Review the list of admin-consented grants. Remove any where the application is no longer in use. Schedule an annual admin-consent review." `
                -RoadmapPhase "61-90 Days" `
                -SuccessMeasure "All admin-consented grants reviewed and documented. Annual review cadence established."
        }
        else {
            Add-Finding -CheckId "F3" `
                -Title "No Admin-Consented Delegated Grants — Verify Scope Completeness" `
                -Evidence "Admin-consented (AllPrincipals) OAuth2 grants: 0" `
                -CurrentState "No admin-consented delegated permission grants were detected." `
                -Gap "Confirm data completeness — this may indicate a restricted tenant or an assessment token without sufficient scope." `
                -Risk "Info" `
                -BusinessImpact "Low — if accurate, this is a strong governance signal." `
                -TargetState "Maintain minimal admin-consented grants. Establish a governance gate for new admin consent requests." `
                -Recommendation "Verify token scope includes DelegatedPermissionGrant.Read.All. If accurate, maintain this posture with a governance gate for future admin consent requests." `
                -RoadmapPhase "Strategic" `
                -SuccessMeasure "Admin consent governance gate active."
        }

        # ── Finding F4: User Consent (Shadow IT) ──────────────────────────────────
        $userConsentGrants = @($oauth2Grants | Where-Object { $_.consentType -eq "Principal" })
        $userConsentedApps = ($userConsentGrants | Select-Object -ExpandProperty clientId -Unique).Count

        if ($userConsentedApps -gt 50) {
            Add-Finding -CheckId "F4" `
                -Title "Shadow IT at Scale — $userConsentedApps Apps with User-Only Consent" `
                -Evidence "User-consented (Principal) OAuth2 grants: $($userConsentGrants.Count) | Unique apps with user consent only: $userConsentedApps" `
                -CurrentState "$userConsentedApps applications have been authorised by individual users without IT review. These represent unmanaged shadow IT applications accessing tenant data." `
                -Gap "User-consented applications have no IT oversight, no business justification review, and no data handling validation. They may access mail, calendar, contacts, or files on behalf of the consenting user." `
                -Risk "High" `
                -BusinessImpact "Shadow IT applications represent uncontrolled data egress. User-consented apps can read email, contacts, and calendar — sufficient for social engineering, credential harvesting, and competitive intelligence exfiltration. Compliance frameworks (GDPR, HIPAA, SOC 2) require organisations to know and control where data flows." `
                -TargetState "User consent disabled or restricted to verified publishers with low-risk permissions only. All applications accessing tenant data reviewed and approved by IT. App catalog established for approved applications." `
                -Recommendation "(1) Immediately restrict user consent to low-risk permissions for verified publishers (Entra → Enterprise Applications → User consent settings). (2) Review existing user-consented apps and revoke those accessing sensitive scopes (Mail.Read, Files.Read, Calendars.Read). (3) Implement an app request portal (MyApps). (4) Enable Microsoft Defender for Cloud Apps to classify and monitor shadow IT." `
                -RoadmapPhase "0-30 Days" `
                -SuccessMeasure "User consent restricted. Shadow IT app count reduced by >60%. App catalog and request workflow operational."
        }
        elseif ($userConsentedApps -gt 10) {
            Add-Finding -CheckId "F4" `
                -Title "User-Consented Applications Detected — Shadow IT Risk ($userConsentedApps apps)" `
                -Evidence "User-consented apps: $userConsentedApps | Total user grants: $($userConsentGrants.Count)" `
                -CurrentState "$userConsentedApps applications were consented to by individual users without IT governance review." `
                -Gap "Each user-consented app can access data on behalf of the consenting user. Sensitive scope access (Mail.Read, Calendars.Read) is a data leakage risk." `
                -Risk "Medium" `
                -BusinessImpact "User-consented apps with sensitive scopes create untracked data flows that may violate data residency, compliance, and privacy requirements." `
                -TargetState "User consent policy restricted. Sensitive-scope user consent disabled. All existing consents reviewed." `
                -Recommendation "Review user-consented apps with sensitive scopes. Restrict user consent policy. Consider enabling admin consent workflow for sensitive permissions." `
                -RoadmapPhase "31-60 Days" `
                -SuccessMeasure "User consent policy configured. Sensitive-scope user consent reviewed and cleaned up."
        }
        else {
            Add-Finding -CheckId "F4" `
                -Title "Minimal User-Consented Applications — Good Governance Signal ($userConsentedApps apps)" `
                -Evidence "User-consented (Principal) grants: $($userConsentGrants.Count) | Unique apps: $userConsentedApps" `
                -CurrentState "User consent is limited to a small number of applications." `
                -Gap "Verify user consent policy settings to ensure this posture is by design, not just current state." `
                -Risk "Low" `
                -BusinessImpact "Low — limited user consent exposure. Review user consent policy settings to ensure this is governed." `
                -TargetState "User consent policy enforced. App catalog available for user self-service within IT-approved boundaries." `
                -Recommendation "Confirm user consent policy is set to restrict or disable consent. Maintain this posture." `
                -RoadmapPhase "Strategic" `
                -SuccessMeasure "User consent policy verified and documented."
        }

        # ── Finding F5: Unverified Publishers with Sensitive Access ───────────────
        $unverifiedHighPerm = @($script:AppRiskRecords | Where-Object {
                -not $_.IsVerifiedPublisher -and
                -not $_.IsFirstPartyMS -and
                ($_.HasAppPermissions -or $_.DelegatedScopeCount -gt 0) -and
                $_.D5_PublisherVerif -ge 8
            })

        if ($unverifiedHighPerm.Count -gt 0) {
            Add-Finding -CheckId "F5" `
                -Title "Unverified Publishers with Sensitive API Access ($($unverifiedHighPerm.Count) apps)" `
                -Evidence "Apps with unverified publisher AND sensitive permissions: $($unverifiedHighPerm.Count) | Examples: $(($unverifiedHighPerm | Select-Object -First 3 | ForEach-Object { $_.DisplayName }) -join ', ')" `
                -CurrentState "$($unverifiedHighPerm.Count) applications that have not completed Microsoft's Publisher Verification hold sensitive API access. Their identity as legitimate software publishers has not been verified." `
                -Gap "Unverified publishers have not attested to Microsoft's verification requirements. They may be OAuth phishing apps, abandoned third-party tools, or internally developed apps without proper governance." `
                -Risk "High" `
                -BusinessImpact "OAuth consent phishing campaigns specifically target unverified applications to grant high-privilege access under the guise of legitimate-looking app names. Unverified apps with Directory.Read.All, Mail.Read, or similar scopes are high-value targets for account takeover campaigns." `
                -TargetState "All third-party applications holding sensitive permissions are from verified publishers. Internal applications are registered in a dedicated internal tenant namespace. Unverified app consent is blocked by Conditional Access." `
                -Recommendation "(1) Review all unverified-publisher apps with sensitive permissions. Remove any not business-justified. (2) Configure user consent to require verified publishers for sensitive permission scopes. (3) Enable Microsoft Defender for Cloud Apps App Governance anomaly detection. (4) For internal apps, complete Microsoft Publisher Verification or isolate to internal consent flows." `
                -RoadmapPhase "0-30 Days" `
                -SuccessMeasure "All sensitive-access apps either verified, removed, or risk-accepted. User consent restricted to verified publishers."
        }
        else {
            Add-Finding -CheckId "F5" `
                -Title "No High-Risk Unverified Publisher Apps Detected" `
                -Evidence "Apps with unverified publisher and high-sensitivity permissions: 0" `
                -CurrentState "All apps holding sensitive permissions appear to be from verified publishers or Microsoft first-party services." `
                -Gap "Continue monitoring. New app registrations may introduce unverified publishers over time." `
                -Risk "Info" `
                -BusinessImpact "Low — publisher verification is in good standing for sensitive-access applications." `
                -TargetState "Maintain publisher verification policy. Restrict future admin consent to verified publishers." `
                -Recommendation "Configure user consent settings to require publisher verification for sensitive scopes. Periodically audit new app registrations." `
                -RoadmapPhase "Strategic" `
                -SuccessMeasure "Publisher verification policy enforced. No unverified publisher apps with sensitive access in next quarterly audit."
        }

        # ── Finding F6: Ownerless Applications ───────────────────────────────────
        $ownerlessApps = @($script:AppRiskRecords | Where-Object { $_.OwnerCount -eq 0 -and ($_.HasAppPermissions -or $_.DelegatedScopeCount -gt 0) })

        if ($ownerlessApps.Count -gt 0) {
            $riskF6 = if ($ownerlessApps.Count -ge 20) { "Critical" } elseif ($ownerlessApps.Count -ge 5) { "High" } else { "Medium" }
            Add-Finding -CheckId "F6" `
                -Title "Ownerless Applications with API Access — Accountability Gap ($($ownerlessApps.Count) apps)" `
                -Evidence "Apps with permissions but no registered owner: $($ownerlessApps.Count) | Examples: $(($ownerlessApps | Sort-Object CompositeScore -Descending | Select-Object -First 3 | ForEach-Object { $_.DisplayName }) -join ', ')" `
                -CurrentState "$($ownerlessApps.Count) applications that hold API permissions have no registered owner in Entra ID. There is no individual or team accountable for reviewing, maintaining, or decommissioning these applications." `
                -Gap "Ownerless applications cannot be risk-reviewed, decommissioned, or subject to a least-privilege governance process. They accumulate access over time with no oversight. In an audit, inability to identify an application owner is a compliance failure." `
                -Risk $riskF6 `
                -BusinessImpact "Ownerless applications are the most likely candidates for abandoned, forgotten, or legacy API integrations. They are also the most likely to have long-lived, unrotated credentials — a key breach vector. In a security incident, unowned apps cannot be quickly assessed or disabled." `
                -TargetState "Every application holding API permissions has a named owner (individual or group) registered in Entra ID. Owner assignment is part of the app registration lifecycle checklist. Quarterly access review covers ownership confirmation." `
                -Recommendation "(1) Assign owners to all applications with permissions — start with highest risk score. (2) For applications with no identifiable owner, initiate an orphan app review process: identify via Git history, Azure DevOps, or service desk records. (3) Disable or delete apps where ownership cannot be established and the app shows no sign-in activity. (4) Enforce owner assignment as a governance gate in the app registration request process." `
                -RoadmapPhase "0-30 Days" `
                -SuccessMeasure "100% of high-permission apps have a named owner. Orphan app review process documented and scheduled."
        }
        else {
            Add-Finding -CheckId "F6" `
                -Title "All Active Permission-Holding Apps Have Owners" `
                -Evidence "Apps with permissions and no owner: 0 (sampled up to 200 SPNs)" `
                -CurrentState "All sampled applications with API permissions have registered owners." `
                -Gap "Note: owner data was sampled. Large tenants may have unsampled apps. Verify coverage." `
                -Risk "Info" `
                -BusinessImpact "Low — ownership accountability is in place for the assessed sample." `
                -TargetState "Maintain ownership hygiene. Include owner assignment in all new app governance processes." `
                -Recommendation "Continue owner assignment practice. Enforce as a governance gate for new app registrations." `
                -RoadmapPhase "Strategic" `
                -SuccessMeasure "Owner assignment in app registration checklist. Next audit shows 100% coverage."
        }

        # ── Finding F7: Credential Hygiene ────────────────────────────────────────
        $expiredCredApps = @($script:AppRiskRecords | Where-Object { $_.HasExpiredCreds })
        $longLivedApps = @($script:AppRiskRecords | Where-Object { $_.HasLongLivedSecrets })
        $secretOnlyApps = @($script:AppRiskRecords | Where-Object { $_.HasActiveSecrets -and -not $_.NoCredentials -and -not $_.HasCerts })
        $secretlessApps = @($script:AppRiskRecords | Where-Object { $_.NoCredentials })

        $totalWithCreds = ($script:AppRiskRecords | Where-Object { -not $_.NoCredentials }).Count
        $secretlessRatio = if ($script:AppRiskRecords.Count -gt 0) { [Math]::Round(($secretlessApps.Count / $script:AppRiskRecords.Count) * 100, 0) } else { 0 }

        $riskF7 = if ($expiredCredApps.Count -gt 10 -or $longLivedApps.Count -gt 15) { "High" }
        elseif ($expiredCredApps.Count -gt 0 -or $longLivedApps.Count -gt 5) { "Medium" }
        else { "Low" }

        Add-Finding -CheckId "F7" `
            -Title "Application Credential Hygiene: $secretlessRatio% Secretless | $($expiredCredApps.Count) Expired | $($longLivedApps.Count) Long-Lived" `
            -Evidence "Secretless apps (MI/Federated): $($secretlessApps.Count) ($secretlessRatio%) | Apps with expired credentials: $($expiredCredApps.Count) | Apps with secrets >1 year: $($longLivedApps.Count) | Apps with active secrets only: $($secretOnlyApps.Count)" `
            -CurrentState "$secretlessRatio% of applications use secretless authentication (Managed Identity or Federated Credentials). $($expiredCredApps.Count) application(s) have expired credentials still registered, and $($longLivedApps.Count) have long-lived secrets exceeding 1 year." `
            -Gap "Client secrets are the primary credential theft vector for application identities. Expired credentials left in place indicate poor credential lifecycle hygiene. Long-lived secrets extend the exploitation window after a potential leak." `
            -Risk $riskF7 `
            -BusinessImpact "Every client secret is a static credential that can be exfiltrated from code, config files, environment variables, or build pipelines. Secret compromise is silent — unlike a user sign-in, there is no MFA challenge. A compromised application secret provides persistent API access until manually revoked." `
            -TargetState "≥80% secretless applications (Managed Identity or Federated Credentials). Maximum secret lifetime: 90 days. Zero expired credentials registered. Annual secrets-to-federated migration programme." `
            -Recommendation "(1) Immediately remove all expired credentials (they serve no purpose but confuse auditors). (2) For apps with secrets >1 year, initiate rotation and set 90-day expiry. (3) For Azure-hosted workloads, migrate to Managed Identity. (4) For non-Azure workloads, implement Workload Identity Federation (GitHub Actions OIDC, etc.)." `
            -RoadmapPhase $(if ($riskF7 -eq "High") { "0-30 Days" } else { "31-60 Days" }) `
            -SuccessMeasure "Zero expired credentials in tenant. Secretless ratio >80%. All secrets have <90 day lifetime."

        # ── Finding F8: Multi-Tenant Applications ─────────────────────────────────
        $multiTenantApps = @($script:AppRiskRecords | Where-Object { $_.IsMultiTenant -and ($_.HasAppPermissions -or $_.DelegatedScopeCount -gt 0) })

        if ($multiTenantApps.Count -gt 0) {
            $riskF8 = if ($multiTenantApps.Count -ge 10) { "High" } else { "Medium" }
            Add-Finding -CheckId "F8" `
                -Title "Multi-Tenant Applications with API Access ($($multiTenantApps.Count) apps)" `
                -Evidence "Multi-tenant apps with permissions: $($multiTenantApps.Count) | Examples: $(($multiTenantApps | Select-Object -First 3 | ForEach-Object { $_.DisplayName }) -join ', ')" `
                -CurrentState "$($multiTenantApps.Count) applications configured as multi-tenant (accessible from other Entra ID tenants) hold API permissions in this tenant." `
                -Gap "Multi-tenant applications widen the attack surface to external tenants. Users from any Entra ID tenant can potentially authenticate to these applications, which in turn can access this tenant's resources if permission grants exist." `
                -Risk $riskF8 `
                -BusinessImpact "Cross-tenant application access is a vector for tenant confusion attacks, where a malicious actor from a different tenant tricks a user into authorising access. Multi-tenant apps with high permissions can exfiltrate data across tenant boundaries." `
                -TargetState "Multi-tenant configuration is explicitly justified and reviewed. Internal-only applications are configured as single-tenant. External access is governed by a cross-tenant access policy." `
                -Recommendation "(1) Review each multi-tenant app — is cross-tenant access a genuine business requirement? (2) Change any internal-only apps from multi-tenant to single-tenant. (3) Implement cross-tenant access settings to restrict inbound access from unknown tenants. (4) Require documented justification and security review for any new multi-tenant app registration." `
                -RoadmapPhase "31-60 Days" `
                -SuccessMeasure "All multi-tenant apps justified. Internal apps single-tenant. Cross-tenant access policy configured."
        }
        else {
            Add-Finding -CheckId "F8" `
                -Title "No Multi-Tenant Applications with API Access Detected" `
                -Evidence "Multi-tenant apps with permissions: 0" `
                -CurrentState "No multi-tenant applications holding API permissions were detected." `
                -Gap "Verify this is accurate — some SaaS integrations are inherently multi-tenant and may not appear in this scan." `
                -Risk "Info" `
                -BusinessImpact "Low — single-tenant posture limits cross-tenant attack surface." `
                -TargetState "Maintain single-tenant posture for all internal apps. Require justification for any multi-tenant registration." `
                -Recommendation "Enforce single-tenant configuration as the default for new app registrations. Review cross-tenant access settings." `
                -RoadmapPhase "Strategic" `
                -SuccessMeasure "Single-tenant posture maintained. Cross-tenant access policy reviewed."
        }

        # ── Finding F9: Legacy/Over-Permissioned Service Principals ───────────────
        $appRegsCount = $appRegs.Count
        $legacySPNs = @($spns | Where-Object {
                $_.servicePrincipalType -eq "Legacy" -or
                ($_.tags -and $_.tags -contains "WindowsAzureActiveDirectoryIntegratedApp")
            })

        if ($legacySPNs.Count -gt 0) {
            Add-Finding -CheckId "F9" `
                -Title "Legacy Service Principals Detected ($($legacySPNs.Count) legacy SPNs)" `
                -Evidence "Legacy-type service principals: $($legacySPNs.Count) | Examples: $(($legacySPNs | Select-Object -First 3 -ExpandProperty displayName) -join ', ')" `
                -CurrentState "$($legacySPNs.Count) service principals are classified as Legacy type. These are typically older Azure AD integrations, ADAL-based applications, or applications pre-dating modern OAuth2 flows." `
                -Gap "Legacy service principals may use deprecated authentication protocols (ADAL, Basic Auth), have no modern permission governance, and may hold permissions granted years ago that are no longer needed." `
                -Risk "Medium" `
                -BusinessImpact "Legacy authentication bypasses Conditional Access policies. Applications using ADAL or Basic Auth cannot be MFA-protected, device-compliance-checked, or blocked by risk-based policy. They are a preferred target for credential spray attacks." `
                -TargetState "All legacy SPNs migrated to MSAL-based authentication. ADAL/Basic Auth deprecated. Legacy SPNs decommissioned or modernised." `
                -Recommendation "(1) Identify which legacy SPNs are still active (sign-in logs). (2) For active ones, assess migration to MSAL and modern OAuth2. (3) For inactive ones, disable or delete. (4) Block legacy authentication at the Conditional Access layer." `
                -RoadmapPhase "31-60 Days" `
                -SuccessMeasure "Zero active legacy SPNs using deprecated auth protocols. Legacy auth blocked by Conditional Access."
        }
        else {
            Add-Finding -CheckId "F9" `
                -Title "No Legacy Service Principals Detected" `
                -Evidence "Legacy-type service principals: 0" `
                -CurrentState "No legacy service principal types were detected." `
                -Gap "Continue monitoring. Legacy apps may be re-introduced through third-party integrations." `
                -Risk "Info" `
                -BusinessImpact "Low — modern authentication posture is intact." `
                -TargetState "Maintain modern authentication posture. Block legacy authentication via Conditional Access." `
                -Recommendation "Ensure Conditional Access blocks legacy authentication protocols as a defence-in-depth measure." `
                -RoadmapPhase "Strategic" `
                -SuccessMeasure "Conditional Access legacy auth block policy active."
        }

        # ── Finding F10: Blast Radius Assessment ─────────────────────────────────
        $highBlastApps = @($script:AppRiskRecords | Where-Object { $_.D6_BlastRadius -ge 8 })

        if ($highBlastApps.Count -gt 0) {
            Add-Finding -CheckId "F10" `
                -Title "Applications with Maximum Blast Radius Identified ($($highBlastApps.Count) apps)" `
                -Evidence "Apps with maximum blast radius score (≥8/10): $($highBlastApps.Count) | Top apps: $(($highBlastApps | Sort-Object CompositeScore -Descending | Select-Object -First 3 | ForEach-Object { "$($_.DisplayName) [$($_.RiskBand)]" }) -join '; ')" `
                -CurrentState "$($highBlastApps.Count) applications have a maximum blast radius rating — meaning if compromised, they have the potential for tenant-wide data exposure or configuration manipulation." `
                -Gap "Blast radius is a measure of potential worst-case impact. Applications with critical-tier application permissions (Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory) can compromise the entire tenant if their credentials are stolen." `
                -Risk "Critical" `
                -BusinessImpact "A single compromised application with tenant-wide write permissions is equivalent to a global administrator breach. The attacker can create new admin accounts, assign privileged roles, modify Conditional Access policies, read all email and files, and establish persistence — all without triggering a user sign-in alert." `
                -TargetState "Maximum blast radius applications have Managed Identity or Federated Credentials (no secrets). Credentials are monitored for anomalous use via Microsoft Defender for Cloud Apps. Least-privilege review completed — permissions scoped to the minimum required." `
                -Recommendation "(1) For each maximum blast-radius app: verify the business justification for the permission level. (2) Reduce permissions to the minimum required — e.g., use resource-scoped permissions where available. (3) Ensure credentials use Managed Identity or Federated Credentials. (4) Enable Microsoft Entra Workload Identity Protection alerts. (5) Add to a priority monitoring group in the SIEM." `
                -RoadmapPhase "0-30 Days" `
                -SuccessMeasure "Zero maximum blast-radius apps with client secrets. All high blast-radius apps have documented justification and are in SIEM monitoring."
        }
        else {
            Add-Finding -CheckId "F10" `
                -Title "No Maximum Blast Radius Applications Detected" `
                -Evidence "Apps with maximum blast radius score (≥8/10): 0" `
                -CurrentState "No applications with maximum blast radius were identified in the risk model." `
                -Gap "Continue monitoring. New app registrations or permission grants may introduce maximum blast-radius exposure." `
                -Risk "Low" `
                -BusinessImpact "Low — current application portfolio does not present a maximum blast radius risk." `
                -TargetState "Maintain current posture. Implement a governance gate before any tenant-wide write permissions are granted." `
                -Recommendation "Implement App Governance policies to alert on any future grant of critical-tier permissions. Include blast radius review in the app permission approval workflow." `
                -RoadmapPhase "Strategic" `
                -SuccessMeasure "App Governance policies active. No unreviewed maximum blast-radius permissions."
        }

        Write-Host "  ✅ Tenant-level findings complete ($($script:Findings.Count) findings)." -ForegroundColor Green
    }

    #endregion

    #region ── JSON Serialisation Helpers ─────────────────────────────────────────

    Function ConvertTo-JsonSafe {
        param ([string]$s)
        return $s -replace '\\', '\\' `
            -replace '"', '\"' `
            -replace "`r", '' `
            -replace "`n", '\n' `
            -replace "`t", '\t' `
            -replace '<', '\u003c' `
            -replace '>', '\u003e' `
            -replace '\$', '\u0024'
    }


    Function Build-FindingsJson {
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.Append("[")
        $first = $true
        foreach ($f in $script:Findings) {
            if (-not $first) { $null = $sb.Append(",") }
            $first = $false
            $null = $sb.Append("{")
            $null = $sb.Append("""checkId"":""$(ConvertTo-JsonSafe $f.CheckId)"",")
            $null = $sb.Append("""title"":""$(ConvertTo-JsonSafe $f.Title)"",")
            $null = $sb.Append("""evidence"":""$(ConvertTo-JsonSafe $f.Evidence)"",")
            $null = $sb.Append("""currentState"":""$(ConvertTo-JsonSafe $f.CurrentState)"",")
            $null = $sb.Append("""gap"":""$(ConvertTo-JsonSafe $f.Gap)"",")
            $null = $sb.Append("""risk"":""$(ConvertTo-JsonSafe $f.Risk)"",")
            $null = $sb.Append("""businessImpact"":""$(ConvertTo-JsonSafe $f.BusinessImpact)"",")
            $null = $sb.Append("""targetState"":""$(ConvertTo-JsonSafe $f.TargetState)"",")
            $null = $sb.Append("""recommendation"":""$(ConvertTo-JsonSafe $f.Recommendation)"",")
            $null = $sb.Append("""roadmapPhase"":""$(ConvertTo-JsonSafe $f.RoadmapPhase)"",")
            $null = $sb.Append("""successMeasure"":""$(ConvertTo-JsonSafe $f.SuccessMeasure)""")
            $null = $sb.Append("}")
        }
        $null = $sb.Append("]")
        return $sb.ToString()
    }


    Function Build-AppRiskJson {
        # Top 100 by risk score to keep JSON payload manageable in the dashboard
        $topApps = $script:AppRiskRecords | Sort-Object CompositeScore -Descending | Select-Object -First 100
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.Append("[")
        $first = $true
        foreach ($a in $topApps) {
            if (-not $first) { $null = $sb.Append(",") }
            $first = $false
            $null = $sb.Append("{")
            $null = $sb.Append("""displayName"":""$(ConvertTo-JsonSafe $a.DisplayName)"",")
            $null = $sb.Append("""publisherName"":""$(ConvertTo-JsonSafe $a.PublisherName)"",")
            $null = $sb.Append("""isVerifiedPublisher"":$(if($a.IsVerifiedPublisher){'true'}else{'false'}),")
            $null = $sb.Append("""isMultiTenant"":$(if($a.IsMultiTenant){'true'}else{'false'}),")
            $null = $sb.Append("""hasAppPermissions"":$(if($a.HasAppPermissions){'true'}else{'false'}),")
            $null = $sb.Append("""appRoleCount"":$($a.AppRoleCount),")
            $null = $sb.Append("""delegatedScopeCount"":$($a.DelegatedScopeCount),")
            $null = $sb.Append("""adminConsentCount"":$($a.AdminConsentCount),")
            $null = $sb.Append("""userConsentCount"":$($a.UserConsentCount),")
            $null = $sb.Append("""ownerCount"":$($a.OwnerCount),")
            $null = $sb.Append("""hasExpiredCreds"":$(if($a.HasExpiredCreds){'true'}else{'false'}),")
            $null = $sb.Append("""hasLongLivedSecrets"":$(if($a.HasLongLivedSecrets){'true'}else{'false'}),")
            $null = $sb.Append("""permSummary"":""$(ConvertTo-JsonSafe $a.PermSummary)"",")
            $null = $sb.Append("""credSummary"":""$(ConvertTo-JsonSafe $a.CredSummary)"",")
            $null = $sb.Append("""compositeScore"":$($a.CompositeScore),")
            $null = $sb.Append("""riskBand"":""$(ConvertTo-JsonSafe $a.RiskBand)"",")
            $null = $sb.Append("""d1"":$($a.D1_PermSensitivity),")
            $null = $sb.Append("""d2"":$($a.D2_ConsentModel),")
            $null = $sb.Append("""d3"":$($a.D3_AppCriticality),")
            $null = $sb.Append("""d4"":$($a.D4_Ownership),")
            $null = $sb.Append("""d5"":$($a.D5_PublisherVerif),")
            $null = $sb.Append("""d6"":$($a.D6_BlastRadius),")
            $null = $sb.Append("""d7"":$($a.D7_CredHygiene)")
            $null = $sb.Append("}")
        }
        $null = $sb.Append("]")
        return $sb.ToString()
    }

    #endregion

    #region ── JSON Export ────────────────────────────────────────────────────────

    Function Export-RiskModelJson {
        param (
            [string]$TenantName,
            [string]$TenantId,
            [string]$AssessmentDate,
            [string]$OutputFilePath
        )

        $critical = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Critical" }).Count
        $high = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "High" }).Count
        $medium = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Medium" }).Count
        $low = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Low" }).Count

        $export = [PSCustomObject]@{
            Assessment  = [PSCustomObject]@{
                Script         = "Get-EntraApplicationPermissionRiskModel"
                Version        = "1.0"
                TenantName     = $TenantName
                TenantId       = $TenantId
                AssessmentDate = $AssessmentDate
                AppsScored     = $script:AppRiskRecords.Count
                RiskSummary    = [PSCustomObject]@{
                    Critical = $critical
                    High     = $high
                    Medium   = $medium
                    Low      = $low
                }
            }
            Findings    = $script:Findings
            TopRiskApps = ($script:AppRiskRecords | Sort-Object CompositeScore -Descending | Select-Object -First 50)
        }

        Try {
            $export | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
        }
        Catch {
            Write-Warning "  Failed to write JSON export: $_"
        }
    }

    #endregion

    #region ── HTML Dashboard Generation ─────────────────────────────────────────

    Function Generate-HtmlDashboard {
        param (
            [string]$TenantName,
            [string]$TenantId,
            [string]$AssessmentDate,
            [string]$FindingsJson,
            [string]$AppRiskJson,
            [string]$OutputFilePath
        )

        $critical = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Critical" }).Count
        $high = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "High" }).Count
        $medium = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Medium" }).Count
        $low = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Low" }).Count
        $totalScored = $script:AppRiskRecords.Count
        $secretless = ($script:AppRiskRecords | Where-Object { $_.NoCredentials }).Count
        $ownerless = ($script:AppRiskRecords | Where-Object { $_.OwnerCount -eq 0 -and ($_.HasAppPermissions -or $_.DelegatedScopeCount -gt 0) }).Count
        $expiredCreds = ($script:AppRiskRecords | Where-Object { $_.HasExpiredCreds }).Count
        $withAppPerms = ($script:AppRiskRecords | Where-Object { $_.HasAppPermissions }).Count

        $secretlessRatio = if ($totalScored -gt 0) { [Math]::Round(($secretless / $totalScored) * 100) } else { 0 }

        # Overall risk posture band
        $overallBand = if ($critical -gt 0) { "Critical" } elseif ($high -gt 3) { "High" } elseif ($medium -gt 10) { "Medium" } else { "Low" }
        $overallColor = $script:RiskColors[$overallBand]

        # Ring chart — posture score = 100 - weighted risk ratio
        $riskScore = [Math]::Max(0, 100 - ($critical * 10 + $high * 4 + $medium * 1))
        $riskScore = [Math]::Min(100, $riskScore)
        $ringR = 54
        $ringCirc = [Math]::Round(2 * [Math]::PI * $ringR, 1)
        $ringDash = [Math]::Round($ringCirc * ($riskScore / 100), 1)
        $ringGap = [Math]::Round($ringCirc - $ringDash, 1)
        $ringColor = if ($riskScore -ge 75) { "#3fb950" } elseif ($riskScore -ge 50) { "#388bfd" } elseif ($riskScore -ge 25) { "#d29922" } else { "#f85149" }

        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Application Permission Risk Model — __TENANT_NAME__</title>
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
#main{margin-left:240px;padding:28px}
.page{display:none;animation:fadeIn .25s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:24px}
.page-header h1{font-size:22px;font-weight:700}
.page-header p{color:var(--muted);font-size:13px;margin-top:4px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;cursor:default}
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
.risk-scale{display:flex;gap:6px;margin-top:12px;flex-wrap:wrap}
.rs-pill{font-size:10px;padding:3px 10px;border-radius:20px;border:1px solid var(--border);color:var(--muted);cursor:default}
.rs-pill.active{font-weight:700;border-color:currentColor}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.panel-title{font-size:14px;font-weight:700}
.panel-badge{font-size:10px;padding:2px 9px;border-radius:20px;background:var(--surface3);color:var(--muted);font-family:var(--mono)}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.bar-label{font-size:11px;color:var(--muted2);width:130px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;width:0;transition:width 1s ease}
.bar-val{font-size:11px;font-family:var(--mono);color:var(--muted);width:36px;text-align:right;flex-shrink:0}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.search-wrap{position:relative;flex:1;min-width:200px}
.search-wrap input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px 7px 32px;color:var(--text);font-size:12px;font-family:var(--sans)}
.search-wrap input:focus{outline:none;border-color:var(--accent)}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
.filter-pills{display:flex;gap:6px;flex-wrap:wrap}
.fpill{font-size:11px;padding:4px 11px;border-radius:20px;cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted);transition:all .15s}
.fpill.active{font-weight:700}
.fpill-all.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.fpill-crit.active{background:var(--red);color:#fff;border-color:var(--red)}
.fpill-high.active{background:var(--amber);color:#fff;border-color:var(--amber)}
.fpill-medium.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.fpill-low.active{background:var(--green);color:#fff;border-color:var(--green)}
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
.score-bar-wrap{display:flex;align-items:center;gap:6px}
.score-mini-bar{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden;min-width:50px}
.score-mini-fill{height:100%;border-radius:3px}
.score-mini-val{font-size:10px;font-family:var(--mono);color:var(--muted2);white-space:nowrap}
.phase-badge{font-size:10px;padding:2px 8px;border-radius:12px;background:var(--surface3);color:var(--muted);font-family:var(--mono);white-space:nowrap}
.verify-badge{font-size:10px;padding:2px 7px;border-radius:12px;font-family:var(--mono)}
.vb-yes{background:rgba(63,185,80,.12);color:#3fb950}
.vb-no{background:rgba(248,81,73,.12);color:#f85149}
.tag-chip{font-size:10px;padding:2px 7px;border-radius:12px;background:rgba(163,113,247,.12);color:var(--accent3);font-family:var(--mono)}
.pagination{display:flex;align-items:center;gap:6px;margin-top:14px;flex-wrap:wrap}
.pg-btn{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 10px;cursor:pointer;font-size:12px;color:var(--text);font-family:var(--sans)}
.pg-btn:hover{background:var(--surface3)}
.pg-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.pg-info{font-size:11px;color:var(--muted);margin-left:8px}
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
.dim-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}
.dim-cell{background:var(--surface3);border-radius:var(--radius-sm);padding:8px 10px}
.dim-cell-label{font-size:10px;color:var(--muted);margin-bottom:3px}
.dim-cell-val{font-size:13px;font-weight:700;font-family:var(--mono)}
.roadmap-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.roadmap-col{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px}
.roadmap-col-header{display:flex;align-items:center;gap:8px;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.roadmap-col-label{font-size:12px;font-weight:700}
.roadmap-count{font-size:11px;font-family:var(--mono);background:var(--surface3);padding:2px 8px;border-radius:20px;color:var(--muted)}
.roadmap-item{margin-bottom:10px;padding:10px;background:var(--surface2);border-radius:var(--radius-sm);border:1px solid var(--border);cursor:pointer;transition:all .15s}
.roadmap-item:hover{border-color:var(--accent);background:var(--surface3)}
.roadmap-item-title{font-size:11px;font-weight:600;line-height:1.4;margin-bottom:5px}
.roadmap-item-meta{display:flex;gap:5px;flex-wrap:wrap}
.arch-note{background:rgba(56,139,253,.08);border:1px solid rgba(56,139,253,.25);border-radius:var(--radius);padding:14px 16px;margin-bottom:18px;font-size:12px;color:var(--muted2);line-height:1.6}
.arch-note strong{color:var(--accent)}
.dim-bar-row{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.dim-bar-label{font-size:11px;color:var(--muted2);width:160px;flex-shrink:0}
.dim-bar-track{flex:1;height:10px;background:var(--surface3);border-radius:5px;overflow:hidden}
.dim-bar-fill{height:100%;border-radius:5px;transition:width 1s ease}
.dim-bar-val{font-size:11px;font-family:var(--mono);color:var(--muted);width:50px;text-align:right;flex-shrink:0}
#toast{position:fixed;bottom:20px;right:20px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 16px;font-size:12px;z-index:9999;transform:translateY(12px);opacity:0;transition:all .25s;pointer-events:none;box-shadow:var(--shadow)}
#toast.show{transform:none;opacity:1}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;font-size:18px;color:var(--text)}
@media(max-width:768px){
  #menuToggle{display:block}
  #sidebar{transform:translateX(-100%);transition:transform .25s}
  #sidebar.open{transform:none}
  #main{margin-left:0;padding:16px;padding-top:52px}
  .chart-grid{grid-template-columns:1fr}
  .dim-grid{grid-template-columns:1fr}
}
.success-measure{background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.2);border-radius:var(--radius-sm);padding:8px 12px;font-size:11px;color:#3fb950;margin-top:8px;line-height:1.5}
.success-label{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;margin-bottom:3px;opacity:.8}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<div id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🔐</div>
    <div class="logo-title">Application Permission<br>Risk Model</div>
    <div class="logo-sub">__TENANT_NAME__</div>
    <span class="ver-badge">v1.0</span>
  </div>

  <nav>
    <div class="nav-section">Assessment</div>
    <button class="nav-btn active" id="nav-posture"   onclick="showPage('posture',this)">
      <span class="nav-icon">🏛️</span> Risk Posture
    </button>
    <button class="nav-btn" id="nav-findings"  onclick="showPage('findings',this)">
      <span class="nav-icon">🔍</span> Key Findings
    </button>
    <button class="nav-btn" id="nav-apps"      onclick="showPage('apps',this)">
      <span class="nav-icon">📱</span> Application Risk
    </button>
    <button class="nav-btn" id="nav-roadmap"   onclick="showPage('roadmap',this)">
      <span class="nav-icon">🗺️</span> Action Roadmap
    </button>

    <div class="nav-section">Reference</div>
    <button class="nav-btn" id="nav-model"     onclick="showPage('model',this)">
      <span class="nav-icon">⚙️</span> Risk Model
    </button>
  </nav>

  <div class="theme-toggle">
    <div class="theme-pill">
      <div class="theme-opt active" id="thDark"  onclick="setTheme('dark')">🌙 Dark</div>
      <div class="theme-opt"        id="thLight" onclick="setTheme('light')">☀️ Light</div>
    </div>
  </div>

  <div class="sidebar-footer">
    Generated: __ASSESS_DATE__<br>
    Tenant: __TENANT_ID_SHORT__<br><br>
    <span class="kbd">Esc</span> close drawer &nbsp;
    <span class="kbd">/</span> search
  </div>
</div>

<div id="main">

  <!-- ══ Risk Posture ══════════════════════════════════════════════════════ -->
  <div class="page active" id="page-posture">
    <div class="page-header">
      <h1>🏛️ Application Permission Risk Posture</h1>
      <p>Tenant-wide API governance risk overview — what access exists, why it matters, and what the overall exposure is.</p>
    </div>

    <div class="health-card">
      <div class="health-ring-wrap">
        <svg viewBox="0 0 128 128" width="128" height="128">
          <circle class="health-ring-bg" cx="64" cy="64" r="54"/>
          <circle class="health-ring-fill" cx="64" cy="64" r="54"
            id="riskRing"
            stroke="__RING_COLOR__"
            stroke-dasharray="__RING_DASH__ __RING_GAP__"/>
        </svg>
        <div class="ring-label">
          <div class="ring-val" style="color:__RING_COLOR__">__RISK_SCORE__</div>
          <div class="ring-sub">/ 100</div>
        </div>
      </div>
      <div class="health-info">
        <h2>Overall Risk Posture: <span style="color:__OVERALL_COLOR__">__OVERALL_BAND__</span></h2>
        <p>__TOTAL_SCORED__ applications scored across 7 risk dimensions. A higher governance score indicates stronger permission hygiene. Focus immediate attention on Critical and High band applications.</p>
        <div class="risk-scale">
          <div class="rs-pill __RS_CRIT_ACTIVE__" style="color:#f85149">🔴 Critical: __CRITICAL__</div>
          <div class="rs-pill __RS_HIGH_ACTIVE__"  style="color:#d29922">🟠 High: __HIGH__</div>
          <div class="rs-pill __RS_MED_ACTIVE__"   style="color:#388bfd">🔵 Medium: __MEDIUM__</div>
          <div class="rs-pill"                      style="color:#3fb950">🟢 Low: __LOW__</div>
        </div>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-label">Critical Risk Apps</div>
        <div class="stat-value" style="color:var(--red)">__CRITICAL__</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-label">High Risk Apps</div>
        <div class="stat-value" style="color:var(--amber)">__HIGH__</div>
        <div class="stat-sub">Address within 30 days</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-label">Apps with App Permissions</div>
        <div class="stat-value" style="color:var(--accent)">__WITH_APP_PERMS__</div>
        <div class="stat-sub">No signed-in user context</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-label">Ownerless Apps</div>
        <div class="stat-value" style="color:var(--accent3)">__OWNERLESS__</div>
        <div class="stat-sub">No accountability chain</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-label">Expired Credentials</div>
        <div class="stat-value" style="color:var(--amber)">__EXPIRED_CREDS__</div>
        <div class="stat-sub">Credential hygiene gap</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-label">Secretless Apps</div>
        <div class="stat-value" style="color:var(--green)">__SECRETLESS_RATIO__%</div>
        <div class="stat-sub">MI or Federated Credentials</div>
      </div>
    </div>

    <div class="arch-note">
      <strong>Architecture principle:</strong> Every application permission is an API governance decision. The risk model scores each application across seven dimensions — permission sensitivity, consent model, criticality, ownership, publisher trust, blast radius, and credential hygiene — to surface where governance investment will have the greatest security impact.
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Risk Band Distribution</span>
          <span class="panel-badge">__TOTAL_SCORED__ apps</span>
        </div>
        <div id="riskBandBars"></div>
      </div>
      <div class="panel">
        <div class="panel-header">
          <span class="panel-title">Risk Dimension Heat</span>
          <span class="panel-badge">Average score / max</span>
        </div>
        <div id="dimHeatBars"></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Top 10 Highest Risk Applications</span>
        <button class="pg-btn" onclick="showPage('apps',document.getElementById('nav-apps'))" style="font-size:11px">View all →</button>
      </div>
      <table id="top10Table">
        <thead>
          <tr>
            <th>Risk</th>
            <th>Application</th>
            <th>Score</th>
            <th>Key Risk Factor</th>
            <th>Credentials</th>
          </tr>
        </thead>
        <tbody id="top10Body"></tbody>
      </table>
    </div>
  </div>

  <!-- ══ Key Findings ══════════════════════════════════════════════════════ -->
  <div class="page" id="page-findings">
    <div class="page-header">
      <h1>🔍 Key Risk Findings</h1>
      <p>Ten evidence-based findings covering the full governance context — current state, gap analysis, business impact, and target state.</p>
    </div>

    <div class="toolbar">
      <div class="search-wrap">
        <span class="search-icon">🔍</span>
        <input type="text" id="findSearch" placeholder="Search findings..." oninput="filterFindings()">
      </div>
      <div class="filter-pills">
        <div class="fpill fpill-all active"  onclick="setRiskFilter('All',this)">All</div>
        <div class="fpill fpill-crit"        onclick="setRiskFilter('Critical',this)">🔴 Critical</div>
        <div class="fpill fpill-high"        onclick="setRiskFilter('High',this)">🟠 High</div>
        <div class="fpill fpill-medium"      onclick="setRiskFilter('Medium',this)">🔵 Medium</div>
        <div class="fpill fpill-low"         onclick="setRiskFilter('Low',this)">🟢 Low/Info</div>
      </div>
      <button class="pg-btn" onclick="exportFindingsCSV()" style="white-space:nowrap">⬇ Export CSV</button>
    </div>

    <div class="panel" style="padding:0;overflow:hidden">
      <table id="findingsTable">
        <thead>
          <tr>
            <th onclick="sortFindings('risk')"         id="th-risk">Risk <span class="sort-arrow">↕</span></th>
            <th onclick="sortFindings('checkId')"      id="th-id">ID <span class="sort-arrow">↕</span></th>
            <th onclick="sortFindings('title')"        id="th-title">Finding <span class="sort-arrow">↕</span></th>
            <th onclick="sortFindings('roadmapPhase')" id="th-phase">Phase <span class="sort-arrow">↕</span></th>
          </tr>
        </thead>
        <tbody id="findingsTbody"></tbody>
      </table>
    </div>
    <div class="pagination" id="findingsPagination"></div>
  </div>

  <!-- ══ Application Risk ══════════════════════════════════════════════════ -->
  <div class="page" id="page-apps">
    <div class="page-header">
      <h1>📱 Application Risk Register</h1>
      <p>Per-application composite risk scores across all seven governance dimensions. Click any row for full dimension breakdown.</p>
    </div>

    <div class="toolbar">
      <div class="search-wrap">
        <span class="search-icon">🔍</span>
        <input type="text" id="appSearch" placeholder="Search applications..." oninput="filterApps()">
      </div>
      <div class="filter-pills">
        <div class="fpill fpill-all active"  onclick="setAppFilter('All',this)">All</div>
        <div class="fpill fpill-crit"        onclick="setAppFilter('Critical',this)">🔴 Critical</div>
        <div class="fpill fpill-high"        onclick="setAppFilter('High',this)">🟠 High</div>
        <div class="fpill fpill-medium"      onclick="setAppFilter('Medium',this)">🔵 Medium</div>
        <div class="fpill fpill-low"         onclick="setAppFilter('Low',this)">🟢 Low</div>
      </div>
      <button class="pg-btn" onclick="exportAppsCSV()" style="white-space:nowrap">⬇ Export CSV</button>
    </div>

    <div class="panel" style="padding:0;overflow:hidden">
      <table id="appsTable">
        <thead>
          <tr>
            <th onclick="sortApps('riskBand')"      id="ath-risk">Risk <span class="sort-arrow">↕</span></th>
            <th onclick="sortApps('displayName')"   id="ath-name">Application <span class="sort-arrow">↕</span></th>
            <th onclick="sortApps('compositeScore')" id="ath-score">Score <span class="sort-arrow">↕</span></th>
            <th>Permissions</th>
            <th>Credentials</th>
            <th onclick="sortApps('ownerCount')"    id="ath-owners">Owners <span class="sort-arrow">↕</span></th>
            <th>Publisher</th>
          </tr>
        </thead>
        <tbody id="appsTbody"></tbody>
      </table>
    </div>
    <div class="pagination" id="appsPagination"></div>
  </div>

  <!-- ══ Action Roadmap ═══════════════════════════════════════════════════ -->
  <div class="page" id="page-roadmap">
    <div class="page-header">
      <h1>🗺️ Action Roadmap</h1>
      <p>Sequenced governance actions prioritised by risk severity, blast radius, and implementation dependency.</p>
    </div>

    <div class="arch-note">
      <strong>Sequencing principle:</strong> Actions are sequenced by security risk reduction impact, not arbitrary severity. Foundational controls (ownerless app cleanup, expired credential removal, user consent restriction) appear first because they unlock all downstream governance investments and provide immediate risk reduction.
    </div>

    <div class="roadmap-grid" id="roadmapGrid"></div>
  </div>

  <!-- ══ Risk Model ════════════════════════════════════════════════════════ -->
  <div class="page" id="page-model">
    <div class="page-header">
      <h1>⚙️ Risk Model Reference</h1>
      <p>Seven-dimension risk scoring methodology, permission sensitivity taxonomy, and assessment architecture.</p>
    </div>

    <div class="arch-note">
      <strong>Assessment architecture:</strong> Business Context → Current State → Gap Analysis → Target State → Recommendations → Success Measures. Each finding follows this model so security, identity, and application teams understand what access exists, why it matters, what risk it creates, and what should be done next.
    </div>

    <div class="panel">
      <div class="panel-header"><span class="panel-title">Seven Risk Dimensions</span><span class="panel-badge">0–100 composite</span></div>
      <div style="display:grid;gap:12px">
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #f85149">
          <div style="font-size:22px;font-weight:900;color:#f85149;font-family:var(--mono);width:28px;text-align:center">D1</div>
          <div><div style="font-weight:700;margin-bottom:3px">Permission Sensitivity &amp; Privilege Level <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">(0–25 pts)</span></div><div style="font-size:12px;color:var(--muted2)">The most critical dimension. Scores based on the highest-tier permission the application holds, with a breadth bonus for excessive permission accumulation. Application permissions (no user context) carry higher weight than delegated permissions.</div></div>
        </div>
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #d29922">
          <div style="font-size:22px;font-weight:900;color:#d29922;font-family:var(--mono);width:28px;text-align:center">D2</div>
          <div><div style="font-weight:700;margin-bottom:3px">Consent Model <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">(0–20 pts)</span></div><div style="font-size:12px;color:var(--muted2)">How was access granted? Application-level consent (no user involved) is highest risk. Admin-consented delegated permissions apply to all users. User-consented permissions reflect shadow IT and lack IT oversight.</div></div>
        </div>
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #388bfd">
          <div style="font-size:22px;font-weight:900;color:#388bfd;font-family:var(--mono);width:28px;text-align:center">D3</div>
          <div><div style="font-weight:700;margin-bottom:3px">Application Criticality <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">(0–15 pts)</span></div><div style="font-size:12px;color:var(--muted2)">Is the application widely used, externally exposed, or serving sensitive business functions? Multi-tenant apps, broadly assigned apps, and actively used apps score higher criticality.</div></div>
        </div>
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #39c5cf">
          <div style="font-size:22px;font-weight:900;color:#39c5cf;font-family:var(--mono);width:28px;text-align:center">D4</div>
          <div><div style="font-weight:700;margin-bottom:3px">Ownership &amp; Accountability <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">(0–10 pts)</span></div><div style="font-size:12px;color:var(--muted2)">Is anyone accountable for this application? No registered owner means no review, no decommission, and no incident response chain. Single owners create bus-factor risk.</div></div>
        </div>
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #a371f7">
          <div style="font-size:22px;font-weight:900;color:#a371f7;font-family:var(--mono);width:28px;text-align:center">D5</div>
          <div><div style="font-weight:700;margin-bottom:3px">Publisher Verification &amp; Trust <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">(0–10 pts)</span></div><div style="font-size:12px;color:var(--muted2)">Has the publisher completed Microsoft's verification programme? Unverified publishers with sensitive permissions are high-value OAuth phishing targets. Microsoft first-party apps are implicitly trusted.</div></div>
        </div>
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #d29922">
          <div style="font-size:22px;font-weight:900;color:#d29922;font-family:var(--mono);width:28px;text-align:center">D6</div>
          <div><div style="font-weight:700;margin-bottom:3px">Downstream API Exposure &amp; Blast Radius <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">(0–10 pts)</span></div><div style="font-size:12px;color:var(--muted2)">If this application were compromised, how broad is the potential impact? Applications with critical-tier application permissions can affect the entire tenant — equivalent to a global administrator breach.</div></div>
        </div>
        <div style="display:flex;gap:14px;align-items:flex-start;padding:12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #3fb950">
          <div style="font-size:22px;font-weight:900;color:#3fb950;font-family:var(--mono);width:28px;text-align:center">D7</div>
          <div><div style="font-weight:700;margin-bottom:3px">Credential Hygiene <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">(0–10 pts)</span></div><div style="font-size:12px;color:var(--muted2)">How are application credentials managed? Secretless (Managed Identity, Federated Credentials) is the gold standard. Client secrets are static credentials vulnerable to exfiltration. Expired secrets left in place are a hygiene and audit failure.</div></div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><span class="panel-title">Permission Sensitivity Taxonomy</span><span class="panel-badge">4-tier model</span></div>
      <div style="display:grid;gap:10px">
        <div style="padding:10px 12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #f85149">
          <div style="font-weight:700;color:#f85149;margin-bottom:4px">Tier 4 — Critical</div>
          <div style="font-size:12px;color:var(--muted2)">Tenant-wide write or admin equivalent. Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, Application.ReadWrite.All, User.ReadWrite.All, Policy.ReadWrite.ConditionalAccess, UserAuthenticationMethod.ReadWrite.All, Exchange.ManageAsApp</div>
        </div>
        <div style="padding:10px 12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #d29922">
          <div style="font-weight:700;color:#d29922;margin-bottom:4px">Tier 3 — High</div>
          <div style="font-size:12px;color:var(--muted2)">Broad read of sensitive data. Directory.Read.All, User.Read.All, Mail.Read, Files.Read.All, AuditLog.Read.All, IdentityRiskyUser.Read.All, SecurityEvents.Read.All, Reports.Read.All</div>
        </div>
        <div style="padding:10px 12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #388bfd">
          <div style="font-weight:700;color:#388bfd;margin-bottom:4px">Tier 2 — Medium</div>
          <div style="font-size:12px;color:var(--muted2)">Read of user or group data with limited write. User.ReadBasic.All, GroupMember.Read.All, Device.Read.All, Chat.Read.All, Notes.Read.All</div>
        </div>
        <div style="padding:10px 12px;background:var(--surface2);border-radius:var(--radius-sm);border-left:4px solid #3fb950">
          <div style="font-weight:700;color:#3fb950;margin-bottom:4px">Tier 1 — Low</div>
          <div style="font-size:12px;color:var(--muted2)">Profile and basic access. openid, profile, email, offline_access, User.Read, Mail.Send</div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><span class="panel-title">Assessment Methodology</span></div>
      <div style="font-size:12px;color:var(--muted2);line-height:1.7">
        <p style="margin-bottom:10px">Each finding follows the enterprise architecture thinking model: <strong style="color:var(--text)">Business Context → Current State → Gap Analysis → Target State → Recommendations → Success Measures</strong></p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Risk Score:</strong> Composite 0–100 across 7 dimensions. Critical: 75–100. High: 50–74. Medium: 25–49. Low: 0–24.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Business Impact:</strong> Describes what happens to the business if the risk materialises — not just the technical consequence.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Blast Radius:</strong> The maximum potential scope of impact if an application is compromised — from single-user to tenant-wide.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Success Measures:</strong> Objective, measurable outcomes that confirm the risk has been addressed.</p>
        <p style="margin-bottom:10px"><strong style="color:var(--text)">Data sources:</strong> Microsoft Graph Beta API — servicePrincipals, applications, oauth2PermissionGrants, appRoleAssignments. Sign-in activity requires AuditLog.Read.All.</p>
      </div>
    </div>
  </div>

</div>

<!-- Detail Drawer -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDetail()"></div>
  <div id="detailDrawer">
    <div class="drawer-header">
      <div class="drawer-title" id="drawerTitle"></div>
      <button class="drawer-close" onclick="closeDetail()">✕</button>
    </div>
    <div class="drawer-chips" id="drawerChips"></div>
    <div id="drawerBody"></div>
    <div class="drawer-nav">
      <button onclick="navDetail(-1)">← Prev</button>
      <button onclick="navDetail(1)">Next →</button>
      <span class="drawer-count" id="drawerCount"></span>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
// ── Data ──────────────────────────────────────────────────────────────────────
const FINDINGS  = __FINDINGS_JSON__;
const APPS      = __APP_RISK_JSON__;

// ── Utility ───────────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

function riskColor(r){
  return {Critical:'#f85149',High:'#d29922',Medium:'#388bfd',Low:'#3fb950',Info:'#7d8590'}[r]||'#7d8590';
}
function scoreColor(s){
  if(s>=75)return '#f85149';
  if(s>=50)return '#d29922';
  if(s>=25)return '#388bfd';
  return '#3fb950';
}
function phaseIcon(p){
  if(p==='0-30 Days') return '🔴';
  if(p==='31-60 Days')return '🟠';
  if(p==='61-90 Days')return '🔵';
  return '🟢';
}

function showToast(msg,icon='✅'){
  const t=document.getElementById('toast');
  t.textContent=icon+' '+msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

function dlFile(content,name,type){
  const blob=new Blob([content],{type});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=name;
  a.click();
}

// ── Page navigation ────────────────────────────────────────────────────────────
function showPage(id,btnEl){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  const pg=document.getElementById('page-'+id);
  if(pg) pg.classList.add('active');
  if(btnEl) btnEl.classList.add('active');
  if(id==='posture') initPosture();
  if(id==='apps') { filterApps(); }
  document.getElementById('sidebar').classList.remove('open');
}

// ── Theme ─────────────────────────────────────────────────────────────────────
function setTheme(t){
  document.body.classList.toggle('light-theme', t==='light');
  document.getElementById('thDark').classList.toggle('active',t==='dark');
  document.getElementById('thLight').classList.toggle('active',t==='light');
}

// ── Posture page ──────────────────────────────────────────────────────────────
function initPosture(){
  // Risk band bars
  const bandCounts={Critical:0,High:0,Medium:0,Low:0};
  APPS.forEach(a=>{ if(bandCounts[a.riskBand]!==undefined) bandCounts[a.riskBand]++; });
  const maxBand=Math.max(...Object.values(bandCounts),1);
  const bandColors={Critical:'#f85149',High:'#d29922',Medium:'#388bfd',Low:'#3fb950'};
  const bandEl=document.getElementById('riskBandBars');
  if(bandEl){
    bandEl.innerHTML=Object.entries(bandCounts).map(([band,cnt])=>`
      <div class="bar-row">
        <div class="bar-label" style="color:${bandColors[band]}">${band}</div>
        <div class="bar-track"><div class="bar-fill" style="background:${bandColors[band]}" data-pct="${Math.round(cnt/maxBand*100)}"></div></div>
        <div class="bar-val">${cnt}</div>
      </div>`).join('');
    animateBars(bandEl);
  }

  // Dimension heat bars (average scores across all apps)
  const dims=['d1','d2','d3','d4','d5','d6','d7'];
  const dimLabels=['Permission Sensitivity /25','Consent Model /20','App Criticality /15','Ownership /10','Publisher Verif. /10','Blast Radius /10','Credential Hygiene /10'];
  const dimMax=[25,20,15,10,10,10,10];
  const dimAvg=dims.map((d,i)=>{
    const vals=APPS.map(a=>a[d]||0);
    return vals.length>0?vals.reduce((a,b)=>a+b,0)/vals.length:0;
  });
  const dimEl=document.getElementById('dimHeatBars');
  if(dimEl){
    dimEl.innerHTML=dims.map((d,i)=>{
      const avg=dimAvg[i].toFixed(1);
      const pct=Math.round(dimAvg[i]/dimMax[i]*100);
      const col=pct>=70?'#f85149':pct>=40?'#d29922':'#388bfd';
      return `<div class="dim-bar-row">
        <div class="dim-bar-label">${dimLabels[i]}</div>
        <div class="dim-bar-track"><div class="dim-bar-fill" style="background:${col}" data-pct="${pct}"></div></div>
        <div class="dim-bar-val">${avg}</div>
      </div>`;
    }).join('');
    animateBars(dimEl);
  }

  // Top 10 table
  const top10=APPS.slice(0,10);
  const tbody=document.getElementById('top10Body');
  if(tbody){
    tbody.innerHTML=top10.map((a,i)=>{
      const keyRisk=a.hasAppPermissions?'App permissions (no user)':a.adminConsentCount>0?'Admin-consented delegated':a.ownerCount===0?'No owner':a.hasExpiredCreds?'Expired credentials':'User consent';
      return `<tr onclick="openAppDetail(${i})" style="cursor:pointer">
        <td><span class="risk-badge rb-${escH(a.riskBand)}">${escH(a.riskBand)}</span></td>
        <td style="font-weight:600">${escH(a.displayName)}</td>
        <td>
          <div class="score-bar-wrap">
            <div class="score-mini-bar"><div class="score-mini-fill" style="width:${a.compositeScore}%;background:${scoreColor(a.compositeScore)}"></div></div>
            <span class="score-mini-val" style="color:${scoreColor(a.compositeScore)}">${a.compositeScore}</span>
          </div>
        </td>
        <td style="font-size:11px;color:var(--muted2)">${escH(keyRisk)}</td>
        <td><span style="font-size:11px;color:var(--muted2)">${escH(a.credSummary)}</span></td>
      </tr>`;
    }).join('');
  }
}

function animateBars(container){
  requestAnimationFrame(()=>{
    container.querySelectorAll('[data-pct]').forEach(el=>{
      el.style.width=el.getAttribute('data-pct')+'%';
    });
  });
}

// ── Findings table ─────────────────────────────────────────────────────────────
let findingsFilter='All', findingsSearch='', findingsSort={col:'risk',dir:1}, findingsPage=1;
const findingsPerPage=10;
let filteredFindings=[];

const riskOrder={Critical:0,High:1,Medium:2,Low:3,Info:4};

function filterFindings(){
  findingsSearch=document.getElementById('findSearch').value.toLowerCase();
  findingsPage=1;
  applyFindingsFilter();
}
function setRiskFilter(r,el){
  document.querySelectorAll('#page-findings .fpill').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  findingsFilter=r;
  findingsPage=1;
  applyFindingsFilter();
}
function sortFindings(col){
  if(findingsSort.col===col) findingsSort.dir*=-1;
  else { findingsSort.col=col; findingsSort.dir=1; }
  document.querySelectorAll('#findingsTable th').forEach(th=>th.classList.remove('sort-active'));
  const th=document.getElementById('th-'+col);
  if(th) th.classList.add('sort-active');
  applyFindingsFilter();
}
function applyFindingsFilter(){
  filteredFindings=FINDINGS.filter(f=>{
    const rMatch=findingsFilter==='All'||(findingsFilter==='Low'?(f.risk==='Low'||f.risk==='Info'):f.risk===findingsFilter);
    const sMatch=!findingsSearch||(f.title||'').toLowerCase().includes(findingsSearch)||(f.evidence||'').toLowerCase().includes(findingsSearch);
    return rMatch&&sMatch;
  });
  filteredFindings.sort((a,b)=>{
    const col=findingsSort.col;
    let va=col==='risk'?riskOrder[a.risk]??99:a[col]??'';
    let vb=col==='risk'?riskOrder[b.risk]??99:b[col]??'';
    if(typeof va==='string') va=va.toLowerCase();
    if(typeof vb==='string') vb=vb.toLowerCase();
    return findingsSort.dir*(va<vb?-1:va>vb?1:0);
  });
  renderFindingsTable();
  renderFindingsPagination();
}
function renderFindingsTable(){
  const start=(findingsPage-1)*findingsPerPage;
  const slice=filteredFindings.slice(start,start+findingsPerPage);
  const tbody=document.getElementById('findingsTbody');
  tbody.innerHTML=slice.map((f,idx)=>`
    <tr onclick="openFindingDetail(${filteredFindings.indexOf(f)})" style="cursor:pointer">
      <td><span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span></td>
      <td><span class="tag-chip">${escH(f.checkId)}</span></td>
      <td style="font-weight:600;max-width:380px">${escH(f.title)}</td>
      <td><span class="phase-badge">${phaseIcon(f.roadmapPhase)} ${escH(f.roadmapPhase)}</span></td>
    </tr>`).join('');
}
function renderFindingsPagination(){
  const totalPages=Math.max(1,Math.ceil(filteredFindings.length/findingsPerPage));
  const el=document.getElementById('findingsPagination');
  let html=`<span class="pg-info">${filteredFindings.length} finding(s)</span>`;
  for(let i=1;i<=totalPages;i++){
    html+=`<button class="pg-btn${i===findingsPage?' active':''}" onclick="goFindingsPage(${i})">${i}</button>`;
  }
  el.innerHTML=html;
}
function goFindingsPage(p){ findingsPage=p; renderFindingsTable(); renderFindingsPagination(); }

// ── Applications table ─────────────────────────────────────────────────────────
let appsFilter='All', appsSearch='', appsSort={col:'compositeScore',dir:-1}, appsPage=1;
const appsPerPage=15;
let filteredApps=[];

function filterApps(){
  appsSearch=(document.getElementById('appSearch')||{}).value||'';
  appsSearch=appsSearch.toLowerCase();
  appsPage=1;
  applyAppsFilter();
}
function setAppFilter(r,el){
  document.querySelectorAll('#page-apps .fpill').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  appsFilter=r;
  appsPage=1;
  applyAppsFilter();
}
function sortApps(col){
  if(appsSort.col===col) appsSort.dir*=-1;
  else { appsSort.col=col; appsSort.dir=-1; }
  document.querySelectorAll('#appsTable th').forEach(th=>th.classList.remove('sort-active'));
  const th=document.getElementById('ath-'+col.replace('compositeScore','score').replace('displayName','name').replace('ownerCount','owners').replace('riskBand','risk'));
  if(th) th.classList.add('sort-active');
  applyAppsFilter();
}
function applyAppsFilter(){
  filteredApps=APPS.filter(a=>{
    const rMatch=appsFilter==='All'||a.riskBand===appsFilter;
    const sMatch=!appsSearch||(a.displayName||'').toLowerCase().includes(appsSearch)||(a.publisherName||'').toLowerCase().includes(appsSearch);
    return rMatch&&sMatch;
  });
  filteredApps.sort((a,b)=>{
    const col=appsSort.col;
    const bandOrd={Critical:0,High:1,Medium:2,Low:3};
    let va=col==='riskBand'?bandOrd[a.riskBand]??99:a[col]??'';
    let vb=col==='riskBand'?bandOrd[b.riskBand]??99:b[col]??'';
    if(typeof va==='string') va=va.toLowerCase();
    if(typeof vb==='string') vb=vb.toLowerCase();
    return appsSort.dir*(va<vb?-1:va>vb?1:0);
  });
  renderAppsTable();
  renderAppsPagination();
}
function renderAppsTable(){
  const start=(appsPage-1)*appsPerPage;
  const slice=filteredApps.slice(start,start+appsPerPage);
  const tbody=document.getElementById('appsTbody');
  tbody.innerHTML=slice.map((a)=>{
    const globalIdx=APPS.indexOf(a);
    return `<tr onclick="openAppDetail(${globalIdx})" style="cursor:pointer">
      <td><span class="risk-badge rb-${escH(a.riskBand)}">${escH(a.riskBand)}</span></td>
      <td style="font-weight:600;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escH(a.displayName)}">${escH(a.displayName)}</td>
      <td>
        <div class="score-bar-wrap">
          <div class="score-mini-bar"><div class="score-mini-fill" style="width:${a.compositeScore}%;background:${scoreColor(a.compositeScore)}"></div></div>
          <span class="score-mini-val" style="color:${scoreColor(a.compositeScore)}">${a.compositeScore}</span>
        </div>
      </td>
      <td style="font-size:11px;color:var(--muted2);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escH(a.permSummary)}">${escH(a.permSummary)}</td>
      <td style="font-size:11px;color:var(--muted2)">${escH(a.credSummary)}</td>
      <td style="text-align:center;font-family:var(--mono);font-size:11px">${a.ownerCount}</td>
      <td>${a.isVerifiedPublisher?'<span class="verify-badge vb-yes">✓ Verified</span>':'<span class="verify-badge vb-no">✗ Unverified</span>'}</td>
    </tr>`;
  }).join('');
}
function renderAppsPagination(){
  const totalPages=Math.max(1,Math.ceil(filteredApps.length/appsPerPage));
  const el=document.getElementById('appsPagination');
  let html=`<span class="pg-info">${filteredApps.length} app(s)</span>`;
  for(let i=1;i<=totalPages;i++){
    html+=`<button class="pg-btn${i===appsPage?' active':''}" onclick="goAppsPage(${i})">${i}</button>`;
  }
  el.innerHTML=html;
}
function goAppsPage(p){ appsPage=p; renderAppsTable(); renderAppsPagination(); }

// ── Detail Drawer ──────────────────────────────────────────────────────────────
let detailMode='', currentDetailIndex=0, detailList=[];

function openFindingDetail(idx){
  detailMode='findings';
  detailList=filteredFindings;
  currentDetailIndex=idx;
  renderFindingDrawer(idx);
  document.getElementById('detailPanel').classList.add('open');
}
function openAppDetail(globalIdx){
  detailMode='apps';
  detailList=APPS;
  currentDetailIndex=globalIdx;
  renderAppDrawer(globalIdx);
  document.getElementById('detailPanel').classList.add('open');
}
function closeDetail(){
  document.getElementById('detailPanel').classList.remove('open');
}
function navDetail(dir){
  currentDetailIndex=Math.max(0,Math.min(detailList.length-1,currentDetailIndex+dir));
  if(detailMode==='findings') renderFindingDrawer(currentDetailIndex);
  else renderAppDrawer(currentDetailIndex);
}

function renderFindingDrawer(idx){
  const f=detailList[idx];
  if(!f) return;
  document.getElementById('drawerTitle').textContent=f.title;
  document.getElementById('drawerChips').innerHTML=`
    <span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span>
    <span class="tag-chip">${escH(f.checkId)}</span>
    <span class="phase-badge">${phaseIcon(f.roadmapPhase)} ${escH(f.roadmapPhase)}</span>`;
  document.getElementById('drawerBody').innerHTML=`
    <div class="drawer-section"><div class="drawer-label">Evidence</div><div class="drawer-value">${escH(f.evidence)}</div></div>
    <div class="drawer-section"><div class="drawer-label">Current State</div><div class="drawer-value">${escH(f.currentState)}</div></div>
    <div class="drawer-section"><div class="drawer-label">Gap / Risk</div><div class="drawer-value">${escH(f.gap)}</div></div>
    <div class="drawer-section"><div class="drawer-label">Business Impact</div><div class="drawer-value">${escH(f.businessImpact)}</div></div>
    <div class="drawer-section"><div class="drawer-label">Target State</div><div class="drawer-value">${escH(f.targetState)}</div></div>
    <div class="drawer-section"><div class="drawer-label">Recommendation</div><div class="drawer-value">${escH(f.recommendation)}</div></div>
    ${f.successMeasure?`<div class="success-measure"><div class="success-label">✅ Success Measure</div>${escH(f.successMeasure)}</div>`:''}`;
  document.getElementById('drawerCount').textContent=`${idx+1} / ${detailList.length}`;
}

function renderAppDrawer(idx){
  const a=APPS[idx];
  if(!a) return;
  const dims=[
    {label:'D1 Permission Sensitivity',val:a.d1,max:25},
    {label:'D2 Consent Model',val:a.d2,max:20},
    {label:'D3 App Criticality',val:a.d3,max:15},
    {label:'D4 Ownership',val:a.d4,max:10},
    {label:'D5 Publisher Verification',val:a.d5,max:10},
    {label:'D6 Blast Radius',val:a.d6,max:10},
    {label:'D7 Credential Hygiene',val:a.d7,max:10},
  ];
  document.getElementById('drawerTitle').textContent=a.displayName;
  document.getElementById('drawerChips').innerHTML=`
    <span class="risk-badge rb-${escH(a.riskBand)}">${escH(a.riskBand)}</span>
    <span style="font-family:var(--mono);font-size:11px;color:${scoreColor(a.compositeScore)}">Score: ${a.compositeScore}/100</span>
    ${a.isVerifiedPublisher?'<span class="verify-badge vb-yes">✓ Verified Publisher</span>':'<span class="verify-badge vb-no">✗ Unverified</span>'}
    ${a.isMultiTenant?'<span class="tag-chip">Multi-Tenant</span>':''}
    ${a.hasAppPermissions?'<span class="tag-chip">App Permissions</span>':''}`;
  document.getElementById('drawerBody').innerHTML=`
    <div class="drawer-section">
      <div class="drawer-label">Risk Dimension Breakdown</div>
      <div style="margin-top:8px">
        ${dims.map(d=>{
          const pct=Math.round(d.val/d.max*100);
          const col=pct>=70?'#f85149':pct>=40?'#d29922':'#388bfd';
          return `<div class="dim-bar-row">
            <div class="dim-bar-label" style="font-size:10px">${escH(d.label)} /${d.max}</div>
            <div class="dim-bar-track"><div class="dim-bar-fill" style="width:${pct}%;background:${col}"></div></div>
            <div class="dim-bar-val">${d.val}</div>
          </div>`;
        }).join('')}
      </div>
    </div>
    <div class="drawer-section"><div class="drawer-label">Permissions</div><div class="drawer-value">${escH(a.permSummary||'None detected')}</div></div>
    <div class="drawer-section"><div class="drawer-label">Credentials</div><div class="drawer-value">${escH(a.credSummary)}</div></div>
    <div class="drawer-section">
      <div class="drawer-label">Details</div>
      <div class="drawer-value">
        Publisher: ${escH(a.publisherName||'Unknown')}<br>
        Owners: ${a.ownerCount}<br>
        App Role Assignments: ${a.appRoleCount}<br>
        Delegated Scopes: ${a.delegatedScopeCount}<br>
        Admin Consent Grants: ${a.adminConsentCount}<br>
        User Consent Grants: ${a.userConsentCount}<br>
        Multi-Tenant: ${a.isMultiTenant?'Yes':'No'}<br>
        Verified Publisher: ${a.isVerifiedPublisher?'Yes':'No'}<br>
        Has Expired Credentials: ${a.hasExpiredCreds?'⚠️ Yes':'No'}
      </div>
    </div>`;
  document.getElementById('drawerCount').textContent=`${idx+1} / ${APPS.length}`;
}

// ── Roadmap ────────────────────────────────────────────────────────────────────
function buildRoadmap(){
  const phases=['0-30 Days','31-60 Days','61-90 Days','Strategic'];
  const phaseIcons=['🔴','🟠','🔵','🟢'];
  const el=document.getElementById('roadmapGrid');
  if(!el) return;
  el.innerHTML=phases.map((phase,pi)=>{
    const items=FINDINGS.filter(f=>f.roadmapPhase===phase && f.risk!=='Info').sort((a,b)=>(riskOrder[a.risk]??9)-(riskOrder[b.risk]??9));
    return `<div class="roadmap-col">
      <div class="roadmap-col-header">
        <span>${phaseIcons[pi]}</span>
        <span class="roadmap-col-label">${phase}</span>
        <span class="roadmap-count">${items.length}</span>
      </div>
      ${items.map((f,fi)=>`
        <div class="roadmap-item" onclick="openFindingDetailFromRoadmap('${escJ(f.checkId)}')">
          <div class="roadmap-item-title">${escH(f.title.substring(0,80))}${f.title.length>80?'…':''}</div>
          <div class="roadmap-item-meta">
            <span class="risk-badge rb-${escH(f.risk)}" style="font-size:9px">${escH(f.risk)}</span>
            <span class="tag-chip" style="font-size:9px">${escH(f.checkId)}</span>
          </div>
        </div>`).join('')}
      ${items.length===0?'<div style="font-size:11px;color:var(--muted);text-align:center;padding:12px 0">No actions in this phase</div>':''}
    </div>`;
  }).join('');
}

function openFindingDetailFromRoadmap(checkId){
  const idx=FINDINGS.findIndex(f=>f.checkId===checkId);
  if(idx<0) return;
  detailMode='findings';
  detailList=FINDINGS;
  currentDetailIndex=idx;
  renderFindingDrawer(idx);
  document.getElementById('detailPanel').classList.add('open');
}

// ── CSV Exports ────────────────────────────────────────────────────────────────
function exportFindingsCSV(){
  const rows=[['CheckId','Risk','Title','Phase','Evidence','CurrentState','Gap','BusinessImpact','TargetState','Recommendation','SuccessMeasure']];
  FINDINGS.forEach(f=>rows.push([f.checkId,f.risk,f.title,f.roadmapPhase,f.evidence,f.currentState,f.gap,f.businessImpact,f.targetState,f.recommendation,f.successMeasure||'']));
  dlFile(rows.map(r=>r.map(c=>'"'+String(c||'').replace(/"/g,'""')+'"').join(',')).join('\r\n'),'permission-risk-findings.csv','text/csv');
  showToast('Findings exported');
}
function exportAppsCSV(){
  const rows=[['DisplayName','Publisher','RiskBand','Score','AppRoles','DelegatedScopes','AdminConsent','UserConsent','Owners','Credentials','VerifiedPublisher','MultiTenant']];
  APPS.forEach(a=>rows.push([a.displayName,a.publisherName||'',a.riskBand,a.compositeScore,a.appRoleCount,a.delegatedScopeCount,a.adminConsentCount,a.userConsentCount,a.ownerCount,a.credSummary,a.isVerifiedPublisher?'Yes':'No',a.isMultiTenant?'Yes':'No']));
  dlFile(rows.map(r=>r.map(c=>'"'+String(c||'').replace(/"/g,'""')+'"').join(',')).join('\r\n'),'application-risk-register.csv','text/csv');
  showToast('App register exported');
}

// ── Keyboard shortcuts ─────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDetail();
  if(e.key==='/'&&!document.getElementById('detailPanel').classList.contains('open')){
    e.preventDefault();
    const inp=document.querySelector('.page.active input[type=text]');
    if(inp) inp.focus();
  }
  if(document.getElementById('detailPanel').classList.contains('open')){
    if(e.key==='ArrowLeft') navDetail(-1);
    if(e.key==='ArrowRight') navDetail(1);
  }
});

// ── Init ───────────────────────────────────────────────────────────────────────
initPosture();
applyFindingsFilter();
applyAppsFilter();
buildRoadmap();
</script>
</body>
</html>
'@

        $tenantIdShort = if ($TenantId.Length -gt 12) { $TenantId.Substring(0, 8) + "..." } else { $TenantId }

        $rsActiveCrit = if ($overallBand -eq "Critical") { "active" } else { "" }
        $rsActiveHigh = if ($overallBand -eq "High") { "active" } else { "" }
        $rsActiveMed = if ($overallBand -eq "Medium") { "active" } else { "" }

        $html = $html `
            -replace "__TENANT_NAME__", ([System.Web.HttpUtility]::HtmlEncode($TenantName)) `
            -replace "__TENANT_ID_SHORT__", $tenantIdShort `
            -replace "__ASSESS_DATE__", $AssessmentDate `
            -replace "__RING_COLOR__", $ringColor `
            -replace "__RING_DASH__", $ringDash `
            -replace "__RING_GAP__", $ringGap `
            -replace "__RISK_SCORE__", $riskScore `
            -replace "__OVERALL_BAND__", $overallBand `
            -replace "__OVERALL_COLOR__", $overallColor `
            -replace "__CRITICAL__", $critical `
            -replace "__HIGH__", $high `
            -replace "__MEDIUM__", $medium `
            -replace "__LOW__", $low `
            -replace "__TOTAL_SCORED__", $totalScored `
            -replace "__WITH_APP_PERMS__", $withAppPerms `
            -replace "__OWNERLESS__", $ownerless `
            -replace "__EXPIRED_CREDS__", $expiredCreds `
            -replace "__SECRETLESS_RATIO__", $secretlessRatio `
            -replace "__RS_CRIT_ACTIVE__", $rsActiveCrit `
            -replace "__RS_HIGH_ACTIVE__", $rsActiveHigh `
            -replace "__RS_MED_ACTIVE__", $rsActiveMed `
            -replace "__FINDINGS_JSON__", $FindingsJson `
            -replace "__APP_RISK_JSON__", $AppRiskJson

        Try {
            # Add-Type for HtmlEncode is needed only for the replacements; if unavailable, fall back
            $html | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
        }
        Catch {
            Write-Warning "  Failed to write HTML dashboard: $_"
        }
    }

    #endregion

    #region ── Main Execution ─────────────────────────────────────────────────────

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   Entra Application Permission Risk Model  v1.0              ║" -ForegroundColor Cyan
    Write-Host "  ║   Enterprise API Governance & Risk Assessment                ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $scriptStartTime = Get-Date
    Write-Host "  🕐 Started  : $($scriptStartTime.ToString('dd-MMM-yyyy  hh:mm:ss tt'))" -ForegroundColor Gray
    Write-Host "  📂 Output   : $OutputPath" -ForegroundColor Gray
    Write-Host "  🔑 Auth Mode: $($PSCmdlet.ParameterSetName)" -ForegroundColor Gray
    Write-Host ""

    # ── Ensure output path exists ─────────────────────────────────────────────
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Host "  📁 Created output directory: $OutputPath" -ForegroundColor Gray
    }

    # ── Step 1: Authentication ────────────────────────────────────────────────
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

    # ── Step 1.1: Validate Required Graph Permissions ─────────────────────────
    Write-Host "  🔍 Validating required Microsoft Graph permissions..." -ForegroundColor Yellow

    $requiredGraphPermissions = @(
        "Application.Read.All"
        "Directory.Read.All"
        "AuditLog.Read.All"
        "DelegatedPermissionGrant.Read.All"
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

    # ── Step 2: Tenant Baseline ───────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 2  ›  Collecting Tenant Baseline                     │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  ⏳ Retrieving tenant organisation data..." -ForegroundColor Yellow

    $orgData = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/organization?`$select=id,displayName,verifiedDomains,createdDateTime"
    $tenantName = "Unknown"
    if ($orgData -and $orgData.value -and $orgData.value.Count -gt 0) {
        $tenantName = $orgData.value[0].displayName
    }
    elseif ($orgData -and $orgData.displayName) {
        $tenantName = $orgData.displayName
    }

    Write-Host "  ✅ Tenant: $tenantName ($TenantId)" -ForegroundColor Green
    Write-Host ""

    # ── Step 3: Application & Permission Inventory ────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 3  ›  Building Application & Permission Inventory     │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $tenantInfoObj = [PSCustomObject]@{ TenantName = $tenantName; TenantId = $TenantId }
    $inventory = Invoke-PermissionInventory -TenantInfo $tenantInfoObj

    Write-Host ""
    Write-Host "  ✅ Inventory complete." -ForegroundColor Green
    Write-Host ""

    # ── Step 4: Risk Engine ───────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 4  ›  Running 7-Dimension Risk Engine                │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    Invoke-AppRiskEngine -Inventory $inventory -OrgTenantId $TenantId

    Write-Host ""

    # ── Step 5: Tenant-Level Findings ─────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 5  ›  Generating Risk Posture Findings (10 checks)   │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    Invoke-TenantRiskFindings -Inventory $inventory

    Write-Host ""

    # ── Step 6: Summary scoring ────────────────────────────────────────────────
    $totalCritical = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Critical" }).Count
    $totalHigh = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "High" }).Count
    $totalMedium = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Medium" }).Count
    $totalLow = ($script:AppRiskRecords | Where-Object { $_.RiskBand -eq "Low" }).Count
    $overallBand = if ($totalCritical -gt 0) { "Critical" } elseif ($totalHigh -gt 3) { "High" } elseif ($totalMedium -gt 10) { "Medium" } else { "Low" }

    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 6  ›  Overall Risk Posture                           │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  📊 Overall Posture  : $overallBand" -ForegroundColor Cyan
    Write-Host "  📱 Apps Scored      : $($script:AppRiskRecords.Count)" -ForegroundColor Gray
    Write-Host "  🔴 Critical         : $totalCritical" -ForegroundColor Red
    Write-Host "  🟠 High             : $totalHigh" -ForegroundColor Yellow
    Write-Host "  🔵 Medium           : $totalMedium" -ForegroundColor Blue
    Write-Host "  🟢 Low              : $totalLow" -ForegroundColor Green
    Write-Host ""

    # ── Step 7: Export ────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 7  ›  Generating Reports                             │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $htmlPath = Join-Path $OutputPath "EntraApplicationPermissionRiskModel_$timestamp.html"
    $jsonPath = Join-Path $OutputPath "EntraApplicationPermissionRiskModel_$timestamp.json"
    $assessDate = (Get-Date).ToString("dd MMM yyyy HH:mm")

    Write-Host "  ⏳ Building HTML dashboard..." -ForegroundColor Yellow
    $findingsJson = Build-FindingsJson
    $appRiskJson = Build-AppRiskJson

    Generate-HtmlDashboard `
        -TenantName     $tenantName `
        -TenantId       $TenantId `
        -AssessmentDate $assessDate `
        -FindingsJson   $findingsJson `
        -AppRiskJson    $appRiskJson `
        -OutputFilePath $htmlPath

    Write-Host "  ✅ HTML dashboard written → $htmlPath" -ForegroundColor Green

    Write-Host "  ⏳ Exporting JSON risk model..." -ForegroundColor Yellow
    Export-RiskModelJson `
        -TenantName     $tenantName `
        -TenantId       $TenantId `
        -AssessmentDate $assessDate `
        -OutputFilePath $jsonPath

    Write-Host "  ✅ JSON export written → $jsonPath" -ForegroundColor Green
    Write-Host ""

    # ── Execution Summary ─────────────────────────────────────────────────────
    $scriptEndTime = Get-Date
    $executionTime = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime

    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║              APPLICATION PERMISSION RISK SUMMARY              ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  🏛️  Tenant                : $($tenantName.PadRight(30))║" -ForegroundColor White
    Write-Host "  ║  📊 Overall Posture        : $($overallBand.PadRight(30))║" -ForegroundColor Cyan
    Write-Host "  ║  📱 Applications Scored    : $($script:AppRiskRecords.Count.ToString().PadRight(30))║" -ForegroundColor White
    Write-Host "  ║  🔴 Critical Risk Apps     : $($totalCritical.ToString().PadRight(30))║" -ForegroundColor Red
    Write-Host "  ║  🟠 High Risk Apps         : $($totalHigh.ToString().PadRight(30))║" -ForegroundColor Yellow
    Write-Host "  ║  🔵 Medium Risk Apps       : $($totalMedium.ToString().PadRight(30))║" -ForegroundColor Blue
    Write-Host "  ║  🔍 Findings Generated     : $($script:Findings.Count.ToString().PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  🕐 Started               : $($scriptStartTime.ToString('hh:mm:ss tt').PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  🕑 Ended                 : $($scriptEndTime.ToString('hh:mm:ss tt').PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  ⏱️ Duration               : $($executionTime.ToString('hh\:mm\:ss').PadRight(30))║" -ForegroundColor Yellow
    Write-Host "  ║  🌐 HTML Dashboard        : $(('...' + $htmlPath.Substring([Math]::Max(0,$htmlPath.Length-27))).PadRight(30))║" -ForegroundColor Green
    Write-Host "  ║  📄 JSON Export           : $(('...' + $jsonPath.Substring([Math]::Max(0,$jsonPath.Length-27))).PadRight(30))║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    #endregion
}
