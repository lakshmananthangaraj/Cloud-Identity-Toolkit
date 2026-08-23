<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 23 August 2026
Modified-On  : 23 August 2026

.SYNOPSIS
    Evaluates an application's access control model against Zero Trust principles
    and produces a maturity-rated, gap-analysed, risk-prioritised assessment report.

.DESCRIPTION
    This script connects to Microsoft Graph (BYOT or Client Credentials) and assesses
    a specific Entra ID application registration or service principal across seven
    Zero Trust architectural domains:

        Domain 1  — Identity Assurance
        Domain 2  — Device Assurance
        Domain 3  — Authentication Strength
        Domain 4  — Least Privilege & Permission Governance
        Domain 5  — Privileged Access to Application
        Domain 6  — Workload Identity Controls
        Domain 7  — Continuous Evaluation & Session Controls

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
        - Blast radius (tenant-wide vs application-scoped)
        - Privilege exposure (admin plane vs data plane)

    The assessment accepts either an App Registration's AppId (-AppId) or the Object ID
    of a Service Principal (-ServicePrincipalId) and automatically resolves the
    complementary object so all domains are assessed from a complete picture.

    Output:
        - HTML interactive dashboard (light/dark theme, tabbed by domain)
        - JSON assessment export (machine-readable, CI/CD integrable)

.PARAMETER TenantId
    The Directory (tenant) ID of the Entra ID tenant containing the application.

.PARAMETER ClientId
    The Application (client) ID of the app registration used for Client Credentials
    authentication. Required when -AuthMode is ClientCredentials.

.PARAMETER ClientSecret
    The client secret as a SecureString. Required when -AuthMode is ClientCredentials.

.PARAMETER AccessToken
    A pre-obtained bearer token (BYOT — Bring Your Own Token). Use when the caller
    already has a valid Graph token (e.g. from az account get-access-token or a
    pipeline step). Mutually exclusive with -ClientId / -ClientSecret.

.PARAMETER AuthMode
    Authentication mode. Accepted values: ClientCredentials, BYOT.
    Default: ClientCredentials.

.PARAMETER AppId
    The Application (client) ID of the application registration to assess.
    Mutually exclusive with -ServicePrincipalId. The associated service principal
    is resolved automatically.

.PARAMETER ServicePrincipalId
    The Object ID of the service principal (enterprise application) to assess.
    Mutually exclusive with -AppId. The associated app registration is resolved
    automatically where available.

.PARAMETER OutputPath
    Directory where the HTML and JSON reports will be written.
    Default: C:\Temp\EntraAccessControlAssessment

.PARAMETER ShowHelp
    Displays a plain-language usage guide and exits immediately.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        HTML dashboard : <OutputPath>\EntraAccessControlAssessment_<AppName>_<timestamp>.html
        JSON export    : <OutputPath>\EntraAccessControlAssessment_<AppName>_<timestamp>.json

.EXAMPLE
    Start-EntraAccessControlArchitectureAssessment -ShowHelp

    Displays the friendly usage guide and exits.

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Start-EntraAccessControlArchitectureAssessment `
        -AuthMode     ClientCredentials `
        -TenantId     "f4310b4f-xxxx" `
        -ClientId     "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -AppId        "a1b2c3d4-xxxx"

    Full Zero Trust assessment of a specific application using Client Credentials auth.

.EXAMPLE
    $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    Start-EntraAccessControlArchitectureAssessment `
        -AuthMode          BYOT `
        -TenantId          "f4310b4f-xxxx" `
        -AccessToken       $token `
        -ServicePrincipalId "e9f8g7h6-xxxx"

    Assessment using a pre-obtained bearer token, resolving via Service Principal Object ID.

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Start-EntraAccessControlArchitectureAssessment `
        -AuthMode     ClientCredentials `
        -TenantId     "f4310b4f-xxxx" `
        -ClientId     "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -AppId        "a1b2c3d4-xxxx" `
        -OutputPath   "D:\Reports\ZeroTrustAssessments"

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
               Application.Read.All       (app registrations, service principals,
                                           app roles, owners)
               Policy.Read.All            (Conditional Access policies, token lifetime
                                           policies, authentication methods policy)
               Directory.Read.All         (app role assignments, groups, users)
               AuditLog.Read.All          (sign-in activity, non-interactive sign-ins)

        2. BYOT mode: the delegated or application token must carry the same
           scopes as above. Delegated tokens require the caller to hold at least
           the Application Administrator or Global Reader role.

        3. Entra ID P1 minimum for Conditional Access evaluation.
           Entra ID P2 for PIM-based app role assignment data (gracefully degraded
           to P1 data when P2 is absent).

        4. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  → Show help and exit if -ShowHelp
        Step 1  → Authenticate (BYOT or Client Credentials)
        Step 2  → Resolve application identity (App Registration + Service Principal)
        Step 3  → Collect application baseline (permissions, credentials, owners)
        Step 4  → Run domain assessments D1–D7
        Step 5  → Score domains, compute overall Zero Trust maturity
        Step 6  → Build prioritised finding list with recommendations
        Step 7  → Generate roadmap (0-30 / 31-60 / 61-90 days + Strategic)
        Step 8  → Export HTML dashboard + JSON

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the /beta Graph endpoint. Beta APIs are subject to change.
        - CA policy evaluation is configuration-based; it does not simulate
          runtime policy evaluation against real sign-in sessions.
        - For first-party Microsoft applications (e.g. Microsoft Graph, Office 365)
          assessed as service principals, the associated app registration lives in
          Microsoft's home tenant and cannot be resolved. D6 and partial D4 checks
          will degrade gracefully to "Insufficient Data" in those cases.
        - Sign-in activity data reflects the past 30 days. Applications with
          infrequent but legitimate usage may show as inactive.
        - Applications accessed only via non-interactive (daemon) flows will show
          no interactive sign-in activity; this is expected and noted in findings.

.LINK
    https://learn.microsoft.com/en-us/security/zero-trust/
.LINK
    https://learn.microsoft.com/en-us/entra/architecture/zero-trust-identity
.LINK
    https://learn.microsoft.com/en-us/graph/api/overview

#>


Function Start-EntraAccessControlArchitectureAssessment {
    [CmdletBinding()]
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
        [string]$AppId,

        [Parameter(ParameterSetName = "ClientCredentials")]
        [Parameter(ParameterSetName = "BYOT")]
        [string]$ServicePrincipalId,

        [Parameter(ParameterSetName = "ClientCredentials")]
        [Parameter(ParameterSetName = "BYOT")]
        [string]$OutputPath = "C:\Temp\EntraAccessControlAssessment",

        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    #region ── Friendly Help ─────────────────────────────────────────────────────

    Function Show-FriendlyHelp {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║   Entra Access Control Architecture Assessment  v1.0         ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  PURPOSE" -ForegroundColor Yellow
        Write-Host "    Evaluates an application's access control model against Zero Trust"
        Write-Host "    principles across 7 domains: Identity Assurance, Device Assurance,"
        Write-Host "    Authentication Strength, Least Privilege, Privileged Access,"
        Write-Host "    Workload Identity Controls, and Continuous Evaluation."
        Write-Host ""
        Write-Host "  IDENTIFY THE TARGET APPLICATION" -ForegroundColor Yellow
        Write-Host "    Provide either the App Registration's AppId, or the Service Principal"
        Write-Host "    Object ID. The complementary object is resolved automatically."
        Write-Host ""
        Write-Host "  AUTHENTICATION" -ForegroundColor Yellow
        Write-Host "    Client Credentials (app-only):"
        Write-Host '      $secret = Read-Host "Client secret" -AsSecureString'
        Write-Host '      Start-EntraAccessControlArchitectureAssessment \'
        Write-Host '          -AuthMode ClientCredentials -TenantId "<tenant-id>" \'
        Write-Host '          -ClientId "<app-id>" -ClientSecret $secret \'
        Write-Host '          -AppId "<target-app-id>"'
        Write-Host ""
        Write-Host "    BYOT (Bring Your Own Token):"
        Write-Host '      $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken'
        Write-Host '      Start-EntraAccessControlArchitectureAssessment \'
        Write-Host '          -AuthMode BYOT -TenantId "<tenant-id>" -AccessToken $token \'
        Write-Host '          -ServicePrincipalId "<spn-object-id>"'
        Write-Host ""
        Write-Host "  REQUIRED APP PERMISSIONS (Application, admin-consented)" -ForegroundColor Yellow
        Write-Host "    Application.Read.All, Policy.Read.All,"
        Write-Host "    Directory.Read.All, AuditLog.Read.All"
        Write-Host ""
        Write-Host "  For full documentation: Get-Help Start-EntraAccessControlArchitectureAssessment -Full"
        Write-Host ""
    }

    if ($ShowHelp) {
        Show-FriendlyHelp
        return
    }

    # Validate that at least one application identifier is supplied
    if (-not $AppId -and -not $ServicePrincipalId) {
        Write-Error "You must supply either -AppId (App Registration client ID) or -ServicePrincipalId (Service Principal object ID)."
        return
    }

    #endregion

    #region ── Token Management ──────────────────────────────────────────────────

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

    #region ── Graph API Helper ──────────────────────────────────────────────────

    Function Invoke-GraphRequest {
        param (
            [Parameter(Mandatory = $true)] [string]$Uri,
            [string]$Method = "GET",
            [hashtable]$Body = $null,
            [int]$MaxRetries = 5
        )

        RenewTokenIfNeeded

        $headers = @{ Authorization = "Bearer $global:accessToken" }
        $attempt = 0

        while ($attempt -le $MaxRetries) {
            Try {
                $params = @{
                    Uri         = $Uri
                    Method      = $Method
                    Headers     = $headers
                    ContentType = "application/json"
                    ErrorAction = "Stop"
                }
                if ($Body -and $Method -ne "GET") { $params.Body = ($Body | ConvertTo-Json -Depth 10) }

                return Invoke-RestMethod @params
            }
            Catch {
                $status = $null
                if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }

                if ($status -eq 429 -and $attempt -lt $MaxRetries) {
                    $retryAfter = 30
                    Try {
                        $headerVal = $_.Exception.Response.Headers["Retry-After"]
                        if ($headerVal) { $retryAfter = [int]$headerVal }
                    }
                    Catch { }
                    Write-Warning "  ⏳ Graph API throttled (429). Waiting $retryAfter seconds..."
                    Start-Sleep -Seconds $retryAfter
                    $attempt++
                    continue
                }

                if ($status -eq 404) { return $null }

                if ($status -eq 403 -or $status -eq 401) {
                    Write-Warning "  ⚠️  Insufficient permissions for: $Uri — check required scopes."
                    return $null
                }

                Write-Warning "  ⚠️  Graph request failed [$status]: $Uri — $_"
                return $null
            }
        }

        return $null
    }


    Function Get-GraphPagedResults {
        param (
            [Parameter(Mandatory = $true)] [string]$Uri,
            [int]$MaxPages = 50
        )

        $allItems = [System.Collections.ArrayList]::new()
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

    # Global assessment store
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

    #region ── Permission Risk Classification ────────────────────────────────────

    # High-risk Microsoft Graph Application permission IDs (non-exhaustive; covers major blast-radius scopes)
    $script:HighRiskPermissions = @{
        # Directory / Role manipulation
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" = "RoleManagement.ReadWrite.Directory"
        "06b708a9-e830-4db3-a914-8e69da51d44f" = "AppRoleAssignment.ReadWrite.All"
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Application.ReadWrite.All"
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7" = "Directory.ReadWrite.All"
        # User & Group write
        "741f803b-c850-494e-b5df-cde7c675a1ca" = "User.ReadWrite.All"
        "62a82d76-70ea-41e2-9197-370581804d09" = "Group.ReadWrite.All"
        # Mail & calendar write
        "e2a3a72e-5f79-4c64-b1b1-878b674786c9" = "Mail.ReadWrite"
        "024d486e-b451-40bb-833d-3e66d98c5c73" = "Mail.Send"
        # Files write
        "75359482-378d-4052-8f01-80520e7db3cd" = "Files.ReadWrite.All"
        # Security write
        "bf394140-e372-4bf9-a898-299cfc7564e5" = "SecurityEvents.ReadWrite.All"
        "34bf0e97-1971-4929-b999-9e2442d941d7" = "SecurityAlert.ReadWrite.All"
        # Teams write
        "bdd80a03-d9bc-451d-b7c4-ce7c63fe3c8f" = "TeamMember.ReadWrite.All"
        "0121dc95-1b9f-4aed-8bac-58c5ac466691" = "Channel.Create"
    }

    # Medium-risk Microsoft Graph Application permission IDs
    $script:MediumRiskPermissions = @{
        # Read-all scopes with broad data access
        "df021288-bdef-4463-88db-98f22de89214" = "User.Read.All"
        "7ab1d382-f21e-4acd-a863-ba3e13f7da61" = "Directory.Read.All"
        "246dd0d5-5bd0-4def-940b-0421030a5b68" = "Policy.Read.All"
        "b0afded3-3588-46d8-8b3d-9842eff778da" = "AuditLog.Read.All"
        "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" = "Application.Read.All"
        "e321f0bb-e7f7-481e-bb28-e3b0b32d4bd0" = "Mail.ReadBasic.All"
        "810c84a8-4a9e-49e6-bf7d-12d183f40d01" = "Mail.Read"
        "01d4889c-1287-42c6-ac1f-5d1e02578ef6" = "Files.Read.All"
        "7427e0e9-2fba-42fe-b0c0-848c9e6a8182" = "offline_access"
        "5b567255-7703-4780-807c-7be8301ae99b" = "Group.Read.All"
    }

    Function Get-PermissionRiskLevel {
        param ([string]$PermissionId, [string]$PermissionType)

        # Application permissions (Role) are inherently higher risk than Delegated (Scope)
        if ($script:HighRiskPermissions.ContainsKey($PermissionId)) {
            if ($PermissionType -eq "Role") { return "High" } else { return "Medium" }
        }
        if ($script:MediumRiskPermissions.ContainsKey($PermissionId)) {
            if ($PermissionType -eq "Role") { return "Medium" } else { return "Low" }
        }
        if ($PermissionType -eq "Role") { return "Low" } else { return "Info" }
    }

    Function Get-PermissionDisplayName {
        param ([string]$PermissionId)
        if ($script:HighRiskPermissions.ContainsKey($PermissionId)) { return $script:HighRiskPermissions[$PermissionId] }
        if ($script:MediumRiskPermissions.ContainsKey($PermissionId)) { return $script:MediumRiskPermissions[$PermissionId] }
        return $PermissionId
    }

    #endregion

    #region ── Domain 1: Identity Assurance ──────────────────────────────────────

    Function Invoke-Domain1-IdentityAssurance {
        param (
            [PSCustomObject]$AppContext,
            [array]$AllCAPolicies
        )

        Write-Host "  🪪  D1: Identity Assurance..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $spnId = $AppContext.SpnObjectId
        $appId = $AppContext.AppId

        # ── Resolve which CA policies cover this application ──────────────────────
        $enabledCA = @($AllCAPolicies | Where-Object { $_.state -eq "enabled" })

        $coveringPolicies = @($enabledCA | Where-Object {
                $incApps = $_.conditions.applications.includeApplications
                $excApps = $_.conditions.applications.excludeApplications
                $coversAll = $incApps -contains "All"
                $coversApp = $incApps -contains $appId
                $excluded = $excApps -contains $appId
                ($coversAll -or $coversApp) -and -not $excluded
            })

        # ── Check 1.1: MFA enforcement via Conditional Access ─────────────────────
        $mfaPolicies = @($coveringPolicies | Where-Object {
                $gc = $_.grantControls
                ($gc -and ($gc.builtInControls -contains "mfa" -or
                    ($gc.authenticationStrength -and $gc.authenticationStrength.id)))
            })

        if ($mfaPolicies.Count -eq 0) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D1" -DomainName "Identity Assurance" -CheckId "D1.1" `
                -Title "No MFA Requirement Detected for This Application" `
                -Evidence "CA policies covering this app: $($coveringPolicies.Count) | Policies requiring MFA or Authentication Strength: 0" `
                -CurrentState "No Conditional Access policy covering this application enforces MFA or an Authentication Strength policy." `
                -Gap "Users can authenticate to this application using only a password. Zero Trust Identity Assurance requires verified identity on every access attempt." `
                -Risk "Critical" `
                -BusinessImpact "Password-only authentication is the single most exploited vector in Entra ID. Without MFA, a stolen credential provides immediate unrestricted access to this application and all data it exposes." `
                -TargetState "A Conditional Access policy enforcing MFA (minimum) or an Authentication Strength policy (preferred) must cover this application for all non-excluded users." `
                -Recommendation "Create or extend a CA policy: Users = All, Apps = this application (or All Cloud Apps), Grant = Require MFA. For elevated-risk apps, use Authentication Strength requiring phishing-resistant methods (FIDO2, CBA, WHfB)." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            # Distinguish between basic MFA and phishing-resistant Authentication Strength
            $authStrengthPolicies = @($mfaPolicies | Where-Object {
                    $_.grantControls.authenticationStrength -and $_.grantControls.authenticationStrength.id
                })

            if ($authStrengthPolicies.Count -gt 0) {
                $maturityPoints += 5
                Add-Finding -DomainId "D1" -DomainName "Identity Assurance" -CheckId "D1.1" `
                    -Title "Authentication Strength Policy Enforced ($($authStrengthPolicies.Count) policy/ies)" `
                    -Evidence "CA policies covering app: $($coveringPolicies.Count) | Policies with Authentication Strength: $($authStrengthPolicies.Count)" `
                    -CurrentState "This application is protected by an Authentication Strength policy, which enforces specific phishing-resistant or strong MFA methods." `
                    -Gap "Verify the Authentication Strength definition targets phishing-resistant methods (FIDO2, Windows Hello for Business, CBA) for sensitive access." `
                    -Risk "Info" -BusinessImpact "Low — strong identity assurance is enforced. Continuously review strength definitions as new methods become available." `
                    -TargetState "Phishing-resistant Authentication Strength enforced for all users. Method definitions reviewed quarterly." `
                    -Recommendation "Confirm the Authentication Strength policy targets FIDO2, WHfB, or CBA. Periodically review and tighten the allowed methods list as the threat landscape evolves." `
                    -RoadmapPhase "Strategic" -MaturityContribution 5
            }
            else {
                $maturityPoints += 3
                Add-Finding -DomainId "D1" -DomainName "Identity Assurance" -CheckId "D1.1" `
                    -Title "MFA Required via Conditional Access ($($mfaPolicies.Count) policy/ies)" `
                    -Evidence "CA policies covering app: $($coveringPolicies.Count) | Policies requiring MFA: $($mfaPolicies.Count) | With Authentication Strength: 0" `
                    -CurrentState "MFA is enforced for this application via Conditional Access. Basic MFA (any method) is required." `
                    -Gap "Basic MFA (including SMS and voice) is phishable. Zero Trust targets phishing-resistant methods for all applications, especially those handling sensitive data." `
                    -Risk "Low" -BusinessImpact "Identity assurance is present but uses basic MFA methods that are susceptible to real-time phishing attacks. Uplift to phishing-resistant methods reduces breach probability significantly." `
                    -TargetState "Authentication Strength policy requiring FIDO2, Windows Hello for Business, or Certificate-Based Authentication applied to this application." `
                    -Recommendation "Upgrade the CA grant control from 'Require MFA' to an Authentication Strength policy. Define the strength to require FIDO2, WHfB, or CBA. Use report-only mode to assess impact before enabling." `
                    -RoadmapPhase "31-60 Days" -MaturityContribution 3
            }
        }

        # ── Check 1.2: Identity risk — sign-in risk policy coverage ──────────────
        $riskPolicies = @($coveringPolicies | Where-Object {
                $_.conditions.signInRiskLevels.Count -gt 0 -or $_.conditions.userRiskLevels.Count -gt 0
            })

        if ($riskPolicies.Count -eq 0) {
            $high++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Identity Assurance" -CheckId "D1.2" `
                -Title "No Identity Risk-Based Access Policy Covers This Application" `
                -Evidence "CA policies covering this app: $($coveringPolicies.Count) | Policies with sign-in or user risk conditions: 0" `
                -CurrentState "No Conditional Access policy applies sign-in risk or user risk conditions when accessing this application." `
                -Gap "Risk-blind authentication allows compromised accounts and anomalous sign-ins to authenticate with the same controls as trusted sessions. Continuous evaluation of identity risk is a core Zero Trust principle." `
                -Risk "High" -BusinessImpact "Users flagged by Entra ID Identity Protection as high-risk can access this application with no additional friction. Compromised accounts remain in active use until manually remediated." `
                -TargetState "A CA policy requiring MFA or blocking on medium/high sign-in risk, and requiring password change or blocking on high user risk, covers this application." `
                -Recommendation "Create a risk-based CA policy: Apps = this application (or All), Sign-in risk = Medium/High → require MFA; User risk = High → require password change. Ensure Entra ID P2 is licensed for Identity Protection signals." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D1" -DomainName "Identity Assurance" -CheckId "D1.2" `
                -Title "Risk-Based Access Policy Active ($($riskPolicies.Count) policy/ies)" `
                -Evidence "CA policies covering app: $($coveringPolicies.Count) | Risk-conditioned policies: $($riskPolicies.Count)" `
                -CurrentState "Identity risk signals (sign-in risk or user risk) are evaluated when accessing this application." `
                -Gap "Verify risk thresholds: medium and high risk should trigger MFA or block. High user risk should require password change. Confirm the risk evaluation is not excluded for service accounts." `
                -Risk "Info" -BusinessImpact "Low — risk-based access control is in place. Review thresholds and ensure coverage is not bypassed by exclusion groups." `
                -TargetState "Sign-in risk high → block. Sign-in risk medium → require MFA. User risk high → require password change. All thresholds enforced with no broad exclusions." `
                -Recommendation "Review the risk policy thresholds and exclusion groups. Aim for blocking high sign-in risk rather than stepping up to MFA — which can be bypassed by real-time phishing." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 1.3: Sign-in audience (single-tenant vs multi-tenant) ────────────
        $signInAudience = $AppContext.SignInAudience
        if ($signInAudience -and $signInAudience -ne "AzureADMyOrg") {
            $high++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Identity Assurance" -CheckId "D1.3" `
                -Title "Application Accepts External Identities — Sign-In Audience: '$signInAudience'" `
                -Evidence "Sign-in audience: $signInAudience | Expected for internal apps: AzureADMyOrg" `
                -CurrentState "This application is configured to accept identities from external tenants or Microsoft personal accounts, beyond the home tenant." `
                -Gap "A multi-tenant or public audience configuration expands the identity boundary beyond the organisation's governance perimeter. External identities are not subject to the organisation's Conditional Access and identity protection controls by default." `
                -Risk "High" -BusinessImpact "Users from any Entra ID tenant (or personal MSA accounts) can attempt authentication to this application. If the app's CA policies do not explicitly scope and control external identities, the trust boundary is undefined." `
                -TargetState "Internal applications scoped to AzureADMyOrg only. Multi-tenant apps documented with business justification, subject to enhanced CA controls (Tenant Restrictions v2) and regular access reviews." `
                -Recommendation "If this is an internal app, change the sign-in audience to AzureADMyOrg in the App Registration manifest. If multi-tenant is required by design, implement Tenant Restrictions v2, add CA conditions for external identity control, and schedule an annual business justification review." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D1" -DomainName "Identity Assurance" -CheckId "D1.3" `
                -Title "Application Is Scoped to Home Tenant Only (AzureADMyOrg)" `
                -Evidence "Sign-in audience: $(if ($signInAudience) { $signInAudience } else { 'AzureADMyOrg (default or not applicable)' })" `
                -CurrentState "Authentication is restricted to identities from the home tenant. External tenants and personal accounts cannot authenticate." `
                -Gap "Correct posture for internal applications. Maintain governance to prevent inadvertent audience widening during app updates." `
                -Risk "Info" -BusinessImpact "Low — identity trust boundary is correctly scoped to the organisation's directory." `
                -TargetState "All internal applications maintain AzureADMyOrg sign-in audience. Audience changes require Security Review Board approval." `
                -Recommendation "Add a manifest review check to the application deployment pipeline to prevent accidental audience widening in future updates." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D1" -Name "Identity Assurance" -Icon "🪪" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "CA policies covering app: $($coveringPolicies.Count). MFA policies: $($mfaPolicies.Count). Risk policies: $($riskPolicies.Count). Audience: $(if ($signInAudience) { $signInAudience } else { 'AzureADMyOrg' })." `
            -TargetStateSummary "Phishing-resistant Authentication Strength enforced. Risk-based policy blocks high-risk sessions. Single-tenant audience." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 2: Device Assurance ────────────────────────────────────────

    Function Invoke-Domain2-DeviceAssurance {
        param (
            [PSCustomObject]$AppContext,
            [array]$AllCAPolicies
        )

        Write-Host "  💻  D2: Device Assurance..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $appId = $AppContext.AppId

        $enabledCA = @($AllCAPolicies | Where-Object { $_.state -eq "enabled" })

        $coveringPolicies = @($enabledCA | Where-Object {
                $incApps = $_.conditions.applications.includeApplications
                $excApps = $_.conditions.applications.excludeApplications
                ($incApps -contains "All" -or $incApps -contains $appId) -and ($excApps -notcontains $appId)
            })

        # ── Check 2.1: Device compliance or Hybrid AAD join requirement ───────────
        $devicePolicies = @($coveringPolicies | Where-Object {
                $gc = $_.grantControls
                $gc -and ($gc.builtInControls -contains "compliantDevice" -or
                    $gc.builtInControls -contains "domainJoinedDevice")
            })

        if ($devicePolicies.Count -eq 0) {
            $high++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Device Assurance" -CheckId "D2.1" `
                -Title "No Device Compliance or Hybrid Join Requirement for This Application" `
                -Evidence "CA policies covering this app: $($coveringPolicies.Count) | Policies requiring compliant or hybrid-joined device: 0" `
                -CurrentState "Access to this application is not conditioned on device health. Any device — personal, unmanaged, or non-compliant — can authenticate successfully." `
                -Gap "Zero Trust Device assurance requires that the accessing device meet a known compliance baseline before granting access. Without this control, compromised or unmanaged devices represent an uncontrolled access vector." `
                -Risk "High" -BusinessImpact "Malware on unmanaged devices can harvest session tokens and credentials post-authentication. Personal devices outside corporate security policy may lack endpoint protection, patch compliance, or disk encryption." `
                -TargetState "A CA policy requiring Compliant Device (Intune) or Hybrid AAD Join applies to this application. Mobile apps additionally require Approved Client App or App Protection Policy." `
                -Recommendation "Create a CA policy requiring device compliance (Intune enrolled and compliant) for this application. For apps accessed from mobile, add an Approved Client App or App Protection Policy requirement. Use report-only mode to assess impact before enabling." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $compliancePolicies = @($devicePolicies | Where-Object {
                    $_.grantControls.builtInControls -contains "compliantDevice"
                })

            if ($compliancePolicies.Count -gt 0) {
                $maturityPoints += 5
                Add-Finding -DomainId "D2" -DomainName "Device Assurance" -CheckId "D2.1" `
                    -Title "Device Compliance Required via Conditional Access ($($compliancePolicies.Count) policy/ies)" `
                    -Evidence "Policies requiring compliant device: $($compliancePolicies.Count) | Total device-conditioned policies: $($devicePolicies.Count)" `
                    -CurrentState "Access to this application requires the device to be enrolled in Intune and marked as compliant — the strongest device assurance control available." `
                    -Gap "Verify the Intune compliance policy definitions are appropriately strict (patch level, disk encryption, AV, firewall). Confirm no broad device exclusions exist in the CA policy." `
                    -Risk "Info" -BusinessImpact "Low — device assurance is at the highest level. Focus on compliance policy coverage and strength." `
                    -TargetState "Device compliance enforced with strict compliance policies (patch, encryption, AV, firewall). No broad device exclusions. Compliance policies reviewed quarterly." `
                    -Recommendation "Audit the Intune compliance policies applied to devices accessing this app. Ensure they include OS patch requirements, disk encryption, AV enablement, and firewall state. Review CA device exclusion rules." `
                    -RoadmapPhase "Strategic" -MaturityContribution 5
            }
            else {
                # Hybrid join only — weaker than compliance
                $maturityPoints += 3
                Add-Finding -DomainId "D2" -DomainName "Device Assurance" -CheckId "D2.1" `
                    -Title "Hybrid AAD Join Required — Device Compliance Not Yet Enforced" `
                    -Evidence "Policies requiring hybrid-joined device: $($devicePolicies.Count) | Policies requiring compliant device: 0" `
                    -CurrentState "Access requires a Hybrid AAD-joined (domain-joined) device. Full Intune compliance enforcement is not yet applied." `
                    -Gap "Hybrid AAD join confirms the device is domain-joined but does not evaluate its health posture (patch level, AV, encryption). Compliant device provides real-time health verification." `
                    -Risk "Medium" -BusinessImpact "Domain-joined but unhealthy or unpatched devices can access the application. Ransomware or malware on AD-joined devices remains an access path." `
                    -TargetState "Device compliance (Intune enrolled + compliant) replaces or augments Hybrid AAD join as the device assurance control. Health-based access decisions rather than domain membership alone." `
                    -Recommendation "Enable Intune co-management or full MDM enrollment for domain-joined devices. Migrate the CA policy from Hybrid AAD join to Compliant Device over a phased rollout. Use report-only to validate impact." `
                    -RoadmapPhase "31-60 Days" -MaturityContribution 3
            }
        }

        # ── Check 2.2: Device filter conditions (named location / device state) ────
        $deviceFilterPolicies = @($coveringPolicies | Where-Object {
                $_.conditions.PSObject.Properties["devices"] -and
                $_.conditions.devices -and
                $_.conditions.devices.deviceFilter
            })

        if ($deviceFilterPolicies.Count -gt 0) {
            $maturityPoints += 4
            Add-Finding -DomainId "D2" -DomainName "Device Assurance" -CheckId "D2.2" `
                -Title "Device Filter Conditions Applied ($($deviceFilterPolicies.Count) policy/ies)" `
                -Evidence "CA policies with device filter rules: $($deviceFilterPolicies.Count)" `
                -CurrentState "Device filter conditions are used to target or exclude specific device attributes in CA policies covering this application." `
                -Gap "Review device filter rules to ensure they are not inadvertently excluding compliant device checks for specific device types (e.g. shared devices, kiosk devices)." `
                -Risk "Info" -BusinessImpact "Low — device-level granularity is in place. Audit filter logic to confirm intended scope." `
                -TargetState "Device filters complement — not bypass — compliance requirements. All device types that access this app are subject to appropriate assurance controls." `
                -Recommendation "Review device filter conditions for each policy. Ensure filters are additive (additional scope control) rather than reductive (bypassing compliance for device subsets)." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }
        else {
            $maturityPoints += 3
            Add-Finding -DomainId "D2" -DomainName "Device Assurance" -CheckId "D2.2" `
                -Title "No Device Filter Conditions Configured for This Application" `
                -Evidence "CA policies with device filter conditions: 0 across $($coveringPolicies.Count) covering policies" `
                -CurrentState "Device filter conditions are not applied. Policies apply uniformly to all devices meeting the base condition." `
                -Gap "While not a gap if device compliance is enforced, device filters enable advanced scenarios: Privileged Access Workstations for admin roles, shared-device mode for kiosk environments." `
                -Risk "Low" -BusinessImpact "Low — absence of device filters is acceptable when device compliance is enforced. Filters add value for tiered device trust scenarios." `
                -TargetState "For sensitive applications: device filter conditions to enforce PAW requirements for admin-equivalent access. Kiosk devices handled via shared-device policies." `
                -Recommendation "Evaluate whether tiered device access (PAW for admin, standard for users) is appropriate for this application. Implement device filter conditions as part of the next CA policy iteration." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 3
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D2" -Name "Device Assurance" -Icon "💻" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Device-assurance policies: $($devicePolicies.Count). Compliance-enforcing: $($compliancePolicies.Count). Device filter policies: $($deviceFilterPolicies.Count)." `
            -TargetStateSummary "Intune device compliance enforced for all access. Tiered device trust (PAW for admin). Compliance policies include patch, encryption, AV." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 3: Authentication Strength ─────────────────────────────────

    Function Invoke-Domain3-AuthStrength {
        param (
            [PSCustomObject]$AppContext,
            [array]$AllCAPolicies
        )

        Write-Host "  🔐  D3: Authentication Strength..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $appId = $AppContext.AppId

        $enabledCA = @($AllCAPolicies | Where-Object { $_.state -eq "enabled" })

        $coveringPolicies = @($enabledCA | Where-Object {
                $incApps = $_.conditions.applications.includeApplications
                $excApps = $_.conditions.applications.excludeApplications
                ($incApps -contains "All" -or $incApps -contains $appId) -and ($excApps -notcontains $appId)
            })

        # Reuse variables computed in D1 if available — or recompute defensively
        $mfaPolicies = @($coveringPolicies | Where-Object {
                $gc = $_.grantControls
                $gc -and ($gc.builtInControls -contains "mfa" -or
                    ($gc.authenticationStrength -and $gc.authenticationStrength.id))
            })

        # ── Check 3.1: Legacy authentication blocking ─────────────────────────────
        $legacyBlockPolicies = @($enabledCA | Where-Object {
                $appInScope = ($_.conditions.applications.includeApplications -contains "All") -or
                ($_.conditions.applications.includeApplications -contains $appId)
                $notExcluded = $_.conditions.applications.excludeApplications -notcontains $appId
                $blocksLegacy = (
                    ($_.conditions.clientAppTypes -contains "exchangeActiveSync" -or
                    $_.conditions.clientAppTypes -contains "other") -and
                    $_.grantControls -and $_.grantControls.builtInControls -contains "block"
                )
                $appInScope -and $notExcluded -and $blocksLegacy
            })

        if ($legacyBlockPolicies.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D3" -DomainName "Authentication Strength" -CheckId "D3.1" `
                -Title "No Policy Blocking Legacy Authentication for This Application" `
                -Evidence "CA policies covering this app that block legacy auth (exchangeActiveSync/other): 0" `
                -CurrentState "Legacy authentication protocols (SMTP AUTH, POP3, IMAP, Basic Auth over legacy clients) are not explicitly blocked for this application." `
                -Gap "Legacy protocols bypass MFA entirely. Any MFA requirement in other CA policies has no effect on legacy authentication flows to this app." `
                -Risk "High" -BusinessImpact "Password spray and credential-stuffing attacks use legacy authentication endpoints specifically because they bypass MFA controls. Even a well-enforced MFA policy provides zero protection against legacy auth attacks against this application." `
                -TargetState "All legacy authentication to this application (and tenant-wide) explicitly blocked via Conditional Access. Service accounts requiring legacy auth are individually documented and on a migration path." `
                -Recommendation "Create or extend a CA policy: All Users, All Cloud Apps (or this app), Client App = Exchange ActiveSync + Other → Block. Test with Sign-In logs filtered by 'Legacy Auth Protocols' before enforcement. Identify service accounts using legacy auth and plan modernisation." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D3" -DomainName "Authentication Strength" -CheckId "D3.1" `
                -Title "Legacy Authentication Blocked via Conditional Access ($($legacyBlockPolicies.Count) policy/ies)" `
                -Evidence "CA policies blocking legacy auth (exchangeActiveSync/other) covering this app: $($legacyBlockPolicies.Count)" `
                -CurrentState "Legacy authentication protocols are blocked for this application (or tenant-wide) via Conditional Access." `
                -Gap "Verify exclusion groups on legacy auth block policies are minimal and time-bound. Any exclusion re-opens the legacy auth attack surface for excluded identities." `
                -Risk "Info" -BusinessImpact "Low — legacy authentication attack surface is eliminated for this app. Regularly audit exclusion group membership." `
                -TargetState "Zero exceptions to legacy auth block. All service accounts that previously required legacy auth migrated to modern OAuth 2.0 / OIDC flows." `
                -Recommendation "Quarterly review of CA exclusion groups on legacy auth block policies. Target zero exclusions. Monitor Sign-In logs for legacy auth attempts from excluded accounts." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 3.2: Authentication Strength policy (phishing-resistant) ─────────
        $authStrengthPolicies = @($coveringPolicies | Where-Object {
                $_.grantControls -and
                $_.grantControls.authenticationStrength -and
                $_.grantControls.authenticationStrength.id
            })

        if ($authStrengthPolicies.Count -eq 0 -and $mfaPolicies.Count -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D3" -DomainName "Authentication Strength" -CheckId "D3.2" `
                -Title "MFA Enforced but No Authentication Strength Policy — Phishable Methods Permitted" `
                -Evidence "Policies requiring MFA: $($mfaPolicies.Count) | Policies with Authentication Strength: 0" `
                -CurrentState "MFA is required but no Authentication Strength policy defines which methods are acceptable. Users can satisfy MFA with SMS OTP, voice call, or Microsoft Authenticator push — all of which are susceptible to real-time phishing." `
                -Gap "Basic MFA with phishable methods provides weaker identity assurance than phishing-resistant alternatives. Real-time adversary-in-the-middle (AiTM) attacks can bypass SMS and push notification MFA." `
                -Risk "Medium" -BusinessImpact "AiTM phishing kits can intercept MFA tokens in real time, bypassing SMS and push-notification-based MFA. High-value applications should require phishing-resistant methods that bind authentication to the specific site being accessed." `
                -TargetState "Authentication Strength policy requiring FIDO2 security keys, Windows Hello for Business, or Certificate-Based Authentication applied to this application." `
                -Recommendation "Create a Custom Authentication Strength in Entra ID requiring FIDO2, WHfB, or CBA. Replace the grant control 'Require MFA' with 'Require Authentication Strength' for this application's CA policy. Roll out incrementally using Entra ID Temporary Access Pass for onboarding." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        elseif ($authStrengthPolicies.Count -gt 0) {
            $maturityPoints += 5
            Add-Finding -DomainId "D3" -DomainName "Authentication Strength" -CheckId "D3.2" `
                -Title "Phishing-Resistant Authentication Strength Policy Applied ($($authStrengthPolicies.Count) policy/ies)" `
                -Evidence "CA policies with Authentication Strength: $($authStrengthPolicies.Count) | Policy names: $(($authStrengthPolicies.displayName | Select-Object -First 3) -join ', ')" `
                -CurrentState "An Authentication Strength policy is applied to this application, enforcing specific strong authentication methods." `
                -Gap "Confirm the strength definition includes only phishing-resistant methods. Review allowed combinations to ensure no weak fallback (e.g. SMS) is included in the strength definition." `
                -Risk "Info" -BusinessImpact "Low — phishing-resistant authentication is enforced. Review strength definitions annually as new authentication methods emerge." `
                -TargetState "Strength definition restricted to FIDO2, WHfB, and CBA only. No phishable methods in the allowed combination list. Reviewed annually." `
                -Recommendation "Open the Authentication Strength definition in Entra ID → Security → Authentication Strengths. Confirm allowed combinations exclude SMS, voice, and TOTP-only. Keep FIDO2, WHfB, and CBA as the only allowed methods for this application." `
                -RoadmapPhase "Strategic" -MaturityContribution 5
        }
        else {
            # No MFA at all — already caught in D1.1 as Critical; do not double-count
            $maturityPoints += 1
        }

        # ── Check 3.3: Token lifetime / sign-in frequency controls ────────────────
        $signInFreqPolicies = @($coveringPolicies | Where-Object {
                $_.sessionControls -and $_.sessionControls.signInFrequency -and
                $_.sessionControls.signInFrequency.isEnabled -eq $true
            })

        if ($signInFreqPolicies.Count -eq 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D3" -DomainName "Authentication Strength" -CheckId "D3.3" `
                -Title "No Sign-In Frequency Control Applied — Long-Lived Sessions Permitted" `
                -Evidence "CA policies with sign-in frequency controls covering this app: 0" `
                -CurrentState "No CA policy enforces a sign-in frequency (token re-authentication interval) for this application. Sessions may persist for up to the platform default (typically 90 days for refresh tokens)." `
                -Gap "Without sign-in frequency controls, a stolen refresh token provides extended access without re-verification of identity or device. Continuous authentication validation is a Zero Trust session control requirement." `
                -Risk "Medium" -BusinessImpact "Stolen refresh tokens for this application remain valid for the platform default lifetime (days to weeks). An attacker with a stolen token has persistent access without triggering re-authentication." `
                -TargetState "Sign-in frequency enforced at an interval appropriate to application sensitivity (1 hour for high-sensitivity, 8 hours for standard business apps). Continuous Access Evaluation (CAE) enabled for real-time revocation." `
                -Recommendation "Add a sign-in frequency session control to the CA policy for this application. For high-sensitivity apps, set 1-hour frequency. For standard apps, 8 hours. Enable Continuous Access Evaluation for this application to allow real-time token revocation on user risk events." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D3" -DomainName "Authentication Strength" -CheckId "D3.3" `
                -Title "Sign-In Frequency Control Applied ($($signInFreqPolicies.Count) policy/ies)" `
                -Evidence "CA policies with sign-in frequency: $($signInFreqPolicies.Count)" `
                -CurrentState "Sign-in frequency controls are in place. Users are required to re-authenticate at a defined interval when accessing this application." `
                -Gap "Review the configured frequency interval against the sensitivity of data this application exposes. Check whether Continuous Access Evaluation (CAE) is also enabled for real-time revocation." `
                -Risk "Info" -BusinessImpact "Low — session lifetime is controlled. Verify frequency is appropriate for data sensitivity." `
                -TargetState "Sign-in frequency aligned to app sensitivity. CAE enabled for real-time token revocation on risk signal or policy change." `
                -Recommendation "Review the configured interval in the CA policy. Enable CAE for this application in the Entra ID app registration (CAE claim verification) for real-time continuous evaluation alongside the periodic frequency control." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D3" -Name "Authentication Strength" -Icon "🔐" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Legacy auth blocked: $(if ($legacyBlockPolicies.Count -gt 0){'Yes'}else{'No'}). Authentication Strength: $($authStrengthPolicies.Count) policies. Sign-in frequency: $($signInFreqPolicies.Count) policies." `
            -TargetStateSummary "Legacy auth blocked tenant-wide. Phishing-resistant Authentication Strength enforced. Sign-in frequency + CAE active." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 4: Least Privilege & Permission Governance ─────────────────

    Function Invoke-Domain4-LeastPrivilege {
        param ([PSCustomObject]$AppContext)

        Write-Host "  🔬  D4: Least Privilege & Permission Governance..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $appReg = $AppContext.AppRegistration

        if (-not $appReg) {
            $maturityPoints += 2
            Set-DomainResult -Id "D4" -Name "Least Privilege & Permissions" -Icon "🔬" `
                -MaturityScore 2 `
                -CurrentStateSummary "App registration not resolvable (first-party Microsoft application or external tenant app). Partial assessment." `
                -TargetStateSummary "All permission scopes reviewed and justified. Application permissions minimised. Admin consent for all grants documented." `
                -CriticalCount 0 -HighCount 0 -MediumCount 0 -LowCount 0 -DataQuality "Insufficient"
            return
        }

        $requiredResources = $appReg.requiredResourceAccess
        $totalPermissions = 0
        $highRiskCount = 0
        $mediumRiskCount = 0
        $applicationPermCount = 0
        $delegatedPermCount = 0
        $highRiskNames = [System.Collections.ArrayList]::new()
        $mediumRiskNames = [System.Collections.ArrayList]::new()

        if ($requiredResources) {
            foreach ($resource in $requiredResources) {
                foreach ($access in $resource.resourceAccess) {
                    $totalPermissions++
                    $riskLevel = Get-PermissionRiskLevel -PermissionId $access.id -PermissionType $access.type
                    $permName = Get-PermissionDisplayName -PermissionId $access.id

                    if ($access.type -eq "Role") { $applicationPermCount++ } else { $delegatedPermCount++ }

                    switch ($riskLevel) {
                        "High" {
                            $highRiskCount++
                            $null = $highRiskNames.Add("$permName [$($access.type)]")
                        }
                        "Medium" {
                            $mediumRiskCount++
                            $null = $mediumRiskNames.Add("$permName [$($access.type)]")
                        }
                    }
                }
            }
        }

        # ── Check 4.1: High-risk Application permissions ──────────────────────────
        if ($highRiskCount -gt 0) {
            if ($applicationPermCount -gt 0 -and $highRiskCount -ge 3) {
                $critical++
                $maturityPoints += 1
                $risk = "Critical"
                $phase = "0-30 Days"
            }
            else {
                $high++
                $maturityPoints += 2
                $risk = "High"
                $phase = "31-60 Days"
            }

            Add-Finding -DomainId "D4" -DomainName "Least Privilege & Permissions" -CheckId "D4.1" `
                -Title "High-Risk Permissions Requested — $highRiskCount Scope(s) with Significant Blast Radius" `
                -Evidence "Total permissions: $totalPermissions | High-risk: $highRiskCount | Application (non-interactive): $applicationPermCount | Delegated: $delegatedPermCount | High-risk scopes: $(($highRiskNames | Select-Object -First 5) -join '; ')" `
                -CurrentState "$highRiskCount high-risk permission scope(s) are declared in this application's required resource access. Application-type permissions ($applicationPermCount) are always active and not user-constrained." `
                -Gap "High-risk Application permissions grant this application persistent, non-interactive access to tenant-wide data and operations. There is no user-level scope — the application acts with full permission at all times." `
                -Risk $risk `
                -BusinessImpact "A compromised service credential for this application enables immediate access to the resources covered by these high-risk scopes — directory write, mail, files, or security events — with no MFA and no user approval at runtime." `
                -TargetState "No high-risk Application permissions without documented business justification, quarterly review, and compensating controls (Managed Identity, short-lived FIC tokens, alert-on-use monitoring)." `
                -Recommendation "For each high-risk permission: (1) confirm it is actively used (check App Insights / sign-in logs), (2) explore scoped alternatives (e.g. Mail.Send vs Mail.ReadWrite), (3) document business justification, (4) schedule quarterly privilege review, (5) protect the workload credential with Managed Identity or Workload Identity Federation." `
                -RoadmapPhase $phase -MaturityContribution ($maturityPoints[-1])
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D4" -DomainName "Least Privilege & Permissions" -CheckId "D4.1" `
                -Title "No High-Risk Permissions Detected ($totalPermissions total scope(s))" `
                -Evidence "Total permissions: $totalPermissions | High-risk: 0 | Application permissions: $applicationPermCount | Delegated: $delegatedPermCount" `
                -CurrentState "No high-risk permission scopes are declared. The application's required permissions are within moderate risk boundaries." `
                -Gap "Continue to review permissions for creep over time. Medium-risk Application permissions ($mediumRiskCount detected) should also be justified and monitored." `
                -Risk "Info" -BusinessImpact "Low — permission footprint is within acceptable boundaries. Focus on monitoring and preventing permission creep through change control." `
                -TargetState "Formal permission justification register maintained. All permissions reviewed quarterly. Zero unused or stale permissions." `
                -Recommendation "Implement a permission change control process: any new scope addition requires architectural review. Schedule quarterly permission audit using Entra ID Workbook — App Permissions." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 4.2: Medium-risk Application permissions ────────────────────────
        if ($mediumRiskCount -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D4" -DomainName "Least Privilege & Permissions" -CheckId "D4.2" `
                -Title "Medium-Risk Permissions Present — $mediumRiskCount Scope(s) with Broad Read Access" `
                -Evidence "Medium-risk scopes: $mediumRiskCount | Examples: $(($mediumRiskNames | Select-Object -First 5) -join '; ')" `
                -CurrentState "$mediumRiskCount medium-risk permission scope(s) are declared. These include read-all permissions over user data, directory, audit logs, or files." `
                -Gap "Read-all Application permissions provide access to all data in the covered resource regardless of organisational boundaries. Least privilege requires scoping to the minimum data set needed." `
                -Risk "Medium" -BusinessImpact "Broad read permissions enable data exfiltration if the application's workload identity is compromised. User.Read.All and Files.Read.All in particular provide extensive data harvesting capability." `
                -TargetState "Medium-risk Application permissions reviewed and replaced with scoped alternatives where available. Remaining permissions documented with data flow justification." `
                -Recommendation "Review each medium-risk scope. For directory permissions, evaluate resource-specific scopes (e.g. read only specific groups rather than Directory.Read.All). For file permissions, evaluate SharePoint site-scoped access. Document data flow for retained permissions." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
        }

        # ── Check 4.3: Application (non-interactive) vs Delegated permission ratio ─
        if ($totalPermissions -gt 0) {
            $appPermRatio = [Math]::Round(($applicationPermCount / $totalPermissions) * 100, 0)

            if ($appPermRatio -gt 70 -and $applicationPermCount -gt 5) {
                $medium++
                $maturityPoints += 2
                Add-Finding -DomainId "D4" -DomainName "Least Privilege & Permissions" -CheckId "D4.3" `
                    -Title "High Application Permission Ratio — $appPermRatio% of Scopes Are Non-Interactive (App)" `
                    -Evidence "Application permissions: $applicationPermCount ($appPermRatio%) | Delegated permissions: $delegatedPermCount | Total: $totalPermissions" `
                    -CurrentState "$appPermRatio% of this application's declared permissions are Application type (non-interactive, always active). Only $delegatedPermCount are Delegated (user-scoped)." `
                    -Gap "A high ratio of Application permissions means the application acts autonomously with broad tenant-wide access. This is appropriate for daemon/automation workloads but should be reviewed for user-facing applications." `
                    -Risk "Medium" -BusinessImpact "Application permissions are always active — they are not scoped to the authenticated user's data. A user-facing app with high Application permission ratios holds far more access than any individual user it serves." `
                    -TargetState "User-facing applications use primarily Delegated permissions (scoped to the authenticated user). Application permissions limited to daemon/background workloads with explicit justification." `
                    -Recommendation "Review whether this application serves human users or operates as a daemon. For user-facing apps, replace Application permissions with Delegated equivalents where the API supports them. For daemon apps, this ratio is expected — document the daemon classification." `
                    -RoadmapPhase "61-90 Days" -MaturityContribution 2
            }
            else {
                $maturityPoints += 4
                Add-Finding -DomainId "D4" -DomainName "Least Privilege & Permissions" -CheckId "D4.3" `
                    -Title "Application vs Delegated Permission Balance Is Appropriate ($appPermRatio% Application)" `
                    -Evidence "Application permissions: $applicationPermCount ($appPermRatio%) | Delegated: $delegatedPermCount | Total: $totalPermissions" `
                    -CurrentState "The ratio of Application to Delegated permissions is within acceptable bounds for this application type." `
                    -Gap "Ensure the classification (user-facing vs daemon) is documented. For user-facing apps, continue to prefer Delegated permissions for new scopes." `
                    -Risk "Info" -BusinessImpact "Low — permission type balance is appropriate. Maintain this pattern through change control." `
                    -TargetState "Permission type documented and justified per application classification. New scope additions reviewed against the Delegated-first principle." `
                    -Recommendation "Document whether this is a user-facing or daemon application. Codify the Delegated-first permission policy in the app registration governance process." `
                    -RoadmapPhase "Strategic" -MaturityContribution 4
            }
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D4" -Name "Least Privilege & Permissions" -Icon "🔬" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Total permissions: $totalPermissions. High-risk: $highRiskCount. Medium-risk: $mediumRiskCount. Application type: $applicationPermCount. Delegated: $delegatedPermCount." `
            -TargetStateSummary "Zero unjustified high-risk permissions. Delegated-first for user-facing apps. Quarterly permission review. All scopes documented with business justification." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 5: Privileged Access to Application ────────────────────────

    Function Invoke-Domain5-PrivilegedAccess {
        param ([PSCustomObject]$AppContext)

        Write-Host "  👑  D5: Privileged Access to Application..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $spnObjectId = $AppContext.SpnObjectId
        $appRegId = $AppContext.AppRegistrationObjectId

        # ── Check 5.1: Application owners ────────────────────────────────────────
        $owners = $null
        if ($appRegId) {
            $owners = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/applications/$appRegId/owners?`$select=id,displayName,userPrincipalName,userType"
        }

        if (-not $owners -or $owners.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D5" -DomainName "Privileged Access" -CheckId "D5.1" `
                -Title "No Owners Assigned to This Application Registration" `
                -Evidence "App Registration owners: 0" `
                -CurrentState "The application registration has no assigned owners. No individual is formally accountable for this application's configuration and security posture." `
                -Gap "An ownerless application is a governance gap — changes can be made by Global Admins or Application Admins without an application-specific accountable owner. Security incidents have no clear escalation path." `
                -Risk "High" -BusinessImpact "Without an accountable owner, permission changes, credential additions, and manifest updates may go unnoticed. In a security incident, there is no designated responder for this application." `
                -TargetState "Minimum 2 named owners assigned: a primary (application developer/lead) and a secondary (team manager or security delegate). Owners reviewed annually." `
                -Recommendation "Assign at least 2 owners to this application registration: a technical owner (developer lead) and a business/security owner (team manager or ISSO). Avoid assigning Global Admins as owners — use application-specific accounts." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $guestOwners = @($owners | Where-Object { $_.userType -eq "Guest" })
            $ownerNames = ($owners | Select-Object -First 5 | ForEach-Object {
                    if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName }
                }) -join ", "

            if ($guestOwners.Count -gt 0) {
                $high++
                $maturityPoints += 1
                Add-Finding -DomainId "D5" -DomainName "Privileged Access" -CheckId "D5.1" `
                    -Title "External (Guest) Users Are Application Owners — $($guestOwners.Count) Guest Owner(s)" `
                    -Evidence "Total owners: $($owners.Count) | Guest owners: $($guestOwners.Count) | All owners: $ownerNames" `
                    -CurrentState "$($guestOwners.Count) guest (external) user(s) are assigned as owners of this application registration. Guest owners have the same configuration rights as internal owners." `
                    -Gap "External identities as application owners represent a privileged access risk. Guest accounts are not subject to the same lifecycle controls as internal accounts. A lapsed B2B guest retains owner rights until manually removed." `
                    -Risk "High" -BusinessImpact "Guest owners can modify app manifests, add credentials, change redirect URIs, and alter permission declarations. Stale guest accounts with owner rights are an uncontrolled privileged access path into this application." `
                    -TargetState "Application owners restricted to internal (member) users only. Guest users removed from owner assignments immediately." `
                    -Recommendation "Remove all guest users from the application owner list immediately. Replace with named internal users (member accounts). If external accountability is required, use an internal proxy account or a shared mailbox with access review." `
                    -RoadmapPhase "0-30 Days" -MaturityContribution 1
            }
            elseif ($owners.Count -lt 2) {
                $medium++
                $maturityPoints += 2
                Add-Finding -DomainId "D5" -DomainName "Privileged Access" -CheckId "D5.1" `
                    -Title "Only One Owner Assigned — No Redundant Accountability" `
                    -Evidence "Total owners: $($owners.Count) | Owner(s): $ownerNames" `
                    -CurrentState "This application has only one owner. Single-owner applications create an accountability and business continuity risk." `
                    -Gap "If the single owner leaves the organisation or is unavailable during an incident, there is no secondary owner to authorise changes or lead incident response for this application." `
                    -Risk "Medium" -BusinessImpact "Business continuity risk: credential rotation, emergency access changes, and security incident response are blocked if the single owner is unavailable." `
                    -TargetState "Minimum 2 owners: a technical owner and a business/security owner. Access reviewed annually." `
                    -Recommendation "Add a secondary owner (team manager or security delegate). Avoid using shared service accounts as owners — use named individuals with clear accountability." `
                    -RoadmapPhase "31-60 Days" -MaturityContribution 2
            }
            else {
                $maturityPoints += 4
                Add-Finding -DomainId "D5" -DomainName "Privileged Access" -CheckId "D5.1" `
                    -Title "Application Has $($owners.Count) Named Owner(s) — Accountability Is Present" `
                    -Evidence "Owner count: $($owners.Count) | Owners: $ownerNames" `
                    -CurrentState "The application has multiple named owners providing accountability and business continuity." `
                    -Gap "Ensure owner list is current. Validate no guest accounts are included (currently confirmed: none). Schedule annual owner review." `
                    -Risk "Info" -BusinessImpact "Low — ownership accountability is established. Maintain through annual access reviews." `
                    -TargetState "Owners reviewed annually. No guest owners. Each owner with documented role (technical vs business/security)." `
                    -Recommendation "Document each owner's role (technical vs security). Add annual calendar reminder to review owner list, especially after staff changes. Consider using Entra ID Access Reviews to automate this process." `
                    -RoadmapPhase "Strategic" -MaturityContribution 4
            }
        }

        # ── Check 5.2: App role assignments (who has access to the application) ────
        $appRoleAssignments = $null
        if ($spnObjectId) {
            $appRoleAssignments = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals/$spnObjectId/appRoleAssignedTo?`$select=id,principalId,principalDisplayName,principalType,appRoleId"
        }

        $totalAssignments = if ($appRoleAssignments) { $appRoleAssignments.Count } else { 0 }
        $groupAssignments = @($appRoleAssignments | Where-Object { $_.principalType -eq "Group" })
        $userAssignments = @($appRoleAssignments | Where-Object { $_.principalType -eq "User" })
        $spnAssignments = @($appRoleAssignments | Where-Object { $_.principalType -eq "ServicePrincipal" })

        if ($totalAssignments -eq 0) {
            # App role assignment not required — open access OR no assignments yet
            $appRoleAssignmentRequired = $AppContext.AppRoleAssignmentRequired

            if ($appRoleAssignmentRequired -eq $false) {
                $high++
                $maturityPoints += 1
                Add-Finding -DomainId "D5" -DomainName "Privileged Access" -CheckId "D5.2" `
                    -Title "App Role Assignment NOT Required — Any User in Tenant Can Access This Application" `
                    -Evidence "appRoleAssignmentRequired: false | App Role Assignments in appRoleAssignedTo: 0" `
                    -CurrentState "The enterprise application (service principal) does not require users to be explicitly assigned before accessing it. Any user in the tenant can authenticate to this application if they hold a valid token." `
                    -Gap "Zero Trust requires explicit assignment of users and groups to applications (least-privilege access). Open access violates the 'verify explicitly' and 'assume breach' principles by trusting all tenant users implicitly." `
                    -Risk "High" `
                    -BusinessImpact "Every user in the tenant is a potential user of this application, regardless of role, department, or need-to-know. Data exposed by this application is accessible to all authenticated users — a significant over-entitlement for most applications." `
                    -TargetState "App Role Assignment Required = true. All users and groups explicitly assigned. Access provisioned via Entra ID Entitlement Management or HR-driven group membership." `
                    -Recommendation "Enable 'Assignment Required' on the Enterprise Application (Service Principal) in Entra ID → Enterprise Applications → Properties. Then assign approved users and groups explicitly. For scale, use security groups and provision via access packages (Entitlement Management, P2)." `
                    -RoadmapPhase "0-30 Days" -MaturityContribution 1
            }
            else {
                $medium++
                $maturityPoints += 2
                Add-Finding -DomainId "D5" -DomainName "Privileged Access" -CheckId "D5.2" `
                    -Title "Assignment Required Is Enabled but No Users or Groups Are Assigned" `
                    -Evidence "appRoleAssignmentRequired: true | App Role Assignments: 0" `
                    -CurrentState "Assignment Required is enabled but no users, groups, or service principals have been assigned. This may mean the application is unused, or assignments are pending." `
                    -Gap "An application with no assignments but assignment required enabled effectively blocks all access. Confirm this is intentional (pre-production) or resolve pending assignments." `
                    -Risk "Medium" -BusinessImpact "Either the application is not accessible to anyone (possible production outage risk if this is unintended) or the application is in a pre-production state that should be confirmed." `
                    -TargetState "Correct assignments in place matching the authorised user population. Access documented and provisioned via access packages or group-based assignment." `
                    -Recommendation "Confirm whether this application is in production or pre-production. If production, identify and assign the correct user groups immediately to restore access. If pre-production, document the expected go-live assignment plan." `
                    -RoadmapPhase "0-30 Days" -MaturityContribution 2
            }
        }
        else {
            $maturityPoints += 3
            $assignmentSummary = "Total assignments: $totalAssignments (Groups: $($groupAssignments.Count), Users: $($userAssignments.Count), Service Principals: $($spnAssignments.Count))"

            if ($groupAssignments.Count -gt 0 -and $userAssignments.Count -eq 0) {
                $maturityPoints += 1  # Bonus: group-based is better than individual user assignment
                Add-Finding -DomainId "D5" -DomainName "Privileged Access" -CheckId "D5.2" `
                    -Title "Access Governed via Group Assignments — $($groupAssignments.Count) Group(s) Assigned" `
                    -Evidence $assignmentSummary `
                    -CurrentState "Application access is provisioned exclusively via group assignments — the recommended Zero Trust access model. No direct individual user assignments detected." `
                    -Gap "Verify groups are security-scoped (not All Users or broad mail-enabled groups). Ensure group membership is governed via access reviews or Entitlement Management." `
                    -Risk "Info" -BusinessImpact "Low — group-based access is scalable and auditable. Focus on group membership governance and lifecycle." `
                    -TargetState "Group assignments governed via Entitlement Management access packages. Quarterly access reviews on assigned groups. No orphaned group memberships." `
                    -Recommendation "Confirm assigned groups have access reviews configured (P2). Review group membership to ensure no 'All Users' or overly broad groups are assigned. Consider migrating assignment management to Entitlement Management access packages for self-service with approval workflow." `
                    -RoadmapPhase "Strategic" -MaturityContribution 4
            }
            else {
                Add-Finding -DomainId "D5" -DomainName "Privileged Access" -CheckId "D5.2" `
                    -Title "Application Access Assignments Present — $totalAssignments Total Assignment(s)" `
                    -Evidence $assignmentSummary `
                    -CurrentState "Users, groups, and/or service principals have explicit role assignments to this application." `
                    -Gap "Individual user assignments ($($userAssignments.Count)) are harder to review and govern at scale. Group-based assignment with access reviews is the recommended model." `
                    -Risk "Low" -BusinessImpact "Direct user assignments are manageable at small scale but become a governance burden as the application user base grows. Group-based assignment with lifecycle controls is the scalable target." `
                    -TargetState "All access via group assignment. Individual user assignments replaced by group membership. Access provisioned via Entitlement Management. Quarterly access reviews." `
                    -Recommendation "Migrate individual user assignments to named security groups. Configure access reviews for those groups. Consider Entitlement Management access packages for self-service with approval workflow (P2)." `
                    -RoadmapPhase "61-90 Days" -MaturityContribution 3
            }
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D5" -Name "Privileged Access" -Icon "👑" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Owners: $(if ($owners) { $owners.Count } else { 0 }). Assignments: $totalAssignments (Groups: $($groupAssignments.Count), Users: $($userAssignments.Count)). Assignment required: $($AppContext.AppRoleAssignmentRequired)." `
            -TargetStateSummary "2+ named internal owners. Assignment Required enabled. Group-only access via Entitlement Management. Quarterly access reviews." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 6: Workload Identity Controls ───────────────────────────────

    Function Invoke-Domain6-WorkloadIdentity {
        param ([PSCustomObject]$AppContext)

        Write-Host "  ⚙️  D6: Workload Identity Controls..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $appReg = $AppContext.AppRegistration
        $spn = $AppContext.ServicePrincipal

        if (-not $appReg) {
            $maturityPoints += 2
            Set-DomainResult -Id "D6" -Name "Workload Identity Controls" -Icon "⚙️" `
                -MaturityScore 2 `
                -CurrentStateSummary "App registration not resolvable. Credential assessment unavailable for first-party or external tenant apps." `
                -TargetStateSummary "Managed Identity or Workload Identity Federation. Zero long-lived secrets. 90-day max lifetime." `
                -CriticalCount 0 -HighCount 0 -MediumCount 0 -LowCount 0 -DataQuality "Insufficient"
            return
        }

        $passwordCreds = @($appReg.passwordCredentials)
        $keyCreds = @($appReg.keyCredentials)
        $spnType = if ($spn) { $spn.servicePrincipalType } else { "Unknown" }
        $today = Get-Date
        $warn30 = $today.AddDays(30)

        # ── Check 6.1: Credential type — secrets vs certificates ──────────────────
        $hasSecrets = $passwordCreds.Count -gt 0
        $hasCerts = $keyCreds.Count -gt 0
        $isManagedIdentity = ($spnType -eq "ManagedIdentity")

        if ($isManagedIdentity) {
            $maturityPoints += 5
            Add-Finding -DomainId "D6" -DomainName "Workload Identity Controls" -CheckId "D6.1" `
                -Title "Workload Uses Managed Identity — Secretless Authentication Achieved" `
                -Evidence "Service Principal type: ManagedIdentity | Client secrets: $($passwordCreds.Count) | Certificates: $($keyCreds.Count)" `
                -CurrentState "This workload authenticates using Managed Identity — Azure-managed credentials with no client secrets or certificates required. This is the highest Zero Trust maturity for workload identity." `
                -Gap "No credential management gap. Verify the Managed Identity has least-privilege RBAC/API permissions. Confirm no fallback client secret credentials co-exist." `
                -Risk "Info" -BusinessImpact "Low — secretless authentication eliminates credential lifecycle risk entirely. Focus on permission governance for the Managed Identity." `
                -TargetState "Managed Identity with least-privilege permissions. No fallback client secrets. RBAC/API permissions reviewed quarterly." `
                -Recommendation "Review the permissions assigned to this Managed Identity (Azure RBAC + Microsoft Graph API roles). Ensure no over-privileged assignments exist. Audit regularly via Entra Workload Identity Insights." `
                -RoadmapPhase "Strategic" -MaturityContribution 5
        }
        elseif (-not $hasSecrets -and $hasCerts) {
            $maturityPoints += 4
            Add-Finding -DomainId "D6" -DomainName "Workload Identity Controls" -CheckId "D6.1" `
                -Title "Certificate-Based Credential Only — No Client Secrets Detected" `
                -Evidence "Client secrets: 0 | Certificate credentials: $($keyCreds.Count) | Service Principal type: $spnType" `
                -CurrentState "This application uses certificate credentials only, with no client secrets. Certificate-based authentication is stronger than secret-based and supports shorter rotation cycles." `
                -Gap "Evaluate whether Workload Identity Federation (OIDC) can replace certificate management entirely, eliminating the need to manage private key distribution and rotation." `
                -Risk "Low" -BusinessImpact "Low — certificate credentials are stronger than secrets. The remaining risk is private key protection and rotation hygiene. Workload Identity Federation would further reduce this risk." `
                -TargetState "Migrate to Workload Identity Federation (if workload supports OIDC) or Managed Identity (if Azure-hosted). Zero long-lived certificate credentials." `
                -Recommendation "Evaluate the hosting environment for this application. If Azure-hosted, migrate to Managed Identity. If non-Azure (GitHub Actions, Azure DevOps, GCP, AWS), implement Workload Identity Federation via OIDC. This eliminates certificate management entirely." `
                -RoadmapPhase "61-90 Days" -MaturityContribution 4
        }
        elseif ($hasSecrets -and -not $hasCerts) {
            $high++
            $maturityPoints += 2
            Add-Finding -DomainId "D6" -DomainName "Workload Identity Controls" -CheckId "D6.1" `
                -Title "Client Secret Credentials Only — No Certificate or Secretless Authentication" `
                -Evidence "Client secrets: $($passwordCreds.Count) | Certificate credentials: 0 | Service Principal type: $spnType" `
                -CurrentState "This application authenticates using client secrets (passwords) only. Secrets are long-lived credentials that must be manually managed, rotated, and securely stored." `
                -Gap "Client secrets are the weakest workload authentication method. They require secure storage, rotation, and lifecycle management — all points of failure. Secrets checked into source control or environment variables represent a significant exfiltration risk." `
                -Risk "High" -BusinessImpact "A leaked client secret provides immediate, unrestricted access to all permissions granted to this application. Secrets in source control, CI/CD logs, or misconfigured vaults are a leading cause of application-layer breaches." `
                -TargetState "Migrate to Managed Identity (Azure-hosted workloads) or Workload Identity Federation (non-Azure). Interim: store secrets in Azure Key Vault with access control and rotation policy." `
                -Recommendation "Prioritise this application for credential modernisation: (1) If Azure-hosted → enable Managed Identity, (2) If GitHub/ADO/GCP/AWS → implement Workload Identity Federation, (3) Interim: store secrets in Azure Key Vault with Key Vault references in app config. Set 90-day secret rotation policy immediately." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        elseif ($hasSecrets -and $hasCerts) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D6" -DomainName "Workload Identity Controls" -CheckId "D6.1" `
                -Title "Both Client Secrets and Certificates Present — Redundant Credential Surface" `
                -Evidence "Client secrets: $($passwordCreds.Count) | Certificate credentials: $($keyCreds.Count)" `
                -CurrentState "This application has both client secrets and certificate credentials active simultaneously. Multiple credential types increase the attack surface and complicate lifecycle management." `
                -Gap "Each active credential independently grants access to this application's permissions. Secrets and certificates may be managed by different teams with different rotation cadences, creating inconsistent security posture." `
                -Risk "Medium" -BusinessImpact "Multiple active credentials mean multiple independent breach vectors. If one credential set is compromised but not the others, the breach may not trigger rotation of all access paths." `
                -TargetState "Single credential type only (preferably certificate or secretless). Redundant credentials removed. Migration path to Managed Identity or Workload Identity Federation planned." `
                -Recommendation "Identify which credential type is actively used (check sign-in logs for the application). Remove unused credential type. Then plan migration to Managed Identity or Workload Identity Federation to eliminate credential management entirely." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D6" -DomainName "Workload Identity Controls" -CheckId "D6.1" `
                -Title "No Credentials Registered on App Registration" `
                -Evidence "Client secrets: 0 | Certificate credentials: 0 | Service Principal type: $spnType" `
                -CurrentState "No credentials are registered on this application registration. The application may use implicit flow, Managed Identity at the platform level, or may not be actively used." `
                -Gap "Confirm the authentication mechanism used by this application. If it is a multi-tenant app authenticating users without app credentials, this is expected. If it is a daemon expecting to have credentials, this may indicate misconfiguration." `
                -Risk "Info" -BusinessImpact "Low — no credential surface present. Confirm intended authentication pattern." `
                -TargetState "Authentication pattern explicitly documented. If daemon/automation: use Managed Identity or Workload Identity Federation. If user-interactive only: no app credential is correct." `
                -Recommendation "Document the intended authentication flow for this application. If it is user-interactive only (Authorization Code + PKCE), no credentials are needed — this is correct. If it is a daemon, investigate whether Managed Identity or platform-level credentials are used outside this app registration." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 6.2: Secret expiry and lifetime governance ──────────────────────
        if ($hasSecrets) {
            $expiredSecrets = @($passwordCreds | Where-Object { $_.endDateTime -and [datetime]$_.endDateTime -lt $today })
            $expiringSecrets = @($passwordCreds | Where-Object { $_.endDateTime -and [datetime]$_.endDateTime -ge $today -and [datetime]$_.endDateTime -lt $warn30 })
            $longLivedSecrets = @($passwordCreds | Where-Object {
                    $_.startDateTime -and $_.endDateTime -and
                    ([datetime]$_.endDateTime - [datetime]$_.startDateTime).TotalDays -gt 365
                })

            if ($expiredSecrets.Count -gt 0) {
                $high++
                $maturityPoints += 1
                Add-Finding -DomainId "D6" -DomainName "Workload Identity Controls" -CheckId "D6.2a" `
                    -Title "Expired Client Secrets Detected — $($expiredSecrets.Count) Credential(s) Past Expiry" `
                    -Evidence "Expired secrets: $($expiredSecrets.Count) of $($passwordCreds.Count) total | Hints: $(($expiredSecrets | Select-Object -ExpandProperty displayName -First 3 | Where-Object {$_}) -join ', ')" `
                    -CurrentState "$($expiredSecrets.Count) client secret(s) on this application have passed their expiry date. These credentials will fail authentication attempts." `
                    -Gap "Expired credentials indicate absent credential lifecycle governance. Applications using expired secrets are either broken (service disruption) or have undocumented alternative credentials in use." `
                    -Risk "High" -BusinessImpact "Either this application is partially broken (failed auth causing service disruption), or developers have added undocumented alternative credentials as a workaround — creating untracked privileged access vectors." `
                    -TargetState "Zero expired credentials at any time. Automated renewal alerts at 90 and 30 days. All credentials tracked in a credential registry." `
                    -Recommendation "Remove expired credentials immediately. Rotate to new credentials if the app is in use. Identify and remove any undocumented workaround credentials. Implement Azure Monitor alerts for credential expiry on this application." `
                    -RoadmapPhase "0-30 Days" -MaturityContribution 1
            }

            if ($expiringSecrets.Count -gt 0) {
                $medium++
                $maturityPoints += 2
                Add-Finding -DomainId "D6" -DomainName "Workload Identity Controls" -CheckId "D6.2b" `
                    -Title "Client Secrets Expiring Within 30 Days — $($expiringSecrets.Count) Credential(s) at Risk" `
                    -Evidence "Secrets expiring < 30 days: $($expiringSecrets.Count) | Hint names: $(($expiringSecrets | Select-Object -ExpandProperty displayName -First 3 | Where-Object {$_}) -join ', ')" `
                    -CurrentState "$($expiringSecrets.Count) client secret(s) are expiring within 30 days. Immediate renewal is required to prevent service disruption." `
                    -Gap "Imminent expiry with no automated rotation signals absent credential lifecycle management." `
                    -Risk "Medium" -BusinessImpact "Service disruption within 30 days if not renewed. Emergency credential rotations under time pressure are error-prone and may result in outages or insecure interim credentials." `
                    -TargetState "Automated 90-day advance renewal alerts. Rotation completed minimum 14 days before expiry. Migration to Managed Identity removes this lifecycle burden entirely." `
                    -Recommendation "Renew expiring secrets immediately. Then plan migration to Managed Identity or Workload Identity Federation to eliminate future renewal cycles. Implement Azure Monitor alerts for 90-day and 30-day pre-expiry warnings." `
                    -RoadmapPhase "0-30 Days" -MaturityContribution 2
            }

            if ($longLivedSecrets.Count -gt 0) {
                $medium++
                $maturityPoints += 2
                Add-Finding -DomainId "D6" -DomainName "Workload Identity Controls" -CheckId "D6.2c" `
                    -Title "Long-Lived Secrets Detected — $($longLivedSecrets.Count) Credential(s) Valid for More Than 1 Year" `
                    -Evidence "Secrets with lifetime > 365 days: $($longLivedSecrets.Count) of $($passwordCreds.Count)" `
                    -CurrentState "$($longLivedSecrets.Count) client secret(s) have been configured with a lifetime exceeding 1 year. These secrets are rarely (if ever) rotated." `
                    -Gap "Long-lived secrets extend the exploitation window after a credential compromise. Many compliance frameworks mandate 90-day maximum credential lifetime for non-human identities." `
                    -Risk "Medium" -BusinessImpact "A compromised long-lived secret provides extended, potentially undetected access to all permissions granted to this application. Without rotation, a breach may not be discovered until active malicious use is observed." `
                    -TargetState "Maximum secret lifetime: 90 days. Enforced via Azure AD tenant policy where available. Automated rotation via Azure Key Vault." `
                    -Recommendation "Immediately rotate secrets with lifetime > 1 year to new credentials with ≤90 day lifetime. Implement Azure Key Vault with secret rotation and Key Vault references in the application configuration. Plan migration to Managed Identity as the permanent solution." `
                    -RoadmapPhase "31-60 Days" -MaturityContribution 2
            }

            if ($expiredSecrets.Count -eq 0 -and $expiringSecrets.Count -eq 0 -and $longLivedSecrets.Count -eq 0) {
                $maturityPoints += 3
                Add-Finding -DomainId "D6" -DomainName "Workload Identity Controls" -CheckId "D6.2" `
                    -Title "No Expired, Imminent, or Long-Lived Secrets Detected" `
                    -Evidence "Expired: 0 | Expiring <30 days: 0 | Lifetime >365 days: 0 | Total secrets: $($passwordCreds.Count)" `
                    -CurrentState "Client secret credentials appear to be within acceptable lifecycle parameters." `
                    -Gap "While secret lifecycle appears managed, migrate to Managed Identity or Workload Identity Federation to eliminate secret management overhead entirely." `
                    -Risk "Low" -BusinessImpact "Low — secret lifecycle is currently healthy. Proactive migration to secretless authentication removes this risk class permanently." `
                    -TargetState "Secretless authentication via Managed Identity or Workload Identity Federation. Zero client secrets." `
                    -Recommendation "Prioritise migration to Managed Identity (Azure-hosted) or Workload Identity Federation (non-Azure) in the next architectural iteration. This removes the credential lifecycle risk class entirely." `
                    -RoadmapPhase "61-90 Days" -MaturityContribution 3
            }
        }

        # ── Check 6.3: Multiple active credentials (blast radius amplifier) ────────
        $totalActiveCreds = $passwordCreds.Count + $keyCreds.Count
        if ($totalActiveCreds -ge 3) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D6" -DomainName "Workload Identity Controls" -CheckId "D6.3" `
                -Title "High Active Credential Count — $totalActiveCreds Credentials on This Application" `
                -Evidence "Client secrets: $($passwordCreds.Count) | Certificates: $($keyCreds.Count) | Total: $totalActiveCreds" `
                -CurrentState "This application has $totalActiveCreds active credentials — an unusually high number suggesting either poor lifecycle hygiene (orphaned old credentials) or a multi-team credential management pattern." `
                -Gap "Each active credential independently grants access. Unused or orphaned credentials represent unmonitored access paths. Multiple credentials complicate rotation and incident response." `
                -Risk "Medium" -BusinessImpact "Every active credential is an independent breach vector. Orphaned credentials from developers who have left the team may be unknown to current maintainers and go unrotated indefinitely." `
                -TargetState "Maximum 2 active credentials at any time (to support zero-downtime rotation: 1 active + 1 new-during-rotation). All credentials with names identifying owner and purpose." `
                -Recommendation "Audit all active credentials. Remove any that cannot be traced to a current system or deployment. Enforce a maximum of 2 concurrent credentials (rotation overlap only). Name credentials with owning system and rotation date for traceability." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        $credSummary = if ($isManagedIdentity) { "Managed Identity (secretless)" }
        elseif (-not $hasSecrets -and $hasCerts) { "Certificate-only ($($keyCreds.Count) cert(s))" }
        elseif ($hasSecrets) { "$($passwordCreds.Count) secret(s), $($keyCreds.Count) cert(s)" }
        else { "No credentials registered" }

        Set-DomainResult -Id "D6" -Name "Workload Identity Controls" -Icon "⚙️" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Credential type: $credSummary. Total active credentials: $totalActiveCreds. SPN type: $spnType." `
            -TargetStateSummary "Managed Identity or Workload Identity Federation. Zero client secrets. 90-day max lifetime enforced. Single active credential during rotation." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 7: Continuous Evaluation & Session Controls ─────────────────

    Function Invoke-Domain7-ContinuousEvaluation {
        param (
            [PSCustomObject]$AppContext,
            [array]$AllCAPolicies
        )

        Write-Host "  🔄  D7: Continuous Evaluation & Session Controls..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $appId = $AppContext.AppId
        $spnObjectId = $AppContext.SpnObjectId

        $enabledCA = @($AllCAPolicies | Where-Object { $_.state -eq "enabled" })

        $coveringPolicies = @($enabledCA | Where-Object {
                $incApps = $_.conditions.applications.includeApplications
                $excApps = $_.conditions.applications.excludeApplications
                ($incApps -contains "All" -or $incApps -contains $appId) -and ($excApps -notcontains $appId)
            })

        # ── Check 7.1: Persistent browser session controls ───────────────────────
        $persistentSessionPolicies = @($coveringPolicies | Where-Object {
                $_.sessionControls -and
                $_.sessionControls.persistentBrowser -and
                $_.sessionControls.persistentBrowser.isEnabled -eq $true -and
                $_.sessionControls.persistentBrowser.mode -eq "never"
            })

        if ($persistentSessionPolicies.Count -eq 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D7" -DomainName "Continuous Evaluation" -CheckId "D7.1" `
                -Title "Persistent Browser Sessions Not Restricted for This Application" `
                -Evidence "CA policies blocking persistent browser sessions for this app: 0 (of $($coveringPolicies.Count) covering policies)" `
                -CurrentState "Persistent browser sessions ('Stay signed in') are not restricted. Users may maintain long-lived authenticated sessions in browser profiles on shared or personal devices." `
                -Gap "Persistent sessions bypass re-authentication requirements. A logged-in session on an unmanaged device remains accessible even after the device is no longer compliant or the user's access is revoked." `
                -Risk "Medium" -BusinessImpact "A persistent authenticated session on a stolen laptop, shared workstation, or personal device provides continued application access after the session should have been invalidated. This is particularly risky for applications handling sensitive data." `
                -TargetState "Persistent browser sessions disabled (never) for this application. Users must re-authenticate at each session start." `
                -Recommendation "Add a session control to the CA policy for this application: Session → Persistent Browser Session → Never persist. Combine with sign-in frequency controls to define the complete session lifecycle policy." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D7" -DomainName "Continuous Evaluation" -CheckId "D7.1" `
                -Title "Persistent Browser Sessions Disabled ($($persistentSessionPolicies.Count) policy/ies)" `
                -Evidence "CA policies with persistent browser = never: $($persistentSessionPolicies.Count)" `
                -CurrentState "Persistent browser sessions are disabled for this application. Users cannot use 'Stay signed in' to maintain long-lived browser sessions." `
                -Gap "Verify this control applies to all user populations accessing this application and is not bypassed by CA policy exclusions." `
                -Risk "Info" -BusinessImpact "Low — persistent session risk is mitigated. Review exclusion groups for this session control." `
                -TargetState "Zero persistent sessions across all user populations. Combined with sign-in frequency for complete session lifecycle control." `
                -Recommendation "Confirm no CA exclusion groups bypass this control. Combine with an appropriate sign-in frequency interval to define the complete session policy." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 7.2: Sign-in frequency (re-authentication interval) ─────────────
        # Already partially covered in D3.3 — here we focus on the CAE + frequency combination
        $signInFreqPolicies = @($coveringPolicies | Where-Object {
                $_.sessionControls -and $_.sessionControls.signInFrequency -and
                $_.sessionControls.signInFrequency.isEnabled -eq $true
            })

        # ── Check 7.3: Token lifetime policy (custom token lifetime) ─────────────
        $tokenLifetimePolicies = $null
        if ($spnObjectId) {
            $tokenLifetimePolicies = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/servicePrincipals/$spnObjectId/tokenLifetimePolicies"
        }

        $hasCustomTokenLifetime = ($tokenLifetimePolicies -and
            $tokenLifetimePolicies.value -and
            $tokenLifetimePolicies.value.Count -gt 0)

        if ($signInFreqPolicies.Count -eq 0 -and -not $hasCustomTokenLifetime) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D7" -DomainName "Continuous Evaluation" -CheckId "D7.2" `
                -Title "No Token Lifetime or Sign-In Frequency Controls — Default Platform Lifetimes in Effect" `
                -Evidence "CA sign-in frequency policies: $($signInFreqPolicies.Count) | Custom token lifetime policy: $(if ($hasCustomTokenLifetime){'Yes'}else{'No'})" `
                -CurrentState "No CA sign-in frequency controls and no custom token lifetime policy are applied to this application. Default Entra ID token lifetimes are in effect (access token: 1h; refresh token: 90 days; session: persistent)." `
                -Gap "A 90-day refresh token provides 90 days of persistent access after a single authentication. This violates Zero Trust continuous verification principles for any application handling sensitive data." `
                -Risk "High" -BusinessImpact "A stolen refresh token provides 90 days of access without re-verification of identity, device health, or risk posture. This is a significant token exfiltration risk for applications accessed from unmanaged devices." `
                -TargetState "Sign-in frequency set per application sensitivity. CAE enabled for real-time token revocation. No refresh token valid for more than 8 hours for sensitive applications." `
                -Recommendation "Configure sign-in frequency in the CA policy for this application (8 hours for standard, 1 hour for sensitive). Enable Continuous Access Evaluation by ensuring the application supports CAE claims. Use Entra ID Token Protection (preview) for additional binding." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($signInFreqPolicies.Count -gt 0 -or $hasCustomTokenLifetime) {
            $maturityPoints += 4
            Add-Finding -DomainId "D7" -DomainName "Continuous Evaluation" -CheckId "D7.2" `
                -Title "Token Lifetime Controls Active — $(if ($signInFreqPolicies.Count -gt 0){"Sign-In Frequency ($($signInFreqPolicies.Count) policy/ies)"} else {"Custom Token Lifetime Policy"})" `
                -Evidence "CA sign-in frequency policies: $($signInFreqPolicies.Count) | Custom token lifetime policy: $(if ($hasCustomTokenLifetime){'Yes'}else{'No'})" `
                -CurrentState "Token lifetime is actively managed via $(if ($signInFreqPolicies.Count -gt 0){'CA sign-in frequency controls'}else{'a custom token lifetime policy'})." `
                -Gap "Evaluate whether Continuous Access Evaluation (CAE) is also in use to complement the periodic frequency control with real-time revocation." `
                -Risk "Info" -BusinessImpact "Low — token lifetime is actively managed. Add CAE for real-time revocation to achieve continuous evaluation maturity." `
                -TargetState "Sign-in frequency + CAE for real-time and periodic re-verification. Token Protection (preview) for token binding to device." `
                -Recommendation "Enable Continuous Access Evaluation claim support in the application code to receive CAE events. Consider Token Protection (currently in preview) for high-sensitivity applications." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 7.4: Recent sign-in activity — is this app actively used? ───────
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $signInUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=appId eq '$appId' and createdDateTime ge $thirtyDaysAgo&`$top=1&`$select=id,createdDateTime,userDisplayName,status,riskLevelAggregated"
        $recentSignIns = Invoke-GraphRequest -Uri $signInUri

        $nonInteractiveUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=appId eq '$appId' and createdDateTime ge $thirtyDaysAgo&`$top=1&`$select=id"
        $hasRecentSignIns = ($recentSignIns -and $recentSignIns.value -and $recentSignIns.value.Count -gt 0)

        # Count risky sign-ins if any sign-in data is available
        $riskySignInUri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=appId eq '$appId' and createdDateTime ge $thirtyDaysAgo and riskLevelAggregated ne 'none'&`$top=10&`$select=id,riskLevelAggregated,createdDateTime"
        $riskySignIns = Invoke-GraphRequest -Uri $riskySignInUri
        $riskyCount = if ($riskySignIns -and $riskySignIns.value) { $riskySignIns.value.Count } else { 0 }

        if (-not $hasRecentSignIns) {
            $low++
            $maturityPoints += 3
            Add-Finding -DomainId "D7" -DomainName "Continuous Evaluation" -CheckId "D7.3" `
                -Title "No Sign-In Activity Detected for This Application in the Past 30 Days" `
                -Evidence "Interactive sign-ins in last 30 days: 0 (or insufficient permissions to retrieve sign-in logs)" `
                -CurrentState "No interactive sign-in activity has been recorded for this application in the past 30 days. This may indicate the app is inactive, used only for non-interactive (daemon) flows, or sign-in log permissions are insufficient." `
                -Gap "Unused applications accumulate stale permissions and credentials without business justification. If the application is genuinely inactive, it should be reviewed for decommissioning." `
                -Risk "Low" -BusinessImpact "An inactive application with broad permissions is an unnecessary attack surface. If it is decommissioned, its permissions and credentials should be removed to reduce the tenant's permission footprint." `
                -TargetState "All applications verified as actively used with documented business purpose. Inactive applications decommissioned after review. Non-interactive usage confirmed in service logs." `
                -Recommendation "Investigate whether this application is genuinely inactive or used only for daemon flows (check service-side logs, not just Entra sign-in logs). If inactive: initiate decommission review with the application owner. If daemon: document this in the application record." `
                -RoadmapPhase "31-60 Days" -MaturityContribution 3
        }
        elseif ($riskyCount -gt 0) {
            $high++
            $maturityPoints += 2
            Add-Finding -DomainId "D7" -DomainName "Continuous Evaluation" -CheckId "D7.3" `
                -Title "Risky Sign-Ins Detected for This Application in the Past 30 Days — $riskyCount Event(s)" `
                -Evidence "Interactive sign-ins: Active | Risky sign-ins (non-none risk level) in last 30 days: $riskyCount" `
                -CurrentState "Entra ID Identity Protection has flagged $riskyCount sign-in(s) to this application as risky in the past 30 days." `
                -Gap "Risky sign-ins that completed authentication indicate that risk-based CA policies may not be blocking or challenging high-risk sessions effectively for this application." `
                -Risk "High" -BusinessImpact "Risky sign-ins that succeed may represent credential compromise, AiTM token theft, or anomalous access patterns. Completed risky sign-ins mean the application's data was accessed under suspicious circumstances." `
                -TargetState "Zero completed high-risk sign-ins. Medium-risk challenged with MFA. High-risk blocked. All risk events investigated within 24 hours." `
                -Recommendation "Review the risky sign-in events in Entra ID → Identity Protection → Risky Sign-Ins, filtered by this application. Confirm risk-based CA policies are in place (see D1.2 findings). Investigate each risky event and remediate affected accounts." `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D7" -DomainName "Continuous Evaluation" -CheckId "D7.3" `
                -Title "Application Is Actively Used — No Risky Sign-Ins Detected in Past 30 Days" `
                -Evidence "Sign-in activity in last 30 days: Confirmed | Risky sign-ins (non-none risk): $riskyCount" `
                -CurrentState "This application has active sign-in activity and no risky sign-in events have been detected in the past 30 days." `
                -Gap "Continue monitoring. Risk detection requires Entra ID Identity Protection (P2). Periodically review Sign-In logs for anomalous patterns even when automated risk classification is not triggered." `
                -Risk "Info" -BusinessImpact "Low — active, healthy usage pattern with no current risk signals. Maintain monitoring posture." `
                -TargetState "Continuous monitoring via Identity Protection. Alert rules for this application in SIEM or Sentinel. Zero risky sign-ins through enforcement of risk-based CA policies." `
                -Recommendation "Set up Azure Monitor alert for new risky sign-in events for this application ID. Integrate with Microsoft Sentinel (if available) for correlation with other signals. Schedule monthly sign-in anomaly review." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D7" -Name "Continuous Evaluation" -Icon "🔄" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Sign-in freq policies: $($signInFreqPolicies.Count). Persistent session blocked: $($persistentSessionPolicies.Count -gt 0). Custom token lifetime: $hasCustomTokenLifetime. Risky sign-ins (30d): $riskyCount." `
            -TargetStateSummary "Sign-in frequency + persistent session blocked. CAE enabled. No risky sign-ins. Token protection applied for sensitive apps." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── JSON Serialisation Helpers ────────────────────────────────────────

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
            $null = $sb.Append("""low"":$($d.LowCount),")
            $null = $sb.Append("""dataQuality"":""$(ConvertTo-JsonSafe $d.DataQuality)""")
            $null = $sb.Append("}")
        }

        $null = $sb.Append("]")
        return $sb.ToString()
    }

    #endregion

    #region ── HTML Dashboard Generation ─────────────────────────────────────────

    Function Generate-HtmlDashboard {
        param (
            [string]$AppDisplayName,
            [string]$AppId,
            [string]$SpnObjectId,
            [string]$SignInAudience,
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

        $maturityColor = $script:MaturityColors[[int][Math]::Round($OverallMaturity)]
        if (-not $maturityColor) { $maturityColor = "#f85149" }

        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Zero Trust Access Control Assessment — __APP_NAME__</title>
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
.logo-sub{font-size:10px;color:var(--muted);margin-top:3px;line-height:1.4}
.ver-badge{display:inline-block;font-size:9px;background:var(--surface3);color:var(--accent);padding:2px 7px;border-radius:20px;margin-top:6px;font-family:var(--mono)}
nav{flex:1;padding:10px 8px}
.nav-section{font-size:9px;font-weight:700;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;padding:10px 10px 4px}
.nav-btn{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:var(--radius-sm);cursor:pointer;font-size:12px;color:var(--muted2);margin-bottom:2px;transition:all .15s;border:none;background:none;width:100%;text-align:left}
.nav-btn:hover{background:var(--surface2);color:var(--text)}
.nav-btn.active{background:rgba(56,139,253,.12);color:var(--accent);border-left:3px solid var(--accent);font-weight:600}
.nav-btn .nav-icon{font-size:14px;width:18px;text-align:center;flex-shrink:0}
.nav-domain-score{margin-left:auto;font-size:9px;font-family:var(--mono);padding:1px 6px;border-radius:10px;font-weight:700}
.theme-toggle{padding:12px 16px;border-top:1px solid var(--border)}
.theme-pill{display:flex;background:var(--surface2);border-radius:20px;padding:3px}
.theme-opt{flex:1;padding:5px;text-align:center;font-size:11px;border-radius:16px;cursor:pointer;transition:all .2s;color:var(--muted)}
.theme-opt.active{background:var(--accent);color:#fff;font-weight:600}
.sidebar-footer{padding:10px 14px;font-size:10px;color:var(--muted);border-top:1px solid var(--border)}

/* ── Main ── */
#main{margin-left:240px;padding:28px}
.page{display:none;animation:fadeIn .25s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:24px}
.page-header h1{font-size:22px;font-weight:700}
.page-header p{color:var(--muted);font-size:13px;margin-top:4px}

/* ── ZT Posture Ring ── */
.zt-hero{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;display:flex;align-items:center;gap:28px;margin-bottom:24px}
.zt-ring-wrap{position:relative;width:128px;height:128px;flex-shrink:0}
.zt-ring-wrap svg{transform:rotate(-90deg)}
.ring-bg{stroke:var(--surface3);stroke-width:10;fill:none}
.ring-fill{stroke-width:10;fill:none;stroke-linecap:round;transition:stroke-dasharray 1.2s cubic-bezier(.4,0,.2,1)}
.ring-label{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}
.ring-val{font-size:26px;font-weight:700;font-family:var(--mono)}
.ring-sub{font-size:9px;color:var(--muted);margin-top:1px}
.zt-info{flex:1}
.zt-info h2{font-size:20px;font-weight:700;margin-bottom:4px}
.zt-app-meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.meta-chip{font-size:10px;font-family:var(--mono);padding:3px 9px;border-radius:12px;background:var(--surface3);color:var(--muted2)}
.maturity-scale{display:flex;gap:6px;margin-top:14px;flex-wrap:wrap}
.ms-pill{font-size:10px;padding:3px 10px;border-radius:20px;border:1px solid var(--border);color:var(--muted);cursor:default}
.ms-pill.active{font-weight:700;border-color:currentColor}

/* ── Stat Cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}
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

/* ── Panels ── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.panel-title{font-size:14px;font-weight:700}
.panel-badge{font-size:10px;padding:2px 9px;border-radius:20px;background:var(--surface3);color:var(--muted);font-family:var(--mono)}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}

/* ── Bar lists ── */
.bar-row{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.bar-label{font-size:12px;width:150px;flex-shrink:0;color:var(--muted2)}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s ease;width:0}
.bar-val{font-size:11px;font-family:var(--mono);color:var(--muted);width:30px;text-align:right}

/* ── Domain cards (Overview grid) ── */
.domain-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:14px;margin-bottom:24px}
.domain-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;cursor:pointer;transition:all .2s;border-left:4px solid}
.domain-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.domain-card-header{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.domain-icon{font-size:20px}
.domain-name{font-size:13px;font-weight:700;flex:1}
.maturity-badge{font-size:10px;font-weight:700;padding:3px 9px;border-radius:20px;background:rgba(255,255,255,.08)}
.domain-score-bar{height:4px;background:var(--surface3);border-radius:2px;margin-bottom:10px}
.domain-score-fill{height:100%;border-radius:2px;transition:width 1s ease}
.domain-state{font-size:11px;color:var(--muted);line-height:1.4;margin-bottom:10px}
.domain-risk-chips{display:flex;gap:6px;flex-wrap:wrap}
.risk-chip{font-size:10px;padding:2px 8px;border-radius:12px;font-weight:600;font-family:var(--mono)}
.rc-critical{background:rgba(248,81,73,.15);color:#f85149}
.rc-high    {background:rgba(210,153,34,.15);color:#d29922}
.rc-medium  {background:rgba(56,139,253,.15);color:#388bfd}
.rc-low     {background:rgba(63,185,80,.15);color:#3fb950}
.rc-info    {background:rgba(125,133,144,.15);color:#7d8590}

/* ── Zero Trust Radar chart ── */
.radar-wrap{display:flex;justify-content:center;padding:10px 0}

/* ── Roadmap timeline ── */
.roadmap-phases{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:4px}
@media(max-width:900px){.roadmap-phases{grid-template-columns:1fr 1fr}}
.phase-col{border-radius:var(--radius-sm);overflow:hidden}
.phase-header{padding:10px 14px;font-size:11px;font-weight:700;letter-spacing:.04em;display:flex;align-items:center;gap:7px}
.phase-0-30 .phase-header{background:rgba(248,81,73,.15);color:#f85149}
.phase-31-60 .phase-header{background:rgba(210,153,34,.15);color:#d29922}
.phase-61-90 .phase-header{background:rgba(56,139,253,.15);color:#388bfd}
.phase-strategic .phase-header{background:rgba(163,113,247,.15);color:#a371f7}
.phase-items{padding:10px;background:var(--surface2);min-height:60px}
.phase-item{font-size:11px;padding:7px 9px;margin-bottom:6px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);line-height:1.4}
.phase-item .pi-domain{font-size:9px;font-family:var(--mono);color:var(--muted);margin-bottom:2px}
.phase-item .pi-risk{float:right;font-size:9px;font-weight:700;font-family:var(--mono)}
.pi-risk-Critical{color:#f85149}
.pi-risk-High    {color:#d29922}
.pi-risk-Medium  {color:#388bfd}
.pi-risk-Low     {color:#3fb950}

/* ── Findings table ── */
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
.fpill-med.active   {background:var(--accent);color:#fff;border-color:var(--accent)}
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
.pagination{display:flex;align-items:center;gap:8px;margin-top:14px;flex-wrap:wrap}
.page-size-sel{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 8px;color:var(--text);font-size:11px;font-family:var(--sans)}
.pg-info{font-size:11px;color:var(--muted);flex:1}
.pg-btn{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 10px;color:var(--text);font-size:11px;cursor:pointer}
.pg-btn:hover:not(:disabled){background:var(--surface3)}
.pg-btn:disabled{opacity:.4;cursor:default}
.pg-num{display:flex;gap:4px}
.pg-n{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 9px;font-size:11px;cursor:pointer;font-family:var(--mono)}
.pg-n:hover{background:var(--surface3)}
.pg-n.active{background:var(--accent);color:#fff;border-color:var(--accent)}

/* ── Detail Drawer ── */
#detailBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:200;backdrop-filter:blur(2px)}
#detailBackdrop.open{display:block}
#detailDrawer{position:fixed;right:-520px;top:0;width:520px;height:100vh;background:var(--surface);border-left:1px solid var(--border);z-index:201;overflow-y:auto;transition:right .3s cubic-bezier(.4,0,.2,1);padding:24px}
#detailDrawer.open{right:0}
.drawer-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px}
.drawer-close{background:none;border:none;color:var(--muted);font-size:18px;cursor:pointer;padding:4px;border-radius:4px}
.drawer-close:hover{color:var(--text);background:var(--surface2)}
.drawer-nav{display:flex;gap:8px;margin-top:8px}
.drawer-nav-btn{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 10px;font-size:11px;cursor:pointer;color:var(--text)}
.drawer-nav-btn:hover:not(:disabled){background:var(--surface3)}
.drawer-nav-btn:disabled{opacity:.4;cursor:default}
.drawer-title{font-size:15px;font-weight:700;line-height:1.4;flex:1;margin-right:12px}
.drawer-chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
.d-chip{font-size:10px;padding:3px 9px;border-radius:12px;background:var(--surface3);color:var(--muted2);font-family:var(--mono)}
.drawer-section{margin-bottom:14px}
.drawer-section-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:5px}
.drawer-section-body{font-size:12px;color:var(--muted2);line-height:1.6;background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px;border-left:3px solid var(--border)}
.drawer-section-body.evidence{border-left-color:var(--accent);font-family:var(--mono);font-size:11px}
.drawer-section-body.gap-body{border-left-color:var(--amber)}
.drawer-section-body.target-body{border-left-color:var(--green)}
.drawer-section-body.impact-body{border-left-color:var(--red)}
.drawer-section-body.rec-body{border-left-color:var(--accent3)}

/* ── Toast ── */
#toast{position:fixed;bottom:24px;right:24px;background:var(--surface3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 14px;font-size:12px;opacity:0;transform:translateY(10px);transition:all .25s;z-index:300;pointer-events:none}
#toast.show{opacity:1;transform:none}

/* ── Mobile ── */
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:150;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;font-size:16px;color:var(--text)}
@media(max-width:768px){
  #menuToggle{display:block}
  #sidebar{transform:translateX(-100%);transition:transform .3s}
  #sidebar.mobile-open{transform:none}
  #main{margin-left:0;padding:16px;padding-top:52px}
}
</style>
</head>
<body>

<button id="menuToggle" onclick="toggleMobileMenu()">☰</button>

<div id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🛡️</div>
    <div class="logo-title">Zero Trust Access Control<br>Architecture Assessment</div>
    <div class="logo-sub">__APP_NAME__</div>
    <span class="ver-badge">v1.0</span>
  </div>
  <nav>
    <div class="nav-section">Assessment Views</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">📊</span> Overview
    </button>
    <button class="nav-btn" onclick="showPage('domains',this)">
      <span class="nav-icon">🏛️</span> ZT Domains
    </button>
    <button class="nav-btn" onclick="showPage('findings',this)">
      <span class="nav-icon">🔍</span> Findings
      <span class="nav-domain-score" style="background:rgba(248,81,73,.15);color:#f85149" id="nav-critical-count">__TOTAL_CRITICAL__</span>
    </button>
    <button class="nav-btn" onclick="showPage('roadmap',this)">
      <span class="nav-icon">🗺️</span> Roadmap
    </button>
    <div class="nav-section" style="margin-top:8px">Zero Trust Domains</div>
    <div id="domainNavItems"></div>
  </nav>
  <div class="theme-toggle">
    <div class="theme-pill">
      <div class="theme-opt active" onclick="setTheme('dark',this)">Dark</div>
      <div class="theme-opt" onclick="setTheme('light',this)">Light</div>
    </div>
  </div>
  <div class="sidebar-footer">
    Generated: __ASSESS_DATE__<br>
    Tenant: <span style="font-family:var(--mono);font-size:9px">__TENANT_ID_SHORT__</span>
  </div>
</div>

<div id="main">

  <!-- ═══════════════════════ OVERVIEW PAGE ═══════════════════════ -->
  <div class="page active" id="page-overview">
    <div class="page-header">
      <h1>Zero Trust Access Control Assessment</h1>
      <p>Evaluated: <strong>__APP_NAME__</strong> &nbsp;·&nbsp; __ASSESS_DATE__ &nbsp;·&nbsp; 7 Zero Trust Domains</p>
    </div>

    <!-- ZT Posture Ring -->
    <div class="zt-hero">
      <div class="zt-ring-wrap">
        <svg viewBox="0 0 128 128" width="128" height="128">
          <circle class="ring-bg" cx="64" cy="64" r="54"/>
          <circle class="ring-fill" cx="64" cy="64" r="54"
            stroke="__MATURITY_COLOR__"
            stroke-dasharray="__RING_DASH__ __RING_GAP__"/>
        </svg>
        <div class="ring-label">
          <div class="ring-val" style="color:__MATURITY_COLOR__">__OVERALL_MATURITY__</div>
          <div class="ring-sub">/ 5.0</div>
        </div>
      </div>
      <div class="zt-info">
        <h2>Zero Trust Maturity: <span style="color:__MATURITY_COLOR__">__MATURITY_LABEL__</span></h2>
        <p style="color:var(--muted2);font-size:13px;margin-top:4px;line-height:1.5">This score reflects how closely this application's access model aligns with Zero Trust principles across identity assurance, device assurance, authentication strength, least privilege, privileged access, workload identity controls, and continuous evaluation.</p>
        <div class="zt-app-meta">
          <span class="meta-chip">AppId: __APP_ID__</span>
          <span class="meta-chip">SPN: __SPN_ID_SHORT__</span>
          <span class="meta-chip">Audience: __SIGN_IN_AUDIENCE__</span>
        </div>
        <div class="maturity-scale">
          <div class="ms-pill" style="color:#f85149">1 · Initial</div>
          <div class="ms-pill" style="color:#d29922">2 · Developing</div>
          <div class="ms-pill" style="color:#388bfd">3 · Defined</div>
          <div class="ms-pill" style="color:#39c5cf">4 · Managed</div>
          <div class="ms-pill" style="color:#3fb950">5 · Optimised</div>
        </div>
      </div>
    </div>

    <!-- Risk Summary Stats -->
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
        <div class="stat-label">Low Findings</div>
        <div class="stat-value" style="color:var(--green)">__TOTAL_LOW__</div>
        <div class="stat-sub">Backlog / hardening</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-label">ZT Maturity Score</div>
        <div class="stat-value" style="color:__MATURITY_COLOR__">__OVERALL_MATURITY__</div>
        <div class="stat-sub">/ 5.0 &nbsp;·&nbsp; __MATURITY_LABEL__</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-label">Total Findings</div>
        <div class="stat-value" style="color:var(--accent3)">__TOTAL_FINDINGS__</div>
        <div class="stat-sub">Across 7 ZT domains</div>
      </div>
    </div>

    <!-- Domain Overview Grid -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Zero Trust Domain Summary</span>
        <span class="panel-badge">7 domains</span>
      </div>
      <div class="domain-grid" id="overview-domain-grid"></div>
    </div>

    <!-- Key Actions -->
    <div class="panel" id="key-actions-panel">
      <div class="panel-header">
        <span class="panel-title">Top Priority Actions</span>
        <span class="panel-badge">Critical + High</span>
      </div>
      <div id="key-actions-list"></div>
    </div>
  </div>

  <!-- ═══════════════════════ ZT DOMAINS PAGE ═══════════════════════ -->
  <div class="page" id="page-domains">
    <div class="page-header">
      <h1>Zero Trust Domain Deep-Dive</h1>
      <p>Current state, target state, and gap analysis for each architectural domain</p>
    </div>
    <div id="domain-detail-grid"></div>
  </div>

  <!-- ═══════════════════════ FINDINGS PAGE ═══════════════════════ -->
  <div class="page" id="page-findings">
    <div class="page-header">
      <h1>Findings Register</h1>
      <p>All assessment findings — filterable, sortable, and searchable</p>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findingSearch" placeholder="Search findings..." oninput="filterFindings()">
        </div>
        <div class="filter-pills">
          <span class="fpill fpill-all active" onclick="setRiskFilter('All',this)">All</span>
          <span class="fpill fpill-crit" onclick="setRiskFilter('Critical',this)">🔴 Critical</span>
          <span class="fpill fpill-high" onclick="setRiskFilter('High',this)">🟠 High</span>
          <span class="fpill fpill-med"  onclick="setRiskFilter('Medium',this)">🔵 Medium</span>
          <span class="fpill fpill-low"  onclick="setRiskFilter('Low',this)">🟢 Low</span>
          <span class="fpill fpill-low"  onclick="setRiskFilter('Info',this)">⚪ Info</span>
        </div>
        <button class="pg-btn" onclick="exportFindingsCsv()">⬇ CSV</button>
      </div>
      <div style="overflow-x:auto">
        <table id="findingsTable">
          <thead>
            <tr>
              <th onclick="sortFindings('risk')"       class="sort-active">Risk <span class="sort-arrow">↕</span></th>
              <th onclick="sortFindings('domainName')">Domain <span class="sort-arrow">↕</span></th>
              <th onclick="sortFindings('checkId')">Check <span class="sort-arrow">↕</span></th>
              <th onclick="sortFindings('title')">Finding <span class="sort-arrow">↕</span></th>
              <th onclick="sortFindings('roadmapPhase')">Roadmap <span class="sort-arrow">↕</span></th>
              <th></th>
            </tr>
          </thead>
          <tbody id="findingsBody"></tbody>
        </table>
      </div>
      <div class="pagination">
        <select class="page-size-sel" id="pageSizeSel" onchange="changePageSize()">
          <option value="10">10/page</option>
          <option value="25" selected>25/page</option>
          <option value="50">50/page</option>
        </select>
        <span class="pg-info" id="pgInfo"></span>
        <button class="pg-btn" id="pgPrev" onclick="changePage(-1)">← Prev</button>
        <div class="pg-num" id="pgNums"></div>
        <button class="pg-btn" id="pgNext" onclick="changePage(1)">Next →</button>
      </div>
    </div>
  </div>

  <!-- ═══════════════════════ ROADMAP PAGE ═══════════════════════ -->
  <div class="page" id="page-roadmap">
    <div class="page-header">
      <h1>Improvement Roadmap</h1>
      <p>Prioritised action plan: where to start, what to do next, and what to sustain</p>
    </div>
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Zero Trust Improvement Roadmap</span>
        <span class="panel-badge">__TOTAL_FINDINGS__ actions</span>
      </div>
      <div class="roadmap-phases" id="roadmapGrid"></div>
    </div>
    <div class="panel" style="margin-top:18px">
      <div class="panel-header">
        <span class="panel-title">Architectural Thinking Model</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;text-align:center;padding:8px 0">
        <div><div style="font-size:22px;margin-bottom:6px">🔍</div><div style="font-size:12px;font-weight:700">Current State</div><div style="font-size:11px;color:var(--muted);margin-top:3px">What does the access model look like today?</div></div>
        <div style="display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:18px">→</div>
        <div><div style="font-size:22px;margin-bottom:6px">⚠️</div><div style="font-size:12px;font-weight:700">Gap &amp; Risk</div><div style="font-size:11px;color:var(--muted);margin-top:3px">What is missing and why does it matter?</div></div>
        <div style="display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:18px">→</div>
        <div><div style="font-size:22px;margin-bottom:6px">🎯</div><div style="font-size:12px;font-weight:700">Target State</div><div style="font-size:11px;color:var(--muted);margin-top:3px">What does Zero Trust maturity look like for this domain?</div></div>
        <div style="display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:18px">→</div>
        <div><div style="font-size:22px;margin-bottom:6px">✅</div><div style="font-size:12px;font-weight:700">Action</div><div style="font-size:11px;color:var(--muted);margin-top:3px">What specific steps will move us forward?</div></div>
      </div>
    </div>
  </div>

</div>

<!-- Detail Drawer -->
<div id="detailBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <div>
      <div class="drawer-title" id="drawerTitle"></div>
      <div class="drawer-nav">
        <button class="drawer-nav-btn" id="drawerPrev" onclick="navigateDrawer(-1)">← Previous</button>
        <button class="drawer-nav-btn" id="drawerNext" onclick="navigateDrawer(1)">Next →</button>
      </div>
    </div>
    <button class="drawer-close" onclick="closeDrawer()">✕</button>
  </div>
  <div class="drawer-chips" id="drawerChips"></div>
  <div class="drawer-section">
    <div class="drawer-section-label">Evidence</div>
    <div class="drawer-section-body evidence" id="drawerEvidence"></div>
  </div>
  <div class="drawer-section">
    <div class="drawer-section-label">Current State</div>
    <div class="drawer-section-body" id="drawerCurrent"></div>
  </div>
  <div class="drawer-section">
    <div class="drawer-section-label">Gap &amp; Zero Trust Alignment</div>
    <div class="drawer-section-body gap-body" id="drawerGap"></div>
  </div>
  <div class="drawer-section">
    <div class="drawer-section-label">Business Impact</div>
    <div class="drawer-section-body impact-body" id="drawerImpact"></div>
  </div>
  <div class="drawer-section">
    <div class="drawer-section-label">Target State</div>
    <div class="drawer-section-body target-body" id="drawerTarget"></div>
  </div>
  <div class="drawer-section">
    <div class="drawer-section-label">Recommendation</div>
    <div class="drawer-section-body rec-body" id="drawerRec"></div>
  </div>
</div>

<div id="toast"></div>

<script>
// ── Data ──────────────────────────────────────────────────────────────────────
const DOMAINS   = __DOMAINS_JSON__;
const FINDINGS  = __FINDINGS_JSON__;

const RISK_ORDER = {Critical:0,High:1,Medium:2,Low:3,Info:4};

// ── Utilities ─────────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

function showToast(msg,icon='✅'){
  const t=document.getElementById('toast');
  t.textContent=(icon?' ':'')+msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2200);
}

function setTheme(t,el){
  document.body.classList.toggle('light-theme',t==='light');
  document.querySelectorAll('.theme-opt').forEach(o=>o.classList.remove('active'));
  el.classList.add('active');
}

function showPage(id,el){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(el)el.classList.add('active');
}

function toggleMobileMenu(){
  document.getElementById('sidebar').classList.toggle('mobile-open');
}

// ── Domain Nav Items (sidebar) ────────────────────────────────────────────────
function buildDomainNav(){
  const c=document.getElementById('domainNavItems');
  DOMAINS.forEach(d=>{
    const btn=document.createElement('button');
    btn.className='nav-btn';
    btn.onclick=()=>{showPage('domains',null); scrollToDomain(d.id);};
    const score=document.createElement('span');
    score.className='nav-domain-score';
    score.style.background=d.maturityColor+'22';
    score.style.color=d.maturityColor;
    score.textContent=d.maturityScore+'/5';
    btn.innerHTML=`<span class="nav-icon">${escH(d.icon)}</span>${escH(d.name)}`;
    btn.appendChild(score);
    c.appendChild(btn);
  });
}

// ── Overview: domain grid ─────────────────────────────────────────────────────
function buildOverviewDomainGrid(){
  const g=document.getElementById('overview-domain-grid');
  DOMAINS.forEach(d=>{
    const chips=[
      d.critical>0?`<span class="risk-chip rc-critical">🔴 ${d.critical} Critical</span>`:'',
      d.high>0?`<span class="risk-chip rc-high">🟠 ${d.high} High</span>`:'',
      d.medium>0?`<span class="risk-chip rc-medium">🔵 ${d.medium} Medium</span>`:'',
      d.low>0?`<span class="risk-chip rc-low">🟢 ${d.low} Low</span>`:''
    ].filter(Boolean).join('');
    const pct=Math.round((d.maturityScore/5)*100);
    g.innerHTML+=`
    <div class="domain-card" style="border-left-color:${escH(d.maturityColor)}"
         onclick="showPage('domains',null);scrollToDomain('${escJ(d.id)}')">
      <div class="domain-card-header">
        <span class="domain-icon">${escH(d.icon)}</span>
        <span class="domain-name">${escH(d.name)}</span>
        <span class="maturity-badge" style="color:${escH(d.maturityColor)};background:${escH(d.maturityColor)}22">${escH(d.maturityLabel)}</span>
      </div>
      <div class="domain-score-bar"><div class="domain-score-fill" style="width:${pct}%;background:${escH(d.maturityColor)}"></div></div>
      <div class="domain-state">${escH(d.currentStateSummary)}</div>
      <div class="domain-risk-chips">${chips||'<span class="risk-chip rc-info">✅ No issues</span>'}</div>
    </div>`;
  });
}

// ── Overview: key actions ─────────────────────────────────────────────────────
function buildKeyActions(){
  const list=document.getElementById('key-actions-list');
  const top=FINDINGS
    .filter(f=>f.risk==='Critical'||f.risk==='High')
    .sort((a,b)=>RISK_ORDER[a.risk]-RISK_ORDER[b.risk])
    .slice(0,8);
  if(top.length===0){list.innerHTML='<p style="color:var(--muted);font-size:13px">No Critical or High findings detected. Focus on Medium findings for continued improvement.</p>';return;}
  top.forEach((f,i)=>{
    list.innerHTML+=`
    <div style="display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);cursor:pointer" onclick="openDrawer(${FINDINGS.indexOf(f)})">
      <span class="risk-badge rb-${escH(f.risk)}" style="flex-shrink:0;margin-top:1px">${escH(f.risk)}</span>
      <div style="flex:1">
        <div style="font-size:12px;font-weight:600">${escH(f.title)}</div>
        <div style="font-size:11px;color:var(--muted);margin-top:2px">${escH(f.domainName)} &nbsp;·&nbsp; ${escH(f.roadmapPhase)}</div>
      </div>
      <span style="color:var(--muted);font-size:12px">›</span>
    </div>`;
  });
}

// ── Domains page: detail cards ────────────────────────────────────────────────
function buildDomainDetailCards(){
  const g=document.getElementById('domain-detail-grid');
  DOMAINS.forEach(d=>{
    const domainFindings=FINDINGS.filter(f=>f.domainId===d.id);
    const sortedFindings=domainFindings.sort((a,b)=>RISK_ORDER[a.risk]-RISK_ORDER[b.risk]);
    let findingsHtml='';
    sortedFindings.forEach((f,i)=>{
      const idx=FINDINGS.indexOf(f);
      findingsHtml+=`
      <tr style="cursor:pointer" onclick="openDrawer(${idx})">
        <td><span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span></td>
        <td style="font-size:12px;font-weight:500">${escH(f.title)}</td>
        <td><span class="phase-badge">${escH(f.roadmapPhase)}</span></td>
        <td style="color:var(--muted);font-size:11px">›</td>
      </tr>`;
    });
    const pct=Math.round((d.maturityScore/5)*100);
    g.innerHTML+=`
    <div class="panel" id="domain-${escH(d.id)}" style="border-top:3px solid ${escH(d.maturityColor)}">
      <div class="panel-header">
        <span class="panel-title">${escH(d.icon)} ${escH(d.name)}</span>
        <span class="maturity-badge" style="color:${escH(d.maturityColor)};background:${escH(d.maturityColor)}22;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700">${escH(d.maturityScore)}/5 · ${escH(d.maturityLabel)}</span>
      </div>
      <div class="domain-score-bar" style="margin-bottom:16px;height:6px">
        <div class="domain-score-fill" style="width:${pct}%;background:${escH(d.maturityColor)}"></div>
      </div>
      <div class="chart-grid">
        <div>
          <div style="font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">Current State</div>
          <div style="font-size:12px;color:var(--muted2);line-height:1.6;background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px;border-left:3px solid ${escH(d.maturityColor)}">${escH(d.currentStateSummary)}</div>
        </div>
        <div>
          <div style="font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">Target State</div>
          <div style="font-size:12px;color:var(--muted2);line-height:1.6;background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px;border-left:3px solid var(--green)">${escH(d.targetStateSummary)}</div>
        </div>
      </div>
      ${findingsHtml?`
      <div style="margin-top:16px">
        <div style="font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Domain Findings</div>
        <div style="overflow-x:auto"><table><thead><tr>
          <th>Risk</th><th>Finding</th><th>Roadmap</th><th></th>
        </tr></thead><tbody>${findingsHtml}</tbody></table></div>
      </div>`:''}
    </div>`;
  });
}

function scrollToDomain(id){
  const el=document.getElementById('domain-'+id);
  if(el)setTimeout(()=>el.scrollIntoView({behavior:'smooth',block:'start'}),100);
}

// ── Findings table ────────────────────────────────────────────────────────────
let filteredFindings=[...FINDINGS];
let currentPage=1;
let pageSize=25;
let sortKey='risk';
let sortDir=1;
let riskFilter='All';

function renderFindings(){
  const body=document.getElementById('findingsBody');
  const start=(currentPage-1)*pageSize;
  const end=Math.min(start+pageSize,filteredFindings.length);
  const slice=filteredFindings.slice(start,end);
  body.innerHTML=slice.map((f,i)=>{
    const idx=FINDINGS.indexOf(f);
    return `<tr style="cursor:pointer" onclick="openDrawer(${idx})">
      <td><span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span></td>
      <td><span class="domain-tag">${escH(f.domainId)}</span> <span style="font-size:10px;color:var(--muted)">${escH(f.domainName)}</span></td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--muted)">${escH(f.checkId)}</td>
      <td style="font-size:12px;max-width:320px">${escH(f.title)}</td>
      <td><span class="phase-badge">${escH(f.roadmapPhase)}</span></td>
      <td style="color:var(--muted);font-size:12px">›</td>
    </tr>`;
  }).join('');
  renderPagination();
}

function renderPagination(){
  const total=filteredFindings.length;
  const totalPages=Math.ceil(total/pageSize)||1;
  const start=(currentPage-1)*pageSize+1;
  const end=Math.min(currentPage*pageSize,total);
  document.getElementById('pgInfo').textContent=`Showing ${start}–${end} of ${total}`;
  document.getElementById('pgPrev').disabled=currentPage<=1;
  document.getElementById('pgNext').disabled=currentPage>=totalPages;
  const nums=document.getElementById('pgNums');
  nums.innerHTML='';
  for(let p=Math.max(1,currentPage-2);p<=Math.min(totalPages,currentPage+2);p++){
    const b=document.createElement('button');
    b.className='pg-n'+(p===currentPage?' active':'');
    b.textContent=p;
    b.onclick=()=>{currentPage=p;renderFindings();};
    nums.appendChild(b);
  }
}

function changePage(d){currentPage+=d;renderFindings();}
function changePageSize(){pageSize=parseInt(document.getElementById('pageSizeSel').value);currentPage=1;renderFindings();}

function filterFindings(){
  const q=document.getElementById('findingSearch').value.toLowerCase();
  filteredFindings=FINDINGS.filter(f=>{
    const rMatch=riskFilter==='All'||f.risk===riskFilter;
    const tMatch=!q||(f.title+f.domainName+f.currentState+f.recommendation).toLowerCase().includes(q);
    return rMatch&&tMatch;
  }).sort((a,b)=>{
    let av=a[sortKey]||'',bv=b[sortKey]||'';
    if(sortKey==='risk'){av=RISK_ORDER[a.risk]??9;bv=RISK_ORDER[b.risk]??9;return (av-bv)*sortDir;}
    return av.toString().localeCompare(bv.toString())*sortDir;
  });
  currentPage=1;
  renderFindings();
}

function setRiskFilter(r,el){
  riskFilter=r;
  document.querySelectorAll('.fpill').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  filterFindings();
}

function sortFindings(key){
  if(sortKey===key)sortDir*=-1;else{sortKey=key;sortDir=1;}
  document.querySelectorAll('th').forEach(th=>th.classList.remove('sort-active'));
  event.currentTarget.classList.add('sort-active');
  filterFindings();
}

// ── Roadmap ───────────────────────────────────────────────────────────────────
function buildRoadmap(){
  const phases=[
    {key:'0-30 Days',  label:'0 – 30 Days',  cls:'phase-0-30',       icon:'🔴'},
    {key:'31-60 Days', label:'31 – 60 Days', cls:'phase-31-60',      icon:'🟠'},
    {key:'61-90 Days', label:'61 – 90 Days', cls:'phase-61-90',      icon:'🔵'},
    {key:'Strategic',  label:'Strategic',    cls:'phase-strategic',  icon:'🟣'}
  ];
  const grid=document.getElementById('roadmapGrid');
  phases.forEach(ph=>{
    const items=FINDINGS.filter(f=>f.roadmapPhase===ph.key&&f.risk!=='Info')
      .sort((a,b)=>RISK_ORDER[a.risk]-RISK_ORDER[b.risk]);
    grid.innerHTML+=`
    <div class="phase-col ${escH(ph.cls)}">
      <div class="phase-header">${ph.icon} ${escH(ph.label)}</div>
      <div class="phase-items">${items.map(f=>`
        <div class="phase-item" style="cursor:pointer" onclick="openDrawer(${FINDINGS.indexOf(f)})">
          <div class="pi-domain">${escH(f.domainId)} · ${escH(f.checkId)}</div>
          <div>${escH(f.title)} <span class="pi-risk pi-risk-${escH(f.risk)}">${escH(f.risk)}</span></div>
        </div>`).join('')||'<div style="font-size:11px;color:var(--muted);padding:4px 0">No actions in this phase</div>'}
      </div>
    </div>`;
  });
}

// ── Detail Drawer ─────────────────────────────────────────────────────────────
let currentDetailList=[];
let currentDetailIndex=0;

function openDrawer(idx){
  currentDetailList=filteredFindings.length>0?filteredFindings:FINDINGS;
  const f=FINDINGS[idx];
  currentDetailIndex=currentDetailList.indexOf(f);
  if(currentDetailIndex<0){currentDetailList=FINDINGS;currentDetailIndex=idx;}
  renderDrawer();
}

function renderDrawer(){
  const f=currentDetailList[currentDetailIndex];
  if(!f)return;
  document.getElementById('drawerTitle').textContent=f.title;
  document.getElementById('drawerChips').innerHTML=
    `<span class="d-chip risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span>`+
    `<span class="d-chip">${escH(f.domainId)} · ${escH(f.domainName)}</span>`+
    `<span class="d-chip">${escH(f.checkId)}</span>`+
    `<span class="d-chip">${escH(f.roadmapPhase)}</span>`;
  document.getElementById('drawerEvidence').textContent=f.evidence;
  document.getElementById('drawerCurrent').textContent=f.currentState;
  document.getElementById('drawerGap').textContent=f.gap;
  document.getElementById('drawerImpact').textContent=f.businessImpact;
  document.getElementById('drawerTarget').textContent=f.targetState;
  document.getElementById('drawerRec').textContent=f.recommendation;
  document.getElementById('drawerPrev').disabled=currentDetailIndex<=0;
  document.getElementById('drawerNext').disabled=currentDetailIndex>=currentDetailList.length-1;
  document.getElementById('detailBackdrop').classList.add('open');
  document.getElementById('detailDrawer').classList.add('open');
}

function navigateDrawer(d){
  currentDetailIndex+=d;
  if(currentDetailIndex<0)currentDetailIndex=0;
  if(currentDetailIndex>=currentDetailList.length)currentDetailIndex=currentDetailList.length-1;
  renderDrawer();
}

function closeDrawer(){
  document.getElementById('detailBackdrop').classList.remove('open');
  document.getElementById('detailDrawer').classList.remove('open');
}

// ── CSV Export ────────────────────────────────────────────────────────────────
function exportFindingsCsv(){
  const cols=['domainId','domainName','checkId','title','risk','roadmapPhase','currentState','gap','businessImpact','targetState','recommendation'];
  const hdr=cols.join(',');
  const rows=filteredFindings.map(f=>cols.map(c=>{
    const v=String(f[c]||'').replace(/"/g,'""');
    return `"${v}"`;
  }).join(','));
  const csv=hdr+'\n'+rows.join('\n');
  const b=new Blob([csv],{type:'text/csv'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(b);
  a.download='ZeroTrustFindings___APP_NAME_SAFE__.csv';
  a.click();
  showToast('CSV exported');
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='Escape')closeDrawer();
  if(e.key==='/'&&!['INPUT','TEXTAREA'].includes(document.activeElement.tagName)){
    e.preventDefault();
    const s=document.getElementById('findingSearch');
    if(s){s.focus();}
  }
  if(document.getElementById('detailDrawer').classList.contains('open')){
    if(e.key==='ArrowLeft')navigateDrawer(-1);
    if(e.key==='ArrowRight')navigateDrawer(1);
  }
});

// ── Init ──────────────────────────────────────────────────────────────────────
(function init(){
  buildDomainNav();
  buildOverviewDomainGrid();
  buildKeyActions();
  buildDomainDetailCards();
  filterFindings();
  buildRoadmap();
})();
</script>
</body>
</html>
'@

        # ── Token substitution ─────────────────────────────────────────────────────
        $appNameSafe = $AppDisplayName -replace '[^a-zA-Z0-9_-]', '_'
        $spnShort = if ($SpnObjectId -and $SpnObjectId.Length -gt 8) { $SpnObjectId.Substring(0, 8) + "..." } else { $SpnObjectId }
        $tenantShort = if ($TenantId -and $TenantId.Length -gt 8) { $TenantId.Substring(0, 8) + "..." } else { $TenantId }

        $html = $html `
            -replace '__APP_NAME__', (ConvertTo-JsonSafe $AppDisplayName) `
            -replace '__APP_NAME_SAFE__', $appNameSafe `
            -replace '__APP_ID__', (ConvertTo-JsonSafe $AppId) `
            -replace '__SPN_ID_SHORT__', (ConvertTo-JsonSafe $spnShort) `
            -replace '__TENANT_ID_SHORT__', (ConvertTo-JsonSafe $tenantShort) `
            -replace '__SIGN_IN_AUDIENCE__', (ConvertTo-JsonSafe $(if ($SignInAudience) { $SignInAudience } else { 'N/A' })) `
            -replace '__ASSESS_DATE__', (ConvertTo-JsonSafe $AssessmentDate) `
            -replace '__OVERALL_MATURITY__', $OverallMaturity `
            -replace '__MATURITY_LABEL__', (ConvertTo-JsonSafe $overallLabel) `
            -replace '__MATURITY_COLOR__', $maturityColor `
            -replace '__RING_DASH__', $ringDash `
            -replace '__RING_GAP__', $ringGap `
            -replace '__TOTAL_CRITICAL__', $totalCritical `
            -replace '__TOTAL_HIGH__', $totalHigh `
            -replace '__TOTAL_MEDIUM__', $totalMedium `
            -replace '__TOTAL_LOW__', $totalLow `
            -replace '__TOTAL_FINDINGS__', $totalFindings `
            -replace '__DOMAINS_JSON__', $DomainsJson `
            -replace '__FINDINGS_JSON__', $FindingsJson

        $html | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
    }

    #endregion

    #region ── JSON Export ───────────────────────────────────────────────────────

    Function Export-AssessmentJson {
        param (
            [string]$AppDisplayName,
            [string]$AppId,
            [string]$SpnObjectId,
            [string]$TenantId,
            [double]$OverallMaturity,
            [string]$AssessmentDate,
            [string]$OutputFilePath
        )

        $overallLabel = $script:MaturityLabels[[int][Math]::Round($OverallMaturity)]
        $totalCritical = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
        $totalHigh = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
        $totalMedium = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count
        $totalLow = ($script:Findings | Where-Object { $_.Risk -eq "Low" }).Count

        $export = [PSCustomObject]@{
            SchemaVersion   = "1.0"
            AssessmentType  = "EntraAccessControlArchitectureAssessment"
            ApplicationName = $AppDisplayName
            AppId           = $AppId
            SpnObjectId     = $SpnObjectId
            TenantId        = $TenantId
            AssessmentDate  = $AssessmentDate
            OverallMaturity = $OverallMaturity
            MaturityLabel   = $overallLabel
            Summary         = [PSCustomObject]@{
                CriticalFindings = $totalCritical
                HighFindings     = $totalHigh
                MediumFindings   = $totalMedium
                LowFindings      = $totalLow
                TotalFindings    = $script:Findings.Count
            }
            Domains         = $script:Domains
            Findings        = $script:Findings
        }

        $export | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
    }

    #endregion

    #region ── Main Entry Point ──────────────────────────────────────────────────

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   Zero Trust Access Control Architecture Assessment  v1.0    ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║   Architectural model: Evidence → Gap → Target → Roadmap     ║" -ForegroundColor DarkCyan
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
        "Policy.Read.All"
        "Directory.Read.All"
        "AuditLog.Read.All"
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

    # ── Step 2: Resolve Application Identity ─────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 2  ›  Resolving Application Identity                 │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $resolvedApp = $null  # App Registration object
    $resolvedSpn = $null  # Service Principal object
    $resolvedAppId = $null

    if ($AppId) {
        Write-Host "  ⏳ Resolving App Registration for AppId: $AppId..." -ForegroundColor Yellow
        $appByAppId = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/applications?`$filter=appId eq '$AppId'&`$select=id,appId,displayName,passwordCredentials,keyCredentials,requiredResourceAccess,signInAudience,createdDateTime"

        if ($appByAppId -and $appByAppId.Count -gt 0) {
            $resolvedApp = $appByAppId[0]
            $resolvedAppId = $AppId
            Write-Host "  ✅ App Registration found: $($resolvedApp.displayName)" -ForegroundColor Green
        }
        else {
            Write-Host "  ⚠️  App Registration not found by AppId — may be a first-party or external tenant app." -ForegroundColor Yellow
        }

        Write-Host "  ⏳ Resolving Service Principal for AppId: $AppId..." -ForegroundColor Yellow
        $spnByAppId = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appId eq '$AppId'&`$select=id,appId,displayName,servicePrincipalType,appRoleAssignmentRequired,passwordCredentials,keyCredentials,publisherName"

        if ($spnByAppId -and $spnByAppId.Count -gt 0) {
            $resolvedSpn = $spnByAppId[0]
            Write-Host "  ✅ Service Principal found: $($resolvedSpn.displayName) (ObjectId: $($resolvedSpn.id))" -ForegroundColor Green
        }
        else {
            Write-Error "  ✖ No Service Principal found for AppId '$AppId'. Verify the app is registered in this tenant."
            return
        }
    }
    elseif ($ServicePrincipalId) {
        Write-Host "  ⏳ Resolving Service Principal for ObjectId: $ServicePrincipalId..." -ForegroundColor Yellow
        $resolvedSpn = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/servicePrincipals/$ServicePrincipalId`?`$select=id,appId,displayName,servicePrincipalType,appRoleAssignmentRequired,passwordCredentials,keyCredentials,publisherName"

        if (-not $resolvedSpn) {
            Write-Error "  ✖ Service Principal not found for ObjectId '$ServicePrincipalId'. Verify the Object ID."
            return
        }

        $resolvedAppId = $resolvedSpn.appId
        Write-Host "  ✅ Service Principal found: $($resolvedSpn.displayName) (AppId: $resolvedAppId)" -ForegroundColor Green

        Write-Host "  ⏳ Resolving App Registration for AppId: $resolvedAppId..." -ForegroundColor Yellow
        $appByAppId2 = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/applications?`$filter=appId eq '$resolvedAppId'&`$select=id,appId,displayName,passwordCredentials,keyCredentials,requiredResourceAccess,signInAudience,createdDateTime"

        if ($appByAppId2 -and $appByAppId2.Count -gt 0) {
            $resolvedApp = $appByAppId2[0]
            Write-Host "  ✅ App Registration found: $($resolvedApp.displayName)" -ForegroundColor Green
        }
        else {
            Write-Host "  ⚠️  App Registration not resolvable — first-party Microsoft app or external tenant. Some checks will use partial data." -ForegroundColor Yellow
        }
    }

    $displayName = if ($resolvedApp) { $resolvedApp.displayName } elseif ($resolvedSpn) { $resolvedSpn.displayName } else { "Unknown Application" }
    $signInAudience = if ($resolvedApp) { $resolvedApp.signInAudience } else { $null }

    $appContext = [PSCustomObject]@{
        AppDisplayName            = $displayName
        AppId                     = $resolvedAppId
        AppRegistrationObjectId   = if ($resolvedApp) { $resolvedApp.id } else { $null }
        SpnObjectId               = if ($resolvedSpn) { $resolvedSpn.id } else { $null }
        SignInAudience            = $signInAudience
        AppRoleAssignmentRequired = if ($resolvedSpn) { $resolvedSpn.appRoleAssignmentRequired } else { $null }
        AppRegistration           = $resolvedApp
        ServicePrincipal          = $resolvedSpn
    }

    Write-Host ""
    Write-Host "  📋 Target Application: $displayName" -ForegroundColor Cyan
    Write-Host "  🆔 AppId             : $resolvedAppId" -ForegroundColor Gray
    Write-Host "  🔗 SPN ObjectId      : $($appContext.SpnObjectId)" -ForegroundColor Gray
    Write-Host "  🌐 Sign-In Audience  : $(if ($signInAudience) { $signInAudience } else { 'N/A' })" -ForegroundColor Gray
    Write-Host ""

    # ── Step 3: Retrieve Shared Data (CA Policies) ────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 3  ›  Retrieving Shared Assessment Data              │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  ⏳ Retrieving all Conditional Access policies..." -ForegroundColor Yellow

    $allCAPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies?`$select=id,displayName,state,conditions,grantControls,sessionControls"
    Write-Host "  ✅ CA policies retrieved: $($allCAPolicies.Count)" -ForegroundColor Green
    Write-Host ""

    # ── Step 4: Domain Assessments ────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 4  ›  Running Zero Trust Domain Assessments          │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    Invoke-Domain1-IdentityAssurance  -AppContext $appContext -AllCAPolicies $allCAPolicies
    Invoke-Domain2-DeviceAssurance    -AppContext $appContext -AllCAPolicies $allCAPolicies
    Invoke-Domain3-AuthStrength       -AppContext $appContext -AllCAPolicies $allCAPolicies
    Invoke-Domain4-LeastPrivilege     -AppContext $appContext
    Invoke-Domain5-PrivilegedAccess   -AppContext $appContext
    Invoke-Domain6-WorkloadIdentity   -AppContext $appContext
    Invoke-Domain7-ContinuousEvaluation -AppContext $appContext -AllCAPolicies $allCAPolicies

    Write-Host ""
    Write-Host "  ✅ All 7 Zero Trust domain assessments complete." -ForegroundColor Green
    Write-Host ""

    # ── Step 5: Score ─────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 5  ›  Computing Zero Trust Maturity Score            │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $overallMaturity = Get-OverallMaturityScore
    $overallLabel = $script:MaturityLabels[[int][Math]::Round($overallMaturity)]
    $totalCritical = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
    $totalHigh = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
    $totalMedium = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count

    Write-Host "  📊 Overall ZT Maturity: $overallMaturity / 5.0 ($overallLabel)" -ForegroundColor Cyan
    Write-Host "  🔴 Critical: $totalCritical  |  🟠 High: $totalHigh  |  🔵 Medium: $totalMedium" -ForegroundColor Gray
    Write-Host ""

    # ── Step 6: Export ────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 6  ›  Generating Reports                             │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $appNameSafe = $displayName -replace '[^a-zA-Z0-9_-]', '_'
    $htmlPath = Join-Path $OutputPath "EntraAccessControlAssessment_${appNameSafe}_$timestamp.html"
    $jsonPath = Join-Path $OutputPath "EntraAccessControlAssessment_${appNameSafe}_$timestamp.json"
    $assessDate = (Get-Date).ToString("dd MMM yyyy HH:mm")

    Write-Host "  ⏳ Building HTML dashboard..." -ForegroundColor Yellow
    $domainsJson = Build-DomainsJson
    $findingsJson = Build-FindingsJson

    Generate-HtmlDashboard `
        -AppDisplayName  $displayName `
        -AppId           $resolvedAppId `
        -SpnObjectId     $appContext.SpnObjectId `
        -SignInAudience  $signInAudience `
        -TenantId        $TenantId `
        -OverallMaturity $overallMaturity `
        -AssessmentDate  $assessDate `
        -DomainsJson     $domainsJson `
        -FindingsJson    $findingsJson `
        -OutputFilePath  $htmlPath

    Write-Host "  ✅ HTML dashboard written → $htmlPath" -ForegroundColor Green

    Write-Host "  ⏳ Exporting JSON assessment..." -ForegroundColor Yellow
    Export-AssessmentJson `
        -AppDisplayName  $displayName `
        -AppId           $resolvedAppId `
        -SpnObjectId     $appContext.SpnObjectId `
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
    Write-Host "  ║              ZERO TRUST ASSESSMENT SUMMARY                   ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  🛡️  Application           : $($displayName.PadRight(30))║" -ForegroundColor White
    Write-Host "  ║  📊 ZT Maturity Score      : $("$overallMaturity / 5.0 ($overallLabel)".PadRight(30))║" -ForegroundColor Cyan
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
