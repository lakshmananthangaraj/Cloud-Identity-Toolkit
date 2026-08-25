<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 25 August 2026
Modified-On  : 25 August 2026

.SYNOPSIS
    Assesses workload identities (Service Principals, Managed Identities, App Registrations,
    and automation identities) against an enterprise target architecture and produces a
    risk-prioritised, migration-pathed assessment report.

.DESCRIPTION
    This script connects to Microsoft Graph (BYOT or Client Credentials) and evaluates
    workload identities in the Entra ID tenant across six architectural domains aligned
    to the Microsoft Identity Reference Architecture and Zero Trust principles for
    non-human identities:

        Domain 1  — Identity Inventory & Classification
                    Catalogues all Service Principals, Managed Identities, and App
                    Registrations. Detects identity sprawl, orphans, and unowned identities.

        Domain 2  — Credential & Authentication Posture
                    Assesses secret dependency, certificate usage, federated credentials,
                    and migration readiness. Maps the target migration path:
                    Secrets → Certificates → Federated Credentials → Managed Identity.

        Domain 3  — Privilege & Permission Architecture
                    Evaluates API permissions (application vs delegated), OAuth2 grants,
                    Azure RBAC assignments, and excessive privilege patterns.

        Domain 4  — Lifecycle & Governance
                    Assesses stale identities, expiring credentials, ownership gaps,
                    and identity lifecycle automation maturity.

        Domain 5  — Workload Identity Security Controls
                    Reviews Workload Identity Premium policies, Conditional Access for
                    workload identities, and federated identity trust boundaries.

        Domain 6  — Application Architecture Alignment
                    Evaluates multi-tenant applications, publisher verification, consent
                    framework usage, and alignment to enterprise app registration standards.

    For each domain the script follows this architectural thinking model:

        Context → Current State → Gap/Risk → Target State → Transition → Success Measures

    The collected identity data is structured for future dependency-graph analysis,
    mapping the relationship chain:
        Workload → Application → Service Principal → Credential/Federation → API/Resource → Permission

    Maturity levels are assigned using a five-stage model:
        1 - Initial      : Ad-hoc, undocumented, reactive
        2 - Developing   : Partial controls, inconsistently applied
        3 - Defined      : Controls exist and are documented but not fully enforced
        4 - Managed      : Consistently enforced, measured, and reviewed
        5 - Optimised    : Continuously improved, automated, Zero Trust-aligned

    Findings are prioritised by:
        - Business impact (credential theft, lateral movement, supply chain risk)
        - Security risk severity (Critical / High / Medium / Low)
        - Blast radius (tenant-wide vs scoped)
        - Privilege exposure (admin plane vs data plane)
        - Migration urgency (secret expiry, orphaned credential risk)

    Migration path recommendations follow the Zero Trust identity ladder:
        Shared Secrets → Certificates → Workload Identity Federation → Managed Identity

    Output:
        - CSV findings export (pipeline-compatible, CI/CD integrable)
        - HTML interactive dashboard (light/dark theme, tabbed by domain)

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
    Directory where the CSV and HTML reports will be written.
    Default: C:\Temp\WorkloadIdentityAssessment

.PARAMETER ShowHelp
    Displays a plain-language usage guide and exits immediately.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        HTML dashboard : <OutputPath>\EntraWorkloadIdentityAssessment_<timestamp>.html
        CSV export     : <OutputPath>\EntraWorkloadIdentityAssessment_<timestamp>.csv

.EXAMPLE
    Get-EntraWorkloadIdentityArchitectureAssessment -ShowHelp

    Displays the friendly usage guide and exits.

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraWorkloadIdentityArchitectureAssessment `
        -AuthMode     ClientCredentials `
        -ClientId     "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId     "f4310b4f-xxxx"

    Full assessment using app-only Client Credentials authentication.

.EXAMPLE
    $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    Get-EntraWorkloadIdentityArchitectureAssessment `
        -AuthMode    BYOT `
        -AccessToken $token `
        -TenantId    "f4310b4f-xxxx"

    Full assessment using a pre-obtained bearer token (BYOT).

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraWorkloadIdentityArchitectureAssessment `
        -AuthMode     ClientCredentials `
        -ClientId     "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId     "f4310b4f-xxxx" `
        -OutputPath   "D:\Reports\WorkloadIdentity"

    Assessment with a custom output directory.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (25-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. App Registration (Client Credentials mode) with admin-consented
           Application permissions:
               Application.Read.All            (app registrations, service principals,
                                                credentials, federated identities)
               Directory.Read.All              (tenant info, roles, group memberships)
               Policy.Read.All                 (Conditional Access for workload identities)
               AuditLog.Read.All               (sign-in activity for SPs and MIs)
               RoleManagement.Read.Directory   (Azure AD role assignments)

        2. BYOT mode: the delegated or application token must carry the same
           scopes as above. Delegated tokens require the caller to be a
           Global Reader or Security Reader.

        3. PowerShell 5.1 or later.

        4. Workload Identity Premium (Entra ID P2 add-on) required for:
               - Workload Identity Conditional Access policies
               - Workload Identity risk detection
               The script gracefully degrades for tenants without this licence.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  → Show help and exit if -ShowHelp
        Step 1  → Authenticate (BYOT or Client Credentials)
        Step 1.1→ Validate required Graph permissions
        Step 2  → Collect tenant baseline (org, licences, domains)
        Step 3  → Collect identity inventory (SPs, MIs, App Registrations)
        Step 4  → Run domain assessments 1–6
        Step 5  → Compute overall maturity score
        Step 6  → Export CSV findings
        Step 7  → Generate HTML dashboard

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the /beta Graph endpoint. Beta APIs are subject to change.
        - Azure RBAC assignments are not evaluated (out of scope — requires Az module).
        - Last sign-in activity for Service Principals requires AuditLog.Read.All
          and may be unavailable in tenants with log retention policies < 30 days.
        - Large tenants with thousands of Service Principals may experience longer
          run times due to Graph pagination and per-SP credential enumeration.
        - Workload Identity Conditional Access policies require Workload Identity
          Premium. The domain assessment gracefully degrades without this licence.
        - Managed Identity sign-in data is only available via the beta endpoint
          and may be incomplete for system-assigned MIs on deleted resources.

.LINK
    https://learn.microsoft.com/en-us/entra/workload-id/
.LINK
    https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview
.LINK
    https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
.LINK
    https://learn.microsoft.com/en-us/graph/api/overview

#>


Function Get-EntraWorkloadIdentityArchitectureAssessment {
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
        [string]$OutputPath = "C:\Temp\WorkloadIdentityAssessment",

        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    #region ── Friendly Help ──────────────────────────────────────────────────────

    Function Show-FriendlyHelp {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║   Entra Workload Identity Architecture Assessment  v1.0      ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  PURPOSE" -ForegroundColor Yellow
        Write-Host "    Assesses Service Principals, Managed Identities, App Registrations,"
        Write-Host "    and automation identities against an enterprise workload identity"
        Write-Host "    reference architecture. Identifies secret dependency, identity sprawl,"
        Write-Host "    excessive permissions, and governance gaps. Recommends migration paths:"
        Write-Host "    Secrets → Certificates → Federated Credentials → Managed Identity."
        Write-Host ""
        Write-Host "  AUTHENTICATION" -ForegroundColor Yellow
        Write-Host "    Client Credentials (app-only):"
        Write-Host '      $secret = Read-Host "Client secret" -AsSecureString'
        Write-Host '      Get-EntraWorkloadIdentityArchitectureAssessment \'
        Write-Host '          -AuthMode ClientCredentials \'
        Write-Host '          -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "    BYOT (Bring Your Own Token):"
        Write-Host '      $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken'
        Write-Host '      Get-EntraWorkloadIdentityArchitectureAssessment \'
        Write-Host '          -AuthMode BYOT -AccessToken $token -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "  REQUIRED APP PERMISSIONS (Application, admin-consented)" -ForegroundColor Yellow
        Write-Host "    Application.Read.All, Directory.Read.All, Policy.Read.All,"
        Write-Host "    AuditLog.Read.All, RoleManagement.Read.Directory"
        Write-Host ""
        Write-Host "  MIGRATION PATH" -ForegroundColor Yellow
        Write-Host "    Shared Secrets → Certificates → Workload Identity Federation → Managed Identity"
        Write-Host ""
        Write-Host "  For full documentation: Get-Help Get-EntraWorkloadIdentityArchitectureAssessment -Full"
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

        Try {
            $tokenParts = $AccessToken.Split(".")
            if ($tokenParts.Count -ne 3) {
                return @{ Valid = $false; MissingPermissions = $RequiredPermissions }
            }

            $payload = $tokenParts[1].Replace("-", "+").Replace("_", "/")
            switch ($payload.Length % 4) {
                2 { $payload += "==" }
                3 { $payload += "=" }
            }

            $claims = [System.Text.Encoding]::UTF8.GetString(
                [Convert]::FromBase64String($payload)) | ConvertFrom-Json

            $tokenPermissions = @()
            if ($claims.scp) { $tokenPermissions += $claims.scp -split " " }
            if ($claims.roles) { $tokenPermissions += @($claims.roles) }

            $missingPermissions = @($RequiredPermissions | Where-Object { $_ -notin $tokenPermissions })
            return @{ Valid = ($missingPermissions.Count -eq 0); MissingPermissions = $missingPermissions }
        }
        Catch {
            return @{ Valid = $false; MissingPermissions = $RequiredPermissions }
        }
    }

    #endregion

    #region ── Graph API Helpers ─────────────────────────────────────────────────

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
                return Invoke-RestMethod @invokeParams
            }
            Catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                if ($statusCode -eq 429) {
                    $retryAfter = 30
                    Try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } Catch {}
                    Write-Host "  ⏳ Throttled (429). Waiting $retryAfter s..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $retryAfter
                    $retries++
                }
                elseif ($statusCode -eq 403) {
                    Write-Verbose "  ⚠ 403 Forbidden on $Uri — permission not granted or licence required."
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

    #region ── Maturity Model & Assessment Stores ─────────────────────────────────

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

    # Global assessment stores
    $script:Domains = [System.Collections.ArrayList]::new()
    $script:Findings = [System.Collections.ArrayList]::new()

    # Graph-friendly identity relationship store (future dependency-graph ready)
    # Schema: Workload → Application → ServicePrincipal → Credential/Federation → API/Resource → Permission
    $script:IdentityGraph = [System.Collections.ArrayList]::new()


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
            [string]$MigrationPath,
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
                MigrationPath        = $MigrationPath
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

        $null = $script:Domains.Add([PSCustomObject]@{
                Id                  = $Id
                Name                = $Name
                Icon                = $Icon
                MaturityScore       = $MaturityScore
                MaturityLabel       = $script:MaturityLabels[$MaturityScore]
                MaturityColor       = $script:MaturityColors[$MaturityScore]
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


    Function Add-IdentityGraphNode {
        param (
            [string]$WorkloadType,       # "Application" | "ManagedIdentity" | "ServicePrincipal"
            [string]$AppId,
            [string]$ObjectId,
            [string]$DisplayName,
            [string]$CredentialType,     # "Secret" | "Certificate" | "FederatedCredential" | "None"
            [string[]]$ApiPermissions,
            [string[]]$Resources,
            [string]$PublisherName,
            [bool]$IsManaged,
            [string]$OwnerUpn,
            [string]$LastSignInDateTime
        )

        $null = $script:IdentityGraph.Add([PSCustomObject]@{
                WorkloadType       = $WorkloadType
                AppId              = $AppId
                ObjectId           = $ObjectId
                DisplayName        = $DisplayName
                CredentialType     = $CredentialType
                ApiPermissions     = $ApiPermissions -join "|"
                Resources          = $Resources -join "|"
                PublisherName      = $PublisherName
                IsManaged          = $IsManaged
                OwnerUpn           = $OwnerUpn
                LastSignInDateTime = $LastSignInDateTime
            })
    }

    #endregion

    #region ── Domain 1: Identity Inventory & Classification ─────────────────────

    Function Invoke-Domain1-IdentityInventory {
        param ([ref]$SpRef, [ref]$MiRef, [ref]$AppRef)

        Write-Host "  🗂️  D1: Identity Inventory & Classification..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Collect all Service Principals ───────────────────────────────────────
        Write-Host "     ↳ Collecting Service Principals..." -ForegroundColor DarkGray
        $allSPs = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,accountEnabled,createdDateTime,tags,appOwnerOrganizationId,publisherName,verifiedPublisher,passwordCredentials,keyCredentials,info,alternativeNames"
        $SpRef.Value = $allSPs

        # ── Collect App Registrations ─────────────────────────────────────────────
        Write-Host "     ↳ Collecting App Registrations..." -ForegroundColor DarkGray
        $allApps = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/applications?`$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess,owners,publisherDomain,verifiedPublisher,identifierUris,web,spa,publicClient"
        $AppRef.Value = $allApps

        # ── Classify identity types ──────────────────────────────────────────────
        $managedIdentities = @($allSPs | Where-Object { $_.servicePrincipalType -eq "ManagedIdentity" })
        $appSPs = @($allSPs | Where-Object { $_.servicePrincipalType -eq "Application" })
        $legacySPs = @($allSPs | Where-Object { $_.servicePrincipalType -eq "Legacy" })
        $firstPartySPs = @($appSPs | Where-Object { $_.tags -contains "WindowsAzureActiveDirectoryIntegratedApp" -or $_.appOwnerOrganizationId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a" })
        $thirdPartySPs = @($appSPs | Where-Object { $_.appOwnerOrganizationId -and $_.appOwnerOrganizationId -ne $TenantId -and $_.appOwnerOrganizationId -ne "f8cdef31-a31e-4b4a-93e4-5f571e91255a" })
        $ownTenantSPs = @($appSPs | Where-Object { -not $_.appOwnerOrganizationId -or $_.appOwnerOrganizationId -eq $TenantId })
        $MiRef.Value = $managedIdentities

        $totalWorkloadIds = $allSPs.Count

        Write-Host "     ↳ Service Principals: $($allSPs.Count) total | Managed Identities: $($managedIdentities.Count) | App SPs: $($appSPs.Count)" -ForegroundColor DarkGray

        # ── Check 1.1: Identity volume and sprawl ────────────────────────────────
        if ($totalWorkloadIds -gt 500) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D1" -DomainName "Identity Inventory" -CheckId "D1.1" `
                -Title "High Identity Volume Detected — Potential Sprawl ($totalWorkloadIds Service Principals)" `
                -Evidence "Total Service Principals: $totalWorkloadIds | App SPs: $($appSPs.Count) | Managed Identities: $($managedIdentities.Count) | Legacy: $($legacySPs.Count)" `
                -CurrentState "The tenant has $totalWorkloadIds Service Principal objects. High volumes frequently indicate unchecked provisioning, test identities never decommissioned, and third-party SaaS integrations accumulating over time." `
                -Gap "Identity sprawl increases the attack surface, complicates permission auditing, and is a leading indicator of governance gaps. The tenant cannot demonstrate a least-privilege posture without a current inventory." `
                -Risk "High" `
                -BusinessImpact "Each unclaimed or undocumented identity is a potential attack vector. Credential theft on any SP may enable lateral movement across APIs, Azure resources, and connected workloads." `
                -TargetState "All identities catalogued with an owner, workload mapping, and documented purpose. Auto-decommission for identities unused >90 days. Target: Managed Identities for all Azure-hosted workloads (zero secret dependency)." `
                -Recommendation "Export this inventory to a CMDB or workload identity register. Tag each SP with workload owner. Initiate decommission review for SPs with no sign-in activity in 90 days. Introduce provisioning governance: no new SP without a workload ticket." `
                -MigrationPath "Inventory → Classify → Owner Assignment → Lifecycle Policy → Decommission Stale" `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($totalWorkloadIds -gt 200) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Identity Inventory" -CheckId "D1.1" `
                -Title "Moderate Identity Volume — Inventory Governance Recommended ($totalWorkloadIds SPs)" `
                -Evidence "Total Service Principals: $totalWorkloadIds | App SPs: $($appSPs.Count) | Managed Identities: $($managedIdentities.Count)" `
                -CurrentState "$totalWorkloadIds Service Principals registered. Volume is within a manageable range but warrants a structured inventory." `
                -Gap "Without a workload-to-identity register, ownership and lifecycle accountability cannot be confirmed at scale." `
                -Risk "Medium" `
                -BusinessImpact "Untracked identities accumulate permissions over time. Moderate risk of orphaned credential exposure." `
                -TargetState "All SPs documented, tagged with owner and workload. Automated stale-identity detection in place." `
                -Recommendation "Establish a workload identity register. Tag SPs with environment, owner, and workload metadata. Schedule quarterly cleanup reviews." `
                -MigrationPath "Inventory → Tag → Register → Govern" `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $low++
            $maturityPoints += 4
            Add-Finding -DomainId "D1" -DomainName "Identity Inventory" -CheckId "D1.1" `
                -Title "Identity Volume Within Manageable Range ($totalWorkloadIds SPs)" `
                -Evidence "Total Service Principals: $totalWorkloadIds | App SPs: $($appSPs.Count) | Managed Identities: $($managedIdentities.Count)" `
                -CurrentState "$totalWorkloadIds Service Principals — volume is low enough for manual inventory governance." `
                -Gap "Maintain documented ownership. As volume grows, automate inventory tagging and stale-identity detection." `
                -Risk "Low" `
                -BusinessImpact "Low — manageable inventory. Establish ownership records before volume grows." `
                -TargetState "100% SP ownership recorded. Automated lifecycle policy when count exceeds 100." `
                -Recommendation "Document workload-to-SP mapping now. Establish an onboarding standard for new SP provisioning." `
                -MigrationPath "Document → Govern" `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 1.2: Managed Identity adoption ratio ───────────────────────────
        $miRatio = if ($appSPs.Count -gt 0) { [Math]::Round(($managedIdentities.Count / ($managedIdentities.Count + $appSPs.Count)) * 100, 0) } else { 0 }

        if ($miRatio -lt 20) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D1" -DomainName "Identity Inventory" -CheckId "D1.2" `
                -Title "Low Managed Identity Adoption — Secret-Dependent Architecture ($miRatio% MI ratio)" `
                -Evidence "Managed Identities: $($managedIdentities.Count) | Application SPs: $($appSPs.Count) | MI adoption ratio: $miRatio%" `
                -CurrentState "Only $miRatio% of workload identities are Managed Identities. The majority of workloads are using Application Service Principals, which require manually managed credentials (secrets or certificates)." `
                -Gap "Low MI adoption indicates the workload identity architecture has not evolved beyond traditional credential-based patterns. Every application SP with a secret is a potential credential-theft target. Managed Identities eliminate this risk entirely for Azure-hosted workloads." `
                -Risk "High" `
                -BusinessImpact "Credential theft (secret exfiltration) is the primary attack vector against workload identities. A low MI ratio means the majority of workloads depend on credentials that can be stolen, hardcoded in code, or exposed in CI/CD pipelines." `
                -TargetState "Managed Identities for all Azure-hosted workloads. Federated Workload Identity for non-Azure workloads (GitHub Actions, Kubernetes, external CI/CD). MI ratio target: >60% within 12 months." `
                -Recommendation "Identify all Azure-hosted workloads (App Service, Functions, AKS, VMs, Logic Apps, Container Apps) that use Application SP credentials. Migrate each to System-assigned or User-assigned Managed Identity. For non-Azure workloads, implement Workload Identity Federation (GitHub Actions OIDC, AKS Workload Identity)." `
                -MigrationPath "Secret/Cert → Managed Identity (Azure) | Secret/Cert → Federated Credential (non-Azure)" `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($miRatio -lt 50) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Identity Inventory" -CheckId "D1.2" `
                -Title "Partial Managed Identity Adoption — Migration Opportunity ($miRatio%)" `
                -Evidence "Managed Identities: $($managedIdentities.Count) | Application SPs: $($appSPs.Count) | MI adoption ratio: $miRatio%" `
                -CurrentState "$miRatio% of workload identities use Managed Identity. Migration is underway but a significant portion of workloads still rely on application credentials." `
                -Gap "Remaining Application SPs with secrets/certificates carry credential management overhead and exposure risk. Completing the MI migration would eliminate this residual risk." `
                -Risk "Medium" `
                -BusinessImpact "Residual credential-theft risk on remaining Application SPs. Partial adoption indicates inconsistent engineering standards across workload teams." `
                -TargetState "Managed Identity for all Azure-hosted workloads. >60% MI ratio within 6 months. Federated credentials for all non-Azure CI/CD workloads." `
                -Recommendation "Accelerate MI migration for remaining Azure-hosted workloads. Implement engineering standards: new Azure workload deployments must use MI by default. Establish a migration tracker for remaining application SPs." `
                -MigrationPath "Remaining Secrets/Certs → Managed Identity or Federated Credential" `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 5
            Add-Finding -DomainId "D1" -DomainName "Identity Inventory" -CheckId "D1.2" `
                -Title "Strong Managed Identity Adoption — Modern Workload Identity Posture ($miRatio%)" `
                -Evidence "Managed Identities: $($managedIdentities.Count) | Application SPs: $($appSPs.Count) | MI adoption ratio: $miRatio%" `
                -CurrentState "$miRatio% of workload identities use Managed Identity. The tenant has broadly adopted the Zero Trust workload identity pattern." `
                -Gap "Maintain discipline: ensure all new Azure workloads default to MI. Confirm remaining Application SPs have documented justification and are on the migration backlog." `
                -Risk "Info" `
                -BusinessImpact "Low — strong MI adoption significantly reduces credential-theft exposure." `
                -TargetState "100% MI adoption for Azure-hosted workloads. Federated Workload Identity for all external workloads. Zero shared secret dependencies for Azure resources." `
                -Recommendation "Formalize MI-first as an engineering standard in your Cloud Adoption Framework or landing zone policy. Audit remaining Application SPs for migration blockers." `
                -MigrationPath "Maintain MI-first standard. Document exceptions." `
                -RoadmapPhase "Strategic" -MaturityContribution 5
        }

        # ── Check 1.3: Disabled vs enabled SP ratio ──────────────────────────────
        $disabledSPs = @($allSPs | Where-Object { $_.accountEnabled -eq $false })

        if ($disabledSPs.Count -gt 20) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Identity Inventory" -CheckId "D1.3" `
                -Title "Disabled Service Principals Accumulating — Decommission Backlog ($($disabledSPs.Count) disabled)" `
                -Evidence "Disabled SPs: $($disabledSPs.Count) | Total SPs: $totalWorkloadIds" `
                -CurrentState "$($disabledSPs.Count) Service Principals are disabled but not deleted. Disabled accounts still consume identity graph nodes and may have live credentials or role assignments." `
                -Gap "Disabled SPs are not decommissioned. They can be re-enabled by a privileged actor, and their role assignments and app permissions remain active. This is a hidden attack surface." `
                -Risk "Medium" `
                -BusinessImpact "Disabled SPs with active credentials or role assignments can be re-enabled and used by an attacker who gains privileged access. Dormant identities are difficult to detect in SIEM alerting." `
                -TargetState "No disabled SPs with active credentials or role assignments. Disabled SPs in a decommission queue with a 30-day grace period, then hard-deleted." `
                -Recommendation "Review all disabled SPs. Revoke credentials on disabled SPs. Remove role assignments. Delete SPs with no remaining business justification. Establish a decommission workflow: disable → credential revocation → 30-day hold → delete." `
                -MigrationPath "Disabled SPs → Credential Revocation → Role Assignment Removal → Delete" `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }

        # ── Check 1.4: Third-party SP count ──────────────────────────────────────
        if ($thirdPartySPs.Count -gt 50) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D1" -DomainName "Identity Inventory" -CheckId "D1.4" `
                -Title "High Third-Party Service Principal Count — SaaS Sprawl Risk ($($thirdPartySPs.Count) external SPs)" `
                -Evidence "Third-party SPs (external publisher): $($thirdPartySPs.Count) | First-party Microsoft SPs: $($firstPartySPs.Count) | Own-tenant SPs: $($ownTenantSPs.Count)" `
                -CurrentState "$($thirdPartySPs.Count) Service Principals registered from external/third-party publishers. Each represents a consented SaaS integration with varying permission scopes." `
                -Gap "Third-party SaaS integrations are a supply chain risk. Each consented SP has access to tenant data within its granted permissions. Without a review cadence, overly-permissive or orphaned SaaS connections accumulate." `
                -Risk "Medium" `
                -BusinessImpact "SaaS supply chain attacks (compromised third-party OAuth apps) are an active threat vector. Overly-permissive SaaS integrations may enable data exfiltration even when the primary SaaS vendor is not the target." `
                -TargetState "All third-party SaaS SPs reviewed and approved. Permissions aligned to least privilege. Annual recertification of all SaaS integrations. Publisher verification confirmed for all business-critical SaaS." `
                -Recommendation "Review all third-party SPs. Revoke consent for SPs no longer in use. Require publisher verification and minimal permissions for any new SaaS integration. Establish an App Governance policy." `
                -MigrationPath "Inventory SaaS SPs → Review Permissions → Revoke Unused → Recertify Annually" `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D1" -Name "Identity Inventory" -Icon "🗂️" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Total SPs: $totalWorkloadIds. Managed Identities: $($managedIdentities.Count) ($miRatio% ratio). Third-party SPs: $($thirdPartySPs.Count). Disabled SPs: $($disabledSPs.Count)." `
            -TargetStateSummary "100% SP ownership documented. Managed Identity for all Azure workloads. No orphaned or disabled SPs with active credentials. Quarterly SaaS recertification." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 2: Credential & Authentication Posture ─────────────────────

    Function Invoke-Domain2-CredentialPosture {
        param ([object[]]$AllApps, [object[]]$AllSPs)

        Write-Host "  🔑 D2: Credential & Authentication Posture..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $now = Get-Date
        $allSecrets = @()
        $allCerts = @()
        $expiredSecrets = @()
        $expiringSoonSecrets = @()
        $expiredCerts = @()
        $expiringSoonCerts = @()
        $appsWithSecrets = @()
        $appsWithCerts = @()
        $appsWithFederated = @()
        $appsWithNoCredential = @()

        # ── Enumerate App Registration credentials ────────────────────────────────
        Write-Host "     ↳ Enumerating App Registration credentials..." -ForegroundColor DarkGray
        foreach ($app in $AllApps) {
            $hasSecret = $app.passwordCredentials -and $app.passwordCredentials.Count -gt 0
            $hasCert = $app.keyCredentials -and $app.keyCredentials.Count -gt 0

            # Federated credentials (checked separately per app)
            $fedCreds = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/applications/$($app.id)/federatedIdentityCredentials"
            $hasFed = $fedCreds -and $fedCreds.value -and $fedCreds.value.Count -gt 0

            if ($hasSecret) { $appsWithSecrets += $app }
            if ($hasCert) { $appsWithCerts += $app }
            if ($hasFed) { $appsWithFederated += $app }
            if (-not $hasSecret -and -not $hasCert -and -not $hasFed) { $appsWithNoCredential += $app }

            foreach ($secret in $app.passwordCredentials) {
                $allSecrets += $secret
                if ($secret.endDateTime) {
                    $expiry = [datetime]$secret.endDateTime
                    if ($expiry -lt $now) { $expiredSecrets += $secret }
                    elseif ($expiry -lt $now.AddDays(30)) { $expiringSoonSecrets += $secret }
                }
            }

            foreach ($cert in $app.keyCredentials) {
                $allCerts += $cert
                if ($cert.endDateTime) {
                    $expiry = [datetime]$cert.endDateTime
                    if ($expiry -lt $now) { $expiredCerts += $cert }
                    elseif ($expiry -lt $now.AddDays(30)) { $expiringSoonCerts += $cert }
                }
            }
        }

        # ── Also check SP-level credentials (some SaaS SPs have their own creds) ──
        $spsWithSecrets = @($AllSPs | Where-Object { $_.passwordCredentials -and $_.passwordCredentials.Count -gt 0 })
        $spsWithCerts = @($AllSPs | Where-Object { $_.keyCredentials -and $_.keyCredentials.Count -gt 0 })

        # ── Check 2.1: Secret usage prevalence ───────────────────────────────────
        $secretDependentApps = $appsWithSecrets.Count
        $totalApps = $AllApps.Count
        $secretPct = if ($totalApps -gt 0) { [Math]::Round(($secretDependentApps / $totalApps) * 100, 0) } else { 0 }

        if ($secretPct -gt 60) {
            $critical++
            $maturityPoints += 1
            Add-Finding -DomainId "D2" -DomainName "Credential Posture" -CheckId "D2.1" `
                -Title "Critical Secret Dependency — Majority of App Registrations Use Secrets ($secretPct%)" `
                -Evidence "Apps with secrets: $secretDependentApps / $totalApps ($secretPct%) | Apps with certificates: $($appsWithCerts.Count) | Apps with federated creds: $($appsWithFederated.Count) | No credential: $($appsWithNoCredential.Count)" `
                -CurrentState "$secretPct% of App Registrations use client secrets as their primary authentication mechanism. Client secrets are symmetrical shared credentials — they are high-value theft targets and cannot be detected if copied." `
                -Gap "Client secrets are the least secure workload identity credential type. They can be hardcoded in source code, leaked in CI/CD logs, stored in unencrypted config files, and are undetectable if copied. This represents a fundamental architecture gap in Zero Trust workload identity posture." `
                -Risk "Critical" `
                -BusinessImpact "A single secret leak enables persistent, silent access as the application identity. Attackers routinely scan public repositories (GitHub, Docker Hub) for leaked client secrets. Each secret-dependent identity is a potential supply chain compromise vector." `
                -TargetState "Zero client secrets for any Azure-hosted workload. Certificates for workloads that cannot use MI or federated credentials. Federated Workload Identity (OIDC) for CI/CD pipelines, GitHub Actions, Kubernetes, and non-Azure workloads." `
                -Recommendation "Immediately audit source code, CI/CD pipelines, and configuration management for hardcoded secrets. Migrate Azure-hosted workloads to Managed Identity. Implement Workload Identity Federation for GitHub Actions, Azure DevOps, and Kubernetes workloads. Enforce: no new App Registration may use secrets — certificates minimum, MI preferred." `
                -MigrationPath "Secrets → Certificates (short term) → Federated Credentials/Managed Identity (target)" `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($secretPct -gt 30) {
            $high++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Credential Posture" -CheckId "D2.1" `
                -Title "Elevated Secret Dependency — Migration Partially Underway ($secretPct%)" `
                -Evidence "Apps with secrets: $secretDependentApps / $totalApps ($secretPct%) | Certs: $($appsWithCerts.Count) | Federated: $($appsWithFederated.Count)" `
                -CurrentState "$secretPct% of apps use client secrets. Partial migration to modern credentials may be underway but significant residual secret dependency remains." `
                -Gap "Remaining secret-based apps carry an ongoing credential-theft risk. Migration to MI or federated credentials should be accelerated." `
                -Risk "High" `
                -BusinessImpact "Secret leaks in the residual population remain possible. Accelerating migration reduces the window of exposure." `
                -TargetState "All Azure-hosted workloads on Managed Identity. All CI/CD workloads on Federated Credentials. Secret usage <5% (documented legacy exceptions only)." `
                -Recommendation "Produce a migration tracker listing each secret-using app with a target credential type and migration owner. Prioritise apps with broadest API permissions first." `
                -MigrationPath "Remaining Secrets → Certificates or Federated Credentials or Managed Identity" `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $low++
            $maturityPoints += 4
            Add-Finding -DomainId "D2" -DomainName "Credential Posture" -CheckId "D2.1" `
                -Title "Low Secret Dependency — Modern Credential Architecture ($secretPct%)" `
                -Evidence "Apps with secrets: $secretDependentApps / $totalApps ($secretPct%) | Certs: $($appsWithCerts.Count) | Federated: $($appsWithFederated.Count)" `
                -CurrentState "Only $secretPct% of App Registrations use client secrets. The credential posture is broadly modern." `
                -Gap "Eliminate remaining $secretDependentApps secret-using apps. Formalise a no-new-secrets policy." `
                -Risk "Low" `
                -BusinessImpact "Low residual risk. Remaining secret-based apps should be tracked for migration." `
                -TargetState "Zero client secret dependency. Policy-enforced MI-first posture." `
                -Recommendation "Complete migration of remaining $secretDependentApps apps. Enforce no-new-secrets via Conditional Access App Policy or IaC guardrails." `
                -MigrationPath "Remaining Secrets → Managed Identity or Federated Credential" `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 2.2: Expired credentials ───────────────────────────────────────
        $totalExpired = $expiredSecrets.Count + $expiredCerts.Count

        if ($totalExpired -gt 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D2" -DomainName "Credential Posture" -CheckId "D2.2" `
                -Title "Expired Credentials Found — Broken Workloads and Cleanup Backlog ($totalExpired expired)" `
                -Evidence "Expired secrets: $($expiredSecrets.Count) | Expired certificates: $($expiredCerts.Count) | Expiring within 30 days (secrets): $($expiringSoonSecrets.Count) | Expiring within 30 days (certs): $($expiringSoonCerts.Count)" `
                -CurrentState "$totalExpired credentials have passed their expiry date. These are either abandoned (workload already broken) or represent unmanaged credential lifecycle — the application may be using a duplicate active credential while the expired one was never cleaned up." `
                -Gap "Expired credentials that remain registered are governance clutter at best and a security risk at worst. They indicate that credential lifecycle is not automated or monitored. They also mask the true active credential inventory." `
                -Risk "High" `
                -BusinessImpact "Expired credentials indicate absent credential lifecycle management. The same workloads are likely missing rotation policies, creating a future breach risk when active credentials eventually expire without automated renewal." `
                -TargetState "Zero expired credentials. Automated credential rotation with 90-day maximum lifetime for any secrets that remain. Expiry alerting at 60, 30, and 7 days. Expired credentials removed within 14 days of expiry." `
                -Recommendation "Remove all expired credentials from App Registrations immediately. Investigate which workloads they belonged to — determine if broken. For expiring-soon credentials: automate rotation or migrate to Managed Identity before expiry. Implement Azure Monitor alerts for credential expiry." `
                -MigrationPath "Expired Credentials → Remove → Replace with Managed Identity or Federated Credential" `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif (($expiringSoonSecrets.Count + $expiringSoonCerts.Count) -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D2" -DomainName "Credential Posture" -CheckId "D2.2" `
                -Title "Credentials Expiring Within 30 Days — Rotation or Migration Required ($($expiringSoonSecrets.Count + $expiringSoonCerts.Count) expiring soon)" `
                -Evidence "Secrets expiring <30 days: $($expiringSoonSecrets.Count) | Certs expiring <30 days: $($expiringSoonCerts.Count) | Already expired: 0" `
                -CurrentState "No expired credentials but $($expiringSoonSecrets.Count + $expiringSoonCerts.Count) credentials expire within 30 days." `
                -Gap "Imminent expiry without confirmed rotation plan will cause workload authentication failures. This is a recurring operational risk without automated credential lifecycle management." `
                -Risk "Medium" `
                -BusinessImpact "Workload authentication failures causing service outages if credentials expire without rotation. Each rotation event without automation is an opportunity for credential exposure." `
                -TargetState "Automated rotation for all remaining credentials. Managed Identity eliminates rotation entirely for Azure workloads." `
                -Recommendation "Immediate: verify rotation plans for all expiring-within-30-day credentials. Prioritise migrating these workloads to MI — the expiry event is the ideal migration trigger." `
                -MigrationPath "Expiring Credentials → Migrate to Managed Identity before expiry" `
                -RoadmapPhase "0-30 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D2" -DomainName "Credential Posture" -CheckId "D2.2" `
                -Title "No Expired or Imminent-Expiry Credentials Detected" `
                -Evidence "Expired: 0 | Expiring within 30 days: 0 | Total secrets: $($allSecrets.Count) | Total certificates: $($allCerts.Count)" `
                -CurrentState "No expired or imminent-expiry credentials found in App Registrations." `
                -Gap "Confirm that credential lifecycle is actively managed rather than incidentally healthy. Implement expiry alerting to maintain this posture as the inventory evolves." `
                -Risk "Info" `
                -BusinessImpact "Low — no immediate credential expiry risk." `
                -TargetState "Automated expiry alerting and rotation. MI adoption to eliminate rotation requirement entirely." `
                -Recommendation "Implement Azure Monitor credential expiry alerts (60/30/7 day thresholds) to maintain this posture proactively rather than reactively." `
                -MigrationPath "Maintain automated monitoring" `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 2.3: Workload Identity Federation adoption ─────────────────────
        $fedPct = if ($totalApps -gt 0) { [Math]::Round(($appsWithFederated.Count / $totalApps) * 100, 0) } else { 0 }

        if ($appsWithFederated.Count -eq 0 -and $secretDependentApps -gt 10) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D2" -DomainName "Credential Posture" -CheckId "D2.3" `
                -Title "No Workload Identity Federation Configured — CI/CD Pipelines Likely Using Secrets" `
                -Evidence "Apps with Federated Identity Credentials: 0 | Apps with secrets: $secretDependentApps" `
                -CurrentState "No Workload Identity Federation (WIF) configurations found. CI/CD pipelines (GitHub Actions, Azure DevOps, Jenkins, GitLab), Kubernetes workloads, and non-Azure workloads are likely authenticating with client secrets." `
                -Gap "WIF eliminates the need for client secrets in CI/CD pipelines entirely. Without it, pipeline secrets must be managed in secret stores, rotated manually, and are exposed in pipeline runner environments. This is a primary secret-exfiltration vector." `
                -Risk "High" `
                -BusinessImpact "CI/CD pipeline secrets are a high-value target. A compromised pipeline runner or a misconfigured secret mask can expose credentials granting access to Azure, Microsoft 365, or production APIs. Supply chain attacks via CI/CD are a top attack vector." `
                -TargetState "All CI/CD pipelines (GitHub Actions, Azure DevOps, GitLab CI, Jenkins) use Federated Identity Credentials. All Kubernetes workloads use AKS Workload Identity (OIDC). Zero pipeline secrets for Azure authentication." `
                -Recommendation "Immediately configure Workload Identity Federation for GitHub Actions using the OIDC provider. Enable Azure DevOps Federated Service Connections. For AKS: enable OIDC issuer and configure Workload Identity. Remove all pipeline secrets used for Azure authentication after federation is configured." `
                -MigrationPath "Pipeline Secrets → Federated Identity Credentials (OIDC) → Remove Secrets" `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($appsWithFederated.Count -gt 0) {
            $maturityPoints += 4
            Add-Finding -DomainId "D2" -DomainName "Credential Posture" -CheckId "D2.3" `
                -Title "Workload Identity Federation In Use ($($appsWithFederated.Count) apps, $fedPct% adoption)" `
                -Evidence "Apps with Federated Identity Credentials: $($appsWithFederated.Count) ($fedPct%)" `
                -CurrentState "$($appsWithFederated.Count) App Registrations use Federated Identity Credentials. WIF is in use — likely for CI/CD pipelines or Kubernetes workloads." `
                -Gap "Verify that all CI/CD pipelines have migrated from secrets to federation. Confirm federation subject constraints are tightly scoped (not wildcard trust)." `
                -Risk "Info" `
                -BusinessImpact "Low — WIF adoption is a positive architectural signal. Audit federation subjects to prevent overly-broad OIDC trust grants." `
                -TargetState "All eligible pipelines and non-Azure workloads use WIF. Zero pipeline secrets for Azure authentication. Federation subjects scoped to minimum required branches/environments." `
                -Recommendation "Audit each federated credential configuration: verify issuer, subject, and audience are correctly scoped. Avoid wildcard subjects. Ensure unused federated credentials are removed." `
                -MigrationPath "Continue expanding WIF adoption. Tighten subject constraints where broad." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D2" -Name "Credential Posture" -Icon "🔑" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Secret-using apps: $secretDependentApps ($secretPct%). Federated creds: $($appsWithFederated.Count). Expired: $totalExpired. Expiring soon: $($expiringSoonSecrets.Count + $expiringSoonCerts.Count)." `
            -TargetStateSummary "Zero client secrets. Managed Identity for Azure workloads. Federated Credentials for CI/CD and non-Azure. Automated rotation for remaining certificates." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 3: Privilege & Permission Architecture ─────────────────────

    Function Invoke-Domain3-PermissionArchitecture {
        param ([object[]]$AllApps, [object[]]$AllSPs)

        Write-Host "  🛡️  D3: Privilege & Permission Architecture..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Collect OAuth2 permission grants (delegated) ───────────────────────────
        Write-Host "     ↳ Collecting OAuth2 permission grants..." -ForegroundColor DarkGray
        $oauth2Grants = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/oauth2PermissionGrants?`$top=999"

        # ── Collect app role assignments (application permissions on SPs) ─────────
        Write-Host "     ↳ Sampling app role assignments..." -ForegroundColor DarkGray
        # $appRoleAssignments = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,displayName,appRoles,appId&`$top=200"
        # $appRoleAssignments = $appRoleAssignments | Where-Object { $_.appId -ne '' }

        $appRoleAssignments = @()
        $totalSPs = $AllSPs.Count
        $currentSP = 0

        foreach ($sp in $AllSPs) {
            $currentSP++

            $percentComplete = if ($totalSPs -gt 0) {
                [Math]::Round(($currentSP / $totalSPs) * 100)
            }
            else {
                100
            }

            Write-Progress -Activity "Collecting Service Principal App Role Assignments" -Status "$currentSP of $totalSPs — $($sp.displayName)" -PercentComplete $percentComplete

            try {
                $uri = "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)/appRoleAssignments?`$top=999"

                $assignments = Get-GraphPagedResults -Uri $uri

                foreach ($assignment in $assignments) {
                    $appRoleAssignments += [PSCustomObject]@{
                        ServicePrincipalId          = $sp.id
                        ServicePrincipalDisplayName = $sp.displayName
                        ResourceId                  = $assignment.resourceId
                        AppRoleId                   = $assignment.appRoleId
                        PrincipalId                 = $assignment.principalId
                        PrincipalDisplayName        = $assignment.principalDisplayName
                        PrincipalType               = $assignment.principalType
                    }
                }
            }
            catch {
                Write-Warning "Unable to retrieve app role assignments for '$($sp.displayName)': $($_.Exception.Message)"
            }
        }

        Write-Progress -Activity "Collecting Service Principal App Role Assignments" -Completed

        # ── Check 3.1: Overly-broad consent grants ────────────────────────────────
        $fullAccessGrants = @($oauth2Grants | Where-Object { $_.scope -like "*Mail.ReadWrite*" -or $_.scope -like "*Files.ReadWrite.All*" -or $_.scope -like "*Directory.ReadWrite.All*" -or $_.scope -like "*User.ReadWrite.All*" })
        $allDataGrants = @($oauth2Grants | Where-Object { $_.scope -like "*All*" })

        if ($fullAccessGrants.Count -gt 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D3" -DomainName "Permission Architecture" -CheckId "D3.1" `
                -Title "High-Privilege OAuth2 Consent Grants Detected ($($fullAccessGrants.Count) grants with broad write access)" `
                -Evidence "Grants with broad write scopes (Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All, User.ReadWrite.All): $($fullAccessGrants.Count) | Total OAuth2 grants with 'All' scope: $($allDataGrants.Count)" `
                -CurrentState "$($fullAccessGrants.Count) OAuth2 permission grants include high-privilege write scopes across tenant data (mail, files, directory). These grants allow delegated identities to read or write tenant data at scale on behalf of consented principals." `
                -Gap "Broad OAuth2 consent scopes violate the principle of least privilege. A compromised application or token carrying these scopes can exfiltrate significant tenant data or modify directory objects. Without user consent restrictions, end users may have granted these scopes to unknown applications." `
                -Risk "High" `
                -BusinessImpact "Applications with Mail.ReadWrite or Files.ReadWrite.All can read and delete all email or files in the consented user's scope. Directory.ReadWrite.All or User.ReadWrite.All can enumerate and modify directory objects. These are primary targets in OAuth phishing attacks." `
                -TargetState "No end-user consent to high-privilege scopes. All high-privilege delegated grants reviewed and approved by admins. Admin consent workflow enforced for all 'All' scopes. User consent restricted to verified publishers and low-risk permissions only." `
                -Recommendation "Review each high-privilege grant. Revoke grants that cannot be justified. Restrict user consent via Entra ID Consent Settings: allow only low-risk verified publisher apps. Enable admin consent workflow. Consider App Governance (Microsoft Defender for Cloud Apps) for continuous consent monitoring." `
                -MigrationPath "User consent grants → Admin-approved grants → Least-privilege scopes" `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        elseif ($allDataGrants.Count -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D3" -DomainName "Permission Architecture" -CheckId "D3.1" `
                -Title "Broad 'All' Scope Consent Grants Present — Review Required ($($allDataGrants.Count) grants)" `
                -Evidence "OAuth2 grants with 'All' suffix scope: $($allDataGrants.Count) | High-privilege write grants: 0" `
                -CurrentState "$($allDataGrants.Count) OAuth2 permission grants include scopes with 'All' suffix, indicating broad read access across resource collections." `
                -Gap "While not write-privileged, broad read scopes (e.g., Mail.Read, Files.Read.All) still expose significant tenant data. Review whether each grant is necessary and scoped to the minimum required." `
                -Risk "Medium" `
                -BusinessImpact "Broad read access can enable data exfiltration through a compromised application token. Review each grant for business necessity." `
                -TargetState "All grants reviewed and documented. No 'All' scope grants approved without admin review. User consent restricted to low-risk permissions." `
                -Recommendation "Review and document each 'All' scope grant. Restrict user consent. Implement admin consent workflow." `
                -MigrationPath "Broad scopes → Minimum-required scopes" `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D3" -DomainName "Permission Architecture" -CheckId "D3.1" `
                -Title "No High-Privilege Broad OAuth2 Consent Grants Detected" `
                -Evidence "High-privilege write grants: 0 | Total OAuth2 grants: $($oauth2Grants.Count)" `
                -CurrentState "No high-privilege (Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All) consent grants found." `
                -Gap "Maintain this posture. Confirm user consent restrictions are policy-enforced, not incidentally clean." `
                -Risk "Info" `
                -BusinessImpact "Low — no high-privilege consent grants." `
                -TargetState "Policy-enforced consent restrictions. Admin consent workflow for all elevated permissions." `
                -Recommendation "Verify Entra ID consent settings: ensure user consent is restricted. Enable admin consent workflow." `
                -MigrationPath "Maintain consent governance policy" `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 3.2: Application permissions (not delegated) on SP credentials ─
        $appsWithHighPrivAppPerms = @()
        $highPrivilegeRoles = @("Directory.ReadWrite.All", "Application.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "User.ReadWrite.All", "Mail.ReadWrite", "Files.ReadWrite.All")

        foreach ($app in $AllApps) {
            if (-not $app.requiredResourceAccess) { continue }
            foreach ($resource in $app.requiredResourceAccess) {
                foreach ($perm in $resource.resourceAccess) {
                    # type "Role" = Application permission (not delegated)
                    if ($perm.type -eq "Role") {
                        $appsWithHighPrivAppPerms += $app
                        break
                    }
                }
            }
        }

        if ($appsWithHighPrivAppPerms.Count -gt 20) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D3" -DomainName "Permission Architecture" -CheckId "D3.2" `
                -Title "Excessive Application Permission Usage — $($appsWithHighPrivAppPerms.Count) Apps with Non-Delegated Permissions" `
                -Evidence "App Registrations with Application-type (non-delegated) permissions: $($appsWithHighPrivAppPerms.Count) / $($AllApps.Count) apps" `
                -CurrentState "$($appsWithHighPrivAppPerms.Count) App Registrations have one or more Application-type API permissions. Application permissions run with no user context and grant access to all data in the tenant for the permitted scope — significantly broader than delegated permissions." `
                -Gap "Application permissions (Role type) violate least privilege when used for operations that could be performed with delegated (scoped) permissions. Over-reliance on application permissions is a common workload identity over-privilege pattern." `
                -Risk "High" `
                -BusinessImpact "An application with Application-type Directory.ReadWrite.All or User.ReadWrite.All can read and modify all users and directory data without any user context or approval. A compromised application token grants tenant-wide access." `
                -TargetState "Application permissions granted only when delegated permissions are technically insufficient (e.g., background daemons). All application permission grants admin-consented and reviewed. No application permissions with 'All' write scope unless explicitly justified." `
                -Recommendation "Review each application permission grant. For each: confirm delegated permissions are insufficient. Remove or downscope where possible. Maintain a permission justification register." `
                -MigrationPath "Application Permissions → Review → Downscope to Delegated where possible → Justify remaining" `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 3
            Add-Finding -DomainId "D3" -DomainName "Permission Architecture" -CheckId "D3.2" `
                -Title "Application Permission Usage Within Expected Range ($($appsWithHighPrivAppPerms.Count) apps)" `
                -Evidence "Apps with Application-type permissions: $($appsWithHighPrivAppPerms.Count) / $($AllApps.Count)" `
                -CurrentState "$($appsWithHighPrivAppPerms.Count) apps use Application-type permissions. Volume is manageable." `
                -Gap "Ensure each application permission grant is documented and justified. Delegated permissions preferred where technically feasible." `
                -Risk "Low" `
                -BusinessImpact "Low — within expected range. Maintain permission documentation." `
                -TargetState "All application permission grants documented with business justification. Periodic permission review cycle." `
                -Recommendation "Document each application permission grant. Schedule semi-annual permission review." `
                -MigrationPath "Maintain review cadence" `
                -RoadmapPhase "Strategic" -MaturityContribution 3
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D3" -Name "Permission Architecture" -Icon "🛡️" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "High-privilege OAuth2 grants: $($fullAccessGrants.Count). Apps with application permissions: $($appsWithHighPrivAppPerms.Count)/$($AllApps.Count)." `
            -TargetStateSummary "Least-privilege permissions. Admin consent for all grants. No high-privilege user consent. Application permissions documented and justified." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 4: Lifecycle & Governance ──────────────────────────────────

    Function Invoke-Domain4-LifecycleGovernance {
        param ([object[]]$AllApps, [object[]]$AllSPs)

        Write-Host "  🔄 D4: Lifecycle & Governance..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        $now = Get-Date
        $staleThreshold = $now.AddDays(-90)

        # ── Stale App Registrations (created >180 days ago, check sign-in) ────────
        Write-Host "     ↳ Identifying stale and ownerless apps..." -ForegroundColor DarkGray

        $oldApps = @($AllApps | Where-Object {
                $_.createdDateTime -and ([datetime]$_.createdDateTime) -lt $now.AddDays(-180)
            })

        $ownerlessApps = @()
        $ownersCheckedCount = 0
        foreach ($app in $AllApps) {
            if ($ownersCheckedCount -ge 100) { break }   # limit API calls for large tenants
            $owners = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/applications/$($app.id)/owners?`$select=id,userPrincipalName"
            if (-not $owners -or -not $owners.value -or $owners.value.Count -eq 0) {
                $ownerlessApps += $app
            }
            $ownersCheckedCount++
        }

        # ── Check 4.1: Ownerless App Registrations ────────────────────────────────
        if ($ownerlessApps.Count -gt 0) {
            $ownerlessPct = [Math]::Round(($ownerlessApps.Count / [Math]::Max(1, $ownersCheckedCount)) * 100, 0)
            $riskLevel = if ($ownerlessPct -gt 30) { "High"; $high++ } else { "Medium"; $medium++ }

            $maturityPoints += if ($ownerlessPct -gt 30) { 1 } else { 2 }

            Add-Finding -DomainId "D4" -DomainName "Lifecycle & Governance" -CheckId "D4.1" `
                -Title "Ownerless App Registrations Detected — Governance Gap ($($ownerlessApps.Count) apps in sample of $ownersCheckedCount)" `
                -Evidence "Ownerless Apps: $($ownerlessApps.Count) / $ownersCheckedCount sampled ($ownerlessPct%) | Ownerless app names (first 5): $(($ownerlessApps | Select-Object -First 5 | ForEach-Object { $_.displayName }) -join ', ')" `
                -CurrentState "$($ownerlessApps.Count) App Registrations have no registered owner. These are effectively orphaned — no accountable party to respond to security incidents, credential expiry notifications, or decommission requests." `
                -Gap "Ownerless identities are a governance blind spot. No one receives expiry alerts, no one can confirm the app is still in use, and no one is accountable for permissions granted. This is a common root cause of stale credential exposure." `
                -Risk $riskLevel `
                -BusinessImpact "Ownerless apps with active credentials and permissions are persistent attack surface that no team monitors. In a security incident, ownerless identities take significantly longer to investigate and contain." `
                -TargetState "100% of App Registrations have at least one named owner. Ownership enforced at provisioning. Ownerless apps blocked by governance policy (e.g., IaC policy or Entra ID lifecycle policy)." `
                -Recommendation "Assign owners to all identified ownerless apps. For apps with no identifiable owner: verify if the workload is still live. If not — decommission. Add app ownership assignment to the provisioning process. Consider Azure Policy or Entra lifecycle policies to enforce owner requirements." `
                -MigrationPath "Ownerless → Owner Assignment → Lifecycle Policy → Auto-decommission if abandoned" `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 5
            Add-Finding -DomainId "D4" -DomainName "Lifecycle & Governance" -CheckId "D4.1" `
                -Title "All Sampled App Registrations Have Registered Owners" `
                -Evidence "Sampled $ownersCheckedCount apps — all have at least one owner registered" `
                -CurrentState "All sampled App Registrations have registered owners — ownership governance is in place." `
                -Gap "Ensure ownership is enforced at provisioning, not corrected retroactively. Verify owners are still active employees/teams." `
                -Risk "Info" `
                -BusinessImpact "Low — ownership accountability is present." `
                -TargetState "Ownership enforced by policy at provisioning. Automated ownership validation against HR feed." `
                -Recommendation "Validate that app owners are current employees. Implement ownership validation in the IaC/provisioning pipeline." `
                -MigrationPath "Maintain ownership governance" `
                -RoadmapPhase "Strategic" -MaturityContribution 5
        }

        # ── Check 4.2: Long-lived secrets (>1 year expiry) ───────────────────────
        $longLivedSecrets = @()
        foreach ($app in $AllApps) {
            foreach ($secret in $app.passwordCredentials) {
                if ($secret.endDateTime) {
                    $expiry = [datetime]$secret.endDateTime
                    $created = if ($secret.startDateTime) { [datetime]$secret.startDateTime } else { $now }
                    $lifetime = ($expiry - $created).TotalDays
                    if ($lifetime -gt 365) { $longLivedSecrets += @{ App = $app.displayName; Lifetime = [int]$lifetime } }
                }
                elseif (-not $secret.endDateTime) {
                    # No expiry = never-expiring secret
                    $longLivedSecrets += @{ App = $app.displayName; Lifetime = 99999 }
                }
            }
        }

        if ($longLivedSecrets.Count -gt 0) {
            $neverExpiring = @($longLivedSecrets | Where-Object { $_.Lifetime -eq 99999 })
            $riskLevel = if ($neverExpiring.Count -gt 0) { $critical++; "Critical" } else { $high++; "High" }
            $maturityPoints += 1

            Add-Finding -DomainId "D4" -DomainName "Lifecycle & Governance" -CheckId "D4.2" `
                -Title "Long-Lived or Non-Expiring Secrets Detected ($($longLivedSecrets.Count) secrets, $($neverExpiring.Count) never-expiring)" `
                -Evidence "Long-lived secrets (>1 year): $($longLivedSecrets.Count) | Never-expiring (no expiry date): $($neverExpiring.Count) | Apps affected: $(($longLivedSecrets | Select-Object -ExpandProperty App -Unique | Select-Object -First 5) -join ', ')" `
                -CurrentState "$($longLivedSecrets.Count) client secrets have a lifetime exceeding 1 year or have no expiry date. Long-lived secrets are incompatible with a Zero Trust posture — they cannot be rotated regularly without intentional lifecycle management, and non-expiring secrets persist indefinitely." `
                -Gap "Microsoft best practice and most compliance frameworks require secrets to be rotated at least annually. Never-expiring secrets are a critical deviation from Zero Trust. A leaked never-expiring secret remains valid until manually revoked — which, without automated detection, may be never." `
                -Risk $riskLevel `
                -BusinessImpact "A leaked never-expiring secret provides permanent access as the application identity until manually detected and revoked. These are the credentials most likely found in hardcoded configuration years after initial development." `
                -TargetState "Maximum 90-day secret lifetime. Never-expiring secrets eliminated. Automated rotation via Key Vault. Preferred: Managed Identity to eliminate rotation entirely." `
                -Recommendation "Immediately revoke all never-expiring secrets. Replace with 90-day maximum lifetime secrets stored in Azure Key Vault with auto-rotation. Prioritise migrating these workloads to Managed Identity — the rotation event is the ideal migration trigger." `
                -MigrationPath "Never-expiring secrets → 90-day secrets in Key Vault → Managed Identity (eliminate rotation)" `
                -RoadmapPhase "0-30 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D4" -DomainName "Lifecycle & Governance" -CheckId "D4.2" `
                -Title "No Long-Lived or Never-Expiring Secrets Detected" `
                -Evidence "Long-lived secrets (>1 year) found: 0" `
                -CurrentState "All detected secrets have expiry dates within 1 year. Secret lifetime governance appears to be in place." `
                -Gap "Confirm secrets are stored in Key Vault with automated rotation rather than managed manually. Verify maximum lifetime policy is enforced." `
                -Risk "Info" `
                -BusinessImpact "Low — good secret lifetime hygiene." `
                -TargetState "90-day max lifetime enforced by Key Vault policy. MI adoption to eliminate rotation entirely." `
                -Recommendation "Verify secrets are in Key Vault with automated rotation configured. Establish policy: no new secret with lifetime >90 days." `
                -MigrationPath "Maintain automated rotation. Migrate to MI to eliminate rotation." `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Check 4.3: Apps older than 2 years with no sign-in (proxy via credentials) ─
        $veryOldApps = @($AllApps | Where-Object {
                $_.createdDateTime -and ([datetime]$_.createdDateTime) -lt $now.AddYears(-2)
            })

        if ($veryOldApps.Count -gt 0) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D4" -DomainName "Lifecycle & Governance" -CheckId "D4.3" `
                -Title "Legacy App Registrations (>2 Years Old) — Stale Identity Risk ($($veryOldApps.Count) apps)" `
                -Evidence "App Registrations older than 2 years: $($veryOldApps.Count) / $($AllApps.Count) total | Names (first 5): $(($veryOldApps | Select-Object -First 5 | ForEach-Object { $_.displayName }) -join ', ')" `
                -CurrentState "$($veryOldApps.Count) App Registrations are more than 2 years old. These may represent legacy integrations, abandoned development apps, or workloads that have never been reviewed for current credential and permission hygiene." `
                -Gap "Age alone is not a disqualifier, but legacy apps are more likely to have: long-lived secrets set at creation, permissions granted historically that exceed current need, no current owner aware of the application, and no alignment to current security standards." `
                -Risk "Medium" `
                -BusinessImpact "Legacy apps are a latent risk. Credentials may have been shared, hardcoded, or stored in decommissioned systems. A review may reveal permissions that are no longer justified." `
                -TargetState "All apps >2 years old reviewed within 90 days. Stale apps decommissioned. Remaining legacy apps brought to current credential standards (MI preferred, certificates minimum)." `
                -Recommendation "Run a legacy app review: for each app >2 years old, confirm (1) active workload consuming it, (2) owner identity, (3) credential type and expiry, (4) permissions still justified. Decommission any without confirmed active workload." `
                -MigrationPath "Legacy Apps → Review → Decommission or Modernise Credentials" `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D4" -Name "Lifecycle & Governance" -Icon "🔄" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Ownerless apps (sampled): $($ownerlessApps.Count). Long-lived/never-expiring secrets: $($longLivedSecrets.Count). Apps >2 years old: $($veryOldApps.Count)." `
            -TargetStateSummary "100% app ownership. 90-day max secret lifetime. Automated decommission for stale identities. MI adoption eliminates rotation." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 5: Workload Identity Security Controls ─────────────────────

    Function Invoke-Domain5-SecurityControls {
        param ([object[]]$AllSPs)

        Write-Host "  🔒 D5: Workload Identity Security Controls..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check for Conditional Access targeting workload identities ────────────
        Write-Host "     ↳ Checking Conditional Access for workload identities..." -ForegroundColor DarkGray
        $caPolicies = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies?`$select=id,displayName,state,conditions,grantControls"

        $wiCAPolicies = @($caPolicies | Where-Object {
                $_.conditions.clientApplications -ne $null -or
                ($_.displayName -like "*workload*" -or $_.displayName -like "*service principal*" -or $_.displayName -like "*managed identity*")
            })

        $enabledWiCA = @($wiCAPolicies | Where-Object { $_.state -eq "enabled" })

        if ($enabledWiCA.Count -eq 0) {
            $high++
            $maturityPoints += 1
            Add-Finding -DomainId "D5" -DomainName "Security Controls" -CheckId "D5.1" `
                -Title "No Conditional Access Policies Target Workload Identities" `
                -Evidence "CA policies targeting workload identities (enabled): 0 | Total CA policies: $($caPolicies.Count) | WI CA policies (all states): $($wiCAPolicies.Count)" `
                -CurrentState "No Conditional Access policies are configured to govern workload identity sign-in behaviour. Service Principals authenticate with no context-based access controls beyond the credential itself." `
                -Gap "Workload identity Conditional Access (requires Workload Identity Premium) enables IP-based location restrictions for Service Principals, blocking authentication from unexpected network locations. Without it, a stolen SP credential can be used from anywhere in the world." `
                -Risk "High" `
                -BusinessImpact "A stolen Service Principal credential has no network or context constraints. Attackers can authenticate from any IP, at any time, with no alerting beyond token issuance. This is a critical gap in Zero Trust workload identity posture." `
                -TargetState "Workload Identity Conditional Access policies restricting SP authentication to named corporate egress IPs or Azure datacenter ranges. Critical SPs (high-permission daemon apps) restricted to specific IP ranges. Named location policies applied to all external SPs." `
                -Recommendation "Evaluate Workload Identity Premium licencing. Configure Conditional Access targeting service principal sign-ins: restrict high-privilege SPs to named locations (corporate NAT IPs, Azure IP ranges). Start with report-only mode, then enforce." `
                -MigrationPath "No WI CA → Workload Identity Premium → CA Policies for SP sign-ins" `
                -RoadmapPhase "31-60 Days" -MaturityContribution 1
        }
        else {
            $maturityPoints += 5
            Add-Finding -DomainId "D5" -DomainName "Security Controls" -CheckId "D5.1" `
                -Title "Workload Identity Conditional Access Policies Active ($($enabledWiCA.Count) enabled)" `
                -Evidence "Enabled WI CA policies: $($enabledWiCA.Count) | Policy names: $(($enabledWiCA | ForEach-Object { $_.displayName } | Select-Object -First 3) -join ', ')" `
                -CurrentState "$($enabledWiCA.Count) Conditional Access policies govern workload identity sign-ins. This indicates Workload Identity Premium is licensed and the team is applying context-based controls to non-human identities." `
                -Gap "Verify policy coverage: confirm all high-privilege SPs are included. Ensure policies are not in report-only mode. Verify named locations are accurate and up to date." `
                -Risk "Info" `
                -BusinessImpact "Low — WI CA is an advanced control that significantly reduces risk from stolen SP credentials." `
                -TargetState "All high-privilege SPs covered by IP-based CA policies. CI/CD-sourced SPs excluded (covered by WIF). Policies reviewed quarterly as network topology changes." `
                -Recommendation "Audit WI CA policy scope: confirm all high-privilege SPs are included. Review named locations. Ensure no SPs are excluded from CA policies without documented justification." `
                -MigrationPath "Extend WI CA coverage to all high-privilege SPs" `
                -RoadmapPhase "Strategic" -MaturityContribution 5
        }

        # ── Check 5.2: Publisher verification ────────────────────────────────────
        $verifiedPublisherSPs = @($AllSPs | Where-Object { $_.verifiedPublisher -and $_.verifiedPublisher.displayName })
        $thirdPartySPs = @($AllSPs | Where-Object { $_.appOwnerOrganizationId -and $_.appOwnerOrganizationId -ne $TenantId -and $_.appOwnerOrganizationId -ne "f8cdef31-a31e-4b4a-93e4-5f571e91255a" })
        $unverifiedThirdParty = @($thirdPartySPs | Where-Object { -not $_.verifiedPublisher -or -not $_.verifiedPublisher.displayName })

        if ($unverifiedThirdParty.Count -gt 10) {
            $medium++
            $maturityPoints += 2
            Add-Finding -DomainId "D5" -DomainName "Security Controls" -CheckId "D5.2" `
                -Title "Unverified Third-Party Service Principals Present ($($unverifiedThirdParty.Count) unverified)" `
                -Evidence "Third-party SPs total: $($thirdPartySPs.Count) | With publisher verification: $($verifiedPublisherSPs.Count) | Without publisher verification: $($unverifiedThirdParty.Count)" `
                -CurrentState "$($unverifiedThirdParty.Count) third-party Service Principals have not completed Microsoft's publisher verification process. Publisher verification provides cryptographic assurance that the app publisher is a verified Microsoft Partner." `
                -Gap "Unverified publishers cannot be trusted to the same degree as verified publishers. Restrict user consent to verified publishers — this reduces the risk of OAuth phishing attacks where malicious apps impersonate trusted tools." `
                -Risk "Medium" `
                -BusinessImpact "Unverified publisher apps are the primary vehicle for OAuth phishing attacks. Employees consenting to unverified apps may grant access to corporate data to malicious actors." `
                -TargetState "User consent restricted to verified publisher apps only. All existing unverified third-party SPs reviewed and approved or removed. New SaaS integrations require verified publisher status." `
                -Recommendation "Restrict user consent to verified publisher apps via Entra ID consent settings. Review the $($unverifiedThirdParty.Count) unverified third-party SPs — remove those not in active use." `
                -MigrationPath "Unverified SaaS SPs → Admin Review → Remove Unused → Require Verified Publisher for New" `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 4
            Add-Finding -DomainId "D5" -DomainName "Security Controls" -CheckId "D5.2" `
                -Title "Third-Party Publisher Verification Posture Is Acceptable ($($unverifiedThirdParty.Count) unverified)" `
                -Evidence "Third-party SPs: $($thirdPartySPs.Count) | Unverified: $($unverifiedThirdParty.Count)" `
                -CurrentState "Low count of unverified third-party SPs." `
                -Gap "Enforce verified-publisher-only for new user consents going forward." `
                -Risk "Low" `
                -BusinessImpact "Low — limited unverified publisher exposure." `
                -TargetState "Policy-enforced verified publisher requirement for all new consents." `
                -Recommendation "Enforce verified publisher restriction in Entra ID consent settings. Review remaining $($unverifiedThirdParty.Count) unverified SPs." `
                -MigrationPath "Maintain verified publisher enforcement policy" `
                -RoadmapPhase "Strategic" -MaturityContribution 4
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D5" -Name "Security Controls" -Icon "🔒" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "WI Conditional Access policies (enabled): $($enabledWiCA.Count). Unverified third-party SPs: $($unverifiedThirdParty.Count)." `
            -TargetStateSummary "WI CA policies for all high-privilege SPs. Verified publisher enforcement. Named location restrictions on critical SPs." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── Domain 6: Application Architecture Alignment ──────────────────────

    Function Invoke-Domain6-AppArchitecture {
        param ([object[]]$AllApps, [object[]]$AllSPs)

        Write-Host "  🏗️  D6: Application Architecture Alignment..." -ForegroundColor Cyan

        $critical = 0; $high = 0; $medium = 0; $low = 0
        $maturityPoints = @()

        # ── Check 6.1: Multi-tenant apps ─────────────────────────────────────────
        $multiTenantApps = @($AllApps | Where-Object {
                $_.signInAudience -eq "AzureADMultipleOrgs" -or $_.signInAudience -eq "AzureADandPersonalMicrosoftAccount"
            })

        if ($multiTenantApps.Count -gt 0) {
            $riskLevel = if ($multiTenantApps.Count -gt 10) { $high++; "High" } else { $medium++; "Medium" }
            $maturityPoints += if ($multiTenantApps.Count -gt 10) { 1 } else { 2 }

            Add-Finding -DomainId "D6" -DomainName "App Architecture" -CheckId "D6.1" `
                -Title "Multi-Tenant App Registrations Detected — Cross-Tenant Trust Review Required ($($multiTenantApps.Count) apps)" `
                -Evidence "Multi-tenant Apps (AzureADMultipleOrgs or AzureADandPersonalMicrosoftAccount): $($multiTenantApps.Count) | Names (first 5): $(($multiTenantApps | Select-Object -First 5 | ForEach-Object { $_.displayName }) -join ', ')" `
                -CurrentState "$($multiTenantApps.Count) App Registrations are configured for multi-tenant (cross-tenant) sign-in. These applications can be consented to and used by identities in any Entra ID tenant, not just your own." `
                -Gap "Multi-tenant apps have a much larger trust surface than single-tenant apps. A misconfigured multi-tenant app can be exploited by external tenants, and OAuth consent by users in external tenants can expose your application's back-end services." `
                -Risk $riskLevel `
                -BusinessImpact "Multi-tenant app misconfiguration is a documented attack vector. If a multi-tenant app grants permissions based on tenant identity without validation, an attacker from any tenant can abuse the application." `
                -TargetState "All multi-tenant apps intentionally designed and reviewed. Publisher verification completed. Audience restricted to single-tenant where multi-tenancy is not required. Cross-tenant access controls in place." `
                -Recommendation "Review each multi-tenant app: (1) Is multi-tenant sign-in intentional and required? (2) Is publisher verification complete? (3) Are there tenant-side validation controls in the application code? Convert to single-tenant (AzureADMyOrg) where multi-tenancy is not required." `
                -MigrationPath "Multi-tenant → Single-tenant where multi-tenancy not required | Remaining → Publisher verify + tenant validation" `
                -RoadmapPhase "31-60 Days" -MaturityContribution 2
        }
        else {
            $maturityPoints += 5
            Add-Finding -DomainId "D6" -DomainName "App Architecture" -CheckId "D6.1" `
                -Title "No Multi-Tenant App Registrations Detected — Single-Tenant Posture Maintained" `
                -Evidence "Multi-tenant App Registrations: 0 / $($AllApps.Count)" `
                -CurrentState "All App Registrations are scoped to the home tenant (single-tenant). No cross-tenant trust surface present." `
                -Gap "Maintain this posture. Any new app requiring multi-tenant sign-in must go through a security review before enabling multi-tenant sign-in audience." `
                -Risk "Info" `
                -BusinessImpact "Low — single-tenant posture reduces OAuth attack surface." `
                -TargetState "Maintain single-tenant default. Multi-tenant requires security architecture review and approval." `
                -Recommendation "Formalise a policy: new App Registrations must default to AzureADMyOrg. Multi-tenant requires Architecture Review Board approval." `
                -MigrationPath "Maintain single-tenant default policy" `
                -RoadmapPhase "Strategic" -MaturityContribution 5
        }

        # ── Check 6.2: Apps without identifier URIs (public API surface) ─────────
        $appsWithoutIdentifierUri = @($AllApps | Where-Object {
                (-not $_.identifierUris -or $_.identifierUris.Count -eq 0) -and
                ($_.requiredResourceAccess -and $_.requiredResourceAccess.Count -gt 0)
            })

        if ($appsWithoutIdentifierUri.Count -gt 0) {
            $low++
            $maturityPoints += 3
            Add-Finding -DomainId "D6" -DomainName "App Architecture" -CheckId "D6.2" `
                -Title "Apps With API Permissions But No Identifier URI ($($appsWithoutIdentifierUri.Count) apps)" `
                -Evidence "Apps with permissions but no Identifier URI: $($appsWithoutIdentifierUri.Count)" `
                -CurrentState "$($appsWithoutIdentifierUri.Count) App Registrations have API permissions but no Application ID URI configured. Identifier URIs are required for apps that expose their own API scopes." `
                -Gap "Missing identifier URIs may indicate apps that expose APIs without proper URI registration, or apps that are misconfigured. While low risk on its own, it indicates incomplete app registration hygiene." `
                -Risk "Low" `
                -BusinessImpact "Low — primarily a hygiene concern. Incomplete registrations can complicate troubleshooting and governance." `
                -TargetState "All apps exposing APIs have properly registered identifier URIs using api:// or https:// scheme with tenant-specific path." `
                -Recommendation "Review apps without identifier URIs. Add api://<client-id> URI to all apps that expose API scopes. Remove permission declarations from apps that do not actually call those APIs." `
                -MigrationPath "App hygiene review → Configure identifier URIs → Remove unused permission declarations" `
                -RoadmapPhase "61-90 Days" -MaturityContribution 3
        }

        # ── Compute domain maturity ───────────────────────────────────────────────
        $avgPoints = if ($maturityPoints.Count -gt 0) { [Math]::Round(($maturityPoints | Measure-Object -Average).Average, 0) } else { 1 }
        $domainMaturity = [Math]::Max(1, [Math]::Min(5, $avgPoints))

        Set-DomainResult -Id "D6" -Name "App Architecture" -Icon "🏗️" `
            -MaturityScore $domainMaturity `
            -CurrentStateSummary "Multi-tenant apps: $($multiTenantApps.Count). Apps missing identifier URIs: $($appsWithoutIdentifierUri.Count)." `
            -TargetStateSummary "Single-tenant default. Multi-tenant requires ARB approval. All APIs have identifier URIs. Publisher verification for all external apps." `
            -CriticalCount $critical -HighCount $high -MediumCount $medium -LowCount $low
    }

    #endregion

    #region ── JSON Serialisation Helpers ────────────────────────────────────────

    Function ConvertTo-JsonSafe {
        param ([string]$s)
        return $s `
            -replace '\\', '\\' `
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
            $null = $sb.Append("""migrationPath"":""$(ConvertTo-JsonSafe $f.MigrationPath)"",")
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

    #region ── CSV Export ────────────────────────────────────────────────────────

    Function Export-FindingsCsv {
        param ([string]$OutputFilePath)

        $script:Findings | Select-Object `
            DomainId, DomainName, CheckId, Title, Risk, RoadmapPhase, MigrationPath,
        Evidence, CurrentState, Gap, BusinessImpact, TargetState, Recommendation |
        Export-Csv -Path $OutputFilePath -NoTypeInformation -Encoding UTF8 -Force
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
        if (-not $overallLabel) { $overallLabel = "Initial" }

        $totalCritical = ($script:Findings | Where-Object { $_.Risk -eq "Critical" }).Count
        $totalHigh = ($script:Findings | Where-Object { $_.Risk -eq "High" }).Count
        $totalMedium = ($script:Findings | Where-Object { $_.Risk -eq "Medium" }).Count
        $totalLow = ($script:Findings | Where-Object { $_.Risk -eq "Low" }).Count
        $totalFindings = $script:Findings.Count

        $ringR = 54
        $ringCirc = [Math]::Round(2 * [Math]::PI * $ringR, 1)
        $ringPct = [int]([Math]::Round(($OverallMaturity / 5) * 100, 0))
        $ringDash = [Math]::Round($ringCirc * ($ringPct / 100), 1)
        $ringGap = [Math]::Round($ringCirc - $ringDash, 1)
        $ringColor = $script:MaturityColors[[int][Math]::Round($OverallMaturity)]
        if (-not $ringColor) { $ringColor = "#f85149" }

        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Workload Identity Architecture Assessment — __TENANT_NAME__</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
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
.nav-btn.active{background:rgba(57,197,207,.1);color:var(--accent2);border-left:3px solid var(--accent2);font-weight:600}
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

/* ── Maturity Ring ── */
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

/* ── Panels ── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.panel-title{font-size:14px;font-weight:700}
.panel-badge{font-size:10px;padding:2px 9px;border-radius:20px;background:var(--surface3);color:var(--muted);font-family:var(--mono)}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}

/* ── Bar list ── */
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.bar-label{font-size:11px;color:var(--muted2);width:130px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.bar-fill{height:100%;border-radius:3px;width:0;transition:width 1s ease}
.bar-val{font-size:10px;color:var(--muted);font-family:var(--mono);width:24px;text-align:right}

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
.domain-tag{font-size:10px;padding:2px 7px;border-radius:12px;background:rgba(57,197,207,.1);color:var(--accent2);font-family:var(--mono)}

/* ── Pagination ── */
.pagination{display:flex;align-items:center;gap:6px;margin-top:14px;flex-wrap:wrap}
.pg-btn{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:4px 10px;cursor:pointer;font-size:12px;color:var(--text);font-family:var(--sans)}
.pg-btn:hover{background:var(--surface3)}
.pg-btn.active{background:var(--accent2);color:#fff;border-color:var(--accent2)}
.pg-info{font-size:11px;color:var(--muted);margin-left:8px}

/* ── Migration ladder ── */
.migration-ladder{display:flex;gap:0;margin:16px 0;flex-wrap:wrap}
.ml-step{flex:1;min-width:120px;padding:12px 14px;background:var(--surface2);border:1px solid var(--border);position:relative;font-size:11px}
.ml-step:not(:last-child)::after{content:'→';position:absolute;right:-10px;top:50%;transform:translateY(-50%);color:var(--accent2);font-weight:700;z-index:1}
.ml-step:first-child{border-radius:var(--radius-sm) 0 0 var(--radius-sm)}
.ml-step:last-child{border-radius:0 var(--radius-sm) var(--radius-sm) 0}
.ml-label{font-size:9px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:4px}
.ml-value{font-weight:700;color:var(--text)}
.ml-step.ml-target{background:rgba(57,197,207,.08);border-color:var(--accent2)}
.ml-step.ml-target .ml-value{color:var(--accent2)}

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
.drawer-value{font-size:12px;line-height:1.55;color:var(--muted2);background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px;border:1px solid var(--border)}
.drawer-migration{font-size:11px;line-height:1.55;color:var(--accent2);background:rgba(57,197,207,.06);border-radius:var(--radius-sm);padding:10px 12px;border:1px solid rgba(57,197,207,.2);font-family:var(--mono)}
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

/* ── Architecture / model panel ── */
.arch-note{background:linear-gradient(135deg,rgba(57,197,207,.07),rgba(163,113,247,.07));border:1px solid rgba(57,197,207,.2);border-radius:var(--radius);padding:14px 16px;margin-bottom:14px;font-size:12px;line-height:1.6;color:var(--muted2)}
.arch-note strong{color:var(--accent2)}

/* ── Toast ── */
#toast{position:fixed;bottom:20px;right:20px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 16px;font-size:12px;z-index:9999;transform:translateY(12px);opacity:0;transition:all .25s;pointer-events:none;box-shadow:var(--shadow)}
#toast.show{transform:none;opacity:1}

/* ── Mobile ── */
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
    <div class="logo-icon">🤖</div>
    <div class="logo-title">Workload Identity<br>Architecture Assessment</div>
    <div class="logo-sub">Non-Human Identity Review</div>
    <div class="ver-badge">v1.0 · __ASSESSMENT_DATE__</div>
  </div>

  <nav>
    <div class="nav-section">Assessment</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span>Overview</button>
    <button class="nav-btn" onclick="showPage('domains',this)"><span class="nav-icon">🗂️</span>Domain Results</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span>Findings</button>
    <button class="nav-btn" onclick="showPage('roadmap',this)"><span class="nav-icon">🗺️</span>Roadmap</button>
    <div class="nav-section">Reference</div>
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
      <h1>🤖 Workload Identity Architecture Assessment</h1>
      <p>Tenant: <strong>__TENANT_NAME__</strong> &nbsp;·&nbsp; Assessment date: __ASSESSMENT_DATE__ &nbsp;·&nbsp; Total findings: __TOTAL_FINDINGS__</p>
    </div>

    <!-- Maturity Ring -->
    <div class="health-card">
      <div class="health-ring-wrap">
        <svg viewBox="0 0 128 128" width="128" height="128">
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
        <h2>Overall Maturity: __OVERALL_LABEL__</h2>
        <p>Workload identities assessed across 6 architectural domains. The score reflects the current state of service principal governance, credential posture, permission architecture, and alignment to the Managed Identity first target state.</p>
        <div class="maturity-scale">
          <div class="ms-pill" style="color:#f85149;border-color:#f85149">1 · Initial</div>
          <div class="ms-pill" style="color:#d29922;border-color:#d29922">2 · Developing</div>
          <div class="ms-pill" style="color:#388bfd;border-color:#388bfd">3 · Defined</div>
          <div class="ms-pill" style="color:#39c5cf;border-color:#39c5cf">4 · Managed</div>
          <div class="ms-pill" style="color:#3fb950;border-color:#3fb950">5 · Optimised</div>
        </div>
      </div>
    </div>

    <!-- Migration Ladder -->
    <div class="arch-note">
      <strong>Target Migration Path</strong> — Zero Trust workload identity ladder:
    </div>
    <div class="migration-ladder" style="margin-top:0;margin-bottom:20px">
      <div class="ml-step"><div class="ml-label">Legacy</div><div class="ml-value">Shared Secrets</div></div>
      <div class="ml-step"><div class="ml-label">Intermediate</div><div class="ml-value">Certificates</div></div>
      <div class="ml-step"><div class="ml-label">Modern (CI/CD)</div><div class="ml-value">Federated Creds</div></div>
      <div class="ml-step ml-target"><div class="ml-label">Target (Azure)</div><div class="ml-value">Managed Identity</div></div>
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
        <div class="stat-value" style="color:var(--accent3)">6</div>
        <div class="stat-sub">Workload identity domains</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-label">Total Findings</div>
        <div class="stat-value" style="color:var(--accent2)">__TOTAL_FINDINGS__</div>
        <div class="stat-sub">Evidence-based checks</div>
      </div>
    </div>

    <!-- Charts -->
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
  </div>

  <!-- ══ Domain Results ═══════════════════════════════════════════════════ -->
  <div class="page" id="page-domains">
    <div class="page-header">
      <h1>🗂️ Domain Assessment Results</h1>
      <p>Six workload identity architectural domains assessed. Click a domain to view its findings.</p>
    </div>
    <div class="domain-grid" id="domainGrid"></div>
  </div>

  <!-- ══ Findings ══════════════════════════════════════════════════════════ -->
  <div class="page" id="page-findings">
    <div class="page-header">
      <h1>🔍 Assessment Findings</h1>
      <p>All findings follow the model: Context → Current State → Gap → Target State → Migration Path</p>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search findings, domains, recommendations..." oninput="filterFindings()">
        </div>
        <div class="filter-pills">
          <span class="fpill fpill-all active" onclick="setRiskFilter('all',this)">All</span>
          <span class="fpill fpill-crit"   onclick="setRiskFilter('Critical',this)">Critical</span>
          <span class="fpill fpill-high"   onclick="setRiskFilter('High',this)">High</span>
          <span class="fpill fpill-medium" onclick="setRiskFilter('Medium',this)">Medium</span>
          <span class="fpill fpill-low"    onclick="setRiskFilter('Low',this)">Low</span>
        </div>
        <button class="pg-btn" onclick="exportFindingsCSV()">⬇ CSV</button>
      </div>
      <div style="overflow-x:auto">
        <table>
          <thead>
            <tr>
              <th onclick="sortFindings('risk')" class="sort-active">Risk <span class="sort-arrow">▼</span></th>
              <th onclick="sortFindings('domainId')">Domain <span class="sort-arrow">↕</span></th>
              <th onclick="sortFindings('title')">Finding <span class="sort-arrow">↕</span></th>
              <th onclick="sortFindings('roadmapPhase')">Phase <span class="sort-arrow">↕</span></th>
              <th>Migration Path</th>
            </tr>
          </thead>
          <tbody id="findingsTbody"></tbody>
        </table>
      </div>
      <div class="pagination" id="findingsPagination"></div>
    </div>
  </div>

  <!-- ══ Roadmap ═══════════════════════════════════════════════════════════ -->
  <div class="page" id="page-roadmap">
    <div class="page-header">
      <h1>🗺️ Migration Roadmap</h1>
      <p>Sequenced by risk reduction, dependency, and migration complexity. Click any item to view full finding details.</p>
    </div>
    <div class="roadmap-grid" id="roadmapGrid"></div>
  </div>

  <!-- ══ Architecture Model ════════════════════════════════════════════════ -->
  <div class="page" id="page-architecture">
    <div class="page-header">
      <h1>🎯 Architecture Model & Methodology</h1>
      <p>Assessment methodology, domain definitions, and the Zero Trust workload identity target state.</p>
    </div>

    <div class="arch-note">
      <strong>Assessment Methodology</strong> — Each check follows the architectural thinking model:
      <em>Context → Current State → Gap/Risk → Target State → Migration Path → Success Measures</em>.
      This assessment is deliberately architecture-focused — findings describe <em>why</em> a gap matters
      and provide a concrete migration path, not just a raw configuration delta.
    </div>

    <div class="arch-note">
      <strong>Zero Trust Workload Identity Ladder</strong><br>
      Shared Secrets (lowest assurance) → Certificates (asymmetric, non-copyable)
      → Federated Workload Identity / OIDC (no credential at rest — for CI/CD, GitHub, AKS)
      → Managed Identity (no credential management — for Azure-hosted workloads).
      The target state for all Azure-hosted workloads is Managed Identity.
      For non-Azure workloads, the target is Workload Identity Federation.
    </div>

    <div class="arch-note">
      <strong>Graph-Friendly Data Model (Future-Ready)</strong><br>
      Assessment data is structured to support future dependency-graph and LLM-based analysis.
      The relationship chain collected: <em>Workload → Application → Service Principal
      → Credential/Federation → API/Resource → Permission</em>.
      This enables future visualisation as a dependency graph and automated impact analysis.
    </div>

    <div class="panel">
      <div class="panel-header"><span class="panel-title">Domain Definitions & Target States</span></div>
      <div id="archDomainList" style="display:flex;flex-direction:column;gap:10px"></div>
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
    <div class="drawer-section"><div class="drawer-label">Migration Path</div><div class="drawer-migration" id="drawerMigration"></div></div>
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
// ── Data ──────────────────────────────────────────────────────────────────────
const DOMAINS  = __DOMAINS_JSON__;
const FINDINGS = __FINDINGS_JSON__;

// ── Utilities ─────────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
function showToast(msg,icon='✅'){const t=document.getElementById('toast');t.textContent=(icon?icon+' ':'')+msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800);}

// ── Navigation ────────────────────────────────────────────────────────────────
function showPage(id, btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn) btn.classList.add('active');
  if(id==='findings')    setTimeout(renderFindingsTable,50);
  if(id==='roadmap')     renderRoadmap();
  if(id==='domains')     renderDomainGrid();
  if(id==='architecture') renderArchDomainList();
}

// ── Theme ─────────────────────────────────────────────────────────────────────
function setTheme(t){
  document.body.classList.toggle('light-theme',t==='light');
  document.getElementById('theme-dark').classList.toggle('active',t==='dark');
  document.getElementById('theme-light').classList.toggle('active',t==='light');
  localStorage.setItem('wi-theme',t);
}
(function(){const t=localStorage.getItem('wi-theme');if(t)setTheme(t);})();

// ── Overview ──────────────────────────────────────────────────────────────────
(function renderOverview(){
  const barContainer = document.getElementById('domainBars');
  DOMAINS.forEach(d=>{
    const pct = (d.maturityScore/5)*100;
    barContainer.innerHTML += `<div class="bar-row">
      <div class="bar-label" title="${escH(d.name)}">${escH(d.icon)} ${escH(d.name)}</div>
      <div class="bar-track"><div class="bar-fill" data-pct="${pct}" style="background:${escH(d.maturityColor)}"></div></div>
      <div class="bar-val">${d.maturityScore}</div>
    </div>`;
  });

  const rmContainer = document.getElementById('riskMatrix');
  DOMAINS.forEach(d=>{
    const total = d.critical+d.high+d.medium+d.low;
    rmContainer.innerHTML += `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:11px">
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
    grid.innerHTML += `<div class="domain-card" style="border-left-color:${escH(d.maturityColor)}" onclick="openDomainFindings('${escJ(d.id)}')">
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
let sortAsc = false;
let riskFilter = 'all';

const riskOrder = {Critical:0,High:1,Medium:2,Low:3,Info:4};

function filterFindings(){
  const q = (document.getElementById('findSearch').value||'').toLowerCase();
  filteredFindings = FINDINGS.filter(f=>{
    const matchRisk = riskFilter==='all' || f.risk===riskFilter;
    const matchQ = !q || (f.title+f.domainName+f.evidence+f.recommendation+f.migrationPath).toLowerCase().includes(q);
    return matchRisk && matchQ;
  });
  sortFindingsArr();
  findingsPage=0;
  renderFindingsTable();
}

function setRiskFilter(risk,el){
  riskFilter=risk;
  document.querySelectorAll('.fpill').forEach(p=>p.classList.remove('active'));
  el.classList.add('active');
  filterFindings();
}

function sortFindings(col){
  if(sortCol===col) sortAsc=!sortAsc; else{sortCol=col;sortAsc=true;}
  document.querySelectorAll('th').forEach(th=>th.classList.remove('sort-active'));
  event.currentTarget.classList.add('sort-active');
  sortFindingsArr();
  findingsPage=0;
  renderFindingsTable();
}

function sortFindingsArr(){
  filteredFindings.sort((a,b)=>{
    let av=a[sortCol]||'', bv=b[sortCol]||'';
    if(sortCol==='risk'){av=riskOrder[av]??9;bv=riskOrder[bv]??9;return sortAsc?av-bv:bv-av;}
    return sortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
}

function renderFindingsTable(){
  const tbody  = document.getElementById('findingsTbody');
  const pagDiv = document.getElementById('findingsPagination');
  const start  = findingsPage * PAGE_SIZE;
  const page   = filteredFindings.slice(start, start+PAGE_SIZE);

  tbody.innerHTML = page.map((f,i)=>{
    const idx = start+i;
    const migText = f.migrationPath ? `<span style="font-family:var(--mono);font-size:10px;color:var(--accent2)">${escH(f.migrationPath)}</span>` : '<span style="color:var(--muted)">—</span>';
    return `<tr style="cursor:pointer" onclick="openFinding(${idx})">
      <td><span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span></td>
      <td><span class="domain-tag">${escH(f.domainId)}</span></td>
      <td style="max-width:300px">${escH(f.title)}</td>
      <td><span class="phase-badge">${escH(f.roadmapPhase)}</span></td>
      <td style="max-width:200px">${migText}</td>
    </tr>`;
  }).join('');

  // Pagination
  const totalPages = Math.ceil(filteredFindings.length/PAGE_SIZE);
  let pag = `<span class="pg-info">${filteredFindings.length} finding${filteredFindings.length!==1?'s':''}</span>`;
  if(totalPages>1){
    if(findingsPage>0) pag+=`<button class="pg-btn" onclick="goPage(${findingsPage-1})">‹</button>`;
    for(let p=0;p<totalPages;p++){
      if(p===findingsPage||totalPages<=7||Math.abs(p-findingsPage)<=1||(p===0||p===totalPages-1)){
        pag+=`<button class="pg-btn${p===findingsPage?' active':''}" onclick="goPage(${p})">${p+1}</button>`;
      } else if(Math.abs(p-findingsPage)===2){pag+=`<span style="color:var(--muted)">…</span>`;}
    }
    if(findingsPage<totalPages-1) pag+=`<button class="pg-btn" onclick="goPage(${findingsPage+1})">›</button>`;
  }
  pagDiv.innerHTML = pag;
}

function goPage(p){findingsPage=p;renderFindingsTable();window.scrollTo(0,0);}

// ── Detail Drawer ─────────────────────────────────────────────────────────────
let drawerList = [];
let currentDrawerIndex = 0;

function openFinding(idx){
  drawerList = filteredFindings;
  currentDrawerIndex = idx;
  populateDrawer(drawerList[currentDrawerIndex]);
  document.getElementById('detailPanel').classList.add('open');
}

function populateDrawer(f){
  document.getElementById('drawerTitle').textContent = f.title;
  document.getElementById('drawerEvidence').textContent      = f.evidence;
  document.getElementById('drawerCurrentState').textContent  = f.currentState;
  document.getElementById('drawerGap').textContent           = f.gap;
  document.getElementById('drawerImpact').textContent        = f.businessImpact;
  document.getElementById('drawerTarget').textContent        = f.targetState;
  document.getElementById('drawerRec').textContent           = f.recommendation;
  document.getElementById('drawerMigration').textContent     = f.migrationPath || '—';
  document.getElementById('drawerPhase').textContent         = f.roadmapPhase;
  document.getElementById('drawerCount').textContent         = `${currentDrawerIndex+1} / ${drawerList.length}`;

  const chips = document.getElementById('drawerChips');
  chips.innerHTML =
    `<span class="risk-badge rb-${escH(f.risk)}">${escH(f.risk)}</span>` +
    `<span class="domain-tag">${escH(f.domainId)} · ${escH(f.domainName)}</span>` +
    `<span class="phase-badge">${escH(f.roadmapPhase)}</span>` +
    `<span style="font-size:10px;padding:2px 7px;border-radius:12px;background:rgba(57,197,207,.1);color:var(--accent2);font-family:var(--mono)">${escH(f.checkId)}</span>`;
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
    items.forEach(f=>{
      const idx=FINDINGS.indexOf(f);
      col.innerHTML+=`<div class="roadmap-item" onclick="openFinding(${idx})">
        <div class="roadmap-item-title">${escH(f.title)}</div>
        <div class="roadmap-item-meta">
          <span class="risk-badge rb-${escH(f.risk)}" style="font-size:9px">${escH(f.risk)}</span>
          <span class="domain-tag" style="font-size:9px">${escH(f.domainId)}</span>
        </div>
        ${f.migrationPath?`<div style="font-size:9px;color:var(--accent2);font-family:var(--mono);margin-top:5px;line-height:1.3">${escH(f.migrationPath)}</div>`:''}
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
      <div style="font-size:10px;color:var(--accent2);font-style:italic">Target: ${escH(d.targetStateSummary)}</div>
    </div>`;
  });
}

// ── CSV Export ────────────────────────────────────────────────────────────────
function exportFindingsCSV(){
  const fields=['domainId','domainName','checkId','title','risk','roadmapPhase','migrationPath','evidence','currentState','gap','businessImpact','targetState','recommendation'];
  const header=fields.join(',');
  const rows=filteredFindings.map(f=>fields.map(k=>'"'+(String(f[k]||'')).replace(/"/g,'""')+'"').join(','));
  const csv=[header,...rows].join('\r\n');
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download='WorkloadIdentityFindings.csv';
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

// ── Initial render ────────────────────────────────────────────────────────────
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
            -replace '__TOTAL_LOW__', ($totalLow + ($script:Findings | Where-Object { $_.Risk -eq "Info" }).Count) `
            -replace '__TOTAL_FINDINGS__', $totalFindings `
            -replace '__RING_COLOR__', $ringColor `
            -replace '__RING_DASH__', $ringDash `
            -replace '__RING_GAP__', $ringGap `
            -replace '__DOMAINS_JSON__', $DomainsJson `
            -replace '__FINDINGS_JSON__', $FindingsJson

        $html | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
    }

    #endregion

    #region ── Script Execution ───────────────────────────────────────────────────

    Clear-Host

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   Entra Workload Identity Architecture Assessment  v1.0      ║" -ForegroundColor Cyan
    Write-Host "  ║   Non-Human Identity Architecture Review                     ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $scriptStartTime = Get-Date
    Write-Host "  🕐 Started   : $($scriptStartTime.ToString('dd-MMM-yyyy  hh:mm:ss tt'))" -ForegroundColor Gray
    Write-Host "  📂 Output    : $OutputPath" -ForegroundColor Gray
    Write-Host "  🔑 Auth Mode : $($PSCmdlet.ParameterSetName)" -ForegroundColor Gray
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

    # ── Step 1.1: Validate permissions ───────────────────────────────────────
    Write-Host "  🔍 Validating required Microsoft Graph permissions..." -ForegroundColor Yellow

    $requiredPermissions = @(
        "Application.Read.All"
        "Directory.Read.All"
        "Policy.Read.All"
        "AuditLog.Read.All"
        "RoleManagement.Read.Directory"
    )

    $permCheck = Test-GraphTokenPermissions -AccessToken $global:accessToken -RequiredPermissions $requiredPermissions

    if (-not $permCheck.Valid) {
        Write-Host ""
        Write-Host "  ⚠️  Warning: Some required permissions are missing." -ForegroundColor Yellow
        foreach ($perm in $permCheck.MissingPermissions) {
            Write-Host "    • $perm" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  Assessment will continue with available permissions." -ForegroundColor Yellow
        Write-Host "  Some findings may be incomplete or unavailable." -ForegroundColor Yellow
    }
    else {
        Write-Host "  ✅ All required permissions validated." -ForegroundColor Green
    }

    Write-Host ""

    # ── Step 2: Tenant Baseline ───────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 2  ›  Collecting Tenant Baseline                     │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $orgData = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/organization?`$select=id,displayName,verifiedDomains,assignedPlans"
    $tenantName = "Unknown"
    if ($orgData -and $orgData.value -and $orgData.value.Count -gt 0) { $tenantName = $orgData.value[0].displayName }
    elseif ($orgData -and $orgData.displayName) { $tenantName = $orgData.displayName }

    Write-Host "  ✅ Tenant: $tenantName ($TenantId)" -ForegroundColor Green
    Write-Host ""

    # ── Step 3: Identity Inventory Collection ────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 3  ›  Collecting Workload Identity Inventory         │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $allSPs = $null
    $allMIs = $null
    $allApps = $null

    # ── Step 4: Domain Assessments ───────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 4  ›  Running Domain Assessments (6 Domains)         │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    Invoke-Domain1-IdentityInventory -SpRef ([ref]$allSPs) -MiRef ([ref]$allMIs) -AppRef ([ref]$allApps)

    Invoke-Domain2-CredentialPosture -AllApps $allApps -AllSPs $allSPs

    Invoke-Domain3-PermissionArchitecture -AllApps $allApps -AllSPs $allSPs

    Invoke-Domain4-LifecycleGovernance -AllApps $allApps -AllSPs $allSPs

    Invoke-Domain5-SecurityControls -AllSPs $allSPs

    Invoke-Domain6-AppArchitecture -AllApps $allApps -AllSPs $allSPs

    Write-Host ""
    Write-Host "  ✅ All 6 domain assessments complete." -ForegroundColor Green
    Write-Host ""

    # ── Step 5: Maturity Score ────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 5  ›  Computing Overall Maturity Score               │" -ForegroundColor DarkCyan
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

    # ── Step 6–7: Export ──────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 6-7 ›  Generating Reports                            │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $htmlPath = Join-Path $OutputPath "EntraWorkloadIdentityAssessment_$timestamp.html"
    $csvPath = Join-Path $OutputPath "EntraWorkloadIdentityAssessment_$timestamp.csv"
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

    Write-Host "  ⏳ Exporting CSV findings..." -ForegroundColor Yellow
    Export-FindingsCsv -OutputFilePath $csvPath
    Write-Host "  ✅ CSV findings written   → $csvPath" -ForegroundColor Green
    Write-Host ""

    # ── Execution Summary ─────────────────────────────────────────────────────
    $scriptEndTime = Get-Date
    $executionTime = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime

    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                 ASSESSMENT SUMMARY                           ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  🏛️  Tenant                 : $($tenantName.PadRight(29))║" -ForegroundColor White
    Write-Host "  ║  📊 Overall Maturity        : $("$overallMaturity / 5.0 ($overallLabel)".PadRight(29))║" -ForegroundColor Cyan
    Write-Host "  ║  🔴 Critical Findings       : $($totalCritical.ToString().PadRight(29))║" -ForegroundColor Red
    Write-Host "  ║  🟠 High Findings           : $($totalHigh.ToString().PadRight(29))║" -ForegroundColor Yellow
    Write-Host "  ║  🔵 Medium Findings         : $($totalMedium.ToString().PadRight(29))║" -ForegroundColor Blue
    Write-Host "  ║  📋 Total Findings          : $(($script:Findings.Count).ToString().PadRight(29))║" -ForegroundColor Gray
    Write-Host "  ║  🕐 Started                : $($scriptStartTime.ToString('hh:mm:ss tt').PadRight(29))║" -ForegroundColor Gray
    Write-Host "  ║  ⏱️  Duration               : $($executionTime.ToString('hh\:mm\:ss').PadRight(29))║" -ForegroundColor Yellow
    Write-Host "  ║  🌐 HTML Dashboard         : $(('...' + $htmlPath.Substring([Math]::Max(0,$htmlPath.Length-26))).PadRight(29))║" -ForegroundColor Green
    Write-Host "  ║  📄 CSV Findings           : $(('...' + $csvPath.Substring([Math]::Max(0,$csvPath.Length-26))).PadRight(29))║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    #endregion
}
