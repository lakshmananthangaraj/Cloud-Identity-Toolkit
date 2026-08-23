<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 23 August 2026
Modified-On  : 23 August 2026

.SYNOPSIS
    Defines enterprise identity standards as machine-readable policies, evaluates the Entra ID
    tenant against them, and produces a compliance-scored, gap-analysed Policy-as-Code report.

.DESCRIPTION
    This script implements a Policy-as-Code (PaC) engine for Entra ID. It encodes enterprise
    identity standards as structured, versioned policy definitions and evaluates the tenant's
    current configuration against each standard at runtime.

    The approach addresses a fundamental enterprise problem: identity controls are documented in
    Word files, enforced inconsistently, and never automatically verified. This script replaces
    that model with machine-readable policies that can be evaluated, versioned, and integrated
    into CI/CD pipelines or scheduled governance workflows.

    Policy Categories (8 domains):

        Policy Set 1  — Privileged Access Standards
        Policy Set 2  — Authentication & MFA Requirements
        Policy Set 3  — Conditional Access Baseline
        Policy Set 4  — Application Governance Standards
        Policy Set 5  — Workload Identity Standards
        Policy Set 6  — Guest & External Identity Standards
        Policy Set 7  — Data Access & High-Risk Permission Standards
        Policy Set 8  — Identity Lifecycle & Governance Standards

    Each policy follows the architectural thinking model:

        Context → Current State → Gap → Target State → Transition → Success Measure

    Compliance Outcomes per Policy:
        Compliant      : Standard is met. Evidence confirmed.
        NonCompliant   : Standard is not met. Gap identified. Remediation required.
        PartiallyCompliant : Standard partially met. Controls present but insufficient.
        Exempt         : Policy evaluation skipped (feature unavailable or out of scope).

    Overall Compliance Score:
        Each policy is weighted by risk tier (Critical / High / Medium / Low).
        Score = (weighted compliant points) / (total possible weighted points) × 100.

    Output:
        - HTML interactive Policy Compliance Dashboard (light/dark theme, tabbed by policy set)
        - JSON policy evaluation export (machine-readable, CI/CD integrable)

.PARAMETER TenantId
    The Directory (tenant) ID of the Entra ID tenant to evaluate.

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
    Directory where the HTML dashboard and JSON export will be written.
    Default: C:\Temp\EntraIdentityPolicyAsCode

.PARAMETER ShowHelp
    Displays a plain-language usage guide and exits immediately.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        HTML dashboard: <OutputPath>\EntraIdentityPolicyAsCode_<timestamp>.html
        JSON export   : <OutputPath>\EntraIdentityPolicyAsCode_<timestamp>.json

.EXAMPLE
    Get-EntraIdentityPolicyAsCode -ShowHelp

    Displays the friendly usage guide and exits.

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraIdentityPolicyAsCode `
        -AuthMode ClientCredentials `
        -ClientId  "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId "f4310b4f-xxxx"

    Full policy evaluation using app-only Client Credentials auth.

.EXAMPLE
    $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    Get-EntraIdentityPolicyAsCode `
        -AuthMode BYOT `
        -AccessToken $token `
        -TenantId "f4310b4f-xxxx"

    Full policy evaluation using a pre-obtained bearer token (BYOT).

.EXAMPLE
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraIdentityPolicyAsCode `
        -AuthMode ClientCredentials `
        -ClientId  "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId "f4310b4f-xxxx" `
        -OutputPath "D:\Reports\PolicyAsCode"

    Policy evaluation with a custom output directory.

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
               Directory.Read.All                (tenant info, roles, groups, devices)
               Policy.Read.All                   (Conditional Access, auth methods policy)
               Application.Read.All              (app registrations, service principals)
               AuditLog.Read.All                 (sign-in activity, audit logs)
               RoleManagement.Read.Directory     (PIM, role definitions, assignments)
               IdentityRiskyUser.Read.All        (Identity Protection risk state)
               UserAuthenticationMethod.Read.All (MFA registration coverage)
               Reports.Read.All                  (usage/activity reports)
               AccessReview.Read.All             (access reviews)
               EntitlementManagement.Read.All    (access packages, catalogs)

        2. BYOT mode: the delegated or application token must carry the same
           scopes as above. Delegated tokens require the caller to be a
           Global Reader or Security Reader.

        3. Entra ID P1 minimum. P2 required for:
               - PIM eligible role evaluation
               - Identity Protection risk policy checks
               - Access Review compliance checks
               - Entitlement Management policy checks

        4. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  → Show help and exit if -ShowHelp
        Step 1  → Authenticate (BYOT or Client Credentials)
        Step 2  → Collect tenant baseline (org, licenses, domains)
        Step 3  → Define policy catalog (8 policy sets, ~30 policies)
        Step 4  → Evaluate each policy against live tenant data
        Step 5  → Compute weighted compliance score per policy set and overall
        Step 6  → Build prioritised violation list with remediation guidance
        Step 7  → Export HTML dashboard + JSON

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the /beta Graph endpoint. Beta APIs are subject to change.
        - PIM, Access Reviews, and Entitlement Management data require Entra ID P2.
          Policy evaluations for these features degrade to Exempt when P2 is absent.
        - Conditional Access policy evaluation is configuration-based; it does not
          simulate runtime policy evaluation against real sign-in sessions.
        - Workload identity federation detection is limited to what is exposed via
          Graph API — federation configurations in Azure AD B2C are out of scope.
        - Large tenants (>50 000 users) may experience longer run times due to
          Graph pagination.

.LINK
    https://learn.microsoft.com/en-us/entra/architecture/
.LINK
    https://learn.microsoft.com/en-us/security/zero-trust/
.LINK
    https://learn.microsoft.com/en-us/graph/api/overview
.LINK
    https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview

#>


Function Get-EntraIdentityPolicyAsCode {
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
        [string]$OutputPath = "C:\Temp\EntraIdentityPolicyAsCode",

        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    #region ── Friendly Help ──────────────────────────────────────────────────────

    Function Show-FriendlyHelp {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║    Entra ID Identity Policy as Code Evaluator  v1.0          ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  PURPOSE" -ForegroundColor Yellow
        Write-Host "    Defines enterprise identity standards as machine-readable policies"
        Write-Host "    and evaluates your Entra ID tenant against them. Produces a"
        Write-Host "    compliance-scored report across 8 policy sets (~30 policies)."
        Write-Host ""
        Write-Host "  WHY POLICY AS CODE?" -ForegroundColor Yellow
        Write-Host "    Traditional identity standards live in Word documents and are never"
        Write-Host "    automatically verified. This script encodes those standards as"
        Write-Host "    versioned, machine-readable policy definitions — evaluated at runtime"
        Write-Host "    against live tenant configuration."
        Write-Host ""
        Write-Host "  AUTHENTICATION" -ForegroundColor Yellow
        Write-Host "    Client Credentials (app-only):"
        Write-Host '      $secret = Read-Host "Client secret" -AsSecureString'
        Write-Host '      Get-EntraIdentityPolicyAsCode \'
        Write-Host '          -AuthMode ClientCredentials \'
        Write-Host '          -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "    BYOT (Bring Your Own Token):"
        Write-Host '      $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken'
        Write-Host '      Get-EntraIdentityPolicyAsCode \'
        Write-Host '          -AuthMode BYOT -AccessToken $token -TenantId "<tenant-id>"'
        Write-Host ""
        Write-Host "  REQUIRED APP PERMISSIONS (Application, admin-consented)" -ForegroundColor Yellow
        Write-Host "    Directory.Read.All, Policy.Read.All, Application.Read.All,"
        Write-Host "    AuditLog.Read.All, RoleManagement.Read.Directory,"
        Write-Host "    IdentityRiskyUser.Read.All, UserAuthenticationMethod.Read.All,"
        Write-Host "    Reports.Read.All, AccessReview.Read.All, EntitlementManagement.Read.All"
        Write-Host ""
        Write-Host "  LICENSE REQUIREMENTS" -ForegroundColor Yellow
        Write-Host "    P1 minimum. P2 required for PIM, Access Reviews, and Entitlement Management."
        Write-Host ""
        Write-Host "  For full documentation: Get-Help Get-EntraIdentityPolicyAsCode -Full"
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
                return @{ Valid = $false; MissingPermissions = $RequiredPermissions }
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

            $missingPermissions = @($RequiredPermissions | Where-Object { $_ -notin $tokenPermissions })

            return @{
                Valid              = ($missingPermissions.Count -eq 0)
                MissingPermissions = $missingPermissions
            }
        }
        Catch {
            return @{ Valid = $false; MissingPermissions = $RequiredPermissions }
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

    #region ── Policy Engine ─────────────────────────────────────────────────────

    # Compliance outcomes
    $script:COMPLIANT = "Compliant"
    $script:NON_COMPLIANT = "NonCompliant"
    $script:PARTIAL = "PartiallyCompliant"
    $script:EXEMPT = "Exempt"

    # Risk weights for scoring
    $script:RiskWeights = @{
        "Critical" = 4
        "High"     = 3
        "Medium"   = 2
        "Low"      = 1
    }

    $script:ComplianceColors = @{
        "Compliant"          = "#3fb950"   # green
        "NonCompliant"       = "#f85149"   # red
        "PartiallyCompliant" = "#d29922"   # amber
        "Exempt"             = "#7d8590"   # muted
    }

    $script:RiskColors = @{
        "Critical" = "#f85149"
        "High"     = "#d29922"
        "Medium"   = "#388bfd"
        "Low"      = "#3fb950"
    }

    # Global stores
    $script:PolicySets = [System.Collections.ArrayList]::new()
    $script:Policies = [System.Collections.ArrayList]::new()
    $script:Violations = [System.Collections.ArrayList]::new()


    Function Add-PolicyResult {
        <#
        .SYNOPSIS
            Records the evaluation result of a single policy into the global policy list.
        #>
        param (
            [string]$PolicySetId,
            [string]$PolicySetName,
            [string]$PolicyId,
            [string]$PolicyName,
            [string]$PolicyStatement,           # The enterprise standard being enforced
            [string]$Context,                   # Why this standard matters to the business
            [string]$Evidence,                  # Raw data from Graph
            [string]$CurrentState,              # What is true about the tenant today
            [string]$Gap,                       # Delta from standard (or "None — standard is met")
            [ValidateSet("Compliant", "NonCompliant", "PartiallyCompliant", "Exempt")]
            [string]$Outcome,
            [ValidateSet("Critical", "High", "Medium", "Low")]
            [string]$RiskTier,
            [string]$BusinessRisk,              # Business/security consequence if non-compliant
            [string]$TargetState,               # What "good" looks like
            [string]$TransitionGuidance,        # How to get from current to target without disruption
            [string]$SuccessMeasure,            # How compliance will be measured over time
            [ValidateSet("Immediate", "0-30 Days", "31-60 Days", "61-90 Days", "Strategic")]
            [string]$RemediationPhase
        )

        $null = $script:Policies.Add([PSCustomObject]@{
                PolicySetId        = $PolicySetId
                PolicySetName      = $PolicySetName
                PolicyId           = $PolicyId
                PolicyName         = $PolicyName
                PolicyStatement    = $PolicyStatement
                Context            = $Context
                Evidence           = $Evidence
                CurrentState       = $CurrentState
                Gap                = $Gap
                Outcome            = $Outcome
                RiskTier           = $RiskTier
                BusinessRisk       = $BusinessRisk
                TargetState        = $TargetState
                TransitionGuidance = $TransitionGuidance
                SuccessMeasure     = $SuccessMeasure
                RemediationPhase   = $RemediationPhase
                OutcomeColor       = $script:ComplianceColors[$Outcome]
                RiskColor          = $script:RiskColors[$RiskTier]
            })

        # If non-compliant or partial, record as a violation for the violations tab
        if ($Outcome -in @($script:NON_COMPLIANT, $script:PARTIAL)) {
            $null = $script:Violations.Add([PSCustomObject]@{
                    PolicySetId        = $PolicySetId
                    PolicySetName      = $PolicySetName
                    PolicyId           = $PolicyId
                    PolicyName         = $PolicyName
                    Outcome            = $Outcome
                    RiskTier           = $RiskTier
                    Gap                = $Gap
                    BusinessRisk       = $BusinessRisk
                    TransitionGuidance = $TransitionGuidance
                    RemediationPhase   = $RemediationPhase
                    OutcomeColor       = $script:ComplianceColors[$Outcome]
                    RiskColor          = $script:RiskColors[$RiskTier]
                })
        }
    }


    Function Set-PolicySetResult {
        param (
            [string]$Id,
            [string]$Name,
            [string]$Icon,
            [string]$Description,
            [int]$CompliantCount,
            [int]$NonCompliantCount,
            [int]$PartialCount,
            [int]$ExemptCount,
            [double]$ComplianceScore    # 0–100
        )

        $null = $script:PolicySets.Add([PSCustomObject]@{
                Id                = $Id
                Name              = $Name
                Icon              = $Icon
                Description       = $Description
                CompliantCount    = $CompliantCount
                NonCompliantCount = $NonCompliantCount
                PartialCount      = $PartialCount
                ExemptCount       = $ExemptCount
                ComplianceScore   = $ComplianceScore
            })
    }


    Function Get-PolicySetScore {
        <#
        .SYNOPSIS
            Computes the weighted compliance score for policies belonging to a given policy set.
        #>
        param ([string]$PolicySetId)

        $setPolicies = $script:Policies | Where-Object { $_.PolicySetId -eq $PolicySetId -and $_.Outcome -ne $script:EXEMPT }
        if (-not $setPolicies -or @($setPolicies).Count -eq 0) { return 0 }

        $totalWeight = 0
        $earnedWeight = 0

        foreach ($p in $setPolicies) {
            $w = $script:RiskWeights[$p.RiskTier]
            $totalWeight += $w
            if ($p.Outcome -eq $script:COMPLIANT) { $earnedWeight += $w }
            elseif ($p.Outcome -eq $script:PARTIAL) { $earnedWeight += [Math]::Round($w * 0.5, 0) }
        }

        if ($totalWeight -eq 0) { return 100 }
        return [Math]::Round(($earnedWeight / $totalWeight) * 100, 0)
    }


    Function Get-OverallComplianceScore {
        $evaluatedPolicies = $script:Policies | Where-Object { $_.Outcome -ne $script:EXEMPT }
        if (-not $evaluatedPolicies -or @($evaluatedPolicies).Count -eq 0) { return 0 }

        $totalWeight = 0
        $earnedWeight = 0

        foreach ($p in $evaluatedPolicies) {
            $w = $script:RiskWeights[$p.RiskTier]
            $totalWeight += $w
            if ($p.Outcome -eq $script:COMPLIANT) { $earnedWeight += $w }
            elseif ($p.Outcome -eq $script:PARTIAL) { $earnedWeight += [Math]::Round($w * 0.5, 0) }
        }

        if ($totalWeight -eq 0) { return 100 }
        return [Math]::Round(($earnedWeight / $totalWeight) * 100, 0)
    }

    #endregion

    #region ── Policy Set 1: Privileged Access Standards ─────────────────────────

    Function Invoke-PolicySet1-PrivilegedAccess {
        Write-Host "  👑 PS1: Privileged Access Standards..." -ForegroundColor Cyan

        $compliant = 0; $nonCompliant = 0; $partial = 0; $exempt = 0

        # ── Policy 1.1: Global Admin count must be ≤ 5 ───────────────────────────
        # Context: Global Admin is the highest-privilege role in Entra ID. Excess GA accounts
        # dramatically increase the blast radius of any credential compromise.
        $gaRole = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/directoryRoles?`$filter=displayName eq 'Global Administrator'"
        $gaCount = 0
        if ($gaRole -and $gaRole.value -and $gaRole.value.Count -gt 0) {
            $gaMembers = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/directoryRoles/$($gaRole.value[0].id)/members"
            $gaCount = $gaMembers.Count
        }

        if ($gaCount -le 5 -and $gaCount -ge 2) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS1" -PolicySetName "Privileged Access" `
                -PolicyId "PS1.1" -PolicyName "Global Admin Count Within Bounds" `
                -PolicyStatement "The tenant must have between 2 and 5 active Global Administrators." `
                -Context "Excess Global Admin accounts exponentially increase blast radius. 2 minimum ensures break-glass redundancy; 5 maximum limits standing exposure." `
                -Evidence "Active Global Administrators: $gaCount" `
                -CurrentState "$gaCount Global Admin account(s) — within the enterprise policy threshold of 2–5." `
                -Gap "None — standard is met." `
                -Outcome $script:COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "N/A — policy is satisfied." `
                -TargetState "2–4 active Global Admins. Named, documented, and break-glass access only." `
                -TransitionGuidance "Maintain periodic review of GA list. Any addition must go through change management." `
                -SuccessMeasure "Monthly audit of Global Admin count. Alert on any addition via PIM audit log." `
                -RemediationPhase "Strategic"
        }
        elseif ($gaCount -gt 5) {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS1" -PolicySetName "Privileged Access" `
                -PolicyId "PS1.1" -PolicyName "Global Admin Count Exceeds Policy Threshold" `
                -PolicyStatement "The tenant must have between 2 and 5 active Global Administrators." `
                -Context "Excess Global Admin accounts exponentially increase blast radius. 2 minimum ensures break-glass redundancy; 5 maximum limits standing exposure." `
                -Evidence "Active Global Administrators: $gaCount (policy threshold: ≤ 5)" `
                -CurrentState "$gaCount Global Admin accounts are permanently assigned. $($gaCount - 4) account(s) exceed the enterprise maximum of 4 active GAs." `
                -Gap "Excess GA accounts expand the attack surface. Each additional GA account is a potential tenant takeover vector if compromised without MFA." `
                -Outcome $script:NON_COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "Tenant takeover risk is multiplicative with GA count. Identity-related breaches in Microsoft's DART incident data show excess GA accounts as the #1 pre-condition for full tenant compromise." `
                -TargetState "Maximum 4 active Global Admins. All others converted to PIM-eligible JIT assignments or replaced with scoped admin roles." `
                -TransitionGuidance "1) Audit each GA: identify functional vs redundant accounts. 2) Convert excess GAs to PIM eligible. 3) Replace standing GAs with scoped roles (e.g. Security Admin, Exchange Admin) where full GA is not required. 4) Target completion in 30 days." `
                -SuccessMeasure "GA count ≤ 4. Confirmed in monthly governance report. PIM alert active for any new GA assignment." `
                -RemediationPhase "Immediate"
        }
        else {
            # gaCount < 2
            $partial++
            Add-PolicyResult -PolicySetId "PS1" -PolicySetName "Privileged Access" `
                -PolicyId "PS1.1" -PolicyName "Insufficient Global Admin Accounts (Break-Glass Risk)" `
                -PolicyStatement "The tenant must have between 2 and 5 active Global Administrators." `
                -Context "Excess Global Admin accounts exponentially increase blast radius. 2 minimum ensures break-glass redundancy; 5 maximum limits standing exposure." `
                -Evidence "Active Global Administrators: $gaCount (policy minimum: 2 for redundancy)" `
                -CurrentState "$gaCount Global Admin account(s) active. Fewer than the minimum 2 required for break-glass redundancy." `
                -Gap "Single GA is a single point of failure. If the account is locked out or compromised, tenant recovery may require Microsoft support engagement." `
                -Outcome $script:PARTIAL -RiskTier "Critical" `
                -BusinessRisk "A single-GA tenant risks complete administrative lockout if the account is lost, compromised, or disabled — even by MFA reset or conditional access policy change." `
                -TargetState "2 dedicated break-glass Global Admin accounts — cloud-only, with FIDO2 hardware keys, no MFA dependencies, monitored for any sign-in." `
                -TransitionGuidance "Create a second cloud-only GA break-glass account. Assign a hardware FIDO2 key. Store credentials in a secure vault. Configure sign-in alert for any usage." `
                -SuccessMeasure "2 break-glass GA accounts confirmed. Sign-in alerts active. Credentials rotation documented." `
                -RemediationPhase "Immediate"
        }

        # ── Policy 1.2: Privileged users must have phishing-resistant MFA ─────────
        $activeAssignmentsUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?`$filter=directoryScopeId eq '/'&`$select=principalId,roleDefinitionId&`$top=100"
        $activeAssignments = Get-GraphPagedResults -Uri $activeAssignmentsUri
        $privilegedPrincipalIds = @($activeAssignments | Select-Object -ExpandProperty principalId -Unique)

        $mfaUri = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails?`$top=500"
        $mfaData = Get-GraphPagedResults -Uri $mfaUri

        $mfaLookup = @{}
        foreach ($m in $mfaData) { $mfaLookup[$m.id] = $m }

        $privNoMfa = @($privilegedPrincipalIds | Where-Object {
                $reg = $mfaLookup[$_]
                (-not $reg) -or ($reg.isMfaRegistered -ne $true)
            })
        $privNoMfaPct = if ($privilegedPrincipalIds.Count -gt 0) { [Math]::Round(($privNoMfa.Count / $privilegedPrincipalIds.Count) * 100, 0) } else { 0 }

        if ($privNoMfa.Count -eq 0) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS1" -PolicySetName "Privileged Access" `
                -PolicyId "PS1.2" -PolicyName "All Privileged Users Have MFA Registered" `
                -PolicyStatement "All users with active directory role assignments must have MFA registered. Global Admins and Tier 0 roles must use phishing-resistant MFA (FIDO2 or CBA)." `
                -Context "MFA blocks >99.9% of automated account compromise attacks. For privileged roles, phishing-resistant MFA eliminates the AiTM (Adversary-in-the-Middle) bypass vector that defeats SMS and app-based MFA." `
                -Evidence "Privileged principals: $($privilegedPrincipalIds.Count) | Without MFA: 0 (0%)" `
                -CurrentState "All detected role holders have MFA registered. Standard is met for MFA coverage." `
                -Gap "Verify MFA method strength — SMS and voice are not phishing-resistant and do not satisfy the full standard for Tier 0 roles." `
                -Outcome $script:COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "N/A — coverage standard is met. Validate method strength separately." `
                -TargetState "100% MFA coverage. Phishing-resistant MFA (FIDO2/WHfB/CBA) enforced for all Tier 0 roles via CA Authentication Strength policy." `
                -TransitionGuidance "Evaluate current MFA methods for GA accounts. Create an Authentication Strength policy requiring FIDO2 or CBA. Apply to all privileged role CA policy." `
                -SuccessMeasure "Zero privileged accounts without MFA in monthly report. Authentication Strength policy active for GA CA." `
                -RemediationPhase "Strategic"
        }
        else {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS1" -PolicySetName "Privileged Access" `
                -PolicyId "PS1.2" -PolicyName "Privileged Users Without MFA — $($privNoMfa.Count) Account(s) ($privNoMfaPct%)" `
                -PolicyStatement "All users with active directory role assignments must have MFA registered. Global Admins and Tier 0 roles must use phishing-resistant MFA (FIDO2 or CBA)." `
                -Context "MFA blocks >99.9% of automated account compromise attacks. For privileged roles, phishing-resistant MFA eliminates the AiTM bypass vector that defeats SMS and app-based MFA." `
                -Evidence "Privileged principals: $($privilegedPrincipalIds.Count) | Without MFA: $($privNoMfa.Count) ($privNoMfaPct%)" `
                -CurrentState "$($privNoMfa.Count) account(s) with active directory role assignments have no MFA method registered. Password-only access to admin capabilities is possible." `
                -Gap "Privileged accounts reachable via password-only auth. Direct violation of Zero Trust and CISA MFA guidance for privileged access." `
                -Outcome $script:NON_COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "Any compromised admin credential without MFA enables immediate, unrestricted privileged access. Credential stuffing and password spray attacks are automated — a single exposed password is sufficient for tenant-level compromise." `
                -TargetState "100% MFA for all privileged identities. Phishing-resistant MFA (FIDO2 or CBA) for all Tier 0 roles. Enforced via Conditional Access — registration alone is not enforcement." `
                -TransitionGuidance "1) Use Temporary Access Pass (TAP) to onboard MFA for accounts without it. 2) Create CA policy requiring MFA for all directory roles. 3) Target FIDO2 or WHfB for GA accounts in 30 days. 4) Do not block access until TAP is in hand to avoid lockout." `
                -SuccessMeasure "Zero admin accounts without MFA. CA policy active and in Report-Only mode for 7 days before enforcement. MFA coverage tracked weekly during remediation." `
                -RemediationPhase "Immediate"
        }

        # ── Policy 1.3: PIM JIT must be adopted for privileged roles ──────────────
        $eligibleUri = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances?`$select=principalId,roleDefinitionId"
        $eligibleAssignments = Get-GraphPagedResults -Uri $eligibleUri
        $eligibleCount = $eligibleAssignments.Count
        $activePrivCount = $activeAssignments.Count
        $pimAdoptionPct = if (($activePrivCount + $eligibleCount) -gt 0) { [Math]::Round(($eligibleCount / ($activePrivCount + $eligibleCount)) * 100, 0) } else { 0 }

        if ($eligibleCount -eq 0 -and $activePrivCount -gt 0) {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS1" -PolicySetName "Privileged Access" `
                -PolicyId "PS1.3" -PolicyName "PIM JIT Not Adopted — All Privileges Are Permanent" `
                -PolicyStatement "A minimum of 80% of privileged role assignments must be PIM-eligible (JIT). Permanent standing access must be limited to ≤ 4 break-glass accounts." `
                -Context "Permanent privileged access means admin capabilities are available 24/7, including weekends, holidays, and nights — precisely when adversaries operate. JIT eliminates this standing exposure by time-boxing activation." `
                -Evidence "Active permanent assignments: $activePrivCount | PIM-eligible JIT assignments: $eligibleCount (0%)" `
                -CurrentState "Zero JIT adoption. All $activePrivCount privileged role assignments are permanent standing access. PIM has not been deployed." `
                -Gap "100% of privileged access is permanent — directly violates Zero Trust time-of-access principle. Compromised admin accounts can be exploited at any time without time constraint." `
                -Outcome $script:NON_COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "Permanent privileged access is the most significant identity risk in Entra ID. Industry data shows lateral movement with admin credentials typically occurs outside business hours — permanent access removes all time-based controls." `
                -TargetState "≥80% PIM-eligible assignments. Activation policy: max 4-hour window, MFA on activation, justification required, approval for Global Admin. Only break-glass accounts retain permanent GA." `
                -TransitionGuidance "1) Enable Entra ID PIM (requires P2). 2) Audit all permanent assignments. 3) Convert GA to PIM-eligible with approval workflow first. 4) Roll out to Security Admin, Exchange Admin, and other privileged roles in sequence. 5) Retain 2 permanent break-glass GA accounts during transition." `
                -SuccessMeasure "PIM JIT adoption ≥80%. Monthly PIM access review scheduled. GA activation alerts active in SIEM. Time-to-activate SLA defined and measured." `
                -RemediationPhase "0-30 Days"
        }
        elseif ($pimAdoptionPct -lt 80) {
            $partial++
            Add-PolicyResult -PolicySetId "PS1" -PolicySetName "Privileged Access" `
                -PolicyId "PS1.3" -PolicyName "PIM Partially Adopted — $pimAdoptionPct% JIT Coverage" `
                -PolicyStatement "A minimum of 80% of privileged role assignments must be PIM-eligible (JIT). Permanent standing access must be limited to ≤ 4 break-glass accounts." `
                -Context "Permanent privileged access means admin capabilities are available 24/7. JIT time-boxes activation windows, limits blast radius, and creates an audit trail for every privileged action." `
                -Evidence "Permanent assignments: $activePrivCount | PIM-eligible: $eligibleCount ($pimAdoptionPct%)" `
                -CurrentState "PIM is in use but only $pimAdoptionPct% of assignments are JIT-eligible. $($100 - $pimAdoptionPct)% of privileged assignments remain as permanent standing access." `
                -Gap "Sub-policy JIT coverage. $($activePrivCount - $eligibleCount) permanent assignments remain — these accounts carry full admin access at all times." `
                -Outcome $script:PARTIAL -RiskTier "Critical" `
                -BusinessRisk "Remaining permanent assignments extend the attack window and dilute the value of the PIM investment. Any single compromised permanent admin account retains full privilege 24/7." `
                -TargetState "≥90% PIM-eligible. Non-break-glass permanent assignments: 0. Activation policy applied consistently across all roles." `
                -TransitionGuidance "1) Identify remaining permanent role holders. 2) Prioritise conversion of high-privilege roles (GA, Privileged Role Admin, Security Admin). 3) Define activation SLA to reduce friction for operations teams. 4) Use PIM Insights to identify low-activation accounts for entitlement removal." `
                -SuccessMeasure "PIM adoption ≥90% within 60 days. Permanent assignments reduced to break-glass only. Monthly PIM access review completion rate ≥95%." `
                -RemediationPhase "0-30 Days"
        }
        else {
            $compliant++
            Add-PolicyResult -PolicySetId "PS1" -PolicySetName "Privileged Access" `
                -PolicyId "PS1.3" -PolicyName "PIM JIT Adopted — $pimAdoptionPct% JIT Coverage" `
                -PolicyStatement "A minimum of 80% of privileged role assignments must be PIM-eligible (JIT). Permanent standing access must be limited to ≤ 4 break-glass accounts." `
                -Context "Permanent privileged access means admin capabilities are available 24/7. JIT time-boxes activation windows and creates a full audit trail." `
                -Evidence "Permanent assignments: $activePrivCount | PIM-eligible: $eligibleCount ($pimAdoptionPct%)" `
                -CurrentState "PIM JIT adoption is at $pimAdoptionPct% — above the 80% policy threshold. Standing access is substantially reduced." `
                -Gap "Verify activation policies are tight (max 4h, approval for GA, justification required). Schedule quarterly PIM access reviews." `
                -Outcome $script:COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "N/A — JIT adoption meets policy. Focus shifts to activation policy tightening and review quality." `
                -TargetState "100% JIT for non-break-glass accounts. Activation policy: 4h max, justification required, GA requires approval." `
                -TransitionGuidance "Audit activation policies across all roles. Enable PIM alert rules for suspicious elevation patterns. Schedule quarterly PIM access reviews." `
                -SuccessMeasure "PIM activation policy audit completed. Quarterly access review cadence established. PIM alerts routed to SIEM." `
                -RemediationPhase "Strategic"
        }

        # ── Compute PS1 score and register ────────────────────────────────────────
        $ps1Score = Get-PolicySetScore -PolicySetId "PS1"
        Set-PolicySetResult -Id "PS1" -Name "Privileged Access Standards" -Icon "👑" `
            -Description "Defines the minimum security standards for all privileged role holders including GA count limits, MFA requirements, and PIM JIT adoption targets." `
            -CompliantCount $compliant -NonCompliantCount $nonCompliant `
            -PartialCount $partial -ExemptCount $exempt `
            -ComplianceScore $ps1Score
    }

    #endregion

    #region ── Policy Set 2: Authentication & MFA Requirements ────────────────────

    Function Invoke-PolicySet2-Authentication {
        Write-Host "  🔐 PS2: Authentication & MFA Requirements..." -ForegroundColor Cyan

        $compliant = 0; $nonCompliant = 0; $partial = 0; $exempt = 0

        # ── Policy 2.1: Overall MFA registration must be ≥ 95% ───────────────────
        $mfaUri = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails?`$top=500"
        $mfaData = Get-GraphPagedResults -Uri $mfaUri
        $totalUsers = $mfaData.Count
        $mfaRegistered = @($mfaData | Where-Object { $_.isMfaRegistered -eq $true })
        $mfaRegPct = if ($totalUsers -gt 0) { [Math]::Round(($mfaRegistered.Count / $totalUsers) * 100, 0) } else { 0 }

        if ($mfaRegPct -ge 95) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS2" -PolicySetName "Authentication & MFA" `
                -PolicyId "PS2.1" -PolicyName "MFA Registration Coverage Meets Policy Threshold (≥95%)" `
                -PolicyStatement "Enterprise standard: ≥95% of all licensed users must have MFA registered." `
                -Context "MFA registration is the baseline pre-requisite for all other authentication controls. Users without registered MFA cannot be protected by Conditional Access MFA enforcement policies." `
                -Evidence "Licensed users evaluated: $totalUsers | MFA registered: $($mfaRegistered.Count) ($mfaRegPct%)" `
                -CurrentState "$mfaRegPct% of users have MFA registered — above the 95% policy threshold." `
                -Gap "Residual $($totalUsers - $mfaRegistered.Count) user(s) without MFA should be targeted via Temporary Access Pass and a nudge CA policy." `
                -Outcome $script:COMPLIANT -RiskTier "High" `
                -BusinessRisk "N/A — threshold met. Track the residual unregistered population." `
                -TargetState "100% MFA registration. Enforced via CA policy. Temporary Access Pass process defined for new hires." `
                -TransitionGuidance "Use MFA Registration Campaign in Entra ID to nudge remaining users. Use TAP for accounts that cannot self-register." `
                -SuccessMeasure "MFA registration rate tracked weekly. Target 100% within 90 days for residual population." `
                -RemediationPhase "Strategic"
        }
        elseif ($mfaRegPct -ge 80) {
            $partial++
            Add-PolicyResult -PolicySetId "PS2" -PolicySetName "Authentication & MFA" `
                -PolicyId "PS2.1" -PolicyName "MFA Registration Below Policy Threshold ($mfaRegPct% — Standard: ≥95%)" `
                -PolicyStatement "Enterprise standard: ≥95% of all licensed users must have MFA registered." `
                -Context "MFA registration is the baseline pre-requisite for all other authentication controls. Users without registered MFA cannot be protected by Conditional Access MFA enforcement policies." `
                -Evidence "Licensed users evaluated: $totalUsers | MFA registered: $($mfaRegistered.Count) ($mfaRegPct%)" `
                -CurrentState "$mfaRegPct% of users have MFA registered. $($totalUsers - $mfaRegistered.Count) user(s) remain unregistered and cannot benefit from MFA enforcement policies." `
                -Gap "$($100 - $mfaRegPct)% below the 95% enterprise standard. Unregistered users are a gap in the authentication perimeter." `
                -Outcome $script:PARTIAL -RiskTier "High" `
                -BusinessRisk "Unregistered users fall through MFA enforcement gaps. They become the soft underbelly of the authentication perimeter — targeted by credential stuffing and phishing campaigns." `
                -TargetState "≥95% MFA registration. Enforced registration campaign active. MFA required for all sign-ins via CA policy within 90 days." `
                -TransitionGuidance "Launch MFA Registration Campaign (Entra ID > Authentication Methods). Use Temporary Access Pass (TAP) for accounts that cannot self-register. Identify and segment remaining users by role/risk for targeted outreach." `
                -SuccessMeasure "MFA registration ≥95% tracked weekly. TAP issuance volume reported. CA policy in Report-Only mode for 14 days before enforcement." `
                -RemediationPhase "0-30 Days"
        }
        else {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS2" -PolicySetName "Authentication & MFA" `
                -PolicyId "PS2.1" -PolicyName "Critical MFA Registration Gap ($mfaRegPct% — Standard: ≥95%)" `
                -PolicyStatement "Enterprise standard: ≥95% of all licensed users must have MFA registered." `
                -Context "MFA registration is the baseline pre-requisite for all other authentication controls. Without it, CA enforcement is impossible and every unregistered account is a potential compromise vector." `
                -Evidence "Licensed users evaluated: $totalUsers | MFA registered: $($mfaRegistered.Count) ($mfaRegPct%)" `
                -CurrentState "Only $mfaRegPct% of users have MFA registered. $($totalUsers - $mfaRegistered.Count) user(s) have password-only access." `
                -Gap "$($100 - $mfaRegPct)% gap — far below the 95% enterprise standard. The authentication perimeter has significant unprotected exposure." `
                -Outcome $script:NON_COMPLIANT -RiskTier "High" `
                -BusinessRisk "Low MFA registration rates are the primary enabler of large-scale phishing and credential compromise campaigns. Organisations below 80% MFA registration are disproportionately represented in breach statistics." `
                -TargetState "≥95% MFA registration. Enforced by CA. No user should be able to complete sign-in without MFA or a registered TAP." `
                -TransitionGuidance "1) Launch MFA Registration Campaign immediately. 2) Block sign-ins for users in non-critical roles who have not registered after 14 days. 3) Issue TAPs to service accounts and non-interactive users. 4) Engage help desk to support registration." `
                -SuccessMeasure "MFA registration rate reported weekly with trend. Target ≥80% in 30 days, ≥95% in 60 days." `
                -RemediationPhase "Immediate"
        }

        # ── Policy 2.2: Legacy authentication must be blocked ─────────────────────
        $caUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $caPolicies = Get-GraphPagedResults -Uri $caUri
        $enabledPolicies = @($caPolicies | Where-Object { $_.state -eq "enabled" })

        $legacyAuthBlock = @($enabledPolicies | Where-Object {
                $_.conditions.clientAppTypes -contains "exchangeActiveSync" -or
                $_.conditions.clientAppTypes -contains "other" -or
                (
                    $_.conditions.PSObject.Properties["clientAppTypes"] -and
                    (@($_.conditions.clientAppTypes) | Where-Object { $_ -in @("exchangeActiveSync", "other") }).Count -gt 0
                )
            })

        if ($legacyAuthBlock.Count -gt 0) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS2" -PolicySetName "Authentication & MFA" `
                -PolicyId "PS2.2" -PolicyName "Legacy Authentication Blocked via Conditional Access" `
                -PolicyStatement "All legacy authentication protocols (Basic Auth, NTLM via EAS, ROPC) must be blocked for all users via Conditional Access." `
                -Context "Legacy auth protocols cannot perform MFA. They are the primary bypass vector for CA policies — any tenant with legacy auth enabled is vulnerable regardless of how many CA policies are in place." `
                -Evidence "CA policies blocking legacy auth/EAS: $($legacyAuthBlock.Count) policy(ies) found" `
                -CurrentState "Legacy authentication appears to be blocked by Conditional Access policy. Standard is met." `
                -Gap "Verify the blocking policy covers all users and all legacy client app types (exchangeActiveSync AND other). Confirm it is not scoped to a subset of users." `
                -Outcome $script:COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "N/A — standard met. Verify coverage completeness." `
                -TargetState "Global legacy auth block: all users, all client app types. No exceptions. Exemptions only via support case with documented business justification." `
                -TransitionGuidance "Audit the blocking policy scope. Ensure it applies to All Users with no exclusions except break-glass accounts. Review Sign-in logs for any legacy auth attempts post-block." `
                -SuccessMeasure "Zero legacy auth sign-ins in Sign-In logs. Policy applies to 100% of users. Legacy auth attempts tracked in workbook." `
                -RemediationPhase "Strategic"
        }
        else {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS2" -PolicySetName "Authentication & MFA" `
                -PolicyId "PS2.2" -PolicyName "Legacy Authentication Not Blocked — Policy Violation" `
                -PolicyStatement "All legacy authentication protocols (Basic Auth, NTLM via EAS, ROPC) must be blocked for all users via Conditional Access." `
                -Context "Legacy auth protocols cannot perform MFA. They bypass every CA policy. Any tenant with unblocked legacy auth has a permanent gap in its MFA enforcement regardless of other controls." `
                -Evidence "CA policies blocking legacy auth (EAS/Other client types): 0 found in $($enabledPolicies.Count) enabled policy(ies)" `
                -CurrentState "No Conditional Access policy explicitly blocks legacy authentication protocols. Legacy auth is accessible to all users." `
                -Gap "Critical gap: legacy auth bypass is open. Every enabled CA policy can be bypassed by any legacy auth client." `
                -Outcome $script:NON_COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "Microsoft telemetry shows >99% of password spray attacks use legacy auth protocols. An open legacy auth endpoint makes all MFA investments irrelevant — adversaries route around CA by using legacy clients." `
                -TargetState "A single, global CA policy blocking legacy auth for All Users with client app types: Exchange ActiveSync and Other. No user exclusions except break-glass." `
                -TransitionGuidance "1) Check Sign-In logs for legacy auth usage (filter: Client App = Legacy Auth) — identify who is using it. 2) Communicate cutover date to affected users/teams. 3) Create CA policy in Report-Only for 14 days. 4) Enable policy. Monitor and address exceptions." `
                -SuccessMeasure "Zero legacy auth sign-ins in Sign-In log. Policy active and covering all users. Quarterly review of legacy auth attempts." `
                -RemediationPhase "Immediate"
        }

        # ── Policy 2.3: Security Defaults or CA — not both, not neither ────────────
        $secDefaults = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy"
        $secDefaultsEnabled = ($secDefaults -and $secDefaults.isEnabled -eq $true)
        $totalCaPolicies = $caPolicies.Count

        if ($secDefaultsEnabled -and $totalCaPolicies -gt 0) {
            $partial++
            Add-PolicyResult -PolicySetId "PS2" -PolicySetName "Authentication & MFA" `
                -PolicyId "PS2.3" -PolicyName "Security Defaults Enabled Alongside Conditional Access — Conflict" `
                -PolicyStatement "Security Defaults and Conditional Access are mutually exclusive governance models. Tenants with CA policies must disable Security Defaults and manage authentication policy exclusively through CA." `
                -Context "Security Defaults is a baseline for tenants without P1/P2. Enabling it alongside CA creates unpredictable policy precedence and may block legitimate access scenarios that CA is designed to handle explicitly." `
                -Evidence "Security Defaults: Enabled | Conditional Access policies found: $totalCaPolicies" `
                -CurrentState "Both Security Defaults and Conditional Access policies are active. This configuration is unsupported and creates policy conflicts." `
                -Gap "Dual-mode operation. CA policies cannot override Security Defaults behaviours. Authentication control is split between two systems." `
                -Outcome $script:PARTIAL -RiskTier "Medium" `
                -BusinessRisk "Unexpected sign-in blocks for service accounts, automation, and guest users. Unpredictable MFA prompts. Reduced operational confidence in policy outcomes." `
                -TargetState "Security Defaults disabled. All identity protection policies managed exclusively through Conditional Access (P1/P2 required)." `
                -TransitionGuidance "1) Validate all CA policies cover the scenarios Security Defaults previously handled (MFA for admins, block legacy auth, MFA for Azure management). 2) Disable Security Defaults after CA policies are validated in Report-Only. 3) Never re-enable Security Defaults once CA is adopted." `
                -SuccessMeasure "Security Defaults = Disabled. CA baseline policy set covers all users. No policy conflicts reported." `
                -RemediationPhase "0-30 Days"
        }
        elseif (-not $secDefaultsEnabled -and $totalCaPolicies -eq 0) {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS2" -PolicySetName "Authentication & MFA" `
                -PolicyId "PS2.3" -PolicyName "No Authentication Governance — Neither Security Defaults Nor Conditional Access Active" `
                -PolicyStatement "All tenants must have an active authentication governance model — either Security Defaults (basic) or Conditional Access (enterprise). No authentication policy is a critical gap." `
                -Context "Without Security Defaults or Conditional Access, there is no baseline authentication enforcement. Every user can sign in from any location, any device, with any client, at any time." `
                -Evidence "Security Defaults: Disabled | Conditional Access policies: 0" `
                -CurrentState "No authentication policy is active. The tenant has no baseline protection against password spray, credential stuffing, or anonymous access." `
                -Gap "Critical — zero authentication governance. All accounts accessible via password-only from any location and any device." `
                -Outcome $script:NON_COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "Highest possible risk exposure. No controls preventing automated credential attacks. This configuration is responsible for the majority of Entra ID account compromises in incident response engagements." `
                -TargetState "Minimum: Security Defaults enabled (immediate). Target: Conditional Access baseline (within 30 days with P1 licensing)." `
                -TransitionGuidance "Immediate: enable Security Defaults. Parallel: procure Entra ID P1 and design CA baseline policies (MFA for all, legacy auth block, MFA for Azure management). Transition to CA within 30 days." `
                -SuccessMeasure "Security Defaults or CA active. MFA enforced for all users. Legacy auth blocked. Sign-In log shows <1% unauthenticated access." `
                -RemediationPhase "Immediate"
        }
        else {
            $compliant++
            Add-PolicyResult -PolicySetId "PS2" -PolicySetName "Authentication & MFA" `
                -PolicyId "PS2.3" -PolicyName "Authentication Governance Model Correctly Configured" `
                -PolicyStatement "All tenants must have an active authentication governance model — either Security Defaults (basic) or Conditional Access (enterprise). Both simultaneously is unsupported." `
                -Context "Clear, single-model governance is essential for predictable authentication policy outcomes and operational confidence." `
                -Evidence "Security Defaults: $(if($secDefaultsEnabled){'Enabled'}else{'Disabled'}) | CA policies: $totalCaPolicies" `
                -CurrentState "$(if($secDefaultsEnabled){'Security Defaults is active as the authentication governance model.'}else{"Conditional Access is the active governance model with $totalCaPolicies policy(ies)."})" `
                -Gap "None — governance model is consistently configured." `
                -Outcome $script:COMPLIANT -RiskTier "Medium" `
                -BusinessRisk "N/A — authentication governance model is correctly configured." `
                -TargetState "Conditional Access (P1/P2) as the single governance model. CA baseline covering all users, all apps, all locations." `
                -TransitionGuidance "If on Security Defaults, plan migration to CA as licensing allows. CA provides granular controls not available in Security Defaults." `
                -SuccessMeasure "Single governance model active. No policy conflicts. CA coverage tracked per user population and app." `
                -RemediationPhase "Strategic"
        }

        $ps2Score = Get-PolicySetScore -PolicySetId "PS2"
        Set-PolicySetResult -Id "PS2" -Name "Authentication & MFA Requirements" -Icon "🔐" `
            -Description "Defines minimum MFA registration coverage, legacy auth blocking requirements, and the authoritative authentication governance model for the tenant." `
            -CompliantCount $compliant -NonCompliantCount $nonCompliant `
            -PartialCount $partial -ExemptCount $exempt `
            -ComplianceScore $ps2Score
    }

    #endregion

    #region ── Policy Set 3: Conditional Access Baseline ─────────────────────────

    Function Invoke-PolicySet3-ConditionalAccess {
        Write-Host "  🛡️ PS3: Conditional Access Baseline Standards..." -ForegroundColor Cyan

        $compliant = 0; $nonCompliant = 0; $partial = 0; $exempt = 0

        $caUri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $caPolicies = Get-GraphPagedResults -Uri $caUri
        $enabledPolicies = @($caPolicies | Where-Object { $_.state -eq "enabled" })
        $reportOnlyPolicies = @($caPolicies | Where-Object { $_.state -eq "enabledForReportingButNotEnforcing" })
        $disabledPolicies = @($caPolicies | Where-Object { $_.state -eq "disabled" })

        # ── Policy 3.1: CA coverage — MFA required for all users ─────────────────
        $mfaForAllPolicy = @($enabledPolicies | Where-Object {
                $grantControls = $_.grantControls
                $hasAllUsers = $_.conditions.users.includeUsers -contains "All" -or
                $_.conditions.users.includeGroups -contains "All"
                $hasMfa = $grantControls -and (
                    $grantControls.builtInControls -contains "mfa" -or
                    $grantControls.authenticationStrength -ne $null
                )
                $hasAllUsers -and $hasMfa
            })

        if ($mfaForAllPolicy.Count -gt 0) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS3" -PolicySetName "Conditional Access Baseline" `
                -PolicyId "PS3.1" -PolicyName "MFA Required for All Users via Conditional Access" `
                -PolicyStatement "A Conditional Access policy must require MFA for all users, all cloud apps, with no user exclusions except break-glass emergency accounts." `
                -Context "MFA as a CA grant control is the single most effective identity security control available. Unlike Security Defaults, CA-enforced MFA can be scoped, monitored, and made adaptive." `
                -Evidence "Enabled CA policies requiring MFA for all users: $($mfaForAllPolicy.Count)" `
                -CurrentState "A CA policy requiring MFA for all users is active. Standard met." `
                -Gap "Verify exclusions are minimal (break-glass only). Verify the policy targets All Cloud Apps." `
                -Outcome $script:COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "N/A — standard met. Validate exclusion scope." `
                -TargetState "All users, all apps, all locations require MFA. Authentication Strength upgraded to phishing-resistant MFA for Tier 0 over time." `
                -TransitionGuidance "Audit exclusion groups in the MFA policy. Ensure no service accounts, automation accounts, or broad user groups are excluded without compensating controls." `
                -SuccessMeasure "MFA enforcement rate tracked in Sign-In workbook. Exclusion group membership reviewed monthly." `
                -RemediationPhase "Strategic"
        }
        else {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS3" -PolicySetName "Conditional Access Baseline" `
                -PolicyId "PS3.1" -PolicyName "No All-User MFA CA Policy — Critical Baseline Gap" `
                -PolicyStatement "A Conditional Access policy must require MFA for all users, all cloud apps, with no user exclusions except break-glass emergency accounts." `
                -Context "MFA as a CA grant control is the single most effective identity security control available. Without a blanket MFA CA policy, users can authenticate from any location with just a password." `
                -Evidence "Enabled CA policies requiring MFA for all users: 0 (Report-Only policies found: $($reportOnlyPolicies.Count))" `
                -CurrentState "No enabled CA policy enforces MFA for all users. $(if($reportOnlyPolicies.Count -gt 0){"$($reportOnlyPolicies.Count) policy(ies) are in Report-Only mode — not enforced."})" `
                -Gap "No baseline MFA enforcement. Users can authenticate with passwords only from any location, any device." `
                -Outcome $script:NON_COMPLIANT -RiskTier "Critical" `
                -BusinessRisk "The absence of a blanket MFA CA policy is the most common finding in post-breach identity reviews. It removes the primary defence against credential theft, phishing, and password spray attacks." `
                -TargetState "One enabled CA policy: All Users, All Cloud Apps, grant = Require MFA. Exclusions: break-glass accounts only. No location, device, or network exclusions for the base policy." `
                -TransitionGuidance "1) Create CA policy in Report-Only: All Users, All Cloud Apps, Require MFA. 2) Review Report-Only insights for 14 days — identify service accounts, automation, and legacy clients that will be impacted. 3) Remediate impacted systems. 4) Enable policy. 5) Monitor for 72 hours post-enable." `
                -SuccessMeasure "CA MFA policy active for all users. MFA satisfaction rate ≥95% in Sign-In logs. <1% of sign-ins use single-factor auth." `
                -RemediationPhase "0-30 Days"
        }

        # ── Policy 3.2: High-risk sign-in must require MFA or be blocked ──────────
        $riskSignInPolicy = @($enabledPolicies | Where-Object {
                $_.conditions.signInRiskLevels -contains "high" -or
                $_.conditions.signInRiskLevels -contains "medium"
            })

        if ($riskSignInPolicy.Count -gt 0) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS3" -PolicySetName "Conditional Access Baseline" `
                -PolicyId "PS3.2" -PolicyName "Sign-In Risk Policy Active (Identity Protection Integration)" `
                -PolicyStatement "A Conditional Access policy must respond to high-risk sign-in events with MFA challenge or block. Medium-risk should require password change or MFA." `
                -Context "Identity Protection detects anomalous sign-in signals (impossible travel, anonymised IP, malware-linked IPs). Without a risk-based CA policy, these detections generate alerts but no enforcement action." `
                -Evidence "Enabled CA policies targeting sign-in risk (medium or high): $($riskSignInPolicy.Count)" `
                -CurrentState "Sign-in risk policies are active. High or medium-risk sign-in events trigger enforcement action." `
                -Gap "Verify the policy blocks or challenges (not just notifies) on high-risk events. Confirm it covers all users — not just a subset." `
                -Outcome $script:COMPLIANT -RiskTier "High" `
                -BusinessRisk "N/A — risk integration is active." `
                -TargetState "High-risk sign-in = Block. Medium-risk = Require MFA + password change. All users covered. Integrated with SIEM alerting." `
                -TransitionGuidance "Audit risk policy grant controls — ensure high-risk is blocked, not just challenged. Review risk event volume in Identity Protection dashboard." `
                -SuccessMeasure "Risk-based CA policy coverage confirmed for all users. High-risk sign-in block rate tracked monthly." `
                -RemediationPhase "Strategic"
        }
        else {
            $exempt++
            Add-PolicyResult -PolicySetId "PS3" -PolicySetName "Conditional Access Baseline" `
                -PolicyId "PS3.2" -PolicyName "Sign-In Risk Policy Not Detected (P2 Feature — May Be Unlicensed)" `
                -PolicyStatement "A Conditional Access policy must respond to high-risk sign-in events with MFA challenge or block. Medium-risk should require password change or MFA." `
                -Context "Identity Protection risk policies require Entra ID P2. Without P2, risk-based CA conditions are not available — the tenant cannot respond automatically to detected anomalous sign-in events." `
                -Evidence "Enabled CA policies with sign-in risk conditions: 0 (policy may require Entra ID P2)" `
                -CurrentState "No sign-in risk CA policy is active. This may indicate Entra ID P2 is not licensed, or the policy has not been configured." `
                -Gap "Without risk-based CA, Identity Protection detections (impossible travel, anonymised IPs, etc.) generate no enforcement action — alerts only." `
                -Outcome $script:EXEMPT -RiskTier "High" `
                -BusinessRisk "Risk-based CA is a Tier 1 control for detecting and responding to active account compromise in real time. Without it, compromised accounts may remain active until manual review." `
                -TargetState "Entra ID P2 licensed. Sign-in risk policy: High = Block, Medium = Require MFA. User risk policy: High = Block + force password reset." `
                -TransitionGuidance "1) Confirm P2 licensing. 2) Enable Identity Protection. 3) Create sign-in risk CA policy (start with Report-Only for 14 days). 4) Create user risk CA policy. 5) Integrate with SIEM for risk event alerting." `
                -SuccessMeasure "P2 licensed. Risk policies active and covering all users. Risk event volume and remediation rate tracked monthly." `
                -RemediationPhase "31-60 Days"
        }

        # ── Policy 3.3: Compliant/hybrid-joined device required for admin access ──
        $adminDevicePolicy = @($enabledPolicies | Where-Object {
                $grantControls = $_.grantControls
                $hasManagedDevice = $grantControls -and (
                    $grantControls.builtInControls -contains "compliantDevice" -or
                    $grantControls.builtInControls -contains "domainJoinedDevice"
                )
                $targetsAdmins = $_.conditions.users.includeRoles -and $_.conditions.users.includeRoles.Count -gt 0
                $hasManagedDevice -and $targetsAdmins
            })

        if ($adminDevicePolicy.Count -gt 0) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS3" -PolicySetName "Conditional Access Baseline" `
                -PolicyId "PS3.3" -PolicyName "Managed/Compliant Device Required for Administrative Access" `
                -PolicyStatement "Access to administrative portals and privileged operations must require a compliant or Hybrid Azure AD Joined device." `
                -Context "Admin access from unmanaged personal devices bypasses all endpoint security controls. A managed device requirement ensures admins operate from controlled, monitored, and hardened endpoints." `
                -Evidence "Enabled CA policies requiring managed device for admin roles: $($adminDevicePolicy.Count)" `
                -CurrentState "At least one CA policy requires a managed or compliant device for administrative role holders." `
                -Gap "Verify the policy covers all admin roles, not just a subset. Verify it includes Azure portal and PowerShell/Graph access." `
                -Outcome $script:COMPLIANT -RiskTier "High" `
                -BusinessRisk "N/A — device compliance requirement is active for admins." `
                -TargetState "All admin portals (Entra, Azure, M365 Admin, Exchange, Security) require compliant or HAADJ device. No browser exceptions for admin access." `
                -TransitionGuidance "Audit which admin roles and which applications are covered by the device policy. Extend coverage to any gaps identified." `
                -SuccessMeasure "Admin sign-in compliance rate (device-compliant ratio) tracked monthly. Non-compliant device blocks reported." `
                -RemediationPhase "Strategic"
        }
        else {
            $partial++
            Add-PolicyResult -PolicySetId "PS3" -PolicySetName "Conditional Access Baseline" `
                -PolicyId "PS3.3" -PolicyName "No Managed Device Requirement for Administrative Access" `
                -PolicyStatement "Access to administrative portals and privileged operations must require a compliant or Hybrid Azure AD Joined device." `
                -Context "Admin access from unmanaged personal devices bypasses all endpoint security controls. Without this control, an admin can log into Azure portal from an unmanaged personal device, hotel kiosk, or compromised machine." `
                -Evidence "Enabled CA policies requiring managed device for admin roles: 0" `
                -CurrentState "No CA policy enforces managed/compliant device for administrative role holders. Admins can authenticate from any device including unmanaged personal devices." `
                -Gap "Unmanaged device access is permitted for admin operations. Malware on a personal device can harvest admin session tokens without triggering any security control." `
                -Outcome $script:PARTIAL -RiskTier "High" `
                -BusinessRisk "Admin token theft from unmanaged devices is a primary lateral movement vector. PASS-THE-COOKIE and token replay attacks are undetectable without endpoint management context." `
                -TargetState "CA policy: admin roles require compliant device (Intune-enrolled) or Hybrid AADJ. No unmanaged device access to admin portals. PAW (Privileged Access Workstation) model for Tier 0." `
                -TransitionGuidance "1) Define admin device compliance policy in Intune. 2) Enroll all admin workstations. 3) Create CA policy (Report-Only first): Admin roles, All Cloud Apps, grant = compliant device or HAADJ. 4) Enable after 14-day Report-Only validation." `
                -SuccessMeasure "100% of admin role sign-ins from compliant or HAADJ devices. Non-compliant device access blocks tracked. PAW adoption tracked by role tier." `
                -RemediationPhase "31-60 Days"
        }

        $ps3Score = Get-PolicySetScore -PolicySetId "PS3"
        Set-PolicySetResult -Id "PS3" -Name "Conditional Access Baseline" -Icon "🛡️" `
            -Description "Defines the minimum Conditional Access policy baseline including MFA enforcement, risk-based access controls, and device compliance requirements for privileged access." `
            -CompliantCount $compliant -NonCompliantCount $nonCompliant `
            -PartialCount $partial -ExemptCount $exempt `
            -ComplianceScore $ps3Score
    }

    #endregion

    #region ── Policy Set 4: Application Governance Standards ─────────────────────

    Function Invoke-PolicySet4-AppGovernance {
        Write-Host "  📱 PS4: Application Governance Standards..." -ForegroundColor Cyan

        $compliant = 0; $nonCompliant = 0; $partial = 0; $exempt = 0

        # ── Policy 4.1: Critical applications must have two owners ────────────────
        $apps = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/applications?`$select=id,displayName,createdDateTime,owners&`$top=100"

        $appsWithInsufficientOwners = New-Object System.Collections.ArrayList
        $appsWithOwners = New-Object System.Collections.ArrayList
        $appsTotal = @($apps).Count

        foreach ($app in $apps) {
            Try {
                $owners = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/applications/$($app.id)/owners"
                $ownerCount = $owners.Count

                if ($ownerCount -lt 2) {
                    $null = $appsWithInsufficientOwners.Add([PSCustomObject]@{ Name = $app.displayName; Owners = $ownerCount })
                }
                else {
                    $null = $appsWithOwners.Add($app)
                }
            }
            Catch {
                Write-Verbose "Could not retrieve owners for app: $($app.displayName)"
            }
        }

        $insufficientOwnerPct = if ($appsTotal -gt 0) { [Math]::Round(($appsWithInsufficientOwners.Count / $appsTotal) * 100, 0) } else { 0 }

        if ($insufficientOwnerPct -le 10) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS4" -PolicySetName "Application Governance" `
                -PolicyId "PS4.1" -PolicyName "Application Ownership Coverage Meets Standard" `
                -PolicyStatement "Every app registration must have a minimum of two designated owners. Applications with zero owners represent unmanaged, orphaned assets." `
                -Context "App registration owners are responsible for secret rotation, permission reviews, and decommissioning. An app with a single owner becomes orphaned when that person leaves. Apps with zero owners are ungoverned attack surface." `
                -Evidence "Total app registrations evaluated: $appsTotal | Insufficient owners (<2): $($appsWithInsufficientOwners.Count) ($insufficientOwnerPct%)" `
                -CurrentState "$($100 - $insufficientOwnerPct)% of app registrations have ≥2 owners. Standard is substantially met." `
                -Gap "Residual $($appsWithInsufficientOwners.Count) app(s) with <2 owners should be assigned a secondary owner or reviewed for decommissioning." `
                -Outcome $script:COMPLIANT -RiskTier "Medium" `
                -BusinessRisk "N/A — standard met. Address residual apps with insufficient owners." `
                -TargetState "100% of app registrations have ≥2 named owners. Owner list validated in annual app governance review." `
                -TransitionGuidance "Assign secondary owners to remaining gap apps. Integrate owner assignment into the app registration request process." `
                -SuccessMeasure "Owner coverage tracked in monthly app governance report. Zero-owner apps = zero. Annual app ownership attestation cycle." `
                -RemediationPhase "Strategic"
        }
        else {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS4" -PolicySetName "Application Governance" `
                -PolicyId "PS4.1" -PolicyName "Application Ownership Gap — $insufficientOwnerPct% of Apps Have <2 Owners" `
                -PolicyStatement "Every app registration must have a minimum of two designated owners. Applications with zero owners represent unmanaged, orphaned assets." `
                -Context "App registration owners are accountable for secret rotation, permission reviews, and decommissioning. Apps without owners become permanently ungoverned — no one knows what they do, who uses them, or whether they should still exist." `
                -Evidence "Total apps: $appsTotal | Apps with <2 owners: $($appsWithInsufficientOwners.Count) ($insufficientOwnerPct%)" `
                -CurrentState "$($appsWithInsufficientOwners.Count) app registration(s) ($insufficientOwnerPct%) have fewer than the required 2 owners. These apps are at risk of becoming permanently orphaned." `
                -Gap "$insufficientOwnerPct% below the enterprise standard of ≥2 owners per app. Orphaned apps accumulate dangerous permissions over time without anyone accountable." `
                -Outcome $script:NON_COMPLIANT -RiskTier "Medium" `
                -BusinessRisk "Orphaned app registrations with high-privilege Graph permissions (e.g., Mail.ReadWrite, Files.ReadWrite.All) have been exploited in documented supply chain and insider threat scenarios when the owning team departed." `
                -TargetState "100% of active app registrations: ≥2 named owners. Quarterly app ownership review. Apps with no sign-in activity in 90 days reviewed for decommissioning." `
                -TransitionGuidance "1) Export all app registrations with owner count from Entra ID. 2) Identify business owners via manager chain or app name pattern. 3) Assign minimum 2 owners per app. 4) For apps with no identifiable owner, escalate for decommissioning review." `
                -SuccessMeasure "Zero-owner apps = 0. Owner coverage ≥95% tracked in monthly app governance report. App ownership attestation cycle defined." `
                -RemediationPhase "31-60 Days"
        }

        # ── Policy 4.2: App secrets must not be expired or near-expiry ───────────
        $today = Get-Date
        $warningDate = $today.AddDays(30)
        $allAppsForSecrets = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/applications?`$select=id,displayName,passwordCredentials,keyCredentials&`$top=100"

        $expiredSecrets = New-Object System.Collections.ArrayList
        $nearExpirySecrets = New-Object System.Collections.ArrayList

        foreach ($app in $allAppsForSecrets) {
            foreach ($cred in $app.passwordCredentials) {
                if ($cred.endDateTime) {
                    $expiry = [datetime]$cred.endDateTime
                    if ($expiry -lt $today) {
                        $null = $expiredSecrets.Add([PSCustomObject]@{ App = $app.displayName; Expiry = $expiry.ToString("dd-MMM-yyyy") })
                    }
                    elseif ($expiry -lt $warningDate) {
                        $null = $nearExpirySecrets.Add([PSCustomObject]@{ App = $app.displayName; Expiry = $expiry.ToString("dd-MMM-yyyy") })
                    }
                }
            }
            foreach ($cred in $app.keyCredentials) {
                if ($cred.endDateTime) {
                    $expiry = [datetime]$cred.endDateTime
                    if ($expiry -lt $today) {
                        $null = $expiredSecrets.Add([PSCustomObject]@{ App = $app.displayName; Expiry = $expiry.ToString("dd-MMM-yyyy") })
                    }
                    elseif ($expiry -lt $warningDate) {
                        $null = $nearExpirySecrets.Add([PSCustomObject]@{ App = $app.displayName; Expiry = $expiry.ToString("dd-MMM-yyyy") })
                    }
                }
            }
        }

        if ($expiredSecrets.Count -eq 0 -and $nearExpirySecrets.Count -eq 0) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS4" -PolicySetName "Application Governance" `
                -PolicyId "PS4.2" -PolicyName "No Expired or Near-Expiry App Credentials Detected" `
                -PolicyStatement "App registration secrets and certificates must not be expired. Secrets expiring within 30 days must be flagged for immediate renewal." `
                -Context "Expired app credentials cause service outages. Unrotated long-lived secrets are a security risk — the longer a secret lives, the higher the probability it has been exposed in a code repository, log, or config file." `
                -Evidence "Expired credentials: $($expiredSecrets.Count) | Near-expiry (<30 days): $($nearExpirySecrets.Count)" `
                -CurrentState "No expired or near-expiry app secrets or certificates detected across evaluated app registrations." `
                -Gap "Maintain proactive rotation cadence. Consider migrating to Managed Identity or Federated Identity Credentials to eliminate secrets entirely." `
                -Outcome $script:COMPLIANT -RiskTier "High" `
                -BusinessRisk "N/A — no expired credentials detected." `
                -TargetState "Zero expired credentials. Automated rotation or Managed Identity adoption. Secret lifetime ≤12 months for all remaining secrets." `
                -TransitionGuidance "Configure app secret expiry alerts in Entra ID. Target Managed Identity or Federated Identity Credentials for all workloads that support it." `
                -SuccessMeasure "Monthly expired credential scan with zero tolerance. Secret rotation SLA defined. Managed Identity adoption rate tracked." `
                -RemediationPhase "Strategic"
        }
        elseif ($expiredSecrets.Count -gt 0) {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS4" -PolicySetName "Application Governance" `
                -PolicyId "PS4.2" -PolicyName "Expired App Credentials Detected — $($expiredSecrets.Count) Secret(s)/Certificate(s) Expired" `
                -PolicyStatement "App registration secrets and certificates must not be expired. Expired credentials indicate broken rotation processes and potential service disruption." `
                -Context "Expired credentials signal a broken secret management process. Apps with expired secrets either have outage risk (if actively used) or are abandoned apps with credentials that were never rotated — both are governance failures." `
                -Evidence "Expired credentials: $($expiredSecrets.Count) | Near-expiry (<30 days): $($nearExpirySecrets.Count) | Sample expired apps: $(($expiredSecrets | Select-Object -First 3 | ForEach-Object { $_.App }) -join ', ')" `
                -CurrentState "$($expiredSecrets.Count) app credential(s) have expired. Either affected apps are broken (outage) or the credentials were never used (orphaned app)." `
                -Gap "Expired credentials violate the secret management standard. Root cause: missing rotation process and no expiry alert integration." `
                -Outcome $script:NON_COMPLIANT -RiskTier "High" `
                -BusinessRisk "Expired secrets in active apps cause authentication failures and service outages. In orphaned apps, expired secrets indicate the app itself is ungoverned — its permissions remain active even when the authentication mechanism is broken." `
                -TargetState "Zero expired credentials. Automated expiry alerts with 60/30/7-day warning thresholds. Rotation process documented for each app." `
                -TransitionGuidance "1) For each expired credential: determine if app is in use. 2) Renew credentials for active apps. 3) Initiate decommissioning review for unused apps. 4) Configure Entra ID Workbooks or a custom alert for approaching expiry. 5) Migrate to Managed Identity where possible." `
                -SuccessMeasure "Zero expired credentials in monthly scan. Secret rotation SLA ≤12 months. Managed Identity adoption tracked quarterly." `
                -RemediationPhase "0-30 Days"
        }
        else {
            $partial++
            Add-PolicyResult -PolicySetId "PS4" -PolicySetName "Application Governance" `
                -PolicyId "PS4.2" -PolicyName "App Credentials Near Expiry — $($nearExpirySecrets.Count) Secret(s) Expiring Within 30 Days" `
                -PolicyStatement "App registration secrets and certificates must not be expired. Secrets expiring within 30 days must be flagged for immediate renewal." `
                -Context "Near-expiry credentials require immediate action to prevent service outages. The 30-day warning threshold allows time for coordinated rotation without emergency change processes." `
                -Evidence "Expired credentials: 0 | Near-expiry (<30 days): $($nearExpirySecrets.Count) | Sample apps: $(($nearExpirySecrets | Select-Object -First 3 | ForEach-Object { $_.App }) -join ', ')" `
                -CurrentState "$($nearExpirySecrets.Count) app credential(s) expire within 30 days. Renewal is urgently required to prevent service disruption." `
                -Gap "Rotation process not triggered early enough. Credentials are within the critical rotation window." `
                -Outcome $script:PARTIAL -RiskTier "High" `
                -BusinessRisk "Credentials expiring within 30 days without active rotation planning will cause service outages and emergency change tickets — disrupting business operations and consuming unplanned IT capacity." `
                -TargetState "Rotation completed ≥30 days before expiry. Automated alerts at 60, 30, and 7 days before expiry. Managed Identity adoption tracked." `
                -TransitionGuidance "Prioritise renewal of the listed expiring credentials. Contact app owners immediately. Run rotation using App Registration > Certificates & Secrets > New Secret." `
                -SuccessMeasure "All near-expiry credentials renewed within 14 days. Expiry alerts active. Rotation completed >30 days before expiry in future cycles." `
                -RemediationPhase "0-30 Days"
        }

        $ps4Score = Get-PolicySetScore -PolicySetId "PS4"
        Set-PolicySetResult -Id "PS4" -Name "Application Governance Standards" -Icon "📱" `
            -Description "Defines minimum ownership, credential management, and lifecycle standards for app registrations to prevent orphaned apps and secret sprawl." `
            -CompliantCount $compliant -NonCompliantCount $nonCompliant `
            -PartialCount $partial -ExemptCount $exempt `
            -ComplianceScore $ps4Score
    }

    #endregion

    #region ── Policy Set 5: Workload Identity Standards ─────────────────────────

    Function Invoke-PolicySet5-WorkloadIdentities {
        Write-Host "  ⚙️ PS5: Workload Identity Standards..." -ForegroundColor Cyan

        $compliant = 0; $nonCompliant = 0; $partial = 0; $exempt = 0

        # ── Policy 5.1: Prefer Managed Identity over client secrets for Azure workloads
        $spWithSecretsUri = "https://graph.microsoft.com/beta/servicePrincipals?`$filter=servicePrincipalType eq 'Application'&`$select=id,displayName,passwordCredentials,keyCredentials&`$top=100"
        $servicePrincipals = Get-GraphPagedResults -Uri $spWithSecretsUri

        $spWithSecrets = @($servicePrincipals | Where-Object {
                $_.passwordCredentials -and $_.passwordCredentials.Count -gt 0
            })
        $totalSPs = @($servicePrincipals).Count
        $secretSpPct = if ($totalSPs -gt 0) { [Math]::Round(($spWithSecrets.Count / $totalSPs) * 100, 0) } else { 0 }

        $miUri = "https://graph.microsoft.com/beta/servicePrincipals?`$filter=servicePrincipalType eq 'ManagedIdentity'&`$select=id,displayName&`$top=1&`$count=true"
        $miResponse = Invoke-GraphRequest -Uri $miUri
        $miCount = if ($miResponse -and $miResponse.'@odata.count') { $miResponse.'@odata.count' } elseif ($miResponse -and $miResponse.value) { $miResponse.value.Count } else { 0 }

        if ($secretSpPct -le 30 -and $miCount -gt 0) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS5" -PolicySetName "Workload Identity Standards" `
                -PolicyId "PS5.1" -PolicyName "Low Secret Usage — Managed Identities Adopted" `
                -PolicyStatement "Azure workloads must prefer Managed Identity over client secrets/certificates. Target: <30% of service principals using secrets. Managed Identity adoption must be measurable and growing." `
                -Context "Client secrets are credentials — they can be stolen, committed to code repositories, or included in logs. Managed Identities eliminate this entire credential class by using Azure-managed, hardware-bound identity with automatic rotation." `
                -Evidence "Service Principals with client secrets: $($spWithSecrets.Count) ($secretSpPct%) | Managed Identities detected: $miCount" `
                -CurrentState "Only $secretSpPct% of evaluated service principals use client secrets. Managed Identity adoption is measurable at $miCount identity(ies)." `
                -Gap "Continue reducing secret-based workload identities. Target 0% for all Azure-hosted workloads." `
                -Outcome $script:COMPLIANT -RiskTier "High" `
                -BusinessRisk "N/A — standard substantially met. Maintain adoption momentum." `
                -TargetState "0% Azure-hosted workloads using secrets. 100% Managed Identity for Azure resources. Federated Identity Credentials for external workloads (GitHub Actions, Terraform Cloud)." `
                -TransitionGuidance "Identify remaining secret-based service principals. For each: assess if the workload runs in Azure (Managed Identity candidate) or external (Federated Identity Credential candidate). Plan migration in next development sprint." `
                -SuccessMeasure "Secret-based SP percentage tracked quarterly. Target reduction of 10% per quarter until ≤5%." `
                -RemediationPhase "Strategic"
        }
        elseif ($secretSpPct -gt 60) {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS5" -PolicySetName "Workload Identity Standards" `
                -PolicyId "PS5.1" -PolicyName "Excessive Secret-Based Workload Identities — $secretSpPct% Use Secrets" `
                -PolicyStatement "Azure workloads must prefer Managed Identity over client secrets/certificates. Target: <30% of service principals using secrets." `
                -Context "Client secrets are credentials that can be stolen, committed to repos, or included in logs. Every client secret is a potential breach vector. Managed Identities eliminate this risk class entirely." `
                -Evidence "Service Principals with client secrets: $($spWithSecrets.Count) ($secretSpPct%) | Managed Identities: $miCount" `
                -CurrentState "$secretSpPct% of service principals use client secrets. The enterprise is heavily dependent on secret-based workload authentication." `
                -Gap "Far above the 30% threshold. Secret sprawl across workloads increases the probability of a workload credential breach that could be escalated to tenant-level access." `
                -Outcome $script:NON_COMPLIANT -RiskTier "High" `
                -BusinessRisk "Workload credential theft is a primary cloud compromise vector. Secrets committed to code repositories, stored in config files, or included in logs have been the root cause of high-profile cloud breaches." `
                -TargetState "<30% service principals using secrets within 12 months. All Azure-hosted workloads migrated to Managed Identity. External workloads migrated to Federated Identity Credentials." `
                -TransitionGuidance "1) Inventory all secret-based SPs and map to workloads. 2) Classify workloads: Azure-hosted vs external. 3) For Azure-hosted: enable System-Assigned Managed Identity. 4) For external: implement Workload Identity Federation (GitHub Actions OIDC, Terraform). 5) Define migration SLAs per workload tier." `
                -SuccessMeasure "Secret-based SP percentage tracked monthly. 10% reduction target per quarter. Zero new secret-based SPs created without approved exception." `
                -RemediationPhase "31-60 Days"
        }
        else {
            $partial++
            Add-PolicyResult -PolicySetId "PS5" -PolicySetName "Workload Identity Standards" `
                -PolicyId "PS5.1" -PolicyName "Moderate Secret Usage — Managed Identity Adoption Underway ($secretSpPct% Using Secrets)" `
                -PolicyStatement "Azure workloads must prefer Managed Identity over client secrets/certificates. Target: <30% of service principals using secrets." `
                -Context "Client secrets are credentials — they expire, rotate, and leak. Managed Identities eliminate this class entirely. The transition from secrets to MI is the most impactful workload identity security improvement available." `
                -Evidence "Service Principals with client secrets: $($spWithSecrets.Count) ($secretSpPct%) | Managed Identities: $miCount" `
                -CurrentState "$secretSpPct% of service principals still use client secrets — between the partial (30-60%) range." `
                -Gap "Above the 30% policy threshold. Managed Identity adoption should be accelerated." `
                -Outcome $script:PARTIAL -RiskTier "High" `
                -BusinessRisk "Remaining secret-based workloads carry ongoing credential breach risk. Each secret is a potential exposure point in deployment pipelines, config management, or developer workstations." `
                -TargetState "<30% secret-based SPs within 90 days. Managed Identity standard for all new workloads. Federated Identity Credentials for non-Azure external systems." `
                -TransitionGuidance "Accelerate Managed Identity migration. Establish a policy: all new Azure workloads must use Managed Identity — no exceptions without architecture review board approval." `
                -SuccessMeasure "Secret SP percentage below 30% within 90 days. New workload registration checklist mandates MI evaluation." `
                -RemediationPhase "31-60 Days"
        }

        $ps5Score = Get-PolicySetScore -PolicySetId "PS5"
        Set-PolicySetResult -Id "PS5" -Name "Workload Identity Standards" -Icon "⚙️" `
            -Description "Defines the migration path from client-secret-based workload identities to Managed Identity and Federated Identity Credentials, reducing credential attack surface." `
            -CompliantCount $compliant -NonCompliantCount $nonCompliant `
            -PartialCount $partial -ExemptCount $exempt `
            -ComplianceScore $ps5Score
    }

    #endregion

    #region ── Policy Set 6: Guest & External Identity Standards ─────────────────

    Function Invoke-PolicySet6-ExternalIdentities {
        Write-Host "  🌐 PS6: Guest & External Identity Standards..." -ForegroundColor Cyan

        $compliant = 0; $nonCompliant = 0; $partial = 0; $exempt = 0

        # ── Policy 6.1: Guest users must not have stale access (>90 days inactive) ─
        $cutoffDate = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddT00:00:00Z")
        $guestUri = "https://graph.microsoft.com/beta/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName,createdDateTime,signInActivity&`$count=true&`$top=100"
        $guests = Get-GraphPagedResults -Uri $guestUri
        $totalGuests = $guests.Count

        $staleGuests = @($guests | Where-Object {
                $lastSign = if ($_.PSObject.Properties["signInActivity"] -and $_.signInActivity) { $_.signInActivity.lastSignInDateTime } else { $null }
                (-not $lastSign) -or ([datetime]$lastSign -lt [datetime]$cutoffDate)
            })
        $staleGuestPct = if ($totalGuests -gt 0) { [Math]::Round(($staleGuests.Count / $totalGuests) * 100, 0) } else { 0 }

        if ($staleGuestPct -le 10) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS6" -PolicySetName "External Identity Standards" `
                -PolicyId "PS6.1" -PolicyName "Guest Account Staleness Within Policy Threshold" `
                -PolicyStatement "Guest accounts inactive for more than 90 days must not exceed 10% of the total guest population. All guest access must be reviewed annually." `
                -Context "Stale guest accounts represent former partners, contractors, and suppliers who retain tenant access long after their business relationship ended. They are persistent, low-signal access vectors that accumulate over time." `
                -Evidence "Total guests: $totalGuests | Inactive >90 days: $($staleGuests.Count) ($staleGuestPct%)" `
                -CurrentState "$staleGuestPct% of guest accounts are inactive for >90 days — within the ≤10% policy threshold." `
                -Gap "Maintain proactive guest lifecycle management. Annual access review recommended for all guest accounts." `
                -Outcome $script:COMPLIANT -RiskTier "Medium" `
                -BusinessRisk "N/A — threshold met. Sustain with Access Reviews and guest expiration policy." `
                -TargetState "Zero stale guest accounts. Automated expiration policy active. Annual access review for all guests. Supplier offboarding triggers same-day guest account removal." `
                -TransitionGuidance "Enable Guest User Expiration Policy in Entra ID. Configure Access Reviews for all guests (semi-annual). Integrate guest offboarding with supplier management process." `
                -SuccessMeasure "Stale guest rate ≤10% in monthly report. Access review completion rate ≥95%. Guest count trend tracked quarterly." `
                -RemediationPhase "Strategic"
        }
        else {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS6" -PolicySetName "External Identity Standards" `
                -PolicyId "PS6.1" -PolicyName "Excessive Stale Guest Accounts — $staleGuestPct% Inactive >90 Days" `
                -PolicyStatement "Guest accounts inactive for more than 90 days must not exceed 10% of the total guest population." `
                -Context "Stale guest accounts are silent, persistent access vectors. They are rarely monitored, never challenged, and are ideal targets for adversaries who have obtained a former partner's email credentials." `
                -Evidence "Total guests: $totalGuests | Inactive >90 days: $($staleGuests.Count) ($staleGuestPct%)" `
                -CurrentState "$($staleGuests.Count) guest account(s) ($staleGuestPct%) have had no sign-in activity in 90+ days. These accounts retain all the access they were granted, including group memberships and app assignments." `
                -Gap "$($staleGuestPct - 10)% above the policy threshold. Stale external identities accumulate access over time without any lifecycle governance." `
                -Outcome $script:NON_COMPLIANT -RiskTier "Medium" `
                -BusinessRisk "Stale external accounts are a persistent data exfiltration risk. Former partners who retain access to SharePoint, Teams, or OneDrive can access sensitive business data indefinitely. This is a common GDPR data residency violation vector." `
                -TargetState "Zero stale guest accounts. Automated expiration policy active (30/60/90-day lifecycle). Annual access review required for all guests." `
                -TransitionGuidance "1) Export stale guest list. 2) For each: confirm business relationship status with sponsor. 3) Disable accounts where relationship has ended. 4) Delete after 30-day disabled period. 5) Enable Guest Expiration Policy for future guests." `
                -SuccessMeasure "Stale guest rate ≤10% within 30 days. Guest Expiration Policy active. Access Reviews for guests scheduled. Monthly guest hygiene report." `
                -RemediationPhase "0-30 Days"
        }

        # ── Policy 6.2: External collaboration settings must restrict invitation scope ─
        $extCollabPolicy = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy"
        $allowInvites = if ($extCollabPolicy -and $extCollabPolicy.value -and $extCollabPolicy.value.Count -gt 0) { $extCollabPolicy.value[0].allowInvitesFrom } else { if ($extCollabPolicy) { $extCollabPolicy.allowInvitesFrom } else { "unknown" } }

        if ($allowInvites -in @("adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers") -or $allowInvites -eq "none") {
            if ($allowInvites -eq "none" -or $allowInvites -eq "adminsAndGuestInviters") {
                $compliant++
                Add-PolicyResult -PolicySetId "PS6" -PolicySetName "External Identity Standards" `
                    -PolicyId "PS6.2" -PolicyName "Guest Invitation Restricted to Authorised Roles" `
                    -PolicyStatement "Guest invitations must be restricted to administrators and designated Guest Inviters. All-member invitation must be disabled." `
                    -Context "When all members can invite guests, external identity creation is decentralised and ungovernored. Any employee can bring in any external identity — bypassing vendor onboarding, NDA requirements, and security screening." `
                    -Evidence "allowInvitesFrom policy: $allowInvites" `
                    -CurrentState "Guest invitation is restricted to administrators and/or designated Guest Inviter roles. Standard met." `
                    -Gap "Ensure the Guest Inviter role is assigned to a managed, small group — not broadly distributed." `
                    -Outcome $script:COMPLIANT -RiskTier "Medium" `
                    -BusinessRisk "N/A — invitation scope standard met." `
                    -TargetState "Invitations restricted to admins and approved Guest Inviters only. Invitation triggers automated onboarding workflow with sponsor attestation." `
                    -TransitionGuidance "Review Guest Inviter role membership. Define a structured B2B onboarding request process. Integrate with procurement/vendor management." `
                    -SuccessMeasure "Guest Inviter role membership reviewed quarterly. Guest invitation count tracked monthly. Sponsor attestation rate tracked." `
                    -RemediationPhase "Strategic"
            }
            else {
                $partial++
                Add-PolicyResult -PolicySetId "PS6" -PolicySetName "External Identity Standards" `
                    -PolicyId "PS6.2" -PolicyName "All Members Can Invite Guests — Invitation Governance Gap" `
                    -PolicyStatement "Guest invitations must be restricted to administrators and designated Guest Inviters. All-member invitation must be disabled." `
                    -Context "When all members can invite guests, external identity creation is decentralised. Any employee can onboard any external person — bypassing NDA, security screening, and vendor governance processes." `
                    -Evidence "allowInvitesFrom policy: $allowInvites (all members can invite)" `
                    -CurrentState "All tenant members can send B2B guest invitations. External identity creation is ungoverned." `
                    -Gap "All-member invitation creates unsanctioned external access pathways. Governance, compliance, and NDA controls cannot be enforced." `
                    -Outcome $script:PARTIAL -RiskTier "Medium" `
                    -BusinessRisk "Ungoverned guest invitations create shadow IT relationships, expose sensitive data to unvetted external parties, and create GDPR/data residency compliance risk." `
                    -TargetState "allowInvitesFrom = adminsAndGuestInviters. Guest Inviter role assigned to a managed team. Formal B2B onboarding process in place." `
                    -TransitionGuidance "Update External Collaboration Settings (Entra ID > External Identities > External Collaboration Settings) to restrict invitations to admins and Guest Inviters only. Communicate the process change to business stakeholders." `
                    -SuccessMeasure "allowInvitesFrom = adminsAndGuestInviters. Guest invitation volume tracked. Invitations per requester monitored for anomalies." `
                    -RemediationPhase "0-30 Days"
            }
        }
        else {
            $partial++
            Add-PolicyResult -PolicySetId "PS6" -PolicySetName "External Identity Standards" `
                -PolicyId "PS6.2" -PolicyName "Guest Invitation Policy Setting Undetermined" `
                -PolicyStatement "Guest invitations must be restricted to administrators and designated Guest Inviters." `
                -Context "The external collaboration settings could not be definitively read. The policy state is unclear." `
                -Evidence "allowInvitesFrom policy returned: $allowInvites" `
                -CurrentState "Guest invitation policy state could not be confirmed. Manual verification is required." `
                -Gap "Policy state undetermined — manual review required via Entra ID Portal > External Identities." `
                -Outcome $script:PARTIAL -RiskTier "Medium" `
                -BusinessRisk "Unknown policy state creates governance uncertainty. The setting may allow broader guest invitation than intended." `
                -TargetState "allowInvitesFrom = adminsAndGuestInviters. Confirmed and documented." `
                -TransitionGuidance "Navigate to Entra ID > External Identities > External Collaboration Settings and manually verify and set the allowInvitesFrom value." `
                -SuccessMeasure "Policy state confirmed in Entra Portal. Set to adminsAndGuestInviters." `
                -RemediationPhase "0-30 Days"
        }

        $ps6Score = Get-PolicySetScore -PolicySetId "PS6"
        Set-PolicySetResult -Id "PS6" -Name "Guest & External Identity Standards" -Icon "🌐" `
            -Description "Defines lifecycle and access governance standards for guest and B2B identities, including staleness thresholds and invitation scope restrictions." `
            -CompliantCount $compliant -NonCompliantCount $nonCompliant `
            -PartialCount $partial -ExemptCount $exempt `
            -ComplianceScore $ps6Score
    }

    #endregion

    #region ── Policy Set 7: High-Risk Permission Standards ──────────────────────

    Function Invoke-PolicySet7-HighRiskPermissions {
        Write-Host "  🔑 PS7: High-Risk Permission Standards..." -ForegroundColor Cyan

        $compliant = 0; $nonCompliant = 0; $partial = 0; $exempt = 0

        # High-risk Graph API permissions that warrant elevated scrutiny
        $highRiskPermissions = @(
            "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",   # Application.ReadWrite.All
            "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",   # RoleManagement.ReadWrite.Directory
            "06b708a9-e830-4db3-a914-8e69da51d44f",   # AppRoleAssignment.ReadWrite.All
            "19dbc75e-c2e2-444c-a770-ec69d8559fc7",   # Directory.ReadWrite.All
            "e1fe6dd8-ba31-4d61-89e7-88639da4683d",   # User.Read.All (delegated - high risk in context)
            "741f803b-c850-494e-b5df-cde7c675a1ca",   # User.ReadWrite.All
            "62a82d76-70ea-41e2-9197-370581804d09",   # Group.ReadWrite.All
            "7ab1d382-f21e-4acd-a863-ba3e13f7da61",   # Directory.Read.All
            "5b567255-7703-4780-807c-7be8301ae99b",   # Group.Read.All
            "df021288-bdef-4463-88db-98f22de89214"    # User.Read.All (application)
        )

        $spsForPerms = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$select=id,displayName,appRoles,oauth2PermissionScopes&`$filter=servicePrincipalType eq 'Application'&`$top=100"

        # Check for admin consent grants of high-risk permissions
        $highRiskGrants = New-Object System.Collections.ArrayList
        $appPermGrants = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/oauth2PermissionGrants?`$top=100"
        foreach ($grant in $appPermGrants) {
            $scopes = $grant.scope -split " " | Where-Object { $_ }
            $highRiskScopes = @($scopes | Where-Object {
                    $_ -in @(
                        "Application.ReadWrite.All",
                        "Directory.ReadWrite.All",
                        "RoleManagement.ReadWrite.Directory",
                        "AppRoleAssignment.ReadWrite.All",
                        "User.ReadWrite.All",
                        "Group.ReadWrite.All"
                    )
                })
            if ($highRiskScopes.Count -gt 0) {
                $null = $highRiskGrants.Add([PSCustomObject]@{
                        ClientId    = $grant.clientId
                        Scopes      = $highRiskScopes -join ", "
                        ConsentType = $grant.consentType
                    })
            }
        }

        if ($highRiskGrants.Count -eq 0) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS7" -PolicySetName "High-Risk Permissions" `
                -PolicyId "PS7.1" -PolicyName "No High-Risk Delegated OAuth Grants Detected" `
                -PolicyStatement "Delegated OAuth grants for high-risk permissions (Application.ReadWrite.All, Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory) must require explicit justification, approval, and periodic review." `
                -Context "High-risk delegated permissions allow apps to act on behalf of users with powerful capabilities — modifying the directory, granting permissions to other apps, or reading all users. These permissions should be treated like privileged access assignments." `
                -Evidence "High-risk delegated OAuth grants detected: $($highRiskGrants.Count)" `
                -CurrentState "No delegated OAuth grants for high-risk permissions are detected. Standard met." `
                -Gap "Maintain vigilance. Implement an approval workflow for any future request for these permission classes." `
                -Outcome $script:COMPLIANT -RiskTier "High" `
                -BusinessRisk "N/A — no high-risk grants detected." `
                -TargetState "Zero unapproved high-risk grants. Any new grant for this permission class requires documented business justification and security review." `
                -TransitionGuidance "Implement a permission grant request process. Configure Entra ID to require admin consent for these permission classes (block user consent for dangerous permissions)." `
                -SuccessMeasure "High-risk grant count tracked monthly. New grant approvals documented. Admin consent policy active." `
                -RemediationPhase "Strategic"
        }
        else {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS7" -PolicySetName "High-Risk Permissions" `
                -PolicyId "PS7.1" -PolicyName "High-Risk OAuth Grants Detected — $($highRiskGrants.Count) Grant(s) Require Review" `
                -PolicyStatement "Delegated OAuth grants for high-risk permissions must require explicit justification, approval, and periodic review." `
                -Context "High-risk delegated permissions allow apps to act on behalf of signed-in users with directory-level capabilities. If the app is compromised, the attacker inherits these permissions for every user who has consented." `
                -Evidence "High-risk delegated grants: $($highRiskGrants.Count) | Sample scopes: $(($highRiskGrants | Select-Object -First 3 | ForEach-Object { $_.Scopes }) -join ' | ')" `
                -CurrentState "$($highRiskGrants.Count) OAuth grant(s) for high-risk delegated permissions exist. These may be legitimate but require documented review and justification." `
                -Gap "High-risk grants exist without confirmed review. Each grant represents a potential scope for abuse if the app or delegating user is compromised." `
                -Outcome $script:NON_COMPLIANT -RiskTier "High" `
                -BusinessRisk "Apps with high-risk delegated grants can modify directory objects, assign roles, or read sensitive user data on behalf of any consenting user. Supply chain attacks targeting OAuth apps with these grants have resulted in full tenant compromise." `
                -TargetState "All high-risk grants reviewed, documented, and periodically re-approved. User consent disabled for this permission class. Admin consent required for all high-risk scope requests." `
                -TransitionGuidance "1) Export all grants (Entra ID > Enterprise Apps > Permissions > Admin Consent). 2) For each high-risk grant: verify business justification. 3) Revoke grants for apps that no longer require them. 4) Configure User Consent Settings to restrict this permission class to admin approval only." `
                -SuccessMeasure "All high-risk grants reviewed and documented. New grants require security team approval. Admin consent enforced for high-risk permission classes." `
                -RemediationPhase "0-30 Days"
        }

        # ── Policy 7.2: User consent for high-risk permissions must be disabled ───
        $consentPolicy = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/policies/authorizationPolicy"
        $defaultUserRolePermissions = if ($consentPolicy -and $consentPolicy.value) { $consentPolicy.value[0].defaultUserRolePermissions } else { if ($consentPolicy) { $consentPolicy.defaultUserRolePermissions } else { $null } }

        $allowUserConsent = $true
        if ($defaultUserRolePermissions -and $defaultUserRolePermissions.PSObject.Properties["allowUserConsentForRisky Apps"]) {
            $allowUserConsent = $defaultUserRolePermissions.allowUserConsentForRiskyApps
        }

        $consentSettingsUri = "https://graph.microsoft.com/beta/policies/adminConsentRequestPolicy"
        $adminConsentPolicy = Invoke-GraphRequest -Uri $consentSettingsUri
        $adminConsentEnabled = ($adminConsentPolicy -and $adminConsentPolicy.isEnabled -eq $true)

        if ($adminConsentEnabled) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS7" -PolicySetName "High-Risk Permissions" `
                -PolicyId "PS7.2" -PolicyName "Admin Consent Workflow Active for App Permission Requests" `
                -PolicyStatement "Users must not be able to grant app permissions autonomously. An admin consent workflow must be active so users can request access while admins retain approval authority." `
                -Context "Without an admin consent workflow, users either cannot access apps they legitimately need (if user consent is disabled) or can grant any app any permission themselves (if user consent is enabled). The workflow provides a governance middle ground." `
                -Evidence "Admin Consent Request Policy: isEnabled = $($adminConsentPolicy.isEnabled)" `
                -CurrentState "Admin Consent Workflow is active. Users can request app permissions which route to an admin for review and approval." `
                -Gap "Verify the reviewer list is current and that requests are processed within SLA (typically ≤2 business days)." `
                -Outcome $script:COMPLIANT -RiskTier "Medium" `
                -BusinessRisk "N/A — consent governance is active." `
                -TargetState "Admin consent workflow active. User consent for high-risk permissions disabled. Consent request SLA ≤2 business days. Stale requests auto-expire." `
                -TransitionGuidance "Review consent workflow reviewer list. Ensure reviewers are active and responding. Track consent request backlog and approval times." `
                -SuccessMeasure "Consent request SLA compliance rate tracked. Reviewer list reviewed quarterly. User consent for high-risk permissions verified as disabled." `
                -RemediationPhase "Strategic"
        }
        else {
            $partial++
            Add-PolicyResult -PolicySetId "PS7" -PolicySetName "High-Risk Permissions" `
                -PolicyId "PS7.2" -PolicyName "Admin Consent Workflow Not Enabled" `
                -PolicyStatement "An admin consent workflow must be active so users can request app permissions while admins retain approval authority." `
                -Context "Without a consent workflow, disabling user consent creates a dead end (users can't get the apps they need), while enabling it creates uncontrolled permission grants. The workflow is the only scalable governance solution." `
                -Evidence "Admin Consent Request Policy: isEnabled = $(if($adminConsentPolicy){'False'}else{'Could not be read'})" `
                -CurrentState "Admin Consent Workflow is not enabled. Users either cannot request app permissions or can grant them autonomously — neither is the correct enterprise posture." `
                -Gap "Absent consent governance. Either user consent is open (security risk) or blocked with no request path (productivity impact)." `
                -Outcome $script:PARTIAL -RiskTier "Medium" `
                -BusinessRisk "Open user consent allows employees to grant any app access to their Microsoft 365 data. Apps registered by attackers or distributed via phishing can be consented to by any user — enabling OAuth phishing attacks." `
                -TargetState "Admin Consent Workflow active. Users can request, admins approve. User consent for verified publishers allowed for low-risk permissions only. High-risk permissions always require admin consent." `
                -TransitionGuidance "Enable Admin Consent Request Policy in Entra ID > Enterprise Applications > Consent and Permissions. Assign reviewers (Security team or IAM team). Set request expiry. Communicate the process to the business." `
                -SuccessMeasure "Admin Consent Workflow active. Consent request volume and approval rate tracked. User consent limited to low-risk, verified publisher apps only." `
                -RemediationPhase "31-60 Days"
        }

        $ps7Score = Get-PolicySetScore -PolicySetId "PS7"
        Set-PolicySetResult -Id "PS7" -Name "High-Risk Permission Standards" -Icon "🔑" `
            -Description "Defines governance standards for OAuth permission grants and admin consent, ensuring high-risk API access is reviewed, approved, and periodically audited." `
            -CompliantCount $compliant -NonCompliantCount $nonCompliant `
            -PartialCount $partial -ExemptCount $exempt `
            -ComplianceScore $ps7Score
    }

    #endregion

    #region ── Policy Set 8: Identity Lifecycle & Governance Standards ────────────

    Function Invoke-PolicySet8-LifecycleGovernance {
        Write-Host "  🏛️ PS8: Identity Lifecycle & Governance Standards..." -ForegroundColor Cyan

        $compliant = 0; $nonCompliant = 0; $partial = 0; $exempt = 0

        # ── Policy 8.1: Access Reviews must be configured for privileged roles ─────
        $accessReviews = Get-GraphPagedResults -Uri "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions?`$top=20"

        if ($null -eq $accessReviews) {
            $exempt++
            Add-PolicyResult -PolicySetId "PS8" -PolicySetName "Lifecycle & Governance" `
                -PolicyId "PS8.1" -PolicyName "Access Reviews Not Available (Entra ID P2 Required)" `
                -PolicyStatement "Quarterly access reviews must be configured for all privileged roles. Semi-annual reviews required for sensitive groups. Annual reviews required for all guest users." `
                -Context "Access Reviews provide the periodic entitlement certification required by SOC 2, ISO 27001, and most regulated industry frameworks. Without them, access accumulates without anyone being accountable for its validity." `
                -Evidence "Access Reviews API returned null — P2 may not be licensed" `
                -CurrentState "Access Reviews feature is not accessible. Entra ID P2 license is likely absent." `
                -Gap "Without Access Reviews, accumulated privileged access is never certified, reviewed, or revoked — a compliance and audit failure." `
                -Outcome $script:EXEMPT -RiskTier "High" `
                -BusinessRisk "Non-compliance with SOC 2 CC6.1, ISO 27001 A.9.2.5, and regulatory access control requirements. Entitlement creep is invisible to governance and compliance auditors." `
                -TargetState "Entra ID P2 licensed. Quarterly PIM role reviews. Semi-annual sensitive group reviews. Annual guest access reviews. Review reports integrated with compliance reporting." `
                -TransitionGuidance "Invest in Entra ID P2 or M365 E5. Enable Access Reviews. Configure reviews for: (1) PIM roles, (2) sensitive security groups, (3) all guest accounts." `
                -SuccessMeasure "P2 licensed. Access Reviews configured for all three scope types. Review completion rate ≥95%. Review outcomes documented for compliance audits." `
                -RemediationPhase "31-60 Days"
        }
        elseif (@($accessReviews).Count -eq 0) {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS8" -PolicySetName "Lifecycle & Governance" `
                -PolicyId "PS8.1" -PolicyName "No Access Reviews Configured — Entitlement Certification Absent" `
                -PolicyStatement "Quarterly access reviews must be configured for all privileged roles. Semi-annual reviews for sensitive groups. Annual reviews for all guest users." `
                -Context "Access Reviews are the only systematic mechanism for certifying that existing access assignments are still valid. Without them, all access persists indefinitely regardless of changing roles, responsibilities, or risk." `
                -Evidence "Access Review definitions configured: 0 (P2 appears licensed — API is accessible)" `
                -CurrentState "Access Reviews are licensed (P2 accessible) but zero review definitions have been configured. No periodic entitlement certification is occurring." `
                -Gap "Zero access certification. Privileged roles, sensitive groups, and guest accounts accumulate access indefinitely without review." `
                -Outcome $script:NON_COMPLIANT -RiskTier "High" `
                -BusinessRisk "Compliance gap: SOC 2, ISO 27001, and regulated industry frameworks require periodic access certification. Without documented reviews, organisations fail access control audits. Unchecked entitlement drift enables insider threat and privilege abuse." `
                -TargetState "Quarterly PIM access reviews (reviewer = admin manager). Semi-annual sensitive group reviews. Annual guest reviews with auto-remove on no response." `
                -TransitionGuidance "Configure Access Reviews immediately: (1) Navigate to Entra ID > Identity Governance > Access Reviews. (2) Create quarterly review for PIM roles. (3) Create semi-annual review for security groups with sensitive app access. (4) Create annual guest review with auto-remove on no decision." `
                -SuccessMeasure "Access Reviews configured for all three scope types. Review completion rate tracked. Review outcomes documented for compliance." `
                -RemediationPhase "0-30 Days"
        }
        else {
            $activeReviews = @($accessReviews | Where-Object { $_.status -in @("active", "inProgress") })
            $compliant++
            Add-PolicyResult -PolicySetId "PS8" -PolicySetName "Lifecycle & Governance" `
                -PolicyId "PS8.1" -PolicyName "Access Reviews Configured ($(@($accessReviews).Count) Definitions — $($activeReviews.Count) Active)" `
                -PolicyStatement "Quarterly access reviews must be configured for all privileged roles. Semi-annual reviews for sensitive groups. Annual reviews for all guest users." `
                -Context "Access Reviews provide systematic entitlement certification — the audit-defensible evidence that access is periodically validated and that invalid access is removed." `
                -Evidence "Total Access Review definitions: $(@($accessReviews).Count) | Active/In-progress: $($activeReviews.Count)" `
                -CurrentState "Access Reviews are configured and operational. $(@($accessReviews).Count) review definition(s) with $($activeReviews.Count) currently active." `
                -Gap "Verify reviews cover all three required scopes: PIM privileged roles, sensitive security groups, and all guest accounts." `
                -Outcome $script:COMPLIANT -RiskTier "High" `
                -BusinessRisk "N/A — reviews are active. Focus on scope completeness and reviewer participation quality." `
                -TargetState "100% scope coverage: PIM roles (quarterly), sensitive groups (semi-annual), guests (annual). Reviewer participation ≥95%. Auto-remove applied within 14 days of decision." `
                -TransitionGuidance "Audit existing review scope against the three required scopes. Add reviews for any gap. Monitor reviewer participation rates in Identity Governance insights." `
                -SuccessMeasure "All three review scopes covered. Participation rate ≥95%. Review outcomes applied within SLA. Compliance report generated per cycle." `
                -RemediationPhase "Strategic"
        }

        # ── Policy 8.2: Stale member accounts must not exceed 5% ─────────────────
        $staleThreshold = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddT00:00:00Z")
        $staleUri = "https://graph.microsoft.com/beta/users?`$filter=accountEnabled eq true and userType eq 'Member'&`$select=id,displayName,signInActivity&`$top=100"
        $memberUsers = Get-GraphPagedResults -Uri $staleUri
        $totalMembers = $memberUsers.Count

        $staleMembers = @($memberUsers | Where-Object {
                $lastSign = if ($_.PSObject.Properties["signInActivity"] -and $_.signInActivity) { $_.signInActivity.lastSignInDateTime } else { $null }
                (-not $lastSign) -or ([datetime]$lastSign -lt [datetime]$staleThreshold)
            })
        $staleMemberPct = if ($totalMembers -gt 0) { [Math]::Round(($staleMembers.Count / $totalMembers) * 100, 0) } else { 0 }

        if ($staleMemberPct -le 5) {
            $compliant++
            Add-PolicyResult -PolicySetId "PS8" -PolicySetName "Lifecycle & Governance" `
                -PolicyId "PS8.2" -PolicyName "Stale Member Account Rate Within Policy Threshold" `
                -PolicyStatement "Stale member accounts (active but no sign-in in >90 days) must not exceed 5% of the enabled member account population." `
                -Context "Stale internal accounts are commonly associated with employees who have left but whose accounts were not deprovisioned, shared mailbox accounts, service accounts, or automation accounts. All represent ungoverned access." `
                -Evidence "Enabled member accounts evaluated: $totalMembers | Inactive >90 days: $($staleMembers.Count) ($staleMemberPct%)" `
                -CurrentState "$staleMemberPct% of enabled member accounts show no sign-in activity in 90+ days — within the ≤5% policy threshold." `
                -Gap "Maintain lifecycle discipline. Verify stale accounts are monitored in a regular hygiene review." `
                -Outcome $script:COMPLIANT -RiskTier "Medium" `
                -BusinessRisk "N/A — threshold met. Sustain with automated joiner/mover/leaver workflows." `
                -TargetState "Stale rate ≤2%. Automated deprovisioning triggered by HR termination event within 24 hours. Stale account detection in weekly governance report." `
                -TransitionGuidance "Define SLA for account deprovisioning after HR termination. Implement Lifecycle Workflows (P2) or Logic Apps for automated deprovisioning." `
                -SuccessMeasure "Stale rate ≤5% monthly. Deprovisioning SLA compliance rate tracked. Leavers processed within 24 hours of HR trigger." `
                -RemediationPhase "Strategic"
        }
        else {
            $nonCompliant++
            Add-PolicyResult -PolicySetId "PS8" -PolicySetName "Lifecycle & Governance" `
                -PolicyId "PS8.2" -PolicyName "Stale Member Account Rate Exceeds Policy Threshold — $staleMemberPct% Inactive" `
                -PolicyStatement "Stale member accounts must not exceed 5% of the enabled member population." `
                -Context "Stale internal accounts are a primary indicator of broken leaver processes. Active accounts with accumulated access, no sign-in activity, and no owner represent dormant attack vectors." `
                -Evidence "Enabled member accounts: $totalMembers | Inactive >90 days: $($staleMembers.Count) ($staleMemberPct%)" `
                -CurrentState "$staleMemberPct% of enabled member accounts have no sign-in activity in the past 90 days — $($staleMemberPct - 5)% above the policy threshold." `
                -Gap "Stale account rate exceeds the 5% threshold. This indicates that leaver and account lifecycle processes are not operating effectively." `
                -Outcome $script:NON_COMPLIANT -RiskTier "Medium" `
                -BusinessRisk "Stale accounts from departed employees retain access to business data, SharePoint sites, Teams channels, and applications. They are a persistent insider threat vector and a GDPR/data governance risk." `
                -TargetState "Stale rate ≤2%. Automated leaver deprovisioning within 24 hours of HR termination event. Monthly stale account hygiene review." `
                -TransitionGuidance "1) Export stale account list. 2) Cross-reference with HR leavers data. 3) Disable accounts immediately for confirmed leavers. 4) Delete after 30-day quarantine period. 5) Implement Lifecycle Workflows (P2) for automated deprovisioning going forward." `
                -SuccessMeasure "Stale rate ≤5% within 30 days. Automated deprovisioning active. Leaver SLA ≤24 hours after HR trigger." `
                -RemediationPhase "0-30 Days"
        }

        $ps8Score = Get-PolicySetScore -PolicySetId "PS8"
        Set-PolicySetResult -Id "PS8" -Name "Identity Lifecycle & Governance" -Icon "🏛️" `
            -Description "Defines entitlement certification and account lifecycle standards including access review requirements and stale account tolerance thresholds." `
            -CompliantCount $compliant -NonCompliantCount $nonCompliant `
            -PartialCount $partial -ExemptCount $exempt `
            -ComplianceScore $ps8Score
    }

    #endregion

    #region ── JSON Building ─────────────────────────────────────────────────────

    Function ConvertTo-JsonSafe {
        param ([string]$s)
        return $s -replace '\\', '\\' -replace '"', '\"' -replace "`r", '' -replace "`n", '\n' -replace "`t", '\t' -replace '<', '\u003c' -replace '>', '\u003e' -replace '\$', '\u0024'
    }


    Function Build-PolicySetsJson {
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.Append("[")
        $first = $true
        foreach ($ps in $script:PolicySets) {
            if (-not $first) { $null = $sb.Append(",") }
            $first = $false
            $null = $sb.Append("{")
            $null = $sb.Append("""id"":""$(ConvertTo-JsonSafe $ps.Id)"",")
            $null = $sb.Append("""name"":""$(ConvertTo-JsonSafe $ps.Name)"",")
            $null = $sb.Append("""icon"":""$(ConvertTo-JsonSafe $ps.Icon)"",")
            $null = $sb.Append("""description"":""$(ConvertTo-JsonSafe $ps.Description)"",")
            $null = $sb.Append("""compliant"":$($ps.CompliantCount),")
            $null = $sb.Append("""nonCompliant"":$($ps.NonCompliantCount),")
            $null = $sb.Append("""partial"":$($ps.PartialCount),")
            $null = $sb.Append("""exempt"":$($ps.ExemptCount),")
            $null = $sb.Append("""complianceScore"":$($ps.ComplianceScore)")
            $null = $sb.Append("}")
        }
        $null = $sb.Append("]")
        return $sb.ToString()
    }


    Function Build-PoliciesJson {
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.Append("[")
        $first = $true
        foreach ($p in $script:Policies) {
            if (-not $first) { $null = $sb.Append(",") }
            $first = $false
            $null = $sb.Append("{")
            $null = $sb.Append("""policySetId"":""$(ConvertTo-JsonSafe $p.PolicySetId)"",")
            $null = $sb.Append("""policySetName"":""$(ConvertTo-JsonSafe $p.PolicySetName)"",")
            $null = $sb.Append("""policyId"":""$(ConvertTo-JsonSafe $p.PolicyId)"",")
            $null = $sb.Append("""policyName"":""$(ConvertTo-JsonSafe $p.PolicyName)"",")
            $null = $sb.Append("""policyStatement"":""$(ConvertTo-JsonSafe $p.PolicyStatement)"",")
            $null = $sb.Append("""context"":""$(ConvertTo-JsonSafe $p.Context)"",")
            $null = $sb.Append("""evidence"":""$(ConvertTo-JsonSafe $p.Evidence)"",")
            $null = $sb.Append("""currentState"":""$(ConvertTo-JsonSafe $p.CurrentState)"",")
            $null = $sb.Append("""gap"":""$(ConvertTo-JsonSafe $p.Gap)"",")
            $null = $sb.Append("""outcome"":""$(ConvertTo-JsonSafe $p.Outcome)"",")
            $null = $sb.Append("""riskTier"":""$(ConvertTo-JsonSafe $p.RiskTier)"",")
            $null = $sb.Append("""businessRisk"":""$(ConvertTo-JsonSafe $p.BusinessRisk)"",")
            $null = $sb.Append("""targetState"":""$(ConvertTo-JsonSafe $p.TargetState)"",")
            $null = $sb.Append("""transitionGuidance"":""$(ConvertTo-JsonSafe $p.TransitionGuidance)"",")
            $null = $sb.Append("""successMeasure"":""$(ConvertTo-JsonSafe $p.SuccessMeasure)"",")
            $null = $sb.Append("""remediationPhase"":""$(ConvertTo-JsonSafe $p.RemediationPhase)"",")
            $null = $sb.Append("""outcomeColor"":""$(ConvertTo-JsonSafe $p.OutcomeColor)"",")
            $null = $sb.Append("""riskColor"":""$(ConvertTo-JsonSafe $p.RiskColor)""")
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
            [string]$PolicySetsJson,
            [string]$PoliciesJson,
            [string]$OutputFilePath
        )

        $totalPolicies = $script:Policies.Count
        $totalCompliant = ($script:Policies | Where-Object { $_.Outcome -eq "Compliant" }).Count
        $totalNonCompliant = ($script:Policies | Where-Object { $_.Outcome -eq "NonCompliant" }).Count
        $totalPartial = ($script:Policies | Where-Object { $_.Outcome -eq "PartiallyCompliant" }).Count
        $totalExempt = ($script:Policies | Where-Object { $_.Outcome -eq "Exempt" }).Count
        $totalCritical = ($script:Policies | Where-Object { $_.RiskTier -eq "Critical" -and $_.Outcome -eq "NonCompliant" }).Count

        $ringPct = [int]([Math]::Round(($OverallScore / 100) * 100, 0))
        $ringR = 54
        $ringCirc = [Math]::Round(2 * [Math]::PI * $ringR, 1)
        $ringDash = [Math]::Round($ringCirc * ($ringPct / 100), 1)
        $ringGap = [Math]::Round($ringCirc - $ringDash, 1)

        # Determine ring colour based on score
        $ringColor = if ($OverallScore -ge 80) { "#3fb950" } elseif ($OverallScore -ge 60) { "#d29922" } else { "#f85149" }

        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Identity Policy as Code — __TENANT_NAME__</title>
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
.logo-icon{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,#a371f7,#388bfd);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3}
.logo-sub{font-size:10px;color:var(--muted);margin-top:3px}
.ver-badge{display:inline-block;font-size:9px;background:var(--surface3);color:var(--accent3);padding:2px 7px;border-radius:20px;margin-top:6px;font-family:var(--mono)}
nav{flex:1;padding:10px 8px}
.nav-section{font-size:9px;font-weight:700;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;padding:10px 10px 4px}
.nav-btn{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:var(--radius-sm);cursor:pointer;font-size:12px;color:var(--muted2);margin-bottom:2px;transition:all .15s;border:none;background:none;width:100%;text-align:left}
.nav-btn:hover{background:var(--surface2);color:var(--text)}
.nav-btn.active{background:rgba(163,113,247,.12);color:var(--accent3);border-left:3px solid var(--accent3);font-weight:600}
.nav-btn .nav-icon{font-size:14px;width:18px;text-align:center}
.theme-toggle{padding:12px 16px;border-top:1px solid var(--border)}
.theme-pill{display:flex;background:var(--surface2);border-radius:20px;padding:3px}
.theme-opt{flex:1;padding:5px;text-align:center;font-size:11px;border-radius:16px;cursor:pointer;transition:all .2s;color:var(--muted)}
.theme-opt.active{background:var(--accent3);color:#fff;font-weight:600}
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

/* ── Compliance Ring ── */
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

/* ── Panels ── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.panel-title{font-size:14px;font-weight:700}
.panel-badge{font-size:10px;padding:2px 9px;border-radius:20px;background:var(--surface3);color:var(--muted);font-family:var(--mono)}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}

/* ── Policy Set Cards ── */
.pset-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-bottom:24px}
.pset-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;cursor:pointer;transition:transform .15s,box-shadow .15s}
.pset-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.pset-card-header{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.pset-icon{font-size:22px}
.pset-name{font-size:13px;font-weight:700;line-height:1.3}
.pset-score-bar{height:6px;background:var(--surface3);border-radius:3px;margin-bottom:10px;overflow:hidden}
.pset-score-fill{height:100%;border-radius:3px;transition:width 1s ease}
.pset-counts{display:flex;gap:8px;flex-wrap:wrap}
.pset-count-chip{font-size:10px;padding:2px 8px;border-radius:20px;font-family:var(--mono);font-weight:600}
.chip-green{background:rgba(63,185,80,.15);color:var(--green)}
.chip-red{background:rgba(248,81,73,.15);color:var(--red)}
.chip-amber{background:rgba(210,153,34,.15);color:var(--amber)}
.chip-muted{background:var(--surface3);color:var(--muted)}

/* ── Outcome Badges ── */
.outcome-badge{display:inline-block;font-size:10px;padding:2px 8px;border-radius:20px;font-weight:700;font-family:var(--mono)}
.ob-Compliant{background:rgba(63,185,80,.15);color:var(--green)}
.ob-NonCompliant{background:rgba(248,81,73,.15);color:var(--red)}
.ob-PartiallyCompliant{background:rgba(210,153,34,.15);color:var(--amber)}
.ob-Exempt{background:var(--surface3);color:var(--muted)}
.risk-badge{display:inline-block;font-size:10px;padding:2px 8px;border-radius:20px;font-weight:700;font-family:var(--mono)}
.rb-Critical{background:rgba(248,81,73,.15);color:var(--red)}
.rb-High{background:rgba(210,153,34,.15);color:var(--amber)}
.rb-Medium{background:rgba(56,139,253,.15);color:var(--accent)}
.rb-Low{background:rgba(63,185,80,.15);color:var(--green)}

/* ── Data Table ── */
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.search-wrap{position:relative;flex:1;min-width:180px}
.search-wrap input{width:100%;padding:7px 10px 7px 30px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface2);color:var(--text);font-size:12px}
.search-wrap::before{content:"🔍";position:absolute;left:8px;top:50%;transform:translateY(-50%);font-size:11px;pointer-events:none}
.filter-btn{padding:6px 12px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface2);color:var(--muted2);font-size:11px;cursor:pointer;transition:all .15s}
.filter-btn:hover,.filter-btn.active{background:rgba(163,113,247,.15);color:var(--accent3);border-color:var(--accent3)}
.tbl-wrap{overflow-x:auto}
.policies-table{width:100%;border-collapse:collapse;font-size:12px}
.policies-table th{background:var(--surface2);padding:10px 12px;text-align:left;font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;cursor:pointer;white-space:nowrap;user-select:none}
.policies-table th:hover{color:var(--text)}
.sort-active{color:var(--accent3)!important}
.sort-arrow{margin-left:4px;font-size:9px}
.policies-table td{padding:10px 12px;border-top:1px solid var(--border);vertical-align:middle}
.policies-table tr:hover td{background:var(--surface2);cursor:pointer}
.policy-name-cell{font-weight:600;color:var(--text);max-width:300px}
.pagination{display:flex;align-items:center;gap:6px;margin-top:12px;font-size:12px;color:var(--muted)}
.pg-btn{padding:4px 10px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface2);color:var(--muted2);cursor:pointer;font-size:11px}
.pg-btn:hover{background:var(--surface3);color:var(--text)}
.pg-btn.active{background:rgba(163,113,247,.2);color:var(--accent3);border-color:var(--accent3);font-weight:700}

/* ── Detail Drawer ── */
#detailPanel{position:fixed;inset:0;z-index:200;pointer-events:none}
#detailPanel.open{pointer-events:all}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.55);opacity:0;transition:opacity .25s}
#detailPanel.open #detailBackdrop{opacity:1}
#detailDrawer{position:absolute;right:0;top:0;bottom:0;width:560px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;transform:translateX(100%);transition:transform .25s cubic-bezier(.4,0,.2,1);padding:0;display:flex;flex-direction:column}
#detailPanel.open #detailDrawer{transform:none}
.drawer-header{padding:18px 20px 14px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:12px;position:sticky;top:0;background:var(--surface);z-index:1}
.drawer-title{font-size:14px;font-weight:700;flex:1;line-height:1.4}
.drawer-close{background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px;padding:4px;border-radius:var(--radius-sm);flex-shrink:0}
.drawer-close:hover{color:var(--text);background:var(--surface2)}
.drawer-chips{padding:12px 20px;display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--border)}
.drawer-section{padding:14px 20px;border-bottom:1px solid var(--border)}
.drawer-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
.drawer-value{font-size:12px;color:var(--muted2);line-height:1.6}
.drawer-value.highlight{color:var(--text);font-weight:600}
.drawer-nav{padding:14px 20px;display:flex;align-items:center;gap:10px;border-top:1px solid var(--border);margin-top:auto}
.drawer-nav button{padding:6px 14px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface2);color:var(--muted2);cursor:pointer;font-size:11px}
.drawer-nav button:hover{background:var(--surface3);color:var(--text)}
.drawer-count{margin-left:auto;font-size:11px;color:var(--muted);font-family:var(--mono)}

/* ── Roadmap ── */
.roadmap-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}
.roadmap-col-header{display:flex;align-items:center;gap:8px;padding:10px 0;margin-bottom:10px;border-bottom:2px solid var(--border)}
.roadmap-col-label{font-size:13px;font-weight:700}
.roadmap-count{margin-left:auto;font-size:11px;font-family:var(--mono);background:var(--surface3);padding:2px 8px;border-radius:20px;color:var(--muted)}
.roadmap-item{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;margin-bottom:8px;cursor:pointer;transition:all .15s}
.roadmap-item:hover{border-color:var(--accent3);transform:translateX(2px)}
.roadmap-item-title{font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;line-height:1.4}
.roadmap-item-meta{display:flex;gap:6px;align-items:center;flex-wrap:wrap}

/* ── Policy Catalog ── */
.pac-note{background:rgba(163,113,247,.08);border:1px solid rgba(163,113,247,.25);border-radius:var(--radius);padding:14px 16px;margin-bottom:20px;font-size:12px;color:var(--muted2);line-height:1.6}
.pac-note strong{color:var(--accent3)}
.pset-detail-list{display:grid;gap:12px}
.pset-detail-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;border-left:3px solid var(--accent3)}
.pset-detail-name{font-size:13px;font-weight:700;margin-bottom:4px}
.pset-detail-desc{font-size:11px;color:var(--muted2);line-height:1.5}

/* ── Toast ── */
#toast{position:fixed;bottom:24px;right:24px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px 18px;font-size:12px;transform:translateY(20px);opacity:0;pointer-events:none;transition:all .2s;z-index:999;box-shadow:var(--shadow)}
#toast.show{transform:none;opacity:1}

/* ── Mobile ── */
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:300;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 10px;cursor:pointer;font-size:16px}
@media(max-width:768px){
  #menuToggle{display:flex}
  #sidebar{transform:translateX(-100%);transition:transform .25s}
  #sidebar.open{transform:none}
  #main{margin-left:0;padding:16px;padding-top:50px}
}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<!-- ── Sidebar ── -->
<div id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">📋</div>
    <div class="logo-title">Identity Policy as Code</div>
    <div class="logo-sub">Entra ID Policy Compliance Engine</div>
    <span class="ver-badge">v1.0</span>
  </div>
  <nav>
    <div class="nav-section">Navigation</div>
    <button class="nav-btn active" onclick="showPage('page-overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('page-policysets',this)"><span class="nav-icon">📦</span> Policy Sets</button>
    <button class="nav-btn" onclick="showPage('page-policies',this)"><span class="nav-icon">📋</span> All Policies</button>
    <button class="nav-btn" onclick="showPage('page-violations',this)"><span class="nav-icon">⚠️</span> Violations</button>
    <button class="nav-btn" onclick="showPage('page-roadmap',this);renderRoadmap()"><span class="nav-icon">🗺️</span> Roadmap</button>
    <button class="nav-btn" onclick="showPage('page-catalog',this)"><span class="nav-icon">📖</span> Policy Catalog</button>
  </nav>
  <div class="theme-toggle">
    <div class="theme-pill">
      <div class="theme-opt active" id="themeDark" onclick="setTheme('dark')">🌙 Dark</div>
      <div class="theme-opt" id="themeLight" onclick="setTheme('light')">☀️ Light</div>
    </div>
  </div>
  <div class="sidebar-footer">
    Generated: __ASSESSMENT_DATE__<br>
    Tenant: __TENANT_NAME__<br><br>
    <span class="kbd">/</span> search &nbsp; <span class="kbd">Esc</span> close
  </div>
</div>

<div id="main">

  <!-- ══ Overview ══════════════════════════════════════════════════════════════ -->
  <div class="page active" id="page-overview">
    <div class="page-header">
      <h1>📊 Policy Compliance Overview</h1>
      <p>Tenant: <strong>__TENANT_NAME__</strong> &nbsp;·&nbsp; __TENANT_ID__ &nbsp;·&nbsp; Evaluated: __ASSESSMENT_DATE__</p>
    </div>

    <div class="health-card">
      <div class="health-ring-wrap">
        <svg viewBox="0 0 128 128" width="128" height="128">
          <circle class="health-ring-bg" cx="64" cy="64" r="54"/>
          <circle class="health-ring-fill" cx="64" cy="64" r="54"
            stroke="__RING_COLOR__"
            stroke-dasharray="__RING_DASH__ __RING_GAP__"/>
        </svg>
        <div class="ring-label">
          <div class="ring-val" style="color:__RING_COLOR__">__OVERALL_SCORE__%</div>
          <div class="ring-sub">compliant</div>
        </div>
      </div>
      <div class="health-info">
        <h2>Overall Compliance Score: __OVERALL_SCORE__%</h2>
        <p>Weighted compliance score across all evaluated policy sets. Score = (weighted compliant + 0.5 × partial) ÷ total possible weight × 100. Exempt policies are excluded from scoring.</p>
        <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
          <span class="outcome-badge ob-Compliant">✓ Compliant</span>
          <span class="outcome-badge ob-NonCompliant">✗ Non-Compliant</span>
          <span class="outcome-badge ob-PartiallyCompliant">~ Partial</span>
          <span class="outcome-badge ob-Exempt">— Exempt</span>
        </div>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-label">Total Policies</div>
        <div class="stat-value">__TOTAL_POLICIES__</div>
        <div class="stat-sub">across 8 policy sets</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-label">Compliant</div>
        <div class="stat-value" style="color:var(--green)">__TOTAL_COMPLIANT__</div>
        <div class="stat-sub">standards met</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-label">Non-Compliant</div>
        <div class="stat-value" style="color:var(--red)">__TOTAL_NONCOMPLIANT__</div>
        <div class="stat-sub">violations requiring action</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-label">Partially Compliant</div>
        <div class="stat-value" style="color:var(--amber)">__TOTAL_PARTIAL__</div>
        <div class="stat-sub">partially met</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-label">Exempt</div>
        <div class="stat-value" style="color:var(--accent3)">__TOTAL_EXEMPT__</div>
        <div class="stat-sub">feature unavailable (P2)</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-label">Critical Violations</div>
        <div class="stat-value" style="color:var(--red)">__TOTAL_CRITICAL__</div>
        <div class="stat-sub">non-compliant critical-risk policies</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-header"><span class="panel-title">Policy Set Compliance Scores</span></div>
        <div id="psetBars"></div>
      </div>
      <div class="panel">
        <div class="panel-header"><span class="panel-title">Violations by Risk Tier</span></div>
        <div id="riskBars"></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Top Violations Requiring Immediate Action</span>
        <span class="panel-badge" id="topViolBadge">0 items</span>
      </div>
      <div id="topViolations"></div>
    </div>
  </div>

  <!-- ══ Policy Sets ═══════════════════════════════════════════════════════════ -->
  <div class="page" id="page-policysets">
    <div class="page-header">
      <h1>📦 Policy Sets</h1>
      <p>Enterprise identity standards grouped into 8 policy domains. Click a card to explore policies within that set.</p>
    </div>
    <div class="pset-grid" id="psetGrid"></div>
  </div>

  <!-- ══ All Policies ══════════════════════════════════════════════════════════ -->
  <div class="page" id="page-policies">
    <div class="page-header">
      <h1>📋 All Policies</h1>
      <p>Full policy evaluation list. Click any row to view complete evidence, gap analysis, and remediation guidance.</p>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <input type="text" id="policySearch" placeholder="Search policies..." oninput="filterPolicies()">
        </div>
        <button class="filter-btn active" onclick="setPolicyFilter('all',this)">All</button>
        <button class="filter-btn" onclick="setPolicyFilter('NonCompliant',this)">Non-Compliant</button>
        <button class="filter-btn" onclick="setPolicyFilter('PartiallyCompliant',this)">Partial</button>
        <button class="filter-btn" onclick="setPolicyFilter('Compliant',this)">Compliant</button>
        <button class="filter-btn" onclick="setPolicyFilter('Exempt',this)">Exempt</button>
        <button class="filter-btn" onclick="exportPoliciesCSV()" style="margin-left:auto">⬇ Export CSV</button>
      </div>
      <div class="tbl-wrap">
        <table class="policies-table">
          <thead>
            <tr>
              <th onclick="sortPolicies('policyId')">Policy ID <span class="sort-arrow" id="sort-policyId"></span></th>
              <th onclick="sortPolicies('policyName')">Policy Name <span class="sort-arrow" id="sort-policyName"></span></th>
              <th onclick="sortPolicies('policySetName')">Policy Set <span class="sort-arrow" id="sort-policySetName"></span></th>
              <th onclick="sortPolicies('outcome')">Outcome <span class="sort-arrow" id="sort-outcome"></span></th>
              <th onclick="sortPolicies('riskTier')">Risk <span class="sort-arrow" id="sort-riskTier"></span></th>
              <th onclick="sortPolicies('remediationPhase')">Phase <span class="sort-arrow" id="sort-remediationPhase"></span></th>
            </tr>
          </thead>
          <tbody id="policiesTbody"></tbody>
        </table>
      </div>
      <div class="pagination" id="policiesPagination"></div>
    </div>
  </div>

  <!-- ══ Violations ════════════════════════════════════════════════════════════ -->
  <div class="page" id="page-violations">
    <div class="page-header">
      <h1>⚠️ Policy Violations</h1>
      <p>All non-compliant and partially compliant policies, prioritised by risk tier and remediation phase.</p>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <input type="text" id="violSearch" placeholder="Search violations..." oninput="filterViolations()">
        </div>
        <button class="filter-btn active" onclick="setViolFilter('all',this)">All</button>
        <button class="filter-btn" onclick="setViolFilter('NonCompliant',this)">Non-Compliant</button>
        <button class="filter-btn" onclick="setViolFilter('PartiallyCompliant',this)">Partial</button>
        <button class="filter-btn" onclick="setViolFilter('Critical',this)">Critical Risk</button>
        <button class="filter-btn" onclick="setViolFilter('High',this)">High Risk</button>
      </div>
      <div class="tbl-wrap">
        <table class="policies-table">
          <thead>
            <tr>
              <th onclick="sortViolations('policyId')">ID</th>
              <th onclick="sortViolations('policyName')">Violation</th>
              <th onclick="sortViolations('policySetName')">Policy Set</th>
              <th onclick="sortViolations('outcome')">Status</th>
              <th onclick="sortViolations('riskTier')">Risk</th>
              <th onclick="sortViolations('remediationPhase')">Phase</th>
            </tr>
          </thead>
          <tbody id="violationsTbody"></tbody>
        </table>
      </div>
      <div class="pagination" id="violationsPagination"></div>
    </div>
  </div>

  <!-- ══ Roadmap ═══════════════════════════════════════════════════════════════ -->
  <div class="page" id="page-roadmap">
    <div class="page-header">
      <h1>🗺️ Remediation Roadmap</h1>
      <p>Prioritised remediation plan based on risk tier, business impact, and architectural dependencies.</p>
    </div>
    <div class="pac-note">
      <strong>Roadmap principle:</strong> Violations are sequenced by security risk reduction and dependency order. Foundational controls (MFA for all, legacy auth block) appear in Immediate/0-30 days because they are pre-conditions for all downstream security investments. Partial compliance earns half credit toward the score and represents in-progress improvement.
    </div>
    <div class="roadmap-grid" id="roadmapGrid"></div>
  </div>

  <!-- ══ Policy Catalog ════════════════════════════════════════════════════════ -->
  <div class="page" id="page-catalog">
    <div class="page-header">
      <h1>📖 Policy Catalog</h1>
      <p>Enterprise identity standards as machine-readable policies. This is the authoritative definition of what is being evaluated.</p>
    </div>
    <div class="pac-note">
      <strong>Policy as Code principle:</strong> Identity standards must be machine-readable, version-controlled, and automatically evaluated against live tenant state. This catalog replaces Word-document-based identity standards with enforceable, measurable policy definitions. Each policy follows the architectural model: <strong>Context → Current State → Gap → Target State → Transition → Success Measure</strong>.
    </div>
    <div class="pset-detail-list" id="catalogList"></div>
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
    <div class="drawer-section"><div class="drawer-label">Policy Statement</div><div class="drawer-value highlight" id="drawerStatement"></div></div>
    <div class="drawer-section"><div class="drawer-label">Context — Why This Standard Matters</div><div class="drawer-value" id="drawerContext"></div></div>
    <div class="drawer-section"><div class="drawer-label">Evidence</div><div class="drawer-value" id="drawerEvidence"></div></div>
    <div class="drawer-section"><div class="drawer-label">Current State</div><div class="drawer-value" id="drawerCurrentState"></div></div>
    <div class="drawer-section"><div class="drawer-label">Gap</div><div class="drawer-value" id="drawerGap"></div></div>
    <div class="drawer-section"><div class="drawer-label">Business Risk</div><div class="drawer-value" id="drawerRisk"></div></div>
    <div class="drawer-section"><div class="drawer-label">Target State</div><div class="drawer-value" id="drawerTarget"></div></div>
    <div class="drawer-section"><div class="drawer-label">Transition Guidance</div><div class="drawer-value" id="drawerTransition"></div></div>
    <div class="drawer-section"><div class="drawer-label">Success Measure</div><div class="drawer-value" id="drawerSuccess"></div></div>
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
const POLICY_SETS = __POLICY_SETS_JSON__;
const POLICIES    = __POLICIES_JSON__;

// ── Utilities ─────────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

function showToast(msg){
  const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2200);
}

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  if(btn)btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
}

function setTheme(t){
  document.body.classList.toggle('light-theme',t==='light');
  document.getElementById('themeDark').classList.toggle('active',t==='dark');
  document.getElementById('themeLight').classList.toggle('active',t==='light');
}

const riskOrder={Critical:0,High:1,Medium:2,Low:3};
const phaseOrder={'Immediate':0,'0-30 Days':1,'31-60 Days':2,'61-90 Days':3,'Strategic':4};
const outcomeOrder={NonCompliant:0,PartiallyCompliant:1,Exempt:2,Compliant:3};

// ── Overview ──────────────────────────────────────────────────────────────────
function renderOverview(){
  // Policy set bars
  const pb=document.getElementById('psetBars');
  if(!pb.innerHTML){
    POLICY_SETS.forEach(ps=>{
      const col=ps.complianceScore>=80?'var(--green)':ps.complianceScore>=60?'var(--amber)':'var(--red)';
      pb.innerHTML+=`<div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px">
          <span>${escH(ps.icon)} ${escH(ps.name)}</span>
          <span style="font-family:var(--mono);font-weight:700;color:${col}">${ps.complianceScore}%</span>
        </div>
        <div style="height:8px;background:var(--surface3);border-radius:4px;overflow:hidden">
          <div style="width:${ps.complianceScore}%;height:100%;background:${col};border-radius:4px;transition:width 1s ease"></div>
        </div>
      </div>`;
    });
  }

  // Risk bars
  const rb=document.getElementById('riskBars');
  if(!rb.innerHTML){
    const violations=POLICIES.filter(p=>p.outcome!=='Compliant'&&p.outcome!=='Exempt');
    const riskGroups={Critical:0,High:0,Medium:0,Low:0};
    violations.forEach(p=>{ if(riskGroups.hasOwnProperty(p.riskTier)) riskGroups[p.riskTier]++; });
    const maxV=Math.max(...Object.values(riskGroups),1);
    const riskColors={Critical:'var(--red)',High:'var(--amber)',Medium:'var(--accent)',Low:'var(--green)'};
    Object.entries(riskGroups).forEach(([tier,count])=>{
      const pct=Math.round((count/maxV)*100);
      rb.innerHTML+=`<div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px">
          <span>${tier}</span><span style="font-family:var(--mono);font-weight:700;color:${riskColors[tier]}">${count} violation(s)</span>
        </div>
        <div style="height:8px;background:var(--surface3);border-radius:4px;overflow:hidden">
          <div style="width:${pct}%;height:100%;background:${riskColors[tier]};border-radius:4px;transition:width 1s ease"></div>
        </div>
      </div>`;
    });
  }

  // Top violations
  const tv=document.getElementById('topViolations');
  if(!tv.innerHTML){
    const topViols=POLICIES
      .filter(p=>p.outcome==='NonCompliant')
      .sort((a,b)=>(riskOrder[a.riskTier]??9)-(riskOrder[b.riskTier]??9)||(phaseOrder[a.remediationPhase]??9)-(phaseOrder[b.remediationPhase]??9))
      .slice(0,5);
    document.getElementById('topViolBadge').textContent=topViols.length+' items';
    topViols.forEach(p=>{
      const idx=POLICIES.indexOf(p);
      tv.innerHTML+=`<div style="display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-top:1px solid var(--border);cursor:pointer" onclick="openPolicy(${idx})">
        <span class="risk-badge rb-${escH(p.riskTier)}" style="flex-shrink:0;margin-top:2px">${escH(p.riskTier)}</span>
        <div style="flex:1">
          <div style="font-size:12px;font-weight:600;color:var(--text);margin-bottom:2px">${escH(p.policyName)}</div>
          <div style="font-size:10px;color:var(--muted)">${escH(p.policySetName)} · ${escH(p.remediationPhase)}</div>
        </div>
        <span class="outcome-badge ob-${escH(p.outcome)}">${escH(p.outcome==='NonCompliant'?'Violation':'Partial')}</span>
      </div>`;
    });
    if(!topViols.length) tv.innerHTML='<div style="padding:16px;color:var(--muted);font-size:12px">🎉 No critical violations found.</div>';
  }
}
renderOverview();

// ── Policy Sets ───────────────────────────────────────────────────────────────
function renderPolicySets(){
  const grid=document.getElementById('psetGrid');
  if(grid.innerHTML) return;
  POLICY_SETS.forEach(ps=>{
    const col=ps.complianceScore>=80?'var(--green)':ps.complianceScore>=60?'var(--amber)':'var(--red)';
    grid.innerHTML+=`<div class="pset-card" onclick="showPage('page-policies',document.querySelectorAll('.nav-btn')[2]);setPolicyFilterBySet('${escJ(ps.id)}')">
      <div class="pset-card-header">
        <span class="pset-icon">${escH(ps.icon)}</span>
        <span class="pset-name">${escH(ps.name)}</span>
      </div>
      <div style="font-size:10px;color:var(--muted);margin-bottom:10px">${escH(ps.description)}</div>
      <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px">
        <span>Compliance</span><span style="font-family:var(--mono);font-weight:700;color:${col}">${ps.complianceScore}%</span>
      </div>
      <div class="pset-score-bar"><div class="pset-score-fill" style="width:${ps.complianceScore}%;background:${col}"></div></div>
      <div class="pset-counts">
        <span class="pset-count-chip chip-green">✓ ${ps.compliant}</span>
        <span class="pset-count-chip chip-red">✗ ${ps.nonCompliant}</span>
        <span class="pset-count-chip chip-amber">~ ${ps.partial}</span>
        <span class="pset-count-chip chip-muted">— ${ps.exempt}</span>
      </div>
    </div>`;
  });
}

// ── All Policies Table ────────────────────────────────────────────────────────
let filteredPolicies=[];
let policyPage=1;
const policyPageSize=15;
let policySortCol='outcome';
let policySortAsc=true;
let policyOutcomeFilter='all';
let policySetFilter='all';

function setPolicyFilter(f,btn){
  policyOutcomeFilter=f;policySetFilter='all';
  document.querySelectorAll('#page-policies .filter-btn').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  filterPolicies();
}
function setPolicyFilterBySet(setId){
  policySetFilter=setId;policyOutcomeFilter='all';filterPolicies();
}

function filterPolicies(){
  const q=(document.getElementById('policySearch')?.value||'').toLowerCase();
  filteredPolicies=POLICIES.filter(p=>{
    const matchOutcome=policyOutcomeFilter==='all'||p.outcome===policyOutcomeFilter;
    const matchSet=policySetFilter==='all'||p.policySetId===policySetFilter;
    const matchQ=!q||(p.policyName||'').toLowerCase().includes(q)||(p.policySetName||'').toLowerCase().includes(q)||(p.policyId||'').toLowerCase().includes(q);
    return matchOutcome&&matchSet&&matchQ;
  });
  filteredPolicies.sort((a,b)=>{
    let va=a[policySortCol]??'';let vb=b[policySortCol]??'';
    if(policySortCol==='riskTier'){va=riskOrder[va]??9;vb=riskOrder[vb]??9;return policySortAsc?va-vb:vb-va;}
    if(policySortCol==='outcome'){va=outcomeOrder[va]??9;vb=outcomeOrder[vb]??9;return policySortAsc?va-vb:vb-va;}
    if(policySortCol==='remediationPhase'){va=phaseOrder[va]??9;vb=phaseOrder[vb]??9;return policySortAsc?va-vb:vb-va;}
    return policySortAsc?String(va).localeCompare(String(vb)):String(vb).localeCompare(String(va));
  });
  policyPage=1;renderPoliciesTable();
}

function sortPolicies(col){
  if(policySortCol===col)policySortAsc=!policySortAsc;else{policySortCol=col;policySortAsc=true;}
  document.querySelectorAll('[id^="sort-"]').forEach(el=>el.textContent='');
  const el=document.getElementById('sort-'+col);
  if(el)el.textContent=policySortAsc?'▲':'▼';
  document.querySelectorAll('#page-policies th').forEach(th=>th.classList.remove('sort-active'));
  filterPolicies();
}

function renderPoliciesTable(){
  const start=(policyPage-1)*policyPageSize;
  const pageItems=filteredPolicies.slice(start,start+policyPageSize);
  const tbody=document.getElementById('policiesTbody');
  tbody.innerHTML='';
  pageItems.forEach(p=>{
    const idx=POLICIES.indexOf(p);
    const row=document.createElement('tr');
    row.onclick=()=>openPolicy(idx);
    row.innerHTML=`<td style="font-family:var(--mono);font-size:10px;color:var(--muted);white-space:nowrap">${escH(p.policyId)}</td>
      <td class="policy-name-cell">${escH(p.policyName)}</td>
      <td style="color:var(--muted2);white-space:nowrap">${escH(p.policySetName)}</td>
      <td><span class="outcome-badge ob-${escH(p.outcome)}">${escH(p.outcome==='NonCompliant'?'Violation':p.outcome==='PartiallyCompliant'?'Partial':p.outcome)}</span></td>
      <td><span class="risk-badge rb-${escH(p.riskTier)}">${escH(p.riskTier)}</span></td>
      <td style="color:var(--muted2);font-size:11px;white-space:nowrap">${escH(p.remediationPhase)}</td>`;
    tbody.appendChild(row);
  });
  renderPagination('policiesPagination',filteredPolicies.length,policyPage,policyPageSize,pg=>{policyPage=pg;renderPoliciesTable();});
}

filterPolicies();

// ── Violations Table ──────────────────────────────────────────────────────────
const VIOLATIONS=POLICIES.filter(p=>p.outcome==='NonCompliant'||p.outcome==='PartiallyCompliant');
let filteredViolations=[];
let violPage=1;
const violPageSize=15;
let violFilter='all';

function setViolFilter(f,btn){
  violFilter=f;
  document.querySelectorAll('#page-violations .filter-btn').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  filterViolations();
}

function filterViolations(){
  const q=(document.getElementById('violSearch')?.value||'').toLowerCase();
  filteredViolations=VIOLATIONS.filter(p=>{
    const matchF=violFilter==='all'||(violFilter==='NonCompliant'&&p.outcome==='NonCompliant')
      ||(violFilter==='PartiallyCompliant'&&p.outcome==='PartiallyCompliant')
      ||(violFilter==='Critical'&&p.riskTier==='Critical')
      ||(violFilter==='High'&&p.riskTier==='High');
    const matchQ=!q||(p.policyName||'').toLowerCase().includes(q)||(p.gap||'').toLowerCase().includes(q);
    return matchF&&matchQ;
  });
  filteredViolations.sort((a,b)=>(riskOrder[a.riskTier]??9)-(riskOrder[b.riskTier]??9)||(phaseOrder[a.remediationPhase]??9)-(phaseOrder[b.remediationPhase]??9));
  violPage=1;renderViolationsTable();
}

function renderViolationsTable(){
  const start=(violPage-1)*violPageSize;
  const pageItems=filteredViolations.slice(start,start+violPageSize);
  const tbody=document.getElementById('violationsTbody');
  tbody.innerHTML='';
  pageItems.forEach(p=>{
    const idx=POLICIES.indexOf(p);
    const row=document.createElement('tr');
    row.onclick=()=>openPolicy(idx);
    row.innerHTML=`<td style="font-family:var(--mono);font-size:10px;color:var(--muted);white-space:nowrap">${escH(p.policyId)}</td>
      <td class="policy-name-cell">${escH(p.policyName)}</td>
      <td style="color:var(--muted2);white-space:nowrap">${escH(p.policySetName)}</td>
      <td><span class="outcome-badge ob-${escH(p.outcome)}">${escH(p.outcome==='NonCompliant'?'Violation':'Partial')}</span></td>
      <td><span class="risk-badge rb-${escH(p.riskTier)}">${escH(p.riskTier)}</span></td>
      <td style="color:var(--muted2);font-size:11px;white-space:nowrap">${escH(p.remediationPhase)}</td>`;
    tbody.appendChild(row);
  });
  renderPagination('violationsPagination',filteredViolations.length,violPage,violPageSize,pg=>{violPage=pg;renderViolationsTable();});
}
filterViolations();

// ── Pagination helper ─────────────────────────────────────────────────────────
function renderPagination(containerId,total,currentPage,pageSize,onPage){
  const container=document.getElementById(containerId);
  const totalPages=Math.ceil(total/pageSize);
  if(totalPages<=1){container.innerHTML='';return;}
  let html=`<span style="margin-right:8px">${total} items</span>`;
  for(let i=1;i<=totalPages;i++){
    html+=`<button class="pg-btn${i===currentPage?' active':''}" onclick="(${onPage})(${i})">${i}</button>`;
  }
  container.innerHTML=html;
}

// ── Detail Drawer ─────────────────────────────────────────────────────────────
let drawerList=[];
let currentDrawerIndex=0;

function openPolicy(idx){
  drawerList=filteredPolicies.length>0?filteredPolicies:POLICIES;
  const p=POLICIES[idx];
  currentDrawerIndex=drawerList.indexOf(p);
  if(currentDrawerIndex===-1){drawerList=POLICIES;currentDrawerIndex=idx;}
  populateDrawer(p);
  document.getElementById('detailPanel').classList.add('open');
}

function openViolation(idx){
  drawerList=filteredViolations;
  const p=VIOLATIONS[idx];
  currentDrawerIndex=drawerList.indexOf(p);
  if(currentDrawerIndex===-1){drawerList=VIOLATIONS;currentDrawerIndex=idx;}
  populateDrawer(p);
  document.getElementById('detailPanel').classList.add('open');
}

function populateDrawer(p){
  if(!p) return;
  document.getElementById('drawerTitle').textContent=p.policyName||'Policy Detail';
  document.getElementById('drawerChips').innerHTML=`
    <span class="outcome-badge ob-${escH(p.outcome)}">${escH(p.outcome)}</span>
    <span class="risk-badge rb-${escH(p.riskTier)}">${escH(p.riskTier)}</span>
    <span style="font-size:10px;background:var(--surface3);color:var(--muted);padding:2px 8px;border-radius:20px;font-family:var(--mono)">${escH(p.policyId)}</span>
    <span style="font-size:10px;background:var(--surface3);color:var(--muted);padding:2px 8px;border-radius:20px">${escH(p.remediationPhase)}</span>
  `;
  document.getElementById('drawerStatement').textContent=p.policyStatement||'';
  document.getElementById('drawerContext').textContent=p.context||'';
  document.getElementById('drawerEvidence').textContent=p.evidence||'';
  document.getElementById('drawerCurrentState').textContent=p.currentState||'';
  document.getElementById('drawerGap').textContent=p.gap||'';
  document.getElementById('drawerRisk').textContent=p.businessRisk||'';
  document.getElementById('drawerTarget').textContent=p.targetState||'';
  document.getElementById('drawerTransition').textContent=p.transitionGuidance||'';
  document.getElementById('drawerSuccess').textContent=p.successMeasure||'';
  document.getElementById('drawerCount').textContent=`${currentDrawerIndex+1} / ${drawerList.length}`;
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
  const phases=['Immediate','0-30 Days','31-60 Days','61-90 Days','Strategic'];
  const phaseIcons={'Immediate':'🚨','0-30 Days':'🔥','31-60 Days':'⚡','61-90 Days':'📈','Strategic':'🎯'};
  const phaseColors={'Immediate':'var(--red)','0-30 Days':'var(--red)','31-60 Days':'var(--amber)','61-90 Days':'var(--accent)','Strategic':'var(--green)'};
  phases.forEach(phase=>{
    const items=POLICIES.filter(p=>p.remediationPhase===phase&&(p.outcome==='NonCompliant'||p.outcome==='PartiallyCompliant'));
    if(!items.length&&phase!=='Immediate') return;
    const col=document.createElement('div');
    col.innerHTML=`<div class="roadmap-col-header">
      <span style="font-size:18px">${phaseIcons[phase]}</span>
      <span class="roadmap-col-label" style="color:${phaseColors[phase]}">${escH(phase)}</span>
      <span class="roadmap-count">${items.length}</span>
    </div>`;
    items.sort((a,b)=>(riskOrder[a.riskTier]??9)-(riskOrder[b.riskTier]??9));
    items.forEach(p=>{
      const idx=POLICIES.indexOf(p);
      col.innerHTML+=`<div class="roadmap-item" onclick="openPolicy(${idx})">
        <div class="roadmap-item-title">${escH(p.policyName)}</div>
        <div class="roadmap-item-meta">
          <span class="risk-badge rb-${escH(p.riskTier)}" style="font-size:9px">${escH(p.riskTier)}</span>
          <span class="outcome-badge ob-${escH(p.outcome)}" style="font-size:9px">${escH(p.outcome==='NonCompliant'?'Violation':'Partial')}</span>
          <span style="font-size:9px;color:var(--muted)">${escH(p.policySetName)}</span>
        </div>
      </div>`;
    });
    if(items.length===0) col.innerHTML+=`<div style="font-size:11px;color:var(--green);padding:10px 0">✓ No violations in this phase</div>`;
    grid.appendChild(col);
  });
}

// ── Policy Catalog ────────────────────────────────────────────────────────────
function renderCatalog(){
  const list=document.getElementById('catalogList');
  if(list.innerHTML) return;
  POLICY_SETS.forEach(ps=>{
    const setPolicies=POLICIES.filter(p=>p.policySetId===ps.id);
    let policyRows=setPolicies.map(p=>{
      const idx=POLICIES.indexOf(p);
      return `<div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-top:1px solid var(--border);cursor:pointer" onclick="openPolicy(${idx})">
        <span style="font-family:var(--mono);font-size:10px;color:var(--muted);min-width:50px;padding-top:2px">${escH(p.policyId)}</span>
        <div style="flex:1">
          <div style="font-size:11px;font-weight:600;color:var(--text);margin-bottom:2px">${escH(p.policyName)}</div>
          <div style="font-size:10px;color:var(--muted2);margin-bottom:4px;font-style:italic">${escH(p.policyStatement)}</div>
        </div>
        <span class="outcome-badge ob-${escH(p.outcome)}" style="flex-shrink:0">${escH(p.outcome==='NonCompliant'?'Violation':p.outcome==='PartiallyCompliant'?'Partial':p.outcome)}</span>
      </div>`;
    }).join('');
    list.innerHTML+=`<div class="pset-detail-card">
      <div class="pset-detail-name">${escH(ps.icon)} ${escH(ps.name)}</div>
      <div class="pset-detail-desc">${escH(ps.description)}</div>
      <div style="margin-top:10px">${policyRows}</div>
    </div>`;
  });
}

// ── CSV Export ────────────────────────────────────────────────────────────────
function exportPoliciesCSV(){
  const fields=['policyId','policyName','policySetName','outcome','riskTier','remediationPhase','policyStatement','evidence','currentState','gap','businessRisk','targetState','transitionGuidance','successMeasure'];
  const header=fields.join(',');
  const rows=(filteredPolicies.length>0?filteredPolicies:POLICIES).map(p=>fields.map(k=>'"'+(String(p[k]||'')).replace(/"/g,'""')+'"').join(','));
  const csv=[header,...rows].join('\r\n');
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download='EntraIdentityPolicyCompliance.csv';
  a.click();
  showToast('Policy data exported as CSV');
}

// ── Nav hooks for lazy render ─────────────────────────────────────────────────
document.querySelectorAll('.nav-btn').forEach(btn=>{
  const orig=btn.onclick;
  btn.addEventListener('click',()=>{
    const pg=btn.getAttribute('onclick');
    if(pg&&pg.includes('page-policysets')) renderPolicySets();
    if(pg&&pg.includes('page-catalog')) renderCatalog();
  });
});

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='/'&&!e.target.matches('input')){
    e.preventDefault();
    const s=document.getElementById('policySearch');if(s)s.focus();
  }
  if(document.getElementById('detailPanel').classList.contains('open')){
    if(e.key==='ArrowLeft') navDrawer(-1);
    if(e.key==='ArrowRight') navDrawer(1);
  }
});
</script>
</body>
</html>
'@

        # ── Inject data ───────────────────────────────────────────────────────────
        $html = $html `
            -replace '__TENANT_NAME__', $TenantName `
            -replace '__TENANT_ID__', $TenantId `
            -replace '__ASSESSMENT_DATE__', $AssessmentDate `
            -replace '__OVERALL_SCORE__', $OverallScore `
            -replace '__RING_COLOR__', $ringColor `
            -replace '__RING_DASH__', $ringDash `
            -replace '__RING_GAP__', $ringGap `
            -replace '__TOTAL_POLICIES__', $totalPolicies `
            -replace '__TOTAL_COMPLIANT__', $totalCompliant `
            -replace '__TOTAL_NONCOMPLIANT__', $totalNonCompliant `
            -replace '__TOTAL_PARTIAL__', $totalPartial `
            -replace '__TOTAL_EXEMPT__', $totalExempt `
            -replace '__TOTAL_CRITICAL__', $totalCritical `
            -replace '__POLICY_SETS_JSON__', $PolicySetsJson `
            -replace '__POLICIES_JSON__', $PoliciesJson

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
            schemaVersion          = "1.0"
            assessmentTool         = "Get-EntraIdentityPolicyAsCode"
            assessmentDate         = $AssessmentDate
            tenantName             = $TenantName
            tenantId               = $TenantId
            overallComplianceScore = $OverallScore
            totalPolicies          = $script:Policies.Count
            compliantPolicies      = ($script:Policies | Where-Object { $_.Outcome -eq "Compliant" }).Count
            nonCompliantPolicies   = ($script:Policies | Where-Object { $_.Outcome -eq "NonCompliant" }).Count
            partialPolicies        = ($script:Policies | Where-Object { $_.Outcome -eq "PartiallyCompliant" }).Count
            exemptPolicies         = ($script:Policies | Where-Object { $_.Outcome -eq "Exempt" }).Count
            policySets             = $script:PolicySets
            policies               = $script:Policies
            violations             = $script:Violations
        }

        $exportObj | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
    }

    #endregion

    #region ── Script Execution ───────────────────────────────────────────────────

    Clear-Host

    # ── Banner ────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "  ║      Entra ID Identity Policy as Code Evaluator  v1.0        ║" -ForegroundColor Magenta
    Write-Host "  ║      Policy Compliance Engine — Enterprise Identity          ║" -ForegroundColor Magenta
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
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
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkMagenta
    Write-Host "  │   STEP 1  ›  Authenticating to Entra ID                     │" -ForegroundColor DarkMagenta
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkMagenta
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

    # ── Step 1.1: Validate Required Permissions ───────────────────────────────────
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
        "EntitlementManagement.Read.All"
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
        Write-Host "  Evaluation will continue with available permissions." -ForegroundColor Yellow
        Write-Host "  Some policy evaluations may be marked Exempt due to missing data." -ForegroundColor Yellow
        Write-Host ""
    }
    else {
        Write-Host "  ✅ All required Microsoft Graph permissions validated." -ForegroundColor Green
    }

    Write-Host ""

    # ── Step 2: Tenant Baseline ───────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkMagenta
    Write-Host "  │   STEP 2  ›  Collecting Tenant Baseline                     │" -ForegroundColor DarkMagenta
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkMagenta
    Write-Host ""
    Write-Host "  ⏳ Retrieving tenant organisation data..." -ForegroundColor Yellow

    $orgData = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/organization?`$select=id,displayName,verifiedDomains,assignedPlans,createdDateTime"
    $tenantName = "Unknown"
    if ($orgData -and $orgData.value -and $orgData.value.Count -gt 0) { $tenantName = $orgData.value[0].displayName }
    elseif ($orgData -and $orgData.displayName) { $tenantName = $orgData.displayName }

    Write-Host "  ✅ Tenant: $tenantName ($TenantId)" -ForegroundColor Green
    Write-Host ""

    # ── Step 3: Policy Evaluation ─────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkMagenta
    Write-Host "  │   STEP 3  ›  Evaluating Identity Policies (8 Policy Sets)   │" -ForegroundColor DarkMagenta
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkMagenta
    Write-Host ""

    Invoke-PolicySet1-PrivilegedAccess
    Invoke-PolicySet2-Authentication
    Invoke-PolicySet3-ConditionalAccess
    Invoke-PolicySet4-AppGovernance
    Invoke-PolicySet5-WorkloadIdentities
    Invoke-PolicySet6-ExternalIdentities
    Invoke-PolicySet7-HighRiskPermissions
    Invoke-PolicySet8-LifecycleGovernance

    Write-Host ""
    Write-Host "  ✅ All 8 policy set evaluations complete." -ForegroundColor Green
    Write-Host ""

    # ── Step 4: Score ─────────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkMagenta
    Write-Host "  │   STEP 4  ›  Computing Compliance Score                     │" -ForegroundColor DarkMagenta
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkMagenta
    Write-Host ""

    $overallScore = Get-OverallComplianceScore
    $totalCompliant = ($script:Policies | Where-Object { $_.Outcome -eq "Compliant" }).Count
    $totalNonCompliant = ($script:Policies | Where-Object { $_.Outcome -eq "NonCompliant" }).Count
    $totalPartial = ($script:Policies | Where-Object { $_.Outcome -eq "PartiallyCompliant" }).Count
    $totalCritical = ($script:Policies | Where-Object { $_.RiskTier -eq "Critical" -and $_.Outcome -eq "NonCompliant" }).Count

    Write-Host "  📊 Overall Compliance Score: $overallScore%" -ForegroundColor Cyan
    Write-Host "  ✅ Compliant: $totalCompliant  |  ✗ Non-Compliant: $totalNonCompliant  |  ~ Partial: $totalPartial" -ForegroundColor Gray
    Write-Host "  🔴 Critical Violations: $totalCritical" -ForegroundColor Gray
    Write-Host ""

    # ── Step 5: Export ─────────────────────────────────────────────────────────────
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkMagenta
    Write-Host "  │   STEP 5  ›  Generating Reports                             │" -ForegroundColor DarkMagenta
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkMagenta
    Write-Host ""

    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $htmlPath = Join-Path $OutputPath "EntraIdentityPolicyAsCode_$timestamp.html"
    $jsonPath = Join-Path $OutputPath "EntraIdentityPolicyAsCode_$timestamp.json"
    $assessDate = (Get-Date).ToString("dd MMM yyyy HH:mm")

    Write-Host "  ⏳ Building HTML Policy Compliance Dashboard..." -ForegroundColor Yellow
    $policySetsJson = Build-PolicySetsJson
    $policiesJson = Build-PoliciesJson

    Generate-HtmlDashboard `
        -TenantName    $tenantName `
        -TenantId      $TenantId `
        -OverallScore  $overallScore `
        -AssessmentDate $assessDate `
        -PolicySetsJson $policySetsJson `
        -PoliciesJson  $policiesJson `
        -OutputFilePath $htmlPath

    Write-Host "  ✅ HTML dashboard written → $htmlPath" -ForegroundColor Green

    Write-Host "  ⏳ Exporting JSON policy evaluation..." -ForegroundColor Yellow
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

    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "  ║                 POLICY EVALUATION SUMMARY                    ║" -ForegroundColor Magenta
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Magenta
    Write-Host "  ║  🏛️  Tenant                : $($tenantName.PadRight(30))║" -ForegroundColor White
    Write-Host "  ║  📊 Compliance Score       : $("$overallScore%".PadRight(30))║" -ForegroundColor Cyan
    Write-Host "  ║  ✅ Compliant Policies      : $($totalCompliant.ToString().PadRight(30))║" -ForegroundColor Green
    Write-Host "  ║  ✗  Non-Compliant Policies  : $($totalNonCompliant.ToString().PadRight(30))║" -ForegroundColor Red
    Write-Host "  ║  ~  Partially Compliant     : $($totalPartial.ToString().PadRight(30))║" -ForegroundColor Yellow
    Write-Host "  ║  🔴 Critical Violations     : $($totalCritical.ToString().PadRight(30))║" -ForegroundColor Red
    Write-Host "  ║  📋 Total Policies          : $(($script:Policies.Count).ToString().PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  🕐 Started               : $($scriptStartTime.ToString('hh:mm:ss tt').PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  🕑 Ended                 : $($scriptEndTime.ToString('hh:mm:ss tt').PadRight(30))║" -ForegroundColor Gray
    Write-Host "  ║  ⏱️ Duration               : $($executionTime.ToString('hh\:mm\:ss').PadRight(30))║" -ForegroundColor Yellow
    Write-Host "  ║  🌐 HTML Dashboard        : $(('...' + $htmlPath.Substring([Math]::Max(0,$htmlPath.Length-27))).PadRight(30))║" -ForegroundColor Green
    Write-Host "  ║  📄 JSON Export           : $(('...' + $jsonPath.Substring([Math]::Max(0,$jsonPath.Length-27))).PadRight(30))║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""

    #endregion
}
