<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 22 August 2026
Modified-On     : 22 August 2026

.SYNOPSIS
    Analyzes the blast radius of a compromised Entra ID identity by tracing all
    relationships, attack paths, affected resources, and risk exposure, then
    generates a prioritized remediation dashboard and CSV report.

.DESCRIPTION
    This script implements a Zero Trust threat-modeling capability for Entra ID.
    It accepts a target identity (User, Group, Service Principal, or Application)
    and performs a structured blast-radius assessment by traversing the full
    identity relationship graph from that single point of compromise:

        Identity → Group Membership → Directory Roles → Azure RBAC Roles
                → Application Permissions → API Delegated Scopes
                → Owned Applications → Owned Service Principals → Owned Devices

    For each discovered relationship the script:
        1. Classifies the relationship as Evidence (raw data from Graph)
        2. Maps it to an attack path (Relationship)
        3. Assigns a risk tier: Critical / High / Medium / Low / Informational
        4. Calculates an aggregate blast-radius score (0–100)
        5. Produces prioritized remediation actions
        6. Exports a machine-readable CSV and a browser-ready HTML dashboard

    ASSESSMENT FRAMEWORK (architect thinking pattern):
        Business Problem  → Who or what is the identity and what can it touch?
        Current State     → All live relationships, roles, permissions, and resources
        Risk / Gap        → Which relationships violate Zero Trust / least-privilege?
        Target State      → Clean identity with minimal, just-in-time, scoped access
        Transition        → Ordered remediation actions with owner and priority
        Success Metrics   → Blast-radius score drops to 0–20 (Green), MFA enforced,
                            no standing privileged roles, no broad API scopes

    AUTHENTICATION:
        Mode 1 — Client Credentials (BYOT / app registration)
                  Supply -ClientId, -ClientSecret (SecureString), -TenantId
        Mode 2 — Bring-Your-Own-Token (interactive or CI/CD token injection)
                  Supply -AccessToken and -TenantId (no client secret required)

    OUTPUT:
        CSV  → One row per relationship finding with all risk fields
        HTML → Enterprise-grade interactive dashboard (requires -GenerateDashboard)
               Sections: Executive Summary | Evidence | Relationship Map |
                         Blast Radius | Risk Register | Remediation Plan

.PARAMETER ClientId
    The Application (client) ID of the Azure AD app registration used for
    app-only (client credentials) authentication.
    Required when -AccessToken is not provided.

.PARAMETER ClientSecret
    The client secret of the Azure AD app registration, supplied as a
    SecureString. Example:
        $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    Required when -AccessToken is not provided.

.PARAMETER TenantId
    The Directory (tenant) ID of the Entra ID tenant to assess.
    Always required.

.PARAMETER AccessToken
    A pre-obtained Microsoft Graph bearer token (BYOT mode). When supplied,
    -ClientId and -ClientSecret are not required. The token must have the
    permissions listed in the Pre-Requisites section.

.PARAMETER TargetIdentityId
    The object ID (GUID) of the identity to assess. Supports Users, Groups,
    Service Principals, and Applications.
    Mutually exclusive with -TargetUserPrincipalName.

.PARAMETER TargetUserPrincipalName
    The UPN (e.g. user@contoso.com) of the user to assess. The script
    resolves this to an object ID before beginning the assessment.
    Mutually exclusive with -TargetIdentityId.

.PARAMETER IncludeEligibleRoles
    Switch. When supplied, also traces PIM-eligible directory-role assignments
    in addition to active assignments. Requires Entra ID P2. If the tenant
    lacks P2 licensing the eligible-role query is skipped with a warning and
    active-only results are still returned.

.PARAMETER IncludeAzureRBAC
    Switch. When supplied, also queries Azure RBAC role assignments at the
    subscription scope for the target identity. Requires
    Management.ReadWrite (or Reader) on the subscription and the
    AZURE_SUBSCRIPTION_ID environment variable, or the
    -SubscriptionId parameter.

.PARAMETER SubscriptionId
    Optional Azure subscription ID used when -IncludeAzureRBAC is supplied.
    If omitted, the script reads the AZURE_SUBSCRIPTION_ID environment
    variable. If neither is set, Azure RBAC collection is skipped with a
    warning.

.PARAMETER OutputPath
    Directory where output files are written.
    Default: C:\Temp\BlastRadius\

.PARAMETER GenerateDashboard
    Switch. When supplied, generates an interactive HTML dashboard alongside
    the CSV export. The dashboard is opened automatically in the default
    browser unless -NoBrowserLaunch is also set.

.PARAMETER NoBrowserLaunch
    Switch. Prevents the auto-launch of the HTML dashboard after generation.
    Has no effect if -GenerateDashboard is not supplied.

.PARAMETER ShowHelp
    Displays a friendly plain-language usage guide and exits immediately.
    No authentication is attempted when this switch is used.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        CSV file:  <OutputPath>\BlastRadius-<ObjectId>-<Timestamp>.csv
        HTML file: <OutputPath>\BlastRadius-<ObjectId>-<Timestamp>.html
                   (only when -GenerateDashboard is supplied)

.EXAMPLE
    Get-EntraIdentityBlastRadiusAssessment -ShowHelp

    Displays the usage guide and exits without connecting.

.EXAMPLE
    $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    Get-EntraIdentityBlastRadiusAssessment `
        -ClientId   "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId   "f4310b4f-xxxx" `
        -TargetUserPrincipalName "john.doe@contoso.com" `
        -GenerateDashboard

    Assesses the blast radius of john.doe@contoso.com and opens the HTML dashboard.

.EXAMPLE
    $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    Get-EntraIdentityBlastRadiusAssessment `
        -ClientId   "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantId   "f4310b4f-xxxx" `
        -TargetIdentityId "a1b2c3d4-xxxx" `
        -IncludeEligibleRoles `
        -IncludeAzureRBAC `
        -GenerateDashboard

    Full assessment including PIM-eligible roles and Azure RBAC for a service principal.

.EXAMPLE
    # BYOT mode — pipe in a token obtained externally (e.g. from az account get-access-token)
    Get-EntraIdentityBlastRadiusAssessment `
        -AccessToken $myToken `
        -TenantId    "f4310b4f-xxxx" `
        -TargetUserPrincipalName "svc-deploy@contoso.com" `
        -GenerateDashboard -NoBrowserLaunch

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (22-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Azure AD App Registration with admin-consented Graph API permissions:
               User.Read.All                          (Application)
               Group.Read.All                         (Application)
               Directory.Read.All                     (Application)
               Application.Read.All                   (Application)
               RoleManagement.Read.Directory          (Application)
               AuditLog.Read.All                      (Application)  — sign-in activity
               AppRoleAssignment.ReadWrite.All         (Application)  — app permissions

        2. For -IncludeAzureRBAC: the app or token identity must have at minimum
           Reader on the target subscription (Microsoft.Authorization/roleAssignments/read).

        3. Entra ID P1 or P2 for sign-in activity. P2 only required for
           -IncludeEligibleRoles (PIM).

        4. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  →  If -ShowHelp: print guide and exit
        Step 1  →  Authenticate (BYOT or Client Credentials)
        Step 2  →  Resolve target identity (UPN → ObjectId if needed)
        Step 3  →  Collect Evidence layers:
                       3a. Identity profile + sign-in activity
                       3b. Group memberships (transitive)
                       3c. Directory role assignments (active + eligible)
                       3d. Application role assignments (app permissions)
                       3e. Delegated OAuth2 permission grants
                       3f. Owned objects (apps, service principals, devices)
                       3g. Azure RBAC roles (if -IncludeAzureRBAC)
        Step 4  →  Build Relationship map (attack paths)
        Step 5  →  Risk-classify each finding
        Step 6  →  Calculate blast-radius score
        Step 7  →  Generate prioritized remediation plan
        Step 8  →  Export CSV
        Step 9  →  Generate HTML dashboard (if -GenerateDashboard)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the /beta Graph endpoint. Beta APIs may change without notice.
        - Azure RBAC collection is subscription-scoped. Management-group or
          resource-group-only assignments at higher/lower scopes are not queried
          unless those scopes are also subscriptions passed via -SubscriptionId.
        - PIM for Groups (group-based privileged access) is not in scope for v1.0.
        - Cross-tenant application permissions are flagged but not traversed.
        - The blast-radius score is a weighted heuristic; it is not a CVSSv3 score.
        - Client secret is marshaled to plaintext only transiently within
          RequestAccessToken and scrubbed immediately after (ZeroFreeBSTR).

.LINK
    Microsoft Graph API - User
    https://learn.microsoft.com/en-us/graph/api/user-get

.LINK
    Microsoft Graph API - transitiveMemberOf
    https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof

.LINK
    Microsoft Graph API - roleAssignmentScheduleInstances
    https://learn.microsoft.com/en-us/graph/api/resources/unifiedroleassignmentscheduleinstance

.LINK
    Microsoft Graph API - appRoleAssignments
    https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto

.LINK
    Azure REST API - Role Assignments
    https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list

#>


Function Get-EntraIdentityBlastRadiusAssessment {
  [CmdletBinding(DefaultParameterSetName = "ClientCredentials")]
  param (

    # ── Authentication — Client Credentials ──────────────────────────────────
    [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
    [System.Security.SecureString]$ClientSecret,

    # ── Authentication — BYOT ────────────────────────────────────────────────
    [Parameter(Mandatory = $true, ParameterSetName = "BYOT")]
    [ValidateNotNullOrEmpty()]
    [string]$AccessToken,

    # ── Always required ───────────────────────────────────────────────────────
    [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
    [Parameter(Mandatory = $true, ParameterSetName = "BYOT")]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    # ── Target identity ───────────────────────────────────────────────────────
    [Parameter(ParameterSetName = "ClientCredentials")]
    [Parameter(ParameterSetName = "BYOT")]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TargetIdentityId,

    [Parameter(ParameterSetName = "ClientCredentials")]
    [Parameter(ParameterSetName = "BYOT")]
    [ValidateNotNullOrEmpty()]
    [string]$TargetUserPrincipalName,

    # ── Scope switches ────────────────────────────────────────────────────────
    [Parameter(ParameterSetName = "ClientCredentials")]
    [Parameter(ParameterSetName = "BYOT")]
    [switch]$IncludeEligibleRoles,

    [Parameter(ParameterSetName = "ClientCredentials")]
    [Parameter(ParameterSetName = "BYOT")]
    [switch]$IncludeAzureRBAC,

    [Parameter(ParameterSetName = "ClientCredentials")]
    [Parameter(ParameterSetName = "BYOT")]
    [string]$SubscriptionId,

    # ── Output ────────────────────────────────────────────────────────────────
    [Parameter(ParameterSetName = "ClientCredentials")]
    [Parameter(ParameterSetName = "BYOT")]
    [string]$OutputPath = "C:\Temp\BlastRadius",

    [Parameter(ParameterSetName = "ClientCredentials")]
    [Parameter(ParameterSetName = "BYOT")]
    [switch]$GenerateDashboard,

    [Parameter(ParameterSetName = "ClientCredentials")]
    [Parameter(ParameterSetName = "BYOT")]
    [switch]$NoBrowserLaunch,

    # ── Help ──────────────────────────────────────────────────────────────────
    [Parameter(ParameterSetName = "Help")]
    [switch]$ShowHelp
  )

  #─────────────────────────────────────────────────────────────────────────────
  #  REGION: Friendly Help
  #─────────────────────────────────────────────────────────────────────────────

  Function Show-FriendlyHelp {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║      Entra ID — Identity Blast Radius Assessment             ║" -ForegroundColor Cyan
    Write-Host "  ║                   Version 1.0  |  Help                       ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this script does:" -ForegroundColor Yellow
    Write-Host "    Traces every relationship, role, permission, and resource reachable"
    Write-Host "    from a single compromised Entra ID identity and produces a risk-rated"
    Write-Host "    blast-radius score with a prioritized remediation plan."
    Write-Host ""
    Write-Host "  Authentication:" -ForegroundColor Yellow
    Write-Host "    Mode 1 — App-only (client credentials):"
    Write-Host '      $secret = Read-Host -Prompt "Client secret" -AsSecureString'
    Write-Host '      Get-EntraIdentityBlastRadiusAssessment -ClientId <id> -ClientSecret $secret -TenantId <tid> ...'
    Write-Host ""
    Write-Host "    Mode 2 — Bring-Your-Own-Token (BYOT):"
    Write-Host '      Get-EntraIdentityBlastRadiusAssessment -AccessToken $myToken -TenantId <tid> ...'
    Write-Host ""
    Write-Host "  Target identity (supply one):" -ForegroundColor Yellow
    Write-Host "    -TargetUserPrincipalName  e.g. john.doe@contoso.com"
    Write-Host "    -TargetIdentityId         Object ID GUID (User, Group, SP, or App)"
    Write-Host ""
    Write-Host "  Optional switches:" -ForegroundColor Yellow
    Write-Host "    -IncludeEligibleRoles   Add PIM-eligible role assignments (needs Entra P2)"
    Write-Host "    -IncludeAzureRBAC       Add Azure RBAC roles (needs Reader on subscription)"
    Write-Host "    -SubscriptionId         Azure subscription ID for RBAC lookup"
    Write-Host "    -GenerateDashboard      Produce the interactive HTML dashboard"
    Write-Host "    -NoBrowserLaunch        Do not auto-open the dashboard after generation"
    Write-Host "    -OutputPath             Where to write output files (default: C:\Temp\BlastRadius\)"
    Write-Host ""
    Write-Host "  Required Graph API permissions (Application, admin-consented):" -ForegroundColor Yellow
    Write-Host "    User.Read.All, Group.Read.All, Directory.Read.All"
    Write-Host "    Application.Read.All, RoleManagement.Read.Directory"
    Write-Host "    AuditLog.Read.All, AppRoleAssignment.ReadWrite.All"
    Write-Host ""
    Write-Host "  For full documentation run:" -ForegroundColor Green
    Write-Host "    Get-Help Get-EntraIdentityBlastRadiusAssessment -Full"
    Write-Host ""
  }

  if ($ShowHelp) {
    Show-FriendlyHelp
    return
  }

  # Validate target identity — exactly one must be supplied
  if (-not $TargetIdentityId -and -not $TargetUserPrincipalName) {
    Write-Error "Supply either -TargetIdentityId or -TargetUserPrincipalName."
    return
  }
  if ($TargetIdentityId -and $TargetUserPrincipalName) {
    Write-Error "-TargetIdentityId and -TargetUserPrincipalName are mutually exclusive. Supply only one."
    return
  }

  #─────────────────────────────────────────────────────────────────────────────
  #  REGION: Token Management (Client Credentials path)
  #  Identical pattern to reference script — RequestAccessToken / ShouldRenewToken
  #  / RenewTokenIfNeeded live at script scope so they survive across function calls.
  #─────────────────────────────────────────────────────────────────────────────

  Function RequestAccessToken {
    $tokenEndpoint = "https://login.microsoftonline.com/$global:TenantId/oauth2/v2.0/token"

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($global:ClientSecretSecure)
    Try {
      $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

      $body = @{
        client_id     = $global:ClientId
        client_secret = $plainSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
      }
      $resp = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ErrorAction Stop
      $global:accessToken = $resp.access_token
      $global:tokenExpirationTime = (Get-Date).AddSeconds($resp.expires_in)
    }
    Finally {
      if ($bstr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
      $plainSecret = $null
      $body = $null
    }
  }

  Function ShouldRenewToken {
    if (-not $global:accessToken -or -not $global:tokenExpirationTime) { return $true }
    return (($global:tokenExpirationTime - (Get-Date)).TotalMinutes -lt $global:RefreshIntervalInMinutes)
  }

  Function RenewTokenIfNeeded {
    if (ShouldRenewToken) {
      Write-Host "  🔄 Refreshing access token..." -ForegroundColor Yellow
      RequestAccessToken
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

  #─────────────────────────────────────────────────────────────────────────────
  #  REGION: Graph Helper
  #─────────────────────────────────────────────────────────────────────────────

  Function Invoke-GraphRequest {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $true)]
      [string]$Uri,

      [string]$Method = "GET",

      [hashtable]$AdditionalHeaders = @{}
    )

    $allItems = New-Object System.Collections.ArrayList

    do {
      RenewTokenIfNeeded

      $headers = @{ "Authorization" = "Bearer $global:accessToken"; "ConsistencyLevel" = "eventual" }
      foreach ($key in $AdditionalHeaders.Keys) { $headers[$key] = $AdditionalHeaders[$key] }

      $skip = $false
      $response = $null

      do {
        Try {
          $raw = Invoke-WebRequest -Uri $Uri -Headers $headers -Method $Method -ErrorAction Stop
          $statusCode = $raw.StatusCode
        }
        Catch {
          $statusCode = $_.Exception.Response.StatusCode

          if ($statusCode -eq 429) {
            $retryAfter = $_.Exception.Response.Headers.Item("Retry-After")
            if (-not $retryAfter) { $retryAfter = 10 }
            Write-Host "  ⏸  Graph throttled — waiting $retryAfter s..." -ForegroundColor Yellow
            Start-Sleep -Seconds $retryAfter
          }
          elseif ($statusCode -eq 403) {
            Write-Warning "Graph returned 403 Forbidden for: $Uri — skipping (check API permissions)."
            $skip = $true
          }
          elseif ($statusCode -eq 404) {
            $skip = $true  # resource simply does not exist
          }
          else {
            Write-Warning "Graph error $statusCode for $Uri — $($_.Exception.Message)"
            $skip = $true
          }
        }
      } until (($statusCode -eq 200) -or $skip)

      if ($skip -or -not $raw) { break }

      $data = $raw.Content | ConvertFrom-Json

      if ($data.PSObject.Properties['value']) {
        $data.value | ForEach-Object { $null = $allItems.Add($_) }
      }
      else {
        # Single-object response (e.g. /users/{id})
        return $data
      }

      $Uri = if ($data.PSObject.Properties['@odata.nextLink']) { $data.'@odata.nextLink' } else { $null }

    } until (-not $Uri)

    return $allItems
  }

  #─────────────────────────────────────────────────────────────────────────────
  #  REGION: Risk Classification Engine
  #─────────────────────────────────────────────────────────────────────────────

  # Weighted blast-radius scoring table
  # Each finding category carries a base weight; multiplied by a severity factor.
  # Total score is clamped 0–100. Score bands:
  #   0–20  → Green  (Minimal exposure)
  #   21–40 → Blue   (Low)
  #   41–60 → Amber  (Medium)
  #   61–80 → Orange (High)
  #   81–100→ Red    (Critical)

  $script:RiskWeights = @{
    # Directory roles
    "Global Administrator"               = @{ Tier = "Critical"; Weight = 30 }
    "Privileged Role Administrator"      = @{ Tier = "Critical"; Weight = 28 }
    "Security Administrator"             = @{ Tier = "Critical"; Weight = 25 }
    "Application Administrator"          = @{ Tier = "Critical"; Weight = 24 }
    "Cloud Application Administrator"    = @{ Tier = "Critical"; Weight = 23 }
    "Exchange Administrator"             = @{ Tier = "High"; Weight = 18 }
    "SharePoint Administrator"           = @{ Tier = "High"; Weight = 18 }
    "User Administrator"                 = @{ Tier = "High"; Weight = 16 }
    "Authentication Administrator"       = @{ Tier = "High"; Weight = 16 }
    "Conditional Access Administrator"   = @{ Tier = "High"; Weight = 15 }
    "Intune Administrator"               = @{ Tier = "High"; Weight = 14 }
    "Groups Administrator"               = @{ Tier = "Medium"; Weight = 10 }
    "Teams Administrator"                = @{ Tier = "Medium"; Weight = 9 }
    "Directory Readers"                  = @{ Tier = "Low"; Weight = 3 }

    # App / OAuth scopes
    "Directory.ReadWrite.All"            = @{ Tier = "Critical"; Weight = 28 }
    "RoleManagement.ReadWrite.Directory" = @{ Tier = "Critical"; Weight = 27 }
    "User.ReadWrite.All"                 = @{ Tier = "Critical"; Weight = 25 }
    "Mail.ReadWrite"                     = @{ Tier = "High"; Weight = 18 }
    "Files.ReadWrite.All"                = @{ Tier = "High"; Weight = 16 }
    "Sites.FullControl.All"              = @{ Tier = "Critical"; Weight = 24 }
    "offline_access"                     = @{ Tier = "Medium"; Weight = 8 }
    "User.Read"                          = @{ Tier = "Low"; Weight = 2 }

    # Azure RBAC
    "Owner"                              = @{ Tier = "Critical"; Weight = 30 }
    "Contributor"                        = @{ Tier = "High"; Weight = 20 }
    "User Access Administrator"          = @{ Tier = "Critical"; Weight = 28 }
    "Reader"                             = @{ Tier = "Low"; Weight = 3 }
  }

  Function Get-RiskTier {
    param ([string]$Name)

    $entry = $script:RiskWeights[$Name]
    if ($entry) { return $entry.Tier }

    # Heuristic fallback — broad wildcard scopes
    if ($Name -match 'ReadWrite\.All|FullControl|\.All$') { return "High" }
    if ($Name -match 'Read\.All') { return "Medium" }
    return "Informational"
  }

  Function Get-RiskWeight {
    param ([string]$Name)

    $entry = $script:RiskWeights[$Name]
    if ($entry) { return $entry.Weight }
    if ($Name -match 'ReadWrite\.All|FullControl') { return 15 }
    if ($Name -match 'Read\.All') { return 5 }
    return 1
  }

  Function New-Finding {
    param (
      [string]$Layer,
      [string]$AttackPath,
      [string]$ResourceType,
      [string]$ResourceName,
      [string]$ResourceId,
      [string]$Permission,
      [string]$AssignmentType,
      [string]$Evidence,
      [string]$Remediation,
      [int]$RemediationPriority,
      [string]$RemediationOwner
    )

    $riskTier = Get-RiskTier   -Name $Permission
    $riskWeight = Get-RiskWeight  -Name $Permission

    return [PSCustomObject]@{
      Layer               = $Layer
      AttackPath          = $AttackPath
      ResourceType        = $ResourceType
      ResourceName        = $ResourceName
      ResourceId          = $ResourceId
      Permission          = $Permission
      AssignmentType      = $AssignmentType
      RiskTier            = $riskTier
      RiskWeight          = $riskWeight
      Evidence            = $Evidence
      Remediation         = $Remediation
      RemediationPriority = $RemediationPriority
      RemediationOwner    = $RemediationOwner
    }
  }

  #─────────────────────────────────────────────────────────────────────────────
  #  REGION: Evidence Collection Functions
  #─────────────────────────────────────────────────────────────────────────────

  Function Get-IdentityProfile {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $true)] [string]$ObjectId
    )

    Write-Verbose "Fetching identity profile for $ObjectId"

    # Try user first, then service principal, then group
    $profile = $null
    $identityType = "Unknown"

    Try {
      $profile = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/users/$($ObjectId)?`$select=id,displayName,userPrincipalName,mail,userType,accountEnabled,createdDateTime,onPremisesSyncEnabled,signInActivity,department,jobTitle,assignedLicenses"
      if ($profile -and $profile.id) {
        $identityType = "User"
      }
    }
    Catch { }

    if (-not $profile -or -not $profile.id) {
      Try {
        $profile = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($ObjectId)?`$select=id,displayName,appId,servicePrincipalType,accountEnabled,createdDateTime,appOwnerOrganizationId"
        if ($profile -and $profile.id) { $identityType = "ServicePrincipal" }
      }
      Catch { }
    }

    if (-not $profile -or -not $profile.id) {
      Try {
        $profile = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/groups/$($ObjectId)?`$select=id,displayName,groupTypes,securityEnabled,mailEnabled,membershipRule,isAssignableToRole"
        if ($profile -and $profile.id) { $identityType = "Group" }
      }
      Catch { }
    }

    if (-not $profile -or -not $profile.id) {
      Try {
        $profile = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/applications/$($ObjectId)?`$select=id,displayName,appId,createdDateTime,publisherDomain,signInAudience"
        if ($profile -and $profile.id) { $identityType = "Application" }
      }
      Catch { }
    }

    return [PSCustomObject]@{
      Profile      = $profile
      IdentityType = $identityType
    }
  }

  Function Resolve-UPNToObjectId {
    [CmdletBinding()]
    param ([string]$UserPrincipalName)

    $user = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/users/$([System.Uri]::EscapeDataString($UserPrincipalName))?`$select=id,displayName,userPrincipalName"
    if ($user -and $user.id) { return $user.id }
    return $null
  }

  Function Get-GroupMemberships {
    [CmdletBinding()]
    param (
      [string]$ObjectId,
      [string]$IdentityType
    )

    $endpoint = switch ($IdentityType) {
      "User" { "https://graph.microsoft.com/beta/users/$ObjectId/transitiveMemberOf?`$select=id,displayName,groupTypes,securityEnabled,isAssignableToRole" }
      "ServicePrincipal" { "https://graph.microsoft.com/beta/servicePrincipals/$ObjectId/transitiveMemberOf?`$select=id,displayName,groupTypes,securityEnabled,isAssignableToRole" }
      default { $null }
    }

    if (-not $endpoint) { return @() }
    return Invoke-GraphRequest -Uri $endpoint
  }

  Function Get-DirectoryRoleAssignments {
    [CmdletBinding()]
    param (
      [string]$ObjectId,
      [switch]$IncludeEligible
    )

    $findings = New-Object System.Collections.ArrayList

    # Role definitions — one call (cache for this run)
    if (-not $script:RoleDefinitionCache) {
      $script:RoleDefinitionCache = @{}
      $defs = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?`$select=id,displayName,isPrivileged"
      foreach ($d in $defs) {
        $script:RoleDefinitionCache[$d.id] = [PSCustomObject]@{
          DisplayName  = $d.displayName
          IsPrivileged = [bool]$d.isPrivileged
        }
      }
    }

    # Active assignments
    Try {
      $activeAssignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$ObjectId'&`$select=principalId,roleDefinitionId,directoryScopeId,assignmentType"
      foreach ($a in $activeAssignments) {
        $def = $script:RoleDefinitionCache[$a.roleDefinitionId]
        $name = if ($def) { $def.DisplayName } else { $a.roleDefinitionId }
        $scope = if ($a.directoryScopeId -eq "/") { "Tenant-Wide" } else { $a.directoryScopeId }

        $remediationPriority = if ((Get-RiskTier -Name $name) -in @("Critical", "High")) { 1 } else { 2 }

        $null = $findings.Add(
          (New-Finding `
            -Layer             "DirectoryRole" `
            -AttackPath        "Identity → DirectoryRole → $name ($scope)" `
            -ResourceType      "DirectoryRole" `
            -ResourceName      $name `
            -ResourceId        $a.roleDefinitionId `
            -Permission        $name `
            -AssignmentType    "Active" `
            -Evidence          "principalId=$ObjectId assigned roleDefinitionId=$($a.roleDefinitionId) scope=$scope" `
            -Remediation       "Remove active role assignment '$name'. If required, convert to PIM-eligible and require justification + MFA to activate." `
            -RemediationPriority $remediationPriority `
            -RemediationOwner  "Identity & Access Management Team"
                )
        )
      }
    }
    Catch {
      Write-Warning "Could not retrieve active role assignments: $($_.Exception.Message)"
    }

    # Eligible assignments (PIM)
    if ($IncludeEligible) {
      Try {
        $eligAssignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$ObjectId'&`$select=principalId,roleDefinitionId,directoryScopeId"
        foreach ($e in $eligAssignments) {
          $def = $script:RoleDefinitionCache[$e.roleDefinitionId]
          $name = if ($def) { $def.DisplayName } else { $e.roleDefinitionId }
          $scope = if ($e.directoryScopeId -eq "/") { "Tenant-Wide" } else { $e.directoryScopeId }

          $null = $findings.Add(
            (New-Finding `
              -Layer             "DirectoryRole" `
              -AttackPath        "Identity → PIM-EligibleRole → $name ($scope)" `
              -ResourceType      "DirectoryRole (Eligible)" `
              -ResourceName      $name `
              -ResourceId        $e.roleDefinitionId `
              -Permission        $name `
              -AssignmentType    "Eligible" `
              -Evidence          "principalId=$ObjectId eligible roleDefinitionId=$($e.roleDefinitionId) scope=$scope" `
              -Remediation       "Review PIM-eligible assignment '$name'. Enforce approval workflow, time-bound activations (max 4 hr), and MFA on activation." `
              -RemediationPriority 3 `
              -RemediationOwner  "Identity & Access Management Team"
                    )
          )
        }
      }
      Catch {
        Write-Warning "Could not retrieve PIM-eligible role assignments (Entra P2 required): $($_.Exception.Message)"
      }
    }

    return $findings
  }

  Function Get-AppRoleAssignments {
    [CmdletBinding()]
    param (
      [string]$ObjectId,
      [string]$IdentityType
    )

    $findings = New-Object System.Collections.ArrayList

    # App role assignments received by this identity (what apps it can call)
    $endpoint = switch ($IdentityType) {
      "User" { "https://graph.microsoft.com/beta/users/$ObjectId/appRoleAssignments" }
      "ServicePrincipal" { "https://graph.microsoft.com/beta/servicePrincipals/$ObjectId/appRoleAssignments" }
      default { $null }
    }

    if (-not $endpoint) { return $findings }

    Try {
      $assignments = Invoke-GraphRequest -Uri $endpoint
      foreach ($a in $assignments) {
        # Look up the resource service principal to get the role name
        $roleName = $a.roleId
        Try {
          $resourceSp = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($a.resourceId)?`$select=displayName,appRoles"
          $roleObj = $resourceSp.appRoles | Where-Object { $_.id -eq $a.roleId }
          $roleName = if ($roleObj) { $roleObj.value } else { $a.roleId }
          $resourceName = $resourceSp.displayName
        }
        Catch { $resourceName = $a.resourceId }

        $remediationPriority = if ((Get-RiskTier -Name $roleName) -in @("Critical", "High")) { 1 } else { 3 }

        $null = $findings.Add(
          (New-Finding `
            -Layer             "AppRoleAssignment" `
            -AttackPath        "Identity → AppRole → $resourceName → $roleName" `
            -ResourceType      "Application" `
            -ResourceName      $resourceName `
            -ResourceId        $a.resourceId `
            -Permission        $roleName `
            -AssignmentType    "AppRole" `
            -Evidence          "principalId=$ObjectId resourceId=$($a.resourceId) roleId=$($a.roleId)" `
            -Remediation       "Audit whether '$roleName' on '$resourceName' is still required. Remove if unused for >90 days. Apply least-privilege alternative." `
            -RemediationPriority $remediationPriority `
            -RemediationOwner  "Application Security Team"
                )
        )
      }
    }
    Catch {
      Write-Warning "Could not retrieve app role assignments: $($_.Exception.Message)"
    }

    return $findings
  }

  Function Get-DelegatedPermissions {
    [CmdletBinding()]
    param (
      [string]$ObjectId,
      [string]$IdentityType
    )

    $findings = New-Object System.Collections.ArrayList

    if ($IdentityType -ne "User") { return $findings }

    # OAuth2 permission grants (delegated, user-consented)
    Try {
      $grants = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/oauth2PermissionGrants?`$filter=principalId eq '$ObjectId'"
      foreach ($g in $grants) {
        $scopes = ($g.scope -split ' ') | Where-Object { $_ }
        $resourceName = $g.resourceId

        Try {
          $resourceSp = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($g.resourceId)?`$select=displayName"
          $resourceName = $resourceSp.displayName
        }
        Catch { }

        $remediationPriority = if ((Get-RiskTier -Name $scope) -in @("Critical", "High")) { 1 } else { 3 }

        foreach ($scope in $scopes) {
          $null = $findings.Add(
            (New-Finding `
              -Layer             "DelegatedPermission" `
              -AttackPath        "Identity → DelegatedOAuth2 → $resourceName → $scope" `
              -ResourceType      "Application" `
              -ResourceName      $resourceName `
              -ResourceId        $g.resourceId `
              -Permission        $scope `
              -AssignmentType    "Delegated ($($g.consentType))" `
              -Evidence          "principalId=$ObjectId consentType=$($g.consentType) scope=$scope resourceId=$($g.resourceId)" `
              -Remediation       "Revoke delegated '$scope' consent on '$resourceName'. Re-consent with narrower scope if still needed. Review All-Principal consents." `
              -RemediationPriority $remediationPriority `
              -RemediationOwner  "Application Security Team"
                    )
          )
        }
      }
    }
    Catch {
      Write-Warning "Could not retrieve delegated permission grants: $($_.Exception.Message)"
    }

    return $findings
  }

  Function Get-OwnedObjects {
    [CmdletBinding()]
    param (
      [string]$ObjectId,
      [string]$IdentityType
    )

    $findings = New-Object System.Collections.ArrayList

    $endpoint = switch ($IdentityType) {
      # "User" { "https://graph.microsoft.com/beta/users/$ObjectId/ownedObjects?`$select=id,displayName,@odata.type" }
      # "ServicePrincipal" { "https://graph.microsoft.com/beta/servicePrincipals/$ObjectId/ownedObjects?`$select=id,displayName,@odata.type" }

      "User" { "https://graph.microsoft.com/beta/users/$ObjectId/ownedObjects?`$select=id,displayName" }
      "ServicePrincipal" { "https://graph.microsoft.com/beta/servicePrincipals/$ObjectId/ownedObjects?`$select=id,displayName" }
      default { $null }
    }

    if (-not $endpoint) { return $findings }

    Try {
      $owned = Invoke-GraphRequest -Uri $endpoint
      foreach ($o in $owned) {
        $type = $o.'@odata.type' -replace '#microsoft.graph.', ''

        $null = $findings.Add(
          (New-Finding `
            -Layer             "OwnedObject" `
            -AttackPath        "Identity → Owns → $type → $($o.displayName)" `
            -ResourceType      $type `
            -ResourceName      $o.displayName `
            -ResourceId        $o.id `
            -Permission        "Owner" `
            -AssignmentType    "Ownership" `
            -Evidence          "principalId=$ObjectId ownsObjectId=$($o.id) type=$type" `
            -Remediation       "Review ownership of '$($o.displayName)' ($type). Ownership grants full control. Remove if not required or reassign to a break-glass account." `
            -RemediationPriority 2 `
            -RemediationOwner  "Application Security Team"
                )
        )
      }
    }
    Catch {
      Write-Warning "Could not retrieve owned objects: $($_.Exception.Message)"
    }

    return $findings
  }

  Function Get-OwnedDevices {
    [CmdletBinding()]
    param ([string]$ObjectId)

    $findings = New-Object System.Collections.ArrayList

    Try {
      $devices = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/users/$ObjectId/ownedDevices?`$select=id,displayName,operatingSystem,complianceState,isManaged,registrationDateTime"
      foreach ($d in $devices) {
        $null = $findings.Add(
          (New-Finding `
            -Layer             "OwnedDevice" `
            -AttackPath        "Identity → Device → $($d.displayName) ($($d.operatingSystem))" `
            -ResourceType      "Device" `
            -ResourceName      $d.displayName `
            -ResourceId        $d.id `
            -Permission        "DeviceOwner" `
            -AssignmentType    "Device Ownership" `
            -Evidence          "ownedDeviceId=$($d.id) OS=$($d.operatingSystem) Compliant=$($d.complianceState) Managed=$($d.isManaged)" `
            -Remediation       "Ensure device '$($d.displayName)' is compliant and managed. Enforce Conditional Access device compliance policy." `
            -RemediationPriority 3 `
            -RemediationOwner  "Endpoint Security Team"
                )
        )
      }
    }
    Catch {
      Write-Warning "Could not retrieve owned devices: $($_.Exception.Message)"
    }

    return $findings
  }

  Function Get-AzureRBACAssignments {
    [CmdletBinding()]
    param (
      [string]$ObjectId,
      [string]$SubscriptionId
    )

    $findings = New-Object System.Collections.ArrayList

    if (-not $SubscriptionId) {
      Write-Warning "No SubscriptionId supplied and AZURE_SUBSCRIPTION_ID env var not set — skipping Azure RBAC collection."
      return $findings
    }

    $armToken = $null

    # Try to swap Graph token for ARM token (only if client-credential mode)
    if ($global:ClientId -and $global:ClientSecretSecure) {
      $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($global:ClientSecretSecure)
      Try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        $body = @{
          client_id     = $global:ClientId
          client_secret = $plain
          scope         = "https://management.azure.com/.default"
          grant_type    = "client_credentials"
        }
        $tokenResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$global:TenantId/oauth2/v2.0/token" -Method POST -Body $body -ErrorAction Stop
        $armToken = $tokenResp.access_token
      }
      Finally {
        if ($bstr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $plain = $null
        $body = $null
      }
    }

    if (-not $armToken) {
      Write-Warning "Could not obtain an ARM token for Azure RBAC lookup — skipping. In BYOT mode supply an ARM-scoped token or use client-credential mode."
      return $findings
    }

    Try {
      $armHeaders = @{ "Authorization" = "Bearer $armToken" }
      $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$ObjectId'"
      $rbacResp = Invoke-RestMethod -Uri $uri -Headers $armHeaders -Method GET -ErrorAction Stop

      foreach ($ra in $rbacResp.value) {
        # Resolve role definition name
        $roleName = $ra.properties.roleDefinitionId
        Try {
          $roleDefUri = "https://management.azure.com$($ra.properties.roleDefinitionId)?api-version=2022-04-01"
          $roleDefResp = Invoke-RestMethod -Uri $roleDefUri -Headers $armHeaders -Method GET -ErrorAction Stop
          $roleName = $roleDefResp.properties.roleName
        }
        Catch { }

        $scope = $ra.properties.scope

        $remediationPriority = if ((Get-RiskTier -Name $roleName) -in @("Critical", "High")) { 1 } else { 2 }

        $null = $findings.Add(
          (New-Finding `
            -Layer             "AzureRBAC" `
            -AttackPath        "Identity → AzureRBAC → $roleName → $scope" `
            -ResourceType      "AzureSubscription" `
            -ResourceName      "Subscription: $SubscriptionId" `
            -ResourceId        $ra.id `
            -Permission        $roleName `
            -AssignmentType    "AzureRBAC" `
            -Evidence          "principalId=$ObjectId roleAssignmentId=$($ra.id) scope=$scope" `
            -Remediation       "Review Azure RBAC '$roleName' at scope '$scope'. Downscope to minimum required. Use PIM for Just-In-Time Azure role activation." `
            -RemediationPriority $remediationPriority `
            -RemediationOwner  "Cloud Platform Security Team"
                )
        )
      }
    }
    Catch {
      Write-Warning "Azure RBAC lookup failed: $($_.Exception.Message)"
    }

    return $findings
  }

  Function Get-ServicePrincipalAppPermissions {
    [CmdletBinding()]
    param ([string]$ObjectId)

    # For Service Principals: get the application permissions (app roles assigned TO this SP)
    $findings = New-Object System.Collections.ArrayList

    Try {
      $assignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/servicePrincipals/$ObjectId/appRoleAssignments"
      foreach ($a in $assignments) {
        $roleName = $a.roleId
        $resourceName = $a.resourceId

        Try {
          $resourceSp = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($a.resourceId)?`$select=displayName,appRoles"
          $roleObj = $resourceSp.appRoles | Where-Object { $_.id -eq $a.roleId }
          $roleName = if ($roleObj) { $roleObj.value } else { $a.roleId }
          $resourceName = $resourceSp.displayName
        }
        Catch { }

        $remediationPriority = if ((Get-RiskTier -Name $roleName) -in @("Critical", "High")) { 1 } else { 2 }

        $null = $findings.Add(
          (New-Finding `
            -Layer             "SPAppPermission" `
            -AttackPath        "Identity(SP) → AppPermission → $resourceName → $roleName" `
            -ResourceType      "Application" `
            -ResourceName      $resourceName `
            -ResourceId        $a.resourceId `
            -Permission        $roleName `
            -AssignmentType    "ApplicationPermission" `
            -Evidence          "servicePrincipalId=$ObjectId resourceId=$($a.resourceId) roleId=$($a.roleId)" `
            -Remediation       "Validate '$roleName' on '$resourceName' is consumed. Remove unused app permissions. Prefer delegated scopes over application permissions where possible." `
            -RemediationPriority $remediationPriority `
            -RemediationOwner  "Application Security Team"
                )
        )
      }
    }
    Catch {
      Write-Warning "Could not retrieve SP app permissions: $($_.Exception.Message)"
    }

    return $findings
  }

  #─────────────────────────────────────────────────────────────────────────────
  #  REGION: Blast Radius Score Calculator
  #─────────────────────────────────────────────────────────────────────────────

  Function Measure-BlastRadius {
    param ([System.Collections.ArrayList]$Findings)

    if (-not $Findings -or $Findings.Count -eq 0) { return 0 }

    $rawScore = 0
    foreach ($f in $Findings) {
      $rawScore += [int]$f.RiskWeight
    }

    # Cap at 100
    return [Math]::Min(100, $rawScore)
  }

  Function Get-BlastRadiusBand {
    param ([int]$Score)

    switch ($Score) {
      { $_ -le 20 } { return @{ Label = "Minimal"; Color = "#3fb950"; CssClass = "band-green" } }
      { $_ -le 40 } { return @{ Label = "Low"; Color = "#388bfd"; CssClass = "band-blue" } }
      { $_ -le 60 } { return @{ Label = "Medium"; Color = "#d29922"; CssClass = "band-amber" } }
      { $_ -le 80 } { return @{ Label = "High"; Color = "#f08030"; CssClass = "band-orange" } }
      default { return @{ Label = "Critical"; Color = "#f85149"; CssClass = "band-red" } }
    }
  }

  #─────────────────────────────────────────────────────────────────────────────
  #  REGION: MFA Status Helper
  #─────────────────────────────────────────────────────────────────────────────

  Function Get-MFAStatus {
    [CmdletBinding()]
    param ([string]$UserId)

    Try {
      $methods = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/users/$UserId/authentication/methods"
      $strongMethods = $methods | Where-Object {
        $_.'@odata.type' -match 'microsoftAuthenticator|fido2|windowsHelloForBusiness|softwareOath'
      }
      return @{
        HasMFA        = ([bool]($strongMethods.Count -gt 0))
        MethodCount   = $methods.Count
        StrongMethods = ($strongMethods | ForEach-Object { $_.'@odata.type' -replace '#microsoft.graph.', '' }) -join ', '
      }
    }
    Catch {
      return @{ HasMFA = $false; MethodCount = 0; StrongMethods = "Unknown (permission error)" }
    }
  }

  #─────────────────────────────────────────────────────────────────────────────
  #  REGION: HTML Dashboard Generator
  #─────────────────────────────────────────────────────────────────────────────

  Function ConvertTo-JsonSafe {
    param ([string]$Value)
    return [string]$Value `
      -replace '\\', '\\\\' `
      -replace '"', '\"'   `
      -replace "`r", ''     `
      -replace "`n", '\n'   `
      -replace "`t", '\t'   `
      -replace '<', '\u003c' `
      -replace '>', '\u003e' `
      -replace '&', '\u0026'
  }

  Function Generate-BlastRadiusDashboard {
    [CmdletBinding()]
    param (
      [PSCustomObject]$IdentityProfile,
      [string]$IdentityType,
      [System.Collections.ArrayList]$Findings,
      [System.Collections.ArrayList]$GroupMemberships,
      [int]$BlastRadiusScore,
      [hashtable]$BlastRadiusBand,
      [hashtable]$MFAStatus,
      [string]$AssessmentTimestamp,
      [string]$TenantId,
      [string]$OutputFilePath
    )

    # ── Pre-compute summary metrics ───────────────────────────────────────────
    $criticalCount = ($Findings | Where-Object { $_.RiskTier -eq "Critical" }).Count
    $highCount = ($Findings | Where-Object { $_.RiskTier -eq "High" }).Count
    $mediumCount = ($Findings | Where-Object { $_.RiskTier -eq "Medium" }).Count
    $lowCount = ($Findings | Where-Object { $_.RiskTier -eq "Low" }).Count
    $totalFindings = $Findings.Count
    $groupCount = $GroupMemberships.Count

    $displayName = ConvertTo-JsonSafe $IdentityProfile.displayName

    $upnValue = if ($IdentityProfile.userPrincipalName) { $IdentityProfile.userPrincipalName } else { $IdentityProfile.appId }
    $upn = ConvertTo-JsonSafe $upnValue

    $departmentValue = if ($IdentityProfile.department) { $IdentityProfile.department } else { "N/A" }
    $department = ConvertTo-JsonSafe $departmentValue

    $jobTitleValue = if ($IdentityProfile.jobTitle) { $IdentityProfile.jobTitle } else { "N/A" }
    $jobTitle = ConvertTo-JsonSafe $jobTitleValue

    $accountEnabled = if ($IdentityProfile.accountEnabled -eq $true) { "Yes" } elseif ($IdentityProfile.accountEnabled -eq $false) { "No" } else { "N/A" }
    $onPremSync = if ($IdentityProfile.onPremisesSyncEnabled) { "Yes" } else { "No" }
    $mfaLabel = if ($MFAStatus.HasMFA) { "Registered" } else { "NOT Registered ⚠️" }
    $mfaCss = if ($MFAStatus.HasMFA) { "c-green" } else { "c-red" }
    $bandColor = $BlastRadiusBand.Color
    $bandLabel = $BlastRadiusBand.Label

    # ── Serialize Findings to JSON ────────────────────────────────────────────
    $findingsJsonParts = New-Object System.Collections.ArrayList
    foreach ($f in $Findings) {
      $part = '{' +
      '"layer":"' + (ConvertTo-JsonSafe $f.Layer) + '",' +
      '"attackPath":"' + (ConvertTo-JsonSafe $f.AttackPath) + '",' +
      '"resourceType":"' + (ConvertTo-JsonSafe $f.ResourceType) + '",' +
      '"resourceName":"' + (ConvertTo-JsonSafe $f.ResourceName) + '",' +
      '"resourceId":"' + (ConvertTo-JsonSafe $f.ResourceId) + '",' +
      '"permission":"' + (ConvertTo-JsonSafe $f.Permission) + '",' +
      '"assignmentType":"' + (ConvertTo-JsonSafe $f.AssignmentType) + '",' +
      '"riskTier":"' + (ConvertTo-JsonSafe $f.RiskTier) + '",' +
      '"riskWeight":' + [int]$f.RiskWeight + ',' +
      '"evidence":"' + (ConvertTo-JsonSafe $f.Evidence) + '",' +
      '"remediation":"' + (ConvertTo-JsonSafe $f.Remediation) + '",' +
      '"remediationPriority":' + [int]$f.RemediationPriority + ',' +
      '"remediationOwner":"' + (ConvertTo-JsonSafe $f.RemediationOwner) + '"' +
      '}'
      $null = $findingsJsonParts.Add($part)
    }
    $findingsJson = '[' + ($findingsJsonParts -join ',') + ']'

    # ── Groups JSON ───────────────────────────────────────────────────────────
    $groupJsonParts = New-Object System.Collections.ArrayList
    foreach ($g in $GroupMemberships) {
      $gType = if ($g.isAssignableToRole) { "Role-Assignable" } elseif ($g.securityEnabled) { "Security" } else { "M365" }
      $part = '{"name":"' + (ConvertTo-JsonSafe $g.displayName) + '","type":"' + $gType + '","id":"' + (ConvertTo-JsonSafe $g.id) + '"}'
      $null = $groupJsonParts.Add($part)
    }
    $groupsJson = '[' + ($groupJsonParts -join ',') + ']'

    # ── SVG Donut math ────────────────────────────────────────────────────────
    $circumference = [Math]::Round(2 * [Math]::PI * 54, 2)   # r=54
    $scoreStroke = [Math]::Round(($BlastRadiusScore / 100) * $circumference, 2)
    $gapStroke = [Math]::Round($circumference - $scoreStroke, 2)

    # ── HTML here-string ──────────────────────────────────────────────────────
    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blast Radius Assessment — __DISPLAY_NAME__</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;
  --border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;
  --green:#3fb950;--amber:#d29922;--red:#f85149;--orange:#f08030;
  --text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);
}
body.light-theme{
  --bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;
  --border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;
  --green:#1a7f37;--amber:#b08000;--red:#cf222e;--orange:#c05a00;
  --text:#1f2328;--muted:#636c76;--muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--sans);background:var(--bg);color:var(--text);display:flex;min-height:100vh;font-size:14px}
a{color:var(--accent);text-decoration:none}
/* ── Sidebar ── */
#sidebar{
  position:fixed;top:0;left:0;bottom:0;width:240px;
  background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;z-index:200;overflow-y:auto;
}
.logo-block{padding:20px 16px 16px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;border-radius:8px;
  background:linear-gradient(135deg,var(--red) 0%,var(--accent3) 100%);
  display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:10px}
.logo-title{font-size:13px;font-weight:700;letter-spacing:.4px;line-height:1.3}
.logo-sub{font-size:10px;color:var(--muted);margin-top:2px;font-family:var(--mono)}
.ver-badge{display:inline-block;margin-top:6px;padding:2px 7px;
  border-radius:99px;background:var(--surface2);border:1px solid var(--border);
  font-size:10px;color:var(--muted2);font-family:var(--mono)}
.nav-section{padding:12px 8px}
.nav-label{font-size:10px;color:var(--muted);letter-spacing:.8px;
  text-transform:uppercase;padding:4px 8px 6px;font-weight:700}
.nav-btn{
  display:flex;align-items:center;gap:9px;padding:8px 12px;
  border-radius:var(--radius-sm);cursor:pointer;transition:background .15s;
  font-size:13px;color:var(--muted2);border:none;background:none;width:100%;text-align:left;
}
.nav-btn:hover{background:var(--surface2);color:var(--text)}
.nav-btn.active{
  background:rgba(56,139,253,.12);color:var(--accent);
  border-left:3px solid var(--accent);padding-left:9px;font-weight:600
}
.nav-icon{font-size:15px;width:18px;text-align:center}
.sidebar-footer{margin-top:auto;padding:14px 16px;border-top:1px solid var(--border);font-size:10px;color:var(--muted)}
.theme-toggle{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.toggle-pill{
  width:36px;height:20px;border-radius:99px;border:1px solid var(--border);
  background:var(--surface3);cursor:pointer;position:relative;transition:background .2s;
}
.toggle-pill::after{
  content:'';position:absolute;top:2px;left:2px;
  width:14px;height:14px;border-radius:50%;background:var(--muted2);transition:left .2s;
}
body.light-theme .toggle-pill::after{left:18px;background:var(--accent)}
/* ── Main ── */
#main{margin-left:240px;flex:1;min-height:100vh;padding:28px 28px 48px}
.page{display:none;animation:fadeIn .2s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
/* ── Header band ── */
.identity-header{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px 24px;margin-bottom:22px;
  display:flex;align-items:center;gap:18px;flex-wrap:wrap;
}
.id-avatar{width:52px;height:52px;border-radius:50%;
  background:linear-gradient(135deg,var(--accent) 0%,var(--accent3) 100%);
  display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0}
.id-name{font-size:18px;font-weight:700;margin-bottom:3px}
.id-upn{font-family:var(--mono);font-size:11px;color:var(--muted)}
.id-chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.chip{display:inline-block;padding:3px 10px;border-radius:99px;
  font-size:11px;font-family:var(--mono);border:1px solid var(--border);background:var(--surface2)}
.chip.c-red{border-color:var(--red);color:var(--red);background:rgba(248,81,73,.08)}
.chip.c-amber{border-color:var(--amber);color:var(--amber);background:rgba(210,153,34,.08)}
.chip.c-green{border-color:var(--green);color:var(--green);background:rgba(63,185,80,.08)}
.chip.c-blue{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.chip.c-purple{border-color:var(--accent3);color:var(--accent3);background:rgba(163,113,247,.08)}
/* ── Score ring ── */
.score-area{margin-left:auto;display:flex;flex-direction:column;align-items:center;gap:6px}
.score-ring{width:120px;height:120px}
.score-val{font-size:28px;font-weight:700;font-family:var(--mono);fill:var(--text)}
.score-lbl{font-size:10px;fill:var(--muted);font-family:var(--sans)}
/* ── Stat cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;margin-bottom:22px}
.stat-card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:16px;border-top:3px solid transparent;transition:transform .15s;
}
.stat-card:hover{transform:translateY(-2px)}
.stat-card.c-red{border-top-color:var(--red)}
.stat-card.c-amber{border-top-color:var(--amber)}
.stat-card.c-blue{border-top-color:var(--accent)}
.stat-card.c-green{border-top-color:var(--green)}
.stat-card.c-purple{border-top-color:var(--accent3)}
.stat-card.c-orange{border-top-color:var(--orange)}
.stat-val{font-size:28px;font-weight:700;font-family:var(--mono);margin-bottom:4px}
.stat-lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
/* ── Panel ── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px}
.panel-title{font-size:13px;font-weight:700;letter-spacing:.3px;margin-bottom:14px;
  display:flex;align-items:center;gap:8px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:18px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
/* ── Risk badge ── */
.risk{display:inline-block;padding:2px 9px;border-radius:4px;font-size:11px;font-family:var(--mono);font-weight:600}
.risk-critical{background:rgba(248,81,73,.15);color:var(--red)}
.risk-high{background:rgba(240,128,48,.15);color:var(--orange)}
.risk-medium{background:rgba(210,153,34,.15);color:var(--amber)}
.risk-low{background:rgba(56,139,253,.15);color:var(--accent)}
.risk-informational{background:rgba(125,133,144,.15);color:var(--muted2)}
/* ── Table ── */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:var(--surface2);color:var(--muted2);font-weight:600;
  padding:8px 12px;text-align:left;border-bottom:1px solid var(--border);
  cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:var(--text)}
th .sort-arrow{margin-left:4px;opacity:.4}
th.sort-active .sort-arrow{opacity:1}
td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top}
tr:hover td{background:var(--surface2)}
tr:last-child td{border-bottom:none}
.mono{font-family:var(--mono);font-size:11px}
.evidence-text{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer}
/* ── Toolbar ── */
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.search-wrap{position:relative;flex:1;min-width:180px}
.search-wrap input{
  width:100%;padding:7px 12px 7px 32px;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);
  color:var(--text);font-size:12px;font-family:var(--sans);
}
.search-wrap input:focus{outline:none;border-color:var(--accent)}
.search-icon{position:absolute;left:9px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px}
.filter-btn{
  padding:6px 13px;border-radius:var(--radius-sm);border:1px solid var(--border);
  background:var(--surface2);color:var(--muted2);cursor:pointer;font-size:12px;
  transition:all .15s;
}
.filter-btn:hover,.filter-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
/* ── Attack path row ── */
.path-row{display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)}
.path-row:last-child{border-bottom:none}
.path-line{font-family:var(--mono);font-size:11px;color:var(--accent2);word-break:break-all;flex:1}
/* ── Groups list ── */
.group-tag{
  display:inline-block;margin:3px;padding:3px 10px;border-radius:99px;
  font-size:11px;border:1px solid var(--border);background:var(--surface2);
}
.group-tag.role-assignable{border-color:var(--red);color:var(--red);background:rgba(248,81,73,.08)}
.group-tag.security{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
/* ── Remediation cards ── */
.remed-card{
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:14px;margin-bottom:10px;border-left:3px solid var(--border);
}
.remed-card.p1{border-left-color:var(--red)}
.remed-card.p2{border-left-color:var(--amber)}
.remed-card.p3{border-left-color:var(--accent)}
.remed-header{display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap}
.remed-priority{font-size:10px;font-family:var(--mono);font-weight:700;
  padding:2px 8px;border-radius:4px;background:var(--surface3);letter-spacing:.4px}
.remed-owner{font-size:10px;color:var(--muted);margin-left:auto}
.remed-text{font-size:12px;color:var(--muted2);line-height:1.6}
/* ── Pagination ── */
.pagination{display:flex;align-items:center;gap:6px;margin-top:12px;justify-content:flex-end;flex-wrap:wrap}
.page-btn{
  padding:4px 10px;border-radius:var(--radius-sm);border:1px solid var(--border);
  background:var(--surface2);color:var(--muted2);cursor:pointer;font-size:12px;
}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-info{font-size:11px;color:var(--muted);margin-right:auto}
/* ── Toast ── */
#toast{
  position:fixed;bottom:20px;right:20px;z-index:9999;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:10px 16px;font-size:12px;box-shadow:var(--shadow);
  opacity:0;transform:translateY(10px);transition:all .25s;pointer-events:none;
}
#toast.show{opacity:1;transform:none}
/* ── Bar chart ── */
.bar-row{display:flex;align-items:center;gap:10px;padding:5px 0}
.bar-label{width:140px;font-size:11px;color:var(--muted2);flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;width:0;transition:width .6s ease}
.bar-count{width:30px;font-size:11px;font-family:var(--mono);color:var(--muted2);text-align:right}
/* ── Mobile ── */
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:300;
  background:var(--surface2);border:1px solid var(--border);border-radius:6px;
  padding:6px 10px;cursor:pointer;font-size:18px}
@media(max-width:768px){
  #sidebar{transform:translateX(-100%);transition:transform .25s}
  #sidebar.open{transform:translateX(0)}
  #main{margin-left:0;padding:16px}
  #menuToggle{display:block}
  .stats-grid{grid-template-columns:repeat(2,1fr)}
  .score-area{margin-left:0;margin-top:16px}
}
/* ── Target state / Framework ── */
.framework-steps{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.fw-step{
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:14px;
}
.fw-step-num{font-family:var(--mono);font-size:10px;color:var(--accent);margin-bottom:6px;font-weight:700}
.fw-step-title{font-size:12px;font-weight:700;margin-bottom:6px}
.fw-step-text{font-size:11px;color:var(--muted2);line-height:1.6}
/* ── Section subtitle ── */
.section-sub{font-size:11px;color:var(--muted);margin-bottom:14px;margin-top:-6px}
/* ── Metric table ── */
.metric-row{display:flex;justify-content:space-between;align-items:center;
  padding:8px 0;border-bottom:1px solid var(--border);font-size:12px}
.metric-row:last-child{border-bottom:none}
.metric-key{color:var(--muted2)}
.metric-val{font-family:var(--mono);font-size:11px}
</style>
</head>
<body>

<button id="menuToggle" onclick="toggleSidebar()">☰</button>
<div id="toast"></div>

<!-- ══ SIDEBAR ══════════════════════════════════════════════════════════════ -->
<nav id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">💥</div>
    <div class="logo-title">Blast Radius Assessment</div>
    <div class="logo-sub">Entra ID · Zero Trust</div>
    <span class="ver-badge">v1.0 · 2026</span>
  </div>

  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('summary',this)">
      <span class="nav-icon">📊</span>Executive Summary
    </button>
    <button class="nav-btn" onclick="showPage('evidence',this)">
      <span class="nav-icon">🔍</span>Evidence
    </button>
    <button class="nav-btn" onclick="showPage('relationships',this)">
      <span class="nav-icon">🕸️</span>Relationship Map
    </button>
    <button class="nav-btn" onclick="showPage('riskregister',this)">
      <span class="nav-icon">⚠️</span>Risk Register
    </button>
    <button class="nav-btn" onclick="showPage('remediation',this)">
      <span class="nav-icon">🛡️</span>Remediation Plan
    </button>
    <button class="nav-btn" onclick="showPage('targetstate',this)">
      <span class="nav-icon">🎯</span>Target State
    </button>
  </div>

  <div class="nav-section" style="margin-top:auto">
    <div class="theme-toggle">
      <span style="font-size:12px;color:var(--muted)">Theme</span>
      <div class="toggle-pill" onclick="toggleTheme()" title="Toggle light/dark"></div>
    </div>
  </div>

  <div class="sidebar-footer">
    <div>Generated: __TIMESTAMP__</div>
    <div style="margin-top:4px">Tenant: __TENANT_ID_SHORT__</div>
    <div style="margin-top:8px;color:var(--muted);font-size:9px">Press / to search · Esc to close</div>
  </div>
</nav>

<!-- ══ MAIN ════════════════════════════════════════════════════════════════ -->
<main id="main">

  <!-- Identity Header (shared across all pages) -->
  <div class="identity-header">
    <div class="id-avatar">__IDENTITY_ICON__</div>
    <div>
      <div class="id-name">__DISPLAY_NAME__</div>
      <div class="id-upn">__UPN__</div>
      <div class="id-chips">
        <span class="chip c-blue">__IDENTITY_TYPE__</span>
        <span class="chip __ACCT_CHIP__">Account: __ACCOUNT_ENABLED__</span>
        <span class="chip __MFA_CHIP__">MFA: __MFA_LABEL__</span>
        <span class="chip">Dept: __DEPARTMENT__</span>
        <span class="chip">On-Prem Sync: __ON_PREM_SYNC__</span>
      </div>
    </div>
    <div class="score-area">
      <svg class="score-ring" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="54" fill="none" stroke="var(--surface2)" stroke-width="10"/>
        <circle cx="60" cy="60" r="54" fill="none"
          stroke="__BAND_COLOR__" stroke-width="10"
          stroke-dasharray="__SCORE_STROKE__ __GAP_STROKE__"
          stroke-dashoffset="85"
          stroke-linecap="round"
          transform="rotate(-90 60 60)"/>
        <text x="60" y="55" text-anchor="middle" class="score-val" style="fill:__BAND_COLOR__">__BLAST_SCORE__</text>
        <text x="60" y="68" text-anchor="middle" class="score-lbl">/ 100</text>
        <text x="60" y="82" text-anchor="middle" style="font-size:9px;fill:var(--muted);font-family:var(--sans)">__BAND_LABEL__</text>
      </svg>
      <div style="font-size:10px;color:var(--muted);font-family:var(--mono)">BLAST RADIUS</div>
    </div>
  </div>

  <!-- ═══════════════════════════════════════════════════════ PAGE: Summary -->
  <div class="page active" id="page-summary">

    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-val" style="color:var(--red)" id="cnt-critical">__CRITICAL_COUNT__</div>
        <div class="stat-lbl">Critical Findings</div>
      </div>
      <div class="stat-card c-orange">
        <div class="stat-val" style="color:var(--orange)" id="cnt-high">__HIGH_COUNT__</div>
        <div class="stat-lbl">High Findings</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-val" style="color:var(--amber)" id="cnt-medium">__MEDIUM_COUNT__</div>
        <div class="stat-lbl">Medium Findings</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-val" style="color:var(--accent)" id="cnt-low">__LOW_COUNT__</div>
        <div class="stat-lbl">Low / Info Findings</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-val" style="color:var(--accent3)">__TOTAL_FINDINGS__</div>
        <div class="stat-lbl">Total Findings</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-val" style="color:var(--green)">__GROUP_COUNT__</div>
        <div class="stat-lbl">Group Memberships</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">📈 Risk Distribution by Layer</div>
        <div id="layerBars"></div>
      </div>
      <div class="panel">
        <div class="panel-title">🎯 Business Impact Assessment</div>
        <div id="impactList"></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">🏗️ Assessment Framework</div>
      <div class="section-sub">Business Problem → Current State → Risk/Gap → Target State → Transition → Success Metrics</div>
      <div class="framework-steps" id="frameworkSteps"></div>
    </div>

  </div><!-- /page-summary -->

  <!-- ═══════════════════════════════════════════════════════ PAGE: Evidence -->
  <div class="page" id="page-evidence">
    <div class="panel">
      <div class="panel-title">🔍 Raw Evidence — Identity Profile</div>
      <div id="profileMetrics"></div>
    </div>
    <div class="panel">
      <div class="panel-title">👥 Group Memberships (Transitive)</div>
      <div id="groupTags"></div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 All Collected Evidence</div>
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔎</span>
          <input type="text" id="evidenceSearch" placeholder="Search evidence..." oninput="filterEvidence()">
        </div>
        <button class="filter-btn active" onclick="filterLayer(this,'all')">All</button>
        <button class="filter-btn" onclick="filterLayer(this,'DirectoryRole')">Dir Roles</button>
        <button class="filter-btn" onclick="filterLayer(this,'AppRoleAssignment')">App Roles</button>
        <button class="filter-btn" onclick="filterLayer(this,'DelegatedPermission')">Delegated</button>
        <button class="filter-btn" onclick="filterLayer(this,'OwnedObject')">Owned</button>
        <button class="filter-btn" onclick="filterLayer(this,'AzureRBAC')">Azure RBAC</button>
      </div>
      <div class="tbl-wrap">
        <table id="evidenceTable">
          <thead><tr>
            <th onclick="sortTable('evidenceTable',0,this)">Layer <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable('evidenceTable',1,this)">Resource <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable('evidenceTable',2,this)">Permission <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable('evidenceTable',3,this)">Type <span class="sort-arrow">↕</span></th>
            <th>Evidence</th>
          </tr></thead>
          <tbody id="evidenceTbody"></tbody>
        </table>
      </div>
      <div class="pagination" id="evidencePager"></div>
    </div>
  </div><!-- /page-evidence -->

  <!-- ═══════════════════════════════════════════ PAGE: Relationship Map -->
  <div class="page" id="page-relationships">
    <div class="panel">
      <div class="panel-title">🕸️ Attack Relationship Paths</div>
      <div class="section-sub">Every path represents a lateral-movement or privilege-escalation route from the compromised identity.</div>
      <div id="attackPaths"></div>
    </div>
  </div><!-- /page-relationships -->

  <!-- ═══════════════════════════════════════════════ PAGE: Risk Register -->
  <div class="page" id="page-riskregister">
    <div class="panel">
      <div class="panel-title">⚠️ Risk Register</div>
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔎</span>
          <input type="text" id="riskSearch" placeholder="Search risks..." oninput="filterRisk()">
        </div>
        <button class="filter-btn active" onclick="filterRiskTier(this,'all')">All</button>
        <button class="filter-btn" onclick="filterRiskTier(this,'Critical')" style="border-color:var(--red);color:var(--red)">Critical</button>
        <button class="filter-btn" onclick="filterRiskTier(this,'High')" style="border-color:var(--orange);color:var(--orange)">High</button>
        <button class="filter-btn" onclick="filterRiskTier(this,'Medium')" style="border-color:var(--amber);color:var(--amber)">Medium</button>
        <button class="filter-btn" onclick="filterRiskTier(this,'Low')">Low</button>
      </div>
      <div class="tbl-wrap">
        <table id="riskTable">
          <thead><tr>
            <th onclick="sortTable('riskTable',0,this)">Risk Tier <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable('riskTable',1,this)">Layer <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable('riskTable',2,this)">Resource <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable('riskTable',3,this)">Permission <span class="sort-arrow">↕</span></th>
            <th onclick="sortTable('riskTable',4,this)">Score <span class="sort-arrow">↕</span></th>
            <th>Assignment Type</th>
          </tr></thead>
          <tbody id="riskTbody"></tbody>
        </table>
      </div>
      <div class="pagination" id="riskPager"></div>
    </div>
  </div><!-- /page-riskregister -->

  <!-- ═════════════════════════════════════════════ PAGE: Remediation Plan -->
  <div class="page" id="page-remediation">
    <div class="panel">
      <div class="panel-title">🛡️ Prioritized Remediation Plan</div>
      <div class="section-sub">Priority 1 = Immediate (0–48 hr) · Priority 2 = Short-term (1–2 weeks) · Priority 3 = Planned (30–90 days)</div>
      <div id="remediationCards"></div>
    </div>
    <div class="panel">
      <div class="panel-title">📥 Export</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <button class="filter-btn" onclick="exportCSV()" style="background:var(--green);border-color:var(--green);color:#fff">⬇ Download CSV</button>
        <button class="filter-btn" onclick="exportJSON()" style="background:var(--accent);border-color:var(--accent);color:#fff">⬇ Download JSON</button>
        <button class="filter-btn" onclick="copyText(JSON.stringify(window.findings,null,2),this)">📋 Copy JSON</button>
      </div>
    </div>
  </div><!-- /page-remediation -->

  <!-- ══════════════════════════════════════════════ PAGE: Target State -->
  <div class="page" id="page-targetstate">
    <div class="panel">
      <div class="panel-title">🎯 Target State — Zero Trust Identity Posture</div>
      <div class="section-sub">What the identity configuration should look like after all remediations are applied.</div>
      <div class="framework-steps" id="targetSteps"></div>
    </div>
    <div class="panel">
      <div class="panel-title">📏 Success Metrics</div>
      <div id="successMetrics"></div>
    </div>
  </div><!-- /page-targetstate -->

</main>

<script>
// ══ DATA ════════════════════════════════════════════════════════════════════
const findings  = __FINDINGS_JSON__;
const groups    = __GROUPS_JSON__;
const identity  = {
  displayName: "__DISPLAY_NAME__",
  upn:         "__UPN__",
  type:        "__IDENTITY_TYPE__",
  dept:        "__DEPARTMENT__",
  job:         "__JOB_TITLE__",
  enabled:     "__ACCOUNT_ENABLED__",
  onPrem:      "__ON_PREM_SYNC__",
  mfa:         "__MFA_LABEL__",
  mfaMethods:  "__MFA_METHODS__",
  score:       __BLAST_SCORE__,
  band:        "__BAND_LABEL__",
};

// ══ UTILS ════════════════════════════════════════════════════════════════════
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

function riskBadge(tier){
  const m={Critical:'risk-critical',High:'risk-high',Medium:'risk-medium',Low:'risk-low',Informational:'risk-informational'};
  return `<span class="risk ${m[tier]||'risk-informational'}">${escH(tier)}</span>`;
}

function showToast(msg,icon='✅'){
  const t=document.getElementById('toast');
  t.textContent=icon+' '+msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

function copyText(txt,btn){
  navigator.clipboard.writeText(txt).then(()=>{
    const orig=btn?btn.textContent:'';
    if(btn)btn.textContent='✅ Copied!';
    showToast('Copied to clipboard');
    if(btn)setTimeout(()=>btn.textContent=orig,2000);
  });
}

function dlFile(content,name,type){
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([content],{type}));
  a.download=name;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ══ NAV ══════════════════════════════════════════════════════════════════════
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
}
function toggleSidebar(){document.getElementById('sidebar').classList.toggle('open');}
function toggleTheme(){document.body.classList.toggle('light-theme');}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape') document.getElementById('sidebar').classList.remove('open');
  if(e.key==='/'){ e.preventDefault();
    const el=document.querySelector('.page.active input[type=text]');
    if(el)el.focus();
  }
});

// ══ TABLE SORT ════════════════════════════════════════════════════════════════
const sortState={};
function sortTable(tableId,col,th){
  const tbl=document.getElementById(tableId);
  const tbody=tbl.querySelector('tbody');
  const rows=Array.from(tbody.querySelectorAll('tr'));
  const key=tableId+'-'+col;
  sortState[key]=!sortState[key];
  rows.sort((a,b)=>{
    const va=a.cells[col]?a.cells[col].textContent.trim():'';
    const vb=b.cells[col]?b.cells[col].textContent.trim():'';
    const r=va.localeCompare(vb,undefined,{numeric:true});
    return sortState[key]?r:-r;
  });
  rows.forEach(r=>tbody.appendChild(r));
  tbl.querySelectorAll('th').forEach(h=>{h.classList.remove('sort-active');h.querySelector('.sort-arrow').textContent='↕';});
  th.classList.add('sort-active');
  th.querySelector('.sort-arrow').textContent=sortState[key]?'↑':'↓';
}

// ══ PAGINATION ════════════════════════════════════════════════════════════════
const pagerState={};
function paginate(rows,pagerId,pageSize,renderFn){
  const state=pagerState[pagerId]||{page:1};
  pagerState[pagerId]=state;
  const total=rows.length;
  const pages=Math.max(1,Math.ceil(total/pageSize));
  if(state.page>pages)state.page=1;
  const start=(state.page-1)*pageSize;
  const slice=rows.slice(start,start+pageSize);
  renderFn(slice,start);
  buildPager(pagerId,pages,state.page,total,start,pageSize);
}
function buildPager(pagerId,pages,cur,total,start,pageSize){
  const el=document.getElementById(pagerId);
  if(!el)return;
  const end=Math.min(start+pageSize,total);
  let h=`<span class="page-info">Showing ${start+1}–${end} of ${total}</span>`;
  if(cur>1)h+=`<button class="page-btn" onclick="goPage('${pagerId}',${cur-1})">‹</button>`;
  for(let i=Math.max(1,cur-2);i<=Math.min(pages,cur+2);i++){
    h+=`<button class="page-btn${i===cur?' active':''}" onclick="goPage('${pagerId}',${i})">${i}</button>`;
  }
  if(cur<pages)h+=`<button class="page-btn" onclick="goPage('${pagerId}',${cur+1})">›</button>`;
  el.innerHTML=h;
}
function goPage(pagerId,p){
  if(!pagerState[pagerId])pagerState[pagerId]={page:1};
  pagerState[pagerId].page=p;
  if(pagerId==='evidencePager')renderEvidence();
  if(pagerId==='riskPager')renderRisk();
}

// ══ EVIDENCE PAGE ═════════════════════════════════════════════════════════════
let evidenceFilter={layer:'all',text:''};
function filterLayer(btn,layer){
  evidenceFilter.layer=layer;
  pagerState['evidencePager']={page:1};
  document.querySelectorAll('#page-evidence .filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderEvidence();
}
function filterEvidence(){evidenceFilter.text=document.getElementById('evidenceSearch').value.toLowerCase();pagerState['evidencePager']={page:1};renderEvidence();}
function getFilteredEvidence(){
  return findings.filter(f=>{
    const layerMatch = evidenceFilter.layer==='all'||f.layer===evidenceFilter.layer;
    const textMatch  = !evidenceFilter.text ||
      (f.resourceName+f.permission+f.evidence+f.layer).toLowerCase().includes(evidenceFilter.text);
    return layerMatch && textMatch;
  });
}
function renderEvidence(){
  const rows=getFilteredEvidence();
  paginate(rows,'evidencePager',15,function(slice){
    document.getElementById('evidenceTbody').innerHTML=slice.map(f=>`
      <tr>
        <td><span class="chip c-blue" style="font-size:10px">${escH(f.layer)}</span></td>
        <td>${escH(f.resourceName)}<div class="mono" style="color:var(--muted);font-size:10px">${escH(f.resourceType)}</div></td>
        <td class="mono">${escH(f.permission)}</td>
        <td>${escH(f.assignmentType)}</td>
        <td><div class="evidence-text mono" title="${escH(f.evidence)}" onclick="copyText('${escJ(f.evidence)}',this)">${escH(f.evidence)}</div></td>
      </tr>`).join('');
  });
}

// ══ RISK REGISTER ═════════════════════════════════════════════════════════════
let riskFilter={tier:'all',text:''};
function filterRiskTier(btn,tier){
  riskFilter.tier=tier;
  pagerState['riskPager']={page:1};
  document.querySelectorAll('#page-riskregister .filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderRisk();
}
function filterRisk(){riskFilter.text=document.getElementById('riskSearch').value.toLowerCase();pagerState['riskPager']={page:1};renderRisk();}
function getFilteredRisk(){
  return findings.filter(f=>{
    const tierMatch = riskFilter.tier==='all'||f.riskTier===riskFilter.tier;
    const textMatch = !riskFilter.text ||
      (f.resourceName+f.permission+f.riskTier+f.layer).toLowerCase().includes(riskFilter.text);
    return tierMatch && textMatch;
  }).sort((a,b)=>b.riskWeight-a.riskWeight);
}
function renderRisk(){
  const rows=getFilteredRisk();
  paginate(rows,'riskPager',20,function(slice){
    document.getElementById('riskTbody').innerHTML=slice.map(f=>`
      <tr>
        <td>${riskBadge(f.riskTier)}</td>
        <td><span class="chip c-blue" style="font-size:10px">${escH(f.layer)}</span></td>
        <td>${escH(f.resourceName)}</td>
        <td class="mono">${escH(f.permission)}</td>
        <td class="mono" style="color:${f.riskWeight>=20?'var(--red)':f.riskWeight>=10?'var(--amber)':'var(--muted)'}">${f.riskWeight}</td>
        <td>${escH(f.assignmentType)}</td>
      </tr>`).join('');
  });
}

// ══ REMEDIATION ═══════════════════════════════════════════════════════════════
function renderRemediation(){
  const byPriority=[1,2,3];
  const priorityLabels={1:'P1 · Immediate (0–48 hr)',2:'P2 · Short-term (1–2 weeks)',3:'P3 · Planned (30–90 days)'};
  let html='';
  byPriority.forEach(p=>{
    const items=findings.filter(f=>f.remediationPriority===p);
    if(!items.length)return;
    html+=`<h4 style="margin:18px 0 10px;font-size:12px;color:var(--muted2);letter-spacing:.4px">${priorityLabels[p]} — ${items.length} action${items.length!==1?'s':''}</h4>`;
    items.forEach(f=>{
      html+=`<div class="remed-card p${p}">
        <div class="remed-header">
          <span class="remed-priority">P${p}</span>
          ${riskBadge(f.riskTier)}
          <span class="chip c-blue" style="font-size:10px">${escH(f.layer)}</span>
          <span class="remed-owner">Owner: ${escH(f.remediationOwner)}</span>
        </div>
        <div style="font-size:12px;font-weight:600;margin-bottom:4px">${escH(f.resourceName)} · <span class="mono" style="font-size:11px">${escH(f.permission)}</span></div>
        <div class="remed-text">${escH(f.remediation)}</div>
      </div>`;
    });
  });
  document.getElementById('remediationCards').innerHTML=html||'<div style="color:var(--muted)">No findings to remediate.</div>';
}

// ══ ATTACK PATHS ══════════════════════════════════════════════════════════════
function renderAttackPaths(){
  const sorted=[...findings].sort((a,b)=>b.riskWeight-a.riskWeight);
  const el=document.getElementById('attackPaths');
  if(!sorted.length){el.innerHTML='<div style="color:var(--muted)">No attack paths found.</div>';return;}
  el.innerHTML=sorted.map(f=>`
    <div class="path-row">
      <div style="flex-shrink:0">${riskBadge(f.riskTier)}</div>
      <div class="path-line">⇒ ${escH(f.attackPath)}</div>
      <div class="mono" style="flex-shrink:0;color:var(--muted);font-size:10px">${f.riskWeight}</div>
    </div>`).join('');
}

// ══ LAYER BARS ════════════════════════════════════════════════════════════════
function renderLayerBars(){
  const layerCounts={};
  findings.forEach(f=>{layerCounts[f.layer]=(layerCounts[f.layer]||0)+1;});
  const sorted=Object.entries(layerCounts).sort((a,b)=>b[1]-a[1]);
  const max=sorted[0]?sorted[0][1]:1;
  const colors={DirectoryRole:'var(--red)',AppRoleAssignment:'var(--amber)',DelegatedPermission:'var(--orange)',
    OwnedObject:'var(--accent)',AzureRBAC:'var(--accent3)',SPAppPermission:'var(--accent2)',OwnedDevice:'var(--green)'};
  const el=document.getElementById('layerBars');
  if(!sorted.length){el.innerHTML='<div style="color:var(--muted)">No findings.</div>';return;}
  el.innerHTML=sorted.map(([layer,cnt])=>`
    <div class="bar-row">
      <div class="bar-label" title="${escH(layer)}">${escH(layer)}</div>
      <div class="bar-track"><div class="bar-fill" data-pct="${Math.round(cnt/max*100)}" style="background:${colors[layer]||'var(--accent)'}"></div></div>
      <div class="bar-count">${cnt}</div>
    </div>`).join('');
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill').forEach(b=>{b.style.width=b.dataset.pct+'%';});
  });
}

// ══ IMPACT LIST ═══════════════════════════════════════════════════════════════
function renderImpactList(){
  const el=document.getElementById('impactList');
  const impacts=[];
  const tierOrder={Critical:0,High:1,Medium:2,Low:3,Informational:4};
  const sorted=[...findings].sort((a,b)=>(tierOrder[a.riskTier]||4)-(tierOrder[b.riskTier]||4));
  const seen=new Set();
  sorted.forEach(f=>{
    const key=f.layer+f.permission;
    if(seen.has(key))return;
    seen.add(key);
    impacts.push(f);
  });
  const top=impacts.slice(0,8);
  el.innerHTML=top.map(f=>`
    <div class="metric-row">
      <span class="metric-key">${escH(f.resourceName)}</span>
      <div style="display:flex;align-items:center;gap:6px">
        ${riskBadge(f.riskTier)}
        <span class="mono" style="font-size:10px;color:var(--muted)">${escH(f.layer)}</span>
      </div>
    </div>`).join('');
}

// ══ FRAMEWORK ════════════════════════════════════════════════════════════════
function renderFramework(){
  const steps=[
    {num:'01',title:'Business Problem',text:'A compromised identity is the #1 initial access vector. Without blast-radius visibility, security teams cannot scope the impact or prioritize containment during a breach.'},
    {num:'02',title:'Current State',text:`Identity: ${escH(identity.displayName)} (${escH(identity.type)}). ${findings.length} relationship paths discovered. Blast-radius score: ${identity.score}/100 (${escH(identity.band)}).`},
    {num:'03',title:'Risk / Gap',text:`${findings.filter(f=>f.riskTier==='Critical').length} Critical and ${findings.filter(f=>f.riskTier==='High').length} High findings identified. MFA: ${escH(identity.mfa)}. Standing privileged access without PIM may exist.`},
    {num:'04',title:'Target State',text:'Zero standing privilege: all roles PIM-activated, JIT, time-bound. No broad API scopes. All devices compliant. CA policy enforcing MFA + compliant device.'},
    {num:'05',title:'Transition',text:'Prioritized 3-tier remediation plan in the Remediation Plan tab. P1 actions must be completed within 48 hours for Critical/High findings.'},
    {num:'06',title:'Success Metrics',text:'Blast-radius score ≤ 20. Zero active Critical directory roles. MFA registered and enforced. No .All Graph permissions unless justified.'},
  ];
  document.getElementById('frameworkSteps').innerHTML=steps.map(s=>`
    <div class="fw-step">
      <div class="fw-step-num">STEP ${s.num}</div>
      <div class="fw-step-title">${s.title}</div>
      <div class="fw-step-text">${s.text}</div>
    </div>`).join('');
}

// ══ GROUPS ════════════════════════════════════════════════════════════════════
function renderGroups(){
  const el=document.getElementById('groupTags');
  if(!groups.length){el.innerHTML='<div style="color:var(--muted)">No group memberships found.</div>';return;}
  el.innerHTML=groups.map(g=>{
    const cls=g.type==='Role-Assignable'?'role-assignable':g.type==='Security'?'security':'';
    return `<span class="group-tag ${cls}" title="${escH(g.id)}">${escH(g.name)} <span style="font-size:9px;opacity:.7">${escH(g.type)}</span></span>`;
  }).join('');
}

// ══ PROFILE METRICS ═══════════════════════════════════════════════════════════
function renderProfileMetrics(){
  const rows=[
    ['Display Name',identity.displayName],
    ['UPN / App ID',identity.upn],
    ['Identity Type',identity.type],
    ['Department',identity.dept],
    ['Job Title',identity.job],
    ['Account Enabled',identity.enabled],
    ['On-Premises Sync',identity.onPrem],
    ['MFA Status',identity.mfa],
    ['MFA Methods',identity.mfaMethods||'N/A'],
    ['Blast-Radius Score',identity.score+'/100 ('+identity.band+')'],
    ['Total Findings',findings.length],
    ['Group Memberships',groups.length],
  ];
  document.getElementById('profileMetrics').innerHTML=rows.map(([k,v])=>`
    <div class="metric-row">
      <span class="metric-key">${escH(k)}</span>
      <span class="metric-val">${escH(String(v||'N/A'))}</span>
    </div>`).join('');
}

// ══ TARGET STATE ══════════════════════════════════════════════════════════════
function renderTargetState(){
  const steps=[
    {title:'Zero Standing Privilege',text:'All directory roles converted to PIM-eligible. Activation requires MFA + business justification. Maximum activation duration: 4 hours.'},
    {title:'Least-Privilege API Scope',text:'Remove any .ReadWrite.All or .All Graph permissions not explicitly required. Replace with scoped permissions (e.g. Mail.Send instead of Mail.ReadWrite.All).'},
    {title:'Conditional Access Coverage',text:'All sign-ins require MFA. Device compliance enforced via Intune. Named location policies restrict access from non-corporate networks.'},
    {title:'No Broad Ownership',text:'Application and service principal ownership limited to named break-glass accounts. Devices managed and compliant before accessing corporate resources.'},
    {title:'Continuous Monitoring',text:'PIM activation alerts enabled. Privileged identity sign-in risk policy active. Blast-radius re-assessment triggered on any role or permission change.'},
    {title:'Governance Cadence',text:'Quarterly access review for all privileged identities. Annual application permission review. Immediate de-provisioning on role change or departure.'},
  ];
  document.getElementById('targetSteps').innerHTML=steps.map((s,i)=>`
    <div class="fw-step">
      <div class="fw-step-num">TARGET ${String(i+1).padStart(2,'0')}</div>
      <div class="fw-step-title">${s.title}</div>
      <div class="fw-step-text">${s.text}</div>
    </div>`).join('');

  const metrics=[
    ['Blast-Radius Score','≤ 20 (Minimal)','Target'],
    ['Critical Findings','0','Target'],
    ['High Findings','0','Target'],
    ['MFA Registration','100% of privileged identities','Target'],
    ['Standing Privileged Roles','0 (all PIM-eligible)','Target'],
    ['Broad .All API Scopes','0 unjustified','Target'],
    ['Unmanaged Devices','0 with corporate access','Target'],
    ['Current Score',identity.score+'/100 ('+identity.band+')','Current'],
  ];
  document.getElementById('successMetrics').innerHTML=metrics.map(([m,v,state])=>`
    <div class="metric-row">
      <span class="metric-key">${escH(m)}</span>
      <span class="metric-val">${escH(v)} ${state==='Current'?'<span style="color:var(--muted);font-size:10px">(current)</span>':''}</span>
    </div>`).join('');
}

// ══ EXPORT ════════════════════════════════════════════════════════════════════
function exportCSV(){
  const headers=['Layer','AttackPath','ResourceType','ResourceName','ResourceId','Permission','AssignmentType','RiskTier','RiskWeight','Evidence','Remediation','RemediationPriority','RemediationOwner'];
  const rows=findings.map(f=>headers.map(h=>{const v=String(f[h.charAt(0).toLowerCase()+h.slice(1)]||'');return '"'+v.replace(/"/g,'""')+'"';}).join(','));
  dlFile([headers.join(','),...rows].join('\r\n'),'blast-radius-findings.csv','text/csv');
  showToast('CSV downloaded');
}
function exportJSON(){
  dlFile(JSON.stringify(findings,null,2),'blast-radius-findings.json','application/json');
  showToast('JSON downloaded');
}

// ══ INIT ══════════════════════════════════════════════════════════════════════
(function init(){
  renderProfileMetrics();
  renderGroups();
  renderLayerBars();
  renderImpactList();
  renderFramework();
  renderEvidence();
  renderAttackPaths();
  renderRisk();
  renderRemediation();
  renderTargetState();
})();
</script>
</body>
</html>
'@

    # ── Token substitution (no string interpolation inside the here-string) ──
    $tenantShort = if ($TenantId.Length -ge 8) { $TenantId.Substring(0, 8) + "..." } else { $TenantId }
    $identityIcon = switch ($IdentityType) {
      "User" { "👤" }
      "ServicePrincipal" { "⚙️" }
      "Group" { "👥" }
      "Application" { "🔑" }
      default { "🆔" }
    }
    $acctChip = if ($accountEnabled -eq "Yes") { "c-green" } else { "c-red" }
    $mfaChipCss = if ($MFAStatus.HasMFA) { "c-green" } else { "c-red" }
    $mfaMethods = ConvertTo-JsonSafe($MFAStatus.StrongMethods)

    $html = $html `
      -replace '__DISPLAY_NAME__', $displayName `
      -replace '__UPN__', $upn `
      -replace '__IDENTITY_TYPE__', $IdentityType `
      -replace '__IDENTITY_ICON__', $identityIcon `
      -replace '__DEPARTMENT__', $department `
      -replace '__JOB_TITLE__', $jobTitle `
      -replace '__ACCOUNT_ENABLED__', $accountEnabled `
      -replace '__ACCT_CHIP__', $acctChip `
      -replace '__ON_PREM_SYNC__', $onPremSync `
      -replace '__MFA_LABEL__', $mfaLabel `
      -replace '__MFA_CHIP__', $mfaCss `
      -replace '__MFA_METHODS__', $mfaMethods `
      -replace '__BLAST_SCORE__', $BlastRadiusScore `
      -replace '__BAND_COLOR__', $bandColor `
      -replace '__BAND_LABEL__', $bandLabel `
      -replace '__SCORE_STROKE__', $scoreStroke `
      -replace '__GAP_STROKE__', $gapStroke `
      -replace '__CRITICAL_COUNT__', $criticalCount `
      -replace '__HIGH_COUNT__', $highCount `
      -replace '__MEDIUM_COUNT__', $mediumCount `
      -replace '__LOW_COUNT__', ($lowCount + ($Findings | Where-Object { $_.RiskTier -eq "Informational" }).Count) `
      -replace '__TOTAL_FINDINGS__', $totalFindings `
      -replace '__GROUP_COUNT__', $groupCount `
      -replace '__TIMESTAMP__', $AssessmentTimestamp `
      -replace '__TENANT_ID_SHORT__', $tenantShort `
      -replace '__FINDINGS_JSON__', $findingsJson `
      -replace '__GROUPS_JSON__', $groupsJson

    $html | Out-File -FilePath $OutputFilePath -Encoding UTF8 -Force
  }

  #─────────────────────────────────────────────────────────────────────────────
  #  REGION: Script Execution
  #─────────────────────────────────────────────────────────────────────────────

  Clear-Host

  # Stale variable cleanup (matches reference script pattern)
  Remove-Variable -Name partialData, usersData, skip -ErrorAction SilentlyContinue

  # Ensure output directory exists
  If (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
  }

  $scriptStartTime = Get-Date
  $assessmentTimestamp = $scriptStartTime.ToString("dd-MMM-yyyy HH:mm:ss")
  $fileTimestamp = $scriptStartTime.ToString("yyyyMMdd-HHmmss")

  # ── Banner ────────────────────────────────────────────────────────────────────
  Write-Host ""
  Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
  Write-Host "  ║       Entra ID — Identity Blast Radius Assessment            ║" -ForegroundColor Cyan
  Write-Host "  ║                    Version 1.0  |  2026                      ║" -ForegroundColor Cyan
  Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "  🕐 Started    : $($scriptStartTime.ToString('dd-MMM-yyyy  hh:mm:ss tt'))" -ForegroundColor Gray
  Write-Host "  📁 Output Dir : $OutputPath" -ForegroundColor Gray
  Write-Host ""

  # ── Step 1 : Authentication ───────────────────────────────────────────────────
  Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
  Write-Host "  │   STEP 1 of 9  ›  Authenticating                            │" -ForegroundColor DarkCyan
  Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
  Write-Host ""

  if ($PSCmdlet.ParameterSetName -eq "BYOT") {
    # BYOT — store token directly, set expiry far in future so ShouldRenewToken stays false
    Write-Host "  ⚡ BYOT mode — using supplied access token" -ForegroundColor Yellow
    $global:accessToken = $AccessToken
    $global:tokenExpirationTime = (Get-Date).AddHours(1)
    $global:RefreshIntervalInMinutes = 5
    $global:TenantId = $TenantId
    Write-Host "  ✅ Token accepted" -ForegroundColor Green
  }
  else {
    Write-Host "  ⏳ Requesting access token (client credentials)..." -ForegroundColor Yellow
    $token = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId -RefreshInterval 15

    if (-not $token) {
      Write-Error "Authentication failed. Verify ClientId, ClientSecret, and TenantId."
      return
    }
    $global:accessToken = $token
    $global:TenantId = $TenantId
    Write-Host "  ✅ Authentication successful" -ForegroundColor Green
  }

  Write-Host ""

  # ── Step 1.1 : Validate Required Graph Permissions ───────────────────────────
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
    Write-Host "  The assessment will continue with the available permissions." -ForegroundColor Yellow
    Write-Host "  Some assessment values or findings may not be available." -ForegroundColor Yellow
    Write-Host ""
  }
  else {
    Write-Host "  ✅ All required Microsoft Graph permissions validated." -ForegroundColor Green
  }

  Write-Host ""

  # ── Step 2 : Resolve Target Identity ─────────────────────────────────────────
  Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
  Write-Host "  │   STEP 2 of 9  ›  Resolving Target Identity                 │" -ForegroundColor DarkCyan
  Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
  Write-Host ""

  if ($TargetUserPrincipalName) {
    Write-Host "  ⏳ Resolving UPN: $TargetUserPrincipalName" -ForegroundColor Yellow
    $TargetIdentityId = Resolve-UPNToObjectId -UserPrincipalName $TargetUserPrincipalName
    if (-not $TargetIdentityId) {
      Write-Error "Could not resolve UPN '$TargetUserPrincipalName' to an object ID. Verify the UPN exists in the tenant."
      return
    }
    Write-Host "  ✅ Resolved to ObjectId: $TargetIdentityId" -ForegroundColor Green
  }
  else {
    Write-Host "  ✅ Using ObjectId: $TargetIdentityId" -ForegroundColor Green
  }

  Write-Host ""

  # ── Step 3 : Identity Profile ─────────────────────────────────────────────────
  Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
  Write-Host "  │   STEP 3 of 9  ›  Collecting Evidence — Identity Profile    │" -ForegroundColor DarkCyan
  Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
  Write-Host ""
  Write-Host "  ⏳ Fetching identity profile..." -ForegroundColor Yellow

  $identityResult = Get-IdentityProfile -ObjectId $TargetIdentityId
  $identityProfile = $identityResult.Profile
  $identityType = $identityResult.IdentityType

  if (-not $identityProfile -or -not $identityProfile.id) {
    Write-Error "Could not retrieve identity profile for ObjectId '$TargetIdentityId'. Check that the ID is valid and the token has Directory.Read.All."
    return
  }

  Write-Host "  ✅ Identity resolved: $($identityProfile.displayName) [$identityType]" -ForegroundColor Green
  Write-Host ""

  # All findings accumulate here
  $allFindings = New-Object System.Collections.ArrayList

  # ── Step 4 : Group Memberships ────────────────────────────────────────────────
  Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
  Write-Host "  │   STEP 4 of 9  ›  Group Memberships (Transitive)            │" -ForegroundColor DarkCyan
  Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
  Write-Host ""
  Write-Host "  ⏳ Resolving transitive group memberships..." -ForegroundColor Yellow

  $groupMemberships = Get-GroupMemberships -ObjectId $TargetIdentityId -IdentityType $identityType

  foreach ($g in $groupMemberships) {
    $isRoleAssignable = [bool]$g.isAssignableToRole

    $permission = if ($isRoleAssignable) { "RoleAssignableGroup" } else { "GroupMember" }

    $remediation = if ($isRoleAssignable) {
      "CRITICAL: This group is role-assignable. Review all roles assigned to '$($g.displayName)' immediately. Remove identity from group if membership is not required."
    }
    else {
      "Review membership in '$($g.displayName)'. Remove if no longer required (least-privilege principle)."
    }

    $remediationPriority = if ($isRoleAssignable) { 1 } else { 3 }

    $null = $allFindings.Add(
      (New-Finding `
        -Layer                "GroupMembership" `
        -AttackPath           "Identity → Group → $($g.displayName)" `
        -ResourceType         "Group" `
        -ResourceName         $g.displayName `
        -ResourceId           $g.id `
        -Permission           $permission `
        -AssignmentType       "Member" `
        -Evidence             "principalId=$TargetIdentityId memberOfGroupId=$($g.id) isRoleAssignable=$isRoleAssignable" `
        -Remediation          $remediation `
        -RemediationPriority  $remediationPriority `
        -RemediationOwner     "Identity & Access Management Team"
            )
    )
  }

  Write-Host "  ✅ $($groupMemberships.Count) group memberships found" -ForegroundColor Green
  Write-Host ""

  # ── Step 5 : Directory Roles ──────────────────────────────────────────────────
  Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
  Write-Host "  │   STEP 5 of 9  ›  Directory Role Assignments                │" -ForegroundColor DarkCyan
  Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
  Write-Host ""
  Write-Host "  ⏳ Querying directory role assignments..." -ForegroundColor Yellow
  if ($IncludeEligibleRoles) { Write-Host "  ℹ️  PIM-eligible roles included" -ForegroundColor Cyan }

  $roleFindings = Get-DirectoryRoleAssignments -ObjectId $TargetIdentityId -IncludeEligible:$IncludeEligibleRoles
  $roleFindings | ForEach-Object { $null = $allFindings.Add($_) }

  Write-Host "  ✅ $($roleFindings.Count) role finding(s) collected" -ForegroundColor Green
  Write-Host ""

  # ── Step 6 : App Role Assignments & Delegated Permissions ────────────────────
  Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
  Write-Host "  │   STEP 6 of 9  ›  App Permissions & Delegated Scopes        │" -ForegroundColor DarkCyan
  Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
  Write-Host ""
  Write-Host "  ⏳ Collecting application role assignments..." -ForegroundColor Yellow
  $appFindings = Get-AppRoleAssignments -ObjectId $TargetIdentityId -IdentityType $identityType
  $appFindings | ForEach-Object { $null = $allFindings.Add($_) }

  Write-Host "  ⏳ Collecting delegated OAuth2 permissions..." -ForegroundColor Yellow
  $delegatedFindings = Get-DelegatedPermissions -ObjectId $TargetIdentityId -IdentityType $identityType
  $delegatedFindings | ForEach-Object { $null = $allFindings.Add($_) }

  if ($identityType -eq "ServicePrincipal") {
    Write-Host "  ⏳ Collecting service principal app permissions..." -ForegroundColor Yellow
    $spFindings = Get-ServicePrincipalAppPermissions -ObjectId $TargetIdentityId
    $spFindings | ForEach-Object { $null = $allFindings.Add($_) }
  }

  Write-Host "  ✅ $($appFindings.Count + $delegatedFindings.Count) app/delegated finding(s)" -ForegroundColor Green
  Write-Host ""

  # ── Step 7 : Owned Objects & Devices ─────────────────────────────────────────
  Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
  Write-Host "  │   STEP 7 of 9  ›  Owned Objects & Devices                   │" -ForegroundColor DarkCyan
  Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
  Write-Host ""
  Write-Host "  ⏳ Collecting owned objects..." -ForegroundColor Yellow
  $ownedFindings = Get-OwnedObjects -ObjectId $TargetIdentityId -IdentityType $identityType
  $ownedFindings | ForEach-Object { $null = $allFindings.Add($_) }

  if ($identityType -eq "User") {
    Write-Host "  ⏳ Collecting owned devices..." -ForegroundColor Yellow
    $deviceFindings = Get-OwnedDevices -ObjectId $TargetIdentityId
    $deviceFindings | ForEach-Object { $null = $allFindings.Add($_) }
  }

  Write-Host "  ✅ $($ownedFindings.Count) owned object finding(s)" -ForegroundColor Green
  Write-Host ""

  # ── Step 7b : MFA Status (Users only) ────────────────────────────────────────
  $mfaStatus = @{ HasMFA = $false; MethodCount = 0; StrongMethods = "N/A" }
  if ($identityType -eq "User") {
    Write-Host "  ⏳ Checking MFA registration..." -ForegroundColor Yellow
    $mfaStatus = Get-MFAStatus -UserId $TargetIdentityId

    if (-not $mfaStatus.HasMFA) {
      $null = $allFindings.Add(
        (New-Finding `
          -Layer             "MFAPosture" `
          -AttackPath        "Identity → NoMFA → CredentialHijack" `
          -ResourceType      "AuthenticationMethod" `
          -ResourceName      "No Strong MFA Registered" `
          -ResourceId        $TargetIdentityId `
          -Permission        "NoMFA" `
          -AssignmentType    "MFA Gap" `
          -Evidence          "userId=$TargetIdentityId strongMFAMethods=0 totalMethods=$($mfaStatus.MethodCount)" `
          -Remediation       "IMMEDIATE: Register Microsoft Authenticator (phishing-resistant preferred) or FIDO2 key. Enforce MFA via Conditional Access policy. Do NOT allow SMS or phone call as the only MFA method." `
          -RemediationPriority 1 `
          -RemediationOwner  "Identity & Access Management Team"
            )
      )
    }
    Write-Host "  ✅ MFA check complete — HasMFA: $($mfaStatus.HasMFA)" -ForegroundColor Green
    Write-Host ""
  }

  # ── Step 8 : Azure RBAC ───────────────────────────────────────────────────────
  if ($IncludeAzureRBAC) {
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   STEP 8 of 9  ›  Azure RBAC Role Assignments               │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    $effectiveSubscriptionId = if ($SubscriptionId) { $SubscriptionId } else { [System.Environment]::GetEnvironmentVariable("AZURE_SUBSCRIPTION_ID") }
    Write-Host "  ⏳ Querying Azure RBAC for subscription: $effectiveSubscriptionId" -ForegroundColor Yellow

    $rbacFindings = Get-AzureRBACAssignments -ObjectId $TargetIdentityId -SubscriptionId $effectiveSubscriptionId
    $rbacFindings | ForEach-Object { $null = $allFindings.Add($_) }

    Write-Host "  ✅ $($rbacFindings.Count) Azure RBAC finding(s)" -ForegroundColor Green
    Write-Host ""
  }

  # ── Step 9 : Score & Export ───────────────────────────────────────────────────
  Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
  Write-Host "  │   STEP 9 of 9  ›  Scoring, Export & Dashboard               │" -ForegroundColor DarkCyan
  Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
  Write-Host ""

  $blastScore = Measure-BlastRadius -Findings $allFindings
  $blastBand = Get-BlastRadiusBand -Score $blastScore

  $critCount = ($allFindings | Where-Object { $_.RiskTier -eq "Critical" }).Count
  $highCount = ($allFindings | Where-Object { $_.RiskTier -eq "High" }).Count

  Write-Host "  💥 Blast-Radius Score : $blastScore / 100  [$($blastBand.Label)]" -ForegroundColor $(if ($blastScore -ge 61) { "Red" } elseif ($blastScore -ge 41) { "Yellow" } else { "Green" })
  Write-Host "  🔴 Critical Findings  : $critCount" -ForegroundColor Red
  Write-Host "  🟠 High Findings      : $highCount" -ForegroundColor Yellow
  Write-Host "  📊 Total Findings     : $($allFindings.Count)" -ForegroundColor Cyan
  Write-Host ""

  # CSV Export
  $csvPath = Join-Path $OutputPath "BlastRadius-$TargetIdentityId-$fileTimestamp.csv"
  Write-Host "  ⏳ Exporting CSV..." -ForegroundColor Yellow
  $allFindings | Export-Csv -Path $csvPath -NoTypeInformation -Force
  Write-Host "  ✅ CSV exported → $csvPath" -ForegroundColor Green

  # HTML Dashboard
  $htmlPath = $null
  if ($GenerateDashboard) {
    $htmlPath = Join-Path $OutputPath "BlastRadius-$TargetIdentityId-$fileTimestamp.html"
    Write-Host "  ⏳ Generating HTML dashboard..." -ForegroundColor Yellow

    Generate-BlastRadiusDashboard `
      -IdentityProfile    $identityProfile `
      -IdentityType       $identityType `
      -Findings           $allFindings `
      -GroupMemberships   $groupMemberships `
      -BlastRadiusScore   $blastScore `
      -BlastRadiusBand    $blastBand `
      -MFAStatus          $mfaStatus `
      -AssessmentTimestamp $assessmentTimestamp `
      -TenantId           $TenantId `
      -OutputFilePath     $htmlPath

    Write-Host "  ✅ Dashboard generated → $htmlPath" -ForegroundColor Green

    if (-not $NoBrowserLaunch) {
      Write-Host "  🌐 Opening dashboard in browser..." -ForegroundColor Cyan
      Start-Process $htmlPath
    }
  }

  # ── Execution Summary ─────────────────────────────────────────────────────────
  $scriptEndTime = Get-Date
  $execTime = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime

  Write-Host ""
  Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
  Write-Host "  ║                    EXECUTION SUMMARY                         ║" -ForegroundColor Cyan
  Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
  Write-Host "  ║  👤 Identity           : $($identityProfile.displayName.PadRight(33))║" -ForegroundColor Green
  Write-Host "  ║  🆔 Type               : $($identityType.PadRight(33))║" -ForegroundColor Green
  Write-Host "  ║  💥 Blast-Radius Score : $("$blastScore / 100  [$($blastBand.Label)]".PadRight(33))║" -ForegroundColor $(if ($blastScore -ge 61) { "Red" } elseif ($blastScore -ge 41) { "Yellow" } else { "Green" })
  Write-Host "  ║  🔴 Critical Findings  : $($critCount.ToString().PadRight(33))║" -ForegroundColor Red
  Write-Host "  ║  🟠 High Findings      : $($highCount.ToString().PadRight(33))║" -ForegroundColor Yellow
  Write-Host "  ║  📊 Total Findings     : $($allFindings.Count.ToString().PadRight(33))║" -ForegroundColor Cyan
  Write-Host "  ║  👥 Group Memberships  : $($groupMemberships.Count.ToString().PadRight(33))║" -ForegroundColor Cyan
  Write-Host "  ║  🕐 Started            : $($scriptStartTime.ToString('hh:mm:ss tt').PadRight(33))║" -ForegroundColor Gray
  Write-Host "  ║  🕑 Ended              : $($scriptEndTime.ToString('hh:mm:ss tt').PadRight(33))║" -ForegroundColor Gray
  Write-Host "  ║  ⏱️ Duration           : $($execTime.ToString('hh\:mm\:ss').PadRight(33))║" -ForegroundColor Yellow
  Write-Host "  ║  📄 CSV                : $('See OutputPath'.PadRight(33))║" -ForegroundColor Gray
  if ($htmlPath) {
    Write-Host "  ║  🌐 Dashboard          : $('See OutputPath'.PadRight(33))║" -ForegroundColor Gray
  }
  Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
  Write-Host ""
}
