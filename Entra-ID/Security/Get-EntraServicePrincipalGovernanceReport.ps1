<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 24 August 2026
Modified-On  : 24 August 2026

.SYNOPSIS
    Multi-tenant Service Principal governance report for Entra ID — exports a
    detailed CSV and an interactive HTML dashboard.

.DESCRIPTION
    Connects to one or more Entra ID tenants using app-only (client credentials)
    authentication and collects Service Principal data via Microsoft Graph API:
    attributes, application permissions, delegated permissions, and owner details.

    For each Service Principal the script calculates a permission-risk rating
    (High / Medium / Low), identifies missing owners, and captures governance
    signals useful for security review and remediation.

    Two outputs are produced:
        CSV  — one row per permission grant; suitable for SIEM ingestion, further
               analysis, or upstream tooling.
        HTML — executive / analyst dashboard built on the golden theme, with tabs
               for Overview, Governance Findings, All Service Principals, and a
               searchable permission detail table.

    The relationship model collected is intentionally graph-friendly:
        Tenant → Service Principal → Application → Owner → Permission → API
    Consistent keys (SP id, appId, TenantId) allow the data to seed a future
    dependency-graph or LLM-based analysis pipeline without schema changes.

.PARAMETER ClientId
    Application (client) ID of the multi-tenant app registration used for
    authentication. Must be registered in your "home" tenant and have a Service
    Principal instantiated in every target tenant (see Prerequisites).

.PARAMETER ClientSecret
    Client secret for the app registration, supplied as a SecureString.
    Example:
        $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
        Get-EntraServicePrincipalGovernanceReport `
            -ClientId $id -ClientSecret $secret -TenantIds $tids

.PARAMETER TenantIds
    String array of Entra ID tenant IDs to process.
    Example: -TenantIds "tenant1-guid","tenant2-guid"

.PARAMETER OutputPath
    Full file path for the CSV report.
    Default: C:\Temp\EntraID-ServicePrincipal-GovernanceReport.csv

.PARAMETER HtmlOutputPath
    Full file path for the HTML dashboard.
    Default: C:\Temp\EntraID-ServicePrincipal-GovernanceDashboard.html

.PARAMETER OpenBrowser
    Switch. When supplied, opens the generated HTML dashboard in the default
    browser after generation.

.PARAMETER ShowHelp
    Switch. Displays a plain-language usage guide and exits immediately.
    No authentication is attempted.

.INPUTS
    None. Does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        CSV report and HTML dashboard written to the paths defined by
        -OutputPath and -HtmlOutputPath.

.EXAMPLE
    Get-EntraServicePrincipalGovernanceReport -ShowHelp

    Displays the usage guide and exits.

.EXAMPLE
    $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    Get-EntraServicePrincipalGovernanceReport `
        -ClientId "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantIds "aabbcc00-xxxx","ddeeff11-xxxx"

    Runs against two tenants with default output paths.

.EXAMPLE
    $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    Get-EntraServicePrincipalGovernanceReport `
        -ClientId "8ad5d2f5-xxxx" `
        -ClientSecret $secret `
        -TenantIds "aabbcc00-xxxx" `
        -OutputPath "D:\Reports\SP-Report.csv" `
        -HtmlOutputPath "D:\Reports\SP-Dashboard.html" `
        -OpenBrowser

    Custom output paths, opens the dashboard on completion.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (24-Aug-2026) - Initial public release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. App registration in your home tenant:
               Supported account types: "Accounts in any organizational directory
               (Any Entra ID directory — Multitenant)"
               API permissions (Application, admin-consented):
                   Application.Read.All
                   Directory.Read.All
                   RoleManagement.Read.Directory    (for permission resolution)

        2. For each additional (target) tenant, create a Service Principal from
           the home-tenant App registration and grant the permissions above:

               # Run in each target tenant
               Connect-MgGraph -Scopes "Application.ReadWrite.All" -TenantId <TargetTenantId>
               New-MgServicePrincipal -AppId "<HomeAppClientId>"

           Then grant the API permissions via Microsoft Graph or the portal
           (see the Microsoft article linked in .LINK).

        3. PowerShell 5.1 or later.

        4. The Microsoft.Graph PowerShell module is NOT required — this script
           calls the Graph REST API directly and manages its own token lifecycle.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0 → If -ShowHelp, display guide and exit
        Step 1 → For each tenant:
                   a. Authenticate (client credentials flow)
                   b. Retrieve tenant metadata
                   c. Retrieve all Service Principals (paginated)
                   d. For each SP: fetch permissions and owners
                   e. Calculate per-permission risk rating
        Step 2 → Export consolidated CSV
        Step 3 → Generate HTML dashboard from the collected data
        Step 4 → Optionally open the dashboard

    ─────────────────────────────────────────────────────────────────────────────
    Architecture Note (Future-Readiness):
    ─────────────────────────────────────────────────────────────────────────────
        The data model is intentionally relationship-structured so every record
        carries consistent keys for graph-based analysis:
            TenantId  → sp.Id  → sp.appId  → ownerId  → permission  → resource

        This makes the CSV a suitable seed for a future Neo4j / Kusto / LLM
        dependency-graph pipeline without schema changes.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the /beta Graph API endpoint. Beta endpoints are subject to change
          and should be monitored for breaking changes before production use.
        - The client secret is marshaled to plaintext transiently inside
          RequestAccessToken for the OAuth token request. This is inherent to
          the client-credentials grant type.
        - Permission risk ratings are heuristic (pattern-based). They indicate
          elevated-risk patterns, not confirmed security incidents.
        - "Unused SP" detection is not implemented — last sign-in data for
          Service Principals requires additional licensing and scope, and results
          can be unreliable. Do not assert staleness without reliable data.

.LINK
    Microsoft Graph — List Service Principals
    https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list

.LINK
    Microsoft Graph — Grant app-role assignments (multi-tenant consent)
    https://learn.microsoft.com/en-us/graph/permissions-grant-via-msgraph?tabs=http&pivots=grant-application-permissions

.LINK
    Create a multi-tenant Service Principal cross-tenant
    https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/create-service-principal-cross-tenant

#>


Function Get-EntraServicePrincipalGovernanceReport {
  [CmdletBinding(DefaultParameterSetName = 'Run')]
  param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Run')]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Run')]
    [System.Security.SecureString]$ClientSecret,

    [Parameter(Mandatory = $true, ParameterSetName = 'Run')]
    [ValidateNotNullOrEmpty()]
    [string[]]$TenantIds,

    [Parameter(ParameterSetName = 'Run')]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = 'C:\Temp\EntraID-ServicePrincipal-GovernanceReport.csv',

    [Parameter(ParameterSetName = 'Run')]
    [ValidateNotNullOrEmpty()]
    [string]$HtmlOutputPath = 'C:\Temp\EntraID-ServicePrincipal-GovernanceDashboard.html',

    [Parameter(ParameterSetName = 'Run')]
    [switch]$OpenBrowser,

    [Parameter(ParameterSetName = 'Help')]
    [switch]$ShowHelp
  )

  #region ── Friendly Help ──────────────────────────────────────────────────────

  Function Show-FriendlyHelp {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║   Entra ID Service Principal Governance Report  v1.0            ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  PURPOSE" -ForegroundColor Yellow
    Write-Host "    Audits Service Principals across multiple Entra ID tenants."
    Write-Host "    Exports a CSV and an interactive HTML governance dashboard."
    Write-Host ""
    Write-Host "  SYNTAX" -ForegroundColor Yellow
    Write-Host '    $secret = Read-Host -Prompt "Enter client secret" -AsSecureString'
    Write-Host '    Get-EntraServicePrincipalGovernanceReport \'
    Write-Host '        -ClientId   "<AppClientId>" \'
    Write-Host '        -ClientSecret $secret \'
    Write-Host '        -TenantIds  "tenant1-guid","tenant2-guid"'
    Write-Host ""
    Write-Host "  PARAMETERS" -ForegroundColor Yellow
    Write-Host "    -ClientId          App (client) ID of your multi-tenant app registration."
    Write-Host "    -ClientSecret      Client secret (SecureString)."
    Write-Host "    -TenantIds         One or more target tenant IDs (comma-separated)."
    Write-Host "    -OutputPath        CSV report path. Default: C:\Temp\...Report.csv"
    Write-Host "    -HtmlOutputPath    HTML dashboard path. Default: C:\Temp\...Dashboard.html"
    Write-Host "    -OpenBrowser       Opens the HTML dashboard after generation."
    Write-Host "    -ShowHelp          Shows this guide and exits."
    Write-Host ""
    Write-Host "  PREREQUISITES" -ForegroundColor Yellow
    Write-Host "    1. Multi-tenant app registration in your home tenant."
    Write-Host "    2. API permissions (Application, admin-consented):"
    Write-Host "          Application.Read.All  |  Directory.Read.All  |  RoleManagement.Read.Directory"
    Write-Host "    3. Service Principal created in each target tenant."
    Write-Host "    4. PowerShell 5.1 or later (no extra modules required)."
    Write-Host ""
    Write-Host "  OUTPUTS" -ForegroundColor Yellow
    Write-Host "    CSV  — one row per permission grant; columns include SP attributes,"
    Write-Host "           owner details, permission type, risk rating, and tenant context."
    Write-Host "    HTML — multi-tab governance dashboard with Overview, Findings, SPs,"
    Write-Host "           and Permissions detail table."
    Write-Host ""
  }

  if ($ShowHelp) {
    Show-FriendlyHelp
    return
  }

  #endregion

  #region ── Token Helpers (script scope) ──────────────────────────────────────

  Function RequestAccessToken {
    $tokenEndpoint = "https://login.microsoftonline.com/$global:TenantId/oauth2/v2.0/token"
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($global:ClientSecretSecure)
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    try {
      $body = @{
        client_id     = $global:ClientId
        client_secret = $plain
        scope         = 'https://graph.microsoft.com/.default'
        grant_type    = 'client_credentials'
      }
      $resp = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ErrorAction Stop
      $global:accessToken = $resp.access_token
      $global:tokenExpirationTime = (Get-Date).AddSeconds($resp.expires_in)
    }
    finally {
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
      $plain = $null
    }
  }

  Function RenewTokenIfNeeded {
    if (-not $global:accessToken -or -not $global:tokenExpirationTime) { RequestAccessToken; return }
    $minutesToExpiry = ($global:tokenExpirationTime - (Get-Date)).TotalMinutes
    if ($minutesToExpiry -lt 5) { RequestAccessToken }
  }

  #endregion

  #region ── Functions ──────────────────────────────────────────────────────────

  Function Connect-EntraID {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$ClientId,

      [Parameter(Mandatory = $true)]
      [System.Security.SecureString]$ClientSecret,

      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$TenantId
    )

    try {
      $global:accessToken = $null
      $global:tokenExpirationTime = $null
      $global:TenantId = $TenantId
      $global:ClientId = $ClientId
      $global:ClientSecretSecure = $ClientSecret

      RequestAccessToken
      return $global:accessToken
    }
    catch {
      Write-Error "Connect-EntraID: Failed to authenticate to tenant '$TenantId'. Details: $_"
      return $null
    }
  }


  Function Get-TenantDetails {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$AccessToken
    )

    $headers = @{ 'Authorization' = "Bearer $AccessToken" }

    try {
      $resp = Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/organization' `
        -Headers $headers -Method Get -ErrorAction Stop

      $primaryDomain = ($resp.value.verifiedDomains | Where-Object { $_.isDefault -eq $true }).name

      return [PSCustomObject]@{
        TenantId            = $resp.value.id
        TenantName          = $resp.value.displayName
        TenantPrimaryDomain = $primaryDomain
        TenantType          = $resp.value.tenantType
        Country             = $resp.value.country
        CountryCode         = $resp.value.countryLetterCode
        CreatedDate         = $resp.value.createdDateTime
        TechnicalContacts   = ($resp.value.technicalNotificationMails -join '; ')
      }
    }
    catch {
      Write-Error "Get-TenantDetails: Failed. Details: $_"
      return $null
    }
  }


  Function Get-AllServicePrincipals {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$AccessToken
    )

    $allSPs = New-Object System.Collections.ArrayList
    $totalSPs = 0
    $fields = 'id,appId,appDisplayName,accountEnabled,createdDateTime,appOwnerOrganizationId,' +
    'appRoleAssignmentRequired,disabledByMicrosoftStatus,notificationEmailAddresses,' +
    'preferredSingleSignOnMode,publisherName,servicePrincipalType,signInAudience,tags'
    $uri = "https://graph.microsoft.com/beta/servicePrincipals?`$top=999&`$select=$fields&`$count=true"

    do {
      RenewTokenIfNeeded
      $AccessToken = $global:accessToken

      if (-not $AccessToken) {
        Write-Error "Get-AllServicePrincipals: No access token available."
        return
      }

      $headers = @{
        'Authorization'    = "Bearer $AccessToken"
        'ConsistencyLevel' = 'eventual'
      }

      $skip = $false
      $partialData = $null

      do {
        try {
          $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
          $statusCode = $partialData.StatusCode
        }
        catch {
          $statusCode = $_.Exception.Response.StatusCode

          if ($statusCode -eq 429) {
            $sleepTime = $_.Exception.Response.Headers.Item('Retry-After')
            Write-Host "    ⏳ Throttled — retrying in $sleepTime seconds..." -ForegroundColor DarkYellow
            Start-Sleep -Seconds $sleepTime
          }
          else {
            Write-Warning "Get-AllServicePrincipals: HTTP $statusCode — $($_.Exception.Message)"
            $skip = $true
          }
        }
      } until (($statusCode -eq 200) -or ($skip -eq $true))

      if ($partialData) {
        $spData = $partialData.content | ConvertFrom-Json
        $totalSPs += $spData.value.Count

        if ($spData.PSObject.Properties['@odata.nextLink']) {
          Write-Host -NoNewline "`r    📦 $totalSPs Service Principals retrieved...    " -ForegroundColor Cyan
        }
        else {
          Write-Host -NoNewline "`r    📦 $totalSPs Service Principals retrieved (100%)    " -ForegroundColor Cyan
        }

        if ($spData.PSObject.Properties['@odata.nextLink']) { $uri = $spData.'@odata.nextLink' }
        $spData.value | ForEach-Object { $null = $allSPs.Add($_) }
      }

    } until (-not ($spData.PSObject.Properties['@odata.nextLink']))

    Write-Host ""
    return $allSPs
  }


  Function Get-ServicePrincipalPermissions {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$AccessToken,

      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$ServicePrincipalId,

      [ValidateSet('Application', 'Delegated', 'Both')]
      [string]$PermissionType = 'Both'
    )

    $headers = @{ 'Authorization' = "Bearer $AccessToken" }
    $permissions = @()

    # ── Application permissions ──────────────────────────────────────────────
    if ($PermissionType -in 'Both', 'Application') {
      try {
        $uri = "https://graph.microsoft.com/beta/servicePrincipals/$ServicePrincipalId/appRoleAssignments"
        $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop

        foreach ($grant in $resp.value) {
          # Resolve the API resource name and role display name via the resource SP
          $resourceUri = "https://graph.microsoft.com/beta/servicePrincipals/$($grant.resourceId)?`$select=appDisplayName,appRoles"
          $resourceResp = Invoke-RestMethod -Uri $resourceUri -Headers $headers -Method Get -ErrorAction SilentlyContinue

          $resourceName = if ($resourceResp) { $resourceResp.appDisplayName } else { $grant.resourceDisplayName }
          $roleName = if ($resourceResp) {
            ($resourceResp.appRoles | Where-Object { $_.id -eq $grant.appRoleId } | Select-Object -First 1).value
          }
          else { $grant.appRoleId }

          if (-not $roleName) { $roleName = $grant.appRoleId }

          $permissions += [PSCustomObject]@{
            PermissionType = 'Application'
            Resource       = $resourceName
            PermissionName = $roleName
            Consent        = 'AdminConsent'
          }
        }
      }
      catch {
        Write-Verbose "Get-ServicePrincipalPermissions: Application permissions lookup failed for $ServicePrincipalId — $($_.Exception.Message)"
      }
    }

    # ── Delegated permissions ────────────────────────────────────────────────
    if ($PermissionType -in 'Both', 'Delegated') {
      try {
        $uri = "https://graph.microsoft.com/beta/servicePrincipals/$ServicePrincipalId/oauth2PermissionGrants"
        $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop

        foreach ($grant in $resp.value) {
          $resourceUri = "https://graph.microsoft.com/beta/servicePrincipals/$($grant.resourceId)?`$select=appDisplayName"
          $resourceResp = Invoke-RestMethod -Uri $resourceUri -Headers $headers -Method Get -ErrorAction SilentlyContinue
          $resourceName = if ($resourceResp) { $resourceResp.appDisplayName } else { $grant.resourceId }

          $scopeNames = ($grant.scope -split '\s+' | Where-Object { $_ }) -join ', '

          $permissions += [PSCustomObject]@{
            PermissionType = 'Delegated'
            Resource       = $resourceName
            PermissionName = $scopeNames
            Consent        = $grant.consentType
          }
        }
      }
      catch {
        Write-Verbose "Get-ServicePrincipalPermissions: Delegated permissions lookup failed for $ServicePrincipalId — $($_.Exception.Message)"
      }
    }

    return $permissions
  }


  Function Get-ServicePrincipalOwners {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$AccessToken,

      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$ServicePrincipalId
    )

    $headers = @{ 'Authorization' = "Bearer $AccessToken" }

    try {
      $resp = Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/beta/servicePrincipals/$ServicePrincipalId/owners" `
        -Headers $headers -Method Get -ErrorAction Stop

      if (-not $resp.value -or $resp.value.Count -eq 0) { return $null }

      return $resp.value | ForEach-Object {
        [PSCustomObject]@{
          DisplayName       = if ($_.PSObject.Properties['displayName']) { $_.displayName }       else { '-' }
          UserPrincipalName = if ($_.PSObject.Properties['userPrincipalName']) { $_.userPrincipalName } else { '-' }
          Mail              = if ($_.PSObject.Properties['mail']) { $_.mail }              else { '-' }
        }
      }
    }
    catch {
      Write-Verbose "Get-ServicePrincipalOwners: Lookup failed for $ServicePrincipalId — $($_.Exception.Message)"
      return $null
    }
  }


  Function Get-PermissionRisk {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $true)]
      [string]$PermissionName,

      [Parameter(Mandatory = $true)]
      [ValidateSet('Application', 'Delegated')]
      [string]$PermissionType
    )

    # Application permissions are inherently higher risk than delegated
    $baseMultiplier = if ($PermissionType -eq 'Application') { 1 } else { 0 }

    if ($PermissionName -match '\.(Delete|Manage|PrivilegedOperations|Migrate|FullControl|Export|ManageIdentities|Initiate|AccessMedia|JoinGroupCall|InitiateGroupCall|JoinGroupCallAsGuest)\.All' -or
      $PermissionName -match '\.(ReadWrite|Send)\.' -or
      $PermissionName -like '*.Create' -or
      $PermissionName -like '*.Invite.All' -or
      $PermissionName -like 'Directory.ReadWrite.*' -or
      $PermissionName -like 'RoleManagement.ReadWrite.*') {
      return 'High'
    }
    elseif ($PermissionName -like '*.Read.All' -or $PermissionName -match '\.Read\.') {
      if ($baseMultiplier -eq 1) { return 'Medium' } else { return 'Low' }
    }
    else {
      return 'Low'
    }
  }


  Function ConvertTo-JsonSafe {
    param([string]$Value)
    return [string]$Value `
      -replace '\\', '\\' `
      -replace '"', '\"' `
      -replace "`r`n", '\n' `
      -replace "`n", '\n' `
      -replace "`r", '\n' `
      -replace "`t", '\t' `
      -replace '<', '\u003c' `
      -replace '>', '\u003e' `
      -replace '\$', '\u0024'
  }

  #endregion

  #region ── Startup ────────────────────────────────────────────────────────────

  Clear-Host

  Write-Host ""
  Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
  Write-Host "  ║   Entra ID Service Principal Governance Report  v1.0             ║" -ForegroundColor Cyan
  Write-Host "  ║   Multi-Tenant  ·  App-Only Auth  ·  CSV + HTML Dashboard        ║" -ForegroundColor Cyan
  Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
  Write-Host ""

  $scriptStartTime = Get-Date
  Write-Host "  🕐 Started: $($scriptStartTime.ToString('dd MMM yyyy  HH:mm:ss'))" -ForegroundColor Gray
  Write-Host "  🏢 Tenants configured: $($TenantIds.Count)" -ForegroundColor Gray
  Write-Host "  📄 CSV output  : $OutputPath" -ForegroundColor Gray
  Write-Host "  🌐 HTML output : $HtmlOutputPath" -ForegroundColor Gray
  Write-Host ""

  # ── Ensure output directories exist ─────────────────────────────────────────
  foreach ($outPath in @($OutputPath, $HtmlOutputPath)) {
    $dir = Split-Path -Parent $outPath
    if ($dir -and -not (Test-Path $dir)) {
      try { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
      catch { Write-Warning "Could not create directory '$dir': $_" }
    }
  }

  #endregion

  #region ── Data Collection ────────────────────────────────────────────────────

  $allTenantsData = New-Object System.Collections.ArrayList
  $tenantSummaries = New-Object System.Collections.ArrayList
  $tenantCounter = 1

  foreach ($tid in $TenantIds) {
    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │  TENANT $tenantCounter of $($TenantIds.Count)                                                  │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    # ── Authenticate ─────────────────────────────────────────────────────────
    Write-Host "  ⏳ Authenticating..." -ForegroundColor Yellow
    $token = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $tid

    if (-not $token) {
      Write-Warning "  ❌ Authentication failed for tenant '$tid'. Skipping."
      $tenantCounter++
      continue
    }

    # ── Tenant metadata ───────────────────────────────────────────────────────
    $tenant = Get-TenantDetails -AccessToken $token

    if (-not $tenant) {
      Write-Warning "  ❌ Could not retrieve tenant details for '$tid'. Skipping."
      $tenantCounter++
      continue
    }

    Write-Host "  ✅ Connected to: $($tenant.TenantName) ($($tenant.TenantPrimaryDomain))" -ForegroundColor Green
    Write-Host ""

    # ── Service Principals ────────────────────────────────────────────────────
    Write-Host "  ⏳ Retrieving Service Principals..." -ForegroundColor Yellow
    $servicePrincipals = Get-AllServicePrincipals -AccessToken $global:accessToken

    $spCount = $servicePrincipals.Count
    Write-Host "  ✅ $spCount Service Principals found" -ForegroundColor Green
    Write-Host ""

    # ── Per-SP detail loop ────────────────────────────────────────────────────
    Write-Host "  ⏳ Processing permissions and owners..." -ForegroundColor Yellow
    Write-Host ""

    $progress = 0
    $tenantRows = New-Object System.Collections.ArrayList
    $milestoneStep = [Math]::Max(1, [Math]::Ceiling($spCount / 10))

    foreach ($sp in $servicePrincipals) {
      RenewTokenIfNeeded
      $token = $global:accessToken

      $permissions = Get-ServicePrincipalPermissions -AccessToken $token -ServicePrincipalId $sp.id
      $owners = Get-ServicePrincipalOwners      -AccessToken $token -ServicePrincipalId $sp.id

      $ownerName = if ($owners) { ($owners.DisplayName       | Where-Object { $_ -ne '-' }) -join ' ; ' } else { '-' }
      $ownerMail = if ($owners) { ($owners.Mail              | Where-Object { $_ -ne '-' }) -join ' ; ' } else { '-' }
      $ownerUPN = if ($owners) { ($owners.UserPrincipalName | Where-Object { $_ -ne '-' }) -join ' ; ' } else { '-' }

      if ($permissions.Count -eq 0) {
        # Emit one row with empty permission fields so the SP is still visible in CSV
        $null = $tenantRows.Add([PSCustomObject]@{
            Id                         = $sp.id
            AppId                      = $sp.appId
            AppDisplayName             = $sp.appDisplayName
            AccountEnabled             = $sp.accountEnabled
            CreatedDateTime            = $sp.createdDateTime
            AppOwnerOrganizationId     = $sp.appOwnerOrganizationId
            AppRoleAssignmentRequired  = $sp.appRoleAssignmentRequired
            DisabledByMicrosoftStatus  = if ($sp.disabledByMicrosoftStatus) { $sp.disabledByMicrosoftStatus } else { '-' }
            NotificationEmailAddresses = if ($sp.notificationEmailAddresses) { $sp.notificationEmailAddresses -join ', ' } else { '-' }
            PreferredSingleSignOnMode  = if ($sp.preferredSingleSignOnMode) { $sp.preferredSingleSignOnMode } else { '-' }
            PublisherName              = if ($sp.publisherName) { $sp.publisherName }              else { '-' }
            ServicePrincipalType       = $sp.servicePrincipalType
            SignInAudience             = $sp.signInAudience
            Tags                       = if ($sp.tags) { $sp.tags -join ', ' } else { '-' }
            HasOwner                   = ($owners -ne $null)
            OwnerName                  = $ownerName
            OwnerMail                  = $ownerMail
            OwnerUPN                   = $ownerUPN
            PermissionType             = '-'
            Resource                   = '-'
            PermissionName             = '-'
            Risk                       = '-'
            Consent                    = '-'
            TenantId                   = $tenant.TenantId
            TenantName                 = $tenant.TenantName
            TenantPrimaryDomainName    = $tenant.TenantPrimaryDomain
          })
      }
      else {
        foreach ($perm in $permissions) {
          $risk = Get-PermissionRisk -PermissionName $perm.PermissionName -PermissionType $perm.PermissionType

          $null = $tenantRows.Add([PSCustomObject]@{
              Id                         = $sp.id
              AppId                      = $sp.appId
              AppDisplayName             = $sp.appDisplayName
              AccountEnabled             = $sp.accountEnabled
              CreatedDateTime            = $sp.createdDateTime
              AppOwnerOrganizationId     = $sp.appOwnerOrganizationId
              AppRoleAssignmentRequired  = $sp.appRoleAssignmentRequired
              DisabledByMicrosoftStatus  = if ($sp.disabledByMicrosoftStatus) { $sp.disabledByMicrosoftStatus } else { '-' }
              NotificationEmailAddresses = if ($sp.notificationEmailAddresses) { $sp.notificationEmailAddresses -join ', ' } else { '-' }
              PreferredSingleSignOnMode  = if ($sp.preferredSingleSignOnMode) { $sp.preferredSingleSignOnMode } else { '-' }
              PublisherName              = if ($sp.publisherName) { $sp.publisherName }              else { '-' }
              ServicePrincipalType       = $sp.servicePrincipalType
              SignInAudience             = $sp.signInAudience
              Tags                       = if ($sp.tags) { $sp.tags -join ', ' } else { '-' }
              HasOwner                   = ($owners -ne $null)
              OwnerName                  = $ownerName
              OwnerMail                  = $ownerMail
              OwnerUPN                   = $ownerUPN
              PermissionType             = $perm.PermissionType
              Resource                   = $perm.Resource
              PermissionName             = $perm.PermissionName
              Risk                       = $risk
              Consent                    = $perm.Consent
              TenantId                   = $tenant.TenantId
              TenantName                 = $tenant.TenantName
              TenantPrimaryDomainName    = $tenant.TenantPrimaryDomain
            })
        }
      }

      $progress++

      # Inline progress bar (20 blocks = 100%)
      $pct = [Math]::Round(($progress / $spCount) * 100)
      $filled = [Math]::Floor($pct / 5)
      $bar = '█' * $filled + '░' * (20 - $filled)
      Write-Host -NoNewline "`r  [$bar] $pct%  ($progress / $spCount)   " -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host ""

    # ── Tenant summary for the dashboard ────────────────────────────────────
    $tenantSPs = $tenantRows | Select-Object -Property Id, AppDisplayName, HasOwner, Risk, ServicePrincipalType, AccountEnabled -Unique
    $highRiskSPs = @($tenantRows | Where-Object { $_.Risk -eq 'High' } | Select-Object Id -Unique).Count
    $noOwnerSPs = @($tenantRows | Where-Object { $_.HasOwner -eq $false } | Select-Object Id -Unique).Count
    $disabledSPs = @($tenantRows | Where-Object { $_.AccountEnabled -eq $false } | Select-Object Id -Unique).Count

    $null = $tenantSummaries.Add([PSCustomObject]@{
        TenantId      = $tenant.TenantId
        TenantName    = $tenant.TenantName
        PrimaryDomain = $tenant.TenantPrimaryDomain
        Country       = $tenant.Country
        SPCount       = $spCount
        HighRiskSPs   = $highRiskSPs
        NoOwnerSPs    = $noOwnerSPs
        DisabledSPs   = $disabledSPs
      })

    $tenantRows | ForEach-Object { $null = $allTenantsData.Add($_) }

    Write-Host "  ✅ Tenant '$($tenant.TenantName)' complete — $($tenantRows.Count) records collected" -ForegroundColor Green
    Write-Host ""
    $tenantCounter++
  }

  #endregion

  #region ── CSV Export ─────────────────────────────────────────────────────────

  Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
  Write-Host "  │  STEP 2  ›  Exporting CSV                                       │" -ForegroundColor DarkCyan
  Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
  Write-Host ""

  if ($allTenantsData.Count -gt 0) {
    try {
      $allTenantsData | Export-Csv -Path $OutputPath -NoTypeInformation -Force
      Write-Host "  ✅ CSV exported: $OutputPath  ($($allTenantsData.Count) rows)" -ForegroundColor Green
    }
    catch {
      Write-Warning "  ❌ CSV export failed: $_"
    }
  }
  else {
    Write-Warning "  ⚠️  No data collected — CSV not written."
  }

  Write-Host ""

  #endregion

  #region ── HTML Dashboard ─────────────────────────────────────────────────────

  Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
  Write-Host "  │  STEP 3  ›  Generating HTML Dashboard                           │" -ForegroundColor DarkCyan
  Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
  Write-Host ""
  Write-Host "  ⏳ Building dashboard data..." -ForegroundColor Yellow

  # ── Compute governance metrics ───────────────────────────────────────────────
  $totalSPsAll = ($allTenantsData | Select-Object Id -Unique).Count
  $totalHighRisk = ($allTenantsData | Where-Object { $_.Risk -eq 'High' }   | Select-Object Id -Unique).Count
  $totalNoOwner = ($allTenantsData | Where-Object { $_.HasOwner -eq $false } | Select-Object Id -Unique).Count
  $totalDisabled = ($allTenantsData | Where-Object { $_.AccountEnabled -eq $false } | Select-Object Id -Unique).Count
  $totalTenants = $tenantSummaries.Count
  $totalHighRiskPerms = ($allTenantsData | Where-Object { $_.Risk -eq 'High' } | Measure-Object).Count

  # Risk distribution (by unique SP)
  $spRiskGroups = $allTenantsData | Group-Object Id | ForEach-Object {
    $risks = $_.Group.Risk | Where-Object { $_ -ne '-' }
    if ($risks -contains 'High') { 'High' }
    elseif ($risks -contains 'Medium') { 'Medium' }
    elseif ($risks -contains 'Low') { 'Low' }
    else { 'None' }
  } | Group-Object | Sort-Object Name

  $riskHigh = ($spRiskGroups | Where-Object { $_.Name -eq 'High' }).Count
  $riskMed = ($spRiskGroups | Where-Object { $_.Name -eq 'Medium' }).Count
  $riskLow = ($spRiskGroups | Where-Object { $_.Name -eq 'Low' }).Count
  $riskNone = ($spRiskGroups | Where-Object { $_.Name -eq 'None' }).Count

  # SP type distribution
  $typeGroups = $allTenantsData | Select-Object Id, ServicePrincipalType -Unique |
  Group-Object ServicePrincipalType | Sort-Object Count -Descending

  # Top high-risk SPs (unique, sorted by permission count)
  $topHighRiskSPs = $allTenantsData | Where-Object { $_.Risk -eq 'High' } |
  Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10 |
  ForEach-Object {
    $first = $_.Group[0]
    [PSCustomObject]@{
      Name      = $first.AppDisplayName
      Tenant    = $first.TenantName
      PermCount = $_.Count
      HasOwner  = $first.HasOwner
      Enabled   = $first.AccountEnabled
    }
  }

  # SPs without owners (top 10 for display)
  $noOwnerList = $allTenantsData | Where-Object { $_.HasOwner -eq $false } |
  Select-Object Id, AppDisplayName, TenantName, ServicePrincipalType, AccountEnabled -Unique |
  Select-Object -First 10

  # Permission resource breakdown
  $resourceGroups = $allTenantsData | Where-Object { $_.Resource -ne '-' } |
  Group-Object Resource | Sort-Object Count -Descending | Select-Object -First 8

  # ── Serialize data for JS ────────────────────────────────────────────────────
  $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')

  # Tenant summaries JSON
  $tenantJson = ($tenantSummaries | ForEach-Object {
      $n = ConvertTo-JsonSafe $_.TenantName
      $d = ConvertTo-JsonSafe $_.PrimaryDomain
      $c = ConvertTo-JsonSafe $_.Country
      "{`"name`":`"$n`",`"domain`":`"$d`",`"country`":`"$c`",`"spCount`":$($_.SPCount),`"highRisk`":$($_.HighRiskSPs),`"noOwner`":$($_.NoOwnerSPs),`"disabled`":$($_.DisabledSPs)}"
    }) -join ','

  # Full SP table JSON (unique SPs, aggregated risk)
  $spTableJson = ($allTenantsData | Select-Object Id, AppDisplayName, AppId, ServicePrincipalType,
    AccountEnabled, HasOwner, TenantName, TenantPrimaryDomainName, CreatedDateTime,
    PublisherName, AppOwnerOrganizationId -Unique |
    ForEach-Object {
      # Determine highest risk for this SP
      $spRows = @($allTenantsData | Where-Object { $_.Id -eq $_.Id })
      $risks = @($allTenantsData | Where-Object { $_.Id -eq $PSItem.Id }).Risk | Where-Object { $_ -ne '-' }
      $topRisk = if ($risks -contains 'High') { 'High' } elseif ($risks -contains 'Medium') { 'Medium' } elseif ($risks -contains 'Low') { 'Low' } else { 'None' }
      $permCnt = @($allTenantsData | Where-Object { $_.Id -eq $PSItem.Id -and $_.PermissionName -ne '-' }).Count

      $nm = ConvertTo-JsonSafe $PSItem.AppDisplayName
      $aid = ConvertTo-JsonSafe $PSItem.AppId
      $tp = ConvertTo-JsonSafe $PSItem.ServicePrincipalType
      $tn = ConvertTo-JsonSafe $PSItem.TenantName
      $dom = ConvertTo-JsonSafe $PSItem.TenantPrimaryDomainName
      $pub = ConvertTo-JsonSafe $PSItem.PublisherName
      $cdt = ConvertTo-JsonSafe $PSItem.CreatedDateTime
      $aorg = ConvertTo-JsonSafe $PSItem.AppOwnerOrganizationId

      "{`"id`":`"$(ConvertTo-JsonSafe $PSItem.Id)`",`"name`":`"$nm`",`"appId`":`"$aid`",`"type`":`"$tp`",`"enabled`":$(if($PSItem.AccountEnabled){'true'}else{'false'}),`"hasOwner`":$(if($PSItem.HasOwner){'true'}else{'false'}),`"tenant`":`"$tn`",`"domain`":`"$dom`",`"publisher`":`"$pub`",`"created`":`"$cdt`",`"appOwnerOrg`":`"$aorg`",`"topRisk`":`"$topRisk`",`"permCount`":$permCnt}"
    }) -join ','

  # Permissions detail JSON (capped at 2000 rows to keep HTML manageable)
  $permJson = ($allTenantsData | Where-Object { $_.PermissionName -ne '-' } | Select-Object -First 2000 | ForEach-Object {
      $nm = ConvertTo-JsonSafe $_.AppDisplayName
      $pn = ConvertTo-JsonSafe $_.PermissionName
      $res = ConvertTo-JsonSafe $_.Resource
      $tn = ConvertTo-JsonSafe $_.TenantName
      $risk = ConvertTo-JsonSafe $_.Risk
      $pt = ConvertTo-JsonSafe $_.PermissionType
      $con = ConvertTo-JsonSafe $_.Consent
      "{`"sp`":`"$nm`",`"perm`":`"$pn`",`"resource`":`"$res`",`"tenant`":`"$tn`",`"risk`":`"$risk`",`"type`":`"$pt`",`"consent`":`"$con`"}"
    }) -join ','

  # Resource bar data
  $resourceJson = ($resourceGroups | ForEach-Object {
      $rn = ConvertTo-JsonSafe $_.Name
      "{`"name`":`"$rn`",`"count`":$($_.Count)}"
    }) -join ','

  # Type distribution
  $typeJson = ($typeGroups | ForEach-Object {
      $tn = ConvertTo-JsonSafe $_.Name
      "{`"name`":`"$tn`",`"count`":$($_.Count)}"
    }) -join ','

  # ── Build HTML ───────────────────────────────────────────────────────────────
  $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Entra ID — Service Principal Governance Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;--border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;--green:#3fb950;--amber:#d29922;--red:#f85149;--text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;--mono:'JetBrains Mono','Consolas','Courier New',monospace;--sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;--radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5)}
body.light-theme{--bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;--border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;--green:#1a7f37;--amber:#b08000;--red:#cf222e;--text:#1f2328;--muted:#636c76;--muted2:#424a53;--shadow:0 4px 24px rgba(0,0,0,.12)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}
#sidebar{position:fixed;top:0;left:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text)}
.sidebar-logo p{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.version-badge{display:inline-block;margin-top:5px;background:rgba(56,139,253,.15);color:var(--accent);font-family:var(--mono);font-size:10px;padding:1px 8px;border-radius:20px;border:1px solid rgba(56,139,253,.3)}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13.5px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.nav-btn .nav-badge{margin-left:auto;background:var(--surface3);color:var(--muted2);font-family:var(--mono);font-size:11px;padding:1px 7px;border-radius:20px}
.nav-btn:hover{color:var(--text);background:var(--surface2)}
.nav-btn.active{color:var(--accent);background:rgba(56,139,253,.1)}
.nav-btn.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);border-radius:0 2px 2px 0}
.theme-toggle-wrap{padding:10px 14px;border-top:1px solid var(--border)}
.theme-toggle{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;transition:all .2s}
.theme-toggle:hover{border-color:var(--accent);color:var(--text)}
.toggle-pill{width:34px;height:18px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--muted2);transition:transform .2s,background .2s}
body.light-theme .toggle-pill{background:var(--accent)}
body.light-theme .toggle-pill::after{transform:translateX(16px);background:#fff}
.sidebar-footer{padding:10px 18px 12px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);font-family:var(--mono);line-height:1.6}
kbd{display:inline-block;padding:1px 5px;background:var(--surface3);border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:11px;color:var(--muted)}
#main{margin-left:236px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:24px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:25px;font-weight:700;color:var(--text);line-height:1}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-family:var(--mono);font-size:11px;color:var(--muted2);width:108px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:32px;text-align:right;flex-shrink:0}
.donut-wrap{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.donut-svg{width:160px;height:160px;flex-shrink:0}
.legend-list{flex:1;min-width:130px;display:flex;flex-direction:column;gap:5px}
.legend-item{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted2);padding:2px 4px;border-radius:4px}
.legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.legend-pct{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}
.finding-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;margin-bottom:12px;border-left:4px solid var(--accent)}
.finding-card.severity-high{border-left-color:var(--red)}
.finding-card.severity-medium{border-left-color:var(--amber)}
.finding-card.severity-info{border-left-color:var(--accent)}
.finding-title{font-size:14px;font-weight:700;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.finding-body{font-size:13px;color:var(--muted2);line-height:1.6}
.severity-badge{font-size:11px;padding:1px 8px;border-radius:20px;font-weight:600}
.severity-badge.high{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.severity-badge.medium{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3)}
.severity-badge.info{background:rgba(56,139,253,.12);color:var(--accent);border:1px solid rgba(56,139,253,.3)}
.tenant-row{display:flex;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid var(--border)}
.tenant-row:last-child{border-bottom:none}
.tenant-name{font-size:13.5px;font-weight:600;flex:1}
.tenant-domain{font-family:var(--mono);font-size:11px;color:var(--muted);flex:1}
.tenant-metric{font-family:var(--mono);font-size:12px;width:72px;text-align:right;flex-shrink:0}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;padding:8px 11px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--accent)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:13px;flex-shrink:0}
.page-size-wrap{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.scripts-table{width:100%;border-collapse:collapse}
.scripts-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.scripts-table thead th:hover{color:var(--text)}
.scripts-table thead th.sort-active{color:var(--accent)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.scripts-table tbody tr{border-bottom:1px solid var(--border);transition:background .15s}
.scripts-table tbody tr:hover{background:var(--surface2)}
.scripts-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13.5px}
.td-mono{font-family:var(--mono);font-size:12.5px}
.td-muted{color:var(--muted2)}
.risk-badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600}
.risk-badge.High{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.25)}
.risk-badge.Medium{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.25)}
.risk-badge.Low{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.25)}
.risk-badge.None{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
.owner-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}
.owner-dot.yes{background:var(--green)}
.owner-dot.no{background:var(--red)}
.enabled-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}
.enabled-dot.yes{background:var(--green)}
.enabled-dot.no{background:var(--muted)}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:14px}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}
@media(max-width:768px){#sidebar{transform:translateX(-236px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🔐</div>
    <h1>SP Governance</h1>
    <p>Entra ID · Multi-Tenant</p>
    <span class="version-badge">v1.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">📊</span> Overview
    </button>
    <button class="nav-btn" onclick="showPage('findings',this)">
      <span class="nav-icon">🔍</span> Governance Findings
    </button>
    <button class="nav-btn" onclick="showPage('sps',this)">
      <span class="nav-icon">📋</span> Service Principals
      <span class="nav-badge">__TOTALSP__</span>
    </button>
    <button class="nav-btn" onclick="showPage('perms',this)">
      <span class="nav-icon">🔑</span> Permissions
    </button>
    <button class="nav-btn" onclick="showPage('tenants',this)">
      <span class="nav-icon">🏢</span> Tenants
      <span class="nav-badge">__TOTALTENANTS__</span>
    </button>
  </div>
  <div class="theme-toggle-wrap">
    <button class="theme-toggle" onclick="toggleTheme()">
      <span id="themeIcon">🌙</span>
      <span id="themeLabel" style="flex:1;text-align:left">Dark Mode</span>
      <span class="toggle-pill"></span>
    </button>
  </div>
  <div class="sidebar-footer">
    Generated<br>__GENERATEDAT__<br>
    <span style="color:var(--accent2)">⌨</span> <kbd>/</kbd> search
  </div>
</nav>

<main id="main">

<!-- OVERVIEW -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Service Principal Governance Overview</div>
      <div class="page-subtitle">Multi-tenant Entra ID assessment — app-only authentication · __GENERATEDAT__</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV()">⬇ Export CSV</button>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue">
      <div class="stat-icon">🏢</div>
      <div class="stat-value" id="s-tenants">__TOTALTENANTS__</div>
      <div class="stat-label">Tenants Assessed</div>
    </div>
    <div class="stat-card c-cyan">
      <div class="stat-icon">⚙️</div>
      <div class="stat-value" id="s-sps">__TOTALSP__</div>
      <div class="stat-label">Service Principals</div>
    </div>
    <div class="stat-card c-red">
      <div class="stat-icon">⚠️</div>
      <div class="stat-value" id="s-high">__HIGHRISK__</div>
      <div class="stat-label">High-Risk SPs</div>
    </div>
    <div class="stat-card c-amber">
      <div class="stat-icon">👤</div>
      <div class="stat-value" id="s-noowner">__NOOWNER__</div>
      <div class="stat-label">No Owner</div>
    </div>
    <div class="stat-card c-purple">
      <div class="stat-icon">🔑</div>
      <div class="stat-value" id="s-highperms">__HIGHPERMS__</div>
      <div class="stat-label">High-Risk Grants</div>
    </div>
    <div class="stat-card c-green">
      <div class="stat-icon">⛔</div>
      <div class="stat-value" id="s-disabled">__DISABLED__</div>
      <div class="stat-label">Disabled SPs</div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🎯 Risk Distribution (by SP)</div>
      <div class="donut-wrap">
        <svg class="donut-svg" id="riskDonut" viewBox="0 0 160 160"></svg>
        <div class="legend-list" id="riskLegend"></div>
      </div>
    </div>
    <div class="panel">
      <div class="section-title">🗂 SP Type Distribution</div>
      <div id="typeBars"></div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🔌 Top API Resources (Permission Grants)</div>
      <div id="resourceBars"></div>
    </div>
    <div class="panel">
      <div class="section-title">🏢 Tenant Summary</div>
      <div style="display:flex;gap:8px;font-size:10.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);padding-bottom:7px;border-bottom:1px solid var(--border);margin-bottom:4px">
        <span style="flex:1">Tenant</span>
        <span style="width:72px;text-align:right">SPs</span>
        <span style="width:72px;text-align:right">⚠ High</span>
        <span style="width:72px;text-align:right">👤 No Owner</span>
      </div>
      <div id="tenantSummaryList"></div>
    </div>
  </div>
</section>

<!-- GOVERNANCE FINDINGS -->
<section id="page-findings" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Governance Findings</div>
      <div class="page-subtitle">Security and governance signals derived from the collected data</div>
    </div>
  </div>

  <div style="background:rgba(56,139,253,.08);border:1px solid rgba(56,139,253,.2);border-radius:var(--radius);padding:12px 16px;margin-bottom:20px;font-size:12.5px;color:var(--muted2)">
    <strong style="color:var(--accent)">ℹ️ Methodology note:</strong>
    Risk ratings are heuristic and pattern-based. "High-risk" indicates an elevated-impact permission pattern, not a confirmed incident.
    Ownership findings are confirmed from Graph API data. "No owner" is a confirmed gap, not an estimate.
  </div>

  <div id="findingsContainer"></div>
</section>

<!-- SERVICE PRINCIPALS -->
<section id="page-sps" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Service Principals</div>
      <div class="page-subtitle">All unique Service Principals across assessed tenants</div>
    </div>
  </div>

  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔍</span>
      <input type="text" id="spSearch" placeholder="Search by name, type, tenant…" oninput="filterSPs()"/>
    </div>
    <select id="spRiskFilter" onchange="filterSPs()">
      <option value="">All Risks</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
      <option value="None">None</option>
    </select>
    <select id="spOwnerFilter" onchange="filterSPs()">
      <option value="">All Ownership</option>
      <option value="true">Has Owner</option>
      <option value="false">No Owner</option>
    </select>
    <select id="spEnabledFilter" onchange="filterSPs()">
      <option value="">All Status</option>
      <option value="true">Enabled</option>
      <option value="false">Disabled</option>
    </select>
    <span class="result-count" id="spCount"></span>
    <div class="page-size-wrap">
      Show <select id="spPageSize" onchange="renderSPTable()">
        <option value="25">25</option>
        <option value="50" selected>50</option>
        <option value="100">100</option>
      </select>
    </div>
  </div>

  <table class="scripts-table" id="spTable">
    <thead>
      <tr>
        <th onclick="sortSP('name')">Name <span class="sort-arrow">↕</span></th>
        <th onclick="sortSP('type')">Type <span class="sort-arrow">↕</span></th>
        <th onclick="sortSP('tenant')">Tenant <span class="sort-arrow">↕</span></th>
        <th onclick="sortSP('topRisk')">Top Risk <span class="sort-arrow">↕</span></th>
        <th onclick="sortSP('permCount')">Permissions <span class="sort-arrow">↕</span></th>
        <th onclick="sortSP('hasOwner')">Owner <span class="sort-arrow">↕</span></th>
        <th onclick="sortSP('enabled')">Enabled <span class="sort-arrow">↕</span></th>
        <th onclick="sortSP('publisher')">Publisher <span class="sort-arrow">↕</span></th>
      </tr>
    </thead>
    <tbody id="spTbody"></tbody>
  </table>
  <div class="pagination" id="spPagination"></div>
</section>

<!-- PERMISSIONS -->
<section id="page-perms" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Permission Grants</div>
      <div class="page-subtitle">Individual permission grants (capped at 2,000 rows in this view; full data in CSV)</div>
    </div>
  </div>

  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔍</span>
      <input type="text" id="permSearch" placeholder="Search by SP name, permission, resource…" oninput="filterPerms()"/>
    </div>
    <select id="permRiskFilter" onchange="filterPerms()">
      <option value="">All Risks</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
    </select>
    <select id="permTypeFilter" onchange="filterPerms()">
      <option value="">All Types</option>
      <option value="Application">Application</option>
      <option value="Delegated">Delegated</option>
    </select>
    <span class="result-count" id="permCount"></span>
    <div class="page-size-wrap">
      Show <select id="permPageSize" onchange="renderPermTable()">
        <option value="25">25</option>
        <option value="50" selected>50</option>
        <option value="100">100</option>
      </select>
    </div>
  </div>

  <table class="scripts-table" id="permTable">
    <thead>
      <tr>
        <th onclick="sortPerm('sp')">Service Principal <span class="sort-arrow">↕</span></th>
        <th onclick="sortPerm('resource')">Resource (API) <span class="sort-arrow">↕</span></th>
        <th onclick="sortPerm('perm')">Permission <span class="sort-arrow">↕</span></th>
        <th onclick="sortPerm('type')">Type <span class="sort-arrow">↕</span></th>
        <th onclick="sortPerm('risk')">Risk <span class="sort-arrow">↕</span></th>
        <th onclick="sortPerm('consent')">Consent <span class="sort-arrow">↕</span></th>
        <th onclick="sortPerm('tenant')">Tenant <span class="sort-arrow">↕</span></th>
      </tr>
    </thead>
    <tbody id="permTbody"></tbody>
  </table>
  <div class="pagination" id="permPagination"></div>
</section>

<!-- TENANTS -->
<section id="page-tenants" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Tenant Breakdown</div>
      <div class="page-subtitle">Per-tenant Service Principal governance summary</div>
    </div>
  </div>

  <div id="tenantCards"></div>
</section>

</main>

<!-- Toast -->
<div id="toast"><span id="toastIcon"></span><span id="toastMsg"></span></div>

<script>
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function showToast(msg,icon){var t=document.getElementById('toast');document.getElementById('toastMsg').textContent=msg;document.getElementById('toastIcon').textContent=icon||'✅';t.classList.add('show');setTimeout(function(){t.classList.remove('show');},2800);}
function showPage(id,btn){document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});document.querySelectorAll('.nav-btn').forEach(function(b){b.classList.remove('active');});document.getElementById('page-'+id).classList.add('active');if(btn)btn.classList.add('active');}
function toggleTheme(){var b=document.body;b.classList.toggle('light-theme');var light=b.classList.contains('light-theme');document.getElementById('themeIcon').textContent=light?'☀️':'🌙';document.getElementById('themeLabel').textContent=light?'Light Mode':'Dark Mode';}
document.addEventListener('keydown',function(e){if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){e.preventDefault();var s=document.querySelector('.page.active input[type=text]');if(s)s.focus();}});

// ── Data ─────────────────────────────────────────────────────────────────────
var TENANTS  = [__TENANTJSON__];
var SPS      = [__SPJSON__];
var PERMS    = [__PERMJSON__];
var RESOURCES= [__RESOURCEJSON__];
var TYPES    = [__TYPEJSON__];

// ── Donut chart ───────────────────────────────────────────────────────────────
var RISK_COLORS = {High:'#f85149',Medium:'#d29922',Low:'#3fb950',None:'#7d8590'};
var RISK_DATA   = [
  {label:'High',   value:__RISKHIGH__,   color:'#f85149'},
  {label:'Medium', value:__RISKMED__,    color:'#d29922'},
  {label:'Low',    value:__RISKLOW__,    color:'#3fb950'},
  {label:'None',   value:__RISKNONE__,   color:'#7d8590'}
];
function buildDonut(){
  var total=RISK_DATA.reduce(function(s,d){return s+d.value;},0);
  if(total===0){return;}
  var cx=80,cy=80,r=60,stroke=22,circ=2*Math.PI*r;
  var svg=document.getElementById('riskDonut');
  var html='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="var(--surface3)" stroke-width="'+stroke+'"/>';
  var offset=0;
  RISK_DATA.forEach(function(d){
    if(!d.value)return;
    var pct=d.value/total;
    var dash=pct*circ;
    var gap=circ-dash;
    var rot=-90+(offset/total)*360;
    html+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+d.color+'" stroke-width="'+stroke+'" stroke-dasharray="'+dash+' '+gap+'" stroke-dashoffset="'+(-circ*(offset/total))+'" transform="rotate('+rot+' '+cx+' '+cy+')" style="transition:stroke-dasharray .8s ease"/>';
    offset+=d.value;
  });
  svg.innerHTML=html;
  var leg=document.getElementById('riskLegend');
  leg.innerHTML=RISK_DATA.map(function(d){
    var pct=total?Math.round(d.value/total*100):0;
    return '<div class="legend-item"><span class="legend-dot" style="background:'+d.color+'"></span>'+escH(d.label)+' ('+d.value+')<span class="legend-pct">'+pct+'%</span></div>';
  }).join('');
}

// ── Bar charts ────────────────────────────────────────────────────────────────
function buildBars(containerId,data,colorVar){
  var max=data.reduce(function(m,d){return Math.max(m,d.count);},1);
  var el=document.getElementById(containerId);
  if(!el)return;
  el.innerHTML=data.map(function(d){
    var pct=Math.round(d.count/max*100);
    return '<div class="bar-row"><span class="bar-label" title="'+escH(d.name)+'">'+escH(d.name)+'</span><div class="bar-track"><div class="bar-fill" style="width:0%;background:var('+(colorVar||'--accent')+')" data-pct="'+pct+'"></div></div><span class="bar-count">'+d.count+'</span></div>';
  }).join('');
  requestAnimationFrame(function(){el.querySelectorAll('.bar-fill').forEach(function(f){f.style.width=f.getAttribute('data-pct')+'%';});});
}

// ── Tenant summary ────────────────────────────────────────────────────────────
function buildTenantSummary(){
  var el=document.getElementById('tenantSummaryList');
  if(!el||!TENANTS.length)return;
  el.innerHTML=TENANTS.map(function(t){
    return '<div class="tenant-row"><span class="tenant-name">'+escH(t.name)+'</span><span class="tenant-domain">'+escH(t.domain)+'</span><span class="tenant-metric">'+t.spCount+'</span><span class="tenant-metric" style="color:var(--red)">'+t.highRisk+'</span><span class="tenant-metric" style="color:var(--amber)">'+t.noOwner+'</span></div>';
  }).join('');
}

// ── Tenant cards page ─────────────────────────────────────────────────────────
function buildTenantCards(){
  var el=document.getElementById('tenantCards');
  if(!el)return;
  el.innerHTML=TENANTS.map(function(t){
    var riskPct=t.spCount?Math.round(t.highRisk/t.spCount*100):0;
    var ownerPct=t.spCount?Math.round(t.noOwner/t.spCount*100):0;
    return '<div class="finding-card severity-info" style="margin-bottom:14px">'+
      '<div class="finding-title">🏢 '+escH(t.name)+' <span style="font-family:var(--mono);font-weight:400;font-size:12px;color:var(--muted)">'+escH(t.domain)+'</span></div>'+
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-top:10px">'+
        '<div style="background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px"><div style="font-size:20px;font-weight:700">'+t.spCount+'</div><div style="font-size:12px;color:var(--muted)">Service Principals</div></div>'+
        '<div style="background:rgba(248,81,73,.07);border-radius:var(--radius-sm);padding:10px 12px"><div style="font-size:20px;font-weight:700;color:var(--red)">'+t.highRisk+'</div><div style="font-size:12px;color:var(--muted)">High-Risk ('+riskPct+'%)</div></div>'+
        '<div style="background:rgba(210,153,34,.07);border-radius:var(--radius-sm);padding:10px 12px"><div style="font-size:20px;font-weight:700;color:var(--amber)">'+t.noOwner+'</div><div style="font-size:12px;color:var(--muted)">No Owner ('+ownerPct+'%)</div></div>'+
        '<div style="background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px"><div style="font-size:20px;font-weight:700;color:var(--muted)">'+t.disabled+'</div><div style="font-size:12px;color:var(--muted)">Disabled SPs</div></div>'+
      '</div>'+
    '</div>';
  }).join('');
}

// ── Governance findings ───────────────────────────────────────────────────────
function buildFindings(){
  var el=document.getElementById('findingsContainer');
  if(!el)return;
  var totalSP=__TOTALSP__;
  var highRisk=__HIGHRISK__;
  var noOwner=__NOOWNER__;
  var disabled=__DISABLED__;
  var findings=[];

  if(highRisk>0){
    var pct=Math.round(highRisk/totalSP*100);
    findings.push({sev:'high',title:'⚠️ High-Risk Permission Grants Detected',body:'<strong>'+highRisk+'</strong> Service Principals ('+pct+'% of total) hold at least one permission classified as high-risk — typically ReadWrite, Delete, FullControl, or similar high-impact scopes. Each of these represents a potential lateral-movement or data-exfiltration surface. Review and apply least-privilege principles. Refer to the <em>Permissions</em> tab, filtered to High risk, for the full list.'});
  }
  if(noOwner>0){
    var pct2=Math.round(noOwner/totalSP*100);
    findings.push({sev:'high',title:'👤 Service Principals Without Owners',body:'<strong>'+noOwner+'</strong> Service Principals ('+pct2+'% of total) have no registered owner in Entra ID. Unowned SPs create accountability gaps: there is no individual responsible for reviewing or rotating credentials, validating continued necessity, or responding to security incidents. Assign owners immediately, prioritising high-risk SPs. <em>Finding confirmed from Graph API data.</em>'});
  }
  if(disabled>0){
    findings.push({sev:'medium',title:'⛔ Disabled Service Principals With Permissions',body:'<strong>'+disabled+'</strong> disabled Service Principals were found to still hold permission grants. While disabled SPs cannot authenticate, residual permission grants are a governance gap: re-enabling the SP instantly restores access. Review whether these SPs should be deleted rather than merely disabled, and revoke any grants that are no longer required.'});
  }
  TENANTS.forEach(function(t){
    if(t.highRisk>0 && t.spCount>0){
      var rp=Math.round(t.highRisk/t.spCount*100);
      if(rp>=30){
        findings.push({sev:'medium',title:'🏢 High Risk Concentration: '+escH(t.name),body:'<strong>'+rp+'%</strong> of Service Principals in tenant <em>'+escH(t.name)+'</em> carry high-risk permissions. This concentration warrants a targeted remediation effort for this tenant. Use the Service Principals tab filtered by tenant to review individual SPs.'});
      }
    }
  });
  findings.push({sev:'info',title:'📊 Permission Review Recommended',body:'All application-type permissions are admin-consented and operate without user context. These are inherently higher-impact than delegated permissions. Conduct a periodic review cycle (recommended: quarterly) comparing current grants against the principle of least privilege, particularly for Microsoft Graph permissions.'});
  findings.push({sev:'info',title:'🔭 Future-Ready Data Structure',body:'This assessment collects data in a relationship-structured format: <code>Tenant → Service Principal → Application → Owner → Permission → API</code>. The CSV output uses consistent keys (SP id, appId, TenantId) suitable for ingestion into a graph database, SIEM, or LLM-based analysis pipeline without schema changes.'});

  el.innerHTML=findings.map(function(f){
    var badge='<span class="severity-badge '+f.sev+'">'+f.sev.toUpperCase()+'</span>';
    return '<div class="finding-card severity-'+f.sev+'"><div class="finding-title">'+badge+' '+f.title+'</div><div class="finding-body" style="margin-top:6px">'+f.body+'</div></div>';
  }).join('');
}

// ── SP Table ─────────────────────────────────────────────────────────────────
var spFiltered=SPS.slice();
var spSortCol='';var spSortAsc=true;var spPage=1;
function filterSPs(){
  var q=(document.getElementById('spSearch').value||'').toLowerCase();
  var rk=(document.getElementById('spRiskFilter').value||'').toLowerCase();
  var ow=document.getElementById('spOwnerFilter').value;
  var en=document.getElementById('spEnabledFilter').value;
  spFiltered=SPS.filter(function(s){
    var txt=(s.name+' '+s.type+' '+s.tenant+' '+s.publisher).toLowerCase();
    if(q&&txt.indexOf(q)<0)return false;
    if(rk&&s.topRisk.toLowerCase()!==rk)return false;
    if(ow!==''&&String(s.hasOwner)!==ow)return false;
    if(en!==''&&String(s.enabled)!==en)return false;
    return true;
  });
  spPage=1;
  renderSPTable();
}
function sortSP(col){
  if(spSortCol===col){spSortAsc=!spSortAsc;}else{spSortCol=col;spSortAsc=true;}
  spFiltered.sort(function(a,b){
    var av=a[col]||'';var bv=b[col]||'';
    if(typeof av==='number'&&typeof bv==='number')return spSortAsc?av-bv:bv-av;
    return spSortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  renderSPTable();
}
function renderSPTable(){
  var ps=parseInt(document.getElementById('spPageSize').value)||50;
  var total=spFiltered.length;
  var pages=Math.max(1,Math.ceil(total/ps));
  if(spPage>pages)spPage=pages;
  var start=(spPage-1)*ps;
  var rows=spFiltered.slice(start,start+ps);
  var RISK_COLORS2={High:'var(--red)',Medium:'var(--amber)',Low:'var(--green)',None:'var(--muted)'};
  document.getElementById('spCount').textContent=total+' Service Principals';
  document.getElementById('spTbody').innerHTML=rows.map(function(s){
    var ownerDot='<span class="owner-dot '+(s.hasOwner?'yes':'no')+'"></span>'+(s.hasOwner?'Yes':'No');
    var enDot='<span class="enabled-dot '+(s.enabled?'yes':'no')+'"></span>'+(s.enabled?'Yes':'No');
    return '<tr><td class="td-mono" style="color:var(--accent2)">'+escH(s.name)+'</td><td class="td-muted">'+escH(s.type)+'</td><td>'+escH(s.tenant)+'</td><td><span class="risk-badge '+s.topRisk+'">'+escH(s.topRisk)+'</span></td><td class="td-mono" style="text-align:center">'+s.permCount+'</td><td>'+ownerDot+'</td><td>'+enDot+'</td><td class="td-muted td-mono" style="font-size:11.5px">'+escH(s.publisher||'-')+'</td></tr>';
  }).join('');
  var pag=document.getElementById('spPagination');
  var btns='';
  for(var i=1;i<=Math.min(pages,10);i++){btns+='<button class="page-btn'+(i===spPage?' active':'')+'" onclick="spPage='+i+';renderSPTable()">'+i+'</button>';}
  pag.innerHTML=btns;
}

// ── Permissions Table ──────────────────────────────────────────────────────────
var permFiltered=PERMS.slice();
var permSortCol='';var permSortAsc=true;var permPage=1;
function filterPerms(){
  var q=(document.getElementById('permSearch').value||'').toLowerCase();
  var rk=(document.getElementById('permRiskFilter').value||'').toLowerCase();
  var tp=(document.getElementById('permTypeFilter').value||'').toLowerCase();
  permFiltered=PERMS.filter(function(p){
    var txt=(p.sp+' '+p.perm+' '+p.resource+' '+p.tenant).toLowerCase();
    if(q&&txt.indexOf(q)<0)return false;
    if(rk&&p.risk.toLowerCase()!==rk)return false;
    if(tp&&p.type.toLowerCase()!==tp)return false;
    return true;
  });
  permPage=1;
  renderPermTable();
}
function sortPerm(col){
  if(permSortCol===col){permSortAsc=!permSortAsc;}else{permSortCol=col;permSortAsc=true;}
  permFiltered.sort(function(a,b){
    var av=a[col]||'';var bv=b[col]||'';
    return permSortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  renderPermTable();
}
function renderPermTable(){
  var ps=parseInt(document.getElementById('permPageSize').value)||50;
  var total=permFiltered.length;
  var pages=Math.max(1,Math.ceil(total/ps));
  if(permPage>pages)permPage=pages;
  var start=(permPage-1)*ps;
  var rows=permFiltered.slice(start,start+ps);
  document.getElementById('permCount').textContent=total+' grants';
  document.getElementById('permTbody').innerHTML=rows.map(function(p){
    return '<tr><td class="td-mono" style="color:var(--accent2)">'+escH(p.sp)+'</td><td>'+escH(p.resource)+'</td><td class="td-mono" style="font-size:12px">'+escH(p.perm)+'</td><td class="td-muted">'+escH(p.type)+'</td><td><span class="risk-badge '+p.risk+'">'+escH(p.risk)+'</span></td><td class="td-muted">'+escH(p.consent)+'</td><td>'+escH(p.tenant)+'</td></tr>';
  }).join('');
  var pag=document.getElementById('permPagination');
  var btns='';
  for(var i=1;i<=Math.min(pages,10);i++){btns+='<button class="page-btn'+(i===permPage?' active':'')+'" onclick="permPage='+i+';renderPermTable()">'+i+'</button>';}
  pag.innerHTML=btns;
}

// ── CSV export (SP data) ──────────────────────────────────────────────────────
function exportCSV(){
  var header='Name,AppId,Type,TopRisk,Permissions,HasOwner,Enabled,Tenant,Domain,Publisher\n';
  var rows=SPS.map(function(s){
    return [s.name,s.appId,s.type,s.topRisk,s.permCount,s.hasOwner,s.enabled,s.tenant,s.domain,s.publisher||''].map(function(v){return '"'+String(v||'').replace(/"/g,'""')+'"';}).join(',');
  }).join('\n');
  var blob=new Blob([header+rows],{type:'text/csv'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='SP-Governance-Export.csv';
  a.click();
  showToast('CSV downloaded','⬇');
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded',function(){
  buildDonut();
  buildBars('resourceBars',RESOURCES,'--accent');
  buildBars('typeBars',TYPES,'--accent2');
  buildTenantSummary();
  buildFindings();
  buildTenantCards();
  filterSPs();
  filterPerms();
});
</script>
</body>
</html>
'@

  # ── Token substitution ───────────────────────────────────────────────────────
  $html = $html `
    -replace '__GENERATEDAT__', $generatedAt `
    -replace '__TOTALTENANTS__', $totalTenants `
    -replace '__TOTALSP__', $totalSPsAll `
    -replace '__HIGHRISK__', $totalHighRisk `
    -replace '__NOOWNER__', $totalNoOwner `
    -replace '__HIGHPERMS__', $totalHighRiskPerms `
    -replace '__DISABLED__', $totalDisabled `
    -replace '__RISKHIGH__', $riskHigh `
    -replace '__RISKMED__', $riskMed `
    -replace '__RISKLOW__', $riskLow `
    -replace '__RISKNONE__', $riskNone `
    -replace '__TENANTJSON__', $tenantJson `
    -replace '__SPJSON__', $spTableJson `
    -replace '__PERMJSON__', $permJson `
    -replace '__RESOURCEJSON__', $resourceJson `
    -replace '__TYPEJSON__', $typeJson

  try {
    $html | Out-File -FilePath $HtmlOutputPath -Encoding UTF8 -Force
    Write-Host "  ✅ HTML dashboard generated: $HtmlOutputPath" -ForegroundColor Green
  }
  catch {
    Write-Warning "  ❌ HTML dashboard write failed: $_"
  }

  #endregion

  #region ── Summary ────────────────────────────────────────────────────────────

  $scriptEndTime = Get-Date
  $executionTime = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime

  Write-Host ""
  Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
  Write-Host "  ║                       EXECUTION SUMMARY                         ║" -ForegroundColor Cyan
  Write-Host "  ╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
  Write-Host "  ║  🏢 Tenants Assessed        : $($totalTenants.ToString().PadRight(35))║" -ForegroundColor Green
  Write-Host "  ║  ⚙️ Service Principals      : $($totalSPsAll.ToString().PadRight(35))║" -ForegroundColor Green
  Write-Host "  ║  ⚠️ High-Risk SPs           : $($totalHighRisk.ToString().PadRight(35))║" -ForegroundColor Yellow
  Write-Host "  ║  👤 No-Owner SPs            : $($totalNoOwner.ToString().PadRight(35))║" -ForegroundColor Yellow
  Write-Host "  ║  📋 CSV Rows Exported       : $($allTenantsData.Count.ToString().PadRight(35))║" -ForegroundColor Gray
  Write-Host "  ║  🕐 Started                 : $($scriptStartTime.ToString('HH:mm:ss').PadRight(35))║" -ForegroundColor Gray
  Write-Host "  ║  🕑 Ended                   : $($scriptEndTime.ToString('HH:mm:ss').PadRight(35))║" -ForegroundColor Gray
  Write-Host "  ║  ⏱️ Duration                : $($executionTime.ToString('hh\:mm\:ss').PadRight(35))║" -ForegroundColor Yellow
  Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
  Write-Host ""

  if ($OpenBrowser -and (Test-Path $HtmlOutputPath)) {
    Start-Process $HtmlOutputPath
  }

  #endregion
}
