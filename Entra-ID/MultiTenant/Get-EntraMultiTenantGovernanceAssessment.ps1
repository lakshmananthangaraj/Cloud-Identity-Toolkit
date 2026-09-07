<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 07 September 2026
Modified-On  : 07 September 2026

.SYNOPSIS
    Enterprise multi-tenant Entra ID governance and security assessment across N tenants.

.DESCRIPTION
    Get-EntraMultiTenantGovernanceAssessment orchestrates a consistent security and governance
    posture assessment across multiple Microsoft Entra ID tenants. It is designed for enterprise
    scenarios where multiple tenants must be assessed uniformly — subsidiaries, geographic
    regions, acquired companies, or partner tenants.

    The function follows a layered architecture:

      Orchestration → Tenant Management → Authentication → Capability Pre-flight
      → Collectors (8 domains) → Normalization → Assessment → Scoring → Reporting

    Assessment domains (V1):
      Users · Groups · Devices · Applications · Service Principals
      MFA · Conditional Access · PIM

    Output:
      • HTML dashboard — Enterprise → Tenant → Domain → Finding drill-down
      • JSON           — Graph-ready data model with stable Finding IDs and schema version
      • Findings CSV   — One row per finding; remediation/ticketing focused
      • Metrics CSV    — One row per tenant/domain; analytics/trending focused

    Authentication (per tenant):
      • BringYourOwnToken  — Graph Bearer token supplied via environment variable
      • ClientCredentials  — Tenant ID + Client ID + Client Secret (secret via env var)
      Architecture is designed for Managed Identity to be added as a third auth mode
      without any changes to the collector or reporting layers.

    Resilience:
      A single tenant authentication failure skips that tenant and continues.
      A single domain collector failure is captured in the tenant result; other
      domains continue. All failures are surfaced in the dashboard and JSON output.

.PARAMETER TenantConfigPath
    Path to a JSON configuration file listing tenants to assess. The preferred enterprise
    input method. See .NOTES for the JSON schema. Cannot be used with -Tenants.

.PARAMETER Tenants
    An array of PSCustomObject tenant configuration objects. Each object must contain the
    same properties as the JSON schema. Useful for programmatic/pipeline invocation.
    Cannot be used with -TenantConfigPath.

.PARAMETER OutputPath
    Directory where output files are written. A timestamped sub-folder is created automatically.
    Defaults to the current working directory.

.PARAMETER ExcludeTenantIds
    One or more tenant GUIDs to exclude from the assessment. Applies after the tenant list
    is resolved from -TenantConfigPath or -Tenants.

.PARAMETER IncludeDomains
    Limit assessment to specific domain collectors. Valid values: Users, Groups, Devices,
    Applications, ServicePrincipals, MFA, ConditionalAccess, PIM.
    Defaults to all eight domains.

.PARAMETER ExcludeDomains
    Exclude specific domain collectors. Valid values: same as IncludeDomains.

.PARAMETER OpenDashboard
    If specified, opens the generated HTML dashboard in the default browser after the
    assessment completes.

.PARAMETER PassThru
    If specified, returns the full assessment result object to the pipeline in addition
    to writing the output files.

.INPUTS
    None. Parameters only.

.OUTPUTS
    System.Management.Automation.PSCustomObject
    Only when -PassThru is specified. The complete assessment result object.

.EXAMPLE
    # Assess all tenants defined in a JSON config file
    Get-EntraMultiTenantGovernanceAssessment -TenantConfigPath "C:\Config\tenants.json" -OpenDashboard

.EXAMPLE
    # Inline tenant objects with BYOT auth; output to a specific path
    $tenants = @(
        [PSCustomObject]@{
            TenantId     = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
            DisplayName  = 'Contoso Production'
            BusinessUnit = 'Corporate IT'
            AuthMode     = 'BringYourOwnToken'
            TokenEnvVar  = 'CONTOSO_GRAPH_TOKEN'
        }
    )
    Get-EntraMultiTenantGovernanceAssessment -Tenants $tenants -OutputPath "C:\Reports"

.EXAMPLE
    # Client Credentials auth; exclude PIM (no P2 license in this environment)
    Get-EntraMultiTenantGovernanceAssessment `
        -TenantConfigPath "C:\Config\tenants.json" `
        -ExcludeDomains PIM `
        -OutputPath "C:\Reports" `
        -PassThru

.EXAMPLE
    # Assess only MFA and Conditional Access across all tenants
    Get-EntraMultiTenantGovernanceAssessment `
        -TenantConfigPath "C:\Config\tenants.json" `
        -IncludeDomains MFA, ConditionalAccess `
        -OpenDashboard

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (07-Sep-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Microsoft Graph API access — no PowerShell module required; uses REST calls directly.

    2. The token or service principal used per tenant must have the following Graph
    application permissions (not delegated):
        User.Read.All
        Group.Read.All
        Device.Read.All
        Application.Read.All
        ServicePrincipalEndpoint.Read.All
        Policy.Read.All
        RoleManagement.Read.All
        UserAuthenticationMethod.Read.All
        PrivilegedAccess.Read.AzureAD   (Entra ID P2 required for PIM collector)
        
    Granting fewer permissions causes the affected collector(s) to fail gracefully
    with a Permission-NotGranted capability status — the assessment continues.

    3. Tenant JSON configuration schema:
    {
        "SchemaVersion": "1.0",
        "Tenants": [
        {
            "TenantId":           "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "DisplayName":        "Contoso Production",
            "BusinessUnit":       "Corporate IT",
            "AuthMode":           "ClientCredentials",
            "ClientId":           "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "ClientSecretEnvVar": "CONTOSO_PROD_SECRET"
        },
        {
            "TenantId":    "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
            "DisplayName": "Fabrikam Subsidiary",
            "BusinessUnit": "EMEA",
            "AuthMode":    "BringYourOwnToken",
            "TokenEnvVar": "FABRIKAM_GRAPH_TOKEN"
        }
        ]
    }
    ClientSecretEnvVar and TokenEnvVar name environment variables — never the
    secret value itself. Secrets must never appear in the JSON file.

    4. Multi-Tenant Authentication Using a Single Application Registration
    -----------------------------------------------------------------------
    A single application registered in the HOME tenant can authenticate and assess
    ALL target tenants without requiring a separate app registration in each one.
    Think of it as one master key that each target tenant issues a local pass for.

    This is the recommended enterprise pattern for subsidiaries, acquired companies,
    MSSP environments, and cross-region assessments. The same ClientId and
    ClientSecretEnvVar are reused across every ClientCredentials tenant entry in
    the JSON configuration file (see schema in item 3 above).

    STEP 1 — Register the Application in the Home Tenant (one-time)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    a. Azure Portal → Microsoft Entra ID → App registrations → New registration
       - Name:                    EntraGovernanceAssessment  (or your naming convention)
       - Supported account types: Accounts in any organizational directory
                                  (Any Microsoft Entra ID tenant — Multitenant)
                                  *** Must be Multitenant — Single tenant will not work ***
       - Redirect URI:            Leave blank (daemon/background service, no interactive login)

    b. After registration, note:
       - Application (client) ID  → used as ClientId in the JSON config
       - Directory (tenant) ID    → your home tenant only; not used for target tenants

    c. Create a Client Secret:
       Azure Portal → App registration → Certificates & secrets → New client secret
       - Set a description and expiry (12 months recommended; never "Never expires")
       - Copy the secret VALUE immediately — it is shown only once
       - Store it in Azure Key Vault or a secure secrets manager
       - Reference it via ClientSecretEnvVar in the JSON config — never paste the
         value directly into the JSON file or source control

    d. Grant API Permissions in the Home Tenant:
       Azure Portal → App registration → API permissions → Add a permission
       → Microsoft Graph → Application permissions
       Add all permissions listed in item 2 above, then click
       "Grant admin consent for [Your Organization]".
       Note: This consent applies to the home tenant only. Each target tenant
       requires its own permission grants (Step 3 below).

    STEP 2 — Create a Service Principal in Each Target Tenant
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    The app registration exists only in the home tenant. To use it in a target
    tenant, a Service Principal (the app's local representative) must be created
    there first. Repeat the following for each target tenant:

    Pre-requisite: Application Administrator or Cloud Application Administrator
    role in the target tenant. Microsoft Graph PowerShell SDK must be installed:
        Install-Module Microsoft.Graph -Scope CurrentUser

        # Connect interactively to the TARGET tenant (not the home tenant)
        Connect-MgGraph -Scopes "Application.ReadWrite.All" `
                        -TenantId "TARGET_TENANT_ID"

        # Create the service principal using the home tenant's App (Client) ID
        $sp = New-MgServicePrincipal -AppId "HOME_TENANT_APP_CLIENT_ID"

        # Note this Object ID — required in Step 3
        Write-Host "Service Principal Object ID: $($sp.Id)"

    STEP 3 — Grant API Permissions to the Service Principal in Each Target Tenant
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Creating the service principal (Step 2) establishes the identity but grants
    no permissions. Each required Graph permission must be assigned explicitly via
    app role assignments. A Global Administrator or Privileged Role Administrator
    in the TARGET tenant must execute these calls.

    3a. Retrieve the Microsoft Graph service principal Object ID in the target tenant
        and the App Role ID (permission GUID) for each permission required.
        These values are consistent across all tenants:

        # Still connected to the target tenant from Step 2
        $graphSp = Get-MgServicePrincipal `
                       -Filter "AppId eq '00000003-0000-0000-c000-000000000e00'"
        $graphObjectId = $graphSp.Id

        # List all available permissions and their GUIDs
        $graphSp.AppRoles | Select-Object Value, Id | Sort-Object Value

        Common permission GUIDs for reference (always verify dynamically):
        User.Read.All                         df021288-bdef-4463-88db-98f22de89214
        Group.Read.All                        5b567255-7703-4780-807c-7be8301ae99b
        Device.Read.All                       7438b122-aefc-4978-80ed-43db9064d31d
        Application.Read.All                  9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30
        Policy.Read.All                       246dd0d5-5bd0-4def-940b-0421030a5b68
        RoleManagement.Read.All               c7fbd983-d9aa-4fa7-84b8-17382c103bc4
        UserAuthenticationMethod.Read.All     38d9df27-64da-44fd-b7c5-a6fbac20248f
        PrivilegedAccess.Read.AzureAD         4cdc2547-9148-4295-8d11-be0db1391d6b

    3b. Grant permissions using PowerShell (recommended for automation):

        $spObjectId    = "SP_OBJECT_ID_FROM_STEP_2"
        $graphObjectId = "GRAPH_SP_OBJECT_ID_FROM_STEP_3a"

        $permissionsToGrant = @(
            "df021288-bdef-4463-88db-98f22de89214",  # User.Read.All
            "5b567255-7703-4780-807c-7be8301ae99b",  # Group.Read.All
            "7438b122-aefc-4978-80ed-43db9064d31d",  # Device.Read.All
            "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",  # Application.Read.All
            "246dd0d5-5bd0-4def-940b-0421030a5b68",  # Policy.Read.All
            "c7fbd983-d9aa-4fa7-84b8-17382c103bc4",  # RoleManagement.Read.All
            "38d9df27-64da-44fd-b7c5-a6fbac20248f",  # UserAuthenticationMethod.Read.All
            "4cdc2547-9148-4295-8d11-be0db1391d6b"   # PrivilegedAccess.Read.AzureAD (P2)
        )

        foreach ($appRoleId in $permissionsToGrant)
        {
            $params = @{
                PrincipalId = $spObjectId
                ResourceId  = $graphObjectId
                AppRoleId   = $appRoleId
            }
            try
            {
                New-MgServicePrincipalAppRoleAssignment `
                    -ServicePrincipalId $spObjectId `
                    -BodyParameter $params `
                    -ErrorAction Stop
                Write-Host "Granted: $appRoleId"
            }
            catch
            {
                Write-Warning "Failed to grant $appRoleId — $($_.Exception.Message)"
            }
        }

    3c. Grant permissions using Graph API / REST (alternative for CI/CD pipelines):

        POST https://graph.microsoft.com/v1.0/servicePrincipals/{SP_OBJECT_ID}/appRoleAssignments
        Content-Type:  application/json
        Authorization: Bearer YOUR_ADMIN_ACCESS_TOKEN

        {
            "principalId": "SP_OBJECT_ID_FROM_STEP_2",
            "resourceId":  "GRAPH_SP_OBJECT_ID_FROM_STEP_3a",
            "appRoleId":   "PERMISSION_GUID_FROM_TABLE_ABOVE"
        }

        Repeat one POST per permission. HTTP 201 = success.
        HTTP 400 "Permission being assigned already exists" = already granted (safe to ignore).
        Reference: https://learn.microsoft.com/en-us/graph/permissions-grant-via-msgraph
                   ?tabs=http&pivots=grant-application-permissions

    3d. Verify in the Azure Portal (target tenant):
        Microsoft Entra ID → Enterprise applications → [App Name]
        → Permissions → Admin consent granted
        Each permission should show a green checkmark and "Granted for [Tenant]".

    STEP 4 — JSON Configuration for Multi-Tenant Single-App Assessment
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Once Steps 1–3 are complete for all target tenants, update the JSON
    configuration file. The same ClientId and ClientSecretEnvVar are reused
    across all ClientCredentials entries — only TenantId changes per tenant:

    {
        "SchemaVersion": "1.0",
        "Tenants": [
        {
            "TenantId":           "11111111-1111-1111-1111-111111111111",
            "DisplayName":        "Contoso — Production",
            "BusinessUnit":       "Corporate IT",
            "AuthMode":           "ClientCredentials",
            "ClientId":           "aabbccdd-aabb-aabb-aabb-aabbccddeeff",
            "ClientSecretEnvVar": "ENTRA_ASSESSMENT_CLIENT_SECRET"
        },
        {
            "TenantId":           "22222222-2222-2222-2222-222222222222",
            "DisplayName":        "Fabrikam — EMEA Subsidiary",
            "BusinessUnit":       "EMEA",
            "AuthMode":           "ClientCredentials",
            "ClientId":           "aabbccdd-aabb-aabb-aabb-aabbccddeeff",
            "ClientSecretEnvVar": "ENTRA_ASSESSMENT_CLIENT_SECRET"
        },
        {
            "TenantId":           "33333333-3333-3333-3333-333333333333",
            "DisplayName":        "Tailwind — APAC Region",
            "BusinessUnit":       "APAC",
            "AuthMode":           "ClientCredentials",
            "ClientId":           "aabbccdd-aabb-aabb-aabb-aabbccddeeff",
            "ClientSecretEnvVar": "ENTRA_ASSESSMENT_CLIENT_SECRET"
        }
        ]
    }

    Set the environment variable on the host before running:
        $env:ENTRA_ASSESSMENT_CLIENT_SECRET = "your-client-secret-value"

    Then invoke normally:
        Get-EntraMultiTenantGovernanceAssessment `
            -TenantConfigPath "C:\Config\tenants.json" `
            -OutputPath       "C:\Reports" `
            -OpenDashboard

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - PIM collector requires Entra ID P2 or Entra ID Governance. A 403 response is
    annotated as a license/access limitation, not a security finding.
    - Graph API throttling across large tenants (100k+ users) may extend runtime.
    The function honours Retry-After headers and retries up to 3 times per call.
    - UserAuthenticationMethod.Read.All is a high-privilege permission; some
    organisations require conditional access policy review before granting it.
    - The Nodes/Edges arrays in JSON output are populated at tenant/domain aggregate
    level in V1. Object-level graph traversal (User → Group → Role → App → SPN)
    is the V2 roadmap item.
    - Large tenants with $select-limited Graph endpoints (e.g. /users with 200k+
    records) use server-side paging; runtime scales with tenant size.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW:
    ─────────────────────────────────────────────────────────────────────────────
    1.  Resolve tenant list (JSON file or inline objects)
    2.  Validate tenant config and apply ExcludeTenantIds / IncludeDomains filters
    3.  For each tenant:
        a.  Acquire token (BYOT or Client Credentials)
        b.  Run capability pre-flight (permission probe per domain)
        c.  Run enabled collectors (independent try/catch per domain)
        d.  Normalize collector output to DomainResult objects
        e.  Evaluate findings against the finding catalogue
        f.  Calculate tenant score (0–100 penalty model + maturity label)
    4.  Calculate enterprise score (risk-weighted by user population)
    5.  Build Nodes/Edges graph summary (V1: tenant + domain aggregate nodes)
    6.  Export: Findings.csv, Metrics.csv, assessment.json, dashboard.html
    7.  Optionally open dashboard in browser / return result object via PassThru

#>




Function Get-EntraMultiTenantGovernanceAssessment {
    [CmdletBinding(DefaultParameterSetName = 'ConfigFile')]
    param (

        #region ── Input — Tenant Configuration ───────────────────────────────
        [Parameter(Mandatory = $true, ParameterSetName = 'ConfigFile',
            HelpMessage = 'Path to the tenant JSON configuration file.')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string] $TenantConfigPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'InlineObjects',
            HelpMessage = 'Array of tenant configuration PSCustomObjects.')]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]] $Tenants,
        #endregion

        #region ── Output ─────────────────────────────────────────────────────
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath = '.',
        #endregion

        #region ── Scope Controls ─────────────────────────────────────────────
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]] $ExcludeTenantIds,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Users', 'Groups', 'Devices', 'Applications',
            'ServicePrincipals', 'MFA', 'ConditionalAccess', 'PIM')]
        [string[]] $IncludeDomains,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Users', 'Groups', 'Devices', 'Applications',
            'ServicePrincipals', 'MFA', 'ConditionalAccess', 'PIM')]
        [string[]] $ExcludeDomains,
        #endregion

        #region ── Behaviour ──────────────────────────────────────────────────
        [Parameter(Mandatory = $false)]
        [switch] $OpenDashboard,

        [Parameter(Mandatory = $false)]
        [switch] $PassThru
        #endregion
    )

    #region ══════════════════════════════════════════════════════════════════
    #  CONSTANTS & SCHEMA
    #══════════════════════════════════════════════════════════════════════════

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $SCHEMA_VERSION = '1.0'
    $ASSESSMENT_VERSION = '1.0'
    $GRAPH_BASE = 'https://graph.microsoft.com/v1.0'
    $GRAPH_BETA = 'https://graph.microsoft.com/beta'
    $TOKEN_ENDPOINT = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token'
    $GRAPH_SCOPE = 'https://graph.microsoft.com/.default'
    $MAX_RETRY = 3

    $ALL_DOMAINS = @('Users', 'Groups', 'Devices', 'Applications',
        'ServicePrincipals', 'MFA', 'ConditionalAccess', 'PIM')

    # Scoring penalties per severity
    $SEVERITY_PENALTY = @{
        Critical      = 20
        High          = 10
        Medium        = 5
        Low           = 2
        Informational = 0
    }

    # Maturity thresholds
    $MATURITY_BANDS = @(
        @{ Min = 85; Label = 'Strong'; Color = '#3fb950' }
        @{ Min = 65; Label = 'Good'; Color = '#d29922' }
        @{ Min = 45; Label = 'Fair'; Color = '#e09e42' }
        @{ Min = 0; Label = 'Poor'; Color = '#f85149' }
    )

    $AssessmentId = [System.Guid]::NewGuid().ToString()
    $AssessmentTs = Get-Date
    $TimestampSlug = $AssessmentTs.ToString('yyyyMMdd_HHmmss')

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  CONSOLE OUTPUT HELPERS
    #══════════════════════════════════════════════════════════════════════════

    function Write-Banner {
        Write-Host ''
        Write-Host '  ╔══════════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
        Write-Host '  ║   🏢 Entra Multi-Tenant Governance Assessment  v1.0              ║' -ForegroundColor Cyan
        Write-Host '  ║   Enterprise Identity Security & Governance Posture              ║' -ForegroundColor Cyan
        Write-Host '  ╚══════════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
        Write-Host ''
    }

    function Write-SectionHeader {
        param([string]$Text, [string]$Icon = '►')
        Write-Host ''
        Write-Host "  $Icon  $Text" -ForegroundColor Cyan
        Write-Host "  $('─' * 68)" -ForegroundColor DarkGray
    }

    function Write-TenantHeader {
        param([string]$Name, [string]$TenantId, [int]$Index, [int]$Total)
        Write-Host ''
        Write-Host "  ┌─ Tenant $Index/$Total : $Name" -ForegroundColor Yellow
        Write-Host "  │  ID        : $TenantId" -ForegroundColor DarkGray
    }

    function Write-CollectorStatus {
        param([string]$Domain, [string]$Status, [string]$Detail = '')
        $icon = switch ($Status) {
            'Success' { '  ✅' }
            'PartialSuccess' { '  ⚠️ ' }
            'Skipped' { '  ⏭ ' }
            'Failed' { '  ❌' }
            default { '  •  ' }
        }
        $color = switch ($Status) {
            'Success' { 'Green' }
            'PartialSuccess' { 'Yellow' }
            'Skipped' { 'Gray' }
            'Failed' { 'Red' }
            default { 'Gray' }
        }
        $padded = $Domain.PadRight(20)
        if ($Detail) {
            Write-Host "  │  $icon $padded  $Detail" -ForegroundColor $color
        }
        else {
            Write-Host "  │  $icon $padded" -ForegroundColor $color
        }
    }

    function Write-TenantScore {
        param([int]$Score, [string]$Label, [int]$Findings)
        $color = switch ($Label) {
            'Strong' { 'Green' }
            'Good' { 'Green' }
            'Fair' { 'Yellow' }
            'Poor' { 'Red' }
            default { 'Gray' }
        }
        Write-Host "  └─ Score: $Score/100  [$Label]   Findings: $Findings" -ForegroundColor $color
    }

    function Write-JsonSafe {
        param([string]$Text)
        # Escape for safe embedding inside a JSON string literal
        $Text `
            -replace '\\', '\\\\'   `
            -replace '"', '\"'     `
            -replace "`r`n", '\n'     `
            -replace "`n", '\n'     `
            -replace "`r", '\n'     `
            -replace "`t", '\t'     `
            -replace '<', '\u003c' `
            -replace '>', '\u003e' `
            -replace '\$', '\u0024'
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  LAYER 1 — TENANT MANAGEMENT
    #══════════════════════════════════════════════════════════════════════════

    function Resolve-TenantList {
        param(
            [string]       $ConfigPath,
            [PSCustomObject[]] $InlineTenants,
            [string[]]     $ExcludeIds
        )

        $tenantList = @()

        if ($ConfigPath) {
            Write-Verbose "Resolving tenant list from JSON config: $ConfigPath"
            try {
                $raw = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
                $cfg = $raw | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                throw "Cannot parse tenant configuration file '$ConfigPath': $_"
            }

            if (-not $cfg.Tenants -or $cfg.Tenants.Count -eq 0) {
                throw "Tenant configuration file contains no tenant entries under the 'Tenants' key."
            }

            $tenantList = @($cfg.Tenants)
        }
        else {
            $tenantList = @($InlineTenants)
        }

        # Validate required fields on each tenant entry
        $required = @('TenantId', 'DisplayName', 'AuthMode')
        $i = 0
        foreach ($t in $tenantList) {
            $i++
            foreach ($field in $required) {
                if (-not ($t.PSObject.Properties.Name -contains $field) -or
                    [string]::IsNullOrWhiteSpace($t.$field)) {
                    throw "Tenant entry #$i is missing required field '$field'."
                }
            }

            # Auth-mode-specific validation
            switch ($t.AuthMode) {
                'ClientCredentials' {
                    if (-not $t.ClientId -or -not $t.ClientSecretEnvVar) {
                        throw "Tenant '$($t.DisplayName)' (AuthMode=ClientCredentials) requires ClientId and ClientSecretEnvVar."
                    }
                }
                'BringYourOwnToken' {
                    if (-not $t.TokenEnvVar) {
                        throw "Tenant '$($t.DisplayName)' (AuthMode=BringYourOwnToken) requires TokenEnvVar."
                    }
                }
                default {
                    throw "Tenant '$($t.DisplayName)' has unknown AuthMode '$($t.AuthMode)'. Valid: ClientCredentials, BringYourOwnToken."
                }
            }
        }

        # Apply exclusion filter
        if ($ExcludeIds -and $ExcludeIds.Count -gt 0) {
            $before = $tenantList.Count
            $tenantList = @($tenantList | Where-Object { $ExcludeIds -notcontains $_.TenantId })
            $excluded = $before - $tenantList.Count
            if ($excluded -gt 0) {
                Write-Verbose "$excluded tenant(s) excluded by ExcludeTenantIds filter."
            }
        }

        if ($tenantList.Count -eq 0) {
            throw "No tenants remain after applying filters. Nothing to assess."
        }

        return $tenantList
    }

    function Resolve-ActiveDomains {
        param([string[]]$Include, [string[]]$Exclude)

        $domains = if ($Include -and $Include.Count -gt 0) { $Include } else { $ALL_DOMAINS }

        if ($Exclude -and $Exclude.Count -gt 0) {
            $domains = @($domains | Where-Object { $Exclude -notcontains $_ })
        }

        if ($domains.Count -eq 0) {
            throw "No domains remain after applying IncludeDomains/ExcludeDomains filters."
        }

        return $domains
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  LAYER 2 — AUTHENTICATION
    #══════════════════════════════════════════════════════════════════════════

    function Invoke-TenantTokenProvider {
        <#
        .SYNOPSIS
            Returns a Graph Bearer token for the specified tenant configuration.
        .NOTES
            Token provider pattern: the switch on AuthMode is the only place
            that changes when adding a new auth mode (e.g. ManagedIdentity).
            All callers receive the same { AccessToken; ExpiresOn; TenantId } object.
            # FUTURE: Add 'ManagedIdentity' branch — query IMDS endpoint
            #         http://169.254.169.254/metadata/identity/oauth2/token
        #>
        param([PSCustomObject]$TenantConfig)

        $result = [PSCustomObject]@{
            AccessToken = $null
            ExpiresOn   = [datetime]::MinValue
            TenantId    = $TenantConfig.TenantId
            AuthMode    = $TenantConfig.AuthMode
            Error       = $null
        }

        try {
            switch ($TenantConfig.AuthMode) {
                'BringYourOwnToken' {
                    $envValue = [System.Environment]::GetEnvironmentVariable($TenantConfig.TokenEnvVar)
                    if ([string]::IsNullOrWhiteSpace($envValue)) {
                        throw "Environment variable '$($TenantConfig.TokenEnvVar)' is not set or is empty."
                    }
                    $result.AccessToken = $envValue.Trim()
                    # BYOT tokens are assumed valid; we verify by calling /me in pre-flight
                    $result.ExpiresOn = (Get-Date).AddHours(1)
                }

                'ClientCredentials' {
                    $secret = [System.Environment]::GetEnvironmentVariable($TenantConfig.ClientSecretEnvVar)
                    if ([string]::IsNullOrWhiteSpace($secret)) {
                        throw "Environment variable '$($TenantConfig.ClientSecretEnvVar)' is not set or is empty."
                    }

                    $body = @{
                        grant_type    = 'client_credentials'
                        client_id     = $TenantConfig.ClientId
                        client_secret = $secret
                        scope         = $GRAPH_SCOPE
                    }

                    $tokenUrl = $TOKEN_ENDPOINT -f $TenantConfig.TenantId

                    $response = Invoke-RestMethod `
                        -Uri    $tokenUrl `
                        -Method Post `
                        -Body   $body `
                        -ContentType 'application/x-www-form-urlencoded' `
                        -ErrorAction Stop

                    $result.AccessToken = $response.access_token
                    $result.ExpiresOn = (Get-Date).AddSeconds($response.expires_in - 30)
                    # Clear the secret from memory immediately
                    $secret = $null
                }

                # FUTURE: 'ManagedIdentity' { ... }

                default {
                    throw "Unsupported AuthMode: $($TenantConfig.AuthMode)"
                }
            }
        }
        catch {
            $result.Error = $_.Exception.Message
        }

        return $result
    }

    function New-GraphHeaders {
        param([string]$AccessToken)
        return @{
            'Authorization'    = "Bearer $AccessToken"
            'Content-Type'     = 'application/json'
            'ConsistencyLevel' = 'eventual'
        }
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  LAYER 3 — CAPABILITY & PERMISSION PRE-FLIGHT
    #══════════════════════════════════════════════════════════════════════════

    function Invoke-CapabilityPreflight {
        <#
        .SYNOPSIS
            Probes which Graph permissions and Entra features are accessible for a tenant.
            Returns a hashtable: Domain => CapabilityStatus object.
            This layer answers "what CAN this token assess?" before collectors run.
        #>
        param(
            [hashtable] $Headers,
            [string]    $TenantId,
            [string[]]  $ActiveDomains
        )

        # Map domain → minimal probe endpoint → human-readable permission name
        $probeMap = @{
            Users             = @{ Uri = "$GRAPH_BASE/users?`$top=1&`$select=id"; Permission = 'User.Read.All' }
            Groups            = @{ Uri = "$GRAPH_BASE/groups?`$top=1&`$select=id"; Permission = 'Group.Read.All' }
            Devices           = @{ Uri = "$GRAPH_BASE/devices?`$top=1&`$select=id"; Permission = 'Device.Read.All' }
            Applications      = @{ Uri = "$GRAPH_BASE/applications?`$top=1&`$select=id"; Permission = 'Application.Read.All' }
            ServicePrincipals = @{ Uri = "$GRAPH_BASE/servicePrincipals?`$top=1&`$select=id"; Permission = 'Application.Read.All' }
            MFA               = @{ Uri = "$GRAPH_BASE/reports/authenticationMethods/userRegistrationDetails?`$top=1"; Permission = 'UserAuthenticationMethod.Read.All' }
            ConditionalAccess = @{ Uri = "$GRAPH_BASE/identity/conditionalAccess/policies?`$top=1"; Permission = 'Policy.Read.All' }
            PIM               = @{ Uri = "$GRAPH_BETA/privilegedAccess/aadRoles/resources"; Permission = 'PrivilegedAccess.Read.AzureAD' }
        }

        $capabilities = @{}

        foreach ($domain in $ActiveDomains) {
            if (-not $probeMap.ContainsKey($domain)) {
                $capabilities[$domain] = [PSCustomObject]@{
                    Domain     = $domain
                    Status     = 'Unknown'
                    Permission = 'Unknown'
                    Reason     = 'No probe defined for this domain'
                }
                continue
            }

            $probe = $probeMap[$domain]
            $cap = [PSCustomObject]@{
                Domain     = $domain
                Status     = 'Available'
                Permission = $probe.Permission
                Reason     = $null
            }

            try {
                $null = Invoke-GraphRequest -Uri $probe.Uri -Headers $Headers
            }
            catch {
                $errMsg = $_.Exception.Message
                if ($errMsg -match '403|Forbidden|Authorization_RequestDenied') {
                    # Distinguish PIM license issues from plain permission denials
                    if ($domain -eq 'PIM' -and $errMsg -match 'Premium|License|Subscription') {
                        $cap.Status = 'LicenseRequired'
                        $cap.Reason = 'Entra ID P2 or Governance license not detected on this tenant.'
                    }
                    else {
                        $cap.Status = 'PermissionNotGranted'
                        $cap.Reason = "Required permission '$($probe.Permission)' not granted to this token."
                    }
                }
                elseif ($errMsg -match '401|Unauthorized') {
                    $cap.Status = 'AuthenticationFailed'
                    $cap.Reason = 'Token is invalid or expired.'
                }
                else {
                    $cap.Status = 'ProbeError'
                    $cap.Reason = $errMsg
                }
            }

            $capabilities[$domain] = $cap
        }

        return $capabilities
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  GRAPH INFRASTRUCTURE — PAGING & RETRY
    #══════════════════════════════════════════════════════════════════════════

    function Invoke-GraphRequest {
        <#
        .SYNOPSIS
            Single Graph API call with exponential-backoff retry on throttling (429).
        #>
        param(
            [string]    $Uri,
            [hashtable] $Headers,
            [string]    $Method = 'GET'
        )

        $attempt = 0
        do {
            $attempt++
            try {
                $response = Invoke-RestMethod `
                    -Uri     $Uri `
                    -Headers $Headers `
                    -Method  $Method `
                    -ErrorAction Stop

                return $response
            }
            catch {
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }

                if ($statusCode -eq 429 -and $attempt -lt $MAX_RETRY) {
                    $retryAfter = 10
                    try {
                        $retryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                    }
                    catch { }
                    Write-Verbose "Graph throttled (429). Waiting $retryAfter seconds before retry $attempt/$MAX_RETRY..."
                    Start-Sleep -Seconds $retryAfter
                }
                else {
                    throw
                }
            }
        }
        while ($attempt -lt $MAX_RETRY)
    }

    function Invoke-GraphPagedRequest {
        <#
        .SYNOPSIS
            Follows @odata.nextLink pagination and returns all result values.
            Caps at $MaxPages to prevent runaway calls on very large tenants.
        #>
        param(
            [string]    $Uri,
            [hashtable] $Headers,
            [int]       $MaxPages = 50
        )

        $allValues = [System.Collections.Generic.List[object]]::new()
        $nextUri = $Uri
        $page = 0

        while ($nextUri -and $page -lt $MaxPages) {
            $page++
            $response = Invoke-GraphRequest -Uri $nextUri -Headers $Headers
            if ($response.value) {
                $allValues.AddRange(@($response.value))
            }
            $nextUri = if ($response.PSObject.Properties['@odata.nextLink']) { $response.'@odata.nextLink' } else { $null }
        }

        return $allValues.ToArray()
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  LAYER 4 — DOMAIN COLLECTORS
    #══════════════════════════════════════════════════════════════════════════

    function New-CollectorResult {
        param([string]$Domain, [string]$Status = 'Success')
        return [PSCustomObject]@{
            Domain      = $Domain
            Status      = $Status
            CollectedAt = Get-Date
            Metrics     = @{}
            RawSummary  = @{}
            Errors      = [System.Collections.Generic.List[string]]::new()
        }
    }

    # ── COLLECTOR: Users ────────────────────────────────────────────────────
    function Invoke-UsersCollector {
        param([hashtable]$Headers)

        $cr = New-CollectorResult -Domain 'Users'
        try {
            # Total count
            $countResp = Invoke-GraphRequest -Uri "$GRAPH_BASE/users/`$count" -Headers $Headers
            $totalUsers = [int]$countResp

            # Guest users
            $guestUri = "$GRAPH_BASE/users?`$filter=userType eq 'Guest'&`$count=true&`$top=1&`$select=id"
            $guestResp = Invoke-GraphRequest -Uri $guestUri -Headers $Headers
            $guestCount = if ($guestResp.PSObject.Properties['@odata.count']) { [int]$guestResp.'@odata.count' } else { 0 }

            # Blocked sign-in accounts
            $blockedUri = "$GRAPH_BASE/users?`$filter=accountEnabled eq false&`$count=true&`$top=1&`$select=id"
            $blockedResp = Invoke-GraphRequest -Uri $blockedUri -Headers $Headers
            $blockedCount = if ($blockedResp.PSObject.Properties['@odata.count']) { [int]$blockedResp.'@odata.count' } else { 0 }

            # Stale accounts — sign-in older than 90 days
            $staleDate = (Get-Date).AddDays(-90).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $staleUri = "$GRAPH_BASE/users?`$filter=signInActivity/lastSignInDateTime le $staleDate&`$count=true&`$top=1&`$select=id"
            $staleResp = Invoke-GraphRequest -Uri $staleUri -Headers $Headers
            $staleCount = if ($staleResp.PSObject.Properties['@odata.count']) { [int]$staleResp.'@odata.count' } else { 0 }

            # Licensed users
            $licensedUri = "$GRAPH_BASE/users?`$filter=assignedLicenses/`$count ne 0&`$count=true&`$top=1&`$select=id"
            $licensedResp = Invoke-GraphRequest -Uri $licensedUri -Headers $Headers
            $licensedCount = if ($licensedResp.PSObject.Properties['@odata.count']) { [int]$licensedResp.'@odata.count' } else { 0 }

            $guestPct = if ($totalUsers -gt 0) { [math]::Round(($guestCount / $totalUsers) * 100, 1) } else { 0 }

            $cr.Metrics = @{
                TotalUsers    = $totalUsers
                GuestUsers    = $guestCount
                GuestPercent  = $guestPct
                BlockedUsers  = $blockedCount
                StaleUsers    = $staleCount
                LicensedUsers = $licensedCount
            }
            $cr.RawSummary = $cr.Metrics
        }
        catch {
            $cr.Status = 'Failed'
            $cr.Errors.Add($_.Exception.Message)
        }
        return $cr
    }

    # ── COLLECTOR: Groups ───────────────────────────────────────────────────
    function Invoke-GroupsCollector {
        param([hashtable]$Headers)

        $cr = New-CollectorResult -Domain 'Groups'
        try {
            $countResp = Invoke-GraphRequest -Uri "$GRAPH_BASE/groups/`$count" -Headers $Headers
            $totalGroups = [int]$countResp

            # M365 groups
            $m365Uri = "$GRAPH_BASE/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$count=true&`$top=1&`$select=id"
            $m365Resp = Invoke-GraphRequest -Uri $m365Uri -Headers $Headers
            $m365Count = if ($m365Resp.'@odata.count') { [int]$m365Resp.'@odata.count' } else { 0 }

            # Dynamic membership groups
            $dynUri = "$GRAPH_BASE/groups?`$filter=groupTypes/any(c:c eq 'DynamicMembership')&`$count=true&`$top=1&`$select=id"
            $dynResp = Invoke-GraphRequest -Uri $dynUri -Headers $Headers
            $dynCount = if ($dynResp.'@odata.count') { [int]$dynResp.'@odata.count' } else { 0 }

            # Groups with no owners — sample first 999 for performance
            $ownerUri = "$GRAPH_BASE/groups?`$top=999&`$select=id,displayName"
            $groupSample = @(Invoke-GraphPagedRequest -Uri $ownerUri -Headers $Headers -MaxPages 10)
            $noOwnerCount = 0
            foreach ($g in $groupSample) {
                try {
                    $ownersCheck = Invoke-GraphRequest -Uri "$GRAPH_BASE/groups/$($g.id)/owners/`$count" -Headers $Headers
                    if ([int]$ownersCheck -eq 0) { $noOwnerCount++ }
                }
                catch { }
            }

            $cr.Metrics = @{
                TotalGroups    = $totalGroups
                M365Groups     = $m365Count
                DynamicGroups  = $dynCount
                SecurityGroups = $totalGroups - $m365Count
                NoOwnerGroups  = $noOwnerCount
                SampleSize     = $groupSample.Count
            }
            $cr.RawSummary = $cr.Metrics
        }
        catch {
            $cr.Status = 'Failed'
            $cr.Errors.Add($_.Exception.Message)
        }
        return $cr
    }

    # ── COLLECTOR: Devices ──────────────────────────────────────────────────
    function Invoke-DevicesCollector {
        param([hashtable]$Headers)

        $cr = New-CollectorResult -Domain 'Devices'
        try {
            $countResp = Invoke-GraphRequest -Uri "$GRAPH_BASE/devices/`$count" -Headers $Headers
            $totalDevices = [int]$countResp

            # Compliant devices
            $compUri = "$GRAPH_BASE/devices?`$filter=isCompliant eq true&`$count=true&`$top=1&`$select=id"
            $compResp = Invoke-GraphRequest -Uri $compUri -Headers $Headers
            $compCount = if ($compResp.'@odata.count') { [int]$compResp.'@odata.count' } else { 0 }

            # Stale devices — approximateLastSignInDateTime > 90 days
            $staleDate = (Get-Date).AddDays(-90).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $staleUri = "$GRAPH_BASE/devices?`$filter=approximateLastSignInDateTime le $staleDate&`$count=true&`$top=1&`$select=id"
            $staleResp = Invoke-GraphRequest -Uri $staleUri -Headers $Headers
            $staleDevCount = if ($staleResp.'@odata.count') { [int]$staleResp.'@odata.count' } else { 0 }

            # Hybrid Azure AD joined
            $hybridUri = "$GRAPH_BASE/devices?`$filter=trustType eq 'ServerAd'&`$count=true&`$top=1&`$select=id"
            $hybridResp = Invoke-GraphRequest -Uri $hybridUri -Headers $Headers
            $hybridCount = if ($hybridResp.'@odata.count') { [int]$hybridResp.'@odata.count' } else { 0 }

            $compPct = if ($totalDevices -gt 0) { [math]::Round(($compCount / $totalDevices) * 100, 1) } else { 0 }

            $cr.Metrics = @{
                TotalDevices        = $totalDevices
                CompliantDevices    = $compCount
                CompliancePercent   = $compPct
                StaleDevices        = $staleDevCount
                HybridJoined        = $hybridCount
                NonCompliantDevices = $totalDevices - $compCount
            }
            $cr.RawSummary = $cr.Metrics
        }
        catch {
            $cr.Status = 'Failed'
            $cr.Errors.Add($_.Exception.Message)
        }
        return $cr
    }

    # ── COLLECTOR: Applications ─────────────────────────────────────────────
    function Invoke-ApplicationsCollector {
        param([hashtable]$Headers)

        $cr = New-CollectorResult -Domain 'Applications'
        try {
            # Fetch all app registrations with credential info
            $appsUri = "$GRAPH_BASE/applications?`$select=id,displayName,appId,passwordCredentials,keyCredentials,owners&`$top=999"
            $apps = @(Invoke-GraphPagedRequest -Uri $appsUri -Headers $Headers -MaxPages 20)

            $totalApps = $apps.Count
            $expiringSecrets = [System.Collections.Generic.List[string]]::new()
            $expiredSecrets = [System.Collections.Generic.List[string]]::new()
            $longLivedCreds = [System.Collections.Generic.List[string]]::new()
            $noOwnerApps = [System.Collections.Generic.List[string]]::new()
            $now = Get-Date
            $soonThreshold = $now.AddDays(30)
            $longLivedDays = 180

            foreach ($app in $apps) {
                # Check owners
                try {
                    $ownerCount = Invoke-GraphRequest -Uri "$GRAPH_BASE/applications/$($app.id)/owners/`$count" -Headers $Headers
                    if ([int]$ownerCount -eq 0) { $noOwnerApps.Add($app.displayName) }
                }
                catch { }

                # Check password credentials (secrets)
                foreach ($cred in @($app.passwordCredentials)) {
                    if ($null -eq $cred -or -not $cred.endDateTime) { continue }
                    $expiry = [datetime]$cred.endDateTime
                    if ($expiry -lt $now) { $expiredSecrets.Add("$($app.displayName) [expired $($expiry.ToString('yyyy-MM-dd'))]") }
                    elseif ($expiry -lt $soonThreshold) { $expiringSecrets.Add("$($app.displayName) [expires $($expiry.ToString('yyyy-MM-dd'))]") }

                    # Long-lived secrets
                    $startDt = if ($cred.startDateTime) { [datetime]$cred.startDateTime } else { $now.AddDays(-$longLivedDays - 1) }
                    $lifeDays = ($expiry - $startDt).TotalDays
                    if ($lifeDays -gt $longLivedDays) { $longLivedCreds.Add($app.displayName) }
                }
            }

            $cr.Metrics = @{
                TotalApps       = $totalApps
                ExpiringSecrets = $expiringSecrets.Count
                ExpiredSecrets  = $expiredSecrets.Count
                LongLivedCreds  = $longLivedCreds.Count
                NoOwnerApps     = $noOwnerApps.Count
            }
            $cr.RawSummary = @{
                TotalApps           = $totalApps
                ExpiringSecretsList = @($expiringSecrets | Select-Object -First 20)
                ExpiredSecretsList  = @($expiredSecrets  | Select-Object -First 20)
                LongLivedCredsList  = @($longLivedCreds  | Select-Object -Unique -First 20)
                NoOwnerAppsList     = @($noOwnerApps     | Select-Object -First 20)
            }
        }
        catch {
            $cr.Status = 'Failed'
            $cr.Errors.Add($_.Exception.Message)
        }
        return $cr
    }

    # ── COLLECTOR: Service Principals ───────────────────────────────────────
    function Invoke-ServicePrincipalsCollector {
        param([hashtable]$Headers)

        $cr = New-CollectorResult -Domain 'ServicePrincipals'
        try {
            $spUri = "$GRAPH_BASE/servicePrincipals?`$select=id,displayName,appId,servicePrincipalType,passwordCredentials,keyCredentials,appRoleAssignments&`$top=999"
            $sps = @(Invoke-GraphPagedRequest -Uri $spUri -Headers $Headers -MaxPages 20)

            $totalSPs = $sps.Count
            $managedIdentities = @($sps | Where-Object { $_.servicePrincipalType -eq 'ManagedIdentity' })
            $enterpriseApps = @($sps | Where-Object { $_.servicePrincipalType -eq 'Application' })

            # High-privilege delegated permissions — check app role assignments
            $highPrivAppIds = @(
                '00000003-0000-0000-c000-000000000000'  # Microsoft Graph
            )
            $highPrivRoles = @(
                # Graph app role IDs for sensitive permissions
                '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30'  # Application.ReadWrite.All
                '06b708a9-e830-4db3-a914-8e69da51d44f'  # AppRoleAssignment.ReadWrite.All
                '741f803b-c850-494e-b5df-cde7c675a1ca'  # User.ReadWrite.All
                'e1fe6dd8-ba31-4d61-89e7-88639da4683d'  # User.Read.All (for tracking)
                '62a82d76-70ea-41e2-9197-370581804d09'  # Group.ReadWrite.All
                '19dbc75e-c2e2-444c-a770-ec69d8559fc7'  # Directory.ReadWrite.All
            )

            $highPrivSPs = [System.Collections.Generic.List[string]]::new()
            foreach ($sp in $enterpriseApps) {
                try {
                    $roleAssignUri = "$GRAPH_BASE/servicePrincipals/$($sp.id)/appRoleAssignments"
                    $assignments = @(Invoke-GraphPagedRequest -Uri $roleAssignUri -Headers $Headers -MaxPages 5)
                    $hasHighPriv = $assignments | Where-Object {
                        $highPrivAppIds -contains $_.resourceId -or
                        $highPrivRoles -contains $_.appRoleId
                    }
                    if ($hasHighPriv) { $highPrivSPs.Add($sp.displayName) }
                }
                catch { }
            }

            # Admin-consented OAuth2 grants
            $grantUri = "$GRAPH_BASE/oauth2PermissionGrants?`$filter=consentType eq 'AllPrincipals'&`$top=999"
            $adminGrants = @(Invoke-GraphPagedRequest -Uri $grantUri -Headers $Headers -MaxPages 5)

            $cr.Metrics = @{
                TotalServicePrincipals = $totalSPs
                ManagedIdentities      = $managedIdentities.Count
                EnterpriseApps         = $enterpriseApps.Count
                HighPrivilegeSPs       = $highPrivSPs.Count
                AdminConsentedGrants   = $adminGrants.Count
            }
            $cr.RawSummary = @{
                TotalServicePrincipals = $totalSPs
                HighPrivSPList         = @($highPrivSPs | Select-Object -First 20)
                AdminGrantCount        = $adminGrants.Count
            }
        }
        catch {
            $cr.Status = 'Failed'
            $cr.Errors.Add($_.Exception.Message)
        }
        return $cr
    }

    # ── COLLECTOR: MFA ──────────────────────────────────────────────────────
    function Invoke-MFACollector {
        param([hashtable]$Headers)

        $cr = New-CollectorResult -Domain 'MFA'
        try {
            # Authentication method registration details — paged
            $regUri = "$GRAPH_BASE/reports/authenticationMethods/userRegistrationDetails?`$top=999&`$select=id,isMfaRegistered,isMfaCapable,isPasswordlessCapable,methodsRegistered"
            $regData = @(Invoke-GraphPagedRequest -Uri $regUri -Headers $Headers -MaxPages 100)

            $totalUsers = $regData.Count
            $mfaRegistered = @($regData | Where-Object { $_.isMfaRegistered -eq $true }).Count
            $mfaCapable = @($regData | Where-Object { $_.isMfaCapable -eq $true }).Count
            $passwordless = @($regData | Where-Object { $_.isPasswordlessCapable -eq $true }).Count

            # Method breakdown
            $methodCounts = @{}
            foreach ($user in $regData) {
                foreach ($method in @($user.methodsRegistered)) {
                    if (-not $method) { continue }
                    $methodCounts[$method] = ($methodCounts[$method] ?? 0) + 1
                }
            }

            $mfaRegPct = if ($totalUsers -gt 0) { [math]::Round(($mfaRegistered / $totalUsers) * 100, 1) } else { 0 }
            $pwdlessPct = if ($totalUsers -gt 0) { [math]::Round(($passwordless / $totalUsers) * 100, 1) } else { 0 }

            # Check if legacy per-user MFA is still configured (beta endpoint)
            $legacyUri = "$GRAPH_BETA/reports/credentialUserRegistrationDetails?`$top=1"
            $legacyEnabled = $false
            try {
                $legacyResp = Invoke-GraphRequest -Uri $legacyUri -Headers $Headers
                # If the endpoint is reachable, legacy MFA reporting is available
                # A non-zero count of users with only SMS/call indicates per-user MFA usage
                $smsOnlyUsers = @($regData | Where-Object {
                        $_.methodsRegistered -and
                        $_.methodsRegistered.Count -eq 1 -and
                        ($_.methodsRegistered -contains 'mobilePhone' -or
                        $_.methodsRegistered -contains 'alternateMobilePhone')
                    }).Count
                $legacyEnabled = $smsOnlyUsers -gt 0
            }
            catch { }

            $cr.Metrics = @{
                TotalUsersAssessed   = $totalUsers
                MFARegistered        = $mfaRegistered
                MFARegisteredPercent = $mfaRegPct
                MFACapable           = $mfaCapable
                PasswordlessCapable  = $passwordless
                PasswordlessPercent  = $pwdlessPct
                LegacyMFAInUse       = $legacyEnabled
                MethodBreakdown      = $methodCounts
            }
            $cr.RawSummary = $cr.Metrics
        }
        catch {
            $cr.Status = 'Failed'
            $cr.Errors.Add($_.Exception.Message)
        }
        return $cr
    }

    # ── COLLECTOR: Conditional Access ───────────────────────────────────────
    function Invoke-ConditionalAccessCollector {
        param([hashtable]$Headers)

        $cr = New-CollectorResult -Domain 'ConditionalAccess'
        try {
            $caPolicies = @(Invoke-GraphPagedRequest `
                    -Uri "$GRAPH_BASE/identity/conditionalAccess/policies?`$select=id,displayName,state,conditions,grantControls,sessionControls" `
                    -Headers $Headers -MaxPages 5)

            $totalPolicies = $caPolicies.Count
            $enabledPolicies = @($caPolicies | Where-Object { $_.state -eq 'enabled' }).Count
            $reportOnlyPols = @($caPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
            $disabledPolicies = @($caPolicies | Where-Object { $_.state -eq 'disabled' }).Count

            # MFA enforcement — any enabled policy requiring MFA for all users
            $mfaEnforcedAllUsers = $false
            $legacyAuthBlocked = $false
            $adminsCovered = $false
            $deviceComplianceReq = $false

            foreach ($pol in $caPolicies | Where-Object { $_.state -eq 'enabled' }) {
                $users = $pol.conditions.users
                $allUsersInc = $users.includeUsers -contains 'All'
                $grantCtrl = $pol.grantControls

                # MFA for all users
                if ($allUsersInc -and
                    $grantCtrl -and
                    $grantCtrl.builtInControls -contains 'mfa') {
                    $mfaEnforcedAllUsers = $true
                }

                # Legacy auth (client app types = exchangeActiveSync + other)
                $clientApps = $pol.conditions.clientAppTypes
                if ($clientApps -contains 'exchangeActiveSync' -or
                    $clientApps -contains 'other') {
                    if ($grantCtrl -and $grantCtrl.builtInControls -contains 'block') {
                        $legacyAuthBlocked = $true
                    }
                }

                # Admin role coverage
                $roles = $pol.conditions.users.includeRoles
                if ($roles -and $roles.Count -gt 0) {
                    $adminsCovered = $true
                }

                # Device compliance
                if ($grantCtrl -and
                    $grantCtrl.builtInControls -contains 'compliantDevice') {
                    $deviceComplianceReq = $true
                }
            }

            $cr.Metrics = @{
                TotalPolicies       = $totalPolicies
                EnabledPolicies     = $enabledPolicies
                ReportOnlyPolicies  = $reportOnlyPols
                DisabledPolicies    = $disabledPolicies
                MFAEnforcedAllUsers = $mfaEnforcedAllUsers
                LegacyAuthBlocked   = $legacyAuthBlocked
                AdminsCovered       = $adminsCovered
                DeviceComplianceReq = $deviceComplianceReq
            }
            $cr.RawSummary = $cr.Metrics
        }
        catch {
            $cr.Status = 'Failed'
            $cr.Errors.Add($_.Exception.Message)
        }
        return $cr
    }

    # ── COLLECTOR: PIM ──────────────────────────────────────────────────────
    function Invoke-PIMCollector {
        param([hashtable]$Headers, [PSCustomObject]$Capability)

        $cr = New-CollectorResult -Domain 'PIM'

        # Honour capability pre-flight result
        if ($Capability -and $Capability.Status -ne 'Available') {
            $cr.Status = switch ($Capability.Status) {
                'LicenseRequired' { 'LicenseNotAvailable' }
                'PermissionNotGranted' { 'PermissionDenied' }
                default { 'Unavailable' }
            }
            $cr.Errors.Add($Capability.Reason)
            $cr.RawSummary = @{ CapabilityStatus = $Capability.Status; Reason = $Capability.Reason }
            return $cr
        }

        try {
            # Active role assignments
            $activeUri = "$GRAPH_BETA/roleManagement/directory/roleAssignments?`$expand=principal,roleDefinition&`$top=999"
            $activeAssignments = @(Invoke-GraphPagedRequest -Uri $activeUri -Headers $Headers -MaxPages 10)

            # Eligible role assignments
            $eligUri = "$GRAPH_BETA/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition&`$top=999"
            $eligibleAssignments = @(Invoke-GraphPagedRequest -Uri $eligUri -Headers $Headers -MaxPages 10)

            # PIM configured = at least some eligible assignments exist
            $pimConfigured = $eligibleAssignments.Count -gt 0

            # Permanent Global Admins — active permanent (no schedule) assignments to GA role
            $gaRoleId = '62e90394-69f5-4237-9190-012177145e10'
            $permGAs = @($activeAssignments | Where-Object {
                    $_.roleDefinition.id -eq $gaRoleId -and
                    (-not $_.scheduleInfo -or $_.scheduleInfo.expiration.type -eq 'noExpiration')
                })

            # Roles with no activation approval requirement — check PIM policies
            $noApprovalRoles = [System.Collections.Generic.List[string]]::new()
            try {
                $pimPolicyUri = "$GRAPH_BETA/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'"
                $pimPolicies = @(Invoke-GraphPagedRequest -Uri $pimPolicyUri -Headers $Headers -MaxPages 5)

                foreach ($policy in $pimPolicies) {
                    $approvalRule = $policy.rules | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' }
                    if ($approvalRule -and
                        $approvalRule.setting -and
                        $approvalRule.setting.isApprovalRequired -eq $false) {
                        $noApprovalRoles.Add($policy.displayName ?? 'Unknown Role')
                    }
                }
            }
            catch {
                $cr.Errors.Add("PIM policy check failed (non-fatal): $($_.Exception.Message)")
            }

            # High-privilege roles without MFA on activation
            $noMFARoles = [System.Collections.Generic.List[string]]::new()
            try {
                foreach ($policy in $pimPolicies) {
                    $mfaRule = $policy.rules | Where-Object { $_.id -eq 'AuthenticationContext_EndUser_Assignment' }
                    if (-not $mfaRule -or -not $mfaRule.claimValue) {
                        $noMFARoles.Add($policy.displayName ?? 'Unknown Role')
                    }
                }
            }
            catch { }

            $cr.Metrics = @{
                PIMConfigured               = $pimConfigured
                ActiveAssignments           = $activeAssignments.Count
                EligibleAssignments         = $eligibleAssignments.Count
                PermanentGlobalAdmins       = $permGAs.Count
                RolesWithNoApproval         = $noApprovalRoles.Count
                RolesWithoutMFAOnActivation = $noMFARoles.Count
            }
            $cr.RawSummary = @{
                PIMConfigured            = $pimConfigured
                PermanentGlobalAdminList = @($permGAs | ForEach-Object { $_.principal.displayName ?? $_.principal.id } | Select-Object -First 20)
                NoApprovalRolesList      = @($noApprovalRoles | Select-Object -First 20)
                NoMFARolesList           = @($noMFARoles      | Select-Object -First 20)
            }
        }
        catch {
            $cr.Status = 'Failed'
            $cr.Errors.Add($_.Exception.Message)
        }
        return $cr
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  LAYER 5 — ASSESSMENT & FINDINGS ENGINE
    #══════════════════════════════════════════════════════════════════════════

    function Invoke-FindingsAssessment {
        <#
        .SYNOPSIS
            Evaluates domain collector results against the finding catalogue.
            Returns an array of Finding objects with stable IDs, severity,
            business impact statements, and remediation recommendations.
        #>
        param(
            [PSCustomObject]$TenantResult,
            [hashtable]     $CollectorResults
        )

        $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

        function New-Finding {
            param(
                [string] $FindingId,
                [string] $Domain,
                [string] $Title,
                [string] $Severity,
                [string] $BusinessImpact,
                [string] $TechnicalDetail,
                [string] $Recommendation,
                [int]    $AffectedCount = 0,
                [array]  $AffectedObjects = @(),
                [string] $RemediationEffort = 'Medium',
                [array]  $References = @()
            )

            return [PSCustomObject]@{
                FindingId         = $FindingId
                TenantId          = $TenantResult.TenantId
                TenantName        = $TenantResult.DisplayName
                Domain            = $Domain
                Title             = $Title
                Severity          = $Severity
                BusinessImpact    = $BusinessImpact
                TechnicalDetail   = $TechnicalDetail
                Recommendation    = $Recommendation
                AffectedCount     = $AffectedCount
                AffectedObjects   = @($AffectedObjects | Select-Object -First 20)
                RemediationEffort = $RemediationEffort
                References        = $References
            }
        }

        # ── USERS ─────────────────────────────────────────────────────────
        if ($CollectorResults.ContainsKey('Users') -and
            $CollectorResults['Users'].Status -eq 'Success') {
            $um = $CollectorResults['Users'].Metrics

            # ENT-USR-001: High guest ratio
            if ($um.GuestPercent -gt 20) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-USR-001' `
                            -Domain          'Users' `
                            -Title           'Guest accounts exceed 20% of total user population' `
                            -Severity        'High' `
                            -BusinessImpact  "External guest accounts represent $($um.GuestPercent)% of your user base. This significantly expands the attack surface and increases the risk of data leakage to external parties if guest access is not properly governed." `
                            -TechnicalDetail "$($um.GuestUsers) guest users out of $($um.TotalUsers) total ($($um.GuestPercent)%). Threshold: 20%." `
                            -Recommendation  'Review and implement a Guest Access Lifecycle policy. Define which business units can invite guests, require periodic access reviews, and enforce guest account expiry. Consider enabling Entra ID Access Reviews for all guest users.' `
                            -AffectedCount   $um.GuestUsers `
                            -RemediationEffort 'Medium' `
                            -References      @('https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b', 'https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview')
                    ))
            }

            # ENT-USR-002: Stale accounts
            if ($um.StaleUsers -gt 0) {
                $sev = if ($um.StaleUsers -gt 500) { 'High' } else { 'Medium' }
                $findings.Add((New-Finding `
                            -FindingId       'ENT-USR-002' `
                            -Domain          'Users' `
                            -Title           'Stale user accounts with no sign-in in 90+ days' `
                            -Severity        $sev `
                            -BusinessImpact  "Accounts that have not been used in 90 or more days represent dormant attack vectors. If compromised through password spray or credential stuffing, they may go undetected for extended periods because there is no legitimate sign-in baseline to compare against." `
                            -TechnicalDetail "$($um.StaleUsers) accounts have not signed in within the last 90 days." `
                            -Recommendation  'Implement an automated stale account remediation process: disable after 90 days of inactivity and delete after 180 days. Use Entra ID Lifecycle Workflows or a custom governance script to enforce this at scale.' `
                            -AffectedCount   $um.StaleUsers `
                            -RemediationEffort 'Low' `
                            -References      @('https://learn.microsoft.com/en-us/entra/id-governance/lifecycle-workflows-overview')
                    ))
            }

            # ENT-USR-003: Blocked accounts still licensed
            if ($um.BlockedUsers -gt 0) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-USR-003' `
                            -Domain          'Users' `
                            -Title           'Blocked accounts consuming paid licences' `
                            -Severity        'Low' `
                            -BusinessImpact  "$($um.BlockedUsers) accounts are blocked from signing in but may still hold Microsoft 365 licences, creating unnecessary licence spend. While blocked accounts cannot authenticate, licence wastage is a governance and cost concern." `
                            -TechnicalDetail "$($um.BlockedUsers) accounts have sign-in blocked (accountEnabled = false)." `
                            -Recommendation  'Audit all blocked accounts quarterly. Reclaim licences from accounts blocked longer than 30 days. If the account is a leaver, initiate off-boarding automation to remove licences at the point of blocking.' `
                            -AffectedCount   $um.BlockedUsers `
                            -RemediationEffort 'Low' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/users/users-bulk-delete')
                    ))
            }
        }

        # ── GROUPS ────────────────────────────────────────────────────────
        if ($CollectorResults.ContainsKey('Groups') -and
            $CollectorResults['Groups'].Status -eq 'Success') {
            $gm = $CollectorResults['Groups'].Metrics

            # ENT-GRP-001: Groups with no owners
            if ($gm.NoOwnerGroups -gt 0) {
                $sev = if ($gm.NoOwnerGroups -gt 50) { 'High' } else { 'Medium' }
                $findings.Add((New-Finding `
                            -FindingId       'ENT-GRP-001' `
                            -Domain          'Groups' `
                            -Title           'Groups with no assigned owners' `
                            -Severity        $sev `
                            -BusinessImpact  "Owner-less groups have no accountable party to review membership, approve join requests, or respond to access reviews. This creates ungoverned access pathways that persist indefinitely and are invisible during routine access reviews." `
                            -TechnicalDetail "$($gm.NoOwnerGroups) groups (out of $($gm.SampleSize) sampled) have zero assigned owners." `
                            -Recommendation  'Run a group ownership remediation campaign: assign at least two owners (a primary and a backup) to every group. Automate this via Entra ID Access Reviews with owner attestation. Block creation of new groups without a nominated owner.' `
                            -AffectedCount   $gm.NoOwnerGroups `
                            -RemediationEffort 'Medium' `
                            -References      @('https://learn.microsoft.com/en-us/microsoft-365/admin/create-groups/manage-groups?view=o365-worldwide')
                    ))
            }

            # ENT-GRP-002: High dynamic group ratio
            if ($gm.TotalGroups -gt 0) {
                $dynPct = [math]::Round(($gm.DynamicGroups / $gm.TotalGroups) * 100, 1)
                if ($dynPct -gt 40) {
                    $findings.Add((New-Finding `
                                -FindingId       'ENT-GRP-002' `
                                -Domain          'Groups' `
                                -Title           'High proportion of dynamic membership groups without owner governance' `
                                -Severity        'Medium' `
                                -BusinessImpact  "Dynamic groups ($dynPct% of all groups) automatically add members based on attribute rules. If user attributes are inaccurate or maliciously manipulated, dynamic groups can grant unintended access to resources without any human approval step." `
                                -TechnicalDetail "$($gm.DynamicGroups) dynamic groups out of $($gm.TotalGroups) total ($dynPct%)." `
                                -Recommendation  'Audit dynamic group membership rules quarterly. Ensure sensitive resource groups are not using dynamic membership — require manual approval for access to high-value assets. Validate that user attributes driving dynamic rules cannot be self-modified.' `
                                -AffectedCount   $gm.DynamicGroups `
                                -RemediationEffort 'Medium' `
                                -References      @('https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership')
                        ))
                }
            }
        }

        # ── DEVICES ───────────────────────────────────────────────────────
        if ($CollectorResults.ContainsKey('Devices') -and
            $CollectorResults['Devices'].Status -eq 'Success') {
            $dm = $CollectorResults['Devices'].Metrics

            # ENT-DEV-001: Low device compliance
            if ($dm.TotalDevices -gt 0 -and $dm.CompliancePercent -lt 80) {
                $sev = if ($dm.CompliancePercent -lt 50) { 'Critical' } else { 'High' }
                $findings.Add((New-Finding `
                            -FindingId       'ENT-DEV-001' `
                            -Domain          'Devices' `
                            -Title           'High percentage of non-compliant devices accessing the tenant' `
                            -Severity        $sev `
                            -BusinessImpact  "Only $($dm.CompliancePercent)% of enrolled devices meet your compliance baseline. Non-compliant devices — missing patches, disabled encryption, or no endpoint security — are common entry points for ransomware and targeted attacks. They undermine any Conditional Access controls that rely on device health signals." `
                            -TechnicalDetail "$($dm.NonCompliantDevices) non-compliant devices out of $($dm.TotalDevices) total ($($dm.CompliancePercent)% compliant)." `
                            -Recommendation  'Enforce device compliance as a Conditional Access grant condition for access to critical applications. Investigate and remediate non-compliant devices using Intune. Set a 30-day remediation SLA for compliance failures before device access is revoked.' `
                            -AffectedCount   $dm.NonCompliantDevices `
                            -RemediationEffort 'High' `
                            -References      @('https://learn.microsoft.com/en-us/intune/protect/device-compliance-get-started', 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device')
                    ))
            }

            # ENT-DEV-002: Stale devices
            if ($dm.StaleDevices -gt 0) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-DEV-002' `
                            -Domain          'Devices' `
                            -Title           'Stale device registrations (90+ days inactive)' `
                            -Severity        'Medium' `
                            -BusinessImpact  "Stale device records inflate your managed device count and may allow decommissioned or repurposed devices to retain access tokens. Unmanaged devices that remain registered can be used to access resources if a user's credentials are later compromised." `
                            -TechnicalDetail "$($dm.StaleDevices) devices have not checked in within the last 90 days." `
                            -Recommendation  'Enable Intune stale device cleanup rules (disable after 90 days, delete after 180 days). Audit hybrid-joined stale devices, as on-premises AD objects may need to be cleaned up separately.' `
                            -AffectedCount   $dm.StaleDevices `
                            -RemediationEffort 'Low' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/devices/manage-stale-devices')
                    ))
            }
        }

        # ── APPLICATIONS ──────────────────────────────────────────────────
        if ($CollectorResults.ContainsKey('Applications') -and
            $CollectorResults['Applications'].Status -eq 'Success') {
            $am = $CollectorResults['Applications'].Metrics
            $ars = $CollectorResults['Applications'].RawSummary

            # ENT-APP-001: Expiring credentials
            if ($am.ExpiringSecrets -gt 0 -or $am.ExpiredSecrets -gt 0) {
                $total = $am.ExpiringSecrets + $am.ExpiredSecrets
                $sev = if ($am.ExpiredSecrets -gt 0) { 'Critical' } elseif ($am.ExpiringSecrets -gt 3) { 'High' } else { 'High' }
                $findings.Add((New-Finding `
                            -FindingId       'ENT-APP-001' `
                            -Domain          'Applications' `
                            -Title           'Application registrations with expiring or expired credentials' `
                            -Severity        $sev `
                            -BusinessImpact  "Application secrets and certificates that expire cause immediate service outages. Expired credentials on critical integrations (ERP, HR, CRM) can halt business operations without warning and require emergency change windows to remediate." `
                            -TechnicalDetail "$($am.ExpiredSecrets) expired and $($am.ExpiringSecrets) expiring within 30 days across $($am.TotalApps) app registrations." `
                            -Recommendation  'Implement a credential expiry monitoring pipeline. Rotate expiring secrets at least 14 days before expiry. Migrate to certificate-based credentials where possible — they are easier to monitor and rotate via automation. Consider Managed Identities to eliminate credential management entirely for Azure-hosted workloads.' `
                            -AffectedCount   $total `
                            -AffectedObjects ($ars.ExpiringSecretsList + $ars.ExpiredSecretsList) `
                            -RemediationEffort 'Medium' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal', 'https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview')
                    ))
            }

            # ENT-APP-002: Owner-less apps
            if ($am.NoOwnerApps -gt 0) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-APP-002' `
                            -Domain          'Applications' `
                            -Title           'Application registrations with no assigned owners' `
                            -Severity        'High' `
                            -BusinessImpact  "Owner-less application registrations have no accountable team to respond to security incidents, rotate credentials, or review permission changes. These become orphaned assets that accumulate permissions over time with no governance oversight." `
                            -TechnicalDetail "$($am.NoOwnerApps) app registrations have no owners assigned." `
                            -Recommendation  'Assign at least two owners (a primary developer and a service owner) to every application registration. Implement a governance policy that prevents new app registrations without a nominated owner. Audit and remediate existing owner-less apps within 60 days.' `
                            -AffectedCount   $am.NoOwnerApps `
                            -AffectedObjects $ars.NoOwnerAppsList `
                            -RemediationEffort 'Medium' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview-assign-app-owners')
                    ))
            }

            # ENT-APP-003: Long-lived secrets
            if ($am.LongLivedCreds -gt 0) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-APP-003' `
                            -Domain          'Applications' `
                            -Title           'Application secrets with lifetime exceeding 180 days' `
                            -Severity        'Medium' `
                            -BusinessImpact  "Long-lived application secrets remain valid for extended periods, giving attackers a wide window to exploit compromised credentials. If a secret is leaked in source code, logs, or configuration files, the impact window is proportionally longer." `
                            -TechnicalDetail "$($am.LongLivedCreds) app registrations have secrets configured with a lifetime greater than 180 days." `
                            -Recommendation  "Enforce a maximum secret lifetime policy of 90 days for all new application registrations. Migrate existing long-lived secrets to shorter durations. Evaluate the use of certificates or Workload Identity Federation as a secret-free alternative." `
                            -AffectedCount   $am.LongLivedCreds `
                            -AffectedObjects $ars.LongLivedCredsList `
                            -RemediationEffort 'Medium' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration')
                    ))
            }
        }

        # ── SERVICE PRINCIPALS ────────────────────────────────────────────
        if ($CollectorResults.ContainsKey('ServicePrincipals') -and
            $CollectorResults['ServicePrincipals'].Status -eq 'Success') {
            $sm = $CollectorResults['ServicePrincipals'].Metrics
            $srs = $CollectorResults['ServicePrincipals'].RawSummary

            # ENT-SPN-001: High-privilege service principals
            if ($sm.HighPrivilegeSPs -gt 0) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-SPN-001' `
                            -Domain          'ServicePrincipals' `
                            -Title           'Service principals with high-privilege Microsoft Graph permissions' `
                            -Severity        'Critical' `
                            -BusinessImpact  "Service principals with permissions such as Directory.ReadWrite.All, User.ReadWrite.All, or AppRoleAssignment.ReadWrite.All can read and modify all users, groups, and applications in the tenant. If these principals are compromised (via secret leak or misconfiguration), an attacker gains near-complete tenant control without needing any user credentials." `
                            -TechnicalDetail "$($sm.HighPrivilegeSPs) enterprise application service principals hold high-privilege Graph application permissions." `
                            -Recommendation  'Review each high-privilege service principal and apply the principle of least privilege — replace broad permissions with the minimal set required. For Microsoft-published integrations, verify the permissions are genuinely necessary. Consider blocking admin consent for high-privilege permissions organisation-wide and requiring individual justification via a consent workflow.' `
                            -AffectedCount   $sm.HighPrivilegeSPs `
                            -AffectedObjects $srs.HighPrivSPList `
                            -RemediationEffort 'High' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-consent-requests', 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-management-policies')
                    ))
            }

            # ENT-SPN-002: Admin-consented OAuth2 grants
            if ($sm.AdminConsentedGrants -gt 10) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-SPN-002' `
                            -Domain          'ServicePrincipals' `
                            -Title           'High number of tenant-wide admin-consented OAuth2 permission grants' `
                            -Severity        'High' `
                            -BusinessImpact  "Admin consent grants apply permissions to all users in the tenant simultaneously. A large number of tenant-wide grants indicates that many third-party or internal applications can access organisational data on behalf of any user, creating a broad data access risk landscape." `
                            -TechnicalDetail "$($sm.AdminConsentedGrants) tenant-wide OAuth2 permission grants (AllPrincipals consent) detected." `
                            -Recommendation  'Audit all tenant-wide consent grants and revoke those for applications no longer in use or where the permissions exceed what is necessary. Implement a Permission Grant Policy to restrict which permissions can be admin-consented without CISO/IT approval.' `
                            -AffectedCount   $sm.AdminConsentedGrants `
                            -RemediationEffort 'High' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-permission-classifications')
                    ))
            }
        }

        # ── MFA ───────────────────────────────────────────────────────────
        if ($CollectorResults.ContainsKey('MFA') -and
            $CollectorResults['MFA'].Status -eq 'Success') {
            $mm = $CollectorResults['MFA'].Metrics

            # ENT-MFA-001: Low MFA registration
            if ($mm.MFARegisteredPercent -lt 90) {
                $sev = if ($mm.MFARegisteredPercent -lt 50) { 'Critical' } else { 'High' }
                $findings.Add((New-Finding `
                            -FindingId       'ENT-MFA-001' `
                            -Domain          'MFA' `
                            -Title           'MFA registration rate below 90%' `
                            -Severity        $sev `
                            -BusinessImpact  "Only $($mm.MFARegisteredPercent)% of users have registered an MFA method. Users without MFA are fully exposed to password-based attacks — credential stuffing, phishing, and password spray — which are the leading cause of identity compromise in enterprise environments. A single compromised non-MFA account can be the entry point for a full tenant breach." `
                            -TechnicalDetail "$($mm.MFARegistered) of $($mm.TotalUsersAssessed) assessed users have MFA registered ($($mm.MFARegisteredPercent)%). Target: ≥ 90%." `
                            -Recommendation  'Launch an MFA registration campaign targeting all non-registered users. Enforce registration via a Conditional Access policy requiring MFA registration completion within 14 days of first sign-in. Prioritise privileged accounts, remote workers, and users with access to sensitive data.' `
                            -AffectedCount   ($mm.TotalUsersAssessed - $mm.MFARegistered) `
                            -RemediationEffort 'Medium' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks', 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-mfa-policy')
                    ))
            }

            # ENT-MFA-002: Low passwordless adoption
            if ($mm.PasswordlessPercent -lt 30) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-MFA-002' `
                            -Domain          'MFA' `
                            -Title           'Passwordless authentication adoption below 30%' `
                            -Severity        'High' `
                            -BusinessImpact  "Only $($mm.PasswordlessPercent)% of users have a passwordless method (Windows Hello, FIDO2, Authenticator app passwordless). Passwordless methods are phishing-resistant and eliminate the risk of password-based attacks entirely. Organisations without meaningful passwordless adoption remain vulnerable to modern phishing techniques that bypass traditional MFA." `
                            -TechnicalDetail "$($mm.PasswordlessCapable) of $($mm.TotalUsersAssessed) users are passwordless-capable ($($mm.PasswordlessPercent)%). Target: ≥ 30%." `
                            -Recommendation  'Define and publish a Passwordless Adoption Roadmap. Begin with Microsoft Authenticator Passwordless Phone Sign-in (lowest friction). Target privileged users and new joiners first. Set a 12-month goal to reach 60% passwordless adoption across the organisation.' `
                            -AffectedCount   ($mm.TotalUsersAssessed - $mm.PasswordlessCapable) `
                            -RemediationEffort 'High' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless')
                    ))
            }

            # ENT-MFA-003: Legacy per-user MFA
            if ($mm.LegacyMFAInUse -eq $true) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-MFA-003' `
                            -Domain          'MFA' `
                            -Title           'Legacy per-user MFA configuration detected' `
                            -Severity        'Medium' `
                            -BusinessImpact  "Legacy per-user MFA (SMS, voice call) provides weaker protection than modern MFA methods and cannot be managed through Conditional Access policies. SMS-based MFA is susceptible to SIM-swapping attacks. Managing MFA at the user level rather than through Conditional Access policies means enforcement is inconsistent and difficult to audit at scale." `
                            -TechnicalDetail "Users with only SMS/call as their registered MFA method were detected. These users are not using modern authentication methods." `
                            -Recommendation  'Migrate all users to modern MFA methods managed through Conditional Access (Microsoft Authenticator, FIDO2 keys, Windows Hello). Disable the legacy per-user MFA portal once all users are migrated to Conditional Access-managed authentication.' `
                            -AffectedCount   0 `
                            -RemediationEffort 'Medium' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates')
                    ))
            }
        }

        # ── CONDITIONAL ACCESS ────────────────────────────────────────────
        if ($CollectorResults.ContainsKey('ConditionalAccess') -and
            $CollectorResults['ConditionalAccess'].Status -eq 'Success') {
            $cm = $CollectorResults['ConditionalAccess'].Metrics

            # ENT-CA-001: No MFA enforcement for all users
            if (-not $cm.MFAEnforcedAllUsers) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-CA-001' `
                            -Domain          'ConditionalAccess' `
                            -Title           'No Conditional Access policy enforcing MFA for all users' `
                            -Severity        'Critical' `
                            -BusinessImpact  "Without a Conditional Access policy that enforces MFA for all users, any account with a compromised password can sign in without any additional challenge. This is the single most impactful control gap in Entra ID security — the majority of identity-related breaches involve accounts without enforced MFA." `
                            -TechnicalDetail "No enabled Conditional Access policy was found that requires MFA for all users across all cloud applications." `
                            -Recommendation  'Create and enable a Conditional Access policy: Assignments → All users (exclude emergency access accounts and service accounts) → All cloud apps → Grant: Require MFA. Test in report-only mode first, then enforce. This is the highest-priority remediation action for Entra ID security.' `
                            -AffectedCount   0 `
                            -RemediationEffort 'Low' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa')
                    ))
            }

            # ENT-CA-002: Only report-only policies
            if ($cm.TotalPolicies -gt 0 -and $cm.EnabledPolicies -eq 0 -and $cm.ReportOnlyPolicies -gt 0) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-CA-002' `
                            -Domain          'ConditionalAccess' `
                            -Title           'All Conditional Access policies are in report-only mode — no enforcement active' `
                            -Severity        'High' `
                            -BusinessImpact  "Report-only policies log what would happen but do not block or enforce any controls. Having zero enforcement means that all access controls are purely advisory — users can access all resources regardless of risk, device compliance, or MFA status." `
                            -TechnicalDetail "$($cm.ReportOnlyPolicies) policies in report-only mode; $($cm.EnabledPolicies) enabled (enforcing). Zero policies are actively enforcing access controls." `
                            -Recommendation  'Review the report-only policies currently deployed. For each policy, analyse the What If simulation results to understand impact before enforcement. Transition the most critical policies (MFA for all users, block legacy auth) to enabled state with a controlled rollout plan.' `
                            -AffectedCount   $cm.ReportOnlyPolicies `
                            -RemediationEffort 'Medium' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only')
                    ))
            }

            # ENT-CA-003: No device compliance policy
            if (-not $cm.DeviceComplianceReq) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-CA-003' `
                            -Domain          'ConditionalAccess' `
                            -Title           'No Conditional Access policy requiring device compliance' `
                            -Severity        'High' `
                            -BusinessImpact  "Without device compliance enforcement in Conditional Access, users can access organisational resources from unmanaged, unpatched, or compromised devices. This bypasses endpoint security controls and enables data access from devices that may be infected with malware or running outdated operating systems." `
                            -TechnicalDetail "No enabled Conditional Access policy was found that grants access only to compliant devices." `
                            -Recommendation  'Implement a Conditional Access policy requiring device compliance for access to sensitive applications (at minimum: Exchange Online, SharePoint, Teams). Ensure Intune device compliance policies are configured before enforcing this control, to avoid locking out legitimate users.' `
                            -AffectedCount   0 `
                            -RemediationEffort 'Medium' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device')
                    ))
            }

            # ENT-CA-004: Legacy authentication not blocked
            if (-not $cm.LegacyAuthBlocked) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-CA-004' `
                            -Domain          'ConditionalAccess' `
                            -Title           'Legacy authentication protocols not blocked' `
                            -Severity        'Critical' `
                            -BusinessImpact  "Legacy authentication protocols (Basic Auth, NTLM, older EAS clients) do not support MFA, making accounts that use them permanently vulnerable to password-based attacks — regardless of MFA policies applied to modern authentication flows. Attackers actively probe for legacy auth endpoints as a bypass route around MFA." `
                            -TechnicalDetail "No enabled Conditional Access policy was found that blocks legacy authentication client app types (exchangeActiveSync, other)." `
                            -Recommendation  "Create and enable a Conditional Access policy: All users → All cloud apps → Client apps: Exchange ActiveSync clients + Other clients → Grant: Block. Monitor the Sign-in logs for 2 weeks using report-only mode first. Identify any legitimate business applications that use legacy auth and migrate them to modern authentication before enforcement." `
                            -AffectedCount   0 `
                            -RemediationEffort 'Low' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication')
                    ))
            }

            # ENT-CA-005: Admin roles not covered
            if (-not $cm.AdminsCovered) {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-CA-005' `
                            -Domain          'ConditionalAccess' `
                            -Title           'Privileged administrator roles not covered by a dedicated Conditional Access policy' `
                            -Severity        'High' `
                            -BusinessImpact  "Administrator accounts require stricter access controls than regular users because a compromised administrator account gives an attacker the ability to escalate privileges, exfiltrate data at scale, disable security controls, or persist in the environment. A dedicated admin CA policy enables stricter MFA requirements, sign-in frequency controls, and network location restrictions for all privileged roles." `
                            -TechnicalDetail "No enabled Conditional Access policy was found that targets specific directory role assignments." `
                            -Recommendation  "Create a separate Conditional Access policy targeting all privileged directory roles (Global Administrator, Security Administrator, Privileged Role Administrator, etc.). Apply stricter controls: require phishing-resistant MFA (FIDO2 or Windows Hello), limit sign-in frequency, and optionally restrict to known corporate networks for break-glass scenarios." `
                            -AffectedCount   0 `
                            -RemediationEffort 'Low' `
                            -References      @('https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa')
                    ))
            }
        }

        # ── PIM ───────────────────────────────────────────────────────────
        if ($CollectorResults.ContainsKey('PIM')) {
            $pc = $CollectorResults['PIM']
            $pm = $pc.Metrics
            $prs = $pc.RawSummary

            # ENT-PIM-005: PIM not licensed (distinguish from configuration gap)
            if ($pc.Status -eq 'LicenseNotAvailable') {
                $findings.Add((New-Finding `
                            -FindingId       'ENT-PIM-005' `
                            -Domain          'PIM' `
                            -Title           'Privileged Identity Management cannot be assessed — licensing limitation' `
                            -Severity        'Informational' `
                            -BusinessImpact  "This tenant does not appear to have the Entra ID P2 or Entra ID Governance licence required for Privileged Identity Management. Without PIM, privileged roles must be assigned permanently rather than on a just-in-time basis, which increases risk exposure. This item is informational — it may reflect a deliberate licensing decision rather than a configuration gap." `
                            -TechnicalDetail "The PIM API returned a licence-related restriction. Assessment of PIM configuration was not possible for this tenant." `
                            -Recommendation  "Evaluate whether Entra ID P2 or Entra ID Governance is appropriate for this tenant, particularly if it hosts privileged accounts or sensitive workloads. If PIM cannot be licensed, implement compensating controls: strict break-glass procedures, frequent admin account reviews, and enhanced sign-in monitoring for all privileged role members." `
                            -AffectedCount   0 `
                            -RemediationEffort 'High' `
                            -References      @('https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals')
                    ))
            }
            elseif ($pc.Status -eq 'Success' -and $pm) {
                # ENT-PIM-001: Permanent GA assignments
                if ($pm.PermanentGlobalAdmins -gt 0) {
                    $sev = if ($pm.PermanentGlobalAdmins -gt 2) { 'Critical' } else { 'Critical' }
                    $findings.Add((New-Finding `
                                -FindingId       'ENT-PIM-001' `
                                -Domain          'PIM' `
                                -Title           'Permanent Global Administrator role assignments detected' `
                                -Severity        $sev `
                                -BusinessImpact  "Global Administrator is the most powerful role in Entra ID. Permanent (non-eligible) GA assignments mean these accounts hold maximum tenant privileges at all times — 24x7, even outside of business hours. A compromised permanent GA account gives an attacker immediate, unrestricted control of the entire tenant with no time limit." `
                                -TechnicalDetail "$($pm.PermanentGlobalAdmins) permanent Global Administrator assignment(s) detected. Best practice: 0 permanent, 2–4 eligible break-glass accounts." `
                                -Recommendation  "Convert all permanent Global Administrator assignments to PIM-eligible assignments. Break-glass accounts are the only exception — maintain 2 permanent GA accounts in a separate Entra ID tenant with hardware MFA, and store credentials in physical safe storage. Require approval and MFA for all GA role activations. Set a maximum activation duration of 4 hours." `
                                -AffectedCount   $pm.PermanentGlobalAdmins `
                                -AffectedObjects $prs.PermanentGlobalAdminList `
                                -RemediationEffort 'Medium' `
                                -References      @('https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure', 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access')
                        ))
                }

                # ENT-PIM-002: Roles without activation approval
                if ($pm.RolesWithNoApproval -gt 0) {
                    $findings.Add((New-Finding `
                                -FindingId       'ENT-PIM-002' `
                                -Domain          'PIM' `
                                -Title           'Privileged roles activatable without approval' `
                                -Severity        'High' `
                                -BusinessImpact  "PIM roles that do not require an approver allow any eligible user to self-activate a privileged role without any human oversight. This removes the four-eyes principle from privileged access, meaning a malicious insider or a compromised eligible account can immediately escalate to a sensitive role." `
                                -TechnicalDetail "$($pm.RolesWithNoApproval) role(s) have no activation approval requirement configured in PIM." `
                                -Recommendation  "Enable approval requirements for all high-impact roles (Global Administrator, Privileged Role Administrator, Security Administrator, Exchange Administrator). Define a group of designated approvers for each role. Consider using an approval workflow that creates an audit trail in your ITSM system." `
                                -AffectedCount   $pm.RolesWithNoApproval `
                                -AffectedObjects $prs.NoApprovalRolesList `
                                -RemediationEffort 'Low' `
                                -References      @('https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-approval-workflow')
                        ))
                }

                # ENT-PIM-003: PIM not configured
                if (-not $pm.PIMConfigured) {
                    $findings.Add((New-Finding `
                                -FindingId       'ENT-PIM-003' `
                                -Domain          'PIM' `
                                -Title           'Privileged Identity Management not configured — no eligible role assignments found' `
                                -Severity        'High' `
                                -BusinessImpact  "Without PIM, all privileged role assignments are permanent. There is no just-in-time access, no approval workflow, no time-limited activation, and no audit trail of who activated which privilege and why. This means privileged accounts are always-on targets with no visibility into whether a privilege was legitimately used." `
                                -TechnicalDetail "Zero eligible role assignments were found. All privileged access is being granted via permanent direct assignment." `
                                -Recommendation  "Implement PIM for all privileged roles as a priority. Begin with Global Administrator and Privileged Role Administrator. Convert permanent assignments to eligible assignments. Establish activation policies (require MFA, set max duration, require justification). Then extend PIM to all other sensitive roles within 90 days." `
                                -AffectedCount   0 `
                                -RemediationEffort 'High' `
                                -References      @('https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-getting-started')
                        ))
                }

                # ENT-PIM-004: High-privilege roles without MFA on activation
                if ($pm.RolesWithoutMFAOnActivation -gt 0) {
                    $findings.Add((New-Finding `
                                -FindingId       'ENT-PIM-004' `
                                -Domain          'PIM' `
                                -Title           'Privileged roles can be activated without MFA verification' `
                                -Severity        'Critical' `
                                -BusinessImpact  "Allowing PIM role activation without MFA means that a stolen session cookie or persistent malware on a user's device could be used to activate a privileged role without any additional challenge. MFA at activation time is the last line of defence against session hijacking being escalated to full privilege compromise." `
                                -TechnicalDetail "$($pm.RolesWithoutMFAOnActivation) role(s) do not require MFA verification at activation time." `
                                -Recommendation  "Require MFA (ideally phishing-resistant MFA: FIDO2 or Windows Hello for Business) for all PIM role activations. Configure this in each role's PIM policy under 'Activation → Multi-factor authentication'. This should be enforced for all roles — not just Global Administrator." `
                                -AffectedCount   $pm.RolesWithoutMFAOnActivation `
                                -AffectedObjects $prs.NoMFARolesList `
                                -RemediationEffort 'Low' `
                                -References      @('https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings')
                        ))
                }
            }
        }

        return $findings.ToArray()
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  LAYER 6 — SCORING ENGINE
    #══════════════════════════════════════════════════════════════════════════

    function Get-MaturityLabel {
        param([int]$Score)
        foreach ($band in $MATURITY_BANDS) {
            if ($Score -ge $band.Min) {
                return [PSCustomObject]@{ Label = $band.Label; Color = $band.Color }
            }
        }
        return [PSCustomObject]@{ Label = 'Poor'; Color = '#f85149' }
    }

    function Invoke-TenantScoring {
        param([array]$Findings)

        $score = 100
        $breakdown = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }

        foreach ($f in $Findings) {
            $sev = $f.Severity
            $breakdown[$sev]++
            $score -= $SEVERITY_PENALTY[$sev]
        }

        # Critical findings hard floor: no more than -60 from Criticals
        # (already accumulated in above loop, but ensure floor is 0)
        $score = [math]::Max(0, $score)

        $maturity = Get-MaturityLabel -Score $score

        return [PSCustomObject]@{
            Score     = $score
            Label     = $maturity.Label
            Color     = $maturity.Color
            Breakdown = $breakdown
        }
    }

    function Invoke-EnterpriseScoring {
        param([array]$TenantResults)

        # Risk-weighted by user population
        $weightedSum = 0.0
        $totalWeight = 0

        foreach ($t in $TenantResults) {
            $userCount = 1   # default weight = 1 if user count unavailable
            if ($t.Domains.ContainsKey('Users') -and
                $t.Domains['Users'].Metrics -and
                $t.Domains['Users'].Metrics.ContainsKey('TotalUsers') -and
                $t.Domains['Users'].Metrics.TotalUsers -gt 0) {
                $userCount = $t.Domains['Users'].Metrics.TotalUsers
            }

            $weightedSum += ($t.Score * $userCount)
            $totalWeight += $userCount
        }

        $entScore = if ($totalWeight -gt 0) {
            [math]::Round($weightedSum / $totalWeight, 0)
        }
        else { 0 }

        $entScore = [int][math]::Max(0, [math]::Min(100, $entScore))
        $maturity = Get-MaturityLabel -Score $entScore

        # Aggregate severity breakdown
        $breakdown = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
        foreach ($t in $TenantResults) {
            foreach ($sev in @($breakdown.Keys)) {
                $breakdown[$sev] += $t.SeverityBreakdown[$sev]
            }
        }

        return [PSCustomObject]@{
            Score     = $entScore
            Label     = $maturity.Label
            Color     = $maturity.Color
            Breakdown = $breakdown
        }
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  LAYER 7 — GRAPH-READY DATA MODEL (Nodes + Edges)
    #══════════════════════════════════════════════════════════════════════════

    function Build-GraphModel {
        param([array]$TenantResults)

        $nodes = [System.Collections.Generic.List[PSCustomObject]]::new()
        $edges = [System.Collections.Generic.List[PSCustomObject]]::new()

        # V1: Tenant and Domain aggregate nodes
        # V2 Extension Point: add User, Group, App, SPN, Role object-level nodes
        foreach ($t in $TenantResults) {
            $tNode = [PSCustomObject]@{
                Id            = "tenant-$($t.TenantId)"
                Type          = 'Tenant'
                Label         = $t.DisplayName
                TenantId      = $t.TenantId
                Score         = $t.Score
                MaturityLabel = $t.MaturityLabel
            }
            $nodes.Add($tNode)

            foreach ($domainKey in $t.Domains.Keys) {
                $dNode = [PSCustomObject]@{
                    Id       = "domain-$($t.TenantId)-$domainKey"
                    Type     = 'Domain'
                    Label    = $domainKey
                    TenantId = $t.TenantId
                    Status   = $t.Domains[$domainKey].Status
                }
                $nodes.Add($dNode)

                $edges.Add([PSCustomObject]@{
                        Source   = "tenant-$($t.TenantId)"
                        Target   = "domain-$($t.TenantId)-$domainKey"
                        Relation = 'Contains'
                    })
            }
        }

        return [PSCustomObject]@{
            Nodes = $nodes.ToArray()
            Edges = $edges.ToArray()
        }
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  LAYER 8 — REPORTING
    #══════════════════════════════════════════════════════════════════════════

    function Export-FindingsCSV {
        param([array]$AllFindings, [string]$FilePath)

        $rows = @($AllFindings | ForEach-Object {
                [PSCustomObject]@{
                    FindingId         = $_.FindingId
                    TenantId          = $_.TenantId
                    TenantName        = $_.TenantName
                    Domain            = $_.Domain
                    Severity          = $_.Severity
                    Title             = $_.Title
                    AffectedCount     = $_.AffectedCount
                    BusinessImpact    = $_.BusinessImpact -replace "`r`n|`n", ' '
                    Recommendation    = $_.Recommendation -replace "`r`n|`n", ' '
                    RemediationEffort = $_.RemediationEffort
                    TechnicalDetail   = $_.TechnicalDetail -replace "`r`n|`n", ' '
                    AffectedObjects   = ($_.AffectedObjects -join '; ')
                    References        = ($_.References -join '; ')
                }
            })

        $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8 -Force
    }

    function Export-MetricsCSV {
        param([array]$TenantResults, [string]$FilePath)

        $rows = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($t in $TenantResults) {
            foreach ($domainKey in $t.Domains.Keys) {
                $dr = $t.Domains[$domainKey]
                $row = [PSCustomObject]@{
                    TenantId      = $t.TenantId
                    TenantName    = $t.DisplayName
                    BusinessUnit  = $t.BusinessUnit
                    TenantScore   = $t.Score
                    MaturityLabel = $t.MaturityLabel
                    Domain        = $domainKey
                    DomainStatus  = $dr.Status
                    CollectedAt   = $dr.CollectedAt.ToString('yyyy-MM-dd HH:mm:ss')
                }

                # Flatten metrics into columns
                foreach ($key in $dr.Metrics.Keys) {
                    $val = $dr.Metrics[$key]
                    if ($val -is [hashtable] -or $val -is [System.Collections.Hashtable]) {
                        $row | Add-Member -NotePropertyName $key -NotePropertyValue ($val | ConvertTo-Json -Compress) -Force
                    }
                    else {
                        $row | Add-Member -NotePropertyName $key -NotePropertyValue $val -Force
                    }
                }

                $rows.Add($row)
            }
        }

        $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8 -Force
    }

    function Export-AssessmentJSON {
        param(
            [PSCustomObject] $EnterpriseScore,
            [array]          $TenantResults,
            [array]          $AllFindings,
            [PSCustomObject] $GraphModel,
            [string]         $FilePath
        )

        $output = [PSCustomObject]@{
            SchemaVersion     = $SCHEMA_VERSION
            AssessmentVersion = $ASSESSMENT_VERSION
            AssessmentId      = $AssessmentId
            GeneratedAt       = $AssessmentTs.ToString('o')
            Enterprise        = [PSCustomObject]@{
                Score             = $EnterpriseScore.Score
                MaturityLabel     = $EnterpriseScore.Label
                TotalTenants      = $TenantResults.Count
                SeverityBreakdown = $EnterpriseScore.Breakdown
            }
            Tenants           = @($TenantResults | ForEach-Object {
                    [PSCustomObject]@{
                        TenantId          = $_.TenantId
                        DisplayName       = $_.DisplayName
                        BusinessUnit      = $_.BusinessUnit
                        AuthMode          = $_.AuthMode
                        Score             = $_.Score
                        MaturityLabel     = $_.MaturityLabel
                        SeverityBreakdown = $_.SeverityBreakdown
                        AssessmentStatus  = $_.AssessmentStatus
                        CollectorErrors   = $_.CollectorErrors
                        Domains           = $_.Domains
                        CapabilityMatrix  = $_.CapabilityMatrix
                    }
                })
            Findings          = @($AllFindings)
            Nodes             = $GraphModel.Nodes
            Edges             = $GraphModel.Edges
            # FUTURE: Historical comparison, LLM narratives, collection schedule
            _future           = [PSCustomObject]@{
                HistoricalBaseline = $null
                DeltaFromBaseline  = $null
                CollectionSchedule = $null
                LLMNarratives      = $null
            }
        }

        $output | ConvertTo-Json -Depth 20 | Out-File -FilePath $FilePath -Encoding UTF8 -Force
    }

    function Export-HTMLDashboard {
        param(
            [PSCustomObject] $EnterpriseScore,
            [array]          $TenantResults,
            [array]          $AllFindings,
            [string]         $FilePath
        )

        $generatedAt = $AssessmentTs.ToString('dddd, dd MMMM yyyy  HH:mm:ss')
        $tenantCount = $TenantResults.Count
        $totalFindings = $AllFindings.Count
        $criticalCount = @($AllFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $highCount = @($AllFindings | Where-Object { $_.Severity -eq 'High' }).Count
        $mediumCount = @($AllFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
        $lowCount = @($AllFindings | Where-Object { $_.Severity -eq 'Low' }).Count

        # Determine arc colour based on enterprise score
        $arcColor = $EnterpriseScore.Color

        # ── Tenant cards JSON ──────────────────────────────────────────────
        $tenantsJson = ($TenantResults | ForEach-Object {
                $t = $_
                $critT = $t.SeverityBreakdown.Critical
                $highT = $t.SeverityBreakdown.High
                $medT = $t.SeverityBreakdown.Medium
                $lowT = $t.SeverityBreakdown.Low

                $domainStatuses = ($t.Domains.Keys | ForEach-Object {
                        $dk = $_
                        $ds = $t.Domains[$dk].Status
                        "{`"domain`":`"$(Write-JsonSafe $dk)`",`"status`":`"$(Write-JsonSafe $ds)`"}"
                    }) -join ','

                $scoreColor = switch ($t.MaturityLabel) {
                    'Strong' { '#3fb950' }
                    'Good' { '#d29922' }
                    'Fair' { '#e09e42' }
                    'Poor' { '#f85149' }
                    default { '#7d8590' }
                }

                $capMatrix = ($t.CapabilityMatrix.Keys | ForEach-Object {
                        $ck = $_
                        $cap = $t.CapabilityMatrix[$ck]
                        "{`"domain`":`"$(Write-JsonSafe $ck)`",`"status`":`"$(Write-JsonSafe $cap.Status)`",`"permission`":`"$(Write-JsonSafe $cap.Permission)`",`"reason`":`"$(Write-JsonSafe ($cap.Reason ?? ''))`"}"
                    }) -join ','

                $dNameSafe = Write-JsonSafe $t.DisplayName
                $buSafe = Write-JsonSafe ($t.BusinessUnit ?? '')
                $idSafe = Write-JsonSafe $t.TenantId
                $statusSafe = Write-JsonSafe $t.AssessmentStatus

                "{`"tenantId`":`"$idSafe`",`"displayName`":`"$dNameSafe`",`"businessUnit`":`"$buSafe`",`"score`":$($t.Score),`"maturity`":`"$(Write-JsonSafe $t.MaturityLabel)`",`"scoreColor`":`"$scoreColor`",`"status`":`"$statusSafe`",`"critical`":$critT,`"high`":$highT,`"medium`":$medT,`"low`":$lowT,`"domains`":[$domainStatuses],`"capabilities`":[$capMatrix]}"
            }) -join ','

        # ── Findings JSON ──────────────────────────────────────────────────
        $findingsJson = ($AllFindings | ForEach-Object {
                $f = $_
                $sevColor = switch ($f.Severity) {
                    'Critical' { '#f85149' }
                    'High' { '#d29922' }
                    'Medium' { '#e09e42' }
                    'Low' { '#3fb950' }
                    'Informational' { '#388bfd' }
                    default { '#7d8590' }
                }
                $affObjs = ($f.AffectedObjects | Select-Object -First 10 | ForEach-Object { "`"$(Write-JsonSafe $_)`"" }) -join ','
                $refs = ($f.References | ForEach-Object { "`"$(Write-JsonSafe $_)`"" }) -join ','

                $fid = Write-JsonSafe $f.FindingId
                $tid = Write-JsonSafe $f.TenantId
                $tname = Write-JsonSafe $f.TenantName
                $dom = Write-JsonSafe $f.Domain
                $sev = Write-JsonSafe $f.Severity
                $title = Write-JsonSafe $f.Title
                $bi = Write-JsonSafe $f.BusinessImpact
                $td = Write-JsonSafe $f.TechnicalDetail
                $rec = Write-JsonSafe $f.Recommendation
                $effort = Write-JsonSafe $f.RemediationEffort

                "{`"findingId`":`"$fid`",`"tenantId`":`"$tid`",`"tenantName`":`"$tname`",`"domain`":`"$dom`",`"severity`":`"$sev`",`"sevColor`":`"$sevColor`",`"title`":`"$title`",`"businessImpact`":`"$bi`",`"technicalDetail`":`"$td`",`"recommendation`":`"$rec`",`"affectedCount`":$($f.AffectedCount),`"remediationEffort`":`"$effort`",`"affectedObjects`":[$affObjs],`"references`":[$refs]}"
            }) -join ','

        # ── Domain coverage JSON for analytics ────────────────────────────
        $domainSummaryJson = ($ALL_DOMAINS | ForEach-Object {
                $dom = $_
                $domFindings = @($AllFindings | Where-Object { $_.Domain -eq $dom })
                $crit = @($domFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
                $high = @($domFindings | Where-Object { $_.Severity -eq 'High' }).Count
                $med = @($domFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
                $low = @($domFindings | Where-Object { $_.Severity -eq 'Low' }).Count
                $domSafe = Write-JsonSafe $dom
                "{`"domain`":`"$domSafe`",`"critical`":$crit,`"high`":$high,`"medium`":$med,`"low`":$low,`"total`":$($domFindings.Count)}"
            }) -join ','

        $entScore = $EnterpriseScore.Score
        $entLabel = $EnterpriseScore.Label
        $entCrit = $EnterpriseScore.Breakdown.Critical
        $entHigh = $EnterpriseScore.Breakdown.High
        $entMed = $EnterpriseScore.Breakdown.Medium
        $entLow = $EnterpriseScore.Breakdown.Low

        # SVG arc math: circumference of r=30 circle = 188.496
        $circ = 188.5
        $arcOffset = [math]::Round($circ - ($circ * $entScore / 100), 2)

        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Entra Multi-Tenant Governance Assessment</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root {
  --bg:#0d1117; --surface:#161b22; --surface2:#1c2333; --surface3:#243048;
  --border:#30363d; --accent:#388bfd; --accent2:#39c5cf; --accent3:#a371f7;
  --green:#3fb950; --amber:#d29922; --red:#f85149; --orange:#e09e42;
  --text:#e6edf3; --muted:#7d8590; --muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px; --radius-sm:6px; --shadow:0 4px 24px rgba(0,0,0,.5);
}
body.light-theme {
  --bg:#f6f8fa; --surface:#fff; --surface2:#f0f3f6; --surface3:#e4e9ef;
  --border:#d0d7de; --accent:#0969da; --accent2:#0284a8; --accent3:#7c3aed;
  --green:#1a7f37; --amber:#b08000; --red:#cf222e; --orange:#b06000;
  --text:#1f2328; --muted:#636c76; --muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}
/* Sidebar */
#sidebar{position:fixed;top:0;left:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:13px;font-weight:700;color:var(--text)}
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
/* Main */
#main{margin-left:236px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:24px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}
/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
/* Stat cards */
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
/* Posture card */
.posture-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 24px;display:flex;align-items:center;gap:24px;margin-bottom:22px;flex-wrap:wrap}
.posture-ring-wrap{position:relative;width:88px;height:88px;flex-shrink:0}
.posture-ring-wrap svg{width:88px;height:88px}
.posture-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.posture-score-num{font-family:var(--mono);font-size:22px;font-weight:700;line-height:1}
.posture-score-sub{font-size:9px;color:var(--muted)}
.posture-info{flex:1;min-width:200px}
.posture-info h3{font-size:16px;font-weight:700;margin-bottom:4px}
.posture-info p{font-size:13px;color:var(--muted2);margin-bottom:10px}
.sev-pill-row{display:flex;gap:7px;flex-wrap:wrap}
.sev-pill{display:inline-flex;align-items:center;gap:5px;padding:4px 11px;border-radius:20px;font-size:12px;font-family:var(--mono);font-weight:600;border:1px solid transparent}
.sev-pill.critical{background:rgba(248,81,73,.15);color:var(--red);border-color:rgba(248,81,73,.3)}
.sev-pill.high{background:rgba(210,153,34,.15);color:var(--amber);border-color:rgba(210,153,34,.3)}
.sev-pill.medium{background:rgba(224,158,66,.12);color:var(--orange);border-color:rgba(224,158,66,.3)}
.sev-pill.low{background:rgba(63,185,80,.12);color:var(--green);border-color:rgba(63,185,80,.3)}
/* Panels */
.section-title{font-size:15px;font-weight:700;margin-bottom:14px;color:var(--text)}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
/* Tenant grid */
.tenant-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-bottom:22px}
.tenant-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;cursor:pointer;transition:border-color .2s,transform .15s,box-shadow .2s}
.tenant-card:hover{border-color:var(--accent);transform:translateY(-2px);box-shadow:0 4px 16px rgba(56,139,253,.12)}
.tc-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.tc-name{font-weight:700;font-size:14px;color:var(--text)}
.tc-bu{font-size:11px;color:var(--muted);margin-top:2px}
.tc-score-badge{font-family:var(--mono);font-size:18px;font-weight:700;line-height:1}
.tc-maturity{font-size:11px;color:var(--muted);text-align:right}
.tc-domains{display:flex;flex-wrap:wrap;gap:5px;margin-top:10px}
.domain-chip{font-size:10px;font-family:var(--mono);padding:2px 7px;border-radius:4px;border:1px solid var(--border)}
.domain-chip.ok{background:rgba(63,185,80,.1);color:var(--green);border-color:rgba(63,185,80,.25)}
.domain-chip.warn{background:rgba(210,153,34,.1);color:var(--amber);border-color:rgba(210,153,34,.25)}
.domain-chip.fail{background:rgba(248,81,73,.1);color:var(--red);border-color:rgba(248,81,73,.25)}
.domain-chip.skip{background:rgba(125,133,144,.1);color:var(--muted);border-color:rgba(125,133,144,.2)}
/* Findings table */
.toolbar{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none}
.search-wrap input{width:100%;padding:8px 11px 8px 34px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;outline:none;transition:border-color .2s}
.search-wrap input:focus{border-color:var(--accent)}
select{padding:8px 11px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:13px;outline:none;cursor:pointer}
select:focus{border-color:var(--accent)}
.findings-table{width:100%;border-collapse:collapse;font-size:13px}
.findings-table th{text-align:left;padding:9px 12px;background:var(--surface2);color:var(--muted2);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;border-bottom:2px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none}
.findings-table th:hover{color:var(--text)}
.findings-table td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
.findings-table tr:hover td{background:var(--surface2)}
.findings-table tr:last-child td{border-bottom:none}
.sev-badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;font-family:var(--mono);font-weight:600}
.sev-critical{background:rgba(248,81,73,.18);color:var(--red)}
.sev-high{background:rgba(210,153,34,.18);color:var(--amber)}
.sev-medium{background:rgba(224,158,66,.15);color:var(--orange)}
.sev-low{background:rgba(63,185,80,.15);color:var(--green)}
.sev-informational{background:rgba(56,139,253,.15);color:var(--accent)}
.finding-title{color:var(--text);font-size:13px}
.finding-title:hover{color:var(--accent);cursor:pointer}
.pagination{display:flex;align-items:center;gap:7px;margin-top:12px;font-size:13px}
.pagination .page-info{color:var(--muted);flex:1}
.page-btn{padding:5px 11px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:12px;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}
/* Domain bar chart */
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.bar-label{font-family:var(--mono);font-size:11px;color:var(--muted2);width:120px;flex-shrink:0}
.bar-track{flex:1;height:10px;background:var(--surface3);border-radius:5px;overflow:hidden}
.bar-fill{height:100%;border-radius:5px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:30px;text-align:right;flex-shrink:0}
/* Capability matrix */
.cap-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;margin-top:10px}
.cap-item{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 12px}
.cap-domain{font-family:var(--mono);font-size:12px;color:var(--text);font-weight:600}
.cap-status{font-size:11px;margin-top:3px}
.cap-ok{color:var(--green)}
.cap-warn{color:var(--amber)}
.cap-fail{color:var(--red)}
.cap-info{color:var(--accent)}
/* Detail drawer */
#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(720px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:26px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
#detailClose{margin-left:auto;background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--red);color:#fff}
#detailContent{flex:1;overflow-y:auto}
.detail-finding-id{font-family:var(--mono);font-size:12px;color:var(--muted);margin-bottom:4px}
.detail-title{font-size:18px;font-weight:700;color:var(--text);margin-bottom:10px;line-height:1.4}
.detail-chip-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 11px;font-size:12px;color:var(--muted2)}
.detail-section{margin-bottom:18px}
.detail-section-title{font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.detail-body{color:var(--muted2);font-size:13.5px;line-height:1.75}
.affected-list{list-style:none;margin-top:7px}
.affected-list li{font-family:var(--mono);font-size:12px;color:var(--accent2);padding:2px 0;display:flex;align-items:center;gap:6px}
.affected-list li::before{content:'›';color:var(--muted)}
.ref-list{list-style:none;margin-top:7px}
.ref-list li a{color:var(--accent);font-size:12.5px;text-decoration:none}
.ref-list li a:hover{text-decoration:underline}
.effort-badge{display:inline-block;padding:2px 9px;border-radius:4px;font-size:11px;font-family:var(--mono)}
.effort-low{background:rgba(63,185,80,.15);color:var(--green)}
.effort-medium{background:rgba(210,153,34,.15);color:var(--amber)}
.effort-high{background:rgba(248,81,73,.15);color:var(--red)}
/* Assessment Info table */
.info-table{width:100%;border-collapse:collapse;font-size:13px}
.info-table th{text-align:left;padding:8px 12px;background:var(--surface2);color:var(--muted2);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;border-bottom:2px solid var(--border)}
.info-table td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
.info-table tr:last-child td{border-bottom:none}
/* Toast */
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}
/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}
/* Responsive */
@media(max-width:768px){#sidebar{transform:translateX(-236px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🏢</div>
    <h1>Entra Governance Assessment</h1>
    <p>Multi-Tenant Security Posture</p>
    <span class="version-badge">v1.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Views</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">📊</span> Enterprise Overview
    </button>
    <button class="nav-btn" onclick="showPage('tenants',this)">
      <span class="nav-icon">🏛</span> Tenant Detail
      <span class="nav-badge">__TENANT_COUNT__</span>
    </button>
    <button class="nav-btn" onclick="showPage('findings',this)">
      <span class="nav-icon">🔍</span> Findings Explorer
      <span class="nav-badge">__TOTAL_FINDINGS__</span>
    </button>
    <button class="nav-btn" onclick="showPage('domains',this)">
      <span class="nav-icon">📈</span> Domain Analysis
    </button>
    <button class="nav-btn" onclick="showPage('info',this)">
      <span class="nav-icon">ℹ</span> Assessment Info
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
    Generated<br>__GENERATED_AT__<br>
    <span style="color:var(--accent2)">⌨</span> <kbd>/</kbd> search &nbsp; <kbd>Esc</kbd> close
  </div>
</nav>

<main id="main">

<!-- ═══════════════════════════════════════════════════
     PAGE: ENTERPRISE OVERVIEW
════════════════════════════════════════════════════ -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Enterprise Security Posture</div>
      <div class="page-subtitle">Unified Entra ID governance view across all assessed tenants</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportFindings()">⬇ Export Findings CSV</button>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">🏛</div><div class="stat-value">__TENANT_COUNT__</div><div class="stat-label">Tenants Assessed</div></div>
    <div class="stat-card c-red"><div class="stat-icon">🔴</div><div class="stat-value" id="critStat">__CRITICAL_COUNT__</div><div class="stat-label">Critical Findings</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">🟡</div><div class="stat-value">__HIGH_COUNT__</div><div class="stat-label">High Findings</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">🟠</div><div class="stat-value">__MEDIUM_COUNT__</div><div class="stat-label">Medium Findings</div></div>
    <div class="stat-card c-green"><div class="stat-icon">🟢</div><div class="stat-value">__LOW_COUNT__</div><div class="stat-label">Low Findings</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">📋</div><div class="stat-value">__TOTAL_FINDINGS__</div><div class="stat-label">Total Findings</div></div>
  </div>

  <div class="posture-card">
    <div class="posture-ring-wrap">
      <svg viewBox="0 0 76 76">
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--surface3)" stroke-width="9"/>
        <circle cx="38" cy="38" r="30" fill="none" stroke="__ARC_COLOR__" stroke-width="9"
          stroke-dasharray="188.5" stroke-dashoffset="188.5" stroke-linecap="round"
          transform="rotate(-90 38 38)" id="postureArc" style="transition:stroke-dashoffset 1.4s ease"/>
      </svg>
      <div class="posture-ring-center">
        <span class="posture-score-num" id="postureNum" style="color:__ARC_COLOR__">__ENT_SCORE__</span>
        <span class="posture-score-sub">/ 100</span>
      </div>
    </div>
    <div class="posture-info">
      <h3>Enterprise Posture Score — <span style="color:__ARC_COLOR__">__ENT_LABEL__</span></h3>
      <p>Risk-weighted across all tenants by user population. Higher-user tenants have greater influence on the enterprise score.</p>
      <div class="sev-pill-row">
        <span class="sev-pill critical">🔴 __ENT_CRIT__ Critical</span>
        <span class="sev-pill high">🟡 __ENT_HIGH__ High</span>
        <span class="sev-pill medium">🟠 __ENT_MED__ Medium</span>
        <span class="sev-pill low">🟢 __ENT_LOW__ Low</span>
      </div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🏛 Tenant Posture Summary</div>
      <div id="tenantBars"></div>
    </div>
    <div class="panel">
      <div class="section-title">⚠️ Top Findings by Risk</div>
      <div id="topFindings"></div>
    </div>
  </div>

  <div class="panel">
    <div class="section-title">🏛 Tenant Cards</div>
    <div class="tenant-grid" id="tenantCards"></div>
  </div>
</section>

<!-- ═══════════════════════════════════════════════════
     PAGE: TENANT DETAIL
════════════════════════════════════════════════════ -->
<section id="page-tenants" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Tenant Detail</div>
      <div class="page-subtitle">Domain breakdown, findings, and capability coverage per tenant</div>
    </div>
    <select id="tenantSelector" onchange="renderTenantDetail()"></select>
  </div>
  <div id="tenantDetailContent"></div>
</section>

<!-- ═══════════════════════════════════════════════════
     PAGE: FINDINGS EXPLORER
════════════════════════════════════════════════════ -->
<section id="page-findings" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Findings Explorer</div>
      <div class="page-subtitle">All findings across all tenants — filter, sort, and drill into each</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportFindings(true)">⬇ Export Filtered CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="findingSearch" placeholder="Search findings… (press / to focus)" oninput="renderFindingsTable()"/>
    </div>
    <select id="sevFilter" onchange="renderFindingsTable()">
      <option value="">All Severities</option>
      <option value="Critical">🔴 Critical</option>
      <option value="High">🟡 High</option>
      <option value="Medium">🟠 Medium</option>
      <option value="Low">🟢 Low</option>
      <option value="Informational">🔵 Informational</option>
    </select>
    <select id="domainFilter" onchange="renderFindingsTable()">
      <option value="">All Domains</option>
      <option>Users</option><option>Groups</option><option>Devices</option>
      <option>Applications</option><option>ServicePrincipals</option>
      <option>MFA</option><option>ConditionalAccess</option><option>PIM</option>
    </select>
    <select id="tenantFilter" onchange="renderFindingsTable()">
      <option value="">All Tenants</option>
    </select>
  </div>
  <table class="findings-table" id="findingsTable">
    <thead>
      <tr>
        <th onclick="sortFindings('severity')">Severity ⇅</th>
        <th onclick="sortFindings('domain')">Domain ⇅</th>
        <th onclick="sortFindings('title')">Finding ⇅</th>
        <th onclick="sortFindings('tenantName')">Tenant ⇅</th>
        <th onclick="sortFindings('affectedCount')">Affected ⇅</th>
        <th>Effort</th>
      </tr>
    </thead>
    <tbody id="findingsBody"></tbody>
  </table>
  <div class="pagination" id="findingsPagination"></div>
</section>

<!-- ═══════════════════════════════════════════════════
     PAGE: DOMAIN ANALYSIS
════════════════════════════════════════════════════ -->
<section id="page-domains" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Domain Analysis</div>
      <div class="page-subtitle">Findings distribution and risk exposure by assessment domain</div>
    </div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Findings by Domain</div>
      <div id="domainBars"></div>
    </div>
    <div class="panel">
      <div class="section-title">🎯 Domain Risk Heatmap</div>
      <div id="domainHeatmap"></div>
    </div>
  </div>
</section>

<!-- ═══════════════════════════════════════════════════
     PAGE: ASSESSMENT INFO
════════════════════════════════════════════════════ -->
<section id="page-info" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Assessment Information</div>
      <div class="page-subtitle">Authentication modes, collector status, and Graph permissions used</div>
    </div>
  </div>
  <div class="panel">
    <div class="section-title">📋 Assessment Summary</div>
    <table class="info-table">
      <tr><th>Field</th><th>Value</th></tr>
      <tr><td>Assessment ID</td><td style="font-family:var(--mono);font-size:12px">__ASSESSMENT_ID__</td></tr>
      <tr><td>Generated At</td><td>__GENERATED_AT__</td></tr>
      <tr><td>Schema Version</td><td style="font-family:var(--mono)">__SCHEMA_VERSION__</td></tr>
      <tr><td>Assessment Version</td><td style="font-family:var(--mono)">__ASSESSMENT_VERSION__</td></tr>
      <tr><td>Tenants Assessed</td><td>__TENANT_COUNT__</td></tr>
      <tr><td>Total Findings</td><td>__TOTAL_FINDINGS__</td></tr>
    </table>
  </div>
  <div class="panel">
    <div class="section-title">🔑 Tenant Authentication &amp; Collector Status</div>
    <div id="tenantInfoTable"></div>
  </div>
</section>

</main>

<!-- Detail Drawer -->
<div id="detailPanel" onclick="if(event.target===this||event.target.id==='detailBackdrop')closeDetail()">
  <div id="detailBackdrop"></div>
  <div id="detailDrawer">
    <div class="detail-toolbar">
      <button class="btn" onclick="navigateDetail(-1)" id="detailPrevBtn">← Prev</button>
      <button class="btn" onclick="navigateDetail(1)"  id="detailNextBtn">Next →</button>
      <button id="detailClose" onclick="closeDetail()">✕</button>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<div id="toast"><span id="toastIcon">✓</span><span id="toastMsg"></span></div>

<script>
// ── Data ──
const TENANTS  = [__TENANTS_JSON__];
const FINDINGS = [__FINDINGS_JSON__];
const DOMAINS_SUMMARY = [__DOMAIN_SUMMARY_JSON__];

// ── Navigation ──
function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  if (btn) btn.classList.add('active');
  if (id === 'findings') renderFindingsTable();
}

function toggleTheme() {
  const light = document.body.classList.toggle('light-theme');
  document.getElementById('themeIcon').textContent  = light ? '☀️' : '🌙';
  document.getElementById('themeLabel').textContent = light ? 'Light Mode' : 'Dark Mode';
}

// ── Utils ──
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
function sevClass(s){return({Critical:'sev-critical',High:'sev-high',Medium:'sev-medium',Low:'sev-low',Informational:'sev-informational'})[s]||'sev-informational';}
function effortClass(e){return({Low:'effort-low',Medium:'effort-medium',High:'effort-high'})[e]||'effort-medium';}
function domainChipClass(s){if(s==='Success')return 'ok';if(s==='PartialSuccess')return 'warn';if(['Failed','PermissionDenied'].includes(s))return 'fail';return 'skip';}
function showToast(msg,icon='✓'){document.getElementById('toastMsg').textContent=msg;document.getElementById('toastIcon').textContent=icon;const t=document.getElementById('toast');t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800);}
function dlFile(content,name,type){const b=new Blob([content],{type});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=name;a.click();URL.revokeObjectURL(u);}

// ── Enterprise Overview ──
(function initOverview(){
  // Tenant bars
  const sorted = [...TENANTS].sort((a,b)=>a.score-b.score);
  const maxScore = 100;
  document.getElementById('tenantBars').innerHTML = sorted.map(t =>
    `<div class="bar-row">
       <div class="bar-label" title="${escH(t.displayName)}">${escH(t.displayName.length>18?t.displayName.substring(0,18)+'…':t.displayName)}</div>
       <div class="bar-track"><div class="bar-fill" style="width:0%;background:${escH(t.scoreColor)}" data-pct="${t.score}"></div></div>
       <div class="bar-count" style="color:${escH(t.scoreColor)}">${t.score}</div>
     </div>`
  ).join('');

  // Tenant cards
  document.getElementById('tenantCards').innerHTML = TENANTS.map(t =>
    `<div class="tenant-card" onclick="openTenantDetail('${escJ(t.tenantId)}')">
       <div class="tc-header">
         <div><div class="tc-name">${escH(t.displayName)}</div><div class="tc-bu">${escH(t.businessUnit||'')}</div></div>
         <div style="text-align:right">
           <div class="tc-score-badge" style="color:${escH(t.scoreColor)}">${t.score}</div>
           <div class="tc-maturity" style="color:${escH(t.scoreColor)}">${escH(t.maturity)}</div>
         </div>
       </div>
       <div class="sev-pill-row" style="font-size:11px">
         ${t.critical>0?`<span class="sev-pill critical">${t.critical} Crit</span>`:''}
         ${t.high>0?`<span class="sev-pill high">${t.high} High</span>`:''}
         ${t.medium>0?`<span class="sev-pill medium">${t.medium} Med</span>`:''}
       </div>
       <div class="tc-domains">
         ${t.domains.map(d=>`<span class="domain-chip ${domainChipClass(d.status)}" title="${escH(d.domain+': '+d.status)}">${escH(d.domain)}</span>`).join('')}
       </div>
     </div>`
  ).join('');

  // Top findings (Critical first, then High)
  const topF = [...FINDINGS].filter(f=>['Critical','High'].includes(f.severity))
    .sort((a,b)=>{ const o={'Critical':0,'High':1}; return o[a.severity]-o[b.severity]||a.title.localeCompare(b.title); })
    .slice(0,8);

  document.getElementById('topFindings').innerHTML = topF.map((f,i) =>
    `<div style="display:flex;align-items:flex-start;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);cursor:pointer" onclick="openFindingDetail(${FINDINGS.indexOf(f)})">
       <span class="sev-badge ${sevClass(f.severity)}" style="flex-shrink:0;margin-top:1px">${escH(f.severity)}</span>
       <div>
         <div style="font-size:13px;color:var(--text)">${escH(f.title)}</div>
         <div style="font-size:11px;color:var(--muted);margin-top:2px">${escH(f.tenantName)} · ${escH(f.domain)}</div>
       </div>
     </div>`
  ).join('') || '<div style="color:var(--muted);font-size:13px;padding:12px 0">No Critical or High findings. 🎉</div>';

  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';});
    const arc=document.getElementById('postureArc');
    if(arc){ arc.style.strokeDashoffset='__ARC_OFFSET__'; }
  });
})();

// ── Tenant Detail page ──
const tenantSelector = document.getElementById('tenantSelector');
TENANTS.forEach(t=>{
  const opt=document.createElement('option');
  opt.value=t.tenantId; opt.textContent=t.displayName;
  tenantSelector.appendChild(opt);
});

function openTenantDetail(tenantId) {
  showPage('tenants', document.querySelector('.nav-btn:nth-child(2)'));
  tenantSelector.value = tenantId;
  renderTenantDetail();
}

function renderTenantDetail() {
  const tid = tenantSelector.value;
  const t   = TENANTS.find(x=>x.tenantId===tid);
  if (!t) { document.getElementById('tenantDetailContent').innerHTML='<p style="color:var(--muted)">Select a tenant above.</p>'; return; }

  const tFindings = FINDINGS.filter(f=>f.tenantId===tid);
  const crit = tFindings.filter(f=>f.severity==='Critical').length;
  const high = tFindings.filter(f=>f.severity==='High').length;

  const capRows = t.capabilities.map(c=> {
    const cls = c.status==='Available'?'cap-ok':c.status==='LicenseRequired'?'cap-warn':'cap-fail';
    const icon = c.status==='Available'?'✅':c.status==='LicenseRequired'?'🔑':c.status==='PermissionNotGranted'?'🔒':'⚠️';
    return `<div class="cap-item">
      <div class="cap-domain">${escH(c.domain)}</div>
      <div class="cap-status ${cls}">${icon} ${escH(c.status)}</div>
      ${c.reason?`<div style="font-size:10px;color:var(--muted);margin-top:3px">${escH(c.reason)}</div>`:''}
    </div>`;
  }).join('');

  const findRows = tFindings.map((f,i) =>
    `<tr onclick="openFindingDetail(${FINDINGS.indexOf(f)})" style="cursor:pointer">
       <td><span class="sev-badge ${sevClass(f.severity)}">${escH(f.severity)}</span></td>
       <td style="font-family:var(--mono);font-size:12px;color:var(--muted2)">${escH(f.domain)}</td>
       <td class="finding-title">${escH(f.title)}</td>
       <td>${f.affectedCount>0?`<span style="font-family:var(--mono);font-size:12px">${f.affectedCount}</span>`:'-'}</td>
     </tr>`
  ).join('');

  document.getElementById('tenantDetailContent').innerHTML = `
    <div class="posture-card" style="margin-bottom:18px">
      <div class="posture-ring-wrap" style="width:68px;height:68px">
        <svg viewBox="0 0 76 76"><circle cx="38" cy="38" r="30" fill="none" stroke="var(--surface3)" stroke-width="9"/>
        <circle cx="38" cy="38" r="30" fill="none" stroke="${escH(t.scoreColor)}" stroke-width="9"
          stroke-dasharray="188.5" stroke-dashoffset="${188.5-(188.5*t.score/100)}" stroke-linecap="round"
          transform="rotate(-90 38 38)"/></svg>
        <div class="posture-ring-center"><span class="posture-score-num" style="color:${escH(t.scoreColor)};font-size:17px">${t.score}</span><span class="posture-score-sub">/ 100</span></div>
      </div>
      <div class="posture-info">
        <h3>${escH(t.displayName)} — <span style="color:${escH(t.scoreColor)}">${escH(t.maturity)}</span></h3>
        <p style="font-family:var(--mono);font-size:11px;color:var(--muted)">${escH(t.tenantId)} · ${escH(t.businessUnit||'')}</p>
        <div class="sev-pill-row">
          <span class="sev-pill critical">🔴 ${t.critical} Critical</span>
          <span class="sev-pill high">🟡 ${t.high} High</span>
          <span class="sev-pill medium">🟠 ${t.medium} Medium</span>
          <span class="sev-pill low">🟢 ${t.low} Low</span>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="section-title">🔍 Capability Coverage</div>
      <div class="cap-grid">${capRows}</div>
    </div>
    <div class="panel">
      <div class="section-title">⚠️ Findings (${tFindings.length})</div>
      <table class="findings-table"><thead><tr><th>Severity</th><th>Domain</th><th>Finding</th><th>Affected</th></tr></thead>
      <tbody>${findRows||'<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:18px">No findings for this tenant.</td></tr>'}</tbody></table>
    </div>`;
}

// ── Findings Explorer ──
let filteredFindings = [...FINDINGS];
let findingsSort     = { key: 'severity', dir: 1 };
let findingsPage     = 1;
const PAGE_SIZE      = 20;
const SEV_ORDER      = { Critical:0, High:1, Medium:2, Low:3, Informational:4 };

// Populate tenant filter
const tenantFilterEl = document.getElementById('tenantFilter');
TENANTS.forEach(t=>{ const o=document.createElement('option'); o.value=t.tenantId; o.textContent=t.displayName; tenantFilterEl.appendChild(o); });

function sortFindings(key) {
  if (findingsSort.key===key) findingsSort.dir*=-1; else { findingsSort.key=key; findingsSort.dir=1; }
  renderFindingsTable();
}

function renderFindingsTable() {
  const q   = (document.getElementById('findingSearch').value||'').toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  const dom = document.getElementById('domainFilter').value;
  const tid = document.getElementById('tenantFilter').value;

  filteredFindings = FINDINGS.filter(f=> {
    if (sev && f.severity!==sev) return false;
    if (dom && f.domain!==dom)   return false;
    if (tid && f.tenantId!==tid) return false;
    if (q && !( f.title.toLowerCase().includes(q) ||
                f.tenantName.toLowerCase().includes(q) ||
                f.domain.toLowerCase().includes(q) ||
                f.findingId.toLowerCase().includes(q) ||
                f.businessImpact.toLowerCase().includes(q))) return false;
    return true;
  });

  // Sort
  filteredFindings.sort((a,b)=>{
    let av=a[findingsSort.key], bv=b[findingsSort.key];
    if (findingsSort.key==='severity') { av=SEV_ORDER[av]??5; bv=SEV_ORDER[bv]??5; }
    if (typeof av==='number') return findingsSort.dir*(av-bv);
    return findingsSort.dir*String(av||'').localeCompare(String(bv||''));
  });

  // Paginate
  const total = filteredFindings.length;
  const pages = Math.max(1, Math.ceil(total/PAGE_SIZE));
  findingsPage = Math.min(findingsPage, pages);
  const slice  = filteredFindings.slice((findingsPage-1)*PAGE_SIZE, findingsPage*PAGE_SIZE);

  document.getElementById('findingsBody').innerHTML = slice.map((f,i)=>
    `<tr onclick="openFindingDetail(${FINDINGS.indexOf(f)})" style="cursor:pointer">
       <td><span class="sev-badge ${sevClass(f.severity)}">${escH(f.severity)}</span></td>
       <td style="font-family:var(--mono);font-size:12px;color:var(--muted2)">${escH(f.domain)}</td>
       <td><span class="finding-title">${escH(f.title)}</span><br><span style="font-size:11px;color:var(--muted)">${escH(f.findingId)}</span></td>
       <td style="font-size:12px;color:var(--muted2)">${escH(f.tenantName)}</td>
       <td style="font-family:var(--mono);font-size:12px">${f.affectedCount>0?f.affectedCount:'-'}</td>
       <td><span class="effort-badge ${effortClass(f.remediationEffort)}">${escH(f.remediationEffort)}</span></td>
     </tr>`
  ).join('') || '<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:18px">No findings match the current filters.</td></tr>';

  // Pagination
  const pEl = document.getElementById('findingsPagination');
  if (pages<=1) { pEl.innerHTML=''; return; }
  let btns=`<span class="page-info">Showing ${(findingsPage-1)*PAGE_SIZE+1}–${Math.min(findingsPage*PAGE_SIZE,total)} of ${total}</span>`;
  btns+=`<button class="page-btn" onclick="changeFPage(${findingsPage-1})" ${findingsPage===1?'disabled':''}>← Prev</button>`;
  for(let p=Math.max(1,findingsPage-2);p<=Math.min(pages,findingsPage+2);p++){
    btns+=`<button class="page-btn ${p===findingsPage?'active':''}" onclick="changeFPage(${p})">${p}</button>`;
  }
  btns+=`<button class="page-btn" onclick="changeFPage(${findingsPage+1})" ${findingsPage===pages?'disabled':''}>Next →</button>`;
  pEl.innerHTML=btns;
}

function changeFPage(p){ findingsPage=p; renderFindingsTable(); }

// ── Domain Analysis ──
(function initDomains(){
  const maxTotal = Math.max(...DOMAINS_SUMMARY.map(d=>d.total), 1);
  document.getElementById('domainBars').innerHTML = DOMAINS_SUMMARY.map(d=>
    `<div class="bar-row">
       <div class="bar-label">${escH(d.domain)}</div>
       <div class="bar-track"><div class="bar-fill" style="width:0%;background:${d.critical>0?'var(--red)':d.high>0?'var(--amber)':'var(--green)'}" data-pct="${Math.round((d.total/maxTotal)*100)}"></div></div>
       <div class="bar-count">${d.total}</div>
     </div>`
  ).join('');

  document.getElementById('domainHeatmap').innerHTML =
    '<table style="width:100%;border-collapse:collapse;font-size:12px">' +
    '<thead><tr><th style="text-align:left;padding:6px 8px;color:var(--muted);font-size:11px;text-transform:uppercase">Domain</th>' +
    '<th style="padding:6px 8px;color:var(--red);font-size:11px">Critical</th>' +
    '<th style="padding:6px 8px;color:var(--amber);font-size:11px">High</th>' +
    '<th style="padding:6px 8px;color:var(--orange);font-size:11px">Medium</th>' +
    '<th style="padding:6px 8px;color:var(--green);font-size:11px">Low</th></tr></thead><tbody>' +
    DOMAINS_SUMMARY.map(d=>{
      const bg = d.critical>0?'rgba(248,81,73,.08)':d.high>0?'rgba(210,153,34,.08)':'';
      return `<tr style="background:${bg}">
        <td style="padding:6px 8px;font-family:var(--mono)">${escH(d.domain)}</td>
        <td style="text-align:center;padding:6px 8px;color:var(--red);font-family:var(--mono)">${d.critical||'-'}</td>
        <td style="text-align:center;padding:6px 8px;color:var(--amber);font-family:var(--mono)">${d.high||'-'}</td>
        <td style="text-align:center;padding:6px 8px;color:var(--orange);font-family:var(--mono)">${d.medium||'-'}</td>
        <td style="text-align:center;padding:6px 8px;color:var(--green);font-family:var(--mono)">${d.low||'-'}</td>
      </tr>`;
    }).join('') + '</tbody></table>';

  requestAnimationFrame(()=>{
    document.querySelectorAll('#page-domains .bar-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';});
  });
})();

// ── Assessment Info ──
(function initInfo(){
  document.getElementById('tenantInfoTable').innerHTML =
    '<table class="info-table"><thead><tr><th>Tenant</th><th>Auth Mode</th><th>Status</th><th>Collector Errors</th></tr></thead><tbody>' +
    TENANTS.map(t=>
      `<tr><td>${escH(t.displayName)}<br><span style="font-family:var(--mono);font-size:10px;color:var(--muted)">${escH(t.tenantId)}</span></td>` +
      `<td style="font-family:var(--mono);font-size:12px">${escH(t.businessUnit||'')}</td>` +
      `<td><span style="color:${t.status==='Completed'?'var(--green)':t.status==='PartialSuccess'?'var(--amber)':'var(--red)'}">${escH(t.status)}</span></td>` +
      `<td style="font-size:12px;color:var(--muted)">${t.domains.filter(d=>['Failed','PermissionDenied'].includes(d.status)).map(d=>escH(d.domain)).join(', ')||'None'}</td></tr>`
    ).join('') + '</tbody></table>';
})();

// ── Detail Drawer ──
let currentDetailIndex = -1;
let detailList         = FINDINGS;

function openFindingDetail(idx) {
  detailList = filteredFindings.length > 0 ? filteredFindings : FINDINGS;
  const finding = FINDINGS[idx];
  if (!finding) return;
  currentDetailIndex = detailList.indexOf(finding);
  if (currentDetailIndex < 0) { currentDetailIndex = 0; detailList = FINDINGS; }
  _renderDetail(finding);
}

function navigateDetail(dir) {
  const ni = currentDetailIndex + dir;
  if (ni < 0 || ni >= detailList.length) return;
  currentDetailIndex = ni;
  _renderDetail(detailList[ni]);
}

function _renderDetail(f) {
  document.getElementById('detailPrevBtn').disabled = currentDetailIndex <= 0;
  document.getElementById('detailNextBtn').disabled = currentDetailIndex >= detailList.length - 1;

  const affHtml = f.affectedObjects && f.affectedObjects.length > 0
    ? '<ul class="affected-list">' + f.affectedObjects.map(o=>`<li>${escH(o)}</li>`).join('') + '</ul>'
    : '<span style="color:var(--muted);font-size:12px">No specific objects listed.</span>';

  const refHtml = f.references && f.references.length > 0
    ? '<ul class="ref-list">' + f.references.map(r=>`<li><a href="${escH(r)}" target="_blank" rel="noopener">${escH(r)}</a></li>`).join('') + '</ul>'
    : '';

  document.getElementById('detailContent').innerHTML = `
    <div class="detail-finding-id">${escH(f.findingId)}</div>
    <div class="detail-title">${escH(f.title)}</div>
    <div class="detail-chip-row">
      <span class="sev-badge ${sevClass(f.severity)}" style="padding:4px 13px;font-size:12px">${escH(f.severity)}</span>
      <span class="detail-chip">📁 ${escH(f.domain)}</span>
      <span class="detail-chip">🏛 ${escH(f.tenantName)}</span>
      ${f.affectedCount>0?`<span class="detail-chip">👤 ${f.affectedCount} affected</span>`:''}
      <span class="effort-badge ${effortClass(f.remediationEffort)}" style="padding:4px 11px">⚙ ${escH(f.remediationEffort)} effort</span>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Business Impact</div>
      <div class="detail-body">${escH(f.businessImpact)}</div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Technical Detail</div>
      <div class="detail-body">${escH(f.technicalDetail)}</div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Recommendation</div>
      <div class="detail-body">${escH(f.recommendation)}</div>
    </div>
    ${f.affectedObjects&&f.affectedObjects.length>0?`<div class="detail-section"><div class="detail-section-title">Affected Objects</div>${affHtml}</div>`:''}
    ${refHtml?`<div class="detail-section"><div class="detail-section-title">References</div>${refHtml}</div>`:''}`;

  document.getElementById('detailPanel').classList.add('open');
  document.body.style.overflow = 'hidden';
  document.getElementById('detailContent').scrollTo(0,0);
}

function closeDetail() {
  document.getElementById('detailPanel').classList.remove('open');
  document.body.style.overflow = '';
}

// ── Export ──
function exportFindings(filtered) {
  const data = filtered ? filteredFindings : FINDINGS;
  const esc  = v => `"${String(v||'').replace(/"/g,'""')}"`;
  const rows = data.map(f=>[
    esc(f.findingId), esc(f.tenantId), esc(f.tenantName), esc(f.domain),
    esc(f.severity), esc(f.title), f.affectedCount,
    esc(f.businessImpact), esc(f.recommendation), esc(f.remediationEffort),
    esc(f.technicalDetail), esc((f.affectedObjects||[]).join('; ')), esc((f.references||[]).join('; '))
  ].join(','));
  dlFile(
    ['FindingId,TenantId,TenantName,Domain,Severity,Title,AffectedCount,BusinessImpact,Recommendation,RemediationEffort,TechnicalDetail,AffectedObjects,References',...rows].join('\r\n'),
    'EntraGovernance_Findings.csv', 'text/csv'
  );
  showToast(`Exported ${data.length} findings as CSV`);
}

// ── Keyboard shortcuts ──
document.addEventListener('keydown', e => {
  if (e.key==='Escape') { closeDetail(); return; }
  if (e.key==='/' && document.activeElement.tagName!=='INPUT') {
    e.preventDefault();
    const inp = document.querySelector('.page.active input[type=text]');
    if (inp) inp.focus();
  }
  if (document.getElementById('detailPanel').classList.contains('open')) {
    if (e.key==='ArrowLeft')  navigateDetail(-1);
    if (e.key==='ArrowRight') navigateDetail(1);
  }
});
</script>
</body>
</html>
'@

        $html = $html `
            -replace '__TENANT_COUNT__', $tenantCount `
            -replace '__TOTAL_FINDINGS__', $totalFindings `
            -replace '__CRITICAL_COUNT__', $criticalCount `
            -replace '__HIGH_COUNT__', $highCount `
            -replace '__MEDIUM_COUNT__', $mediumCount `
            -replace '__LOW_COUNT__', $lowCount `
            -replace '__ENT_SCORE__', $entScore `
            -replace '__ENT_LABEL__', $entLabel `
            -replace '__ENT_CRIT__', $entCrit `
            -replace '__ENT_HIGH__', $entHigh `
            -replace '__ENT_MED__', $entMed `
            -replace '__ENT_LOW__', $entLow `
            -replace '__ARC_COLOR__', $arcColor `
            -replace '__ARC_OFFSET__', $arcOffset `
            -replace '__GENERATED_AT__', $generatedAt `
            -replace '__ASSESSMENT_ID__', $AssessmentId `
            -replace '__SCHEMA_VERSION__', $SCHEMA_VERSION `
            -replace '__ASSESSMENT_VERSION__', $ASSESSMENT_VERSION `
            -replace '__TENANTS_JSON__', $tenantsJson `
            -replace '__FINDINGS_JSON__', $findingsJson `
            -replace '__DOMAIN_SUMMARY_JSON__', $domainSummaryJson

        $html | Out-File -FilePath $FilePath -Encoding UTF8 -Force
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  ORCHESTRATION — BEGIN BLOCK
    #══════════════════════════════════════════════════════════════════════════

    Write-Banner

    # ── Resolve output directory ───────────────────────────────────────────
    $outputDir = $OutputPath.TrimEnd('\', '/')
    if (-not (Test-Path $outputDir -PathType Container)) {
        try { New-Item -Path $outputDir -ItemType Directory -Force | Out-Null }
        catch { throw "Cannot create output directory '$outputDir': $_" }
    }

    $runFolder = Join-Path $outputDir "EntraMultiTenantGovernance_$TimestampSlug"
    New-Item -Path $runFolder -ItemType Directory -Force | Out-Null

    $outFindingsCSV = Join-Path $runFolder "Get-EntraMultiTenantGovernanceAssessment_Findings_$TimestampSlug.csv"
    $outMetricsCSV = Join-Path $runFolder "Get-EntraMultiTenantGovernanceAssessment_Metrics_$TimestampSlug.csv"
    $outJSON = Join-Path $runFolder "Get-EntraMultiTenantGovernanceAssessment_$TimestampSlug.json"
    $outHTML = Join-Path $runFolder "Get-EntraMultiTenantGovernanceAssessment_$TimestampSlug.html"

    # ── Resolve tenant list and domain scope ───────────────────────────────
    Write-SectionHeader -Text 'Resolving Configuration' -Icon '⚙'

    $resolvedConfigPath = if ($PSCmdlet.ParameterSetName -eq 'ConfigFile') { $TenantConfigPath } else { $null }
    $resolvedInlineTenants = if ($PSCmdlet.ParameterSetName -eq 'InlineObjects') { $Tenants } else { $null }

    $resolvedTenants = Resolve-TenantList `
        -ConfigPath    $resolvedConfigPath `
        -InlineTenants $resolvedInlineTenants `
        -ExcludeIds    $ExcludeTenantIds

    $activeDomains = Resolve-ActiveDomains -Include $IncludeDomains -Exclude $ExcludeDomains

    Write-Host "  ✅  Tenants resolved   : $($resolvedTenants.Count)" -ForegroundColor Green
    Write-Host "  ✅  Domains active     : $($activeDomains -join ', ')" -ForegroundColor Green
    Write-Host "  📁  Output folder      : $runFolder" -ForegroundColor Cyan
    Write-Host ''

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  ORCHESTRATION — TENANT LOOP
    #══════════════════════════════════════════════════════════════════════════

    Write-SectionHeader -Text 'Assessing Tenants' -Icon '🏛'

    $allTenantResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $tenantIndex = 0

    foreach ($tenantCfg in $resolvedTenants) {
        $tenantIndex++
        Write-TenantHeader `
            -Name     $tenantCfg.DisplayName `
            -TenantId $tenantCfg.TenantId `
            -Index    $tenantIndex `
            -Total    $resolvedTenants.Count

        $tenantResult = [PSCustomObject]@{
            TenantId          = $tenantCfg.TenantId
            DisplayName       = $tenantCfg.DisplayName
            BusinessUnit      = $tenantCfg.BusinessUnit ?? ''
            AuthMode          = $tenantCfg.AuthMode
            Score             = 0
            MaturityLabel     = 'Poor'
            SeverityBreakdown = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Informational = 0 }
            AssessmentStatus  = 'Pending'
            CollectorErrors   = [System.Collections.Generic.List[string]]::new()
            Domains           = @{}
            CapabilityMatrix  = @{}
            Findings          = @()
        }

        # ── LAYER 2: Authenticate ──────────────────────────────────────────
        Write-Host "  │  🔑  Authenticating ($($tenantCfg.AuthMode))..." -ForegroundColor DarkGray
        $tokenResult = Invoke-TenantTokenProvider -TenantConfig $tenantCfg

        if ($tokenResult.Error) {
            Write-Host "  └─ ❌  Authentication failed: $($tokenResult.Error)" -ForegroundColor Red
            $tenantResult.AssessmentStatus = 'AuthenticationFailed'
            $tenantResult.CollectorErrors.Add("Authentication: $($tokenResult.Error)")
            $allTenantResults.Add($tenantResult)
            continue
        }

        $headers = New-GraphHeaders -AccessToken $tokenResult.AccessToken

        # ── LAYER 3: Capability Pre-flight ─────────────────────────────────
        Write-Host "  │  🔍  Running capability pre-flight..." -ForegroundColor DarkGray
        $capabilities = @{}
        try {
            $capabilities = Invoke-CapabilityPreflight `
                -Headers       $headers `
                -TenantId      $tenantCfg.TenantId `
                -ActiveDomains $activeDomains
        }
        catch {
            Write-Host "  │  ⚠️   Pre-flight probe failed (non-fatal): $_" -ForegroundColor Yellow
        }

        $tenantResult.CapabilityMatrix = $capabilities

        # Log capability summary
        foreach ($domain in $activeDomains) {
            $cap = if ($capabilities.ContainsKey($domain)) { $capabilities[$domain] } else { $null }
            $capStatus = if ($cap) { $cap.Status } else { 'Unknown' }
            $indicator = switch ($capStatus) {
                'Available' { '✅' }
                'LicenseRequired' { '🔑' }
                'PermissionNotGranted' { '🔒' }
                default { '⚠️ ' }
            }
            Write-Host "  │  $indicator  $($domain.PadRight(20))  $capStatus" -ForegroundColor DarkGray
        }

        # ── LAYER 4: Run Domain Collectors ─────────────────────────────────
        Write-Host "  │" -ForegroundColor DarkGray
        Write-Host "  │  📡  Running collectors..." -ForegroundColor DarkGray

        $collectorMap = @{
            'Users'             = { param($h, $cap) Invoke-UsersCollector             -Headers $h }
            'Groups'            = { param($h, $cap) Invoke-GroupsCollector            -Headers $h }
            'Devices'           = { param($h, $cap) Invoke-DevicesCollector           -Headers $h }
            'Applications'      = { param($h, $cap) Invoke-ApplicationsCollector      -Headers $h }
            'ServicePrincipals' = { param($h, $cap) Invoke-ServicePrincipalsCollector -Headers $h }
            'MFA'               = { param($h, $cap) Invoke-MFACollector               -Headers $h }
            'ConditionalAccess' = { param($h, $cap) Invoke-ConditionalAccessCollector -Headers $h }
            'PIM'               = { param($h, $cap) Invoke-PIMCollector               -Headers $h -Capability $cap }
        }

        $collectorResults = @{}

        foreach ($domain in $activeDomains) {
            # Skip if capability check shows access is not possible
            $cap = if ($capabilities.ContainsKey($domain)) { $capabilities[$domain] } else { $null }

            if ($cap -and $cap.Status -ne 'Available' -and $domain -ne 'PIM') {
                # PIM handles its own capability check internally
                $cr = New-CollectorResult -Domain $domain -Status 'Skipped'
                $cr.Errors.Add($cap.Reason ?? "Skipped: $($cap.Status)")
                $collectorResults[$domain] = $cr
                $tenantResult.Domains[$domain] = $cr
                Write-CollectorStatus -Domain $domain -Status 'Skipped' -Detail $cap.Status
                continue
            }

            Write-Progress -Activity "Assessing $($tenantCfg.DisplayName)" `
                -Status   "Collecting: $domain" `
                -PercentComplete ([math]::Round(($activeDomains.IndexOf($domain) / $activeDomains.Count) * 100))

            $cr = $null
            try {
                $cr = & $collectorMap[$domain] $headers $cap
            }
            catch {
                $cr = New-CollectorResult -Domain $domain -Status 'Failed'
                $cr.Errors.Add($_.Exception.Message)
            }

            $collectorResults[$domain] = $cr
            $tenantResult.Domains[$domain] = $cr

            $statusDetail = if ($cr.Errors.Count -gt 0) { $cr.Errors[0] } else { '' }
            Write-CollectorStatus -Domain $domain -Status $cr.Status -Detail $statusDetail

            if ($cr.Status -eq 'Failed') {
                $tenantResult.CollectorErrors.Add("$domain`: $($cr.Errors[0])")
            }
        }

        Write-Progress -Activity "Assessing $($tenantCfg.DisplayName)" -Completed

        # ── LAYER 5: Assessment & Findings ─────────────────────────────────
        $tenantFindings = @(Invoke-FindingsAssessment `
                -TenantResult     $tenantResult `
                -CollectorResults $collectorResults)

        $tenantResult.Findings = $tenantFindings
        foreach ($f in $tenantFindings) { $allFindings.Add($f) }

        # ── LAYER 6: Tenant Scoring ────────────────────────────────────────
        $tenantScore = Invoke-TenantScoring -Findings $tenantFindings
        $tenantResult.Score = $tenantScore.Score
        $tenantResult.MaturityLabel = $tenantScore.Label
        $tenantResult.SeverityBreakdown = $tenantScore.Breakdown

        $failedCollectors = @($collectorResults.Values | Where-Object { $_.Status -eq 'Failed' }).Count
        $tenantResult.AssessmentStatus = if ($failedCollectors -eq 0) {
            'Completed'
        }
        elseif ($failedCollectors -eq $activeDomains.Count) {
            'Failed'
        }
        else {
            'PartialSuccess'
        }

        Write-TenantScore `
            -Score    $tenantScore.Score `
            -Label    $tenantScore.Label `
            -Findings $tenantFindings.Count

        $allTenantResults.Add($tenantResult)
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  ENTERPRISE SCORING & GRAPH MODEL
    #══════════════════════════════════════════════════════════════════════════

    Write-SectionHeader -Text 'Calculating Enterprise Score' -Icon '📊'

    $successfulTenants = @($allTenantResults | Where-Object { $_.AssessmentStatus -ne 'AuthenticationFailed' })

    $enterpriseScore = Invoke-EnterpriseScoring -TenantResults $successfulTenants
    $graphModel = Build-GraphModel          -TenantResults $successfulTenants

    $scoreColor = switch ($enterpriseScore.Label) {
        'Strong' { 'Green' }
        'Good' { 'Yellow' }
        'Fair' { 'Yellow' }
        'Poor' { 'Red' }
        default { 'Gray' }
    }

    Write-Host "  🏢  Enterprise Score  : $($enterpriseScore.Score)/100  [$($enterpriseScore.Label)]" -ForegroundColor $scoreColor
    Write-Host "  🔴  Critical          : $($enterpriseScore.Breakdown.Critical)" -ForegroundColor Red
    Write-Host "  🟡  High              : $($enterpriseScore.Breakdown.High)"     -ForegroundColor Yellow
    Write-Host "  🟠  Medium            : $($enterpriseScore.Breakdown.Medium)"   -ForegroundColor Yellow
    Write-Host "  🟢  Low               : $($enterpriseScore.Breakdown.Low)"      -ForegroundColor Green

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  REPORTING OUTPUT
    #══════════════════════════════════════════════════════════════════════════

    Write-SectionHeader -Text 'Generating Reports' -Icon '📄'

    $findingsArray = $allFindings.ToArray()

    # Findings CSV
    Write-Host "  📋  Exporting Findings CSV..." -ForegroundColor Cyan
    try {
        Export-FindingsCSV -AllFindings $findingsArray -FilePath $outFindingsCSV
        Write-Host "  ✅  Findings CSV       : $outFindingsCSV" -ForegroundColor Green
    }
    catch {
        Write-Warning "Findings CSV export failed: $_"
    }

    # Metrics CSV
    Write-Host "  📊  Exporting Metrics CSV..."  -ForegroundColor Cyan
    try {
        Export-MetricsCSV -TenantResults $successfulTenants -FilePath $outMetricsCSV
        Write-Host "  ✅  Metrics CSV        : $outMetricsCSV" -ForegroundColor Green
    }
    catch {
        Write-Warning "Metrics CSV export failed: $_"
    }

    # JSON
    Write-Host "  🔗  Exporting JSON..." -ForegroundColor Cyan
    try {
        Export-AssessmentJSON `
            -EnterpriseScore $enterpriseScore `
            -TenantResults   $successfulTenants `
            -AllFindings     $findingsArray `
            -GraphModel      $graphModel `
            -FilePath        $outJSON
        Write-Host "  ✅  JSON               : $outJSON" -ForegroundColor Green
    }
    catch {
        Write-Warning "JSON export failed: $_"
    }

    # HTML Dashboard
    Write-Host "  🌐  Generating HTML Dashboard..." -ForegroundColor Cyan
    try {
        Export-HTMLDashboard `
            -EnterpriseScore $enterpriseScore `
            -TenantResults   $successfulTenants `
            -AllFindings     $findingsArray `
            -FilePath        $outHTML
        Write-Host "  ✅  HTML Dashboard     : $outHTML" -ForegroundColor Green
    }
    catch {
        Write-Warning "HTML dashboard export failed: $_"
    }

    #endregion

    #region ══════════════════════════════════════════════════════════════════
    #  COMPLETION SUMMARY
    #══════════════════════════════════════════════════════════════════════════

    Write-Host ''
    Write-Host '  ╔══════════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '  ║   ✅  Assessment Complete                                        ║' -ForegroundColor Cyan
    Write-Host '  ╚══════════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "  📊  Tenants assessed  : $($resolvedTenants.Count)" -ForegroundColor White
    Write-Host "  📋  Total findings    : $($findingsArray.Count)"   -ForegroundColor White
    Write-Host "  💯  Enterprise score  : $($enterpriseScore.Score)/100  [$($enterpriseScore.Label)]" `
        -ForegroundColor $scoreColor
    Write-Host "  📁  Output folder     : $runFolder" -ForegroundColor White
    Write-Host ''

    if ($OpenDashboard) {
        Write-Host "  🌐  Opening dashboard in browser..." -ForegroundColor Green
        Start-Process $outHTML
    }

    if ($PassThru) {
        return [PSCustomObject]@{
            AssessmentId    = $AssessmentId
            GeneratedAt     = $AssessmentTs
            EnterpriseScore = $enterpriseScore
            TenantResults   = $successfulTenants
            AllFindings     = $findingsArray
            GraphModel      = $graphModel
            OutputFolder    = $runFolder
            OutputFiles     = [PSCustomObject]@{
                FindingsCSV = $outFindingsCSV
                MetricsCSV  = $outMetricsCSV
                JSON        = $outJSON
                HTML        = $outHTML
            }
        }
    }

    #endregion

} 
# End Function Get-EntraMultiTenantGovernanceAssessment
