<#

Author       : Lakshmanan Thangaraj
Version      : 1.1
Created-On   : 10 September 2026
Modified-On  : 10 September 2026

.SYNOPSIS
    Assesses configuration drift across multiple Entra ID tenants against an enterprise security baseline.

.DESCRIPTION
    Get-EntraMultiTenantConfigurationDriftAssessment compares the security configuration of one or
    more Microsoft Entra ID tenants against a versioned enterprise baseline. For each tenant the
    function collects configuration data across four security domains (Conditional Access, MFA, PIM,
    and External Identity), normalises the raw Graph API responses into a consistent internal model,
    evaluates each control against the baseline, classifies the result as Compliant / MinorDrift /
    SignificantDrift / CriticalDrift / NotAssessed / NotApplicable, derives a 0–100 enterprise
    alignment score, and produces a full report set: CSV (findings + metrics), JSON, and an
    interactive HTML dashboard.

    The function is read-only. It never creates, modifies, or deletes any tenant resource.

    The function follows a layered architecture:

      Orchestration → Tenant Management → Authentication → Baseline Resolution
      → Collectors (4 domains) → Normalisation → Drift Evaluation → Scoring → Reporting

    Assessment domains (V1):
      Conditional Access · MFA · PIM · External Identity

    Output:
      • HTML dashboard — Enterprise → Tenant → Domain → Finding drill-down
      • JSON           — Graph-ready data model with stable Finding IDs and schema version
      • Findings CSV   — One row per finding; remediation/ticketing focused
      • Metrics CSV    — One row per tenant/domain; analytics/trending focused

    Authentication (per tenant):
      • ClientCredentials — Tenant ID + Client ID + Client Secret (secret via env var)
      Architecture is designed for Managed Identity to be added as a second auth mode
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

.PARAMETER BaselineConfigPath
    Path to a JSON file containing the enterprise security baseline. If omitted the built-in
    default baseline (Enterprise Entra Security Baseline v1.0) is used.
    See .NOTES for the baseline JSON schema.

.PARAMETER OutputPath
    Directory where output files are written. A timestamped sub-folder is created automatically.
    Defaults to the current working directory.

.PARAMETER IncludeDomains
    Limit assessment to specific domain collectors. Valid values: ConditionalAccess, MFA, PIM,
    ExternalIdentity.
    Defaults to all four domains.

.PARAMETER ExcludeDomains
    Exclude specific domain collectors. Valid values: same as IncludeDomains.
    Cannot be combined meaningfully with IncludeDomains for the same domain; IncludeDomains
    wins when both are supplied.

.PARAMETER ExcludeTenantIds
    One or more tenant GUIDs to exclude from the assessment. Applies after the tenant list
    is resolved from -TenantConfigPath or -Tenants.

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
    # Assess tenants defined in a JSON config file using the built-in baseline
    Get-EntraMultiTenantConfigurationDriftAssessment -TenantConfigPath ".\tenants.json" -OpenDashboard

.EXAMPLE
    # Assess only Conditional Access and MFA, skipping one tenant
    Get-EntraMultiTenantConfigurationDriftAssessment `
        -TenantConfigPath   ".\tenants.json" `
        -BaselineConfigPath ".\baseline.json" `
        -IncludeDomains     ConditionalAccess, MFA `
        -ExcludeTenantIds   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -OutputPath         "C:\Reports"

.EXAMPLE
    # Supply tenants inline and capture the result object
    $tenants = @(
        [PSCustomObject]@{
            TenantId           = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            DisplayName        = "Contoso Production"
            BusinessUnit       = "Corporate IT"
            AuthMode           = "ClientCredentials"
            ClientId           = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            ClientSecretEnvVar = "CONTOSO_PROD_SECRET"
        }
    )
    $result = Get-EntraMultiTenantConfigurationDriftAssessment -Tenants $tenants -PassThru

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.1 (10-Sep-2026) - Added HTTP 429 retry/throttle logic to Invoke-GraphRequest
                        (up to 3 retries, honours Retry-After header).
                        Replaced PS 7.0-only ?? operator with PS 5.1-safe equivalents
                        in Get-PimDriftFindings and Get-TenantRiskScore.
    1.0 (10-Sep-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Microsoft Graph API access — no PowerShell module required; uses REST calls directly.

    2. The service principal used per tenant must have the following Graph application
    permissions (not delegated):
        Policy.Read.All                        (Conditional Access policies)
        AuditLog.Read.All                      (MFA registration reports)
        RoleManagement.Read.Directory          (PIM active/eligible assignments)
        RoleManagementPolicy.Read.Directory    (PIM policy rules)
        Policy.Read.All                        (Authorization / Cross-Tenant policies)

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
        }
        ]
    }
    ClientSecretEnvVar names an environment variable — never the secret value itself.
    Secrets must never appear in the JSON file.

    4. Baseline JSON configuration schema:
    {
        "SchemaVersion":   "1.0",
        "BaselineVersion": "1.0",
        "BaselineName":    "Enterprise Entra Security Baseline",
        "ConditionalAccess": {
            "RequireMFAForAdmins":       true,
            "BlockLegacyAuthentication": true,
            "RequireCompliantDevice":    true
        },
        "MFA": {
            "MinimumRegistrationRate": 90,
            "PasswordlessTarget":      30
        },
        "PIM": {
            "RequireEligibleAssignments": true,
            "RequireMFAActivation":       true
        },
        "ExternalIdentity": {
            "RestrictExternalCollaboration": true
        }
    }
    If -BaselineConfigPath is omitted, the built-in default baseline above is used.

    5. Multi-Tenant Authentication Using a Single Application Registration
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
       - Name:                    EntraConfigurationDriftAssessment  (or your naming convention)
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
        Policy.Read.All                        246dd0d5-5bd0-4def-940b-0421030a5b68
        AuditLog.Read.All                      b0afded3-3588-46d8-8b3d-9842eff778da
        RoleManagement.Read.Directory          d31a2573-9a62-4d17-87c5-2d73b0e2410d
        RoleManagementPolicy.Read.Directory    fccf63e9-b35d-4524-95ef-feaed6a40a59

    3b. Grant permissions using PowerShell (recommended for automation):

        $spObjectId    = "SP_OBJECT_ID_FROM_STEP_2"
        $graphObjectId = "GRAPH_SP_OBJECT_ID_FROM_STEP_3a"

        $permissionsToGrant = @(
            "246dd0d5-5bd0-4def-940b-0421030a5b68",  # Policy.Read.All
            "b0afded3-3588-46d8-8b3d-9842eff778da",  # AuditLog.Read.All
            "d31a2573-9a62-4d17-87c5-2d73b0e2410d",  # RoleManagement.Read.Directory
            "fccf63e9-b35d-4524-95ef-feaed6a40a59"   # RoleManagementPolicy.Read.Directory
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
            "ClientSecretEnvVar": "ENTRA_DRIFT_CLIENT_SECRET"
        },
        {
            "TenantId":           "22222222-2222-2222-2222-222222222222",
            "DisplayName":        "Fabrikam — EMEA Subsidiary",
            "BusinessUnit":       "EMEA",
            "AuthMode":           "ClientCredentials",
            "ClientId":           "aabbccdd-aabb-aabb-aabb-aabbccddeeff",
            "ClientSecretEnvVar": "ENTRA_DRIFT_CLIENT_SECRET"
        },
        {
            "TenantId":           "33333333-3333-3333-3333-333333333333",
            "DisplayName":        "Tailwind — APAC Region",
            "BusinessUnit":       "APAC",
            "AuthMode":           "ClientCredentials",
            "ClientId":           "aabbccdd-aabb-aabb-aabb-aabbccddeeff",
            "ClientSecretEnvVar": "ENTRA_DRIFT_CLIENT_SECRET"
        }
        ]
    }

    Set the environment variable on the host before running:
        $env:ENTRA_DRIFT_CLIENT_SECRET = "your-client-secret-value"

    Then invoke normally:
        Get-EntraMultiTenantConfigurationDriftAssessment `
            -TenantConfigPath "C:\Config\tenants.json" `
            -OutputPath       "C:\Reports" `
            -OpenDashboard

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - MFA registration data requires an Entra ID P1/P2 license in the target tenant.
      If unavailable, the MFA domain status is reported as Unavailable, not as a
      security failure.
    - PIM data (eligibility schedules, policy rules) requires Entra ID P2 / Identity
      Governance licensing. Missing license is surfaced as Unavailable.
    - Conditional Access named-location expansion is not performed; policy scope is
      evaluated on effective grant controls only.
    - The assessment is a point-in-time snapshot; it does not track historical drift.
    - Managed Identity authentication is not implemented in V1 (architecture is ready).
    - Cross-tenant access partner enumeration may return a large result set for
      organisations with many configured partners; pagination is handled automatically.
    - Graph API throttling across large tenants may extend runtime. The function
      honours Retry-After headers and retries up to 3 times per call.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW:
    ─────────────────────────────────────────────────────────────────────────────
    1.  Resolve tenant list (JSON file or inline objects)
    2.  Validate tenant config and apply ExcludeTenantIds / IncludeDomains filters
    3.  Resolve baseline (JSON file or built-in default)
    4.  For each tenant:
        a.  Acquire token (Client Credentials)
        b.  Run domain collectors (independent try/catch per domain)
        c.  Normalise collector output to DomainResult objects
        d.  Evaluate each control against the resolved baseline
        e.  Classify drift (Compliant / MinorDrift / SignificantDrift /
            CriticalDrift / NotAssessed / NotApplicable)
        f.  Calculate tenant alignment score (0–100)
    5.  Calculate enterprise alignment score (risk-weighted by tenant)
    6.  Export: Findings.csv, Metrics.csv, assessment.json, dashboard.html
    7.  Optionally open dashboard in browser / return result object via PassThru

.LINK
    https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies
.LINK
    https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails
.LINK
    https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignmentschedules
.LINK
    https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityschedules
.LINK
    https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get
.LINK
    https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicyconfigurationdefault-get

#>



#region Metadata
$Script:AssessmentVersion = "1.0"
$Script:SchemaVersion = "1.0"
$Script:DefaultDomains = @("ConditionalAccess", "MFA", "PIM", "ExternalIdentity")

# Well-known GUIDs for Entra ID guest role templates
$Script:GuestUserRoleIds = @{
    "10dae51f-b6af-4016-8d66-8c2a99b929b3" = "User"
    "2af84b1e-32c8-42b7-82bc-daa82404023b" = "GuestUser"
    "c2d11171-863f-477b-a5c5-c1b9f2f0e9cf" = "RestrictedGuest"
}

# Critical directory role definitions (subset of well-known IDs)
$Script:CriticalRoleIds = @{
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
    "158c047a-c907-4556-b7ef-446551a6b5f7" = "Cloud Application Administrator"
    "b0f54661-2d74-4c50-afa3-1ec803f12efe" = "Billing Administrator"
    "29232cdf-9323-42fd-ade2-1d097af3e4de" = "Exchange Administrator"
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint Administrator"
    "69091246-20e8-4a56-aa4d-066075b2a7a8" = "Teams Administrator"
    "c4e39bd9-1100-46d3-8c65-fb160da0071f" = "Authentication Administrator"
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged Authentication Administrator"
    "966707d0-3269-4727-9be2-8c3a10f19b9d" = "Password Administrator"
}
#endregion Metadata

Function Get-EntraMultiTenantConfigurationDriftAssessment {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName = "FromFile")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantConfigPath,

        [Parameter(ParameterSetName = "FromObject")]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$Tenants,

        [ValidateNotNullOrEmpty()]
        [string]$BaselineConfigPath,

        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = ".",

        [ValidateSet("ConditionalAccess", "MFA", "PIM", "ExternalIdentity")]
        [string[]]$IncludeDomains,

        [ValidateSet("ConditionalAccess", "MFA", "PIM", "ExternalIdentity")]
        [string[]]$ExcludeDomains,

        [ValidatePattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")]
        [string[]]$ExcludeTenantIds,

        [switch]$OpenDashboard,

        [switch]$PassThru
    )

    #region Configuration

    $assessmentId = [System.Guid]::NewGuid().ToString()
    $assessmentStart = [datetime]::UtcNow
    $timestamp = $assessmentStart.ToString("yyyyMMdd_HHmmss")

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Entra Multi-Tenant Configuration Drift Assessment" -ForegroundColor Cyan
    Write-Host "  Assessment ID : $assessmentId" -ForegroundColor Cyan
    Write-Host "  Started       : $($assessmentStart.ToString('yyyy-MM-dd HH:mm:ss')) UTC" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    #-- Resolve active domains
    $activeDomains = if ($IncludeDomains) { $IncludeDomains } else { $Script:DefaultDomains }
    if ($ExcludeDomains) {
        $activeDomains = $activeDomains | Where-Object { $_ -notin $ExcludeDomains }
    }

    Write-Verbose "Active assessment domains: $($activeDomains -join ', ')"

    #-- Validate / sanitise output path
    $OutputPath = $OutputPath.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    if ($OutputPath -match '[<>:"|?*]' -and $OutputPath -notmatch '^[A-Za-z]:\\') {
        throw "OutputPath contains invalid characters: '$OutputPath'"
    }

    $outputFolder = Join-Path -Path $OutputPath -ChildPath "EntraMultiTenantConfigurationDrift_$timestamp"

    try {
        $null = New-Item -ItemType Directory -Path $outputFolder -Force -ErrorAction Stop
        Write-Verbose "Output folder created: $outputFolder"
    }
    catch {
        throw "Cannot create output folder '$outputFolder': $_"
    }

    #endregion Configuration

    #region Baseline Management

    $baseline = Get-AssessmentBaseline -BaselineConfigPath $BaselineConfigPath

    Write-Host "Baseline : $($baseline.BaselineName) v$($baseline.BaselineVersion)" -ForegroundColor Green
    Write-Verbose "Baseline loaded. SchemaVersion=$($baseline.SchemaVersion)"

    #endregion Baseline Management

    #region Tenant Management

    $tenantList = Resolve-TenantList -TenantConfigPath $TenantConfigPath -Tenants $Tenants -ExcludeTenantIds $ExcludeTenantIds

    Write-Host "Tenants  : $($tenantList.Count) tenant(s) to assess" -ForegroundColor Green
    Write-Host ""

    #endregion Tenant Management

    #region Assessment Loop

    $allTenantResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $tenantIndex = 0

    foreach ($tenantConfig in $tenantList) {
        $tenantIndex++
        $tenantId = $tenantConfig.TenantId
        $tenantName = if ($tenantConfig.DisplayName) { $tenantConfig.DisplayName } else { $tenantId }

        Write-Host "[$tenantIndex/$($tenantList.Count)] $tenantName ($tenantId)" -ForegroundColor Yellow
        Write-Progress -Activity "Assessing Tenants" -Status "$tenantName" -PercentComplete (($tenantIndex - 1) / $tenantList.Count * 100)

        $tenantResult = [PSCustomObject]@{
            TenantId        = $tenantId
            TenantName      = $tenantName
            BusinessUnit    = $tenantConfig.BusinessUnit
            AssessmentStart = [datetime]::UtcNow.ToString("o")
            AssessmentEnd   = $null
            Status          = "InProgress"
            AuthStatus      = "Unknown"
            Domains         = [ordered]@{}
            Findings        = [System.Collections.Generic.List[PSCustomObject]]::new()
            Score           = $null
            Errors          = [System.Collections.Generic.List[string]]::new()
        }

        try {
            #region Authentication
            Write-Verbose "[$tenantName] Acquiring access token..."

            $token = Get-TenantAccessToken -TenantConfig $tenantConfig

            if (-not $token) {
                throw "Authentication failed; no token returned."
            }

            $tenantResult.AuthStatus = "Success"
            Write-Verbose "[$tenantName] Token acquired."
            #endregion Authentication

            #region Domain Collectors
            foreach ($domain in $activeDomains) {
                Write-Host "  [$domain]" -NoNewline -ForegroundColor Cyan

                $collectorResult = $null

                try {
                    switch ($domain) {
                        "ConditionalAccess" {
                            $collectorResult = Invoke-ConditionalAccessConfigurationCollector -Token $token -TenantId $tenantId -TenantName $tenantName
                        }
                        "MFA" {
                            $collectorResult = Invoke-MFAConfigurationCollector -Token $token -TenantId $tenantId -TenantName $tenantName
                        }
                        "PIM" {
                            $collectorResult = Invoke-PIMConfigurationCollector -Token $token -TenantId $tenantId -TenantName $tenantName
                        }
                        "ExternalIdentity" {
                            $collectorResult = Invoke-ExternalIdentityConfigurationCollector -Token $token -TenantId $tenantId -TenantName $tenantName
                        }
                    }

                    $collectorColor = switch ($collectorResult.Status) {
                        "Success" { "Green" }
                        "PartialSuccess" { "Yellow" }
                        default { "Red" }
                    }

                    Write-Host " [$($collectorResult.Status)]" -ForegroundColor $collectorColor
                }
                catch {
                    Write-Host " [Error]" -ForegroundColor Red
                    Write-Warning "[$tenantName][$domain] Collector exception: $_"

                    $collectorResult = [PSCustomObject]@{
                        Domain        = $domain
                        Status        = "Failed"
                        CollectedAt   = [datetime]::UtcNow
                        Metrics       = @{}
                        Configuration = @{}
                        Errors        = @("Unhandled collector exception: $_")
                    }
                }

                $tenantResult.Domains[$domain] = $collectorResult
            }
            #endregion Domain Collectors

            # Clear token from memory immediately after collectors finish
            Remove-Variable -Name token -ErrorAction SilentlyContinue
            [System.GC]::Collect()

            #region Drift Detection
            Write-Verbose "[$tenantName] Running drift detection..."

            $domainFindings = Invoke-DriftDetection -TenantId $tenantId -TenantName $tenantName -DomainResults $tenantResult.Domains -Baseline $baseline

            foreach ($f in $domainFindings) {
                $tenantResult.Findings.Add($f)
            }
            #endregion Drift Detection

            #region Risk Scoring
            $tenantResult.Score = Get-TenantRiskScore -Findings $tenantResult.Findings -DomainResults $tenantResult.Domains -ActiveDomains $activeDomains
            #endregion Risk Scoring

            $tenantResult.Status = "Completed"
        }
        catch {
            $errorMsg = "[$tenantName] Tenant-level failure: $_"
            Write-Warning $errorMsg
            $tenantResult.Status = "Failed"
            $tenantResult.AuthStatus = if ($tenantResult.AuthStatus -eq "Unknown") { "Failed" } else { $tenantResult.AuthStatus }
            $tenantResult.Errors.Add($errorMsg)

            # Ensure token is cleared even on failure
            Remove-Variable -Name token -ErrorAction SilentlyContinue
            [System.GC]::Collect()
        }

        $tenantResult.AssessmentEnd = [datetime]::UtcNow.ToString("o")
        $allTenantResults.Add($tenantResult)

        Write-Host ""
    }

    Write-Progress -Activity "Assessing Tenants" -Completed

    #endregion Assessment Loop

    #region Enterprise Scoring

    $enterpriseScore = Get-EnterpriseScore -TenantResults $allTenantResults

    #endregion Enterprise Scoring

    #region Reporting

    $assessmentEnd = [datetime]::UtcNow

    Write-Host "Generating reports..." -ForegroundColor Green

    $reportPayload = [PSCustomObject]@{
        SchemaVersion     = $Script:SchemaVersion
        AssessmentVersion = $Script:AssessmentVersion
        BaselineVersion   = $baseline.BaselineVersion
        BaselineName      = $baseline.BaselineName
        AssessmentId      = $assessmentId
        GeneratedAt       = $assessmentEnd.ToString("o")
        Enterprise        = $enterpriseScore
        Tenants           = $allTenantResults
        ActiveDomains     = $activeDomains
        Controls          = Get-BaselineControlCatalog -Baseline $baseline -ActiveDomains $activeDomains
        Findings          = $allTenantResults | ForEach-Object { $_.Findings } | Where-Object { $_ }
        Nodes             = Get-GraphNodes -TenantResults $allTenantResults
        Edges             = Get-GraphEdges -TenantResults $allTenantResults -AssessmentId $assessmentId
        _future           = @{
            ManagedIdentityAuth  = $false
            HistoricalComparison = $false
            ApprovedExceptions   = $false
            ITSMIntegration      = $false
            AutomatedRemediation = $false
            LLMNarratives        = $false
        }
    }

    $baseFilename = "Get-EntraMultiTenantConfigurationDriftAssessment_$timestamp"

    #-- Findings CSV
    $findingsCsvPath = Join-Path $outputFolder "${baseFilename}_Findings.csv"
    Export-FindingsCsv -Findings $reportPayload.Findings -Path $findingsCsvPath

    #-- Metrics CSV
    $metricsCsvPath = Join-Path $outputFolder "${baseFilename}_Metrics.csv"
    Export-MetricsCsv -TenantResults $allTenantResults -EnterpriseScore $enterpriseScore -Path $metricsCsvPath

    #-- JSON
    $jsonPath = Join-Path $outputFolder "${baseFilename}.json"
    Export-AssessmentJson -Payload $reportPayload -Path $jsonPath

    #-- HTML Dashboard
    $htmlPath = Join-Path $outputFolder "${baseFilename}.html"
    Export-HtmlDashboard -Payload $reportPayload -Path $htmlPath -Timestamp $timestamp

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Assessment Complete" -ForegroundColor Cyan
    Write-Host "  Duration      : $([math]::Round(($assessmentEnd - $assessmentStart).TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "  Enterprise    : Score $($enterpriseScore.AlignmentScore)/100" -ForegroundColor Cyan
    Write-Host "  Critical Drifts: $($enterpriseScore.CriticalDrifts)" -ForegroundColor $(if ($enterpriseScore.CriticalDrifts -gt 0) { "Red" } else { "Green" })
    Write-Host "  Output        : $outputFolder" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    if ($OpenDashboard -and (Test-Path $htmlPath)) {
        try { Start-Process $htmlPath } catch { Write-Warning "Cannot open dashboard automatically: $_" }
    }

    if ($PassThru) {
        return $reportPayload
    }

    #endregion Reporting
}

#region Baseline Management

Function Get-AssessmentBaseline {
    [CmdletBinding()]
    param (
        [string]$BaselineConfigPath
    )

    if ($BaselineConfigPath) {
        if (-not (Test-Path -LiteralPath $BaselineConfigPath -PathType Leaf)) {
            throw "Baseline config file not found: '$BaselineConfigPath'"
        }

        Write-Verbose "Loading baseline from: $BaselineConfigPath"

        try {
            $raw = Get-Content -LiteralPath $BaselineConfigPath -Raw -ErrorAction Stop
            $baseline = $raw | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "Failed to parse baseline JSON from '$BaselineConfigPath': $_"
        }

        # Validate required fields
        foreach ($field in @("SchemaVersion", "BaselineVersion", "BaselineName")) {
            if (-not $baseline.$field) {
                throw "Baseline JSON is missing required field '$field'."
            }
        }

        return $baseline
    }

    Write-Verbose "No baseline file specified; using built-in default baseline."

    return [PSCustomObject]@{
        SchemaVersion     = "1.0"
        BaselineVersion   = "1.0"
        BaselineName      = "Enterprise Entra Security Baseline"
        ConditionalAccess = [PSCustomObject]@{
            RequireMFAForAdmins       = $true
            BlockLegacyAuthentication = $true
            RequireCompliantDevice    = $true
        }
        MFA               = [PSCustomObject]@{
            MinimumRegistrationRate = 90
            PasswordlessTarget      = 30
        }
        PIM               = [PSCustomObject]@{
            RequireEligibleAssignments = $true
            RequireMFAActivation       = $true
        }
        ExternalIdentity  = [PSCustomObject]@{
            RestrictExternalCollaboration = $true
        }
    }
}

Function Get-BaselineControlCatalog {
    [CmdletBinding()]
    param (
        [PSCustomObject]$Baseline,
        [string[]]$ActiveDomains
    )

    $controls = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ("ConditionalAccess" -in $ActiveDomains) {
        $controls.Add([PSCustomObject]@{ ControlId = "CA-BASELINE-001"; Domain = "ConditionalAccess"; Name = "Block Legacy Authentication"; BaselineValue = $Baseline.ConditionalAccess.BlockLegacyAuthentication })
        $controls.Add([PSCustomObject]@{ ControlId = "CA-BASELINE-002"; Domain = "ConditionalAccess"; Name = "Require MFA for Administrators"; BaselineValue = $Baseline.ConditionalAccess.RequireMFAForAdmins })
        $controls.Add([PSCustomObject]@{ ControlId = "CA-BASELINE-003"; Domain = "ConditionalAccess"; Name = "Require Compliant Device"; BaselineValue = $Baseline.ConditionalAccess.RequireCompliantDevice })
        $controls.Add([PSCustomObject]@{ ControlId = "CA-BASELINE-004"; Domain = "ConditionalAccess"; Name = "No Required Policy in Report-Only"; BaselineValue = $false })
        $controls.Add([PSCustomObject]@{ ControlId = "CA-BASELINE-005"; Domain = "ConditionalAccess"; Name = "No Required Policy Disabled"; BaselineValue = $false })
    }
    if ("MFA" -in $ActiveDomains) {
        $controls.Add([PSCustomObject]@{ ControlId = "MFA-BASELINE-001"; Domain = "MFA"; Name = "MFA Registration Rate >= Baseline"; BaselineValue = "$($Baseline.MFA.MinimumRegistrationRate)%" })
        $controls.Add([PSCustomObject]@{ ControlId = "MFA-BASELINE-002"; Domain = "MFA"; Name = "Passwordless Adoption >= Target"; BaselineValue = "$($Baseline.MFA.PasswordlessTarget)%" })
        $controls.Add([PSCustomObject]@{ ControlId = "MFA-BASELINE-003"; Domain = "MFA"; Name = "Privileged Users MFA Registered"; BaselineValue = "100%" })
    }
    if ("PIM" -in $ActiveDomains) {
        $controls.Add([PSCustomObject]@{ ControlId = "PIM-BASELINE-001"; Domain = "PIM"; Name = "No Permanent Critical Role Assignments"; BaselineValue = $Baseline.PIM.RequireEligibleAssignments })
        $controls.Add([PSCustomObject]@{ ControlId = "PIM-BASELINE-002"; Domain = "PIM"; Name = "MFA Required at Activation"; BaselineValue = $Baseline.PIM.RequireMFAActivation })
        $controls.Add([PSCustomObject]@{ ControlId = "PIM-BASELINE-003"; Domain = "PIM"; Name = "Approval Required for Global Admin"; BaselineValue = $true })
    }
    if ("ExternalIdentity" -in $ActiveDomains) {
        $controls.Add([PSCustomObject]@{ ControlId = "EXT-BASELINE-001"; Domain = "ExternalIdentity"; Name = "Restrict Guest Invitations"; BaselineValue = $Baseline.ExternalIdentity.RestrictExternalCollaboration })
        $controls.Add([PSCustomObject]@{ ControlId = "EXT-BASELINE-002"; Domain = "ExternalIdentity"; Name = "Guest User Role Is Restricted"; BaselineValue = "RestrictedGuest or GuestUser" })
        $controls.Add([PSCustomObject]@{ ControlId = "EXT-BASELINE-003"; Domain = "ExternalIdentity"; Name = "External Collaboration Not Open"; BaselineValue = $true })
    }

    return $controls
}

#endregion Baseline Management

#region Authentication

Function Get-TenantAccessToken {
    [CmdletBinding()]
    param (
        [PSCustomObject]$TenantConfig
    )

    switch ($TenantConfig.AuthMode) {
        "ClientCredentials" {
            return Get-ClientCredentialsToken -TenantConfig $TenantConfig
        }
        "ManagedIdentity" {
            # FUTURE: Implement Managed Identity token acquisition
            throw "AuthMode 'ManagedIdentity' is not yet implemented in V1."
        }
        default {
            throw "Unknown AuthMode '$($TenantConfig.AuthMode)'. Supported: ClientCredentials"
        }
    }
}

Function Get-ClientCredentialsToken {
    [CmdletBinding()]
    param (
        [PSCustomObject]$TenantConfig
    )

    # Retrieve secret from environment variable — never from the config object directly
    if (-not $TenantConfig.ClientSecretEnvVar) {
        throw "Tenant '$($TenantConfig.DisplayName)' is missing ClientSecretEnvVar."
    }

    $clientSecret = [System.Environment]::GetEnvironmentVariable($TenantConfig.ClientSecretEnvVar)

    if ([string]::IsNullOrWhiteSpace($clientSecret)) {
        throw "Environment variable '$($TenantConfig.ClientSecretEnvVar)' is not set or is empty for tenant '$($TenantConfig.DisplayName)'."
    }

    $tokenEndpoint = "https://login.microsoftonline.com/$($TenantConfig.TenantId)/oauth2/v2.0/token"

    $body = @{
        client_id     = $TenantConfig.ClientId
        client_secret = $clientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }

    try {
        Write-Verbose "Requesting token for tenant '$($TenantConfig.DisplayName)' from $tokenEndpoint"

        $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

        if (-not $response.access_token) {
            throw "Token response did not contain access_token."
        }

        # Return only the token string; caller is responsible for scoping the variable lifetime
        return $response.access_token
    }
    catch {
        # Ensure secret is not in the exception message
        $safeMsg = $_.ToString() -replace [regex]::Escape($clientSecret), "<REDACTED>"
        throw "Token acquisition failed for tenant '$($TenantConfig.DisplayName)': $safeMsg"
    }
    finally {
        # Null out local secret reference
        $clientSecret = $null
        $body = $null
    }
}

#endregion Authentication

#region Tenant Management

Function Resolve-TenantList {
    [CmdletBinding()]
    param (
        [string]$TenantConfigPath,
        [PSCustomObject[]]$Tenants,
        [string[]]$ExcludeTenantIds
    )

    # Guard: both cannot be set (ParameterSetName handles at CLI level, but this protects internal callers)
    if ($TenantConfigPath -and $Tenants) {
        throw "Specify either -TenantConfigPath or -Tenants, not both. Supply one source of tenant configuration."
    }

    $resolvedTenants = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($TenantConfigPath) {
        if (-not (Test-Path -LiteralPath $TenantConfigPath -PathType Leaf)) {
            throw "Tenant config file not found: '$TenantConfigPath'"
        }

        try {
            $raw = Get-Content -LiteralPath $TenantConfigPath -Raw -ErrorAction Stop
            $config = $raw | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "Failed to parse tenant config JSON from '$TenantConfigPath': $_"
        }

        if (-not $config.Tenants -or $config.Tenants.Count -eq 0) {
            throw "Tenant config JSON contains no tenant entries."
        }

        foreach ($t in $config.Tenants) { $resolvedTenants.Add($t) }
    }
    elseif ($Tenants) {
        foreach ($t in $Tenants) { $resolvedTenants.Add($t) }
    }
    else {
        throw "Either -TenantConfigPath or -Tenants must be supplied."
    }

    # Validate each tenant entry
    $validated = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($t in $resolvedTenants) {
        $issues = @()

        if (-not $t.TenantId) { $issues += "Missing TenantId" }
        if (-not $t.ClientId) { $issues += "Missing ClientId" }
        if (-not $t.AuthMode) { $issues += "Missing AuthMode" }
        if ($t.AuthMode -eq "ClientCredentials" -and -not $t.ClientSecretEnvVar) {
            $issues += "Missing ClientSecretEnvVar (required for ClientCredentials auth)"
        }

        if ($issues.Count -gt 0) {
            $label = if ($t.DisplayName) { $t.DisplayName } elseif ($t.TenantId) { $t.TenantId } else { "(unknown)" }
            Write-Warning "Tenant '$label' has configuration issues and will be skipped: $($issues -join '; ')"
            continue
        }

        if ($ExcludeTenantIds -and $t.TenantId -in $ExcludeTenantIds) {
            Write-Verbose "Tenant '$($t.TenantId)' excluded by -ExcludeTenantIds."
            continue
        }

        $validated.Add($t)
    }

    if ($validated.Count -eq 0) {
        throw "No valid tenants remain after validation and exclusions."
    }

    return $validated
}

#endregion Tenant Management

#region Collectors

Function Invoke-GraphRequest {
    #
    # FIX 1 of 3 — Added HTTP 429 retry / Retry-After throttle handling.
    # The .NOTES documented "honours Retry-After headers and retries up to 3 times per call"
    # but the original implementation had no retry loop at all; any throttle response would
    # immediately surface as an unhandled GraphError and abort the collector.
    #
    # Change: wrapped the per-page REST call in a retry loop (max 3 attempts).
    # On HTTP 429 the function reads the Retry-After response header (seconds),
    # emits a Write-Warning, sleeps for that duration (min 1 s, max 120 s), then retries.
    # All other error types continue to throw immediately as before.
    # The outer do/while pagination logic and all caller contracts are unchanged.
    #
    [CmdletBinding()]
    param (
        [string]$Token,
        [string]$Uri,
        [string]$Method = "GET",
        [int]$MaxPages = 20
    )

    $headers = @{
        Authorization  = "Bearer $Token"
        "Content-Type" = "application/json"
    }

    $allValues = [System.Collections.Generic.List[object]]::new()
    $currentUri = $Uri
    $pageCount = 0

    do {
        $pageCount++

        # --- Retry loop: up to 3 attempts per page to honour Retry-After on HTTP 429 ---
        $maxRetries = 3
        $attempt = 0
        $response = $null

        while ($attempt -lt $maxRetries) {
            $attempt++

            try {
                $response = Invoke-RestMethod -Method $Method -Uri $currentUri -Headers $headers -ErrorAction Stop
                break  # Success — exit the retry loop
            }
            catch {
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }

                # HTTP 429 — Graph API throttling; honour Retry-After and retry
                if ($statusCode -eq 429 -and $attempt -lt $maxRetries) {
                    $retryAfterSeconds = 30  # Default wait if header is absent

                    try {
                        $retryHeader = $_.Exception.Response.Headers["Retry-After"]
                        if ($retryHeader) {
                            $parsed = 0
                            if ([int]::TryParse($retryHeader, [ref]$parsed)) {
                                # Clamp to a safe range: never less than 1 s, never more than 120 s
                                $retryAfterSeconds = [math]::Min([math]::Max($parsed, 1), 120)
                            }
                        }
                    }
                    catch {
                        # Header parse failure is non-fatal; use the default wait
                    }

                    Write-Warning "Graph API throttled (HTTP 429) on '$currentUri'. Retry-After: ${retryAfterSeconds}s. Attempt $attempt of $maxRetries."
                    Start-Sleep -Seconds $retryAfterSeconds
                    continue  # Retry the same page
                }

                # Non-429 errors or retries exhausted — surface as before
                if ($statusCode -in @(401, 403)) {
                    throw [PSCustomObject]@{ Type = "PermissionDenied"; StatusCode = $statusCode; Message = $_.ToString() }
                }
                elseif ($statusCode -eq 404) {
                    throw [PSCustomObject]@{ Type = "Unavailable"; StatusCode = $statusCode; Message = $_.ToString() }
                }
                else {
                    throw [PSCustomObject]@{ Type = "GraphError"; StatusCode = $statusCode; Message = $_.ToString() }
                }
            }
        }

        # Retries exhausted on HTTP 429 without a successful response
        if ($null -eq $response) {
            throw [PSCustomObject]@{
                Type       = "GraphError"
                StatusCode = 429
                Message    = "Graph API request to '$currentUri' failed after $maxRetries retries due to persistent throttling."
            }
        }
        # --- End retry loop ---

        # Collect paged values
        if ($response.value -is [array] -or $response.value -is [System.Collections.IEnumerable]) {
            foreach ($item in $response.value) { $allValues.Add($item) }
        }
        elseif ($response.PSObject.Properties.Name -notcontains "value") {
            # Non-array response (singleton) — return directly
            return $response
        }

        $currentUri = $response.'@odata.nextLink'

    } while ($currentUri -and $pageCount -lt $MaxPages)

    return $allValues
}

Function New-CollectorResult {
    param (
        [string]$Domain,
        [string]$Status,
        [hashtable]$Metrics = @{},
        [hashtable]$Configuration = @{},
        [string[]]$Errors = @()
    )

    return [PSCustomObject]@{
        Domain        = $Domain
        Status        = $Status
        CollectedAt   = [datetime]::UtcNow
        Metrics       = $Metrics
        Configuration = $Configuration
        Errors        = $Errors
    }
}

Function Invoke-ConditionalAccessConfigurationCollector {
    [CmdletBinding()]
    param (
        [string]$Token,
        [string]$TenantId,
        [string]$TenantName
    )

    $graphBase = "https://graph.microsoft.com/v1.0"
    $errors = [System.Collections.Generic.List[string]]::new()

    try {
        # GET /identity/conditionalAccess/policies — requires Policy.Read.All
        $policies = Invoke-GraphRequest -Token $Token -Uri "$graphBase/identity/conditionalAccess/policies"

        $configuration = @{
            Policies    = $policies
            PolicyCount = @($policies).Count
        }

        $metrics = @{
            TotalPolicies    = @($policies).Count
            EnabledPolicies  = @($policies | Where-Object { $_.state -eq "enabled" }).Count
            ReportOnly       = @($policies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }).Count
            DisabledPolicies = @($policies | Where-Object { $_.state -eq "disabled" }).Count
        }

        return New-CollectorResult -Domain "ConditionalAccess" -Status "Success" -Metrics $metrics -Configuration $configuration
    }
    catch {
        $errType = if ($_ -is [PSCustomObject] -and $_.Type) { $_.Type } else { "Failed" }
        $errMsg = if ($_ -is [PSCustomObject] -and $_.Message) { $_.Message } else { $_.ToString() }

        Write-Verbose "[$TenantName][ConditionalAccess] Collector $errType : $errMsg"
        return New-CollectorResult -Domain "ConditionalAccess" -Status $errType -Errors @($errMsg)
    }
}

Function Invoke-MFAConfigurationCollector {
    [CmdletBinding()]
    param (
        [string]$Token,
        [string]$TenantId,
        [string]$TenantName
    )

    $graphBase = "https://graph.microsoft.com/v1.0"
    $errors = [System.Collections.Generic.List[string]]::new()
    $status = "Success"

    $mfaDetails = @{
        TotalUsers              = 0
        MfaRegistered           = 0
        MfaCapable              = 0
        PasswordlessCapable     = 0
        PrivilegedUsers         = 0
        PrivilegedMfaRegistered = 0
        MfaRegistrationRate     = 0
        PasswordlessRate        = 0
        PrivilegedMfaRate       = 0
    }

    try {
        # GET /reports/authenticationMethods/userRegistrationDetails
        # Requires AuditLog.Read.All (application permission)
        # Supports $filter; we retrieve all and compute server-side pagination
        $regDetails = Invoke-GraphRequest -Token $Token -Uri "$graphBase/reports/authenticationMethods/userRegistrationDetails" -MaxPages 50

        if ($null -eq $regDetails -or @($regDetails).Count -eq 0) {
            $errors.Add("userRegistrationDetails returned no data; tenant may lack required Entra P1/P2 license.")
            $status = "Unavailable"
        }
        else {
            $allUsers = @($regDetails)
            $totalUsers = $allUsers.Count
            $mfaRegistered = @($allUsers | Where-Object { $_.isMfaRegistered -eq $true }).Count
            $mfaCapable = @($allUsers | Where-Object { $_.isMfaCapable -eq $true }).Count
            $passwordless = @($allUsers | Where-Object { $_.isPasswordlessCapable -eq $true }).Count
            $adminUsers = @($allUsers | Where-Object { $_.isAdmin -eq $true })
            $adminMfa = @($adminUsers | Where-Object { $_.isMfaRegistered -eq $true }).Count

            $mfaDetails = @{
                TotalUsers              = $totalUsers
                MfaRegistered           = $mfaRegistered
                MfaCapable              = $mfaCapable
                PasswordlessCapable     = $passwordless
                PrivilegedUsers         = $adminUsers.Count
                PrivilegedMfaRegistered = $adminMfa
                MfaRegistrationRate     = if ($totalUsers -gt 0) { [math]::Round($mfaRegistered / $totalUsers * 100, 1) } else { 0 }
                PasswordlessRate        = if ($totalUsers -gt 0) { [math]::Round($passwordless / $totalUsers * 100, 1) } else { 0 }
                PrivilegedMfaRate       = if ($adminUsers.Count -gt 0) { [math]::Round($adminMfa / $adminUsers.Count * 100, 1) } else { 100 }
            }
        }

        return New-CollectorResult -Domain "MFA" -Status $status -Metrics $mfaDetails -Configuration @{ SampleSize = $mfaDetails.TotalUsers } -Errors $errors.ToArray()
    }
    catch {
        $errType = if ($_ -is [PSCustomObject] -and $_.Type) { $_.Type } else { "Failed" }
        $errMsg = if ($_ -is [PSCustomObject] -and $_.Message) { $_.Message } else { $_.ToString() }

        Write-Verbose "[$TenantName][MFA] Collector $errType : $errMsg"
        return New-CollectorResult -Domain "MFA" -Status $errType -Errors @($errMsg)
    }
}

Function Invoke-PIMConfigurationCollector {
    [CmdletBinding()]
    param (
        [string]$Token,
        [string]$TenantId,
        [string]$TenantName
    )

    $graphBase = "https://graph.microsoft.com/v1.0"
    $errors = [System.Collections.Generic.List[string]]::new()
    $status = "Success"

    $pimData = @{
        ActiveAssignments    = @()
        EligibleAssignments  = @()
        PolicyAssignments    = @()
        PermanentCritical    = @()
        MissingMfaActivation = @()
        MissingApprovalRoles = @()
    }

    # -- Active role assignment schedules (includes permanent assignments)
    try {
        $activeSchedules = Invoke-GraphRequest -Token $Token -Uri "$graphBase/roleManagement/directory/roleAssignmentSchedules" -MaxPages 30
        $pimData.ActiveAssignments = @($activeSchedules)
    }
    catch {
        $errType = if ($_ -is [PSCustomObject] -and $_.Type) { $_.Type } else { "Failed" }
        $errMsg = if ($_ -is [PSCustomObject] -and $_.Message) { $_.Message } else { $_.ToString() }

        if ($errType -in "PermissionDenied", "Unavailable") {
            $errors.Add("roleAssignmentSchedules: $errType - $errMsg")
            $status = $errType

            return New-CollectorResult -Domain "PIM" -Status $status -Metrics @{ Note = "PIM data unavailable; check licensing (Entra P2 required) and permissions (RoleManagement.Read.Directory)." } -Errors $errors.ToArray()
        }
        else {
            $errors.Add("roleAssignmentSchedules error: $errMsg")
            $status = "PartialSuccess"
        }
    }

    # -- Eligible role assignment schedules
    try {
        $eligibleSchedules = Invoke-GraphRequest -Token $Token -Uri "$graphBase/roleManagement/directory/roleEligibilitySchedules" -MaxPages 30
        $pimData.EligibleAssignments = @($eligibleSchedules)
    }
    catch {
        $errType = if ($_ -is [PSCustomObject] -and $_.Type) { $_.Type } else { "Failed" }
        $errMsg = if ($_ -is [PSCustomObject] -and $_.Message) { $_.Message } else { $_.ToString() }
        $errors.Add("roleEligibilitySchedules error: $errType - $errMsg")
        $status = "PartialSuccess"
    }

    # -- PIM policy assignments (rules: MFA, approval, etc.)
    # Requires RoleManagementPolicy.Read.Directory
    try {
        $policyAssignments = Invoke-GraphRequest -Token $Token -Uri "$graphBase/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=policy(`$expand=rules)" -MaxPages 30
        $pimData.PolicyAssignments = @($policyAssignments)
    }
    catch {
        $errType = if ($_ -is [PSCustomObject] -and $_.Type) { $_.Type } else { "Failed" }
        $errMsg = if ($_ -is [PSCustomObject] -and $_.Message) { $_.Message } else { $_.ToString() }
        $errors.Add("roleManagementPolicyAssignments error: $errType - $errMsg")
        $status = "PartialSuccess"
    }

    # -- Derive permanent critical assignments (scheduled type = "Direct", no expiration, critical role)
    $permanentCritical = @($pimData.ActiveAssignments | Where-Object {
            $_.scheduleInfo.expiration.type -in @("noExpiration", $null) -and
            $_.assignmentType -eq "Assigned" -and
            $_.roleDefinitionId -in $Script:CriticalRoleIds.Keys
        })
    $pimData.PermanentCritical = $permanentCritical

    # -- Check MFA activation rule per policy
    $missingMfa = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pa in $pimData.PolicyAssignments) {
        if (-not $pa.policy.rules) { continue }

        $mfaRule = $pa.policy.rules | Where-Object { $_.id -eq "Enablement_EndUser_Assignment" }
        if ($mfaRule) {
            $hasMfa = $mfaRule.enabledRules -contains "Mfa"
            if (-not $hasMfa) {
                $missingMfa.Add([PSCustomObject]@{
                        RoleDefinitionId = $pa.roleDefinitionId
                        PolicyId         = $pa.policyId
                    })
            }
        }
    }
    $pimData.MissingMfaActivation = $missingMfa.ToArray()

    # -- Check approval rule for Global Admin
    $missingApproval = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pa in $pimData.PolicyAssignments) {
        # Only for Global Administrator
        if ($pa.roleDefinitionId -ne "62e90394-69f5-4237-9190-012177145e10") { continue }
        if (-not $pa.policy.rules) { continue }

        $approvalRule = $pa.policy.rules | Where-Object { $_.id -eq "Approval_EndUser_Assignment" }
        if ($approvalRule) {
            $approvalRequired = $approvalRule.setting.isApprovalRequired
            if (-not $approvalRequired) {
                $missingApproval.Add([PSCustomObject]@{
                        RoleDefinitionId = $pa.roleDefinitionId
                        RoleName         = "Global Administrator"
                        PolicyId         = $pa.policyId
                    })
            }
        }
    }
    $pimData.MissingApprovalRoles = $missingApproval.ToArray()

    $metrics = @{
        ActiveAssignmentCount     = $pimData.ActiveAssignments.Count
        EligibleAssignmentCount   = $pimData.EligibleAssignments.Count
        PermanentCriticalCount    = $pimData.PermanentCritical.Count
        MissingMfaActivationCount = $pimData.MissingMfaActivation.Count
        MissingApprovalCount      = $pimData.MissingApprovalRoles.Count
    }

    return New-CollectorResult -Domain "PIM" -Status $status -Metrics $metrics -Configuration $pimData -Errors $errors.ToArray()
}

Function Invoke-ExternalIdentityConfigurationCollector {
    [CmdletBinding()]
    param (
        [string]$Token,
        [string]$TenantId,
        [string]$TenantName
    )

    $graphBase = "https://graph.microsoft.com/v1.0"
    $errors = [System.Collections.Generic.List[string]]::new()
    $status = "Success"

    $extData = @{
        AuthorizationPolicy = $null
        CrossTenantDefault  = $null
        CrossTenantPartners = @()
    }

    # -- Authorization policy (guest invite restrictions, guest user role)
    # Requires Policy.Read.All
    try {
        $authPolicy = Invoke-GraphRequest -Token $Token -Uri "$graphBase/policies/authorizationPolicy"
        $extData.AuthorizationPolicy = $authPolicy
    }
    catch {
        $errType = if ($_ -is [PSCustomObject] -and $_.Type) { $_.Type } else { "Failed" }
        $errMsg = if ($_ -is [PSCustomObject] -and $_.Message) { $_.Message } else { $_.ToString() }
        $errors.Add("authorizationPolicy: $errType - $errMsg")
        $status = if ($errType -in "PermissionDenied", "Unavailable") { $errType } else { "PartialSuccess" }
    }

    # -- Cross-tenant access policy default settings
    try {
        $ctDefault = Invoke-GraphRequest -Token $Token -Uri "$graphBase/policies/crossTenantAccessPolicy/default"
        $extData.CrossTenantDefault = $ctDefault
    }
    catch {
        $errType = if ($_ -is [PSCustomObject] -and $_.Type) { $_.Type } else { "Failed" }
        $errMsg = if ($_ -is [PSCustomObject] -and $_.Message) { $_.Message } else { $_.ToString() }
        $errors.Add("crossTenantAccessPolicy/default: $errType - $errMsg")
        if ($status -eq "Success") { $status = "PartialSuccess" }
    }

    # -- Cross-tenant access policy partners
    try {
        $ctPartners = Invoke-GraphRequest -Token $Token -Uri "$graphBase/policies/crossTenantAccessPolicy/partners" -MaxPages 10
        $extData.CrossTenantPartners = @($ctPartners)
    }
    catch {
        $errType = if ($_ -is [PSCustomObject] -and $_.Type) { $_.Type } else { "Failed" }
        $errMsg = if ($_ -is [PSCustomObject] -and $_.Message) { $_.Message } else { $_.ToString() }
        $errors.Add("crossTenantAccessPolicy/partners: $errType - $errMsg")
        if ($status -eq "Success") { $status = "PartialSuccess" }
    }

    $metrics = @{
        AllowInvitesFrom        = if ($extData.AuthorizationPolicy) { $extData.AuthorizationPolicy.allowInvitesFrom } else { "Unknown" }
        GuestUserRoleId         = if ($extData.AuthorizationPolicy) { $extData.AuthorizationPolicy.guestUserRoleId } else { "Unknown" }
        GuestUserRole           = if ($extData.AuthorizationPolicy -and $Script:GuestUserRoleIds[$extData.AuthorizationPolicy.guestUserRoleId]) { $Script:GuestUserRoleIds[$extData.AuthorizationPolicy.guestUserRoleId] } else { "Unknown" }
        CrossTenantPartnerCount = $extData.CrossTenantPartners.Count
    }

    return New-CollectorResult -Domain "ExternalIdentity" -Status $status -Metrics $metrics -Configuration $extData -Errors $errors.ToArray()
}

#endregion Collectors

#region Normalization

Function Get-NormalisedCAIntent {
    param ([PSCustomObject[]]$Policies)

    # Determine effective security intent from policy collection
    # We assess intent, not policy name

    $enabled = @($Policies | Where-Object { $_.state -eq "enabled" })
    $reportOnly = @($Policies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" })

    $intent = @{
        HasLegacyAuthBlock      = $false
        LegacyAuthPolicies      = @()
        HasAdminMfaPolicy       = $false
        AdminMfaPolicies        = @()
        HasCompliantDevice      = $false
        CompliantDevicePolicies = @()
        ReportOnlyHighRisk      = @()
        DisabledHighRisk        = @()
    }

    # Legacy authentication: policy blocks exchange active sync / other legacy clients
    $legacyBlocking = @($enabled | Where-Object {
            $p = $_
            $clientTypes = $p.conditions.clientAppTypes
            $blockLegacy = $clientTypes -contains "exchangeActiveSync" -or $clientTypes -contains "other"
            $isBlock = $p.grantControls -eq $null -or $p.grantControls.builtInControls -contains "block"
            $blockLegacy -and $isBlock
        })
    $intent.HasLegacyAuthBlock = $legacyBlocking.Count -gt 0
    $intent.LegacyAuthPolicies = $legacyBlocking

    # Admin MFA: policy requiring MFA for directory roles / admin users
    $adminMfa = @($enabled | Where-Object {
            $p = $_
            $targetsRoles = ($p.conditions.users.includeRoles -and $p.conditions.users.includeRoles.Count -gt 0) -or
            ($p.conditions.users.includeUsers -contains "All" -or $p.conditions.users.includeGroups -and $p.conditions.users.includeGroups.Count -gt 0)
            $requiresMfa = $p.grantControls -and $p.grantControls.builtInControls -contains "mfa"
            $targetsRoles -and $requiresMfa
        })
    $intent.HasAdminMfaPolicy = $adminMfa.Count -gt 0
    $intent.AdminMfaPolicies = $adminMfa

    # Compliant device
    $compliantDevice = @($enabled | Where-Object {
            $p = $_
            $p.grantControls -and ($p.grantControls.builtInControls -contains "compliantDevice" -or $p.grantControls.builtInControls -contains "domainJoinedDevice")
        })
    $intent.HasCompliantDevice = $compliantDevice.Count -gt 0
    $intent.CompliantDevicePolicies = $compliantDevice

    # Report-only policies that appear to address high-risk scenarios
    $intent.ReportOnlyHighRisk = @($reportOnly | Where-Object {
            $p = $_
            ($p.grantControls -and ($p.grantControls.builtInControls -contains "mfa" -or $p.grantControls.builtInControls -contains "block")) -or
            ($p.conditions.signInRiskLevels -and $p.conditions.signInRiskLevels.Count -gt 0)
        })

    return $intent
}

#endregion Normalization

#region Drift Detection

Function Invoke-DriftDetection {
    [CmdletBinding()]
    param (
        [string]$TenantId,
        [string]$TenantName,
        [hashtable]$DomainResults,
        [PSCustomObject]$Baseline
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($domain in $DomainResults.Keys) {
        $result = $DomainResults[$domain]

        # If domain collector failed critically, record assessment limitation — NOT a security finding
        if ($result.Status -in @("Failed", "PermissionDenied", "Unavailable")) {
            Write-Verbose "[$TenantName][$domain] Skipping drift detection: Status=$($result.Status)"
            continue
        }

        $domainFindings = switch ($domain) {
            "ConditionalAccess" { Get-CaDriftFindings  -TenantId $TenantId -TenantName $TenantName -CollectorResult $result -Baseline $Baseline }
            "MFA" { Get-MfaDriftFindings  -TenantId $TenantId -TenantName $TenantName -CollectorResult $result -Baseline $Baseline }
            "PIM" { Get-PimDriftFindings  -TenantId $TenantId -TenantName $TenantName -CollectorResult $result -Baseline $Baseline }
            "ExternalIdentity" { Get-ExtDriftFindings  -TenantId $TenantId -TenantName $TenantName -CollectorResult $result -Baseline $Baseline }
        }
        foreach ($f in $domainFindings) {
            if ($null -ne $f) { $findings.Add($f) }
        }
    }

    return $findings
}

Function New-DriftFinding {
    param (
        [string]$FindingId,
        [string]$TenantId,
        [string]$TenantName,
        [string]$Domain,
        [string]$ControlId,
        [string]$DriftType,
        [string]$Title,
        [string]$Severity,
        [string]$BusinessImpact,
        [string]$BaselineValue,
        [string]$ActualValue,
        [string]$TechnicalDetail,
        [string]$Recommendation,
        [string]$RemediationPriority,
        [string]$RemediationEffort,
        [string[]]$References = @()
    )

    return [PSCustomObject]@{
        FindingId           = $FindingId
        TenantId            = $TenantId
        TenantName          = $TenantName
        Domain              = $Domain
        ControlId           = $ControlId
        DriftType           = $DriftType
        Title               = $Title
        Severity            = $Severity
        BusinessImpact      = $BusinessImpact
        BaselineValue       = $BaselineValue
        ActualValue         = $ActualValue
        TechnicalDetail     = $TechnicalDetail
        Recommendation      = $Recommendation
        RemediationPriority = $RemediationPriority
        RemediationEffort   = $RemediationEffort
        References          = $References
    }
}

Function Get-CaDriftFindings {
    param (
        [string]$TenantId,
        [string]$TenantName,
        [PSCustomObject]$CollectorResult,
        [PSCustomObject]$Baseline
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not $CollectorResult.Configuration.Policies) { return $findings }

    $policies = @($CollectorResult.Configuration.Policies)
    $intent = Get-NormalisedCAIntent -Policies $policies

    # CA-001: Legacy Authentication Blocking
    if ($Baseline.ConditionalAccess.BlockLegacyAuthentication -and -not $intent.HasLegacyAuthBlock) {
        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-CA-001" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "ConditionalAccess" `
                    -ControlId           "CA-BASELINE-001" `
                    -DriftType           "CriticalDrift" `
                    -Title               "Legacy Authentication Is Not Blocked" `
                    -Severity            "Critical" `
                    -BusinessImpact      "Legacy authentication protocols do not support modern MFA and are a primary attack vector for credential-based breaches. Blocking legacy auth is a foundational security control." `
                    -BaselineValue       "Enabled (legacy auth blocked)" `
                    -ActualValue         "No enabled Conditional Access policy blocks legacy authentication" `
                    -TechnicalDetail     "Assessment found $($CollectorResult.Metrics.TotalPolicies) CA policies ($($CollectorResult.Metrics.EnabledPolicies) enabled). None contain conditions targeting exchangeActiveSync/other clients with a block grant control." `
                    -Recommendation      "Create a Conditional Access policy that targets all users, sets clientAppTypes to exchangeActiveSync and other, and applies a Block grant control. Pilot in report-only mode first to identify affected legacy clients." `
                    -RemediationPriority "P0" `
                    -RemediationEffort   "Low" `
                    -References          @("https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication")))
    }

    # CA-002: Admin MFA Coverage
    if ($Baseline.ConditionalAccess.RequireMFAForAdmins -and -not $intent.HasAdminMfaPolicy) {
        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-CA-002" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "ConditionalAccess" `
                    -ControlId           "CA-BASELINE-002" `
                    -DriftType           "CriticalDrift" `
                    -Title               "No Conditional Access Policy Enforces MFA for Administrators" `
                    -Severity            "Critical" `
                    -BusinessImpact      "Administrative accounts without enforced MFA are the highest-value targets for identity attacks. A compromised admin account can result in full tenant takeover." `
                    -BaselineValue       "Enabled (MFA required for admins)" `
                    -ActualValue         "No enabled CA policy targets directory roles or all users with an MFA grant control" `
                    -TechnicalDetail     "Checked $($CollectorResult.Metrics.EnabledPolicies) enabled policies for inclusion of directory roles with MFA grant requirement. No qualifying policy found." `
                    -Recommendation      "Deploy the 'Require MFA for administrators' Microsoft-managed policy or create a custom policy targeting all directory role members with MFA as a grant requirement." `
                    -RemediationPriority "P0" `
                    -RemediationEffort   "Low" `
                    -References          @("https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa")))
    }

    # CA-003: Compliant Device Requirement
    if ($Baseline.ConditionalAccess.RequireCompliantDevice -and -not $intent.HasCompliantDevice) {
        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-CA-003" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "ConditionalAccess" `
                    -ControlId           "CA-BASELINE-003" `
                    -DriftType           "SignificantDrift" `
                    -Title               "No Conditional Access Policy Requires a Compliant or Joined Device" `
                    -Severity            "High" `
                    -BusinessImpact      "Without device compliance checks, corporate data can be accessed from unmanaged or compromised devices, increasing the risk of data exfiltration." `
                    -BaselineValue       "Enabled (compliant/joined device required)" `
                    -ActualValue         "No enabled CA policy includes compliantDevice or domainJoinedDevice in grant controls" `
                    -TechnicalDetail     "Reviewed $($CollectorResult.Metrics.EnabledPolicies) enabled CA policies. None specify compliantDevice or domainJoinedDevice as a grant control requirement." `
                    -Recommendation      "Implement a Conditional Access policy requiring device compliance for access to corporate resources. Ensure Intune or a compatible MDM solution is enrolled for device compliance evaluation." `
                    -RemediationPriority "P1" `
                    -RemediationEffort   "Medium" `
                    -References          @("https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device")))
    }

    # CA-004: Required policies stuck in report-only
    if ($intent.ReportOnlyHighRisk.Count -gt 0) {
        $reportOnlyNames = ($intent.ReportOnlyHighRisk | ForEach-Object { $_.displayName }) -join ", "
        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-CA-004" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "ConditionalAccess" `
                    -ControlId           "CA-BASELINE-004" `
                    -DriftType           "MinorDrift" `
                    -Title               "Security-Relevant Conditional Access Policies Are in Report-Only Mode" `
                    -Severity            "Medium" `
                    -BusinessImpact      "Policies in report-only mode do not enforce controls. If deployed permanently in this state, they provide a false sense of coverage." `
                    -BaselineValue       "Security policies should be enforced (enabled)" `
                    -ActualValue         "$($intent.ReportOnlyHighRisk.Count) high-value CA policies in report-only mode: $reportOnlyNames" `
                    -TechnicalDetail     "Report-only policies log what would have happened without taking enforcement action." `
                    -Recommendation      "Review report-only CA policies and transition to enforced state after validating impact through sign-in logs." `
                    -RemediationPriority "P2" `
                    -RemediationEffort   "Low" `
                    -References          @("https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only")))
    }

    return $findings
}

Function Get-MfaDriftFindings {
    param (
        [string]$TenantId,
        [string]$TenantName,
        [PSCustomObject]$CollectorResult,
        [PSCustomObject]$Baseline
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($CollectorResult.Status -eq "Unavailable" -or $CollectorResult.Metrics.TotalUsers -eq 0) { return $findings }

    $metrics = $CollectorResult.Metrics

    # MFA-001: Registration rate below baseline
    $baselineRate = $Baseline.MFA.MinimumRegistrationRate
    $actualRate = $metrics.MfaRegistrationRate

    if ($actualRate -lt $baselineRate) {
        $gap = $baselineRate - $actualRate
        $driftType = if ($gap -ge 20) { "CriticalDrift" } elseif ($gap -ge 10) { "SignificantDrift" } else { "MinorDrift" }
        $severity = if ($gap -ge 20) { "Critical" } elseif ($gap -ge 10) { "High" } else { "Medium" }

        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-MFA-001" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "MFA" `
                    -ControlId           "MFA-BASELINE-001" `
                    -DriftType           $driftType `
                    -Title               "MFA Registration Rate Is Below Enterprise Baseline" `
                    -Severity            $severity `
                    -BusinessImpact      "Users without MFA registration are vulnerable to phishing and credential-based attacks. Lower registration rates directly increase tenant risk exposure." `
                    -BaselineValue       ">= $baselineRate%" `
                    -ActualValue         "$actualRate% ($($metrics.MfaRegistered) of $($metrics.TotalUsers) users)" `
                    -TechnicalDetail     "Registration rate gap: $($gap)%. Passwordless capable: $($metrics.PasswordlessCapable) users ($($metrics.PasswordlessRate)%)." `
                    -Recommendation      "Enforce MFA registration via Conditional Access (block access until registered) or the Registration Campaign feature in Entra ID. Target users without isMfaRegistered=true." `
                    -RemediationPriority $(if ($severity -eq "Critical") { "P0" } elseif ($severity -eq "High") { "P1" } else { "P2" }) `
                    -RemediationEffort   "Medium" `
                    -References          @("https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings#mfa-registration-campaign")))
    }

    # MFA-002: Passwordless adoption below target
    $passwordlessTarget = $Baseline.MFA.PasswordlessTarget
    $passwordlessRate = $metrics.PasswordlessRate

    if ($passwordlessRate -lt $passwordlessTarget) {
        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-MFA-002" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "MFA" `
                    -ControlId           "MFA-BASELINE-002" `
                    -DriftType           "MinorDrift" `
                    -Title               "Passwordless Authentication Adoption Is Below Target" `
                    -Severity            "Low" `
                    -BusinessImpact      "Passwordless authentication eliminates phishable credentials. Low adoption means users remain dependent on passwords and traditional MFA methods vulnerable to MFA fatigue attacks." `
                    -BaselineValue       ">= $passwordlessTarget%" `
                    -ActualValue         "$passwordlessRate% ($($metrics.PasswordlessCapable) of $($metrics.TotalUsers) users)" `
                    -TechnicalDetail     "Passwordless-capable users have registered FIDO2, Microsoft Authenticator (passwordless), or Windows Hello for Business." `
                    -Recommendation      "Run a passwordless deployment campaign using Microsoft Authenticator number matching and FIDO2 security keys for high-value users first." `
                    -RemediationPriority "P3" `
                    -RemediationEffort   "Medium" `
                    -References          @("https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless")))
    }

    # MFA-003: Privileged users without MFA
    if ($metrics.PrivilegedUsers -gt 0 -and $metrics.PrivilegedMfaRate -lt 100) {
        $unprotectedCount = $metrics.PrivilegedUsers - $metrics.PrivilegedMfaRegistered
        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-MFA-003" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "MFA" `
                    -ControlId           "MFA-BASELINE-003" `
                    -DriftType           "CriticalDrift" `
                    -Title               "Privileged Users Detected Without MFA Registration" `
                    -Severity            "Critical" `
                    -BusinessImpact      "Administrator accounts without MFA are the highest-risk accounts in the tenant. Compromise of a single unprotected admin account can result in full tenant takeover." `
                    -BaselineValue       "100% of privileged users MFA registered" `
                    -ActualValue         "$($metrics.PrivilegedMfaRate)% — $unprotectedCount privileged user(s) without MFA registration" `
                    -TechnicalDetail     "Graph API isAdmin=true users without isMfaRegistered=true. Total admin users: $($metrics.PrivilegedUsers), MFA registered: $($metrics.PrivilegedMfaRegistered)." `
                    -Recommendation      "Immediately require MFA for all administrator accounts. Use Conditional Access with admin role targeting and block access until MFA is registered." `
                    -RemediationPriority "P0" `
                    -RemediationEffort   "Low" `
                    -References          @("https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning")))
    }

    return $findings
}

Function Get-PimDriftFindings {
    param (
        [string]$TenantId,
        [string]$TenantName,
        [PSCustomObject]$CollectorResult,
        [PSCustomObject]$Baseline
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($CollectorResult.Status -in @("Unavailable", "PermissionDenied")) { return $findings }

    $config = $CollectorResult.Configuration

    # PIM-001: Permanent critical role assignments
    if ($Baseline.PIM.RequireEligibleAssignments -and $config.PermanentCritical -and $config.PermanentCritical.Count -gt 0) {

        #
        # FIX 2 of 3 — Replaced PS 7.0-only ?? (null coalescing) operator with PS 5.1-safe equivalent.
        # Original: $Script:CriticalRoleIds[$_.roleDefinitionId] ?? $_.roleDefinitionId
        # This fails on PowerShell 5.1 with a parse error. The logic is identical; if the hashtable
        # lookup returns a non-empty value use it, otherwise fall back to the raw GUID string.
        #
        $criticalRoleNames = ($config.PermanentCritical | ForEach-Object {
                $resolvedName = $Script:CriticalRoleIds[$_.roleDefinitionId]
                if ($resolvedName) { $resolvedName } else { $_.roleDefinitionId }
            } | Select-Object -Unique) -join ", "

        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-PIM-001" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "PIM" `
                    -ControlId           "PIM-BASELINE-001" `
                    -DriftType           "CriticalDrift" `
                    -Title               "Permanent Assignments Found for Critical Directory Roles" `
                    -Severity            "Critical" `
                    -BusinessImpact      "Permanent role assignments mean privileged access is always active, increasing the attack surface. If credentials are compromised, the attacker has immediate persistent privileged access." `
                    -BaselineValue       "All critical roles use eligible (just-in-time) assignments" `
                    -ActualValue         "$($config.PermanentCritical.Count) permanent assignment(s) found in: $criticalRoleNames" `
                    -TechnicalDetail     "roleAssignmentSchedules with scheduleInfo.expiration.type=noExpiration and assignmentType=Assigned for critical role IDs." `
                    -Recommendation      "Convert permanent role assignments to PIM-eligible assignments. Require users to activate roles just-in-time with MFA and justification." `
                    -RemediationPriority "P0" `
                    -RemediationEffort   "Medium" `
                    -References          @("https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user")))
    }

    # PIM-002: MFA not required at activation
    if ($Baseline.PIM.RequireMFAActivation -and $config.MissingMfaActivation -and $config.MissingMfaActivation.Count -gt 0) {
        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-PIM-002" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "PIM" `
                    -ControlId           "PIM-BASELINE-002" `
                    -DriftType           "SignificantDrift" `
                    -Title               "PIM Role Activation Does Not Require MFA for One or More Roles" `
                    -Severity            "High" `
                    -BusinessImpact      "Without MFA at activation, a compromised eligible account can activate privileged roles without additional authentication challenge, bypassing a critical compensating control." `
                    -BaselineValue       "MFA required for all role activations" `
                    -ActualValue         "$($config.MissingMfaActivation.Count) role policy/policies do not require MFA in the Enablement_EndUser_Assignment rule" `
                    -TechnicalDetail     "roleManagementPolicyAssignments reviewed. Activation rules (Enablement_EndUser_Assignment) checked for 'Mfa' in enabledRules collection." `
                    -Recommendation      "Update PIM role settings for each affected role: Settings → Activation → Require Azure MFA. Apply to all critical and privileged roles." `
                    -RemediationPriority "P1" `
                    -RemediationEffort   "Low" `
                    -References          @("https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings")))
    }

    # PIM-003: No approval required for Global Administrator
    if ($config.MissingApprovalRoles -and $config.MissingApprovalRoles.Count -gt 0) {
        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-PIM-003" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "PIM" `
                    -ControlId           "PIM-BASELINE-003" `
                    -DriftType           "SignificantDrift" `
                    -Title               "Global Administrator Role Activation Does Not Require Approval" `
                    -Severity            "High" `
                    -BusinessImpact      "Without approval workflow, any eligible Global Administrator can self-activate the most powerful role in the tenant. Approval provides a human checkpoint before privilege escalation." `
                    -BaselineValue       "Approval required for Global Administrator activation" `
                    -ActualValue         "Global Administrator PIM policy (Approval_EndUser_Assignment) has isApprovalRequired=false" `
                    -TechnicalDetail     "Checked roleManagementPolicyAssignment for roleDefinitionId=62e90394-69f5-4237-9190-012177145e10 (Global Administrator). Approval rule isApprovalRequired is false." `
                    -Recommendation      "Configure approval workflow for Global Administrator in PIM: Role settings → Require approval to activate → Add designated approvers." `
                    -RemediationPriority "P1" `
                    -RemediationEffort   "Low" `
                    -References          @("https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-approval-workflow")))
    }

    return $findings
}

Function Get-ExtDriftFindings {
    param (
        [string]$TenantId,
        [string]$TenantName,
        [PSCustomObject]$CollectorResult,
        [PSCustomObject]$Baseline
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not $CollectorResult.Configuration.AuthorizationPolicy) { return $findings }

    $authPolicy = $CollectorResult.Configuration.AuthorizationPolicy
    $metrics = $CollectorResult.Metrics

    # EXT-001: Guest invitation restriction
    if ($Baseline.ExternalIdentity.RestrictExternalCollaboration) {
        $allowInvites = $authPolicy.allowInvitesFrom

        # Compliant: only admins (or none) can invite
        $isCompliant = $allowInvites -in @("none", "adminsAndGuestInviters")

        if (-not $isCompliant) {
            $driftType = if ($allowInvites -eq "everyone") { "CriticalDrift" } else { "MinorDrift" }
            $severity = if ($allowInvites -eq "everyone") { "High" } else { "Medium" }

            $findings.Add((New-DriftFinding `
                        -FindingId           "DRIFT-EXT-001" `
                        -TenantId            $TenantId `
                        -TenantName          $TenantName `
                        -Domain              "ExternalIdentity" `
                        -ControlId           "EXT-BASELINE-001" `
                        -DriftType           $driftType `
                        -Title               "Guest Invitation Permissions Are Insufficiently Restricted" `
                        -Severity            $severity `
                        -BusinessImpact      "Allowing all members (or anyone) to invite guests can lead to uncontrolled external access, shadow IT collaboration, and data exposure to unauthorised parties." `
                        -BaselineValue       "adminsAndGuestInviters or none" `
                        -ActualValue         $allowInvites `
                        -TechnicalDetail     "policies/authorizationPolicy.allowInvitesFrom = '$allowInvites'. Baseline requires 'adminsAndGuestInviters' or 'none'." `
                        -Recommendation      "Set External collaboration settings → Guest invite settings to 'Only users assigned to specific admin roles can invite guest users' or 'No one in the organization can invite guest users'." `
                        -RemediationPriority $(if ($severity -eq "High") { "P1" } else { "P2" }) `
                        -RemediationEffort   "Low" `
                        -References          @("https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure")))
        }
    }

    # EXT-002: Guest user role is too permissive
    $guestRoleId = $authPolicy.guestUserRoleId
    $guestRole = $Script:GuestUserRoleIds[$guestRoleId]

    if ($guestRole -eq "User") {
        # Most permissive: guests have same access as member users
        $findings.Add((New-DriftFinding `
                    -FindingId           "DRIFT-EXT-002" `
                    -TenantId            $TenantId `
                    -TenantName          $TenantName `
                    -Domain              "ExternalIdentity" `
                    -ControlId           "EXT-BASELINE-002" `
                    -DriftType           "SignificantDrift" `
                    -Title               "Guest Users Are Assigned Full Member-Equivalent Permissions" `
                    -Severity            "High" `
                    -BusinessImpact      "When guests have member-level permissions they can enumerate users, groups, and applications in the directory, creating a significant information disclosure risk." `
                    -BaselineValue       "Guest user access should be restricted (GuestUser or RestrictedGuest role)" `
                    -ActualValue         "guestUserRoleId = $guestRoleId (User — same access as members)" `
                    -TechnicalDetail     "policies/authorizationPolicy.guestUserRoleId maps to role template 'User', granting guests the same directory read permissions as member users." `
                    -Recommendation      "Change guest user access level to 'Guest users have limited access to properties and memberships of directory objects' (GuestUser) or 'Guest user access is restricted to properties and memberships of their own directory objects' (RestrictedGuest)." `
                    -RemediationPriority "P1" `
                    -RemediationEffort   "Low" `
                    -References          @("https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure")))
    }

    # EXT-003: Cross-tenant access allows unrestricted inbound
    $ctDefault = $CollectorResult.Configuration.CrossTenantDefault
    if ($ctDefault -and $ctDefault.b2bCollaborationInbound) {
        $inboundAccess = $ctDefault.b2bCollaborationInbound.usersAndGroups.accessType
        if ($inboundAccess -eq "allowed") {
            $findings.Add((New-DriftFinding `
                        -FindingId           "DRIFT-EXT-003" `
                        -TenantId            $TenantId `
                        -TenantName          $TenantName `
                        -Domain              "ExternalIdentity" `
                        -ControlId           "EXT-BASELINE-003" `
                        -DriftType           "MinorDrift" `
                        -Title               "Cross-Tenant Default Inbound B2B Collaboration Is Open to All External Organisations" `
                        -Severity            "Medium" `
                        -BusinessImpact      "An open default allows any Microsoft Entra organisation to initiate B2B collaboration without per-partner approval, increasing the risk of unsanctioned access." `
                        -BaselineValue       "Inbound B2B collaboration restricted (not open to all)" `
                        -ActualValue         "crossTenantAccessPolicy/default.b2bCollaborationInbound.usersAndGroups.accessType = 'allowed'" `
                        -TechnicalDetail     "Default cross-tenant policy permits inbound collaboration from all external tenants. Partner-specific overrides may provide additional restriction but the default is permissive." `
                        -Recommendation      "Review whether the open default is intentional. For organisations not operating as a multi-tenant org, consider restricting the default inbound policy and using explicit partner configurations for trusted tenants." `
                        -RemediationPriority "P2" `
                        -RemediationEffort   "Medium" `
                        -References          @("https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-settings-b2b-collaboration")))
        }
    }

    return $findings
}

#endregion Drift Detection

#region Risk and Scoring

Function Get-TenantRiskScore {
    [CmdletBinding()]
    param (
        [System.Collections.Generic.List[PSCustomObject]]$Findings,
        [hashtable]$DomainResults,
        [string[]]$ActiveDomains
    )

    # Deductions per severity
    $deductions = @{ Critical = 20; High = 10; Medium = 5; Low = 2; Info = 0 }

    $totalDeduction = 0
    $criticalCount = 0
    $highCount = 0
    $mediumCount = 0
    $lowCount = 0
    $infoCount = 0

    foreach ($f in $Findings) {
        $d = $deductions[$f.Severity]
        if ($null -eq $d) { $d = 0 }
        $totalDeduction += $d

        switch ($f.Severity) {
            "Critical" { $criticalCount++ }
            "High" { $highCount++ }
            "Medium" { $mediumCount++ }
            "Low" { $lowCount++ }
            default { $infoCount++ }
        }
    }

    # Count assessable controls per active domain
    $controlsMap = @{
        "ConditionalAccess" = 5
        "MFA"               = 3
        "PIM"               = 3
        "ExternalIdentity"  = 3
    }

    $totalControls = 0
    $notAssessedCount = 0

    foreach ($domain in $ActiveDomains) {
        #
        # FIX 3 of 3 — Replaced PS 7.0-only ?? (null coalescing) operator with PS 5.1-safe equivalent.
        # Original: $controlsMap[$domain] ?? 0
        # This fails on PowerShell 5.1 with a parse error.
        # The logic is identical: look up the controls count; default to 0 if the key is absent.
        #
        $domainControlCount = $controlsMap[$domain]
        if (-not $domainControlCount) { $domainControlCount = 0 }
        $totalControls += $domainControlCount

        $result = $DomainResults[$domain]
        if ($result -and $result.Status -in @("Failed", "PermissionDenied", "Unavailable")) {
            $notAssessedCount += $domainControlCount
        }
    }

    $driftedControls = $Findings.Count
    $compliantControls = $totalControls - $driftedControls - $notAssessedCount
    if ($compliantControls -lt 0) { $compliantControls = 0 }

    $rawScore = [math]::Max(0, 100 - $totalDeduction)
    $coveragePct = if ($totalControls -gt 0) { [math]::Round(($totalControls - $notAssessedCount) / $totalControls * 100, 1) } else { 0 }

    $domainStatuses = [ordered]@{}
    foreach ($domain in $ActiveDomains) {
        $result = $DomainResults[$domain]
        $domainStatuses[$domain] = if ($result) { $result.Status } else { "NotAssessed" }
    }

    return [PSCustomObject]@{
        AlignmentScore      = $rawScore
        TotalDeduction      = $totalDeduction
        TotalControls       = $totalControls
        CompliantControls   = $compliantControls
        DriftedControls     = $driftedControls
        CriticalDrifts      = $criticalCount
        HighDrifts          = $highCount
        MediumDrifts        = $mediumCount
        LowDrifts           = $lowCount
        InfoDrifts          = $infoCount
        NotAssessedControls = $notAssessedCount
        CoveragePercentage  = $coveragePct
        DomainStatuses      = $domainStatuses
    }
}

Function Get-EnterpriseScore {
    [CmdletBinding()]
    param (
        [System.Collections.Generic.List[PSCustomObject]]$TenantResults
    )

    # Enterprise score: population-weighted average of tenant alignment scores
    # Weighting method: each tenant carries equal weight in V1 (equal-weighted average)
    # Tenants that failed authentication entirely are excluded from the weighted average
    # but counted in the population statistics.

    $scoredTenants = @($TenantResults | Where-Object { $_.Score -ne $null })
    $enterpriseScore = 0

    if ($scoredTenants.Count -gt 0) {
        $sum = ($scoredTenants | ForEach-Object { $_.Score.AlignmentScore } | Measure-Object -Sum).Sum
        $enterpriseScore = [math]::Round($sum / $scoredTenants.Count, 1)
    }

    $allFindings = $TenantResults | ForEach-Object { $_.Findings } | Where-Object { $_ }
    $criticalCount = @($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = @($allFindings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = @($allFindings | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = @($allFindings | Where-Object { $_.Severity -eq "Low" }).Count

    $totalTenants = $TenantResults.Count
    $completedTenants = @($TenantResults | Where-Object { $_.Status -eq "Completed" }).Count
    $failedTenants = @($TenantResults | Where-Object { $_.Status -eq "Failed" }).Count

    $fullyCompliant = @($scoredTenants | Where-Object {
            $_.Score -and $_.Score.DriftedControls -eq 0 -and $_.Score.CoveragePercentage -ge 80
        }).Count

    $avgCoverage = if ($scoredTenants.Count -gt 0) {
        [math]::Round(($scoredTenants | ForEach-Object { $_.Score.CoveragePercentage } | Measure-Object -Average).Average, 1)
    }
    else { 0 }

    $baselineCompliance = if ($scoredTenants.Count -gt 0) {
        $totalControls = ($scoredTenants | ForEach-Object { $_.Score.TotalControls } | Measure-Object -Sum).Sum
        $compliantTotal = ($scoredTenants | ForEach-Object { $_.Score.CompliantControls } | Measure-Object -Sum).Sum
        if ($totalControls -gt 0) { [math]::Round($compliantTotal / $totalControls * 100, 1) } else { 0 }
    }
    else { 0 }

    return [PSCustomObject]@{
        AlignmentScore        = $enterpriseScore
        BaselineCompliance    = $baselineCompliance
        WeightingMethod       = "EqualWeight_V1"
        WeightingNote         = "Each tenant carries equal weight. V2 will support user-count or risk-tier weighting."
        TotalTenants          = $totalTenants
        ScoredTenants         = $scoredTenants.Count
        CompletedTenants      = $completedTenants
        FailedTenants         = $failedTenants
        FullyCompliantTenants = $fullyCompliant
        CriticalDrifts        = $criticalCount
        HighDrifts            = $highCount
        MediumDrifts          = $mediumCount
        LowDrifts             = $lowCount
        TotalFindings         = @($allFindings).Count
        AverageCoverage       = $avgCoverage
    }
}

#endregion Risk and Scoring

#region Graph Nodes and Edges (V1 — summary level, schema-ready for V2)

Function Get-GraphNodes {
    param ([System.Collections.Generic.List[PSCustomObject]]$TenantResults)

    $nodes = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($t in $TenantResults) {
        $nodes.Add([PSCustomObject]@{
                Id         = "tenant:$($t.TenantId)"
                Type       = "Tenant"
                Label      = $t.TenantName
                TenantId   = $t.TenantId
                Score      = if ($t.Score) { $t.Score.AlignmentScore } else { $null }
                Properties = @{
                    BusinessUnit     = $t.BusinessUnit
                    AssessmentStatus = $t.Status
                }
            })
    }

    return $nodes
}

Function Get-GraphEdges {
    param (
        [System.Collections.Generic.List[PSCustomObject]]$TenantResults,
        [string]$AssessmentId
    )

    # V1: no meaningful edges (single root enterprise node → tenant nodes)
    # Schema ready for V2 cross-tenant trust relationships, PIM delegation edges, etc.
    $edges = [System.Collections.Generic.List[PSCustomObject]]::new()

    $edges.Add([PSCustomObject]@{
            Source     = "enterprise:root"
            Target     = "assessment:$AssessmentId"
            Type       = "Assessment"
            Properties = @{ Version = $Script:AssessmentVersion }
        })

    return $edges
}

#endregion Graph Nodes and Edges

#region Reporting

Function Export-FindingsCsv {
    param (
        [PSCustomObject[]]$Findings,
        [string]$Path
    )

    if (-not $Findings -or @($Findings).Count -eq 0) {
        Write-Verbose "No findings to export to CSV."
        @() | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        return
    }

    try {
        $Findings | Select-Object FindingId, TenantId, TenantName, Domain, ControlId, DriftType, Title,
        Severity, BusinessImpact, BaselineValue, ActualValue, TechnicalDetail,
        Recommendation, RemediationPriority, RemediationEffort |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

        Write-Verbose "Findings CSV: $Path ($(@($Findings).Count) findings)"
    }
    catch {
        Write-Warning "Failed to write Findings CSV to '$Path': $_"
    }
}

Function Export-MetricsCsv {
    param (
        [System.Collections.Generic.List[PSCustomObject]]$TenantResults,
        [PSCustomObject]$EnterpriseScore,
        [string]$Path
    )

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($t in $TenantResults) {
        $score = $t.Score

        $rows.Add([PSCustomObject]@{
                TenantId               = $t.TenantId
                TenantName             = $t.TenantName
                BusinessUnit           = $t.BusinessUnit
                AssessmentStatus       = $t.Status
                AlignmentScore         = if ($score) { $score.AlignmentScore } else { "" }
                TotalControls          = if ($score) { $score.TotalControls } else { "" }
                CompliantControls      = if ($score) { $score.CompliantControls } else { "" }
                DriftedControls        = if ($score) { $score.DriftedControls } else { "" }
                CriticalDrifts         = if ($score) { $score.CriticalDrifts } else { "" }
                HighDrifts             = if ($score) { $score.HighDrifts } else { "" }
                MediumDrifts           = if ($score) { $score.MediumDrifts } else { "" }
                LowDrifts              = if ($score) { $score.LowDrifts } else { "" }
                NotAssessedControls    = if ($score) { $score.NotAssessedControls } else { "" }
                CoveragePercentage     = if ($score) { $score.CoveragePercentage } else { "" }
                AssessmentStart        = $t.AssessmentStart
                AssessmentEnd          = if ($t.AssessmentEnd) { $t.AssessmentEnd } else { "" }
                CAStatus               = if ($t.Domains["ConditionalAccess"]) { $t.Domains["ConditionalAccess"].Status } else { "NotAssessed" }
                MFAStatus              = if ($t.Domains["MFA"]) { $t.Domains["MFA"].Status } else { "NotAssessed" }
                PIMStatus              = if ($t.Domains["PIM"]) { $t.Domains["PIM"].Status } else { "NotAssessed" }
                ExternalIdentityStatus = if ($t.Domains["ExternalIdentity"]) { $t.Domains["ExternalIdentity"].Status } else { "NotAssessed" }
            })
    }

    try {
        $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Verbose "Metrics CSV: $Path ($($rows.Count) tenant rows)"
    }
    catch {
        Write-Warning "Failed to write Metrics CSV to '$Path': $_"
    }
}

Function Export-AssessmentJson {
    param (
        [PSCustomObject]$Payload,
        [string]$Path
    )

    try {
        $serializablePayload = $Payload | Select-Object * -ExcludeProperty Tenants
        $serializablePayload | Add-Member -MemberType NoteProperty -Name Tenants -Value (
            $Payload.Tenants | ForEach-Object {
                $t = $_
                $t | Select-Object TenantId, TenantName, BusinessUnit,
                AssessmentStart, AssessmentEnd,
                Status, AuthStatus, Score, Errors,
                Findings,
                @{ N = 'Domains'; E = {
                        $summary = [ordered]@{}
                        foreach ($k in $t.Domains.Keys) {
                            $d = $t.Domains[$k]
                            $summary[$k] = [PSCustomObject]@{
                                Status      = $d.Status
                                CollectedAt = $d.CollectedAt
                                Metrics     = $d.Metrics
                                Errors      = $d.Errors
                            }
                        }
                        $summary
                    }
                }
            }
        )
        # Depth 10 handles nested CA policy objects
        $json = $Payload | ConvertTo-Json -Depth 10 -ErrorAction Stop
        $json | Out-File -LiteralPath $Path -Encoding UTF8 -Force -ErrorAction Stop
        Write-Verbose "JSON report: $Path"
    }
    catch {
        Write-Warning "Failed to write JSON report to '$Path': $_"
    }
}

#endregion Reporting

#region HTML Dashboard

Function Export-HtmlDashboard {
    [CmdletBinding()]
    param (
        [PSCustomObject]$Payload,
        [string]$Path,
        [string]$Timestamp
    )

    #-- Prepare data for injection
    $ent = $Payload.Enterprise

    # Severity colour helpers
    $scoreColor = if ($ent.AlignmentScore -ge 80) { "#3fb950" } elseif ($ent.AlignmentScore -ge 60) { "#d29922" } else { "#f85149" }
    $critColor = if ($ent.CriticalDrifts -gt 0) { "#f85149" } else { "#3fb950" }

    # Build tenant rows JSON (safe)
    $tenantRowsJson = ConvertTo-SafeJsonArray -Objects (
        $Payload.Tenants | ForEach-Object {
            $t = $_
            $score = $t.Score

            [PSCustomObject]@{
                id        = $t.TenantId
                name      = $t.TenantName
                bu        = if ($t.BusinessUnit) { $t.BusinessUnit } else { "" }
                status    = $t.Status
                score     = if ($score) { $score.AlignmentScore } else { -1 }
                critical  = if ($score) { $score.CriticalDrifts } else { 0 }
                high      = if ($score) { $score.HighDrifts } else { 0 }
                medium    = if ($score) { $score.MediumDrifts } else { 0 }
                low       = if ($score) { $score.LowDrifts } else { 0 }
                findings  = if ($score) { $score.DriftedControls } else { 0 }
                coverage  = if ($score) { $score.CoveragePercentage } else { 0 }
                caStatus  = if ($t.Domains["ConditionalAccess"]) { $t.Domains["ConditionalAccess"].Status } else { "NotAssessed" }
                mfaStatus = if ($t.Domains["MFA"]) { $t.Domains["MFA"].Status } else { "NotAssessed" }
                pimStatus = if ($t.Domains["PIM"]) { $t.Domains["PIM"].Status } else { "NotAssessed" }
                extStatus = if ($t.Domains["ExternalIdentity"]) { $t.Domains["ExternalIdentity"].Status } else { "NotAssessed" }
            }
        }
    )

    # Build findings rows JSON
    $allFindings = @($Payload.Findings | Where-Object { $_ })
    $findingRowsJson = ConvertTo-SafeJsonArray -Objects (
        $allFindings | ForEach-Object {
            [PSCustomObject]@{
                id        = $_.FindingId
                tenant    = $_.TenantName
                tenantId  = $_.TenantId
                domain    = $_.Domain
                control   = $_.ControlId
                driftType = $_.DriftType
                title     = $_.Title
                severity  = $_.Severity
                impact    = $_.BusinessImpact
                baseline  = $_.BaselineValue
                actual    = $_.ActualValue
                detail    = $_.TechnicalDetail
                reco      = $_.Recommendation
                priority  = $_.RemediationPriority
                effort    = $_.RemediationEffort
            }
        }
    )

    # Compliance matrix data per control per tenant
    $controls = @($Payload.Controls)
    $matrixJson = ConvertTo-SafeJsonArray -Objects $controls
    $tenantNamesJson = ConvertTo-SafeJsonArray -Objects ($Payload.Tenants | ForEach-Object {
            [PSCustomObject]@{ id = $_.TenantId; name = $_.TenantName }
        })

    # Control compliance lookup: controlId → tenantId → status
    $complianceLookup = @{}
    foreach ($t in $Payload.Tenants) {
        foreach ($f in $t.Findings) {
            if (-not $complianceLookup[$f.ControlId]) { $complianceLookup[$f.ControlId] = @{} }
            $complianceLookup[$f.ControlId][$t.TenantId] = "FAIL"
        }
    }
    $complianceLookupJson = ($complianceLookup | ConvertTo-Json -Depth 5 -Compress)

    # Domain coverage data
    $domainSummaryJson = ConvertTo-SafeJsonArray -Objects ($Payload.ActiveDomains | ForEach-Object {
            $domain = $_
            $domainStatuses = $Payload.Tenants | ForEach-Object {
                if ($_.Domains[$domain]) { $_.Domains[$domain].Status } else { "NotAssessed" }
            }

            [PSCustomObject]@{
                domain   = $domain
                total    = $Payload.Tenants.Count
                success  = @($domainStatuses | Where-Object { $_ -in @("Success", "PartialSuccess") }).Count
                failed   = @($domainStatuses | Where-Object { $_ -in @("Failed", "PermissionDenied", "Unavailable") }).Count
                findings = @($allFindings    | Where-Object { $_.Domain -eq $domain }).Count
            }
        })

    $generatedAt = [datetime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss")

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Entra Multi-Tenant Drift Assessment</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap"/>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;--border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;--green:#3fb950;--amber:#d29922;--red:#f85149;--text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;--mono:'JetBrains Mono','Consolas','Courier New',monospace;--sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;--radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5)}
body.light-theme{--bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;--border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;--green:#1a7f37;--amber:#b08000;--red:#cf222e;--text:#1f2328;--muted:#636c76;--muted2:#424a53;--shadow:0 4px 24px rgba(0,0,0,.12)}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh}
/* Sidebar */
#sidebar{position:fixed;left:0;top:0;width:236px;height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;overflow-y:auto}
.sidebar-logo{padding:18px 16px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent3));display:inline-flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:8px}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px}
.version-badge{display:inline-block;background:var(--surface3);color:var(--accent);font-family:var(--mono);font-size:10px;padding:2px 6px;border-radius:4px;margin-top:6px}
.nav-section{padding:12px 0;flex:1}
.nav-label{font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;padding:0 16px 6px}
.nav-btn{display:flex;align-items:center;gap:10px;padding:8px 16px;cursor:pointer;font-size:13px;color:var(--muted2);background:transparent;border:none;width:100%;text-align:left;border-left:3px solid transparent;transition:all .15s}
.nav-btn:hover{background:var(--surface2);color:var(--text)}
.nav-btn.active{background:rgba(56,139,253,.12);color:var(--accent);border-left-color:var(--accent)}
.nav-btn .nav-icon{font-size:15px;width:18px;text-align:center}
.sidebar-footer{padding:12px 16px;border-top:1px solid var(--border);font-size:10px;color:var(--muted)}
.theme-toggle{display:flex;align-items:center;gap:8px;cursor:pointer;padding:8px 16px;margin-bottom:4px}
.toggle-track{width:36px;height:20px;border-radius:10px;background:var(--surface3);position:relative;transition:background .2s}
.toggle-thumb{position:absolute;top:3px;left:3px;width:14px;height:14px;border-radius:50%;background:var(--accent);transition:transform .2s}
body.light-theme .toggle-thumb{transform:translateX(16px)}
/* Main */
#main{margin-left:236px;padding:24px}
.page{display:none;animation:fadeIn .2s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:24px}
.page-title{font-size:22px;font-weight:700}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px}
/* Stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;border-top:3px solid transparent;transition:transform .15s,box-shadow .15s}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.stat-card.c-blue{border-top-color:var(--accent)}
.stat-card.c-cyan{border-top-color:var(--accent2)}
.stat-card.c-purple{border-top-color:var(--accent3)}
.stat-card.c-green{border-top-color:var(--green)}
.stat-card.c-amber{border-top-color:var(--amber)}
.stat-card.c-red{border-top-color:var(--red)}
.stat-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}
.stat-value{font-size:28px;font-weight:700;font-family:var(--mono);line-height:1}
.stat-sub{font-size:11px;color:var(--muted);margin-top:4px}
/* Score ring */
.health-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;display:flex;align-items:center;gap:24px;margin-bottom:24px}
.health-ring-wrap{position:relative;width:100px;height:100px;flex-shrink:0}
.health-ring-wrap svg{transform:rotate(-90deg)}
.health-ring-bg{fill:none;stroke:var(--surface3);stroke-width:8}
.health-ring-fg{fill:none;stroke-width:8;stroke-linecap:round;transition:stroke-dashoffset .6s ease}
.health-center{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}
.health-score{font-size:22px;font-weight:700;font-family:var(--mono)}
.health-label{font-size:10px;color:var(--muted)}
.health-info{flex:1}
.health-title{font-size:16px;font-weight:600;margin-bottom:4px}
.health-desc{font-size:13px;color:var(--muted2);margin-bottom:12px}
.health-mini-bar{height:6px;border-radius:3px;background:var(--surface3);overflow:hidden;margin-bottom:4px}
.health-mini-fill{height:100%;border-radius:3px;transition:width .5s ease}
.health-mini-label{font-size:11px;color:var(--muted);display:flex;justify-content:space-between}
/* Panels */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:20px}
.panel-title{font-size:14px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
/* Tables */
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.search-wrap{position:relative;flex:1;min-width:160px}
.search-wrap input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px 7px 32px;color:var(--text);font-size:13px;outline:none}
.search-wrap input:focus{border-color:var(--accent)}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px}
.filter-sel{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;color:var(--text);font-size:12px;cursor:pointer;outline:none}
.scripts-table{width:100%;border-collapse:collapse;font-size:12px}
.scripts-table th{background:var(--surface2);padding:9px 12px;text-align:left;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.scripts-table th:hover{color:var(--text)}
.scripts-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.scripts-table tr:hover td{background:var(--surface2)}
.pagination{display:flex;align-items:center;gap:6px;margin-top:12px;flex-wrap:wrap}
.pagination button{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:5px 10px;color:var(--text);font-size:12px;cursor:pointer}
.pagination button.active{background:var(--accent);border-color:var(--accent);color:#fff}
.pagination button:disabled{opacity:.4;cursor:default}
.page-info{font-size:12px;color:var(--muted);margin-left:4px}
/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;font-family:var(--mono)}
.badge-critical{background:rgba(248,81,73,.15);color:var(--red)}
.badge-high{background:rgba(210,153,34,.15);color:var(--amber)}
.badge-medium{background:rgba(56,139,253,.15);color:var(--accent)}
.badge-low{background:rgba(63,185,80,.15);color:var(--green)}
.badge-pass{background:rgba(63,185,80,.15);color:var(--green)}
.badge-fail{background:rgba(248,81,73,.15);color:var(--red)}
.badge-na{background:rgba(125,133,144,.15);color:var(--muted)}
.badge-warn{background:rgba(210,153,34,.15);color:var(--amber)}
/* Status dots */
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}
.dot-green{background:var(--green)}
.dot-red{background:var(--red)}
.dot-amber{background:var(--amber)}
.dot-muted{background:var(--muted)}
/* Detail Drawer */
#detailPanel{position:fixed;inset:0;z-index:200;pointer-events:none}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.5);opacity:0;transition:opacity .25s;pointer-events:none}
#detailDrawer{position:absolute;right:0;top:0;bottom:0;width:540px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);transform:translateX(100%);transition:transform .25s ease;overflow-y:auto;padding:24px;pointer-events:auto}
#detailPanel.open{pointer-events:auto}
#detailPanel.open #detailBackdrop{opacity:1;pointer-events:auto}
#detailPanel.open #detailDrawer{transform:none}
.drawer-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:16px}
.drawer-title{font-size:15px;font-weight:700;line-height:1.4;flex:1;margin-right:12px}
.drawer-close{background:none;border:none;color:var(--muted);font-size:18px;cursor:pointer;padding:2px 6px}
.drawer-close:hover{color:var(--text)}
.chip-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:11px;color:var(--muted2)}
.drawer-section{margin-bottom:16px}
.drawer-section-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:6px}
.drawer-field{font-size:13px;color:var(--text);line-height:1.6;white-space:pre-wrap;background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px;font-family:var(--mono);font-size:12px}
/* Matrix */
.matrix-wrap{overflow-x:auto}
.matrix-table{border-collapse:collapse;font-size:11px;min-width:max-content}
.matrix-table th,.matrix-table td{border:1px solid var(--border);padding:6px 10px;text-align:center}
.matrix-table th:first-child,.matrix-table td:first-child{text-align:left;min-width:200px;white-space:nowrap}
.matrix-table thead th{background:var(--surface2);font-weight:600;text-transform:uppercase;letter-spacing:.4px;color:var(--muted)}
.matrix-pass{background:rgba(63,185,80,.12);color:var(--green);font-weight:700}
.matrix-fail{background:rgba(248,81,73,.12);color:var(--red);font-weight:700}
.matrix-na{background:rgba(125,133,144,.08);color:var(--muted)}
/* Bar list */
.bar-row{margin-bottom:10px}
.bar-label{display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px}
.bar-track{height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;width:0;transition:width .6s ease}
/* Toast */
#toast{position:fixed;bottom:24px;right:24px;background:var(--surface3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;z-index:300;transform:translateY(20px);opacity:0;transition:all .25s;pointer-events:none}
#toast.show{transform:none;opacity:1}
/* Mobile */
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:150;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 10px;cursor:pointer;font-size:16px}
@media(max-width:768px){#sidebar{transform:translateX(-100%);transition:transform .25s}#sidebar.open{transform:none}#main{margin-left:0;padding:16px 12px}#menuToggle{display:block}.chart-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🛡️</div>
    <div class="logo-title">Entra Drift Assessment</div>
    <div class="logo-sub">Multi-Tenant Configuration Analysis</div>
    <span class="version-badge">v__ASSESSMENT_VERSION__</span>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Enterprise Overview</button>
    <button class="nav-btn" onclick="showPage('baseline',this)"><span class="nav-icon">✅</span> Baseline Compliance</button>
    <button class="nav-btn" onclick="showPage('tenants',this)"><span class="nav-icon">🏢</span> Tenant Comparison</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> Drift Findings</button>
    <button class="nav-btn" onclick="showPage('domains',this)"><span class="nav-icon">🗂️</span> Domain Analysis</button>
    <button class="nav-btn" onclick="showPage('coverage',this)"><span class="nav-icon">📋</span> Assessment Coverage</button>
    <button class="nav-btn" onclick="showPage('info',this)"><span class="nav-icon">ℹ️</span> Assessment Info</button>
  </div>
  <div onclick="toggleTheme()" class="theme-toggle" title="Toggle theme">
    <div class="toggle-track"><div class="toggle-thumb"></div></div>
    <span style="font-size:12px;color:var(--muted)">Light mode</span>
  </div>
  <div class="sidebar-footer">Generated __GENERATED_AT__ UTC<br/>Press / to search • Esc to close</div>
</nav>

<main id="main">

<!-- ENTERPRISE OVERVIEW -->
<div id="page-overview" class="page active">
  <div class="page-header">
    <div class="page-title">Enterprise Overview</div>
    <div class="page-sub">Baseline: __BASELINE_NAME__ v__BASELINE_VERSION__ &nbsp;•&nbsp; Assessment ID: __ASSESSMENT_ID__</div>
  </div>

  <div class="health-card">
    <div class="health-ring-wrap">
      <svg width="100" height="100" viewBox="0 0 100 100">
        <circle class="health-ring-bg" cx="50" cy="50" r="40"/>
        <circle id="scoreRing" class="health-ring-fg" cx="50" cy="50" r="40" stroke="__SCORE_COLOR__"
          stroke-dasharray="251.2" stroke-dashoffset="251.2"/>
      </svg>
      <div class="health-center">
        <div class="health-score" id="scoreVal">__ENTERPRISE_SCORE__</div>
        <div class="health-label">/ 100</div>
      </div>
    </div>
    <div class="health-info">
      <div class="health-title">Enterprise Alignment Score</div>
      <div class="health-desc">Equal-weighted average across __SCORED_TENANTS__ assessed tenant(s). __WEIGHTING_NOTE__</div>
      <div class="health-mini-bar"><div class="health-mini-fill" id="coverageBar" style="background:var(--accent);width:0%"></div></div>
      <div class="health-mini-label"><span>Assessment Coverage</span><span id="coverageVal">__AVG_COVERAGE__%</span></div>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-label">Enterprise Score</div><div class="stat-value" style="color:__SCORE_COLOR__">__ENTERPRISE_SCORE__</div><div class="stat-sub">/ 100</div></div>
    <div class="stat-card c-cyan"><div class="stat-label">Baseline Compliance</div><div class="stat-value">__BASELINE_COMPLIANCE__%</div><div class="stat-sub">of assessed controls</div></div>
    <div class="stat-card c-blue"><div class="stat-label">Total Tenants</div><div class="stat-value">__TOTAL_TENANTS__</div><div class="stat-sub">__COMPLETED_TENANTS__ completed</div></div>
    <div class="stat-card c-green"><div class="stat-label">Fully Compliant</div><div class="stat-value">__FULLY_COMPLIANT__</div><div class="stat-sub">tenants</div></div>
    <div class="stat-card c-red"><div class="stat-label">Critical Drifts</div><div class="stat-value" style="color:__CRIT_COLOR__">__CRITICAL_DRIFTS__</div><div class="stat-sub">findings</div></div>
    <div class="stat-card c-amber"><div class="stat-label">High Drifts</div><div class="stat-value">__HIGH_DRIFTS__</div><div class="stat-sub">findings</div></div>
    <div class="stat-card c-purple"><div class="stat-label">Total Findings</div><div class="stat-value">__TOTAL_FINDINGS__</div><div class="stat-sub">across all tenants</div></div>
    <div class="stat-card c-cyan"><div class="stat-label">Avg Coverage</div><div class="stat-value">__AVG_COVERAGE__%</div><div class="stat-sub">assessment coverage</div></div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="panel-title">📊 Severity Distribution</div>
      <div id="severityBars"></div>
    </div>
    <div class="panel">
      <div class="panel-title">🏢 Tenant Alignment Scores</div>
      <div id="tenantScoreBars"></div>
    </div>
  </div>
</div>

<!-- BASELINE COMPLIANCE MATRIX -->
<div id="page-baseline" class="page">
  <div class="page-header">
    <div class="page-title">Baseline Compliance Matrix</div>
    <div class="page-sub">Per-control compliance status across all tenants</div>
  </div>
  <div class="panel">
    <div class="matrix-wrap">
      <table class="matrix-table" id="matrixTable">
        <thead id="matrixHead"></thead>
        <tbody id="matrixBody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- TENANT COMPARISON -->
<div id="page-tenants" class="page">
  <div class="page-header">
    <div class="page-title">Tenant Comparison</div>
    <div class="page-sub">Side-by-side comparison of tenant alignment and domain status</div>
  </div>
  <div class="panel">
    <div class="toolbar">
      <div class="search-wrap"><span class="search-icon">🔍</span><input id="tenantSearch" type="text" placeholder="Search tenants..." oninput="filterTenants()"/></div>
    </div>
    <table class="scripts-table" id="tenantTable">
      <thead>
        <tr>
          <th onclick="sortTenants('name')">Tenant</th>
          <th onclick="sortTenants('bu')">Business Unit</th>
          <th onclick="sortTenants('score')">Score</th>
          <th>Status</th>
          <th>CA</th><th>MFA</th><th>PIM</th><th>Ext ID</th>
          <th onclick="sortTenants('critical')">Critical</th>
          <th onclick="sortTenants('findings')">Total</th>
          <th>Coverage</th>
        </tr>
      </thead>
      <tbody id="tenantBody"></tbody>
    </table>
    <div class="pagination" id="tenantPagination"></div>
  </div>
</div>

<!-- DRIFT FINDINGS -->
<div id="page-findings" class="page">
  <div class="page-header">
    <div class="page-title">Drift Findings</div>
    <div class="page-sub">All security configuration deviations with remediation guidance</div>
  </div>
  <div class="panel">
    <div class="toolbar">
      <div class="search-wrap"><span class="search-icon">🔍</span><input id="findingSearch" type="text" placeholder="Search findings..." oninput="filterFindings()"/></div>
      <select class="filter-sel" id="sevFilter" onchange="filterFindings()">
        <option value="">All Severities</option>
        <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
      </select>
      <select class="filter-sel" id="domainFilter" onchange="filterFindings()">
        <option value="">All Domains</option>
        <option>ConditionalAccess</option><option>MFA</option><option>PIM</option><option>ExternalIdentity</option>
      </select>
      <select class="filter-sel" id="tenantFilter" onchange="filterFindings()">
        <option value="">All Tenants</option>
      </select>
    </div>
    <table class="scripts-table" id="findingsTable">
      <thead>
        <tr>
          <th>ID</th><th>Tenant</th><th>Domain</th><th>Severity</th><th>Title</th><th>Priority</th><th>Effort</th>
        </tr>
      </thead>
      <tbody id="findingsBody"></tbody>
    </table>
    <div class="pagination" id="findingsPagination"></div>
  </div>
</div>

<!-- DOMAIN ANALYSIS -->
<div id="page-domains" class="page">
  <div class="page-header">
    <div class="page-title">Domain Analysis</div>
    <div class="page-sub">Collector status and finding counts per security domain</div>
  </div>
  <div id="domainCards"></div>
</div>

<!-- ASSESSMENT COVERAGE -->
<div id="page-coverage" class="page">
  <div class="page-header">
    <div class="page-title">Assessment Coverage</div>
    <div class="page-sub">Domain collection status per tenant — limitations are not security failures</div>
  </div>
  <div class="panel">
    <table class="scripts-table" id="coverageTable">
      <thead>
        <tr><th>Tenant</th><th>CA Status</th><th>MFA Status</th><th>PIM Status</th><th>Ext ID Status</th><th>Coverage %</th><th>Errors</th></tr>
      </thead>
      <tbody id="coverageBody"></tbody>
    </table>
  </div>
</div>

<!-- ASSESSMENT INFO -->
<div id="page-info" class="page">
  <div class="page-header">
    <div class="page-title">Assessment Information</div>
    <div class="page-sub">Baseline parameters and assessment metadata</div>
  </div>
  <div class="panel">
    <div class="panel-title">🗂️ Assessment Metadata</div>
    <table class="scripts-table">
      <tbody>
        <tr><td style="width:200px;color:var(--muted)">Assessment ID</td><td style="font-family:var(--mono)">__ASSESSMENT_ID__</td></tr>
        <tr><td style="color:var(--muted)">Generated At</td><td>__GENERATED_AT__ UTC</td></tr>
        <tr><td style="color:var(--muted)">Assessment Version</td><td>__ASSESSMENT_VERSION__</td></tr>
        <tr><td style="color:var(--muted)">Baseline Name</td><td>__BASELINE_NAME__</td></tr>
        <tr><td style="color:var(--muted)">Baseline Version</td><td>__BASELINE_VERSION__</td></tr>
        <tr><td style="color:var(--muted)">Active Domains</td><td>__ACTIVE_DOMAINS__</td></tr>
        <tr><td style="color:var(--muted)">Total Tenants</td><td>__TOTAL_TENANTS__</td></tr>
        <tr><td style="color:var(--muted)">Weighting Method</td><td>__WEIGHTING_METHOD__</td></tr>
      </tbody>
    </table>
  </div>
  <div class="panel">
    <div class="panel-title">ℹ️ Required Graph Permissions (per tenant)</div>
    <table class="scripts-table">
      <thead><tr><th>Permission</th><th>Used For</th></tr></thead>
      <tbody>
        <tr><td style="font-family:var(--mono)">Policy.Read.All</td><td>Conditional Access policies, Authorization policy, Cross-tenant access policy</td></tr>
        <tr><td style="font-family:var(--mono)">AuditLog.Read.All</td><td>MFA registration reports (userRegistrationDetails)</td></tr>
        <tr><td style="font-family:var(--mono)">RoleManagement.Read.Directory</td><td>PIM active/eligible role assignment schedules</td></tr>
        <tr><td style="font-family:var(--mono)">RoleManagementPolicy.Read.Directory</td><td>PIM activation rules (MFA, approval settings)</td></tr>
      </tbody>
    </table>
  </div>
  <div class="panel">
    <div class="panel-title">⚠️ Assessment Limitations</div>
    <p style="font-size:13px;color:var(--muted2);line-height:1.7">
      This assessment is a read-only, point-in-time snapshot. It does not modify any tenant configuration.
      Domains with status <span class="badge badge-na">PermissionDenied</span> or <span class="badge badge-na">Unavailable</span>
      indicate assessment gaps — they are <strong>not</strong> security findings.
      PIM and MFA data require Entra ID P2 licensing in each assessed tenant.
      Conditional Access named-location policies are not expanded.
    </p>
  </div>
</div>

</main>

<!-- Detail Drawer -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDrawer()"></div>
  <div id="detailDrawer">
    <div class="drawer-header">
      <div class="drawer-title" id="drawerTitle"></div>
      <button class="drawer-close" onclick="closeDrawer()">✕</button>
    </div>
    <div class="chip-row" id="drawerChips"></div>
    <div id="drawerContent"></div>
  </div>
</div>

<div id="toast"></div>

<script>
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

// Data
const TENANTS   = __TENANTS_JSON__;
const FINDINGS  = __FINDINGS_JSON__;
const CONTROLS  = __CONTROLS_JSON__;
const TENANT_NAMES = __TENANT_NAMES_JSON__;
const COMPLIANCE = __COMPLIANCE_LOOKUP_JSON__;
const DOMAINS   = __DOMAINS_JSON__;

// Page navigation
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn) btn.classList.add('active');
  if(id==='baseline') buildMatrix();
}

// Theme toggle
function toggleTheme(){document.body.classList.toggle('light-theme');}

// Toast
function showToast(msg,icon){
  const t=document.getElementById('toast');
  t.textContent=(icon||'')+' '+msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2400);
}

// Status formatting helpers
function statusDot(s){
  if(s==='Success'||s==='Completed') return '<span class="dot dot-green"></span>';
  if(s==='PartialSuccess') return '<span class="dot dot-amber"></span>';
  if(s==='Failed'||s==='PermissionDenied') return '<span class="dot dot-red"></span>';
  return '<span class="dot dot-muted"></span>';
}
function statusBadge(s){
  if(s==='Success'||s==='Completed') return '<span class="badge badge-pass">'+escH(s)+'</span>';
  if(s==='PartialSuccess') return '<span class="badge badge-warn">'+escH(s)+'</span>';
  if(s==='Failed'||s==='PermissionDenied') return '<span class="badge badge-fail">'+escH(s)+'</span>';
  return '<span class="badge badge-na">'+escH(s||'N/A')+'</span>';
}
function sevBadge(s){
  const m={'Critical':'badge-critical','High':'badge-high','Medium':'badge-medium','Low':'badge-low'};
  return '<span class="badge '+(m[s]||'badge-na')+'">'+escH(s)+'</span>';
}
function scoreColor(n){if(n<0) return 'var(--muted)'; if(n>=80) return 'var(--green)'; if(n>=60) return 'var(--amber)'; return 'var(--red)';}

// === OVERVIEW ===
(function initOverview(){
  // Animate score ring
  const ring = document.getElementById('scoreRing');
  const score = __ENTERPRISE_SCORE__;
  const circumference = 251.2;
  setTimeout(()=>{
    ring.style.strokeDashoffset = circumference - (circumference * score / 100);
  },200);

  // Coverage bar
  const cvg = __AVG_COVERAGE__;
  setTimeout(()=>{
    document.getElementById('coverageBar').style.width = cvg+'%';
  },300);

  // Severity bars
  const sevData = [
    {label:'Critical',count:__CRITICAL_DRIFTS__,color:'var(--red)'},
    {label:'High',    count:__HIGH_DRIFTS__,    color:'var(--amber)'},
    {label:'Medium',  count:__MEDIUM_DRIFTS__,  color:'var(--accent)'},
    {label:'Low',     count:__LOW_DRIFTS__,      color:'var(--green)'},
  ];
  const maxSev = Math.max(...sevData.map(x=>x.count),1);
  const sevEl = document.getElementById('severityBars');
  sevData.forEach(d=>{
    sevEl.innerHTML += `<div class="bar-row">
      <div class="bar-label"><span>${escH(d.label)}</span><span>${d.count}</span></div>
      <div class="bar-track"><div class="bar-fill" data-pct="${d.count/maxSev*100}" style="background:${d.color}"></div></div>
    </div>`;
  });

  // Tenant score bars
  const maxScore = 100;
  const tScoreEl = document.getElementById('tenantScoreBars');
  TENANTS.forEach(t=>{
    const s = t.score >= 0 ? t.score : null;
    const pct = s !== null ? s : 0;
    const col = s !== null ? scoreColor(s) : 'var(--muted)';
    tScoreEl.innerHTML += `<div class="bar-row">
      <div class="bar-label"><span>${escH(t.name)}</span><span style="color:${col}">${s !== null ? s : 'N/A'}</span></div>
      <div class="bar-track"><div class="bar-fill" data-pct="${pct}" style="background:${col}"></div></div>
    </div>`;
  });

  // Animate bars
  setTimeout(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width = el.dataset.pct + '%';
    });
  },400);
})();

// === COMPLIANCE MATRIX ===
function buildMatrix(){
  const head = document.getElementById('matrixHead');
  const body = document.getElementById('matrixBody');
  if(head.childElementCount > 0) return; // already built

  // Header row: Control | Tenant A | Tenant B ...
  let hRow = '<tr><th>Control</th><th>Domain</th>';
  TENANT_NAMES.forEach(t=>{ hRow += '<th>'+escH(t.name)+'</th>'; });
  hRow += '</tr>';
  head.innerHTML = hRow;

  // Body: one row per control
  let bHtml = '';
  CONTROLS.forEach(c=>{
    bHtml += '<tr><td>'+escH(c.ControlId)+' — '+escH(c.Name)+'</td><td><span class="badge badge-na">'+escH(c.Domain)+'</span></td>';
    TENANT_NAMES.forEach(t=>{
      const domainMap = {};
      TENANTS.forEach(ten=>{
        // Check if domain is unavailable
        const ds = ten.caStatus === 'PermissionDenied' || ten.caStatus === 'Unavailable' ||
                   ten.mfaStatus === 'PermissionDenied' || ten.mfaStatus === 'Unavailable' ||
                   ten.pimStatus === 'PermissionDenied' || ten.pimStatus === 'Unavailable' ||
                   ten.extStatus === 'PermissionDenied' || ten.extStatus === 'Unavailable';
        domainMap[ten.id] = ten;
      });

      const isFail = COMPLIANCE[c.ControlId] && COMPLIANCE[c.ControlId][t.id] === 'FAIL';
      const ten = domainMap[t.id];
      let domainStatus = 'Success';
      if(c.Domain === 'ConditionalAccess' && ten) domainStatus = ten.caStatus;
      else if(c.Domain === 'MFA' && ten) domainStatus = ten.mfaStatus;
      else if(c.Domain === 'PIM' && ten) domainStatus = ten.pimStatus;
      else if(c.Domain === 'ExternalIdentity' && ten) domainStatus = ten.extStatus;

      const isUnavailable = domainStatus === 'PermissionDenied' || domainStatus === 'Unavailable' || domainStatus === 'Failed';

      if(isUnavailable){
        bHtml += '<td class="matrix-na">N/A</td>';
      } else if(isFail){
        bHtml += '<td class="matrix-fail">FAIL</td>';
      } else {
        bHtml += '<td class="matrix-pass">PASS</td>';
      }
    });
    bHtml += '</tr>';
  });
  body.innerHTML = bHtml;
}

// === TENANT TABLE ===
let tenantData = [...TENANTS];
let tenantPage = 1;
const tenantPageSize = 25;
let tenantSortKey = 'score';
let tenantSortAsc = false;

function filterTenants(){
  const q = document.getElementById('tenantSearch').value.toLowerCase();
  tenantData = TENANTS.filter(t=>
    t.name.toLowerCase().includes(q) || t.bu.toLowerCase().includes(q) || t.id.toLowerCase().includes(q)
  );
  tenantPage = 1;
  renderTenantTable();
}
function sortTenants(key){
  if(tenantSortKey===key) tenantSortAsc=!tenantSortAsc; else{tenantSortKey=key;tenantSortAsc=false;}
  tenantData.sort((a,b)=>{
    const av=a[key]??'',bv=b[key]??'';
    return typeof av==='number' ? (tenantSortAsc?av-bv:bv-av) : (tenantSortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av)));
  });
  renderTenantTable();
}
function renderTenantTable(){
  const start=(tenantPage-1)*tenantPageSize;
  const rows=tenantData.slice(start,start+tenantPageSize);
  const tbody=document.getElementById('tenantBody');
  tbody.innerHTML=rows.map(t=>{
    const sc=t.score>=0?t.score:null;
    const scol=sc!==null?scoreColor(sc):'var(--muted)';
    return `<tr>
      <td title="${escH(t.id)}">${statusDot(t.status)}${escH(t.name)}</td>
      <td>${escH(t.bu)}</td>
      <td style="color:${scol};font-family:var(--mono);font-weight:700">${sc!==null?sc:'N/A'}</td>
      <td>${statusBadge(t.status)}</td>
      <td>${statusBadge(t.caStatus)}</td>
      <td>${statusBadge(t.mfaStatus)}</td>
      <td>${statusBadge(t.pimStatus)}</td>
      <td>${statusBadge(t.extStatus)}</td>
      <td style="color:${t.critical>0?'var(--red)':'var(--muted)'}">${t.critical}</td>
      <td>${t.findings}</td>
      <td>${t.coverage}%</td>
    </tr>`;
  }).join('');
  renderPagination('tenantPagination',tenantData.length,tenantPage,tenantPageSize,(p)=>{tenantPage=p;renderTenantTable();});
}

// === FINDINGS TABLE ===
let findingData=[...FINDINGS];
let findingPage=1;
const findingPageSize=20;

// Populate tenant filter
(function(){
  const sel=document.getElementById('tenantFilter');
  const seen=new Set();
  FINDINGS.forEach(f=>{if(!seen.has(f.tenantId)){seen.add(f.tenantId);sel.innerHTML+=`<option value="${escH(f.tenantId)}">${escH(f.tenant)}</option>`;}});
})();

function filterFindings(){
  const q=document.getElementById('findingSearch').value.toLowerCase();
  const sev=document.getElementById('sevFilter').value;
  const dom=document.getElementById('domainFilter').value;
  const ten=document.getElementById('tenantFilter').value;
  findingData=FINDINGS.filter(f=>{
    const matchQ=!q||(f.title.toLowerCase().includes(q)||f.tenant.toLowerCase().includes(q)||f.id.toLowerCase().includes(q)||f.reco.toLowerCase().includes(q));
    const matchS=!sev||f.severity===sev;
    const matchD=!dom||f.domain===dom;
    const matchT=!ten||f.tenantId===ten;
    return matchQ&&matchS&&matchD&&matchT;
  });
  findingPage=1;
  renderFindingsTable();
}
function renderFindingsTable(){
  const start=(findingPage-1)*findingPageSize;
  const rows=findingData.slice(start,start+findingPageSize);
  const tbody=document.getElementById('findingsBody');
  tbody.innerHTML=rows.map((f,i)=>`<tr style="cursor:pointer" onclick="openFinding(${start+i})">
    <td style="font-family:var(--mono);font-size:11px">${escH(f.id)}</td>
    <td>${escH(f.tenant)}</td>
    <td><span class="badge badge-na">${escH(f.domain)}</span></td>
    <td>${sevBadge(f.severity)}</td>
    <td>${escH(f.title)}</td>
    <td style="font-family:var(--mono)">${escH(f.priority)}</td>
    <td>${escH(f.effort)}</td>
  </tr>`).join('');
  renderPagination('findingsPagination',findingData.length,findingPage,findingPageSize,(p)=>{findingPage=p;renderFindingsTable();});
}

let currentDetailIndex=-1;
function openFinding(idx){
  currentDetailIndex=idx;
  const f=findingData[idx];
  document.getElementById('drawerTitle').textContent=f.title;
  document.getElementById('drawerChips').innerHTML=`
    <span class="chip">${escH(f.id)}</span>
    <span class="chip">${escH(f.domain)}</span>
    ${sevBadge(f.severity)}
    <span class="chip">${escH(f.priority)} · ${escH(f.effort)}</span>
    <span class="chip">Tenant: ${escH(f.tenant)}</span>`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-section"><div class="drawer-section-title">Business Impact</div><div class="drawer-field">${escH(f.impact)}</div></div>
    <div class="drawer-section"><div class="drawer-section-title">Baseline Expected</div><div class="drawer-field">${escH(f.baseline)}</div></div>
    <div class="drawer-section"><div class="drawer-section-title">Actual Value</div><div class="drawer-field">${escH(f.actual)}</div></div>
    <div class="drawer-section"><div class="drawer-section-title">Technical Detail</div><div class="drawer-field">${escH(f.detail)}</div></div>
    <div class="drawer-section"><div class="drawer-section-title">Recommendation</div><div class="drawer-field">${escH(f.reco)}</div></div>`;
  document.getElementById('detailPanel').classList.add('open');
}
function closeDrawer(){document.getElementById('detailPanel').classList.remove('open');}

// === DOMAIN ANALYSIS ===
(function(){
  const el=document.getElementById('domainCards');
  const domainIcons={'ConditionalAccess':'🔐','MFA':'📲','PIM':'👑','ExternalIdentity':'🌐'};
  DOMAINS.forEach(d=>{
    el.innerHTML+=`<div class="panel">
      <div class="panel-title">${domainIcons[d.domain]||'🗂️'} ${escH(d.domain)}</div>
      <div class="stats-grid" style="margin-bottom:0">
        <div class="stat-card c-blue"><div class="stat-label">Tenants Assessed</div><div class="stat-value">${d.success}</div><div class="stat-sub">of ${d.total}</div></div>
        <div class="stat-card c-red"><div class="stat-label">Assessment Gaps</div><div class="stat-value">${d.failed}</div><div class="stat-sub">failed/unavailable</div></div>
        <div class="stat-card c-amber"><div class="stat-label">Findings</div><div class="stat-value">${d.findings}</div><div class="stat-sub">in this domain</div></div>
      </div>
    </div>`;
  });
})();

// === COVERAGE TABLE ===
(function(){
  const tbody=document.getElementById('coverageBody');
  tbody.innerHTML=TENANTS.map(t=>`<tr>
    <td>${statusDot(t.status)}${escH(t.name)}</td>
    <td>${statusBadge(t.caStatus)}</td>
    <td>${statusBadge(t.mfaStatus)}</td>
    <td>${statusBadge(t.pimStatus)}</td>
    <td>${statusBadge(t.extStatus)}</td>
    <td style="font-family:var(--mono)">${t.coverage}%</td>
    <td><span style="font-size:11px;color:var(--muted)">—</span></td>
  </tr>`).join('');
})();

// === PAGINATION ===
function renderPagination(containerId,total,current,pageSize,onPage){
  const pages=Math.ceil(total/pageSize);
  const el=document.getElementById(containerId);
  if(pages<=1){el.innerHTML='';return;}
  let html=`<button onclick="(${onPage})(${Math.max(1,current-1)})" ${current===1?'disabled':''}>‹</button>`;
  for(let p=1;p<=pages;p++){
    if(p===1||p===pages||Math.abs(p-current)<=2){
      html+=`<button class="${p===current?'active':''}" onclick="(${onPage})(${p})">${p}</button>`;
    } else if(Math.abs(p-current)===3){
      html+='<span style="padding:0 4px;color:var(--muted)">…</span>';
    }
  }
  html+=`<button onclick="(${onPage})(${Math.min(pages,current+1)})" ${current===pages?'disabled':''}>›</button>`;
  html+=`<span class="page-info">${total} items</span>`;
  el.innerHTML=html;
}

// Init tables
filterTenants();
filterFindings();

// Keyboard shortcuts
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='/'&&!['INPUT','TEXTAREA'].includes(document.activeElement.tagName)){
    e.preventDefault();
    const activePage=document.querySelector('.page.active');
    if(activePage){const inp=activePage.querySelector('input[type=text]');if(inp) inp.focus();}
  }
});
</script>
</body>
</html>
'@

    # Inject all data values
    $html = $html `
        -replace '__ASSESSMENT_VERSION__', ($Script:AssessmentVersion) `
        -replace '__ASSESSMENT_ID__', ($Payload.AssessmentId) `
        -replace '__GENERATED_AT__', $generatedAt `
        -replace '__BASELINE_NAME__', (EscapeHtmlAttr $Payload.BaselineName) `
        -replace '__BASELINE_VERSION__', (EscapeHtmlAttr $Payload.BaselineVersion) `
        -replace '__ENTERPRISE_SCORE__', ($ent.AlignmentScore) `
        -replace '__SCORE_COLOR__', $scoreColor `
        -replace '__CRIT_COLOR__', $critColor `
        -replace '__BASELINE_COMPLIANCE__', ($ent.BaselineCompliance) `
        -replace '__TOTAL_TENANTS__', ($ent.TotalTenants) `
        -replace '__COMPLETED_TENANTS__', ($ent.CompletedTenants) `
        -replace '__FULLY_COMPLIANT__', ($ent.FullyCompliantTenants) `
        -replace '__CRITICAL_DRIFTS__', ($ent.CriticalDrifts) `
        -replace '__HIGH_DRIFTS__', ($ent.HighDrifts) `
        -replace '__MEDIUM_DRIFTS__', ($ent.MediumDrifts) `
        -replace '__LOW_DRIFTS__', ($ent.LowDrifts) `
        -replace '__TOTAL_FINDINGS__', ($ent.TotalFindings) `
        -replace '__AVG_COVERAGE__', ($ent.AverageCoverage) `
        -replace '__SCORED_TENANTS__', ($ent.ScoredTenants) `
        -replace '__WEIGHTING_NOTE__', (EscapeHtmlAttr $ent.WeightingNote) `
        -replace '__WEIGHTING_METHOD__', (EscapeHtmlAttr $ent.WeightingMethod) `
        -replace '__ACTIVE_DOMAINS__', ($Payload.ActiveDomains -join ", ") `
        -replace '__TENANTS_JSON__', $tenantRowsJson `
        -replace '__FINDINGS_JSON__', $findingRowsJson `
        -replace '__CONTROLS_JSON__', $matrixJson `
        -replace '__TENANT_NAMES_JSON__', $tenantNamesJson `
        -replace '__COMPLIANCE_LOOKUP_JSON__', $complianceLookupJson `
        -replace '__DOMAINS_JSON__', $domainSummaryJson

    try {
        $html | Out-File -LiteralPath $Path -Encoding UTF8 -Force -ErrorAction Stop
        Write-Verbose "HTML dashboard: $Path"
    }
    catch {
        Write-Warning "Failed to write HTML dashboard to '$Path': $_"
    }
}

Function EscapeHtmlAttr {
    param ([string]$Value)
    if (-not $Value) { return "" }
    return $Value `
        -replace '&', '&amp;' `
        -replace '"', '&quot;' `
        -replace '<', '&lt;'  `
        -replace '>', '&gt;'
}

Function ConvertTo-SafeJsonArray {
    param ([object[]]$Objects)

    if (-not $Objects -or $Objects.Count -eq 0) { return "[]" }

    # Use ConvertTo-Json and ensure compact, safe output
    $json = $Objects | ConvertTo-Json -Depth 5 -Compress

    # Ensure it is always an array
    if ($json -and -not $json.TrimStart().StartsWith("[")) {
        $json = "[$json]"
    }

    # Escape any </script> sequences that could break the HTML embedding
    $json = $json -replace "</script>", "<\/script>"

    return $json
}

#endregion HTML Dashboard
