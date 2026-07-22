<#

Author          : Lakshmanan Thangaraj
Version         : 2.0
Created-On      : 10 April 2025
Modified-On     : 22 July 2026

.SYNOPSIS
    Retrieves Conditional Access Policies from Entra ID using Microsoft Graph API
    and exports the report to a CSV or JSON file.

.DESCRIPTION
    This script connects to Entra ID (Azure AD) using either direct bearer token
    or app-only authentication via the Microsoft Graph API beta endpoint. It retrieves
    all Conditional Access Policies with their conditions, grant controls, and session
    controls, then exports them to either CSV or JSON format.

    The following policy attributes are collected:
        - Policy ID, display name, state, creation/modified dates
        - Included and excluded users, groups, and applications
        - Conditions (flattened in CSV, nested in JSON)
        - Grant controls and session controls

    The final report is exported as a CSV or JSON file to C:\Temp\ConditionalAccessPolicies.

.PARAMETER AccessToken
    Access token with delegated or app-only permission to query Microsoft Graph Beta
    endpoint for Conditional Access Policies. Required when using direct token auth.

.PARAMETER ClientId
    The Application (client) ID of the Azure AD app registration used for
    authentication. Required when using client credentials flow.

.PARAMETER ClientSecret
    The client secret associated with the Azure AD app registration, supplied
    as a SecureString. Required when using client credentials flow.

.PARAMETER TenantId
    The Directory (tenant) ID of the Entra ID tenant to query.
    Required when using client credentials flow.

.PARAMETER OutputPath
    The full file path (without extension) where the report will be saved.
    Default: C:\Temp\ConditionalAccessPolicies

.PARAMETER OutputFormat
    Specifies the export format. Acceptable values are:
    - CSV: Flattens key policy attributes into a table-friendly structure.
    - JSON: Preserves full nested structure for advanced use or parsing.
    Default: JSON

.PARAMETER PolicyName
    (Optional) If specified, retrieves only the Conditional Access Policy with the
    matching display name. Multiple names can be provided as an array.
    When not provided, all Conditional Access Policies will be retrieved.

.PARAMETER ShowHelp
    Displays a friendly, plain-language usage guide (parameters, examples,
    prerequisites) and exits immediately. No authentication is attempted and
    no other parameters are required when this switch is used.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        A CSV or JSON file exported to the path defined in $OutputPath containing
        Conditional Access Policy details.

.EXAMPLE
    .\Get-ConditionalAccessPoliciesReport.ps1 -ShowHelp

    Displays the friendly usage guide and exits without connecting to anything.

.EXAMPLE
    $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    .\Get-ConditionalAccessPoliciesReport.ps1 -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"

    Runs the script using client credentials flow and exports to the default output path.

.EXAMPLE
    $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    .\Get-ConditionalAccessPoliciesReport.ps1 -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" -OutputFormat CSV -OutputPath "D:\Reports\CAReport"

    With custom output path and CSV format.

.EXAMPLE
    $token = Get-MgContext | Select-Object -ExpandProperty AccessToken
    .\Get-ConditionalAccessPoliciesReport.ps1 -AccessToken $token -PolicyName "Block Legacy Authentication"

    Uses a directly-provided access token to fetch a specific policy.

.EXAMPLE
    .\Get-ConditionalAccessPoliciesReport.ps1 -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" -PolicyName @("Block Legacy Authentication","MFA for Admins")

    Retrieves multiple specific policies by name.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (10-Apr-2025)  - Initial release
        1.1 (18-Aug-2025)  - Added optional parameter -PolicyName to allow retrieving
                              a specific Conditional Access Policy by display name.
        2.0 (22-Jul-2026)  - Added client credentials flow authentication
                              (ClientId, ClientSecret, TenantId parameters)
                              - Added -ShowHelp switch for friendly usage guide
                              - Added SecureString handling for ClientSecret

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Azure AD App Registration with admin-consented API permissions:
               Policy.Read.All                    (Application)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Functions:
    ─────────────────────────────────────────────────────────────────────────────
        Show-FriendlyHelp
            Prints a plain-language usage guide (parameters, examples,
            prerequisites) via Write-Host, then returns control to the
            caller so the script can exit early.

        Connect-EntraID
            Authenticates to Microsoft Graph API using client credentials flow
            (client ID, client secret, tenant ID) and returns a bearer token.

        Get-ConditionalAccessPoliciesReport
            Retrieves Conditional Access Policies from Graph API with optional
            filtering by policy name. Exports to CSV or JSON format.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  →  If -ShowHelp was supplied, print the friendly guide and exit
        Step 1  →  Authenticate to Entra ID and obtain access token
                   (either via client credentials or direct token)
        Step 2  →  Retrieve Conditional Access Policies with optional filtering
        Step 3  →  Export report to specified format (CSV or JSON)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The script uses the /beta Graph API endpoint. Beta endpoints are
          subject to change and are not recommended for production without
          monitoring for breaking changes.
        - When using client credentials, the client secret is marshaled to
          plaintext in memory for the brief moment required to build the OAuth
          token request body. This is inherent to the grant type, not a script
          shortcut.

.LINK
    Microsoft Graph API - Conditional Access Policies
    https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccess-policy

#>

param (
    [Parameter(Mandatory = $true, ParameterSetName = "DirectToken")]
    [string]$AccessToken,

    [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
    [string]$ClientId,

    [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
    [System.Security.SecureString]$ClientSecret,

    [Parameter(Mandatory = $true, ParameterSetName = "ClientCredentials")]
    [string]$TenantId,

    [Parameter(ParameterSetName = "DirectToken")]
    [Parameter(ParameterSetName = "ClientCredentials")]
    [ValidateSet("CSV", "JSON")]
    [string]$OutputFormat = "JSON",

    [Parameter(ParameterSetName = "DirectToken")]
    [Parameter(ParameterSetName = "ClientCredentials")]
    [string]$OutputPath = "C:\Temp\ConditionalAccessPolicies",

    [Parameter(ParameterSetName = "DirectToken")]
    [Parameter(ParameterSetName = "ClientCredentials")]
    [string[]]$PolicyName,

    [Parameter(Mandatory = $true, ParameterSetName = "Help")]
    [switch]$ShowHelp
)

#--------------------------------------------------------------------------------------------------- [ Friendly Help ]

Function Show-FriendlyHelp
{
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       Entra ID — Conditional Access Policies Report          ║" -ForegroundColor Cyan
    Write-Host "  ║                Version 2.0  |  Help                          ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this script does:" -ForegroundColor Yellow
    Write-Host "    Connects to Entra ID via Microsoft Graph (app-only auth or direct"
    Write-Host "    token) and pulls all Conditional Access Policies into a CSV or JSON report."
    Write-Host ""
    Write-Host "  Authentication options:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Option A - Direct Bearer Token:" -ForegroundColor Cyan
    Write-Host "    -AccessToken    Access token with Policy.Read.All permission"
    Write-Host ""
    Write-Host "  Option B - Client Credentials Flow:" -ForegroundColor Cyan
    Write-Host "    -ClientId       Application (client) ID of your Azure AD app registration"
    Write-Host "    -ClientSecret   The app's client secret, as a SecureString (see example)"
    Write-Host "    -TenantId       Directory (tenant) ID of the Entra ID tenant"
    Write-Host ""
    Write-Host "  Other parameters:" -ForegroundColor Yellow
    Write-Host "    -OutputFormat   CSV or JSON (default: JSON)"
    Write-Host "    -OutputPath     Where to save the report (default: C:\Temp\ConditionalAccessPolicies)"
    Write-Host "    -PolicyName     One or more policy names to filter (optional)"
    Write-Host "    -ShowHelp       Shows this guide and exits"
    Write-Host ""
    Write-Host "  Before you run it:" -ForegroundColor Yellow
    Write-Host "    1. Your app registration needs these Graph API Application permissions,"
    Write-Host "       admin-consented: Policy.Read.All"
    Write-Host ""
    Write-Host "  Example (Client Credentials):" -ForegroundColor Yellow
    Write-Host '    $secret = Read-Host -Prompt "Client secret" -AsSecureString'
    Write-Host '    .\Get-ConditionalAccessPoliciesReport.ps1 -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
    Write-Host ""
    Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
    Write-Host "     Get-Help .\Get-ConditionalAccessPoliciesReport.ps1 -Full"
    Write-Host ""
}

if ($ShowHelp)
{
    Show-FriendlyHelp
    return
}

#--------------------------------------------------------------------------------------------------- [ Helper Functions ]

Function RequestAccessToken
{
    $tokenEndpoint = "https://login.microsoftonline.com/$global:TenantId/oauth2/v2.0/token"

    # Marshal the SecureString to plaintext only for the instant it's needed
    # to build the token request body, then scrub it from memory right after.
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($global:ClientSecretSecure)
    Try
    {
        $plainClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

        $tokenRequestBody = @{
            client_id     = $global:ClientId
            client_secret = $plainClientSecret
            scope         = "https://graph.microsoft.com/.default"
            grant_type    = "client_credentials"
        }
        $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $tokenRequestBody
        $global:accessToken = $tokenResponse.access_token
        $global:tokenExpirationTime = (Get-Date).AddSeconds($tokenResponse.expires_in)
    }
    Finally
    {
        if ($bstr -ne [IntPtr]::Zero)
        {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $plainClientSecret = $null
        $tokenRequestBody = $null
    }
}

Function ShouldRenewToken
{
    if (!$global:accessToken -or !$global:tokenExpirationTime)
    {
        return $true
    }
    $timeToExpire = ($global:tokenExpirationTime - (Get-Date)).TotalMinutes
    return ($timeToExpire -lt $global:RefreshIntervalInMinutes)
}

Function RenewTokenIfNeeded
{
    if (ShouldRenewToken)                # ← now resolves correctly (ShouldRenewToken is at script scope)
    {
        Write-Host ""
        Write-Host "Refreshing Graph access token..." -ForegroundColor Yellow
        RequestAccessToken               # ← now resolves correctly (RequestAccessToken is at script scope)
        Write-Host "Token refreshed successfully." -ForegroundColor Green
    }
}


#--------------------------------------------------------------------------------------------------- [ Function to connect to Entra ID using Microsoft Graph API endpoints ]
Function Connect-EntraID
{
    param (
        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$ClientSecret,

        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [int]$RefreshInterval
    )

    try
    {
        # Initialize token variables
        $global:accessToken          = $null
        $global:tokenExpirationTime  = $null

        # Initialize refresh interval in minutes
        $global:RefreshIntervalInMinutes = $RefreshInterval

        # ADDED ↓ — store identifiers/secret as globals so RequestAccessToken
        # can reach them after Connect-EntraID returns. ClientSecret is kept
        # as a SecureString global; it is only ever marshaled to plaintext
        # transiently inside RequestAccessToken.
        $global:TenantId           = $TenantId
        $global:ClientId           = $ClientId
        $global:ClientSecretSecure = $ClientSecret

        # Request initial access token — still called here for first-time auth
        RequestAccessToken

        # Return access token
        return $global:accessToken
    }
    catch
    {
        Write-Error "Failed to connect to Entra ID. Details: $_"
        return $null
    }
}


#--------------------------------------------------------------------------------------------------- [ Function to retrieves Conditional Access Policies from Microsoft Graph Beta API and exports them to CSV or JSON format ]
Function Get-ConditionalAccessPoliciesReport
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV", "JSON")]
        [string]$OutputFormat = "JSON",

        [string]$OutputPath = "C:\temp\ConditionalAccessPolicies",

        [string[]]$PolicyName   # Accepts one or more policy names
    )

    # Prepare Graph API call
    $headers = @{
        "ConsistencyLevel" = "eventual"
        "Content-Type"     = "application/json"
    }

    if ($AccessToken)
    {
        $headers["Authorization"] = "Bearer $AccessToken"
    }

    $uri = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"

    try
    {
        Write-Host "Fetching Conditional Access Policies from Graph Beta endpoint..." -ForegroundColor Yellow
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers

        $policies = $response.value

        if ($policies.Count -eq 0)
        {
            Write-Warning "No Conditional Access Policies found."
            return
        }

        # 🔹 Filter by PolicyName if provided
        if ($PolicyName)
        {
            $policies = $policies | Where-Object { $_.displayName -in $PolicyName }
            if (-not $policies)
            {
                Write-Warning "No Conditional Access Policy found matching the specified PolicyName(s): $($PolicyName -join ', ')"
                return
            }
        }

        $report = foreach ($policy in $policies)
        {
            if ($OutputFormat -eq 'CSV') {
                [PSCustomObject]@{
                    Id                   = $policy.id
                    PolicyName           = $policy.displayName
                    State                = $policy.state
                    CreatedDateTime      = $policy.createdDateTime
                    ModifiedDateTime     = $policy.modifiedDateTime
                    IncludeUsers         = ($policy.conditions.users.includeUsers -join ", ")
                    ExcludeUsers         = ($policy.conditions.users.excludeUsers -join ", ")
                    IncludeGroups        = ($policy.conditions.users.includeGroups -join ", ")
                    ExcludeGroups        = ($policy.conditions.users.excludeGroups -join ", ")
                    IncludeApps          = ($policy.conditions.applications.includeApplications -join ", ")
                    ExcludeApps          = ($policy.conditions.applications.excludeApplications -join ", ")
                    Conditions           = ($policy.conditions | ConvertTo-Json -Depth 5 -Compress)
                    GrantControls        = ($policy.grantControls | ConvertTo-Json -Depth 5 -Compress)
                    SessionControls      = ($policy.sessionControls | ConvertTo-Json -Depth 5 -Compress)
                }
            }
            else {
                # For JSON, keep objects raw and nested for full structure
                [PSCustomObject]@{
                    Id                   = $policy.id
                    PolicyName           = $policy.displayName
                    State                = $policy.state
                    CreatedDateTime      = $policy.createdDateTime
                    ModifiedDateTime     = $policy.modifiedDateTime
                    IncludeUsers         = $policy.conditions.users.includeUsers
                    ExcludeUsers         = $policy.conditions.users.excludeUsers
                    IncludeGroups        = $policy.conditions.users.includeGroups
                    ExcludeGroups        = $policy.conditions.users.excludeGroups
                    IncludeApps          = $policy.conditions.applications.includeApplications
                    ExcludeApps          = $policy.conditions.applications.excludeApplications
                    Conditions           = $policy.conditions
                    GrantControls        = $policy.grantControls
                    SessionControls      = $policy.sessionControls
                }
            }
        }

        # Export or show the report
        switch ($OutputFormat.ToUpper())
        {
            'CSV'
            {
                # Ensure output folder exists
                $folder = Split-Path -Path $OutputPath -Parent
                if (-not (Test-Path $folder)) {
                    New-Item -ItemType Directory -Path $folder -Force | Out-Null
                }

                $csvPath = [System.IO.Path]::ChangeExtension($OutputPath, "csv")
                $report | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Host "✅ CSV Report exported to: $csvPath" -ForegroundColor Green
            }
            'JSON'
            {
                $jsonPath = [System.IO.Path]::ChangeExtension($OutputPath, "json")

                # Ensure output folder exists
                $folder = Split-Path -Path $jsonPath -Parent
                if (-not (Test-Path $folder)) {
                    New-Item -ItemType Directory -Path $folder -Force | Out-Null
                }

                $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
                Write-Host "✅ JSON Report exported to: $jsonPath" -ForegroundColor Green
            }
            Default
            {
                Write-Warning "Unsupported output format '$OutputFormat'. Supported values: CSV, JSON."
            }
        }

    }
    catch
    {
        Write-Error "Failed to retrieve Conditional Access Policies. $_"
    }
}


#--------------------------------------------------------------------------------------------------- [ Script Execution ]

Clear-Host

# Remove stale session variables if they exist
Remove-Variable -Name accessToken, tokenExpirationTime -ErrorAction SilentlyContinue

# Ensure default output directory exists
If ((Test-Path "C:\Temp") -eq $false)
{
   New-Item -Path "C" -Name "Temp" -ItemType "Directory" | Out-Null
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║     Entra ID — Conditional Access Policies Report            ║" -ForegroundColor Cyan
Write-Host "  ║                     Version 2.0  |  2026                     ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Step 1 : Authentication ───────────────────────────────────────────────────
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
Write-Host "  │   STEP 1 of 2  ›  Authenticating to Entra ID                │" -ForegroundColor DarkCyan
Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
Write-Host ""

# Check which authentication method to use
$effectiveAccessToken = $null

if ($PSCmdlet.ParameterSetName -eq "ClientCredentials")
{
    # Using client credentials flow
    Write-Host "  ⏳ Requesting access token via client credentials..." -ForegroundColor Yellow
    $effectiveAccessToken = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId -RefreshInterval 15
}
else
{
    # Using direct bearer token
    $effectiveAccessToken = $AccessToken
}

# Validate that access token was obtained successfully
if (-not $effectiveAccessToken)
{
    Write-Error "Failed to obtain access token. Please check your credentials."
    return
}

Write-Host "  ✅ Authentication successful" -ForegroundColor Green
Write-Host ""

# ── Step 2 : Retrieve Policies ───────────────────────────────────────────────────
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
Write-Host "  │   STEP 2 of 2  ›  Retrieving Conditional Access Policies    │" -ForegroundColor DarkCyan
Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
Write-Host ""

# Invoke the Get-ConditionalAccessPoliciesReport function
Get-ConditionalAccessPoliciesReport -AccessToken $effectiveAccessToken -OutputFormat $OutputFormat -OutputPath $OutputPath -PolicyName $PolicyName

Write-Host ""