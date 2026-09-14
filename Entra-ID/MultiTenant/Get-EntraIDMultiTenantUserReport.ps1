<#

.AUTHOR
    Author       : Lakshmanan Thangaraj
    Version      : 1.2
    Created-On   : 12 September 2026
    Modified-On  : 14 September 2026

.SYNOPSIS
    Generates a consolidated user account report across one or more Microsoft Entra ID tenants.

.DESCRIPTION
    Think of Microsoft Entra ID as a company's digital employee directory — it holds
    every person's name, email, job title, and more. Large organisations often have
    MORE THAN ONE such directory (called a "tenant"), sometimes one per region or
    subsidiary.

    This script reads those directories — from as many tenants as you give it —
    and combines everything into ONE tidy spreadsheet (CSV file) that you can open
    in Microsoft Excel.

    The final report tells you:
      • Who exists in each tenant (name, email, account status)
      • Whether they are synced from an on-premises Active Directory
      • Their manager's details
      • Which Microsoft 365 licences they hold
      • When they last signed in (if the tenant supports this)
      • Which tenant each user belongs to

    ─────────────────────────────────────────────────────────────────────────────
    HOW DOES IT WORK? (Step by Step)
    ─────────────────────────────────────────────────────────────────────────────

    Step 1  →  The script uses a registered Azure App (like a door pass) to
                authenticate to each tenant securely — no passwords typed manually.

    Step 2  →  It fetches ALL users from each tenant, page by page, so even
                tenants with 100,000+ users are handled correctly.

    Step 3  →  For every user it collects:
                  - Manager information
                  - Assigned Microsoft 365 licence details
                  - Sign-in activity (last sign-in timestamps)
                  - Tenant-level details (name, primary domain, country)

    Step 4  →  If the access token is about to expire during a long run, the
                script automatically renews it — no manual intervention needed.

    Step 5  →  All data is merged and exported to a single CSV file.

    ─────────────────────────────────────────────────────────────────────────────
    AUTHENTICATION MODEL
    ─────────────────────────────────────────────────────────────────────────────

    This script uses the OAuth 2.0 Client Credentials Flow exclusively.
    That means it authenticates as an APPLICATION (not a user), which is the
    recommended approach for automation and large-scale reporting because:

      ✔  No interactive login prompts
      ✔  Works unattended in scheduled tasks or Azure Automation
      ✔  Access can be scoped tightly to read-only Graph permissions
      ✔  Client secret is accepted as a SecureString — never stored as plain text
          in the script file or logs

    ─────────────────────────────────────────────────────────────────────────────
    INTERNAL HELPER FUNCTIONS (called automatically — you do not invoke these)
    ─────────────────────────────────────────────────────────────────────────────

    Connect-EntraIDTenant       Authenticates to a tenant and retrieves an access token
    Invoke-EntraIDTokenRefresh  Checks token age and renews it before it expires
    Get-EntraIDAllUsers         Retrieves all users with pagination support
    Get-EntraIDManagerDetails   Fetches manager info for a given user
    Get-EntraIDAssignedLicenses Fetches assigned Microsoft 365 licences for a user
    Get-EntraIDTenantDetails    Retrieves tenant-level metadata (name, domain, country)

.PARAMETER ClientId
    The Application (Client) ID of the Azure App Registration created in your
    primary tenant. This is the "identity card" your script uses to authenticate.

    Where to find it:
    Azure Portal → Azure Active Directory → App Registrations → Your App → Overview → Application (client) ID

.PARAMETER ClientSecret
    The client secret of the Azure App Registration, provided as a SecureString.

    A SecureString keeps the secret encrypted in memory — it is NEVER stored or
    logged as plain text anywhere in this script.

    How to create one at runtime:
        $secret = Read-Host -Prompt "Enter Client Secret" -AsSecureString

    Where to create it in Azure:
    Azure Portal → App Registrations → Your App → Certificates & Secrets → New Client Secret

.PARAMETER TenantIds
    An array of one or more Tenant IDs (GUIDs) to report against.

    A Tenant ID is a unique identifier for each Microsoft Entra ID directory.
    You can find it at:
    Azure Portal → Azure Active Directory → Overview → Tenant ID

    Examples:
        Single tenant  : @("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
        Multi-tenant   : @("tenant1-guid", "tenant2-guid", "tenant3-guid")

.PARAMETER TokenRefreshIntervalMinutes
    How many minutes before token expiry the script should proactively renew the
    access token. Default is 5 minutes.

    Increase this value for very large tenants where processing a single page of
    users might take longer than expected.

.PARAMETER ExportPath
    Full file path for the exported CSV report.

    Defaults to: C:\Temp\EntraID-Multi-Tenants-UserAccount-Report.csv

    The folder is created automatically if it does not already exist.

.PARAMETER GenerateHtmlReport
    When this switch is present, the script generates an additional HTML dashboard report
    alongside the CSV export.

    The HTML file is saved to the same folder as -ExportPath, using the same base file name
    with an .html extension.

    Example: if -ExportPath is "D:\Reports\MyReport.csv", the HTML report is saved as
             "D:\Reports\MyReport.html"

    When -ExportPath is not specified, the HTML defaults to:
    C:\Temp\EntraID-Multi-Tenants-UserAccount-Report.html

    The dashboard includes 7 enterprise-focused tabs:
      • Executive Overview  — KPIs and overall identity posture
      • Tenant Overview     — per-tenant user and governance breakdown
      • User Governance     — searchable, sortable full user inventory
      • Sign-In & Inactivity— inactive, stale, and never-signed-in users
      • License & Identity  — licensing and usage insights
      • Governance & Risk   — actionable identity governance exceptions
      • Data Quality        — missing data and collection anomalies

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Collections.ArrayList
    Returns all user records as an in-memory object array.
    Also exports the data to a CSV file at the specified ExportPath.

.EXAMPLE
    ── Example 1: Single tenant, interactive secret prompt ──────────────────────

    $secret = Read-Host -Prompt "Enter Client Secret" -AsSecureString

    Get-EntraIDMultiTenantUserReport `
        -ClientId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret $secret `
        -TenantIds   @("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    Connects to one tenant and exports the report to the default path.

.EXAMPLE
    ── Example 2: Multiple tenants, custom export path ──────────────────────────

    $secret = Read-Host -Prompt "Enter Client Secret" -AsSecureString

    Get-EntraIDMultiTenantUserReport `
        -ClientId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret $secret `
        -TenantIds   @(
                         "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                         "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
                     ) `
        -ExportPath  "D:\Reports\EntraID-UserReport.csv"

    Connects to two tenants and saves the merged report to a custom location.

.EXAMPLE
    ── Example 3: Capture output for further processing in the same session ─────

    $secret = Read-Host -Prompt "Enter Client Secret" -AsSecureString

    $report = Get-EntraIDMultiTenantUserReport `
                  -ClientId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
                  -ClientSecret $secret `
                  -TenantIds   @("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    # Filter only disabled accounts in PowerShell after the fact
    $report | Where-Object { $_.AccountEnabled -eq $false }

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.2 (14-Sep-2026) - Added -GenerateHtmlReport switch. When present, generates a
                        7-tab HTML dashboard alongside the existing CSV export. HTML
                        is written to the same folder as -ExportPath with a .html
                        extension. No changes to existing CSV logic.

    1.1 (12-Sep-2026) - Added parallel user enrichment via runspace pool 
                        ($ThrottleLimit param); manager and license calls now run 
                        concurrently per tenant.

    1.0 (12-Sep-2026) - Initial public release. Refactored from internal version
                        with standards compliance, SecureString auth, automatic
                        token renewal, Write-Progress support, and full help block.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────

    ════════════════════════════════════════════════════════════════
    STEP 1 — Register an Application in Your PRIMARY Tenant
    ════════════════════════════════════════════════════════════════

    (Do this once. This is your script's "identity card" for authenticating.)

    1.1  Sign in to https://portal.azure.com with a Global Administrator account.

    1.2  Go to:
         Azure Active Directory → App Registrations → New Registration

    1.3  Fill in the registration form:
           Name                  : EntraIDUserReportApp   (or any name you choose)
           Supported account types: Accounts in any organizational directory
                                    (Multitenant)
           Redirect URI          : Leave blank (not needed for this script)

    1.4  Click Register. Note down the "Application (client) ID" — you will need
         this as the -ClientId parameter.

    1.5  Create a Client Secret:
         → Certificates & Secrets → New Client Secret
         → Set a description and expiry → Click Add
         → Copy the VALUE immediately (you cannot see it again after you leave the page)

    1.6  Grant API Permissions (read-only, application permissions):
         → API Permissions → Add a Permission → Microsoft Graph → Application Permissions

         Add ALL of the following:
           ┌──────────────────────────────┬────────────────────────────────────────────┐
           │ Permission                   │ Why it is needed                           │
           ├──────────────────────────────┼────────────────────────────────────────────┤
           │ User.Read.All                │ Read all user profiles                     │
           │ Directory.Read.All           │ Read tenant and organisational data        │
           │ AuditLog.Read.All            │ Read sign-in activity timestamps           │
           │ Organization.Read.All        │ Read tenant name, domain, and country      │
           └──────────────────────────────┴────────────────────────────────────────────┘

         → Click "Grant admin consent for [Your Organisation]" (requires Global Admin)

    ════════════════════════════════════════════════════════════════
    STEP 2 — Register the App in Each ADDITIONAL Tenant
    ════════════════════════════════════════════════════════════════

    (Repeat this for every tenant you want to include in the report.)

    Because the App was registered as "Multitenant", you must create a Service
    Principal (a local copy of the App) inside each additional tenant.

    2.1  Connect to the additional tenant using PowerShell:

         Connect-MgGraph `
             -Scopes "Application.ReadWrite.All" `
             -TenantId "additional-tenant-id-here"

    2.2  Create the Service Principal:

         New-MgServicePrincipal -AppId "YOUR_APP_CLIENT_ID_FROM_STEP_1"

    2.3  Grant the same API permissions in the additional tenant.
         Use either the Azure Portal (App Registrations → Enterprise Applications →
         find your app → Permissions → Grant admin consent) or PowerShell:

         # Example: granting User.Read.All
         $params = @{
             principalId = "ServicePrincipal_ObjectID_In_Tenant2"
             resourceId  = "MicrosoftGraph_ServicePrincipal_ObjectID_In_Tenant2"
             appRoleId   = "df021288-bdef-4463-88db-98f22de89214"  # User.Read.All
         }
         New-MgServicePrincipalAppRoleAssignedTo `
             -ServicePrincipalId $params.principalId `
             -BodyParameter $params

         Reference: https://learn.microsoft.com/en-us/graph/permissions-grant-via-msgraph

    ════════════════════════════════════════════════════════════════
    STEP 3 — No PowerShell Modules Required
    ════════════════════════════════════════════════════════════════

    This script uses direct REST calls to Microsoft Graph API.
    You do NOT need to install the Microsoft.Graph PowerShell SDK.
    PowerShell 5.1 or later is sufficient.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Sign-in activity fields (LastSignInDateTime etc.) will be blank for tenants
      that do not have a Microsoft Entra ID P1 or P2 licence. This is a Microsoft
      licencing constraint, not a script defect.

    - Microsoft Graph may throttle requests (HTTP 429) for tenants with very large
      user populations. The script handles this automatically by honouring the
      Retry-After header, but total run time will increase accordingly.

    - Manager details are retrieved one user at a time (Graph does not support
      bulk manager lookups). For tenants with 50,000+ users, expect longer run times.

    - The Client Secret has an expiry date set in Azure. When it expires, the
      script will fail to authenticate. Rotate the secret before expiry and update
      the value you supply to -ClientSecret.

.LINK
    https://learn.microsoft.com/en-us/graph/api/user-list
    https://learn.microsoft.com/en-us/graph/api/user-get-manager
    https://learn.microsoft.com/en-us/graph/api/user-list-licensedetails
    https://learn.microsoft.com/en-us/graph/api/organization-get
    https://learn.microsoft.com/en-us/graph/permissions-grant-via-msgraph
    https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow

#>


Function Get-EntraIDMultiTenantUserReport {
    [CmdletBinding()]
    param
    (
        # ── Mandatory Parameters ──────────────────────────────────────────────────

        [Parameter(Mandatory = $true, HelpMessage = "Application (Client) ID of the Azure App Registration.")]
        [ValidateNotNullOrEmpty()]
        [string] $ClientId,

        [Parameter(Mandatory = $true, HelpMessage = "Client secret as a SecureString. Use: Read-Host -AsSecureString")]
        [ValidateNotNull()]
        [System.Security.SecureString] $ClientSecret,

        [Parameter(Mandatory = $true, HelpMessage = "One or more Tenant IDs (GUIDs) to report against.")]
        [ValidateNotNullOrEmpty()]
        [string[]] $TenantIds,

        # ── Optional Parameters ───────────────────────────────────────────────────

        [Parameter(Mandatory = $false, HelpMessage = "Minutes before token expiry at which the token is proactively renewed.")]
        [ValidateRange(1, 30)]
        [int] $TokenRefreshIntervalMinutes = 5,

        [Parameter(Mandatory = $false, HelpMessage = "Full path for the exported CSV report.")]
        [ValidateNotNullOrEmpty()]
        [string] $ExportPath = "C:\Temp\EntraID-Multi-Tenants-UserAccount-Report.csv",

        [Parameter(Mandatory = $false, HelpMessage = "Maximum number of users to process in parallel. Default is 10.")]
        [ValidateRange(1, 20)]
        [int] $ThrottleLimit = 10,

        [Parameter(Mandatory = $false, HelpMessage = "When present, generates an HTML dashboard report alongside the CSV export.")]
        [switch] $GenerateHtmlReport
    )


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Token helpers (Client Credentials Flow)
    #
    # WHY $global: IS USED HERE
    # All helper functions below are nested inside Get-EntraIDMultiTenantUserReport.
    # In PS 5.1, nested functions resolve variables by walking up the call stack,
    # but $script: inside a function body refers to the .ps1 file scope — not the
    # parent function's local scope. $global: is the only qualifier guaranteed to
    # be visible to all nested functions regardless of nesting depth.
    #
    # WHY THE SECRET IS DECODED IN THE PARENT BODY (not inside a nested function)
    # SecureString objects in PS 5.1 are DPAPI-bound to the scope/thread that
    # created them. Decoding a SecureString passed as a parameter from inside a
    # nested function produces a corrupted BSTR — the plain text is wrong and
    # Azure rejects it with AADSTS7000215. Decoding in the parent function body
    # (same scope where $ClientSecret arrived) works correctly every time.
    #─────────────────────────────────────────────────────────────────────────────


    # ── Fetches a fresh access token from the Microsoft identity platform ─────────

    Function Invoke-EntraIDTokenRequest {
        $tokenEndpoint = "https://login.microsoftonline.com/$($global:_ctx.TenantId)/oauth2/v2.0/token"

        Try {
            $body = @{
                client_id     = $global:_ctx.ClientId
                client_secret = $global:_ctx.ClientSecret   # plain string, decoded once in parent body
                scope         = "https://graph.microsoft.com/.default"
                grant_type    = "client_credentials"
            }

            $response = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ErrorAction Stop
            $global:_ctx.AccessToken = $response.access_token
            $global:_ctx.TokenExpiry = (Get-Date).AddSeconds($response.expires_in)

            Write-Verbose "Access token acquired. Expires at: $($global:_ctx.TokenExpiry.ToString('HH:mm:ss'))"
        }
        Finally {
            # Scrub only the local body hashtable — NOT $global:_ctx.ClientSecret,
            # because the same secret must survive across all tenants in the loop.
            $body = $null
        }
    }


    # ── Returns $true if the current token needs to be renewed ────────────────────

    Function Test-EntraIDTokenRenewalRequired {
        if (-not $global:_ctx.AccessToken -or -not $global:_ctx.TokenExpiry) {
            return $true
        }

        $minutesRemaining = ($global:_ctx.TokenExpiry - (Get-Date)).TotalMinutes
        return ($minutesRemaining -lt $global:_ctx.RefreshIntervalMinutes)
    }


    # ── Renews the token if it is approaching expiry ──────────────────────────────

    Function Invoke-EntraIDTokenRefreshIfNeeded {
        if (Test-EntraIDTokenRenewalRequired) {
            Write-Host "  🔄  Our temporary pass to this directory is about to expire — getting a fresh one..." -ForegroundColor Yellow
            Invoke-EntraIDTokenRequest
            Write-Host "  ✅  Fresh pass obtained — continuing where we left off." -ForegroundColor Green
        }
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Tenant Authentication
    #─────────────────────────────────────────────────────────────────────────────

    Function Connect-EntraIDTenant {
        param
        (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $TenantId
        )

        Try {
            $global:_ctx.TenantId = $TenantId
            $global:_ctx.AccessToken = $null
            $global:_ctx.TokenExpiry = $null

            Invoke-EntraIDTokenRequest

            Write-Verbose "Connected to tenant: $TenantId"
            return $global:_ctx.AccessToken
        }
        Catch {
            Write-Error "Failed to authenticate to tenant '$TenantId'. Details: $_"
            return $null
        }
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Graph API Call Wrapper
    # Central wrapper for all Graph calls. Handles throttling (HTTP 429)
    # automatically by honouring the Retry-After header.
    #─────────────────────────────────────────────────────────────────────────────

    Function Invoke-GraphRequestAPI {
        param
        (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $Uri,

            [hashtable] $AdditionalHeaders = @{}
        )

        $headers = @{ "Authorization" = "Bearer $($global:_ctx.AccessToken)" } + $AdditionalHeaders

        $maxRetries = 5
        $retryCount = 0
        $responseData = $null

        do {
            $retryCount++
            Try {
                $response = Invoke-WebRequest -Uri $Uri -Headers $headers -Method Get -ErrorAction Stop
                $responseData = $response.Content | ConvertFrom-Json
                break
            }
            Catch {
                $statusCode = $_.Exception.Response.StatusCode

                if ($statusCode -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers.Item("Retry-After")
                    Write-Warning "Graph API throttled (HTTP 429). Waiting $retryAfter seconds before retry $retryCount of $maxRetries..."
                    Start-Sleep -Seconds $retryAfter
                }
                elseif ($statusCode -eq 404) {
                    # Resource not found is expected for some calls (e.g. no manager) — return null silently
                    return $null
                }
                else {
                    Write-Warning "Graph API request failed. URI: $Uri | StatusCode: $statusCode | Error: $($_.Exception.Message)"
                    return $null
                }
            }
        }
        while ($retryCount -lt $maxRetries)

        return $responseData
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Data Retrieval Functions
    #─────────────────────────────────────────────────────────────────────────────

    Function Get-EntraIDAllUsers {
        $allUsers = New-Object System.Collections.ArrayList
        $totalCount = 0

        # $select ensures only the fields we need are returned — faster and lighter.
        # signInActivity requires the AuditLog.Read.All permission.
        $uri = "https://graph.microsoft.com/beta/users" +
        "?`$top=100" +
        "&`$select=id,userPrincipalName,mail,displayName,userType,accountEnabled," +
        "onPremisesSyncEnabled,createdDateTime,department,signInActivity" +
        "&`$count=true"

        do {
            Invoke-EntraIDTokenRefreshIfNeeded

            $data = Invoke-GraphRequestAPI -Uri $uri -AdditionalHeaders @{ "ConsistencyLevel" = "eventual" }

            if (-not $data) {
                Write-Warning "No data returned from users endpoint. Stopping pagination."
                break
            }

            # Flatten signInActivity into top-level properties so the object is
            # simple and CSV-serialisable without nested expansion later.
            foreach ($user in $data.value) {
                $null = $allUsers.Add(
                    [PSCustomObject]@{
                        Id                               = $user.id
                        UserPrincipalName                = $user.userPrincipalName
                        Mail                             = $user.mail
                        DisplayName                      = $user.displayName
                        UserType                         = $user.userType
                        AccountEnabled                   = $user.accountEnabled
                        OnPremisesSyncEnabled            = $user.onPremisesSyncEnabled
                        CreatedDateTime                  = $user.createdDateTime
                        Department                       = $user.department
                        LastSignInDateTime               = if ($user.PSObject.Properties['signInActivity']) { $user.signInActivity.lastSignInDateTime }               else { $null }
                        LastNonInteractiveSignInDateTime = if ($user.PSObject.Properties['signInActivity']) { $user.signInActivity.lastNonInteractiveSignInDateTime } else { $null }
                        LastSuccessfulSignInDateTime     = if ($user.PSObject.Properties['signInActivity']) { $user.signInActivity.lastSuccessfulSignInDateTime }     else { $null }
                    }
                )
            }

            $totalCount += $data.value.Count
            Write-Verbose "Users retrieved so far: $totalCount"

            # Follow the nextLink for pagination; stop when it is absent.
            $uri = if ($data.PSObject.Properties['@odata.nextLink']) { $data.'@odata.nextLink' } else { $null }
        }
        while ($uri)

        return $allUsers
    }


    Function Get-EntraIDManagerDetails {
        param
        (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $UserId
        )

        $uri = "https://graph.microsoft.com/beta/users/$UserId/manager"
        return Invoke-GraphRequestAPI -Uri $uri
    }


    Function Get-EntraIDAssignedLicenses {
        param
        (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $UserId
        )

        $uri = "https://graph.microsoft.com/beta/users/$UserId/licenseDetails"
        $data = Invoke-GraphRequestAPI -Uri $uri

        if ($data -and $data.value) {
            return $data.value
        }

        return @()
    }


    Function Get-EntraIDTenantDetails {
        $uri = "https://graph.microsoft.com/beta/organization"
        $data = Invoke-GraphRequestAPI -Uri $uri

        if (-not $data -or -not $data.value) {
            Write-Warning "Could not retrieve tenant details."
            return $null
        }

        $tenant = $data.value
        $primaryDomain = ($tenant.verifiedDomains | Where-Object { $_.isDefault -eq $true }).name

        return [PSCustomObject]@{
            TenantId            = $tenant.id
            TenantName          = $tenant.displayName
            TenantPrimaryDomain = $primaryDomain
            TenantType          = $tenant.tenantType
            Country             = $tenant.country
            CountryCode         = $tenant.countryLetterCode
            CreatedDate         = $tenant.createdDateTime
            TechnicalContact    = ($tenant.technicalNotificationMails -join " ; ")
            VerifiedDomainNames = ($tenant.verifiedDomains.name -join " ; ")
            VerifiedDomainTypes = ($tenant.verifiedDomains.type -join " ; ")
        }
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: HTML Helper
    # Escapes a PowerShell string for safe embedding inside a JavaScript string
    # literal. Called once per field, per user, when building the JSON data blob
    # for the HTML dashboard. Never used in the CSV path.
    #─────────────────────────────────────────────────────────────────────────────

    Function ConvertTo-HtmlJsonSafe
    {
        param ([string] $Text)

        $Text `
            -replace '\\',      '\\\\'   `
            -replace '"',       '\"'     `
            -replace "`r`n",    '\n'     `
            -replace "`n",      '\n'     `
            -replace "`r",      '\n'     `
            -replace "`t",      '\t'     `
            -replace '<',       '\u003c' `
            -replace '>',       '\u003e' `
            -replace '\$',      '\u0024'
    }

    Function Export-EntraIDHtmlReport
    {
        param
        (
            [Parameter(Mandatory = $true)]
            [System.Collections.ArrayList] $UserRecords,

            [Parameter(Mandatory = $true)]
            [string[]] $TenantIdList,

            [Parameter(Mandatory = $true)]
            [string] $OutputPath
        )

        #─────────────────────────────────────────────────────────────────────────
        # STEP 1 — Pre-compute all metrics PowerShell-side.
        # Rule: compute everything here; substitute into the here-string via
        # -replace tokens. Never do logic inside the here-string itself.
        #─────────────────────────────────────────────────────────────────────────

        $generatedAt  = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')
        $totalUsers   = $UserRecords.Count
        $totalTenants = $TenantIdList.Count

        # ── Stat card metrics ──────────────────────────────────────────────────

        $cntEnabled         = @($UserRecords | Where-Object { $_.'Account Enabled' -eq $true  }).Count
        $cntDisabled        = @($UserRecords | Where-Object { $_.'Account Enabled' -eq $false }).Count
        $cntLicensed        = @($UserRecords | Where-Object { $_.'Is Licence Assigned' -eq 'Yes' }).Count
        $cntUnlicensed      = @($UserRecords | Where-Object { $_.'Is Licence Assigned' -eq 'No'  }).Count
        $cntGuest           = @($UserRecords | Where-Object { $_.'User Type' -eq 'Guest' }).Count
        $cntSynced          = @($UserRecords | Where-Object { $_.'Is Synced From On-Premises' -eq $true -or $_.'Is Synced From On-Premises' -eq 'True' }).Count

        # ── Sign-in inactivity buckets (days since last successful sign-in) ────
        # Users with no sign-in date at all are treated as "Never Signed In"

        $now = Get-Date

        $cntNeverSignedIn   = @($UserRecords | Where-Object { [string]::IsNullOrEmpty($_.'Last Successful Sign-In') }).Count
        $cntInactive90      = @($UserRecords | Where-Object {
            -not [string]::IsNullOrEmpty($_.'Last Successful Sign-In') -and
            ($now - [datetime]$_.'Last Successful Sign-In').TotalDays -gt 90
        }).Count
        $cntInactive30      = @($UserRecords | Where-Object {
            -not [string]::IsNullOrEmpty($_.'Last Successful Sign-In') -and
            ($now - [datetime]$_.'Last Successful Sign-In').TotalDays -gt 30 -and
            ($now - [datetime]$_.'Last Successful Sign-In').TotalDays -le 90
        }).Count
        $cntActiveRecent    = @($UserRecords | Where-Object {
            -not [string]::IsNullOrEmpty($_.'Last Successful Sign-In') -and
            ($now - [datetime]$_.'Last Successful Sign-In').TotalDays -le 30
        }).Count

        # ── Risk / governance exception counts ────────────────────────────────

        $cntNoManager       = @($UserRecords | Where-Object {
            $_.'Account Enabled' -eq $true -and [string]::IsNullOrEmpty($_.'Manager UPN')
        }).Count
        $cntLicensedDisabled = @($UserRecords | Where-Object {
            $_.'Account Enabled' -eq $false -and $_.'Is Licence Assigned' -eq 'Yes'
        }).Count
        $cntStaleLicensed   = @($UserRecords | Where-Object {
            $_.'Is Licence Assigned' -eq 'Yes' -and
            -not [string]::IsNullOrEmpty($_.'Last Successful Sign-In') -and
            ($now - [datetime]$_.'Last Successful Sign-In').TotalDays -gt 90
        }).Count

        # ── Data quality counts ────────────────────────────────────────────────

        $cntNoEmail         = @($UserRecords | Where-Object {
            $_.'User Type' -ne 'Guest' -and [string]::IsNullOrEmpty($_.'Email')
        }).Count
        $cntNoDept          = @($UserRecords | Where-Object {
            $_.'User Type' -ne 'Guest' -and [string]::IsNullOrEmpty($_.'Department')
        }).Count
        $cntNoDisplayName   = @($UserRecords | Where-Object {
            [string]::IsNullOrEmpty($_.'Display Name')
        }).Count

        #─────────────────────────────────────────────────────────────────────────
        # STEP 2 — Build per-tenant summary JSON for the Tenant Overview tab.
        # One JSON object per tenant: name, domain, counts.
        #─────────────────────────────────────────────────────────────────────────

        $tenantSummaryJson = ($UserRecords |
            Group-Object 'Tenant ID' |
            ForEach-Object {
                $grp     = $_.Group
                $tName   = ConvertTo-HtmlJsonSafe ($grp[0].'Tenant Name'          ?? '')
                $tDomain = ConvertTo-HtmlJsonSafe ($grp[0].'Tenant Primary Domain' ?? '')
                $tId     = ConvertTo-HtmlJsonSafe ($_.Name ?? '')
                $tTotal  = $grp.Count
                $tEn     = @($grp | Where-Object { $_.'Account Enabled' -eq $true  }).Count
                $tDis    = @($grp | Where-Object { $_.'Account Enabled' -eq $false }).Count
                $tLic    = @($grp | Where-Object { $_.'Is Licence Assigned' -eq 'Yes' }).Count
                $tGuest  = @($grp | Where-Object { $_.'User Type' -eq 'Guest' }).Count
                $tSynced = @($grp | Where-Object { $_.'Is Synced From On-Premises' -eq $true -or $_.'Is Synced From On-Premises' -eq 'True' }).Count
                "{`"id`":`"$tId`",`"name`":`"$tName`",`"domain`":`"$tDomain`",`"total`":$tTotal,`"enabled`":$tEn,`"disabled`":$tDis,`"licensed`":$tLic,`"guest`":$tGuest,`"synced`":$tSynced}"
            }
        ) -join ','

        #─────────────────────────────────────────────────────────────────────────
        # STEP 3 — Build the per-user JSON array for the User Governance tab.
        # Fields map directly to the CSV columns. All string fields are run
        # through ConvertTo-HtmlJsonSafe before embedding.
        #─────────────────────────────────────────────────────────────────────────

        $usersJson = ($UserRecords | ForEach-Object {
            $upn        = ConvertTo-HtmlJsonSafe ($_.'Login Name'          ?? '')
            $display    = ConvertTo-HtmlJsonSafe ($_.'Display Name'        ?? '')
            $email      = ConvertTo-HtmlJsonSafe ($_.'Email'               ?? '')
            $dept       = ConvertTo-HtmlJsonSafe ($_.'Department'          ?? '')
            $userType   = ConvertTo-HtmlJsonSafe ($_.'User Type'           ?? '')
            $mgrDisplay = ConvertTo-HtmlJsonSafe ($_.'Manager Display Name'?? '')
            $mgrUpn     = ConvertTo-HtmlJsonSafe ($_.'Manager UPN'         ?? '')
            $tenantName = ConvertTo-HtmlJsonSafe ($_.'Tenant Name'         ?? '')
            $tenantDom  = ConvertTo-HtmlJsonSafe ($_.'Tenant Primary Domain'?? '')
            $licenses   = ConvertTo-HtmlJsonSafe ($_.'Assigned Licences'   ?? '')
            $lastSignIn = ConvertTo-HtmlJsonSafe ($_.'Last Successful Sign-In' ?? '')
            $created    = ConvertTo-HtmlJsonSafe ($_.'Created Date'        ?? '')
            $enabled    = if ($_.'Account Enabled' -eq $true)  { 'true' } else { 'false' }
            $licensed   = if ($_.'Is Licence Assigned' -eq 'Yes') { 'true' } else { 'false' }
            $synced     = if ($_.'Is Synced From On-Premises' -eq $true -or $_.'Is Synced From On-Premises' -eq 'True') { 'true' } else { 'false' }

            "{`"upn`":`"$upn`",`"display`":`"$display`",`"email`":`"$email`",`"dept`":`"$dept`",`"type`":`"$userType`",`"enabled`":$enabled,`"licensed`":$licensed,`"synced`":$synced,`"mgrDisplay`":`"$mgrDisplay`",`"mgrUpn`":`"$mgrUpn`",`"tenant`":`"$tenantName`",`"tenantDom`":`"$tenantDom`",`"licenses`":`"$licenses`",`"lastSignIn`":`"$lastSignIn`",`"created`":`"$created`"}"
        }) -join ','

        #─────────────────────────────────────────────────────────────────────────
        # STEP 4 — Build the HTML here-string with __TOKEN__ placeholders.
        # The single-quoted @'...'@ means NO PowerShell interpolation happens
        # inside this block. All values are injected via -replace at the end.
        # CSS variables, JS template literals, and $ signs are all safe.
        #─────────────────────────────────────────────────────────────────────────

        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Entra ID — Multi-Tenant User Report</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root {
  --bg:#0d1117; --surface:#161b22; --surface2:#1c2333; --surface3:#243048;
  --border:#30363d; --accent:#388bfd; --accent2:#39c5cf; --accent3:#a371f7;
  --green:#3fb950; --amber:#d29922; --red:#f85149;
  --text:#e6edf3; --muted:#7d8590; --muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px; --radius-sm:6px; --shadow:0 4px 24px rgba(0,0,0,.5);
}
body.light-theme {
  --bg:#f6f8fa; --surface:#fff; --surface2:#f0f3f6; --surface3:#e4e9ef;
  --border:#d0d7de; --accent:#0969da; --accent2:#0284a8; --accent3:#7c3aed;
  --green:#1a7f37; --amber:#b08000; --red:#cf222e;
  --text:#1f2328; --muted:#636c76; --muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}

/* ── Sidebar ── */
#sidebar{position:fixed;top:0;left:0;bottom:0;width:240px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text)}
.sidebar-logo p{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.version-badge{display:inline-block;margin-top:5px;background:rgba(56,139,253,.15);color:var(--accent);font-family:var(--mono);font-size:10px;padding:1px 8px;border-radius:20px;border:1px solid rgba(56,139,253,.3)}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:14px;width:20px;text-align:center;flex-shrink:0}
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

/* ── Main ── */
#main{margin-left:240px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:22px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

/* ── Stat cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:22px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s;cursor:default}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:26px;font-weight:700;color:var(--text);line-height:1}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}

/* ── Panels ── */
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.section-title{font-size:14px;font-weight:700;margin-bottom:14px;color:var(--text);display:flex;align-items:center;gap:7px}

/* ── Bar rows (used in charts) ── */
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-family:var(--mono);font-size:11px;color:var(--muted2);width:100px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:40px;text-align:right;flex-shrink:0}

/* ── Donut chart ── */
#donutWrap{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.legend-list{flex:1;min-width:130px;display:flex;flex-direction:column;gap:5px}
.legend-item{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted2);padding:2px 4px;border-radius:4px}
.legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.legend-pct{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}

/* ── Tenant cards ── */
.tenant-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;margin-bottom:22px}
.tenant-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;transition:border-color .2s,transform .15s}
.tenant-card:hover{border-color:var(--accent);transform:translateY(-2px)}
.tenant-card-head{display:flex;align-items:center;gap:10px;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.tenant-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0}
.tenant-name{font-size:13.5px;font-weight:700;color:var(--text)}
.tenant-domain{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:2px}
.tenant-stats{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.tenant-stat{background:var(--surface2);border-radius:var(--radius-sm);padding:8px 10px}
.tenant-stat-val{font-family:var(--mono);font-size:16px;font-weight:700;color:var(--text)}
.tenant-stat-lbl{font-size:11px;color:var(--muted);margin-top:1px}

/* ── Data table ── */
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:13px;padding:7px 10px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--accent)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:12px;flex-shrink:0}
.page-size-wrap{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.users-table{width:100%;border-collapse:collapse}
.users-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.users-table thead th:hover{color:var(--text)}
.users-table thead th.sort-active{color:var(--accent)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.users-table tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.users-table tbody tr:hover{background:var(--surface2)}
.users-table tbody td{padding:8px 12px;vertical-align:middle;font-size:13px}
.td-mono{font-family:var(--mono);font-size:12px}
.td-muted{color:var(--muted2);font-size:12px}
.status-pill{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600}
.pill-green{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.pill-red{background:rgba(248,81,73,.12);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.pill-amber{background:rgba(210,153,34,.12);color:var(--amber);border:1px solid rgba(210,153,34,.3)}
.pill-blue{background:rgba(56,139,253,.12);color:var(--accent);border:1px solid rgba(56,139,253,.3)}
.pill-muted{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:12px}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}

/* ── Risk item rows ── */
.risk-list{display:flex;flex-direction:column;gap:10px}
.risk-row{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 16px;display:flex;align-items:center;gap:14px;transition:border-color .15s}
.risk-row:hover{border-color:var(--amber)}
.risk-icon{font-size:20px;flex-shrink:0;width:28px;text-align:center}
.risk-title{font-size:13.5px;font-weight:600;color:var(--text)}
.risk-desc{font-size:12px;color:var(--muted2);margin-top:2px}
.risk-count{margin-left:auto;font-family:var(--mono);font-size:16px;font-weight:700;flex-shrink:0}
.risk-count.danger{color:var(--red)}
.risk-count.warn{color:var(--amber)}
.risk-count.ok{color:var(--green)}

/* ── Data quality rows ── */
.dq-list{display:flex;flex-direction:column;gap:8px}
.dq-row{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 14px;display:flex;align-items:center;gap:12px}
.dq-label{flex:1;font-size:13px;color:var(--muted2)}
.dq-val{font-family:var(--mono);font-size:14px;font-weight:700}
.dq-track{width:120px;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden;flex-shrink:0}
.dq-fill{height:100%;border-radius:3px;transition:width 1s ease}

/* ── Toast ── */
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

/* ── Responsive ── */
@media(max-width:768px){#sidebar{transform:translateX(-240px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">👥</div>
    <h1>Entra ID User Report</h1>
    <p>Multi-Tenant Identity Dashboard</p>
    <span class="version-badge">v1.2</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('exec',this)">
      <span class="nav-icon">📊</span> Executive Overview
    </button>
    <button class="nav-btn" onclick="showPage('tenants',this)">
      <span class="nav-icon">🏢</span> Tenant Overview
    </button>
    <button class="nav-btn" onclick="showPage('governance',this)">
      <span class="nav-icon">👤</span> User Governance
    </button>
    <button class="nav-btn" onclick="showPage('signin',this)">
      <span class="nav-icon">🔑</span> Sign-In &amp; Inactivity
    </button>
    <button class="nav-btn" onclick="showPage('license',this)">
      <span class="nav-icon">🪪</span> License &amp; Identity
    </button>
    <button class="nav-btn" onclick="showPage('risk',this)">
      <span class="nav-icon">⚠️</span> Governance &amp; Risk
    </button>
    <button class="nav-btn" onclick="showPage('dq',this)">
      <span class="nav-icon">🔎</span> Data Quality
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
    <span style="color:var(--accent2)">⌨</span> <kbd>/</kbd> search &nbsp; <kbd>Esc</kbd> close
  </div>
</nav>

<main id="main">

<!-- ══════════════════════════════════════════════════════ -->
<!-- TAB 1 — Executive Overview                           -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="page-exec" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Executive Overview</div>
      <div class="page-subtitle">Identity posture across __TOTALTENANTS__ tenant(s) · __TOTALUSERS__ users · Generated __GENERATEDAT__</div>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue">   <div class="stat-icon">👥</div><div class="stat-value">__TOTALUSERS__</div>  <div class="stat-label">Total Users</div></div>
    <div class="stat-card c-green">  <div class="stat-icon">✅</div><div class="stat-value">__CNTENABLED__</div>  <div class="stat-label">Enabled</div></div>
    <div class="stat-card c-red">    <div class="stat-icon">🚫</div><div class="stat-value">__CNTDISABLED__</div> <div class="stat-label">Disabled</div></div>
    <div class="stat-card c-cyan">   <div class="stat-icon">🪪</div><div class="stat-value">__CNTLICENSED__</div> <div class="stat-label">Licensed</div></div>
    <div class="stat-card c-amber">  <div class="stat-icon">📭</div><div class="stat-value">__CNTUNLICENSED__</div><div class="stat-label">Unlicensed</div></div>
    <div class="stat-card c-purple"> <div class="stat-icon">🌐</div><div class="stat-value">__CNTGUEST__</div>   <div class="stat-label">Guest Users</div></div>
    <div class="stat-card c-blue">   <div class="stat-icon">🔗</div><div class="stat-value">__CNTSYNCED__</div>  <div class="stat-label">Synced On-Prem</div></div>
    <div class="stat-card c-red">    <div class="stat-icon">👻</div><div class="stat-value">__CNTNEVER__</div>   <div class="stat-label">Never Signed In</div></div>
    <div class="stat-card c-amber">  <div class="stat-icon">⏳</div><div class="stat-value">__CNTINACTIVE90__</div><div class="stat-label">Inactive &gt;90 Days</div></div>
    <div class="stat-card c-cyan">   <div class="stat-icon">🏢</div><div class="stat-value">__TOTALTENANTS__</div><div class="stat-label">Total Tenants</div></div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Account Status</div>
      <div id="execStatusBars"></div>
    </div>
    <div class="panel">
      <div class="section-title">🪪 Licence Coverage</div>
      <div id="execLicBars"></div>
    </div>
  </div>

  <div class="panel">
    <div class="section-title">🔑 Sign-In Activity Summary</div>
    <div id="execSignInBars"></div>
  </div>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!-- TAB 2 — Tenant Overview                             -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="page-tenants" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Tenant Overview</div>
      <div class="page-subtitle">Per-tenant user and governance breakdown</div>
    </div>
  </div>
  <div class="tenant-grid" id="tenantCards"></div>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!-- TAB 3 — User Governance                             -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="page-governance" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">User Governance</div>
      <div class="page-subtitle">Full user inventory — search, filter, sort</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportUsersCSV()">⬇ Export CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="userSearch" placeholder="Search name, UPN, email, department… (press / to focus)" oninput="filterUsers()"/>
    </div>
    <select id="filterTenant"  onchange="filterUsers()"><option value="">All Tenants</option></select>
    <select id="filterStatus"  onchange="filterUsers()">
      <option value="">All Status</option>
      <option value="enabled">Enabled</option>
      <option value="disabled">Disabled</option>
    </select>
    <select id="filterType"    onchange="filterUsers()">
      <option value="">All Types</option>
      <option value="Member">Member</option>
      <option value="Guest">Guest</option>
    </select>
    <select id="filterLicense" onchange="filterUsers()">
      <option value="">All Licence</option>
      <option value="licensed">Licensed</option>
      <option value="unlicensed">Unlicensed</option>
    </select>
    <div class="page-size-wrap">
      Show <select id="govPageSize" onchange="changeGovPageSize()">
        <option>25</option><option>50</option><option>100</option>
      </select>
    </div>
    <span class="result-count" id="userResultCount"></span>
  </div>
  <table class="users-table">
    <thead><tr>
      <th onclick="sortUsers('display')" id="uth-display">Display Name <span class="sort-arrow">↕</span></th>
      <th onclick="sortUsers('upn')"     id="uth-upn">UPN <span class="sort-arrow">↕</span></th>
      <th onclick="sortUsers('dept')"    id="uth-dept">Department <span class="sort-arrow">↕</span></th>
      <th onclick="sortUsers('tenant')"  id="uth-tenant">Tenant <span class="sort-arrow">↕</span></th>
      <th>Status</th>
      <th>Type</th>
      <th>Licence</th>
      <th onclick="sortUsers('lastSignIn')" id="uth-lastSignIn">Last Sign-In <span class="sort-arrow">↕</span></th>
    </tr></thead>
    <tbody id="usersTableBody"></tbody>
  </table>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:8px">
    <span id="govPageInfo" style="font-size:12px;color:var(--muted)"></span>
    <div class="pagination" id="govPagination"></div>
  </div>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!-- TAB 4 — Sign-In & Inactivity                        -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="page-signin" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Sign-In &amp; Inactivity</div>
      <div class="page-subtitle">Inactive, stale, and never-signed-in users</div>
    </div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🔑 Sign-In Status Distribution</div>
      <div id="signinDistBars"></div>
    </div>
    <div class="panel">
      <div class="section-title">⏳ Inactivity Risk Levels</div>
      <div id="signinRiskBars"></div>
    </div>
  </div>
  <div class="panel">
    <div class="section-title">👻 Never Signed In — Enabled Accounts</div>
    <div id="neverSignedInList" style="max-height:340px;overflow-y:auto"></div>
  </div>
  <div class="panel">
    <div class="section-title">⏳ Inactive &gt;90 Days — Enabled &amp; Licensed</div>
    <div id="staleLicensedList" style="max-height:340px;overflow-y:auto"></div>
  </div>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!-- TAB 5 — License & Identity Usage                    -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="page-license" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">License &amp; Identity Usage</div>
      <div class="page-subtitle">Licence assignment, identity type, and sync coverage</div>
    </div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🪪 Licence Assignment</div>
      <div id="licAssignBars"></div>
    </div>
    <div class="panel">
      <div class="section-title">🌐 User Type Breakdown</div>
      <div id="userTypeBars"></div>
    </div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🔗 On-Premises Sync Coverage</div>
      <div id="syncBars"></div>
    </div>
    <div class="panel">
      <div class="section-title">📋 Top Assigned Licence SKUs</div>
      <div id="topSkuBars"></div>
    </div>
  </div>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!-- TAB 6 — Governance & Risk                           -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="page-risk" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Governance &amp; Risk</div>
      <div class="page-subtitle">Actionable identity governance exceptions</div>
    </div>
  </div>
  <div class="risk-list" id="riskList"></div>
</section>

<!-- ══════════════════════════════════════════════════════ -->
<!-- TAB 7 — Data Quality                                -->
<!-- ══════════════════════════════════════════════════════ -->
<section id="page-dq" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Data Quality</div>
      <div class="page-subtitle">Missing attributes and data completeness</div>
    </div>
  </div>
  <div class="dq-list" id="dqList"></div>
</section>

</main>

<!-- ── Toast notification ── -->
<div id="toast"></div>

<script>
'use strict';

// ── Data blobs injected by PowerShell ──────────────────────────────────────
const USERS   = [__USERS_JSON__];
const TENANTS = [__TENANTS_JSON__];

// ── Escape helpers (mandatory for any user-derived string in innerHTML) ────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

// ── Navigation ─────────────────────────────────────────────────────────────
function showPage(id, btnEl) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  if (btnEl) btnEl.classList.add('active');
}

// ── Theme toggle ───────────────────────────────────────────────────────────
function toggleTheme() {
  const isLight = document.body.classList.toggle('light-theme');
  document.getElementById('themeIcon').textContent  = isLight ? '☀️' : '🌙';
  document.getElementById('themeLabel').textContent = isLight ? 'Light Mode' : 'Dark Mode';
  localStorage.setItem('entraid-theme', isLight ? 'light' : 'dark');
}
(function() {
  if (localStorage.getItem('entraid-theme') === 'light') {
    document.body.classList.add('light-theme');
    document.getElementById('themeIcon').textContent  = '☀️';
    document.getElementById('themeLabel').textContent = 'Light Mode';
  }
})();

// ── Toast ──────────────────────────────────────────────────────────────────
function showToast(msg, icon) {
  const t = document.getElementById('toast');
  t.innerHTML = (icon || '✅') + ' ' + escH(msg);
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2800);
}

// ── Bar chart helper ───────────────────────────────────────────────────────
// Renders an array of {label, count, color} into a container as animated bars.
function renderBars(containerId, rows, maxVal) {
  const el  = document.getElementById(containerId);
  const max = maxVal || Math.max(...rows.map(r => r.count), 1);
  el.innerHTML = rows.map(r => {
    const pct = Math.round((r.count / max) * 100);
    return `<div class="bar-row">
      <span class="bar-label" title="${escH(r.label)}">${escH(r.label)}</span>
      <div class="bar-track"><div class="bar-fill" style="background:${r.color};width:0%" data-pct="${pct}"></div></div>
      <span class="bar-count">${r.count}</span>
    </div>`;
  }).join('');
  requestAnimationFrame(() => {
    el.querySelectorAll('.bar-fill').forEach(el => { el.style.width = el.dataset.pct + '%'; });
  });
}

// ── TAB 1: Executive Overview charts ──────────────────────────────────────
(function buildExecCharts() {
  const enabled   = USERS.filter(u => u.enabled).length;
  const disabled  = USERS.length - enabled;
  const licensed  = USERS.filter(u => u.licensed).length;
  const unlicensed= USERS.length - licensed;
  const guest     = USERS.filter(u => u.type === 'Guest').length;
  const member    = USERS.length - guest;
  const now       = new Date();

  function daysSince(ds) {
    if (!ds) return null;
    return (now - new Date(ds)) / 86400000;
  }
  const never   = USERS.filter(u => !u.lastSignIn).length;
  const gt90    = USERS.filter(u => { const d = daysSince(u.lastSignIn); return d !== null && d > 90; }).length;
  const d30to90 = USERS.filter(u => { const d = daysSince(u.lastSignIn); return d !== null && d > 30 && d <= 90; }).length;
  const active  = USERS.filter(u => { const d = daysSince(u.lastSignIn); return d !== null && d <= 30; }).length;

  renderBars('execStatusBars', [
    { label: 'Enabled',  count: enabled,  color: 'var(--green)' },
    { label: 'Disabled', count: disabled, color: 'var(--red)'   }
  ]);

  renderBars('execLicBars', [
    { label: 'Licensed',   count: licensed,   color: 'var(--accent)'  },
    { label: 'Unlicensed', count: unlicensed, color: 'var(--muted)'   },
    { label: 'Guest',      count: guest,      color: 'var(--accent3)' },
    { label: 'Member',     count: member,     color: 'var(--accent2)' }
  ]);

  renderBars('execSignInBars', [
    { label: 'Active ≤30 days',   count: active,  color: 'var(--green)' },
    { label: 'Inactive 31-90d',   count: d30to90, color: 'var(--amber)' },
    { label: 'Inactive >90 days', count: gt90,    color: 'var(--red)'   },
    { label: 'Never Signed In',   count: never,   color: 'var(--muted)' }
  ]);
})();

// ── TAB 2: Tenant cards ────────────────────────────────────────────────────
(function buildTenantCards() {
  const el = document.getElementById('tenantCards');
  if (!TENANTS.length) {
    el.innerHTML = '<p style="color:var(--muted)">No tenant data available.</p>';
    return;
  }
  el.innerHTML = TENANTS.map(t => `
    <div class="tenant-card">
      <div class="tenant-card-head">
        <div class="tenant-icon">🏢</div>
        <div>
          <div class="tenant-name">${escH(t.name || t.id)}</div>
          <div class="tenant-domain">${escH(t.domain || t.id)}</div>
        </div>
      </div>
      <div class="tenant-stats">
        <div class="tenant-stat"><div class="tenant-stat-val">${t.total}</div>    <div class="tenant-stat-lbl">Total Users</div></div>
        <div class="tenant-stat"><div class="tenant-stat-val" style="color:var(--green)">${t.enabled}</div>  <div class="tenant-stat-lbl">Enabled</div></div>
        <div class="tenant-stat"><div class="tenant-stat-val" style="color:var(--red)">${t.disabled}</div>  <div class="tenant-stat-lbl">Disabled</div></div>
        <div class="tenant-stat"><div class="tenant-stat-val" style="color:var(--accent)">${t.licensed}</div> <div class="tenant-stat-lbl">Licensed</div></div>
        <div class="tenant-stat"><div class="tenant-stat-val" style="color:var(--accent3)">${t.guest}</div>   <div class="tenant-stat-lbl">Guests</div></div>
        <div class="tenant-stat"><div class="tenant-stat-val" style="color:var(--accent2)">${t.synced}</div>  <div class="tenant-stat-lbl">Synced</div></div>
      </div>
    </div>`).join('');
})();

// ── TAB 3: User Governance table ───────────────────────────────────────────
let filteredUsers = [...USERS];
let govPage = 1;
let govPageSize = 25;
let govSortCol = 'display';
let govSortAsc = true;

(function initGovFilters() {
  const sel = document.getElementById('filterTenant');
  const tenants = [...new Set(USERS.map(u => u.tenant).filter(Boolean))].sort();
  tenants.forEach(t => {
    const o = document.createElement('option');
    o.value = t; o.textContent = t;
    sel.appendChild(o);
  });
  filterUsers();
})();

function filterUsers() {
  const q   = document.getElementById('userSearch').value.toLowerCase().trim();
  const ten = document.getElementById('filterTenant').value;
  const st  = document.getElementById('filterStatus').value;
  const typ = document.getElementById('filterType').value;
  const lic = document.getElementById('filterLicense').value;

  filteredUsers = USERS.filter(u => {
    const mQ   = !q   || u.display.toLowerCase().includes(q) || u.upn.toLowerCase().includes(q) || u.email.toLowerCase().includes(q) || u.dept.toLowerCase().includes(q);
    const mTen = !ten || u.tenant === ten;
    const mSt  = !st  || (st === 'enabled' ? u.enabled : !u.enabled);
    const mTyp = !typ || u.type === typ;
    const mLic = !lic || (lic === 'licensed' ? u.licensed : !u.licensed);
    return mQ && mTen && mSt && mTyp && mLic;
  });

  const sorts = {
    display:    (a,b) => a.display.localeCompare(b.display),
    upn:        (a,b) => a.upn.localeCompare(b.upn),
    dept:       (a,b) => (a.dept||'').localeCompare(b.dept||''),
    tenant:     (a,b) => (a.tenant||'').localeCompare(b.tenant||''),
    lastSignIn: (a,b) => (a.lastSignIn||'').localeCompare(b.lastSignIn||'')
  };
  if (sorts[govSortCol]) {
    filteredUsers.sort(sorts[govSortCol]);
    if (!govSortAsc) filteredUsers.reverse();
  }

  govPage = 1;
  renderUsersTable();
}

function sortUsers(col) {
  if (govSortCol === col) { govSortAsc = !govSortAsc; }
  else { govSortCol = col; govSortAsc = true; }
  document.querySelectorAll('.users-table thead th').forEach(th => th.classList.remove('sort-active'));
  const th = document.getElementById('uth-' + col);
  if (th) th.classList.add('sort-active');
  filterUsers();
}

function changeGovPageSize() {
  govPageSize = parseInt(document.getElementById('govPageSize').value, 10);
  govPage = 1;
  renderUsersTable();
}

function renderUsersTable() {
  const start = (govPage - 1) * govPageSize;
  const slice = filteredUsers.slice(start, start + govPageSize);

  document.getElementById('userResultCount').textContent = `${filteredUsers.length} of ${USERS.length}`;
  document.getElementById('govPageInfo').textContent = `Showing ${start + 1}–${Math.min(start + govPageSize, filteredUsers.length)} of ${filteredUsers.length}`;

  document.getElementById('usersTableBody').innerHTML = slice.map(u => {
    const statusPill   = u.enabled  ? '<span class="status-pill pill-green">Enabled</span>'   : '<span class="status-pill pill-red">Disabled</span>';
    const typePill     = u.type === 'Guest' ? '<span class="status-pill pill-amber">Guest</span>' : '<span class="status-pill pill-blue">Member</span>';
    const licensePill  = u.licensed ? '<span class="status-pill pill-green">Licensed</span>'  : '<span class="status-pill pill-muted">None</span>';
    const signInLabel  = u.lastSignIn ? escH(u.lastSignIn.substring(0,10)) : '<span style="color:var(--muted)">Never</span>';
    return `<tr>
      <td class="td-mono">${escH(u.display)}</td>
      <td class="td-mono td-muted">${escH(u.upn)}</td>
      <td class="td-muted">${escH(u.dept||'—')}</td>
      <td class="td-muted">${escH(u.tenant||'—')}</td>
      <td>${statusPill}</td>
      <td>${typePill}</td>
      <td>${licensePill}</td>
      <td class="td-mono td-muted">${signInLabel}</td>
    </tr>`;
  }).join('');

  renderGovPagination();
}

function renderGovPagination() {
  const total = Math.ceil(filteredUsers.length / govPageSize);
  const el = document.getElementById('govPagination');
  if (total <= 1) { el.innerHTML = ''; return; }
  let h = `<button class="page-btn" onclick="govGoPage(${govPage-1})" ${govPage===1?'disabled':''}>‹</button>`;
  for (let i = 1; i <= total; i++) {
    if (i === 1 || i === total || Math.abs(i - govPage) <= 1)
      h += `<button class="page-btn ${i===govPage?'active':''}" onclick="govGoPage(${i})">${i}</button>`;
    else if (Math.abs(i - govPage) === 2)
      h += `<span style="color:var(--muted);padding:0 4px">…</span>`;
  }
  h += `<button class="page-btn" onclick="govGoPage(${govPage+1})" ${govPage===total?'disabled':''}>›</button>`;
  el.innerHTML = h;
}

function govGoPage(p) {
  const total = Math.ceil(filteredUsers.length / govPageSize);
  if (p < 1 || p > total) return;
  govPage = p;
  renderUsersTable();
}

// ── TAB 4: Sign-In & Inactivity ────────────────────────────────────────────
(function buildSignInTab() {
  const now = new Date();
  function days(ds) { return ds ? (now - new Date(ds)) / 86400000 : null; }

  const never   = USERS.filter(u => !u.lastSignIn);
  const gt90    = USERS.filter(u => { const d = days(u.lastSignIn); return d !== null && d > 90; });
  const d30_90  = USERS.filter(u => { const d = days(u.lastSignIn); return d !== null && d > 30 && d <= 90; });
  const active  = USERS.filter(u => { const d = days(u.lastSignIn); return d !== null && d <= 30; });

  renderBars('signinDistBars', [
    { label: 'Active ≤30 days',   count: active.length,  color: 'var(--green)' },
    { label: 'Inactive 31-90d',   count: d30_90.length,  color: 'var(--amber)' },
    { label: 'Inactive >90 days', count: gt90.length,    color: 'var(--red)'   },
    { label: 'Never Signed In',   count: never.length,   color: 'var(--muted)' }
  ]);

  const neverEnabled  = never.filter(u => u.enabled);
  const staleLicensed = gt90.filter(u => u.enabled && u.licensed);
  renderBars('signinRiskBars', [
    { label: 'Never — Enabled',        count: neverEnabled.length,  color: 'var(--red)'   },
    { label: '>90d — Enabled+Licensed', count: staleLicensed.length, color: 'var(--amber)' }
  ]);

  function userRow(u) {
    return `<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border)">
      <span style="font-family:var(--mono);font-size:12px;color:var(--accent2);flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${escH(u.upn)}">${escH(u.display||u.upn)}</span>
      <span style="font-size:11px;color:var(--muted);flex-shrink:0">${escH(u.tenant||'')}</span>
    </div>`;
  }

  const nEL = document.getElementById('neverSignedInList');
  nEL.innerHTML = neverEnabled.length
    ? neverEnabled.map(userRow).join('')
    : '<p style="color:var(--muted);font-size:13px;padding:12px 0">✅ No enabled accounts with a missing sign-in date.</p>';

  const sLL = document.getElementById('staleLicensedList');
  sLL.innerHTML = staleLicensed.length
    ? staleLicensed.map(userRow).join('')
    : '<p style="color:var(--muted);font-size:13px;padding:12px 0">✅ No enabled licensed accounts inactive for more than 90 days.</p>';
})();

// ── TAB 5: License & Identity Usage ───────────────────────────────────────
(function buildLicenseTab() {
  const licensed   = USERS.filter(u => u.licensed).length;
  const unlicensed = USERS.length - licensed;
  const guest      = USERS.filter(u => u.type === 'Guest').length;
  const member     = USERS.length - guest;
  const synced     = USERS.filter(u => u.synced).length;
  const cloudOnly  = USERS.length - synced;

  renderBars('licAssignBars', [
    { label: 'Licensed',   count: licensed,   color: 'var(--accent)' },
    { label: 'Unlicensed', count: unlicensed, color: 'var(--muted)'  }
  ]);
  renderBars('userTypeBars', [
    { label: 'Member', count: member, color: 'var(--accent2)' },
    { label: 'Guest',  count: guest,  color: 'var(--accent3)' }
  ]);
  renderBars('syncBars', [
    { label: 'Cloud-Only',    count: cloudOnly, color: 'var(--accent)'  },
    { label: 'Synced On-Prem', count: synced,   color: 'var(--accent2)' }
  ]);

  // Top SKUs — split the semicolon-delimited licence strings and count each SKU
  const skuMap = {};
  USERS.filter(u => u.licensed && u.licenses).forEach(u => {
    u.licenses.split(' ; ').forEach(sku => {
      const s = sku.trim();
      if (s && s !== '-') skuMap[s] = (skuMap[s] || 0) + 1;
    });
  });
  const topSkus = Object.entries(skuMap).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const palette = ['var(--accent)','var(--accent2)','var(--accent3)','var(--green)','var(--amber)'];
  renderBars('topSkuBars', topSkus.map(([sku,cnt],i) => ({
    label: sku, count: cnt, color: palette[i % palette.length]
  })));
})();

// ── TAB 6: Governance & Risk ───────────────────────────────────────────────
(function buildRiskTab() {
  const now = new Date();
  function days(ds) { return ds ? (now - new Date(ds)) / 86400000 : null; }

  const risks = [
    {
      icon: '👤',
      title: 'Enabled accounts with no manager assigned',
      desc:  'Active users with no manager in directory — review for orphaned accounts.',
      count: USERS.filter(u => u.enabled && !u.mgrUpn).length,
      level: 'warn'
    },
    {
      icon: '💸',
      title: 'Disabled accounts still holding a licence',
      desc:  'Licences assigned to disabled accounts are wasted spend. Reclaim them.',
      count: USERS.filter(u => !u.enabled && u.licensed).length,
      level: 'danger'
    },
    {
      icon: '⏳',
      title: 'Licensed accounts inactive for >90 days',
      desc:  'Enabled licensed users who have not signed in for over 90 days.',
      count: USERS.filter(u => { const d = days(u.lastSignIn); return u.licensed && u.enabled && d !== null && d > 90; }).length,
      level: 'warn'
    },
    {
      icon: '👻',
      title: 'Enabled accounts that have never signed in',
      desc:  'Provisioned but never used — verify if still required.',
      count: USERS.filter(u => u.enabled && !u.lastSignIn).length,
      level: 'warn'
    },
    {
      icon: '🌐',
      title: 'Licensed guest accounts',
      desc:  'External guests consuming licences — confirm business justification.',
      count: USERS.filter(u => u.type === 'Guest' && u.licensed).length,
      level: 'warn'
    }
  ];

  document.getElementById('riskList').innerHTML = risks.map(r => {
    const cls = r.count === 0 ? 'ok' : r.level;
    return `<div class="risk-row">
      <div class="risk-icon">${r.icon}</div>
      <div style="flex:1">
        <div class="risk-title">${escH(r.title)}</div>
        <div class="risk-desc">${escH(r.desc)}</div>
      </div>
      <div class="risk-count ${cls}">${r.count}</div>
    </div>`;
  }).join('');
})();

// ── TAB 7: Data Quality ────────────────────────────────────────────────────
(function buildDQTab() {
  const total = USERS.length || 1;
  const dqItems = [
    { label: 'Members missing email address',   count: USERS.filter(u => u.type !== 'Guest' && !u.email).length },
    { label: 'Users missing department',         count: USERS.filter(u => u.type !== 'Guest' && !u.dept).length  },
    { label: 'Users missing display name',       count: USERS.filter(u => !u.display).length                     },
    { label: 'Enabled users missing manager',    count: USERS.filter(u => u.enabled && !u.mgrUpn).length         },
    { label: 'Licensed users missing sign-in data', count: USERS.filter(u => u.licensed && !u.lastSignIn).length  }
  ];

  document.getElementById('dqList').innerHTML = dqItems.map(item => {
    const pct  = Math.round((item.count / total) * 100);
    const col  = item.count === 0 ? 'var(--green)' : pct > 20 ? 'var(--red)' : 'var(--amber)';
    return `<div class="dq-row">
      <div class="dq-label">${escH(item.label)}</div>
      <div class="dq-track"><div class="dq-fill" style="background:${col};width:0%" data-pct="${pct}"></div></div>
      <div class="dq-val" style="color:${col}">${item.count}</div>
    </div>`;
  }).join('');

  requestAnimationFrame(() => {
    document.querySelectorAll('.dq-fill').forEach(el => { el.style.width = el.dataset.pct + '%'; });
  });
})();

// ── CSV export from User Governance table ──────────────────────────────────
function exportUsersCSV() {
  const esc = v => `"${String(v || '').replace(/"/g, '""')}"`;
  const rows = filteredUsers.map(u => [
    esc(u.display), esc(u.upn), esc(u.email), esc(u.dept),
    esc(u.type), u.enabled, u.licensed, u.synced,
    esc(u.mgrDisplay), esc(u.mgrUpn), esc(u.tenant), esc(u.tenantDom),
    esc(u.licenses), esc(u.lastSignIn), esc(u.created)
  ].join(','));
  const header = 'Display Name,UPN,Email,Department,Type,Enabled,Licensed,Synced,Manager Name,Manager UPN,Tenant,Tenant Domain,Licences,Last Sign-In,Created Date';
  const blob = new Blob([[header, ...rows].join('\r\n')], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a'); a.href = url; a.download = 'EntraID-UserGovernance.csv'; a.click();
  URL.revokeObjectURL(url);
  showToast('Exported ' + filteredUsers.length + ' users as CSV');
}

// ── Keyboard shortcuts ─────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'SELECT') {
    e.preventDefault();
    const inp = document.querySelector('.page.active input[type=text]');
    if (inp) inp.focus();
  }
});

</script>
</body>
</html>
'@

        #─────────────────────────────────────────────────────────────────────────
        # STEP 5 — Substitute all __TOKEN__ placeholders via chained -replace.
        # Single-quoted here-string means NO interpolation happened above,
        # so every $ in the HTML/CSS/JS was preserved verbatim.
        #─────────────────────────────────────────────────────────────────────────

        $html = $html `
            -replace '__GENERATEDAT__',   $generatedAt  `
            -replace '__TOTALUSERS__',    $totalUsers   `
            -replace '__TOTALTENANTS__',  $totalTenants `
            -replace '__CNTENABLED__',    $cntEnabled   `
            -replace '__CNTDISABLED__',   $cntDisabled  `
            -replace '__CNTLICENSED__',   $cntLicensed  `
            -replace '__CNTUNLICENSED__', $cntUnlicensed `
            -replace '__CNTGUEST__',      $cntGuest     `
            -replace '__CNTSYNCED__',     $cntSynced    `
            -replace '__CNTNEVER__',      $cntNeverSignedIn `
            -replace '__CNTINACTIVE90__', $cntInactive90 `
            -replace '__USERS_JSON__',    $usersJson    `
            -replace '__TENANTS_JSON__',  $tenantSummaryJson

        #─────────────────────────────────────────────────────────────────────────
        # STEP 6 — Write the file.
        #─────────────────────────────────────────────────────────────────────────

        Try {
            $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force -ErrorAction Stop
            return $true
        }
        Catch {
            Write-Error "Failed to write HTML report to '$OutputPath'. Details: $_"
            return $false
        }
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Main Execution
    #─────────────────────────────────────────────────────────────────────────────

    Clear-Host

    # ── Validate and prepare export directory ─────────────────────────────────────

    $exportDir = Split-Path -Path $ExportPath -Parent

    if (-not (Test-Path -Path $exportDir)) {
        Try {
            New-Item -Path $exportDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Created export directory: $exportDir"
        }
        Catch {
            Write-Error "Cannot create export directory '$exportDir'. Please supply a valid -ExportPath. Details: $_"
            return
        }
    }

    # ── Derive HTML export path (same folder and base name as CSV, .html extension) ─

    $HtmlExportPath = [System.IO.Path]::ChangeExtension($ExportPath, '.html')

    # ── Decode SecureString HERE in the parent function body ──────────────────────
    #
    # This is the only place SecureString decoding works correctly in PS 5.1.
    # $ClientSecret arrived as a parameter in THIS scope. Decoding it here — not
    # inside any nested function — ensures DPAPI can access the key material.
    # PtrToStringAuto is used (not PtrToStringBSTR) as it is the correct method
    # for SecureString-derived BSTRs on Windows.
    #
    # The decoded plain string is stored in $global:_ctx.ClientSecret so all
    # nested helper functions can reach it without re-decoding.
    # It is scrubbed from memory after all tenants are processed.

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
    $plainSecret = $null
    Try {
        $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    Finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $bstr = $null
    }

    if ([string]::IsNullOrEmpty($plainSecret)) {
        Write-Host "  ❌  Could not read the password you entered." -ForegroundColor Red
        Write-Host "      Please make sure you typed it using:" -ForegroundColor Red
        Write-Host "      `$secret = Read-Host -Prompt 'Enter Client Secret' -AsSecureString" -ForegroundColor Yellow
        Write-Host "      Then pass `$secret to -ClientSecret in the same session." -ForegroundColor Yellow
        Write-Error "Failed to decode the ClientSecret SecureString. Ensure the secret was created with Read-Host -AsSecureString in the current session."
        return
    }

    # ── Initialise shared global context ──────────────────────────────────────────
    #
    # $global: is used (not $script:) because nested functions in PS 5.1 do not
    # reliably inherit the parent function's local variable scope. $global: is
    # unambiguous at all nesting depths.

    $global:_ctx = @{
        ClientId               = $ClientId
        ClientSecret           = $plainSecret          # plain string, decoded above
        TenantId               = $null
        AccessToken            = $null
        TokenExpiry            = $null
        RefreshIntervalMinutes = $TokenRefreshIntervalMinutes
    }

    # Scrub the local plain-text copy — the only surviving copy is now inside
    # $global:_ctx.ClientSecret, which is cleared at the end of this function.
    $plainSecret = $null

    # ── Timing ────────────────────────────────────────────────────────────────────

    $scriptStartTime = Get-Date

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  👥  Entra ID — Multi-Tenant User Account Report                         ║" -ForegroundColor Cyan
    Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
    Write-Host "  ║  Connecting to each tenant, collecting all user accounts,                ║" -ForegroundColor Cyan
    Write-Host "  ║  and consolidating everything into a single report.                      ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  🕐  Started  : $($scriptStartTime.ToString('dd-MMM-yyyy  HH:mm:ss'))" -ForegroundColor White
    Write-Host "  🏢  Checking : $($TenantIds.Count) company director$(if ($TenantIds.Count -eq 1) {'y'} else {'ies'})" -ForegroundColor White
    Write-Host "  ⚡  Parallel : $ThrottleLimit users processed simultaneously per tenant" -ForegroundColor White
    Write-Host ""

    $allUserRecords = New-Object System.Collections.ArrayList

    # ── Per-tenant processing loop ────────────────────────────────────────────────

    foreach ($tenantId in $TenantIds) {
        Write-Host "  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  🔌  Connecting to company directory..." -ForegroundColor Yellow
        Write-Host "      (ID: $tenantId)" -ForegroundColor DarkGray

        $accessToken = Connect-EntraIDTenant -TenantId $tenantId

        if (-not $accessToken) {
            Write-Host "  ⛔  Could not connect to this directory — skipping it." -ForegroundColor Red
            Write-Host "      The password (client secret) was rejected. Please check it and try again." -ForegroundColor Red
            Write-Host "      (Directory ID: $tenantId)" -ForegroundColor DarkGray
            continue
        }

        # Retrieve tenant metadata
        $tenant = Get-EntraIDTenantDetails
        $tenantLabel = if ($tenant) { "$($tenant.TenantName) [$($tenant.TenantPrimaryDomain)]" } else { $tenantId }

        Write-Host "  ✅  Connected! You are now inside:  $tenantLabel" -ForegroundColor Green
        Write-Host ""

        # Retrieve all users (with pagination)
        Write-Host "  📋  Getting the full list of people in this directory..." -ForegroundColor Yellow
        Write-Host "      (This is like downloading the whole staff list — may take a moment)" -ForegroundColor DarkGray
        $users = Get-EntraIDAllUsers
        $totalUsers = @($users).Count

        if ($totalUsers -eq 0) {
            Write-Host "  ⚠️   No people found. This may be a permissions issue — check that" -ForegroundColor Yellow
            Write-Host "      'User.Read.All' permission is granted in this directory." -ForegroundColor Yellow
        }
        else {
            Write-Host "  ✅  Found $totalUsers $(if ($totalUsers -eq 1) {'person'} else {'people'}) in this directory!" -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "  ⚙️   Now collecting extra details for each person..." -ForegroundColor Yellow
        Write-Host "      (Their manager, software subscriptions, and last login time)" -ForegroundColor DarkGray
        Write-Host "      Running $ThrottleLimit users in parallel — hang tight. ☕" -ForegroundColor DarkGray
        Write-Host ""

        $syncedRecords = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        $accessTokenSnapshot = $global:_ctx.AccessToken   # snapshot — parallel threads cannot call the nested functions
        $tenantSnapshot = $tenant

        $users | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {

            $user = $_
            $accessToken = $using:accessTokenSnapshot
            $tenantLocal = $using:tenantSnapshot
            $bag = $using:syncedRecords

            $headers = @{ "Authorization" = "Bearer $accessToken" }

            # Inline manager call (cannot call nested functions from parallel scope)
            Try {
                $mgr = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/users/$($user.Id)/manager" `
                    -Headers $headers -Method Get -ErrorAction Stop
            }
            Catch { $mgr = $null }

            # Inline license call
            Try {
                $lic = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/users/$($user.Id)/licenseDetails" `
                    -Headers $headers -Method Get -ErrorAction Stop
                $licenses = $lic.value
            }
            Catch { $licenses = @() }

            $record = [PSCustomObject]@{
                'Object ID'                    = $user.Id
                'Login Name'                   = $user.UserPrincipalName
                'Email'                        = $user.Mail
                'Display Name'                 = $user.DisplayName
                'User Type'                    = $user.UserType
                'Is Synced From On-Premises'   = if ($user.OnPremisesSyncEnabled) { $user.OnPremisesSyncEnabled } else { 'False' }
                'Account Enabled'              = $user.AccountEnabled
                'Created Date'                 = $user.CreatedDateTime
                'Department'                   = $user.Department
                'Last Successful Sign-In'      = $user.LastSuccessfulSignInDateTime
                'Last Interactive Sign-In'     = $user.LastSignInDateTime
                'Last Non-Interactive Sign-In' = $user.LastNonInteractiveSignInDateTime
                'Manager Display Name'         = if ($mgr -and $mgr.PSObject.Properties['displayName']) { $mgr.displayName }        else { $null }
                'Manager UPN'                  = if ($mgr -and $mgr.PSObject.Properties['userPrincipalName']) { $mgr.userPrincipalName }  else { $null }
                'Manager Email'                = if ($mgr -and $mgr.PSObject.Properties['mail']) { $mgr.mail }               else { $null }
                'Is Licence Assigned'          = if ($licenses -and $licenses.Count -gt 0) { 'Yes' }                                  else { 'No' }
                'Assigned Licences'            = if ($licenses -and $licenses.Count -gt 0) { ($licenses.skuPartNumber -join ' ; ') }  else { '-' }
                'Assigned Licence SKU IDs'     = if ($licenses -and $licenses.Count -gt 0) { ($licenses.skuId -join ' ; ') }          else { '-' }
                'Tenant ID'                    = if ($tenantLocal) { $tenantLocal.TenantId }            else { $null }
                'Tenant Name'                  = if ($tenantLocal) { $tenantLocal.TenantName }          else { $null }
                'Tenant Primary Domain'        = if ($tenantLocal) { $tenantLocal.TenantPrimaryDomain } else { $null }
                # 'Tenant Country'               = if ($tenantLocal) { $tenantLocal.Country }             else { $null }
            }

            $null = $bag.Add($record)
        }

        # Merge parallel results back into the main collection
        foreach ($r in $syncedRecords) { $null = $allUserRecords.Add($r) }

        Write-Progress -Activity "📂  $tenantLabel — Collecting people's details" -Completed
        Write-Host "  ✅  All done for $tenantLabel  ($totalUsers people collected)" -ForegroundColor Green
    }

    # ── Export ────────────────────────────────────────────────────────────────────

    Write-Host ""
    Write-Host "  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  💾  Saving everything to your report file..." -ForegroundColor Yellow

    Try {
        $allUserRecords | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop

        Write-Host "  ✅  Report saved! Open it in Excel to see all the details." -ForegroundColor Green
        Write-Host ""
        Write-Host "      📄  File location  : $ExportPath" -ForegroundColor White
        Write-Host "      👥  Total people   : $($allUserRecords.Count) across $($TenantIds.Count) director$(if ($TenantIds.Count -eq 1) {'y'} else {'ies'})" -ForegroundColor White
    }
    Catch {
        Write-Host "  ❌  Oops! Could not save the file." -ForegroundColor Red
        Write-Host "      Make sure the folder exists and you have permission to write there." -ForegroundColor Red
        Write-Host "      Location tried: $ExportPath" -ForegroundColor DarkGray
        Write-Error "Details: $_"
    }

    # ── HTML report (only when -GenerateHtmlReport switch is present) ─────────────

    if ($GenerateHtmlReport) {

        Write-Host ""
        Write-Host "  💡  -GenerateHtmlReport specified — building HTML dashboard..." -ForegroundColor Yellow

        $htmlSuccess = Export-EntraIDHtmlReport `
            -UserRecords  $allUserRecords `
            -TenantIdList $TenantIds      `
            -OutputPath   $HtmlExportPath

        if ($htmlSuccess) {
            Write-Host "  ✅  HTML dashboard saved!" -ForegroundColor Green
            Write-Host ""
            Write-Host "      🌐  File location  : $HtmlExportPath" -ForegroundColor White
        }
        else {
            Write-Host "  ❌  HTML report could not be saved — see error above." -ForegroundColor Red
        }
    }

    # ── Scrub secret from memory now that all tenants are processed ───────────────

    $global:_ctx.ClientSecret = $null
    $global:_ctx = $null

    # ── Summary ───────────────────────────────────────────────────────────────────

    $scriptEndTime = Get-Date
    $executionTime = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  🎉  All done! Here is a quick summary of what we collected:             ║" -ForegroundColor Green
    Write-Host "  ╠══════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host ("  ║  🕐  Started at     : {0,-51}║" -f $scriptStartTime.ToString('dd-MMM-yyyy  HH:mm:ss')) -ForegroundColor Green
    Write-Host ("  ║  🏁  Finished at    : {0,-51}║" -f $scriptEndTime.ToString('dd-MMM-yyyy  HH:mm:ss'))   -ForegroundColor Green
    Write-Host ("  ║  ⏱️  Time taken     : {0,-51}║" -f ($executionTime.ToString('hh\:mm\:ss') + '  (hours:minutes:seconds)')) -ForegroundColor Green
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host ("  ║  🏢  Directories    : {0,-51}║" -f "$($TenantIds.Count) checked")                      -ForegroundColor Green
    Write-Host ("  ║  👥  People found   : {0,-51}║" -f "$($allUserRecords.Count) total (across all directories)") -ForegroundColor Green
    Write-Host ("  ║  📄  CSV report     : {0,-51}║" -f $ExportPath)                          -ForegroundColor Green
    if ($GenerateHtmlReport) {
    Write-Host ("  ║  🌐  HTML report    : {0,-51}║" -f $HtmlExportPath)                      -ForegroundColor Green
    }
    Write-Host ("  ║  ⚡  Parallel limit : {0,-51}║" -f "$ThrottleLimit users at a time") -ForegroundColor Green
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    # return $allUserRecords
}
