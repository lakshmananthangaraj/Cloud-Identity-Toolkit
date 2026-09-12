<#

.AUTHOR
    Author       : Lakshmanan Thangaraj
    Version      : 1.1
    Created-On   : 12 September 2026
    Modified-On  : 12 September 2026

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
        [int] $ThrottleLimit = 10
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

    Function Invoke-GraphRequest {
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

            $data = Invoke-GraphRequest -Uri $uri -AdditionalHeaders @{ "ConsistencyLevel" = "eventual" }

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
        return Invoke-GraphRequest -Uri $uri
    }


    Function Get-EntraIDAssignedLicenses {
        param
        (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $UserId
        )

        $uri = "https://graph.microsoft.com/beta/users/$UserId/licenseDetails"
        $data = Invoke-GraphRequest -Uri $uri

        if ($data -and $data.value) {
            return $data.value
        }

        return @()
    }


    Function Get-EntraIDTenantDetails {
        $uri = "https://graph.microsoft.com/beta/organization"
        $data = Invoke-GraphRequest -Uri $uri

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
        $totalUsers = $users.Count

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
    Write-Host ("  ║  ⚡  Parallel limit : {0,-51}║" -f "$ThrottleLimit users at a time") -ForegroundColor Green
    Write-Host "  ║                                                                          ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    # return $allUserRecords
}
