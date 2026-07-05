<#

Author          : Lakshmanan Thangaraj
Version         : 2.1
Created-On      : 09 April 2024
Modified-On     : 05 July 2026

.SYNOPSIS
    Retrieves user data and MFA registration details from Entra ID using
    Microsoft Graph API and exports the report to a CSV file.

.DESCRIPTION
    This script connects to Entra ID (Azure AD) using app-only authentication
    via the Microsoft Graph API beta endpoint. It retrieves all users along
    with their sign-in activity, manager details, and MFA authentication
    method registrations.

    The following user attributes are collected:
        - Login name (UPN), email address, display name
        - User type, account enabled status, on-premises sync status
        - Account creation date and department
        - Last sign-in, last non-interactive sign-in, last successful sign-in
        - Manager display name, UPN, and email

    The following MFA method details are collected per user:
        - Phone authentication (number, type, SMS sign-in state)
        - Email authentication
        - Microsoft Authenticator (display name, device tag, app version)
        - Windows Hello for Business (display name, created date, key strength)
        - FIDO2 security key (display name, created date, model)
        - Temporary Access Pass / TAP (usable, start time, lifetime, one-time)
        - Passwordless phone sign-in
        - Software OATH token

    The final report is exported as a CSV file to C:\Temp\EntraID-Users-MFAReport.CSV.

.PARAMETER ClientId
    The Application (client) ID of the Azure AD app registration used for
    authentication.

.PARAMETER ClientSecret
    The client secret associated with the Azure AD app registration, supplied
    as a SecureString. Example:

        $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
        .\Get-EntraID-MFARegistrationReport.ps1 -ClientId $id -ClientSecret $secret -TenantId $tid

.PARAMETER TenantId
    The Directory (tenant) ID of the Entra ID tenant to query.

.PARAMETER OutputPath
    The full file path where the CSV report will be saved.
    Default: C:\Temp\EntraID-Users-MFAReport.CSV

.PARAMETER ShowHelp
    Displays a friendly, plain-language usage guide (parameters, examples,
    prerequisites) and exits immediately. No authentication is attempted and
    no other parameters are required when this switch is used.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        A CSV file exported to the path defined in $outputPath containing
        one row per user with all collected user and MFA details.

.EXAMPLE
    .\Get-EntraID-MFARegistrationReport.ps1 -ShowHelp

    Displays the friendly usage guide and exits without connecting to anything.

.EXAMPLE
    $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    .\Get-EntraID-MFARegistrationReport.ps1 -ClientId "8ad5d2f5-xxxx" -ClientSecret $secret -TenantId "f4310b4f-xxxx"

    Runs the script using the credentials defined in the Parameters section and exports the MFA report to the default output path.

.EXAMPLE
    $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
    .\Get-EntraID-MFARegistrationReport.ps1 -ClientId "8ad5d2f5-xxxx" -ClientSecret $secret -TenantId "f4310b4f-xxxx" -OutputPath "D:\Reports\MFAReport.CSV"

    With custom output path

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (09-Apr-2024)  - Initial release
        2.0 (12-Jun-2026)  - Added signInActivity flattening in Get-AllUsers
                           - Fixed inner loop until condition (= vs -eq bug)
                           - Fixed $skip variable scoping and reset logic
                           - Normalized Get-ManagerDetails response to
                             handle orgContact type and missing managers
                           - Switched Manager/MFA lookups to use user ID
                             instead of UPN for reliability
                           - Added modern console UI with inline progress bar
                           - Added stale session variable cleanup at startup
                           - Moved RequestAccessToken, ShouldRenewToken and
                             RenewTokenIfNeeded to script scope so token
                             renewal survives outside Connect-EntraID
                           - Stored TenantId, ClientId and ClientSecret as
                             globals so RequestAccessToken can reference them
                             after Connect-EntraID returns
                           - Added RenewTokenIfNeeded call in Get-AllUsers
                             pagination loop to cover Step 2 token expiry
        2.1 (05-Jul-2026)  - Converted ClientSecret parameter from [string] to
                             [SecureString] to satisfy PSAvoidUsingPlainText-
                             ForPassword / PSAvoidUsingConvertToSecureString-
                             WithPlainText analyzer rules. Plaintext is
                             marshaled only transiently inside
                             RequestAccessToken via PtrToStringAuto and
                             scrubbed immediately afterward with ZeroFreeBSTR.
                           - Added -ShowHelp switch: prints a friendly,
                             plain-language usage guide and exits before any
                             mandatory-parameter prompting or auth attempt.
                             No other logic, template, or console output was
                             changed in this version.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Azure AD App Registration with admin-consented API permissions:
               User.Read.All                     (Application)
               AuditLog.Read.All                 (Application)
               Directory.Read.All                (Application)
               UserAuthenticationMethod.Read.All (Application)

        2. Entra ID tenant must have Azure AD Premium P1 or P2 license.
           The signInActivity property is license-gated and returns HTTP 403
           on tenants without a qualifying license.

        3. PowerShell 5.1 or later.

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
            Supports configurable token refresh interval. Accepts the client
            secret as a SecureString and never persists plaintext.

        Get-AllUsers
            Retrieves all users from Entra ID with pagination support ($top=100).
            Flattens the nested signInActivity object into top-level properties
            for safe downstream access. Optionally exports results to CSV.
            Handles Graph API throttling (HTTP 429) with automatic retry.

        Get-ManagerDetails
            Retrieves the manager of a given user by user ID.
            Normalizes the response into a consistent PSCustomObject regardless
            of whether the manager is a user or an org contact type.
            Returns null-safe object when no manager exists (HTTP 404).

        Get-MFAAuthenticationMethods
            Retrieves all registered MFA authentication methods for a given user.
            Processes each method type via switch and maps properties into a
            flat PSCustomObject with 22 fields covering all supported MFA types.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  →  If -ShowHelp was supplied, print the friendly guide and exit
        Step 1  →  Authenticate to Entra ID and obtain access token
        Step 2  →  Retrieve all users with pagination (100 users per page)
        Step 3  →  For each user:
                       - Fetch manager details
                       - Fetch MFA authentication methods
                       - Build report object
        Step 4  →  Export full report to CSV

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The script uses the /beta Graph API endpoint. Beta endpoints are
          subject to change and are not recommended for production without
          monitoring for breaking changes.
        - The client secret is still marshaled to plaintext in memory for the
          brief moment required to build the OAuth token request body. This is
          inherent to the client-credentials grant type, not a script-level
          shortcut.

.LINK
    Microsoft Graph API - List Users
    https://learn.microsoft.com/en-us/graph/api/user-list

.LINK
    Microsoft Graph API - Authentication Methods
    https://learn.microsoft.com/en-us/graph/api/authentication-list-methods

.LINK
    Microsoft Graph API - signInActivity
    https://learn.microsoft.com/en-us/graph/api/resources/signinactivity

#>

param (
    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$ClientId,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [System.Security.SecureString]$ClientSecret,

    [Parameter(Mandatory = $true, ParameterSetName = "Run")]
    [string]$TenantId,

    [Parameter(ParameterSetName = "Run")]
    [string]$OutputPath = "C:\Temp\EntraID-Users-MFAReport.CSV",

    [Parameter(ParameterSetName = "Help")]
    [switch]$ShowHelp
)

#--------------------------------------------------------------------------------------------------- [ Friendly Help ]

Function Show-FriendlyHelp
{
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║          Entra ID — MFA Registration Report Generator        ║" -ForegroundColor Cyan
    Write-Host "  ║                   Version 2.1  |  Help                       ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this script does:" -ForegroundColor Yellow
    Write-Host "    Connects to Entra ID via Microsoft Graph (app-only auth) and pulls"
    Write-Host "    every user's profile, manager, and MFA method registrations into"
    Write-Host "    one CSV report."
    Write-Host ""
    Write-Host "  Required parameters:" -ForegroundColor Yellow
    Write-Host "    -ClientId      Application (client) ID of your Azure AD app registration"
    Write-Host "    -ClientSecret  The app's client secret, as a SecureString (see example below)"
    Write-Host "    -TenantId      Directory (tenant) ID of the Entra ID tenant to query"
    Write-Host ""
    Write-Host "  Optional parameters:" -ForegroundColor Yellow
    Write-Host "    -OutputPath    Where to save the CSV (default: C:\Temp\EntraID-Users-MFAReport.CSV)"
    Write-Host "    -ShowHelp      Shows this guide and exits, no connection is attempted"
    Write-Host ""
    Write-Host "  Before you run it:" -ForegroundColor Yellow
    Write-Host "    1. Your app registration needs these Graph API Application permissions,"
    Write-Host "       admin-consented: User.Read.All, AuditLog.Read.All, Directory.Read.All,"
    Write-Host "       UserAuthenticationMethod.Read.All"
    Write-Host "    2. Your tenant needs Azure AD Premium P1 or P2 for sign-in activity data."
    Write-Host ""
    Write-Host "  Example:" -ForegroundColor Yellow
    Write-Host '    $secret = Read-Host -Prompt "Client secret" -AsSecureString'
    Write-Host '    .\Get-EntraID-MFARegistrationReport.ps1 -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
    Write-Host ""
    Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
    Write-Host "     Get-Help .\Get-EntraID-MFARegistrationReport.ps1 -Full"
    Write-Host ""
}

if ($ShowHelp)
{
    Show-FriendlyHelp
    return
}

#--------------------------------------------------------------------------------------------------- [ Helper Functions ]

# MOVED OUTSIDE Connect-EntraID ↓
# Uses $global:TenantId, $global:ClientId, $global:ClientSecretSecure
# (stored as globals inside Connect-EntraID before first call)

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


# MOVED OUTSIDE Connect-EntraID ↓
# No changes to logic, only location changed

Function ShouldRenewToken
{
    if (!$global:accessToken -or !$global:tokenExpirationTime)
    {
        return $true
    }
    $timeToExpire = ($global:tokenExpirationTime - (Get-Date)).TotalMinutes
    return ($timeToExpire -lt $global:RefreshIntervalInMinutes)
}


# ALREADY OUTSIDE — no changes needed

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

        # REMOVED ↓ — nested function definitions for RequestAccessToken
        #              and ShouldRenewToken are no longer here
        #              They now live at script scope above

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


#--------------------------------------------------------------------------------------------------- [ Function to get All users from Entra ID ]
Function Get-AllUsers 
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Define an empty array to hold all users
    $allUsers = New-Object System.Collections.ArrayList
    $totalUsers = 0

    # Define the initial URI to retrieve all users with select options
    $uri = "https://graph.microsoft.com/beta/users?`$top=100&`$select=id,userPrincipalName,mail,displayName,userType,accountEnabled,OnPremisesSyncEnabled,createdDateTime,department,signInActivity&`$count=true"

    # Start a do-while loop to handle pagination
    do 
    {
        # Refresh access token if needed
        RenewTokenIfNeeded

        # re-sync local var after potential refresh
        $accessToken = $global:accessToken

        # Check if access token is obtained successfully
        if (-not $accessToken) 
        {
            # If access token is not obtained, write an error and exit the function
            Write-Error "AccessToken is required. Exiting function."
            return
        }

        # Define the request headers with the access token
        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "ConsistencyLevel" = "eventual"
        }

        # Reset per-iteration control variables
        $skip = $false
        $partialData = $null
        $userData = $null

        # Start a nested do-while loop to handle Graph API throttling and errors
        do 
        { 
            Try 
            {
                # Invoke the Graph API to retrieve users
                $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                $statusCode = $partialData.StatusCode;
            }
            catch 
            {
                # If an exception occurs, handle different types of errors
                $statusCode = $_.Exception.Response.StatusCode; 
                $ErrorObject = $_

                # Check if the error is due to throttling (status code 429)
                if($statusCode -eq 429) 
                {
                    $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                    Write-host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                    Start-sleep -Seconds $sleepTime                    
                }
                else 
                {
                    # If it's not throttling, format and display the error message
                    $ErrorOutput = [PSCustomObject][ordered]@{
                        # Response    = $($ErrorObject.Exception.Response.ResponseUri.OriginalString)
                        Response    = $($ErrorObject.Exception.Response)
                        StatusCode  = $($ErrorObject.Exception.Response.StatusCode)
                        Message     = $($ErrorObject.Exception.Message)
                    }; 
                    $ErrorOutput | Format-List
                    $Skip = $true; 
                }
            }
        } until(($statusCode -eq 200) -or ([boolean]$skip -eq $true))

        # If partial data is retrieved successfully
        if($partialData) 
        {
            $usersData = $partialData.content | ConvertFrom-Json
        }

        # Output the total number of users retrieved so far
        Write-Host ""
        Write-Host "Progress: $($totalUsers += $usersData.value.Count; $totalUsers) users retrieved so far" -ForegroundColor Cyan
        
        # Check if there are more pages of data to retrieve
        if ($usersData.PSObject.Properties['@odata.nextLink']) { $uri = $usersData.'@odata.nextLink' }

        # Add the retrieved users to the array list
        # $usersData.value | ForEach-Object { $null = $allUsers.Add($_) }

        # Flatten signInActivity safely
        $usersData.value | ForEach-Object {

            $null = $allUsers.Add(
                [PSCustomObject]@{

                    id                       = $_.id
                    userPrincipalName        = $_.userPrincipalName
                    mail                     = $_.mail
                    displayName              = $_.displayName
                    userType                 = $_.userType
                    accountEnabled           = $_.accountEnabled
                    onPremisesSyncEnabled    = $_.onPremisesSyncEnabled
                    createdDateTime          = $_.createdDateTime
                    department               = $_.department
                    lastSignInDateTime               = if($_.PSObject.Properties['signInActivity']) { $_.signInActivity.lastSignInDateTime } else { $null }
                    lastNonInteractiveSignInDateTime = if($_.PSObject.Properties['signInActivity']) { $_.signInActivity.lastNonInteractiveSignInDateTime } else { $null }
                    lastSuccessfulSignInDateTime     = if($_.PSObject.Properties['signInActivity']) { $_.signInActivity.lastSuccessfulSignInDateTime } else { $null }
                }
            )
        }
        
    } until (-not($usersData.PSObject.Properties['@odata.nextLink']))

    # CSV EXPORT SUPPORT (added only)
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allUsers | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Users report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # Return the array list containing all users
    return $allUsers
}


#--------------------------------------------------------------------------------------------------- [ Function to get manager details for a user ]
Function Get-ManagerDetails 
{
    param (
        [string]$AccessToken,
        [string]$UserId
    )

    # Define the Graph API endpoint for manager details
    $managerEndpoint = "https://graph.microsoft.com/beta/users/$UserId/manager"

    # Define the request headers with the access token
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    Try
    {
        # Invoke the Graph API to retrieve manager details
        $managerResponse = Invoke-RestMethod -Uri $managerEndpoint -Headers $headers -Method Get -ErrorAction Stop

        # Normalize to safe object regardless of returned type (user or orgContact)
        $managerResponse = [PSCustomObject]@{
            displayName       = $managerResponse.displayName
            userPrincipalName = $managerResponse.userPrincipalName
            mail              = $managerResponse.mail
        }
    }
    Catch
    {
        $managerResponse = [PSCustomObject]@{
            displayName       = $null
            userPrincipalName = $null
            mail              = $null
        }
    }

    return $managerResponse
}


#--------------------------------------------------------------------------------------------------- [ Function to get MFA authentication methods for a user ]
Function Get-MFAAuthenticationMethods 
{
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

    # Define the endpoint to retrieve MFA authentication methods
    $endpoint = "https://graph.microsoft.com/beta/users/$UserId/authentication/methods"

    # Define the request headers with the access token
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    try 
    {
        # Invoke the Graph API to retrieve MFA authentication methods
        $response = Invoke-RestMethod -Uri $endpoint -Headers $headers -Method Get -ErrorAction Stop

        # Initialize results object
        $Results = [PSCustomObject]@{
            phoneAuthenticationNumber = ""
            phoneAuthenticationType = ""
            smsSignInState = ""
            passwordCreatedDateTime = ""
            emailAddress = ""
            WHFBDisplayName = ""
            WHFBCreatedDateTime = ""
            WHFBKeyStrength = ""
            microsoftAuthenticatorDisplayName = ""
            microsoftAuthenticatorDeviceTag = ""
            microsoftAuthenticatorPhoneAppVersion = ""
            fido2DisplayName = ""
            fido2CreatedDate = ""
            fido2Model       = ""
            TAPAuthenticationIsUsable = ""
            TAPAuthenticationStartDateTime = ""
            TAPAuthenticationLifetime = ""
            TAPAuthenticationIsUsableOnce = ""
            passwordlessDisplayName = ""
            passwordAuthDeviceTag = ""
            passwordAuthPhoneAppVersion = ""
            softwareOath = ""
        }

        # Iterate through each authentication method for the current user
        foreach ($AuthenticationMethod in $response.value) 
        {
            switch -Wildcard ($AuthenticationMethod.'@odata.type') 
            {
                '*phoneAuthenticationMethod' {
                    $Results.phoneAuthenticationNumber = $AuthenticationMethod.phoneNumber
                    $Results.phoneAuthenticationType = $AuthenticationMethod.phoneType
                    $Results.smsSignInState = $AuthenticationMethod.smsSignInState
                }
                '*passwordAuthenticationMethod' {
                    $Results.passwordCreatedDateTime = $AuthenticationMethod.createdDateTime
                }
                '*emailAuthenticationMethod' {
                    $Results.emailAddress = $AuthenticationMethod.emailAddress
                }
                '*windowsHelloForBusinessAuthenticationMethod' {
                    $Results.WHFBDisplayName = $AuthenticationMethod.displayName
                    $Results.WHFBCreatedDateTime = $AuthenticationMethod.createdDateTime
                    $Results.WHFBKeyStrength = $AuthenticationMethod.KeyStrength
                }
                '*microsoftAuthenticatorAuthenticationMethod' {
                    $Results.microsoftAuthenticatorDisplayName = $AuthenticationMethod.displayName
                    $Results.microsoftAuthenticatorDeviceTag = $AuthenticationMethod.deviceTag
                    $Results.microsoftAuthenticatorPhoneAppVersion = $AuthenticationMethod.phoneAppVersion
                }
                '*fido2AuthenticationMethod' {
                    $Results.fido2DisplayName = $AuthenticationMethod.displayName
                    $Results.fido2CreatedDate = $AuthenticationMethod.creationDateTime
                    $Results.fido2Model       = $AuthenticationMethod.model
                }
                '*TAPAuthenticationMethod' {
                    $Results.TAPAuthenticationIsUsable = $AuthenticationMethod.isUsable
                    $Results.TAPAuthenticationStartDateTime = $AuthenticationMethod.startDateTime
                    $Results.TAPAuthenticationLifetime = $AuthenticationMethod.lifetimeInMinutes
                    $Results.TAPAuthenticationIsUsableOnce = $AuthenticationMethod.isUsableOnce
                }
                '*passwordlessAuthenticationMethod' {
                    $Results.passwordlessDisplayName = $AuthenticationMethod.displayName
                    $Results.passwordAuthDeviceTag = $AuthenticationMethod.deviceTag
                    $Results.passwordAuthPhoneAppVersion = $AuthenticationMethod.phoneAppVersion
                }
                '*softwareOathAuthenticationMethod' {
                    $Results.softwareOath = if ($AuthenticationMethod) {"Enabled"} else {"-"}
                }
            }
        }

        # Return the array containing processed authentication methods
        return $Results
    } 
    catch 
    {
        # Write-Warning "Error occurred while fetching MFA authentication methods for user: $UserId"
        # Write-Warning $_.Exception.Message
        return $null
    }
}


#--------------------------------------------------------------------------------------------------- [ Script Execution ]

Clear-Host

# Remove-Item Function:\Get-AllUsers -ErrorAction SilentlyContinue

Remove-Variable -Name partialData, usersData, skip -ErrorAction SilentlyContinue

#Set report save location
$outputPath = $OutputPath

#Check for default save location and create if missing
If ((Test-Path "C:\Temp") -eq $false)
{
   New-Item -Path "C:\" -Name "Temp" -ItemType "Directory" | Out-Null
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║          Entra ID — MFA Registration Report Generator        ║" -ForegroundColor Cyan
Write-Host "  ║                      Version 2.1  |  2026                    ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Start time
$scriptStartTime = Get-Date
Write-Host "  🕐 Started  : $($scriptStartTime.ToString('dd-MMM-yyyy  hh:mm:ss tt'))" -ForegroundColor Gray
Write-Host "  📄 Output   : $outputPath" -ForegroundColor Gray
Write-Host ""

# ── Step 1 : Authentication ───────────────────────────────────────────────────
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
Write-Host "  │   STEP 1 of 3  ›  Authenticating to Entra ID                │" -ForegroundColor DarkCyan
Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  ⏳ Requesting access token..." -ForegroundColor Yellow

# Obtain access token with a refresh interval
$accessToken = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId -RefreshInterval 15

# Validate that access token was obtained successfully
if (-not $accessToken) 
{
    Write-Error "Failed to obtain access token. Please check your credentials."
    return
}

Write-Host "  ✅ Authentication successful" -ForegroundColor Green
Write-Host ""

# ── Step 2 : Retrieve Users ───────────────────────────────────────────────────
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
Write-Host "  │   STEP 2 of 3  ›  Retrieving Users from Entra ID            │" -ForegroundColor DarkCyan
Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan

# Invoke the Get-AllUsers function to retrieve all user details
$users = Get-AllUsers -AccessToken $accessToken

# Check if there are any users
if (-not $users -or $users.Count -eq 0) 
{
    Write-Warning "No users found."
    return
}

# Calculate total number of users
$totalUsers = $users.Count

# Calculate the number of users to process before displaying progress
$usersToProcessBeforeProgress = [Math]::Ceiling($totalUsers * 0.1)

Write-Host ""
Write-Host "  ✅ $totalUsers users retrieved successfully" -ForegroundColor Green
Write-Host ""

# Initialize an empty array to store all user reports
$allUserReports = @()

# Initialize progress counter
$progress = 0
$skipped = 0

# ── Step 3 : MFA Report Generation ───────────────────────────────────────────
Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
Write-Host "  │   STEP 3 of 3  ›  Processing MFA Details                    │" -ForegroundColor DarkCyan
Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  🔍 Processing MFA details for $totalUsers users..." -ForegroundColor Cyan
Write-Host ""

# Iterate through each user and generate report
foreach ($user in $users) 
{
    RenewTokenIfNeeded

    $accessToken = $global:accessToken

    # Get manager details
    $manager = Get-ManagerDetails -AccessToken $accessToken -UserId $user.id

    # FIX - explicitly cast manager result to prevent scope pollution
    if ($manager -isnot [PSCustomObject] -and $manager -isnot [PSObject]) { $manager = $null }
   
    # Get MFA Authentication methods for each user
    $mfaAuthenticationMehtods = Get-MFAAuthenticationMethods -AccessToken $accessToken -UserId $user.id

    # Increment the count of all user reports
    $allUserReport = [PSCustomObject]@{
        'LoginName'                                = $user.userPrincipalName;
        'Email'                                    = $user.mail;                          
        'DisplayName'                              = $user.displayName;                
        'UserType'                                 = $user.userType;
        'IsOn-PremSynced'                          = if ($user.PSObject.Properties['onPremisesSyncEnabled'] -and $user.onPremisesSyncEnabled) {$user.onPremisesSyncEnabled} else {'null'}
        'AccountEnabled'                           = $user.accountEnabled;
        'CreateDateTime'                           = $user.createdDateTime;
        'Department'                               = $user.department;
        'LastSuccessfulSignInDateTime'             = $user.lastSuccessfulSignInDateTime;;
        'LastSignInDate'                           = $user.lastSignInDateTime;
        'LastNonInteractiveSignInDate'             = $user.lastNonInteractiveSignInDateTime;
        'ManagerDisplayName'                       = $manager.displayName;
        'ManagerUserPrincipalName'                 = $manager.userPrincipalName;
        'ManagerMail'                              = $manager.mail;
        'phoneAuthenticationNumber'                = $mfaAuthenticationMehtods.phoneAuthenticationNumber;
        'phoneAuthenticationType'                  = $mfaAuthenticationMehtods.phoneAuthenticationType;
        'smsSignInState'                           = $mfaAuthenticationMehtods.smsSignInState
        'passwordCreatedDateTime'                  = $mfaAuthenticationMehtods.passwordCreatedDateTime
        'emailAddress'                             = $mfaAuthenticationMehtods.emailAddress
        'WHFBDisplayName'                          = $mfaAuthenticationMehtods.WHFBDisplayName
        'WHFBCreatedDateTime'                      = $mfaAuthenticationMehtods.WHFBCreatedDateTime
        'WHFBKeyStrength'                          = $mfaAuthenticationMehtods.WHFBKeyStrength
        'microsoftAuthenticatorDisplayName'        = $mfaAuthenticationMehtods.microsoftAuthenticatorDisplayName
        'microsoftAuthenticatorDeviceTag'          = $mfaAuthenticationMehtods.microsoftAuthenticatorDeviceTag
        'microsoftAuthenticatorPhoneAppVersion'    = $mfaAuthenticationMehtods.microsoftAuthenticatorPhoneAppVersion
        'fido2DisplayName'                         = $mfaAuthenticationMehtods.fido2DisplayName
        'fido2CreatedDate'                         = $mfaAuthenticationMehtods.fido2CreatedDate
        'fido2Model'                               = $mfaAuthenticationMehtods.fido2Model
        'TAPAuthenticationIsUsable'                = $mfaAuthenticationMehtods.TAPAuthenticationIsUsable
        'TAPAuthenticationStartDateTime'           = $mfaAuthenticationMehtods.TAPAuthenticationStartDateTime
        'TAPAuthenticationLifetime'                = $mfaAuthenticationMehtods.TAPAuthenticationLifetime
        'TAPAuthenticationIsUsableOnce'            = $mfaAuthenticationMehtods.TAPAuthenticationIsUsableOnce
        'passwordlessDisplayName'                  = $mfaAuthenticationMehtods.passwordlessDisplayName
        'passwordAuthDeviceTag'                    = $mfaAuthenticationMehtods.passwordAuthDeviceTag
        'passwordAuthPhoneAppVersion'              = $mfaAuthenticationMehtods.passwordAuthPhoneAppVersion
        'softwareOath'                             = $mfaAuthenticationMehtods.softwareOath
    }
    
    # Add the inactive user to the array
    $allUserReports += $allUserReport

    # Increment progress counter
    $progress++
    
    # ── Inline progress bar ───────────────────────────────────────────────────
    $percentComplete = [Math]::Round(($progress / $totalUsers) * 100)
    $filledBars      = [Math]::Floor($percentComplete / 5)   # 20 chars = 100%
    $emptyBars       = 20 - $filledBars
    $bar             = "█" * $filledBars + "░" * $emptyBars

    Write-Host -NoNewline "`r  [$bar] $percentComplete%  |  $progress / $totalUsers users processed   " -ForegroundColor Cyan

}

Write-Host ""
Write-Host ""

# ── Export ────────────────────────────────────────────────────────────────────
Write-Host "  ⏳ Exporting report to CSV..." -ForegroundColor Yellow
$allUserReports | Export-Csv -Path $outputPath -NoTypeInformation
Write-Host "  ✅ Report exported successfully" -ForegroundColor Green
Write-Host ""

# End time
$scriptEndTime = Get-Date
$executionTime = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime

Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║                       EXECUTION SUMMARY                      ║" -ForegroundColor Cyan
Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "  ║  ✅ Total Users Retrieved   : $($totalUsers.ToString().PadRight(30))║" -ForegroundColor Green
Write-Host "  ║  📋 MFA Records Exported    : $($(@($allUserReports).Count).ToString().PadRight(30))║" -ForegroundColor Green
Write-Host "  ║  🕐 Started                 : $($scriptStartTime.ToString('hh:mm:ss tt').PadRight(30))║" -ForegroundColor Gray
Write-Host "  ║  🕑 Ended                   : $($scriptEndTime.ToString('hh:mm:ss tt').PadRight(30))║" -ForegroundColor Gray
Write-Host "  ║  ⏱️ Duration                : $($executionTime.ToString('hh\:mm\:ss').PadRight(30))║" -ForegroundColor Yellow
Write-Host "  ║  📄 Output File             : $('C:\Temp\...MFAReport.CSV'.PadRight(30))║" -ForegroundColor Gray
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""