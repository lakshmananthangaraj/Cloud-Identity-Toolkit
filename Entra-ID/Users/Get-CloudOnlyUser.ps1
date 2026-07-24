<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 04 May 2024
Modified-On     : 24 July 2026

.SYNOPSIS
    Retrieves all cloud-only users from Microsoft Entra ID (Azure AD) using Microsoft Graph API.

.DESCRIPTION
    The Get-CloudOnlyUser function retrieves user accounts that are cloud-only (not synchronized
    from on-premises Active Directory) using the Microsoft Graph beta endpoint.

    It filters for users where OnPremisesSyncEnabled is not true and userType is Member, handles
    pagination automatically via @odata.nextLink, retries on API throttling (HTTP 429) using the
    Retry-After header, and safely extracts signInActivity properties — lastSignInDateTime,
    lastNonInteractiveSignInDateTime, and lastSuccessfulSignInDateTime — guarding against
    tenants/licenses where signInActivity is not populated.

    Results can optionally be exported to CSV.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK
    below, then pass its returned token into -AccessToken.

    SCOPE & SUITABILITY:
    Like Get-AllUsers, this function is designed for smaller tenants or quick ad-hoc pulls
    where a single Bearer token comfortably outlives the full pagination run. It does not
    implement token refresh mid-run. For large/enterprise-scale tenants, see Known Limitations
    below before relying on this function as-is.

    The following user attributes are collected:
        - id, userPrincipalName, mail, displayName
        - userType, accountEnabled, onPremisesSyncEnabled, createdDateTime, department
        - lastSignInDateTime, lastNonInteractiveSignInDateTime, lastSuccessfulSignInDateTime

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        User.Read.All
        Directory.Read.All

    To obtain this token via app-only authentication instead of an interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
        An array of custom objects containing selected cloud-only user attributes.
        Also optionally exports to CSV.

.EXAMPLE
    Get-CloudOnlyUser -AccessToken $token

    Retrieves all cloud-only users from Microsoft Entra ID.

.EXAMPLE
    Get-CloudOnlyUser -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\CloudOnlyUsers.csv"

    Retrieves all cloud-only users and exports the result to a CSV file.

.EXAMPLE
    $token = Get-AccessToken
    Get-CloudOnlyUser -AccessToken $token

    Demonstrates usage with a dynamically generated access token.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (24-Jul-2026)  - Initial release
                              function renamed Get-CloudOnlyUser (singular); aligned
                              parameters and pagination/throttling logic with
                              Get-AllUsers (direct AccessToken, ExportFormat,
                              ExportPath) in place of the earlier ClientId/
                              ClientSecret/TenantId + internal Connect-EntraID
                              refresh approach

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                User.Read.All      (Application)
                Directory.Read.All (Application)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Build the initial /beta/users request URI with $filter/$select/$count
        Step 2  →  Call Microsoft Graph, retrying on HTTP 429 using Retry-After
        Step 3  →  Parse the JSON response and flatten signInActivity safely
        Step 4  →  Follow @odata.nextLink until pagination is exhausted
        Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The function uses the /beta Graph API endpoint. Beta endpoints are
            subject to change and are not recommended for production without
            monitoring for breaking changes.
        - Requires a valid bearer token with the specified permissions.
        - signInActivity may require Entra ID licensing (e.g., Azure AD Premium P1/P2)
            and will be null otherwise.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer
            token for the entire pagination run and does not refresh it mid-run. In
            very large tenants, if the full pull takes longer than the token's
            lifetime (typically ~60-90 minutes), the run will fail partway through
            with 401 Unauthorized once the token expires.
        - RECOMMENDED FOR: smaller tenants, scoped/filtered pulls, or quick
            one-off/ad-hoc workarounds.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants. For those,
            implement a proper token-refresh pattern (re-acquire via app-only
            client-credentials auth on a timer or before each page/batch) and
            consider parallelized/batched Graph calls instead of this single-
            threaded sequential loop.

.LINK
    Microsoft Graph API - User resource type
    https://learn.microsoft.com/graph/api/user-list

.LINK
    Microsoft Entra ID documentation
    https://learn.microsoft.com/entra/identity/

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-CloudOnlyUser
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Define an empty array to hold all cloud-only users
    $cloudOnlyUsers = New-Object System.Collections.ArrayList
    $totalCloudOnlyUsers = 0

    # Define the initial URI to retrieve cloud-only users with a filter and select options
    $uri = "https://graph.microsoft.com/beta/users?`$top=100&`$filter=OnPremisesSyncEnabled ne true and userType eq 'Member'&`$select=id,userPrincipalName,mail,displayName,userType,accountEnabled,OnPremisesSyncEnabled,createdDateTime,department,signInActivity&`$count=true"

    # Start a do-while loop to handle pagination
    do 
    {
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

        # Start a nested do-while loop to handle Graph API throttling and errors
        do 
        { 
            Try 
            {
                # Invoke the Graph API to retrieve cloud-only users
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
                        Response    = $($ErrorObject.Exception.Response)
                        StatusCode  = $($ErrorObject.Exception.Response.StatusCode)
                        Message     = $($ErrorObject.Exception.Message)
                    }; 
                    $ErrorOutput | Format-List
                    [boolean]$Skip = $true; 
                }
            }
        } until(($statusCode -eq 200) -or ([boolean]$skip = $true))

        # If partial data is retrieved successfully
        if($partialData) 
        {
            $cloudOnlyUsersData = $partialData.content | ConvertFrom-Json
        }

        # Output the total number of cloud-only users retrieved so far
        Write-Host ""
        Write-Host "Progress: $($totalCloudOnlyUsers += $cloudOnlyUsersData.value.Count; $totalCloudOnlyUsers) cloud-only users retrieved so far" -ForegroundColor Cyan
        
        # Check if there are more pages of data to retrieve
        if ($cloudOnlyUsersData.PSObject.Properties['@odata.nextLink']) { $uri = $cloudOnlyUsersData.'@odata.nextLink' }

        # Flatten signInActivity safely
        $cloudOnlyUsersData.value | ForEach-Object {

            $null = $cloudOnlyUsers.Add(
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
        
    } until (-not($cloudOnlyUsersData.PSObject.Properties['@odata.nextLink']))

    # CSV EXPORT SUPPORT
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $cloudOnlyUsers | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Cloud-only users report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # Return the array list containing all cloud-only users
    return $cloudOnlyUsers | Select-Object Id, displayName, userPrincipalName, userType, createdDateTime, accountEnabled, onPremisesSyncEnabled, lastSuccessfulSignInDateTime, lastSignInDateTime, lastNonInteractiveSignInDateTime | FT
}
