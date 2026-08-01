<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Lists all Microsoft Teams (teams-associated groups) in the tenant using
    Microsoft Graph API.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 endpoint to retrieve all
    Microsoft 365 Groups that are provisioned as a Microsoft Team
    (resourceProvisioningOptions contains 'Team').

    It handles pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing it further.

    Results can optionally be exported to CSV. Output is the core inventory
    used as the entry point for Teams administration and lifecycle management,
    and can be piped into Get-TeamOwners / Get-TeamMembers.

    SCOPE & SUITABILITY:
    This function is designed for smaller tenants or quick ad-hoc pulls where
    a single Bearer token comfortably outlives the full pagination run. It
    does not implement token refresh mid-run. For large/enterprise-scale
    tenants, see Known Limitations below before relying on this function as-is.

    This function only accepts a direct Bearer token (AccessToken). It does
    not perform authentication itself. If you need to obtain a token via
    app-only (client credentials) authentication, use the companion
    Connect-EntraID.ps1 script referenced under .LINK below, then pass its
    returned token into -AccessToken.

    The following team attributes are collected:
        - id, displayName, description, visibility, mail, createdDateTime

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Group.Read.All

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
        An array of custom objects containing core team attributes for each
        Microsoft Team in the tenant. Also optionally exports to CSV.

.EXAMPLE
    Get-MicrosoftTeams -AccessToken $token

    Retrieves all Microsoft Teams in the tenant.

.EXAMPLE
    Get-MicrosoftTeams -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\Teams.csv"

    Retrieves all teams and exports the result to a CSV file.

.EXAMPLE
    $token = Get-AccessToken
    Get-MicrosoftTeams -AccessToken $token

    Demonstrates usage with a dynamically generated access token.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Aug-2026)  - Initial release 

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permission:
                Group.Read.All (Application or Delegated)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Build the initial /v1.0/groups request URI filtered to
                    resourceProvisioningOptions containing 'Team', with $select/$count
        Step 2  →  Call Microsoft Graph, retrying on HTTP 429 using Retry-After
        Step 3  →  Parse the JSON response into custom team objects
        Step 4  →  Follow @odata.nextLink until pagination is exhausted
        Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permission.
        - Does not distinguish shared-channel-only teams from standard teams;
            this could not be confirmed from the groups endpoint alone.
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
    Microsoft Graph API - List groups (Teams filter)
    https://learn.microsoft.com/en-us/graph/api/group-list

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-MicrosoftTeams
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Define an empty array to hold all teams
    $allTeams = New-Object System.Collections.ArrayList
    $totalTeams = 0

    # Define the initial URI to retrieve all teams-provisioned groups with select options
    $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName,description,visibility,mail,createdDateTime&`$count=true"

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
                # Invoke the Graph API to retrieve teams
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
            $teamsData = $partialData.content | ConvertFrom-Json
        }

        # Output the total number of teams retrieved so far
        Write-Host ""
        Write-Host "Progress: $($totalTeams += $teamsData.value.Count; $totalTeams) teams retrieved so far" -ForegroundColor Cyan

        # Check if there are more pages of data to retrieve
        if ($teamsData.PSObject.Properties['@odata.nextLink']) { $uri = $teamsData.'@odata.nextLink' }

        # Flatten team objects
        $teamsData.value | ForEach-Object {

            $null = $allTeams.Add(
                [PSCustomObject]@{

                    id              = $_.id
                    displayName     = $_.displayName
                    description     = $_.description
                    visibility      = $_.visibility
                    mail            = $_.mail
                    createdDateTime = $_.createdDateTime
                }
            )
        }

    } until (-not($teamsData.PSObject.Properties['@odata.nextLink']))

    # CSV EXPORT SUPPORT (added only)
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allTeams | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Teams report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # Return the array list containing all teams
    # return $allTeams | Select-Object id, displayName, description, visibility, mail, createdDateTime | FT
    return $allTeams
}
