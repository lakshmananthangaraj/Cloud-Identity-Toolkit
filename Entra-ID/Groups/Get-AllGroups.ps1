<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 05 May 2024
Modified-On     : 24 July 2026

.SYNOPSIS
    Retrieves all groups from Microsoft Entra ID using Microsoft Graph API.

.DESCRIPTION
    This function queries the Microsoft Graph beta endpoint to retrieve all groups in the
    tenant, including security groups, Microsoft 365 (Unified) groups, dynamic groups, and
    role-assignable groups.

    It handles pagination automatically via @odata.nextLink, retries on API throttling
    (HTTP 429) using the Retry-After header, and flattens complex/array properties —
    groupTypes and assignedLicenses — into report-friendly formats.

    Results can optionally be exported to CSV.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK
    below, then pass its returned token into -AccessToken.

    SCOPE & SUITABILITY:
    This function is designed for smaller tenants or quick ad-hoc pulls
    where a single Bearer token comfortably outlives the full pagination run. It does not
    implement token refresh mid-run. For large/enterprise-scale tenants, see Known Limitations
    below before relying on this function as-is.

    The following group attributes are collected:
        - Id, DisplayName, CreatedDateTime
        - GroupTypes (Unified, DynamicMembership; absence of both implies a plain security group)
        - IsAssignableToRole, OnPremisesSyncEnabled
        - SecurityEnabled, Mail, MailEnabled
        - MembershipRule (for dynamic groups)
        - AssignedLicenses (flattened to compact JSON)

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Group.Read.All
        Directory.Read.All (recommended)

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
        An array of custom objects containing selected group attributes.
        Also optionally exports to CSV.

.EXAMPLE
    Get-AllGroups -AccessToken $token

    Retrieves all groups from Microsoft Entra ID.

.EXAMPLE
    Get-AllGroups -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\Groups.csv"

    Retrieves all groups and exports the result to a CSV file.

.EXAMPLE
    Get-AllGroups -AccessToken $token | Where-Object { $_.IsAssignableToRole -eq $true }

    Filters results down to role-assignable groups.

.EXAMPLE
    Get-AllGroups -AccessToken $token | Where-Object { $_.MembershipRule }

    Filters results down to dynamic groups.

.EXAMPLE
    Get-AllGroups -AccessToken $token | Where-Object { $_.OnPremisesSyncEnabled -ne $true }

    Filters results down to cloud-only groups.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (24-Jul-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                Group.Read.All     (Application)
                Directory.Read.All (Application, recommended)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Build the initial /beta/groups request URI with $select/$count
        Step 2  →  Call Microsoft Graph, retrying on HTTP 429 using Retry-After
        Step 3  →  Parse the JSON response and flatten groupTypes/assignedLicenses
        Step 4  →  Follow @odata.nextLink until pagination is exhausted
        Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The function uses the /beta Graph API endpoint. Beta endpoints are
            subject to change and are not recommended for production without
            monitoring for breaking changes.
        - Requires a valid bearer token with the specified permissions.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer
            token for the entire pagination run and does not refresh it mid-run. In
            very large tenants, if the full pull takes longer than the token's
            lifetime (typically ~60-90 minutes), the run will fail partway through
            with 401 Unauthorized once the token expires.
        - GroupTypes is an empty array for plain security groups; check both
            GroupTypes and SecurityEnabled/MailEnabled together to fully classify
            a group (Unified = M365 group, DynamicMembership = dynamic, neither =
            security or distribution group depending on Mail/SecurityEnabled).
        - RECOMMENDED FOR: smaller tenants, scoped/filtered pulls, or quick
            one-off/ad-hoc workarounds.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants. For those,
            implement a proper token-refresh pattern (re-acquire via app-only
            client-credentials auth on a timer or before each page/batch) and
            consider parallelized/batched Graph calls instead of this single-
            threaded sequential loop.

.LINK
    Microsoft Graph API - Group resource type
    https://learn.microsoft.com/en-us/graph/api/resources/group

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-AllGroups
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Define an empty array to hold all groups
    $allGroups = New-Object System.Collections.ArrayList
    $totalGroups = 0

    # Define the initial URI to retrieve all groups with select options
    $uri = "https://graph.microsoft.com/beta/groups?`$top=100&`$select=id,displayName,createdDateTime,groupTypes,isAssignableToRole,onPremisesSyncEnabled,securityEnabled,mail,mailEnabled,membershipRule,assignedLicenses&`$count=true"

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
                # Invoke the Graph API to retrieve groups
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

                    if (-not $sleepTime)
                    {
                        $sleepTime = 5
                    }

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
            Try
            {
                $groupsData = $partialData.content | ConvertFrom-Json -ErrorAction Stop
            }
            Catch
            {
                Write-Warning "Failed to parse JSON response."
                break
            }
        }

        # Output the total number of groups retrieved so far
        Write-Host ""
        Write-Host "Progress: $($totalGroups += $groupsData.value.Count; $totalGroups) groups retrieved so far" -ForegroundColor Cyan
        
        # Check if there are more pages of data to retrieve
        if ($groupsData.PSObject.Properties['@odata.nextLink']) { $uri = $groupsData.'@odata.nextLink' }

        # Flatten complex/array properties safely
        $groupsData.value | ForEach-Object {

            $null = $allGroups.Add(
                [PSCustomObject]@{

                    Id                    = $_.id
                    DisplayName           = $_.displayName
                    CreatedDateTime       = $_.createdDateTime
                    GroupTypes            = ($_.groupTypes -join ",")
                    IsAssignableToRole    = $_.isAssignableToRole
                    OnPremisesSyncEnabled = $_.onPremisesSyncEnabled
                    SecurityEnabled       = $_.securityEnabled
                    Mail                  = $_.mail
                    MailEnabled           = $_.mailEnabled
                    MembershipRule        = $_.membershipRule
                    AssignedLicenses      = ($_.assignedLicenses | ConvertTo-Json -Depth 5 -Compress)
                }
            )
        }
        
    } until (-not($groupsData.PSObject.Properties['@odata.nextLink']))

    # CSV EXPORT SUPPORT
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allGroups | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Groups report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # Return the array list containing all groups
    return $allGroups
}
