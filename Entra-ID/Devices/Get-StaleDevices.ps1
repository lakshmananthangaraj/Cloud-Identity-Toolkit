<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 16 April 2024
Modified-On     : 24 July 2026

.SYNOPSIS
    Retrieves stale (inactive) devices from Microsoft Entra ID based on last sign-in activity.

.DESCRIPTION
    This function queries the Microsoft Graph beta endpoint to retrieve devices whose
    approximateLastSignInDateTime is older than a specified inactivity threshold, and
    optionally filters by TrustType (e.g. AzureAD, ServerAD, Workplace).

    It handles pagination automatically via @odata.nextLink and retries on API throttling
    (HTTP 429) using the Retry-After header. When InactivityThreshold is not explicitly
    provided, the function prints a one-time notice that it is defaulting to 60 days.

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

    The following device attributes are collected:
        - deviceId, id, displayName, accountEnabled
        - operatingSystem, operatingSystemVersion, profileType
        - trustType, onPremisesSyncEnabled
        - isCompliant, isManaged, managementType
        - registrationDateTime, approximateLastSignInDateTime

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API. Mandatory.
    Required permissions:
        Device.Read.All
        Directory.Read.All (recommended)

    To obtain this token via app-only authentication instead of an interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER InactivityThreshold
    Number of days of inactivity used to identify stale devices. Devices whose
    approximateLastSignInDateTime is older than (today - this value) are returned.

    Default value: 60 days. If not explicitly supplied, the function prints a one-time
    notice reminding you of the default and how to override it.

.PARAMETER TrustType
    Optional filter to restrict results to a specific device trust type
    (e.g. AzureAD, ServerAD, Workplace).

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
        An array of custom objects containing selected stale device attributes.
        Also optionally exports to CSV.

.EXAMPLE
    Get-StaleDevices -AccessToken $token

    Retrieves devices inactive for more than 60 days (default threshold).

.EXAMPLE
    Get-StaleDevices -AccessToken $token -InactivityThreshold 90

    Retrieves devices inactive for more than 90 days.

.EXAMPLE
    Get-StaleDevices -AccessToken $token -TrustType "AzureAD"

    Retrieves only Azure AD joined stale devices.

.EXAMPLE
    Get-StaleDevices -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\StaleDevices.csv"

    Retrieves stale devices and exports the result to a CSV file.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (24-Jul-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                Device.Read.All    (Application)
                Directory.Read.All (Application, recommended)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Validate AccessToken; notify if InactivityThreshold uses the default
        Step 2  →  Calculate the cutoff date and build the initial /beta/devices
                    request URI with $filter/$select, adding TrustType if supplied
        Step 3  →  Call Microsoft Graph, retrying on HTTP 429 using Retry-After
        Step 4  →  Parse the JSON response and collect device records
        Step 5  →  Follow @odata.nextLink until pagination is exhausted
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The function uses the /beta Graph API endpoint. Beta endpoints are
            subject to change and are not recommended for production without
            monitoring for breaking changes.
        - Devices with no approximateLastSignInDateTime at all are excluded from
            results, since the Graph $filter compares against that field directly.
        - TrustType filtering relies on an exact match against Graph's stored
            trustType values (AzureAd, ServerAd, Workplace); typos or casing
            mismatches will silently return zero results rather than an error.
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
    Microsoft Graph API - Device resource type
    https://learn.microsoft.com/en-us/graph/api/resources/device

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-StaleDevices
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [int]$InactivityThreshold = 60,

        [string]$TrustType = $null,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Validate token upfront before doing anything
    if (-not $AccessToken)
    {
        Write-Error "AccessToken is required. Please provide a valid Bearer token."
        return
    }

    # Check if InactivityThreshold is not specified
    if (-not $PSBoundParameters.ContainsKey('InactivityThreshold')) 
    {
        Write-Host ""
        Write-Host "----------------------------------------------------------------------------------------------------------------------"
        Write-Host ""
        Write-Host "Attention: The threshold for identifying stale devices is currently set to 60 days by default                         " -ForegroundColor Black -BackgroundColor Yellow
        Write-Host "           If you wish to change this threshold, please provide the 'InactivityThreshold' parameter as follows:       " -ForegroundColor Black -BackgroundColor Yellow
        Write-Host "           Get-StaleDevices -InactivityThreshold 60                                                                   " -ForegroundColor Black -BackgroundColor Yellow
        Write-Host ""
        Write-Host "----------------------------------------------------------------------------------------------------------------------"
    }

    # Define an empty array to hold all devices
    $staleDevices = New-Object System.Collections.ArrayList
    $totalDevices = 0

    # Get current date and calculate cutoff date for inactive devices
    $currentDate = Get-Date
    $currentDateModified = $currentDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

    $cutoffDate = $currentDate.AddDays(-$inactivityThreshold)
    $cutoffDateModified = $cutoffDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

    # Build the filter first
    $filter = "approximateLastSignInDateTime le $cutoffDateModified"

    # Add TrustType filter if provided
    if ($TrustType)
    {
        $filter += " and trustType eq '$TrustType'"
    }

    # Fields to retrieve
    $select = "deviceId,id,displayName,accountEnabled,operatingSystem,operatingSystemVersion,profileType,trustType,onPremisesSyncEnabled,isCompliant,isManaged,managementType,registrationDateTime,approximateLastSignInDateTime"

    # Build the Graph URI
    $uri = "https://graph.microsoft.com/beta/devices?`$top=100&`$filter=$filter&`$select=$select"

    # Start a do-while loop to handle pagination
    do 
    {
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
                # Invoke the Graph API to retrieve devices
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
            $devicesData = $partialData.content | ConvertFrom-Json
        }

        # Output the total number of devices retrieved so far
        Write-Host ""
        Write-Host "Progress: $($totalDevices += $devicesData.value.Count; $totalDevices) devices retrieved so far" -ForegroundColor Cyan
        
        # Check if there are more pages of data to retrieve
        if ($devicesData.PSObject.Properties['@odata.nextLink']) { $uri = $devicesData.'@odata.nextLink' }

        # Add the retrieved devices to the array list
        $devicesData.value | ForEach-Object { $null = $staleDevices.Add($_) }
        
    } until (-not($devicesData.PSObject.Properties['@odata.nextLink']))

    # CSV EXPORT SUPPORT
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        ($staleDevices | Select-Object deviceId,id,displayName,accountEnabled,operatingSystem,operatingSystemVersion,profileType,trustType,onPremisesSyncEnabled,isCompliant,isManaged,managementType,registrationDateTime,approximateLastSignInDateTime) |
            Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Stale devices report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # Return the array list containing all stale devices
    return $staleDevices | Select-Object deviceId,id,displayName,accountEnabled,operatingSystem,operatingSystemVersion,profileType,trustType,onPremisesSyncEnabled,isCompliant,isManaged,managementType,registrationDateTime,approximateLastSignInDateTime
}
