<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 06 May 2024
Modified-On     : 24 July 2026

.SYNOPSIS
    Retrieves all registered devices from Microsoft Entra ID using Microsoft Graph API.

.DESCRIPTION
    This function queries the Microsoft Graph beta endpoint to retrieve all devices
    registered in Microsoft Entra ID.

    It handles pagination automatically via @odata.nextLink, retries on API throttling
    (HTTP 429) using the Retry-After header, and enriches each device record with two
    derived fields not present directly on the Graph response:
        - TrustTypeDisplay: maps the raw trustType value to the same friendly label
          shown in the Azure/Entra portal (e.g. AzureAd → "Microsoft Entra joined")
        - InactiveDays: number of days since approximateLastSignInDateTime, useful for
          identifying stale/inactive device registrations

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
        - DeviceId, Id, DisplayName, AccountEnabled
        - OperatingSystem, OperatingSystemVersion, ProfileType
        - TrustType, TrustTypeDisplay (derived)
        - OnPremisesSyncEnabled, IsCompliant, IsManaged, ManagementType
        - RegistrationDateTime, ApproximateLastSignInDateTime, InactiveDays (derived)

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Device.Read.All
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
        An array of custom objects containing selected device attributes, including
        derived TrustTypeDisplay and InactiveDays fields. Also optionally exports to CSV.

.EXAMPLE
    Get-AllDevices -AccessToken $token

    Retrieves all devices from Microsoft Entra ID.

.EXAMPLE
    Get-AllDevices -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\Devices.csv"

    Retrieves all devices and exports the result to a CSV file.

.EXAMPLE
    (Get-AllDevices -AccessToken $token) | Where-Object { $_.InactiveDays -ge 90 }

    Finds devices with no sign-in activity for 90+ days.

.EXAMPLE
    (Get-AllDevices -AccessToken $token) | Where-Object { $_.IsCompliant -eq $true }

    Filters results down to compliant devices.

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
        Step 1  →  Build the initial /beta/devices request URI with $select
        Step 2  →  Call Microsoft Graph, retrying on HTTP 429 using Retry-After
        Step 3  →  Parse the JSON response
        Step 4  →  Calculate InactiveDays and map TrustType to TrustTypeDisplay
        Step 5  →  Follow @odata.nextLink until pagination is exhausted
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The function uses the /beta Graph API endpoint. Beta endpoints are
            subject to change and are not recommended for production without
            monitoring for breaking changes.
        - Requires a valid bearer token with the specified permissions.
        - InactiveDays is null when approximateLastSignInDateTime is not present
            on the device record (e.g. device has never signed in, or the property
            isn't populated for that device type).
        - TrustTypeDisplay falls back to "Unknown" for any trustType value not in
            the current AzureAd/ServerAd/Workplace mapping (e.g. future Graph
            additions would need the map updated).
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


Function Get-AllDevices
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Define an empty array to hold all devices
    $allDevices = New-Object System.Collections.ArrayList
    $totalDevices = 0

    # Azure Portal-style TrustType mapping
    $trustTypeMap = @{
        "AzureAd"   = "Microsoft Entra joined"
        "ServerAd"  = "Microsoft Entra hybrid joined"
        "Workplace" = "Microsoft Entra registered"
    }

    # Define the initial URI to retrieve all devices with select options
    $uri = "https://graph.microsoft.com/beta/devices?`$top=100&`$select=deviceId,id,displayName,accountEnabled,operatingSystem,operatingSystemVersion,profileType,trustType,onPremisesSyncEnabled,isCompliant,isManaged,managementType,registrationDateTime,approximateLastSignInDateTime"

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
                $devicesData = $partialData.content | ConvertFrom-Json -ErrorAction Stop
            }
            Catch
            {
                Write-Warning "Failed to parse JSON response."
                break
            }
        }

        # Output the total number of devices retrieved so far
        Write-Host ""
        Write-Host "Progress: $($totalDevices += $devicesData.value.Count; $totalDevices) devices retrieved so far" -ForegroundColor Cyan
        
        # Check if there are more pages of data to retrieve
        if ($devicesData.PSObject.Properties['@odata.nextLink']) { $uri = $devicesData.'@odata.nextLink' }

        # Process devices: calculate InactiveDays and map TrustType display
        $devicesData.value | ForEach-Object {

            # Inactive days calculation
            if ($_.approximateLastSignInDateTime)
            {
                $inactiveDays = [math]::Round(
                    (New-TimeSpan -Start $_.approximateLastSignInDateTime -End (Get-Date)).TotalDays
                )
            }
            else
            {
                $inactiveDays = $null
            }

            # TrustType display mapping (Azure Portal style)
            $trustDisplay = $trustTypeMap[$_.trustType]
            if (-not $trustDisplay)
            {
                $trustDisplay = "Unknown"
            }

            $null = $allDevices.Add(
                [PSCustomObject]@{

                    DeviceId                      = $_.deviceId
                    Id                            = $_.id
                    DisplayName                   = $_.displayName
                    AccountEnabled                = $_.accountEnabled
                    OperatingSystem               = $_.operatingSystem
                    OperatingSystemVersion        = $_.operatingSystemVersion
                    ProfileType                   = $_.profileType

                    TrustType                     = $_.trustType
                    TrustTypeDisplay              = $trustDisplay

                    OnPremisesSyncEnabled         = $_.onPremisesSyncEnabled
                    IsCompliant                   = $_.isCompliant
                    IsManaged                     = $_.isManaged
                    ManagementType                = $_.managementType

                    RegistrationDateTime          = $_.registrationDateTime
                    ApproximateLastSignInDateTime = $_.approximateLastSignInDateTime

                    InactiveDays                  = $inactiveDays
                }
            )
        }
        
    } until (-not($devicesData.PSObject.Properties['@odata.nextLink']))

    # CSV EXPORT SUPPORT
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allDevices | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Devices report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # Return the array list containing all devices
    return $allDevices
}
