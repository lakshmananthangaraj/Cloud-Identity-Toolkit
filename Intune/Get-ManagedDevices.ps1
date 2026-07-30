<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 30 July 2026
Modified-On     : 30 July 2026

.SYNOPSIS
    Lists all Intune-managed devices with properties (OS, compliance,
    last check-in) using the Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph beta endpoint to retrieve all devices
    managed by Intune. Handles pagination automatically via
    @odata.nextLink, retries on API throttling (HTTP 429) using the
    Retry-After header, and validates the JSON response before processing.

    Results can optionally be exported to CSV.

    This function only accepts a direct Bearer token (AccessToken). It
    does not perform authentication itself. If you need to obtain a token
    via app-only (client credentials) authentication, use the companion
    Connect-EntraID.ps1 script referenced under .LINK below, then pass its
    returned token into -AccessToken.

    The following device attributes are collected:
        - id, deviceName, operatingSystem, osVersion
        - complianceState, managementAgent, ownerType
        - enrolledDateTime, lastSyncDateTime
        - userPrincipalName, model, manufacturer, serialNumber
        - jailBroken, azureADRegistered

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission:
        DeviceManagementManagedDevices.Read.All

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to:
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
        An array of custom objects containing selected device attributes
        for each Intune-managed device. Also optionally exports to CSV.

.EXAMPLE
    Get-ManagedDevices -AccessToken $token

    Retrieves all Intune-managed devices.

.EXAMPLE
    Get-ManagedDevices -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\ManagedDevices.csv"

    Retrieves all managed devices and exports the result to a CSV file.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (30-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. A valid Microsoft Graph access token with the following permission:
            DeviceManagementManagedDevices.Read.All (Application or Delegated)
    2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
    Step 1  →  Build the initial /beta/deviceManagement/managedDevices request URI
    Step 2  →  Call Microsoft Graph, retrying on HTTP 429 using Retry-After
    Step 3  →  Parse the JSON response and flatten device attributes
    Step 4  →  Follow @odata.nextLink until pagination is exhausted
    Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Uses the /beta Graph API endpoint. Beta endpoints are subject to
      change and are not recommended for production without monitoring
      for breaking changes.
    - SINGLE-TOKEN, SEQUENTIAL PAGINATION: uses one static Bearer token for
      the entire pagination run and does not refresh it mid-run. In very
      large tenants (50k+ devices), if the pull takes longer than the
      token's lifetime (typically ~60-90 minutes), the run will fail
      partway through with 401 Unauthorized once the token expires.
    - complianceState reflects the last evaluation cycle, not real-time
      device state.
    - RECOMMENDED FOR: smaller tenants, scoped pulls, or ad-hoc reporting.
      For large/enterprise-scale tenants, consider the async Export Jobs
      API (/beta/deviceManagement/reports/exportJobs, reportName:
      "Devices") which generates the report server-side instead of paging
      through devices client-side - see Get-DeviceComplianceReport.ps1
      Known Limitations for details.

.LINK
    Microsoft Graph API - managedDevice resource type
    https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-ManagedDevices
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

    # Define the initial URI to retrieve all managed devices with select options
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$top=100&`$select=id,deviceName,operatingSystem,osVersion,complianceState,managementAgent,ownerType,enrolledDateTime,lastSyncDateTime,userPrincipalName,model,manufacturer,serialNumber,jailBroken,azureADRegistered"

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
        }

        # Start a nested do-while loop to handle Graph API throttling and errors
        do
        {
            Try
            {
                # Invoke the Graph API to retrieve managed devices
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

        # Flatten device attributes safely
        $devicesData.value | ForEach-Object {

            $null = $allDevices.Add(
                [PSCustomObject]@{

                    id                  = $_.id
                    deviceName          = $_.deviceName
                    operatingSystem     = $_.operatingSystem
                    osVersion           = $_.osVersion
                    complianceState     = $_.complianceState
                    managementAgent     = $_.managementAgent
                    ownerType           = $_.ownerType
                    enrolledDateTime    = $_.enrolledDateTime
                    lastSyncDateTime    = $_.lastSyncDateTime
                    userPrincipalName   = $_.userPrincipalName
                    model               = $_.model
                    manufacturer        = $_.manufacturer
                    serialNumber        = $_.serialNumber
                    jailBroken          = $_.jailBroken
                    azureADRegistered   = $_.azureADRegistered
                }
            )
        }

    } until (-not($devicesData.PSObject.Properties['@odata.nextLink']))

    # CSV EXPORT SUPPORT
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allDevices | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Managed devices report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # Return the array list containing all devices
    return $allDevices | Select-Object deviceName, operatingSystem, osVersion, complianceState, ownerType, lastSyncDateTime, userPrincipalName | FT
}
