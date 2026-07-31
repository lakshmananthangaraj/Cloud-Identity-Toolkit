<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 31 July 2026
Modified-On     : 31 July 2026

.SYNOPSIS
    Finds the primary user of each Intune-managed device for assignment
    and support, using the Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph beta endpoint to retrieve all Intune-
    managed devices along with their assigned primary user attributes
    (userId, userPrincipalName, userDisplayName, emailAddress). Handles
    pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing.

    Devices with no primary user assigned (e.g. shared/kiosk devices, or
    devices enrolled without user affinity) are still included in the
    report with blank user fields, so they surface as a distinct,
    reviewable category rather than being silently dropped.

    Optionally cross-verifies the primary user via the dedicated
    /managedDevices/{id}/users navigation property, which is the
    authoritative source Intune uses for primary-user display in the
    admin center (the flat userId/userPrincipalName fields on the device
    object can occasionally lag behind after a manual reassignment).

    Results can optionally be exported to CSV.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission:
        DeviceManagementManagedDevices.Read.All

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER VerifyViaDeviceUsersEndpoint
    Optional switch. For each device, additionally call
    /deviceManagement/managedDevices/{id}/users to cross-check the primary
    user against the authoritative navigation property. Adds one extra
    Graph call per device - slower on large fleets, but catches drift
    between the flat device fields and the true assigned-user record.

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
        An array of custom objects mapping each managed device to its
        primary user attributes. Also optionally exports to CSV.

.EXAMPLE
    Get-IntuneManagedDevicePrimaryUser -AccessToken $token

    Retrieves the primary user of every Intune-managed device.

.EXAMPLE
    Get-IntuneManagedDevicePrimaryUser -AccessToken $token -VerifyViaDeviceUsersEndpoint -ExportFormat CSV -ExportPath "C:\Reports\PrimaryUsers.csv"

    Retrieves and cross-verifies primary users, exporting the result to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (31-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. A valid Microsoft Graph access token with the following permission:
            DeviceManagementManagedDevices.Read.All (Application or Delegated)
    2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Uses the /beta Graph API endpoint. Beta endpoints are subject to
      change and are not recommended for production without monitoring
      for breaking changes.
    - Devices without user affinity (shared devices, kiosks, some
      corporate-owned Android/iOS enrollments) legitimately have no
      primary user - these appear with blank user fields, not as errors.
    - -VerifyViaDeviceUsersEndpoint significantly increases call volume
      (one extra call per device) and will be slow on large fleets;
      consider running the default (fast) mode first and only re-running
      with verification on devices flagged as suspicious.
    - SINGLE-TOKEN, SEQUENTIAL PAGINATION: does not refresh the token
      mid-run; see Get-ManagedDevices.ps1 Known Limitations for the same
      caveat on very large device counts.

.LINK
    Microsoft Graph API - managedDevice: users
    https://learn.microsoft.com/en-us/graph/api/manageddevice-list-users

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-IntuneManagedDevicePrimaryUser
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath,

        [switch]$VerifyViaDeviceUsersEndpoint
    )

    # Helper to call Graph with built-in 429 retry, mirroring the shared pattern
    function Invoke-GraphGetWithRetry
    {
        param ([string]$Uri, [hashtable]$Headers)

        do
        {
            Try
            {
                $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
                $statusCode = $response.StatusCode
            }
            catch
            {
                $statusCode = $_.Exception.Response.StatusCode
                $ErrorObject = $_

                if ($statusCode -eq 429)
                {
                    $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                    Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                    Start-Sleep -Seconds $sleepTime
                }
                else
                {
                    $ErrorOutput = [PSCustomObject][ordered]@{
                        Response   = $($ErrorObject.Exception.Response)
                        StatusCode = $($ErrorObject.Exception.Response.StatusCode)
                        Message    = $($ErrorObject.Exception.Message)
                    }
                    $ErrorOutput | Format-List
                    return $null
                }
            }
        } until ($statusCode -eq 200 -or -not $response)

        return $response
    }

    if (-not $AccessToken)
    {
        Write-Error "AccessToken is required. Exiting function."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $allDevices = New-Object System.Collections.ArrayList
    $totalDevices = 0

    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$top=100&`$select=id,deviceName,operatingSystem,userId,userPrincipalName,userDisplayName,emailAddress"

    do
    {
        $partialData = Invoke-GraphGetWithRetry -Uri $uri -Headers $headers
        if (-not $partialData)
        {
            Write-Error "Failed to retrieve managed devices page. Aborting."
            return
        }

        $deviceData = $partialData.Content | ConvertFrom-Json

        Write-Host ""
        Write-Host "Progress: $($totalDevices += $deviceData.value.Count; $totalDevices) devices evaluated so far" -ForegroundColor Cyan

        if ($deviceData.PSObject.Properties['@odata.nextLink']) { $uri = $deviceData.'@odata.nextLink' }

        $deviceData.value | ForEach-Object {

            $device = $_
            $verifiedUser = $null
            $verificationNote = $null

            if ($VerifyViaDeviceUsersEndpoint)
            {
                try
                {
                    $userUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.id)/users"
                    $userResponse = Invoke-GraphGetWithRetry -Uri $userUri -Headers $headers
                    if ($userResponse)
                    {
                        $userData = $userResponse.Content | ConvertFrom-Json
                        $verifiedUser = ($userData.value | Select-Object -First 1).userPrincipalName
                        $verificationNote = if ($verifiedUser -and $verifiedUser -ne $device.userPrincipalName) { "MISMATCH with device.userPrincipalName" } else { "Matches" }
                    }
                }
                catch
                {
                    Write-Warning "Could not verify primary user for device '$($device.deviceName)': $($_.Exception.Message)"
                    $verificationNote = "Verification failed"
                }
            }

            $null = $allDevices.Add(
                [PSCustomObject]@{
                    DeviceName          = $device.deviceName
                    OperatingSystem     = $device.operatingSystem
                    PrimaryUserId       = $device.userId
                    PrimaryUserUPN      = $device.userPrincipalName
                    PrimaryUserDisplay  = $device.userDisplayName
                    PrimaryUserEmail    = $device.emailAddress
                    HasPrimaryUser      = [bool]$device.userId
                    VerifiedUserUPN     = $verifiedUser
                    VerificationNote    = $verificationNote
                }
            )
        }

    } until (-not ($deviceData.PSObject.Properties['@odata.nextLink']))

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allDevices | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Primary user report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # return $allDevices | Select-Object DeviceName, OperatingSystem, PrimaryUserUPN, HasPrimaryUser | FT
    return $allDevices
}
