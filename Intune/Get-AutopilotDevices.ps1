<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 31 July 2026
Modified-On     : 31 July 2026

.SYNOPSIS
    Retrieves Windows Autopilot devices with enrollment status and profile
    assignments, using the Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph beta endpoint to retrieve all Windows
    Autopilot device identities registered in the tenant, expanding each
    device's assigned deployment profile in the same call. Handles
    pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing.

    Captures group tag, enrollment state, deployment profile assignment
    status, and last-contact time - the fields needed to spot zero-touch
    deployment failures (e.g. devices stuck in "pending" assignment, or
    profile assignment failures) before a user shows up to a broken
    out-of-box experience.

    Results can optionally be exported to CSV.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission:
        DeviceManagementServiceConfig.Read.All

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER FailedAssignmentsOnly
    Optional switch. Only include devices where
    deploymentProfileAssignmentStatus indicates a failure state
    (assignedUnkownSyncFailure, assignedError, or similar non-success
    values) - useful for a quick "what's broken" triage view.

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
        An array of custom objects containing Autopilot device identity,
        enrollment, and profile assignment details. Also optionally
        exports to CSV.

.EXAMPLE
    Get-AutopilotDevices -AccessToken $token

    Retrieves all Windows Autopilot devices with their profile assignments.

.EXAMPLE
    Get-AutopilotDevices -AccessToken $token -FailedAssignmentsOnly -ExportFormat CSV -ExportPath "C:\Reports\AutopilotIssues.csv"

    Exports only devices with a failed or problematic profile assignment.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (31-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. A valid Microsoft Graph access token with the following permission:
            DeviceManagementServiceConfig.Read.All (Application or Delegated)
    2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Uses the /beta Graph API endpoint. Beta endpoints are subject to
      change and are not recommended for production without monitoring
      for breaking changes.
    - deploymentProfileAssignmentStatus values are Microsoft-defined
      enums that occasionally gain new members; -FailedAssignmentsOnly
      filters against the known failure values at the time of writing and
      may need updating if Microsoft introduces new status values.
    - This reports Autopilot device *registration* records, not live
      enrollment/OOBE telemetry - lastContactedDateTime is the closest
      proxy for recent activity but is not a full provisioning log.
    - SINGLE-TOKEN, SEQUENTIAL PAGINATION: does not refresh the token
      mid-run; see Get-ManagedDevices.ps1 Known Limitations for the same
      caveat on very large device counts.

.LINK
    Microsoft Graph API - windowsAutopilotDeviceIdentity resource type
    https://learn.microsoft.com/en-us/graph/api/resources/intune-shared-windowsautopilotdeviceidentity

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-AutopilotDevices
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath,

        [switch]$FailedAssignmentsOnly
    )

    $failureStatusValues = @('assignedUnkownSyncFailure', 'assignedError', 'unassignedUnkownSyncFailure', 'unassignedError')

    if (-not $AccessToken)
    {
        Write-Error "AccessToken is required. Exiting function."
        return
    }

    $allDevices = New-Object System.Collections.ArrayList
    $totalDevices = 0

    # $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$top=100&`$expand=deploymentProfile"
    $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$top=100"

    do
    {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
        }

        do
        {
            Try
            {
                $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                $statusCode = $partialData.StatusCode;
            }
            catch
            {
                $statusCode = $_.Exception.Response.StatusCode;
                $ErrorObject = $_

                if($statusCode -eq 429)
                {
                    $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                    Write-host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                    Start-sleep -Seconds $sleepTime
                }
                else
                {
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

        if($partialData)
        {
            $apData = $partialData.content | ConvertFrom-Json
            if (-not $apData)
            {
                Write-Error "No data returned from Microsoft Graph API."
                return
            }
        }

        Write-Host ""
        Write-Host "Progress: $($totalDevices += $apData.value.Count; $totalDevices) Autopilot devices retrieved so far" -ForegroundColor Cyan

        if ($apData.PSObject.Properties['@odata.nextLink']) { $uri = $apData.'@odata.nextLink' }

        $apData.value | ForEach-Object {

            $device = $_
            $profileName = if ($device.deploymentProfile) { $device.deploymentProfile.displayName } else { $null }
            $assignmentStatus = $device.deploymentProfileAssignmentStatus

            if (-not $FailedAssignmentsOnly -or ($assignmentStatus -in $failureStatusValues))
            {
                $null = $allDevices.Add(
                    [PSCustomObject]@{
                        Id                                 = $device.id
                        SerialNumber                       = $device.serialNumber
                        Model                              = $device.model
                        Manufacturer                       = $device.manufacturer
                        GroupTag                           = $device.groupTag
                        EnrollmentState                    = $device.enrollmentState
                        DeploymentProfileName              = $profileName
                        DeploymentProfileAssignmentStatus  = $assignmentStatus
                        DeploymentProfileAssignedDateTime  = $device.deploymentProfileAssignedDateTime
                        LastContactedDateTime              = $device.lastContactedDateTime
                        AzureADDeviceId                    = $device.azureActiveDirectoryDeviceId
                        ManagedDeviceId                    = $device.managedDeviceId
                    }
                )
            }
        }

    } until (-not($apData.PSObject.Properties['@odata.nextLink']))

    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allDevices | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Autopilot devices report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # return $allDevices | Select-Object SerialNumber, Model, GroupTag, EnrollmentState, DeploymentProfileName, DeploymentProfileAssignmentStatus | FT
    return $allDevices
}
