<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 30 July 2026
Modified-On     : 30 July 2026

.SYNOPSIS
    Generates a compliance report showing devices that are compliant or
    non-compliant, using the Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph beta endpoint to retrieve all Intune-
    managed devices and their current complianceState, then produces two
    outputs:
      1. A per-device detail list (device name, OS, compliance state,
         last check-in, owning user).
      2. A summary rollup of device counts by complianceState and by
         operating system, useful for a quick compliance-posture snapshot.

    Handles pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing.

    Results can optionally be exported to CSV. When exporting, the
    per-device detail rows are written to -ExportPath, and a companion
    summary file is written alongside it with a "_Summary" suffix.

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
    File path where the exported per-device CSV output will be saved.
    Required only when ExportFormat is set to CSV. A companion summary
    CSV is written alongside it using the same name with a "_Summary"
    suffix (e.g. "Report.csv" → "Report_Summary.csv").

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Collections.Hashtable
        A hashtable with two keys: 'Devices' (per-device detail array) and
        'Summary' (compliance-state/OS rollup array). Also optionally
        exports both to CSV.

.EXAMPLE
    Get-DeviceComplianceReport -AccessToken $token

    Retrieves per-device compliance detail and a summary rollup, returned
    in-session (not exported).

.EXAMPLE
    Get-DeviceComplianceReport -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\ComplianceReport.csv"

    Exports per-device detail to ComplianceReport.csv and the summary
    rollup to ComplianceReport_Summary.csv.

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
    Step 3  →  Parse the JSON response and flatten per-device compliance detail
    Step 4  →  Follow @odata.nextLink until pagination is exhausted
    Step 5  →  Aggregate device counts by complianceState and operatingSystem
    Step 6  →  Export both detail and summary to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Uses the /beta Graph API endpoint. Beta endpoints are subject to
      change and are not recommended for production without monitoring
      for breaking changes.
    - This function paginates through managedDevices client-side, which
      is fine for smaller/medium tenants but does not scale well: at
      roughly one call per ~100 devices plus throttling overhead, very
      large fleets (tens of thousands of devices) will make many calls.
      For large-scale tenants, Intune's dedicated async Export Jobs API
      (POST https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs
      with reportName: "DeviceCompliance" or "Devices") generates the
      report entirely server-side and returns a single downloadable file,
      cutting a ~100,000-call operation down to a handful of calls. That
      pattern is asynchronous (create job → poll status → download URL)
      and was intentionally left out of this version to keep parity with
      the synchronous style of Get-AllUsers.ps1; consider it as a v2.0
      rewrite if this script needs to run against a large fleet regularly.
    - complianceState reflects the last evaluation cycle, not real-time
      device state.
    - SINGLE-TOKEN, SEQUENTIAL PAGINATION: does not refresh the token
      mid-run; see Get-ManagedDevices.ps1 Known Limitations for the same
      caveat.

.LINK
    Microsoft Graph API - managedDevice resource type
    https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice

.LINK
    Microsoft Graph API - Export Jobs (recommended for large-scale reporting)
    https://learn.microsoft.com/en-us/graph/api/resources/intune-reporting-devicemanagementexportjob

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-DeviceComplianceReport
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Define an empty array to hold all device compliance detail rows
    $allDevices = New-Object System.Collections.ArrayList
    $totalDevices = 0

    # Define the initial URI to retrieve managed devices with select options
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$top=100&`$select=id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,userPrincipalName"

    # Start a do-while loop to handle pagination
    do
    {
        if (-not $accessToken)
        {
            Write-Error "AccessToken is required. Exiting function."
            return
        }

        $headers = @{
            "Authorization" = "Bearer $accessToken"
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
            $deviceData = $partialData.content | ConvertFrom-Json
        }

        Write-Host ""
        Write-Host "Progress: $($totalDevices += $deviceData.value.Count; $totalDevices) devices evaluated so far" -ForegroundColor Cyan

        if ($deviceData.PSObject.Properties['@odata.nextLink']) { $uri = $deviceData.'@odata.nextLink' }

        $deviceData.value | ForEach-Object {

            $null = $allDevices.Add(
                [PSCustomObject]@{
                    DeviceName        = $_.deviceName
                    OperatingSystem   = $_.operatingSystem
                    OSVersion         = $_.osVersion
                    ComplianceState   = $_.complianceState
                    LastSyncDateTime  = $_.lastSyncDateTime
                    UserPrincipalName = $_.userPrincipalName
                }
            )
        }

    } until (-not($deviceData.PSObject.Properties['@odata.nextLink']))

    # Build the summary rollup by ComplianceState and OperatingSystem
    $summary = $allDevices |
        Group-Object -Property OperatingSystem, ComplianceState |
        ForEach-Object {
            [PSCustomObject]@{
                OperatingSystem = $_.Group[0].OperatingSystem
                ComplianceState = $_.Group[0].ComplianceState
                DeviceCount     = $_.Count
            }
        } |
        Sort-Object OperatingSystem, ComplianceState

    # CSV EXPORT SUPPORT
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allDevices | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        $summaryPath = [System.IO.Path]::Combine(
            [System.IO.Path]::GetDirectoryName($ExportPath),
            ([System.IO.Path]::GetFileNameWithoutExtension($ExportPath) + "_Summary" + [System.IO.Path]::GetExtension($ExportPath))
        )
        $summary | Export-Csv -Path $summaryPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Device compliance detail exported successfully → $ExportPath" -ForegroundColor Green
        Write-Host "Compliance summary exported successfully → $summaryPath" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Compliance Summary:" -ForegroundColor Cyan
    $summary | Format-Table -AutoSize

    # $summary
    $allDevices
}
