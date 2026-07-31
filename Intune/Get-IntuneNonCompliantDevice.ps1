<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 31 July 2026
Modified-On     : 31 July 2026

.SYNOPSIS
    Reports devices failing compliance policies, with the specific
    policy - and optionally setting - that is failing, using the
    Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph beta endpoint to identify all Intune
    managed devices with a complianceState of 'noncompliant', then for
    each one calls the device's deviceCompliancePolicyStates navigation
    property to determine exactly which assigned compliance policy (or
    policies) are failing - not just the aggregate device-level flag.

    With -IncludeSettingDetail, drills one level deeper into each failing
    policy's settingStates to report the specific non-compliant setting
    (e.g. "Require BitLocker" or "Minimum OS version") - the detail that
    turns a compliance report from "this device is broken" into
    "this device is broken because of X."

    Handles pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing. Per-device failures are logged as
    warnings and do not abort the run.

    Results can optionally be exported to CSV. One row is produced per
    (device, failing policy) pair, or per (device, failing policy, failing
    setting) when -IncludeSettingDetail is used.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        DeviceManagementManagedDevices.Read.All
        DeviceManagementConfiguration.Read.All

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER IncludeSettingDetail
    Optional switch. For each failing policy on each non-compliant
    device, additionally call settingStates to report the specific
    setting(s) causing the failure. Adds one extra Graph call per
    (device, failing policy) pair - meaningfully slower on large
    non-compliant populations, but gives full root-cause detail.

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
        An array of custom objects, one row per (device, failing policy)
        pair or per (device, failing policy, failing setting) pair. Also
        optionally exports to CSV.

.EXAMPLE
    Get-IntuneNonCompliantDevice -AccessToken $token

    Reports every non-compliant device with the specific policy (or
    policies) causing the failure.

.EXAMPLE
    Get-IntuneNonCompliantDevice -AccessToken $token -IncludeSettingDetail -ExportFormat CSV -ExportPath "C:\Reports\NonCompliant.csv"

    Reports non-compliant devices down to the specific failing setting,
    exported to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (31-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. A valid Microsoft Graph access token with the following
       permissions:
            DeviceManagementManagedDevices.Read.All (Application or Delegated)
            DeviceManagementConfiguration.Read.All (Application or Delegated)
    2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Uses the /beta Graph API endpoint. Beta endpoints are subject to
      change and are not recommended for production without monitoring
      for breaking changes.
    - This function makes one Graph call per non-compliant device (plus
      one more per failing policy if -IncludeSettingDetail is used), so
      call volume scales with the size of your non-compliant population,
      not your total fleet. On tenants with thousands of non-compliant
      devices this can still be significant; for very large tenants,
      Microsoft's async Export Jobs API report
      "DevicesStatusByPolicyPlatformComplianceReportV3" (or
      "ComplianceSettingNonComplianceReport" for setting-level detail)
      generates the equivalent report server-side and is the recommended
      path at scale - see Get-DeviceComplianceReport.ps1 Known
      Limitations for the same trade-off discussion.
    - Setting-level state names come directly from Graph and are
      technical identifiers (e.g. "PasswordRequired"), not always the
      friendly label shown in the admin center UI.
    - SINGLE-TOKEN, SEQUENTIAL PAGINATION: does not refresh the token
      mid-run; see Get-ManagedDevices.ps1 Known Limitations for the same
      caveat.

.LINK
    Microsoft Graph API - deviceCompliancePolicyState resource type
    https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-devicecompliancepolicystate

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-IntuneNonCompliantDevice
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath,

        [switch]$IncludeSettingDetail
    )

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

    # Step 1: retrieve all non-compliant devices
    $nonCompliantDevices = New-Object System.Collections.ArrayList
    $totalDevices = 0
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$top=100&`$filter=complianceState eq 'noncompliant'&`$select=id,deviceName,operatingSystem,userPrincipalName,lastSyncDateTime"

    do
    {
        $partialData = Invoke-GraphGetWithRetry -Uri $uri -Headers $headers
        if (-not $partialData) { Write-Error "Failed to retrieve non-compliant devices page. Aborting."; return }

        $deviceData = $partialData.Content | ConvertFrom-Json
        Write-Host ""
        Write-Host "Progress: $($totalDevices += $deviceData.value.Count; $totalDevices) non-compliant devices found so far" -ForegroundColor Cyan

        if ($deviceData.PSObject.Properties['@odata.nextLink']) { $uri = $deviceData.'@odata.nextLink' }

        $deviceData.value | ForEach-Object { $null = $nonCompliantDevices.Add($_) }

    } until (-not ($deviceData.PSObject.Properties['@odata.nextLink']))

    Write-Host "Resolving failing policy detail for $($nonCompliantDevices.Count) non-compliant device(s)..." -ForegroundColor Cyan

    # Step 2: for each non-compliant device, resolve which policy/policies are failing
    $report = New-Object System.Collections.ArrayList
    $counter = 0

    foreach ($device in $nonCompliantDevices)
    {
        $counter++
        Write-Progress -Activity "Get-IntuneNonCompliantDevice" -Status "Processing $($device.deviceName)" `
            -PercentComplete (($counter / [Math]::Max($nonCompliantDevices.Count,1)) * 100)

        try
        {
            $policyStateUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.id)/deviceCompliancePolicyStates"
            $policyResponse = Invoke-GraphGetWithRetry -Uri $policyStateUri -Headers $headers
            if (-not $policyResponse)
            {
                Write-Warning "Could not retrieve compliance policy states for device '$($device.deviceName)'"
                continue
            }

            $policyStates = ($policyResponse.Content | ConvertFrom-Json).value |
                Where-Object { $_.state -eq 'nonCompliant' -or $_.state -eq 'error' -or $_.state -eq 'conflict' }

            if (-not $policyStates -or $policyStates.Count -eq 0)
            {
                # Device is flagged non-compliant overall, but per-policy state didn't confirm a specific failure
                $null = $report.Add([PSCustomObject]@{
                    DeviceName          = $device.deviceName
                    OperatingSystem     = $device.operatingSystem
                    UserPrincipalName   = $device.userPrincipalName
                    LastSyncDateTime    = $device.lastSyncDateTime
                    FailingPolicyName   = '(could not be confirmed via policy state)'
                    PolicyState         = 'noncompliant (device-level)'
                    FailingSettingName  = $null
                })
                continue
            }

            foreach ($policyState in $policyStates)
            {
                $failingSettings = @()

                if ($IncludeSettingDetail)
                {
                    try
                    {
                        $settingUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($device.id)/deviceCompliancePolicyStates/$($policyState.id)/settingStates"
                        $settingResponse = Invoke-GraphGetWithRetry -Uri $settingUri -Headers $headers
                        if ($settingResponse)
                        {
                            $failingSettings = ($settingResponse.Content | ConvertFrom-Json).value |
                                Where-Object { $_.state -eq 'nonCompliant' -or $_.state -eq 'error' } |
                                Select-Object -ExpandProperty settingName
                        }
                    }
                    catch
                    {
                        Write-Warning "Could not retrieve setting states for device '$($device.deviceName)' / policy '$($policyState.displayName)': $($_.Exception.Message)"
                    }
                }

                if ($failingSettings.Count -gt 0)
                {
                    foreach ($settingName in $failingSettings)
                    {
                        $null = $report.Add([PSCustomObject]@{
                            DeviceName          = $device.deviceName
                            OperatingSystem     = $device.operatingSystem
                            UserPrincipalName   = $device.userPrincipalName
                            LastSyncDateTime    = $device.lastSyncDateTime
                            FailingPolicyName   = $policyState.displayName
                            PolicyState         = $policyState.state
                            FailingSettingName  = $settingName
                        })
                    }
                }
                else
                {
                    $null = $report.Add([PSCustomObject]@{
                        DeviceName          = $device.deviceName
                        OperatingSystem     = $device.operatingSystem
                        UserPrincipalName   = $device.userPrincipalName
                        LastSyncDateTime    = $device.lastSyncDateTime
                        FailingPolicyName   = $policyState.displayName
                        PolicyState         = $policyState.state
                        FailingSettingName  = if ($IncludeSettingDetail) { '(no specific setting flagged)' } else { $null }
                    })
                }
            }
        }
        catch
        {
            Write-Warning "Skipped device '$($device.deviceName)': $($_.Exception.Message)"
            continue
        }
    }
    Write-Progress -Activity "Get-IntuneNonCompliantDevice" -Completed

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $report | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Non-compliant device report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # return $report | Select-Object DeviceName, FailingPolicyName, PolicyState, FailingSettingName | FT
    return $report
}
