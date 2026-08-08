<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Retrieves device risk scores and exposure levels from Microsoft Defender for Endpoint.

.DESCRIPTION
    This function queries the Microsoft Defender for Endpoint native API
    (api.securitycenter.microsoft.com) /api/machines endpoint to retrieve each onboarded
    device's current risk score, exposure level, and health status.

    IMPORTANT - SEPARATE TOKEN AUDIENCE:
    This API is NOT part of Microsoft Graph. It requires a Bearer token issued for the
    resource https://api.securitycenter.microsoft.com, which is a different token audience
    than graph.microsoft.com. A Graph token (e.g. one obtained for Get-AllUsers or the other
    Defender/security functions in this toolkit) will NOT work here and will return 401.
    See .LINK below for how to acquire an app-only token against this resource.

    It handles pagination automatically via @odata.nextLink, retries on API throttling
    (HTTP 429) using the Retry-After header, and validates the JSON response before
    processing it further.

    Results can optionally be exported to CSV.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token issued for the resource https://api.securitycenter.microsoft.com.
    Required application permission (in the WindowsDefenderATP API, not Graph):
        Machine.Read.All

.PARAMETER RiskScore
    Optional. Filters devices by risk score band.
    Supported values:
        None, Informational, Low, Medium, High

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
        An array of custom objects containing selected device risk attributes for each
        onboarded device. Also optionally exports to CSV.

.EXAMPLE
    Get-M365DefenderDeviceRisk -AccessToken $defenderToken

    Retrieves risk data for all onboarded devices.

.EXAMPLE
    Get-M365DefenderDeviceRisk -AccessToken $defenderToken -RiskScore High -ExportFormat CSV -ExportPath "C:\Reports\HighRiskDevices.csv"

    Retrieves only devices currently rated High risk and exports the result to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Defender for Endpoint access token (resource:
                https://api.securitycenter.microsoft.com) with the following
                application permission: Machine.Read.All

        2. Devices must be onboarded to Microsoft Defender for Endpoint; risk score and
                exposure level are not populated for devices outside its coverage.

        3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - THIS IS NOT A GRAPH ENDPOINT. Do not reuse a graph.microsoft.com Bearer token
            here — it must be requested against api.securitycenter.microsoft.com.
        - -RiskScore is applied client-side after retrieval; the /api/machines endpoint's
            server-side $filter support for riskScore can vary by tenant licensing tier
            and was not assumed reliable enough to depend on here.
        - riskScore and exposureLevel could not be confirmed as always non-null — Microsoft
            populates these based on active threat/vulnerability signals for the device,
            so a device with no recent findings may legitimately show $null rather than "None".
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer token
            for the entire pagination run and does not refresh it mid-run. In very large
            device estates, a full pull could fail with 401 if it outlives the token's
            lifetime.

.LINK
    Microsoft Defender for Endpoint API - List machines
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-machines

.LINK
    Microsoft Defender for Endpoint API - Get access with application context (token audience)
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/exposed-apis-create-app-webapp

#>


Function Get-M365DefenderDeviceRisk
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [ValidateSet("None", "Informational", "Low", "Medium", "High")]
        [string]$RiskScore,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    if ($ExportPath -and ($ExportPath -match '\.\.[\\/]'))
    {
        Write-Error "ExportPath contains path-traversal characters and was rejected. Exiting function."
        return
    }

    $allDevices = New-Object System.Collections.ArrayList
    $totalDevices = 0

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $uri = "https://api.securitycenter.microsoft.com/api/machines"

    do
    {
        Try
        {
            $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            $statusCode = $partialData.StatusCode
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
                continue
            }
            else
            {
                $ErrorOutput = [PSCustomObject][ordered]@{
                    Response   = $($ErrorObject.Exception.Response)
                    StatusCode = $($ErrorObject.Exception.Response.StatusCode)
                    Message    = $($ErrorObject.Exception.Message)
                }
                $ErrorOutput | Format-List
                return
            }
        }

        if ($partialData)
        {
            $deviceData = $partialData.Content | ConvertFrom-Json
        }

        $deviceData.value | ForEach-Object {

            $device = $_

            if ($RiskScore -and ($device.riskScore -ne $RiskScore)) { return }

            $null = $allDevices.Add(
                [PSCustomObject][ordered]@{
                    id                = $device.id
                    computerDnsName   = $device.computerDnsName
                    osPlatform        = $device.osPlatform
                    osVersion         = $device.osVersion
                    riskScore         = $device.riskScore
                    exposureLevel     = $device.exposureLevel
                    healthStatus      = $device.healthStatus
                    isAadJoined       = $device.isAadJoined
                    aadDeviceId       = $device.aadDeviceId
                    firstSeen         = $device.firstSeen
                    lastSeen          = $device.lastSeen
                    machineTags       = if ($device.machineTags) { $device.machineTags -join "; " } else { $null }
                }
            )
        }

        $totalDevices += $deviceData.value.Count
        Write-Host "Progress: $totalDevices device(s) retrieved so far" -ForegroundColor Cyan

        if ($deviceData.PSObject.Properties['@odata.nextLink']) { $uri = $deviceData.'@odata.nextLink' } else { $uri = $null }

    } until (-not $uri)

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allDevices | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host ""
        Write-Host "Device risk report exported successfully -> $ExportPath" -ForegroundColor Green
    }

    return $allDevices
}
