<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Retrieves only high-severity Microsoft Defender alerts for the tenant using Microsoft Graph API.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 /security/alerts_v2 endpoint with a
    server-side $filter of severity eq 'high', so only high-severity alerts are ever
    downloaded from Graph — reducing noise and payload size for SOC triage compared to
    pulling all alerts and filtering afterwards.

    This is a standalone function (it does not call Get-DefenderAlerts internally) and
    implements its own pagination and throttling handling.

    Optional -Status, -StartDate, and -EndDate parameters can be combined with the
    high-severity filter to further narrow results (e.g. only unactioned high-severity
    alerts from the last 24 hours).

    It handles pagination automatically via @odata.nextLink, retries on API throttling
    (HTTP 429) using the Retry-After header, and validates the JSON response before
    processing it further.

    Results can optionally be exported to CSV.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK below,
    then pass its returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        SecurityAlert.Read.All (Application)

.PARAMETER StartDate
    Optional. Only return alerts with createdDateTime on or after this UTC date/time.

.PARAMETER EndDate
    Optional. Only return alerts with createdDateTime on or before this UTC date/time.

.PARAMETER Status
    Optional. Further filters high-severity alerts by triage status.
    Supported values:
        new, inProgress, resolved

.PARAMETER Top
    Page size used per Graph request. Default is 50. Does not limit the total number of alerts
    returned — pagination continues via @odata.nextLink until all matching alerts are retrieved.

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
        An array of custom objects containing high-severity alert attributes. Also
        optionally exports to CSV.

.EXAMPLE
    Get-M365DefenderHighSeverityAlerts -AccessToken $token

    Retrieves all high-severity Defender alerts for the tenant.

.EXAMPLE
    Get-M365DefenderHighSeverityAlerts -AccessToken $token -Status new -StartDate (Get-Date).AddHours(-24)

    Retrieves unactioned high-severity alerts created in the last 24 hours.

.EXAMPLE
    Get-M365DefenderHighSeverityAlerts -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\HighSeverityAlerts.csv"

    Retrieves all high-severity alerts and exports the result to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permission:
                SecurityAlert.Read.All (Application)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses /security/alerts_v2, the successor to the deprecated /security/alerts
            endpoint. Do not point this function at the legacy endpoint.
        - This function intentionally duplicates the request/pagination logic in
            Get-DefenderAlerts.ps1 rather than wrapping it, so the severity=high
            filter is always applied server-side even if Get-DefenderAlerts changes.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer
            token for the entire pagination run and does not refresh it mid-run.

.LINK
    Microsoft Graph API - alert_v2 resource type
    https://learn.microsoft.com/en-us/graph/api/resources/security-alert

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-M365DefenderHighSeverityAlerts
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [datetime]$StartDate,

        [datetime]$EndDate,

        [ValidateSet("new", "inProgress", "resolved")]
        [string]$Status,

        [ValidateRange(1, 999)]
        [int]$Top = 50,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    if ($ExportPath -and ($ExportPath -match '\.\.[\\/]'))
    {
        Write-Error "ExportPath contains path-traversal characters and was rejected. Exiting function."
        return
    }

    # severity eq 'high' is always applied; additional filters are appended if supplied
    $filterClauses = New-Object System.Collections.ArrayList
    $null = $filterClauses.Add("severity eq 'high'")
    if ($StartDate) { $null = $filterClauses.Add("createdDateTime ge $($StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))") }
    if ($EndDate) { $null = $filterClauses.Add("createdDateTime le $($EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))") }
    if ($Status) { $null = $filterClauses.Add("status eq '$Status'") }

    $filterQuery = "&`$filter=" + ($filterClauses -join " and ")

    $allAlerts = New-Object System.Collections.ArrayList
    $totalAlerts = 0

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $uri = "https://graph.microsoft.com/v1.0/security/alerts_v2?`$top=$Top$filterQuery"

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
            $alertData = $partialData.Content | ConvertFrom-Json
        }

        $alertData.value | ForEach-Object {

            $alert = $_
            $null = $allAlerts.Add(
                [PSCustomObject][ordered]@{
                    id                 = $alert.id
                    title              = $alert.title
                    severity           = $alert.severity
                    status             = $alert.status
                    category           = $alert.category
                    classification     = $alert.classification
                    determination      = $alert.determination
                    serviceSource      = $alert.serviceSource
                    detectionSource    = $alert.detectionSource
                    createdDateTime    = $alert.createdDateTime
                    lastUpdateDateTime = $alert.lastUpdateDateTime
                    assignedTo         = $alert.assignedTo
                    incidentId         = $alert.incidentId
                    description        = $alert.description
                }
            )
        }

        $totalAlerts += $alertData.value.Count
        Write-Host "Progress: $totalAlerts high-severity alert(s) retrieved so far" -ForegroundColor Cyan

        if ($alertData.PSObject.Properties['@odata.nextLink']) { $uri = $alertData.'@odata.nextLink' } else { $uri = $null }

    } until (-not $uri)

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allAlerts | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host ""
        Write-Host "High-severity alerts exported successfully -> $ExportPath" -ForegroundColor Green
    }

    return $allAlerts
}
