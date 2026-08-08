<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Retrieves Microsoft Defender alerts (Endpoint / Office 365 / Identity / Cloud Apps) for the
    tenant using Microsoft Graph API, with optional filtering.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 /security/alerts_v2 endpoint — the current,
    non-deprecated unified alerts API that spans Microsoft Defender for Endpoint, Defender for
    Office 365, Defender for Identity, Defender for Cloud Apps, and Microsoft Sentinel.

    Optional -StartDate/-EndDate, -Status, and -Severity parameters are combined into a single
    server-side $filter clause, so filtering happens on the Graph side rather than after the
    full result set is downloaded.

    It handles pagination automatically via @odata.nextLink, retries on API throttling (HTTP 429)
    using the Retry-After header, and validates the JSON response before processing it further.

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
    Optional. Filters alerts by triage status.
    Supported values:
        new, inProgress, resolved

.PARAMETER Severity
    Optional. Filters alerts by severity.
    Supported values:
        unknown, informational, low, medium, high

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
        An array of custom objects containing selected alert attributes. Also optionally
        exports to CSV.

.EXAMPLE
    Get-M365DefenderAlerts -AccessToken $token

    Retrieves all Defender alerts for the tenant (no filtering).

.EXAMPLE
    Get-M365DefenderAlerts -AccessToken $token -Status new -Severity medium -StartDate (Get-Date).AddDays(-7)

    Retrieves medium-severity, unactioned alerts created in the last 7 days.

.EXAMPLE
    Get-M365DefenderAlerts -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\DefenderAlerts.csv"

    Retrieves all alerts and exports the result to CSV.

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
        - The full evidence collection (files, processes, IPs, URLs, users associated
            with the alert) is intentionally not flattened into this output to keep
            rows CSV-friendly; only summary fields are returned.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer
            token for the entire pagination run and does not refresh it mid-run. In
            very large/high-alert-volume tenants, a full unfiltered pull could fail
            with 401 if it outlives the token's lifetime — narrow the date range or
            add filters for large tenants.

.LINK
    Microsoft Graph API - alert_v2 resource type
    https://learn.microsoft.com/en-us/graph/api/resources/security-alert

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-M365DefenderAlerts
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

        [ValidateSet("unknown", "informational", "low", "medium", "high")]
        [string]$Severity,

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

    # Build server-side $filter clause from whichever optional parameters were supplied
    $filterClauses = New-Object System.Collections.ArrayList
    if ($StartDate) { $null = $filterClauses.Add("createdDateTime ge $($StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))") }
    if ($EndDate) { $null = $filterClauses.Add("createdDateTime le $($EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))") }
    if ($Status) { $null = $filterClauses.Add("status eq '$Status'") }
    if ($Severity) { $null = $filterClauses.Add("severity eq '$Severity'") }

    $filterQuery = if ($filterClauses.Count -gt 0) { "&`$filter=" + ($filterClauses -join " and ") } else { "" }

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
        Write-Host "Progress: $totalAlerts alert(s) retrieved so far" -ForegroundColor Cyan

        if ($alertData.PSObject.Properties['@odata.nextLink']) { $uri = $alertData.'@odata.nextLink' } else { $uri = $null }

    } until (-not $uri)

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allAlerts | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host ""
        Write-Host "Defender alerts exported successfully -> $ExportPath" -ForegroundColor Green
    }

    return $allAlerts
}
