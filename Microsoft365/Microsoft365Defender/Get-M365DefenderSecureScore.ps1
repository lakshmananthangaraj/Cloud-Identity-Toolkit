<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Retrieves the Microsoft 365 Defender Secure Score for the tenant using Microsoft Graph API.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 /security/secureScores endpoint to retrieve
    the tenant's Secure Score snapshot(s) — an aggregate security posture metric.

    Secure Score snapshots are generated roughly once per day, so this function can return either
    the single latest snapshot or a trend of the most recent N snapshots via -NumberOfRecords.

    It handles pagination automatically via @odata.nextLink, retries on API throttling (HTTP 429)
    using the Retry-After header, and validates the JSON response before processing it further.

    The averageComparativeScores array (peer benchmarking data) is flattened into individual
    AvgScore_<Basis> columns for CSV friendliness, and enabledServices is flattened into a
    comma-separated string.

    Results can optionally be exported to CSV.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK below,
    then pass its returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        SecurityEvents.Read.All (Application)

.PARAMETER NumberOfRecords
    Number of most-recent Secure Score snapshots to retrieve. Default is 1 (latest snapshot only).
    Use a higher value to build a trend of Secure Score over time.

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
        An array of custom objects containing Secure Score attributes for each snapshot
        retrieved. Also optionally exports to CSV.

.EXAMPLE
    Get-M365DefenderSecureScore -AccessToken $token

    Retrieves the single latest Secure Score snapshot for the tenant.

.EXAMPLE
    Get-M365DefenderSecureScore -AccessToken $token -NumberOfRecords 30 -ExportFormat CSV -ExportPath "C:\Reports\SecureScoreTrend.csv"

    Retrieves the last 30 Secure Score snapshots and exports the trend to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permission:
                SecurityEvents.Read.All (Application)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Secure Score snapshots are generated on a rolling daily basis by Microsoft;
            requesting -NumberOfRecords for a period longer than the tenant's history
            simply returns however many snapshots actually exist.
        - averageComparativeScores basis names (e.g. "AllTenants", "TotalSeats",
            "IndustryTypeSeats") are tenant/Microsoft-driven and could vary; any basis
            not present on a given snapshot is exported as $null for that column.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer
            token for the entire run and does not refresh it mid-run. Not expected to
            be an issue at typical NumberOfRecords volumes, but very large trend pulls
            could be affected if the token expires mid-run.

.LINK
    Microsoft Graph API - secureScore resource type
    https://learn.microsoft.com/en-us/graph/api/resources/securescore

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-M365DefenderSecureScore
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [ValidateRange(1, 500)]
        [int]$NumberOfRecords = 1,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Block path-traversal characters before this path is ever used with Export-Csv
    if ($ExportPath -and ($ExportPath -match '\.\.[\\/]'))
    {
        Write-Error "ExportPath contains path-traversal characters and was rejected. Exiting function."
        return
    }

    $allScores = New-Object System.Collections.ArrayList
    $totalRetrieved = 0

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $uri = "https://graph.microsoft.com/v1.0/security/secureScores?`$top=$([Math]::Min($NumberOfRecords, 100))"

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
            $scoreData = $partialData.Content | ConvertFrom-Json
        }

        $scoreData.value | ForEach-Object {

            $record = $_
            $row = [ordered]@{
                id                = $record.id
                azureTenantId     = $record.azureTenantId
                createdDateTime   = $record.createdDateTime
                currentScore      = $record.currentScore
                maxScore          = $record.maxScore
                activeUserCount   = $record.activeUserCount
                licensedUserCount = $record.licensedUserCount
                enabledServices   = if ($record.enabledServices) { $record.enabledServices -join "; " } else { $null }
            }

            if ($record.PSObject.Properties['averageComparativeScores'])
            {
                foreach ($comparison in $record.averageComparativeScores)
                {
                    $row["AvgScore_$($comparison.basis)"] = $comparison.averageScore
                }
            }

            $null = $allScores.Add([PSCustomObject]$row)
        }

        $totalRetrieved += $scoreData.value.Count
        Write-Host "Progress: $totalRetrieved Secure Score snapshot(s) retrieved so far" -ForegroundColor Cyan

        if ($totalRetrieved -ge $NumberOfRecords) { break }

        if ($scoreData.PSObject.Properties['@odata.nextLink']) { $uri = $scoreData.'@odata.nextLink' } else { $uri = $null }

    } until (-not $uri)

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allScores | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host ""
        Write-Host "Secure Score report exported successfully -> $ExportPath" -ForegroundColor Green
    }

    return $allScores
}
