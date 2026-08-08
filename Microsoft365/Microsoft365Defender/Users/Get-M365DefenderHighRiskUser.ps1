<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Surfaces Microsoft Entra ID Protection risky users and risky sign-ins (risk detections)
    using Microsoft Graph API.

.DESCRIPTION
    This function sits at the boundary between Microsoft Entra ID and Microsoft Defender: it
    queries two related but distinct Microsoft Graph v1.0 Identity Protection endpoints and
    returns both as one combined result:
        1. /identityProtection/riskyUsers      — user-level aggregate risk state
        2. /identityProtection/riskDetections   — individual risky sign-in / risk-event records

    A user can appear in riskyUsers with an aggregated riskLevel while having multiple
    individual entries in riskDetections that contributed to it — the two collections are
    related but are NOT a 1:1 join, so they are returned as two separate labeled sections
    rather than merged into a single flattened table.

    The optional -RiskLevel filter is applied identically (server-side) to both underlying
    queries.

    It handles pagination automatically via @odata.nextLink, retries on API throttling
    (HTTP 429) using the Retry-After header, and validates the JSON response before
    processing it further.

    Results can optionally be exported to CSV. Because this function produces two distinct
    result sets, -ExportPath is treated as a base path: the function appends "_RiskyUsers.csv"
    and "_RiskySignIns.csv" to it and writes both files.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK below,
    then pass its returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        IdentityRiskyUser.Read.All (Application)
        IdentityRiskEvent.Read.All (Application)

.PARAMETER RiskLevel
    Optional. Filters both riskyUsers and riskDetections by risk level.
    Supported values:
        low, medium, high

.PARAMETER Top
    Page size used per Graph request for each endpoint. Default is 50.

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV

.PARAMETER ExportPath
    Base file path (without requiring a specific extension) used to derive the two CSV
    output file names. Required only when ExportFormat is set to CSV.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject
        An object with two properties:
            RiskyUsers    - user-level aggregate risk records
            RiskySignIns  - individual risk detection records
        Also optionally exports both to CSV.

.EXAMPLE
    Get-M365DefenderHighRiskUser -AccessToken $token -RiskLevel high

    Retrieves high-risk users and high-risk sign-in detections.

.EXAMPLE
    $risk = Get-M365DefenderHighRiskUser -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\EntraRisk"
    $risk.RiskyUsers | Where-Object riskState -eq 'atRisk'

    Runs the pull, writes "C:\Reports\EntraRisk_RiskyUsers.csv" and
    "C:\Reports\EntraRisk_RiskySignIns.csv", and filters unremediated risky users in-session.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                IdentityRiskyUser.Read.All (Application)
                IdentityRiskEvent.Read.All (Application)

        2. Microsoft Entra ID Protection (Entra ID P2, or equivalent) must be licensed
                for the tenant — both endpoints return empty/limited data otherwise.

        3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - RiskyUsers and RiskySignIns are related but NOT a guaranteed 1:1 join — a risky
            user's aggregate riskLevel can reflect multiple sign-in risk detections, or
            offline/non-sign-in risk signals with no corresponding riskDetections entry at
            all. Do not assume every RiskyUsers row has a matching RiskySignIns row.
        - riskState values (e.g. atRisk, confirmedSafe, remediated, dismissed) are returned
            as-is; this function does not interpret or re-classify risk state.
        - The -hidden riskLevel value (used by Microsoft for lower-confidence detections) is
            intentionally out of scope for -RiskLevel's ValidateSet in this version — only
            low/medium/high are exposed. Treat as a possible future enhancement.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer token for
            both endpoints across the entire run and does not refresh it mid-run.

.LINK
    Microsoft Graph API - riskyUser resource type
    https://learn.microsoft.com/en-us/graph/api/resources/riskyuser

.LINK
    Microsoft Graph API - riskDetection resource type
    https://learn.microsoft.com/en-us/graph/api/resources/riskdetection

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-M365DefenderHighRiskUser
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [ValidateSet("low", "medium", "high")]
        [string]$RiskLevel,

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

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $filterQuery = if ($RiskLevel) { "&`$filter=riskLevel eq '$RiskLevel'" } else { "" }

    # ── Internal helper: paginated GET with 429 retry against a given Graph endpoint
    function Get-GraphCollection
    {
        param ([string]$InitialUri, [hashtable]$Headers, [string]$ItemLabel)

        $items = New-Object System.Collections.ArrayList
        $uri = $InitialUri

        do
        {
            Try
            {
                $response = Invoke-WebRequest -Uri $uri -Headers $Headers -Method Get -ErrorAction Stop
                $pageData = $response.Content | ConvertFrom-Json
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
                    return $items
                }
            }

            $pageData.value | ForEach-Object { $null = $items.Add($_) }
            Write-Host "Progress: $($items.Count) $ItemLabel retrieved so far" -ForegroundColor Cyan

            if ($pageData.PSObject.Properties['@odata.nextLink']) { $uri = $pageData.'@odata.nextLink' } else { $uri = $null }

        } until (-not $uri)

        return $items
    }

    # ── Risky users
    $riskyUsersUri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$top=$Top$filterQuery"
    $rawRiskyUsers = Get-GraphCollection -InitialUri $riskyUsersUri -Headers $headers -ItemLabel "risky user(s)"

    $riskyUsers = $rawRiskyUsers | ForEach-Object {
        [PSCustomObject][ordered]@{
            id                    = $_.id
            userDisplayName       = $_.userDisplayName
            userPrincipalName     = $_.userPrincipalName
            riskLevel             = $_.riskLevel
            riskState             = $_.riskState
            riskDetail            = $_.riskDetail
            riskLastUpdatedDateTime = $_.riskLastUpdatedDateTime
            isDeleted             = $_.isDeleted
            isProcessing          = $_.isProcessing
        }
    }

    # ── Risky sign-ins (risk detections)
    $riskDetectionsUri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$top=$Top$filterQuery"
    $rawRiskDetections = Get-GraphCollection -InitialUri $riskDetectionsUri -Headers $headers -ItemLabel "risk detection(s)"

    $riskySignIns = $rawRiskDetections | ForEach-Object {
        [PSCustomObject][ordered]@{
            id                 = $_.id
            userDisplayName    = $_.userDisplayName
            userPrincipalName  = $_.userPrincipalName
            riskEventType      = $_.riskEventType
            riskLevel          = $_.riskLevel
            riskState          = $_.riskState
            riskDetail         = $_.riskDetail
            detectedDateTime   = $_.detectedDateTime
            activity           = $_.activity
            ipAddress          = $_.ipAddress
            city               = $_.location.city
            countryOrRegion    = $_.location.countryOrRegion
            source             = $_.source
        }
    }

    $result = [PSCustomObject]@{
        RiskyUsers   = $riskyUsers
        RiskySignIns = $riskySignIns
    }

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $riskyUsersPath   = "${ExportPath}_RiskyUsers.csv"
        $riskySignInsPath = "${ExportPath}_RiskySignIns.csv"

        $riskyUsers   | Export-Csv -Path $riskyUsersPath -NoTypeInformation -Force
        $riskySignIns | Export-Csv -Path $riskySignInsPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Risky users exported successfully -> $riskyUsersPath" -ForegroundColor Green
        Write-Host "Risky sign-ins exported successfully -> $riskySignInsPath" -ForegroundColor Green
    }

    return $result
}
