<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Lists actionable Secure Score recommendations for the tenant using Microsoft Graph API.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 /security/secureScoreControlProfiles
    endpoint to retrieve the catalog of security controls that contribute to (or could
    improve) the tenant's Secure Score, along with their current implementation state.

    It handles pagination automatically via @odata.nextLink, retries on API throttling
    (HTTP 429) using the Retry-After header, and validates the JSON response before
    processing it further.

    Array-valued properties (threats, vendorInformation) are flattened into
    comma/semicolon-separated strings for CSV friendliness.

    Results can optionally be exported to CSV.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK below,
    then pass its returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        SecurityEvents.Read.All (Application)

.PARAMETER ControlCategory
    Optional filter to return only controls belonging to a specific controlCategory
    (e.g. "Identity", "Data", "Device", "Apps"). Free-text — categories are Microsoft-defined
    and not exposed as a fixed enum via Graph.

.PARAMETER IncludeDeprecated
    Switch. By default, controls flagged as deprecated by Microsoft are excluded. Pass this
    switch to include them in the output.

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
        An array of custom objects containing Secure Score control/recommendation
        attributes. Also optionally exports to CSV.

.EXAMPLE
    Get-M365DefenderRecommendations -AccessToken $token

    Retrieves all non-deprecated Secure Score recommendations for the tenant.

.EXAMPLE
    Get-M365DefenderRecommendations -AccessToken $token -ControlCategory "Identity" -ExportFormat CSV -ExportPath "C:\Reports\IdentityRecommendations.csv"

    Retrieves only Identity-category recommendations and exports them to CSV.

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
        - controlStateUpdates (history of who assigned/ignored/resolved a control) is
            not flattened into this output; only the control's current definition and
            scoring metadata are returned. Treat controlStateUpdates as a future
            enhancement if per-control assignment history is needed.
        - -ControlCategory is applied client-side after retrieval, not as a server-side
            $filter, since Graph's support for filtering this endpoint by category is
            inconsistent across tenants.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer
            token for the entire pagination run and does not refresh it mid-run. In
            very large tenants this could fail with 401 if the full pull outlives the
            token's lifetime.

.LINK
    Microsoft Graph API - secureScoreControlProfile resource type
    https://learn.microsoft.com/en-us/graph/api/resources/securescorecontrolprofile

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-M365DefenderRecommendations
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [string]$ControlCategory,

        [switch]$IncludeDeprecated,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    if ($ExportPath -and ($ExportPath -match '\.\.[\\/]'))
    {
        Write-Error "ExportPath contains path-traversal characters and was rejected. Exiting function."
        return
    }

    $allControls = New-Object System.Collections.ArrayList
    $totalControls = 0

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $uri = "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?`$top=100"

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
            $controlData = $partialData.Content | ConvertFrom-Json
        }

        $controlData.value | ForEach-Object {

            $control = $_

            if (-not $IncludeDeprecated -and $control.deprecated) { return }
            if ($ControlCategory -and ($control.controlCategory -ne $ControlCategory)) { return }

            $null = $allControls.Add(
                [PSCustomObject][ordered]@{
                    id                 = $control.id
                    title              = $control.title
                    controlCategory    = $control.controlCategory
                    tier               = $control.tier
                    service            = $control.service
                    actionType         = $control.actionType
                    rank               = $control.rank
                    maxScore           = $control.maxScore
                    userImpact         = $control.userImpact
                    implementationCost = $control.implementationCost
                    deprecated         = $control.deprecated
                    threats            = if ($control.threats) { $control.threats -join "; " } else { $null }
                    remediation        = $control.remediation
                    remediationImpact  = $control.remediationImpact
                    lastModifiedDateTime = $control.lastModifiedDateTime
                }
            )
        }

        $totalControls += $controlData.value.Count
        Write-Host "Progress: $totalControls recommendation(s) retrieved so far" -ForegroundColor Cyan

        if ($controlData.PSObject.Properties['@odata.nextLink']) { $uri = $controlData.'@odata.nextLink' } else { $uri = $null }

    } until (-not $uri)

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allControls | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host ""
        Write-Host "Secure Score recommendations exported successfully -> $ExportPath" -ForegroundColor Green
    }

    return $allControls
}
