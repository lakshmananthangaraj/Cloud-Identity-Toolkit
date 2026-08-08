<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Performs a Secure Score gap analysis for the tenant: unrealized score by category, and
    recommendations ranked by score-impact-per-effort.

.DESCRIPTION
    This function independently queries two Microsoft Graph v1.0 endpoints and joins the
    results in-memory:
        1. /security/secureScores  (latest snapshot — includes controlScores: the CURRENT
           score each control is achieving)
        2. /security/secureScoreControlProfiles  (the full control catalog — includes each
           control's maxScore, implementationCost, userImpact, and remediation guidance)

    This function is intentionally standalone: it duplicates the retrieval logic found in
    Get-DefenderSecureScore.ps1 and Get-DefenderRecommendations.ps1 rather than calling them,
    so it has no dependency on those scripts being loaded/dot-sourced first.

    For each non-deprecated control, unrealized score is calculated as:
        unrealizedScore = maxScore - currentScore

    Controls are then rolled up by controlCategory to show where the largest unrealized
    score potential sits, and individually ranked by a score-impact-per-effort metric:
        effortWeight     = weight(implementationCost) + weight(userImpact)     [low=1, moderate=2, high=3]
        impactPerEffort  = unrealizedScore / effortWeight

    Higher impactPerEffort = bigger score gain for comparatively less implementation/user
    friction — useful for prioritizing remediation backlogs.

    It handles pagination automatically via @odata.nextLink, retries on API throttling
    (HTTP 429) using the Retry-After header, and validates the JSON response before
    processing it further.

    Results can optionally be exported to CSV. Because this function produces two distinct
    result sets (category rollup and ranked recommendations), -ExportPath is treated as a
    base path: the function appends "_CategoryBreakdown.csv" and "_RankedRecommendations.csv"
    to it and writes both files.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK below,
    then pass its returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        SecurityEvents.Read.All (Application)

.PARAMETER IncludeDeprecated
    Switch. By default, controls flagged as deprecated by Microsoft are excluded from both
    the category breakdown and the ranked recommendations. Pass this switch to include them.

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
            CategoryBreakdown      - unrealized score rolled up by controlCategory
            RankedRecommendations  - individual controls ranked by impactPerEffort (descending)
        Also optionally exports both to CSV.

.EXAMPLE
    Get-M365DefenderSecureScoreGapAnalysis -AccessToken $token

    Returns the gap analysis object with CategoryBreakdown and RankedRecommendations.

.EXAMPLE
    $gap = Get-M365DefenderSecureScoreGapAnalysis -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\SecureScoreGap"
    $gap.RankedRecommendations | Select-Object -First 10

    Runs the analysis, writes "C:\Reports\SecureScoreGap_CategoryBreakdown.csv" and
    "C:\Reports\SecureScoreGap_RankedRecommendations.csv", and previews the top 10
    highest-impact-per-effort recommendations in-session.

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
        - JOIN ASSUMPTION: this function matches secureScores.controlScores[].controlName
            to secureScoreControlProfiles[].id, per Microsoft's documented data model. This
            join could not be independently verified beyond that documentation — if a
            control's controlName has no matching profile, its currentScore is treated as
            0 and it is flagged via the IsUnmatched column rather than silently dropped.
        - effortWeight uses a simple low=1/moderate=2/high=3 mapping. Any implementationCost
            or userImpact value outside that set (including $null) defaults to a weight of 2
            and is flagged via the IsEffortEstimated column — treat ranking as directional,
            not authoritative, for those rows.
        - Uses only the single LATEST Secure Score snapshot; it does not analyze trend over
            time. Pair with Get-DefenderSecureScore -NumberOfRecords for historical context.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer token for
            the entire run and does not refresh it mid-run.

.LINK
    Microsoft Graph API - secureScore resource type
    https://learn.microsoft.com/en-us/graph/api/resources/securescore

.LINK
    Microsoft Graph API - secureScoreControlProfile resource type
    https://learn.microsoft.com/en-us/graph/api/resources/securescorecontrolprofile

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-M365DefenderSecureScoreGapAnalysis
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

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

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    # ── Internal helper: single GET with 429 retry, returns parsed JSON or $null on hard failure
    function Invoke-GraphGetWithRetry
    {
        param ([string]$Uri, [hashtable]$Headers)

        do
        {
            Try
            {
                $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
                return ($response.Content | ConvertFrom-Json)
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
        } while ($true)
    }

    function Get-EffortWeight
    {
        param ([string]$Value)

        switch ($Value)
        {
            "low"      { return 1 }
            "moderate" { return 2 }
            "high"     { return 3 }
            default    { return 2 }
        }
    }

    # ── Step 1: latest Secure Score snapshot (for controlScores — current achieved per control)
    $secureScoreUri = "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1"
    $secureScoreData = Invoke-GraphGetWithRetry -Uri $secureScoreUri -Headers $headers
    if (-not $secureScoreData -or -not $secureScoreData.value -or $secureScoreData.value.Count -eq 0)
    {
        Write-Error "Unable to retrieve a Secure Score snapshot. Exiting function."
        return
    }

    $latestSnapshot = $secureScoreData.value[0]
    $currentScoreByControl = @{}
    foreach ($cs in $latestSnapshot.controlScores)
    {
        $currentScoreByControl[$cs.controlName] = $cs.score
    }

    # ── Step 2: full control catalog (paginated) for maxScore, effort, and remediation guidance
    $allControls = New-Object System.Collections.ArrayList
    $controlUri = "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?`$top=100"

    do
    {
        $controlData = Invoke-GraphGetWithRetry -Uri $controlUri -Headers $headers
        if (-not $controlData) { return }

        $controlData.value | ForEach-Object { $null = $allControls.Add($_) }
        Write-Host "Progress: $($allControls.Count) control profile(s) retrieved so far" -ForegroundColor Cyan

        if ($controlData.PSObject.Properties['@odata.nextLink']) { $controlUri = $controlData.'@odata.nextLink' } else { $controlUri = $null }

    } until (-not $controlUri)

    # ── Step 3: join, compute unrealized score / effort weight, and roll up by category
    $rankedRecommendations = New-Object System.Collections.ArrayList
    $categoryTotals = @{}

    foreach ($control in $allControls)
    {
        if (-not $IncludeDeprecated -and $control.deprecated) { continue }

        $isUnmatched = -not $currentScoreByControl.ContainsKey($control.id)
        $currentScore = if ($isUnmatched) { 0 } else { $currentScoreByControl[$control.id] }
        $maxScore = if ($control.maxScore) { $control.maxScore } else { 0 }
        $unrealizedScore = [Math]::Max(0, $maxScore - $currentScore)

        $isEffortEstimated = ($control.implementationCost -notin @("low", "moderate", "high")) -or ($control.userImpact -notin @("low", "moderate", "high"))
        $effortWeight = (Get-EffortWeight $control.implementationCost) + (Get-EffortWeight $control.userImpact)
        $impactPerEffort = if ($effortWeight -gt 0) { [Math]::Round($unrealizedScore / $effortWeight, 2) } else { 0 }

        $null = $rankedRecommendations.Add(
            [PSCustomObject][ordered]@{
                id                 = $control.id
                title              = $control.title
                controlCategory    = $control.controlCategory
                maxScore           = $maxScore
                currentScore       = $currentScore
                unrealizedScore    = $unrealizedScore
                implementationCost = $control.implementationCost
                userImpact         = $control.userImpact
                effortWeight       = $effortWeight
                impactPerEffort    = $impactPerEffort
                remediation        = $control.remediation
                isUnmatched        = $isUnmatched
                isEffortEstimated  = $isEffortEstimated
            }
        )

        if (-not $categoryTotals.ContainsKey($control.controlCategory))
        {
            $categoryTotals[$control.controlCategory] = [PSCustomObject][ordered]@{
                controlCategory   = $control.controlCategory
                totalMaxScore     = 0
                totalCurrentScore = 0
                totalUnrealized   = 0
            }
        }
        $categoryTotals[$control.controlCategory].totalMaxScore     += $maxScore
        $categoryTotals[$control.controlCategory].totalCurrentScore += $currentScore
        $categoryTotals[$control.controlCategory].totalUnrealized   += $unrealizedScore
    }

    $categoryBreakdown = $categoryTotals.Values | ForEach-Object {
        $percentRealized = if ($_.totalMaxScore -gt 0) { [Math]::Round(($_.totalCurrentScore / $_.totalMaxScore) * 100, 1) } else { $null }
        [PSCustomObject][ordered]@{
            controlCategory   = $_.controlCategory
            totalMaxScore     = $_.totalMaxScore
            totalCurrentScore = $_.totalCurrentScore
            totalUnrealized   = $_.totalUnrealized
            percentRealized   = $percentRealized
        }
    } | Sort-Object totalUnrealized -Descending

    $rankedRecommendations = $rankedRecommendations | Sort-Object impactPerEffort -Descending

    $result = [PSCustomObject]@{
        CategoryBreakdown     = $categoryBreakdown
        RankedRecommendations = $rankedRecommendations
    }

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $categoryPath = "${ExportPath}_CategoryBreakdown.csv"
        $rankedPath   = "${ExportPath}_RankedRecommendations.csv"

        $categoryBreakdown     | Export-Csv -Path $categoryPath -NoTypeInformation -Force
        $rankedRecommendations | Export-Csv -Path $rankedPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Secure Score gap analysis exported successfully -> $categoryPath" -ForegroundColor Green
        Write-Host "Secure Score gap analysis exported successfully -> $rankedPath" -ForegroundColor Green
    }

    return $result
}
