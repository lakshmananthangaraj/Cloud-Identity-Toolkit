<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 02 August 2026
Modified-On     : 02 August 2026

.SYNOPSIS
    Lists installed Microsoft and third-party apps in Microsoft Teams using
    Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph v1.0 endpoint for the installed-apps list of
    each team in scope, expanding the app catalog entry to surface the
    publishing/distribution method, which helps identify shadow IT and risky
    third-party or sideloaded applications.

    A RiskFlag is computed per app: sideloaded (custom-uploaded, unpublished)
    apps are flagged "Review" since they bypass the Teams app catalog's
    publisher vetting; store/organization-published apps are flagged "Normal".

    Handles pagination via @odata.nextLink, retries on HTTP 429 throttling
    using Retry-After, and skips a failing team without aborting the run.
    Only accepts a direct Bearer token (BYOT); does not authenticate itself.
    Obtain a token via the companion Connect-EntraID.ps1 (see .LINK).

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission: TeamsAppInstallation.Read.All (or
    TeamsAppInstallation.Read.All for the team scope, Application permission)

.PARAMETER TeamId
    Optional. GUID(s) of the Microsoft Team. Accepts an array or pipeline
    input by value/property name (e.g. from Get-Teams). If omitted, every
    team in the tenant is evaluated.

.PARAMETER ExportFormat
    Supported values: CSV

.PARAMETER ExportPath
    File path for the exported CSV. Required only when ExportFormat is CSV.

.INPUTS
    String (TeamId), or objects with an id/TeamId property.

.OUTPUTS
    System.Array of installed-app records; also optionally exports to CSV.

.EXAMPLE
    Get-TeamApps -AccessToken $token

    Lists installed apps across every team in the tenant.

.EXAMPLE
    Get-TeamApps -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamApps.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (02-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with TeamsAppInstallation.Read.All
        2. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve teams to evaluate (all, or supplied -TeamId) + names
        Step 2  →  For each team, GET /teams/{id}/installedApps?$expand=teamsApp,teamsAppDefinition
                    (paginated, retrying on 429)
        Step 3  →  Flatten app objects, computing RiskFlag from distributionMethod
        Step 4  →  Repeat for next team (one failure does not abort the run)
        Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permission.
        - RiskFlag is a heuristic based on distributionMethod alone (sideloaded
            = Review); it does not evaluate the app's actual requested
            permissions/scopes, which would require additional Graph calls
            against the app catalog and could not be confirmed generically
            here.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: uses one static Bearer token
            for the entire run; no mid-run refresh. In very large tenants a
            run exceeding the token lifetime (~60-90 min) will fail with 401.
        - RECOMMENDED FOR: smaller tenants or scoped/filtered pulls.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants without
            adding a token-refresh pattern and/or parallelized calls.

.LINK
    Microsoft Graph API - List apps in team
    https://learn.microsoft.com/en-us/graph/api/team-list-installedapps

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamApps
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("id")]
        [string[]]$TeamId,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    Begin
    {
        $allApps = New-Object System.Collections.ArrayList
        $totalApps = 0

        if (-not $AccessToken)
        {
            Write-Error "AccessToken is required. Exiting function."
            return
        }

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "ConsistencyLevel" = "eventual"
        }

        $resolveAllTeams = (-not $PSBoundParameters.ContainsKey('TeamId')) -and (-not $MyInvocation.ExpectingInput)

        $teamNameMap = @{}
        $allTeamIds  = New-Object System.Collections.ArrayList
        $teamsUri    = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName&`$count=true"

        Write-Verbose "Resolving team display names..."
        do
        {
            $teamsSkip = $false
            do
            {
                Try
                {
                    $teamsPartial = Invoke-WebRequest -Uri $teamsUri -Headers $headers -Method Get -ErrorAction Stop
                    $teamsStatus  = $teamsPartial.StatusCode
                }
                catch
                {
                    $teamsStatus = $_.Exception.Response.StatusCode
                    if ($teamsStatus -eq 429)
                    {
                        $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                        Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                        Start-Sleep -Seconds $sleepTime
                    }
                    else
                    {
                        Write-Warning "Failed to resolve team display names: $($_.Exception.Message)."
                        $teamsSkip = $true
                    }
                }
            } until(($teamsStatus -eq 200) -or $teamsSkip)

            if ($teamsSkip) { break }

            $teamsData = $teamsPartial.Content | ConvertFrom-Json
            $teamsData.value | ForEach-Object {
                $teamNameMap[$_.id] = $_.displayName
                $null = $allTeamIds.Add($_.id)
            }

            if ($teamsData.PSObject.Properties['@odata.nextLink']) { $teamsUri = $teamsData.'@odata.nextLink' } else { $teamsUri = $null }

        } until (-not $teamsUri)

        if ($resolveAllTeams)
        {
            $TeamId = $allTeamIds
            Write-Verbose "Resolved $($TeamId.Count) team(s) to process."
        }
    }

    Process
    {
        foreach ($id in $TeamId)
        {
            Try
            {
                $teamDisplayName = if ($teamNameMap.ContainsKey($id)) { $teamNameMap[$id] } else { "Could not be confirmed" }

                $uri = "https://graph.microsoft.com/v1.0/teams/$id/installedApps?`$expand=teamsApp,teamsAppDefinition"

                do
                {
                    $skip = $false
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
                                    TeamId      = $id
                                    Response    = $($ErrorObject.Exception.Response)
                                    StatusCode  = $($ErrorObject.Exception.Response.StatusCode)
                                    Message     = $($ErrorObject.Exception.Message)
                                };
                                $ErrorOutput | Format-List
                                $skip = $true;
                            }
                        }
                    } until(($statusCode -eq 200) -or $skip)

                    if ($skip)
                    {
                        Write-Warning "Failed to retrieve installed apps for team '$id'. Skipping to next TeamId."
                        break
                    }

                    if($partialData)
                    {
                        $appsData = $partialData.content | ConvertFrom-Json
                    }

                    Write-Host ""
                    Write-Host "Progress: $($totalApps += $appsData.value.Count; $totalApps) installed app record(s) retrieved so far" -ForegroundColor Cyan

                    if ($appsData.PSObject.Properties['@odata.nextLink']) { $uri = $appsData.'@odata.nextLink' }

                    $appsData.value | ForEach-Object {
                        $appDef = $_.teamsAppDefinition
                        $distributionMethod = $_.teamsApp.distributionMethod
                        $riskFlag = if ($distributionMethod -eq "sideloaded") { "Review" } else { "Normal" }

                        $null = $allApps.Add(
                            [PSCustomObject]@{
                                teamId              = $id
                                teamDisplayName     = $teamDisplayName
                                appId               = $_.teamsApp.id
                                appDisplayName      = $appDef.displayName
                                appVersion          = $appDef.version
                                distributionMethod  = $distributionMethod
                                publishingState     = $appDef.publishingState
                                riskFlag            = $riskFlag
                            }
                        )
                    }

                } until (-not($appsData.PSObject.Properties['@odata.nextLink']))
            }
            Catch
            {
                Write-Warning "Failed to retrieve installed apps for team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        $reviewCount = @($allApps | Where-Object { $_.riskFlag -eq "Review" }).Count
        Write-Host ""
        Write-Host "Found $($allApps.Count) installed app record(s); $reviewCount flagged for review (sideloaded)." -ForegroundColor Cyan

        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $allApps | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Team apps report exported successfully → $ExportPath" -ForegroundColor Green
        }

        # return $allApps | Select-Object teamId, teamDisplayName, appId, appDisplayName, appVersion, distributionMethod, publishingState, riskFlag | FT
        return $allApps
    }
}
