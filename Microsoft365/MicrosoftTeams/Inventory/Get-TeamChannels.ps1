<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 02 August 2026
Modified-On     : 02 August 2026

.SYNOPSIS
    Lists Standard, Private, and Shared channels for every Microsoft Team
    using Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph v1.0 endpoint to retrieve every channel
    (Standard/Private/Shared) belonging to each team in scope, essential for
    understanding Team structure and identifying collaboration patterns.

    Handles pagination via @odata.nextLink, retries on HTTP 429 throttling
    using Retry-After, and skips a failing team without aborting the run.
    Only accepts a direct Bearer token (BYOT); does not authenticate itself.
    Obtain a token via the companion Connect-EntraID.ps1 (see .LINK).

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission: Channel.ReadBasic.All (or ChannelSettings.Read.All)

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
    System.Array of channel records; also optionally exports to CSV.

.EXAMPLE
    Get-TeamChannels -AccessToken $token

    Lists every channel across every team in the tenant.

.EXAMPLE
    Get-TeamChannels -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamChannels.csv"

.EXAMPLE
    Get-Teams -AccessToken $token | Get-TeamChannels -AccessToken $token

    Scopes the inventory to a specific set of teams.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (02-Aug-2026) - Initial release
                          - Fixed: the /teams/{id}/channels endpoint does not
                            support the $top query option and returned
                            HTTP 400 Bad Request. Removed $top; the endpoint
                            returns the full channel list in one response.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with Channel.ReadBasic.All
        2. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve teams to evaluate (all, or supplied -TeamId) + names
        Step 2  →  For each team, GET /teams/{id}/channels (paginated, retrying on 429)
        Step 3  →  Flatten channel objects (id, displayName, membershipType, etc.)
        Step 4  →  Repeat for next team (one failure does not abort the run)
        Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permission.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: uses one static Bearer token
            for the entire run; no mid-run refresh. In very large tenants a
            run exceeding the token lifetime (~60-90 min) will fail with 401.
        - RECOMMENDED FOR: smaller tenants or scoped/filtered pulls.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants without
            adding a token-refresh pattern and/or parallelized calls.

.LINK
    Microsoft Graph API - List channels
    https://learn.microsoft.com/en-us/graph/api/team-list-channels

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamChannels
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
        $allChannels = New-Object System.Collections.ArrayList
        $totalChannels = 0

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

                $uri = "https://graph.microsoft.com/v1.0/teams/$id/channels?`$select=id,displayName,description,membershipType,createdDateTime"

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
                        Write-Warning "Failed to retrieve channels for team '$id'. Skipping to next TeamId."
                        break
                    }

                    if($partialData)
                    {
                        $channelsData = $partialData.content | ConvertFrom-Json
                    }

                    Write-Host ""
                    Write-Host "Progress: $($totalChannels += $channelsData.value.Count; $totalChannels) channel(s) retrieved so far" -ForegroundColor Cyan

                    if ($channelsData.PSObject.Properties['@odata.nextLink']) { $uri = $channelsData.'@odata.nextLink' }

                    $channelsData.value | ForEach-Object {
                        $null = $allChannels.Add(
                            [PSCustomObject]@{
                                teamId            = $id
                                teamDisplayName   = $teamDisplayName
                                channelId         = $_.id
                                channelDisplayName = $_.displayName
                                channelType       = $_.membershipType
                                description       = $_.description
                                createdDateTime   = $_.createdDateTime
                            }
                        )
                    }

                } until (-not($channelsData.PSObject.Properties['@odata.nextLink']))
            }
            Catch
            {
                Write-Warning "Failed to retrieve channels for team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $allChannels | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Team channels report exported successfully → $ExportPath" -ForegroundColor Green
        }

        # return $allChannels | Select-Object teamId, teamDisplayName, channelId, channelDisplayName, channelType, description, createdDateTime | FT
        return $allChannels
    }
}
