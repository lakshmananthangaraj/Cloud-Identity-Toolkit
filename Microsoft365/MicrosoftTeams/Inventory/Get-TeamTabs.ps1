<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 12 August 2026
Modified-On     : 12 August 2026

.SYNOPSIS
    Lists configured tabs for every channel across Microsoft Teams using
    Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph v1.0 endpoint to retrieve every tab
    configured on each channel in scope, along with the Teams app backing
    that tab (via $expand=teamsApp). This is the inventory used to document
    integrations and business applications surfaced inside Teams (e.g.
    Planner, Power BI, SharePoint, third-party LOB apps embedded as tabs).

    Resolves teams (and, within each team, channels) first, then retrieves
    tabs per channel. Retries on HTTP 429 throttling using Retry-After, and
    skips a failing team/channel without aborting the run.

    Only accepts a direct Bearer token (BYOT); does not authenticate itself.
    Obtain a token via the companion Connect-EntraID.ps1 (see .LINK).

    The following tab attributes are collected:
        - id, displayName, webUrl, configuration.entityId,
          configuration.contentUrl, teamsApp.id, teamsApp.displayName,
          teamsApp.distributionMethod

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        TeamsTab.Read.All
        Channel.ReadBasic.All (needed to resolve channels when -ChannelId is not supplied)

.PARAMETER TeamId
    Optional. GUID(s) of the Microsoft Team. Accepts an array or pipeline
    input by value/property name (e.g. from Get-MicrosoftTeams). If
    omitted, every team in the tenant is evaluated.

.PARAMETER ChannelId
    Optional. GUID(s) of a specific channel to scope the tab pull to.
    Requires -TeamId to also be supplied (a channel ID is only meaningful
    within its owning team). If omitted, every channel of each team in
    scope is evaluated.

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.INPUTS
    String (TeamId), or objects with an id/TeamId property.

.OUTPUTS
    System.Array
        An array of custom objects containing tab attributes per channel,
        per team. Also optionally exports to CSV.

.EXAMPLE
    Get-TeamTabs -AccessToken $token

    Lists every tab across every channel, across every team in the tenant.

.EXAMPLE
    Get-TeamTabs -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamTabs.csv"

.EXAMPLE
    Get-MicrosoftTeams -AccessToken $token | Get-TeamTabs -AccessToken $token

    Scopes the inventory to a specific set of teams.

.EXAMPLE
    Get-TeamTabs -AccessToken $token -TeamId "11111111-1111-1111-1111-111111111111" -ChannelId "19:abc123@thread.tacv2"

    Lists tabs for a single channel of a single team.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (12-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with:
                TeamsTab.Read.All
                Channel.ReadBasic.All (only needed when resolving channels automatically)
        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve teams to evaluate (all, or supplied -TeamId) + names
        Step 2  →  For each team, resolve channels (all, or supplied -ChannelId) + names
        Step 3  →  For each channel, GET /teams/{id}/channels/{id}/tabs?$expand=teamsApp
                    (retrying on HTTP 429 using Retry-After)
        Step 4  →  Flatten tab objects (id, displayName, webUrl, teamsApp info)
        Step 5  →  Repeat for next channel/team (one failure does not abort the run)
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permissions.
        - The tabs and channels endpoints used here do not support $top and are
            called as a single page per channel/team; this is consistent with
            observed Graph behaviour for these endpoints and not a pagination gap.
        - teamsApp.displayName/distributionMethod could not be confirmed for tabs
            whose backing app was removed from the catalog; these fields return
            $null from Graph in that case rather than an error.
        - SINGLE-TOKEN, SEQUENTIAL RUN: this function uses one static Bearer
            token for the entire run and does not refresh it mid-run. In very
            large tenants, if the full pull (teams × channels × tabs) takes
            longer than the token's lifetime (typically ~60-90 minutes), the run
            will fail partway through with 401 Unauthorized once the token
            expires.
        - RECOMMENDED FOR: smaller/medium tenants, or scoped pulls via -TeamId /
            -ChannelId.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants without a
            token-refresh pattern and/or parallelized calls.

.LINK
    Microsoft Graph API - List tabs
    https://learn.microsoft.com/en-us/graph/api/channel-list-tabs

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamTabs {
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("id")]
        [string[]]$TeamId,

        [Parameter(Mandatory = $false)]
        [string[]]$ChannelId,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    Begin {
        $allTabs = New-Object System.Collections.ArrayList
        $totalTabs = 0

        if (-not $AccessToken) {
            Write-Error "AccessToken is required. Exiting function."
            return
        }

        if ($ChannelId -and -not $PSBoundParameters.ContainsKey('TeamId')) {
            Write-Error "-ChannelId requires -TeamId to also be supplied. Exiting function."
            return
        }

        $headers = @{
            "Authorization"    = "Bearer $AccessToken"
            "ConsistencyLevel" = "eventual"
        }

        $resolveAllTeams = (-not $PSBoundParameters.ContainsKey('TeamId')) -and (-not $MyInvocation.ExpectingInput)

        $teamNameMap = @{}
        $allTeamIds = New-Object System.Collections.ArrayList
        $teamsUri = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName&`$count=true"

        Write-Verbose "Resolving team display names..."
        do {
            $teamsSkip = $false
            do {
                Try {
                    $teamsPartial = Invoke-WebRequest -Uri $teamsUri -Headers $headers -Method Get -ErrorAction Stop
                    $teamsStatus = $teamsPartial.StatusCode
                }
                catch {
                    $teamsStatus = $_.Exception.Response.StatusCode
                    if ($teamsStatus -eq 429) {
                        $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                        Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                        Start-Sleep -Seconds $sleepTime
                    }
                    else {
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

        if ($resolveAllTeams) {
            $TeamId = $allTeamIds
            Write-Verbose "Resolved $($TeamId.Count) team(s) to process."
        }
    }

    Process {
        foreach ($tid in $TeamId) {
            Try {
                $teamDisplayName = if ($teamNameMap.ContainsKey($tid)) { $teamNameMap[$tid] } else { "Could not be confirmed" }

                # Resolve channels for this team unless the caller scoped to specific ChannelId(s)
                $channelsToProcess = New-Object System.Collections.ArrayList
                $channelNameMap = @{}

                if ($ChannelId) {
                    $ChannelId | ForEach-Object { $null = $channelsToProcess.Add($_) }
                }
                else {
                    $channelsUri = "https://graph.microsoft.com/v1.0/teams/$tid/channels?`$select=id,displayName"
                    $chSkip = $false
                    do {
                        Try {
                            $chPartial = Invoke-WebRequest -Uri $channelsUri -Headers $headers -Method Get -ErrorAction Stop
                            $chStatus = $chPartial.StatusCode
                        }
                        catch {
                            $chStatus = $_.Exception.Response.StatusCode
                            if ($chStatus -eq 429) {
                                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                                Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                                Start-Sleep -Seconds $sleepTime
                            }
                            else {
                                Write-Warning "Failed to resolve channels for team '$tid': $($_.Exception.Message)."
                                $chSkip = $true
                            }
                        }
                    } until(($chStatus -eq 200) -or $chSkip)

                    if ($chSkip) { Write-Warning "Skipping team '$tid' (channel resolution failed)."; continue }

                    $chData = $chPartial.Content | ConvertFrom-Json
                    $chData.value | ForEach-Object {
                        $channelNameMap[$_.id] = $_.displayName
                        $null = $channelsToProcess.Add($_.id)
                    }
                }

                foreach ($cid in $channelsToProcess) {
                    $channelDisplayName = if ($channelNameMap.ContainsKey($cid)) { $channelNameMap[$cid] } else { "Could not be confirmed" }

                    $tabsUri = "https://graph.microsoft.com/v1.0/teams/$tid/channels/$cid/tabs?`$expand=teamsApp"

                    $skip = $false
                    do {
                        Try {
                            $partialData = Invoke-WebRequest -Uri $tabsUri -Headers $headers -Method Get -ErrorAction Stop
                            $statusCode = $partialData.StatusCode
                        }
                        catch {
                            $statusCode = $_.Exception.Response.StatusCode
                            $ErrorObject = $_

                            if ($statusCode -eq 429) {
                                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                                Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                                Start-Sleep -Seconds $sleepTime
                            }
                            else {
                                $ErrorOutput = [PSCustomObject][ordered]@{
                                    TeamId     = $tid
                                    ChannelId  = $cid
                                    Response   = $($ErrorObject.Exception.Response)
                                    StatusCode = $($ErrorObject.Exception.Response.StatusCode)
                                    Message    = $($ErrorObject.Exception.Message)
                                };
                                $ErrorOutput | Format-List
                                $skip = $true
                            }
                        }
                    } until(($statusCode -eq 200) -or $skip)

                    if ($skip) {
                        Write-Warning "Failed to retrieve tabs for channel '$cid' in team '$tid'. Skipping to next channel."
                        continue
                    }

                    $tabsData = $partialData.Content | ConvertFrom-Json

                    Write-Host ""
                    Write-Host "Progress: $($totalTabs += $tabsData.value.Count; $totalTabs) tab(s) retrieved so far" -ForegroundColor Cyan

                    $tabsData.value | ForEach-Object {
                        $null = $allTabs.Add(
                            [PSCustomObject]@{
                                teamId                  = $tid
                                teamDisplayName         = $teamDisplayName
                                channelId               = $cid
                                channelDisplayName      = $channelDisplayName
                                tabId                   = $_.id
                                tabDisplayName          = $_.displayName
                                tabWebUrl               = $_.webUrl
                                configurationEntityId   = $_.configuration.entityId
                                configurationContentUrl = $_.configuration.contentUrl
                                teamsAppId              = if ($_.teamsApp) { $_.teamsApp.id } else { "Could not be confirmed" }
                                teamsAppDisplayName     = if ($_.teamsApp) { $_.teamsApp.displayName } else { "Could not be confirmed" }
                                teamsAppDistribution    = if ($_.teamsApp) { $_.teamsApp.distributionMethod } else { "Could not be confirmed" }
                            }
                        )
                    }
                }
            }
            Catch {
                Write-Warning "Failed to process team '$tid': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End {
        if ($ExportFormat -eq "CSV" -and $ExportPath) {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder)) {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $allTabs | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Team tabs report exported successfully → $ExportPath" -ForegroundColor Green
        }

        return $allTabs
    }
}
