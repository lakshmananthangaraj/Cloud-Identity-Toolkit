<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 02 August 2026
Modified-On     : 02 August 2026

.SYNOPSIS
    Retrieves membership of Private and Shared Teams channels using
    Microsoft Graph API.

.DESCRIPTION
    Standard channel membership always mirrors team membership, but Private
    and Shared channels maintain their own membership list, which can differ
    significantly (and, for Shared channels, can include users outside the
    parent team or even outside the tenant). This function enumerates every
    Private/Shared channel across the teams in scope and retrieves its
    member roster.

    Standard channels are intentionally excluded from output since their
    membership is identical to the team's membership (see Get-TeamMembers).

    Handles pagination via @odata.nextLink, retries on HTTP 429 throttling
    using Retry-After, and skips a failing channel without aborting the run.
    Only accepts a direct Bearer token (BYOT); does not authenticate itself.
    Obtain a token via the companion Connect-EntraID.ps1 (see .LINK).

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions: Channel.ReadBasic.All, ChannelMember.Read.All

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
    System.Array of channel-member records; also optionally exports to CSV.

.EXAMPLE
    Get-TeamChannelMembers -AccessToken $token

    Retrieves private/shared channel membership across every team.

.EXAMPLE
    Get-TeamChannelMembers -AccessToken $token -TeamId "11111111-1111-1111-1111-111111111111" -ExportFormat CSV -ExportPath "C:\Reports\ChannelMembers.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (02-Aug-2026) - Initial release
                          - A team with zero Private/Shared channels (Standard
                              channels only) now produces an explicit console
                              message instead of silently returning nothing;
                              added a total-record-count summary line.
                          - Fixed: the /teams/{id}/channels endpoint does not
                              support the $top query option and returned
                              HTTP 400 Bad Request. Removed $top from the
                              channel-listing call (the channel-members call
                              is unaffected - that endpoint does support $top).

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with Channel.ReadBasic.All
            and ChannelMember.Read.All
        2. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve teams to evaluate (all, or supplied -TeamId) + names
        Step 2  →  For each team, GET /teams/{id}/channels filtered client-side
                    to membershipType private/shared
        Step 3  →  For each such channel, GET /teams/{id}/channels/{id}/members
                    (paginated, retrying on 429)
        Step 4  →  Flatten member objects with role (Owner/Member/Guest)
        Step 5  →  Repeat for next channel/team (one failure does not abort the run)
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permissions.
        - Standard channels are excluded by design (membership = team
            membership; use Get-TeamMembers for that).
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: uses one static Bearer token
            for the entire run; no mid-run refresh. In very large tenants a
            run exceeding the token lifetime (~60-90 min) will fail with 401.
        - RECOMMENDED FOR: smaller tenants or scoped/filtered pulls.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants without
            adding a token-refresh pattern and/or parallelized calls. Teams
            with many private/shared channels will incur one extra API call
            per channel on top of the per-team channel listing call.

.LINK
    Microsoft Graph API - List channel members
    https://learn.microsoft.com/en-us/graph/api/channel-list-members

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamChannelMembers
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
        $allChannelMembers = New-Object System.Collections.ArrayList
        $totalMembers = 0

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

                # ── Step 1: Get non-standard channels for this team ──────────
                $channelsUri = "https://graph.microsoft.com/v1.0/teams/$id/channels?`$select=id,displayName,membershipType"
                $nonStandardChannels = New-Object System.Collections.ArrayList

                do
                {
                    $skip = $false
                    do
                    {
                        Try
                        {
                            $partialData = Invoke-WebRequest -Uri $channelsUri -Headers $headers -Method Get -ErrorAction Stop
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

                    if ($channelsData.PSObject.Properties['@odata.nextLink']) { $channelsUri = $channelsData.'@odata.nextLink' }

                    $channelsData.value | Where-Object { $_.membershipType -in @("private","shared") } | ForEach-Object {
                        $null = $nonStandardChannels.Add($_)
                    }

                } until ($skip -or (-not($channelsData.PSObject.Properties['@odata.nextLink'])))

                if ($skip) { Continue }

                if ($nonStandardChannels.Count -eq 0)
                {
                    Write-Host "Team '$teamDisplayName' [$id] has no Private or Shared channels (Standard-only). Nothing to report for this team." -ForegroundColor Yellow
                    Continue
                }

                # ── Step 2: Get members for each private/shared channel ──────
                foreach ($channel in $nonStandardChannels)
                {
                    $membersUri = "https://graph.microsoft.com/v1.0/teams/$id/channels/$($channel.id)/members?`$top=100"

                    do
                    {
                        $memberSkip = $false
                        do
                        {
                            Try
                            {
                                $memberPartial = Invoke-WebRequest -Uri $membersUri -Headers $headers -Method Get -ErrorAction Stop
                                $memberStatus = $memberPartial.StatusCode;
                            }
                            catch
                            {
                                $memberStatus = $_.Exception.Response.StatusCode;
                                $ErrorObject = $_

                                if($memberStatus -eq 429)
                                {
                                    $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                                    Write-host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                                    Start-sleep -Seconds $sleepTime
                                }
                                else
                                {
                                    $ErrorOutput = [PSCustomObject][ordered]@{
                                        TeamId      = $id
                                        ChannelId   = $channel.id
                                        Response    = $($ErrorObject.Exception.Response)
                                        StatusCode  = $($ErrorObject.Exception.Response.StatusCode)
                                        Message     = $($ErrorObject.Exception.Message)
                                    };
                                    $ErrorOutput | Format-List
                                    $memberSkip = $true;
                                }
                            }
                        } until(($memberStatus -eq 200) -or $memberSkip)

                        if ($memberSkip)
                        {
                            Write-Warning "Failed to retrieve members for channel '$($channel.displayName)' [$($channel.id)]. Skipping to next channel."
                            break
                        }

                        if($memberPartial)
                        {
                            $membersData = $memberPartial.content | ConvertFrom-Json
                        }

                        Write-Host ""
                        Write-Host "Progress: $($totalMembers += $membersData.value.Count; $totalMembers) channel member record(s) retrieved so far" -ForegroundColor Cyan

                        if ($membersData.PSObject.Properties['@odata.nextLink']) { $membersUri = $membersData.'@odata.nextLink' }

                        $membersData.value | ForEach-Object {
                            $roles = $_.roles
                            $role  = if ($roles -and $roles -contains "owner") { "Owner" } else { "Member" }

                            $null = $allChannelMembers.Add(
                                [PSCustomObject]@{
                                    teamId              = $id
                                    teamDisplayName     = $teamDisplayName
                                    channelId           = $channel.id
                                    channelDisplayName  = $channel.displayName
                                    channelType         = $channel.membershipType
                                    memberId            = $_.userId
                                    memberDisplayName   = $_.displayName
                                    memberEmail         = $_.email
                                    role                = $role
                                }
                            )
                        }

                    } until ($memberSkip -or (-not($membersData.PSObject.Properties['@odata.nextLink'])))
                }
            }
            Catch
            {
                Write-Warning "Failed to process channel members for team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        Write-Host ""
        Write-Host "Retrieved $($allChannelMembers.Count) private/shared channel member record(s) in total." -ForegroundColor Cyan

        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $allChannelMembers | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Channel members report exported successfully → $ExportPath" -ForegroundColor Green
        }

        # return $allChannelMembers | Select-Object teamId, teamDisplayName, channelId, channelDisplayName, channelType, memberId, memberDisplayName, memberEmail, role | FT
        return $allChannelMembers
    }
}
