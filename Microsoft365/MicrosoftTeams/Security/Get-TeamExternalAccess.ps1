<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 02 August 2026
Modified-On     : 02 August 2026

.SYNOPSIS
    Reports Microsoft Teams configured for external collaboration using
    Microsoft Graph API.

.DESCRIPTION
    True tenant-wide external/federation access (who your organization can
    communicate with externally) is an org-level Teams admin center setting,
    not something exposed per-team via Graph. This function instead reports
    the two per-team signals that actually indicate a given team is open to
    external collaboration:
        1. Guest members present in the team's Microsoft 365 Group
           (userType eq 'Guest')
        2. Shared channels on the team (membershipType eq 'shared'), which by
           design can include members from other tenants

    Each team is scored: teams with BOTH signals present are the highest
    exposure (ExternalAccessRisk = High); teams with only one signal are
    Medium; teams with neither are None.

    Handles pagination via @odata.nextLink, retries on HTTP 429 throttling
    using Retry-After, and skips a failing team without aborting the run.
    Only accepts a direct Bearer token (BYOT); does not authenticate itself.
    Obtain a token via the companion Connect-EntraID.ps1 (see .LINK).

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions: GroupMember.Read.All, Channel.ReadBasic.All

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
    System.Array of external-access records; also optionally exports to CSV.

.EXAMPLE
    Get-TeamExternalAccess -AccessToken $token

    Evaluates external-access exposure for every team in the tenant.

.EXAMPLE
    Get-TeamExternalAccess -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamExternalAccess.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (02-Aug-2026) - Initial release
                          - Fixed: HTTP 400 on the guest-member query - Graph's
                              advanced query capabilities require $count=true
                              in the query string (not just the
                              ConsistencyLevel:eventual header) when filtering
                              on userType. Also fixed a Windows PowerShell 5.1
                              issue where ConvertFrom-Json unwraps a single-item
                              JSON array into a bare object (no .Count member),
                              causing "The property 'Count' cannot be found on
                              this object" - all affected .Count usages are now
                              wrapped in @() to force array semantics.
                          - Fixed: the /teams/{id}/channels endpoint does not
                              support the $top query option and returned
                              HTTP 400 Bad Request. Removed $top; the endpoint
                              returns the full channel list in one response.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with GroupMember.Read.All
            and Channel.ReadBasic.All
        2. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve teams to evaluate (all, or supplied -TeamId) + names
        Step 2  →  For each team, GET /groups/{id}/members?$filter=userType eq 'Guest'
                    to count guest members (paginated, retrying on 429)
        Step 3  →  For each team, GET /teams/{id}/channels and count channels
                    with membershipType eq 'shared' (paginated, retrying on 429)
        Step 4  →  Score ExternalAccessRisk from the two signals combined
        Step 5  →  Repeat for next team (one failure does not abort the run)
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permissions.
        - Does not evaluate tenant-wide federation/external-access allow-lists
            (Skype/Teams admin center → External access); that is an org-level
            setting outside the scope of a per-team Graph report.
        - For shared channels, this reports the channel count only; whether
            individual channel members belong to another tenant could not be
            confirmed reliably from the channel-members endpoint used by
            Get-TeamChannelMembers and is not attempted here to avoid a
            false sense of precision. Use Get-TeamChannelMembers for a full
            member-level roster of shared channels if needed.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: uses one static Bearer token
            for the entire run; no mid-run refresh. In very large tenants a
            run exceeding the token lifetime (~60-90 min) will fail with 401.
        - RECOMMENDED FOR: smaller tenants or scoped/filtered pulls.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants without
            adding a token-refresh pattern and/or parallelized calls.

.LINK
    Microsoft Graph API - List group members
    https://learn.microsoft.com/en-us/graph/api/group-list-members

.LINK
    Microsoft Graph API - List channels
    https://learn.microsoft.com/en-us/graph/api/team-list-channels

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamExternalAccess
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
        $allResults = New-Object System.Collections.ArrayList

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

        $teamMetaMap = @{}
        $allTeamIds  = New-Object System.Collections.ArrayList
        $teamsUri    = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName,visibility&`$count=true"

        Write-Verbose "Resolving team metadata..."
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
                        Write-Warning "Failed to resolve team metadata: $($_.Exception.Message)."
                        $teamsSkip = $true
                    }
                }
            } until(($teamsStatus -eq 200) -or $teamsSkip)

            if ($teamsSkip) { break }

            $teamsData = $teamsPartial.Content | ConvertFrom-Json
            $teamsData.value | ForEach-Object {
                $teamMetaMap[$_.id] = [PSCustomObject]@{ DisplayName = $_.displayName; Visibility = $_.visibility }
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
                $meta = $teamMetaMap[$id]
                $teamDisplayName = if ($meta) { $meta.DisplayName } else { "Could not be confirmed" }
                $visibility      = if ($meta) { $meta.Visibility }  else { "Could not be confirmed" }

                # ── Signal 1: guest member count ─────────────────────────────
                $guestUri = "https://graph.microsoft.com/v1.0/groups/$id/members?`$filter=userType eq 'Guest'&`$select=id&`$top=100&`$count=true"
                $guestCount = 0
                $guestFailed = $false

                do
                {
                    $skip = $false
                    do
                    {
                        Try
                        {
                            $partialData = Invoke-WebRequest -Uri $guestUri -Headers $headers -Method Get -ErrorAction Stop
                            $statusCode = $partialData.StatusCode;
                        }
                        catch
                        {
                            $statusCode = $_.Exception.Response.StatusCode;
                            if($statusCode -eq 429)
                            {
                                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                                Write-host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                                Start-sleep -Seconds $sleepTime
                            }
                            else
                            {
                                Write-Warning "Failed to retrieve guest members for team '$id': $($_.Exception.Message)"
                                $skip = $true
                            }
                        }
                    } until(($statusCode -eq 200) -or $skip)

                    if ($skip) { $guestFailed = $true; break }

                    if($partialData) { $guestsData = $partialData.content | ConvertFrom-Json }
                    $guestCount += @($guestsData.value).Count
                    if ($guestsData.PSObject.Properties['@odata.nextLink']) { $guestUri = $guestsData.'@odata.nextLink' }

                } until ($skip -or (-not($guestsData.PSObject.Properties['@odata.nextLink'])))

                # ── Signal 2: shared-channel count ───────────────────────────
                $channelUri = "https://graph.microsoft.com/v1.0/teams/$id/channels?`$select=id,membershipType"
                $sharedChannelCount = 0
                $channelFailed = $false

                do
                {
                    $skip = $false
                    do
                    {
                        Try
                        {
                            $partialData = Invoke-WebRequest -Uri $channelUri -Headers $headers -Method Get -ErrorAction Stop
                            $statusCode = $partialData.StatusCode;
                        }
                        catch
                        {
                            $statusCode = $_.Exception.Response.StatusCode;
                            if($statusCode -eq 429)
                            {
                                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                                Write-host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                                Start-sleep -Seconds $sleepTime
                            }
                            else
                            {
                                Write-Warning "Failed to retrieve channels for team '$id': $($_.Exception.Message)"
                                $skip = $true
                            }
                        }
                    } until(($statusCode -eq 200) -or $skip)

                    if ($skip) { $channelFailed = $true; break }

                    if($partialData) { $channelsData = $partialData.content | ConvertFrom-Json }
                    $sharedChannelCount += @($channelsData.value | Where-Object { $_.membershipType -eq "shared" }).Count
                    if ($channelsData.PSObject.Properties['@odata.nextLink']) { $channelUri = $channelsData.'@odata.nextLink' }

                } until ($skip -or (-not($channelsData.PSObject.Properties['@odata.nextLink'])))

                # ── Score ─────────────────────────────────────────────────────
                $hasGuests  = (-not $guestFailed) -and ($guestCount -gt 0)
                $hasShared  = (-not $channelFailed) -and ($sharedChannelCount -gt 0)

                $risk = if ($guestFailed -or $channelFailed) { "Unknown" }
                        elseif ($hasGuests -and $hasShared)   { "High" }
                        elseif ($hasGuests -or $hasShared)     { "Medium" }
                        else                                    { "None" }

                $null = $allResults.Add([PSCustomObject]@{
                    teamId               = $id
                    teamDisplayName      = $teamDisplayName
                    visibility           = $visibility
                    guestMemberCount     = if ($guestFailed) { "Could not be confirmed" } else { $guestCount }
                    sharedChannelCount   = if ($channelFailed) { "Could not be confirmed" } else { $sharedChannelCount }
                    hasGuestMembers      = $hasGuests
                    hasSharedChannels    = $hasShared
                    externalAccessRisk   = $risk
                })
            }
            Catch
            {
                Write-Warning "Failed to evaluate external access for team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        $highRiskCount = @($allResults | Where-Object { $_.externalAccessRisk -eq "High" }).Count
        Write-Host ""
        Write-Host "Evaluated $($allResults.Count) team(s); $highRiskCount flagged as High external-access risk." -ForegroundColor Cyan

        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $allResults | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Team external-access report exported successfully → $ExportPath" -ForegroundColor Green
        }

        # return $allResults | Select-Object teamId, teamDisplayName, visibility, guestMemberCount, sharedChannelCount, hasGuestMembers, hasSharedChannels, externalAccessRisk | FT
        return $allResults
    }
}
