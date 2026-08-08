<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 02 August 2026
Modified-On     : 02 August 2026

.SYNOPSIS
    Retrieves Microsoft Teams settings (guest access, member permissions,
    messaging options) using Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph v1.0 /teams/{id} endpoint for each team in
    scope and flattens its guestSettings, memberSettings, and
    messagingSettings so the configuration can be validated against a
    governance baseline (see Test-TeamGovernanceCompliance for a scored
    version of a subset of these checks).

    Handles pagination via @odata.nextLink for team resolution, retries on
    HTTP 429 throttling using Retry-After, and skips a failing team without
    aborting the run. Only accepts a direct Bearer token (BYOT); does not
    authenticate itself. Obtain a token via the companion Connect-EntraID.ps1
    (see .LINK).

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission: TeamSettings.Read.All (Team.ReadBasic.All also works
    for the basic properties, but TeamSettings.Read.All covers all fields
    returned here)

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
    System.Array of team-settings records; also optionally exports to CSV.

.EXAMPLE
    Get-TeamSettings -AccessToken $token

    Retrieves settings for every team in the tenant.

.EXAMPLE
    Get-TeamSettings -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamSettings.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (02-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with TeamSettings.Read.All
        2. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve teams to evaluate (all, or supplied -TeamId) + names
        Step 2  →  For each team, GET /teams/{id} (single object, retrying on 429)
        Step 3  →  Flatten guestSettings/memberSettings/messagingSettings
        Step 4  →  Repeat for next team (one failure does not abort the run)
        Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permission.
        - funSettings and discoverySettings are not included; add them if
            your governance baseline requires evaluating GIFs/stickers/memes
            or team discoverability.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: uses one static Bearer token
            for the entire run; no mid-run refresh. In very large tenants a
            run exceeding the token lifetime (~60-90 min) will fail with 401.
        - RECOMMENDED FOR: smaller tenants or scoped/filtered pulls.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants without
            adding a token-refresh pattern and/or parallelized calls.

.LINK
    Microsoft Graph API - Get team
    https://learn.microsoft.com/en-us/graph/api/team-get

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamSettings
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
        $allSettings = New-Object System.Collections.ArrayList

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

                $uri = "https://graph.microsoft.com/v1.0/teams/$id"

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
                    Write-Warning "Failed to retrieve settings for team '$id'. Skipping to next TeamId."
                    Continue
                }

                $teamData = $partialData.content | ConvertFrom-Json

                $null = $allSettings.Add(
                    [PSCustomObject]@{
                        teamId                              = $id
                        teamDisplayName                     = $teamDisplayName
                        visibility                          = $teamData.visibility
                        isArchived                          = $teamData.isArchived
                        allowGuestCreateUpdateChannels       = $teamData.guestSettings.allowCreateUpdateChannels
                        allowGuestDeleteChannels             = $teamData.guestSettings.allowDeleteChannels
                        allowMemberCreateUpdateChannels      = $teamData.memberSettings.allowCreateUpdateChannels
                        allowMemberDeleteChannels            = $teamData.memberSettings.allowDeleteChannels
                        allowMemberCreatePrivateChannels     = $teamData.memberSettings.allowCreatePrivateChannels
                        allowMemberAddRemoveApps             = $teamData.memberSettings.allowAddRemoveApps
                        allowMemberCreateUpdateRemoveTabs    = $teamData.memberSettings.allowCreateUpdateRemoveTabs
                        allowMemberCreateUpdateRemoveConnectors = $teamData.memberSettings.allowCreateUpdateRemoveConnectors
                        allowUserEditMessages                = $teamData.messagingSettings.allowUserEditMessages
                        allowUserDeleteMessages               = $teamData.messagingSettings.allowUserDeleteMessages
                        allowOwnerDeleteMessages              = $teamData.messagingSettings.allowOwnerDeleteMessages
                        allowTeamMentions                     = $teamData.messagingSettings.allowTeamMentions
                        allowChannelMentions                  = $teamData.messagingSettings.allowChannelMentions
                    }
                )

                Write-Verbose "Retrieved settings for team '$teamDisplayName' [$id]"
            }
            Catch
            {
                Write-Warning "Failed to retrieve settings for team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        Write-Host ""
        Write-Host "Retrieved settings for $($allSettings.Count) team(s)." -ForegroundColor Cyan

        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $allSettings | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Team settings report exported successfully → $ExportPath" -ForegroundColor Green
        }

        return $allSettings
    }
}
