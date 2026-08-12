<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 12 August 2026
Modified-On     : 12 August 2026

.SYNOPSIS
    Lists Microsoft Teams tags and their tagged members using Microsoft
    Graph API.

.DESCRIPTION
    Queries the Microsoft Graph v1.0 endpoint to retrieve every tag defined
    on each team in scope (GET /teams/{id}/tags), then resolves the members
    carrying each tag (GET /teams/{id}/tags/{tagId}/members). This is the
    inventory used to document notification groups and operational teams
    (e.g. "On-Call", "Shift-Lead") built with Teams tags, which are
    otherwise invisible outside the Teams client.

    Retries on HTTP 429 throttling using Retry-After, and skips a failing
    team/tag without aborting the run. Only accepts a direct Bearer token
    (BYOT); does not authenticate itself. Obtain a token via the companion
    Connect-EntraID.ps1 (see .LINK).

    The following attributes are collected:
        - Tag: id, displayName, description, memberCount, tagType
        - Tagged member: userId, tenantId, displayName

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        TeamworkTag.Read.All

.PARAMETER TeamId
    Optional. GUID(s) of the Microsoft Team. Accepts an array or pipeline
    input by value/property name (e.g. from Get-MicrosoftTeams). If
    omitted, every team in the tenant is evaluated.

.PARAMETER IncludeMembers
    Switch. When specified, also resolves and returns the members tagged
    under each tag (one output row per tagged member). When omitted, the
    function returns one row per tag with memberCount only, which is
    considerably faster for a large tenant.

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
        An array of custom objects containing tag (and optionally tagged
        member) attributes per team. Also optionally exports to CSV.

.EXAMPLE
    Get-TeamTags -AccessToken $token

    Lists every tag, per team, across the tenant (one row per tag).

.EXAMPLE
    Get-TeamTags -AccessToken $token -IncludeMembers

    Lists every tag together with its tagged members (one row per member).

.EXAMPLE
    Get-TeamTags -AccessToken $token -IncludeMembers -ExportFormat CSV -ExportPath "C:\Reports\TeamTags.csv"

.EXAMPLE
    Get-MicrosoftTeams -AccessToken $token | Get-TeamTags -AccessToken $token -IncludeMembers

    Scopes the report to a specific set of teams.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (12-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with TeamworkTag.Read.All
        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve teams to evaluate (all, or supplied -TeamId) + names
        Step 2  →  For each team, GET /teams/{id}/tags (retrying on HTTP 429)
        Step 3  →  If -IncludeMembers, for each tag GET /teams/{id}/tags/{tagId}/members
        Step 4  →  Flatten tag (and member) objects
        Step 5  →  Repeat for next team (one failure does not abort the run)
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permission.
        - The tags and tag-members endpoints used here do not support $top and
            are called as a single page per team/tag; this is consistent with
            observed Graph behaviour for these endpoints and not a pagination gap.
        - Built-in tags (e.g. tagType "builtIn" for org-wide/role tags where
            applicable) are returned alongside standard tags; tagType is
            included in the output so these can be filtered separately.
        - Without -IncludeMembers, member identities are not resolved — only
            memberCount is returned — to avoid an N+1 call pattern when the
            caller only needs an inventory, not a full membership audit.
        - SINGLE-TOKEN, SEQUENTIAL RUN: this function uses one static Bearer
            token for the entire run and does not refresh it mid-run. In very
            large tenants, if the full pull (teams × tags × members) takes
            longer than the token's lifetime (typically ~60-90 minutes), the run
            will fail partway through with 401 Unauthorized once the token
            expires.
        - RECOMMENDED FOR: smaller/medium tenants, or scoped pulls via -TeamId.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants running with
            -IncludeMembers without a token-refresh pattern and/or parallelized
            calls.

.LINK
    Microsoft Graph API - List teamworkTags
    https://learn.microsoft.com/en-us/graph/api/team-list-tags

.LINK
    Microsoft Graph API - List taggedUsers (tag members)
    https://learn.microsoft.com/en-us/graph/api/teamworktag-list-members

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamTags {
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("id")]
        [string[]]$TeamId,

        [switch]$IncludeMembers,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    Begin {
        $allTags = New-Object System.Collections.ArrayList
        $totalTags = 0

        if (-not $AccessToken) {
            Write-Error "AccessToken is required. Exiting function."
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

                $tagsUri = "https://graph.microsoft.com/v1.0/teams/$tid/tags"

                $skip = $false
                do {
                    Try {
                        $partialData = Invoke-WebRequest -Uri $tagsUri -Headers $headers -Method Get -ErrorAction Stop
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
                    Write-Warning "Failed to retrieve tags for team '$tid'. Skipping to next team."
                    continue
                }

                $tagsData = $partialData.Content | ConvertFrom-Json

                Write-Host ""
                Write-Host "Progress: $($totalTags += $tagsData.value.Count; $totalTags) tag(s) retrieved so far" -ForegroundColor Cyan

                foreach ($tag in $tagsData.value) {
                    $memberRows = New-Object System.Collections.ArrayList

                    if ($IncludeMembers) {
                        $membersUri = "https://graph.microsoft.com/v1.0/teams/$tid/tags/$($tag.id)/members"

                        $memberSkip = $false
                        do {
                            Try {
                                $memberPartial = Invoke-WebRequest -Uri $membersUri -Headers $headers -Method Get -ErrorAction Stop
                                $memberStatus = $memberPartial.StatusCode
                            }
                            catch {
                                $memberStatus = $_.Exception.Response.StatusCode
                                if ($memberStatus -eq 429) {
                                    $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                                    Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                                    Start-Sleep -Seconds $sleepTime
                                }
                                else {
                                    Write-Warning "Failed to retrieve members for tag '$($tag.id)' in team '$tid': $($_.Exception.Message)."
                                    $memberSkip = $true
                                }
                            }
                        } until(($memberStatus -eq 200) -or $memberSkip)

                        if (-not $memberSkip) {
                            $membersData = $memberPartial.Content | ConvertFrom-Json
                            $membersData.value | ForEach-Object { $null = $memberRows.Add($_) }
                        }
                    }

                    if ($IncludeMembers -and $memberRows.Count -gt 0) {
                        foreach ($member in $memberRows) {
                            $null = $allTags.Add(
                                [PSCustomObject]@{
                                    teamId            = $tid
                                    teamDisplayName   = $teamDisplayName
                                    tagId             = $tag.id
                                    tagDisplayName    = $tag.displayName
                                    tagDescription    = $tag.description
                                    tagType           = $tag.tagType
                                    memberCount       = $tag.memberCount
                                    memberUserId      = $member.userId
                                    memberDisplayName = $member.displayName
                                    memberTenantId    = $member.tenantId
                                }
                            )
                        }
                    }
                    else {
                        $null = $allTags.Add(
                            [PSCustomObject]@{
                                teamId            = $tid
                                teamDisplayName   = $teamDisplayName
                                tagId             = $tag.id
                                tagDisplayName    = $tag.displayName
                                tagDescription    = $tag.description
                                tagType           = $tag.tagType
                                memberCount       = $tag.memberCount
                                memberUserId      = $null
                                memberDisplayName = $null
                                memberTenantId    = $null
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

            $allTags | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Team tags report exported successfully → $ExportPath" -ForegroundColor Green
        }

        return $allTags
    }
}
