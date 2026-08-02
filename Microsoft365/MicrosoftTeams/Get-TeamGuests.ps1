<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 02 August 2026
Modified-On     : 02 August 2026

.SYNOPSIS
    Retrieves guest users across all Microsoft Teams using Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph v1.0 endpoint for each team's underlying
    Microsoft 365 Group membership, filtered to userType eq 'Guest', so
    enterprise security teams can audit guest access across the Teams estate.

    Handles pagination via @odata.nextLink, retries on HTTP 429 throttling
    using Retry-After, and skips a failing team without aborting the run.
    Only accepts a direct Bearer token (BYOT); does not authenticate itself.
    Obtain a token via the companion Connect-EntraID.ps1 (see .LINK).

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission: GroupMember.Read.All (User.Read.All recommended for
    fully resolved guest profile fields)

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
    System.Array of guest records; also optionally exports to CSV.

.EXAMPLE
    Get-TeamGuests -AccessToken $token

    Retrieves guest members across every team in the tenant.

.EXAMPLE
    Get-TeamGuests -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamGuests.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (02-Aug-2026) - Initial release
                          - Fixed: HTTP 400 on the guest-member query - Graph's
                              advanced query capabilities require $count=true
                              in the query string (not just the
                              ConsistencyLevel:eventual header) when filtering
                              on userType. Also guarded against a Windows
                              PowerShell 5.1 issue where ConvertFrom-Json
                              unwraps a single-item JSON array into a bare
                              object with no .Count member.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with GroupMember.Read.All
        2. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve teams to evaluate (all, or supplied -TeamId) + names
        Step 2  →  For each team, GET /groups/{id}/members?$filter=userType eq 'Guest'
                    (paginated, ConsistencyLevel:eventual, retrying on 429)
        Step 3  →  Flatten guest objects (id, displayName, mail, UPN)
        Step 4  →  Repeat for next team (one failure does not abort the run)
        Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permission.
        - Reports guests present in the team's Microsoft 365 Group; guests
            added only at a Shared-channel level (not the parent group) are
            not covered here - use Get-TeamChannelMembers for that.
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
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamGuests
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
        $allGuests = New-Object System.Collections.ArrayList
        $totalGuests = 0

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

                $uri = "https://graph.microsoft.com/v1.0/groups/$id/members?`$filter=userType eq 'Guest'&`$select=id,displayName,mail,userPrincipalName&`$top=100&`$count=true"

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
                        Write-Warning "Failed to retrieve guest members for team '$id'. Skipping to next TeamId."
                        break
                    }

                    if($partialData)
                    {
                        $guestsData = $partialData.content | ConvertFrom-Json
                    }

                    if (@($guestsData.value).Count -gt 0)
                    {
                        Write-Host ""
                        Write-Host "Progress: $($totalGuests += @($guestsData.value).Count; $totalGuests) guest record(s) retrieved so far" -ForegroundColor Cyan
                    }

                    if ($guestsData.PSObject.Properties['@odata.nextLink']) { $uri = $guestsData.'@odata.nextLink' }

                    $guestsData.value | ForEach-Object {
                        $null = $allGuests.Add(
                            [PSCustomObject]@{
                                teamId                = $id
                                teamDisplayName       = $teamDisplayName
                                guestId               = $_.id
                                guestDisplayName      = $_.displayName
                                guestMail             = $_.mail
                                guestUserPrincipalName = $_.userPrincipalName
                            }
                        )
                    }

                } until (-not($guestsData.PSObject.Properties['@odata.nextLink']))
            }
            Catch
            {
                Write-Warning "Failed to retrieve guest members for team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        Write-Host ""
        Write-Host "Found $($allGuests.Count) guest membership record(s) across the evaluated teams." -ForegroundColor Cyan

        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $allGuests | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Team guests report exported successfully → $ExportPath" -ForegroundColor Green
        }

        # return $allGuests | Select-Object teamId, teamDisplayName, guestId, guestDisplayName, guestMail, guestUserPrincipalName | FT
        return $allGuests
    }
}
