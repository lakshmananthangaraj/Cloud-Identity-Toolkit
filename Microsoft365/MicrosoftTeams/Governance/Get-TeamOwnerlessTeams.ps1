<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Finds Microsoft Teams that have no owner or only a single owner.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 endpoint to evaluate the
    owner count of every team in scope and flags teams that are at
    governance risk:
        - 0 owners  → Critical  (the team is effectively unmanaged; no one
                                   can approve membership, settings, or
                                   lifecycle changes)
        - 1 owner   → Warning   (single point of failure; if that owner
                                   leaves or loses access, the team becomes
                                   ownerless with no warning)

    Teams with 2 or more owners are considered healthy and are not included
    in the output. Results are returned as an array of at-risk teams and can
    optionally be exported to CSV.

    It handles pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing it further. One team's failure does not
    stop processing of the remaining teams.

    SCOPE & SUITABILITY:
    This function is designed for smaller tenants or quick ad-hoc pulls where
    a single Bearer token comfortably outlives the full pagination run. It
    does not implement token refresh mid-run. For large/enterprise-scale
    tenants, see Known Limitations below before relying on this function as-is.

    This function only accepts a direct Bearer token (AccessToken). It does
    not perform authentication itself. If you need to obtain a token via
    app-only (client credentials) authentication, use the companion
    Connect-EntraID.ps1 script referenced under .LINK below, then pass its
    returned token into -AccessToken.

    The following attributes are collected:
        - teamId, teamDisplayName, ownerCount, riskLevel, recommendation

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Group.Read.All

    To obtain this token via app-only authentication instead of an interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER TeamId
    Optional. The Id (GUID) of the Microsoft Team / Microsoft 365 Group.
    Accepts an array, or pipeline input by value or by property name (e.g.
    from Get-Teams output, whose 'id' property maps onto this parameter).
    If omitted entirely (no value and no pipeline input), every team in the
    tenant is evaluated.

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.INPUTS
    String (TeamId), or objects with an id/TeamId property (e.g. Get-Teams output).

.OUTPUTS
    System.Array
        An array of custom objects, one per at-risk team (0 or 1 owners).
        Also optionally exports to CSV.

.EXAMPLE
    Get-TeamOwnerlessTeams -AccessToken $token

    Evaluates every team in the tenant and returns those with 0 or 1 owners.

.EXAMPLE
    Get-TeamOwnerlessTeams -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\OwnerlessTeams.csv"

    Same as above, exporting the results to CSV.

.EXAMPLE
    Get-Teams -AccessToken $token | Get-TeamOwnerlessTeams -AccessToken $token

    Chains from Get-Teams to scope the check to a specific set of teams.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permission:
                Group.Read.All (Application or Delegated)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve the set of teams to evaluate (all teams, or the
                    supplied -TeamId values) and their display names
        Step 2  →  For each team, retrieve its owners via /groups/{id}/owners
                    (paginated, retrying on HTTP 429)
        Step 3  →  Classify: 0 owners = Critical, 1 owner = Warning,
                    2+ owners = healthy (excluded from output)
        Step 4  →  Repeat for the next team (one failure does not abort the run)
        Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permission.
        - Does not distinguish an owner who is a disabled/soft-deleted
            directory object from an active one; an owner record that exists
            in Graph is counted even if that account could not be confirmed
            as currently usable.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static
            Bearer token for the entire run and does not refresh it mid-run.
            In very large tenants, if the full pull takes longer than the
            token's lifetime (typically ~60-90 minutes), the run will fail
            partway through with 401 Unauthorized once the token expires.
        - RECOMMENDED FOR: smaller tenants, scoped/filtered pulls, or quick
            one-off/ad-hoc governance sweeps.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants. For those,
            implement a proper token-refresh pattern (re-acquire via app-only
            client-credentials auth on a timer or before each page/batch) and
            consider parallelized/batched Graph calls instead of this single-
            threaded sequential loop.

.LINK
    Microsoft Graph API - List group owners
    https://learn.microsoft.com/en-us/graph/api/group-list-owners

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamOwnerlessTeams
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
        # Define an empty array to hold all at-risk team records
        $atRiskTeams = New-Object System.Collections.ArrayList
        $totalEvaluated = 0

        # Check if access token is obtained successfully
        if (-not $AccessToken)
        {
            Write-Error "AccessToken is required. Exiting function."
            return
        }

        # Define the request headers with the access token
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "ConsistencyLevel" = "eventual"
        }

        # Always resolve a teamId -> displayName lookup map (single paginated
        # call) so every output row can include a human-readable team name.
        # If -TeamId was not supplied on the command line and no pipeline
        # input is expected, also use this pass to resolve every team in the
        # tenant automatically so TeamId behaves as optional.
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
                        Write-Warning "Failed to resolve team display names: $($_.Exception.Message). TeamDisplayName will show 'Could not be confirmed'."
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
            Write-Verbose "Resolved $($TeamId.Count) team(s) to evaluate."
        }
    }

    Process
    {
        foreach ($id in $TeamId)
        {
            Try
            {
                $totalEvaluated++
                $teamDisplayName = if ($teamNameMap.ContainsKey($id)) { $teamNameMap[$id] } else { "Could not be confirmed" }

                # Define the initial URI to retrieve owners for this team
                $uri = "https://graph.microsoft.com/v1.0/groups/$id/owners?`$select=id&`$top=100"
                $ownerCount = 0

                # Start a do-while loop to handle pagination for this team
                do
                {
                    # Reset the skip flag at the start of every page/attempt so a
                    # successful (200) response never leaves it unset
                    $skip = $false

                    # Start a nested do-while loop to handle Graph API throttling and errors
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
                        Write-Warning "Failed to retrieve owners for team '$id'. Skipping to next TeamId."
                        break
                    }

                    if($partialData)
                    {
                        $ownersData = $partialData.content | ConvertFrom-Json
                    }

                    $ownerCount += $ownersData.value.Count

                    if ($ownersData.PSObject.Properties['@odata.nextLink']) { $uri = $ownersData.'@odata.nextLink' }

                } until (-not($ownersData.PSObject.Properties['@odata.nextLink']))

                if ($skip) { Continue }

                Write-Verbose "Team '$teamDisplayName' [$id] - owner count: $ownerCount"

                if ($ownerCount -eq 0)
                {
                    $null = $atRiskTeams.Add([PSCustomObject]@{
                        teamId          = $id
                        teamDisplayName = $teamDisplayName
                        ownerCount      = $ownerCount
                        riskLevel       = "Critical"
                        recommendation  = "Assign at least one owner immediately - this team has no owner and cannot be governed."
                    })
                }
                elseif ($ownerCount -eq 1)
                {
                    $null = $atRiskTeams.Add([PSCustomObject]@{
                        teamId          = $id
                        teamDisplayName = $teamDisplayName
                        ownerCount      = $ownerCount
                        riskLevel       = "Warning"
                        recommendation  = "Assign a second owner - a single owner is a single point of failure for this team."
                    })
                }
            }
            Catch
            {
                Write-Warning "Failed to evaluate team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        Write-Host ""
        Write-Host "Evaluated $totalEvaluated team(s); found $($atRiskTeams.Count) at-risk team(s)." -ForegroundColor Cyan

        # CSV EXPORT SUPPORT (added only)
        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $atRiskTeams | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Ownerless/under-owned teams report exported successfully → $ExportPath" -ForegroundColor Green
        }

        # Return the array list containing all at-risk teams
        # return $atRiskTeams | Select-Object teamId, teamDisplayName, ownerCount, riskLevel, recommendation | FT
        return $atRiskTeams
    }
}
