<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Retrieves owners of one or more Microsoft Teams using Microsoft Graph API,
    for accountability and governance.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 endpoint to retrieve the
    owner(s) of each Microsoft Team supplied via -TeamId, directly, as an
    array, or via the pipeline (e.g. from Get-Teams).

    It handles pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing it further. One TeamId's failure does not
    stop processing of the remaining TeamIds.

    Results can optionally be exported to CSV. Helps identify who is
    responsible for team content and membership.

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

    The following owner attributes are collected:
        - teamId, teamDisplayName, ownerId, ownerDisplayName, ownerUserPrincipalName

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
    If omitted entirely (no value and no pipeline input), the function
    automatically resolves and processes every team in the tenant.

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
        An array of custom objects containing owner attributes for each
        supplied team. Also optionally exports to CSV.

.EXAMPLE
    Get-TeamOwners -AccessToken $token

    TeamId omitted: automatically resolves and retrieves owners for every team in the tenant.

.EXAMPLE
    Get-TeamOwners -AccessToken $token -TeamId "11111111-1111-1111-1111-111111111111"

    Retrieves owners for a single team.

.EXAMPLE
    (Get-Teams -AccessToken $token) | Get-TeamOwners -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamOwners.csv"

    Chains from Get-Teams to retrieve owners for every team in the tenant and exports to CSV.

.EXAMPLE
    $token = Get-AccessToken
    Get-TeamOwners -AccessToken $token -TeamId $teamId1, $teamId2

    Demonstrates usage with a dynamically generated access token and multiple TeamIds.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Aug-2026)  - Initial release (Microsoft.Graph SDK based)
                            - Added teamDisplayName to output/CSV via a
                              teamId -> displayName lookup resolved once per run.
                            - Fixed: $skip variable was unset on a successful
                              (200) response, causing "cannot be retrieved
                              because it has not been set" after every
                              successful page. Now reset explicitly per attempt.
                            - TeamId is now optional; when omitted, all teams
                              in the tenant are resolved and processed
                              automatically.
                            - Export-Csv now creates the destination folder
                              if it does not already exist.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permission:
                Group.Read.All (Application or Delegated)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  For each TeamId, build the /v1.0/groups/{id}/owners request URI
        Step 2  →  Call Microsoft Graph, retrying on HTTP 429 using Retry-After
        Step 3  →  Parse the JSON response into custom owner objects
        Step 4  →  Follow @odata.nextLink until pagination is exhausted for that team
        Step 5  →  Repeat for the next TeamId (one failure does not abort the run)
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permission.
        - Owner userPrincipalName could not be confirmed for guest or non-user
            directory objects returned as owners (e.g. service principals);
            these rows show a blank/null value as returned by Graph.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer
            token for the entire run and does not refresh it mid-run. In very
            large tenants, if the full pull takes longer than the token's
            lifetime (typically ~60-90 minutes), the run will fail partway through
            with 401 Unauthorized once the token expires.
        - RECOMMENDED FOR: smaller tenants, scoped/filtered pulls, or quick
            one-off/ad-hoc workarounds.
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


Function Get-TeamOwners
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
        # Define an empty array to hold all owner records across all teams
        $allOwners = New-Object System.Collections.ArrayList
        $totalOwners = 0

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
        # call) so every output row can include a human-readable team name,
        # regardless of whether -TeamId was supplied explicitly.
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
            Write-Verbose "Resolved $($TeamId.Count) team(s) to process."
        }
    }

    Process
    {
        foreach ($id in $TeamId)
        {
            Try
            {
                # Define the initial URI to retrieve owners for this team
                $uri = "https://graph.microsoft.com/v1.0/groups/$id/owners?`$select=id,displayName,userPrincipalName&`$top=100"

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
                            # Invoke the Graph API to retrieve owners
                            $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                            $statusCode = $partialData.StatusCode;
                        }
                        catch
                        {
                            # If an exception occurs, handle different types of errors
                            $statusCode = $_.Exception.Response.StatusCode;
                            $ErrorObject = $_

                            # Check if the error is due to throttling (status code 429)
                            if($statusCode -eq 429)
                            {
                                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                                Write-host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                                Start-sleep -Seconds $sleepTime
                            }
                            else
                            {
                                # If it's not throttling, format and display the error message
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

                    # If throttling/error skip was set, abandon this team and move to the next one
                    if ($skip)
                    {
                        Write-Warning "Failed to retrieve owners for team '$id'. Skipping to next TeamId."
                        break
                    }

                    # If partial data is retrieved successfully
                    if($partialData)
                    {
                        $ownersData = $partialData.content | ConvertFrom-Json
                    }

                    Write-Host ""
                    Write-Host "Progress: $($totalOwners += $ownersData.value.Count; $totalOwners) owner records retrieved so far" -ForegroundColor Cyan

                    # Check if there are more pages of data to retrieve
                    if ($ownersData.PSObject.Properties['@odata.nextLink']) { $uri = $ownersData.'@odata.nextLink' }

                    if (-not $ownersData.value -or $ownersData.value.Count -eq 0)
                    {
                        Write-Warning "Team '$id' has no owners on record."
                    }

                    # Flatten owner objects
                    $ownersData.value | ForEach-Object {

                        $null = $allOwners.Add(
                            [PSCustomObject]@{

                                teamId                 = $id
                                teamDisplayName        = if ($teamNameMap.ContainsKey($id)) { $teamNameMap[$id] } else { "Could not be confirmed" }
                                ownerId                = $_.id
                                ownerDisplayName       = $_.displayName
                                ownerUserPrincipalName = $_.userPrincipalName
                            }
                        )
                    }

                } until (-not($ownersData.PSObject.Properties['@odata.nextLink']))
            }
            Catch
            {
                Write-Warning "Failed to retrieve owners for team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        # CSV EXPORT SUPPORT (added only)
        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $allOwners | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Team owners report exported successfully → $ExportPath" -ForegroundColor Green
        }

        # Return the array list containing all owner records
        # return $allOwners | Select-Object teamId, teamDisplayName, ownerId, ownerDisplayName, ownerUserPrincipalName | FT
        return $allOwners
    }
}
