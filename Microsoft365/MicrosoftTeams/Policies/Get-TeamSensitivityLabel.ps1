<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 08 August 2026
Modified-On     : 08 August 2026

.SYNOPSIS
    Retrieves sensitivity labels assigned to Microsoft Teams in the tenant using
    Microsoft Graph API.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 endpoint to retrieve all
    Microsoft 365 Groups provisioned as a Microsoft Team and reports the
    sensitivity label (assignedLabels) applied to each Team.

    It handles pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing it further. One TeamId's failure does not
    stop processing of the remaining TeamIds.

    Results can optionally be exported to CSV. Useful for validating information
    protection implementation across the tenant and identifying Teams that are
    missing a sensitivity label (unlabelled Teams are flagged in the output).

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

    The following attributes are collected per team:
        - teamId, teamDisplayName, labelId, labelDisplayName, labelStatus

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Group.Read.All
        InformationProtectionPolicy.Read.All

    To obtain this token via app-only authentication instead of an interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER TeamId
    Optional. The Id (GUID) of the Microsoft Team. Accepts an array, or
    pipeline input by value or by property name (e.g. from Get-MicrosoftTeams output,
    whose 'id' property maps onto this parameter). If omitted entirely (no
    value and no pipeline input), the function automatically resolves and
    processes every team in the tenant.

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.INPUTS
    String (TeamId), or objects with an id/TeamId property (e.g. Get-MicrosoftTeams output).

.OUTPUTS
    System.Array
        An array of custom objects containing sensitivity label attributes for
        each supplied team. Also optionally exports to CSV.

.EXAMPLE
    Get-TeamSensitivityLabel -AccessToken $token

    TeamId omitted: automatically resolves and retrieves sensitivity labels for every team in the tenant.

.EXAMPLE
    Get-TeamSensitivityLabel -AccessToken $token -TeamId "11111111-1111-1111-1111-111111111111"

    Retrieves the sensitivity label for a single team.

.EXAMPLE
    (Get-MicrosoftTeams -AccessToken $token) | Get-TeamSensitivityLabel -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamSensitivityLabels.csv"

    Chains from Get-MicrosoftTeams to audit sensitivity labels across every team in the tenant and exports to CSV.

.EXAMPLE
    $token = Get-AccessToken
    Get-TeamSensitivityLabel -AccessToken $token -TeamId $teamId1, $teamId2

    Demonstrates usage with a dynamically generated access token and multiple TeamIds.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (08-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                Group.Read.All (Application or Delegated)
                InformationProtectionPolicy.Read.All (Application or Delegated)

        2. Sensitivity labels must be configured in Microsoft Purview and
           published to the tenant before assignedLabels will be populated
           on groups.

        3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve a teamId -> displayName lookup map via a single
                   paginated GET /groups call (also resolves full tenant scope
                   when TeamId is omitted)
        Step 2  →  For each TeamId, call GET /groups/{id}?$select=id,displayName,assignedLabels
        Step 3  →  Retry on HTTP 429 using Retry-After header
        Step 4  →  Parse assignedLabels: if empty, record labelStatus = "Not Labelled";
                   if populated, record label details and labelStatus = "Labelled"
        Step 5  →  Repeat for the next TeamId (one failure does not abort the run)
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permissions.
        - assignedLabels is only populated when sensitivity labels are configured
          in Microsoft Purview and applied at the M365 Group level. Teams that
          were created before label policies were configured may appear as
          "Not Labelled" even if a label was later published.
        - A Team can only have one sensitivity label assigned at a time
          (M365 Group limitation); this function reflects that single-label model.
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
    Microsoft Graph API - Get group (assignedLabels)
    https://learn.microsoft.com/en-us/graph/api/group-get

.LINK
    Microsoft Purview sensitivity labels with Microsoft Teams
    https://learn.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels-teams-groups-sites

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamSensitivityLabel
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
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
        # Define an empty array to hold all label records across all teams
        $allLabelRecords = New-Object System.Collections.ArrayList
        $totalRecords    = 0

        # Check if access token is obtained successfully
        if (-not $AccessToken)
        {
            Write-Error "AccessToken is required. Exiting function."
            return
        }

        # Define the request headers with the access token
        $headers = @{
            "Authorization"    = "Bearer $AccessToken"
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

        $teamsHeaders = @{
            "Authorization"    = "Bearer $AccessToken"
            "ConsistencyLevel" = "eventual"
        }

        Write-Verbose "Resolving team display names..."
        do
        {
            $teamsSkip = $false
            do
            {
                Try
                {
                    $teamsPartial = Invoke-WebRequest -Uri $teamsUri -Headers $teamsHeaders -Method Get -ErrorAction Stop
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
            } until (($teamsStatus -eq 200) -or $teamsSkip)

            if ($teamsSkip) { break }

            $teamsData = $teamsPartial.Content | ConvertFrom-Json
            @($teamsData.value) | ForEach-Object {
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
                Write-Progress -Activity "Retrieving sensitivity labels" `
                               -Status "Processing team: $id" `
                               -PercentComplete (($totalRecords / [Math]::Max($TeamId.Count, 1)) * 100)

                # Build the URI to retrieve assignedLabels for this group/team
                $uri = "https://graph.microsoft.com/v1.0/groups/$id`?`$select=id,displayName,assignedLabels"

                $skip = $false
                do
                {
                    Try
                    {
                        $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                        $statusCode  = $partialData.StatusCode
                    }
                    catch
                    {
                        $statusCode  = $_.Exception.Response.StatusCode
                        $ErrorObject = $_

                        if ($statusCode -eq 429)
                        {
                            $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                            Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                            Start-Sleep -Seconds $sleepTime
                        }
                        else
                        {
                            $ErrorOutput = [PSCustomObject][ordered]@{
                                TeamId     = $id
                                Response   = $($ErrorObject.Exception.Response)
                                StatusCode = $($ErrorObject.Exception.Response.StatusCode)
                                Message    = $($ErrorObject.Exception.Message)
                            }
                            $ErrorOutput | Format-List
                            $skip = $true
                        }
                    }
                } until (($statusCode -eq 200) -or $skip)

                if ($skip)
                {
                    Write-Warning "Failed to retrieve sensitivity label for team '$id'. Skipping to next TeamId."
                    Continue
                }

                $groupData     = $partialData.Content | ConvertFrom-Json
                $assignedLabels = @($groupData.assignedLabels)

                if ($assignedLabels.Count -eq 0)
                {
                    # No sensitivity label assigned — record as Not Labelled
                    $null = $allLabelRecords.Add(
                        [PSCustomObject]@{
                            teamId           = $id
                            teamDisplayName  = if ($teamNameMap.ContainsKey($id)) { $teamNameMap[$id] } else { "Could not be confirmed" }
                            labelId          = "N/A"
                            labelDisplayName = "N/A"
                            labelStatus      = "Not Labelled"
                        }
                    )
                }
                else
                {
                    # One label per team — reflect it
                    $label = $assignedLabels[0]
                    $null  = $allLabelRecords.Add(
                        [PSCustomObject]@{
                            teamId           = $id
                            teamDisplayName  = if ($teamNameMap.ContainsKey($id)) { $teamNameMap[$id] } else { "Could not be confirmed" }
                            labelId          = if ($label.labelId)      { $label.labelId }      else { "N/A" }
                            labelDisplayName = if ($label.displayName)  { $label.displayName }  else { "Could not be confirmed" }
                            labelStatus      = "Labelled"
                        }
                    )
                }

                $totalRecords++
                Write-Host "Progress: $totalRecords team(s) processed so far" -ForegroundColor Cyan
            }
            Catch
            {
                Write-Warning "Failed to retrieve sensitivity label for team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        Write-Progress -Activity "Retrieving sensitivity labels" -Completed

        Write-Host ""
        Write-Host "Sensitivity label retrieval complete. Total teams processed: $totalRecords" -ForegroundColor Green

        # CSV EXPORT SUPPORT
        if ($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $allLabelRecords | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Sensitivity label report exported successfully → $ExportPath" -ForegroundColor Green
        }

        return $allLabelRecords
    }
}
