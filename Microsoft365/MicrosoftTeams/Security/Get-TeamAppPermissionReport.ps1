<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 08 August 2026
Modified-On     : 08 August 2026

.SYNOPSIS
    Reports application permissions (RSC and distribution metadata) for all
    installed apps in one or more Microsoft Teams using Microsoft Graph API.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 endpoint to retrieve all
    apps installed in each Microsoft Team, expanding their teamsApp and
    teamsAppDefinition to surface:

        - App display name, publisher, and distribution method
        - Resource-Specific Consent (RSC) permissions granted to the app
        - A risk classification derived from distribution method and permission scope

    Risk classification rules applied:
        High    — sideloaded app (distributionMethod = "sideloaded") with any
                  RSC write or full-access permission, OR any sideloaded app
                  requesting more than 3 RSC permissions
        Medium  — sideloaded app with read-only RSC permissions, OR any app
                  (store or organisation-uploaded) with RSC write permissions
        Low     — store/organisation app with read-only RSC permissions or no RSC
        Info    — app has no RSC permissions at all (no consent granted)

    It handles pagination automatically via @odata.nextLink on the outer team
    loop, retries on API throttling (HTTP 429) using the Retry-After header,
    and validates the JSON response before processing it further. One TeamId's
    failure does not stop processing of the remaining TeamIds.

    Results can optionally be exported to CSV. Essential for identifying
    shadow-IT applications and over-privileged RSC consents in Teams.

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

    The following attributes are collected per installed app per team:
        - teamId, teamDisplayName, appId, appDisplayName, appVersion,
          publisher, distributionMethod, rscPermissions, rscPermissionCount,
          rscPermissionTypes, riskLevel, riskReason

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Group.Read.All
        TeamsAppInstallation.ReadForTeam.All (or TeamsAppInstallation.Read.All)

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
        An array of custom objects containing app permission attributes for
        each installed app across the supplied teams. Also optionally exports to CSV.

.EXAMPLE
    Get-TeamAppPermissionReport -AccessToken $token

    TeamId omitted: automatically resolves and retrieves app permission reports for every team in the tenant.

.EXAMPLE
    Get-TeamAppPermissionReport -AccessToken $token -TeamId "11111111-1111-1111-1111-111111111111"

    Retrieves the app permission report for a single team.

.EXAMPLE
    (Get-MicrosoftTeams -AccessToken $token) | Get-TeamAppPermissionReport -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamAppPermissions.csv"

    Chains from Get-MicrosoftTeams to audit app permissions across every team in the tenant and exports to CSV.

.EXAMPLE
    $token = Get-AccessToken
    Get-TeamAppPermissionReport -AccessToken $token -TeamId $teamId1, $teamId2 -ExportFormat CSV -ExportPath "C:\Reports\TeamAppPermissions.csv"

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
                TeamsAppInstallation.ReadForTeam.All (Application)
                  or TeamsAppInstallation.Read.All (Application)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve a teamId -> displayName lookup map via a single
                   paginated GET /groups call (also resolves full tenant scope
                   when TeamId is omitted)
        Step 2  →  For each TeamId, call GET /teams/{id}/installedApps
                   with $expand=teamsApp,teamsAppDefinition to retrieve apps
                   with RSC permission details in one call
        Step 3  →  Retry on HTTP 429 using Retry-After header
        Step 4  →  For each installed app, extract distributionMethod, publisher,
                   RSC permissions from teamsAppDefinition/authorization/
                   resourceSpecificPermissions
        Step 5  →  Classify risk level based on distributionMethod + RSC
                   permission scope (write vs. read) and count
        Step 6  →  Repeat for the next TeamId (one failure does not abort the run)
        Step 7  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permissions.
        - RSC permissions reflect what the app's manifest declares it can request
          (teamsAppDefinition/authorization/resourceSpecificPermissions); they do
          not confirm that admin consent was explicitly granted for each permission.
          Actual granted consent is managed via Azure AD service principal grants
          and cannot be confirmed from this endpoint alone.
        - Risk classification is heuristic (sideloaded flag + permission scope/count);
          it does not inspect OAuth delegated or application Graph permissions granted
          at the Entra ID level. A store app may still hold sensitive Graph API
          permissions outside of RSC.
        - The $expand=teamsApp,teamsAppDefinition query may return partial data for
          apps whose definitions are not published to the tenant's app catalog;
          these will be reported as "Could not be confirmed" where details are absent.
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
    Microsoft Graph API - List apps installed in a team
    https://learn.microsoft.com/en-us/graph/api/team-list-installedapps

.LINK
    Microsoft Teams Resource-specific consent (RSC)
    https://learn.microsoft.com/en-us/microsoftteams/platform/graph-api/rsc/resource-specific-consent

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamAppPermissionReport
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
        # Define an empty array to hold all app permission records across all teams
        $allAppRecords = New-Object System.Collections.ArrayList
        $totalRecords  = 0
        $teamIndex     = 0

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
                $teamIndex++
                $percentComplete = [math]::Round(($teamIndex / [Math]::Max($TeamId.Count, 1)) * 100, 0)

                Write-Progress -Activity "Retrieving app permission reports" `
                    -Status "Processing team $teamIndex of $($TeamId.Count): $(if ($teamNameMap.ContainsKey($id)) { $teamNameMap[$id] } else { $id })" `
                    -PercentComplete $percentComplete

                # Build the URI to retrieve installed apps with full expansion for this team.
                # $expand=teamsApp,teamsAppDefinition surfaces distributionMethod and RSC permissions.
                $uri = "https://graph.microsoft.com/v1.0/teams/$id/installedApps?`$expand=teamsApp,teamsAppDefinition"

                $teamAppCount = 0

                do
                {
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
                        Write-Warning "Failed to retrieve installed apps for team '$id'. Skipping to next TeamId."
                        break
                    }

                    $appsData = $partialData.Content | ConvertFrom-Json

                    @($appsData.value) | ForEach-Object {
                        $installedApp = $_

                        Try
                        {
                            $teamsApp       = $installedApp.teamsApp
                            $appDefinition  = $installedApp.teamsAppDefinition

                            # Extract core app metadata
                            $appId              = if ($teamsApp -and $teamsApp.PSObject.Properties['id'])              { $teamsApp.id }              else { "Could not be confirmed" }
                            $appDisplayName     = if ($teamsApp -and $teamsApp.PSObject.Properties['displayName'])     { $teamsApp.displayName }     else { "Could not be confirmed" }
                            $distributionMethod = if ($teamsApp -and $teamsApp.PSObject.Properties['distributionMethod']) { $teamsApp.distributionMethod } else { "Could not be confirmed" }
                            $appVersion         = if ($appDefinition -and $appDefinition.PSObject.Properties['version'])  { $appDefinition.version }  else { "Could not be confirmed" }
                            $publisher          = if ($appDefinition -and $appDefinition.PSObject.Properties['publishingState']) { $appDefinition.publishingState } else { "Could not be confirmed" }

                            # Prefer developer.websiteUrl or developer name from the definition when available
                            if ($appDefinition -and $appDefinition.PSObject.Properties['authorization'])
                            {
                                $authorization = $appDefinition.authorization
                            }
                            else
                            {
                                $authorization = $null
                            }

                            # Extract RSC (Resource-Specific Consent) permissions
                            $rscPermissions    = @()
                            $rscPermissionList = "None"
                            $rscHasWrite       = $false

                            if ($authorization -and $authorization.PSObject.Properties['resourceSpecificPermissions'])
                            {
                                $rscPermissions = @($authorization.resourceSpecificPermissions)
                                if ($rscPermissions.Count -gt 0)
                                {
                                    $rscPermissionList = ($rscPermissions | ForEach-Object {
                                        if ($_.PSObject.Properties['permissionValue']) { $_.permissionValue }
                                    } | Where-Object { $_ }) -join "; "

                                    # Check if any RSC permission is a write or full-access type
                                    $rscHasWrite = $rscPermissions | Where-Object {
                                        $_.PSObject.Properties['permissionValue'] -and
                                        ($_.permissionValue -match '\.ReadWrite\.' -or
                                         $_.permissionValue -match '\.Write\.' -or
                                         $_.permissionValue -match 'FullControl')
                                    }
                                }
                            }

                            $rscPermissionCount = $rscPermissions.Count

                            # Classify RSC permission types
                            $rscPermissionTypes = "None"
                            if ($rscPermissionCount -gt 0)
                            {
                                $hasWrite = [bool]$rscHasWrite
                                $rscPermissionTypes = if ($hasWrite) { "Read + Write" } else { "Read Only" }
                            }

                            # ─────────────────────────────────────────────────
                            # Risk classification heuristic
                            # ─────────────────────────────────────────────────
                            $riskLevel  = "Info"
                            $riskReason = "No RSC permissions detected"

                            if ($distributionMethod -eq "sideloaded")
                            {
                                if ($rscHasWrite -or $rscPermissionCount -gt 3)
                                {
                                    $riskLevel  = "High"
                                    $riskReason = "Sideloaded app with write/elevated RSC permissions ($rscPermissionCount permission(s))"
                                }
                                elseif ($rscPermissionCount -gt 0)
                                {
                                    $riskLevel  = "Medium"
                                    $riskReason = "Sideloaded app with read-only RSC permissions ($rscPermissionCount permission(s))"
                                }
                                else
                                {
                                    $riskLevel  = "Medium"
                                    $riskReason = "Sideloaded app — distribution method is not from the official store"
                                }
                            }
                            elseif ($rscHasWrite)
                            {
                                $riskLevel  = "Medium"
                                $riskReason = "Store/organisation app with write RSC permissions ($rscPermissionCount permission(s))"
                            }
                            elseif ($rscPermissionCount -gt 0)
                            {
                                $riskLevel  = "Low"
                                $riskReason = "Store/organisation app with read-only RSC permissions ($rscPermissionCount permission(s))"
                            }

                            $null = $allAppRecords.Add(
                                [PSCustomObject]@{
                                    teamId              = $id
                                    teamDisplayName     = if ($teamNameMap.ContainsKey($id)) { $teamNameMap[$id] } else { "Could not be confirmed" }
                                    appId               = $appId
                                    appDisplayName      = $appDisplayName
                                    appVersion          = $appVersion
                                    publisher           = $publisher
                                    distributionMethod  = $distributionMethod
                                    rscPermissions      = $rscPermissionList
                                    rscPermissionCount  = $rscPermissionCount
                                    rscPermissionTypes  = $rscPermissionTypes
                                    riskLevel           = $riskLevel
                                    riskReason          = $riskReason
                                }
                            )

                            $teamAppCount++
                            $totalRecords++
                        }
                        Catch
                        {
                            Write-Warning "Error processing installed app in team '$id': $($_.Exception.Message)"
                        }
                    }

                    Write-Host "Progress: $totalRecords app permission record(s) retrieved so far" -ForegroundColor Cyan

                    if ($appsData.PSObject.Properties['@odata.nextLink']) { $uri = $appsData.'@odata.nextLink' } else { $uri = $null }

                } until (-not $uri)

                Write-Verbose "Team '$id': $teamAppCount app(s) processed."
            }
            Catch
            {
                Write-Warning "Failed to retrieve app permissions for team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        Write-Progress -Activity "Retrieving app permission reports" -Completed

        Write-Host ""
        Write-Host "App permission report complete. Total app records retrieved: $totalRecords" -ForegroundColor Green

        # CSV EXPORT SUPPORT
        if ($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $allAppRecords | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Teams app permission report exported successfully → $ExportPath" -ForegroundColor Green
        }

        return $allAppRecords
    }
}
