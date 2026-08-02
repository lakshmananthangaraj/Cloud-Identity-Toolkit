<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 02 August 2026
Modified-On     : 02 August 2026

.SYNOPSIS
    Combines ownership, activity, creation date, and membership into a single
    Microsoft Teams lifecycle report using Microsoft Graph API.

.DESCRIPTION
    Standalone, self-contained executive reporting script (no dependency on
    the other scripts in this suite). For every team in scope it collects:
        - createdDateTime, visibility, ageInDays
        - ownerCount, memberCount, guestCount (via lightweight Graph
          /$count endpoints - no full member listing is downloaded)
        - lastActivityDate / daysSinceActivity (via the Graph usage report
          getTeamsTeamActivityDetail, joined by Team Id so real display
          names are shown when the tenant's report concealment setting is
          off - see Get-TeamInactive for the same technique. NOTE: if the
          tenant has "Display concealed user, group, and site names in all
          reports" enabled, Microsoft Graph anonymizes the Team Id itself
          (returned as 00000000-0000-0000-0000-000000000000 for every row)
          in addition to Team Name, in which case this join cannot recover
          real activity data and lastActivityDate will show "Could not be
          confirmed" for all teams - this is a tenant admin-center setting,
          not something this script can work around)

    From these it derives a single LifecycleStage per team, evaluated in
    priority order:
        1. Ownerless   - 0 owners (Critical - unmanaged)
        2. Inactive     - no activity within -InactivityThresholdDays, or
                           never active
        3. UnderOwned  - exactly 1 owner (single point of failure)
        4. Active       - none of the above

    Handles pagination via @odata.nextLink for team resolution, retries on
    HTTP 429 throttling using Retry-After, and skips a failing team without
    aborting the run. Only accepts a direct Bearer token (BYOT); does not
    authenticate itself. Obtain a token via the companion Connect-EntraID.ps1
    (see .LINK).

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions: Group.Read.All, GroupMember.Read.All, Reports.Read.All

.PARAMETER TeamId
    Optional. GUID(s) of the Microsoft Team. Accepts an array or pipeline
    input by value/property name (e.g. from Get-Teams). If omitted, every
    team in the tenant is evaluated.

.PARAMETER Period
    Reporting window for the underlying activity report.
    Supported values: D7, D30, D90, D180 (default: D90)

.PARAMETER InactivityThresholdDays
    Number of days since last activity beyond which a team counts toward the
    Inactive lifecycle stage. Default: 90.

.PARAMETER ExportFormat
    Supported values: CSV

.PARAMETER ExportPath
    File path for the exported CSV. Required only when ExportFormat is CSV.

.INPUTS
    String (TeamId), or objects with an id/TeamId property.

.OUTPUTS
    System.Array of lifecycle records, one per team; also optionally exports
    to CSV.

.EXAMPLE
    Get-TeamLifecycleReport -AccessToken $token

    Produces a lifecycle report for every team in the tenant.

.EXAMPLE
    Get-TeamLifecycleReport -AccessToken $token -Period D180 -InactivityThresholdDays 120 -ExportFormat CSV -ExportPath "C:\Reports\TeamLifecycle.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (02-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with Group.Read.All,
            GroupMember.Read.All, and Reports.Read.All
        2. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve teams to evaluate (all, or supplied -TeamId) with
                    displayName, createdDateTime, visibility
        Step 2  →  Call GET /reports/getTeamsTeamActivityDetail(period='{Period}')
                    once and index the results by Team Id
        Step 3  →  For each team, retrieve ownerCount, memberCount, guestCount
                    via /$count endpoints (retrying on 429)
        Step 4  →  Compute ageInDays, join activity data, and derive
                    LifecycleStage (Ownerless > Inactive > UnderOwned > Active)
        Step 5  →  Repeat for next team (one failure does not abort the run)
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permissions.
        - Activity report data can lag by up to 48 hours per Microsoft's
            documented refresh cadence.
        - If the tenant has "Display concealed user, group, and site names
            in all reports" enabled (M365 admin center > Org Settings >
            Services > Reports), Microsoft Graph anonymizes the Team Id
            itself (all rows return 00000000-0000-0000-0000-000000000000),
            not just Team Name. In that case the Team Id join used here
            cannot recover real activity data, and lastActivityDate will
            show "Could not be confirmed" for every team. A Global Admin
            must disable that setting for this report to return usable
            data; changes take up to 48 hours to reflect.
        - LifecycleStage priority order means a team with 0 owners AND no
            activity is reported only as "Ownerless" (the more severe
            condition), not both - check ownerCount/daysSinceActivity columns
            directly for the full picture.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: uses one static Bearer token
            for the entire run; no mid-run refresh. In very large tenants a
            run exceeding the token lifetime (~60-90 min) will fail with 401.
        - RECOMMENDED FOR: smaller tenants or scoped/filtered pulls.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants without
            adding a token-refresh pattern and/or parallelized calls.

.LINK
    Microsoft Graph API - Get Teams team activity detail
    https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsteamactivitydetail

.LINK
    Microsoft Graph API - List group owners
    https://learn.microsoft.com/en-us/graph/api/group-list-owners

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


# Private helper: retrieves a single Graph /$count value with throttle/retry
# handling. Not exported for standalone use - internal to this script only.
Function Get-GraphCountInternal
{
    param (
        [string]$Uri,
        [hashtable]$Headers
    )

    $skip = $false
    $countValue = $null

    do
    {
        Try
        {
            $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
            $statusCode = $response.StatusCode
        }
        catch
        {
            $statusCode = $_.Exception.Response.StatusCode
            if ($statusCode -eq 429)
            {
                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                Start-Sleep -Seconds $sleepTime
            }
            else
            {
                Write-Warning "Count query failed for '$Uri': $($_.Exception.Message)"
                $skip = $true
            }
        }
    } until(($statusCode -eq 200) -or $skip)

    if (-not $skip)
    {
        Try { $countValue = [int]($response.Content.Trim()) } Catch { $countValue = $null }
    }

    return $countValue
}


Function Get-TeamLifecycleReport
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("id")]
        [string[]]$TeamId,

        [ValidateSet("D7","D30","D90","D180")]
        [string]$Period = "D90",

        [int]$InactivityThresholdDays = 90,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    Begin
    {
        $lifecycleReport = New-Object System.Collections.ArrayList

        if (-not $AccessToken)
        {
            Write-Error "AccessToken is required. Exiting function."
            return
        }

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "ConsistencyLevel" = "eventual"
        }

        # ── Resolve team metadata (displayName, createdDateTime, visibility) ──
        $resolveAllTeams = (-not $PSBoundParameters.ContainsKey('TeamId')) -and (-not $MyInvocation.ExpectingInput)

        $teamMetaMap = @{}
        $allTeamIds  = New-Object System.Collections.ArrayList
        $teamsUri    = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName,createdDateTime,visibility&`$count=true"

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
                $teamMetaMap[$_.id] = [PSCustomObject]@{
                    DisplayName     = $_.displayName
                    CreatedDateTime = $_.createdDateTime
                    Visibility      = $_.visibility
                }
                $null = $allTeamIds.Add($_.id)
            }

            if ($teamsData.PSObject.Properties['@odata.nextLink']) { $teamsUri = $teamsData.'@odata.nextLink' } else { $teamsUri = $null }

        } until (-not $teamsUri)

        if ($resolveAllTeams)
        {
            $TeamId = $allTeamIds
            Write-Verbose "Resolved $($TeamId.Count) team(s) to process."
        }

        # ── Resolve activity report once, indexed by Team Id ──────────────────
        $activityMap = @{}
        $reportUri = "https://graph.microsoft.com/v1.0/reports/getTeamsTeamActivityDetail(period='$Period')"

        Write-Verbose "Retrieving Teams activity report (period=$Period)..."
        $reportSkip = $false
        do
        {
            Try
            {
                $reportPartial = Invoke-WebRequest -Uri $reportUri -Headers $headers -Method Get -ErrorAction Stop
                $reportStatus  = $reportPartial.StatusCode
            }
            catch
            {
                $reportStatus = $_.Exception.Response.StatusCode
                if ($reportStatus -eq 429)
                {
                    $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                    Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                    Start-Sleep -Seconds $sleepTime
                }
                else
                {
                    Write-Warning "Failed to retrieve the Teams activity report: $($_.Exception.Message). Activity columns will show 'Could not be confirmed'."
                    $reportSkip = $true
                }
            }
        } until(($reportStatus -eq 200) -or $reportSkip)

        if (-not $reportSkip)
        {
            $csvContent = [System.Text.Encoding]::UTF8.GetString($reportPartial.Content)
            $csvRows = $csvContent | ConvertFrom-Csv
            foreach ($row in $csvRows)
            {
                $teamIdProp = $row.PSObject.Properties['Team Id']
                if ($teamIdProp -and $teamIdProp.Value)
                {
                    $lastActivityProp = $row.PSObject.Properties['Last Activity Date']
                    $activityMap[$teamIdProp.Value] = if ($lastActivityProp) { $lastActivityProp.Value } else { $null }
                }
            }
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
                $createdRaw      = if ($meta) { $meta.CreatedDateTime } else { $null }

                $ageInDays = $null
                if ($createdRaw)
                {
                    if ($createdRaw -is [DateTime])
                    {
                        $ageInDays = ((Get-Date) - $createdRaw).Days
                    }
                    else
                    {
                        $createdDate = $null
                        if ([DateTime]::TryParse([string]$createdRaw, [ref]$createdDate)) { $ageInDays = ((Get-Date) - $createdDate).Days }
                    }
                }

                # ── Counts via lightweight /$count endpoints ────────────────
                $ownerCount = Get-GraphCountInternal -Uri "https://graph.microsoft.com/v1.0/groups/$id/owners/`$count" -Headers $headers
                $memberCount = Get-GraphCountInternal -Uri "https://graph.microsoft.com/v1.0/groups/$id/members/`$count" -Headers $headers
                $guestCount = Get-GraphCountInternal -Uri "https://graph.microsoft.com/v1.0/groups/$id/members/`$count?`$filter=userType eq 'Guest'" -Headers $headers

                # ── Activity lookup ───────────────────────────────────────────
                $lastActivityRaw = if ($activityMap.ContainsKey($id)) { $activityMap[$id] } else { $null }
                $lastActivityDate = $null
                $daysSinceActivity = $null
                $activityStatus = "Could not be confirmed"

                if ($activityMap.ContainsKey($id))
                {
                    if ([string]::IsNullOrWhiteSpace($lastActivityRaw))
                    {
                        $activityStatus = "Never Active"
                    }
                    else
                    {
                        $parsed = $null
                        if ([DateTime]::TryParse([string]$lastActivityRaw, [ref]$parsed))
                        {
                            $lastActivityDate = $parsed.ToString("yyyy-MM-dd")
                            $daysSinceActivity = ((Get-Date) - $parsed).Days
                            $activityStatus = if ($daysSinceActivity -ge $InactivityThresholdDays) { "Inactive" } else { "Active" }
                        }
                    }
                }

                # ── Derive LifecycleStage (priority order) ──────────────────
                $lifecycleStage =
                    if ($null -eq $ownerCount)                              { "Unknown" }
                    elseif ($ownerCount -eq 0)                              { "Ownerless" }
                    elseif ($activityStatus -in @("Inactive","Never Active")) { "Inactive" }
                    elseif ($ownerCount -eq 1)                              { "UnderOwned" }
                    else                                                     { "Active" }

                $null = $lifecycleReport.Add([PSCustomObject]@{
                    teamId               = $id
                    teamDisplayName      = $teamDisplayName
                    visibility           = $visibility
                    createdDateTime      = $createdRaw
                    ageInDays            = $ageInDays
                    ownerCount           = if ($null -eq $ownerCount) { "Could not be confirmed" } else { $ownerCount }
                    memberCount          = if ($null -eq $memberCount) { "Could not be confirmed" } else { $memberCount }
                    guestCount           = if ($null -eq $guestCount) { "Could not be confirmed" } else { $guestCount }
                    lastActivityDate     = if ($lastActivityDate) { $lastActivityDate } else { $activityStatus }
                    daysSinceActivity    = $daysSinceActivity
                    lifecycleStage       = $lifecycleStage
                })

                Write-Verbose "Processed team '$teamDisplayName' [$id] - stage: $lifecycleStage"
            }
            Catch
            {
                Write-Warning "Failed to process lifecycle data for team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        $summary = $lifecycleReport | Group-Object lifecycleStage | Select-Object Name, Count
        Write-Host ""
        Write-Host "Lifecycle report complete for $($lifecycleReport.Count) team(s):" -ForegroundColor Cyan
        $summary | ForEach-Object { Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor Cyan }

        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $lifecycleReport | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Team lifecycle report exported successfully → $ExportPath" -ForegroundColor Green
        }

        # return $lifecycleReport | Select-Object teamId, teamDisplayName, visibility, createdDateTime, ageInDays, ownerCount, memberCount, guestCount, lastActivityDate, daysSinceActivity, lifecycleStage | FT
        return $lifecycleReport
    }
}
