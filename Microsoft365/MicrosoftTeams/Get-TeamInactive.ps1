<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 02 August 2026
Modified-On     : 02 August 2026

.SYNOPSIS
    Identifies Microsoft Teams with little or no recent activity using the
    Microsoft Graph usage reports API.

.DESCRIPTION
    Calls the Graph reports endpoint getTeamsTeamActivityDetail(period=...)
    to retrieve each team's Last Activity Date, then classifies teams as
    Inactive (no activity within -InactivityThresholdDays) or Never Active
    (no recorded activity at all in the report period).

    RECOMMENDED APPROACH FOR ENTERPRISE USE: the Graph reports endpoint is
    the fast, low-call-volume option, but by default Microsoft conceals
    user/group-identifiable columns (e.g. "Team Name") in report output
    tenant-wide unless an admin enables "concealed names" in the M365 admin
    center. Rather than depend on that tenant setting - or fall back to a
    much slower per-channel message-scan - this function sidesteps the
    problem entirely: the report's "Team Id" (GUID) column is never
    anonymized, so it is joined against a display-name lookup resolved
    independently via /groups (same approach used across this script suite).
    The result is fast (one report call + one paginated groups call) and
    always shows real team names, regardless of the tenant's concealment
    setting.

    Handles retries on HTTP 429 throttling using Retry-After. Only accepts a
    direct Bearer token (BYOT); does not authenticate itself. Obtain a token
    via the companion Connect-EntraID.ps1 (see .LINK).

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission: Reports.Read.All

.PARAMETER Period
    Reporting window for the underlying usage report.
    Supported values: D7, D30, D90, D180 (default: D90)

.PARAMETER InactivityThresholdDays
    Number of days since last activity beyond which a team is classified as
    Inactive. Default: 90. Should not exceed the numeric value implied by
    -Period, since the report itself only covers that window.

.PARAMETER ExportFormat
    Supported values: CSV

.PARAMETER ExportPath
    File path for the exported CSV. Required only when ExportFormat is CSV.

.INPUTS
    None. This function does not accept pipeline input (it evaluates the
    tenant-wide activity report in a single call).

.OUTPUTS
    System.Array of at-risk team records (Inactive / Never Active only);
    also optionally exports to CSV.

.EXAMPLE
    Get-TeamInactive -AccessToken $token

    Flags teams with no activity in the last 90 days.

.EXAMPLE
    Get-TeamInactive -AccessToken $token -Period D180 -InactivityThresholdDays 120 -ExportFormat CSV -ExportPath "C:\Reports\InactiveTeams.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (02-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with Reports.Read.All
        2. A valid Microsoft Graph access token with Group.Read.All (for the
            display-name lookup)
        3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve a teamId -> displayName lookup via /groups (paginated)
        Step 2  →  Call GET /reports/getTeamsTeamActivityDetail(period='{Period}')
                    (retrying on 429), which returns CSV content
        Step 3  →  Parse the CSV and join each row's Team Id to the display-name lookup
        Step 4  →  Classify each team as Inactive / Never Active / Active based
                    on Last Activity Date vs -InactivityThresholdDays
        Step 5  →  Return only Inactive / Never Active teams
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permissions.
        - "Activity" as defined by this report reflects channel/chat message
            activity captured by Microsoft's usage-reporting pipeline; a team
            with only file/tab activity and no messages may still show as
            inactive here - this could not be confirmed as covered by the
            report and should be treated as a limitation of the underlying
            Graph report, not this script.
        - Report data can lag by up to 48 hours per Microsoft's documented
            refresh cadence.
        - The getTeamsTeamActivityDetail report does not include an "Is
            Deleted" column (that field only exists on the separate
            getTeamsUserActivityUserDetail report), so this function cannot
            distinguish deleted teams from active ones - a deleted team may
            still appear here as Inactive or Never Active.

.LINK
    Microsoft Graph API - Get Teams team activity detail
    https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsteamactivitydetail

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamInactive
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("D7","D30","D90","D180")]
        [string]$Period = "D90",

        [int]$InactivityThresholdDays = 90,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    if (-not $AccessToken)
    {
        Write-Error "AccessToken is required. Exiting function."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "ConsistencyLevel" = "eventual"
    }

    # ── Step 1: Resolve teamId -> displayName lookup ─────────────────────────
    $teamNameMap = @{}
    $teamsUri = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName&`$count=true"

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
        $teamsData.value | ForEach-Object { $teamNameMap[$_.id] = $_.displayName }

        if ($teamsData.PSObject.Properties['@odata.nextLink']) { $teamsUri = $teamsData.'@odata.nextLink' } else { $teamsUri = $null }

    } until (-not $teamsUri)

    # ── Step 2: Call the usage report ────────────────────────────────────────
    $reportUri = "https://graph.microsoft.com/v1.0/reports/getTeamsTeamActivityDetail(period='$Period')"

    $skip = $false
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
            $ErrorObject  = $_

            if ($reportStatus -eq 429)
            {
                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                Start-Sleep -Seconds $sleepTime
            }
            else
            {
                $ErrorOutput = [PSCustomObject][ordered]@{
                    Response   = $($ErrorObject.Exception.Response)
                    StatusCode = $($ErrorObject.Exception.Response.StatusCode)
                    Message    = $($ErrorObject.Exception.Message)
                };
                $ErrorOutput | Format-List
                $skip = $true
            }
        }
    } until(($reportStatus -eq 200) -or $skip)

    if ($skip)
    {
        Write-Error "Failed to retrieve the Teams activity report. Exiting function."
        return
    }

    # ── Step 3: Parse CSV and classify ───────────────────────────────────────
    $csvContent = [System.Text.Encoding]::UTF8.GetString($reportPartial.Content)
    $csvRows = $csvContent | ConvertFrom-Csv

    $atRiskTeams = New-Object System.Collections.ArrayList
    $today = Get-Date

    foreach ($row in $csvRows)
    {
        Try
        {
            $teamId = $row.'Team Id'
            if (-not $teamId) { Continue }

            $teamDisplayName = if ($teamNameMap.ContainsKey($teamId)) { $teamNameMap[$teamId] } else { $row.'Team Name' }

            $lastActivityRaw = $row.'Last Activity Date'
            $lastActivityDate = $null
            if ($lastActivityRaw) { [void][DateTime]::TryParse($lastActivityRaw, [ref]$lastActivityDate) }

            if (-not $lastActivityRaw -or $lastActivityRaw -eq '')
            {
                $null = $atRiskTeams.Add([PSCustomObject]@{
                    teamId            = $teamId
                    teamDisplayName   = $teamDisplayName
                    lastActivityDate  = "Never"
                    daysSinceActivity = $null
                    status            = "Never Active"
                })
            }
            elseif ($lastActivityDate)
            {
                $daysSince = ($today - $lastActivityDate).Days
                if ($daysSince -ge $InactivityThresholdDays)
                {
                    $null = $atRiskTeams.Add([PSCustomObject]@{
                        teamId            = $teamId
                        teamDisplayName   = $teamDisplayName
                        lastActivityDate  = $lastActivityDate.ToString("yyyy-MM-dd")
                        daysSinceActivity = $daysSince
                        status            = "Inactive"
                    })
                }
            }
        }
        Catch
        {
            Write-Warning "Failed to evaluate a report row (Team Id: $($row.'Team Id')): $($_.Exception.Message)"
            Continue
        }
    }

    Write-Host ""
    Write-Host "Evaluated $($csvRows.Count) team(s) from the activity report; found $($atRiskTeams.Count) at-risk team(s)." -ForegroundColor Cyan

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
        Write-Host "Inactive teams report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # return $atRiskTeams | Select-Object teamId, teamDisplayName, lastActivityDate, daysSinceActivity, status | FT
    return $atRiskTeams
}
