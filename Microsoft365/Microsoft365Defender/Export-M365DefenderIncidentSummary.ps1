<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Pulls open/recent unified Microsoft Defender incidents and exports both a raw CSV and an
    executive-readable Markdown summary.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 /security/incidents endpoint — the unified
    Defender incidents API that correlates related alerts (across Defender for Endpoint,
    Office 365, Identity, Cloud Apps, and Sentinel) into a single incident.

    Unlike the other Get-* functions in this toolkit, this function always writes output to
    disk (the Export- verb reflects that this is a reporting action, not just a data pull):
        - <ExportPath>.csv  — one row per incident (raw/detailed)
        - <ExportPath>.md   — a short narrative summary intended for a non-technical/
                              leadership audience: overall counts, severity breakdown, and
                              the highest-severity currently-active incidents

    The full incident collection is also returned to the pipeline so it can be chained into
    further PowerShell processing in the same session.

    It handles pagination automatically via @odata.nextLink, retries on API throttling
    (HTTP 429) using the Retry-After header, and validates the JSON response before
    processing it further.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK below,
    then pass its returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        SecurityIncident.Read.All (Application)

.PARAMETER ExportPath
    Mandatory. Base file path (without extension) used to derive both output files, e.g.
    "C:\Reports\IncidentSummary" produces "C:\Reports\IncidentSummary.csv" and
    "C:\Reports\IncidentSummary.md".

.PARAMETER Status
    Optional. Filters incidents by status.
    Supported values:
        active, resolved, redirected

.PARAMETER Severity
    Optional. Filters incidents by severity.
    Supported values:
        unspecified, informational, low, medium, high

.PARAMETER StartDate
    Optional. Only include incidents with createdDateTime on or after this UTC date/time.

.PARAMETER EndDate
    Optional. Only include incidents with createdDateTime on or before this UTC date/time.

.PARAMETER TopIncidentCount
    Number of highest-severity active incidents to feature individually in the Markdown
    exec brief. Default is 5.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
        An array of custom objects containing selected incident attributes. Also always
        writes a CSV and a Markdown exec-brief to disk at -ExportPath.

.EXAMPLE
    Export-M365DefenderIncidentSummary -AccessToken $token -ExportPath "C:\Reports\IncidentSummary"

    Retrieves all incidents and writes IncidentSummary.csv and IncidentSummary.md.

.EXAMPLE
    Export-M365DefenderIncidentSummary -AccessToken $token -Status active -StartDate (Get-Date).AddDays(-30) -ExportPath "C:\Reports\LastMonthActive"

    Retrieves active incidents opened in the last 30 days and exports both artifacts.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permission:
                SecurityIncident.Read.All (Application)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The Markdown exec brief is a plain narrative summary generated from the incident
            metadata retrieved at run time; it does not pull in analyst comments or
            investigation notes attached to each incident.
        - "Longest-open active incident" and the top-N featured incidents are ranked using
            only createdDateTime and severity as returned by Graph — if assignedTo or
            classification are null for a given incident, this could not be confirmed as an
            unassigned/unclassified incident versus a data-population gap, and is reported
            as "Not confirmed" rather than assumed either way.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer token for
            the entire pagination run and does not refresh it mid-run.
        - This function's Export- verb means it ALWAYS writes files to -ExportPath; there is
            no in-memory-only mode. Use the pipeline return value if you only need the data
            in-session without touching disk.

.LINK
    Microsoft Graph API - incident resource type
    https://learn.microsoft.com/en-us/graph/api/resources/security-incident

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Export-M365DefenderIncidentSummary
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExportPath,

        [ValidateSet("active", "resolved", "redirected")]
        [string]$Status,

        [ValidateSet("unspecified", "informational", "low", "medium", "high")]
        [string]$Severity,

        [datetime]$StartDate,

        [datetime]$EndDate,

        [ValidateRange(1, 50)]
        [int]$TopIncidentCount = 5
    )

    if ($ExportPath -match '\.\.[\\/]')
    {
        Write-Error "ExportPath contains path-traversal characters and was rejected. Exiting function."
        return
    }

    $filterClauses = New-Object System.Collections.ArrayList
    if ($Status) { $null = $filterClauses.Add("status eq '$Status'") }
    if ($Severity) { $null = $filterClauses.Add("severity eq '$Severity'") }
    if ($StartDate) { $null = $filterClauses.Add("createdDateTime ge $($StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))") }
    if ($EndDate) { $null = $filterClauses.Add("createdDateTime le $($EndDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))") }

    $filterQuery = if ($filterClauses.Count -gt 0) { "&`$filter=" + ($filterClauses -join " and ") } else { "" }

    $allIncidents = New-Object System.Collections.ArrayList
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $uri = "https://graph.microsoft.com/v1.0/security/incidents?`$top=50$filterQuery"

    do
    {
        Try
        {
            $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            $statusCode = $partialData.StatusCode
        }
        catch
        {
            $statusCode = $_.Exception.Response.StatusCode
            $ErrorObject = $_

            if ($statusCode -eq 429)
            {
                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                Start-Sleep -Seconds $sleepTime
                continue
            }
            else
            {
                $ErrorOutput = [PSCustomObject][ordered]@{
                    Response   = $($ErrorObject.Exception.Response)
                    StatusCode = $($ErrorObject.Exception.Response.StatusCode)
                    Message    = $($ErrorObject.Exception.Message)
                }
                $ErrorOutput | Format-List
                return
            }
        }

        if ($partialData)
        {
            $incidentData = $partialData.Content | ConvertFrom-Json
        }

        $incidentData.value | ForEach-Object {

            $incident = $_
            $null = $allIncidents.Add(
                [PSCustomObject][ordered]@{
                    id                 = $incident.id
                    displayName        = $incident.displayName
                    severity           = $incident.severity
                    status             = $incident.status
                    classification     = $incident.classification
                    determination      = $incident.determination
                    createdDateTime    = $incident.createdDateTime
                    lastUpdateDateTime = $incident.lastUpdateDateTime
                    assignedTo         = $incident.assignedTo
                    tags               = if ($incident.tags) { $incident.tags -join "; " } else { $null }
                    incidentWebUrl     = $incident.incidentWebUrl
                }
            )
        }

        $totalIncidents = $allIncidents.Count
        Write-Host "Progress: $totalIncidents incident(s) retrieved so far" -ForegroundColor Cyan

        if ($incidentData.PSObject.Properties['@odata.nextLink']) { $uri = $incidentData.'@odata.nextLink' } else { $uri = $null }

    } until (-not $uri)

    # ── CSV export (raw/detailed)
    $csvPath = "${ExportPath}.csv"
    $allIncidents | Export-Csv -Path $csvPath -NoTypeInformation -Force
    Write-Host ""
    Write-Host "Incident detail exported successfully -> $csvPath" -ForegroundColor Green

    # ── Markdown exec brief (narrative summary)
    $now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + " UTC"
    $totalCount = $allIncidents.Count

    $statusGroups = $allIncidents | Group-Object status
    $severityGroups = $allIncidents | Group-Object severity

    $activeIncidents = $allIncidents | Where-Object { $_.status -eq 'active' }
    $longestOpenActive = $activeIncidents | Sort-Object createdDateTime | Select-Object -First 1

    $severityRank = @{ high = 4; medium = 3; low = 2; informational = 1; unspecified = 0 }
    $topActiveIncidents = $activeIncidents |
        Sort-Object -Property @{ Expression = { $severityRank[$_.severity] } }, createdDateTime -Descending |
        Select-Object -First $TopIncidentCount

    $md = New-Object System.Text.StringBuilder
    [void]$md.AppendLine("# Microsoft Defender - Incident Summary")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("Generated: $now")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("## Overview")
    [void]$md.AppendLine("- Total incidents in scope: $totalCount")
    foreach ($group in $statusGroups) { [void]$md.AppendLine("- Status `$($group.Name)`: $($group.Count)") }
    [void]$md.AppendLine("")
    [void]$md.AppendLine("## By Severity")
    foreach ($group in $severityGroups) { [void]$md.AppendLine("- $($group.Name): $($group.Count)") }
    [void]$md.AppendLine("")
    [void]$md.AppendLine("## Longest-Open Active Incident")
    if ($longestOpenActive)
    {
        $daysOpen = [Math]::Round(((Get-Date).ToUniversalTime() - [datetime]$longestOpenActive.createdDateTime).TotalDays, 1)
        $assignedDisplay = if ($longestOpenActive.assignedTo) { $longestOpenActive.assignedTo } else { "Not confirmed" }
        [void]$md.AppendLine("- $($longestOpenActive.displayName) (opened $($longestOpenActive.createdDateTime), $daysOpen days open, assigned to: $assignedDisplay)")
    }
    else
    {
        [void]$md.AppendLine("- No active incidents in scope.")
    }
    [void]$md.AppendLine("")
    [void]$md.AppendLine("## Top $TopIncidentCount Highest-Severity Active Incidents")
    if ($topActiveIncidents)
    {
        $rank = 1
        foreach ($inc in $topActiveIncidents)
        {
            $assignedDisplay = if ($inc.assignedTo) { $inc.assignedTo } else { "Not confirmed" }
            [void]$md.AppendLine("$rank. $($inc.displayName) - Severity: $($inc.severity) - Opened: $($inc.createdDateTime) - Assigned: $assignedDisplay")
            $rank++
        }
    }
    else
    {
        [void]$md.AppendLine("- No active incidents to feature.")
    }
    [void]$md.AppendLine("")
    [void]$md.AppendLine("## Notes")
    [void]$md.AppendLine("- This summary reflects incidents retrieved at run time via Microsoft Graph and does not include analyst comments or investigation notes.")

    $mdPath = "${ExportPath}.md"
    $md.ToString() | Out-File -FilePath $mdPath -Encoding utf8 -Force
    Write-Host "Executive summary exported successfully -> $mdPath" -ForegroundColor Green

    return $allIncidents
}
