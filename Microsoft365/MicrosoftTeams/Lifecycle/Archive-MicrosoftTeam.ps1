<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 10 August 2026
Modified-On     : 10 August 2026

.SYNOPSIS
    Bulk-archives one or more Microsoft Teams using Microsoft Graph API.

.DESCRIPTION
    This function archives a batch of Microsoft Teams. The TeamId list can
    be supplied directly (-TeamIds) or read from a CSV file (-InputCsv)
    containing a 'TeamId' or 'Id' column — the two input methods are
    mutually exclusive parameter sets.

    Before any changes are made, the function:
        - De-duplicates the input ID list and rejects entries that are
          not valid-format GUIDs (reported as InvalidFormat).
        - Looks up every remaining Team (GET /teams/{id}) to confirm it
          exists and is not already archived. Teams that are already
          archived are reported as AlreadyArchived and skipped; Teams
          that can't be found are reported as NotFound.

    A single confirmation prompt (ShouldProcess) covers the whole batch —
    not one prompt per Team — since this is one logical bulk action, and
    it's raised only once the actual to-be-archived count is known.

    Archiving itself is an ASYNCHRONOUS Graph operation: a 202 Accepted
    response means the archive request was queued, not that the Team is
    archived yet. Processing is continue-on-error — if requesting archive
    for one Team fails, the function logs it and moves on to the rest of
    the batch. Use Get-TeamArchived.ps1 afterwards to confirm which Teams
    have actually finished archiving.

    This function only accepts a direct Bearer token (AccessToken). It
    does not perform authentication itself. If you need to obtain a token
    via app-only (client credentials) authentication, use the companion
    Connect-EntraID.ps1 script referenced under .LINK below, then pass its
    returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission (least privileged):
        Application : TeamSettings.ReadWrite.Group (resource-specific consent)
        Delegated   : TeamSettings.ReadWrite.All
    Higher-privileged alternatives (backward compatibility only):
        Group.ReadWrite.All, Directory.ReadWrite.All

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to Connect-EntraID.ps1 (see .LINK).

.PARAMETER TeamIds
    One or more Team IDs (GUIDs — same value as the underlying Microsoft
    365 Group's Object ID) to archive. Mutually exclusive with -InputCsv.

.PARAMETER InputCsv
    Path to a CSV file containing the Teams to archive. The file must
    have a column named 'TeamId' or 'Id' (case-insensitive) holding each
    Team's GUID. Mutually exclusive with -TeamIds. Rejected if the path
    contains a '..' path-traversal sequence.

.PARAMETER SetSpoSiteReadOnly
    Optional switch. When set, requests that the Team's associated
    SharePoint Online site also be set to read-only for members as part
    of archiving.
    IMPORTANT: per Microsoft Graph, this option is NOT supported in the
    application (app-only / client-credentials) context — it only takes
    effect when -AccessToken is a delegated (signed-in user) token. If
    used with an application token, Graph silently ignores it and the
    SharePoint site is left as-is. Default: off (switch not supplied).

.PARAMETER ExportFormat
    Specifies the output format for the detailed per-Team results.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV. Rejected if it contains
    a '..' path-traversal sequence.

.PARAMETER Force
    Suppresses the interactive confirmation prompt. The batch is still
    skipped entirely when -WhatIf is supplied.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject
        A summary object: totalRequested, duplicatesRemoved,
        archiveRequested, alreadyArchived, notFound, invalidFormat,
        failed, and results (an array of per-Team PSCustomObjects:
        teamId, displayName, status, detail). Also optionally exports the
        per-Team results to CSV.

.EXAMPLE
    Archive-MicrosoftTeam -AccessToken $token -TeamIds "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb","cccccccc-3333-4444-5555-dddddddddddd"

    Requests archiving of two Teams after a single confirmation prompt.

.EXAMPLE
    Archive-MicrosoftTeam -AccessToken $token `
        -InputCsv "C:\Lifecycle\InactiveTeams.csv" `
        -Force `
        -ExportFormat CSV -ExportPath "C:\Reports\ArchiveResults.csv"

    Requests archiving of every Team listed in InactiveTeams.csv, without
    an interactive prompt, and exports per-Team results to CSV.

.EXAMPLE
    Archive-MicrosoftTeam -AccessToken $token -TeamIds "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb" -SetSpoSiteReadOnly -WhatIf

    Shows what would happen without making any changes. -SetSpoSiteReadOnly
    only has effect if $token is a delegated token (see parameter note).

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (10-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permission:
                TeamSettings.ReadWrite.Group (Application, least privileged)
                or TeamSettings.ReadWrite.All (Delegated, least privileged)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Archiving is asynchronous. A 202 response (status
            "ArchiveRequested") confirms the request was accepted, not
            that the Team has finished archiving. Confirm completion with
            Get-TeamArchived.ps1.
        - Per Microsoft Graph, a Team (and its underlying group) must
            have an owner before it can be archived; Teams without an
            owner will surface as Failed with Graph's own error detail.
        - -SetSpoSiteReadOnly is ignored by Graph when using an
            application (app-only) token — it only works with a delegated
            token. This function does not attempt to detect the token
            type and will not warn if the switch has no effect.
        - On a 429 throttle response, each archive request is retried
            once after the Retry-After delay; a second consecutive
            throttle on the same Team is recorded as Failed rather than
            retried further.
        - CSV export writes the per-Team results, not the summary object;
            read the console summary line (or the returned object's
            top-level properties) for aggregate counts.

.LINK
    Microsoft Graph API - Archive team
    https://learn.microsoft.com/en-us/graph/api/team-archive

.LINK
    Microsoft Graph API - Get team
    https://learn.microsoft.com/en-us/graph/api/team-get

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Archive-MicrosoftTeam {
    [CmdletBinding(DefaultParameterSetName = 'ByArray', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByArray')]
        [ValidateNotNullOrEmpty()]
        [string[]]$TeamIds,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByCsv')]
        [ValidateNotNullOrEmpty()]
        [string]$InputCsv,

        [Parameter(Mandatory = $false)]
        [switch]$SetSpoSiteReadOnly,

        [Parameter(Mandatory = $false)]
        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    if ($ExportPath -and ($ExportPath -match '\.\.[\\/]')) {
        Write-Error "ExportPath contains an invalid path-traversal sequence ('..'). Exiting."
        return
    }

    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1 — Resolve the raw TeamId list (array or CSV)
    # ─────────────────────────────────────────────────────────────────────────
    $rawIds = New-Object System.Collections.ArrayList

    if ($PSCmdlet.ParameterSetName -eq 'ByCsv') {
        if ($InputCsv -match '\.\.[\\/]') {
            Write-Error "InputCsv contains an invalid path-traversal sequence ('..'). Exiting."
            return
        }

        if (-not (Test-Path -Path $InputCsv)) {
            Write-Error "InputCsv path '$InputCsv' was not found. Exiting."
            return
        }

        Try {
            $csvRows = Import-Csv -Path $InputCsv -ErrorAction Stop
        }
        Catch {
            Write-Error "Failed to read InputCsv '$InputCsv': $($_.Exception.Message). Exiting."
            return
        }

        if (-not $csvRows -or $csvRows.Count -eq 0) {
            Write-Error "InputCsv '$InputCsv' contains no rows. Exiting."
            return
        }

        $idColumn = ($csvRows[0].PSObject.Properties.Name | Where-Object { $_ -in @('TeamId', 'Id') } | Select-Object -First 1)

        if (-not $idColumn) {
            Write-Error "InputCsv '$InputCsv' must contain a 'TeamId' or 'Id' column. Exiting."
            return
        }

        foreach ($row in $csvRows) {
            $val = $row.$idColumn
            if (-not [string]::IsNullOrWhiteSpace($val)) {
                $null = $rawIds.Add($val.Trim())
            }
        }
    }
    else {
        foreach ($id in $TeamIds) {
            $null = $rawIds.Add($id.Trim())
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2 — De-duplicate while preserving distinct entries
    # ─────────────────────────────────────────────────────────────────────────
    $uniqueIds = @($rawIds | Select-Object -Unique)
    $duplicatesRemoved = $rawIds.Count - $uniqueIds.Count

    if ($duplicatesRemoved -gt 0) {
        Write-Verbose "$duplicatesRemoved duplicate entr$(if ($duplicatesRemoved -eq 1) { 'y' } else { 'ies' }) removed from the input list."
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3 — Split valid-format GUIDs from invalid entries
    # ─────────────────────────────────────────────────────────────────────────
    $validIds = New-Object System.Collections.ArrayList
    $results = New-Object System.Collections.ArrayList

    foreach ($id in $uniqueIds) {
        if ($id -match $guidPattern) {
            $null = $validIds.Add($id)
        }
        else {
            $null = $results.Add([PSCustomObject]@{
                    teamId      = $id
                    displayName = $null
                    status      = "InvalidFormat"
                    detail      = "Not a valid GUID."
                })
        }
    }

    if ($validIds.Count -eq 0) {
        Write-Error "No valid-format Team IDs to process. Exiting."
        return
    }

    $headers = @{
        "Authorization"    = "Bearer $AccessToken"
        "ConsistencyLevel" = "eventual"
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4 — Verify each Team exists and is not already archived
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Verifying $($validIds.Count) Team(s)..." -ForegroundColor Cyan

    $toProcess = New-Object System.Collections.ArrayList
    $current = 0

    foreach ($id in $validIds) {
        $current++
        Write-Progress -Activity "Verifying Teams" -Status "$id ($current of $($validIds.Count))" -PercentComplete (($current / $validIds.Count) * 100)

        Try {
            $getResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/teams/$id`?`$select=id,displayName,isArchived" -Headers $headers -Method Get -ErrorAction Stop
            $teamInfo = $getResponse.Content | ConvertFrom-Json
        }
        Catch {
            $getStatus = $_.Exception.Response.StatusCode.value__
            if ($getStatus -eq 404) {
                $null = $results.Add([PSCustomObject]@{
                        teamId      = $id
                        displayName = $null
                        status      = "NotFound"
                        detail      = "No Microsoft Team found with this ID."
                    })
            }
            else {
                $null = $results.Add([PSCustomObject]@{
                        teamId      = $id
                        displayName = $null
                        status      = "Failed"
                        detail      = $_.Exception.Message
                    })
            }
            continue
        }

        if ($teamInfo.isArchived) {
            $null = $results.Add([PSCustomObject]@{
                    teamId      = $id
                    displayName = $teamInfo.displayName
                    status      = "AlreadyArchived"
                    detail      = "Team is already archived."
                })
        }
        else {
            $null = $toProcess.Add([PSCustomObject]@{
                    teamId      = $id
                    displayName = $teamInfo.displayName
                })
        }
    }

    Write-Progress -Activity "Verifying Teams" -Completed

    if ($toProcess.Count -eq 0) {
        Write-Host ""
        Write-Host "No Teams require archiving (all were already archived, not found, or invalid)." -ForegroundColor Yellow
    }
    else {
        # ─────────────────────────────────────────────────────────────────
        # STEP 5 — Single batch-level confirmation
        # ─────────────────────────────────────────────────────────────────
        if (-not $PSCmdlet.ShouldProcess("$($toProcess.Count) Microsoft Team(s)", "Archive")) {
            Write-Host "WhatIf: Would request archiving for $($toProcess.Count) Team(s)." -ForegroundColor Yellow
            $toProcess = @()
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 6 — Per-Team archive request, continue on error
    # ─────────────────────────────────────────────────────────────────────────
    if ($toProcess.Count -gt 0) {
        Write-Host ""
        Write-Host "Requesting archive for $($toProcess.Count) Team(s)..." -ForegroundColor Cyan

        $bodyObject = @{}
        if ($SetSpoSiteReadOnly) {
            $bodyObject["shouldSetSpoSiteReadOnlyForMembers"] = $true
        }
        $body = $bodyObject | ConvertTo-Json

        $current = 0
        foreach ($team in $toProcess) {
            $current++
            $errorDetail = $null
            Write-Progress -Activity "Archiving Teams" -Status "$($team.teamId) ($current of $($toProcess.Count))" -PercentComplete (($current / $toProcess.Count) * 100)

            $archiveStatus = $null
            $headers["Content-Type"] = "application/json"

            Try {
                $archiveResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/teams/$($team.teamId)/archive" -Headers $headers -Method Post -Body $body -ErrorAction Stop
                $archiveStatus = $archiveResponse.StatusCode
            }
            Catch {
                $archiveStatus = $_.Exception.Response.StatusCode.value__

                if ($archiveStatus -eq 429) {
                    $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                    Write-Host "Throttled. Waiting for $sleepTime seconds." -ForegroundColor Cyan
                    Start-Sleep -Seconds $sleepTime

                    Try {
                        $archiveResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/teams/$($team.teamId)/archive" -Headers $headers -Method Post -Body $body -ErrorAction Stop
                        $archiveStatus = $archiveResponse.StatusCode
                    }
                    Catch {
                        $archiveStatus = $_.Exception.Response.StatusCode.value__
                        $errorDetail = $_.Exception.Message
                    }
                }
                else {
                    $errorDetail = $_.Exception.Message
                }
            }
            $headers.Remove("Content-Type")

            if ($archiveStatus -eq 202) {
                $null = $results.Add([PSCustomObject]@{
                        teamId      = $team.teamId
                        displayName = $team.displayName
                        status      = "ArchiveRequested"
                        detail      = "Archive request accepted (async — completion not yet confirmed)."
                    })
                Write-Verbose "Archive requested for $($team.teamId)."
            }
            else {
                $detailText = if ($errorDetail) { $errorDetail } else { "HTTP status $archiveStatus." }
                $null = $results.Add([PSCustomObject]@{
                        teamId      = $team.teamId
                        displayName = $team.displayName
                        status      = "Failed"
                        detail      = $detailText
                    })
                Write-Warning "  Failed to archive '$($team.teamId)': $detailText"
            }
        }

        Write-Progress -Activity "Archiving Teams" -Completed
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 7 — Build summary
    # ─────────────────────────────────────────────────────────────────────────
    $summary = [PSCustomObject]@{
        totalRequested    = @($uniqueIds).Count
        duplicatesRemoved = $duplicatesRemoved
        archiveRequested  = @($results | Where-Object { $_.status -eq "ArchiveRequested" }).Count
        alreadyArchived   = @($results | Where-Object { $_.status -eq "AlreadyArchived" }).Count
        notFound          = @($results | Where-Object { $_.status -eq "NotFound" }).Count
        invalidFormat     = @($results | Where-Object { $_.status -eq "InvalidFormat" }).Count
        failed            = @($results | Where-Object { $_.status -eq "Failed" }).Count
        results           = $results
    }

    Write-Host ""
    Write-Host "Done. Archive requested: $($summary.archiveRequested)  Already archived: $($summary.alreadyArchived)  Not found: $($summary.notFound)  Invalid format: $($summary.invalidFormat)  Failed: $($summary.failed)" -ForegroundColor Green

    if ($summary.failed -gt 0) {
        Write-Warning "$($summary.failed) Team(s) failed to be archived. See the 'results' property (or CSV export) for details."
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 8 — CSV export (detailed per-Team results)
    # ─────────────────────────────────────────────────────────────────────────
    if ($ExportFormat -eq "CSV" -and $ExportPath) {
        $exportFolder = Split-Path -Path $ExportPath -Parent
        if ($exportFolder -and -not (Test-Path -Path $exportFolder)) {
            New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
        }

        $results | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Detailed results exported successfully → $ExportPath" -ForegroundColor Green
    }

    return $summary
}
