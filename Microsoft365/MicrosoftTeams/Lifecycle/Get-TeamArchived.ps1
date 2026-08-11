<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 10 August 2026
Modified-On     : 10 August 2026

.SYNOPSIS
    Lists archived Microsoft Teams — either across the whole tenant, or
    limited to a specified list of Team IDs — using Microsoft Graph API.

.DESCRIPTION
    This function reports which Microsoft Teams are currently archived.
    It runs in one of three modes, chosen automatically from the
    parameters supplied:

        - TenantWide (default, no -TeamIds / -InputCsv given): discovers
          every Teams-provisioned Microsoft 365 Group in the tenant
          (GET /groups filtered on resourceProvisioningOptions), then
          checks each one's archive state.
        - ByArray (-TeamIds): checks only the supplied GUIDs.
        - ByCsv (-InputCsv): checks the GUIDs listed in a CSV file's
          'TeamId' or 'Id' column.

    Execution flow:
        1. Authenticate using the caller-supplied AccessToken (no
           internal authentication is performed).
        2. Resolve scope — either enumerate all Teams-provisioned groups
           tenant-wide, or use the caller-supplied TeamId list/CSV
           (de-duplicated; non-GUID entries reported as InvalidFormat).
        3. For each candidate Team, GET /teams/{id} inside a per-resource
           try/catch, categorizing the result as Archived, NotArchived,
           NotFound, or Failed. One failure never stops the scan.
        4. Aggregate counts and build the list of archived Teams.
        5. Optionally export the archived-Teams list to CSV.

    This is a read-only reporting function — it makes no changes and does
    not support -WhatIf/-Confirm.

    This function only accepts a direct Bearer token (AccessToken). It
    does not perform authentication itself. If you need to obtain a token
    via app-only (client credentials) authentication, use the companion
    Connect-EntraID.ps1 script referenced under .LINK below, then pass its
    returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions (least privileged):
        Team.ReadBasic.All  (Application or Delegated) — to read each
            Team's archive state.
        Group.Read.All      (Application or Delegated) — only needed for
            TenantWide mode, to enumerate Teams-provisioned groups.

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to Connect-EntraID.ps1 (see .LINK).

.PARAMETER TeamIds
    One or more Team IDs (GUIDs) to check. Switches the function into
    ByArray mode. Mutually exclusive with -InputCsv. Omit both this and
    -InputCsv to scan the whole tenant instead.

.PARAMETER InputCsv
    Path to a CSV file containing the Teams to check. The file must have
    a column named 'TeamId' or 'Id' (case-insensitive) holding each
    Team's GUID. Switches the function into ByCsv mode. Mutually
    exclusive with -TeamIds. Rejected if the path contains a '..'
    path-traversal sequence.

.PARAMETER ExportFormat
    Specifies the output format for the archived-Teams list.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV. Rejected if it contains
    a '..' path-traversal sequence.

.PARAMETER IncludeAllResults
    Optional switch. By default this function returns just the archived
    Teams (an array of PSCustomObjects). Pass this switch to instead get
    back the full summary object — scope, all counts, archivedTeams, and
    the complete per-candidate results (including NotArchived/NotFound/
    Failed entries).

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    Default: an array of PSCustomObjects, one per archived Team
        (teamId, displayName, visibility, webUrl) — empty if none are
        archived.
    With -IncludeAllResults: a single PSCustomObject summary — scope
        (TenantWide/Specified), totalScanned, archived, notArchived,
        notFound, invalidFormat, failed, archivedTeams (same array as
        the default output), and results (the full per-Team scan
        outcome, including non-archived/failed entries).
    CSV export always writes archivedTeams, not the full results,
        regardless of -IncludeAllResults.

.EXAMPLE
    Get-TeamArchived -AccessToken $token

    Scans every Teams-provisioned group in the tenant and returns the
    ones that are currently archived.

.EXAMPLE
    Get-TeamArchived -AccessToken $token -TeamIds "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb","cccccccc-3333-4444-5555-dddddddddddd"

    Checks only the two specified Teams' archive state.

.EXAMPLE
    Get-TeamArchived -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\ArchivedTeams.csv"

    Scans the whole tenant and exports the archived-Teams list to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (10-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Execution Flow:
    ─────────────────────────────────────────────────────────────────────────────
        1. Authenticate using the caller-supplied AccessToken.
        2. Resolve scope: tenant-wide Teams-provisioned groups (default),
           or the caller-supplied TeamId list/CSV.
        3. Per-candidate try/catch call to Get team, categorizing
           Archived / NotArchived / NotFound / Failed — one failure does
           not stop the scan.
        4. Aggregate counts and build the archived-Teams list.
        5. Optionally export the archived-Teams list to CSV.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                Team.ReadBasic.All   (Application or Delegated)
                Group.Read.All       (Application or Delegated — TenantWide
                    mode only)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - TenantWide mode's group discovery query relies on the
            resourceProvisioningOptions/Any() filter, which requires the
            ConsistencyLevel: eventual header (applied automatically);
            very large tenants may see eventually-consistent results
            immediately after a Team is created or deleted.
        - No retry-on-throttle logic is applied to the tenant-wide group
            discovery page requests (only to the per-Team GET calls) —
            a 429 during discovery will surface as a terminating error.
        - CSV export writes only the archivedTeams list, not the full
            per-candidate results (which includes NotArchived/Failed
            entries); inspect the returned object's 'results' property
            for the complete scan detail.

.LINK
    Microsoft Graph API - Get team
    https://learn.microsoft.com/en-us/graph/api/team-get

.LINK
    Microsoft Graph API - List groups
    https://learn.microsoft.com/en-us/graph/api/group-list

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamArchived {
    [CmdletBinding(DefaultParameterSetName = 'TenantWide')]
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
        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ExportPath,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeAllResults
    )

    if ($ExportPath -and ($ExportPath -match '\.\.[\\/]')) {
        Write-Error "ExportPath contains an invalid path-traversal sequence ('..'). Exiting."
        return
    }

    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

    $headers = @{
        "Authorization"    = "Bearer $AccessToken"
        "ConsistencyLevel" = "eventual"
    }

    $results = New-Object System.Collections.ArrayList
    $candidateIds = New-Object System.Collections.ArrayList
    $duplicatesRemoved = 0
    $scope = $PSCmdlet.ParameterSetName

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1 — Resolve scope
    # ─────────────────────────────────────────────────────────────────────────
    if ($scope -eq 'TenantWide') {
        Write-Host ""
        Write-Host "Discovering Teams-provisioned groups tenant-wide..." -ForegroundColor Cyan

        $groupsUri = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$select=id&`$top=999&`$count=true"

        Try {
            do {
                $groupsResponse = Invoke-WebRequest -Uri $groupsUri -Headers $headers -Method Get -ErrorAction Stop
                $groupsData = $groupsResponse.Content | ConvertFrom-Json

                foreach ($grp in $groupsData.value) {
                    $null = $candidateIds.Add($grp.id)
                }

                if ($groupsData.PSObject.Properties.Name -contains '@odata.nextLink') {
                    $groupsUri = $groupsData.'@odata.nextLink'
                }
                else {
                    $groupsUri = $null
                }
            } while ($groupsUri)
        }
        Catch {
            Write-Error "Failed to enumerate Teams-provisioned groups: $($_.Exception.Message). Exiting."
            return
        }

        Write-Host "Found $($candidateIds.Count) Teams-provisioned group(s) to check." -ForegroundColor Green
    }
    else {
        $rawIds = New-Object System.Collections.ArrayList

        if ($scope -eq 'ByCsv') {
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

        $uniqueIds = @($rawIds | Select-Object -Unique)
        $duplicatesRemoved = $rawIds.Count - $uniqueIds.Count

        if ($duplicatesRemoved -gt 0) {
            Write-Verbose "$duplicatesRemoved duplicate entr$(if ($duplicatesRemoved -eq 1) { 'y' } else { 'ies' }) removed from the input list."
        }

        foreach ($id in $uniqueIds) {
            if ($id -match $guidPattern) {
                $null = $candidateIds.Add($id)
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

        if ($candidateIds.Count -eq 0) {
            Write-Error "No valid-format Team IDs to check. Exiting."
            return
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2 — Per-Team check, continue on error
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Checking archive state for $($candidateIds.Count) Team(s)..." -ForegroundColor Cyan

    $current = 0
    foreach ($id in $candidateIds) {
        $current++
        Write-Progress -Activity "Checking Teams" -Status "$id ($current of $($candidateIds.Count))" -PercentComplete (($current / $candidateIds.Count) * 100)

        Try {
            $teamResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/teams/$id`?`$select=id,displayName,isArchived,visibility,webUrl" -Headers $headers -Method Get -ErrorAction Stop
            $teamInfo = $teamResponse.Content | ConvertFrom-Json
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
                    status      = "Archived"
                    detail      = $teamInfo.visibility
                    webUrl      = $teamInfo.webUrl
                })
        }
        else {
            $null = $results.Add([PSCustomObject]@{
                    teamId      = $id
                    displayName = $teamInfo.displayName
                    status      = "NotArchived"
                    detail      = $null
                })
        }
    }

    Write-Progress -Activity "Checking Teams" -Completed

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3 — Build archived-Teams list and summary
    # ─────────────────────────────────────────────────────────────────────────
    $archivedTeams = @($results | Where-Object { $_.status -eq "Archived" } | ForEach-Object {
            [PSCustomObject]@{
                teamId      = $_.teamId
                displayName = $_.displayName
                visibility  = $_.detail
                webUrl      = $_.webUrl
            }
        })

    $summary = [PSCustomObject]@{
        scope             = $scope
        totalScanned      = @($candidateIds).Count
        duplicatesRemoved = $duplicatesRemoved
        archived          = @($archivedTeams).Count
        notArchived       = @($results | Where-Object { $_.status -eq "NotArchived" }).Count
        notFound          = @($results | Where-Object { $_.status -eq "NotFound" }).Count
        invalidFormat     = @($results | Where-Object { $_.status -eq "InvalidFormat" }).Count
        failed            = @($results | Where-Object { $_.status -eq "Failed" }).Count
        archivedTeams     = $archivedTeams
        results           = $results
    }

    Write-Host ""
    Write-Host "Done. Archived: $($summary.archived)  Not archived: $($summary.notArchived)  Not found: $($summary.notFound)  Invalid format: $($summary.invalidFormat)  Failed: $($summary.failed)" -ForegroundColor Green

    if ($summary.failed -gt 0) {
        Write-Warning "$($summary.failed) Team(s) could not be checked. See the 'results' property for details."
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4 — CSV export (archived Teams only)
    # ─────────────────────────────────────────────────────────────────────────
    if ($ExportFormat -eq "CSV" -and $ExportPath) {
        $exportFolder = Split-Path -Path $ExportPath -Parent
        if ($exportFolder -and -not (Test-Path -Path $exportFolder)) {
            New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
        }

        $archivedTeams | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Archived-Teams list exported successfully → $ExportPath" -ForegroundColor Green
    }

    if ($IncludeAllResults) {
        return $summary
    }

    return $archivedTeams
}
