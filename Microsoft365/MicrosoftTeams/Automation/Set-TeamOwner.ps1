<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 10 August 2026
Modified-On     : 10 August 2026

.SYNOPSIS
    Assigns or removes owner(s) on a Microsoft Team using Microsoft Graph API,
    with a minimum-one-owner safety guard.

.DESCRIPTION
    This function manages ownership of a Microsoft Team by operating on the
    underlying Microsoft 365 Group's owners collection via Microsoft Graph
    v1.0. It supports both adding and removing owners in a single call and
    enforces a tenant-safe minimum-of-one-owner rule — removal is blocked
    for any user whose removal would leave the team with zero owners.

    For each supplied OwnerId, the function:
        - Verifies the user exists in Azure AD before attempting the operation.
        - For Add: checks whether the user is already an owner to keep the
          operation idempotent (no duplicate-owner error).
        - For Remove: checks current owner count first; blocks removal if it
          would leave zero owners.
        - Returns a per-action result object for every supplied OwnerId so
          callers can audit exactly what succeeded, was skipped, or failed.

    This function only accepts a direct Bearer token (AccessToken). It does
    not perform authentication itself. If you need to obtain a token via
    app-only (client credentials) authentication, use the companion
    Connect-EntraID.ps1 script referenced under .LINK below, then pass its
    returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Group.ReadWrite.All
        Directory.ReadWrite.All

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to Connect-EntraID.ps1 (see .LINK).

.PARAMETER TeamId
    The Azure AD Object ID (GUID) of the Microsoft Team (Group) to modify.
    This is the Group/Team ID, not the Team's internal channel ID.

.PARAMETER OwnerIds
    One or more Azure AD Object IDs (GUIDs) of users to add or remove as owners.
    All values must be valid GUIDs.

.PARAMETER Action
    Specifies whether to Add or Remove the supplied owners.
    Accepted values: Add, Remove
    - Add:    Grants ownership. Idempotent — skips users already owners.
    - Remove: Revokes ownership. Blocked if removal would leave zero owners.

.PARAMETER ExportFormat
    Specifies the output format for the action result set.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
        An array of PSCustomObjects — one per supplied OwnerId — containing:
        teamId, ownerId, action, status (Success / Skipped / Failed), detail.
        Also optionally exports to CSV.

.EXAMPLE
    Set-TeamOwner -AccessToken $token `
        -TeamId "11111111-1111-1111-1111-111111111111" `
        -OwnerIds "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb" `
        -Action Add

    Adds a single user as an owner of the specified team.

.EXAMPLE
    Set-TeamOwner -AccessToken $token `
        -TeamId "11111111-1111-1111-1111-111111111111" `
        -OwnerIds "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb","cccccccc-3333-4444-5555-dddddddddddd" `
        -Action Add

    Adds two users as owners. Any user already an owner is skipped (idempotent).

.EXAMPLE
    Set-TeamOwner -AccessToken $token `
        -TeamId "11111111-1111-1111-1111-111111111111" `
        -OwnerIds "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb" `
        -Action Remove

    Removes an owner. If this is the last remaining owner, the operation is
    blocked and a warning is emitted.

.EXAMPLE
    Set-TeamOwner -AccessToken $token `
        -TeamId "11111111-1111-1111-1111-111111111111" `
        -OwnerIds "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb" `
        -Action Add `
        -ExportFormat CSV `
        -ExportPath "C:\Reports\OwnerChanges.csv"

    Adds an owner and exports the per-action result set to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (10-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                Group.ReadWrite.All    (Application or Delegated)
                Directory.ReadWrite.All (required for owner add/remove)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Validate inputs (TeamId and all OwnerIds are valid GUIDs)
        Step 2  →  Verify the target Team (Group) exists in the tenant
        Step 3  →  Retrieve the current owners list for the team (once per call)
        Step 4  →  For each OwnerId:
                        Add:    Skip if already an owner; else POST /$ref
                        Remove: Block if last owner; else DELETE /$ref
        Step 5  →  Collect a per-action result object for each OwnerId
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permissions.
        - TeamId must be the Group Object ID (GUID); DisplayName resolution
            is not supported in v1.0.
        - The current owner count is resolved once at the start of the call.
            If another process removes an owner concurrently, the in-memory
            count may be stale. The minimum-owner guard is best-effort.
        - Guest/external users may not be assignable as owners depending on
            tenant guest access policy; such failures surface as a warning
            with the Graph error message in the result detail field.

.LINK
    Microsoft Graph API - Add group owner
    https://learn.microsoft.com/en-us/graph/api/group-post-owners

.LINK
    Microsoft Graph API - Remove group owner
    https://learn.microsoft.com/en-us/graph/api/group-delete-owners

.LINK
    Microsoft Graph API - List group owners
    https://learn.microsoft.com/en-us/graph/api/group-list-owners

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Set-TeamOwner {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$TeamId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$OwnerIds,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Add", "Remove")]
        [string]$Action,

        [Parameter(Mandatory = $false)]
        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ExportPath
    )

    # ── Shared headers ────────────────────────────────────────────────────────
    $headers = @{
        "Authorization"    = "Bearer $AccessToken"
        "Content-Type"     = "application/json"
        "ConsistencyLevel" = "eventual"
    }

    # ── Helper: Invoke-GraphApiRequest with 429 retry ────────────────────────────
    function Invoke-GraphApiRequest {
        param (
            [string]$Uri,
            [string]$Method = "Get",
            [hashtable]$Headers,
            [string]$Body
        )

        $statusCode = $null
        $response = $null
        $skip = $false

        do {
            Try {
                $params = @{
                    Uri         = $Uri
                    Method      = $Method
                    Headers     = $Headers
                    ErrorAction = "Stop"
                }
                if ($Body) { $params["Body"] = $Body }

                $response = Invoke-WebRequest @params
                $statusCode = $response.StatusCode
            }
            catch {
                $statusCode = $_.Exception.Response.StatusCode

                if ($statusCode -eq 429) {
                    $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                    Write-Host "Throttled. Waiting for $sleepTime seconds." -ForegroundColor Cyan
                    Start-Sleep -Seconds $sleepTime
                }
                else {
                    $script:LastGraphError = [PSCustomObject][ordered]@{
                        Uri        = $Uri
                        Method     = $Method
                        StatusCode = $statusCode
                        Message    = $_.Exception.Message
                    }
                    $skip = $true
                }
            }
        } until (($statusCode -eq 200) -or ($statusCode -eq 201) -or ($statusCode -eq 204) -or $skip)

        if ($skip) { return $null }
        return $response
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1 — Validate all OwnerIds are valid GUIDs
    # ─────────────────────────────────────────────────────────────────────────
    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

    foreach ($oid in $OwnerIds) {
        if ($oid -notmatch $guidPattern) {
            Write-Error "OwnerIds contains an invalid GUID: '$oid'. All OwnerIds must be valid Azure AD Object IDs."
            return
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2 — Verify the target Team (Group) exists
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Verifying Team '$TeamId' exists..." -ForegroundColor Cyan

    $script:LastGraphError = $null
    $teamCheckResponse = Invoke-GraphApiRequest `
        -Uri     "https://graph.microsoft.com/v1.0/groups/$TeamId`?`$select=id,displayName" `
        -Method  "Get" `
        -Headers $headers

    if (-not $teamCheckResponse) {
        Write-Host ""
        $script:LastGraphError | Format-List
        Write-Error "Team '$TeamId' could not be found or accessed. Exiting."
        return
    }

    $teamInfo = $teamCheckResponse.Content | ConvertFrom-Json
    $teamDisplayName = $teamInfo.displayName

    Write-Host "Team found: '$teamDisplayName' ($TeamId)" -ForegroundColor Green

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3 — Retrieve current owners list (once per call)
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Retrieving current owners for '$teamDisplayName'..." -ForegroundColor Cyan

    $currentOwnerIds = New-Object System.Collections.ArrayList
    $ownersUri = "https://graph.microsoft.com/v1.0/groups/$TeamId/owners?`$select=id,displayName&`$top=100"

    do {
        $script:LastGraphError = $null
        $ownersResponse = Invoke-GraphApiRequest -Uri $ownersUri -Method "Get" -Headers $headers

        if (-not $ownersResponse) {
            Write-Host ""
            $script:LastGraphError | Format-List
            Write-Error "Failed to retrieve current owners for Team '$TeamId'. Exiting."
            return
        }

        $ownersData = $ownersResponse.Content | ConvertFrom-Json
        $ownersData.value | ForEach-Object { $null = $currentOwnerIds.Add($_.id) }

        if ($ownersData.PSObject.Properties['@odata.nextLink']) { $ownersUri = $ownersData.'@odata.nextLink' } else { $ownersUri = $null }

    } until (-not $ownersUri)

    Write-Host "Current owner count: $($currentOwnerIds.Count)" -ForegroundColor Cyan

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4 — Process each OwnerId
    # ─────────────────────────────────────────────────────────────────────────
    $results = New-Object System.Collections.ArrayList
    # Track effective count in memory for the minimum-owner guard during Remove loops
    $effectiveOwnerCount = $currentOwnerIds.Count

    foreach ($oid in $OwnerIds) {
        $resultEntry = [PSCustomObject][ordered]@{
            teamId   = $TeamId
            teamName = $teamDisplayName
            ownerId  = $oid
            action   = $Action
            status   = "Pending"
            detail   = ""
        }

        if ($Action -eq "Add") {
            # Idempotency check — skip if already an owner
            if ($currentOwnerIds -contains $oid) {
                Write-Host "  ~ Skipped (already an owner): $oid" -ForegroundColor Yellow
                $resultEntry.status = "Skipped"
                $resultEntry.detail = "User is already an owner of this team."
                $null = $results.Add($resultEntry)
                continue
            }

            if (-not $PSCmdlet.ShouldProcess("Team '$teamDisplayName'", "Add owner '$oid'")) {
                $resultEntry.status = "WhatIf"
                $resultEntry.detail = "WhatIf: Would add owner '$oid'."
                $null = $results.Add($resultEntry)
                continue
            }

            $ownerBody = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/users/$oid"
            } | ConvertTo-Json

            $script:LastGraphError = $null
            $addResponse = Invoke-GraphApiRequest `
                -Uri     "https://graph.microsoft.com/v1.0/groups/$TeamId/owners/`$ref" `
                -Method  "Post" `
                -Headers $headers `
                -Body    $ownerBody

            if ($addResponse -or (-not $script:LastGraphError)) {
                Write-Host "  ✓ Owner added: $oid" -ForegroundColor Green
                $resultEntry.status = "Success"
                $resultEntry.detail = "Owner added successfully."
                $null = $currentOwnerIds.Add($oid)
                $effectiveOwnerCount++
            }
            else {
                Write-Warning "  ✗ Failed to add owner '$oid': $($script:LastGraphError.Message)"
                $resultEntry.status = "Failed"
                $resultEntry.detail = $script:LastGraphError.Message
            }
        }
        elseif ($Action -eq "Remove") {
            # Minimum-owner safety guard
            if ($effectiveOwnerCount -le 1) {
                Write-Warning "  ✗ Blocked: Removing '$oid' would leave Team '$teamDisplayName' with no owners. Operation skipped."
                $resultEntry.status = "Skipped"
                $resultEntry.detail = "Removal blocked — would leave team with zero owners. Minimum one owner required."
                $null = $results.Add($resultEntry)
                continue
            }

            # Check the user is actually a current owner before attempting removal
            if ($currentOwnerIds -notcontains $oid) {
                Write-Host "  ~ Skipped (not a current owner): $oid" -ForegroundColor Yellow
                $resultEntry.status = "Skipped"
                $resultEntry.detail = "User is not a current owner of this team."
                $null = $results.Add($resultEntry)
                continue
            }

            if (-not $PSCmdlet.ShouldProcess("Team '$teamDisplayName'", "Remove owner '$oid'")) {
                $resultEntry.status = "WhatIf"
                $resultEntry.detail = "WhatIf: Would remove owner '$oid'."
                $null = $results.Add($resultEntry)
                continue
            }

            $script:LastGraphError = $null
            $removeResponse = Invoke-GraphApiRequest `
                -Uri     "https://graph.microsoft.com/v1.0/groups/$TeamId/owners/$oid/`$ref" `
                -Method  "Delete" `
                -Headers $headers

            if ($removeResponse -or (-not $script:LastGraphError)) {
                Write-Host "  ✓ Owner removed: $oid" -ForegroundColor Green
                $resultEntry.status = "Success"
                $resultEntry.detail = "Owner removed successfully."
                $null = $currentOwnerIds.Remove($oid)
                $effectiveOwnerCount--
            }
            else {
                Write-Warning "  ✗ Failed to remove owner '$oid': $($script:LastGraphError.Message)"
                $resultEntry.status = "Failed"
                $resultEntry.detail = $script:LastGraphError.Message
            }
        }

        $null = $results.Add($resultEntry)
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 5 — Summary
    # ─────────────────────────────────────────────────────────────────────────
    $successCount = @($results | Where-Object { $_.status -eq "Success" }).Count
    $skippedCount = @($results | Where-Object { $_.status -eq "Skipped" }).Count
    $failedCount = @($results | Where-Object { $_.status -eq "Failed" }).Count

    Write-Host ""
    Write-Host "Owner update complete for '$teamDisplayName'." -ForegroundColor Green
    Write-Host "  Succeeded : $successCount" -ForegroundColor Green
    Write-Host "  Skipped   : $skippedCount" -ForegroundColor Yellow
    Write-Host "  Failed    : $failedCount"  -ForegroundColor $(if ($failedCount -gt 0) { "Red" } else { "Green" })

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 6 — CSV export (if requested)
    # ─────────────────────────────────────────────────────────────────────────
    if ($ExportFormat -eq "CSV" -and $ExportPath) {
        $exportFolder = Split-Path -Path $ExportPath -Parent
        if ($exportFolder -and -not (Test-Path -Path $exportFolder)) {
            New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
        }

        $results | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Owner change report exported successfully → $ExportPath" -ForegroundColor Green
    }

    return $results
}
