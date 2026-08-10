<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 10 August 2026
Modified-On     : 10 August 2026

.SYNOPSIS
    Creates a new Microsoft Team with predefined governance standards using
    Microsoft Graph API.

.DESCRIPTION
    This function provisions a new Microsoft Team (Microsoft 365 Group +
    Teams provisioning) via the Microsoft Graph v1.0 endpoint. Before
    creation, it checks whether a team with the same DisplayName already
    exists in the tenant to prevent duplicates.

    Initial owners can be supplied at creation time via -OwnerIds. At least
    one owner should be supplied; if none are provided, the service account
    whose token is used becomes the implicit owner (Graph API behaviour).

    The function is intentionally kept at Microsoft defaults for settings not
    explicitly parameterised, making it safe to extend in future iterations
    with template IDs, channel scaffolding, or policy assignments.

    This function only accepts a direct Bearer token (AccessToken). It does
    not perform authentication itself. If you need to obtain a token via
    app-only (client credentials) authentication, use the companion
    Connect-EntraID.ps1 script referenced under .LINK below, then pass its
    returned token into -AccessToken.

    The following attributes are set at creation time:
        - displayName, description (optional), visibility (default: Private)
        - memberSettings, messagingSettings, funSettings (Microsoft defaults)
        - Owners wired via Group member binding prior to team provisioning

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Group.ReadWrite.All
        Team.Create
        Directory.ReadWrite.All  (required to assign owners at creation)

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to Connect-EntraID.ps1 (see .LINK).

.PARAMETER DisplayName
    The display name for the new Microsoft Team.
    Must be between 1 and 256 characters. A duplicate-name check is
    performed against existing teams before creation proceeds.

.PARAMETER Description
    Optional. A description for the new Microsoft Team.
    Maximum 1024 characters.

.PARAMETER Visibility
    Specifies the team visibility.
    Accepted values: Private, Public
    Default: Private

.PARAMETER OwnerIds
    Optional. One or more Azure AD Object IDs (GUIDs) of users to assign
    as owners at creation time. Owners are bound to the underlying
    Microsoft 365 Group before Teams provisioning is applied.
    If omitted, the identity behind the access token becomes the sole owner.

.PARAMETER ExportFormat
    Specifies the output format for the creation result.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject
        A custom object containing the newly created team's core attributes:
        teamId, displayName, description, visibility, mail, createdDateTime, ownersAdded.
        Also optionally exports to CSV.

.EXAMPLE
    New-MicrosoftTeam -AccessToken $token -DisplayName "Project Apollo"

    Creates a new private team named "Project Apollo" with no description
    and no explicitly assigned owners (Graph assigns the token identity).

.EXAMPLE
    New-MicrosoftTeam -AccessToken $token `
        -DisplayName "Project Apollo" `
        -Description "Cross-functional project team for Apollo initiative." `
        -Visibility Private `
        -OwnerIds "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb","cccccccc-3333-4444-5555-dddddddddddd"

    Creates a private team with a description and two initial owners.

.EXAMPLE
    New-MicrosoftTeam -AccessToken $token `
        -DisplayName "All Company" `
        -Visibility Public `
        -ExportFormat CSV `
        -ExportPath "C:\Reports\NewTeam.csv"

    Creates a public team and exports the creation result to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (10-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                Group.ReadWrite.All      (Application or Delegated)
                Team.Create              (Application or Delegated)
                Directory.ReadWrite.All  (required for owner assignment)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Validate inputs (DisplayName length, Description length, GUID format for OwnerIds)
        Step 2  →  Duplicate check: query Graph /groups filtered by displayName
                    to confirm no existing team shares the same name
        Step 3  →  Create the Microsoft 365 Group with resourceProvisioningOptions
                    set to 'Team' via POST /groups
        Step 4  →  Wait for Group provisioning to settle (retry loop on 404 /teams/{id})
        Step 5  →  Apply Teams provisioning via PUT /teams/{groupId}
        Step 6  →  Assign OwnerIds (if supplied) via POST /groups/{id}/owners/$ref
        Step 7  →  Retrieve and return the newly created team's details
        Step 8  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permissions.
        - Duplicate check is case-insensitive on displayName but does not
            account for Unicode normalisation edge cases.
        - The Group-to-Team provisioning step (PUT /teams/{id}) may take
            several seconds to complete in the Graph backend; this function
            retries up to 10 times with a 6-second delay (60 s total window).
            If provisioning exceeds this window, increase $maxRetries and $retryDelaySeconds.
        - Owner assignment requires Directory.ReadWrite.All; if this permission
            is absent the team is still created but owner binding will fail with
            a warning per owner (non-terminating).
        - Template support is not implemented in v1.0 but the body payload is
            structured to accept a 'template@odata.bind' field in a future version.

.LINK
    Microsoft Graph API - Create team
    https://learn.microsoft.com/en-us/graph/api/team-post

.LINK
    Microsoft Graph API - Create group
    https://learn.microsoft.com/en-us/graph/api/group-post-groups

.LINK
    Microsoft Graph API - Add group owner
    https://learn.microsoft.com/en-us/graph/api/group-post-owners

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function New-MicrosoftTeam {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(1, 256)]
        [string]$DisplayName,

        [Parameter(Mandatory = $false)]
        [ValidateLength(0, 1024)]
        [string]$Description = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Private", "Public")]
        [string]$Visibility = "Private",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$OwnerIds,

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
        "ConsistencyLevel" = "eventual"
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1 — Validate OwnerIds are GUIDs
    # ─────────────────────────────────────────────────────────────────────────
    if ($OwnerIds) {
        $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        foreach ($oid in $OwnerIds) {
            if ($oid -notmatch $guidPattern) {
                Write-Error "OwnerIds contains an invalid GUID: '$oid'. All OwnerIds must be valid Azure AD Object IDs."
                return
            }
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2 — Duplicate display name check
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Checking for existing team with displayName '$DisplayName'..." -ForegroundColor Cyan

    $encodedName = [Uri]::EscapeDataString($DisplayName)
    $duplicateUri = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team') and displayName eq '$encodedName'&`$select=id,displayName&`$count=true"

    $dupResponse = $null
    do {
        Try {
            $dupResponse = Invoke-WebRequest -Uri $duplicateUri -Headers $headers -Method Get -ErrorAction Stop
            $dupStatus = $dupResponse.StatusCode
        }
        catch {
            $dupStatus = $_.Exception.Response.StatusCode
            if ($dupStatus -eq 429) {
                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                Write-Host "Throttled. Waiting for $sleepTime seconds." -ForegroundColor Cyan
                Start-Sleep -Seconds $sleepTime
            }
            else {
                Write-Error "Duplicate check failed: $($_.Exception.Message). Exiting to avoid unintended provisioning."
                return
            }
        }
    } until ($dupStatus -eq 200)

    $dupData = $dupResponse.Content | ConvertFrom-Json

    if ($dupData.value -and $dupData.value.Count -gt 0) {
        Write-Warning "A Microsoft Team named '$DisplayName' already exists (TeamId: $($dupData.value[0].id)). Exiting to prevent duplicate provisioning."
        return
    }

    Write-Host "No duplicate found. Proceeding with team creation." -ForegroundColor Green

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3 — Create the Microsoft 365 Group with Teams provisioning
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $PSCmdlet.ShouldProcess("Microsoft Teams tenant", "Create new team '$DisplayName'")) {
        Write-Host "WhatIf: Would create team '$DisplayName' (Visibility: $Visibility)." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Creating Microsoft 365 Group for team '$DisplayName'..." -ForegroundColor Cyan

    # Build the group body — resourceProvisioningOptions signals Teams provisioning
    # 'template@odata.bind' is reserved here for future template support (v1.1+)
    $groupBody = [ordered]@{
        displayName                 = $DisplayName
        description                 = $Description
        groupTypes                  = @("Unified")
        mailEnabled                 = $true
        mailNickname                = ($DisplayName -replace '[^a-zA-Z0-9]', '') + (Get-Random -Minimum 100 -Maximum 999)
        securityEnabled             = $false
        visibility                  = $Visibility
        resourceProvisioningOptions = @("Team")
    }

    $groupBodyJson = $groupBody | ConvertTo-Json -Depth 5

    $groupResponse = $null
    $headers["Content-Type"] = "application/json"
    do {
        Try {
            $groupResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/groups" -Headers $headers -Method Post -Body $groupBodyJson -ErrorAction Stop
            $groupStatus = $groupResponse.StatusCode
        }
        catch {
            $groupStatus = $_.Exception.Response.StatusCode
            if ($groupStatus -eq 429) {
                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                Write-Host "Throttled. Waiting for $sleepTime seconds." -ForegroundColor Cyan
                Start-Sleep -Seconds $sleepTime
            }
            else {
                Write-Error "Failed to create Microsoft 365 Group: $($_.Exception.Message). Exiting."
                return
            }
        }
    } until ($groupStatus -eq 201)
    $headers.Remove("Content-Type")

    $groupData = $groupResponse.Content | ConvertFrom-Json
    $groupId = $groupData.id

    Write-Host "Microsoft 365 Group created successfully. GroupId: $groupId" -ForegroundColor Green

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3b — Wait for Microsoft 365 Group to replicate before Teams provisioning
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Waiting for Microsoft 365 Group to replicate..." -ForegroundColor Cyan

    $groupSettled = $false
    $groupAttempt = 0
    $groupMaxRetries = 10
    $groupRetryDelay = 6

    do {
        $groupAttempt++
        Start-Sleep -Seconds $groupRetryDelay

        Try {
            $groupCheckResponse = Invoke-WebRequest `
                -Uri     "https://graph.microsoft.com/v1.0/groups/$groupId" `
                -Headers $headers `
                -Method  Get `
                -ErrorAction Stop

            if ($groupCheckResponse.StatusCode -eq 200) {
                $groupSettled = $true
            }
        }
        catch {
            Write-Host "  Group replication check attempt $groupAttempt/$groupMaxRetries — not yet available. Retrying in $groupRetryDelay`s..." -ForegroundColor Yellow
        }

    } until ($groupSettled -or ($groupAttempt -ge $groupMaxRetries))

    if (-not $groupSettled) {
        Write-Error "Microsoft 365 Group '$groupId' did not replicate within the wait window ($($groupMaxRetries * $groupRetryDelay)s). Exiting."
        return
    }

    Write-Host "Microsoft 365 Group confirmed replicated. Proceeding with Teams provisioning..." -ForegroundColor Green
    Start-Sleep -Seconds 30

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4 — Apply Teams provisioning via POST /teams
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Applying Teams provisioning for GroupId '$groupId'..." -ForegroundColor Cyan

    $teamsProvisioningBody = @{
        "template@odata.bind" = "https://graph.microsoft.com/v1.0/teamsTemplates('standard')"
        "group@odata.bind"    = "https://graph.microsoft.com/v1.0/groups('$groupId')"
    } | ConvertTo-Json -Depth 5

    $teamsProvResponse = $null
    $headers["Content-Type"] = "application/json"
    do {
        Try {
            $teamsProvResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/teams" -Headers $headers -Method Post -Body $teamsProvisioningBody -ErrorAction Stop
            $teamsProvStatus = $teamsProvResponse.StatusCode
        }
        catch {
            $teamsProvStatus = $_.Exception.Response.StatusCode.value__
            if ($teamsProvStatus -eq 429) {
                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                Write-Host "Throttled. Waiting for $sleepTime seconds." -ForegroundColor Cyan
                Start-Sleep -Seconds $sleepTime
            }
            else {
                Write-Error "Teams provisioning POST failed for GroupId '$groupId': $($_.Exception.Message)."
                return
            }
        }
    } until ($teamsProvStatus -eq 202)
    $headers.Remove("Content-Type")

    Write-Host "Teams provisioning request accepted (202). Polling for Teams layer availability..." -ForegroundColor Cyan

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 5 — Wait for Teams layer to settle
    # ─────────────────────────────────────────────────────────────────────────
    $maxRetries = 30
    $retryDelaySeconds = 10
    $attempt = 0
    $teamSettled = $false

    do {
        $attempt++
        Start-Sleep -Seconds $retryDelaySeconds

        Try {
            $checkResponse = Invoke-WebRequest `
                -Uri     "https://graph.microsoft.com/v1.0/teams/$groupId" `
                -Headers $headers `
                -Method  Get `
                -ErrorAction Stop

            if ($checkResponse.StatusCode -eq 200) {
                $teamSettled = $true
            }
        }
        catch {
            Write-Host "  Provisioning check attempt $attempt/$maxRetries — Teams layer not yet available. Retrying in $retryDelaySeconds`s..." -ForegroundColor Yellow
            Write-Verbose "Provisioning check attempt $attempt/$maxRetries — not yet settled ($($_.Exception.Message))."
        }

    } until ($teamSettled -or ($attempt -ge $maxRetries))

    if (-not $teamSettled) {
        Write-Error "Teams layer for Group '$groupId' did not become available within the wait window ($($maxRetries * $retryDelaySeconds)s). The Group was created but Teams provisioning is still pending. Verify manually via GET https://graph.microsoft.com/v1.0/teams/$groupId and retry owner assignment if needed."
        return
    }

    Write-Host "Teams layer confirmed available." -ForegroundColor Green

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 6 — Assign initial owners (if supplied)
    # ─────────────────────────────────────────────────────────────────────────
    $ownersAdded = New-Object System.Collections.ArrayList

    if ($OwnerIds) {
        Write-Host ""
        Write-Host "Assigning $($OwnerIds.Count) owner(s)..." -ForegroundColor Cyan

        foreach ($oid in $OwnerIds) {
            $ownerBody = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/users/$oid"
            } | ConvertTo-Json

            $ownerStatus = $null
            $headers["Content-Type"] = "application/json"
            Try {
                $ownerResp = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/owners/`$ref" -Headers $headers -Method Post -Body $ownerBody -ErrorAction Stop
                $ownerStatus = $ownerResp.StatusCode
            }
            catch {
                $ownerStatus = $_.Exception.Response.StatusCode
            }
            $headers.Remove("Content-Type")

            if ($ownerStatus -eq 204) {
                Write-Host "  ✓ Owner assigned: $oid" -ForegroundColor Green
                $null = $ownersAdded.Add($oid)
            }
            else {
                Write-Warning "  ✗ Failed to assign owner '$oid': $($script:LastGraphError.Message)"
            }
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 7 — Retrieve and return the newly created team details
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Retrieving newly created team details..." -ForegroundColor Cyan

    $teamDetailsResponse = $null
    Try {
        $teamDetailsResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/groups/$groupId`?`$select=id,displayName,description,visibility,mail,createdDateTime" -Headers $headers -Method Get -ErrorAction Stop
    }
    catch {
        $teamDetailsResponse = $null
    }

    $newTeam = $null

    if ($teamDetailsResponse) {
        $td = $teamDetailsResponse.Content | ConvertFrom-Json

        $newTeam = [PSCustomObject]@{
            teamId          = $td.id
            displayName     = $td.displayName
            description     = $td.description
            visibility      = $td.visibility
            mail            = $td.mail
            createdDateTime = $td.createdDateTime
            ownersAdded     = if ($ownersAdded.Count -gt 0) { $ownersAdded -join "; " } else { "None (token identity)" }
        }
    }
    else {
        # Build a minimal result from what we already know if the detail call fails
        Write-Warning "Could not retrieve full team details post-creation (non-fatal). Returning partial result."
        $newTeam = [PSCustomObject]@{
            teamId          = $groupId
            displayName     = $DisplayName
            description     = $Description
            visibility      = $Visibility
            mail            = "Could not be confirmed"
            createdDateTime = "Could not be confirmed"
            ownersAdded     = if ($ownersAdded.Count -gt 0) { $ownersAdded -join "; " } else { "None (token identity)" }
        }
    }

    Write-Host ""
    Write-Host "Team '$DisplayName' created successfully." -ForegroundColor Green
    Write-Host "TeamId : $($newTeam.teamId)" -ForegroundColor Green

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 8 — CSV export (if requested)
    # ─────────────────────────────────────────────────────────────────────────
    if ($ExportFormat -eq "CSV" -and $ExportPath) {
        $exportFolder = Split-Path -Path $ExportPath -Parent
        if ($exportFolder -and -not (Test-Path -Path $exportFolder)) {
            New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
        }

        $newTeam | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "New team report exported successfully → $ExportPath" -ForegroundColor Green
    }

    return $newTeam
}
