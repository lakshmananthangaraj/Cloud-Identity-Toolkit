<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 10 August 2026
Modified-On     : 10 August 2026

.SYNOPSIS
    Soft-deletes an existing Microsoft Team after verifying it exists, using
    Microsoft Graph API.

.DESCRIPTION
    This function removes a Microsoft Team (the underlying Microsoft 365
    Group) via the Microsoft Graph v1.0 endpoint. Before deletion, it
    retrieves the group and confirms both that it exists and that it is
    actually Teams-provisioned (resourceProvisioningOptions contains
    'Team') — this prevents the function from being used to silently
    delete a plain Microsoft 365 Group that was never turned into a Team.

    By design, this function does NOT validate owner or member counts
    before deletion — that check was explicitly scoped out.

    Deletion is soft-delete only. DELETE /groups/{id} is Microsoft Graph's
    default behaviour for Microsoft 365 Groups/Teams: the object moves to
    the tenant's deleted-items container and is restorable for
    approximately 30 days. There is no permanent-purge switch in this
    version — see Known Limitations.

    This function only accepts a direct Bearer token (AccessToken). It
    does not perform authentication itself. If you need to obtain a token
    via app-only (client credentials) authentication, use the companion
    Connect-EntraID.ps1 script referenced under .LINK below, then pass its
    returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Group.ReadWrite.All   (Application or Delegated)
    Optional (non-fatal if absent):
        Directory.Read.All    (used only to look up the deletedDateTime /
                                retention-expiration estimate after deletion)

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to Connect-EntraID.ps1 (see .LINK).

.PARAMETER TeamId
    The Azure AD Object ID (GUID) of the Microsoft Team to remove. This is
    the same GUID as the underlying Microsoft 365 Group's id — Microsoft
    Graph uses one identifier for both. A GUID-format check is performed
    before any Graph call is made, and the Team's existence (and
    Teams-provisioned status) is verified before deletion proceeds.

.PARAMETER ExportFormat
    Specifies the output format for the deletion result.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV. Rejected if it contains
    a '..' path-traversal sequence.

.PARAMETER Force
    Suppresses the interactive confirmation prompt. Deletion is still
    skipped entirely when -WhatIf is supplied.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject
        A custom object describing the removed team: teamId, displayName,
        mail, visibility, deletionStatus, deletedDateTime,
        retentionExpirationDateTime. Also optionally exports to CSV.

.EXAMPLE
    Remove-MicrosoftTeam -AccessToken $token -TeamId "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb"

    Verifies the Team exists, prompts for confirmation, then soft-deletes it.

.EXAMPLE
    Remove-MicrosoftTeam -AccessToken $token -TeamId "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb" -WhatIf

    Shows what would happen without deleting anything.

.EXAMPLE
    Remove-MicrosoftTeam -AccessToken $token `
        -TeamId "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb" `
        -Force `
        -ExportFormat CSV `
        -ExportPath "C:\Reports\RemovedTeam.csv"

    Deletes without an interactive prompt (still logged/confirmed via
    ShouldProcess machinery) and exports the result to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (10-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                Group.ReadWrite.All   (Application or Delegated) — required
                Directory.Read.All    (Application or Delegated) — optional,
                    used only for retention-expiration lookup post-deletion

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Soft delete only. Permanent purge (DELETE
            /directory/deletedItems/{id}) is intentionally not implemented in
            v1.0; add as a separate, explicitly-gated switch in a future
            version if required.
        - No owner/member count validation is performed before deletion —
            this was explicitly scoped out of v1.0.
        - The deletedDateTime / retentionExpirationDateTime lookup is
            non-fatal: if the caller's token lacks Directory.Read.All, or the
            deleted-items lookup otherwise fails, the team is still removed
            and those two fields report "Could not be confirmed".
        - Retention window is Microsoft's current ~30-day default for
            deleted Microsoft 365 Groups; Microsoft can change this without
            notice.

.LINK
    Microsoft Graph API - Delete group
    https://learn.microsoft.com/en-us/graph/api/group-delete

.LINK
    Microsoft Graph API - Get deleted item (directory)
    https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-get

.LINK
    Microsoft Graph API - Get group
    https://learn.microsoft.com/en-us/graph/api/group-get

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Remove-MicrosoftTeam {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$TeamId,

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

    # ── Shared headers ────────────────────────────────────────────────────────
    $headers = @{
        "Authorization"    = "Bearer $AccessToken"
        "ConsistencyLevel" = "eventual"
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 1 — Verify the Team exists and is actually Teams-provisioned
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Verifying Team '$TeamId' exists..." -ForegroundColor Cyan

    $verifyUri = "https://graph.microsoft.com/v1.0/groups/$TeamId`?`$select=id,displayName,mail,visibility,resourceProvisioningOptions"

    $teamData = $null
    Try {
        $verifyResponse = Invoke-WebRequest -Uri $verifyUri -Headers $headers -Method Get -ErrorAction Stop
        $teamData = $verifyResponse.Content | ConvertFrom-Json
    }
    Catch {
        $verifyStatus = $_.Exception.Response.StatusCode.value__
        if ($verifyStatus -eq 404) {
            Write-Error "No Team found with TeamId '$TeamId'. Exiting."
        }
        else {
            Write-Error "Failed to verify Team '$TeamId': $($_.Exception.Message). Exiting."
        }
        return
    }

    if (-not $teamData.resourceProvisioningOptions -or ($teamData.resourceProvisioningOptions -notcontains 'Team')) {
        Write-Error "Group '$TeamId' exists but is not Teams-provisioned (not a Microsoft Team). Exiting to prevent unintended group deletion."
        return
    }

    Write-Host "Team confirmed: '$($teamData.displayName)' ($TeamId)." -ForegroundColor Green

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2 — Confirm and soft-delete
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $PSCmdlet.ShouldProcess("Microsoft Team '$($teamData.displayName)' ($TeamId)", "Soft-delete (remove)")) {
        Write-Host "WhatIf: Would soft-delete Team '$($teamData.displayName)' ($TeamId)." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Deleting Team '$($teamData.displayName)' ($TeamId)..." -ForegroundColor Cyan

    $deleteStatus = $null
    do {
        Try {
            $deleteResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/groups/$TeamId" -Headers $headers -Method Delete -ErrorAction Stop
            $deleteStatus = $deleteResponse.StatusCode
        }
        Catch {
            $deleteStatus = $_.Exception.Response.StatusCode.value__
            if ($deleteStatus -eq 429) {
                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                Write-Host "Throttled. Waiting for $sleepTime seconds." -ForegroundColor Cyan
                Start-Sleep -Seconds $sleepTime
            }
            else {
                Write-Error "Failed to delete Team '$TeamId': $($_.Exception.Message). Exiting."
                return
            }
        }
    } until ($deleteStatus -eq 204)

    Write-Host "Team soft-deleted successfully." -ForegroundColor Green

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 3 — Look up retention info from the deleted-items container
    #          (best-effort; non-fatal if the token lacks Directory.Read.All)
    # ─────────────────────────────────────────────────────────────────────────
    $deletedDateTime = "Could not be confirmed"
    $retentionExpirationDateTime = "Could not be confirmed"

    Try {
        $deletedItemUri = "https://graph.microsoft.com/v1.0/directory/deletedItems/$TeamId`?`$select=deletedDateTime"
        $deletedItemResponse = Invoke-WebRequest -Uri $deletedItemUri -Headers $headers -Method Get -ErrorAction Stop
        $deletedItemData = $deletedItemResponse.Content | ConvertFrom-Json

        if ($deletedItemData.deletedDateTime) {
            $deletedDateTime = $deletedItemData.deletedDateTime
            $retentionExpirationDateTime = ([datetime]$deletedDateTime).AddDays(30).ToString("o")
        }
    }
    Catch {
        Write-Verbose "Could not retrieve deletedDateTime for '$TeamId' (non-fatal): $($_.Exception.Message)."
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4 — Build return object
    # ─────────────────────────────────────────────────────────────────────────
    $removedTeam = [PSCustomObject]@{
        teamId                      = $TeamId
        displayName                 = $teamData.displayName
        mail                        = $teamData.mail
        visibility                  = $teamData.visibility
        deletionStatus              = "SoftDeleted"
        deletedDateTime             = $deletedDateTime
        retentionExpirationDateTime = $retentionExpirationDateTime
    }

    Write-Host ""
    Write-Host "Team '$($teamData.displayName)' removed (soft delete). Restorable until: $retentionExpirationDateTime" -ForegroundColor Green

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 5 — CSV export (if requested)
    # ─────────────────────────────────────────────────────────────────────────
    if ($ExportFormat -eq "CSV" -and $ExportPath) {
        $exportFolder = Split-Path -Path $ExportPath -Parent
        if ($exportFolder -and -not (Test-Path -Path $exportFolder)) {
            New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
        }

        $removedTeam | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Team removal report exported successfully → $ExportPath" -ForegroundColor Green
    }

    return $removedTeam
}
