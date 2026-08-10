<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 10 August 2026
Modified-On     : 10 August 2026

.SYNOPSIS
    Bulk-adds one or more members (or owners) to an existing Microsoft Team
    using Microsoft Graph API.

.DESCRIPTION
    This function adds a batch of users to a Microsoft Team's underlying
    Microsoft 365 Group, either as Members or as Owners (via -Role). The
    ID list can be supplied directly (-MemberIds) or read from a CSV file
    (-InputCsv) containing a 'MemberId', 'UserId', or 'Id' column — the
    two input methods are mutually exclusive parameter sets.

    Before any changes are made, the function:
        - Verifies the target Team exists and is Teams-provisioned.
        - De-duplicates the input ID list.
        - Splits out entries that are not valid-format GUIDs (reported as
          InvalidFormat, not attempted against Graph).

    A single confirmation prompt (ShouldProcess) covers the whole batch —
    not one prompt per user — since this is one logical bulk action.

    Processing is continue-on-error: if adding one user fails, the
    function logs it and moves on to the rest of the batch rather than
    aborting. Users who are already a Member/Owner of the Team are
    reported as "AlreadyPresent" (idempotent, not a failure). A full
    per-user result set is returned and can optionally be exported to
    CSV.

    This function only accepts a direct Bearer token (AccessToken). It
    does not perform authentication itself. If you need to obtain a token
    via app-only (client credentials) authentication, use the companion
    Connect-EntraID.ps1 script referenced under .LINK below, then pass its
    returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Group.ReadWrite.All   (Application or Delegated)
        (GroupMember.ReadWrite.All is also sufficient for the member-add
        calls, but Group.ReadWrite.All covers both Member and Owner adds.)

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to Connect-EntraID.ps1 (see .LINK).

.PARAMETER TeamId
    The Azure AD Object ID (GUID) of the Microsoft Team to add members to.
    Verified to exist and be Teams-provisioned before any adds are attempted.

.PARAMETER MemberIds
    One or more Azure AD Object IDs (GUIDs) of the users to add.
    Mutually exclusive with -InputCsv.

.PARAMETER InputCsv
    Path to a CSV file containing the users to add. The file must have a
    column named 'MemberId', 'UserId', or 'Id' (case-insensitive) holding
    each user's Azure AD Object ID (GUID). Mutually exclusive with
    -MemberIds. Rejected if the path contains a '..' path-traversal
    sequence.

.PARAMETER Role
    The role to add each user as.
    Accepted values: Member, Owner
    Default: Member

.PARAMETER ExportFormat
    Specifies the output format for the detailed per-user results.
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
        A summary object: teamId, displayName, role, totalRequested,
        duplicatesRemoved, added, alreadyPresent, invalidFormat, failed,
        and results (an array of per-user PSCustomObjects: memberId,
        status, detail). Also optionally exports the per-user results to
        CSV.

.EXAMPLE
    Add-TeamMembers -AccessToken $token `
        -TeamId "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb" `
        -MemberIds "cccccccc-3333-4444-5555-dddddddddddd","eeeeeeee-6666-7777-8888-ffffffffffff"

    Adds two users as Members after a single confirmation prompt.

.EXAMPLE
    Add-TeamMembers -AccessToken $token `
        -TeamId "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb" `
        -InputCsv "C:\Onboarding\NewHires.csv" `
        -Role Owner `
        -Force `
        -ExportFormat CSV -ExportPath "C:\Reports\AddResults.csv"

    Adds every user listed in NewHires.csv as an Owner, without an
    interactive prompt, and exports per-user results to CSV.

.EXAMPLE
    Add-TeamMembers -AccessToken $token -TeamId "aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb" -MemberIds "cccccccc-3333-4444-5555-dddddddddddd" -WhatIf

    Shows what would happen without making any changes.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (10-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permission:
                Group.ReadWrite.All   (Application or Delegated)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Accepts Azure AD Object IDs (GUIDs) only — UPNs are not resolved
            in v1.0. Pre-resolve UPNs to Object IDs before calling.
        - On a 429 throttle response, each user-add is retried once after
            the Retry-After delay; a second consecutive throttle on the
            same user is recorded as Failed rather than retried further.
        - Does not pre-check whether an ID belongs to a real, enabled
            user — invalid or disabled accounts surface as a Failed entry
            with Graph's own error detail.
        - CSV export writes the per-user results, not the summary object;
            read the console summary line (or the returned object's
            top-level properties) for aggregate counts.

.LINK
    Microsoft Graph API - Add group member
    https://learn.microsoft.com/en-us/graph/api/group-post-members

.LINK
    Microsoft Graph API - Add group owner
    https://learn.microsoft.com/en-us/graph/api/group-post-owners

.LINK
    Microsoft Graph API - Get group
    https://learn.microsoft.com/en-us/graph/api/group-get

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Add-TeamMembers {
    [CmdletBinding(DefaultParameterSetName = 'ByArray', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$TeamId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByArray')]
        [ValidateNotNullOrEmpty()]
        [string[]]$MemberIds,

        [Parameter(Mandatory = $true, ParameterSetName = 'ByCsv')]
        [ValidateNotNullOrEmpty()]
        [string]$InputCsv,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Member", "Owner")]
        [string]$Role = "Member",

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
    # STEP 1 — Resolve the raw member list (array or CSV)
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

        $idColumn = ($csvRows[0].PSObject.Properties.Name | Where-Object { $_ -in @('MemberId', 'UserId', 'Id') } | Select-Object -First 1)

        if (-not $idColumn) {
            Write-Error "InputCsv '$InputCsv' must contain a 'MemberId', 'UserId', or 'Id' column. Exiting."
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
        foreach ($id in $MemberIds) {
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
                    memberId = $id
                    status   = "InvalidFormat"
                    detail   = "Not a valid GUID."
                })
        }
    }

    if ($validIds.Count -eq 0) {
        Write-Error "No valid-format member IDs to process. Exiting."
        return
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 4 — Verify the Team exists and is Teams-provisioned
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Verifying Team '$TeamId' exists..." -ForegroundColor Cyan

    $headers = @{
        "Authorization"    = "Bearer $AccessToken"
        "ConsistencyLevel" = "eventual"
    }

    $teamData = $null
    Try {
        $verifyResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/groups/$TeamId`?`$select=id,displayName,resourceProvisioningOptions" -Headers $headers -Method Get -ErrorAction Stop
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
        Write-Error "Group '$TeamId' exists but is not Teams-provisioned (not a Microsoft Team). Exiting."
        return
    }

    Write-Host "Team confirmed: '$($teamData.displayName)' ($TeamId)." -ForegroundColor Green

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 5 — Single batch-level confirmation
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $PSCmdlet.ShouldProcess("Microsoft Team '$($teamData.displayName)' ($TeamId)", "Add $($validIds.Count) $Role(s)")) {
        Write-Host "WhatIf: Would add $($validIds.Count) $Role(s) to Team '$($teamData.displayName)' ($TeamId)." -ForegroundColor Yellow
        return
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 6 — Per-user add, continue on error
    # ─────────────────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "Adding $($validIds.Count) $Role(s) to Team '$($teamData.displayName)'..." -ForegroundColor Cyan

    $targetSegment = if ($Role -eq "Owner") { "owners" } else { "members" }
    $current = 0

    foreach ($id in $validIds) {
        $current++
        $errorDetail = $null
        Write-Progress -Activity "Adding $Role(s)" -Status "$id ($current of $($validIds.Count))" -PercentComplete (($current / $validIds.Count) * 100)

        $body = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/users/$id"
        } | ConvertTo-Json

        $addStatus = $null
        $headers["Content-Type"] = "application/json"

        Try {
            $addResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/groups/$TeamId/$targetSegment/`$ref" -Headers $headers -Method Post -Body $body -ErrorAction Stop
            $addStatus = $addResponse.StatusCode
        }
        Catch {
            $addStatus = $_.Exception.Response.StatusCode.value__

            if ($addStatus -eq 429) {
                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                Write-Host "Throttled. Waiting for $sleepTime seconds." -ForegroundColor Cyan
                Start-Sleep -Seconds $sleepTime

                Try {
                    $addResponse = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/groups/$TeamId/$targetSegment/`$ref" -Headers $headers -Method Post -Body $body -ErrorAction Stop
                    $addStatus = $addResponse.StatusCode
                }
                Catch {
                    $addStatus = $_.Exception.Response.StatusCode.value__
                    $errorDetail = $_.Exception.Message
                }
            }
            else {
                $errorDetail = $_.Exception.Message
            }
        }
        $headers.Remove("Content-Type")

        if ($addStatus -eq 204) {
            $null = $results.Add([PSCustomObject]@{
                    memberId = $id
                    status   = "Added"
                    detail   = "Added as $Role."
                })
            Write-Verbose "Added $id as $Role."
        }
        elseif ($errorDetail -and $errorDetail -match 'already exist') {
            $null = $results.Add([PSCustomObject]@{
                    memberId = $id
                    status   = "AlreadyPresent"
                    detail   = "Already a $Role of this Team."
                })
            Write-Verbose "$id is already a $Role — skipped."
        }
        else {
            $detailText = if ($errorDetail) { $errorDetail } else { "HTTP status $addStatus." }
            $null = $results.Add([PSCustomObject]@{
                    memberId = $id
                    status   = "Failed"
                    detail   = $detailText
                })
            Write-Warning "  Failed to add '$id' as $Role`: $detailText"
        }
    }

    Write-Progress -Activity "Adding $Role(s)" -Completed

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 7 — Build summary
    # ─────────────────────────────────────────────────────────────────────────
    $summary = [PSCustomObject]@{
        teamId            = $TeamId
        displayName       = $teamData.displayName
        role              = $Role
        totalRequested    = @($uniqueIds).Count
        duplicatesRemoved = $duplicatesRemoved
        added             = @($results | Where-Object { $_.status -eq "Added" }).Count
        alreadyPresent    = @($results | Where-Object { $_.status -eq "AlreadyPresent" }).Count
        invalidFormat     = @($results | Where-Object { $_.status -eq "InvalidFormat" }).Count
        failed            = @($results | Where-Object { $_.status -eq "Failed" }).Count
        results           = $results
    }

    Write-Host ""
    Write-Host "Done. Added: $($summary.added)  Already present: $($summary.alreadyPresent)  Invalid format: $($summary.invalidFormat)  Failed: $($summary.failed)" -ForegroundColor Green

    if ($summary.failed -gt 0) {
        Write-Warning "$($summary.failed) user(s) failed to be added. See the 'results' property (or CSV export) for details."
    }

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 8 — CSV export (detailed per-user results)
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
