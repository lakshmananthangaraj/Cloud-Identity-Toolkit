<#

Author          : Lakshmanan Thangaraj
Version         : 1.2
Created-On      : 31 July 2026
Modified-On     : 31 July 2026

.SYNOPSIS
    Reports which App Protection Policies (MAM) are assigned to which
    groups, and optionally flags groups with no policy assigned, using
    the Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph beta endpoint for both iOS and Android
    Managed App Protection policies, expanding each policy's group
    assignments in the same call. Produces one row per (policy, assigned
    group) pair, giving a direct answer to "which groups actually have
    MAM coverage, and from which policy."

    Gap analysis: when -CompareAgainstGroupId is supplied with one or
    more Entra ID group object IDs, the function cross-references that
    list against every group found in a policy assignment and reports
    any supplied group ID with zero MAM policy coverage. Only 'include'
    assignments count as coverage - a group that is only present via an
    exclusionGroupAssignmentTarget is NOT treated as covered. This is
    left as an explicit opt-in rather than scanning the entire tenant's
    groups, because "should this group have a MAM policy" is a business
    decision - most groups in a tenant (distribution lists, unrelated
    security groups) are never meant to carry app protection, so blindly
    flagging all ungoverned groups would bury the real gaps in noise.

    Handles pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing.

    Results can optionally be exported to CSV. When -CompareAgainstGroupId
    is used and exporting, a companion "_Gaps" CSV is written listing the
    unmatched groups.

    Console feedback (retrieval status, formatted assignment table, gap
    summary line) can be suppressed with -Quiet for use inside larger
    automation/CI pipelines. The returned object is identical either way.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission:
        DeviceManagementApps.Read.All

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER CompareAgainstGroupId
    Optional. One or more Entra ID group object IDs to check for MAM
    policy coverage. Any group in this list with no matching 'include'
    assignment across the retrieved App Protection Policies is reported
    as a gap. If omitted, the function returns the full assignment
    inventory only, with no gap analysis performed.

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.PARAMETER Quiet
    Optional switch. Suppresses all Write-Host progress/table console
    output (retrieval status, formatted assignment table, gap summary
    line). Intended for use inside larger automation/CI pipelines where
    console noise is undesirable. The return value (Assignments/Gaps
    hashtable) is unaffected either way.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Collections.Hashtable
        A hashtable with two keys: 'Assignments' (one row per policy/group
        pair, as PSCustomObject with PolicyId, PolicyName, Platform,
        LastModified, AssignmentType, TargetGroupId properties) and 'Gaps'
        (groups from -CompareAgainstGroupId with no MAM coverage, as
        PSCustomObject with GroupId, MAMCoverage properties; empty if
        -CompareAgainstGroupId was not supplied). Also optionally exports
        both to CSV.

.EXAMPLE
    Get-IntuneMAMPolicyAssignment -AccessToken $token

    Reports every App Protection Policy-to-group assignment across iOS
    and Android, with full console feedback.

.EXAMPLE
    $result = Get-IntuneMAMPolicyAssignment -AccessToken $token -Quiet
    foreach ($row in $result.Assignments) {
        "$($row.PolicyName) [$($row.Platform)] -> $($row.TargetGroupId)"
    }

    Silent automation-friendly run - captures the return value and
    iterates over each assignment row's properties (e.g. PolicyId,
    TargetGroupId) for use in a bigger pipeline.

.EXAMPLE
    Get-IntuneMAMPolicyAssignment -AccessToken $token -CompareAgainstGroupId 'aaaa-...','bbbb-...' -ExportFormat CSV -ExportPath "C:\Reports\MAMAssignments.csv"

    Reports assignments and flags any of the two supplied groups that
    have no MAM policy coverage, exporting both the assignment inventory
    and the gap list.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.2 (31-Jul-2026) - Added -Quiet switch to suppress console progress
                        output/table for automation scenarios. Return value (hashtable
                        shape) unaffected - existing callers using $result.Assignments /
                        $result.Gaps continue to work unchanged.
    1.1 (31-Jul-2026) - Console now prints a formatted table of
                        Assignments before returning (via Out-Host, so the return value
                        passed to the caller is unaffected). Fixed gap analysis
                        incorrectly treating excluded groups (exclusionGroupAssignmentTarget)
                        as covered - only include-type assignments now count toward MAM
                        coverage.
    1.0 (31-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. A valid Microsoft Graph access token with the following permission:
            DeviceManagementApps.Read.All (Application or Delegated)
    2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Uses the /beta Graph API endpoint. Beta endpoints are subject to
      change and are not recommended for production without monitoring
      for breaking changes.
    - Only covers iosManagedAppProtections and androidManagedAppProtections
      (the two MAM-without-enrollment policy types). Windows Information
      Protection policies use a different Graph resource
      (windowsInformationProtectionPolicies) and are not included here.
    - Reports assigned group object IDs, not resolved display names -
      cross-reference against /groups/{id} for friendly names.
    - Gap analysis only evaluates groups explicitly passed via
      -CompareAgainstGroupId; it does not attempt to infer which tenant
      groups "should" have MAM coverage.

.LINK
    Microsoft Graph API - iosManagedAppProtection resource type
    https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-iosmanagedappprotection

.LINK
    Microsoft Graph API - androidManagedAppProtection resource type
    https://learn.microsoft.com/en-us/graph/api/resources/intune-mam-androidmanagedappprotection

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-IntuneMAMPolicyAssignment
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath,

        [string[]]$CompareAgainstGroupId,

        [switch]$Quiet
    )

    function Invoke-GraphGetWithRetry
    {
        param ([string]$Uri, [hashtable]$Headers)

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
                        Response   = $($ErrorObject.Exception.Response)
                        StatusCode = $($ErrorObject.Exception.Response.StatusCode)
                        Message    = $($ErrorObject.Exception.Message)
                    }
                    $ErrorOutput | Format-List
                    return $null
                }
            }
        } until ($statusCode -eq 200 -or -not $response)

        return $response
    }

    function Get-MAMPolicyAssignments
    {
        param ([string]$PolicyTypeUri, [string]$PolicyTypeLabel, [hashtable]$Headers)

        $rows = New-Object System.Collections.ArrayList
        $uri = "$PolicyTypeUri`?`$top=50&`$expand=assignments"

        do
        {
            $partialData = Invoke-GraphGetWithRetry -Uri $uri -Headers $Headers
            if (-not $partialData) { Write-Warning "Failed to retrieve $PolicyTypeLabel policies page."; break }

            $policyData = $partialData.Content | ConvertFrom-Json

            if ($policyData.PSObject.Properties['@odata.nextLink']) { $uri = $policyData.'@odata.nextLink' } else { $uri = $null }

            $policyData.value | ForEach-Object {

                $policy = $_

                if ($policy.assignments -and $policy.assignments.Count -gt 0)
                {
                    foreach ($assignment in $policy.assignments)
                    {
                        $targetType = if ($assignment.target.PSObject.Properties['@odata.type']) { $assignment.target.'@odata.type' -replace '#microsoft.graph.','' } else { $null }
                        $targetGroupId = $assignment.target.groupId

                        $null = $rows.Add([PSCustomObject]@{
                            PolicyId       = $policy.id
                            PolicyName     = $policy.displayName
                            Platform       = $PolicyTypeLabel
                            LastModified   = $policy.lastModifiedDateTime
                            AssignmentType = $targetType
                            TargetGroupId  = $targetGroupId
                        })
                    }
                }
                else
                {
                    $null = $rows.Add([PSCustomObject]@{
                        PolicyId       = $policy.id
                        PolicyName     = $policy.displayName
                        Platform       = $PolicyTypeLabel
                        LastModified   = $policy.lastModifiedDateTime
                        AssignmentType = '(unassigned)'
                        TargetGroupId  = $null
                    })
                }
            }

        } until (-not $uri)

        return $rows
    }

    if (-not $AccessToken)
    {
        Write-Error "AccessToken is required. Exiting function."
        return
    }

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    if (-not $Quiet) { Write-Host "Retrieving iOS App Protection Policies..." -ForegroundColor Cyan }
    $iosRows = Get-MAMPolicyAssignments -PolicyTypeUri "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections" -PolicyTypeLabel "iOS" -Headers $headers

    if (-not $Quiet) { Write-Host "Retrieving Android App Protection Policies..." -ForegroundColor Cyan }
    $androidRows = Get-MAMPolicyAssignments -PolicyTypeUri "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections" -PolicyTypeLabel "Android" -Headers $headers

    $allAssignments = New-Object System.Collections.ArrayList
    $iosRows | ForEach-Object { $null = $allAssignments.Add($_) }
    $androidRows | ForEach-Object { $null = $allAssignments.Add($_) }

    if (-not $Quiet)
    {
        Write-Host ""
        Write-Host "Total MAM policy assignment rows: $($allAssignments.Count)" -ForegroundColor Cyan

        if ($allAssignments.Count -gt 0)
        {
            Write-Host ""
            $allAssignments | Format-Table PolicyId, PolicyName, Platform, LastModified, AssignmentType, TargetGroupId -AutoSize | Out-Host
        }
    }

    # Gap analysis - only if the caller supplied a comparison list
    $gaps = New-Object System.Collections.ArrayList
    if ($CompareAgainstGroupId -and $CompareAgainstGroupId.Count -gt 0)
    {
        $coveredGroupIds = $allAssignments |
            Where-Object { $_.TargetGroupId -and $_.AssignmentType -ne 'exclusionGroupAssignmentTarget' } |
            Select-Object -ExpandProperty TargetGroupId -Unique

        foreach ($groupId in $CompareAgainstGroupId)
        {
            if ($groupId -notin $coveredGroupIds)
            {
                $null = $gaps.Add([PSCustomObject]@{
                    GroupId        = $groupId
                    MAMCoverage    = 'None found'
                })
            }
        }

        if (-not $Quiet)
        {
            Write-Host "Groups with no MAM policy coverage: $($gaps.Count) of $($CompareAgainstGroupId.Count) checked" -ForegroundColor $(if ($gaps.Count -gt 0) { 'Yellow' } else { 'Green' })
            if ($gaps.Count -gt 0)
            {
                Write-Host ""
                $gaps | Format-Table GroupId, MAMCoverage -AutoSize | Out-Host
            }
        }
    }

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allAssignments | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        if (-not $Quiet)
        {
            Write-Host ""
            Write-Host "MAM policy assignment report exported successfully → $ExportPath" -ForegroundColor Green
        }

        if ($CompareAgainstGroupId -and $CompareAgainstGroupId.Count -gt 0)
        {
            $gapsPath = [System.IO.Path]::Combine(
                [System.IO.Path]::GetDirectoryName($ExportPath),
                ([System.IO.Path]::GetFileNameWithoutExtension($ExportPath) + "_Gaps" + [System.IO.Path]::GetExtension($ExportPath))
            )
            $gaps | Export-Csv -Path $gapsPath -NoTypeInformation -Force
            if (-not $Quiet)
            {
                Write-Host "MAM coverage gap report exported successfully → $gapsPath" -ForegroundColor Green
            }
        }
    }

    return @{
        Assignments = $allAssignments
        Gaps        = $gaps
    }
}
