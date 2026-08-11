<#

Author          : Lakshmanan Thangaraj
Version         : 1.1
Created-On      : 11 August 2026
Modified-On     : 11 August 2026

.SYNOPSIS
    Reports Teams calling policy assignments for users in the tenant using
    Microsoft Graph API.

.DESCRIPTION
    Queries Microsoft Graph to retrieve the calling-family policy assignments
    for each user in scope. Up to four policy types are evaluated per user:

        • TeamsCallingPolicy         — core call routing, PSTN, voicemail
        • TeamsCallHoldPolicy        — music-on-hold behaviour
        • TeamsCallParkPolicy        — call park and retrieve
        • TeamsEmergencyCallingPolicy — enhanced emergency (E911) routing

    One output row is produced per user per policy type, making the report
    easy to pivot, filter, and compare against a baseline in Excel or Power BI.

    Use -PolicyType to restrict output to one or more specific types; omit it
    to return all four. Use -NonDefaultOnly to surface only users whose
    effective policy for any selected type is not 'Global' (the tenant-wide
    default) — ideal for producing an exceptions list in large tenants.

    When no -UserPrincipalName is supplied the function resolves the full set
    of Teams-licensed users from /v1.0/users (filtered to accounts that have
    an active Microsoft Teams service plan) before pulling policy assignments.

    Each user's effective policy assignments are retrieved via
    GET /v1.0/admin/teams/userConfigurations/{userId}, which returns every
    Teams policy type for that user, including whether each was assigned
    directly or inherited from a group. This function filters the response
    to the selected calling policy types only.

    Handles pagination via @odata.nextLink on the user listing, retries on
    HTTP 429 throttling using Retry-After, and skips a failing user without
    aborting the run. Only accepts a direct Bearer token (BYOT); does not
    authenticate itself.

    The following attributes are collected per output row:
        - userId, userPrincipalName, displayName, department,
          policyType, policyName, assignmentType, isDefaultPolicy

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        User.Read.All
        TeamsUserConfiguration.Read.All

    Obtain the token via Connect-EntraID.ps1 and pass it here.

.PARAMETER UserPrincipalName
    Optional. One or more UPNs to scope the report to specific users.
    Accepts an array or pipeline input.
    If omitted, all Teams-licensed users in the tenant are evaluated.

.PARAMETER PolicyType
    Optional. One or more calling policy types to include in the report.
    Valid values:
        TeamsCallingPolicy
        TeamsCallHoldPolicy
        TeamsCallParkPolicy
        TeamsEmergencyCallingPolicy

    Defaults to all four types when omitted.

.PARAMETER NonDefaultOnly
    Switch. When specified, only rows where the effective policy name is NOT
    'Global' (the tenant default) are included in the output. Useful for
    producing an exceptions report in large tenants.

    When combined with -PolicyType, the filter applies within the selected
    types only.

.PARAMETER ExportFormat
    Specifies the output format. Supported values: CSV

.PARAMETER ExportPath
    File path where the exported CSV will be saved.
    Required only when ExportFormat is specified.

.INPUTS
    String (UserPrincipalName). Accepts pipeline input by value or by
    property name.

.OUTPUTS
    System.Array of PSCustomObjects, one per user per policy type.
    Also optionally exports to CSV.

.EXAMPLE
    Get-TeamCallingPolicyAssignment -AccessToken $token

    Returns all four calling policy type assignments for all Teams-licensed
    users in the tenant.

.EXAMPLE
    Get-TeamCallingPolicyAssignment -AccessToken $token -PolicyType TeamsCallingPolicy

    Returns only the core TeamsCallingPolicy assignment for every
    Teams-licensed user.

.EXAMPLE
    Get-TeamCallingPolicyAssignment -AccessToken $token -NonDefaultOnly -ExportFormat CSV -ExportPath "C:\Reports\CallingPolicies.csv"

    Returns only users with a non-default calling policy assignment (across all
    four types) and exports the results to CSV.

.EXAMPLE
    Get-TeamCallingPolicyAssignment -AccessToken $token -UserPrincipalName "alice@contoso.com","bob@contoso.com" -PolicyType TeamsCallingPolicy, TeamsEmergencyCallingPolicy

    Returns core calling and emergency calling policy assignments for two
    specific users.

.EXAMPLE
    "alice@contoso.com","bob@contoso.com" | Get-TeamCallingPolicyAssignment -AccessToken $token

    Demonstrates pipeline input of UPNs.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.1 (11-Aug-2026) - Fixed policy data extraction: the single-user GET
                             endpoint wraps its payload in a 'value' object;
                             code now reads .value.effectivePolicyAssignments
                             instead of .effectivePolicyAssignments. Fixed
                             missing-assignment fallback: Graph omits policy
                             types that carry the tenant default; absence of
                             an entry now correctly resolves to 'Global' /
                             'inherited' rather than 'Could not be confirmed'.
        1.0 (11-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with User.Read.All and
           TeamsUserConfiguration.Read.All
        2. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve the set of users to evaluate: if -UserPrincipalName
                    is supplied, look up each UPN individually via
                    /v1.0/users/{UPN}; otherwise page all Teams-licensed users
                    from /v1.0/users with a service-plan filter
        Step 2  →  For each user, GET /v1.0/admin/teams/userConfigurations/{id}
                    (retrying on HTTP 429) and extract rows matching the
                    selected calling policy types
        Step 3  →  Apply -NonDefaultOnly filter if specified
        Step 4  →  One failure per user does not abort the run
        Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Policy name is reported as returned by Graph. 'Global' is Microsoft's
          internal name for the tenant-wide default policy; it is not the
          display name shown in the Teams Admin Center for that policy.
        - SINGLE-TOKEN, SEQUENTIAL: uses one static Bearer token for the entire
          run; no mid-run refresh. In very large tenants a run exceeding the
          token lifetime (~60-90 min) will fail with 401 Unauthorized.
        - Tenant-wide user pulls in large organisations can exceed 100,000
          users; consider scoping with -UserPrincipalName or -NonDefaultOnly
          to reduce volume.
        - Graph omits policy types from effectivePolicyAssignments when the
          user inherits the tenant-wide default. The function treats absence
          of an entry as 'Global' / 'inherited', which is correct per the
          API contract but means the distinction between "confirmed Global"
          and "entry absent" is not visible in the output.

.LINK
    Microsoft Graph API - Get userConfiguration
    https://learn.microsoft.com/en-us/graph/api/teamsadministration-teamsadminroot-list-userconfigurations

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamCallingPolicyAssignment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [ValidateSet(
            'TeamsCallingPolicy',
            'TeamsCallHoldPolicy',
            'TeamsCallParkPolicy',
            'TeamsEmergencyCallingPolicy'
        )]
        [string[]]$PolicyType = @(
            'TeamsCallingPolicy',
            'TeamsCallHoldPolicy',
            'TeamsCallParkPolicy',
            'TeamsEmergencyCallingPolicy'
        ),

        [Parameter(Mandatory = $false)]
        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^(?!.*\.\.)[^<>:"|?*]+$')]
        [string]$ExportPath,

        [switch]$NonDefaultOnly
    )

    Begin {
        $allResults = New-Object System.Collections.ArrayList
        $resolvedUsers = New-Object System.Collections.ArrayList
        $pipelineUpns = New-Object System.Collections.ArrayList
        $totalProcessed = 0

        $headers = @{
            "Authorization"    = "Bearer $AccessToken"
            "ConsistencyLevel" = "eventual"
        }

        Write-Host ""
        Write-Host "  🔍  Starting Teams Calling Policy Assignment report..." -ForegroundColor Cyan
        Write-Host "  📌  Policy type(s) in scope: $($PolicyType -join ', ')" -ForegroundColor Cyan
    }

    Process {
        if ($UserPrincipalName) {
            foreach ($upn in $UserPrincipalName) {
                $null = $pipelineUpns.Add($upn)
            }
        }
    }

    End {
        #region ── Step 1: Resolve users ──────────────────────────────────────

        if ($pipelineUpns.Count -gt 0) {
            Write-Host "  📋  Resolving $($pipelineUpns.Count) supplied UPN(s)..." -ForegroundColor Cyan

            foreach ($upn in $pipelineUpns) {
                Try {
                    $skip = $false

                    do {
                        Try {
                            $r = Invoke-WebRequest `
                                -Uri "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($upn))?`$select=id,userPrincipalName,displayName,department" `
                                -Headers $headers `
                                -Method Get `
                                -ErrorAction Stop

                            $status = $r.StatusCode
                        }
                        Catch {
                            $status = $_.Exception.Response.StatusCode

                            if ($status -eq 429) {
                                $sleep = $_.Exception.Response.Headers.Item("Retry-After")
                                Write-Host "  Throttled. Waiting $sleep s..." -ForegroundColor Cyan
                                Start-Sleep -Seconds $sleep
                            }
                            else {
                                Write-Warning "Failed to resolve UPN '$upn': $($_.Exception.Message)"
                                $skip = $true
                            }
                        }
                    } until (($status -eq 200) -or $skip)

                    if (-not $skip) {
                        $null = $resolvedUsers.Add(($r.Content | ConvertFrom-Json))
                    }
                }
                Catch {
                    Write-Warning "Unexpected error resolving UPN '$upn': $($_.Exception.Message)"
                }
            }
        }
        else {
            Write-Host "  📋  Resolving all Teams-licensed users from tenant..." -ForegroundColor Cyan

            $uri = "https://graph.microsoft.com/v1.0/users?`$filter=assignedPlans/any(a:a/service eq 'TeamspaceAPI' and a/capabilityStatus eq 'Enabled')&`$select=id,userPrincipalName,displayName,department&`$top=999&`$count=true"

            do {
                $skip = $false

                do {
                    Try {
                        $r = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                        $status = $r.StatusCode
                    }
                    Catch {
                        $status = $_.Exception.Response.StatusCode

                        if ($status -eq 429) {
                            $sleep = $_.Exception.Response.Headers.Item("Retry-After")
                            Write-Host "  Throttled. Waiting $sleep s..." -ForegroundColor Cyan
                            Start-Sleep -Seconds $sleep
                        }
                        else {
                            Write-Warning "User listing failed: $($_.Exception.Message)"
                            $skip = $true
                        }
                    }
                } until (($status -eq 200) -or $skip)

                if ($skip) { break }

                $page = $r.Content | ConvertFrom-Json
                @($page.value) | ForEach-Object { $null = $resolvedUsers.Add($_) }

                $uri = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }

                Write-Host "  Progress: $($resolvedUsers.Count) user(s) resolved so far..." -ForegroundColor Cyan

            } until (-not $uri)
        }

        Write-Host "  ✅  $($resolvedUsers.Count) user(s) to evaluate." -ForegroundColor Green

        #endregion

        #region ── Step 2: Retrieve calling policy assignments per user ────────

        foreach ($user in $resolvedUsers) {
            $totalProcessed++

            Write-Progress -Activity "Retrieving calling policy assignments" `
                -Status "$($user.userPrincipalName)" `
                -PercentComplete ([Math]::Min(($totalProcessed / [Math]::Max($resolvedUsers.Count, 1)) * 100, 100))

            Try {
                $skip = $false

                do {
                    Try {
                        $pr = Invoke-WebRequest `
                            -Uri "https://graph.microsoft.com/v1.0/admin/teams/userConfigurations/$($user.id)" `
                            -Headers $headers `
                            -Method Get `
                            -ErrorAction Stop

                        $pstatus = $pr.StatusCode
                    }
                    Catch {
                        $pstatus = $_.Exception.Response.StatusCode
                        $errObj = $_

                        if ($pstatus -eq 429) {
                            $sleep = $_.Exception.Response.Headers.Item("Retry-After")
                            Write-Host "  Throttled. Waiting $sleep s..." -ForegroundColor Cyan
                            Start-Sleep -Seconds $sleep
                        }
                        else {
                            $ErrorOutput = [PSCustomObject][ordered]@{
                                UserId     = $user.id
                                UPN        = $user.userPrincipalName
                                Response   = $($errObj.Exception.Response)
                                StatusCode = $($errObj.Exception.Response.StatusCode)
                                Message    = $($errObj.Exception.Message)
                            }
                            $ErrorOutput | Format-List
                            $skip = $true
                        }
                    }
                } until (($pstatus -eq 200) -or $skip)

                if ($skip) {
                    Write-Warning "Skipping '$($user.userPrincipalName)' — policy retrieval failed."
                    Continue
                }

                # The single-user GET endpoint wraps its payload in a 'value'
                # object: { "value": { "effectivePolicyAssignments": [...] } }
                $rawConfig = $pr.Content | ConvertFrom-Json
                $userConfig = if ($rawConfig.PSObject.Properties['value']) { $rawConfig.value } else { $rawConfig }

                # ── Emit one row per selected calling policy type ──────────────
                foreach ($type in $PolicyType) {
                    $assignment = @($userConfig.effectivePolicyAssignments |
                        Where-Object { $_.policyType -eq $type }) |
                    Select-Object -First 1

                    # Graph omits a policy type entirely when the user inherits
                    # the tenant-wide default — absence == Global/inherited.
                    $policyName = if ($assignment) { $assignment.policyAssignment.displayName } else { 'Global' }
                    $assignType = if ($assignment) { $assignment.policyAssignment.assignmentType } else { 'inherited' }
                    $isDefault = ($policyName -eq 'Global')

                    # Apply -NonDefaultOnly filter at the row level
                    if ($NonDefaultOnly -and $isDefault) { Continue }

                    $null = $allResults.Add([PSCustomObject]@{
                            userId            = $user.id
                            userPrincipalName = $user.userPrincipalName
                            displayName       = $user.displayName
                            department        = $user.department
                            policyType        = $type
                            policyName        = $policyName
                            assignmentType    = $assignType
                            isDefaultPolicy   = $isDefault
                        })
                }
            }
            Catch {
                Write-Warning "Unexpected error for user '$($user.userPrincipalName)': $($_.Exception.Message)"
                Continue
            }
        }

        Write-Progress -Activity "Retrieving calling policy assignments" -Completed

        #endregion

        #region ── Step 3: Export and return ──────────────────────────────────

        Write-Host ""
        Write-Host "  ✅  Processed $totalProcessed user(s); $($allResults.Count) record(s) in output." -ForegroundColor Green

        if ($ExportFormat -eq "CSV" -and $ExportPath) {
            Try {
                $exportFolder = Split-Path -Path $ExportPath -Parent

                if ($exportFolder -and -not (Test-Path -Path $exportFolder)) {
                    New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
                }

                $allResults | Export-Csv -Path $ExportPath -NoTypeInformation -Force

                Write-Host "  📄  Calling policy report exported → $ExportPath" -ForegroundColor Green
            }
            Catch {
                Write-Error "Failed to export CSV: $($_.Exception.Message)"
            }
        }

        return $allResults

        #endregion
    }
}
