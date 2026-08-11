<#

Author          : Lakshmanan Thangaraj
Version         : 1.2
Created-On      : 11 August 2026
Modified-On     : 11 August 2026

.SYNOPSIS
    Reports Microsoft Teams messaging policy assignments for users in the
    tenant using Microsoft Graph API.

.DESCRIPTION
    Queries Microsoft Graph to retrieve the Teams messaging policy
    (TeamsMessagingPolicy) assigned to each user in scope. One output row is
    produced per user, making the report easy to pivot, filter, and compare
    against a policy baseline in Excel or Power BI.

    When no -UserPrincipalName is supplied the function resolves the full set
    of Teams-licensed users from /v1.0/users (filtered to accounts that have
    an active Microsoft Teams service plan) before pulling policy assignments.
    This avoids pulling unlicensed or disabled accounts in large tenants.

    The optional -NonDefaultOnly switch restricts output to users whose
    effective policy name is not 'Global' (the tenant-wide default). In
    large tenants where most users inherit the default policy this can reduce
    output from tens of thousands of rows to a manageable exceptions list.

    Each user's effective policy assignments are retrieved via
    GET /v1.0/admin/teams/userConfigurations/{userId}, which returns every
    Teams policy type for that user, including whether each was assigned
    directly or inherited from a group. This function filters the response
    to policyType eq 'TeamsMessagingPolicy'.

    Handles pagination via @odata.nextLink on the user listing, retries on
    HTTP 429 throttling using Retry-After, and skips a failing user without
    aborting the run. Only accepts a direct Bearer token (BYOT); does not
    authenticate itself.

    The following attributes are collected per user:
        - userId, userPrincipalName, displayName, department,
          policyName, policyType, assignmentType, isDefaultPolicy

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

.PARAMETER NonDefaultOnly
    Switch. When specified, only users whose effective messaging policy is NOT
    'Global' (the tenant default) are included in the output. Useful for
    producing an exceptions report in large tenants.

.PARAMETER ExportFormat
    Specifies the output format. Supported values: CSV

.PARAMETER ExportPath
    File path where the exported CSV will be saved.
    Required only when ExportFormat is specified.

.INPUTS
    String (UserPrincipalName). Accepts pipeline input by value or by
    property name.

.OUTPUTS
    System.Array of PSCustomObjects, one per user. Also optionally exports
    to CSV.

.EXAMPLE
    Get-TeamMessagingPolicyAssignment -AccessToken $token

    Returns messaging policy assignments for all Teams-licensed users.

.EXAMPLE
    Get-TeamMessagingPolicyAssignment -AccessToken $token -NonDefaultOnly -ExportFormat CSV -ExportPath "C:\Reports\MessagingPolicies.csv"

    Returns only users with a non-default messaging policy and exports to CSV.

.EXAMPLE
    Get-TeamMessagingPolicyAssignment -AccessToken $token -UserPrincipalName "alice@contoso.com","bob@contoso.com"

    Returns messaging policy assignments for two specific users.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.2 (11-Aug-2026) - Fixed policy data extraction: the single-user GET
                             endpoint wraps its payload in a 'value' object;
                             code now reads .value.effectivePolicyAssignments
                             instead of .effectivePolicyAssignments. Fixed
                             missing-assignment fallback: Graph omits policy
                             types that carry the tenant default; absence of
                             an entry now correctly resolves to 'Global' /
                             'inherited' rather than 'Could not be confirmed'.
        1.1 (11-Aug-2026) - Fixed tenant-wide filter (service plan name was
                             invalid, silently returning 0 users). Fixed
                             policy retrieval — the previous
                             /beta/users/{id}/teamwork/assignedPolicies
                             endpoint does not exist in Microsoft Graph;
                             replaced with the real, v1.0
                             /admin/teams/userConfigurations/{id} API, which
                             also exposes assignmentType (direct vs group).
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
                    (retrying on HTTP 429) and extract the TeamsMessagingPolicy row
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
        - Tenant-wide user pulls in large organisations can exceed 100,000 users;
            consider scoping with -UserPrincipalName or using -NonDefaultOnly
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


Function Get-TeamMessagingPolicyAssignment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserPrincipalName,

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
        # Policy type this function targets
        $PolicyTypeFilter = 'TeamsMessagingPolicy'

        $allResults = New-Object System.Collections.ArrayList
        $resolvedUsers = New-Object System.Collections.ArrayList
        $pipelineUpns = New-Object System.Collections.ArrayList
        $totalProcessed = 0

        $headers = @{
            "Authorization"    = "Bearer $AccessToken"
            "ConsistencyLevel" = "eventual"
        }

        Write-Host ""
        Write-Host "  🔍  Starting Teams Messaging Policy Assignment report..." -ForegroundColor Cyan
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
                            $r = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($upn))?`$select=id,userPrincipalName,displayName,department" -Headers $headers -Method Get -ErrorAction Stop
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

        #region ── Step 2: Retrieve policy assignments per user ───────────────

        foreach ($user in $resolvedUsers) {
            $totalProcessed++
            Write-Progress -Activity "Retrieving messaging policy assignments" `
                -Status "$($user.userPrincipalName)" `
                -PercentComplete ([Math]::Min(($totalProcessed / [Math]::Max($resolvedUsers.Count, 1)) * 100, 100))

            Try {
                $skip = $false
                do {
                    Try {
                        $pr = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/admin/teams/userConfigurations/$($user.id)" -Headers $headers -Method Get -ErrorAction Stop
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

                $targetAssignment = @($userConfig.effectivePolicyAssignments | Where-Object { $_.policyType -eq $PolicyTypeFilter }) | Select-Object -First 1

                # Graph omits policy types from effectivePolicyAssignments when
                # the user inherits the tenant-wide default — absence == Global/inherited.
                $policyName = if ($targetAssignment) { $targetAssignment.policyAssignment.displayName } else { 'Global' }
                $assignmentType = if ($targetAssignment) { $targetAssignment.policyAssignment.assignmentType } else { 'inherited' }
                $isDefaultPolicy = ($policyName -eq 'Global')

                if ($NonDefaultOnly -and $isDefaultPolicy) { Continue }

                $null = $allResults.Add([PSCustomObject]@{
                        userId            = $user.id
                        userPrincipalName = $user.userPrincipalName
                        displayName       = $user.displayName
                        department        = $user.department
                        policyType        = $PolicyTypeFilter
                        policyName        = $policyName
                        assignmentType    = $assignmentType
                        isDefaultPolicy   = $isDefaultPolicy
                    })
            }
            Catch {
                Write-Warning "Unexpected error for user '$($user.userPrincipalName)': $($_.Exception.Message)"
                Continue
            }
        }

        Write-Progress -Activity "Retrieving messaging policy assignments" -Completed

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

                Write-Host "  📄  Messaging policy report exported → $ExportPath" -ForegroundColor Green
            }
            Catch {
                Write-Error "Failed to export CSV: $($_.Exception.Message)"
            }
        }

        return $allResults

        #endregion
    }
}
