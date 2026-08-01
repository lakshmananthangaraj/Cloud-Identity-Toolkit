<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Tests Microsoft Teams against a set of governance/compliance standards
    using Microsoft Graph API.

.DESCRIPTION
    This function queries the Microsoft Graph v1.0 endpoint to evaluate every
    team in scope against a fixed set of governance rules and reports one row
    per rule violation (plus one "Compliant" row for teams that pass every
    evaluated rule), similar in shape to the Azure NSG compliance scripts.

    Rules evaluated:
        1. Ownership        - 0 owners = Critical, 1 owner = Warning,
                               2+ owners = Pass
        2. Visibility        - Public visibility = Warning (teams should
                               default to Private unless a documented
                               exception exists)
        3. Description      - Missing/blank description = Warning
        4. Naming convention - Only evaluated when -NamingPattern is supplied;
                               DisplayName not matching the supplied regex =
                               Warning. Skipped entirely (not counted toward
                               the compliance score) if -NamingPattern is
                               omitted.

    Every output row - violation or "Compliant" - also carries a per-team
    compliance rollup (RulesEvaluated, RulesFailed, CompliancePercentage) so
    the CSV supports both violation-level triage and team-level scoring
    without a second export.

    It handles pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing it further. One team's failure does not
    stop processing of the remaining teams.

    SCOPE & SUITABILITY:
    This function is designed for smaller tenants or quick ad-hoc pulls where
    a single Bearer token comfortably outlives the full pagination run. It
    does not implement token refresh mid-run. For large/enterprise-scale
    tenants, see Known Limitations below before relying on this function as-is.

    This function only accepts a direct Bearer token (AccessToken). It does
    not perform authentication itself. If you need to obtain a token via
    app-only (client credentials) authentication, use the companion
    Connect-EntraID.ps1 script referenced under .LINK below, then pass its
    returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Group.Read.All

    To obtain this token via app-only authentication instead of an interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER TeamId
    Optional. The Id (GUID) of the Microsoft Team / Microsoft 365 Group.
    Accepts an array, or pipeline input by value or by property name (e.g.
    from Get-Teams output, whose 'id' property maps onto this parameter).
    If omitted entirely (no value and no pipeline input), every team in the
    tenant is evaluated.

.PARAMETER NamingPattern
    Optional regular expression that team DisplayName values are expected to
    match (e.g. '^(HR|FIN|IT)-' to require a department prefix). When
    supplied, non-matching teams are reported as a naming-convention
    violation. When omitted, the naming-convention rule is skipped entirely
    and does not count toward the compliance score.

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.INPUTS
    String (TeamId), or objects with an id/TeamId property (e.g. Get-Teams output).

.OUTPUTS
    System.Array
        An array of custom objects, one per rule violation (plus one
        "Compliant" row for fully-compliant teams). Also optionally exports
        to CSV.

.EXAMPLE
    Test-TeamGovernanceCompliance -AccessToken $token

    Evaluates every team against Ownership, Visibility, and Description rules.

.EXAMPLE
    Test-TeamGovernanceCompliance -AccessToken $token -NamingPattern '^(HR|FIN|IT)-' -ExportFormat CSV -ExportPath "C:\Reports\TeamCompliance.csv"

    Also enforces a department-prefix naming convention and exports the findings.

.EXAMPLE
    Get-Teams -AccessToken $token | Test-TeamGovernanceCompliance -AccessToken $token

    Chains from Get-Teams to scope the compliance check to a specific set of teams.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permission:
                Group.Read.All (Application or Delegated)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve the set of teams to evaluate (all teams, or the
                    supplied -TeamId values) along with displayName,
                    description, and visibility
        Step 2  →  For each team, retrieve its owner count via
                    /groups/{id}/owners (paginated, retrying on HTTP 429)
        Step 3  →  Evaluate Ownership, Visibility, Description, and (if
                    -NamingPattern supplied) Naming-convention rules
        Step 4  →  Emit one row per violation, or one "Compliant" row if no
                    rule failed; stamp every row with the team's
                    RulesEvaluated / RulesFailed / CompliancePercentage
        Step 5  →  Repeat for the next team (one failure does not abort the run)
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Requires a valid bearer token with the specified permission.
        - Rule set is fixed to Ownership/Visibility/Description/Naming; it
            does not evaluate guest access, sensitivity labels, retention
            policies, or channel-level settings - these could not be
            confirmed from the group/team endpoints used here and would
            require additional Graph permissions and calls.
        - CompliancePercentage is calculated only from the rules actually
            evaluated for that team (the naming rule is excluded from both
            numerator and denominator when -NamingPattern is not supplied).
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static
            Bearer token for the entire run and does not refresh it mid-run.
            In very large tenants, if the full pull takes longer than the
            token's lifetime (typically ~60-90 minutes), the run will fail
            partway through with 401 Unauthorized once the token expires.
        - RECOMMENDED FOR: smaller tenants, scoped/filtered pulls, or quick
            one-off/ad-hoc governance sweeps.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants. For those,
            implement a proper token-refresh pattern (re-acquire via app-only
            client-credentials auth on a timer or before each page/batch) and
            consider parallelized/batched Graph calls instead of this single-
            threaded sequential loop.

.LINK
    Microsoft Graph API - List groups
    https://learn.microsoft.com/en-us/graph/api/group-list

.LINK
    Microsoft Graph API - List group owners
    https://learn.microsoft.com/en-us/graph/api/group-list-owners

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Test-TeamGovernanceCompliance
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("id")]
        [string[]]$TeamId,

        [string]$NamingPattern,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    Begin
    {
        # Define an empty array to hold all finding records (one per
        # violation, plus one "Compliant" row per fully-compliant team)
        $findings = New-Object System.Collections.ArrayList
        $totalEvaluated = 0

        # Check if access token is obtained successfully
        if (-not $AccessToken)
        {
            Write-Error "AccessToken is required. Exiting function."
            return
        }

        # Validate the naming pattern compiles, if supplied, before spending
        # any API calls
        if ($NamingPattern)
        {
            Try
            {
                [regex]::new($NamingPattern) | Out-Null
            }
            Catch
            {
                Write-Error "NamingPattern is not a valid regular expression: $($_.Exception.Message)"
                return
            }
        }

        # Define the request headers with the access token
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "ConsistencyLevel" = "eventual"
        }

        # Always resolve team metadata (displayName, description, visibility)
        # via a single paginated call. If -TeamId was not supplied on the
        # command line and no pipeline input is expected, also use this pass
        # to resolve every team in the tenant automatically so TeamId behaves
        # as optional.
        $resolveAllTeams = (-not $PSBoundParameters.ContainsKey('TeamId')) -and (-not $MyInvocation.ExpectingInput)

        $teamMetaMap = @{}
        $allTeamIds  = New-Object System.Collections.ArrayList
        $teamsUri    = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName,description,visibility&`$count=true"

        Write-Verbose "Resolving team metadata..."
        do
        {
            $teamsSkip = $false
            do
            {
                Try
                {
                    $teamsPartial = Invoke-WebRequest -Uri $teamsUri -Headers $headers -Method Get -ErrorAction Stop
                    $teamsStatus  = $teamsPartial.StatusCode
                }
                catch
                {
                    $teamsStatus = $_.Exception.Response.StatusCode
                    if ($teamsStatus -eq 429)
                    {
                        $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                        Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                        Start-Sleep -Seconds $sleepTime
                    }
                    else
                    {
                        Write-Warning "Failed to resolve team metadata: $($_.Exception.Message). DisplayName/Description/Visibility will show 'Could not be confirmed'."
                        $teamsSkip = $true
                    }
                }
            } until(($teamsStatus -eq 200) -or $teamsSkip)

            if ($teamsSkip) { break }

            $teamsData = $teamsPartial.Content | ConvertFrom-Json
            $teamsData.value | ForEach-Object {
                $teamMetaMap[$_.id] = [PSCustomObject]@{
                    DisplayName = $_.displayName
                    Description = $_.description
                    Visibility  = $_.visibility
                }
                $null = $allTeamIds.Add($_.id)
            }

            if ($teamsData.PSObject.Properties['@odata.nextLink']) { $teamsUri = $teamsData.'@odata.nextLink' } else { $teamsUri = $null }

        } until (-not $teamsUri)

        if ($resolveAllTeams)
        {
            $TeamId = $allTeamIds
            Write-Verbose "Resolved $($TeamId.Count) team(s) to evaluate."
        }
    }

    Process
    {
        foreach ($id in $TeamId)
        {
            Try
            {
                $totalEvaluated++

                $meta = $teamMetaMap[$id]
                $teamDisplayName = if ($meta) { $meta.DisplayName } else { "Could not be confirmed" }
                $description     = if ($meta) { $meta.Description } else { $null }
                $visibility      = if ($meta) { $meta.Visibility }  else { "Could not be confirmed" }

                # ── Rule 1: Ownership ────────────────────────────────────────
                $uri = "https://graph.microsoft.com/v1.0/groups/$id/owners?`$select=id&`$top=100"
                $ownerCount = 0

                do
                {
                    $skip = $false
                    do
                    {
                        Try
                        {
                            $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                            $statusCode = $partialData.StatusCode;
                        }
                        catch
                        {
                            $statusCode = $_.Exception.Response.StatusCode;
                            $ErrorObject = $_

                            if($statusCode -eq 429)
                            {
                                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                                Write-host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                                Start-sleep -Seconds $sleepTime
                            }
                            else
                            {
                                $ErrorOutput = [PSCustomObject][ordered]@{
                                    TeamId      = $id
                                    Response    = $($ErrorObject.Exception.Response)
                                    StatusCode  = $($ErrorObject.Exception.Response.StatusCode)
                                    Message     = $($ErrorObject.Exception.Message)
                                };
                                $ErrorOutput | Format-List
                                $skip = $true;
                            }
                        }
                    } until(($statusCode -eq 200) -or $skip)

                    if ($skip)
                    {
                        Write-Warning "Failed to retrieve owners for team '$id'. Ownership rule will show 'Could not be confirmed'."
                        $ownerCount = -1
                        break
                    }

                    if($partialData)
                    {
                        $ownersData = $partialData.content | ConvertFrom-Json
                    }

                    $ownerCount += $ownersData.value.Count

                    if ($ownersData.PSObject.Properties['@odata.nextLink']) { $uri = $ownersData.'@odata.nextLink' }

                } until ($skip -or (-not($ownersData.PSObject.Properties['@odata.nextLink'])))

                # ── Evaluate rules ───────────────────────────────────────────
                $ruleResults = New-Object System.Collections.ArrayList

                if ($ownerCount -eq -1)
                {
                    $null = $ruleResults.Add([PSCustomObject]@{
                        RuleId   = "GOV-001"
                        RuleName = "Ownership"
                        Severity = "Unknown"
                        Passed   = $null
                        Details  = "Owner count could not be confirmed due to a Graph API error."
                    })
                }
                elseif ($ownerCount -eq 0)
                {
                    $null = $ruleResults.Add([PSCustomObject]@{
                        RuleId   = "GOV-001"
                        RuleName = "Ownership"
                        Severity = "Critical"
                        Passed   = $false
                        Details  = "Team has no owner (0 owners) and is effectively unmanaged."
                    })
                }
                elseif ($ownerCount -eq 1)
                {
                    $null = $ruleResults.Add([PSCustomObject]@{
                        RuleId   = "GOV-001"
                        RuleName = "Ownership"
                        Severity = "Warning"
                        Passed   = $false
                        Details  = "Team has only one owner, a single point of failure."
                    })
                }
                else
                {
                    $null = $ruleResults.Add([PSCustomObject]@{
                        RuleId   = "GOV-001"
                        RuleName = "Ownership"
                        Severity = "Pass"
                        Passed   = $true
                        Details  = "Team has $ownerCount owners."
                    })
                }

                if ($visibility -eq "Public")
                {
                    $null = $ruleResults.Add([PSCustomObject]@{
                        RuleId   = "GOV-002"
                        RuleName = "Visibility"
                        Severity = "Warning"
                        Passed   = $false
                        Details  = "Team visibility is Public; governance policy expects Private unless a documented exception exists."
                    })
                }
                elseif ($visibility -eq "Could not be confirmed")
                {
                    $null = $ruleResults.Add([PSCustomObject]@{
                        RuleId   = "GOV-002"
                        RuleName = "Visibility"
                        Severity = "Unknown"
                        Passed   = $null
                        Details  = "Team visibility could not be confirmed."
                    })
                }
                else
                {
                    $null = $ruleResults.Add([PSCustomObject]@{
                        RuleId   = "GOV-002"
                        RuleName = "Visibility"
                        Severity = "Pass"
                        Passed   = $true
                        Details  = "Team visibility is $visibility."
                    })
                }

                if ([string]::IsNullOrWhiteSpace($description))
                {
                    $null = $ruleResults.Add([PSCustomObject]@{
                        RuleId   = "GOV-003"
                        RuleName = "Description"
                        Severity = "Warning"
                        Passed   = $false
                        Details  = "Team is missing a description."
                    })
                }
                else
                {
                    $null = $ruleResults.Add([PSCustomObject]@{
                        RuleId   = "GOV-003"
                        RuleName = "Description"
                        Severity = "Pass"
                        Passed   = $true
                        Details  = "Team has a description."
                    })
                }

                if ($NamingPattern)
                {
                    if ($teamDisplayName -notmatch $NamingPattern)
                    {
                        $null = $ruleResults.Add([PSCustomObject]@{
                            RuleId   = "GOV-004"
                            RuleName = "NamingConvention"
                            Severity = "Warning"
                            Passed   = $false
                            Details  = "Team name '$teamDisplayName' does not match required pattern '$NamingPattern'."
                        })
                    }
                    else
                    {
                        $null = $ruleResults.Add([PSCustomObject]@{
                            RuleId   = "GOV-004"
                            RuleName = "NamingConvention"
                            Severity = "Pass"
                            Passed   = $true
                            Details  = "Team name matches required pattern '$NamingPattern'."
                        })
                    }
                }

                # ── Roll up compliance score (excludes Unknown/unconfirmed rules) ──
                $scoredRules   = $ruleResults | Where-Object { $null -ne $_.Passed }
                $rulesEvaluated = $scoredRules.Count
                $rulesFailed    = ($scoredRules | Where-Object { $_.Passed -eq $false }).Count
                $compliancePct  = if ($rulesEvaluated -gt 0) { [Math]::Round((($rulesEvaluated - $rulesFailed) / $rulesEvaluated) * 100, 2) } else { $null }

                $violations = $ruleResults | Where-Object { $_.Passed -eq $false -or $null -eq $_.Passed }

                if ($violations.Count -eq 0)
                {
                    $null = $findings.Add([PSCustomObject]@{
                        teamId               = $id
                        teamDisplayName      = $teamDisplayName
                        ruleId               = "N/A"
                        ruleName             = "N/A"
                        severity             = "Info"
                        status               = "Compliant"
                        details              = "All evaluated governance rules passed."
                        ownerCount           = $ownerCount
                        visibility           = $visibility
                        rulesEvaluated       = $rulesEvaluated
                        rulesFailed          = $rulesFailed
                        compliancePercentage = $compliancePct
                    })
                }
                else
                {
                    foreach ($violation in $violations)
                    {
                        $status = if ($null -eq $violation.Passed) { "Unknown" } else { "NonCompliant" }

                        $null = $findings.Add([PSCustomObject]@{
                            teamId               = $id
                            teamDisplayName      = $teamDisplayName
                            ruleId               = $violation.RuleId
                            ruleName             = $violation.RuleName
                            severity             = $violation.Severity
                            status               = $status
                            details              = $violation.Details
                            ownerCount           = $ownerCount
                            visibility           = $visibility
                            rulesEvaluated       = $rulesEvaluated
                            rulesFailed          = $rulesFailed
                            compliancePercentage = $compliancePct
                        })
                    }
                }
            }
            Catch
            {
                Write-Warning "Failed to evaluate team '$id': $($_.Exception.Message)"
                Continue
            }
        }
    }

    End
    {
        $nonCompliantTeamCount = ($findings | Where-Object { $_.status -eq "NonCompliant" } | Select-Object -ExpandProperty teamId -Unique).Count

        Write-Host ""
        Write-Host "Evaluated $totalEvaluated team(s); $nonCompliantTeamCount team(s) have at least one violation." -ForegroundColor Cyan

        # CSV EXPORT SUPPORT (added only)
        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $exportFolder = Split-Path -Path $ExportPath -Parent
            if ($exportFolder -and -not (Test-Path -Path $exportFolder))
            {
                New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
            }

            $findings | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "Team governance compliance report exported successfully → $ExportPath" -ForegroundColor Green
        }

        # Return the array list containing all findings
        # return $findings | Select-Object teamId, teamDisplayName, ruleId, ruleName, severity, status, details, ownerCount, visibility, rulesEvaluated, rulesFailed, compliancePercentage | FT
        return $findings
    }
}
