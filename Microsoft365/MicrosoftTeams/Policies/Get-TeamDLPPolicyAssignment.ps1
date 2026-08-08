<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 08 August 2026
Modified-On     : 08 August 2026

.SYNOPSIS
    Retrieves Microsoft Purview Data Loss Prevention (DLP) policies that are
    assigned to Microsoft Teams workloads using the Microsoft Graph Beta API.

.DESCRIPTION
    This function queries the Microsoft Graph Beta endpoint to retrieve all
    DLP policies configured in Microsoft Purview that are scoped to Teams
    workloads (TeamsChannelMessages and/or TeamsChatMessages).

    It reports each policy's name, enabled state, policy mode (enforce vs.
    test/audit), the Teams workloads it covers, scope type (static or adaptive),
    and whether specific Teams are explicitly included or excluded. When a static
    policy includes specific team IDs, those are cross-referenced against the
    tenant's team display names for readability.

    This function handles pagination automatically via @odata.nextLink, retries
    on API throttling (HTTP 429) using the Retry-After header, and validates
    the JSON response before processing it further.

    Results can optionally be exported to CSV. Useful for compliance audits to
    verify DLP policy coverage across Teams and identify any coverage gaps.

    IMPORTANT: Microsoft Graph Beta APIs are subject to change and may be
    deprecated or altered without notice. This function should be reviewed and
    tested against current Beta API behaviour before use in production.

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

    The following attributes are collected per policy:
        - policyId, policyName, policyMode, isEnabled, teamsWorkloadsInScope,
          scopeType, specificTeamsIncluded, specificTeamsExcluded,
          ruleCount, sensitiveInfoTypesProtected

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        InformationProtectionPolicy.Read.All (Application or Delegated)
        Group.Read.All (Application or Delegated) — for team name resolution

    To obtain this token via app-only authentication instead of an interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
        An array of custom objects containing DLP policy attributes scoped to
        Teams workloads. Also optionally exports to CSV.

.EXAMPLE
    Get-TeamDLPPolicyAssignment -AccessToken $token

    Retrieves all Purview DLP policies covering Teams workloads.

.EXAMPLE
    Get-TeamDLPPolicyAssignment -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamDLPPolicies.csv"

    Retrieves all Teams DLP policy assignments and exports the result to a CSV file.

.EXAMPLE
    $token = Get-AccessToken
    Get-TeamDLPPolicyAssignment -AccessToken $token

    Demonstrates usage with a dynamically generated access token.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (08-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                InformationProtectionPolicy.Read.All (Application or Delegated)
                Group.Read.All (Application or Delegated)

        2. DLP policies must be configured in Microsoft Purview
           (Microsoft 365 compliance portal) before this function will return
           any results.

        3. The caller's account or service principal must be assigned the
           DLP Compliance Management or Compliance Administrator role in Purview
           for InformationProtectionPolicy.Read.All to be effective.

        4. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve a teamId -> displayName lookup map via a single
                   paginated GET /v1.0/groups call (used to expand specific
                   team GUIDs in static policy scopes to human-readable names)
        Step 2  →  Call GET /beta/security/dataLossPrevention/policies with
                   pagination to retrieve all tenant DLP policies
        Step 3  →  Retry on HTTP 429 using Retry-After header
        Step 4  →  Filter to policies containing TeamsChannelMessages or
                   TeamsChatMessages workloads in their locations
        Step 5  →  For each matching policy, flatten scope details, policy mode,
                   rule count, and sensitive information types protected
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the Microsoft Graph Beta endpoint which is subject to change
          without notice; validate against current API behaviour before
          relying on this in production.
        - DLP policies operate at workload level (all of Teams) or with specific
          Teams included/excluded as static locations. Per-team DLP assignment is
          not an independent concept in Purview — this function reflects the
          policy-centric view, not a per-team view.
        - Policies in Test/Audit mode (policyMode != Enforce) are still reported
          but flagged; they do not actively block sharing in Teams.
        - sensitiveInfoTypesProtected lists type names from the first DLP rule
          containing a sensitiveInformation condition; policies with complex
          multi-rule structures may not have all types fully enumerated.
        - Requires a valid bearer token with the specified permissions.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer
          token for the entire run and does not refresh it mid-run. In very
          large tenants, if the full pull takes longer than the token's
          lifetime (typically ~60-90 minutes), the run will fail partway through
          with 401 Unauthorized once the token expires.
        - RECOMMENDED FOR: smaller tenants, scoped/filtered pulls, or quick
          one-off/ad-hoc workarounds.
        - NOT RECOMMENDED AS-IS FOR: large/enterprise-scale tenants. For those,
          implement a proper token-refresh pattern (re-acquire via app-only
          client-credentials auth on a timer or before each page/batch) and
          consider parallelized/batched Graph calls instead of this single-
          threaded sequential loop.

.LINK
    Microsoft Graph Beta API - List DLP policies
    https://learn.microsoft.com/en-us/graph/api/security-dlppolicies-list

.LINK
    Microsoft Purview DLP for Microsoft Teams
    https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-microsoft-teams

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamDLPPolicyAssignment
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Define an empty array to hold all DLP policy records
    $allPolicyRecords = New-Object System.Collections.ArrayList
    $totalRecords     = 0

    # Check if access token is obtained successfully
    if (-not $AccessToken)
    {
        Write-Error "AccessToken is required. Exiting function."
        return
    }

    # Define the request headers with the access token
    $headers = @{
        "Authorization"    = "Bearer $AccessToken"
        "ConsistencyLevel" = "eventual"
    }

    # ─────────────────────────────────────────────────────────────────────────
    # Step 1: Resolve teamId -> displayName lookup map for scope expansion
    # ─────────────────────────────────────────────────────────────────────────
    $teamNameMap = @{}
    $teamsUri    = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName&`$count=true"

    Write-Verbose "Resolving team display names for scope expansion..."
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
                    Write-Warning "Failed to resolve team display names: $($_.Exception.Message). Team GUIDs in policy scopes will not be expanded to display names."
                    $teamsSkip = $true
                }
            }
        } until (($teamsStatus -eq 200) -or $teamsSkip)

        if ($teamsSkip) { break }

        $teamsData = $teamsPartial.Content | ConvertFrom-Json
        @($teamsData.value) | ForEach-Object {
            $teamNameMap[$_.id] = $_.displayName
        }

        if ($teamsData.PSObject.Properties['@odata.nextLink']) { $teamsUri = $teamsData.'@odata.nextLink' } else { $teamsUri = $null }

    } until (-not $teamsUri)

    Write-Verbose "Team name map built with $($teamNameMap.Count) entries."

    # ─────────────────────────────────────────────────────────────────────────
    # Step 2: Retrieve DLP policies from Purview via Graph Beta
    # ─────────────────────────────────────────────────────────────────────────
    $uri = "https://graph.microsoft.com/beta/security/dataLossPrevention/policies"

    Write-Host ""
    Write-Host "Retrieving DLP policies from Microsoft Purview..." -ForegroundColor Cyan

    do
    {
        $skip = $false
        do
        {
            Try
            {
                $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                $statusCode  = $partialData.StatusCode
            }
            catch
            {
                $statusCode  = $_.Exception.Response.StatusCode
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
                    $skip = $true
                }
            }
        } until (($statusCode -eq 200) -or $skip)

        if ($skip)
        {
            Write-Warning "Failed to retrieve DLP policies. Exiting."
            break
        }

        $policiesData = $partialData.Content | ConvertFrom-Json

        # ─────────────────────────────────────────────────────────────────
        # Step 3: Filter to Teams workload policies and flatten each record
        # ─────────────────────────────────────────────────────────────────
        @($policiesData.value) | ForEach-Object {
            $policy = $_

            Try
            {
                # Collect the workload locations for this policy
                $locations      = @($policy.locations)
                $teamsWorkloads = @($locations | Where-Object {
                    $_.name -eq "TeamsChannelMessages" -or $_.name -eq "TeamsChatMessages"
                })

                # Skip policies that do not cover any Teams workload
                if ($teamsWorkloads.Count -eq 0) { return }

                $workloadNames = ($teamsWorkloads | Select-Object -ExpandProperty name) -join "; "

                # Determine scope type and included/excluded team names
                $scopeType             = "Static"
                $specificTeamsIncluded = "All Teams"
                $specificTeamsExcluded = "None"

                # Check for adaptive scope references
                if ($policy.PSObject.Properties['adaptiveScopeHolders'] -and @($policy.adaptiveScopeHolders).Count -gt 0)
                {
                    $scopeType             = "Adaptive"
                    $specificTeamsIncluded = (@($policy.adaptiveScopeHolders) | Select-Object -ExpandProperty displayName) -join "; "
                    $specificTeamsExcluded = "N/A (Adaptive scope)"
                }
                else
                {
                    $includedIds = New-Object System.Collections.ArrayList
                    $excludedIds = New-Object System.Collections.ArrayList

                    $teamsWorkloads | ForEach-Object {
                        @($_.inclusionExclusion.inclusions) | ForEach-Object {
                            if ($_ -and $_.PSObject.Properties['id']) { $null = $includedIds.Add($_.id) }
                        }
                        @($_.inclusionExclusion.exclusions) | ForEach-Object {
                            if ($_ -and $_.PSObject.Properties['id']) { $null = $excludedIds.Add($_.id) }
                        }
                    }

                    if ($includedIds.Count -gt 0)
                    {
                        $specificTeamsIncluded = ($includedIds | ForEach-Object {
                            if ($teamNameMap.ContainsKey($_)) { $teamNameMap[$_] } else { $_ }
                        }) -join "; "
                    }

                    if ($excludedIds.Count -gt 0)
                    {
                        $specificTeamsExcluded = ($excludedIds | ForEach-Object {
                            if ($teamNameMap.ContainsKey($_)) { $teamNameMap[$_] } else { $_ }
                        }) -join "; "
                    }
                }

                # Count rules and extract sensitive info type names from the first matching rule
                $rules            = @($policy.rules)
                $ruleCount        = $rules.Count
                $sensitiveInfoTypes = "None detected"

                $firstSensitiveRule = $rules | Where-Object {
                    $_.PSObject.Properties['conditions'] -and
                    @($_.conditions) | Where-Object { $_.PSObject.Properties['sensitiveInformation'] }
                } | Select-Object -First 1

                if ($firstSensitiveRule)
                {
                    $sitNames = @($firstSensitiveRule.conditions) | Where-Object {
                        $_.PSObject.Properties['sensitiveInformation']
                    } | ForEach-Object {
                        @($_.sensitiveInformation) | ForEach-Object {
                            if ($_.PSObject.Properties['name']) { $_.name }
                        }
                    }
                    if (@($sitNames).Count -gt 0) { $sensitiveInfoTypes = $sitNames -join "; " }
                }

                $null = $allPolicyRecords.Add(
                    [PSCustomObject]@{
                        policyId                  = if ($policy.id)          { $policy.id }          else { "N/A" }
                        policyName                = if ($policy.displayName) { $policy.displayName } else { "Could not be confirmed" }
                        policyMode                = if ($policy.PSObject.Properties['mode'])      { $policy.mode }      else { "Could not be confirmed" }
                        isEnabled                 = if ($policy.PSObject.Properties['isEnabled']) { $policy.isEnabled } else { "Could not be confirmed" }
                        teamsWorkloadsInScope     = $workloadNames
                        scopeType                 = $scopeType
                        specificTeamsIncluded     = $specificTeamsIncluded
                        specificTeamsExcluded     = $specificTeamsExcluded
                        ruleCount                 = $ruleCount
                        sensitiveInfoTypesProtected = $sensitiveInfoTypes
                    }
                )

                $totalRecords++
            }
            Catch
            {
                Write-Warning "Error processing DLP policy '$($policy.id)': $($_.Exception.Message)"
            }
        }

        Write-Host "Progress: $totalRecords Teams-scoped DLP polic(ies) found so far" -ForegroundColor Cyan

        if ($policiesData.PSObject.Properties['@odata.nextLink']) { $uri = $policiesData.'@odata.nextLink' } else { $uri = $null }

    } until (-not $uri)

    Write-Host ""
    Write-Host "DLP policy retrieval complete. Total Teams-scoped policies found: $totalRecords" -ForegroundColor Green

    # CSV EXPORT SUPPORT
    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $exportFolder = Split-Path -Path $ExportPath -Parent
        if ($exportFolder -and -not (Test-Path -Path $exportFolder))
        {
            New-Item -Path $exportFolder -ItemType Directory -Force | Out-Null
        }

        $allPolicyRecords | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Teams DLP policy assignment report exported successfully → $ExportPath" -ForegroundColor Green
    }

    return $allPolicyRecords
}
