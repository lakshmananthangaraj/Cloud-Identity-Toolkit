<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 08 August 2026
Modified-On     : 08 August 2026

.SYNOPSIS
    Retrieves Microsoft Purview retention policies that apply to Microsoft Teams
    workloads using the Microsoft Graph Beta API.

.DESCRIPTION
    This function queries the Microsoft Graph Beta endpoint to retrieve all
    retention policies configured in Microsoft Purview that are scoped to
    Teams workloads (TeamsChannelMessages and/or TeamsChatMessages).

    It reports each policy's name, retention duration, retention action,
    the Teams workloads it covers, and whether specific Teams are included
    or excluded (adaptive scope vs. static scope). When a static policy
    includes specific team IDs, those are cross-referenced against the
    tenant's team display names for readability.

    This function handles pagination automatically via @odata.nextLink, retries
    on API throttling (HTTP 429) using the Retry-After header, and validates
    the JSON response before processing it further.

    Results can optionally be exported to CSV. Essential for compliance audits
    to verify that all Teams data is covered by an appropriate retention policy.

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
        - policyId, policyName, retentionDuration, retentionDurationUnit,
          retentionAction, isEnabled, teamsWorkloadsInScope,
          scopeType, specificTeamsIncluded, specificTeamsExcluded

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        RecordsManagement.Read.All (Application or Delegated)
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
        An array of custom objects containing retention policy attributes
        scoped to Teams workloads. Also optionally exports to CSV.

.EXAMPLE
    Get-TeamRetentionPolicy -AccessToken $token

    Retrieves all Purview retention policies covering Teams workloads.

.EXAMPLE
    Get-TeamRetentionPolicy -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\TeamRetentionPolicies.csv"

    Retrieves all Teams retention policies and exports the result to a CSV file.

.EXAMPLE
    $token = Get-AccessToken
    Get-TeamRetentionPolicy -AccessToken $token

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
                RecordsManagement.Read.All (Application or Delegated)
                Group.Read.All (Application or Delegated)

        2. Retention policies must be configured in Microsoft Purview
           (Microsoft 365 compliance portal) before this function will return
           any results.

        3. The caller's account or service principal must be assigned the
           Records Management or Compliance Administrator role in Purview for
           the RecordsManagement.Read.All permission to be effective.

        4. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Resolve a teamId -> displayName lookup map via a single
                   paginated GET /v1.0/groups call (used to expand specific
                   team GUIDs in static policy scopes to human-readable names)
        Step 2  →  Call GET /beta/security/dataSecurityAndGovernance/retentionPolicies
                   with pagination to retrieve all tenant retention policies
        Step 3  →  Retry on HTTP 429 using Retry-After header
        Step 4  →  Filter to policies containing TeamsChannelMessages or
                   TeamsChatMessages workloads in their locations
        Step 5  →  For each matching policy, flatten scope details:
                   adaptive vs. static, included/excluded team lists
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Uses the Microsoft Graph Beta endpoint which is subject to change
          without notice; validate against current API behaviour before
          relying on this in production.
        - Retention policies applied via adaptive scopes (Purview adaptive
          scopes using KQL queries) will report scopeType = "Adaptive" but
          the specific Teams matched by the adaptive scope query cannot be
          enumerated via this endpoint; only the scope name is reported.
        - Hold policies (eDiscovery holds) are not the same as retention
          policies and are not returned by this function.
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
    Microsoft Graph Beta API - List retentionPolicies
    https://learn.microsoft.com/en-us/graph/api/security-retentionpolicy-list

.LINK
    Microsoft Purview retention policies for Teams
    https://learn.microsoft.com/en-us/microsoft-365/compliance/retention-policies-teams

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-TeamRetentionPolicy
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

    # Define an empty array to hold all retention policy records
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
    # Step 2: Retrieve retention policies from Purview via Graph Beta
    # ─────────────────────────────────────────────────────────────────────────
    $uri = "https://graph.microsoft.com/beta/security/dataSecurityAndGovernance/retentionPolicies"

    Write-Host ""
    Write-Host "Retrieving retention policies from Microsoft Purview..." -ForegroundColor Cyan

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
            Write-Warning "Failed to retrieve retention policies. Exiting."
            break
        }

        $policiesData = $partialData.Content | ConvertFrom-Json

        # ─────────────────────────────────────────────────────────────────
        # Step 3: Filter to Teams workload policies and flatten each record
        # ─────────────────────────────────────────────────────────────────
        @($policiesData.value) | ForEach-Object {
            $policy = $_

            # Collect the workload locations for this policy
            $locations       = @($policy.locations)
            $teamsWorkloads  = @($locations | Where-Object {
                $_.name -eq "TeamsChannelMessages" -or $_.name -eq "TeamsChatMessages"
            })

            # Skip policies that do not cover any Teams workload
            if ($teamsWorkloads.Count -eq 0) { return }

            $workloadNames = ($teamsWorkloads | Select-Object -ExpandProperty name) -join "; "

            # Determine scope type (adaptive or static) and extract included/excluded team names
            $scopeType               = "Static"
            $specificTeamsIncluded   = "All Teams"
            $specificTeamsExcluded   = "None"

            # Check for adaptive scope references (adaptiveScopeHolders)
            if ($policy.PSObject.Properties['adaptiveScopeHolders'] -and @($policy.adaptiveScopeHolders).Count -gt 0)
            {
                $scopeType             = "Adaptive"
                $specificTeamsIncluded = (@($policy.adaptiveScopeHolders) | Select-Object -ExpandProperty displayName) -join "; "
                $specificTeamsExcluded = "N/A (Adaptive scope)"
            }
            else
            {
                # Static scope — check included and excluded locations per Teams workload
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

            # Parse retention duration from retentionDuration object
            $retentionDuration     = "Could not be confirmed"
            $retentionDurationUnit = "Could not be confirmed"
            if ($policy.PSObject.Properties['retentionDuration'])
            {
                $rd = $policy.retentionDuration
                if ($rd.PSObject.Properties['duration'])      { $retentionDuration     = $rd.duration }
                if ($rd.PSObject.Properties['durationType'])  { $retentionDurationUnit = $rd.durationType }
            }

            $null = $allPolicyRecords.Add(
                [PSCustomObject]@{
                    policyId               = if ($policy.id)           { $policy.id }           else { "N/A" }
                    policyName             = if ($policy.displayName)   { $policy.displayName }  else { "Could not be confirmed" }
                    retentionDuration      = $retentionDuration
                    retentionDurationUnit  = $retentionDurationUnit
                    retentionAction        = if ($policy.PSObject.Properties['retentionTrigger']) { $policy.retentionTrigger } else { "Could not be confirmed" }
                    isEnabled              = if ($policy.PSObject.Properties['isEnabled'])        { $policy.isEnabled }        else { "Could not be confirmed" }
                    teamsWorkloadsInScope  = $workloadNames
                    scopeType              = $scopeType
                    specificTeamsIncluded  = $specificTeamsIncluded
                    specificTeamsExcluded  = $specificTeamsExcluded
                }
            )

            $totalRecords++
        }

        Write-Host "Progress: $totalRecords Teams-scoped retention polic(ies) found so far" -ForegroundColor Cyan

        if ($policiesData.PSObject.Properties['@odata.nextLink']) { $uri = $policiesData.'@odata.nextLink' } else { $uri = $null }

    } until (-not $uri)

    Write-Host ""
    Write-Host "Retention policy retrieval complete. Total Teams-scoped policies found: $totalRecords" -ForegroundColor Green

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
        Write-Host "Teams retention policy report exported successfully → $ExportPath" -ForegroundColor Green
    }

    return $allPolicyRecords
}
