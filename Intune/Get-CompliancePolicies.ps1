<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 30 July 2026
Modified-On     : 30 July 2026

.SYNOPSIS
    Retrieves all device compliance policies from Intune, including
    settings and assignments, using the Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph beta endpoint to retrieve all device
    compliance policies configured in Intune, expanding each policy's
    group assignments in the same call. Handles pagination automatically
    via @odata.nextLink, retries on API throttling (HTTP 429) using the
    Retry-After header, and validates the JSON response before processing.

    Because compliance policies span multiple platform-specific types
    (windows10CompliancePolicy, iosCompliancePolicy, androidCompliancePolicy,
    etc.), the policy's @odata.type is captured as PolicyType so the
    platform can be identified without a separate lookup per policy.

    Results can optionally be exported to CSV. Since a policy can have
    multiple assignments, the exported CSV contains one row per
    (policy, assignment) pair; policies with no assignments still appear
    as a single row with AssignmentTarget = "(unassigned)".

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permission:
        DeviceManagementConfiguration.Read.All

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to:
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
        An array of custom objects containing policy details and
        assignment targets, one row per (policy, assignment) pair. Also
        optionally exports to CSV.

.EXAMPLE
    Get-CompliancePolicies -AccessToken $token

    Retrieves all device compliance policies and their assignments.

.EXAMPLE
    Get-CompliancePolicies -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\CompliancePolicies.csv"

    Retrieves all compliance policies and exports the result to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (30-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. A valid Microsoft Graph access token with the following permission:
            DeviceManagementConfiguration.Read.All (Application or Delegated)
    2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
    Step 1  →  Build the initial /beta/deviceManagement/deviceCompliancePolicies
               request URI with $expand=assignments
    Step 2  →  Call Microsoft Graph, retrying on HTTP 429 using Retry-After
    Step 3  →  Parse the JSON response and flatten each policy's assignments
               into one row per assignment target
    Step 4  →  Follow @odata.nextLink until pagination is exhausted
    Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Uses the /beta Graph API endpoint. Beta endpoints are subject to
      change and are not recommended for production without monitoring
      for breaking changes.
    - Assignment targets are reported as group object IDs (or
      "All devices"/"All users" for built-in targets), not resolved group
      display names - resolve via /groups/{id} separately if friendly
      names are needed.
    - Per-setting policy configuration (e.g. specific password rules) is
      not flattened into columns in this version - only policy-level
      metadata and assignments are reported. The raw settings JSON can be
      added as an extra column if deeper drill-down is needed.
    - SINGLE-TOKEN, SEQUENTIAL PAGINATION: does not refresh the token
      mid-run; see Get-ManagedDevices.ps1 Known Limitations for the same
      caveat on very large policy sets.

.LINK
    Microsoft Graph API - deviceCompliancePolicy resource type
    https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicecompliancepolicy

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-CompliancePolicies
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Define an empty array to hold all policy/assignment rows
    $allPolicies = New-Object System.Collections.ArrayList
    $totalPolicies = 0

    # Define the initial URI to retrieve all compliance policies with assignments expanded
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$top=50&`$expand=assignments"

    # Start a do-while loop to handle pagination
    do
    {
        if (-not $accessToken)
        {
            Write-Error "AccessToken is required. Exiting function."
            return
        }

        $headers = @{
            "Authorization" = "Bearer $accessToken"
        }

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
                        Response    = $($ErrorObject.Exception.Response)
                        StatusCode  = $($ErrorObject.Exception.Response.StatusCode)
                        Message     = $($ErrorObject.Exception.Message)
                    };
                    $ErrorOutput | Format-List
                    [boolean]$Skip = $true;
                }
            }
        } until(($statusCode -eq 200) -or ([boolean]$skip = $true))

        if($partialData)
        {
            $policyData = $partialData.content | ConvertFrom-Json
        }

        Write-Host ""
        Write-Host "Progress: $($totalPolicies += $policyData.value.Count; $totalPolicies) compliance policies retrieved so far" -ForegroundColor Cyan

        if ($policyData.PSObject.Properties['@odata.nextLink']) { $uri = $policyData.'@odata.nextLink' }

        # Flatten each policy into one row per assignment target
        $policyData.value | ForEach-Object {

            $policy = $_
            $policyType = if ($policy.PSObject.Properties['@odata.type']) { $policy.'@odata.type' -replace '#microsoft.graph.','' } else { $null }

            if ($policy.assignments -and $policy.assignments.Count -gt 0)
            {
                foreach ($assignment in $policy.assignments)
                {
                    $targetType = if ($assignment.target.PSObject.Properties['@odata.type']) { $assignment.target.'@odata.type' -replace '#microsoft.graph.','' } else { $null }
                    $targetGroupId = $assignment.target.groupId

                    $assignmentLabel = switch ($targetType)
                    {
                        'allDevicesAssignmentTarget' { 'All devices' }
                        'allLicensedUsersAssignmentTarget' { 'All users' }
                        default { if ($targetGroupId) { "Group: $targetGroupId" } else { $targetType } }
                    }

                    $null = $allPolicies.Add(
                        [PSCustomObject]@{
                            Id                  = $policy.id
                            DisplayName         = $policy.displayName
                            Description         = $policy.description
                            PolicyType          = $policyType
                            Version             = $policy.version
                            CreatedDateTime     = $policy.createdDateTime
                            LastModifiedDateTime = $policy.lastModifiedDateTime
                            AssignmentTarget    = $assignmentLabel
                        }
                    )
                }
            }
            else
            {
                $null = $allPolicies.Add(
                    [PSCustomObject]@{
                        Id                  = $policy.id
                        DisplayName         = $policy.displayName
                        Description         = $policy.description
                        PolicyType          = $policyType
                        Version             = $policy.version
                        CreatedDateTime     = $policy.createdDateTime
                        LastModifiedDateTime = $policy.lastModifiedDateTime
                        AssignmentTarget    = '(unassigned)'
                    }
                )
            }
        }

    } until (-not($policyData.PSObject.Properties['@odata.nextLink']))

    # CSV EXPORT SUPPORT
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allPolicies | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Compliance policies report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # return $allPolicies | Select-Object DisplayName, PolicyType, AssignmentTarget, LastModifiedDateTime | FT
    return $allPolicies
}
