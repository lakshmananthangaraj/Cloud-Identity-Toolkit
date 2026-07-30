<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 30 July 2026
Modified-On     : 30 July 2026

.SYNOPSIS
    Lists device configuration profiles (settings, restrictions, etc.)
    from Intune with assignment details, using the Microsoft Graph API.

.DESCRIPTION
    Queries the Microsoft Graph beta endpoint to retrieve all device
    configuration profiles configured in Intune, expanding each profile's
    group assignments in the same call. Handles pagination automatically
    via @odata.nextLink, retries on API throttling (HTTP 429) using the
    Retry-After header, and validates the JSON response before processing.

    Configuration profiles span many platform-specific types
    (windows10GeneralConfiguration, iosGeneralDeviceConfiguration,
    androidWorkProfileGeneralDeviceConfiguration, etc.); the profile's
    @odata.type is captured as ProfileType so the platform/category can be
    identified without a separate lookup per profile.

    Results can optionally be exported to CSV. Since a profile can have
    multiple assignments, the exported CSV contains one row per
    (profile, assignment) pair; profiles with no assignments still appear
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
        An array of custom objects containing profile details and
        assignment targets, one row per (profile, assignment) pair. Also
        optionally exports to CSV.

.EXAMPLE
    Get-ConfigurationProfiles -AccessToken $token

    Retrieves all device configuration profiles and their assignments.

.EXAMPLE
    Get-ConfigurationProfiles -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\ConfigProfiles.csv"

    Retrieves all configuration profiles and exports the result to CSV.

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
    Step 1  →  Build the initial /beta/deviceManagement/deviceConfigurations
               request URI with $expand=assignments
    Step 2  →  Call Microsoft Graph, retrying on HTTP 429 using Retry-After
    Step 3  →  Parse the JSON response and flatten each profile's
               assignments into one row per assignment target
    Step 4  →  Follow @odata.nextLink until pagination is exhausted
    Step 5  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Uses the /beta Graph API endpoint. Beta endpoints are subject to
      change and are not recommended for production without monitoring
      for breaking changes.
    - Does not cover Settings Catalog profiles
      (deviceManagement/configurationPolicies), which use a different
      Graph resource than legacy deviceConfigurations. If your tenant uses
      Settings Catalog profiles extensively, a companion script against
      that endpoint would be needed for full coverage.
    - Assignment targets are reported as group object IDs (or "All
      devices"/"All users"), not resolved group display names.
    - Individual setting values (e.g. specific restriction toggles) are
      not flattened into columns - only profile-level metadata and
      assignments are reported.
    - SINGLE-TOKEN, SEQUENTIAL PAGINATION: does not refresh the token
      mid-run; see Get-ManagedDevices.ps1 Known Limitations for the same
      caveat on very large profile sets.

.LINK
    Microsoft Graph API - deviceConfiguration resource type
    https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-deviceconfiguration

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-ConfigurationProfiles
{
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    # Define an empty array to hold all profile/assignment rows
    $allProfiles = New-Object System.Collections.ArrayList
    $totalProfiles = 0

    # Define the initial URI to retrieve all configuration profiles with assignments expanded
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$top=50&`$expand=assignments"

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
            $profileData = $partialData.content | ConvertFrom-Json
        }

        Write-Host ""
        Write-Host "Progress: $($totalProfiles += $profileData.value.Count; $totalProfiles) configuration profiles retrieved so far" -ForegroundColor Cyan

        if ($profileData.PSObject.Properties['@odata.nextLink']) { $uri = $profileData.'@odata.nextLink' }

        # Flatten each profile into one row per assignment target
        $profileData.value | ForEach-Object {

            $profile = $_
            $profileType = if ($profile.PSObject.Properties['@odata.type']) { $profile.'@odata.type' -replace '#microsoft.graph.','' } else { $null }

            if ($profile.assignments -and $profile.assignments.Count -gt 0)
            {
                foreach ($assignment in $profile.assignments)
                {
                    $targetType = if ($assignment.target.PSObject.Properties['@odata.type']) { $assignment.target.'@odata.type' -replace '#microsoft.graph.','' } else { $null }
                    $targetGroupId = if ($assignment.target.PSObject.Properties['groupId']) { $assignment.target.groupId } else { $null }

                    $assignmentLabel = switch ($targetType)
                    {
                        'allDevicesAssignmentTarget' { 'All devices' }
                        'allLicensedUsersAssignmentTarget' { 'All users' }
                        default { if ($targetGroupId) { "Group: $targetGroupId" } else { $targetType } }
                    }

                    $null = $allProfiles.Add(
                        [PSCustomObject]@{
                            Id                   = $profile.id
                            DisplayName          = $profile.displayName
                            Description          = $profile.description
                            ProfileType          = $profileType
                            Version              = $profile.version
                            CreatedDateTime      = $profile.createdDateTime
                            LastModifiedDateTime = $profile.lastModifiedDateTime
                            AssignmentTarget     = $assignmentLabel
                        }
                    )
                }
            }
            else
            {
                $null = $allProfiles.Add(
                    [PSCustomObject]@{
                        Id                   = $profile.id
                        DisplayName          = $profile.displayName
                        Description          = $profile.description
                        ProfileType          = $profileType
                        Version              = $profile.version
                        CreatedDateTime      = $profile.createdDateTime
                        LastModifiedDateTime = $profile.lastModifiedDateTime
                        AssignmentTarget     = '(unassigned)'
                    }
                )
            }
        }

    } until (-not($profileData.PSObject.Properties['@odata.nextLink']))

    # CSV EXPORT SUPPORT
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allProfiles | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Configuration profiles report exported successfully → $ExportPath" -ForegroundColor Green
    }

    # return $allProfiles | Select-Object DisplayName, ProfileType, AssignmentTarget, LastModifiedDateTime | FT
    return $allProfiles
}
