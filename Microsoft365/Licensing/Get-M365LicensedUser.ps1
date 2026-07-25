<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 21 May 2025
Modified-On     : 25 July 2026

.SYNOPSIS
    Retrieves Microsoft 365 users who have at least one assigned license, enriched with
    license/service plan mapping and sign-in activity, from Microsoft Graph.

.DESCRIPTION
    This function retrieves the Microsoft 365 subscribed license inventory, then queries
    Microsoft Graph (beta endpoint) for users who have at least one assigned license
    (server-side filtered via assignedLicenses/$count ne 0), and enriches each user with:

        - License assignments mapped from SKU GUIDs to friendly SKU part numbers
        - Disabled service plans mapped to friendly service plan names
        - Sign-in activity details (last attempt, last successful sign-in)
        - Derived inactivity status (no successful sign-in, or >90 days since last one)

    It handles pagination automatically via @odata.nextLink and retries on API throttling
    (HTTP 429) using the Retry-After header. Optional verbose progress output and optional
    file-based logging of API activity are supported.

    Results can optionally be exported to CSV.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK
    below, then pass its returned token into -AccessToken.

    This function is useful for Microsoft 365 license governance, identity reporting,
    and user activity monitoring — scoped specifically to the licensed user population
    (unlicensed accounts are excluded by the Graph filter, not by client-side discarding).

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        User.Read.All / Directory.Read.All
        Access to /subscribedSkus and /users endpoints

    To obtain this token via app-only authentication instead of an interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER LogFilePath
    Optional. If provided, logs API request activity (timestamped) to the specified file path.

.PARAMETER VerboseOutput
    Optional switch. Enables real-time progress output while retrieving users.

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
    System.Management.Automation.PSCustomObject
        A collection of enriched, license-assigned Microsoft 365 user objects containing:
            - Profile details (DisplayName, UPN, Country, Department, JobTitle, Company)
            - DirectLicenses (mapped SKU part numbers), DisabledPlans (mapped names)
            - GroupBasedLicenses, LastLicenseChange (reserved; currently $null — see
              Known Limitations)
            - AccountStatus, AccountCreated
            - LastSignInAttempt, LastSuccessfulSignIn, DaysSinceLastSignIn,
              InactiveUserStatus
        Also optionally exports to CSV.

.EXAMPLE
    Get-M365LicensedUser -AccessToken $token

    Retrieves all license-assigned users with license and sign-in details.

.EXAMPLE
    Get-M365LicensedUser -AccessToken $token -VerboseOutput

    Retrieves license-assigned users with real-time progress output.

.EXAMPLE
    Get-M365LicensedUser -AccessToken $token -LogFilePath "C:\Logs\M365Users.log"

    Retrieves license-assigned users and logs API activity to a file.

.EXAMPLE
    Get-M365LicensedUser -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\LicensedUsers.csv"

    Retrieves license-assigned users and exports the result to a CSV file.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (21-May-2025)  - Initial release 

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                User.Read.All / Directory.Read.All (Application)
                Access to /subscribedSkus and /users endpoints

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Retrieve license inventory from /v1.0/subscribedSkus
        Step 2  →  Query /beta/users, filtered to assignedLicenses/$count ne 0,
                    with pagination and throttling retry
        Step 3  →  Map each user's assignedLicenses skuId to a friendly skuPartNumber
        Step 4  →  Map disabled service plans (assignedPlans) to friendly names
        Step 5  →  Compute sign-in activity and derived inactivity status
        Step 6  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The function uses the /beta Graph API endpoint for users, and /v1.0 for
            subscribedSkus. Beta endpoints are subject to change and are not
            recommended for production without monitoring for breaking changes.
        - GroupBasedLicenses and LastLicenseChange are currently always $null.
            Distinguishing directly assigned vs. group-based license assignment
            requires the licenseAssignmentStates property (not currently selected)
            rather than assignedLicenses, which reflects the effective license set
            regardless of source. This is reserved for a future enhancement.
        - The assignedLicenses/$count ne 0 filter requires Graph advanced query
            support (ConsistencyLevel: eventual + $count=true), which this function
            already sets — no additional configuration needed, but be aware if
            reusing this filter pattern elsewhere without those headers.
        - signInActivity (and its nested properties) may be absent depending on
            licensing/tenant configuration; these are guarded individually rather
            than assumed present.
        - No token-refresh handling: a single Bearer token is used for the entire
            paginated run (see Get-AllUsers's Known Limitations for the general
            token-expiry caveat in large tenants).

.LINK
    Microsoft Graph API - User resource type
    https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-beta

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-M365LicensedUser
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath,

        [string]$LogFilePath = $null,

        [switch]$VerboseOutput
    )

    $headers = @{
        Authorization    = "Bearer $AccessToken"
        ConsistencyLevel = "eventual"
    }

    # Step 1: Get license inventory from Microsoft Graph
    try {
        $licenseInventoryUrl = "https://graph.microsoft.com/beta/subscribedSkus"
        $licenseInventoryResponse = Invoke-RestMethod -Uri $licenseInventoryUrl -Headers $headers -Method Get
        $licenseInventory = $licenseInventoryResponse.value
    }
    catch {
        Write-Error "Failed to retrieve license inventory: $_"
        return
    }

    # Prepare user query
    $selectFields = @(
        "id",
        "displayName",
        "userPrincipalName",
        "assignedLicenses",
        "assignedPlans",
        "department",
        "jobTitle",
        "country",
        "companyName",
        "accountEnabled",
        "createdDateTime",
        "signInActivity"
    ) -join ","

    $top = 800

    # Filter to users with at least one assigned license (server-side, via Graph advanced query)
    $url = "https://graph.microsoft.com/beta/users?`$select=$selectFields&`$filter=assignedLicenses/`$count ne 0&`$count=true&`$top=$top"

    $allUsers = @()

    do 
    {
        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

            $allUsers += $response.value

            if ($VerboseOutput) {
                Write-Host "Fetched $($allUsers.Count) licensed users so far..." -ForegroundColor Cyan
            }

            if ($LogFilePath) {
                Add-Content -Path $LogFilePath -Value "[$(Get-Date -Format 'u')] Retrieved $($response.value.Count) users from: $url"
            }

            $url = if ($response.PSObject.Properties['@odata.nextLink']) { $response.'@odata.nextLink' } else { $null }
        }
        catch {
            $statusCode = if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
                              $_.Exception.Response.StatusCode.Value__
                          } else { $null }

            if ($_.Exception.Response.StatusCode.Value__ -eq 429) {
                $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                Write-Warning "Throttled. Retrying after $retryAfter seconds."
                Start-Sleep -Seconds ([int]$retryAfter)
            }
            else {
                Write-Error "Failed to retrieve users: $_"
                break
            }
        }
    } while ($url)

    # Step 2: Transform users and map license GUIDs to friendly names
    $result = foreach ($user in $allUsers) {

        # Map assignedLicenses skuId to skuPartNumber from licenseInventory
        $licenseNames = @()
        foreach ($license in $user.assignedLicenses) {
            $match = $licenseInventory | Where-Object { $_.skuId -eq $license.skuId }
            if ($match) {
                $licenseNames += $match.skuPartNumber
            } else {
                $licenseNames += $license.skuId  # fallback to GUID if no match
            }
        }
        $licenseDisplayNames = $licenseNames -join ", "

        # Map disabled plans to friendly names if possible
        $disabledPlanNames = $user.assignedPlans | Where-Object { $_.capabilityStatus -ne "Enabled" } | ForEach-Object {
            $currentPlanId = $_.servicePlanId
            $foundPlanName = $null

            foreach ($license in $licenseInventory) {
                $foundPlan = $license.servicePlans | Where-Object { $_.servicePlanId -eq $currentPlanId }
                if ($foundPlan) {
                    $foundPlanName = $foundPlan.servicePlanName
                    break
                }
            }

            if ($foundPlanName) {
                $foundPlanName
            } else {
                $currentPlanId
            }
        }

        $disabledPlanNamesString = $disabledPlanNames -join ", "

        # Guard the signInActivity object existence
        $signInActivity = if ($user.PSObject.Properties['signInActivity']) { $user.signInActivity } else { $null }

        # Guard each nested property individually - they can be absent even when signInActivity exists
        $lastSignIn           = if ($signInActivity -and $signInActivity.PSObject.Properties['lastSignInDateTime'])           { $signInActivity.lastSignInDateTime }           else { $null }
        $lastSuccessfulSignIn = if ($signInActivity -and $signInActivity.PSObject.Properties['lastSuccessfulSignInDateTime']) { $signInActivity.lastSuccessfulSignInDateTime } else { $null }

        # Compute days since last sign-in safely
        $daysSinceLastSignIn = if ($lastSuccessfulSignIn) {
            (New-TimeSpan -Start $lastSuccessfulSignIn -End (Get-Date)).Days
        } else {
            "Never"
        }

        # Compute inactive status safely
        $inactiveUserStatus = if (-not $lastSuccessfulSignIn) {
            $true
        } elseif ((New-TimeSpan -Start $lastSuccessfulSignIn -End (Get-Date)).Days -gt 90) {
            $true
        } else {
            $false
        }

        [PSCustomObject]@{
            DisplayName           = $user.displayName
            UPN                   = $user.userPrincipalName
            Country               = $user.country
            Department            = $user.department
            JobTitle              = $user.jobTitle
            Company               = $user.companyName
            DirectLicenses        = $licenseDisplayNames
            DisabledPlans         = $disabledPlanNamesString
            GroupBasedLicenses    = $null  # Reserved: requires licenseAssignmentStates to populate
            LastLicenseChange     = $null  # Not available directly from Graph
            AccountStatus         = if ($user.accountEnabled) { "Enabled" } else { "Disabled" }
            AccountCreated        = $user.createdDateTime
            LastSignInAttempt     = $lastSignIn
            LastSuccessfulSignIn  = $lastSuccessfulSignIn
            DaysSinceLastSignIn   = $daysSinceLastSignIn
            InactiveUserStatus    = $inactiveUserStatus
        }
    }

    # CSV EXPORT SUPPORT
    if($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $result | Export-Csv -Path $ExportPath -NoTypeInformation -Force

        Write-Host ""
        Write-Host "Licensed users report exported successfully → $ExportPath" -ForegroundColor Green
    }

    return $result
}
