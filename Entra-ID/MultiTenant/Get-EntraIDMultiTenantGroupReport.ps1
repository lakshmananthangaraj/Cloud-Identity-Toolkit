<#

.AUTHOR
    Author       : Lakshmanan Thangaraj
    Version      : 1.0
    Created-On   : 12 September 2026
    Modified-On  : 12 September 2026

.SYNOPSIS
    Generates a consolidated group report across one or more Microsoft Entra ID tenants,
    with CSV export options and an interactive HTML dashboard.

.DESCRIPTION
    Microsoft Entra ID groups are the backbone of access control — they determine who can
    reach which resources, who receives which licences, and how policies are applied.
    Large organisations often manage groups across MULTIPLE tenants (one per region or
    subsidiary), making it difficult to see the full picture in one place.

    This script connects to every tenant you specify, collects every group's details,
    enriches each group with its members and owners (in parallel), and produces your
    choice of output:

      CSV Reports (menu options 1–5):
        [1]  Full Groups Inventory        — every group, all details
        [2]  Orphan Groups               — no members AND no owners
        [3]  Empty Member Groups         — no members of any type
        [4]  Empty Owner Groups          — no owners assigned
        [5]  Office 365 Licensed Groups  — groups with assigned M365 licences

      HTML Dashboard (menu option 6):
        [6]  Interactive HTML Dashboard  — all groups in a searchable, filterable,
             dark/light-theme dashboard with stat cards, charts, and detail drawer

    ─────────────────────────────────────────────────────────────────────────────
    HOW DOES IT WORK? (Step by Step)
    ─────────────────────────────────────────────────────────────────────────────

    Step 1  →  Authenticates to each tenant using OAuth 2.0 Client Credentials Flow
                (app-only, no interactive login prompts).

    Step 2  →  Fetches ALL groups from each tenant with pagination, so tenants with
                50,000+ groups are handled correctly.

    Step 3  →  For every group, collects members and owners in PARALLEL (controlled
                by -ThrottleLimit) — the biggest time-saver versus the original
                serial approach.

    Step 4  →  Classifies each group by type: Microsoft 365, Security, Mail-enabled
                Security, Distribution, or Dynamic.

    Step 5  →  Merges data from all tenants and exports to your chosen format.

    ─────────────────────────────────────────────────────────────────────────────
    AUTHENTICATION MODEL
    ─────────────────────────────────────────────────────────────────────────────

    OAuth 2.0 Client Credentials Flow — authenticates as an APPLICATION, not a user.

      ✔  No interactive login prompts
      ✔  Works unattended in scheduled tasks or Azure Automation
      ✔  Client secret accepted as a SecureString — never stored as plain text

.PARAMETER ClientId
    The Application (Client) ID of the Azure App Registration.

    Where to find it:
    Azure Portal → Azure Active Directory → App Registrations → Your App → Overview

.PARAMETER ClientSecret
    The client secret of the Azure App Registration, provided as a SecureString.

    How to create one at runtime:
        $secret = Read-Host -Prompt "Enter Client Secret" -AsSecureString

.PARAMETER TenantIds
    An array of one or more Tenant IDs (GUIDs) to report against.

    Examples:
        Single tenant  : @("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
        Multi-tenant   : @("tenant1-guid", "tenant2-guid", "tenant3-guid")

.PARAMETER TokenRefreshIntervalMinutes
    Minutes before token expiry at which the token is proactively renewed.
    Default is 5 minutes.

.PARAMETER ExportPath
    Base folder path for all CSV and HTML output files.
    Defaults to: C:\Temp

    CSV files are written as:
        <ExportPath>\EntraID-Groups-Inventory.csv
        <ExportPath>\EntraID-Groups-Orphan.csv
        <ExportPath>\EntraID-Groups-EmptyMembers.csv
        <ExportPath>\EntraID-Groups-EmptyOwners.csv
        <ExportPath>\EntraID-Groups-Licensed.csv

    HTML dashboard is written as:
        <ExportPath>\EntraID-Groups-Dashboard.html

.PARAMETER ThrottleLimit
    Maximum number of groups whose members/owners are fetched simultaneously
    per tenant. Default is 10. Range: 1–20.

    Start at 5 for large tenants and increase once you confirm no HTTP 429 bursts.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Collections.ArrayList
    Returns all group records as an in-memory object array.
    Also exports data to CSV and/or HTML at the specified ExportPath.

.EXAMPLE
    ── Example 1: Single tenant, interactive secret prompt ──────────────────────

    $secret = Read-Host -Prompt "Enter Client Secret" -AsSecureString

    Get-EntraIDMultiTenantGroupReport `
        -ClientId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret $secret `
        -TenantIds   @("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    Launches the interactive menu for one tenant.

.EXAMPLE
    ── Example 2: Multiple tenants, custom export path ──────────────────────────

    $secret = Read-Host -Prompt "Enter Client Secret" -AsSecureString

    Get-EntraIDMultiTenantGroupReport `
        -ClientId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret $secret `
        -TenantIds   @(
                         "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                         "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
                     ) `
        -ExportPath  "D:\Reports"

    Connects to two tenants and saves all output to D:\Reports.

.EXAMPLE
    ── Example 3: Higher parallelism for faster runs ────────────────────────────

    $secret = Read-Host -Prompt "Enter Client Secret" -AsSecureString

    Get-EntraIDMultiTenantGroupReport `
        -ClientId      "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret  $secret `
        -TenantIds     @("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") `
        -ThrottleLimit 15

    Processes 15 groups in parallel — suitable for tenants with fewer than 10,000 groups.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (12-Sep-2026) - Initial release. Refactored from legacy script with full
                        standards compliance, SecureString auth, parallel member/
                        owner enrichment, menu-driven output selection, and
                        interactive HTML dashboard generation.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────

    ════════════════════════════════════════════════════════════════
    STEP 1 — Register an Application in Your PRIMARY Tenant
    ════════════════════════════════════════════════════════════════

    1.1  Sign in to https://portal.azure.com with a Global Administrator account.

    1.2  Go to:
         Azure Active Directory → App Registrations → New Registration

    1.3  Fill in the registration form:
           Name                   : EntraIDGroupReportApp
           Supported account types: Accounts in any organizational directory (Multitenant)
           Redirect URI           : Leave blank

    1.4  Note the "Application (client) ID" — this is your -ClientId value.

    1.5  Create a Client Secret:
         → Certificates & Secrets → New Client Secret → Add
         → Copy the VALUE immediately

    1.6  Grant API Permissions (Application permissions, not Delegated):
         ┌──────────────────────────────┬──────────────────────────────────────────────┐
         │ Permission                   │ Why it is needed                             │
         ├──────────────────────────────┼──────────────────────────────────────────────┤
         │ Group.Read.All               │ Read all group profiles                      │
         │ GroupMember.Read.All         │ Read group memberships                       │
         │ Directory.Read.All           │ Read tenant and organisational data          │
         │ Organization.Read.All        │ Read tenant name, domain, country            │
         └──────────────────────────────┴──────────────────────────────────────────────┘

         → Click "Grant admin consent for [Your Organisation]"

    ════════════════════════════════════════════════════════════════
    STEP 2 — Register the App in Each ADDITIONAL Tenant
    ════════════════════════════════════════════════════════════════

    2.1  Connect to the additional tenant:
         Connect-MgGraph -Scopes "Application.ReadWrite.All" -TenantId "additional-tenant-id"

    2.2  Create the Service Principal:
         New-MgServicePrincipal -AppId "YOUR_APP_CLIENT_ID_FROM_STEP_1"

    2.3  Grant the same API permissions in the additional tenant via Azure Portal or:
         https://learn.microsoft.com/en-us/graph/permissions-grant-via-msgraph

    ════════════════════════════════════════════════════════════════
    STEP 3 — No PowerShell Modules Required
    ════════════════════════════════════════════════════════════════

    Direct REST calls to Microsoft Graph API only.
    PowerShell 7.0 or later is required for -Parallel support.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Member and owner lookups use transitiveMembers — nested group members are
      included. This is intentional for accurate reporting but increases call volume.

    - Microsoft Graph may throttle (HTTP 429) for large tenants. The script honours
      the Retry-After header automatically.

    - Dynamic group membership rules are reported but not evaluated — actual members
      are still fetched via the API.

    - The HTML dashboard is self-contained (no external JS dependencies at runtime)
      but requires an internet connection at open time for the Google Fonts import.
      Remove the font link for fully offline use.

    - ThrottleLimit applies per tenant. With 3 tenants and ThrottleLimit=10, up to
      10 parallel Graph calls per tenant are made (not 30 total).

.LINK
    https://learn.microsoft.com/en-us/graph/api/group-list
    https://learn.microsoft.com/en-us/graph/api/group-list-transitivemembers
    https://learn.microsoft.com/en-us/graph/api/group-list-owners
    https://learn.microsoft.com/en-us/graph/api/organization-get
    https://learn.microsoft.com/en-us/graph/permissions-grant-via-msgraph
    https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow

#>


Function Get-EntraIDMultiTenantGroupReport {
    [CmdletBinding()]
    param
    (
        # ── Mandatory Parameters ──────────────────────────────────────────────────

        [Parameter(Mandatory = $true, HelpMessage = "Application (Client) ID of the Azure App Registration.")]
        [ValidateNotNullOrEmpty()]
        [string] $ClientId,

        [Parameter(Mandatory = $true, HelpMessage = "Client secret as a SecureString. Use: Read-Host -AsSecureString")]
        [ValidateNotNull()]
        [System.Security.SecureString] $ClientSecret,

        [Parameter(Mandatory = $true, HelpMessage = "One or more Tenant IDs (GUIDs) to report against.")]
        [ValidateNotNullOrEmpty()]
        [string[]] $TenantIds,

        # ── Optional Parameters ───────────────────────────────────────────────────

        [Parameter(Mandatory = $false, HelpMessage = "Minutes before token expiry at which the token is proactively renewed.")]
        [ValidateRange(1, 30)]
        [int] $TokenRefreshIntervalMinutes = 5,

        [Parameter(Mandatory = $false, HelpMessage = "Base folder path for all CSV and HTML output files.")]
        [ValidateNotNullOrEmpty()]
        [string] $ExportPath = "C:\Temp",

        [Parameter(Mandatory = $false, HelpMessage = "Maximum number of groups to enrich in parallel per tenant. Default is 10.")]
        [ValidateRange(1, 20)]
        [int] $ThrottleLimit = 10
    )


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Token helpers (Client Credentials Flow)
    #─────────────────────────────────────────────────────────────────────────────

    Function Invoke-EntraIDTokenRequest {
        $tokenEndpoint = "https://login.microsoftonline.com/$($global:_grpctx.TenantId)/oauth2/v2.0/token"

        Try {
            $body = @{
                client_id     = $global:_grpctx.ClientId
                client_secret = $global:_grpctx.ClientSecret
                scope         = "https://graph.microsoft.com/.default"
                grant_type    = "client_credentials"
            }

            $response = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ErrorAction Stop
            $global:_grpctx.AccessToken = $response.access_token
            $global:_grpctx.TokenExpiry = (Get-Date).AddSeconds($response.expires_in)

            Write-Verbose "Access token acquired. Expires at: $($global:_grpctx.TokenExpiry.ToString('HH:mm:ss'))"
        }
        Finally {
            $body = $null
        }
    }


    Function Test-EntraIDTokenRenewalRequired {
        if (-not $global:_grpctx.AccessToken -or -not $global:_grpctx.TokenExpiry) {
            return $true
        }

        $minutesRemaining = ($global:_grpctx.TokenExpiry - (Get-Date)).TotalMinutes
        return ($minutesRemaining -lt $global:_grpctx.RefreshIntervalMinutes)
    }


    Function Invoke-EntraIDTokenRefreshIfNeeded {
        if (Test-EntraIDTokenRenewalRequired) {
            Write-Host "  🔄  Access token approaching expiry — renewing..." -ForegroundColor Yellow
            Invoke-EntraIDTokenRequest
            Write-Host "  ✅  Token renewed — continuing." -ForegroundColor Green
        }
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Tenant Authentication
    #─────────────────────────────────────────────────────────────────────────────

    Function Connect-EntraIDTenant {
        param
        (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $TenantId
        )

        Try {
            $global:_grpctx.TenantId = $TenantId
            $global:_grpctx.AccessToken = $null
            $global:_grpctx.TokenExpiry = $null

            Invoke-EntraIDTokenRequest

            Write-Verbose "Connected to tenant: $TenantId"
            return $global:_grpctx.AccessToken
        }
        Catch {
            Write-Error "Failed to authenticate to tenant '$TenantId'. Details: $_"
            return $null
        }
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Graph API Wrapper — throttle-aware
    #─────────────────────────────────────────────────────────────────────────────

    Function Invoke-GraphRequest {
        param
        (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $Uri,

            [hashtable] $AdditionalHeaders = @{}
        )

        $headers = @{ "Authorization" = "Bearer $($global:_grpctx.AccessToken)" } + $AdditionalHeaders
        $maxRetries = 5
        $retryCount = 0

        do {
            $retryCount++
            Try {
                $response = Invoke-WebRequest -Uri $Uri -Headers $headers -Method Get -ErrorAction Stop
                return ($response.Content | ConvertFrom-Json)
            }
            Catch {
                $statusCode = $_.Exception.Response.StatusCode

                if ($statusCode -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers.Item("Retry-After")
                    if (-not $retryAfter) { $retryAfter = 10 }
                    Write-Warning "Graph API throttled (HTTP 429). Waiting $retryAfter seconds before retry $retryCount of $maxRetries..."
                    Start-Sleep -Seconds $retryAfter
                }
                elseif ($statusCode -eq 404) {
                    return $null
                }
                else {
                    Write-Warning "Graph API request failed. URI: $Uri | StatusCode: $statusCode | Error: $($_.Exception.Message)"
                    return $null
                }
            }
        }
        while ($retryCount -lt $maxRetries)

        return $null
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Data Retrieval Functions
    #─────────────────────────────────────────────────────────────────────────────

    Function Get-EntraIDAllGroups {
        $allGroups = New-Object System.Collections.ArrayList
        $totalCount = 0

        $uri = "https://graph.microsoft.com/beta/groups" +
        "?`$top=999" +
        "&`$select=id,displayName,createdDateTime,groupTypes,isAssignableToRole," +
        "onPremisesSyncEnabled,securityEnabled,mail,mailEnabled,membershipRule,assignedLicenses" +
        "&`$count=true"

        do {
            Invoke-EntraIDTokenRefreshIfNeeded

            $data = Invoke-GraphRequest -Uri $uri -AdditionalHeaders @{ "ConsistencyLevel" = "eventual" }

            if (-not $data) {
                Write-Warning "No data returned from groups endpoint. Stopping pagination."
                break
            }

            foreach ($group in $data.value) {
                $null = $allGroups.Add(
                    [PSCustomObject]@{
                        Id                    = $group.id
                        DisplayName           = $group.displayName
                        CreatedDateTime       = $group.createdDateTime
                        GroupTypes            = ($group.groupTypes -join ",")
                        IsAssignableToRole    = $group.isAssignableToRole
                        OnPremisesSyncEnabled = $group.onPremisesSyncEnabled
                        SecurityEnabled       = $group.securityEnabled
                        Mail                  = $group.mail
                        MailEnabled           = $group.mailEnabled
                        MembershipRule        = $group.membershipRule
                        AssignedLicenses      = $group.assignedLicenses
                    }
                )
            }

            $totalCount += $data.value.Count
            Write-Verbose "Groups retrieved so far: $totalCount"

            $uri = if ($data.PSObject.Properties['@odata.nextLink']) { $data.'@odata.nextLink' } else { $null }
        }
        while ($uri)

        return $allGroups
    }


    Function Get-EntraIDTenantDetails {
        $uri = "https://graph.microsoft.com/beta/organization"
        $data = Invoke-GraphRequest -Uri $uri

        if (-not $data -or -not $data.value) {
            Write-Warning "Could not retrieve tenant details."
            return $null
        }

        $tenant = $data.value
        $primaryDomain = ($tenant.verifiedDomains | Where-Object { $_.isDefault -eq $true }).name

        return [PSCustomObject]@{
            TenantId            = $tenant.id
            TenantName          = $tenant.displayName
            TenantPrimaryDomain = $primaryDomain
            TenantType          = $tenant.tenantType
            Country             = $tenant.country
            CountryCode         = $tenant.countryLetterCode
            CreatedDate         = $tenant.createdDateTime
            TechnicalContact    = ($tenant.technicalNotificationMails -join " ; ")
            VerifiedDomainNames = ($tenant.verifiedDomains.name -join " ; ")
            VerifiedDomainTypes = ($tenant.verifiedDomains.type -join " ; ")
        }
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Group Type Classification
    #─────────────────────────────────────────────────────────────────────────────

    Function Resolve-GroupType {
        param
        (
            [Parameter(Mandatory = $true)]
            [PSCustomObject] $Group
        )

        $types = $Group.GroupTypes

        if ($types -eq "Unified" -and $Group.SecurityEnabled) { return "Microsoft 365 (Security-enabled)" }
        if ($types -eq "Unified" -and -not $Group.SecurityEnabled) { return "Microsoft 365" }
        if ($types -ne "Unified" -and $Group.SecurityEnabled -and $Group.MailEnabled) { return "Mail-enabled Security" }
        if ($types -ne "Unified" -and $Group.SecurityEnabled) { return "Entra ID Security" }
        if ($types -ne "Unified" -and $Group.MailEnabled) { return "Distribution" }
        return "Unknown"
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Parallel Group Enrichment (members + owners)
    #─────────────────────────────────────────────────────────────────────────────

    Function Invoke-GroupEnrichmentParallel {
        param
        (
            [Parameter(Mandatory = $true)]
            [System.Collections.ArrayList] $Groups,

            [Parameter(Mandatory = $true)]
            [string] $AccessTokenSnapshot,

            [Parameter(Mandatory = $true)]
            [PSCustomObject] $TenantSnapshot,

            [Parameter(Mandatory = $true)]
            [int] $ThrottleLimit
        )

        $bag = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

        $Groups | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {

            $group = $_
            $accessToken = $using:AccessTokenSnapshot
            $tenantLocal = $using:TenantSnapshot
            $bag = $using:bag

            $headers = @{ "Authorization" = "Bearer $accessToken" }

            # ── Resolve group type ────────────────────────────────────────────
            $types = $group.GroupTypes
            $groupType = if ($types -eq "Unified" -and $group.SecurityEnabled -eq $true) { "Microsoft 365 (Security-enabled)" }
            elseif ($types -eq "Unified" -and $group.SecurityEnabled -ne $true) { "Microsoft 365" }
            elseif ($types -ne "Unified" -and $group.SecurityEnabled -eq $true -and $group.MailEnabled -eq $true) { "Mail-enabled Security" }
            elseif ($types -ne "Unified" -and $group.SecurityEnabled -eq $true) { "Entra ID Security" }
            elseif ($types -ne "Unified" -and $group.MailEnabled -eq $true) { "Distribution" }
            else { "Unknown" }

            # ── Members (transitive) ──────────────────────────────────────────
            $userMembers = [System.Collections.Generic.List[string]]::new()
            $appMembers = [System.Collections.Generic.List[string]]::new()
            $groupMembers = [System.Collections.Generic.List[string]]::new()
            $deviceMembers = [System.Collections.Generic.List[string]]::new()
            $userMembersCount = 0; $groupMembersCount = 0
            $deviceMembersCount = 0; $spMembersCount = 0

            Try {
                $membersUri = "https://graph.microsoft.com/beta/groups/$($group.Id)/transitiveMembers"
                do {
                    $mData = Invoke-RestMethod -Uri $membersUri -Headers $headers -Method Get -ErrorAction Stop
                    foreach ($m in $mData.value) {
                        switch ($m.'@odata.type') {
                            "#microsoft.graph.user" { $userMembers.Add($m.userPrincipalName); $userMembersCount++ }
                            "#microsoft.graph.group" { $groupMembers.Add($m.displayName); $groupMembersCount++ }
                            "#microsoft.graph.device" { $deviceMembers.Add($m.displayName); $deviceMembersCount++ }
                            "#microsoft.graph.servicePrincipal" { $appMembers.Add($m.appDisplayName); $spMembersCount++ }
                        }
                    }
                    $membersUri = if ($mData.PSObject.Properties['@odata.nextLink']) { $mData.'@odata.nextLink' } else { $null }
                }
                while ($membersUri)
            }
            Catch { <# silently continue — member fetch failure is non-fatal #> }

            # ── Owners ────────────────────────────────────────────────────────
            $ownerUpns = [System.Collections.Generic.List[string]]::new()
            $ownerApps = [System.Collections.Generic.List[string]]::new()
            $ownersCount = 0

            Try {
                $ownersData = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/groups/$($group.Id)/owners" `
                    -Headers $headers -Method Get -ErrorAction Stop
                foreach ($o in $ownersData.value) {
                    switch ($o.'@odata.type') {
                        "#microsoft.graph.user" { $ownerUpns.Add($o.userPrincipalName); $ownersCount++ }
                        "#microsoft.graph.servicePrincipal" { $ownerApps.Add($o.appDisplayName); $ownersCount++ }
                    }
                }
            }
            Catch { <# silently continue #> }

            # ── Build record ──────────────────────────────────────────────────
            $record = [PSCustomObject]@{
                'Group ID'                        = $group.Id
                'Display Name'                    = $group.DisplayName
                'Created Date'                    = $group.CreatedDateTime
                'Group Type'                      = $groupType
                'Membership Type'                 = if ($group.MembershipRule) { 'Dynamic' } else { 'Assigned' }
                'Membership Rule'                 = $group.MembershipRule
                'Is Assignable To Role'           = if ($group.IsAssignableToRole) { 'True' } else { 'False' }
                'Is Synced From On-Premises'      = if ($group.OnPremisesSyncEnabled) { 'True' } else { 'False' }
                'Security Enabled'                = $group.SecurityEnabled
                'Mail Enabled'                    = $group.MailEnabled
                'Mail'                            = if ($group.Mail) { $group.Mail } else { '-' }
                'Is Licence Assigned'             = if ($group.AssignedLicenses -and $group.AssignedLicenses.Count -gt 0) { 'Yes' } else { 'No' }
                'Assigned Licence SKU IDs'        = if ($group.AssignedLicenses -and $group.AssignedLicenses.Count -gt 0) { ($group.AssignedLicenses.skuId -join ' ; ') } else { '-' }
                'User Members Count'              = $userMembersCount
                'Group Members Count'             = $groupMembersCount
                'Device Members Count'            = $deviceMembersCount
                'Service Principal Members Count' = $spMembersCount
                'Total Members Count'             = $userMembersCount + $groupMembersCount + $deviceMembersCount + $spMembersCount
                'Owners Count'                    = $ownersCount
                'User Members'                    = ($userMembers -join ' ; ')
                'App Members'                     = ($appMembers -join ' ; ')
                'Group Members'                   = ($groupMembers -join ' ; ')
                'Device Members'                  = ($deviceMembers -join ' ; ')
                'Owner UPNs'                      = ($ownerUpns -join ' ; ')
                'Owner App Names'                 = ($ownerApps -join ' ; ')
                'Tenant ID'                       = if ($tenantLocal) { $tenantLocal.TenantId }            else { $null }
                'Tenant Name'                     = if ($tenantLocal) { $tenantLocal.TenantName }          else { $null }
                'Tenant Primary Domain'           = if ($tenantLocal) { $tenantLocal.TenantPrimaryDomain } else { $null }
                'Tenant Country'                  = if ($tenantLocal) { $tenantLocal.Country }             else { $null }
            }

            $null = $bag.Add($record)
        }

        return $bag
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: HTML Dashboard Generator
    #─────────────────────────────────────────────────────────────────────────────

    Function Export-GroupsDashboard {
        param
        (
            [Parameter(Mandatory = $true)]
            [System.Collections.ArrayList] $AllRecords,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $OutputPath,

            [Parameter(Mandatory = $true)]
            [string[]] $TenantIds
        )

        # ── Compute summary stats ─────────────────────────────────────────────
        $totalGroups = $AllRecords.Count
        $m365Groups = ($AllRecords | Where-Object { $_.'Group Type' -like 'Microsoft 365*' }).Count
        $securityGroups = ($AllRecords | Where-Object { $_.'Group Type' -eq 'Entra ID Security' }).Count
        $mailSecGroups = ($AllRecords | Where-Object { $_.'Group Type' -eq 'Mail-enabled Security' }).Count
        $distGroups = ($AllRecords | Where-Object { $_.'Group Type' -eq 'Distribution' }).Count
        $dynamicGroups = ($AllRecords | Where-Object { $_.'Membership Type' -eq 'Dynamic' }).Count
        $orphanGroups = ($AllRecords | Where-Object { $_.'Total Members Count' -eq 0 -and $_.'Owners Count' -eq 0 }).Count
        $emptyMemberGroups = ($AllRecords | Where-Object { $_.'Total Members Count' -eq 0 }).Count
        $emptyOwnerGroups = ($AllRecords | Where-Object { $_.'Owners Count' -eq 0 }).Count
        $licensedGroups = ($AllRecords | Where-Object { $_.'Is Licence Assigned' -eq 'Yes' }).Count
        $syncedGroups = ($AllRecords | Where-Object { $_.'Is Synced From On-Premises' -eq 'True' }).Count
        $cloudOnlyGroups = $totalGroups - $syncedGroups
        $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')

        # ── JsonSafe helper (inline — no nested function needed here) ─────────
        $js = {
            param ([string]$s)
            $s = $s -replace '\\', '\\' -replace '"', '\"' -replace "`r`n", '\n' -replace "`n", '\n' -replace "`t", '\t' -replace '<', '\u003c' -replace '>', '\u003e' -replace '\$', '\u0024'
            return $s
        }

        # ── Build groups JSON array ───────────────────────────────────────────
        $groupsJson = ($AllRecords | ForEach-Object {
                $id = & $js $_.'Group ID'
                $name = & $js $_.'Display Name'
                $gtype = & $js $_.'Group Type'
                $mtype = & $js $_.'Membership Type'
                $mail = & $js $_.'Mail'
                $tenant = & $js $_.'Tenant Name'
                $domain = & $js $_.'Tenant Primary Domain'
                $created = & $js $_.'Created Date'
                $ownerUpns = & $js $_.'Owner UPNs'
                $userMem = & $js $_.'User Members'
                $licSku = & $js $_.'Assigned Licence SKU IDs'

                "{`"id`":`"$id`",`"name`":`"$name`",`"gtype`":`"$gtype`",`"mtype`":`"$mtype`"," +
                "`"mail`":`"$mail`",`"tenant`":`"$tenant`",`"domain`":`"$domain`",`"created`":`"$created`"," +
                "`"userCount`":$($_.'User Members Count'),`"groupCount`":$($_.'Group Members Count')," +
                "`"deviceCount`":$($_.'Device Members Count'),`"spCount`":$($_.'Service Principal Members Count')," +
                "`"totalMembers`":$($_.'Total Members Count'),`"ownersCount`":$($_.'Owners Count')," +
                "`"licensed`":$(if($_.'Is Licence Assigned' -eq 'Yes'){'true'}else{'false'})," +
                "`"synced`":$(if($_.'Is Synced From On-Premises' -eq 'True'){'true'}else{'false'})," +
                "`"assignableToRole`":$(if($_.'Is Assignable To Role' -eq 'True'){'true'}else{'false'})," +
                "`"secEnabled`":$(if($_.'Security Enabled'){'true'}else{'false'})," +
                "`"mailEnabled`":$(if($_.'Mail Enabled'){'true'}else{'false'})," +
                "`"ownerUpns`":`"$ownerUpns`",`"userMembers`":`"$userMem`",`"licSku`":`"$licSku`"}"
            }) -join ','

        # ── Build type distribution JSON ──────────────────────────────────────
        $typeGroups = $AllRecords | Group-Object 'Group Type' | Sort-Object Count -Descending
        $typeJson = ($typeGroups | ForEach-Object {
                "{`"type`":`"$(& $js $_.Name)`",`"count`":$($_.Count)}"
            }) -join ','

        # ── Build per-tenant JSON ─────────────────────────────────────────────
        $tenantGroups = $AllRecords | Group-Object 'Tenant Name' | Sort-Object Count -Descending
        $tenantJson = ($tenantGroups | ForEach-Object {
                "{`"name`":`"$(& $js $_.Name)`",`"count`":$($_.Count)}"
            }) -join ','

        # ── HTML here-string ──────────────────────────────────────────────────
        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Entra ID Group Report Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root {
  --bg:#0d1117; --surface:#161b22; --surface2:#1c2333; --surface3:#243048;
  --border:#30363d; --accent:#388bfd; --accent2:#39c5cf; --accent3:#a371f7;
  --green:#3fb950; --amber:#d29922; --red:#f85149;
  --text:#e6edf3; --muted:#7d8590; --muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px; --radius-sm:6px; --shadow:0 4px 24px rgba(0,0,0,.5);
}
body.light-theme {
  --bg:#f6f8fa; --surface:#fff; --surface2:#f0f3f6; --surface3:#e4e9ef;
  --border:#d0d7de; --accent:#0969da; --accent2:#0284a8; --accent3:#7c3aed;
  --green:#1a7f37; --amber:#b08000; --red:#cf222e;
  --text:#1f2328; --muted:#636c76; --muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}
/* Sidebar */
#sidebar{position:fixed;left:0;top:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;overflow-y:auto}
.sidebar-logo{padding:20px 16px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:8px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text);line-height:1.3}
.sidebar-logo p{font-size:11px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.version-badge{display:inline-block;background:var(--surface3);border:1px solid var(--border);border-radius:20px;padding:1px 8px;font-size:10px;color:var(--accent2);margin-top:5px;font-family:var(--mono)}
.sidebar-nav{flex:1;padding:10px 8px}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding:8px 8px 4px}
.nav-btn{display:flex;align-items:center;gap:9px;width:100%;padding:8px 10px;border:none;background:transparent;color:var(--muted2);border-radius:var(--radius-sm);cursor:pointer;font-size:13px;font-family:var(--sans);text-align:left;transition:all .15s;position:relative}
.nav-btn:hover{background:var(--surface2);color:var(--text)}
.nav-btn.active{background:rgba(56,139,253,.12);color:var(--accent)}
.nav-btn.active::before{content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;background:var(--accent);border-radius:0 3px 3px 0}
.nav-icon{font-size:14px;width:18px;text-align:center;flex-shrink:0}
.nav-badge{margin-left:auto;background:var(--surface3);border-radius:20px;padding:1px 7px;font-size:10px;font-family:var(--mono);color:var(--accent2)}
.theme-toggle-wrap{padding:10px 8px;border-top:1px solid var(--border)}
.theme-toggle{display:flex;align-items:center;gap:9px;width:100%;padding:8px 10px;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);border-radius:var(--radius-sm);cursor:pointer;font-size:12px;font-family:var(--sans);transition:all .15s}
.theme-toggle:hover{border-color:var(--accent);color:var(--text)}
.toggle-pill{width:28px;height:16px;background:var(--surface3);border-radius:8px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;width:12px;height:12px;background:var(--muted);border-radius:50%;top:2px;left:2px;transition:all .2s}
body.light-theme .toggle-pill{background:var(--accent)}
body.light-theme .toggle-pill::after{transform:translateX(12px);background:#fff}
.sidebar-footer{padding:12px 14px;border-top:1px solid var(--border);font-size:10.5px;color:var(--muted);line-height:1.6}
kbd{background:var(--surface3);border:1px solid var(--border);border-radius:3px;padding:1px 5px;font-size:10px;font-family:var(--mono)}
/* Main */
#main{margin-left:236px}
.page{display:none;padding:24px 28px;animation:fadeIn .2s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.page-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px;gap:12px;flex-wrap:wrap}
.page-title{font-size:20px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:2px}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
.btn{background:var(--surface2);border:1px solid var(--border);color:var(--muted2);border-radius:var(--radius-sm);padding:7px 14px;font-size:13px;font-family:var(--sans);cursor:pointer;transition:all .2s}
.btn:hover{border-color:var(--accent);color:var(--accent)}
/* Stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:14px;margin-bottom:22px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;border-top-width:3px;transition:transform .2s,box-shadow .2s}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.c-blue{border-top-color:#3b82f6}.c-cyan{border-top-color:#06b6d4}.c-purple{border-top-color:#8b5cf6}
.c-green{border-top-color:#10b981}.c-amber{border-top-color:#f59e0b}.c-red{border-top-color:#ef4444}
.c-pink{border-top-color:#ec4899}.c-lime{border-top-color:#84cc16}
.stat-icon{font-size:20px;margin-bottom:6px}
.stat-value{font-size:26px;font-weight:700;font-family:var(--mono);line-height:1}
.stat-label{font-size:12px;color:var(--muted);margin-top:4px}
/* Panels */
.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px;cursor:pointer}
.bar-row:hover .bar-label{color:var(--text)}
.bar-label{font-family:var(--mono);font-size:11px;color:var(--muted2);width:140px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:34px;text-align:right;flex-shrink:0}
/* Table */
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;padding:8px 11px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--accent)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:13px;flex-shrink:0}
.page-size-wrap{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.page-size-wrap select{padding:5px 8px;font-size:12px}
.groups-table{width:100%;border-collapse:collapse}
.groups-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.groups-table thead th:hover{color:var(--text)}
.groups-table thead th.sort-active{color:var(--accent)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.groups-table tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.groups-table tbody tr:hover{background:var(--surface2)}
.groups-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13.5px}
.td-name{font-family:var(--mono);font-size:12.5px;color:var(--accent2);font-weight:600}
.type-badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600}
.td-meta{color:var(--muted);font-family:var(--mono);font-size:12px;white-space:nowrap}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}
/* Detail panel */
#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(680px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:24px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
#detailClose{margin-left:auto;background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--red);color:#fff}
#detailContent{flex:1;overflow-y:auto}
.detail-header{margin-bottom:16px}
.detail-name{font-family:var(--mono);font-size:16px;color:var(--accent2);font-weight:600;word-break:break-all}
.detail-mail{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:4px}
.detail-meta-row{display:flex;gap:9px;flex-wrap:wrap;margin:12px 0}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:12px;color:var(--muted2)}
.detail-section{margin-top:18px}
.detail-section-title{font-size:11.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:9px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.member-list{font-family:var(--mono);font-size:12px;color:var(--muted2);line-height:1.8;max-height:200px;overflow-y:auto;background:var(--bg);border-radius:var(--radius-sm);padding:8px 10px;border:1px solid var(--border)}
/* Toast */
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}
@media(max-width:768px){#sidebar{transform:translateX(-236px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">👥</div>
    <h1>Entra ID Group Report</h1>
    <p>Multi-Tenant Dashboard</p>
    <span class="version-badge">v1.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">📊</span> Overview
    </button>
    <button class="nav-btn" onclick="showPage('groups',this)">
      <span class="nav-icon">📋</span> All Groups
      <span class="nav-badge">__TOTALGROUPS__</span>
    </button>
    <button class="nav-btn" onclick="showPage('insights',this)">
      <span class="nav-icon">🔍</span> Insights
    </button>
  </div>
  <div class="theme-toggle-wrap">
    <button class="theme-toggle" onclick="toggleTheme()">
      <span id="themeIcon">🌙</span>
      <span id="themeLabel" style="flex:1;text-align:left">Dark Mode</span>
      <span class="toggle-pill"></span>
    </button>
  </div>
  <div class="sidebar-footer">
    Generated<br>__GENERATEDAT__<br>
    <span style="color:var(--accent2)">⌨</span> <kbd>/</kbd> search &nbsp; <kbd>Esc</kbd> close
  </div>
</nav>

<main id="main">

<!-- OVERVIEW -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Group Inventory Overview</div>
      <div class="page-subtitle">Consolidated view across __TENANTCOUNT__ tenant(s) — generated __GENERATEDAT__</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(false)">⬇ Export CSV</button>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue">  <div class="stat-icon">👥</div><div class="stat-value">__TOTALGROUPS__</div>  <div class="stat-label">Total Groups</div></div>
    <div class="stat-card c-cyan">  <div class="stat-icon">☁️</div> <div class="stat-value">__M365GROUPS__</div>   <div class="stat-label">Microsoft 365</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">🔒</div><div class="stat-value">__SECGROUPS__</div>    <div class="stat-label">Security Groups</div></div>
    <div class="stat-card c-amber"> <div class="stat-icon">📧</div><div class="stat-value">__DISTGROUPS__</div>   <div class="stat-label">Distribution</div></div>
    <div class="stat-card c-lime">  <div class="stat-icon">⚡</div><div class="stat-value">__DYNGROUPS__</div>    <div class="stat-label">Dynamic Groups</div></div>
    <div class="stat-card c-green"> <div class="stat-icon">🎫</div><div class="stat-value">__LICGROUPS__</div>    <div class="stat-label">Licensed Groups</div></div>
    <div class="stat-card c-red">   <div class="stat-icon">👻</div><div class="stat-value">__ORPHANGROUPS__</div> <div class="stat-label">Orphan Groups</div></div>
    <div class="stat-card c-pink">  <div class="stat-icon">🏢</div><div class="stat-value">__SYNCEDGROUPS__</div> <div class="stat-label">On-Prem Synced</div></div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Groups by Type</div>
      <div id="typesBars"></div>
    </div>
    <div class="panel">
      <div class="section-title">🏢 Groups by Tenant</div>
      <div id="tenantBars"></div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">⚠️ Groups Requiring Attention</div>
      <div class="bar-row" style="cursor:default">
        <span class="bar-label" style="width:180px">Orphan (no members or owners)</span>
        <div class="bar-track"><div class="bar-fill" style="background:#ef4444" id="barOrphan" data-pct="0"></div></div>
        <span class="bar-count" id="cntOrphan">__ORPHANGROUPS__</span>
      </div>
      <div class="bar-row" style="cursor:default">
        <span class="bar-label" style="width:180px">Empty members</span>
        <div class="bar-track"><div class="bar-fill" style="background:#f59e0b" id="barEmptyMem" data-pct="0"></div></div>
        <span class="bar-count" id="cntEmptyMem">__EMPTYMEMGROUPS__</span>
      </div>
      <div class="bar-row" style="cursor:default">
        <span class="bar-label" style="width:180px">No owners assigned</span>
        <div class="bar-track"><div class="bar-fill" style="background:#8b5cf6" id="barEmptyOwn" data-pct="0"></div></div>
        <span class="bar-count" id="cntEmptyOwn">__EMPTYOWNGROUPS__</span>
      </div>
    </div>
    <div class="panel">
      <div class="section-title">📈 Membership Statistics</div>
      <div id="memberStats"></div>
    </div>
  </div>
</section>

<!-- ALL GROUPS TABLE -->
<section id="page-groups" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">All Groups</div>
      <div class="page-subtitle">Browse, filter and inspect every group across all tenants</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(true)">⬇ Export Filtered CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="tableSearch" placeholder="Search name, type, tenant, mail… (press / to focus)" oninput="filterTable()"/>
    </div>
    <select id="typeFilter" onchange="filterTable()"><option value="">All Types</option></select>
    <select id="tenantFilter" onchange="filterTable()"><option value="">All Tenants</option></select>
    <select id="memberFilter" onchange="filterTable()">
      <option value="">All Groups</option>
      <option value="orphan">👻 Orphan</option>
      <option value="empty-members">📭 Empty Members</option>
      <option value="empty-owners">🚫 No Owners</option>
      <option value="licensed">🎫 Licensed</option>
      <option value="dynamic">⚡ Dynamic</option>
      <option value="synced">🔄 On-Prem Synced</option>
    </select>
    <select id="sortSelect" onchange="filterTable()">
      <option value="name-asc">Name A→Z</option>
      <option value="name-desc">Name Z→A</option>
      <option value="members-desc">Most Members</option>
      <option value="owners-desc">Most Owners</option>
    </select>
    <div class="page-size-wrap">
      Show <select id="pageSizeSelect" onchange="changePageSize()"><option>25</option><option>50</option><option>100</option></select>
    </div>
    <span class="result-count" id="resultCount"></span>
  </div>
  <table class="groups-table">
    <thead><tr>
      <th onclick="sortByCol('name')"    id="th-name">Display Name <span class="sort-arrow">↕</span></th>
      <th onclick="sortByCol('gtype')"   id="th-gtype">Type <span class="sort-arrow">↕</span></th>
      <th onclick="sortByCol('mtype')"   id="th-mtype">Membership <span class="sort-arrow">↕</span></th>
      <th onclick="sortByCol('members')" id="th-members">Members <span class="sort-arrow">↕</span></th>
      <th onclick="sortByCol('owners')"  id="th-owners">Owners <span class="sort-arrow">↕</span></th>
      <th>Licensed</th>
      <th onclick="sortByCol('tenant')"  id="th-tenant">Tenant <span class="sort-arrow">↕</span></th>
    </tr></thead>
    <tbody id="groupsTableBody"></tbody>
  </table>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:12px">
    <span id="pageInfo" style="font-size:12px;color:var(--muted)"></span>
    <div class="pagination" id="pagination"></div>
  </div>
</section>

<!-- INSIGHTS -->
<section id="page-insights" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Insights</div>
      <div class="page-subtitle">Top groups and membership breakdown</div>
    </div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🏆 Top 10 Groups by Member Count</div>
      <div id="topByMembers"></div>
    </div>
    <div class="panel">
      <div class="section-title">👻 Orphan Groups (no members or owners)</div>
      <div id="orphanList"></div>
    </div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🎫 Licensed Groups</div>
      <div id="licensedList"></div>
    </div>
    <div class="panel">
      <div class="section-title">🚫 Groups with No Owners</div>
      <div id="noOwnersList"></div>
    </div>
  </div>
</section>

</main>

<!-- DETAIL PANEL -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDetail()"></div>
  <div id="detailDrawer">
    <div class="detail-toolbar">
      <button class="btn" id="detailPrevBtn" onclick="navigateDetail(-1)">‹ Prev</button>
      <button class="btn" id="detailNextBtn" onclick="navigateDetail(1)">Next ›</button>
      <button class="btn" onclick="copyDetailName()">📋 Copy Name</button>
      <button id="detailClose" onclick="closeDetail()" title="Close (Esc)">✕</button>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<div id="toast"><span id="toastIcon">✅</span><span id="toastMsg">Done</span></div>

<script>
const GROUPS  = [__GROUPS_JSON__];
const TYPES   = [__TYPES_JSON__];
const TENANTS = [__TENANTS_JSON__];
const PALETTE = ['#3b82f6','#06b6d4','#8b5cf6','#10b981','#f59e0b','#ef4444','#ec4899','#84cc16','#f97316','#a78bfa'];

function typeBadge(t) {
  const map = {
    'Microsoft 365':'#06b6d4','Microsoft 365 (Security-enabled)':'#3b82f6',
    'Entra ID Security':'#8b5cf6','Mail-enabled Security':'#10b981',
    'Distribution':'#f59e0b','Unknown':'#64748b'
  };
  const col = map[t] || '#64748b';
  return `<span class="type-badge" style="background:${col}22;color:${col};border:1px solid ${col}44">${escH(t)}</span>`;
}

let _toastT;
function showToast(msg, icon='✅') {
  document.getElementById('toastMsg').textContent  = msg;
  document.getElementById('toastIcon').textContent = icon;
  const el = document.getElementById('toast');
  el.classList.add('show');
  clearTimeout(_toastT);
  _toastT = setTimeout(() => el.classList.remove('show'), 2600);
}

function toggleTheme() {
  const light = document.body.classList.toggle('light-theme');
  document.getElementById('themeIcon').textContent  = light ? '☀️' : '🌙';
  document.getElementById('themeLabel').textContent = light ? 'Light Mode' : 'Dark Mode';
  try { localStorage.setItem('entraid-grp-theme', light ? 'light' : 'dark'); } catch(e){}
}
(function(){
  try { if (localStorage.getItem('entraid-grp-theme') === 'light') {
    document.body.classList.add('light-theme');
    document.getElementById('themeIcon').textContent  = '☀️';
    document.getElementById('themeLabel').textContent = 'Light Mode';
  }} catch(e){}
})();

function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  if (btn) btn.classList.add('active');
}

// ── Overview bars ──
(function(){
  const maxT = Math.max(...TYPES.map(t => t.count), 1);
  const el   = document.getElementById('typesBars');
  TYPES.forEach((t, i) => {
    const pct = Math.round((t.count / maxT) * 100);
    const col = PALETTE[i % PALETTE.length];
    el.innerHTML += `<div class="bar-row" onclick="filterByType('${escJ(t.type)}')">
      <span class="bar-label" title="${escH(t.type)}">${escH(t.type)}</span>
      <div class="bar-track"><div class="bar-fill" style="background:${col}" data-pct="${pct}"></div></div>
      <span class="bar-count">${t.count}</span></div>`;
  });

  const maxTn = Math.max(...TENANTS.map(t => t.count), 1);
  const el2   = document.getElementById('tenantBars');
  TENANTS.forEach((t, i) => {
    const pct = Math.round((t.count / maxTn) * 100);
    const col = PALETTE[(i + 3) % PALETTE.length];
    el2.innerHTML += `<div class="bar-row" onclick="filterByTenant('${escJ(t.name)}')">
      <span class="bar-label" title="${escH(t.name)}">${escH(t.name)}</span>
      <div class="bar-track"><div class="bar-fill" style="background:${col}" data-pct="${pct}"></div></div>
      <span class="bar-count">${t.count}</span></div>`;
  });

  // Attention bars
  const total = GROUPS.length || 1;
  document.getElementById('barOrphan').dataset.pct   = Math.round((GROUPS.filter(g=>g.totalMembers===0&&g.ownersCount===0).length/total)*100);
  document.getElementById('barEmptyMem').dataset.pct = Math.round((GROUPS.filter(g=>g.totalMembers===0).length/total)*100);
  document.getElementById('barEmptyOwn').dataset.pct = Math.round((GROUPS.filter(g=>g.ownersCount===0).length/total)*100);

  // Member stats
  const totalUsers   = GROUPS.reduce((s,g)=>s+g.userCount,0);
  const totalGrpMem  = GROUPS.reduce((s,g)=>s+g.groupCount,0);
  const totalDev     = GROUPS.reduce((s,g)=>s+g.deviceCount,0);
  const totalSP      = GROUPS.reduce((s,g)=>s+g.spCount,0);
  const grandTotal   = totalUsers + totalGrpMem + totalDev + totalSP || 1;
  const statsEl      = document.getElementById('memberStats');
  [['👤 User members', totalUsers, '#3b82f6'],
   ['👥 Nested groups', totalGrpMem, '#8b5cf6'],
   ['💻 Devices', totalDev, '#10b981'],
   ['⚙️ Service Principals', totalSP, '#f59e0b']].forEach(([label, cnt, col]) => {
    const pct = Math.round((cnt/grandTotal)*100);
    statsEl.innerHTML += `<div class="bar-row" style="cursor:default">
      <span class="bar-label" style="width:160px">${label}</span>
      <div class="bar-track"><div class="bar-fill" style="background:${col}" data-pct="${pct}"></div></div>
      <span class="bar-count">${cnt}</span></div>`;
  });

  requestAnimationFrame(() => {
    document.querySelectorAll('.bar-fill').forEach(el => { el.style.width = el.dataset.pct + '%'; });
  });
})();

function filterByType(t)   { showPage('groups', document.querySelectorAll('.nav-btn')[1]); setTimeout(()=>{ document.getElementById('typeFilter').value=t;   filterTable(); }, 50); }
function filterByTenant(t) { showPage('groups', document.querySelectorAll('.nav-btn')[1]); setTimeout(()=>{ document.getElementById('tenantFilter').value=t; filterTable(); }, 50); }

// ── Table ──
let PAGE_SIZE = 25, filteredGroups = [...GROUPS], currentPage = 1, currentSort = 'name-asc';
(function(){
  const typesSel   = document.getElementById('typeFilter');
  const tenantsSel = document.getElementById('tenantFilter');
  TYPES.forEach(t   => { const o=document.createElement('option'); o.value=t.type;   o.textContent=`${t.type} (${t.count})`;   typesSel.appendChild(o); });
  TENANTS.forEach(t => { const o=document.createElement('option'); o.value=t.name;   o.textContent=`${t.name} (${t.count})`;   tenantsSel.appendChild(o); });
  filterTable();
})();

function changePageSize() { PAGE_SIZE = parseInt(document.getElementById('pageSizeSelect').value); currentPage = 1; renderTable(); }

function sortByCol(col) {
  const map   = { name:'name-asc', gtype:'gtype-asc', mtype:'mtype-asc', members:'members-desc', owners:'owners-desc', tenant:'tenant-asc' };
  const flip  = { asc:'desc', desc:'asc' };
  const cur   = currentSort;
  currentSort = cur.startsWith(col) ? col + '-' + flip[cur.endsWith('asc') ? 'asc' : 'desc'] : (map[col] || col + '-asc');
  document.getElementById('sortSelect').value = currentSort;
  document.querySelectorAll('.groups-table thead th').forEach(t => t.classList.remove('sort-active'));
  const th = document.getElementById('th-' + col);
  if (th) { th.classList.add('sort-active'); th.querySelector('.sort-arrow').textContent = currentSort.endsWith('asc') ? '↑' : '↓'; }
  filterTable();
}

function filterTable() {
  const q      = document.getElementById('tableSearch').value.toLowerCase().trim();
  const type   = document.getElementById('typeFilter').value;
  const tenant = document.getElementById('tenantFilter').value;
  const special= document.getElementById('memberFilter').value;
  currentSort  = document.getElementById('sortSelect').value;

  filteredGroups = GROUPS.filter(g => {
    const mQ = !q || g.name.toLowerCase().includes(q) || g.gtype.toLowerCase().includes(q) || g.tenant.toLowerCase().includes(q) || g.mail.toLowerCase().includes(q) || g.domain.toLowerCase().includes(q);
    const mT = !type   || g.gtype  === type;
    const mTn= !tenant || g.tenant === tenant;
    let mS   = true;
    if      (special === 'orphan')        mS = g.totalMembers === 0 && g.ownersCount === 0;
    else if (special === 'empty-members') mS = g.totalMembers === 0;
    else if (special === 'empty-owners')  mS = g.ownersCount  === 0;
    else if (special === 'licensed')      mS = g.licensed;
    else if (special === 'dynamic')       mS = g.mtype === 'Dynamic';
    else if (special === 'synced')        mS = g.synced;
    return mQ && mT && mTn && mS;
  });

  const sorts = {
    'name-asc':    (a,b) => a.name.localeCompare(b.name),
    'name-desc':   (a,b) => b.name.localeCompare(a.name),
    'gtype-asc':   (a,b) => a.gtype.localeCompare(b.gtype),
    'gtype-desc':  (a,b) => b.gtype.localeCompare(a.gtype),
    'mtype-asc':   (a,b) => a.mtype.localeCompare(b.mtype),
    'mtype-desc':  (a,b) => b.mtype.localeCompare(a.mtype),
    'members-desc':(a,b) => b.totalMembers - a.totalMembers,
    'members-asc': (a,b) => a.totalMembers - b.totalMembers,
    'owners-desc': (a,b) => b.ownersCount  - a.ownersCount,
    'owners-asc':  (a,b) => a.ownersCount  - b.ownersCount,
    'tenant-asc':  (a,b) => a.tenant.localeCompare(b.tenant),
    'tenant-desc': (a,b) => b.tenant.localeCompare(a.tenant)
  };
  if (sorts[currentSort]) filteredGroups.sort(sorts[currentSort]);
  currentPage = 1;
  renderTable();
}

function renderTable() {
  const start = (currentPage - 1) * PAGE_SIZE;
  const slice = filteredGroups.slice(start, start + PAGE_SIZE);
  document.getElementById('resultCount').textContent = `${filteredGroups.length} of ${GROUPS.length}`;
  document.getElementById('pageInfo').textContent    = `Showing ${start+1}–${Math.min(start+PAGE_SIZE, filteredGroups.length)} of ${filteredGroups.length}`;
  document.getElementById('groupsTableBody').innerHTML = slice.map((g, idx) => `
    <tr onclick="openDetailFromList(${start + idx})">
      <td class="td-name">${escH(g.name)}</td>
      <td>${typeBadge(g.gtype)}</td>
      <td class="td-meta">${escH(g.mtype)}</td>
      <td class="td-meta">${g.totalMembers}</td>
      <td class="td-meta">${g.ownersCount}</td>
      <td class="td-meta">${g.licensed ? '<span style="color:var(--green)">✅</span>' : '<span style="color:var(--muted)">—</span>'}</td>
      <td class="td-meta" style="color:var(--muted2)">${escH(g.domain || g.tenant)}</td>
    </tr>`).join('');
  renderPagination();
}

function renderPagination() {
  const total = Math.ceil(filteredGroups.length / PAGE_SIZE);
  const el    = document.getElementById('pagination');
  if (total <= 1) { el.innerHTML = ''; return; }
  let h = `<button class="page-btn" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>‹</button>`;
  for (let i=1; i<=total; i++) {
    if (i===1||i===total||Math.abs(i-currentPage)<=1) h += `<button class="page-btn ${i===currentPage?'active':''}" onclick="goPage(${i})">${i}</button>`;
    else if (Math.abs(i-currentPage)===2) h += `<span style="color:var(--muted);padding:0 4px">…</span>`;
  }
  h += `<button class="page-btn" onclick="goPage(${currentPage+1})" ${currentPage===total?'disabled':''}>›</button>`;
  el.innerHTML = h;
}

function goPage(p) {
  const total = Math.ceil(filteredGroups.length / PAGE_SIZE);
  if (p < 1 || p > total) return;
  currentPage = p; renderTable();
}

// ── Insights ──
(function(){
  const topMem = [...GROUPS].sort((a,b)=>b.totalMembers-a.totalMembers).slice(0,10);
  document.getElementById('topByMembers').innerHTML = topMem.map((g,i) =>
    `<div class="bar-row" style="cursor:pointer" onclick="openDetail('${escJ(g.id)}')">
      <span style="font-family:var(--mono);font-size:11px;color:var(--muted);width:20px;flex-shrink:0">${i+1}</span>
      <span class="bar-label" style="flex:1;width:auto" title="${escH(g.name)}">${escH(g.name)}</span>
      <span class="bar-count" style="width:auto;color:var(--muted)">${g.totalMembers} members</span></div>`).join('');

  const orphans = GROUPS.filter(g=>g.totalMembers===0&&g.ownersCount===0).slice(0,10);
  document.getElementById('orphanList').innerHTML = orphans.length === 0
    ? '<p style="color:var(--green);font-size:13px">✅ No orphan groups found!</p>'
    : orphans.map(g=>`<div class="bar-row" onclick="openDetail('${escJ(g.id)}')">
        <span class="bar-label" style="flex:1;width:auto" title="${escH(g.name)}">${escH(g.name)}</span>
        <span style="font-size:11px;color:var(--muted)">${escH(g.gtype)}</span></div>`).join('') +
      (GROUPS.filter(g=>g.totalMembers===0&&g.ownersCount===0).length > 10 ? `<div style="color:var(--muted);font-size:12px;margin-top:7px">…and ${GROUPS.filter(g=>g.totalMembers===0&&g.ownersCount===0).length-10} more</div>` : '');

  const licensed = GROUPS.filter(g=>g.licensed).slice(0,10);
  document.getElementById('licensedList').innerHTML = licensed.length === 0
    ? '<p style="color:var(--muted);font-size:13px">No licensed groups found.</p>'
    : licensed.map(g=>`<div class="bar-row" onclick="openDetail('${escJ(g.id)}')">
        <span class="bar-label" style="flex:1;width:auto" title="${escH(g.name)}">${escH(g.name)}</span>
        <span style="font-size:11px;color:var(--green)">🎫 ${escH(g.licSku||'')}</span></div>`).join('');

  const noOwners = GROUPS.filter(g=>g.ownersCount===0).slice(0,10);
  document.getElementById('noOwnersList').innerHTML = noOwners.length === 0
    ? '<p style="color:var(--green);font-size:13px">✅ All groups have owners!</p>'
    : noOwners.map(g=>`<div class="bar-row" onclick="openDetail('${escJ(g.id)}')">
        <span class="bar-label" style="flex:1;width:auto" title="${escH(g.name)}">${escH(g.name)}</span>
        <span style="font-size:11px;color:var(--muted)">${escH(g.gtype)}</span></div>`).join('') +
      (noOwners.length === 10 && GROUPS.filter(g=>g.ownersCount===0).length > 10 ? `<div style="color:var(--muted);font-size:12px;margin-top:7px">…and ${GROUPS.filter(g=>g.ownersCount===0).length-10} more</div>` : '');
})();

// ── Detail panel ──
let currentDetailIndex = -1, detailList = GROUPS;
function openDetailFromList(idx) { detailList = filteredGroups; currentDetailIndex = idx; _renderDetail(detailList[idx]); }
function openDetail(id) { const idx = GROUPS.findIndex(x => x.id === id); detailList = GROUPS; currentDetailIndex = idx; if (idx >= 0) _renderDetail(GROUPS[idx]); }
function navigateDetail(dir) { const ni = currentDetailIndex + dir; if (ni < 0 || ni >= detailList.length) return; currentDetailIndex = ni; _renderDetail(detailList[ni]); }
function _renderDetail(g) {
  if (!g) return;
  document.getElementById('detailPrevBtn').disabled = currentDetailIndex <= 0;
  document.getElementById('detailNextBtn').disabled = currentDetailIndex >= detailList.length - 1;

  const fmt = (label, val, col) => val
    ? `<div class="detail-section"><div class="detail-section-title">${label}</div><div class="member-list" style="color:${col||'var(--muted2)'}">${escH(val).replace(/; /g,'<br>')}</div></div>`
    : '';

  document.getElementById('detailContent').innerHTML = `
    <div class="detail-header">
      <div class="detail-name">${escH(g.name)}</div>
      ${g.mail && g.mail !== '-' ? `<div class="detail-mail">${escH(g.mail)}</div>` : ''}
    </div>
    <div class="detail-meta-row">
      ${typeBadge(g.gtype)}
      <span class="detail-chip">⚡ ${escH(g.mtype)}</span>
      <span class="detail-chip">👤 ${g.userCount} users</span>
      <span class="detail-chip">👥 ${g.groupCount} groups</span>
      <span class="detail-chip">💻 ${g.deviceCount} devices</span>
      <span class="detail-chip">🔑 ${g.ownersCount} owners</span>
      <span class="detail-chip" style="color:${g.licensed?'var(--green)':'var(--muted)'}">${g.licensed?'🎫 Licensed':'No Licence'}</span>
      <span class="detail-chip" style="color:${g.synced?'var(--amber)':'var(--muted)'}">${g.synced?'🔄 On-Prem Synced':'☁️ Cloud Only'}</span>
      ${g.assignableToRole?'<span class="detail-chip" style="color:var(--accent3)">🔐 Role-Assignable</span>':''}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Tenant</div>
      <p style="color:var(--muted2);font-size:13px">${escH(g.tenant)} — ${escH(g.domain)}</p>
    </div>
    ${g.licSku && g.licSku !== '-' ? `<div class="detail-section"><div class="detail-section-title">Assigned Licence SKU IDs</div><p style="font-family:var(--mono);font-size:12px;color:var(--accent2)">${escH(g.licSku)}</p></div>` : ''}
    ${fmt('Owner UPNs', g.ownerUpns, 'var(--accent)')}
    ${fmt('User Members', g.userMembers, 'var(--muted2)')}`;

  document.getElementById('detailPanel').classList.add('open');
  document.body.style.overflow = 'hidden';
  document.getElementById('detailContent').scrollTo(0, 0);
}
function closeDetail() { document.getElementById('detailPanel').classList.remove('open'); document.body.style.overflow = ''; }
function copyDetailName() { if (currentDetailIndex >= 0 && detailList[currentDetailIndex]) copyText(detailList[currentDetailIndex].name, null); }
function copyText(text, btn) {
  try { navigator.clipboard.writeText(text).then(() => { showToast('Copied to clipboard!'); if(btn){btn.textContent='Copied!';btn.classList.add('copied');setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('copied');},1800);}}); }
  catch(e) { showToast('Copy not available','⚠'); }
}

// ── CSV Export ──
function exportCSV(filtered) {
  const data = filtered ? filteredGroups : GROUPS;
  const esc  = v => `"${String(v||'').replace(/"/g,'""')}"`;
  const hdrs = 'Display Name,Group Type,Membership Type,Total Members,User Members,Group Members,Device Members,SP Members,Owners Count,Licensed,On-Prem Synced,Role-Assignable,Tenant,Domain,Mail,Owner UPNs,User Members List';
  const rows = data.map(g => [
    esc(g.name), esc(g.gtype), esc(g.mtype), g.totalMembers, g.userCount, g.groupCount, g.deviceCount, g.spCount,
    g.ownersCount, g.licensed, g.synced, g.assignableToRole, esc(g.tenant), esc(g.domain), esc(g.mail),
    esc(g.ownerUpns), esc(g.userMembers)
  ].join(','));
  dlFile([hdrs, ...rows].join('\r\n'), 'EntraID-Groups-Dashboard-Export.csv', 'text/csv');
  showToast(`Exported ${data.length} groups as CSV`);
}

function dlFile(content, name, type) { const b=new Blob([content],{type}); const u=URL.createObjectURL(b); const a=document.createElement('a'); a.href=u; a.download=name; a.click(); URL.revokeObjectURL(u); }

// ── Keyboard shortcuts ──
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeDetail(); return; }
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'SELECT') {
    e.preventDefault();
    const inp = document.querySelector('.page.active input[type=text]');
    if (inp) inp.focus();
  }
  if (document.getElementById('detailPanel').classList.contains('open')) {
    if (e.key === 'ArrowLeft')  navigateDetail(-1);
    if (e.key === 'ArrowRight') navigateDetail(1);
  }
});

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
</script>
</body>
</html>
'@

        # ── Token substitution ────────────────────────────────────────────────
        $html = $html `
            -replace '__TOTALGROUPS__', $totalGroups `
            -replace '__M365GROUPS__', $m365Groups `
            -replace '__SECGROUPS__', ($securityGroups + $mailSecGroups) `
            -replace '__DISTGROUPS__', $distGroups `
            -replace '__DYNGROUPS__', $dynamicGroups `
            -replace '__LICGROUPS__', $licensedGroups `
            -replace '__ORPHANGROUPS__', $orphanGroups `
            -replace '__SYNCEDGROUPS__', $syncedGroups `
            -replace '__EMPTYMEMGROUPS__', $emptyMemberGroups `
            -replace '__EMPTYOWNGROUPS__', $emptyOwnerGroups `
            -replace '__TENANTCOUNT__', $TenantIds.Count `
            -replace '__GENERATEDAT__', $generatedAt `
            -replace '__GROUPS_JSON__', $groupsJson `
            -replace '__TYPES_JSON__', $typeJson `
            -replace '__TENANTS_JSON__', $tenantJson

        # ── Write file ────────────────────────────────────────────────────────
        Try {
            $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force -ErrorAction Stop
            Write-Host "  ✅  HTML dashboard saved!" -ForegroundColor Green
            Write-Host ""
            Write-Host ("      📊  {0,-20} : {1}" -f "Total groups", $totalGroups)   -ForegroundColor White
            Write-Host ("      ☁️  {0,-20} : {1}" -f "Microsoft 365", $m365Groups)    -ForegroundColor White
            Write-Host ("      🔒  {0,-20} : {1}" -f "Security groups", ($securityGroups + $mailSecGroups)) -ForegroundColor White
            Write-Host ("      👻  {0,-20} : {1}" -f "Orphan groups", $orphanGroups)  -ForegroundColor White
            Write-Host ("      🎫  {0,-20} : {1}" -f "Licensed groups", $licensedGroups) -ForegroundColor White
            Write-Host ""
            Write-Host "      📄  Dashboard : $OutputPath" -ForegroundColor White
        }
        Catch {
            Write-Error "Failed to write HTML dashboard to '$OutputPath'. Details: $_"
        }
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: CSV Export Helper
    #─────────────────────────────────────────────────────────────────────────────

    Function Export-RecordsToCsv {
        param
        (
            [Parameter(Mandatory = $true)]
            [System.Collections.ArrayList] $Records,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $FilePath,

            [Parameter(Mandatory = $true)]
            [string] $ReportLabel
        )

        Try {
            $Records | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
            Write-Host "  ✅  $ReportLabel saved!" -ForegroundColor Green
            Write-Host "      📄  File : $FilePath" -ForegroundColor White
            Write-Host "      👥  Rows : $($Records.Count)" -ForegroundColor White
        }
        Catch {
            Write-Error "Failed to save '$FilePath'. Details: $_"
        }
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Main Execution — Shared Setup
    #─────────────────────────────────────────────────────────────────────────────

    # ── Validate and prepare export directory ─────────────────────────────────

    if (-not (Test-Path -Path $ExportPath)) {
        Try {
            New-Item -Path $ExportPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Created export directory: $ExportPath"
        }
        Catch {
            Write-Error "Cannot create export directory '$ExportPath'. Please supply a valid -ExportPath. Details: $_"
            return
        }
    }

    # ── Decode SecureString in the parent function body (PS 5.1 DPAPI requirement) ─

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
    $plainSecret = $null
    Try {
        $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    Finally {
        if ($bstr -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $bstr = $null
    }

    if ([string]::IsNullOrEmpty($plainSecret)) {
        Write-Host "  ❌  Could not decode the ClientSecret SecureString." -ForegroundColor Red
        Write-Host "      Ensure it was created with: Read-Host -AsSecureString" -ForegroundColor Yellow
        Write-Error "ClientSecret decoding failed."
        return
    }

    # ── Initialise global context ─────────────────────────────────────────────

    $global:_grpctx = @{
        ClientId               = $ClientId
        ClientSecret           = $plainSecret
        TenantId               = $null
        AccessToken            = $null
        TokenExpiry            = $null
        RefreshIntervalMinutes = $TokenRefreshIntervalMinutes
    }

    $plainSecret = $null   # scrub local copy

    # ── Collect ALL groups from ALL tenants (done once, reused by all menu options) ─

    Function Invoke-CollectAllGroups {
        $allRecords = New-Object System.Collections.ArrayList
        $scriptStartTime = Get-Date

        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║  👥  Entra ID — Multi-Tenant Group Report                                ║" -ForegroundColor Cyan
        Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
        Write-Host "  ║  Querying Microsoft Graph across all specified tenants to produce        ║" -ForegroundColor Cyan
        Write-Host "  ║  a unified group inventory with members, owners and licence data.        ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  🕐  Started  : $($scriptStartTime.ToString('dd-MMM-yyyy  HH:mm:ss'))" -ForegroundColor White
        Write-Host "  🏢  Checking : $($TenantIds.Count) company director$(if ($TenantIds.Count -eq 1) {'y'} else {'ies'})" -ForegroundColor White
        Write-Host "  ⚡  Parallel : $ThrottleLimit groups processed simultaneously per tenant" -ForegroundColor White
        Write-Host ""

        foreach ($tenantId in $TenantIds) {
            Write-Host "  ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "  🔌  Connecting to directory..." -ForegroundColor Yellow
            Write-Host "      (ID: $tenantId)" -ForegroundColor DarkGray

            $accessToken = Connect-EntraIDTenant -TenantId $tenantId

            if (-not $accessToken) {
                Write-Host "  ⛔  Could not connect — skipping this directory." -ForegroundColor Red
                Write-Host "      (Directory ID: $tenantId)" -ForegroundColor DarkGray
                continue
            }

            $tenant = Get-EntraIDTenantDetails
            $tenantLabel = if ($tenant) { "$($tenant.TenantName) [$($tenant.TenantPrimaryDomain)]" } else { $tenantId }

            Write-Host "  ✅  Connected to: $tenantLabel" -ForegroundColor Green
            Write-Host ""

            Write-Host "  📋  Fetching full group list..." -ForegroundColor Yellow
            Write-Host "      (Paginating through all groups — may take a moment for large tenants)" -ForegroundColor DarkGray
            $groups = Get-EntraIDAllGroups
            $totalGroups = $groups.Count

            if ($totalGroups -eq 0) {
                Write-Host "  ⚠️   No groups found. Check that 'Group.Read.All' permission is granted." -ForegroundColor Yellow
                continue
            }

            Write-Host "  ✅  Found $totalGroups group$(if ($totalGroups -ne 1) {'s'}) in this directory." -ForegroundColor Green
            Write-Host ""
            Write-Host "  ⚙️   Enriching groups with members and owners in parallel..." -ForegroundColor Yellow
            Write-Host "      Running $ThrottleLimit groups in parallel — hang tight. ☕" -ForegroundColor DarkGray
            Write-Host ""

            $accessTokenSnapshot = $global:_grpctx.AccessToken
            $tenantSnapshot = $tenant

            $bag = Invoke-GroupEnrichmentParallel `
                -Groups              $groups `
                -AccessTokenSnapshot $accessTokenSnapshot `
                -TenantSnapshot      $tenantSnapshot `
                -ThrottleLimit       $ThrottleLimit

            foreach ($r in $bag) { $null = $allRecords.Add($r) }

            Write-Host "  ✅  All done for $tenantLabel  ($totalGroups groups collected)" -ForegroundColor Green
        }

        # ── Summary ──────────────────────────────────────────────────────────
        $scriptEndTime = Get-Date
        $executionTime = New-TimeSpan -Start $scriptStartTime -End $scriptEndTime

        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "  ║  🎉  Collection complete — here is a quick summary:                      ║" -ForegroundColor Green
        Write-Host "  ╠══════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
        Write-Host "  ║                                                                          ║" -ForegroundColor Green
        Write-Host ("  ║  🕐  Started at     : {0,-51}║" -f $scriptStartTime.ToString('dd-MMM-yyyy  HH:mm:ss')) -ForegroundColor Green
        Write-Host ("  ║  🏁  Finished at    : {0,-51}║" -f $scriptEndTime.ToString('dd-MMM-yyyy  HH:mm:ss'))   -ForegroundColor Green
        Write-Host ("  ║  ⏱️  Time taken     : {0,-51}║" -f ($executionTime.ToString('hh\:mm\:ss') + '  (hours:minutes:seconds)')) -ForegroundColor Green
        Write-Host "  ║                                                                          ║" -ForegroundColor Green
        Write-Host ("  ║  🏢  Directories    : {0,-51}║" -f "$($TenantIds.Count) checked")                         -ForegroundColor Green
        Write-Host ("  ║  👥  Groups found   : {0,-51}║" -f "$($allRecords.Count) total (across all directories)") -ForegroundColor Green
        Write-Host ("  ║  ⚡  Parallel limit : {0,-51}║" -f "$ThrottleLimit groups at a time")                     -ForegroundColor Green
        Write-Host "  ║                                                                          ║" -ForegroundColor Green
        Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""

        return $allRecords
    }


    #─────────────────────────────────────────────────────────────────────────────
    # REGION: Interactive Menu
    #─────────────────────────────────────────────────────────────────────────────

    Function Show-GroupReportMenu {
        Clear-Host
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║  👥  Entra ID — Multi-Tenant Group Report Menu                           ║" -ForegroundColor Cyan
        Write-Host "  ╠══════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
        Write-Host "  ║  CSV Reports                                                             ║" -ForegroundColor Cyan
        Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
        Write-Host "  ║    [1]  Full Groups Inventory         — every group, all fields          ║" -ForegroundColor White
        Write-Host "  ║    [2]  Orphan Groups                 — no members AND no owners         ║" -ForegroundColor White
        Write-Host "  ║    [3]  Empty Member Groups           — no members of any type           ║" -ForegroundColor White
        Write-Host "  ║    [4]  Empty Owner Groups            — no owners assigned               ║" -ForegroundColor White
        Write-Host "  ║    [5]  Office 365 Licensed Groups    — groups with M365 licences        ║" -ForegroundColor White
        Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
        Write-Host "  ║  HTML Dashboard                                                          ║" -ForegroundColor Cyan
        Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
        Write-Host "  ║    [6]  Interactive HTML Dashboard    — searchable, filterable,          ║" -ForegroundColor Yellow
        Write-Host "  ║         dark/light theme, stat cards, charts, detail drawer              ║" -ForegroundColor Yellow
        Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
        Write-Host "  ║    [Q]  Quit                                                             ║" -ForegroundColor DarkGray
        Write-Host "  ║                                                                          ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host ("  🏢  Tenants : {0}  |  ⚡ Parallel : {1}  |  📁 Output : {2}" -f $TenantIds.Count, $ThrottleLimit, $ExportPath) -ForegroundColor DarkGray
        Write-Host ""
    }

    # ── Main loop ──────────────────────────────────────────────────────────────

    $continue = $true
    $allGroupRecords = $null   # collected once, reused across menu selections

    while ($continue) {
        Show-GroupReportMenu
        Write-Host -NoNewline "  Enter your option: " -ForegroundColor Cyan
        $choice = Read-Host

        if ($choice -notin @('1', '2', '3', '4', '5', '6', 'Q', 'q')) {
            Write-Host "  ❌  Invalid option. Please enter 1–6 or Q." -ForegroundColor Red
            Start-Sleep -Seconds 2
            continue
        }

        if ($choice -in @('Q', 'q')) {
            Write-Host ""
            Write-Host "  👋  Exiting. Report session ended." -ForegroundColor DarkGray
            $continue = $false
            break
        }

        # Collect groups if not already done
        if ($null -eq $allGroupRecords) {
            $allGroupRecords = Invoke-CollectAllGroups
        }

        if ($allGroupRecords.Count -eq 0) {
            Write-Host "  ⚠️   No group records collected. Please check your permissions and tenant IDs." -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            continue
        }

        Write-Host ""

        switch ($choice) {
            '1' {
                $csvPath = Join-Path $ExportPath "EntraID-Groups-Inventory.csv"
                Write-Host "  💾  Exporting full group inventory..." -ForegroundColor Yellow
                Export-RecordsToCsv -Records $allGroupRecords -FilePath $csvPath -ReportLabel "Full Groups Inventory"
            }
            '2' {
                $orphans = [System.Collections.ArrayList]($allGroupRecords | Where-Object {
                        $_.'Total Members Count' -eq 0 -and $_.'Owners Count' -eq 0
                    })
                $csvPath = Join-Path $ExportPath "EntraID-Groups-Orphan.csv"
                Write-Host "  💾  Exporting orphan groups ($($orphans.Count) found)..." -ForegroundColor Yellow
                if ($orphans.Count -gt 0) {
                    Export-RecordsToCsv -Records $orphans -FilePath $csvPath -ReportLabel "Orphan Groups"
                }
                else {
                    Write-Host "  ✅  No orphan groups found across all tenants!" -ForegroundColor Green
                }
            }
            '3' {
                $emptyMem = [System.Collections.ArrayList]($allGroupRecords | Where-Object {
                        $_.'Total Members Count' -eq 0
                    })
                $csvPath = Join-Path $ExportPath "EntraID-Groups-EmptyMembers.csv"
                Write-Host "  💾  Exporting empty member groups ($($emptyMem.Count) found)..." -ForegroundColor Yellow
                if ($emptyMem.Count -gt 0) {
                    Export-RecordsToCsv -Records $emptyMem -FilePath $csvPath -ReportLabel "Empty Member Groups"
                }
                else {
                    Write-Host "  ✅  No empty member groups found!" -ForegroundColor Green
                }
            }
            '4' {
                $emptyOwn = [System.Collections.ArrayList]($allGroupRecords | Where-Object {
                        $_.'Owners Count' -eq 0
                    })
                $csvPath = Join-Path $ExportPath "EntraID-Groups-EmptyOwners.csv"
                Write-Host "  💾  Exporting empty owner groups ($($emptyOwn.Count) found)..." -ForegroundColor Yellow
                if ($emptyOwn.Count -gt 0) {
                    Export-RecordsToCsv -Records $emptyOwn -FilePath $csvPath -ReportLabel "Empty Owner Groups"
                }
                else {
                    Write-Host "  ✅  No groups without owners found!" -ForegroundColor Green
                }
            }
            '5' {
                $licensed = [System.Collections.ArrayList]($allGroupRecords | Where-Object {
                        $_.'Is Licence Assigned' -eq 'Yes'
                    })
                $csvPath = Join-Path $ExportPath "EntraID-Groups-Licensed.csv"
                Write-Host "  💾  Exporting licensed groups ($($licensed.Count) found)..." -ForegroundColor Yellow
                if ($licensed.Count -gt 0) {
                    Export-RecordsToCsv -Records $licensed -FilePath $csvPath -ReportLabel "Licensed Groups"
                }
                else {
                    Write-Host "  ℹ️   No licence-assigned groups found across all tenants." -ForegroundColor DarkCyan
                }
            }
            '6' {
                $htmlPath = Join-Path $ExportPath "EntraID-Groups-Dashboard.html"
                Write-Host "  🌐  Generating HTML dashboard..." -ForegroundColor Yellow
                Export-GroupsDashboard -AllRecords $allGroupRecords -OutputPath $htmlPath -TenantIds $TenantIds
            }
        }

        Write-Host ""
        Write-Host -NoNewline "  Press Enter to return to the menu (or Q to quit): " -ForegroundColor DarkGray
        $nav = Read-Host
        if ($nav -in @('Q', 'q')) { $continue = $false }
    }

    # ── Scrub secret from memory ──────────────────────────────────────────────
    $global:_grpctx.ClientSecret = $null
    $global:_grpctx = $null

    # return $allGroupRecords
}
