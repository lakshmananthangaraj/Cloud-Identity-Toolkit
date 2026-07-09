<#

Author          : Lakshmanan Thangaraj
Version         : 2.0
Created-On      : 28 May 2024
Modified-On     : 09 July 2026

.SYNOPSIS
    Retrieves active PIM Entra ID role assignment details and optionally generates an enhanced HTML dashboard report.

.DESCRIPTION
    The Get-PIMActiveEntraIDRoleAssignmentDetails function retrieves active Privileged Identity Management (PIM)
    role assignment schedule instances from Microsoft Graph (beta endpoint).

    Authentication is flexible — supply either:
        - A ready-made -AccessToken (e.g. copied from Graph Explorer, or obtained via
          Connect-MgGraph), for quick manual/ad-hoc runs, OR
        - -ClientId, -ClientSecret, and -TenantId, so the function authenticates itself
          via app-only client credentials using Connect-EntraID.ps1 under the hood —
          ideal for unattended/automated runs (Azure Automation, scheduled tasks, CI).

    It supports:
        - Access token validation
        - Pagination handling
        - Graph API throttling handling (HTTP 429)
        - Transformation of role assignment data into structured objects
        - Optional HTML dashboard report generation with:
            ✅ Overview tab      — KPI cards, charts, security risk score, layman-friendly explainers
            ✅ Users tab         — User-specific role assignments with UPN, mail
            ✅ Groups tab        — Group-based role assignments
            ✅ Service Principals tab — App/SP role assignments
            ✅ Risk Insights tab — Permanent access, high-privilege roles, stale access warnings
            ✅ Export tab        — CSV / JSON download buttons
        - Tenant name and Tenant ID in report header
        - Dark/Light theme toggle
        - Per-tab search, sort, and pagination
        - Toast notifications

.PARAMETER AccessToken
    Microsoft Graph access token used for authentication.

.PARAMETER ClientId
    The Application (client) ID of the Azure AD app registration used for app-only
    authentication. Use this together with -ClientSecret and -TenantId instead of
    -AccessToken when running unattended.

.PARAMETER ClientSecret
    The client secret for the app registration, supplied as a SecureString. Example:
        $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Used together with -ClientId and -TenantId.

.PARAMETER TenantId
    The Directory (tenant) ID. Serves double duty: it's used both to authenticate
    (when -ClientId/-ClientSecret are supplied) and to display in the dashboard
    header. If you already have an -AccessToken, this is only used for display.

.PARAMETER TenantName
    Display name of the tenant (e.g. "Contoso Ltd"). Shown in the dashboard header.

.PARAMETER TenantId
    The Azure AD Tenant ID (GUID). Shown in the dashboard header.

.PARAMETER GenerateHtmlDoc
    Switch parameter. If specified, generates a formatted HTML dashboard and saves it locally.

.OUTPUTS
    System.Object[]
    Returns a collection of PIM active role assignment objects.

.EXAMPLE
    Get-PIMActiveEntraIDRoleAssignmentDetails -AccessToken $token -TenantName "Contoso" -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    Get-PIMActiveEntraIDRoleAssignmentDetails -AccessToken $token -TenantName "Contoso" -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -GenerateHtmlDoc

.EXAMPLE
    . .\Connect-EntraID.ps1
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-PIMActiveEntraIDRoleAssignmentDetails -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" -GenerateHtmlDoc

    Authenticates automatically via app-only client credentials (no manual token
    copy-paste needed) and generates the HTML dashboard. Ideal for scheduled/
    unattended runs.

.NOTES
    To use app-only authentication, download Connect-EntraID.ps1 from the link below.

    Microsoft Graph endpoint:
    https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances

    Requires (Application permissions, if using -ClientId/-ClientSecret/-TenantId):
    - RoleManagement.Read.Directory
    - Directory.Read.All
    (Same permission names apply whether delegated via -AccessToken or app-only.)

    Note on least privilege: Directory.Read.All is broad. If your tenant's principal
                             types are limited to users only (no group/SP-based PIM assignments), consider
                             testing with RoleManagement.Read.Directory alone first before granting the wider
                             Directory.Read.All permission to the app registration.

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (28-May-2024)      - Initial release: pagination, throttling handling,
                                 structured output, HTML dashboard.
        2.0 (09-Jul-2026)      - Added app-only authentication support via
                                 Connect-EntraID.ps1 (-ClientId/-ClientSecret/
                                 -TenantId), as an alternative to supplying a raw
                                 -AccessToken. Long-running pagination now silently
                                 renews the token when authenticated this way.

.LINK
    https://learn.microsoft.com/en-us/graph/api/roleeligibilityscheduleinstance-list?view=graph-rest-beta

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Show-FriendlyHelp
{
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       Get-PIMActiveEntraIDRoleAssignmentDetails  v2.0        ║" -ForegroundColor Cyan
    Write-Host "  ║                   Friendly Help Guide                        ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this does:" -ForegroundColor Yellow
    Write-Host "    Pulls every active PIM role assignment from your Entra ID tenant"
    Write-Host "    (users, groups, and service principals), and optionally builds an"
    Write-Host "    interactive HTML dashboard summarizing privileged access."
    Write-Host ""
    Write-Host "  Choose ONE authentication method:" -ForegroundColor Yellow
    Write-Host "    Option A — Bring your own token:"
    Write-Host "      -AccessToken   A bearer token (e.g. from Graph Explorer or Connect-MgGraph)"
    Write-Host ""
    Write-Host "  Option B — App-only login (recommended for automation):" -ForegroundColor Yellow
    Write-Host "      (Requires Connect-EntraID.ps1 – get it from the repo:)" -ForegroundColor DarkYellow
    Write-Host "      https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1" -ForegroundColor Cyan
    Write-Host "      -ClientId       Application (client) ID of your app registration" -ForegroundColor Yellow
    Write-Host "      -ClientSecret   The app's client secret, as a SecureString" -ForegroundColor Yellow
    Write-Host "      -TenantId       Directory (tenant) ID" -ForegroundColor Yellow
    Write-Host "      -RefreshInterval  (optional) Minutes before expiry to renew early (default: 5)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Optional parameters (either method):" -ForegroundColor Yellow
    Write-Host "    -TenantName       Display name shown in the dashboard header"
    Write-Host "    -GenerateHtmlDoc  Builds and opens the HTML dashboard"
    Write-Host "    -ShowHelp         Shows this guide and exits, nothing is generated"
    Write-Host ""
    Write-Host "  Example (Option A):" -ForegroundColor Yellow
    Write-Host '    Get-PIMActiveEntraIDRoleAssignmentDetails -AccessToken $token -TenantName "Contoso" -GenerateHtmlDoc'
    Write-Host ""
    Write-Host "  Example (Option B):" -ForegroundColor Yellow
    Write-Host '    . .\Connect-EntraID.ps1'
    Write-Host '    $secret = Read-Host -Prompt "Client secret" -AsSecureString'
    Write-Host '    Get-PIMActiveEntraIDRoleAssignmentDetails -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" -GenerateHtmlDoc'
    Write-Host ""
    Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
    Write-Host "     Get-Help Get-PIMActiveEntraIDRoleAssignmentDetails -Full"
    Write-Host ""
}

Function Get-PIMActiveEntraIDRoleAssignmentDetails
{
    [CmdletBinding(DefaultParameterSetName = "Token")]
    param (
        # ── Auth Option A: bring your own token ─────────────────────────────
        [Parameter(Mandatory = $true, ParameterSetName = "Token")]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        # ── Auth Option B: app-only client credentials (via Connect-EntraID) ─
        [Parameter(Mandatory = $true, ParameterSetName = "AppAuth")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = "AppAuth")]
        [ValidateNotNull()]
        [System.Security.SecureString]$ClientSecret,

        [Parameter(ParameterSetName = "AppAuth")]
        [int]$RefreshInterval = 5,

        # ── Shared: used for auth (AppAuth) and/or dashboard display (both) ──
        [Parameter(Mandatory = $true,  ParameterSetName = "AppAuth")]
        [Parameter(Mandatory = $false, ParameterSetName = "Token")]
        [string]$TenantId = "N/A",

        [Parameter(Mandatory = $false)]
        [string]$TenantName = "Your Organization",

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = $env:TEMP,

        [switch]$GenerateHtmlDoc,

        # ── Help ──────────────────────────────────────────────────────────────
        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    if ($ShowHelp)
    {
        Show-FriendlyHelp
        return
    }

    # Validate token upfront before doing anything (only applies to the Token parameter set —
    # AppAuth mode obtains its own token in the next block)
    if ($PSCmdlet.ParameterSetName -eq "Token" -and -not $AccessToken)
    {
        Write-Error "AccessToken is required. Please provide a valid Bearer token."
        return
    }

    if ($PSCmdlet.ParameterSetName -eq "AppAuth")
    {
        if (-not (Get-Command Connect-EntraID -ErrorAction SilentlyContinue))
        {
            Write-Error @"
Connect-EntraID function not found. 
To use app-only authentication, you need the Connect-EntraID.ps1 helper script.
Download it from:
  https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

Then dot‑source it in your session before calling this function, e.g.:
  . .\Connect-EntraID.ps1
"@
            return
        }

        Write-Verbose "Authenticating via app-only client credentials for tenant $TenantId"

        $AccessToken = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId -RefreshInterval $RefreshInterval

        if (-not $AccessToken)
        {
            Write-Error "Failed to obtain an access token via Connect-EntraID. See error above for details."
            return
        }
    }

    $allLogs   = New-Object System.Collections.ArrayList
    $totalLogs = 0

    $uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentScheduleInstances?`$expand=*&`$count=true"

    do
    {
        # If authenticated via app-only credentials, pull a fresh token each page —
        # Get-EntraIDAccessToken silently renews only if it's actually close to expiry,
        # so this is cheap to call every iteration and protects large tenants whose
        # pagination can outlast a single token's ~60 minute lifetime.
        if ($PSCmdlet.ParameterSetName -eq "AppAuth")
        {
            $AccessToken = Get-EntraIDAccessToken
        }

        $headers = @{
            "Authorization"    = "Bearer $AccessToken"
            "ConsistencyLevel" = "eventual"
        }

        $Skip = $false

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
                    [boolean]$Skip = $true
                }
            }
        } until (($statusCode -eq 200) -or $Skip)

        if (!$partialData)
        {
            Write-Host "PIM Role Active Assignments not found or do not exist" -ForegroundColor Red
        }

        if ($partialData)
        {
            $logsData = $partialData.content | ConvertFrom-Json
        }

        Write-Host ""
        Write-Host "Progress: $($totalLogs += $logsData.value.Count; $totalLogs) entries retrieved so far" -ForegroundColor Cyan

        if ($logsData.PSObject.Properties['@odata.nextLink']) { $uri = $logsData.'@odata.nextLink' }

        $logsData.value | ForEach-Object { $null = $allLogs.Add($_) }

    } until (-not($logsData.PSObject.Properties['@odata.nextLink']))

    # ── Transform raw Graph data into clean structured objects ───────────────
    $result = $allLogs | ForEach-Object {

        $isAssignable = $null
        if ($_.principal.'@odata.type' -eq "#microsoft.graph.group") {
            if ($_.principal.PSObject.Properties['isAssignableToRole']) {
                $isAssignable = $_.principal.isAssignableToRole
            }
        }

        [PSCustomObject]@{
            "Assignment State"             = if ($_.assignmentType) { $_.assignmentType } else { "Eligible" }
            "Assigned Type"                = if ($_.principal.'@odata.type' -eq "#microsoft.graph.user") { "User" } else { $_.principal.'@odata.type' -replace "#microsoft.graph.", "" }
            "Role Name"                    = $_.roleDefinition.displayName
            "User Id"                      = if ($_.principal.'@odata.type' -eq "#microsoft.graph.user") { $_.principal.id } else { $null }
            "User DisplayName"             = if ($_.principal.'@odata.type' -eq "#microsoft.graph.user") { $_.principal.displayName } else { $null }
            "User Mail"                    = if ($_.principal.'@odata.type' -eq "#microsoft.graph.user") { $_.principal.mail } else { $null }
            "User UserPrincipalName"       = if ($_.principal.'@odata.type' -eq "#microsoft.graph.user") { $_.principal.userPrincipalName } else { $null }
            "Group ID"                     = if ($_.principal.'@odata.type' -eq "#microsoft.graph.group") { $_.principal.id } else { $null }
            "Group Name"                   = if ($_.principal.'@odata.type' -eq "#microsoft.graph.group") { $_.principal.displayName } else { $null }
            "isAssignableToRole"           = $isAssignable
            "ServicePrincipal ObjectId"    = if ($_.principal.'@odata.type' -eq "#microsoft.graph.servicePrincipal") { $_.principal.id } else { $null }
            "ServicePrincipal DisplayName" = if ($_.principal.'@odata.type' -eq "#microsoft.graph.servicePrincipal") { $_.principal.displayName } else { $null }
            "ServicePrincipal Enabled"     = if ($_.principal.'@odata.type' -eq "#microsoft.graph.servicePrincipal") { $_.principal.accountEnabled } else { $null }
            "Member Type"                  = $_.memberType
            "Assignment Start Time (UTC)"  = $_.startDateTime
            "Assignment End Time (UTC)"    = if ($_.endDateTime -eq $null) { "Permanent" } else { $_.endDateTime }
        }
    }

    # ══════════════════════════════════════════════════════════════════════════
    #   HTML DASHBOARD GENERATION
    # ══════════════════════════════════════════════════════════════════════════
    if ($GenerateHtmlDoc)
    {
        # ── KPI Calculations ──────────────────────────────────────────────────
        $totalRows      = $result.Count
        $totalUsers     = ($result | Where-Object { $_.'Assigned Type' -eq 'User' }             | Measure-Object).Count
        $totalGroups    = ($result | Where-Object { $_.'Assigned Type' -eq 'group' }            | Measure-Object).Count
        $totalSPs       = ($result | Where-Object { $_.'Assigned Type' -eq 'servicePrincipal' } | Measure-Object).Count
        $permanentCount = ($result | Where-Object { $_.'Assignment End Time (UTC)' -eq 'Permanent' } | Measure-Object).Count
        $timeBoundCount = $totalRows - $permanentCount
        $uniqueRoles    = ($result | Select-Object -ExpandProperty 'Role Name' -Unique | Measure-Object).Count
        $assignedCount  = ($result | Where-Object { $_.'Assignment State' -eq 'Assigned'  } | Measure-Object).Count
        $activatedCount = ($result | Where-Object { $_.'Assignment State' -eq 'Activated' } | Measure-Object).Count

        # ── High-Privilege Role Detection (Risk Insights) ─────────────────────
        $highPrivRoles  = @(
            'Global Administrator','Privileged Role Administrator','Security Administrator',
            'Exchange Administrator','SharePoint Administrator','User Administrator',
            'Application Administrator','Cloud Application Administrator',
            'Privileged Authentication Administrator','Hybrid Identity Administrator'
        )
        $highPrivCount  = ($result | Where-Object { $highPrivRoles -contains $_.'Role Name' } | Measure-Object).Count
        $highPrivPerm   = ($result | Where-Object { $highPrivRoles -contains $_.'Role Name' -and $_.'Assignment End Time (UTC)' -eq 'Permanent' } | Measure-Object).Count

        # ── Security Risk Score (0–100, lower is riskier) ────────────────────
        # Factors: % permanent of total, % high-priv permanent, % non-user principals
        $permRatio      = if ($totalRows -gt 0) { $permanentCount / $totalRows } else { 0 }
        $highPrivRatio  = if ($totalRows -gt 0) { $highPrivPerm / $totalRows } else { 0 }
        $nonUserRatio   = if ($totalRows -gt 0) { ($totalGroups + $totalSPs) / $totalRows } else { 0 }
        $riskScore      = [math]::Round(100 - ($permRatio * 35) - ($highPrivRatio * 40) - ($nonUserRatio * 15) - ($(if($totalRows -gt 50){10} else {0})))
        $riskScore      = [math]::Max(0, [math]::Min(100, $riskScore))
        $riskLabel      = if ($riskScore -ge 80) { "Good" } elseif ($riskScore -ge 60) { "Fair" } elseif ($riskScore -ge 40) { "Needs Review" } else { "High Risk" }
        $riskColor      = if ($riskScore -ge 80) { "#3fb950" } elseif ($riskScore -ge 60) { "#d29922" } elseif ($riskScore -ge 40) { "#e3b341" } else { "#f85149" }

        $todayDate      = Get-Date -Format "dddd, MMMM dd, yyyy hh:mm:ss tt"
        $todayDateShort = Get-Date -Format "yyyy-MM-dd"

        # ── Chart data ────────────────────────────────────────────────────────
        $roleBreakdown   = $result | Group-Object "Role Name" | Sort-Object Count -Descending | Select-Object -First 10
        $roleLabelsJson  = ($roleBreakdown | ForEach-Object { "'$($_.Name -replace "'", "\\'")'" }) -join ","
        $roleCountsJson  = ($roleBreakdown | ForEach-Object { $_.Count }) -join ","

        $stateBreakdown  = $result | Group-Object "Assignment State" | Sort-Object Count -Descending
        $stateLabelsJson = ($stateBreakdown | ForEach-Object { "'$($_.Name)'" }) -join ","
        $stateCountsJson = ($stateBreakdown | ForEach-Object { $_.Count }) -join ","

        $donutData       = "$totalUsers,$totalGroups,$totalSPs"
        $durData         = "$permanentCount,$timeBoundCount"
        $stateData       = "$assignedCount,$activatedCount"

        # ── Helper: HTML-escape ───────────────────────────────────────────────
        function HtmlEncode([string]$s) { $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }

        # ── Helper: build one table row ───────────────────────────────────────
        function Build-TableRow {
            param($item)

            $state      = $item.'Assignment State'
            $stateClass = if ($state -eq 'Activated') { 'badge-activated' } else { 'badge-assigned' }
            $endTime    = $item.'Assignment End Time (UTC)'
            $endClass   = if ($endTime -eq 'Permanent') { 'end-perm' } else { 'end-timebound' }
            $endIcon    = if ($endTime -eq 'Permanent') { '♾️' } else { '⏱️' }
            $startTime  = if ($item.'Assignment Start Time (UTC)') { $item.'Assignment Start Time (UTC)' } else { '—' }
            $roleName   = HtmlEncode $item.'Role Name'
            $isHighPriv = $highPrivRoles -contains $item.'Role Name'
            $privBadge  = if ($isHighPriv) { ' <span class="high-priv-badge" title="High-Privilege Role — this role has significant admin power">⚠ High-Priv</span>' } else { '' }

            switch ($item.'Assigned Type') {
                'User' {
                    $icon      = '👤'
                    $name      = HtmlEncode ($(if ($item.'User DisplayName') { $item.'User DisplayName' } else { '—' }))
                    $sub       = HtmlEncode ($(if ($item.'User UserPrincipalName') { $item.'User UserPrincipalName' } else { '—' }))
                    $typeLabel = 'User'
                    $typeClass = 'pill-user'
                }
                'group' {
                    $icon      = '👥'
                    $name      = HtmlEncode ($(if ($item.'Group Name') { $item.'Group Name' } else { '—' }))
                    $sub       = HtmlEncode ($(if ($item.'Group ID') { $item.'Group ID' } else { '' }))
                    $typeLabel = 'Group'
                    $typeClass = 'pill-group'
                }
                'servicePrincipal' {
                    $icon      = '⚙️'
                    $name      = HtmlEncode ($(if ($item.'ServicePrincipal DisplayName') { $item.'ServicePrincipal DisplayName' } else { '—' }))
                    $sub       = HtmlEncode ($(if ($item.'ServicePrincipal ObjectId') { $item.'ServicePrincipal ObjectId' } else { '' }))
                    $typeLabel = 'App / Bot'
                    $typeClass = 'pill-sp'
                }
                default {
                    $icon      = '❓'
                    $name      = '—'
                    $sub       = ''
                    $typeLabel = HtmlEncode $item.'Assigned Type'
                    $typeClass = 'pill-other'
                }
            }

            return "<tr>
                <td><span class='badge $stateClass'>$state</span></td>
                <td><span class='type-pill $typeClass'>$icon $typeLabel</span></td>
                <td class='role-cell'><strong>$roleName</strong>$privBadge</td>
                <td><span class='principal-name'>$name</span><br><span class='principal-sub'>$sub</span></td>
                <td><span class='member-pill'>$($item.'Member Type')</span></td>
                <td class='time-cell'>$startTime</td>
                <td><span class='$endClass'>$endIcon $endTime</span></td>
            </tr>"
        }

        # ── Build rows per tab ────────────────────────────────────────────────
        $allRowsHtml    = ($result                                                                            | ForEach-Object { Build-TableRow $_ }) -join "`n"
        $userRowsHtml   = ($result | Where-Object { $_.'Assigned Type' -eq 'User' }                          | ForEach-Object { Build-TableRow $_ }) -join "`n"
        $groupRowsHtml  = ($result | Where-Object { $_.'Assigned Type' -eq 'group' }                         | ForEach-Object { Build-TableRow $_ }) -join "`n"
        $spRowsHtml     = ($result | Where-Object { $_.'Assigned Type' -eq 'servicePrincipal' }              | ForEach-Object { Build-TableRow $_ }) -join "`n"

        # ── Risk Insights rows ────────────────────────────────────────────────
        $highPrivRows   = ($result | Where-Object { $highPrivRoles -contains $_.'Role Name' }                | ForEach-Object { Build-TableRow $_ }) -join "`n"
        $permRows       = ($result | Where-Object { $_.'Assignment End Time (UTC)' -eq 'Permanent' }         | ForEach-Object { Build-TableRow $_ }) -join "`n"
        $highPrivPermRows = ($result | Where-Object { $highPrivRoles -contains $_.'Role Name' -and $_.'Assignment End Time (UTC)' -eq 'Permanent' } | ForEach-Object { Build-TableRow $_ }) -join "`n"

        $highPrivTotal  = ($result | Where-Object { $highPrivRoles -contains $_.'Role Name' } | Measure-Object).Count

        # ── JSON export data ──────────────────────────────────────────────────
        $exportJson = $result | ForEach-Object {
            [PSCustomObject]@{
                AssignmentState    = $_.'Assignment State'
                AssignedType       = $_.'Assigned Type'
                RoleName           = $_.'Role Name'
                UserDisplayName    = $_.'User DisplayName'
                UserMail           = $_.'User Mail'
                UserUPN            = $_.'User UserPrincipalName'
                GroupName          = $_.'Group Name'
                SPDisplayName      = $_.'ServicePrincipal DisplayName'
                MemberType         = $_.'Member Type'
                StartTimeUTC       = $_.'Assignment Start Time (UTC)'
                EndTimeUTC         = $_.'Assignment End Time (UTC)'
            }
        } | ConvertTo-Json -Compress

        # Escape for embedding in JS string
        $exportJsonEscaped = $exportJson -replace '\\', '\\\\' -replace "'", "\'" -replace "`r`n", '\n' -replace "`n", '\n'

        # ── CSV export (build header + rows as PS string) ─────────────────────
        $csvLines = @("AssignmentState,AssignedType,RoleName,UserDisplayName,UserMail,UserUPN,GroupName,SPDisplayName,MemberType,StartTimeUTC,EndTimeUTC")
        $result | ForEach-Object {
            $esc = { param($v) '"' + ($v -replace '"', '""') + '"' }
            $csvLines += @(
                (& $esc $_.'Assignment State'),
                (& $esc $_.'Assigned Type'),
                (& $esc $_.'Role Name'),
                (& $esc $_.'User DisplayName'),
                (& $esc $_.'User Mail'),
                (& $esc $_.'User UserPrincipalName'),
                (& $esc $_.'Group Name'),
                (& $esc $_.'ServicePrincipal DisplayName'),
                (& $esc $_.'Member Type'),
                (& $esc $_.'Assignment Start Time (UTC)'),
                (& $esc $_.'Assignment End Time (UTC)')
            ) -join ','
        }
        $csvContent = $csvLines -join "`n"
        $csvEscaped = $csvContent -replace '\\', '\\\\' -replace "'", "\'" -replace "`r`n", '\n' -replace "`n", '\n'

        # ── Pre-compute high-priv role list for JS (cannot use pipelines inside here-string) ──
        $highPrivRolesJs = ($highPrivRoles | ForEach-Object { "'$_'" }) -join ','

        # ── Pre-compute horizontal bar rows for role chart (MyScriptDashboard style) ──
        $maxRoleCount = if ($roleBreakdown) { ($roleBreakdown | Measure-Object -Property Count -Maximum).Maximum } else { 1 }
        $roleBarsHtml = ($roleBreakdown | ForEach-Object {
            $pct = if ($maxRoleCount -gt 0) { [math]::Round($_.Count / $maxRoleCount * 100) } else { 0 }
            $safeName = $_.Name -replace "'","&#39;" -replace '"','&quot;'
            "<div class='bar-row'><span class='bar-label' title='$safeName'>$safeName</span><div class='bar-track'><div class='bar-fill' style='width:0%;background:var(--accent)' data-w='$pct'></div></div><span class='bar-count'>$($_.Count)</span></div>"
        }) -join "`n"

        # ── Gauge dash-offset for risk score SVG ring ──
        $gaugeCirc      = 188.5
        $gaugeDashOffset = [math]::Round($gaugeCirc - ($gaugeCirc * $riskScore / 100), 2)

        # ── Pct helpers for donut legend ──
        $pctUsers  = if ($totalRows -gt 0) { [math]::Round($totalUsers  / $totalRows * 100) } else { 0 }
        $pctGroups = if ($totalRows -gt 0) { [math]::Round($totalGroups / $totalRows * 100) } else { 0 }
        $pctSPs    = if ($totalRows -gt 0) { [math]::Round($totalSPs    / $totalRows * 100) } else { 0 }
        $pctPerm   = if ($totalRows -gt 0) { [math]::Round($permanentCount / $totalRows * 100) } else { 0 }
        $pctTB     = if ($totalRows -gt 0) { [math]::Round($timeBoundCount / $totalRows * 100) } else { 0 }

        # ════════════════════════════════════════════════════════════════════════
        #   FULL HTML CONTENT  —  MyScriptDashboard design language
        # ════════════════════════════════════════════════════════════════════════
        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>PIM Entra ID — $TenantName — Role Active Assignment Report</title>
<style>
/* ═══════════════════════════════════════════════════
   DESIGN: MyScriptDashboard — Calibri / sidebar layout
═══════════════════════════════════════════════════ */
:root {
  --bg:#0d1117; --surface:#161b22; --surface2:#1c2333; --surface3:#243048;
  --border:#30363d; --accent:#388bfd; --accent2:#39c5cf; --accent3:#a371f7;
  --green:#3fb950; --amber:#d29922; --red:#f85149;
  --text:#e6edf3; --muted:#7d8590; --muted2:#adbac7;
  --mono:'Consolas','Courier New',monospace;
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

/* ─── SIDEBAR ─── */
#sidebar{position:fixed;top:0;left:0;bottom:0;width:240px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:38px;height:38px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:9px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text)}
.sidebar-logo .tenant-line{font-size:11px;color:var(--muted);margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:var(--mono)}
.tenant-dot{display:inline-block;width:7px;height:7px;background:var(--green);border-radius:50%;margin-right:5px;animation:blink 2.4s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:14px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:15px;width:22px;text-align:center;flex-shrink:0}
.nav-btn .nav-badge{margin-left:auto;background:var(--surface3);color:var(--muted2);font-family:var(--mono);font-size:11px;padding:1px 7px;border-radius:20px}
.nav-btn:hover{color:var(--text);background:var(--surface2)}
.nav-btn.active{color:var(--accent);background:rgba(56,139,253,.1)}
.nav-btn.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);border-radius:0 2px 2px 0}
.theme-toggle-wrap{padding:10px 14px;border-top:1px solid var(--border)}
.theme-toggle{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;transition:all .2s}
.theme-toggle:hover{border-color:var(--accent);color:var(--text)}
.toggle-pill{width:34px;height:18px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--muted2);transition:transform .2s,background .2s}
body.light-theme .toggle-pill{background:var(--accent)}
body.light-theme .toggle-pill::after{transform:translateX(16px);background:#fff}
.sidebar-footer{padding:10px 18px 14px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);font-family:var(--mono);line-height:1.7}

/* ─── MAIN ─── */
#main{margin-left:240px;min-height:100vh}
.page{display:none;padding:28px 32px 52px;animation:fadeIn .2s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:24px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}

/* ─── BUTTONS ─── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn-primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-primary:hover{filter:brightness(1.1);color:#fff}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

/* ─── SECTION LABEL ─── */
.section-label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:14px;display:flex;align-items:center;gap:10px}
.section-label::after{content:'';flex:1;height:1px;background:var(--border)}

/* ─── STAT / KPI CARDS ─── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(158px,1fr));gap:13px;margin-bottom:22px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s,box-shadow .2s;cursor:default}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent);box-shadow:0 2px 14px rgba(56,139,253,.12)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:28px;font-weight:700;color:var(--text);line-height:1;font-variant-numeric:tabular-nums}
.stat-label{color:var(--muted);font-size:12px;margin-top:5px;font-weight:600}
.stat-sub{color:var(--muted);font-size:11px;margin-top:2px}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}

/* ─── HEALTH / RISK SCORE CARD ─── */
.health-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 22px;display:flex;align-items:center;gap:22px;margin-bottom:22px;flex-wrap:wrap}
.health-ring-wrap{position:relative;width:84px;height:84px;flex-shrink:0}
.health-ring-wrap svg{width:84px;height:84px}
.health-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.health-score-num{font-family:var(--mono);font-size:20px;font-weight:700;line-height:1}
.health-score-pct{font-size:9px;color:var(--muted);font-weight:600}
.health-info{flex:1;min-width:200px}
.health-info h3{font-size:14px;font-weight:700;margin-bottom:4px}
.health-info p{font-size:12px;color:var(--muted2);line-height:1.5}
.health-bar-row{display:flex;align-items:center;gap:8px;margin-top:8px;font-size:12px}
.health-mini-bar{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.health-mini-fill{height:100%;border-radius:3px;transition:width 1s ease}

/* ─── CHARTS / PANELS ─── */
.chart-grid{display:grid;grid-template-columns:3fr 2fr;gap:16px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.section-title{font-size:14px;font-weight:700;margin-bottom:14px;color:var(--text);display:flex;align-items:center;gap:7px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-size:12px;color:var(--muted2);width:160px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:var(--mono)}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:28px;text-align:right;flex-shrink:0}

/* Donut / legend */
.donut-wrap{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.donut-svg{width:150px;height:150px;flex-shrink:0}
.legend-list{flex:1;min-width:120px;display:flex;flex-direction:column;gap:7px}
.legend-item{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted2)}
.legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.legend-pct{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}
.legend-count{font-weight:700;color:var(--text);font-size:13px}

/* ─── EXPLAINER CARDS ─── */
.explainer-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:13px;margin-bottom:22px}
.explainer-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.explainer-icon{font-size:22px;margin-bottom:9px}
.explainer-title{font-size:13px;font-weight:700;color:var(--text);margin-bottom:6px}
.explainer-text{font-size:12px;color:var(--muted);line-height:1.65}
.explainer-text strong{color:var(--muted2)}

/* ─── TABLE CARD ─── */
.table-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:22px}
.table-toolbar{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.toolbar-info-title{font-size:14px;font-weight:700;color:var(--text)}
.toolbar-info-sub{font-size:11px;color:var(--muted);margin-top:2px}
.toolbar-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.search-wrap{position:relative}
.search-icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);font-size:13px;color:var(--muted);pointer-events:none}
.search-box{padding:8px 12px 8px 34px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:13px;font-family:var(--sans);width:230px;outline:none;transition:border-color .2s,width .2s}
.search-box:focus{border-color:var(--accent);width:270px}
.search-box::placeholder{color:var(--muted)}

/* TABLE */
.table-scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px}
thead tr{background:var(--surface2);border-bottom:1px solid var(--border)}
th{padding:10px 14px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);white-space:nowrap;cursor:pointer;user-select:none;transition:color .2s}
th:hover{color:var(--text)}
th.sorted{color:var(--accent)}
tbody tr{border-bottom:1px solid var(--border);transition:background .15s}
tbody tr:nth-child(even){background:rgba(255,255,255,0.02)}
body.light-theme tbody tr:nth-child(even){background:rgba(0,0,0,0.025)}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface2) !important}
td{padding:8px 14px;vertical-align:middle;color:var(--muted2)}
.role-cell strong{color:var(--text);font-size:13px}
.time-cell{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}

/* BADGES & PILLS */
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.6px;white-space:nowrap}
.badge-assigned{background:rgba(56,139,253,.12);color:var(--accent);border:1px solid rgba(56,139,253,.25)}
.badge-activated{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.25)}
.type-pill{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:var(--radius-sm);font-size:11px;font-weight:600;white-space:nowrap;border:1px solid transparent}
.pill-user{background:rgba(56,139,253,.10);color:var(--accent);border-color:rgba(56,139,253,.2)}
.pill-group{background:rgba(163,113,247,.10);color:var(--accent3);border-color:rgba(163,113,247,.2)}
.pill-sp{background:rgba(210,153,34,.10);color:var(--amber);border-color:rgba(210,153,34,.2)}
.pill-other{background:var(--surface3);color:var(--muted)}
.member-pill{display:inline-block;padding:1px 8px;border-radius:4px;font-size:10px;font-weight:600;background:var(--surface3);color:var(--muted);border:1px solid var(--border)}
.principal-name{font-weight:600;color:var(--text);font-size:13px;display:block}
.principal-sub{font-size:11px;color:var(--muted);display:block;margin-top:1px;word-break:break-all;font-family:var(--mono)}
.end-perm{color:var(--amber);font-weight:700;font-size:12px;white-space:nowrap}
.end-timebound{color:var(--green);font-size:12px;white-space:nowrap}
.high-priv-badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:9px;font-weight:700;text-transform:uppercase;background:rgba(248,81,73,.12);color:var(--red);border:1px solid rgba(248,81,73,.25);margin-left:6px;vertical-align:middle;cursor:help}

/* ─── PAGINATION ─── */
.table-footer{padding:12px 18px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;background:var(--surface)}
.page-info{font-size:12px;color:var(--muted)}
.pagination{display:flex;gap:4px;flex-wrap:wrap}
.page-btn{min-width:30px;padding:4px 9px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface2);color:var(--muted2);font-size:12px;font-family:var(--mono);cursor:pointer;transition:all .18s;line-height:1.4}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.page-btn.ellipsis{cursor:default;border:none;background:none;color:var(--muted)}

/* ─── RISK INSIGHTS ─── */
.risk-alert-bar{border-radius:var(--radius-sm);padding:14px 18px;margin-bottom:12px;display:flex;align-items:flex-start;gap:14px;border:1px solid}
.risk-alert-bar.danger{background:rgba(248,81,73,.07);border-color:rgba(248,81,73,.25)}
.risk-alert-bar.warning{background:rgba(210,153,34,.07);border-color:rgba(210,153,34,.25)}
.risk-alert-bar.info{background:rgba(56,139,253,.07);border-color:rgba(56,139,253,.25)}
.risk-alert-icon{font-size:20px;flex-shrink:0;margin-top:1px}
.risk-alert-title{font-size:13px;font-weight:700;color:var(--text);margin-bottom:3px}
.risk-alert-desc{font-size:12px;color:var(--muted);line-height:1.6}
.risk-alert-count{font-size:24px;font-weight:800;flex-shrink:0;align-self:center;min-width:44px;text-align:right;font-family:var(--mono)}

/* ─── EXPORT ─── */
.export-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:16px;margin-bottom:22px}
.export-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:22px}
.export-card-icon{font-size:26px;margin-bottom:10px}
.export-card-title{font-size:15px;font-weight:700;color:var(--text);margin-bottom:6px}
.export-card-desc{font-size:12px;color:var(--muted);line-height:1.65;margin-bottom:16px}

/* ─── EMPTY STATE ─── */
.empty-state{text-align:center;padding:44px 20px;color:var(--muted)}
.empty-state .empty-icon{font-size:34px;margin-bottom:10px}
.empty-state p{font-size:13px}

/* ─── TOAST ─── */
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:11px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}

/* ─── SCROLLBAR ─── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

/* ─── RESPONSIVE ─── */
@media(max-width:768px){#sidebar{transform:translateX(-240px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px 16px}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text);font-size:16px}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<!-- ══════════════════════════════════════════════════
     SIDEBAR
══════════════════════════════════════════════════ -->
<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🛡️</div>
    <h1>PIM Role Assignments</h1>
    <div class="tenant-line"><span class="tenant-dot"></span>$TenantName</div>
    <div class="tenant-line" style="color:var(--muted);font-size:10px;margin-top:1px">$TenantId</div>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">📊</span> Overview
    </button>
    <button class="nav-btn" onclick="showPage('all',this)">
      <span class="nav-icon">📋</span> All Assignments
      <span class="nav-badge">$totalRows</span>
    </button>
    <button class="nav-btn" onclick="showPage('users',this)">
      <span class="nav-icon">👤</span> Users
      <span class="nav-badge">$totalUsers</span>
    </button>
    <button class="nav-btn" onclick="showPage('groups',this)">
      <span class="nav-icon">👥</span> Groups
      <span class="nav-badge">$totalGroups</span>
    </button>
    <button class="nav-btn" onclick="showPage('sps',this)">
      <span class="nav-icon">⚙️</span> Apps &amp; Bots
      <span class="nav-badge">$totalSPs</span>
    </button>
    <button class="nav-btn" onclick="showPage('risk',this)">
      <span class="nav-icon">🔴</span> Risk Insights
      <span class="nav-badge">$highPrivTotal</span>
    </button>
    <button class="nav-btn" onclick="showPage('export',this)">
      <span class="nav-icon">⬇️</span> Export
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
    Generated<br>$todayDate<br>
    <span style="color:var(--accent2)">⌨</span> <kbd style="display:inline-block;padding:1px 5px;background:var(--surface3);border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:10px">/</kbd> focus search
  </div>
</nav>

<main id="main">

<!-- ══════════════════════════════════════════════════
     PAGE: OVERVIEW
══════════════════════════════════════════════════ -->
<section class="page active" id="page-overview">
  <div class="page-header">
    <div>
      <div class="page-title">PIM Role Assignments — Overview</div>
      <div class="page-subtitle">Privileged Identity Management · Microsoft Entra ID · $TenantName</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV()">⬇ Export CSV</button>
      <button class="btn" onclick="exportJSON()">⬇ Export JSON</button>
    </div>
  </div>

  <!-- Explainer cards -->
  <div class="section-label">💡 What does this report tell you?</div>
  <div class="explainer-grid">
    <div class="explainer-card">
      <div class="explainer-icon">🔑</div>
      <div class="explainer-title">What is a Role Assignment?</div>
      <div class="explainer-text">A <strong>role assignment</strong> means someone (or an app) has been given a specific set of admin permissions in your Microsoft 365 and Azure environment. Think of it like handing someone a keycard — they can open certain doors.</div>
    </div>
    <div class="explainer-card">
      <div class="explainer-icon">♾️</div>
      <div class="explainer-title">Permanent vs Time-Bound</div>
      <div class="explainer-text"><strong>Permanent</strong> access never expires — the person keeps admin rights indefinitely. <strong>Time-bound</strong> access automatically expires on a set date, which is safer and follows the principle of least privilege.</div>
    </div>
    <div class="explainer-card">
      <div class="explainer-icon">⚡</div>
      <div class="explainer-title">Assigned vs Activated</div>
      <div class="explainer-text"><strong>Assigned</strong> means the access was given directly. <strong>Activated</strong> means the person used PIM to temporarily activate an eligible role — the recommended, safer way to grant on-demand admin access.</div>
    </div>
    <div class="explainer-card">
      <div class="explainer-icon">⚠️</div>
      <div class="explainer-title">Why Review This Regularly?</div>
      <div class="explainer-text">Admin accounts are the highest-value targets for attackers. Reviewing who has admin access — and removing unnecessary or permanent rights — significantly reduces your organisation's security risk.</div>
    </div>
  </div>

  <!-- KPI cards -->
  <div class="section-label">📊 At a Glance — Key Numbers</div>
  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">🔑</div><div class="stat-value">$totalRows</div><div class="stat-label">Total Assignments</div><div class="stat-sub">Active admin roles right now</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">🎭</div><div class="stat-value">$uniqueRoles</div><div class="stat-label">Unique Roles</div><div class="stat-sub">Different admin role types</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">👤</div><div class="stat-value">$totalUsers</div><div class="stat-label">People</div><div class="stat-sub">Individuals with admin access</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">👥</div><div class="stat-value">$totalGroups</div><div class="stat-label">Groups</div><div class="stat-sub">Teams sharing admin access</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">⚙️</div><div class="stat-value">$totalSPs</div><div class="stat-label">Apps &amp; Bots</div><div class="stat-sub">Automated systems with access</div></div>
    <div class="stat-card c-red"><div class="stat-icon">♾️</div><div class="stat-value">$permanentCount</div><div class="stat-label">Permanent Access</div><div class="stat-sub">Never expires automatically</div></div>
    <div class="stat-card c-green"><div class="stat-icon">⏱️</div><div class="stat-value">$timeBoundCount</div><div class="stat-label">Time-Bound Access</div><div class="stat-sub">Has an automatic end date</div></div>
    <div class="stat-card c-red"><div class="stat-icon">🚨</div><div class="stat-value">$highPrivCount</div><div class="stat-label">High-Privilege Roles</div><div class="stat-sub">Most powerful permissions</div></div>
  </div>

  <!-- Security Risk / Health Score -->
  <div class="section-label">🛡️ Security Health Score</div>
  <div class="health-card">
    <div class="health-ring-wrap">
      <svg viewBox="0 0 84 84">
        <circle cx="42" cy="42" r="34" fill="none" stroke="var(--surface3)" stroke-width="9"/>
        <circle cx="42" cy="42" r="34" fill="none" stroke="$riskColor" stroke-width="9"
          stroke-dasharray="213.6" stroke-dashoffset="$([math]::Round(213.6 - (213.6 * $riskScore / 100), 2))"
          stroke-linecap="round" transform="rotate(-90 42 42)" id="healthArc" style="transition:stroke-dashoffset 1.2s ease"/>
      </svg>
      <div class="health-ring-center">
        <span class="health-score-num" style="color:$riskColor">$riskScore</span>
        <span class="health-score-pct">/ 100</span>
      </div>
    </div>
    <div class="health-info">
      <h3>Security Health: <span style="color:$riskColor">$riskLabel</span></h3>
      <p>Reflects how well your tenant follows the <strong>least-privilege principle</strong> — giving people only the access they need, for only as long as they need it. A higher score means lower risk.</p>
      <div class="health-bar-row">
        <span style="color:var(--red);font-size:12px;width:180px;flex-shrink:0">♾️ Permanent assignments</span>
        <div class="health-mini-bar"><div class="health-mini-fill" style="background:var(--red);width:$(if($totalRows -gt 0){[math]::Round($permanentCount/$totalRows*100)}else{0})%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">$permanentCount / $totalRows</span>
      </div>
      <div class="health-bar-row">
        <span style="color:var(--amber);font-size:12px;width:180px;flex-shrink:0">⚠️ High-priv permanent</span>
        <div class="health-mini-bar"><div class="health-mini-fill" style="background:var(--amber);width:$(if($totalRows -gt 0){[math]::Round($highPrivPerm/$totalRows*100)}else{0})%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">$highPrivPerm / $totalRows</span>
      </div>
      <div class="health-bar-row">
        <span style="color:var(--accent3);font-size:12px;width:180px;flex-shrink:0">🤖 Non-personal accounts</span>
        <div class="health-mini-bar"><div class="health-mini-fill" style="background:var(--accent3);width:$(if($totalRows -gt 0){[math]::Round(($totalGroups+$totalSPs)/$totalRows*100)}else{0})%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">$($totalGroups+$totalSPs) / $totalRows</span>
      </div>
    </div>
  </div>

  <!-- Charts -->
  <div class="section-label">📈 Visual Breakdown</div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Top Admin Roles by Assignment Count</div>
      <div id="roleBarsContainer">$roleBarsHtml</div>
    </div>
    <div class="panel">
      <div class="section-title">🍩 Who Has Admin Access?</div>
      <div class="donut-wrap">
        <svg class="donut-svg" id="donutSvg" viewBox="0 0 150 150"></svg>
        <div class="legend-list">
          <div class="legend-item"><span class="legend-dot" style="background:var(--accent)"></span>People<span class="legend-count" style="margin-left:auto">$totalUsers</span><span class="legend-pct">($pctUsers%)</span></div>
          <div class="legend-item"><span class="legend-dot" style="background:var(--accent3)"></span>Groups<span class="legend-count" style="margin-left:auto">$totalGroups</span><span class="legend-pct">($pctGroups%)</span></div>
          <div class="legend-item"><span class="legend-dot" style="background:var(--amber)"></span>Apps &amp; Bots<span class="legend-count" style="margin-left:auto">$totalSPs</span><span class="legend-pct">($pctSPs%)</span></div>
          <div class="legend-item" style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border)"><span class="legend-dot" style="background:var(--red)"></span>Permanent<span class="legend-count" style="margin-left:auto">$permanentCount</span><span class="legend-pct">($pctPerm%)</span></div>
          <div class="legend-item"><span class="legend-dot" style="background:var(--green)"></span>Time-Bound<span class="legend-count" style="margin-left:auto">$timeBoundCount</span><span class="legend-pct">($pctTB%)</span></div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ══════════════════════════════════════════════════
     PAGE: ALL ASSIGNMENTS
══════════════════════════════════════════════════ -->
<section class="page" id="page-all">
  <div class="page-header">
    <div><div class="page-title">All Active Role Assignments</div><div class="page-subtitle">Every admin access entry currently active in your tenant. Click column headers to sort.</div></div>
  </div>
  <div class="table-card">
    <div class="table-toolbar">
      <div><div class="toolbar-info-title">All Assignments</div><div class="toolbar-info-sub">$totalRows total entries</div></div>
      <div class="toolbar-right">
        <div class="search-wrap"><span class="search-icon">🔍</span><input class="search-box" type="text" id="search-all" placeholder="Search name, role, email…" oninput="filterTable('all')"/></div>
      </div>
    </div>
    <div class="table-scroll">
      <table id="tbl-all">
        <thead><tr>
          <th onclick="sortTbl('all',0,this)">Status</th>
          <th onclick="sortTbl('all',1,this)">Account Type</th>
          <th onclick="sortTbl('all',2,this)">Admin Role</th>
          <th onclick="sortTbl('all',3,this)">Person / Group / App</th>
          <th onclick="sortTbl('all',4,this)">Member Type</th>
          <th onclick="sortTbl('all',5,this)">Access Started (UTC)</th>
          <th onclick="sortTbl('all',6,this)">Access Expires</th>
        </tr></thead>
        <tbody id="tbody-all">$allRowsHtml</tbody>
      </table>
    </div>
    <div class="table-footer"><span class="page-info" id="info-all"></span><div class="pagination" id="pag-all"></div></div>
  </div>
</section>

<!-- USERS -->
<section class="page" id="page-users">
  <div class="page-header">
    <div><div class="page-title">👤 People with Admin Access</div><div class="page-subtitle">Individual user accounts assigned admin roles in your organisation.</div></div>
  </div>
  <div class="table-card">
    <div class="table-toolbar">
      <div><div class="toolbar-info-title">User Assignments</div><div class="toolbar-info-sub">$totalUsers entries</div></div>
      <div class="toolbar-right">
        <div class="search-wrap"><span class="search-icon">🔍</span><input class="search-box" type="text" id="search-users" placeholder="Search name, email, role…" oninput="filterTable('users')"/></div>
      </div>
    </div>
    <div class="table-scroll">
      <table id="tbl-users">
        <thead><tr>
          <th onclick="sortTbl('users',0,this)">Status</th>
          <th onclick="sortTbl('users',1,this)">Account Type</th>
          <th onclick="sortTbl('users',2,this)">Admin Role</th>
          <th onclick="sortTbl('users',3,this)">Person / Group / App</th>
          <th onclick="sortTbl('users',4,this)">Member Type</th>
          <th onclick="sortTbl('users',5,this)">Access Started (UTC)</th>
          <th onclick="sortTbl('users',6,this)">Access Expires</th>
        </tr></thead>
        <tbody id="tbody-users">$userRowsHtml</tbody>
      </table>
    </div>
    <div class="table-footer"><span class="page-info" id="info-users"></span><div class="pagination" id="pag-users"></div></div>
  </div>
</section>

<!-- GROUPS -->
<section class="page" id="page-groups">
  <div class="page-header">
    <div><div class="page-title">👥 Groups with Admin Access</div><div class="page-subtitle">Security groups assigned admin roles. Every member inherits the permission.</div></div>
  </div>
  <div class="table-card">
    <div class="table-toolbar">
      <div><div class="toolbar-info-title">Group Assignments</div><div class="toolbar-info-sub">$totalGroups entries</div></div>
      <div class="toolbar-right">
        <div class="search-wrap"><span class="search-icon">🔍</span><input class="search-box" type="text" id="search-groups" placeholder="Search group name or role…" oninput="filterTable('groups')"/></div>
      </div>
    </div>
    <div class="table-scroll">
      <table id="tbl-groups">
        <thead><tr>
          <th onclick="sortTbl('groups',0,this)">Status</th>
          <th onclick="sortTbl('groups',1,this)">Account Type</th>
          <th onclick="sortTbl('groups',2,this)">Admin Role</th>
          <th onclick="sortTbl('groups',3,this)">Person / Group / App</th>
          <th onclick="sortTbl('groups',4,this)">Member Type</th>
          <th onclick="sortTbl('groups',5,this)">Access Started (UTC)</th>
          <th onclick="sortTbl('groups',6,this)">Access Expires</th>
        </tr></thead>
        <tbody id="tbody-groups">$groupRowsHtml</tbody>
      </table>
    </div>
    <div class="table-footer"><span class="page-info" id="info-groups"></span><div class="pagination" id="pag-groups"></div></div>
  </div>
</section>

<!-- SERVICE PRINCIPALS -->
<section class="page" id="page-sps">
  <div class="page-header">
    <div><div class="page-title">⚙️ Apps &amp; Bots with Admin Access</div><div class="page-subtitle">Automated applications and service accounts with admin roles. Review carefully.</div></div>
  </div>
  <div class="table-card">
    <div class="table-toolbar">
      <div><div class="toolbar-info-title">App / Service Principal Assignments</div><div class="toolbar-info-sub">$totalSPs entries</div></div>
      <div class="toolbar-right">
        <div class="search-wrap"><span class="search-icon">🔍</span><input class="search-box" type="text" id="search-sps" placeholder="Search app name or role…" oninput="filterTable('sps')"/></div>
      </div>
    </div>
    <div class="table-scroll">
      <table id="tbl-sps">
        <thead><tr>
          <th onclick="sortTbl('sps',0,this)">Status</th>
          <th onclick="sortTbl('sps',1,this)">Account Type</th>
          <th onclick="sortTbl('sps',2,this)">Admin Role</th>
          <th onclick="sortTbl('sps',3,this)">Person / Group / App</th>
          <th onclick="sortTbl('sps',4,this)">Member Type</th>
          <th onclick="sortTbl('sps',5,this)">Access Started (UTC)</th>
          <th onclick="sortTbl('sps',6,this)">Access Expires</th>
        </tr></thead>
        <tbody id="tbody-sps">$spRowsHtml</tbody>
      </table>
    </div>
    <div class="table-footer"><span class="page-info" id="info-sps"></span><div class="pagination" id="pag-sps"></div></div>
  </div>
</section>

<!-- ══════════════════════════════════════════════════
     PAGE: RISK INSIGHTS
══════════════════════════════════════════════════ -->
<section class="page" id="page-risk">
  <div class="page-header">
    <div><div class="page-title">🔴 Risk Insights</div><div class="page-subtitle">Security alerts and high-risk role assignments that need your attention.</div></div>
  </div>

  <div class="section-label">🔴 Security Alerts</div>

  <div class="risk-alert-bar danger">
    <div class="risk-alert-icon">🔥</div>
    <div style="flex:1">
      <div class="risk-alert-title">High-Privilege Roles with Permanent Access — Highest Risk</div>
      <div class="risk-alert-desc">The most powerful admin roles (e.g. Global Administrator, Security Administrator) that <strong>never expire</strong>. Best practice is to convert these to time-bound or eligible-only assignments.</div>
    </div>
    <div class="risk-alert-count" style="color:var(--red)">$highPrivPerm</div>
  </div>

  <div class="risk-alert-bar warning">
    <div class="risk-alert-icon">⚠️</div>
    <div style="flex:1">
      <div class="risk-alert-title">All High-Privilege Role Assignments</div>
      <div class="risk-alert-desc">Total count of assignments to highly sensitive roles regardless of expiry. Roles include: Global Administrator, Security Administrator, Exchange Administrator, Privileged Role Administrator, and others. Each should be individually reviewed and justified.</div>
    </div>
    <div class="risk-alert-count" style="color:var(--amber)">$highPrivCount</div>
  </div>

  <div class="risk-alert-bar info">
    <div class="risk-alert-icon">♾️</div>
    <div style="flex:1">
      <div class="risk-alert-title">All Permanent Assignments (Any Role)</div>
      <div class="risk-alert-desc">These assignments across all roles never expire automatically. Microsoft recommends converting permanent assignments to <strong>eligible</strong> PIM assignments wherever possible, so access is only activated when genuinely needed.</div>
    </div>
    <div class="risk-alert-count" style="color:var(--accent)">$permanentCount</div>
  </div>

  <div class="section-label" style="margin-top:22px">🔥 High-Privilege + Permanent — Details</div>
  <div class="table-card">
    <div class="table-toolbar">
      <div><div class="toolbar-info-title">Critical: High-Privilege Roles that Never Expire</div><div class="toolbar-info-sub">$highPrivPerm entries — highest security risk, review immediately.</div></div>
      <div class="toolbar-right">
        <div class="search-wrap"><span class="search-icon">🔍</span><input class="search-box" type="text" id="search-riskperm" placeholder="Search…" oninput="filterTable('riskperm')"/></div>
      </div>
    </div>
    <div class="table-scroll">
      <table id="tbl-riskperm">
        <thead><tr>
          <th onclick="sortTbl('riskperm',0,this)">Status</th>
          <th onclick="sortTbl('riskperm',1,this)">Account Type</th>
          <th onclick="sortTbl('riskperm',2,this)">Admin Role</th>
          <th onclick="sortTbl('riskperm',3,this)">Person / Group / App</th>
          <th onclick="sortTbl('riskperm',4,this)">Member Type</th>
          <th onclick="sortTbl('riskperm',5,this)">Access Started (UTC)</th>
          <th onclick="sortTbl('riskperm',6,this)">Access Expires</th>
        </tr></thead>
        <tbody id="tbody-riskperm">$(if($highPrivPermRows){''+$highPrivPermRows}else{'<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">✅</div><p>No high-privilege permanent assignments found — great work!</p></div></td></tr>'})</tbody>
      </table>
    </div>
    <div class="table-footer"><span class="page-info" id="info-riskperm"></span><div class="pagination" id="pag-riskperm"></div></div>
  </div>

  <div class="section-label">⚠️ All High-Privilege Assignments</div>
  <div class="table-card">
    <div class="table-toolbar">
      <div><div class="toolbar-info-title">All High-Privilege Role Assignments</div><div class="toolbar-info-sub">Includes both permanent and time-bound — $highPrivTotal total entries.</div></div>
      <div class="toolbar-right">
        <div class="search-wrap"><span class="search-icon">🔍</span><input class="search-box" type="text" id="search-riskhigh" placeholder="Search…" oninput="filterTable('riskhigh')"/></div>
      </div>
    </div>
    <div class="table-scroll">
      <table id="tbl-riskhigh">
        <thead><tr>
          <th onclick="sortTbl('riskhigh',0,this)">Status</th>
          <th onclick="sortTbl('riskhigh',1,this)">Account Type</th>
          <th onclick="sortTbl('riskhigh',2,this)">Admin Role</th>
          <th onclick="sortTbl('riskhigh',3,this)">Person / Group / App</th>
          <th onclick="sortTbl('riskhigh',4,this)">Member Type</th>
          <th onclick="sortTbl('riskhigh',5,this)">Access Started (UTC)</th>
          <th onclick="sortTbl('riskhigh',6,this)">Access Expires</th>
        </tr></thead>
        <tbody id="tbody-riskhigh">$(if($highPrivRows){''+$highPrivRows}else{'<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">✅</div><p>No high-privilege role assignments found.</p></div></td></tr>'})</tbody>
      </table>
    </div>
    <div class="table-footer"><span class="page-info" id="info-riskhigh"></span><div class="pagination" id="pag-riskhigh"></div></div>
  </div>
</section>

<!-- ══════════════════════════════════════════════════
     PAGE: EXPORT
══════════════════════════════════════════════════ -->
<section class="page" id="page-export">
  <div class="page-header">
    <div><div class="page-title">⬇️ Export Data</div><div class="page-subtitle">Download role assignment data in your preferred format.</div></div>
  </div>

  <div class="section-label">📦 Download Options</div>
  <div class="export-grid">
    <div class="export-card">
      <div class="export-card-icon">📄</div>
      <div class="export-card-title">Export as CSV</div>
      <div class="export-card-desc">Downloads all $totalRows role assignments as a <strong>comma-separated values (.csv)</strong> file. Ideal for opening in <strong>Microsoft Excel</strong> or importing into other tools.</div>
      <button class="btn btn-primary" onclick="exportCSV()">⬇ Download CSV</button>
    </div>
    <div class="export-card">
      <div class="export-card-icon">🗄️</div>
      <div class="export-card-title">Export as JSON</div>
      <div class="export-card-desc">Downloads all $totalRows assignments as a <strong>structured JSON (.json)</strong> file. Best for developers, automation scripts, or ingesting into SIEM or monitoring tools like Microsoft Sentinel.</div>
      <button class="btn btn-primary" onclick="exportJSON()">⬇ Download JSON</button>
    </div>
    <div class="export-card">
      <div class="export-card-icon">🚨</div>
      <div class="export-card-title">Export Risk Insights (CSV)</div>
      <div class="export-card-desc">Downloads only the <strong>$highPrivCount high-privilege role assignments</strong> as a CSV. Useful for sharing with your security team or management for immediate review.</div>
      <button class="btn" onclick="exportHighPrivCSV()">⬇ Download Risk CSV</button>
    </div>
    <div class="export-card">
      <div class="export-card-icon">🖨️</div>
      <div class="export-card-title">Print / Save as PDF</div>
      <div class="export-card-desc">Use your browser's built-in print function to <strong>save this dashboard as a PDF</strong>. Great for audit records, management reports, or offline sharing. Choose "Save as PDF" in the print dialog.</div>
      <button class="btn" onclick="window.print()">🖨️ Print / Save PDF</button>
    </div>
  </div>

  <div class="section-label">📋 Report Summary</div>
  <div class="panel">
    <table style="width:auto;font-size:13px;border-collapse:collapse">
      <tr><td style="padding:7px 24px 7px 0;color:var(--muted);font-weight:600">Tenant Name</td><td style="padding:7px 0;color:var(--text);font-weight:700">$TenantName</td></tr>
      <tr><td style="padding:7px 24px 7px 0;color:var(--muted);font-weight:600">Tenant ID</td><td style="padding:7px 0;color:var(--text);font-family:var(--mono);font-size:12px">$TenantId</td></tr>
      <tr><td style="padding:7px 24px 7px 0;color:var(--muted);font-weight:600">Report Generated</td><td style="padding:7px 0;color:var(--text)">$todayDate</td></tr>
      <tr><td style="padding:7px 24px 7px 0;color:var(--muted);font-weight:600">Total Assignments</td><td style="padding:7px 0;color:var(--text);font-weight:700">$totalRows</td></tr>
      <tr><td style="padding:7px 24px 7px 0;color:var(--muted);font-weight:600">Security Health Score</td><td style="padding:7px 0;font-weight:700;color:$riskColor">$riskScore / 100 — $riskLabel</td></tr>
      <tr><td style="padding:7px 24px 7px 0;color:var(--muted);font-weight:600">Data Source</td><td style="padding:7px 0;color:var(--text)">Microsoft Graph API (Beta) — roleAssignmentScheduleInstances</td></tr>
    </table>
  </div>
</section>

</main><!-- /main -->

<!-- TOAST -->
<div id="toast"></div>

<!-- ══════════════════════════════════════════════════
     SCRIPTS
══════════════════════════════════════════════════ -->
<script>
/* ── Theme ── */
function toggleTheme(){
  const light=document.body.classList.toggle('light-theme');
  document.getElementById('themeIcon').textContent=light?'☀️':'🌙';
  document.getElementById('themeLabel').textContent=light?'Light Mode':'Dark Mode';
  buildDonut();
}

/* ── Page navigation ── */
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
}

/* ── Horizontal bar chart animation ── */
function animateBars(){
  document.querySelectorAll('#roleBarsContainer .bar-fill').forEach(el=>{
    const w=el.getAttribute('data-w');
    if(w)setTimeout(()=>{el.style.width=w+'%'},100);
  });
}

/* ── SVG Donut chart ── */
function buildDonut(){
  const svg=document.getElementById('donutSvg');
  if(!svg)return;
  const total=$totalRows;
  if(total===0){svg.innerHTML='';return;}
  const vals=[$totalUsers,$totalGroups,$totalSPs];
  const colors=['var(--accent)','var(--accent3)','var(--amber)'];
  const cx=75,cy=75,r=55,stroke=22;
  const circ=2*Math.PI*r;
  let offset=0;
  svg.innerHTML='';
  // background
  const bg=document.createElementNS('http://www.w3.org/2000/svg','circle');
  bg.setAttribute('cx',cx);bg.setAttribute('cy',cy);bg.setAttribute('r',r);
  bg.setAttribute('fill','none');bg.setAttribute('stroke','var(--surface3)');bg.setAttribute('stroke-width',stroke);
  svg.appendChild(bg);
  vals.forEach((v,i)=>{
    if(v===0)return;
    const pct=v/total;
    const dash=pct*circ;
    const gap=circ-dash;
    const c=document.createElementNS('http://www.w3.org/2000/svg','circle');
    c.setAttribute('cx',cx);c.setAttribute('cy',cy);c.setAttribute('r',r);
    c.setAttribute('fill','none');c.setAttribute('stroke',colors[i]);c.setAttribute('stroke-width',stroke);
    c.setAttribute('stroke-dasharray',dash+' '+gap);
    c.setAttribute('stroke-dashoffset',-offset*circ);
    c.setAttribute('transform','rotate(-90 '+cx+' '+cy+')');
    svg.appendChild(c);
    offset+=pct;
  });
}

/* ── Sort ── */
const sortState={};
function sortTbl(tab,col,thEl){
  const tbody=document.getElementById('tbody-'+tab);
  const key=tab+'-'+col;
  sortState[key]=!sortState[key];
  const asc=sortState[key];
  const rows=Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a,b)=>{
    const x=(a.cells[col]?.textContent||'').trim().toLowerCase();
    const y=(b.cells[col]?.textContent||'').trim().toLowerCase();
    return asc?x.localeCompare(y,undefined,{numeric:true}):y.localeCompare(x,undefined,{numeric:true});
  });
  rows.forEach(r=>tbody.appendChild(r));
  document.querySelectorAll('#tbl-'+tab+' th').forEach(t=>t.classList.remove('sorted'));
  thEl.classList.add('sorted');
  pagState[tab].page=1;
  renderPag(tab);
}

/* ── Search / Filter ── */
function filterTable(tab){
  const q=(document.getElementById('search-'+tab)||{}).value||'';
  const ql=q.toLowerCase().trim();
  const rows=Array.from(document.querySelectorAll('#tbody-'+tab+' tr'));
  // Use data-search-hidden attribute (not style.display) to mark filtered-out rows,
  // so renderPag can still enumerate all search-matched rows across all pages
  rows.forEach(r=>{
    if(!ql||r.textContent.toLowerCase().includes(ql)){
      r.removeAttribute('data-search-hidden');
    } else {
      r.setAttribute('data-search-hidden','1');
      r.style.display='none';
    }
  });
  pagState[tab].page=1;
  renderPag(tab);
}

/* ── Pagination ── */
const PAGE_SIZE=15;
const pagState={all:{page:1},users:{page:1},groups:{page:1},sps:{page:1},riskperm:{page:1},riskhigh:{page:1}};
// Returns all rows not hidden by search — including those hidden by a prior renderPag call
function getVisible(tab){return Array.from(document.querySelectorAll('#tbody-'+tab+' tr')).filter(r=>!r.getAttribute('data-search-hidden'));}
function renderPag(tab){
  const rows=getVisible(tab);
  const total=rows.length;
  const pages=Math.max(1,Math.ceil(total/PAGE_SIZE));
  const cur=Math.min(pagState[tab].page,pages);
  pagState[tab].page=cur;
  // Show only current-page rows; hide the rest (pagination-level hiding only)
  rows.forEach((r,i)=>{r.style.display=(i>=(cur-1)*PAGE_SIZE&&i<cur*PAGE_SIZE)?'':'none';});
  const infoEl=document.getElementById('info-'+tab);
  const pagEl=document.getElementById('pag-'+tab);
  if(!infoEl)return;
  if(total===0){infoEl.textContent='No matching results';pagEl.innerHTML='';return;}
  const from=(cur-1)*PAGE_SIZE+1,to=Math.min(cur*PAGE_SIZE,total);
  infoEl.textContent='Showing '+from+'–'+to+' of '+total+' entries';
  let html='';
  html+='<button class="page-btn'+(cur===1?' active':'')+'" onclick="goPage(\''+tab+'\',1)">«</button>';
  for(let p=1;p<=pages;p++){
    if(pages>8&&Math.abs(p-cur)>2&&p!==1&&p!==pages){if(p===2||p===pages-1)html+='<button class="page-btn ellipsis" disabled>…</button>';continue;}
    html+='<button class="page-btn'+(p===cur?' active':'')+'" onclick="goPage(\''+tab+'\','+p+')">'+p+'</button>';
  }
  html+='<button class="page-btn'+(cur===pages?' active':'')+'" onclick="goPage(\''+tab+'\','+pages+')">»</button>';
  pagEl.innerHTML=html;
}
function goPage(tab,p){pagState[tab].page=p;renderPag(tab);}

/* ── Export ── */
const CSV_DATA='$csvEscaped';
const JSON_DATA='$exportJsonEscaped';
function dlFile(content,name,type){
  const b=new Blob([content],{type});
  const u=URL.createObjectURL(b);
  const a=document.createElement('a');
  a.href=u;a.download=name;a.click();
  URL.revokeObjectURL(u);
}
function exportCSV(){
  dlFile(CSV_DATA,'PIM_RoleAssignments_${TenantName}_$todayDateShort.csv','text/csv');
  showToast('✅ Exported $totalRows assignments as CSV');
}
function exportJSON(){
  dlFile(JSON_DATA,'PIM_RoleAssignments_${TenantName}_$todayDateShort.json','application/json');
  showToast('✅ Exported $totalRows assignments as JSON');
}
function exportHighPrivCSV(){
  const lines=CSV_DATA.split('\n');
  const header=lines[0];
  const filtered=lines.slice(1).filter(l=>{
    const cols=l.split(',');
    if(cols.length<3)return false;
    const role=cols[2].replace(/^"|"$/g,'');
    return [$highPrivRolesJs].includes(role);
  });
  dlFile([header,...filtered].join('\n'),'PIM_HighPriv_${TenantName}_$todayDateShort.csv','text/csv');
  showToast('✅ Exported high-privilege assignments as CSV');
}

/* ── Toast ── */
function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),3200);
}

/* ── Keyboard: / to focus search ── */
document.addEventListener('keydown',e=>{
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){
    e.preventDefault();
    const inp=document.querySelector('.page.active .search-box');
    if(inp)inp.focus();
  }
});

/* ── Init ── */
window.addEventListener('DOMContentLoaded',function(){
  buildDonut();
  animateBars();
  ['all','users','groups','sps','riskperm','riskhigh'].forEach(t=>renderPag(t));
});
</script>
</body>
</html>
"@

        # Save the HTML content to a file
        $htmlFile = Join-Path -Path $OutputPath -ChildPath "PIMEntraIDRoleActiveAssignment_$($TenantName -replace '\s','_')_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"

        # Ensure the output folder exists
        if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

        $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
        Write-Host ""
        Write-Host "✅ Dashboard saved to: $htmlFile" -ForegroundColor Green

        # Open the HTML file
        Invoke-Item $htmlFile
    }

    # ── Return the structured result ────────────────────────────────────────
    $result

    # ── Console Summary ──────────────────────────────────────────────────────
    $stats = $result | Group-Object "Assigned Type" | Select-Object @{Name='Assigned Type'; Expression={$_.Name}}, Count | Out-String

    $stats1 = $result | Group-Object "Role Name" | ForEach-Object {
        $roleName       = $_.Name
        $assignedCount  = ($_.Group | Where-Object { $_.'Assignment State' -eq 'Assigned'  } | Measure-Object).Count
        $activatedCount = ($_.Group | Where-Object { $_.'Assignment State' -eq 'Activated' } | Measure-Object).Count

        [PSCustomObject]@{
            "Role Name" = $roleName
            "Assigned"  = $assignedCount
            "Activated" = $activatedCount
        }
    } | Out-String

    Write-Host $stats  -ForegroundColor Yellow
    Write-Host $stats1 -ForegroundColor Yellow
}
