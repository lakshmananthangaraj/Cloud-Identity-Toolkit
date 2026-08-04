<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 04 August 2026
Modified-On     : 04 August 2026

.SYNOPSIS
    Fast, standalone report of ONLY currently privileged Entra ID principals
    (active + optionally PIM-eligible directory role assignments) — built for
    incident-response / emergency access reviews where running the full MFA
    pipeline (Get-EntraID-MFARegistrationReport.ps1) is unnecessary overhead.

.DESCRIPTION
    Dot-source this file and call Get-PrivilegedUsersReport. The function:

      1. Authenticates using ONE of two supported modes (mutually exclusive
         parameter sets — see .PARAMETER notes below):
           - ClientCredential : ClientId + ClientSecret + TenantId
                                (app-only, auto-renews token on expiry)
           - BringYourOwnToken: a pre-acquired AccessToken string, e.g. from
                                Connect-MgGraph / az account get-access-token
                                (no refresh capability — see warning below)
      2. Pulls all Entra directory role definitions and flags which are
         privileged (isPrivileged), same logic as Get-PrivilegedRoleAssignments
         in the MFA toolkit — kept deliberately identical so results from both
         scripts never disagree.
      3. Pulls ACTIVE role assignments (roleAssignmentScheduleInstances) and,
         if -IncludeEligibleRoles is specified, PIM-ELIGIBLE assignments
         (roleEligibilityScheduleInstances) — requires Entra ID P2.
      4. Resolves each principalId to a DisplayName/UPN/ObjectType via a
         batched directoryObjects/getByIds call (handles users, groups, and
         service principals — not just users).
      5. Optionally exports to CSV and/or a standalone, multi-tab HTML
         report (Overview / Findings / Analytics / Data / Recommendations)
         styled per the html-dashboard-design golden theme — still a single
         self-contained file with zero external dependency other than the
         report itself, so it remains safe to run in an emergency.

.PARAMETER ClientId
    Azure AD App Registration (Application) ID. Required with -ClientSecret
    and -TenantId for the ClientCredential authentication mode.

.PARAMETER ClientSecret
    Client secret value for the app registration. Required with -ClientId
    and -TenantId. Passed as a SecureString-backed [string] at the console —
    do NOT hardcode this in scripts or commit it to source control.

.PARAMETER TenantId
    Entra ID tenant ID (GUID) or verified domain. Required with -ClientId
    and -ClientSecret.

.PARAMETER AccessToken
    A pre-acquired Microsoft Graph access token (Bearer token string), e.g.
    from `Connect-MgGraph` + `(Get-MgContext)` token retrieval, or
    `az account get-access-token --resource https://graph.microsoft.com`.

    WARNING: this mode has NO refresh capability — there is no client secret
    to renew with. Tokens are typically valid ~60-90 minutes. For large
    tenants where the run may exceed that window, use -ClientCredential mode
    instead. This function checks token expiry (from the JWT `exp` claim)
    before each paginated call and throws a clear error if the token has
    expired mid-run, rather than failing with an opaque 401.

.PARAMETER CustomPrivilegedRoles
    Optional array of additional role display names (beyond Entra's built-in
    isPrivileged flag) to also treat as privileged — e.g. custom roles your
    org has defined. Case-insensitive exact match on role display name.

.PARAMETER IncludeEligibleRoles
    Switch. If specified, also queries PIM-eligible (not just active) role
    assignments. Requires Entra ID P2 / Governance licensing — if the tenant
    lacks it, this call fails gracefully with a warning and active-only
    results are still returned.

.PARAMETER ExportCsv
    Switch. If specified, exports results to CsvPath.

.PARAMETER CsvPath
    Output path for the CSV. Defaults to
    "$env:TEMP\PrivilegedUsersReport_<timestamp>.csv".

.PARAMETER ExportHtml
    Switch. If specified, exports a lightweight standalone HTML table to
    HtmlPath.

.PARAMETER HtmlPath
    Output path for the HTML file. Defaults to
    "$env:TEMP\PrivilegedUsersReport_<timestamp>.html".

.PARAMETER OpenBrowser
    Switch. If specified with -ExportHtml, opens the generated HTML in the
    default browser automatically.

.OUTPUTS
    PSCustomObject[]
        One object per privileged principal: PrincipalId, DisplayName, UPN,
        ObjectType, PrivilegedRoles, AssignmentTypes, Sources.
    Also returns to the pipeline even if neither -ExportCsv nor -ExportHtml
    is specified, so it can be piped/filtered/stored in a variable directly.

.EXAMPLE
    . .\Get-PrivilegedUsersReport.ps1
    Get-PrivilegedUsersReport -ClientId $cid -ClientSecret $secret -TenantId $tid -ExportCsv -OpenBrowser:$false

    App-only auth, active roles only, exports CSV to the default temp path.

.EXAMPLE
    . .\Get-PrivilegedUsersReport.ps1
    Get-PrivilegedUsersReport -AccessToken $token -IncludeEligibleRoles -ExportHtml -OpenBrowser

    Bring-your-own-token mode (e.g. already signed in via Connect-MgGraph),
    includes PIM-eligible roles, opens an HTML view immediately — the
    "emergency, I'm already authenticated, just show me who's privileged
    right now" path.

.EXAMPLE
    . .\Get-PrivilegedUsersReport.ps1
    $priv = Get-PrivilegedUsersReport -ClientId $cid -ClientSecret $secret -TenantId $tid
    $priv | Where-Object { $_.AssignmentTypes -contains 'Active' } | Format-Table

    Capture to a variable and filter in-session without writing any files —
    fastest path when you just need an answer, not a report artifact.

.NOTES
    Required Graph Application permission (client credential mode) or
    delegated scope (bring-your-own-token mode): RoleManagement.Read.Directory
    (admin consent required for application permissions).

    KNOWN DEPENDENCY: role definitions are pulled from the /beta Graph
    endpoint, not v1.0, because `isPrivileged` is not a selectable property
    on v1.0's roleManagement/directory/roleDefinitions (confirmed via a 400
    BadRequest — v1.0 rejects the $select entirely). Only this one call uses
    beta; role assignment/eligibility calls remain on v1.0. Beta endpoints
    are not SLA-backed and can change shape without notice — if this call
    starts failing unexpectedly, check the Graph beta changelog first.

    Companion scripts in this toolkit:
      - Entra-ID/PIM   : Get-PrivilegedRoleAssignments.ps1 (full active +
                          eligible PIM report, standalone)
      - Entra-ID/MFA   : Get-EntraID-MFARegistrationReport.ps1 (full MFA
                          registration CSV, of which privileged-role columns
                          are one section) + Generate-MFADashboard.ps1

    This script deliberately duplicates the role-definition/assignment
    resolution logic from those two rather than importing them, so it has
    zero dependency on either being present — the entire point is a single
    file that works standalone in an emergency.

    Version History:
        1.0 (04-Aug-2026)  - Initial release. Dual auth modes (ClientCredential
                              / BringYourOwnToken), active + optional eligible
                              role resolution, batched principal resolution
                              (users/groups/service principals), CSV export,
                              lightweight standalone HTML export.

                           - Fixed role definitions call: switched from v1.0 to
                              beta Graph endpoint. v1.0 returns 400 BadRequest
                              when `isPrivileged` is included in $select — that
                              property isn't exposed on v1.0's
                              unifiedRoleDefinition. Same fix already applied
                              to Get-PrivilegedRoleAssignments in the MFA
                              toolkit; this closes the same gap here.

                           - Fixed identity resolution: directoryObjects/getByIds
                              only returns type-specific properties
                              (userPrincipalName, mail, appId, etc.) when a
                              `types` array is included in the request body —
                              without it, Graph returns bare id + @odata.type
                              only, which is why the majority of principals
                              were showing as unresolved. Added
                              types: ['user','group','servicePrincipal'].
                              Also hardened all property access with
                              PSObject.Properties[] checks instead of bare dot
                              notation, since different principal types expose
                              different property sets and some session
                              configurations throw rather than return $null on
                              a missing property.
                            - Replaced the flat single-table HTML export with a
                              full visual dashboard, per the
                              html-dashboard-design skill golden theme: sidebar
                              shell with dark/light toggle, 7-tile KPI row
                              (Global Admins, Total, Active-Only, Eligible-Only,
                              Active+Eligible, Human vs non-human), a dedicated
                              red-bordered "Global Administrator Holders"
                              findings callout, a Top Privileged Roles bar
                              chart, a Principal Type donut chart, and a
                              searchable/exportable full data table with
                              Global-Admin row highlighting. Old function name
                              (Export-PrivilegedUsersHtml) and call site
                              unchanged — only the HTML/CSS/JS body and the PS
                              aggregation feeding it changed.

                           - Converted the single-page HTML export into a
                              multi-tab report (Overview / Findings /
                              Analytics / Data / Recommendations), matching a
                              Power BI-style business+technical reporting
                              layout. Added: an executive-summary paragraph
                              and heuristic 0-100 privileged-access risk
                              score with a ring gauge (clearly labelled as an
                              indicative heuristic, not Microsoft Secure
                              Score); dedicated Findings tab breaking out
                              Global Admin holders, active-only (always-on)
                              privileged assignments, non-human privileged
                              principals, and unresolved principals as their
                              own callouts; an Analytics tab adding
                              Assignment-Type and Role-Source donut charts
                              alongside the existing Top-Roles bar chart and
                              Principal-Type donut; and a Recommendations tab
                              with prioritized, data-driven suggestions
                              (Business impact + Technical action per item).
                              Sidebar gained tab navigation (reused
                              show/hide-page pattern from the
                              html-dashboard-design golden script) alongside
                              the existing dark/light toggle. NO CHANGE to any
                              authentication, Graph call, pagination,
                              principal-resolution, or privileged-role
                              detection logic — only Export-PrivilegedUsersHtml
                              (HTML/CSS/JS body + its PS-side aggregation) was
                              touched; function name, parameters, and the
                              Step 6 call site are all unchanged.

                           - Data tab: added Object Type, Assignment Type,
                              and Role Source filter dropdowns plus a "GA
                              only" checkbox and a Reset button, so large
                              enterprise tenants can narrow the table before
                              scanning/exporting instead of relying on free-
                              text search alone. Refactored the search-only
                              filter in renderTable()/exportCsvFromTable()
                              into a shared getFilteredData() so search and
                              the new filters combine and CSV export always
                              matches what's on screen. No PS-side change —
                              front-end (HTML/CSS/JS inside
                              Export-PrivilegedUsersHtml) only.

#>

# ── Auth: Client Credential flow ─────────────────────────────────────────────
function Get-ClientCredentialToken
{
    param(
        [Parameter(Mandatory = $true)][string]$ClientId,
        [Parameter(Mandatory = $true)][string]$ClientSecret,
        [Parameter(Mandatory = $true)][string]$TenantId
    )

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }

    Try
    {
        $resp = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        return [PSCustomObject]@{
            AccessToken = $resp.access_token
            ExpiresOn   = (Get-Date).AddSeconds([int]$resp.expires_in - 60)  # 60s safety buffer
        }
    }
    Catch
    {
        throw "Client credential token request failed. Verify ClientId/ClientSecret/TenantId and that admin consent has been granted for RoleManagement.Read.Directory. Details: $($_.Exception.Message)"
    }
}

# ── Auth: decode exp claim from a bring-your-own token (no validation, read-only) ──
function Get-JwtExpiry
{
    param([Parameter(Mandatory = $true)][string]$Token)

    Try
    {
        $parts = $Token.Split('.')
        if ($parts.Count -lt 2) { return $null }
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
        if ($json.exp) { return [DateTimeOffset]::FromUnixTimeSeconds([int64]$json.exp).LocalDateTime }
        return $null
    }
    Catch { return $null }
}

# ── Token renewal gate — called before every paginated Graph call ───────────
function Test-PrivReportTokenValid
{
    if ($script:AuthMode -eq 'ClientCredential')
    {
        if ((Get-Date) -ge $script:TokenExpiresOn)
        {
            Write-Host "  🔄 Access token expiring — renewing (client credential mode)..." -ForegroundColor Yellow
            $t = Get-ClientCredentialToken -ClientId $script:ClientId -ClientSecret $script:ClientSecret -TenantId $script:TenantId
            $script:AccessToken   = $t.AccessToken
            $script:TokenExpiresOn = $t.ExpiresOn
        }
    }
    else
    {
        # BringYourOwnToken mode: cannot refresh — fail clearly instead of a bare 401 mid-pagination.
        if ($script:TokenExpiresOn -and (Get-Date) -ge $script:TokenExpiresOn)
        {
            throw "The provided AccessToken has expired (bring-your-own-token mode has no refresh capability). Re-authenticate and re-run with a fresh token."
        }
    }
}

# ── Generic paginated GET helper ─────────────────────────────────────────────
function Get-AllGraphPages
{
    param([Parameter(Mandatory = $true)][string]$Uri)

    $results = @()
    $next = $Uri
    do
    {
        Test-PrivReportTokenValid
        $headers = @{ "Authorization" = "Bearer $script:AccessToken" }
        $resp = Invoke-RestMethod -Uri $next -Headers $headers -Method Get -ErrorAction Stop
        $results += $resp.value
        $next = if ($resp.PSObject.Properties['@odata.nextLink']) { $resp.'@odata.nextLink' } else { $null }
    } until (-not $next)
    return $results
}

# ── Resolve principalIds → DisplayName/UPN/ObjectType in batches of 1000 ────
function Resolve-PrincipalDetails
{
    param([Parameter(Mandatory = $true)][string[]]$PrincipalIds)

    $resolved = @{}
    $batchSize = 1000  # Graph getByIds max batch size
    for ($i = 0; $i -lt $PrincipalIds.Count; $i += $batchSize)
    {
        Test-PrivReportTokenValid
        $slice = $PrincipalIds[$i..([Math]::Min($i + $batchSize - 1, $PrincipalIds.Count - 1))]
        $bodyJson = @{ ids = $slice; types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json
        $headers  = @{ "Authorization" = "Bearer $script:AccessToken"; "Content-Type" = "application/json" }

        Try
        {
            $resp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryObjects/getByIds" -Headers $headers -Method Post -Body $bodyJson -ErrorAction Stop
            foreach ($obj in $resp.value)
            {
                $type = ($obj.'@odata.type' -replace '#microsoft.graph.', '')
                # Defensive PSObject.Properties checks — different principal types
                # (user/group/servicePrincipal) expose different property sets, and
                # dot-notation access on a missing property can throw depending on
                # session strict-mode settings. Never assume a property exists.
                $displayName = if ($obj.PSObject.Properties['displayName'] -and $obj.displayName) { $obj.displayName } else { "(unresolved $type)" }
                $upn = if ($obj.PSObject.Properties['userPrincipalName'] -and $obj.userPrincipalName) { $obj.userPrincipalName }
                       elseif ($obj.PSObject.Properties['mail'] -and $obj.mail) { $obj.mail }
                       elseif ($obj.PSObject.Properties['appId'] -and $obj.appId) { $obj.appId }
                       else { '' }
                $resolved[$obj.id] = [PSCustomObject]@{
                    DisplayName = $displayName
                    UPN         = $upn
                    ObjectType  = $type
                }
            }
        }
        Catch
        {
            Write-Warning "Batch principal resolution failed for one batch (indices $i..$($i+$slice.Count-1)). Those principals will show as unresolved. Details: $($_.Exception.Message)"
        }
    }
    return $resolved
}

# ── PowerShell-side JSON-safe string escaper (per design-tokens.md §5 pattern —
#    hand-built JS object literals, not ConvertTo-Json, for tight escaping control) ──
function ConvertTo-JsonSafe
{
    param([string]$Value)
    if (-not $Value) { return '' }
    return $Value -replace '\\','\\\\' -replace '"','\"' -replace "`n",' ' -replace "`r",'' -replace "`t",' ' -replace '<','\u003c' -replace '>','\u003e' -replace '\$','\u0024'
}

# ── Full multi-tab dashboard export — golden theme (html-dashboard-design skill) ──
function Export-PrivilegedUsersHtml
{
    param([Parameter(Mandatory = $true)][array]$Data, [Parameter(Mandatory = $true)][string]$Path)

    # ── PS-side aggregation (all computed once, injected as tokens/JSON) ──
    $total          = $Data.Count
    $globalAdmins   = @($Data | Where-Object { $_.PrivilegedRoles -contains 'Global Administrator' })
    $activeOnlySet  = @($Data | Where-Object { $_.AssignmentTypes -contains 'Active'   -and $_.AssignmentTypes -notcontains 'Eligible' })
    $eligibleOnlySet= @($Data | Where-Object { $_.AssignmentTypes -contains 'Eligible' -and $_.AssignmentTypes -notcontains 'Active' })
    $bothTypesSet   = @($Data | Where-Object { $_.AssignmentTypes -contains 'Active'   -and $_.AssignmentTypes -contains 'Eligible' })
    $activeOnly     = $activeOnlySet.Count
    $eligibleOnly   = $eligibleOnlySet.Count
    $bothTypes      = $bothTypesSet.Count
    $userCount      = @($Data | Where-Object { $_.ObjectType -eq 'user' }).Count
    $groupCount     = @($Data | Where-Object { $_.ObjectType -eq 'group' }).Count
    $spCount        = @($Data | Where-Object { $_.ObjectType -eq 'servicePrincipal' }).Count
    $nonHumanSet    = @($Data | Where-Object { $_.ObjectType -eq 'group' -or $_.ObjectType -eq 'servicePrincipal' })
    $unresolvedSet  = @($Data | Where-Object { $_.DisplayName -like '(unresolved*' })
    $unresolvedCnt  = $unresolvedSet.Count
    $builtInCount   = @($Data | Where-Object { $_.Sources -contains 'BuiltIn' -and $_.Sources -notcontains 'Custom' }).Count
    $customCount    = @($Data | Where-Object { $_.Sources -contains 'Custom'  -and $_.Sources -notcontains 'BuiltIn' }).Count
    $bothSrcCount   = @($Data | Where-Object { $_.Sources -contains 'Both' -or ($_.Sources -contains 'BuiltIn' -and $_.Sources -contains 'Custom') }).Count

    # ── Heuristic 0-100 privileged-access risk score (indicative only — NOT
    #    Microsoft Secure Score). Weighted on: standing Global Admin count,
    #    share of always-on (active-only, no PIM) privileged assignments,
    #    share of non-human privileged principals, and unresolved principals. ──
    $gaWeight        = [math]::Min($globalAdmins.Count * 8, 40)
    $activeOnlyWeight= if ($total -gt 0) { [math]::Round(($activeOnly    / $total) * 30) } else { 0 }
    $nonHumanWeight  = if ($total -gt 0) { [math]::Round(($nonHumanSet.Count / $total) * 15) } else { 0 }
    $unresolvedWeight= [math]::Min($unresolvedCnt * 5, 15)
    $riskScore       = [math]::Min(($gaWeight + $activeOnlyWeight + $nonHumanWeight + $unresolvedWeight), 100)
    $riskLevel       = switch ($riskScore) { { $_ -ge 75 } { 'Critical'; break } { $_ -ge 50 } { 'High'; break } { $_ -ge 25 } { 'Medium'; break } default { 'Low' } }
    $riskColor       = switch ($riskLevel) { 'Critical' { 'var(--red)' } 'High' { 'var(--red)' } 'Medium' { 'var(--amber)' } default { 'var(--green)' } }

    # ── Executive summary paragraph (plain-language, for non-technical readers) ──
    $summaryText = "This scan identified $total privileged Entra ID principal$(if($total -ne 1){'s'}) across active" + `
        $(if ($eligibleOnly -gt 0 -or $bothTypes -gt 0) { ' and PIM-eligible' } else { '' }) + " directory role assignments. " + `
        "$($globalAdmins.Count) of these hold the Global Administrator role, the highest-privilege role in the tenant. " + `
        "$activeOnly principal$(if($activeOnly -ne 1){'s'}) hold privileged access on a standing (always-on) basis with no time-bound PIM activation. " + `
        "$($nonHumanSet.Count) are non-human identities (groups or service principals). " + `
        "Overall indicative risk for this scan is rated $riskLevel ($riskScore/100)."

    # Top roles by principal count, for the bar chart
    $roleCounts = @{}
    foreach ($p in $Data) { foreach ($r in $p.PrivilegedRoles) { $roleCounts[$r] = ($roleCounts[$r] + 1) } }
    $topRoles = $roleCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8
    $maxRoleCount = if ($topRoles) { ($topRoles | Measure-Object Value -Maximum).Maximum } else { 1 }
    $roleBarsHtml = ($topRoles | ForEach-Object {
        $pct = [math]::Round(($_.Value / [math]::Max($maxRoleCount,1)) * 100, 0)
        "<div class='bar-row'><div class='bar-label'>$(ConvertTo-JsonSafe $_.Key)</div><div class='bar-track'><div class='bar-fill' data-pct='$pct' style='background:var(--red)'></div></div><div class='bar-val'>$($_.Value)</div></div>"
    }) -join "`n"

    # Object type donut segments (User / Group / Service Principal)
    $typeDonutParts = @(
        @{ Label='Users'; Value=$userCount; Color='var(--accent)' },
        @{ Label='Groups'; Value=$groupCount; Color='var(--accent3)' },
        @{ Label='Service Principals'; Value=$spCount; Color='var(--amber)' }
    ) | Where-Object { $_.Value -gt 0 }

    # Assignment type donut segments (Active-only / Eligible-only / Active+Eligible)
    $assignDonutParts = @(
        @{ Label='Active Only'; Value=$activeOnly; Color='var(--green)' },
        @{ Label='Eligible Only'; Value=$eligibleOnly; Color='var(--amber)' },
        @{ Label='Active + Eligible'; Value=$bothTypes; Color='var(--accent3)' }
    ) | Where-Object { $_.Value -gt 0 }

    # Role source donut segments (BuiltIn / Custom / Both)
    $srcDonutParts = @(
        @{ Label='Built-in Only'; Value=$builtInCount; Color='var(--accent)' },
        @{ Label='Custom Only'; Value=$customCount; Color='var(--accent2)' },
        @{ Label='Built-in + Custom'; Value=$bothSrcCount; Color='var(--accent3)' }
    ) | Where-Object { $_.Value -gt 0 }

    # Row data as hand-built JSON-safe JS array (per design-tokens.md pattern — not ConvertTo-Json)
    $rowsJs = ($Data | ForEach-Object {
        $isGA = if ($_.PrivilegedRoles -contains 'Global Administrator') { 'true' } else { 'false' }
        "{dn:`"$(ConvertTo-JsonSafe $_.DisplayName)`",upn:`"$(ConvertTo-JsonSafe $_.UPN)`",ot:`"$(ConvertTo-JsonSafe $_.ObjectType)`",roles:`"$(ConvertTo-JsonSafe ($_.PrivilegedRoles -join ', '))`",atype:`"$(ConvertTo-JsonSafe ($_.AssignmentTypes -join ', '))`",src:`"$(ConvertTo-JsonSafe ($_.Sources -join ', '))`",ga:$isGA}"
    }) -join ",`n"

    $gaChipsHtml = if ($globalAdmins.Count -gt 0) {
        ($globalAdmins | ForEach-Object { "<span class='chip chip-red'>👑 $(ConvertTo-JsonSafe $_.DisplayName)</span>" }) -join "`n"
    } else { "<span style='color:var(--muted)'>None found — no Global Administrator role holders in this scan.</span>" }

    # ── Small reusable mini-table builder for the Findings tab callouts ──
    function New-MiniTableHtml
    {
        param([array]$Rows, [string]$EmptyText, [int]$MaxRows = 25)
        if (-not $Rows -or $Rows.Count -eq 0) { return "<span style='color:var(--muted)'>$EmptyText</span>" }
        $shown = $Rows | Select-Object -First $MaxRows
        $rowsHtml = ($shown | ForEach-Object {
            "<tr><td>$(ConvertTo-JsonSafe $_.DisplayName)</td><td>$(ConvertTo-JsonSafe $_.UPN)</td><td>$(ConvertTo-JsonSafe ($_.PrivilegedRoles -join ', '))</td></tr>"
        }) -join "`n"
        $note = if ($Rows.Count -gt $MaxRows) { "<div style='font-size:11px;color:var(--muted);margin-top:8px'>Showing first $MaxRows of $($Rows.Count) — see the Data tab for the complete list.</div>" } else { '' }
        return "<table class='mini-table'><thead><tr><th>Display Name</th><th>UPN / App ID</th><th>Privileged Roles</th></tr></thead><tbody>$rowsHtml</tbody></table>$note"
    }
    $activeOnlyTableHtml   = New-MiniTableHtml -Rows $activeOnlySet  -EmptyText 'No always-on (active-only, non-PIM) privileged assignments found.'
    $nonHumanTableHtml     = New-MiniTableHtml -Rows $nonHumanSet    -EmptyText 'No non-human (group / service principal) privileged principals found.'
    $unresolvedTableHtml   = New-MiniTableHtml -Rows $unresolvedSet  -EmptyText 'No unresolved principals — every principalId resolved to a directory object.'

    # ── Data-driven recommendations (Business impact + Technical action, prioritized) ──
    $recommendations = New-Object System.Collections.Generic.List[object]
    if ($globalAdmins.Count -gt 4)
    {
        $recommendations.Add([PSCustomObject]@{
            Priority = 'High'
            Title    = "Reduce the number of standing Global Administrator holders"
            Business = "$($globalAdmins.Count) people or apps can currently do anything in the tenant. That's a large blast radius if any one of those accounts is compromised."
            Technical= "Microsoft recommends keeping fewer than 5 Global Administrators, plus at least 2 cloud-only break-glass accounts excluded from Conditional Access and monitored separately. Move remaining Global Admin need to PIM-eligible with approval + MFA on activation."
        })
    }
    elseif ($globalAdmins.Count -eq 0)
    {
        $recommendations.Add([PSCustomObject]@{
            Priority = 'Medium'
            Title    = "Verify break-glass access exists outside this scan's scope"
            Business = "No Global Administrator holders were found. If this is expected (e.g. break-glass accounts live in a different tenant/subscription boundary), no action is needed."
            Technical= "Confirm at least 2 emergency-access (break-glass) accounts exist, are cloud-only, use strong non-expiring credentials, and are excluded from Conditional Access — then verify this scan's app registration has RoleManagement.Read.Directory consent granted, in case results are incomplete rather than genuinely zero."
        })
    }
    if ($activeOnly -gt 0)
    {
        $recommendations.Add([PSCustomObject]@{
            Priority = 'High'
            Title    = "Convert always-on privileged access to time-bound PIM"
            Business = "$activeOnly principal$(if($activeOnly -ne 1){'s'}) can use privileged roles at any time, with no approval or expiry — this is the standing-access pattern PIM was built to eliminate."
            Technical= "Re-run this report with -IncludeEligibleRoles to confirm eligible-role coverage, then migrate active-only assignments for high-impact roles to roleEligibilityScheduleRequests with maxDuration + approval + MFA-on-activation policies."
        })
    }
    if ($nonHumanSet.Count -gt 0)
    {
        $recommendations.Add([PSCustomObject]@{
            Priority = 'Medium'
            Title    = "Review non-human privileged principals"
            Business = "$($nonHumanSet.Count) of the privileged principals are groups or applications rather than people. Someone should own and periodically justify each of these."
            Technical= "For service principals: verify credential rotation cadence and least-privilege app permissions. For role-assignable groups: confirm group membership is tightly controlled and, ideally, itself PIM-governed."
        })
    }
    if ($unresolvedCnt -gt 0)
    {
        $recommendations.Add([PSCustomObject]@{
            Priority = 'Low'
            Title    = "Clean up unresolved / orphaned role assignments"
            Business = "$unresolvedCnt principal$(if($unresolvedCnt -ne 1){'s'}) could not be matched to a current display name — likely deleted or external directory objects still holding a role."
            Technical= "Cross-check these principalIds against deleted objects / external tenant references; remove orphaned roleAssignmentScheduleInstances or roleEligibilityScheduleInstances that no longer resolve to a valid principal."
        })
    }
    $recommendations.Add([PSCustomObject]@{
        Priority = 'Medium'
        Title    = "Schedule recurring Access Reviews on privileged roles"
        Business = "Privileged access tends to accumulate over time as people change roles. A recurring review keeps the list in this report from quietly growing."
        Technical= "Configure Entra ID Governance Access Reviews (quarterly minimum) scoped to each isPrivileged directory role, with self-review or manager-review and automatic removal on no-response."
    })
    $recommendations.Add([PSCustomObject]@{
        Priority = 'Low'
        Title    = "Automate a recurring diff of this report"
        Business = "Knowing who is privileged today is useful; knowing what changed since last week is what catches problems early."
        Technical= "Schedule Get-PrivilegedUsersReport (e.g. via Azure Automation or a GitHub Actions runner) and diff PrincipalId/PrivilegedRoles against the prior run's CSV to alert on newly-granted privileged access."
    })
    $prioRank = @{ High = 0; Medium = 1; Low = 2 }
    $recommendations = $recommendations | Sort-Object { $prioRank[$_.Priority] }
    $recCardsHtml = ($recommendations | ForEach-Object {
        $cls = switch ($_.Priority) { 'High' { 'rec-high' } 'Medium' { 'rec-medium' } default { 'rec-low' } }
        "<div class='rec-card $cls'><div class='rec-head'><span class='rec-badge $cls'>$(ConvertTo-JsonSafe $_.Priority)</span><h4>$(ConvertTo-JsonSafe $_.Title)</h4></div><div class='rec-body'><div class='rec-col'><div class='rec-col-lbl'>💼 Business impact</div><p>$(ConvertTo-JsonSafe $_.Business)</p></div><div class='rec-col'><div class='rec-col-lbl'>🛠 Technical action</div><p>$(ConvertTo-JsonSafe $_.Technical)</p></div></div></div>"
    }) -join "`n"

    $genTime = Get-Date -Format 'dd MMM yyyy, hh:mm tt'

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privileged Users Report</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
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
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh}
#sidebar{position:fixed;top:0;left:0;width:236px;height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;padding:20px 16px;z-index:10}
.logo-block{display:flex;align-items:center;gap:10px;margin-bottom:20px}
.logo-tile{width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,var(--red),var(--amber));display:flex;align-items:center;justify-content:center;font-size:18px}
.logo-title{font-size:14.5px;font-weight:600;line-height:1.2}
.logo-sub{font-size:10.5px;color:var(--muted)}
.nav-section{display:flex;flex-direction:column;gap:3px;margin-bottom:14px}
.nav-btn{display:flex;align-items:center;gap:9px;padding:9px 10px;border-radius:var(--radius-sm);border:none;background:transparent;color:var(--muted2);font-size:12.5px;text-align:left;cursor:pointer;border-left:3px solid transparent;font-family:var(--sans)}
.nav-btn:hover{background:var(--surface2)}
.nav-btn.active{background:var(--surface2);color:var(--text);border-left-color:var(--accent);font-weight:600}
.theme-toggle{margin-top:auto;display:flex;background:var(--surface2);border-radius:20px;padding:3px;cursor:pointer}
.theme-toggle span{flex:1;text-align:center;padding:6px 0;font-size:11px;border-radius:16px;transition:.2s}
.theme-toggle .active{background:var(--accent);color:#fff}
.sidebar-footer{font-size:10px;color:var(--muted);margin-top:14px;line-height:1.6}
#main{margin-left:236px;padding:28px 32px}
h1{font-size:21px;margin-bottom:2px}
.pagesub{color:var(--muted);font-size:12.5px;margin-bottom:22px}
.page{display:none}
.page.active{display:block;animation:fadeIn .25s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-top:3px solid var(--accent);border-radius:var(--radius);padding:16px;transition:.2s}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.stat-card.c-red{border-top-color:var(--red)}
.stat-card.c-amber{border-top-color:var(--amber)}
.stat-card.c-green{border-top-color:var(--green)}
.stat-card.c-purple{border-top-color:var(--accent3)}
.stat-card.c-cyan{border-top-color:var(--accent2)}
.stat-icon{font-size:19px;margin-bottom:6px}
.stat-val{font-size:26px;font-weight:700;font-family:var(--mono)}
.stat-lbl{font-size:11.5px;color:var(--muted);margin-top:2px}
.chart-grid{display:grid;grid-template-columns:1.1fr 1fr;gap:16px;margin-bottom:22px}
.chart-grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:22px}
@media(max-width:1000px){.chart-grid3{grid-template-columns:1fr}}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:22px}
.panel h3{font-size:13.5px;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.bar-row{display:grid;grid-template-columns:150px 1fr 34px;align-items:center;gap:10px;margin-bottom:10px;font-size:12px}
.bar-label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--muted2)}
.bar-track{height:9px;background:var(--surface2);border-radius:5px;overflow:hidden}
.bar-fill{height:100%;width:0;border-radius:5px;transition:width 1s ease}
.bar-val{text-align:right;font-family:var(--mono);font-weight:600}
#donutWrap,.donut-wrap{display:flex;align-items:center;gap:18px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:12px;margin-bottom:8px}
.legend-dot{width:10px;height:10px;border-radius:3px;flex-shrink:0}
.findings-panel{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--red);border-radius:var(--radius);padding:18px;margin-bottom:22px}
.findings-panel.amber{border-left-color:var(--amber)}
.findings-panel.cyan{border-left-color:var(--accent2)}
.findings-panel h3{font-size:14px;margin-bottom:10px}
.chip{display:inline-block;padding:5px 11px;border-radius:20px;font-size:11.5px;margin:3px 4px 3px 0;background:var(--surface2)}
.chip-red{background:rgba(248,81,73,.12);color:var(--red);font-weight:600}
.mini-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px}
.mini-table th{background:var(--surface2);color:var(--muted);text-align:left;padding:7px 9px;font-size:10.5px;text-transform:uppercase;letter-spacing:.4px}
.mini-table td{padding:7px 9px;border-bottom:1px solid var(--border);font-family:var(--mono)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.srch-wrap{position:relative;flex:1;min-width:220px}
.srch-wrap input{width:100%;padding:9px 12px 9px 34px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:12.5px}
.si{position:absolute;left:11px;top:9px;opacity:.6}
.filter-select{padding:8px 10px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:12.5px;font-family:var(--sans)}
.ga-only-label{display:flex;align-items:center;gap:6px;font-size:12.5px;color:var(--muted2);cursor:pointer;padding:0 4px}
.btn{padding:8px 14px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface2);color:var(--muted2);font-size:12.5px;cursor:pointer}
.btn:hover{border-color:var(--accent);color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:var(--surface2);color:var(--muted);text-align:left;padding:9px 10px;position:sticky;top:0;font-size:11px;text-transform:uppercase;letter-spacing:.4px}
td{padding:9px 10px;border-bottom:1px solid var(--border);font-family:var(--mono);white-space:nowrap;max-width:220px;overflow:hidden;text-overflow:ellipsis}
tr:hover td{background:rgba(56,139,253,.06)}
tr.ga-row td{background:rgba(248,81,73,.06)}
.rcount{font-size:11.5px;color:var(--muted);margin-left:auto}
#toast{position:fixed;bottom:24px;right:24px;background:var(--surface3);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 18px;font-size:12.5px;opacity:0;transform:translateY(10px);transition:.3s;box-shadow:var(--shadow)}
#toast.show{opacity:1;transform:translateY(0)}
.summary-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;margin-bottom:22px;font-size:13px;line-height:1.7;color:var(--muted2)}
.overview-grid{display:grid;grid-template-columns:1fr 260px;gap:16px;margin-bottom:22px}
@media(max-width:900px){.overview-grid{grid-template-columns:1fr}}
.gauge-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px}
.gauge-val{font-family:var(--mono);font-weight:700;font-size:22px}
.gauge-lvl{font-size:12px;font-weight:600;padding:3px 10px;border-radius:20px}
.rec-card{border:1px solid var(--border);border-left:4px solid var(--muted);border-radius:var(--radius);padding:16px;margin-bottom:14px;background:var(--surface)}
.rec-card.rec-high{border-left-color:var(--red)}
.rec-card.rec-medium{border-left-color:var(--amber)}
.rec-card.rec-low{border-left-color:var(--accent2)}
.rec-head{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.rec-head h4{font-size:13.5px}
.rec-badge{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;padding:3px 9px;border-radius:20px}
.rec-badge.rec-high{background:rgba(248,81,73,.15);color:var(--red)}
.rec-badge.rec-medium{background:rgba(210,153,34,.18);color:var(--amber)}
.rec-badge.rec-low{background:rgba(57,197,207,.15);color:var(--accent2)}
.rec-body{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:900px){.rec-body{grid-template-columns:1fr}}
.rec-col-lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px}
.rec-col p{font-size:12.5px;line-height:1.6;color:var(--muted2)}
</style>
</head>
<body>
<div id="sidebar">
  <div class="logo-block">
    <div class="logo-tile">👑</div>
    <div><div class="logo-title">Privileged Users</div><div class="logo-sub">Emergency Access Review</div></div>
  </div>
  <div class="nav-section">
    <button class="nav-btn active" onclick="showPage('page-overview', this)">🏠 Overview</button>
    <button class="nav-btn" onclick="showPage('page-findings', this)">🚨 Findings</button>
    <button class="nav-btn" onclick="showPage('page-analytics', this)">📊 Analytics</button>
    <button class="nav-btn" onclick="showPage('page-data', this)">📋 Data</button>
    <button class="nav-btn" onclick="showPage('page-recs', this)">💡 Recommendations</button>
  </div>
  <div style="font-size:11px;color:var(--muted);line-height:1.8">
    Generated<br><b style="color:var(--text)">__GENTIME__</b>
  </div>
  <div class="theme-toggle" id="themeToggle">
    <span id="darkBtn" class="active">🌙 Dark</span><span id="lightBtn">☀️ Light</span>
  </div>
  <div class="sidebar-footer">Cloud Identity Toolkit<br>Get-PrivilegedUsersReport.ps1</div>
</div>

<div id="main">

  <!-- ═══ OVERVIEW ═══ -->
  <div class="page active" id="page-overview">
    <h1>Privileged Users Report — Overview</h1>
    <div class="pagesub">__TOTAL__ privileged principals found across active + eligible Entra directory role assignments</div>

    <div class="summary-panel">__SUMMARYTEXT__</div>

    <div class="stats-grid">
      <div class="stat-card c-red"><div class="stat-icon">👑</div><div class="stat-val">__GACOUNT__</div><div class="stat-lbl">Global Administrators</div></div>
      <div class="stat-card"><div class="stat-icon">🔢</div><div class="stat-val">__TOTAL__</div><div class="stat-lbl">Total Privileged</div></div>
      <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-val">__ACTIVEONLY__</div><div class="stat-lbl">Active Only</div></div>
      <div class="stat-card c-amber"><div class="stat-icon">⏳</div><div class="stat-val">__ELIGIBLEONLY__</div><div class="stat-lbl">Eligible Only</div></div>
      <div class="stat-card c-purple"><div class="stat-icon">🔁</div><div class="stat-val">__BOTHCOUNT__</div><div class="stat-lbl">Active + Eligible</div></div>
      <div class="stat-card c-cyan"><div class="stat-icon">👤</div><div class="stat-val">__USERCOUNT__</div><div class="stat-lbl">Human Users</div></div>
      <div class="stat-card"><div class="stat-icon">🤖</div><div class="stat-val">__NONHUMANCOUNT__</div><div class="stat-lbl">Groups + Service Principals</div></div>
    </div>

    <div class="overview-grid">
      <div class="panel">
        <h3>📊 Top Privileged Roles</h3>
        __ROLEBARS__
      </div>
      <div class="panel gauge-wrap">
        <h3 style="align-self:flex-start">⚠️ Indicative Risk</h3>
        <svg id="gaugeSvg" width="140" height="140" viewBox="0 0 140 140"></svg>
        <div class="gauge-val">__RISKSCORE__ / 100</div>
        <div class="gauge-lvl" style="background:rgba(0,0,0,.15);color:__RISKCOLOR__">__RISKLEVEL__</div>
        <div style="font-size:10.5px;color:var(--muted);text-align:center;margin-top:4px">Heuristic estimate — not Microsoft Secure Score</div>
      </div>
    </div>
  </div>

  <!-- ═══ FINDINGS ═══ -->
  <div class="page" id="page-findings">
    <h1>Findings</h1>
    <div class="pagesub">Notable conditions worth a closer look, grouped by theme</div>

    <div class="findings-panel">
      <h3>🚨 Global Administrator Holders — Highest Blast Radius</h3>
      __GACHIPS__
    </div>

    <div class="findings-panel amber">
      <h3>⏳ Always-On (Active-Only) Privileged Assignments</h3>
      __ACTIVEONLYTABLE__
    </div>

    <div class="findings-panel amber">
      <h3>🤖 Non-Human Privileged Principals</h3>
      __NONHUMANTABLE__
    </div>

    <div class="findings-panel cyan">
      <h3>❓ Unresolved Principals</h3>
      __UNRESOLVEDTABLE__
    </div>
  </div>

  <!-- ═══ ANALYTICS ═══ -->
  <div class="page" id="page-analytics">
    <h1>Analytics</h1>
    <div class="pagesub">Distribution of privileged access by role, type, assignment, and source</div>

    <div class="panel">
      <h3>📊 Top Privileged Roles</h3>
      __ROLEBARS2__
    </div>

    <div class="chart-grid3">
      <div class="panel">
        <h3>🧬 Principal Type</h3>
        <div class="donut-wrap">
          <svg id="donutType" width="120" height="120" viewBox="0 0 140 140"></svg>
          <div id="legendType"></div>
        </div>
      </div>
      <div class="panel">
        <h3>🔁 Assignment Type</h3>
        <div class="donut-wrap">
          <svg id="donutAssign" width="120" height="120" viewBox="0 0 140 140"></svg>
          <div id="legendAssign"></div>
        </div>
      </div>
      <div class="panel">
        <h3>🏷 Role Source</h3>
        <div class="donut-wrap">
          <svg id="donutSrc" width="120" height="120" viewBox="0 0 140 140"></svg>
          <div id="legendSrc"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ═══ DATA ═══ -->
  <div class="page" id="page-data">
    <h1>Full Privileged Principal List</h1>
    <div class="pagesub">Search, filter, and export the complete underlying dataset</div>

    <div class="panel">
      <div class="toolbar">
        <div class="srch-wrap"><span class="si">🔎</span><input type="text" id="search" placeholder="Search name, UPN, role…" oninput="renderTable()"></div>
        <select id="fType" class="filter-select" onchange="renderTable()">
          <option value="">All Types</option>
          <option value="user">Users</option>
          <option value="group">Groups</option>
          <option value="servicePrincipal">Service Principals</option>
        </select>
        <select id="fAssign" class="filter-select" onchange="renderTable()">
          <option value="">All Assignments</option>
          <option value="activeOnly">Active Only</option>
          <option value="eligibleOnly">Eligible Only</option>
          <option value="both">Active + Eligible</option>
        </select>
        <select id="fSrc" class="filter-select" onchange="renderTable()">
          <option value="">All Sources</option>
          <option value="BuiltIn">Built-in Only</option>
          <option value="Custom">Custom Only</option>
          <option value="Both">Built-in + Custom</option>
        </select>
        <label class="ga-only-label"><input type="checkbox" id="fGaOnly" onchange="renderTable()"> 👑 GA only</label>
        <button class="btn" onclick="resetFilters()">✕ Reset</button>
        <button class="btn" onclick="exportCsvFromTable()">⬇ Export CSV</button>
        <span class="rcount" id="rcount"></span>
      </div>
      <div style="overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius-sm)">
        <table>
          <thead><tr><th>Display Name</th><th>UPN / App ID</th><th>Type</th><th>Privileged Roles</th><th>Assignment</th><th>Source</th></tr></thead>
          <tbody id="tblBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ═══ RECOMMENDATIONS ═══ -->
  <div class="page" id="page-recs">
    <h1>Recommendations</h1>
    <div class="pagesub">Prioritized, data-driven suggestions — business impact and technical action for each</div>
    __RECCARDS__
  </div>

</div>

<div id="toast"></div>

<script>
const DATA = [
__ROWS_JSON__
];
const DONUT_TYPE   = __TYPE_DONUT_JSON__;
const DONUT_ASSIGN = __ASSIGN_DONUT_JSON__;
const DONUT_SRC    = __SRC_DONUT_JSON__;
const RISK_SCORE   = __RISKSCORE__;
const RISK_COLOR   = "__RISKCOLOR__";

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id, btnEl){
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  if (btnEl) btnEl.classList.add('active');
}

function showToast(msg){
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2200);
}

function srcCategory(src){
  const has = s => src.includes(s);
  if (has('Both') || (has('BuiltIn') && has('Custom'))) return 'Both';
  if (has('BuiltIn')) return 'BuiltIn';
  if (has('Custom')) return 'Custom';
  return '';
}

function getFilteredData(){
  const q       = document.getElementById('search').value.toLowerCase().trim();
  const fType   = document.getElementById('fType').value;
  const fAssign = document.getElementById('fAssign').value;
  const fSrc    = document.getElementById('fSrc').value;
  const gaOnly  = document.getElementById('fGaOnly').checked;
  return DATA.filter(d => {
    if (q && !(d.dn+d.upn+d.roles+d.ot).toLowerCase().includes(q)) return false;
    if (fType && d.ot !== fType) return false;
    if (fAssign === 'activeOnly'   && !(d.atype.includes('Active') && !d.atype.includes('Eligible'))) return false;
    if (fAssign === 'eligibleOnly' && !(d.atype.includes('Eligible') && !d.atype.includes('Active'))) return false;
    if (fAssign === 'both'         && !(d.atype.includes('Active') && d.atype.includes('Eligible'))) return false;
    if (fSrc && srcCategory(d.src) !== fSrc) return false;
    if (gaOnly && !d.ga) return false;
    return true;
  });
}

function resetFilters(){
  document.getElementById('search').value = '';
  document.getElementById('fType').value = '';
  document.getElementById('fAssign').value = '';
  document.getElementById('fSrc').value = '';
  document.getElementById('fGaOnly').checked = false;
  renderTable();
}

function renderTable(){
  const filtered = getFilteredData();
  document.getElementById('rcount').textContent = `${filtered.length} of ${DATA.length}`;
  document.getElementById('tblBody').innerHTML = filtered.map(d =>
    `<tr class="${d.ga ? 'ga-row' : ''}"><td>${d.ga ? '👑 ' : ''}${escH(d.dn)}</td><td>${escH(d.upn)}</td><td>${escH(d.ot)}</td><td>${escH(d.roles)}</td><td>${escH(d.atype)}</td><td>${escH(d.src)}</td></tr>`
  ).join('');
}

function exportCsvFromTable(){
  const filtered = getFilteredData();
  const esc = v => `"${String(v||'').replace(/"/g,'""')}"`;
  const hdr = ['DisplayName','UPN','ObjectType','PrivilegedRoles','AssignmentType','Source'].map(esc).join(',');
  const rows = filtered.map(d => [d.dn,d.upn,d.ot,d.roles,d.atype,d.src].map(esc).join(','));
  const blob = new Blob([[hdr,...rows].join('\r\n')], {type:'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'PrivilegedUsers.csv'; a.click();
  showToast(`Exported ${filtered.length} rows`);
}

function drawDonutInto(svgId, legendId, segs){
  const total = segs.reduce((s,d)=>s+d.v,0);
  const svg = document.getElementById(svgId);
  if(!svg || total === 0) return;
  const r = 55, cx = 70, cy = 70, circ = 2*Math.PI*r;
  let offset = 0;
  let legendHtml = '';
  segs.forEach(seg => {
    const pct = seg.v/total;
    const dash = pct*circ;
    const circle = document.createElementNS('http://www.w3.org/2000/svg','circle');
    circle.setAttribute('cx',cx); circle.setAttribute('cy',cy); circle.setAttribute('r',r);
    circle.setAttribute('fill','none'); circle.setAttribute('stroke',seg.c);
    circle.setAttribute('stroke-width','18');
    circle.setAttribute('stroke-dasharray', `${dash} ${circ-dash}`);
    circle.setAttribute('stroke-dashoffset', -offset);
    circle.setAttribute('transform', `rotate(-90 ${cx} ${cy})`);
    svg.appendChild(circle);
    offset += dash;
    legendHtml += `<div class="legend-item"><span class="legend-dot" style="background:${seg.c}"></span>${escH(seg.l)}: <b style="margin-left:4px">${seg.v}</b></div>`;
  });
  const legendEl = document.getElementById(legendId);
  if (legendEl) legendEl.innerHTML = legendHtml;
}

function drawGauge(){
  const svg = document.getElementById('gaugeSvg');
  if(!svg) return;
  const r = 55, cx = 70, cy = 70, circ = 2*Math.PI*r;
  const pct = Math.max(0, Math.min(RISK_SCORE, 100))/100;
  const dash = pct*circ;
  const track = document.createElementNS('http://www.w3.org/2000/svg','circle');
  track.setAttribute('cx',cx); track.setAttribute('cy',cy); track.setAttribute('r',r);
  track.setAttribute('fill','none'); track.setAttribute('stroke','var(--surface2)');
  track.setAttribute('stroke-width','14');
  svg.appendChild(track);
  const fill = document.createElementNS('http://www.w3.org/2000/svg','circle');
  fill.setAttribute('cx',cx); fill.setAttribute('cy',cy); fill.setAttribute('r',r);
  fill.setAttribute('fill','none'); fill.setAttribute('stroke',RISK_COLOR);
  fill.setAttribute('stroke-width','14'); fill.setAttribute('stroke-linecap','round');
  fill.setAttribute('stroke-dasharray', `${dash} ${circ-dash}`);
  fill.setAttribute('transform', `rotate(-90 ${cx} ${cy})`);
  svg.appendChild(fill);
}

function animateBars(){
  document.querySelectorAll('.bar-fill').forEach(el=>{
    const pct = el.getAttribute('data-pct');
    requestAnimationFrame(()=> el.style.width = pct+'%');
  });
}

document.getElementById('darkBtn').onclick = ()=>{
  document.body.classList.remove('light-theme');
  document.getElementById('darkBtn').classList.add('active');
  document.getElementById('lightBtn').classList.remove('active');
};
document.getElementById('lightBtn').onclick = ()=>{
  document.body.classList.add('light-theme');
  document.getElementById('lightBtn').classList.add('active');
  document.getElementById('darkBtn').classList.remove('active');
};

renderTable();
drawDonutInto('donutType','legendType', DONUT_TYPE);
drawDonutInto('donutAssign','legendAssign', DONUT_ASSIGN);
drawDonutInto('donutSrc','legendSrc', DONUT_SRC);
drawGauge();
animateBars();
</script>
</body>
</html>
'@

    $typeDonutJson   = "[" + (($typeDonutParts   | ForEach-Object { "{l:`"$(ConvertTo-JsonSafe $_.Label)`",v:$($_.Value),c:`"$($_.Color)`"}" }) -join ",") + "]"
    $assignDonutJson = "[" + (($assignDonutParts | ForEach-Object { "{l:`"$(ConvertTo-JsonSafe $_.Label)`",v:$($_.Value),c:`"$($_.Color)`"}" }) -join ",") + "]"
    $srcDonutJson    = "[" + (($srcDonutParts    | ForEach-Object { "{l:`"$(ConvertTo-JsonSafe $_.Label)`",v:$($_.Value),c:`"$($_.Color)`"}" }) -join ",") + "]"

    $html = $html `
        -replace '__GENTIME__',        $genTime `
        -replace '__TOTAL__',          $total `
        -replace '__GACOUNT__',        $globalAdmins.Count `
        -replace '__ACTIVEONLY__',     $activeOnly `
        -replace '__ELIGIBLEONLY__',   $eligibleOnly `
        -replace '__BOTHCOUNT__',      $bothTypes `
        -replace '__USERCOUNT__',      $userCount `
        -replace '__NONHUMANCOUNT__',  ($groupCount + $spCount) `
        -replace '__GACHIPS__',        $gaChipsHtml `
        -replace '__ROLEBARS2__',      $roleBarsHtml `
        -replace '__ROLEBARS__',       $roleBarsHtml `
        -replace '__ACTIVEONLYTABLE__',$activeOnlyTableHtml `
        -replace '__NONHUMANTABLE__',  $nonHumanTableHtml `
        -replace '__UNRESOLVEDTABLE__',$unresolvedTableHtml `
        -replace '__RECCARDS__',       $recCardsHtml `
        -replace '__SUMMARYTEXT__',    (ConvertTo-JsonSafe $summaryText) `
        -replace '__RISKSCORE__',      $riskScore `
        -replace '__RISKLEVEL__',      $riskLevel `
        -replace '__RISKCOLOR__',      $riskColor `
        -replace '__ROWS_JSON__',      $rowsJs `
        -replace '__TYPE_DONUT_JSON__',   $typeDonutJson `
        -replace '__ASSIGN_DONUT_JSON__',$assignDonutJson `
        -replace '__SRC_DONUT_JSON__',   $srcDonutJson

    $html | Out-File -FilePath $Path -Encoding UTF8 -Force

    if ($unresolvedCnt -gt 0)
    {
        Write-Warning "$unresolvedCnt of $total principals could not be resolved to a display name (deleted/external objects, or a resolution batch failure logged above)."
    }
}

# ── Main entry point ──────────────────────────────────────────────────────────
function Get-PrivilegedUsersReport
{
    [CmdletBinding(DefaultParameterSetName = 'ClientCredential')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredential')]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredential')]
        [string]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = 'ClientCredential')]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ParameterSetName = 'BringYourOwnToken')]
        [string]$AccessToken,

        [string[]]$CustomPrivilegedRoles,
        [switch]$IncludeEligibleRoles,

        [switch]$ExportCsv,
        [string]$CsvPath,

        [switch]$ExportHtml,
        [string]$HtmlPath,

        [switch]$OpenBrowser
    )

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    if (-not $CsvPath)  { $CsvPath  = "$env:TEMP\PrivilegedUsersReport_$stamp.csv" }
    if (-not $HtmlPath) { $HtmlPath = "$env:TEMP\PrivilegedUsersReport_$stamp.html" }

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │   PRIVILEGED USERS REPORT  ›  Emergency / On-Demand Mode     │" -ForegroundColor DarkCyan
    Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan

    # ── Step 1: Authenticate ──
    if ($PSCmdlet.ParameterSetName -eq 'ClientCredential')
    {
        Write-Host "  ⏳ Authenticating (client credential flow)..." -ForegroundColor Yellow
        $t = Get-ClientCredentialToken -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId
        $script:AuthMode      = 'ClientCredential'
        $script:ClientId      = $ClientId
        $script:ClientSecret  = $ClientSecret
        $script:TenantId      = $TenantId
        $script:AccessToken   = $t.AccessToken
        $script:TokenExpiresOn = $t.ExpiresOn
        Write-Host "  ✅ Authenticated — token auto-renews if this run exceeds its lifetime" -ForegroundColor Green
    }
    else
    {
        $script:AuthMode      = 'BringYourOwnToken'
        $script:AccessToken   = $AccessToken
        $script:TokenExpiresOn = Get-JwtExpiry -Token $AccessToken
        if ($script:TokenExpiresOn)
        {
            $mins = [math]::Round((New-TimeSpan -Start (Get-Date) -End $script:TokenExpiresOn).TotalMinutes, 1)
            if ($mins -le 0) { throw "The provided AccessToken is already expired." }
            Write-Host "  ✅ Using supplied token — expires in ~$mins min (no auto-renew in this mode)" -ForegroundColor Green
        }
        else
        {
            Write-Host "  ⚠️  Could not parse token expiry — proceeding without expiry monitoring" -ForegroundColor Yellow
        }
    }

    # ── Step 2: Role definitions ──
    Write-Host ""
    Write-Host "  ⏳ Retrieving role definitions..." -ForegroundColor Yellow
    $defs = Get-AllGraphPages -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?`$select=id,displayName,isPrivileged"
    $roleDefinitions = @{}
    foreach ($d in $defs) { $roleDefinitions[$d.id] = [PSCustomObject]@{ DisplayName = $d.displayName; IsPrivileged = [bool]$d.isPrivileged } }
    $customSet = @()
    if ($CustomPrivilegedRoles) { $customSet = $CustomPrivilegedRoles | ForEach-Object { $_.Trim().ToLowerInvariant() } }
    Write-Host "  ✅ $($roleDefinitions.Count) role definitions retrieved" -ForegroundColor Green

    # ── Step 3: Active + (optional) eligible assignments ──
    Write-Host "  ⏳ Retrieving active role assignments..." -ForegroundColor Yellow
    $active = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$select=principalId,roleDefinitionId"
    Write-Host "  ✅ $($active.Count) active assignments retrieved" -ForegroundColor Green

    $eligible = @()
    if ($IncludeEligibleRoles)
    {
        Write-Host "  ⏳ Retrieving PIM-eligible role assignments (requires Entra ID P2)..." -ForegroundColor Yellow
        Try
        {
            $eligible = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$select=principalId,roleDefinitionId"
            Write-Host "  ✅ $($eligible.Count) eligible assignments retrieved" -ForegroundColor Green
        }
        Catch
        {
            Write-Warning "Could not retrieve PIM-eligible assignments (tenant may lack Entra ID P2, or RoleManagement.Read.Directory is not granted). Continuing with active-role data only. Details: $($_.Exception.Message)"
        }
    }

    # ── Step 4: Build per-principal lookup, privileged only ──
    $lookup = @{}
    function Add-Hit($PrincipalId, $Def, $AssignmentType)
    {
        if (-not $Def) { return }
        $isCustom = $customSet -contains $Def.DisplayName.ToLowerInvariant()
        if (-not ($Def.IsPrivileged -or $isCustom)) { return }

        if (-not $lookup.ContainsKey($PrincipalId))
        {
            $lookup[$PrincipalId] = [PSCustomObject]@{
                PrivilegedRoles = New-Object System.Collections.Generic.List[string]
                AssignmentTypes = New-Object System.Collections.Generic.List[string]
                Sources         = New-Object System.Collections.Generic.List[string]
            }
        }
        $entry = $lookup[$PrincipalId]
        if (-not $entry.PrivilegedRoles.Contains($Def.DisplayName)) { $entry.PrivilegedRoles.Add($Def.DisplayName) }
        if (-not $entry.AssignmentTypes.Contains($AssignmentType))  { $entry.AssignmentTypes.Add($AssignmentType) }
        $src = if ($Def.IsPrivileged -and $isCustom) { 'Both' } elseif ($Def.IsPrivileged) { 'BuiltIn' } else { 'Custom' }
        if (-not $entry.Sources.Contains($src)) { $entry.Sources.Add($src) }
    }
    foreach ($a in $active)   { Add-Hit $a.principalId $roleDefinitions[$a.roleDefinitionId] 'Active' }
    foreach ($e in $eligible) { Add-Hit $e.principalId $roleDefinitions[$e.roleDefinitionId] 'Eligible' }

    if ($lookup.Count -eq 0)
    {
        Write-Host "  ⚠️  No privileged principals found." -ForegroundColor Yellow
        return @()
    }

    # ── Step 5: Resolve principal identities ──
    Write-Host "  ⏳ Resolving $($lookup.Count) principal identities..." -ForegroundColor Yellow
    $identities = Resolve-PrincipalDetails -PrincipalIds @($lookup.Keys)
    Write-Host "  ✅ Identity resolution complete" -ForegroundColor Green

    $report = foreach ($id in $lookup.Keys)
    {
        $who = $identities[$id]
        [PSCustomObject]@{
            PrincipalId     = $id
            DisplayName     = if ($who) { $who.DisplayName } else { '(unresolved)' }
            UPN             = if ($who) { $who.UPN } else { '' }
            ObjectType      = if ($who) { $who.ObjectType } else { 'unknown' }
            PrivilegedRoles = @($lookup[$id].PrivilegedRoles)
            AssignmentTypes = @($lookup[$id].AssignmentTypes)
            Sources         = @($lookup[$id].Sources)
        }
    }
    $report = $report | Sort-Object DisplayName

    # ── Step 6: Exports ──
    if ($ExportCsv)
    {
        $report | Select-Object PrincipalId, DisplayName, UPN, ObjectType,
            @{N='PrivilegedRoles';E={$_.PrivilegedRoles -join '; '}},
            @{N='AssignmentTypes';E={$_.AssignmentTypes -join '; '}},
            @{N='Sources';E={$_.Sources -join '; '}} |
            Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "  📄 CSV exported: $CsvPath" -ForegroundColor Gray
    }
    if ($ExportHtml)
    {
        Export-PrivilegedUsersHtml -Data $report -Path $HtmlPath
        Write-Host "  📄 HTML exported: $HtmlPath" -ForegroundColor Gray
        if ($OpenBrowser) { Start-Process $HtmlPath }
    }

    Write-Host ""
    Write-Host "  ✅ $($report.Count) privileged principals resolved" -ForegroundColor Green
    Write-Host ""

    return $report
}
