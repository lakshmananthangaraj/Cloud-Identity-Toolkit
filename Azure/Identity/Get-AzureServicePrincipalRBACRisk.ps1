<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 21 August 2026
Modified-On     : 21 August 2026

.SYNOPSIS
    Correlates Entra ID service principals with Azure RBAC assignments and scores
    each workload identity for excessive privilege, credential hygiene, and
    multi-tenant exposure risk.

.DESCRIPTION
    Get-AzureServicePrincipalRBACRisk builds a unified risk picture of every
    service principal in the tenant by joining four data sources that no single
    Azure portal blade surfaces together:

        Source 1 — Entra ID (Microsoft Graph)
            Service principal metadata: display name, app ID, sign-in audience,
            sign-in activity (last sign-in date), credential objects (secrets and
            certificates), owner list, multi-tenant flag, managed identity type.

        Source 2 — Azure RBAC
            All role assignments across scopes where the authenticated account
            has Reader access. Each assignment is resolved to scope level
            (Management Group / Subscription / Resource Group / Resource) and
            built-in role sensitivity tier (Critical / High / Medium / Low).

        Source 3 — Credential hygiene
            For each secret or certificate: expiry date, days remaining, state
            (Expired / Expiring ≤ 30d / Expiring ≤ 90d / Valid / No Credentials).

        Source 4 — Ownership and accountability
            Owner count per SP, guest-user owner detection, orphaned SPs (zero
            owners), and whether the owning application is a multi-tenant app.

    Risk Scoring Model (0 – 100):
        Each service principal is given a composite risk score built from
        six weighted dimensions:

        Dimension                    Weight  Max points
        ─────────────────────────────────────────────────
        RBAC Scope Breadth            25     Owner/Contrib at Subscription or MG
        RBAC Role Sensitivity         20     Critical built-in roles (Owner, UAMI Op)
        Credential Hygiene            20     Expired / near-expiry secrets
        Stale Sign-In Activity        15     No sign-in > 90 days with high RBAC
        Multi-Tenant Exposure         10     signInAudience = AzureADMultipleOrgs
        Ownership Accountability      10     No owners, or guest-owned

        Score thresholds:
            75 – 100  →  Critical Risk  (immediate remediation)
            50 –  74  →  High Risk      (remediate within 30 days)
            25 –  49  →  Medium Risk    (review and schedule remediation)
             0 –  24  →  Low Risk       (monitor)

    Assessment outputs:
        - Color-coded console progress and per-subscription RBAC summary
        - Interactive HTML dashboard (dark/light theme, sortable table, filterable
          by risk tier / SP type / scope, detail drawer per SP with full credential
          and RBAC breakdown, risk distribution charts, score gauge)
        - Optional CSV export of all findings

.PARAMETER SubscriptionIds
    String array of Azure subscription IDs to enumerate for RBAC assignments.
    When omitted, all subscriptions visible to the authenticated account are
    scanned for RBAC assignments.

.PARAMETER IncludeGraphSignInActivity
    Switch. Fetches the last sign-in date for each service principal via
    Microsoft Graph (beta endpoint: signInActivity). Requires AuditLog.Read.All
    permission. When absent or if the call fails, sign-in activity is marked
    "Not Available" and the stale-activity dimension contributes zero risk score.

.PARAMETER ExportToCsv
    Switch. Exports all service principal risk findings to -CsvPath.
    The HTML dashboard is always generated regardless of this switch.

.PARAMETER CsvPath
    Path for the CSV export when -ExportToCsv is specified. The HTML dashboard
    is saved with the same base name and a .html extension.
    Default: C:\Temp\AzureServicePrincipalRBACRisk-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard. Optionally
    writes CSV when -ExportToCsv is specified.

.EXAMPLE
    Get-AzureServicePrincipalRBACRisk

.EXAMPLE
    Get-AzureServicePrincipalRBACRisk -IncludeGraphSignInActivity -ExportToCsv

.EXAMPLE
    Get-AzureServicePrincipalRBACRisk -SubscriptionIds @("sub-id-1","sub-id-2") -IncludeGraphSignInActivity -ExportToCsv -CsvPath "C:\Reports\SPRiskReport.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (21-Aug-2026) - Initial release. Entra ID + Azure RBAC correlation,
                            six-dimension risk scoring, credential hygiene,
                            multi-tenant and ownership risk. Graph sign-in activity
                            optional. HTML dashboard and optional CSV export.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module — Az.Accounts, Az.Resources.
           Installed automatically with user consent if not present.
        2. Microsoft.Graph PowerShell module — Microsoft.Graph.Applications,
           Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users.
           Installed automatically with user consent if not present.
        3. Authenticated Azure session (Connect-AzAccount) for RBAC data.
        4. Microsoft Graph authentication (Connect-MgGraph) — prompted
           automatically if no active session is found.
        5. Required Microsoft Graph permissions (delegated or app):
               Application.Read.All          — SP and app metadata, credentials
               Directory.Read.All            — Owner resolution
               AuditLog.Read.All             — Required only for -IncludeGraphSignInActivity
        6. Reader role at subscription scope for each subscription to be scanned.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Sign-in activity via Graph beta endpoint may not reflect service
          principal OAuth flows that do not generate an interactive sign-in;
          daemon/M2M flows using client credentials may appear stale even
          when actively used.
        - Managed Identity RBAC assignments are included in the report but
          their credential hygiene dimension is always scored 0 (managed
          identities have no user-managed secrets or certificates).
        - RBAC enumeration at Management Group scope requires the authenticated
          account to have Reader at the MG level; otherwise only subscription-
          scoped assignments are returned.
        - The Graph API rate-limits large tenants. On tenants with >5,000
          service principals, the scan may take several minutes.
        - Multi-tenant detection relies on the signInAudience property. SPs of
          type ManagedIdentity always show AzureADMyOrg regardless of actual scope.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.

.LINK
    https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals
    https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list
    https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
    https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview
    https://learn.microsoft.com/en-us/graph/api/resources/signin

#>


#------------------------------------------------------------------------ [ Risk Model ]

# Role sensitivity tiers — used in RBAC role sensitivity dimension scoring
$script:CRITICAL_ROLES = @(
    "Owner",
    "User Access Administrator",
    "Role Based Access Control Administrator",
    "Privileged Role Administrator",
    "Azure AD Join",
    "Global Administrator"      # Rare but possible via cross-sync
)

$script:HIGH_ROLES = @(
    "Contributor",
    "Network Contributor",
    "Virtual Machine Contributor",
    "Storage Account Contributor",
    "Key Vault Administrator",
    "Key Vault Secrets Officer",
    "Security Admin",
    "Azure Kubernetes Service Cluster Admin Role",
    "Azure Arc ScVmm Administrator role",
    "Managed Identity Operator"
)

$script:MEDIUM_ROLES = @(
    "Reader",
    "Monitoring Contributor",
    "Log Analytics Contributor",
    "Automation Operator",
    "API Management Service Contributor",
    "Azure Service Bus Data Owner"
)

# Scope breadth risk scores
$script:SCOPE_RISK = @{
    "Management Group" = 25
    "Subscription"     = 20
    "Resource Group"   = 8
    "Resource"         = 3
}

# Role sensitivity risk scores
$script:ROLE_RISK = @{
    "Critical" = 20
    "High"     = 14
    "Medium"   = 7
    "Low"      = 2
}


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CenteredText
{
    param(
        [string]$Text,
        [int]$Width    = 80,
        [string]$Color = "White"
    )
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-Banner
{
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Service Principal RBAC Risk Assessment v1.0" -Color White
    Write-CenteredText "Workload Identity · Least Privilege · Credential Hygiene" -Color DarkGray
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-Section
{
    param(
        [string]$Title,
        [hashtable]$Data
    )
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($key in $Data.Keys)
    {
        $value = $Data[$key]
        if ([string]::IsNullOrWhiteSpace($value)) { $value = "None"; $valColor = "DarkGray" }
        else { $valColor = "White" }
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(30) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-ProgressBar
{
    param(
        [int]$Current,
        [int]$Total,
        [string]$CurrentItem,
        [int]$BarWidth = 40
    )
    $percentage  = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
    $completed   = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $remaining   = $BarWidth - $completed
    $bar         = ("█" * $completed) + ("░" * $remaining)
    Write-Host "`r" -NoNewline
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White
    if ($CurrentItem)
    {
        $maxLen      = 32
        $displayItem = if ($CurrentItem.Length -gt $maxLen) { $CurrentItem.Substring(0, $maxLen - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-RiskSummary
{
    param([array]$Findings)
    $critical = @($Findings | Where-Object { $_.RiskTier -eq "Critical" }).Count
    $high     = @($Findings | Where-Object { $_.RiskTier -eq "High" }).Count
    $medium   = @($Findings | Where-Object { $_.RiskTier -eq "Medium" }).Count
    $low      = @($Findings | Where-Object { $_.RiskTier -eq "Low" }).Count

    Write-Host ""
    Write-Host "  Risk Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  " -NoNewline; Write-Host "Service Principals Assessed".PadRight(34) -NoNewline -ForegroundColor Gray
    Write-Host ": $($Findings.Count)" -ForegroundColor White
    Write-Host "  " -NoNewline; Write-Host "Critical Risk".PadRight(34) -NoNewline -ForegroundColor Red
    Write-Host ": $critical  (score 75–100 — immediate remediation)" -ForegroundColor White
    Write-Host "  " -NoNewline; Write-Host "High Risk".PadRight(34)     -NoNewline -ForegroundColor Yellow
    Write-Host ": $high  (score 50–74 — remediate within 30 days)" -ForegroundColor White
    Write-Host "  " -NoNewline; Write-Host "Medium Risk".PadRight(34)   -NoNewline -ForegroundColor Cyan
    Write-Host ": $medium  (score 25–49 — review and schedule)" -ForegroundColor White
    Write-Host "  " -NoNewline; Write-Host "Low Risk".PadRight(34)      -NoNewline -ForegroundColor DarkGray
    Write-Host ": $low  (score 0–24 — monitor)" -ForegroundColor White
}

Function Write-TopRisks
{
    param([array]$Findings)
    $top = @($Findings | Sort-Object RiskScore -Descending | Select-Object -First 5)
    if ($top.Count -eq 0) { return }
    Write-Host ""
    Write-Host "  Top 5 Highest Risk Service Principals" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($sp in $top)
    {
        $tierColor = switch ($sp.RiskTier) { "Critical" { "Red" }; "High" { "Yellow" }; "Medium" { "Cyan" }; default { "DarkGray" } }
        $paddedName = if ($sp.DisplayName.Length -gt 38) { $sp.DisplayName.Substring(0, 35) + "..." } else { $sp.DisplayName }
        Write-Host "  " -NoNewline
        Write-Host ("[{0,3}] " -f $sp.RiskScore) -NoNewline -ForegroundColor $tierColor
        Write-Host $paddedName.PadRight(40) -NoNewline -ForegroundColor White
        Write-Host " $($sp.RiskTier)" -ForegroundColor $tierColor
    }
}

Function Write-OutputFiles
{
    param(
        [string]$CsvPath,
        [string]$HtmlPath,
        [bool]$GridViewOpened
    )
    Write-Host ""
    Write-Host "  Output Files" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    if ($CsvPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host "CSV Export".PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }
    if ($HtmlPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host "HTML Dashboard".PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }
    if ($GridViewOpened)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host "Grid View".PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": Opened in separate window" -ForegroundColor White
    }
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-ObjProperty
{
    param([object]$Obj, [string]$PropName, $Default = $null)
    try { $val = $Obj.$PropName; if ($null -ne $val) { return $val }; return $Default }
    catch { return $Default }
}

Function Get-RoleRiskTier
{
    param([string]$RoleName)
    if ($script:CRITICAL_ROLES -contains $RoleName) { return "Critical" }
    if ($script:HIGH_ROLES     -contains $RoleName) { return "High" }
    if ($script:MEDIUM_ROLES   -contains $RoleName) { return "Medium" }
    return "Low"
}

Function Get-ScopeLevel
{
    param([string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Scope)) { return "Unknown" }
    if ($Scope -like "*/providers/Microsoft.Management/managementGroups/*") { return "Management Group" }
    if ($Scope -match "^/subscriptions/[^/]+$")                            { return "Subscription" }
    if ($Scope -match "^/subscriptions/[^/]+/resourceGroups/[^/]+$")       { return "Resource Group" }
    return "Resource"
}

Function Compute-RiskScore
{
    param(
        [array]$RbacAssignments,        # All RBAC for this SP
        [string]$CredentialState,       # Expired / Expiring30 / Expiring90 / Valid / None / NA
        [string]$LastSignInDays,        # Integer string or "Unknown"
        [bool]$IsMultiTenant,
        [int]$OwnerCount,
        [bool]$HasGuestOwner
    )

    $score = 0

    # Dimension 1 — RBAC Scope Breadth (max 25)
    $maxScopeScore = 0
    foreach ($a in $RbacAssignments)
    {
        $scopeScore = if ($script:SCOPE_RISK.ContainsKey($a.ScopeLevel)) { $script:SCOPE_RISK[$a.ScopeLevel] } else { 3 }
        if ($scopeScore -gt $maxScopeScore) { $maxScopeScore = $scopeScore }
    }
    $score += $maxScopeScore

    # Dimension 2 — RBAC Role Sensitivity (max 20)
    $maxRoleScore = 0
    foreach ($a in $RbacAssignments)
    {
        $tier      = Get-RoleRiskTier -RoleName $a.RoleDefinitionName
        $roleScore = if ($script:ROLE_RISK.ContainsKey($tier)) { $script:ROLE_RISK[$tier] } else { 2 }
        if ($roleScore -gt $maxRoleScore) { $maxRoleScore = $roleScore }
    }
    $score += $maxRoleScore

    # Dimension 3 — Credential Hygiene (max 20)
    $credScore = switch ($CredentialState)
    {
        "Expired"    { 20 }
        "Expiring30" { 15 }
        "Expiring90" { 8  }
        "Valid"      { 0  }
        "None"       { 5  }   # No credentials at all is unusual — possible misconfiguration
        default      { 0  }
    }
    $score += $credScore

    # Dimension 4 — Stale Sign-In Activity (max 15)
    # Only applies if RBAC exists (idle SP with no RBAC is no risk)
    if ($RbacAssignments.Count -gt 0 -and $LastSignInDays -ne "Unknown")
    {
        try
        {
            $days = [int]$LastSignInDays
            if ($days -ge 180)     { $score += 15 }
            elseif ($days -ge 90)  { $score += 10 }
            elseif ($days -ge 60)  { $score += 5  }
        }
        catch { }
    }

    # Dimension 5 — Multi-Tenant Exposure (max 10)
    if ($IsMultiTenant -and $RbacAssignments.Count -gt 0) { $score += 10 }

    # Dimension 6 — Ownership Accountability (max 10)
    if ($OwnerCount -eq 0)       { $score += 10 }
    elseif ($HasGuestOwner)      { $score += 6  }
    elseif ($OwnerCount -gt 5)   { $score += 3  }   # Shared ownership dilutes accountability

    # Cap at 100
    return [math]::Min($score, 100)
}

Function Get-RiskTier
{
    param([int]$Score)
    if ($Score -ge 75) { return "Critical" }
    if ($Score -ge 50) { return "High" }
    if ($Score -ge 25) { return "Medium" }
    return "Low"
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\','\\\\' -replace "'","\'" -replace '"','\"' -replace "`n",' ' -replace "`r",' ' }

Function Generate-SPRiskHtml
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [hashtable]$RiskTierDist,
        [hashtable]$SpTypeDist,
        [hashtable]$CredStateDist,
        [hashtable]$ScopeDist,
        [string]$GeneratedOn,
        [bool]$SignInActivityIncluded
    )

    $total        = @($Findings).Count
    $critCount    = if ($RiskTierDist.ContainsKey("Critical")) { $RiskTierDist["Critical"] } else { 0 }
    $highCount    = if ($RiskTierDist.ContainsKey("High"))     { $RiskTierDist["High"]     } else { 0 }
    $medCount     = if ($RiskTierDist.ContainsKey("Medium"))   { $RiskTierDist["Medium"]   } else { 0 }
    $lowCount     = if ($RiskTierDist.ContainsKey("Low"))      { $RiskTierDist["Low"]       } else { 0 }

    $expiredCreds = if ($CredStateDist.ContainsKey("Expired"))    { $CredStateDist["Expired"]    } else { 0 }
    $exp30Creds   = if ($CredStateDist.ContainsKey("Expiring30")) { $CredStateDist["Expiring30"] } else { 0 }
    $orphanedSPs  = @($Findings | Where-Object { $_.OwnerCount -eq 0 -and $_.SPType -ne "ManagedIdentity" }).Count
    $multiTenant  = @($Findings | Where-Object { $_.IsMultiTenant -eq $true }).Count
    $withRbac     = @($Findings | Where-Object { $_.RbacAssignmentCount -gt 0 }).Count

    $siNote = if ($SignInActivityIncluded) { "Sign-in activity included via Graph beta" } else { "Sign-in activity skipped — use -IncludeGraphSignInActivity" }

    # ── Main findings table rows ───────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings)
    {
        $tierCls = switch ($f.RiskTier) { "Critical" { "badge-red" }; "High" { "badge-amber" }; "Medium" { "badge-blue" }; "Low" { "" }; default { "" } }
        $credCls = switch ($f.CredentialState)
        {
            "Expired"    { "badge-red" }
            "Expiring30" { "badge-amber" }
            "Expiring90" { "badge-amber" }
            "Valid"      { "badge-green" }
            default      { "" }
        }
        $credLabel = switch ($f.CredentialState)
        {
            "Expired"    { "Expired" }
            "Expiring30" { "≤30d" }
            "Expiring90" { "≤90d" }
            "Valid"      { "Valid" }
            "None"       { "No Creds" }
            default      { "N/A" }
        }
        $scoreBar = [math]::Min([math]::Max($f.RiskScore, 0), 100)
        $scoreColor = if ($f.RiskScore -ge 75) { "var(--red)" } elseif ($f.RiskScore -ge 50) { "var(--amber)" } elseif ($f.RiskScore -ge 25) { "var(--accent2)" } else { "var(--muted)" }
        $nameDisplay = if ($f.DisplayName.Length -gt 34) { EscHtml($f.DisplayName.Substring(0,31) + "...") } else { EscHtml $f.DisplayName }

        $findingRows += @"
          <tr onclick="showDetail($($Findings.IndexOf($f)))">
            <td title="$(EscHtml $f.DisplayName)">$nameDisplay</td>
            <td>
              <div style="display:flex;align-items:center;gap:8px;">
                <div style="flex:1;height:6px;background:var(--surface3);border-radius:3px;min-width:48px;">
                  <div style="height:100%;border-radius:3px;background:$scoreColor;width:$scoreBar%"></div>
                </div>
                <span style="font-family:var(--mono);font-size:11px;width:28px;text-align:right">$($f.RiskScore)</span>
              </div>
            </td>
            <td><span class="badge $(EscHtml $tierCls)">$(EscHtml $f.RiskTier)</span></td>
            <td><span class="type-badge">$(EscHtml $f.SPType)</span></td>
            <td>$(EscHtml $f.RbacAssignmentCount) assignment(s)</td>
            <td><span class="badge $(EscHtml $credCls)">$(EscHtml $credLabel)</span></td>
            <td>$(EscHtml $f.OwnerCount)</td>
            <td>$(if ($f.IsMultiTenant) { '<span class="badge badge-amber">Multi-Tenant</span>' } else { '<span style="color:var(--muted);font-size:11px">Single</span>' })</td>
          </tr>
"@
    }

    # ── Risk tier bar rows ─────────────────────────────────────────────────────
    $tierRows = ""
    $tierOrder = @("Critical","High","Medium","Low")
    $tierColors = @{ "Critical" = "var(--red)"; "High" = "var(--amber)"; "Medium" = "var(--accent2)"; "Low" = "var(--muted)" }
    foreach ($t in $tierOrder)
    {
        $cnt = if ($RiskTierDist.ContainsKey($t)) { $RiskTierDist[$t] } else { 0 }
        $pct = if ($total -gt 0) { [math]::Round(($cnt / $total) * 100) } else { 0 }
        $tierRows += @"
          <div class="bar-row">
            <span class="bar-label">$t</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$($tierColors[$t])"></div></div>
            <span class="bar-pct">$cnt ($pct%)</span>
          </div>
"@
    }

    # ── SP type bar rows ───────────────────────────────────────────────────────
    $typeRows = ""
    foreach ($t in ($SpTypeDist.GetEnumerator() | Sort-Object Value -Descending))
    {
        $pct = if ($total -gt 0) { [math]::Round(($t.Value / $total) * 100) } else { 0 }
        $typeRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $t.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($t.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Credential state bar rows ──────────────────────────────────────────────
    $credRows = ""
    $credOrder  = @("Expired","Expiring30","Expiring90","Valid","None","NA")
    $credLabels = @{ "Expired" = "Expired"; "Expiring30" = "Expiring ≤30d"; "Expiring90" = "Expiring ≤90d"; "Valid" = "Valid"; "None" = "No Credentials"; "NA" = "Managed Identity" }
    $credColors = @{ "Expired" = "var(--red)"; "Expiring30" = "var(--amber)"; "Expiring90" = "var(--amber)"; "Valid" = "var(--green)"; "None" = "var(--muted)"; "NA" = "var(--muted2)" }
    foreach ($c in $credOrder)
    {
        $cnt = if ($CredStateDist.ContainsKey($c)) { $CredStateDist[$c] } else { 0 }
        if ($cnt -eq 0) { continue }
        $pct = if ($total -gt 0) { [math]::Round(($cnt / $total) * 100) } else { 0 }
        $credRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $credLabels[$c])</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$($credColors[$c])"></div></div>
            <span class="bar-pct">$cnt ($pct%)</span>
          </div>
"@
    }

    # ── Scope distribution bar rows ────────────────────────────────────────────
    $scopeRows = ""
    foreach ($s in ($ScopeDist.GetEnumerator() | Sort-Object Value -Descending))
    {
        if ($s.Value -eq 0) { continue }
        $scopeTotal = ($ScopeDist.Values | Measure-Object -Sum).Sum
        $pct = if ($scopeTotal -gt 0) { [math]::Round(($s.Value / $scopeTotal) * 100) } else { 0 }
        $scopeRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $s.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($s.Value) ($pct%)</span>
          </div>
"@
    }

    # ── JSON for detail drawer ─────────────────────────────────────────────────
    $findingJson = "["
    foreach ($f in $Findings)
    {
        # Serialize RBAC assignments for drawer
        $rbacJson = "["
        foreach ($a in $f.RbacAssignments)
        {
            $rbacJson += "{" +
                """role"":""$(EscJ $a.RoleDefinitionName)""," +
                """tier"":""$(EscJ $a.RoleTier)""," +
                """scope"":""$(EscJ $a.Scope)""," +
                """scopeLevel"":""$(EscJ $a.ScopeLevel)""," +
                """sub"":""$(EscJ $a.SubscriptionName)""" +
                "},"
        }
        $rbacJson = $rbacJson.TrimEnd(",") + "]"

        $findingJson += "{" +
            """displayName"":""$(EscJ $f.DisplayName)""," +
            """appId"":""$(EscJ $f.AppId)""," +
            """objectId"":""$(EscJ $f.ObjectId)""," +
            """spType"":""$(EscJ $f.SPType)""," +
            """riskScore"":$($f.RiskScore)," +
            """riskTier"":""$(EscJ $f.RiskTier)""," +
            """credState"":""$(EscJ $f.CredentialState)""," +
            """credDetail"":""$(EscJ $f.CredentialDetail)""," +
            """isMultiTenant"":$(if ($f.IsMultiTenant) { 'true' } else { 'false' })," +
            """signInAudience"":""$(EscJ $f.SignInAudience)""," +
            """lastSignIn"":""$(EscJ $f.LastSignInDays)""," +
            """ownerCount"":$($f.OwnerCount)," +
            """hasGuestOwner"":$(if ($f.HasGuestOwner) { 'true' } else { 'false' })," +
            """owners"":""$(EscJ $f.OwnerNames)""," +
            """rbacCount"":$($f.RbacAssignmentCount)," +
            """rbac"":$rbacJson," +
            """scoreDimensions"":""$(EscJ $f.ScoreDimensions)""" +
            "},"
    }
    $findingJson = $findingJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure SP RBAC Risk Assessment</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;
  --border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;
  --green:#3fb950;--amber:#d29922;--red:#f85149;
  --text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);
}
html[data-theme="light"]{
  --bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;
  --border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;
  --green:#1a7f37;--amber:#b08000;--red:#cf222e;
  --text:#1f2328;--muted:#636c76;--muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;}
#sidebar{width:240px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:transform .25s;}
.logo-block{padding:22px 18px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,var(--red),var(--accent3));display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{display:inline-block;margin-top:8px;padding:2px 8px;border-radius:20px;font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent);border:1px solid var(--border);}
.nav-section{padding:14px 10px;flex:1;}
.nav-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;padding:0 8px;margin-bottom:6px;}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 12px;border:none;background:transparent;color:var(--muted2);font-size:13px;border-radius:var(--radius-sm);cursor:pointer;text-align:left;transition:background .15s,color .15s;position:relative;margin-bottom:2px;}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:var(--surface3);color:var(--accent);font-weight:600;}
.nav-btn.active::before{content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;background:var(--accent);border-radius:0 3px 3px 0;}
.nav-icon{font-size:16px;width:20px;text-align:center;}
.sidebar-footer{padding:14px 16px;border-top:1px solid var(--border);}
.theme-toggle{display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:10px;}
.toggle-pill{width:40px;height:22px;border-radius:11px;border:none;cursor:pointer;background:var(--surface3);position:relative;transition:background .2s;}
.toggle-pill::after{content:'';position:absolute;top:3px;left:3px;width:16px;height:16px;border-radius:50%;background:var(--accent);transition:transform .2s;}
html[data-theme="light"] .toggle-pill::after{transform:translateX(18px);}
.footer-meta{font-size:10px;color:var(--muted);line-height:1.6;}
#main{margin-left:240px;padding:28px;width:calc(100% - 240px);min-height:100vh;}
.page{display:none;animation:fadeIn .2s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px);}to{opacity:1;transform:none;}}
.page-header{margin-bottom:22px;}
.page-title{font-size:22px;font-weight:700;}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:14px;margin-bottom:22px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-card.c-muted{border-top-color:var(--muted);}
.stat-num{font-size:30px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.chart-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:130px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:80px;text-align:right;flex-shrink:0;}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;}
.search-wrap input{width:100%;padding:8px 12px 8px 34px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;outline:none;}
.search-wrap input:focus{border-color:var(--accent);}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:14px;}
.filter-select{padding:7px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:12px;cursor:pointer;}
.tbl-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{padding:10px 12px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);background:var(--surface2);border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap;user-select:none;}
th:hover{color:var(--text);}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:middle;}
tr:hover td{background:var(--surface2);cursor:pointer;}
.pagination{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:12px;color:var(--muted);flex-wrap:wrap;}
.pg-btn{padding:4px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;}
.pg-btn:hover{border-color:var(--accent);color:var(--accent);}
.pg-btn.active{background:var(--accent);color:#fff;border-color:var(--accent);}
.pg-btn:disabled{opacity:.4;cursor:not-allowed;}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.type-badge{font-size:11px;font-family:var(--mono);color:var(--muted2);}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.notice-banner{padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:16px;display:flex;align-items:center;gap:10px;font-size:13px;}
.notice-banner.info{background:rgba(56,139,253,.08);border-color:rgba(56,139,253,.3);color:var(--accent);}
.notice-banner.warn{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3);color:var(--amber);}
/* Drawer */
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:520px;max-width:96vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
#detailDrawer.open{transform:translateX(0);}
.drawer-header{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.drawer-title{font-size:13px;font-weight:700;word-break:break-word;flex:1;margin-right:12px;}
.drawer-close{background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;padding:2px 6px;border-radius:var(--radius-sm);}
.drawer-close:hover{color:var(--text);background:var(--surface2);}
.drawer-body{padding:20px;overflow-y:auto;flex:1;}
.drawer-nav{display:flex;gap:8px;align-items:center;margin-bottom:16px;}
.drawer-nav-btn{padding:5px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;}
.drawer-nav-btn:hover{border-color:var(--accent);color:var(--accent);}
.drawer-nav-info{font-size:12px;color:var(--muted);flex:1;text-align:center;}
.score-gauge{text-align:center;margin-bottom:18px;}
.score-circle{display:inline-flex;align-items:center;justify-content:center;width:80px;height:80px;border-radius:50%;border:5px solid;font-size:22px;font-weight:700;font-family:var(--mono);}
.score-circle.tier-critical{border-color:var(--red);color:var(--red);}
.score-circle.tier-high{border-color:var(--amber);color:var(--amber);}
.score-circle.tier-medium{border-color:var(--accent2);color:var(--accent2);}
.score-circle.tier-low{border-color:var(--muted);color:var(--muted);}
.score-tier-label{margin-top:8px;font-size:12px;font-weight:700;}
.drawer-field{margin-bottom:12px;}
.drawer-field-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px;}
.drawer-field-value{font-size:13px;line-height:1.5;word-break:break-word;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.dim-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px;}
.dim-card{background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px;border:1px solid var(--border);}
.dim-label{font-size:10px;color:var(--muted);margin-bottom:2px;}
.dim-value{font-size:18px;font-weight:700;font-family:var(--mono);}
.rbac-row{display:flex;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);align-items:flex-start;}
.rbac-row:last-child{border-bottom:none;}
.rbac-role{font-size:12px;font-weight:600;flex:1;}
.rbac-meta{font-size:11px;color:var(--muted2);font-family:var(--mono);}
#toast{position:fixed;bottom:24px;right:24px;padding:12px 18px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);font-size:13px;box-shadow:var(--shadow);opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:300;}
#toast.show{opacity:1;transform:translateY(0);}
#menuToggle{display:none;}
@media(max-width:900px){
  .chart-grid-3{grid-template-columns:1fr 1fr;}
}
@media(max-width:768px){
  #menuToggle{display:flex;align-items:center;justify-content:center;position:fixed;top:12px;left:12px;z-index:300;width:36px;height:36px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:18px;}
  #sidebar{transform:translateX(-100%);}
  #sidebar.open{transform:translateX(0);}
  #main{margin-left:0;width:100%;padding:16px;padding-top:56px;}
  .chart-grid,.chart-grid-3{grid-template-columns:1fr;}
}
@media print{
  #sidebar,#menuToggle,#toast,#drawerBackdrop,#detailDrawer{display:none!important;}
  #main{margin-left:0;width:100%;}
  .page{display:block!important;}
}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🔑</div>
    <div class="logo-title">SP RBAC Risk</div>
    <div class="logo-sub">Workload Identity Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">⚠️</span> All Findings</button>
    <button class="nav-btn" onclick="showPage('credentials',this)"><span class="nav-icon">🔐</span> Credential Hygiene</button>
    <button class="nav-btn" onclick="showPage('rbac',this)"><span class="nav-icon">🛡️</span> RBAC Exposure</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      SP RBAC Risk Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Service Principal RBAC Risk</div>
      <div class="page-sub">Entra ID workload identity risk across __SUB_COUNT__ subscription(s) · __TOTAL__ service principals assessed</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRIT_COUNT__</div>
        <div class="stat-label">Critical Risk</div>
        <div class="stat-sub">Score 75–100</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High Risk</div>
        <div class="stat-sub">Score 50–74</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__MED_COUNT__</div>
        <div class="stat-label">Medium Risk</div>
        <div class="stat-sub">Score 25–49</div>
      </div>
      <div class="stat-card c-muted">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low Risk</div>
        <div class="stat-sub">Score 0–24</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__EXPIRED_CREDS__</div>
        <div class="stat-label">Expired Credentials</div>
        <div class="stat-sub">Immediate rotation needed</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__EXP30_CREDS__</div>
        <div class="stat-label">Expiring ≤30d</div>
        <div class="stat-sub">Act within 30 days</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__ORPHANED__</div>
        <div class="stat-label">Orphaned SPs</div>
        <div class="stat-sub">No owners assigned</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__MULTI_TENANT__</div>
        <div class="stat-label">Multi-Tenant</div>
        <div class="stat-sub">With RBAC assignments</div>
      </div>
    </div>

    <div class="notice-banner __SI_BANNER_CLS__">
      <span>📋</span>
      <span><strong>Sign-In Activity:</strong> __SI_NOTE__</span>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Risk Tier Distribution</div>
        __TIER_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🏷️ SP Type Distribution</div>
        __TYPE_ROWS__
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🔐 Credential State Distribution</div>
        __CRED_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">🎯 RBAC Scope Distribution</div>
        __SCOPE_ROWS__
      </div>
    </div>
  </div>

  <!-- All Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">All Service Principal Findings</div>
      <div class="page-sub">Sorted by risk score descending. Click any row to view full credential and RBAC detail.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search SP name, App ID…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterTier" onchange="filterFindings()">
          <option value="">All Risk Tiers</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-select" id="filterType" onchange="filterFindings()">
          <option value="">All SP Types</option>
          <option value="Application">Application</option>
          <option value="ManagedIdentity">Managed Identity</option>
          <option value="Legacy">Legacy</option>
        </select>
        <select class="filter-select" id="pgSizeFind" onchange="changeFindPageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="findTable">
          <thead>
            <tr>
              <th onclick="sortFindings(0)">Display Name</th>
              <th onclick="sortFindings(1)">Risk Score</th>
              <th onclick="sortFindings(2)">Risk Tier</th>
              <th onclick="sortFindings(3)">SP Type</th>
              <th onclick="sortFindings(4)">RBAC Assignments</th>
              <th onclick="sortFindings(5)">Credentials</th>
              <th onclick="sortFindings(6)">Owners</th>
              <th onclick="sortFindings(7)">Audience</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- Credential Hygiene -->
  <div id="page-credentials" class="page">
    <div class="page-header">
      <div class="page-title">Credential Hygiene</div>
      <div class="page-sub">Service principals with expired, near-expiry, or missing credentials</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="credSearch" placeholder="Search SP name…" oninput="filterCreds()"/>
        </div>
        <select class="filter-select" id="filterCredState" onchange="filterCreds()">
          <option value="">All States</option>
          <option value="Expired">Expired</option>
          <option value="Expiring30">Expiring ≤30d</option>
          <option value="Expiring90">Expiring ≤90d</option>
          <option value="None">No Credentials</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="credTable">
          <thead>
            <tr>
              <th onclick="sortCreds(0)">Display Name</th>
              <th onclick="sortCreds(1)">SP Type</th>
              <th onclick="sortCreds(2)">Credential State</th>
              <th onclick="sortCreds(3)">Credential Detail</th>
              <th onclick="sortCreds(4)">Risk Score</th>
              <th onclick="sortCreds(5)">RBAC Count</th>
            </tr>
          </thead>
          <tbody id="credBody"></tbody>
        </table>
      </div>
      <div class="pagination" id="credPagination"></div>
    </div>
  </div>

  <!-- RBAC Exposure -->
  <div id="page-rbac" class="page">
    <div class="page-header">
      <div class="page-title">RBAC Exposure</div>
      <div class="page-sub">Service principals with high-scope or sensitive role assignments</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="rbacSearch" placeholder="Search SP name, role…" oninput="filterRbac()"/>
        </div>
        <select class="filter-select" id="filterRbacScope" onchange="filterRbac()">
          <option value="">All Scopes</option>
          <option value="Management Group">Management Group</option>
          <option value="Subscription">Subscription</option>
          <option value="Resource Group">Resource Group</option>
          <option value="Resource">Resource</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="rbacTable">
          <thead>
            <tr>
              <th onclick="sortRbac(0)">Display Name</th>
              <th onclick="sortRbac(1)">Role</th>
              <th onclick="sortRbac(2)">Role Tier</th>
              <th onclick="sortRbac(3)">Scope Level</th>
              <th onclick="sortRbac(4)">Subscription</th>
              <th onclick="sortRbac(5)">SP Risk Score</th>
            </tr>
          </thead>
          <tbody id="rbacBody"></tbody>
        </table>
      </div>
      <div class="pagination" id="rbacPagination"></div>
    </div>
  </div>

  <!-- Session -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Scan Parameters</div>
      <div class="page-sub">Authentication context and configuration used for this assessment</div>
    </div>
    <div class="panel">
      <div class="panel-title">🔐 Session Information</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Tenant ID</div><div class="info-value">__TENANT__</div></div>
        <div class="info-card"><div class="info-label">Az Account</div><div class="info-value">__AZ_ACCOUNT__</div></div>
        <div class="info-card"><div class="info-label">Graph Account</div><div class="info-value">__GRAPH_ACCOUNT__</div></div>
        <div class="info-card"><div class="info-label">Generated On</div><div class="info-value">__GENERATED_ON__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">⚙️ Scan Parameters</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Subscription Scope</div><div class="info-value">__SCOPE__</div></div>
        <div class="info-card"><div class="info-label">Sign-In Activity</div><div class="info-value">__SI_PARAM__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">SPs Assessed</div><div class="info-value">__TOTAL__</div></div>
        <div class="info-card"><div class="info-label">Subscriptions Scanned</div><div class="info-value">__SUB_COUNT__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Risk Score Model</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">RBAC Scope Breadth</div><div class="info-value">Max 25 pts</div></div>
        <div class="info-card"><div class="info-label">RBAC Role Sensitivity</div><div class="info-value">Max 20 pts</div></div>
        <div class="info-card"><div class="info-label">Credential Hygiene</div><div class="info-value">Max 20 pts</div></div>
        <div class="info-card"><div class="info-label">Stale Sign-In Activity</div><div class="info-value">Max 15 pts</div></div>
        <div class="info-card"><div class="info-label">Multi-Tenant Exposure</div><div class="info-value">Max 10 pts</div></div>
        <div class="info-card"><div class="info-label">Ownership Accountability</div><div class="info-value">Max 10 pts</div></div>
      </div>
    </div>
  </div>

</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">SP Detail</span>
    <button class="drawer-close" onclick="closeDrawer()">✕</button>
  </div>
  <div class="drawer-body">
    <div class="drawer-nav">
      <button class="drawer-nav-btn" onclick="navDetail(-1)">← Prev</button>
      <span class="drawer-nav-info" id="drawerNavInfo"></span>
      <button class="drawer-nav-btn" onclick="navDetail(1)">Next →</button>
    </div>
    <div id="drawerContent"></div>
  </div>
</div>

<div id="toast"></div>

<script>
const FIND_DATA = __FINDING_JSON__;

// Pre-compute flat RBAC rows for the RBAC tab
const RBAC_ROWS = [];
FIND_DATA.forEach(f => {
  (f.rbac||[]).forEach(r => {
    RBAC_ROWS.push({
      displayName: f.displayName,
      riskScore:   f.riskScore,
      role:        r.role,
      roleTier:    r.tier,
      scopeLevel:  r.scopeLevel,
      sub:         r.sub,
      scope:       r.scope,
      findIdx:     FIND_DATA.indexOf(f)
    });
  });
});

// Credential focus rows
const CRED_ROWS = FIND_DATA.filter(f => f.credState !== 'NA');

let findFiltered  = [...FIND_DATA].sort((a,b) => b.riskScore - a.riskScore);
let credFiltered  = [...CRED_ROWS];
let rbacFiltered  = [...RBAC_ROWS];
let findPage = 1, findPageSz = 25;
let credPage = 1, credPageSz = 25;
let rbacPage = 1, rbacPageSz = 25;
let findSortCol = 1, findSortAsc = false;
let credSortCol = -1, credSortAsc = true;
let rbacSortCol = -1, rbacSortAsc = true;
let currentDetailIdx = 0;

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
  if(id==='credentials') renderCreds();
  if(id==='rbac') renderRbac();
}

function toggleTheme(){
  document.documentElement.dataset.theme = document.documentElement.dataset.theme==='dark'?'light':'dark';
}

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Helper: score bar HTML ───────────────────────────────────────────────────
function scoreBarHtml(score){
  const clr = score>=75?'var(--red)':score>=50?'var(--amber)':score>=25?'var(--accent2)':'var(--muted)';
  return `<div style="display:flex;align-items:center;gap:8px;">
    <div style="flex:1;height:6px;background:var(--surface3);border-radius:3px;min-width:48px;">
      <div style="height:100%;border-radius:3px;background:${clr};width:${score}%"></div>
    </div>
    <span style="font-family:var(--mono);font-size:11px;width:28px;text-align:right">${score}</span>
  </div>`;
}

function tierCls(t){ return t==='Critical'?'badge-red':t==='High'?'badge-amber':t==='Medium'?'badge-blue':''; }
function credCls(c){ return c==='Expired'?'badge-red':c==='Expiring30'||c==='Expiring90'?'badge-amber':c==='Valid'?'badge-green':''; }
function credLbl(c){ return c==='Expired'?'Expired':c==='Expiring30'?'≤30d':c==='Expiring90'?'≤90d':c==='Valid'?'Valid':c==='None'?'No Creds':'N/A'; }

// ── Findings table ───────────────────────────────────────────────────────────
function filterFindings(){
  const q=document.getElementById('findSearch').value.toLowerCase();
  const t=document.getElementById('filterTier').value;
  const tp=document.getElementById('filterType').value;
  findFiltered=FIND_DATA.filter(r=>{
    const mQ=!q||(r.displayName+r.appId).toLowerCase().includes(q);
    const mT=!t||r.riskTier===t;
    const mTp=!tp||r.spType===tp;
    return mQ&&mT&&mTp;
  });
  findFiltered.sort((a,b)=>b.riskScore-a.riskScore);
  findPage=1; renderFindings();
}

function changeFindPageSize(){
  findPageSz=parseInt(document.getElementById('pgSizeFind').value);
  findPage=1; renderFindings();
}

function sortFindings(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=col!==1;}
  const tierOrd={Critical:0,High:1,Medium:2,Low:3};
  const keys=['displayName','riskScore','riskTier','spType','rbacCount','credState','ownerCount','signInAudience'];
  findFiltered.sort((a,b)=>{
    const k=keys[col];
    if(k==='riskScore'||k==='rbacCount'||k==='ownerCount'){
      return findSortAsc?(a[k]-b[k]):(b[k]-a[k]);
    }
    if(k==='riskTier'){const av=tierOrd[a[k]]??9,bv=tierOrd[b[k]]??9;return findSortAsc?av-bv:bv-av;}
    return findSortAsc?String(a[k]??'').localeCompare(String(b[k]??'')):String(b[k]??'').localeCompare(String(a[k]??''));
  });
  renderFindings();
}

function renderFindings(){
  const tbody=document.getElementById('findBody');
  const start=(findPage-1)*findPageSz;
  const slice=findFiltered.slice(start,start+findPageSz);
  tbody.innerHTML=slice.map(r=>{
    const gi=FIND_DATA.indexOf(r);
    const nm=r.displayName.length>34?r.displayName.substring(0,31)+'...':r.displayName;
    return `<tr onclick="showDetail(${gi})">
      <td title="${escH(r.displayName)}">${escH(nm)}</td>
      <td>${scoreBarHtml(r.riskScore)}</td>
      <td><span class="badge ${tierCls(r.riskTier)}">${escH(r.riskTier)}</span></td>
      <td><span class="type-badge">${escH(r.spType)}</span></td>
      <td>${r.rbacCount}</td>
      <td><span class="badge ${credCls(r.credState)}">${credLbl(r.credState)}</span></td>
      <td>${r.ownerCount}</td>
      <td style="font-size:11px;font-family:var(--mono)">${r.isMultiTenant?'<span class="badge badge-amber">Multi</span>':'Single'}</td>
    </tr>`;
  }).join('');
  renderFindPg();
}

function renderFindPg(){
  const total=Math.ceil(findFiltered.length/findPageSz);
  const el=document.getElementById('findPagination');
  let h=`<span>${findFiltered.length} service principals</span>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,findPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeFindPage(p){
  const total=Math.ceil(findFiltered.length/findPageSz);
  if(p<1||p>total)return;
  findPage=p; renderFindings();
}

// ── Credential table ─────────────────────────────────────────────────────────
function filterCreds(){
  const q=document.getElementById('credSearch').value.toLowerCase();
  const st=document.getElementById('filterCredState').value;
  credFiltered=CRED_ROWS.filter(r=>{
    const mQ=!q||r.displayName.toLowerCase().includes(q);
    const mS=!st||r.credState===st;
    return mQ&&mS;
  });
  credPage=1; renderCreds();
}

function sortCreds(col){
  if(credSortCol===col){credSortAsc=!credSortAsc;}else{credSortCol=col;credSortAsc=true;}
  const keys=['displayName','spType','credState','credDetail','riskScore','rbacCount'];
  credFiltered.sort((a,b)=>{
    const k=keys[col];
    if(k==='riskScore'||k==='rbacCount')return credSortAsc?a[k]-b[k]:b[k]-a[k];
    return credSortAsc?String(a[k]??'').localeCompare(String(b[k]??'')):String(b[k]??'').localeCompare(String(a[k]??''));
  });
  renderCreds();
}

function renderCreds(){
  const tbody=document.getElementById('credBody');
  if(!tbody) return;
  const start=(credPage-1)*credPageSz;
  const slice=credFiltered.slice(start,start+credPageSz);
  tbody.innerHTML=slice.map((r,i)=>{
    const gi=FIND_DATA.indexOf(r);
    const nm=r.displayName.length>38?r.displayName.substring(0,35)+'...':r.displayName;
    const cd=r.credDetail.length>48?r.credDetail.substring(0,45)+'...':r.credDetail;
    return `<tr onclick="showDetail(${gi})">
      <td title="${escH(r.displayName)}">${escH(nm)}</td>
      <td><span class="type-badge">${escH(r.spType)}</span></td>
      <td><span class="badge ${credCls(r.credState)}">${credLbl(r.credState)}</span></td>
      <td style="font-size:11px;font-family:var(--mono)" title="${escH(r.credDetail)}">${escH(cd)}</td>
      <td>${scoreBarHtml(r.riskScore)}</td>
      <td>${r.rbacCount}</td>
    </tr>`;
  }).join('');
  renderCredPg();
}

function renderCredPg(){
  const total=Math.ceil(credFiltered.length/credPageSz);
  const el=document.getElementById('credPagination');
  let h=`<span>${credFiltered.length} service principals with credential data</span>`;
  h+=`<button class="pg-btn" onclick="changeCredPage(${credPage-1})" ${credPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,credPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===credPage?'active':''}" onclick="changeCredPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeCredPage(${credPage+1})" ${credPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeCredPage(p){
  const total=Math.ceil(credFiltered.length/credPageSz);
  if(p<1||p>total)return;
  credPage=p; renderCreds();
}

// ── RBAC Exposure table ──────────────────────────────────────────────────────
function filterRbac(){
  const q=document.getElementById('rbacSearch').value.toLowerCase();
  const sc=document.getElementById('filterRbacScope').value;
  rbacFiltered=RBAC_ROWS.filter(r=>{
    const mQ=!q||(r.displayName+r.role).toLowerCase().includes(q);
    const mS=!sc||r.scopeLevel===sc;
    return mQ&&mS;
  });
  rbacFiltered.sort((a,b)=>b.riskScore-a.riskScore);
  rbacPage=1; renderRbac();
}

function sortRbac(col){
  if(rbacSortCol===col){rbacSortAsc=!rbacSortAsc;}else{rbacSortCol=col;rbacSortAsc=true;}
  const keys=['displayName','role','roleTier','scopeLevel','sub','riskScore'];
  rbacFiltered.sort((a,b)=>{
    const k=keys[col];
    if(k==='riskScore') return rbacSortAsc?a[k]-b[k]:b[k]-a[k];
    return rbacSortAsc?String(a[k]??'').localeCompare(String(b[k]??'')):String(b[k]??'').localeCompare(String(a[k]??''));
  });
  renderRbac();
}

function renderRbac(){
  const tbody=document.getElementById('rbacBody');
  if(!tbody) return;
  const start=(rbacPage-1)*rbacPageSz;
  const slice=rbacFiltered.slice(start,start+rbacPageSz);
  const tierOrd={Critical:'badge-red',High:'badge-amber',Medium:'badge-blue',Low:''};
  tbody.innerHTML=slice.map(r=>{
    const nm=r.displayName.length>34?r.displayName.substring(0,31)+'...':r.displayName;
    const rl=r.role.length>36?r.role.substring(0,33)+'...':r.role;
    return `<tr onclick="showDetail(${r.findIdx})">
      <td title="${escH(r.displayName)}">${escH(nm)}</td>
      <td title="${escH(r.role)}">${escH(rl)}</td>
      <td><span class="badge ${tierOrd[r.roleTier]||''}">${escH(r.roleTier)}</span></td>
      <td><span class="type-badge">${escH(r.scopeLevel)}</span></td>
      <td style="font-size:11px">${escH(r.sub||'—')}</td>
      <td>${scoreBarHtml(r.riskScore)}</td>
    </tr>`;
  }).join('');
  renderRbacPg();
}

function renderRbacPg(){
  const total=Math.ceil(rbacFiltered.length/rbacPageSz);
  const el=document.getElementById('rbacPagination');
  let h=`<span>${rbacFiltered.length} RBAC assignments</span>`;
  h+=`<button class="pg-btn" onclick="changeRbacPage(${rbacPage-1})" ${rbacPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,rbacPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===rbacPage?'active':''}" onclick="changeRbacPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changeRbacPage(${rbacPage+1})" ${rbacPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}

function changeRbacPage(p){
  const total=Math.ceil(rbacFiltered.length/rbacPageSz);
  if(p<1||p>total)return;
  rbacPage=p; renderRbac();
}

// ── Detail Drawer ────────────────────────────────────────────────────────────
function showDetail(idx){
  currentDetailIdx=idx;
  const r=FIND_DATA[idx];
  if(!r) return;
  document.getElementById('drawerTitle').textContent=r.displayName;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${FIND_DATA.length}`;
  const tierClass=`tier-${r.riskTier.toLowerCase()}`;
  const dimParts = r.scoreDimensions.split('|');

  // Build RBAC rows HTML
  let rbacHtml='<div style="color:var(--muted);font-size:12px">No RBAC assignments found</div>';
  if(r.rbac&&r.rbac.length>0){
    const tierClsMap={Critical:'badge-red',High:'badge-amber',Medium:'badge-blue',Low:''};
    rbacHtml=r.rbac.map(a=>`
      <div class="rbac-row">
        <div>
          <div class="rbac-role">${escH(a.role)}</div>
          <div class="rbac-meta">${escH(a.scopeLevel)} · ${escH(a.sub||a.scope)}</div>
        </div>
        <span class="badge ${tierClsMap[a.tier]||''}">${escH(a.tier)}</span>
      </div>`).join('');
  }

  document.getElementById('drawerContent').innerHTML=`
    <div class="score-gauge">
      <div class="score-circle ${tierClass}">${r.riskScore}</div>
      <div class="score-tier-label" style="color:${r.riskTier==='Critical'?'var(--red)':r.riskTier==='High'?'var(--amber)':r.riskTier==='Medium'?'var(--accent2)':'var(--muted)'}">${r.riskTier} Risk</div>
    </div>

    <div class="drawer-section">Identity</div>
    <div class="drawer-field"><div class="drawer-field-label">Display Name</div><div class="drawer-field-value">${escH(r.displayName)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">SP Type</div><div class="drawer-field-value">${escH(r.spType)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">App ID (Client ID)</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.appId)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Object ID</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.objectId)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Sign-In Audience</div><div class="drawer-field-value">${r.isMultiTenant?'<span class="badge badge-amber">'+escH(r.signInAudience)+'</span>':escH(r.signInAudience)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Last Sign-In (days ago)</div><div class="drawer-field-value">${escH(r.lastSignIn)}</div></div>

    <div class="drawer-section">Ownership</div>
    <div class="drawer-field"><div class="drawer-field-label">Owner Count</div><div class="drawer-field-value">${r.ownerCount===0?'<span style="color:var(--red);font-weight:600">0 — Orphaned</span>':r.ownerCount}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Owner Names</div><div class="drawer-field-value">${escH(r.owners||'—')}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Guest Owner Present</div><div class="drawer-field-value">${r.hasGuestOwner?'<span class="badge badge-amber">Yes</span>':'No'}</div></div>

    <div class="drawer-section">Credential Hygiene</div>
    <div class="drawer-field"><div class="drawer-field-label">State</div><div class="drawer-field-value"><span class="badge ${credCls(r.credState)}">${credLbl(r.credState)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Detail</div><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px;background:var(--surface2);padding:8px 10px;border-radius:var(--radius-sm)">${escH(r.credDetail||'—')}</div></div>

    <div class="drawer-section">RBAC Assignments (${r.rbacCount})</div>
    ${rbacHtml}

    <div class="drawer-section">Score Dimensions</div>
    <div class="drawer-field"><div class="drawer-field-value" style="font-family:var(--mono);font-size:11px;background:var(--surface2);padding:8px 10px;border-radius:var(--radius-sm);white-space:pre-wrap">${escH(r.scoreDimensions)}</div></div>

    <div class="drawer-section">Portal Links</div>
    <div style="display:flex;flex-direction:column;gap:8px">
      <a href="https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/${escH(r.objectId)}" target="_blank" style="color:var(--accent);text-decoration:none;font-size:12px;padding:5px 10px;border:1px solid var(--border);border-radius:var(--radius-sm);display:inline-block">Open in Entra ID ↗</a>
    </div>
  `;

  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}

function closeDrawer(){
  document.getElementById('drawerBackdrop').style.display='none';
  document.getElementById('detailDrawer').classList.remove('open');
}

function navDetail(dir){
  const next=currentDetailIdx+dir;
  if(next>=0&&next<FIND_DATA.length) showDetail(next);
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width=el.dataset.pct+'%';
    });
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

filterFindings();
renderCreds();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__',    $ScanParameters.SubCount `
        -replace '__TOTAL__',        $total `
        -replace '__CRIT_COUNT__',   $critCount `
        -replace '__HIGH_COUNT__',   $highCount `
        -replace '__MED_COUNT__',    $medCount `
        -replace '__LOW_COUNT__',    $lowCount `
        -replace '__EXPIRED_CREDS__', $expiredCreds `
        -replace '__EXP30_CREDS__',  $exp30Creds `
        -replace '__ORPHANED__',     $orphanedSPs `
        -replace '__MULTI_TENANT__', $multiTenant `
        -replace '__SI_BANNER_CLS__', $(if ($SignInActivityIncluded) { 'info' } else { 'warn' }) `
        -replace '__SI_NOTE__',      $siNote `
        -replace '__SI_PARAM__',     $siNote `
        -replace '__TIER_ROWS__',    $tierRows `
        -replace '__TYPE_ROWS__',    $typeRows `
        -replace '__CRED_ROWS__',    $credRows `
        -replace '__SCOPE_ROWS__',   $scopeRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__TENANT__',       $SessionInfo.Tenant `
        -replace '__AZ_ACCOUNT__',   $SessionInfo.AzAccount `
        -replace '__GRAPH_ACCOUNT__', $SessionInfo.GraphAccount `
        -replace '__SCOPE__',        $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__',    $ScanParameters.ExecTime `
        -replace '__FINDING_JSON__', $findingJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureServicePrincipalRBACRisk
{
    [CmdletBinding()]
    param (
        [string[]]$SubscriptionIds,

        [switch]$IncludeGraphSignInActivity,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureServicePrincipalRBACRisk-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check — Az ─────────────────────────────────────────────────────
    $requiredAzModules = @("Az.Accounts", "Az.Resources")
    $missingAz = $requiredAzModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
    if ($missingAz)
    {
        Write-Host "  ⚠ Missing Az modules: $($missingAz -join ', ')" -ForegroundColor Yellow
        $install = Read-Host "  Install Az module now? (Y/N)"
        if ($install -match '^[Yy]$')
        {
            try
            {
                Write-Host "  Installing Az module..." -ForegroundColor Cyan
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "  ✓ Az module installed" -ForegroundColor Green
            }
            catch { Write-Host "  ✗ Install failed: $_" -ForegroundColor Red; return }
        }
        else { Write-Host "  Cannot proceed without Az modules." -ForegroundColor Yellow; return }
    }

    # ── Module check — Microsoft Graph ────────────────────────────────────────
    $requiredGraphModules = @("Microsoft.Graph.Applications", "Microsoft.Graph.Users")
    if ($IncludeGraphSignInActivity) { $requiredGraphModules += "Microsoft.Graph.Identity.SignIns" }

    $missingGraph = $requiredGraphModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
    if ($missingGraph)
    {
        Write-Host "  ⚠ Missing Graph modules: $($missingGraph -join ', ')" -ForegroundColor Yellow
        $install = Read-Host "  Install Microsoft.Graph module now? (Y/N)"
        if ($install -match '^[Yy]$')
        {
            try
            {
                Write-Host "  Installing Microsoft.Graph module (this may take a moment)..." -ForegroundColor Cyan
                Install-Module -Name Microsoft.Graph -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Write-Host "  ✓ Microsoft.Graph installed" -ForegroundColor Green
            }
            catch { Write-Host "  ✗ Install failed: $_" -ForegroundColor Red; return }
        }
        else { Write-Host "  Cannot proceed without Microsoft.Graph modules." -ForegroundColor Yellow; return }
    }

    # ── Az Authentication ─────────────────────────────────────────────────────
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx)
    {
        Write-Host "  ⚠ No active Az session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $ctx = Get-AzContext
    }

    # ── Graph Authentication ──────────────────────────────────────────────────
    $graphScopes = @("Application.Read.All", "Directory.Read.All")
    if ($IncludeGraphSignInActivity) { $graphScopes += "AuditLog.Read.All" }

    $graphCtx = $null
    try { $graphCtx = Get-MgContext -ErrorAction Stop } catch { }

    if (-not $graphCtx)
    {
        Write-Host "  ⚠ No active Microsoft Graph session. Authenticating..." -ForegroundColor Yellow
        try
        {
            Connect-MgGraph -Scopes $graphScopes -ErrorAction Stop
            $graphCtx = Get-MgContext
            Write-Host "  ✓ Graph authentication successful" -ForegroundColor Green
        }
        catch
        {
            Write-Host "  ✗ Graph authentication failed: $_" -ForegroundColor Red
            Write-Host "  Cannot retrieve Entra SP data without Graph access. Exiting." -ForegroundColor Yellow
            return
        }
    }

    # ── Subscription resolution ───────────────────────────────────────────────
    $subscriptions = @()
    if ($SubscriptionIds)
    {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
            Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count) requested)"
    }
    else
    {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText = "All Accessible Subscriptions"
    }
    $subCount = $subscriptions.Count

    # ── Display session / params ──────────────────────────────────────────────
    Write-Section -Title "Session Information" -Data @{
        "Az Tenant"        = $ctx.Tenant.Id
        "Az Account"       = $ctx.Account.Id
        "Graph Account"    = if ($graphCtx) { $graphCtx.Account } else { "Not connected" }
        "Graph Scopes"     = ($graphScopes -join ", ")
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "RBAC Scope"            = "$scopeText ($subCount subscription(s))"
        "Sign-In Activity"      = if ($IncludeGraphSignInActivity) { "Enabled (Graph beta — AuditLog.Read.All required)" } else { "Skipped (use -IncludeGraphSignInActivity)" }
        "Export to CSV"         = if ($ExportToCsv.IsPresent) { "Enabled → $CsvPath" } else { "Disabled" }
    }

    # ── Step 1: Enumerate all RBAC assignments across all subscriptions ───────
    Write-Host ""
    Write-Host "  Phase 1 of 3 — Collecting Azure RBAC Assignments" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    # Key: SP ObjectId → list of RBAC assignment objects
    $rbacBySpId     = @{}
    $subNameById    = @{}
    $subIndex       = 1
    $maxNameLen     = ([math]::Max(($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum, 35))

    foreach ($sub in $subscriptions)
    {
        try
        {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
            $subNameById[$sub.Id] = $sub.Name

            $assignments = @(Get-AzRoleAssignment -ErrorAction Stop |
                Where-Object { $_.ObjectType -in @("ServicePrincipal", "Unknown") })

            foreach ($a in $assignments)
            {
                $spId = $a.ObjectId
                if ([string]::IsNullOrWhiteSpace($spId)) { continue }

                $scopeLevel = Get-ScopeLevel -Scope $a.Scope
                $roleTier   = Get-RoleRiskTier -RoleName $a.RoleDefinitionName

                $rbacEntry = [pscustomobject]@{
                    ObjectId           = $spId
                    RoleDefinitionName = $a.RoleDefinitionName
                    RoleDefinitionId   = $a.RoleDefinitionId
                    RoleTier           = $roleTier
                    Scope              = $a.Scope
                    ScopeLevel         = $scopeLevel
                    SubscriptionId     = $sub.Id
                    SubscriptionName   = $sub.Name
                }

                if (-not $rbacBySpId.ContainsKey($spId)) { $rbacBySpId[$spId] = [System.Collections.Generic.List[object]]::new() }
                $rbacBySpId[$spId].Add($rbacEntry)
            }

            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  ✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → SP assignments: $($assignments.Count)" -ForegroundColor White
        }
        catch
        {
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            Write-Host "  ✗ " -NoNewline -ForegroundColor Red
            Write-Host "$($sub.Name) → $($_.Exception.Message)" -ForegroundColor Red
        }
        $subIndex++
    }

    $totalRbacAssignments = ($rbacBySpId.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    Write-Host ""
    Write-Host "  ✓ RBAC collection complete — $totalRbacAssignments SP assignment(s) across $subCount subscription(s)" -ForegroundColor Green

    # ── Step 2: Enumerate all service principals via Graph ────────────────────
    Write-Host ""
    Write-Host "  Phase 2 of 3 — Collecting Service Principals via Microsoft Graph" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Fetching service principals (may take several minutes for large tenants)..." -ForegroundColor Gray

    $allSPs = @()
    try
    {
        # Retrieve SP core properties. AppRoleAssignments and Owners require separate calls below.
        $spSelectProps = "id,displayName,appId,servicePrincipalType,signInAudience,accountEnabled,appOwnerOrganizationId,passwordCredentials,keyCredentials"
        if ($IncludeGraphSignInActivity) { $spSelectProps += ",signInActivity" }

        $allSPs = @(Get-MgServicePrincipal -All -Property $spSelectProps -ErrorAction Stop)
        Write-Host "  ✓ Retrieved $($allSPs.Count) service principal(s)" -ForegroundColor Green
    }
    catch
    {
        Write-Host "  ✗ Could not retrieve service principals from Graph: $_" -ForegroundColor Red
        Write-Host "  Ensure Application.Read.All permission is consented." -ForegroundColor Yellow
        return
    }

    # ── Step 3: Correlate SPs with RBAC and compute risk scores ──────────────
    Write-Host ""
    Write-Host "  Phase 3 of 3 — Correlating RBAC, Credentials, Ownership, and Scoring" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $allFindings     = [System.Collections.Generic.List[pscustomobject]]::new()
    $riskTierDist    = @{ "Critical" = 0; "High" = 0; "Medium" = 0; "Low" = 0 }
    $spTypeDist      = @{}
    $credStateDist   = @{}
    $scopeDist       = @{ "Management Group" = 0; "Subscription" = 0; "Resource Group" = 0; "Resource" = 0 }
    $spCount         = $allSPs.Count
    $spIndex         = 1

    # Batch fetch all owners in a single pass to reduce Graph API calls
    # For large tenants: cache owner lookups to avoid N+1 calls
    $ownerCache      = @{}

    foreach ($sp in $allSPs)
    {
        try { Write-ProgressBar -Current $spIndex -Total $spCount -CurrentItem $sp.DisplayName } catch { }

        # ── SP Type ───────────────────────────────────────────────────────────
        $spType = switch ($sp.ServicePrincipalType)
        {
            "Application"     { "Application" }
            "ManagedIdentity" { "ManagedIdentity" }
            "SocialIdp"       { "Legacy" }
            default           { if ($sp.ServicePrincipalType) { $sp.ServicePrincipalType } else { "Application" } }
        }

        # ── RBAC Assignments ──────────────────────────────────────────────────
        $spRbac = @()
        if ($rbacBySpId.ContainsKey($sp.Id)) { $spRbac = @($rbacBySpId[$sp.Id]) }

        # Update scope distribution
        foreach ($a in $spRbac)
        {
            if ($scopeDist.ContainsKey($a.ScopeLevel)) { $scopeDist[$a.ScopeLevel]++ }
        }

        # ── Credential hygiene ────────────────────────────────────────────────
        $credState  = "NA"    # Default for Managed Identities
        $credDetail = "Managed Identity — no user credentials"

        if ($spType -ne "ManagedIdentity")
        {
            $allCreds = @()
            try
            {
                $pwdCreds  = @(Get-ObjProperty -Obj $sp -PropName 'PasswordCredentials' -Default @())
                $keyCreds  = @(Get-ObjProperty -Obj $sp -PropName 'KeyCredentials'      -Default @())
                $allCreds  = @($pwdCreds) + @($keyCreds)
            }
            catch { }

            if ($allCreds.Count -eq 0)
            {
                $credState  = "None"
                $credDetail = "No secrets or certificates registered"
            }
            else
            {
                # Find the worst credential state
                $now          = Get-Date
                $worstState   = "Valid"
                $detailParts  = @()

                foreach ($cred in $allCreds)
                {
                    $endDate = $null
                    try { $endDate = [datetime]$cred.EndDateTime } catch { }
                    if (-not $endDate) { continue }

                    $daysLeft    = ($endDate - $now).Days
                    $credType    = if ($cred.PSObject.Properties.Name -contains 'SecretText') { "Secret" } else { "Certificate" }
                    $credName    = if ($cred.DisplayName) { $cred.DisplayName } else { $cred.KeyId }
                    $detailParts += "$credType '$credName': $(if ($daysLeft -lt 0) { 'Expired $([math]::Abs($daysLeft))d ago' } else { 'Expires in $daysLeft days' })"

                    $thisState = if ($daysLeft -lt 0)    { "Expired"    }
                                 elseif ($daysLeft -le 30) { "Expiring30" }
                                 elseif ($daysLeft -le 90) { "Expiring90" }
                                 else                     { "Valid"      }

                    # Worst state wins
                    $stateOrder = @{ "Expired" = 0; "Expiring30" = 1; "Expiring90" = 2; "Valid" = 3 }
                    if ($stateOrder[$thisState] -lt $stateOrder[$worstState]) { $worstState = $thisState }
                }

                $credState  = $worstState
                $credDetail = ($detailParts -join " | ")
                if ([string]::IsNullOrWhiteSpace($credDetail)) { $credDetail = "Credentials present but expiry could not be determined" }
            }
        }

        # Update cred state distribution
        if ($credStateDist.ContainsKey($credState)) { $credStateDist[$credState]++ } else { $credStateDist[$credState] = 1 }

        # ── Sign-in activity (optional) ───────────────────────────────────────
        $lastSignInDays = "Unknown"
        if ($IncludeGraphSignInActivity)
        {
            try
            {
                $signInActivity = Get-ObjProperty -Obj $sp -PropName 'SignInActivity' -Default $null
                if ($signInActivity)
                {
                    $lastDate = $null
                    try { $lastDate = [datetime]$signInActivity.LastSignInDateTime } catch { }
                    if ($lastDate) { $lastSignInDays = [math]::Abs(($lastDate - (Get-Date)).Days).ToString() }
                }
            }
            catch { }
        }

        # ── Multi-tenant detection ────────────────────────────────────────────
        $isMultiTenant = $false
        try
        {
            $audience      = Get-ObjProperty -Obj $sp -PropName 'SignInAudience' -Default "AzureADMyOrg"
            $isMultiTenant = ($audience -in @("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount", "PersonalMicrosoftAccount"))
        }
        catch { $audience = "Unknown" }

        # ── Ownership ─────────────────────────────────────────────────────────
        $ownerCount   = 0
        $hasGuestOwner = $false
        $ownerNames   = ""
        if ($spType -ne "ManagedIdentity")
        {
            try
            {
                if (-not $ownerCache.ContainsKey($sp.Id))
                {
                    $owners = @(Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -ErrorAction Stop)
                    $ownerCache[$sp.Id] = $owners
                }
                else { $owners = $ownerCache[$sp.Id] }

                $ownerCount    = $owners.Count
                $hasGuestOwner = @($owners | Where-Object {
                    $_.AdditionalProperties.ContainsKey("userPrincipalName") -and
                    $_.AdditionalProperties["userPrincipalName"] -like "*#EXT#*"
                }).Count -gt 0
                $ownerNames    = ($owners | ForEach-Object {
                    $upn = if ($_.AdditionalProperties.ContainsKey("userPrincipalName")) { $_.AdditionalProperties["userPrincipalName"] } else { $_.Id }
                    $upn
                } | Select-Object -First 5) -join "; "
            }
            catch { Write-Verbose "Owner fetch failed for $($sp.DisplayName): $_" }
        }

        # ── Risk Scoring ──────────────────────────────────────────────────────
        $riskScore = Compute-RiskScore `
            -RbacAssignments  $spRbac `
            -CredentialState  $credState `
            -LastSignInDays   $lastSignInDays `
            -IsMultiTenant    $isMultiTenant `
            -OwnerCount       $ownerCount `
            -HasGuestOwner    $hasGuestOwner

        $riskTier = Get-RiskTier -Score $riskScore

        # Score dimension breakdown for drawer transparency
        $highestScope   = ($spRbac | ForEach-Object { if ($script:SCOPE_RISK.ContainsKey($_.ScopeLevel)) { $script:SCOPE_RISK[$_.ScopeLevel] } else { 3 } } | Measure-Object -Maximum).Maximum
        $highestRole    = ($spRbac | ForEach-Object { $t = Get-RoleRiskTier -RoleName $_.RoleDefinitionName; if ($script:ROLE_RISK.ContainsKey($t)) { $script:ROLE_RISK[$t] } else { 2 } } | Measure-Object -Maximum).Maximum
        $credPts        = switch ($credState) { "Expired" { 20 }; "Expiring30" { 15 }; "Expiring90" { 8 }; "Valid" { 0 }; "None" { 5 }; default { 0 } }
        $staleInt       = 0
        try { if ($lastSignInDays -ne "Unknown") { $d = [int]$lastSignInDays; $staleInt = if ($d -ge 180) { 15 } elseif ($d -ge 90) { 10 } elseif ($d -ge 60) { 5 } else { 0 } } } catch { }
        $multiPts       = if ($isMultiTenant -and $spRbac.Count -gt 0) { 10 } else { 0 }
        $ownerPts       = if ($ownerCount -eq 0) { 10 } elseif ($hasGuestOwner) { 6 } elseif ($ownerCount -gt 5) { 3 } else { 0 }

        $scoreDimensions = @(
            "RBAC Scope Breadth     : +$(if($highestScope) { $highestScope } else { 0 }) pts  (max scope: $(if ($spRbac.Count -gt 0) { ($spRbac | Sort-Object { $script:SCOPE_RISK[$_.ScopeLevel] } -Descending | Select-Object -First 1).ScopeLevel } else { 'None' }))"
            "RBAC Role Sensitivity  : +$(if($highestRole) { $highestRole } else { 0 }) pts  (highest role tier: $(if ($spRbac.Count -gt 0) { Get-RoleRiskTier -RoleName ($spRbac | Sort-Object { $script:ROLE_RISK[(Get-RoleRiskTier -RoleName $_.RoleDefinitionName)] } -Descending | Select-Object -First 1).RoleDefinitionName } else { 'None' }))"
            "Credential Hygiene     : +$credPts pts  (state: $credState)"
            "Stale Sign-In          : +$staleInt pts  (last sign-in: $lastSignInDays days ago)"
            "Multi-Tenant Exposure  : +$multiPts pts  (audience: $audience)"
            "Ownership              : +$ownerPts pts  (owners: $ownerCount$(if ($hasGuestOwner) { ', guest owner present' } else { '' }))"
            "─────────────────────────────────"
            "Total Score            : $riskScore / 100  →  $riskTier"
        ) -join "`n"

        # ── Assemble finding ──────────────────────────────────────────────────
        $finding = [pscustomobject]@{
            DisplayName          = $sp.DisplayName
            AppId                = $sp.AppId
            ObjectId             = $sp.Id
            SPType               = $spType
            SignInAudience       = $audience
            IsMultiTenant        = $isMultiTenant
            AccountEnabled       = Get-ObjProperty -Obj $sp -PropName 'AccountEnabled' -Default $true
            CredentialState      = $credState
            CredentialDetail     = $credDetail
            LastSignInDays       = $lastSignInDays
            OwnerCount           = $ownerCount
            HasGuestOwner        = $hasGuestOwner
            OwnerNames           = $ownerNames
            RbacAssignmentCount  = $spRbac.Count
            RbacAssignments      = $spRbac
            RiskScore            = $riskScore
            RiskTier             = $riskTier
            ScoreDimensions      = $scoreDimensions
        }

        $allFindings.Add($finding)

        # Update distributions
        if ($riskTierDist.ContainsKey($riskTier)) { $riskTierDist[$riskTier]++ }
        if ($spTypeDist.ContainsKey($spType)) { $spTypeDist[$spType]++ } else { $spTypeDist[$spType] = 1 }

        $spIndex++
    }

    Write-Host "`r$(' ' * 120)`r" -NoNewline
    Write-Host "  ✓ Risk scoring complete — $($allFindings.Count) service principal(s) assessed" -ForegroundColor Green

    # ── Summary ───────────────────────────────────────────────────────────────
    $endTime  = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    $findingsList = @($allFindings)
    Write-RiskSummary -Findings $findingsList
    Write-TopRisks    -Findings $findingsList

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported    = $false
    $htmlExported   = $false
    $gridViewOpened = $false
    $htmlPath       = ""

    if ($findingsList.Count -gt 0)
    {
        # CSV
        if ($ExportToCsv)
        {
            try
            {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $csvRows = $findingsList | Select-Object `
                    DisplayName, AppId, ObjectId, SPType, SignInAudience, IsMultiTenant,
                    AccountEnabled, CredentialState, CredentialDetail, LastSignInDays,
                    OwnerCount, HasGuestOwner, OwnerNames, RbacAssignmentCount,
                    RiskScore, RiskTier

                $csvRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                # RBAC flat export
                $rbacCsvPath = [System.IO.Path]::ChangeExtension($CsvPath, '') + "RBAC.csv"
                $rbacFlatRows = foreach ($f in $findingsList)
                {
                    foreach ($a in $f.RbacAssignments)
                    {
                        [pscustomobject]@{
                            SPDisplayName      = $f.DisplayName
                            SPObjectId         = $f.ObjectId
                            SPType             = $f.SPType
                            SPRiskScore        = $f.RiskScore
                            SPRiskTier         = $f.RiskTier
                            RoleDefinitionName = $a.RoleDefinitionName
                            RoleTier           = $a.RoleTier
                            ScopeLevel         = $a.ScopeLevel
                            Scope              = $a.Scope
                            SubscriptionName   = $a.SubscriptionName
                        }
                    }
                }
                $rbacFlatRows | Export-Csv -Path $rbacCsvPath -NoTypeInformation -Encoding UTF8

                $csvExported = $true
                Write-Host "  ✓ RBAC flat export: $rbacCsvPath" -ForegroundColor DarkGray
            }
            catch { Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red }
        }

        # HTML
        try
        {
            $htmlPath    = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
            $sessionInfo = @{
                Tenant       = $ctx.Tenant.Id
                AzAccount    = $ctx.Account.Id
                GraphAccount = if ($graphCtx) { $graphCtx.Account } else { "N/A" }
            }
            $scanParams  = @{
                Scope         = "$scopeText ($subCount subscription(s))"
                SubCount      = $subCount
                ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime      = $duration
            }

            $htmlContent = Generate-SPRiskHtml `
                -SessionInfo              $sessionInfo `
                -ScanParameters           $scanParams `
                -Findings                 $findingsList `
                -RiskTierDist             $riskTierDist `
                -SpTypeDist               $spTypeDist `
                -CredStateDist            $credStateDist `
                -ScopeDist                $scopeDist `
                -GeneratedOn              (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -SignInActivityIncluded    $IncludeGraphSignInActivity.IsPresent

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch { Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red }

        # Grid View
        try
        {
            $findingsList |
                Sort-Object RiskScore -Descending |
                Select-Object DisplayName, SPType, RiskScore, RiskTier, RbacAssignmentCount,
                    CredentialState, OwnerCount, IsMultiTenant, LastSignInDays |
                Out-GridView -Title "Azure Service Principal RBAC Risk Assessment"
            $gridViewOpened = $true
        }
        catch { Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow }
    }
    else
    {
        Write-Host ""
        Write-Host "  ⚠ No service principals found. Verify Graph permissions and subscription access." -ForegroundColor Yellow
    }

    $outCsv  = if ($csvExported)  { $CsvPath }  else { $null }
    $outHtml = if ($htmlExported) { $htmlPath } else { $null }
    if ($csvExported -or $htmlExported -or $gridViewOpened)
    {
        Write-OutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
    }
    else
    {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
