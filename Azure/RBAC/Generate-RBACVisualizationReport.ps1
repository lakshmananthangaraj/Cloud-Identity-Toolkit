<#

Author       : Lakshmanan Thangaraj
Version      : 3.0
Created-On   : 02 March 2026
Modified-On  : 05 August 2026

.SYNOPSIS
    Generates an interactive HTML visualization report from Azure RBAC assignment CSV data.

.DESCRIPTION
    The Generate-RBACVisualizationReport function transforms Azure RBAC assignment data,
    previously exported to CSV (e.g. via Get-AzureRBACAssignments.ps1), into a self-contained,
    interactive HTML dashboard following the Cloud-Identity-Toolkit golden design system.

    Features (v3.0):
        - Fixed sidebar navigation with dark / light mode toggle
        - CSV Upload Mode — the generated HTML can accept a new CSV drag-and-drop at runtime
          to reload the entire dashboard without re-running the PowerShell script
        - Header Bar      — Tenant Name, Report Title, Health Score, Risk Score, scan metadata
        - Executive Dashboard — full KPI suite (Users, Groups, SPs, MIs, Custom Roles,
                               Owner/Contributor/Reader/Unknown counts, High Risk), trend badges
        - Security Dashboard — Critical/High/Medium/Low finding cards, 8 automated security checks
                               (Owner ratio, SP-as-Owner, root-scope assignments, unknown principals,
                               guest users, custom roles, wildcard scopes, over-provisioned principals)
        - Principals      — Per-principal assignment breakdown with SignInName, Risk Score badge,
                           searchable / filterable / paginated table, slide-in detail drawer
        - Roles           — Per-role usage breakdown, permission-level badge, animated bar chart
        - Resource Analysis — Top resource types, resource groups, individual resources with
                             drill-down drawer showing assigned users / groups / SPs / roles / scope
        - Subscriptions   — Per-subscription cards with Health Score, Risk Score,
                           Owner/Contributor/Reader counts, slide-in detail drawer
        - Environments    — Auto-detected Dev/UAT/Prod/Test/Staging breakdown; per-env
                           Health Score, High Risk Count, assignment & principal charts
        - Recommendations — Enhanced cards with Priority, Business Impact, Effort, MS Best Practice,
                           Suggested Fix, export affected objects per finding
        - Audit Report    — Executive summary: total assignments, high risk, passed/failed checks,
                           compliance status (Pass / Warning / Fail)
        - Raw Data        — All 10 columns with global search, multi-column filters,
                           column chooser, copy-row button, export filtered CSV
        - Footer          — Toolkit name, version, PowerShell version, execution time,
                           record count, author, GitHub repository

.PARAMETER CsvPath
    Path to the input CSV file containing Azure RBAC assignments.
    Expected columns: SubscriptionName, SubscriptionId, TenantId, DisplayName, SignInName,
    ObjectType, RoleDefinitionName, ResourceType, Scope.

.PARAMETER OutputPath
    Path where the generated HTML report will be saved.
    Default: RBAC-Visualization-Report.html

.PARAMETER TenantName
    Optional friendly name for the Azure tenant displayed in the report header.
    Default: inferred from TenantId or "Unknown Tenant".

.PARAMETER GroupCategories
    Optional hashtable to categorize principals by naming pattern.
    Reserved for a future release.

.INPUTS
    None. Reads from -CsvPath on disk.

.OUTPUTS
    None. Writes a self-contained HTML file to -OutputPath.

.EXAMPLE
    Generate-RBACVisualizationReport -CsvPath ".\rbac-assignments.csv"

.EXAMPLE
    Generate-RBACVisualizationReport -CsvPath ".\rbac-assignments.csv" `
        -OutputPath ".\reports\rbac-report.html" -TenantName "Contoso Corp"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        3.0 (05-Aug-2026)      - Major enterprise upgrade. New: CSV runtime upload,
                                 header bar with Health/Risk Score, Executive Dashboard
                                 (full KPI suite), Security Dashboard (8 checks, severity
                                 cards), Resource Analysis tab, enhanced Subscription cards
                                 (Health/Risk/counts), enhanced Environment tab (Health/Risk),
                                 enhanced Recommendations (Priority/Impact/Effort/Fix/Export),
                                 Audit Report tab, enhanced Raw Data (column chooser, copy row),
                                 footer, -TenantName parameter.
        2.0 (05-Aug-2026)      - Major redesign: golden dark/light dashboard theme,
                                 fixed sidebar navigation, dark/light toggle. Tabs:
                                 Environments, Subscriptions, Principals, Raw Data.
        1.0 (22-Jul-2026)      - Initial public release.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. PowerShell 5.1 or higher.
        2. Input CSV produced by Get-AzureRBACAssignments.ps1 (-ExportToCsv switch).
        3. Internet access for Chart.js CDN (cdn.jsdelivr.net).

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - -GroupCategories is accepted but not yet surfaced in HTML (reserved).
        - Environment auto-detection scans SubscriptionName for keywords.
        - Principal-Role matrix capped at 50 x 20 for browser performance.

.LINK
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/RBAC/Get-AzureRBACAssignments.ps1

#>

Function Generate-RBACVisualizationReport
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$CsvPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = 'C:\temp\RBAC-Visualization-Report.html',

        [Parameter(Mandatory = $false)]
        [string]$TenantName = '',

        [Parameter(Mandatory = $false)]
        [hashtable]$GroupCategories = @{}
    )

    $scriptStartTime = Get-Date
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    #region ── Helpers ────────────────────────────────────────────────────────

    function ConvertTo-JsonSafe
    {
        param([string]$Text)
        $Text `
            -replace '\\',      '\\\\' `
            -replace '"',       '\"'   `
            -replace "`r`n",    '\n'   `
            -replace "`n",      '\n'   `
            -replace "`r",      '\n'   `
            -replace "`t",      '\t'   `
            -replace '<',       '\u003c' `
            -replace '>',       '\u003e' `
            -replace '\$',      '\u0024'
    }

    function Get-Environment {
        param([string]$SubscriptionName)
        $name = $SubscriptionName.ToLower()
        switch -Regex ($name) {
            'non-prod|nonprod'                   { return 'NonProd' }
            'pre-prod|preprod|preproduction'     { return 'PreProd' }
            'prod|production'                    { return 'Prod' }
            'dev|development'                    { return 'Dev' }
            'uat'                                { return 'UAT' }
            'sit'                                { return 'SIT' }
            'qa'                                 { return 'QA' }
            'test|testing'                       { return 'Test' }
            'stage|staging'                      { return 'Staging' }
            'sandbox|sbx'                        { return 'Sandbox' }
            'poc|proof.?of.?concept'             { return 'POC' }
            'lab|demo'                           { return 'Lab' }
            'pilot'                              { return 'Pilot' }
            'training|train'                     { return 'Training' }
            'dr|disaster.?recovery'              { return 'DR' }
            'engineering|engg|eng'               { return 'Engineering' }

            # Common Azure/Microsoft subscription types
            'visual studio'                      { return 'Dev' }
            'visualstudio'                       { return 'Dev' }
            'msdn'                               { return 'Dev' }
            'developer'                          { return 'Dev' }
            'development subscription'           { return 'Dev' }

            default                              { return 'Unknown' }
        }
    }

    function Get-PrincipalRiskScore {
        param($PrincipalRows)
        $score = 0
        $roles = $PrincipalRows | Select-Object -ExpandProperty RoleDefinitionName -Unique
        foreach ($role in $roles) {
            $r = $role.ToLower()
            if ($r -match 'owner')                          { $score += 40 }
            elseif ($r -match 'user access administrator')  { $score += 35 }
            elseif ($r -match 'contributor')                { $score += 20 }
            elseif ($r -match 'administrator')              { $score += 15 }
        }
        $scopeTypes = $PrincipalRows | ForEach-Object {
            if ($_.Scope -eq '/')                                  { 'Root' }
            elseif ($_.Scope -match '/subscriptions/[^/]+$')      { 'Subscription' }
            elseif ($_.Scope -match '/resourceGroups/[^/]+$')     { 'ResourceGroup' }
            else                                                   { 'Resource' }
        }
        if ($scopeTypes -contains 'Root')         { $score += 30 }
        if ($scopeTypes -contains 'Subscription') { $score += 10 }
        $score = [Math]::Min($score, 100)
        return $score
    }

    function Get-RiskLevel {
        param([int]$Score)
        if ($Score -ge 70) { return 'Critical' }
        if ($Score -ge 40) { return 'High' }
        if ($Score -ge 20) { return 'Medium' }
        return 'Low'
    }

    #endregion

    #region ── Banner ─────────────────────────────────────────────────────────

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║     Azure RBAC Visualization Report Generator  v3.0          ║' -ForegroundColor Cyan
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''

    #endregion

    #region ── Import & Validate ──────────────────────────────────────────────

    Write-Host '  [1/5] Importing CSV data...' -ForegroundColor Yellow
    try
    {
        $rbacData     = @(Import-Csv -Path $CsvPath -Encoding UTF8)
        $totalRecords = $rbacData.Count
        Write-Host "        ✓ Loaded $totalRecords RBAC assignments" -ForegroundColor Green
    }
    catch { Write-Error "Failed to import CSV: $_"; return }

    if ($totalRecords -eq 0) { Write-Error "The CSV at '$CsvPath' contains no data rows."; return }

    Write-Host '  [2/5] Validating CSV structure...' -ForegroundColor Yellow
    $requiredColumns = @('SubscriptionName','SubscriptionId','DisplayName','RoleDefinitionName','Scope')
    $csvColumns      = $rbacData[0].PSObject.Properties.Name
    foreach ($col in $requiredColumns) {
        if ($col -notin $csvColumns) { Write-Error "Missing required column: $col"; return }
    }
    Write-Host '        ✓ CSV structure validated' -ForegroundColor Green

    #endregion

    #region ── Analysis ───────────────────────────────────────────────────────

    Write-Host '  [3/5] Analysing RBAC assignments...' -ForegroundColor Yellow

    # Enrich rows
    $enriched = $rbacData | ForEach-Object {
        $env = Get-Environment -SubscriptionName ($_.SubscriptionName)
        $_ | Select-Object *,
            @{ N = 'Environment';     E = { $env } },
            @{ N = 'TenantIdSafe';    E = { if ($_.PSObject.Properties['TenantId'])     { $_.TenantId    } else { '' } } },
            @{ N = 'SignInNameSafe';  E = { if ($_.PSObject.Properties['SignInName'])   { $_.SignInName  } else { '' } } },
            @{ N = 'ObjectTypeSafe';  E = { if ($_.PSObject.Properties['ObjectType'])   { $_.ObjectType  } else { 'Unknown' } } },
            @{ N = 'ResourceTypeSafe';E = { if ($_.PSObject.Properties['ResourceType']) { $_.ResourceType } else { '' } } }
    }

    $uniqueSubscriptions  = @($enriched | Select-Object -ExpandProperty SubscriptionName -Unique | Sort-Object)
    $uniqueRoles          = @($enriched | Select-Object -ExpandProperty RoleDefinitionName -Unique | Sort-Object)
    $uniquePrincipals     = @($enriched | Select-Object -ExpandProperty DisplayName -Unique | Where-Object { $_ } | Sort-Object)
    $uniqueResourceTypes  = @($enriched | Where-Object { $_.ResourceTypeSafe } | Select-Object -ExpandProperty ResourceTypeSafe -Unique | Sort-Object)
    $uniqueEnvironments   = @($enriched | Select-Object -ExpandProperty Environment -Unique | Sort-Object)

    # Tenant name
    if (-not $TenantName) {
        $firstTenant = $enriched | Where-Object { $_.TenantIdSafe } | Select-Object -First 1
        $TenantName  = if ($firstTenant) { "Tenant: $($firstTenant.TenantIdSafe.Substring(0,8))..." } else { 'Azure Tenant' }
    }

    # ── Principal breakdown by ObjectType ──
    $userRows          = @($enriched | Where-Object { $_.ObjectTypeSafe -eq 'User' })
    $groupRows         = @($enriched | Where-Object { $_.ObjectTypeSafe -eq 'Group' })
    $spRows            = @($enriched | Where-Object { $_.ObjectTypeSafe -eq 'ServicePrincipal' })
    $miRows            = @($enriched | Where-Object { $_.ObjectTypeSafe -eq 'ManagedIdentity' })
    $unknownObjRows    = @($enriched | Where-Object { $_.ObjectTypeSafe -eq 'Unknown' -or -not $_.ObjectTypeSafe })

    $uniqueUsers       = @($userRows  | Select-Object -ExpandProperty DisplayName -Unique | Where-Object { $_ }).Count
    $uniqueGroups      = @($groupRows | Select-Object -ExpandProperty DisplayName -Unique | Where-Object { $_ }).Count
    $uniqueSPs         = @($spRows    | Select-Object -ExpandProperty DisplayName -Unique | Where-Object { $_ }).Count
    $uniqueMIs         = @($miRows    | Select-Object -ExpandProperty DisplayName -Unique | Where-Object { $_ }).Count

    # ── Role category counts ──
    $ownerRows       = @($enriched | Where-Object { $_.RoleDefinitionName -imatch 'owner' })
    $contribRows     = @($enriched | Where-Object { $_.RoleDefinitionName -imatch 'contributor' })
    $readerRows      = @($enriched | Where-Object { $_.RoleDefinitionName -imatch 'reader' })
    $customRoleRows  = @($uniqueRoles | Where-Object { $_ -notmatch 'Owner|Contributor|Reader|Administrator|Operator|Storage|Key Vault|Backup|Network|Virtual Machine|SQL|Cosmos|Azure' })

    # ── Guest users ──
    $guestRows = @($enriched | Where-Object { $_.SignInNameSafe -imatch '#EXT#' })

    # ── Root scope assignments ──
    $rootScopeRows = @($enriched | Where-Object { $_.Scope -eq '/' })

    # ── SP with Owner ──
    $spOwnerRows = @($enriched | Where-Object { $_.ObjectTypeSafe -eq 'ServicePrincipal' -and $_.RoleDefinitionName -imatch 'owner' })

    # ── Unknown principals ──
    $unknownPrincipalRows = @($enriched | Where-Object { -not $_.DisplayName -or $_.ObjectTypeSafe -eq 'Unknown' })

    # ── Over-provisioned principals (10+ assignments) ──
    $principalAssignCounts = $enriched | Group-Object DisplayName | Where-Object { $_.Count -ge 10 }
    $overProvisionedCount  = @($principalAssignCounts).Count

    # ── Per-principal risk scoring ──
    $principalRiskData = $enriched | Group-Object DisplayName | ForEach-Object {
        $pRows  = $_.Group
        $score  = Get-PrincipalRiskScore -PrincipalRows $pRows
        $level  = Get-RiskLevel -Score $score
        [PSCustomObject]@{
            DisplayName = $_.Name
            RiskScore   = $score
            RiskLevel   = $level
            Count       = $_.Count
        }
    }
    $highRiskPrincipals = @($principalRiskData | Where-Object { $_.RiskLevel -in @('Critical','High') })
    $highRiskCount      = $highRiskPrincipals.Count

    # ── Security checks → severity bucketing ──
    $securityChecks = @()

    $ownerRatioPct = if ($totalRecords -gt 0) { [Math]::Round(($ownerRows.Count / $totalRecords) * 100, 1) } else { 0 }
    $securityChecks += [PSCustomObject]@{
        CheckName   = 'Owner Role Ratio'
        Description = "$($ownerRows.Count) Owner assignments ($ownerRatioPct% of total). Recommended threshold: ≤5%."
        Severity    = if ($ownerRatioPct -gt 15) { 'Critical' } elseif ($ownerRatioPct -gt 5) { 'High' } else { 'Low' }
        Passed      = ($ownerRatioPct -le 5)
        AffectedCount = $ownerRows.Count
        Fix         = 'Replace Owner with scoped custom roles. Use PIM for JIT Owner access.'
        Impact      = 'Owner role grants full control. Excessive usage is the leading cause of privilege escalation.'
        Effort      = 'Medium'
        Priority    = if ($ownerRatioPct -gt 15) { 'P1' } elseif ($ownerRatioPct -gt 5) { 'P2' } else { 'P4' }
    }

    $securityChecks += [PSCustomObject]@{
        CheckName   = 'Service Principal with Owner Role'
        Description = "$($spOwnerRows.Count) Service Principal(s) assigned the Owner role."
        Severity    = if ($spOwnerRows.Count -gt 0) { 'Critical' } else { 'Low' }
        Passed      = ($spOwnerRows.Count -eq 0)
        AffectedCount = $spOwnerRows.Count
        Fix         = 'Replace Owner with least-privilege custom roles for Service Principals. Review necessity of each SP Owner assignment.'
        Impact      = 'Compromised service principals with Owner rights enable lateral movement across the entire subscription.'
        Effort      = 'Low'
        Priority    = if ($spOwnerRows.Count -gt 0) { 'P1' } else { 'P4' }
    }

    $securityChecks += [PSCustomObject]@{
        CheckName   = 'Root Scope Assignments'
        Description = "$($rootScopeRows.Count) assignment(s) at Management Group root scope (/)."
        Severity    = if ($rootScopeRows.Count -gt 0) { 'Critical' } else { 'Low' }
        Passed      = ($rootScopeRows.Count -eq 0)
        AffectedCount = $rootScopeRows.Count
        Fix         = 'Remove root-scope assignments. Assign at lowest required scope (Resource Group or Resource).'
        Impact      = 'Root scope grants access to all management groups, subscriptions, and resources in the tenant.'
        Effort      = 'Low'
        Priority    = if ($rootScopeRows.Count -gt 0) { 'P1' } else { 'P4' }
    }

    $securityChecks += [PSCustomObject]@{
        CheckName   = 'Unknown / Orphaned Principals'
        Description = "$($unknownPrincipalRows.Count) assignment(s) with no identifiable principal (deleted objects)."
        Severity    = if ($unknownPrincipalRows.Count -gt 10) { 'High' } elseif ($unknownPrincipalRows.Count -gt 0) { 'Medium' } else { 'Low' }
        Passed      = ($unknownPrincipalRows.Count -eq 0)
        AffectedCount = $unknownPrincipalRows.Count
        Fix         = 'Remove orphaned role assignments using Azure CLI: az role assignment delete. Run periodic cleanup automation.'
        Impact      = 'Orphaned assignments consume license slots and can be exploited if object IDs are re-used.'
        Effort      = 'Low'
        Priority    = if ($unknownPrincipalRows.Count -gt 0) { 'P2' } else { 'P4' }
    }

    $securityChecks += [PSCustomObject]@{
        CheckName   = 'Guest / External Users'
        Description = "$($guestRows.Count) assignment(s) belong to external (guest) user accounts (#EXT#)."
        Severity    = if ($guestRows.Count -gt 5) { 'High' } elseif ($guestRows.Count -gt 0) { 'Medium' } else { 'Low' }
        Passed      = ($guestRows.Count -eq 0)
        AffectedCount = $guestRows.Count
        Fix         = 'Review necessity of each guest assignment. Enforce time-bound access and periodic re-certification.'
        Impact      = 'External users may not be subject to your organisation''s MFA and conditional access policies.'
        Effort      = 'Medium'
        Priority    = if ($guestRows.Count -gt 0) { 'P2' } else { 'P4' }
    }

    $securityChecks += [PSCustomObject]@{
        CheckName   = 'Over-Provisioned Principals'
        Description = "$overProvisionedCount principal(s) hold 10 or more role assignments."
        Severity    = if ($overProvisionedCount -gt 3) { 'High' } elseif ($overProvisionedCount -gt 0) { 'Medium' } else { 'Low' }
        Passed      = ($overProvisionedCount -eq 0)
        AffectedCount = $overProvisionedCount
        Fix         = 'Consolidate multiple assignments into a single custom role. Audit for role stacking anti-patterns.'
        Impact      = 'Excess permissions violate least-privilege and increase blast radius in a breach.'
        Effort      = 'Medium'
        Priority    = if ($overProvisionedCount -gt 0) { 'P2' } else { 'P4' }
    }

    $prodOwnerRows = @($ownerRows | Where-Object { $_.Environment -eq 'Prod' })
    $securityChecks += [PSCustomObject]@{
        CheckName   = 'Owner Roles in Production'
        Description = "$($prodOwnerRows.Count) Owner assignment(s) found in Production environment."
        Severity    = if ($prodOwnerRows.Count -gt 0) { 'High' } else { 'Low' }
        Passed      = ($prodOwnerRows.Count -eq 0)
        AffectedCount = $prodOwnerRows.Count
        Fix         = 'Enforce PIM JIT access for all Production Owner assignments. Require approval workflow and audit logging.'
        Impact      = 'Standing Owner access in Production is the highest-risk RBAC posture.'
        Effort      = 'Medium'
        Priority    = if ($prodOwnerRows.Count -gt 0) { 'P1' } else { 'P4' }
    }

    $uaaRows = @($enriched | Where-Object { $_.RoleDefinitionName -imatch 'user access administrator' })
    $securityChecks += [PSCustomObject]@{
        CheckName   = 'User Access Administrator Assignments'
        Description = "$($uaaRows.Count) User Access Administrator assignment(s) detected."
        Severity    = if ($uaaRows.Count -gt 3) { 'High' } elseif ($uaaRows.Count -gt 0) { 'Medium' } else { 'Low' }
        Passed      = ($uaaRows.Count -le 2)
        AffectedCount = $uaaRows.Count
        Fix         = 'Restrict User Access Administrator to break-glass accounts only. Use PIM for JIT activation.'
        Impact      = 'This role can re-assign any Azure RBAC role including Owner, enabling privilege escalation.'
        Effort      = 'Low'
        Priority    = if ($uaaRows.Count -gt 0) { 'P2' } else { 'P4' }
    }

    # ── Severity summary ──
    $criticalChecks = @($securityChecks | Where-Object { $_.Severity -eq 'Critical' -and -not $_.Passed })
    $highChecks     = @($securityChecks | Where-Object { $_.Severity -eq 'High'     -and -not $_.Passed })
    $mediumChecks   = @($securityChecks | Where-Object { $_.Severity -eq 'Medium'   -and -not $_.Passed })
    $lowChecks      = @($securityChecks | Where-Object { $_.Severity -eq 'Low'      -and -not $_.Passed })
    $passedChecks   = @($securityChecks | Where-Object { $_.Passed })
    $failedChecks   = @($securityChecks | Where-Object { -not $_.Passed })

    # ── Health & Risk scores ──
    $riskScore   = [Math]::Min(100, ($criticalChecks.Count * 30) + ($highChecks.Count * 15) + ($mediumChecks.Count * 5) + ($lowChecks.Count * 1))
    $healthScore = [Math]::Max(0, 100 - $riskScore)

    $complianceStatus = if ($criticalChecks.Count -gt 0)     { 'Fail' }
                        elseif ($highChecks.Count -gt 0)      { 'Warning' }
                        else                                   { 'Pass' }

    # ── Scope distribution ──
    $scopeDistribution = $enriched | Group-Object -Property {
        if     ($_.Scope -eq '/')                              { 'Root' }
        elseif ($_.Scope -match '/subscriptions/[^/]+$')      { 'Subscription' }
        elseif ($_.Scope -match '/resourceGroups/[^/]+$')     { 'Resource Group' }
        else                                                   { 'Resource' }
    } | Select-Object Name, Count

    # ── Object type distribution ──
    $objectTypeDistribution = $enriched | Group-Object -Property ObjectTypeSafe |
        Select-Object Name, Count | Sort-Object Count -Descending

    # ── Top principals & roles ──
    $topPrincipals = $enriched | Group-Object -Property DisplayName |
        Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 15

    $topRoles = $enriched | Group-Object -Property RoleDefinitionName |
        Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 15

    # ── Resource analysis ──
    $resourceTypeDistribution = $enriched | Where-Object { $_.ResourceTypeSafe -and $_.ResourceTypeSafe -ne 'Subscription' -and $_.ResourceTypeSafe -ne 'ResourceGroup' } |
        Group-Object -Property ResourceTypeSafe |
        Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 20

    $resourceGroupDist = $enriched | Where-Object { $_.Scope -match '/resourceGroups/([^/]+)' } | ForEach-Object {
        if ($_.Scope -match '/resourceGroups/([^/]+)') { $matches[1] }
    } | Group-Object | Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 15

    $individualResources = $enriched | Where-Object {
        $_.Scope -ne '/' -and
        $_.Scope -notmatch '/subscriptions/[^/]+$' -and
        $_.Scope -notmatch '/resourceGroups/[^/]+$'
    } | Group-Object -Property Scope | Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 15

    # ── Environment breakdown ──
    $environmentStats = $enriched | Group-Object -Property Environment | ForEach-Object {
        $envRows       = $_.Group
        $envPrincipals = @($envRows | Select-Object -ExpandProperty DisplayName -Unique).Count
        $envRoles      = @($envRows | Select-Object -ExpandProperty RoleDefinitionName -Unique).Count
        $envSubs       = @($envRows | Select-Object -ExpandProperty SubscriptionName -Unique).Count
        $envOwners     = @($envRows | Where-Object { $_.RoleDefinitionName -imatch 'owner' }).Count
        $envHighRisk   = @($envRows | Where-Object {
            $_.RoleDefinitionName -imatch 'owner|user access administrator' -or $_.Scope -eq '/'
        }).Count
        $envRisk       = [Math]::Min(100, ($envOwners / [Math]::Max(1,$envRows.Count)) * 100 + $envHighRisk)
        $envHealth     = [Math]::Max(0, 100 - $envRisk)
        [PSCustomObject]@{
            Environment   = $_.Name
            Count         = $_.Count
            Principals    = $envPrincipals
            Roles         = $envRoles
            Subscriptions = $envSubs
            OwnerCount    = $envOwners
            HighRiskCount = $envHighRisk
            HealthScore   = [Math]::Round($envHealth)
            RiskScore     = [Math]::Round($envRisk)
        }
    } | Sort-Object Count -Descending

    # ── Per-subscription stats ──
    $subscriptionStats = $enriched | Group-Object -Property SubscriptionName | ForEach-Object {
        $subRows   = $_.Group
        $firstRow  = $subRows[0]
        $subId     = $firstRow.SubscriptionId
        $tenantId  = $firstRow.TenantIdSafe
        $subEnv    = $firstRow.Environment
        $subOwners = @($subRows | Where-Object { $_.RoleDefinitionName -imatch 'owner' }).Count
        $subContrib= @($subRows | Where-Object { $_.RoleDefinitionName -imatch 'contributor' }).Count
        $subReader = @($subRows | Where-Object { $_.RoleDefinitionName -imatch 'reader' }).Count
        $subHighR  = @($subRows | Where-Object { $_.RoleDefinitionName -imatch 'owner|user access administrator' -or $_.Scope -eq '/' }).Count
        $subRiskPct= [Math]::Min(100, ($subOwners / [Math]::Max(1,$subRows.Count)) * 80 + ($subHighR / [Math]::Max(1,$subRows.Count)) * 20)
        $subHealth = [Math]::Max(0, 100 - $subRiskPct)
        $topSubRoles = $subRows | Group-Object -Property RoleDefinitionName |
            Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 5
        $topSubPrincipals = $subRows | Group-Object -Property DisplayName |
            Select-Object Name, Count | Sort-Object Count -Descending | Select-Object -First 5
        [PSCustomObject]@{
            SubscriptionName = $_.Name
            SubscriptionId   = $subId
            TenantId         = $tenantId
            Environment      = $subEnv
            TotalAssignments = $_.Count
            UniquePrincipals = @($subRows | Select-Object -ExpandProperty DisplayName -Unique).Count
            UniqueRoles      = @($subRows | Select-Object -ExpandProperty RoleDefinitionName -Unique).Count
            OwnerCount       = $subOwners
            ContribCount     = $subContrib
            ReaderCount      = $subReader
            HighRiskCount    = $subHighR
            HealthScore      = [Math]::Round($subHealth)
            RiskScore        = [Math]::Round($subRiskPct)
            TopRoles         = $topSubRoles
            TopPrincipals    = $topSubPrincipals
        }
    } | Sort-Object TotalAssignments -Descending

    # Execution time
    $executionTime = [Math]::Round(((Get-Date) - $scriptStartTime).TotalSeconds, 2)
    $psVersion     = $PSVersionTable.PSVersion.ToString()

    Write-Host "        ✓ Analysis complete" -ForegroundColor Green
    Write-Host "          Subscriptions    : $($uniqueSubscriptions.Count)"   -ForegroundColor Gray
    Write-Host "          Unique Roles     : $($uniqueRoles.Count)"           -ForegroundColor Gray
    Write-Host "          Unique Principals: $($uniquePrincipals.Count)"      -ForegroundColor Gray
    Write-Host "          Environments     : $($uniqueEnvironments -join ', ')" -ForegroundColor Gray
    Write-Host "          Health Score     : $healthScore / 100"              -ForegroundColor Gray
    Write-Host "          Risk Score       : $riskScore / 100"                -ForegroundColor Gray
    Write-Host "          Compliance       : $complianceStatus"               -ForegroundColor Gray

    #endregion

    #region ── JSON blobs ─────────────────────────────────────────────────────

    Write-Host '  [4/5] Building JSON data blobs...' -ForegroundColor Yellow

    $reportTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $reportDate      = Get-Date -Format 'MMMM dd, yyyy'

    # All rows
    $enrichedJson = ($enriched | ForEach-Object {
        $subN  = ConvertTo-JsonSafe $_.SubscriptionName
        $subId = ConvertTo-JsonSafe $_.SubscriptionId
        $tenId = ConvertTo-JsonSafe $_.TenantIdSafe
        $dn    = ConvertTo-JsonSafe $_.DisplayName
        $sin   = ConvertTo-JsonSafe $_.SignInNameSafe
        $ot    = ConvertTo-JsonSafe $_.ObjectTypeSafe
        $role  = ConvertTo-JsonSafe $_.RoleDefinitionName
        $rt    = ConvertTo-JsonSafe $_.ResourceTypeSafe
        $sc    = ConvertTo-JsonSafe $_.Scope
        $ev    = ConvertTo-JsonSafe $_.Environment
        "{`"SubscriptionName`":`"$subN`",`"SubscriptionId`":`"$subId`",`"TenantId`":`"$tenId`",`"DisplayName`":`"$dn`",`"SignInName`":`"$sin`",`"ObjectType`":`"$ot`",`"RoleDefinitionName`":`"$role`",`"ResourceType`":`"$rt`",`"Scope`":`"$sc`",`"Environment`":`"$ev`"}"
    }) -join ','

    $scopeJson = ($scopeDistribution | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name; "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $objTypeJson = ($objectTypeDistribution | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name; "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $topPrincJson = ($topPrincipals | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name; "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $topRolesJson = ($topRoles | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name; "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $resTypeJson = ($resourceTypeDistribution | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name; "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $resGroupJson = ($resourceGroupDist | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name; "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $indResJson = ($individualResources | ForEach-Object {
        $n = ConvertTo-JsonSafe $_.Name; "{`"Name`":`"$n`",`"Count`":$($_.Count)}"
    }) -join ','

    $envStatsJson = ($environmentStats | ForEach-Object {
        $e = ConvertTo-JsonSafe $_.Environment
        "{`"Environment`":`"$e`",`"Count`":$($_.Count),`"Principals`":$($_.Principals),`"Roles`":$($_.Roles),`"Subscriptions`":$($_.Subscriptions),`"OwnerCount`":$($_.OwnerCount),`"HighRiskCount`":$($_.HighRiskCount),`"HealthScore`":$($_.HealthScore),`"RiskScore`":$($_.RiskScore)}"
    }) -join ','

    $subStatsJson = ($subscriptionStats | ForEach-Object {
        $sn  = ConvertTo-JsonSafe $_.SubscriptionName
        $sid = ConvertTo-JsonSafe $_.SubscriptionId
        $tid = ConvertTo-JsonSafe $_.TenantId
        $ev  = ConvertTo-JsonSafe $_.Environment
        $trJson = ($_.TopRoles | ForEach-Object { $rn = ConvertTo-JsonSafe $_.Name; "{`"Name`":`"$rn`",`"Count`":$($_.Count)}" }) -join ','
        $tpJson = ($_.TopPrincipals | ForEach-Object { $pn = ConvertTo-JsonSafe $_.Name; "{`"Name`":`"$pn`",`"Count`":$($_.Count)}" }) -join ','
        "{`"SubscriptionName`":`"$sn`",`"SubscriptionId`":`"$sid`",`"TenantId`":`"$tid`",`"Environment`":`"$ev`",`"TotalAssignments`":$($_.TotalAssignments),`"UniquePrincipals`":$($_.UniquePrincipals),`"UniqueRoles`":$($_.UniqueRoles),`"OwnerCount`":$($_.OwnerCount),`"ContribCount`":$($_.ContribCount),`"ReaderCount`":$($_.ReaderCount),`"HighRiskCount`":$($_.HighRiskCount),`"HealthScore`":$($_.HealthScore),`"RiskScore`":$($_.RiskScore),`"TopRoles`":[$trJson],`"TopPrincipals`":[$tpJson]}"
    }) -join ','

    $secChecksJson = ($securityChecks | ForEach-Object {
        $cn  = ConvertTo-JsonSafe $_.CheckName
        $cd  = ConvertTo-JsonSafe $_.Description
        $fix = ConvertTo-JsonSafe $_.Fix
        $imp = ConvertTo-JsonSafe $_.Impact
        $sev = ConvertTo-JsonSafe $_.Severity
        $pri = ConvertTo-JsonSafe $_.Priority
        $eff = ConvertTo-JsonSafe $_.Effort
        $pas = if ($_.Passed) { 'true' } else { 'false' }
        "{`"CheckName`":`"$cn`",`"Description`":`"$cd`",`"Severity`":`"$sev`",`"Passed`":$pas,`"AffectedCount`":$($_.AffectedCount),`"Fix`":`"$fix`",`"Impact`":`"$imp`",`"Effort`":`"$eff`",`"Priority`":`"$pri`"}"
    }) -join ','

    $principalRiskJson = ($principalRiskData | ForEach-Object {
        $n  = ConvertTo-JsonSafe $_.DisplayName
        $rl = ConvertTo-JsonSafe $_.RiskLevel
        "{`"DisplayName`":`"$n`",`"RiskScore`":$($_.RiskScore),`"RiskLevel`":`"$rl`",`"Count`":$($_.Count)}"
    }) -join ','

    $uniqueSubsJson   = ($uniqueSubscriptions | ForEach-Object { "`"$(ConvertTo-JsonSafe $_)`"" }) -join ','
    $uniqueRolesJson  = ($uniqueRoles          | ForEach-Object { "`"$(ConvertTo-JsonSafe $_)`"" }) -join ','
    $uniqueEnvsJson   = ($uniqueEnvironments   | ForEach-Object { "`"$(ConvertTo-JsonSafe $_)`"" }) -join ','

    Write-Host '        ✓ JSON blobs ready' -ForegroundColor Green

    #endregion

    #region ── HTML Template ──────────────────────────────────────────────────

    Write-Host '  [5/5] Generating HTML dashboard...' -ForegroundColor Yellow

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure RBAC Analysis Report — __TENANTNAME__</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
/* ── All styles unchanged from v3.0 ── */
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

/* ── Sidebar ── */
#sidebar{position:fixed;top:0;left:0;bottom:0;width:220px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s;overflow-y:auto}
.sidebar-logo{padding:16px 16px 12px;border-bottom:1px solid var(--border);flex-shrink:0}
.logo-icon{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;margin-bottom:8px}
.sidebar-logo h1{font-size:13px;font-weight:700;color:var(--text)}
.sidebar-logo p{font-size:10.5px;color:var(--muted);font-family:var(--mono);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.version-badge{display:inline-block;margin-top:4px;background:rgba(56,139,253,.15);color:var(--accent);font-family:var(--mono);font-size:10px;padding:1px 7px;border-radius:20px;border:1px solid rgba(56,139,253,.3)}
.sidebar-nav{flex:1;padding:6px 0}
.nav-section-label{font-size:9.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:7px 15px 3px}
.nav-btn{display:flex;align-items:center;gap:9px;width:100%;padding:8px 15px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:14px;width:18px;text-align:center;flex-shrink:0}
.nav-btn .nav-badge{margin-left:auto;background:var(--surface3);color:var(--muted2);font-family:var(--mono);font-size:10px;padding:1px 6px;border-radius:20px}
.nav-btn:hover{color:var(--text);background:var(--surface2)}
.nav-btn.active{color:var(--accent);background:rgba(56,139,253,.1)}
.nav-btn.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);border-radius:0 2px 2px 0}
.theme-toggle-wrap{padding:8px 12px;border-top:1px solid var(--border);flex-shrink:0}
.theme-toggle{display:flex;align-items:center;gap:7px;width:100%;padding:7px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:12px;transition:all .2s}
.theme-toggle:hover{border-color:var(--accent);color:var(--text)}
.toggle-pill{width:32px;height:17px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;top:2px;left:2px;width:13px;height:13px;border-radius:50%;background:var(--muted2);transition:transform .2s,background .2s}
body.light-theme .toggle-pill{background:var(--accent)}
body.light-theme .toggle-pill::after{transform:translateX(15px);background:#fff}
.sidebar-footer{padding:8px 15px 10px;border-top:1px solid var(--border);font-size:10.5px;color:var(--muted);font-family:var(--mono);line-height:1.7;flex-shrink:0}
kbd{display:inline-block;padding:1px 4px;background:var(--surface3);border:1px solid var(--border);border-radius:3px;font-family:var(--mono);font-size:10px;color:var(--muted)}

/* ── Header bar ── */
#header-bar{position:fixed;top:0;left:220px;right:0;height:52px;background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 24px;gap:16px;z-index:90;transition:background .25s,border-color .25s}
.hbar-title{font-size:13.5px;font-weight:700;color:var(--text);flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hbar-tenant{font-family:var(--mono);font-size:11px;color:var(--muted2)}
.hbar-score{display:flex;align-items:center;gap:6px;font-size:12px;font-family:var(--mono)}
.hbar-score-pill{padding:3px 10px;border-radius:20px;font-weight:700;font-size:11px}
.health-pill{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.4)}
.health-pill.warn{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.4)}
.health-pill.bad{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.4)}
.risk-pill{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.4)}
.risk-pill.medium{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.4)}
.risk-pill.low{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.4)}
.hbar-divider{width:1px;height:28px;background:var(--border)}
.upload-btn{display:flex;align-items:center;gap:6px;padding:6px 12px;border-radius:var(--radius-sm);border:1px solid var(--border);background:var(--surface2);color:var(--muted2);font-size:12px;cursor:pointer;transition:all .2s;white-space:nowrap;font-family:var(--sans)}
.upload-btn:hover{border-color:var(--accent2);color:var(--accent2)}

/* ── Main ── */
#main{margin-left:220px;margin-top:52px;min-height:calc(100vh - 52px)}
.page{display:none;padding:24px 28px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:18px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:10px}
.page-title{font-size:22px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:12.5px;margin-top:2px}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 13px;border-radius:var(--radius-sm);font-size:12.5px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn.btn-green{border-color:var(--green);color:var(--green)}
.btn.btn-green:hover{background:rgba(63,185,80,.08)}
.btn.btn-red{border-color:var(--red);color:var(--red)}
.btn.btn-red:hover{background:rgba(248,81,73,.08)}
.btn-group{display:flex;gap:7px;flex-wrap:wrap}

/* ── Stat cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:11px;margin-bottom:18px}
.stats-grid-wide{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:11px;margin-bottom:18px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 15px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-icon{font-size:18px;margin-bottom:7px}
.stat-value{font-size:24px;font-weight:700;color:var(--text);line-height:1}
.stat-label{color:var(--muted);font-size:11.5px;margin-top:3px}
.stat-card.c-blue  {border-top:2px solid var(--accent)}
.stat-card.c-cyan  {border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green {border-top:2px solid var(--green)}
.stat-card.c-amber {border-top:2px solid var(--amber)}
.stat-card.c-red   {border-top:2px solid var(--red)}
.stat-card.c-muted {border-top:2px solid var(--muted)}

/* ── Panel / chart grid ── */
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
.chart-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px}
@media(max-width:1100px){.chart-grid-3{grid-template-columns:1fr 1fr}}
@media(max-width:900px){.chart-grid,.chart-grid-3{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:16px}
.section-title{font-size:14px;font-weight:700;margin-bottom:11px;color:var(--text);display:flex;align-items:center;gap:7px}
.chart-wrap{position:relative;height:300px}
.chart-wrap.tall{height:380px}
.chart-wrap.short{height:220px}

/* ── Score ring ── */
.score-ring-wrap{display:flex;align-items:center;gap:18px;padding:10px 0}
.score-ring{width:80px;height:80px;flex-shrink:0}
.score-ring svg{width:80px;height:80px;transform:rotate(-90deg)}
.score-ring svg text{transform:rotate(90deg);transform-origin:40px 41px}
.score-ring circle{fill:none;stroke-width:8}
.score-track{stroke:var(--surface3)}
.score-fill{stroke-dasharray:220;stroke-linecap:round;transition:stroke-dashoffset 1s ease}
.score-label{font-family:var(--mono);font-size:17px;font-weight:700;text-anchor:middle;dominant-baseline:middle}
.score-info h3{font-size:14px;font-weight:700;color:var(--text)}
.score-info p{font-size:12px;color:var(--muted);margin-top:3px}

/* ── Bar list ── */
.bar-row{display:flex;align-items:center;gap:9px;margin-bottom:8px}
.bar-label{font-family:var(--mono);font-size:11px;color:var(--muted2);width:130px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:7px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:28px;text-align:right;flex-shrink:0}

/* ── Environment cards ── */
.env-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:13px;margin-bottom:20px}
.env-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;cursor:pointer;transition:border-color .2s,transform .2s}
.env-card:hover{border-color:var(--accent2);transform:translateY(-2px)}
.env-badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:10.5px;font-weight:700;font-family:var(--mono);letter-spacing:.04em;margin-bottom:9px}
.env-badge.prod   {background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.4)}
.env-badge.uat    {background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.4)}
.env-badge.dev    {background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.4)}
.env-badge.test   {background:rgba(163,113,247,.15);color:var(--accent3);border:1px solid rgba(163,113,247,.3)}
.env-badge.unknown{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
.env-total{font-size:26px;font-weight:700;color:var(--text);line-height:1}
.env-sub-stats{display:flex;gap:12px;margin-top:8px;font-size:11.5px;color:var(--muted2)}
.env-sub-stat{display:flex;flex-direction:column;gap:1px}
.env-sub-stat span:first-child{font-family:var(--mono);font-size:13px;color:var(--text);font-weight:600}
.env-scores{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}

/* ── Subscription cards ── */
.sub-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:13px;margin-bottom:20px}
.sub-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px;cursor:pointer;transition:border-color .2s,transform .2s;display:flex;flex-direction:column;gap:9px}
.sub-card:hover{border-color:var(--accent);transform:translateY(-2px)}
.sub-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:7px}
.sub-name{font-size:12.5px;font-weight:700;color:var(--text);line-height:1.3}
.sub-id{font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:2px;word-break:break-all}
.sub-stats-row{display:flex;gap:10px;flex-wrap:wrap}
.sub-stat{display:flex;flex-direction:column;gap:1px}
.sub-stat span:first-child{font-family:var(--mono);font-size:14px;font-weight:700;color:var(--accent2)}
.sub-stat span:last-child{font-size:10.5px;color:var(--muted)}
.sub-role-row{display:flex;gap:6px;flex-wrap:wrap}

/* ── Security check cards ── */
.sec-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px;margin-bottom:20px}
.sec-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;transition:border-color .2s}
.sec-card.critical{border-left:3px solid var(--red)}
.sec-card.high{border-left:3px solid var(--amber)}
.sec-card.medium{border-left:3px solid var(--accent3)}
.sec-card.low,.sec-card.passed{border-left:3px solid var(--green)}
.sec-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:8px}
.sec-card-title{font-size:13px;font-weight:700;color:var(--text)}
.sec-card-body{font-size:12px;color:var(--muted2);line-height:1.5}
.sec-card-fix{margin-top:8px;padding:8px;background:var(--surface2);border-radius:var(--radius-sm);font-size:11.5px;color:var(--muted);line-height:1.5}
.sec-card-fix strong{color:var(--accent2);display:block;margin-bottom:2px}
.sec-meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.sec-meta-chip{font-size:10.5px;padding:2px 8px;border-radius:20px;background:var(--surface3);color:var(--muted2)}

/* ── Severity summary cards ── */
.sev-summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
@media(max-width:800px){.sev-summary{grid-template-columns:repeat(2,1fr)}}
.sev-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center}
.sev-count{font-family:var(--mono);font-size:32px;font-weight:700;line-height:1}
.sev-label{font-size:12px;color:var(--muted);margin-top:4px}
.sev-card.c-critical .sev-count{color:var(--red)}
.sev-card.c-high .sev-count{color:var(--amber)}
.sev-card.c-medium .sev-count{color:var(--accent3)}
.sev-card.c-low-pass .sev-count{color:var(--green)}

/* ── Compliance banner ── */
.compliance-banner{display:flex;align-items:center;gap:14px;padding:14px 18px;border-radius:var(--radius);margin-bottom:18px;border:1px solid}
.compliance-banner.pass{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.3)}
.compliance-banner.warn{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3)}
.compliance-banner.fail{background:rgba(248,81,73,.08);border-color:rgba(248,81,73,.3)}
.compliance-icon{font-size:28px}
.compliance-text h3{font-size:14px;font-weight:700}
.compliance-text p{font-size:12px;color:var(--muted2);margin-top:2px}
.compliance-banner.pass .compliance-text h3{color:var(--green)}
.compliance-banner.warn .compliance-text h3{color:var(--amber)}
.compliance-banner.fail .compliance-text h3{color:var(--red)}

/* ── Recommendation cards (enhanced) ── */
.reco-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:14px;transition:border-color .2s}
.reco-card:hover{border-color:var(--accent)}
.reco-card-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:10px}
.reco-priority-badge{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;font-family:var(--mono)}
.reco-priority-badge.P1{background:rgba(248,81,73,.2);color:var(--red)}
.reco-priority-badge.P2{background:rgba(210,153,34,.2);color:var(--amber)}
.reco-priority-badge.P3{background:rgba(163,113,247,.2);color:var(--accent3)}
.reco-priority-badge.P4{background:rgba(63,185,80,.2);color:var(--green)}
.reco-card-title{font-size:14px;font-weight:700;color:var(--text)}
.reco-card-desc{font-size:13px;color:var(--muted2);line-height:1.5;margin-bottom:10px}
.reco-detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}
@media(max-width:700px){.reco-detail-grid{grid-template-columns:1fr}}
.reco-detail-box{background:var(--surface2);border-radius:var(--radius-sm);padding:10px 12px}
.reco-detail-box h5{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:4px}
.reco-detail-box p{font-size:12px;color:var(--muted2);line-height:1.5}
.reco-footer{display:flex;align-items:center;gap:8px;margin-top:12px;flex-wrap:wrap}

/* ── Audit report ── */
.audit-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.audit-stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px;text-align:center}
.audit-stat .val{font-family:var(--mono);font-size:28px;font-weight:700;color:var(--text);line-height:1}
.audit-stat .lbl{font-size:11.5px;color:var(--muted);margin-top:4px}
.audit-check-list{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:6px 0;margin-bottom:16px}
.audit-check-row{display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border);font-size:13px}
.audit-check-row:last-child{border-bottom:none}
.audit-status-icon{width:20px;text-align:center;flex-shrink:0}
.audit-check-name{flex:1;font-weight:600}
.audit-check-sev{flex-shrink:0}
.audit-check-count{font-family:var(--mono);font-size:12px;color:var(--muted);flex-shrink:0;width:60px;text-align:right}

/* ── Table ── */
.toolbar{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:11px;align-items:center}
.search-wrap{flex:1;min-width:180px;position:relative}
.search-wrap .icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:12px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:13.5px;padding:7px 10px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:32px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--accent)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:12.5px;flex-shrink:0}
.page-size-wrap{display:flex;align-items:center;gap:5px;font-size:11.5px;color:var(--muted)}
.page-size-wrap select{padding:4px 7px;font-size:11.5px}
.rbac-table{width:100%;border-collapse:collapse}
.rbac-table thead th{text-align:left;font-family:var(--sans);font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:8px 11px;border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer;user-select:none}
.rbac-table thead th:hover{color:var(--text)}
.rbac-table thead th .sort-icon{margin-left:4px;opacity:.4}
.rbac-table tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.rbac-table tbody tr:hover{background:var(--surface2)}
.rbac-table tbody td{padding:8px 11px;vertical-align:middle;font-size:12.5px}
.td-mono{font-family:var(--mono);font-size:11.5px;color:var(--accent2)}
.td-scope{font-family:var(--mono);font-size:10.5px;color:var(--muted);max-width:240px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.td-actions{display:flex;gap:4px}
.icon-btn{background:none;border:none;cursor:pointer;color:var(--muted);font-size:13px;padding:2px 5px;border-radius:4px;transition:all .2s}
.icon-btn:hover{background:var(--surface3);color:var(--text)}
.pagination{display:flex;gap:4px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:11px}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:11.5px;padding:4px 9px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}

/* ── Column chooser ── */
.col-chooser-wrap{position:relative}
.col-chooser-dropdown{position:absolute;top:calc(100% + 4px);right:0;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:8px;z-index:200;min-width:180px;box-shadow:var(--shadow);display:none}
.col-chooser-dropdown.open{display:block}
.col-chooser-item{display:flex;align-items:center;gap:8px;padding:5px 8px;cursor:pointer;border-radius:var(--radius-sm);font-size:12.5px;color:var(--muted2)}
.col-chooser-item:hover{background:var(--surface2);color:var(--text)}
.col-chooser-item input{cursor:pointer}

/* ── Badges ── */
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:10.5px;font-weight:600;font-family:var(--sans)}
.badge-blue  {background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3)}
.badge-green {background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.badge-amber {background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3)}
.badge-red   {background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.badge-purple{background:rgba(163,113,247,.15);color:var(--accent3);border:1px solid rgba(163,113,247,.3)}
.badge-muted {background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
.badge-critical{background:rgba(248,81,73,.2);color:var(--red);border:1px solid rgba(248,81,73,.5)}
.badge-high  {background:rgba(210,153,34,.2);color:var(--amber);border:1px solid rgba(210,153,34,.5)}
.badge-medium{background:rgba(163,113,247,.15);color:var(--accent3);border:1px solid rgba(163,113,247,.3)}
.badge-low   {background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}

/* ── Info / warning boxes ── */
.info-box  {background:rgba(56,139,253,.08);border-left:3px solid var(--accent);padding:12px 14px;border-radius:0 var(--radius-sm) var(--radius-sm) 0;margin-bottom:16px}
.info-box h4{color:var(--accent);font-size:12.5px;margin-bottom:3px}
.info-box p {color:var(--muted2);font-size:12.5px}
.warn-box  {background:rgba(210,153,34,.08);border-left:3px solid var(--amber);padding:12px 14px;border-radius:0 var(--radius-sm) var(--radius-sm) 0;margin-bottom:16px}
.warn-box h4{color:var(--amber);font-size:12.5px;margin-bottom:3px}
.warn-box p {color:var(--muted2);font-size:12.5px}
.danger-box{background:rgba(248,81,73,.08);border-left:3px solid var(--red);padding:12px 14px;border-radius:0 var(--radius-sm) var(--radius-sm) 0;margin-bottom:11px}
.danger-box h4{color:var(--red);font-size:12.5px;margin-bottom:3px}
.danger-box p {color:var(--muted2);font-size:12.5px}

/* ── Detail drawer ── */
#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(680px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:22px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:7px;margin-bottom:16px;flex-shrink:0}
.detail-toolbar-title{font-family:var(--mono);font-size:12.5px;color:var(--muted2);flex:1}
#detailClose{background:var(--surface3);border:none;color:var(--muted2);width:28px;height:28px;border-radius:50%;cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--red);color:#fff}
#detailContent{flex:1;overflow-y:auto}
.detail-header{margin-bottom:14px}
.detail-name{font-family:var(--mono);font-size:15px;color:var(--accent2);font-weight:600;word-break:break-all}
.detail-sub{font-family:var(--mono);font-size:10.5px;color:var(--muted);margin-top:3px;word-break:break-all}
.detail-meta-row{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:2px 9px;font-size:11.5px;color:var(--muted2)}
.detail-section{margin-top:16px}
.detail-section-title{font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.detail-mini-row{display:flex;align-items:center;gap:9px;padding:5px 0;border-bottom:1px solid var(--border);font-size:12px}
.detail-mini-row:last-child{border-bottom:none}
.detail-mini-label{color:var(--muted);width:110px;flex-shrink:0;font-size:11.5px}
.detail-mini-val{color:var(--text);font-family:var(--mono);font-size:11.5px;flex:1;word-break:break-all}

/* ── CSV Upload overlay ── */
#uploadOverlay{position:fixed;inset:0;z-index:600;background:rgba(0,0,0,.8);backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center}
#uploadOverlay.open{display:flex}
.upload-modal{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:32px;width:min(520px,90vw);text-align:center}
.upload-modal h2{font-size:18px;font-weight:700;margin-bottom:8px;color:var(--text)}
.upload-modal p{font-size:13px;color:var(--muted);margin-bottom:24px}
.drop-zone{border:2px dashed var(--border);border-radius:var(--radius);padding:40px 20px;cursor:pointer;transition:all .25s;position:relative}
.drop-zone.drag-over{border-color:var(--accent2);background:rgba(57,197,207,.06)}
.drop-zone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.drop-zone-icon{font-size:36px;margin-bottom:10px}
.drop-zone-text{font-size:13.5px;color:var(--muted2)}
.drop-zone-sub{font-size:12px;color:var(--muted);margin-top:4px}
.upload-progress{margin-top:16px;display:none}
.progress-bar{height:4px;background:var(--surface3);border-radius:2px;overflow:hidden;margin-top:6px}
.progress-fill{height:100%;background:var(--accent2);border-radius:2px;width:0%;transition:width .3s}
.upload-modal-footer{display:flex;justify-content:center;gap:10px;margin-top:20px}

/* ── Footer ── */
#app-footer{background:var(--surface);border-top:1px solid var(--border);padding:12px 28px;font-size:11px;color:var(--muted);font-family:var(--mono);display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between}
.footer-brand{color:var(--accent2);font-weight:600}
.footer-link{color:var(--accent);text-decoration:none}
.footer-link:hover{text-decoration:underline}
.footer-divider{color:var(--border)}

/* ── Toast ── */
#toast{position:fixed;bottom:20px;right:20px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:9px 14px;font-size:12.5px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:7px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

/* ── Mobile ── */
@media(max-width:768px){
  #sidebar{transform:translateX(-220px);transition:transform .3s}
  #sidebar.open{transform:translateX(0)}
  #main{margin-left:0}
  #header-bar{left:0}
  .page{padding:16px}
  #menuToggle{display:flex}
  .chart-grid,.chart-grid-3{grid-template-columns:1fr}
  .sev-summary{grid-template-columns:repeat(2,1fr)}
}
#menuToggle{display:none;position:fixed;top:13px;left:13px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 9px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<!-- ════════════════ HEADER BAR ════════════════ -->
<div id="header-bar">
  <div>
    <div class="hbar-title">Azure RBAC Analysis — <span class="hbar-tenant">__TENANTNAME__</span></div>
  </div>
  <div class="hbar-divider"></div>
  <div class="hbar-score">
    <span>Health</span>
    <span class="hbar-score-pill health-pill __HEALTHCLASS__" id="healthPill">__HEALTHSCORE__ / 100</span>
  </div>
  <div class="hbar-score">
    <span>Risk</span>
    <span class="hbar-score-pill risk-pill __RISKCLASS__" id="riskPill">__RISKSCORE__ / 100</span>
  </div>
  <div class="hbar-divider"></div>
  <div class="hbar-score">
    <span class="hbar-score-pill __COMPLIANCECLASS__" id="statusPill">__COMPLIANCESTATUS__</span>
  </div>
  <div class="hbar-divider"></div>
  <button class="upload-btn" onclick="openUpload()">📂 Load CSV</button>
</div>

<!-- ════════════════ SIDEBAR ════════════════ -->
<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🔐</div>
    <h1>RBAC Analysis</h1>
    <p>__REPORTDATE__</p>
    <span class="version-badge">v3.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Analytics</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">📊</span> Executive Dashboard
    </button>
    <button class="nav-btn" onclick="showPage('security',this)">
      <span class="nav-icon">🛡</span> Security Dashboard
      <span class="nav-badge" id="secBadge">__FAILEDCHECKS__</span>
    </button>
    <div class="nav-section-label">Identity</div>
    <button class="nav-btn" onclick="showPage('principals',this)">
      <span class="nav-icon">👥</span> Principals
      <span class="nav-badge">__PRINCIPALCOUNT__</span>
    </button>
    <button class="nav-btn" onclick="showPage('roles',this)">
      <span class="nav-icon">🎭</span> Roles
      <span class="nav-badge">__ROLECOUNT__</span>
    </button>
    <div class="nav-section-label">Infrastructure</div>
    <button class="nav-btn" onclick="showPage('resources',this)">
      <span class="nav-icon">📦</span> Resources
    </button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)">
      <span class="nav-icon">📋</span> Subscriptions
      <span class="nav-badge">__SUBCOUNT__</span>
    </button>
    <button class="nav-btn" onclick="showPage('environments',this)">
      <span class="nav-icon">🌍</span> Environments
    </button>
    <div class="nav-section-label">Reports</div>
    <button class="nav-btn" onclick="showPage('recommendations',this)">
      <span class="nav-icon">💡</span> Recommendations
    </button>
    <button class="nav-btn" onclick="showPage('audit',this)">
      <span class="nav-icon">📑</span> Audit Report
    </button>
    <button class="nav-btn" onclick="showPage('rawdata',this)">
      <span class="nav-icon">🗄</span> Raw Data
      <span class="nav-badge">__TOTALRECORDS__</span>
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
    <span class="footer-brand">Cloud-Identity-Toolkit</span><br>
    Generated: __REPORTTIMESTAMP__<br>
    <span style="color:var(--accent2)">⌨</span>&nbsp;<kbd>/</kbd> search &nbsp;<kbd>Esc</kbd> close
  </div>
</nav>

<!-- ════════════════ MAIN ════════════════ -->
<main id="main">

<!-- ── EXECUTIVE DASHBOARD ── -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Executive Dashboard</div>
      <div class="page-subtitle">Tenant-wide RBAC health &amp; access snapshot — __TOTALRECORDS__ total assignments</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportAllCSV()">⬇ Export Full CSV</button>
    </div>
  </div>

  <!-- Score cards -->
  <div class="chart-grid" style="margin-bottom:16px">
    <div class="panel" style="display:flex;align-items:center;gap:0">
      <div class="score-ring-wrap" style="flex:1">
        <div class="score-ring">
          <svg viewBox="0 0 80 80">
            <circle class="score-track" cx="40" cy="40" r="30"/>
            <circle class="score-fill" id="healthRing" cx="40" cy="40" r="30" stroke="var(--green)" stroke-dashoffset="220"/>
            <text class="score-label" x="40" y="41" fill="var(--green)" ... id="healthScoreText" transform="rotate(90,40,41)">__HEALTHSCORE__</text>
          </svg>
        </div>
        <div class="score-info">
          <h3>Health Score</h3>
          <p>Based on __CHECKTOTAL__ security checks</p>
          <div style="margin-top:6px"><span class="hbar-score-pill health-pill __HEALTHCLASS__">__HEALTHSCORE__ / 100</span></div>
        </div>
      </div>
      <div style="width:1px;height:80px;background:var(--border);flex-shrink:0;margin:0 16px"></div>
      <div class="score-ring-wrap" style="flex:1">
        <div class="score-ring">
          <svg viewBox="0 0 80 80">
            <circle class="score-track" cx="40" cy="40" r="30"/>
            <circle class="score-fill" id="riskRing" cx="40" cy="40" r="30" stroke="var(--red)" stroke-dashoffset="220"/>
            <text class="score-label" x="40" y="41" fill="var(--red)" font-family="JetBrains Mono" font-size="14" font-weight="700" id="riskScoreText">__RISKSCORE__</text>
          </svg>
        </div>
        <div class="score-info">
          <h3>Risk Score</h3>
          <p>__CRITICALCHECKS__ critical · __HIGHCHECKS__ high findings</p>
          <div style="margin-top:6px"><span class="hbar-score-pill risk-pill __RISKCLASS__">__RISKSCORE__ / 100</span></div>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="section-title">🔢 Assignment Summary</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
        <div style="background:var(--surface2);border-radius:var(--radius-sm);padding:10px;text-align:center"><div style="font-family:var(--mono);font-size:22px;font-weight:700;color:var(--accent)">__TOTALRECORDS__</div><div style="font-size:11px;color:var(--muted);margin-top:2px">Total Assignments</div></div>
        <div style="background:var(--surface2);border-radius:var(--radius-sm);padding:10px;text-align:center"><div style="font-family:var(--mono);font-size:22px;font-weight:700;color:var(--red)" id="ownerCountStat">-</div><div style="font-size:11px;color:var(--muted);margin-top:2px">Owner Assignments</div></div>
        <div style="background:var(--surface2);border-radius:var(--radius-sm);padding:10px;text-align:center"><div style="font-family:var(--mono);font-size:22px;font-weight:700;color:var(--accent3)">__ROLECOUNT__</div><div style="font-size:11px;color:var(--muted);margin-top:2px">Unique Roles</div></div>
        <div style="background:var(--surface2);border-radius:var(--radius-sm);padding:10px;text-align:center"><div style="font-family:var(--mono);font-size:22px;font-weight:700;color:var(--accent2)">__SUBCOUNT__</div><div style="font-size:11px;color:var(--muted);margin-top:2px">Subscriptions</div></div>
      </div>
    </div>
  </div>

  <!-- Principal type KPIs -->
  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">👤</div><div class="stat-value">__UNIQUEUSERS__</div><div class="stat-label">Users</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">👥</div><div class="stat-value">__UNIQUEGROUPS__</div><div class="stat-label">Groups</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">⚙</div><div class="stat-value">__UNIQUESPS__</div><div class="stat-label">Service Principals</div></div>
    <div class="stat-card c-green"><div class="stat-icon">🤖</div><div class="stat-value">__UNIQUEMIS__</div><div class="stat-label">Managed Identities</div></div>
    <div class="stat-card c-muted"><div class="stat-icon">❓</div><div class="stat-value">__UNKNOWNOBJS__</div><div class="stat-label">Unknown Objects</div></div>
    <div class="stat-card c-red"><div class="stat-icon">⚠</div><div class="stat-value">__HIGHRISKCOUNT__</div><div class="stat-label">High Risk Principals</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">🌍</div><div class="stat-value">__ENVCOUNT__</div><div class="stat-label">Environments</div></div>
    <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-value">__PASSEDCHECKS__</div><div class="stat-label">Checks Passed</div></div>
  </div>

  <!-- Role breakdown KPIs -->
  <div class="stats-grid-wide" style="margin-bottom:20px">
    <div class="stat-card c-red"><div class="stat-icon">🔴</div><div class="stat-value" id="ownerRoleCount">-</div><div class="stat-label">Owner Assignments</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">🟡</div><div class="stat-value" id="contribRoleCount">-</div><div class="stat-label">Contributor Assignments</div></div>
    <div class="stat-card c-green"><div class="stat-icon">🟢</div><div class="stat-value" id="readerRoleCount">-</div><div class="stat-label">Reader Assignments</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">🎯</div><div class="stat-value">__CUSTOMROLECOUNT__</div><div class="stat-label">Custom Roles Defined</div></div>
    <div class="stat-card c-muted"><div class="stat-icon">👻</div><div class="stat-value">__GUESTCOUNT__</div><div class="stat-label">Guest User Assignments</div></div>
    <div class="stat-card c-red"><div class="stat-icon">🌐</div><div class="stat-value">__ROOTSCOPECOUNT__</div><div class="stat-label">Root Scope Assignments</div></div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🍩 Scope Distribution</div>
      <div class="chart-wrap"><canvas id="scopeChart"></canvas></div>
    </div>
    <div class="panel">
      <div class="section-title">👤 Object Type Distribution</div>
      <div class="chart-wrap"><canvas id="objTypeChart"></canvas></div>
    </div>
  </div>

  <div class="panel">
    <div class="section-title">🏆 Top 15 Principals by Assignment Count</div>
    <div class="chart-wrap tall"><canvas id="topPrincChart"></canvas></div>
  </div>

  <div class="panel">
    <div class="section-title">🎯 Top 15 Roles by Usage</div>
    <div class="chart-wrap tall"><canvas id="topRolesChart"></canvas></div>
  </div>
</section>

<!-- ── SECURITY DASHBOARD ── -->
<section id="page-security" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Security Dashboard</div>
      <div class="page-subtitle">Automated RBAC security posture assessment — __CHECKTOTAL__ checks executed</div>
    </div>
    <div class="btn-group">
      <button class="btn btn-red" onclick="exportSecurityReport()">⬇ Export Security Report</button>
    </div>
  </div>

  <div id="complianceBanner"></div>

  <div class="sev-summary">
    <div class="sev-card c-critical">
      <div class="sev-count" id="critCount">-</div>
      <div class="sev-label">Critical Findings</div>
    </div>
    <div class="sev-card c-high">
      <div class="sev-count" id="highCount">-</div>
      <div class="sev-label">High Findings</div>
    </div>
    <div class="sev-card c-medium">
      <div class="sev-count" id="medCount">-</div>
      <div class="sev-label">Medium Findings</div>
    </div>
    <div class="sev-card c-low-pass">
      <div class="sev-count" id="passCount">-</div>
      <div class="sev-label">Checks Passed</div>
    </div>
  </div>

  <div id="secCheckFilter" class="toolbar" style="margin-bottom:14px">
    <select id="sevFilter" onchange="renderSecChecks()">
      <option value="">All Severities</option>
      <option value="Critical">Critical</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
    </select>
    <select id="statusFilter" onchange="renderSecChecks()">
      <option value="">All Status</option>
      <option value="failed">Failed Only</option>
      <option value="passed">Passed Only</option>
    </select>
  </div>
  <div class="sec-grid" id="secCardsContainer"></div>
</section>

<!-- ── PRINCIPALS ── -->
<section id="page-principals" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Principal Analysis</div>
      <div class="page-subtitle">Per-user / group / service-principal assignment breakdown with risk scoring</div>
    </div>
    <div class="btn-group">
      <button class="btn btn-green" onclick="exportPrincCSV()">⬇ Export CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="princSearch" placeholder="Search name or sign-in…" oninput="renderPrincTable()"/>
    </div>
    <select id="princEnvFilter" onchange="renderPrincTable()"><option value="">All Environments</option></select>
    <select id="princTypeFilter" onchange="renderPrincTable()"><option value="">All Object Types</option></select>
    <select id="princRiskFilter" onchange="renderPrincTable()">
      <option value="">All Risk Levels</option>
      <option value="Critical">Critical</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
    </select>
    <div class="page-size-wrap">Show <select id="princPageSize" onchange="renderPrincTable()"><option>25</option><option>50</option><option>100</option></select></div>
    <span class="result-count" id="princResultCount"></span>
  </div>
  <div style="overflow-x:auto">
    <table class="rbac-table">
      <thead><tr>
        <th>Principal</th>
        <th>Sign-In Name</th>
        <th>Object Type</th>
        <th>Risk Score</th>
        <th>Assignments</th>
        <th>Unique Roles</th>
        <th>Subscriptions</th>
        <th>Environment(s)</th>
      </tr></thead>
      <tbody id="princTableBody"></tbody>
    </table>
  </div>
  <div class="pagination" id="princPagination"></div>
</section>

<!-- ── ROLES ── -->
<section id="page-roles" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Role Usage Analysis</div>
      <div class="page-subtitle">How roles are distributed across the tenant</div>
    </div>
    <div class="btn-group">
      <button class="btn btn-green" onclick="exportRolesCSV()">⬇ Export CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="roleSearch" placeholder="Search roles…" oninput="renderRoleTable()"/>
    </div>
    <select id="rolePermFilter" onchange="renderRoleTable()">
      <option value="">All Levels</option>
      <option value="owner">Owner</option>
      <option value="contributor">Contributor</option>
      <option value="reader">Reader</option>
      <option value="custom">Custom / Other</option>
    </select>
    <span class="result-count" id="roleResultCount"></span>
  </div>
  <div style="overflow-x:auto">
    <table class="rbac-table">
      <thead><tr>
        <th>Role Name</th>
        <th>Assignments</th>
        <th>Unique Principals</th>
        <th>Subscriptions</th>
        <th>Permission Level</th>
      </tr></thead>
      <tbody id="roleTableBody"></tbody>
    </table>
  </div>
  <div class="panel" style="margin-top:20px">
    <div class="section-title">📊 Top 10 Roles — Bar Distribution</div>
    <div id="roleBarList"></div>
  </div>
</section>

<!-- ── RESOURCE ANALYSIS ── -->
<section id="page-resources" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Resource Analysis</div>
      <div class="page-subtitle">RBAC assignments by resource type, resource group, and individual resource</div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📦 Top Resource Types</div>
      <div class="chart-wrap"><canvas id="resTypeChart"></canvas></div>
    </div>
    <div class="panel">
      <div class="section-title">📁 Top Resource Groups</div>
      <div class="chart-wrap"><canvas id="resGroupChart"></canvas></div>
    </div>
  </div>

  <div class="panel">
    <div class="section-title">🔍 Individual Resources with Assignments</div>
    <div class="toolbar">
      <div class="search-wrap">
        <span class="icon">🔎</span>
        <input type="text" id="resSearch" placeholder="Search resources…" oninput="renderResTable()"/>
      </div>
      <span class="result-count" id="resResultCount"></span>
    </div>
    <div style="overflow-x:auto">
      <table class="rbac-table">
        <thead><tr>
          <th>Resource Scope</th>
          <th>Assignments</th>
          <th>Resource Type</th>
          <th>Resource Group</th>
        </tr></thead>
        <tbody id="resTableBody"></tbody>
      </table>
    </div>
    <div class="pagination" id="resPagination"></div>
  </div>
</section>

<!-- ── SUBSCRIPTIONS ── -->
<section id="page-subscriptions" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Subscriptions</div>
      <div class="page-subtitle">Per-subscription assignment summary with health &amp; risk scores</div>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="subSearch" placeholder="Search subscriptions…" oninput="renderSubCards()"/>
    </div>
    <select id="subEnvFilter" onchange="renderSubCards()"><option value="">All Environments</option></select>
  </div>
  <div class="sub-grid" id="subCardsContainer"></div>
</section>

<!-- ── ENVIRONMENTS ── -->
<section id="page-environments" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Environment Breakdown</div>
      <div class="page-subtitle">Auto-detected from subscription name keywords — includes health &amp; risk scoring per environment</div>
    </div>
  </div>
  <div class="info-box">
    <h4>📌 Detection Logic</h4>
    <p>Environments are inferred by scanning each SubscriptionName for keywords: <strong>prod, uat, dev, test, staging, sandbox, engineering</strong> etc. Unmatched subscriptions are labelled <em>Unknown</em>.</p>
  </div>
  <div class="env-grid" id="envCardsContainer"></div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Assignments per Environment</div>
      <div class="chart-wrap"><canvas id="envAssignChart"></canvas></div>
    </div>
    <div class="panel">
      <div class="section-title">👥 Principals per Environment</div>
      <div class="chart-wrap"><canvas id="envPrincChart"></canvas></div>
    </div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">⚠ High Risk Assignments per Environment</div>
      <div class="chart-wrap"><canvas id="envRiskChart"></canvas></div>
    </div>
    <div class="panel">
      <div class="section-title">💊 Health Score per Environment</div>
      <div class="chart-wrap"><canvas id="envHealthChart"></canvas></div>
    </div>
  </div>
</section>

<!-- ── RECOMMENDATIONS ── -->
<section id="page-recommendations" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Recommendations</div>
      <div class="page-subtitle">Prioritised least-privilege findings with business impact, effort estimates &amp; suggested fixes</div>
    </div>
    <div class="btn-group">
      <button class="btn btn-green" onclick="exportRecoCSV()">⬇ Export Recommendations</button>
    </div>
  </div>
  <div id="recoContent"></div>
</section>

<!-- ── AUDIT REPORT ── -->
<section id="page-audit" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Audit Report</div>
      <div class="page-subtitle">Executive summary — RBAC compliance posture for governance reporting</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="window.print()">🖨 Print / PDF</button>
    </div>
  </div>
  <div id="auditContent"></div>
</section>

<!-- ── RAW DATA ── -->
<section id="page-rawdata" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Raw Data</div>
      <div class="page-subtitle">All __TOTALRECORDS__ RBAC assignments — 10-column view with column chooser</div>
    </div>
    <div class="btn-group">
      <button class="btn btn-green" onclick="exportRawCSV()">⬇ Export Filtered CSV</button>
      <div class="col-chooser-wrap">
        <button class="btn" onclick="toggleColChooser()">⚙ Columns</button>
        <div class="col-chooser-dropdown" id="colChooserDropdown"></div>
      </div>
    </div>
  </div>
  <div class="toolbar" style="flex-wrap:wrap;gap:7px">
    <div class="search-wrap" style="min-width:200px">
      <span class="icon">🔎</span>
      <input type="text" id="rawSearch" placeholder="Search all fields…" oninput="renderRawTable()"/>
    </div>
    <select id="rawSubFilter"  onchange="renderRawTable()"><option value="">All Subscriptions</option></select>
    <select id="rawRoleFilter" onchange="renderRawTable()"><option value="">All Roles</option></select>
    <select id="rawEnvFilter"  onchange="renderRawTable()"><option value="">All Environments</option></select>
    <select id="rawTypeFilter" onchange="renderRawTable()"><option value="">All Object Types</option></select>
    <select id="rawResTypeFilter" onchange="renderRawTable()"><option value="">All Resource Types</option></select>
    <div class="page-size-wrap">Show <select id="rawPageSize" onchange="renderRawTable()"><option>25</option><option>50</option><option>100</option></select></div>
    <span class="result-count" id="rawResultCount"></span>
  </div>
  <div style="overflow-x:auto">
    <table class="rbac-table" id="rawTable">
      <thead id="rawTableHead"><tr></tr></thead>
      <tbody id="rawTableBody"></tbody>
    </table>
  </div>
  <div class="pagination" id="rawPagination"></div>
</section>

</main>

<!-- ════════════════ FOOTER ════════════════ -->
<footer id="app-footer">
  <div>
    <span class="footer-brand">Cloud-Identity-Toolkit</span>
    <span class="footer-divider">|</span>
    RBAC Visualization Report v3.0
    <span class="footer-divider">|</span>
    Author: Lakshmanan Thangaraj
    <span class="footer-divider">|</span>
    <a class="footer-link" href="https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit" target="_blank">GitHub</a>
  </div>
  <div>
    PowerShell __PSVERSION__
    <span class="footer-divider">|</span>
    Scan Duration: __EXECUTIONTIME__s
    <span class="footer-divider">|</span>
    Records: __TOTALRECORDS__
    <span class="footer-divider">|</span>
    Generated: __REPORTTIMESTAMP__
  </div>
</footer>

<!-- ════════════════ DETAIL DRAWER ════════════════ -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDetail()"></div>
  <div id="detailDrawer">
    <div class="detail-toolbar">
      <span class="detail-toolbar-title" id="detailTitle">Details</span>
      <button id="detailClose" onclick="closeDetail()" title="Close (Esc)">✕</button>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<!-- ════════════════ CSV UPLOAD OVERLAY ════════════════ -->
<div id="uploadOverlay">
  <div class="upload-modal">
    <h2>📂 Load New CSV Report</h2>
    <p>Upload a new RBAC assignment CSV to reload the dashboard without re-running the PowerShell script. The file must include the standard 9 column headers.</p>
    <div class="drop-zone" id="dropZone">
      <input type="file" accept=".csv" id="csvFileInput" onchange="handleFileSelect(event)"/>
      <div class="drop-zone-icon">📄</div>
      <div class="drop-zone-text">Drag &amp; drop your CSV here</div>
      <div class="drop-zone-sub">or click to browse — .csv files only</div>
    </div>
    <div class="upload-progress" id="uploadProgress">
      <div style="font-size:12px;color:var(--muted2)" id="uploadStatusText">Processing…</div>
      <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
    </div>
    <div class="upload-modal-footer">
      <button class="btn" onclick="closeUpload()">Cancel</button>
    </div>
  </div>
</div>

<!-- ════════════════ TOAST ════════════════ -->
<div id="toast"></div>

<!-- ════════════════ JAVASCRIPT ════════════════ -->
<script>
// ── Data (injected by PowerShell) ──────────────────────────────────────────────
let DATA        = [__ENRICHED_JSON__];
let SCOPE_DIST  = [__SCOPE_JSON__];
let OBJ_DIST    = [__OBJTYPE_JSON__];
let TOP_PRINC   = [__TOP_PRINC_JSON__];
let TOP_ROLES   = [__TOP_ROLES_JSON__];
let RES_TYPE    = [__RESTYPE_JSON__];
let RES_GROUP   = [__RESGROUP_JSON__];
let IND_RES     = [__INDRES_JSON__];
let ENV_STATS   = [__ENVSTATS_JSON__];
let SUB_STATS   = [__SUBSTATS_JSON__];
let UNIQUE_SUBS = [__UNIQUE_SUBS_JSON__];
let UNIQUE_ROLES= [__UNIQUE_ROLES_JSON__];
let UNIQUE_ENVS = [__UNIQUE_ENVS_JSON__];
let SEC_CHECKS  = [__SECCHECKS_JSON__];
let PRINC_RISK  = [__PRINCRISK_JSON__];

// ── Config (will be updated after upload) ─────────────────────────────────────
let CFG = {
  totalRecords:  __TOTALRECORDS__,
  principalCount:__PRINCIPALCOUNT__,
  roleCount:     __ROLECOUNT__,
  subCount:      __SUBCOUNT__,
  envCount:      __ENVCOUNT__,
  healthScore:   __HEALTHSCORE__,
  riskScore:     __RISKSCORE__,
  critChecks:    __CRITICALCHECKS__,
  highChecks:    __HIGHCHECKS__,
  passedChecks:  __PASSEDCHECKS__,
  checkTotal:    __CHECKTOTAL__,
  uniqueUsers:   __UNIQUEUSERS__,
  uniqueGroups:  __UNIQUEGROUPS__,
  uniqueSPs:     __UNIQUESPS__,
  uniqueMIs:     __UNIQUEMIS__,
  unknownObjs:   __UNKNOWNOBJS__,
  highRiskCount: __HIGHRISKCOUNT__,
  guestCount:    __GUESTCOUNT__,
  rootScopeCount:__ROOTSCOPECOUNT__,
  customRoleCount:__CUSTOMROLECOUNT__,
  complianceStatus:'__COMPLIANCESTATUS__'
};

// ── Escape helpers ─────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

// ── Theme ──────────────────────────────────────────────────────────────────────
function toggleTheme(){
  document.body.classList.toggle('light-theme');
  const isLight=document.body.classList.contains('light-theme');
  document.getElementById('themeIcon').textContent=isLight?'☀':'🌙';
  document.getElementById('themeLabel').textContent=isLight?'Light Mode':'Dark Mode';
  localStorage.setItem('rbac-theme',isLight?'light':'dark');
  refreshAllCharts();
}
(function(){
  const saved=localStorage.getItem('rbac-theme');
  if(saved==='light'){document.body.classList.add('light-theme');document.getElementById('themeIcon').textContent='☀';document.getElementById('themeLabel').textContent='Light Mode';}
})();

// ── Page navigation ────────────────────────────────────────────────────────────
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
}

// ── Toast ──────────────────────────────────────────────────────────────────────
let toastTimer;
function showToast(msg,icon){
  const t=document.getElementById('toast');
  t.innerHTML=(icon||'✅')+' '+escH(msg);
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>t.classList.remove('show'),3000);
}

// ── Detail drawer ──────────────────────────────────────────────────────────────
function openDetail(html,title){
  document.getElementById('detailTitle').textContent=title||'Details';
  document.getElementById('detailContent').innerHTML=html;
  document.getElementById('detailPanel').classList.add('open');
  document.body.style.overflow='hidden';
  document.getElementById('detailContent').scrollTo(0,0);
}
function closeDetail(){
  document.getElementById('detailPanel').classList.remove('open');
  document.body.style.overflow='';
}

// ── Palette & colour helpers ───────────────────────────────────────────────────
const PALETTE=['#388bfd','#39c5cf','#a371f7','#3fb950','#d29922','#f85149','#58a6ff','#56d364','#ffa657','#ff7b72','#79c0ff','#d2a8ff'];
function envColor(env){
  const e=(env||'').toLowerCase();
  if(e==='prod'||e==='production') return'var(--red)';
  if(e==='uat'||e==='staging')     return'var(--amber)';
  if(e==='dev'||e==='development') return'var(--green)';
  if(e==='test'||e==='testing')    return'var(--accent3)';
  return'var(--muted)';
}
function envBadgeClass(env){
  const e=(env||'').toLowerCase();
  if(e==='prod'||e==='production') return'env-badge prod';
  if(e==='uat'||e==='staging')     return'env-badge uat';
  if(e==='dev'||e==='development') return'env-badge dev';
  if(e==='test'||e==='testing')    return'env-badge test';
  return'env-badge unknown';
}
function permBadge(role){
  const r=(role||'').toLowerCase();
  if(r.includes('owner'))          return'<span class="badge badge-red">Owner</span>';
  if(r.includes('contributor'))    return'<span class="badge badge-amber">Contributor</span>';
  if(r.includes('reader'))         return'<span class="badge badge-green">Reader</span>';
  if(r.includes('administrator'))  return'<span class="badge badge-purple">Admin</span>';
  return'<span class="badge badge-muted">Custom</span>';
}
function riskBadge(level){
  const l=(level||'Low');
  const cls={Critical:'badge-critical',High:'badge-high',Medium:'badge-medium',Low:'badge-low'}[l]||'badge-muted';
  return`<span class="badge ${cls}">${escH(l)}</span>`;
}
function riskScoreBar(score){
  const pct=Math.min(100,score||0);
  const col=pct>=70?'var(--red)':pct>=40?'var(--amber)':pct>=20?'var(--accent3)':'var(--green)';
  return`<div style="display:flex;align-items:center;gap:6px"><div style="width:60px;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden"><div style="width:${pct}%;height:100%;background:${col};border-radius:3px"></div></div><span style="font-family:var(--mono);font-size:11px;color:var(--muted)">${pct}</span></div>`;
}
function sevBadge(sev){
  const cls={Critical:'badge-critical',High:'badge-high',Medium:'badge-medium',Low:'badge-low'}[sev]||'badge-muted';
  return`<span class="badge ${cls}">${escH(sev||'Low')}</span>`;
}
function healthPill(score){
  const cls=score>=70?'health-pill':score>=40?'health-pill warn':'health-pill bad';
  return`<span class="hbar-score-pill ${cls}">${score}</span>`;
}
function riskPill(score){
  const cls=score<20?'risk-pill low':score<50?'risk-pill medium':'risk-pill';
  return`<span class="hbar-score-pill ${cls}">${score}</span>`;
}

// ── Score rings ────────────────────────────────────────────────────────────────
function animateRing(id,score,color){
  const el=document.getElementById(id);
  if(!el) return;
  const circ=2*Math.PI*30;
  const offset=circ-(circ*Math.min(100,score)/100);
  el.style.stroke=color;
  requestAnimationFrame(()=>{el.style.strokeDashoffset=offset;});
}

// ── Charts ─────────────────────────────────────────────────────────────────────
const chartInstances={};
function safeChart(id,cfg){
  const el=document.getElementById(id);
  if(!el||typeof Chart==='undefined') return;
  if(chartInstances[id]) chartInstances[id].destroy();
  chartInstances[id]=new Chart(el,cfg);
}
function getTextColor(){return document.body.classList.contains('light-theme')?'#424a53':'#adbac7';}
function getGridColor(){return document.body.classList.contains('light-theme')?'rgba(0,0,0,.06)':'rgba(127,127,127,.1)';}

function initOverviewCharts(){
  const tc=getTextColor();
  safeChart('scopeChart',{type:'doughnut',data:{labels:SCOPE_DIST.map(s=>s.Name),datasets:[{data:SCOPE_DIST.map(s=>s.Count),backgroundColor:PALETTE,borderWidth:2,borderColor:'transparent'}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:tc,padding:10,font:{size:11}}},tooltip:{callbacks:{label:ctx=>{const tot=ctx.dataset.data.reduce((a,b)=>a+b,0);return ctx.label+': '+ctx.parsed+' ('+(ctx.parsed/tot*100).toFixed(1)+'%)';}}}}}}); 
  safeChart('objTypeChart',{type:'pie',data:{labels:OBJ_DIST.map(o=>o.Name||'Unknown'),datasets:[{data:OBJ_DIST.map(o=>o.Count),backgroundColor:PALETTE.slice(3),borderWidth:2,borderColor:'transparent'}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:tc,padding:10,font:{size:11}}},tooltip:{callbacks:{label:ctx=>{const tot=ctx.dataset.data.reduce((a,b)=>a+b,0);return ctx.label+': '+ctx.parsed+' ('+(ctx.parsed/tot*100).toFixed(1)+'%)';}}}}}}); 
  safeChart('topPrincChart',{type:'bar',data:{labels:TOP_PRINC.map(p=>p.Name.length>42?p.Name.slice(0,42)+'…':p.Name),datasets:[{label:'Assignments',data:TOP_PRINC.map(p=>p.Count),backgroundColor:'#388bfd',borderRadius:4}]},options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{title:ctx=>TOP_PRINC[ctx[0].dataIndex].Name}}},scales:{x:{beginAtZero:true,grid:{color:getGridColor()},ticks:{color:tc}},y:{grid:{display:false},ticks:{color:tc}}}}}); 
  safeChart('topRolesChart',{type:'bar',data:{labels:TOP_ROLES.map(r=>r.Name.length>42?r.Name.slice(0,42)+'…':r.Name),datasets:[{label:'Usage',data:TOP_ROLES.map(r=>r.Count),backgroundColor:'#3fb950',borderRadius:4}]},options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{title:ctx=>TOP_ROLES[ctx[0].dataIndex].Name}}},scales:{x:{beginAtZero:true,grid:{color:getGridColor()},ticks:{color:tc}},y:{grid:{display:false},ticks:{color:tc}}}}}); 
}
function initEnvCharts(){
  const tc=getTextColor(),gc=getGridColor();
  const colors=ENV_STATS.map(e=>envColor(e.Environment));
  safeChart('envAssignChart',{type:'bar',data:{labels:ENV_STATS.map(e=>e.Environment),datasets:[{label:'Assignments',data:ENV_STATS.map(e=>e.Count),backgroundColor:colors,borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:tc}},y:{beginAtZero:true,grid:{color:gc},ticks:{color:tc}}}}});
  safeChart('envPrincChart',{type:'bar',data:{labels:ENV_STATS.map(e=>e.Environment),datasets:[{label:'Principals',data:ENV_STATS.map(e=>e.Principals),backgroundColor:colors.map(c=>c+'88'),borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:tc}},y:{beginAtZero:true,grid:{color:gc},ticks:{color:tc}}}}});
  safeChart('envRiskChart',{type:'bar',data:{labels:ENV_STATS.map(e=>e.Environment),datasets:[{label:'High Risk',data:ENV_STATS.map(e=>e.HighRiskCount),backgroundColor:'rgba(248,81,73,.7)',borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:tc}},y:{beginAtZero:true,grid:{color:gc},ticks:{color:tc}}}}});
  safeChart('envHealthChart',{type:'bar',data:{labels:ENV_STATS.map(e=>e.Environment),datasets:[{label:'Health Score',data:ENV_STATS.map(e=>e.HealthScore),backgroundColor:'rgba(63,185,80,.7)',borderRadius:6}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:tc}},y:{beginAtZero:true,max:100,grid:{color:gc},ticks:{color:tc}}}}});
}
function initResourceCharts(){
  const tc=getTextColor(),gc=getGridColor();
  if(RES_TYPE.length){
    safeChart('resTypeChart',{type:'bar',data:{labels:RES_TYPE.map(r=>r.Name.length>30?r.Name.slice(0,30)+'…':r.Name),datasets:[{label:'Assignments',data:RES_TYPE.map(r=>r.Count),backgroundColor:'#a371f7',borderRadius:4}]},options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{title:ctx=>RES_TYPE[ctx[0].dataIndex].Name}}},scales:{x:{beginAtZero:true,grid:{color:gc},ticks:{color:tc}},y:{grid:{display:false},ticks:{color:tc,font:{size:10}}}}}});
  }
  if(RES_GROUP.length){
    safeChart('resGroupChart',{type:'bar',data:{labels:RES_GROUP.map(r=>r.Name.length>25?r.Name.slice(0,25)+'…':r.Name),datasets:[{label:'Assignments',data:RES_GROUP.map(r=>r.Count),backgroundColor:'#d29922',borderRadius:4}]},options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{title:ctx=>RES_GROUP[ctx[0].dataIndex].Name}}},scales:{x:{beginAtZero:true,grid:{color:gc},ticks:{color:tc}},y:{grid:{display:false},ticks:{color:tc,font:{size:10}}}}}});
  }
}
function refreshAllCharts(){
  initOverviewCharts();
  initEnvCharts();
  initResourceCharts();
}

// ── Update header & score rings ───────────────────────────────────────────────
function updateHeader(health, risk, status){
  const hPill=document.getElementById('healthPill');
  const rPill=document.getElementById('riskPill');
  const sPill=document.getElementById('statusPill');
  if(hPill){
    const cls=health>=70?'health-pill':health>=40?'health-pill warn':'health-pill bad';
    hPill.className='hbar-score-pill '+cls;
    hPill.textContent=health+' / 100';
  }
  if(rPill){
    const cls=risk<20?'risk-pill low':risk<50?'risk-pill medium':'risk-pill';
    rPill.className='hbar-score-pill '+cls;
    rPill.textContent=risk+' / 100';
  }
  if(sPill){
    const cls={Pass:'badge-green',Warning:'badge-amber',Fail:'badge-red'}[status]||'badge-muted';
    sPill.className='hbar-score-pill '+cls;
    sPill.textContent=status;
  }
  // Score ring texts
  const hText=document.getElementById('healthScoreText');
  const rText=document.getElementById('riskScoreText');
  if(hText) hText.textContent=health;
  if(rText) rText.textContent=risk;
  // Animate rings
  animateRing('healthRing',health,'var(--green)');
  animateRing('riskRing',risk,'var(--red)');
  // Update CFG
  CFG.healthScore=health;
  CFG.riskScore=risk;
  CFG.complianceStatus=status;
}

// ── Security checks recomputation (mirrors PowerShell logic) ─────────────────
function recomputeSecurityChecks(data){
  const total=data.length;
  const ownerRows=data.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner'));
  const ownerPct=total?Math.round((ownerRows.length/total)*100*10)/10:0;
  const spOwnerRows=data.filter(r=>r.ObjectType==='ServicePrincipal' && r.RoleDefinitionName.toLowerCase().includes('owner'));
  const rootRows=data.filter(r=>r.Scope==='/');
  const unknownRows=data.filter(r=>!r.DisplayName || r.ObjectType==='Unknown');
  const guestRows=data.filter(r=>r.SignInName && r.SignInName.includes('#EXT#'));
  const contribRows=data.filter(r=>r.RoleDefinitionName.toLowerCase().includes('contributor'));
  const prodOwnerRows=data.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner') && r.Environment==='Prod');
  const uaaRows=data.filter(r=>r.RoleDefinitionName.toLowerCase().includes('user access administrator'));
  // over-provisioned
  const assignCounts={};
  data.forEach(r=>{assignCounts[r.DisplayName]=(assignCounts[r.DisplayName]||0)+1;});
  const overProv=Object.values(assignCounts).filter(c=>c>=10).length;

  const checks=[];
  checks.push({
    CheckName:'Owner Role Ratio',
    Description:ownerRows.length+' Owner assignments ('+ownerPct+'% of total). Recommended threshold: ≤5%.',
    Severity: ownerPct>15?'Critical':ownerPct>5?'High':'Low',
    Passed: ownerPct<=5,
    AffectedCount:ownerRows.length,
    Fix:'Replace Owner with scoped custom roles. Use PIM for JIT Owner access.',
    Impact:'Owner role grants full control. Excessive usage is the leading cause of privilege escalation.',
    Effort:'Medium',
    Priority: ownerPct>15?'P1':ownerPct>5?'P2':'P4'
  });
  checks.push({
    CheckName:'Service Principal with Owner Role',
    Description:spOwnerRows.length+' Service Principal(s) assigned the Owner role.',
    Severity: spOwnerRows.length>0?'Critical':'Low',
    Passed: spOwnerRows.length===0,
    AffectedCount:spOwnerRows.length,
    Fix:'Replace Owner with least-privilege custom roles for Service Principals. Review necessity of each SP Owner assignment.',
    Impact:'Compromised service principals with Owner rights enable lateral movement across the entire subscription.',
    Effort:'Low',
    Priority: spOwnerRows.length>0?'P1':'P4'
  });
  checks.push({
    CheckName:'Root Scope Assignments',
    Description:rootRows.length+' assignment(s) at Management Group root scope (/).',
    Severity: rootRows.length>0?'Critical':'Low',
    Passed: rootRows.length===0,
    AffectedCount:rootRows.length,
    Fix:'Remove root-scope assignments. Assign at lowest required scope (Resource Group or Resource).',
    Impact:'Root scope grants access to all management groups, subscriptions, and resources in the tenant.',
    Effort:'Low',
    Priority: rootRows.length>0?'P1':'P4'
  });
  checks.push({
    CheckName:'Unknown / Orphaned Principals',
    Description:unknownRows.length+' assignment(s) with no identifiable principal (deleted objects).',
    Severity: unknownRows.length>10?'High':unknownRows.length>0?'Medium':'Low',
    Passed: unknownRows.length===0,
    AffectedCount:unknownRows.length,
    Fix:'Remove orphaned role assignments using Azure CLI: az role assignment delete. Run periodic cleanup automation.',
    Impact:'Orphaned assignments consume license slots and can be exploited if object IDs are re-used.',
    Effort:'Low',
    Priority: unknownRows.length>0?'P2':'P4'
  });
  checks.push({
    CheckName:'Guest / External Users',
    Description:guestRows.length+' assignment(s) belong to external (guest) user accounts (#EXT#).',
    Severity: guestRows.length>5?'High':guestRows.length>0?'Medium':'Low',
    Passed: guestRows.length===0,
    AffectedCount:guestRows.length,
    Fix:'Review necessity of each guest assignment. Enforce time-bound access and periodic re-certification.',
    Impact:'External users may not be subject to your organisation\'s MFA and conditional access policies.',
    Effort:'Medium',
    Priority: guestRows.length>0?'P2':'P4'
  });
  checks.push({
    CheckName:'Over-Provisioned Principals',
    Description:overProv+' principal(s) hold 10 or more role assignments.',
    Severity: overProv>3?'High':overProv>0?'Medium':'Low',
    Passed: overProv===0,
    AffectedCount:overProv,
    Fix:'Consolidate multiple assignments into a single custom role. Audit for role stacking anti-patterns.',
    Impact:'Excess permissions violate least-privilege and increase blast radius in a breach.',
    Effort:'Medium',
    Priority: overProv>0?'P2':'P4'
  });
  checks.push({
    CheckName:'Owner Roles in Production',
    Description:prodOwnerRows.length+' Owner assignment(s) found in Production environment.',
    Severity: prodOwnerRows.length>0?'High':'Low',
    Passed: prodOwnerRows.length===0,
    AffectedCount:prodOwnerRows.length,
    Fix:'Enforce PIM JIT access for all Production Owner assignments. Require approval workflow and audit logging.',
    Impact:'Standing Owner access in Production is the highest-risk RBAC posture.',
    Effort:'Medium',
    Priority: prodOwnerRows.length>0?'P1':'P4'
  });
  checks.push({
    CheckName:'User Access Administrator Assignments',
    Description:uaaRows.length+' User Access Administrator assignment(s) detected.',
    Severity: uaaRows.length>3?'High':uaaRows.length>0?'Medium':'Low',
    Passed: uaaRows.length<=2,
    AffectedCount:uaaRows.length,
    Fix:'Restrict User Access Administrator to break-glass accounts only. Use PIM for JIT activation.',
    Impact:'This role can re-assign any Azure RBAC role including Owner, enabling privilege escalation.',
    Effort:'Low',
    Priority: uaaRows.length>0?'P2':'P4'
  });
  return checks;
}

// ── Recompute CFG ─────────────────────────────────────────────────────────────
function recomputeCFG(data, secChecks){
  const total=data.length;
  const uniquePrincipals=new Set(data.map(r=>r.DisplayName)).size;
  const uniqueRolesSet=[...new Set(data.map(r=>r.RoleDefinitionName))];
  const uniqueRoles=uniqueRolesSet.length;
  const uniqueSubs=new Set(data.map(r=>r.SubscriptionName)).size;
  const uniqueEnvs=new Set(data.map(r=>r.Environment)).size;
  const ownerRows=data.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner'));
  const contribRows=data.filter(r=>r.RoleDefinitionName.toLowerCase().includes('contributor'));
  const readerRows=data.filter(r=>r.RoleDefinitionName.toLowerCase().includes('reader'));
  const userRows=data.filter(r=>r.ObjectType==='User');
  const groupRows=data.filter(r=>r.ObjectType==='Group');
  const spRows=data.filter(r=>r.ObjectType==='ServicePrincipal');
  const miRows=data.filter(r=>r.ObjectType==='ManagedIdentity');
  const unknownObjs=data.filter(r=>r.ObjectType==='Unknown' || !r.ObjectType);
  const guestRows=data.filter(r=>r.SignInName && r.SignInName.includes('#EXT#'));
  const rootRows=data.filter(r=>r.Scope==='/');
  const customRoles=uniqueRolesSet.filter(r=>!r.toLowerCase().match('owner|contributor|reader|administrator|operator|storage|key vault|backup|network|virtual machine|sql|cosmos|azure'));
  const highRiskPrincipals=[]; // will compute from PRINC_RISK later
  const failedChecks=secChecks.filter(c=>!c.Passed);
  const criticalChecks=failedChecks.filter(c=>c.Severity==='Critical');
  const highChecks=failedChecks.filter(c=>c.Severity==='High');
  const passedChecks=secChecks.filter(c=>c.Passed);
  const riskScore=Math.min(100, (criticalChecks.length*30)+(highChecks.length*15)+(failedChecks.filter(c=>c.Severity==='Medium').length*5)+(failedChecks.filter(c=>c.Severity==='Low').length*1));
  const healthScore=Math.max(0,100-riskScore);
  const complianceStatus=criticalChecks.length>0?'Fail':highChecks.length>0?'Warning':'Pass';

  return {
    totalRecords:total,
    principalCount:uniquePrincipals,
    roleCount:uniqueRoles,
    subCount:uniqueSubs,
    envCount:uniqueEnvs,
    healthScore:healthScore,
    riskScore:riskScore,
    critChecks:criticalChecks.length,
    highChecks:highChecks.length,
    passedChecks:passedChecks.length,
    checkTotal:secChecks.length,
    uniqueUsers:userRows.length,
    uniqueGroups:groupRows.length,
    uniqueSPs:spRows.length,
    uniqueMIs:miRows.length,
    unknownObjs:unknownObjs.length,
    highRiskCount:highRiskPrincipals.length,
    guestCount:guestRows.length,
    rootScopeCount:rootRows.length,
    customRoleCount:customRoles.length,
    complianceStatus:complianceStatus
  };
}

// ── Overview KPI population ────────────────────────────────────────────────────
function populateOverviewKPIs(){
  const owners=DATA.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner')).length;
  const contrib=DATA.filter(r=>r.RoleDefinitionName.toLowerCase().includes('contributor')).length;
  const readers=DATA.filter(r=>r.RoleDefinitionName.toLowerCase().includes('reader')).length;
  const el=n=>document.getElementById(n);
  if(el('ownerCountStat'))   el('ownerCountStat').textContent=owners;
  if(el('ownerRoleCount'))   el('ownerRoleCount').textContent=owners;
  if(el('contribRoleCount')) el('contribRoleCount').textContent=contrib;
  if(el('readerRoleCount'))  el('readerRoleCount').textContent=readers;
}

// ── Security checks rendering ─────────────────────────────────────────────────
function renderSecChecks(){
  const sevF=document.getElementById('sevFilter').value;
  const statF=document.getElementById('statusFilter').value;
  let filtered=SEC_CHECKS.filter(c=>{
    if(sevF&&c.Severity!==sevF)return false;
    if(statF==='failed'&&c.Passed)return false;
    if(statF==='passed'&&!c.Passed)return false;
    return true;
  });
  const crit=SEC_CHECKS.filter(c=>!c.Passed&&c.Severity==='Critical').length;
  const high=SEC_CHECKS.filter(c=>!c.Passed&&c.Severity==='High').length;
  const med=SEC_CHECKS.filter(c=>!c.Passed&&c.Severity==='Medium').length;
  const pass=SEC_CHECKS.filter(c=>c.Passed).length;
  ['critCount','highCount','medCount','passCount'].forEach((id,i)=>{
    const el=document.getElementById(id);
    if(el)el.textContent=[crit,high,med,pass][i];
  });
  const cb=document.getElementById('complianceBanner');
  if(cb){
    const s=CFG.complianceStatus;
    const ico={Pass:'✅',Warning:'⚠️',Fail:'🚨'}[s]||'ℹ️';
    const msg={Pass:'All critical checks passed. RBAC posture is acceptable.',Warning:'High severity findings detected. Review and remediate before next audit.',Fail:'Critical security issues found. Immediate remediation required.'}[s]||'';
    cb.innerHTML=`<div class="compliance-banner ${s.toLowerCase()}"><div class="compliance-icon">${ico}</div><div class="compliance-text"><h3>Compliance Status: ${s}</h3><p>${msg}</p></div></div>`;
  }
  const container=document.getElementById('secCardsContainer');
  if(!container)return;
  container.innerHTML=filtered.map(c=>{
    const sevCls=c.Passed?'passed':c.Severity.toLowerCase();
    return`<div class="sec-card ${sevCls}">
      <div class="sec-card-head">
        <span class="sec-card-title">${escH(c.CheckName)}</span>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px">
          ${sevBadge(c.Passed?'Pass':c.Severity)}
          <span class="badge ${c.Passed?'badge-green':'badge-red'}">${c.Passed?'✓ Passed':'✗ Failed'}</span>
        </div>
      </div>
      <div class="sec-card-body">${escH(c.Description)}</div>
      ${!c.Passed?`<div class="sec-card-fix"><strong>💡 Suggested Fix:</strong>${escH(c.Fix)}</div>`:''}
      <div class="sec-meta">
        <span class="sec-meta-chip">Priority: ${escH(c.Priority)}</span>
        <span class="sec-meta-chip">Effort: ${escH(c.Effort)}</span>
        <span class="sec-meta-chip">Affected: ${c.AffectedCount}</span>
      </div>
      ${!c.Passed?`<div style="margin-top:8px"><span style="font-size:11px;color:var(--muted)">Business Impact: </span><span style="font-size:11.5px;color:var(--muted2)">${escH(c.Impact)}</span></div>`:''}
    </div>`;
  }).join('');
}

// ── Principal data & table ─────────────────────────────────────────────────────
let princData=[], princPage=1, princPageSz=25;
function buildPrincData(){
  const riskMap={};
  PRINC_RISK.forEach(p=>{riskMap[p.DisplayName]={score:p.RiskScore,level:p.RiskLevel};});
  const map={};
  DATA.forEach(r=>{
    const k=r.DisplayName||'(Unknown)';
    if(!map[k])map[k]={name:k,signIn:r.SignInName,type:r.ObjectType||'Unknown',count:0,roles:new Set(),subs:new Set(),envs:new Set()};
    map[k].count++;
    map[k].roles.add(r.RoleDefinitionName);
    map[k].subs.add(r.SubscriptionName);
    map[k].envs.add(r.Environment);
    if(!map[k].signIn&&r.SignInName)map[k].signIn=r.SignInName;
  });
  princData=Object.values(map).sort((a,b)=>b.count-a.count).map(p=>({
    ...p,
    riskScore:(riskMap[p.name]||{}).score||0,
    riskLevel:(riskMap[p.name]||{}).level||'Low'
  }));
  const types=[...new Set(princData.map(p=>p.type))].sort();
  const tf=document.getElementById('princTypeFilter');
  if(tf){tf.innerHTML='<option value="">All Object Types</option>';types.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;tf.appendChild(o);});}
  const ef=document.getElementById('princEnvFilter');
  if(ef){ef.innerHTML='<option value="">All Environments</option>';UNIQUE_ENVS.forEach(e=>{const o=document.createElement('option');o.value=e;o.textContent=e;ef.appendChild(o);});}
}
function renderPrincTable(){
  const q=(document.getElementById('princSearch').value||'').toLowerCase();
  const envF=document.getElementById('princEnvFilter').value;
  const typeF=document.getElementById('princTypeFilter').value;
  const riskF=document.getElementById('princRiskFilter').value;
  princPageSz=+document.getElementById('princPageSize').value;
  let filtered=princData.filter(p=>{
    if(q&&!p.name.toLowerCase().includes(q)&&!(p.signIn||'').toLowerCase().includes(q))return false;
    if(envF&&![...p.envs].includes(envF))return false;
    if(typeF&&p.type!==typeF)return false;
    if(riskF&&p.riskLevel!==riskF)return false;
    return true;
  });
  document.getElementById('princResultCount').textContent=filtered.length+' result'+(filtered.length!==1?'s':'');
  const pages=Math.max(1,Math.ceil(filtered.length/princPageSz));
  if(princPage>pages)princPage=1;
  const slice=filtered.slice((princPage-1)*princPageSz,princPage*princPageSz);
  document.getElementById('princTableBody').innerHTML=slice.map(p=>`<tr onclick="openPrincDetail('${escJ(p.name)}')">
    <td><strong>${escH(p.name)}</strong></td>
    <td class="td-mono" style="font-size:10.5px">${escH(p.signIn||'—')}</td>
    <td><span class="badge badge-blue">${escH(p.type)}</span></td>
    <td>${riskScoreBar(p.riskScore)} ${riskBadge(p.riskLevel)}</td>
    <td>${p.count}</td>
    <td>${p.roles.size}</td>
    <td>${p.subs.size}</td>
    <td>${[...p.envs].map(e=>`<span class="${envBadgeClass(e)}" style="margin-right:3px">${escH(e)}</span>`).join('')}</td>
  </tr>`).join('');
  renderPagination('princPagination',pages,princPage,pg=>{princPage=pg;renderPrincTable();});
}
function openPrincDetail(name){
  const rows=DATA.filter(r=>r.DisplayName===name);
  if(!rows.length)return;
  const p=princData.find(x=>x.name===name)||{};
  const roleList=[...new Map(rows.map(r=>[r.RoleDefinitionName,r])).values()];
  const html=`
    <div class="detail-header">
      <div class="detail-name">${escH(name)}</div>
      ${p.signIn?`<div class="detail-sub">${escH(p.signIn)}</div>`:''}
    </div>
    <div class="detail-meta-row">
      <span class="detail-chip"><span class="badge badge-blue">${escH(p.type||'Unknown')}</span></span>
      ${riskBadge(p.riskLevel)} ${riskScoreBar(p.riskScore)}
      <span class="detail-chip">📌 ${p.count} assignments</span>
      <span class="detail-chip">🎭 ${p.roles?p.roles.size:0} roles</span>
      <span class="detail-chip">🗂 ${p.subs?p.subs.size:0} subscriptions</span>
      ${p.envs?[...p.envs].map(e=>`<span class="detail-chip"><span class="${envBadgeClass(e)}">${escH(e)}</span></span>`).join(''):''}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Roles Assigned</div>
      ${roleList.map(r=>`<div class="detail-mini-row">${permBadge(r.RoleDefinitionName)}<span style="font-family:var(--mono);font-size:11.5px;color:var(--text);margin-left:8px">${escH(r.RoleDefinitionName)}</span></div>`).join('')}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">All Assignments (${rows.length})</div>
      <div style="overflow-x:auto;margin-top:6px">
        <table class="rbac-table">
          <thead><tr><th>Subscription</th><th>Role</th><th>Resource Type</th><th>Scope</th></tr></thead>
          <tbody>${rows.map(r=>`<tr><td>${escH(r.SubscriptionName)}</td><td>${escH(r.RoleDefinitionName)}</td><td>${escH(r.ResourceType||'—')}</td><td class="td-scope" title="${escH(r.Scope)}">${escH(r.Scope)}</td></tr>`).join('')}</tbody>
        </table>
      </div>
    </div>`;
  openDetail(html,name);
}
function exportPrincCSV(){
  const rows=['Principal,SignInName,ObjectType,RiskLevel,RiskScore,Assignments,UniqueRoles,Subscriptions,Environments'];
  princData.forEach(p=>rows.push(`"${p.name.replace(/"/g,'""')}","${(p.signIn||'').replace(/"/g,'""')}","${p.type}","${p.riskLevel}",${p.riskScore},${p.count},${p.roles.size},${p.subs.size},"${[...p.envs].join('; ')}"`));
  dlFile(rows.join('\r\n'),'rbac-principals.csv','text/csv');
  showToast('Exported '+princData.length+' principals');
}

// ── Roles table ────────────────────────────────────────────────────────────────
let rolesData=[];
function buildRolesData(){
  const map={};
  DATA.forEach(r=>{
    const k=r.RoleDefinitionName;
    if(!map[k])map[k]={name:k,count:0,principals:new Set(),subs:new Set()};
    map[k].count++;
    map[k].principals.add(r.DisplayName);
    map[k].subs.add(r.SubscriptionName);
  });
  rolesData=Object.values(map).sort((a,b)=>b.count-a.count);
}
function renderRoleTable(){
  const q=(document.getElementById('roleSearch').value||'').toLowerCase();
  const permF=document.getElementById('rolePermFilter').value;
  let filtered=rolesData.filter(r=>{
    if(q&&!r.name.toLowerCase().includes(q))return false;
    if(permF){const rn=r.name.toLowerCase();
      if(permF==='owner'&&!rn.includes('owner'))return false;
      if(permF==='contributor'&&!rn.includes('contributor'))return false;
      if(permF==='reader'&&!rn.includes('reader'))return false;
      if(permF==='custom'&&(rn.includes('owner')||rn.includes('contributor')||rn.includes('reader')))return false;
    }
    return true;
  });
  document.getElementById('roleResultCount').textContent=filtered.length+' result'+(filtered.length!==1?'s':'');
  document.getElementById('roleTableBody').innerHTML=filtered.map(r=>`<tr>
    <td><strong>${escH(r.name)}</strong></td>
    <td>${r.count}</td>
    <td>${r.principals.size}</td>
    <td>${r.subs.size}</td>
    <td>${permBadge(r.name)}</td>
  </tr>`).join('');
  const top10=rolesData.slice(0,10);
  const maxC=top10[0]?top10[0].count:1;
  document.getElementById('roleBarList').innerHTML=top10.map((r,i)=>`
    <div class="bar-row">
      <span class="bar-label" title="${escH(r.name)}">${escH(r.name.length>28?r.name.slice(0,28)+'…':r.name)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:0%;background:${PALETTE[i%PALETTE.length]}" data-pct="${Math.round(r.count/maxC*100)}"></div></div>
      <span class="bar-count">${r.count}</span>
    </div>`).join('');
  requestAnimationFrame(()=>document.querySelectorAll('#roleBarList .bar-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';}));
}
function exportRolesCSV(){
  const rows=['RoleName,Assignments,UniquePrincipals,Subscriptions,PermissionLevel'];
  rolesData.forEach(r=>{
    const lvl=r.name.toLowerCase().includes('owner')?'Owner':r.name.toLowerCase().includes('contributor')?'Contributor':r.name.toLowerCase().includes('reader')?'Reader':'Custom';
    rows.push(`"${r.name.replace(/"/g,'""')}",${r.count},${r.principals.size},${r.subs.size},"${lvl}"`);
  });
  dlFile(rows.join('\r\n'),'rbac-roles.csv','text/csv');
  showToast('Exported '+rolesData.length+' roles');
}

// ── Resource Analysis ──────────────────────────────────────────────────────────
let resData=[], resPage=1;
function buildResData(){
  resData=DATA.filter(r=>r.Scope&&r.Scope!=='/'&&!r.Scope.match(/\/subscriptions\/[^\/]+$/)&&!r.Scope.match(/\/resourceGroups\/[^\/]+$/));
}
function renderResTable(){
  const q=(document.getElementById('resSearch').value||'').toLowerCase();
  const filtered=resData.filter(r=>!q||r.Scope.toLowerCase().includes(q)||(r.ResourceType||'').toLowerCase().includes(q));
  document.getElementById('resResultCount').textContent=filtered.length+' resources';
  const grouped=Object.values(filtered.reduce((m,r)=>{if(!m[r.Scope])m[r.Scope]={scope:r.Scope,count:0,rt:r.ResourceType,rows:[]};m[r.Scope].count++;m[r.Scope].rows.push(r);return m;},{})).sort((a,b)=>b.count-a.count);
  const pages=Math.max(1,Math.ceil(grouped.length/25));
  if(resPage>pages)resPage=1;
  const slice=grouped.slice((resPage-1)*25,resPage*25);
  document.getElementById('resTableBody').innerHTML=slice.map(g=>{
    const rgMatch=g.scope.match(/\/resourceGroups\/([^\/]+)/);
    const rg=rgMatch?rgMatch[1]:'—';
    return`<tr onclick="openResDetail('${escJ(g.scope)}')">
      <td class="td-mono" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escH(g.scope)}">${escH(g.scope)}</td>
      <td>${g.count}</td>
      <td><span class="badge badge-purple">${escH(g.rt||'—')}</span></td>
      <td>${escH(rg)}</td>
    </tr>`;
  }).join('');
  renderPagination('resPagination',pages,resPage,pg=>{resPage=pg;renderResTable();});
}
function openResDetail(scope){
  const rows=DATA.filter(r=>r.Scope===scope);
  if(!rows.length)return;
  const users  =rows.filter(r=>r.ObjectType==='User');
  const groups =rows.filter(r=>r.ObjectType==='Group');
  const sps    =rows.filter(r=>r.ObjectType==='ServicePrincipal');
  const roles  =[...new Set(rows.map(r=>r.RoleDefinitionName))];
  const rgMatch=scope.match(/\/resourceGroups\/([^\/]+)/);
  const rg=rgMatch?rgMatch[1]:'—';
  const html=`
    <div class="detail-header">
      <div class="detail-name" style="font-size:12px">${escH(scope)}</div>
    </div>
    <div class="detail-meta-row">
      <span class="detail-chip">📌 ${rows.length} assignments</span>
      <span class="detail-chip">📁 RG: ${escH(rg)}</span>
      <span class="detail-chip">${escH(rows[0].ResourceType||'—')}</span>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Roles Applied (${roles.length})</div>
      ${roles.map(r=>`<div class="detail-mini-row">${permBadge(r)}<span style="font-family:var(--mono);font-size:11.5px;margin-left:8px">${escH(r)}</span></div>`).join('')}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Assigned Users (${users.length})</div>
      ${users.length?users.map(r=>`<div class="detail-mini-row"><span>👤</span><span style="flex:1;font-size:12.5px;margin-left:8px">${escH(r.DisplayName||'—')}</span>${permBadge(r.RoleDefinitionName)}</div>`).join(''):'<div style="font-size:12px;color:var(--muted);padding:6px 0">No user assignments</div>'}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Assigned Groups (${groups.length})</div>
      ${groups.length?groups.map(r=>`<div class="detail-mini-row"><span>👥</span><span style="flex:1;font-size:12.5px;margin-left:8px">${escH(r.DisplayName||'—')}</span>${permBadge(r.RoleDefinitionName)}</div>`).join(''):'<div style="font-size:12px;color:var(--muted);padding:6px 0">No group assignments</div>'}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Assigned Service Principals (${sps.length})</div>
      ${sps.length?sps.map(r=>`<div class="detail-mini-row"><span>⚙</span><span style="flex:1;font-size:12.5px;margin-left:8px">${escH(r.DisplayName||'—')}</span>${permBadge(r.RoleDefinitionName)}</div>`).join(''):'<div style="font-size:12px;color:var(--muted);padding:6px 0">No SP assignments</div>'}
    </div>`;
  openDetail(html,'Resource Detail');
}

// ── Subscriptions ──────────────────────────────────────────────────────────────
function renderSubCards(){
  const q=(document.getElementById('subSearch').value||'').toLowerCase();
  const envF=document.getElementById('subEnvFilter').value;
  const filtered=SUB_STATS.filter(s=>{
    if(q&&!s.SubscriptionName.toLowerCase().includes(q)&&!s.SubscriptionId.toLowerCase().includes(q))return false;
    if(envF&&s.Environment!==envF)return false;
    return true;
  });
  document.getElementById('subCardsContainer').innerHTML=filtered.map((s,i)=>`
    <div class="sub-card" onclick="openSubDetail(${i})">
      <div class="sub-card-head">
        <div>
          <div class="sub-name">${escH(s.SubscriptionName)}</div>
          <div class="sub-id">${escH(s.SubscriptionId)}</div>
        </div>
        <span class="${envBadgeClass(s.Environment)}">${escH(s.Environment)}</span>
      </div>
      <div class="sub-stats-row">
        <div class="sub-stat"><span>${s.TotalAssignments}</span><span>Assignments</span></div>
        <div class="sub-stat"><span>${s.UniquePrincipals}</span><span>Principals</span></div>
        <div class="sub-stat"><span>${s.UniqueRoles}</span><span>Roles</span></div>
      </div>
      <div class="sub-role-row">
        <span class="badge badge-red" title="Owner">👑 ${s.OwnerCount||0}</span>
        <span class="badge badge-amber" title="Contributor">🔧 ${s.ContribCount||0}</span>
        <span class="badge badge-green" title="Reader">👁 ${s.ReaderCount||0}</span>
        <span style="margin-left:auto;display:flex;gap:6px;align-items:center">
          ${healthPill(s.HealthScore||0)} ${riskPill(s.RiskScore||0)}
        </span>
      </div>
    </div>`).join('');
  window._filteredSubStats=filtered;
}
function openSubDetail(idx){
  const s=window._filteredSubStats[idx];
  if(!s)return;
  const subRows=DATA.filter(r=>r.SubscriptionName===s.SubscriptionName);
  const ownerCnt=subRows.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner')).length;
  const html=`
    <div class="detail-header">
      <div class="detail-name">${escH(s.SubscriptionName)}</div>
      <div class="detail-sub">${escH(s.SubscriptionId)}</div>
    </div>
    <div class="detail-meta-row">
      <span class="detail-chip"><span class="${envBadgeClass(s.Environment)}">${escH(s.Environment)}</span></span>
      <span class="detail-chip">TenantId: <span class="td-mono" style="font-size:10.5px">${escH(s.TenantId||'—')}</span></span>
      <span class="detail-chip">📌 ${s.TotalAssignments} assignments</span>
      <span class="detail-chip">👤 ${s.UniquePrincipals} principals</span>
      <span class="detail-chip">🎭 ${s.UniqueRoles} roles</span>
      ${ownerCnt>0?`<span class="detail-chip" style="color:var(--red)">⚠ ${ownerCnt} Owner</span>`:''}
    </div>
    <div class="detail-meta-row">${healthPill(s.HealthScore||0)} Health &nbsp;&nbsp; ${riskPill(s.RiskScore||0)} Risk</div>
    <div class="detail-section">
      <div class="detail-section-title">Role Breakdown</div>
      <div style="display:flex;gap:12px;flex-wrap:wrap;padding:6px 0">
        <span class="badge badge-red">Owner: ${s.OwnerCount||0}</span>
        <span class="badge badge-amber">Contributor: ${s.ContribCount||0}</span>
        <span class="badge badge-green">Reader: ${s.ReaderCount||0}</span>
        <span class="badge badge-muted">High Risk: ${s.HighRiskCount||0}</span>
      </div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Top Roles</div>
      ${s.TopRoles.map(r=>`<div class="detail-mini-row">${permBadge(r.Name)}<span style="font-family:var(--mono);font-size:11.5px;margin-left:8px;flex:1">${escH(r.Name)}</span><span style="font-family:var(--mono);font-size:11.5px;color:var(--muted)">${r.Count}</span></div>`).join('')}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Top Principals</div>
      ${s.TopPrincipals.map(p=>`<div class="detail-mini-row"><span>👤</span><span style="flex:1;font-size:12.5px;margin-left:8px">${escH(p.Name)}</span><span style="font-family:var(--mono);font-size:11.5px;color:var(--muted)">${p.Count}</span></div>`).join('')}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">All Assignments (${subRows.length})</div>
      <div style="overflow-x:auto;margin-top:6px;max-height:320px;overflow-y:auto">
        <table class="rbac-table">
          <thead><tr><th>Principal</th><th>Sign-In</th><th>Role</th><th>Resource Type</th><th>Scope</th></tr></thead>
          <tbody>${subRows.map(r=>`<tr><td>${escH(r.DisplayName)}</td><td class="td-mono" style="font-size:10.5px">${escH(r.SignInName||'—')}</td><td>${escH(r.RoleDefinitionName)}</td><td>${escH(r.ResourceType||'—')}</td><td class="td-scope" title="${escH(r.Scope)}">${escH(r.Scope)}</td></tr>`).join('')}</tbody>
        </table>
      </div>
    </div>`;
  openDetail(html,s.SubscriptionName);
}
function populateSubEnvFilter(){
  const ef=document.getElementById('subEnvFilter');
  if(ef)UNIQUE_ENVS.forEach(e=>{const o=document.createElement('option');o.value=e;o.textContent=e;ef.appendChild(o);});
}

// ── Environment cards ──────────────────────────────────────────────────────────
function renderEnvCards(){
  const container=document.getElementById('envCardsContainer');
  if(!container)return;
  container.innerHTML=ENV_STATS.map(e=>`
    <div class="env-card">
      <span class="${envBadgeClass(e.Environment)}">${escH(e.Environment)}</span>
      <div class="env-total">${e.Count} <span style="font-size:12px;font-weight:400;color:var(--muted)">assignments</span></div>
      <div class="env-sub-stats">
        <div class="env-sub-stat"><span>${e.Subscriptions}</span><span>Subscriptions</span></div>
        <div class="env-sub-stat"><span>${e.Principals}</span><span>Principals</span></div>
        <div class="env-sub-stat"><span>${e.Roles}</span><span>Roles</span></div>
        <div class="env-sub-stat"><span style="color:var(--red)">${e.OwnerCount||0}</span><span>Owners</span></div>
      </div>
      <div class="env-scores">
        ${healthPill(e.HealthScore||0)}
        ${riskPill(e.RiskScore||0)}
        ${e.HighRiskCount>0?`<span class="badge badge-red">⚠ ${e.HighRiskCount} High Risk</span>`:''}
      </div>
    </div>`).join('');
}

// ── Recommendations (enhanced) ─────────────────────────────────────────────────
function renderRecommendations(){
  const recos=[
    {
      priority:'P1',title:'Eliminate Owner Roles — Replace with Custom Least-Privilege Roles',
      desc:`${SEC_CHECKS.find(c=>c.CheckName==='Owner Role Ratio')?.AffectedCount||0} Owner assignments detected. Owner grants unrestricted control over all resources and access management.`,
      impact:'Critical breach enabler. Compromised Owner accounts allow full tenant takeover.',
      effort:'Medium',msBestPractice:'Microsoft recommends replacing Owner with scoped custom roles for all non-break-glass scenarios.',
      fix:'1. Identify all Owner assignments in Raw Data tab. 2. Design custom roles matching actual permissions needed. 3. Migrate assignments. 4. Enable PIM for residual Owner accounts.',
      affectedFn:()=>DATA.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner'))
    },
    {
      priority:'P1',title:'Move Owner & Contributor to PIM JIT Access',
      desc:`Permanent privileged assignments increase attack surface. ${SEC_CHECKS.find(c=>c.CheckName==='Owner Role Ratio')?.AffectedCount||0} Owner + ${DATA.filter(r=>r.RoleDefinitionName.toLowerCase().includes('contributor')).length} Contributor assignments are candidates.`,
      impact:'Persistent privileged access is exploitable 24/7. JIT access reduces exposure window to hours.',
      effort:'Medium',msBestPractice:'Azure AD Privileged Identity Management (PIM) is the Microsoft-recommended approach for privileged access management.',
      fix:'1. Enable PIM in Azure AD. 2. Configure approval workflows for Owner/Contributor roles. 3. Set 4-8 hour activation windows. 4. Enable MFA on activation.',
      affectedFn:()=>DATA.filter(r=>r.RoleDefinitionName.toLowerCase().match('owner|contributor'))
    },
    {
      priority:'P1',title:'Remove Root Scope (/) Assignments',
      desc:`${CFG.rootScopeCount} assignment(s) at root scope grant access across ALL management groups and subscriptions.`,
      impact:'Root scope is the highest possible blast radius — a single compromised identity can access the entire tenant.',
      effort:'Low',msBestPractice:'Microsoft best practice: Assign roles at the lowest necessary scope. Root scope should only be used for Management Group policies.',
      fix:'Review and remove root-scope assignments. Move to subscription or resource group scope.',
      affectedFn:()=>DATA.filter(r=>r.Scope==='/')
    },
    {
      priority:'P2',title:'Clean Up Orphaned / Unknown Principal Assignments',
      desc:`${SEC_CHECKS.find(c=>c.CheckName==='Unknown / Orphaned Principals')?.AffectedCount||0} assignments reference deleted or unknown principal objects.`,
      impact:'Orphaned assignments consume Azure AD object limits and may be exploitable if object IDs are recycled.',
      effort:'Low',msBestPractice:'Use Azure AD Access Reviews or PowerShell to identify and remove stale role assignments quarterly.',
      fix:'Run: Get-AzRoleAssignment | Where-Object {$_.ObjectType -eq "Unknown"} | Remove-AzRoleAssignment',
      affectedFn:()=>DATA.filter(r=>!r.DisplayName||r.ObjectType==='Unknown')
    },
    {
      priority:'P2',title:'Audit Guest / External User Access',
      desc:`${SEC_CHECKS.find(c=>c.CheckName==='Guest / External Users')?.AffectedCount||0} external (#EXT#) user assignments found.`,
      impact:'External users may bypass your Conditional Access and MFA policies.',
      effort:'Medium',msBestPractice:'Enforce Conditional Access for all guest users. Use Azure AD Entitlement Management for time-bound external access.',
      fix:'1. Review all #EXT# assignments. 2. Apply Conditional Access for guests. 3. Set 90-day access expiry. 4. Enable quarterly access reviews.',
      affectedFn:()=>DATA.filter(r=>r.SignInName&&r.SignInName.includes('#EXT#'))
    },
    {
      priority:'P3',title:'Design Three Custom Role Tiers for Least-Privilege',
      desc:'Replace broad built-in roles with environment-specific custom roles: Reader Tier, Developer Tier, and Architect Tier.',
      impact:'Right-sized permissions reduce blast radius and align with Zero Trust principles.',
      effort:'High',msBestPractice:'Microsoft Cloud Adoption Framework recommends custom roles aligned to job functions rather than broad built-in roles.',
      fix:'1. Audit actual API calls made by each principal (Azure Monitor). 2. Design custom role JSON with minimal required actions. 3. Test in Dev first. 4. Roll out via IaC.',
      affectedFn:()=>[]
    },
    {
      priority:'P3',title:'Implement Quarterly RBAC Access Reviews',
      desc:'Establish recurring access reviews using Azure AD Access Reviews to maintain least-privilege posture over time.',
      impact:'Without reviews, access accumulates (permission creep) as people change roles.',
      effort:'Low',msBestPractice:'Azure AD Access Reviews (P2 license) automates reviewer workflows and removes inactive assignments.',
      fix:'1. Enable Azure AD Access Reviews. 2. Create review scopes per subscription. 3. Assign reviewers (managers or resource owners). 4. Set quarterly cadence.',
      affectedFn:()=>[]
    },
    {
      priority:'P4',title:'Scope Resource Group-Level Assignments Where Possible',
      desc:`${DATA.filter(r=>r.Scope&&r.Scope.match(/\/subscriptions\/[^\/]+$/)).length} subscription-scoped assignments could potentially be moved to resource group scope.`,
      impact:'Narrower scope limits lateral movement if credentials are compromised.',
      effort:'High',msBestPractice:'Prefer Resource Group scope over Subscription scope for application teams. Reserve Subscription scope for platform teams.',
      fix:'Identify which subscription-scoped users only need access to specific resource groups. Migrate assignments and validate access.',
      affectedFn:()=>DATA.filter(r=>r.Scope&&r.Scope.match(/\/subscriptions\/[^\/]+$/))
    }
  ];

  document.getElementById('recoContent').innerHTML=recos.map(r=>{
    const affected=r.affectedFn();
    return`<div class="reco-card">
      <div class="reco-card-head">
        <div class="reco-priority-badge ${r.priority}">${r.priority}</div>
        <div style="flex:1">
          <div class="reco-card-title">${escH(r.title)}</div>
          <div style="display:flex;gap:8px;margin-top:5px">
            <span class="badge badge-muted">Effort: ${escH(r.effort)}</span>
            ${affected.length>0?`<span class="badge badge-amber">${affected.length} affected</span>`:''}
          </div>
        </div>
      </div>
      <div class="reco-card-desc">${escH(r.desc)}</div>
      <div class="reco-detail-grid">
        <div class="reco-detail-box">
          <h5>💥 Business Impact</h5>
          <p>${escH(r.impact)}</p>
        </div>
        <div class="reco-detail-box">
          <h5>🏅 Microsoft Best Practice</h5>
          <p>${escH(r.msBestPractice)}</p>
        </div>
      </div>
      <div class="reco-detail-box" style="margin-top:10px">
        <h5>🔧 Suggested Fix</h5>
        <p style="white-space:pre-line">${escH(r.fix)}</p>
      </div>
      <div class="reco-footer">
        ${affected.length>0?`<button class="btn btn-green" onclick="exportAffectedObjects(${JSON.stringify(r.title)})">⬇ Export Affected (${affected.length})</button>`:''}
      </div>
    </div>`;
  }).join('');
}
function exportAffectedObjects(title){
  const recoMap={
    'Eliminate Owner Roles — Replace with Custom Least-Privilege Roles':DATA.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner')),
    'Move Owner & Contributor to PIM JIT Access':DATA.filter(r=>r.RoleDefinitionName.toLowerCase().match('owner|contributor')),
    'Remove Root Scope (/) Assignments':DATA.filter(r=>r.Scope==='/'),
    'Clean Up Orphaned / Unknown Principal Assignments':DATA.filter(r=>!r.DisplayName||r.ObjectType==='Unknown'),
    'Audit Guest / External User Access':DATA.filter(r=>r.SignInName&&r.SignInName.includes('#EXT#')),
    'Scope Resource Group-Level Assignments Where Possible':DATA.filter(r=>r.Scope&&r.Scope.match(/\/subscriptions\/[^\/]+$/))
  };
  const rows=recoMap[title]||[];
  if(!rows.length){showToast('No affected objects to export','ℹ️');return;}
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const header='SubscriptionName,DisplayName,SignInName,ObjectType,RoleDefinitionName,Scope,Environment';
  const csv=rows.map(r=>[r.SubscriptionName,r.DisplayName,r.SignInName,r.ObjectType,r.RoleDefinitionName,r.Scope,r.Environment].map(esc).join(','));
  dlFile([header,...csv].join('\r\n'),'rbac-affected-'+Date.now()+'.csv','text/csv');
  showToast('Exported '+rows.length+' affected objects');
}
function exportRecoCSV(){
  const rows=['Priority,Title,AffectedCount,Effort,BusinessImpact,MicrosoftBestPractice,SuggestedFix'];
  document.querySelectorAll('.reco-card').forEach(card=>{
    const title=card.querySelector('.reco-card-title')?.textContent||'';
    const pri=card.querySelector('.reco-priority-badge')?.textContent||'';
    rows.push(`"${pri}","${title.replace(/"/g,'""')}","","","","",""`);
  });
  dlFile(rows.join('\r\n'),'rbac-recommendations.csv','text/csv');
  showToast('Exported recommendations');
}

// ── Audit Report ───────────────────────────────────────────────────────────────
function renderAuditReport(){
  const owners=DATA.filter(r=>r.RoleDefinitionName.toLowerCase().includes('owner')).length;
  const ownerPct=DATA.length?((owners/DATA.length)*100).toFixed(1):0;
  const cs=CFG.complianceStatus;
  const csColor={Pass:'var(--green)',Warning:'var(--amber)',Fail:'var(--red)'}[cs]||'var(--muted)';
  const html=`
    <div class="compliance-banner ${cs.toLowerCase()}" style="margin-bottom:20px">
      <div class="compliance-icon">${cs==='Pass'?'✅':cs==='Warning'?'⚠️':'🚨'}</div>
      <div class="compliance-text">
        <h3>Compliance Status: ${cs}</h3>
        <p>Based on ${CFG.checkTotal} automated security checks executed against ${DATA.length} RBAC assignments across ${CFG.subCount} subscription(s).</p>
      </div>
    </div>

    <div class="audit-grid">
      <div class="audit-stat"><div class="val">${DATA.length}</div><div class="lbl">Total Assignments</div></div>
      <div class="audit-stat"><div class="val" style="color:var(--red)">${SEC_CHECKS.filter(c=>!c.Passed&&c.Severity==='Critical').length+SEC_CHECKS.filter(c=>!c.Passed&&c.Severity==='High').length}</div><div class="lbl">High Risk Findings</div></div>
      <div class="audit-stat"><div class="val" style="color:var(--green)">${SEC_CHECKS.filter(c=>c.Passed).length}</div><div class="lbl">Checks Passed</div></div>
      <div class="audit-stat"><div class="val" style="color:var(--red)">${SEC_CHECKS.filter(c=>!c.Passed).length}</div><div class="lbl">Checks Failed</div></div>
      <div class="audit-stat"><div class="val">${owners}</div><div class="lbl">Owner Assignments (${ownerPct}%)</div></div>
      <div class="audit-stat"><div class="val">${[...new Set(DATA.map(r=>r.DisplayName))].length}</div><div class="lbl">Unique Principals</div></div>
      <div class="audit-stat"><div class="val">${CFG.healthScore}</div><div class="lbl">Health Score</div></div>
      <div class="audit-stat"><div class="val">${CFG.riskScore}</div><div class="lbl">Risk Score</div></div>
    </div>

    <div class="panel">
      <div class="section-title">📋 Security Check Results</div>
      <div class="audit-check-list">
        ${SEC_CHECKS.map(c=>`<div class="audit-check-row">
          <span class="audit-status-icon">${c.Passed?'✅':'❌'}</span>
          <span class="audit-check-name">${escH(c.CheckName)}</span>
          <span class="audit-check-sev">${sevBadge(c.Passed?'Low':c.Severity)}</span>
          <span class="badge badge-muted">${escH(c.Priority)}</span>
          <span class="audit-check-count">${c.AffectedCount} affected</span>
        </div>`).join('')}
      </div>
    </div>

    <div class="panel">
      <div class="section-title">📝 Executive Summary</div>
      <div style="font-size:13.5px;color:var(--muted2);line-height:1.8">
        <p>This RBAC audit analysed <strong style="color:var(--text)">${DATA.length} role assignments</strong> across <strong style="color:var(--text)">${CFG.subCount} subscription(s)</strong> for the tenant <strong style="color:var(--accent2)">__TENANTNAME__</strong>.</p>
        <br>
        <p>The tenant achieved a <strong style="color:${csColor}">Compliance Status of ${cs}</strong>, a Health Score of <strong style="color:var(--green)">${CFG.healthScore}/100</strong>, and a Risk Score of <strong style="color:var(--red)">${CFG.riskScore}/100</strong>.</p>
        <br>
        <p><strong style="color:var(--text)">${SEC_CHECKS.filter(c=>c.Passed).length}</strong> of <strong style="color:var(--text)">${CFG.checkTotal}</strong> security checks passed. There are <strong style="color:var(--red)">${SEC_CHECKS.filter(c=>!c.Passed&&c.Severity==='Critical').length}</strong> critical and <strong style="color:var(--amber)">${SEC_CHECKS.filter(c=>!c.Passed&&c.Severity==='High').length}</strong> high-severity findings that require remediation.</p>
        <br>
        <p>Owner roles represent <strong style="color:var(--red)">${ownerPct}%</strong> of all assignments. The recommended threshold is ≤5%. ${DATA.filter(r=>r.Scope==='/').length} root-scope assignment(s) were detected.</p>
        <br>
        <p style="color:var(--muted);font-size:12px">Report generated: __REPORTTIMESTAMP__ &nbsp;|&nbsp; PowerShell __PSVERSION__ &nbsp;|&nbsp; Cloud-Identity-Toolkit v3.0</p>
      </div>
    </div>`;
  document.getElementById('auditContent').innerHTML=html;
}

// ── Raw Data table with column chooser ────────────────────────────────────────
let rawPage=1, rawPageSz=25, rawFiltered=[];
const RAW_COLS=[
  {key:'SubscriptionName',label:'Subscription',visible:true},
  {key:'SubscriptionId',label:'Sub ID',visible:true},
  {key:'TenantId',label:'Tenant ID',visible:false},
  {key:'DisplayName',label:'Display Name',visible:true},
  {key:'SignInName',label:'Sign-In Name',visible:true},
  {key:'ObjectType',label:'Object Type',visible:true},
  {key:'RoleDefinitionName',label:'Role',visible:true},
  {key:'ResourceType',label:'Resource Type',visible:true},
  {key:'Scope',label:'Scope',visible:true},
  {key:'Environment',label:'Environment',visible:true}
];
function buildColChooser(){
  const dd=document.getElementById('colChooserDropdown');
  if(!dd)return;
  dd.innerHTML=RAW_COLS.map((c,i)=>`
    <label class="col-chooser-item">
      <input type="checkbox" ${c.visible?'checked':''} onchange="toggleColumn(${i},this.checked)"/>
      ${escH(c.label)}
    </label>`).join('');
}
function toggleColChooser(){
  document.getElementById('colChooserDropdown').classList.toggle('open');
}
function toggleColumn(idx,visible){
  RAW_COLS[idx].visible=visible;
  renderRawTable();
}
document.addEventListener('click',e=>{
  if(!e.target.closest('.col-chooser-wrap'))document.getElementById('colChooserDropdown').classList.remove('open');
});
function populateRawFilters(){
  const subF=document.getElementById('rawSubFilter');
  const roleF=document.getElementById('rawRoleFilter');
  const envF=document.getElementById('rawEnvFilter');
  const typeF=document.getElementById('rawTypeFilter');
  if(subF){UNIQUE_SUBS.forEach(s=>{const o=document.createElement('option');o.value=s;o.textContent=s;subF.appendChild(o);});}
  if(roleF){UNIQUE_ROLES.forEach(r=>{const o=document.createElement('option');o.value=r;o.textContent=r;roleF.appendChild(o);});}
  if(envF){UNIQUE_ENVS.forEach(e=>{const o=document.createElement('option');o.value=e;o.textContent=e;envF.appendChild(o);});}
  if(typeF){const types=[...new Set(DATA.map(r=>r.ObjectType||'Unknown'))].sort();types.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;typeF.appendChild(o);});}
  const resTypeF=document.getElementById('rawResTypeFilter');
  if(resTypeF){const rtypes=[...new Set(DATA.map(r=>r.ResourceType||'').filter(v=>v))].sort();rtypes.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;resTypeF.appendChild(o);});}
}
function renderRawTableHead(){
  const visCols=RAW_COLS.filter(c=>c.visible);
  document.getElementById('rawTableHead').innerHTML='<tr>'+visCols.map(c=>`<th>${escH(c.label)}</th>`).join('')+'<th>Actions</th></tr>';
}
function renderRawTable(){
  const q=(document.getElementById('rawSearch').value||'').toLowerCase();
  const subF=(document.getElementById('rawSubFilter')||{}).value||'';
  const roleF=(document.getElementById('rawRoleFilter')||{}).value||'';
  const envF=(document.getElementById('rawEnvFilter')||{}).value||'';
  const typeF=(document.getElementById('rawTypeFilter')||{}).value||'';
  const resTypeF=(document.getElementById('rawResTypeFilter')||{}).value||'';
  rawPageSz=+((document.getElementById('rawPageSize')||{}).value||25);
  rawFiltered=DATA.filter(r=>{
    if(subF&&r.SubscriptionName!==subF)return false;
    if(roleF&&r.RoleDefinitionName!==roleF)return false;
    if(envF&&r.Environment!==envF)return false;
    if(typeF&&(r.ObjectType||'Unknown')!==typeF)return false;
    if(resTypeF&&(r.ResourceType||'')!==resTypeF)return false;
    if(q){const blob=(r.SubscriptionName+r.SubscriptionId+r.TenantId+r.DisplayName+r.SignInName+r.ObjectType+r.RoleDefinitionName+r.ResourceType+r.Scope+r.Environment).toLowerCase();if(!blob.includes(q))return false;}
    return true;
  });
  const rc=document.getElementById('rawResultCount');
  if(rc)rc.textContent=rawFiltered.length+' of '+DATA.length;
  const pages=Math.max(1,Math.ceil(rawFiltered.length/rawPageSz));
  if(rawPage>pages)rawPage=1;
  const slice=rawFiltered.slice((rawPage-1)*rawPageSz,rawPage*rawPageSz);
  renderRawTableHead();
  const visCols=RAW_COLS.filter(c=>c.visible);
  document.getElementById('rawTableBody').innerHTML=slice.map((r,idx)=>{
    const cells=visCols.map(c=>{
      const v=r[c.key]||'';
      if(c.key==='ObjectType')return`<td><span class="badge badge-blue">${escH(v||'Unknown')}</span></td>`;
      if(c.key==='Environment')return`<td><span class="${envBadgeClass(v)}">${escH(v)}</span></td>`;
      if(c.key==='Scope'||c.key==='SubscriptionId'||c.key==='TenantId')return`<td class="td-mono" style="font-size:10.5px" title="${escH(v)}">${escH(v.length>40?v.slice(0,40)+'…':v)}</td>`;
      return`<td>${escH(v)}</td>`;
    }).join('');
    return`<tr>${cells}<td class="td-actions"><button class="icon-btn" title="Copy row" onclick="copyRow(${(rawPage-1)*rawPageSz+idx})">📋</button></td></tr>`;
  }).join('');
  renderPagination('rawPagination',pages,rawPage,pg=>{rawPage=pg;renderRawTable();});
}
function copyRow(idx){
  const r=rawFiltered[idx];
  if(!r)return;
  const txt=[r.SubscriptionName,r.SubscriptionId,r.TenantId,r.DisplayName,r.SignInName,r.ObjectType,r.RoleDefinitionName,r.ResourceType,r.Scope,r.Environment].join('\t');
  navigator.clipboard.writeText(txt).then(()=>showToast('Row copied to clipboard')).catch(()=>showToast('Copy failed','⚠'));
}
function exportRawCSV(){
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const header='SubscriptionName,SubscriptionId,TenantId,DisplayName,SignInName,ObjectType,RoleDefinitionName,ResourceType,Scope,Environment';
  const rows=rawFiltered.map(r=>[r.SubscriptionName,r.SubscriptionId,r.TenantId,r.DisplayName,r.SignInName,r.ObjectType,r.RoleDefinitionName,r.ResourceType,r.Scope,r.Environment].map(esc).join(','));
  dlFile([header,...rows].join('\r\n'),'rbac-filtered-export.csv','text/csv');
  showToast('Exported '+rawFiltered.length+' records');
}
function exportAllCSV(){rawFiltered=DATA;exportRawCSV();}
function exportSecurityReport(){
  const rows=['CheckName,Severity,Status,AffectedCount,Priority,Effort,Description,Fix,BusinessImpact'];
  SEC_CHECKS.forEach(c=>{rows.push(`"${c.CheckName.replace(/"/g,'""')}","${c.Severity}","${c.Passed?'Passed':'Failed'}",${c.AffectedCount},"${c.Priority}","${c.Effort}","${c.Description.replace(/"/g,'""')}","${c.Fix.replace(/"/g,'""')}","${c.Impact.replace(/"/g,'""')}"`);});
  dlFile(rows.join('\r\n'),'rbac-security-report.csv','text/csv');
  showToast('Exported security report');
}

// ── CSV Upload (runtime re-load) ───────────────────────────────────────────────
function openUpload(){document.getElementById('uploadOverlay').classList.add('open');}
function closeUpload(){document.getElementById('uploadOverlay').classList.remove('open');resetDropZone();}
function resetDropZone(){
  const p=document.getElementById('uploadProgress');
  const f=document.getElementById('progressFill');
  if(p)p.style.display='none';
  if(f)f.style.width='0%';
}

function handleFileSelect(event){const f=event.target.files[0];if(f)processCSVFile(f);}
function processCSVFile(file){
  if(!file.name.toLowerCase().endsWith('.csv')){showToast('Please select a .csv file','⚠');return;}
  const prog=document.getElementById('uploadProgress');
  const fill=document.getElementById('progressFill');
  const stat=document.getElementById('uploadStatusText');
  if(prog)prog.style.display='block';
  if(stat)stat.textContent='Reading file…';
  if(fill)fill.style.width='20%';
  const reader=new FileReader();
  reader.onload=function(e){
    if(fill)fill.style.width='60%';
    if(stat)stat.textContent='Parsing CSV…';
    try{
      const parsed=parseCSV(e.target.result);
      if(fill)fill.style.width='80%';
      if(stat)stat.textContent='Rebuilding dashboard…';
      setTimeout(()=>{
        try{
          rebuildDashboard(parsed);
          if(fill)fill.style.width='100%';
          if(stat)stat.textContent='Done!';
          setTimeout(()=>{ closeUpload(); showToast('Dashboard reloaded with '+parsed.length+' assignments','🔄'); },600);
        }catch(rebuildErr){
          if(stat)stat.textContent='Error: '+rebuildErr.message;
          showToast('Rebuild error: '+rebuildErr.message,'⚠');
          console.error('rebuildDashboard error:',rebuildErr);
        }
      },100);
    }catch(err){
      if(stat)stat.textContent='Error: '+err.message;
      showToast('CSV parse error: '+err.message,'⚠');
    }
  };
  reader.readAsText(file,'UTF-8');
}
function parseCSV(text){
  const lines=text.replace(/\r\n/g,'\n').replace(/\r/g,'\n').split('\n').filter(l=>l.trim());
  if(!lines.length)throw new Error('Empty file');
  const headers=parseCsvLine(lines[0]).map(h=>h.trim());
  const required=['SubscriptionName','SubscriptionId','DisplayName','RoleDefinitionName','Scope'];
  for(const r of required){if(!headers.includes(r))throw new Error('Missing column: '+r);}
  const rows=[];
  for(let i=1;i<lines.length;i++){
    const vals=parseCsvLine(lines[i]);
    if(vals.length<3)continue;
    const row={};
    headers.forEach((h,idx)=>row[h]=vals[idx]||'');
    row.Environment=detectEnv(row.SubscriptionName||'');
    row.SignInName=row.SignInName||'';
    row.ObjectType=row.ObjectType||'Unknown';
    row.TenantId=row.TenantId||'';
    row.ResourceType=row.ResourceType||'';
    rows.push(row);
  }
  if(!rows.length)throw new Error('No data rows found');
  return rows;
}
function parseCsvLine(line){
  const result=[];
  let i=0,len=line.length;
  while(i<=len){
    if(i===len){result.push('');break;}
    if(line[i]==='"'){
      let val='',j=i+1;
      while(j<len){
        if(line[j]==='"'&&line[j+1]==='"'){val+='"';j+=2;}
        else if(line[j]==='"'){j++;break;}
        else{val+=line[j++];}
      }
      result.push(val);
      i=j;
      if(i<len&&line[i]===',')i++;
    }else{
      let start=i;
      while(i<len&&line[i]!==',')i++;
      result.push(line.slice(start,i));
      if(i<len)i++;
    }
  }
  return result;
}
function detectEnv(name){
  const n=name.toLowerCase();
  if(/non-prod|nonprod/.test(n))return 'NonProd';
  if(/pre-prod|preprod/.test(n))return 'PreProd';
  if(/prod|production/.test(n))return 'Prod';
  if(/dev|development/.test(n))return 'Dev';
  if(/uat/.test(n))return 'UAT';
  if(/sit/.test(n))return 'SIT';
  if(/qa/.test(n))return 'QA';
  if(/test|testing/.test(n))return 'Test';
  if(/stage|staging/.test(n))return 'Staging';
  if(/sandbox|sbx/.test(n))return 'Sandbox';
  if(/poc/.test(n))return 'POC';
  if(/lab|demo/.test(n))return 'Lab';
  if(/pilot/.test(n))return 'Pilot';
  if(/training|train/.test(n))return 'Training';
  if(/engineering|engg|eng/.test(n))return 'Engineering';
  return 'Unknown';
}

// ── Full dashboard rebuild after upload ──────────────────────────────────────
function rebuildDashboard(newData){
  DATA=newData;

  // Rebuild all derived data structures
  UNIQUE_SUBS=[...new Set(DATA.map(r=>r.SubscriptionName))].sort();
  UNIQUE_ROLES=[...new Set(DATA.map(r=>r.RoleDefinitionName))].sort();
  UNIQUE_ENVS=[...new Set(DATA.map(r=>r.Environment))].sort();

  // Top principals & roles
  const pm={};DATA.forEach(r=>{pm[r.DisplayName]=(pm[r.DisplayName]||0)+1;});
  TOP_PRINC=Object.entries(pm).map(([n,c])=>({Name:n,Count:c})).sort((a,b)=>b.Count-a.Count).slice(0,15);
  const rm={};DATA.forEach(r=>{rm[r.RoleDefinitionName]=(rm[r.RoleDefinitionName]||0)+1;});
  TOP_ROLES=Object.entries(rm).map(([n,c])=>({Name:n,Count:c})).sort((a,b)=>b.Count-a.Count).slice(0,15);

  // Scope distribution
  const sm={Subscription:0,'Resource Group':0,Resource:0,Root:0};
  DATA.forEach(r=>{
    if(r.Scope==='/')sm.Root++;
    else if(r.Scope.match(/\/subscriptions\/[^\/]+$/))sm.Subscription++;
    else if(r.Scope.match(/\/resourceGroups\/[^\/]+$/))sm['Resource Group']++;
    else sm.Resource++;
  });
  SCOPE_DIST=Object.entries(sm).filter(([,v])=>v>0).map(([n,c])=>({Name:n,Count:c}));

  // Object type
  const otm={};DATA.forEach(r=>{const t=r.ObjectType||'Unknown';otm[t]=(otm[t]||0)+1;});
  OBJ_DIST=Object.entries(otm).map(([n,c])=>({Name:n,Count:c})).sort((a,b)=>b.Count-a.Count);

  // Environment stats
  const evm={};DATA.forEach(r=>{
    const e=r.Environment||'Unknown';
    if(!evm[e])evm[e]={Environment:e,Count:0,Principals:new Set(),Roles:new Set(),Subscriptions:new Set(),OwnerCount:0,HighRiskCount:0};
    evm[e].Count++;
    evm[e].Principals.add(r.DisplayName);
    evm[e].Roles.add(r.RoleDefinitionName);
    evm[e].Subscriptions.add(r.SubscriptionName);
    if(r.RoleDefinitionName.toLowerCase().includes('owner'))evm[e].OwnerCount++;
    if(r.RoleDefinitionName.toLowerCase().match('owner|user access administrator')||r.Scope==='/')evm[e].HighRiskCount++;
  });
  ENV_STATS=Object.values(evm).map(e=>({
    ...e,
    Principals:e.Principals.size,
    Roles:e.Roles.size,
    Subscriptions:e.Subscriptions.size,
    RiskScore:Math.min(100, Math.round((e.OwnerCount/Math.max(1,e.Count))*100 + e.HighRiskCount)),
    HealthScore:Math.max(0, 100 - Math.min(100, Math.round((e.OwnerCount/Math.max(1,e.Count))*100 + e.HighRiskCount)))
  })).sort((a,b)=>b.Count-a.Count);

  // Subscription stats
  const subm={};DATA.forEach(r=>{
    const s=r.SubscriptionName;
    if(!subm[s])subm[s]={SubscriptionName:s,SubscriptionId:r.SubscriptionId,TenantId:r.TenantId,Environment:r.Environment,TotalAssignments:0,Principals:new Set(),Roles:new Set(),OwnerCount:0,ContribCount:0,ReaderCount:0,HighRiskCount:0};
    subm[s].TotalAssignments++;
    subm[s].Principals.add(r.DisplayName);
    subm[s].Roles.add(r.RoleDefinitionName);
    const rn=r.RoleDefinitionName.toLowerCase();
    if(rn.includes('owner'))subm[s].OwnerCount++;
    if(rn.includes('contributor'))subm[s].ContribCount++;
    if(rn.includes('reader'))subm[s].ReaderCount++;
    if(rn.match('owner|user access administrator')||r.Scope==='/')subm[s].HighRiskCount++;
  });
  SUB_STATS=Object.values(subm).map(s=>({
    ...s,
    UniquePrincipals:s.Principals.size,
    UniqueRoles:s.Roles.size,
    RiskScore:Math.min(100, Math.round((s.OwnerCount/Math.max(1,s.TotalAssignments))*80 + (s.HighRiskCount/Math.max(1,s.TotalAssignments))*20)),
    HealthScore:Math.max(0, 100 - Math.min(100, Math.round((s.OwnerCount/Math.max(1,s.TotalAssignments))*80 + (s.HighRiskCount/Math.max(1,s.TotalAssignments))*20))),
    TopRoles:Object.entries(
      DATA.filter(r=>r.SubscriptionName===s.SubscriptionName)
          .reduce((m,r)=>{m[r.RoleDefinitionName]=(m[r.RoleDefinitionName]||0)+1;return m;},{})
    ).map(([n,c])=>({Name:n,Count:c})).sort((a,b)=>b.Count-a.Count).slice(0,5),
    TopPrincipals:Object.entries(
      DATA.filter(r=>r.SubscriptionName===s.SubscriptionName)
          .reduce((m,r)=>{m[r.DisplayName]=(m[r.DisplayName]||0)+1;return m;},{})
    ).map(([n,c])=>({Name:n,Count:c})).sort((a,b)=>b.Count-a.Count).slice(0,5)
  })).sort((a,b)=>b.TotalAssignments-a.TotalAssignments);

  // Principal risk
  PRINC_RISK=Object.entries(DATA.reduce((m,r)=>{
    const k=r.DisplayName||'(Unknown)';
    if(!m[k])m[k]=[];m[k].push(r);return m;
  },{})).map(([name,rows])=>{
    let sc=0;
    const roles=[...new Set(rows.map(r=>r.RoleDefinitionName))];
    roles.forEach(r=>{const rn=r.toLowerCase();if(rn.includes('owner'))sc+=40;else if(rn.includes('user access administrator'))sc+=35;else if(rn.includes('contributor'))sc+=20;else if(rn.includes('administrator'))sc+=15;});
    rows.forEach(r=>{if(r.Scope==='/')sc+=30;else if(r.Scope.match(/\/subscriptions\/[^\/]+$/))sc+=5;});
    sc=Math.min(100,sc);
    return{DisplayName:name,RiskScore:sc,RiskLevel:sc>=70?'Critical':sc>=40?'High':sc>=20?'Medium':'Low',Count:rows.length};
  });

  // Recompute security checks and CFG
  SEC_CHECKS = recomputeSecurityChecks(DATA);
  CFG = recomputeCFG(DATA, SEC_CHECKS);

  // Update sidebar badges
  document.querySelectorAll('.nav-badge').forEach(b=>{
    const parentText=b.closest('.nav-btn')?.textContent||'';
    if(parentText.includes('Principals')) b.textContent=CFG.principalCount;
    else if(parentText.includes('Roles')) b.textContent=CFG.roleCount;
    else if(parentText.includes('Subscriptions')) b.textContent=CFG.subCount;
    else if(parentText.includes('Raw Data')) b.textContent=CFG.totalRecords;
  });
  const secBadge=document.getElementById('secBadge');
  if(secBadge) secBadge.textContent=CFG.checkTotal - CFG.passedChecks;

  // Update header, score rings, KPIs
  updateHeader(CFG.healthScore, CFG.riskScore, CFG.complianceStatus);
  populateOverviewKPIs();

  // Re-render all tabs
  renderSecChecks();
  renderEnvCards();
  buildPrincData();
  renderPrincTable();
  buildRolesData();
  renderRoleTable();
  buildResData();
  renderResTable();
  renderSubCards();
  populateRawFilters();
  renderRawTable();
  renderRecommendations();
  renderAuditReport();

  // Refresh charts
  refreshAllCharts();
}

// ── Subscriptions env filter ───────────────────────────────────────────────────
function populateSubEnvFilter2(){
  const ef=document.getElementById('subEnvFilter');
  if(ef&&ef.options.length<=1)UNIQUE_ENVS.forEach(e=>{const o=document.createElement('option');o.value=e;o.textContent=e;ef.appendChild(o);});
}

// ── Pagination helper ──────────────────────────────────────────────────────────
function renderPagination(containerId,pages,current,onPage){
  const el=document.getElementById(containerId);
  if(!el)return;
  if(pages<=1){el.innerHTML='';return;}
  let html='';
  const show=p=>`<button class="page-btn${p===current?' active':''}" onclick="(${onPage.toString()})(${p})">${p}</button>`;
  if(current>1)html+=`<button class="page-btn" onclick="(${onPage.toString()})(${current-1})">‹</button>`;
  if(pages<=7){for(let i=1;i<=pages;i++)html+=show(i);}
  else{html+=show(1);if(current>3)html+='<span style="color:var(--muted);padding:0 4px">…</span>';for(let i=Math.max(2,current-1);i<=Math.min(pages-1,current+1);i++)html+=show(i);if(current<pages-2)html+='<span style="color:var(--muted);padding:0 4px">…</span>';html+=show(pages);}
  if(current<pages)html+=`<button class="page-btn" onclick="(${onPage.toString()})(${current+1})">›</button>`;
  el.innerHTML=html;
}

// ── File download ──────────────────────────────────────────────────────────────
function dlFile(content,name,type){
  const b=new Blob([content],{type});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=name;a.click();URL.revokeObjectURL(u);
}

// ── Keyboard shortcuts ─────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closeDetail();closeUpload();return;}
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'&&document.activeElement.tagName!=='SELECT'){
    e.preventDefault();const inp=document.querySelector('.page.active input[type=text]');if(inp)inp.focus();
  }
});

// ── Bootstrap ──────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded',function(){
  try{
    if(typeof Chart==='undefined'){
      document.querySelectorAll('.chart-wrap').forEach(el=>{el.innerHTML='<p style="text-align:center;padding:2rem;color:var(--amber)">⚠ Chart.js unavailable (CDN blocked). Data tables are fully functional.</p>';});
    }else{
      Chart.defaults.font.family="'Calibri','Segoe UI',sans-serif";
      initOverviewCharts();
      initEnvCharts();
      initResourceCharts();
    }
    populateOverviewKPIs();
    renderSecChecks();
    renderEnvCards();
    buildPrincData();
    renderPrincTable();
    buildRolesData();
    renderRoleTable();
    buildResData();
    renderResTable();
    populateSubEnvFilter();
    populateSubEnvFilter2();
    renderSubCards();
    populateRawFilters();
    buildColChooser();
    rawFiltered=DATA;
    renderRawTable();
    const dz=document.getElementById('dropZone');
    if(dz){
      dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('drag-over');});
      dz.addEventListener('dragleave',()=>dz.classList.remove('drag-over'));
      dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('drag-over');const f=e.dataTransfer.files[0];if(f)processCSVFile(f);});
    }
    renderRecommendations();
    renderAuditReport();
    // Initial header update (ensures consistency)
    updateHeader(CFG.healthScore, CFG.riskScore, CFG.complianceStatus);
  }catch(e){
    console.error('Dashboard init error:',e);
    showToast('Init error: '+e.message,'⚠');
  }
});
</script>
</body>
</html>
'@

    #endregion

    #region ── Token substitution ─────────────────────────────────────────────

    $failedChecksCount = $failedChecks.Count
    $passedChecksCount = $passedChecks.Count
    $checkTotal        = $securityChecks.Count
    $criticalCount     = $criticalChecks.Count
    $highCount         = $highChecks.Count
    $guestCount        = $guestRows.Count
    $rootScopeCount    = $rootScopeRows.Count
    $customRoleCount   = $customRoleRows.Count
    $tenantNameSafe    = $TenantName -replace '"','&quot;'

    $complianceClass = switch ($complianceStatus) {
        'Pass'    { 'badge-green' }
        'Warning' { 'badge-amber' }
        'Fail'    { 'badge-red'   }
        default   { 'badge-muted' }
    }
    $healthClass = if ($healthScore -ge 70) { '' } elseif ($healthScore -ge 40) { 'warn' } else { 'bad' }
    $riskClass   = if ($riskScore -lt 20)   { 'low' } elseif ($riskScore -lt 50) { 'medium' } else { '' }

    $html = $html `
        -replace '__TENANTNAME__',        $tenantNameSafe `
        -replace '__REPORTDATE__',        $reportDate `
        -replace '__REPORTTIMESTAMP__',   $reportTimestamp `
        -replace '__TOTALRECORDS__',      $totalRecords `
        -replace '__PRINCIPALCOUNT__',    $uniquePrincipals.Count `
        -replace '__ROLECOUNT__',         $uniqueRoles.Count `
        -replace '__SUBCOUNT__',          $uniqueSubscriptions.Count `
        -replace '__ENVCOUNT__',          $uniqueEnvironments.Count `
        -replace '__HEALTHSCORE__',       $healthScore `
        -replace '__RISKSCORE__',         $riskScore `
        -replace '__HEALTHCLASS__',       $healthClass `
        -replace '__RISKCLASS__',         $riskClass `
        -replace '__COMPLIANCESTATUS__',  $complianceStatus `
        -replace '__COMPLIANCECLASS__',   $complianceClass `
        -replace '__FAILEDCHECKS__',      $failedChecksCount `
        -replace '__PASSEDCHECKS__',      $passedChecksCount `
        -replace '__CHECKTOTAL__',        $checkTotal `
        -replace '__CRITICALCHECKS__',    $criticalCount `
        -replace '__HIGHCHECKS__',        $highCount `
        -replace '__UNIQUEUSERS__',       $uniqueUsers `
        -replace '__UNIQUEGROUPS__',      $uniqueGroups `
        -replace '__UNIQUESPS__',         $uniqueSPs `
        -replace '__UNIQUEMIS__',         $uniqueMIs `
        -replace '__UNKNOWNOBJS__',       $unknownObjRows.Count `
        -replace '__HIGHRISKCOUNT__',     $highRiskCount `
        -replace '__GUESTCOUNT__',        $guestCount `
        -replace '__ROOTSCOPECOUNT__',    $rootScopeCount `
        -replace '__CUSTOMROLECOUNT__',   $customRoleCount `
        -replace '__PSVERSION__',         $psVersion `
        -replace '__EXECUTIONTIME__',     $executionTime `
        -replace '__ENRICHED_JSON__',     $enrichedJson `
        -replace '__SCOPE_JSON__',        $scopeJson `
        -replace '__OBJTYPE_JSON__',      $objTypeJson `
        -replace '__TOP_PRINC_JSON__',    $topPrincJson `
        -replace '__TOP_ROLES_JSON__',    $topRolesJson `
        -replace '__RESTYPE_JSON__',      $resTypeJson `
        -replace '__RESGROUP_JSON__',     $resGroupJson `
        -replace '__INDRES_JSON__',       $indResJson `
        -replace '__ENVSTATS_JSON__',     $envStatsJson `
        -replace '__SUBSTATS_JSON__',     $subStatsJson `
        -replace '__UNIQUE_SUBS_JSON__',  $uniqueSubsJson `
        -replace '__UNIQUE_ROLES_JSON__', $uniqueRolesJson `
        -replace '__UNIQUE_ENVS_JSON__',  $uniqueEnvsJson `
        -replace '__SECCHECKS_JSON__',    $secChecksJson `
        -replace '__PRINCRISK_JSON__',    $principalRiskJson

    #endregion

    #region ── Write output ───────────────────────────────────────────────────

    try
    {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Host '        ✓ HTML report written' -ForegroundColor Green
    }
    catch
    {
        Write-Error "Failed to write HTML report: $_"
        return
    }

    #endregion

    $totalTime = [Math]::Round(((Get-Date) - $scriptStartTime).TotalSeconds, 2)

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Green
    Write-Host '║   ✅  RBAC Visualization Report v3.0 — Generated!            ║' -ForegroundColor Green
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Green
    Write-Host ''
    Write-Host "  📊  Records analysed   : $totalRecords"                                      -ForegroundColor White
    Write-Host "  👤  Unique principals  : $($uniquePrincipals.Count)"                         -ForegroundColor White
    Write-Host "  🎭  Unique roles       : $($uniqueRoles.Count)"                              -ForegroundColor White
    Write-Host "  🗂   Subscriptions      : $($uniqueSubscriptions.Count)"                      -ForegroundColor White
    Write-Host "  🌍  Environments       : $($uniqueEnvironments -join ', ')"                  -ForegroundColor White
    Write-Host "  💊  Health Score       : $healthScore / 100"                                 -ForegroundColor White
    Write-Host "  ⚠   Risk Score         : $riskScore / 100"                                   -ForegroundColor White
    Write-Host "  📋  Compliance Status  : $complianceStatus"                                  -ForegroundColor White
    Write-Host "  ⏱   Execution Time     : $totalTime seconds"                                 -ForegroundColor White
    Write-Host "  📁  Output file        : $OutputPath"                                        -ForegroundColor White
    Write-Host ''
}
