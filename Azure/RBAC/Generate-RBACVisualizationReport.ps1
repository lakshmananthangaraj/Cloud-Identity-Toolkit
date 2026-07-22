<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 02 March 2026
Modified-On     : 22 July 2026

.SYNOPSIS
    Generates an interactive HTML visualization report from Azure RBAC assignment CSV data.

.DESCRIPTION
    The Generate-RBACVisualizationReport script transforms Azure RBAC assignment data,
    previously exported to CSV (e.g. via Get-AzureRBACAssignments.ps1), into a self-contained,
    interactive HTML report.

    It supports:
        - Overview tab      — KPI cards, scope/object-type distribution charts
        - Principals tab    — Per-principal assignment breakdown, searchable
        - Roles tab         — Per-role usage breakdown, searchable
        - Resources tab     — Resource-type distribution
        - Analysis Matrix tab — Principal-to-role assignment matrix, filterable
        - Recommendations tab — Automated least-privilege findings (Owner-role ratio,
          over-provisioned principals) and custom-role design suggestions
        - Raw Data tab      — Full searchable/filterable assignment table with CSV export
        - Optional GroupCategories parameter to bucket principals by naming pattern
          (e.g. Reader/Developer/Architect) for organization-specific reporting

.PARAMETER CsvPath
    Path to the input CSV file containing Azure RBAC assignments. Expected columns:
    SubscriptionName, SubscriptionId, DisplayName, RoleDefinitionName, ResourceType, Scope
    (matches the export format of Get-AzureRBACAssignments.ps1).

.PARAMETER OutputPath
    Path where the generated HTML report will be saved. Default: RBAC-Visualization-Report.html

.PARAMETER GroupCategories
    Optional hashtable to categorize principals by naming pattern, e.g.: @{Reader=@('*reader*')

.OUTPUTS
    None. Writes an HTML file to -OutputPath.

.EXAMPLE
    .\Generate-RBACVisualizationReport -CsvPath ".\rbac-assignments.csv"

.EXAMPLE
    .\Generate-RBACVisualizationReport -CsvPath ".\rbac-assignments.csv" -OutputPath ".\reports\rbac-report.html"

.NOTES
    Requires: PowerShell 5.1 or higher.

    Input dependency:
    Expects a CSV in the format produced by Get-AzureRBACAssignments.ps1 (this repo,
    Azure/RBAC/). Run that script first with -ExportToCsv to generate compatible input.

    External dependency:
    Loads Chart.js from a public CDN (cdn.jsdelivr.net) for chart rendering. In network-
    restricted/offline environments, charts will not render; data tables remain fully
    functional (report includes an on-page fallback message in that case).

    Known limitation:
    -GroupCategories is accepted and internally computed into $categorizedPrincipals,
    but that grouping is not currently surfaced anywhere in the generated HTML report
    (no dedicated tab, filter, or chart consumes it yet). Passing this parameter today
    has no visible effect on the output. Treat as reserved for a future release.

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (22-Jul-2026)      - Initial public release: interactive HTML report with
                                 charts, tables, principal-role matrix, and automated
                                 least-privilege recommendations, generated from
                                 Get-AzureRBACAssignments.ps1 CSV output.

.LINK
    Get-AzureRBACAssignments.ps1 (companion script — generates compatible CSV input)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/RBAC/Get-AzureRBACAssignments.ps1

#>

Function Generate-RBACVisualizationReport
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$CsvPath,
    
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "RBAC-Visualization-Report.html",
    
        [Parameter(Mandatory = $false)]
        [hashtable]$GroupCategories = @{}
    )

    # Set strict mode for better error handling
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Azure RBAC Visualization Report Generator" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    # Import CSV data
    Write-Host "[1/5] Importing CSV data..." -ForegroundColor Yellow
    try {
        $rbacData = Import-Csv -Path $CsvPath -Encoding UTF8
        $totalRecords = $rbacData.Count
        Write-Host "      ✓ Loaded $totalRecords RBAC assignments" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to import CSV: $_"
        return
    }

    # NEW: guard clause before anything indexes into $rbacData[0]
    if ($totalRecords -eq 0) {
        Write-Error "The CSV at '$CsvPath' contains no data rows. Nothing to report on."
        return
    }

    # existing column-validation logic continues here safely
    $csvColumns = $rbacData[0].PSObject.Properties.Name

    # Validate CSV structure
    Write-Host "[2/5] Validating CSV structure..." -ForegroundColor Yellow
    $requiredColumns = @('SubscriptionName', 'SubscriptionId', 'DisplayName', 'RoleDefinitionName', 'ResourceType', 'Scope')
    $csvColumns = $rbacData[0].PSObject.Properties.Name

    foreach ($col in $requiredColumns) {
        if ($col -notin $csvColumns) {
            Write-Error "Missing required column: $col"
            return
        }
    }
    Write-Host "      ✓ CSV structure validated" -ForegroundColor Green

    # Analyze data
    Write-Host "[3/5] Analyzing RBAC assignments..." -ForegroundColor Yellow

    # Get unique values for analysis
    $uniqueSubscriptions = @($rbacData | Select-Object -ExpandProperty SubscriptionName -Unique | Sort-Object)
    $uniqueRoles = $rbacData | Select-Object -ExpandProperty RoleDefinitionName -Unique | Sort-Object
    $uniqueResourceTypes = $rbacData | Where-Object { $_.ResourceType } | Select-Object -ExpandProperty ResourceType -Unique | Sort-Object
    $uniquePrincipals = $rbacData | Select-Object -ExpandProperty DisplayName -Unique | Sort-Object

    # Categorize principals if categories provided
    $categorizedPrincipals = @{}
    if ($GroupCategories.Count -gt 0) {
        foreach ($category in $GroupCategories.Keys) {
            $patterns = $GroupCategories[$category]
            $categorizedPrincipals[$category] = $uniquePrincipals | Where-Object {
                $principal = $_
                $matched = $false
                foreach ($pattern in $patterns) {
                    if ($principal -like $pattern) {
                        $matched = $true
                        break
                    }
                }
                $matched
            }
        }
    }

    # Scope analysis
    $scopeDistribution = $rbacData | Group-Object -Property {
        if ($_.Scope -match '/subscriptions/[^/]+$') { 'Subscription' }
        elseif ($_.Scope -match '/resourceGroups/[^/]+$') { 'Resource Group' }
        else { 'Resource' }
    } | Select-Object Name, Count

    # Object type distribution
    $objectTypeDistribution = $rbacData | ForEach-Object {
        $_ | Select-Object *, @{Name = 'ObjectTypeFixed'; Expression = { if ($_.ObjectType) { $_.ObjectType } else { 'Unknown' } } }
    } | Group-Object -Property ObjectTypeFixed | Select-Object Name, Count | Sort-Object Count -Descending

    # Top principals by assignment count
    $topPrincipals = $rbacData | Group-Object -Property DisplayName | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending | 
    Select-Object -First 15

    # Top roles by usage
    $topRoles = $rbacData | Group-Object -Property RoleDefinitionName | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending | 
    Select-Object -First 15

    # Resource type distribution
    $resourceTypeDistribution = $rbacData | Where-Object { $_.ResourceType } | 
    Group-Object -Property ResourceType | 
    Select-Object Name, Count | 
    Sort-Object Count -Descending | 
    Select-Object -First 20

    # Create principal-role matrix
    $principalRoleMatrix = @{}
    foreach ($assignment in $rbacData) {
        $principal = $assignment.DisplayName
        $role = $assignment.RoleDefinitionName
    
        if (-not $principalRoleMatrix.ContainsKey($principal)) {
            $principalRoleMatrix[$principal] = @{}
        }
    
        if (-not $principalRoleMatrix[$principal].ContainsKey($role)) {
            $principalRoleMatrix[$principal][$role] = 0
        }
    
        $principalRoleMatrix[$principal][$role]++
    }

    Write-Host "      ✓ Analysis complete" -ForegroundColor Green
    Write-Host "        - Subscriptions: $($uniqueSubscriptions.Count)" -ForegroundColor Gray
    Write-Host "        - Unique Roles: $($uniqueRoles.Count)" -ForegroundColor Gray
    Write-Host "        - Unique Principals: $($uniquePrincipals.Count)" -ForegroundColor Gray
    Write-Host "        - Resource Types: $($uniqueResourceTypes.Count)" -ForegroundColor Gray

    # Generate timestamp
    $reportTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $reportDate = Get-Date -Format "MMMM dd, yyyy"

    Write-Host "[4/5] Generating HTML report..." -ForegroundColor Yellow

    # Convert data to JSON for JavaScript
    $rbacDataJson = @($rbacData) | ConvertTo-Json -Depth 10 -Compress
    $scopeDistributionJson = @($scopeDistribution) | ConvertTo-Json -Compress
    $objectTypeDistributionJson = @($objectTypeDistribution) | ConvertTo-Json -Compress
    $topPrincipalsJson = @($topPrincipals) | ConvertTo-Json -Compress
    $topRolesJson = @($topRoles) | ConvertTo-Json -Compress
    $resourceTypeDistributionJson = @($resourceTypeDistribution) | ConvertTo-Json -Compress
    if ($uniqueRoles.Count -eq 1) { $uniqueRolesJson = "[$($uniqueRoles[0] | ConvertTo-Json -Compress)]" } else { $uniqueRolesJson = @($uniqueRoles) | ConvertTo-Json -Compress }
    if ($uniquePrincipals.Count -eq 1) { $uniquePrincipalsJson = "[$($uniquePrincipals[0] | ConvertTo-Json -Compress)]" } else { $uniquePrincipalsJson = @($uniquePrincipals) | ConvertTo-Json -Compress }
    if ($uniqueResourceTypes.Count -eq 1) { $uniqueResourceTypesJson = "[$($uniqueResourceTypes[0] | ConvertTo-Json -Compress)]" } else { $uniqueResourceTypesJson = @($uniqueResourceTypes) | ConvertTo-Json -Compress }
    if ($uniqueSubscriptions.Count -eq 1) { $uniqueSubscriptionsJson = "[$($uniqueSubscriptions[0] | ConvertTo-Json -Compress)]" } else { $uniqueSubscriptionsJson = @($uniqueSubscriptions) | ConvertTo-Json -Compress }

    # Build HTML Report
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure RBAC Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary-color: #0078d4;
            --secondary-color: #106ebe;
            --success-color: #107c10;
            --warning-color: #ff8c00;
            --danger-color: #d13438;
            --dark-bg: #1e1e1e;
            --card-bg: #ffffff;
            --text-primary: #323130;
            --text-secondary: #605e5c;
            --border-color: #edebe9;
            --hover-bg: #f3f2f1;
            --shadow: 0 2px 8px rgba(0,0,0,0.1);
            --shadow-hover: 0 4px 16px rgba(0,0,0,0.15);
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #e8eef3 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        .header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            padding: 2.5rem 2rem;
            box-shadow: var(--shadow);
            position: sticky;
            top: 0;
            z-index: 1000;
        }

        .header h1 {
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .header-icon {
            width: 48px;
            height: 48px;
            background: rgba(255,255,255,0.2);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }

        .header-subtitle {
            opacity: 0.95;
            font-size: 1rem;
            font-weight: 400;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 2rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
            border-left: 4px solid var(--primary-color);
        }

        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-hover);
        }

        .stat-card.success { border-left-color: var(--success-color); }
        .stat-card.warning { border-left-color: var(--warning-color); }
        .stat-card.danger { border-left-color: var(--danger-color); }

        .stat-label {
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.5rem;
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
        }

        .stat-card.success .stat-value { color: var(--success-color); }
        .stat-card.warning .stat-value { color: var(--warning-color); }
        .stat-card.danger .stat-value { color: var(--danger-color); }

        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 2rem;
            border-bottom: 2px solid var(--border-color);
            overflow-x: auto;
            padding-bottom: 0;
        }

        .tab-button {
            background: transparent;
            border: none;
            padding: 1rem 1.5rem;
            font-size: 1rem;
            font-weight: 500;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.3s ease;
            border-bottom: 3px solid transparent;
            white-space: nowrap;
        }

        .tab-button:hover {
            color: var(--primary-color);
            background: var(--hover-bg);
        }

        .tab-button.active {
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
            background: var(--hover-bg);
        }

        .tab-content {
            display: none;
            animation: fadeIn 0.5s ease;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
        }

        .card:hover {
            box-shadow: var(--shadow-hover);
        }

        .card-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .card-icon {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 18px;
        }

        .chart-container {
            position: relative;
            height: 400px;
            margin-bottom: 1rem;
        }

        .chart-container.small {
            height: 300px;
        }

        .grid-2 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 2rem;
        }

        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            font-size: 0.9rem;
        }

        thead {
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
        }

        th {
            padding: 1rem;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.5px;
        }

        th:first-child {
            border-top-left-radius: 8px;
        }

        th:last-child {
            border-top-right-radius: 8px;
        }

        td {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        tbody tr {
            transition: background 0.2s ease;
        }

        tbody tr:hover {
            background: var(--hover-bg);
        }

        tbody tr:last-child td:first-child {
            border-bottom-left-radius: 8px;
        }

        tbody tr:last-child td:last-child {
            border-bottom-right-radius: 8px;
        }

        .badge {
            display: inline-block;
            padding: 0.375rem 0.75rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 500;
            background: var(--primary-color);
            color: white;
        }

        .badge.success { background: var(--success-color); }
        .badge.warning { background: var(--warning-color); }
        .badge.danger { background: var(--danger-color); }

        .search-filter {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }

        .search-input, .filter-select {
            padding: 0.75rem 1rem;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            font-size: 1rem;
            transition: all 0.3s ease;
            flex: 1;
            min-width: 200px;
        }

        .search-input:focus, .filter-select:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(0, 120, 212, 0.1);
        }

        .export-button {
            background: linear-gradient(135deg, var(--success-color), #0b6a0b);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .export-button:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-hover);
        }

        .info-box {
            background: linear-gradient(135deg, #e6f4ff, #cce7ff);
            border-left: 4px solid var(--primary-color);
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 2rem;
        }

        .info-box h3 {
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }

        .warning-box {
            background: linear-gradient(135deg, #fff4e6, #ffe7cc);
            border-left: 4px solid var(--warning-color);
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 2rem;
        }

        .warning-box h3 {
            color: var(--warning-color);
            margin-bottom: 0.5rem;
        }

        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
            border-top: 1px solid var(--border-color);
            margin-top: 3rem;
        }

        .loading {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 400px;
        }

        .spinner {
            border: 4px solid var(--border-color);
            border-top: 4px solid var(--primary-color);
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .highlight {
            background: linear-gradient(135deg, #fff4e6, #ffe7cc);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }

        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.5rem;
            }
            
            .container {
                padding: 1rem;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .grid-2 {
                grid-template-columns: 1fr;
            }
            
            .tabs {
                flex-wrap: nowrap;
                overflow-x: scroll;
            }
        }

        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }

        ::-webkit-scrollbar-track {
            background: var(--border-color);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--primary-color);
            border-radius: 5px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--secondary-color);
        }
    </style>
</head>
<body>
    <!-- Loading Overlay -->
    <div id="loadingOverlay" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255,255,255,0.95); z-index: 9999; display: flex; align-items: center; justify-content: center; flex-direction: column;">
        <div class="spinner"></div>
        <p style="margin-top: 2rem; font-size: 1.2rem; color: #0078d4;">Loading RBAC Report...</p>
        <p style="margin-top: 0.5rem; color: #605e5c;" id="loadingStatus">Initializing...</p>
    </div>

    <div class="header">
        <h1>
            <div class="header-icon">🔐</div>
            Azure RBAC Analysis Report
        </h1>
        <div class="header-subtitle">Generated on $reportDate | Total Assignments: $totalRecords</div>
    </div>

    <div class="container">
        <!-- Statistics Overview -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Assignments</div>
                <div class="stat-value">$totalRecords</div>
            </div>
            <div class="stat-card success">
                <div class="stat-label">Unique Principals</div>
                <div class="stat-value">$($uniquePrincipals.Count)</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-label">Unique Roles</div>
                <div class="stat-value">$($uniqueRoles.Count)</div>
            </div>
            <div class="stat-card danger">
                <div class="stat-label">Subscriptions</div>
                <div class="stat-value">$($uniqueSubscriptions.Count)</div>
            </div>
        </div>

        <!-- Tabs Navigation -->
        <div class="tabs">
            <button class="tab-button active" onclick="openTab(event, 'overview')">📊 Overview</button>
            <button class="tab-button" onclick="openTab(event, 'principals')">👥 Principals</button>
            <button class="tab-button" onclick="openTab(event, 'roles')">🎭 Roles</button>
            <button class="tab-button" onclick="openTab(event, 'resources')">📦 Resources</button>
            <button class="tab-button" onclick="openTab(event, 'matrix')">🔍 Analysis Matrix</button>
            <button class="tab-button" onclick="openTab(event, 'recommendations')">💡 Recommendations</button>
            <button class="tab-button" onclick="openTab(event, 'data')">📋 Raw Data</button>
        </div>

        <!-- Tab 1: Overview -->
        <div id="overview" class="tab-content active">
            <div class="info-box">
                <h3>📌 Report Summary</h3>
                <p>This report provides comprehensive analysis of Azure RBAC assignments across your organization. Use the tabs above to explore different aspects of your access control configuration.</p>
            </div>

            <div class="grid-2">
                <div class="card">
                    <h2 class="card-title">
                        <div class="card-icon">📈</div>
                        Scope Distribution
                    </h2>
                    <div class="chart-container">
                        <canvas id="scopeChart"></canvas>
                    </div>
                </div>

                <div class="card">
                    <h2 class="card-title">
                        <div class="card-icon">👤</div>
                        Object Type Distribution
                    </h2>
                    <div class="chart-container">
                        <canvas id="objectTypeChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">🏆</div>
                    Top 15 Principals by Assignment Count
                </h2>
                <div class="chart-container">
                    <canvas id="topPrincipalsChart"></canvas>
                </div>
            </div>

            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">🎯</div>
                    Top 15 Roles by Usage
                </h2>
                <div class="chart-container">
                    <canvas id="topRolesChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Tab 2: Principals Analysis -->
        <div id="principals" class="tab-content">
            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">👥</div>
                    Principal Analysis
                </h2>
                
                <div class="search-filter">
                    <input type="text" id="principalSearch" class="search-input" placeholder="🔍 Search principals..." onkeyup="filterPrincipalTable()">
                    <button class="export-button" onclick="exportPrincipalData()">📥 Export to CSV</button>
                </div>

                <div style="overflow-x: auto;">
                    <table id="principalTable">
                        <thead>
                            <tr>
                                <th>Principal Name</th>
                                <th>Object Type</th>
                                <th>Assignment Count</th>
                                <th>Unique Roles</th>
                                <th>Subscriptions</th>
                            </tr>
                        </thead>
                        <tbody id="principalTableBody">
                            <!-- Populated by JavaScript -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Tab 3: Roles Analysis -->
        <div id="roles" class="tab-content">
            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">🎭</div>
                    Role Usage Analysis
                </h2>
                
                <div class="search-filter">
                    <input type="text" id="roleSearch" class="search-input" placeholder="🔍 Search roles..." onkeyup="filterRoleTable()">
                    <button class="export-button" onclick="exportRoleData()">📥 Export to CSV</button>
                </div>

                <div style="overflow-x: auto;">
                    <table id="roleTable">
                        <thead>
                            <tr>
                                <th>Role Name</th>
                                <th>Assignment Count</th>
                                <th>Unique Principals</th>
                                <th>Permission Level</th>
                            </tr>
                        </thead>
                        <tbody id="roleTableBody">
                            <!-- Populated by JavaScript -->
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">📊</div>
                    Role Distribution
                </h2>
                <div class="chart-container">
                    <canvas id="roleDistributionChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Tab 4: Resources -->
        <div id="resources" class="tab-content">
            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">📦</div>
                    Resource Type Distribution
                </h2>
                <div class="chart-container">
                    <canvas id="resourceTypeChart"></canvas>
                </div>
            </div>

            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">🗂️</div>
                    Resource Type Details
                </h2>
                
                <div class="search-filter">
                    <input type="text" id="resourceSearch" class="search-input" placeholder="🔍 Search resource types..." onkeyup="filterResourceTable()">
                </div>

                <div style="overflow-x: auto;">
                    <table id="resourceTable">
                        <thead>
                            <tr>
                                <th>Resource Type</th>
                                <th>Assignment Count</th>
                                <th>Percentage</th>
                            </tr>
                        </thead>
                        <tbody id="resourceTableBody">
                            <!-- Populated by JavaScript -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Tab 5: Analysis Matrix -->
        <div id="matrix" class="tab-content">
            <div class="warning-box">
                <h3>⚠️ Access Pattern Analysis</h3>
                <p>This matrix shows the relationship between principals and roles. Use this to identify over-privileged accounts, redundant assignments, and optimization opportunities.</p>
            </div>

            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">🔍</div>
                    Principal-Role Matrix
                </h2>
                
                <div class="search-filter">
                    <select id="matrixPrincipalFilter" class="filter-select" onchange="updateMatrix()">
                        <option value="">All Principals</option>
                    </select>
                    <select id="matrixRoleFilter" class="filter-select" onchange="updateMatrix()">
                        <option value="">All Roles</option>
                    </select>
                </div>

                <div id="matrixContainer" style="overflow-x: auto;">
                    <!-- Populated by JavaScript -->
                </div>
            </div>
        </div>

        <!-- Tab 6: Recommendations -->
        <div id="recommendations" class="tab-content">
            <div class="info-box">
                <h3>💡 Custom Role Design Recommendations</h3>
                <p>Based on the analysis of your current RBAC assignments, here are strategic recommendations for designing custom roles.</p>
            </div>

            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">🎯</div>
                    Key Findings
                </h2>
                <div id="keyFindings">
                    <!-- Populated by JavaScript -->
                </div>
            </div>

            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">✅</div>
                    Recommended Actions
                </h2>
                <div id="recommendedActions">
                    <!-- Populated by JavaScript -->
                </div>
            </div>

            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">⚠️</div>
                    Potential Security Concerns
                </h2>
                <div id="securityConcerns">
                    <!-- Populated by JavaScript -->
                </div>
            </div>
        </div>

        <!-- Tab 7: Raw Data -->
        <div id="data" class="tab-content">
            <div class="card">
                <h2 class="card-title">
                    <div class="card-icon">📋</div>
                    All RBAC Assignments
                </h2>
                
                <div class="search-filter">
                    <input type="text" id="dataSearch" class="search-input" placeholder="🔍 Search all fields..." onkeyup="filterDataTable()">
                    <select id="dataSubFilter" class="filter-select" onchange="filterDataTable()">
                        <option value="">All Subscriptions</option>
                    </select>
                    <select id="dataRoleFilter" class="filter-select" onchange="filterDataTable()">
                        <option value="">All Roles</option>
                    </select>
                    <button class="export-button" onclick="exportAllData()">📥 Export Filtered Data</button>
                </div>

                <div style="overflow-x: auto;">
                    <table id="dataTable">
                        <thead>
                            <tr>
                                <th>Subscription</th>
                                <th>Principal</th>
                                <th>Object Type</th>
                                <th>Role</th>
                                <th>Resource Type</th>
                                <th>Scope</th>
                            </tr>
                        </thead>
                        <tbody id="dataTableBody">
                            <!-- Populated by JavaScript -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div class="footer">
        <p><strong>Azure RBAC Visualization Report</strong></p>
        <p>Generated: $reportTimestamp | Total Records: $totalRecords</p>
        <p style="margin-top: 1rem; opacity: 0.7;">💡 Use this report to make informed decisions about custom RBAC role design and implementation</p>
    </div>

    <script>
        // Error handling
        window.onerror = function(msg, url, lineNo, columnNo, error) {
            console.error('Error: ' + msg + '\nLine: ' + lineNo);
            alert('JavaScript Error: ' + msg + '\nCheck browser console (F12) for details');
            return false;
        };

        // Loading indicator
        console.log('Loading RBAC data...');

        // Data from PowerShell
        let rbacData, scopeDistribution, objectTypeDistribution, topPrincipals, topRoles;
        let resourceTypeDistribution, uniqueRoles, uniquePrincipals, uniqueResourceTypes, uniqueSubscriptions;
        
        try {
            rbacData = $rbacDataJson;
            scopeDistribution = $scopeDistributionJson;
            objectTypeDistribution = $objectTypeDistributionJson;
            topPrincipals = $topPrincipalsJson;
            topRoles = $topRolesJson;
            resourceTypeDistribution = $resourceTypeDistributionJson;
            uniqueRoles = $uniqueRolesJson;
            uniquePrincipals = $uniquePrincipalsJson;
            uniqueResourceTypes = $uniqueResourceTypesJson;
            uniqueSubscriptions = $uniqueSubscriptionsJson;
            
            console.log('Data loaded successfully:', rbacData.length, 'records');
        } catch(e) {
            alert('Failed to load data: ' + e.message);
            console.error('Data loading error:', e);
        }

        // Check if Chart.js is available
        if (typeof Chart === 'undefined') {
            alert('Chart.js failed to load. Charts will not display.\nThis may be due to network/firewall restrictions.\nData tables will still work.');
            console.error('Chart.js not loaded');
        }

        // Chart.js default configuration
        Chart.defaults.font.family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
        Chart.defaults.color = '#605e5c';

        // Color palettes
        const primaryColors = [
            '#0078d4', '#106ebe', '#005a9e', '#004578', '#003152',
            '#00bcf2', '#0099bc', '#0078a1', '#005b70', '#004052'
        ];

        const gradientColors = [
            '#107c10', '#0b6a0b', '#0c5308', '#094509', '#063407',
            '#ff8c00', '#d97700', '#b36500', '#8c5100', '#664000'
        ];

        // Tab switching
        function openTab(evt, tabName) {
            const tabcontent = document.getElementsByClassName("tab-content");
            for (let i = 0; i < tabcontent.length; i++) {
                tabcontent[i].classList.remove("active");
            }
            
            const tabbuttons = document.getElementsByClassName("tab-button");
            for (let i = 0; i < tabbuttons.length; i++) {
                tabbuttons[i].classList.remove("active");
            }
            
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");
        }

        // Initialize charts
        function initCharts() {
            if (typeof Chart === 'undefined') {
                console.warn('Chart.js not available, skipping chart initialization');
                document.querySelectorAll('.chart-container').forEach(el => {
                    el.innerHTML = '<p style="text-align: center; padding: 2rem; color: #ff8c00;">Charts unavailable - Chart.js failed to load from CDN. Data tables below still work.</p>';
                });
                return;
            }
            
            try {
                console.log('Initializing charts...');
                
            // Scope Distribution Chart
            new Chart(document.getElementById('scopeChart'), {
                type: 'doughnut',
                data: {
                    labels: scopeDistribution.map(s => s.Name),
                    datasets: [{
                        data: scopeDistribution.map(s => s.Count),
                        backgroundColor: primaryColors,
                        borderWidth: 2,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { padding: 15, font: { size: 12 } }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((context.parsed / total) * 100).toFixed(1);
                                    return context.label + ': ' + context.parsed + ' (' + percentage + '%)';
                                }
                            }
                        }
                    }
                }
            });

            // Object Type Distribution Chart
            new Chart(document.getElementById('objectTypeChart'), {
                type: 'pie',
                data: {
                    labels: objectTypeDistribution.map(o => o.Name || 'Unknown'),
                    datasets: [{
                        data: objectTypeDistribution.map(o => o.Count),
                        backgroundColor: gradientColors,
                        borderWidth: 2,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { padding: 15, font: { size: 12 } }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((context.parsed / total) * 100).toFixed(1);
                                    return context.label + ': ' + context.parsed + ' (' + percentage + '%)';
                                }
                            }
                        }
                    }
                }
            });

            // Top Principals Chart
            new Chart(document.getElementById('topPrincipalsChart'), {
                type: 'bar',
                data: {
                    labels: topPrincipals.map(p => p.Name.length > 40 ? p.Name.substring(0, 40) + '...' : p.Name),
                    datasets: [{
                        label: 'Assignment Count',
                        data: topPrincipals.map(p => p.Count),
                        backgroundColor: '#0078d4',
                        borderRadius: 6
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                title: function(context) {
                                    return topPrincipals[context[0].dataIndex].Name;
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            grid: { display: false }
                        },
                        y: {
                            grid: { display: false }
                        }
                    }
                }
            });

            // Top Roles Chart
            new Chart(document.getElementById('topRolesChart'), {
                type: 'bar',
                data: {
                    labels: topRoles.map(r => r.Name.length > 40 ? r.Name.substring(0, 40) + '...' : r.Name),
                    datasets: [{
                        label: 'Usage Count',
                        data: topRoles.map(r => r.Count),
                        backgroundColor: '#107c10',
                        borderRadius: 6
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                title: function(context) {
                                    return topRoles[context[0].dataIndex].Name;
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            grid: { display: false }
                        },
                        y: {
                            grid: { display: false }
                        }
                    }
                }
            });

            // Resource Type Chart
            if (resourceTypeDistribution && resourceTypeDistribution.length > 0) {
                new Chart(document.getElementById('resourceTypeChart'), {
                    type: 'bar',
                    data: {
                        labels: resourceTypeDistribution.map(r => r.Name.length > 50 ? r.Name.substring(0, 50) + '...' : r.Name),
                        datasets: [{
                            label: 'Assignment Count',
                            data: resourceTypeDistribution.map(r => r.Count),
                            backgroundColor: primaryColors,
                            borderRadius: 6
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                callbacks: {
                                    title: function(context) {
                                        return resourceTypeDistribution[context[0].dataIndex].Name;
                                    }
                                }
                            }
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                grid: { display: false }
                            },
                            y: {
                                grid: { display: false }
                            }
                        }
                    }
                });
            }

            // Role Distribution Chart
            new Chart(document.getElementById('roleDistributionChart'), {
                type: 'bar',
                data: {
                    labels: topRoles.slice(0, 10).map(r => r.Name.length > 30 ? r.Name.substring(0, 30) + '...' : r.Name),
                    datasets: [{
                        label: 'Assignment Count',
                        data: topRoles.slice(0, 10).map(r => r.Count),
                        backgroundColor: gradientColors,
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            grid: { color: '#f3f2f1' }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: '#f3f2f1' }
                        }
                    }
                }
            });
            
            console.log('Charts initialized successfully');
            } catch(e) {
                console.error('Chart initialization error:', e);
                alert('Error creating charts: ' + e.message);
            }
        }

        // Populate tables
        function populatePrincipalTable() {
            const tbody = document.getElementById('principalTableBody');
            const principalStats = {};

            rbacData.forEach(row => {
                const principal = row.DisplayName;
                if (!principalStats[principal]) {
                    principalStats[principal] = {
                        objectType: row.ObjectType || 'Unknown',
                        count: 0,
                        roles: new Set(),
                        subscriptions: new Set()
                    };
                } else {
                    // Update objectType if it was Unknown but now we have a value
                    if (principalStats[principal].objectType === 'Unknown' && row.ObjectType) {
                        principalStats[principal].objectType = row.ObjectType;
                    }
                }
                principalStats[principal].count++;
                principalStats[principal].roles.add(row.RoleDefinitionName);
                principalStats[principal].subscriptions.add(row.SubscriptionName);
            });

            const sortedPrincipals = Object.entries(principalStats).sort((a, b) => b[1].count - a[1].count);

            sortedPrincipals.forEach(([principal, stats]) => {
                const tr = document.createElement('tr');
                tr.innerHTML = '<td><strong>' + principal + '</strong></td>' +
                    '<td><span class="badge">' + stats.objectType + '</span></td>' +
                    '<td>' + stats.count + '</td>' +
                    '<td>' + stats.roles.size + '</td>' +
                    '<td>' + stats.subscriptions.size + '</td>';
                tbody.appendChild(tr);
            });
        }

        function populateRoleTable() {
            const tbody = document.getElementById('roleTableBody');
            const roleStats = {};

            rbacData.forEach(row => {
                const role = row.RoleDefinitionName;
                if (!roleStats[role]) {
                    roleStats[role] = {
                        count: 0,
                        principals: new Set()
                    };
                }
                roleStats[role].count++;
                roleStats[role].principals.add(row.DisplayName);
            });

            const sortedRoles = Object.entries(roleStats).sort((a, b) => b[1].count - a[1].count);

            sortedRoles.forEach(([role, stats]) => {
                const tr = document.createElement('tr');
                const permLevel = role.toLowerCase().includes('owner') ? 'danger' : 
                                 role.toLowerCase().includes('contributor') ? 'warning' :
                                 role.toLowerCase().includes('reader') ? 'success' : '';
                
                tr.innerHTML = '<td><strong>' + role + '</strong></td>' +
                    '<td>' + stats.count + '</td>' +
                    '<td>' + stats.principals.size + '</td>' +
                    '<td><span class="badge ' + permLevel + '">' + (permLevel.toUpperCase() || 'CUSTOM') + '</span></td>';
                tbody.appendChild(tr);
            });
        }

        function populateResourceTable() {
            const tbody = document.getElementById('resourceTableBody');
            const total = rbacData.filter(r => r.ResourceType).length;

            if (resourceTypeDistribution && resourceTypeDistribution.length > 0) {
                resourceTypeDistribution.forEach(resource => {
                    const percentage = ((resource.Count / total) * 100).toFixed(2);
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td><strong>' + resource.Name + '</strong></td>' +
                        '<td>' + resource.Count + '</td>' +
                        '<td>' + percentage + '%</td>';
                    tbody.appendChild(tr);
                });
            }
        }

        function populateDataTable() {
            const tbody = document.getElementById('dataTableBody');
            
            rbacData.forEach(row => {
                const tr = document.createElement('tr');
                tr.innerHTML = '<td>' + (row.SubscriptionName || 'N/A') + '</td>' +
                    '<td><strong>' + row.DisplayName + '</strong></td>' +
                    '<td><span class="badge">' + (row.ObjectType || 'Unknown') + '</span></td>' +
                    '<td>' + row.RoleDefinitionName + '</td>' +
                    '<td>' + (row.ResourceType || 'N/A') + '</td>' +
                    '<td style="font-size: 0.8rem; max-width: 300px; overflow: hidden; text-overflow: ellipsis;" title="' + row.Scope + '">' + row.Scope + '</td>';
                tbody.appendChild(tr);
            });

            // Populate filters
            const subFilter = document.getElementById('dataSubFilter');
            const roleFilter = document.getElementById('dataRoleFilter');
            
            uniqueSubscriptions.forEach(sub => {
                const option = document.createElement('option');
                option.value = sub;
                option.textContent = sub;
                subFilter.appendChild(option);
            });

            uniqueRoles.forEach(role => {
                const option = document.createElement('option');
                option.value = role;
                option.textContent = role;
                roleFilter.appendChild(option);
            });
        }

        function populateMatrix() {
            const container = document.getElementById('matrixContainer');
            const principalFilter = document.getElementById('matrixPrincipalFilter');
            const roleFilter = document.getElementById('matrixRoleFilter');

            // Populate filters
            uniquePrincipals.forEach(principal => {
                const option = document.createElement('option');
                option.value = principal;
                option.textContent = principal;
                principalFilter.appendChild(option);
            });

            uniqueRoles.forEach(role => {
                const option = document.createElement('option');
                option.value = role;
                option.textContent = role;
                roleFilter.appendChild(option);
            });

            updateMatrix();
        }

        function updateMatrix() {
            const container = document.getElementById('matrixContainer');
            const selectedPrincipal = document.getElementById('matrixPrincipalFilter').value;
            const selectedRole = document.getElementById('matrixRoleFilter').value;

            const matrix = {};
            let filteredData = rbacData;

            if (selectedPrincipal) {
                filteredData = filteredData.filter(r => r.DisplayName === selectedPrincipal);
            }

            if (selectedRole) {
                filteredData = filteredData.filter(r => r.RoleDefinitionName === selectedRole);
            }

            filteredData.forEach(row => {
                const principal = row.DisplayName;
                const role = row.RoleDefinitionName;

                if (!matrix[principal]) {
                    matrix[principal] = {};
                }

                if (!matrix[principal][role]) {
                    matrix[principal][role] = 0;
                }

                matrix[principal][role]++;
            });

            let html = '<table><thead><tr><th>Principal</th>';
            
            const roles = [...new Set(filteredData.map(r => r.RoleDefinitionName))].slice(0, 20);
            roles.forEach(role => {
                const displayRole = role.length > 30 ? role.substring(0, 30) + '...' : role;
                html += '<th style="writing-mode: vertical-rl; text-align: left;">'+displayRole+'</th>';
            });
            html += '</tr></thead><tbody>';

            const principals = Object.keys(matrix).slice(0, 50);
            principals.forEach(principal => {
                html += '<tr><td><strong>'+principal+'</strong></td>';
                roles.forEach(role => {
                    const count = matrix[principal][role] || 0;
                    const bgColor = count > 0 ? 'rgba(0, 120, 212, '+Math.min(count / 10, 1)+')' : '#f3f2f1';
                    const textColor = count > 3 ? 'white' : '#323130';
                    const displayCount = count > 0 ? count : '';
                    html += '<td style="background: '+bgColor+'; color: '+textColor+'; text-align: center;">'+displayCount+'</td>';
                });
                html += '</tr>';
            });

            html += '</tbody></table>';
            container.innerHTML = html;
        }

        function generateRecommendations() {
            const keyFindings = document.getElementById('keyFindings');
            const recommendedActions = document.getElementById('recommendedActions');
            const securityConcerns = document.getElementById('securityConcerns');

            // Key Findings
            const ownerRoles = rbacData.filter(r => r.RoleDefinitionName.toLowerCase().includes('owner')).length;
            const contributorRoles = rbacData.filter(r => r.RoleDefinitionName.toLowerCase().includes('contributor')).length;
            const readerRoles = rbacData.filter(r => r.RoleDefinitionName.toLowerCase().includes('reader')).length;

            keyFindings.innerHTML = '<ul style="list-style: none; padding: 0;">' +
                '<li style="padding: 0.75rem 0; border-bottom: 1px solid #edebe9;">✅ <strong>Total Assignments:</strong> '+rbacData.length+' across '+uniqueSubscriptions.length+' subscription(s)</li>' +
                '<li style="padding: 0.75rem 0; border-bottom: 1px solid #edebe9;">👥 <strong>Unique Principals:</strong> '+uniquePrincipals.length+'</li>' +
                '<li style="padding: 0.75rem 0; border-bottom: 1px solid #edebe9;">🎭 <strong>Built-in Roles Used:</strong> '+uniqueRoles.length+'</li>' +
                '<li style="padding: 0.75rem 0; border-bottom: 1px solid #edebe9;">⚠️ <strong>Owner Roles:</strong> '+ownerRoles+' (High Privilege)</li>' +
                '<li style="padding: 0.75rem 0; border-bottom: 1px solid #edebe9;">📊 <strong>Contributor Roles:</strong> '+contributorRoles+' (Medium Privilege)</li>' +
                '<li style="padding: 0.75rem 0;">📖 <strong>Reader Roles:</strong> '+readerRoles+' (Low Privilege)</li>' +
                '</ul>';

            // Recommended Actions
            recommendedActions.innerHTML = 
                '<div style="background: #e6f4ff; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem;">' +
                    '<h4 style="color: #0078d4; margin-bottom: 0.5rem;">1. Design Three Custom Role Tiers</h4>' +
                    '<p style="margin: 0;">Create custom roles for Reader, Developer, and Architect groups based on actual resource access patterns identified in this report.</p>' +
                '</div>' +
                '<div style="background: #e6f4ff; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem;">' +
                    '<h4 style="color: #0078d4; margin-bottom: 0.5rem;">2. Consolidate Redundant Assignments</h4>' +
                    '<p style="margin: 0;">Identify principals with multiple similar roles and consolidate them into single custom role assignments.</p>' +
                '</div>' +
                '<div style="background: #e6f4ff; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem;">' +
                    '<h4 style="color: #0078d4; margin-bottom: 0.5rem;">3. Implement Least Privilege</h4>' +
                    '<p style="margin: 0;">Review '+ownerRoles+' Owner role assignments - many can likely be replaced with more restrictive custom roles.</p>' +
                '</div>' +
                '<div style="background: #e6f4ff; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem;">' +
                    '<h4 style="color: #0078d4; margin-bottom: 0.5rem;">4. Start with Resource-Level, Scale to RG</h4>' +
                    '<p style="margin: 0;">Begin by applying custom roles at resource level for testing, then expand to Resource Group level for easier management.</p>' +
                '</div>' +
                '<div style="background: #e6f4ff; padding: 1.5rem; border-radius: 8px;">' +
                    '<h4 style="color: #0078d4; margin-bottom: 0.5rem;">5. Implement Quarterly Reviews</h4>' +
                    '<p style="margin: 0;">Schedule regular RBAC audits using this report to ensure custom roles remain aligned with actual needs.</p>' +
                '</div>';

            // Security Concerns
            let concerns = '';
            
            if (ownerRoles > uniquePrincipals.length * 0.1) {
                const percentage = ((ownerRoles/rbacData.length)*100).toFixed(1);
                concerns += '<div style="background: #fff4e6; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem; border-left: 4px solid #ff8c00;">' +
                    '<h4 style="color: #ff8c00; margin-bottom: 0.5rem;">⚠️ High Number of Owner Assignments</h4>' +
                    '<p style="margin: 0;">'+ownerRoles+' Owner role assignments detected ('+percentage+'% of total). Consider reducing Owner privileges through custom roles.</p>' +
                    '</div>';
            }

            const principalsWithMultipleRoles = topPrincipals.filter(p => p.Count > 10).length;
            if (principalsWithMultipleRoles > 0) {
                concerns += '<div style="background: #fff4e6; padding: 1.5rem; border-radius: 8px; margin-bottom: 1rem; border-left: 4px solid #ff8c00;">' +
                    '<h4 style="color: #ff8c00; margin-bottom: 0.5rem;">🔍 Principals with Multiple Assignments</h4>' +
                    '<p style="margin: 0;">'+principalsWithMultipleRoles+' principal(s) have 10+ role assignments. Review for potential over-provisioning.</p>' +
                    '</div>';
            }

            if (!concerns) {
                concerns = '<div style="background: #e6f4ff; padding: 1.5rem; border-radius: 8px; border-left: 4px solid #0078d4;">' +
                    '<h4 style="color: #0078d4; margin-bottom: 0.5rem;">✅ No Critical Security Concerns Detected</h4>' +
                    '<p style="margin: 0;">Your RBAC configuration appears reasonable. Focus on implementing custom roles for better governance and least privilege.</p>' +
                    '</div>';
            }

            securityConcerns.innerHTML = concerns;
        }

        // Filter functions
        function filterPrincipalTable() {
            const searchValue = document.getElementById('principalSearch').value.toLowerCase();
            const table = document.getElementById('principalTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchValue) ? '' : 'none';
            }
        }

        function filterRoleTable() {
            const searchValue = document.getElementById('roleSearch').value.toLowerCase();
            const table = document.getElementById('roleTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchValue) ? '' : 'none';
            }
        }

        function filterResourceTable() {
            const searchValue = document.getElementById('resourceSearch').value.toLowerCase();
            const table = document.getElementById('resourceTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchValue) ? '' : 'none';
            }
        }

        function filterDataTable() {
            const searchValue = document.getElementById('dataSearch').value.toLowerCase();
            const subFilter = document.getElementById('dataSubFilter').value;
            const roleFilter = document.getElementById('dataRoleFilter').value;
            const table = document.getElementById('dataTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const cells = row.getElementsByTagName('td');
                const subscription = cells[0].textContent;
                const role = cells[3].textContent;
                const text = row.textContent.toLowerCase();

                const matchesSearch = text.includes(searchValue);
                const matchesSub = !subFilter || subscription === subFilter;
                const matchesRole = !roleFilter || role === roleFilter;

                row.style.display = (matchesSearch && matchesSub && matchesRole) ? '' : 'none';
            }
        }

        // Export functions
        function exportPrincipalData() {
            const table = document.getElementById('principalTable');
            const rows = Array.from(table.querySelectorAll('tr'));
            const visibleRows = rows.filter(row => row.style.display !== 'none');
            
            let csv = 'Principal Name,Object Type,Assignment Count,Unique Roles,Subscriptions\n';
            
            visibleRows.slice(1).forEach(row => {
                const cells = row.querySelectorAll('td');
                const data = Array.from(cells).map(cell => {
                    const badge = cell.querySelector('.badge');
                    return badge ? badge.textContent : cell.textContent;
                });
                csv += data.join(',') + '\n';
            });
            
            downloadCSV(csv, 'principal-analysis.csv');
        }

        function exportRoleData() {
            const table = document.getElementById('roleTable');
            const rows = Array.from(table.querySelectorAll('tr'));
            const visibleRows = rows.filter(row => row.style.display !== 'none');
            
            let csv = 'Role Name,Assignment Count,Unique Principals,Permission Level\n';
            
            visibleRows.slice(1).forEach(row => {
                const cells = row.querySelectorAll('td');
                const data = Array.from(cells).map(cell => {
                    const badge = cell.querySelector('.badge');
                    return badge ? badge.textContent : cell.textContent;
                });
                csv += data.join(',') + '\n';
            });
            
            downloadCSV(csv, 'role-analysis.csv');
        }

        function exportAllData() {
            const table = document.getElementById('dataTable');
            const rows = Array.from(table.querySelectorAll('tr'));
            const visibleRows = rows.filter(row => row.style.display !== 'none');
            
            let csv = 'Subscription,Principal,Object Type,Role,Resource Type,Scope\n';
            
            visibleRows.slice(1).forEach(row => {
                const cells = row.querySelectorAll('td');
                const data = Array.from(cells).map(cell => {
                    const badge = cell.querySelector('.badge');
                    const text = badge ? badge.textContent : cell.textContent;
                    return '"' + text.replace(/"/g, '""') + '"';
                });
                csv += data.join(',') + '\n';
            });
            
            downloadCSV(csv, 'rbac-filtered-data.csv');
        }

        function downloadCSV(csv, filename) {
            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', filename);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // Initialize everything on page load
        window.addEventListener('DOMContentLoaded', function() {
            try {
                const loadingStatus = document.getElementById('loadingStatus');
                const loadingOverlay = document.getElementById('loadingOverlay');
                
                console.log('DOM loaded, initializing report...');
                console.log('Total records:', rbacData ? rbacData.length : 'DATA NOT LOADED');
                
                loadingStatus.textContent = 'Loading charts...';
                initCharts();
                console.log('Charts done');
                
                loadingStatus.textContent = 'Loading principal data...';
                populatePrincipalTable();
                console.log('Principal table done');
                
                loadingStatus.textContent = 'Loading role data...';
                populateRoleTable();
                console.log('Role table done');
                
                loadingStatus.textContent = 'Loading resource data...';
                populateResourceTable();
                console.log('Resource table done');
                
                loadingStatus.textContent = 'Loading assignment data...';
                populateDataTable();
                console.log('Data table done');
                
                loadingStatus.textContent = 'Building analysis matrix...';
                populateMatrix();
                console.log('Matrix done');
                
                loadingStatus.textContent = 'Generating recommendations...';
                generateRecommendations();
                console.log('Recommendations done');
                
                // Hide loading overlay
                loadingStatus.textContent = 'Complete!';
                setTimeout(function() {
                    loadingOverlay.style.display = 'none';
                }, 500);
                
                console.log('Report initialization complete!');
            } catch(e) {
                console.error('Initialization error:', e);
                document.getElementById('loadingStatus').textContent = 'Error: ' + e.message;
                document.getElementById('loadingStatus').style.color = '#d13438';
                alert('Error initializing report: ' + e.message + '\n\nCheck browser console (F12) for details.\n\nPress OK to try viewing the report anyway.');
                document.getElementById('loadingOverlay').style.display = 'none';
            }
        });
    </script>
</body>
</html>
"@

    # Write HTML to file
    Write-Host "[5/5] Writing HTML report..." -ForegroundColor Yellow
    try {
        $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "      ✓ Report generated successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to write HTML report: $_"
        return
    }

    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✅ Report Generation Complete!" -ForegroundColor Green
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "📊 Report Location: $OutputPath" -ForegroundColor Cyan
    Write-Host "📈 Total Records Analyzed: $totalRecords" -ForegroundColor Cyan
    Write-Host "🌐 Open the HTML file in your browser to view the interactive report" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "💡 Tip: Share this self-contained HTML file with stakeholders for decision-making" -ForegroundColor Yellow
    Write-Host ""
}
