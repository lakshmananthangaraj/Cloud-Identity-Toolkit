<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 10 September 2026
Modified-On  : 10 September 2026

.SYNOPSIS
    Enterprise Entra Posture Dashboard — aggregates multi-tenant drift assessment outputs
    into a scored, executive-ready HTML dashboard with JSON and CSV outputs.

.DESCRIPTION
    Generate-EntraEnterprisePostureDashboard reads the JSON result files produced by
    Get-EntraMultiTenantConfigurationDriftAssessment and turns them into a single
    enterprise-wide security posture report. Think of it as the "final report card"
    that takes raw assessment data from every tenant and rolls it up into one clear,
    consistent picture for executives, security leads, and operations teams.

    The script is a READ-ONLY reporting and aggregation layer. It does NOT query
    Microsoft Graph, does NOT modify any Entra ID configuration, and does NOT store
    or transmit credentials or secrets. All it needs are the JSON files already on disk.

    What the report covers:
      • Enterprise Posture Score — a single weighted score (0–100) across all tenants
      • Tenant-level scores with classification:
        Excellent / Good / Needs Improvement / Poor / Critical
      • Domain-level scores per tenant:
        Conditional Access · MFA · PIM · External Identity
      • Risk distribution — how many Critical / High / Medium / Low findings exist
      • Baseline compliance — which tenants meet the enterprise security baseline
      • Comparison matrices — side-by-side tenant and domain views
      • Top enterprise risks — ranked by severity, blast radius, and fix priority
      • Remediation queue — findings grouped P0 (fix now) → P3 (plan later)
      • Assessment coverage — shows which tenants and domains have complete data
      • Historical trend — automatically activated when two or more assessment
        snapshots (different points in time) are supplied as input

    The layered processing pipeline is:
      Input Discovery → Schema Validation → Data Normalisation → Scoring
      → Risk Ranking → Remediation Prioritisation → Report Generation

    Output files written per run (all to a timestamped sub-folder under -OutputPath):
      EntraEnterprisePosture_<timestamp>.json
      Generate-EntraEnterprisePostureDashboard_Enterprise_<timestamp>.csv
      Generate-EntraEnterprisePostureDashboard_Tenants_<timestamp>.csv
      Generate-EntraEnterprisePostureDashboard_Domains_<timestamp>.csv
      Generate-EntraEnterprisePostureDashboard_Findings_<timestamp>.csv
      Generate-EntraEnterprisePostureDashboard_Remediation_<timestamp>.csv
      Generate-EntraEnterprisePostureDashboard_<timestamp>.html

.PARAMETER InputPath
    Folder path that contains one or more assessment JSON files produced by
    Get-EntraMultiTenantConfigurationDriftAssessment. The script will automatically
    find and load all compatible JSON files in that folder and skip any files it
    cannot recognise. Cannot be used as the sole source if -InputFiles is also
    supplied — both are merged when used together.

.PARAMETER InputFiles
    One or more specific assessment JSON file paths to process. Use this when you
    want precise control over exactly which files are included — for example, when
    comparing two specific quarterly snapshots. Can be combined with -InputPath;
    the file lists are merged and deduplicated.

.PARAMETER OutputPath
    Folder where all output files (HTML dashboard, JSON, CSV exports) will be
    written. A timestamped sub-folder is created automatically so repeated runs
    never overwrite each other. Defaults to the current working directory.

.PARAMETER BaselineConfigPath
    Optional path to a baseline metadata JSON file. When supplied, the dashboard
    enriches each finding with control descriptions, expected values, and business
    impact annotations sourced from the baseline. Without this, the built-in
    Enterprise Entra Security Baseline v1.0 descriptions are used.

.PARAMETER TenantIds
    Optional list of tenant GUIDs. When supplied, only findings and scores for
    those tenants are included in the report. All other tenants present in the
    input files are ignored. Useful for producing a scoped report for a specific
    business unit or region without re-running the full assessment.

.PARAMETER IncludeDomains
    Restricts the report to the specified security domains. Valid values:
    ConditionalAccess, MFA, PIM, ExternalIdentity. Defaults to all four.

.PARAMETER ExcludeDomains
    Excludes specific security domains from scoring and output. Valid values:
    same as IncludeDomains. Cannot be combined meaningfully with IncludeDomains
    for the same domain; IncludeDomains wins when both are supplied.

.PARAMETER OpenDashboard
    If specified, the HTML dashboard is opened in the default browser automatically
    after the report is generated.

.PARAMETER PassThru
    If specified, returns the full enterprise posture object to the pipeline in
    addition to writing the output files. Useful for chaining with other scripts
    or storing the result in a variable for further processing.

.INPUTS
    JSON assessment files produced by Get-EntraMultiTenantConfigurationDriftAssessment.
    No pipeline input is accepted directly.

.OUTPUTS
    System.Management.Automation.PSCustomObject
    Only when -PassThru is specified. The complete enterprise posture model.

.EXAMPLE
    # EVERYDAY USE — Point at a folder, get a dashboard
    # This is the most common way to run the script.
    # It finds all assessment files in the folder, builds the report,
    # and opens the HTML dashboard in your browser automatically.
    Generate-EntraEnterprisePostureDashboard `
        -InputPath    "C:\EntraAssessments" `
        -OpenDashboard

.EXAMPLE
    # TREND REPORTING — Compare two assessments taken at different times
    # Supply two (or more) JSON files explicitly to enable the historical
    # trend view in the dashboard. The script detects different assessment
    # timestamps automatically and plots how your posture changed over time.
    Generate-EntraEnterprisePostureDashboard `
        -InputFiles @(
            "C:\Assessments\Assessment_2026-Q3.json",
            "C:\Assessments\Assessment_2026-Q4.json"
        ) `
        -OutputPath    "C:\Reports" `
        -OpenDashboard

.EXAMPLE
    # SCOPED REPORT — One tenant, two domains, result captured for further use
    # Use -TenantIds to focus on a single tenant (e.g. a subsidiary under review)
    # and -IncludeDomains to limit the report to MFA and PIM only.
    # -PassThru sends the structured result object back to the pipeline so you
    # can inspect it in the console, export it, or feed it into another script.
    Generate-EntraEnterprisePostureDashboard `
        -InputPath      "C:\EntraAssessments" `
        -TenantIds      @("aaaaaaaa-0000-1111-2222-bbbbbbbbbbbb") `
        -IncludeDomains @("MFA", "PIM") `
        -PassThru |
        Select-Object -ExpandProperty Enterprise

.EXAMPLE
    # ENRICHED REPORT — Add business context from a custom baseline file
    # When a baseline config file is supplied, every finding in the dashboard
    # gains a plain-English description of the control, its expected value,
    # and the business risk if it is not met. Useful for presenting results
    # to audiences who are not Entra ID specialists.
    Generate-EntraEnterprisePostureDashboard `
        -InputPath          "C:\EntraAssessments" `
        -BaselineConfigPath "C:\Config\EntraBaseline.json" `
        -OutputPath         "C:\Reports" `
        -OpenDashboard

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (10-Sep-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. PowerShell 5.1 or later. No external modules are required; the script uses
       only built-in cmdlets (ConvertFrom-Json, Export-Csv, Invoke-Item, etc.).

    2. One or more assessment JSON files produced by
       Get-EntraMultiTenantConfigurationDriftAssessment. These are the only input
       this script consumes. If no compatible files are found, the script exits
       with a clear error message before generating any output.

    3. No Microsoft Graph connectivity is required. The script is fully offline
       — it reads files already on disk and generates reports from them.

    4. No credentials, tokens, or secrets are needed. This script never
       authenticates to any service; all authentication happens in
       Get-EntraMultiTenantConfigurationDriftAssessment before this script runs.

    5. Write permission to -OutputPath. The script creates a timestamped
       sub-folder and writes all output files there. Ensure the account running
       the script has at least write access to the target directory.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Historical trend comparison only activates when input files contain different
      AssessmentIds and compatible SchemaVersions. The script will not fabricate
      trend data if timestamps are identical or schema versions conflict.
    - The enterprise posture score is suppressed and flagged as Incomplete when
      assessment coverage falls below 50% of tenants. This prevents an incomplete
      data set from being misread as a clean security posture by executives.
    - Domain scores for tenants where a collector failed due to permission denial
      are excluded from domain averages rather than counted as a zero/failing score,
      so a missing permission does not artificially lower the overall score.
    - Graph relationship (Nodes/Edges) structures in the JSON output are at
      summary level in V1. Object-level graph traversal (User → Group → Role →
      App → Service Principal) is a planned V2 capability.
    - Tenant population weighting uses equal weights in V1 unless a TenantWeight
      property is present in the input assessment's Tenants array.
    - Very large assessment files (100k+ findings) may increase dashboard generation
      time. No data is truncated; all findings are written to CSV regardless of size.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW:
    ─────────────────────────────────────────────────────────────────────────────
    1.  Discover and validate input JSON files (schema version check)
    2.  Apply TenantIds / IncludeDomains / ExcludeDomains filters
    3.  Normalise all tenant and domain result objects into a unified model
    4.  Resolve baseline metadata (supplied file or built-in default)
    5.  Calculate per-tenant domain scores and posture classifications
    6.  Calculate enterprise posture score (weighted aggregate)
    7.  Rank findings by severity, blast radius, and remediation priority
    8.  Build remediation queue (P0 → P3)
    9.  Detect multiple assessment timestamps → activate trend view if found
    10. Export: Enterprise CSV, Tenants CSV, Domains CSV, Findings CSV,
        Remediation CSV, assessment JSON, dashboard HTML
    11. Optionally open dashboard in browser / return result object via PassThru

.LINK
    https://learn.microsoft.com/en-us/entra/identity/monitoring-health/overview-monitoring-health
.LINK
    https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview
.LINK
    https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure

#>



#region ── Metadata ───────────────────────────────────────────────────────────

$Script:DashboardVersion = '1.0'
$Script:SchemaVersion = '1.0'
$Script:MinAssessmentSchema = '1.0'

#endregion

#region ── Public Function ────────────────────────────────────────────────────

Function Generate-EntraEnterprisePostureDashboard {
    [CmdletBinding()]
    param (
        [string]   $InputPath,
        [string[]] $InputFiles,
        [string]   $OutputPath = '.',
        [string]   $BaselineConfigPath,
        [string[]] $TenantIds,
        [string[]] $IncludeDomains,
        [string[]] $ExcludeDomains,
        [switch]   $OpenDashboard,
        [switch]   $PassThru
    )

    #region ── Initialise ─────────────────────────────────────────────────────

    $ctx = Initialize-AssessmentContext -OutputPath $OutputPath -TenantIds $TenantIds `
        -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Dashboard generation started' `
        -Detail "DashboardVersion=$Script:DashboardVersion | OutputPath=$($ctx.OutputPath)"

    #endregion

    #region ── Input Resolution ───────────────────────────────────────────────

    $resolvedFiles = Resolve-AssessmentInput -InputPath $InputPath -InputFiles $InputFiles -Context $ctx

    if ($resolvedFiles.Count -eq 0) {
        Write-AssessmentLog -Context $ctx -Level 'ERROR' -Message 'No valid assessment files found. Aborting.'
        Write-Error 'No compatible assessment JSON files were discovered. Check -InputPath or -InputFiles.'
        return
    }

    #endregion

    #region ── Data Loading & Normalization ───────────────────────────────────

    $rawAssessments = @()
    foreach ($file in $resolvedFiles) {
        Write-AssessmentLog -Context $ctx -Level 'INFO' -Message "Loading assessment file" -Detail $file
        $data = Read-EntraAssessmentData -FilePath $file -Context $ctx
        if ($null -ne $data) {
            $rawAssessments += $data
        }
    }

    if ($rawAssessments.Count -eq 0) {
        Write-AssessmentLog -Context $ctx -Level 'ERROR' -Message 'All assessment files failed validation. Aborting.'
        Write-Error 'No assessment files passed schema validation. Review log for per-file rejection reasons.'
        return
    }

    $normalized = Normalize-EntraAssessmentData -Assessments $rawAssessments -Context $ctx

    #endregion

    #region ── Optional Baseline Enrichment ──────────────────────────────────

    $baselineConfig = $null
    if (-not [string]::IsNullOrWhiteSpace($BaselineConfigPath)) {
        if (Test-Path -Path $BaselineConfigPath -PathType Leaf) {
            try {
                $baselineConfig = Get-Content -Path $BaselineConfigPath -Raw -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
                Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Baseline config loaded' `
                    -Detail $BaselineConfigPath
            }
            catch {
                Write-AssessmentLog -Context $ctx -Level 'WARN' `
                    -Message 'Baseline config could not be parsed — proceeding without enrichment' `
                    -Detail $_.Exception.Message
                Write-Warning "Baseline config at '$BaselineConfigPath' could not be parsed: $($_.Exception.Message)"
            }
        }
        else {
            Write-AssessmentLog -Context $ctx -Level 'WARN' -Message 'Baseline config file not found' `
                -Detail $BaselineConfigPath
            Write-Warning "Baseline config file not found: $BaselineConfigPath"
        }
    }

    #endregion

    #region ── Scoring ────────────────────────────────────────────────────────

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Scoring — tenant posture'
    $tenantScores = Get-TenantPostureScore   -Normalized $normalized -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Scoring — domain posture'
    $domainScores = Get-DomainPostureScore   -Normalized $normalized -TenantScores $tenantScores -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Scoring — enterprise posture'
    $enterpriseScore = Get-EnterprisePostureScore -TenantScores $tenantScores -DomainScores $domainScores -Context $ctx

    #endregion

    #region ── Risk & Compliance Aggregation ─────────────────────────────────

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Aggregating risk summary'
    $riskSummary = Get-RiskSummary           -Normalized $normalized -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Aggregating baseline compliance'
    $baselineCompliance = Get-BaselineComplianceSummary -Normalized $normalized -BaselineConfig $baselineConfig -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Computing assessment coverage'
    $coverage = Get-AssessmentCoverage    -Normalized $normalized -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Identifying top risks'
    $topRisks = Get-TopRiskFindings       -Normalized $normalized -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Building tenant comparison'
    $tenantComparison = Get-TenantComparison      -TenantScores $tenantScores -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Building domain comparison'
    $domainComparison = Get-DomainComparison      -DomainScores $domainScores -TenantScores $tenantScores -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Building remediation priorities'
    $remediationPriority = Get-RemediationPriority  -TopRisks $topRisks -Normalized $normalized -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Checking for historical comparison'
    $historicalComparison = $null
    if ($normalized.Assessments.Count -gt 1) {
        $historicalComparison = Get-HistoricalComparison -Normalized $normalized -Context $ctx
    }

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Computing data quality metrics'
    $dataQuality = Get-DataQualitySummary -Context $ctx -Normalized $normalized

    #endregion

    #region ── Output Generation ──────────────────────────────────────────────

    $ts = (Get-Date).ToString('yyyyMMdd_HHmmss')

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Generating JSON output'
    $jsonPath = New-EnterprisePostureJson `
        -OutputPath $ctx.OutputPath -Timestamp $ts `
        -EnterpriseScore $enterpriseScore -TenantScores $tenantScores `
        -DomainScores $domainScores -RiskSummary $riskSummary `
        -BaselineCompliance $baselineCompliance -Coverage $coverage `
        -TopRisks $topRisks -Remediation $remediationPriority `
        -Historical $historicalComparison -DataQuality $dataQuality `
        -Normalized $normalized -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Generating CSV outputs'
    New-EnterprisePostureCsv `
        -OutputPath $ctx.OutputPath -Timestamp $ts `
        -EnterpriseScore $enterpriseScore -TenantScores $tenantScores `
        -DomainScores $domainScores -Normalized $normalized `
        -Remediation $remediationPriority -Context $ctx

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Generating HTML dashboard'
    $htmlPath = New-EnterprisePostureHtml `
        -OutputPath $ctx.OutputPath -Timestamp $ts `
        -EnterpriseScore $enterpriseScore -TenantScores $tenantScores `
        -DomainScores $domainScores -RiskSummary $riskSummary `
        -BaselineCompliance $baselineCompliance -Coverage $coverage `
        -TenantComparison $tenantComparison -DomainComparison $domainComparison `
        -TopRisks $topRisks -Remediation $remediationPriority `
        -Historical $historicalComparison -DataQuality $dataQuality `
        -Normalized $normalized -Context $ctx

    #endregion

    #region ── Console Summary ────────────────────────────────────────────────

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║    Enterprise Entra Posture Dashboard v1.0  —  Complete      ║' -ForegroundColor Cyan
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "  🏢  Enterprise Posture Score : $($enterpriseScore.Score) / 100  [$($enterpriseScore.Classification)]" `
        -ForegroundColor $(switch ($enterpriseScore.Classification) {
            'Excellent' { 'Green' }
            'Good' { 'Green' }
            'Needs Improvement' { 'Yellow' }
            'Poor' { 'Yellow' }
            default { 'Red' }
        })
    Write-Host "  🏢  Tenants Assessed         : $($coverage.SuccessfullyAssessed) / $($coverage.TotalTenants)" -ForegroundColor White
    Write-Host "  🔴  Critical Findings        : $($riskSummary.Critical)"  -ForegroundColor $(if ($riskSummary.Critical -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  🟠  High Findings            : $($riskSummary.High)"      -ForegroundColor $(if ($riskSummary.High -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  📊  Assessment Coverage      : $($coverage.CoveragePercentage)%" -ForegroundColor White
    Write-Host ''
    Write-Host "  📄  HTML Dashboard           : $htmlPath"   -ForegroundColor White
    Write-Host "  📋  JSON Output              : $jsonPath"   -ForegroundColor White
    Write-Host "  📁  Output Directory         : $($ctx.OutputPath)" -ForegroundColor White
    Write-Host ''

    Write-AssessmentLog -Context $ctx -Level 'INFO' -Message 'Dashboard generation completed' `
        -Detail "Score=$($enterpriseScore.Score) | Coverage=$($coverage.CoveragePercentage)%"

    #endregion

    #region ── Open & PassThru ────────────────────────────────────────────────

    if ($OpenDashboard) {
        Write-Host '  🌐  Opening dashboard in browser…' -ForegroundColor Green
        Start-Process $htmlPath
    }

    if ($PassThru) {
        [PSCustomObject]@{
            Enterprise         = $enterpriseScore
            Tenants            = $tenantScores
            Domains            = $domainScores
            RiskSummary        = $riskSummary
            BaselineCompliance = $baselineCompliance
            Coverage           = $coverage
            TopRisks           = $topRisks
            Remediation        = $remediationPriority
            TenantComparison   = $tenantComparison
            DomainComparison   = $domainComparison
            Historical         = $historicalComparison
            DataQuality        = $dataQuality
            OutputPaths        = [PSCustomObject]@{
                Html      = $htmlPath
                Json      = $jsonPath
                OutputDir = $ctx.OutputPath
            }
            GeneratedAt        = (Get-Date).ToString('o')
            DashboardVersion   = $Script:DashboardVersion
        }
    }

    #endregion
}

#endregion

#region ── Configuration ──────────────────────────────────────────────────────

$Script:SeverityWeights = @{
    Critical      = 20
    High          = 10
    Medium        = 5
    Low           = 2
    Informational = 0
    Info          = 0
    Unknown       = 2
}

$Script:PostureThresholds = @{
    Excellent        = 90
    Good             = 75
    NeedsImprovement = 60
    Poor             = 40
}

$Script:RemediationPriority = @{
    P0 = 'Immediate'
    P1 = 'High'
    P2 = 'Planned'
    P3 = 'Monitor'
}

$Script:SupportedDomains = @(
    'ConditionalAccess',
    'MFA',
    'PIM',
    'ExternalIdentity'
)

$Script:SeverityOrder = @{
    Critical      = 0
    High          = 1
    Medium        = 2
    Low           = 3
    Informational = 4
    Info          = 4
    Unknown       = 5
}

# Minimum coverage percentage below which enterprise score is flagged as unreliable
$Script:MinReliableCoverage = 50

#endregion

#region ── Input Validation ───────────────────────────────────────────────────

Function Test-EntraAssessmentSchema {
    param (
        [Parameter(Mandatory)] [object] $Data,
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [object] $Context
    )

    $required = @('SchemaVersion', 'AssessmentId', 'GeneratedAt', 'Tenants', 'Controls', 'Findings')
    $missing = @()

    foreach ($field in $required) {
        if ($null -eq $Data.$field) {
            $missing += $field
        }
    }

    if ($missing.Count -gt 0) {
        Write-AssessmentLog -Context $Context -Level 'WARN' `
            -Message "Schema validation failed — missing fields: $($missing -join ', ')" `
            -Detail $FilePath
        $Context.DataQuality.RejectedFiles += $FilePath
        return $false
    }

    # Version check — warn but do not reject on minor version differences
    $schemaVer = [string]$Data.SchemaVersion
    if ([string]::IsNullOrWhiteSpace($schemaVer)) {
        Write-AssessmentLog -Context $Context -Level 'WARN' `
            -Message 'Assessment has no SchemaVersion — treating as compatible with caution' `
            -Detail $FilePath
    }

    $Context.DataQuality.ValidFiles++
    Write-AssessmentLog -Context $Context -Level 'INFO' `
        -Message "Schema validation passed [AssessmentId=$($Data.AssessmentId)]" `
        -Detail $FilePath
    return $true
}

#endregion

#region ── Input Discovery ────────────────────────────────────────────────────

Function Initialize-AssessmentContext {
    param (
        [string]   $OutputPath,
        [string[]] $TenantIds,
        [string[]] $IncludeDomains,
        [string[]] $ExcludeDomains
    )

    # Resolve and validate output path
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = '.' }
    $resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

    if (-not (Test-Path -Path $resolvedOutput -PathType Container)) {
        try {
            New-Item -Path $resolvedOutput -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "Cannot create output directory '$resolvedOutput': $($_.Exception.Message)"
            throw
        }
    }

    # Normalise domain filters
    $normInclude = @()
    $normExclude = @()
    if ($IncludeDomains) { $normInclude = $IncludeDomains | ForEach-Object { $_.Trim() } }
    if ($ExcludeDomains) { $normExclude = $ExcludeDomains | ForEach-Object { $_.Trim() } }

    [PSCustomObject]@{
        OutputPath     = $resolvedOutput
        TenantFilter   = if ($TenantIds) { $TenantIds | ForEach-Object { $_.ToLower().Trim() } } else { @() }
        IncludeDomains = $normInclude
        ExcludeDomains = $normExclude
        LogEntries     = [System.Collections.Generic.List[object]]::new()
        DataQuality    = [PSCustomObject]@{
            InputFiles           = 0
            ValidFiles           = 0
            RejectedFiles        = [System.Collections.Generic.List[string]]::new()
            DuplicateAssessments = 0
            MissingTenantInfo    = 0
            MissingControlInfo   = 0
            IncompleteFindings   = 0
            AssessmentVersions   = [System.Collections.Generic.List[string]]::new()
            BaselineVersions     = [System.Collections.Generic.List[string]]::new()
        }
    }
}

Function Resolve-AssessmentInput {
    param (
        [string]   $InputPath,
        [string[]] $InputFiles,
        [Parameter(Mandatory)] [object] $Context
    )

    $candidates = [System.Collections.Generic.List[string]]::new()

    # Collect from directory
    if (-not [string]::IsNullOrWhiteSpace($InputPath)) {
        Write-AssessmentLog -Context $Context -Level 'INFO' `
            -Message 'Input discovery started' -Detail $InputPath

        if (-not (Test-Path -Path $InputPath -PathType Container)) {
            Write-Warning "InputPath '$InputPath' does not exist or is not a directory."
            Write-AssessmentLog -Context $Context -Level 'WARN' `
                -Message 'InputPath not found' -Detail $InputPath
        }
        else {
            $jsonFiles = Get-ChildItem -Path $InputPath -Filter '*.json' -File -ErrorAction SilentlyContinue
            foreach ($f in $jsonFiles) {
                $candidates.Add($f.FullName)
            }
            Write-AssessmentLog -Context $Context -Level 'INFO' `
                -Message "Discovered $($jsonFiles.Count) JSON file(s) in InputPath"
        }
    }

    # Collect explicit files
    if ($InputFiles -and $InputFiles.Count -gt 0) {
        foreach ($f in $InputFiles) {
            if ([string]::IsNullOrWhiteSpace($f)) { continue }
            $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($f)
            if (-not (Test-Path -Path $resolved -PathType Leaf)) {
                Write-Warning "InputFile '$f' not found — skipping."
                Write-AssessmentLog -Context $Context -Level 'WARN' `
                    -Message 'InputFile not found' -Detail $f
                continue
            }
            if ($candidates -notcontains $resolved) {
                $candidates.Add($resolved)
            }
        }
    }

    $Context.DataQuality.InputFiles = $candidates.Count

    # Quick-parse each candidate to confirm it looks like an assessment JSON
    $valid = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $candidates) {
        try {
            $peek = Get-Content -Path $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $peek.AssessmentId -and $null -eq $peek.Findings) {
                Write-AssessmentLog -Context $Context -Level 'WARN' `
                    -Message 'File rejected — does not appear to be an assessment JSON' `
                    -Detail $path
                Write-Warning "Skipping '$path' — not a recognised assessment JSON format."
                $Context.DataQuality.RejectedFiles.Add($path)
                continue
            }
            $valid.Add($path)
            Write-AssessmentLog -Context $Context -Level 'INFO' `
                -Message 'File accepted for processing' -Detail $path
        }
        catch {
            Write-AssessmentLog -Context $Context -Level 'WARN' `
                -Message "File rejected — JSON parse error: $($_.Exception.Message)" `
                -Detail $path
            Write-Warning "Skipping '$path' — JSON parse error: $($_.Exception.Message)"
            $Context.DataQuality.RejectedFiles.Add($path)
        }
    }

    Write-AssessmentLog -Context $Context -Level 'INFO' `
        -Message "Input resolution complete — $($valid.Count) valid / $($Context.DataQuality.RejectedFiles.Count) rejected"

    return $valid
}

Function Read-EntraAssessmentData {
    param (
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [object] $Context
    )

    try {
        $raw = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        $data = $raw | ConvertFrom-Json -ErrorAction Stop

        if (-not (Test-EntraAssessmentSchema -Data $data -FilePath $FilePath -Context $Context)) {
            return $null
        }

        # Track versions for data quality
        $av = [string]$data.AssessmentVersion
        $bv = [string]$data.BaselineVersion
        if (-not [string]::IsNullOrWhiteSpace($av) -and
            $Context.DataQuality.AssessmentVersions -notcontains $av) {
            $Context.DataQuality.AssessmentVersions.Add($av)
        }
        if (-not [string]::IsNullOrWhiteSpace($bv) -and
            $Context.DataQuality.BaselineVersions -notcontains $bv) {
            $Context.DataQuality.BaselineVersions.Add($bv)
        }

        # Attach source file path for traceability
        $data | Add-Member -NotePropertyName '_SourceFile' -NotePropertyValue $FilePath -Force

        return $data
    }
    catch {
        Write-AssessmentLog -Context $Context -Level 'ERROR' `
            -Message "Failed to read assessment file: $($_.Exception.Message)" `
            -Detail $FilePath
        Write-Warning "Could not read '$FilePath': $($_.Exception.Message)"
        return $null
    }
}

#endregion

#region ── Data Normalization ─────────────────────────────────────────────────

Function Normalize-SeverityValue {
    param([string]$Severity)
    switch -Regex ($Severity.Trim()) {
        '^[Cc]ritical' { return 'Critical' }
        '^[Hh]igh' { return 'High' }
        '^[Mm]edium' { return 'Medium' }
        '^[Ll]ow' { return 'Low' }
        '^[Ii]nfo' { return 'Informational' }
        '^[Ii]nformational' { return 'Informational' }
        default { return 'Unknown' }
    }
}

Function Normalize-DomainValue {
    param([string]$Domain)
    switch -Regex ($Domain.Trim()) {
        'ConditionalAccess|CA|Conditional.Access' { return 'ConditionalAccess' }
        '^MFA|Multi.Factor' { return 'MFA' }
        '^PIM|Privileged.Identity' { return 'PIM' }
        'External.Identity|ExternalId|GuestAccess|Guest' { return 'ExternalIdentity' }
        default { return $Domain.Trim() }
    }
}

Function Normalize-TenantId {
    param([string]$TenantId)
    if ([string]::IsNullOrWhiteSpace($TenantId)) { return 'unknown' }
    return $TenantId.Trim().ToLower()
}

Function Normalize-EntraAssessmentData {
    param (
        [Parameter(Mandatory)] [object[]] $Assessments,
        [Parameter(Mandatory)] [object]   $Context
    )

    Write-AssessmentLog -Context $Context -Level 'INFO' `
        -Message "Normalizing $($Assessments.Count) assessment(s)"

    $seenAssessmentIds = [System.Collections.Generic.HashSet[string]]::new()
    $allFindings = [System.Collections.Generic.List[object]]::new()
    $allControls = [System.Collections.Generic.List[object]]::new()
    $allTenants = [System.Collections.Generic.List[object]]::new()
    $processedAssess = [System.Collections.Generic.List[object]]::new()

    foreach ($assess in $Assessments) {
        $assessId = [string]$assess.AssessmentId

        # Duplicate detection
        if ($seenAssessmentIds.Contains($assessId)) {
            Write-AssessmentLog -Context $Context -Level 'WARN' `
                -Message "Duplicate AssessmentId detected — skipping" -Detail $assessId
            $Context.DataQuality.DuplicateAssessments++
            continue
        }
        [void]$seenAssessmentIds.Add($assessId)
        $processedAssess.Add($assess)

        # Normalize tenants
        $tenants = @($assess.Tenants)
        foreach ($t in $tenants) {
            $tId = Normalize-TenantId -TenantId ([string]$t.TenantId)
            if ($tId -eq 'unknown') { $Context.DataQuality.MissingTenantInfo++ }

            # Apply tenant filter
            if ($Context.TenantFilter.Count -gt 0 -and
                $Context.TenantFilter -notcontains $tId) { continue }

            $normalizedTenant = [PSCustomObject]@{
                TenantId             = $tId
                TenantName           = if ([string]::IsNullOrWhiteSpace($t.TenantName)) { $tId } else { [string]$t.TenantName }
                BusinessUnit         = if ([string]::IsNullOrWhiteSpace($t.BusinessUnit)) { 'Unknown' } else { [string]$t.BusinessUnit }
                AssessmentId         = $assessId
                AssessmentStatus     = if ([string]::IsNullOrWhiteSpace($t.AssessmentStatus)) { 'Unknown' } else { [string]$t.AssessmentStatus }
                PermissionStatus     = if ($null -eq $t.PermissionStatus) { 'Unknown' } else { [string]$t.PermissionStatus }
                PostureScore         = if ($null -ne $t.PostureScore) { [int]$t.PostureScore }      else { $null }
                CompliancePercentage = if ($null -ne $t.CompliancePercentage) { [double]$t.CompliancePercentage } else { $null }
                TenantWeight         = if ($null -ne $t.TenantWeight) { [double]$t.TenantWeight }   else { 1.0 }
                CollectorErrors      = if ($null -ne $t.CollectorErrors) { $t.CollectorErrors }        else { @() }
                LicenseIssues        = if ($null -ne $t.LicenseIssues) { $t.LicenseIssues }          else { @() }
                SourceAssessmentId   = $assessId
                GeneratedAt          = [string]$assess.GeneratedAt
                SourceFile           = [string]$assess._SourceFile
            }
            $allTenants.Add($normalizedTenant)
        }

        # Normalize controls
        $controls = @($assess.Controls)
        foreach ($c in $controls) {
            if ($null -eq $c) { $Context.DataQuality.MissingControlInfo++; continue }
            $cId = [string]$c.ControlId
            $domain = Normalize-DomainValue -Domain ([string]$c.Domain)

            # Apply domain filters
            if ($Context.IncludeDomains.Count -gt 0 -and $Context.IncludeDomains -notcontains $domain) { continue }
            if ($Context.ExcludeDomains.Count -gt 0 -and $Context.ExcludeDomains -contains $domain) { continue }

            $allControls.Add([PSCustomObject]@{
                    ControlId     = $cId
                    Domain        = $domain
                    Title         = if ([string]::IsNullOrWhiteSpace($c.Title)) { $cId }    else { [string]$c.Title }
                    Description   = if ([string]::IsNullOrWhiteSpace($c.Description)) { '' }      else { [string]$c.Description }
                    Severity      = Normalize-SeverityValue -Severity ([string]$c.Severity)
                    ExpectedValue = if ($null -ne $c.ExpectedValue) { [string]$c.ExpectedValue } else { '' }
                    AssessmentId  = $assessId
                })
        }

        # Normalize findings
        $findings = @($assess.Findings)
        foreach ($f in $findings) {
            if ($null -eq $f) { $Context.DataQuality.IncompleteFindings++; continue }

            $tId = Normalize-TenantId -TenantId ([string]$f.TenantId)
            $domain = Normalize-DomainValue -Domain ([string]$f.Domain)
            $sev = Normalize-SeverityValue -Severity ([string]$f.Severity)
            $fId = [string]$f.FindingId

            # Apply filters
            if ($Context.TenantFilter.Count -gt 0 -and
                $Context.TenantFilter -notcontains $tId) { continue }
            if ($Context.IncludeDomains.Count -gt 0 -and $Context.IncludeDomains -notcontains $domain) { continue }
            if ($Context.ExcludeDomains.Count -gt 0 -and $Context.ExcludeDomains -contains $domain) { continue }

            if ([string]::IsNullOrWhiteSpace($fId)) { $fId = "$tId-$domain-$(New-Guid)" }

            $nf = [PSCustomObject]@{
                UniqueKey         = "$tId|$fId|$assessId"
                FindingId         = $fId
                TenantId          = $tId
                TenantName        = if ([string]::IsNullOrWhiteSpace($f.TenantName)) { $tId } else { [string]$f.TenantName }
                Domain            = $domain
                ControlId         = [string]$f.ControlId
                Severity          = $sev
                SeverityOrder     = if ($Script:SeverityOrder.ContainsKey($sev)) { $Script:SeverityOrder[$sev] } else { 5 }
                Title             = if ([string]::IsNullOrWhiteSpace($f.Title)) { $fId }  else { [string]$f.Title }
                Description       = if ([string]::IsNullOrWhiteSpace($f.Description)) { '' } else { [string]$f.Description }
                Recommendation    = if ([string]::IsNullOrWhiteSpace($f.Recommendation)) { '' } else { [string]$f.Recommendation }
                BusinessImpact    = if ([string]::IsNullOrWhiteSpace($f.BusinessImpact)) { 'Not specified' } else { [string]$f.BusinessImpact }
                CurrentValue      = if ($null -ne $f.CurrentValue) { [string]$f.CurrentValue }  else { '' }
                ExpectedValue     = if ($null -ne $f.ExpectedValue) { [string]$f.ExpectedValue } else { '' }
                DriftType         = if ([string]::IsNullOrWhiteSpace($f.DriftType)) { 'Drift' } else { [string]$f.DriftType }
                Status            = if ([string]::IsNullOrWhiteSpace($f.Status)) { 'Open' }  else { [string]$f.Status }
                RemediationEffort = if ([string]::IsNullOrWhiteSpace($f.RemediationEffort)) { 'Medium' } else { [string]$f.RemediationEffort }
                AssessmentId      = $assessId
                GeneratedAt       = [string]$assess.GeneratedAt
                SourceFile        = [string]$assess._SourceFile
            }
            $allFindings.Add($nf)
        }
    }

    Write-AssessmentLog -Context $Context -Level 'INFO' `
        -Message "Normalization complete — Tenants=$($allTenants.Count) | Controls=$($allControls.Count) | Findings=$($allFindings.Count)"

    return [PSCustomObject]@{
        Assessments = $processedAssess
        Tenants     = $allTenants
        Controls    = $allControls
        Findings    = $allFindings
    }
}

#endregion

#region ── Scoring ────────────────────────────────────────────────────────────

Function Invoke-ScoreCalculation {
    param (
        [Parameter(Mandatory)] [object[]] $Findings
    )
    # Start at 100, apply deductions per finding
    $score = 100
    foreach ($f in $Findings) {
        $sev = $f.Severity
        if ($Script:SeverityWeights.ContainsKey($sev)) {
            $score -= $Script:SeverityWeights[$sev]
        }
        else {
            $score -= $Script:SeverityWeights['Unknown']
        }
    }
    return [Math]::Max(0, $score)
}

Function Get-PostureClassification {
    param([int]$Score)
    if ($Score -ge $Script:PostureThresholds.Excellent) { return 'Excellent' }
    if ($Score -ge $Script:PostureThresholds.Good) { return 'Good' }
    if ($Score -ge $Script:PostureThresholds.NeedsImprovement) { return 'Needs Improvement' }
    if ($Score -ge $Script:PostureThresholds.Poor) { return 'Poor' }
    return 'Critical'
}

Function Get-TenantPostureScore {
    param (
        [Parameter(Mandatory)] [object] $Normalized,
        [Parameter(Mandatory)] [object] $Context
    )

    $result = [System.Collections.Generic.List[object]]::new()

    # Group findings by tenant
    $byTenant = $Normalized.Findings | Group-Object TenantId

    # Also include tenants that were assessed but had zero findings
    $assessedTenantIds = @($Normalized.Tenants | Select-Object -ExpandProperty TenantId -Unique)
    $findingTenantIds = @($byTenant | Select-Object -ExpandProperty Name)
    $zeroFindingIds = $assessedTenantIds | Where-Object { $findingTenantIds -notcontains $_ }

    foreach ($group in $byTenant) {
        $tId = $group.Name
        $findings = @($group.Group)
        $tenant = $Normalized.Tenants | Where-Object { $_.TenantId -eq $tId } | Select-Object -First 1

        $tName = if ($tenant) { $tenant.TenantName } else { $tId }
        $bu = if ($tenant) { $tenant.BusinessUnit } else { 'Unknown' }
        $weight = if ($tenant -and $tenant.TenantWeight) { [double]$tenant.TenantWeight } else { 1.0 }
        $status = if ($tenant) { $tenant.AssessmentStatus } else { 'Unknown' }

        # Use pre-computed score from assessment if available; otherwise recalculate
        $score = if ($tenant -and $null -ne $tenant.PostureScore) `
        { [int]$tenant.PostureScore } `
            else `
        { Invoke-ScoreCalculation -Findings $findings }

        $crit = ($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $high = ($findings | Where-Object { $_.Severity -eq 'High' }).Count
        $med = ($findings | Where-Object { $_.Severity -eq 'Medium' }).Count
        $low = ($findings | Where-Object { $_.Severity -eq 'Low' }).Count
        $info = ($findings | Where-Object { $_.Severity -eq 'Informational' }).Count

        # Compliance from tenant data or estimate from findings vs controls
        $tenantControls = @($Normalized.Controls | Where-Object { $true })
        $totalCtrl = $tenantControls.Count
        $driftedCtrl = @($findings | Select-Object -ExpandProperty ControlId -Unique).Count
        $compliantCtrl = [Math]::Max(0, $totalCtrl - $driftedCtrl)
        $compliancePct = if ($tenant -and $null -ne $tenant.CompliancePercentage) `
        { [Math]::Round([double]$tenant.CompliancePercentage, 1) } `
            elseif ($totalCtrl -gt 0) `
        { [Math]::Round(($compliantCtrl / $totalCtrl) * 100, 1) } `
            else { 0.0 }

        $result.Add([PSCustomObject]@{
                TenantId              = $tId
                TenantName            = $tName
                BusinessUnit          = $bu
                PostureScore          = $score
                Classification        = Get-PostureClassification -Score $score
                CompliancePercentage  = $compliancePct
                TotalControls         = $totalCtrl
                CompliantControls     = $compliantCtrl
                DriftedControls       = $driftedCtrl
                CriticalFindings      = $crit
                HighFindings          = $high
                MediumFindings        = $med
                LowFindings           = $low
                InformationalFindings = $info
                TotalFindings         = $findings.Count
                AssessmentStatus      = $status
                TenantWeight          = $weight
                CollectorErrors       = if ($tenant) { @($tenant.CollectorErrors) } else { @() }
                Findings              = $findings
            })
    }

    # Add zero-finding tenants with maximum score
    foreach ($tId in $zeroFindingIds) {
        $tenant = $Normalized.Tenants | Where-Object { $_.TenantId -eq $tId } | Select-Object -First 1
        if (-not $tenant) { continue }
        $score = if ($null -ne $tenant.PostureScore) { [int]$tenant.PostureScore } else { 100 }
        $result.Add([PSCustomObject]@{
                TenantId              = $tId
                TenantName            = $tenant.TenantName
                BusinessUnit          = $tenant.BusinessUnit
                PostureScore          = $score
                Classification        = Get-PostureClassification -Score $score
                CompliancePercentage  = if ($null -ne $tenant.CompliancePercentage) { [double]$tenant.CompliancePercentage } else { 100.0 }
                TotalControls         = $Normalized.Controls.Count
                CompliantControls     = $Normalized.Controls.Count
                DriftedControls       = 0
                CriticalFindings      = 0
                HighFindings          = 0
                MediumFindings        = 0
                LowFindings           = 0
                InformationalFindings = 0
                TotalFindings         = 0
                AssessmentStatus      = $tenant.AssessmentStatus
                TenantWeight          = $tenant.TenantWeight
                CollectorErrors       = @($tenant.CollectorErrors)
                Findings              = @()
            })
    }

    return $result
}

Function Get-DomainPostureScore {
    param (
        [Parameter(Mandatory)] [object]   $Normalized,
        [Parameter(Mandatory)] [object[]] $TenantScores,
        [Parameter(Mandatory)] [object]   $Context
    )

    $result = [System.Collections.Generic.List[object]]::new()

    # Determine active domains from controls + findings
    $activeDomains = @($Normalized.Controls | Select-Object -ExpandProperty Domain -Unique)
    $findingDomains = @($Normalized.Findings | Select-Object -ExpandProperty Domain -Unique)
    $allDomains = @(($activeDomains + $findingDomains) | Select-Object -Unique | Sort-Object)

    if ($allDomains.Count -eq 0) { $allDomains = $Script:SupportedDomains }

    foreach ($domain in $allDomains) {
        $domainFindings = @($Normalized.Findings  | Where-Object { $_.Domain -eq $domain })
        $domainControls = @($Normalized.Controls  | Where-Object { $_.Domain -eq $domain })

        $crit = ($domainFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $high = ($domainFindings | Where-Object { $_.Severity -eq 'High' }).Count
        $med = ($domainFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
        $low = ($domainFindings | Where-Object { $_.Severity -eq 'Low' }).Count

        $score = Invoke-ScoreCalculation -Findings $domainFindings
        $totalCtrl = $domainControls.Count
        $driftedCtrl = ($domainFindings | Select-Object -ExpandProperty ControlId -Unique).Count
        $complCtrl = [Math]::Max(0, $totalCtrl - $driftedCtrl)
        $compPct = if ($totalCtrl -gt 0) { [Math]::Round(($complCtrl / $totalCtrl) * 100, 1) } else { 0.0 }

        $affectedTenants = @($domainFindings | Select-Object -ExpandProperty TenantId -Unique).Count

        $result.Add([PSCustomObject]@{
                Domain               = $domain
                PostureScore         = $score
                Classification       = Get-PostureClassification -Score $score
                TotalControls        = $totalCtrl
                CompliantControls    = $complCtrl
                DriftedControls      = $driftedCtrl
                CriticalFindings     = $crit
                HighFindings         = $high
                MediumFindings       = $med
                LowFindings          = $low
                TotalFindings        = $domainFindings.Count
                CompliancePercentage = $compPct
                AffectedTenants      = $affectedTenants
            })
    }

    return $result
}

Function Get-EnterprisePostureScore {
    param (
        [Parameter(Mandatory)] [object[]] $TenantScores,
        [Parameter(Mandatory)] [object[]] $DomainScores,
        [Parameter(Mandatory)] [object]   $Context
    )

    if ($TenantScores.Count -eq 0) {
        return [PSCustomObject]@{
            Score           = 0
            Classification  = 'Critical'
            WeightedAverage = 0
            IsReliable      = $false
            ReliabilityNote = 'No tenant scores available'
            TotalTenants    = 0
            ScoredTenants   = 0
        }
    }

    # Weighted average across tenants (equal weights in V1 unless TenantWeight is set)
    $totalWeight = ($TenantScores | Measure-Object -Property TenantWeight -Sum).Sum
    if ($totalWeight -eq 0) { $totalWeight = $TenantScores.Count }

    $weightedSum = 0.0
    foreach ($t in $TenantScores) {
        $w = if ($t.TenantWeight -gt 0) { $t.TenantWeight } else { 1.0 }
        $weightedSum += $t.PostureScore * $w
    }

    $enterpriseScore = [Math]::Max(0, [Math]::Round($weightedSum / $totalWeight, 0))

    # Reliability flag
    $successCount = ($TenantScores | Where-Object {
            $_.AssessmentStatus -match 'Success|Completed|Complete'
        }).Count
    $coveragePct = if ($TenantScores.Count -gt 0) {
        [Math]::Round(($successCount / $TenantScores.Count) * 100, 0)
    }
    else { 0 }
    $isReliable = $coveragePct -ge $Script:MinReliableCoverage
    $reliNote = if ($isReliable) {
        "Based on $($TenantScores.Count) tenant(s) — Coverage: $coveragePct%"
    }
    else {
        "⚠ Score reliability is LOW — assessment coverage is $coveragePct% (minimum recommended: $Script:MinReliableCoverage%)"
    }

    return [PSCustomObject]@{
        Score              = [int]$enterpriseScore
        Classification     = Get-PostureClassification -Score ([int]$enterpriseScore)
        WeightedAverage    = [double][Math]::Round($weightedSum / $totalWeight, 2)
        IsReliable         = $isReliable
        ReliabilityNote    = $reliNote
        CoveragePercentage = $coveragePct
        TotalTenants       = $TenantScores.Count
        ScoredTenants      = $TenantScores.Count
        WeightingMethod    = 'Equal weight per tenant (V1). Set TenantWeight in assessment JSON to enable population-based weighting.'
    }
}

#endregion

#region ── Risk Aggregation ───────────────────────────────────────────────────

Function Get-RiskSummary {
    param (
        [Parameter(Mandatory)] [object] $Normalized,
        [Parameter(Mandatory)] [object] $Context
    )

    $findings = @($Normalized.Findings)

    # De-duplicate by TenantId+FindingId to avoid counting the same finding twice
    # when multiple input files represent overlapping assessments
    $unique = $findings | Sort-Object UniqueKey -Unique

    $crit = ($unique | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = ($unique | Where-Object { $_.Severity -eq 'High' }).Count
    $med = ($unique | Where-Object { $_.Severity -eq 'Medium' }).Count
    $low = ($unique | Where-Object { $_.Severity -eq 'Low' }).Count
    $info = ($unique | Where-Object { $_.Severity -eq 'Informational' }).Count
    $open = ($unique | Where-Object { $_.Status -ne 'Resolved' }).Count

    return [PSCustomObject]@{
        Critical               = $crit
        High                   = $high
        Medium                 = $med
        Low                    = $low
        Informational          = $info
        TotalFindings          = $unique.Count
        OpenFindings           = $open
        UniqueControlsAffected = ($unique | Select-Object -ExpandProperty ControlId -Unique).Count
        AffectedTenants        = ($unique | Select-Object -ExpandProperty TenantId   -Unique).Count
        AffectedDomains        = ($unique | Select-Object -ExpandProperty Domain     -Unique).Count
    }
}

Function Get-DataQualitySummary {
    param (
        [Parameter(Mandatory)] [object] $Context,
        [Parameter(Mandatory)] [object] $Normalized
    )

    return [PSCustomObject]@{
        InputFiles           = $Context.DataQuality.InputFiles
        ValidFiles           = $Context.DataQuality.ValidFiles
        RejectedFiles        = @($Context.DataQuality.RejectedFiles)
        RejectedCount        = $Context.DataQuality.RejectedFiles.Count
        DuplicateAssessments = $Context.DataQuality.DuplicateAssessments
        MissingTenantInfo    = $Context.DataQuality.MissingTenantInfo
        MissingControlInfo   = $Context.DataQuality.MissingControlInfo
        IncompleteFindings   = $Context.DataQuality.IncompleteFindings
        AssessmentVersions   = @($Context.DataQuality.AssessmentVersions)
        BaselineVersions     = @($Context.DataQuality.BaselineVersions)
        AssessmentCount      = $Normalized.Assessments.Count
        TenantCount          = $Normalized.Tenants.Count
        ControlCount         = $Normalized.Controls.Count
        FindingCount         = $Normalized.Findings.Count
    }
}

#endregion

#region ── Tenant Analysis ────────────────────────────────────────────────────

Function Get-TenantComparison {
    param (
        [Parameter(Mandatory)] [object[]] $TenantScores,
        [Parameter(Mandatory)] [object]   $Context
    )

    $ranked = @($TenantScores | Sort-Object PostureScore -Descending)

    $best = $ranked | Select-Object -First 1
    $worst = $ranked | Select-Object -Last  1
    $mostAtRisk = $TenantScores | Sort-Object CriticalFindings -Descending | Select-Object -First 1
    $highestVol = $TenantScores | Sort-Object TotalFindings    -Descending | Select-Object -First 1
    $highestCrit = $TenantScores | Sort-Object CriticalFindings -Descending | Select-Object -First 1

    # Caveat best tenant if coverage is incomplete
    $bestCaveat = ''
    if ($best -and $best.AssessmentStatus -notmatch 'Success|Complete') {
        $bestCaveat = "⚠ Assessment coverage for this tenant may be incomplete ($($best.AssessmentStatus))"
    }

    return [PSCustomObject]@{
        RankedTenants        = $ranked
        BestPerforming       = $best
        BestPerformingCaveat = $bestCaveat
        LowestPerforming     = $worst
        MostAtRisk           = $mostAtRisk
        HighestFindingVolume = $highestVol
        HighestCriticalRisk  = $highestCrit
    }
}

#endregion

#region ── Domain Analysis ────────────────────────────────────────────────────

Function Get-DomainComparison {
    param (
        [Parameter(Mandatory)] [object[]] $DomainScores,
        [Parameter(Mandatory)] [object[]] $TenantScores,
        [Parameter(Mandatory)] [object]   $Context
    )

    $ranked = @($DomainScores | Sort-Object PostureScore -Descending)
    return [PSCustomObject]@{
        RankedDomains   = $ranked
        StrongestDomain = $ranked | Select-Object -First 1
        WeakestDomain   = $ranked | Select-Object -Last  1
    }
}

#endregion

#region ── Enterprise Analysis ────────────────────────────────────────────────

Function Get-TopRiskFindings {
    param (
        [Parameter(Mandatory)] [object] $Normalized,
        [Parameter(Mandatory)] [object] $Context
    )

    # Rank by: Severity → affected tenant count → control importance
    $grouped = $Normalized.Findings |
    Where-Object { $_.Status -ne 'Resolved' } |
    Group-Object ControlId |
    ForEach-Object {
        $grp = $_.Group
        $first = $grp | Select-Object -First 1
        $sev = Normalize-SeverityValue -Severity ($grp | Sort-Object SeverityOrder | Select-Object -First 1 -ExpandProperty Severity)
        $sevOrder = if ($Script:SeverityOrder.ContainsKey($sev)) { $Script:SeverityOrder[$sev] } else { 5 }

        [PSCustomObject]@{
            ControlId        = $first.ControlId
            Title            = $first.Title
            Domain           = $first.Domain
            Severity         = $sev
            SeverityOrder    = $sevOrder
            AffectedTenants  = ($grp | Select-Object -ExpandProperty TenantId -Unique).Count
            AffectedControls = 1
            BusinessImpact   = $first.BusinessImpact
            Recommendation   = $first.Recommendation
            FindingCount     = $grp.Count
        }
    }

    $ranked = @($grouped | Sort-Object SeverityOrder, @{Expression = { - $_.AffectedTenants } })
    return $ranked
}

Function Get-HistoricalComparison {
    param (
        [Parameter(Mandatory)] [object] $Normalized,
        [Parameter(Mandatory)] [object] $Context
    )

    # Sort assessments by GeneratedAt
    $sorted = @($Normalized.Assessments | Sort-Object GeneratedAt)
    if ($sorted.Count -lt 2) { return $null }

    $previous = $sorted[0]
    $current = $sorted[-1]

    $prevId = [string]$previous.AssessmentId
    $currId = [string]$current.AssessmentId

    if ($prevId -eq $currId) {
        Write-AssessmentLog -Context $Context -Level 'INFO' `
            -Message 'Historical comparison skipped — all input files share the same AssessmentId'
        return $null
    }

    $prevFindings = @($Normalized.Findings | Where-Object { $_.AssessmentId -eq $prevId })
    $currFindings = @($Normalized.Findings | Where-Object { $_.AssessmentId -eq $currId })

    $prevFindingKeys = @($prevFindings | ForEach-Object { "$($_.TenantId)|$($_.ControlId)" })
    $currFindingKeys = @($currFindings | ForEach-Object { "$($_.TenantId)|$($_.ControlId)" })

    $newFindings = @($currFindingKeys | Where-Object { $prevFindingKeys -notcontains $_ })
    $resolvedFindings = @($prevFindingKeys | Where-Object { $currFindingKeys -notcontains $_ })
    $persistent = @($currFindingKeys | Where-Object { $prevFindingKeys -contains $_ })

    $prevScore = [int](Invoke-ScoreCalculation -Findings $prevFindings)
    $currScore = [int](Invoke-ScoreCalculation -Findings $currFindings)
    $scoreDiff = $currScore - $prevScore

    $newCritical = ($currFindings | Where-Object {
            $_.Severity -eq 'Critical' -and $prevFindingKeys -notcontains "$($_.TenantId)|$($_.ControlId)"
        }).Count
    $resolvedCritical = ($prevFindings | Where-Object {
            $_.Severity -eq 'Critical' -and $currFindingKeys -notcontains "$($_.TenantId)|$($_.ControlId)"
        }).Count

    Write-AssessmentLog -Context $Context -Level 'INFO' `
        -Message "Historical comparison: Previous=$prevScore Current=$currScore Change=$(if($scoreDiff -ge 0){'+'}else{''}$scoreDiff)"

    return [PSCustomObject]@{
        PreviousAssessmentId  = $prevId
        CurrentAssessmentId   = $currId
        PreviousGeneratedAt   = [string]$previous.GeneratedAt
        CurrentGeneratedAt    = [string]$current.GeneratedAt
        PreviousScore         = $prevScore
        CurrentScore          = $currScore
        ScoreChange           = $scoreDiff
        ScoreTrend            = if ($scoreDiff -gt 0) { 'Improved' } elseif ($scoreDiff -lt 0) { 'Declined' } else { 'Unchanged' }
        PreviousFindings      = $prevFindings.Count
        CurrentFindings       = $currFindings.Count
        NewFindings           = $newFindings.Count
        ResolvedFindings      = $resolvedFindings.Count
        PersistentFindings    = $persistent.Count
        NewCriticalRisks      = $newCritical
        ResolvedCriticalRisks = $resolvedCritical
    }
}

Function Get-BaselineComplianceSummary {
    param (
        [Parameter(Mandatory)] [object] $Normalized,
        [object] $BaselineConfig,
        [Parameter(Mandatory)] [object] $Context
    )

    $controls = @($Normalized.Controls)
    $findings = @($Normalized.Findings | Where-Object { $_.Status -ne 'Resolved' })

    $driftedControlIds = @($findings | Select-Object -ExpandProperty ControlId -Unique)
    $totalCtrl = $controls.Count
    $driftedCtrl = ($driftedControlIds | Measure-Object).Count
    $compliantCtrl = [Math]::Max(0, $totalCtrl - $driftedCtrl)
    $compPct = if ($totalCtrl -gt 0) { [Math]::Round(($compliantCtrl / $totalCtrl) * 100, 1) } else { 0.0 }

    # Per-tenant compliance
    $tenantCompliance = [System.Collections.Generic.List[object]]::new()
    $tenantGroups = $findings | Group-Object TenantId
    foreach ($tg in $tenantGroups) {
        $tDrifted = @($tg.Group | Select-Object -ExpandProperty ControlId -Unique).Count
        $tCompliant = [Math]::Max(0, $totalCtrl - $tDrifted)
        $tPct = if ($totalCtrl -gt 0) { [Math]::Round(($tCompliant / $totalCtrl) * 100, 1) } else { 0.0 }
        $tenantName = ($tg.Group | Select-Object -First 1).TenantName

        $tenantCompliance.Add([PSCustomObject]@{
                TenantId             = $tg.Name
                TenantName           = $tenantName
                TotalControls        = $totalCtrl
                CompliantControls    = $tCompliant
                DriftedControls      = $tDrifted
                CompliancePercentage = $tPct
            })
    }

    # Control matrix (Tenant x Control)
    $matrix = [System.Collections.Generic.List[object]]::new()
    $uniqueTenants = @($Normalized.Tenants | Select-Object -ExpandProperty TenantId -Unique)
    foreach ($ctrl in $controls) {
        $row = [ordered]@{ ControlId = $ctrl.ControlId; Domain = $ctrl.Domain; Title = $ctrl.Title }
        foreach ($tId in $uniqueTenants) {
            $isDrifted = $driftedControlIds -contains $ctrl.ControlId -and
            ($findings | Where-Object { $_.TenantId -eq $tId -and $_.ControlId -eq $ctrl.ControlId }).Count -gt 0
            $row[$tId] = if ($isDrifted) { 'DRIFT' } else { 'PASS' }
        }
        $matrix.Add([PSCustomObject]$row)
    }

    return [PSCustomObject]@{
        TotalControls        = $totalCtrl
        CompliantControls    = $compliantCtrl
        DriftedControls      = $driftedCtrl
        CompliancePercentage = $compPct
        TenantCompliance     = $tenantCompliance
        ControlMatrix        = $matrix
    }
}

#endregion

#region ── Remediation Prioritization ────────────────────────────────────────

Function Get-RemediationPriority {
    param (
        [Parameter(Mandatory)] [object[]] $TopRisks,
        [Parameter(Mandatory)] [object]   $Normalized,
        [Parameter(Mandatory)] [object]   $Context
    )

    $result = [System.Collections.Generic.List[object]]::new()
    $rank = 1

    foreach ($risk in $TopRisks) {
        # Assign P0–P3 based on severity and affected tenant count
        $priority = switch ($risk.Severity) {
            'Critical' { 'P0' }
            'High' { if ($risk.AffectedTenants -ge 3) { 'P0' } else { 'P1' } }
            'Medium' { if ($risk.AffectedTenants -ge 5) { 'P1' } else { 'P2' } }
            'Low' { 'P3' }
            default { 'P3' }
        }

        $effort = switch ($risk.Severity) {
            'Critical' { 'High' }
            'High' { 'Medium' }
            'Medium' { 'Medium' }
            default { 'Low' }
        }

        $result.Add([PSCustomObject]@{
                Priority          = $priority
                PriorityLabel     = $Script:RemediationPriority[$priority]
                Rank              = $rank
                FindingTitle      = $risk.Title
                ControlId         = $risk.ControlId
                Domain            = $risk.Domain
                Severity          = $risk.Severity
                AffectedTenants   = $risk.AffectedTenants
                BusinessImpact    = $risk.BusinessImpact
                RecommendedAction = $risk.Recommendation
                EstimatedEffort   = $effort
            })
        $rank++
    }

    # Sort by priority label then rank
    $priorityOrder = @{ P0 = 0; P1 = 1; P2 = 2; P3 = 3 }
    $sorted = @($result | Sort-Object {
            $p = $_.Priority
            if ($priorityOrder.ContainsKey($p)) { $priorityOrder[$p] } else { 99 }
        }, Rank)

    return $sorted
}

#endregion

#region ── Assessment Coverage ────────────────────────────────────────────────

Function Get-AssessmentCoverage {
    param (
        [Parameter(Mandatory)] [object] $Normalized,
        [Parameter(Mandatory)] [object] $Context
    )

    $tenants = @($Normalized.Tenants)
    $total = $tenants.Count
    $successful = ($tenants | Where-Object { $_.AssessmentStatus -match 'Success|Completed|Complete' }).Count
    $partial = ($tenants | Where-Object { $_.AssessmentStatus -match 'Partial' }).Count
    $failed = ($tenants | Where-Object { $_.AssessmentStatus -match 'Failed|Error' }).Count
    $denied = ($tenants | Where-Object { $_.PermissionStatus -match 'Denied|Insufficient' }).Count
    $unavailable = ($tenants | Where-Object { $_.AssessmentStatus -match 'Unavailable|Unreachable' }).Count
    $notAssessed = [Math]::Max(0, $total - $successful - $partial - $failed - $unavailable)

    $covPct = if ($total -gt 0) { [Math]::Round((($successful + $partial) / $total) * 100, 1) } else { 0.0 }

    return [PSCustomObject]@{
        TotalTenants         = $total
        SuccessfullyAssessed = $successful
        PartiallyAssessed    = $partial
        FailedAssessments    = $failed
        PermissionDenied     = $denied
        Unavailable          = $unavailable
        NotAssessed          = $notAssessed
        CoveragePercentage   = $covPct
        CoverageStatus       = if ($covPct -ge 95) { 'Complete' }
        elseif ($covPct -ge 75) { 'Good' }
        elseif ($covPct -ge 50) { 'Partial' }
        else { 'Insufficient' }
        TenantDetails        = $tenants
    }
}

#endregion

#region ── JSON Reporting ─────────────────────────────────────────────────────

Function New-EnterprisePostureJson {
    param (
        [string]   $OutputPath,
        [string]   $Timestamp,
        [object]   $EnterpriseScore,
        [object[]] $TenantScores,
        [object[]] $DomainScores,
        [object]   $RiskSummary,
        [object]   $BaselineCompliance,
        [object]   $Coverage,
        [object[]] $TopRisks,
        [object[]] $Remediation,
        [object]   $Historical,
        [object]   $DataQuality,
        [object]   $Normalized,
        [object]   $Context
    )

    $fileName = "EntraEnterprisePosture_$Timestamp.json"
    $outFile = Join-Path -Path $OutputPath -ChildPath $fileName

    # Build graph-ready nodes and edges (summary level, V1)
    $nodes = [System.Collections.Generic.List[object]]::new()
    $edges = [System.Collections.Generic.List[object]]::new()

    $nodes.Add([PSCustomObject]@{ Id = 'enterprise'; Type = 'Enterprise'; Label = 'Enterprise'; Score = $EnterpriseScore.Score })
    foreach ($t in $TenantScores) {
        $nId = "tenant|$($t.TenantId)"
        $nodes.Add([PSCustomObject]@{ Id = $nId; Type = 'Tenant'; Label = $t.TenantName; TenantId = $t.TenantId; Score = $t.PostureScore })
        $edges.Add([PSCustomObject]@{ Source = 'enterprise'; Target = $nId; Relationship = 'HAS_TENANT' })
    }
    foreach ($d in $DomainScores) {
        $nId = "domain|$($d.Domain)"
        $nodes.Add([PSCustomObject]@{ Id = $nId; Type = 'Domain'; Label = $d.Domain; Score = $d.PostureScore })
        $edges.Add([PSCustomObject]@{ Source = 'enterprise'; Target = $nId; Relationship = 'HAS_DOMAIN' })
    }
    foreach ($r in $TopRisks | Select-Object -First 20) {
        $nId = "control|$($r.ControlId)"
        if (-not ($nodes | Where-Object { $_.Id -eq $nId })) {
            $nodes.Add([PSCustomObject]@{ Id = $nId; Type = 'Control'; Label = $r.Title; ControlId = $r.ControlId; Severity = $r.Severity })
        }
        $domNId = "domain|$($r.Domain)"
        $edges.Add([PSCustomObject]@{ Source = $domNId; Target = $nId; Relationship = 'HAS_FINDING' })
    }

    $output = [ordered]@{
        SchemaVersion         = $Script:SchemaVersion
        DashboardVersion      = $Script:DashboardVersion
        GeneratedAt           = (Get-Date).ToString('o')
        AssessmentSources     = @($Normalized.Assessments | ForEach-Object {
                [ordered]@{
                    AssessmentId      = $_.AssessmentId
                    GeneratedAt       = $_.GeneratedAt
                    AssessmentVersion = $_.AssessmentVersion
                    BaselineVersion   = $_.BaselineVersion
                    SourceFile        = $_._SourceFile
                }
            })
        Enterprise            = $EnterpriseScore
        Tenants               = $TenantScores | Select-Object -ExcludeProperty Findings
        Domains               = $DomainScores
        RiskSummary           = $RiskSummary
        BaselineCompliance    = [ordered]@{
            Enterprise = [ordered]@{
                TotalControls        = $BaselineCompliance.TotalControls
                CompliantControls    = $BaselineCompliance.CompliantControls
                DriftedControls      = $BaselineCompliance.DriftedControls
                CompliancePercentage = $BaselineCompliance.CompliancePercentage
            }
            Tenants    = $BaselineCompliance.TenantCompliance
        }
        AssessmentCoverage    = $Coverage | Select-Object -ExcludeProperty TenantDetails
        DataQuality           = $DataQuality
        TopRisks              = $TopRisks | Select-Object -First 20
        RemediationPriorities = $Remediation
        HistoricalComparison  = $Historical
        Nodes                 = $nodes
        Edges                 = $edges
        _future               = [ordered]@{
            PowerBiIntegration           = 'planned'
            AzureSqlStorage              = 'planned'
            SentinelIntegration          = 'planned'
            LlmExecutiveNarrative        = 'planned'
            BusinessUnitBenchmarking     = 'planned'
            EnterpriseRiskHeatmap        = 'planned'
            ObjectLevelRelationshipGraph = 'planned'
        }
    }

    try {
        $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $outFile -Encoding UTF8 -Force -ErrorAction Stop
        Write-AssessmentLog -Context $Context -Level 'INFO' -Message "JSON output written" -Detail $outFile
        Write-Host "  📋  JSON: $outFile" -ForegroundColor White
    }
    catch {
        Write-AssessmentLog -Context $Context -Level 'ERROR' `
            -Message "Failed to write JSON output: $($_.Exception.Message)" -Detail $outFile
        Write-Warning "Could not write JSON to '$outFile': $($_.Exception.Message)"
    }

    return $outFile
}

#endregion

#region ── CSV Reporting ──────────────────────────────────────────────────────

Function New-EnterprisePostureCsv {
    param (
        [string]   $OutputPath,
        [string]   $Timestamp,
        [object]   $EnterpriseScore,
        [object[]] $TenantScores,
        [object[]] $DomainScores,
        [object]   $Normalized,
        [object[]] $Remediation,
        [object]   $Context
    )

    $prefix = 'Generate-EntraEnterprisePostureDashboard'

    # Enterprise summary CSV
    $entFile = Join-Path $OutputPath "${prefix}_Enterprise_${Timestamp}.csv"
    try {
        [PSCustomObject]@{
            GeneratedAt        = (Get-Date).ToString('o')
            DashboardVersion   = $Script:DashboardVersion
            EnterpriseScore    = $EnterpriseScore.Score
            Classification     = $EnterpriseScore.Classification
            WeightedAverage    = $EnterpriseScore.WeightedAverage
            IsReliable         = $EnterpriseScore.IsReliable
            CoveragePercentage = $EnterpriseScore.CoveragePercentage
            TotalTenants       = $EnterpriseScore.TotalTenants
            ScoredTenants      = $EnterpriseScore.ScoredTenants
            ReliabilityNote    = $EnterpriseScore.ReliabilityNote
        } | Export-Csv -Path $entFile -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        Write-AssessmentLog -Context $Context -Level 'INFO' -Message 'Enterprise CSV written' -Detail $entFile
    }
    catch {
        Write-Warning "Could not write Enterprise CSV: $($_.Exception.Message)"
    }

    # Tenants CSV
    $tenFile = Join-Path $OutputPath "${prefix}_Tenants_${Timestamp}.csv"
    try {
        $TenantScores | Select-Object TenantId, TenantName, BusinessUnit, PostureScore,
        Classification, CompliancePercentage, TotalControls, CompliantControls,
        DriftedControls, CriticalFindings, HighFindings, MediumFindings, LowFindings,
        InformationalFindings, TotalFindings, AssessmentStatus, TenantWeight |
        Export-Csv -Path $tenFile -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        Write-AssessmentLog -Context $Context -Level 'INFO' -Message 'Tenants CSV written' -Detail $tenFile
    }
    catch {
        Write-Warning "Could not write Tenants CSV: $($_.Exception.Message)"
    }

    # Domains CSV
    $domFile = Join-Path $OutputPath "${prefix}_Domains_${Timestamp}.csv"
    try {
        $DomainScores | Select-Object Domain, PostureScore, Classification,
        TotalControls, CompliantControls, DriftedControls,
        CriticalFindings, HighFindings, MediumFindings, LowFindings,
        TotalFindings, CompliancePercentage, AffectedTenants |
        Export-Csv -Path $domFile -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        Write-AssessmentLog -Context $Context -Level 'INFO' -Message 'Domains CSV written' -Detail $domFile
    }
    catch {
        Write-Warning "Could not write Domains CSV: $($_.Exception.Message)"
    }

    # Findings CSV
    $findFile = Join-Path $OutputPath "${prefix}_Findings_${Timestamp}.csv"
    try {
        $Normalized.Findings | Select-Object FindingId, TenantId, TenantName,
        Domain, ControlId, Severity, Title, BusinessImpact,
        Recommendation, CurrentValue, ExpectedValue, DriftType, Status,
        RemediationEffort, AssessmentId, GeneratedAt |
        Export-Csv -Path $findFile -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        Write-AssessmentLog -Context $Context -Level 'INFO' -Message 'Findings CSV written' -Detail $findFile
    }
    catch {
        Write-Warning "Could not write Findings CSV: $($_.Exception.Message)"
    }

    # Remediation CSV
    $remFile = Join-Path $OutputPath "${prefix}_Remediation_${Timestamp}.csv"
    try {
        $Remediation | Select-Object Priority, PriorityLabel, Rank, FindingTitle,
        ControlId, Domain, Severity, AffectedTenants, BusinessImpact,
        RecommendedAction, EstimatedEffort |
        Export-Csv -Path $remFile -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
        Write-AssessmentLog -Context $Context -Level 'INFO' -Message 'Remediation CSV written' -Detail $remFile
    }
    catch {
        Write-Warning "Could not write Remediation CSV: $($_.Exception.Message)"
    }

    Write-Host "  📊  CSV files written to: $OutputPath" -ForegroundColor White
}

#endregion

#region ── HTML Dashboard ─────────────────────────────────────────────────────

Function ConvertTo-DashboardJsonSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $Text `
        -replace '\\', '\\' `
        -replace '"', '\"' `
        -replace "`r`n", '\n' `
        -replace "`n", '\n' `
        -replace "`r", '\n' `
        -replace "`t", '\t' `
        -replace '<', '\u003c' `
        -replace '>', '\u003e' `
        -replace '\$', '\u0024'
}

Function New-EnterprisePostureHtml {
    param (
        [string]   $OutputPath,
        [string]   $Timestamp,
        [object]   $EnterpriseScore,
        [object[]] $TenantScores,
        [object[]] $DomainScores,
        [object]   $RiskSummary,
        [object]   $BaselineCompliance,
        [object]   $Coverage,
        [object]   $TenantComparison,
        [object]   $DomainComparison,
        [object[]] $TopRisks,
        [object[]] $Remediation,
        [object]   $Historical,
        [object]   $DataQuality,
        [object]   $Normalized,
        [object]   $Context
    )

    $fileName = "Generate-EntraEnterprisePostureDashboard_$Timestamp.html"
    $outFile = Join-Path -Path $OutputPath -ChildPath $fileName
    $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')

    #──────────────────────────────────────────────────────────────────────────
    # Build JSON data blobs
    #──────────────────────────────────────────────────────────────────────────

    # Tenants JSON
    $tenantsJson = ($TenantScores | ForEach-Object {
            $t = $_
            $tIdS = ConvertTo-DashboardJsonSafe $t.TenantId
            $tNameS = ConvertTo-DashboardJsonSafe $t.TenantName
            $buS = ConvertTo-DashboardJsonSafe $t.BusinessUnit
            $statusS = ConvertTo-DashboardJsonSafe $t.AssessmentStatus
            $classS = ConvertTo-DashboardJsonSafe $t.Classification
            "{`"id`":`"$tIdS`",`"name`":`"$tNameS`",`"bu`":`"$buS`",`"score`":$($t.PostureScore),`"class`":`"$classS`",`"compliance`":$($t.CompliancePercentage),`"critical`":$($t.CriticalFindings),`"high`":$($t.HighFindings),`"medium`":$($t.MediumFindings),`"low`":$($t.LowFindings),`"total`":$($t.TotalFindings),`"status`":`"$statusS`"}"
        }) -join ','

    # Domains JSON
    $domainsJson = ($DomainScores | ForEach-Object {
            $d = $_
            $dS = ConvertTo-DashboardJsonSafe $d.Domain
            $cS = ConvertTo-DashboardJsonSafe $d.Classification
            "{`"domain`":`"$dS`",`"score`":$($d.PostureScore),`"class`":`"$cS`",`"compliance`":$($d.CompliancePercentage),`"critical`":$($d.CriticalFindings),`"high`":$($d.HighFindings),`"medium`":$($d.MediumFindings),`"low`":$($d.LowFindings),`"total`":$($d.TotalFindings),`"affectedTenants`":$($d.AffectedTenants)}"
        }) -join ','

    # Findings JSON (top 200 for the table)
    $findingsJson = ($Normalized.Findings | Select-Object -First 200 | ForEach-Object {
            $f = $_
            $tS = ConvertTo-DashboardJsonSafe $f.TenantName
            $tId = ConvertTo-DashboardJsonSafe $f.TenantId
            $dS = ConvertTo-DashboardJsonSafe $f.Domain
            $cS = ConvertTo-DashboardJsonSafe $f.ControlId
            $sS = ConvertTo-DashboardJsonSafe $f.Severity
            $titS = ConvertTo-DashboardJsonSafe $f.Title
            $biS = ConvertTo-DashboardJsonSafe $f.BusinessImpact
            $recS = ConvertTo-DashboardJsonSafe $f.Recommendation
            $prS = ConvertTo-DashboardJsonSafe $f.Priority
            $efS = ConvertTo-DashboardJsonSafe $f.RemediationEffort
            $stS = ConvertTo-DashboardJsonSafe $f.Status
            $fIdS = ConvertTo-DashboardJsonSafe $f.FindingId
            "{`"fid`":`"$fIdS`",`"tenant`":`"$tS`",`"tenantId`":`"$tId`",`"domain`":`"$dS`",`"control`":`"$cS`",`"sev`":`"$sS`",`"sevOrd`":$($f.SeverityOrder),`"title`":`"$titS`",`"impact`":`"$biS`",`"rec`":`"$recS`",`"effort`":`"$efS`",`"status`":`"$stS`"}"
        }) -join ','

    # Top risks JSON
    $topRisksJson = ($TopRisks | Select-Object -First 15 | ForEach-Object {
            $r = $_
            $tS = ConvertTo-DashboardJsonSafe $r.Title
            $dS = ConvertTo-DashboardJsonSafe $r.Domain
            $sS = ConvertTo-DashboardJsonSafe $r.Severity
            $biS = ConvertTo-DashboardJsonSafe $r.BusinessImpact
            $recS = ConvertTo-DashboardJsonSafe $r.Recommendation
            "{`"title`":`"$tS`",`"domain`":`"$dS`",`"sev`":`"$sS`",`"sevOrd`":$($r.SeverityOrder),`"tenants`":$($r.AffectedTenants),`"impact`":`"$biS`",`"rec`":`"$recS`"}"
        }) -join ','

    # Remediation JSON
    $remJson = ($Remediation | ForEach-Object {
            $r = $_
            $pS = ConvertTo-DashboardJsonSafe $r.Priority
            $plS = ConvertTo-DashboardJsonSafe $r.PriorityLabel
            $tS = ConvertTo-DashboardJsonSafe $r.FindingTitle
            $dS = ConvertTo-DashboardJsonSafe $r.Domain
            $sS = ConvertTo-DashboardJsonSafe $r.Severity
            $biS = ConvertTo-DashboardJsonSafe $r.BusinessImpact
            $raS = ConvertTo-DashboardJsonSafe $r.RecommendedAction
            $efS = ConvertTo-DashboardJsonSafe $r.EstimatedEffort
            "{`"priority`":`"$pS`",`"label`":`"$plS`",`"rank`":$($r.Rank),`"title`":`"$tS`",`"domain`":`"$dS`",`"sev`":`"$sS`",`"tenants`":$($r.AffectedTenants),`"impact`":`"$biS`",`"action`":`"$raS`",`"effort`":`"$efS`"}"
        }) -join ','

    # Coverage tenant details JSON
    $coverageTenJson = ($Coverage.TenantDetails | ForEach-Object {
            $t = $_
            $nS = ConvertTo-DashboardJsonSafe $t.TenantName
            $iS = ConvertTo-DashboardJsonSafe $t.TenantId
            $aS = ConvertTo-DashboardJsonSafe $t.AssessmentStatus
            $pS = ConvertTo-DashboardJsonSafe $t.PermissionStatus
            $eC = if ($t.CollectorErrors -and $t.CollectorErrors.Count -gt 0) { $t.CollectorErrors.Count } else { 0 }
            "{`"name`":`"$nS`",`"id`":`"$iS`",`"status`":`"$aS`",`"perms`":`"$pS`",`"errors`":$eC}"
        }) -join ','

    # Source files JSON
    $srcFilesJson = ($Normalized.Assessments | ForEach-Object {
            $a = $_
            $aI = ConvertTo-DashboardJsonSafe ([string]$a.AssessmentId)
            $gA = ConvertTo-DashboardJsonSafe ([string]$a.GeneratedAt)
            $sF = ConvertTo-DashboardJsonSafe ([string]$a._SourceFile)
            $aV = ConvertTo-DashboardJsonSafe ([string]$a.AssessmentVersion)
            $bV = ConvertTo-DashboardJsonSafe ([string]$a.BaselineVersion)
            "{`"assessmentId`":`"$aI`",`"generatedAt`":`"$gA`",`"sourceFile`":`"$sF`",`"assessmentVersion`":`"$aV`",`"baselineVersion`":`"$bV`"}"
        }) -join ','

    # Historical JSON
    $histJson = if ($Historical) {
        $tS = ConvertTo-DashboardJsonSafe $Historical.ScoreTrend
        "{`"prevScore`":$($Historical.PreviousScore),`"currScore`":$($Historical.CurrentScore),`"change`":$($Historical.ScoreChange),`"trend`":`"$tS`",`"prevFindings`":$($Historical.PreviousFindings),`"currFindings`":$($Historical.CurrentFindings),`"newFindings`":$($Historical.NewFindings),`"resolvedFindings`":$($Historical.ResolvedFindings),`"persistentFindings`":$($Historical.PersistentFindings),`"newCritical`":$($Historical.NewCriticalRisks),`"resolvedCritical`":$($Historical.ResolvedCriticalRisks)}"
    }
    else { 'null' }

    # Score color helper
    $scoreColor = switch ($EnterpriseScore.Classification) {
        'Excellent' { '#3fb950' }
        'Good' { '#3fb950' }
        'Needs Improvement' { '#d29922' }
        'Poor' { '#f85149' }
        default { '#f85149' }
    }

    #──────────────────────────────────────────────────────────────────────────
    # HTML here-string
    #──────────────────────────────────────────────────────────────────────────

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Enterprise Entra Posture Dashboard</title>
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
#sidebar{position:fixed;top:0;left:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text)}
.sidebar-logo p{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.version-badge{display:inline-block;margin-top:5px;background:rgba(56,139,253,.15);color:var(--accent);font-family:var(--mono);font-size:10px;padding:1px 8px;border-radius:20px;border:1px solid rgba(56,139,253,.3)}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13.5px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0}
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
.sidebar-footer{padding:10px 18px 12px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);font-family:var(--mono);line-height:1.6}
kbd{display:inline-block;padding:1px 5px;background:var(--surface3);border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:11px;color:var(--muted)}
#main{margin-left:236px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:24px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-card::after{content:'';position:absolute;top:-26px;right:-26px;width:68px;height:68px;border-radius:50%;background:radial-gradient(circle,rgba(59,130,246,.1),transparent 70%)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:25px;font-weight:700;color:var(--text);line-height:1}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}
.health-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;display:flex;align-items:center;gap:18px;margin-bottom:22px;flex-wrap:wrap}
.health-ring-wrap{position:relative;width:86px;height:86px;flex-shrink:0}
.health-ring-wrap svg{width:86px;height:86px}
.health-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.health-score-num{font-family:var(--mono);font-size:21px;font-weight:700;line-height:1}
.health-score-pct{font-size:9px;color:var(--muted)}
.health-info{flex:1;min-width:200px}
.health-info h3{font-size:14px;font-weight:700;margin-bottom:4px}
.health-info p{font-size:12px;color:var(--muted2)}
.health-bar-row{display:flex;align-items:center;gap:8px;margin-top:8px;font-size:12px}
.health-mini-bar{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.health-mini-fill{height:100%;border-radius:3px;transition:width 1s ease}
.reliability-banner{background:rgba(210,153,34,.1);border:1px solid rgba(210,153,34,.4);border-radius:var(--radius-sm);padding:8px 14px;font-size:12px;color:var(--amber);margin-top:8px}
.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-family:var(--mono);font-size:11px;color:var(--muted2);width:120px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:32px;text-align:right;flex-shrink:0}
.donut-wrap{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.legend-list{flex:1;min-width:130px;display:flex;flex-direction:column;gap:5px}
.legend-item{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted2);padding:2px 4px;border-radius:4px}
.legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.legend-pct{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;padding:8px 11px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--accent)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:13px;flex-shrink:0}
.data-table{width:100%;border-collapse:collapse}
.data-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.data-table thead th:hover{color:var(--text)}
.data-table thead th.sort-active{color:var(--accent)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.data-table tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.data-table tbody tr:hover{background:var(--surface2)}
.data-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13.5px}
.td-mono{font-family:var(--mono);font-size:12.5px}
.td-muted{color:var(--muted2);font-size:13px}
.sev-badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600;font-family:var(--sans)}
.sev-critical{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.sev-high{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3)}
.sev-medium{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3)}
.sev-low{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.sev-info{background:rgba(125,133,144,.15);color:var(--muted2);border:1px solid rgba(125,133,144,.3)}
.score-pill{display:inline-flex;align-items:center;justify-content:center;min-width:42px;padding:2px 8px;border-radius:20px;font-family:var(--mono);font-size:12px;font-weight:700}
.score-excellent{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.4)}
.score-good{background:rgba(63,185,80,.1);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.score-improve{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3)}
.score-poor{background:rgba(248,81,73,.1);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.score-critical{background:rgba(248,81,73,.2);color:var(--red);border:1px solid rgba(248,81,73,.5)}
.priority-badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11.5px;font-weight:700;font-family:var(--mono)}
.p0{background:rgba(248,81,73,.2);color:var(--red);border:1px solid rgba(248,81,73,.5)}
.p1{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3)}
.p2{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3)}
.p3{background:rgba(63,185,80,.1);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:14px}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}
#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(700px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:24px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
#detailClose{margin-left:auto;background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--red);color:#fff}
#detailContent{flex:1;overflow-y:auto}
.detail-header{margin-bottom:16px}
.detail-name{font-size:16px;font-weight:700;color:var(--text);word-break:break-word}
.detail-meta-row{display:flex;gap:9px;flex-wrap:wrap;margin:12px 0}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:12px;color:var(--muted2)}
.detail-section{margin-top:18px}
.detail-section-title{font-size:11.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:9px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.detail-text{color:var(--muted2);font-size:13.5px;line-height:1.7}
.hist-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;margin-bottom:18px}
.hist-stat{text-align:center}
.hist-val{font-family:var(--mono);font-size:22px;font-weight:700}
.hist-lbl{font-size:11px;color:var(--muted);margin-top:3px}
.coverage-badge{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:var(--radius);font-size:13px;font-weight:700;margin-bottom:16px}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0}
.dq-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border);font-size:13.5px}
.dq-row:last-child{border-bottom:none}
.dq-val{font-family:var(--mono);font-size:12.5px;color:var(--accent2)}
.risk-item{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 14px;margin-bottom:8px;display:flex;align-items:flex-start;gap:12px}
.risk-rank{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--muted);min-width:24px;margin-top:1px}
.risk-body{flex:1}
.risk-title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:5px}
.risk-meta{display:flex;gap:8px;flex-wrap:wrap;font-size:12px;color:var(--muted2)}
#toast{position:fixed;bottom:22px;right:22px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:10px 18px;display:flex;align-items:center;gap:9px;font-size:13.5px;box-shadow:var(--shadow);transform:translateY(20px);opacity:0;transition:all .3s;z-index:999;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}
@media(max-width:768px){#sidebar{transform:translateX(-236px);transition:transform .25s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px;cursor:pointer;font-size:18px}
.table-wrap{overflow-x:auto}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🏢</div>
    <h1>Entra Posture</h1>
    <p>Enterprise Dashboard</p>
    <span class="version-badge">v__DASHVER__</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">🏠</span> Enterprise Overview
    </button>
    <button class="nav-btn" onclick="showPage('tenants',this)">
      <span class="nav-icon">🏢</span> Tenant Posture
    </button>
    <button class="nav-btn" onclick="showPage('domains',this)">
      <span class="nav-icon">🔐</span> Domain Analysis
    </button>
    <button class="nav-btn" onclick="showPage('findings',this)">
      <span class="nav-icon">⚠️</span> Risk Findings
    </button>
    <button class="nav-btn" onclick="showPage('baseline',this)">
      <span class="nav-icon">📋</span> Baseline Compliance
    </button>
    <button class="nav-btn" onclick="showPage('remediation',this)">
      <span class="nav-icon">🔧</span> Remediation
    </button>
    <button class="nav-btn" onclick="showPage('coverage',this)">
      <span class="nav-icon">📡</span> Assessment Coverage
    </button>
    <button class="nav-btn" onclick="showPage('info',this)">
      <span class="nav-icon">ℹ️</span> Assessment Info
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

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- PAGE: Enterprise Overview                                               -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Enterprise Overview</div>
      <div class="page-subtitle">Aggregated Entra ID security posture across all assessed tenants</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="dlFile(exportFindingsCSV(),'EntraFindings.csv','text/csv')">⬇ Export Findings CSV</button>
    </div>
  </div>

  <div class="health-card" id="enterpriseHealthCard">
    <div class="health-ring-wrap">
      <svg viewBox="0 0 86 86">
        <circle cx="43" cy="43" r="34" fill="none" stroke="var(--surface3)" stroke-width="10"/>
        <circle cx="43" cy="43" r="34" fill="none" stroke="__SCORECOLOR__" stroke-width="10"
          stroke-dasharray="213.6" stroke-dashoffset="213.6" stroke-linecap="round"
          transform="rotate(-90 43 43)" id="enterpriseArc" style="transition:stroke-dashoffset 1.3s ease"/>
      </svg>
      <div class="health-ring-center">
        <span class="health-score-num" id="enterpriseScoreNum" style="color:__SCORECOLOR__">__ENTERPRISESCORE__</span>
        <span class="health-score-pct">/ 100</span>
      </div>
    </div>
    <div class="health-info">
      <h3>Enterprise Posture Score — __ENTERPRISECLASS__</h3>
      <p id="reliabilityNote">__RELIABILITYNOTE__</p>
      <div class="health-bar-row">
        <span style="color:var(--green);font-size:12px">✅ Healthy Tenants</span>
        <div class="health-mini-bar"><div class="health-mini-fill" id="healthyBar" style="background:var(--green);width:0%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)" id="healthyCount">__HEALTHYTENANTS__</span>
      </div>
      <div class="health-bar-row">
        <span style="color:var(--red);font-size:12px">⚠ At-Risk Tenants</span>
        <div class="health-mini-bar"><div class="health-mini-fill" id="atRiskBar" style="background:var(--red);width:0%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)" id="atRiskCount">__ATRISKTENANTS__</span>
      </div>
    </div>
  </div>
  <div id="histBanner" style="margin-bottom:16px"></div>

  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">🏢</div><div class="stat-value">__TOTALTENANTS__</div><div class="stat-label">Total Tenants</div></div>
    <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-value">__HEALTHYTENANTS__</div><div class="stat-label">Healthy Tenants</div></div>
    <div class="stat-card c-red"><div class="stat-icon">🚨</div><div class="stat-value" id="critCount">__CRITICALFINDINGS__</div><div class="stat-label">Critical Findings</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">⚠️</div><div class="stat-value">__HIGHFINDINGS__</div><div class="stat-label">High Findings</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">📊</div><div class="stat-value">__TOTALFINDINGS__</div><div class="stat-label">Total Findings</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">📡</div><div class="stat-value">__COVERAGEPCT__%</div><div class="stat-label">Assessment Coverage</div></div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🎯 Risk Distribution</div>
      <div class="donut-wrap">
        <svg id="riskDonutSvg" viewBox="0 0 180 180" width="160" height="160" flex-shrink="0"></svg>
        <div class="legend-list" id="riskDonutLegend"></div>
      </div>
    </div>
    <div class="panel">
      <div class="section-title">🔐 Domain Scores</div>
      <div id="domainBarsContainer"></div>
    </div>
  </div>

  <div class="panel">
    <div class="section-title">🔴 Top Enterprise Risks</div>
    <div id="topRisksContainer"></div>
  </div>

  <div class="panel">
    <div class="section-title">📊 Tenant Score Distribution</div>
    <div id="tenantScoreBars"></div>
  </div>
</section>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- PAGE: Tenant Posture                                                    -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<section id="page-tenants" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Tenant Posture</div>
      <div class="page-subtitle">Security posture scores and finding distribution per tenant</div>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="tenantSearch" placeholder="Search tenant name, business unit…" oninput="filterTenants()"/>
    </div>
    <select id="tenantClassFilter" onchange="filterTenants()">
      <option value="">All Classifications</option>
      <option>Excellent</option><option>Good</option>
      <option>Needs Improvement</option><option>Poor</option><option>Critical</option>
    </select>
    <span class="result-count" id="tenantCount"></span>
  </div>
  <div class="table-wrap">
    <table class="data-table" id="tenantsTable">
      <thead>
        <tr>
          <th onclick="sortTenants('name')">Tenant <span class="sort-arrow" id="ts-name">↕</span></th>
          <th onclick="sortTenants('bu')">Business Unit <span class="sort-arrow" id="ts-bu">↕</span></th>
          <th onclick="sortTenants('score')">Score <span class="sort-arrow" id="ts-score">↓</span></th>
          <th onclick="sortTenants('compliance')">Compliance <span class="sort-arrow" id="ts-compliance">↕</span></th>
          <th onclick="sortTenants('critical')">Critical <span class="sort-arrow" id="ts-critical">↕</span></th>
          <th onclick="sortTenants('high')">High <span class="sort-arrow" id="ts-high">↕</span></th>
          <th onclick="sortTenants('medium')">Medium <span class="sort-arrow" id="ts-medium">↕</span></th>
          <th onclick="sortTenants('low')">Low <span class="sort-arrow" id="ts-low">↕</span></th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="tenantsTableBody"></tbody>
    </table>
  </div>
  <div class="pagination" id="tenantPagination"></div>
</section>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- PAGE: Domain Analysis                                                   -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<section id="page-domains" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Domain Analysis</div>
      <div class="page-subtitle">Security posture by control domain across all tenants</div>
    </div>
  </div>
  <div id="domainCards" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;margin-bottom:22px"></div>
  <div class="table-wrap">
    <table class="data-table">
      <thead>
        <tr>
          <th>Domain</th>
          <th>Score</th>
          <th>Compliance</th>
          <th>Critical</th>
          <th>High</th>
          <th>Medium</th>
          <th>Low</th>
          <th>Affected Tenants</th>
        </tr>
      </thead>
      <tbody id="domainsTableBody"></tbody>
    </table>
  </div>
</section>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- PAGE: Risk Findings                                                     -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<section id="page-findings" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Risk Findings</div>
      <div class="page-subtitle">All findings — filter by severity, tenant, domain or search</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="dlFile(exportFindingsCSV(),'EntraFindings.csv','text/csv')">⬇ CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="findingSearch" placeholder="Search title, control, tenant…" oninput="filterFindings()"/>
    </div>
    <select id="findingSevFilter" onchange="filterFindings()">
      <option value="">All Severities</option>
      <option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option>
    </select>
    <select id="findingDomainFilter" onchange="filterFindings()">
      <option value="">All Domains</option>
    </select>
    <select id="findingTenantFilter" onchange="filterFindings()">
      <option value="">All Tenants</option>
    </select>
    <span class="result-count" id="findingCount"></span>
  </div>
  <div class="table-wrap">
    <table class="data-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Title</th>
          <th>Tenant</th>
          <th>Domain</th>
          <th>Control</th>
          <th>Status</th>
          <th>Effort</th>
        </tr>
      </thead>
      <tbody id="findingsTableBody"></tbody>
    </table>
  </div>
  <div class="pagination" id="findingPagination"></div>
</section>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- PAGE: Baseline Compliance                                               -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<section id="page-baseline" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Baseline Compliance</div>
      <div class="page-subtitle">Control compliance status across all assessed tenants</div>
    </div>
  </div>
  <div class="stats-grid" style="margin-bottom:22px">
    <div class="stat-card c-blue"><div class="stat-icon">📋</div><div class="stat-value">__TOTALCONTROLS__</div><div class="stat-label">Total Controls</div></div>
    <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-value">__COMPLIANTCONTROLS__</div><div class="stat-label">Compliant Controls</div></div>
    <div class="stat-card c-red"><div class="stat-icon">❌</div><div class="stat-value">__DRIFTEDCONTROLS__</div><div class="stat-label">Drifted Controls</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">📊</div><div class="stat-value">__COMPLIANCEPCT__%</div><div class="stat-label">Compliance %</div></div>
  </div>
  <div class="panel">
    <div class="section-title">🏢 Tenant Compliance</div>
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Tenant</th>
            <th>Total Controls</th>
            <th>Compliant</th>
            <th>Drifted</th>
            <th>Compliance %</th>
          </tr>
        </thead>
        <tbody id="tenantComplianceBody"></tbody>
      </table>
    </div>
  </div>
</section>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- PAGE: Remediation                                                       -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<section id="page-remediation" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Remediation Priority Queue</div>
      <div class="page-subtitle">Enterprise-ranked remediation actions — P0 (Immediate) through P3 (Monitor)</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="dlFile(exportRemCSV(),'EntraRemediation.csv','text/csv')">⬇ CSV</button>
    </div>
  </div>
  <div id="remediationContainer"></div>
</section>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- PAGE: Assessment Coverage                                               -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<section id="page-coverage" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Assessment Coverage</div>
      <div class="page-subtitle">Data collection status and permission coverage per tenant</div>
    </div>
  </div>
  <div id="coverageSummaryCards" class="stats-grid" style="margin-bottom:22px"></div>
  <div class="panel">
    <div class="section-title">📡 Tenant Assessment Status</div>
    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Tenant</th>
            <th>Assessment Status</th>
            <th>Permission Status</th>
            <th>Collector Errors</th>
          </tr>
        </thead>
        <tbody id="coverageTableBody"></tbody>
      </table>
    </div>
  </div>
</section>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- PAGE: Assessment Info                                                   -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<section id="page-info" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Assessment Information</div>
      <div class="page-subtitle">Dashboard metadata, source files and data quality</div>
    </div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">ℹ️ Dashboard Metadata</div>
      <div id="dashMeta"></div>
    </div>
    <div class="panel">
      <div class="section-title">🔍 Data Quality</div>
      <div id="dataQuality"></div>
    </div>
  </div>
  <div class="panel">
    <div class="section-title">📁 Source Assessment Files</div>
    <div id="sourceFiles"></div>
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
      <button id="detailClose" onclick="closeDetail()" title="Close (Esc)">✕</button>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<div id="toast"><span id="toastIcon">✅</span><span id="toastMsg">Done</span></div>

<script>
// ── Data ──────────────────────────────────────────────────────────────────
const TENANTS    = [__TENANTS_JSON__];
const DOMAINS    = [__DOMAINS_JSON__];
const FINDINGS   = [__FINDINGS_JSON__];
const TOP_RISKS  = [__TOPRISKS_JSON__];
const REMEDIATION= [__REMEDIATION_JSON__];
const COVERAGE_T = [__COVERAGET_JSON__];
const SRC_FILES  = [__SRCFILES_JSON__];
const HIST       = __HIST_JSON__;

const ENT_SCORE  = __ENTERPRISESCORE__;
const ENT_CLASS  = '__ENTERPRISECLASS__';
const SCORE_COLOR= '__SCORECOLOR__';
const TOTAL_T    = __TOTALTENANTS__;
const HEALTHY_T  = __HEALTHYTENANTS__;
const ATRISK_T   = __ATRISKTENANTS__;
const CRIT_F     = __CRITICALFINDINGS__;
const HIGH_F     = __HIGHFINDINGS__;
const MED_F      = __MEDIUMFINDINGS__;
const LOW_F      = __LOWFINDINGS__;
const TOTAL_F    = __TOTALFINDINGS__;
const COV_PCT    = __COVERAGEPCT__;
const COV_OK     = __COVISRELIABLE__;
const TOTAL_CTRL = __TOTALCONTROLS__;
const COMP_CTRL  = __COMPLIANTCONTROLS__;
const DRIFT_CTRL = __DRIFTEDCONTROLS__;
const COMP_PCT   = __COMPLIANCEPCT__;
const COV_SUCCESS = __COVSUCCESS__;
const COV_PARTIAL = __COVPARTIAL__;
const COV_FAILED  = __COVFAILED__;

const DQ = __DQJSON__;

const PALETTE = ['#3b82f6','#ef4444','#f59e0b','#10b981','#8b5cf6','#06b6d4','#ec4899','#84cc16'];

// ── Utils ─────────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
function dlFile(content,name,type){const b=new Blob([content],{type});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=name;a.click();URL.revokeObjectURL(u);}
let _toastT;
function showToast(msg,icon='✅'){document.getElementById('toastMsg').textContent=msg;document.getElementById('toastIcon').textContent=icon;const el=document.getElementById('toast');el.classList.add('show');clearTimeout(_toastT);_toastT=setTimeout(()=>el.classList.remove('show'),2600);}

// ── Theme ─────────────────────────────────────────────────────────────────
function toggleTheme(){const light=document.body.classList.toggle('light-theme');document.getElementById('themeIcon').textContent=light?'☀️':'🌙';document.getElementById('themeLabel').textContent=light?'Light Mode':'Dark Mode';try{localStorage.setItem('entra-dash-theme',light?'light':'dark');}catch(e){}}
(function(){try{if(localStorage.getItem('entra-dash-theme')==='light'){document.body.classList.add('light-theme');document.getElementById('themeIcon').textContent='☀️';document.getElementById('themeLabel').textContent='Light Mode';}}catch(e){}})();

// ── Navigation ────────────────────────────────────────────────────────────
function showPage(id,btn){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));document.getElementById('page-'+id).classList.add('active');if(btn)btn.classList.add('active');}

// ── Score ring ────────────────────────────────────────────────────────────
(function(){
  const arc=document.getElementById('enterpriseArc');
  const circ=2*Math.PI*34;
  requestAnimationFrame(()=>requestAnimationFrame(()=>{arc.style.strokeDashoffset=circ*(1-ENT_SCORE/100);}));
  const ht=TENANTS.filter(t=>t.score>=75).length;
  const total=TENANTS.length||1;
  document.getElementById('healthyBar').style.width=(ht/total*100)+'%';
  document.getElementById('atRiskBar').style.width=((total-ht)/total*100)+'%';
})();

// ── Historical banner ─────────────────────────────────────────────────────
(function(){
  if(!HIST) return;
  const el=document.getElementById('histBanner');
  const ch=HIST.change; const arrow=ch>0?'↑':ch<0?'↓':'→';
  const col=ch>0?'var(--green)':ch<0?'var(--red)':'var(--muted)';
  el.innerHTML=`<div class="hist-card">
    <div class="hist-stat"><div class="hist-val" style="color:var(--muted)">${HIST.prevScore}</div><div class="hist-lbl">Previous Score</div></div>
    <div class="hist-stat"><div class="hist-val" style="color:${SCORE_COLOR}">${HIST.currScore}</div><div class="hist-lbl">Current Score</div></div>
    <div class="hist-stat"><div class="hist-val" style="color:${col}">${arrow} ${Math.abs(ch)}</div><div class="hist-lbl">Score Change</div></div>
    <div class="hist-stat"><div class="hist-val" style="color:var(--red)">${HIST.newFindings}</div><div class="hist-lbl">New Findings</div></div>
    <div class="hist-stat"><div class="hist-val" style="color:var(--green)">${HIST.resolvedFindings}</div><div class="hist-lbl">Resolved</div></div>
    <div class="hist-stat"><div class="hist-val">${HIST.persistentFindings}</div><div class="hist-lbl">Persistent</div></div>
  </div>`;
})();

// ── Risk donut ────────────────────────────────────────────────────────────
(function(){
  const data=[{label:'Critical',count:CRIT_F,col:'#f85149'},{label:'High',count:HIGH_F,col:'#d29922'},{label:'Medium',count:MED_F,col:'#388bfd'},{label:'Low',count:LOW_F,col:'#3fb950'}].filter(d=>d.count>0);
  const svg=document.getElementById('riskDonutSvg');
  const leg=document.getElementById('riskDonutLegend');
  const total=data.reduce((s,d)=>s+d.count,0)||1;
  const R=68,cx=90,cy=90,stroke=24,circ=2*Math.PI*R;
  let offset=0;
  data.forEach((d,i)=>{
    const frac=d.count/total,drawFrac=Math.max(0,frac-(1.5/360));
    const dl=drawFrac*circ,gap=circ-dl;
    const c=document.createElementNS('http://www.w3.org/2000/svg','circle');
    c.setAttribute('cx',cx);c.setAttribute('cy',cy);c.setAttribute('r',R);
    c.setAttribute('fill','none');c.setAttribute('stroke',d.col);c.setAttribute('stroke-width',stroke);
    c.setAttribute('stroke-dasharray',`${dl} ${gap}`);
    const fo=-(offset*circ)+circ*0.25;
    c.setAttribute('stroke-dashoffset',circ);c.style.transition=`stroke-dashoffset 0.9s cubic-bezier(.4,0,.2,1) ${i*0.08}s`;
    svg.appendChild(c);requestAnimationFrame(()=>requestAnimationFrame(()=>{c.style.strokeDashoffset=fo;}));
    offset+=frac;
    const pct=Math.round(frac*100);
    leg.innerHTML+=`<div class="legend-item"><span class="legend-dot" style="background:${d.col}"></span><span>${d.label}</span><span class="legend-pct">${d.count} (${pct}%)</span></div>`;
  });
  const mk=(y,sz,fw,fill,txt)=>{const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',cx);t.setAttribute('y',y);t.setAttribute('text-anchor','middle');t.setAttribute('fill',fill);t.setAttribute('font-size',sz);t.setAttribute('font-weight',fw);t.textContent=txt;svg.appendChild(t);};
  mk(cy-6,'20','800','#e2e8f0',total);mk(cy+12,'10','400','#64748b','findings');
})();

// ── Domain bars (overview) ─────────────────────────────────────────────────
(function(){
  const el=document.getElementById('domainBarsContainer');
  const sorted=[...DOMAINS].sort((a,b)=>a.score-b.score);
  sorted.forEach(d=>{
    const col=d.score>=90?'#3fb950':d.score>=75?'#3fb950':d.score>=60?'#d29922':'#f85149';
    el.innerHTML+=`<div class="bar-row">
      <span class="bar-label" title="${escH(d.domain)}">${escH(d.domain)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:0%;background:${col}" data-pct="${d.score}"></div></div>
      <span class="bar-count">${d.score}</span></div>`;
  });
  requestAnimationFrame(()=>{document.querySelectorAll('#domainBarsContainer .bar-fill').forEach(b=>{b.style.width=b.dataset.pct+'%';});});
})();

// ── Tenant score bars (overview) ───────────────────────────────────────────
(function(){
  const el=document.getElementById('tenantScoreBars');
  const sorted=[...TENANTS].sort((a,b)=>a.score-b.score);
  sorted.forEach(t=>{
    const col=t.score>=90?'#3fb950':t.score>=75?'#3fb950':t.score>=60?'#d29922':'#f85149';
    el.innerHTML+=`<div class="bar-row">
      <span class="bar-label" title="${escH(t.name)}">${escH(t.name)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:0%;background:${col}" data-pct="${t.score}"></div></div>
      <span class="bar-count">${t.score}</span></div>`;
  });
  requestAnimationFrame(()=>{document.querySelectorAll('#tenantScoreBars .bar-fill').forEach(b=>{b.style.width=b.dataset.pct+'%';});});
})();

// ── Top risks ──────────────────────────────────────────────────────────────
(function(){
  const el=document.getElementById('topRisksContainer');
  if(!TOP_RISKS.length){el.innerHTML='<p style="color:var(--muted)">No open findings.</p>';return;}
  TOP_RISKS.slice(0,10).forEach((r,i)=>{
    el.innerHTML+=`<div class="risk-item">
      <div class="risk-rank">#${i+1}</div>
      <div class="risk-body">
        <div class="risk-title">${escH(r.title)}</div>
        <div class="risk-meta">
          <span class="sev-badge sev-${r.sev.toLowerCase()}">${escH(r.sev)}</span>
          <span>🏢 ${r.tenants} tenant(s)</span>
          <span>🔐 ${escH(r.domain)}</span>
          ${r.impact&&r.impact!=='Not specified'?`<span title="${escH(r.impact)}">💥 ${escH(r.impact.length>60?r.impact.substring(0,60)+'…':r.impact)}</span>`:''}
        </div>
      </div></div>`;
  });
})();

// ── Score pill helper ──────────────────────────────────────────────────────
function scorePill(score,cls){
  const cmap={'Excellent':'excellent','Good':'good','Needs Improvement':'improve','Poor':'poor','Critical':'critical'};
  const c=cmap[cls]||'critical';
  return `<span class="score-pill score-${c}">${score}</span>`;
}

// ── Tenants table ──────────────────────────────────────────────────────────
let filteredTenants=[...TENANTS].sort((a,b)=>b.score-a.score);
let tenantPage=1;const TENANT_PAGE_SIZE=20;
let tenantSortCol='score';let tenantSortDir='desc';

function filterTenants(){
  const q=document.getElementById('tenantSearch').value.toLowerCase().trim();
  const cls=document.getElementById('tenantClassFilter').value;
  filteredTenants=TENANTS.filter(t=>{
    const mQ=!q||t.name.toLowerCase().includes(q)||t.bu.toLowerCase().includes(q)||t.id.toLowerCase().includes(q);
    const mC=!cls||t.class===cls;
    return mQ&&mC;
  });
  sortTenants(tenantSortCol,true);
  tenantPage=1;renderTenants();
}

function sortTenants(col,noFlip){
  if(!noFlip){if(tenantSortCol===col){tenantSortDir=tenantSortDir==='asc'?'desc':'asc';}else{tenantSortCol=col;tenantSortDir=col==='score'||col==='critical'||col==='high'?'desc':'asc';}}
  const dirs=tenantSortDir==='asc'?1:-1;
  filteredTenants.sort((a,b)=>{
    const av=a[col]??''; const bv=b[col]??'';
    return typeof av==='number'?((av-bv)*dirs):String(av).localeCompare(String(bv))*dirs;
  });
  document.querySelectorAll('#ts-name,#ts-bu,#ts-score,#ts-compliance,#ts-critical,#ts-high,#ts-medium,#ts-low').forEach(el=>el.textContent='↕');
  const arrow=document.getElementById('ts-'+col);if(arrow)arrow.textContent=tenantSortDir==='asc'?'↑':'↓';
  renderTenants();
}

function renderTenants(){
  const start=(tenantPage-1)*TENANT_PAGE_SIZE;
  const slice=filteredTenants.slice(start,start+TENANT_PAGE_SIZE);
  document.getElementById('tenantCount').textContent=`${filteredTenants.length} of ${TENANTS.length}`;
  document.getElementById('tenantsTableBody').innerHTML=slice.map((t,idx)=>{
    const statusCol=t.status.match(/Success|Complete/i)?'var(--green)':t.status.match(/Partial/i)?'var(--amber)':'var(--red)';
    return `<tr onclick="openTenantDetail(${start+idx})">
      <td class="td-mono" style="color:var(--accent2)">${escH(t.name)}</td>
      <td class="td-muted">${escH(t.bu)}</td>
      <td>${scorePill(t.score,t.class)}</td>
      <td class="td-mono">${t.compliance}%</td>
      <td class="td-mono" style="color:${t.critical>0?'var(--red)':'var(--muted)'}">${t.critical}</td>
      <td class="td-mono" style="color:${t.high>0?'var(--amber)':'var(--muted)'}">${t.high}</td>
      <td class="td-mono">${t.medium}</td>
      <td class="td-mono">${t.low}</td>
      <td><span style="font-family:var(--mono);font-size:11px;color:${statusCol}">${escH(t.status)}</span></td>
    </tr>`;
  }).join('');
  renderTenantPagination();
}

function renderTenantPagination(){
  const total=Math.ceil(filteredTenants.length/TENANT_PAGE_SIZE);
  const el=document.getElementById('tenantPagination');
  if(total<=1){el.innerHTML='';return;}
  let h=`<button class="page-btn" onclick="goTenantPage(${tenantPage-1})" ${tenantPage===1?'disabled':''}>‹</button>`;
  for(let i=1;i<=total;i++){
    if(i===1||i===total||Math.abs(i-tenantPage)<=1)h+=`<button class="page-btn ${i===tenantPage?'active':''}" onclick="goTenantPage(${i})">${i}</button>`;
    else if(Math.abs(i-tenantPage)===2)h+=`<span style="color:var(--muted);padding:0 4px">…</span>`;
  }
  h+=`<button class="page-btn" onclick="goTenantPage(${tenantPage+1})" ${tenantPage===total?'disabled':''}>›</button>`;
  el.innerHTML=h;
}
function goTenantPage(p){const total=Math.ceil(filteredTenants.length/TENANT_PAGE_SIZE);if(p<1||p>total)return;tenantPage=p;renderTenants();}

// Detail drawer state
let currentDetailList=[],currentDetailIdx=0,currentDetailType='';
function openDetail(type,idx){currentDetailType=type;currentDetailIdx=idx;renderDetail();document.getElementById('detailPanel').classList.add('open');}
function closeDetail(){document.getElementById('detailPanel').classList.remove('open');}
function navigateDetail(dir){const next=currentDetailIdx+dir;if(next>=0&&next<currentDetailList.length){currentDetailIdx=next;renderDetail();}}

function openTenantDetail(idx){
  currentDetailList=filteredTenants;currentDetailIdx=idx;currentDetailType='tenant';
  renderDetail();document.getElementById('detailPanel').classList.add('open');
}
function openFindingDetail(idx){
  currentDetailList=filteredFindings;currentDetailIdx=idx;currentDetailType='finding';
  renderDetail();document.getElementById('detailPanel').classList.add('open');
}

function renderDetail(){
  const prevBtn=document.getElementById('detailPrevBtn');
  const nextBtn=document.getElementById('detailNextBtn');
  prevBtn.disabled=currentDetailIdx<=0;
  nextBtn.disabled=currentDetailIdx>=currentDetailList.length-1;
  const item=currentDetailList[currentDetailIdx];
  if(!item)return;
  const el=document.getElementById('detailContent');
  if(currentDetailType==='tenant'){
    el.innerHTML=`
      <div class="detail-header">
        <div class="detail-name">${escH(item.name)}</div>
        <div class="detail-meta-row">
          ${scorePill(item.score,item.class)}
          <span class="detail-chip">${escH(item.bu)}</span>
          <span class="detail-chip">${escH(item.status)}</span>
          <span class="detail-chip">Compliance: ${item.compliance}%</span>
        </div>
      </div>
      <div class="detail-section">
        <div class="detail-section-title">Finding Distribution</div>
        <div class="stats-grid" style="margin-bottom:0">
          <div class="stat-card c-red"><div class="stat-icon">🚨</div><div class="stat-value">${item.critical}</div><div class="stat-label">Critical</div></div>
          <div class="stat-card c-amber"><div class="stat-icon">⚠️</div><div class="stat-value">${item.high}</div><div class="stat-label">High</div></div>
          <div class="stat-card c-blue"><div class="stat-icon">📋</div><div class="stat-value">${item.medium}</div><div class="stat-label">Medium</div></div>
          <div class="stat-card c-green"><div class="stat-icon">ℹ️</div><div class="stat-value">${item.low}</div><div class="stat-label">Low</div></div>
        </div>
      </div>`;
  } else if(currentDetailType==='finding'){
    el.innerHTML=`
      <div class="detail-header">
        <div class="detail-name">${escH(item.title)}</div>
        <div class="detail-meta-row">
          <span class="sev-badge sev-${item.sev.toLowerCase()}">${escH(item.sev)}</span>
          <span class="detail-chip">${escH(item.domain)}</span>
          <span class="detail-chip">${escH(item.tenant)}</span>
          <span class="detail-chip">${escH(item.status)}</span>
        </div>
      </div>
      ${item.impact&&item.impact!=='Not specified'?`<div class="detail-section"><div class="detail-section-title">Business Impact</div><div class="detail-text">${escH(item.impact)}</div></div>`:''}
      ${item.rec?`<div class="detail-section"><div class="detail-section-title">Recommended Action</div><div class="detail-text">${escH(item.rec)}</div></div>`:''}
      <div class="detail-section">
        <div class="detail-section-title">Details</div>
        <div class="dq-row"><span>Control ID</span><span class="dq-val">${escH(item.control)}</span></div>
        <div class="dq-row"><span>Effort</span><span class="dq-val">${escH(item.effort)}</span></div>
        <div class="dq-row"><span>Finding ID</span><span class="dq-val" style="font-size:11px">${escH(item.fid)}</span></div>
      </div>`;
  }
}

// ── Domains page ───────────────────────────────────────────────────────────
(function(){
  const cards=document.getElementById('domainCards');
  const body=document.getElementById('domainsTableBody');
  const sorted=[...DOMAINS].sort((a,b)=>b.score-a.score);
  sorted.forEach(d=>{
    const col=d.score>=90?'var(--green)':d.score>=75?'var(--green)':d.score>=60?'var(--amber)':'var(--red)';
    const icon={'ConditionalAccess':'🔒','MFA':'🔑','PIM':'👑','ExternalIdentity':'🌐'}[d.domain]||'🔐';
    cards.innerHTML+=`<div class="panel" style="margin-bottom:0">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <span style="font-size:22px">${icon}</span>
        <div><div style="font-weight:700;font-size:15px">${escH(d.domain)}</div>
        <div style="font-size:11px;color:var(--muted)">${escH(d.class)}</div></div>
        <div style="margin-left:auto">${scorePill(d.score,d.class)}</div>
      </div>
      <div class="health-bar-row"><span style="font-size:12px">Compliance</span>
        <div class="health-mini-bar"><div class="health-mini-fill" style="background:${col};width:${d.compliance}%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">${d.compliance}%</span>
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        ${d.critical>0?`<span class="sev-badge sev-critical">Critical: ${d.critical}</span>`:''}
        ${d.high>0?`<span class="sev-badge sev-high">High: ${d.high}</span>`:''}
        ${d.medium>0?`<span class="sev-badge sev-medium">Medium: ${d.medium}</span>`:''}
        ${d.low>0?`<span class="sev-badge sev-low">Low: ${d.low}</span>`:''}
      </div></div>`;
    body.innerHTML+=`<tr>
      <td><span style="font-weight:700">${icon} ${escH(d.domain)}</span></td>
      <td>${scorePill(d.score,d.class)}</td>
      <td class="td-mono">${d.compliance}%</td>
      <td class="td-mono" style="color:${d.critical>0?'var(--red)':'var(--muted)'}">${d.critical}</td>
      <td class="td-mono" style="color:${d.high>0?'var(--amber)':'var(--muted)'}">${d.high}</td>
      <td class="td-mono">${d.medium}</td>
      <td class="td-mono">${d.low}</td>
      <td class="td-mono">${d.affectedTenants}</td>
    </tr>`;
  });
})();

// ── Findings table ─────────────────────────────────────────────────────────
let filteredFindings=[...FINDINGS].sort((a,b)=>a.sevOrd-b.sevOrd);
let findingPage=1; const FINDING_PAGE_SIZE=25;

(function(){
  const dSel=document.getElementById('findingDomainFilter');
  const tSel=document.getElementById('findingTenantFilter');
  const domains=[...new Set(FINDINGS.map(f=>f.domain))].sort();
  const tenants=[...new Set(FINDINGS.map(f=>f.tenant))].sort();
  domains.forEach(d=>{const o=document.createElement('option');o.value=d;o.textContent=d;dSel.appendChild(o);});
  tenants.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;tSel.appendChild(o);});
  renderFindings();
})();

function filterFindings(){
  const q=document.getElementById('findingSearch').value.toLowerCase().trim();
  const sev=document.getElementById('findingSevFilter').value;
  const dom=document.getElementById('findingDomainFilter').value;
  const ten=document.getElementById('findingTenantFilter').value;
  filteredFindings=FINDINGS.filter(f=>{
    const mQ=!q||f.title.toLowerCase().includes(q)||f.control.toLowerCase().includes(q)||f.tenant.toLowerCase().includes(q)||f.fid.toLowerCase().includes(q);
    const mS=!sev||f.sev===sev;
    const mD=!dom||f.domain===dom;
    const mT=!ten||f.tenant===ten;
    return mQ&&mS&&mD&&mT;
  }).sort((a,b)=>a.sevOrd-b.sevOrd);
  findingPage=1;renderFindings();
}

function renderFindings(){
  const start=(findingPage-1)*FINDING_PAGE_SIZE;
  const slice=filteredFindings.slice(start,start+FINDING_PAGE_SIZE);
  document.getElementById('findingCount').textContent=`${filteredFindings.length} of ${FINDINGS.length}`;
  document.getElementById('findingsTableBody').innerHTML=slice.map((f,idx)=>`
    <tr onclick="openFindingDetail(${start+idx})">
      <td><span class="sev-badge sev-${f.sev.toLowerCase()}">${escH(f.sev)}</span></td>
      <td style="max-width:280px"><span style="display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px" title="${escH(f.title)}">${escH(f.title)}</span></td>
      <td class="td-mono" style="color:var(--accent2);font-size:12px">${escH(f.tenant)}</td>
      <td class="td-muted">${escH(f.domain)}</td>
      <td class="td-mono" style="font-size:12px">${escH(f.control)}</td>
      <td><span style="font-family:var(--mono);font-size:11px;color:var(--muted2)">${escH(f.status)}</span></td>
      <td class="td-muted">${escH(f.effort)}</td>
    </tr>`).join('');
  renderFindingPagination();
}

function renderFindingPagination(){
  const total=Math.ceil(filteredFindings.length/FINDING_PAGE_SIZE);
  const el=document.getElementById('findingPagination');
  if(total<=1){el.innerHTML='';return;}
  let h=`<button class="page-btn" onclick="goFindingPage(${findingPage-1})" ${findingPage===1?'disabled':''}>‹</button>`;
  for(let i=1;i<=total;i++){
    if(i===1||i===total||Math.abs(i-findingPage)<=1)h+=`<button class="page-btn ${i===findingPage?'active':''}" onclick="goFindingPage(${i})">${i}</button>`;
    else if(Math.abs(i-findingPage)===2)h+=`<span style="color:var(--muted);padding:0 4px">…</span>`;
  }
  h+=`<button class="page-btn" onclick="goFindingPage(${findingPage+1})" ${findingPage===total?'disabled':''}>›</button>`;
  el.innerHTML=h;
}
function goFindingPage(p){const total=Math.ceil(filteredFindings.length/FINDING_PAGE_SIZE);if(p<1||p>total)return;findingPage=p;renderFindings();}

// ── Baseline compliance page ────────────────────────────────────────────────
(function(){
  const body=document.getElementById('tenantComplianceBody');
  const data=TENANTS.map(t=>({name:t.name,total:TOTAL_CTRL,drifted:0,compliant:0,pct:t.compliance}));
  data.forEach(t=>{
    const col=t.pct>=90?'var(--green)':t.pct>=75?'var(--green)':t.pct>=60?'var(--amber)':'var(--red)';
    body.innerHTML+=`<tr>
      <td style="font-family:var(--mono);font-size:12.5px;color:var(--accent2)">${escH(t.name)}</td>
      <td class="td-mono">${t.total}</td>
      <td class="td-mono" style="color:var(--green)">${Math.round(t.total*(t.pct/100))}</td>
      <td class="td-mono" style="color:var(--red)">${Math.round(t.total*(1-t.pct/100))}</td>
      <td><div class="health-bar-row" style="margin:0;gap:8px">
        <div class="health-mini-bar" style="min-width:80px"><div class="health-mini-fill" style="background:${col};width:${t.pct}%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:${col}">${t.pct}%</span>
      </div></td>
    </tr>`;
  });
})();

// ── Remediation page ────────────────────────────────────────────────────────
(function(){
  const el=document.getElementById('remediationContainer');
  const groups={'P0':[],'P1':[],'P2':[],'P3':[]};
  REMEDIATION.forEach(r=>{if(groups[r.priority])groups[r.priority].push(r);});
  ['P0','P1','P2','P3'].forEach(p=>{
    if(!groups[p].length)return;
    const labels={'P0':'🔴 P0 — Immediate','P1':'🟠 P1 — High','P2':'🔵 P2 — Planned','P3':'🟢 P3 — Monitor'};
    el.innerHTML+=`<div class="panel"><div class="section-title">${labels[p]}</div>`;
    groups[p].forEach(r=>{
      el.innerHTML+=`<div class="risk-item">
        <div class="risk-rank">#${r.rank}</div>
        <div class="risk-body">
          <div class="risk-title">${escH(r.title)}</div>
          <div class="risk-meta" style="margin-bottom:6px">
            <span class="sev-badge sev-${r.sev.toLowerCase()}">${escH(r.sev)}</span>
            <span class="priority-badge ${r.priority.toLowerCase()}">${escH(r.priority)}</span>
            <span>🏢 ${r.tenants} tenant(s)</span>
            <span>🔐 ${escH(r.domain)}</span>
            <span>⏱ ${escH(r.effort)} effort</span>
          </div>
          ${r.impact&&r.impact!=='Not specified'?`<div style="font-size:12.5px;color:var(--muted2);margin-bottom:4px">💥 ${escH(r.impact)}</div>`:''}
          ${r.action?`<div style="font-size:12.5px;color:var(--muted2)">🔧 ${escH(r.action)}</div>`:''}
        </div></div>`;
    });
    el.innerHTML+='</div>';
  });
  if(!el.innerHTML)el.innerHTML='<div class="panel"><p style="color:var(--muted)">No remediation items identified.</p></div>';
})();

// ── Coverage page ───────────────────────────────────────────────────────────
(function(){
  const cards=document.getElementById('coverageSummaryCards');
  const covCol=COV_PCT>=95?'c-green':COV_PCT>=75?'c-cyan':COV_PCT>=50?'c-amber':'c-red';
  cards.innerHTML=`
    <div class="stat-card ${covCol}"><div class="stat-icon">📡</div><div class="stat-value">${COV_PCT}%</div><div class="stat-label">Coverage</div></div>
    <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-value">${COV_SUCCESS}</div><div class="stat-label">Successfully Assessed</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">⚠️</div><div class="stat-value">${COV_PARTIAL}</div><div class="stat-label">Partially Assessed</div></div>
    <div class="stat-card c-red"><div class="stat-icon">❌</div><div class="stat-value">${COV_FAILED}</div><div class="stat-label">Failed Assessments</div></div>`;
  const body=document.getElementById('coverageTableBody');
  COVERAGE_T.forEach(t=>{
    const statusCol=t.status.match(/Success|Complete/i)?'var(--green)':t.status.match(/Partial/i)?'var(--amber)':'var(--red)';
    const permCol=t.perms.match(/Granted|OK|Success/i)?'var(--green)':t.perms.match(/Denied|Insufficient/i)?'var(--red)':'var(--muted2)';
    body.innerHTML+=`<tr>
      <td style="font-family:var(--mono);font-size:12.5px;color:var(--accent2)">${escH(t.name||t.id)}</td>
      <td><span style="font-family:var(--mono);font-size:11px;color:${statusCol}">${escH(t.status)}</span></td>
      <td><span style="font-family:var(--mono);font-size:11px;color:${permCol}">${escH(t.perms)}</span></td>
      <td class="td-mono" style="color:${t.errors>0?'var(--amber)':'var(--muted)'}">${t.errors}</td>
    </tr>`;
  });
})();

// ── Info page ───────────────────────────────────────────────────────────────
(function(){
  const meta=document.getElementById('dashMeta');
  meta.innerHTML=`
    <div class="dq-row"><span>Dashboard Version</span><span class="dq-val">v${escH('__DASHVER__')}</span></div>
    <div class="dq-row"><span>Generated At</span><span class="dq-val" style="font-size:11px">${escH('__GENERATEDAT__')}</span></div>
    <div class="dq-row"><span>Assessments Loaded</span><span class="dq-val">${SRC_FILES.length}</span></div>
    <div class="dq-row"><span>Assessment Versions</span><span class="dq-val">${escH(DQ.assessmentVersions?.join(', ')||'—')}</span></div>
    <div class="dq-row"><span>Baseline Versions</span><span class="dq-val">${escH(DQ.baselineVersions?.join(', ')||'—')}</span></div>`;
  const dq=document.getElementById('dataQuality');
  dq.innerHTML=`
    <div class="dq-row"><span>Input Files</span><span class="dq-val">${DQ.inputFiles}</span></div>
    <div class="dq-row"><span>Valid Files</span><span class="dq-val" style="color:var(--green)">${DQ.validFiles}</span></div>
    <div class="dq-row"><span>Rejected Files</span><span class="dq-val" style="color:${DQ.rejectedCount>0?'var(--red)':'var(--muted)'}">${DQ.rejectedCount}</span></div>
    <div class="dq-row"><span>Duplicate Assessments</span><span class="dq-val" style="color:${DQ.duplicateAssessments>0?'var(--amber)':'var(--muted)'}">${DQ.duplicateAssessments}</span></div>
    <div class="dq-row"><span>Incomplete Findings</span><span class="dq-val" style="color:${DQ.incompleteFindings>0?'var(--amber)':'var(--muted)'}">${DQ.incompleteFindings}</span></div>
    <div class="dq-row"><span>Tenants Normalized</span><span class="dq-val">${DQ.tenantCount}</span></div>
    <div class="dq-row"><span>Controls Loaded</span><span class="dq-val">${DQ.controlCount}</span></div>
    <div class="dq-row"><span>Findings Loaded</span><span class="dq-val">${DQ.findingCount}</span></div>`;
  const sf=document.getElementById('sourceFiles');
  if(!SRC_FILES.length){sf.innerHTML='<p style="color:var(--muted)">No source files.</p>';return;}
  SRC_FILES.forEach(s=>{
    sf.innerHTML+=`<div class="risk-item" style="cursor:default">
      <div class="risk-body">
        <div class="risk-title" style="font-family:var(--mono);font-size:12px">${escH(s.sourceFile)}</div>
        <div class="risk-meta">
          <span class="detail-chip">ID: ${escH(s.assessmentId)}</span>
          <span class="detail-chip">Generated: ${escH(s.generatedAt)}</span>
          ${s.assessmentVersion?`<span class="detail-chip">v${escH(s.assessmentVersion)}</span>`:''}
          ${s.baselineVersion?`<span class="detail-chip">Baseline: ${escH(s.baselineVersion)}</span>`:''}
        </div>
      </div></div>`;
  });
})();

// ── Export helpers ─────────────────────────────────────────────────────────
function exportFindingsCSV(){
  const rows=[['FindingId','Tenant','Domain','Control','Severity','Title','BusinessImpact','Recommendation','Effort','Status']];
  filteredFindings.forEach(f=>rows.push([f.fid,f.tenant,f.domain,f.control,f.sev,f.title,f.impact,f.rec,f.effort,f.status]));
  return rows.map(r=>r.map(v=>'"'+String(v||'').replace(/"/g,'""')+'"').join(',')).join('\r\n');
}
function exportRemCSV(){
  const rows=[['Priority','Rank','Title','Domain','Severity','AffectedTenants','BusinessImpact','RecommendedAction','EstimatedEffort']];
  REMEDIATION.forEach(r=>rows.push([r.priority,r.rank,r.title,r.domain,r.sev,r.tenants,r.impact,r.action,r.effort]));
  return rows.map(r=>r.map(v=>'"'+String(v||'').replace(/"/g,'""')+'"').join(',')).join('\r\n');
}

// ── Keyboard shortcuts ─────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closeDetail();return;}
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'&&document.activeElement.tagName!=='SELECT'){
    e.preventDefault();const inp=document.querySelector('.page.active input[type=text]');if(inp)inp.focus();
  }
  if(document.getElementById('detailPanel').classList.contains('open')){
    if(e.key==='ArrowLeft')navigateDetail(-1);
    if(e.key==='ArrowRight')navigateDetail(1);
  }
});

// ── Init ────────────────────────────────────────────────────────────────────
filterTenants();
</script>
</body>
</html>
'@

    #──────────────────────────────────────────────────────────────────────────
    # Compute scalar tokens
    #──────────────────────────────────────────────────────────────────────────

    $healthyTenants = ($TenantScores | Where-Object { $_.PostureScore -ge 75 }).Count
    $atRiskTenants = ($TenantScores | Where-Object { $_.PostureScore -lt 75 }).Count
    $enterpriseClass = $EnterpriseScore.Classification
    $reliNote = [string]$EnterpriseScore.ReliabilityNote
    $reliNoteSafe = ConvertTo-DashboardJsonSafe $reliNote
    $isReliable = if ($EnterpriseScore.IsReliable) { 'true' } else { 'false' }
    $covSuccess = $Coverage.SuccessfullyAssessed
    $covPartial = $Coverage.PartiallyAssessed
    $covFailed = $Coverage.FailedAssessments

    # Data Quality as JSON
    $dqJson = "{`"inputFiles`":$($DataQuality.InputFiles),`"validFiles`":$($DataQuality.ValidFiles),`"rejectedCount`":$($DataQuality.RejectedCount),`"duplicateAssessments`":$($DataQuality.DuplicateAssessments),`"incompleteFindings`":$($DataQuality.IncompleteFindings),`"tenantCount`":$($DataQuality.TenantCount),`"controlCount`":$($DataQuality.ControlCount),`"findingCount`":$($DataQuality.FindingCount),`"assessmentVersions`":[$(($DataQuality.AssessmentVersions | ForEach-Object { "`"$(ConvertTo-DashboardJsonSafe $_)`"" }) -join ',')],`"baselineVersions`":[$(($DataQuality.BaselineVersions | ForEach-Object { "`"$(ConvertTo-DashboardJsonSafe $_)`"" }) -join ',')]}"

    #──────────────────────────────────────────────────────────────────────────
    # Substitution chain
    #──────────────────────────────────────────────────────────────────────────

    $html = $html `
        -replace '__DASHVER__', $Script:DashboardVersion `
        -replace '__GENERATEDAT__', $generatedAt `
        -replace '__ENTERPRISESCORE__', $EnterpriseScore.Score `
        -replace '__ENTERPRISECLASS__', $enterpriseClass `
        -replace '__SCORECOLOR__', $scoreColor `
        -replace '__RELIABILITYNOTE__', $reliNote `
        -replace '__TOTALTENANTS__', $TenantScores.Count `
        -replace '__HEALTHYTENANTS__', $healthyTenants `
        -replace '__ATRISKTENANTS__', $atRiskTenants `
        -replace '__CRITICALFINDINGS__', $RiskSummary.Critical `
        -replace '__HIGHFINDINGS__', $RiskSummary.High `
        -replace '__MEDIUMFINDINGS__', $RiskSummary.Medium `
        -replace '__LOWFINDINGS__', $RiskSummary.Low `
        -replace '__TOTALFINDINGS__', $RiskSummary.TotalFindings `
        -replace '__COVERAGEPCT__', $Coverage.CoveragePercentage `
        -replace '__COVISRELIABLE__', $isReliable `
        -replace '__TOTALCONTROLS__', $BaselineCompliance.TotalControls `
        -replace '__COMPLIANTCONTROLS__', $BaselineCompliance.CompliantControls `
        -replace '__DRIFTEDCONTROLS__', $BaselineCompliance.DriftedControls `
        -replace '__COMPLIANCEPCT__', $BaselineCompliance.CompliancePercentage `
        -replace '__COVSUCCESS__', $covSuccess `
        -replace '__COVPARTIAL__', $covPartial `
        -replace '__COVFAILED__', $covFailed `
        -replace '__TENANTS_JSON__', $tenantsJson `
        -replace '__DOMAINS_JSON__', $domainsJson `
        -replace '__FINDINGS_JSON__', $findingsJson `
        -replace '__TOPRISKS_JSON__', $topRisksJson `
        -replace '__REMEDIATION_JSON__', $remJson `
        -replace '__COVERAGET_JSON__', $coverageTenJson `
        -replace '__SRCFILES_JSON__', $srcFilesJson `
        -replace '__HIST_JSON__', $histJson `
        -replace '__DQJSON__', $dqJson

    try {
        $html | Out-File -FilePath $outFile -Encoding UTF8 -Force -ErrorAction Stop
        Write-AssessmentLog -Context $Context -Level 'INFO' `
            -Message 'HTML dashboard written' -Detail $outFile
        Write-Host "  🌐  HTML: $outFile" -ForegroundColor White
    }
    catch {
        Write-AssessmentLog -Context $Context -Level 'ERROR' `
            -Message "Failed to write HTML dashboard: $($_.Exception.Message)" -Detail $outFile
        Write-Warning "Could not write HTML dashboard to '$outFile': $($_.Exception.Message)"
    }

    return $outFile
}

#endregion

#region ── Logging ────────────────────────────────────────────────────────────

Function Write-AssessmentLog {
    param (
        [Parameter(Mandatory)] [object] $Context,
        [Parameter(Mandatory)] [ValidateSet('INFO', 'WARN', 'ERROR')] [string] $Level,
        [Parameter(Mandatory)] [string] $Message,
        [string] $Detail
    )

    $entry = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Level     = $Level
        Message   = $Message
        Detail    = $Detail
    }

    $Context.LogEntries.Add($entry)

    switch ($Level) {
        'INFO' { Write-Verbose   "[$Level] $Message$(if ($Detail) { " | $Detail" })" }
        'WARN' { Write-Warning   "[$Level] $Message$(if ($Detail) { " | $Detail" })" }
        'ERROR' { Write-Warning   "[ERROR] $Message$(if ($Detail) { " | $Detail" })" }
    }
}

#endregion
