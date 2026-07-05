<#

Author          : Lakshmanan Thangaraj
Version         : 2.1
Created-On      : 12 June 2026
Modified-On     : 05 July 2026

.SYNOPSIS
    Generates a modern HTML security dashboard from an Entra ID MFA Registration
    Report CSV, aligned with NIST CSF 2.0, CIS Controls v8, Zero Trust, and
    ISO 27001:2022 identity security standards.

.DESCRIPTION
    Dot-source this file and call Generate-MFADashboard to import a CSV produced
    by Get-EntraID-MFARegistrationReport.ps1 and render a multi-tab, interactive
    HTML dashboard with the following tabs:

      • Overview          – KPI tiles, MFA health ring, risk distribution,
                            method adoption bars, user-type donut, account health
      • Users             – Searchable, filterable, sortable user directory with
                            per-user detail panel, prev/next navigation, MFA method
                            dots, risk badges, and page-size selector
      • Risk & Findings   – Prioritised security findings (Critical → Low) with
                            per-user drill-down, affected user chips, copy-UPN-list
                            button per finding, and Manager Accountability section
                            grouping no-MFA users by their direct manager
      • MFA Methods       – Method adoption breakdown (8 method types), MS
                            Authenticator version analysis, FIDO2 model inventory,
                            Windows Hello key strength distribution
      • Sign-in Health    – Stale sign-in tiers (7d / 30d / 90d), never-signed-in
                            list, account age distribution, guest vs member ratios,
                            sync status tracking
      • Recommendations   – 7 actionable remediation cards sorted by severity with
                            step-by-step guidance and compliance tag labels
      • Raw Data          – Full 36-column CSV data viewer with search, department
                            filter, type filter, account filter, pagination,
                            Export Raw CSV, and Copy to Clipboard
      • Executive Summary – Board-ready one-page posture snapshot with overall
                            security grade (A–F), health score, KPI tiles, MFA
                            breakdown, top risks, identity population, priority
                            actions, Print/Save-as-PDF, and JSON export
      • Compliance Score  – Control-by-control pass/fail/partial scorecard mapped
                            against NIST CSF 2.0 (PR.AA / PR.AC), CIS Controls v8
                            (Control 5 & 6), Zero Trust Identity Pillar (NIST SP
                            800-207), and ISO 27001:2022 (A.5.9 / A.8.2 / A.8.5 /
                            A.8.7) with per-framework coverage percentage and
                            Export Scorecard CSV
      • Department Risk   – Per-department MFA coverage table with risk scoring,
                            No-MFA bar chart, phishing-resistant coverage bars,
                            sortable by risk / name / user count / no-MFA count,
                            click-to-filter integration with Users tab, and
                            Export Department CSV
      • Guest Accounts    – Dedicated external identity view with KPI tiles, MFA
                            method adoption bars, sign-in activity tiers, searchable
                            filterable guest table, and Export Guest CSV
      • Password Age      – Password hygiene analysis (NIST SP 800-63B) with age
                            distribution buckets, department average age bars,
                            oldest-password list (Top 30), KPI tiles, and
                            Export Password Age CSV

    Global dashboard features:
        - Light / dark theme toggle (persisted via localStorage)
        - Print-to-PDF via browser (Executive Summary tab auto-hides navigation)
        - CSV and JSON export on every tab
        - Copy-to-clipboard on findings, UPN lists, and Raw Data
        - Keyboard shortcuts: / (search), Esc (close panel), ← → (navigate detail)
        - Toast notifications for all user actions
        - Per-user detail panel with risk flags, MFA method cards, identity info,
          prev/next navigation, and copy-UPN button
        - Admin/service account detection (UPN pattern matching) with elevated
          risk weighting and dedicated finding card
        - Manager Accountability grouping — no-MFA users grouped by manager
          with per-manager copy-UPN-list button
        - Responsive layout with mobile sidebar toggle

.PARAMETER CsvPath
    Path to the MFA registration CSV file produced by
    Get-EntraID-MFARegistrationReport.ps1.

    Expected columns (36 total):
        LoginName, Email, DisplayName, UserType, IsOn-PremSynced,
        AccountEnabled, CreateDateTime, Department,
        LastSuccessfulSignInDateTime, LastSignInDate,
        LastNonInteractiveSignInDate, ManagerDisplayName,
        ManagerUserPrincipalName, ManagerMail,
        phoneAuthenticationNumber, phoneAuthenticationType,
        smsSignInState, passwordCreatedDateTime, emailAddress,
        WHFBDisplayName, WHFBCreatedDateTime, WHFBKeyStrength,
        microsoftAuthenticatorDisplayName, microsoftAuthenticatorDeviceTag,
        microsoftAuthenticatorPhoneAppVersion, fido2DisplayName,
        fido2CreatedDate, fido2Model, TAPAuthenticationIsUsable,
        TAPAuthenticationStartDateTime, TAPAuthenticationLifetime,
        TAPAuthenticationIsUsableOnce, passwordlessDisplayName,
        passwordAuthDeviceTag, passwordAuthPhoneAppVersion, softwareOath

.PARAMETER OutputPath
    Full file path where the generated HTML dashboard will be saved.
    Defaults to "$env:TEMP\MFADashboard.html".

.PARAMETER OpenBrowser
    Switch parameter. If specified, automatically opens the generated
    dashboard in the system default browser after generation.

.PARAMETER ShowHelp
    Switch parameter. Displays a friendly, plain-language usage guide
    (parameters, examples, prerequisites) and returns immediately — no CSV
    is loaded and no HTML is generated. Useful for a quick reminder of how
    to call this function without opening the full comment-based help.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo
        A CSV file exported to the path defined in $outputPath containing
        one row per user with all collected user and MFA details.

.EXAMPLE
    . .\Generate-MFADashboard.ps1
    Generate-MFADashboard -ShowHelp

    Dot-sources the script and prints the friendly usage guide without
    generating anything.

.EXAMPLE
    . .\Generate-MFADashboard.ps1
    Generate-MFADashboard -CsvPath "C:\Reports\MFA_Report.csv" -OpenBrowser

    Dot-sources the script, generates the dashboard from the specified CSV,
    and opens it automatically in the default browser.

.EXAMPLE
    . .\Generate-MFADashboard.ps1
    Generate-MFADashboard -CsvPath "C:\Reports\MFA_Report.csv" -OutputPath "C:\Reports\MFADashboard.html"

    Generates the dashboard and saves it to a custom output path.

.EXAMPLE
    . .\Generate-MFADashboard.ps1
    Generate-MFADashboard -CsvPath "C:\Temp\EntraID-Users-MFAReport.CSV" -OutputPath "C:\Reports\MFADashboard.html" -OpenBrowser

    Full example combining all three parameters.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (12-Jun-2026)  - Initial release
                           - 6 dashboard tabs: Overview, Users, Risk & Findings,
                             MFA Methods, Sign-in Health, Recommendations
                           - Light/dark theme, CSV/JSON export, keyboard shortcuts,
                             toast notifications, per-user detail panel

        2.0 (13-Jun-2026)  - Added Raw Data tab (36-column full CSV viewer with
                             search, filters, pagination, export, clipboard copy)
                           - Added Executive Summary tab (board-ready grade A–F,
                             health score, KPIs, print-to-PDF, JSON export)
                           - Added Compliance Scorecard tab (NIST CSF 2.0,
                             CIS Controls v8, Zero Trust NIST SP 800-207,
                             ISO 27001:2022 — pass/fail/partial per control,
                             export to CSV)
                           - Added Department Risk tab (per-department risk table,
                             no-MFA and phish-resistant bar charts, click-to-filter
                             integration with Users tab, export to CSV)
                           - Added Guest Accounts tab (dedicated external identity
                             view, KPI tiles, MFA bars, sign-in tiers, filterable
                             table, export to CSV)
                           - Added Password Age tab (NIST SP 800-63B aligned,
                             age distribution, department averages, oldest-password
                             list, export to CSV)
                           - Added isAdminLike() helper for UPN pattern detection
                             (admin, adm, svc, service, priv, break-glass, tier0/1)
                           - Added admin/service account finding to Risk & Findings
                             with elevated risk score weighting (+20 points)
                           - Added Manager Accountability section to Risk & Findings
                             grouping no-MFA users by direct manager with per-manager
                             copy-UPN-list button
                           - Added Copy UPN List button to every finding card
                           - Sidebar reorganised with Views and Reports sections
                           - Print CSS added for clean browser PDF output

        2.1 (05-Jul-2026)  - Added -ShowHelp switch parameter: prints a friendly,
                             plain-language usage guide and returns immediately,
                             before the CSV path is validated or loaded.
                             No other logic, template, styling, or dashboard
                             behaviour was changed in this version.

    ─────────────────────────────────────────────────────────────────────────────
    Security Standards Coverage (v2.0):
    ─────────────────────────────────────────────────────────────────────────────
        NIST CSF 2.0        PR.AA-01 / PR.AA-02 / PR.AA-03
                            PR.AC-01 / PR.AC-02 / PR.AC-03
        CIS Controls v8     Control 5 (Account Management): 5.1 / 5.2 / 5.3
                            Control 6 (Access Control):     6.3 / 6.4 / 6.5
        Zero Trust          NIST SP 800-207 Identity Pillar:
                            ZT-ID-01 through ZT-ID-05
        ISO 27001:2022      A.5.9  (Asset Inventory)
                            A.8.2  (Privileged Access Rights)
                            A.8.3  (Information Access Restriction)
                            A.8.5  (Secure Authentication)
                            A.8.7  (Protection Against Social Engineering)
        NIST SP 800-63B     Password age and credential hygiene analysis

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. PowerShell 5.1 or later.
        2. A valid CSV file generated by Get-EntraID-MFARegistrationReport.ps1
           v2.0 or later, containing all 36 expected columns.
        3. A modern browser (Chrome, Edge, Firefox) to view the HTML dashboard.
           Internet Explorer is not supported.

    ─────────────────────────────────────────────────────────────────────────────
    Functions:
    ─────────────────────────────────────────────────────────────────────────────
        Generate-MFADashboard
            Main entry point. Loads the CSV, computes all metrics, builds the
            HTML dashboard string, performs token substitution, and writes the
            output file. Optionally opens the result in the default browser.

        Show-FriendlyHelp   (internal helper)
            Prints a plain-language usage guide (parameters, examples,
            prerequisites) via Write-Host, then returns control to the caller
            so the function can exit early when -ShowHelp is supplied.

        ConvertTo-JsonSafe  (internal helper)
            Escapes special characters in string values before embedding them
            in the inline JavaScript JSON payload within the HTML file.

        Get-StrVal          (internal helper)
            Safely retrieves a named property from a CSV row object, returning
            an empty string instead of null for missing or undefined values.

    ─────────────────────────────────────────────────────────────────────────────
    Dashboard JavaScript Helpers (embedded in HTML output):
    ─────────────────────────────────────────────────────────────────────────────
        hasMFA(u)           Returns true if the user has any strong MFA method
        isPhishR(u)         Returns true if FIDO2 or WHFB is registered
        isSMSOnly(u)        Returns true if phone is the only method (no stronger)
        isAdminLike(u)      Returns true if UPN matches admin/service account patterns
        isStale(u, days)    Returns true if last sign-in exceeds the given day threshold
        riskScore(u)        Returns a numeric risk score (0–100) per user
        riskLabel(score)    Returns a {l, cls} object for risk badge rendering
        hasMFA / methodDots / filterTable / renderTable — table and filter helpers
        openDP / renderDP / closeDP / navDP — detail panel lifecycle
        exportCSV / exportJSON / exportRawCSV / exportGuestCSV /
        exportPwdAgeCSV / exportDeptCSV / exportComplianceCSV /
        exportExecJSON      — per-tab export functions
        copyFindingUPNs / copyMgrList / copyRawCSV — clipboard helpers
        showToast           — notification system
        toggleTheme         — light/dark mode with localStorage persistence
        showPage            — tab navigation controller

.LINK
    Get-EntraID-MFARegistrationReport.ps1
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/Entra-ID/MFA

.LINK
    NIST CSF 2.0
    https://www.nist.gov/cyberframework

.LINK
    CIS Controls v8
    https://www.cisecurity.org/controls/v8

.LINK
    NIST SP 800-207 Zero Trust Architecture
    https://doi.org/10.6028/NIST.SP.800-207

.LINK
    ISO/IEC 27001:2022
    https://www.iso.org/standard/27001

.LINK
    NIST SP 800-63B Digital Identity Guidelines
    https://pages.nist.gov/800-63-3/sp800-63b.html

#>



Function Generate-MFADashboard
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = "Run")]
        [string]$CsvPath,

        [Parameter(ParameterSetName = "Run")]
        [string]$OutputPath = "$env:TEMP\MFADashboard.html",

        [Parameter(ParameterSetName = "Run")]
        [switch]$OpenBrowser,

        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    #region ── Friendly Help ──────────────────────────────────────────────────

    function Show-FriendlyHelp
    {
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║          MFA Registration Dashboard  v2.1            ║" -ForegroundColor Cyan
        Write-Host "║                  Friendly Help                       ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  What this does:" -ForegroundColor Yellow
        Write-Host "    Reads the CSV produced by Get-EntraID-MFARegistrationReport.ps1"
        Write-Host "    and builds a single, self-contained HTML dashboard covering MFA"
        Write-Host "    coverage, risk findings, compliance mapping, and more."
        Write-Host ""
        Write-Host "  Required parameters:" -ForegroundColor Yellow
        Write-Host "    -CsvPath      Path to the MFA registration CSV file"
        Write-Host ""
        Write-Host "  Optional parameters:" -ForegroundColor Yellow
        Write-Host "    -OutputPath   Where to save the HTML file (default: `$env:TEMP\MFADashboard.html)"
        Write-Host "    -OpenBrowser  Opens the generated dashboard automatically when done"
        Write-Host "    -ShowHelp     Shows this guide and exits, nothing is generated"
        Write-Host ""
        Write-Host "  Before you run it:" -ForegroundColor Yellow
        Write-Host "    1. You need a CSV already produced by Get-EntraID-MFARegistrationReport.ps1"
        Write-Host "       (v2.0 or later, with all 36 expected columns)."
        Write-Host "    2. Use a modern browser (Chrome, Edge, Firefox) to view the result."
        Write-Host ""
        Write-Host "  Example:" -ForegroundColor Yellow
        Write-Host "    . .\Generate-MFADashboard.ps1"
        Write-Host '    Generate-MFADashboard -CsvPath "C:\Reports\MFA_Report.csv" -OpenBrowser'
        Write-Host ""
        Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
        Write-Host "     Get-Help Generate-MFADashboard -Full"
        Write-Host ""
    }

    if ($ShowHelp)
    {
        Show-FriendlyHelp
        return
    }

    #endregion

    #region ── Helpers ────────────────────────────────────────────────────────

    function ConvertTo-JsonSafe {
        param([string]$Text)
        if ($null -eq $Text) { return '' }
        $Text `
            -replace '\\', '\\' `
            -replace '"',  '\"' `
            -replace "`r`n", '\n' `
            -replace "`n",   '\n' `
            -replace "`r",   '\n' `
            -replace "`t",   '\t'
    }

    function Get-StrVal {
        param($obj, [string]$prop)
        $v = $obj.$prop
        if ($null -eq $v) { return '' }
        return [string]$v
    }

    #endregion

    #region ── Load CSV ───────────────────────────────────────────────────────

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║      MFA Registration Dashboard  v1.0                ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  🔍  Loading: $CsvPath" -ForegroundColor Cyan

    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV not found: $CsvPath"
        return
    }

    try {
        $users = Import-Csv -Path $CsvPath -ErrorAction Stop
    } catch {
        Write-Error "Failed to import CSV: $_"
        return
    }

    if ($users.Count -eq 0) {
        Write-Warning "CSV contains no data rows."
        return
    }

    Write-Host "  📦  Loaded $($users.Count) user records — analysing…" -ForegroundColor Cyan

    #endregion

    #region ── Computed Metrics ───────────────────────────────────────────────

    $total          = $users.Count
    $enabled        = ($users | Where-Object { (Get-StrVal $_ 'AccountEnabled') -eq 'True' }).Count
    $disabled       = $total - $enabled
    $members        = ($users | Where-Object { (Get-StrVal $_ 'UserType') -eq 'Member' }).Count
    $guests         = ($users | Where-Object { (Get-StrVal $_ 'UserType') -eq 'Guest'  }).Count
    $synced         = ($users | Where-Object { (Get-StrVal $_ 'IsOn-PremSynced') -eq 'True' }).Count
    $cloudOnly      = $total - $synced

    # MFA method flags (presence = non-empty)
    $hasMSAuth      = @($users | Where-Object { (Get-StrVal $_ 'microsoftAuthenticatorDisplayName') -ne '' }).Count
    $hasPhone       = @($users | Where-Object { (Get-StrVal $_ 'phoneAuthenticationNumber')        -ne '' }).Count
    $hasWHFB        = @($users | Where-Object { (Get-StrVal $_ 'WHFBDisplayName')                  -ne '' }).Count
    $hasFIDO2       = @($users | Where-Object { (Get-StrVal $_ 'fido2DisplayName')                 -ne '' }).Count
    $hasTAP         = @($users | Where-Object { (Get-StrVal $_ 'TAPAuthenticationIsUsable') -eq 'True' }).Count
    $hasPasswordless= @($users | Where-Object { (Get-StrVal $_ 'passwordlessDisplayName')         -ne '' }).Count
    $hasSoftOath    = @($users | Where-Object { (Get-StrVal $_ 'softwareOath') -ne '' -and (Get-StrVal $_ 'softwareOath') -ne 'False' }).Count
    $hasSMSSignIn   = @($users | Where-Object { (Get-StrVal $_ 'smsSignInState') -eq 'ready' }).Count
    $hasEmailMFA    = @($users | Where-Object { (Get-StrVal $_ 'emailAddress') -ne '' }).Count

    # Any MFA = at least one strong method registered
    $anyMFA = ($users | Where-Object {
        (Get-StrVal $_ 'microsoftAuthenticatorDisplayName') -ne '' -or
        (Get-StrVal $_ 'phoneAuthenticationNumber')        -ne '' -or
        (Get-StrVal $_ 'WHFBDisplayName')                  -ne '' -or
        (Get-StrVal $_ 'fido2DisplayName')                 -ne '' -or
        (Get-StrVal $_ 'softwareOath') -notin @('','False')
    }).Count
    $noMFA = $total - $anyMFA

    # Phishing-resistant: FIDO2 or WHFB
    $phishResistant = @($users | Where-Object {
        (Get-StrVal $_ 'fido2DisplayName') -ne '' -or
        (Get-StrVal $_ 'WHFBDisplayName')  -ne ''
    }).Count

    # Stale sign-ins: enabled users with no sign-in in 90 days
    $cutoff90 = (Get-Date).AddDays(-90)
    $stale90  = @($users | Where-Object {
        (Get-StrVal $_ 'AccountEnabled') -eq 'True' -and
        $(
            $d = [string](Get-StrVal $_ 'LastSignInDate')
            $dt = [datetime]::MinValue
            if ($d -ne '' -and [datetime]::TryParse($d, [ref]$dt)) { $dt -lt $cutoff90 }
            else { $true }
        )
    }).Count
    $cutoff30 = (Get-Date).AddDays(-30)
    $stale30  = @($users | Where-Object {
        (Get-StrVal $_ 'AccountEnabled') -eq 'True' -and
        $(
            $d = [string](Get-StrVal $_ 'LastSignInDate')
            $dt = [datetime]::MinValue
            if ($d -ne '' -and [datetime]::TryParse($d, [ref]$dt)) { $dt -lt $cutoff30 }
            else { $true }
        )
    }).Count
    $neverSignedIn = @($users | Where-Object {
        (Get-StrVal $_ 'AccountEnabled') -eq 'True' -and
        (Get-StrVal $_ 'LastSignInDate') -eq ''
    }).Count

    # SMS-only risk (has phone but no stronger method)
    $smsOnly = @($users | Where-Object {
        (Get-StrVal $_ 'phoneAuthenticationNumber')        -ne '' -and
        (Get-StrVal $_ 'microsoftAuthenticatorDisplayName') -eq '' -and
        (Get-StrVal $_ 'fido2DisplayName')                 -eq '' -and
        (Get-StrVal $_ 'WHFBDisplayName')                  -eq '' -and
        (Get-StrVal $_ 'softwareOath') -in @('','False')
    }).Count

    # Department breakdown
    $deptGroups = $users | Group-Object Department | Sort-Object Count -Descending | Select-Object -First 12

    # Health score: % of enabled users with at least 1 MFA method
    $enabledUsers = $users | Where-Object { (Get-StrVal $_ 'AccountEnabled') -eq 'True' }
    $enabledCount = $enabledUsers.Count
    $enabledWithMFA = ($enabledUsers | Where-Object {
        (Get-StrVal $_ 'microsoftAuthenticatorDisplayName') -ne '' -or
        (Get-StrVal $_ 'phoneAuthenticationNumber')        -ne '' -or
        (Get-StrVal $_ 'WHFBDisplayName')                  -ne '' -or
        (Get-StrVal $_ 'fido2DisplayName')                 -ne '' -or
        (Get-StrVal $_ 'softwareOath') -notin @('','False')
    }).Count
    $healthScore = if ($enabledCount -gt 0) { [math]::Round(($enabledWithMFA / $enabledCount) * 100, 0) } else { 0 }

    $mfaPct           = if ($total -gt 0) { [math]::Round(($anyMFA  / $total) * 100, 1) } else { 0 }
    $phishResistantPct= if ($total -gt 0) { [math]::Round(($phishResistant / $total) * 100, 1) } else { 0 }
    $stale90Pct       = if ($enabledCount -gt 0) { [math]::Round(($stale90 / $enabledCount) * 100, 1) } else { 0 }
    $generatedAt      = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')

    Write-Host "  ✅  Analysis complete. Building dashboard…" -ForegroundColor Green

    #endregion

    #region ── JSON Data ──────────────────────────────────────────────────────

    $usersJson = ($users | ForEach-Object {
        $u = $_
        $ln   = ConvertTo-JsonSafe (Get-StrVal $u 'LoginName')
        $em   = ConvertTo-JsonSafe (Get-StrVal $u 'Email')
        $dn   = ConvertTo-JsonSafe (Get-StrVal $u 'DisplayName')
        $ut   = ConvertTo-JsonSafe (Get-StrVal $u 'UserType')
        $sync = ConvertTo-JsonSafe (Get-StrVal $u 'IsOn-PremSynced')
        $ae   = ConvertTo-JsonSafe (Get-StrVal $u 'AccountEnabled')
        $cdt  = ConvertTo-JsonSafe (Get-StrVal $u 'CreateDateTime')
        $dept = ConvertTo-JsonSafe (Get-StrVal $u 'Department')
        $lsi  = ConvertTo-JsonSafe (Get-StrVal $u 'LastSignInDate')
        $lnisi= ConvertTo-JsonSafe (Get-StrVal $u 'LastNonInteractiveSignInDate')
        $lssi = ConvertTo-JsonSafe (Get-StrVal $u 'LastSuccessfulSignInDateTime')
        $mgr  = ConvertTo-JsonSafe (Get-StrVal $u 'ManagerDisplayName')
        $mgrU = ConvertTo-JsonSafe (Get-StrVal $u 'ManagerUserPrincipalName')
        $mgrM = ConvertTo-JsonSafe (Get-StrVal $u 'ManagerMail')
        $ph   = ConvertTo-JsonSafe (Get-StrVal $u 'phoneAuthenticationNumber')
        $phT  = ConvertTo-JsonSafe (Get-StrVal $u 'phoneAuthenticationType')
        $sms  = ConvertTo-JsonSafe (Get-StrVal $u 'smsSignInState')
        $pwCr = ConvertTo-JsonSafe (Get-StrVal $u 'passwordCreatedDateTime')
        $emA  = ConvertTo-JsonSafe (Get-StrVal $u 'emailAddress')
        $whN  = ConvertTo-JsonSafe (Get-StrVal $u 'WHFBDisplayName')
        $whC  = ConvertTo-JsonSafe (Get-StrVal $u 'WHFBCreatedDateTime')
        $whKS = ConvertTo-JsonSafe (Get-StrVal $u 'WHFBKeyStrength')
        $msN  = ConvertTo-JsonSafe (Get-StrVal $u 'microsoftAuthenticatorDisplayName')
        $msDT = ConvertTo-JsonSafe (Get-StrVal $u 'microsoftAuthenticatorDeviceTag')
        $msV  = ConvertTo-JsonSafe (Get-StrVal $u 'microsoftAuthenticatorPhoneAppVersion')
        $f2N  = ConvertTo-JsonSafe (Get-StrVal $u 'fido2DisplayName')
        $f2D  = ConvertTo-JsonSafe (Get-StrVal $u 'fido2CreatedDate')
        $f2M  = ConvertTo-JsonSafe (Get-StrVal $u 'fido2Model')
        $tapU = ConvertTo-JsonSafe (Get-StrVal $u 'TAPAuthenticationIsUsable')
        $tapS = ConvertTo-JsonSafe (Get-StrVal $u 'TAPAuthenticationStartDateTime')
        $tapL = ConvertTo-JsonSafe (Get-StrVal $u 'TAPAuthenticationLifetime')
        $tapO = ConvertTo-JsonSafe (Get-StrVal $u 'TAPAuthenticationIsUsableOnce')
        $plN  = ConvertTo-JsonSafe (Get-StrVal $u 'passwordlessDisplayName')
        $plDT = ConvertTo-JsonSafe (Get-StrVal $u 'passwordAuthDeviceTag')
        $plV  = ConvertTo-JsonSafe (Get-StrVal $u 'passwordAuthPhoneAppVersion')
        $soath= ConvertTo-JsonSafe (Get-StrVal $u 'softwareOath')

        "{`"ln`":`"$ln`",`"email`":`"$em`",`"dn`":`"$dn`",`"ut`":`"$ut`",`"sync`":`"$sync`",`"ae`":`"$ae`",`"cdt`":`"$cdt`",`"dept`":`"$dept`",`"lsi`":`"$lsi`",`"lnisi`":`"$lnisi`",`"lssi`":`"$lssi`",`"mgr`":`"$mgr`",`"mgrU`":`"$mgrU`",`"mgrM`":`"$mgrM`",`"ph`":`"$ph`",`"phT`":`"$phT`",`"sms`":`"$sms`",`"pwCr`":`"$pwCr`",`"emA`":`"$emA`",`"whN`":`"$whN`",`"whC`":`"$whC`",`"whKS`":`"$whKS`",`"msN`":`"$msN`",`"msDT`":`"$msDT`",`"msV`":`"$msV`",`"f2N`":`"$f2N`",`"f2D`":`"$f2D`",`"f2M`":`"$f2M`",`"tapU`":`"$tapU`",`"tapS`":`"$tapS`",`"tapL`":`"$tapL`",`"tapO`":`"$tapO`",`"plN`":`"$plN`",`"plDT`":`"$plDT`",`"plV`":`"$plV`",`"soath`":`"$soath`"}"
    }) -join ','

    $deptJson = ($deptGroups | ForEach-Object {
        $dname = ConvertTo-JsonSafe ($_.Name)
        "{`"dept`":`"$dname`",`"count`":$($_.Count)}"
    }) -join ','

    #endregion

    #region ── HTML ───────────────────────────────────────────────────────────

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Entra ID MFA Registration Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root {
  --bg:#080e1a; --surface:#0d1526; --surface2:#111d32; --surface3:#172240;
  --border:#1e2d4a; --border2:#263654;
  --accent:#4f8ef7; --accent2:#38d9c0; --accent3:#a87fff;
  --green:#2dd4a0; --amber:#f0a830; --red:#f05968; --orange:#f07830;
  --text:#dce8f8; --muted:#6b82a8; --muted2:#9bb3d4;
  --mono:'JetBrains Mono','Consolas',monospace;
  --sans:'Inter','Segoe UI',sans-serif;
  --radius:12px; --radius-sm:7px;
  --shadow:0 8px 32px rgba(0,0,0,.6);
  --glow-blue:0 0 20px rgba(79,142,247,.18);
  --glow-green:0 0 20px rgba(45,212,160,.15);
}
body.light {
  --bg:#f0f4fb; --surface:#fff; --surface2:#e8eef8; --surface3:#d8e3f2;
  --border:#c5d3e8; --border2:#b0c4de;
  --accent:#2563eb; --accent2:#0891b2; --accent3:#7c3aed;
  --green:#059669; --amber:#d97706; --red:#dc2626; --orange:#ea580c;
  --text:#1a2840; --muted:#6b7280; --muted2:#374151;
  --shadow:0 8px 32px rgba(0,0,0,.1);
  --glow-blue:0 0 20px rgba(37,99,235,.08);
  --glow-green:0 0 20px rgba(5,150,105,.06);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .3s,color .3s}

/* ── SIDEBAR ── */
#sidebar{position:fixed;top:0;left:0;bottom:0;width:230px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .3s,border-color .3s}
.sb-logo{padding:20px 18px 16px;border-bottom:1px solid var(--border)}
.sb-icon{width:40px;height:40px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:11px;display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;box-shadow:var(--glow-blue)}
.sb-logo h1{font-size:13.5px;font-weight:700;color:var(--text);line-height:1.3}
.sb-logo p{font-size:11px;color:var(--muted);margin-top:2px}
.sb-badge{display:inline-block;margin-top:6px;background:rgba(79,142,247,.12);color:var(--accent);font-family:var(--mono);font-size:10px;padding:2px 9px;border-radius:20px;border:1px solid rgba(79,142,247,.25)}
.sb-nav{flex:1;padding:10px 0;overflow-y:auto}
.sb-section{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:10px 18px 4px}
.nb{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;text-align:left;position:relative;transition:all .18s;border-radius:0}
.nb .ni{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.nb .nbadge{margin-left:auto;background:var(--surface3);color:var(--muted2);font-family:var(--mono);font-size:10.5px;padding:1px 7px;border-radius:20px}
.nb:hover{color:var(--text);background:var(--surface2)}
.nb.active{color:var(--accent);background:rgba(79,142,247,.1)}
.nb.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);border-radius:0 2px 2px 0}
.sb-theme{padding:10px 14px;border-top:1px solid var(--border)}
.theme-btn{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:12.5px;transition:all .2s}
.theme-btn:hover{border-color:var(--accent);color:var(--text)}
.tpill{width:34px;height:18px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0;margin-left:auto}
.tpill::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--muted);transition:transform .2s,background .2s}
body.light .tpill{background:var(--accent)}
body.light .tpill::after{transform:translateX(16px);background:#fff}
.sb-foot{padding:10px 18px 14px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);font-family:var(--mono);line-height:1.7}
kbd{display:inline-block;padding:1px 5px;background:var(--surface3);border:1px solid var(--border);border-radius:3px;font-family:var(--mono);font-size:10px;color:var(--muted)}

/* ── MAIN ── */
#main{margin-left:230px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .2s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.ph{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.ph-left h2{font-size:22px;font-weight:700}
.ph-left p{color:var(--muted);font-size:12.5px;margin-top:3px}

/* ── BUTTONS ── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:var(--radius-sm);font-size:12.5px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(79,142,247,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

/* ── KPI GRID ── */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s,box-shadow .2s}
.kpi:hover{transform:translateY(-3px);border-color:var(--accent);box-shadow:var(--glow-blue)}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.kpi.blue::before{background:linear-gradient(90deg,var(--accent),var(--accent3))}
.kpi.green::before{background:linear-gradient(90deg,var(--green),var(--accent2))}
.kpi.amber::before{background:linear-gradient(90deg,var(--amber),var(--orange))}
.kpi.red::before{background:linear-gradient(90deg,var(--red),var(--orange))}
.kpi.purple::before{background:linear-gradient(90deg,var(--accent3),var(--accent))}
.kpi.cyan::before{background:linear-gradient(90deg,var(--accent2),var(--green))}
.kpi-icon{font-size:19px;margin-bottom:8px}
.kpi-val{font-size:26px;font-weight:700;line-height:1;font-family:var(--mono)}
.kpi-sub{color:var(--muted);font-size:11.5px;margin-top:4px}
.kpi-trend{position:absolute;top:12px;right:14px;font-size:11px;font-family:var(--mono);padding:1px 7px;border-radius:20px}
.kpi-trend.good{background:rgba(45,212,160,.15);color:var(--green)}
.kpi-trend.bad{background:rgba(240,89,104,.15);color:var(--red)}
.kpi-trend.warn{background:rgba(240,168,48,.15);color:var(--amber)}

/* ── HEALTH CARD ── */
.health-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 22px;display:flex;align-items:center;gap:22px;margin-bottom:20px;flex-wrap:wrap;box-shadow:var(--glow-green)}
.hring{position:relative;width:90px;height:90px;flex-shrink:0}
.hring svg{width:90px;height:90px}
.hring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.hring-num{font-family:var(--mono);font-size:22px;font-weight:700;line-height:1}
.hring-pct{font-size:9px;color:var(--muted)}
.health-info{flex:1;min-width:200px}
.health-info h3{font-size:14px;font-weight:700;margin-bottom:4px}
.health-info p{font-size:12px;color:var(--muted2);margin-bottom:10px}
.hbar{display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:12px}
.hbar-track{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.hbar-fill{height:100%;border-radius:3px;transition:width 1s ease}
.hbar-lbl{width:130px;flex-shrink:0;color:var(--muted2)}
.hbar-val{width:28px;text-align:right;color:var(--muted);font-family:var(--mono);font-size:11px}

/* ── PANELS ── */
.panel-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
@media(max-width:900px){.panel-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.panel-title{font-size:13.5px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:7px;color:var(--text)}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:8px;cursor:pointer}
.bar-row:hover .blabel{color:var(--text)}
.blabel{font-size:11.5px;color:var(--muted2);width:92px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:var(--mono)}
.btrack{flex:1;height:9px;background:var(--surface3);border-radius:5px;overflow:hidden}
.bfill{height:100%;border-radius:5px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bcount{font-family:var(--mono);font-size:11px;color:var(--accent2);width:30px;text-align:right;flex-shrink:0}
.bpct{font-family:var(--mono);font-size:10px;color:var(--muted);width:32px;text-align:right;flex-shrink:0}

/* ── DONUT ── */
.donut-wrap{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
#donutSvg{width:170px;height:170px;flex-shrink:0}
.dlegend{flex:1;min-width:120px;display:flex;flex-direction:column;gap:5px;max-height:200px;overflow-y:auto}
.dleg-item{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted2);cursor:pointer;padding:2px 4px;border-radius:4px}
.dleg-item:hover{background:var(--surface2)}
.dleg-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.dleg-pct{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}

/* ── TABLE ── */
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.srch-wrap{flex:1;min-width:200px;position:relative}
.srch-wrap .si{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:13.5px;padding:8px 11px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--accent)}
select{cursor:pointer}
select option{background:var(--surface2)}
.rcount{color:var(--muted);font-size:12.5px;flex-shrink:0}
.psize-wrap{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.psize-wrap select{padding:5px 8px;font-size:12px}
.tbl{width:100%;border-collapse:collapse}
.tbl thead th{text-align:left;font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 11px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.tbl thead th:hover{color:var(--text)}
.tbl thead th.sa{color:var(--accent)}
.sarr{margin-left:4px;opacity:.4;font-size:10px}
.sa .sarr{opacity:1}
.tbl tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.tbl tbody tr:hover{background:var(--surface2)}
.tbl tbody td{padding:8px 11px;vertical-align:middle;font-size:13px}
.td-name{font-family:var(--mono);font-size:12px;color:var(--accent2)}
.td-muted{color:var(--muted);font-family:var(--mono);font-size:11.5px;white-space:nowrap}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%}
.chip{display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:500;border:1px solid}
.chip-blue{background:rgba(79,142,247,.1);color:var(--accent);border-color:rgba(79,142,247,.25)}
.chip-green{background:rgba(45,212,160,.1);color:var(--green);border-color:rgba(45,212,160,.25)}
.chip-red{background:rgba(240,89,104,.1);color:var(--red);border-color:rgba(240,89,104,.25)}
.chip-amber{background:rgba(240,168,48,.1);color:var(--amber);border-color:rgba(240,168,48,.25)}
.chip-purple{background:rgba(168,127,255,.1);color:var(--accent3);border-color:rgba(168,127,255,.25)}
.chip-cyan{background:rgba(56,217,192,.1);color:var(--accent2);border-color:rgba(56,217,192,.25)}
.chip-muted{background:var(--surface3);color:var(--muted);border-color:var(--border)}
.method-dots{display:flex;gap:4px;flex-wrap:wrap}
.method-dot{width:18px;height:18px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:9px;title-attr:attr(title)}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:12px}
.pb{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:11.5px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.pb:hover{border-color:var(--accent);color:var(--accent)}
.pb.active{background:var(--accent);border-color:var(--accent);color:#fff}
.pb:disabled{opacity:.3;cursor:default}

/* ── DETAIL PANEL ── */
#dp{position:fixed;inset:0;z-index:500;display:none}
#dp.open{display:flex}
#dpBack{position:absolute;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(5px)}
#dpDrawer{position:relative;margin-left:auto;width:min(680px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:24px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.dp-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
#dpClose{margin-left:auto;background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#dpClose:hover{background:var(--red);color:#fff}
#dpContent{flex:1;overflow-y:auto}
.dp-name{font-family:var(--mono);font-size:15px;color:var(--accent2);font-weight:600;margin-bottom:3px;word-break:break-all}
.dp-email{font-size:12px;color:var(--muted);font-family:var(--mono);margin-bottom:12px;word-break:break-all}
.dp-chips{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:16px}
.dp-section{margin-top:18px}
.dp-stitle{font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin-bottom:9px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.method-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 13px;margin-bottom:6px}
.method-card-head{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.method-card-title{font-size:13px;font-weight:600}
.method-card-body{font-size:12px;color:var(--muted2);line-height:1.6}
.risk-item{background:var(--surface2);border-left:3px solid;border-radius:0 var(--radius-sm) var(--radius-sm) 0;padding:9px 12px;margin-bottom:6px}
.risk-item.critical{border-color:var(--red)}
.risk-item.high{border-color:var(--orange)}
.risk-item.medium{border-color:var(--amber)}
.risk-item.low{border-color:var(--green)}
.risk-title{font-size:12.5px;font-weight:600;margin-bottom:2px}
.risk-desc{font-size:12px;color:var(--muted2)}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:5px}
.info-row{display:flex;flex-direction:column;padding:6px 0;border-bottom:1px solid var(--border)}
.info-row:last-child{border-bottom:none}
.info-label{font-size:11px;color:var(--muted);margin-bottom:1px}
.info-val{font-size:12.5px;color:var(--muted2);font-family:var(--mono);word-break:break-all}

/* ── RISK / FINDINGS ── */
.finding-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;margin-bottom:12px;transition:border-color .2s}
.finding-card:hover{border-color:var(--accent)}
.fc-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:10px}
.severity-badge{padding:3px 11px;border-radius:20px;font-size:11px;font-weight:700;white-space:nowrap;flex-shrink:0;margin-top:1px}
.sev-critical{background:rgba(240,89,104,.15);color:var(--red);border:1px solid rgba(240,89,104,.3)}
.sev-high{background:rgba(240,120,48,.15);color:var(--orange);border:1px solid rgba(240,120,48,.3)}
.sev-medium{background:rgba(240,168,48,.15);color:var(--amber);border:1px solid rgba(240,168,48,.3)}
.sev-low{background:rgba(45,212,160,.15);color:var(--green);border:1px solid rgba(45,212,160,.3)}
.fc-title{font-size:14px;font-weight:700;flex:1}
.fc-body{font-size:13px;color:var(--muted2);line-height:1.7;margin-bottom:10px}
.fc-stat{display:inline-flex;align-items:center;gap:6px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:5px 12px;font-size:12.5px;margin-right:8px;margin-bottom:6px}
.fc-stat strong{color:var(--text);font-family:var(--mono)}
.fc-actions{margin-top:10px;border-top:1px solid var(--border);padding-top:10px}
.fc-action-title{font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin-bottom:7px}
.affected-list{max-height:160px;overflow-y:auto;display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
.affected-chip{background:var(--surface3);border:1px solid var(--border);border-radius:20px;padding:2px 9px;font-family:var(--mono);font-size:11px;color:var(--muted2);cursor:pointer;transition:all .2s}
.affected-chip:hover{border-color:var(--accent);color:var(--accent)}

/* ── RECOMMENDATIONS ── */
.rec-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;margin-bottom:10px;display:flex;gap:14px}
.rec-icon-wrap{width:36px;height:36px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.rec-body{flex:1}
.rec-title{font-size:13.5px;font-weight:700;margin-bottom:4px}
.rec-desc{font-size:12.5px;color:var(--muted2);line-height:1.7;margin-bottom:8px}
.rec-steps{padding-left:18px;font-size:12.5px;color:var(--muted2);line-height:1.9}
.rec-steps li{margin-bottom:2px}
.rec-tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}

/* ── METHODS PAGE ── */
.method-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:20px}
.method-stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.method-stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.ms-icon{font-size:24px;margin-bottom:10px}
.ms-val{font-size:22px;font-weight:700;font-family:var(--mono)}
.ms-label{font-size:12px;color:var(--muted);margin-top:3px}
.ms-pct{position:absolute;top:14px;right:14px;font-family:var(--mono);font-size:11px;color:var(--muted)}
.ms-bar{position:absolute;bottom:0;left:0;right:0;height:3px}
.ms-bar-fill{height:100%;transition:width 1s ease}

/* ── TOAST ── */
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s,opacity .3s;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}

/* ── SCROLLBAR ── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

/* ── RESPONSIVE ── */
@media(max-width:768px){#sidebar{transform:translateX(-230px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:16px}#mbt{display:flex}}
#mbt{display:none;position:fixed;top:10px;left:10px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}

/* ── SIGN-IN HEALTH ── */
.stale-level{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border)}
.stale-level:last-child{border-bottom:none}
.stale-icon{font-size:18px;width:28px;text-align:center}
.stale-info{flex:1}
.stale-label{font-size:13px;font-weight:600}
.stale-sub{font-size:11.5px;color:var(--muted)}
.stale-count{font-family:var(--mono);font-size:16px;font-weight:700}
.empty-state{text-align:center;padding:40px;color:var(--muted)}
.empty-state .es-icon{font-size:32px;display:block;margin-bottom:10px}

/* ── PRINT / EXECUTIVE SUMMARY ── */
@media print {
  #sidebar,#mbt,#toast,.btn-group,.exec-noprint{display:none!important}
  #main{margin-left:0!important}
  body{background:#fff!important;color:#000!important}
  .exec-card{border:1px solid #ccc!important;box-shadow:none!important;break-inside:avoid}
  .exec-kpi-grid{display:grid!important;grid-template-columns:repeat(4,1fr)!important}
  .page{display:none!important}
  #page-exec{display:block!important}
}
.exec-kpi-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:14px;margin-bottom:22px}
.exec-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;break-inside:avoid}
.exec-card-title{font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.exec-stat-row{display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid var(--border);font-size:12.5px}
.exec-stat-row:last-child{border-bottom:none}
.exec-stat-val{font-family:var(--mono);font-weight:700}
.exec-grade{display:inline-flex;align-items:center;justify-content:center;width:54px;height:54px;border-radius:50%;font-size:22px;font-weight:800;font-family:var(--mono);border:3px solid}
.exec-grade.A{border-color:var(--green);color:var(--green)}
.exec-grade.B{border-color:var(--accent);color:var(--accent)}
.exec-grade.C{border-color:var(--amber);color:var(--amber)}
.exec-grade.D{border-color:var(--orange);color:var(--orange)}
.exec-grade.F{border-color:var(--red);color:var(--red)}
.exec-finding-row{display:flex;align-items:flex-start;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);font-size:12px}
.exec-finding-row:last-child{border-bottom:none}
.exec-trend-up{color:var(--green);font-size:11px}
.exec-trend-down{color:var(--red);font-size:11px}

/* ── COMPLIANCE SCORECARD ── */
.comp-framework{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:18px}
.comp-fw-header{display:flex;align-items:center;gap:14px;margin-bottom:16px;flex-wrap:wrap}
.comp-fw-icon{font-size:24px;width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.comp-fw-title{font-size:15px;font-weight:700}
.comp-fw-sub{font-size:12px;color:var(--muted);margin-top:2px}
.comp-fw-score{margin-left:auto;text-align:center}
.comp-fw-score-val{font-family:var(--mono);font-size:22px;font-weight:800}
.comp-fw-score-lbl{font-size:10px;color:var(--muted)}
.comp-control-row{display:flex;align-items:flex-start;gap:12px;padding:9px 0;border-bottom:1px solid var(--border)}
.comp-control-row:last-child{border-bottom:none}
.comp-status{width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;flex-shrink:0;margin-top:1px}
.comp-status.pass{background:rgba(45,212,160,.2);color:var(--green)}
.comp-status.fail{background:rgba(240,89,104,.2);color:var(--red)}
.comp-status.partial{background:rgba(240,168,48,.2);color:var(--amber)}
.comp-status.info{background:rgba(79,142,247,.2);color:var(--accent)}
.comp-control-body{flex:1}
.comp-control-title{font-size:13px;font-weight:600;margin-bottom:2px}
.comp-control-desc{font-size:12px;color:var(--muted2)}
.comp-control-val{font-family:var(--mono);font-size:12px;color:var(--accent2);white-space:nowrap;margin-left:auto;flex-shrink:0}
.comp-progress-bar{height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;margin-top:8px}
.comp-progress-fill{height:100%;border-radius:4px;transition:width 1s ease}

</style>
</head>
<body>

<button id="mbt" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sb-logo">
    <div class="sb-icon">🔐</div>
    <h1>MFA Registration<br>Dashboard</h1>
    <p>Entra ID Identity Security</p>
    <span class="sb-badge">v1.0</span>
  </div>
  <div class="sb-nav">
    <div class="sb-section">Views</div>
    <button class="nb active" onclick="showPage('overview',this)"><span class="ni">📊</span> Overview</button>
    <button class="nb" onclick="showPage('users',this)"><span class="ni">👥</span> Users <span class="nbadge">__TOTAL__</span></button>
    <button class="nb" onclick="showPage('risk',this)"><span class="ni">⚠️</span> Risk &amp; Findings</button>
    <button class="nb" onclick="showPage('methods',this)"><span class="ni">🔑</span> MFA Methods</button>
    <button class="nb" onclick="showPage('signin',this)"><span class="ni">🕐</span> Sign-in Health</button>
    <button class="nb" onclick="showPage('recs',this)"><span class="ni">💡</span> Recommendations</button>
	<button class="nb" onclick="showPage('raw',this)"><span class="ni">📋</span> Raw Data <span class="nbadge">__TOTAL__</span></button>
	<div class="sb-section">Reports</div>
    <button class="nb" onclick="showPage('exec',this)"><span class="ni">📄</span> Executive Summary</button>
    <button class="nb" onclick="showPage('compliance',this)"><span class="ni">🏛️</span> Compliance Score</button>
    <button class="nb" onclick="showPage('deptRisk',this)"><span class="ni">🏢</span> Department Risk</button>
    <button class="nb" onclick="showPage('guests',this)"><span class="ni">👤</span> Guest Accounts</button>
    <button class="nb" onclick="showPage('pwdage',this)"><span class="ni">🔑</span> Password Age</button>
  </div>
  <div class="sb-theme">
    <button class="theme-btn" onclick="toggleTheme()">
      <span id="thIcon">🌙</span>
      <span id="thLabel" style="flex:1;text-align:left">Dark Mode</span>
      <span class="tpill"></span>
    </button>
  </div>
  <div class="sb-foot">
    Generated<br>__GENERATEDAT__<br>
    <span style="color:var(--accent2)">⌨</span> <kbd>/</kbd> search &nbsp;<kbd>Esc</kbd> close &nbsp;<kbd>←</kbd><kbd>→</kbd> nav
  </div>
</nav>

<main id="main">

<!-- ═══ OVERVIEW ═══ -->
<section id="page-overview" class="page active">
  <div class="ph">
    <div class="ph-left">
      <h2>Security Overview</h2>
      <p>MFA registration posture and identity health at a glance</p>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(false)">⬇ Export CSV</button>
      <button class="btn" onclick="exportJSON(false)">⬇ Export JSON</button>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi blue"><div class="kpi-icon">👥</div><div class="kpi-val">__TOTAL__</div><div class="kpi-sub">Total Users</div></div>
    <div class="kpi green"><div class="kpi-icon">✅</div><div class="kpi-val">__ENABLED__</div><div class="kpi-sub">Active Accounts</div></div>
    <div class="kpi green"><div class="kpi-icon">🔐</div><div class="kpi-val">__ANYMFA__</div><div class="kpi-sub">MFA Registered</div><span class="kpi-trend good">__MFAPCT__%</span></div>
    <div class="kpi red"><div class="kpi-icon">⚠️</div><div class="kpi-val">__NOMFA__</div><div class="kpi-sub">No MFA Registered</div></div>
    <div class="kpi purple"><div class="kpi-icon">🛡️</div><div class="kpi-val">__PHISHR__</div><div class="kpi-sub">Phishing-Resistant</div><span class="kpi-trend good">__PHISHRPCT__%</span></div>
    <div class="kpi amber"><div class="kpi-icon">📱</div><div class="kpi-val">__SMSONLY__</div><div class="kpi-sub">SMS-Only (Weak)</div></div>
    <div class="kpi cyan"><div class="kpi-icon">🔄</div><div class="kpi-val">__SYNCED__</div><div class="kpi-sub">Hybrid Synced</div></div>
    <div class="kpi red"><div class="kpi-icon">💤</div><div class="kpi-val">__STALE90__</div><div class="kpi-sub">Stale 90+ Days</div><span class="kpi-trend bad">__STALE90PCT__%</span></div>
  </div>

  <div class="health-wrap">
    <div class="hring">
      <svg viewBox="0 0 90 90">
        <circle cx="45" cy="45" r="36" fill="none" stroke="var(--surface3)" stroke-width="10"/>
        <circle cx="45" cy="45" r="36" fill="none" stroke-width="10"
          stroke-dasharray="226.2" stroke-dashoffset="226.2" stroke-linecap="round"
          transform="rotate(-90 45 45)" id="healthArc" style="transition:stroke-dashoffset 1.3s ease"/>
      </svg>
      <div class="hring-center">
        <span class="hring-num" id="healthNum">__HEALTHSCORE__</span>
        <span class="hring-pct">/ 100</span>
      </div>
    </div>
    <div class="health-info">
      <h3>MFA Coverage Health Score</h3>
      <p>Percentage of active accounts with at least one MFA method registered</p>
      <div class="hbar"><span class="hbar-lbl" style="color:var(--green)">✅ With MFA</span><div class="hbar-track"><div class="hbar-fill" id="hfWith" style="background:var(--green);width:0%"></div></div><span class="hbar-val" id="hvWith">0</span></div>
      <div class="hbar"><span class="hbar-lbl" style="color:var(--red)">⚠ No MFA</span><div class="hbar-track"><div class="hbar-fill" id="hfNo" style="background:var(--red);width:0%"></div></div><span class="hbar-val" id="hvNo">0</span></div>
      <div class="hbar"><span class="hbar-lbl" style="color:var(--accent3)">🛡 Phish-Resistant</span><div class="hbar-track"><div class="hbar-fill" id="hfPR" style="background:var(--accent3);width:0%"></div></div><span class="hbar-val" id="hvPR">0</span></div>
    </div>
  </div>

  <div class="panel-grid">
    <div class="panel">
      <div class="panel-title">📊 MFA Method Adoption</div>
      <div id="methodBars"></div>
    </div>
    <div class="panel">
      <div class="panel-title">🏢 Users by Department</div>
      <div id="deptBars"></div>
    </div>
  </div>

  <div class="panel-grid">
    <div class="panel">
      <div class="panel-title">🍩 User Type Distribution</div>
      <div class="donut-wrap">
        <svg id="donutSvg" viewBox="0 0 170 170"></svg>
        <div class="dlegend" id="donutLegend"></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">🏥 Account Health Breakdown</div>
      <div id="acctHealth"></div>
    </div>
  </div>
</section>

<!-- ═══ USERS TABLE ═══ -->
<section id="page-users" class="page">
  <div class="ph">
    <div class="ph-left">
      <h2>All Users</h2>
      <p>Searchable, filterable user directory with full MFA details</p>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(true)">⬇ Export Filtered CSV</button>
      <button class="btn" onclick="exportJSON(true)">⬇ Export Filtered JSON</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="srch-wrap">
      <span class="si">🔎</span>
      <input type="text" id="tableSearch" placeholder="Search name, email, department… (press / to focus)" oninput="filterTable()"/>
    </div>
    <select id="typeFilter" onchange="filterTable()">
      <option value="">All Types</option>
      <option value="Member">Member</option>
      <option value="Guest">Guest</option>
    </select>
    <select id="mfaFilter" onchange="filterTable()">
      <option value="">All MFA</option>
      <option value="yes">✅ Has MFA</option>
      <option value="no">⚠ No MFA</option>
      <option value="phish">🛡 Phish-Resistant</option>
      <option value="smsonly">📵 SMS-Only</option>
    </select>
    <select id="acctFilter" onchange="filterTable()">
      <option value="">All Accounts</option>
      <option value="enabled">✅ Enabled</option>
      <option value="disabled">🚫 Disabled</option>
    </select>
    <select id="syncFilter" onchange="filterTable()">
      <option value="">All Sync</option>
      <option value="synced">🔄 Synced</option>
      <option value="cloud">☁ Cloud-Only</option>
    </select>
    <div class="psize-wrap">
      Show <select id="pageSel" onchange="chPageSize()"><option>20</option><option>50</option><option>100</option></select>
    </div>
    <span class="rcount" id="rcount"></span>
  </div>
  <table class="tbl">
    <thead><tr>
      <th onclick="sortCol('dn')" id="th-dn">Display Name <span class="sarr">↕</span></th>
      <th onclick="sortCol('dept')" id="th-dept">Department <span class="sarr">↕</span></th>
      <th>MFA Methods</th>
      <th onclick="sortCol('ut')" id="th-ut">Type <span class="sarr">↕</span></th>
      <th>Acct</th>
      <th onclick="sortCol('lsi')" id="th-lsi">Last Sign-In <span class="sarr">↕</span></th>
      <th>Risk</th>
    </tr></thead>
    <tbody id="tblBody"></tbody>
  </table>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:10px">
    <span id="pageInfo" style="font-size:11.5px;color:var(--muted)"></span>
    <div class="pagination" id="pgn"></div>
  </div>
</section>

<!-- ═══ RISK & FINDINGS ═══ -->
<section id="page-risk" class="page">
  <div class="ph">
    <div class="ph-left">
      <h2>Risk &amp; Findings</h2>
      <p>Security findings with severity ratings and affected user lists</p>
    </div>
  </div>
  <div id="findingsContainer"></div>
  <div style="margin-top:24px">
    <div class="panel-title" style="font-size:15px;font-weight:700;margin-bottom:14px">👔 Manager Accountability — Users Without MFA</div>
    <p style="font-size:12.5px;color:var(--muted2);margin-bottom:14px">Managers with the most direct reports lacking MFA registration. Use this to target remediation communications.</p>
    <div id="managerAccountability"></div>
  </div>
</section>

<!-- ═══ MFA METHODS ═══ -->
<section id="page-methods" class="page">
  <div class="ph">
    <div class="ph-left">
      <h2>MFA Methods</h2>
      <p>Authentication method adoption and coverage analysis</p>
    </div>
  </div>
  <div class="method-grid" id="methodCards"></div>
  <div class="panel-grid">
    <div class="panel">
      <div class="panel-title">📊 Method Coverage (enabled users)</div>
      <div id="methodDetailBars"></div>
    </div>
    <div class="panel">
      <div class="panel-title">🔐 Authenticator App Details</div>
      <div id="msAuthDetails"></div>
    </div>
  </div>
  <div class="panel-grid">
    <div class="panel">
      <div class="panel-title">🔑 FIDO2 / Passkey Models</div>
      <div id="fido2Models"></div>
    </div>
    <div class="panel">
      <div class="panel-title">🪪 Windows Hello Key Strength</div>
      <div id="whfbKeys"></div>
    </div>
  </div>
</section>

<!-- ═══ SIGN-IN HEALTH ═══ -->
<section id="page-signin" class="page">
  <div class="ph">
    <div class="ph-left">
      <h2>Sign-in Health</h2>
      <p>Stale accounts, never signed in, and access patterns</p>
    </div>
  </div>
  <div class="panel-grid">
    <div class="panel">
      <div class="panel-title">💤 Stale Sign-in Tiers</div>
      <div id="stalePanel"></div>
    </div>
    <div class="panel">
      <div class="panel-title">📅 Account Age Distribution</div>
      <div id="acctAgePanel"></div>
    </div>
  </div>
  <div class="panel" style="margin-bottom:16px">
    <div class="panel-title">🚫 Never Signed In (Enabled Accounts)</div>
    <div id="neverSignedInList"></div>
  </div>
  <div class="panel">
    <div class="panel-title">📋 Recently Stale (90+ days, enabled)</div>
    <div id="staleList"></div>
  </div>
</section>

<!-- ═══ RAW DATA ═══ -->
<section id="page-raw" class="page">
  <div class="ph">
    <div class="ph-left">
      <h2>Raw Data</h2>
      <p>Full unfiltered CSV data — all 36 columns as imported</p>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportRawCSV()">⬇ Export Raw CSV</button>
      <button class="btn" onclick="copyRawCSV()">📋 Copy to Clipboard</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="srch-wrap">
      <span class="si">🔎</span>
      <input type="text" id="rawSearch" placeholder="Search any column…" oninput="filterRaw()"/>
    </div>
    <select id="rawDeptFilter" onchange="filterRaw()">
      <option value="">All Departments</option>
    </select>
    <select id="rawTypeFilter" onchange="filterRaw()">
      <option value="">All Types</option>
      <option value="Member">Member</option>
      <option value="Guest">Guest</option>
    </select>
    <select id="rawAcctFilter" onchange="filterRaw()">
      <option value="">All Accounts</option>
      <option value="True">Enabled</option>
      <option value="False">Disabled</option>
    </select>
    <div class="psize-wrap">
      Show <select id="rawPageSel" onchange="chRawPageSize()"><option>20</option><option>50</option><option>100</option><option value="99999">All</option></select>
    </div>
    <span class="rcount" id="rawRcount"></span>
  </div>
  <div style="overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius)">
    <table class="tbl" id="rawTbl" style="min-width:2800px;font-size:11.5px">
      <thead><tr id="rawTblHead"></tr></thead>
      <tbody id="rawTblBody"></tbody>
    </table>
  </div>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:10px">
    <span id="rawPageInfo" style="font-size:11.5px;color:var(--muted)"></span>
    <div class="pagination" id="rawPgn"></div>
  </div>
</section>

<!-- ═══ PASSWORD AGE ═══ -->
<section id="page-pwdage" class="page">
  <div class="ph">
    <div class="ph-left"><h2>Password &amp; Credential Age</h2><p>Password hygiene analysis based on passwordCreatedDateTime — NIST SP 800-63B</p></div>
    <div class="btn-group">
      <button class="btn" onclick="exportPwdAgeCSV()">⬇ Export Password Age CSV</button>
    </div>
  </div>
  <div class="kpi-grid" id="pwdKpiGrid"></div>
  <div class="panel-grid" style="margin-bottom:16px">
    <div class="panel">
      <div class="panel-title">📅 Password Age Distribution</div>
      <div id="pwdAgeBars"></div>
    </div>
    <div class="panel">
      <div class="panel-title">🏢 Oldest Passwords by Department</div>
      <div id="pwdDeptBars"></div>
    </div>
  </div>
  <div class="panel" style="margin-bottom:16px">
    <div class="panel-title">⚠️ Accounts With Oldest Passwords (Top 30, enabled)</div>
    <div id="pwdOldestList"></div>
  </div>
</section>

<!-- ═══ GUEST ACCOUNTS ═══ -->
<section id="page-guests" class="page">
  <div class="ph">
    <div class="ph-left"><h2>Guest Accounts</h2><p>External identity security — MFA, sign-in activity, and risk posture</p></div>
    <div class="btn-group">
      <button class="btn" onclick="exportGuestCSV()">⬇ Export Guest CSV</button>
    </div>
  </div>
  <div class="kpi-grid" id="guestKpiGrid"></div>
  <div class="panel-grid" style="margin-bottom:16px">
    <div class="panel">
      <div class="panel-title">🔐 Guest MFA Method Adoption</div>
      <div id="guestMFABars"></div>
    </div>
    <div class="panel">
      <div class="panel-title">💤 Guest Sign-in Activity</div>
      <div id="guestStalePanel"></div>
    </div>
  </div>
  <div class="toolbar">
    <div class="srch-wrap">
      <span class="si">🔎</span>
      <input type="text" id="guestSearch" placeholder="Search guests…" oninput="filterGuests()"/>
    </div>
    <select id="guestMFAFilter" onchange="filterGuests()">
      <option value="">All MFA States</option>
      <option value="yes">✅ Has MFA</option>
      <option value="no">⚠ No MFA</option>
    </select>
    <select id="guestAcctFilter" onchange="filterGuests()">
      <option value="">All Accounts</option>
      <option value="True">Enabled</option>
      <option value="False">Disabled</option>
    </select>
    <span class="rcount" id="guestRcount"></span>
  </div>
  <table class="tbl">
    <thead><tr>
      <th>Display Name</th>
      <th>Email / UPN</th>
      <th>MFA Methods</th>
      <th>Account</th>
      <th>Last Sign-In</th>
      <th>Manager</th>
      <th>Risk</th>
    </tr></thead>
    <tbody id="guestTblBody"></tbody>
  </table>
</section>

<!-- ═══ DEPARTMENT RISK ═══ -->
<section id="page-deptRisk" class="page">
  <div class="ph">
    <div class="ph-left"><h2>Department Risk</h2><p>MFA coverage and security posture broken down by department</p></div>
    <div class="btn-group">
      <button class="btn" onclick="exportDeptCSV()">⬇ Export Department CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <select id="deptSortSel" onchange="renderDeptTable()">
      <option value="risk">Sort by Risk Score</option>
      <option value="name">Sort by Department Name</option>
      <option value="users">Sort by User Count</option>
      <option value="nomfa">Sort by No-MFA Count</option>
    </select>
    <span class="rcount" id="deptCount"></span>
  </div>
  <div style="overflow-x:auto">
    <table class="tbl" id="deptTbl">
      <thead><tr>
        <th>Department</th>
        <th>Users</th>
        <th>Enabled</th>
        <th>With MFA</th>
        <th>No MFA</th>
        <th>Phish-Resistant</th>
        <th>SMS-Only</th>
        <th>Stale 90d+</th>
        <th>Guests</th>
        <th>Coverage</th>
        <th>Risk Level</th>
      </tr></thead>
      <tbody id="deptTblBody"></tbody>
    </table>
  </div>
  <div style="margin-top:20px" class="panel-grid">
    <div class="panel">
      <div class="panel-title">📊 No-MFA Users by Department (Top 10)</div>
      <div id="deptNoMFABars"></div>
    </div>
    <div class="panel">
      <div class="panel-title">🛡️ Phishing-Resistant Coverage by Department</div>
      <div id="deptPhishBars"></div>
    </div>
  </div>
</section>

<!-- ═══ COMPLIANCE SCORECARD ═══ -->
<section id="page-compliance" class="page">
  <div class="ph">
    <div class="ph-left">
      <h2>Compliance Scorecard</h2>
      <p>MFA posture mapped against NIST CSF 2.0 · CIS Controls v8 · Zero Trust · ISO 27001</p>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportComplianceCSV()">⬇ Export Scorecard CSV</button>
    </div>
  </div>
  <div id="complianceGrid"></div>
</section>

<!-- ═══ EXECUTIVE SUMMARY ═══ -->
<section id="page-exec" class="page">
  <div class="ph">
    <div class="ph-left">
      <h2>Executive Summary</h2>
      <p>Board-ready identity security posture snapshot — generated <span id="execGenDate"></span></p>
    </div>
    <div class="btn-group exec-noprint">
      <button class="btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
      <button class="btn" onclick="exportExecJSON()">⬇ Export Summary JSON</button>
    </div>
  </div>

  <!-- Header identity block -->
  <div class="exec-card" style="margin-bottom:18px;display:flex;align-items:center;gap:22px;flex-wrap:wrap">
    <div style="flex:1;min-width:220px">
      <div style="font-size:20px;font-weight:800;margin-bottom:4px">Entra ID MFA Security Posture</div>
      <div style="font-size:12px;color:var(--muted)" id="execSubtitle"></div>
      <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap" id="execTopChips"></div>
    </div>
    <div style="text-align:center">
      <div class="exec-grade" id="execGrade">—</div>
      <div style="font-size:11px;color:var(--muted);margin-top:5px">Overall Grade</div>
    </div>
    <div style="text-align:center">
      <div style="font-family:var(--mono);font-size:32px;font-weight:800" id="execScore">—</div>
      <div style="font-size:11px;color:var(--muted);margin-top:2px">Health Score / 100</div>
    </div>
  </div>

  <!-- KPI tiles -->
  <div class="exec-kpi-grid" id="execKpiGrid"></div>

  <!-- Two-column detail cards -->
  <div class="panel-grid">
    <div class="exec-card">
      <div class="exec-card-title">🔐 MFA Registration Breakdown</div>
      <div id="execMFABreakdown"></div>
    </div>
    <div class="exec-card">
      <div class="exec-card-title">⚠️ Top Security Risks</div>
      <div id="execTopRisks"></div>
    </div>
  </div>

  <div class="panel-grid" style="margin-top:16px">
    <div class="exec-card">
      <div class="exec-card-title">👥 Identity Population</div>
      <div id="execIdentityPop"></div>
    </div>
    <div class="exec-card">
      <div class="exec-card-title">💡 Priority Actions</div>
      <div id="execActions"></div>
    </div>
  </div>

  <!-- Footer -->
  <div style="margin-top:18px;padding:12px 18px;background:var(--surface2);border-radius:var(--radius);font-size:11.5px;color:var(--muted);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px">
    <span>Generated by Entra ID MFA Registration Dashboard v1.0</span>
    <span id="execFooterDate"></span>
    <span>CONFIDENTIAL — For internal use only</span>
  </div>
</section>

<!-- ═══ RECOMMENDATIONS ═══ -->
<section id="page-recs" class="page">
  <div class="ph">
    <div class="ph-left">
      <h2>Recommendations</h2>
      <p>Actionable remediation steps sorted by priority</p>
    </div>
  </div>
  <div id="recsContainer"></div>
</section>

</main>

<!-- DETAIL PANEL -->
<div id="dp">
  <div id="dpBack" onclick="closeDP()"></div>
  <div id="dpDrawer">
    <div class="dp-toolbar">
      <button class="btn" id="dpPrev" onclick="navDP(-1)">‹ Prev</button>
      <button class="btn" id="dpNext" onclick="navDP(1)">Next ›</button>
      <button class="btn" onclick="copyDPName()">📋 Copy UPN</button>
      <button id="dpClose" onclick="closeDP()" title="Esc">✕</button>
    </div>
    <div id="dpContent"></div>
  </div>
</div>

<div id="toast"><span id="toastIcon">✅</span><span id="toastMsg">Done</span></div>

<script>
const USERS = [__USERS_JSON__];
const DEPTS = [__DEPTS_JSON__];
const TOTAL = __TOTAL__;
const HEALTH_SCORE = __HEALTHSCORE__;
const PALETTE = ['#4f8ef7','#38d9c0','#a87fff','#2dd4a0','#f0a830','#f05968','#f07830','#ec4899','#84cc16','#60a5fa','#fbbf24','#34d399'];

// ── helpers ──
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'")}
function hasMFA(u){return u.msN||u.ph||(u.soath&&u.soath!=='False')||u.f2N||u.whN}
function isPhishR(u){return !!(u.f2N||u.whN)}
function isSMSOnly(u){return !!(u.ph && !u.msN && !u.f2N && !u.whN && (!u.soath||u.soath==='False'))}
function isStale(u,days){
  if(u.ae!=='True') return false;
  if(!u.lsi) return true;
  const d=new Date(u.lsi);
  return isNaN(d)?true:(Date.now()-d.getTime())>days*86400000;
}
function riskScore(u){
  let s=0;
  if(!hasMFA(u)&&u.ae==='True') s+=40;
  else if(isSMSOnly(u)&&u.ae==='True') s+=20;
  if(isAdminLike(u)&&!hasMFA(u)&&u.ae==='True') s+=20; // admin without MFA = extra weight
  if(isStale(u,90)&&u.ae==='True') s+=15;
  if(isStale(u,30)&&!isStale(u,90)&&u.ae==='True') s+=8;
  if(u.tapU==='True') s+=10;
  return s;
}
function isAdminLike(u){
  return /admin|adm\b|svc-|svc_|service|priv|break.?glass|tier0|tier1/i.test(u.ln||'');
}
function riskLabel(s){
  if(s>=40) return {l:'Critical',cls:'chip-red'};
  if(s>=20) return {l:'High',cls:'chip-amber'};
  if(s>=8)  return {l:'Medium',cls:'chip-amber'};
  if(s>0)   return {l:'Low',cls:'chip-green'};
  return {l:'None',cls:'chip-muted'};
}

// ── Toast ──
let _tT;
function showToast(m,i='✅'){
  document.getElementById('toastMsg').textContent=m;
  document.getElementById('toastIcon').textContent=i;
  const el=document.getElementById('toast');
  el.classList.add('show');
  clearTimeout(_tT);_tT=setTimeout(()=>el.classList.remove('show'),2600);
}

// ── Theme ──
function toggleTheme(){
  const l=document.body.classList.toggle('light');
  document.getElementById('thIcon').textContent=l?'☀️':'🌙';
  document.getElementById('thLabel').textContent=l?'Light Mode':'Dark Mode';
  try{localStorage.setItem('mfa-dash-theme',l?'light':'dark')}catch(e){}
}
(function(){
  try{if(localStorage.getItem('mfa-dash-theme')==='light'){
    document.body.classList.add('light');
    document.getElementById('thIcon').textContent='☀️';
    document.getElementById('thLabel').textContent='Light Mode';
  }}catch(e){}
})();

// ── Page nav ──
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn)btn.classList.add('active');
}

// ── Health ring ──
(function(){
  const s=HEALTH_SCORE, arc=document.getElementById('healthArc'), num=document.getElementById('healthNum');
  const circ=2*Math.PI*36; // ~226.2
  const col=s>=80?'var(--green)':s>=50?'var(--amber)':'var(--red)';
  arc.style.stroke=col; num.style.color=col;
  requestAnimationFrame(()=>requestAnimationFrame(()=>{arc.style.strokeDashoffset=circ*(1-s/100);}));
  const enabled=USERS.filter(u=>u.ae==='True');
  const withMFA=enabled.filter(hasMFA).length;
  const noMFA=enabled.length-withMFA;
  const pr=USERS.filter(isPhishR).length;
  const pct=(n,d)=>d?Math.round((n/d)*100):0;
  document.getElementById('hfWith').style.width=pct(withMFA,enabled.length)+'%';
  document.getElementById('hfNo').style.width=pct(noMFA,enabled.length)+'%';
  document.getElementById('hfPR').style.width=pct(pr,TOTAL)+'%';
  document.getElementById('hvWith').textContent=withMFA;
  document.getElementById('hvNo').textContent=noMFA;
  document.getElementById('hvPR').textContent=pr;
})();

// ── Method bars (overview) ──
(function(){
  const enabled=USERS.filter(u=>u.ae==='True');
  const N=enabled.length||1;
  const methods=[
    {l:'MS Authenticator', n:enabled.filter(u=>u.msN).length, col:'#4f8ef7'},
    {l:'Phone/SMS',        n:enabled.filter(u=>u.ph).length,  col:'#f0a830'},
    {l:'WHFB/Passkey',     n:enabled.filter(u=>u.whN).length, col:'#a87fff'},
    {l:'FIDO2 Key',        n:enabled.filter(u=>u.f2N).length, col:'#2dd4a0'},
    {l:'Software OATH',    n:enabled.filter(u=>u.soath&&u.soath!=='False').length, col:'#38d9c0'},
    {l:'Email MFA',        n:enabled.filter(u=>u.emA).length, col:'#60a5fa'},
    {l:'Passwordless',     n:enabled.filter(u=>u.plN).length, col:'#ec4899'},
    {l:'TAP Active',       n:enabled.filter(u=>u.tapU==='True').length, col:'#f07830'},
  ];
  const max=Math.max(...methods.map(m=>m.n))||1;
  const el=document.getElementById('methodBars');
  methods.forEach(m=>{
    const pct=Math.round((m.n/max)*100);
    const userPct=Math.round((m.n/N)*100);
    el.innerHTML+=`<div class="bar-row"><span class="blabel" title="${m.l}">${m.l}</span><div class="btrack"><div class="bfill" style="width:0%;background:${m.col}" data-pct="${pct}"></div></div><span class="bcount">${m.n}</span><span class="bpct">${userPct}%</span></div>`;
  });
  const el2=document.getElementById('methodDetailBars');
  methods.forEach(m=>{
    const pct=Math.round((m.n/N)*100);
    el2.innerHTML+=`<div class="bar-row"><span class="blabel" title="${m.l}">${m.l}</span><div class="btrack"><div class="bfill" style="width:0%;background:${m.col}" data-pct="${pct}"></div></div><span class="bcount">${m.n}</span><span class="bpct">${pct}%</span></div>`;
  });
  requestAnimationFrame(()=>{document.querySelectorAll('.bfill').forEach(e=>{e.style.width=e.dataset.pct+'%';});});
})();

// ── Dept bars ──
(function(){
  const el=document.getElementById('deptBars');
  const max=DEPTS.length?DEPTS[0].count:1;
  DEPTS.slice(0,10).forEach((d,i)=>{
    const pct=Math.round((d.count/max)*100);
    const col=PALETTE[i%PALETTE.length];
    el.innerHTML+=`<div class="bar-row"><span class="blabel" title="${d.dept||'(none)'}">${d.dept||'(none)'}</span><div class="btrack"><div class="bfill" style="width:0%;background:${col}" data-pct="${pct}"></div></div><span class="bcount">${d.count}</span></div>`;
  });
})();

// ── Donut ──
(function(){
  const svg=document.getElementById('donutSvg'), legend=document.getElementById('donutLegend');
  const cats=[
    {l:'Member',n:USERS.filter(u=>u.ut==='Member').length,col:'#4f8ef7'},
    {l:'Guest',n:USERS.filter(u=>u.ut==='Guest').length,col:'#a87fff'},
    {l:'Other',n:USERS.filter(u=>u.ut!=='Member'&&u.ut!=='Guest').length,col:'#38d9c0'},
  ].filter(c=>c.n>0);
  const total=cats.reduce((s,c)=>s+c.n,0)||1;
  const R=64,cx=85,cy=85,sw=22,circ=2*Math.PI*R,GAP=1.5/360;
  let offset=0;
  cats.forEach((c,i)=>{
    const frac=c.n/total,draw=Math.max(0,frac-GAP);
    const dl=draw*circ,gap=circ-dl;
    const el=document.createElementNS('http://www.w3.org/2000/svg','circle');
    el.setAttribute('cx',cx);el.setAttribute('cy',cy);el.setAttribute('r',R);
    el.setAttribute('fill','none');el.setAttribute('stroke',c.col);el.setAttribute('stroke-width',sw);
    el.setAttribute('stroke-dasharray',`${dl} ${gap}`);
    const fo=-(offset*circ)+circ*0.25;
    el.setAttribute('stroke-dashoffset',circ);
    el.style.transition=`stroke-dashoffset 0.9s cubic-bezier(.4,0,.2,1) ${i*0.1}s`;
    svg.appendChild(el);
    requestAnimationFrame(()=>requestAnimationFrame(()=>{el.style.strokeDashoffset=fo;}));
    offset+=frac;
    const pct=Math.round(frac*100);
    legend.innerHTML+=`<div class="dleg-item"><span class="dleg-dot" style="background:${c.col}"></span><span>${c.l}</span><span class="dleg-pct">${c.n} (${pct}%)</span></div>`;
  });
  const mk=(y,sz,fw,fill,txt)=>{const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',cx);t.setAttribute('y',y);t.setAttribute('text-anchor','middle');t.setAttribute('fill',fill);t.setAttribute('font-size',sz);t.setAttribute('font-weight',fw);t.textContent=txt;svg.appendChild(t);};
  mk(cy-4,'18','800','var(--text)',total);
  mk(cy+12,'10','400','var(--muted)','users');
})();

// ── Account Health panel ──
(function(){
  const el=document.getElementById('acctHealth');
  const rows=[
    {l:'✅ Enabled',n:USERS.filter(u=>u.ae==='True').length,col:'var(--green)'},
    {l:'🚫 Disabled',n:USERS.filter(u=>u.ae!=='True').length,col:'var(--red)'},
    {l:'🔄 Synced',n:USERS.filter(u=>u.sync==='True').length,col:'var(--accent)'},
    {l:'☁ Cloud-Only',n:USERS.filter(u=>u.sync!=='True').length,col:'var(--accent2)'},
    {l:'🛡 Phish-Resistant',n:USERS.filter(isPhishR).length,col:'var(--accent3)'},
    {l:'📵 SMS-Only Risk',n:USERS.filter(isSMSOnly).length,col:'var(--amber)'},
    {l:'💤 Stale 90d',n:USERS.filter(u=>isStale(u,90)).length,col:'var(--orange)'},
    {l:'⚠ No MFA',n:USERS.filter(u=>!hasMFA(u)&&u.ae==='True').length,col:'var(--red)'},
  ];
  const max=Math.max(...rows.map(r=>r.n))||1;
  rows.forEach(r=>{
    const pct=Math.round((r.n/max)*100);
    el.innerHTML+=`<div class="bar-row"><span class="blabel">${r.l}</span><div class="btrack"><div class="bfill" style="width:0%;background:${r.col}" data-pct="${pct}"></div></div><span class="bcount">${r.n}</span></div>`;
  });
  requestAnimationFrame(()=>{document.querySelectorAll('.bfill').forEach(e=>{e.style.width=e.dataset.pct+'%';});});
})();

// ── TABLE ──
let PAGE_SIZE=20,filteredUsers=[...USERS],curPage=1,curSort='dn-asc';
function chPageSize(){PAGE_SIZE=parseInt(document.getElementById('pageSel').value);curPage=1;renderTable();}
function sortCol(c){
  const flip={asc:'desc',desc:'asc'};
  const map={dn:'dn-asc',dept:'dept-asc',ut:'ut-asc',lsi:'lsi-desc'};
  if(curSort.startsWith(c)){const d=flip[curSort.endsWith('asc')?'asc':'desc'];curSort=c+'-'+d;}
  else{curSort=map[c]||c+'-asc';}
  filterTable();
}
function filterTable(){
  const q=document.getElementById('tableSearch').value.toLowerCase().trim();
  const type=document.getElementById('typeFilter').value;
  const mfa=document.getElementById('mfaFilter').value;
  const acct=document.getElementById('acctFilter').value;
  const sync=document.getElementById('syncFilter').value;
  filteredUsers=USERS.filter(u=>{
    if(q&&!u.dn.toLowerCase().includes(q)&&!u.email.toLowerCase().includes(q)&&!u.ln.toLowerCase().includes(q)&&!u.dept.toLowerCase().includes(q)&&!(u.mgr||'').toLowerCase().includes(q)) return false;
    if(type&&u.ut!==type) return false;
    if(acct==='enabled'&&u.ae!=='True') return false;
    if(acct==='disabled'&&u.ae==='True') return false;
    if(sync==='synced'&&u.sync!=='True') return false;
    if(sync==='cloud'&&u.sync==='True') return false;
    if(mfa==='yes'&&!hasMFA(u)) return false;
    if(mfa==='no'&&hasMFA(u)) return false;
    if(mfa==='phish'&&!isPhishR(u)) return false;
    if(mfa==='smsonly'&&!isSMSOnly(u)) return false;
    return true;
  });
  const S={
    'dn-asc':(a,b)=>a.dn.localeCompare(b.dn),'dn-desc':(a,b)=>b.dn.localeCompare(a.dn),
    'dept-asc':(a,b)=>a.dept.localeCompare(b.dept),'dept-desc':(a,b)=>b.dept.localeCompare(a.dept),
    'ut-asc':(a,b)=>a.ut.localeCompare(b.ut),'ut-desc':(a,b)=>b.ut.localeCompare(a.ut),
    'lsi-desc':(a,b)=>(b.lsi||'').localeCompare(a.lsi||''),'lsi-asc':(a,b)=>(a.lsi||'').localeCompare(b.lsi||''),
  };
  if(S[curSort]) filteredUsers.sort(S[curSort]);
  curPage=1;renderTable();
}
function methodDots(u){
  const methods=[];
  if(u.msN) methods.push({icon:'📱',title:'MS Authenticator',col:'#4f8ef7'});
  if(u.ph)  methods.push({icon:'📞',title:'Phone/SMS',col:'#f0a830'});
  if(u.whN) methods.push({icon:'💻',title:'Windows Hello',col:'#a87fff'});
  if(u.f2N) methods.push({icon:'🔑',title:'FIDO2',col:'#2dd4a0'});
  if(u.soath&&u.soath!=='False') methods.push({icon:'🔢',title:'Software OATH',col:'#38d9c0'});
  if(u.plN) methods.push({icon:'🔓',title:'Passwordless',col:'#ec4899'});
  if(!methods.length) return '<span style="color:var(--red);font-size:12px">⚠ None</span>';
  return `<div class="method-dots">${methods.map(m=>`<span class="method-dot" title="${m.title}" style="background:${m.col}22;border:1px solid ${m.col}44;color:${m.col}">${m.icon}</span>`).join('')}</div>`;
}
function renderTable(){
  const st=(curPage-1)*PAGE_SIZE, sl=filteredUsers.slice(st,st+PAGE_SIZE);
  document.getElementById('rcount').textContent=`${filteredUsers.length} of ${USERS.length}`;
  document.getElementById('pageInfo').textContent=`Showing ${st+1}–${Math.min(st+PAGE_SIZE,filteredUsers.length)} of ${filteredUsers.length}`;
  const rs=riskScore, rl=riskLabel;
  document.getElementById('tblBody').innerHTML=sl.map((u,i)=>{
    const r=rs(u), rb=rl(r);
    return `<tr onclick="openDP_list(${st+i})">
      <td><div class="td-name">${escH(u.dn||u.ln)}</div><div style="font-size:11px;color:var(--muted);font-family:var(--mono)">${escH(u.email||u.ln)}</div></td>
      <td class="td-muted">${escH(u.dept)||'—'}</td>
      <td>${methodDots(u)}</td>
      <td><span class="chip ${u.ut==='Guest'?'chip-purple':'chip-blue'}">${escH(u.ut)}</span></td>
      <td><span class="dot" style="background:${u.ae==='True'?'var(--green)':'var(--red)'}" title="${u.ae==='True'?'Enabled':'Disabled'}"></span></td>
      <td class="td-muted">${escH(u.lsi)||'Never'}</td>
      <td><span class="chip ${rb.cls}">${rb.l}</span></td>
    </tr>`;
  }).join('');
  renderPgn();
}
function renderPgn(){
  const total=Math.ceil(filteredUsers.length/PAGE_SIZE),el=document.getElementById('pgn');
  if(total<=1){el.innerHTML='';return;}
  let h=`<button class="pb" onclick="goPage(${curPage-1})" ${curPage===1?'disabled':''}>‹</button>`;
  for(let i=1;i<=total;i++){
    if(i===1||i===total||Math.abs(i-curPage)<=1) h+=`<button class="pb ${i===curPage?'active':''}" onclick="goPage(${i})">${i}</button>`;
    else if(Math.abs(i-curPage)===2) h+=`<span style="color:var(--muted);padding:0 4px">…</span>`;
  }
  h+=`<button class="pb" onclick="goPage(${curPage+1})" ${curPage===total?'disabled':''}>›</button>`;
  el.innerHTML=h;
}
function goPage(p){const t=Math.ceil(filteredUsers.length/PAGE_SIZE);if(p<1||p>t)return;curPage=p;renderTable();}
filterTable();

// ── DETAIL PANEL ──
let dpList=USERS,dpIdx=-1;
function openDP_list(i){dpList=filteredUsers;dpIdx=i;renderDP(dpList[i]);}
function openDP(ln){const i=USERS.findIndex(u=>u.ln===ln||u.email===ln);dpList=USERS;dpIdx=i;if(i>=0)renderDP(USERS[i]);}
function navDP(dir){const ni=dpIdx+dir;if(ni<0||ni>=dpList.length)return;dpIdx=ni;renderDP(dpList[ni]);}
function renderDP(u){
  if(!u)return;
  document.getElementById('dpPrev').disabled=dpIdx<=0;
  document.getElementById('dpNext').disabled=dpIdx>=dpList.length-1;
  const r=riskScore(u),rb=riskLabel(r);
  const risks=[];
  if(!hasMFA(u)&&u.ae==='True') risks.push({sev:'critical',t:'No MFA Registered',d:'This enabled account has no authentication methods registered. It is vulnerable to password attacks and account takeover.'});
  if(isSMSOnly(u)) risks.push({sev:'high',t:'SMS-Only Authentication',d:'SMS/voice authentication is susceptible to SIM-swap and SS7 attacks. Upgrade to Microsoft Authenticator or FIDO2.'});
  if(isStale(u,90)&&u.ae==='True') risks.push({sev:'medium',t:'Stale Account (90+ days)',d:'No interactive sign-in detected in over 90 days. Consider reviewing account necessity and disabling if not required.'});
  if(isStale(u,30)&&!isStale(u,90)&&u.ae==='True') risks.push({sev:'low',t:'Stale Account (30–90 days)',d:'No sign-in in 30–90 days. Monitor for continued inactivity.'});
  if(u.tapU==='True') risks.push({sev:'medium',t:'Active TAP Credential',d:`A Temporary Access Pass is active (started: ${u.tapS||'unknown'}, lifetime: ${u.tapL||'unknown'} min). Ensure it was issued intentionally.`});
  if(u.ut==='Guest'&&!hasMFA(u)) risks.push({sev:'high',t:'Guest Account Without MFA',d:'External guest accounts without MFA represent a significant risk, especially for collaboration data access.'});

  const methodsHtml=(()=>{
    const ms=[];
    if(u.msN) ms.push(`<div class="method-card"><div class="method-card-head"><span>📱</span><span class="method-card-title" style="color:#4f8ef7">Microsoft Authenticator</span></div><div class="method-card-body">Device: ${escH(u.msN)}<br>Tag: ${escH(u.msDT)||'—'} &nbsp;·&nbsp; Version: ${escH(u.msV)||'—'}</div></div>`);
    if(u.ph)  ms.push(`<div class="method-card"><div class="method-card-head"><span>📞</span><span class="method-card-title" style="color:#f0a830">Phone Authentication</span></div><div class="method-card-body">Number: ${escH(u.ph)}<br>Type: ${escH(u.phT)||'—'} &nbsp;·&nbsp; SMS Sign-In: ${escH(u.sms)||'—'}</div></div>`);
    if(u.whN) ms.push(`<div class="method-card"><div class="method-card-head"><span>💻</span><span class="method-card-title" style="color:#a87fff">Windows Hello for Business</span></div><div class="method-card-body">Device: ${escH(u.whN)}<br>Created: ${escH(u.whC)||'—'} &nbsp;·&nbsp; Key Strength: ${escH(u.whKS)||'—'}</div></div>`);
    if(u.f2N) ms.push(`<div class="method-card"><div class="method-card-head"><span>🔑</span><span class="method-card-title" style="color:#2dd4a0">FIDO2 Security Key</span></div><div class="method-card-body">Name: ${escH(u.f2N)}<br>Model: ${escH(u.f2M)||'—'} &nbsp;·&nbsp; Created: ${escH(u.f2D)||'—'}</div></div>`);
    if(u.soath&&u.soath!=='False') ms.push(`<div class="method-card"><div class="method-card-head"><span>🔢</span><span class="method-card-title" style="color:#38d9c0">Software OATH Token</span></div><div class="method-card-body">Status: ${escH(u.soath)}</div></div>`);
    if(u.plN) ms.push(`<div class="method-card"><div class="method-card-head"><span>🔓</span><span class="method-card-title" style="color:#ec4899">Passwordless Phone Sign-in</span></div><div class="method-card-body">Device: ${escH(u.plN)}<br>Tag: ${escH(u.plDT)||'—'} &nbsp;·&nbsp; Version: ${escH(u.plV)||'—'}</div></div>`);
    if(u.tapU==='True') ms.push(`<div class="method-card" style="border-color:var(--amber)"><div class="method-card-head"><span>🎫</span><span class="method-card-title" style="color:var(--amber)">Temporary Access Pass (ACTIVE)</span></div><div class="method-card-body">Start: ${escH(u.tapS)||'—'} &nbsp;·&nbsp; Lifetime: ${escH(u.tapL)||'—'} min<br>One-time: ${escH(u.tapO)||'—'}</div></div>`);
    if(u.emA) ms.push(`<div class="method-card"><div class="method-card-head"><span>📧</span><span class="method-card-title" style="color:#60a5fa">Email MFA</span></div><div class="method-card-body">Address: ${escH(u.emA)}</div></div>`);
    return ms.length?ms.join(''):'<p style="color:var(--muted);font-size:12px">No authentication methods registered.</p>';
  })();

  document.getElementById('dpContent').innerHTML=`
    <div class="dp-name">${escH(u.dn||u.ln)}</div>
    <div class="dp-email">${escH(u.email||u.ln)}</div>
    <div class="dp-chips">
      <span class="chip ${u.ut==='Guest'?'chip-purple':'chip-blue'}">${escH(u.ut)}</span>
      <span class="chip ${u.ae==='True'?'chip-green':'chip-red'}">${u.ae==='True'?'✅ Enabled':'🚫 Disabled'}</span>
      <span class="chip ${u.sync==='True'?'chip-cyan':'chip-muted'}">${u.sync==='True'?'🔄 Synced':'☁ Cloud'}</span>
      <span class="chip ${rb.cls}">${rb.l} Risk</span>
      ${hasMFA(u)?'<span class="chip chip-green">🔐 MFA Registered</span>':'<span class="chip chip-red">⚠ No MFA</span>'}
      ${isPhishR(u)?'<span class="chip chip-purple">🛡 Phish-Resistant</span>':''}
    </div>
    <div class="dp-section">
      <div class="dp-stitle">Identity Details</div>
      <div class="info-grid">
        <div class="info-row"><span class="info-label">Department</span><span class="info-val">${escH(u.dept)||'—'}</span></div>
        <div class="info-row"><span class="info-label">Last Sign-In</span><span class="info-val">${escH(u.lsi)||'Never'}</span></div>
        <div class="info-row"><span class="info-label">Last Non-Interactive</span><span class="info-val">${escH(u.lnisi)||'—'}</span></div>
        <div class="info-row"><span class="info-label">Account Created</span><span class="info-val">${escH(u.cdt)||'—'}</span></div>
        <div class="info-row"><span class="info-label">Password Created</span><span class="info-val">${escH(u.pwCr)||'—'}</span></div>
        <div class="info-row"><span class="info-label">Manager</span><span class="info-val">${escH(u.mgr)||'—'}</span></div>
        <div class="info-row"><span class="info-label">Manager UPN</span><span class="info-val">${escH(u.mgrU)||'—'}</span></div>
        <div class="info-row"><span class="info-label">Manager Email</span><span class="info-val">${escH(u.mgrM)||'—'}</span></div>
      </div>
    </div>
    <div class="dp-section">
      <div class="dp-stitle">Authentication Methods</div>
      ${methodsHtml}
    </div>
    ${risks.length?`<div class="dp-section"><div class="dp-stitle">Risk Flags</div>${risks.map(r=>`<div class="risk-item ${r.sev}"><div class="risk-title">${r.t}</div><div class="risk-desc">${r.d}</div></div>`).join('')}</div>`:'<div class="dp-section"><div class="dp-stitle">Risk Flags</div><p style="color:var(--green);font-size:13px">✅ No active risks detected.</p></div>'}`;
  document.getElementById('dp').classList.add('open');
  document.body.style.overflow='hidden';
  document.getElementById('dpContent').scrollTo(0,0);
}
function closeDP(){document.getElementById('dp').classList.remove('open');document.body.style.overflow='';}
function copyDPName(){if(dpIdx>=0&&dpList[dpIdx])copyText(dpList[dpIdx].ln||dpList[dpIdx].email,null);}
function copyText(t,btn){
  try{navigator.clipboard.writeText(t).then(()=>{showToast('Copied to clipboard!');if(btn){btn.textContent='✓';setTimeout(()=>btn.textContent='Copy',1800);}});}
  catch(e){showToast('Copy unavailable','⚠');}
}

// ── RISK & FINDINGS ──
(function(){
  const el=document.getElementById('findingsContainer');
  const enabled=USERS.filter(u=>u.ae==='True');
  const noMFAList=enabled.filter(u=>!hasMFA(u));
  const smsOnlyList=USERS.filter(isSMSOnly);
  const stale90List=enabled.filter(u=>isStale(u,90));
  const tapList=USERS.filter(u=>u.tapU==='True');
  const guestNoMFA=USERS.filter(u=>u.ut==='Guest'&&!hasMFA(u));
  const noSyncMFA=USERS.filter(u=>u.sync==='True'&&!hasMFA(u)&&u.ae==='True');
  const neverList=enabled.filter(u=>!u.lsi);
  const phishPct=Math.round((USERS.filter(isPhishR).length/TOTAL)*100);

  const findings=[
    {
      sev:'critical',title:'Enabled Accounts Without Any MFA',
      body:`${noMFAList.length} active accounts have no MFA methods registered. These accounts rely solely on password authentication and are highly vulnerable to credential-based attacks including phishing, password spray, and credential stuffing.`,
      stats:[{l:'Affected Users',v:noMFAList.length},{l:'% of Active Accounts',v:Math.round((noMFAList.length/(enabled.length||1))*100)+'%'}],
      affected:noMFAList,
      action:'Enforce MFA via Conditional Access policy. Communicate enrollment deadline. Use Microsoft Authenticator App — it provides the strongest protection and supports passwordless sign-in.',
    },
    {
      sev:'high',title:'SMS / Voice Call Only — Weak Authentication',
      body:`${smsOnlyList.length} users have only phone-based (SMS or voice call) MFA with no stronger method. SMS is vulnerable to SIM-swapping, SS7 attacks, and real-time phishing interception. Attackers can intercept these codes within seconds using phishing kits.`,
      stats:[{l:'SMS-Only Users',v:smsOnlyList.length},{l:'% of MFA Users',v:USERS.filter(hasMFA).length?Math.round((smsOnlyList.length/USERS.filter(hasMFA).length)*100)+'%':'—'}],
      affected:smsOnlyList,
      action:'Enrol these users in Microsoft Authenticator (number matching enabled). Disable SMS sign-in for accounts that do not require it. Consider blocking SMS MFA for privileged roles via Conditional Access authentication strength policies.',
    },
    {
      sev:'high',title:'Guest Accounts Without MFA',
      body:`${guestNoMFA.length} external guest accounts have no MFA. Guest accounts often have access to SharePoint sites, Teams channels, and other sensitive collaboration resources. Without MFA they represent a significant supply-chain and data-exfiltration risk.`,
      stats:[{l:'Guest Accounts',v:USERS.filter(u=>u.ut==='Guest').length},{l:'Without MFA',v:guestNoMFA.length}],
      affected:guestNoMFA,
      action:'Apply Conditional Access policies that require MFA for all guest/external identities. Use Cross-Tenant Access Settings to enforce inbound MFA trust only when the partner organisation has equivalent controls.',
    },
    {
      sev:'medium',title:'Active Temporary Access Passes (TAP)',
      body:`${tapList.length} user(s) currently have an active Temporary Access Pass. TAPs bypass normal authentication and are designed for emergency/onboarding use only. Active TAPs that are not immediately needed represent an open authentication bypass.`,
      stats:[{l:'Active TAPs',v:tapList.length}],
      affected:tapList,
      action:'Review all active TAPs. Revoke any that have served their purpose. Audit TAP issuance logs in the Entra portal. Consider scoping TAP issuance to a break-glass or Service Desk role only.',
    },
    {
      sev:'medium',title:'Stale Accounts — No Sign-In for 90+ Days',
      body:`${stale90List.length} enabled accounts have had no interactive sign-in in over 90 days. Stale accounts increase the attack surface — if their passwords are compromised, attackers gain persistent, undetected access. They also indicate orphaned or redundant identities.`,
      stats:[{l:'Stale 90d+',v:stale90List.length},{l:'Never Signed In',v:neverList.length}],
      affected:stale90List.slice(0,30),
      action:'Review stale accounts with account owners and managers. Disable accounts unused for 90+ days. Delete accounts unused for 180+ days (after backup of any owned resources). Implement a quarterly joiner/mover/leaver review process.',
    },
    {
      sev:'medium',title:'Synced Accounts Without MFA',
      body:`${noSyncMFA.length} on-premises synced accounts have no MFA registered. Hybrid accounts inherit the risk of on-prem credential compromise — if on-prem Active Directory is breached, these accounts can be used to access cloud resources without any additional authentication barrier.`,
      stats:[{l:'Synced Accounts',v:USERS.filter(u=>u.sync==='True').length},{l:'Without MFA',v:noSyncMFA.length}],
      affected:noSyncMFA,
      action:'Prioritise MFA enrolment for synced accounts. Consider deploying Microsoft Entra Password Protection on-premises. Review on-prem AD security posture alongside cloud MFA remediation.',
    },
    {
      sev:'low',title:'Low Phishing-Resistant MFA Adoption',
      body:`Only ${phishPct}% of users have phishing-resistant methods (FIDO2 or Windows Hello for Business). While any MFA is better than none, push notification and OTP-based MFA can still be bypassed by real-time phishing kits (e.g. Evilginx2, Modlishka). Phishing-resistant methods eliminate this attack vector entirely.`,
      stats:[{l:'Phish-Resistant',v:USERS.filter(isPhishR).length},{l:'Coverage',v:phishPct+'%'}],
      affected:[],
      action:'Define a roadmap to increase phishing-resistant MFA adoption. Prioritise privileged/admin roles first. Deploy FIDO2 hardware keys for admins and high-risk users. Enable Windows Hello for Business for Windows-joined devices. Use Conditional Access Authentication Strength to enforce phishing-resistant MFA for sensitive apps.',
    },
	{
      sev:'critical',title:'Admin / Service Accounts Without MFA',
      body:`Accounts with admin-like naming patterns (admin, adm, svc, service, priv) that have no MFA registered. These accounts typically hold elevated privileges and represent the highest-priority risk in any identity estate.`,
      stats:[{l:'Admin-like accounts without MFA',v:enabled.filter(u=>isAdminLike(u)&&!hasMFA(u)).length}],
      affected:enabled.filter(u=>isAdminLike(u)&&!hasMFA(u)),
      action:'Immediately enrol all admin and service accounts in MFA. For service accounts, consider using Workload Identity Federation or Managed Identities instead of interactive credentials. Enforce phishing-resistant MFA (FIDO2/WHFB) for all privileged roles via Conditional Access Authentication Strength.',
    },
  ].filter(f=>f.stats[0].v>0||(typeof f.stats[0].v==='string'));

  el.innerHTML=findings.map(f=>`
    <div class="finding-card">
      <div class="fc-head">
        <span class="severity-badge sev-${f.sev}">${f.sev.toUpperCase()}</span>
        <div class="fc-title">${escH(f.title)}</div>
      </div>
      <div class="fc-body">${escH(f.body)}</div>
      ${f.stats.map(s=>`<span class="fc-stat"><strong>${escH(String(s.v))}</strong> ${escH(s.l)}</span>`).join('')}
      <div class="fc-actions">
        <div class="fc-action-title" style="display:flex;align-items:center;gap:10px">
          Recommended Action
          ${f.affected.length?`<button class="btn exec-noprint" onclick="copyFindingUPNs(this,'${escJ(f.affected.slice(0,40).map(u=>u.ln||u.email).join(';'))}')" style="font-size:11px;padding:3px 9px;margin-left:auto">📋 Copy ${Math.min(f.affected.length,40)} UPNs</button>`:''}
        </div>
        <p style="font-size:12.5px;color:var(--muted2)">${escH(f.action)}</p>
        ${f.affected.length?`<div class="affected-list">${f.affected.slice(0,40).map(u=>`<span class="affected-chip" onclick="openDP('${escJ(u.ln||u.email)}')">${escH(u.dn||u.ln)}</span>`).join('')}${f.affected.length>40?`<span class="affected-chip" style="background:var(--surface2);color:var(--muted)">+${f.affected.length-40} more</span>`:''}</div>`:''}
      </div>
    </div>`).join('');
})();

// ── MANAGER ACCOUNTABILITY ──
(function(){
  const noMFAUsers=USERS.filter(u=>u.ae==='True'&&!hasMFA(u)&&u.mgr);
  const mgrMap={};
  noMFAUsers.forEach(u=>{
    const key=u.mgr||'Unknown Manager';
    if(!mgrMap[key]) mgrMap[key]={name:u.mgr,upn:u.mgrU,email:u.mgrM,users:[]};
    mgrMap[key].users.push(u);
  });
  const sorted=Object.values(mgrMap).sort((a,b)=>b.users.length-a.users.length).slice(0,15);
  const el=document.getElementById('managerAccountability');
  if(!sorted.length){
    el.innerHTML='<p style="color:var(--green);font-size:13px">✅ No managers have direct reports without MFA.</p>';
    return;
  }
  el.innerHTML=sorted.map(m=>`
    <div class="finding-card" style="margin-bottom:10px">
      <div class="fc-head">
        <span class="severity-badge sev-${m.users.length>=5?'critical':m.users.length>=3?'high':'medium'}">${m.users.length} USER${m.users.length>1?'S':''}</span>
        <div>
          <div class="fc-title">${escH(m.name)}</div>
          <div style="font-size:12px;color:var(--muted);font-family:var(--mono)">${escH(m.upn||m.email||'')}</div>
        </div>
        <button class="btn exec-noprint" onclick="copyMgrList('${escJ(m.users.map(u=>u.ln).join(';'))}','${escJ(m.name)}')" style="margin-left:auto;font-size:11.5px">📋 Copy UPNs</button>
      </div>
      <div class="affected-list">${m.users.map(u=>`<span class="affected-chip" onclick="openDP('${escJ(u.ln||u.email)}')">${escH(u.dn||u.ln)}</span>`).join('')}</div>
    </div>`).join('');
})();

function copyFindingUPNs(btn, upnsRaw){
  const upns=upnsRaw.split(';').filter(Boolean).join('\n');
  const count=upnsRaw.split(';').filter(Boolean).length;
  navigator.clipboard.writeText(upns)
    .then(()=>{
      showToast(`Copied ${count} UPN(s) to clipboard`);
      const orig=btn.textContent;
      btn.textContent='✓ Copied!';
      setTimeout(()=>btn.textContent=orig,2000);
    })
    .catch(()=>showToast('Copy unavailable — use Export CSV instead','⚠'));
}

function copyMgrList(upnsRaw, mgrName){
  const upns=upnsRaw.split(';').join('\n');
  navigator.clipboard.writeText(upns).then(()=>showToast(`Copied ${upnsRaw.split(';').length} UPNs for ${mgrName}`));
}

// ── MFA METHODS PAGE ──
(function(){
  const enabled=USERS.filter(u=>u.ae==='True'),N=enabled.length||1;
  const cards=[
    {icon:'📱',label:'MS Authenticator',n:USERS.filter(u=>u.msN).length,col:'#4f8ef7'},
    {icon:'📞',label:'Phone / SMS',n:USERS.filter(u=>u.ph).length,col:'#f0a830'},
    {icon:'💻',label:'Win Hello (WHFB)',n:USERS.filter(u=>u.whN).length,col:'#a87fff'},
    {icon:'🔑',label:'FIDO2 Key',n:USERS.filter(u=>u.f2N).length,col:'#2dd4a0'},
    {icon:'🔢',label:'Software OATH',n:USERS.filter(u=>u.soath&&u.soath!=='False').length,col:'#38d9c0'},
    {icon:'🔓',label:'Passwordless',n:USERS.filter(u=>u.plN).length,col:'#ec4899'},
    {icon:'📧',label:'Email MFA',n:USERS.filter(u=>u.emA).length,col:'#60a5fa'},
    {icon:'🎫',label:'TAP Active',n:USERS.filter(u=>u.tapU==='True').length,col:'#f07830'},
  ];
  document.getElementById('methodCards').innerHTML=cards.map(c=>{
    const pct=Math.round((c.n/TOTAL)*100);
    return `<div class="method-stat-card"><div class="ms-icon">${c.icon}</div><div class="ms-val" style="color:${c.col}">${c.n}</div><div class="ms-label">${c.label}</div><span class="ms-pct">${pct}%</span><div class="ms-bar"><div class="ms-bar-fill" style="width:0%;background:${c.col}" data-pct="${pct}"></div></div></div>`;
  }).join('');

  // MS Auth details
  const msV=USERS.filter(u=>u.msV).reduce((a,u)=>{const v=(u.msV||'').split('.').slice(0,2).join('.');a[v]=(a[v]||0)+1;return a},{});
  const msVArr=Object.entries(msV).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const msVMax=msVArr.length?msVArr[0][1]:1;
  document.getElementById('msAuthDetails').innerHTML=msVArr.length?msVArr.map(([v,n])=>`<div class="bar-row"><span class="blabel" title="v${v}">v${v}</span><div class="btrack"><div class="bfill" style="width:0%;background:#4f8ef7" data-pct="${Math.round((n/msVMax)*100)}"></div></div><span class="bcount">${n}</span></div>`).join(''):'<p style="color:var(--muted);font-size:12px">No Authenticator app version data.</p>';

  // FIDO2 models
  const f2m=USERS.filter(u=>u.f2M).reduce((a,u)=>{a[u.f2M]=(a[u.f2M]||0)+1;return a},{});
  const f2Arr=Object.entries(f2m).sort((a,b)=>b[1]-a[1]);
  const f2Max=f2Arr.length?f2Arr[0][1]:1;
  document.getElementById('fido2Models').innerHTML=f2Arr.length?f2Arr.map(([m,n])=>`<div class="bar-row"><span class="blabel" title="${m}">${m}</span><div class="btrack"><div class="bfill" style="width:0%;background:#2dd4a0" data-pct="${Math.round((n/f2Max)*100)}"></div></div><span class="bcount">${n}</span></div>`).join(''):'<p style="color:var(--muted);font-size:12px">No FIDO2 keys registered.</p>';

  // WHFB key strength
  const wks=USERS.filter(u=>u.whKS).reduce((a,u)=>{a[u.whKS]=(a[u.whKS]||0)+1;return a},{});
  const wksArr=Object.entries(wks).sort((a,b)=>b[1]-a[1]);
  const wksMax=wksArr.length?wksArr[0][1]:1;
  document.getElementById('whfbKeys').innerHTML=wksArr.length?wksArr.map(([k,n],i)=>`<div class="bar-row"><span class="blabel" title="${k}">${k}</span><div class="btrack"><div class="bfill" style="width:0%;background:${PALETTE[i%PALETTE.length]}" data-pct="${Math.round((n/wksMax)*100)}"></div></div><span class="bcount">${n}</span></div>`).join(''):'<p style="color:var(--muted);font-size:12px">No Windows Hello data available.</p>';

  requestAnimationFrame(()=>{document.querySelectorAll('.ms-bar-fill,.bfill').forEach(e=>{e.style.width=e.dataset.pct+'%';});});
})();

// ── SIGN-IN HEALTH ──
(function(){
  const enabled=USERS.filter(u=>u.ae==='True');
  const neverList=enabled.filter(u=>!u.lsi).slice(0,20);
  const s90=enabled.filter(u=>isStale(u,90)).sort((a,b)=>(a.lsi||'').localeCompare(b.lsi||''));
  const s30=enabled.filter(u=>isStale(u,30)&&!isStale(u,90));
  const s7=enabled.filter(u=>isStale(u,7)&&!isStale(u,30));
  const active=enabled.filter(u=>!isStale(u,7));

  document.getElementById('stalePanel').innerHTML=[
    {icon:'✅',label:'Active (< 7 days)',sub:'Healthy sign-in activity',n:active.length,col:'var(--green)'},
    {icon:'🟡',label:'Moderately Stale (7–30d)',sub:'Watch for continued inactivity',n:s7.length,col:'var(--amber)'},
    {icon:'🟠',label:'Stale (30–90d)',sub:'Review account necessity',n:s30.length,col:'var(--orange)'},
    {icon:'🔴',label:'Very Stale (90d+)',sub:'Consider disabling',n:s90.length,col:'var(--red)'},
    {icon:'⚫',label:'Never Signed In',sub:'Newly provisioned or orphaned',n:enabled.filter(u=>!u.lsi).length,col:'var(--muted)'},
  ].map(r=>`<div class="stale-level"><span class="stale-icon">${r.icon}</span><div class="stale-info"><div class="stale-label">${r.label}</div><div class="stale-sub">${r.sub}</div></div><span class="stale-count" style="color:${r.col}">${r.n}</span></div>`).join('');

  // Account age distribution
  const now=Date.now();
  const ages=USERS.map(u=>{if(!u.cdt)return null;const d=new Date(u.cdt);return isNaN(d)?null:Math.floor((now-d.getTime())/(86400000*30));}).filter(a=>a!==null);
  const ageBuckets=[
    {l:'< 1 month',fn:a=>a<1},{l:'1–6 months',fn:a=>a>=1&&a<6},{l:'6–12 months',fn:a=>a>=6&&a<12},
    {l:'1–2 years',fn:a=>a>=12&&a<24},{l:'2–3 years',fn:a=>a>=24&&a<36},{l:'3+ years',fn:a=>a>=36},
  ];
  const aBCols=['#4f8ef7','#38d9c0','#a87fff','#2dd4a0','#f0a830','#f05968'];
  const aBmax=Math.max(...ageBuckets.map(b=>ages.filter(b.fn).length))||1;
  document.getElementById('acctAgePanel').innerHTML=ageBuckets.map((b,i)=>{
    const n=ages.filter(b.fn).length,pct=Math.round((n/aBmax)*100);
    return `<div class="bar-row"><span class="blabel">${b.l}</span><div class="btrack"><div class="bfill" style="width:0%;background:${aBCols[i]}" data-pct="${pct}"></div></div><span class="bcount">${n}</span></div>`;
  }).join('');

  document.getElementById('neverSignedInList').innerHTML=neverList.length?neverList.map(u=>`<span class="affected-chip" onclick="openDP('${escJ(u.ln||u.email)}')">${escH(u.dn||u.ln)}</span>`).join(''):'<p style="color:var(--green);font-size:13px">✅ All enabled accounts have signed in at least once.</p>';

  document.getElementById('staleList').innerHTML=s90.length?s90.slice(0,20).map(u=>`<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border)"><span style="color:var(--red);font-size:12px">💤</span><span class="td-name" style="flex:1;cursor:pointer" onclick="openDP('${escJ(u.ln||u.email)}')">${escH(u.dn||u.ln)}</span><span class="td-muted">${escH(u.dept)||'—'}</span><span class="td-muted">${escH(u.lsi)||'Never'}</span></div>`).join(''):'<p style="color:var(--green);font-size:13px">✅ No enabled accounts stale 90+ days.</p>';

  requestAnimationFrame(()=>{document.querySelectorAll('.bfill').forEach(e=>{e.style.width=e.dataset.pct+'%';});});
})();

// ── RECOMMENDATIONS ──
(function(){
  const el=document.getElementById('recsContainer');
  const noMFA=USERS.filter(u=>!hasMFA(u)&&u.ae==='True').length;
  const smsOnly=USERS.filter(isSMSOnly).length;
  const stale=USERS.filter(u=>isStale(u,90)&&u.ae==='True').length;
  const guestNoMFA=USERS.filter(u=>u.ut==='Guest'&&!hasMFA(u)).length;
  const phishPct=Math.round((USERS.filter(isPhishR).length/TOTAL)*100);

  const recs=[
    {
      icon:'🚨',col:'#f05968',title:'Enforce MFA for All Active Users via Conditional Access',
      sev:'critical',score:noMFA,
      desc:'Conditional Access is the most effective control to ensure MFA is enforced at sign-in time, not just registered. Registration alone does not guarantee MFA is required at login.',
      steps:['Navigate to Entra ID → Protection → Conditional Access → New Policy','Target: All Users (exclude break-glass accounts)','Cloud Apps: All Cloud Apps','Grant: Require multi-factor authentication','Enable in Report-Only mode first, review sign-in logs, then switch to Enabled','Monitor for legacy auth clients — block them with a separate policy'],
      tags:['Conditional Access','MFA','Zero Trust'],
    },
    {
      icon:'📱',col:'#4f8ef7',title:'Migrate SMS/Voice Users to Microsoft Authenticator',
      sev:'high',score:smsOnly,
      desc:'Microsoft Authenticator with number matching is significantly more resistant to real-time phishing. The Authenticator app also supports passwordless phone sign-in, reducing reliance on passwords entirely.',
      steps:['Enable the Microsoft Authenticator in Authentication Methods policy','Enable Number Matching (blocks OTP relay attacks)','Enable Additional Context (shows app name and location)','Create a communication campaign targeting SMS-only users','Set a 30-day deadline with helpdesk support available','Consider nudge campaigns via MySecurityInfo (aka.ms/mysecurityinfo)'],
      tags:['Authenticator','Phishing Prevention','User Education'],
    },
    {
      icon:'🛡️',col:'#a87fff',title:'Expand Phishing-Resistant MFA Coverage',
      sev:'medium',score:100-phishPct,
      desc:`Current phishing-resistant coverage is ${phishPct}%. FIDO2 and Windows Hello for Business are the only methods that cryptographically bind authentication to the legitimate site, making real-time phishing impossible.`,
      steps:['Prioritise FIDO2 enrolment for all privileged/admin roles immediately','Enable Windows Hello for Business for all Entra ID joined devices','Use Authentication Strength in Conditional Access to require phishing-resistant MFA for sensitive apps (e.g., admin portals, finance systems)','Deploy hardware security keys (e.g., YubiKey) for accounts that cannot use biometrics','Set a 12-month roadmap to reach 80%+ phishing-resistant coverage'],
      tags:['FIDO2','WHFB','Authentication Strength'],
    },
    {
      icon:'👤',col:'#f0a830',title:'Remediate Guest Accounts Without MFA',
      sev:'high',score:guestNoMFA,
      desc:'External collaborators without MFA can access shared documents, Teams channels, and applications. A compromised guest account can be used for data exfiltration or lateral movement into shared resources.',
      steps:['Create a Conditional Access policy targeting all Guest users requiring MFA','Use Cross-Tenant Access Settings to require MFA for specific partner tenants','Review all guest accounts — remove any that are no longer active','Enable access reviews for guest accounts (Entra ID Governance)','Set guest account expiry policies (180 days recommended)'],
      tags:['Guest Access','External Collaboration','Access Reviews'],
    },
    {
      icon:'💤',col:'#38d9c0',title:'Implement a Stale Account Remediation Programme',
      sev:'medium',score:stale,
      desc:`${stale} accounts have been inactive for 90+ days. A formal joiner/mover/leaver process reduces the stale account footprint and limits the blast radius of any credential compromise.`,
      steps:['Run this report monthly and export the stale account list','Send automated access review notifications to managers via Entra ID Governance','Disable accounts with no sign-in for 90 days after manager review','Delete (or archive group memberships for) accounts inactive 180+ days','Integrate with HR system to trigger automatic offboarding on departure date','Review and revoke all app registrations and group memberships before deletion'],
      tags:['Lifecycle Management','Access Reviews','Governance'],
    },
    {
      icon:'🎫',col:'#f07830',title:'Tighten Temporary Access Pass Controls',
      sev:'medium',score:0,
      desc:'TAPs bypass normal authentication and should be tightly controlled. Audit existing TAP issuance and establish operational procedures to prevent misuse.',
      steps:['Restrict TAP creation to a specific security role (e.g., Authentication Admin)','Set TAP lifetime to the minimum required (default 1 hour; reduce if possible)','Use one-time TAPs unless multiple uses are genuinely required','Enable alerting for TAP issuance in Microsoft Sentinel or Defender for Identity','Review TAP usage in Sign-In logs monthly (filter: Authentication Detail = Temporary Access Pass)'],
      tags:['TAP','Privileged Access','Audit'],
    },
    {
      icon:'📊',col:'#2dd4a0',title:'Establish a Monthly MFA Health Review Process',
      sev:'low',score:0,
      desc:'Point-in-time reports become stale quickly. Automating a monthly review ensures new hires, role changes, and method degradations are caught promptly.',
      steps:['Schedule this script to run automatically each month and email the HTML report to IT Security','Set up Entra ID access reviews for MFA registration (Entra ID Governance)','Configure alerts in Microsoft Sentinel for accounts with MFA disabled','Track phishing-resistant coverage % as a KPI in your security dashboard','Review Entra ID Recommendations blade monthly for Microsoft-generated guidance'],
      tags:['Automation','KPIs','Continuous Improvement'],
    },
  ];

  el.innerHTML=recs.map(r=>`
    <div class="rec-card">
      <div class="rec-icon-wrap" style="background:${r.col}18">${r.icon}</div>
      <div class="rec-body">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
          <div class="rec-title">${escH(r.title)}</div>
          <span class="chip sev-${r.sev==='critical'?'critical':r.sev==='high'?'high':r.sev==='medium'?'medium':'low'} chip-${r.sev==='critical'?'red':r.sev==='high'?'amber':r.sev==='medium'?'amber':'green'}">${r.sev.toUpperCase()}</span>
        </div>
        <div class="rec-desc">${escH(r.desc)}</div>
        <ol class="rec-steps">${r.steps.map(s=>`<li>${escH(s)}</li>`).join('')}</ol>
        <div class="rec-tags">${r.tags.map(t=>`<span class="chip chip-muted">${escH(t)}</span>`).join('')}</div>
      </div>
    </div>`).join('');
})();

// ── PASSWORD AGE ──
(function(){
  const now=Date.now();
  function pwdAgeDays(u){
    if(!u.pwCr) return null;
    const d=new Date(u.pwCr);
    return isNaN(d)?null:Math.floor((now-d.getTime())/86400000);
  }

  const enabled=USERS.filter(u=>u.ae==='True');
  const withPwd=enabled.filter(u=>pwdAgeDays(u)!==null);
  const noPwdDate=enabled.length-withPwd.length;

  const buckets=[
    {l:'< 30 days',   min:0,   max:30,  col:'#2dd4a0'},
    {l:'30–90 days',  min:30,  max:90,  col:'#38d9c0'},
    {l:'90–180 days', min:90,  max:180, col:'#4f8ef7'},
    {l:'180d – 1yr',  min:180, max:365, col:'#f0a830'},
    {l:'1–2 years',   min:365, max:730, col:'#f07830'},
    {l:'2+ years',    min:730, max:99999,col:'#f05968'},
  ];

  const bCounts=buckets.map(b=>withPwd.filter(u=>{const d=pwdAgeDays(u);return d>=b.min&&d<b.max;}).length);
  const bMax=Math.max(...bCounts)||1;
  const oldest=withPwd.sort((a,b)=>pwdAgeDays(b)-pwdAgeDays(a));
  const avg=withPwd.length?Math.round(withPwd.reduce((s,u)=>s+pwdAgeDays(u),0)/withPwd.length):0;
  const over180=withPwd.filter(u=>pwdAgeDays(u)>=180).length;
  const over365=withPwd.filter(u=>pwdAgeDays(u)>=365).length;

  // KPIs
  document.getElementById('pwdKpiGrid').innerHTML=[
    {icon:'📅',label:'Avg Password Age',val:`${avg}d`,col:'blue'},
    {icon:'⚠️',label:'180d+ Old',val:over180,sub:`${Math.round((over180/(withPwd.length||1))*100)}%`,col:over180>0?'amber':'green'},
    {icon:'🔴',label:'1yr+ Old',val:over365,sub:`${Math.round((over365/(withPwd.length||1))*100)}%`,col:over365>0?'red':'green'},
    {icon:'❓',label:'No Date Recorded',val:noPwdDate,col:'amber'},
  ].map(k=>`<div class="kpi ${k.col}"><div class="kpi-icon">${k.icon}</div><div class="kpi-val">${k.val}</div><div class="kpi-sub">${k.label}</div>${k.sub?`<span class="kpi-trend ${k.col==='red'?'bad':'warn'}">${k.sub}</span>`:''}</div>`).join('');

  // Age distribution bars
  document.getElementById('pwdAgeBars').innerHTML=buckets.map((b,i)=>`
    <div class="bar-row"><span class="blabel">${b.l}</span>
    <div class="btrack"><div class="bfill" style="width:${Math.round((bCounts[i]/bMax)*100)}%;background:${b.col}"></div></div>
    <span class="bcount">${bCounts[i]}</span>
    <span class="bpct">${Math.round((bCounts[i]/(withPwd.length||1))*100)}%</span></div>`).join('');

  // Dept bars — avg age per dept
  const depts=[...new Set(USERS.map(u=>u.dept||'(None)'))].sort();
  const deptAvgs=depts.map(d=>{
    const du=withPwd.filter(u=>(u.dept||'(None)')===d);
    return {dept:d,avg:du.length?Math.round(du.reduce((s,u)=>s+pwdAgeDays(u),0)/du.length):0,n:du.length};
  }).filter(d=>d.n>0).sort((a,b)=>b.avg-a.avg).slice(0,10);
  const dMax=deptAvgs[0]?.avg||1;
  document.getElementById('pwdDeptBars').innerHTML=deptAvgs.map((d,i)=>`
    <div class="bar-row"><span class="blabel" title="${d.dept}">${d.dept}</span>
    <div class="btrack"><div class="bfill" style="width:${Math.round((d.avg/dMax)*100)}%;background:${PALETTE[i%PALETTE.length]}"></div></div>
    <span class="bcount">${d.avg}d</span></div>`).join('');

  // Oldest list
  document.getElementById('pwdOldestList').innerHTML=oldest.slice(0,30).map(u=>{
    const days=pwdAgeDays(u);
    const col=days>=730?'var(--red)':days>=365?'var(--orange)':days>=180?'var(--amber)':'var(--muted2)';
    return `<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border)">
      <span class="td-name" style="flex:1;cursor:pointer" onclick="openDP('${escJ(u.ln||u.email)}')">${escH(u.dn||u.ln)}</span>
      <span class="td-muted">${escH(u.dept)||'—'}</span>
      <span style="font-family:var(--mono);font-size:12px;color:${col};font-weight:700">${days}d old</span>
      <span style="font-size:11px;color:var(--muted)">${escH(u.pwCr?.split('T')[0]||'—')}</span>
    </div>`;
  }).join('');
})();

function exportPwdAgeCSV(){
  const now=Date.now();
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const enabled=USERS.filter(u=>u.ae==='True');
  const hdr='DisplayName,UPN,Department,PasswordCreatedDate,PasswordAgeDays,AgeCategory,HasMFA,AccountEnabled';
  const rows=enabled.map(u=>{
    const d=u.pwCr?new Date(u.pwCr):null;
    const age=d&&!isNaN(d)?Math.floor((now-d.getTime())/86400000):null;
    const cat=age===null?'Unknown':age<30?'<30d':age<90?'30-90d':age<180?'90-180d':age<365?'180d-1yr':age<730?'1-2yr':'2yr+';
    return [esc(u.dn),esc(u.ln),esc(u.dept),esc(u.pwCr?.split('T')[0]||''),age??'',cat,hasMFA(u)?'Yes':'No',u.ae].join(',');
  });
  dlFile([hdr,...rows].join('\r\n'),'PasswordAge.csv','text/csv');
  showToast('Password age data exported');
}

// ── GUEST ACCOUNTS ──
(function(){
  const guests=USERS.filter(u=>u.ut==='Guest');
  const gN=guests.length||1;
  const gEnabled=guests.filter(u=>u.ae==='True');
  const gWithMFA=guests.filter(hasMFA).length;
  const gNoMFA=guests.filter(u=>!hasMFA(u)).length;
  const gStale=gEnabled.filter(u=>isStale(u,90)).length;
  const gNever=gEnabled.filter(u=>!u.lsi).length;

  // KPIs
  const kpis=[
    {icon:'👤',label:'Total Guests',val:guests.length,col:'blue'},
    {icon:'✅',label:'Enabled',val:gEnabled.length,col:'green'},
    {icon:'🔐',label:'With MFA',val:gWithMFA,sub:`${Math.round((gWithMFA/gN)*100)}%`,col:'green'},
    {icon:'⚠️',label:'No MFA',val:gNoMFA,col:'red'},
    {icon:'💤',label:'Stale 90d+',val:gStale,col:'amber'},
    {icon:'⚫',label:'Never Signed In',val:gNever,col:'red'},
  ];
  document.getElementById('guestKpiGrid').innerHTML=kpis.map(k=>`
    <div class="kpi ${k.col}"><div class="kpi-icon">${k.icon}</div><div class="kpi-val">${k.val}</div><div class="kpi-sub">${k.label}</div>${k.sub?`<span class="kpi-trend good">${k.sub}</span>`:''}</div>`).join('');

  // MFA bars
  const methods=[
    {l:'MS Authenticator',n:guests.filter(u=>u.msN).length,col:'#4f8ef7'},
    {l:'Phone/SMS',       n:guests.filter(u=>u.ph).length, col:'#f0a830'},
    {l:'FIDO2 Key',       n:guests.filter(u=>u.f2N).length,col:'#2dd4a0'},
    {l:'WHFB',            n:guests.filter(u=>u.whN).length,col:'#a87fff'},
    {l:'No MFA',          n:gNoMFA,                         col:'#f05968'},
  ];
  const mMax=Math.max(...methods.map(m=>m.n))||1;
  document.getElementById('guestMFABars').innerHTML=methods.map(m=>`
    <div class="bar-row"><span class="blabel">${m.l}</span>
    <div class="btrack"><div class="bfill" style="width:${Math.round((m.n/mMax)*100)}%;background:${m.col}"></div></div>
    <span class="bcount">${m.n}</span><span class="bpct">${Math.round((m.n/gN)*100)}%</span></div>`).join('');

  // Stale panel
  const staleRows=[
    {icon:'✅',l:'Active (< 30d)',n:gEnabled.filter(u=>!isStale(u,30)).length,col:'var(--green)'},
    {icon:'🟡',l:'Stale 30–90d', n:gEnabled.filter(u=>isStale(u,30)&&!isStale(u,90)).length,col:'var(--amber)'},
    {icon:'🔴',l:'Stale 90d+',   n:gStale,col:'var(--red)'},
    {icon:'⚫',l:'Never Signed In',n:gNever,col:'var(--muted)'},
  ];
  document.getElementById('guestStalePanel').innerHTML=staleRows.map(r=>`
    <div class="stale-level"><span class="stale-icon">${r.icon}</span>
    <div class="stale-info"><div class="stale-label">${r.l}</div></div>
    <span class="stale-count" style="color:${r.col}">${r.n}</span></div>`).join('');
})();

function filterGuests(){
  const q   =document.getElementById('guestSearch').value.toLowerCase();
  const mfa =document.getElementById('guestMFAFilter').value;
  const acct=document.getElementById('guestAcctFilter').value;
  const data=USERS.filter(u=>u.ut==='Guest').filter(u=>{
    if(q&&!u.dn.toLowerCase().includes(q)&&!u.email.toLowerCase().includes(q)&&!u.ln.toLowerCase().includes(q)) return false;
    if(mfa==='yes'&&!hasMFA(u)) return false;
    if(mfa==='no'&&hasMFA(u))   return false;
    if(acct&&u.ae!==acct)        return false;
    return true;
  });
  document.getElementById('guestRcount').textContent=`${data.length} guests`;
  document.getElementById('guestTblBody').innerHTML=data.map((u,i)=>{
    const r=riskScore(u),rb=riskLabel(r);
    return `<tr onclick="openDP_list(${USERS.indexOf(u)})">
      <td><div class="td-name">${escH(u.dn||u.ln)}</div></td>
      <td class="td-muted">${escH(u.email||u.ln)}</td>
      <td>${methodDots(u)}</td>
      <td><span class="dot" style="background:${u.ae==='True'?'var(--green)':'var(--red)'}"></span></td>
      <td class="td-muted">${escH(u.lsi)||'Never'}</td>
      <td class="td-muted">${escH(u.mgr)||'—'}</td>
      <td><span class="chip ${rb.cls}">${rb.l}</span></td>
    </tr>`;
  }).join('');
}

function exportGuestCSV(){
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const guests=USERS.filter(u=>u.ut==='Guest');
  const hdr='DisplayName,UPN,Email,AccountEnabled,LastSignIn,HasMFA,MFAMethods,Manager,RiskLevel';
  const rows=guests.map(u=>[esc(u.dn),esc(u.ln),esc(u.email),esc(u.ae),esc(u.lsi),hasMFA(u)?'Yes':'No',esc([u.msN?'MSAuth':'',u.ph?'Phone':'',u.whN?'WHFB':'',u.f2N?'FIDO2':''].filter(Boolean).join('|')),esc(u.mgr),esc(riskLabel(riskScore(u)).l)].join(','));
  dlFile([hdr,...rows].join('\r\n'),'GuestAccounts.csv','text/csv');
  showToast(`Exported ${guests.length} guest accounts`);
}

filterGuests();

// ── DEPARTMENT RISK ──
function buildDeptData(){
  const depts=[...new Set(USERS.map(u=>u.dept||'(No Department)'))].sort();
  return depts.map(dept=>{
    const du=USERS.filter(u=>(u.dept||'(No Department)')===dept);
    const en=du.filter(u=>u.ae==='True');
    const enN=en.length||1;
    const withMFAn=en.filter(hasMFA).length;
    const noMFAn=en.filter(u=>!hasMFA(u)).length;
    const phishRn=du.filter(isPhishR).length;
    const smsOnlyN=du.filter(isSMSOnly).length;
    const staleN=en.filter(u=>isStale(u,90)).length;
    const guestN=du.filter(u=>u.ut==='Guest').length;
    const cov=Math.round((withMFAn/enN)*100);
    let riskScore=0;
    if(noMFAn>0) riskScore+=Math.round((noMFAn/enN)*60);
    if(smsOnlyN>0) riskScore+=Math.round((smsOnlyN/enN)*20);
    if(staleN>0) riskScore+=Math.round((staleN/enN)*20);
    return {dept,total:du.length,enabled:en.length,withMFA:withMFAn,noMFA:noMFAn,phishR:phishRn,smsOnly:smsOnlyN,stale:staleN,guests:guestN,coverage:cov,riskScore:Math.min(riskScore,100)};
  });
}

function renderDeptTable(){
  const sort=document.getElementById('deptSortSel').value;
  let data=buildDeptData();
  if(sort==='risk')  data.sort((a,b)=>b.riskScore-a.riskScore);
  if(sort==='name')  data.sort((a,b)=>a.dept.localeCompare(b.dept));
  if(sort==='users') data.sort((a,b)=>b.total-a.total);
  if(sort==='nomfa') data.sort((a,b)=>b.noMFA-a.noMFA);
  document.getElementById('deptCount').textContent=`${data.length} departments`;
  document.getElementById('deptTblBody').innerHTML=data.map(d=>{
    const rl=riskLabel(d.riskScore);
    const covCol=d.coverage>=90?'var(--green)':d.coverage>=70?'var(--amber)':'var(--red)';
    return `<tr onclick="filterTableByDept('${escJ(d.dept==='(No Department)'?'':d.dept)}')" title="Click to filter Users tab">
      <td style="font-weight:600">${escH(d.dept)}</td>
      <td class="td-muted">${d.total}</td>
      <td class="td-muted">${d.enabled}</td>
      <td style="color:var(--green);font-family:var(--mono)">${d.withMFA}</td>
      <td style="color:${d.noMFA>0?'var(--red)':'var(--muted)'};font-family:var(--mono);font-weight:${d.noMFA>0?700:400}">${d.noMFA}</td>
      <td style="color:var(--accent3);font-family:var(--mono)">${d.phishR}</td>
      <td style="color:${d.smsOnly>0?'var(--amber)':'var(--muted)'};font-family:var(--mono)">${d.smsOnly}</td>
      <td style="color:${d.stale>0?'var(--orange)':'var(--muted)'};font-family:var(--mono)">${d.stale}</td>
      <td class="td-muted">${d.guests}</td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <div style="flex:1;height:6px;background:var(--surface3);border-radius:3px;min-width:50px"><div style="width:${d.coverage}%;height:100%;background:${covCol};border-radius:3px"></div></div>
          <span style="font-family:var(--mono);font-size:11px;color:${covCol}">${d.coverage}%</span>
        </div>
      </td>
      <td><span class="chip ${rl.cls}">${rl.l}</span></td>
    </tr>`;
  }).join('');

  // Bar charts
  const top10noMFA=data.sort((a,b)=>b.noMFA-a.noMFA).slice(0,10);
  const nmMax=top10noMFA[0]?.noMFA||1;
  document.getElementById('deptNoMFABars').innerHTML=top10noMFA.filter(d=>d.noMFA>0).map(d=>`
    <div class="bar-row"><span class="blabel" title="${d.dept}">${d.dept}</span>
    <div class="btrack"><div class="bfill" style="width:${Math.round((d.noMFA/nmMax)*100)}%;background:var(--red)"></div></div>
    <span class="bcount">${d.noMFA}</span></div>`).join('')||'<p style="color:var(--green);font-size:13px">✅ No departments with unprotected users.</p>';

  const top10pr=buildDeptData().filter(d=>d.enabled>0).sort((a,b)=>b.coverage-a.coverage).slice(0,10);
  document.getElementById('deptPhishBars').innerHTML=top10pr.map((d,i)=>`
    <div class="bar-row"><span class="blabel" title="${d.dept}">${d.dept}</span>
    <div class="btrack"><div class="bfill" style="width:${d.coverage}%;background:${PALETTE[i%PALETTE.length]}"></div></div>
    <span class="bcount">${d.coverage}%</span></div>`).join('');
}

function filterTableByDept(dept){
  showPage('users', document.querySelector('.nb[onclick*="users"]'));
  document.getElementById('rawDeptFilter') && (document.getElementById('rawDeptFilter').value=dept);
  const sel=document.querySelector('#page-users select');
  filterTable();
  showToast(`Filtered Users tab by: ${dept||'(No Department)'}`);
}

function exportDeptCSV(){
  const data=buildDeptData();
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const hdr='Department,TotalUsers,EnabledUsers,WithMFA,NoMFA,PhishResistant,SMSOnly,Stale90d,Guests,MFACoverage%,RiskScore';
  const rows=data.map(d=>[esc(d.dept),d.total,d.enabled,d.withMFA,d.noMFA,d.phishR,d.smsOnly,d.stale,d.guests,d.coverage,d.riskScore].join(','));
  dlFile([hdr,...rows].join('\r\n'),'DepartmentRisk.csv','text/csv');
  showToast('Department risk exported');
}

renderDeptTable();

// ── COMPLIANCE SCORECARD ──
(function(){
  const enabled  = USERS.filter(u=>u.ae==='True');
  const enN      = enabled.length||1;
  const withMFA  = enabled.filter(hasMFA).length;
  const mfaPct   = Math.round((withMFA/enN)*100);
  const phishRPct= Math.round((USERS.filter(isPhishR).length/TOTAL)*100);
  const smsOnlyN = USERS.filter(isSMSOnly).length;
  const noMFAN   = enabled.filter(u=>!hasMFA(u)).length;
  const stale90N = enabled.filter(u=>isStale(u,90)).length;
  const guestNoMFAN=USERS.filter(u=>u.ut==='Guest'&&!hasMFA(u)).length;
  const tapN     = USERS.filter(u=>u.tapU==='True').length;

  function pct(n,d){return d?Math.round((n/d)*100):0;}

  const frameworks=[
    {
      icon:'🏛️', col:'#4f8ef7', title:'NIST CSF 2.0', sub:'Identity & Access Management Controls (PR.AA, PR.AC)',
      controls:[
        {id:'PR.AA-01',title:'MFA Enforced for All Active Accounts',desc:`${mfaPct}% of enabled accounts have at least one MFA method registered.`,status:mfaPct>=95?'pass':mfaPct>=70?'partial':'fail',val:`${mfaPct}%`},
        {id:'PR.AA-02',title:'Phishing-Resistant Authentication',desc:`${phishRPct}% use FIDO2 or Windows Hello — the only methods immune to real-time phishing.`,status:phishRPct>=50?'pass':phishRPct>=20?'partial':'fail',val:`${phishRPct}%`},
        {id:'PR.AA-03',title:'Privileged Account MFA Coverage',desc:'Accounts with admin-like UPN patterns checked for MFA registration.',status:enabled.filter(u=>/admin|adm|svc|service|priv/i.test(u.ln)&&!hasMFA(u)).length===0?'pass':'fail',val:enabled.filter(u=>/admin|adm|svc|service|priv/i.test(u.ln)&&!hasMFA(u)).length===0?'✅ Pass':'⚠ Fail'},
        {id:'PR.AC-01',title:'Stale Account Lifecycle Management',desc:`${stale90N} enabled accounts with no sign-in in 90+ days.`,status:stale90N===0?'pass':stale90N<=5?'partial':'fail',val:`${stale90N} stale`},
        {id:'PR.AC-02',title:'Guest/External Identity Controls',desc:`${guestNoMFAN} guest accounts have no MFA registered.`,status:guestNoMFAN===0?'pass':guestNoMFAN<=3?'partial':'fail',val:`${guestNoMFAN} at risk`},
        {id:'PR.AC-03',title:'Temporary Credential Controls (TAP)',desc:`${tapN} active Temporary Access Pass(es) detected.`,status:tapN===0?'pass':tapN<=2?'partial':'fail',val:`${tapN} active`},
      ]
    },
    {
      icon:'🔒', col:'#2dd4a0', title:'CIS Controls v8', sub:'Control 5 (Account Management) · Control 6 (Access Control)',
      controls:[
        {id:'CIS-5.1',title:'Establish and Maintain an Inventory of Accounts',desc:`${TOTAL} accounts inventoried across ${[...new Set(USERS.map(u=>u.dept).filter(Boolean))].length} departments.`,status:'info',val:`${TOTAL} accounts`},
        {id:'CIS-5.2',title:'Use Unique Passwords (Password Age)',desc:'Accounts with password older than 180 days represent a credential hygiene risk.',status:pct(USERS.filter(u=>{const d=new Date(u.pwCr);return !isNaN(d)&&(Date.now()-d.getTime())>180*86400000;}).length,TOTAL)<20?'pass':'partial',val:`${USERS.filter(u=>{const d=new Date(u.pwCr);return !isNaN(d)&&(Date.now()-d.getTime())>180*86400000;}).length} old`},
        {id:'CIS-5.3',title:'Disable Dormant Accounts',desc:`${stale90N} accounts inactive for 90+ days should be reviewed for disablement.`,status:stale90N===0?'pass':stale90N<10?'partial':'fail',val:`${stale90N} dormant`},
        {id:'CIS-6.3',title:'Require MFA for Externally-Exposed Applications',desc:`${mfaPct}% MFA coverage across all accounts.`,status:mfaPct>=90?'pass':mfaPct>=70?'partial':'fail',val:`${mfaPct}%`},
        {id:'CIS-6.4',title:'Require MFA for Remote Network Access',desc:'SMS-only accounts are considered weak MFA and may not satisfy CIS intent.',status:smsOnlyN===0?'pass':smsOnlyN<5?'partial':'fail',val:`${smsOnlyN} SMS-only`},
        {id:'CIS-6.5',title:'Require MFA for Admin Accounts',desc:'Admin/service accounts without MFA are the highest-priority risk.',status:enabled.filter(u=>/admin|adm|svc/i.test(u.ln)&&!hasMFA(u)).length===0?'pass':'fail',val:enabled.filter(u=>/admin|adm|svc/i.test(u.ln)&&!hasMFA(u)).length===0?'✅ Pass':'⚠ Fail'},
      ]
    },
    {
      icon:'🛡️', col:'#a87fff', title:'Zero Trust Identity Pillar', sub:'NIST SP 800-207 · Microsoft Zero Trust Framework',
      controls:[
        {id:'ZT-ID-01',title:'Verify Explicitly — MFA on Every Sign-In Path',desc:`${noMFAN} active accounts can authenticate with password only.`,status:noMFAN===0?'pass':noMFAN<5?'partial':'fail',val:`${noMFAN} unprotected`},
        {id:'ZT-ID-02',title:'Use Least Privilege Access',desc:'Guest accounts should have minimum permissions and mandatory MFA.',status:guestNoMFAN===0?'pass':'partial',val:`${guestNoMFAN} guests at risk`},
        {id:'ZT-ID-03',title:'Assume Breach — Phishing-Resistant Priority',desc:`${phishRPct}% phishing-resistant. Zero Trust recommends 100% for privileged paths.`,status:phishRPct>=80?'pass':phishRPct>=40?'partial':'fail',val:`${phishRPct}%`},
        {id:'ZT-ID-04',title:'Continuous Validation — Stale Session Control',desc:`${stale90N} accounts with 90d+ inactivity represent unmonitored identities.`,status:stale90N===0?'pass':stale90N<5?'partial':'fail',val:`${stale90N} stale`},
        {id:'ZT-ID-05',title:'On-Premises Hybrid Trust Boundary',desc:`${USERS.filter(u=>u.sync==='True').length} synced accounts. Hybrid accounts inherit on-prem AD risk.`,status:'info',val:`${USERS.filter(u=>u.sync==='True').length} synced`},
      ]
    },
    {
      icon:'📋', col:'#f0a830', title:'ISO 27001:2022', sub:'Clause A.8.2 (Privileged Access) · A.8.5 (Secure Authentication)',
      controls:[
        {id:'A.8.5',title:'Secure Authentication Policy',desc:`MFA coverage at ${mfaPct}%. ISO 27001 requires strong authentication for all information systems.`,status:mfaPct>=90?'pass':mfaPct>=70?'partial':'fail',val:`${mfaPct}%`},
        {id:'A.8.2',title:'Privileged Access Rights Management',desc:'Admin-pattern accounts checked for MFA registration.',status:enabled.filter(u=>/admin|adm|svc/i.test(u.ln)&&!hasMFA(u)).length===0?'pass':'fail',val:enabled.filter(u=>/admin|adm|svc/i.test(u.ln)&&!hasMFA(u)).length===0?'✅ Pass':'⚠ Fail'},
        {id:'A.8.3',title:'Information Access Restriction — Guest Control',desc:`${guestNoMFAN} external guests without MFA. ISO 27001 requires verified identity for all access.`,status:guestNoMFAN===0?'pass':guestNoMFAN<3?'partial':'fail',val:`${guestNoMFAN} at risk`},
        {id:'A.8.7',title:'Protection Against Malware — Phishing Controls',desc:`${phishRPct}% phishing-resistant MFA. ISO 27001 A.8.7 covers protection from social engineering.`,status:phishRPct>=50?'pass':phishRPct>=20?'partial':'fail',val:`${phishRPct}%`},
        {id:'A.5.9',title:'Inventory of Information Assets',desc:`${TOTAL} identities catalogued. Full inventory supports A.5.9 asset management.`,status:'pass',val:`${TOTAL} catalogued`},
      ]
    },
  ];

  const statusIcon={pass:'✓',fail:'✗',partial:'~',info:'i'};
  const el=document.getElementById('complianceGrid');

  frameworks.forEach(fw=>{
    const pass=fw.controls.filter(c=>c.status==='pass').length;
    const total=fw.controls.filter(c=>c.status!=='info').length||1;
    const score=Math.round((pass/total)*100);
    el.innerHTML+=`
      <div class="comp-framework">
        <div class="comp-fw-header">
          <div class="comp-fw-icon" style="background:${fw.col}18">${fw.icon}</div>
          <div><div class="comp-fw-title">${fw.title}</div><div class="comp-fw-sub">${fw.sub}</div></div>
          <div class="comp-fw-score" style="min-width:70px">
            <div class="comp-fw-score-val" style="color:${score>=80?'var(--green)':score>=50?'var(--amber)':'var(--red)'}">${score}%</div>
            <div class="comp-fw-score-lbl">${pass}/${fw.controls.filter(c=>c.status!=='info').length} controls</div>
            <div class="comp-progress-bar" style="margin-top:4px;width:60px"><div class="comp-progress-fill" style="width:${score}%;background:${score>=80?'var(--green)':score>=50?'var(--amber)':'var(--red)'}"></div></div>
          </div>
        </div>
        ${fw.controls.map(c=>`
          <div class="comp-control-row">
            <div class="comp-status ${c.status}">${statusIcon[c.status]}</div>
            <div class="comp-control-body">
              <div class="comp-control-title"><span style="color:var(--muted);font-family:var(--mono);font-size:10px;margin-right:6px">${c.id}</span>${c.title}</div>
              <div class="comp-control-desc">${c.desc}</div>
            </div>
            <span class="comp-control-val">${c.val}</span>
          </div>`).join('')}
      </div>`;
  });
})();

function exportComplianceCSV(){
  const rows=['Framework,Control ID,Control Title,Status,Value'];
  document.querySelectorAll('.comp-framework').forEach(fw=>{
    const fwTitle=fw.querySelector('.comp-fw-title').textContent;
    fw.querySelectorAll('.comp-control-row').forEach(row=>{
      const id=row.querySelector('.comp-control-title span')?.textContent||'';
      const title=row.querySelector('.comp-control-title').textContent.replace(id,'').trim();
      const status=row.querySelector('.comp-status').className.includes('pass')?'PASS':row.querySelector('.comp-status').className.includes('fail')?'FAIL':row.querySelector('.comp-status').className.includes('partial')?'PARTIAL':'INFO';
      const val=row.querySelector('.comp-control-val')?.textContent||'';
      rows.push([`"${fwTitle}"`,`"${id}"`,`"${title}"`,status,`"${val}"`].join(','));
    });
  });
  dlFile(rows.join('\r\n'),'ComplianceScorecard.csv','text/csv');
  showToast('Compliance scorecard exported');
}

// ── EXECUTIVE SUMMARY ──
(function(){
  const enabled   = USERS.filter(u=>u.ae==='True');
  const enN       = enabled.length||1;
  const withMFA   = enabled.filter(hasMFA).length;
  const noMFAn    = enabled.filter(u=>!hasMFA(u)).length;
  const phishRn   = USERS.filter(isPhishR).length;
  const smsOnlyn  = USERS.filter(isSMSOnly).length;
  const stale90n  = enabled.filter(u=>isStale(u,90)).length;
  const guestN    = USERS.filter(u=>u.ut==='Guest').length;
  const gNoMFA    = USERS.filter(u=>u.ut==='Guest'&&!hasMFA(u)).length;
  const tapN      = USERS.filter(u=>u.tapU==='True').length;
  const neverN    = enabled.filter(u=>!u.lsi).length;
  const hs        = HEALTH_SCORE;

  // Grade calculation
  let grade='A';
  if(hs<50) grade='F';
  else if(hs<60) grade='D';
  else if(hs<70) grade='C';
  else if(hs<85) grade='B';
  const gradeEl=document.getElementById('execGrade');
  gradeEl.textContent=grade; gradeEl.className='exec-grade '+grade;

  // Score + subtitle
  document.getElementById('execScore').textContent=hs;
  document.getElementById('execScore').style.color=hs>=80?'var(--green)':hs>=50?'var(--amber)':'var(--red)';
  document.getElementById('execGenDate').textContent=new Date().toLocaleDateString('en-GB',{day:'2-digit',month:'long',year:'numeric'});
  document.getElementById('execFooterDate').textContent=new Date().toLocaleString();
  document.getElementById('execSubtitle').textContent=`${TOTAL} identities across ${[...new Set(USERS.map(u=>u.dept).filter(Boolean))].length} departments`;

  // Top chips
  const chips=[
    {l:`${TOTAL} Total Users`,cls:'chip-blue'},
    {l:`${Math.round((withMFA/enN)*100)}% MFA Coverage`,cls:withMFA/enN>=0.9?'chip-green':'chip-red'},
    {l:`${Math.round((phishRn/TOTAL)*100)}% Phish-Resistant`,cls:'chip-purple'},
    {l:grade+' Grade',cls:grade==='A'?'chip-green':grade==='B'?'chip-blue':grade==='C'?'chip-amber':'chip-red'},
  ];
  document.getElementById('execTopChips').innerHTML=chips.map(c=>`<span class="chip ${c.cls}">${c.l}</span>`).join('');

  // KPI tiles
  const kpis=[
    {icon:'👥',label:'Total Identities',val:TOTAL,sub:'All user objects',col:'blue'},
    {icon:'✅',label:'Active Accounts',val:enabled.length,sub:`${USERS.filter(u=>u.ae!=='True').length} disabled`,col:'green'},
    {icon:'🔐',label:'MFA Registered',val:withMFA,sub:`${Math.round((withMFA/enN)*100)}% of active`,col:'green'},
    {icon:'⚠️',label:'No MFA',val:noMFAn,sub:'Immediate action',col:'red'},
    {icon:'🛡️',label:'Phish-Resistant',val:phishRn,sub:'FIDO2 + WHFB',col:'purple'},
    {icon:'📱',label:'SMS-Only Risk',val:smsOnlyn,sub:'Weak method',col:'amber'},
    {icon:'💤',label:'Stale 90d+',val:stale90n,sub:'Enabled accounts',col:'red'},
    {icon:'👤',label:'Guests No MFA',val:gNoMFA,sub:`of ${guestN} guests`,col:'amber'},
  ];
  document.getElementById('execKpiGrid').innerHTML=kpis.map(k=>`
    <div class="exec-card kpi ${k.col}" style="padding:14px 16px">
      <div class="kpi-icon">${k.icon}</div>
      <div class="kpi-val">${k.val}</div>
      <div class="kpi-sub">${k.label}</div>
      <div style="font-size:11px;color:var(--muted);margin-top:2px">${k.sub}</div>
    </div>`).join('');

  // MFA breakdown
  const mfaRows=[
    {l:'Microsoft Authenticator', v:USERS.filter(u=>u.msN).length},
    {l:'Phone / SMS',             v:USERS.filter(u=>u.ph).length},
    {l:'Windows Hello (WHFB)',    v:USERS.filter(u=>u.whN).length},
    {l:'FIDO2 Security Key',      v:USERS.filter(u=>u.f2N).length},
    {l:'Software OATH',           v:USERS.filter(u=>u.soath&&u.soath!=='False').length},
    {l:'Passwordless',            v:USERS.filter(u=>u.plN).length},
    {l:'Email MFA',               v:USERS.filter(u=>u.emA).length},
    {l:'No Method (enabled)',     v:noMFAn, warn:true},
  ];
  document.getElementById('execMFABreakdown').innerHTML=mfaRows.map(r=>`
    <div class="exec-stat-row">
      <span style="${r.warn?'color:var(--red)':'color:var(--muted2)'}">${r.l}</span>
      <span class="exec-stat-val" style="${r.warn?'color:var(--red)':''}">${r.v}</span>
    </div>`).join('');

  // Top risks
  const risks=[
    {sev:'CRITICAL',l:'Enabled users with no MFA',v:noMFAn,show:noMFAn>0},
    {sev:'HIGH',    l:'Guest accounts without MFA',v:gNoMFA,show:gNoMFA>0},
    {sev:'HIGH',    l:'SMS-only authentication',v:smsOnlyn,show:smsOnlyn>0},
    {sev:'MEDIUM',  l:'Active TAP credentials',v:tapN,show:tapN>0},
    {sev:'MEDIUM',  l:'Stale accounts (90d+)',v:stale90n,show:stale90n>0},
    {sev:'MEDIUM',  l:'Never signed in (enabled)',v:neverN,show:neverN>0},
    {sev:'LOW',     l:'Low phishing-resistant coverage',v:`${Math.round((phishRn/TOTAL)*100)}%`,show:phishRn/TOTAL<0.5},
  ].filter(r=>r.show);
  const sevCol={CRITICAL:'var(--red)',HIGH:'var(--orange)',MEDIUM:'var(--amber)',LOW:'var(--green)'};
  document.getElementById('execTopRisks').innerHTML=risks.length
    ? risks.map(r=>`<div class="exec-finding-row"><span class="chip" style="background:${sevCol[r.sev]}18;color:${sevCol[r.sev]};border-color:${sevCol[r.sev]}44;font-size:10px;padding:1px 7px;white-space:nowrap">${r.sev}</span><span style="flex:1;color:var(--muted2)">${r.l}</span><span class="exec-stat-val">${r.v}</span></div>`).join('')
    : '<p style="color:var(--green);font-size:13px;padding:10px 0">✅ No critical risks detected.</p>';

  // Identity population
  const popRows=[
    {l:'Members',     v:USERS.filter(u=>u.ut==='Member').length},
    {l:'Guests',      v:guestN},
    {l:'Hybrid Synced', v:USERS.filter(u=>u.sync==='True').length},
    {l:'Cloud-Only',  v:USERS.filter(u=>u.sync!=='True').length},
    {l:'Departments', v:[...new Set(USERS.map(u=>u.dept).filter(Boolean))].length},
  ];
  document.getElementById('execIdentityPop').innerHTML=popRows.map(r=>`
    <div class="exec-stat-row"><span style="color:var(--muted2)">${r.l}</span><span class="exec-stat-val">${r.v}</span></div>`).join('');

  // Priority actions
  const actions=[];
  if(noMFAn>0)    actions.push({p:1,l:`Enrol ${noMFAn} active user(s) with no MFA immediately`});
  if(gNoMFA>0)    actions.push({p:2,l:`Apply MFA Conditional Access to ${gNoMFA} guest account(s)`});
  if(smsOnlyn>0)  actions.push({p:3,l:`Migrate ${smsOnlyn} SMS-only user(s) to MS Authenticator`});
  if(stale90n>0)  actions.push({p:4,l:`Review and disable ${stale90n} stale account(s) (90d+)`});
  if(tapN>0)      actions.push({p:5,l:`Revoke ${tapN} active Temporary Access Pass(es)`});
  if(phishRn/TOTAL<0.3) actions.push({p:6,l:'Expand FIDO2/WHFB adoption — currently below 30%'});
  document.getElementById('execActions').innerHTML=actions.slice(0,6).map((a,i)=>`
    <div class="exec-finding-row">
      <span style="background:var(--accent);color:#fff;border-radius:50%;width:18px;height:18px;display:inline-flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0">${i+1}</span>
      <span style="flex:1;color:var(--muted2);font-size:12px">${a.l}</span>
    </div>`).join('');
})();

function exportExecJSON(){
  const enabled=USERS.filter(u=>u.ae==='True');
  const enN=enabled.length||1;
  const summary={
    generatedAt:new Date().toISOString(),
    totalUsers:TOTAL,
    enabledAccounts:enabled.length,
    disabledAccounts:TOTAL-enabled.length,
    mfaRegistered:enabled.filter(hasMFA).length,
    noMFA:enabled.filter(u=>!hasMFA(u)).length,
    mfaCoveragePct:Math.round((enabled.filter(hasMFA).length/enN)*100),
    phishResistant:USERS.filter(isPhishR).length,
    smsOnly:USERS.filter(isSMSOnly).length,
    stale90Days:enabled.filter(u=>isStale(u,90)).length,
    guestsTotal:USERS.filter(u=>u.ut==='Guest').length,
    guestsNoMFA:USERS.filter(u=>u.ut==='Guest'&&!hasMFA(u)).length,
    activeTAP:USERS.filter(u=>u.tapU==='True').length,
    healthScore:HEALTH_SCORE,
  };
  dlFile(JSON.stringify(summary,null,2),'ExecSummary.json','application/json');
  showToast('Executive summary exported as JSON');
}

// ── RAW DATA TABLE ──
const RAW_COLS = [
  {k:'ln',    h:'LoginName'},
  {k:'email', h:'Email'},
  {k:'dn',    h:'DisplayName'},
  {k:'ut',    h:'UserType'},
  {k:'sync',  h:'IsOn-PremSynced'},
  {k:'ae',    h:'AccountEnabled'},
  {k:'cdt',   h:'CreateDateTime'},
  {k:'dept',  h:'Department'},
  {k:'lssi',  h:'LastSuccessfulSignInDateTime'},
  {k:'lsi',   h:'LastSignInDate'},
  {k:'lnisi', h:'LastNonInteractiveSignInDate'},
  {k:'mgr',   h:'ManagerDisplayName'},
  {k:'mgrU',  h:'ManagerUserPrincipalName'},
  {k:'mgrM',  h:'ManagerMail'},
  {k:'ph',    h:'phoneAuthenticationNumber'},
  {k:'phT',   h:'phoneAuthenticationType'},
  {k:'sms',   h:'smsSignInState'},
  {k:'pwCr',  h:'passwordCreatedDateTime'},
  {k:'emA',   h:'emailAddress'},
  {k:'whN',   h:'WHFBDisplayName'},
  {k:'whC',   h:'WHFBCreatedDateTime'},
  {k:'whKS',  h:'WHFBKeyStrength'},
  {k:'msN',   h:'microsoftAuthenticatorDisplayName'},
  {k:'msDT',  h:'microsoftAuthenticatorDeviceTag'},
  {k:'msV',   h:'microsoftAuthenticatorPhoneAppVersion'},
  {k:'f2N',   h:'fido2DisplayName'},
  {k:'f2D',   h:'fido2CreatedDate'},
  {k:'f2M',   h:'fido2Model'},
  {k:'tapU',  h:'TAPAuthenticationIsUsable'},
  {k:'tapS',  h:'TAPAuthenticationStartDateTime'},
  {k:'tapL',  h:'TAPAuthenticationLifetime'},
  {k:'tapO',  h:'TAPAuthenticationIsUsableOnce'},
  {k:'plN',   h:'passwordlessDisplayName'},
  {k:'plDT',  h:'passwordAuthDeviceTag'},
  {k:'plV',   h:'passwordAuthPhoneAppVersion'},
  {k:'soath', h:'softwareOath'},
];

// Build header row once
(function(){
  const tr = document.getElementById('rawTblHead');
  RAW_COLS.forEach(c => {
    const th = document.createElement('th');
    th.textContent = c.h;
    th.style.whiteSpace = 'nowrap';
    th.style.fontSize = '10.5px';
    tr.appendChild(th);
  });

  // Populate department filter
  const depts = [...new Set(USERS.map(u=>u.dept).filter(Boolean))].sort();
  const sel = document.getElementById('rawDeptFilter');
  depts.forEach(d => {
    const o = document.createElement('option');
    o.value = d; o.textContent = d;
    sel.appendChild(o);
  });
})();

let rawFiltered = [...USERS], rawPage = 1, rawPageSize = 20;

function chRawPageSize(){
  rawPageSize = parseInt(document.getElementById('rawPageSel').value);
  rawPage = 1; renderRaw();
}

function filterRaw(){
  const q    = document.getElementById('rawSearch').value.toLowerCase().trim();
  const dept = document.getElementById('rawDeptFilter').value;
  const type = document.getElementById('rawTypeFilter').value;
  const acct = document.getElementById('rawAcctFilter').value;

  rawFiltered = USERS.filter(u => {
    if(dept && u.dept !== dept) return false;
    if(type && u.ut   !== type) return false;
    if(acct && u.ae   !== acct) return false;
    if(q){
      // search across all column values
      return RAW_COLS.some(c => (u[c.k]||'').toLowerCase().includes(q));
    }
    return true;
  });
  rawPage = 1; renderRaw();
}

function renderRaw(){
  const st  = (rawPage-1)*rawPageSize;
  const sl  = rawPageSize >= 99999 ? rawFiltered : rawFiltered.slice(st, st+rawPageSize);
  const end = Math.min(st + rawPageSize, rawFiltered.length);

  document.getElementById('rawRcount').textContent  = `${rawFiltered.length} of ${USERS.length}`;
  document.getElementById('rawPageInfo').textContent = rawPageSize >= 99999
    ? `Showing all ${rawFiltered.length} records`
    : `Showing ${st+1}–${end} of ${rawFiltered.length}`;

  // Colour helpers for specific columns
  function cellStyle(key, val){
    if(key==='ae')   return val==='True'  ? 'color:var(--green)'  : val==='False' ? 'color:var(--red)' : '';
    if(key==='sync') return val==='True'  ? 'color:var(--accent)' : '';
    if(key==='tapU') return val==='True'  ? 'color:var(--amber)'  : '';
    if(key==='ut')   return val==='Guest' ? 'color:var(--accent3)': '';
    return '';
  }

  document.getElementById('rawTblBody').innerHTML = sl.map(u =>
    `<tr onclick="openDP('${escJ(u.ln||u.email)}')" title="Click to view full details">${
      RAW_COLS.map(c => {
        const v = u[c.k] || '';
        const s = cellStyle(c.k, v);
        return `<td style="white-space:nowrap;max-width:200px;overflow:hidden;text-overflow:ellipsis;font-family:var(--mono);font-size:11px;${s}" title="${escH(v)}">${escH(v)||'<span style="color:var(--border2)">—</span>'}</td>`;
      }).join('')
    }</tr>`
  ).join('');

  renderRawPgn();
}

function renderRawPgn(){
  if(rawPageSize >= 99999){ document.getElementById('rawPgn').innerHTML=''; return; }
  const total = Math.ceil(rawFiltered.length/rawPageSize);
  const el    = document.getElementById('rawPgn');
  if(total <= 1){ el.innerHTML=''; return; }
  let h = `<button class="pb" onclick="goRawPage(${rawPage-1})" ${rawPage===1?'disabled':''}>‹</button>`;
  for(let i=1;i<=total;i++){
    if(i===1||i===total||Math.abs(i-rawPage)<=1)
      h += `<button class="pb ${i===rawPage?'active':''}" onclick="goRawPage(${i})">${i}</button>`;
    else if(Math.abs(i-rawPage)===2)
      h += `<span style="color:var(--muted);padding:0 4px">…</span>`;
  }
  h += `<button class="pb" onclick="goRawPage(${rawPage+1})" ${rawPage===total?'disabled':''}>›</button>`;
  el.innerHTML = h;
}

function goRawPage(p){
  const t = Math.ceil(rawFiltered.length/rawPageSize);
  if(p<1||p>t) return;
  rawPage=p; renderRaw();
}

function exportRawCSV(){
  const esc = v => `"${String(v||'').replace(/"/g,'""')}"`;
  const hdr = RAW_COLS.map(c=>esc(c.h)).join(',');
  const rows = rawFiltered.map(u => RAW_COLS.map(c=>esc(u[c.k]||'')).join(','));
  dlFile([hdr,...rows].join('\r\n'), 'MFAReport-Raw.csv', 'text/csv');
  showToast(`Exported ${rawFiltered.length} rows as Raw CSV`);
}

function copyRawCSV(){
  const esc = v => `"${String(v||'').replace(/"/g,'""')}"`;
  const hdr = RAW_COLS.map(c=>esc(c.h)).join(',');
  const rows = rawFiltered.map(u => RAW_COLS.map(c=>esc(u[c.k]||'')).join(','));
  const content = [hdr,...rows].join('\r\n');
  try{
    navigator.clipboard.writeText(content).then(()=>showToast(`Copied ${rawFiltered.length} rows to clipboard`));
  } catch(e){ showToast('Copy unavailable — use Export CSV instead','⚠'); }
}

// Initialise raw table on first load
filterRaw();

// ── EXPORTS ──
function exportCSV(filtered){
  const data=filtered?filteredUsers:USERS;
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  const hdr='DisplayName,LoginName,Email,Department,UserType,AccountEnabled,OnPremSynced,LastSignIn,HasMFA,HasPhishResistant,SMSOnly,MSAuthenticator,Phone,WHFB,FIDO2,SoftwareOATH,Passwordless,TAPActive,RiskScore,RiskLevel';
  const rows=data.map(u=>[esc(u.dn),esc(u.ln),esc(u.email),esc(u.dept),esc(u.ut),esc(u.ae),esc(u.sync),esc(u.lsi),hasMFA(u)?'Yes':'No',isPhishR(u)?'Yes':'No',isSMSOnly(u)?'Yes':'No',u.msN?'Yes':'No',u.ph?'Yes':'No',u.whN?'Yes':'No',u.f2N?'Yes':'No',(u.soath&&u.soath!=='False')?'Yes':'No',u.plN?'Yes':'No',(u.tapU==='True')?'Yes':'No',riskScore(u),riskLabel(riskScore(u)).l].join(','));
  dlFile([hdr,...rows].join('\r\n'),'MFADashboard.csv','text/csv');
  showToast(`Exported ${data.length} users as CSV`);
}
function exportJSON(filtered){
  const data=(filtered?filteredUsers:USERS).map(u=>({...u,hasMFA:hasMFA(u),phishResistant:isPhishR(u),smsOnly:isSMSOnly(u),riskScore:riskScore(u),riskLevel:riskLabel(riskScore(u)).l}));
  dlFile(JSON.stringify(data,null,2),'MFADashboard.json','application/json');
  showToast(`Exported ${data.length} users as JSON`);
}
function dlFile(content,name,type){const b=new Blob([content],{type});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=name;a.click();URL.revokeObjectURL(u);}

// ── KEYBOARD ──
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closeDP();return;}
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){
    e.preventDefault();const inp=document.querySelector('.page.active input[type=text]');if(inp)inp.focus();
  }
  if(document.getElementById('dp').classList.contains('open')){
    if(e.key==='ArrowLeft') navDP(-1);
    if(e.key==='ArrowRight') navDP(1);
  }
});
</script>
</body>
</html>
'@

    # ── Substitution ──────────────────────────────────────────────────────────
    $html = $html `
        -replace '__TOTAL__',         $total `
        -replace '__ENABLED__',       $enabled `
        -replace '__ANYMFA__',        $anyMFA `
        -replace '__NOMFA__',         $noMFA `
        -replace '__MFAPCT__',        $mfaPct `
        -replace '__PHISHR__',        $phishResistant `
        -replace '__PHISHRPCT__',     $phishResistantPct `
        -replace '__SMSONLY__',       $smsOnly `
        -replace '__SYNCED__',        $synced `
        -replace '__STALE90__',       $stale90 `
        -replace '__STALE90PCT__',    $stale90Pct `
        -replace '__HEALTHSCORE__',   $healthScore `
        -replace '__GENERATEDAT__',   $generatedAt `
        -replace '__USERS_JSON__',    $usersJson `
        -replace '__DEPTS_JSON__',    $deptJson

    #endregion

    #region ── Write Output ───────────────────────────────────────────────────

    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   ✅  MFA Dashboard v1.0 — generated!                ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  👥  Total users       : $total"                  -ForegroundColor White
    Write-Host "  ✅  Enabled accounts  : $enabled"                -ForegroundColor White
    Write-Host "  🔐  With MFA          : $anyMFA ($mfaPct%)"      -ForegroundColor White
    Write-Host "  ⚠   No MFA            : $noMFA"                  -ForegroundColor $(if($noMFA -eq 0){'Green'} elseif($noMFA -le 5){'Yellow'} else{'Red'})
    Write-Host "  🛡   Phish-Resistant   : $phishResistant ($phishResistantPct%)" -ForegroundColor White
    Write-Host "  📵  SMS-Only (weak)   : $smsOnly"                -ForegroundColor $(if($smsOnly -eq 0){'Green'} else{'Yellow'})
    Write-Host "  💤  Stale 90d+        : $stale90"                -ForegroundColor $(if($stale90 -eq 0){'Green'} else{'Yellow'})
    Write-Host "  💯  Health score      : $healthScore / 100"      -ForegroundColor $(if($healthScore -ge 80){'Green'} elseif($healthScore -ge 50){'Yellow'} else{'Red'})
    Write-Host "  📁  Output file       : $OutputPath"             -ForegroundColor White
    Write-Host ""

    if ($OpenBrowser) {
        Write-Host "  🌐  Opening in browser…" -ForegroundColor Green
        Start-Process $OutputPath
    }

    #endregion
}
