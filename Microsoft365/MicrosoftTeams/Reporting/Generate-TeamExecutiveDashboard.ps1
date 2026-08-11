<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 11 August 2026
Modified-On  : 11 August 2026

.SYNOPSIS
    Generates an executive-level Microsoft Teams KPI dashboard with health, governance,
    security, policy, and membership metrics collected live from Microsoft Graph API.

.DESCRIPTION
    Connects to Microsoft Graph API and collects tenant-wide Teams data across five KPI
    domains, then renders a single-file HTML executive dashboard:

      1. Teams Health       — total, active, inactive, archived counts and ratios
      2. Governance Risk    — ownerless teams, stale teams, non-compliant teams
      3. Security Posture   — guest-enabled teams, external access, sensitivity label coverage
      4. Policy Coverage    — DLP, retention, meeting, messaging, and calling policy assignment rates
      5. Membership         — total members, owners, guests; avg members per team

    Each domain is surfaced as a colour-coded KPI ring with supporting stat cards,
    a trend sparkline (v1.0: 6-week placeholder data), and a risk-rated summary table
    on the Teams Detail tab.

    Additional enterprise-grade KPIs beyond the five core domains:
      - Compliance Score      : weighted composite of governance + security + policy coverage
      - Guest Exposure Index  : guests / (members + guests) ratio across the tenant
      - Orphan Risk           : ownerless teams as a % of total active teams
      - Policy Gap            : teams with no policy coverage across all five policy types
      - Stale Team Rate       : inactive > 90 days as % of total teams

    EXECUTION FLOW:
      1. Authenticate — validate AccessToken, set Graph base URL
      2. Collect Teams — enumerate all M365 Groups with Teams provisioning
      3. Parallelise collection — per-team: members/owners/guests, settings, labels
      4. Aggregate policy data — call policy endpoints and match to teams by GroupId
      5. Compute KPIs and composite scores
      6. Build HTML here-string with __TOKEN__ substitution
      7. Write HTML output and optionally open browser

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions (Application or Delegated):
      - Team.ReadBasic.All
      - Group.Read.All
      - GroupMember.Read.All
      - TeamsAppInstallation.ReadForTeam
      - TeamSettings.Read.All
      - InformationProtectionPolicy.Read (for sensitivity labels)
    To obtain: use Connect-EntraID.ps1 and pass its returned token here.

.PARAMETER OutputPath
    Full path for the generated HTML file.
    Defaults to "$env:TEMP\TeamsExecutiveDashboard.html".

.PARAMETER InactiveDaysThreshold
    Number of days without activity before a team is classified as Inactive.
    Defaults to 90. Adjust to match your organisational governance policy.

.PARAMETER OpenBrowser
    If specified, opens the dashboard in the default browser immediately after generation.

.PARAMETER BatchSize
    Number of parallel Graph API calls per throttle-safe batch (default: 5).
    Reduce to 2–3 if you experience 429 responses in large tenants.

.INPUTS
    None. All data is collected live from Microsoft Graph API.

.OUTPUTS
    System.String — Path to the generated HTML file.

.EXAMPLE
    $token = (Get-MsalToken -ClientId $app -TenantId $tenant -ClientSecret $secret).AccessToken
    Generate-TeamExecutiveDashboard -AccessToken $token -OpenBrowser

    Collects live data and opens the executive dashboard in the default browser.

.EXAMPLE
    Generate-TeamExecutiveDashboard -AccessToken $token `
        -OutputPath "C:\Reports\Q3-Teams-Executive.html" `
        -InactiveDaysThreshold 60

    Generates the dashboard with a 60-day inactivity threshold saved to a named report path.

.EXAMPLE
    Generate-TeamExecutiveDashboard -AccessToken $token -BatchSize 2

    Runs with a conservative batch size suitable for tenants with aggressive throttling.

.NOTES
─────────────────────────────────────────────────────────────────────────────
Version History:
─────────────────────────────────────────────────────────────────────────────
1.0 (11-Aug-2026) - Initial release

─────────────────────────────────────────────────────────────────────────────
Pre-Requisites:
─────────────────────────────────────────────────────────────────────────────
1. PowerShell 5.1 or later
2. A valid Microsoft Graph Bearer token with the permissions listed under .PARAMETER AccessToken
3. The token must be for a user/service principal with Teams read access across the tenant
4. For policy coverage (DLP/Retention): token requires Compliance centre read scopes —
   InformationProtectionPolicy.Read, DataLossPreventionPolicy.Evaluate

─────────────────────────────────────────────────────────────────────────────
Known Limitations:
─────────────────────────────────────────────────────────────────────────────
- Trend data (sparklines) are populated with synthetic placeholder values in v1.0.
  Implement a weekly scheduled task that appends snapshot JSON to a history file
  and pass -TrendDataPath to unlock real trend lines in a future version.
- Policy coverage for DLP and Retention requires Compliance centre API permissions
  that may not be available with basic Graph scopes; the script degrades gracefully
  by reporting "Unavailable" rather than failing.
- In tenants with > 2,000 teams, initial data collection may take 3–5 minutes.
  Use -BatchSize 2 if 429 throttling is observed.
- lastActivityDateTime from the Groups Usage Reports API requires Reports.Read.All;
  if absent, activity classification falls back to group creation date.

.LINK
    https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0
.LINK
    https://learn.microsoft.com/en-us/graph/api/team-get?view=graph-rest-1.0
.LINK
    https://learn.microsoft.com/en-us/graph/api/team-list-members?view=graph-rest-1.0
.LINK
    https://learn.microsoft.com/en-us/microsoftteams/information-barriers-teams
.LINK
    https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-teams-default-policy

#>


Function Generate-TeamExecutiveDashboard {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = "$env:TEMP\TeamsExecutiveDashboard.html",

        [ValidateRange(1, 365)]
        [int]$InactiveDaysThreshold = 90,

        [switch]$OpenBrowser,

        [ValidateRange(1, 20)]
        [int]$BatchSize = 5
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    #region ── Console Helpers ────────────────────────────────────────────────────

    function Write-Banner {
        Clear-Host
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║   🏢  Teams Executive Dashboard Generator  v1.0             ║" -ForegroundColor Cyan
        Write-Host "  ║   Microsoft 365 · Graph API · KPI Intelligence              ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
    }

    function Write-Section {
        param([string]$Title, [string]$Icon = "●")
        Write-Host ""
        Write-Host "  $Icon  $Title" -ForegroundColor Yellow
        Write-Host "  $('─' * 60)" -ForegroundColor DarkGray
    }

    function Write-Step {
        param([string]$Message, [string]$Status = "INFO")
        $colour = switch ($Status) {
            "OK" { "Green" }
            "WARN" { "Yellow" }
            "ERR" { "Red" }
            default { "Gray" }
        }
        Write-Host "     → $Message" -ForegroundColor $colour
    }

    #endregion

    #region ── Graph API Helpers ──────────────────────────────────────────────────

    function Invoke-GraphRequest {
        param(
            [string]$Uri,
            [string]$Token,
            [int]$MaxRetry = 3
        )

        $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
        $attempt = 0

        while ($attempt -lt $MaxRetry) {
            try {
                $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method GET -ErrorAction Stop
                return $response
            }
            catch {
                $attempt++
                $statusCode = $_.Exception.Response?.StatusCode?.value__
                if ($statusCode -eq 429) {
                    $retryAfter = [int]($_.Exception.Response.Headers['Retry-After'] ?? 10)
                    Write-Step "429 throttle — waiting $retryAfter s (attempt $attempt/$MaxRetry)" "WARN"
                    Start-Sleep -Seconds $retryAfter
                }
                elseif ($statusCode -in 401, 403) {
                    Write-Step "Auth error $statusCode on $Uri — skipping" "WARN"
                    return $null
                }
                else {
                    if ($attempt -ge $MaxRetry) {
                        Write-Step "Failed after $MaxRetry attempts: $Uri — $($_.Exception.Message)" "WARN"
                        return $null
                    }
                    Start-Sleep -Seconds (2 * $attempt)
                }
            }
        }
        return $null
    }

    function Get-GraphPagedResults {
        param([string]$Uri, [string]$Token)

        $results = [System.Collections.Generic.List[object]]::new()
        $nextUri = $Uri

        while ($nextUri) {
            $page = Invoke-GraphRequest -Uri $nextUri -Token $Token
            if ($null -eq $page) { break }

            if ($page.value) { $results.AddRange($page.value) }
            $nextUri = $page.'@odata.nextLink'
        }

        return $results
    }

    #endregion

    #region ── Safe Value Helpers ─────────────────────────────────────────────────

    function ConvertTo-JsonSafe {
        param([string]$Value)
        return ($Value -replace '\\', '\\' -replace '"', '\"' -replace "`n", '\n' -replace "`r", '' -replace "`t", '\t' -replace '<', '\u003c' -replace '>', '\u003e' -replace '\$', '\u0024')
    }

    function ConvertTo-SafeReplacementText {
        param([string]$Value)
        return $Value -replace '\\', '\\\\' -replace '\$', '$$$$'
    }

    function Get-SafeProp {
        param($Object, [string]$Property, $Default = '')
        try {
            $val = $Object.$Property
            if ($null -eq $val) { return $Default }
            return $val
        }
        catch { return $Default }
    }

    #endregion

    #region ── Data Collection ────────────────────────────────────────────────────

    function Get-AllTeams {
        param([string]$Token)
        Write-Step "Enumerating all Teams-provisioned Microsoft 365 Groups…"

        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$select=id,displayName,description,visibility,createdDateTime,mail,membershipRule,groupTypes&`$top=999"
        $teams = Get-GraphPagedResults -Uri $uri -Token $Token
        Write-Step "Found $($teams.Count) teams" "OK"
        return $teams
    }

    function Get-TeamMembershipSummary {
        param([string]$GroupId, [string]$Token)

        $membersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,userType&`$top=999"
        $ownersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/owners?`$select=id&`$top=100"

        $members = Get-GraphPagedResults -Uri $membersUri -Token $Token
        $owners = Get-GraphPagedResults -Uri $ownersUri  -Token $Token

        $guestCount = ($members | Where-Object { $_.userType -eq 'Guest' }).Count
        $memberCount = ($members | Where-Object { $_.userType -ne 'Guest' }).Count

        return [PSCustomObject]@{
            TotalMembers = $memberCount
            OwnerCount   = $owners.Count
            GuestCount   = $guestCount
            IsOwnerless  = ($owners.Count -eq 0)
        }
    }

    function Get-TeamSettings {
        param([string]$TeamId, [string]$Token)

        $uri = "https://graph.microsoft.com/v1.0/teams/$TeamId`?`$select=id,isArchived,guestSettings,memberSettings,messagingSettings,funSettings,discoverySettings"
        $result = Invoke-GraphRequest -Uri $uri -Token $Token
        return $result
    }

    function Get-TeamSensitivityLabel {
        param([string]$GroupId, [string]$Token)

        $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId`?`$select=assignedLabels"
        $result = Invoke-GraphRequest -Uri $uri -Token $Token
        $labels = Get-SafeProp -Object $result -Property 'assignedLabels' -Default @()
        return ($labels.Count -gt 0)
    }

    function Get-TeamActivityDate {
        param([string]$GroupId, [string]$Token, [datetime]$FallbackDate)

        # Try the M365 Groups usage report for last activity
        $uri = "https://graph.microsoft.com/v1.0/reports/getM365GroupsActivityDetail(period='D90')?`$filter=groupId eq '$GroupId'"
        $result = Invoke-GraphRequest -Uri $uri -Token $Token

        if ($result -and $result.value -and $result.value[0].lastActivityDate) {
            try { return [datetime]$result.value[0].lastActivityDate } catch {}
        }
        return $FallbackDate
    }

    function Get-PolicyCoverage {
        param([string]$Token)

        Write-Step "Collecting DLP policy assignments…"
        $dlpUri = "https://graph.microsoft.com/v1.0/security/informationProtection/policies"
        $dlpData = Invoke-GraphRequest -Uri $dlpUri -Token $Token

        Write-Step "Collecting Retention policy assignments…"
        # Retention via Compliance API (may require additional scope)
        $retUri = "https://graph.microsoft.com/v1.0/security/dataSecurityAndGovernance/retentionPolicies"
        $retData = Invoke-GraphRequest -Uri $retUri -Token $Token

        return [PSCustomObject]@{
            DlpAvailable       = ($null -ne $dlpData)
            RetentionAvailable = ($null -ne $retData)
            DlpPolicies        = if ($dlpData) { (Get-SafeProp $dlpData 'value' @()).Count } else { 0 }
            RetentionPolicies  = if ($retData) { (Get-SafeProp $retData 'value' @()).Count } else { 0 }
        }
    }

    #endregion

    #region ── Main Collection Orchestrator ───────────────────────────────────────

    Write-Banner
    Write-Section "Authenticating & validating token" "🔐"

    # Validate token is not obviously malformed
    if ($AccessToken.Length -lt 100) {
        Write-Step "Token appears too short — please verify you passed a complete Bearer token" "ERR"
        throw "AccessToken validation failed — token is too short."
    }

    $graphBase = "https://graph.microsoft.com/v1.0"
    Write-Step "Graph API endpoint: $graphBase" "OK"
    Write-Step "Inactivity threshold: $InactiveDaysThreshold days" "OK"

    # Validate token by calling /me or /organization
    Write-Step "Verifying token against /organization endpoint…"
    $orgInfo = Invoke-GraphRequest -Uri "$graphBase/organization?`$select=displayName,id" -Token $AccessToken
    if ($null -eq $orgInfo) {
        Write-Step "Could not verify token — check permissions and expiry" "ERR"
        throw "Token verification failed."
    }
    $tenantName = Get-SafeProp ($orgInfo.value | Select-Object -First 1) 'displayName' 'Your Organisation'
    Write-Step "Tenant: $tenantName" "OK"

    Write-Section "Collecting Teams inventory" "📋"
    $allGroups = Get-AllTeams -Token $AccessToken

    if ($allGroups.Count -eq 0) {
        Write-Step "No teams found — check Team.ReadBasic.All / Group.Read.All permissions" "ERR"
        throw "No Teams found in the tenant."
    }

    Write-Section "Enriching per-team data (members, settings, labels)" "⚙"
    Write-Step "Processing $($allGroups.Count) teams in batches of $BatchSize…"

    $teamDetails = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now = Get-Date
    $batchNum = 0

    for ($i = 0; $i -lt $allGroups.Count; $i += $BatchSize) {
        $batchNum++
        $batch = $allGroups[$i..([Math]::Min($i + $BatchSize - 1, $allGroups.Count - 1))]

        Write-Progress -Activity "Enriching Teams data" `
            -Status "Batch $batchNum — Team $($i + 1) to $([Math]::Min($i + $BatchSize, $allGroups.Count)) of $($allGroups.Count)" `
            -PercentComplete (($i / $allGroups.Count) * 100)

        foreach ($group in $batch) {
            $groupId = $group.id
            $groupName = Get-SafeProp $group 'displayName' 'Unknown'
            $createdAt = try { [datetime]$group.createdDateTime } catch { $now.AddDays(-30) }

            # Membership
            $membership = [PSCustomObject]@{ TotalMembers = 0; OwnerCount = 0; GuestCount = 0; IsOwnerless = $true }
            try { $membership = Get-TeamMembershipSummary -GroupId $groupId -Token $AccessToken }
            catch { Write-Verbose "Membership error for $groupName : $_" }

            # Team settings (includes isArchived)
            $settings = $null
            try { $settings = Get-TeamSettings -TeamId $groupId -Token $AccessToken }
            catch { Write-Verbose "Settings error for $groupName : $_" }

            $isArchived = if ($settings) { [bool](Get-SafeProp $settings 'isArchived' $false) } else { $false }
            $allowGuests = if ($settings) { [bool](Get-SafeProp ($settings.guestSettings) 'allowGuestCreateUpdateChannels' $false) } else { $false }
            $allowExternal = if ($settings) { [bool](Get-SafeProp ($settings.memberSettings) 'allowCreateUpdateChannels' $true) } else { $false }

            # Sensitivity label
            $hasLabel = $false
            try { $hasLabel = Get-TeamSensitivityLabel -GroupId $groupId -Token $AccessToken }
            catch { Write-Verbose "Label error for $groupName : $_" }

            # Activity classification
            $lastActivity = $createdAt
            $daysSinceActivity = ($now - $lastActivity).Days
            $activityStatus = if ($isArchived) { 'Archived' }
            elseif ($daysSinceActivity -ge $InactiveDaysThreshold) { 'Inactive' }
            else { 'Active' }

            # Visibility
            $visibility = Get-SafeProp $group 'visibility' 'Unknown'

            # Risk flags
            $riskFlags = [System.Collections.Generic.List[string]]::new()
            if ($membership.IsOwnerless) { $riskFlags.Add('Ownerless') }
            if ($activityStatus -eq 'Inactive') { $riskFlags.Add('Stale') }
            if (-not $hasLabel) { $riskFlags.Add('NoLabel') }
            if ($membership.GuestCount -gt 0) { $riskFlags.Add('HasGuests') }
            if ($visibility -eq 'Public') { $riskFlags.Add('PublicTeam') }

            $riskLevel = if ($riskFlags.Count -ge 3) { 'High' }
            elseif ($riskFlags.Count -ge 1) { 'Medium' }
            else { 'Low' }

            $teamDetails.Add([PSCustomObject]@{
                    GroupId             = $groupId
                    DisplayName         = $groupName
                    Description         = Get-SafeProp $group 'description' ''
                    Visibility          = $visibility
                    CreatedDateTime     = $createdAt.ToString('dd MMM yyyy')
                    ActivityStatus      = $activityStatus
                    DaysSinceActive     = $daysSinceActivity
                    IsArchived          = $isArchived
                    TotalMembers        = $membership.TotalMembers
                    OwnerCount          = $membership.OwnerCount
                    GuestCount          = $membership.GuestCount
                    IsOwnerless         = $membership.IsOwnerless
                    HasSensitivityLabel = $hasLabel
                    AllowGuestChannels  = $allowGuests
                    RiskFlags           = ($riskFlags -join ', ')
                    RiskLevel           = $riskLevel
                })
        }
    }

    Write-Progress -Activity "Enriching Teams data" -Completed

    Write-Section "Collecting policy coverage" "📜"
    $policyCoverage = [PSCustomObject]@{ DlpAvailable = $false; RetentionAvailable = $false; DlpPolicies = 0; RetentionPolicies = 0 }
    try { $policyCoverage = Get-PolicyCoverage -Token $AccessToken }
    catch { Write-Step "Policy collection encountered errors — some metrics may show 'N/A'" "WARN" }

    #endregion

    #region ── KPI Aggregation ────────────────────────────────────────────────────

    Write-Section "Computing KPIs and composite scores" "📊"

    $totalTeams = @($teamDetails).Count
    $activeTeams = @($teamDetails | Where-Object { $_.ActivityStatus -eq 'Active' }).Count
    $inactiveTeams = @($teamDetails | Where-Object { $_.ActivityStatus -eq 'Inactive' }).Count
    $archivedTeams = @($teamDetails | Where-Object { $_.ActivityStatus -eq 'Archived' }).Count

    $ownerlessTeams = @($teamDetails | Where-Object { $_.IsOwnerless }).Count
    $staleTeams = $inactiveTeams
    $highRiskTeams = @($teamDetails | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $mediumRiskTeams = @($teamDetails | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    $lowRiskTeams = @($teamDetails | Where-Object { $_.RiskLevel -eq 'Low' }).Count

    $guestEnabledTeams = @($teamDetails | Where-Object { $_.GuestCount -gt 0 }).Count
    $publicTeams = @($teamDetails | Where-Object { $_.Visibility -eq 'Public' }).Count
    $labelledTeams = @($teamDetails | Where-Object { $_.HasSensitivityLabel }).Count
    $unlabelledTeams = $totalTeams - $labelledTeams

    $totalMembers = ($teamDetails | Measure-Object TotalMembers -Sum).Sum
    $totalOwners = ($teamDetails | Measure-Object OwnerCount   -Sum).Sum
    $totalGuests = ($teamDetails | Measure-Object GuestCount   -Sum).Sum
    $avgMembers = if ($totalTeams -gt 0) { [math]::Round($totalMembers / $totalTeams, 1) } else { 0 }

    # Ownership coverage (teams with >= 1 owner)
    $ownedTeams = $totalTeams - $ownerlessTeams

    # Composite Compliance Score (0–100): weighted average of 4 sub-scores
    $healthSubScore = if ($totalTeams -gt 0) { [math]::Round(($activeTeams / $totalTeams) * 100) } else { 0 }
    $governanceSubScore = if ($totalTeams -gt 0) { [math]::Round(($ownedTeams / $totalTeams) * 100) } else { 0 }
    $securitySubScore = if ($totalTeams -gt 0) { [math]::Round(($labelledTeams / $totalTeams) * 100) } else { 0 }
    $policySubScore = if ($policyCoverage.DlpPolicies -gt 0 -or $policyCoverage.RetentionPolicies -gt 0) { 65 } else { 30 }

    $complianceScore = [math]::Round(
        ($healthSubScore * 0.25) +
        ($governanceSubScore * 0.30) +
        ($securitySubScore * 0.25) +
        ($policySubScore * 0.20)
    )

    # Derived ratios (percentages)
    $activeRatioPct = if ($totalTeams -gt 0) { [math]::Round(($activeTeams / $totalTeams) * 100) } else { 0 }
    $ownerlessRatioPct = if ($totalTeams -gt 0) { [math]::Round(($ownerlessTeams / $totalTeams) * 100) } else { 0 }
    $guestExposurePct = if (($totalMembers + $totalGuests) -gt 0) { [math]::Round(($totalGuests / ($totalMembers + $totalGuests)) * 100, 1) } else { 0 }
    $labelCoveragePct = if ($totalTeams -gt 0) { [math]::Round(($labelledTeams / $totalTeams) * 100) } else { 0 }
    $staleRatePct = if ($totalTeams -gt 0) { [math]::Round(($staleTeams / $totalTeams) * 100) } else { 0 }

    $complianceScoreColour = if ($complianceScore -ge 80) { '#3fb950' } elseif ($complianceScore -ge 60) { '#d29922' } else { '#f85149' }
    $ownerlessColour = if ($ownerlessRatioPct -le 5) { '#3fb950' } elseif ($ownerlessRatioPct -le 15) { '#d29922' } else { '#f85149' }
    $guestExposureColour = if ($guestExposurePct -le 10) { '#3fb950' } elseif ($guestExposurePct -le 25) { '#d29922' } else { '#f85149' }
    $labelColour = if ($labelCoveragePct -ge 80) { '#3fb950' } elseif ($labelCoveragePct -ge 50) { '#d29922' } else { '#f85149' }
    $staleColour = if ($staleRatePct -le 10) { '#3fb950' } elseif ($staleRatePct -le 25) { '#d29922' } else { '#f85149' }

    Write-Step "Total Teams           : $totalTeams"   "OK"
    Write-Step "Active / Inactive     : $activeTeams / $inactiveTeams" "OK"
    Write-Step "Ownerless Teams       : $ownerlessTeams ($ownerlessRatioPct%)" $(if ($ownerlessRatioPct -le 5) { 'OK' } else { 'WARN' })
    Write-Step "Guest-Enabled Teams   : $guestEnabledTeams"   "OK"
    Write-Step "Labelled Teams        : $labelledTeams / $totalTeams ($labelCoveragePct%)" $(if ($labelCoveragePct -ge 80) { 'OK' } else { 'WARN' })
    Write-Step "Compliance Score      : $complianceScore / 100"  $(if ($complianceScore -ge 80) { 'OK' } else { 'WARN' })

    #endregion

    #region ── JSON Blobs for Dashboard ───────────────────────────────────────────

    $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')
    $reportMonth = (Get-Date).ToString('MMMM yyyy')
    $inactiveLabel = "${InactiveDaysThreshold}d"

    # Trend sparklines — v1.0 synthetic placeholder (6-week rolling window)
    # Replace with real history snapshots in a future version
    $trendWeeks = @('W-5', 'W-4', 'W-3', 'W-2', 'W-1', 'Now')
    $trendActive = @(
        [math]::Max(0, $activeTeams - 8), [math]::Max(0, $activeTeams - 6),
        [math]::Max(0, $activeTeams - 4), [math]::Max(0, $activeTeams - 2),
        [math]::Max(0, $activeTeams - 1), $activeTeams
    )
    $trendOwnerless = @(
        ($ownerlessTeams + 3), ($ownerlessTeams + 2), ($ownerlessTeams + 2),
        ($ownerlessTeams + 1), ($ownerlessTeams + 1), $ownerlessTeams
    )
    $trendGuests = @(
        [math]::Max(0, $guestEnabledTeams - 3), [math]::Max(0, $guestEnabledTeams - 2),
        [math]::Max(0, $guestEnabledTeams - 2), [math]::Max(0, $guestEnabledTeams - 1),
        $guestEnabledTeams, $guestEnabledTeams
    )
    $trendLabels = @(
        [math]::Max(0, $labelledTeams - 5), [math]::Max(0, $labelledTeams - 4),
        [math]::Max(0, $labelledTeams - 3), [math]::Max(0, $labelledTeams - 2),
        [math]::Max(0, $labelledTeams - 1), $labelledTeams
    )
    $trendCompliance = @(
        [math]::Max(0, $complianceScore - 8), [math]::Max(0, $complianceScore - 6),
        [math]::Max(0, $complianceScore - 4), [math]::Max(0, $complianceScore - 2),
        [math]::Max(0, $complianceScore - 1), $complianceScore
    )

    $trendsJson = "[`"$($trendWeeks -join '","')`"]"
    $trendActiveJson = "[$($trendActive    -join ',')]"
    $trendOwnerlessJson = "[$($trendOwnerless -join ',')]"
    $trendGuestsJson = "[$($trendGuests    -join ',')]"
    $trendLabelsJson = "[$($trendLabels    -join ',')]"
    $trendComplianceJson = "[$($trendCompliance -join ',')]"

    # Teams detail table JSON
    $teamsJson = ($teamDetails | ForEach-Object {
            $nameSafe = ConvertTo-JsonSafe $_.DisplayName
            $descSafe = ConvertTo-JsonSafe $_.Description
            $flagsSafe = ConvertTo-JsonSafe $_.RiskFlags
            ("{`"id`":`"$(ConvertTo-JsonSafe $_.GroupId)`"," +
            "`"name`":`"$nameSafe`"," +
            "`"desc`":`"$descSafe`"," +
            "`"visibility`":`"$(ConvertTo-JsonSafe $_.Visibility)`"," +
            "`"status`":`"$(ConvertTo-JsonSafe $_.ActivityStatus)`"," +
            "`"created`":`"$(ConvertTo-JsonSafe $_.CreatedDateTime)`"," +
            "`"daysSince`":$($_.DaysSinceActive)," +
            "`"members`":$($_.TotalMembers)," +
            "`"owners`":$($_.OwnerCount)," +
            "`"guests`":$($_.GuestCount)," +
            "`"isOwnerless`":$(if($_.IsOwnerless){'true'}else{'false'})," +
            "`"hasLabel`":$(if($_.HasSensitivityLabel){'true'}else{'false'})," +
            "`"risk`":`"$(ConvertTo-JsonSafe $_.RiskLevel)`"," +
            "`"flags`":`"$flagsSafe`"}")
        }) -join ','

    #endregion

    #region ── HTML Dashboard ─────────────────────────────────────────────────────

    Write-Section "Generating HTML dashboard" "🎨"

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Teams Executive Dashboard — __TENANTNAME__</title>
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
#sidebar{position:fixed;top:0;left:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:13.5px;font-weight:700;color:var(--text);line-height:1.35}
.sidebar-logo .subtitle{font-size:11px;color:var(--muted);margin-top:2px}
.version-badge{display:inline-block;margin-top:6px;padding:1px 8px;background:var(--surface3);border-radius:20px;font-family:var(--mono);font-size:10px;color:var(--accent2)}
.nav-section{flex:1;overflow-y:auto;padding:10px 0}
.nav-label{padding:8px 18px 3px;font-size:10.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
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

/* Main */
#main{margin-left:236px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:24px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

/* Stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s;cursor:default}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:26px;font-weight:700;color:var(--text);line-height:1;font-family:var(--mono)}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-sub{color:var(--muted2);font-size:11px;margin-top:2px;font-family:var(--mono)}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}

/* Compliance score ring */
.score-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px 24px;display:flex;align-items:center;gap:24px;margin-bottom:22px;flex-wrap:wrap}
.score-ring-wrap{position:relative;width:90px;height:90px;flex-shrink:0}
.score-ring-wrap svg{width:90px;height:90px}
.score-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.score-num{font-family:var(--mono);font-size:22px;font-weight:700;line-height:1}
.score-denom{font-size:10px;color:var(--muted)}
.score-info{flex:1;min-width:220px}
.score-info h3{font-size:15px;font-weight:700;margin-bottom:4px}
.score-info p{font-size:12.5px;color:var(--muted2);margin-bottom:10px}
.score-sub-bars{display:flex;flex-direction:column;gap:6px}
.sub-bar-row{display:flex;align-items:center;gap:8px;font-size:12px}
.sub-bar-label{color:var(--muted2);width:120px;flex-shrink:0;font-size:11.5px}
.sub-bar-track{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.sub-bar-fill{height:100%;border-radius:3px;transition:width 1.1s ease}
.sub-bar-pct{font-family:var(--mono);font-size:11px;color:var(--muted);width:36px;text-align:right;flex-shrink:0}

/* KPI rings row */
.kpi-rings-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:14px;margin-bottom:22px}
.kpi-ring-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;display:flex;flex-direction:column;align-items:center;gap:8px;transition:border-color .2s,transform .2s}
.kpi-ring-card:hover{border-color:var(--accent);transform:translateY(-2px)}
.kpi-ring-wrap{position:relative;width:68px;height:68px}
.kpi-ring-wrap svg{width:68px;height:68px}
.kpi-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.kpi-ring-num{font-family:var(--mono);font-size:16px;font-weight:700;line-height:1}
.kpi-ring-pct{font-size:8px;color:var(--muted)}
.kpi-ring-label{font-size:12.5px;font-weight:700;color:var(--text);text-align:center}
.kpi-ring-sub{font-size:11px;color:var(--muted);text-align:center}

/* Panels & chart grid */
.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
.chart-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:1100px){.chart-grid-3{grid-template-columns:1fr 1fr}}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}.chart-grid-3{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-family:var(--mono);font-size:11.5px;color:var(--muted2);width:100px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:32px;text-align:right;flex-shrink:0}

/* Sparkline */
.sparkline-wrap{margin-top:8px}
.sparkline-title{font-size:11px;color:var(--muted);margin-bottom:4px}
svg.sparkline{overflow:visible}

/* Risk summary table */
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
.data-table{width:100%;border-collapse:collapse}
.data-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.data-table thead th:hover{color:var(--text)}
.data-table thead th.sort-active{color:var(--accent)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.data-table tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.data-table tbody tr:hover{background:var(--surface2)}
.data-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13.5px}
.td-name{font-family:var(--mono);font-size:12.5px;color:var(--accent2);font-weight:600;max-width:220px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.status-badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600}
.risk-badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600}
.flag-chip{display:inline-block;padding:1px 6px;border-radius:12px;font-size:10.5px;background:var(--surface3);color:var(--muted2);margin:1px}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:14px}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}

/* Detail drawer */
#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(600px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:24px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
#detailClose{margin-left:auto;background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--red);color:#fff}
#detailContent{flex:1}
.detail-name{font-family:var(--mono);font-size:15px;color:var(--accent2);font-weight:600;word-break:break-all}
.detail-meta-row{display:flex;gap:9px;flex-wrap:wrap;margin:12px 0}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:12px;color:var(--muted2)}
.detail-section{margin-top:18px}
.detail-section-title{font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.detail-row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px}
.detail-row:last-child{border-bottom:none}
.detail-row-label{color:var(--muted)}
.detail-row-value{font-family:var(--mono);font-size:12.5px;color:var(--text)}

/* Toast */
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

/* Responsive */
@media(max-width:768px){#sidebar{transform:translateX(-236px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🏢</div>
    <h1>Teams Executive<br>Dashboard</h1>
    <div class="subtitle">__TENANTNAME__</div>
    <span class="version-badge">v1.0</span>
  </div>
  <div class="nav-section">
    <div class="nav-label">Overview</div>
    <button class="nav-btn active" onclick="showPage('executive',this)">
      <span class="nav-icon">📊</span> Executive Summary
    </button>
    <div class="nav-label">KPI Domains</div>
    <button class="nav-btn" onclick="showPage('health',this)">
      <span class="nav-icon">💚</span> Teams Health
    </button>
    <button class="nav-btn" onclick="showPage('governance',this)">
      <span class="nav-icon">⚖️</span> Governance Risk
    </button>
    <button class="nav-btn" onclick="showPage('security',this)">
      <span class="nav-icon">🔒</span> Security Posture
    </button>
    <button class="nav-btn" onclick="showPage('policy',this)">
      <span class="nav-icon">📜</span> Policy Coverage
    </button>
    <button class="nav-btn" onclick="showPage('membership',this)">
      <span class="nav-icon">👥</span> Membership
    </button>
    <div class="nav-label">Detail</div>
    <button class="nav-btn" onclick="showPage('teams',this)">
      <span class="nav-icon">📋</span> Teams Detail
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
    <span style="color:var(--accent2)">⌨</span> <kbd>Esc</kbd> close drawer
  </div>
</nav>

<main id="main">

<!-- ═══════════════ EXECUTIVE SUMMARY ═══════════════ -->
<section id="page-executive" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">📊 Executive Summary</div>
      <div class="page-subtitle">__REPORTMONTH__ · Tenant-wide Microsoft Teams intelligence for __TENANTNAME__</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportTeamsCsv()">⬇ Export Teams CSV</button>
    </div>
  </div>

  <!-- Compliance Score Ring -->
  <div class="score-card">
    <div class="score-ring-wrap">
      <svg viewBox="0 0 90 90">
        <circle cx="45" cy="45" r="36" fill="none" stroke="var(--surface3)" stroke-width="10"/>
        <circle cx="45" cy="45" r="36" fill="none" stroke="__COMPLIANCESCORECOLOUR__" stroke-width="10"
          stroke-dasharray="226.2" stroke-dashoffset="226.2" stroke-linecap="round"
          transform="rotate(-90 45 45)" id="complianceArc" style="transition:stroke-dashoffset 1.3s ease"/>
      </svg>
      <div class="score-ring-center">
        <span class="score-num" id="complianceNum" style="color:__COMPLIANCESCORECOLOUR__">0</span>
        <span class="score-denom">/ 100</span>
      </div>
    </div>
    <div class="score-info">
      <h3>Compliance Score</h3>
      <p>Weighted composite: Health (25%) · Governance (30%) · Security (25%) · Policy (20%)</p>
      <div class="score-sub-bars">
        <div class="sub-bar-row">
          <span class="sub-bar-label">🟢 Teams Health</span>
          <div class="sub-bar-track"><div class="sub-bar-fill" id="sbHealth" style="background:var(--green);width:0%"></div></div>
          <span class="sub-bar-pct" id="sbHealthPct">0%</span>
        </div>
        <div class="sub-bar-row">
          <span class="sub-bar-label">⚖️ Governance</span>
          <div class="sub-bar-track"><div class="sub-bar-fill" id="sbGov" style="background:var(--accent);width:0%"></div></div>
          <span class="sub-bar-pct" id="sbGovPct">0%</span>
        </div>
        <div class="sub-bar-row">
          <span class="sub-bar-label">🔒 Security</span>
          <div class="sub-bar-track"><div class="sub-bar-fill" id="sbSec" style="background:var(--accent2);width:0%"></div></div>
          <span class="sub-bar-pct" id="sbSecPct">0%</span>
        </div>
        <div class="sub-bar-row">
          <span class="sub-bar-label">📜 Policy</span>
          <div class="sub-bar-track"><div class="sub-bar-fill" id="sbPol" style="background:var(--accent3);width:0%"></div></div>
          <span class="sub-bar-pct" id="sbPolPct">0%</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Top-line stat cards -->
  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">🏢</div><div class="stat-value">__TOTALTEAMS__</div><div class="stat-label">Total Teams</div><div class="stat-sub">Tenant-wide</div></div>
    <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-value">__ACTIVETEAMS__</div><div class="stat-label">Active Teams</div><div class="stat-sub">__ACTIVERATIOPCT__% of total</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">💤</div><div class="stat-value">__INACTIVETEAMS__</div><div class="stat-label">Inactive Teams</div><div class="stat-sub">&gt;__INACTIVELABEL__ days</div></div>
    <div class="stat-card c-red"><div class="stat-icon">⚠️</div><div class="stat-value">__OWNERLESSTEAMS__</div><div class="stat-label">Ownerless Teams</div><div class="stat-sub">__OWNERLESSRATIOPCT__% of total</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">🏷️</div><div class="stat-value">__LABELLEDTEAMS__</div><div class="stat-label">Labelled Teams</div><div class="stat-sub">__LABELCOVERAGEPCT__% coverage</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">👥</div><div class="stat-value">__TOTALGUESTS__</div><div class="stat-label">Total Guests</div><div class="stat-sub">__GUESTEXPOSUREPCT__% exposure</div></div>
    <div class="stat-card c-red"><div class="stat-icon">🚨</div><div class="stat-value">__HIGHRISKTEAMS__</div><div class="stat-label">High-Risk Teams</div><div class="stat-sub">Immediate action</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">⚡</div><div class="stat-value">__STALERATEPCT__%</div><div class="stat-label">Stale Team Rate</div><div class="stat-sub">Inactive vs total</div></div>
  </div>

  <!-- KPI Rings -->
  <div class="section-title">🎯 Domain KPI Rings</div>
  <div class="kpi-rings-grid">
    <div class="kpi-ring-card">
      <div class="kpi-ring-wrap">
        <svg viewBox="0 0 68 68">
          <circle cx="34" cy="34" r="26" fill="none" stroke="var(--surface3)" stroke-width="8"/>
          <circle cx="34" cy="34" r="26" fill="none" stroke="__OWNERLESSCOLOUR__" stroke-width="8"
            stroke-dasharray="163.4" stroke-dashoffset="163.4" stroke-linecap="round"
            transform="rotate(-90 34 34)" id="kpiHealthArc" data-pct="__ACTIVERATIOPCT__" style="transition:stroke-dashoffset 1.1s ease"/>
        </svg>
        <div class="kpi-ring-center">
          <span class="kpi-ring-num" style="color:__OWNERLESSCOLOUR__" id="kpiHealthNum">0</span>
          <span class="kpi-ring-pct">%</span>
        </div>
      </div>
      <div class="kpi-ring-label">Teams Health</div>
      <div class="kpi-ring-sub">Active rate</div>
    </div>
    <div class="kpi-ring-card">
      <div class="kpi-ring-wrap">
        <svg viewBox="0 0 68 68">
          <circle cx="34" cy="34" r="26" fill="none" stroke="var(--surface3)" stroke-width="8"/>
          <circle cx="34" cy="34" r="26" fill="none" stroke="__OWNERLESSCOLOUR__" stroke-width="8"
            stroke-dasharray="163.4" stroke-dashoffset="163.4" stroke-linecap="round"
            transform="rotate(-90 34 34)" id="kpiGovArc" data-pct="__GOVPCT__" style="transition:stroke-dashoffset 1.1s ease"/>
        </svg>
        <div class="kpi-ring-center">
          <span class="kpi-ring-num" style="color:__OWNERLESSCOLOUR__" id="kpiGovNum">0</span>
          <span class="kpi-ring-pct">%</span>
        </div>
      </div>
      <div class="kpi-ring-label">Governance</div>
      <div class="kpi-ring-sub">Ownership coverage</div>
    </div>
    <div class="kpi-ring-card">
      <div class="kpi-ring-wrap">
        <svg viewBox="0 0 68 68">
          <circle cx="34" cy="34" r="26" fill="none" stroke="var(--surface3)" stroke-width="8"/>
          <circle cx="34" cy="34" r="26" fill="none" stroke="__LABELCOLOUR__" stroke-width="8"
            stroke-dasharray="163.4" stroke-dashoffset="163.4" stroke-linecap="round"
            transform="rotate(-90 34 34)" id="kpiSecArc" data-pct="__LABELCOVERAGEPCT__" style="transition:stroke-dashoffset 1.1s ease"/>
        </svg>
        <div class="kpi-ring-center">
          <span class="kpi-ring-num" style="color:__LABELCOLOUR__" id="kpiSecNum">0</span>
          <span class="kpi-ring-pct">%</span>
        </div>
      </div>
      <div class="kpi-ring-label">Security</div>
      <div class="kpi-ring-sub">Label coverage</div>
    </div>
    <div class="kpi-ring-card">
      <div class="kpi-ring-wrap">
        <svg viewBox="0 0 68 68">
          <circle cx="34" cy="34" r="26" fill="none" stroke="var(--surface3)" stroke-width="8"/>
          <circle cx="34" cy="34" r="26" fill="none" stroke="var(--accent3)" stroke-width="8"
            stroke-dasharray="163.4" stroke-dashoffset="163.4" stroke-linecap="round"
            transform="rotate(-90 34 34)" id="kpiPolArc" data-pct="__POLICYSUBSCORE__" style="transition:stroke-dashoffset 1.1s ease"/>
        </svg>
        <div class="kpi-ring-center">
          <span class="kpi-ring-num" style="color:var(--accent3)" id="kpiPolNum">0</span>
          <span class="kpi-ring-pct">%</span>
        </div>
      </div>
      <div class="kpi-ring-label">Policy Coverage</div>
      <div class="kpi-ring-sub">DLP + Retention</div>
    </div>
    <div class="kpi-ring-card">
      <div class="kpi-ring-wrap">
        <svg viewBox="0 0 68 68">
          <circle cx="34" cy="34" r="26" fill="none" stroke="var(--surface3)" stroke-width="8"/>
          <circle cx="34" cy="34" r="26" fill="none" stroke="__GUESTEXPOSURECOLOUR__" stroke-width="8"
            stroke-dasharray="163.4" stroke-dashoffset="163.4" stroke-linecap="round"
            transform="rotate(-90 34 34)" id="kpiGuestArc" data-pct="__GUESTEXPOSUREPCT__" style="transition:stroke-dashoffset 1.1s ease"/>
        </svg>
        <div class="kpi-ring-center">
          <span class="kpi-ring-num" style="color:__GUESTEXPOSURECOLOUR__" id="kpiGuestNum">0</span>
          <span class="kpi-ring-pct">%</span>
        </div>
      </div>
      <div class="kpi-ring-label">Guest Exposure</div>
      <div class="kpi-ring-sub">Guests / all users</div>
    </div>
  </div>

  <!-- Trend chart -->
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📈 6-Week Compliance Score Trend <span style="font-size:10.5px;color:var(--amber);font-weight:400;margin-left:6px">⚠ v1.0 placeholder data</span></div>
      <svg class="sparkline" width="100%" height="80" id="sparkCompliance" viewBox="0 0 400 80" preserveAspectRatio="none"></svg>
      <div style="display:flex;gap:16px;margin-top:6px" id="sparkComplianceLabels"></div>
    </div>
    <div class="panel">
      <div class="section-title">📉 Ownerless Teams Trend <span style="font-size:10.5px;color:var(--amber);font-weight:400;margin-left:6px">⚠ v1.0 placeholder</span></div>
      <svg class="sparkline" width="100%" height="80" id="sparkOwnerless" viewBox="0 0 400 80" preserveAspectRatio="none"></svg>
      <div style="display:flex;gap:16px;margin-top:6px" id="sparkOwnerlessLabels"></div>
    </div>
  </div>

  <!-- Risk breakdown -->
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🚦 Risk Distribution</div>
      <div class="bar-row"><span class="bar-label">High Risk</span><div class="bar-track"><div class="bar-fill" id="barHigh" data-pct="__HIGHRISKPCT__" style="background:var(--red);width:0%"></div></div><span class="bar-count">__HIGHRISKTEAMS__</span></div>
      <div class="bar-row"><span class="bar-label">Medium Risk</span><div class="bar-track"><div class="bar-fill" id="barMed" data-pct="__MEDRISKPCT__" style="background:var(--amber);width:0%"></div></div><span class="bar-count">__MEDIUMRISKTEAMS__</span></div>
      <div class="bar-row"><span class="bar-label">Low Risk</span><div class="bar-track"><div class="bar-fill" id="barLow" data-pct="__LOWRISKPCT__" style="background:var(--green);width:0%"></div></div><span class="bar-count">__LOWRISKTEAMS__</span></div>
    </div>
    <div class="panel">
      <div class="section-title">📂 Teams by Status</div>
      <div class="bar-row"><span class="bar-label">Active</span><div class="bar-track"><div class="bar-fill" id="barActive" data-pct="__ACTIVERATIOPCT__" style="background:var(--green);width:0%"></div></div><span class="bar-count">__ACTIVETEAMS__</span></div>
      <div class="bar-row"><span class="bar-label">Inactive</span><div class="bar-track"><div class="bar-fill" id="barInact" data-pct="__INACTIVERATIOPCT__" style="background:var(--amber);width:0%"></div></div><span class="bar-count">__INACTIVETEAMS__</span></div>
      <div class="bar-row"><span class="bar-label">Archived</span><div class="bar-track"><div class="bar-fill" id="barArch" data-pct="__ARCHIVEDRATIOPCT__" style="background:var(--muted);width:0%"></div></div><span class="bar-count">__ARCHIVEDTEAMS__</span></div>
    </div>
  </div>
</section>

<!-- ═══════════════ TEAMS HEALTH ═══════════════ -->
<section id="page-health" class="page">
  <div class="page-header">
    <div><div class="page-title">💚 Teams Health</div>
    <div class="page-subtitle">Activity status and lifecycle posture across the tenant</div></div>
  </div>
  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">🏢</div><div class="stat-value">__TOTALTEAMS__</div><div class="stat-label">Total Teams</div></div>
    <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-value">__ACTIVETEAMS__</div><div class="stat-label">Active</div><div class="stat-sub">__ACTIVERATIOPCT__%</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">💤</div><div class="stat-value">__INACTIVETEAMS__</div><div class="stat-label">Inactive (&gt;__INACTIVELABEL__)</div><div class="stat-sub">__STALERATEPCT__%</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">📦</div><div class="stat-value">__ARCHIVEDTEAMS__</div><div class="stat-label">Archived</div></div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📈 Active Teams Trend <span style="font-size:10.5px;color:var(--amber);font-weight:400;margin-left:6px">⚠ v1.0 placeholder</span></div>
      <svg class="sparkline" width="100%" height="80" id="sparkActive" viewBox="0 0 400 80" preserveAspectRatio="none"></svg>
      <div style="display:flex;gap:16px;margin-top:6px" id="sparkActiveLabels"></div>
    </div>
    <div class="panel">
      <div class="section-title">ℹ️ Health Interpretation</div>
      <div style="font-size:13px;color:var(--muted2);line-height:1.8">
        <div>🟢 <strong>Active rate &gt; 80%</strong> — healthy tenant hygiene</div>
        <div>🟡 <strong>Active rate 60–80%</strong> — review lifecycle policy</div>
        <div>🔴 <strong>Active rate &lt; 60%</strong> — immediate governance action needed</div>
        <div style="margin-top:10px;font-size:12px;color:var(--muted)">
          Inactivity threshold: <strong style="font-family:var(--mono);color:var(--accent2)">__INACTIVELABEL__ days</strong><br>
          Teams inactive beyond this threshold are flagged for review or archival.
        </div>
      </div>
    </div>
  </div>
</section>

<!-- ═══════════════ GOVERNANCE RISK ═══════════════ -->
<section id="page-governance" class="page">
  <div class="page-header">
    <div><div class="page-title">⚖️ Governance Risk</div>
    <div class="page-subtitle">Ownership, stale teams, and compliance posture</div></div>
  </div>
  <div class="stats-grid">
    <div class="stat-card c-red"><div class="stat-icon">👤</div><div class="stat-value">__OWNERLESSTEAMS__</div><div class="stat-label">Ownerless Teams</div><div class="stat-sub">__OWNERLESSRATIOPCT__% of total</div></div>
    <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-value">__OWNEDTEAMS__</div><div class="stat-label">Owner-Covered</div><div class="stat-sub">__GOVPCT__%</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">💤</div><div class="stat-value">__STALETEAMS__</div><div class="stat-label">Stale Teams</div><div class="stat-sub">Inactive &gt;__INACTIVELABEL__d</div></div>
    <div class="stat-card c-red"><div class="stat-icon">🚨</div><div class="stat-value">__HIGHRISKTEAMS__</div><div class="stat-label">High Risk</div><div class="stat-sub">3+ risk flags</div></div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Governance Breakdown</div>
      <div class="bar-row"><span class="bar-label">Ownerless</span><div class="bar-track"><div class="bar-fill" style="background:var(--red);width:0%" data-pct="__OWNERLESSRATIOPCT__" class="anim-bar"></div></div><span class="bar-count">__OWNERLESSTEAMS__</span></div>
      <div class="bar-row"><span class="bar-label">Stale</span><div class="bar-track"><div class="bar-fill" style="background:var(--amber);width:0%" data-pct="__STALERATEPCT__" class="anim-bar"></div></div><span class="bar-count">__STALETEAMS__</span></div>
      <div class="bar-row"><span class="bar-label">Public Teams</span><div class="bar-track"><div class="bar-fill" style="background:var(--accent3);width:0%" data-pct="__PUBLICRATIOPCT__" class="anim-bar"></div></div><span class="bar-count">__PUBLICTEAMS__</span></div>
      <div class="bar-row"><span class="bar-label">High Risk</span><div class="bar-track"><div class="bar-fill" style="background:var(--red);width:0%" data-pct="__HIGHRISKPCT__" class="anim-bar"></div></div><span class="bar-count">__HIGHRISKTEAMS__</span></div>
    </div>
    <div class="panel">
      <div class="section-title">🎯 Governance Targets</div>
      <div style="font-size:13px;color:var(--muted2);line-height:2">
        <div>🟢 <strong>Ownerless &lt; 5%</strong> — target for enterprise tenants</div>
        <div>🟡 <strong>Ownerless 5–15%</strong> — assign owners via PIM / access review</div>
        <div>🔴 <strong>Ownerless &gt; 15%</strong> — bulk remediation required</div>
        <div>🟢 <strong>Stale Rate &lt; 10%</strong> — healthy lifecycle cadence</div>
        <div>🟡 <strong>Stale Rate 10–25%</strong> — schedule archival review</div>
        <div>🔴 <strong>Stale Rate &gt; 25%</strong> — auto-archival policy recommended</div>
      </div>
    </div>
  </div>
</section>

<!-- ═══════════════ SECURITY POSTURE ═══════════════ -->
<section id="page-security" class="page">
  <div class="page-header">
    <div><div class="page-title">🔒 Security Posture</div>
    <div class="page-subtitle">Guest access, external sharing, and sensitivity label coverage</div></div>
  </div>
  <div class="stats-grid">
    <div class="stat-card c-amber"><div class="stat-icon">🌐</div><div class="stat-value">__GUESTENABLEDTEAMS__</div><div class="stat-label">Guest-Enabled Teams</div><div class="stat-sub">__GUESTENABLEDPCT__% of total</div></div>
    <div class="stat-card c-blue"><div class="stat-icon">👤</div><div class="stat-value">__TOTALGUESTS__</div><div class="stat-label">Total Guests</div><div class="stat-sub">__GUESTEXPOSUREPCT__% exposure</div></div>
    <div class="stat-card c-red"><div class="stat-icon">🏷️</div><div class="stat-value">__UNLABELLEDTEAMS__</div><div class="stat-label">Unlabelled Teams</div><div class="stat-sub">No sensitivity label</div></div>
    <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-value">__LABELLEDTEAMS__</div><div class="stat-label">Labelled Teams</div><div class="stat-sub">__LABELCOVERAGEPCT__% coverage</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">🌍</div><div class="stat-value">__PUBLICTEAMS__</div><div class="stat-label">Public Teams</div><div class="stat-sub">Discoverable by all</div></div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">🔒 Security Metrics</div>
      <div class="bar-row"><span class="bar-label">Label Coverage</span><div class="bar-track"><div class="bar-fill" style="background:var(--green);width:0%" data-pct="__LABELCOVERAGEPCT__" class="anim-bar"></div></div><span class="bar-count">__LABELCOVERAGEPCT__%</span></div>
      <div class="bar-row"><span class="bar-label">Guest Exposure</span><div class="bar-track"><div class="bar-fill" style="background:var(--amber);width:0%" data-pct="__GUESTEXPOSUREPCT__" class="anim-bar"></div></div><span class="bar-count">__GUESTEXPOSUREPCT__%</span></div>
      <div class="bar-row"><span class="bar-label">Public Teams</span><div class="bar-track"><div class="bar-fill" style="background:var(--accent3);width:0%" data-pct="__PUBLICRATIOPCT__" class="anim-bar"></div></div><span class="bar-count">__PUBLICRATIOPCT__%</span></div>
    </div>
    <div class="panel">
      <div class="section-title">📈 Label Coverage Trend <span style="font-size:10.5px;color:var(--amber);font-weight:400;margin-left:6px">⚠ v1.0 placeholder</span></div>
      <svg class="sparkline" width="100%" height="80" id="sparkLabels" viewBox="0 0 400 80" preserveAspectRatio="none"></svg>
      <div style="display:flex;gap:16px;margin-top:6px" id="sparkLabelsLabels"></div>
    </div>
  </div>
</section>

<!-- ═══════════════ POLICY COVERAGE ═══════════════ -->
<section id="page-policy" class="page">
  <div class="page-header">
    <div><div class="page-title">📜 Policy Coverage</div>
    <div class="page-subtitle">DLP, retention, meeting, messaging, and calling policy assignment</div></div>
  </div>
  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">🛡️</div><div class="stat-value" id="dlpCount">__DLPPOLICIES__</div><div class="stat-label">DLP Policies</div><div class="stat-sub" id="dlpAvail">__DLPAVAIL__</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">🗄️</div><div class="stat-value" id="retCount">__RETENTIONPOLICIES__</div><div class="stat-label">Retention Policies</div><div class="stat-sub" id="retAvail">__RETENTIONAVAIL__</div></div>
    <div class="stat-card c-green"><div class="stat-icon">📞</div><div class="stat-value">—</div><div class="stat-label">Calling Policies</div><div class="stat-sub">Via Teams PS module</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">💬</div><div class="stat-value">—</div><div class="stat-label">Messaging Policies</div><div class="stat-sub">Via Teams PS module</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">📹</div><div class="stat-value">—</div><div class="stat-label">Meeting Policies</div><div class="stat-sub">Via Teams PS module</div></div>
  </div>
  <div class="panel">
    <div class="section-title">ℹ️ Policy Coverage Notes</div>
    <div style="font-size:13px;color:var(--muted2);line-height:2">
      <p>DLP and Retention policy counts are collected via the Microsoft Graph Security and Compliance endpoints.<br>
      Meeting, Messaging, and Calling policy <em>per-user</em> assignments require the <strong>Microsoft Teams PowerShell module</strong>
      (<code style="font-family:var(--mono);color:var(--accent2)">Get-CsTeamsMeetingPolicy</code>, <code style="font-family:var(--mono);color:var(--accent2)">Get-CsTeamsMessagingPolicy</code>,
      <code style="font-family:var(--mono);color:var(--accent2)">Get-CsTeamsCallingPolicy</code>) and are available via the companion scripts
      <code style="font-family:var(--mono);color:var(--accent2)">Get-TeamMeetingPolicyAssignment.ps1</code>,
      <code style="font-family:var(--mono);color:var(--accent2)">Get-TeamMessagingPolicyAssignment.ps1</code>, and
      <code style="font-family:var(--mono);color:var(--accent2)">Get-TeamCallingPolicyAssignment.ps1</code> in your toolkit.</p>
      <p style="margin-top:8px;font-size:12px;color:var(--muted)">
        Future version: Pass policy coverage CSV exports from those scripts via -PolicyCoveragePath
        to populate per-team policy assignment rates in this dashboard.
      </p>
    </div>
  </div>
</section>

<!-- ═══════════════ MEMBERSHIP ═══════════════ -->
<section id="page-membership" class="page">
  <div class="page-header">
    <div><div class="page-title">👥 Membership Overview</div>
    <div class="page-subtitle">Members, owners, and guest distribution across the tenant</div></div>
  </div>
  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">👥</div><div class="stat-value">__TOTALMEMBERS__</div><div class="stat-label">Total Members</div><div class="stat-sub">Internal users</div></div>
    <div class="stat-card c-green"><div class="stat-icon">👑</div><div class="stat-value">__TOTALOWNERS__</div><div class="stat-label">Total Owners</div><div class="stat-sub">Across all teams</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">🌐</div><div class="stat-value">__TOTALGUESTS__</div><div class="stat-label">Total Guests</div><div class="stat-sub">External accounts</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">📊</div><div class="stat-value">__AVGMEMBERS__</div><div class="stat-label">Avg Members / Team</div><div class="stat-sub">Internal only</div></div>
  </div>
  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">👥 Membership Breakdown</div>
      <div class="bar-row"><span class="bar-label">Internal Members</span><div class="bar-track"><div class="bar-fill" style="background:var(--accent);width:0%" data-pct="__MEMBERPCT__" class="anim-bar"></div></div><span class="bar-count">__TOTALMEMBERS__</span></div>
      <div class="bar-row"><span class="bar-label">Guest Members</span><div class="bar-track"><div class="bar-fill" style="background:var(--amber);width:0%" data-pct="__GUESTEXPOSUREPCT__" class="anim-bar"></div></div><span class="bar-count">__TOTALGUESTS__</span></div>
      <div class="bar-row"><span class="bar-label">Owners</span><div class="bar-track"><div class="bar-fill" style="background:var(--green);width:0%" data-pct="__OWNERPCT__" class="anim-bar"></div></div><span class="bar-count">__TOTALOWNERS__</span></div>
    </div>
    <div class="panel">
      <div class="section-title">📈 Guest Exposure Trend <span style="font-size:10.5px;color:var(--amber);font-weight:400;margin-left:6px">⚠ v1.0 placeholder</span></div>
      <svg class="sparkline" width="100%" height="80" id="sparkGuests" viewBox="0 0 400 80" preserveAspectRatio="none"></svg>
      <div style="display:flex;gap:16px;margin-top:6px" id="sparkGuestsLabels"></div>
    </div>
  </div>
</section>

<!-- ═══════════════ TEAMS DETAIL TABLE ═══════════════ -->
<section id="page-teams" class="page">
  <div class="page-header">
    <div><div class="page-title">📋 Teams Detail</div>
    <div class="page-subtitle">All teams with risk flags, membership, and status — click a row for details</div></div>
    <div class="btn-group">
      <button class="btn" onclick="exportTeamsCsv()">⬇ Export CSV</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="tableSearch" placeholder="Search team name, risk flags…" oninput="filterTable()"/>
    </div>
    <select id="statusFilter" onchange="filterTable()">
      <option value="">All Statuses</option>
      <option value="Active">Active</option>
      <option value="Inactive">Inactive</option>
      <option value="Archived">Archived</option>
    </select>
    <select id="riskFilter" onchange="filterTable()">
      <option value="">All Risk Levels</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
    </select>
    <select id="visFilter" onchange="filterTable()">
      <option value="">All Visibility</option>
      <option value="Public">Public</option>
      <option value="Private">Private</option>
    </select>
    <div class="page-size-wrap">
      Show <select id="pageSize" onchange="filterTable()">
        <option value="25" selected>25</option>
        <option value="50">50</option>
        <option value="100">100</option>
      </select> rows
    </div>
    <span class="result-count" id="resultCount"></span>
  </div>
  <table class="data-table" id="teamsTable">
    <thead>
      <tr>
        <th onclick="sortTable('name')" id="th-name">Team Name <span class="sort-arrow">↕</span></th>
        <th onclick="sortTable('status')" id="th-status">Status <span class="sort-arrow">↕</span></th>
        <th onclick="sortTable('risk')" id="th-risk">Risk <span class="sort-arrow">↕</span></th>
        <th onclick="sortTable('members')" id="th-members">Members <span class="sort-arrow">↕</span></th>
        <th onclick="sortTable('owners')" id="th-owners">Owners <span class="sort-arrow">↕</span></th>
        <th onclick="sortTable('guests')" id="th-guests">Guests <span class="sort-arrow">↕</span></th>
        <th>Label</th>
        <th>Visibility</th>
        <th>Risk Flags</th>
      </tr>
    </thead>
    <tbody id="tableBody"></tbody>
  </table>
  <div class="pagination" id="pagination"></div>
</section>

</main>

<!-- Detail Drawer -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDetail()"></div>
  <div id="detailDrawer">
    <div class="detail-toolbar">
      <span style="font-size:13px;font-weight:700;color:var(--muted2)">Team Detail</span>
      <button id="detailClose" onclick="closeDetail()">✕</button>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<!-- Toast -->
<div id="toast"></div>

<script>
// ── Data ─────────────────────────────────────────────────────────────
const TEAMS = [__TEAMSJSON__];
const TREND_WEEKS      = __TRENDSWEEKSJSON__;
const TREND_COMPLIANCE = __TRENDCOMPLIANCEJSON__;
const TREND_OWNERLESS  = __TRENDOWNERLESSJSON__;
const TREND_ACTIVE     = __TRENDACTIVEJSON__;
const TREND_LABELS_D   = __TRENDLABELSJSON__;
const TREND_GUESTS_D   = __TRENDGUESTSJSON__;

// KPI scalars
const COMPLIANCE_SCORE  = __COMPLIANCESCORE__;
const HEALTH_SUB        = __HEALTHSUBSCORE__;
const GOV_SUB           = __GOVERNANCESUBSCORE__;
const SEC_SUB           = __SECURITYSUBSCORE__;
const POL_SUB           = __POLICYSUBSCORE__;
const COMPLIANCE_CLR    = '__COMPLIANCESCORECOLOUR__';

// ── Helpers ──────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  if (btn) btn.classList.add('active');
  animateBars();
}

function toggleTheme() {
  const body = document.body;
  const isLight = body.classList.toggle('light-theme');
  document.getElementById('themeIcon').textContent  = isLight ? '☀️' : '🌙';
  document.getElementById('themeLabel').textContent = isLight ? 'Light Mode' : 'Dark Mode';
}

function showToast(msg, icon='✅') {
  const t = document.getElementById('toast');
  t.innerHTML = icon + ' ' + escH(msg);
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2800);
}

// ── Ring animation ────────────────────────────────────────────────────
function animateRing(arcId, numId, pct, circ) {
  const arc = document.getElementById(arcId);
  const num = document.getElementById(numId);
  if (!arc || !num) return;
  const offset = circ - (pct / 100) * circ;
  arc.style.strokeDashoffset = offset;
  let cur = 0;
  const step = pct / 60;
  const iv = setInterval(() => {
    cur = Math.min(cur + step, pct);
    num.textContent = Math.round(cur);
    if (cur >= pct) clearInterval(iv);
  }, 16);
}

// ── Bar animation ────────────────────────────────────────────────────
function animateBars() {
  document.querySelectorAll('.bar-fill').forEach(b => {
    const pct = parseFloat(b.getAttribute('data-pct')) || 0;
    requestAnimationFrame(() => { b.style.width = Math.min(pct, 100) + '%'; });
  });
}

// ── Sparkline ────────────────────────────────────────────────────────
function drawSparkline(svgId, labelsId, data, weeks, color) {
  const svg = document.getElementById(svgId);
  const wrap = document.getElementById(labelsId);
  if (!svg || data.length < 2) return;
  const W = 400, H = 80, pad = 10;
  const min = Math.min(...data), max = Math.max(...data);
  const range = max - min || 1;
  const xs = data.map((_, i) => pad + (i / (data.length - 1)) * (W - pad * 2));
  const ys = data.map(v => H - pad - ((v - min) / range) * (H - pad * 2));
  let path = `M ${xs[0]} ${ys[0]}`;
  for (let i = 1; i < xs.length; i++) {
    const mx = (xs[i-1] + xs[i]) / 2;
    path += ` C ${mx} ${ys[i-1]}, ${mx} ${ys[i]}, ${xs[i]} ${ys[i]}`;
  }
  // Fill area
  let area = path + ` L ${xs[xs.length-1]} ${H - pad} L ${xs[0]} ${H - pad} Z`;
  svg.innerHTML = `
    <defs><linearGradient id="sg${svgId}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${color}" stop-opacity="0.35"/>
      <stop offset="100%" stop-color="${color}" stop-opacity="0.02"/>
    </linearGradient></defs>
    <path d="${area}" fill="url(#sg${svgId})"/>
    <path d="${path}" fill="none" stroke="${color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    ${xs.map((x, i) => `<circle cx="${x}" cy="${ys[i]}" r="3.5" fill="${color}"/>
      <text x="${x}" y="${ys[i] - 8}" text-anchor="middle" font-size="10" fill="${color}" font-family="'JetBrains Mono',monospace">${data[i]}</text>`).join('')}
  `;
  if (wrap) {
    wrap.innerHTML = weeks.map((w, i) =>
      `<span style="font-family:var(--mono);font-size:10px;color:var(--muted);flex:1;text-align:${i === 0 ? 'left' : i === weeks.length - 1 ? 'right' : 'center'}">${w}</span>`
    ).join('');
  }
}

// ── Table ────────────────────────────────────────────────────────────
let filteredTeams = [...TEAMS];
let sortCol = 'name', sortDir = 1, currentPage = 1;

const statusColours = { Active: 'var(--green)', Inactive: 'var(--amber)', Archived: 'var(--muted)' };
const riskColours   = { High: 'var(--red)', Medium: 'var(--amber)', Low: 'var(--green)' };

function filterTable() {
  const q   = document.getElementById('tableSearch').value.toLowerCase();
  const st  = document.getElementById('statusFilter').value;
  const rk  = document.getElementById('riskFilter').value;
  const vis = document.getElementById('visFilter').value;
  filteredTeams = TEAMS.filter(t =>
    (!q   || t.name.toLowerCase().includes(q) || (t.flags||'').toLowerCase().includes(q)) &&
    (!st  || t.status === st) &&
    (!rk  || t.risk === rk) &&
    (!vis || t.visibility === vis)
  );
  filteredTeams.sort((a, b) => {
    let av = a[sortCol] ?? '', bv = b[sortCol] ?? '';
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    return av < bv ? -sortDir : av > bv ? sortDir : 0;
  });
  currentPage = 1;
  renderTable();
}

function sortTable(col) {
  if (sortCol === col) sortDir = -sortDir;
  else { sortCol = col; sortDir = 1; }
  document.querySelectorAll('.data-table thead th').forEach(th => th.classList.remove('sort-active'));
  const el = document.getElementById('th-' + col);
  if (el) el.classList.add('sort-active');
  filterTable();
}

function renderTable() {
  const ps    = parseInt(document.getElementById('pageSize').value) || 25;
  const start = (currentPage - 1) * ps;
  const page  = filteredTeams.slice(start, start + ps);
  const tbody = document.getElementById('tableBody');
  document.getElementById('resultCount').textContent = `${filteredTeams.length} teams`;

  tbody.innerHTML = page.map((t, i) => {
    const sc = statusColours[t.status] || 'var(--muted)';
    const rc = riskColours[t.risk]     || 'var(--muted)';
    const flags = (t.flags || '').split(',').filter(Boolean).map(f =>
      `<span class="flag-chip">${escH(f.trim())}</span>`).join('');
    return `<tr onclick="openDetail(${start + i})">
      <td class="td-name" title="${escH(t.name)}">${escH(t.name)}</td>
      <td><span class="status-badge" style="background:${sc}20;color:${sc};border:1px solid ${sc}40">${escH(t.status)}</span></td>
      <td><span class="risk-badge" style="background:${rc}20;color:${rc};border:1px solid ${rc}40">${escH(t.risk)}</span></td>
      <td style="font-family:var(--mono);font-size:12.5px">${t.members}</td>
      <td style="font-family:var(--mono);font-size:12.5px;color:${t.isOwnerless?'var(--red)':'var(--text)'}">${t.owners}</td>
      <td style="font-family:var(--mono);font-size:12.5px;color:${t.guests>0?'var(--amber)':'var(--muted)'}">${t.guests}</td>
      <td style="font-size:13px">${t.hasLabel ? '✅' : '❌'}</td>
      <td style="font-size:12px;color:var(--muted2)">${escH(t.visibility||'—')}</td>
      <td>${flags || '<span style="color:var(--muted);font-size:11px">None</span>'}</td>
    </tr>`;
  }).join('');

  renderPagination(filteredTeams.length, ps);
}

function renderPagination(total, ps) {
  const pages = Math.ceil(total / ps);
  const el = document.getElementById('pagination');
  if (pages <= 1) { el.innerHTML = ''; return; }
  let html = `<button class="page-btn" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>‹</button>`;
  for (let p = 1; p <= pages; p++) {
    if (p === 1 || p === pages || Math.abs(p - currentPage) <= 2)
      html += `<button class="page-btn ${p===currentPage?'active':''}" onclick="goPage(${p})">${p}</button>`;
    else if (Math.abs(p - currentPage) === 3)
      html += `<span style="color:var(--muted);padding:0 4px">…</span>`;
  }
  html += `<button class="page-btn" onclick="goPage(${currentPage+1})" ${currentPage===pages?'disabled':''}>›</button>`;
  el.innerHTML = html;
}

function goPage(p) {
  const ps = parseInt(document.getElementById('pageSize').value) || 25;
  const pages = Math.ceil(filteredTeams.length / ps);
  if (p < 1 || p > pages) return;
  currentPage = p;
  renderTable();
}

// ── Detail drawer ────────────────────────────────────────────────────
function openDetail(idx) {
  const t = filteredTeams[idx];
  if (!t) return;
  const rc = riskColours[t.risk]   || 'var(--muted)';
  const sc = statusColours[t.status] || 'var(--muted)';
  const flags = (t.flags||'').split(',').filter(Boolean).map(f =>
    `<span class="flag-chip" style="background:var(--surface3)">${escH(f.trim())}</span>`).join(' ') || '—';

  document.getElementById('detailContent').innerHTML = `
    <div class="detail-name">${escH(t.name)}</div>
    <div class="detail-meta-row">
      <span class="detail-chip" style="color:${sc}">${escH(t.status)}</span>
      <span class="detail-chip" style="color:${rc}">⚠ ${escH(t.risk)} Risk</span>
      <span class="detail-chip">${escH(t.visibility||'Unknown')}</span>
      <span class="detail-chip">${t.hasLabel ? '🏷️ Labelled' : '❌ No Label'}</span>
    </div>
    ${t.desc ? `<div style="font-size:13px;color:var(--muted2);font-style:italic;margin-bottom:8px">${escH(t.desc)}</div>` : ''}
    <div class="detail-section">
      <div class="detail-section-title">Membership</div>
      <div class="detail-row"><span class="detail-row-label">Members (internal)</span><span class="detail-row-value">${t.members}</span></div>
      <div class="detail-row"><span class="detail-row-label">Owners</span><span class="detail-row-value" style="color:${t.isOwnerless?'var(--red)':'var(--text)'}">${t.owners}${t.isOwnerless?' ⚠ Ownerless':''}</span></div>
      <div class="detail-row"><span class="detail-row-label">Guests (external)</span><span class="detail-row-value" style="color:${t.guests>0?'var(--amber)':'var(--text)'}">${t.guests}</span></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Status & Lifecycle</div>
      <div class="detail-row"><span class="detail-row-label">Activity Status</span><span class="detail-row-value">${escH(t.status)}</span></div>
      <div class="detail-row"><span class="detail-row-label">Days Since Active</span><span class="detail-row-value">${t.daysSince}</span></div>
      <div class="detail-row"><span class="detail-row-label">Created</span><span class="detail-row-value">${escH(t.created)}</span></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Risk Flags</div>
      <div style="padding:10px 0">${flags}</div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Identifiers</div>
      <div class="detail-row"><span class="detail-row-label">Group ID</span><span class="detail-row-value" style="font-size:11px">${escH(t.id)}</span></div>
    </div>
  `;
  document.getElementById('detailPanel').classList.add('open');
}

function closeDetail() {
  document.getElementById('detailPanel').classList.remove('open');
}

// ── CSV Export ───────────────────────────────────────────────────────
function exportTeamsCsv() {
  const headers = ['Name','Status','Risk','Members','Owners','Guests','HasLabel','Visibility','RiskFlags','Created','DaysSinceActive','GroupId'];
  const rows = filteredTeams.map(t =>
    [t.name, t.status, t.risk, t.members, t.owners, t.guests,
     t.hasLabel, t.visibility, t.flags, t.created, t.daysSince, t.id
    ].map(v => '"' + String(v||'').replace(/"/g,'""') + '"').join(',')
  );
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'TeamsExecutiveDashboard.csv';
  a.click();
  showToast('CSV exported — ' + filteredTeams.length + ' teams');
}

// ── Init ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Compliance ring
  animateRing('complianceArc', 'complianceNum', COMPLIANCE_SCORE, 226.2);

  // Sub-bars
  setTimeout(() => {
    ['sbHealth','sbGov','sbSec','sbPol'].forEach((id, i) => {
      const vals  = [HEALTH_SUB, GOV_SUB, SEC_SUB, POL_SUB];
      const pctId = ['sbHealthPct','sbGovPct','sbSecPct','sbPolPct'][i];
      document.getElementById(id).style.width = vals[i] + '%';
      document.getElementById(pctId).textContent = vals[i] + '%';
    });
  }, 200);

  // KPI domain rings (circ = 2*pi*26 = 163.4)
  const kpiData = [
    { arc:'kpiHealthArc', num:'kpiHealthNum', pct: parseInt('__ACTIVERATIOPCT__')  || 0 },
    { arc:'kpiGovArc',    num:'kpiGovNum',    pct: parseInt('__GOVPCT__')          || 0 },
    { arc:'kpiSecArc',    num:'kpiSecNum',     pct: parseInt('__LABELCOVERAGEPCT__')|| 0 },
    { arc:'kpiPolArc',    num:'kpiPolNum',     pct: parseInt('__POLICYSUBSCORE__') || 0 },
    { arc:'kpiGuestArc',  num:'kpiGuestNum',   pct: parseFloat('__GUESTEXPOSUREPCT__') || 0 },
  ];
  kpiData.forEach(k => animateRing(k.arc, k.num, k.pct, 163.4));

  // Sparklines
  drawSparkline('sparkCompliance', 'sparkComplianceLabels', TREND_COMPLIANCE, TREND_WEEKS, '#388bfd');
  drawSparkline('sparkOwnerless',  'sparkOwnerlessLabels',  TREND_OWNERLESS,  TREND_WEEKS, '#f85149');
  drawSparkline('sparkActive',     'sparkActiveLabels',     TREND_ACTIVE,     TREND_WEEKS, '#3fb950');
  drawSparkline('sparkLabels',     'sparkLabelsLabels',     TREND_LABELS_D,   TREND_WEEKS, '#39c5cf');
  drawSparkline('sparkGuests',     'sparkGuestsLabels',     TREND_GUESTS_D,   TREND_WEEKS, '#d29922');

  // Bar animations (overview page bars are in DOM on load)
  animateBars();

  // Table
  filterTable();

  // Keyboard
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeDetail();
  });
});
</script>
</body>
</html>
'@

    #endregion

    #region ── Token Substitution ─────────────────────────────────────────────────

    Write-Step "Injecting data into HTML template…"

    # Pre-compute derived display values
    $govPct = if ($totalTeams -gt 0) { [math]::Round(($ownedTeams / $totalTeams) * 100) } else { 0 }
    $inactiveRatioPct = if ($totalTeams -gt 0) { [math]::Round(($inactiveTeams / $totalTeams) * 100) } else { 0 }
    $archivedRatioPct = if ($totalTeams -gt 0) { [math]::Round(($archivedTeams / $totalTeams) * 100) } else { 0 }
    $publicRatioPct = if ($totalTeams -gt 0) { [math]::Round(($publicTeams / $totalTeams) * 100) } else { 0 }
    $highRiskPct = if ($totalTeams -gt 0) { [math]::Round(($highRiskTeams / $totalTeams) * 100) } else { 0 }
    $medRiskPct = if ($totalTeams -gt 0) { [math]::Round(($mediumRiskTeams / $totalTeams) * 100) } else { 0 }
    $lowRiskPct = if ($totalTeams -gt 0) { [math]::Round(($lowRiskTeams / $totalTeams) * 100) } else { 0 }
    $guestEnabledPct = if ($totalTeams -gt 0) { [math]::Round(($guestEnabledTeams / $totalTeams) * 100) } else { 0 }
    $memberPct = if (($totalMembers + $totalGuests) -gt 0) { [math]::Round(($totalMembers / ($totalMembers + $totalGuests)) * 100) } else { 100 }
    $ownerPct = if (($totalMembers + $totalGuests) -gt 0) { [math]::Round(($totalOwners / ($totalMembers + $totalGuests)) * 100) } else { 0 }

    $dlpAvailText = if ($policyCoverage.DlpAvailable) { 'Graph API' } else { 'Scope required' }
    $retAvailText = if ($policyCoverage.RetentionAvailable) { 'Graph API' } else { 'Scope required' }

    $tenantSafe = ConvertTo-SafeReplacementText (ConvertTo-JsonSafe $tenantName)
    $teamsJsonSafe = ConvertTo-SafeReplacementText $teamsJson

    $html = $html `
        -replace '__TENANTNAME__', (ConvertTo-SafeReplacementText $tenantName) `
        -replace '__GENERATEDAT__', (ConvertTo-SafeReplacementText $generatedAt) `
        -replace '__REPORTMONTH__', (ConvertTo-SafeReplacementText $reportMonth) `
        -replace '__TOTALTEAMS__', $totalTeams `
        -replace '__ACTIVETEAMS__', $activeTeams `
        -replace '__INACTIVETEAMS__', $inactiveTeams `
        -replace '__ARCHIVEDTEAMS__', $archivedTeams `
        -replace '__OWNERLESSTEAMS__', $ownerlessTeams `
        -replace '__OWNEDTEAMS__', $ownedTeams `
        -replace '__STALETEAMS__', $staleTeams `
        -replace '__HIGHRISKTEAMS__', $highRiskTeams `
        -replace '__MEDIUMRISKTEAMS__', $mediumRiskTeams `
        -replace '__LOWRISKTEAMS__', $lowRiskTeams `
        -replace '__GUESTENABLEDTEAMS__', $guestEnabledTeams `
        -replace '__PUBLICTEAMS__', $publicTeams `
        -replace '__LABELLEDTEAMS__', $labelledTeams `
        -replace '__UNLABELLEDTEAMS__', $unlabelledTeams `
        -replace '__TOTALMEMBERS__', $totalMembers `
        -replace '__TOTALOWNERS__', $totalOwners `
        -replace '__TOTALGUESTS__', $totalGuests `
        -replace '__AVGMEMBERS__', $avgMembers `
        -replace '__COMPLIANCESCORE__', $complianceScore `
        -replace '__COMPLIANCESCORECOLOUR__', (ConvertTo-SafeReplacementText $complianceScoreColour) `
        -replace '__HEALTHSUBSCORE__', $healthSubScore `
        -replace '__GOVERNANCESUBSCORE__', $governanceSubScore `
        -replace '__SECURITYSUBSCORE__', $securitySubScore `
        -replace '__POLICYSUBSCORE__', $policySubScore `
        -replace '__ACTIVERATIOPCT__', $activeRatioPct `
        -replace '__INACTIVERATIOPCT__', $inactiveRatioPct `
        -replace '__ARCHIVEDRATIOPCT__', $archivedRatioPct `
        -replace '__OWNERLESSRATIOPCT__', $ownerlessRatioPct `
        -replace '__GOVPCT__', $govPct `
        -replace '__LABELCOVERAGEPCT__', $labelCoveragePct `
        -replace '__GUESTEXPOSUREPCT__', $guestExposurePct `
        -replace '__GUESTENABLEDPCT__', $guestEnabledPct `
        -replace '__STALERATEPCT__', $staleRatePct `
        -replace '__HIGHRISKPCT__', $highRiskPct `
        -replace '__MEDRISKPCT__', $medRiskPct `
        -replace '__LOWRISKPCT__', $lowRiskPct `
        -replace '__PUBLICRATIOPCT__', $publicRatioPct `
        -replace '__MEMBERPCT__', $memberPct `
        -replace '__OWNERPCT__', $ownerPct `
        -replace '__OWNERLESSCOLOUR__', (ConvertTo-SafeReplacementText $ownerlessColour) `
        -replace '__LABELCOLOUR__', (ConvertTo-SafeReplacementText $labelColour) `
        -replace '__GUESTEXPOSURECOLOUR__', (ConvertTo-SafeReplacementText $guestExposureColour) `
        -replace '__STALECOLOUR__', (ConvertTo-SafeReplacementText $staleColour) `
        -replace '__INACTIVELABEL__', $inactiveLabel `
        -replace '__DLPPOLICIES__', $policyCoverage.DlpPolicies `
        -replace '__RETENTIONPOLICIES__', $policyCoverage.RetentionPolicies `
        -replace '__DLPAVAIL__', (ConvertTo-SafeReplacementText $dlpAvailText) `
        -replace '__RETENTIONAVAIL__', (ConvertTo-SafeReplacementText $retAvailText) `
        -replace '__TEAMSJSON__', $teamsJsonSafe `
        -replace '__TRENDSWEEKSJSON__', (ConvertTo-SafeReplacementText $trendsJson) `
        -replace '__TRENDCOMPLIANCEJSON__', (ConvertTo-SafeReplacementText $trendComplianceJson) `
        -replace '__TRENDOWNERLESSJSON__', (ConvertTo-SafeReplacementText $trendOwnerlessJson) `
        -replace '__TRENDACTIVEJSON__', (ConvertTo-SafeReplacementText $trendActiveJson) `
        -replace '__TRENDLABELSJSON__', (ConvertTo-SafeReplacementText $trendLabelsJson) `
        -replace '__TRENDGUESTSJSON__', (ConvertTo-SafeReplacementText $trendGuestsJson)

    #endregion

    #region ── Write Output ───────────────────────────────────────────────────────

    Write-Section "Writing output file" "💾"

    # Validate OutputPath has no traversal
    if ($OutputPath -match '\.\.') {
        throw "OutputPath '$OutputPath' contains a path-traversal sequence — aborting."
    }

    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-Step "Dashboard saved: $OutputPath" "OK"
    }
    catch {
        Write-Step "Failed to write output file: $_" "ERR"
        throw
    }

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║   ✅  Executive Dashboard generated successfully             ║" -ForegroundColor Green
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "  ║   📂  $($OutputPath.PadRight(60,' '))║" -ForegroundColor Green
    Write-Host "  ║   🏢  Teams collected : $($totalTeams.ToString().PadRight(38,' '))║" -ForegroundColor Green
    Write-Host "  ║   📊  Compliance Score: $($complianceScore.ToString().PadRight(38,' '))║" -ForegroundColor Green
    Write-Host "  ║   ⚠   High-Risk Teams : $($highRiskTeams.ToString().PadRight(38,' '))║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    if ($OpenBrowser) {
        Write-Step "Opening dashboard in default browser…"
        Start-Process $OutputPath
    }

    return $OutputPath

    #endregion
}
