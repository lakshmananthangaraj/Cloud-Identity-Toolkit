<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 02 August 2026
Modified-On  : 02 August 2026

.SYNOPSIS
    Generates an HTML Teams Governance Dashboard highlighting ownerless,
    inactive, and non-compliant teams.

.DESCRIPTION
    Accepts either a live -AccessToken (queries Graph API directly) or
    pre-collected PSCustomObject arrays from the governance scripts in the
    Cloud Identity Toolkit suite.

    Produces a single self-contained HTML file styled with the golden
    dashboard theme (dark/light toggle, stat cards, sortable tables, detail
    drawer, CSV export, keyboard shortcuts).

    Tabs:
        Overview          — governance health score ring, stat cards
                            (ownerless, under-owned, inactive, non-compliant,
                            public teams), risk distribution bar chart, most
                            critical findings list
        Ownerless Teams   — searchable/sortable table of 0-owner (Critical)
                            and 1-owner (Warning) teams
        Compliance        — searchable/sortable table of all rule violations
                            from Test-TeamGovernanceCompliance with per-team
                            rollup columns (rulesEvaluated, compliancePercentage)
        Inactive Teams    — searchable/sortable table of teams exceeding the
                            inactivity threshold (Never Active / Inactive)
        Lifecycle         — searchable/sortable full lifecycle report

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions: Group.Read.All, Reports.Read.All.
    When supplied, live data is collected for any collection not piped in.

.PARAMETER OwnerlessTeams
    Pre-collected output of Get-TeamOwnerlessTeams.

.PARAMETER ComplianceFindings
    Pre-collected output of Test-TeamGovernanceCompliance.

.PARAMETER InactiveTeams
    Pre-collected output of Get-TeamInactive.

.PARAMETER LifecycleReport
    Pre-collected output of Get-TeamLifecycleReport.

.PARAMETER OutputPath
    Full file path for the generated HTML file.
    Default: "$env:TEMP\TeamGovernanceDashboard.html"

.PARAMETER OpenBrowser
    If specified, opens the generated HTML in the default browser.

.INPUTS
    PSCustomObject arrays from the governance scripts in this suite.

.OUTPUTS
    A self-contained HTML file at -OutputPath.

.EXAMPLE
    Generate-TeamGovernanceDashboard -AccessToken $token -OpenBrowser

    Pulls live data and opens the governance dashboard.

.EXAMPLE
    $ownerless  = Get-TeamOwnerlessTeams -AccessToken $token
    $compliance = Test-TeamGovernanceCompliance -AccessToken $token
    Generate-TeamGovernanceDashboard -OwnerlessTeams $ownerless -ComplianceFindings $compliance -OutputPath "C:\Reports\Governance.html"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (02-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. PowerShell 5.1 or later
        2. When using -AccessToken: Group.Read.All, Reports.Read.All
        3. When using pre-collected data: run the relevant governance scripts
            from the Cloud Identity Toolkit first

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Live-pull path for InactiveTeams and LifecycleReport requires
            Reports.Read.All which may be absent from existing app registrations.
        - Governance health score is calculated from compliance findings only;
            teams for which compliance data was not collected show as unknown.
        - The script does not authenticate; -AccessToken must be provided by
            the caller (e.g. via Connect-EntraID.ps1).

.LINK
    Cloud Identity Toolkit
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit

#>


Function Generate-TeamGovernanceDashboard {
    [CmdletBinding()]
    param (
        [string]$AccessToken,
        [object[]]$OwnerlessTeams,
        [object[]]$ComplianceFindings,
        [object[]]$InactiveTeams,
        [object[]]$LifecycleReport,

        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^(?!.*\.\.)[^<>:"|?*]+$')]
        [string]$OutputPath = "$env:TEMP\TeamGovernanceDashboard.html",

        [switch]$OpenBrowser
    )

    #region ── Helpers ────────────────────────────────────────────────────────────

    function ConvertTo-JsonSafe {
        param([string]$Text)
        $Text `
            -replace '\\', '\\\\' `
            -replace '"', '\"'   `
            -replace "`r`n", '\n'   `
            -replace "`n", '\n'   `
            -replace "`r", '\n'   `
            -replace "`t", '\t'   `
            -replace '<', '\u003c' `
            -replace '>', '\u003e' `
            -replace '\$', '\u0024'
    }

    function Invoke-GraphPagedRequest {
        param([string]$Uri, [hashtable]$Headers)
        $results = [System.Collections.ArrayList]::new()
        $next = $Uri
        do {
            $skip = $false
            do {
                Try {
                    $r = Invoke-WebRequest -Uri $next -Headers $Headers -Method Get -ErrorAction Stop
                    $status = $r.StatusCode
                }
                Catch {
                    $status = $_.Exception.Response.StatusCode
                    if ($status -eq 429) {
                        $sleep = $_.Exception.Response.Headers.Item("Retry-After")
                        Write-Host "Throttled — waiting $sleep s" -ForegroundColor Cyan
                        Start-Sleep -Seconds $sleep
                    }
                    else { Write-Warning "Graph error: $($_.Exception.Message)"; $skip = $true }
                }
            } until (($status -eq 200) -or $skip)
            if ($skip) { break }
            $page = ($r.Content | ConvertFrom-Json)
            @($page.value) | ForEach-Object { $null = $results.Add($_) }
            $next = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
        } until (-not $next)
        return $results
    }

    #endregion

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║      Teams Governance Dashboard  v1.0                ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $headers = @{ "Authorization" = "Bearer $AccessToken"; "ConsistencyLevel" = "eventual" }

    #region ── Data Collection ────────────────────────────────────────────────────

    # Ownerless / under-owned teams
    if ($OwnerlessTeams -and @($OwnerlessTeams).Count -gt 0) {
        $allOwnerless = @($OwnerlessTeams)
        Write-Host "  ✅  Using $(@($allOwnerless).Count) ownerless/under-owned record(s) from pipeline." -ForegroundColor Green
    }
    elseif ($AccessToken) {
        Write-Host "  🔍  Evaluating team ownership from Graph..." -ForegroundColor Cyan
        $allOwnerless = [System.Collections.ArrayList]::new()
        $teams = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName,description,visibility&`$count=true" -Headers $headers
        foreach ($t in $teams) {
            Try {
                $owners = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($t.id)/owners?`$select=id&`$top=100" -Headers $headers
                $oc = @($owners).Count
                if ($oc -le 1) {
                    $null = $allOwnerless.Add([PSCustomObject]@{
                            teamId          = $t.id
                            teamDisplayName = $t.displayName
                            ownerCount      = $oc
                            riskLevel       = if ($oc -eq 0) { 'Critical' } else { 'Warning' }
                            recommendation  = if ($oc -eq 0) { 'Assign at least one owner immediately.' } else { 'Assign a second owner — single point of failure.' }
                        })
                }
            }
            Catch { Write-Warning "Owner check failed for $($t.id): $($_.Exception.Message)" }
        }
        Write-Host "  ✅  Found $($allOwnerless.Count) at-risk team(s)." -ForegroundColor Green
    }
    else { $allOwnerless = @() }

    # Compliance findings
    if ($ComplianceFindings -and @($ComplianceFindings).Count -gt 0) {
        $allCompliance = @($ComplianceFindings)
        Write-Host "  ✅  Using $(@($allCompliance).Count) compliance finding(s) from pipeline." -ForegroundColor Green
    }
    elseif ($AccessToken) {
        Write-Host "  🔍  Running compliance checks from Graph..." -ForegroundColor Cyan
        $allCompliance = [System.Collections.ArrayList]::new()
        if (-not $teams) { $teams = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName,description,visibility&`$count=true" -Headers $headers }
        foreach ($t in $teams) {
            Try {
                $owners = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($t.id)/owners?`$select=id&`$top=100" -Headers $headers
                $oc = @($owners).Count
                $ruleResults = @()
                if ($oc -eq 0) { $ruleResults += [PSCustomObject]@{ RuleId = 'GOV-001'; RuleName = 'Ownership'; Severity = 'Critical'; Passed = $false; Details = '0 owners — unmanaged.' } }
                elseif ($oc -eq 1) { $ruleResults += [PSCustomObject]@{ RuleId = 'GOV-001'; RuleName = 'Ownership'; Severity = 'Warning'; Passed = $false; Details = '1 owner — single point of failure.' } }
                else { $ruleResults += [PSCustomObject]@{ RuleId = 'GOV-001'; RuleName = 'Ownership'; Severity = 'Pass'; Passed = $true; Details = "$oc owners." } }
                if ($t.visibility -eq 'Public') { $ruleResults += [PSCustomObject]@{ RuleId = 'GOV-002'; RuleName = 'Visibility'; Severity = 'Warning'; Passed = $false; Details = 'Team is Public.' } }
                else { $ruleResults += [PSCustomObject]@{ RuleId = 'GOV-002'; RuleName = 'Visibility'; Severity = 'Pass'; Passed = $true; Details = "Visibility: $($t.visibility)." } }
                if ([string]::IsNullOrWhiteSpace($t.description)) { $ruleResults += [PSCustomObject]@{ RuleId = 'GOV-003'; RuleName = 'Description'; Severity = 'Warning'; Passed = $false; Details = 'Missing description.' } }
                else { $ruleResults += [PSCustomObject]@{ RuleId = 'GOV-003'; RuleName = 'Description'; Severity = 'Pass'; Passed = $true; Details = 'Has description.' } }
                $scored = @($ruleResults | Where-Object { $null -ne $_.Passed })
                $failed = @($scored | Where-Object { $_.Passed -eq $false }).Count
                $pct = if ($scored.Count -gt 0) { [Math]::Round((($scored.Count - $failed) / $scored.Count) * 100, 1) } else { 100 }
                $violations = @($ruleResults | Where-Object { $_.Passed -eq $false })
                if ($violations.Count -eq 0) {
                    $null = $allCompliance.Add([PSCustomObject]@{ teamId = $t.id; teamDisplayName = $t.displayName; ruleId = 'N/A'; ruleName = 'N/A'; severity = 'Info'; status = 'Compliant'; details = 'All rules passed.'; ownerCount = $oc; visibility = $t.visibility; rulesEvaluated = $scored.Count; rulesFailed = 0; compliancePercentage = 100 })
                }
                else {
                    foreach ($v in $violations) {
                        $null = $allCompliance.Add([PSCustomObject]@{ teamId = $t.id; teamDisplayName = $t.displayName; ruleId = $v.RuleId; ruleName = $v.RuleName; severity = $v.Severity; status = 'NonCompliant'; details = $v.Details; ownerCount = $oc; visibility = $t.visibility; rulesEvaluated = $scored.Count; rulesFailed = $failed; compliancePercentage = $pct })
                    }
                }
            }
            Catch { Write-Warning "Compliance check failed for $($t.id): $($_.Exception.Message)" }
        }
        Write-Host "  ✅  Generated $($allCompliance.Count) compliance finding(s)." -ForegroundColor Green
    }
    else { $allCompliance = @() }

    # Inactive teams
    if ($InactiveTeams -and @($InactiveTeams).Count -gt 0) {
        $allInactive = @($InactiveTeams)
        Write-Host "  ✅  Using $(@($allInactive).Count) inactive team(s) from pipeline." -ForegroundColor Green
    }
    elseif ($AccessToken) {
        Write-Host "  🔍  Fetching activity report from Graph..." -ForegroundColor Cyan
        $allInactive = [System.Collections.ArrayList]::new()
        $teamNameMap = @{}
        if ($teams) { $teams | ForEach-Object { $teamNameMap[$_.id] = $_.displayName } }
        Try {
            $skip = $false
            do {
                Try {
                    $rpt = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0/reports/getTeamsTeamActivityDetail(period='D90')" -Headers $headers -Method Get -ErrorAction Stop
                    $status = $rpt.StatusCode
                }
                Catch {
                    $status = $_.Exception.Response.StatusCode
                    if ($status -eq 429) { $sleep = $_.Exception.Response.Headers.Item("Retry-After"); Start-Sleep -Seconds $sleep }
                    else { Write-Warning "Activity report failed: $($_.Exception.Message)"; $skip = $true }
                }
            } until (($status -eq 200) -or $skip)
            if (-not $skip) {
                $csvRows = $rpt.Content | ConvertFrom-Csv
                foreach ($row in $csvRows) {
                    $tidProp = $row.PSObject.Properties['Team Id']
                    if (-not ($tidProp -and $tidProp.Value)) { continue }
                    $tid = $tidProp.Value
                    $laProp = $row.PSObject.Properties['Last Activity Date']
                    $la = if ($laProp) { $laProp.Value } else { '' }
                    $tname = if ($teamNameMap.ContainsKey($tid)) { $teamNameMap[$tid] } else { $row.PSObject.Properties['Team Name']?.Value }
                    if ([string]::IsNullOrWhiteSpace($la)) {
                        $null = $allInactive.Add([PSCustomObject]@{ teamId = $tid; teamDisplayName = $tname; lastActivityDate = 'Never'; daysSinceActivity = $null; status = 'Never Active' })
                    }
                    else {
                        $parsed = [datetime]::MinValue
                        if ([datetime]::TryParse($la, [ref]$parsed)) {
                            $days = ((Get-Date) - $parsed).Days
                            if ($days -ge 90) { $null = $allInactive.Add([PSCustomObject]@{ teamId = $tid; teamDisplayName = $tname; lastActivityDate = $parsed.ToString('yyyy-MM-dd'); daysSinceActivity = $days; status = 'Inactive' }) }
                        }
                    }
                }
            }
        }
        Catch { Write-Warning "Activity report processing failed: $($_.Exception.Message)" }
        Write-Host "  ✅  Found $($allInactive.Count) inactive team(s)." -ForegroundColor Green
    }
    else { $allInactive = @() }

    # Lifecycle report (optional — no live-pull here to avoid duplicate Graph calls)
    if ($LifecycleReport -and @($LifecycleReport).Count -gt 0) {
        $allLifecycle = @($LifecycleReport)
        Write-Host "  ✅  Using $(@($allLifecycle).Count) lifecycle record(s) from pipeline." -ForegroundColor Green
    }
    else { $allLifecycle = @() }

    #endregion

    #region ── Compute Governance Metrics ─────────────────────────────────────────

    $criticalCount = @($allOwnerless | Where-Object { $_.riskLevel -eq 'Critical' }).Count
    $warningCount = @($allOwnerless | Where-Object { $_.riskLevel -eq 'Warning' }).Count
    $inactiveCount = @($allInactive).Count
    $nonCompliantTeams = @($allCompliance | Where-Object { $_.status -eq 'NonCompliant' } | Select-Object -ExpandProperty teamId -Unique).Count
    $compliantTeams = @($allCompliance | Where-Object { $_.status -eq 'Compliant' } | Select-Object -ExpandProperty teamId -Unique).Count
    $publicCount = @($allCompliance | Where-Object { $_.ruleName -eq 'Visibility' -and $_.status -eq 'NonCompliant' } | Select-Object -ExpandProperty teamId -Unique).Count
    $totalUniqueTeams = @($allCompliance | Select-Object -ExpandProperty teamId -Unique).Count
    $govHealthScore = if ($totalUniqueTeams -gt 0) { [Math]::Round(($compliantTeams / $totalUniqueTeams) * 100, 0) } else { 0 }
    $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')

    #endregion

    #region ── JSON Data Blobs ────────────────────────────────────────────────────

    $ownerlessJson = (@($allOwnerless) | ForEach-Object {
            $n = ConvertTo-JsonSafe "$($_.teamDisplayName)"
            $r = ConvertTo-JsonSafe "$($_.riskLevel)"
            $c = ConvertTo-JsonSafe "$($_.recommendation)"
            $i = ConvertTo-JsonSafe "$($_.teamId)"
            $o = if ($null -ne $_.ownerCount) { $_.ownerCount } else { 0 }
            "{`"id`":`"$i`",`"name`":`"$n`",`"ownerCount`":$o,`"risk`":`"$r`",`"recommendation`":`"$c`"}"
        }) -join ','

    $complianceJson = (@($allCompliance) | ForEach-Object {
            $n = ConvertTo-JsonSafe "$($_.teamDisplayName)"
            $ri = ConvertTo-JsonSafe "$($_.ruleId)"
            $rn = ConvertTo-JsonSafe "$($_.ruleName)"
            $sv = ConvertTo-JsonSafe "$($_.severity)"
            $st = ConvertTo-JsonSafe "$($_.status)"
            $dt = ConvertTo-JsonSafe "$($_.details)"
            $ti = ConvertTo-JsonSafe "$($_.teamId)"
            $oc = if ($null -ne $_.ownerCount) { $_.ownerCount } else { 0 }
            $re = if ($null -ne $_.rulesEvaluated) { $_.rulesEvaluated } else { 0 }
            $rf = if ($null -ne $_.rulesFailed) { $_.rulesFailed } else { 0 }
            $cp = if ($null -ne $_.compliancePercentage) { $_.compliancePercentage } else { 0 }
            "{`"teamId`":`"$ti`",`"teamName`":`"$n`",`"ruleId`":`"$ri`",`"ruleName`":`"$rn`",`"severity`":`"$sv`",`"status`":`"$st`",`"details`":`"$dt`",`"ownerCount`":$oc,`"rulesEvaluated`":$re,`"rulesFailed`":$rf,`"compliancePct`":$cp}"
        }) -join ','

    $inactiveJson = (@($allInactive) | ForEach-Object {
            $n = ConvertTo-JsonSafe "$($_.teamDisplayName)"
            $la = ConvertTo-JsonSafe "$($_.lastActivityDate)"
            $st = ConvertTo-JsonSafe "$($_.status)"
            $ti = ConvertTo-JsonSafe "$($_.teamId)"
            $ds = if ($null -ne $_.daysSinceActivity) { $_.daysSinceActivity } else { 0 }
            "{`"teamId`":`"$ti`",`"name`":`"$n`",`"lastActivity`":`"$la`",`"daysSince`":$ds,`"status`":`"$st`"}"
        }) -join ','

    $lifecycleJson = (@($allLifecycle) | ForEach-Object {
            $n = ConvertTo-JsonSafe "$($_.teamDisplayName)"
            $v = ConvertTo-JsonSafe "$($_.visibility)"
            $ls = ConvertTo-JsonSafe "$($_.lifecycleStage)"
            $la = ConvertTo-JsonSafe "$($_.lastActivityDate)"
            $ti = ConvertTo-JsonSafe "$($_.teamId)"
            $oc = if ($null -ne $_.ownerCount) { $_.ownerCount }    else { 0 }
            $mc = if ($null -ne $_.memberCount) { $_.memberCount }   else { 0 }
            $gc = if ($null -ne $_.guestCount) { $_.guestCount }    else { 0 }
            $ag = if ($null -ne $_.ageInDays) { $_.ageInDays }     else { 0 }
            "{`"teamId`":`"$ti`",`"name`":`"$n`",`"visibility`":`"$v`",`"ageInDays`":$ag,`"ownerCount`":$oc,`"memberCount`":$mc,`"guestCount`":$gc,`"lastActivity`":`"$la`",`"lifecycleStage`":`"$ls`"}"
        }) -join ','

    #endregion

    #region ── HTML ───────────────────────────────────────────────────────────────

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Teams Governance Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;--border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;--green:#3fb950;--amber:#d29922;--red:#f85149;--text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;--mono:'JetBrains Mono','Consolas','Courier New',monospace;--sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;--radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5)}
body.light-theme{--bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;--border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;--green:#1a7f37;--amber:#b08000;--red:#cf222e;--text:#1f2328;--muted:#636c76;--muted2:#424a53;--shadow:0 4px 24px rgba(0,0,0,.12)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}
#sidebar{position:fixed;top:0;left:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--amber),var(--red));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text)}
.sidebar-logo p{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px}
.version-badge{display:inline-block;margin-top:5px;background:rgba(210,153,34,.15);color:var(--amber);font-family:var(--mono);font-size:10px;padding:1px 8px;border-radius:20px;border:1px solid rgba(210,153,34,.3)}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13.5px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.nav-btn .nav-badge{margin-left:auto;background:var(--surface3);color:var(--muted2);font-family:var(--mono);font-size:11px;padding:1px 7px;border-radius:20px}
.nav-btn:hover{color:var(--text);background:var(--surface2)}
.nav-btn.active{color:var(--amber);background:rgba(210,153,34,.1)}
.nav-btn.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--amber);border-radius:0 2px 2px 0}
.theme-toggle-wrap{padding:10px 14px;border-top:1px solid var(--border)}
.theme-toggle{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;transition:all .2s}
.theme-toggle:hover{border-color:var(--amber);color:var(--text)}
.toggle-pill{width:34px;height:18px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--muted2);transition:transform .2s,background .2s}
body.light-theme .toggle-pill{background:var(--amber)}
body.light-theme .toggle-pill::after{transform:translateX(16px);background:#fff}
.sidebar-footer{padding:10px 18px 12px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);font-family:var(--mono);line-height:1.6}
kbd{display:inline-block;padding:1px 5px;background:var(--surface3);border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:11px;color:var(--muted)}
#main{margin-left:236px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:24px;font-weight:700}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--amber);color:var(--amber);background:rgba(210,153,34,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:25px;font-weight:700;line-height:1}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-card.c-red{border-top:2px solid var(--red)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.health-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;display:flex;align-items:center;gap:18px;margin-bottom:22px;flex-wrap:wrap}
.health-ring-wrap{position:relative;width:76px;height:76px;flex-shrink:0}
.health-ring-wrap svg{width:76px;height:76px}
.health-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.health-score-num{font-family:var(--mono);font-size:19px;font-weight:700;line-height:1}
.health-score-pct{font-size:9px;color:var(--muted)}
.health-info{flex:1;min-width:200px}
.health-info h3{font-size:14px;font-weight:700;margin-bottom:4px}
.health-info p{font-size:12px;color:var(--muted2)}
.health-bar-row{display:flex;align-items:center;gap:8px;margin-top:8px;font-size:12px}
.health-mini-bar{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.health-mini-fill{height:100%;border-radius:3px;transition:width 1s ease}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-size:12.5px;color:var(--muted2);width:110px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:10px;background:var(--surface3);border-radius:5px;overflow:hidden}
.bar-fill{height:100%;border-radius:5px;transition:width .9s ease}
.bar-val{font-family:var(--mono);font-size:11px;color:var(--muted);width:30px;text-align:right;flex-shrink:0}
.finding-row{display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)}
.finding-row:last-child{border-bottom:none}
.finding-severity{font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;flex-shrink:0;margin-top:2px}
.sev-critical{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.sev-warning{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3)}
.sev-pass{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.sev-info{background:rgba(57,197,207,.12);color:var(--accent2);border:1px solid rgba(57,197,207,.3)}
.finding-name{font-family:var(--mono);font-size:12.5px;color:var(--accent2);flex:1}
.finding-detail{font-size:12px;color:var(--muted2);margin-top:2px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;padding:8px 11px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--amber)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:13px;flex-shrink:0}
.data-table{width:100%;border-collapse:collapse}
.data-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.data-table thead th:hover{color:var(--text)}
.data-table thead th.sort-active{color:var(--amber)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.data-table tbody tr{border-bottom:1px solid var(--border);transition:background .15s}
.data-table tbody tr:hover{background:var(--surface2)}
.data-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13.5px}
.td-mono{font-family:var(--mono);font-size:12.5px;color:var(--accent2);font-weight:600}
.td-muted{color:var(--muted2)}
.td-small{color:var(--muted);font-family:var(--mono);font-size:12px;white-space:nowrap}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:14px}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--amber);color:var(--amber)}
.page-btn.active{background:var(--amber);border-color:var(--amber);color:#000}
.page-btn:disabled{opacity:.35;cursor:default}
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
@media(max-width:768px){#sidebar{transform:translateX(-236px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">🏛</div>
    <h1>Teams Governance</h1>
    <p>Cloud Identity Toolkit</p>
    <span class="version-badge">v1.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span>Overview</button>
    <button class="nav-btn" onclick="showPage('ownerless',this)"><span class="nav-icon">⚠</span>Ownerless<span class="nav-badge">__OWNERLESS_COUNT__</span></button>
    <button class="nav-btn" onclick="showPage('compliance',this)"><span class="nav-icon">📋</span>Compliance<span class="nav-badge">__COMPLIANCE_COUNT__</span></button>
    <button class="nav-btn" onclick="showPage('inactive',this)"><span class="nav-icon">💤</span>Inactive<span class="nav-badge">__INACTIVE_COUNT__</span></button>
    <button class="nav-btn" onclick="showPage('lifecycle',this)"><span class="nav-icon">🔄</span>Lifecycle<span class="nav-badge">__LIFECYCLE_COUNT__</span></button>
  </div>
  <div class="theme-toggle-wrap">
    <button class="theme-toggle" onclick="toggleTheme()"><span id="themeIcon">🌙</span><span id="themeLabel" style="flex:1;text-align:left">Dark Mode</span><span class="toggle-pill"></span></button>
  </div>
  <div class="sidebar-footer">Generated<br>__GENERATEDAT__<br><span style="color:var(--accent2)">⌨</span> <kbd>/</kbd> search &nbsp;<kbd>Esc</kbd> close</div>
</nav>

<main id="main">

<!-- OVERVIEW -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div><div class="page-title">Governance Overview</div><div class="page-subtitle">Ownerless, inactive and non-compliant Teams at a glance</div></div>
  </div>

  <div class="health-card">
    <div class="health-ring-wrap">
      <svg viewBox="0 0 76 76">
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--surface3)" stroke-width="9"/>
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--green)" stroke-width="9" stroke-dasharray="188.5" stroke-dashoffset="188.5" stroke-linecap="round" transform="rotate(-90 38 38)" id="healthArc" style="transition:stroke-dashoffset 1.2s ease"/>
      </svg>
      <div class="health-ring-center">
        <span class="health-score-num" id="healthNum">__GOV_SCORE__</span>
        <span class="health-score-pct">/ 100</span>
      </div>
    </div>
    <div class="health-info">
      <h3>Governance Health Score</h3>
      <p>Percentage of teams passing all evaluated governance rules</p>
      <div class="health-bar-row">
        <span style="color:var(--green);font-size:12px">✅ Compliant</span>
        <div class="health-mini-bar"><div class="health-mini-fill" id="hCompliant" style="background:var(--green);width:0%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">__COMPLIANT_TEAMS__</span>
      </div>
      <div class="health-bar-row">
        <span style="color:var(--red);font-size:12px">❌ Non-Compliant</span>
        <div class="health-mini-bar"><div class="health-mini-fill" id="hNonCompliant" style="background:var(--red);width:0%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">__NONCOMPLIANT_TEAMS__</span>
      </div>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-red"><div class="stat-icon">🚫</div><div class="stat-value" style="color:var(--red)">__CRITICAL_COUNT__</div><div class="stat-label">Ownerless Teams (Critical)</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">⚠</div><div class="stat-value" style="color:var(--amber)">__WARNING_COUNT__</div><div class="stat-label">Under-Owned Teams (Warning)</div></div>
    <div class="stat-card c-blue"><div class="stat-icon">💤</div><div class="stat-value">__INACTIVE_COUNT__</div><div class="stat-label">Inactive / Never Active</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">❌</div><div class="stat-value">__NONCOMPLIANT_TEAMS__</div><div class="stat-label">Non-Compliant Teams</div></div>
    <div class="stat-card c-green"><div class="stat-icon">✅</div><div class="stat-value" style="color:var(--green)">__COMPLIANT_TEAMS__</div><div class="stat-label">Fully Compliant Teams</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">🌐</div><div class="stat-value">__PUBLIC_COUNT__</div><div class="stat-label">Public Teams (Visibility Risk)</div></div>
  </div>

  <div class="chart-grid">
    <div class="panel"><div class="section-title">🔥 Risk Distribution</div><div id="riskChart"></div></div>
    <div class="panel"><div class="section-title">📋 Most Critical Findings</div><div id="criticalFindings"></div></div>
  </div>
</section>

<!-- OWNERLESS -->
<section id="page-ownerless" class="page">
  <div class="page-header">
    <div><div class="page-title">Ownerless &amp; Under-Owned Teams</div><div class="page-subtitle">Teams with 0 owners (Critical) or 1 owner (Warning)</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('ownerless')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="ownerlessSearch" placeholder="Search teams…" oninput="filterTable('ownerless')"/></div>
    <select id="ownerlessRisk" onchange="filterTable('ownerless')"><option value="">All Risk Levels</option><option>Critical</option><option>Warning</option></select>
    <span class="result-count" id="ownerlessCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('ownerless',0,this)">Team Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('ownerless',1,this)">Owner Count<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('ownerless',2,this)">Risk Level<span class="sort-arrow">↕</span></th>
    <th>Recommendation</th>
  </tr></thead><tbody id="ownerlessBody"></tbody></table>
  <div class="pagination" id="ownerlessPager"></div>
</section>

<!-- COMPLIANCE -->
<section id="page-compliance" class="page">
  <div class="page-header">
    <div><div class="page-title">Compliance Findings</div><div class="page-subtitle">Rule-by-rule governance compliance report</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('compliance')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="complianceSearch" placeholder="Search findings…" oninput="filterTable('compliance')"/></div>
    <select id="complianceSev" onchange="filterTable('compliance')"><option value="">All Severities</option><option>Critical</option><option>Warning</option><option>Pass</option><option>Info</option></select>
    <select id="complianceStatus" onchange="filterTable('compliance')"><option value="">All Status</option><option>Compliant</option><option>NonCompliant</option></select>
    <span class="result-count" id="complianceCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('compliance',0,this)">Team Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('compliance',1,this)">Rule<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('compliance',2,this)">Severity<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('compliance',3,this)">Status<span class="sort-arrow">↕</span></th>
    <th>Details</th>
    <th onclick="sortTable('compliance',5,this)">Compliance %<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="complianceBody"></tbody></table>
  <div class="pagination" id="compliancePager"></div>
</section>

<!-- INACTIVE -->
<section id="page-inactive" class="page">
  <div class="page-header">
    <div><div class="page-title">Inactive Teams</div><div class="page-subtitle">Teams with no activity in the reporting period</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('inactive')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="inactiveSearch" placeholder="Search teams…" oninput="filterTable('inactive')"/></div>
    <select id="inactiveStatus" onchange="filterTable('inactive')"><option value="">All Status</option><option>Inactive</option><option>Never Active</option></select>
    <span class="result-count" id="inactiveCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('inactive',0,this)">Team Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('inactive',1,this)">Last Activity<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('inactive',2,this)">Days Since Activity<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('inactive',3,this)">Status<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="inactiveBody"></tbody></table>
  <div class="pagination" id="inactivePager"></div>
</section>

<!-- LIFECYCLE -->
<section id="page-lifecycle" class="page">
  <div class="page-header">
    <div><div class="page-title">Lifecycle Report</div><div class="page-subtitle">Full teams lifecycle stage classification</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('lifecycle')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="lifecycleSearch" placeholder="Search teams…" oninput="filterTable('lifecycle')"/></div>
    <select id="lifecycleStage" onchange="filterTable('lifecycle')"><option value="">All Stages</option><option>Active</option><option>Inactive</option><option>Ownerless</option><option>UnderOwned</option><option>Unknown</option></select>
    <span class="result-count" id="lifecycleCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('lifecycle',0,this)">Team Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('lifecycle',1,this)">Lifecycle Stage<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('lifecycle',2,this)">Owners<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('lifecycle',3,this)">Members<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('lifecycle',4,this)">Age (Days)<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('lifecycle',5,this)">Last Activity<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('lifecycle',6,this)">Visibility<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="lifecycleBody"></tbody></table>
  <div class="pagination" id="lifecyclePager"></div>
</section>

</main>

<div id="toast"><span id="toastIcon">✓</span><span id="toastMsg"></span></div>

<script>
const OWNERLESS   = [__OWNERLESS_JSON__];
const COMPLIANCE  = [__COMPLIANCE_JSON__];
const INACTIVE    = [__INACTIVE_JSON__];
const LIFECYCLE   = [__LIFECYCLE_JSON__];
const GOV_SCORE   = __GOV_SCORE__;
const TOTAL_TEAMS = __TOTAL_UNIQUE_TEAMS__;

function showPage(id,btn){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));document.getElementById('page-'+id).classList.add('active');if(btn)btn.classList.add('active');}
function toggleTheme(){document.body.classList.toggle('light-theme');const lt=document.body.classList.contains('light-theme');document.getElementById('themeIcon').textContent=lt?'☀️':'🌙';document.getElementById('themeLabel').textContent=lt?'Light Mode':'Dark Mode';}
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function showToast(msg,icon){document.getElementById('toastMsg').textContent=msg;document.getElementById('toastIcon').textContent=icon||'✓';const t=document.getElementById('toast');t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800);}
function dlFile(c,n,t){const b=new Blob([c],{type:t});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=n;a.click();URL.revokeObjectURL(u);}

function sevBadge(s){const m={Critical:'sev-critical',Warning:'sev-warning',Pass:'sev-pass',Info:'sev-info'};return`<span class="badge ${m[s]||'sev-info'}">${escH(s)}</span>`;}
function stageBadge(s){const c={Active:'var(--green)',Inactive:'var(--amber)',Ownerless:'var(--red)',UnderOwned:'var(--amber)',Unknown:'var(--muted)'};return`<span class="badge" style="background:${c[s]||'var(--muted)'}22;color:${c[s]||'var(--muted)'};border:1px solid ${c[s]||'var(--muted)'}44">${escH(s)}</span>`;}

const tableState={
  ownerless: {data:OWNERLESS,  filtered:OWNERLESS,  page:1,pageSize:15,sortCol:-1,sortDir:1},
  compliance:{data:COMPLIANCE, filtered:COMPLIANCE, page:1,pageSize:15,sortCol:-1,sortDir:1},
  inactive:  {data:INACTIVE,   filtered:INACTIVE,   page:1,pageSize:15,sortCol:-1,sortDir:1},
  lifecycle: {data:LIFECYCLE,  filtered:LIFECYCLE,  page:1,pageSize:15,sortCol:-1,sortDir:1}
};

function renderRows(key){
  const s=tableState[key];const start=(s.page-1)*s.pageSize,slice=s.filtered.slice(start,start+s.pageSize);
  const cnt=document.getElementById(key+'Count');if(cnt)cnt.textContent=`${s.filtered.length} result${s.filtered.length!==1?'s':''}`;
  const tbody=document.getElementById(key+'Body');if(!tbody)return;
  tbody.innerHTML=slice.map(r=>rowHtml(key,r)).join('');renderPager(key);
}

function rowHtml(key,r){
  if(key==='ownerless') return`<tr><td class="td-mono">${escH(r.name)}</td><td class="td-small">${r.ownerCount}</td><td>${sevBadge(r.risk)}</td><td class="td-muted" style="font-size:12px">${escH(r.recommendation)}</td></tr>`;
  if(key==='compliance')return`<tr><td class="td-mono">${escH(r.teamName)}</td><td class="td-small">${escH(r.ruleName)}</td><td>${sevBadge(r.severity)}</td><td>${r.status==='Compliant'?'<span style="color:var(--green)">✅ Compliant</span>':'<span style="color:var(--red)">❌ NonCompliant</span>'}</td><td class="td-muted" style="font-size:12px">${escH(r.details)}</td><td class="td-small">${r.compliancePct}%</td></tr>`;
  if(key==='inactive')  return`<tr><td class="td-mono">${escH(r.name)}</td><td class="td-small">${escH(r.lastActivity)}</td><td class="td-small">${r.daysSince||'—'}</td><td>${sevBadge(r.status==='Never Active'?'Critical':'Warning')}</td></tr>`;
  if(key==='lifecycle') return`<tr><td class="td-mono">${escH(r.name)}</td><td>${stageBadge(r.lifecycleStage)}</td><td class="td-small">${r.ownerCount}</td><td class="td-small">${r.memberCount}</td><td class="td-small">${r.ageInDays}</td><td class="td-small">${escH(r.lastActivity)}</td><td class="td-small">${escH(r.visibility)}</td></tr>`;
  return'';
}

function filterTable(key){
  const s=tableState[key];
  const q=(document.getElementById(key+'Search')||{value:''}).value.toLowerCase();
  const riskF=(document.getElementById('ownerlessRisk')||{value:''}).value;
  const sevF=(document.getElementById('complianceSev')||{value:''}).value;
  const statusF=(document.getElementById('complianceStatus')||{value:''}).value;
  const inactF=(document.getElementById('inactiveStatus')||{value:''}).value;
  const stageF=(document.getElementById('lifecycleStage')||{value:''}).value;
  s.filtered=s.data.filter(r=>{
    if(q&&!JSON.stringify(r).toLowerCase().includes(q))return false;
    if(key==='ownerless'  && riskF  && r.risk!==riskF)         return false;
    if(key==='compliance' && sevF   && r.severity!==sevF)       return false;
    if(key==='compliance' && statusF&& r.status!==statusF)      return false;
    if(key==='inactive'   && inactF && r.status!==inactF)       return false;
    if(key==='lifecycle'  && stageF && r.lifecycleStage!==stageF)return false;
    return true;
  });s.page=1;renderRows(key);
}

function sortTable(key,col,th){
  const s=tableState[key];
  const cols={ownerless:['name','ownerCount','risk'],compliance:['teamName','ruleName','severity','status','details','compliancePct'],inactive:['name','lastActivity','daysSince','status'],lifecycle:['name','lifecycleStage','ownerCount','memberCount','ageInDays','lastActivity','visibility']};
  const field=cols[key][col];s.sortDir=(s.sortCol===col)?-s.sortDir:1;s.sortCol=col;
  s.filtered.sort((a,b)=>{const av=String(a[field]||'').toLowerCase(),bv=String(b[field]||'').toLowerCase();return av<bv?-s.sortDir:av>bv?s.sortDir:0;});
  document.querySelectorAll('#page-'+key+' .data-table th').forEach((h,i)=>{h.classList.toggle('sort-active',i===col);const arr=h.querySelector('.sort-arrow');if(arr)arr.textContent=i===col?(s.sortDir===1?'↑':'↓'):'↕';});
  s.page=1;renderRows(key);
}

function renderPager(key){
  const s=tableState[key];const pages=Math.ceil(s.filtered.length/s.pageSize)||1;
  const el=document.getElementById(key+'Pager');if(!el)return;
  let h=`<button class="page-btn" onclick="gotoPage('${key}',${s.page-1})" ${s.page===1?'disabled':''}>◀</button>`;
  for(let i=1;i<=pages;i++){if(i===1||i===pages||Math.abs(i-s.page)<=1)h+=`<button class="page-btn${i===s.page?' active':''}" onclick="gotoPage('${key}',${i})">${i}</button>`;else if(Math.abs(i-s.page)===2)h+=`<span style="color:var(--muted);padding:0 4px">…</span>`;}
  h+=`<button class="page-btn" onclick="gotoPage('${key}',${s.page+1})" ${s.page===pages?'disabled':''}>▶</button>`;el.innerHTML=h;
}
function gotoPage(key,p){const s=tableState[key];const pages=Math.ceil(s.filtered.length/s.pageSize)||1;s.page=Math.max(1,Math.min(p,pages));renderRows(key);}

function exportCSV(key){
  const s=tableState[key];const data=s.filtered;
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  let h='',rows=[];
  if(key==='ownerless') {h='Team,OwnerCount,Risk,Recommendation';rows=data.map(r=>[esc(r.name),r.ownerCount,esc(r.risk),esc(r.recommendation)].join(','));}
  if(key==='compliance'){h='Team,RuleId,Rule,Severity,Status,Details,RulesEvaluated,RulesFailed,Compliance%';rows=data.map(r=>[esc(r.teamName),esc(r.ruleId),esc(r.ruleName),esc(r.severity),esc(r.status),esc(r.details),r.rulesEvaluated,r.rulesFailed,r.compliancePct].join(','));}
  if(key==='inactive')  {h='Team,LastActivity,DaysSince,Status';rows=data.map(r=>[esc(r.name),esc(r.lastActivity),r.daysSince,esc(r.status)].join(','));}
  if(key==='lifecycle') {h='Team,Stage,Owners,Members,Guests,AgeDays,LastActivity,Visibility';rows=data.map(r=>[esc(r.name),esc(r.lifecycleStage),r.ownerCount,r.memberCount,r.guestCount,r.ageInDays,esc(r.lastActivity),esc(r.visibility)].join(','));}
  dlFile([h,...rows].join('\r\n'),`Teams_Governance_${key}_${new Date().toISOString().substring(0,10)}.csv`,'text/csv');
  showToast(`Exported ${data.length} rows as CSV`);
}

// ── Overview charts ──
(function initOverview(){
  const score=GOV_SCORE;
  const arc=188.5,offset=arc-(arc*(score/100));
  const arcEl=document.getElementById('healthArc');
  const col=score>=80?'var(--green)':score>=50?'var(--amber)':'var(--red)';
  if(arcEl){arcEl.style.stroke=col;setTimeout(()=>{arcEl.style.strokeDashoffset=offset;},100);}
  document.getElementById('healthNum').style.color=col;

  const tot=TOTAL_TEAMS||1;
  const compliant=__COMPLIANT_TEAMS__,nc=__NONCOMPLIANT_TEAMS__;
  setTimeout(()=>{
    const hc=document.getElementById('hCompliant');if(hc)hc.style.width=Math.round(compliant/tot*100)+'%';
    const hn=document.getElementById('hNonCompliant');if(hn)hn.style.width=Math.round(nc/tot*100)+'%';
  },300);

  const critical=__CRITICAL_COUNT__,warning=__WARNING_COUNT__,inactive=__INACTIVE_COUNT__;
  const riskMax=Math.max(critical,warning,nc,inactive)||1;
  document.getElementById('riskChart').innerHTML=[
    {l:'Ownerless (Critical)',v:critical,c:'var(--red)'},
    {l:'Under-Owned (Warning)',v:warning,c:'var(--amber)'},
    {l:'Non-Compliant',v:nc,c:'var(--accent3)'},
    {l:'Inactive',v:inactive,c:'var(--accent)'}
  ].map(b=>`<div class="bar-row"><span class="bar-label">${b.l}</span><div class="bar-track"><div class="bar-fill" style="width:0%;background:${b.c}" data-pct="${Math.round(b.v/riskMax*100)}"></div></div><span class="bar-val">${b.v}</span></div>`).join('');

  const critical_findings=OWNERLESS.filter(o=>o.risk==='Critical').slice(0,6);
  document.getElementById('criticalFindings').innerHTML=critical_findings.length
    ?critical_findings.map(f=>`<div class="finding-row"><span class="finding-severity sev-critical">Critical</span><div><div class="finding-name">${escH(f.name)}</div><div class="finding-detail">${escH(f.recommendation)}</div></div></div>`).join('')
    :'<p style="color:var(--muted);font-size:13px;padding:8px 0">No critical ownership findings. ✅</p>';

  requestAnimationFrame(()=>{document.querySelectorAll('.bar-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';});});
})();

document.addEventListener('keydown',e=>{
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){e.preventDefault();const inp=document.querySelector('.page.active input[type=text]');if(inp)inp.focus();}
});

['ownerless','compliance','inactive','lifecycle'].forEach(k=>renderRows(k));
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GOV_SCORE__', $govHealthScore  `
        -replace '__TOTAL_UNIQUE_TEAMS__', $totalUniqueTeams `
        -replace '__COMPLIANT_TEAMS__', $compliantTeams   `
        -replace '__NONCOMPLIANT_TEAMS__', $nonCompliantTeams `
        -replace '__CRITICAL_COUNT__', $criticalCount    `
        -replace '__WARNING_COUNT__', $warningCount     `
        -replace '__INACTIVE_COUNT__', $inactiveCount    `
        -replace '__PUBLIC_COUNT__', $publicCount      `
        -replace '__OWNERLESS_COUNT__', @($allOwnerless).Count   `
        -replace '__COMPLIANCE_COUNT__', @($allCompliance).Count  `
        -replace '__LIFECYCLE_COUNT__', @($allLifecycle).Count   `
        -replace '__GENERATEDAT__', $generatedAt      `
        -replace '__OWNERLESS_JSON__', $ownerlessJson    `
        -replace '__COMPLIANCE_JSON__', $complianceJson   `
        -replace '__INACTIVE_JSON__', $inactiveJson     `
        -replace '__LIFECYCLE_JSON__', $lifecycleJson

    #endregion

    #region ── Output ─────────────────────────────────────────────────────────

    Try {
        $outFolder = Split-Path -Path $OutputPath -Parent
        if ($outFolder -and -not (Test-Path -Path $outFolder)) {
            New-Item -Path $outFolder -ItemType Directory -Force | Out-Null
        }
        $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║   ✅  Teams Governance Dashboard — generated!        ║" -ForegroundColor Green
        Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "  🏛  Governance Score  : $govHealthScore / 100" -ForegroundColor $(if ($govHealthScore -ge 80) { 'Green' } elseif ($govHealthScore -ge 50) { 'Yellow' } else { 'Red' })
        Write-Host "  🚫  Critical          : $criticalCount ownerless team(s)"    -ForegroundColor White
        Write-Host "  ⚠   Warning           : $warningCount under-owned team(s)"   -ForegroundColor White
        Write-Host "  💤  Inactive          : $inactiveCount team(s)"              -ForegroundColor White
        Write-Host "  📋  Non-Compliant     : $nonCompliantTeams team(s)"          -ForegroundColor White
        Write-Host "  📁  Output            : $OutputPath"                         -ForegroundColor White
        Write-Host ""

        if ($OpenBrowser) { Start-Process $OutputPath }
    }
    Catch {
        Write-Error "Failed to write dashboard: $($_.Exception.Message)"
    }

    #endregion

}
