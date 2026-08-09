<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 02 August 2026
Modified-On  : 02 August 2026

.SYNOPSIS
    Generates an HTML Teams Inventory Dashboard from live Graph data or
    pre-collected pipeline input.

.DESCRIPTION
    Accepts either a live -AccessToken (queries Graph API directly to collect
    teams, owners, members, channels, and apps) or pre-collected PSCustomObject
    arrays piped in from the Get-Teams / Get-TeamMembers / Get-TeamChannels /
    Get-TeamApps suite.

    Produces a single self-contained HTML file styled with the Cloud Identity
    Toolkit golden dashboard theme (dark/light toggle, stat cards, sortable
    tables, detail drawer, CSV export, keyboard shortcuts).

    Tabs:
        Overview   — stat cards (team count, members, guests, channels, apps,
                      archived), visibility pie, channel-type breakdown, top
                      teams by member count
        All Teams  — searchable/sortable table with per-team drill-down drawer
        Members    — searchable/sortable table of all team members with role
        Channels   — searchable/sortable table of all channels by type
        Apps       — searchable/sortable table of installed apps with risk flag

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions: Group.Read.All, TeamMember.Read.All,
    Channel.ReadBasic.All, TeamsAppInstallation.Read.All.
    When supplied alongside piped data, live Graph data takes precedence for
    any collection that was not piped in.

.PARAMETER Teams
    Pre-collected teams array (output of Get-Teams). When omitted and
    -AccessToken is provided, teams are fetched from Graph.

.PARAMETER Members
    Pre-collected members array (output of Get-TeamMembers). When omitted and
    -AccessToken is provided, members are fetched from Graph.

.PARAMETER Channels
    Pre-collected channels array (output of Get-TeamChannels). When omitted
    and -AccessToken is provided, channels are fetched from Graph.

.PARAMETER Apps
    Pre-collected apps array (output of Get-TeamApps). When omitted and
    -AccessToken is provided, apps are fetched from Graph.

.PARAMETER OutputPath
    Full file path for the generated HTML file.
    Default: "$env:TEMP\TeamInventoryDashboard.html"

.PARAMETER OpenBrowser
    If specified, opens the generated HTML in the default browser.

.INPUTS
    PSCustomObject arrays from Get-Teams, Get-TeamMembers, Get-TeamChannels,
    Get-TeamApps.

.OUTPUTS
    A self-contained HTML file at -OutputPath.

.EXAMPLE
    Generate-TeamInventoryDashboard -AccessToken $token -OpenBrowser

    Pulls live data from Graph and opens the dashboard.

.EXAMPLE
    $teams   = Get-Teams   -AccessToken $token
    $members = Get-TeamMembers -AccessToken $token
    Generate-TeamInventoryDashboard -Teams $teams -Members $members -OutputPath "C:\Reports\Inventory.html"

    Uses pre-collected data for teams and members; skips channels and apps.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (02-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. PowerShell 5.1 or later
        2. When using -AccessToken: Group.Read.All, TeamMember.Read.All,
            Channel.ReadBasic.All, TeamsAppInstallation.Read.All
        3. When using pre-collected data: run the relevant Get-Team* functions
            from the Cloud Identity Toolkit first

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Large tenants (1000+ teams) will produce a large HTML file; consider
            scoping with -TeamId on the upstream Get-Team* functions first.
        - The live-pull path uses BYOT (bearer token passed as parameter);
            no authentication is performed by this script.
        - App data requires TeamsAppInstallation.Read.All which is commonly
            absent from existing app registrations; the Apps tab gracefully
            shows an empty state when no app data is available.

.LINK
    Cloud Identity Toolkit
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit

#>


Function Generate-TeamInventoryDashboard {
  [CmdletBinding()]
  param (
    [string]$AccessToken,

    [Parameter(ValueFromPipeline = $true)]
    [object[]]$Teams,

    [object[]]$Members,
    [object[]]$Channels,
    [object[]]$Apps,

    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^(?!.*\.\.)[^<>:"|?*]+$')]
    [string]$OutputPath = "$env:TEMP\TeamInventoryDashboard.html",

    [switch]$OpenBrowser
  )

  Begin {
    #region ── Helpers ────────────────────────────────────────────────────────

    Function ConvertTo-JsonSafe {
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

    Function Invoke-GraphPagedRequest {
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

    $headers = @{ "Authorization" = "Bearer $AccessToken"; "ConsistencyLevel" = "eventual" }

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║      Teams Inventory Dashboard  v1.0                 ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Accumulated pipeline input
    $pipeTeams = [System.Collections.ArrayList]::new()
    #endregion
  }

  Process {
    # Collect pipeline input (Teams array piped in)
    if ($Teams) {
      @($Teams) | ForEach-Object { $null = $pipeTeams.Add($_) }
    }
  }

  End {
    #region ── Data Collection ────────────────────────────────────────────────

    # Resolve teams
    if ($pipeTeams.Count -gt 0) {
      $allTeams = @($pipeTeams)
      Write-Host "  ✅  Using $($allTeams.Count) team(s) from pipeline." -ForegroundColor Green
    }
    elseif ($AccessToken) {
      Write-Host "  🔍  Fetching teams from Graph..." -ForegroundColor Cyan
      $raw = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName,description,visibility,mail,createdDateTime&`$count=true" -Headers $headers
      $allTeams = @($raw | ForEach-Object {
          [PSCustomObject]@{ id = $_.id; displayName = $_.displayName; description = $_.description; visibility = $_.visibility; mail = $_.mail; createdDateTime = $_.createdDateTime }
        })
      Write-Host "  ✅  Found $($allTeams.Count) team(s)." -ForegroundColor Green
    }
    else { Write-Error "Provide -AccessToken or pipe team data. Exiting."; return }

    # Resolve members
    if ($Members -and @($Members).Count -gt 0) {
      $allMembers = @($Members)
      Write-Host "  ✅  Using $(@($allMembers).Count) member record(s) from pipeline." -ForegroundColor Green
    }
    elseif ($AccessToken) {
      Write-Host "  🔍  Fetching members from Graph..." -ForegroundColor Cyan
      $allMembers = [System.Collections.ArrayList]::new()
      foreach ($t in $allTeams) {
        Try {
          $mems = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/teams/$($t.id)/members?`$top=100" -Headers $headers
          @($mems) | ForEach-Object {
            $null = $allMembers.Add([PSCustomObject]@{
                teamId            = $t.id
                teamDisplayName   = $t.displayName
                memberId          = $_.userId
                memberDisplayName = $_.displayName
                memberEmail       = $_.email
                role              = if ($_.roles -and @($_.roles) -contains 'owner') { 'Owner' } else { 'Member' }
              })
          }
        }
        Catch { Write-Warning "Members fetch failed for $($t.id): $($_.Exception.Message)" }
      }
      Write-Host "  ✅  Found $($allMembers.Count) member record(s)." -ForegroundColor Green
    }
    else { $allMembers = @() }

    # Resolve channels
    if ($Channels -and @($Channels).Count -gt 0) {
      $allChannels = @($Channels)
      Write-Host "  ✅  Using $(@($allChannels).Count) channel(s) from pipeline." -ForegroundColor Green
    }
    elseif ($AccessToken) {
      Write-Host "  🔍  Fetching channels from Graph..." -ForegroundColor Cyan
      $allChannels = [System.Collections.ArrayList]::new()
      foreach ($t in $allTeams) {
        Try {
          $chans = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/teams/$($t.id)/channels?`$select=id,displayName,description,membershipType,createdDateTime" -Headers $headers
          @($chans) | ForEach-Object {
            $null = $allChannels.Add([PSCustomObject]@{
                teamId             = $t.id
                teamDisplayName    = $t.displayName
                channelId          = $_.id
                channelDisplayName = $_.displayName
                channelType        = $_.membershipType
                description        = $_.description
                createdDateTime    = $_.createdDateTime
              })
          }
        }
        Catch { Write-Warning "Channels fetch failed for $($t.id): $($_.Exception.Message)" }
      }
      Write-Host "  ✅  Found $($allChannels.Count) channel(s)." -ForegroundColor Green
    }
    else { $allChannels = @() }

    # Resolve apps
    if ($Apps -and @($Apps).Count -gt 0) {
      $allApps = @($Apps)
      Write-Host "  ✅  Using $(@($allApps).Count) app record(s) from pipeline." -ForegroundColor Green
    }
    elseif ($AccessToken) {
      Write-Host "  🔍  Fetching installed apps from Graph..." -ForegroundColor Cyan
      $allApps = [System.Collections.ArrayList]::new()
      foreach ($t in $allTeams) {
        Try {
          $appList = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/teams/$($t.id)/installedApps?`$expand=teamsApp,teamsAppDefinition" -Headers $headers
          @($appList) | ForEach-Object {
            $dm = $_.teamsApp.distributionMethod
            $null = $allApps.Add([PSCustomObject]@{
                teamId             = $t.id
                teamDisplayName    = $t.displayName
                appId              = $_.teamsApp.id
                appDisplayName     = $_.teamsAppDefinition.displayName
                appVersion         = $_.teamsAppDefinition.version
                distributionMethod = $dm
                publishingState    = $_.teamsAppDefinition.publishingState
                riskFlag           = if ($dm -eq 'sideloaded') { 'Review' } else { 'Normal' }
              })
          }
        }
        Catch { Write-Warning "Apps fetch failed for $($t.id): $($_.Exception.Message)" }
      }
      Write-Host "  ✅  Found $($allApps.Count) app record(s)." -ForegroundColor Green
    }
    else { $allApps = @() }

    #endregion

    #region ── Compute Summary Metrics ────────────────────────────────────────

    $totalTeams = @($allTeams).Count
    $totalMembers = @($allMembers).Count
    $totalGuests = @($allMembers | Where-Object { $_.memberEmail -like '*#EXT#*' -or $_.role -eq 'Guest' }).Count
    $totalChannels = @($allChannels).Count
    $totalApps = @($allApps).Count
    $publicTeams = @($allTeams | Where-Object { $_.visibility -eq 'Public' }).Count
    $privateTeams = @($allTeams | Where-Object { $_.visibility -eq 'Private' }).Count
    $stdChannels = @($allChannels | Where-Object { $_.channelType -eq 'standard' }).Count
    $privChannels = @($allChannels | Where-Object { $_.channelType -eq 'private' }).Count
    $sharedChans = @($allChannels | Where-Object { $_.channelType -eq 'shared' }).Count
    $reviewApps = @($allApps | Where-Object { $_.riskFlag -eq 'Review' }).Count
    $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')

    # Top 5 teams by member count
    $teamMemberCounts = $allMembers | Group-Object teamId | Sort-Object Count -Descending | Select-Object -First 5
    $topTeamsJson = ($teamMemberCounts | ForEach-Object {
        # $name = ConvertTo-JsonSafe ($allTeams | Where-Object { $_.id -eq $grp.Name } | Select-Object -ExpandProperty displayName -First 1)
        $grp = $_
        $tname = ConvertTo-JsonSafe (@($allTeams | Where-Object { $_.id -eq $grp.Name })[0].displayName)
        "{`"name`":`"$tname`",`"count`":$($grp.Count)}"
      }) -join ','

    #endregion

    #region ── JSON Data Blobs ────────────────────────────────────────────────

    $teamsJson = (@($allTeams) | ForEach-Object {
        $n = ConvertTo-JsonSafe "$($_.displayName)"
        $d = ConvertTo-JsonSafe "$($_.description)"
        $v = ConvertTo-JsonSafe "$($_.visibility)"
        $m = ConvertTo-JsonSafe "$($_.mail)"
        $id = ConvertTo-JsonSafe "$($_.id)"
        $cd = ConvertTo-JsonSafe "$($_.createdDateTime)"
        # $mc = @($allMembers | Where-Object { $_.teamId -eq $_.id }).Count
        $tmc = @($allMembers | Where-Object { $_.teamId -eq $id }).Count
        $tcc = @($allChannels | Where-Object { $_.teamId -eq $id }).Count
        $tac = @($allApps | Where-Object { $_.teamId -eq $id }).Count
        "{`"id`":`"$id`",`"name`":`"$n`",`"desc`":`"$d`",`"visibility`":`"$v`",`"mail`":`"$m`",`"created`":`"$cd`",`"memberCount`":$tmc,`"channelCount`":$tcc,`"appCount`":$tac}"
      }) -join ','

    $membersJson = (@($allMembers) | ForEach-Object {
        $tn = ConvertTo-JsonSafe "$($_.teamDisplayName)"
        $mn = ConvertTo-JsonSafe "$($_.memberDisplayName)"
        $me = ConvertTo-JsonSafe "$($_.memberEmail)"
        $ro = ConvertTo-JsonSafe "$($_.role)"
        $ti = ConvertTo-JsonSafe "$($_.teamId)"
        "{`"teamId`":`"$ti`",`"teamName`":`"$tn`",`"name`":`"$mn`",`"email`":`"$me`",`"role`":`"$ro`"}"
      }) -join ','

    $channelsJson = (@($allChannels) | ForEach-Object {
        $tn = ConvertTo-JsonSafe "$($_.teamDisplayName)"
        $cn = ConvertTo-JsonSafe "$($_.channelDisplayName)"
        $ct = ConvertTo-JsonSafe "$($_.channelType)"
        $cd = ConvertTo-JsonSafe "$($_.description)"
        $cr = ConvertTo-JsonSafe "$($_.createdDateTime)"
        $ti = ConvertTo-JsonSafe "$($_.teamId)"
        "{`"teamId`":`"$ti`",`"teamName`":`"$tn`",`"name`":`"$cn`",`"type`":`"$ct`",`"desc`":`"$cd`",`"created`":`"$cr`"}"
      }) -join ','

    $appsJson = (@($allApps) | ForEach-Object {
        $tn = ConvertTo-JsonSafe "$($_.teamDisplayName)"
        $an = ConvertTo-JsonSafe "$($_.appDisplayName)"
        $av = ConvertTo-JsonSafe "$($_.appVersion)"
        $dm = ConvertTo-JsonSafe "$($_.distributionMethod)"
        $ps = ConvertTo-JsonSafe "$($_.publishingState)"
        $rf = ConvertTo-JsonSafe "$($_.riskFlag)"
        $ti = ConvertTo-JsonSafe "$($_.teamId)"
        "{`"teamId`":`"$ti`",`"teamName`":`"$tn`",`"name`":`"$an`",`"version`":`"$av`",`"distribution`":`"$dm`",`"state`":`"$ps`",`"risk`":`"$rf`"}"
      }) -join ','

    #endregion

    #region ── HTML ───────────────────────────────────────────────────────────

    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Teams Inventory Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;--border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;--green:#3fb950;--amber:#d29922;--red:#f85149;--text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;--mono:'JetBrains Mono','Consolas','Courier New',monospace;--sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;--radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5)}
body.light-theme{--bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;--border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;--green:#1a7f37;--amber:#b08000;--red:#cf222e;--text:#1f2328;--muted:#636c76;--muted2:#424a53;--shadow:0 4px 24px rgba(0,0,0,.12)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}
#sidebar{position:fixed;top:0;left:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text)}
.sidebar-logo p{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px}
.version-badge{display:inline-block;margin-top:5px;background:rgba(56,139,253,.15);color:var(--accent);font-family:var(--mono);font-size:10px;padding:1px 8px;border-radius:20px;border:1px solid rgba(56,139,253,.3)}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13.5px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0}
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
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:25px;font-weight:700;line-height:1}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-size:12.5px;color:var(--muted2);width:90px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:10px;background:var(--surface3);border-radius:5px;overflow:hidden}
.bar-fill{height:100%;border-radius:5px;transition:width .9s ease}
.bar-val{font-family:var(--mono);font-size:11px;color:var(--muted);width:36px;text-align:right;flex-shrink:0}
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
.td-mono{font-family:var(--mono);font-size:12.5px;color:var(--accent2);font-weight:600}
.td-muted{color:var(--muted2)}
.td-small{color:var(--muted);font-family:var(--mono);font-size:12px;white-space:nowrap}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600}
.badge-public{background:rgba(248,81,73,.12);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.badge-private{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.badge-owner{background:rgba(56,139,253,.12);color:var(--accent);border:1px solid rgba(56,139,253,.3)}
.badge-member{background:rgba(125,133,144,.12);color:var(--muted2);border:1px solid var(--border)}
.badge-std{background:rgba(57,197,207,.12);color:var(--accent2);border:1px solid rgba(57,197,207,.3)}
.badge-priv{background:rgba(163,113,247,.12);color:var(--accent3);border:1px solid rgba(163,113,247,.3)}
.badge-shared{background:rgba(210,153,34,.12);color:var(--amber);border:1px solid rgba(210,153,34,.3)}
.badge-review{background:rgba(248,81,73,.12);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.badge-normal{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:14px}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}
#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(620px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:24px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
#detailClose{margin-left:auto;background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--red);color:#fff}
#detailContent{flex:1;overflow-y:auto}
.detail-title{font-family:var(--mono);font-size:16px;color:var(--accent2);font-weight:600;margin-bottom:4px}
.detail-sub{font-size:11px;color:var(--muted);font-family:var(--mono);margin-bottom:12px;word-break:break-all}
.detail-meta-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:12px;color:var(--muted2)}
.detail-section{margin-top:16px}
.detail-section-title{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid var(--border)}
.detail-row{display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px}
.detail-row:last-child{border-bottom:none}
.detail-row-label{color:var(--muted);width:120px;flex-shrink:0;font-size:12px}
.detail-row-val{color:var(--text);font-family:var(--mono);font-size:12.5px}
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
    <div class="logo-icon">📦</div>
    <h1>Teams Inventory</h1>
    <p>Cloud Identity Toolkit</p>
    <span class="version-badge">v1.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span>Overview</button>
    <button class="nav-btn" onclick="showPage('teams',this)"><span class="nav-icon">👥</span>All Teams<span class="nav-badge">__TOTAL_TEAMS__</span></button>
    <button class="nav-btn" onclick="showPage('members',this)"><span class="nav-icon">👤</span>Members<span class="nav-badge">__TOTAL_MEMBERS__</span></button>
    <button class="nav-btn" onclick="showPage('channels',this)"><span class="nav-icon">📢</span>Channels<span class="nav-badge">__TOTAL_CHANNELS__</span></button>
    <button class="nav-btn" onclick="showPage('apps',this)"><span class="nav-icon">🧩</span>Apps<span class="nav-badge">__TOTAL_APPS__</span></button>
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
    <div><div class="page-title">Teams Inventory Overview</div><div class="page-subtitle">Tenant-wide Microsoft Teams estate at a glance</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('teams')">⬇ Export Teams CSV</button></div>
  </div>
  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">👥</div><div class="stat-value">__TOTAL_TEAMS__</div><div class="stat-label">Total Teams</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">👤</div><div class="stat-value">__TOTAL_MEMBERS__</div><div class="stat-label">Total Members</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">🌐</div><div class="stat-value">__TOTAL_GUESTS__</div><div class="stat-label">Guest Members</div></div>
    <div class="stat-card c-green"><div class="stat-icon">📢</div><div class="stat-value">__TOTAL_CHANNELS__</div><div class="stat-label">Total Channels</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">🧩</div><div class="stat-value">__TOTAL_APPS__</div><div class="stat-label">Installed Apps</div></div>
    <div class="stat-card c-red"><div class="stat-icon">⚠</div><div class="stat-value">__REVIEW_APPS__</div><div class="stat-label">Apps for Review</div></div>
  </div>
  <div class="chart-grid">
    <div class="panel"><div class="section-title">🔒 Visibility Breakdown</div><div id="visChart"></div></div>
    <div class="panel"><div class="section-title">📢 Channel Type Breakdown</div><div id="chanChart"></div></div>
    <div class="panel"><div class="section-title">🏆 Top Teams by Member Count</div><div id="topTeamsChart"></div></div>
    <div class="panel"><div class="section-title">ℹ️ Estate Summary</div>
      <div class="detail-row"><span class="detail-row-label">Public Teams</span><span class="detail-row-val">__PUBLIC_TEAMS__</span></div>
      <div class="detail-row"><span class="detail-row-label">Private Teams</span><span class="detail-row-val">__PRIVATE_TEAMS__</span></div>
      <div class="detail-row"><span class="detail-row-label">Standard Channels</span><span class="detail-row-val">__STD_CHANNELS__</span></div>
      <div class="detail-row"><span class="detail-row-label">Private Channels</span><span class="detail-row-val">__PRIV_CHANNELS__</span></div>
      <div class="detail-row"><span class="detail-row-label">Shared Channels</span><span class="detail-row-val">__SHARED_CHANS__</span></div>
      <div class="detail-row"><span class="detail-row-label">Sideloaded Apps</span><span class="detail-row-val" style="color:var(--red)">__REVIEW_APPS__</span></div>
    </div>
  </div>
</section>

<!-- ALL TEAMS -->
<section id="page-teams" class="page">
  <div class="page-header">
    <div><div class="page-title">All Teams</div><div class="page-subtitle">Complete teams inventory</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('teams')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="teamsSearch" placeholder="Search teams…" oninput="filterTable('teams')"/></div>
    <select id="teamsVis" onchange="filterTable('teams')"><option value="">All Visibility</option><option>Public</option><option>Private</option></select>
    <input type="date" id="teamsDateFrom" title="Created from" onchange="filterTable('teams')" style="padding:8px 10px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-size:13px;cursor:pointer"/>
    <input type="date" id="teamsDateTo" title="Created to" onchange="filterTable('teams')" style="padding:8px 10px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-size:13px;cursor:pointer"/>
    <select id="teamsMinMembers" onchange="filterTable('teams')"><option value="">Any Size</option><option value="1">1+ members</option><option value="5">5+ members</option><option value="10">10+ members</option><option value="25">25+ members</option><option value="50">50+ members</option></select>
    <button class="btn" onclick="clearFilters('teams')">✕ Clear</button>
    <span class="result-count" id="teamsCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('teams',0,this)">Team Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('teams',1,this)">Visibility<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('teams',2,this)">Members<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('teams',3,this)">Channels<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('teams',4,this)">Apps<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('teams',5,this)">Mail<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="teamsBody"></tbody></table>
  <div class="pagination" id="teamsPager"></div>
</section>

<!-- MEMBERS -->
<section id="page-members" class="page">
  <div class="page-header">
    <div><div class="page-title">Members</div><div class="page-subtitle">All team members and roles</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('members')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="membersSearch" placeholder="Search members…" oninput="filterTable('members')"/></div>
    <select id="membersRole" onchange="filterTable('members')"><option value="">All Roles</option><option>Owner</option><option>Member</option></select>
    <select id="membersTeam" onchange="filterTable('members')"><option value="">All Teams</option></select>
    <button class="btn" onclick="clearFilters('members')">✕ Clear</button>
    <span class="result-count" id="membersCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('members',0,this)">Member Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('members',1,this)">Email<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('members',2,this)">Role<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('members',3,this)">Team<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="membersBody"></tbody></table>
  <div class="pagination" id="membersPager"></div>
</section>

<!-- CHANNELS -->
<section id="page-channels" class="page">
  <div class="page-header">
    <div><div class="page-title">Channels</div><div class="page-subtitle">Standard, Private and Shared channels</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('channels')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="channelsSearch" placeholder="Search channels…" oninput="filterTable('channels')"/></div>
    <select id="channelsType" onchange="filterTable('channels')"><option value="">All Types</option><option>standard</option><option>private</option><option>shared</option></select>
    <select id="channelsTeam" onchange="filterTable('channels')"><option value="">All Teams</option></select>
    <input type="date" id="channelsDateFrom" title="Created from" onchange="filterTable('channels')" style="padding:8px 10px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-size:13px;cursor:pointer"/>
    <input type="date" id="channelsDateTo" title="Created to" onchange="filterTable('channels')" style="padding:8px 10px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-size:13px;cursor:pointer"/>
    <button class="btn" onclick="clearFilters('channels')">✕ Clear</button>
    <span class="result-count" id="channelsCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('channels',0,this)">Channel Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('channels',1,this)">Type<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('channels',2,this)">Team<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('channels',3,this)">Created<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="channelsBody"></tbody></table>
  <div class="pagination" id="channelsPager"></div>
</section>

<!-- APPS -->
<section id="page-apps" class="page">
  <div class="page-header">
    <div><div class="page-title">Installed Apps</div><div class="page-subtitle">Microsoft and third-party apps across all teams</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('apps')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="appsSearch" placeholder="Search apps…" oninput="filterTable('apps')"/></div>
    <select id="appsRisk" onchange="filterTable('apps')"><option value="">All Risk Levels</option><option>Normal</option><option>Review</option></select>
    <select id="appsDist" onchange="filterTable('apps')"><option value="">All Distribution</option></select>
    <select id="appsTeam" onchange="filterTable('apps')"><option value="">All Teams</option></select>
    <button class="btn" onclick="clearFilters('apps')">✕ Clear</button>
    <span class="result-count" id="appsCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('apps',0,this)">App Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('apps',1,this)">Version<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('apps',2,this)">Distribution<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('apps',3,this)">Risk<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('apps',4,this)">Team<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="appsBody"></tbody></table>
  <div class="pagination" id="appsPager"></div>
</section>

</main>

<!-- DETAIL PANEL -->
<div id="detailPanel"><div id="detailBackdrop" onclick="closeDetail()"></div><div id="detailDrawer">
  <div class="detail-toolbar">
    <button class="btn" id="detailPrevBtn" onclick="navigateDetail(-1)">◀ Prev</button>
    <button class="btn" id="detailNextBtn" onclick="navigateDetail(1)">Next ▶</button>
    <button id="detailClose" onclick="closeDetail()">✕</button>
  </div>
  <div id="detailContent"></div>
</div></div>

<!-- TOAST -->
<div id="toast"><span id="toastIcon">✓</span><span id="toastMsg"></span></div>

<script>
const TEAMS    = [__TEAMS_JSON__];
const MEMBERS  = [__MEMBERS_JSON__];
const CHANNELS = [__CHANNELS_JSON__];
const APPS     = [__APPS_JSON__];

// ── Page navigation ──
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn)btn.classList.add('active');
}

// ── Theme ──
function toggleTheme(){document.body.classList.toggle('light-theme');const lt=document.body.classList.contains('light-theme');document.getElementById('themeIcon').textContent=lt?'☀️':'🌙';document.getElementById('themeLabel').textContent=lt?'Light Mode':'Dark Mode';}

// ── Utils ──
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
function showToast(msg,icon){document.getElementById('toastMsg').textContent=msg;document.getElementById('toastIcon').textContent=icon||'✓';const t=document.getElementById('toast');t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800);}
function dlFile(c,n,t){const b=new Blob([c],{type:t});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=n;a.click();URL.revokeObjectURL(u);}

// ── Table state ──
const tableState={
  teams:   {data:TEAMS,   filtered:TEAMS,   page:1,pageSize:15,sortCol:-1,sortDir:1},
  members: {data:MEMBERS, filtered:MEMBERS, page:1,pageSize:15,sortCol:-1,sortDir:1},
  channels:{data:CHANNELS,filtered:CHANNELS,page:1,pageSize:15,sortCol:-1,sortDir:1},
  apps:    {data:APPS,    filtered:APPS,    page:1,pageSize:15,sortCol:-1,sortDir:1}
};

// ── Render rows ──
function renderRows(key){
  const s=tableState[key];
  const start=(s.page-1)*s.pageSize, slice=s.filtered.slice(start,start+s.pageSize);
  const cnt=document.getElementById(key+'Count');
  if(cnt)cnt.textContent=`${s.filtered.length} result${s.filtered.length!==1?'s':''}`;
  const tbody=document.getElementById(key+'Body');
  if(!tbody)return;
  tbody.innerHTML=slice.map((r,i)=>rowHtml(key,r,start+i)).join('');
  renderPager(key);
}

function rowHtml(key,r,idx){
  if(key==='teams')   return `<tr onclick="openDetail('teams',${idx},true)"><td class="td-mono">${escH(r.name)}</td><td>${visBadge(r.visibility)}</td><td class="td-small">${r.memberCount}</td><td class="td-small">${r.channelCount}</td><td class="td-small">${r.appCount}</td><td class="td-small">${escH(r.mail)}</td></tr>`;
  if(key==='members') return `<tr><td class="td-mono">${escH(r.name)}</td><td class="td-small">${escH(r.email)}</td><td>${roleBadge(r.role)}</td><td class="td-muted">${escH(r.teamName)}</td></tr>`;
  if(key==='channels')return `<tr><td class="td-mono">${escH(r.name)}</td><td>${chanBadge(r.type)}</td><td class="td-muted">${escH(r.teamName)}</td><td class="td-small">${escH(r.created?r.created.substring(0,10):'')}</td></tr>`;
  if(key==='apps')    return `<tr><td class="td-mono">${escH(r.name)}</td><td class="td-small">${escH(r.version)}</td><td class="td-small">${escH(r.distribution)}</td><td>${riskBadge(r.risk)}</td><td class="td-muted">${escH(r.teamName)}</td></tr>`;
  return '';
}

function visBadge(v){return v==='Public'?`<span class="badge badge-public">Public</span>`:`<span class="badge badge-private">Private</span>`;}
function roleBadge(r){return r==='Owner'?`<span class="badge badge-owner">Owner</span>`:`<span class="badge badge-member">Member</span>`;}
function chanBadge(t){if(t==='private')return`<span class="badge badge-priv">Private</span>`;if(t==='shared')return`<span class="badge badge-shared">Shared</span>`;return`<span class="badge badge-std">Standard</span>`;}
function riskBadge(r){return r==='Review'?`<span class="badge badge-review">⚠ Review</span>`:`<span class="badge badge-normal">Normal</span>`;}

// ── Filter ──
function filterTable(key){
  const s=tableState[key];
  const val=id=>(document.getElementById(id)||{value:''}).value;
  const q=val(key+'Search').toLowerCase();

  s.filtered=s.data.filter(r=>{
    // Full-text search
    if(q && !JSON.stringify(r).toLowerCase().includes(q)) return false;

    if(key==='teams'){
      if(val('teamsVis')   && r.visibility!==val('teamsVis'))   return false;
      if(val('teamsMinMembers') && r.memberCount < parseInt(val('teamsMinMembers'))) return false;
      const df=val('teamsDateFrom'), dt=val('teamsDateTo');
      if(df && r.created && r.created.substring(0,10) < df) return false;
      if(dt && r.created && r.created.substring(0,10) > dt) return false;
    }
    if(key==='members'){
      if(val('membersRole') && r.role!==val('membersRole'))         return false;
      if(val('membersTeam') && r.teamName!==val('membersTeam'))     return false;
    }
    if(key==='channels'){
      if(val('channelsType') && r.type!==val('channelsType'))       return false;
      if(val('channelsTeam') && r.teamName!==val('channelsTeam'))   return false;
      const df=val('channelsDateFrom'), dt=val('channelsDateTo');
      if(df && r.created && r.created.substring(0,10) < df) return false;
      if(dt && r.created && r.created.substring(0,10) > dt) return false;
    }
    if(key==='apps'){
      if(val('appsRisk') && r.risk!==val('appsRisk'))               return false;
      if(val('appsDist') && r.distribution!==val('appsDist'))       return false;
      if(val('appsTeam') && r.teamName!==val('appsTeam'))           return false;
    }
    return true;
  });
  s.page=1;
  renderRows(key);
}

// ── Clear all filters for a tab ──
function clearFilters(key){
  const ids={
    teams:   ['teamsSearch','teamsVis','teamsDateFrom','teamsDateTo','teamsMinMembers'],
    members: ['membersSearch','membersRole','membersTeam'],
    channels:['channelsSearch','channelsType','channelsTeam','channelsDateFrom','channelsDateTo'],
    apps:    ['appsSearch','appsRisk','appsDist','appsTeam']
  };
  (ids[key]||[]).forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  filterTable(key);
}

// ── Populate dynamic dropdowns from live data ──
function populateDynamicDropdowns(){
  // Members → team list
  const mTeams=[...new Set(MEMBERS.map(r=>r.teamName).filter(Boolean))].sort();
  const mSel=document.getElementById('membersTeam');
  if(mSel) mTeams.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;mSel.appendChild(o);});

  // Channels → team list
  const cTeams=[...new Set(CHANNELS.map(r=>r.teamName).filter(Boolean))].sort();
  const cSel=document.getElementById('channelsTeam');
  if(cSel) cTeams.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;cSel.appendChild(o);});

  // Apps → team list
  const aTeams=[...new Set(APPS.map(r=>r.teamName).filter(Boolean))].sort();
  const aSel=document.getElementById('appsTeam');
  if(aSel) aTeams.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;aSel.appendChild(o);});

  // Apps → distribution method list
  const dists=[...new Set(APPS.map(r=>r.distribution).filter(Boolean))].sort();
  const dSel=document.getElementById('appsDist');
  if(dSel) dists.forEach(d=>{const o=document.createElement('option');o.value=d;o.textContent=d;dSel.appendChild(o);});
}

// ── Sort ──
function sortTable(key,col,th){
  const s=tableState[key];
  const cols={teams:['name','visibility','memberCount','channelCount','appCount','mail'],members:['name','email','role','teamName'],channels:['name','type','teamName','created'],apps:['name','version','distribution','risk','teamName']};
  const field=cols[key][col];
  s.sortDir=(s.sortCol===col)?-s.sortDir:1;s.sortCol=col;
  s.filtered.sort((a,b)=>{const av=String(a[field]||'').toLowerCase(),bv=String(b[field]||'').toLowerCase();return av<bv?-s.sortDir:av>bv?s.sortDir:0;});
  document.querySelectorAll('#page-'+key+' .data-table th').forEach((h,i)=>{h.classList.toggle('sort-active',i===col);const arr=h.querySelector('.sort-arrow');if(arr)arr.textContent=i===col?(s.sortDir===1?'↑':'↓'):'↕';});
  s.page=1;renderRows(key);
}

// ── Pagination ──
function renderPager(key){
  const s=tableState[key];const pages=Math.ceil(s.filtered.length/s.pageSize)||1;
  const el=document.getElementById(key+'Pager');if(!el)return;
  let h=`<button class="page-btn" onclick="gotoPage('${key}',${s.page-1})" ${s.page===1?'disabled':''}>◀</button>`;
  for(let i=1;i<=pages;i++){if(i===1||i===pages||Math.abs(i-s.page)<=1)h+=`<button class="page-btn${i===s.page?' active':''}" onclick="gotoPage('${key}',${i})">${i}</button>`;else if(Math.abs(i-s.page)===2)h+=`<span style="color:var(--muted);padding:0 4px">…</span>`;}
  h+=`<button class="page-btn" onclick="gotoPage('${key}',${s.page+1})" ${s.page===pages?'disabled':''}>▶</button>`;
  el.innerHTML=h;
}
function gotoPage(key,p){const s=tableState[key];const pages=Math.ceil(s.filtered.length/s.pageSize)||1;s.page=Math.max(1,Math.min(p,pages));renderRows(key);}

// ── Detail drawer ──
let currentDetailKey='',currentDetailIdx=-1;
function openDetail(key,idx,fromFiltered){
  const s=tableState[key];
  const item=fromFiltered?s.filtered[idx]:s.data[idx];
  if(!item)return;
  currentDetailKey=key;currentDetailIdx=fromFiltered?idx:idx;
  _renderDetailContent(key,item);
  document.getElementById('detailPrevBtn').disabled=currentDetailIdx<=0;
  document.getElementById('detailNextBtn').disabled=currentDetailIdx>=s.filtered.length-1;
  document.getElementById('detailPanel').classList.add('open');
  document.body.style.overflow='hidden';
}
function navigateDetail(dir){
  const s=tableState[currentDetailKey];
  const ni=currentDetailIdx+dir;
  if(ni<0||ni>=s.filtered.length)return;
  currentDetailIdx=ni;
  const item=s.filtered[ni];
  _renderDetailContent(currentDetailKey,item);
  document.getElementById('detailPrevBtn').disabled=currentDetailIdx<=0;
  document.getElementById('detailNextBtn').disabled=currentDetailIdx>=s.filtered.length-1;
}
function _renderDetailContent(key,r){
  let h='';
  if(key==='teams'){
    const tMembers=MEMBERS.filter(m=>m.teamId===r.id);
    const tChannels=CHANNELS.filter(c=>c.teamId===r.id);
    const tApps=APPS.filter(a=>a.teamId===r.id);
    h=`<div class="detail-title">${escH(r.name)}</div><div class="detail-sub">${escH(r.mail)}</div>
    <div class="detail-meta-row">${visBadge(r.visibility)}<span class="detail-chip">👤 ${r.memberCount} members</span><span class="detail-chip">📢 ${r.channelCount} channels</span><span class="detail-chip">🧩 ${r.appCount} apps</span></div>
    <div class="detail-section"><div class="detail-section-title">Details</div>
    <div class="detail-row"><span class="detail-row-label">Description</span><span class="detail-row-val">${escH(r.desc||'—')}</span></div>
    <div class="detail-row"><span class="detail-row-label">Created</span><span class="detail-row-val">${escH(r.created?r.created.substring(0,10):'—')}</span></div>
    <div class="detail-row"><span class="detail-row-label">Team ID</span><span class="detail-row-val" style="font-size:11px">${escH(r.id)}</span></div></div>
    <div class="detail-section"><div class="detail-section-title">Members (${tMembers.length})</div>${tMembers.length?tMembers.map(m=>`<div class="detail-row">${roleBadge(m.role)}<span class="detail-row-val" style="margin-left:8px">${escH(m.name)}</span><span class="detail-row-label" style="margin-left:auto;width:auto">${escH(m.email)}</span></div>`).join(''):'<p style="color:var(--muted);font-size:12px;padding:8px 0">No member data loaded.</p>'}</div>
    <div class="detail-section"><div class="detail-section-title">Channels (${tChannels.length})</div>${tChannels.length?tChannels.map(c=>`<div class="detail-row">${chanBadge(c.type)}<span class="detail-row-val" style="margin-left:8px">${escH(c.name)}</span></div>`).join(''):'<p style="color:var(--muted);font-size:12px;padding:8px 0">No channel data loaded.</p>'}</div>`;
  } else if(key==='apps'){
    h=`<div class="detail-title">${escH(r.name)}</div><div class="detail-sub">v${escH(r.version)}</div>
    <div class="detail-meta-row">${riskBadge(r.risk)}<span class="detail-chip">${escH(r.distribution)}</span><span class="detail-chip">${escH(r.state)}</span></div>
    <div class="detail-section"><div class="detail-section-title">Details</div>
    <div class="detail-row"><span class="detail-row-label">Team</span><span class="detail-row-val">${escH(r.teamName)}</span></div>
    <div class="detail-row"><span class="detail-row-label">Distribution</span><span class="detail-row-val">${escH(r.distribution)}</span></div>
    <div class="detail-row"><span class="detail-row-label">State</span><span class="detail-row-val">${escH(r.state)}</span></div></div>`;
  }
  if(h) document.getElementById('detailContent').innerHTML=h;
  document.getElementById('detailContent').scrollTo(0,0);
}
function closeDetail(){document.getElementById('detailPanel').classList.remove('open');document.body.style.overflow='';}

// ── CSV Export ──
function exportCSV(key){
  const s=tableState[key];const data=s.filtered;
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  let headers='',rows=[];
  if(key==='teams'){headers='Name,Visibility,Members,Channels,Apps,Mail,Created,ID';rows=data.map(r=>[esc(r.name),esc(r.visibility),r.memberCount,r.channelCount,r.appCount,esc(r.mail),esc(r.created),esc(r.id)].join(','));}
  if(key==='members'){headers='Name,Email,Role,Team';rows=data.map(r=>[esc(r.name),esc(r.email),esc(r.role),esc(r.teamName)].join(','));}
  if(key==='channels'){headers='Name,Type,Team,Created';rows=data.map(r=>[esc(r.name),esc(r.type),esc(r.teamName),esc(r.created)].join(','));}
  if(key==='apps'){headers='Name,Version,Distribution,Risk,Team';rows=data.map(r=>[esc(r.name),esc(r.version),esc(r.distribution),esc(r.risk),esc(r.teamName)].join(','));}
  dlFile([headers,...rows].join('\r\n'),`Teams_${key}_${new Date().toISOString().substring(0,10)}.csv`,'text/csv');
  showToast(`Exported ${data.length} rows as CSV`);
}

// ── Overview Charts ──
(function initOverview(){
  // Visibility
  const pub=__PUBLIC_TEAMS__,priv=__PRIVATE_TEAMS__;const visTotal=pub+priv||1;
  document.getElementById('visChart').innerHTML=[{l:'Private',v:priv,c:'var(--green)'},{l:'Public',v:pub,c:'var(--red)'}]
    .map(b=>`<div class="bar-row"><span class="bar-label">${b.l}</span><div class="bar-track"><div class="bar-fill" style="width:0%;background:${b.c}" data-pct="${Math.round(b.v/visTotal*100)}"></div></div><span class="bar-val">${b.v}</span></div>`).join('');
  // Channel types
  const std=__STD_CHANNELS__,pc=__PRIV_CHANNELS__,sc=__SHARED_CHANS__;const chanTotal=std+pc+sc||1;
  document.getElementById('chanChart').innerHTML=[{l:'Standard',v:std,c:'var(--accent2)'},{l:'Private',v:pc,c:'var(--accent3)'},{l:'Shared',v:sc,c:'var(--amber)'}]
    .map(b=>`<div class="bar-row"><span class="bar-label">${b.l}</span><div class="bar-track"><div class="bar-fill" style="width:0%;background:${b.c}" data-pct="${Math.round(b.v/chanTotal*100)}"></div></div><span class="bar-val">${b.v}</span></div>`).join('');
  // Top teams
  const TOP=[__TOP_TEAMS_JSON__];const tmax=TOP.length?Math.max(...TOP.map(t=>t.count)):1;
  document.getElementById('topTeamsChart').innerHTML=TOP.map((t,i)=>`<div class="bar-row"><span class="bar-label" title="${escH(t.name)}">${escH(t.name)}</span><div class="bar-track"><div class="bar-fill" style="width:0%;background:var(--accent)" data-pct="${Math.round(t.count/tmax*100)}"></div></div><span class="bar-val">${t.count}</span></div>`).join('');
  requestAnimationFrame(()=>{document.querySelectorAll('.bar-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';});});
})();

// ── Keyboard shortcuts ──
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closeDetail();return;}
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){e.preventDefault();const inp=document.querySelector('.page.active input[type=text]');if(inp)inp.focus();}
  if(document.getElementById('detailPanel').classList.contains('open')){if(e.key==='ArrowLeft')navigateDetail(-1);if(e.key==='ArrowRight')navigateDetail(1);}
});

// ── Init all tables ──
['teams','members','channels','apps'].forEach(k=>renderRows(k));
populateDynamicDropdowns();
</script>
</body>
</html>
'@

    $html = $html `
      -replace '__TOTAL_TEAMS__', $totalTeams    `
      -replace '__TOTAL_MEMBERS__', $totalMembers  `
      -replace '__TOTAL_GUESTS__', $totalGuests   `
      -replace '__TOTAL_CHANNELS__', $totalChannels `
      -replace '__TOTAL_APPS__', $totalApps     `
      -replace '__REVIEW_APPS__', $reviewApps    `
      -replace '__PUBLIC_TEAMS__', $publicTeams   `
      -replace '__PRIVATE_TEAMS__', $privateTeams  `
      -replace '__STD_CHANNELS__', $stdChannels   `
      -replace '__PRIV_CHANNELS__', $privChannels  `
      -replace '__SHARED_CHANS__', $sharedChans   `
      -replace '__GENERATEDAT__', $generatedAt   `
      -replace '__TEAMS_JSON__', $teamsJson     `
      -replace '__MEMBERS_JSON__', $membersJson   `
      -replace '__CHANNELS_JSON__', $channelsJson  `
      -replace '__APPS_JSON__', $appsJson      `
      -replace '__TOP_TEAMS_JSON__', $topTeamsJson

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
      Write-Host "║   ✅  Teams Inventory Dashboard — generated!         ║" -ForegroundColor Green
      Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
      Write-Host ""
      Write-Host "  👥  Teams       : $totalTeams"    -ForegroundColor White
      Write-Host "  👤  Members     : $totalMembers"  -ForegroundColor White
      Write-Host "  📢  Channels    : $totalChannels" -ForegroundColor White
      Write-Host "  🧩  Apps        : $totalApps"     -ForegroundColor White
      Write-Host "  📁  Output      : $OutputPath"    -ForegroundColor White
      Write-Host ""

      if ($OpenBrowser) { Start-Process $OutputPath }
    }
    Catch {
      Write-Error "Failed to write dashboard: $($_.Exception.Message)"
    }

    #endregion
  }
}
