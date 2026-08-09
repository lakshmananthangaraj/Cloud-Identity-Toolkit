<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 09 August 2026
Modified-On  : 09 August 2026

.SYNOPSIS
    Generates a self-contained HTML Teams Security Posture Dashboard from
    live Graph data or pre-collected pipeline input.

.DESCRIPTION
    Accepts either a live -AccessToken (queries Microsoft Graph API directly)
    or pre-collected PSCustomObject arrays piped in from the Cloud Identity
    Toolkit suite (Get-TeamApps, Get-TeamOwnerlessTeams, etc.).

    Produces a single self-contained HTML file styled with the Cloud Identity
    Toolkit golden dashboard theme (dark/light toggle, per-category score
    cards, sortable tables, CSV export, keyboard shortcuts).

    Security categories covered:
        Guest Access     — external users (#EXT#) across all teams
        App Risk         — sideloaded / non-store apps (distributionMethod)
        Channel Exposure — private and shared channel inventory
        Visibility Risk  — public teams (discoverable by all tenant users)
        Ownership Risk   — teams with 0 or 1 owner
        MFA Status       — owner MFA coverage (pipeline input only)

    Per-category scores are weighted using the CIS Microsoft 365 Foundations
    Benchmark and NIST CSF priorities:
        Ownership Risk   30 %
        Guest Access     25 %
        App Risk         25 %
        Visibility Risk  10 %
        Channel Exposure 10 %

    Tabs:
        Overview   — overall posture score ring, per-category score cards,
                     risk distribution bar chart, top findings list
        Findings   — unified searchable/sortable table of all risk findings
                     across every category with severity, category, and detail
        Guests     — per-team guest and external user breakdown
        Apps       — sideloaded / risky app inventory
        Channels   — private and shared channel exposure list
        Visibility — public team list
        Ownership  — ownerless and under-owned team list
        MFA        — owner MFA coverage (requires pipeline input)

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions: Group.Read.All, TeamMember.Read.All,
    Channel.ReadBasic.All, TeamsAppInstallation.Read.All.
    When supplied alongside piped data, live Graph calls are made only for
    collections that were not piped in.

.PARAMETER Members
    Pre-collected members array (output of Get-TeamMembers or equivalent).
    Each object must have: teamId, teamDisplayName, memberEmail, role.

.PARAMETER Apps
    Pre-collected apps array (output of Get-TeamApps).
    Each object must have: teamId, teamDisplayName, appDisplayName,
    appVersion, distributionMethod, publishingState, riskFlag.

.PARAMETER Channels
    Pre-collected channels array (output of Get-TeamChannels or equivalent).
    Each object must have: teamId, teamDisplayName, channelDisplayName,
    channelType.

.PARAMETER Teams
    Pre-collected teams array (output of Get-Teams or equivalent).
    Each object must have: id, displayName, visibility.

.PARAMETER OwnerlessTeams
    Pre-collected ownerless/under-owned teams array (output of
    Get-TeamOwnerlessTeams). Each object must have: teamId, teamDisplayName,
    ownerCount, riskLevel.

.PARAMETER MfaReport
    Pre-collected MFA status array. Live MFA checks are not performed by this
    script (UserAuthenticationMethod.Read.All is commonly restricted).
    Each object must have: userId, displayName, email, mfaEnabled (bool or
    string), teamId, teamDisplayName, role.

.PARAMETER OutputPath
    Full file path for the generated HTML file.
    Default: "$env:TEMP\TeamSecurityDashboard.html"

.PARAMETER OpenBrowser
    If specified, opens the generated HTML in the default browser after
    writing the file.

.INPUTS
    PSCustomObject arrays from the Cloud Identity Toolkit Get-Team* suite.

.OUTPUTS
    A self-contained HTML file at -OutputPath.

.EXAMPLE
    Generate-TeamSecurityDashboard -AccessToken $token -OpenBrowser

    Pulls all security data live from Graph and opens the dashboard.

.EXAMPLE
    $apps      = Get-TeamApps -AccessToken $token
    $ownerless = Get-TeamOwnerlessTeams -AccessToken $token
    Generate-TeamSecurityDashboard -Apps $apps -OwnerlessTeams $ownerless `
        -AccessToken $token -OutputPath "C:\Reports\Security.html"

    Uses pre-collected apps and ownership data; fetches remaining data live.

.EXAMPLE
    $mfa = Get-TeamOwnerMfaStatus -AccessToken $token   # your own collector
    Generate-TeamSecurityDashboard -AccessToken $token -MfaReport $mfa -OpenBrowser

    Includes MFA coverage tab using pre-collected MFA data.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (09-Aug-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. PowerShell 5.1 or later
        2. When using -AccessToken:
               Group.Read.All
               TeamMember.Read.All
               Channel.ReadBasic.All
               TeamsAppInstallation.Read.All
        3. MFA data must be pre-collected externally and passed via -MfaReport;
           this script does not query userAuthenticationMethod endpoints.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - MFA coverage is pipeline-input only; the tab shows an empty state
          with guidance when -MfaReport is not supplied.
        - Scores are heuristic. A team with 0 ownerless members but all-public
          visibility will still show a reduced Visibility score.
        - Large tenants (1 000+ teams) produce a large HTML file; pre-scope
          using -TeamId on the upstream Get-Team* functions first.
        - The live-pull path uses BYOT (token passed as parameter); this script
          does not perform authentication.

.LINK
    Cloud Identity Toolkit
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit

#>


Function Generate-TeamSecurityDashboard {
    [CmdletBinding()]
    param (
        [string]$AccessToken,

        [object[]]$Members,
        [object[]]$Apps,
        [object[]]$Channels,

        [Parameter(ValueFromPipeline = $true)]
        [object[]]$Teams,

        [object[]]$OwnerlessTeams,
        [object[]]$MfaReport,

        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^(?!.*\.\.)[^<>:"|?*]+$')]
        [string]$OutputPath = "$env:TEMP\TeamSecurityDashboard.html",

        [switch]$OpenBrowser
    )

    Begin {
        #region ── Helpers ────────────────────────────────────────────────────

        function ConvertTo-JsonSafe {
            param([string]$Text)
            $Text `
                -replace '\\', '\\\\'   `
                -replace '"', '\"'     `
                -replace "`r`n", '\n'     `
                -replace "`n", '\n'     `
                -replace "`r", '\n'     `
                -replace "`t", '\t'     `
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

        $headers = @{ "Authorization" = "Bearer $AccessToken"; "ConsistencyLevel" = "eventual" }
        $pipeTeams = [System.Collections.ArrayList]::new()

        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║      Teams Security Dashboard  v1.0                  ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""

        #endregion
    }

    Process {
        if ($Teams) { @($Teams) | ForEach-Object { $null = $pipeTeams.Add($_) } }
    }

    End {
        #region ── Data Collection ────────────────────────────────────────────

        # ── Teams ──────────────────────────────────────────────────────────
        if ($pipeTeams.Count -gt 0) {
            $allTeams = @($pipeTeams)
            Write-Host "  ✅  Using $($allTeams.Count) team(s) from pipeline." -ForegroundColor Green
        }
        elseif ($AccessToken) {
            Write-Host "  🔍  Fetching teams from Graph..." -ForegroundColor Cyan
            $raw = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$top=100&`$select=id,displayName,description,visibility,mail,createdDateTime&`$count=true" -Headers $headers
            $allTeams = @($raw | ForEach-Object {
                    [PSCustomObject]@{
                        id              = $_.id
                        displayName     = $_.displayName
                        description     = $_.description
                        visibility      = $_.visibility
                        mail            = $_.mail
                        createdDateTime = $_.createdDateTime
                    }
                })
            Write-Host "  ✅  Found $($allTeams.Count) team(s)." -ForegroundColor Green
        }
        else { Write-Error "Provide -AccessToken or pipe team data. Exiting."; return }

        # ── Members ────────────────────────────────────────────────────────
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

        # ── Apps ───────────────────────────────────────────────────────────
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

        # ── Channels ───────────────────────────────────────────────────────
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
                                createdDateTime    = $_.createdDateTime
                            })
                    }
                }
                Catch { Write-Warning "Channels fetch failed for $($t.id): $($_.Exception.Message)" }
            }
            Write-Host "  ✅  Found $($allChannels.Count) channel(s)." -ForegroundColor Green
        }
        else { $allChannels = @() }

        # ── Ownerless Teams ────────────────────────────────────────────────
        if ($OwnerlessTeams -and @($OwnerlessTeams).Count -gt 0) {
            $allOwnerless = @($OwnerlessTeams)
            Write-Host "  ✅  Using $(@($allOwnerless).Count) ownerless/under-owned record(s) from pipeline." -ForegroundColor Green
        }
        elseif ($AccessToken) {
            Write-Host "  🔍  Evaluating team ownership from Graph..." -ForegroundColor Cyan
            $allOwnerless = [System.Collections.ArrayList]::new()
            foreach ($t in $allTeams) {
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

        # ── MFA (pipeline only) ────────────────────────────────────────────
        if ($MfaReport -and @($MfaReport).Count -gt 0) {
            $allMfa = @($MfaReport)
            Write-Host "  ✅  Using $(@($allMfa).Count) MFA record(s) from pipeline." -ForegroundColor Green
        }
        else {
            $allMfa = @()
            Write-Host "  ℹ️   No MFA data supplied — MFA tab will show guidance." -ForegroundColor Yellow
        }

        #endregion

        #region ── Derive Security Sub-Collections ────────────────────────────

        # Guests — members whose email contains #EXT# or role is Guest
        $allGuests = @($allMembers | Where-Object { $_.memberEmail -like '*#EXT#*' -or $_.role -eq 'Guest' })

        # Risky apps — sideloaded only
        $riskyApps = @($allApps | Where-Object { $_.riskFlag -eq 'Review' })

        # Exposed channels — private + shared only
        $exposedChannels = @($allChannels | Where-Object { $_.channelType -eq 'private' -or $_.channelType -eq 'shared' })

        # Public teams
        $publicTeams = @($allTeams | Where-Object { $_.visibility -eq 'Public' })

        # Critical ownerless (0 owners)
        $criticalOwnerless = @($allOwnerless | Where-Object { $_.riskLevel -eq 'Critical' })

        # MFA — owners with MFA disabled (if data supplied)
        $mfaDisabledOwners = @($allMfa | Where-Object { $_.mfaEnabled -eq $false -or $_.mfaEnabled -eq 'False' -or $_.mfaEnabled -eq 'No' })

        #endregion

        #region ── Per-Category Score Calculation ─────────────────────────────
        #
        #  Weights follow CIS Microsoft 365 Foundations Benchmark + NIST CSF:
        #    Ownership Risk   30%  — ownerless = unmanaged data + highest blast radius
        #    Guest Access     25%  — external user exposure = top cloud breach vector
        #    App Risk         25%  — sideloaded apps bypass catalog vetting (supply chain)
        #    Visibility Risk  10%  — public teams = accidental disclosure
        #    Channel Exposure 10%  — private/shared channel sprawl (least critical solo)
        #
        #  Each category score = 100 if no risk items exist; deducted proportionally
        #  to the fraction of teams/items that are at risk, capped at 0.
        #  Overall score = weighted sum of category scores.

        $totalTeamCount = [Math]::Max(@($allTeams).Count, 1)
        $totalAppCount = [Math]::Max(@($allApps).Count, 1)

        # Ownership score — fraction of teams with 0 or 1 owner
        $ownershipRisk = @($allOwnerless).Count
        $ownershipScore = [Math]::Max(0, [Math]::Round(100 - (($ownershipRisk / $totalTeamCount) * 100), 0))

        # Guest score — fraction of teams that have at least one guest
        $teamsWithGuests = @($allGuests | Select-Object -ExpandProperty teamId -Unique).Count
        $guestScore = [Math]::Max(0, [Math]::Round(100 - (($teamsWithGuests / $totalTeamCount) * 100), 0))

        # App score — fraction of installed apps that are sideloaded
        $appRiskCount = @($riskyApps).Count
        $appScore = [Math]::Max(0, [Math]::Round(100 - (($appRiskCount / $totalAppCount) * 100), 0))

        # Visibility score — fraction of teams that are Public
        $publicCount = @($publicTeams).Count
        $visibilityScore = [Math]::Max(0, [Math]::Round(100 - (($publicCount / $totalTeamCount) * 100), 0))

        # Channel score — fraction of channels that are private or shared
        $totalChannelCount = [Math]::Max(@($allChannels).Count, 1)
        $exposedChanCount = @($exposedChannels).Count
        $channelScore = [Math]::Max(0, [Math]::Round(100 - (($exposedChanCount / $totalChannelCount) * 100), 0))

        # MFA score — only computed when data is supplied
        $mfaScore = if ($allMfa.Count -gt 0) {
            $totalOwners = [Math]::Max(@($allMfa | Where-Object { $_.role -eq 'Owner' }).Count, 1)
            $disabledCount = @($mfaDisabledOwners).Count
            [Math]::Max(0, [Math]::Round(100 - (($disabledCount / $totalOwners) * 100), 0))
        }
        else { -1 }   # -1 = unknown / not supplied

        # Weighted overall score (MFA excluded from weighting when not supplied)
        $overallScore = [Math]::Round(
            ($ownershipScore * 0.30) +
            ($guestScore * 0.25) +
            ($appScore * 0.25) +
            ($visibilityScore * 0.10) +
            ($channelScore * 0.10),
            0)

        #endregion

        #region ── Summary Counts ─────────────────────────────────────────────

        $totalTeams = @($allTeams).Count
        $totalMembers = @($allMembers).Count
        $totalGuestCount = @($allGuests).Count
        $totalRiskyApps = @($riskyApps).Count
        $totalExposedChans = @($exposedChannels).Count
        $totalPublicTeams = @($publicTeams).Count
        $totalOwnerlessRisk = @($allOwnerless).Count
        $totalMfaDisabled = @($mfaDisabledOwners).Count
        $mfaDataAvailable = if ($allMfa.Count -gt 0) { 'true' } else { 'false' }
        $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss')

        #endregion

        #region ── Unified Findings Collection ────────────────────────────────

        $allFindings = [System.Collections.ArrayList]::new()

        # Ownership findings
        @($allOwnerless) | ForEach-Object {
            $null = $allFindings.Add([PSCustomObject]@{
                    category = 'Ownership'
                    severity = $_.riskLevel
                    teamName = $_.teamDisplayName
                    detail   = "Owner count: $($_.ownerCount). $($_.recommendation)"
                    teamId   = $_.teamId
                })
        }

        # Guest findings — one finding per team that has guests
        $allGuests | Group-Object teamId | ForEach-Object {
            $grp = $_
            $tname = (@($allTeams | Where-Object { $_.id -eq $grp.Name })[0]).displayName
            $null = $allFindings.Add([PSCustomObject]@{
                    category = 'Guest Access'
                    severity = 'Warning'
                    teamName = $tname
                    detail   = "$($grp.Count) external user(s) in this team."
                    teamId   = $grp.Name
                })
        }

        # App findings — one finding per risky app
        @($riskyApps) | ForEach-Object {
            $null = $allFindings.Add([PSCustomObject]@{
                    category = 'App Risk'
                    severity = 'Review'
                    teamName = $_.teamDisplayName
                    detail   = "Sideloaded app: $($_.appDisplayName) v$($_.appVersion)"
                    teamId   = $_.teamId
                })
        }

        # Visibility findings — one per public team
        @($publicTeams) | ForEach-Object {
            $null = $allFindings.Add([PSCustomObject]@{
                    category = 'Visibility'
                    severity = 'Warning'
                    teamName = $_.displayName
                    detail   = 'Team is Public — discoverable by all tenant users.'
                    teamId   = $_.id
                })
        }

        # Channel findings — one per exposed channel
        @($exposedChannels) | ForEach-Object {
            $null = $allFindings.Add([PSCustomObject]@{
                    category = 'Channel'
                    severity = 'Info'
                    teamName = $_.teamDisplayName
                    detail   = "$($_.channelType) channel: $($_.channelDisplayName)"
                    teamId   = $_.teamId
                })
        }

        # MFA findings — one per disabled owner
        @($mfaDisabledOwners) | ForEach-Object {
            $null = $allFindings.Add([PSCustomObject]@{
                    category = 'MFA'
                    severity = 'Critical'
                    teamName = $_.teamDisplayName
                    detail   = "Owner without MFA: $($_.displayName) ($($_.email))"
                    teamId   = $_.teamId
                })
        }

        #endregion

        #region ── JSON Data Blobs ────────────────────────────────────────────

        $findingsJson = (@($allFindings) | ForEach-Object {
                $cat = ConvertTo-JsonSafe "$($_.category)"
                $sev = ConvertTo-JsonSafe "$($_.severity)"
                $tn = ConvertTo-JsonSafe "$($_.teamName)"
                $det = ConvertTo-JsonSafe "$($_.detail)"
                $tid = ConvertTo-JsonSafe "$($_.teamId)"
                "{`"category`":`"$cat`",`"severity`":`"$sev`",`"teamName`":`"$tn`",`"detail`":`"$det`",`"teamId`":`"$tid`"}"
            }) -join ','

        $guestsJson = (@($allGuests) | ForEach-Object {
                $tn = ConvertTo-JsonSafe "$($_.teamDisplayName)"
                $mn = ConvertTo-JsonSafe "$($_.memberDisplayName)"
                $me = ConvertTo-JsonSafe "$($_.memberEmail)"
                $ro = ConvertTo-JsonSafe "$($_.role)"
                $tid = ConvertTo-JsonSafe "$($_.teamId)"
                "{`"teamId`":`"$tid`",`"teamName`":`"$tn`",`"name`":`"$mn`",`"email`":`"$me`",`"role`":`"$ro`"}"
            }) -join ','

        $appsJson = (@($riskyApps) | ForEach-Object {
                $tn = ConvertTo-JsonSafe "$($_.teamDisplayName)"
                $an = ConvertTo-JsonSafe "$($_.appDisplayName)"
                $av = ConvertTo-JsonSafe "$($_.appVersion)"
                $dm = ConvertTo-JsonSafe "$($_.distributionMethod)"
                $ps = ConvertTo-JsonSafe "$($_.publishingState)"
                $tid = ConvertTo-JsonSafe "$($_.teamId)"
                "{`"teamId`":`"$tid`",`"teamName`":`"$tn`",`"name`":`"$an`",`"version`":`"$av`",`"distribution`":`"$dm`",`"state`":`"$ps`"}"
            }) -join ','

        $channelsJson = (@($exposedChannels) | ForEach-Object {
                $tn = ConvertTo-JsonSafe "$($_.teamDisplayName)"
                $cn = ConvertTo-JsonSafe "$($_.channelDisplayName)"
                $ct = ConvertTo-JsonSafe "$($_.channelType)"
                $cr = ConvertTo-JsonSafe "$($_.createdDateTime)"
                $tid = ConvertTo-JsonSafe "$($_.teamId)"
                "{`"teamId`":`"$tid`",`"teamName`":`"$tn`",`"name`":`"$cn`",`"type`":`"$ct`",`"created`":`"$cr`"}"
            }) -join ','

        $visibilityJson = (@($publicTeams) | ForEach-Object {
                $n = ConvertTo-JsonSafe "$($_.displayName)"
                $m = ConvertTo-JsonSafe "$($_.mail)"
                $cd = ConvertTo-JsonSafe "$($_.createdDateTime)"
                $tid = ConvertTo-JsonSafe "$($_.id)"
                "{`"teamId`":`"$tid`",`"name`":`"$n`",`"mail`":`"$m`",`"created`":`"$cd`"}"
            }) -join ','

        $ownerlessJson = (@($allOwnerless) | ForEach-Object {
                $tn = ConvertTo-JsonSafe "$($_.teamDisplayName)"
                $rl = ConvertTo-JsonSafe "$($_.riskLevel)"
                $rec = ConvertTo-JsonSafe "$($_.recommendation)"
                $tid = ConvertTo-JsonSafe "$($_.teamId)"
                $oc = if ($null -ne $_.ownerCount) { $_.ownerCount } else { 0 }
                "{`"teamId`":`"$tid`",`"teamName`":`"$tn`",`"ownerCount`":$oc,`"riskLevel`":`"$rl`",`"recommendation`":`"$rec`"}"
            }) -join ','

        $mfaJson = (@($allMfa) | ForEach-Object {
                $dn = ConvertTo-JsonSafe "$($_.displayName)"
                $em = ConvertTo-JsonSafe "$($_.email)"
                $ro = ConvertTo-JsonSafe "$($_.role)"
                $tn = ConvertTo-JsonSafe "$($_.teamDisplayName)"
                $tid = ConvertTo-JsonSafe "$($_.teamId)"
                $mfa = if ($_.mfaEnabled -eq $true -or $_.mfaEnabled -eq 'True' -or $_.mfaEnabled -eq 'Yes') { 'true' } else { 'false' }
                "{`"teamId`":`"$tid`",`"teamName`":`"$tn`",`"name`":`"$dn`",`"email`":`"$em`",`"role`":`"$ro`",`"mfaEnabled`":$mfa}"
            }) -join ','

        # Top 5 findings by severity for Overview panel (Critical first, then Warning/Review)
        $severityOrder = @{ 'Critical' = 0; 'Warning' = 1; 'Review' = 2; 'Info' = 3 }
        $topFindings = @($allFindings | Sort-Object { $severityOrder[$_.severity] } | Select-Object -First 6)
        $topFindingsJson = ($topFindings | ForEach-Object {
                $cat = ConvertTo-JsonSafe "$($_.category)"
                $sev = ConvertTo-JsonSafe "$($_.severity)"
                $tn = ConvertTo-JsonSafe "$($_.teamName)"
                $det = ConvertTo-JsonSafe "$($_.detail)"
                "{`"category`":`"$cat`",`"severity`":`"$sev`",`"teamName`":`"$tn`",`"detail`":`"$det`"}"
            }) -join ','

        #endregion

        #region ── HTML ───────────────────────────────────────────────────────

        $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Teams Security Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;--border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;--green:#3fb950;--amber:#d29922;--red:#f85149;--text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;--mono:'JetBrains Mono','Consolas','Courier New',monospace;--sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;--radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5)}
body.light-theme{--bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;--border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;--green:#1a7f37;--amber:#b08000;--red:#cf222e;--text:#1f2328;--muted:#636c76;--muted2:#424a53;--shadow:0 4px 24px rgba(0,0,0,.12)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}
#sidebar{position:fixed;top:0;left:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--red),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text)}
.sidebar-logo p{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px}
.version-badge{display:inline-block;margin-top:5px;background:rgba(248,81,73,.15);color:var(--red);font-family:var(--mono);font-size:10px;padding:1px 8px;border-radius:20px;border:1px solid rgba(248,81,73,.3)}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13.5px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.nav-btn .nav-badge{margin-left:auto;background:var(--surface3);color:var(--muted2);font-family:var(--mono);font-size:11px;padding:1px 7px;border-radius:20px}
.nav-btn .nav-badge.danger{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.nav-btn:hover{color:var(--text);background:var(--surface2)}
.nav-btn.active{color:var(--red);background:rgba(248,81,73,.08)}
.nav-btn.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--red);border-radius:0 2px 2px 0}
.theme-toggle-wrap{padding:10px 14px;border-top:1px solid var(--border)}
.theme-toggle{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;transition:all .2s}
.theme-toggle:hover{border-color:var(--red);color:var(--text)}
.toggle-pill{width:34px;height:18px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--muted2);transition:transform .2s,background .2s}
body.light-theme .toggle-pill{background:var(--red)}
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
.btn:hover{border-color:var(--red);color:var(--red);background:rgba(248,81,73,.08)}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}
/* ── Score cards row ── */
.score-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:12px;margin-bottom:20px}
.score-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;display:flex;align-items:center;gap:14px;transition:transform .2s,border-color .2s}
.score-card:hover{transform:translateY(-2px)}
.score-ring-wrap{position:relative;width:52px;height:52px;flex-shrink:0}
.score-ring-wrap svg{width:52px;height:52px}
.score-ring-center{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-family:var(--mono);font-size:13px;font-weight:700}
.score-info{flex:1;min-width:0}
.score-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.score-weight{font-size:10px;color:var(--muted);font-family:var(--mono)}
/* ── Overall posture hero ── */
.posture-hero{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px 24px;display:flex;align-items:center;gap:24px;margin-bottom:20px;flex-wrap:wrap}
.posture-ring-wrap{position:relative;width:96px;height:96px;flex-shrink:0}
.posture-ring-wrap svg{width:96px;height:96px}
.posture-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.posture-score-num{font-family:var(--mono);font-size:26px;font-weight:700;line-height:1}
.posture-score-lbl{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.posture-info{flex:1;min-width:200px}
.posture-info h2{font-size:17px;font-weight:700;margin-bottom:4px}
.posture-info p{font-size:13px;color:var(--muted2);line-height:1.5}
.posture-legend{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.posture-legend-item{display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted2)}
.posture-legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
/* ── Stat cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:25px;font-weight:700;line-height:1}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}
/* ── Charts / panels ── */
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.bar-label{font-size:12.5px;color:var(--muted2);width:130px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:10px;background:var(--surface3);border-radius:5px;overflow:hidden}
.bar-fill{height:100%;border-radius:5px;transition:width .9s ease}
.bar-val{font-family:var(--mono);font-size:11px;color:var(--muted);width:30px;text-align:right;flex-shrink:0}
/* ── Findings list ── */
.finding-row{display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)}
.finding-row:last-child{border-bottom:none}
.finding-body{flex:1;min-width:0}
.finding-team{font-family:var(--mono);font-size:12px;color:var(--accent2);font-weight:600;margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.finding-detail{font-size:12px;color:var(--muted2)}
/* ── Tables ── */
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;padding:8px 11px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--red)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:13px;flex-shrink:0}
.data-table{width:100%;border-collapse:collapse}
.data-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.data-table thead th:hover{color:var(--text)}
.data-table thead th.sort-active{color:var(--red)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.data-table tbody tr{border-bottom:1px solid var(--border);transition:background .15s}
.data-table tbody tr:hover{background:var(--surface2)}
.data-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13.5px}
.td-mono{font-family:var(--mono);font-size:12.5px;color:var(--accent2);font-weight:600}
.td-muted{color:var(--muted2)}
.td-small{color:var(--muted);font-family:var(--mono);font-size:12px;white-space:nowrap}
/* ── Badges ── */
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:600}
.badge-critical{background:rgba(248,81,73,.12);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.badge-warning{background:rgba(210,153,34,.12);color:var(--amber);border:1px solid rgba(210,153,34,.3)}
.badge-review{background:rgba(163,113,247,.12);color:var(--accent3);border:1px solid rgba(163,113,247,.3)}
.badge-info{background:rgba(57,197,207,.12);color:var(--accent2);border:1px solid rgba(57,197,207,.3)}
.badge-ok{background:rgba(63,185,80,.12);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.badge-cat{background:var(--surface3);color:var(--muted2);border:1px solid var(--border);font-size:10.5px}
/* ── MFA empty state ── */
.empty-state{text-align:center;padding:48px 24px;color:var(--muted)}
.empty-state .empty-icon{font-size:40px;margin-bottom:12px}
.empty-state h3{font-size:15px;font-weight:700;color:var(--text);margin-bottom:6px}
.empty-state p{font-size:13px;line-height:1.6;max-width:480px;margin:0 auto}
.empty-state code{font-family:var(--mono);font-size:12px;background:var(--surface2);padding:2px 7px;border-radius:4px;border:1px solid var(--border)}
/* ── Pagination ── */
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:14px}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--red);color:var(--red)}
.page-btn.active{background:var(--red);border-color:var(--red);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}
/* ── Toast ── */
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
    <div class="logo-icon">🛡</div>
    <h1>Teams Security</h1>
    <p>Cloud Identity Toolkit</p>
    <span class="version-badge">v1.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span>Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span>All Findings<span class="nav-badge __FINDINGS_DANGER__">__FINDINGS_COUNT__</span></button>
    <div class="nav-section-label" style="margin-top:6px">Security Areas</div>
    <button class="nav-btn" onclick="showPage('guests',this)"><span class="nav-icon">🌐</span>Guest Access<span class="nav-badge">__GUEST_COUNT__</span></button>
    <button class="nav-btn" onclick="showPage('apps',this)"><span class="nav-icon">🧩</span>Risky Apps<span class="nav-badge __APPS_DANGER__">__APPS_COUNT__</span></button>
    <button class="nav-btn" onclick="showPage('channels',this)"><span class="nav-icon">🔒</span>Channels<span class="nav-badge">__CHANNELS_COUNT__</span></button>
    <button class="nav-btn" onclick="showPage('visibility',this)"><span class="nav-icon">👁</span>Public Teams<span class="nav-badge __VIS_DANGER__">__VIS_COUNT__</span></button>
    <button class="nav-btn" onclick="showPage('ownership',this)"><span class="nav-icon">👤</span>Ownership<span class="nav-badge __OWN_DANGER__">__OWN_COUNT__</span></button>
    <button class="nav-btn" onclick="showPage('mfa',this)"><span class="nav-icon">🔐</span>MFA Status<span class="nav-badge __MFA_DANGER__">__MFA_COUNT__</span></button>
  </div>
  <div class="theme-toggle-wrap">
    <button class="theme-toggle" onclick="toggleTheme()"><span id="themeIcon">🌙</span><span id="themeLabel" style="flex:1;text-align:left">Dark Mode</span><span class="toggle-pill"></span></button>
  </div>
  <div class="sidebar-footer">Generated<br>__GENERATEDAT__<br><span style="color:var(--accent2)">⌨</span> <kbd>/</kbd> search &nbsp;<kbd>Esc</kbd> close</div>
</nav>

<main id="main">

<!-- ══════════════════════════════════════════ OVERVIEW ══════════════════════════════════════════ -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div><div class="page-title">Security Posture Overview</div><div class="page-subtitle">Weighted security score across all Microsoft Teams risk categories</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('findings')">⬇ Export All Findings</button></div>
  </div>

  <!-- Overall posture hero -->
  <div class="posture-hero">
    <div class="posture-ring-wrap">
      <svg viewBox="0 0 96 96"><circle cx="48" cy="48" r="38" fill="none" stroke="var(--surface3)" stroke-width="10"/><circle cx="48" cy="48" r="38" fill="none" stroke="var(--green)" stroke-width="10" stroke-dasharray="238.76" stroke-dashoffset="238.76" stroke-linecap="round" transform="rotate(-90 48 48)" id="postureArc" style="transition:stroke-dashoffset 1.3s ease"/></svg>
      <div class="posture-ring-center"><span class="posture-score-num" id="postureNum">__OVERALL_SCORE__</span><span class="posture-score-lbl">/ 100</span></div>
    </div>
    <div class="posture-info">
      <h2>Overall Security Posture Score</h2>
      <p>Weighted across 5 security domains based on CIS Microsoft 365 Foundations Benchmark and NIST CSF priorities. Higher is better — scores below 70 warrant immediate remediation.</p>
      <div class="posture-legend">
        <span class="posture-legend-item"><span class="posture-legend-dot" style="background:var(--green)"></span>80 – 100 &nbsp;Strong</span>
        <span class="posture-legend-item"><span class="posture-legend-dot" style="background:var(--amber)"></span>50 – 79 &nbsp;Moderate</span>
        <span class="posture-legend-item"><span class="posture-legend-dot" style="background:var(--red)"></span>0 – 49 &nbsp;Critical</span>
      </div>
    </div>
  </div>

  <!-- Per-category score cards -->
  <div class="score-grid" id="scoreCategoryGrid"></div>

  <!-- Stat counts -->
  <div class="stats-grid">
    <div class="stat-card c-red"><div class="stat-icon">🌐</div><div class="stat-value" style="color:var(--red)">__GUEST_COUNT__</div><div class="stat-label">External / Guest Users</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">🧩</div><div class="stat-value" style="color:var(--accent3)">__APPS_COUNT__</div><div class="stat-label">Sideloaded Apps</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">🔒</div><div class="stat-value" style="color:var(--amber)">__CHANNELS_COUNT__</div><div class="stat-label">Private / Shared Channels</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">👁</div><div class="stat-value">__VIS_COUNT__</div><div class="stat-label">Public Teams</div></div>
    <div class="stat-card c-red"><div class="stat-icon">👤</div><div class="stat-value" style="color:var(--red)">__OWN_COUNT__</div><div class="stat-label">Ownerless / Under-Owned</div></div>
    <div class="stat-card c-blue"><div class="stat-icon">🔐</div><div class="stat-value">__MFA_COUNT__</div><div class="stat-label">Owners without MFA</div></div>
  </div>

  <!-- Charts -->
  <div class="chart-grid">
    <div class="panel"><div class="section-title">📉 Risk Score by Category</div><div id="categoryBarChart"></div></div>
    <div class="panel"><div class="section-title">🔥 Top Security Findings</div><div id="topFindingsPanel"></div></div>
  </div>
</section>

<!-- ══════════════════════════════════════════ ALL FINDINGS ══════════════════════════════════════════ -->
<section id="page-findings" class="page">
  <div class="page-header">
    <div><div class="page-title">All Security Findings</div><div class="page-subtitle">Unified view of every risk item across all security categories</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('findings')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="findingsSearch" placeholder="Search findings…" oninput="filterTable('findings')"/></div>
    <select id="findingsCat" onchange="filterTable('findings')">
      <option value="">All Categories</option>
      <option>Ownership</option><option>Guest Access</option><option>App Risk</option>
      <option>Visibility</option><option>Channel</option><option>MFA</option>
    </select>
    <select id="findingsSev" onchange="filterTable('findings')">
      <option value="">All Severities</option>
      <option>Critical</option><option>Warning</option><option>Review</option><option>Info</option>
    </select>
    <button class="btn" onclick="clearFilters('findings')">✕ Clear</button>
    <span class="result-count" id="findingsCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('findings',0,this)">Team<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('findings',1,this)">Category<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('findings',2,this)">Severity<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('findings',3,this)">Detail<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="findingsBody"></tbody></table>
  <div class="pagination" id="findingsPager"></div>
</section>

<!-- ══════════════════════════════════════════ GUESTS ══════════════════════════════════════════ -->
<section id="page-guests" class="page">
  <div class="page-header">
    <div><div class="page-title">Guest &amp; External User Access</div><div class="page-subtitle">Members whose accounts are external (#EXT#) or have Guest role</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('guests')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="guestsSearch" placeholder="Search guests…" oninput="filterTable('guests')"/></div>
    <select id="guestsTeam" onchange="filterTable('guests')"><option value="">All Teams</option></select>
    <button class="btn" onclick="clearFilters('guests')">✕ Clear</button>
    <span class="result-count" id="guestsCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('guests',0,this)">Display Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('guests',1,this)">Email<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('guests',2,this)">Role<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('guests',3,this)">Team<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="guestsBody"></tbody></table>
  <div class="pagination" id="guestsPager"></div>
</section>

<!-- ══════════════════════════════════════════ APPS ══════════════════════════════════════════ -->
<section id="page-apps" class="page">
  <div class="page-header">
    <div><div class="page-title">Risky / Sideloaded Apps</div><div class="page-subtitle">Apps installed outside the official Microsoft Teams App Store</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('apps')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="appsSearch" placeholder="Search apps…" oninput="filterTable('apps')"/></div>
    <select id="appsTeam" onchange="filterTable('apps')"><option value="">All Teams</option></select>
    <button class="btn" onclick="clearFilters('apps')">✕ Clear</button>
    <span class="result-count" id="appsCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('apps',0,this)">App Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('apps',1,this)">Version<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('apps',2,this)">Distribution<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('apps',3,this)">State<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('apps',4,this)">Team<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="appsBody"></tbody></table>
  <div class="pagination" id="appsPager"></div>
</section>

<!-- ══════════════════════════════════════════ CHANNELS ══════════════════════════════════════════ -->
<section id="page-channels" class="page">
  <div class="page-header">
    <div><div class="page-title">Private &amp; Shared Channel Exposure</div><div class="page-subtitle">Channels that restrict or extend access beyond standard membership</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('channels')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="channelsSearch" placeholder="Search channels…" oninput="filterTable('channels')"/></div>
    <select id="channelsType" onchange="filterTable('channels')"><option value="">All Types</option><option>private</option><option>shared</option></select>
    <select id="channelsTeam" onchange="filterTable('channels')"><option value="">All Teams</option></select>
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

<!-- ══════════════════════════════════════════ VISIBILITY ══════════════════════════════════════════ -->
<section id="page-visibility" class="page">
  <div class="page-header">
    <div><div class="page-title">Public Teams</div><div class="page-subtitle">Teams discoverable by all users in the tenant — potential accidental disclosure</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('visibility')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="visibilitySearch" placeholder="Search teams…" oninput="filterTable('visibility')"/></div>
    <button class="btn" onclick="clearFilters('visibility')">✕ Clear</button>
    <span class="result-count" id="visibilityCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('visibility',0,this)">Team Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('visibility',1,this)">Mail<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('visibility',2,this)">Created<span class="sort-arrow">↕</span></th>
  </tr></thead><tbody id="visibilityBody"></tbody></table>
  <div class="pagination" id="visibilityPager"></div>
</section>

<!-- ══════════════════════════════════════════ OWNERSHIP ══════════════════════════════════════════ -->
<section id="page-ownership" class="page">
  <div class="page-header">
    <div><div class="page-title">Ownership Risk</div><div class="page-subtitle">Teams with 0 owners (Critical) or only 1 owner (Warning)</div></div>
    <div class="btn-group"><button class="btn" onclick="exportCSV('ownership')">⬇ Export CSV</button></div>
  </div>
  <div class="toolbar">
    <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="ownershipSearch" placeholder="Search teams…" oninput="filterTable('ownership')"/></div>
    <select id="ownershipRisk" onchange="filterTable('ownership')"><option value="">All Risk Levels</option><option>Critical</option><option>Warning</option></select>
    <button class="btn" onclick="clearFilters('ownership')">✕ Clear</button>
    <span class="result-count" id="ownershipCount"></span>
  </div>
  <table class="data-table"><thead><tr>
    <th onclick="sortTable('ownership',0,this)">Team Name<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('ownership',1,this)">Owner Count<span class="sort-arrow">↕</span></th>
    <th onclick="sortTable('ownership',2,this)">Risk Level<span class="sort-arrow">↕</span></th>
    <th>Recommendation</th>
  </tr></thead><tbody id="ownershipBody"></tbody></table>
  <div class="pagination" id="ownershipPager"></div>
</section>

<!-- ══════════════════════════════════════════ MFA ══════════════════════════════════════════ -->
<section id="page-mfa" class="page">
  <div class="page-header">
    <div><div class="page-title">MFA Status</div><div class="page-subtitle">Owner MFA coverage — requires pre-collected data via -MfaReport</div></div>
    <div class="btn-group" id="mfaExportBtn" style="display:none"><button class="btn" onclick="exportCSV('mfa')">⬇ Export CSV</button></div>
  </div>
  <div id="mfaContent"></div>
</section>

</main>

<div id="toast"><span id="toastIcon">✓</span><span id="toastMsg"></span></div>

<script>
// ── Data ──────────────────────────────────────────────────────────────────────
const FINDINGS   = [__FINDINGS_JSON__];
const GUESTS     = [__GUESTS_JSON__];
const APPS       = [__APPS_JSON__];
const CHANNELS   = [__CHANNELS_JSON__];
const VISIBILITY = [__VISIBILITY_JSON__];
const OWNERSHIP  = [__OWNERSHIP_JSON__];
const MFA        = [__MFA_JSON__];
const MFA_AVAILABLE = __MFA_AVAILABLE__;

const SCORES = {
  overall:    __OVERALL_SCORE__,
  ownership:  __OWNERSHIP_SCORE__,
  guest:      __GUEST_SCORE__,
  app:        __APP_SCORE__,
  visibility: __VISIBILITY_SCORE__,
  channel:    __CHANNEL_SCORE__,
  mfa:        __MFA_SCORE__
};

// ── Navigation ────────────────────────────────────────────────────────────────
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  if(btn)btn.classList.add('active');
}

// ── Theme ─────────────────────────────────────────────────────────────────────
function toggleTheme(){
  document.body.classList.toggle('light-theme');
  const lt=document.body.classList.contains('light-theme');
  document.getElementById('themeIcon').textContent=lt?'☀️':'🌙';
  document.getElementById('themeLabel').textContent=lt?'Light Mode':'Dark Mode';
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function showToast(msg,icon){document.getElementById('toastMsg').textContent=msg;document.getElementById('toastIcon').textContent=icon||'✓';const t=document.getElementById('toast');t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2800);}
function dlFile(c,n,t){const b=new Blob([c],{type:t});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=n;a.click();URL.revokeObjectURL(u);}
function scoreColor(s){return s>=80?'var(--green)':s>=50?'var(--amber)':'var(--red)';}

// ── Badges ────────────────────────────────────────────────────────────────────
function sevBadge(s){
  const m={Critical:'badge-critical',Warning:'badge-warning',Review:'badge-review',Info:'badge-info'};
  return`<span class="badge ${m[s]||'badge-info'}">${escH(s)}</span>`;
}
function catBadge(c){return`<span class="badge badge-cat">${escH(c)}</span>`;}
function chanBadge(t){return t==='private'?'<span class="badge badge-warning">Private</span>':'<span class="badge badge-info">Shared</span>';}
function riskBadge(r){return r==='Critical'?'<span class="badge badge-critical">Critical</span>':'<span class="badge badge-warning">Warning</span>';}
function mfaBadge(v){return v?'<span class="badge badge-ok">✓ Enabled</span>':'<span class="badge badge-critical">✗ Disabled</span>';}

// ── Table state ───────────────────────────────────────────────────────────────
const tableState={
  findings:   {data:FINDINGS,   filtered:FINDINGS,   page:1,pageSize:15,sortCol:-1,sortDir:1},
  guests:     {data:GUESTS,     filtered:GUESTS,     page:1,pageSize:15,sortCol:-1,sortDir:1},
  apps:       {data:APPS,       filtered:APPS,       page:1,pageSize:15,sortCol:-1,sortDir:1},
  channels:   {data:CHANNELS,   filtered:CHANNELS,   page:1,pageSize:15,sortCol:-1,sortDir:1},
  visibility: {data:VISIBILITY, filtered:VISIBILITY, page:1,pageSize:15,sortCol:-1,sortDir:1},
  ownership:  {data:OWNERSHIP,  filtered:OWNERSHIP,  page:1,pageSize:15,sortCol:-1,sortDir:1},
  mfa:        {data:MFA,        filtered:MFA,        page:1,pageSize:15,sortCol:-1,sortDir:1}
};

// ── Render rows ───────────────────────────────────────────────────────────────
function renderRows(key){
  const s=tableState[key];
  const start=(s.page-1)*s.pageSize,slice=s.filtered.slice(start,start+s.pageSize);
  const cnt=document.getElementById(key+'Count');
  if(cnt)cnt.textContent=`${s.filtered.length} result${s.filtered.length!==1?'s':''}`;
  const tbody=document.getElementById(key+'Body');
  if(!tbody)return;
  tbody.innerHTML=slice.map(r=>rowHtml(key,r)).join('');
  renderPager(key);
}

function rowHtml(key,r){
  if(key==='findings')   return`<tr><td class="td-mono">${escH(r.teamName)}</td><td>${catBadge(r.category)}</td><td>${sevBadge(r.severity)}</td><td class="td-muted" style="font-size:12.5px">${escH(r.detail)}</td></tr>`;
  if(key==='guests')     return`<tr><td class="td-mono">${escH(r.name)}</td><td class="td-small">${escH(r.email)}</td><td class="td-small">${escH(r.role)}</td><td class="td-muted">${escH(r.teamName)}</td></tr>`;
  if(key==='apps')       return`<tr><td class="td-mono">${escH(r.name)}</td><td class="td-small">${escH(r.version)}</td><td class="td-small">${escH(r.distribution)}</td><td class="td-small">${escH(r.state)}</td><td class="td-muted">${escH(r.teamName)}</td></tr>`;
  if(key==='channels')   return`<tr><td class="td-mono">${escH(r.name)}</td><td>${chanBadge(r.type)}</td><td class="td-muted">${escH(r.teamName)}</td><td class="td-small">${escH(r.created?r.created.substring(0,10):'')}</td></tr>`;
  if(key==='visibility') return`<tr><td class="td-mono">${escH(r.name)}</td><td class="td-small">${escH(r.mail)}</td><td class="td-small">${escH(r.created?r.created.substring(0,10):'')}</td></tr>`;
  if(key==='ownership')  return`<tr><td class="td-mono">${escH(r.teamName)}</td><td class="td-small">${r.ownerCount}</td><td>${riskBadge(r.riskLevel)}</td><td class="td-muted" style="font-size:12px">${escH(r.recommendation)}</td></tr>`;
  if(key==='mfa')        return`<tr><td class="td-mono">${escH(r.name)}</td><td class="td-small">${escH(r.email)}</td><td>${mfaBadge(r.mfaEnabled)}</td><td class="td-small">${escH(r.role)}</td><td class="td-muted">${escH(r.teamName)}</td></tr>`;
  return'';
}

// ── Filter ────────────────────────────────────────────────────────────────────
function filterTable(key){
  const s=tableState[key];
  const val=id=>(document.getElementById(id)||{value:''}).value;
  const q=val(key+'Search').toLowerCase();
  s.filtered=s.data.filter(r=>{
    if(q && !JSON.stringify(r).toLowerCase().includes(q)) return false;
    if(key==='findings'  && val('findingsCat') && r.category!==val('findingsCat')) return false;
    if(key==='findings'  && val('findingsSev') && r.severity!==val('findingsSev')) return false;
    if(key==='guests'    && val('guestsTeam')  && r.teamName!==val('guestsTeam'))  return false;
    if(key==='apps'      && val('appsTeam')    && r.teamName!==val('appsTeam'))    return false;
    if(key==='channels'  && val('channelsType')&& r.type!==val('channelsType'))    return false;
    if(key==='channels'  && val('channelsTeam')&& r.teamName!==val('channelsTeam'))return false;
    if(key==='ownership' && val('ownershipRisk')&& r.riskLevel!==val('ownershipRisk'))return false;
    return true;
  });
  s.page=1;renderRows(key);
}

function clearFilters(key){
  const ids={
    findings:  ['findingsSearch','findingsCat','findingsSev'],
    guests:    ['guestsSearch','guestsTeam'],
    apps:      ['appsSearch','appsTeam'],
    channels:  ['channelsSearch','channelsType','channelsTeam'],
    visibility:['visibilitySearch'],
    ownership: ['ownershipSearch','ownershipRisk'],
    mfa:       ['mfaSearch']
  };
  (ids[key]||[]).forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  filterTable(key);
}

// ── Sort ──────────────────────────────────────────────────────────────────────
function sortTable(key,col,th){
  const s=tableState[key];
  const cols={
    findings:  ['teamName','category','severity','detail'],
    guests:    ['name','email','role','teamName'],
    apps:      ['name','version','distribution','state','teamName'],
    channels:  ['name','type','teamName','created'],
    visibility:['name','mail','created'],
    ownership: ['teamName','ownerCount','riskLevel'],
    mfa:       ['name','email','mfaEnabled','role','teamName']
  };
  const field=cols[key][col];
  s.sortDir=(s.sortCol===col)?-s.sortDir:1;s.sortCol=col;
  s.filtered.sort((a,b)=>{const av=String(a[field]||'').toLowerCase(),bv=String(b[field]||'').toLowerCase();return av<bv?-s.sortDir:av>bv?s.sortDir:0;});
  document.querySelectorAll('#page-'+key+' .data-table th').forEach((h,i)=>{h.classList.toggle('sort-active',i===col);const arr=h.querySelector('.sort-arrow');if(arr)arr.textContent=i===col?(s.sortDir===1?'↑':'↓'):'↕';});
  s.page=1;renderRows(key);
}

// ── Pagination ────────────────────────────────────────────────────────────────
function renderPager(key){
  const s=tableState[key];const pages=Math.ceil(s.filtered.length/s.pageSize)||1;
  const el=document.getElementById(key+'Pager');if(!el)return;
  let h=`<button class="page-btn" onclick="gotoPage('${key}',${s.page-1})" ${s.page===1?'disabled':''}>◀</button>`;
  for(let i=1;i<=pages;i++){if(i===1||i===pages||Math.abs(i-s.page)<=1)h+=`<button class="page-btn${i===s.page?' active':''}" onclick="gotoPage('${key}',${i})">${i}</button>`;else if(Math.abs(i-s.page)===2)h+=`<span style="color:var(--muted);padding:0 4px">…</span>`;}
  h+=`<button class="page-btn" onclick="gotoPage('${key}',${s.page+1})" ${s.page===pages?'disabled':''}>▶</button>`;
  el.innerHTML=h;
}
function gotoPage(key,p){const s=tableState[key];const pages=Math.ceil(s.filtered.length/s.pageSize)||1;s.page=Math.max(1,Math.min(p,pages));renderRows(key);}

// ── CSV Export ────────────────────────────────────────────────────────────────
function exportCSV(key){
  const s=tableState[key];const data=s.filtered;
  const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;
  let h='',rows=[];
  if(key==='findings')   {h='Team,Category,Severity,Detail';rows=data.map(r=>[esc(r.teamName),esc(r.category),esc(r.severity),esc(r.detail)].join(','));}
  if(key==='guests')     {h='Name,Email,Role,Team';rows=data.map(r=>[esc(r.name),esc(r.email),esc(r.role),esc(r.teamName)].join(','));}
  if(key==='apps')       {h='AppName,Version,Distribution,State,Team';rows=data.map(r=>[esc(r.name),esc(r.version),esc(r.distribution),esc(r.state),esc(r.teamName)].join(','));}
  if(key==='channels')   {h='Channel,Type,Team,Created';rows=data.map(r=>[esc(r.name),esc(r.type),esc(r.teamName),esc(r.created)].join(','));}
  if(key==='visibility') {h='TeamName,Mail,Created';rows=data.map(r=>[esc(r.name),esc(r.mail),esc(r.created)].join(','));}
  if(key==='ownership')  {h='Team,OwnerCount,RiskLevel,Recommendation';rows=data.map(r=>[esc(r.teamName),r.ownerCount,esc(r.riskLevel),esc(r.recommendation)].join(','));}
  if(key==='mfa')        {h='Name,Email,MfaEnabled,Role,Team';rows=data.map(r=>[esc(r.name),esc(r.email),r.mfaEnabled,esc(r.role),esc(r.teamName)].join(','));}
  dlFile([h,...rows].join('\r\n'),`Teams_Security_${key}_${new Date().toISOString().substring(0,10)}.csv`,'text/csv');
  showToast(`Exported ${data.length} rows as CSV`);
}

// ── Dynamic dropdowns ─────────────────────────────────────────────────────────
function populateDynamicDropdowns(){
  const fill=(elId,items)=>{const el=document.getElementById(elId);if(!el)return;[...new Set(items.filter(Boolean))].sort().forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;el.appendChild(o);});};
  fill('guestsTeam',   GUESTS.map(r=>r.teamName));
  fill('appsTeam',     APPS.map(r=>r.teamName));
  fill('channelsTeam', CHANNELS.map(r=>r.teamName));
}

// ── Overview: posture ring ─────────────────────────────────────────────────────
(function initOverview(){
  const score=SCORES.overall;
  const col=scoreColor(score);
  const arc=238.76, offset=arc-(arc*(score/100));
  const arcEl=document.getElementById('postureArc');
  if(arcEl){arcEl.style.stroke=col;setTimeout(()=>{arcEl.style.strokeDashoffset=offset;},120);}
  const numEl=document.getElementById('postureNum');
  if(numEl)numEl.style.color=col;

  // Per-category score cards
  const cats=[
    {key:'ownership', label:'Ownership Risk',   weight:'30%', icon:'👤'},
    {key:'guest',     label:'Guest Access',      weight:'25%', icon:'🌐'},
    {key:'app',       label:'App Risk',           weight:'25%', icon:'🧩'},
    {key:'visibility',label:'Visibility Risk',   weight:'10%', icon:'👁'},
    {key:'channel',   label:'Channel Exposure',  weight:'10%', icon:'🔒'},
    {key:'mfa',       label:'MFA Coverage',      weight:'—',   icon:'🔐'}
  ];
  const grid=document.getElementById('scoreCategoryGrid');
  if(grid){
    grid.innerHTML=cats.map(c=>{
      const sv=SCORES[c.key];
      const isUnknown=(sv===-1);
      const display=isUnknown?'N/A':sv;
      const col2=isUnknown?'var(--muted)':scoreColor(sv);
      const circumference=2*Math.PI*20; // r=20 for small rings
      const dashOffset=isUnknown?circumference:circumference-(circumference*(sv/100));
      return`<div class="score-card">
        <div class="score-ring-wrap">
          <svg viewBox="0 0 52 52"><circle cx="26" cy="26" r="20" fill="none" stroke="var(--surface3)" stroke-width="6"/><circle cx="26" cy="26" r="20" fill="none" stroke="${col2}" stroke-width="6" stroke-dasharray="${circumference.toFixed(2)}" stroke-dashoffset="${circumference.toFixed(2)}" stroke-linecap="round" transform="rotate(-90 26 26)" class="score-arc" data-offset="${dashOffset.toFixed(2)}" style="transition:stroke-dashoffset 1s ease"/></svg>
          <div class="score-ring-center" style="color:${col2};font-size:${isUnknown?'10px':'13px'}">${display}</div>
        </div>
        <div class="score-info"><div class="score-label">${c.icon} ${c.label}</div><div class="score-weight">Weight: ${c.weight}${isUnknown?' · No data':''}</div></div>
      </div>`;
    }).join('');
    setTimeout(()=>{document.querySelectorAll('.score-arc').forEach(el=>{el.style.strokeDashoffset=el.dataset.offset;});},150);
  }

  // Category bar chart (inverted — shows risk level: 100 - score)
  const barData=[
    {l:'Ownership Risk (30%)',  v:100-SCORES.ownership,  c:'var(--red)'},
    {l:'Guest Access (25%)',    v:100-SCORES.guest,      c:'var(--amber)'},
    {l:'App Risk (25%)',        v:100-SCORES.app,        c:'var(--accent3)'},
    {l:'Visibility Risk (10%)',v:100-SCORES.visibility,  c:'var(--accent2)'},
    {l:'Channel Exp. (10%)',    v:100-SCORES.channel,    c:'var(--accent)'}
  ];
  const barMax=Math.max(...barData.map(b=>b.v),1);
  document.getElementById('categoryBarChart').innerHTML=barData.map(b=>
    `<div class="bar-row"><span class="bar-label" title="${b.l}">${b.l}</span><div class="bar-track"><div class="bar-fill" style="width:0%;background:${b.c}" data-pct="${Math.round(b.v/barMax*100)}"></div></div><span class="bar-val">${b.v}</span></div>`
  ).join('');

  // Top findings panel
  const TOP=[__TOP_FINDINGS_JSON__];
  document.getElementById('topFindingsPanel').innerHTML=TOP.length
    ?TOP.map(f=>`<div class="finding-row">${sevBadge(f.severity)}<div class="finding-body"><div class="finding-team">${escH(f.teamName)}</div><div class="finding-detail">${catBadge(f.category)} ${escH(f.detail)}</div></div></div>`).join('')
    :'<p style="color:var(--green);font-size:13px;padding:8px 0">✅ No critical findings detected.</p>';

  requestAnimationFrame(()=>{document.querySelectorAll('.bar-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';});});
})();

// ── MFA tab setup ─────────────────────────────────────────────────────────────
(function initMfa(){
  const wrap=document.getElementById('mfaContent');
  if(!wrap)return;
  if(!MFA_AVAILABLE||MFA.length===0){
    wrap.innerHTML=`<div class="empty-state"><div class="empty-icon">🔐</div><h3>MFA Data Not Available</h3><p>MFA status checks are not performed live by this dashboard because <code>UserAuthenticationMethod.Read.All</code> is commonly restricted in enterprise tenants.<br><br>To populate this tab, collect MFA data separately and pass it via the <code>-MfaReport</code> parameter:</p><br><p style="font-family:var(--mono);font-size:12px;background:var(--surface2);padding:12px 16px;border-radius:var(--radius-sm);border:1px solid var(--border);text-align:left;line-height:2">Generate-TeamSecurityDashboard -AccessToken $token -MfaReport $mfaData -OpenBrowser</p><br><p>Each record in <code>-MfaReport</code> must include: <code>teamId, teamDisplayName, displayName, email, role, mfaEnabled</code></p></div>`;
    return;
  }
  document.getElementById('mfaExportBtn').style.display='flex';
  wrap.innerHTML=`
    <div class="toolbar">
      <div class="search-wrap"><span class="icon">🔍</span><input type="text" id="mfaSearch" placeholder="Search owners…" oninput="filterTable('mfa')"/></div>
      <select id="mfaStatus" onchange="filterTable('mfa')"><option value="">All MFA Status</option><option value="true">MFA Enabled</option><option value="false">MFA Disabled</option></select>
      <button class="btn" onclick="clearFilters('mfa')">✕ Clear</button>
      <span class="result-count" id="mfaCount"></span>
    </div>
    <table class="data-table"><thead><tr>
      <th onclick="sortTable('mfa',0,this)">Name<span class="sort-arrow">↕</span></th>
      <th onclick="sortTable('mfa',1,this)">Email<span class="sort-arrow">↕</span></th>
      <th onclick="sortTable('mfa',2,this)">MFA Status<span class="sort-arrow">↕</span></th>
      <th onclick="sortTable('mfa',3,this)">Role<span class="sort-arrow">↕</span></th>
      <th onclick="sortTable('mfa',4,this)">Team<span class="sort-arrow">↕</span></th>
    </tr></thead><tbody id="mfaBody"></tbody></table>
    <div class="pagination" id="mfaPager"></div>`;
  renderRows('mfa');
})();

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){e.preventDefault();const inp=document.querySelector('.page.active input[type=text]');if(inp)inp.focus();}
  if(e.key==='Escape'){const inp=document.activeElement;if(inp&&inp.tagName==='INPUT')inp.blur();}
});

// ── Init ──────────────────────────────────────────────────────────────────────
['findings','guests','apps','channels','visibility','ownership'].forEach(k=>renderRows(k));
populateDynamicDropdowns();
</script>
</body>
</html>
'@

        #endregion

        #region ── Token Substitution ─────────────────────────────────────────

        # Sidebar badge danger class helpers (red highlight when count > 0)
        $findingsDanger = if (@($allFindings).Count -gt 0) { 'danger' } else { '' }
        $appsDanger = if ($totalRiskyApps -gt 0) { 'danger' } else { '' }
        $visDanger = if ($totalPublicTeams -gt 0) { 'danger' } else { '' }
        $ownDanger = if ($totalOwnerlessRisk -gt 0) { 'danger' } else { '' }
        $mfaDanger = if ($totalMfaDisabled -gt 0) { 'danger' } else { '' }
        $mfaScoreJs = if ($mfaScore -ge 0) { $mfaScore } else { -1 }

        $html = $html `
            -replace '__OVERALL_SCORE__', $overallScore        `
            -replace '__OWNERSHIP_SCORE__', $ownershipScore      `
            -replace '__GUEST_SCORE__', $guestScore          `
            -replace '__APP_SCORE__', $appScore            `
            -replace '__VISIBILITY_SCORE__', $visibilityScore     `
            -replace '__CHANNEL_SCORE__', $channelScore        `
            -replace '__MFA_SCORE__', $mfaScoreJs          `
            -replace '__MFA_AVAILABLE__', $mfaDataAvailable    `
            -replace '__FINDINGS_COUNT__', @($allFindings).Count `
            -replace '__GUEST_COUNT__', $totalGuestCount     `
            -replace '__APPS_COUNT__', $totalRiskyApps      `
            -replace '__CHANNELS_COUNT__', $totalExposedChans   `
            -replace '__VIS_COUNT__', $totalPublicTeams    `
            -replace '__OWN_COUNT__', $totalOwnerlessRisk  `
            -replace '__MFA_COUNT__', $totalMfaDisabled    `
            -replace '__FINDINGS_DANGER__', $findingsDanger      `
            -replace '__APPS_DANGER__', $appsDanger          `
            -replace '__VIS_DANGER__', $visDanger           `
            -replace '__OWN_DANGER__', $ownDanger           `
            -replace '__MFA_DANGER__', $mfaDanger           `
            -replace '__GENERATEDAT__', $generatedAt         `
            -replace '__FINDINGS_JSON__', $findingsJson        `
            -replace '__GUESTS_JSON__', $guestsJson          `
            -replace '__APPS_JSON__', $appsJson            `
            -replace '__CHANNELS_JSON__', $channelsJson        `
            -replace '__VISIBILITY_JSON__', $visibilityJson      `
            -replace '__OWNERSHIP_JSON__', $ownerlessJson       `
            -replace '__MFA_JSON__', $mfaJson             `
            -replace '__TOP_FINDINGS_JSON__', $topFindingsJson

        #endregion

        #region ── Output ─────────────────────────────────────────────────────

        Try {
            $outFolder = Split-Path -Path $OutputPath -Parent
            if ($outFolder -and -not (Test-Path -Path $outFolder)) {
                New-Item -Path $outFolder -ItemType Directory -Force | Out-Null
            }
            $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

            $scoreColor = if ($overallScore -ge 80) { 'Green' } elseif ($overallScore -ge 50) { 'Yellow' } else { 'Red' }

            Write-Host ""
            Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
            Write-Host "║   ✅  Teams Security Dashboard — generated!          ║" -ForegroundColor Green
            Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
            Write-Host ""
            Write-Host "  🛡  Security Posture Score : $overallScore / 100"         -ForegroundColor $scoreColor
            Write-Host "  ──────────────────────────────────────────────────"       -ForegroundColor DarkGray
            Write-Host "  👤  Ownership Score        : $ownershipScore / 100  (30%)" -ForegroundColor White
            Write-Host "  🌐  Guest Access Score     : $guestScore / 100  (25%)"    -ForegroundColor White
            Write-Host "  🧩  App Risk Score         : $appScore / 100  (25%)"      -ForegroundColor White
            Write-Host "  👁  Visibility Score       : $visibilityScore / 100  (10%)" -ForegroundColor White
            Write-Host "  🔒  Channel Score          : $channelScore / 100  (10%)"  -ForegroundColor White
            if ($mfaScore -ge 0) {
                Write-Host "  🔐  MFA Score              : $mfaScore / 100  (display only)" -ForegroundColor White
            }
            Write-Host "  ──────────────────────────────────────────────────"       -ForegroundColor DarkGray
            Write-Host "  🌐  Guest Users            : $totalGuestCount"            -ForegroundColor White
            Write-Host "  🧩  Sideloaded Apps        : $totalRiskyApps"             -ForegroundColor White
            Write-Host "  🔒  Exposed Channels       : $totalExposedChans"          -ForegroundColor White
            Write-Host "  👁  Public Teams           : $totalPublicTeams"           -ForegroundColor White
            Write-Host "  👤  Ownership Risk Teams   : $totalOwnerlessRisk"         -ForegroundColor White
            Write-Host "  🔍  Total Findings         : $(@($allFindings).Count)"    -ForegroundColor White
            Write-Host "  📁  Output                 : $OutputPath"                 -ForegroundColor White
            Write-Host ""

            if ($OpenBrowser) { Start-Process $OutputPath }
        }
        Catch {
            Write-Error "Failed to write dashboard: $($_.Exception.Message)"
        }

        #endregion
    }
}
