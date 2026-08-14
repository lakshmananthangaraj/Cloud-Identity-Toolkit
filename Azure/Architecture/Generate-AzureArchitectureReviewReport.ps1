<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 14 August 2026
Modified-On     : 14 August 2026

.SYNOPSIS
    Generates a structured architecture review report covering identity, networking,
    security, governance, resilience, cost, and observability across Azure subscriptions,
    with per-pillar scoring and an interactive HTML dashboard.

.DESCRIPTION
    Generate-AzureArchitectureReviewReport performs a Well-Architected-aligned
    architecture review across one or more Azure subscriptions. It evaluates seven
    review pillars and produces per-pillar scores, per-finding details, and an
    executive summary suitable for architecture board presentations.

    Review pillars and what is checked:
        Identity & Access   — RBAC assignments, custom roles, privileged identities,
                              guest accounts, service principal credential expiry
        Networking          — NSG coverage, public IP exposure, VNet peering topology,
                              Private Endpoint adoption, DDoS protection plans
        Security            — Defender for Cloud tier, security contacts, Just-in-Time
                              VM access, disk encryption, key vault usage
        Governance          — Policy assignment coverage, management group structure,
                              tagging compliance, cost alerts, budget configuration
        Resilience          — Availability zones, backup coverage, ASR replication,
                              cross-region redundancy, SLA-tier SKUs
        Cost                — Reserved instance adoption, right-sizing signals,
                              Advisor cost recommendations, idle resource detection
        Observability       — Log Analytics workspace coverage, diagnostic settings,
                              alert rules, Application Insights adoption, ITSM connector

    Each pillar produces a score (0–100) and a list of findings with severity
    (Critical / High / Medium / Low / Informational). An executive summary card
    and a radar-style score table are included in the HTML dashboard.

    Optional live data (-IncludeLiveChecks switch):
        - Calls additional Az cmdlets for Advisor recommendations, Defender plans,
          and JIT VM access status. Disabled by default for speed.
        - If any live call fails, the check is marked "Not Assessed / Warning"
          and the review continues without interruption.

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of all findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          pillar score cards, finding detail drawer, executive summary)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER IncludeLiveChecks
    Switch. When specified, calls additional Az cmdlets for Advisor recommendations,
    Defender plan tiers, and JIT VM access status. Disabled by default.
    If a call fails, that check is marked "Not Assessed / Warning" and the
    review continues.

.PARAMETER ExportToCsv
    Switch. If specified, exports all architecture review findings to the path
    given in -CsvPath. The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzureArchitectureReview-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Generate-AzureArchitectureReviewReport -AllSubscriptions

.EXAMPLE
    Generate-AzureArchitectureReviewReport -AllSubscriptions -IncludeLiveChecks

.EXAMPLE
    Generate-AzureArchitectureReviewReport -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Generate-AzureArchitectureReviewReport -AllSubscriptions -IncludeLiveChecks -ExportToCsv -CsvPath "C:\Reports\ArchReview.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (14-Aug-2026) - Initial release. Seven-pillar architecture review
                            covering Identity, Networking, Security, Governance,
                            Resilience, Cost, and Observability. Optional live
                            checks via -IncludeLiveChecks. CSV export and
                            interactive HTML dashboard with executive summary.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.Network,
           Az.Monitor, Az.RecoveryServices, Az.Billing) — installed automatically
           with user consent if not present.
        2. Az.Security and Az.Advisor are required for -IncludeLiveChecks.
        3. Authenticated Azure session (Connect-AzAccount).
        4. Reader role (minimum) at the subscription level.
        5. Microsoft.Authorization/roleAssignments/read at subscription scope.
        6. For full Networking checks, Microsoft.Network/*/read is required.
        7. Live Advisor checks require Microsoft.Advisor/recommendations/read.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Management Group-level role assignments are not enumerated by
          Get-AzRoleAssignment when called at subscription context.
        - Cost pillar checks are heuristic; no billing API calls are made by
          default. Use -IncludeLiveChecks to retrieve Advisor cost recommendations.
        - Pillar scores are approximations based on control presence across the
          subscription. A higher score does not guarantee architectural excellence.
        - Radar chart in the HTML dashboard is table-based; a canvas radar chart
          would require JavaScript charting libraries not bundled in the output.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Guest user enumeration requires Azure AD / Entra ID read permissions
          not always available at the subscription scope via Az module alone.

.LINK
    https://learn.microsoft.com/en-us/azure/well-architected/
    https://learn.microsoft.com/en-us/azure/architecture/framework/
    https://learn.microsoft.com/en-us/azure/advisor/advisor-overview
    https://learn.microsoft.com/en-us/azure/governance/policy/overview
    https://learn.microsoft.com/en-us/azure/security/fundamentals/overview

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CenteredText
{
    param(
        [string]$Text,
        [int]$Width = 80,
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
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Architecture Review Report v1.0" -Color White
    Write-Host ("=" * 80) -ForegroundColor Cyan
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
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys)
    {
        $value = $Data[$key]
        if ([string]::IsNullOrWhiteSpace($value))
        {
            $value    = "None"
            $valColor = "DarkGray"
        }
        else
        {
            $valColor = "White"
        }

        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(30) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-ScanProgress
{
    Write-Host ""
    Write-Host "  Running Architecture Review" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray
    Write-Host ""
}

Function Write-ProgressBar
{
    param(
        [int]$Current,
        [int]$Total,
        [string]$CurrentItem,
        [int]$BarWidth = 40
    )

    $percentage = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
    $completed   = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $remaining   = $BarWidth - $completed
    $bar         = ("x" * $completed) + ("." * $remaining)

    Write-Host "`r" -NoNewline
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White

    if ($CurrentItem)
    {
        $maxLen      = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLen) { $CurrentItem.Substring(0, $maxLen - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-Summary
{
    param([hashtable]$Data)

    Write-Host ""
    Write-Host "  Review Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys)
    {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(38) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-PillarScores
{
    param([hashtable]$Scores)

    Write-Host ""
    Write-Host "  Pillar Scores" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    foreach ($pillar in $Scores.GetEnumerator() | Sort-Object Value)
    {
        $score = $pillar.Value
        $color = if ($score -ge 80) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" }
        $bar   = ("=" * [math]::Floor($score / 5)).PadRight(20)
        Write-Host "  " -NoNewline
        Write-Host $pillar.Key.PadRight(24) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $bar -NoNewline -ForegroundColor $color
        Write-Host " $score/100" -ForegroundColor $color
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
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    if ($CsvPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "v " -NoNewline -ForegroundColor Green
        Write-Host ("CSV Export").PadRight(24) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }

    if ($HtmlPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "v " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Report").PadRight(24) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }

    if ($GridViewOpened)
    {
        Write-Host "  " -NoNewline
        Write-Host "v " -NoNewline -ForegroundColor Green
        Write-Host ("Grid View").PadRight(24) -NoNewline -ForegroundColor Gray
        Write-Host ": Opened in separate window" -ForegroundColor White
    }

    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-ObjProperty
{
    param(
        [object]$Obj,
        [string]$PropName,
        $Default = $null
    )
    try
    {
        $val = $Obj.$PropName
        if ($null -ne $val) { return $val }
        return $Default
    }
    catch { return $Default }
}

Function New-Finding
{
    param(
        [string]$Pillar,
        [string]$CheckName,
        [string]$Severity,
        [string]$Status,
        [string]$Detail,
        [string]$Recommendation,
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$Resource = ""
    )
    return [pscustomobject]@{
        Pillar           = $Pillar
        CheckName        = $CheckName
        Severity         = $Severity
        Status           = $Status
        Detail           = $Detail
        Recommendation   = $Recommendation
        SubscriptionName = $SubscriptionName
        SubscriptionId   = $SubscriptionId
        Resource         = $Resource
    }
}

Function Compute-PillarScore
{
    param([array]$PillarFindings)

    if ($PillarFindings.Count -eq 0) { return 100 }

    $deductions = 0
    foreach ($f in $PillarFindings)
    {
        switch ($f.Severity)
        {
            "Critical" { $deductions += 25 }
            "High"     { $deductions += 15 }
            "Medium"   { $deductions += 8  }
            "Low"      { $deductions += 3  }
        }
    }
    return [math]::Max(0, [math]::Min(100, 100 - $deductions))
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\','\\\\' -replace "'","\'" -replace '"','\"' -replace "`n",' ' -replace "`r",' ' }

Function Generate-ArchitectureReviewHtml
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [hashtable]$PillarScores,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [bool]$LiveChecksIncluded
    )

    $totalFindings   = @($Findings).Count
    $criticalCount   = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount       = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount     = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $overallScore    = if ($PillarScores.Count -gt 0) {
        [math]::Round(($PillarScores.Values | Measure-Object -Average).Average)
    } else { 0 }

    $liveCheckBadge = if ($LiveChecksIncluded) {
        '<span class="badge badge-green">v Included</span>'
    } else {
        '<span class="badge badge-amber">! Skipped (use -IncludeLiveChecks)</span>'
    }
    $liveCheckText = if ($LiveChecksIncluded) { "Included" } else { "Skipped - use -IncludeLiveChecks to enable" }

    # ── Pillar definitions ────────────────────────────────────────────────────
    $pillarOrder  = @("Identity & Access", "Networking", "Security", "Governance", "Resilience", "Cost", "Observability")
    $pillarIcons  = @{
        "Identity & Access" = "&#128272;"
        "Networking"        = "&#127760;"
        "Security"          = "&#128737;"
        "Governance"        = "&#128196;"
        "Resilience"        = "&#9889;"
        "Cost"              = "&#128181;"
        "Observability"     = "&#128200;"
    }

    # ── Pillar score cards ────────────────────────────────────────────────────
    $pillarCards = ""
    foreach ($pillar in $pillarOrder)
    {
        $score     = if ($PillarScores.ContainsKey($pillar)) { $PillarScores[$pillar] } else { 0 }
        $colorVar  = if ($score -ge 80) { "var(--green)" } elseif ($score -ge 50) { "var(--amber)" } else { "var(--red)" }
        $cardCls   = if ($score -ge 80) { "c-green" } elseif ($score -ge 50) { "c-amber" } else { "c-red" }
        $icon      = if ($pillarIcons.ContainsKey($pillar)) { $pillarIcons[$pillar] } else { "&#9679;" }
        $circum    = [math]::Round(2 * [math]::PI * 30, 0)   # r=30  circumference ~188
        $offset    = [math]::Round($circum * (1 - $score / 100), 0)

        $pillarCards += @"
      <div class="pillar-card $cardCls">
        <div class="pillar-icon">$icon</div>
        <div class="pillar-name">$(EscHtml $pillar)</div>
        <div class="pillar-ring-wrap">
          <svg width="72" height="72" viewBox="0 0 72 72">
            <circle cx="36" cy="36" r="30" fill="none" stroke="var(--surface3)" stroke-width="7"/>
            <circle cx="36" cy="36" r="30" fill="none" stroke="$colorVar" stroke-width="7"
              stroke-dasharray="$circum" stroke-dashoffset="$offset" stroke-linecap="round" transform="rotate(-90 36 36)"/>
          </svg>
          <div class="pillar-ring-text">
            <div class="pillar-score" style="color:$colorVar">$score</div>
            <div class="pillar-score-lbl">/100</div>
          </div>
        </div>
        <div class="pillar-find-count">$(EscHtml (@($Findings | Where-Object { $_.Pillar -eq $pillar }).Count).ToString()) findings</div>
      </div>
"@
    }

    # ── Finding table rows ────────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings)
    {
        $sevCls = switch ($f.Severity) {
            "Critical"      { "badge-red" }
            "High"          { "badge-amber" }
            "Medium"        { "badge-blue" }
            "Low"           { "badge-green" }
            "Informational" { "" }
            default         { "" }
        }
        $stsCls = switch ($f.Status) {
            "Fail"          { "badge-red" }
            "Warning"       { "badge-amber" }
            "Pass"          { "badge-green" }
            "Not Assessed"  { "" }
            default         { "" }
        }
        $findingRows += @"
          <tr onclick="showFindingDetail($($Findings.IndexOf($f)))">
            <td>$(EscHtml $f.Pillar)</td>
            <td title="$(EscHtml $f.CheckName)">$(if ($f.CheckName.Length -gt 38) { EscHtml($f.CheckName.Substring(0,35)+"...") } else { EscHtml $f.CheckName })</td>
            <td><span class="badge $sevCls">$(EscHtml $f.Severity)</span></td>
            <td><span class="badge $stsCls">$(EscHtml $f.Status)</span></td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td title="$(EscHtml $f.Resource)">$(if ($f.Resource.Length -gt 28) { EscHtml($f.Resource.Substring(0,25)+"...") } else { EscHtml $f.Resource })</td>
          </tr>
"@
    }

    # ── Severity distribution bars ────────────────────────────────────────────
    $sevTotal = @($Findings).Count
    $sevRows  = ""
    foreach ($sev in @("Critical", "High", "Medium", "Low", "Informational"))
    {
        $cnt   = @($Findings | Where-Object { $_.Severity -eq $sev }).Count
        $pct   = if ($sevTotal -gt 0) { [math]::Round(($cnt / $sevTotal) * 100) } else { 0 }
        $color = switch ($sev) { "Critical" { "var(--red)" }; "High" { "var(--amber)" }; "Medium" { "var(--accent)" }; "Low" { "var(--green)" }; default { "var(--muted)" } }
        $sevRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $sev)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$color"></div></div>
            <span class="bar-pct">$cnt ($pct%)</span>
          </div>
"@
    }

    # ── Pillar finding distribution bars ──────────────────────────────────────
    $pillarFindRows = ""
    foreach ($pillar in $pillarOrder)
    {
        $cnt   = @($Findings | Where-Object { $_.Pillar -eq $pillar }).Count
        $pct   = if ($sevTotal -gt 0) { [math]::Round(($cnt / $sevTotal) * 100) } else { 0 }
        $pillarFindRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $pillar)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$cnt ($pct%)</span>
          </div>
"@
    }

    # ── Pillar score bar rows ─────────────────────────────────────────────────
    $pillarScoreRows = ""
    foreach ($pillar in $pillarOrder)
    {
        $score  = if ($PillarScores.ContainsKey($pillar)) { $PillarScores[$pillar] } else { 0 }
        $color  = if ($score -ge 80) { "var(--green)" } elseif ($score -ge 50) { "var(--amber)" } else { "var(--red)" }
        $pillarScoreRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $pillar)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$score" style="background:$color"></div></div>
            <span class="bar-pct">$score/100</span>
          </div>
"@
    }

    # ── Exec summary table rows ───────────────────────────────────────────────
    $execRows = ""
    foreach ($pillar in $pillarOrder)
    {
        $score    = if ($PillarScores.ContainsKey($pillar)) { $PillarScores[$pillar] } else { 0 }
        $pFinds   = @($Findings | Where-Object { $_.Pillar -eq $pillar })
        $critF    = @($pFinds | Where-Object { $_.Severity -eq "Critical" }).Count
        $highF    = @($pFinds | Where-Object { $_.Severity -eq "High" }).Count
        $rating   = if ($score -ge 80) { "Good" } elseif ($score -ge 60) { "Needs Attention" } elseif ($score -ge 40) { "At Risk" } else { "Critical" }
        $ratCls   = if ($score -ge 80) { "badge-green" } elseif ($score -ge 60) { "badge-blue" } elseif ($score -ge 40) { "badge-amber" } else { "badge-red" }
        $sColor   = if ($score -ge 80) { "var(--green)" } elseif ($score -ge 50) { "var(--amber)" } else { "var(--red)" }
        $icon     = if ($pillarIcons.ContainsKey($pillar)) { $pillarIcons[$pillar] } else { "" }

        $execRows += @"
          <tr>
            <td>$icon $(EscHtml $pillar)</td>
            <td><span style="font-family:var(--mono);font-weight:700;color:$sColor">$score</span></td>
            <td><span class="badge $ratCls">$(EscHtml $rating)</span></td>
            <td>$($pFinds.Count)</td>
            <td style="color:var(--red)">$critF</td>
            <td style="color:var(--amber)">$highF</td>
          </tr>
"@
    }

    # ── Subscription results ──────────────────────────────────────────────────
    $subRows = ""
    foreach ($s in $SubscriptionResults)
    {
        $icon = switch ($s.Status) { "Success" { "v" }; "Warning" { "!" }; "Error" { "x" }; default { "*" } }
        $cls  = switch ($s.Status) { "Success" { "c-green" }; "Warning" { "c-amber" }; "Error" { "c-red" }; default { "" } }
        $subRows += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $s.Name)</span>
            <span class="sub-detail">$(EscHtml $s.Summary)</span>
          </div>
"@
    }

    # ── JSON for detail drawer ────────────────────────────────────────────────
    $findJson = "["
    foreach ($f in $Findings)
    {
        $findJson += "{" +
            """pillar"":""$(EscJ $f.Pillar)""," +
            """check"":""$(EscJ $f.CheckName)""," +
            """sev"":""$(EscJ $f.Severity)""," +
            """status"":""$(EscJ $f.Status)""," +
            """detail"":""$(EscJ $f.Detail)""," +
            """rec"":""$(EscJ $f.Recommendation)""," +
            """sub"":""$(EscJ $f.SubscriptionName)""," +
            """resource"":""$(EscJ $f.Resource)""" +
            "},"
    }
    $findJson = $findJson.TrimEnd(",") + "]"

    # ── Overall score ring math ───────────────────────────────────────────────
    $circumference  = [math]::Round(2 * [math]::PI * 46, 0)
    $dashOffset     = [math]::Round($circumference * (1 - $overallScore / 100), 0)
    $scoreColor     = if ($overallScore -ge 80) { "#3fb950" } elseif ($overallScore -ge 50) { "#d29922" } else { "#f85149" }
    $overallRating  = if ($overallScore -ge 80) { "Good" } elseif ($overallScore -ge 60) { "Needs Attention" } elseif ($overallScore -ge 40) { "At Risk" } else { "Critical" }

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Architecture Review Report</title>
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
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent3));display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
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
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-num{font-size:30px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:140px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:80px;text-align:right;flex-shrink:0;}
.pillar-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:22px;}
.pillar-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center;border-top:3px solid;transition:transform .15s,box-shadow .15s;cursor:default;}
.pillar-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.pillar-card.c-green{border-top-color:var(--green);}
.pillar-card.c-amber{border-top-color:var(--amber);}
.pillar-card.c-red{border-top-color:var(--red);}
.pillar-icon{font-size:22px;margin-bottom:6px;}
.pillar-name{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--muted2);margin-bottom:10px;}
.pillar-ring-wrap{position:relative;width:72px;height:72px;margin:0 auto 8px;}
.pillar-ring-text{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;}
.pillar-score{font-size:18px;font-weight:700;font-family:var(--mono);line-height:1;}
.pillar-score-lbl{font-size:9px;color:var(--muted);}
.pillar-find-count{font-size:11px;color:var(--muted);}
.score-ring-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.score-ring{position:relative;width:110px;height:110px;flex-shrink:0;}
.score-ring svg{transform:rotate(-90deg);}
.score-ring-text{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;}
.score-ring-num{font-size:24px;font-weight:700;font-family:var(--mono);}
.score-ring-lbl{font-size:10px;color:var(--muted);margin-top:1px;}
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
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.cs-banner{padding:12px 16px;border-radius:var(--radius-sm);border:1px solid;margin-bottom:16px;display:flex;align-items:center;gap:10px;font-size:13px;}
.cs-banner.included{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.3);color:var(--green);}
.cs-banner.skipped{background:rgba(210,153,34,.08);border-color:rgba(210,153,34,.3);color:var(--amber);}
.sub-list{display:flex;flex-direction:column;}
.sub-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}
.sub-icon.c-amber{color:var(--amber);}
.sub-icon.c-red{color:var(--red);}
.sub-name{flex:1;font-size:13px;font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}
.exec-table-wrap table th{cursor:default;}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:480px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
#detailDrawer.open{transform:translateX(0);}
.drawer-header{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.drawer-title{font-size:13px;font-weight:700;word-break:break-word;}
.drawer-close{background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;padding:2px 6px;border-radius:var(--radius-sm);}
.drawer-close:hover{color:var(--text);background:var(--surface2);}
.drawer-body{padding:20px;overflow-y:auto;flex:1;}
.drawer-nav{display:flex;gap:8px;align-items:center;margin-bottom:16px;}
.drawer-nav-btn{padding:5px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;}
.drawer-nav-btn:hover{border-color:var(--accent);color:var(--accent);}
.drawer-nav-info{font-size:12px;color:var(--muted);flex:1;text-align:center;}
.drawer-field{margin-bottom:14px;}
.drawer-field-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.drawer-field-value{font-size:13px;word-break:break-all;line-height:1.5;}
.drawer-section{font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
#toast{position:fixed;bottom:24px;right:24px;padding:12px 18px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);font-size:13px;box-shadow:var(--shadow);opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:300;}
#toast.show{opacity:1;transform:translateY(0);}
#menuToggle{display:none;}
@media(max-width:768px){
  #menuToggle{display:flex;align-items:center;justify-content:center;position:fixed;top:12px;left:12px;z-index:300;width:36px;height:36px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:18px;}
  #sidebar{transform:translateX(-100%);}
  #sidebar.open{transform:translateX(0);}
  #main{margin-left:0;width:100%;padding:16px;padding-top:56px;}
  .chart-grid{grid-template-columns:1fr;}
  .pillar-grid{grid-template-columns:repeat(2,1fr);}
}
@media print{
  #sidebar,#menuToggle,#toast,#drawerBackdrop,#detailDrawer{display:none!important;}
  #main{margin-left:0;width:100%;}
  .page{display:block!important;}
}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">&#9776;</button>

<nav id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">&#127963;</div>
    <div class="logo-title">Architecture Review</div>
    <div class="logo-sub">Well-Architected Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">&#128202;</span> Overview</button>
    <button class="nav-btn" onclick="showPage('executive',this)"><span class="nav-icon">&#128196;</span> Executive Summary</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">&#128270;</span> All Findings</button>
    <button class="nav-btn" onclick="showPage('pillars',this)"><span class="nav-icon">&#127963;</span> Pillar Detail</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">&#128196;</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">&#9881;</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Azure Architecture Review
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Architecture Review Overview</div>
      <div class="page-sub">Well-Architected assessment across __SUB_COUNT__ subscription(s) — __TOTAL_FINDINGS__ findings across 7 pillars</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_FINDINGS__</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__OVERALL_SCORE__</div>
        <div class="stat-label">Overall Score</div>
        <div class="stat-sub">__OVERALL_RATING__</div>
      </div>
    </div>

    <div class="cs-banner __LIVE_BANNER_CLS__">
      <span>&#9889;</span>
      <span><strong>Live Checks:</strong> __LIVE_BANNER_TEXT__</span>
    </div>

    <div class="panel">
      <div class="panel-title">&#127963; Pillar Scores</div>
      <div class="pillar-grid">
        __PILLAR_CARDS__
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">&#128270; Findings by Severity</div>
        __SEV_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">&#127963; Findings by Pillar</div>
        __PILLAR_FIND_ROWS__
      </div>
    </div>
  </div>

  <!-- Executive Summary -->
  <div id="page-executive" class="page">
    <div class="page-header">
      <div class="page-title">Executive Summary</div>
      <div class="page-sub">Architecture review summary suitable for leadership and architecture board review</div>
    </div>
    <div class="panel">
      <div class="panel-title">&#127919; Overall Architecture Posture</div>
      <div class="score-ring-wrap">
        <div class="score-ring">
          <svg width="110" height="110" viewBox="0 0 110 110">
            <circle cx="55" cy="55" r="46" fill="none" stroke="var(--surface3)" stroke-width="10"/>
            <circle cx="55" cy="55" r="46" fill="none" stroke="__SCORE_COLOR__" stroke-width="10"
              stroke-dasharray="__CIRCUMFERENCE__" stroke-dashoffset="__DASH_OFFSET__" stroke-linecap="round"/>
          </svg>
          <div class="score-ring-text">
            <div class="score-ring-num" style="color:__SCORE_COLOR__">__OVERALL_SCORE__</div>
            <div class="score-ring-lbl">/ 100</div>
          </div>
        </div>
        <div style="flex:1">
          <div style="font-size:18px;font-weight:700;margin-bottom:6px">__OVERALL_RATING__</div>
          <div style="font-size:13px;color:var(--muted2);margin-bottom:12px;line-height:1.6">
            The overall architecture score is the average of all seven pillar scores.
            Critical and High findings carry the largest score deductions and should
            be prioritized for remediation.
          </div>
          <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:12px;">
            <span style="color:var(--green)">&#10003; 80-100 = Good</span>
            <span style="color:var(--accent)">&#8901; 60-79 = Needs Attention</span>
            <span style="color:var(--amber)">&#9888; 40-59 = At Risk</span>
            <span style="color:var(--red)">&#10007; 0-39 = Critical</span>
          </div>
        </div>
      </div>
    </div>

    <div class="panel exec-table-wrap">
      <div class="panel-title">&#128200; Pillar Scorecard</div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Pillar</th>
              <th>Score</th>
              <th>Rating</th>
              <th>Total Findings</th>
              <th>Critical</th>
              <th>High</th>
            </tr>
          </thead>
          <tbody>__EXEC_ROWS__</tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">&#128200; Pillar Score Comparison</div>
      __PILLAR_SCORE_ROWS__
    </div>
  </div>

  <!-- All Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">All Findings</div>
      <div class="page-sub">Click any row to view finding detail, recommendation, and affected resource</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">&#128269;</span>
          <input type="text" id="findSearch" placeholder="Search check, pillar, subscription..." oninput="filterFind()"/>
        </div>
        <select class="filter-select" id="filterPillar" onchange="filterFind()">
          <option value="">All Pillars</option>
          <option value="Identity &amp; Access">Identity &amp; Access</option>
          <option value="Networking">Networking</option>
          <option value="Security">Security</option>
          <option value="Governance">Governance</option>
          <option value="Resilience">Resilience</option>
          <option value="Cost">Cost</option>
          <option value="Observability">Observability</option>
        </select>
        <select class="filter-select" id="filterSev" onchange="filterFind()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Informational">Informational</option>
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
              <th onclick="sortFind(0)">Pillar</th>
              <th onclick="sortFind(1)">Check</th>
              <th onclick="sortFind(2)">Severity</th>
              <th onclick="sortFind(3)">Status</th>
              <th onclick="sortFind(4)">Subscription</th>
              <th onclick="sortFind(5)">Resource</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- Pillar Detail -->
  <div id="page-pillars" class="page">
    <div class="page-header">
      <div class="page-title">Pillar Detail</div>
      <div class="page-sub">Select a pillar from the navigation below to view its findings and score</div>
    </div>
    <div class="toolbar" style="margin-bottom:18px;">
      <select class="filter-select" id="pillarSelect" onchange="renderPillarDetail()" style="font-size:13px;padding:10px 14px;flex:none;">
        <option value="Identity &amp; Access">Identity &amp; Access</option>
        <option value="Networking">Networking</option>
        <option value="Security">Security</option>
        <option value="Governance">Governance</option>
        <option value="Resilience">Resilience</option>
        <option value="Cost">Cost</option>
        <option value="Observability">Observability</option>
      </select>
    </div>
    <div id="pillarDetailContent"></div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription architecture review outcome</div>
    </div>
    <div class="panel">
      <div class="panel-title">&#128196; Subscriptions Reviewed</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- Session -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Review Parameters</div>
      <div class="page-sub">Authentication context and configuration used for this review</div>
    </div>
    <div class="panel">
      <div class="panel-title">&#128272; Session Information</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Tenant ID</div><div class="info-value">__TENANT__</div></div>
        <div class="info-card"><div class="info-label">Account</div><div class="info-value">__ACCOUNT__</div></div>
        <div class="info-card"><div class="info-label">Environment</div><div class="info-value">__ENVIRONMENT__</div></div>
        <div class="info-card"><div class="info-label">Generated On</div><div class="info-value">__GENERATED_ON__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">&#9881; Review Parameters</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Scope</div><div class="info-value">__SCOPE__</div></div>
        <div class="info-card"><div class="info-label">Live Checks</div><div class="info-value">__LIVE_TEXT__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Subscriptions Scanned</div><div class="info-value">__SUB_COUNT__</div></div>
      </div>
    </div>
  </div>
</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Finding Detail</span>
    <button class="drawer-close" onclick="closeDrawer()">&#10005;</button>
  </div>
  <div class="drawer-body">
    <div class="drawer-nav">
      <button class="drawer-nav-btn" onclick="navDetail(-1)">&#8592; Prev</button>
      <span class="drawer-nav-info" id="drawerNavInfo"></span>
      <button class="drawer-nav-btn" onclick="navDetail(1)">Next &#8594;</button>
    </div>
    <div id="drawerContent"></div>
  </div>
</div>

<div id="toast"></div>

<script>
const FIND_DATA = __FIND_JSON__;
let findFiltered = [...FIND_DATA];
let findPage = 1, findPageSz = 25;
let findSortCol = -1, findSortAsc = true;
let currentDetailIdx = 0;

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id, btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
  if(id==='pillars') renderPillarDetail();
}

function toggleTheme(){
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme==='dark'?'light':'dark';
}

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Findings table ────────────────────────────────────────────────────────────
function filterFind(){
  const q = document.getElementById('findSearch').value.toLowerCase();
  const p = document.getElementById('filterPillar').value;
  const s = document.getElementById('filterSev').value;
  findFiltered = FIND_DATA.filter(d=>{
    const mQ = !q || JSON.stringify(d).toLowerCase().includes(q);
    const mP = !p || d.pillar === p;
    const mS = !s || d.sev === s;
    return mQ && mP && mS;
  });
  findPage = 1; renderFind();
}

function changeFindPageSize(){
  findPageSz = parseInt(document.getElementById('pgSizeFind').value);
  findPage = 1; renderFind();
}

function sortFind(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys=['pillar','check','sev','status','sub','resource'];
  findFiltered.sort((a,b)=>{
    const k=keys[col]; const av=a[k]??'', bv=b[k]??'';
    return findSortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
  renderFind();
}

function renderFind(){
  const tbody = document.getElementById('findBody');
  const start = (findPage-1)*findPageSz;
  const slice = findFiltered.slice(start, start+findPageSz);
  tbody.innerHTML = slice.map(r=>{
    const gi = FIND_DATA.indexOf(r);
    const sCls = r.sev==='Critical'?'badge-red':r.sev==='High'?'badge-amber':r.sev==='Medium'?'badge-blue':r.sev==='Low'?'badge-green':'';
    const stCls = r.status==='Fail'?'badge-red':r.status==='Warning'?'badge-amber':r.status==='Pass'?'badge-green':'';
    const cn = r.check.length>38?r.check.substring(0,35)+'...':r.check;
    const rn = r.resource.length>28?r.resource.substring(0,25)+'...':r.resource;
    return `<tr onclick="showFindingDetail(${gi})">
      <td>${escH(r.pillar)}</td>
      <td title="${escH(r.check)}">${escH(cn)}</td>
      <td><span class="badge ${sCls}">${escH(r.sev)}</span></td>
      <td><span class="badge ${stCls}">${escH(r.status)}</span></td>
      <td>${escH(r.sub)}</td>
      <td title="${escH(r.resource)}">${escH(rn)}</td>
    </tr>`;
  }).join('');
  renderFindPg();
}

function renderFindPg(){
  const total = Math.ceil(findFiltered.length/findPageSz);
  const el = document.getElementById('findPagination');
  let h = `<span>${findFiltered.length} findings</span>`;
  h += `<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>&#8249; Prev</button>`;
  const s=Math.max(1,findPage-2), e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h += `<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next &#8250;</button>`;
  el.innerHTML = h;
}

function changeFindPage(p){
  const total=Math.ceil(findFiltered.length/findPageSz);
  if(p<1||p>total) return;
  findPage=p; renderFind();
}

// ── Pillar detail ─────────────────────────────────────────────────────────────
function renderPillarDetail(){
  const sel = document.getElementById('pillarSelect');
  if(!sel) return;
  const pillar = sel.value;
  const pFinds = FIND_DATA.filter(d=>d.pillar===pillar);
  const critF  = pFinds.filter(d=>d.sev==='Critical').length;
  const highF  = pFinds.filter(d=>d.sev==='High').length;

  let rows = pFinds.map((r,i)=>{
    const gi  = FIND_DATA.indexOf(r);
    const sCls= r.sev==='Critical'?'badge-red':r.sev==='High'?'badge-amber':r.sev==='Medium'?'badge-blue':r.sev==='Low'?'badge-green':'';
    const stCls=r.status==='Fail'?'badge-red':r.status==='Warning'?'badge-amber':r.status==='Pass'?'badge-green':'';
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.check)}">${escH(r.check.length>40?r.check.substring(0,37)+'...':r.check)}</td>
      <td><span class="badge ${sCls}">${escH(r.sev)}</span></td>
      <td><span class="badge ${stCls}">${escH(r.status)}</span></td>
      <td>${escH(r.sub)}</td>
      <td>${escH(r.resource||'—')}</td>
    </tr>`;
  }).join('');

  if(!rows) rows = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:20px">No findings for this pillar</td></tr>';

  document.getElementById('pillarDetailContent').innerHTML = `
    <div class="stats-grid" style="grid-template-columns:repeat(3,1fr)">
      <div class="stat-card c-blue"><div class="stat-num">${pFinds.length}</div><div class="stat-label">Total Findings</div></div>
      <div class="stat-card c-red"><div class="stat-num">${critF}</div><div class="stat-label">Critical</div></div>
      <div class="stat-card c-amber"><div class="stat-num">${highF}</div><div class="stat-label">High</div></div>
    </div>
    <div class="panel">
      <div class="panel-title">Findings — ${escH(pillar)}</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Check</th><th>Severity</th><th>Status</th><th>Subscription</th><th>Resource</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `;
}

// ── Detail drawer ─────────────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx = idx;
  const r = FIND_DATA[idx];
  if(!r) return;
  document.getElementById('drawerTitle').textContent = r.check;
  document.getElementById('drawerNavInfo').textContent = `${idx+1} of ${FIND_DATA.length}`;
  const sCls = r.sev==='Critical'?'badge-red':r.sev==='High'?'badge-amber':r.sev==='Medium'?'badge-blue':r.sev==='Low'?'badge-green':'';
  const stCls= r.status==='Fail'?'badge-red':r.status==='Warning'?'badge-amber':r.status==='Pass'?'badge-green':'';

  document.getElementById('drawerContent').innerHTML = `
    <div class="drawer-field">
      <div class="drawer-field-label">Pillar</div>
      <div class="drawer-field-value">${escH(r.pillar)}</div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Severity</div>
      <div class="drawer-field-value"><span class="badge ${sCls}">${escH(r.sev)}</span></div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Status</div>
      <div class="drawer-field-value"><span class="badge ${stCls}">${escH(r.status)}</span></div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Resource / Scope</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px;color:var(--muted2)">${r.resource?escH(r.resource):'—'}</div>
    </div>
    <div class="drawer-section">Finding Detail</div>
    <div class="drawer-field">
      <div class="drawer-field-value">${escH(r.detail)}</div>
    </div>
    <div class="drawer-section">Recommendation</div>
    <div class="drawer-field">
      <div class="drawer-field-value" style="color:var(--accent2)">${escH(r.rec)}</div>
    </div>
  `;

  document.getElementById('drawerBackdrop').style.display = 'block';
  document.getElementById('detailDrawer').classList.add('open');
}

function closeDrawer(){
  document.getElementById('drawerBackdrop').style.display = 'none';
  document.getElementById('detailDrawer').classList.remove('open');
}

function navDetail(dir){
  const next = currentDetailIdx + dir;
  if(next >= 0 && next < FIND_DATA.length) showFindingDetail(next);
}

function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width = el.dataset.pct + '%';
    });
  });
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

// ── Init ─────────────────────────────────────────────────────────────────────
filterFind();
renderPillarDetail();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__',     $GeneratedOn `
        -replace '__SUB_COUNT__',        $SubscriptionResults.Count `
        -replace '__TOTAL_FINDINGS__',   $totalFindings `
        -replace '__CRITICAL_COUNT__',   $criticalCount `
        -replace '__HIGH_COUNT__',       $highCount `
        -replace '__MEDIUM_COUNT__',     $mediumCount `
        -replace '__OVERALL_SCORE__',    $overallScore `
        -replace '__OVERALL_RATING__',   $overallRating `
        -replace '__SCORE_COLOR__',      $scoreColor `
        -replace '__CIRCUMFERENCE__',    $circumference `
        -replace '__DASH_OFFSET__',      $dashOffset `
        -replace '__LIVE_BANNER_CLS__',  $(if ($LiveChecksIncluded) { "included" } else { "skipped" }) `
        -replace '__LIVE_BANNER_TEXT__', $liveCheckText `
        -replace '__PILLAR_CARDS__',     $pillarCards `
        -replace '__SEV_ROWS__',         $sevRows `
        -replace '__PILLAR_FIND_ROWS__', $pillarFindRows `
        -replace '__EXEC_ROWS__',        $execRows `
        -replace '__PILLAR_SCORE_ROWS__',$pillarScoreRows `
        -replace '__FINDING_ROWS__',     $findingRows `
        -replace '__SUB_ROWS__',         $subRows `
        -replace '__TENANT__',           $SessionInfo.Tenant `
        -replace '__ACCOUNT__',          $SessionInfo.Account `
        -replace '__ENVIRONMENT__',      $SessionInfo.Environment `
        -replace '__SCOPE__',            $ScanParameters.Scope `
        -replace '__LIVE_TEXT__',        $liveCheckText `
        -replace '__EXPORT_ENABLED__',   $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__',        $ScanParameters.ExecTime `
        -replace '__FIND_JSON__',        $findJson

    return $html
}


#------------------------------------------------------------------------ [ Pillar Check Functions ]

Function Invoke-IdentityAccessChecks
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [bool]$LiveChecks
    )

    $findings = @()

    # Check 1: Owner role assignments count
    try
    {
        $owners = @(Get-AzRoleAssignment -RoleDefinitionName "Owner" -ErrorAction Stop |
            Where-Object { $_.ObjectType -ne "ServicePrincipal" })
        if ($owners.Count -gt 3)
        {
            $findings += New-Finding -Pillar "Identity & Access" `
                -CheckName "Excessive Owner Role Assignments" `
                -Severity "High" -Status "Fail" `
                -Detail "Found $($owners.Count) Owner role assignments. Excessive owners increase the blast radius of account compromise." `
                -Recommendation "Reduce Owner assignments. Use least-privilege roles such as Contributor or custom roles. Target 2-3 Owners maximum." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            $findings += New-Finding -Pillar "Identity & Access" `
                -CheckName "Owner Role Assignment Count" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($owners.Count) Owner role assignment(s) — within acceptable limits." `
                -Recommendation "Continue to review Owner assignments periodically." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        $findings += New-Finding -Pillar "Identity & Access" `
            -CheckName "Owner Role Assignment Count" `
            -Severity "Medium" -Status "Not Assessed" `
            -Detail "Could not retrieve role assignments: $($_.Exception.Message)" `
            -Recommendation "Verify Microsoft.Authorization/roleAssignments/read permission." `
            -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    }

    # Check 2: Custom role definitions
    try
    {
        $customRoles = @(Get-AzRoleDefinition -Custom -ErrorAction Stop)
        if ($customRoles.Count -gt 20)
        {
            $findings += New-Finding -Pillar "Identity & Access" `
                -CheckName "Custom Role Definition Sprawl" `
                -Severity "Medium" -Status "Warning" `
                -Detail "Found $($customRoles.Count) custom role definitions. Large numbers of custom roles are difficult to audit and maintain." `
                -Recommendation "Review and consolidate custom roles. Remove unused definitions and document the purpose of each remaining role." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve custom roles for $SubscriptionName: $_"
    }

    # Check 3: Service principals with secrets (credential expiry check)
    try
    {
        $spAssignments = @(Get-AzRoleAssignment -ErrorAction Stop |
            Where-Object { $_.ObjectType -eq "ServicePrincipal" })
        if ($spAssignments.Count -gt 0)
        {
            $findings += New-Finding -Pillar "Identity & Access" `
                -CheckName "Service Principal Role Assignments" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($spAssignments.Count) service principal role assignments. Verify credential expiry and necessity." `
                -Recommendation "Review service principal credentials periodically. Use managed identities where possible to eliminate credential management." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve SP assignments for $SubscriptionName: $_"
    }

    # Check 4: Conditional Access (informational — not available via Az module)
    $findings += New-Finding -Pillar "Identity & Access" `
        -CheckName "Conditional Access Policy Coverage" `
        -Severity "High" -Status "Warning" `
        -Detail "Conditional Access policy coverage cannot be verified via Az PowerShell. Manual review required via Entra ID portal." `
        -Recommendation "Ensure Conditional Access policies enforce MFA for all admin roles. Apply sign-in risk policies for external access." `
        -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId

    return $findings
}

Function Invoke-NetworkingChecks
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [bool]$LiveChecks
    )

    $findings = @()

    # Check 1: NSG coverage
    try
    {
        $vnets = @(Get-AzVirtualNetwork -ErrorAction Stop)
        $nsgs  = @(Get-AzNetworkSecurityGroup -ErrorAction Stop)

        if ($vnets.Count -gt 0 -and $nsgs.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Networking" `
                -CheckName "Network Security Group Coverage" `
                -Severity "Critical" -Status "Fail" `
                -Detail "Found $($vnets.Count) VNet(s) but no NSGs. Network traffic is unrestricted between subnets." `
                -Recommendation "Apply NSGs to all subnets. Define inbound and outbound rules based on the principle of least-privilege. Enable NSG flow logs." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        elseif ($vnets.Count -gt 0)
        {
            $findings += New-Finding -Pillar "Networking" `
                -CheckName "Network Security Group Coverage" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($nsgs.Count) NSG(s) across $($vnets.Count) VNet(s)." `
                -Recommendation "Periodically review NSG rules. Enable NSG flow logs and integrate with Log Analytics." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        $findings += New-Finding -Pillar "Networking" `
            -CheckName "Network Security Group Coverage" `
            -Severity "Medium" -Status "Not Assessed" `
            -Detail "Could not retrieve NSG information: $($_.Exception.Message)" `
            -Recommendation "Verify Microsoft.Network/networkSecurityGroups/read permission." `
            -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    }

    # Check 2: Public IP exposure
    try
    {
        $publicIPs = @(Get-AzPublicIpAddress -ErrorAction Stop |
            Where-Object { $_.IpAllocationMethod -ne "Dynamic" -or $_.IpAddress -ne "Not Assigned" })

        if ($publicIPs.Count -gt 10)
        {
            $findings += New-Finding -Pillar "Networking" `
                -CheckName "Public IP Address Exposure" `
                -Severity "High" -Status "Warning" `
                -Detail "Found $($publicIPs.Count) allocated public IP addresses. Large public surface area increases attack exposure." `
                -Recommendation "Review all public IPs. Remove unused allocations. Use Azure Front Door, Application Gateway, or Private Link to minimize direct public exposure." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve public IPs for $SubscriptionName: $_"
    }

    # Check 3: DDoS protection
    try
    {
        $ddosPlans = @(Get-AzDdosProtectionPlan -ErrorAction Stop)
        if ($ddosPlans.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Networking" `
                -CheckName "DDoS Protection Plan" `
                -Severity "Medium" -Status "Fail" `
                -Detail "No DDoS Protection Plan found. Internet-facing applications are protected only by basic Azure DDoS mitigation." `
                -Recommendation "Consider enabling Azure DDoS Network Protection for production workloads. Evaluate cost vs. risk for each environment." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            $findings += New-Finding -Pillar "Networking" `
                -CheckName "DDoS Protection Plan" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($ddosPlans.Count) DDoS Protection Plan(s)." `
                -Recommendation "Verify all internet-facing VNets are associated with the DDoS plan." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve DDoS plans for $SubscriptionName: $_"
    }

    # Check 4: Private endpoints
    try
    {
        $privateEndpoints = @(Get-AzPrivateEndpoint -ErrorAction Stop)
        if ($privateEndpoints.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Networking" `
                -CheckName "Private Endpoint Adoption" `
                -Severity "High" -Status "Warning" `
                -Detail "No Private Endpoints found. PaaS services may be accessible over public internet." `
                -Recommendation "Adopt Azure Private Endpoints for all PaaS services (Storage, SQL, Key Vault, etc.). Disable public network access on PaaS services where private endpoints are in use." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            $findings += New-Finding -Pillar "Networking" `
                -CheckName "Private Endpoint Adoption" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($privateEndpoints.Count) Private Endpoint(s) — PaaS services are accessible via private network paths." `
                -Recommendation "Ensure all PaaS services with private endpoints also have public network access disabled." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve private endpoints for $SubscriptionName: $_"
    }

    return $findings
}

Function Invoke-SecurityChecks
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [bool]$LiveChecks
    )

    $findings = @()

    # Check 1: Key Vault usage
    try
    {
        $keyVaults = @(Get-AzKeyVault -ErrorAction Stop)
        if ($keyVaults.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Security" `
                -CheckName "Key Vault Adoption" `
                -Severity "High" -Status "Fail" `
                -Detail "No Azure Key Vaults found. Secrets, keys, and certificates may be stored insecurely in application configuration or code." `
                -Recommendation "Adopt Azure Key Vault for all secrets, keys, and certificates. Enable soft-delete and purge protection. Use managed identities to access Key Vault." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            # Check soft-delete on vaults
            $noSoftDelete = @($keyVaults | Where-Object { -not $_.EnableSoftDelete })
            if ($noSoftDelete.Count -gt 0)
            {
                $findings += New-Finding -Pillar "Security" `
                    -CheckName "Key Vault Soft Delete" `
                    -Severity "High" -Status "Fail" `
                    -Detail "$($noSoftDelete.Count) Key Vault(s) do not have soft-delete enabled: $($noSoftDelete.Name -join ', ')." `
                    -Recommendation "Enable soft-delete and purge protection on all Key Vaults to prevent accidental or malicious deletion of secrets." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Resource ($noSoftDelete[0].VaultName)
            }
            else
            {
                $findings += New-Finding -Pillar "Security" `
                    -CheckName "Key Vault Adoption and Soft Delete" `
                    -Severity "Informational" -Status "Pass" `
                    -Detail "Found $($keyVaults.Count) Key Vault(s) — all have soft-delete enabled." `
                    -Recommendation "Verify purge protection is enabled and audit access policies regularly." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
        }
    }
    catch
    {
        $findings += New-Finding -Pillar "Security" `
            -CheckName "Key Vault Adoption" `
            -Severity "Medium" -Status "Not Assessed" `
            -Detail "Could not retrieve Key Vault information: $($_.Exception.Message)" `
            -Recommendation "Verify Microsoft.KeyVault/vaults/read permission." `
            -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    }

    # Check 2: VM disk encryption
    try
    {
        $vms = @(Get-AzVM -Status -ErrorAction Stop)
        if ($vms.Count -gt 0)
        {
            $unencrypted = @()
            foreach ($vm in $vms)
            {
                try
                {
                    $encStatus = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction SilentlyContinue
                    if ($encStatus -and $encStatus.OsVolumeEncrypted -ne "Encrypted")
                    {
                        $unencrypted += $vm.Name
                    }
                }
                catch { }
            }

            if ($unencrypted.Count -gt 0)
            {
                $findings += New-Finding -Pillar "Security" `
                    -CheckName "VM Disk Encryption" `
                    -Severity "High" -Status "Fail" `
                    -Detail "$($unencrypted.Count) VM(s) may have unencrypted OS disks: $($unencrypted -join ', ')." `
                    -Recommendation "Enable Azure Disk Encryption (ADE) or server-side encryption with CMK on all VM disks. Prioritize VMs handling sensitive data." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Resource ($unencrypted[0])
            }
            else
            {
                $findings += New-Finding -Pillar "Security" `
                    -CheckName "VM Disk Encryption" `
                    -Severity "Informational" -Status "Pass" `
                    -Detail "All $($vms.Count) VM(s) appear to have encrypted OS disks." `
                    -Recommendation "Continue to enforce disk encryption via Azure Policy. Review data disks in addition to OS disks." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve VMs for $SubscriptionName: $_"
    }

    # Check 3: Defender for Cloud (live or heuristic)
    if ($LiveChecks)
    {
        try
        {
            $defenderSettings = @(Get-AzSecurityPricing -ErrorAction Stop)
            $notEnabled = @($defenderSettings | Where-Object { $_.PricingTier -ne "Standard" })
            if ($notEnabled.Count -gt 0)
            {
                $findings += New-Finding -Pillar "Security" `
                    -CheckName "Microsoft Defender for Cloud Coverage" `
                    -Severity "Critical" -Status "Fail" `
                    -Detail "$($notEnabled.Count) resource type(s) not covered by Defender for Cloud Standard tier: $($notEnabled.Name -join ', ')." `
                    -Recommendation "Enable Microsoft Defender for Cloud Standard tier for all resource types, especially Servers, Storage, SQL, and Key Vault." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
            else
            {
                $findings += New-Finding -Pillar "Security" `
                    -CheckName "Microsoft Defender for Cloud Coverage" `
                    -Severity "Informational" -Status "Pass" `
                    -Detail "Microsoft Defender for Cloud Standard tier is enabled for all assessed resource types." `
                    -Recommendation "Regularly review Defender for Cloud secure score and act on recommendations." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
        }
        catch
        {
            $findings += New-Finding -Pillar "Security" `
                -CheckName "Microsoft Defender for Cloud Coverage" `
                -Severity "High" -Status "Not Assessed" `
                -Detail "Could not retrieve Defender for Cloud settings: $($_.Exception.Message)" `
                -Recommendation "Verify Microsoft.Security/pricings/read permission. Run with -IncludeLiveChecks when permissions are available." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    else
    {
        $findings += New-Finding -Pillar "Security" `
            -CheckName "Microsoft Defender for Cloud Coverage" `
            -Severity "High" -Status "Not Assessed" `
            -Detail "Live Defender check skipped. Run with -IncludeLiveChecks to retrieve Defender for Cloud plan coverage." `
            -Recommendation "Enable -IncludeLiveChecks to assess Defender for Cloud coverage. Manually verify via Defender for Cloud portal." `
            -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    }

    return $findings
}

Function Invoke-GovernanceChecks
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [bool]$LiveChecks
    )

    $findings = @()

    # Check 1: Policy assignments
    try
    {
        $assignments = @(Get-AzPolicyAssignment -ErrorAction Stop)
        if ($assignments.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Governance" `
                -CheckName "Policy Assignment Coverage" `
                -Severity "Critical" -Status "Fail" `
                -Detail "No Azure Policy assignments found at subscription scope or below. Resources are operating without guardrails." `
                -Recommendation "Assign Azure Policy initiatives for security baselines (CIS, NIST, or Azure Security Benchmark). Enforce tagging policies and resource type restrictions." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            $enforced = @($assignments | Where-Object { $_.EnforcementMode -ne "DoNotEnforce" })
            if ($enforced.Count -eq 0)
            {
                $findings += New-Finding -Pillar "Governance" `
                    -CheckName "Policy Enforcement Mode" `
                    -Severity "High" -Status "Fail" `
                    -Detail "Found $($assignments.Count) policy assignment(s) but none are in enforce mode (all are DoNotEnforce). Policies are auditing but not blocking non-compliant resources." `
                    -Recommendation "Transition at least critical security policies from DoNotEnforce to Default (enforce) mode after a remediation period." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
            else
            {
                $findings += New-Finding -Pillar "Governance" `
                    -CheckName "Policy Assignment Coverage" `
                    -Severity "Informational" -Status "Pass" `
                    -Detail "Found $($assignments.Count) policy assignment(s), $($enforced.Count) in enforce mode." `
                    -Recommendation "Review policy compliance reports regularly. Ensure exemptions are time-bounded and documented." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
        }
    }
    catch
    {
        $findings += New-Finding -Pillar "Governance" `
            -CheckName "Policy Assignment Coverage" `
            -Severity "Medium" -Status "Not Assessed" `
            -Detail "Could not retrieve policy assignments: $($_.Exception.Message)" `
            -Recommendation "Verify Microsoft.Authorization/policyAssignments/read permission." `
            -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    }

    # Check 2: Resource tagging compliance
    try
    {
        $resources = @(Get-AzResource -ErrorAction Stop)
        if ($resources.Count -gt 0)
        {
            $untagged = @($resources | Where-Object { $null -eq $_.Tags -or $_.Tags.Count -eq 0 })
            $pct      = [math]::Round(($untagged.Count / $resources.Count) * 100)

            if ($pct -gt 30)
            {
                $findings += New-Finding -Pillar "Governance" `
                    -CheckName "Resource Tagging Compliance" `
                    -Severity "Medium" -Status "Fail" `
                    -Detail "$($untagged.Count) of $($resources.Count) resources ($pct%) have no tags. Untagged resources impede cost allocation and operational management." `
                    -Recommendation "Enforce mandatory tags (Owner, Environment, CostCenter, BusinessCriticality) via Azure Policy. Run a tagging remediation task for existing resources." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
            else
            {
                $findings += New-Finding -Pillar "Governance" `
                    -CheckName "Resource Tagging Compliance" `
                    -Severity "Informational" -Status "Pass" `
                    -Detail "$pct% of resources are untagged ($($untagged.Count) of $($resources.Count)). Within acceptable threshold." `
                    -Recommendation "Continue to enforce tagging via policy. Review untagged resources and assign appropriate tags." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve resources for tagging check in $SubscriptionName: $_"
    }

    # Check 3: Budget alerts
    try
    {
        $budgets = @(Get-AzConsumptionBudget -ErrorAction Stop)
        if ($budgets.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Governance" `
                -CheckName "Budget and Cost Alerts" `
                -Severity "Medium" -Status "Fail" `
                -Detail "No consumption budgets found. Cost overruns may go undetected until the billing statement arrives." `
                -Recommendation "Configure Azure Cost Management budgets with alert thresholds at 80% and 100% of the monthly budget. Add email and action group notifications." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            $findings += New-Finding -Pillar "Governance" `
                -CheckName "Budget and Cost Alerts" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($budgets.Count) budget(s) configured." `
                -Recommendation "Verify budget thresholds are current and alert recipients are active distribution lists." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve budgets for $SubscriptionName: $_"
    }

    return $findings
}

Function Invoke-ResilienceChecks
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [bool]$LiveChecks
    )

    $findings = @()

    # Check 1: Backup vaults
    try
    {
        $vaults = @(Get-AzRecoveryServicesVault -ErrorAction Stop)
        if ($vaults.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Resilience" `
                -CheckName "Azure Backup Vaults" `
                -Severity "Critical" -Status "Fail" `
                -Detail "No Recovery Services Vaults found. Resources in this subscription have no Azure Backup coverage." `
                -Recommendation "Create a Recovery Services Vault and configure backup policies for VMs, SQL databases, file shares, and other critical workloads." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            $findings += New-Finding -Pillar "Resilience" `
                -CheckName "Azure Backup Vaults" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($vaults.Count) Recovery Services Vault(s)." `
                -Recommendation "Verify all critical resources have active backup policies. Test restore procedures periodically." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        $findings += New-Finding -Pillar "Resilience" `
            -CheckName "Azure Backup Vaults" `
            -Severity "Medium" -Status "Not Assessed" `
            -Detail "Could not retrieve Recovery Services Vaults: $($_.Exception.Message)" `
            -Recommendation "Verify Microsoft.RecoveryServices/vaults/read permission." `
            -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    }

    # Check 2: Load balancer SKU tiers
    try
    {
        $lbs     = @(Get-AzLoadBalancer -ErrorAction Stop)
        $basicLB = @($lbs | Where-Object { $_.Sku.Name -eq "Basic" })

        if ($basicLB.Count -gt 0)
        {
            $findings += New-Finding -Pillar "Resilience" `
                -CheckName "Load Balancer SKU Tier" `
                -Severity "High" -Status "Fail" `
                -Detail "Found $($basicLB.Count) Basic SKU Load Balancer(s). Basic LBs have no SLA and lack zone-redundancy." `
                -Recommendation "Migrate to Standard SKU Load Balancers which offer 99.99% SLA and availability zone support." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Resource ($basicLB[0].Name)
        }
        elseif ($lbs.Count -gt 0)
        {
            $findings += New-Finding -Pillar "Resilience" `
                -CheckName "Load Balancer SKU Tier" `
                -Severity "Informational" -Status "Pass" `
                -Detail "All $($lbs.Count) Load Balancer(s) use Standard SKU with SLA coverage." `
                -Recommendation "Verify zone redundancy configuration and confirm backend pool health probes are correctly defined." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve load balancers for $SubscriptionName: $_"
    }

    # Check 3: Availability sets vs. zones
    try
    {
        $vms = @(Get-AzVM -ErrorAction Stop)
        if ($vms.Count -gt 0)
        {
            $noZoneNoAS = @($vms | Where-Object {
                ($null -eq $_.Zones -or $_.Zones.Count -eq 0) -and
                ($null -eq $_.AvailabilitySetReference)
            })

            if ($noZoneNoAS.Count -gt 0)
            {
                $findings += New-Finding -Pillar "Resilience" `
                    -CheckName "VM Availability Configuration" `
                    -Severity "High" -Status "Fail" `
                    -Detail "$($noZoneNoAS.Count) VM(s) are not in an Availability Zone or Availability Set: $($noZoneNoAS.Name -join ', ')." `
                    -Recommendation "Deploy VMs in Availability Zones (preferred) or Availability Sets. VMs without these configurations have no SLA and risk downtime during platform maintenance." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                    -Resource ($noZoneNoAS[0].Name)
            }
            else
            {
                $findings += New-Finding -Pillar "Resilience" `
                    -CheckName "VM Availability Configuration" `
                    -Severity "Informational" -Status "Pass" `
                    -Detail "All $($vms.Count) VM(s) are configured with Availability Zones or Availability Sets." `
                    -Recommendation "Prefer Availability Zones over Availability Sets for new deployments." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve VMs for resilience check in $SubscriptionName: $_"
    }

    return $findings
}

Function Invoke-CostChecks
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [bool]$LiveChecks
    )

    $findings = @()

    # Check 1: Advisor cost recommendations (live)
    if ($LiveChecks)
    {
        try
        {
            $costRecs = @(Get-AzAdvisorRecommendation -Category Cost -ErrorAction Stop)
            if ($costRecs.Count -gt 0)
            {
                $findings += New-Finding -Pillar "Cost" `
                    -CheckName "Azure Advisor Cost Recommendations" `
                    -Severity "Medium" -Status "Warning" `
                    -Detail "Azure Advisor has $($costRecs.Count) active cost recommendation(s). Potential savings are being left on the table." `
                    -Recommendation "Review and act on Advisor cost recommendations. Common actions: resize underutilized VMs, delete idle resources, purchase reserved instances." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
            else
            {
                $findings += New-Finding -Pillar "Cost" `
                    -CheckName "Azure Advisor Cost Recommendations" `
                    -Severity "Informational" -Status "Pass" `
                    -Detail "No active cost recommendations from Azure Advisor." `
                    -Recommendation "Continue to review Advisor recommendations monthly." `
                    -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
            }
        }
        catch
        {
            $findings += New-Finding -Pillar "Cost" `
                -CheckName "Azure Advisor Cost Recommendations" `
                -Severity "Medium" -Status "Not Assessed" `
                -Detail "Could not retrieve Advisor recommendations: $($_.Exception.Message)" `
                -Recommendation "Verify Microsoft.Advisor/recommendations/read permission." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    else
    {
        $findings += New-Finding -Pillar "Cost" `
            -CheckName "Azure Advisor Cost Recommendations" `
            -Severity "Medium" -Status "Not Assessed" `
            -Detail "Live Advisor check skipped. Run with -IncludeLiveChecks to retrieve Advisor cost recommendations." `
            -Recommendation "Enable -IncludeLiveChecks to assess Advisor cost recommendations. Review Azure Cost Management and Advisor portal manually." `
            -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    }

    # Check 2: Unattached managed disks
    try
    {
        $disks = @(Get-AzDisk -ErrorAction Stop |
            Where-Object { $_.DiskState -eq "Unattached" })

        if ($disks.Count -gt 0)
        {
            $findings += New-Finding -Pillar "Cost" `
                -CheckName "Unattached Managed Disks" `
                -Severity "Low" -Status "Warning" `
                -Detail "Found $($disks.Count) unattached managed disk(s). These incur storage costs without delivering value." `
                -Recommendation "Review unattached disks and delete those no longer needed. Create snapshots before deletion if data recovery may be required." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Resource ($disks[0].Name)
        }
        else
        {
            $findings += New-Finding -Pillar "Cost" `
                -CheckName "Unattached Managed Disks" `
                -Severity "Informational" -Status "Pass" `
                -Detail "No unattached managed disks found." `
                -Recommendation "Include disk lifecycle management in your regular cost review cadence." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve managed disks for $SubscriptionName: $_"
    }

    # Check 3: Deallocated VMs (potential idle cost)
    try
    {
        $vms       = @(Get-AzVM -Status -ErrorAction Stop)
        $stopped   = @($vms | Where-Object { $_.PowerState -eq "VM stopped" })  # stopped but not deallocated
        if ($stopped.Count -gt 0)
        {
            $findings += New-Finding -Pillar "Cost" `
                -CheckName "Stopped (Non-Deallocated) VMs" `
                -Severity "Low" -Status "Warning" `
                -Detail "Found $($stopped.Count) VM(s) in stopped (non-deallocated) state: $($stopped.Name -join ', '). Stopped VMs continue to incur compute charges." `
                -Recommendation "Deallocate VMs (Stop-AzVM) rather than just stopping them to avoid compute charges. Use auto-shutdown schedules for dev/test VMs." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId `
                -Resource ($stopped[0].Name)
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve VM status for cost check in $SubscriptionName: $_"
    }

    return $findings
}

Function Invoke-ObservabilityChecks
{
    param(
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [bool]$LiveChecks
    )

    $findings = @()

    # Check 1: Log Analytics workspaces
    try
    {
        $workspaces = @(Get-AzOperationalInsightsWorkspace -ErrorAction Stop)
        if ($workspaces.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Observability" `
                -CheckName "Log Analytics Workspace" `
                -Severity "Critical" -Status "Fail" `
                -Detail "No Log Analytics Workspaces found. Centralized log collection and analysis is not configured." `
                -Recommendation "Create a Log Analytics Workspace and configure all resources to send diagnostic logs. Integrate with Microsoft Sentinel for security analytics." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            $findings += New-Finding -Pillar "Observability" `
                -CheckName "Log Analytics Workspace" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($workspaces.Count) Log Analytics Workspace(s)." `
                -Recommendation "Verify all critical resources are connected. Review data retention settings and access controls." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        $findings += New-Finding -Pillar "Observability" `
            -CheckName "Log Analytics Workspace" `
            -Severity "Medium" -Status "Not Assessed" `
            -Detail "Could not retrieve Log Analytics Workspaces: $($_.Exception.Message)" `
            -Recommendation "Verify Microsoft.OperationalInsights/workspaces/read permission." `
            -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
    }

    # Check 2: Alert rules
    try
    {
        $alertRules = @(Get-AzMetricAlertRuleV2 -ErrorAction Stop)
        if ($alertRules.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Observability" `
                -CheckName "Azure Monitor Alert Rules" `
                -Severity "High" -Status "Fail" `
                -Detail "No metric alert rules found. Operational issues such as high CPU, memory pressure, or service outages may go undetected." `
                -Recommendation "Create alert rules for critical metrics: VM CPU, memory, and disk; database DTU/CPU; App Service HTTP errors and response times. Route alerts to action groups." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            $findings += New-Finding -Pillar "Observability" `
                -CheckName "Azure Monitor Alert Rules" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($alertRules.Count) metric alert rule(s)." `
                -Recommendation "Review alert thresholds periodically. Ensure action groups have current notification targets." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve alert rules for $SubscriptionName: $_"
    }

    # Check 3: Application Insights
    try
    {
        $appInsights = @(Get-AzApplicationInsights -ErrorAction Stop)
        if ($appInsights.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Observability" `
                -CheckName "Application Insights Adoption" `
                -Severity "Medium" -Status "Warning" `
                -Detail "No Application Insights components found. Application-level telemetry (requests, dependencies, exceptions) is not being collected." `
                -Recommendation "Instrument application code with Application Insights SDK or agent. Enable distributed tracing and availability tests." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            $findings += New-Finding -Pillar "Observability" `
                -CheckName "Application Insights Adoption" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($appInsights.Count) Application Insights component(s)." `
                -Recommendation "Review sampling rates, data caps, and retention periods. Configure availability tests for all public endpoints." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve Application Insights for $SubscriptionName: $_"
    }

    # Check 4: Activity log alerts
    try
    {
        $activityAlerts = @(Get-AzActivityLogAlert -ErrorAction Stop)
        if ($activityAlerts.Count -eq 0)
        {
            $findings += New-Finding -Pillar "Observability" `
                -CheckName "Activity Log Alerts" `
                -Severity "High" -Status "Fail" `
                -Detail "No Activity Log alerts found. Administrative changes such as role assignments, policy changes, and resource deletions are not being monitored." `
                -Recommendation "Create Activity Log alerts for high-impact operations: Create/Delete/Update on role assignments, policy assignments, NSGs, and Key Vaults." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
        else
        {
            $findings += New-Finding -Pillar "Observability" `
                -CheckName "Activity Log Alerts" `
                -Severity "Informational" -Status "Pass" `
                -Detail "Found $($activityAlerts.Count) Activity Log alert(s)." `
                -Recommendation "Ensure activity log alerts cover security-critical operations. Route to a SIEM or ITSM connector." `
                -SubscriptionName $SubscriptionName -SubscriptionId $SubscriptionId
        }
    }
    catch
    {
        Write-Verbose "Could not retrieve Activity Log alerts for $SubscriptionName: $_"
    }

    return $findings
}


#------------------------------------------------------------------------ [ Main Function ]

Function Generate-AzureArchitectureReviewReport
{
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$IncludeLiveChecks,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureArchitectureReview-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @(
        "Az.Accounts", "Az.Resources", "Az.Network", "Az.Monitor",
        "Az.RecoveryServices", "Az.Compute", "Az.KeyVault",
        "Az.OperationalInsights", "Az.ApplicationInsights"
    )
    if ($IncludeLiveChecks) { $requiredModules += @("Az.Security", "Az.Advisor") }

    $missingModules = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missingModules)
    {
        Write-Host "  Missing Az modules: $($missingModules -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "  Install Az module now? (Y/N)"

        if ($install -match '^[Yy]$')
        {
            try
            {
                Write-Host ""
                Write-Host "  Installing Az module, please wait..." -ForegroundColor Cyan
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "  Az module installed successfully" -ForegroundColor Green
                Write-Host ""
            }
            catch
            {
                Write-Host "  Error installing Az module: $_" -ForegroundColor Red
                return
            }
        }
        else
        {
            Write-Host ""
            Write-Host "  Installation declined. Cannot proceed without required Az modules." -ForegroundColor Yellow
            return
        }
    }

    # ── Authentication ────────────────────────────────────────────────────────
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx)
    {
        Write-Host "  No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $ctx = Get-AzContext
    }

    # ── Subscription resolution ───────────────────────────────────────────────
    if ($AllSubscriptions -or -not $SubscriptionIds)
    {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText     = "All Subscriptions"
    }
    else
    {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
            Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count))"
    }

    $subCount = $subscriptions.Count

    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Review Parameters" -Data @{
        "Scope"       = "$scopeText ($subCount found)"
        "Live Checks" = if ($IncludeLiveChecks) { "Enabled (Advisor, Defender)" } else { "Disabled (use -IncludeLiveChecks)" }
        "Export CSV"  = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path" = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings         = @()
    $subscriptionResults = @()
    $pillarScores        = @{}
    $successCount        = 0
    $errorCount          = 0

    # ── Scan ──────────────────────────────────────────────────────────────────
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = ([math]::Max(
        ($subscriptions | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum,
        35
    ))

    $subIndex = 1

    foreach ($sub in $subscriptions)
    {
        try
        {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

            $liveChecks = $IncludeLiveChecks.IsPresent

            # Run all pillar checks
            $subFindings = @()
            $subFindings += Invoke-IdentityAccessChecks -SubscriptionName $sub.Name -SubscriptionId $sub.Id -LiveChecks $liveChecks
            $subFindings += Invoke-NetworkingChecks     -SubscriptionName $sub.Name -SubscriptionId $sub.Id -LiveChecks $liveChecks
            $subFindings += Invoke-SecurityChecks       -SubscriptionName $sub.Name -SubscriptionId $sub.Id -LiveChecks $liveChecks
            $subFindings += Invoke-GovernanceChecks     -SubscriptionName $sub.Name -SubscriptionId $sub.Id -LiveChecks $liveChecks
            $subFindings += Invoke-ResilienceChecks     -SubscriptionName $sub.Name -SubscriptionId $sub.Id -LiveChecks $liveChecks
            $subFindings += Invoke-CostChecks           -SubscriptionName $sub.Name -SubscriptionId $sub.Id -LiveChecks $liveChecks
            $subFindings += Invoke-ObservabilityChecks  -SubscriptionName $sub.Name -SubscriptionId $sub.Id -LiveChecks $liveChecks

            $allFindings += $subFindings

            $critCount = @($subFindings | Where-Object { $_.Severity -eq "Critical" }).Count
            $highCount  = @($subFindings | Where-Object { $_.Severity -eq "High" }).Count

            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "v " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " -> " -NoNewline -ForegroundColor DarkGray
            Write-Host "Findings: $($subFindings.Count)  Critical: $critCount  High: $highCount" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Findings: $($subFindings.Count)  Critical: $critCount  High: $highCount"
                Status  = "Success"
            }
            $successCount++
        }
        catch
        {
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "x " -NoNewline -ForegroundColor Red
            Write-Host $paddedName -NoNewline -ForegroundColor Red
            Write-Host " -> " -NoNewline -ForegroundColor DarkGray
            Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Failed: $($_.Exception.Message)"
                Status  = "Error"
            }
            $errorCount++
        }

        $subIndex++
    }

    # ── Compute pillar scores ─────────────────────────────────────────────────
    $pillarNames = @("Identity & Access", "Networking", "Security", "Governance", "Resilience", "Cost", "Observability")
    foreach ($pillar in $pillarNames)
    {
        $pFinds = @($allFindings | Where-Object { $_.Pillar -eq $pillar -and $_.Status -ne "Pass" -and $_.Severity -ne "Informational" })
        $pillarScores[$pillar] = Compute-PillarScore -PillarFindings $pFinds
    }

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime  = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    $overallScore = if ($pillarScores.Count -gt 0) {
        [math]::Round(($pillarScores.Values | Measure-Object -Average).Average)
    } else { 0 }

    Write-Summary -Data ([ordered]@{
        "Total Subscriptions Scanned" = $subCount
        "Successful"                  = $successCount
        "Errors"                      = $errorCount
        "Total Findings"              = $allFindings.Count
        "Critical Findings"           = @($allFindings | Where-Object { $_.Severity -eq "Critical" }).Count
        "High Findings"               = @($allFindings | Where-Object { $_.Severity -eq "High" }).Count
        "Overall Architecture Score"  = "$overallScore / 100"
        "Live Checks Included"        = if ($IncludeLiveChecks) { "Yes" } else { "No (use -IncludeLiveChecks)" }
        "Execution Time"              = $duration
    })

    Write-PillarScores -Scores $pillarScores

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported    = $false
    $htmlExported   = $false
    $gridViewOpened = $false
    $htmlPath       = ""

    if ($allFindings.Count -gt 0)
    {
        if ($ExportToCsv)
        {
            try
            {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object `
                    Pillar, CheckName, Severity, Status, SubscriptionName,
                    SubscriptionId, Resource, Detail, Recommendation |
                    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                $csvExported = $true
            }
            catch
            {
                Write-Host "  CSV export failed: $_" -ForegroundColor Red
            }
        }

        try
        {
            $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')

            $sessionInfo = @{
                Tenant      = $ctx.Tenant.Id
                Account     = $ctx.Account.Id
                Environment = $ctx.Environment.Name
            }

            $scanParams = @{
                Scope         = "$scopeText ($subCount found)"
                ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime      = $duration
            }

            $htmlContent = Generate-ArchitectureReviewHtml `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParams `
                -Findings            $allFindings `
                -PillarScores        $pillarScores `
                -SubscriptionResults $subscriptionResults `
                -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -LiveChecksIncluded  $IncludeLiveChecks.IsPresent

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch
        {
            Write-Host "  HTML report generation failed: $_" -ForegroundColor Red
        }

        try
        {
            $allFindings |
                Select-Object Pillar, CheckName, Severity, Status, SubscriptionName, Resource |
                Out-GridView -Title "Azure Architecture Review Report"
            $gridViewOpened = $true
        }
        catch
        {
            Write-Host "  Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else
    {
        Write-Host ""
        Write-Host "  No findings generated. Verify subscription access and permissions." -ForegroundColor Yellow
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened)
    {
        $outCsv  = if ($csvExported)  { $CsvPath  } else { $null }
        $outHtml = if ($htmlExported) { $htmlPath } else { $null }
        Write-OutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
    }
    else
    {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
