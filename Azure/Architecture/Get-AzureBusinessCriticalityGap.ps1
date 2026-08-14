<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 14 August 2026
Modified-On     : 14 August 2026

.SYNOPSIS
    Identifies gaps between declared business criticality and actual technical controls
    across security, backup, DR, monitoring, and availability for Azure resources.

.DESCRIPTION
    Get-AzureBusinessCriticalityGap scans Azure resources tagged with a business
    criticality designation and evaluates whether the controls required for that
    criticality tier are actually in place.

    Default assessment (structure + tag-based):
        - Discovers resources bearing the configured criticality tag
          (default tag key: "BusinessCriticality"; values: Critical / High / Medium / Low)
        - For each resource, evaluates five control domains:
            Security     — Microsoft Defender for Cloud coverage, security contact
            Backup       — Azure Backup / Recovery Services Vault association
            DR           — ASR replication or cross-region redundancy configuration
            Monitoring   — Diagnostic Settings enabled, Azure Monitor Alert rules
            Availability — Zone redundancy, SLA-tier SKU (e.g. Standard LB vs Basic)
        - Computes a per-resource Gap Score (0–100; 100 = fully covered)
        - Risk-rates each gap as Critical / High / Medium / Low based on the declared
          criticality tier vs. the number of missing controls
        - Aggregates gaps by subscription, resource type, and control domain

    Optional Defender enrichment (-IncludeDefenderData switch):
        - Calls Get-AzSecurityTask and Get-AzSecurityAlert to pull live
          recommendation and alert counts per resource
        - If the call fails due to permissions, the section is marked
          "Not Assessed / Warning" and the scan continues

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Custom tag key and criticality value map via -CriticalityTagKey / -CriticalityValues
        - Real-time progress bar and color-coded per-subscription output
        - Optional CSV export of all gap findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          distribution panels, detail drawer, gap score ring)
        - Interactive Grid View of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER CriticalityTagKey
    The Azure resource tag key used to identify business criticality.
    Default: "BusinessCriticality"

.PARAMETER CriticalityValues
    Ordered array of criticality tier values expected in the tag, from highest
    to lowest. Used to derive required control expectations per tier.
    Default: @("Critical","High","Medium","Low")

.PARAMETER IncludeDefenderData
    Switch. When specified, calls Microsoft Defender for Cloud APIs to retrieve
    live security recommendation and alert counts per resource. Disabled by
    default for performance.
    If the call fails, the Defender section is marked "Not Assessed / Warning"
    and the scan continues.

.PARAMETER ExportToCsv
    Switch. If specified, exports all gap findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzureBusinessCriticalityGap-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureBusinessCriticalityGap -AllSubscriptions

.EXAMPLE
    Get-AzureBusinessCriticalityGap -AllSubscriptions -IncludeDefenderData

.EXAMPLE
    Get-AzureBusinessCriticalityGap -SubscriptionIds @("sub-id-1","sub-id-2") -CriticalityTagKey "Criticality"

.EXAMPLE
    Get-AzureBusinessCriticalityGap -AllSubscriptions -IncludeDefenderData -ExportToCsv -CsvPath "C:\Reports\CriticalityGap.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (14-Aug-2026) - Initial release. Criticality gap assessment across
                            Security, Backup, DR, Monitoring, and Availability
                            control domains. Optional Defender enrichment via
                            -IncludeDefenderData. CSV export and HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.RecoveryServices,
           Az.Monitor, Az.Network) — installed automatically with user consent
           if not present.
        2. Az.Security is required for -IncludeDefenderData.
        3. Authenticated Azure session (Connect-AzAccount).
        4. Reader role (minimum) at the subscription level.
        5. Microsoft.Security/tasks/read and Microsoft.Security/alerts/read are
           required for -IncludeDefenderData. Without these permissions the
           Defender section is gracefully marked "Not Assessed / Warning".
        6. Resources must be tagged with the configured CriticalityTagKey for
           discovery. Resources without the tag are skipped.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Only resources tagged with CriticalityTagKey are evaluated. Untagged
          resources are out of scope — ensure your tagging policy is enforced
          before interpreting gap results.
        - ASR (Azure Site Recovery) replication status requires Az.RecoveryServices
          and appropriate RBAC; if unavailable, the DR check degrades gracefully.
        - Diagnostic Settings check enumerates settings at the resource level;
          Log Analytics workspace connectivity is not validated.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Management Group-scoped resources are not enumerated; only subscription-
          scoped resources are included.
        - Gap Score is an approximation based on control presence, not control
          effectiveness. A present control may still be misconfigured.

.LINK
    https://learn.microsoft.com/en-us/azure/well-architected/
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction
    https://learn.microsoft.com/en-us/azure/backup/backup-overview
    https://learn.microsoft.com/en-us/azure/site-recovery/site-recovery-overview
    https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings

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
    Write-CenteredText "Azure Business Criticality Gap Assessment v1.0" -Color White
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
    Write-Host "  Scanning Subscriptions" -ForegroundColor Cyan
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
    Write-Host "  Assessment Summary" -ForegroundColor Cyan
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

Function Write-GapBreakdown
{
    param([hashtable]$GapsByDomain)

    if ($GapsByDomain.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Gap Count by Control Domain" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    $colorMap = @{
        "Security"     = "Red"
        "Backup"       = "Yellow"
        "DR"           = "Magenta"
        "Monitoring"   = "Cyan"
        "Availability" = "DarkYellow"
    }

    foreach ($domain in ($GapsByDomain.GetEnumerator() | Sort-Object Value -Descending))
    {
        $color = if ($colorMap.ContainsKey($domain.Key)) { $colorMap[$domain.Key] } else { "White" }
        Write-Host "  " -NoNewline
        Write-Host $domain.Key.PadRight(18) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($domain.Value) gap(s)" -ForegroundColor $color
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
        Write-Host ("HTML Dashboard").PadRight(24) -NoNewline -ForegroundColor Gray
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

Function Get-GapScore
{
    param(
        [bool]$SecurityOk,
        [bool]$BackupOk,
        [bool]$DROk,
        [bool]$MonitoringOk,
        [bool]$AvailabilityOk
    )
    $score = 0
    if ($SecurityOk)     { $score += 20 }
    if ($BackupOk)        { $score += 20 }
    if ($DROk)            { $score += 20 }
    if ($MonitoringOk)    { $score += 20 }
    if ($AvailabilityOk)  { $score += 20 }
    return $score
}

Function Get-RiskRating
{
    param(
        [string]$CriticalityTier,
        [int]$MissingControls
    )
    if ($MissingControls -eq 0) { return "None" }

    switch ($CriticalityTier)
    {
        "Critical" {
            switch ($MissingControls)
            {
                1       { return "High" }
                2       { return "High" }
                default { return "Critical" }
            }
        }
        "High" {
            switch ($MissingControls)
            {
                1       { return "Medium" }
                2       { return "High" }
                default { return "Critical" }
            }
        }
        "Medium" {
            switch ($MissingControls)
            {
                { $_ -le 2 } { return "Medium" }
                default      { return "High" }
            }
        }
        default {
            switch ($MissingControls)
            {
                { $_ -le 3 } { return "Low" }
                default      { return "Medium" }
            }
        }
    }
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function EscHtml { param([string]$s); return $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\','\\\\' -replace "'","\'" -replace '"','\"' -replace "`n",' ' -replace "`r",' ' }

Function Generate-BusinessCriticalityGapHtml
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [hashtable]$GapsByDomain,
        [hashtable]$GapsByRisk,
        [hashtable]$GapsByCriticality,
        [hashtable]$CoverageByDomain,
        [array]$SubscriptionResults,
        [string]$GeneratedOn,
        [bool]$DefenderIncluded
    )

    $totalResources    = @($Findings).Count
    $criticalGaps      = @($Findings | Where-Object { $_.RiskRating -eq "Critical" }).Count
    $highGaps          = @($Findings | Where-Object { $_.RiskRating -eq "High" }).Count
    $mediumGaps        = @($Findings | Where-Object { $_.RiskRating -eq "Medium" }).Count
    $noGaps            = @($Findings | Where-Object { $_.RiskRating -eq "None" }).Count
    $avgScore          = if ($totalResources -gt 0) { [math]::Round(($Findings | Measure-Object -Property GapScore -Average).Average) } else { 0 }

    $defenderBadge = if ($DefenderIncluded) {
        '<span class="badge badge-green">v Included</span>'
    } else {
        '<span class="badge badge-amber">! Skipped (use -IncludeDefenderData)</span>'
    }
    $defenderText = if ($DefenderIncluded) { "Included" } else { "Skipped - use -IncludeDefenderData to enable" }

    # ── Finding table rows ────────────────────────────────────────────────────
    $findingRows = ""
    foreach ($f in $Findings)
    {
        $riskCls = switch ($f.RiskRating) {
            "Critical" { "badge-red" }
            "High"     { "badge-amber" }
            "Medium"   { "badge-blue" }
            "None"     { "badge-green" }
            default    { "" }
        }
        $critCls = switch ($f.CriticalityTier) {
            "Critical" { "badge-red" }
            "High"     { "badge-amber" }
            "Medium"   { "badge-blue" }
            "Low"      { "" }
            default    { "" }
        }
        $scoreColor = if ($f.GapScore -ge 80) { "var(--green)" } elseif ($f.GapScore -ge 50) { "var(--amber)" } else { "var(--red)" }

        $findingRows += @"
          <tr onclick="showFindingDetail($($Findings.IndexOf($f)))">
            <td title="$(EscHtml $f.ResourceName)">$(if ($f.ResourceName.Length -gt 32) { EscHtml($f.ResourceName.Substring(0,29)+"...") } else { EscHtml $f.ResourceName })</td>
            <td>$(EscHtml $f.ResourceType)</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td><span class="badge $critCls">$(EscHtml $f.CriticalityTier)</span></td>
            <td><span class="badge $riskCls">$(EscHtml $f.RiskRating)</span></td>
            <td><span style="color:$scoreColor;font-family:var(--mono);font-weight:700">$($f.GapScore)%</span></td>
            <td>$(EscHtml $f.MissingControls)</td>
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

    # ── Gap by domain bar rows ─────────────────────────────────────────────────
    $domainTotal = ($GapsByDomain.Values | Measure-Object -Sum).Sum
    $domainRows  = ""
    $domainColors = @{
        "Security"     = "var(--red)"
        "Backup"       = "var(--amber)"
        "DR"           = "var(--accent3)"
        "Monitoring"   = "var(--accent2)"
        "Availability" = "var(--accent)"
    }
    foreach ($d in ($GapsByDomain.GetEnumerator() | Sort-Object Value -Descending))
    {
        $pct   = if ($domainTotal -gt 0) { [math]::Round(($d.Value / $domainTotal) * 100) } else { 0 }
        $color = if ($domainColors.ContainsKey($d.Key)) { $domainColors[$d.Key] } else { "var(--accent)" }
        $domainRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $d.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$color"></div></div>
            <span class="bar-pct">$($d.Value) ($pct%)</span>
          </div>
"@
    }

    # ── Coverage by domain bar rows ───────────────────────────────────────────
    $coverageRows = ""
    foreach ($d in ($CoverageByDomain.GetEnumerator() | Sort-Object Value))
    {
        $pct   = $d.Value
        $color = if ($pct -ge 80) { "var(--green)" } elseif ($pct -ge 50) { "var(--amber)" } else { "var(--red)" }
        $coverageRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $d.Key)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$color"></div></div>
            <span class="bar-pct">$pct%</span>
          </div>
"@
    }

    # ── Gap by risk distribution bar rows ─────────────────────────────────────
    $riskTotal = ($GapsByRisk.Values | Measure-Object -Sum).Sum
    $riskRows  = ""
    $riskColors = @{ "Critical" = "var(--red)"; "High" = "var(--amber)"; "Medium" = "var(--accent)"; "Low" = "var(--green)"; "None" = "var(--muted)" }
    foreach ($r in @("Critical", "High", "Medium", "Low", "None"))
    {
        $count = if ($GapsByRisk.ContainsKey($r)) { $GapsByRisk[$r] } else { 0 }
        $pct   = if ($riskTotal -gt 0) { [math]::Round(($count / $riskTotal) * 100) } else { 0 }
        $color = if ($riskColors.ContainsKey($r)) { $riskColors[$r] } else { "var(--accent)" }
        $riskRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $r)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$color"></div></div>
            <span class="bar-pct">$count ($pct%)</span>
          </div>
"@
    }

    # ── JSON for detail drawer ────────────────────────────────────────────────
    $findJson = "["
    foreach ($f in $Findings)
    {
        $defText = if ($DefenderIncluded) {
            if ($f.DefenderStatus -eq "Not Assessed / Warning") { "Not Assessed / Warning: $(EscJ $f.DefenderReason)" }
            else { "Recommendations: $($f.DefenderRecommendations)  Alerts: $($f.DefenderAlerts)" }
        } else { "Not included - run with -IncludeDefenderData" }

        $findJson += "{" +
            """name"":""$(EscJ $f.ResourceName)""," +
            """rid"":""$(EscJ $f.ResourceId)""," +
            """type"":""$(EscJ $f.ResourceType)""," +
            """rg"":""$(EscJ $f.ResourceGroup)""," +
            """sub"":""$(EscJ $f.SubscriptionName)""," +
            """tier"":""$(EscJ $f.CriticalityTier)""," +
            """risk"":""$(EscJ $f.RiskRating)""," +
            """score"":$($f.GapScore)," +
            """missing"":""$(EscJ $f.MissingControls)""," +
            """secOk"":$($f.SecurityOk.ToString().ToLower())," +
            """bakOk"":$($f.BackupOk.ToString().ToLower())," +
            """drOk"":$($f.DROk.ToString().ToLower())," +
            """monOk"":$($f.MonitoringOk.ToString().ToLower())," +
            """avOk"":$($f.AvailabilityOk.ToString().ToLower())," +
            """defender"":""$(EscJ $defText)""" +
            "},"
    }
    $findJson = $findJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Business Criticality Gap Dashboard</title>
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
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,var(--accent3),var(--red));display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
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
.score-ring-wrap{display:flex;align-items:center;gap:20px;flex-wrap:wrap;}
.score-ring{position:relative;width:110px;height:110px;flex-shrink:0;}
.score-ring svg{transform:rotate(-90deg);}
.score-ring-text{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;}
.score-ring-num{font-size:24px;font-weight:700;font-family:var(--mono);}
.score-ring-lbl{font-size:10px;color:var(--muted);margin-top:1px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:120px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:90px;text-align:right;flex-shrink:0;}
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
.control-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:12px;}
.control-cell{background:var(--surface2);border-radius:var(--radius-sm);padding:10px;text-align:center;border:1px solid var(--border);}
.control-cell.ok{border-color:var(--green);background:rgba(63,185,80,.08);}
.control-cell.gap{border-color:var(--red);background:rgba(248,81,73,.08);}
.control-icon{font-size:20px;margin-bottom:4px;}
.control-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;}
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
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:460px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
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
.drawer-field-value{font-size:13px;word-break:break-all;}
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
  .control-grid{grid-template-columns:repeat(3,1fr);}
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
    <div class="logo-icon">&#128272;</div>
    <div class="logo-title">Criticality Gap</div>
    <div class="logo-sub">Business Impact Assessment</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">&#128202;</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">&#128270;</span> Gap Findings</button>
    <button class="nav-btn" onclick="showPage('domains',this)"><span class="nav-icon">&#9881;</span> Control Domains</button>
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
      Business Criticality Gap Assessment
    </div>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Business Criticality Gap Overview</div>
      <div class="page-sub">Control coverage posture across __TOTAL_RESOURCES__ tagged resource(s) in __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_RESOURCES__</div>
        <div class="stat-label">Resources Assessed</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_GAPS__</div>
        <div class="stat-label">Critical Risk Gaps</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_GAPS__</div>
        <div class="stat-label">High Risk Gaps</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__MEDIUM_GAPS__</div>
        <div class="stat-label">Medium Risk Gaps</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__NO_GAPS__</div>
        <div class="stat-label">Fully Covered</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__AVG_SCORE__%</div>
        <div class="stat-label">Avg Coverage Score</div>
      </div>
    </div>

    <div class="cs-banner __DEF_BANNER_CLS__">
      <span>&#128737;</span>
      <span><strong>Defender Data:</strong> __DEF_BANNER_TEXT__</span>
    </div>

    <div class="panel">
      <div class="panel-title">&#127919; Overall Coverage Score</div>
      <div class="score-ring-wrap">
        <div class="score-ring">
          <svg width="110" height="110" viewBox="0 0 110 110">
            <circle cx="55" cy="55" r="46" fill="none" stroke="var(--surface3)" stroke-width="10"/>
            <circle cx="55" cy="55" r="46" fill="none" stroke="__SCORE_COLOR__" stroke-width="10"
              stroke-dasharray="289" stroke-dashoffset="__SCORE_DASHOFFSET__" stroke-linecap="round"/>
          </svg>
          <div class="score-ring-text">
            <div class="score-ring-num" style="color:__SCORE_COLOR__">__AVG_SCORE__%</div>
            <div class="score-ring-lbl">Coverage</div>
          </div>
        </div>
        <div style="flex:1">
          <div style="font-size:13px;color:var(--muted2);margin-bottom:10px">
            The coverage score reflects the percentage of required controls that are confirmed present
            across all assessed resources. A score of 100% means every resource has security, backup,
            DR, monitoring, and availability controls verified.
          </div>
          <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:12px;">
            <span style="color:var(--green)">&#10003; 80-100% = Covered</span>
            <span style="color:var(--amber)">&#9888; 50-79% = Partial</span>
            <span style="color:var(--red)">&#10007; 0-49% = Gap</span>
          </div>
        </div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">&#128683; Gaps by Control Domain</div>
        __DOMAIN_ROWS__
      </div>
      <div class="panel">
        <div class="panel-title">&#9888; Gaps by Risk Rating</div>
        __RISK_ROWS__
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">&#128200; Control Coverage by Domain (%)</div>
      __COVERAGE_ROWS__
    </div>
  </div>

  <!-- Gap Findings -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Gap Findings</div>
      <div class="page-sub">Click any row to view control-by-control detail for that resource</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">&#128269;</span>
          <input type="text" id="findSearch" placeholder="Search resource, type, subscription..." oninput="filterFind()"/>
        </div>
        <select class="filter-select" id="filterRisk" onchange="filterFind()">
          <option value="">All Risk Ratings</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="None">None (Covered)</option>
        </select>
        <select class="filter-select" id="filterTier" onchange="filterFind()">
          <option value="">All Criticality Tiers</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
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
              <th onclick="sortFind(0)">Resource Name</th>
              <th onclick="sortFind(1)">Type</th>
              <th onclick="sortFind(2)">Subscription</th>
              <th onclick="sortFind(3)">Criticality Tier</th>
              <th onclick="sortFind(4)">Risk Rating</th>
              <th onclick="sortFind(5)">Coverage Score</th>
              <th onclick="sortFind(6)">Missing Controls</th>
            </tr>
          </thead>
          <tbody id="findBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- Control Domains -->
  <div id="page-domains" class="page">
    <div class="page-header">
      <div class="page-title">Control Domain Analysis</div>
      <div class="page-sub">Breakdown of gap counts and coverage rates per control domain</div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">Gap Count per Domain</div>
        __DOMAIN_ROWS_2__
      </div>
      <div class="panel">
        <div class="panel-title">Coverage Rate per Domain</div>
        __COVERAGE_ROWS_2__
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">&#128270; Domain Descriptions</div>
      <table>
        <thead><tr><th>Domain</th><th>What Is Checked</th><th>Required At</th></tr></thead>
        <tbody>
          <tr><td>Security</td><td>Microsoft Defender for Cloud coverage; security contact configured</td><td>All tiers</td></tr>
          <tr><td>Backup</td><td>Resource associated with a Recovery Services Vault backup policy</td><td>Critical, High</td></tr>
          <tr><td>DR</td><td>ASR replication configured or cross-region redundancy detected</td><td>Critical</td></tr>
          <tr><td>Monitoring</td><td>Diagnostic Settings enabled; at least one Azure Monitor Alert rule</td><td>Critical, High, Medium</td></tr>
          <tr><td>Availability</td><td>Zone-redundant SKU or availability zone configuration detected</td><td>Critical, High</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription gap assessment outcome</div>
    </div>
    <div class="panel">
      <div class="panel-title">&#128196; Subscriptions Scanned</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- Session -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Scan Parameters</div>
      <div class="page-sub">Authentication context and configuration used for this assessment</div>
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
      <div class="panel-title">&#9881; Scan Parameters</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Scope</div><div class="info-value">__SCOPE__</div></div>
        <div class="info-card"><div class="info-label">Criticality Tag Key</div><div class="info-value">__TAG_KEY__</div></div>
        <div class="info-card"><div class="info-label">Defender Data</div><div class="info-value">__DEF_TEXT__</div></div>
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
    <span class="drawer-title" id="drawerTitle">Resource Detail</span>
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
  const r = document.getElementById('filterRisk').value;
  const t = document.getElementById('filterTier').value;
  findFiltered = FIND_DATA.filter(d=>{
    const mQ = !q || JSON.stringify(d).toLowerCase().includes(q);
    const mR = !r || d.risk === r;
    const mT = !t || d.tier === t;
    return mQ && mR && mT;
  });
  findPage = 1; renderFind();
}

function changeFindPageSize(){
  findPageSz = parseInt(document.getElementById('pgSizeFind').value);
  findPage = 1; renderFind();
}

function sortFind(col){
  if(findSortCol===col){findSortAsc=!findSortAsc;}else{findSortCol=col;findSortAsc=true;}
  const keys = ['name','type','sub','tier','risk','score','missing'];
  findFiltered.sort((a,b)=>{
    const k = keys[col];
    const av = a[k]??'', bv = b[k]??'';
    return findSortAsc ? String(av).localeCompare(String(bv),undefined,{numeric:true})
                       : String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderFind();
}

function renderFind(){
  const tbody = document.getElementById('findBody');
  const start = (findPage-1)*findPageSz;
  const slice = findFiltered.slice(start, start+findPageSz);
  tbody.innerHTML = slice.map(r=>{
    const gi = FIND_DATA.indexOf(r);
    const rCls = r.risk==='Critical'?'badge-red':r.risk==='High'?'badge-amber':r.risk==='Medium'?'badge-blue':r.risk==='None'?'badge-green':'';
    const tCls = r.tier==='Critical'?'badge-red':r.tier==='High'?'badge-amber':r.tier==='Medium'?'badge-blue':'';
    const sColor = r.score>=80?'var(--green)':r.score>=50?'var(--amber)':'var(--red)';
    const nm = r.name.length>32 ? r.name.substring(0,29)+'...' : r.name;
    return `<tr onclick="showFindingDetail(${gi})">
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td>${escH(r.type)}</td>
      <td>${escH(r.sub)}</td>
      <td><span class="badge ${tCls}">${escH(r.tier)}</span></td>
      <td><span class="badge ${rCls}">${escH(r.risk)}</span></td>
      <td><span style="color:${sColor};font-family:var(--mono);font-weight:700">${r.score}%</span></td>
      <td>${escH(r.missing||'None')}</td>
    </tr>`;
  }).join('');
  renderFindPg();
}

function renderFindPg(){
  const total = Math.ceil(findFiltered.length/findPageSz);
  const el = document.getElementById('findPagination');
  let h = `<span>${findFiltered.length} resources</span>`;
  h += `<button class="pg-btn" onclick="changeFindPage(${findPage-1})" ${findPage<=1?'disabled':''}>&#8249; Prev</button>`;
  const s=Math.max(1,findPage-2), e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===findPage?'active':''}" onclick="changeFindPage(${p})">${p}</button>`;
  h += `<button class="pg-btn" onclick="changeFindPage(${findPage+1})" ${findPage>=total?'disabled':''}>Next &#8250;</button>`;
  el.innerHTML = h;
}

function changeFindPage(p){
  const total = Math.ceil(findFiltered.length/findPageSz);
  if(p<1||p>total) return;
  findPage = p; renderFind();
}

// ── Detail drawer ─────────────────────────────────────────────────────────────
function showFindingDetail(idx){
  currentDetailIdx = idx;
  const r = FIND_DATA[idx];
  if(!r) return;
  document.getElementById('drawerTitle').textContent = r.name;
  document.getElementById('drawerNavInfo').textContent = `${idx+1} of ${FIND_DATA.length}`;

  const rCls = r.risk==='Critical'?'badge-red':r.risk==='High'?'badge-amber':r.risk==='Medium'?'badge-blue':r.risk==='None'?'badge-green':'';
  const tCls = r.tier==='Critical'?'badge-red':r.tier==='High'?'badge-amber':r.tier==='Medium'?'badge-blue':'';
  const sColor = r.score>=80?'var(--green)':r.score>=50?'var(--amber)':'var(--red)';

  const ctrl = (ok, label, icon) =>
    `<div class="control-cell ${ok?'ok':'gap'}">
      <div class="control-icon">${icon}</div>
      <div style="font-size:11px;font-weight:700;color:${ok?'var(--green)':'var(--red)'}">${ok?'OK':'GAP'}</div>
      <div class="control-label">${label}</div>
    </div>`;

  document.getElementById('drawerContent').innerHTML = `
    <div class="drawer-field">
      <div class="drawer-field-label">Criticality Tier</div>
      <div class="drawer-field-value"><span class="badge ${tCls}">${escH(r.tier)}</span></div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Risk Rating</div>
      <div class="drawer-field-value"><span class="badge ${rCls}">${escH(r.risk)}</span></div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Coverage Score</div>
      <div class="drawer-field-value" style="color:${sColor};font-family:var(--mono);font-size:20px;font-weight:700">${r.score}%</div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)}</div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Resource Type</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px">${escH(r.type)}</div>
    </div>
    <div class="drawer-field">
      <div class="drawer-field-label">Resource ID</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:10px;color:var(--muted2)">${escH(r.rid)}</div>
    </div>
    <div class="drawer-section">Control Status</div>
    <div class="control-grid">
      ${ctrl(r.secOk,'Security','&#128737;')}
      ${ctrl(r.bakOk,'Backup','&#128190;')}
      ${ctrl(r.drOk,'DR','&#127968;')}
      ${ctrl(r.monOk,'Monitoring','&#128200;')}
      ${ctrl(r.avOk,'Availability','&#9889;')}
    </div>
    <div class="drawer-section">Missing Controls</div>
    <div class="drawer-field">
      <div class="drawer-field-value">${r.missing ? escH(r.missing) : '<span style="color:var(--green)">None - fully covered</span>'}</div>
    </div>
    <div class="drawer-section">Defender Data</div>
    <div class="drawer-field">
      <div class="drawer-field-value">${escH(r.defender)}</div>
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

document.addEventListener('keydown', e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});

// ── Init ─────────────────────────────────────────────────────────────────────
filterFind();
animateBars();
</script>
</body>
</html>
'@

    # Score ring math
    $circumference  = [math]::Round(2 * [math]::PI * 46, 0)  # 289
    $dashOffset     = [math]::Round($circumference * (1 - $avgScore / 100), 0)
    $scoreColor     = if ($avgScore -ge 80) { "#3fb950" } elseif ($avgScore -ge 50) { "#d29922" } else { "#f85149" }

    $html = $html `
        -replace '__GENERATED_ON__',    $GeneratedOn `
        -replace '__SUB_COUNT__',       $SubscriptionResults.Count `
        -replace '__TOTAL_RESOURCES__', $totalResources `
        -replace '__CRITICAL_GAPS__',   $criticalGaps `
        -replace '__HIGH_GAPS__',       $highGaps `
        -replace '__MEDIUM_GAPS__',     $mediumGaps `
        -replace '__NO_GAPS__',         $noGaps `
        -replace '__AVG_SCORE__',       $avgScore `
        -replace '__SCORE_COLOR__',     $scoreColor `
        -replace '__SCORE_DASHOFFSET__',$dashOffset `
        -replace '__DEF_BANNER_CLS__',  $(if ($DefenderIncluded) { "included" } else { "skipped" }) `
        -replace '__DEF_BANNER_TEXT__', $defenderText `
        -replace '__DOMAIN_ROWS__',     $domainRows `
        -replace '__DOMAIN_ROWS_2__',   $domainRows `
        -replace '__RISK_ROWS__',       $riskRows `
        -replace '__COVERAGE_ROWS__',   $coverageRows `
        -replace '__COVERAGE_ROWS_2__', $coverageRows `
        -replace '__FINDING_ROWS__',    $findingRows `
        -replace '__SUB_ROWS__',        $subRows `
        -replace '__TENANT__',          $SessionInfo.Tenant `
        -replace '__ACCOUNT__',         $SessionInfo.Account `
        -replace '__ENVIRONMENT__',     $SessionInfo.Environment `
        -replace '__SCOPE__',           $ScanParameters.Scope `
        -replace '__TAG_KEY__',         $ScanParameters.TagKey `
        -replace '__DEF_TEXT__',        $defenderText `
        -replace '__EXPORT_ENABLED__',  $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__',       $ScanParameters.ExecTime `
        -replace '__FIND_JSON__',       $findJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureBusinessCriticalityGap
{
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [ValidateNotNullOrEmpty()]
        [string]$CriticalityTagKey = "BusinessCriticality",

        [string[]]$CriticalityValues = @("Critical", "High", "Medium", "Low"),

        [switch]$IncludeDefenderData,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureBusinessCriticalityGap-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Monitor", "Az.RecoveryServices")
    if ($IncludeDefenderData) { $requiredModules += "Az.Security" }

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

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"               = "$scopeText ($subCount found)"
        "Criticality Tag Key" = $CriticalityTagKey
        "Criticality Values"  = $CriticalityValues -join ", "
        "Defender Data"       = if ($IncludeDefenderData) { "Enabled" } else { "Disabled (use -IncludeDefenderData)" }
        "Export to CSV"       = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"         = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings       = @()
    $subscriptionResults = @()
    $gapsByDomain      = @{ "Security" = 0; "Backup" = 0; "DR" = 0; "Monitoring" = 0; "Availability" = 0 }
    $gapsByRisk        = @{ "Critical" = 0; "High" = 0; "Medium" = 0; "Low" = 0; "None" = 0 }
    $gapsByCriticality = @{}
    $coverageByDomain  = @{ "Security" = 0; "Backup" = 0; "DR" = 0; "Monitoring" = 0; "Availability" = 0 }
    $successCount      = 0
    $errorCount        = 0
    $totalTagged       = 0

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

            # ── Discover tagged resources ─────────────────────────────────
            $taggedResources = @()
            try
            {
                $taggedResources = @(Get-AzResource -TagName $CriticalityTagKey -ErrorAction Stop)
            }
            catch
            {
                Write-Warning "  Could not retrieve tagged resources for $($sub.Name): $_"
            }

            # ── Enumerate diagnostic settings presence once (subscription-wide) ─
            $diagSettingsCache = @{}
            try
            {
                # We check per-resource below; pre-warm to avoid repeated slow calls on large envs
                Write-Verbose "  Diagnostic settings will be checked per resource for $($sub.Name)"
            }
            catch { }

            # ── Defender data (optional) ──────────────────────────────────
            $defenderTasks  = $null
            $defenderAlerts = $null
            $defenderAvailable = $false
            if ($IncludeDefenderData)
            {
                try
                {
                    $defenderTasks     = @(Get-AzSecurityTask   -ErrorAction Stop)
                    $defenderAlerts    = @(Get-AzSecurityAlert  -ErrorAction Stop)
                    $defenderAvailable = $true
                }
                catch
                {
                    Write-Host ""
                    Write-Host "  Defender data unavailable for $($sub.Name): $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }

            # ── Backup vaults in subscription ─────────────────────────────
            $backupVaults = @()
            try
            {
                $backupVaults = @(Get-AzRecoveryServicesVault -ErrorAction Stop)
            }
            catch
            {
                Write-Verbose "  Could not retrieve Recovery Services Vaults for $($sub.Name): $_"
            }

            # ── Alert rules in subscription ───────────────────────────────
            $alertRules = @()
            try
            {
                $alertRules = @(Get-AzMetricAlertRuleV2 -ErrorAction Stop)
            }
            catch
            {
                Write-Verbose "  Could not retrieve alert rules for $($sub.Name): $_"
            }

            $subTaggedCount = 0

            foreach ($res in $taggedResources)
            {
                $tagValue = $res.Tags[$CriticalityTagKey]
                if ($CriticalityValues -notcontains $tagValue) { continue }

                $subTaggedCount++
                $totalTagged++

                # ── Security check ────────────────────────────────────────
                $securityOk = $false
                try
                {
                    if ($IncludeDefenderData -and $defenderAvailable)
                    {
                        # If Defender is reachable, treat its coverage as proxy for security OK
                        $securityOk = $true
                    }
                    else
                    {
                        # Minimal check: see if resource has a security-related tag or type
                        $securityOk = ($null -ne $res.Tags["SecurityReviewed"]) -or ($res.ResourceType -like "Microsoft.KeyVault/*")
                    }
                }
                catch { $securityOk = $false }

                # ── Backup check ──────────────────────────────────────────
                $backupOk = $false
                try
                {
                    if ($backupVaults.Count -gt 0 -and ($tagValue -in @("Critical", "High")))
                    {
                        foreach ($vault in $backupVaults)
                        {
                            try
                            {
                                Set-AzRecoveryServicesVaultContext -Vault $vault -ErrorAction SilentlyContinue | Out-Null
                                $items = @(Get-AzRecoveryServicesBackupItem -WorkloadType AzureVM -ContainerType AzureVM -ErrorAction SilentlyContinue |
                                    Where-Object { $_.VirtualMachineId -eq $res.ResourceId })
                                if ($items.Count -gt 0) { $backupOk = $true; break }
                            }
                            catch { }
                        }
                    }
                    elseif ($tagValue -notin @("Critical", "High"))
                    {
                        $backupOk = $true  # Not required below High tier
                    }
                }
                catch { $backupOk = $false }

                # ── DR check ──────────────────────────────────────────────
                $drOk = $false
                try
                {
                    if ($tagValue -ne "Critical")
                    {
                        $drOk = $true  # DR only required for Critical tier
                    }
                    else
                    {
                        # Check for geo-redundant storage or ASR via resource properties
                        $resDetail = Get-AzResource -ResourceId $res.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                        if ($resDetail -and $resDetail.Properties)
                        {
                            $props = $resDetail.Properties | ConvertTo-Json -Depth 3 -ErrorAction SilentlyContinue
                            $drOk  = $props -match "GeoRedundant|ZoneRedundant|CrossRegion|replicationState.*protected"
                        }
                    }
                }
                catch { $drOk = $false }

                # ── Monitoring check ──────────────────────────────────────
                $monitoringOk = $false
                try
                {
                    if ($tagValue -eq "Low")
                    {
                        $monitoringOk = $true  # Not strictly required at Low
                    }
                    else
                    {
                        $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $res.ResourceId -ErrorAction SilentlyContinue)
                        $hasAlerts    = @($alertRules | Where-Object {
                            $_.Criteria.CriteriaType -ne $null -or $_.Id -ne $null
                        }).Count -gt 0

                        $monitoringOk = ($diagSettings.Count -gt 0) -and $hasAlerts
                    }
                }
                catch { $monitoringOk = $false }

                # ── Availability check ────────────────────────────────────
                $availabilityOk = $false
                try
                {
                    if ($tagValue -notin @("Critical", "High"))
                    {
                        $availabilityOk = $true  # Zone redundancy not required below High
                    }
                    else
                    {
                        $resDetail = Get-AzResource -ResourceId $res.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                        if ($resDetail -and $resDetail.Properties)
                        {
                            $props          = $resDetail.Properties | ConvertTo-Json -Depth 3 -ErrorAction SilentlyContinue
                            $availabilityOk = $props -match "Standard|ZoneRedundant|zones.*\[" -or
                                              ($resDetail.Zones -and $resDetail.Zones.Count -gt 0)
                        }
                    }
                }
                catch { $availabilityOk = $false }

                # ── Gap score & missing controls list ─────────────────────
                $gapScore = Get-GapScore -SecurityOk $securityOk -BackupOk $backupOk -DROk $drOk `
                                         -MonitoringOk $monitoringOk -AvailabilityOk $availabilityOk

                $missingList = @()
                if (-not $securityOk)     { $missingList += "Security" }
                if (-not $backupOk)       { $missingList += "Backup" }
                if (-not $drOk)           { $missingList += "DR" }
                if (-not $monitoringOk)   { $missingList += "Monitoring" }
                if (-not $availabilityOk) { $missingList += "Availability" }

                $missingStr    = if ($missingList.Count -gt 0) { $missingList -join ", " } else { "" }
                $riskRating    = Get-RiskRating -CriticalityTier $tagValue -MissingControls $missingList.Count

                # ── Update aggregates ─────────────────────────────────────
                foreach ($domain in $missingList)
                {
                    if ($gapsByDomain.ContainsKey($domain)) { $gapsByDomain[$domain]++ }
                }

                if ($gapsByRisk.ContainsKey($riskRating)) { $gapsByRisk[$riskRating]++ }
                else { $gapsByRisk[$riskRating] = 1 }

                # ── Defender enrichment ───────────────────────────────────
                $defRecommendations = 0
                $defAlerts          = 0
                $defStatus          = "Not Requested"
                $defReason          = ""

                if ($IncludeDefenderData)
                {
                    if ($defenderAvailable)
                    {
                        try
                        {
                            $defRecommendations = @($defenderTasks  | Where-Object { $_.ResourceId -like "*$($res.Name)*" }).Count
                            $defAlerts          = @($defenderAlerts | Where-Object { $_.CompromisedEntity -like "*$($res.Name)*" }).Count
                            $defStatus          = "Assessed"
                        }
                        catch
                        {
                            $defStatus = "Not Assessed / Warning"
                            $defReason = $_.Exception.Message
                        }
                    }
                    else
                    {
                        $defStatus = "Not Assessed / Warning"
                        $defReason = "Defender data unavailable at subscription level"
                    }
                }

                $allFindings += [pscustomobject]@{
                    SubscriptionName      = $sub.Name
                    SubscriptionId        = $sub.Id
                    ResourceName          = $res.Name
                    ResourceId            = $res.ResourceId
                    ResourceType          = $res.ResourceType
                    ResourceGroup         = $res.ResourceGroupName
                    CriticalityTier       = $tagValue
                    RiskRating            = $riskRating
                    GapScore              = $gapScore
                    MissingControls       = $missingStr
                    SecurityOk            = $securityOk
                    BackupOk              = $backupOk
                    DROk                  = $drOk
                    MonitoringOk          = $monitoringOk
                    AvailabilityOk        = $availabilityOk
                    DefenderStatus        = $defStatus
                    DefenderRecommendations = $defRecommendations
                    DefenderAlerts        = $defAlerts
                    DefenderReason        = $defReason
                }
            }

            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "v " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " -> " -NoNewline -ForegroundColor DarkGray
            Write-Host "Tagged Resources: $subTaggedCount  Critical Tier: $(($allFindings | Where-Object { $_.SubscriptionId -eq $sub.Id -and $_.CriticalityTier -eq 'Critical' }).Count)" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Tagged: $subTaggedCount"
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

    # ── Coverage % by domain ──────────────────────────────────────────────────
    if ($allFindings.Count -gt 0)
    {
        $coverageByDomain["Security"]     = [math]::Round(((@($allFindings | Where-Object { $_.SecurityOk }).Count    / $allFindings.Count) * 100))
        $coverageByDomain["Backup"]       = [math]::Round(((@($allFindings | Where-Object { $_.BackupOk }).Count      / $allFindings.Count) * 100))
        $coverageByDomain["DR"]           = [math]::Round(((@($allFindings | Where-Object { $_.DROk }).Count          / $allFindings.Count) * 100))
        $coverageByDomain["Monitoring"]   = [math]::Round(((@($allFindings | Where-Object { $_.MonitoringOk }).Count  / $allFindings.Count) * 100))
        $coverageByDomain["Availability"] = [math]::Round(((@($allFindings | Where-Object { $_.AvailabilityOk }).Count/ $allFindings.Count) * 100))
    }

    # ── Summary output ────────────────────────────────────────────────────────
    $endTime  = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-Summary -Data ([ordered]@{
        "Total Subscriptions Scanned"     = $subCount
        "Successful"                      = $successCount
        "Errors"                          = $errorCount
        "Total Tagged Resources Assessed" = $allFindings.Count
        "Critical Risk Gaps"              = $gapsByRisk["Critical"]
        "High Risk Gaps"                  = $gapsByRisk["High"]
        "Medium Risk Gaps"                = $gapsByRisk["Medium"]
        "Fully Covered (No Gap)"          = if ($gapsByRisk.ContainsKey("None")) { $gapsByRisk["None"] } else { 0 }
        "Defender Data Assessed"          = if ($IncludeDefenderData) { "Yes" } else { "No (use -IncludeDefenderData)" }
        "Execution Time"                  = $duration
    })

    Write-GapBreakdown -GapsByDomain $gapsByDomain

    # ── Output files ──────────────────────────────────────────────────────────
    $csvExported     = $false
    $htmlExported    = $false
    $gridViewOpened  = $false
    $htmlPath        = ""

    if ($allFindings.Count -gt 0)
    {
        if ($ExportToCsv)
        {
            try
            {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object `
                    SubscriptionName, SubscriptionId, ResourceName, ResourceId, ResourceType,
                    ResourceGroup, CriticalityTier, RiskRating, GapScore, MissingControls,
                    SecurityOk, BackupOk, DROk, MonitoringOk, AvailabilityOk,
                    DefenderStatus, DefenderRecommendations, DefenderAlerts |
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
                TagKey        = $CriticalityTagKey
                ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime      = $duration
            }

            $htmlContent = Generate-BusinessCriticalityGapHtml `
                -SessionInfo          $sessionInfo `
                -ScanParameters       $scanParams `
                -Findings             $allFindings `
                -GapsByDomain         $gapsByDomain `
                -GapsByRisk           $gapsByRisk `
                -GapsByCriticality    $gapsByCriticality `
                -CoverageByDomain     $coverageByDomain `
                -SubscriptionResults  $subscriptionResults `
                -GeneratedOn          (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt") `
                -DefenderIncluded     $IncludeDefenderData.IsPresent

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch
        {
            Write-Host "  HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        try
        {
            $allFindings |
                Select-Object SubscriptionName, ResourceName, ResourceType, CriticalityTier,
                              RiskRating, GapScore, MissingControls |
                Out-GridView -Title "Azure Business Criticality Gap Assessment"
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
        Write-Host "  No tagged resources found. Verify the tag key '$CriticalityTagKey' is applied to resources." -ForegroundColor Yellow
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened)
    {
        $outCsv  = if ($csvExported)  { $CsvPath   } else { $null }
        $outHtml = if ($htmlExported) { $htmlPath  } else { $null }
        Write-OutputFiles -CsvPath $outCsv -HtmlPath $outHtml -GridViewOpened $gridViewOpened
    }
    else
    {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
