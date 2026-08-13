<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 13 August 2026
Modified-On     : 13 August 2026

.SYNOPSIS
    Validates mandatory enterprise tags across Azure resources in one or more
    subscriptions, with CSV export and an interactive HTML compliance dashboard.

.DESCRIPTION
    Get-AzureResourceTagCompliance scans Azure resources across one or multiple
    subscriptions and evaluates each resource against a configurable set of
    mandatory enterprise tags.

    Default mandatory tags assessed:
        Application, Owner, Environment, CostCenter,
        DataClassification, BusinessCriticality

    For each resource the script determines:
        - Which mandatory tags are present or missing
        - A compliance status: Compliant (0 missing) / Partial (1-2 missing) /
          Non-Compliant (3 or more missing)
        - Tag coverage percentage per tag across the environment

    It supports:
        - Scanning all subscriptions or a specified list via -SubscriptionIds
        - Narrowing scope to a specific Resource Group via -ResourceGroupName
        - Filtering by resource type via -ResourceType (e.g. Microsoft.Storage)
        - Overriding the default mandatory tag set via -MandatoryTags
        - Optional CSV export of all per-resource findings
        - Always-on interactive HTML dashboard (dark/light theme, sortable table,
          tag-coverage bar chart, donut charts, distribution panels)
        - Real-time progress bar and color-coded per-subscription console output
        - Interactive Grid View display of results where a GUI is available

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    This is the default behavior when -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ResourceGroupName
    Optional. Restricts the scan to a single resource group within each targeted
    subscription. Useful for focused, lower-blast-radius assessments.

.PARAMETER ResourceType
    Optional. Restricts results to resources belonging to a specific Azure
    resource provider, e.g. "Microsoft.Storage", "Microsoft.KeyVault",
    "Microsoft.Compute".

.PARAMETER MandatoryTags
    String array of tag names to enforce. Defaults to:
    @("Application","Owner","Environment","CostCenter","DataClassification","BusinessCriticality")
    Override this to match your organization's tagging policy.

.PARAMETER ExportToCsv
    Switch. If specified, exports all resource tag compliance findings to the
    path given in -CsvPath. The HTML dashboard is always generated regardless
    of whether this switch is used.

.PARAMETER CsvPath
    Path where the CSV export will be written when -ExportToCsv is specified.
    Also used to derive the HTML dashboard file name (same path, .html extension).
    Default: C:\Temp\AzureTagCompliance-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML dashboard alongside
    -CsvPath (or the default path). Optionally writes a CSV file when
    -ExportToCsv is specified. Displays results in an interactive Grid View
    window where a GUI is available.

.EXAMPLE
    Get-AzureResourceTagCompliance -AllSubscriptions

.EXAMPLE
    Get-AzureResourceTagCompliance -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    Get-AzureResourceTagCompliance -AllSubscriptions -ResourceType "Microsoft.Storage"

.EXAMPLE
    Get-AzureResourceTagCompliance -AllSubscriptions -ResourceGroupName "rg-prod-core"

.EXAMPLE
    Get-AzureResourceTagCompliance -AllSubscriptions -MandatoryTags @("Owner","Environment","CostCenter")

.EXAMPLE
    Get-AzureResourceTagCompliance -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\TagCompliance.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (13-Aug-2026) - Initial release. Mandatory tag validation across
                            subscriptions with compliance rating, CSV export,
                            and interactive HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources) — installed
           automatically with user consent if not present.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role (minimum) at the subscription level.
        4. Microsoft.Resources/resources/read permission on each subscription.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Get-AzResource does not return Management Group-scoped resources;
          compliance is assessed at subscription scope and below only.
        - Interactive Grid View requires a GUI-capable session (Windows PowerShell
          ISE or Microsoft.PowerShell.GraphicalTools on PS7). Skipped gracefully
          in headless/CI/Linux sessions; CSV/HTML output is unaffected.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - Tag names are matched case-insensitively; tag values are not validated.
        - Resources without a Tags property (some extension resource types) are
          recorded as Non-Compliant with all mandatory tags missing.

.LINK
    https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources
    https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects
    https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azresource

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
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Resource Tag Compliance Scanner v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
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
    Write-Host ("─" * 76) -ForegroundColor DarkGray

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
        Write-Host $key.PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-ScanProgress
{
    Write-Host ""
    Write-Host "  Scanning Subscriptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
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
    $completed  = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $remaining  = $BarWidth - $completed
    $bar        = ("█" * $completed) + ("░" * $remaining)

    Write-Host "`r" -NoNewline
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White

    if ($CurrentItem)
    {
        $maxLen     = 35
        $displayItem = $(if ($CurrentItem.Length -gt $maxLen) { $CurrentItem.Substring(0, $maxLen - 3) + "..." } else { $CurrentItem })
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-Summary
{
    param([hashtable]$Data)

    Write-Host ""
    Write-Host "  Scan Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys)
    {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(34) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-TagCoverage
{
    param(
        [hashtable]$TagCoverage,
        [int]$TotalResources
    )

    if ($TotalResources -eq 0 -or $TagCoverage.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  Tag Coverage by Mandatory Tag" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($tag in ($TagCoverage.GetEnumerator() | Sort-Object Key))
    {
        $pct   = [math]::Round(($tag.Value / $TotalResources) * 100)
        $color = $(if ($pct -ge 80) { "Green" } elseif ($pct -ge 50) { "Yellow" } else { "Red" })
        Write-Host "  " -NoNewline
        Write-Host $tag.Key.PadRight(26) -NoNewline -ForegroundColor White
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host ("{0}% ({1}/{2} resources)" -f $pct, $tag.Value, $TotalResources) -ForegroundColor $color
    }
}

Function Write-ComplianceDistribution
{
    param(
        [int]$Compliant,
        [int]$Partial,
        [int]$NonCompliant,
        [int]$Total
    )

    if ($Total -eq 0) { return }

    Write-Host ""
    Write-Host "  Compliance Distribution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    $items = [ordered]@{
        "Compliant"     = @{ Count = $Compliant;    Color = "Green"  }
        "Partial"       = @{ Count = $Partial;      Color = "Yellow" }
        "Non-Compliant" = @{ Count = $NonCompliant; Color = "Red"    }
    }

    foreach ($label in $items.Keys)
    {
        $count = $items[$label].Count
        $pct   = [math]::Round(($count / $Total) * 100)
        Write-Host "  " -NoNewline
        Write-Host $label.PadRight(20) -NoNewline -ForegroundColor $items[$label].Color
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host "$count resources ($pct%)" -ForegroundColor White
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
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    if ($CsvPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("CSV Export").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }

    if ($HtmlPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Dashboard").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }

    if ($GridViewOpened)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("Grid View").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": Opened in separate window" -ForegroundColor White
    }

    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}


#------------------------------------------------------------------------ [ HTML Dashboard ]

Function Generate-TagComplianceHtml
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [hashtable]$ScanSummary,
        [array]$SubscriptionResults,
        [hashtable]$TagCoverage,
        [int]$TotalResources,
        [int]$Compliant,
        [int]$Partial,
        [int]$NonCompliant,
        [hashtable]$ResourceTypeDistribution,
        [array]$AllFindings,
        [string]$GeneratedOn
    )

    # ── Compliance score (0-100) ──────────────────────────────────────────────
    $complianceScore = $(if ($TotalResources -gt 0) {
        [math]::Round((($Compliant + ($Partial * 0.5)) / $TotalResources) * 100)
    } else { 0 })

    $scoreColor = $(if ($complianceScore -ge 80) { "#3fb950" }
                  elseif ($complianceScore -ge 50) { "#d29922" }
                  else { "#f85149" })

    # SVG ring math (r=54 → circumference≈339)
    $ringCirc  = 339
    $ringDash  = [math]::Round($complianceScore / 100 * $ringCirc)
    $ringGap   = $ringCirc - $ringDash

    # ── Per-tag coverage rows ─────────────────────────────────────────────────
    $tagCoverageRows = ""
    foreach ($tag in ($TagCoverage.GetEnumerator() | Sort-Object Key))
    {
        $pct       = $(if ($TotalResources -gt 0) { [math]::Round(($tag.Value / $TotalResources) * 100) } else { 0 })
        $barColor  = $(if ($pct -ge 80) { "var(--green)" } elseif ($pct -ge 50) { "var(--amber)" } else { "var(--red)" })
        $badge     = $(if ($pct -ge 80) { "badge-green" } elseif ($pct -ge 50) { "badge-amber" } else { "badge-red" })
        $tagCoverageRows += @"
            <div class="bar-row">
              <span class="bar-label">$($tag.Key)</span>
              <div class="bar-track"><div class="bar-fill" data-pct="$pct" style="background:$barColor"></div></div>
              <span class="bar-pct"><span class="badge $badge">$pct%</span></span>
            </div>
"@
    }

    # ── Resource type distribution rows ──────────────────────────────────────
    $rtRows = ""
    $rtTotal = ($ResourceTypeDistribution.Values | Measure-Object -Sum).Sum
    foreach ($rt in ($ResourceTypeDistribution.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10))
    {
        $pct     = $(if ($rtTotal -gt 0) { [math]::Round(($rt.Value / $rtTotal) * 100) } else { 0 })
        $rtRows += @"
            <div class="bar-row">
              <span class="bar-label" title="$($rt.Key)">$(if ($rt.Key.Length -gt 38) { $rt.Key.Substring(0,35)+"..." } else { $rt.Key })</span>
              <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
              <span class="bar-pct">$($rt.Value)</span>
            </div>
"@
    }

    # ── Subscription results rows ─────────────────────────────────────────────
    $subRows = ""
    foreach ($s in $SubscriptionResults)
    {
        $icon = switch ($s.Status) { "Success" { "✓" }; "Warning" { "⚠" }; "Error" { "✗" }; default { "•" } }
        $cls  = switch ($s.Status) { "Success" { "c-green" }; "Warning" { "c-amber" }; "Error" { "c-red" }; default { "" } }
        $subRows += @"
            <div class="sub-row">
              <span class="sub-icon $cls">$icon</span>
              <span class="sub-name">$($s.Name)</span>
              <span class="sub-detail">$($s.Summary)</span>
            </div>
"@
    }

    # ── Detail table rows ─────────────────────────────────────────────────────
    $tableRows = ""
    foreach ($r in $AllFindings)
    {
        $statusCls = switch ($r.ComplianceStatus) {
            "Compliant"     { "badge-green" }
            "Partial"       { "badge-amber" }
            "Non-Compliant" { "badge-red"   }
            default         { ""            }
        }

        $tagCells = ""
        foreach ($tag in $ScanParameters.MandatoryTags)
        {
            $present  = $r.TagStatuses[$tag]
            $tagCells += $(if ($present) { "<td class='tc-present'>✓</td>" } else { "<td class='tc-missing'>✗</td>" })
        }

        $tableRows += @"
          <tr onclick="showDetail($($AllFindings.IndexOf($r)))">
            <td>$(EscHtml $r.SubscriptionName)</td>
            <td>$(EscHtml $r.ResourceGroup)</td>
            <td title="$(EscHtml $r.ResourceName)">$(if ($r.ResourceName.Length -gt 30) { $r.ResourceName.Substring(0,27)+"..." } else { EscHtml $r.ResourceName })</td>
            <td>$(EscHtml $r.ResourceType)</td>
            $tagCells
            <td><span class="badge $statusCls">$($r.ComplianceStatus)</span></td>
            <td>$($r.MissingTagCount)</td>
          </tr>
"@
    }

    # ── Table header tag columns ──────────────────────────────────────────────
    $tagHeaders = ""
    foreach ($tag in $ScanParameters.MandatoryTags)
    {
        $tagHeaders += "<th>$tag</th>"
    }

    # ── JSON data for detail drawer ───────────────────────────────────────────
    $jsonRows = "["
    foreach ($r in $AllFindings)
    {
        $tagJson = "{"
        foreach ($tag in $ScanParameters.MandatoryTags)
        {
            $val      = $(if ($r.TagStatuses[$tag]) { "Present" } else { "Missing" })
            $tagJson += """$(EscJ $tag)"":""$val"","
        }
        $tagJson  = $tagJson.TrimEnd(",") + "}"
        $jsonRows += "{""sub"":""$(EscJ $r.SubscriptionName)"",""rg"":""$(EscJ $r.ResourceGroup)"",""name"":""$(EscJ $r.ResourceName)"",""type"":""$(EscJ $r.ResourceType)"",""scope"":""$(EscJ $r.Scope)"",""status"":""$(EscJ $r.ComplianceStatus)"",""missing"":$($r.MissingTagCount),""tags"":$tagJson},"
    }
    $jsonRows = $jsonRows.TrimEnd(",") + "]"

    $mandatoryTagsDisplay = $ScanParameters.MandatoryTags -join ", "
    $mandatoryTagsJson    = "[""" + ($ScanParameters.MandatoryTags -join '","') + """]"

    # ── Donut segments (Compliant / Partial / Non-Compliant) ──────────────────
    # SVG donut: r=60, cx=cy=70, circumference=377
    $donutTotal = $Compliant + $Partial + $NonCompliant
    $donutCirc  = 377
    $seg1Dash   = $(if ($donutTotal -gt 0) { [math]::Round($Compliant    / $donutTotal * $donutCirc) } else { 0 })
    $seg2Dash   = $(if ($donutTotal -gt 0) { [math]::Round($Partial      / $donutTotal * $donutCirc) } else { 0 })
    $seg3Dash   = $(if ($donutTotal -gt 0) { [math]::Round($NonCompliant / $donutTotal * $donutCirc) } else { 0 })
    $seg1Offset = 0
    $seg2Offset = $seg1Dash
    $seg3Offset = $seg1Dash + $seg2Dash

    # ── Full HTML ─────────────────────────────────────────────────────────────
    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Tag Compliance Dashboard</title>
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

/* ── Sidebar ──────────────────────────────────────────────────────────────── */
#sidebar{
  width:240px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;
  transition:transform .25s;
}
.logo-block{padding:22px 18px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:38px;height:38px;border-radius:8px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{
  display:inline-block;margin-top:8px;padding:2px 8px;border-radius:20px;
  font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent);border:1px solid var(--border);
}
.nav-section{padding:14px 10px;flex:1;}
.nav-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;
  letter-spacing:.08em;padding:0 8px;margin-bottom:6px;}
.nav-btn{
  display:flex;align-items:center;gap:10px;width:100%;padding:9px 12px;border:none;
  background:transparent;color:var(--muted2);font-size:13px;border-radius:var(--radius-sm);
  cursor:pointer;text-align:left;transition:background .15s,color .15s;position:relative;margin-bottom:2px;
}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:var(--surface3);color:var(--accent);font-weight:600;}
.nav-btn.active::before{
  content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;
  background:var(--accent);border-radius:0 3px 3px 0;
}
.nav-icon{font-size:16px;width:20px;text-align:center;}
.sidebar-footer{padding:14px 16px;border-top:1px solid var(--border);}
.theme-toggle{
  display:flex;align-items:center;justify-content:space-between;
  font-size:12px;color:var(--muted);margin-bottom:10px;
}
.toggle-pill{
  width:40px;height:22px;border-radius:11px;border:none;cursor:pointer;
  background:var(--surface3);position:relative;transition:background .2s;
}
.toggle-pill::after{
  content:'';position:absolute;top:3px;left:3px;width:16px;height:16px;
  border-radius:50%;background:var(--accent);transition:transform .2s;
}
html[data-theme="light"] .toggle-pill::after{transform:translateX(18px);}
.footer-meta{font-size:10px;color:var(--muted);line-height:1.6;}

/* ── Main content ─────────────────────────────────────────────────────────── */
#main{margin-left:240px;padding:28px;width:calc(100% - 240px);min-height:100vh;}
.page{display:none;animation:fadeIn .2s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px);}to{opacity:1;transform:none;}}
.page-header{margin-bottom:22px;}
.page-title{font-size:22px;font-weight:700;color:var(--text);}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}

/* ── Stat cards ───────────────────────────────────────────────────────────── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:22px;}
.stat-card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;cursor:default;
}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-num{font-size:30px;font-weight:700;font-family:var(--mono);color:var(--text);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}

/* ── Panels ───────────────────────────────────────────────────────────────── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:16px;display:flex;align-items:center;gap:8px;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}

/* ── Health ring ──────────────────────────────────────────────────────────── */
.health-card{display:flex;align-items:center;gap:24px;}
.health-ring-wrap{position:relative;width:130px;height:130px;flex-shrink:0;}
.health-ring-wrap svg{width:100%;height:100%;}
.health-center-text{
  position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center;
}
.health-score{font-size:28px;font-weight:700;font-family:var(--mono);}
.health-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;}
.health-details{flex:1;}
.health-details h3{font-size:15px;font-weight:700;margin-bottom:10px;}
.health-mini-bar{height:6px;background:var(--surface3);border-radius:3px;overflow:hidden;margin-top:8px;}
.health-mini-fill{height:100%;border-radius:3px;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width 1s ease;}

/* ── Bar lists ────────────────────────────────────────────────────────────── */
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:160px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:72px;text-align:right;flex-shrink:0;}

/* ── Donut ────────────────────────────────────────────────────────────────── */
.donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.legend-list{display:flex;flex-direction:column;gap:10px;}
.legend-item{display:flex;align-items:center;gap:10px;font-size:13px;}
.legend-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;}

/* ── Table ────────────────────────────────────────────────────────────────── */
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;}
.search-wrap input{
  width:100%;padding:8px 12px 8px 34px;background:var(--surface2);
  border:1px solid var(--border);border-radius:var(--radius-sm);
  color:var(--text);font-size:13px;outline:none;
}
.search-wrap input:focus{border-color:var(--accent);}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:14px;}
.filter-select{
  padding:7px 10px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);font-size:12px;cursor:pointer;
}
.tbl-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{
  padding:10px 12px;text-align:left;font-size:11px;font-weight:700;
  text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
  background:var(--surface2);border-bottom:1px solid var(--border);
  cursor:pointer;white-space:nowrap;user-select:none;
}
th:hover{color:var(--text);}
td{padding:9px 12px;border-bottom:1px solid var(--border);color:var(--text);vertical-align:middle;}
tr:hover td{background:var(--surface2);cursor:pointer;}
.tc-present{color:var(--green);font-size:14px;text-align:center;}
.tc-missing{color:var(--red);font-size:14px;text-align:center;}
.pagination{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:12px;color:var(--muted);flex-wrap:wrap;}
.pg-btn{
  padding:4px 10px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;
}
.pg-btn:hover{border-color:var(--accent);color:var(--accent);}
.pg-btn.active{background:var(--accent);color:#fff;border-color:var(--accent);}
.pg-btn:disabled{opacity:.4;cursor:not-allowed;}

/* ── Badges ───────────────────────────────────────────────────────────────── */
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}

/* ── Info rows (session/scan params) ─────────────────────────────────────── */
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:4px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);color:var(--text);word-break:break-all;}
.info-value.muted{color:var(--muted);font-style:italic;}

/* ── Subscription scan results ────────────────────────────────────────────── */
.sub-list{display:flex;flex-direction:column;gap:0;}
.sub-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}
.sub-icon.c-amber{color:var(--amber);}
.sub-icon.c-red{color:var(--red);}
.sub-name{flex:1;font-size:13px;color:var(--text);font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}

/* ── Detail drawer ────────────────────────────────────────────────────────── */
#drawerBackdrop{
  display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;
  animation:fadeInBg .2s ease;
}
@keyframes fadeInBg{from{opacity:0;}to{opacity:1;}}
#detailDrawer{
  position:fixed;right:0;top:0;bottom:0;width:420px;max-width:95vw;
  background:var(--surface);border-left:1px solid var(--border);
  z-index:201;display:flex;flex-direction:column;
  transform:translateX(100%);transition:transform .25s ease;overflow:hidden;
}
#detailDrawer.open{transform:translateX(0);}
.drawer-header{
  padding:18px 20px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;flex-shrink:0;
}
.drawer-title{font-size:14px;font-weight:700;color:var(--text);}
.drawer-close{
  background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;
  line-height:1;padding:2px 6px;border-radius:var(--radius-sm);
}
.drawer-close:hover{color:var(--text);background:var(--surface2);}
.drawer-body{padding:20px;overflow-y:auto;flex:1;}
.drawer-nav{display:flex;gap:8px;align-items:center;margin-bottom:16px;}
.drawer-nav-btn{
  padding:5px 12px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;
}
.drawer-nav-btn:hover{border-color:var(--accent);color:var(--accent);}
.drawer-nav-info{font-size:12px;color:var(--muted);flex:1;text-align:center;}
.drawer-field{margin-bottom:14px;}
.drawer-field-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.drawer-field-value{font-size:13px;color:var(--text);word-break:break-all;}
.drawer-section{font-size:12px;font-weight:700;color:var(--muted2);
  text-transform:uppercase;letter-spacing:.06em;margin:16px 0 8px;border-top:1px solid var(--border);padding-top:14px;}
.tag-chip-row{display:flex;flex-wrap:wrap;gap:6px;}
.tag-chip{padding:4px 10px;border-radius:20px;font-size:11px;font-family:var(--mono);}

/* ── Toast ────────────────────────────────────────────────────────────────── */
#toast{
  position:fixed;bottom:24px;right:24px;padding:12px 18px;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);
  font-size:13px;color:var(--text);box-shadow:var(--shadow);
  opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:300;
}
#toast.show{opacity:1;transform:translateY(0);}

/* ── Responsive ───────────────────────────────────────────────────────────── */
#menuToggle{display:none;}
@media(max-width:768px){
  #menuToggle{
    display:flex;align-items:center;justify-content:center;
    position:fixed;top:12px;left:12px;z-index:300;width:36px;height:36px;
    background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);
    cursor:pointer;font-size:18px;
  }
  #sidebar{transform:translateX(-100%);}
  #sidebar.open{transform:translateX(0);}
  #main{margin-left:0;width:100%;padding:16px;padding-top:56px;}
  .chart-grid{grid-template-columns:1fr;}
}
@media print{
  #sidebar,#menuToggle,#toast,#drawerBackdrop,#detailDrawer{display:none!important;}
  #main{margin-left:0;width:100%;}
  .page{display:block!important;}
}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<!-- ── Sidebar ────────────────────────────────────────────────────────────── -->
<nav id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🏷️</div>
    <div class="logo-title">Tag Compliance</div>
    <div class="logo-sub">Azure Governance</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('detail',this)"><span class="nav-icon">🔍</span> Resource Detail</button>
    <button class="nav-btn" onclick="showPage('coverage',this)"><span class="nav-icon">📈</span> Tag Coverage</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">📋</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" id="themeToggle" onclick="toggleTheme()" title="Toggle theme"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Azure Tag Compliance Scanner
    </div>
  </div>
</nav>

<!-- ── Main ───────────────────────────────────────────────────────────────── -->
<main id="main">

  <!-- Overview -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Tag Compliance Overview</div>
      <div class="page-sub">Mandatory tag enforcement across __TOTAL_RESOURCES__ resources in __SUB_COUNT__ subscription(s)</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num">__TOTAL_RESOURCES__</div>
        <div class="stat-label">Total Resources</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__COMPLIANT__</div>
        <div class="stat-label">Compliant</div>
        <div class="stat-sub">0 tags missing</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__PARTIAL__</div>
        <div class="stat-label">Partial</div>
        <div class="stat-sub">1–2 tags missing</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num">__NONCOMPLIANT__</div>
        <div class="stat-label">Non-Compliant</div>
        <div class="stat-sub">3+ tags missing</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num">__TAG_COUNT__</div>
        <div class="stat-label">Mandatory Tags</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num">__SUB_COUNT__</div>
        <div class="stat-label">Subscriptions</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Compliance Score</div>
        <div class="health-card">
          <div class="health-ring-wrap">
            <svg viewBox="0 0 140 140" xmlns="http://www.w3.org/2000/svg">
              <circle cx="70" cy="70" r="54" fill="none" stroke="var(--surface3)" stroke-width="12"/>
              <circle cx="70" cy="70" r="54" fill="none" stroke="__SCORE_COLOR__" stroke-width="12"
                stroke-linecap="round" stroke-dasharray="__RING_DASH__ __RING_GAP__"
                stroke-dashoffset="85" transform="rotate(-90 70 70)"/>
            </svg>
            <div class="health-center-text">
              <span class="health-score" style="color:__SCORE_COLOR__">__SCORE__%</span>
              <span class="health-label">Score</span>
            </div>
          </div>
          <div class="health-details">
            <h3>Overall Tag Compliance</h3>
            <p style="font-size:13px;color:var(--muted);">Weighted score — Compliant resources score 100%, Partial 50%, Non-Compliant 0%.</p>
            <div class="health-mini-bar"><div class="health-mini-fill" style="width:__SCORE__%"></div></div>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-title">🍩 Compliance Breakdown</div>
        <div class="donut-wrap">
          <svg id="donutSvg" width="130" height="130" viewBox="0 0 140 140">
            <circle cx="70" cy="70" r="60" fill="none" stroke="var(--surface3)" stroke-width="20"/>
            <circle cx="70" cy="70" r="60" fill="none" stroke="var(--green)" stroke-width="20"
              stroke-dasharray="__SEG1_DASH__ __DONUT_CIRC__" stroke-dashoffset="0"
              transform="rotate(-90 70 70)" opacity="0.9"/>
            <circle cx="70" cy="70" r="60" fill="none" stroke="var(--amber)" stroke-width="20"
              stroke-dasharray="__SEG2_DASH__ __DONUT_CIRC__" stroke-dashoffset="-__SEG2_OFFSET__"
              transform="rotate(-90 70 70)" opacity="0.9"/>
            <circle cx="70" cy="70" r="60" fill="none" stroke="var(--red)" stroke-width="20"
              stroke-dasharray="__SEG3_DASH__ __DONUT_CIRC__" stroke-dashoffset="-__SEG3_OFFSET__"
              transform="rotate(-90 70 70)" opacity="0.9"/>
          </svg>
          <div class="legend-list">
            <div class="legend-item"><div class="legend-dot" style="background:var(--green)"></div><span>Compliant — __COMPLIANT__</span></div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--amber)"></div><span>Partial — __PARTIAL__</span></div>
            <div class="legend-item"><div class="legend-dot" style="background:var(--red)"></div><span>Non-Compliant — __NONCOMPLIANT__</span></div>
          </div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">📦 Top 10 Resource Types by Volume</div>
      __RT_ROWS__
    </div>
  </div>

  <!-- Resource Detail -->
  <div id="page-detail" class="page">
    <div class="page-header">
      <div class="page-title">Resource Compliance Detail</div>
      <div class="page-sub">Click any row to inspect per-tag status. Use filters to narrow results.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="tblSearch" placeholder="Search resource, RG, subscription…" oninput="filterTable()"/>
        </div>
        <select class="filter-select" id="filterStatus" onchange="filterTable()">
          <option value="">All Statuses</option>
          <option value="Compliant">Compliant</option>
          <option value="Partial">Partial</option>
          <option value="Non-Compliant">Non-Compliant</option>
        </select>
        <select class="filter-select" id="pgSize" onchange="changePageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="resTable">
          <thead>
            <tr>
              <th onclick="sortTable(0)">Subscription</th>
              <th onclick="sortTable(1)">Resource Group</th>
              <th onclick="sortTable(2)">Resource Name</th>
              <th onclick="sortTable(3)">Type</th>
              __TAG_HEADERS__
              <th onclick="sortTable(__STATUS_COL__)">Status</th>
              <th onclick="sortTable(__MISSING_COL__)">Missing</th>
            </tr>
          </thead>
          <tbody id="tblBody">
            __TABLE_ROWS__
          </tbody>
        </table>
      </div>
      <div class="pagination" id="pagination"></div>
    </div>
  </div>

  <!-- Tag Coverage -->
  <div id="page-coverage" class="page">
    <div class="page-header">
      <div class="page-title">Tag Coverage Analysis</div>
      <div class="page-sub">Percentage of resources carrying each mandatory tag</div>
    </div>
    <div class="panel">
      <div class="panel-title">📊 Mandatory Tag Coverage</div>
      __TAG_COVERAGE_ROWS__
    </div>
    <div class="panel">
      <div class="panel-title">🔑 Mandatory Tags Assessed</div>
      <div class="tag-chip-row" id="mandatoryTagChips"></div>
    </div>
  </div>

  <!-- Scan Results -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription resource and compliance counts</div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Subscriptions Scanned</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- Session Info -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Scan Parameters</div>
      <div class="page-sub">Authentication context and parameters used for this assessment</div>
    </div>
    <div class="panel">
      <div class="panel-title">🔐 Session Information</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Tenant ID</div><div class="info-value">__TENANT__</div></div>
        <div class="info-card"><div class="info-label">Account</div><div class="info-value">__ACCOUNT__</div></div>
        <div class="info-card"><div class="info-label">Environment</div><div class="info-value">__ENVIRONMENT__</div></div>
        <div class="info-card"><div class="info-label">Generated On</div><div class="info-value">__GENERATED_ON__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">⚙️ Scan Parameters</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Scope</div><div class="info-value">__SCOPE__</div></div>
        <div class="info-card"><div class="info-label">Resource Group Filter</div><div class="info-value __RG_MUTED__">__RG_FILTER__</div></div>
        <div class="info-card"><div class="info-label">Resource Type Filter</div><div class="info-value __RT_MUTED__">__RT_FILTER__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Subscriptions Scanned</div><div class="info-value">__SUB_COUNT__</div></div>
      </div>
    </div>
  </div>

</main>

<!-- ── Detail drawer ──────────────────────────────────────────────────────── -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Resource Detail</span>
    <button class="drawer-close" onclick="closeDrawer()">✕</button>
  </div>
  <div class="drawer-body">
    <div class="drawer-nav">
      <button class="drawer-nav-btn" onclick="navDetail(-1)">← Prev</button>
      <span class="drawer-nav-info" id="drawerNavInfo"></span>
      <button class="drawer-nav-btn" onclick="navDetail(1)">Next →</button>
    </div>
    <div id="drawerContent"></div>
  </div>
</div>

<div id="toast"></div>

<script>
const MANDATORY_TAGS = __MANDATORY_TAGS_JSON__;
const DATA = __DATA_JSON__;
let filtered = [...DATA];
let currentPage = 1;
let pageSize = 25;
let sortCol = -1, sortAsc = true;
let currentDetailIdx = 0;

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// ── Navigation ───────────────────────────────────────────────────────────────
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
}

// ── Theme ────────────────────────────────────────────────────────────────────
function toggleTheme(){
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
}

// ── Toast ────────────────────────────────────────────────────────────────────
function showToast(msg){
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2500);
}

// ── Table ────────────────────────────────────────────────────────────────────
function filterTable(){
  const q = document.getElementById('tblSearch').value.toLowerCase();
  const s = document.getElementById('filterStatus').value;
  filtered = DATA.filter(r=>{
    const matchQ = !q || JSON.stringify(r).toLowerCase().includes(q);
    const matchS = !s || r.status === s;
    return matchQ && matchS;
  });
  currentPage = 1;
  renderTable();
}

function changePageSize(){
  pageSize = parseInt(document.getElementById('pgSize').value);
  currentPage = 1;
  renderTable();
}

function sortTable(col){
  if(sortCol===col){sortAsc=!sortAsc;}else{sortCol=col;sortAsc=true;}
  const keys=['sub','rg','name','type',...MANDATORY_TAGS,'status','missing'];
  filtered.sort((a,b)=>{
    const ak=keys[col],bk=keys[col];
    const av=a[ak]??'', bv=b[bk]??'';
    return sortAsc ? String(av).localeCompare(String(bv),undefined,{numeric:true})
                   : String(bv).localeCompare(String(av),undefined,{numeric:true});
  });
  renderTable();
}

function renderTable(){
  const tbody = document.getElementById('tblBody');
  const start = (currentPage-1)*pageSize;
  const slice = filtered.slice(start, start+pageSize);
  tbody.innerHTML = slice.map((r,i)=>{
    const globalIdx = DATA.indexOf(r);
    const sc = r.status==='Compliant'?'badge-green':r.status==='Partial'?'badge-amber':'badge-red';
    const tagCells = MANDATORY_TAGS.map(t=>
      r.tags[t]==='Present'?`<td class="tc-present">✓</td>`:`<td class="tc-missing">✗</td>`
    ).join('');
    const nm = r.name.length>30?r.name.substring(0,27)+'...':r.name;
    return `<tr onclick="showDetail(${globalIdx})">
      <td>${escH(r.sub)}</td><td>${escH(r.rg)}</td>
      <td title="${escH(r.name)}">${escH(nm)}</td><td>${escH(r.type)}</td>
      ${tagCells}
      <td><span class="badge ${sc}">${escH(r.status)}</span></td>
      <td>${r.missing}</td>
    </tr>`;
  }).join('');
  renderPagination();
}

function renderPagination(){
  const total = Math.ceil(filtered.length/pageSize);
  const el = document.getElementById('pagination');
  let html = `<span>${filtered.length} resources</span>`;
  html += `<button class="pg-btn" onclick="changePage(${currentPage-1})" ${currentPage<=1?'disabled':''}>‹ Prev</button>`;
  const start = Math.max(1,currentPage-2), end = Math.min(total,start+4);
  for(let p=start;p<=end;p++){
    html += `<button class="pg-btn ${p===currentPage?'active':''}" onclick="changePage(${p})">${p}</button>`;
  }
  html += `<button class="pg-btn" onclick="changePage(${currentPage+1})" ${currentPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML = html;
}

function changePage(p){
  const total = Math.ceil(filtered.length/pageSize);
  if(p<1||p>total) return;
  currentPage = p;
  renderTable();
}

// ── Detail drawer ─────────────────────────────────────────────────────────────
function showDetail(idx){
  currentDetailIdx = idx;
  const r = DATA[idx];
  if(!r) return;
  document.getElementById('drawerTitle').textContent = r.name;
  document.getElementById('drawerNavInfo').textContent = `${idx+1} of ${DATA.length}`;

  const sc = r.status==='Compliant'?'badge-green':r.status==='Partial'?'badge-amber':'badge-red';
  const tagChips = MANDATORY_TAGS.map(t=>{
    const present = r.tags[t]==='Present';
    const cls = present ? 'badge-green' : 'badge-red';
    const icon = present ? '✓' : '✗';
    return `<span class="tag-chip ${cls}">${icon} ${escH(t)}</span>`;
  }).join('');

  document.getElementById('drawerContent').innerHTML = `
    <div class="drawer-field"><div class="drawer-field-label">Compliance Status</div>
      <div class="drawer-field-value"><span class="badge ${sc}">${escH(r.status)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Subscription</div>
      <div class="drawer-field-value">${escH(r.sub)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Group</div>
      <div class="drawer-field-value">${escH(r.rg)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Name</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.name)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Resource Type</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:12px">${escH(r.type)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Scope</div>
      <div class="drawer-field-value" style="font-family:var(--mono);font-size:11px;word-break:break-all">${escH(r.scope)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Missing Tags</div>
      <div class="drawer-field-value">${r.missing} of ${MANDATORY_TAGS.length}</div></div>
    <div class="drawer-section">Tag Status</div>
    <div class="tag-chip-row">${tagChips}</div>
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
  if(next >= 0 && next < DATA.length) showDetail(next);
}

// ── Bar animation ─────────────────────────────────────────────────────────────
function animateBars(){
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{
      el.style.width = el.dataset.pct + '%';
    });
  });
}

// ── Mandatory tag chips ───────────────────────────────────────────────────────
function renderTagChips(){
  const el = document.getElementById('mandatoryTagChips');
  if(el) el.innerHTML = MANDATORY_TAGS.map(t=>`<span class="tag-chip badge-blue">${escH(t)}</span>`).join('');
}

// ── Keyboard shortcuts ────────────────────────────────────────────────────────
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
  if(e.key==='/'){
    const s = document.getElementById('tblSearch');
    if(s){ e.preventDefault(); s.focus(); }
  }
});

// ── Init ──────────────────────────────────────────────────────────────────────
filterTable();
animateBars();
renderTagChips();
</script>
</body>
</html>
'@

    # ── Token substitution ────────────────────────────────────────────────────
    $html = $html `
        -replace '__GENERATED_ON__',    $GeneratedOn `
        -replace '__TOTAL_RESOURCES__', $TotalResources `
        -replace '__SUB_COUNT__',       ($SubscriptionResults.Count) `
        -replace '__COMPLIANT__',       $Compliant `
        -replace '__PARTIAL__',         $Partial `
        -replace '__NONCOMPLIANT__',    $NonCompliant `
        -replace '__TAG_COUNT__',       ($ScanParameters.MandatoryTags.Count) `
        -replace '__SCORE__',           $complianceScore `
        -replace '__SCORE_COLOR__',     $scoreColor `
        -replace '__RING_DASH__',       $ringDash `
        -replace '__RING_GAP__',        $ringGap `
        -replace '__SEG1_DASH__',       $seg1Dash `
        -replace '__SEG2_DASH__',       $seg2Dash `
        -replace '__SEG3_DASH__',       $seg3Dash `
        -replace '__DONUT_CIRC__',      $donutCirc `
        -replace '__SEG2_OFFSET__',     $seg2Offset `
        -replace '__SEG3_OFFSET__',     $seg3Offset `
        -replace '__RT_ROWS__',         $rtRows `
        -replace '__TAG_COVERAGE_ROWS__', $tagCoverageRows `
        -replace '__SUB_ROWS__',        $subRows `
        -replace '__TABLE_ROWS__',      $tableRows `
        -replace '__TAG_HEADERS__',     $tagHeaders `
        -replace '__STATUS_COL__',      (4 + $ScanParameters.MandatoryTags.Count) `
        -replace '__MISSING_COL__',     (5 + $ScanParameters.MandatoryTags.Count) `
        -replace '__TENANT__',          $SessionInfo.Tenant `
        -replace '__ACCOUNT__',         $SessionInfo.Account `
        -replace '__ENVIRONMENT__',     $SessionInfo.Environment `
        -replace '__SCOPE__',           $ScanParameters.Scope `
        -replace '__RG_FILTER__',       $(if ($ScanParameters.ResourceGroupName) { $ScanParameters.ResourceGroupName } else { "None" }) `
        -replace '__RG_MUTED__',        $(if ($ScanParameters.ResourceGroupName) { "" } else { "muted" }) `
        -replace '__RT_FILTER__',       $(if ($ScanParameters.ResourceType) { $ScanParameters.ResourceType } else { "None" }) `
        -replace '__RT_MUTED__',        $(if ($ScanParameters.ResourceType) { "" } else { "muted" }) `
        -replace '__EXPORT_ENABLED__',  $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__',       $ScanParameters.ExecTime `
        -replace '__MANDATORY_TAGS_JSON__', $mandatoryTagsJson `
        -replace '__DATA_JSON__',       $jsonRows

    return $html
}

# HTML escaping helpers used inside Generate-TagComplianceHtml
Function EscHtml { param([string]$s); return $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }
Function EscJ    { param([string]$s); return $s -replace '\\','\\\\' -replace "'","\'" -replace '"','\"' }


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureResourceTagCompliance
{
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [string]$ResourceGroupName,

        [string]$ResourceType,

        [string[]]$MandatoryTags = @(
            "Application",
            "Owner",
            "Environment",
            "CostCenter",
            "DataClassification",
            "BusinessCriticality"
        ),

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureTagCompliance-Report.csv"
    )

    $startTime = Get-Date

    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    if (-not (Get-Module -ListAvailable -Name Az.Resources))
    {
        Write-Host "  ⚠ Az.Resources module not found" -ForegroundColor Yellow
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
                Write-Host "  ✓ Az module installed successfully" -ForegroundColor Green
                Write-Host ""
            }
            catch
            {
                Write-Host "  ✗ Error installing Az module: $_" -ForegroundColor Red
                return
            }
        }
        else
        {
            Write-Host ""
            Write-Host "  Installation declined. Cannot proceed without Az.Resources module." -ForegroundColor Yellow
            return
        }
    }

    # ── Authentication ────────────────────────────────────────────────────────
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx)
    {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
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
        $scopeText     = "Specific Subscriptions ($($SubscriptionIds.Count))"
    }

    $subCount = $subscriptions.Count

    # ── Display session info ──────────────────────────────────────────────────
    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }

    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"              = "$scopeText ($subCount found)"
        "Resource Group"     = $(if ($ResourceGroupName) { $ResourceGroupName } else { "" })
        "Resource Type"      = $(if ($ResourceType)      { $ResourceType }      else { "" })
        "Mandatory Tags"     = $MandatoryTags -join ", "
        "Export to CSV"      = $(if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" })
        "Export Path"        = $(if ($ExportToCsv.IsPresent) { $CsvPath }  else { "" })
    }

    # ── Collections ───────────────────────────────────────────────────────────
    $allFindings          = @()
    $subscriptionResults  = @()
    $tagCoverage          = @{}
    $resourceTypeCount    = @{}
    $compliantCount       = 0
    $partialCount         = 0
    $nonCompliantCount    = 0
    $successCount         = 0
    $errorCount           = 0

    foreach ($tag in $MandatoryTags) { $tagCoverage[$tag] = 0 }

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

            # Build Get-AzResource params
            $getParams = @{ ErrorAction = "Stop" }
            if ($ResourceGroupName) { $getParams["ResourceGroupName"] = $ResourceGroupName }
            if ($ResourceType)      { $getParams["ResourceType"]      = $ResourceType }

            $resources = @(Get-AzResource @getParams)

            $subCompliant    = 0
            $subPartial      = 0
            $subNonCompliant = 0

            foreach ($res in $resources)
            {
                $resTags     = $(if ($res.Tags) { $res.Tags } else { @{} })
                $tagStatuses = @{}
                $missingTags = 0

                foreach ($tag in $MandatoryTags)
                {
                    # Case-insensitive match
                    $matched = $resTags.Keys | Where-Object { $_ -ieq $tag }
                    if ($matched)
                    {
                        $tagStatuses[$tag] = $true
                        $tagCoverage[$tag]++
                    }
                    else
                    {
                        $tagStatuses[$tag] = $false
                        $missingTags++
                    }
                }

                $status = $(if ($missingTags -eq 0)            { "Compliant";     $subCompliant++;    $compliantCount++ }
                          elseif ($missingTags -le 2)          { "Partial";       $subPartial++;      $partialCount++ }
                          else                                  { "Non-Compliant"; $subNonCompliant++; $nonCompliantCount++ })

                # Resource type distribution
                $rt = $(if ($res.ResourceType) { $res.ResourceType } else { "Unknown" })
                if ($resourceTypeCount.ContainsKey($rt)) { $resourceTypeCount[$rt]++ } else { $resourceTypeCount[$rt] = 1 }

                $allFindings += [pscustomobject]@{
                    SubscriptionName  = $sub.Name
                    SubscriptionId    = $sub.Id
                    ResourceGroup     = $res.ResourceGroupName
                    ResourceName      = $res.Name
                    ResourceType      = $res.ResourceType
                    Scope             = $res.ResourceId
                    ComplianceStatus  = $status
                    MissingTagCount   = $missingTags
                    TagStatuses       = $tagStatuses
                }
            }

            # Clear progress, display result
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($resources.Count) resources  |  Compliant: $subCompliant  Partial: $subPartial  Non-Compliant: $subNonCompliant" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "$($resources.Count) resources | ✓$subCompliant ⚠$subPartial ✗$subNonCompliant"
                Status  = "Success"
            }
            $successCount++
        }
        catch
        {
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✗ " -NoNewline -ForegroundColor Red
            Write-Host $paddedName -NoNewline -ForegroundColor Red
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
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

    # ── Summary ───────────────────────────────────────────────────────────────
    $endTime  = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-Summary -Data ([ordered]@{
        "Total Subscriptions Scanned" = $subCount
        "Successful"                  = $successCount
        "Errors"                      = $errorCount
        "Total Resources Assessed"    = $allFindings.Count
        "Compliant"                   = $compliantCount
        "Partial (1-2 tags missing)"  = $partialCount
        "Non-Compliant (3+ missing)"  = $nonCompliantCount
        "Execution Time"              = $duration
    })

    Write-TagCoverage         -TagCoverage $tagCoverage -TotalResources $allFindings.Count
    Write-ComplianceDistribution -Compliant $compliantCount -Partial $partialCount `
                                 -NonCompliant $nonCompliantCount -Total $allFindings.Count

    # ── Output ────────────────────────────────────────────────────────────────
    $csvExported      = $false
    $htmlExported     = $false
    $gridViewOpened   = $false
    $htmlPath         = ""

    if ($allFindings.Count -gt 0)
    {
        # CSV export
        if ($ExportToCsv)
        {
            try
            {
                # Flatten TagStatuses into individual columns for CSV readability
                $csvRows = $allFindings | ForEach-Object {
                    $row = [ordered]@{
                        SubscriptionName = $_.SubscriptionName
                        SubscriptionId   = $_.SubscriptionId
                        ResourceGroup    = $_.ResourceGroup
                        ResourceName     = $_.ResourceName
                        ResourceType     = $_.ResourceType
                        Scope            = $_.Scope
                    }
                    foreach ($tag in $MandatoryTags)
                    {
                        $row["Tag_$tag"] = $(if ($_.TagStatuses[$tag]) { "Present" } else { "Missing" })
                    }
                    $row["ComplianceStatus"] = $_.ComplianceStatus
                    $row["MissingTagCount"]  = $_.MissingTagCount
                    [pscustomobject]$row
                }

                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
                $csvRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
                $csvExported = $true
            }
            catch
            {
                Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red
            }
        }

        # HTML dashboard
        try
        {
            $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')

            $sessionInfo = @{
                Tenant      = $ctx.Tenant.Id
                Account     = $ctx.Account.Id
                Environment = $ctx.Environment.Name
            }

            $scanParams = @{
                Scope             = "$scopeText ($subCount found)"
                ResourceGroupName = $ResourceGroupName
                ResourceType      = $ResourceType
                ExportEnabled     = $(if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" })
                MandatoryTags     = $MandatoryTags
                ExecTime          = $duration
            }

            $htmlContent = Generate-TagComplianceHtml `
                -SessionInfo          $sessionInfo `
                -ScanParameters       $scanParams `
                -ScanSummary          @{} `
                -SubscriptionResults  $subscriptionResults `
                -TagCoverage          $tagCoverage `
                -TotalResources       $allFindings.Count `
                -Compliant            $compliantCount `
                -Partial              $partialCount `
                -NonCompliant         $nonCompliantCount `
                -ResourceTypeDistribution $resourceTypeCount `
                -AllFindings          $allFindings `
                -GeneratedOn          (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch
        {
            Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red
        }

        # Grid View
        try
        {
            $allFindings |
                Select-Object SubscriptionName, ResourceGroup, ResourceName, ResourceType, ComplianceStatus, MissingTagCount |
                Out-GridView -Title "Azure Resource Tag Compliance"
            $gridViewOpened = $true
        }
        catch
        {
            Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow
        }
    }
    else
    {
        Write-Host ""
        Write-Host "  ⚠ No resources found matching the specified filters." -ForegroundColor Yellow
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened)
    {
        Write-OutputFiles `
            -CsvPath        $(if ($csvExported)    { $CsvPath  } else { $null }) `
            -HtmlPath       $(if ($htmlExported)   { $htmlPath } else { $null }) `
            -GridViewOpened $gridViewOpened
    }
    else
    {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}

# Select-String -Path "C:\temp\Get-AzureResourceTagCompliance.ps1" -Pattern '\s+if\s+\(' | Select-Object LineNumber, Line
# Select-String -Path "C:\temp\Get-AzureResourceTagCompliance.ps1" -Pattern '\(if\s*\(' | Select-Object LineNumber, Line
# Select-String -Path "C:\temp\Get-AzureResourceTagCompliance.ps1" -Pattern '=\s+if\s*\(' | Select-Object LineNumber, Line
