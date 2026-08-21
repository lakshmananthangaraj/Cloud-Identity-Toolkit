<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 21 August 2026
Modified-On     : 21 August 2026

.SYNOPSIS
    Retrieves the complete effective Azure Policy stack for any Azure resource,
    tracing inheritance from Management Group through to the resource itself,
    with risk rating, exemption status, and an HTML governance report.

.DESCRIPTION
    Get-AzureResourceEffectivePolicies answers the governance question that must
    be asked before any policy exemption is created:

        "Which policies are affecting this resource, where are they inherited
         from, and do we actually need an exemption?"

    The script accepts a resource display name, resolves it dynamically across
    ARM regardless of resource type, then reconstructs the full effective policy
    inheritance chain across four scope levels:

        Management Group hierarchy  (all ancestor MGs up to tenant root)
        Subscription                (/subscriptions/{id})
        Resource Group              (/subscriptions/{id}/resourceGroups/{rg})
        Resource                    (full ARM resource ID)

    For every policy assignment discovered at any scope level the script records:
        - Where the assignment is defined (InheritedFrom scope)
        - Which inheritance level it originates from
        - The policy effect (Deny / Audit / AuditIfNotExists / DeployIfNotExists /
          Disabled / Modify) and enforcement mode (Default / DoNotEnforce)
        - Whether an active exemption already exists at the resource scope
        - Optional live compliance state via Get-AzPolicyState
        - A risk rating (High / Medium / Low) and an exemption recommendation
          (Exemption Needed / Review Required / No Action Needed / Already Exempted)

    The Exemption Planner section of the HTML report pre-fills a
    New-AzureKeyVaultPolicyExemption command block for the assignments that are
    flagged as requiring an exemption, creating a direct governance workflow:

        Get-AzureResourceEffectivePolicies  →  review  →  New-AzureKeyVaultPolicyExemption

    Disambiguation:
        If -ResourceName matches more than one Azure resource, the script fails
        early and instructs the caller to supply -ResourceGroupName or
        -ResourceType to disambiguate. Interactive prompts are never used.

    Management Group traversal:
        The script walks the full MG ancestor chain from the subscription's
        parent MG up to the tenant root. If the caller lacks
        Microsoft.Management/managementGroups/read, the MG scope level is
        gracefully marked "Could not be assessed" and assessment continues from
        the subscription level downward.

.PARAMETER ResourceName
    Display name of the Azure resource to analyse. Resolved dynamically via
    Get-AzResource; not restricted to any specific resource type. The name is
    case-insensitive and matched exactly — wildcards are not supported.

.PARAMETER ResourceType
    Optional. ARM resource type in the format 'Provider/ResourceType'
    (e.g. 'Microsoft.KeyVault/vaults'). Supplied when -ResourceName alone
    matches multiple resources and disambiguation is needed.

.PARAMETER ResourceGroupName
    Optional. Resource group name filter. Supplied when -ResourceName alone
    matches multiple resources and disambiguation is needed.

.PARAMETER SubscriptionId
    Optional. Limits resource lookup to a specific subscription. When omitted
    the script searches all subscriptions accessible to the authenticated account.

.PARAMETER IncludeComplianceState
    Switch. When specified, calls Get-AzPolicyState -ResourceId to retrieve the
    live compliance state for the target resource against each assignment.
    Disabled by default for performance. If the call fails due to permissions,
    the compliance state is marked "Not Assessed / Warning" and the script
    continues without interruption.

.PARAMETER IncludeDisabledPolicies
    Switch. By default, assignments with Effect = Disabled or
    EnforcementMode = DoNotEnforce are included in results but visually
    de-emphasised in the HTML report with a Low risk badge. This switch has no
    effect on which assignments are collected — it is a reporting preference only.

.PARAMETER ExportToCsv
    Switch. When specified, exports the full findings table to -CsvPath.
    The HTML report is always generated regardless of this switch.

.PARAMETER CsvPath
    Output path for the CSV export. The HTML report is always written to the
    same path with a .html extension. Defaults to:
    C:\Temp\AzureResourceEffectivePolicies-Report.csv

.INPUTS
    None. All input is via named parameters.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML governance report.
    Optionally writes a CSV if -ExportToCsv is specified.

.EXAMPLE
    Get-AzureResourceEffectivePolicies -ResourceName "kv-prod-payments"

.EXAMPLE
    Get-AzureResourceEffectivePolicies `
        -ResourceName    "kv-prod-payments" `
        -IncludeComplianceState

.EXAMPLE
    Get-AzureResourceEffectivePolicies `
        -ResourceName      "kv-prod-payments" `
        -ResourceGroupName "rg-prod-payments" `
        -IncludeComplianceState `
        -ExportToCsv `
        -CsvPath           "C:\Reports\kv-prod-payments-policies.csv"

.EXAMPLE
    # Disambiguate by resource type when multiple resources share the same name
    Get-AzureResourceEffectivePolicies `
        -ResourceName  "mySharedName" `
        -ResourceType  "Microsoft.Storage/storageAccounts" `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (21-Aug-2026) - Initial release. Full MG hierarchy traversal, four-level
                            inheritance chain, risk rating, exemption recommendation,
                            Exemption Planner with pre-filled command block, CSV export,
                            and interactive dark-themed HTML governance report.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module — Az.Accounts, Az.Resources (auto-install offered
           if missing). Az.PolicyInsights required only when -IncludeComplianceState
           is specified.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Microsoft.Resources/resources/read at the resource scope (Reader minimum).
        4. Microsoft.Authorization/policyAssignments/read at subscription and RG scope.
        5. Microsoft.Management/managementGroups/read for MG-level inheritance
           traversal — gracefully skipped if absent; assessment continues from
           subscription level downward.
        6. Microsoft.Authorization/policyExemptions/read for exemption check.
        7. Microsoft.PolicyInsights/policyStates/queryResults/action — required only
           when -IncludeComplianceState is specified. Gracefully skipped if absent.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Resource lookup uses Get-AzResource -Name which performs a display-name
          match. If the resource name is ambiguous (multiple matches) the script
          fails early with instructions to supply -ResourceGroupName or
          -ResourceType.
        - Management Group policy assignments are only visible if the authenticated
          account has Microsoft.Management/managementGroups/read. Without it the
          MG scope level is skipped with a warning.
        - Get-AzPolicyState can be slow on subscriptions with many resources.
          Use -IncludeComplianceState selectively for large environments.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. Supply an explicit
          -CsvPath on macOS/Linux PowerShell 7.
        - The Exemption Planner pre-filled command targets New-AzureKeyVaultPolicyExemption.
          For non-Key Vault resources, adapt the -KeyVaultNames parameter or use
          New-AzPolicyExemption directly with the listed AssignmentIds.

.LINK
    https://learn.microsoft.com/en-us/azure/governance/policy/concepts/scope
    https://learn.microsoft.com/en-us/azure/governance/policy/concepts/exemption-structure
    https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azpolicyassignment
    https://learn.microsoft.com/en-us/powershell/module/az.policyinsights/get-azpolicystate
    https://learn.microsoft.com/en-us/azure/governance/management-groups/overview

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
    Write-CenteredText "Azure Resource Effective Policy Analyser v1.0" -Color White
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-Section
{
    param(
        [string]$Title,
        [System.Collections.Specialized.OrderedDictionary]$Data
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
        Write-Host $key.PadRight(26) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-InheritanceChain
{
    param(
        [System.Collections.Generic.List[psobject]]$ChainLevels
    )

    Write-Host ""
    Write-Host "  Inheritance Chain Analysis" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $arrow = "  --->"
    $isFirst = $true

    foreach ($level in $ChainLevels)
    {
        if (-not $isFirst) { Write-Host $arrow -ForegroundColor DarkGray }

        $icon  = if ($level.AssignmentCount -eq 0) { " " } else { "+" }
        $color = switch ($level.Status)
        {
            "Assessed"          { if ($level.AssignmentCount -gt 0) { "Cyan" } else { "DarkGray" } }
            "Skipped"           { "Yellow" }
            "Error"             { "Red" }
            default             { "Gray" }
        }

        $levelLabel  = $level.LevelName.PadRight(20)
        $scopeLabel  = if ($level.ScopeName) { $level.ScopeName } else { "—" }
        $countLabel  = "$($level.AssignmentCount) assignment(s)"

        Write-Host "  " -NoNewline
        Write-Host "[$icon] " -NoNewline -ForegroundColor $color
        Write-Host $levelLabel -NoNewline -ForegroundColor $color
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host $scopeLabel.PadRight(38) -NoNewline -ForegroundColor White
        Write-Host $countLabel -ForegroundColor $color

        if ($level.Status -eq "Skipped")
        {
            Write-Host "       " -NoNewline
            Write-Host "Reason: $($level.SkipReason)" -ForegroundColor DarkGray
        }

        $isFirst = $false
    }

    Write-Host ""
}

Function Write-Summary
{
    param([System.Collections.Specialized.OrderedDictionary]$Data)

    Write-Host ""
    Write-Host "  Assessment Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys)
    {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(34) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-OutputFiles
{
    param(
        [string]$CsvPath,
        [string]$HtmlPath
    )

    Write-Host ""
    Write-Host "  Output Files" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray

    if ($CsvPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "  CSV Export  " -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }

    if ($HtmlPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "  HTML Report " -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }

    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-RiskAndRecommendation
{
    <#
    .SYNOPSIS
        Derives a RiskLevel and ExemptionRecommendation for a single policy assignment row.
    #>
    param(
        [string]$Effect,
        [string]$EnforcementMode,
        [string]$ComplianceState,
        [bool]$ExemptionExists
    )

    if ($ExemptionExists)
    {
        return @{ Risk = "Info"; Recommendation = "Already Exempted" }
    }

    $effectNorm = $Effect.ToLower()

    if ($EnforcementMode -eq "DoNotEnforce" -or $effectNorm -eq "disabled")
    {
        return @{ Risk = "Low"; Recommendation = "No Action Needed" }
    }

    if ($effectNorm -in @("deny"))
    {
        if ($ComplianceState -eq "NonCompliant")
        {
            return @{ Risk = "High"; Recommendation = "Exemption Needed" }
        }
        return @{ Risk = "Medium"; Recommendation = "Review Required" }
    }

    if ($effectNorm -in @("audit", "auditifnotexists", "deployifnotexists", "modify", "append"))
    {
        if ($ComplianceState -eq "NonCompliant")
        {
            return @{ Risk = "Medium"; Recommendation = "Review Required" }
        }
        return @{ Risk = "Low"; Recommendation = "No Action Needed" }
    }

    return @{ Risk = "Low"; Recommendation = "No Action Needed" }
}


#------------------------------------------------------------------------ [ HTML Report Generator ]

Function EscHtml
{
    param([string]$s)
    return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

Function EscJson
{
    param([string]$s)
    return ($s -replace '\\','\\' -replace '"','\"' -replace "`n",' ' -replace "`r",' ' -replace "`t",' ')
}

Function Build-PolicyJson
{
    param([System.Collections.Generic.List[psobject]]$Rows)

    $parts = foreach ($r in $Rows)
    {
        '{"res":"'        + (EscJson $r.ResourceName)          + '",' +
        '"resId":"'       + (EscJson $r.ResourceId)            + '",' +
        '"resType":"'     + (EscJson $r.ResourceType)          + '",' +
        '"rg":"'          + (EscJson $r.ResourceGroup)         + '",' +
        '"sub":"'         + (EscJson $r.SubscriptionName)      + '",' +
        '"level":"'       + (EscJson $r.InheritanceLevel)      + '",' +
        '"from":"'        + (EscJson $r.InheritedFrom)         + '",' +
        '"assignment":"'  + (EscJson $r.PolicyAssignmentName)  + '",' +
        '"assignId":"'    + (EscJson $r.PolicyAssignmentId)    + '",' +
        '"defId":"'       + (EscJson $r.PolicyDefinitionId)    + '",' +
        '"ptype":"'       + (EscJson $r.PolicyType)            + '",' +
        '"effect":"'      + (EscJson $r.Effect)                + '",' +
        '"enforcement":"' + (EscJson $r.EnforcementMode)       + '",' +
        '"exemption":"'   + (EscJson $r.ExemptionExists)       + '",' +
        '"expiresOn":"'   + (EscJson $r.ExemptionExpiry)       + '",' +
        '"compliance":"'  + (EscJson $r.ComplianceState)       + '",' +
        '"nc":'           + [int]$r.NonCompliantResources       + ','  +
        '"risk":"'        + (EscJson $r.RiskLevel)             + '",' +
        '"rec":"'         + (EscJson $r.ExemptionRecommendation) + '"}'
    }

    return '[' + ($parts -join ',') + ']'
}

Function Generate-EffectivePoliciesHtml
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ResourceInfo,
        [hashtable]$RunParameters,
        [System.Collections.Generic.List[psobject]]$ChainLevels,
        [System.Collections.Generic.List[psobject]]$AllRows,
        [hashtable]$RunSummary,
        [string]$HtmlPath,
        [string]$CsvPath,
        [string]$ExemptionPlannerBlock
    )

    $generatedOn = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    # ── Stat counts ───────────────────────────────────────────────────────────
    $totalPolicies   = $AllRows.Count
    $highRisk        = @($AllRows | Where-Object { $_.RiskLevel -eq "High"   }).Count
    $medRisk         = @($AllRows | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $lowRisk         = @($AllRows | Where-Object { $_.RiskLevel -eq "Low"    }).Count
    $needExemption   = @($AllRows | Where-Object { $_.ExemptionRecommendation -eq "Exemption Needed" }).Count
    $alreadyExempted = @($AllRows | Where-Object { $_.ExemptionRecommendation -eq "Already Exempted" }).Count
    $denyCount       = @($AllRows | Where-Object { $_.Effect -eq "Deny" }).Count
    $mgCount         = @($AllRows | Where-Object { $_.InheritanceLevel -eq "Management Group" }).Count
    $subCount        = @($AllRows | Where-Object { $_.InheritanceLevel -eq "Subscription"      }).Count
    $rgCount         = @($AllRows | Where-Object { $_.InheritanceLevel -eq "Resource Group"    }).Count
    $resCount        = @($AllRows | Where-Object { $_.InheritanceLevel -eq "Resource"          }).Count

    # ── Chain level rows for Overview ─────────────────────────────────────────
    $chainHtml = ""
    foreach ($cl in $ChainLevels)
    {
        $iconCls = switch ($cl.Status)
        {
            "Assessed" { if ($cl.AssignmentCount -gt 0) { "chain-active"  } else { "chain-empty" } }
            "Skipped"  { "chain-skipped" }
            "Error"    { "chain-error"   }
            default    { "chain-empty"   }
        }
        $skipNote = if ($cl.Status -eq "Skipped") { " <span class='chain-note'>($(EscHtml $cl.SkipReason))</span>" } else { "" }

        $chainHtml += @"
                <div class="chain-step $iconCls">
                    <div class="chain-icon"></div>
                    <div class="chain-body">
                        <div class="chain-label">$(EscHtml $cl.LevelName)$skipNote</div>
                        <div class="chain-scope">$(EscHtml $cl.ScopeName)</div>
                        <div class="chain-count">$($cl.AssignmentCount) assignment(s)</div>
                    </div>
                </div>
"@
    }

    # ── Exemption planner block (HTML-encoded for <pre>) ──────────────────────
    $plannerHtml = if ($ExemptionPlannerBlock)
    {
        EscHtml $ExemptionPlannerBlock
    }
    else
    {
        "# No assignments currently require an exemption for this resource."
    }

    # ── Output file lines ─────────────────────────────────────────────────────
    $outputFilesHtml = ""
    if ($CsvPath)
    {
        $outputFilesHtml += "<div class='info-card'><div class='info-label'>CSV Export</div><div class='info-value mono'>$(EscHtml $CsvPath)</div></div>"
    }
    $outputFilesHtml += "<div class='info-card'><div class='info-label'>HTML Report (this file)</div><div class='info-value mono'>$(EscHtml $HtmlPath)</div></div>"

    # ── Inline policy data JSON ───────────────────────────────────────────────
    $policyJson = Build-PolicyJson -Rows $AllRows

    # ── HTML template (single-quoted here-string + __TOKEN__ substitution) ────
    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Effective Policy Analysis — __RESOURCE_NAME__</title>
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
body.light-theme{
  --bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;
  --border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;
  --green:#1a7f37;--amber:#b08000;--red:#cf222e;
  --text:#1f2328;--muted:#636c76;--muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;}
#sidebar{
  width:236px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;
}
.logo-block{padding:20px 16px 14px;border-bottom:1px solid var(--border);}
.logo-icon{width:36px;height:36px;border-radius:8px;
  background:linear-gradient(135deg,var(--accent),var(--accent2));
  display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:8px;}
.logo-title{font-size:12px;font-weight:700;color:var(--text);}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{display:inline-block;margin-top:6px;padding:2px 8px;border-radius:20px;
  font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent);border:1px solid var(--border);}
.nav-section{padding:12px 8px;flex:1;}
.nav-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;
  letter-spacing:.08em;padding:0 8px;margin-bottom:4px;}
.nav-btn{
  display:flex;align-items:center;gap:8px;width:100%;padding:8px 10px;border:none;
  background:transparent;color:var(--muted2);font-size:13px;border-radius:var(--radius-sm);
  cursor:pointer;text-align:left;transition:background .15s,color .15s;position:relative;margin-bottom:2px;
}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:var(--surface3);color:var(--accent);font-weight:600;}
.nav-btn.active::before{
  content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;
  background:var(--accent);border-radius:0 3px 3px 0;
}
.nav-icon{font-size:14px;width:18px;text-align:center;}
.sidebar-footer{padding:12px 14px;border-top:1px solid var(--border);}
.theme-toggle{display:flex;align-items:center;justify-content:space-between;font-size:11px;color:var(--muted);margin-bottom:8px;}
.toggle-pill{
  width:38px;height:20px;border-radius:10px;border:none;cursor:pointer;
  background:var(--surface3);position:relative;transition:background .2s;
}
.toggle-pill::after{
  content:'';position:absolute;top:3px;left:3px;width:14px;height:14px;
  border-radius:50%;background:var(--accent);transition:transform .2s;
}
body.light-theme .toggle-pill::after{transform:translateX(18px);}
.footer-meta{font-size:10px;color:var(--muted);line-height:1.5;}
#main{margin-left:236px;padding:26px;width:calc(100% - 236px);min-height:100vh;}
.page{display:none;}
.page.active{display:block;animation:fadeIn .18s ease;}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px);}to{opacity:1;transform:none;}}
.page-header{margin-bottom:20px;}
.page-title{font-size:20px;font-weight:700;}
.page-sub{font-size:12px;color:var(--muted);margin-top:3px;}
/* ── Resource banner ────────────────────────────────── */
.resource-banner{
  background:linear-gradient(135deg,#0d2137 0%,#0a1628 100%);
  border:1px solid var(--border);border-left:4px solid var(--accent2);
  border-radius:var(--radius);padding:18px 22px;margin-bottom:20px;
  display:flex;align-items:center;gap:18px;
}
.resource-banner-icon{font-size:28px;}
.resource-banner-body{}
.resource-banner-name{font-size:16px;font-weight:700;color:var(--accent2);}
.resource-banner-meta{font-size:11px;color:var(--muted2);font-family:var(--mono);margin-top:4px;word-break:break-all;}
/* ── Stat cards ─────────────────────────────────────── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px;}
.stat-card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:16px 14px;border-top:3px solid;transition:transform .15s,box-shadow .15s;
}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-num{font-size:28px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:10px;color:var(--muted);margin-top:5px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:10px;color:var(--muted2);margin-top:3px;}
/* ── Chain visualization ────────────────────────────── */
.chain-wrap{display:flex;align-items:flex-start;gap:0;flex-wrap:wrap;margin-bottom:20px;}
.chain-step{
  display:flex;align-items:flex-start;gap:10px;padding:14px 16px;
  border:1px solid var(--border);border-radius:var(--radius-sm);
  background:var(--surface);min-width:160px;flex:1;position:relative;
}
.chain-step+.chain-step{margin-left:-1px;border-left-color:transparent;}
.chain-step.chain-active{border-top:3px solid var(--accent2);background:rgba(57,197,207,.04);}
.chain-step.chain-empty{border-top:3px solid var(--border);opacity:.65;}
.chain-step.chain-skipped{border-top:3px solid var(--amber);opacity:.8;}
.chain-step.chain-error{border-top:3px solid var(--red);}
.chain-icon{width:10px;height:10px;border-radius:50%;margin-top:4px;flex-shrink:0;}
.chain-active .chain-icon{background:var(--accent2);}
.chain-empty .chain-icon{background:var(--muted);}
.chain-skipped .chain-icon{background:var(--amber);}
.chain-error .chain-icon{background:var(--red);}
.chain-label{font-size:12px;font-weight:700;margin-bottom:3px;}
.chain-scope{font-size:10px;color:var(--muted);font-family:var(--mono);word-break:break-all;margin-bottom:4px;}
.chain-count{font-size:11px;font-family:var(--mono);color:var(--accent2);}
.chain-note{font-size:10px;color:var(--amber);font-weight:400;font-family:var(--sans);}
/* ── Panels ─────────────────────────────────────────── */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px;margin-bottom:16px;}
.panel-title{font-size:13px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;}
.bar-row{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:11px;color:var(--muted2);width:150px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:7px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:11px;font-family:var(--mono);color:var(--muted2);width:80px;text-align:right;flex-shrink:0;}
/* ── Info grid ──────────────────────────────────────── */
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:12px;word-break:break-all;}
.info-value.mono{font-family:var(--mono);font-size:11px;}
/* ── Table ──────────────────────────────────────────── */
.toolbar{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:180px;}
.search-wrap input{
  width:100%;padding:7px 10px 7px 30px;background:var(--surface2);
  border:1px solid var(--border);border-radius:var(--radius-sm);
  color:var(--text);font-size:12px;outline:none;
}
.search-wrap input:focus{border-color:var(--accent);}
.search-icon{position:absolute;left:9px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:12px;}
.filter-sel{
  padding:6px 8px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);font-size:11px;cursor:pointer;
}
.tbl-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{
  padding:9px 10px;text-align:left;font-size:10px;font-weight:700;
  text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
  background:var(--surface2);border-bottom:1px solid var(--border);
  cursor:pointer;white-space:nowrap;user-select:none;
}
th:hover{color:var(--text);}
td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:middle;}
tr:hover td{background:var(--surface2);cursor:pointer;}
.pagination{display:flex;align-items:center;gap:6px;margin-top:10px;font-size:11px;color:var(--muted);flex-wrap:wrap;}
.pg-btn{padding:3px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:11px;}
.pg-btn:hover{border-color:var(--accent);color:var(--accent);}
.pg-btn.active{background:var(--accent);color:#fff;border-color:var(--accent);}
.pg-btn:disabled{opacity:.4;cursor:not-allowed;}
/* ── Badges ─────────────────────────────────────────── */
.badge{display:inline-block;padding:2px 7px;border-radius:20px;font-size:10px;font-weight:700;white-space:nowrap;}
.badge-green {background:rgba(63,185,80,.15); color:var(--green); border:1px solid rgba(63,185,80,.3);}
.badge-amber {background:rgba(210,153,34,.15);color:var(--amber); border:1px solid rgba(210,153,34,.3);}
.badge-red   {background:rgba(248,81,73,.15); color:var(--red);   border:1px solid rgba(248,81,73,.3);}
.badge-blue  {background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.badge-cyan  {background:rgba(57,197,207,.15);color:var(--accent2);border:1px solid rgba(57,197,207,.3);}
.badge-gray  {background:var(--surface3);     color:var(--muted); border:1px solid var(--border);}
/* ── Planner block ──────────────────────────────────── */
.planner-banner{
  padding:14px 16px;border-radius:var(--radius-sm);border:1px solid rgba(163,113,247,.35);
  background:rgba(163,113,247,.06);margin-bottom:14px;font-size:12px;color:var(--muted2);
}
.planner-banner strong{color:var(--accent3);}
pre.code-block{
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:16px;font-family:var(--mono);font-size:11px;color:var(--text);
  overflow-x:auto;white-space:pre;line-height:1.6;
}
.copy-btn{
  padding:5px 12px;background:var(--surface3);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--muted2);font-size:11px;cursor:pointer;
  transition:background .15s,color .15s;margin-bottom:10px;
}
.copy-btn:hover{background:var(--accent);color:#fff;border-color:var(--accent);}
/* ── Detail drawer ──────────────────────────────────── */
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{
  position:fixed;right:0;top:0;bottom:0;width:420px;max-width:95vw;
  background:var(--surface);border-left:1px solid var(--border);
  z-index:201;display:flex;flex-direction:column;
  transform:translateX(100%);transition:transform .22s ease;overflow:hidden;
}
#detailDrawer.open{transform:translateX(0);}
.drawer-header{padding:16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;}
.drawer-title{font-size:12px;font-weight:700;word-break:break-word;flex:1;padding-right:10px;}
.drawer-close{background:none;border:none;color:var(--muted);font-size:18px;cursor:pointer;padding:2px 5px;border-radius:var(--radius-sm);}
.drawer-close:hover{color:var(--text);background:var(--surface2);}
.drawer-body{padding:18px;overflow-y:auto;flex:1;}
.drawer-nav{display:flex;gap:6px;align-items:center;margin-bottom:14px;}
.drawer-nav-btn{padding:4px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:11px;}
.drawer-nav-btn:hover{border-color:var(--accent);color:var(--accent);}
.drawer-nav-info{font-size:11px;color:var(--muted);flex:1;text-align:center;}
.drawer-field{margin-bottom:12px;}
.drawer-field-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px;}
.drawer-field-value{font-size:12px;word-break:break-all;}
.drawer-field-value.mono{font-family:var(--mono);font-size:11px;}
.drawer-divider{font-size:10px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.06em;margin:14px 0 8px;border-top:1px solid var(--border);padding-top:12px;}
/* ── Toast ──────────────────────────────────────────── */
#toast{
  position:fixed;bottom:22px;right:22px;padding:10px 16px;
  background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);
  font-size:12px;box-shadow:var(--shadow);
  opacity:0;transform:translateY(8px);transition:opacity .18s,transform .18s;pointer-events:none;z-index:300;
}
#toast.show{opacity:1;transform:translateY(0);}
/* ── Mobile ─────────────────────────────────────────── */
#menuToggle{display:none;}
@media(max-width:768px){
  #menuToggle{display:flex;align-items:center;justify-content:center;position:fixed;top:10px;left:10px;z-index:300;
    width:34px;height:34px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:16px;}
  #sidebar{transform:translateX(-100%);transition:transform .22s;}
  #sidebar.open{transform:translateX(0);}
  #main{margin-left:0;width:100%;padding:14px;padding-top:52px;}
  .chart-grid{grid-template-columns:1fr;}
  .chain-wrap{flex-direction:column;}
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
    <div class="logo-title">Effective Policy Analyser</div>
    <div class="logo-sub">Azure Resource Policy Scope</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">&#128202;</span> Overview</button>
    <button class="nav-btn" onclick="showPage('policies',this)"><span class="nav-icon">&#128203;</span> Effective Policies</button>
    <button class="nav-btn" onclick="showPage('inheritance',this)"><span class="nav-icon">&#127890;</span> Inheritance Map</button>
    <button class="nav-btn" onclick="showPage('exemptions',this)"><span class="nav-icon">&#128737;</span> Exemptions</button>
    <button class="nav-btn" onclick="showPage('planner',this)"><span class="nav-icon">&#9998;</span> Exemption Planner</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">&#9881;</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">
      Generated: __GENERATED_ON__<br/>
      Effective Policy Analyser v1.0
    </div>
  </div>
</nav>

<main id="main">

  <!-- ─── OVERVIEW ─── -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Effective Policy Overview</div>
      <div class="page-sub">Full inheritance chain for the assessed resource — Management Group to Resource scope</div>
    </div>

    <div class="resource-banner">
      <div class="resource-banner-icon">&#128272;</div>
      <div class="resource-banner-body">
        <div class="resource-banner-name">__RESOURCE_NAME__</div>
        <div class="resource-banner-meta">
          Type: __RESOURCE_TYPE__ &nbsp;|&nbsp; RG: __RESOURCE_RG__ &nbsp;|&nbsp; Sub: __RESOURCE_SUB__<br/>
          __RESOURCE_ID__
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">&#127968; Inheritance Chain</div>
      <div class="chain-wrap">
        __CHAIN_HTML__
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue"><div class="stat-num">__TOTAL_POLICIES__</div><div class="stat-label">Total Effective Policies</div></div>
      <div class="stat-card c-red"><div class="stat-num">__HIGH_RISK__</div><div class="stat-label">High Risk</div><div class="stat-sub">Deny + Enforced + NonCompliant</div></div>
      <div class="stat-card c-amber"><div class="stat-num">__MED_RISK__</div><div class="stat-label">Medium Risk</div></div>
      <div class="stat-card c-green"><div class="stat-num">__LOW_RISK__</div><div class="stat-label">Low Risk</div></div>
      <div class="stat-card c-purple"><div class="stat-num">__NEED_EXEMPTION__</div><div class="stat-label">Exemption Needed</div></div>
      <div class="stat-card c-cyan"><div class="stat-num">__ALREADY_EXEMPTED__</div><div class="stat-label">Already Exempted</div></div>
    </div>

    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">&#128203; Assignments by Inheritance Level</div>
        <div class="bar-row"><span class="bar-label">Management Group</span><div class="bar-track"><div class="bar-fill" data-pct="__MG_PCT__"></div></div><span class="bar-pct">__MG_COUNT__ (__MG_PCT__%)</span></div>
        <div class="bar-row"><span class="bar-label">Subscription</span><div class="bar-track"><div class="bar-fill" data-pct="__SUB_PCT__"></div></div><span class="bar-pct">__SUB_COUNT__ (__SUB_PCT__%)</span></div>
        <div class="bar-row"><span class="bar-label">Resource Group</span><div class="bar-track"><div class="bar-fill" data-pct="__RG_PCT__"></div></div><span class="bar-pct">__RG_COUNT__ (__RG_PCT__%)</span></div>
        <div class="bar-row"><span class="bar-label">Resource</span><div class="bar-track"><div class="bar-fill" data-pct="__RES_PCT__"></div></div><span class="bar-pct">__RES_COUNT__ (__RES_PCT__%)</span></div>
      </div>
      <div class="panel">
        <div class="panel-title">&#128274; Policy Effect Distribution</div>
        __EFFECT_BARS__
      </div>
    </div>
  </div>

  <!-- ─── EFFECTIVE POLICIES ─── -->
  <div id="page-policies" class="page">
    <div class="page-header">
      <div class="page-title">Effective Policies</div>
      <div class="page-sub">All policy assignments in effect for this resource. Click any row for full details.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">&#128269;</span>
          <input type="text" id="polSearch" placeholder="Search assignment, effect, scope…" oninput="filterPol()"/>
        </div>
        <select class="filter-sel" id="filterLevel" onchange="filterPol()">
          <option value="">All Scope Levels</option>
          <option value="Management Group">Management Group</option>
          <option value="Subscription">Subscription</option>
          <option value="Resource Group">Resource Group</option>
          <option value="Resource">Resource</option>
        </select>
        <select class="filter-sel" id="filterRisk" onchange="filterPol()">
          <option value="">All Risk Levels</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select class="filter-sel" id="polPageSz" onchange="changePolPageSz()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="sortPol(0)">Assignment Name</th>
              <th onclick="sortPol(1)">Level</th>
              <th onclick="sortPol(2)">Effect</th>
              <th onclick="sortPol(3)">Enforcement</th>
              <th onclick="sortPol(4)">Compliance</th>
              <th onclick="sortPol(5)">Risk</th>
              <th onclick="sortPol(6)">Recommendation</th>
              <th>Exempt?</th>
            </tr>
          </thead>
          <tbody id="polBody"></tbody>
        </table>
      </div>
      <div class="pagination" id="polPagination"></div>
    </div>
  </div>

  <!-- ─── INHERITANCE MAP ─── -->
  <div id="page-inheritance" class="page">
    <div class="page-header">
      <div class="page-title">Inheritance Map</div>
      <div class="page-sub">Policy assignments grouped by the scope level they are defined at</div>
    </div>
    <div id="inheritanceContent"></div>
  </div>

  <!-- ─── EXEMPTIONS ─── -->
  <div id="page-exemptions" class="page">
    <div class="page-header">
      <div class="page-title">Existing Exemptions</div>
      <div class="page-sub">Active exemptions at this resource scope and which assignments still require one</div>
    </div>
    <div class="panel">
      <div class="panel-title">&#128737; Already Exempted</div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr><th>Assignment Name</th><th>Level</th><th>Effect</th><th>Exemption Expires</th></tr>
          </thead>
          <tbody id="exemptedBody"></tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">&#9888; Still Requires Exemption</div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr><th>Assignment Name</th><th>Level</th><th>Effect</th><th>Risk</th><th>Recommendation</th></tr>
          </thead>
          <tbody id="needsExemptBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ─── EXEMPTION PLANNER ─── -->
  <div id="page-planner" class="page">
    <div class="page-header">
      <div class="page-title">Exemption Planner</div>
      <div class="page-sub">Pre-filled command for New-AzureKeyVaultPolicyExemption — copy, review, then run</div>
    </div>
    <div class="planner-banner">
      <strong>Governance checkpoint:</strong> Review each assignment listed below before creating exemptions.
      Confirm the business justification, validate the exemption category (Waiver vs Mitigated), and set
      the minimum required duration. Remove any assignment that does not actually need exempting.
    </div>
    <div class="panel">
      <div class="panel-title">&#9998; Ready-to-Run PowerShell Block</div>
      <button class="copy-btn" onclick="copyPlanner()">&#128203; Copy to Clipboard</button>
      <pre class="code-block" id="plannerBlock">__PLANNER_HTML__</pre>
    </div>
  </div>

  <!-- ─── SESSION INFO ─── -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Run Parameters</div>
      <div class="page-sub">Authentication context and configuration used for this assessment</div>
    </div>
    <div class="panel">
      <div class="panel-title">&#128274; Session Information</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Tenant ID</div><div class="info-value mono">__TENANT__</div></div>
        <div class="info-card"><div class="info-label">Account</div><div class="info-value mono">__ACCOUNT__</div></div>
        <div class="info-card"><div class="info-label">Environment</div><div class="info-value">__ENVIRONMENT__</div></div>
        <div class="info-card"><div class="info-label">Generated On</div><div class="info-value">__GENERATED_ON__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">&#9881; Run Parameters</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Resource Name</div><div class="info-value mono">__RESOURCE_NAME__</div></div>
        <div class="info-card"><div class="info-label">Resource Type Filter</div><div class="info-value mono">__PARAM_RESTYPE__</div></div>
        <div class="info-card"><div class="info-label">Resource Group Filter</div><div class="info-value mono">__PARAM_RG__</div></div>
        <div class="info-card"><div class="info-label">Subscription Filter</div><div class="info-value mono">__PARAM_SUB__</div></div>
        <div class="info-card"><div class="info-label">Compliance State</div><div class="info-value">__PARAM_COMPLIANCE__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value mono">__EXEC_TIME__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">&#128194; Output Files</div>
      <div class="info-grid">
        __OUTPUT_FILES_HTML__
      </div>
    </div>
  </div>

</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Policy Detail</span>
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
/* ─── Data ───────────────────────────────────────────────────────────────── */
const POL_DATA = __POL_JSON__;

/* ─── Utilities ──────────────────────────────────────────────────────────── */
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function showToast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2500);}

function riskBadge(r){
  if(r==='High')  return '<span class="badge badge-red">High</span>';
  if(r==='Medium')return '<span class="badge badge-amber">Medium</span>';
  if(r==='Low')   return '<span class="badge badge-green">Low</span>';
  if(r==='Info')  return '<span class="badge badge-cyan">Info</span>';
  return '<span class="badge badge-gray">'+escH(r)+'</span>';
}
function recBadge(r){
  if(r==='Exemption Needed') return '<span class="badge badge-red">Exemption Needed</span>';
  if(r==='Review Required')  return '<span class="badge badge-amber">Review Required</span>';
  if(r==='No Action Needed') return '<span class="badge badge-green">No Action Needed</span>';
  if(r==='Already Exempted') return '<span class="badge badge-cyan">Already Exempted</span>';
  return '<span class="badge badge-gray">'+escH(r)+'</span>';
}
function levelBadge(l){
  const m={'Management Group':'badge-purple','Subscription':'badge-blue','Resource Group':'badge-cyan','Resource':'badge-green'};
  return '<span class="badge '+(m[l]||'badge-gray')+'">'+escH(l)+'</span>';
}
function compBadge(c){
  if(c==='Compliant')    return '<span class="badge badge-green">Compliant</span>';
  if(c==='NonCompliant') return '<span class="badge badge-red">NonCompliant</span>';
  if(c==='Not Assessed' || c==='Not Requested') return '<span class="badge badge-gray">'+escH(c)+'</span>';
  return '<span class="badge badge-gray">'+escH(c)+'</span>';
}
function enfBadge(e){
  if(e==='Default')       return '<span class="badge badge-red">Enforcing</span>';
  if(e==='DoNotEnforce')  return '<span class="badge badge-amber">DoNotEnforce</span>';
  return '<span class="badge badge-gray">'+escH(e)+'</span>';
}

/* ─── Theme ──────────────────────────────────────────────────────────────── */
function toggleTheme(){document.body.classList.toggle('light-theme');}
function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
  if(id==='inheritance') buildInheritance();
  if(id==='exemptions')  buildExemptions();
}

/* ─── Policies table ─────────────────────────────────────────────────────── */
let polFiltered=[...POL_DATA], polPage=1, polPageSz=25, polSortCol=-1, polSortAsc=true;
const polKeys=['assignment','level','effect','enforcement','compliance','risk','rec','exemption'];

function filterPol(){
  const q=document.getElementById('polSearch').value.toLowerCase();
  const lv=document.getElementById('filterLevel').value;
  const rk=document.getElementById('filterRisk').value;
  polFiltered=POL_DATA.filter(r=>{
    const mQ=!q||(r.assignment+r.level+r.effect+r.enforcement+r.compliance+r.risk+r.rec).toLowerCase().includes(q);
    const mL=!lv||r.level===lv;
    const mR=!rk||r.risk===rk;
    return mQ&&mL&&mR;
  });
  polPage=1; renderPol();
}

function changePolPageSz(){polPageSz=parseInt(document.getElementById('polPageSz').value);polPage=1;renderPol();}

function sortPol(col){
  if(polSortCol===col){polSortAsc=!polSortAsc;}else{polSortCol=col;polSortAsc=true;}
  const k=polKeys[col];
  polFiltered.sort((a,b)=>polSortAsc?String(a[k]).localeCompare(String(b[k]),undefined,{numeric:true})
                                     :String(b[k]).localeCompare(String(a[k]),undefined,{numeric:true}));
  renderPol();
}

function renderPol(){
  const start=(polPage-1)*polPageSz;
  const slice=polFiltered.slice(start,start+polPageSz);
  document.getElementById('polBody').innerHTML=slice.map(r=>{
    const gi=POL_DATA.indexOf(r);
    const nm=r.assignment.length>40?r.assignment.substring(0,37)+'...':r.assignment;
    return `<tr onclick="showDetail(${gi})">
      <td title="${escH(r.assignment)}">${escH(nm)}</td>
      <td>${levelBadge(r.level)}</td>
      <td><span class="badge badge-gray">${escH(r.effect)}</span></td>
      <td>${enfBadge(r.enforcement)}</td>
      <td>${compBadge(r.compliance)}</td>
      <td>${riskBadge(r.risk)}</td>
      <td>${recBadge(r.rec)}</td>
      <td>${r.exemption==='Yes'?'<span class="badge badge-cyan">Yes</span>':'<span class="badge badge-gray">No</span>'}</td>
    </tr>`;
  }).join('');
  renderPolPg();
}

function renderPolPg(){
  const total=Math.ceil(polFiltered.length/polPageSz);
  const el=document.getElementById('polPagination');
  let h=`<span>${polFiltered.length} policies</span>`;
  h+=`<button class="pg-btn" onclick="changePolPg(${polPage-1})" ${polPage<=1?'disabled':''}>&#8249; Prev</button>`;
  const s=Math.max(1,polPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===polPage?'active':''}" onclick="changePolPg(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="changePolPg(${polPage+1})" ${polPage>=total?'disabled':''}>Next &#8250;</button>`;
  el.innerHTML=h;
}
function changePolPg(p){const t=Math.ceil(polFiltered.length/polPageSz);if(p<1||p>t)return;polPage=p;renderPol();}

/* ─── Inheritance Map ────────────────────────────────────────────────────── */
function buildInheritance(){
  const container=document.getElementById('inheritanceContent');
  const levels=['Management Group','Subscription','Resource Group','Resource'];
  let html='';
  levels.forEach(lv=>{
    const items=POL_DATA.filter(r=>r.level===lv);
    html+=`<div class="panel">
      <div class="panel-title">${levelBadge(lv)} &nbsp; ${items.length} assignment(s)</div>`;
    if(items.length===0){html+='<p style="color:var(--muted);font-size:12px;">No assignments at this scope level.</p>';}
    else{
      html+=`<div class="tbl-wrap"><table>
        <thead><tr><th>Assignment Name</th><th>Effect</th><th>Enforcement</th><th>Defined At (Scope)</th><th>Risk</th></tr></thead>
        <tbody>`;
      items.forEach((r,i)=>{
        const gi=POL_DATA.indexOf(r);
        const nm=r.assignment.length>42?r.assignment.substring(0,39)+'...':r.assignment;
        html+=`<tr onclick="showDetail(${gi})">
          <td title="${escH(r.assignment)}">${escH(nm)}</td>
          <td><span class="badge badge-gray">${escH(r.effect)}</span></td>
          <td>${enfBadge(r.enforcement)}</td>
          <td style="font-family:var(--mono);font-size:10px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escH(r.from)}">${escH(r.from)}</td>
          <td>${riskBadge(r.risk)}</td>
        </tr>`;
      });
      html+='</tbody></table></div>';
    }
    html+='</div>';
  });
  container.innerHTML=html;
}

/* ─── Exemptions page ────────────────────────────────────────────────────── */
function buildExemptions(){
  const exempted=POL_DATA.filter(r=>r.exemption==='Yes');
  const needsEx=POL_DATA.filter(r=>r.rec==='Exemption Needed');

  const eb=document.getElementById('exemptedBody');
  if(exempted.length===0){eb.innerHTML='<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px;">No active exemptions found at this resource scope.</td></tr>';}
  else{
    eb.innerHTML=exempted.map(r=>{
      const gi=POL_DATA.indexOf(r);
      return `<tr onclick="showDetail(${gi})">
        <td>${escH(r.assignment)}</td>
        <td>${levelBadge(r.level)}</td>
        <td><span class="badge badge-gray">${escH(r.effect)}</span></td>
        <td style="font-family:var(--mono);font-size:11px">${escH(r.expiresOn)||'—'}</td>
      </tr>`;
    }).join('');
  }

  const nb=document.getElementById('needsExemptBody');
  if(needsEx.length===0){nb.innerHTML='<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px;">No assignments currently require an exemption.</td></tr>';}
  else{
    nb.innerHTML=needsEx.map(r=>{
      const gi=POL_DATA.indexOf(r);
      return `<tr onclick="showDetail(${gi})">
        <td>${escH(r.assignment)}</td>
        <td>${levelBadge(r.level)}</td>
        <td><span class="badge badge-gray">${escH(r.effect)}</span></td>
        <td>${riskBadge(r.risk)}</td>
        <td>${recBadge(r.rec)}</td>
      </tr>`;
    }).join('');
  }
}

/* ─── Planner ────────────────────────────────────────────────────────────── */
function copyPlanner(){
  const text=document.getElementById('plannerBlock').textContent;
  navigator.clipboard.writeText(text).then(()=>showToast('Copied to clipboard')).catch(()=>showToast('Copy failed — select manually'));
}

/* ─── Detail Drawer ──────────────────────────────────────────────────────── */
let currentDetail=0;
function showDetail(idx){
  currentDetail=idx;
  const r=POL_DATA[idx];
  if(!r) return;
  document.getElementById('drawerTitle').textContent=r.assignment;
  document.getElementById('drawerNavInfo').textContent=`${idx+1} of ${POL_DATA.length}`;
  document.getElementById('drawerContent').innerHTML=`
    <div class="drawer-field"><div class="drawer-field-label">Risk Level</div><div class="drawer-field-value">${riskBadge(r.risk)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Recommendation</div><div class="drawer-field-value">${recBadge(r.rec)}</div></div>
    <div class="drawer-divider">Inheritance</div>
    <div class="drawer-field"><div class="drawer-field-label">Scope Level</div><div class="drawer-field-value">${levelBadge(r.level)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Defined At (Scope)</div><div class="drawer-field-value mono">${escH(r.from)}</div></div>
    <div class="drawer-divider">Policy Details</div>
    <div class="drawer-field"><div class="drawer-field-label">Assignment ID</div><div class="drawer-field-value mono" style="font-size:10px">${escH(r.assignId)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Definition ID</div><div class="drawer-field-value mono" style="font-size:10px">${escH(r.defId)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Policy Type</div><div class="drawer-field-value">${escH(r.ptype)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Effect</div><div class="drawer-field-value"><span class="badge badge-gray">${escH(r.effect)}</span></div></div>
    <div class="drawer-field"><div class="drawer-field-label">Enforcement Mode</div><div class="drawer-field-value">${enfBadge(r.enforcement)}</div></div>
    <div class="drawer-divider">Compliance & Exemption</div>
    <div class="drawer-field"><div class="drawer-field-label">Compliance State</div><div class="drawer-field-value">${compBadge(r.compliance)}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Non-Compliant Resources</div><div class="drawer-field-value mono">${r.nc}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Exemption Exists</div><div class="drawer-field-value">${r.exemption==='Yes'?'<span class="badge badge-cyan">Yes</span>':'<span class="badge badge-gray">No</span>'}</div></div>
    <div class="drawer-field"><div class="drawer-field-label">Exemption Expires</div><div class="drawer-field-value mono">${escH(r.expiresOn)||'—'}</div></div>
  `;
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}
function closeDrawer(){document.getElementById('drawerBackdrop').style.display='none';document.getElementById('detailDrawer').classList.remove('open');}
function navDetail(dir){const n=currentDetail+dir;if(n>=0&&n<POL_DATA.length)showDetail(n);}

/* ─── Bar animation ──────────────────────────────────────────────────────── */
function animateBars(){requestAnimationFrame(()=>{document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>{el.style.width=el.dataset.pct+'%';});});}

/* ─── Keyboard ───────────────────────────────────────────────────────────── */
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft')  navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
  if(e.key==='/'){const s=document.querySelector('.page.active input[type=text]');if(s){e.preventDefault();s.focus();}}
});

/* ─── Init ───────────────────────────────────────────────────────────────── */
filterPol();
animateBars();
</script>
</body>
</html>
'@

    # ── Compute bar chart percentages ─────────────────────────────────────────
    $safeTotal = [math]::Max($totalPolicies, 1)

    $mgPct  = [math]::Round(($mgCount  / $safeTotal) * 100)
    $subPct = [math]::Round(($subCount / $safeTotal) * 100)
    $rgPct  = [math]::Round(($rgCount  / $safeTotal) * 100)
    $resPct = [math]::Round(($resCount / $safeTotal) * 100)

    # ── Effect distribution bars ──────────────────────────────────────────────
    $effectGroups = $AllRows | Group-Object Effect | Sort-Object Count -Descending
    $effectBarsHtml = ""
    foreach ($eg in $effectGroups)
    {
        $pct = [math]::Round(($eg.Count / $safeTotal) * 100)
        $effectBarsHtml += @"
        <div class="bar-row">
            <span class="bar-label">$(EscHtml $eg.Name)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($eg.Count) ($pct%)</span>
        </div>
"@
    }

    # ── Substitute all tokens ─────────────────────────────────────────────────
    $html = $html `
        -replace '__GENERATED_ON__',      $generatedOn `
        -replace '__RESOURCE_NAME__',     (EscHtml $ResourceInfo.Name) `
        -replace '__RESOURCE_TYPE__',     (EscHtml $ResourceInfo.Type) `
        -replace '__RESOURCE_RG__',       (EscHtml $ResourceInfo.ResourceGroup) `
        -replace '__RESOURCE_SUB__',      (EscHtml $ResourceInfo.SubscriptionName) `
        -replace '__RESOURCE_ID__',       (EscHtml $ResourceInfo.ResourceId) `
        -replace '__CHAIN_HTML__',        $chainHtml `
        -replace '__TOTAL_POLICIES__',    $totalPolicies `
        -replace '__HIGH_RISK__',         $highRisk `
        -replace '__MED_RISK__',          $medRisk `
        -replace '__LOW_RISK__',          $lowRisk `
        -replace '__NEED_EXEMPTION__',    $needExemption `
        -replace '__ALREADY_EXEMPTED__',  $alreadyExempted `
        -replace '__MG_COUNT__',          $mgCount `
        -replace '__SUB_COUNT__',         $subCount `
        -replace '__RG_COUNT__',          $rgCount `
        -replace '__RES_COUNT__',         $resCount `
        -replace '__MG_PCT__',            $mgPct `
        -replace '__SUB_PCT__',           $subPct `
        -replace '__RG_PCT__',            $rgPct `
        -replace '__RES_PCT__',           $resPct `
        -replace '__EFFECT_BARS__',       $effectBarsHtml `
        -replace '__PLANNER_HTML__',      $plannerHtml `
        -replace '__TENANT__',            (EscHtml $SessionInfo.TenantId) `
        -replace '__ACCOUNT__',           (EscHtml $SessionInfo.Account) `
        -replace '__ENVIRONMENT__',       (EscHtml $SessionInfo.Environment) `
        -replace '__PARAM_RESTYPE__',     (EscHtml $RunParameters.ResourceType) `
        -replace '__PARAM_RG__',          (EscHtml $RunParameters.ResourceGroupName) `
        -replace '__PARAM_SUB__',         (EscHtml $RunParameters.SubscriptionId) `
        -replace '__PARAM_COMPLIANCE__',  (EscHtml $RunParameters.IncludeComplianceState) `
        -replace '__EXEC_TIME__',         (EscHtml $RunSummary.ExecutionTime) `
        -replace '__OUTPUT_FILES_HTML__', $outputFilesHtml `
        -replace '__POL_JSON__',          $policyJson

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureResourceEffectivePolicies
{
    [CmdletBinding()]
    param (
        # ── Mandatory ────────────────────────────────────────────────────────
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceName,

        # ── Optional disambiguation ──────────────────────────────────────────
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceType,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$SubscriptionId,

        # ── Optional switches ────────────────────────────────────────────────
        [Parameter(Mandatory = $false)]
        [switch]$IncludeComplianceState,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDisabledPolicies,

        [Parameter(Mandatory = $false)]
        [switch]$ExportToCsv,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            $dir = Split-Path $_ -Parent
            if ($dir -and -not (Test-Path $dir)) { throw "Directory does not exist: $dir" }
            if ($_ -match '[<>"|?*]')             { throw "CsvPath contains invalid characters." }
            return $true
        })]
        [string]$CsvPath = "C:\Temp\AzureResourceEffectivePolicies-Report.csv"
    )

    $startTime = Get-Date
    Write-Banner

    #------------------------------------------------------------------------ [ Module check ]

    $requiredModules = @(
        @{ Name = "Az.Accounts";  Cmdlet = "Get-AzContext"          },
        @{ Name = "Az.Resources"; Cmdlet = "Get-AzResource"         }
    )
    if ($IncludeComplianceState)
    {
        $requiredModules += @{ Name = "Az.PolicyInsights"; Cmdlet = "Get-AzPolicyState" }
    }

    foreach ($mod in $requiredModules)
    {
        if (-not (Get-Command $mod.Cmdlet -ErrorAction SilentlyContinue))
        {
            Write-Host "  Module not loaded: $($mod.Name)" -ForegroundColor Yellow
            $answer = Read-Host "  Install $($mod.Name) now? (Y/N)"
            if ($answer -match '^[Yy]$')
            {
                try
                {
                    Write-Host "  Installing $($mod.Name)..." -ForegroundColor Cyan
                    Install-Module -Name $mod.Name -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                    Import-Module  -Name $mod.Name -ErrorAction Stop
                    Write-Host "  $($mod.Name) installed." -ForegroundColor Green
                }
                catch
                {
                    Write-Host "  Failed to install $($mod.Name): $_" -ForegroundColor Red
                    return
                }
            }
            else
            {
                Write-Host "  Cannot proceed without $($mod.Name)." -ForegroundColor Yellow
                return
            }
        }
    }

    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    #------------------------------------------------------------------------ [ Auth check ]

    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx)
    {
        Write-Host "  No active Azure session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $ctx = Get-AzContext
    }

    $sessionInfo = @{
        TenantId    = $ctx.Tenant.Id
        Account     = $ctx.Account.Id
        Environment = $ctx.Environment.Name
    }

    Write-Section -Title "Session Information" -Data ([ordered]@{
        "Tenant ID"   = $sessionInfo.TenantId
        "Account"     = $sessionInfo.Account
        "Environment" = $sessionInfo.Environment
    })

    #------------------------------------------------------------------------ [ Resource resolution ]

    Write-Host ""
    Write-Host "  Resource Resolution" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("-" * 76) -ForegroundColor DarkGray
    Write-Host ""

    try
    {
        # Build Get-AzResource parameter splat
        $getAzResourceParams = @{ Name = $ResourceName; ErrorAction = "Stop" }

        if ($ResourceGroupName) { $getAzResourceParams['ResourceGroupName'] = $ResourceGroupName }
        if ($ResourceType)      { $getAzResourceParams['ResourceType']      = $ResourceType      }

        # If SubscriptionId supplied, switch context for the lookup then switch back
        $originalSubId = $ctx.Subscription.Id
        if ($SubscriptionId -and $SubscriptionId -ne $originalSubId)
        {
            Set-AzContext -SubscriptionId $SubscriptionId -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
        }

        $matchedResources = @(Get-AzResource @getAzResourceParams)

        # Restore context if we switched
        if ($SubscriptionId -and $SubscriptionId -ne $originalSubId)
        {
            Set-AzContext -SubscriptionId $originalSubId -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
        }
    }
    catch
    {
        Write-Host "  Resource lookup failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ("=" * 80) -ForegroundColor Cyan
        return
    }

    # ── Fail-early disambiguation ─────────────────────────────────────────────
    if ($matchedResources.Count -eq 0)
    {
        Write-Host "  No resource found matching name '$ResourceName'." -ForegroundColor Red
        if ($ResourceType      ) { Write-Host "  ResourceType filter    : $ResourceType"      -ForegroundColor Gray }
        if ($ResourceGroupName ) { Write-Host "  ResourceGroup filter   : $ResourceGroupName"  -ForegroundColor Gray }
        if ($SubscriptionId    ) { Write-Host "  Subscription filter    : $SubscriptionId"     -ForegroundColor Gray }
        Write-Host ("=" * 80) -ForegroundColor Cyan
        return
    }

    if ($matchedResources.Count -gt 1)
    {
        Write-Host "  Ambiguous resource name '$ResourceName' — $($matchedResources.Count) resources matched:" -ForegroundColor Yellow
        Write-Host ""
        foreach ($r in $matchedResources)
        {
            Write-Host "    Type : $($r.ResourceType)" -ForegroundColor Gray
            Write-Host "    RG   : $($r.ResourceGroupName)" -ForegroundColor Gray
            Write-Host "    ID   : $($r.ResourceId)" -ForegroundColor DarkGray
            Write-Host ""
        }
        Write-Host "  Rerun with -ResourceType and/or -ResourceGroupName to disambiguate." -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor Cyan
        return
    }

    $resource = $matchedResources[0]

    Write-Host "  Resource resolved:" -ForegroundColor Green
    Write-Host "    Name          : $($resource.Name)"              -ForegroundColor White
    Write-Host "    Type          : $($resource.ResourceType)"      -ForegroundColor White
    Write-Host "    Resource Group: $($resource.ResourceGroupName)" -ForegroundColor White
    Write-Host "    Location      : $($resource.Location)"          -ForegroundColor White
    Write-Host "    Resource ID   : $($resource.ResourceId)"        -ForegroundColor DarkGray

    # Switch context to the resource's subscription for all subsequent calls
    $resourceSubId = ($resource.ResourceId -split '/')[2]
    Set-AzContext -SubscriptionId $resourceSubId -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null

    $subDetails       = Get-AzSubscription -SubscriptionId $resourceSubId -WarningAction SilentlyContinue
    $subscriptionName = if ($subDetails.Name) { $subDetails.Name } else { $resourceSubId }

    $resourceInfo = @{
        Name             = $resource.Name
        ResourceId       = $resource.ResourceId
        Type             = $resource.ResourceType
        ResourceGroup    = $resource.ResourceGroupName
        SubscriptionId   = $resourceSubId
        SubscriptionName = $subscriptionName
        Location         = $resource.Location
    }

    #------------------------------------------------------------------------ [ Build scope chain ]
    #
    #   We collect assignments at four distinct scope levels. Each Get-AzPolicyAssignment
    #   call is scoped to exactly that level. Assignments are deduplicated by AssignmentId
    #   after all levels are collected, with the lowest (most specific) scope winning for
    #   the InheritanceLevel tag — but in practice Azure does not allow duplicate assignment
    #   names at different scopes, so deduplication is a safety net only.
    #
    #   Level order (highest to lowest):
    #       1. Management Groups  (full ancestor chain from tenant root down to sub's parent)
    #       2. Subscription
    #       3. Resource Group
    #       4. Resource

    $allRows     = [System.Collections.Generic.List[psobject]]::new()
    $chainLevels = [System.Collections.Generic.List[psobject]]::new()
    $seenIds     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # ── 1. Management Group hierarchy ────────────────────────────────────────

    Write-Host ""
    Write-Host "  Resolving Management Group hierarchy..." -ForegroundColor Cyan

    $mgScopes      = @()   # ordered from root down to immediate parent
    $mgAssessError = $false

    try
    {
        # Find the MG that directly contains this subscription
        $allMGs = @(Get-AzManagementGroup -ErrorAction Stop)

        # Walk up the parent chain by fetching each MG with -Expand -Recurse from root
        # Strategy: get the sub's parent MG first, then walk upward via ParentId
        # $subObj = Get-AzManagementGroupSubscription -GroupName "" -ErrorAction SilentlyContinue
        
        # Alternative: find which MG contains our subscription
        $parentMG = $null
        foreach ($mg in $allMGs)
        {
            try
            {
                $expanded = Get-AzManagementGroup -GroupName $mg.Name -Expand -Recurse -ErrorAction SilentlyContinue
                $subMatch = $expanded.Children | Where-Object {
                    $_.Type -eq "/subscriptions" -and $_.Name -eq $resourceSubId
                }
                if ($subMatch)
                {
                    $parentMG = $expanded
                    break
                }
            }
            catch { continue }
        }

        if ($parentMG)
        {
            # Build ancestor chain: walk up via ParentName until we reach tenant root (no parent)
            $ancestorChain = [System.Collections.Generic.List[psobject]]::new()
            $current = $parentMG

            while ($current)
            {
                $ancestorChain.Insert(0, $current)   # prepend so chain is root → leaf
                $parentId = $current.ParentId
                if ($parentId -and $parentId -notmatch '/providers/Microsoft\.Management/managementGroups/$')
                {
                    $parentName = $parentId -replace '.*/managementGroups/', ''
                    if ($parentName)
                    {
                        $current = Get-AzManagementGroup -GroupName $parentName -Expand -ErrorAction SilentlyContinue
                    }
                    else { $current = $null }
                }
                else { $current = $null }
            }

            foreach ($mg in $ancestorChain)
            {
                $mgScope = "/providers/Microsoft.Management/managementGroups/$($mg.Name)"
                $mgScopes += [pscustomobject]@{ Scope = $mgScope; DisplayName = $mg.DisplayName; Name = $mg.Name }
            }

            Write-Host "    MG chain: $(@($mgScopes | Select-Object -ExpandProperty DisplayName) -join ' -> ')" -ForegroundColor DarkGray
        }
        else
        {
            Write-Host "    Could not locate the Management Group containing subscription '$subscriptionName'." -ForegroundColor Yellow
            Write-Host "    MG-level policy assignments will not be assessed." -ForegroundColor Yellow
        }
    }
    catch
    {
        Write-Host "    MG traversal failed (likely missing Microsoft.Management/managementGroups/read)." -ForegroundColor Yellow
        Write-Host "    Reason: $($_.Exception.Message)" -ForegroundColor DarkGray
        Write-Host "    Continuing from Subscription scope downward." -ForegroundColor Yellow
        $mgAssessError = $true
    }

    # Collect assignments from each MG scope
    $mgTotalCount = 0
    $mgScopeNames = ""

    foreach ($mgScope in $mgScopes)
    {
        try
        {
            $mgAssignments = @(Get-AzPolicyAssignment -Scope $mgScope.Scope -ErrorAction Stop)
            foreach ($a in $mgAssignments)
            {
                $assignId = if ($null -ne $a.PSObject.Properties['PolicyAssignmentId']) { $a.PolicyAssignmentId } elseif ($null -ne $a.PSObject.Properties['Id']) { $a.Id } else { [guid]::NewGuid().ToString() }
                if ($seenIds.Add($assignId))
                {
                    $effect = Get-PolicyEffect -Assignment $a
                    $row    = New-PolicyRow `
                        -Assignment       $a `
                        -InheritanceLevel "Management Group" `
                        -InheritedFrom    $mgScope.Scope `
                        -ResourceInfo     $resourceInfo `
                        -Effect           $effect `
                        -ComplianceState  "Not Requested"
                    $allRows.Add($row)
                    $mgTotalCount++
                }
            }
            $mgScopeNames = if ($mgScopeNames) { "$mgScopeNames → $($mgScope.DisplayName)" } else { $mgScope.DisplayName }
        }
        catch
        {
            Write-Verbose "  Could not retrieve assignments from MG '$($mgScope.DisplayName)': $_"
        }
    }

    if ($mgAssessError -or $mgScopes.Count -eq 0)
    {
        $chainLevels.Add([pscustomobject]@{
            LevelName       = "Management Group"
            ScopeName       = if ($mgAssessError) { "Access denied" } else { "Not in any MG" }
            AssignmentCount = 0
            Status          = "Skipped"
            SkipReason      = if ($mgAssessError) { "Insufficient permissions (managementGroups/read)" } else { "Subscription not found in any MG" }
        })
    }
    else
    {
        $chainLevels.Add([pscustomobject]@{
            LevelName       = "Management Group"
            ScopeName       = $mgScopeNames
            AssignmentCount = $mgTotalCount
            Status          = "Assessed"
            SkipReason      = ""
        })
    }

    # ── 2. Subscription scope ─────────────────────────────────────────────────

    $subScope        = "/subscriptions/$resourceSubId"
    $subAssignCount  = 0
    $subScopeStatus  = "Assessed"
    $subSkipReason   = ""

    try
    {
        $subAssignments = @(Get-AzPolicyAssignment -Scope $subScope -ErrorAction Stop)

        # TEMPORARY DEBUG — remove after confirming property name
        # if ($subAssignments.Count -gt 0) {
        #     $subAssignments[0] | Get-Member -MemberType Properties | Select-Object Name | Write-Host
        # }

        foreach ($a in $subAssignments)
        {
            $assignId = if ($null -ne $a.PSObject.Properties['PolicyAssignmentId']) { $a.PolicyAssignmentId } elseif ($null -ne $a.PSObject.Properties['Id']) { $a.Id } else { [guid]::NewGuid().ToString() }
            if ($seenIds.Add($assignId))
            {
                $effect = Get-PolicyEffect -Assignment $a
                $row    = New-PolicyRow `
                    -Assignment       $a `
                    -InheritanceLevel "Subscription" `
                    -InheritedFrom    $subScope `
                    -ResourceInfo     $resourceInfo `
                    -Effect           $effect `
                    -ComplianceState  "Not Requested"
                $allRows.Add($row)
                $subAssignCount++
            }
        }
    }
    catch
    {
        Write-Host "  Subscription-scope assignment retrieval failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $subScopeStatus = "Error"
        $subSkipReason  = $_.Exception.Message
    }

    $chainLevels.Add([pscustomobject]@{
        LevelName       = "Subscription"
        ScopeName       = "$subscriptionName ($resourceSubId)"
        AssignmentCount = $subAssignCount
        Status          = $subScopeStatus
        SkipReason      = $subSkipReason
    })

    # ── 3. Resource Group scope ───────────────────────────────────────────────

    $rgScope       = "/subscriptions/$resourceSubId/resourceGroups/$($resource.ResourceGroupName)"
    $rgAssignCount = 0
    $rgScopeStatus = "Assessed"
    $rgSkipReason  = ""

    try
    {
        $rgAssignments = @(Get-AzPolicyAssignment -Scope $rgScope -ErrorAction Stop)
        foreach ($a in $rgAssignments)
        {
            $assignId = if ($null -ne $a.PSObject.Properties['PolicyAssignmentId']) { $a.PolicyAssignmentId } elseif ($null -ne $a.PSObject.Properties['Id']) { $a.Id } else { [guid]::NewGuid().ToString() }
            if ($seenIds.Add($assignId))
            {
                $effect = Get-PolicyEffect -Assignment $a
                $row    = New-PolicyRow `
                    -Assignment       $a `
                    -InheritanceLevel "Resource Group" `
                    -InheritedFrom    $rgScope `
                    -ResourceInfo     $resourceInfo `
                    -Effect           $effect `
                    -ComplianceState  "Not Requested"
                $allRows.Add($row)
                $rgAssignCount++
            }
        }
    }
    catch
    {
        Write-Host "  Resource Group scope assignment retrieval failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $rgScopeStatus = "Error"
        $rgSkipReason  = $_.Exception.Message
    }

    $chainLevels.Add([pscustomobject]@{
        LevelName       = "Resource Group"
        ScopeName       = $resource.ResourceGroupName
        AssignmentCount = $rgAssignCount
        Status          = $rgScopeStatus
        SkipReason      = $rgSkipReason
    })

    # ── 4. Resource scope ─────────────────────────────────────────────────────

    $resAssignCount = 0
    $resScopeStatus = "Assessed"
    $resSkipReason  = ""

    try
    {
        $resAssignments = @(Get-AzPolicyAssignment -Scope $resource.ResourceId -ErrorAction Stop)
        foreach ($a in $resAssignments)
        {
            $assignId = if ($null -ne $a.PSObject.Properties['PolicyAssignmentId']) { $a.PolicyAssignmentId } elseif ($null -ne $a.PSObject.Properties['Id']) { $a.Id } else { [guid]::NewGuid().ToString() }
            if ($seenIds.Add($assignId))
            {
                $effect = Get-PolicyEffect -Assignment $a
                $row    = New-PolicyRow `
                    -Assignment       $a `
                    -InheritanceLevel "Resource" `
                    -InheritedFrom    $resource.ResourceId `
                    -ResourceInfo     $resourceInfo `
                    -Effect           $effect `
                    -ComplianceState  "Not Requested"
                $allRows.Add($row)
                $resAssignCount++
            }
        }
    }
    catch
    {
        Write-Host "  Resource-scope assignment retrieval failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $resScopeStatus = "Error"
        $resSkipReason  = $_.Exception.Message
    }

    $chainLevels.Add([pscustomobject]@{
        LevelName       = "Resource"
        ScopeName       = $resource.Name
        AssignmentCount = $resAssignCount
        Status          = $resScopeStatus
        SkipReason      = $resSkipReason
    })

    #------------------------------------------------------------------------ [ Exemption check ]

    Write-Host ""
    Write-Host "  Checking existing exemptions at resource scope..." -ForegroundColor Cyan

    $existingExemptions = @{}

    try
    {
        $exemptions = @(Get-AzPolicyExemption -Scope $resource.ResourceId -ErrorAction Stop)
        foreach ($ex in $exemptions)
        {
            $exPaid  = ""
            $exExpiry = ""
            try
            {
                $exProps = $ex.Properties
                $exPaid  = if ($exProps.PolicyAssignmentId) { $exProps.PolicyAssignmentId } else { "" }
                if ($exProps.ExpiresOn)
                {
                    $daysLeft = ($exProps.ExpiresOn - (Get-Date)).Days
                    if ($daysLeft -ge 0) { $exExpiry = $exProps.ExpiresOn.ToString("yyyy-MM-dd HH:mm UTC") }
                    # Expired exemptions are not counted as active
                }
            }
            catch { }

            if ($exPaid -and $exExpiry)
            {
                $existingExemptions[$exPaid] = $exExpiry
            }
        }
        Write-Host "    Found $($existingExemptions.Count) active exemption(s) at resource scope." -ForegroundColor DarkGray
    }
    catch
    {
        Write-Host "    Exemption check failed (continuing): $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # ── Apply exemption status and risk to all rows ───────────────────────────
    foreach ($row in $allRows)
    {
        $hasExemption   = $existingExemptions.ContainsKey($row.PolicyAssignmentId)
        $exemptionExpiry = if ($hasExemption) { $existingExemptions[$row.PolicyAssignmentId] } else { "" }

        $row.ExemptionExists = if ($hasExemption) { "Yes" } else { "No" }
        $row.ExemptionExpiry = $exemptionExpiry

        $riskRec = Get-RiskAndRecommendation `
            -Effect           $row.Effect `
            -EnforcementMode  $row.EnforcementMode `
            -ComplianceState  $row.ComplianceState `
            -ExemptionExists  $hasExemption

        $row.RiskLevel                = $riskRec.Risk
        $row.ExemptionRecommendation  = $riskRec.Recommendation
    }

    #------------------------------------------------------------------------ [ Compliance state (optional) ]

    if ($IncludeComplianceState -and $allRows.Count -gt 0)
    {
        Write-Host ""
        Write-Host "  Retrieving compliance state for $($allRows.Count) assignment(s)..." -ForegroundColor Cyan

        try
        {
            $stateResults = @(Get-AzPolicyState -ResourceId $resource.ResourceId -ErrorAction Stop)

            foreach ($row in $allRows)
            {
                $match = $stateResults |
                    Where-Object { $_.PolicyAssignmentId -eq $row.PolicyAssignmentId } |
                    Select-Object -First 1

                if ($match)
                {
                    $row.ComplianceState        = $match.ComplianceState
                    $row.NonCompliantResources  = if ($match.ComplianceState -eq "NonCompliant") { 1 } else { 0 }
                }
                else
                {
                    $row.ComplianceState = "Compliant"
                }

                # Re-derive risk now that we have real compliance state
                $hasExemption = $row.ExemptionExists -eq "Yes"
                $riskRec = Get-RiskAndRecommendation `
                    -Effect          $row.Effect `
                    -EnforcementMode $row.EnforcementMode `
                    -ComplianceState $row.ComplianceState `
                    -ExemptionExists $hasExemption

                $row.RiskLevel               = $riskRec.Risk
                $row.ExemptionRecommendation = $riskRec.Recommendation
            }

            Write-Host "    Compliance state applied to all rows." -ForegroundColor Green
        }
        catch
        {
            Write-Host "    Get-AzPolicyState failed (missing PolicyInsights permission?): $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "    Compliance state will be shown as 'Not Assessed'." -ForegroundColor DarkGray
            foreach ($row in $allRows) { $row.ComplianceState = "Not Assessed" }
        }
    }

    #------------------------------------------------------------------------ [ Inheritance chain output ]

    Write-InheritanceChain -ChainLevels $chainLevels

    # ── Per-assignment console detail ─────────────────────────────────────────
    if ($allRows.Count -gt 0)
    {
        Write-Host ""
        Write-Host "  Effective Assignments ($($allRows.Count) total)" -ForegroundColor Cyan
        Write-Host "  " -NoNewline
        Write-Host ("-" * 76) -ForegroundColor DarkGray
        Write-Host ""

        $maxName = ($allRows | ForEach-Object { $_.PolicyAssignmentName.Length } | Measure-Object -Maximum).Maximum
        $maxName = [math]::Min([math]::Max($maxName, 30), 50)

        foreach ($row in ($allRows | Sort-Object InheritanceLevel, PolicyAssignmentName))
        {
            $riskColor = switch ($row.RiskLevel)
            {
                "High"   { "Red"    }
                "Medium" { "Yellow" }
                "Low"    { "Green"  }
                default  { "Gray"   }
            }

            $levelAbbr = switch ($row.InheritanceLevel)
            {
                "Management Group" { "MG " }
                "Subscription"     { "SUB" }
                "Resource Group"   { "RG " }
                "Resource"         { "RES" }
                default            { "   " }
            }

            $nameDisplay = if ($row.PolicyAssignmentName.Length -gt $maxName)
            {
                $row.PolicyAssignmentName.Substring(0, $maxName - 3) + "..."
            }
            else { $row.PolicyAssignmentName }

            Write-Host "  " -NoNewline
            Write-Host "[$levelAbbr] " -NoNewline -ForegroundColor DarkGray
            Write-Host $nameDisplay.PadRight($maxName) -NoNewline -ForegroundColor White
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-Host $row.Effect.PadRight(22) -NoNewline -ForegroundColor Gray
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-Host $row.RiskLevel.PadRight(7) -NoNewline -ForegroundColor $riskColor
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-Host $row.ExemptionRecommendation -ForegroundColor White
        }
    }
    else
    {
        Write-Host ""
        Write-Host "  No effective policy assignments found for this resource." -ForegroundColor Yellow
    }

    #------------------------------------------------------------------------ [ Summary ]

    $endTime     = Get-Date
    $duration    = $endTime - $startTime
    $durationStr = "{0:hh\:mm\:ss}" -f $duration

    $highCount    = @($allRows | Where-Object { $_.RiskLevel -eq "High"   }).Count
    $medCount     = @($allRows | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $lowCount     = @($allRows | Where-Object { $_.RiskLevel -eq "Low"    }).Count
    $needEx       = @($allRows | Where-Object { $_.ExemptionRecommendation -eq "Exemption Needed"  }).Count
    $reviewEx     = @($allRows | Where-Object { $_.ExemptionRecommendation -eq "Review Required"   }).Count
    $alreadyEx    = @($allRows | Where-Object { $_.ExemptionRecommendation -eq "Already Exempted"  }).Count

    Write-Summary -Data ([ordered]@{
        "Resource"                    = "$($resource.Name) ($($resource.ResourceType))"
        "Total Effective Assignments" = $allRows.Count
        "High Risk"                   = $highCount
        "Medium Risk"                 = $medCount
        "Low Risk"                    = $lowCount
        "Exemption Needed"            = $needEx
        "Review Required"             = $reviewEx
        "Already Exempted"            = $alreadyEx
        "Compliance State"            = if ($IncludeComplianceState) { "Assessed via Get-AzPolicyState" } else { "Not assessed (use -IncludeComplianceState)" }
        "Execution Time"              = $durationStr
    })

    #------------------------------------------------------------------------ [ Exemption Planner block ]

    $needExRows   = @($allRows | Where-Object { $_.ExemptionRecommendation -eq "Exemption Needed" })
    $plannerBlock = ""

    if ($needExRows.Count -gt 0)
    {
        $assignmentNames = $needExRows | ForEach-Object { "        `"$($_.PolicyAssignmentName)`"" }
        $joinedNames     = $assignmentNames -join ",`n"

        $plannerBlock = @"
# ── Exemption Planner ────────────────────────────────────────────────────────
# Generated by Get-AzureResourceEffectivePolicies v1.0
# Resource  : $($resource.Name)
# Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm UTC')
# Review each assignment below before running. Confirm justification,
# category (Waiver vs Mitigated), and minimum required duration.
# ─────────────────────────────────────────────────────────────────────────────

New-AzureKeyVaultPolicyExemption ``
    -KeyVaultNames @("$($resource.Name)") ``
    -PolicyAssignments @(
$joinedNames
    ) ``
    -Justification "<replace with your approved justification>" ``
    -ExemptionCategory Waiver ``
    -ExemptionDurationHours 4
"@
    }
    else
    {
        $plannerBlock = "# No assignments flagged as 'Exemption Needed' for $($resource.Name)."
    }

    #------------------------------------------------------------------------ [ Outputs ]

    $csvExported  = $false
    $htmlExported = $false
    $htmlPath     = [System.IO.Path]::ChangeExtension($CsvPath, '.html')

    # CSV
    if ($ExportToCsv -and $allRows.Count -gt 0)
    {
        try
        {
            $dir = Split-Path $CsvPath -Parent
            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $allRows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Force
            $csvExported = $true
        }
        catch
        {
            Write-Warning "CSV export failed: $_"
        }
    }

    # HTML report (always)
    try
    {
        $runParameters = @{
            ResourceType          = if ($ResourceType)      { $ResourceType }      else { "Not specified" }
            ResourceGroupName     = if ($ResourceGroupName) { $ResourceGroupName } else { "Not specified" }
            SubscriptionId        = if ($SubscriptionId)    { $SubscriptionId }    else { "Not specified" }
            IncludeComplianceState = if ($IncludeComplianceState) { "Enabled" } else { "Disabled (use -IncludeComplianceState)" }
        }

        $runSummary = @{
            ExecutionTime = $durationStr
        }

        $htmlContent = Generate-EffectivePoliciesHtml `
            -SessionInfo         $sessionInfo `
            -ResourceInfo        $resourceInfo `
            -RunParameters       $runParameters `
            -ChainLevels         $chainLevels `
            -AllRows             $allRows `
            -RunSummary          $runSummary `
            -HtmlPath            $htmlPath `
            -CsvPath             $(if ($csvExported) { $CsvPath } else { $null }) `
            -ExemptionPlannerBlock $plannerBlock

        $dir = Split-Path $htmlPath -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
        $htmlExported = $true
    }
    catch
    {
        Write-Warning "HTML report generation failed: $_"
    }

    if ($csvExported -or $htmlExported)
    {
        Write-OutputFiles `
            -CsvPath  $(if ($csvExported)  { $CsvPath  } else { $null }) `
            -HtmlPath $(if ($htmlExported) { $htmlPath } else { $null })
    }
    else
    {
        Write-Host ""
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}


#------------------------------------------------------------------------ [ Private helpers used inside the main function ]
#  Defined after the main function so they are in scope when the module is dot-sourced.
#  In a standalone .ps1 these must be defined BEFORE the main function body executes;
#  move these above Get-AzureResourceEffectivePolicies if dot-sourcing in PS 5.1.

Function Get-PolicyEffect
{
    <#
    .SYNOPSIS
        Best-effort extraction of the policy Effect from an assignment's parameters
        or from the underlying definition's policyRule. Returns "Unknown" if neither
        source yields a value.
    #>
    param([object]$Assignment)

    # Try parameter override first
    try
    {
        $effectParam = if ($Assignment.Parameter.effect)              { $Assignment.Parameter.effect } `
                       elseif ($Assignment.Properties.Parameters.effect.value) { $Assignment.Properties.Parameters.effect.value } `
                       else                                            { $null }
        if ($effectParam) { return "$effectParam" }
    }
    catch { }

    # Try policy definition policyRule
    try
    {
        $defId = if ($null -ne $Assignment.PSObject.Properties['PolicyDefinitionId']) { $Assignment.PolicyDefinitionId } else { "" }

        if ($defId -and $defId -notmatch 'policySetDefinitions')
        {
            $def = Get-AzPolicyDefinition -Id $defId -ErrorAction SilentlyContinue
            if ($def)
            {
                $rule = $def.Properties.PolicyRule | ConvertTo-Json -Depth 10 | ConvertFrom-Json -ErrorAction SilentlyContinue
                $effect = $rule.then.effect
                if ($effect) { return "$effect" }
            }
        }
    }
    catch { }

    return "Unknown"
}

Function New-PolicyRow
{
    <#
    .SYNOPSIS
        Constructs a single flat result row for a policy assignment.
        ExemptionExists, ExemptionExpiry, RiskLevel, and ExemptionRecommendation
        are set to placeholder values here and filled in after the exemption check.
    #>
    param(
        [object]$Assignment,
        [string]$InheritanceLevel,
        [string]$InheritedFrom,
        [hashtable]$ResourceInfo,
        [string]$Effect,
        [string]$ComplianceState
    )

    $enfMode     = if ($Assignment.EnforcementMode) { $Assignment.EnforcementMode } else { "Default" }
    $displayName = if ($Assignment.DisplayName) { $Assignment.DisplayName } elseif ($Assignment.Name) { $Assignment.Name } else { "Unknown" }
    $polType     = if ($Assignment.PolicyDefinitionId -and $Assignment.PolicyDefinitionId -like "*/providers/Microsoft.Authorization/policyDefinitions/*") { "Built-in" } else { "Custom/Initiative" }

    # Check if the definition ID indicates an initiative (set)
    if ($Assignment.PolicyDefinitionId -like "*policySetDefinitions*") { $polType = "Initiative" }

    return [pscustomobject]@{
        ResourceName              = $ResourceInfo.Name
        ResourceId                = $ResourceInfo.ResourceId
        ResourceType              = $ResourceInfo.Type
        ResourceGroup             = $ResourceInfo.ResourceGroup
        SubscriptionName          = $ResourceInfo.SubscriptionName
        InheritanceLevel          = $InheritanceLevel
        InheritedFrom             = $InheritedFrom
        PolicyAssignmentName      = $displayName
        PolicyAssignmentId        = if ($null -ne $Assignment.PSObject.Properties['PolicyAssignmentId']) { $Assignment.PolicyAssignmentId } elseif ($null -ne $Assignment.PSObject.Properties['Id']) { $Assignment.Id } else { "" }
        PolicyDefinitionId        = if ($Assignment.PolicyDefinitionId) { $Assignment.PolicyDefinitionId } else { "" }
        PolicyType                = $polType
        Effect                    = $Effect
        EnforcementMode           = $enfMode
        ExemptionExists           = "No"       # filled after exemption check
        ExemptionExpiry           = ""         # filled after exemption check
        ComplianceState           = $ComplianceState
        NonCompliantResources     = 0
        RiskLevel                 = "Low"      # filled after exemption check
        ExemptionRecommendation   = "No Action Needed"  # filled after exemption check
    }
}
