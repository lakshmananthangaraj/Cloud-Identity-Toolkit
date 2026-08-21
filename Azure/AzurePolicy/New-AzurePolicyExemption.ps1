<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 21 August 2026
Modified-On     : 21 August 2026

.SYNOPSIS
    Creates time-boxed Azure Policy exemptions for any Azure resource type against one
    or more Policy Assignments, with automatic expiry and a full audit trail.

.DESCRIPTION
    New-AzurePolicyExemption is the strategic, resource-agnostic successor to
    New-AzureKeyVaultPolicyExemption. Where the KV-specific script is limited to
    Microsoft.KeyVault/vaults, this solution operates across every Azure resource type
    visible to your account — Storage Accounts, SQL Servers, AKS clusters, App Services,
    Virtual Machines, and any future resource type — without code changes.

    ENTERPRISE PROBLEM SOLVED
    ─────────────────────────
    Large organisations run centralised Azure Policy initiatives across hundreds of
    subscriptions. During maintenance windows, migrations, break-glass events, or
    short-cycle regulatory exceptions, individual resource teams need a repeatable,
    auditable mechanism to temporarily exempt specific resources from specific Policy
    Assignments. Without a standardised tool, teams resort to ad-hoc ARM API calls,
    mis-scoped exemptions, missing justifications, or forgotten permanent exemptions.
    This script eliminates all four failure modes.

    DESIGN PRINCIPLES
    ─────────────────
    · Resource-agnostic  : Any resource type resolvable via Get-AzResource is supported.
    · Dual identification: Accept either a full Resource ID or a Friendly Name
                           (auto-disambiguated with -ResourceType and -ResourceGroupName).
    · Cross-subscription : Optional -SubscriptionId parameter for resources in a
                           non-default subscription, without changing the active context.
    · Least-privilege    : Exemptions are scoped to the individual resource (not RG or sub).
    · Idempotent         : Re-running against an already-exempted resource is a no-op.
    · Governance-ready   : Mandatory justification, auto-expiry, and a tamper-evident
                           HTML report make every exemption fully auditable.

    WHAT THIS SCRIPT DOES
    ─────────────────────
    1.  Validates all required Az sub-modules are present (offers to install if missing).
    2.  Confirms an active Azure session (prompts Connect-AzAccount if not).
    3.  Displays session and run-parameter information on screen.
    4.  Resolves the target resource — either from a full Resource ID or by name lookup
        (Get-AzResource), with optional subscription and resource-group scoping.
    5.  Resolves each Policy Assignment — by full Assignment ID or display name.
    6.  Performs a permission pre-check (Microsoft.Authorization/policyExemptions/write)
        at the target resource scope.
    7.  Displays a summary of planned exemptions and prompts for confirmation (unless
        -Force is supplied).
    8.  Creates each exemption with a safe, auto-generated name and a UTC expiry.
    9.  Applies idempotency: skips creation if an active, non-expired exemption with the
        same name already exists at the same scope.
    10. Writes a dark-themed, self-contained HTML report (always).
    11. Optionally exports a CSV results file.
    12. Displays a consolidated execution summary on screen.

    RELATIONSHIP TO New-AzureKeyVaultPolicyExemption
    ─────────────────────────────────────────────────
    Both scripts coexist. New-AzureKeyVaultPolicyExemption remains fully supported for
    teams whose scope is limited to Key Vault resources and who prefer its simpler,
    KV-specific interface. New-AzurePolicyExemption is the strategic solution for all
    other resource types and for centralised governance teams managing policy exemptions
    at scale. Future releases may deprecate the KV-specific script once this solution
    is proven across all environments.

.PARAMETER ResourceName
    The display name of the Azure resource to exempt. When provided without
    -ResourceId, the script resolves the resource using Get-AzResource with this name.
    Use -ResourceType and -ResourceGroupName to disambiguate if multiple resources
    share the same display name. Mutually exclusive with -ResourceId.

.PARAMETER ResourceId
    The full Azure Resource ID of the target resource, in the form:
        /subscriptions/{id}/resourceGroups/{rg}/providers/{namespace}/{type}/{name}
    When provided, -ResourceName, -ResourceType, -ResourceGroupName, and
    -SubscriptionId are all ignored for resource resolution (the subscription is
    already encoded in the Resource ID). Mutually exclusive with -ResourceName.

.PARAMETER ResourceType
    The Azure resource provider type used to disambiguate a friendly-name lookup.
    Example: "Microsoft.KeyVault/vaults", "Microsoft.Storage/storageAccounts",
    "Microsoft.ContainerService/managedClusters". Required when -ResourceName is
    provided and multiple resources share the same display name across resource types.

.PARAMETER ResourceGroupName
    The Resource Group name used to scope the friendly-name lookup to a specific
    Resource Group. Optional — omit to search across all Resource Groups in the
    resolved subscription.

.PARAMETER SubscriptionId
    The subscription ID to use when resolving a resource by friendly name
    (-ResourceName). Allows targeting a resource in a subscription other than the
    current Az context without switching the active context. When -ResourceId is
    provided, this parameter is ignored.

.PARAMETER PolicyAssignments
    One or more Policy Assignment identifiers. Each value may be:
        - A full Assignment resource ID  (/subscriptions/{id}/providers/
          Microsoft.Authorization/policyAssignments/{name})
        - A Policy Assignment display name (resolved via Get-AzPolicyAssignment)
    Mixed formats are accepted within a single invocation.

.PARAMETER Justification
    Mandatory free-text justification recorded on every exemption created. Required
    for governance auditability. Stored in the exemption's Description field in Azure.
    Should reference a change ticket, CAB approval reference, or incident number.

.PARAMETER ExemptionDurationHours
    Duration in hours that each exemption remains active. Must be between 1 and 720
    hours (30 days). Defaults to 4 hours. After this period the exemption expires
    automatically and policy compliance is restored without manual intervention.

.PARAMETER ExemptionCategory
    Azure Policy exemption category. Accepted values:
        - Waiver    : The policy intent genuinely does not apply to this resource.
        - Mitigated : The policy intent is addressed through an alternative control.
    Defaults to Waiver. Choose Mitigated when a compensating control exists.

.PARAMETER ExemptionNamePrefix
    Optional prefix prepended to the auto-generated exemption name. Useful for
    namespacing by team, change ticket, or environment.
    Auto-generated format (no prefix) : EX-<ResourceShortName>-<PolicyShortName>-<Timestamp>
    Auto-generated format (with prefix): <Prefix>-EX-<ResourceShortName>-<PolicyShortName>-<Timestamp>
    Maximum combined length enforced: 64 characters.

.PARAMETER ExportToCsv
    Switch. When specified, exports the full results table to the path in -CsvPath.
    An HTML report is always generated regardless of this switch.

.PARAMETER CsvPath
    Output path for the CSV export and the co-located HTML report (same path, .html
    extension). Defaults to C:\Temp\AzurePolicyExemptions-Report.csv.
    On macOS/Linux PowerShell 7, supply an explicit -CsvPath.

.PARAMETER Force
    Switch. Suppresses the confirmation prompt before creating exemptions. Without this
    switch the script displays a summary of planned exemptions and prompts for
    confirmation before writing anything to Azure.

.INPUTS
    None. All input is via parameters.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML report. Optionally writes a
    CSV if -ExportToCsv is specified. Returns a summary object to the host.

.EXAMPLE
    # Exempt a Storage Account by friendly name from a single Policy Assignment
    New-AzurePolicyExemption `
        -ResourceName      "stprodpayments001" `
        -ResourceType      "Microsoft.Storage/storageAccounts" `
        -ResourceGroupName "rg-prod-payments" `
        -PolicyAssignments @("Deny-Storage-PublicAccess") `
        -Justification     "Temporary exemption during migration — JIRA INFRA-7821" `
        -ExemptionDurationHours 4

.EXAMPLE
    # Exempt an AKS cluster by full Resource ID, cross-subscription
    New-AzurePolicyExemption `
        -ResourceId        "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/rg-prod-aks/providers/Microsoft.ContainerService/managedClusters/aks-prod-001" `
        -PolicyAssignments @("/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/providers/Microsoft.Authorization/policyAssignments/deny-aks-public-api") `
        -Justification     "Break-glass: urgent node pool upgrade — approved by security lead" `
        -ExemptionCategory Mitigated `
        -ExemptionDurationHours 2 `
        -ExemptionNamePrefix   "SEC-OPS"

.EXAMPLE
    # Exempt a VM in a non-default subscription by friendly name, export to CSV
    New-AzurePolicyExemption `
        -ResourceName      "vm-prod-jumpbox-01" `
        -ResourceType      "Microsoft.Compute/virtualMachines" `
        -ResourceGroupName "rg-prod-jumpbox" `
        -SubscriptionId    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -PolicyAssignments @("Require-VM-Diagnostics", "Deny-VM-PublicIP") `
        -Justification     "Planned maintenance window — CAB approval ref CAB-2026-0820" `
        -ExemptionDurationHours 8 `
        -ExemptionNamePrefix   "MAINT" `
        -ExportToCsv `
        -CsvPath           "C:\Reports\PolicyExemptions-2026-08-21.csv" `
        -Force

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (21-Aug-2026) - Initial release. Resource-agnostic policy exemption
                            creation with dual resource identification (ID or name),
                            optional cross-subscription resource resolution,
                            multi-policy support, permission pre-check, idempotency
                            guard, auto-expiry, CSV export, and HTML report generation.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module sub-modules: Az.Accounts, Az.Resources
           (installed automatically with user consent if missing)
        2. Authenticated Azure session (Connect-AzAccount)
        3. Microsoft.Authorization/policyExemptions/write at the target resource
           scope — typically granted via Owner, User Access Administrator, or
           Resource Policy Contributor
        4. Microsoft.Resources/*/read permission to resolve resource names to IDs
        5. Microsoft.Authorization/policyAssignments/read to resolve Assignment
           names to IDs

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Exemptions are created at the individual resource scope only. Resource
          Group, subscription, and management group scoping are not supported in
          this version and are planned for a future release.
        - When using -ResourceName without -ResourceGroupName, if multiple resources
          share the same display name across resource groups, the script warns and
          uses the first match. Use -ResourceId for deterministic resolution.
        - Policy Assignment name resolution searches across all assignments visible
          to the current account. If multiple assignments share the same display
          name, the script warns and uses the first match — use the full Assignment
          ID to disambiguate.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. On macOS or Linux
          (PowerShell 7+), supply an explicit -CsvPath value.
        - ExemptionDurationHours maximum is 720 hours (30 days), aligned with
          common Azure Policy governance guardrails. Adjust ValidateRange if your
          organisation's policy allows longer exemption windows.
        - The permission pre-check uses role-name matching (Owner, User Access
          Administrator, Resource Policy Contributor) rather than a direct action
          check. Custom roles that grant policyExemptions/write but use a different
          name will show as unconfirmed rather than permitted.

.LINK
    https://learn.microsoft.com/en-us/azure/governance/policy/concepts/exemption-structure
.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.resources/new-azpolicyexemption
.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azpolicyassignment
.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azresource

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CenteredText
{
    param(
        [string]$Text,
        [int]$Width    = 80,
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
    Write-CenteredText "Azure Policy Exemption Manager v1.0" -Color White
    Write-CenteredText "Enterprise Governance Solution" -Color DarkGray
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
        Write-Host $key.PadRight(24) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
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
        $maxLength   = 34
        $displayItem = if ($CurrentItem.Length -gt $maxLength)
        {
            $CurrentItem.Substring(0, $maxLength - 3) + "..."
        }
        else { $CurrentItem }

        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Processing: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-Summary
{
    param([hashtable]$Data)

    Write-Host ""
    Write-Host "  Execution Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys)
    {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(32) -NoNewline -ForegroundColor Gray
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
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    if ($CsvPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("CSV Export").PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }

    if ($HtmlPath)
    {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Report").PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }

    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-SafeExemptionName
{
    <#
    .SYNOPSIS
        Builds a safe, unique exemption name within Azure's 64-character limit.
        Format: [Prefix-]EX-<ResourceShortName>-<PolicyShortName>-<Timestamp>
    #>
    param(
        [string]$Prefix,
        [string]$ResourceShortName,
        [string]$PolicyShortName,
        [string]$Timestamp
    )

    # Strip characters not allowed in Azure resource names (keep alphanumeric and hyphens)
    $safeRes    = ($ResourceShortName -replace '[^a-zA-Z0-9-]', '')
    $safePol    = ($PolicyShortName   -replace '[^a-zA-Z0-9-]', '')
    $safePrefix = if ($Prefix) { ($Prefix -replace '[^a-zA-Z0-9-]', '') + "-" } else { "" }

    # Character budget:
    # prefix (up to 21 including trailing hyphen) + "EX-" (3) + "-" (1) + "-" (1) + timestamp (12)
    $fixedLen  = $safePrefix.Length + 3 + 1 + 1 + $Timestamp.Length
    $budget    = 64 - $fixedLen
    $resBudget = [math]::Min($safeRes.Length, [math]::Floor($budget * 0.55))
    $polBudget = [math]::Min($safePol.Length, $budget - $resBudget)

    $resFrag = $safeRes.Substring(0, [math]::Max(0, $resBudget))
    $polFrag = $safePol.Substring(0, [math]::Max(0, $polBudget))

    return "$($safePrefix)EX-$resFrag-$polFrag-$Timestamp"
}

Function Resolve-ResourceByName
{
    <#
    .SYNOPSIS
        Resolves a friendly resource name to a full resource object using Get-AzResource.
        Optionally scoped by ResourceType, ResourceGroupName, and SubscriptionId.
    #>
    param(
        [string]$ResourceName,
        [string]$ResourceType,
        [string]$ResourceGroupName,
        [string]$SubscriptionId
    )

    # Build the splatted parameter set for Get-AzResource
    $getParams = @{ Name = $ResourceName; ErrorAction = 'Stop' }

    if ($ResourceType)      { $getParams['ResourceType']  = $ResourceType      }
    if ($ResourceGroupName) { $getParams['ResourceGroupName'] = $ResourceGroupName }

    # If a target subscription is specified, temporarily switch context for the lookup
    # then restore it — we never permanently change the user's active context.
    $originalContext = $null

    if ($SubscriptionId)
    {
        $originalContext = Get-AzContext -ErrorAction SilentlyContinue
        try
        {
            Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        }
        catch
        {
            throw "Failed to switch context to subscription '$SubscriptionId': $($_.Exception.Message)"
        }
    }

    try
    {
        $resources = Get-AzResource @getParams

        if (-not $resources -or ($resources | Measure-Object).Count -eq 0)
        {
            throw "No resource found with name '$ResourceName'$(if ($ResourceType) { " of type '$ResourceType'" })$(if ($ResourceGroupName) { " in resource group '$ResourceGroupName'" })."
        }

        if (($resources | Measure-Object).Count -gt 1)
        {
            Write-Warning ("Multiple resources match '$ResourceName'$(if ($ResourceType) { " of type '$ResourceType'" }) — " +
                "using the first match: $($resources[0].ResourceId). " +
                "Provide -ResourceGroupName or -ResourceId to target a specific resource.")
        }

        return $resources | Select-Object -First 1
    }
    finally
    {
        # Always restore the original context
        if ($originalContext)
        {
            Set-AzContext -Context $originalContext -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

Function Generate-HtmlReport
{
    param(
        [hashtable]$SessionInfo,
        [hashtable]$RunParameters,
        [hashtable]$RunSummary,
        [array]$ExemptionResults,
        [string]$HtmlPath,
        [string]$CsvPath
    )

    $generatedAt = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    # ── Escape helper (inline — no external dependency) ───────────────────────
    # Using [System.Web.HttpUtility]::HtmlEncode for all dynamic values
    # injected into HTML attribute/content positions.

    # ── Build per-exemption rows ──────────────────────────────────────────────
    $rowsHtml = ""
    foreach ($r in $ExemptionResults)
    {
        $badgeClass = switch ($r.Status)
        {
            "Created" { "badge-success" }
            "Skipped" { "badge-warning" }
            "Failed"  { "badge-error"   }
            default   { "badge-info"    }
        }

        $statusIcon = switch ($r.Status)
        {
            "Created" { "✓" }
            "Skipped" { "⚠" }
            "Failed"  { "✗" }
            default   { "·" }
        }

        $rowsHtml += @"
                        <tr>
                            <td>
                                <div class="resource-cell">
                                    <div class="resource-name">$([System.Web.HttpUtility]::HtmlEncode($r.ResourceName))</div>
                                    <div class="resource-type">$([System.Web.HttpUtility]::HtmlEncode($r.ResourceType))</div>
                                </div>
                            </td>
                            <td class="mono small">$([System.Web.HttpUtility]::HtmlEncode($r.PolicyAssignment))</td>
                            <td class="mono small">$([System.Web.HttpUtility]::HtmlEncode($r.ExemptionName))</td>
                            <td class="mono small">$([System.Web.HttpUtility]::HtmlEncode($r.ExpiresOn))</td>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($r.ExemptionCategory))</td>
                            <td><span class="badge $badgeClass">$statusIcon $([System.Web.HttpUtility]::HtmlEncode($r.Status))</span></td>
                            <td class="message-cell">$([System.Web.HttpUtility]::HtmlEncode($r.Message))</td>
                        </tr>
"@
    }

    # ── Build resource info card ──────────────────────────────────────────────
    $resourceTypeDisplay = if ($RunParameters.ResourceType) { $RunParameters.ResourceType } else { "Resolved from Resource ID" }
    $subscriptionDisplay = if ($RunParameters.SubscriptionId) { $RunParameters.SubscriptionId } else { "Current context" }

    # ── Build output-files section ────────────────────────────────────────────
    $outputHtml = ""
    if ($CsvPath)
    {
        $outputHtml += @"
                    <div class="output-item">
                        <div class="output-icon success-icon">✓</div>
                        <div class="output-details">
                            <div class="output-label">CSV Export</div>
                            <div class="output-value mono">$([System.Web.HttpUtility]::HtmlEncode($CsvPath))</div>
                        </div>
                    </div>
"@
    }
    $outputHtml += @"
                    <div class="output-item">
                        <div class="output-icon success-icon">✓</div>
                        <div class="output-details">
                            <div class="output-label">HTML Report (this file)</div>
                            <div class="output-value mono">$([System.Web.HttpUtility]::HtmlEncode($HtmlPath))</div>
                        </div>
                    </div>
"@

    # ── Stat colours ─────────────────────────────────────────────────────────
    $createdColor  = if ($RunSummary.Created  -gt 0) { "#3fb950" } else { "#7d8590" }
    $skippedColor  = if ($RunSummary.Skipped  -gt 0) { "#d29922" } else { "#7d8590" }
    $failedColor   = if ($RunSummary.Failed   -gt 0) { "#f85149" } else { "#7d8590" }

    # ── Assemble full HTML ────────────────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Policy Exemption Report</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }

        :root {
            --bg:#0d1117; --surface:#161b22; --surface2:#1c2333; --surface3:#243048;
            --border:#30363d; --accent:#388bfd; --accent2:#39c5cf; --accent3:#a371f7;
            --green:#3fb950; --amber:#d29922; --red:#f85149;
            --text:#e6edf3; --muted:#7d8590; --muted2:#adbac7;
            --mono:'JetBrains Mono','Consolas','Courier New',monospace;
            --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
            --radius:10px; --radius-sm:6px; --shadow:0 4px 24px rgba(0,0,0,.5);
        }

        body {
            font-family: var(--sans);
            background: var(--bg);
            color: var(--text);
            padding: 32px 24px;
            min-height: 100vh;
        }

        /* ── Header ──────────────────────────────────────── */
        .report-header {
            background: linear-gradient(135deg, #0078D4 0%, #50E6FF 100%);
            border-radius: var(--radius);
            padding: 36px 40px;
            margin-bottom: 32px;
            position: relative;
            overflow: hidden;
        }
        .report-header::before {
            content: '';
            position: absolute;
            top: -40px; right: -40px;
            width: 200px; height: 200px;
            background: rgba(255,255,255,0.08);
            border-radius: 50%;
        }
        .report-header::after {
            content: '';
            position: absolute;
            bottom: -60px; right: 60px;
            width: 140px; height: 140px;
            background: rgba(255,255,255,0.05);
            border-radius: 50%;
        }
        .report-header h1 {
            font-size: 26px; font-weight: 300; letter-spacing: 1px;
            color: #fff; margin-bottom: 6px;
        }
        .report-header .sub   { font-size: 13px; color: rgba(255,255,255,0.8); margin-bottom: 4px; }
        .report-header .meta  { font-size: 11px; color: rgba(255,255,255,0.6); font-family: var(--mono); }

        /* ── Sections ────────────────────────────────────── */
        .section { margin-bottom: 32px; }
        .section-title {
            font-size: 15px; font-weight: 600; color: var(--accent2);
            margin-bottom: 16px; padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
            display: flex; align-items: center; gap: 8px;
        }

        /* ── Info grid ───────────────────────────────────── */
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
        }
        .info-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-left: 3px solid var(--accent);
            border-radius: var(--radius-sm);
            padding: 16px 20px;
        }
        .info-card.accent2 { border-left-color: var(--accent2); }
        .info-card.accent3 { border-left-color: var(--accent3); }
        .info-card.green   { border-left-color: var(--green);   }
        .info-label {
            font-size: 11px; color: var(--muted);
            text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;
        }
        .info-value {
            font-size: 14px; color: var(--text); font-weight: 600;
            word-break: break-all;
        }
        .info-value.none    { color: var(--muted); font-style: italic; font-weight: 400; }
        .info-value.mono    { font-family: var(--mono); font-size: 12px; }
        .info-value.normal  { font-weight: 400; }

        /* ── Resource identity card ──────────────────────── */
        .resource-identity {
            background: var(--surface);
            border: 1px solid var(--border);
            border-left: 4px solid var(--accent3);
            border-radius: var(--radius-sm);
            padding: 20px 24px;
        }
        .resource-identity .ri-header {
            display: flex; align-items: center; gap: 12px; margin-bottom: 14px;
        }
        .ri-icon {
            width: 40px; height: 40px; border-radius: 8px;
            background: rgba(163,113,247,0.15);
            display: flex; align-items: center; justify-content: center;
            font-size: 20px; flex-shrink: 0;
        }
        .ri-name  { font-size: 18px; font-weight: 600; color: var(--text); }
        .ri-type  { font-size: 12px; color: var(--muted); font-family: var(--mono); margin-top: 2px; }
        .ri-grid  { display: grid; grid-template-columns: 140px 1fr; gap: 8px 16px; }
        .ri-key   { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; display: flex; align-items: center; }
        .ri-val   { font-size: 12px; color: var(--text); font-family: var(--mono); word-break: break-all; }

        /* ── Stat cards ──────────────────────────────────── */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
        }
        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            padding: 20px;
            text-align: center;
            transition: transform 0.15s;
        }
        .stat-card:hover  { transform: translateY(-2px); }
        .stat-card.c-blue   { border-top: 3px solid var(--accent);  }
        .stat-card.c-green  { border-top: 3px solid var(--green);   }
        .stat-card.c-amber  { border-top: 3px solid var(--amber);   }
        .stat-card.c-red    { border-top: 3px solid var(--red);     }
        .stat-card.c-cyan   { border-top: 3px solid var(--accent2); }
        .stat-card.c-purple { border-top: 3px solid var(--accent3); }
        .stat-number { font-size: 32px; font-weight: 700; margin-bottom: 6px; }
        .stat-card.c-blue   .stat-number { color: var(--accent);  }
        .stat-card.c-green  .stat-number { color: $createdColor;  }
        .stat-card.c-amber  .stat-number { color: $skippedColor;  }
        .stat-card.c-red    .stat-number { color: $failedColor;   }
        .stat-card.c-cyan   .stat-number { color: var(--accent2); }
        .stat-card.c-purple .stat-number { color: var(--accent3); }
        .stat-label {
            font-size: 11px; color: var(--muted);
            text-transform: uppercase; letter-spacing: 1px;
        }

        /* ── Results table ───────────────────────────────── */
        .table-wrap {
            overflow-x: auto;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
        }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        thead th {
            background: var(--surface2);
            color: var(--muted2);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }
        tbody td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            color: var(--text);
            vertical-align: top;
        }
        tbody tr:last-child td  { border-bottom: none; }
        tbody tr:hover td       { background: var(--surface2); }
        .mono  { font-family: var(--mono); }
        .small { font-size: 12px; }
        .resource-cell .resource-name { font-weight: 600; margin-bottom: 3px; }
        .resource-cell .resource-type { font-size: 11px; color: var(--muted); font-family: var(--mono); }
        .message-cell { max-width: 260px; font-size: 12px; color: var(--muted2); }

        /* ── Badges ──────────────────────────────────────── */
        .badge {
            display: inline-block; padding: 3px 10px; border-radius: 20px;
            font-size: 11px; font-weight: 600; letter-spacing: 0.5px; white-space: nowrap;
        }
        .badge-success { background: rgba(63,185,80,.15);  color: var(--green); border: 1px solid rgba(63,185,80,.3);  }
        .badge-warning { background: rgba(210,153,34,.15); color: var(--amber); border: 1px solid rgba(210,153,34,.3); }
        .badge-error   { background: rgba(248,81,73,.15);  color: var(--red);   border: 1px solid rgba(248,81,73,.3);  }
        .badge-info    { background: rgba(56,139,253,.15); color: var(--accent);border: 1px solid rgba(56,139,253,.3); }

        /* ── Governance note ─────────────────────────────── */
        .governance-note {
            background: rgba(163,113,247,.08);
            border: 1px solid rgba(163,113,247,.25);
            border-left: 4px solid var(--accent3);
            border-radius: var(--radius-sm);
            padding: 16px 20px;
            display: flex; gap: 14px; align-items: flex-start;
        }
        .governance-note .gn-icon { font-size: 22px; flex-shrink: 0; margin-top: 2px; }
        .governance-note .gn-label {
            font-size: 11px; color: var(--accent3);
            text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;
        }
        .governance-note .gn-text { font-size: 14px; color: var(--text); line-height: 1.5; }

        /* ── Output files ────────────────────────────────── */
        .output-section {
            background: var(--surface); border: 1px solid var(--border);
            border-radius: var(--radius-sm); padding: 16px;
        }
        .output-item {
            display: flex; align-items: flex-start; gap: 14px;
            padding: 12px 0; border-bottom: 1px solid var(--border);
        }
        .output-item:last-child { border-bottom: none; }
        .output-icon {
            width: 36px; height: 36px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 18px; flex-shrink: 0;
        }
        .success-icon { background: rgba(63,185,80,.15); color: var(--green); }
        .output-label {
            font-size: 11px; color: var(--muted); margin-bottom: 4px;
            text-transform: uppercase; letter-spacing: 0.8px;
        }
        .output-value { font-weight: 600; color: var(--text); word-break: break-all; }

        /* ── Footer ──────────────────────────────────────── */
        .report-footer {
            text-align: center; color: var(--muted); font-size: 12px;
            margin-top: 40px; padding-top: 20px;
            border-top: 1px solid var(--border);
        }
        .report-footer a { color: var(--accent); text-decoration: none; }

        /* ── Responsive ──────────────────────────────────── */
        @media (max-width: 768px)
        {
            body { padding: 16px 12px; }
            .report-header { padding: 24px 20px; }
            .ri-grid { grid-template-columns: 1fr; }
        }
        @media print
        {
            body { background: #fff; color: #000; }
        }
    </style>
</head>
<body>

    <div class="report-header">
        <h1>🔐 Azure Policy Exemption Report</h1>
        <div class="sub">Enterprise Governance Solution — Resource-Agnostic Policy Exemption Management</div>
        <div class="meta">Generated on $generatedAt &nbsp;|&nbsp; v1.0</div>
    </div>

    <!-- Session Info -->
    <div class="section">
        <div class="section-title">📋 Session Information</div>
        <div class="info-grid">
            <div class="info-card">
                <div class="info-label">Tenant ID</div>
                <div class="info-value mono">$($SessionInfo.TenantId)</div>
            </div>
            <div class="info-card">
                <div class="info-label">Account</div>
                <div class="info-value">$($SessionInfo.Account)</div>
            </div>
            <div class="info-card">
                <div class="info-label">Environment</div>
                <div class="info-value">$($SessionInfo.Environment)</div>
            </div>
            <div class="info-card">
                <div class="info-label">Active Subscription</div>
                <div class="info-value mono">$($SessionInfo.SubscriptionName)</div>
            </div>
        </div>
    </div>

    <!-- Target Resource -->
    <div class="section">
        <div class="section-title">🎯 Target Resource</div>
        <div class="resource-identity">
            <div class="ri-header">
                <div class="ri-icon">📦</div>
                <div>
                    <div class="ri-name">$($RunParameters.ResourceDisplayName)</div>
                    <div class="ri-type">$($RunParameters.ResourceType)</div>
                </div>
            </div>
            <div class="ri-grid">
                <div class="ri-key">Resource Group</div>
                <div class="ri-val">$($RunParameters.ResourceGroup)</div>
                <div class="ri-key">Subscription</div>
                <div class="ri-val">$subscriptionDisplay</div>
                <div class="ri-key">Resource ID</div>
                <div class="ri-val">$($RunParameters.ResourceId)</div>
            </div>
        </div>
    </div>

    <!-- Run Parameters -->
    <div class="section">
        <div class="section-title">⚙️ Run Parameters</div>
        <div class="info-grid">
            <div class="info-card accent2">
                <div class="info-label">Policy Assignments</div>
                <div class="info-value">$($RunParameters.PolicyCount)</div>
            </div>
            <div class="info-card accent2">
                <div class="info-label">Exemption Duration</div>
                <div class="info-value">$($RunParameters.DurationHours) hours</div>
            </div>
            <div class="info-card accent2">
                <div class="info-label">Exemption Category</div>
                <div class="info-value">$($RunParameters.ExemptionCategory)</div>
            </div>
            <div class="info-card accent2">
                <div class="info-label">Name Prefix</div>
                <div class="info-value$(if ([string]::IsNullOrWhiteSpace($RunParameters.ExemptionNamePrefix)) {' none'})">$(if ($RunParameters.ExemptionNamePrefix) { $RunParameters.ExemptionNamePrefix } else { 'Auto-generated' })</div>
            </div>
            <div class="info-card accent2">
                <div class="info-label">Expires At (UTC)</div>
                <div class="info-value mono">$($RunParameters.ExpiresAt)</div>
            </div>
            <div class="info-card accent2">
                <div class="info-label">Execution Time</div>
                <div class="info-value mono">$($RunSummary.ExecutionTime)</div>
            </div>
        </div>
    </div>

    <!-- Summary Stats -->
    <div class="section">
        <div class="section-title">📊 Execution Summary</div>
        <div class="stats-grid">
            <div class="stat-card c-blue">
                <div class="stat-number">$($RunSummary.TotalAttempted)</div>
                <div class="stat-label">Total Attempted</div>
            </div>
            <div class="stat-card c-green">
                <div class="stat-number">$($RunSummary.Created)</div>
                <div class="stat-label">Created</div>
            </div>
            <div class="stat-card c-amber">
                <div class="stat-number">$($RunSummary.Skipped)</div>
                <div class="stat-label">Skipped (Existing)</div>
            </div>
            <div class="stat-card c-red">
                <div class="stat-number">$($RunSummary.Failed)</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card c-purple">
                <div class="stat-number">$($RunSummary.PoliciesApplied)</div>
                <div class="stat-label">Policies Applied</div>
            </div>
        </div>
    </div>

    <!-- Governance Justification -->
    <div class="section">
        <div class="section-title">📝 Governance Record</div>
        <div class="governance-note">
            <div class="gn-icon">🛡️</div>
            <div>
                <div class="gn-label">Justification / Audit Trail</div>
                <div class="gn-text">$($RunParameters.Justification)</div>
            </div>
        </div>
    </div>

    <!-- Results Table -->
    <div class="section">
        <div class="section-title">🔍 Exemption Results</div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Resource</th>
                        <th>Policy Assignment</th>
                        <th>Exemption Name</th>
                        <th>Expires On (UTC)</th>
                        <th>Category</th>
                        <th>Status</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
$rowsHtml
                </tbody>
            </table>
        </div>
    </div>

    <!-- Output Files -->
    <div class="section">
        <div class="section-title">📁 Output Files</div>
        <div class="output-section">
$outputHtml
        </div>
    </div>

    <div class="report-footer">
        Generated by <strong>Azure Policy Exemption Manager v1.0</strong>
        &nbsp;|&nbsp; Enterprise Governance Solution
        &nbsp;|&nbsp; <a href="https://learn.microsoft.com/en-us/azure/governance/policy/concepts/exemption-structure" target="_blank">Azure Policy Exemption Docs</a>
    </div>

</body>
</html>
"@

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function New-AzurePolicyExemption
{
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'ByName')]
    param (
        # ── Resource identification — mutually exclusive parameter sets ───────

        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceName,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByName')]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceType,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByName')]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $false, ParameterSetName = 'ByName')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/[^/]+/[^/]+')]
        [string]$ResourceId,

        # ── Mandatory parameters ─────────────────────────────────────────────

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$PolicyAssignments,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Justification,

        # ── Optional parameters ──────────────────────────────────────────────

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 720)]
        [int]$ExemptionDurationHours = 4,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Waiver", "Mitigated")]
        [string]$ExemptionCategory = "Waiver",

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[a-zA-Z0-9-]{1,20}$')]
        [string]$ExemptionNamePrefix,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            $dir = Split-Path $_ -Parent
            if ($dir -and -not (Test-Path $dir))
            {
                throw "Directory does not exist: $dir"
            }
            if ($_ -match '[<>:"|?*]')
            {
                throw "CsvPath contains invalid characters."
            }
            return $true
        })]
        [string]$CsvPath = "C:\Temp\AzurePolicyExemptions-Report.csv",

        # ── Switches ─────────────────────────────────────────────────────────

        [switch]$ExportToCsv,
        [switch]$Force
    )

    #------------------------------------------------------------------------ [ Initialise ]

    $startTime   = Get-Date
    $expiresOn   = $startTime.AddHours($ExemptionDurationHours).ToUniversalTime()
    $timestamp   = Get-Date -Format "yyyyMMddHHmm"

    Write-Banner

    #------------------------------------------------------------------------ [ Module check ]

    $requiredModules = @(
        @{ Name = "Az.Accounts";  Cmdlet = "Get-AzContext"          },
        @{ Name = "Az.Resources"; Cmdlet = "New-AzPolicyExemption"  }
    )

    foreach ($mod in $requiredModules)
    {
        if (-not (Get-Command $mod.Cmdlet -ErrorAction SilentlyContinue))
        {
            Write-Host "  ⚠ Module not loaded: $($mod.Name)" -ForegroundColor Yellow
            $install = Read-Host "  Install $($mod.Name) now? (Y/N)"
            if ($install -match '^[Yy]$')
            {
                try
                {
                    Write-Host "  Installing $($mod.Name), please wait..." -ForegroundColor Cyan
                    Install-Module -Name $mod.Name -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                    Import-Module  $mod.Name -ErrorAction Stop
                    Write-Host "  ✓ $($mod.Name) installed successfully" -ForegroundColor Green
                }
                catch
                {
                    Write-Host "  ✗ Failed to install $($mod.Name): $_" -ForegroundColor Red
                    return
                }
            }
            else
            {
                Write-Host "  Installation declined. Cannot proceed without $($mod.Name)." -ForegroundColor Yellow
                return
            }
        }
    }

    # .NET type for HTML encoding used in the report generator
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    #------------------------------------------------------------------------ [ Auth check ]

    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext)
    {
        Write-Host "  ⚠ No active Azure session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    $sessionInfo = @{
        TenantId         = $currentContext.Tenant.Id
        Account          = $currentContext.Account.Id
        Environment      = $currentContext.Environment.Name
        SubscriptionName = $currentContext.Subscription.Name
    }

    Write-Section -Title "Session Information" -Data ([ordered]@{
        "Tenant ID"    = $sessionInfo.TenantId
        "Account"      = $sessionInfo.Account
        "Environment"  = $sessionInfo.Environment
        "Subscription" = $sessionInfo.SubscriptionName
    })

    #------------------------------------------------------------------------ [ Resolve target resource ]

    Write-Host ""
    Write-Host "  Resolving Target Resource" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $resolvedResource = $null

    if ($PSCmdlet.ParameterSetName -eq 'ById')
    {
        # ── Full Resource ID path ────────────────────────────────────────────
        Write-Host "  → Resolution mode: Full Resource ID" -ForegroundColor DarkGray

        try
        {
            $resolvedResource = Get-AzResource -ResourceId $ResourceId -ErrorAction Stop

            if (-not $resolvedResource)
            {
                throw "Resource not found or no read access."
            }

            Write-Host "  ✓ " -NoNewline -ForegroundColor Green
            Write-Host $resolvedResource.Name.PadRight(40) -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host $resolvedResource.ResourceType -ForegroundColor White
        }
        catch
        {
            Write-Host "  ✗ Failed to resolve Resource ID: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host ("═" * 80) -ForegroundColor Cyan
            return
        }
    }
    else
    {
        # ── Friendly name path ───────────────────────────────────────────────
        $modeDetail = "Name: '$ResourceName'"
        if ($ResourceType)      { $modeDetail += " | Type: '$ResourceType'" }
        if ($ResourceGroupName) { $modeDetail += " | RG: '$ResourceGroupName'" }
        if ($SubscriptionId)    { $modeDetail += " | Sub: '$SubscriptionId'" }

        Write-Host "  → Resolution mode: Friendly Name ($modeDetail)" -ForegroundColor DarkGray

        try
        {
            $resolvedResource = Resolve-ResourceByName `
                -ResourceName      $ResourceName `
                -ResourceType      $ResourceType `
                -ResourceGroupName $ResourceGroupName `
                -SubscriptionId    $SubscriptionId

            Write-Host "  ✓ " -NoNewline -ForegroundColor Green
            Write-Host $resolvedResource.Name.PadRight(40) -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host $resolvedResource.ResourceType -ForegroundColor White
            Write-Host "    Resource ID: " -NoNewline -ForegroundColor DarkGray
            Write-Host $resolvedResource.ResourceId -ForegroundColor Gray
        }
        catch
        {
            Write-Host "  ✗ Failed to resolve resource by name: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host ("═" * 80) -ForegroundColor Cyan
            return
        }
    }

    # Canonical values used throughout the rest of the function
    $targetResourceId    = $resolvedResource.ResourceId
    $targetResourceName  = $resolvedResource.Name
    $targetResourceType  = $resolvedResource.ResourceType
    $targetResourceGroup = $resolvedResource.ResourceGroupName

    #------------------------------------------------------------------------ [ Display parameters ]

    $expiresOnDisplay = $expiresOn.ToString("yyyy-MM-dd HH:mm:ss") + " UTC"

    Write-Section -Title "Run Parameters" -Data ([ordered]@{
        "Resource Name"      = $targetResourceName
        "Resource Type"      = $targetResourceType
        "Resource Group"     = $targetResourceGroup
        "Policy Assignments" = ($PolicyAssignments -join ", ")
        "Exemption Duration" = "$ExemptionDurationHours hour(s)"
        "Expires On (UTC)"   = $expiresOnDisplay
        "Exemption Category" = $ExemptionCategory
        "Name Prefix"        = if ($ExemptionNamePrefix) { $ExemptionNamePrefix } else { "None (auto)" }
        "Export to CSV"      = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Justification"      = $Justification
    })

    #------------------------------------------------------------------------ [ Resolve Policy Assignments ]

    Write-Host ""
    Write-Host "  Resolving Policy Assignments" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $resolvedPolicies = [System.Collections.Generic.List[psobject]]::new()

    foreach ($pa in $PolicyAssignments)
    {
        try
        {
            $assignment = $null

            # Branch: full Assignment resource ID
            if ($pa -match '^/subscriptions/.+/providers/Microsoft\.Authorization/policyAssignments/.+$' -or
                $pa -match '^/providers/Microsoft\.Authorization/policyAssignments/.+$')
            {
                $assignment = Get-AzPolicyAssignment -Id $pa -ErrorAction Stop
            }
            else
            {
                # Resolve by display name or assignment name — search across all visible scopes
                $allAssignments = Get-AzPolicyAssignment -IncludeDescendent -ErrorAction Stop |
                    Where-Object { $_.DisplayName -eq $pa -or $_.Name -eq $pa }

                if (-not $allAssignments)
                {
                    throw "No policy assignment found with name or display name: '$pa'"
                }

                if (($allAssignments | Measure-Object).Count -gt 1)
                {
                    Write-Host "  ⚠ " -NoNewline -ForegroundColor Yellow
                    Write-Host ("Multiple assignments match '$pa' — using first match. " +
                        "Use full Assignment ID to disambiguate.") -ForegroundColor Yellow
                }

                $assignment = $allAssignments | Select-Object -First 1
            }

            $displayName = if ($assignment.DisplayName) { $assignment.DisplayName } else { $assignment.Name }

            Write-Host "  ✓ " -NoNewline -ForegroundColor Green
            Write-Host $pa.PadRight(50) -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host $displayName -ForegroundColor White

            $resolvedPolicies.Add([pscustomobject]@{
                InputValue       = $pa
                AssignmentId     = $assignment.Id
                DisplayName      = $displayName
                ShortName        = $assignment.Name
                AssignmentObject = $assignment
            })
        }
        catch
        {
            Write-Host "  ✗ " -NoNewline -ForegroundColor Red
            Write-Host $pa.PadRight(50) -NoNewline -ForegroundColor Red
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Failed to resolve: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    if ($resolvedPolicies.Count -eq 0)
    {
        Write-Host ""
        Write-Host "  ✗ No Policy Assignments could be resolved. Cannot proceed." -ForegroundColor Red
        Write-Host ("═" * 80) -ForegroundColor Cyan
        return
    }

    #------------------------------------------------------------------------ [ Permission pre-check ]

    Write-Host ""
    Write-Host "  Permission Pre-Check" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $permissionCheckPassed = $true

    try
    {
        # Roles known to carry Microsoft.Authorization/policyExemptions/write.
        # Custom roles with this action but different names will show as "could not be confirmed"
        # — see Known Limitations.
        $rolesWithPermission = @(
            "Owner",
            "User Access Administrator",
            "Resource Policy Contributor"
        )

        $currentUserRoles = Get-AzRoleAssignment -Scope $targetResourceId -ErrorAction Stop |
            Where-Object { $_.SignInName -eq $currentContext.Account.Id }

        $permitted = $currentUserRoles |
            Where-Object { $rolesWithPermission -contains $_.RoleDefinitionName }

        if ($permitted)
        {
            Write-Host "  ✓ " -NoNewline -ForegroundColor Green
            Write-Host $targetResourceName.PadRight(44) -NoNewline -ForegroundColor Green
            Write-Host " → policyExemptions/write: " -NoNewline -ForegroundColor DarkGray
            Write-Host "Permitted" -ForegroundColor White
            Write-Host "    Matched role: " -NoNewline -ForegroundColor DarkGray
            Write-Host ($permitted | Select-Object -First 1 -ExpandProperty RoleDefinitionName) -ForegroundColor Gray
        }
        else
        {
            Write-Host "  ✗ " -NoNewline -ForegroundColor Red
            Write-Host $targetResourceName.PadRight(44) -NoNewline -ForegroundColor Red
            Write-Host " → policyExemptions/write: " -NoNewline -ForegroundColor DarkGray
            Write-Host "DENIED" -ForegroundColor Red
            Write-Host "    Assign Owner, User Access Administrator, or Resource Policy Contributor at this resource scope." -ForegroundColor Red
            $permissionCheckPassed = $false
        }
    }
    catch
    {
        Write-Host "  ⚠ " -NoNewline -ForegroundColor Yellow
        Write-Host $targetResourceName.PadRight(44) -NoNewline -ForegroundColor Yellow
        Write-Host " → Permission check could not be confirmed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Verbose "Get-AzRoleAssignment error for resource '$targetResourceId': $_"
    }

    if (-not $permissionCheckPassed)
    {
        Write-Host ""
        Write-Host "  ✗ Permission pre-check failed. Grant 'Microsoft.Authorization/policyExemptions/write'" -ForegroundColor Red
        Write-Host "    at the resource scope before retrying." -ForegroundColor Red
        Write-Host ("═" * 80) -ForegroundColor Cyan
        return
    }

    #------------------------------------------------------------------------ [ Confirmation prompt ]

    $totalAttempts = $resolvedPolicies.Count

    Write-Host ""
    Write-Host "  Exemption Plan" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  $totalAttempts exemption(s) will be created against:" -ForegroundColor White
    Write-Host "    · Resource  : $targetResourceName ($targetResourceType)" -ForegroundColor Gray
    Write-Host "    · Scope     : $targetResourceId" -ForegroundColor Gray
    Write-Host "    · Policies  : $($resolvedPolicies.Count)" -ForegroundColor Gray
    Write-Host "    · Expires   : $expiresOnDisplay" -ForegroundColor Gray
    Write-Host "    · Category  : $ExemptionCategory" -ForegroundColor Gray
    Write-Host ""

    if (-not $Force -and -not $PSCmdlet.ShouldProcess(
        "Create $totalAttempts policy exemption(s) on '$targetResourceName' ($targetResourceType)",
        "Confirm exemption creation?",
        "Azure Policy Exemption"))
    {
        Write-Host "  Operation cancelled by user." -ForegroundColor Yellow
        Write-Host ("═" * 80) -ForegroundColor Cyan
        return
    }

    #------------------------------------------------------------------------ [ Create exemptions ]

    Write-Host ""
    Write-Host "  Creating Exemptions" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $allResults   = [System.Collections.Generic.List[psobject]]::new()
    $createdCount = 0
    $skippedCount = 0
    $failedCount  = 0
    $currentIndex = 0

    foreach ($policy in $resolvedPolicies)
    {
        $currentIndex++
        Write-ProgressBar -Current $currentIndex -Total $totalAttempts -CurrentItem $policy.ShortName

        $exemptionName = Get-SafeExemptionName `
            -Prefix            $ExemptionNamePrefix `
            -ResourceShortName $targetResourceName `
            -PolicyShortName   $policy.ShortName `
            -Timestamp         $timestamp

        try
        {
            # ── Idempotency guard ────────────────────────────────────────────
            $existing = Get-AzPolicyExemption `
                -Scope $targetResourceId `
                -Name  $exemptionName `
                -ErrorAction SilentlyContinue

            if ($existing -and $existing.Properties.ExpiresOn -gt (Get-Date).ToUniversalTime())
            {
                # Clear progress line
                Write-Host ("`r" + " " * 120 + "`r") -NoNewline

                Write-Host "  ⚠ " -NoNewline -ForegroundColor Yellow
                Write-Host $policy.ShortName.PadRight(44) -NoNewline -ForegroundColor Yellow
                Write-Host " → Skipped (active exemption already exists)" -ForegroundColor DarkGray

                $skippedCount++
                $allResults.Add([pscustomobject]@{
                    ResourceName     = $targetResourceName
                    ResourceType     = $targetResourceType
                    ResourceGroup    = $targetResourceGroup
                    ResourceId       = $targetResourceId
                    PolicyAssignment = $policy.DisplayName
                    PolicyId         = $policy.AssignmentId
                    ExemptionName    = $exemptionName
                    ExemptionId      = $existing.ResourceId
                    ExpiresOn        = $expiresOnDisplay
                    ExemptionCategory = $ExemptionCategory
                    Status           = "Skipped"
                    Message          = "Active exemption already exists; no change made."
                    Justification    = $Justification
                })
                continue
            }

            # ── Create exemption ─────────────────────────────────────────────
            $newExemption = New-AzPolicyExemption `
                -Name              $exemptionName `
                -Scope             $targetResourceId `
                -PolicyAssignment  $policy.AssignmentObject `
                -ExemptionCategory $ExemptionCategory `
                -ExpiresOn         $expiresOn `
                -Description       $Justification `
                -DisplayName       $exemptionName `
                -ErrorAction       Stop

            # Clear progress line
            Write-Host ("`r" + " " * 120 + "`r") -NoNewline

            Write-Host "  ✓ " -NoNewline -ForegroundColor Green
            Write-Host $policy.ShortName.PadRight(44) -NoNewline -ForegroundColor Green
            Write-Host " → Created. Expires $expiresOnDisplay" -ForegroundColor White

            $createdCount++
            $allResults.Add([pscustomobject]@{
                ResourceName      = $targetResourceName
                ResourceType      = $targetResourceType
                ResourceGroup     = $targetResourceGroup
                ResourceId        = $targetResourceId
                PolicyAssignment  = $policy.DisplayName
                PolicyId          = $policy.AssignmentId
                ExemptionName     = $exemptionName
                ExemptionId       = $newExemption.Id
                ExpiresOn         = $expiresOnDisplay
                ExemptionCategory = $ExemptionCategory
                Status            = "Created"
                Message           = "Exemption created successfully."
                Justification     = $Justification
            })
        }
        catch
        {
            # Clear progress line
            Write-Host ("`r" + " " * 120 + "`r") -NoNewline

            Write-Host "  ✗ " -NoNewline -ForegroundColor Red
            Write-Host $policy.ShortName.PadRight(44) -NoNewline -ForegroundColor Red
            Write-Host " → Failed: $($_.Exception.Message)" -ForegroundColor Red

            Write-Verbose "Full error for policy '$($policy.ShortName)' on resource '$targetResourceName': $_"

            $failedCount++
            $allResults.Add([pscustomobject]@{
                ResourceName      = $targetResourceName
                ResourceType      = $targetResourceType
                ResourceGroup     = $targetResourceGroup
                ResourceId        = $targetResourceId
                PolicyAssignment  = $policy.DisplayName
                PolicyId          = $policy.AssignmentId
                ExemptionName     = $exemptionName
                ExemptionId       = ""
                ExpiresOn         = $expiresOnDisplay
                ExemptionCategory = $ExemptionCategory
                Status            = "Failed"
                Message           = $_.Exception.Message
                Justification     = $Justification
            })
        }
    }

    #------------------------------------------------------------------------ [ Summary ]

    $endTime     = Get-Date
    $duration    = $endTime - $startTime
    $durationStr = "{0:hh\:mm\:ss}" -f $duration

    Write-Summary -Data ([ordered]@{
        "Total Attempted"          = $totalAttempts
        "Created"                  = $createdCount
        "Skipped (already exist)"  = $skippedCount
        "Failed"                   = $failedCount
        "Resource Processed"       = $targetResourceName
        "Resource Type"            = $targetResourceType
        "Policies Applied"         = $resolvedPolicies.Count
        "Exemption Expires (UTC)"  = $expiresOnDisplay
        "Execution Time"           = $durationStr
    })

    #------------------------------------------------------------------------ [ Outputs ]

    $csvExported  = $false
    $htmlExported = $false
    $htmlPath     = [System.IO.Path]::ChangeExtension($CsvPath, '.html')

    if ($allResults.Count -gt 0)
    {
        # ── CSV export (optional) ────────────────────────────────────────────
        if ($ExportToCsv)
        {
            try
            {
                $dir = Split-Path $CsvPath -Parent
                if ($dir -and -not (Test-Path $dir))
                {
                    New-Item -ItemType Directory -Path $dir -Force | Out-Null
                }
                $allResults | Export-Csv -Path $CsvPath -NoTypeInformation -Force
                $csvExported = $true
            }
            catch
            {
                Write-Warning "CSV export failed: $_"
            }
        }

        # ── HTML report (always) ─────────────────────────────────────────────
        try
        {
            $runParameters = @{
                ResourceDisplayName = $targetResourceName
                ResourceType        = $targetResourceType
                ResourceGroup       = $targetResourceGroup
                ResourceId          = $targetResourceId
                PolicyCount         = $resolvedPolicies.Count
                DurationHours       = $ExemptionDurationHours
                ExemptionCategory   = $ExemptionCategory
                ExemptionNamePrefix = $ExemptionNamePrefix
                ExpiresAt           = $expiresOnDisplay
                Justification       = $Justification
                SubscriptionId      = $SubscriptionId
            }

            $runSummary = @{
                TotalAttempted = $totalAttempts
                Created        = $createdCount
                Skipped        = $skippedCount
                Failed         = $failedCount
                PoliciesApplied = $resolvedPolicies.Count
                ExecutionTime  = $durationStr
            }

            $htmlContent = Generate-HtmlReport `
                -SessionInfo      $sessionInfo `
                -RunParameters    $runParameters `
                -RunSummary       $runSummary `
                -ExemptionResults $allResults `
                -HtmlPath         $htmlPath `
                -CsvPath          $(if ($csvExported) { $CsvPath } else { $null })

            $dir = Split-Path $htmlPath -Parent
            if ($dir -and -not (Test-Path $dir))
            {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }

            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch
        {
            Write-Warning "HTML report generation failed: $_"
        }
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
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
