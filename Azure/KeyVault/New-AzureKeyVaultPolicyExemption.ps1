<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 20 August 2026
Modified-On     : 20 August 2026

.SYNOPSIS
    Creates time-boxed Azure Policy exemptions for one or more Key Vaults against one
    or more Policy Assignments, with automatic expiry and a full audit trail.

.DESCRIPTION
    New-AzureKeyVaultPolicyExemption automates the creation of Azure Policy exemptions
    scoped to individual Key Vault resources. Exemptions are commonly needed when a Key
    Vault requires a temporary deviation from one or more Policy Assignments — for
    example, during a maintenance window, migration activity, or a break-glass scenario.

    The script supports:
        - Multiple Key Vaults and multiple Policy Assignments in a single execution
        - Policy Assignment resolution by either Assignment ID or Assignment display name
        - Configurable exemption duration (default 4 hours) with automatic expiry via
          ExpiresOn timestamp
        - Two exemption categories: Waiver (default) or Mitigated
        - Auto-generated exemption names with an optional prefix for namespacing
        - Mandatory justification/description for full governance auditability
        - Pre-flight permission check for Microsoft.Authorization/policyExemptions/write
        - Idempotent behaviour: skips creation if an active, non-expired exemption with
          the same name already exists at the same scope
        - Optional CSV export of all results
        - Always-generated HTML report (dark-themed, self-contained) with session info,
          parameters, per-Key Vault results, and a summary

.PARAMETER KeyVaultNames
    One or more Key Vault display names to exempt. The script resolves each name to its
    full resource ID via Get-AzKeyVault. Validation fails early if a name cannot be
    resolved.

.PARAMETER PolicyAssignments
    One or more Policy Assignment identifiers. Each value may be:
        - A full Assignment resource ID  (/subscriptions/{id}/providers/Microsoft.Authorization/
          policyAssignments/{name})
        - A Policy Assignment display name (resolved via Get-AzPolicyAssignment)
    Mixed formats are accepted within a single invocation.

.PARAMETER Justification
    Mandatory free-text justification recorded on every exemption created. Required for
    governance auditability. Stored in the exemption's Description field in Azure.

.PARAMETER ExemptionDurationHours
    Duration in hours that each exemption remains active. Must be between 1 and 720 hours
    (30 days). Defaults to 4 hours.

.PARAMETER ExemptionCategory
    Azure Policy exemption category. Accepted values:
        - Waiver    : The policy intent genuinely does not apply to this resource (default).
        - Mitigated : The policy intent is addressed through an alternative control.

.PARAMETER ExemptionNamePrefix
    Optional prefix prepended to the auto-generated exemption name. Useful for namespacing
    exemptions by team, ticket, or environment.
    Auto-generated format (no prefix) : KV-<KVName>-<PolicyShortName>-<Timestamp>
    Auto-generated format (with prefix): <Prefix>-KV-<KVName>-<PolicyShortName>-<Timestamp>
    Maximum combined length enforced: 64 characters.

.PARAMETER ExportToCsv
    Switch. When specified, exports the full results table to the path in -CsvPath.
    An HTML report is always generated regardless of this switch.

.PARAMETER CsvPath
    Output path for the CSV export and the co-located HTML report (same path, .html
    extension). Defaults to C:\Temp\AzureKVPolicyExemptions-Report.csv.

.PARAMETER Force
    Switch. Suppresses the confirmation prompt before creating exemptions. Without this
    switch the script displays a summary of planned exemptions and prompts for confirmation
    before writing anything to Azure.

.INPUTS
    None. All input is via parameters.

.OUTPUTS
    None directly to the pipeline. Always writes an HTML report. Optionally writes a CSV
    if -ExportToCsv is specified. Returns a summary object to the host.

.EXAMPLE
    New-AzureKeyVaultPolicyExemption `
        -KeyVaultNames @("kv-prod-payments", "kv-prod-secrets") `
        -PolicyAssignments @("Deny-KeyVault-PublicAccess") `
        -Justification "Temporary exemption for migration window — JIRA INFRA-4521" `
        -ExemptionDurationHours 4

.EXAMPLE
    New-AzureKeyVaultPolicyExemption `
        -KeyVaultNames @("kv-dev-api") `
        -PolicyAssignments @("/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/providers/Microsoft.Authorization/policyAssignments/deny-kv-access") `
        -Justification "Break-glass: cert renewal — approved by security lead" `
        -ExemptionCategory Mitigated `
        -ExemptionDurationHours 2 `
        -ExemptionNamePrefix "SEC-OPS"

.EXAMPLE
    New-AzureKeyVaultPolicyExemption `
        -KeyVaultNames @("kv-prod-payments", "kv-prod-secrets", "kv-prod-certs") `
        -PolicyAssignments @("Deny-KeyVault-PublicAccess", "Require-KeyVault-Diagnostics") `
        -Justification "Planned maintenance window — CAB approval ref CAB-2026-0812" `
        -ExemptionDurationHours 8 `
        -ExemptionNamePrefix "MAINT" `
        -ExportToCsv `
        -CsvPath "C:\Reports\KVExemptions-2026-08-20.csv"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (20-Aug-2026) - Initial release. Supports multi-KV, multi-policy exemption
                            creation with auto-expiry, permission pre-check, idempotency
                            guard, CSV export, and HTML report generation.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.KeyVault, Az.Resources, Az.PolicyInsights
           sub-modules — installed/imported automatically if missing, with user consent)
        2. Authenticated Azure session (Connect-AzAccount)
        3. Microsoft.Authorization/policyExemptions/write at each Key Vault resource scope
           (typically granted via Owner, Contributor, or a custom role)
        4. Microsoft.KeyVault/vaults/read to resolve Key Vault names to resource IDs
        5. Microsoft.Authorization/policyAssignments/read to resolve Assignment names to IDs

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Exemptions are created at the Key Vault resource scope only. Resource Group or
          subscription-level scoping is not supported in this version.
        - Policy Assignment name resolution searches across all subscriptions visible to
          the current account. If multiple assignments share the same display name, the
          script warns and uses the first match — use the full Assignment ID to disambiguate.
        - Default -CsvPath (C:\Temp\...) is Windows-specific. On macOS/Linux PowerShell 7,
          supply an explicit -CsvPath.
        - Interactive Grid View for results is not included in this script (exemption
          creation is a write operation; Grid View is output-only and deferred to the
          companion audit script).
        - ExemptionDurationHours maximum is 720 hours (30 days), aligned with common
          Azure Policy governance guardrails. Adjust ValidateRange if your policy allows
          longer windows.

.LINK
    https://learn.microsoft.com/en-us/azure/governance/policy/concepts/exemption-structure
    https://learn.microsoft.com/en-us/powershell/module/az.resources/new-azpolicyexemption
    https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azpolicyassignment

#>


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CenteredText {
    param(
        [string]$Text,
        [int]$Width = 80,
        [string]$Color = "White"
    )
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Key Vault Policy Exemption Manager v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-Section {
    param(
        [string]$Title,
        [hashtable]$Data
    )

    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys) {
        $value = $Data[$key]
        if ([string]::IsNullOrWhiteSpace($value)) {
            $value = "None"
            $valColor = "DarkGray"
        }
        else {
            $valColor = "White"
        }

        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-ProgressBar {
    param(
        [int]$Current,
        [int]$Total,
        [string]$CurrentItem,
        [int]$BarWidth = 40
    )

    $percentage = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
    $completed = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $remaining = $BarWidth - $completed
    $bar = ("█" * $completed) + ("░" * $remaining)

    Write-Host "`r" -NoNewline
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White

    if ($CurrentItem) {
        $maxLength = 30
        $displayItem = if ($CurrentItem.Length -gt $maxLength) {
            $CurrentItem.Substring(0, $maxLength - 3) + "..."
        }
        else { $CurrentItem }

        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-Summary {
    param([hashtable]$Data)

    Write-Host ""
    Write-Host "  Execution Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($key in $Data.Keys) {
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(32) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $Data[$key] -ForegroundColor White
    }
}

Function Write-OutputFiles {
    param(
        [string]$CsvPath,
        [string]$HtmlPath
    )

    Write-Host ""
    Write-Host "  Output Files" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    if ($CsvPath) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("CSV Export").PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }

    if ($HtmlPath) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Report").PadRight(20) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }

    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-SafeExemptionName {
    <#
    .SYNOPSIS
        Builds a safe, unique exemption name within Azure's 64-character limit.
    #>
    param(
        [string]$Prefix,
        [string]$KeyVaultName,
        [string]$PolicyShortName,
        [string]$Timestamp
    )

    # Strip characters not allowed in Azure resource names (keep alphanumeric and hyphens)
    $safeKV = ($KeyVaultName -replace '[^a-zA-Z0-9-]', '') 
    $safePol = ($PolicyShortName -replace '[^a-zA-Z0-9-]', '')
    $safePrefix = if ($Prefix) { ($Prefix -replace '[^a-zA-Z0-9-]', '') + "-" } else { "" }

    # Truncate KV and policy fragments to fit within 64 chars total
    # Reserve: prefix (up to 20) + "KV-" (3) + "-" (1) + "-" (1) + timestamp (12) = up to 37 fixed chars
    # Remaining budget for KVName + PolicyShortName fragments = 64 - fixed
    $fixedLen = $safePrefix.Length + 3 + 1 + 1 + $Timestamp.Length   # "KV-" + "-" + "-" + ts
    $budget = 64 - $fixedLen
    $kvBudget = [math]::Min($safeKV.Length, [math]::Floor($budget * 0.5))
    $polBudget = [math]::Min($safePol.Length, $budget - $kvBudget)

    $kvFrag = $safeKV.Substring(0, $kvBudget)
    $polFrag = $safePol.Substring(0, $polBudget)

    return "$($safePrefix)KV-$kvFrag-$polFrag-$Timestamp"
}

Function Generate-HtmlReport {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$RunParameters,
        [hashtable]$RunSummary,
        [array]$ExemptionResults,
        [string]$HtmlPath,
        [string]$CsvPath
    )

    $timestamp = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    # ── Build per-exemption rows ──────────────────────────────────────────────
    $rowsHtml = ""
    foreach ($r in $ExemptionResults) {
        $badgeClass = switch ($r.Status) {
            "Created" { "badge-success" }
            "Skipped" { "badge-warning" }
            "Failed" { "badge-error" }
            default { "badge-info" }
        }

        $rowsHtml += @"
                        <tr>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($r.KeyVaultName))</td>
                            <td class="mono">$([System.Web.HttpUtility]::HtmlEncode($r.PolicyAssignment))</td>
                            <td class="mono">$([System.Web.HttpUtility]::HtmlEncode($r.ExemptionName))</td>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($r.ExpiresOn))</td>
                            <td><span class="badge $badgeClass">$([System.Web.HttpUtility]::HtmlEncode($r.Status))</span></td>
                            <td>$([System.Web.HttpUtility]::HtmlEncode($r.Message))</td>
                        </tr>
"@
    }

    # ── Build output-files section ────────────────────────────────────────────
    $outputHtml = ""
    if ($CsvPath) {
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

    # ── Assemble full HTML ────────────────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure KV Policy Exemption Report</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }

        :root {
            --bg:#0d1117; --surface:#161b22; --surface2:#1c2333; --surface3:#243048;
            --border:#30363d; --accent:#388bfd; --accent2:#39c5cf; --accent3:#a371f7;
            --green:#3fb950; --amber:#d29922; --red:#f85149;
            --text:#e6edf3; --muted:#7d8590; --muted2:#adbac7;
            --mono:'JetBrains Mono','Consolas','Courier New',monospace;
            --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
            --radius:10px; --radius-sm:6px;
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
            text-align: center;
        }
        .report-header h1 { font-size:28px; font-weight:300; letter-spacing:1px; color:#fff; margin-bottom:8px; }
        .report-header .sub { font-size:13px; color:rgba(255,255,255,0.85); }

        /* ── Sections ────────────────────────────────────── */
        .section { margin-bottom:32px; }
        .section-title {
            font-size:16px; font-weight:600; color:var(--accent2);
            margin-bottom:16px; padding-bottom:8px;
            border-bottom: 1px solid var(--border);
            display:flex; align-items:center; gap:8px;
        }

        /* ── Info grid ───────────────────────────────────── */
        .info-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(220px,1fr)); gap:16px; }
        .info-card {
            background:var(--surface);
            border:1px solid var(--border);
            border-left: 3px solid var(--accent);
            border-radius:var(--radius-sm);
            padding:16px 20px;
        }
        .info-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; }
        .info-value { font-size:15px; color:var(--text); font-weight:600; word-break:break-all; }
        .info-value.none { color:var(--muted); font-style:italic; font-weight:400; }

        /* ── Stat cards ──────────────────────────────────── */
        .stats-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(160px,1fr)); gap:16px; }
        .stat-card {
            background:var(--surface);
            border:1px solid var(--border);
            border-radius:var(--radius-sm);
            padding:20px;
            text-align:center;
        }
        .stat-card.c-blue  { border-top:3px solid var(--accent); }
        .stat-card.c-green { border-top:3px solid var(--green); }
        .stat-card.c-amber { border-top:3px solid var(--amber); }
        .stat-card.c-red   { border-top:3px solid var(--red); }
        .stat-card.c-cyan  { border-top:3px solid var(--accent2); }
        .stat-number { font-size:32px; font-weight:700; margin-bottom:6px; }
        .stat-card.c-blue  .stat-number { color:var(--accent); }
        .stat-card.c-green .stat-number { color:var(--green); }
        .stat-card.c-amber .stat-number { color:var(--amber); }
        .stat-card.c-red   .stat-number { color:var(--red); }
        .stat-card.c-cyan  .stat-number { color:var(--accent2); }
        .stat-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:1px; }

        /* ── Results table ───────────────────────────────── */
        .table-wrap { overflow-x:auto; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); }
        table { width:100%; border-collapse:collapse; font-size:13px; }
        thead th {
            background:var(--surface2);
            color:var(--muted2);
            font-size:11px;
            text-transform:uppercase;
            letter-spacing:.8px;
            padding:12px 16px;
            text-align:left;
            border-bottom:1px solid var(--border);
            white-space:nowrap;
        }
        tbody td { padding:12px 16px; border-bottom:1px solid var(--border); color:var(--text); vertical-align:top; }
        tbody tr:last-child td { border-bottom:none; }
        tbody tr:hover td { background:var(--surface2); }
        .mono { font-family:var(--mono); font-size:12px; }

        /* ── Badges ──────────────────────────────────────── */
        .badge { display:inline-block; padding:3px 10px; border-radius:20px; font-size:11px; font-weight:600; letter-spacing:.5px; }
        .badge-success { background:rgba(63,185,80,.15); color:var(--green); border:1px solid rgba(63,185,80,.3); }
        .badge-warning { background:rgba(210,153,34,.15); color:var(--amber); border:1px solid rgba(210,153,34,.3); }
        .badge-error   { background:rgba(248,81,73,.15);  color:var(--red);   border:1px solid rgba(248,81,73,.3); }
        .badge-info    { background:rgba(56,139,253,.15); color:var(--accent);border:1px solid rgba(56,139,253,.3); }

        /* ── Output files ────────────────────────────────── */
        .output-section { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm); padding:16px; }
        .output-item { display:flex; align-items:flex-start; gap:14px; padding:12px 0; border-bottom:1px solid var(--border); }
        .output-item:last-child { border-bottom:none; }
        .output-icon { width:36px; height:36px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:18px; flex-shrink:0; }
        .success-icon { background:rgba(63,185,80,.15); color:var(--green); }
        .output-label { font-size:11px; color:var(--muted); margin-bottom:4px; text-transform:uppercase; letter-spacing:.8px; }
        .output-value { font-weight:600; color:var(--text); word-break:break-all; }

        /* ── Footer ──────────────────────────────────────── */
        .report-footer { text-align:center; color:var(--muted); font-size:12px; margin-top:40px; padding-top:20px; border-top:1px solid var(--border); }

        /* ── Responsive ──────────────────────────────────── */
        @media (max-width:768px) { body { padding:16px 12px; } .report-header { padding:24px 20px; } }
        @media print { body { background:#fff; color:#000; } }
    </style>
</head>
<body>

    <div class="report-header">
        <h1>🔐 Azure Key Vault Policy Exemption Report</h1>
        <div class="sub">Generated on $timestamp</div>
    </div>

    <!-- Session Info -->
    <div class="section">
        <div class="section-title">📋 Session Information</div>
        <div class="info-grid">
            <div class="info-card">
                <div class="info-label">Tenant ID</div>
                <div class="info-value">$($SessionInfo.TenantId)</div>
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
                <div class="info-label">Execution Time</div>
                <div class="info-value">$($RunSummary.ExecutionTime)</div>
            </div>
        </div>
    </div>

    <!-- Run Parameters -->
    <div class="section">
        <div class="section-title">⚙️ Run Parameters</div>
        <div class="info-grid">
            <div class="info-card">
                <div class="info-label">Key Vaults Targeted</div>
                <div class="info-value">$($RunParameters.KeyVaultCount)</div>
            </div>
            <div class="info-card">
                <div class="info-label">Policy Assignments</div>
                <div class="info-value">$($RunParameters.PolicyCount)</div>
            </div>
            <div class="info-card">
                <div class="info-label">Exemption Duration</div>
                <div class="info-value">$($RunParameters.DurationHours) hours</div>
            </div>
            <div class="info-card">
                <div class="info-label">Exemption Category</div>
                <div class="info-value">$($RunParameters.ExemptionCategory)</div>
            </div>
            <div class="info-card">
                <div class="info-label">Name Prefix</div>
                <div class="info-value$(if ([string]::IsNullOrWhiteSpace($RunParameters.ExemptionNamePrefix)) {' none'})">$(if ($RunParameters.ExemptionNamePrefix) { $RunParameters.ExemptionNamePrefix } else { 'Auto-generated' })</div>
            </div>
            <div class="info-card">
                <div class="info-label">Expires At</div>
                <div class="info-value">$($RunParameters.ExpiresAt)</div>
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
            <div class="stat-card c-cyan">
                <div class="stat-number">$($RunSummary.KeyVaultsProcessed)</div>
                <div class="stat-label">Key Vaults Processed</div>
            </div>
        </div>
    </div>

    <!-- Justification -->
    <div class="section">
        <div class="section-title">📝 Justification Recorded</div>
        <div class="info-card" style="border-left-color:var(--accent3);">
            <div class="info-label">Justification / Description</div>
            <div class="info-value" style="font-weight:400;">$($RunParameters.Justification)</div>
        </div>
    </div>

    <!-- Results Table -->
    <div class="section">
        <div class="section-title">🔍 Exemption Results</div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Key Vault</th>
                        <th>Policy Assignment</th>
                        <th>Exemption Name</th>
                        <th>Expires On (UTC)</th>
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
        Generated by Azure Key Vault Policy Exemption Manager v1.0 &nbsp;|&nbsp; Microsoft Azure &nbsp;|&nbsp; PowerShell Script
    </div>

</body>
</html>
"@

    return $html
}


#------------------------------------------------------------------------ [ Main Function ]

Function New-AzureKeyVaultPolicyExemption {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        # ── Mandatory parameters ─────────────────────────────────────────────
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$KeyVaultNames,

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
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-zA-Z0-9-]{1,20}$')]
        [string]$ExemptionNamePrefix,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
                $dir = Split-Path $_ -Parent
                if ($dir -and -not (Test-Path $dir)) {
                    throw "Directory does not exist: $dir"
                }
                if ($_ -match '[<>:"|?*]') {
                    throw "CsvPath contains invalid characters."
                }
                return $true
            })]
        [string]$CsvPath = "C:\Temp\AzureKVPolicyExemptions-Report.csv",

        # ── Switches ─────────────────────────────────────────────────────────
        [switch]$ExportToCsv,
        [switch]$Force
    )

    #------------------------------------------------------------------------ [ Initialise ]

    $startTime = Get-Date
    $expiresOn = $startTime.AddHours($ExemptionDurationHours).ToUniversalTime()
    $timestamp = Get-Date -Format "yyyyMMddHHmm"

    Write-Banner

    #------------------------------------------------------------------------ [ Module check ]

    $requiredModules = @(
        @{ Name = "Az.Accounts"; Cmdlet = "Get-AzContext" },
        @{ Name = "Az.KeyVault"; Cmdlet = "Get-AzKeyVault" },
        @{ Name = "Az.Resources"; Cmdlet = "New-AzPolicyExemption" }
    )

    foreach ($mod in $requiredModules) {
        if (-not (Get-Command $mod.Cmdlet -ErrorAction SilentlyContinue)) {
            Write-Host "  ⚠ Module not loaded: $($mod.Name)" -ForegroundColor Yellow
            $install = Read-Host "  Install $($mod.Name) now? (Y/N)"
            if ($install -match '^[Yy]$') {
                try {
                    Write-Host "  Installing $($mod.Name), please wait..." -ForegroundColor Cyan
                    Install-Module -Name $mod.Name -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                    Import-Module $mod.Name -ErrorAction Stop
                    Write-Host "  ✓ $($mod.Name) installed successfully" -ForegroundColor Green
                }
                catch {
                    Write-Host "  ✗ Failed to install $($mod.Name): $_" -ForegroundColor Red
                    return
                }
            }
            else {
                Write-Host "  Installation declined. Cannot proceed without $($mod.Name)." -ForegroundColor Yellow
                return
            }
        }
    }

    # .NET type for HTML encoding (used in HTML generation)
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    #------------------------------------------------------------------------ [ Auth check ]

    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext) {
        Write-Host "  ⚠ No active Azure session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $currentContext = Get-AzContext
    }

    $sessionInfo = @{
        TenantId    = $currentContext.Tenant.Id
        Account     = $currentContext.Account.Id
        Environment = $currentContext.Environment.Name
    }

    Write-Section -Title "Session Information" -Data @{
        "Tenant ID"   = $sessionInfo.TenantId
        "Account"     = $sessionInfo.Account
        "Environment" = $sessionInfo.Environment
    }

    #------------------------------------------------------------------------ [ Display parameters ]

    $expiresOnDisplay = $expiresOn.ToString("yyyy-MM-dd HH:mm:ss") + " UTC"

    Write-Section -Title "Run Parameters" -Data ([ordered]@{
            "Key Vaults"         = ($KeyVaultNames -join ", ")
            "Policy Assignments" = ($PolicyAssignments -join ", ")
            "Exemption Duration" = "$ExemptionDurationHours hour(s)"
            "Expires On (UTC)"   = $expiresOnDisplay
            "Exemption Category" = $ExemptionCategory
            "Name Prefix"        = if ($ExemptionNamePrefix) { $ExemptionNamePrefix } else { "None (auto)" }
            "Export to CSV"      = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
            "Justification"      = $Justification
        })

    #------------------------------------------------------------------------ [ Resolve Key Vaults ]

    Write-Host ""
    Write-Host "  Resolving Key Vaults" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $resolvedKVs = [System.Collections.Generic.List[psobject]]::new()

    foreach ($kvName in $KeyVaultNames) {
        try {
            $kv = Get-AzKeyVault -VaultName $kvName -ErrorAction Stop

            if (-not $kv) {
                throw "Key Vault not found or no read access."
            }

            Write-Host "  ✓ " -NoNewline -ForegroundColor Green
            Write-Host $kvName.PadRight(30) -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host $kv.ResourceId -ForegroundColor White

            $resolvedKVs.Add([pscustomobject]@{
                    Name       = $kvName
                    ResourceId = $kv.ResourceId
                    Location   = $kv.Location
                })
        }
        catch {
            Write-Host "  ✗ " -NoNewline -ForegroundColor Red
            Write-Host $kvName.PadRight(30) -NoNewline -ForegroundColor Red
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Failed to resolve: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    if ($resolvedKVs.Count -eq 0) {
        Write-Host ""
        Write-Host "  ✗ No Key Vaults could be resolved. Cannot proceed." -ForegroundColor Red
        Write-Host ("═" * 80) -ForegroundColor Cyan
        return
    }

    #------------------------------------------------------------------------ [ Resolve Policy Assignments ]

    Write-Host ""
    Write-Host "  Resolving Policy Assignments" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""

    $resolvedPolicies = [System.Collections.Generic.List[psobject]]::new()

    foreach ($pa in $PolicyAssignments) {
        try {
            $assignment = $null

            # Branch: full resource ID
            if ($pa -match '^/subscriptions/.+/providers/Microsoft\.Authorization/policyAssignments/.+$' -or
                $pa -match '^/providers/Microsoft\.Authorization/policyAssignments/.+$') {
                $assignment = Get-AzPolicyAssignment -Id $pa -ErrorAction Stop
            }
            else {
                # Resolve by display name — search across all subscriptions
                $allAssignments = Get-AzPolicyAssignment -IncludeDescendent -ErrorAction Stop | Where-Object { $_.DisplayName -eq $pa -or $_.Name -eq $pa }

                if (-not $allAssignments) {
                    throw "No policy assignment found with name or display name: '$pa'"
                }

                if (($allAssignments | Measure-Object).Count -gt 1) {
                    Write-Host "  ⚠ " -NoNewline -ForegroundColor Yellow
                    Write-Host "Multiple assignments match '$pa' — using first match. Use full Assignment ID to disambiguate." -ForegroundColor Yellow
                }

                $assignment = $allAssignments | Select-Object -First 1
            }

            $displayName = if ($assignment.DisplayName) {
                $assignment.DisplayName
            }
            else { $assignment.Name }

            Write-Host "  ✓ " -NoNewline -ForegroundColor Green
            Write-Host $pa.PadRight(40) -NoNewline -ForegroundColor Green
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
        catch {
            Write-Host "  ✗ " -NoNewline -ForegroundColor Red
            Write-Host $pa.PadRight(40) -NoNewline -ForegroundColor Red
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Failed to resolve: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    if ($resolvedPolicies.Count -eq 0) {
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

    foreach ($kv in $resolvedKVs) {
        try {
            # Get role assignments at the KV scope (includes inherited roles from RG/subscription/root)
            # then filter to the current account and check for roles known to carry policyExemptions/write
            $rolesWithPermission = @(
                "Owner",
                "User Access Administrator",
                "Resource Policy Contributor"
            )

            $currentUserRoles = Get-AzRoleAssignment -Scope $kv.ResourceId -ErrorAction Stop |
            Where-Object { $_.SignInName -eq $currentContext.Account.Id }

            $permitted = $currentUserRoles |
            Where-Object { $rolesWithPermission -contains $_.RoleDefinitionName }

            if ($permitted) {
                Write-Host "  ✓ " -NoNewline -ForegroundColor Green
                Write-Host $kv.Name.PadRight(30) -NoNewline -ForegroundColor Green
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "policyExemptions/write: Permitted" -ForegroundColor White
            }
            else {
                Write-Host "  ✗ " -NoNewline -ForegroundColor Red
                Write-Host $kv.Name.PadRight(30) -NoNewline -ForegroundColor Red
                Write-Host " → " -NoNewline -ForegroundColor DarkGray
                Write-Host "policyExemptions/write: DENIED — assign Owner, User Access Administrator, or Resource Policy Contributor." -ForegroundColor Red
                $permissionCheckPassed = $false
            }
        }
        catch {
            Write-Host "  ⚠ " -NoNewline -ForegroundColor Yellow
            Write-Host $kv.Name.PadRight(30) -NoNewline -ForegroundColor Yellow
            Write-Host " → " -NoNewline -ForegroundColor DarkGray
            Write-Host "Permission check could not be confirmed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Verbose "Get-AzRoleAssignment error for $($kv.Name): $_"
        }
    }

    if (-not $permissionCheckPassed) {
        Write-Host ""
        Write-Host "  ✗ One or more Key Vaults failed the permission pre-check." -ForegroundColor Red
        Write-Host "    Grant 'Microsoft.Authorization/policyExemptions/write' to your account" -ForegroundColor Red
        Write-Host "    at each Key Vault resource scope before retrying." -ForegroundColor Red
        Write-Host ("═" * 80) -ForegroundColor Cyan
        return
    }

    #------------------------------------------------------------------------ [ Confirmation prompt ]

    $totalAttempts = $resolvedKVs.Count * $resolvedPolicies.Count

    Write-Host ""
    Write-Host "  Exemption Plan" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  $totalAttempts exemption(s) will be created:" -ForegroundColor White
    Write-Host "    · $($resolvedKVs.Count) Key Vault(s) × $($resolvedPolicies.Count) Policy Assignment(s)" -ForegroundColor Gray
    Write-Host "    · Expires: $expiresOnDisplay" -ForegroundColor Gray
    Write-Host "    · Category: $ExemptionCategory" -ForegroundColor Gray
    Write-Host ""

    if (-not $Force -and -not $PSCmdlet.ShouldProcess(
            "Create $totalAttempts policy exemption(s) across $($resolvedKVs.Count) Key Vault(s)",
            "Confirm exemption creation?",
            "Azure Policy Exemption")) {
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

    $allResults = [System.Collections.Generic.List[psobject]]::new()
    $createdCount = 0
    $skippedCount = 0
    $failedCount = 0
    $currentIndex = 0
    $maxKVLength = ($resolvedKVs  | ForEach-Object { $_.Name.Length }  | Measure-Object -Maximum).Maximum
    $maxKVLength = [math]::Max($maxKVLength, 20)

    foreach ($kv in $resolvedKVs) {
        foreach ($policy in $resolvedPolicies) {
            $currentIndex++
            Write-ProgressBar -Current $currentIndex -Total $totalAttempts -CurrentItem "$($kv.Name) / $($policy.ShortName)"

            $exemptionName = Get-SafeExemptionName `
                -Prefix        $ExemptionNamePrefix `
                -KeyVaultName  $kv.Name `
                -PolicyShortName $policy.ShortName `
                -Timestamp     $timestamp

            try {
                # ── Idempotency guard ────────────────────────────────────────
                $existing = Get-AzPolicyExemption `
                    -Scope $kv.ResourceId `
                    -Name  $exemptionName `
                    -ErrorAction SilentlyContinue

                if ($existing -and $existing.Properties.ExpiresOn -gt (Get-Date).ToUniversalTime()) {
                    # Clear progress line
                    Write-Host "`r" -NoNewline
                    Write-Host (" " * 120) -NoNewline
                    Write-Host "`r" -NoNewline

                    Write-Host "  ⚠ " -NoNewline -ForegroundColor Yellow
                    Write-Host $kv.Name.PadRight($maxKVLength) -NoNewline -ForegroundColor Yellow
                    Write-Host " | " -NoNewline -ForegroundColor DarkGray
                    Write-Host $policy.ShortName.PadRight(30) -NoNewline -ForegroundColor Yellow
                    Write-Host " → Skipped (active exemption already exists)" -ForegroundColor DarkGray

                    $skippedCount++
                    $allResults.Add([pscustomobject]@{
                            KeyVaultName     = $kv.Name
                            KeyVaultId       = $kv.ResourceId
                            PolicyAssignment = $policy.DisplayName
                            PolicyId         = $policy.AssignmentId
                            ExemptionName    = $exemptionName
                            ExemptionId      = $existing.ResourceId
                            ExpiresOn        = $expiresOnDisplay
                            Category         = $ExemptionCategory
                            Status           = "Skipped"
                            Message          = "Active exemption already exists; no change made."
                            Justification    = $Justification
                        })
                    continue
                }

                # ── Create exemption ─────────────────────────────────────────
                $newExemption = New-AzPolicyExemption `
                    -Name              $exemptionName `
                    -Scope             $kv.ResourceId `
                    -PolicyAssignment  $policy.AssignmentObject `
                    -ExemptionCategory $ExemptionCategory `
                    -ExpiresOn         $expiresOn `
                    -Description       $Justification `
                    -DisplayName       $exemptionName `
                    -ErrorAction       Stop

                # Clear progress line
                Write-Host "`r" -NoNewline
                Write-Host (" " * 120) -NoNewline
                Write-Host "`r" -NoNewline

                Write-Host "  ✓ " -NoNewline -ForegroundColor Green
                Write-Host $kv.Name.PadRight($maxKVLength) -NoNewline -ForegroundColor Green
                Write-Host " | " -NoNewline -ForegroundColor DarkGray
                Write-Host $policy.ShortName.PadRight(30) -NoNewline -ForegroundColor Green
                Write-Host " → Created. Expires $expiresOnDisplay" -ForegroundColor White

                $createdCount++
                $allResults.Add([pscustomobject]@{
                        KeyVaultName     = $kv.Name
                        KeyVaultId       = $kv.ResourceId
                        PolicyAssignment = $policy.DisplayName
                        PolicyId         = $policy.AssignmentId
                        ExemptionName    = $exemptionName
                        ExemptionId      = $newExemption.ResourceId
                        ExpiresOn        = $expiresOnDisplay
                        Category         = $ExemptionCategory
                        Status           = "Created"
                        Message          = "Exemption created successfully."
                        Justification    = $Justification
                    })
            }
            catch {
                # Clear progress line
                Write-Host "`r" -NoNewline
                Write-Host (" " * 120) -NoNewline
                Write-Host "`r" -NoNewline

                Write-Host "  ✗ " -NoNewline -ForegroundColor Red
                Write-Host $kv.Name.PadRight($maxKVLength) -NoNewline -ForegroundColor Red
                Write-Host " | " -NoNewline -ForegroundColor DarkGray
                Write-Host $policy.ShortName.PadRight(30) -NoNewline -ForegroundColor Red
                Write-Host " → Failed: $($_.Exception.Message)" -ForegroundColor Red

                Write-Verbose "Full error for $($kv.Name) / $($policy.ShortName): $_"

                $failedCount++
                $allResults.Add([pscustomobject]@{
                        KeyVaultName     = $kv.Name
                        KeyVaultId       = $kv.ResourceId
                        PolicyAssignment = $policy.DisplayName
                        PolicyId         = $policy.AssignmentId
                        ExemptionName    = $exemptionName
                        ExemptionId      = ""
                        ExpiresOn        = $expiresOnDisplay
                        Category         = $ExemptionCategory
                        Status           = "Failed"
                        Message          = $_.Exception.Message
                        Justification    = $Justification
                    })
            }
        }
    }

    #------------------------------------------------------------------------ [ Summary ]

    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationStr = "{0:hh\:mm\:ss}" -f $duration

    Write-Summary -Data ([ordered]@{
            "Total Attempted"         = $totalAttempts
            "Created"                 = $createdCount
            "Skipped (already exist)" = $skippedCount
            "Failed"                  = $failedCount
            "Key Vaults Processed"    = $resolvedKVs.Count
            "Policies Applied"        = $resolvedPolicies.Count
            "Exemption Expires (UTC)" = $expiresOnDisplay
            "Execution Time"          = $durationStr
        })

    #------------------------------------------------------------------------ [ Outputs ]

    $csvExported = $false
    $htmlExported = $false
    $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')

    if ($allResults.Count -gt 0) {
        # CSV export
        if ($ExportToCsv) {
            try {
                $dir = Split-Path $CsvPath -Parent
                if ($dir -and -not (Test-Path $dir)) {
                    New-Item -ItemType Directory -Path $dir -Force | Out-Null
                }
                $allResults | Export-Csv -Path $CsvPath -NoTypeInformation -Force
                $csvExported = $true
            }
            catch {
                Write-Warning "CSV export failed: $_"
            }
        }

        # HTML report (always)
        try {
            $runParameters = @{
                KeyVaultCount       = $resolvedKVs.Count
                PolicyCount         = $resolvedPolicies.Count
                DurationHours       = $ExemptionDurationHours
                ExemptionCategory   = $ExemptionCategory
                ExemptionNamePrefix = $ExemptionNamePrefix
                ExpiresAt           = $expiresOnDisplay
                Justification       = $Justification
            }

            $runSummary = @{
                TotalAttempted     = $totalAttempts
                Created            = $createdCount
                Skipped            = $skippedCount
                Failed             = $failedCount
                KeyVaultsProcessed = $resolvedKVs.Count
                ExecutionTime      = $durationStr
            }

            $htmlContent = Generate-HtmlReport `
                -SessionInfo    $sessionInfo `
                -RunParameters  $runParameters `
                -RunSummary     $runSummary `
                -ExemptionResults $allResults `
                -HtmlPath       $htmlPath `
                -CsvPath        $(if ($csvExported) { $CsvPath } else { $null })

            $dir = Split-Path $htmlPath -Parent
            if ($dir -and -not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }

            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch {
            Write-Warning "HTML report generation failed: $_"
        }
    }

    if ($csvExported -or $htmlExported) {
        Write-OutputFiles `
            -CsvPath  $(if ($csvExported) { $CsvPath } else { $null }) `
            -HtmlPath $(if ($htmlExported) { $htmlPath } else { $null })
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
