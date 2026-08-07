<#

    Author       : Lakshmanan Thangaraj
    Version      : 1.0
    Created-On   : 07 August 2026
    Modified-On  : 07 August 2026

.SYNOPSIS
    Removes Azure RBAC role assignments for individual user accounts across one or
    more subscriptions, with full audit logging, pre-removal backup, and an
    auto-generated HTML summary report.

.DESCRIPTION
    The Remove-AzureRBACUserAssignments function removes Azure Role-Based Access
    Control (RBAC) assignments for User-type principals across one or multiple Azure
    subscriptions.

    It supports three input modes — all operating under the same scope rules:
      - Single or multiple UPNs via -UserPrincipalName
      - Bulk input via -BulkCsvPath (CSV with a required 'UserPrincipalName' column
        and an optional 'Scope' column)

    Scope behaviour (consistent across all input modes):
      - If a Scope is provided (via -Scope parameter or the CSV 'Scope' column),
        the script removes ONLY the assignment(s) at that exact scope for that user.
      - If no Scope is provided, the script removes ALL direct user RBAC assignments
        across the target subscriptions for that user.

    Safety features:
      - ShouldProcess / -WhatIf support — preview changes without making them.
      - Interactive confirmation (bypassed with -Force) before any removal begins.
      - Pre-removal backup of all affected user assignments (JSON + CSV).
      - Session-scoped audit log written in plain English from start to finish.
      - Companion Restore-AzureRBACUserAssignments function in the same file.
      - HTML summary report auto-generated at end of every run.

.PARAMETER UserPrincipalName
    One or more User Principal Names (UPNs / sign-in addresses) whose RBAC
    assignments should be removed. Supports a single string or a string array.
    Example: "alice@contoso.com" or @("alice@contoso.com","bob@contoso.com")

.PARAMETER Scope
    Optional. Azure resource scope path to restrict removal to a specific scope
    (e.g. "/subscriptions/00000000-.../resourceGroups/MyRG"). When provided,
    only assignments at exactly this scope are removed for the given user(s).
    When omitted, all direct assignments across target subscriptions are removed.
    This parameter applies to the -UserPrincipalName input mode only.

.PARAMETER BulkCsvPath
    Path to a CSV file with user removal targets. Required column: UserPrincipalName.
    Optional column: Scope (same semantics as the -Scope parameter, applied per row).
    Rows missing the Scope column (or with a blank Scope value) will have all direct
    assignments removed.

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account. This is
    the default if -SubscriptionIds is not supplied.

.PARAMETER SubscriptionIds
    String array of specific Azure subscription IDs to scan instead of all
    subscriptions. Ignored if -AllSubscriptions is also specified.

.PARAMETER OutputPath
    Folder path where the audit log, backup files, and HTML report are written.
    Defaults to C:\Temp. The folder is created automatically if it does not exist.

.PARAMETER Force
    Switch. Suppresses the interactive confirmation prompt before removals begin.
    Removals still respect -WhatIf if that switch is also used.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline. Writes:
      - Audit log    : <OutputPath>\AzureRBACRemoval-AuditLog-<timestamp>.txt
      - Backup JSON  : <OutputPath>\AzureRBACRemoval-Backup-<timestamp>.json
      - Backup CSV   : <OutputPath>\AzureRBACRemoval-Backup-<timestamp>.csv
      - HTML report  : <OutputPath>\AzureRBACRemoval-Report-<timestamp>.html

.EXAMPLE
    # Remove all RBAC assignments for a single user across all subscriptions
    Remove-AzureRBACUserAssignments -UserPrincipalName "alice@contoso.com" -AllSubscriptions

.EXAMPLE
    # Remove RBAC assignments for multiple users, with -WhatIf to preview first
    Remove-AzureRBACUserAssignments -UserPrincipalName @("alice@contoso.com","bob@contoso.com") `
        -AllSubscriptions -WhatIf

.EXAMPLE
    # Remove only a specific scope assignment for a user, skipping the confirm prompt
    Remove-AzureRBACUserAssignments -UserPrincipalName "alice@contoso.com" `
        -Scope "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/MyRG" `
        -AllSubscriptions -Force

.EXAMPLE
    # Bulk removal from a CSV file across specific subscriptions
    Remove-AzureRBACUserAssignments -BulkCsvPath "C:\Temp\UsersToRemove.csv" `
        -SubscriptionIds @("sub-id-1","sub-id-2")

.EXAMPLE
    # Restore from a previously created JSON backup
    Restore-AzureRBACUserAssignments -BackupJsonPath "C:\Temp\AzureRBACRemoval-Backup-20260807-143022.json"

.NOTES
─────────────────────────────────────────────────────────────────────────────
Version History:
─────────────────────────────────────────────────────────────────────────────
1.0 (07-Aug-2026) - Initial release. Supports single UPN, multi-UPN, and bulk
                    CSV input modes. Full audit logging, pre-removal JSON/CSV
                    backup, HTML summary report, WhatIf/Force/ShouldProcess
                    support, and companion Restore function.

─────────────────────────────────────────────────────────────────────────────
Pre-Requisites:
─────────────────────────────────────────────────────────────────────────────
1. Az PowerShell module (Az.Accounts, Az.Resources) — installed automatically
   with user consent if missing.
2. Authenticated Azure session — the script will call Connect-AzAccount if no
   active context is detected.
3. The executing account must have 'Microsoft.Authorization/roleAssignments/read'
   AND 'Microsoft.Authorization/roleAssignments/delete' permissions on each target
   subscription (typically: User Access Administrator or Owner role).
4. PowerShell 5.1 or later. No PS7-specific syntax is used.

─────────────────────────────────────────────────────────────────────────────
Known Limitations:
─────────────────────────────────────────────────────────────────────────────
- Only removes User-type principal assignments. Group and Service Principal
  assignments are intentionally skipped and logged as informational notices.
- Management Group scoped assignments are not in scope; they require elevated
  permissions and a separate API call. A warning is logged if detected.
- Default -OutputPath (C:\Temp) is a Windows-specific path. On macOS/Linux
  PowerShell 7, supply an explicit -OutputPath value.
- The -Scope parameter applies uniformly to all UPNs supplied via
  -UserPrincipalName. For per-user scope control, use -BulkCsvPath with a
  Scope column.
- Interactive Grid View for the results preview requires a GUI-capable session.
  In headless/CI/Linux environments this step is skipped gracefully.

.LINK
    https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-remove
    https://learn.microsoft.com/en-us/powershell/module/az.resources/remove-azroleassignment
    https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-list-powershell

#>


#region ── Helper Functions ────────────────────────────────────────────────────

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
    Write-CenteredText "Azure RBAC User Assignment Removal Tool v1.0" -Color White
    Write-CenteredText "Sensitive Operation  ·  All actions are logged and backed up" -Color Yellow
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
            $value      = "None"
            $valueColor = "DarkGray"
        }
        else
        {
            $valueColor = "White"
        }
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valueColor
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
    Write-Host ("  Progress: ") -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $percentage, $Current, $Total) -NoNewline -ForegroundColor White
    if ($CurrentItem)
    {
        $maxLength   = 35
        $displayItem = if ($CurrentItem.Length -gt $maxLength) { $CurrentItem.Substring(0, $maxLength - 3) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $displayItem -NoNewline -ForegroundColor Cyan
    }
}

Function Write-AuditLog
{
    <#
    .SYNOPSIS
        Writes a timestamped, plain-English audit log entry to both the console
        and the session log file. Layman-friendly wording is used throughout so
        the log is readable by any audience — not just technical staff.
    #>
    param(
        [string]$LogPath,
        [string]$Message,
        [ValidateSet("INFO","SUCCESS","WARNING","ERROR","HEADER","SEPARATOR")]
        [string]$Level = "INFO"
    )

    $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix     = switch ($Level)
    {
        "INFO"      { "[INFO     ]" }
        "SUCCESS"   { "[SUCCESS  ]" }
        "WARNING"   { "[WARNING  ]" }
        "ERROR"     { "[ERROR    ]" }
        "HEADER"    { "[========]" }
        "SEPARATOR" { "[--------]" }
    }

    $logLine = "$timestamp  $prefix  $Message"

    # Write to file
    if ($LogPath -and (Test-Path (Split-Path $LogPath -Parent)))
    {
        $logLine | Out-File -FilePath $LogPath -Append -Encoding UTF8 -WhatIf:$false
    }

    # Write to console with colour
    $consoleColor = switch ($Level)
    {
        "INFO"      { "Gray" }
        "SUCCESS"   { "Green" }
        "WARNING"   { "Yellow" }
        "ERROR"     { "Red" }
        "HEADER"    { "Cyan" }
        "SEPARATOR" { "DarkGray" }
    }
    Write-Host "  $logLine" -ForegroundColor $consoleColor
}

Function Write-AuditSeparator
{
    param([string]$LogPath)
    $line = "─" * 100
    if ($LogPath -and (Test-Path (Split-Path $LogPath -Parent)))
    {
        $line | Out-File -FilePath $LogPath -Append -Encoding UTF8 -WhatIf:$false
    }
    Write-Host "  $line" -ForegroundColor DarkGray
}

Function Write-SummaryTable
{
    param([hashtable]$Data)
    Write-Host ""
    Write-Host "  Removal Summary" -ForegroundColor Cyan
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
        [string]$LogPath,
        [string]$BackupJsonPath,
        [string]$BackupCsvPath,
        [string]$HtmlPath
    )
    Write-Host ""
    Write-Host "  Output Files" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray

    foreach ($entry in @(
        @{ Label = "Audit Log";    Path = $LogPath },
        @{ Label = "Backup JSON";  Path = $BackupJsonPath },
        @{ Label = "Backup CSV";   Path = $BackupCsvPath },
        @{ Label = "HTML Report";  Path = $HtmlPath }
    ))
    {
        if ($entry.Path)
        {
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host ($entry.Label).PadRight(18) -NoNewline -ForegroundColor Gray
            Write-Host ": " -NoNewline -ForegroundColor DarkGray
            Write-Host $entry.Path -ForegroundColor White
        }
    }

    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Get-ScopeLevel
{
    <#
    .SYNOPSIS
        Returns a human-readable scope level label from an Azure scope path.
        Used in the audit log and HTML report.
    #>
    param([string]$Scope)

    if ([string]::IsNullOrWhiteSpace($Scope))                                          { return "Unknown" }
    if ($Scope -like "/providers/Microsoft.Management/managementGroups/*")              { return "Management Group" }
    if ($Scope -match "^/subscriptions/[^/]+$")                                        { return "Subscription" }
    if ($Scope -match "^/subscriptions/[^/]+/resourceGroups/[^/]+$")                  { return "Resource Group" }
    if ($Scope -match "^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/")        { return "Resource" }
    return "Unknown"
}

Function ConvertTo-JsonSafeString
{
    <#
    .SYNOPSIS
        Escapes a string for safe injection into an inline JSON literal
        inside a PowerShell here-string. Prevents XSS and broken JSON.
    #>
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    return $Value `
        -replace '\\',  '\\' `
        -replace '"',   '\"' `
        -replace "`r",  '' `
        -replace "`n",  '\n' `
        -replace "`t",  '\t' `
        -replace '<',   '\u003c' `
        -replace '>',   '\u003e' `
        -replace '&',   '\u0026'
}

Function Generate-RemovalHtmlReport
{
    <#
    .SYNOPSIS
        Builds a self-contained HTML report summarising the removal session.
        Follows the golden dashboard design theme (dark/light, sidebar, stat cards,
        sortable table, toast).
    #>
    param(
        [hashtable]$SessionInfo,
        [hashtable]$RunParameters,
        [hashtable]$RunSummary,
        [array]$RemovalResults,          # per-assignment outcome rows
        [array]$SkippedItems,            # items skipped (not User type, MG scope, etc.)
        [string]$LogPath,
        [string]$BackupJsonPath,
        [string]$BackupCsvPath,
        [string]$HtmlPath
    )

    $generatedAt = Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt"

    # ── Build per-assignment table rows (JSON for JS table) ──────────────────
    $rowsJson = "["
    foreach ($r in $RemovalResults)
    {
        $upn        = ConvertTo-JsonSafeString $r.UserPrincipalName
        $role       = ConvertTo-JsonSafeString $r.RoleDefinitionName
        $scope      = ConvertTo-JsonSafeString $r.Scope
        $scopeLevel = ConvertTo-JsonSafeString $r.ScopeLevel
        $sub        = ConvertTo-JsonSafeString $r.SubscriptionName
        $status     = ConvertTo-JsonSafeString $r.Status
        $mode       = ConvertTo-JsonSafeString $r.RemovalMode
        $reason     = ConvertTo-JsonSafeString $r.Reason
        $rowsJson  += "{`"upn`":`"$upn`",`"role`":`"$role`",`"scope`":`"$scope`",`"scopeLevel`":`"$scopeLevel`",`"sub`":`"$sub`",`"status`":`"$status`",`"mode`":`"$mode`",`"reason`":`"$reason`"},"
    }
    $rowsJson = $rowsJson.TrimEnd(",") + "]"

    # ── Build skipped rows (JSON) ────────────────────────────────────────────
    $skippedJson = "["
    foreach ($s in $SkippedItems)
    {
        $upn         = ConvertTo-JsonSafeString $s.UserPrincipalName
        $role        = ConvertTo-JsonSafeString $s.RoleDefinitionName
        $scope       = ConvertTo-JsonSafeString $s.Scope
        $reason      = ConvertTo-JsonSafeString $s.Reason
        $skippedJson += "{`"upn`":`"$upn`",`"role`":`"$role`",`"scope`":`"$scope`",`"reason`":`"$reason`"},"
    }
    $skippedJson = $skippedJson.TrimEnd(",") + "]"

    # ── Run parameters block (plain text for display) ────────────────────────
    $scopeMode       = ConvertTo-JsonSafeString $RunParameters.ScopeMode
    $inputMode       = ConvertTo-JsonSafeString $RunParameters.InputMode
    $subscriptionTgt = ConvertTo-JsonSafeString $RunParameters.SubscriptionTarget
    $whatIfMode      = ConvertTo-JsonSafeString $RunParameters.WhatIfMode
    $outputFolder    = ConvertTo-JsonSafeString $RunParameters.OutputFolder
    $logPathSafe     = ConvertTo-JsonSafeString $LogPath
    $backupJsonSafe  = ConvertTo-JsonSafeString $BackupJsonPath
    $backupCsvSafe   = ConvertTo-JsonSafeString $BackupCsvPath
    $htmlPathSafe    = ConvertTo-JsonSafeString $HtmlPath
    $tenantSafe      = ConvertTo-JsonSafeString $SessionInfo.Tenant
    $accountSafe     = ConvertTo-JsonSafeString $SessionInfo.Account
    $envSafe         = ConvertTo-JsonSafeString $SessionInfo.Environment
    $startSafe       = ConvertTo-JsonSafeString $RunSummary.StartTime
    $endSafe         = ConvertTo-JsonSafeString $RunSummary.EndTime
    $durationSafe    = ConvertTo-JsonSafeString $RunSummary.Duration

    $totalProcessed  = $RunSummary.TotalProcessed
    $totalRemoved    = $RunSummary.TotalRemoved
    $totalSkipped    = $RunSummary.TotalSkipped
    $totalFailed     = $RunSummary.TotalFailed
    $totalWhatIf     = $RunSummary.TotalWhatIf
    $uniqueUsers     = $RunSummary.UniqueUsers
    $uniqueSubs      = $RunSummary.UniqueSubscriptions

    # ── HTML template (single-quoted here-string, tokens replaced below) ─────
    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azure RBAC Removal — Session Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
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
body{font-family:var(--sans);background:var(--bg);color:var(--text);display:flex;min-height:100vh;}
#sidebar{width:236px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);
  position:fixed;left:0;top:0;bottom:0;display:flex;flex-direction:column;z-index:100;}
.logo-block{padding:20px 16px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:36px;height:36px;border-radius:8px;
  background:linear-gradient(135deg,var(--red),var(--amber));
  display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;letter-spacing:.3px;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{display:inline-block;background:var(--surface3);color:var(--accent);
  font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:20px;
  border:1px solid var(--border);margin-top:8px;}
nav{flex:1;padding:12px 8px;overflow-y:auto;}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 12px;
  border:none;background:transparent;color:var(--muted2);cursor:pointer;
  border-radius:var(--radius-sm);font-size:13px;text-align:left;transition:all .15s;}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:var(--surface3);color:var(--accent);
  box-shadow:inset 3px 0 0 var(--accent);}
.nav-icon{font-size:15px;width:20px;text-align:center;}
.theme-row{padding:12px 16px;border-top:1px solid var(--border);}
.theme-label{font-size:11px;color:var(--muted);margin-bottom:6px;}
.theme-pill{display:flex;background:var(--surface2);border-radius:20px;
  border:1px solid var(--border);padding:3px;gap:3px;}
.theme-opt{flex:1;padding:5px 0;border:none;background:transparent;color:var(--muted);
  border-radius:16px;cursor:pointer;font-size:11px;transition:all .15s;}
.theme-opt.active{background:var(--accent);color:#fff;}
.sidebar-foot{padding:10px 16px 14px;border-top:1px solid var(--border);font-size:10px;color:var(--muted);}
#main{margin-left:236px;flex:1;min-height:100vh;}
.page{display:none;padding:28px 32px;animation:fadeIn .25s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:24px;}
.page-title{font-size:22px;font-weight:700;}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;border-top:3px solid transparent;transition:transform .15s;cursor:default;}
.stat-card:hover{transform:translateY(-2px);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-card.c-cyan{border-top-color:var(--accent2);}
.stat-num{font-family:var(--mono);font-size:32px;font-weight:700;line-height:1;}
.stat-lbl{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.5px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;margin-bottom:20px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;color:var(--accent2);}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;}
.info-item{background:var(--surface2);border-radius:var(--radius-sm);padding:14px;}
.info-label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:5px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-family:var(--mono);}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.badge-purple{background:rgba(163,113,247,.15);color:var(--accent3);border:1px solid rgba(163,113,247,.3);}
.badge-muted{background:var(--surface2);color:var(--muted);border:1px solid var(--border);}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;}
.search-wrap input{width:100%;background:var(--surface2);border:1px solid var(--border);
  color:var(--text);border-radius:var(--radius-sm);padding:8px 12px 8px 34px;font-size:13px;}
.search-wrap input:focus{outline:none;border-color:var(--accent);}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:14px;}
.filter-btn{padding:7px 14px;background:var(--surface2);border:1px solid var(--border);
  color:var(--muted2);border-radius:var(--radius-sm);cursor:pointer;font-size:12px;transition:all .15s;}
.filter-btn.active,.filter-btn:hover{background:var(--accent);color:#fff;border-color:var(--accent);}
table{width:100%;border-collapse:collapse;font-size:12.5px;}
th{background:var(--surface2);color:var(--muted);text-transform:uppercase;letter-spacing:.5px;
  font-size:10.5px;padding:10px 12px;text-align:left;cursor:pointer;user-select:none;
  position:sticky;top:0;z-index:5;}
th:hover{color:var(--text);}
.sort-arrow{font-size:9px;margin-left:4px;opacity:.5;}
.sort-active .sort-arrow{opacity:1;color:var(--accent);}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:middle;}
tr:last-child td{border-bottom:none;}
tr:hover td{background:var(--surface2);}
.table-wrap{overflow-x:auto;border-radius:var(--radius-sm);border:1px solid var(--border);}
.upn-cell{font-family:var(--mono);font-size:11.5px;color:var(--accent2);}
.scope-cell{font-family:var(--mono);font-size:10.5px;color:var(--muted2);max-width:320px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:help;}
.pagination{display:flex;align-items:center;gap:8px;margin-top:14px;font-size:12px;color:var(--muted);}
.pg-btn{padding:5px 10px;background:var(--surface2);border:1px solid var(--border);
  color:var(--muted2);border-radius:var(--radius-sm);cursor:pointer;font-size:11px;}
.pg-btn:hover{border-color:var(--accent);color:var(--accent);}
.pg-btn:disabled{opacity:.35;cursor:default;}
.pg-info{flex:1;}
select.pg-size{background:var(--surface2);border:1px solid var(--border);
  color:var(--text);border-radius:var(--radius-sm);padding:4px 8px;font-size:11px;}
.no-data{padding:40px;text-align:center;color:var(--muted);}
.file-list{display:flex;flex-direction:column;gap:10px;}
.file-item{display:flex;align-items:center;gap:14px;background:var(--surface2);
  border-radius:var(--radius-sm);padding:14px;}
.file-icon{font-size:22px;}
.file-details .file-label{font-size:11px;color:var(--muted);margin-bottom:3px;}
.file-details .file-path{font-family:var(--mono);font-size:12px;word-break:break-all;}
.warn-box{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.25);
  border-radius:var(--radius-sm);padding:14px 16px;margin-bottom:16px;
  font-size:12.5px;color:var(--amber);}
#toast{position:fixed;bottom:24px;right:24px;background:var(--surface3);
  border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:12px 18px;font-size:13px;box-shadow:var(--shadow);
  opacity:0;transform:translateY(10px);transition:all .25s;pointer-events:none;z-index:9999;}
#toast.show{opacity:1;transform:none;}
#menuToggle{display:none;position:fixed;top:14px;left:14px;z-index:200;
  background:var(--surface);border:1px solid var(--border);border-radius:6px;
  padding:7px 10px;cursor:pointer;font-size:16px;}
@media(max-width:768px){
  #sidebar{transform:translateX(-100%);transition:transform .2s;}
  #sidebar.open{transform:none;}
  #main{margin-left:0;}
  #menuToggle{display:block;}
  .page{padding:16px;}
}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<div id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🔑</div>
    <div class="logo-title">RBAC Removal</div>
    <div class="logo-sub">Session Report</div>
    <div class="version-badge">v1.0</div>
  </div>
  <nav>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">📊</span>Overview
    </button>
    <button class="nav-btn" onclick="showPage('removals',this)">
      <span class="nav-icon">🗑️</span>Removal Results
    </button>
    <button class="nav-btn" onclick="showPage('skipped',this)">
      <span class="nav-icon">⚠️</span>Skipped Items
    </button>
    <button class="nav-btn" onclick="showPage('session',this)">
      <span class="nav-icon">🔐</span>Session &amp; Files
    </button>
  </nav>
  <div class="theme-row">
    <div class="theme-label">Theme</div>
    <div class="theme-pill">
      <button class="theme-opt active" id="btn-dark"  onclick="setTheme('dark')">Dark</button>
      <button class="theme-opt"        id="btn-light" onclick="setTheme('light')">Light</button>
    </div>
  </div>
  <div class="sidebar-foot">Generated __GENERATED_AT__</div>
</div>

<div id="main">

  <!-- ── OVERVIEW ──────────────────────────────────────────────────────── -->
  <div class="page active" id="page-overview">
    <div class="page-header">
      <div class="page-title">Session Overview</div>
      <div class="page-sub">Summary of the RBAC removal session run on __GENERATED_AT__</div>
    </div>

    <div id="whatif-warn" style="display:none" class="warn-box">
      ⚠ This session ran in <strong>WhatIf / Preview Mode</strong>. No assignments
      were actually removed. The results below show what <em>would have been</em> removed.
    </div>

    <div class="stats-grid">
      <div class="stat-card c-blue">
        <div class="stat-num" id="s-processed">__TOTAL_PROCESSED__</div>
        <div class="stat-lbl">Assignments Evaluated</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num" id="s-removed">__TOTAL_REMOVED__</div>
        <div class="stat-lbl">Assignments Removed</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num" id="s-skipped">__TOTAL_SKIPPED__</div>
        <div class="stat-lbl">Items Skipped</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-num" id="s-failed">__TOTAL_FAILED__</div>
        <div class="stat-lbl">Errors</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-num" id="s-whatif">__TOTAL_WHATIF__</div>
        <div class="stat-lbl">WhatIf (Preview Only)</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-num" id="s-users">__UNIQUE_USERS__</div>
        <div class="stat-lbl">Unique Users Targeted</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">⚙️ Run Parameters</div>
      <div class="info-grid">
        <div class="info-item">
          <div class="info-label">Input Mode</div>
          <div class="info-value">__INPUT_MODE__</div>
        </div>
        <div class="info-item">
          <div class="info-label">Scope Mode</div>
          <div class="info-value">__SCOPE_MODE__</div>
        </div>
        <div class="info-item">
          <div class="info-label">Subscription Target</div>
          <div class="info-value">__SUBSCRIPTION_TARGET__</div>
        </div>
        <div class="info-item">
          <div class="info-label">WhatIf Mode</div>
          <div class="info-value">__WHATIF_MODE__</div>
        </div>
        <div class="info-item">
          <div class="info-label">Subscriptions Scanned</div>
          <div class="info-value">__UNIQUE_SUBS__</div>
        </div>
        <div class="info-item">
          <div class="info-label">Duration</div>
          <div class="info-value">__DURATION__</div>
        </div>
        <div class="info-item">
          <div class="info-label">Start Time</div>
          <div class="info-value">__START_TIME__</div>
        </div>
        <div class="info-item">
          <div class="info-label">End Time</div>
          <div class="info-value">__END_TIME__</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── REMOVAL RESULTS ────────────────────────────────────────────────── -->
  <div class="page" id="page-removals">
    <div class="page-header">
      <div class="page-title">Removal Results</div>
      <div class="page-sub">All assignments that were evaluated for removal — one row per assignment</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="rem-search" placeholder="Search by user, role, scope…"
                 oninput="filterRemTable()">
        </div>
        <button class="filter-btn active" onclick="remFilter('all',this)">All</button>
        <button class="filter-btn" onclick="remFilter('Removed',this)">Removed</button>
        <button class="filter-btn" onclick="remFilter('WhatIf',this)">WhatIf</button>
        <button class="filter-btn" onclick="remFilter('Failed',this)">Failed</button>
      </div>
      <div class="table-wrap">
        <table id="rem-table">
          <thead>
            <tr>
              <th onclick="sortRemTable(0)">User <span class="sort-arrow">⇅</span></th>
              <th onclick="sortRemTable(1)">Role <span class="sort-arrow">⇅</span></th>
              <th onclick="sortRemTable(2)">Scope Level <span class="sort-arrow">⇅</span></th>
              <th onclick="sortRemTable(3)">Subscription <span class="sort-arrow">⇅</span></th>
              <th onclick="sortRemTable(4)">Removal Mode <span class="sort-arrow">⇅</span></th>
              <th onclick="sortRemTable(5)">Status <span class="sort-arrow">⇅</span></th>
              <th>Scope Path</th>
            </tr>
          </thead>
          <tbody id="rem-tbody"></tbody>
        </table>
      </div>
      <div class="pagination">
        <button class="pg-btn" id="rem-prev" onclick="remPage(-1)">◀ Prev</button>
        <span class="pg-info" id="rem-pg-info"></span>
        <select class="pg-size" id="rem-size" onchange="remSizeChange()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
        <button class="pg-btn" id="rem-next" onclick="remPage(1)">Next ▶</button>
      </div>
    </div>
  </div>

  <!-- ── SKIPPED ────────────────────────────────────────────────────────── -->
  <div class="page" id="page-skipped">
    <div class="page-header">
      <div class="page-title">Skipped Items</div>
      <div class="page-sub">Assignments found but not removed — reason recorded for each</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="skip-search" placeholder="Search skipped items…"
                 oninput="filterSkipTable()">
        </div>
      </div>
      <div class="table-wrap">
        <table id="skip-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>Scope</th>
              <th>Reason Skipped</th>
            </tr>
          </thead>
          <tbody id="skip-tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── SESSION & FILES ────────────────────────────────────────────────── -->
  <div class="page" id="page-session">
    <div class="page-header">
      <div class="page-title">Session Info &amp; Output Files</div>
      <div class="page-sub">Authentication context and all files written during this session</div>
    </div>
    <div class="panel">
      <div class="panel-title">🔐 Authentication Context</div>
      <div class="info-grid">
        <div class="info-item">
          <div class="info-label">Tenant ID</div>
          <div class="info-value">__TENANT__</div>
        </div>
        <div class="info-item">
          <div class="info-label">Account</div>
          <div class="info-value">__ACCOUNT__</div>
        </div>
        <div class="info-item">
          <div class="info-label">Environment</div>
          <div class="info-value">__ENVIRONMENT__</div>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">📁 Output Files</div>
      <div class="file-list">
        <div class="file-item">
          <div class="file-icon">📋</div>
          <div class="file-details">
            <div class="file-label">Audit Log — full plain-English record of the session</div>
            <div class="file-path">__LOG_PATH__</div>
          </div>
        </div>
        <div class="file-item">
          <div class="file-icon">💾</div>
          <div class="file-details">
            <div class="file-label">Backup JSON — machine-readable backup of all removed assignments (for restore)</div>
            <div class="file-path">__BACKUP_JSON__</div>
          </div>
        </div>
        <div class="file-item">
          <div class="file-icon">📊</div>
          <div class="file-details">
            <div class="file-label">Backup CSV — human-readable backup of all removed assignments</div>
            <div class="file-path">__BACKUP_CSV__</div>
          </div>
        </div>
        <div class="file-item">
          <div class="file-icon">🌐</div>
          <div class="file-details">
            <div class="file-label">HTML Report — this report file</div>
            <div class="file-path">__HTML_PATH__</div>
          </div>
        </div>
      </div>
    </div>
  </div>

</div>

<div id="toast"></div>

<script>
// ── Data injected from PowerShell ─────────────────────────────────────────
const ROWS    = __ROWS_JSON__;
const SKIPPED = __SKIPPED_JSON__;
const WHATIF  = __WHATIF_FLAG__;

// ── Bootstrap ─────────────────────────────────────────────────────────────
if (WHATIF) { document.getElementById('whatif-warn').style.display='block'; }

function escH(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// Theme
function setTheme(t){
  document.body.classList.toggle('light-theme', t==='light');
  document.getElementById('btn-dark').classList.toggle('active',  t==='dark');
  document.getElementById('btn-light').classList.toggle('active', t==='light');
  localStorage.setItem('rbac-theme', t);
}
(function(){ const t=localStorage.getItem('rbac-theme'); if(t) setTheme(t); })();

// Page nav
function showPage(id, btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
}

// Toast
function showToast(msg,icon='✓'){
  const t=document.getElementById('toast');
  t.textContent=(icon+' '+msg);
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2500);
}

// ── Removal table ─────────────────────────────────────────────────────────
let remFiltered=ROWS, remCurPage=1, remPageSize=25, remSortCol=-1, remSortAsc=true;
let remActiveFilter='all';

function statusBadge(s){
  if(s==='Removed') return '<span class="badge badge-green">Removed</span>';
  if(s==='WhatIf')  return '<span class="badge badge-blue">WhatIf</span>';
  if(s==='Failed')  return '<span class="badge badge-red">Failed</span>';
  return '<span class="badge badge-muted">'+escH(s)+'</span>';
}
function modeBadge(m){
  if(m==='Full')          return '<span class="badge badge-amber">Full Removal</span>';
  if(m==='Scope-Specific')return '<span class="badge badge-purple">Scope-Specific</span>';
  return '<span class="badge badge-muted">'+escH(m)+'</span>';
}

function remFilter(f,btn){
  remActiveFilter=f;
  document.querySelectorAll('#page-removals .filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  applyRemFilters();
}
function filterRemTable(){ applyRemFilters(); }
function applyRemFilters(){
  const q=(document.getElementById('rem-search').value||'').toLowerCase();
  remFiltered=ROWS.filter(r=>{
    const match = remActiveFilter==='all' || r.status===remActiveFilter;
    const txt   = (r.upn+r.role+r.scope+r.sub+r.status+r.mode).toLowerCase();
    return match && (!q || txt.includes(q));
  });
  remCurPage=1;
  renderRemTable();
}

function renderRemTable(){
  const tbody=document.getElementById('rem-tbody');
  const start=(remCurPage-1)*remPageSize, end=start+remPageSize;
  const page=remFiltered.slice(start,end);
  if(!page.length){ tbody.innerHTML='<tr><td colspan="7" class="no-data">No matching results.</td></tr>'; }
  else{
    tbody.innerHTML=page.map(r=>`
      <tr>
        <td class="upn-cell">${escH(r.upn)}</td>
        <td>${escH(r.role)}</td>
        <td>${escH(r.scopeLevel)}</td>
        <td>${escH(r.sub)}</td>
        <td>${modeBadge(r.mode)}</td>
        <td>${statusBadge(r.status)}</td>
        <td><span class="scope-cell" title="${escH(r.scope)}">${escH(r.scope)}</span></td>
      </tr>`).join('');
  }
  const total=remFiltered.length, pages=Math.max(1,Math.ceil(total/remPageSize));
  document.getElementById('rem-pg-info').textContent=
    `Page ${remCurPage} of ${pages}  (${total} assignments)`;
  document.getElementById('rem-prev').disabled=remCurPage<=1;
  document.getElementById('rem-next').disabled=remCurPage>=pages;
}
function remPage(d){ remCurPage+=d; renderRemTable(); }
function remSizeChange(){ remPageSize=+document.getElementById('rem-size').value; remCurPage=1; renderRemTable(); }

function sortRemTable(col){
  const cols=['upn','role','scopeLevel','sub','mode','status'];
  if(remSortCol===col) remSortAsc=!remSortAsc; else { remSortCol=col; remSortAsc=true; }
  remFiltered.sort((a,b)=>{
    const av=a[cols[col]]||'', bv=b[cols[col]]||'';
    return remSortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  renderRemTable();
}

// ── Skipped table ──────────────────────────────────────────────────────────
function filterSkipTable(){
  const q=(document.getElementById('skip-search').value||'').toLowerCase();
  const rows=SKIPPED.filter(r=>(r.upn+r.role+r.scope+r.reason).toLowerCase().includes(q));
  const tbody=document.getElementById('skip-tbody');
  if(!rows.length){ tbody.innerHTML='<tr><td colspan="4" class="no-data">No skipped items.</td></tr>'; }
  else{
    tbody.innerHTML=rows.map(r=>`
      <tr>
        <td class="upn-cell">${escH(r.upn)}</td>
        <td>${escH(r.role)}</td>
        <td><span class="scope-cell" title="${escH(r.scope)}">${escH(r.scope)}</span></td>
        <td><span class="badge badge-amber">${escH(r.reason)}</span></td>
      </tr>`).join('');
  }
}

// Init
applyRemFilters();
filterSkipTable();

// Keyboard shortcuts
document.addEventListener('keydown',e=>{
  if(e.key==='/' && document.activeElement.tagName!=='INPUT'){
    e.preventDefault();
    const a=document.querySelector('.page.active');
    const inp=a && a.querySelector('input[type="text"]');
    if(inp) inp.focus();
  }
  if(e.key==='Escape') document.getElementById('sidebar').classList.remove('open');
});
</script>
</body>
</html>
'@

    # ── Token substitution ───────────────────────────────────────────────────
    $whatIfFlag = if ($RunParameters.WhatIfMode -eq "Enabled") { "true" } else { "false" }

    $html = $html `
        -replace '__GENERATED_AT__',       $generatedAt `
        -replace '__TOTAL_PROCESSED__',    $totalProcessed `
        -replace '__TOTAL_REMOVED__',      $totalRemoved `
        -replace '__TOTAL_SKIPPED__',      $totalSkipped `
        -replace '__TOTAL_FAILED__',       $totalFailed `
        -replace '__TOTAL_WHATIF__',       $totalWhatIf `
        -replace '__UNIQUE_USERS__',       $uniqueUsers `
        -replace '__UNIQUE_SUBS__',        $uniqueSubs `
        -replace '__INPUT_MODE__',         $inputMode `
        -replace '__SCOPE_MODE__',         $scopeMode `
        -replace '__SUBSCRIPTION_TARGET__',$subscriptionTgt `
        -replace '__WHATIF_MODE__',        $whatIfMode `
        -replace '__DURATION__',           $durationSafe `
        -replace '__START_TIME__',         $startSafe `
        -replace '__END_TIME__',           $endSafe `
        -replace '__TENANT__',             $tenantSafe `
        -replace '__ACCOUNT__',            $accountSafe `
        -replace '__ENVIRONMENT__',        $envSafe `
        -replace '__LOG_PATH__',           $logPathSafe `
        -replace '__BACKUP_JSON__',        $backupJsonSafe `
        -replace '__BACKUP_CSV__',         $backupCsvSafe `
        -replace '__HTML_PATH__',          $htmlPathSafe `
        -replace '__ROWS_JSON__',          $rowsJson `
        -replace '__SKIPPED_JSON__',       $skippedJson `
        -replace '__WHATIF_FLAG__',        $whatIfFlag

    return $html
}

#endregion ── Helper Functions ─────────────────────────────────────────────────


#region ── Main Removal Function ───────────────────────────────────────────────

Function Remove-AzureRBACUserAssignments
{
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        # ── Input mode A: one or more UPNs directly ──────────────────────────
        [Parameter(ParameterSetName = 'UPN', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserPrincipalName,

        # ── Optional scope filter for UPN mode ───────────────────────────────
        [Parameter(ParameterSetName = 'UPN', Mandatory = $false)]
        [string]$Scope,

        # ── Input mode B: bulk CSV ────────────────────────────────────────────
        [Parameter(ParameterSetName = 'Bulk', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BulkCsvPath,

        # ── Subscription targeting ────────────────────────────────────────────
        [switch]$AllSubscriptions,

        [ValidateNotNullOrEmpty()]
        [string[]]$SubscriptionIds,

        # ── Output / behaviour ────────────────────────────────────────────────
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = "C:\Temp",

        [switch]$Force
    )

    $startTime    = Get-Date
    $sessionStamp = $startTime.ToString("yyyyMMdd-HHmmss")

    # ── Validate and prepare output folder ───────────────────────────────────
    if ($OutputPath -match '[<>"|?*]')
    {
        Write-Error "OutputPath contains invalid characters. Please provide a valid folder path."
        return
    }

    try
    {
        if (-not (Test-Path $OutputPath))
        {
            New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
        }
    }
    catch
    {
        Write-Error "Could not create or access OutputPath '$OutputPath': $_"
        return
    }

    # ── File paths (all session-stamped to avoid overwrites) ─────────────────
    $logPath       = Join-Path $OutputPath "AzureRBACRemoval-AuditLog-$sessionStamp.txt"
    $backupJsonPath= Join-Path $OutputPath "AzureRBACRemoval-Backup-$sessionStamp.json"
    $backupCsvPath = Join-Path $OutputPath "AzureRBACRemoval-Backup-$sessionStamp.csv"
    $htmlPath      = Join-Path $OutputPath "AzureRBACRemoval-Report-$sessionStamp.html"

    # ── Banner ────────────────────────────────────────────────────────────────
    Write-Banner

    # ── Open audit log ────────────────────────────────────────────────────────
    "AZURE RBAC USER ASSIGNMENT REMOVAL — AUDIT LOG" | Out-File -FilePath $logPath -Encoding UTF8 -Force -WhatIf:$false
    ("=" * 100) | Out-File -FilePath $logPath -Append -Encoding UTF8 -WhatIf:$false

    Write-AuditLog -LogPath $logPath -Level HEADER `
        -Message "SESSION STARTED — Azure RBAC User Assignment Removal Tool v1.0"
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "This log records every action taken during this session in plain language."
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "It can be used as an audit trail by technical and non-technical reviewers alike."
    Write-AuditSeparator -LogPath $logPath

    # ── Az module check ───────────────────────────────────────────────────────
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Checking whether the required Azure PowerShell module (Az) is installed on this machine."

    $azAccountsOk  = Get-Module -ListAvailable -Name Az.Accounts  -ErrorAction SilentlyContinue
    $azResourcesOk = Get-Module -ListAvailable -Name Az.Resources -ErrorAction SilentlyContinue

    if (-not $azAccountsOk -or -not $azResourcesOk)
    {
        Write-Host ""
        Write-Host "  ⚠  Az module not found." -ForegroundColor Yellow
        Write-Host ""
        $installAz = Read-Host "  Install Az module now? (Y/N)"
        if ($installAz -eq 'Y' -or $installAz -eq 'y')
        {
            try
            {
                Write-Host ""
                Write-Host "  Installing Az module, please wait..." -ForegroundColor Cyan
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "  ✓ Az module installed successfully." -ForegroundColor Green
                Write-AuditLog -LogPath $logPath -Level SUCCESS `
                    -Message "Az PowerShell module was not present — it was installed successfully at the operator's request."
            }
            catch
            {
                Write-AuditLog -LogPath $logPath -Level ERROR `
                    -Message "Az module installation failed: $_  The session cannot continue without this module."
                Write-Error "Az module installation failed: $_"
                return
            }
        }
        else
        {
            Write-AuditLog -LogPath $logPath -Level ERROR `
                -Message "The operator declined to install the Az module. The session cannot continue."
            Write-Host "  Installation declined. Cannot proceed without Az module." -ForegroundColor Yellow
            return
        }
    }
    else
    {
        Write-AuditLog -LogPath $logPath -Level SUCCESS `
            -Message "Az PowerShell module is present on this machine. No installation needed."
    }

    # ── Azure authentication ──────────────────────────────────────────────────
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Checking whether there is an active, authenticated Azure session."

    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext)
    {
        Write-Host ""
        Write-Host "  ⚠  No active Azure session found. Starting sign-in..." -ForegroundColor Yellow
        Write-AuditLog -LogPath $logPath -Level INFO `
            -Message "No active Azure session was found. The tool is now prompting the operator to sign in."
        try
        {
            Connect-AzAccount -WarningAction SilentlyContinue -ErrorAction Stop
            $currentContext = Get-AzContext -ErrorAction Stop
            Write-AuditLog -LogPath $logPath -Level SUCCESS `
                -Message "Sign-in completed successfully. Authenticated as: $($currentContext.Account.Id)  |  Tenant: $($currentContext.Tenant.Id)"
        }
        catch
        {
            Write-AuditLog -LogPath $logPath -Level ERROR `
                -Message "Azure sign-in failed: $_  The session cannot continue without a valid authenticated account."
            Write-Error "Azure sign-in failed: $_"
            return
        }
    }
    else
    {
        Write-AuditLog -LogPath $logPath -Level SUCCESS `
            -Message "An active Azure session is already present. Signed in as: $($currentContext.Account.Id)  |  Tenant: $($currentContext.Tenant.Id)"
    }

    # ── Determine subscriptions ────────────────────────────────────────────────
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Determining which Azure subscriptions will be scanned for RBAC assignments to remove."

    if ($AllSubscriptions -or -not $SubscriptionIds)
    {
        $subscriptions  = @(Get-AzSubscription -WarningAction SilentlyContinue)
        $scopeText      = "All Subscriptions"
    }
    else
    {
        $subscriptions  = @(Get-AzSubscription -WarningAction SilentlyContinue |
                            Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText      = "Specific Subscriptions ($($SubscriptionIds.Count) requested)"
    }

    $subscriptionCount = @($subscriptions).Count

    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Scope: $scopeText.  Subscriptions found and accessible: $subscriptionCount."

    if ($subscriptionCount -eq 0)
    {
        Write-AuditLog -LogPath $logPath -Level ERROR `
            -Message "No accessible subscriptions were found. Please check your permissions and try again."
        Write-Host "  ✗  No subscriptions accessible. Check your Azure permissions." -ForegroundColor Red
        return
    }

    # ── Build target user list ─────────────────────────────────────────────────
    # Each entry: @{ UserPrincipalName = "...", Scope = "..." (can be empty) }
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Building the list of users to target based on the input provided."

    $targetList = @()
    $inputMode  = ""

    if ($PSCmdlet.ParameterSetName -eq 'UPN')
    {
        $inputMode = "UserPrincipalName parameter ($($UserPrincipalName.Count) UPN(s))"
        foreach ($upn in $UserPrincipalName)
        {
            $targetList += [pscustomobject]@{
                UserPrincipalName = $upn.Trim()
                Scope             = if ($PSBoundParameters.ContainsKey('Scope')) { $Scope } else { "" }
            }
            Write-AuditLog -LogPath $logPath -Level INFO `
                -Message "Target user added: '$($upn.Trim())'  |  Scope filter: $(if ($PSBoundParameters.ContainsKey('Scope')) { $Scope } else { 'None — all assignments will be removed' })"
        }
    }
    else   # Bulk CSV
    {
        $inputMode = "Bulk CSV file ($BulkCsvPath)"
        Write-AuditLog -LogPath $logPath -Level INFO `
            -Message "Reading the bulk input file: '$BulkCsvPath'."

        if (-not (Test-Path $BulkCsvPath))
        {
            Write-AuditLog -LogPath $logPath -Level ERROR `
                -Message "The bulk CSV file was not found at the path provided: '$BulkCsvPath'. Please check the path and try again."
            Write-Error "BulkCsvPath not found: $BulkCsvPath"
            return
        }

        try
        {
            $csvRows = Import-Csv -Path $BulkCsvPath -ErrorAction Stop
        }
        catch
        {
            Write-AuditLog -LogPath $logPath -Level ERROR `
                -Message "Failed to read the CSV file: $_"
            Write-Error "Failed to read BulkCsvPath: $_"
            return
        }

        if (-not ($csvRows | Get-Member -Name "UserPrincipalName" -ErrorAction SilentlyContinue))
        {
            Write-AuditLog -LogPath $logPath -Level ERROR `
                -Message "The CSV file is missing the required 'UserPrincipalName' column. Please add this column and try again."
            Write-Error "CSV is missing the required 'UserPrincipalName' column."
            return
        }

        $hasScopeColumn = ($csvRows | Get-Member -Name "Scope" -ErrorAction SilentlyContinue) -ne $null

        foreach ($row in $csvRows)
        {
            $upn   = $row.UserPrincipalName.Trim()
            $scope = if ($hasScopeColumn) { $row.Scope.Trim() } else { "" }
            if ([string]::IsNullOrWhiteSpace($upn)) { continue }
            $targetList += [pscustomobject]@{ UserPrincipalName = $upn; Scope = $scope }
            Write-AuditLog -LogPath $logPath -Level INFO `
                -Message "CSV row loaded — User: '$upn'  |  Scope filter: $(if ([string]::IsNullOrWhiteSpace($scope)) { 'None — all assignments will be removed' } else { $scope })"
        }

        Write-AuditLog -LogPath $logPath -Level SUCCESS `
            -Message "Bulk CSV loaded successfully.  $($targetList.Count) user entries to process."
    }

    # ── Display session parameters ─────────────────────────────────────────────
    $scopeMode = if (@($targetList | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Scope) }).Count -gt 0)
    {
        "Mixed (some users have a specific scope, others will have all assignments removed)"
    }
    else
    {
        "Full Removal — no scope filter applied (all direct user assignments will be removed)"
    }

    Write-Section -Title "Session Information" -Data @{
        "Tenant"          = $currentContext.Tenant.Id
        "Account"         = $currentContext.Account.Id
        "Environment"     = $currentContext.Environment.Name
    }

    Write-Section -Title "Removal Parameters" -Data @{
        "Input Mode"        = $inputMode
        "Target Users"      = "$($targetList.Count) user(s)"
        "Subscriptions"     = "$scopeText ($subscriptionCount found)"
        "Scope Mode"        = $scopeMode
        "WhatIf Mode"       = if ($PSBoundParameters.ContainsKey('WhatIf') -or $WhatIfPreference -eq 'Continue') { "ENABLED — preview only, nothing will be removed" } else { "Disabled — live removals will occur" }
        "Force"             = if ($Force.IsPresent) { "Enabled — confirmation prompt suppressed" } else { "Disabled — confirmation required" }
        "Output Folder"     = $OutputPath
    }

    Write-AuditSeparator -LogPath $logPath
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Total users targeted: $($targetList.Count).  Subscriptions in scope: $subscriptionCount.  Scope mode: $scopeMode."

    # ── Confirmation gate ──────────────────────────────────────────────────────
    if (-not $Force.IsPresent -and -not ($WhatIfPreference -eq 'Continue'))
    {
        Write-Host ""
        Write-Host ("  " + "─" * 76) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  ⚠  IMPORTANT — Please read before continuing" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  This operation will permanently remove Azure RBAC role assignments" -ForegroundColor White
        Write-Host "  for the users listed above across $subscriptionCount subscription(s)." -ForegroundColor White
        Write-Host ""
        Write-Host "  A backup of all assignments will be saved BEFORE any removal begins." -ForegroundColor Cyan
        Write-Host "  Use Restore-AzureRBACUserAssignments with the backup JSON to roll back." -ForegroundColor Cyan
        Write-Host ""
        $confirm = Read-Host "  Type 'YES' to proceed, or anything else to cancel"
        Write-Host ""

        if ($confirm -ne 'YES')
        {
            Write-AuditLog -LogPath $logPath -Level WARNING `
                -Message "The operator chose NOT to proceed when prompted for confirmation. Session cancelled — no assignments were removed."
            Write-Host "  Operation cancelled. No changes were made." -ForegroundColor Yellow
            Write-Host ""
            return
        }

        Write-AuditLog -LogPath $logPath -Level INFO `
            -Message "The operator confirmed they want to proceed. Entering the discovery and removal phase."
    }
    else
    {
        $reason = if ($Force.IsPresent) { "the -Force switch was used" } else { "WhatIf mode is active (preview only)" }
        Write-AuditLog -LogPath $logPath -Level INFO `
            -Message "Confirmation prompt was skipped because $reason."
    }

    # ── Phase 1: Discovery — find all matching assignments ────────────────────
    Write-Host ""
    Write-Host "  Phase 1: Discovering Assignments" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
    Write-AuditLog -LogPath $logPath -Level HEADER `
        -Message "PHASE 1 — DISCOVERY: Scanning subscriptions to find all RBAC assignments for the target users."

    $assignmentsToRemove = @()    # will be backed up and then removed
    $skippedItems        = @()    # found but will not be removed

    $subIndex = 1
    foreach ($sub in $subscriptions)
    {
        Write-ProgressBar -Current $subIndex -Total $subscriptionCount -CurrentItem $sub.Name

        Write-AuditLog -LogPath $logPath -Level INFO `
            -Message "Scanning subscription '$($sub.Name)' ($($sub.Id))  [$subIndex of $subscriptionCount]."

        try
        {
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue `
              -InformationAction SilentlyContinue -WhatIf:$false | Out-Null

            $allAssignmentsInSub = @(Get-AzRoleAssignment -ErrorAction Stop)

            Write-AuditLog -LogPath $logPath -Level INFO `
                -Message "  Found $($allAssignmentsInSub.Count) total RBAC assignments in this subscription. Now filtering for the target users."

            foreach ($target in $targetList)
            {
                $upn        = $target.UserPrincipalName
                $targetScope= $target.Scope

                # Find assignments matching this UPN
                $matchedAssignments = @($allAssignmentsInSub | Where-Object {
                    $signIn = $_.PSObject.Properties['SignInName']
                    $upnProp = $_.PSObject.Properties['UserPrincipalName']
                    ($signIn -ne $null -and $signIn.Value  -eq $upn) -or
                    ($upnProp -ne $null -and $upnProp.Value -eq $upn)
                })

                if ($matchedAssignments.Count -eq 0)
                {
                    Write-AuditLog -LogPath $logPath -Level INFO `
                        -Message "  No RBAC assignments were found for '$upn' in subscription '$($sub.Name)'. Nothing to do here."
                    continue
                }

                Write-AuditLog -LogPath $logPath -Level INFO `
                    -Message "  Found $($matchedAssignments.Count) assignment(s) for '$upn' in '$($sub.Name)'. Evaluating each one."

                foreach ($assignment in $matchedAssignments)
                {
                    $scopeLevel = Get-ScopeLevel -Scope $assignment.Scope

                    # ── Guard: skip non-User principals ───────────────────────
                    if ($assignment.ObjectType -ne "User")
                    {
                        $skippedItems += [pscustomobject]@{
                            UserPrincipalName = $upn
                            RoleDefinitionName= $assignment.RoleDefinitionName
                            Scope             = $assignment.Scope
                            Reason            = "Not a User principal (ObjectType: $($assignment.ObjectType)) — only User-type assignments are removed by this tool"
                        }
                        Write-AuditLog -LogPath $logPath -Level WARNING `
                            -Message "  SKIPPED — '$upn' has a '$($assignment.RoleDefinitionName)' assignment at scope '$($assignment.Scope)' but its principal type is '$($assignment.ObjectType)', not 'User'. This tool only removes User-type assignments. Skipped safely."
                        continue
                    }

                    # ── Guard: warn about Management Group scope ──────────────
                    if ($scopeLevel -eq "Management Group")
                    {
                        $skippedItems += [pscustomobject]@{
                            UserPrincipalName = $upn
                            RoleDefinitionName= $assignment.RoleDefinitionName
                            Scope             = $assignment.Scope
                            Reason            = "Management Group scoped assignments are out of scope for this tool — remove manually via the Azure Portal"
                        }
                        Write-AuditLog -LogPath $logPath -Level WARNING `
                            -Message "  SKIPPED — '$upn' has a '$($assignment.RoleDefinitionName)' assignment at MANAGEMENT GROUP scope '$($assignment.Scope)'. Management Group assignments are not handled by this tool to avoid accidental tenant-wide changes. Skipped — please remove manually if required."
                        continue
                    }

                    # ── Scope filter logic ─────────────────────────────────────
                    $removalMode = ""
                    if (-not [string]::IsNullOrWhiteSpace($targetScope))
                    {
                        # Scope-specific mode: only include if scope matches exactly
                        if ($assignment.Scope -ne $targetScope)
                        {
                            $skippedItems += [pscustomobject]@{
                                UserPrincipalName = $upn
                                RoleDefinitionName= $assignment.RoleDefinitionName
                                Scope             = $assignment.Scope
                                Reason            = "Scope-specific removal requested — this assignment's scope does not match the requested scope ('$targetScope')"
                            }
                            Write-AuditLog -LogPath $logPath -Level INFO `
                                -Message "  SCOPE MISMATCH — '$upn' has a '$($assignment.RoleDefinitionName)' assignment at '$($assignment.Scope)' but the requested removal scope is '$targetScope'. This assignment is outside the requested scope and will be left in place."
                            continue
                        }
                        $removalMode = "Scope-Specific"
                        Write-AuditLog -LogPath $logPath -Level INFO `
                            -Message "  SCOPE MATCH — '$upn' '$($assignment.RoleDefinitionName)' at '$($assignment.Scope)' matches the requested scope. Queued for removal (Scope-Specific mode)."
                    }
                    else
                    {
                        # Full removal mode
                        $removalMode = "Full"
                        Write-AuditLog -LogPath $logPath -Level INFO `
                            -Message "  QUEUED — '$upn' '$($assignment.RoleDefinitionName)' at '$($assignment.Scope)' [$scopeLevel] in subscription '$($sub.Name)'. Queued for full removal (no scope filter applied)."
                    }

                    $assignmentsToRemove += [pscustomobject]@{
                        UserPrincipalName  = $upn
                        DisplayName        = $assignment.DisplayName
                        RoleDefinitionName = $assignment.RoleDefinitionName
                        RoleDefinitionId   = $assignment.RoleDefinitionId
                        ObjectId           = $assignment.ObjectId
                        Scope              = $assignment.Scope
                        ScopeLevel         = $scopeLevel
                        SubscriptionName   = $sub.Name
                        SubscriptionId     = $sub.Id
                        RemovalMode        = $removalMode
                        RoleAssignmentId   = $assignment.RoleAssignmentId
                    }
                }
            }

            # Clear progress line
            Write-Host "`r" -NoNewline
            Write-Host (" " * 120) -NoNewline
            Write-Host "`r" -NoNewline
            Write-Host "  ✓  $($sub.Name.PadRight(55))" -NoNewline -ForegroundColor Green
            Write-Host " → Scan complete" -ForegroundColor DarkGray
        }
        catch
        {
            Write-Host "`r" -NoNewline
            Write-Host (" " * 120) -NoNewline
            Write-Host "`r" -NoNewline
            Write-Host "  ✗  $($sub.Name.PadRight(55))" -NoNewline -ForegroundColor Red
            Write-Host " → Scan failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-AuditLog -LogPath $logPath -Level ERROR `
                -Message "  SCAN FAILED for subscription '$($sub.Name)': $($_.Exception.Message)  This subscription was skipped. No assignments from this subscription were evaluated."
        }

        $subIndex++
    }

    Write-Host ""
    Write-AuditSeparator -LogPath $logPath
    Write-AuditLog -LogPath $logPath -Level SUCCESS `
        -Message "PHASE 1 COMPLETE — Discovery finished.  Assignments queued for removal: $($assignmentsToRemove.Count).  Items skipped during discovery: $($skippedItems.Count)."

    if ($assignmentsToRemove.Count -eq 0)
    {
        Write-Host ""
        Write-Host "  ✓  No assignments found to remove." -ForegroundColor Yellow
        Write-Host ""
        Write-AuditLog -LogPath $logPath -Level WARNING `
            -Message "No matching assignments were found across any subscription. This could mean the users have no current RBAC assignments, or the scope filter did not match anything. The session will close now — no changes were made."
    }

    # ── Phase 2: Backup ────────────────────────────────────────────────────────
    if ($assignmentsToRemove.Count -gt 0)
    {
        Write-Host "  Phase 2: Backing Up Assignments" -ForegroundColor Cyan
        Write-Host "  " -NoNewline
        Write-Host ("─" * 76) -ForegroundColor DarkGray
        Write-Host ""
        Write-AuditLog -LogPath $logPath -Level HEADER `
            -Message "PHASE 2 — BACKUP: Saving a complete copy of all assignments that are about to be removed. This backup can be used to restore access if needed."

        try
        {
            $assignmentsToRemove | ConvertTo-Json -Depth 5 |
                Out-File -FilePath $backupJsonPath -Encoding UTF8 -Force -ErrorAction Stop -WhatIf:$false

            $assignmentsToRemove |
                Select-Object UserPrincipalName, DisplayName, RoleDefinitionName,
                              RoleDefinitionId, ObjectId, Scope, ScopeLevel,
                              SubscriptionName, SubscriptionId, RemovalMode, RoleAssignmentId |
                Export-Csv -Path $backupCsvPath -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop -WhatIf:$false

            Write-Host "  ✓  Backup JSON  : $backupJsonPath" -ForegroundColor Green
            Write-Host "  ✓  Backup CSV   : $backupCsvPath" -ForegroundColor Green
            Write-Host ""
            Write-AuditLog -LogPath $logPath -Level SUCCESS `
                -Message "Backup saved successfully.  $($assignmentsToRemove.Count) assignment(s) backed up."
            Write-AuditLog -LogPath $logPath -Level INFO `
                -Message "  JSON backup (for restore): $backupJsonPath"
            Write-AuditLog -LogPath $logPath -Level INFO `
                -Message "  CSV  backup (for review) : $backupCsvPath"
            Write-AuditLog -LogPath $logPath -Level INFO `
                -Message "To restore access later, run: Restore-AzureRBACUserAssignments -BackupJsonPath '$backupJsonPath'"
        }
        catch
        {
            Write-AuditLog -LogPath $logPath -Level ERROR `
                -Message "BACKUP FAILED: $_  To protect your data, the removal phase has been stopped. Please fix the backup issue and try again."
            Write-Host "  ✗  Backup failed: $_" -ForegroundColor Red
            Write-Host "  ✗  Removal phase aborted to protect data integrity. Fix the backup issue and retry." -ForegroundColor Red
            return
        }

        Write-AuditSeparator -LogPath $logPath

        # ── Phase 3: Removal ──────────────────────────────────────────────────
        Write-Host "  Phase 3: Removing Assignments" -ForegroundColor Cyan
        Write-Host "  " -NoNewline
        Write-Host ("─" * 76) -ForegroundColor DarkGray
        Write-Host ""
        Write-AuditLog -LogPath $logPath -Level HEADER `
            -Message "PHASE 3 — REMOVAL: Processing each queued assignment. Every action is recorded below."

        $removalResults    = @()
        $totalRemoved      = 0
        $totalFailed       = 0
        $totalWhatIf       = 0
        $removalIndex      = 1

        foreach ($entry in $assignmentsToRemove)
        {
            $actionDesc = "Remove '$($entry.RoleDefinitionName)' role from '$($entry.UserPrincipalName)' at scope '$($entry.Scope)' in subscription '$($entry.SubscriptionName)'"

            if ($PSCmdlet.ShouldProcess($actionDesc, "Remove-AzRoleAssignment"))
            {
                # Live removal
                Write-AuditLog -LogPath $logPath -Level INFO `
                    -Message "[$removalIndex/$($assignmentsToRemove.Count)] REMOVING — $actionDesc  (Removal mode: $($entry.RemovalMode))"
                try
                {
                    Set-AzContext -Subscription $entry.SubscriptionId -WarningAction SilentlyContinue `
                                  -InformationAction SilentlyContinue | Out-Null

                    Remove-AzRoleAssignment `
                        -ObjectId          $entry.ObjectId `
                        -RoleDefinitionName $entry.RoleDefinitionName `
                        -Scope             $entry.Scope `
                        -ErrorAction Stop

                    $totalRemoved++
                    $resultStatus = "Removed"
                    Write-Host "  ✓  [$removalIndex/$($assignmentsToRemove.Count)] Removed  '$($entry.RoleDefinitionName)' from '$($entry.UserPrincipalName)'" -ForegroundColor Green
                    Write-AuditLog -LogPath $logPath -Level SUCCESS `
                        -Message "[$removalIndex/$($assignmentsToRemove.Count)] SUCCESS — The '$($entry.RoleDefinitionName)' role has been successfully removed from '$($entry.UserPrincipalName)' at scope '$($entry.Scope)'. This user can no longer access Azure resources through this role assignment."
                }
                catch
                {
                    $totalFailed++
                    $resultStatus = "Failed"
                    Write-Host "  ✗  [$removalIndex/$($assignmentsToRemove.Count)] Failed  '$($entry.RoleDefinitionName)' from '$($entry.UserPrincipalName)': $($_.Exception.Message)" -ForegroundColor Red
                    Write-AuditLog -LogPath $logPath -Level ERROR `
                        -Message "[$removalIndex/$($assignmentsToRemove.Count)] FAILED — Could not remove '$($entry.RoleDefinitionName)' from '$($entry.UserPrincipalName)' at scope '$($entry.Scope)'. Error: $($_.Exception.Message)  This assignment was NOT removed — it remains in place."
                }
            }
            else
            {
                # WhatIf mode
                $totalWhatIf++
                $resultStatus = "WhatIf"
                Write-Host "  ℹ  [$removalIndex/$($assignmentsToRemove.Count)] WhatIf  Would remove '$($entry.RoleDefinitionName)' from '$($entry.UserPrincipalName)'" -ForegroundColor Cyan
                Write-AuditLog -LogPath $logPath -Level INFO `
                    -Message "[$removalIndex/$($assignmentsToRemove.Count)] WHATIF (PREVIEW) — In a live run, this would remove '$($entry.RoleDefinitionName)' from '$($entry.UserPrincipalName)' at scope '$($entry.Scope)'. No change was made because WhatIf mode is active."
            }

            $removalResults += [pscustomobject]@{
                UserPrincipalName  = $entry.UserPrincipalName
                RoleDefinitionName = $entry.RoleDefinitionName
                Scope              = $entry.Scope
                ScopeLevel         = $entry.ScopeLevel
                SubscriptionName   = $entry.SubscriptionName
                RemovalMode        = $entry.RemovalMode
                Status             = $resultStatus
                Reason             = if ($resultStatus -eq "Failed") { $Error[0].Exception.Message } else { "" }
            }

            $removalIndex++
        }

        Write-AuditSeparator -LogPath $logPath
        Write-AuditLog -LogPath $logPath -Level SUCCESS `
            -Message "PHASE 3 COMPLETE — Removal phase finished.  Removed: $totalRemoved  |  WhatIf (preview only): $totalWhatIf  |  Failed: $totalFailed."
    }
    else
    {
        # No assignments found — build empty result set for the report
        $removalResults = @()
        $totalRemoved   = 0
        $totalFailed    = 0
        $totalWhatIf    = 0
    }

    # ── Final summary ──────────────────────────────────────────────────────────
    $endTime          = Get-Date
    $duration         = $endTime - $startTime
    $durationFmt      = "{0:hh\:mm\:ss}" -f $duration
    $uniqueUsers      = @($assignmentsToRemove | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    $uniqueSubs       = @($assignmentsToRemove | Select-Object -ExpandProperty SubscriptionId   -Unique).Count

    Write-Host ""
    Write-SummaryTable -Data @{
        "Assignments Evaluated"    = $assignmentsToRemove.Count
        "Successfully Removed"     = $totalRemoved
        "WhatIf (Preview Only)"    = $totalWhatIf
        "Failed"                   = $totalFailed
        "Skipped"                  = $skippedItems.Count
        "Unique Users Targeted"    = $uniqueUsers
        "Subscriptions Scanned"    = $subscriptionCount
        "Duration"                 = $durationFmt
        "Session Started"          = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
        "Session Ended"            = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
    }

    Write-AuditSeparator -LogPath $logPath
    Write-AuditLog -LogPath $logPath -Level HEADER `
        -Message "SESSION SUMMARY"
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Assignments evaluated   : $($assignmentsToRemove.Count)"
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Successfully removed    : $totalRemoved"
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "WhatIf (preview only)   : $totalWhatIf"
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Failed removals         : $totalFailed"
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Skipped (not actioned)  : $($skippedItems.Count)"
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Unique users targeted   : $uniqueUsers"
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Subscriptions scanned   : $subscriptionCount"
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Total session duration  : $durationFmt"
    Write-AuditSeparator -LogPath $logPath
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "Output files:"
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "  Audit log    : $logPath"
    if ($assignmentsToRemove.Count -gt 0)
    {
        Write-AuditLog -LogPath $logPath -Level INFO `
            -Message "  Backup JSON  : $backupJsonPath  (use this with Restore-AzureRBACUserAssignments to roll back)"
        Write-AuditLog -LogPath $logPath -Level INFO `
            -Message "  Backup CSV   : $backupCsvPath"
    }
    Write-AuditLog -LogPath $logPath -Level INFO `
        -Message "  HTML report  : $htmlPath"
    Write-AuditSeparator -LogPath $logPath
    Write-AuditLog -LogPath $logPath -Level HEADER `
        -Message "SESSION ENDED — All actions have been completed. Please review the HTML report and keep this audit log for your records."

    # ── Generate HTML report ───────────────────────────────────────────────────
    $whatIfMode = if ($PSBoundParameters.ContainsKey('WhatIf') -or $WhatIfPreference -eq 'Continue') { "Enabled" } else { "Disabled" }

    $runParameters = @{
        InputMode            = $inputMode
        ScopeMode            = $scopeMode
        SubscriptionTarget   = "$scopeText ($subscriptionCount subscriptions)"
        WhatIfMode           = $whatIfMode
        OutputFolder         = $OutputPath
    }

    $runSummary = @{
        StartTime          = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
        EndTime            = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
        Duration           = $durationFmt
        TotalProcessed     = $assignmentsToRemove.Count
        TotalRemoved       = $totalRemoved
        TotalSkipped       = $skippedItems.Count
        TotalFailed        = $totalFailed
        TotalWhatIf        = $totalWhatIf
        UniqueUsers        = $uniqueUsers
        UniqueSubscriptions= $uniqueSubs
    }

    $sessionInfo = @{
        Tenant      = $currentContext.Tenant.Id
        Account     = $currentContext.Account.Id
        Environment = $currentContext.Environment.Name
    }

    try
    {
        $reportHtml = Generate-RemovalHtmlReport `
            -SessionInfo      $sessionInfo `
            -RunParameters    $runParameters `
            -RunSummary       $runSummary `
            -RemovalResults   $removalResults `
            -SkippedItems     $skippedItems `
            -LogPath          $logPath `
            -BackupJsonPath   $backupJsonPath `
            -BackupCsvPath    $backupCsvPath `
            -HtmlPath         $htmlPath

        $reportHtml | Out-File -FilePath $htmlPath -Encoding UTF8 -Force -ErrorAction Stop -WhatIf:$false
    }
    catch
    {
        Write-Warning "HTML report generation failed: $_  All other outputs (log, backup) are unaffected."
    }

    Write-OutputFiles -LogPath $logPath -BackupJsonPath $backupJsonPath `
                      -BackupCsvPath $backupCsvPath -HtmlPath $htmlPath
}

#endregion ── Main Removal Function ────────────────────────────────────────────


#region ── Restore Companion Function ──────────────────────────────────────────

Function Restore-AzureRBACUserAssignments
{
<#
.SYNOPSIS
    Restores Azure RBAC role assignments from a JSON backup file created by
    Remove-AzureRBACUserAssignments.

.DESCRIPTION
    Reads a backup JSON file produced by Remove-AzureRBACUserAssignments and
    re-applies each assignment using New-AzRoleAssignment. This is the rollback
    companion to Remove-AzureRBACUserAssignments.

    Only assignments whose backup ObjectId and Scope are still valid can be
    restored. The function logs all actions (success, failure, already-exists)
    to the console and to an optional restore-specific audit log.

.PARAMETER BackupJsonPath
    Path to the JSON backup file created by Remove-AzureRBACUserAssignments.

.PARAMETER OutputPath
    Folder where the restore audit log is written. Defaults to C:\Temp.

.PARAMETER Force
    Suppresses the restore confirmation prompt.

.INPUTS
    None.

.OUTPUTS
    None directly to the pipeline. Writes a restore audit log.

.EXAMPLE
    Restore-AzureRBACUserAssignments `
        -BackupJsonPath "C:\Temp\AzureRBACRemoval-Backup-20260807-143022.json"

.NOTES
─────────────────────────────────────────────────────────────────────────────
Version History:
─────────────────────────────────────────────────────────────────────────────
1.0 (07-Aug-2026) - Initial release. Companion restore function for
                    Remove-AzureRBACUserAssignments.

─────────────────────────────────────────────────────────────────────────────
Pre-Requisites:
─────────────────────────────────────────────────────────────────────────────
1. Az PowerShell module (Az.Accounts, Az.Resources).
2. Authenticated Azure session with 'Microsoft.Authorization/roleAssignments/write'
   permission (typically: User Access Administrator or Owner).
3. The backup JSON file must be the one produced by Remove-AzureRBACUserAssignments.

─────────────────────────────────────────────────────────────────────────────
Known Limitations:
─────────────────────────────────────────────────────────────────────────────
- If the user's Object ID has changed (e.g. user deleted and recreated), the
  restore will fail for that entry. Re-assign manually in that case.
- If the scope (resource group or resource) no longer exists, the restore will
  fail for that entry. This is expected and logged clearly.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.resources/new-azroleassignment
#>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BackupJsonPath,

        [string]$OutputPath = "C:\Temp",

        [switch]$Force
    )

    $restoreStamp   = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $restoreLogPath = Join-Path $OutputPath "AzureRBACRestore-AuditLog-$restoreStamp.txt"

    Write-Banner

    Write-AuditLog -LogPath $restoreLogPath -Level HEADER `
        -Message "RESTORE SESSION STARTED — Re-applying Azure RBAC assignments from backup."
    Write-AuditLog -LogPath $restoreLogPath -Level INFO `
        -Message "Backup file: $BackupJsonPath"

    if (-not (Test-Path $BackupJsonPath))
    {
        Write-AuditLog -LogPath $restoreLogPath -Level ERROR `
            -Message "Backup file not found at path: '$BackupJsonPath'. Please verify the path and try again."
        Write-Error "Backup file not found: $BackupJsonPath"
        return
    }

    try
    {
        $backup = Get-Content -Path $BackupJsonPath -Raw -ErrorAction Stop | ConvertFrom-Json
    }
    catch
    {
        Write-AuditLog -LogPath $restoreLogPath -Level ERROR `
            -Message "Could not read or parse the backup file: $_"
        Write-Error "Could not read backup JSON: $_"
        return
    }

    Write-AuditLog -LogPath $restoreLogPath -Level INFO `
        -Message "Backup file loaded. $($backup.Count) assignment(s) to restore."

    if (-not $Force.IsPresent -and -not ($PSBoundParameters.ContainsKey('WhatIf') -or $WhatIfPreference -eq 'Continue'))
    {
        Write-Host ""
        Write-Host "  ⚠  This will restore $($backup.Count) RBAC assignment(s)." -ForegroundColor Yellow
        Write-Host ""
        $confirm = Read-Host "  Type 'YES' to proceed, or anything else to cancel"
        if ($confirm -ne 'YES')
        {
            Write-AuditLog -LogPath $restoreLogPath -Level WARNING `
                -Message "Restore cancelled by operator. No assignments were restored."
            Write-Host "  Restore cancelled." -ForegroundColor Yellow
            return
        }
    }

    $restoreIndex = 1
    $restored     = 0
    $failed       = 0

    foreach ($entry in $backup)
    {
        $actionDesc = "Restore '$($entry.RoleDefinitionName)' for '$($entry.UserPrincipalName)' at scope '$($entry.Scope)'"

        if ($PSCmdlet.ShouldProcess($actionDesc, "New-AzRoleAssignment"))
        {
            Write-AuditLog -LogPath $restoreLogPath -Level INFO `
                -Message "[$restoreIndex/$($backup.Count)] Restoring '$($entry.RoleDefinitionName)' for '$($entry.UserPrincipalName)' at '$($entry.Scope)' in subscription '$($entry.SubscriptionName)'."
            try
            {
                Set-AzContext -Subscription $entry.SubscriptionId -WarningAction SilentlyContinue `
                              -InformationAction SilentlyContinue | Out-Null

                New-AzRoleAssignment `
                    -ObjectId           $entry.ObjectId `
                    -RoleDefinitionName $entry.RoleDefinitionName `
                    -Scope              $entry.Scope `
                    -ErrorAction Stop | Out-Null

                $restored++
                Write-Host "  ✓  [$restoreIndex] Restored  '$($entry.RoleDefinitionName)' → '$($entry.UserPrincipalName)'" -ForegroundColor Green
                Write-AuditLog -LogPath $restoreLogPath -Level SUCCESS `
                    -Message "[$restoreIndex/$($backup.Count)] RESTORED — '$($entry.RoleDefinitionName)' has been re-applied to '$($entry.UserPrincipalName)' at '$($entry.Scope)'. Access is restored."
            }
            catch
            {
                $failed++
                $errMsg = $_.Exception.Message
                Write-Host "  ✗  [$restoreIndex] Failed    '$($entry.RoleDefinitionName)' → '$($entry.UserPrincipalName)': $errMsg" -ForegroundColor Red
                Write-AuditLog -LogPath $restoreLogPath -Level ERROR `
                    -Message "[$restoreIndex/$($backup.Count)] FAILED — Could not restore '$($entry.RoleDefinitionName)' for '$($entry.UserPrincipalName)' at '$($entry.Scope)'. Error: $errMsg  You may need to assign this role manually."
            }
        }
        else
        {
            Write-Host "  ℹ  [$restoreIndex] WhatIf — Would restore '$($entry.RoleDefinitionName)' for '$($entry.UserPrincipalName)'" -ForegroundColor Cyan
        }

        $restoreIndex++
    }

    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Restore complete.  Restored: $restored  |  Failed: $failed" -ForegroundColor Cyan
    Write-Host "  Restore audit log : $restoreLogPath" -ForegroundColor Gray
    Write-Host ""

    Write-AuditSeparator -LogPath $restoreLogPath
    Write-AuditLog -LogPath $restoreLogPath -Level HEADER `
        -Message "RESTORE SESSION ENDED — Restored: $restored  |  Failed: $failed.  Review the log above for details on any failures."
}

#endregion ── Restore Companion Function ───────────────────────────────────────
