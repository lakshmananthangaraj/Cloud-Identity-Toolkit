<#

Author       : Lakshmanan Thangaraj
Version      : 1.2
Created-On   : 31 October 2025
Modified-On  : 08 August 2026

.SYNOPSIS
    Removes Azure RBAC role assignments for any principal type (User, Group,
    ServicePrincipal, Unknown) in bulk using a CSV-driven input file, with
    pre-removal backup, HTML audit report, and a companion restore function.

.DESCRIPTION
    Remove-AzureRBACAssignments automates identification and removal of Azure
    Role-Based Access Control (RBAC) assignments using a CSV file as the source
    of truth. Each row in the CSV represents one principal/role/scope combination;
    the script validates the assignment is still live and then removes it — or
    previews the removal when -DryRun is supplied.

    Key behaviours
    ──────────────
    • Validates that the input CSV contains all required columns before processing.
    • Before any removal, writes a timestamped JSON backup and CSV backup of every
      live assignment that is about to be removed — enabling full restore via the
      companion Restore-AzureRBACAssignments function.
    • Switches Azure subscription context per row so multi-subscription CSVs are
      handled correctly.
    • Supports all principal ObjectTypes: User, ServicePrincipal, Group, Unknown.
      User rows are matched by SignInName (UPN). Non-User rows are matched by
      Scope + RoleDefinitionName + ObjectType, then narrowed by DisplayName.
    • Rows missing or containing an unrecognised ObjectType are skipped with
      ResultCode SKIPPED-INVALID-OBJECTTYPE.
    • Non-User rows with no DisplayName and more than one candidate assignment are
      marked Ambiguous and skipped to prevent accidental removal.
    • Validates each assignment is still live before attempting removal. Already-
      removed or never-present assignments are logged as NotFound — not errors.
    • Supports -DryRun (preview without changes) and -Force (suppress confirmation).
    • After processing, generates a self-contained HTML audit report with stat cards,
      filterable/sortable results table, skipped-items tab, and session info tab.
    • All output files (JSON backup, CSV backup, Summary CSV, HTML report, log) are
      written under a single -OutputPath folder with timestamp-based names.

.PARAMETER InputFileCsvPath
    Full path to the CSV file containing RBAC assignment rows to remove. The file
    must exist and must contain the columns: SubscriptionName, SubscriptionId,
    TenantId, DisplayName, SignInName, ObjectType, RoleDefinitionName, Scope.
    ObjectType must be one of: User, ServicePrincipal, Group, Unknown.

.PARAMETER OutputPath
    Folder where all output files are written. Created automatically if it does not
    exist. Defaults to C:\Temp when omitted. All files are timestamped:
      • RBACRemoval_Backup_<ts>.json
      • RBACRemoval_Backup_<ts>.csv
      • RBACRemoval_Summary_<ts>.csv
      • RBACRemoval_Report_<ts>.html
      • RBACRemoval_<ts>.log  (only when -EnableLog is supplied)

.PARAMETER EnableLog
    Switch. When supplied, detailed timestamped log lines are written to the .log
    file under -OutputPath. Omit for high-volume runs where log I/O is not needed.

.PARAMETER DryRun
    Switch. Runs the script in preview mode — resolves and validates each assignment
    but does NOT call Remove-AzRoleAssignment and does NOT write a backup. All
    would-be actions are recorded in the summary CSV with Status = "WhatIf".

.PARAMETER Force
    Switch. Suppresses the interactive confirmation prompt that is shown before any
    live removals begin. Has no effect when -DryRun is supplied.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    Returns a collection of result objects summarising every processed row.

.EXAMPLE
    .\Remove-AzureRBACAssignments.ps1 -InputFileCsvPath "C:\Temp\RBACToRemove.csv"

    Processes the CSV, prompts for confirmation, then removes all matching role
    assignments. Output files land in C:\Temp.

.EXAMPLE
    .\Remove-AzureRBACAssignments.ps1 -InputFileCsvPath "C:\Temp\RBACToRemove.csv" -DryRun

    Dry-run. Validates each row and logs what would be removed without making any
    changes. No backup is written. Safe to run against production.

.EXAMPLE
    .\Remove-AzureRBACAssignments.ps1 `
        -InputFileCsvPath "C:\Temp\RBACToRemove.csv" `
        -OutputPath       "C:\Audits\RBAC" `
        -EnableLog `
        -Force

    Removes all matching assignments without confirmation. All output files are
    written to C:\Audits\RBAC.

.EXAMPLE
    .\Remove-AzureRBACAssignments.ps1 `
        -InputFileCsvPath "C:\Temp\RBACToRemove.csv" `
        -OutputPath       "C:\Audits\RBAC" `
        -EnableLog

    Interactive run with full logging. Confirmation prompt summarises the scope
    before proceeding.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.2 (08-Aug-2026) - Added pre-removal JSON + CSV backup, HTML audit report
                        with stat cards / sortable table / skipped tab / session
                        tab, companion Restore-AzureRBACAssignments function,
                        -OutputPath (replaces individual file-path params),
                        -Force switch with interactive confirmation prompt, and
                        "Unique Principals Targeted" stat card. Version badge in
                        HTML report is driven from the script version string.
    1.1 (07-Aug-2026) - Extended to process all ObjectTypes (User, ServicePrincipal,
                        Group, Unknown). Non-User rows matched by Scope +
                        RoleDefinitionName + ObjectType, narrowed by DisplayName.
                        Added Ambiguous safeguard for blank-DisplayName multi-match
                        rows. Core removal, -WhatIf, logging, and summary unchanged.
    1.0 (31-Oct-2025) - Initial release. CSV-driven RBAC removal for User, Group,
                        and ServicePrincipal scenarios. Includes -WhatIf dry-run,
                        unified console/log output, pre-requisite and authentication
                        checks, and summary CSV reporting.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts and Az.Resources PowerShell modules (auto-installed if absent).
    2. PowerShell 5.1 or higher.
    3. The executing identity must hold Owner or User Access Administrator on every
       subscription whose assignments appear in the input CSV.
    4. An active Azure session — the script prompts Connect-AzAccount if none found.
    5. Input CSV columns required: SubscriptionName, SubscriptionId, TenantId,
       DisplayName, SignInName, ObjectType, RoleDefinitionName, Scope.
    6. For ServicePrincipal/Group/Unknown rows, populate DisplayName whenever
       possible to avoid the Ambiguous-skip safeguard.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Role removals require Owner or User Access Administrator; Contributor alone
      is not sufficient.
    - Processing very large CSVs across many subscriptions may take considerable
      time. Consider splitting into per-subscription batches for parallel runs.
    - Management-Group-scoped assignments require appropriate permissions at that
      scope; subscription-level Owner is not sufficient.
    - Non-User rows with blank DisplayName are only resolved when exactly one
      assignment matches Scope + RoleDefinitionName + ObjectType; otherwise the
      row is skipped as Ambiguous.
    - The backup JSON contains the ObjectId of each removed assignment. Restoring
      after an identity has been deleted from the tenant will fail at re-assignment
      time with a principal-not-found error.

.LINK
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/RBAC/Remove-AzureRBACAssignments.ps1

.LINK
    https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-remove

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.resources/remove-azroleassignment

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azroleassignment

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.accounts/connect-azaccount

#>

Function Remove-AzureRBACAssignments
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$InputFileCsvPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = "C:\Temp",

        [Parameter(Mandatory = $false)]
        [switch]$EnableLog,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    #region ── Script-level constants ─────────────────────────────────────────
    $ScriptVersion  = "1.2"
    $ScriptName     = "AZURE RBAC ASSIGNMENT REMOVER"
    $RunStartTime   = Get-Date
    $Timestamp      = $RunStartTime.ToString("yyyyMMdd-HHmmss")
    $RunBy          = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
    $RunByAccount   = $null

    $BackupJsonPath = Join-Path $OutputPath "RBACRemoval_Backup_$Timestamp.json"
    $BackupCsvPath  = Join-Path $OutputPath "RBACRemoval_Backup_$Timestamp.csv"
    $SummaryCsvPath = Join-Path $OutputPath "RBACRemoval_Summary_$Timestamp.csv"
    $HtmlReportPath = Join-Path $OutputPath "RBACRemoval_Report_$Timestamp.html"
    $LogPath        = Join-Path $OutputPath "RBACRemoval_$Timestamp.log"

    $ValidObjectTypes = @('user','serviceprincipal','group','unknown')
    $BannerLine       = "─" * 95
    #endregion

    #region ── Inline helpers ─────────────────────────────────────────────────

    Function Write-Log
    {
        param(
            [Parameter(Mandatory = $true)][string]$Message,
            [string]$Tag = "INFO"
        )
        $ts   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $tagf = ("[$Tag]").PadRight(10)
        $line = "[$ts] $tagf  $Message"
        switch ($Tag)
        {
            "ERROR"   { Write-Host $line -ForegroundColor Red }
            "WARNING" { Write-Host $line -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $line -ForegroundColor Green }
            default   { Write-Host $line -ForegroundColor White }
        }
        if ($EnableLog)
        {
            $logDir = Split-Path -Path $LogPath -Parent
            if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
            Add-Content -Path $LogPath -Value $line
        }
    }

    Function Write-HostLog
    {
        param(
            [Parameter(Mandatory = $false)][string]$Message = "",
            [string]$Color = "White"
        )
        if ([string]::IsNullOrWhiteSpace($Message))
        {
            Write-Host ""
            if ($EnableLog) { Add-Content -Path $LogPath -Value "" }
            return
        }
        Write-Host $Message -ForegroundColor $Color
        if ($EnableLog)
        {
            $logDir = Split-Path -Path $LogPath -Parent
            if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
            Add-Content -Path $LogPath -Value $Message
        }
    }

    Function Ensure-AzModules
    {
        try
        {
            Write-Log -Message "Checking required Az modules..." -Tag "INFO"
            foreach ($m in @("Az.Accounts","Az.Resources"))
            {
                if (-not (Get-Module -ListAvailable -Name $m))
                {
                    Write-Log -Message "Module $m not found. Installing..." -Tag "WARNING"
                    Install-Module -Name $m -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                }
                Import-Module -Name $m -ErrorAction Stop
                Write-Log -Message "Module $m loaded." -Tag "INFO"
            }
            return $true
        }
        catch
        {
            Write-Log -Message "Failed to ensure Az modules: $($_.Exception.Message)" -Tag "ERROR"
            return $false
        }
    }

    Function Ensure-AzureConnection
    {
        try
        {
            $ctx = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $ctx)
            {
                Write-Log -Message "No active Azure session found. Prompting for login..." -Tag "WARNING"
                Connect-AzAccount -ErrorAction Stop | Out-Null
                $ctx = Get-AzContext -ErrorAction Stop
            }
            Write-Log -Message "Active Azure session: $($ctx.Account.Id) / $($ctx.Subscription.Id)" -Tag "INFO"
            return $ctx
        }
        catch
        {
            Write-Log -Message "Azure authentication failed: $($_.Exception.Message)" -Tag "ERROR"
            throw
        }
    }

    Function ConvertTo-JsonSafe
    {
        param([string]$Value)
        return ($Value -replace '\\','\\\\'  `
                       -replace '"','\"'     `
                       -replace "`r`n",'\n'  `
                       -replace "`n",'\n'    `
                       -replace "`t",'\t'    `
                       -replace '<','&lt;'   `
                       -replace '>','&gt;'   `
                       -replace '\$','\$')
    }

    #endregion

    #region ── Banner ─────────────────────────────────────────────────────────
    Clear-Host
    Write-HostLog ""
    Write-HostLog $BannerLine -Color Cyan
    Write-HostLog ("                    $ScriptName - v$ScriptVersion") -Color Green
    Write-HostLog $BannerLine -Color Cyan
    Write-HostLog ""
    Write-HostLog ("Start Time   : {0}" -f $RunStartTime.ToString("yyyy-MM-dd HH:mm:ss")) -Color Cyan
    Write-HostLog ("Operator     : {0}" -f $RunBy) -Color Cyan
    Write-HostLog ("Input CSV    : {0}" -f $InputFileCsvPath) -Color Cyan
    Write-HostLog ("Output Path  : {0}" -f $OutputPath) -Color Cyan
    Write-HostLog ""
    #endregion

    #region ── Section 1 — Pre-requisites ─────────────────────────────────────
    Write-HostLog "[1/6] Pre-requisites check" -Color Yellow
    Write-HostLog $BannerLine -Color Cyan
    if (-not (Ensure-AzModules))
    {
        Write-Log -Message "Pre-requisites failed. Exiting." -Tag "ERROR"
        return
    }
    if (-not (Test-Path $OutputPath))
    {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Log -Message "Created output folder: $OutputPath" -Tag "INFO"
    }
    Write-Host "`n  ✔ Modules OK" -ForegroundColor Green
    Write-HostLog ""
    #endregion

    #region ── Section 2 — Authentication ─────────────────────────────────────
    Write-HostLog "[2/6] Authentication" -Color Yellow
    Write-HostLog $BannerLine -Color Cyan
    $AzContext     = Ensure-AzureConnection
    $RunByAccount  = $AzContext.Account.Id
    $TenantIdLive  = $AzContext.Tenant.Id
    Write-Host "`n  ✔ Authenticated as: $RunByAccount" -ForegroundColor Green
    Write-HostLog ""
    #endregion

    #region ── Section 3 — Load & validate CSV ────────────────────────────────
    Write-HostLog "[3/6] Loading input file" -Color Yellow
    Write-HostLog $BannerLine -Color Cyan
    Write-Log -Message "Loading CSV from $InputFileCsvPath" -Tag "INFO"

    if (-not (Test-Path -Path $InputFileCsvPath))
    {
        Write-Log -Message "Input CSV not found: $InputFileCsvPath" -Tag "ERROR"
        return
    }

    try
    {
        $Assignments = Import-Csv -Path $InputFileCsvPath -ErrorAction Stop
        if (-not $Assignments -or @($Assignments).Count -eq 0)
        {
            Write-Log -Message "Input CSV contains no records." -Tag "WARNING"
            return
        }
    }
    catch
    {
        Write-Log -Message "Failed to read CSV: $($_.Exception.Message)" -Tag "ERROR"
        return
    }

    $RequiredCols = @('SubscriptionName','SubscriptionId','TenantId','DisplayName',
                      'SignInName','ObjectType','RoleDefinitionName','Scope')
    $MissingCols  = $RequiredCols | Where-Object {
        -not ($Assignments | Get-Member -Name $_ -MemberType NoteProperty -ErrorAction SilentlyContinue)
    }
    if ($MissingCols)
    {
        Write-Log -Message "CSV missing required columns: $($MissingCols -join ', ')" -Tag "ERROR"
        return
    }

    $TotalRows = @($Assignments).Count
    Write-Log -Message "Loaded $TotalRows records from CSV." -Tag "INFO"
    Write-Host "`n  ✔ $TotalRows rows loaded and validated." -ForegroundColor Green
    Write-HostLog ""
    #endregion

    #region ── Section 4 — Confirmation prompt ────────────────────────────────
    if (-not $DryRun)
    {
        $UniqueSubscriptions = @($Assignments | Select-Object -ExpandProperty SubscriptionName -Unique).Count
        Write-HostLog "[4/6] Confirmation" -Color Yellow
        Write-HostLog $BannerLine -Color Cyan
        Write-HostLog ""
        Write-HostLog "  ⚠  You are about to PERMANENTLY REMOVE Azure RBAC assignments." -Color Red
        Write-HostLog ("     Rows to process    : {0}" -f $TotalRows) -Color Yellow
        Write-HostLog ("     Subscriptions      : {0}" -f $UniqueSubscriptions) -Color Yellow
        Write-HostLog ("     Authenticated as   : {0}" -f $RunByAccount) -Color Yellow
        Write-HostLog ("     Tenant             : {0}" -f $TenantIdLive) -Color Yellow
        Write-HostLog ""
        Write-HostLog "     A JSON + CSV backup will be written before any removal." -Color Cyan
        Write-HostLog "     Use -DryRun to simulate without changes." -Color Cyan
        Write-HostLog ""

        if (-not $Force)
        {
            $Confirm = Read-Host "  Type YES to proceed, or anything else to cancel"
            if ($Confirm -ne "YES")
            {
                Write-HostLog ""
                Write-Log -Message "Operation cancelled by operator." -Tag "WARNING"
                Write-HostLog "  Operation cancelled. No changes were made." -Color Yellow
                Write-HostLog ""
                return
            }
        }
        else
        {
            Write-Log -Message "-Force supplied — skipping confirmation prompt." -Tag "INFO"
        }
        Write-HostLog ""
    }
    else
    {
        Write-HostLog "[4/6] Confirmation — SKIPPED (DryRun mode)" -Color Cyan
        Write-HostLog ""
    }
    #endregion

    #region ── Section 5 — Processing ────────────────────────────────────────
    Write-HostLog "[5/6] Processing assignments" -Color Yellow
    Write-HostLog $BannerLine -Color Cyan
    Write-Log -Message "Begin processing $TotalRows assignments." -Tag "INFO"

    $Results     = New-Object System.Collections.Generic.List[PSObject]
    $BackupItems = New-Object System.Collections.Generic.List[PSObject]
    $RowIndex    = 0

    foreach ($Row in $Assignments)
    {
        $RowIndex++
        $Pct          = [math]::Round(($RowIndex / $TotalRows) * 100, 0)
        $ProgressText = "Processing $RowIndex of $TotalRows — $($Row.SignInName) — $($Row.RoleDefinitionName)"
        Write-Progress -Activity "Remove-AzureRBACAssignments" -Status $ProgressText -PercentComplete $Pct

        $Result = [PSCustomObject]@{
            ExecutionTime      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            RunBy              = $RunByAccount
            SubscriptionName   = $Row.SubscriptionName
            SubscriptionId     = $Row.SubscriptionId
            TenantId           = $Row.TenantId
            DisplayName        = $Row.DisplayName
            SignInName         = $Row.SignInName
            ObjectType         = $Row.ObjectType
            RoleDefinitionName = $Row.RoleDefinitionName
            Scope              = $Row.Scope
            Status             = ""
            Message            = ""
            ResultCode         = ""
        }

        Write-HostLog ""
        Write-Log -Message ("Row [{0}/{1}] Principal: [{2}] | Role: [{3}] | Sub: [{4}]" -f `
            $RowIndex, $TotalRows, $Row.SignInName, $Row.RoleDefinitionName, $Row.SubscriptionName) -Tag "INFO"

        try
        {
            #── Validate ObjectType ──────────────────────────────────────────
            $ObjType = if ($Row.ObjectType) { $Row.ObjectType.Trim() } else { $null }
            if (($null -eq $ObjType) -or ($ObjType -eq '') -or
                ($ValidObjectTypes -notcontains $ObjType.ToLower()))
            {
                $Result.Status     = "Skipped"
                $Result.Message    = "ObjectType is missing or unrecognised (expected: User / ServicePrincipal / Group / Unknown)"
                $Result.ResultCode = "SKIPPED-INVALID-OBJECTTYPE"
                $Results.Add($Result)
                Write-Host ("    [{0}/{1}] Skipped — unrecognised ObjectType '{2}' for {3}" -f `
                    $RowIndex,$TotalRows,$Row.ObjectType,$Row.SignInName) -ForegroundColor Yellow
                Write-Log -Message "Skipped $($Row.SignInName) — ObjectType '$($Row.ObjectType)'" -Tag "WARNING"
                continue
            }

            #── Switch subscription context ──────────────────────────────────
            try
            {
                Set-AzContext -Subscription $Row.SubscriptionId `
                    -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            }
            catch
            {
                $Result.Status     = "Error"
                $Result.Message    = "Failed to set subscription context: $($_.Exception.Message)"
                $Result.ResultCode = "ERR-SET-CONTEXT"
                $Results.Add($Result)
                Write-Host ("    [{0}/{1}] Error — cannot switch to subscription {2}" -f `
                    $RowIndex,$TotalRows,$Row.SubscriptionId) -ForegroundColor Red
                Write-Log -Message "Failed to set context to $($Row.SubscriptionId): $($_.Exception.Message)" -Tag "ERROR"
                continue
            }

            #── Resolve live assignment(s) ────────────────────────────────────
            $Found = @()
            try
            {
                if ($ObjType.ToLower() -eq 'user')
                {
                    $Found = Get-AzRoleAssignment -SignInName $Row.SignInName -Scope $Row.Scope `
                        -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                        Where-Object { $_.RoleDefinitionName -eq $Row.RoleDefinitionName -and
                                       $_.Scope              -eq $Row.Scope }
                }
                else
                {
                    $Candidates = Get-AzRoleAssignment -Scope $Row.Scope `
                        -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                        Where-Object { $_.RoleDefinitionName -eq $Row.RoleDefinitionName -and
                                       $_.Scope              -eq $Row.Scope -and
                                       $_.ObjectType         -eq $Row.ObjectType }

                    if ($Row.DisplayName)
                    {
                        $Found = $Candidates | Where-Object {
                            $_.DisplayName -and
                            ($_.DisplayName.Trim().ToLower() -eq $Row.DisplayName.Trim().ToLower())
                        }
                    }
                    else
                    {
                        $Found = $Candidates
                    }
                }
            }
            catch { $Found = @() }

            #── Not found ────────────────────────────────────────────────────
            if (-not $Found -or @($Found).Count -eq 0)
            {
                $Result.Status     = "NotFound"
                $Result.Message    = "No matching live assignment found"
                $Result.ResultCode = "NOT-FOUND"
                $Results.Add($Result)
                Write-Host ("    [{0}/{1}] NotFound — {2} | {3} @ {4}" -f `
                    $RowIndex,$TotalRows,$Row.SignInName,$Row.RoleDefinitionName,$Row.Scope) -ForegroundColor DarkYellow
                Write-Log -Message "NotFound: $($Row.SignInName) — $($Row.RoleDefinitionName) at $($Row.Scope)" -Tag "WARNING"
                continue
            }

            #── Ambiguous guard (non-User, no DisplayName, multiple matches) ──
            if (($ObjType.ToLower() -ne 'user') -and
                (-not $Row.DisplayName) -and
                (@($Found).Count -gt 1))
            {
                $Result.Status     = "Ambiguous"
                $Result.Message    = ("Multiple matching assignments found for Scope/RoleDefinitionName/ObjectType " +
                                      "and DisplayName is empty in the CSV — cannot safely determine which to remove.")
                $Result.ResultCode = "AMBIGUOUS-MULTIPLE-MATCHES"
                $Results.Add($Result)
                Write-Host ("    [{0}/{1}] Ambiguous — {2} matches for {3} @ {4} (ObjectType: {5}) — DisplayName empty, skipped" -f `
                    $RowIndex,$TotalRows,@($Found).Count,$Row.RoleDefinitionName,$Row.Scope,$Row.ObjectType) -ForegroundColor Red
                Write-Log -Message ("Ambiguous: $(@($Found).Count) matches for ObjectType=$($Row.ObjectType) " +
                                    "at $($Row.Scope)/$($Row.RoleDefinitionName) — DisplayName empty. Skipped.") -Tag "WARNING"
                continue
            }

            #── Process each matched assignment ───────────────────────────────
            $RemovedAny = $false

            foreach ($Ra in $Found)
            {
                if ($DryRun)
                {
                    $RC = $Result.PSObject.Copy()
                    $RC.Status     = "WhatIf"
                    $RC.Message    = "Would remove RoleAssignmentId: $($Ra.RoleAssignmentId)"
                    $RC.ResultCode = "WHATIF"
                    $Results.Add($RC)
                    Write-Host ("    [{0}/{1}] WhatIf — would remove Id {2} for {3} — {4}" -f `
                        $RowIndex,$TotalRows,$Ra.RoleAssignmentId,$Row.SignInName,$Ra.RoleDefinitionName) -ForegroundColor Cyan
                    Write-Log -Message "WHATIF: Found Id $($Ra.RoleAssignmentId) for $($Row.SignInName)" -Tag "INFO"
                    $RemovedAny = $true
                    continue
                }

                #── Write backup entry (once per assignment, before removal) ──
                $BackupEntry = [PSCustomObject]@{
                    BackupTime         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    RoleAssignmentId   = $Ra.RoleAssignmentId
                    ObjectId           = $Ra.ObjectId
                    ObjectType         = $Ra.ObjectType
                    DisplayName        = $Ra.DisplayName
                    SignInName         = if ($Ra.SignInName) { $Ra.SignInName } else { $Row.SignInName }
                    RoleDefinitionId   = $Ra.RoleDefinitionId
                    RoleDefinitionName = $Ra.RoleDefinitionName
                    Scope              = $Ra.Scope
                    SubscriptionId     = $Row.SubscriptionId
                    SubscriptionName   = $Row.SubscriptionName
                    TenantId           = $Row.TenantId
                }
                $BackupItems.Add($BackupEntry)

                try
                {
                    Remove-AzRoleAssignment -ObjectId $Ra.ObjectId `
                        -RoleDefinitionName $Ra.RoleDefinitionName `
                        -Scope $Ra.Scope `
                        -Confirm:$false `
                        -ErrorAction Stop `
                        -WarningAction SilentlyContinue

                    $RC = $Result.PSObject.Copy()
                    $RC.Status     = "Removed"
                    $RC.Message    = "Removed RoleAssignmentId: $($Ra.RoleAssignmentId)"
                    $RC.ResultCode = "REMOVED"
                    $Results.Add($RC)
                    Write-Host ("    [{0}/{1}] Removed — {2} | {3} @ {4}" -f `
                        $RowIndex,$TotalRows,$Row.SignInName,$Ra.RoleDefinitionName,$Ra.Scope) -ForegroundColor Green
                    Write-Log -Message ("Removed $($Row.SignInName) — $($Ra.RoleDefinitionName) at $($Ra.Scope) " +
                                        "(Id: $($Ra.RoleAssignmentId))") -Tag "SUCCESS"
                    $RemovedAny = $true
                }
                catch
                {
                    $RC = $Result.PSObject.Copy()
                    $RC.Status     = "Error"
                    $RC.Message    = "Failed to remove RoleAssignmentId $($Ra.RoleAssignmentId): $($_.Exception.Message)"
                    $RC.ResultCode = "ERR-REMOVE"
                    $Results.Add($RC)
                    Write-Host ("    [{0}/{1}] Error removing Id {2}: {3}" -f `
                        $RowIndex,$TotalRows,$Ra.RoleAssignmentId,$_.Exception.Message) -ForegroundColor Red
                    Write-Log -Message ("Failed to remove Id $($Ra.RoleAssignmentId) for " +
                                        "$($Row.SignInName): $($_.Exception.Message)") -Tag "ERROR"
                }
            }

            if (-not $RemovedAny)
            {
                $Result.Status     = "Skipped"
                $Result.Message    = "No action performed"
                $Result.ResultCode = "SKIPPED-NOACTION"
                $Results.Add($Result)
                Write-Host ("    [{0}/{1}] Skipped (no action) for {2}" -f `
                    $RowIndex,$TotalRows,$Row.SignInName) -ForegroundColor Yellow
            }
        }
        catch
        {
            $Result.Status     = "Error"
            $Result.Message    = $_.Exception.Message
            $Result.ResultCode = "ERR-UNHANDLED"
            $Results.Add($Result)
            Write-Host ("    [{0}/{1}] Unhandled error for {2}: {3}" -f `
                $RowIndex,$TotalRows,$Row.SignInName,$_.Exception.Message) -ForegroundColor Red
            Write-Log -Message "Unhandled error processing $($Row.SignInName): $($_.Exception.Message)" -Tag "ERROR"
        }
    }

    Write-Progress -Activity "Remove-AzureRBACAssignments" -Completed
    Write-HostLog ""
    #endregion

    #region ── Section 6 — Outputs ────────────────────────────────────────────
    Write-HostLog "[6/6] Summary & report" -Color Yellow
    Write-HostLog $BannerLine -Color Cyan
    Write-Log -Message "Generating output files." -Tag "INFO"

    #── Backup JSON ──────────────────────────────────────────────────────────
    if (-not $DryRun -and $BackupItems.Count -gt 0)
    {
        try
        {
            $BackupItems | ConvertTo-Json -Depth 5 |
                Out-File -FilePath $BackupJsonPath -Encoding UTF8 -Force
            Write-Log -Message "Backup JSON written: $BackupJsonPath" -Tag "SUCCESS"
        }
        catch { Write-Log -Message "Failed to write backup JSON: $($_.Exception.Message)" -Tag "ERROR" }

        try
        {
            $BackupItems | Export-Csv -Path $BackupCsvPath -NoTypeInformation -Encoding UTF8 -Force
            Write-Log -Message "Backup CSV written: $BackupCsvPath" -Tag "SUCCESS"
        }
        catch { Write-Log -Message "Failed to write backup CSV: $($_.Exception.Message)" -Tag "ERROR" }
    }

    #── Summary CSV ──────────────────────────────────────────────────────────
    try
    {
        $Results | Select-Object ExecutionTime,RunBy,SubscriptionName,SubscriptionId,
            TenantId,DisplayName,SignInName,ObjectType,RoleDefinitionName,
            Scope,Status,Message,ResultCode |
            Export-Csv -Path $SummaryCsvPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Log -Message "Summary CSV written: $SummaryCsvPath" -Tag "SUCCESS"
    }
    catch { Write-Log -Message "Failed to write summary CSV: $($_.Exception.Message)" -Tag "ERROR" }

    #── Compute counters ─────────────────────────────────────────────────────
    $TotalProcessed      = @($Results).Count
    $RemovedCount        = @($Results | Where-Object { $_.ResultCode -eq  'REMOVED'                  }).Count
    $WhatIfCount         = @($Results | Where-Object { $_.ResultCode -eq  'WHATIF'                   }).Count
    $NotFoundCount       = @($Results | Where-Object { $_.ResultCode -eq  'NOT-FOUND'                }).Count
    $AmbiguousCount      = @($Results | Where-Object { $_.ResultCode -eq  'AMBIGUOUS-MULTIPLE-MATCHES' }).Count
    $SkippedCount        = @($Results | Where-Object { $_.ResultCode -like 'SKIPPED*'                }).Count
    $ErrorCount          = @($Results | Where-Object { $_.ResultCode -like 'ERR*'                    }).Count
    $UniquePrincipals    = @($Results | Where-Object { $_.SignInName } | Select-Object -ExpandProperty SignInName -Unique).Count
    $RunEndTime          = Get-Date
    $DurationSecs        = [math]::Round(($RunEndTime - $RunStartTime).TotalSeconds, 1)

    #── HTML Report ──────────────────────────────────────────────────────────
    try
    {
        #── Build rows JSON ──────────────────────────────────────────────────
        $AllRowsJson    = ""
        $SkippedRowsJson = ""

        $MainResults    = $Results | Where-Object { $_.ResultCode -notlike 'SKIPPED*' -and
                                                    $_.ResultCode -ne 'AMBIGUOUS-MULTIPLE-MATCHES' }
        $SkippedResults = $Results | Where-Object { $_.ResultCode -like  'SKIPPED*' -or
                                                    $_.ResultCode -eq   'AMBIGUOUS-MULTIPLE-MATCHES' }

        foreach ($R in $MainResults)
        {
            $AllRowsJson += (@"
{
  "executionTime":"$(ConvertTo-JsonSafe $R.ExecutionTime)",
  "subscriptionName":"$(ConvertTo-JsonSafe $R.SubscriptionName)",
  "displayName":"$(ConvertTo-JsonSafe $R.DisplayName)",
  "signInName":"$(ConvertTo-JsonSafe $R.SignInName)",
  "objectType":"$(ConvertTo-JsonSafe $R.ObjectType)",
  "role":"$(ConvertTo-JsonSafe $R.RoleDefinitionName)",
  "scope":"$(ConvertTo-JsonSafe $R.Scope)",
  "status":"$(ConvertTo-JsonSafe $R.Status)",
  "resultCode":"$(ConvertTo-JsonSafe $R.ResultCode)",
  "message":"$(ConvertTo-JsonSafe $R.Message)"
},
"@)
        }
        $AllRowsJson = "[" + $AllRowsJson.TrimEnd(",`r`n") + "]"

        foreach ($R in $SkippedResults)
        {
            $SkippedRowsJson += (@"
{
  "executionTime":"$(ConvertTo-JsonSafe $R.ExecutionTime)",
  "displayName":"$(ConvertTo-JsonSafe $R.DisplayName)",
  "signInName":"$(ConvertTo-JsonSafe $R.SignInName)",
  "objectType":"$(ConvertTo-JsonSafe $R.ObjectType)",
  "role":"$(ConvertTo-JsonSafe $R.RoleDefinitionName)",
  "scope":"$(ConvertTo-JsonSafe $R.Scope)",
  "resultCode":"$(ConvertTo-JsonSafe $R.ResultCode)",
  "message":"$(ConvertTo-JsonSafe $R.Message)"
},
"@)
        }
        $SkippedRowsJson = "[" + $SkippedRowsJson.TrimEnd(",`r`n") + "]"

        $RunMode = if ($DryRun) { "WhatIf (Dry-Run)" } else { "Live Removal" }

        #── HTML template ────────────────────────────────────────────────────
        $Html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Azure RBAC Removal Report</title>
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
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;display:flex}
/* Sidebar */
#sidebar{
  position:fixed;top:0;left:0;width:236px;height:100vh;
  background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;z-index:100;overflow-y:auto
}
.logo-block{padding:20px 16px 12px;border-bottom:1px solid var(--border)}
.logo-icon{
  width:36px;height:36px;border-radius:8px;
  background:linear-gradient(135deg,var(--accent),var(--accent3));
  display:flex;align-items:center;justify-content:center;
  font-size:18px;margin-bottom:10px
}
.logo-title{font-size:13px;font-weight:700;color:var(--text);line-height:1.3}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px}
.ver-badge{
  display:inline-block;margin-top:6px;padding:2px 8px;border-radius:20px;
  background:var(--surface3);border:1px solid var(--border);
  font-size:10px;font-family:var(--mono);color:var(--accent2)
}
.nav-section{padding:12px 8px;flex:1}
.nav-label{font-size:10px;color:var(--muted);text-transform:uppercase;
  letter-spacing:.8px;padding:0 8px 6px}
.nav-btn{
  display:flex;align-items:center;gap:8px;width:100%;padding:8px 10px;
  border:none;background:none;color:var(--muted2);cursor:pointer;
  border-radius:var(--radius-sm);font-size:12.5px;text-align:left;
  transition:all .15s;margin-bottom:2px
}
.nav-btn:hover{background:var(--surface2);color:var(--text)}
.nav-btn.active{
  background:var(--surface3);color:var(--accent);
  border-left:3px solid var(--accent);padding-left:7px
}
.nav-btn .icon{font-size:14px;width:18px;text-align:center}
.theme-wrap{padding:12px 16px;border-top:1px solid var(--border)}
.theme-label{font-size:10px;color:var(--muted);text-transform:uppercase;
  letter-spacing:.8px;margin-bottom:6px}
.theme-pill{
  display:flex;background:var(--surface2);border:1px solid var(--border);
  border-radius:20px;padding:2px;gap:2px
}
.theme-opt{
  flex:1;padding:4px 0;border:none;background:none;cursor:pointer;
  border-radius:16px;font-size:11px;color:var(--muted);transition:all .2s
}
.theme-opt.active{background:var(--accent);color:#fff;font-weight:600}
.sidebar-footer{padding:10px 16px 14px;border-top:1px solid var(--border)}
.sidebar-footer p{font-size:10px;color:var(--muted);line-height:1.6}
/* Main */
#main{margin-left:236px;flex:1;min-height:100vh;padding:0}
.page{display:none;padding:28px 32px;animation:fadeIn .25s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.page-header{margin-bottom:24px}
.page-title{font-size:20px;font-weight:700;color:var(--text)}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px}
/* Stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;margin-bottom:28px}
.stat-card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:16px;transition:transform .2s,box-shadow .2s;cursor:default
}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow)}
.stat-card.c-blue{border-top:3px solid var(--accent)}
.stat-card.c-cyan{border-top:3px solid var(--accent2)}
.stat-card.c-purple{border-top:3px solid var(--accent3)}
.stat-card.c-green{border-top:3px solid var(--green)}
.stat-card.c-amber{border-top:3px solid var(--amber)}
.stat-card.c-red{border-top:3px solid var(--red)}
.stat-val{font-size:26px;font-weight:700;font-family:var(--mono);color:var(--text);line-height:1}
.stat-lbl{font-size:11px;color:var(--muted);margin-top:6px}
/* Panel */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  margin-bottom:20px}
.panel-hdr{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;
  align-items:center;justify-content:space-between}
.panel-title{font-size:13px;font-weight:700;color:var(--text)}
.panel-body{padding:18px}
/* Table */
.toolbar{display:flex;align-items:center;gap:10px;padding:12px 16px;
  border-bottom:1px solid var(--border);flex-wrap:wrap}
.search-wrap{position:relative;flex:1;min-width:180px}
.search-wrap input{
  width:100%;padding:7px 10px 7px 32px;background:var(--surface2);
  border:1px solid var(--border);border-radius:var(--radius-sm);
  color:var(--text);font-size:12px
}
.search-wrap::before{
  content:"🔍";position:absolute;left:9px;top:50%;transform:translateY(-50%);
  font-size:12px;pointer-events:none
}
.filter-select{
  padding:7px 10px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);font-size:12px;cursor:pointer
}
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{
  background:var(--surface2);color:var(--muted2);font-weight:600;
  padding:9px 12px;text-align:left;border-bottom:1px solid var(--border);
  cursor:pointer;white-space:nowrap;user-select:none
}
th:hover{color:var(--text)}
th.sort-active{color:var(--accent)}
.sort-arrow{margin-left:4px;font-size:10px}
td{padding:9px 12px;border-bottom:1px solid var(--border);color:var(--muted2);
  vertical-align:middle;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--surface2);cursor:pointer}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:600}
.badge-green{background:rgba(63,185,80,.15);color:var(--green)}
.badge-red{background:rgba(248,81,73,.15);color:var(--red)}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber)}
.badge-cyan{background:rgba(57,197,207,.15);color:var(--accent2)}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent)}
.badge-muted{background:var(--surface3);color:var(--muted)}
.pagination{display:flex;align-items:center;gap:8px;padding:12px 16px;
  border-top:1px solid var(--border);font-size:12px;flex-wrap:wrap}
.pg-info{color:var(--muted);flex:1}
.pg-btn{
  padding:4px 10px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:11px
}
.pg-btn:disabled{opacity:.4;cursor:default}
.pg-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-size-sel{padding:4px 8px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);font-size:11px;cursor:pointer}
/* Detail drawer */
#detailPanel{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;display:none}
#detailPanel.open{display:flex;align-items:flex-start;justify-content:flex-end}
#detailDrawer{
  width:min(540px,95vw);height:100vh;background:var(--surface);
  border-left:1px solid var(--border);overflow-y:auto;padding:24px;
  animation:slideIn .25s ease
}
@keyframes slideIn{from{transform:translateX(100%)}to{transform:none}}
.drawer-hdr{display:flex;align-items:flex-start;justify-content:space-between;
  margin-bottom:18px}
.drawer-title{font-size:15px;font-weight:700;color:var(--text)}
.drawer-close{
  background:none;border:none;color:var(--muted);cursor:pointer;
  font-size:18px;padding:0 4px;line-height:1
}
.chip-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.chip{display:inline-block;padding:3px 10px;border-radius:14px;font-size:11px;
  background:var(--surface2);border:1px solid var(--border);color:var(--muted2)}
.detail-kv{margin-bottom:10px}
.detail-k{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;
  margin-bottom:3px}
.detail-v{font-size:12px;color:var(--text);font-family:var(--mono);
  background:var(--surface2);border-radius:var(--radius-sm);padding:6px 10px;
  word-break:break-all;border:1px solid var(--border)}
.drawer-nav{display:flex;gap:8px;margin-top:18px}
.drawer-nav-btn{
  flex:1;padding:7px;background:var(--surface2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px
}
/* Toast */
#toast{
  position:fixed;bottom:24px;right:24px;background:var(--surface3);
  border:1px solid var(--border);border-radius:var(--radius);
  padding:10px 16px;font-size:12px;color:var(--text);z-index:999;
  opacity:0;transform:translateY(8px);pointer-events:none;
  transition:opacity .25s,transform .25s
}
#toast.show{opacity:1;transform:none}
/* Session info */
.kv-grid{display:grid;grid-template-columns:160px 1fr;gap:8px 16px;font-size:12px}
.kv-k{color:var(--muted);font-weight:600}
.kv-v{color:var(--text);font-family:var(--mono);word-break:break-all}
/* Mobile */
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:300;
  background:var(--surface2);border:1px solid var(--border);border-radius:8px;
  padding:6px 10px;cursor:pointer;font-size:18px}
@media(max-width:768px){
  #sidebar{transform:translateX(-100%);transition:transform .25s}
  #sidebar.open{transform:none}
  #main{margin-left:0;padding-top:48px}
  #menuToggle{display:block}
}
</style>
</head>
<body>
<button id="menuToggle" onclick="toggleSidebar()">☰</button>

<nav id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🛡️</div>
    <div class="logo-title">Azure RBAC<br>Removal Report</div>
    <div class="logo-sub">Cloud Identity Toolkit</div>
    <span class="ver-badge">v__SCRIPT_VERSION__</span>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('pgOverview',this)">
      <span class="icon">📊</span>Overview
    </button>
    <button class="nav-btn" onclick="showPage('pgResults',this)">
      <span class="icon">📋</span>Results
    </button>
    <button class="nav-btn" onclick="showPage('pgSkipped',this)">
      <span class="icon">⏭️</span>Skipped / Ambiguous
    </button>
    <button class="nav-btn" onclick="showPage('pgSession',this)">
      <span class="icon">ℹ️</span>Session Info
    </button>
  </div>
  <div class="theme-wrap">
    <div class="theme-label">Theme</div>
    <div class="theme-pill">
      <button class="theme-opt active" id="thDark"  onclick="setTheme('dark')">Dark</button>
      <button class="theme-opt"        id="thLight" onclick="setTheme('light')">Light</button>
    </div>
  </div>
  <div class="sidebar-footer">
    <p>Generated: __GENERATED_AT__</p>
    <p>Press / to search &nbsp;·&nbsp; Esc to close</p>
  </div>
</nav>

<main id="main">

  <!-- Overview -->
  <section class="page active" id="pgOverview">
    <div class="page-header">
      <div class="page-title">Execution Overview</div>
      <div class="page-sub">Run mode: <strong>__RUN_MODE__</strong> &nbsp;·&nbsp; __TOTAL_ROWS__ rows in input CSV</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-green">
        <div class="stat-val">__REMOVED__</div>
        <div class="stat-lbl">Removed</div>
      </div>
      <div class="stat-card c-cyan">
        <div class="stat-val">__WHATIF__</div>
        <div class="stat-lbl">WhatIf (Preview)</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-val">__NOTFOUND__</div>
        <div class="stat-lbl">Not Found</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-val">__AMBIGUOUS__</div>
        <div class="stat-lbl">Ambiguous</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-val">__SKIPPED__</div>
        <div class="stat-lbl">Skipped</div>
      </div>
      <div class="stat-card c-red">
        <div class="stat-val">__ERRORS__</div>
        <div class="stat-lbl">Errors</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-val">__UNIQUE_PRINCIPALS__</div>
        <div class="stat-lbl">Unique Principals Targeted</div>
      </div>
      <div class="stat-card c-purple">
        <div class="stat-val">__DURATION__s</div>
        <div class="stat-lbl">Duration</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-hdr"><span class="panel-title">Result Distribution</span></div>
      <div class="panel-body" id="barPanel"></div>
    </div>
  </section>

  <!-- Results -->
  <section class="page" id="pgResults">
    <div class="page-header">
      <div class="page-title">Assignment Results</div>
      <div class="page-sub">All processed rows (excluding skipped/ambiguous)</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <input type="text" id="resSearch" placeholder="Search principal, role, scope…"
                 oninput="filterResults()"/>
        </div>
        <select class="filter-select" id="resStatus" onchange="filterResults()">
          <option value="">All Statuses</option>
          <option value="Removed">Removed</option>
          <option value="WhatIf">WhatIf</option>
          <option value="NotFound">NotFound</option>
          <option value="Error">Error</option>
        </select>
        <select class="filter-select" id="resObjType" onchange="filterResults()">
          <option value="">All Types</option>
          <option value="User">User</option>
          <option value="Group">Group</option>
          <option value="ServicePrincipal">ServicePrincipal</option>
          <option value="Unknown">Unknown</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="resTbl">
          <thead>
            <tr>
              <th onclick="sortTable('resTbl',0,this)">Principal<span class="sort-arrow"></span></th>
              <th onclick="sortTable('resTbl',1,this)">Type<span class="sort-arrow"></span></th>
              <th onclick="sortTable('resTbl',2,this)">Role<span class="sort-arrow"></span></th>
              <th onclick="sortTable('resTbl',3,this)">Subscription<span class="sort-arrow"></span></th>
              <th onclick="sortTable('resTbl',4,this)">Status<span class="sort-arrow"></span></th>
            </tr>
          </thead>
          <tbody id="resTbody"></tbody>
        </table>
      </div>
      <div class="pagination" id="resPagination"></div>
    </div>
  </section>

  <!-- Skipped -->
  <section class="page" id="pgSkipped">
    <div class="page-header">
      <div class="page-title">Skipped &amp; Ambiguous</div>
      <div class="page-sub">Rows that were not actioned due to validation or ambiguity</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <input type="text" id="skipSearch" placeholder="Search…" oninput="filterSkipped()"/>
        </div>
        <select class="filter-select" id="skipCode" onchange="filterSkipped()">
          <option value="">All Codes</option>
          <option value="SKIPPED-INVALID-OBJECTTYPE">Invalid ObjectType</option>
          <option value="SKIPPED-NOACTION">No Action</option>
          <option value="AMBIGUOUS-MULTIPLE-MATCHES">Ambiguous</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table id="skipTbl">
          <thead>
            <tr>
              <th onclick="sortTable('skipTbl',0,this)">Principal<span class="sort-arrow"></span></th>
              <th onclick="sortTable('skipTbl',1,this)">Type<span class="sort-arrow"></span></th>
              <th onclick="sortTable('skipTbl',2,this)">Role<span class="sort-arrow"></span></th>
              <th onclick="sortTable('skipTbl',3,this)">Code<span class="sort-arrow"></span></th>
              <th onclick="sortTable('skipTbl',4,this)">Message<span class="sort-arrow"></span></th>
            </tr>
          </thead>
          <tbody id="skipTbody"></tbody>
        </table>
      </div>
      <div class="pagination" id="skipPagination"></div>
    </div>
  </section>

  <!-- Session Info -->
  <section class="page" id="pgSession">
    <div class="page-header">
      <div class="page-title">Session Information</div>
      <div class="page-sub">Runtime context for this execution</div>
    </div>
    <div class="panel">
      <div class="panel-hdr"><span class="panel-title">Run Details</span></div>
      <div class="panel-body">
        <div class="kv-grid">
          <span class="kv-k">Script Version</span><span class="kv-v">v__SCRIPT_VERSION__</span>
          <span class="kv-k">Run Mode</span><span class="kv-v">__RUN_MODE__</span>
          <span class="kv-k">Executed By</span><span class="kv-v">__RUN_BY__</span>
          <span class="kv-k">Azure Account</span><span class="kv-v">__RUN_BY_ACCOUNT__</span>
          <span class="kv-k">Tenant ID</span><span class="kv-v">__TENANT_ID__</span>
          <span class="kv-k">Start Time</span><span class="kv-v">__START_TIME__</span>
          <span class="kv-k">End Time</span><span class="kv-v">__END_TIME__</span>
          <span class="kv-k">Duration</span><span class="kv-v">__DURATION__ seconds</span>
          <span class="kv-k">Input CSV</span><span class="kv-v">__INPUT_CSV__</span>
          <span class="kv-k">Backup JSON</span><span class="kv-v">__BACKUP_JSON__</span>
          <span class="kv-k">Backup CSV</span><span class="kv-v">__BACKUP_CSV__</span>
          <span class="kv-k">Summary CSV</span><span class="kv-v">__SUMMARY_CSV__</span>
          <span class="kv-k">Log File</span><span class="kv-v">__LOG_PATH__</span>
        </div>
      </div>
    </div>
  </section>

</main>

<!-- Detail drawer -->
<div id="detailPanel" onclick="closeDrawer(event)">
  <div id="detailDrawer">
    <div class="drawer-hdr">
      <div class="drawer-title" id="drawerTitle">Assignment Detail</div>
      <button class="drawer-close" onclick="closeDrawer()">✕</button>
    </div>
    <div class="chip-row" id="drawerChips"></div>
    <div id="drawerBody"></div>
    <div class="drawer-nav">
      <button class="drawer-nav-btn" id="btnPrev" onclick="navDrawer(-1)">← Previous</button>
      <button class="drawer-nav-btn" id="btnNext" onclick="navDrawer(1)">Next →</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
'use strict';

const allData     = __ALL_ROWS_JSON__;
const skippedData = __SKIPPED_ROWS_JSON__;

let resFiltered  = [...allData];
let skipFiltered = [...skippedData];
let resPage      = 1, skipPage = 1;
const PAGE_SIZE  = 20;
let currentDetailList  = [];
let currentDetailIndex = 0;
let sortState = {};

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function escJ(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'");}

function statusBadge(s){
  const m={Removed:'badge-green',WhatIf:'badge-cyan',NotFound:'badge-amber',
           Error:'badge-red',Ambiguous:'badge-red',Skipped:'badge-amber'};
  const cls = m[s]||'badge-muted';
  return `<span class="badge ${cls}">${escH(s)}</span>`;
}
function codeBadge(c){
  if(c==='REMOVED')      return `<span class="badge badge-green">${escH(c)}</span>`;
  if(c==='WHATIF')       return `<span class="badge badge-cyan">${escH(c)}</span>`;
  if(c==='NOT-FOUND')    return `<span class="badge badge-amber">${escH(c)}</span>`;
  if(c==='ERR-REMOVE'||c==='ERR-UNHANDLED'||c==='ERR-SET-CONTEXT')
                         return `<span class="badge badge-red">${escH(c)}</span>`;
  if(c==='AMBIGUOUS-MULTIPLE-MATCHES') return `<span class="badge badge-red">AMBIGUOUS</span>`;
  return `<span class="badge badge-muted">${escH(c)}</span>`;
}

/* ── Results table ────────────────────────────────────────────── */
function filterResults(){
  const q   = document.getElementById('resSearch').value.toLowerCase();
  const st  = document.getElementById('resStatus').value;
  const ot  = document.getElementById('resObjType').value;
  resFiltered = allData.filter(r=>{
    const txt = (r.signInName+r.displayName+r.role+r.scope+r.subscriptionName).toLowerCase();
    return (!q||txt.includes(q)) && (!st||r.status===st) && (!ot||r.objectType===ot);
  });
  resPage = 1;
  renderResults();
}

function renderResults(){
  const tbody = document.getElementById('resTbody');
  const start = (resPage-1)*PAGE_SIZE;
  const slice = resFiltered.slice(start, start+PAGE_SIZE);
  tbody.innerHTML = slice.map((r,i)=>`
    <tr onclick="openDrawer(${start+i},'res')">
      <td title="${escH(r.scope)}">${escH(r.displayName||r.signInName)}</td>
      <td>${escH(r.objectType)}</td>
      <td title="${escH(r.role)}">${escH(r.role)}</td>
      <td>${escH(r.subscriptionName)}</td>
      <td>${statusBadge(r.status)}</td>
    </tr>`).join('');
  renderPagination('resPagination', resFiltered.length, resPage, PAGE_SIZE, p=>{ resPage=p; renderResults(); });
}

/* ── Skipped table ───────────────────────────────────────────── */
function filterSkipped(){
  const q   = document.getElementById('skipSearch').value.toLowerCase();
  const code= document.getElementById('skipCode').value;
  skipFiltered = skippedData.filter(r=>{
    const txt = (r.signInName+r.displayName+r.role+r.scope+r.message).toLowerCase();
    return (!q||txt.includes(q)) && (!code||r.resultCode===code);
  });
  skipPage = 1;
  renderSkipped();
}

function renderSkipped(){
  const tbody = document.getElementById('skipTbody');
  const start = (skipPage-1)*PAGE_SIZE;
  const slice = skipFiltered.slice(start, start+PAGE_SIZE);
  tbody.innerHTML = slice.map((r,i)=>`
    <tr onclick="openDrawer(${start+i},'skip')">
      <td>${escH(r.displayName||r.signInName)}</td>
      <td>${escH(r.objectType)}</td>
      <td title="${escH(r.role)}">${escH(r.role)}</td>
      <td>${codeBadge(r.resultCode)}</td>
      <td title="${escH(r.message)}">${escH(r.message)}</td>
    </tr>`).join('');
  renderPagination('skipPagination', skipFiltered.length, skipPage, PAGE_SIZE, p=>{ skipPage=p; renderSkipped(); });
}

/* ── Pagination ──────────────────────────────────────────────── */
function renderPagination(id, total, page, size, cb){
  const el    = document.getElementById(id);
  const pages = Math.max(1,Math.ceil(total/size));
  const start = (page-1)*size+1;
  const end   = Math.min(page*size, total);
  let btns    = '';
  const lo    = Math.max(1,page-2), hi = Math.min(pages,page+2);
  if(lo>1) btns += `<button class="pg-btn" onclick="(${cb})(1)">1</button>`;
  if(lo>2) btns += `<span style="color:var(--muted)">…</span>`;
  for(let p=lo;p<=hi;p++) btns += `<button class="pg-btn${p===page?' active':''}" onclick="(${cb})(${p})">${p}</button>`;
  if(hi<pages-1) btns += `<span style="color:var(--muted)">…</span>`;
  if(hi<pages)   btns += `<button class="pg-btn" onclick="(${cb})(${pages})">${pages}</button>`;
  el.innerHTML = `
    <span class="pg-info">${total===0?'No results':start+'–'+end+' of '+total}</span>
    <button class="pg-btn" onclick="(${cb})(${page-1})" ${page<=1?'disabled':''}>‹</button>
    ${btns}
    <button class="pg-btn" onclick="(${cb})(${page+1})" ${page>=pages?'disabled':''}>›</button>`;
}

/* ── Sort ────────────────────────────────────────────────────── */
function sortTable(tblId, colIdx, th){
  const ths = th.closest('thead').querySelectorAll('th');
  ths.forEach(t=>{ t.classList.remove('sort-active'); t.querySelector('.sort-arrow').textContent=''; });
  const key = tblId+'-'+colIdx;
  sortState[key] = sortState[key]==='asc' ? 'desc' : 'asc';
  const asc = sortState[key]==='asc';
  th.classList.add('sort-active');
  th.querySelector('.sort-arrow').textContent = asc ? ' ↑' : ' ↓';
  const keys = tblId==='resTbl'
    ? ['signInName','objectType','role','subscriptionName','status']
    : ['signInName','objectType','role','resultCode','message'];
  const arr  = tblId==='resTbl' ? resFiltered : skipFiltered;
  arr.sort((a,b)=>{
    const av=String(a[keys[colIdx]]||''), bv=String(b[keys[colIdx]]||'');
    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  if(tblId==='resTbl'){ resPage=1; renderResults(); }
  else                { skipPage=1; renderSkipped(); }
}

/* ── Detail drawer ───────────────────────────────────────────── */
function openDrawer(idx, source){
  currentDetailList  = source==='res' ? resFiltered : skipFiltered;
  currentDetailIndex = idx;
  renderDrawer();
  document.getElementById('detailPanel').classList.add('open');
}
function renderDrawer(){
  const r   = currentDetailList[currentDetailIndex];
  if(!r) return;
  const isRes = r.status !== undefined;
  document.getElementById('drawerTitle').textContent = r.displayName || r.signInName || 'Assignment Detail';
  document.getElementById('drawerChips').innerHTML = [
    r.objectType ? `<span class="chip">${escH(r.objectType)}</span>` : '',
    r.status     ? statusBadge(r.status) : '',
    r.resultCode ? codeBadge(r.resultCode) : ''
  ].join('');
  const fields = isRes
    ? [['Display Name',r.displayName],['Sign-In Name',r.signInName],['Object Type',r.objectType],
       ['Role',r.role],['Scope',r.scope],['Subscription',r.subscriptionName],
       ['Status',r.status],['Result Code',r.resultCode],['Message',r.message],['Execution Time',r.executionTime]]
    : [['Display Name',r.displayName],['Sign-In Name',r.signInName],['Object Type',r.objectType],
       ['Role',r.role],['Scope',r.scope],['Result Code',r.resultCode],['Message',r.message],['Execution Time',r.executionTime]];
  document.getElementById('drawerBody').innerHTML = fields.map(([k,v])=>`
    <div class="detail-kv">
      <div class="detail-k">${escH(k)}</div>
      <div class="detail-v">${escH(v||'—')}</div>
    </div>`).join('');
  document.getElementById('btnPrev').disabled = currentDetailIndex === 0;
  document.getElementById('btnNext').disabled = currentDetailIndex === currentDetailList.length-1;
}
function navDrawer(dir){
  const n = currentDetailIndex+dir;
  if(n>=0 && n<currentDetailList.length){ currentDetailIndex=n; renderDrawer(); }
}
function closeDrawer(e){
  if(!e || e.target===document.getElementById('detailPanel'))
    document.getElementById('detailPanel').classList.remove('open');
}

/* ── Bar chart ───────────────────────────────────────────────── */
function buildBars(){
  const counts={Removed:0,WhatIf:0,NotFound:0,Ambiguous:0,Skipped:0,Error:0};
  [...allData,...skippedData].forEach(r=>{ if(counts[r.status]!==undefined) counts[r.status]++; });
  const max = Math.max(...Object.values(counts),1);
  const colors={Removed:'var(--green)',WhatIf:'var(--accent2)',NotFound:'var(--amber)',
                Ambiguous:'var(--red)',Skipped:'var(--amber)',Error:'var(--red)'};
  const el = document.getElementById('barPanel');
  el.innerHTML = Object.entries(counts).map(([k,v])=>`
    <div class="bar-row" style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
      <div style="width:100px;font-size:12px;color:var(--muted2);text-align:right">${k}</div>
      <div class="bar-track" style="flex:1;height:14px;background:var(--surface3);border-radius:7px;overflow:hidden">
        <div class="bar-fill" data-pct="${(v/max*100).toFixed(1)}"
             style="height:100%;width:0;background:${colors[k]};border-radius:7px;transition:width .6s ease"></div>
      </div>
      <div style="width:36px;font-size:12px;font-family:var(--mono);color:var(--text)">${v}</div>
    </div>`).join('');
  requestAnimationFrame(()=>{
    document.querySelectorAll('.bar-fill').forEach(b=>{
      b.style.width = b.dataset.pct+'%';
    });
  });
}

/* ── Page navigation ─────────────────────────────────────────── */
function showPage(id, btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  if(btn) btn.classList.add('active');
}

/* ── Theme ───────────────────────────────────────────────────── */
function setTheme(t){
  document.body.classList.toggle('light-theme', t==='light');
  document.getElementById('thDark').classList.toggle('active',  t==='dark');
  document.getElementById('thLight').classList.toggle('active', t==='light');
  localStorage.setItem('rbacTheme', t);
}

/* ── Sidebar mobile ──────────────────────────────────────────── */
function toggleSidebar(){
  document.getElementById('sidebar').classList.toggle('open');
}

/* ── Toast ───────────────────────────────────────────────────── */
function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),2800);
}

/* ── Keyboard shortcuts ──────────────────────────────────────── */
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='/'&&!['INPUT','TEXTAREA'].includes(document.activeElement.tagName)){
    e.preventDefault();
    const active=document.querySelector('.page.active');
    const inp=active&&active.querySelector('input[type=text]');
    if(inp) inp.focus();
  }
  if(document.getElementById('detailPanel').classList.contains('open')){
    if(e.key==='ArrowLeft')  navDrawer(-1);
    if(e.key==='ArrowRight') navDrawer(1);
  }
});

/* ── Init ────────────────────────────────────────────────────── */
(function init(){
  const saved = localStorage.getItem('rbacTheme');
  if(saved==='light') setTheme('light');
  renderResults();
  renderSkipped();
  buildBars();
})();
</script>
</body>
</html>
'@

        #── Substitute tokens ────────────────────────────────────────────────
        $HtmlEndTime    = $RunEndTime.ToString("yyyy-MM-dd HH:mm:ss")
        $BackupJsonDisp = if ($DryRun) { "N/A (DryRun mode)" } else { $BackupJsonPath }
        $BackupCsvDisp  = if ($DryRun) { "N/A (DryRun mode)" } else { $BackupCsvPath  }
        $LogPathDisp    = if ($EnableLog) { $LogPath } else { "Not enabled" }

        $Html = $Html `
            -replace '__SCRIPT_VERSION__',   $ScriptVersion `
            -replace '__GENERATED_AT__',     $RunStartTime.ToString("yyyy-MM-dd HH:mm:ss") `
            -replace '__RUN_MODE__',         $RunMode `
            -replace '__TOTAL_ROWS__',       $TotalRows `
            -replace '__REMOVED__',          $RemovedCount `
            -replace '__WHATIF__',           $WhatIfCount `
            -replace '__NOTFOUND__',         $NotFoundCount `
            -replace '__AMBIGUOUS__',        $AmbiguousCount `
            -replace '__SKIPPED__',          $SkippedCount `
            -replace '__ERRORS__',           $ErrorCount `
            -replace '__UNIQUE_PRINCIPALS__',$UniquePrincipals `
            -replace '__DURATION__',         $DurationSecs `
            -replace '__RUN_BY__',           (ConvertTo-JsonSafe $RunBy) `
            -replace '__RUN_BY_ACCOUNT__',   (ConvertTo-JsonSafe $RunByAccount) `
            -replace '__TENANT_ID__',        (ConvertTo-JsonSafe $TenantIdLive) `
            -replace '__START_TIME__',       ($RunStartTime.ToString("yyyy-MM-dd HH:mm:ss")) `
            -replace '__END_TIME__',         $HtmlEndTime `
            -replace '__INPUT_CSV__',        (ConvertTo-JsonSafe $InputFileCsvPath) `
            -replace '__BACKUP_JSON__',      (ConvertTo-JsonSafe $BackupJsonDisp) `
            -replace '__BACKUP_CSV__',       (ConvertTo-JsonSafe $BackupCsvDisp) `
            -replace '__SUMMARY_CSV__',      (ConvertTo-JsonSafe $SummaryCsvPath) `
            -replace '__LOG_PATH__',         (ConvertTo-JsonSafe $LogPathDisp) `
            -replace '__ALL_ROWS_JSON__',    $AllRowsJson `
            -replace '__SKIPPED_ROWS_JSON__',$SkippedRowsJson

        $Html | Out-File -FilePath $HtmlReportPath -Encoding UTF8 -Force
        Write-Log -Message "HTML report written: $HtmlReportPath" -Tag "SUCCESS"
    }
    catch
    {
        Write-Log -Message "Failed to generate HTML report: $($_.Exception.Message)" -Tag "ERROR"
    }

    #── Console summary ──────────────────────────────────────────────────────
    Write-HostLog ""
    Write-HostLog $BannerLine -Color Cyan
    Write-HostLog " Execution Summary" -Color White
    Write-HostLog $BannerLine -Color Cyan
    Write-HostLog ("Start Time          : {0}" -f $RunStartTime.ToString("yyyy-MM-dd HH:mm:ss")) -Color Cyan
    Write-HostLog ("End Time            : {0}" -f $RunEndTime.ToString("yyyy-MM-dd HH:mm:ss"))   -Color Cyan
    Write-HostLog ("Duration            : {0}s" -f $DurationSecs)                                 -Color Cyan
    Write-HostLog ("Run By              : {0}" -f $RunByAccount)                                  -Color Cyan
    Write-HostLog ("Total Input Rows    : {0}" -f $TotalRows)                                     -Color White
    Write-HostLog ("Total Processed     : {0}" -f $TotalProcessed)                                -Color White
    Write-HostLog ("Removed             : {0}" -f $RemovedCount)                                  -Color Green
    Write-HostLog ("WhatIf              : {0}" -f $WhatIfCount)                                   -Color Cyan
    Write-HostLog ("NotFound            : {0}" -f $NotFoundCount)                                 -Color Yellow
    Write-HostLog ("Ambiguous           : {0}" -f $AmbiguousCount)                                -Color Red
    Write-HostLog ("Skipped             : {0}" -f $SkippedCount)                                  -Color Yellow
    Write-HostLog ("Errors              : {0}" -f $ErrorCount)                                    -Color Red
    Write-HostLog ("Unique Principals   : {0}" -f $UniquePrincipals)                              -Color White
    Write-HostLog $BannerLine -Color Cyan
    Write-HostLog ""
    if (-not $DryRun -and $BackupItems.Count -gt 0)
    {
        Write-HostLog ("  Backup JSON : {0}" -f $BackupJsonPath) -Color Cyan
        Write-HostLog ("  Backup CSV  : {0}" -f $BackupCsvPath)  -Color Cyan
    }
    Write-HostLog ("  Summary CSV : {0}" -f $SummaryCsvPath)    -Color Cyan
    Write-HostLog ("  HTML Report : {0}" -f $HtmlReportPath)     -Color Cyan
    if ($EnableLog) { Write-HostLog ("  Log File    : {0}" -f $LogPath) -Color Cyan }
    Write-HostLog ""
    #endregion

    return $Results | Select-Object ExecutionTime, SubscriptionName, SignInName,
        RoleDefinitionName, Status, Message, ResultCode | Format-Table -AutoSize
}


# ════════════════════════════════════════════════════════════════════════════════
# Companion: Restore-AzureRBACAssignments
# ════════════════════════════════════════════════════════════════════════════════

<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 08 August 2026
Modified-On  : 08 August 2026

.SYNOPSIS
    Restores Azure RBAC role assignments from a JSON backup produced by
    Remove-AzureRBACAssignments.

.DESCRIPTION
    Restore-AzureRBACAssignments reads the JSON backup file written by
    Remove-AzureRBACAssignments (path: RBACRemoval_Backup_<timestamp>.json)
    and re-creates each role assignment recorded in the backup.

    Key behaviours
    ──────────────
    • Supports all principal ObjectTypes that appear in the backup: User,
      ServicePrincipal, Group, Unknown — and any future types, because the
      restore uses ObjectId rather than a type-specific lookup.
    • Sets the correct subscription context per backup row so multi-subscription
      backups are restored accurately.
    • Detects assignments that already exist and marks them as AlreadyExists
      rather than erroring or duplicating.
    • Supports -DryRun (preview without changes) and -Force (suppress prompt).
    • Writes a timestamped restore-summary CSV to -OutputPath.
    • Writes unified console and, when -EnableLog is supplied, file log output.

.PARAMETER BackupJsonPath
    Full path to the JSON backup file generated by Remove-AzureRBACAssignments
    (e.g. C:\Temp\RBACRemoval_Backup_20260808-130000.json).

.PARAMETER OutputPath
    Folder where the restore-summary CSV and optional log file are written.
    Defaults to C:\Temp when omitted.

.PARAMETER EnableLog
    Switch. When supplied, detailed log lines are written to a timestamped .log
    file under -OutputPath.

.PARAMETER DryRun
    Switch. Validates each backup entry and logs what would be restored without
    calling New-AzRoleAssignment.

.PARAMETER Force
    Switch. Suppresses the interactive confirmation prompt shown before any
    live restores begin.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    Returns a collection of result objects summarising every processed row.

.EXAMPLE
    .\Remove-AzureRBACAssignments.ps1
    Restore-AzureRBACAssignments -BackupJsonPath "C:\Temp\RBACRemoval_Backup_20260808-130000.json"

    Restores all assignments captured in the backup after displaying a
    confirmation prompt.

.EXAMPLE
    Restore-AzureRBACAssignments `
        -BackupJsonPath "C:\Temp\RBACRemoval_Backup_20260808-130000.json" `
        -DryRun

    Dry-run. Shows what would be restored without making any changes.

.EXAMPLE
    Restore-AzureRBACAssignments `
        -BackupJsonPath "C:\Temp\RBACRemoval_Backup_20260808-130000.json" `
        -OutputPath     "C:\Audits\RBAC" `
        -EnableLog `
        -Force

    Restores all assignments immediately (no prompt) and writes a full log
    alongside the restore-summary CSV in C:\Audits\RBAC.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (08-Aug-2026) - Initial release. Companion restore function for
                        Remove-AzureRBACAssignments v1.2. Supports User, Group,
                        ServicePrincipal, Unknown, and future ObjectTypes via
                        ObjectId-based assignment.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts and Az.Resources PowerShell modules (auto-installed if absent).
    2. PowerShell 5.1 or higher.
    3. The executing identity must hold Owner or User Access Administrator on every
       subscription whose assignments appear in the backup.
    4. The backup JSON must have been produced by Remove-AzureRBACAssignments v1.2+.
    5. Identities that have been deleted from the tenant since the backup was taken
       cannot be restored — New-AzRoleAssignment will fail with a principal-not-found
       error; these rows are captured in the summary CSV with ResultCode ERR-RESTORE.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Deleted principals cannot be restored; they produce ERR-RESTORE rows.
    - Management-Group-scoped assignments require appropriate permissions at that
      scope; subscription-level Owner is not sufficient.
    - Restoring assignments to inherited/locked scopes may fail with a policy or
      deny-assignment conflict; review ERR-RESTORE rows in the summary CSV.

.LINK
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/RBAC/Remove-AzureRBACAssignments.ps1

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.resources/new-azroleassignment

.LINK
    https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal

#>

Function Restore-AzureRBACAssignments
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BackupJsonPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = "C:\Temp",

        [Parameter(Mandatory = $false)]
        [switch]$EnableLog,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    #region ── Constants ──────────────────────────────────────────────────────
    $ScriptVersion = "1.0"
    $RunStartTime  = Get-Date
    $Timestamp     = $RunStartTime.ToString("yyyyMMdd-HHmmss")
    $RunBy         = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
    $RunByAccount  = $null
    $SummaryCsvPath = Join-Path $OutputPath "RBACRestore_Summary_$Timestamp.csv"
    $RestoreLogPath = Join-Path $OutputPath "RBACRestore_$Timestamp.log"
    $BannerLine     = "─" * 95
    #endregion

    #region ── Inline helpers ─────────────────────────────────────────────────
    Function Write-RLog
    {
        param([Parameter(Mandatory=$true)][string]$Message, [string]$Tag = "INFO")
        $ts   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $tagf = ("[$Tag]").PadRight(10)
        $line = "[$ts] $tagf  $Message"
        switch ($Tag)
        {
            "ERROR"   { Write-Host $line -ForegroundColor Red }
            "WARNING" { Write-Host $line -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $line -ForegroundColor Green }
            default   { Write-Host $line -ForegroundColor White }
        }
        if ($EnableLog)
        {
            $ld = Split-Path $RestoreLogPath -Parent
            if (-not (Test-Path $ld)) { New-Item -Path $ld -ItemType Directory -Force | Out-Null }
            Add-Content -Path $RestoreLogPath -Value $line
        }
    }

    Function Write-RHostLog
    {
        param([string]$Message = "", [string]$Color = "White")
        if ([string]::IsNullOrWhiteSpace($Message))
        {
            Write-Host ""
            if ($EnableLog) { Add-Content -Path $RestoreLogPath -Value "" }
            return
        }
        Write-Host $Message -ForegroundColor $Color
        if ($EnableLog)
        {
            $ld = Split-Path $RestoreLogPath -Parent
            if (-not (Test-Path $ld)) { New-Item -Path $ld -ItemType Directory -Force | Out-Null }
            Add-Content -Path $RestoreLogPath -Value $Message
        }
    }
    #endregion

    #region ── Banner ─────────────────────────────────────────────────────────
    Clear-Host
    Write-RHostLog ""
    Write-RHostLog $BannerLine -Color Cyan
    Write-RHostLog ("              AZURE RBAC ASSIGNMENT RESTORE - v$ScriptVersion") -Color Green
    Write-RHostLog $BannerLine -Color Cyan
    Write-RHostLog ""
    Write-RHostLog ("Start Time   : {0}" -f $RunStartTime.ToString("yyyy-MM-dd HH:mm:ss")) -Color Cyan
    Write-RHostLog ("Operator     : {0}" -f $RunBy) -Color Cyan
    Write-RHostLog ("Backup JSON  : {0}" -f $BackupJsonPath) -Color Cyan
    Write-RHostLog ("Output Path  : {0}" -f $OutputPath) -Color Cyan
    Write-RHostLog ""
    #endregion

    #region ── Section 1 — Pre-requisites ─────────────────────────────────────
    Write-RHostLog "[1/5] Pre-requisites check" -Color Yellow
    Write-RHostLog $BannerLine -Color Cyan
    try
    {
        foreach ($m in @("Az.Accounts","Az.Resources"))
        {
            if (-not (Get-Module -ListAvailable -Name $m))
            {
                Write-RLog -Message "Module $m not found. Installing..." -Tag "WARNING"
                Install-Module -Name $m -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
            }
            Import-Module -Name $m -ErrorAction Stop
            Write-RLog -Message "Module $m loaded." -Tag "INFO"
        }
    }
    catch
    {
        Write-RLog -Message "Module check failed: $($_.Exception.Message)" -Tag "ERROR"
        return
    }
    if (-not (Test-Path $OutputPath))
    {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    Write-Host "`n  ✔ Modules OK" -ForegroundColor Green
    Write-RHostLog ""
    #endregion

    #region ── Section 2 — Authentication ─────────────────────────────────────
    Write-RHostLog "[2/5] Authentication" -Color Yellow
    Write-RHostLog $BannerLine -Color Cyan
    try
    {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $ctx)
        {
            Write-RLog -Message "No active session. Prompting for login..." -Tag "WARNING"
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $ctx = Get-AzContext -ErrorAction Stop
        }
        $RunByAccount = $ctx.Account.Id
        $TenantIdLive = $ctx.Tenant.Id
        Write-Host "`n  ✔ Authenticated as: $RunByAccount" -ForegroundColor Green
        Write-RLog -Message "Authenticated as $RunByAccount" -Tag "INFO"
    }
    catch
    {
        Write-RLog -Message "Authentication failed: $($_.Exception.Message)" -Tag "ERROR"
        return
    }
    Write-RHostLog ""
    #endregion

    #region ── Section 3 — Load backup JSON ───────────────────────────────────
    Write-RHostLog "[3/5] Loading backup file" -Color Yellow
    Write-RHostLog $BannerLine -Color Cyan
    if (-not (Test-Path $BackupJsonPath))
    {
        Write-RLog -Message "Backup JSON not found: $BackupJsonPath" -Tag "ERROR"
        return
    }
    try
    {
        $BackupData = Get-Content -Path $BackupJsonPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if (-not $BackupData -or @($BackupData).Count -eq 0)
        {
            Write-RLog -Message "Backup JSON contains no records." -Tag "WARNING"
            return
        }
    }
    catch
    {
        Write-RLog -Message "Failed to read backup JSON: $($_.Exception.Message)" -Tag "ERROR"
        return
    }
    $TotalRows = @($BackupData).Count
    Write-Host "`n  ✔ $TotalRows backup entries loaded." -ForegroundColor Green
    Write-RHostLog ""
    #endregion

    #region ── Section 4 — Confirmation ───────────────────────────────────────
    if (-not $DryRun)
    {
        $UniqueSubs = ($BackupData | Select-Object -ExpandProperty SubscriptionName -Unique).Count
        Write-RHostLog "[4/5] Confirmation" -Color Yellow
        Write-RHostLog $BannerLine -Color Cyan
        Write-RHostLog ""
        Write-RHostLog "  ⚠  You are about to RE-ASSIGN Azure RBAC assignments from backup." -Color Yellow
        Write-RHostLog ("     Entries to restore  : {0}" -f $TotalRows)     -Color Yellow
        Write-RHostLog ("     Subscriptions       : {0}" -f $UniqueSubs)    -Color Yellow
        Write-RHostLog ("     Authenticated as    : {0}" -f $RunByAccount)  -Color Yellow
        Write-RHostLog ("     Tenant              : {0}" -f $TenantIdLive)  -Color Yellow
        Write-RHostLog ""
        Write-RHostLog "     Use -DryRun to simulate without changes." -Color Cyan
        Write-RHostLog ""

        if (-not $Force)
        {
            $Confirm = Read-Host "  Type YES to proceed, or anything else to cancel"
            if ($Confirm -ne "YES")
            {
                Write-RHostLog ""
                Write-RLog -Message "Restore cancelled by operator." -Tag "WARNING"
                Write-RHostLog "  Operation cancelled. No assignments were restored." -Color Yellow
                return
            }
        }
        else
        {
            Write-RLog -Message "-Force supplied — skipping confirmation." -Tag "INFO"
        }
        Write-RHostLog ""
    }
    else
    {
        Write-RHostLog "[4/5] Confirmation — SKIPPED (DryRun mode)" -Color Cyan
        Write-RHostLog ""
    }
    #endregion

    #region ── Section 5 — Restore ────────────────────────────────────────────
    Write-RHostLog "[5/5] Restoring assignments" -Color Yellow
    Write-RHostLog $BannerLine -Color Cyan

    $Results   = New-Object System.Collections.Generic.List[PSObject]
    $RowIndex  = 0
    $RestoredCount      = 0
    $AlreadyExistsCount = 0
    $WhatIfCount        = 0
    $ErrorCount         = 0

    foreach ($Entry in $BackupData)
    {
        $RowIndex++
        $Pct = [math]::Round(($RowIndex / $TotalRows) * 100, 0)
        Write-Progress -Activity "Restore-AzureRBACAssignments" `
            -Status ("Restoring {0} of {1} — {2} — {3}" -f $RowIndex,$TotalRows,$Entry.DisplayName,$Entry.RoleDefinitionName) `
            -PercentComplete $Pct

        $Result = [PSCustomObject]@{
            ExecutionTime      = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            RunBy              = $RunByAccount
            SubscriptionName   = $Entry.SubscriptionName
            SubscriptionId     = $Entry.SubscriptionId
            TenantId           = $Entry.TenantId
            ObjectId           = $Entry.ObjectId
            ObjectType         = $Entry.ObjectType
            DisplayName        = $Entry.DisplayName
            SignInName         = $Entry.SignInName
            RoleDefinitionName = $Entry.RoleDefinitionName
            Scope              = $Entry.Scope
            Status             = ""
            Message            = ""
            ResultCode         = ""
        }

        Write-RHostLog ""
        Write-RLog -Message ("Row [{0}/{1}] Principal: [{2}] | Role: [{3}] | Scope: [{4}]" -f `
            $RowIndex,$TotalRows,$Entry.DisplayName,$Entry.RoleDefinitionName,$Entry.Scope) -Tag "INFO"

        try
        {
            #── Switch subscription context ──────────────────────────────────
            try
            {
                Set-AzContext -Subscription $Entry.SubscriptionId `
                    -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            }
            catch
            {
                $Result.Status     = "Error"
                $Result.Message    = "Failed to set subscription context: $($_.Exception.Message)"
                $Result.ResultCode = "ERR-SET-CONTEXT"
                $Results.Add($Result)
                $ErrorCount++
                Write-Host ("    [{0}/{1}] Error — cannot switch to subscription {2}" -f `
                    $RowIndex,$TotalRows,$Entry.SubscriptionId) -ForegroundColor Red
                Write-RLog -Message "Failed to set context to $($Entry.SubscriptionId): $($_.Exception.Message)" -Tag "ERROR"
                continue
            }

            #── Check if assignment already exists ────────────────────────────
            $Existing = $null
            try
            {
                $Existing = Get-AzRoleAssignment -ObjectId $Entry.ObjectId `
                    -RoleDefinitionName $Entry.RoleDefinitionName `
                    -Scope $Entry.Scope `
                    -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                    Where-Object { $_.Scope -eq $Entry.Scope }
            }
            catch { $Existing = $null }

            if ($Existing)
            {
                $Result.Status     = "AlreadyExists"
                $Result.Message    = "Assignment already exists — no action taken."
                $Result.ResultCode = "ALREADY-EXISTS"
                $Results.Add($Result)
                $AlreadyExistsCount++
                Write-Host ("    [{0}/{1}] AlreadyExists — {2} | {3} @ {4}" -f `
                    $RowIndex,$TotalRows,$Entry.DisplayName,$Entry.RoleDefinitionName,$Entry.Scope) -ForegroundColor DarkYellow
                Write-RLog -Message "AlreadyExists: $($Entry.DisplayName) — $($Entry.RoleDefinitionName) at $($Entry.Scope)" -Tag "INFO"
                continue
            }

            #── WhatIf ────────────────────────────────────────────────────────
            if ($DryRun)
            {
                $Result.Status     = "WhatIf"
                $Result.Message    = "Would restore via ObjectId: $($Entry.ObjectId)"
                $Result.ResultCode = "WHATIF"
                $Results.Add($Result)
                $WhatIfCount++
                Write-Host ("    [{0}/{1}] WhatIf — would restore {2} | {3} @ {4}" -f `
                    $RowIndex,$TotalRows,$Entry.DisplayName,$Entry.RoleDefinitionName,$Entry.Scope) -ForegroundColor Cyan
                Write-RLog -Message "WHATIF: $($Entry.DisplayName) — $($Entry.RoleDefinitionName) at $($Entry.Scope)" -Tag "INFO"
                continue
            }

            #── Restore ────────────────────────────────────────────────────────
            New-AzRoleAssignment -ObjectId $Entry.ObjectId `
                -RoleDefinitionName $Entry.RoleDefinitionName `
                -Scope $Entry.Scope `
                -ErrorAction Stop `
                -WarningAction SilentlyContinue | Out-Null

            $Result.Status     = "Restored"
            $Result.Message    = "Assignment restored successfully."
            $Result.ResultCode = "RESTORED"
            $Results.Add($Result)
            $RestoredCount++
            Write-Host ("    [{0}/{1}] Restored — {2} | {3} @ {4}" -f `
                $RowIndex,$TotalRows,$Entry.DisplayName,$Entry.RoleDefinitionName,$Entry.Scope) -ForegroundColor Green
            Write-RLog -Message ("Restored $($Entry.DisplayName) — $($Entry.RoleDefinitionName) at $($Entry.Scope)") -Tag "SUCCESS"
        }
        catch
        {
            $Result.Status     = "Error"
            $Result.Message    = $_.Exception.Message
            $Result.ResultCode = "ERR-RESTORE"
            $Results.Add($Result)
            $ErrorCount++
            Write-Host ("    [{0}/{1}] Error restoring {2}: {3}" -f `
                $RowIndex,$TotalRows,$Entry.DisplayName,$_.Exception.Message) -ForegroundColor Red
            Write-RLog -Message "Failed to restore $($Entry.DisplayName): $($_.Exception.Message)" -Tag "ERROR"
        }
    }

    Write-Progress -Activity "Restore-AzureRBACAssignments" -Completed
    Write-RHostLog ""

    #── Summary CSV ──────────────────────────────────────────────────────────
    try
    {
        $Results | Select-Object ExecutionTime,RunBy,SubscriptionName,SubscriptionId,
            TenantId,ObjectId,ObjectType,DisplayName,SignInName,
            RoleDefinitionName,Scope,Status,Message,ResultCode |
            Export-Csv -Path $SummaryCsvPath -NoTypeInformation -Encoding UTF8 -Force
        Write-RLog -Message "Restore summary CSV written: $SummaryCsvPath" -Tag "SUCCESS"
    }
    catch { Write-RLog -Message "Failed to write summary CSV: $($_.Exception.Message)" -Tag "ERROR" }

    #── Console summary ───────────────────────────────────────────────────────
    $RunEndTime  = Get-Date
    $DurationSecs = [math]::Round(($RunEndTime - $RunStartTime).TotalSeconds, 1)

    Write-RHostLog ""
    Write-RHostLog $BannerLine -Color Cyan
    Write-RHostLog " Restore Summary" -Color White
    Write-RHostLog $BannerLine -Color Cyan
    Write-RHostLog ("Start Time       : {0}" -f $RunStartTime.ToString("yyyy-MM-dd HH:mm:ss")) -Color Cyan
    Write-RHostLog ("End Time         : {0}" -f $RunEndTime.ToString("yyyy-MM-dd HH:mm:ss"))   -Color Cyan
    Write-RHostLog ("Duration         : {0}s" -f $DurationSecs)                                 -Color Cyan
    Write-RHostLog ("Run By           : {0}" -f $RunByAccount)                                  -Color Cyan
    Write-RHostLog ("Total Entries    : {0}" -f $TotalRows)                                     -Color White
    Write-RHostLog ("Restored         : {0}" -f $RestoredCount)                                 -Color Green
    Write-RHostLog ("Already Exists   : {0}" -f $AlreadyExistsCount)                            -Color Yellow
    Write-RHostLog ("WhatIf           : {0}" -f $WhatIfCount)                                   -Color Cyan
    Write-RHostLog ("Errors           : {0}" -f $ErrorCount)                                    -Color Red
    Write-RHostLog $BannerLine -Color Cyan
    Write-RHostLog ""
    Write-RHostLog ("  Summary CSV : {0}" -f $SummaryCsvPath) -Color Cyan
    if ($EnableLog) { Write-RHostLog ("  Log File    : {0}" -f $RestoreLogPath) -Color Cyan }
    Write-RHostLog ""
    #endregion

    return $Results | Select-Object ExecutionTime,SubscriptionName,DisplayName,
        RoleDefinitionName,Status,Message,ResultCode | Format-Table -AutoSize
}
