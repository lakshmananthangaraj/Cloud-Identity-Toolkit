<#

Author       : Lakshmanan Thangaraj
Version      : 1.1
Created-On   : 31 October 2025
Modified-On  : 07 August 2026

.SYNOPSIS
    Removes Azure RBAC role assignments for principals (users, groups, service principals,
    managed identities) in bulk using a CSV-driven input file.

.DESCRIPTION
    Remove-AzureRBACAssignments automates identification and removal of Azure
    Role-Based Access Control (RBAC) assignments using a CSV file as the source of truth.
    Each row in the CSV represents one principal/role/scope combination; the script
    validates the assignment is still live and then removes it — or previews the removal
    when -WhatIf is supplied.

    Key behaviours
    ──────────────
    • Validates that the input CSV contains all required columns before processing any rows.
    • Switches Azure subscription context per row so multi-subscription reports are handled
      correctly.
    • Supports all principal ObjectTypes present in the CSV: User, ServicePrincipal, Group,
      and Unknown. User rows are matched by SignInName (UPN) as before. ServicePrincipal,
      Group, and Unknown rows are matched by Scope + RoleDefinitionName + ObjectType, then
      narrowed by DisplayName when it is populated in the CSV.
    • Rows missing or containing an unrecognized ObjectType are skipped (SKIPPED-INVALID-OBJECTTYPE).
    • If a ServicePrincipal/Group/Unknown row has no DisplayName in the CSV and more than one
      candidate assignment matches on Scope + RoleDefinitionName + ObjectType, the row is marked
      Ambiguous and skipped rather than guessing which assignment to remove.
    • Validates each assignment is still live before attempting removal. Already-removed or
      never-present assignments are logged as skipped — not as errors.
    • Supports -WhatIf. In WhatIf mode the script confirms whether the assignment currently
      exists and logs what would be removed without calling Remove-AzRoleAssignment.
    • Produces a timestamped summary CSV on every run listing each processed row with its
      Status, Message, and ResultCode — suitable for audit import into dashboards.
    • Writes unified console and file log output. Console lines are colour-coded by severity;
      file lines are timestamped and tagged (INFO / WARNING / SUCCESS / ERROR).

.PARAMETER InputFileCsvPath
    Full path to the CSV file containing RBAC assignment rows to remove. The file must
    exist and must contain the columns: SubscriptionName, SubscriptionId, TenantId,
    DisplayName, SignInName, ObjectType, RoleDefinitionName, Scope.

    ObjectType must be one of: User, ServicePrincipal, Group, Unknown.

.PARAMETER SummaryCsvPath
    Optional path for the summary CSV output file. When omitted, a timestamped file is
    auto-generated under C:\Temp (e.g. RBACRemoval_Summary_yyyyMMddHHmmss.csv).

.PARAMETER LogPath
    Optional path for the log file. When omitted, a timestamped file is auto-generated
    under C:\Temp (e.g. RBACRemoval_yyyyMMddHHmmss.log).

.PARAMETER EnableLog
    Switch. When supplied, detailed timestamped and tagged log lines are written to the
    file at -LogPath. Omit for high-volume runs where log I/O is not required.

.PARAMETER WhatIf
    Switch. Runs the script in preview mode — resolves and validates each assignment
    but does NOT call Remove-AzRoleAssignment. All would-be actions are recorded in the
    summary CSV with Status = "WhatIf".

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    None. All output is written to the console and, when -EnableLog is supplied, to the
    timestamped log file. A summary CSV is always written regardless of -EnableLog.

.EXAMPLE
    .\Remove-AzureRBACAssignments.ps1 -InputFileCsvPath "C:\Temp\RBACToRemove.csv"

    Processes the CSV and removes all matching role assignments, prompting for Azure
    authentication if no active session is detected.

.EXAMPLE
    .\Remove-AzureRBACAssignments.ps1 -InputFileCsvPath "C:\Temp\RBACToRemove.csv" -WhatIf

    Dry-run mode. Validates each row and logs what would be removed without making any
    changes. Safe to run against production before committing to a live removal.

.EXAMPLE
    .\Remove-AzureRBACAssignments.ps1 -InputFileCsvPath "C:\Temp\RBACToRemove.csv" -EnableLog

    Removes all matching assignments and writes a full timestamped log file alongside the
    summary CSV.

.EXAMPLE
    .\Remove-AzureRBACAssignments.ps1 `
        -InputFileCsvPath "C:\Temp\RBACToRemove.csv" `
        -SummaryCsvPath   "C:\Audits\RBAC_Summary.csv" `
        -LogPath          "D:\Logs\RBAC_Removal.log" `
        -EnableLog

    Uses explicit paths for both the summary CSV and log file instead of the auto-generated
    defaults under C:\Temp.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (31-Oct-2025) - Initial release. CSV-driven RBAC removal for user, group,
                        and service principal scenarios. Includes -WhatIf dry-run,
                        unified console/log output, pre-requisite and authentication
                        checks, and summary CSV reporting.
    1.1 (07-Aug-2026) - Extended to process all ObjectTypes (User, ServicePrincipal,
                        Group, Unknown) instead of skipping everything but User.
                        User rows are still matched by SignInName. Non-User rows are
                        matched by Scope + RoleDefinitionName + ObjectType, narrowed
                        by DisplayName when available. Added an Ambiguous safeguard
                        that skips (rather than guesses at) non-User rows with no
                        DisplayName and multiple candidate matches. Core validation,
                        removal, -WhatIf, logging, and summary logic unchanged.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts and Az.Resources PowerShell modules. The script will attempt to
       install any missing modules automatically.
    2. PowerShell 5.1 or higher.
    3. The executing identity must hold Owner or User Access Administrator on every
       subscription whose assignments appear in the input CSV.
    4. An active Azure session. The script prompts for Connect-AzAccount if no
       context is found.
    5. Input CSV must contain the columns: SubscriptionName, SubscriptionId, TenantId,
       DisplayName, SignInName, ObjectType, RoleDefinitionName, Scope.
    6. For ServicePrincipal/Group/Unknown rows, populate DisplayName in the CSV whenever
       possible. It is used to disambiguate between multiple assignments that share the
       same Scope + RoleDefinitionName + ObjectType. Rows without it that resolve to more
       than one candidate are skipped as Ambiguous rather than removed.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Role removals require Owner or User Access Administrator on the target scope;
      Contributor alone is not sufficient.
    - Processing very large CSVs across many subscriptions may take considerable time
      depending on tenant size and role-assignment volume. Consider splitting large
      CSVs into per-subscription batches for faster, parallel-friendly runs.
    - Management-Group-scoped assignments require the executing identity to hold the
      appropriate permissions at that scope; subscription-level Owner is not sufficient.
    - ServicePrincipal/Group/Unknown rows with a blank DisplayName can only be uniquely
      resolved when exactly one assignment matches Scope + RoleDefinitionName + ObjectType.
      Otherwise the row is skipped as Ambiguous to avoid removing the wrong assignment.

.LINK
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/RBAC/Get-AzureRBACAssignments.ps1
    
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
        [string]$InputFileCsvPath,

        [Parameter(Mandatory = $false)]
        [string]$SummaryCsvPath,

        [Parameter(Mandatory = $false)]
        [string]$LogPath,

        [Parameter(Mandatory = $false)]
        [switch]$EnableLog,

        [Parameter(Mandatory = $false)]
        [switch]$WhatIf
    )

    # Set defaults only if not supplied by user
    if (-not $SummaryCsvPath) {
        $SummaryCsvPath = "C:\Temp\RemovedRBACAssignments-{0:yyyyMMdd-HHmmss}.csv" -f (Get-Date)
    }
    if (-not $LogPath) {
        $LogPath = "C:\Temp\Remove-AzureRBACAssignments-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date)
    }

    # Local run metadata
    $RunStartTime = Get-Date
    $RunBy = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
    $RunByAccount = $null

    # Inline helper: Write-Log (uses local $EnableLog and $LogPath)
    Function Write-Log {
        param(
            [Parameter(Mandatory = $true)] [string]$Message,
            [string]$Tag = "INFO"
        )
        $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $tagf = ("[$Tag]").PadRight(10)
        $line = "[$ts] $tagf  $Message"
        switch ($Tag) {
            "ERROR" { Write-Host $line -ForegroundColor Red }
            "WARNING" { Write-Host $line -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $line -ForegroundColor Green }
            default { Write-Host $line -ForegroundColor White }
        }
        if ($EnableLog) {
            $logDir = Split-Path -Path $LogPath -Parent
            if (-not (Test-Path -Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
            Add-Content -Path $LogPath -Value $line
        }
    }

    # Inline helper: Write-HostLog (write plain text to screen + clean text to log file)
    Function Write-HostLog {
        param(
            [Parameter(Mandatory = $false)][string]$Message = "",
            [string]$Color = "White",
            [string]$Tag = "INFO"
        )

        # Handle empty message safely (just print a blank line)
        if ([string]::IsNullOrWhiteSpace($Message)) {
            Write-Host ""
            if ($EnableLog) {
                Add-Content -Path $LogPath -Value ""
            }
            return
        }

        # Show plain text on screen
        Write-Host $Message -ForegroundColor $Color

        # Write clean message to log file (without timestamp/tag)
        if ($EnableLog) {
            $logDir = Split-Path -Path $LogPath -Parent
            if (-not (Test-Path -Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            Add-Content -Path $LogPath -Value $Message
        }
    }

    # Inline helper: ensure required Az modules loaded once
    Function Ensure-AzModules {
        try {
            Write-Log -Message "Checking required Az modules..." -Tag "INFO"
            $mods = @("Az.Accounts","Az.Resources")
            foreach ($m in $mods) {
                if (-not (Get-Module -ListAvailable -Name $m)) {
                    Write-Log -Message "Module $m not found. Installing..." -Tag "WARNING"
                    Install-Module -Name $m -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                }
                Import-Module -Name $m -ErrorAction Stop
                Write-Log -Message "Module $m loaded." -Tag "INFO"
            }
            return $true
        } catch {
            Write-Log -Message "Failed to ensure Az modules: $($_.Exception.Message)" -Tag "ERROR"
            return $false
        }
    }

    # Inline helper: connect / verify context
    Function Ensure-AzureConnection {
        try {
            $ctx = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $ctx) {
                Write-Log -Message "No active Azure session found. Prompting for login..." -Tag "WARNING"
                Connect-AzAccount -ErrorAction Stop | Out-Null
                $ctx = Get-AzContext -ErrorAction Stop
            }
            $globalTenant = $ctx.Tenant.Id
            $RunByAccount = $ctx.Account.Id
            Write-Log -Message "Active Azure session: $($ctx.Account.Id) / $($ctx.Subscription.Id)" -Tag "INFO"
            return $ctx
        } catch {
            Write-Log -Message "Azure authentication failed: $($_.Exception.Message)" -Tag "ERROR"
            throw
        }
    }

    # Validate input and prepare
    Clear-Host
    $bannerLine = "─" * 95

    Write-HostLog "" -Color White
    Write-HostLog $bannerLine -Color Cyan
    Write-HostLog "                         AZURE RBAC ASSIGNMENT REMOVER - v1.1          " -Color Green
    Write-HostLog $bannerLine -Color Cyan
    Write-HostLog "" -Color White

    Write-HostLog ("Start Time   : {0}" -f $RunStartTime.ToString("yyyy-MM-dd HH:mm:ss")) -Color Cyan
    Write-HostLog ("Operator     : {0}" -f $RunBy) -Color Cyan
    Write-HostLog ("Input CSV    : {0}" -f $InputFileCsvPath) -Color Cyan
    Write-HostLog ("Summary CSV  : {0}" -f $SummaryCsvPath) -Color Cyan
    Write-HostLog ("Log File     : {0}" -f $LogPath) -Color Cyan
    Write-HostLog "" -Color White

    # Section 1 - Pre-requisites check
    Write-HostLog "[1/5] Pre-requisites check" -Color Yellow
    Write-HostLog "-----------------------------" -Color Cyan
    Write-Log -Message "Starting pre-requisites check" -Tag "INFO"
    if (-not (Ensure-AzModules)) 
    {
        Write-Log -Message "Pre-requisites failed. Exiting." -Tag "ERROR"
        return
    }
    Write-Host ""
    Write-Host "✔ Modules OK" -ForegroundColor Green
    Write-Log -Message "Pre-requisites check completed" -Tag "SUCCESS"
    Write-HostLog ""

    # Section 2 - Authentication
    Write-HostLog "[2/5] Authentication" -Color Yellow
    Write-HostLog "-----------------------------" -Color Cyan
    Write-Log -Message "Verifying Azure authentication" -Tag "INFO"
    $context = Ensure-AzureConnection
    $RunByAccount = $context.Account.Id
    Write-Host ""
    Write-Host "✔ Authenticated as: $RunByAccount" -ForegroundColor Green
    Write-Log -Message "Authentication successful: $RunByAccount" -Tag "SUCCESS"
    Write-HostLog ""

    # Section 3 - Loading input CSV
    Write-HostLog "[3/5] Loading input file" -Color Yellow
    Write-HostLog "-----------------------------" -Color Cyan
    Write-Log -Message "Loading CSV from $InputFileCsvPath" -Tag "INFO"
    if (-not (Test-Path -Path $InputFileCsvPath)) {
        Write-Log -Message "Input CSV not found: $InputFileCsvPath" -Tag "ERROR"
        return
    }

    try {
        $assignments = Import-Csv -Path $InputFileCsvPath -ErrorAction Stop
        if (-not $assignments -or $assignments.Count -eq 0) {
            Write-Log -Message "Input CSV contains no records." -Tag "WARNING"
            return
        }
    } 
    catch {
        Write-Log -Message "Failed to read CSV: $($_.Exception.Message)" -Tag "ERROR"
        return
    }

    # Validate columns
    $expected = @('SubscriptionName','SubscriptionId','TenantId','DisplayName','SignInName','ObjectType','RoleDefinitionName','Scope')
    $missing = $expected | Where-Object { -not ($assignments | Get-Member -Name $_ -MemberType NoteProperty -ErrorAction SilentlyContinue) }
    if ($missing) {
        Write-Log -Message "CSV missing required columns: $($missing -join ', ')" -Tag "ERROR"
        return
    }

    Write-Log -Message "Loaded $($assignments.Count) records" -Tag "INFO"
    Write-HostLog ""

    # Section 4 - Processing
    Write-HostLog "[4/5] Processing assignments" -Color Yellow
    Write-HostLog "-----------------------------" -Color Cyan
    Write-Log -Message "Begin processing assignments" -Tag "INFO"

    $results = New-Object System.Collections.Generic.List[PSObject]
    $total = $assignments.Count
    $i = 0
    $validObjectTypes = @('user','serviceprincipal','group','unknown')

    foreach ($row in $assignments) {
        $i++
        $pct = [math]::Round(($i / $total) * 100, 0)
        $progressText = "Processing $i of $total - $($row.SignInName) - $($row.RoleDefinitionName)"
        Write-Progress -Activity "Removing User RBAC Assignments" -Status $progressText -PercentComplete $pct

        $result = [PSCustomObject]@{
            ExecutionTime       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            RunBy               = $RunByAccount
            SubscriptionName    = $row.SubscriptionName
            SubscriptionId      = $row.SubscriptionId
            TenantId            = $row.TenantId
            DisplayName         = $row.DisplayName
            SignInName          = $row.SignInName
            ObjectType          = $row.ObjectType
            RoleDefinitionName  = $row.RoleDefinitionName
            Scope               = $row.Scope
            Status              = ""
            Message             = ""
            ResultCode          = ""
        }

        Write-HostLog ""
        Write-Log -Message "Processing user [$($row.SignInName)] in subscription [$($row.SubscriptionName)] with role [$($row.RoleDefinitionName)]" -Tag "INFO"

        try {
            # Accept any recognized ObjectType (User, ServicePrincipal, Group, Unknown).
            # Only rows with a missing/unrecognized ObjectType are skipped.
            $objType = if ($row.ObjectType) { $row.ObjectType.Trim() } else { $null }
            if (($null -eq $objType) -or ($objType -eq '') -or ($validObjectTypes -notcontains $objType.ToLower())) {
                $result.Status = "Skipped"
                $result.Message = "ObjectType is missing or not a recognized value (User/ServicePrincipal/Group/Unknown)"
                $result.ResultCode = "SKIPPED-INVALID-OBJECTTYPE"
                $results.Add($result)
                Write-Host ("    [{0}/{1}] Skipped: {2} (ObjectType: {3})" -f $i,$total,$row.SignInName,$row.ObjectType) -ForegroundColor Yellow
                Write-Log -Message "Skipped $($row.SignInName) - ObjectType $($row.ObjectType)" -Tag "WARNING"
                continue
            }

            try {
                Set-AzContext -Subscription $row.SubscriptionId -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            } 
            catch {
                $result.Status = "Error"
                $result.Message = "Failed to set subscription context: $($_.Exception.Message)"
                $result.ResultCode = "ERR-SET-CONTEXT"
                $results.Add($result)
                Write-Host ("    [{0}/{1}] Error setting context to subscription {2}" -f $i,$total,$row.SubscriptionId) -ForegroundColor Red
                Write-Log -Message "Failed to set context to $($row.SubscriptionId): $($_.Exception.Message)" -Tag "ERROR"
                continue
            }

            $found = @()
            try {
                if ($objType.ToLower() -eq 'user') {
                    # Unchanged behaviour for User principals: lookup by SignInName (UPN).
                    $found = Get-AzRoleAssignment -SignInName $row.SignInName -Scope $row.Scope -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                        Where-Object { $_.RoleDefinitionName -eq $row.RoleDefinitionName -and $_.Scope -eq $row.Scope }
                }
                else {
                    # Group / ServicePrincipal / Unknown principals don't have a resolvable
                    # SignInName. Match on Scope + RoleDefinitionName + ObjectType instead,
                    # then narrow by DisplayName when the CSV has one.
                    $candidates = Get-AzRoleAssignment -Scope $row.Scope -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                        Where-Object { $_.RoleDefinitionName -eq $row.RoleDefinitionName -and $_.Scope -eq $row.Scope -and $_.ObjectType -eq $row.ObjectType }

                    if ($row.DisplayName) {
                        $found = $candidates | Where-Object { $_.DisplayName -and ($_.DisplayName.Trim().ToLower() -eq $row.DisplayName.Trim().ToLower()) }
                    } else {
                        $found = $candidates
                    }
                }
            } catch {
                $found = @()
            }

            if (-not $found -or @($found).Count -eq 0) {
                $result.Status = "NotFound"
                $result.Message = "No matching assignment found"
                $result.ResultCode = "NOT-FOUND"
                $results.Add($result)
                Write-Host ("    [{0}/{1}] NotFound: {2} - {3} @ {4}" -f $i,$total,$row.SignInName,$row.RoleDefinitionName,$row.Scope) -ForegroundColor DarkYellow
                Write-Log -Message "No matching assignment for $($row.SignInName) - $($row.RoleDefinitionName) at $($row.Scope)" -Tag "WARNING"
                continue
            }

            # Safety guard: for non-User rows with no DisplayName to disambiguate, never
            # guess which of several matching assignments to remove.
            if (($objType.ToLower() -ne 'user') -and (-not $row.DisplayName) -and (@($found).Count -gt 1)) {
                $result.Status = "Ambiguous"
                $result.Message = "Multiple matching assignments found for this Scope/RoleDefinitionName/ObjectType and DisplayName is empty in the CSV - cannot safely determine which to remove."
                $result.ResultCode = "AMBIGUOUS-MULTIPLE-MATCHES"
                $results.Add($result)
                Write-Host ("    [{0}/{1}] Ambiguous: {2} matches found for {3} @ {4} (ObjectType: {5}) - DisplayName empty, skipping" -f $i,$total,@($found).Count,$row.RoleDefinitionName,$row.Scope,$row.ObjectType) -ForegroundColor Red
                Write-Log -Message "Ambiguous match ($(@($found).Count) results) for ObjectType $($row.ObjectType) at $($row.Scope)/$($row.RoleDefinitionName) - DisplayName empty in CSV. Skipped to avoid removing the wrong assignment." -Tag "WARNING"
                continue
            }

            $removedAny = $false

            foreach ($ra in $found) {
                if ($WhatIf) {
                    $rCopy = $result.PSObject.Copy()
                    $rCopy.Status = "WhatIf"
                    $rCopy.Message = "Would remove RoleAssignmentId: $($ra.RoleAssignmentId)"
                    $rCopy.ResultCode = "WHATIF"
                    $results.Add($rCopy)
                    Write-Host ("    [{0}/{1}] WhatIf: Would remove assignment Id {2} for {3} - {4}" -f $i,$total,$ra.RoleAssignmentId,$row.SignInName,$ra.RoleDefinitionName) -ForegroundColor Cyan
                    Write-Log -Message "WHATIF: Found assignment Id $($ra.RoleAssignmentId) for $($row.SignInName)" -Tag "INFO"
                    $removedAny = $true
                    continue
                }

                try {
                    Remove-AzRoleAssignment -ObjectId $ra.ObjectId -RoleDefinitionName $ra.RoleDefinitionName -Scope $ra.Scope -Confirm:$false -ErrorAction Stop -WarningAction SilentlyContinue
                    $rCopy = $result.PSObject.Copy()
                    $rCopy.Status = "Removed"
                    $rCopy.Message = "Removed RoleAssignmentId: $($ra.RoleAssignmentId)"
                    $rCopy.ResultCode = "REMOVED"
                    $results.Add($rCopy)
                    Write-Host ("    [{0}/{1}] Removed: {2} - {3} @ {4}" -f $i,$total,$row.SignInName,$ra.RoleDefinitionName,$ra.Scope) -ForegroundColor Green
                    Write-Log -Message "Removed $($row.SignInName) - $($ra.RoleDefinitionName) at $($ra.Scope) (Id: $($ra.RoleAssignmentId))" -Tag "SUCCESS"
                    $removedAny = $true
                } catch {
                    $rCopy = $result.PSObject.Copy()
                    $rCopy.Status = "Error"
                    $rCopy.Message = "Failed to remove RoleAssignmentId $($ra.RoleAssignmentId): $($_.Exception.Message)"
                    $rCopy.ResultCode = "ERR-REMOVE"
                    $results.Add($rCopy)
                    Write-Host ("    [{0}/{1}] Error removing assignment Id {2}: {3}" -f $i,$total,$ra.RoleAssignmentId,$_.Exception.Message) -ForegroundColor Red
                    Write-Log -Message "Failed to remove assignment Id $($ra.RoleAssignmentId) for $($row.SignInName): $($_.Exception.Message)" -Tag "ERROR"
                }
            }

            if (-not $removedAny) {
                $result.Status = "Skipped"
                $result.Message = "No action performed"
                $result.ResultCode = "SKIPPED-NOACTION"
                $results.Add($result)
                Write-Host ("    [{0}/{1}] Skipped (no action) for {2}" -f $i,$total,$row.SignInName) -ForegroundColor Yellow
            }
        } catch {
            $result.Status = "Error"
            $result.Message = $_.Exception.Message
            $result.ResultCode = "ERR-UNHANDLED"
            $results.Add($result)
            Write-Host ("    [{0}/{1}] Unhandled error for {2}: {3}" -f $i,$total,$row.SignInName,$_.Exception.Message) -ForegroundColor Red
            Write-Log -Message "Unhandled error processing $($row.SignInName): $($_.Exception.Message)" -Tag "ERROR"
        }
    }

    Write-Progress -Activity "Removing User RBAC Assignments" -Completed
    Write-HostLog ""

    # Section 5 - Summary & report
    Write-HostLog "[5/5] Summary & report" -Color Yellow
    Write-HostLog "-----------------------------" -Color Cyan
    Write-Log -Message "Generating summary and report" -Tag "INFO"

    $sumDir = Split-Path -Path $SummaryCsvPath -Parent
    if (-not (Test-Path -Path $sumDir)) { New-Item -Path $sumDir -ItemType Directory -Force | Out-Null }

    try {
        $results | Select-Object ExecutionTime,RunBy,SubscriptionName,SubscriptionId,TenantId,DisplayName,SignInName,ObjectType,RoleDefinitionName,Scope,Status,Message,ResultCode |
            Export-Csv -Path $SummaryCsvPath -NoTypeInformation -Encoding UTF8 -Force
        Write-Log -Message "Summary CSV generated: $SummaryCsvPath" -Tag "INFO"
    } catch {
        Write-Log -Message "Failed to write summary CSV: $($_.Exception.Message)" -Tag "ERROR"
    }

    # Compute insights
    $totalProcessed = @($results).Count
    $removedCount = @($results | Where-Object { $_.ResultCode -eq 'REMOVED' }).Count
    $whatIfCount = @($results | Where-Object { $_.ResultCode -eq 'WHATIF' }).Count
    $notFound = @($results | Where-Object { $_.ResultCode -eq 'NOT-FOUND' }).Count
    $ambiguous = @($results | Where-Object { $_.ResultCode -eq 'AMBIGUOUS-MULTIPLE-MATCHES' }).Count
    $skipped = @($results | Where-Object { $_.ResultCode -like 'SKIPPED*' }).Count
    $errors = @($results | Where-Object { $_.ResultCode -like 'ERR*' }).Count

    Write-HostLog "" -Color White
    Write-HostLog $bannerLine -Color Cyan
    Write-HostLog " Execution Summary" -Color White
    Write-HostLog $bannerLine -Color Cyan

    Write-HostLog ("Start Time : {0}" -f $RunStartTime.ToString("yyyy-MM-dd HH:mm:ss")) -Color Cyan
    Write-HostLog ("End Time   : {0}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) -Color Cyan
    Write-HostLog ("Run By     : {0}" -f $RunByAccount) -Color Cyan
    Write-HostLog ("Total Rows : {0}" -f $total) -Color White
    Write-HostLog ("Processed  : {0}" -f $totalProcessed) -Color White
    Write-HostLog ("Removed    : {0}" -f $removedCount) -Color Green
    Write-HostLog ("WhatIf     : {0}" -f $whatIfCount) -Color Cyan
    Write-HostLog ("NotFound   : {0}" -f $notFound) -Color Yellow
    Write-HostLog ("Ambiguous  : {0}" -f $ambiguous) -Color Red
    Write-HostLog ("Skipped    : {0}" -f $skipped) -Color Yellow
    Write-HostLog ("Errors     : {0}" -f $errors) -Color Red

    Write-HostLog $bannerLine -Color Cyan
    Write-HostLog "" -Color White

    return $results | Select-Object ExecutionTime, SubscriptionName,SignInName, RoleDefinitionName, Status,Message, ResultCode | ft
}
