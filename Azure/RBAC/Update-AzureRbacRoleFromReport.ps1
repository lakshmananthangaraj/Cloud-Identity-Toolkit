<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 19 October 2026
Modified-On  : 19 October 2026

.SYNOPSIS
    Replaces one Azure RBAC role with another for the identities listed in an RBAC assignment report CSV 
    (default: "Website Contributor" -> "Web App Contributor (No Delete)").

.DESCRIPTION
    Reads an Azure RBAC assignment report (CSV) and, ONLY for rows whose RoleDefinitionName equals the source role,
    performs the following at the exact Scope recorded in the CSV:

    1. Resolves the live role assignment (and its ObjectId) by matching DisplayName / SignInName / ObjectType.
    2. Assigns the target role to the same identity at the same scope (skipped if already assigned).
    3. Confirms the new assignment exists, then removes the source role assignment (skip with -KeepSourceRole).

    Works for any identity type present in the report (User, Group, ServicePrincipal / Application, Managed Identity).
    Nothing outside the rows listed in the CSV is touched. The function is idempotent: if the source assignment no longer
    exists, or the target role is already assigned, it exits cleanly for that row.

    Authentication: re-uses the existing Az context when present; otherwise prompts via Connect-AzAccount.
    Output: a modern colour console UI (banner, pre-flight checks, per-scope sections, status badges, summary dashboard).
    Files written to -LogPath: a log file, a per-row results CSV and a rollback CSV (original assignments removed).
    The log file is an exact plain-text mirror of the on-screen output (same layout, same badges, no colours),
    with a run header (start time, user, machine, options) and a footer (end time).
    Supports -WhatIf (full read-only simulation; log/results files are still written) and -Confirm.
    Use -Force to suppress the per-row confirmation prompts.

.PARAMETER CsvPath
    Full path of the RBAC assignment report CSV. Required columns: SubscriptionName, SubscriptionId, TenantId,
    DisplayName, SignInName, ObjectType, RoleDefinitionName, ResourceType, Scope.

.PARAMETER LogPath
    Folder where the log, results CSV and rollback CSV are written. Created if missing. Default: .\RoleReplacementLogs

.PARAMETER SourceRoleName
    Role to be replaced. Default: "Website Contributor".

.PARAMETER TargetRoleName
    Replacement role. Default: "Web App Contributor (No Delete)".

.PARAMETER TenantId
    Optional tenant GUID. Used when prompting for sign-in, and to force a re-connect if the current context is in a different tenant.

.PARAMETER KeepSourceRole
    Assign the target role but do NOT remove the source role assignment.

.PARAMETER PassThru
    Also emit the per-row result objects to the pipeline (the results are always saved to the results CSV).

.PARAMETER Force
    Suppresses the per-row confirmation prompt (the function is ConfirmImpact = High).

.INPUTS
    None. The function does not accept pipeline input.

.OUTPUTS
    None by default. With -PassThru: System.Management.Automation.PSCustomObject (one object per processed CSV row).

.EXAMPLE
    Update-AzureRbacRoleFromReport -CsvPath 'C:\Reports\RBAC_Report.csv' -WhatIf

    Simulation. Shows what would be assigned / removed without changing anything.

.EXAMPLE
    Update-AzureRbacRoleFromReport -CsvPath 'C:\Reports\RBAC_Report.csv' -LogPath 'C:\Logs\RBAC' -Force -Verbose

    Performs the replacement for every matching row without prompting, with verbose diagnostics.

.EXAMPLE
    Update-AzureRbacRoleFromReport -CsvPath .\RBAC_Report.csv -SourceRoleName 'Contributor' -TargetRoleName 'Reader' -KeepSourceRole -PassThru

    Uses a different role pair, adds the new role only, and returns the result objects.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (19-Oct-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. PowerShell 5.1 (or later) with Az.Accounts and Az.Resources modules installed.
    2. Caller needs Microsoft.Authorization/roleAssignments/write and /delete at the target scopes
    (e.g. Owner, User Access Administrator, or Role Based Access Control Administrator).
    3. The target role must already exist and be assignable at the target scopes.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Only exact-scope assignments are processed; inherited assignments from parent scopes are never modified.
    - The CSV has no ObjectId column, so identities are matched on DisplayName + ObjectType (+ SignInName when present).
    If more than one live assignment matches, the row is skipped as ambiguous.
    - Orphaned identities (ObjectType 'Unknown', blank DisplayName) cannot be matched and are skipped.
    - Conditional (ABAC) role assignments are not recreated with their conditions.
    - Assignable-scope check for the target role is best-effort; the API result is treated as authoritative.
    - Console UI uses colour and box-drawing characters; it is designed for the Windows PowerShell console, Windows Terminal and ISE.
    - The log mirrors the console output only: confirmation prompts, the progress bar, PowerShell warnings and -Verbose messages are not written to it.

.LINK
    https://learn.microsoft.com/powershell/module/az.resources/new-azroleassignment

.LINK
    https://learn.microsoft.com/powershell/module/az.resources/remove-azroleassignment

.LINK
    https://learn.microsoft.com/powershell/module/az.resources/get-azroleassignment

#>


Function Update-AzureRbacRoleFromReport
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ($_ -match '\.\.')
            {
                throw 'Path traversal sequence (..) is not allowed in -CsvPath.'
            }
            if (-not (Test-Path -LiteralPath $_ -PathType Leaf))
            {
                throw "CSV file not found: $_"
            }
            if ([System.IO.Path]::GetExtension($_) -ne '.csv')
            {
                throw 'The file must have a .csv extension.'
            }
            $true
        })]
        [string]$CsvPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ($_ -match '\.\.')
            {
                throw 'Path traversal sequence (..) is not allowed in -LogPath.'
            }
            if ($_.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0)
            {
                throw 'The -LogPath contains invalid characters.'
            }
            $true
        })]
        [string]$LogPath = (Join-Path -Path $PWD.Path -ChildPath 'RoleReplacementLogs'),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$SourceRoleName = 'Website Contributor',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TargetRoleName = 'Web App Contributor (No Delete)',

        [Parameter()]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$TenantId,

        [Parameter()]
        [switch]$KeepSourceRole,

        [Parameter()]
        [switch]$PassThru,

        [Parameter()]
        [switch]$Force
    )

    # -Force suppresses per-row confirmation unless -Confirm is explicit
    if ($Force -and -not $PSBoundParameters.ContainsKey('Confirm'))
    {
        $ConfirmPreference = 'None'
    }

    $sw      = [System.Diagnostics.Stopwatch]::StartNew()
    $isSim   = [bool]$WhatIfPreference
    $version = '1.0'

    # ------------------------------------------------------------------
    # UI primitives (CP437-safe box characters built from code points)
    # ------------------------------------------------------------------
    $ch = @{
        H     = [string][char]0x2500; V   = [string][char]0x2502
        TL    = [string][char]0x250C; BL  = [string][char]0x2514
        DH    = [string][char]0x2550; DV  = [string][char]0x2551
        DTL   = [string][char]0x2554; DTR = [string][char]0x2557
        DBL   = [string][char]0x255A; DBR = [string][char]0x255D
        DML   = [string][char]0x255F; DMR = [string][char]0x2562
        Full  = [string][char]0x2588; Lite = [string][char]0x2591
        Arrow = [string][char]0x25BA; Dot = [string][char]0x25A0
    }
    $uiWidth = 80
    try
    {
        $uiWidth = [Math]::Min(100, [Math]::Max(72, $Host.UI.RawUI.WindowSize.Width - 2))
    }
    catch
    {
        $uiWidth = 80
    }
    $uiInner = $uiWidth - 4

    $badgeMap = @{
        INFO      = @('INFO', 'Cyan', 'Black')
        OK        = @('OK', 'Green', 'Black')
        SUCCESS   = @('OK', 'Green', 'Black')
        WARN      = @('WARN', 'Yellow', 'Black')
        ERROR     = @('FAILED', 'Red', 'White')
        FAILED    = @('FAILED', 'Red', 'White')
        SKIP      = @('SKIPPED', 'DarkGray', 'White')
        WHATIF    = @('WHATIF', 'Yellow', 'Black')
        REPLACED  = @('REPLACED', 'Green', 'Black')
        ASSIGNED  = @('ASSIGNED', 'Cyan', 'Black')
    }

    function Write-UiBadge
    {
        param ([Parameter(Mandatory = $true)][string]$Kind)
        $b = $badgeMap[$Kind]
        Write-Host (' {0,-8} ' -f $b[0]) -BackgroundColor $b[1] -ForegroundColor $b[2] -NoNewline
        Write-Host ' ' -NoNewline
    }

    function Write-UiBoxEdge
    {
        param ([ValidateSet('Top', 'Mid', 'Bottom')][string]$Position, [string]$Color = 'Cyan')
        $line = switch ($Position)
        {
            'Top'    { $ch.DTL + ($ch.DH * ($uiWidth - 2)) + $ch.DTR }
            'Mid'    { $ch.DML + ($ch.H * ($uiWidth - 2)) + $ch.DMR }
            'Bottom' { $ch.DBL + ($ch.DH * ($uiWidth - 2)) + $ch.DBR }
        }
        Write-Host $line -ForegroundColor $Color
    }

    function Write-UiBoxLine
    {
        param ([string]$Text = '', [string]$Fore = 'White', [string]$Border = 'Cyan')
        if ($Text.Length -gt $uiInner)
        {
            $Text = $Text.Substring(0, $uiInner - 3) + '...'
        }
        Write-Host $ch.DV -ForegroundColor $Border -NoNewline
        Write-Host (' ' + $Text.PadRight($uiInner) + ' ') -ForegroundColor $Fore -NoNewline
        Write-Host $ch.DV -ForegroundColor $Border
    }

    function Format-UiSplit
    {
        param ([string]$Left, [string]$Right)
        $pad = $uiInner - $Right.Length
        if ($pad -lt 1) { $pad = 1 }
        return ($Left.PadRight($pad) + $Right)
    }

    function Write-UiSection
    {
        param ([Parameter(Mandatory = $true)][string]$Title)
        Write-Host ''
        Write-Host ($ch.Arrow + ' ') -ForegroundColor Cyan -NoNewline
        Write-Host $Title.ToUpper() -ForegroundColor White -NoNewline
        $fill = $uiWidth - $Title.Length - 3
        if ($fill -lt 2) { $fill = 2 }
        Write-Host (' ' + ($ch.H * ($fill - 1))) -ForegroundColor DarkCyan
    }

    function Write-UiRow
    {
        param (
            [int]$Index, [int]$Total, [string]$Kind,
            [string]$Name, [string]$Type, [string]$Detail
        )
        Write-Host ('  {0,-7}' -f ("$Index/$Total")) -ForegroundColor DarkGray -NoNewline
        Write-UiBadge -Kind $Kind
        Write-Host $Name -ForegroundColor White -NoNewline
        Write-Host ("  ($Type)") -ForegroundColor DarkGray -NoNewline
        Write-Host ('   ' + (Get-Date -Format 'HH:mm:ss')) -ForegroundColor DarkGray
        if ($Detail)
        {
            Write-Host ('          ' + $ch.BL + $ch.H + ' ' + $Detail) -ForegroundColor Gray
        }
    }

    function Get-ScopeLabel
    {
        param ([string]$Scope)
        $rg  = [regex]::Match($Scope, '/resourceGroups/([^/]+)', 'IgnoreCase')
        $res = [regex]::Match($Scope, '/providers/(.+)$', 'IgnoreCase')
        if ($res.Success -and $rg.Success)
        {
            return ('{0} {1} {2}' -f $rg.Groups[1].Value, $ch.Arrow, $res.Groups[1].Value)
        }
        if ($rg.Success)
        {
            return ('Resource group {0}' -f $rg.Groups[1].Value)
        }
        return $Scope
    }

    # ------------------------------------------------------------------
    # Log / output file set-up (always written, even under -WhatIf)
    # ------------------------------------------------------------------
    $stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $results = New-Object -TypeName 'System.Collections.Generic.List[object]'
    try
    {
        if (-not (Test-Path -LiteralPath $LogPath -PathType Container))
        {
            New-Item -Path $LogPath -ItemType Directory -Force -WhatIf:$false -Confirm:$false -ErrorAction Stop | Out-Null
        }
        $logFile      = Join-Path -Path $LogPath -ChildPath "RoleReplacement_$stamp.log"
        $resultFile   = Join-Path -Path $LogPath -ChildPath "RoleReplacement_Results_$stamp.csv"
        $rollbackFile = Join-Path -Path $LogPath -ChildPath "RoleReplacement_Rollback_$stamp.csv"
    }
    catch
    {
        throw "Unable to create log folder '$LogPath': $($_.Exception.Message)"
    }

    # The log file is written by the screen mirror below (Write-Host / Write-LogOnly),
    # so this function only shows the badge line on screen (-Console) and emits -Verbose output.
    function Write-RbacLog
    {
        param (
            [Parameter(Mandatory = $true)][string]$Message,
            [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'SKIP', 'WHATIF')][string]$Level = 'INFO',
            [switch]$Console
        )

        Write-Verbose ('[{0}] {1}' -f $Level, $Message)

        if ($Console)
        {
            Write-Host '  ' -NoNewline
            Write-UiBadge -Kind $Level
            Write-Host $Message -ForegroundColor Gray
        }
    }

    # ------------------------------------------------------------------
    # Log mirroring: everything written to the screen is also written to the log
    # ------------------------------------------------------------------
    $logState = @{ Text = ''; Warned = $false }

    # Writes a plain line to the log file only (nothing on screen)
    function Write-LogOnly
    {
        param ([string]$Text = '')
        try
        {
            Add-Content -LiteralPath $logFile -Value $Text -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop
        }
        catch
        {
            # Logging must never break the run; warn once only
            if (-not $logState.Warned)
            {
                $logState.Warned = $true
                Write-Warning "Could not write to log file: $($_.Exception.Message)"
            }
        }
    }

    # Shadows the Write-Host cmdlet inside this function only: shows the text on screen
    # (with colours) and appends the same text, without colours, to the log file.
    function Write-Host
    {
        [CmdletBinding()]
        param (
            [Parameter(Position = 0, ValueFromRemainingArguments = $true)][object[]]$Object,
            [switch]$NoNewline,
            [object]$Separator = ' ',
            [System.ConsoleColor]$ForegroundColor,
            [System.ConsoleColor]$BackgroundColor
        )

        Microsoft.PowerShell.Utility\Write-Host @PSBoundParameters

        $text = (@($Object) | ForEach-Object { [string]$_ }) -join [string]$Separator
        $logState.Text += $text
        if (-not $NoNewline)
        {
            Write-LogOnly -Text $logState.Text
            $logState.Text = ''
        }
    }

    function Add-RbacResult
    {
        param (
            [Parameter(Mandatory = $true)]$Row,
            [Parameter(Mandatory = $true)][string]$Status,
            [string]$Detail = '',
            [string]$ObjectId = ''
        )

        $results.Add([pscustomobject][ordered]@{
            SubscriptionName = $Row.SubscriptionName
            SubscriptionId   = $Row.SubscriptionId
            DisplayName      = $Row.DisplayName
            SignInName       = $Row.SignInName
            ObjectType       = $Row.ObjectType
            ObjectId         = $ObjectId
            Scope            = $Row.Scope
            SourceRole       = $SourceRoleName
            TargetRole       = $TargetRoleName
            Status           = $Status
            Detail           = $Detail
            Timestamp        = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        })
    }

    function Test-RoleAssignableAtScope
    {
        param (
            [Parameter(Mandatory = $true)]$RoleDefinition,
            [Parameter(Mandatory = $true)][string]$Scope
        )

        foreach ($assignable in $RoleDefinition.AssignableScopes)
        {
            if ($assignable -eq '/' -or
                $Scope.Equals($assignable, [System.StringComparison]::OrdinalIgnoreCase) -or
                $Scope.StartsWith(($assignable.TrimEnd('/') + '/'), [System.StringComparison]::OrdinalIgnoreCase))
            {
                return $true
            }
        }
        return $false
    }

    function Write-UiSummary
    {
        $elapsed = $sw.Elapsed
        $cats = @(
            @{ Label = 'Replaced';  Count = $stats.Replaced;  Color = 'Green' },
            @{ Label = 'Assigned';  Count = $stats.Assigned;  Color = 'Cyan' },
            @{ Label = 'Simulated'; Count = $stats.Simulated; Color = 'Yellow' },
            @{ Label = 'Skipped';   Count = $stats.Skipped;   Color = 'DarkGray' },
            @{ Label = 'Failed';    Count = $stats.Failed;    Color = 'Red' }
        )
        $total = 0
        foreach ($c in $cats) { $total += $c.Count }

        Write-Host ''
        Write-UiBoxEdge -Position Top
        Write-UiBoxLine -Text (Format-UiSplit 'RUN SUMMARY' ($(if ($isSim) { 'SIMULATION' } else { 'LIVE' }))) -Fore White
        Write-UiBoxEdge -Position Mid
        foreach ($c in $cats)
        {
            $fore = $c.Color
            if ($c.Count -eq 0) { $fore = 'DarkGray' }
            Write-UiBoxLine -Text (Format-UiSplit ("  {0} {1}" -f $ch.Dot, $c.Label) ([string]$c.Count)) -Fore $fore
        }
        Write-UiBoxLine -Text (Format-UiSplit '  Rows processed' ([string]$total)) -Fore White
        Write-UiBoxLine -Text (Format-UiSplit '  Duration' ('{0:00}:{1:00}' -f [int][Math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds)) -Fore White
        Write-UiBoxEdge -Position Mid

        # Proportional colour bar
        Write-Host $ch.DV -ForegroundColor Cyan -NoNewline
        Write-Host ' ' -NoNewline
        $used = 0
        if ($total -gt 0)
        {
            foreach ($c in $cats)
            {
                $len = [int][Math]::Floor(($c.Count / $total) * $uiInner)
                if ($len -gt 0)
                {
                    Write-Host ($ch.Full * $len) -ForegroundColor $c.Color -NoNewline
                    $used += $len
                }
            }
        }
        if ($used -lt $uiInner)
        {
            Write-Host ($ch.Lite * ($uiInner - $used)) -ForegroundColor DarkGray -NoNewline
        }
        Write-Host ' ' -NoNewline
        Write-Host $ch.DV -ForegroundColor Cyan
        Write-UiBoxEdge -Position Bottom

        Write-Host ''
        Write-Host ('  {0} Log      : ' -f $ch.Arrow) -ForegroundColor DarkCyan -NoNewline
        Write-Host $logFile -ForegroundColor Gray
        if (Test-Path -LiteralPath $resultFile)
        {
            Write-Host ('  {0} Results  : ' -f $ch.Arrow) -ForegroundColor DarkCyan -NoNewline
            Write-Host $resultFile -ForegroundColor Gray
        }
        if (Test-Path -LiteralPath $rollbackFile)
        {
            Write-Host ('  {0} Rollback : ' -f $ch.Arrow) -ForegroundColor DarkCyan -NoNewline
            Write-Host $rollbackFile -ForegroundColor Gray
        }
        Write-Host ''
        if ($isSim)
        {
            Write-Host '  Simulation only - no role assignments were changed. Re-run without -WhatIf to apply.' -ForegroundColor Yellow
        }
        elseif ($stats.Failed -gt 0)
        {
            Write-Host '  Completed with failures - review the log and results CSV.' -ForegroundColor Red
        }
        else
        {
            Write-Host '  Completed successfully.' -ForegroundColor Green
        }
        Write-Host ''
    }

    # ------------------------------------------------------------------
    # Log run header (log file only)
    # ------------------------------------------------------------------
    Write-LogOnly -Text ('Started   : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Write-LogOnly -Text ('Run by    : {0}\{1} on {2}' -f $env:USERDOMAIN, $env:USERNAME, $env:COMPUTERNAME)
    Write-LogOnly -Text ('CSV       : {0}' -f $CsvPath)
    Write-LogOnly -Text ('Options   : WhatIf={0} | KeepSourceRole={1} | Force={2}' -f $isSim, $KeepSourceRole.IsPresent, $Force.IsPresent)
    Write-LogOnly -Text ''

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------
    Write-Host ''
    Write-UiBoxEdge -Position Top
    Write-UiBoxLine -Text (Format-UiSplit 'AZURE RBAC ROLE REPLACEMENT' "v$version") -Fore White
    Write-UiBoxLine -Text ("{0}  {1}  {2}" -f $SourceRoleName, $ch.Arrow, $TargetRoleName) -Fore Cyan
    Write-UiBoxEdge -Position Mid
    if ($isSim)
    {
        Write-UiBoxLine -Text 'MODE : SIMULATION (-WhatIf) - no changes will be made' -Fore Yellow
    }
    else
    {
        $liveText = 'MODE : LIVE - role assignments will be changed'
        if ($KeepSourceRole) { $liveText += ' (source role kept)' }
        Write-UiBoxLine -Text $liveText -Fore Red
    }
    Write-UiBoxEdge -Position Bottom

    # ------------------------------------------------------------------
    # Main
    # ------------------------------------------------------------------
    $originalContext = $null
    $currentSubId    = $null
    $stats           = @{ Replaced = 0; Assigned = 0; Simulated = 0; Skipped = 0; Failed = 0 }

    try
    {
        Write-RbacLog -Message "=== Role replacement started | '$SourceRoleName' -> '$TargetRoleName' ==="
        Write-RbacLog -Message "CSV: $CsvPath | LogPath: $LogPath | KeepSourceRole: $($KeepSourceRole.IsPresent) | WhatIf: $isSim"

        Write-UiSection -Title 'Pre-flight checks'

        # --- Check specific cmdlets (not just umbrella modules) ---
        $requiredCmdlets = @(
            'Connect-AzAccount', 'Get-AzContext', 'Set-AzContext',
            'Get-AzRoleAssignment', 'New-AzRoleAssignment',
            'Remove-AzRoleAssignment', 'Get-AzRoleDefinition'
        )
        $missing = @($requiredCmdlets | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) })
        if ($missing.Count -gt 0)
        {
            throw "Missing required cmdlets: $($missing -join ', '). Install/Import the Az.Accounts and Az.Resources modules."
        }
        Write-RbacLog -Message "Az cmdlets verified ($($requiredCmdlets.Count))" -Level SUCCESS -Console

        # --- Authentication: re-use existing context or prompt ---
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        $needConnect = $false
        if (-not $ctx -or -not $ctx.Account)
        {
            Write-RbacLog -Message 'No existing Azure connection found - opening sign-in...' -Level INFO -Console
            $needConnect = $true
        }
        elseif ($TenantId -and $ctx.Tenant.Id -ne $TenantId)
        {
            Write-RbacLog -Message "Existing context is in tenant $($ctx.Tenant.Id); required tenant is $TenantId - reconnecting..." -Level WARN -Console
            $needConnect = $true
        }

        if ($needConnect)
        {
            $connectParams = @{ ErrorAction = 'Stop' }
            if ($TenantId)
            {
                $connectParams['Tenant'] = $TenantId
            }
            $ctx = & {
                $WhatIfPreference = $false
                Connect-AzAccount @connectParams | Out-Null
                Get-AzContext
            }
        }
        if (-not $ctx -or -not $ctx.Account)
        {
            throw 'Azure authentication failed or was cancelled.'
        }
        $originalContext = $ctx
        Write-RbacLog -Message "Signed in as $($ctx.Account.Id) | Tenant $($ctx.Tenant.Id)" -Level SUCCESS -Console

        # --- Import & validate CSV ---
        $csvData = @(Import-Csv -LiteralPath $CsvPath -ErrorAction Stop)
        if ($csvData.Count -eq 0)
        {
            throw 'The CSV file is empty.'
        }
        $requiredColumns = @('SubscriptionName', 'SubscriptionId', 'TenantId', 'DisplayName', 'SignInName',
                             'ObjectType', 'RoleDefinitionName', 'ResourceType', 'Scope')
        $csvColumns  = $csvData[0].PSObject.Properties.Name
        $missingCols = @($requiredColumns | Where-Object { $csvColumns -notcontains $_ })
        if ($missingCols.Count -gt 0)
        {
            throw "CSV is missing required column(s): $($missingCols -join ', ')"
        }

        $sourceRows = @(
            $csvData |
                ForEach-Object {
                    foreach ($p in $_.PSObject.Properties)
                    {
                        if ($null -ne $p.Value)
                        {
                            $p.Value = ([string]$p.Value).Trim()
                        }
                    }
                    $_
                } |
                Where-Object { $_.RoleDefinitionName -eq $SourceRoleName -and $_.Scope } |
                Sort-Object -Property SubscriptionId, Scope, ObjectType, DisplayName, SignInName -Unique
        )

        if ($sourceRows.Count -eq 0)
        {
            Write-RbacLog -Message "CSV has $($csvData.Count) row(s) but none for role '$SourceRoleName'. Nothing to do." -Level WARN -Console
            return
        }

        $scopeGroups = @($sourceRows | Group-Object -Property SubscriptionId, Scope)
        Write-RbacLog -Message ("CSV validated: {0} row(s), {1} for '{2}' across {3} scope(s)" -f `
            $csvData.Count, $sourceRows.Count, $SourceRoleName, $scopeGroups.Count) -Level SUCCESS -Console

        # --- Process per scope (one live query per scope) ---
        Write-UiSection -Title 'Processing'

        $roleDefCache = @{}
        $groupIndex   = 0
        $rowCounter   = 0
        $totalRows    = $sourceRows.Count

        foreach ($group in $scopeGroups)
        {
            $groupIndex++
            $rows  = @($group.Group)
            $scope = $rows[0].Scope
            $subId = $rows[0].SubscriptionId

            Write-Host ''
            Write-Host ('  {0}{1} SCOPE {2}/{3}  ' -f $ch.TL, $ch.H, $groupIndex, $scopeGroups.Count) -ForegroundColor DarkCyan -NoNewline
            Write-Host (Get-ScopeLabel -Scope $scope) -ForegroundColor White
            Write-Host ('  {0}   {1} ({2})' -f $ch.V, $rows[0].SubscriptionName, $subId) -ForegroundColor DarkGray
            Write-RbacLog -Message "Scope: $scope | Subscription: $($rows[0].SubscriptionName) ($subId) | Rows: $($rows.Count)"

            try
            {
                if ($currentSubId -ne $subId)
                {
                    $setParams = @{ SubscriptionId = $subId; ErrorAction = 'Stop' }
                    if ($rows[0].TenantId)
                    {
                        $setParams['Tenant'] = $rows[0].TenantId
                    }
                    & {
                        $WhatIfPreference = $false
                        Set-AzContext @setParams | Out-Null
                    }
                    $currentSubId = $subId
                    Write-Verbose "Context switched to subscription $subId"
                }

                if (-not $roleDefCache.ContainsKey($subId))
                {
                    $roleDefCache[$subId] = Get-AzRoleDefinition -Name $TargetRoleName -ErrorAction Stop -WarningAction SilentlyContinue
                }
                $targetRoleDef = $roleDefCache[$subId]
                if (-not $targetRoleDef)
                {
                    throw "Target role '$TargetRoleName' was not found in subscription $subId."
                }
                if (-not (Test-RoleAssignableAtScope -RoleDefinition $targetRoleDef -Scope $scope))
                {
                    Write-RbacLog -Message "Assignability of '$TargetRoleName' at this scope could not be confirmed from its AssignableScopes; will attempt anyway." -Level WARN -Console
                }

                $liveSource = @(
                    Get-AzRoleAssignment -Scope $scope -RoleDefinitionName $SourceRoleName -ErrorAction Stop |
                        Where-Object { $_.Scope -eq $scope }
                )
                Write-Verbose "Live '$SourceRoleName' assignments at exact scope: $($liveSource.Count)"
            }
            catch
            {
                $msg = $_.Exception.Message
                Write-RbacLog -Message "Scope-level failure: $msg" -Level ERROR -Console
                foreach ($r in $rows)
                {
                    $rowCounter++
                    Add-RbacResult -Row $r -Status 'Failed' -Detail "Scope preparation failed: $msg"
                    $stats.Failed++
                }
                continue
            }

            foreach ($row in $rows)
            {
                $rowCounter++
                $who = "$($row.DisplayName) [$($row.ObjectType)]"

                Write-Progress -Activity 'Replacing RBAC roles' `
                               -Status "Row $rowCounter of $totalRows : $($row.DisplayName)" `
                               -PercentComplete ([int](($rowCounter / $totalRows) * 100))
                try
                {
                    if ([string]::IsNullOrWhiteSpace($row.DisplayName) -or $row.ObjectType -eq 'Unknown')
                    {
                        Write-RbacLog -Message "$who - orphaned/unknown identity cannot be matched. Skipped." -Level SKIP
                        Write-UiRow -Index $rowCounter -Total $totalRows -Kind SKIP -Name "$($row.DisplayName)" -Type $row.ObjectType -Detail 'Orphaned/unknown identity - cannot be matched'
                        Add-RbacResult -Row $row -Status 'SkippedUnmatchable' -Detail 'Blank DisplayName or ObjectType Unknown'
                        $stats.Skipped++
                        continue
                    }

                    $found = @(
                        $liveSource | Where-Object {
                            $_.ObjectType -eq $row.ObjectType -and
                            $_.DisplayName -eq $row.DisplayName -and
                            ([string]::IsNullOrWhiteSpace($row.SignInName) -or $_.SignInName -eq $row.SignInName)
                        }
                    )

                    if ($found.Count -eq 0)
                    {
                        Write-RbacLog -Message "$who - source assignment not found at scope (already replaced/removed?). Skipped." -Level SKIP
                        Write-UiRow -Index $rowCounter -Total $totalRows -Kind SKIP -Name $row.DisplayName -Type $row.ObjectType -Detail 'Source role not found at this scope (already replaced?)'
                        Add-RbacResult -Row $row -Status 'SkippedNotFound' -Detail 'Source role assignment not present at scope'
                        $stats.Skipped++
                        continue
                    }
                    if ($found.Count -gt 1)
                    {
                        Write-RbacLog -Message "$who - $($found.Count) live assignments match (ambiguous). Skipped." -Level WARN
                        Write-UiRow -Index $rowCounter -Total $totalRows -Kind WARN -Name $row.DisplayName -Type $row.ObjectType -Detail "$($found.Count) live assignments match - ambiguous, skipped"
                        Add-RbacResult -Row $row -Status 'SkippedAmbiguous' -Detail "$($found.Count) matching live assignments"
                        $stats.Skipped++
                        continue
                    }

                    $src = $found[0]

                    # Read-only check so the simulation is accurate
                    $existingTarget = @(
                        Get-AzRoleAssignment -ObjectId $src.ObjectId -Scope $scope -RoleDefinitionName $TargetRoleName -ErrorAction Stop |
                            Where-Object { $_.Scope -eq $scope }
                    )
                    $targetExists = ($existingTarget.Count -gt 0)

                    if ($targetExists -and $KeepSourceRole)
                    {
                        Write-RbacLog -Message "$who - target role already assigned; nothing to do (-KeepSourceRole)." -Level SKIP
                        Write-UiRow -Index $rowCounter -Total $totalRows -Kind SKIP -Name $row.DisplayName -Type $row.ObjectType -Detail 'Target role already assigned - nothing to do'
                        Add-RbacResult -Row $row -Status 'SkippedAlreadyAssigned' -Detail 'Target already assigned; source kept' -ObjectId $src.ObjectId
                        $stats.Skipped++
                        continue
                    }

                    if ($targetExists)
                    {
                        $plan = "Target already assigned; would remove '$SourceRoleName' only"
                    }
                    elseif ($KeepSourceRole)
                    {
                        $plan = "Would assign '$TargetRoleName' (source role kept)"
                    }
                    else
                    {
                        $plan = "Would assign '$TargetRoleName' and remove '$SourceRoleName'"
                    }

                    # Simulation: no ShouldProcess noise, just the plan
                    if ($isSim)
                    {
                        Write-RbacLog -Message "$who - $plan (simulation, no change made)" -Level WHATIF
                        Write-UiRow -Index $rowCounter -Total $totalRows -Kind WHATIF -Name $row.DisplayName -Type $row.ObjectType -Detail $plan
                        Add-RbacResult -Row $row -Status 'Simulated' -Detail $plan -ObjectId $src.ObjectId
                        $stats.Simulated++
                        continue
                    }

                    $action = $plan -replace '^Would ', ''
                    $action = $action.Substring(0, 1).ToUpper() + $action.Substring(1)
                    if (-not $PSCmdlet.ShouldProcess("$who at $scope", $action))
                    {
                        Write-RbacLog -Message "$who - declined at confirmation prompt. Skipped." -Level SKIP
                        Write-UiRow -Index $rowCounter -Total $totalRows -Kind SKIP -Name $row.DisplayName -Type $row.ObjectType -Detail 'Declined at confirmation prompt'
                        Add-RbacResult -Row $row -Status 'SkippedByUser' -Detail 'Confirmation declined' -ObjectId $src.ObjectId
                        $stats.Skipped++
                        continue
                    }

                    # Step 1: assign target role (idempotent)
                    if ($targetExists)
                    {
                        Write-RbacLog -Message "$who - target role already assigned at scope."
                    }
                    else
                    {
                        New-AzRoleAssignment -ObjectId $src.ObjectId -RoleDefinitionId $targetRoleDef.Id -Scope $scope -ErrorAction Stop | Out-Null
                        Write-RbacLog -Message "$who - assigned '$TargetRoleName'." -Level SUCCESS
                    }

                    # Step 2: verify target before touching the source
                    $verify = @(
                        Get-AzRoleAssignment -ObjectId $src.ObjectId -Scope $scope -RoleDefinitionName $TargetRoleName -ErrorAction Stop |
                            Where-Object { $_.Scope -eq $scope }
                    )
                    if ($verify.Count -eq 0)
                    {
                        throw 'Target role assignment could not be confirmed after creation; source role NOT removed.'
                    }

                    if ($KeepSourceRole)
                    {
                        Write-UiRow -Index $rowCounter -Total $totalRows -Kind ASSIGNED -Name $row.DisplayName -Type $row.ObjectType -Detail "Assigned '$TargetRoleName' (source role kept)"
                        Add-RbacResult -Row $row -Status 'Assigned' -Detail 'Target assigned; source retained (-KeepSourceRole)' -ObjectId $src.ObjectId
                        $stats.Assigned++
                        continue
                    }

                    # Step 3: save rollback info, then remove source role
                    [pscustomobject][ordered]@{
                        SubscriptionId     = $subId
                        Scope              = $scope
                        ObjectId           = $src.ObjectId
                        DisplayName        = $src.DisplayName
                        SignInName         = $src.SignInName
                        ObjectType         = $src.ObjectType
                        RoleDefinitionName = $src.RoleDefinitionName
                        RoleDefinitionId   = $src.RoleDefinitionId
                        RoleAssignmentId   = $src.RoleAssignmentId
                    } | Export-Csv -LiteralPath $rollbackFile -Append -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop

                    Remove-AzRoleAssignment -ObjectId $src.ObjectId -RoleDefinitionName $SourceRoleName -Scope $scope -ErrorAction Stop | Out-Null
                    Write-RbacLog -Message "$who - removed '$SourceRoleName'." -Level SUCCESS
                    Write-UiRow -Index $rowCounter -Total $totalRows -Kind REPLACED -Name $row.DisplayName -Type $row.ObjectType -Detail "Assigned '$TargetRoleName', removed '$SourceRoleName'"
                    Add-RbacResult -Row $row -Status 'Replaced' -Detail 'Target assigned and source removed' -ObjectId $src.ObjectId
                    $stats.Replaced++
                }
                catch
                {
                    $msg = $_.Exception.Message
                    Write-RbacLog -Message "$who - FAILED: $msg" -Level ERROR
                    Write-UiRow -Index $rowCounter -Total $totalRows -Kind FAILED -Name $row.DisplayName -Type $row.ObjectType -Detail $msg
                    Add-RbacResult -Row $row -Status 'Failed' -Detail $msg
                    $stats.Failed++
                }
            }
        }

        Write-Progress -Activity 'Replacing RBAC roles' -Completed
        Write-RbacLog -Message ("=== Completed | Replaced: {0} | Assigned-only: {1} | Simulated: {2} | Skipped: {3} | Failed: {4} ===" -f `
            $stats.Replaced, $stats.Assigned, $stats.Simulated, $stats.Skipped, $stats.Failed)
    }
    catch
    {
        Write-Progress -Activity 'Replacing RBAC roles' -Completed
        Write-RbacLog -Message "Terminating error: $($_.Exception.Message)" -Level ERROR -Console
        throw
    }
    finally
    {
        $sw.Stop()

        if ($results.Count -gt 0)
        {
            try
            {
                $results | Export-Csv -LiteralPath $resultFile -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop
            }
            catch
            {
                Write-Warning "Could not export results CSV: $($_.Exception.Message)"
            }
        }

        if ($originalContext -and $originalContext.Subscription -and $currentSubId -and
            $currentSubId -ne $originalContext.Subscription.Id)
        {
            try
            {
                & {
                    $WhatIfPreference = $false
                    Set-AzContext -SubscriptionId $originalContext.Subscription.Id -Tenant $originalContext.Tenant.Id -ErrorAction Stop | Out-Null
                }
            }
            catch
            {
                Write-Warning "Could not restore original Az context: $($_.Exception.Message)"
            }
        }

        Write-UiSummary
        Write-LogOnly -Text ('Ended     : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    }

    if ($PassThru)
    {
        $results
    }
}
