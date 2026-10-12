<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 12 October 2026
Modified-On  : 12 October 2026

.SYNOPSIS
    Backs up and removes a diagnostic setting (exact name match only) from Azure resources of any type that supports 
    diagnostic settings, for example Function Apps, Logic Apps, App Services and Storage Accounts.

.DESCRIPTION
    Built to clean up POC diagnostic settings (for example "Profile_1") that were pushed to a Log Analytics
    Workspace by an Azure Policy (DeployIfNotExists), before moving to production.

    For every target subscription the function:
      1. Discovers resources of the requested ARM resource type(s) (for example Microsoft.Web/sites,
         Microsoft.Logic/workflows, Microsoft.Storage/storageAccounts). Optionally narrowed by resource kind
         (-ResourceKind), expanded to child scopes (-ChildScope), and filtered by resource group and/or an exact
         list of resource names.
      2. Reads the diagnostic settings on each resource and matches the setting name using an exact,
         case-sensitive comparison (no wildcards, no partial match). Every other diagnostic setting on the
         resource is left untouched. A setting that differs only by letter case is reported and skipped.
      3. Saves the raw ARM JSON of the matched setting to a backup file (unless -SkipBackup is used).
         If the backup fails, the delete is skipped for that resource.
      4. Deletes the matched setting with Remove-AzDiagnosticSetting and re-reads the resource to verify.
      5. Writes a plain-language, timestamped log file and a CSV report with one row per resource, and 
         shows a step-by-step summary on screen.

    Supports -WhatIf / -DryRun (no backup, no delete), -Confirm and -Force. The function is idempotent:
    re-running it when the setting is already gone reports 'NotFound-NothingToDo' and changes nothing.

    IMPORTANT: Remove the Azure Policy assignment (and any open remediation tasks) BEFORE running a live
    delete, otherwise the policy can recreate the diagnostic setting. This function does not remove policy.

.PARAMETER SubscriptionId
    One or more subscription IDs (GUIDs). Single or multiple. Mandatory unless -AllSubscriptions is used.

.PARAMETER DiagnosticSettingName
    Exact name of the diagnostic setting to remove. Default 'Profile_1'. Wildcard and path characters are rejected.

.PARAMETER ResourceName
    Optional array of exact resource names to restrict the run to (for example your list of 49 POC resources).
    If omitted, every resource of the selected type(s) in scope is checked.

.PARAMETER ResourceNameListPath
    Optional path to a text file with one resource name per line (blank lines and lines starting with # are ignored).
    Combined with -ResourceName if both are supplied.

.PARAMETER ResourceGroupName
    Optional resource group name(s) to restrict discovery to.

.PARAMETER ResourceType
    One or more Azure Resource Manager resource types to process, for example 'Microsoft.Web/sites',
    'Microsoft.Logic/workflows' or 'Microsoft.Storage/storageAccounts'.
    Default: 'Microsoft.Web/sites' and 'Microsoft.Logic/workflows'.

.PARAMETER ResourceKind
    Optional. Narrows the discovered resources by their 'kind' value, using -like matching (wildcards allowed).
    Needed because Function Apps, Logic Apps Standard and App Services share Microsoft.Web/sites.
    Examples: 'functionapp*' (Function Apps and Logic Apps Standard), '*workflowapp*' (Logic Apps Standard only).

.PARAMETER ChildScope
    Optional. One or more child resource paths to check in addition to the resource itself, for example
    '/blobServices/default' or '/fileServices/default' for Storage Accounts, where diagnostic settings are
    held on the sub-services.

.PARAMETER AuthenticationMethod
    ExistingContext (default, uses your current Connect-AzAccount session), Interactive, DeviceCode,
    ManagedIdentity, ServicePrincipalCertificate or ServicePrincipalSecret.

.PARAMETER TenantId
    Tenant ID (GUID). Required for the two ServicePrincipal methods, optional otherwise.

.PARAMETER ApplicationId
    Application (client) ID. Required for ServicePrincipalCertificate.

.PARAMETER CertificateThumbprint
    40-character certificate thumbprint. Required for ServicePrincipalCertificate.

.PARAMETER Credential
    PSCredential (UserName = application ID, Password = client secret). Required for ServicePrincipalSecret.
    Prefer certificate or managed identity where possible.

.PARAMETER OutputPath
    Folder for the log, CSV report and backups. Default: .\DiagSettingCleanup_<timestamp> under the current location.

.PARAMETER AllSubscriptions
    Process every enabled subscription visible to the signed-in identity (optionally limited by -TenantId).

.PARAMETER SkipBackup
    Do not back up the setting before deleting it. Not recommended.

.PARAMETER DryRun
    Same effect as -WhatIf: shows what would be deleted, writes the log and CSV, but makes no backup and no change.

.PARAMETER Force
    Suppresses the per-resource confirmation prompt on a live run (ConfirmImpact is High).

.PARAMETER PassThru
    Returns the per-resource result objects to the pipeline.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None by default. With -PassThru: PSCustomObject per resource (Status, Message, BackupPath, WorkspaceId, etc.).
    Status values: DryRun-WouldDelete, Deleted, Deleted-VerifyUnconfirmed, NotFound-NothingToDo,
    Skipped-NameCaseMismatch, Skipped-Declined, Skipped-BackupFailed, Failed-Delete, Failed-StillPresent,
    Error-ReadSettings, Error-Discovery, ResourceNotFound.

.EXAMPLE
    Remove-AppDiagnosticSetting -SubscriptionId '11111111-1111-1111-1111-111111111111' -DryRun

    Dry run on one subscription using the current Az session. Lists every resource that has a 'Profile_1'
    setting. Nothing is backed up or deleted.

.EXAMPLE
    $names = Get-Content .\poc-resources.txt
    Remove-AppDiagnosticSetting -SubscriptionId $subA, $subB -ResourceName $names -WhatIf

    Dry run across two subscriptions, limited to the exact resource names in the list. Names that are not found
    are reported as 'ResourceNotFound' so you can reconcile against your list.

.EXAMPLE
    Remove-AppDiagnosticSetting -SubscriptionId $subA, $subB -ResourceNameListPath .\poc-resources.txt -Force

    Live run: backs up and deletes 'Profile_1' on the listed resources without prompting for each one.

.EXAMPLE
    Remove-AppDiagnosticSetting -AllSubscriptions -AuthenticationMethod ServicePrincipalCertificate `
        -TenantId $tenant -ApplicationId $appId -CertificateThumbprint $thumb `
        -ResourceType 'Microsoft.Web/sites' -ResourceKind 'functionapp*' -DryRun -PassThru

    Authenticates with a service principal certificate and dry-runs against Function Apps in all enabled subscriptions.

.EXAMPLE
    Remove-AppDiagnosticSetting -SubscriptionId $subA -ResourceType 'Microsoft.Storage/storageAccounts' `
        -ChildScope '/blobServices/default', '/fileServices/default' -DryRun

    Dry run against Storage Accounts, checking the blob and file services.

.EXAMPLE
    Remove-AppDiagnosticSetting -SubscriptionId $subA -ResourceType 'Microsoft.Network/applicationGateways' -WhatIf

    Dry run against any other resource type by passing its ARM type.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (12-Oct-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. PowerShell 5.1 or later with Az.Accounts, Az.Resources and Az.Monitor modules
    (cmdlets used: Connect-AzAccount, Set-AzContext, Get-AzSubscription, Invoke-AzRestMethod,
    Get-AzResource, Get-AzDiagnosticSetting, Remove-AzDiagnosticSetting).
    2. Reader on the target resources to discover and read settings, plus permission to delete diagnostic
    settings (Monitoring Contributor or Contributor on the resources / scope).
    3. Azure Policy assignment and remediation tasks for the POC removed before a live run.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Deployment slots (Microsoft.Web/sites/slots) are not discovered.
    - Only resource-level diagnostic settings are handled (not subscription Activity Log settings).
    - Resource types that do not support diagnostic settings are reported as 'Error-ReadSettings'.
    - -ResourceKind relies on the resource 'kind' value; a resource with an empty kind only matches when -ResourceKind is not used.
    - -ChildScope paths are applied to every discovered resource; scopes that do not exist on a resource are reported for that resource.
    - Remove-AzDiagnosticSetting ignores -DefaultProfile in current Az.Monitor, so the function switches the
        Az context per subscription with Set-AzContext. The context left active afterwards is the last subscription processed.
    - The backup is the raw ARM JSON of the setting. A restore by PUT to the same path is expected to work
        but has not been confirmed in this release; test on one resource first.
    - The function does not check whether the policy assignment still exists.
    - Resources are processed sequentially.
    - All PowerShell/Az warnings are suppressed on screen ($WarningPreference). 
        Problems are reported through the function's own colour-coded messages and the log file instead.

.LINK
    https://learn.microsoft.com/powershell/module/az.monitor/remove-azdiagnosticsetting

.LINK
    https://learn.microsoft.com/powershell/module/az.monitor/get-azdiagnosticsetting

.LINK
    https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings

.LINK
    https://learn.microsoft.com/rest/api/monitor/diagnostic-settings

.LINK
    https://learn.microsoft.com/azure/azure-resource-manager/management/azure-services-resource-providers

#>


Function Remove-AppDiagnosticSetting
{
    [CmdletBinding(DefaultParameterSetName = 'Subscription', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Subscription', Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string[]]$SubscriptionId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[\w\.\- ]+$')]
        [string]$DiagnosticSettingName = 'Profile_1',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[\w\.\-\(\)]+$')]
        [string[]]$ResourceName,

        [Parameter()]
        [ValidateScript({
            if ($_ -match '(^|[\\/])\.\.([\\/]|$)')
            {
                throw 'Path traversal sequences (..) are not allowed.'
            }
            if (-not (Test-Path -LiteralPath $_ -PathType Leaf))
            {
                throw "File not found: $_"
            }
            $true
        })]
        [string]$ResourceNameListPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[\w\.\-\(\)]+$')]
        [string[]]$ResourceGroupName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Za-z0-9\.\-]+(/[A-Za-z0-9\.\-]+)+$')]
        [string[]]$ResourceType = @('Microsoft.Web/sites', 'Microsoft.Logic/workflows'),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[\w\.\*,\-]+$')]
        [string[]]$ResourceKind,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^/[A-Za-z0-9\.\-]+(/[A-Za-z0-9\.\-]+)*$')]
        [string[]]$ChildScope,

        [Parameter()]
        [ValidateSet('ExistingContext', 'Interactive', 'DeviceCode', 'ManagedIdentity', 'ServicePrincipalCertificate', 'ServicePrincipalSecret')]
        [string]$AuthenticationMethod = 'ExistingContext',

        [Parameter()]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$TenantId,

        [Parameter()]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$ApplicationId,

        [Parameter()]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$CertificateThumbprint,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateScript({
            if ($_ -match '(^|[\\/])\.\.([\\/]|$)')
            {
                throw 'Path traversal sequences (..) are not allowed.'
            }
            $true
        })]
        [string]$OutputPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'AllSubscriptions')]
        [switch]$AllSubscriptions,

        [switch]$SkipBackup,

        [switch]$DryRun,

        [switch]$Force,

        [switch]$PassThru
    )

    # ------------------------------------------------------------------
    # Run mode
    # ------------------------------------------------------------------
    if ($DryRun)
    {
        $WhatIfPreference = $true
    }
    $isDryRun = [bool]$WhatIfPreference
    if ($Force -and -not $isDryRun)
    {
        $ConfirmPreference = 'None'
    }

    # Hide every PowerShell / Az warning on screen. Problems are still reported clearly through Write-Log (screen + log file).
    $WarningPreference = 'SilentlyContinue'

    # ------------------------------------------------------------------
    # Output folder + logging (.NET calls so -WhatIf does not suppress the log/report)
    # ------------------------------------------------------------------
    $runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    if ([string]::IsNullOrWhiteSpace($OutputPath))
    {
        $OutputPath = Join-Path -Path $PWD.Path -ChildPath ('DiagSettingCleanup_' + $runStamp)
    }
    $OutputPath   = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $backupFolder = Join-Path -Path $OutputPath -ChildPath 'Backup'
    $logFile      = Join-Path -Path $OutputPath -ChildPath ('DiagSettingCleanup_' + $runStamp + '.log')
    $csvFile      = Join-Path -Path $OutputPath -ChildPath ('DiagSettingCleanup_' + $runStamp + '.csv')

    try
    {
        [void][System.IO.Directory]::CreateDirectory($OutputPath)
    }
    catch
    {
        throw "Unable to create output folder '$OutputPath': $($_.Exception.Message)"
    }

    function Write-Log
    {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Message,

            [ValidateSet('INFO', 'WARN', 'ERROR', 'DRYRUN', 'OK')]
            [string]$Level = 'INFO',

            [int]$Indent = 0,

            [switch]$LogOnly
        )

        $line = '{0} [{1,-6}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
        try
        {
            [System.IO.File]::AppendAllText($logFile, $line + [Environment]::NewLine)
        }
        catch
        {
            Write-Host "Could not write to the log file: $($_.Exception.Message)" -ForegroundColor Red
        }
        Write-Verbose $line

        if (-not $LogOnly)
        {
            $colourMap = @{ INFO = 'Gray'; OK = 'Green'; WARN = 'Yellow'; ERROR = 'Red'; DRYRUN = 'Cyan' }
            $tagMap    = @{ INFO = '[INFO]      '; OK = '[OK]        '; WARN = '[ATTENTION]'; ERROR = '[PROBLEM]  '; DRYRUN = '[DRY RUN]  ' }
            Write-Host ((' ' * $Indent) + $tagMap[$Level] + ' ' + $Message) -ForegroundColor $colourMap[$Level]
        }
    }

    function Write-Section
    {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Title
        )

        $bar = '=' * 78
        Write-Host ''
        Write-Host $bar -ForegroundColor Cyan
        Write-Host (' ' + $Title) -ForegroundColor Cyan
        Write-Host $bar -ForegroundColor Cyan
        Write-Log -Message ('----- ' + $Title + ' -----') -LogOnly
    }

    function New-ResultRow
    {
        param (
            $Sub,
            $Res,
            [string]$Status,
            [string]$Message,
            [string]$BackupPath = '',
            [string]$WorkspaceId = '',
            [string[]]$OtherNames = @()
        )

        [pscustomobject][ordered]@{
            Timestamp         = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            SubscriptionId    = $Sub.Id
            SubscriptionName  = $Sub.Name
            ResourceGroup     = $Res.ResourceGroupName
            ResourceName      = $Res.Name
            ResourceType      = $Res.TypeLabel
            SettingName       = $DiagnosticSettingName
            Status            = $Status
            Message           = $Message
            BackupPath        = $BackupPath
            WorkspaceId       = $WorkspaceId
            OtherSettingNames = ($OtherNames -join '; ')
            ResourceId        = $Res.ResourceId
        }
    }

    Write-Section -Title ('Remove-AppDiagnosticSetting v1.0  -  ' + $(if ($isDryRun) { 'DRY RUN (nothing will be changed)' } else { 'LIVE RUN (changes WILL be made)' }))
    Write-Log -Message ("Goal: find the diagnostic setting named '{0}' (spelling and capital letters must match exactly) on the selected Azure resources." -f $DiagnosticSettingName)
    if ($isDryRun)
    {
        Write-Log -Message 'Mode: DRY RUN (practice run). Nothing will be backed up, deleted or changed. You will only see what WOULD happen.' -Level 'DRYRUN'
    }
    else
    {
        Write-Log -Message 'Mode: LIVE RUN. Matching settings WILL be deleted from Azure.' -Level 'WARN'
        if ($SkipBackup)
        {
            Write-Log -Message 'Backups are switched OFF (-SkipBackup). Settings will be deleted without a saved copy.' -Level 'WARN'
        }
        else
        {
            Write-Log -Message 'A backup copy of each setting is saved before it is deleted.'
        }
    }
    Write-Log -Message 'Safety: any other diagnostic settings on the same resources are never touched.'
    Write-Log -Message "Logs and reports will be saved in: $OutputPath"

    Write-Section -Title 'STEP 1 of 5 - Checking the required Azure PowerShell tools'

    # ------------------------------------------------------------------
    # Pre-requisite cmdlet check
    # ------------------------------------------------------------------
    $requiredCmdlets = [ordered]@{
        'Connect-AzAccount'          = 'Az.Accounts'
        'Set-AzContext'              = 'Az.Accounts'
        'Get-AzSubscription'         = 'Az.Accounts'
        'Invoke-AzRestMethod'        = 'Az.Accounts'
        'Get-AzResource'             = 'Az.Resources'
        'Get-AzDiagnosticSetting'    = 'Az.Monitor'
        'Remove-AzDiagnosticSetting' = 'Az.Monitor'
    }
    $missingCmdlets = @()
    foreach ($cmdName in $requiredCmdlets.Keys)
    {
        if (-not (Get-Command -Name $cmdName -ErrorAction SilentlyContinue))
        {
            $missingCmdlets += ('{0} ({1})' -f $cmdName, $requiredCmdlets[$cmdName])
        }
    }
    if ($missingCmdlets.Count -gt 0)
    {
        $msg = 'Some required Azure PowerShell tools are missing: ' + ($missingCmdlets -join ', ') + '. Please install the missing Az module(s) (for example: Install-Module Az -Scope CurrentUser) and run this again.'
        Write-Log -Message $msg -Level 'ERROR'
        throw $msg
    }

    Write-Log -Message 'All required Azure PowerShell tools are installed.' -Level 'OK'
    Write-Log -Message ("Resource types that will be checked: {0}" -f (($ResourceType | Select-Object -Unique) -join ', '))
    if ($ResourceKind)
    {
        Write-Log -Message ("Only resources whose 'kind' matches: {0}" -f ($ResourceKind -join ', '))
    }
    if ($ChildScope)
    {
        Write-Log -Message ("Also checking these child parts of each resource: {0}" -f ($ChildScope -join ', '))
    }

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    Write-Section -Title 'STEP 2 of 5 - Signing in to Azure'
    Write-Log -Message ("Sign-in method: {0}" -f $AuthenticationMethod)

    try
    {
        switch ($AuthenticationMethod)
        {
            'ExistingContext'
            {
                if (-not (Get-AzContext -ErrorAction SilentlyContinue))
                {
                    throw 'No existing Az context. Run Connect-AzAccount first or choose another -AuthenticationMethod.'
                }
            }
            'Interactive'
            {
                $connectParams = @{}
                if ($TenantId)
                {
                    $connectParams['Tenant'] = $TenantId
                }
                Connect-AzAccount @connectParams -WhatIf:$false -ErrorAction Stop | Out-Null
            }
            'DeviceCode'
            {
                $connectParams = @{ UseDeviceAuthentication = $true }
                if ($TenantId)
                {
                    $connectParams['Tenant'] = $TenantId
                }
                Connect-AzAccount @connectParams -WhatIf:$false -ErrorAction Stop | Out-Null
            }
            'ManagedIdentity'
            {
                Connect-AzAccount -Identity -WhatIf:$false -ErrorAction Stop | Out-Null
            }
            'ServicePrincipalCertificate'
            {
                if (-not ($TenantId -and $ApplicationId -and $CertificateThumbprint))
                {
                    throw 'ServicePrincipalCertificate requires -TenantId, -ApplicationId and -CertificateThumbprint.'
                }
                Connect-AzAccount -ServicePrincipal -Tenant $TenantId -ApplicationId $ApplicationId -CertificateThumbprint $CertificateThumbprint -WhatIf:$false -ErrorAction Stop | Out-Null
            }
            'ServicePrincipalSecret'
            {
                if (-not ($TenantId -and $Credential))
                {
                    throw 'ServicePrincipalSecret requires -TenantId and -Credential.'
                }
                Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $Credential -WhatIf:$false -ErrorAction Stop | Out-Null
            }
        }

        $ctx = Get-AzContext -ErrorAction Stop
        Write-Log -Message "Signed in successfully as '$($ctx.Account.Id)' (tenant ID: $($ctx.Tenant.Id))." -Level 'OK'
    }
    catch
    {
        $errMsg = $_.Exception.Message
        Write-Log -Message "Sign-in failed, so the run was stopped. Reason: $errMsg. What to do: run Connect-AzAccount (or check the tenant / application details) and try again." -Level 'ERROR'
        throw "Authentication failed: $errMsg"
    }

    # ------------------------------------------------------------------
    # Resolve subscriptions
    # ------------------------------------------------------------------

    Write-Section -Title 'STEP 3 of 5 - Working out what to scan (subscriptions and filters)'

    $subs = @()
    try
    {
        if ($PSCmdlet.ParameterSetName -eq 'AllSubscriptions')
        {
            $subParams = @{}
            if ($TenantId)
            {
                $subParams['TenantId'] = $TenantId
            }
            $subs = @(Get-AzSubscription @subParams -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
        }
        else
        {
            foreach ($sid in ($SubscriptionId | Select-Object -Unique))
            {
                try
                {
                    $subs += Get-AzSubscription -SubscriptionId $sid -ErrorAction Stop
                }
                catch
                {
                    $errMsg = $_.Exception.Message
                    Write-Warning "Subscription $sid could not be read and will be skipped: $errMsg"
                    Write-Log -Message "Could not open subscription $sid, so it will be SKIPPED. Possible reasons: wrong ID, no access, or an extra sign-in (MFA) is needed. Technical detail: $errMsg" -Level 'ERROR'
                }
            }
        }
    }
    catch
    {
        $errMsg = $_.Exception.Message
        Write-Log -Message "Could not get the list of subscriptions. Technical detail: $errMsg" -Level 'ERROR'
        throw "Subscription lookup failed: $errMsg"
    }

    if ($subs.Count -eq 0)
    {
        Write-Log -Message 'None of the requested subscriptions could be opened, so there is nothing to process. Please check the subscription ID(s) and your access, then try again.' -Level 'ERROR'
        throw 'No usable subscriptions found.'
    }
    Write-Log -Message ("Found {0} subscription(s) to process:" -f $subs.Count) -Level 'OK'
    foreach ($s in $subs)
    {
        Write-Log -Message ("- {0}  [{1}]" -f $s.Name, $s.Id) -Indent 4
    }

    # ------------------------------------------------------------------
    # Build the optional resource-name filter
    # ------------------------------------------------------------------
    $nameBucket = New-Object 'System.Collections.Generic.List[string]'
    if ($ResourceName)
    {
        foreach ($n in $ResourceName)
        {
            $nameBucket.Add($n.Trim())
        }
    }
    if ($ResourceNameListPath)
    {
        foreach ($line in (Get-Content -LiteralPath $ResourceNameListPath -ErrorAction Stop))
        {
            $candidate = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($candidate) -or $candidate.StartsWith('#'))
            {
                continue
            }
            if ($candidate -notmatch '^[\w\.\-\(\)]+$')
            {
                Write-Warning "Ignoring invalid resource name in list file: '$candidate'"
                Write-Log -Message "Skipped an invalid resource name in the list file: '$candidate' (only letters, numbers and . - _ ( ) are allowed)." -Level 'WARN'
                continue
            }
            $nameBucket.Add($candidate)
        }
    }
    $targetNames  = @($nameBucket | Sort-Object -Unique)
    $filterByName = ($targetNames.Count -gt 0)
    if ($filterByName)
    {
        Write-Log -Message ("Only the {0} resource name(s) you supplied will be checked. All other resources are ignored." -f $targetNames.Count)
    }
    else
    {
        Write-Log -Message 'No resource-name list supplied, so ALL resources of the selected type(s) will be checked.'
    }

    if (-not $isDryRun)
    {
        Write-Warning 'LIVE RUN: make sure the Azure Policy assignment and remediation tasks for the POC are already removed, otherwise the setting can be recreated.'
        Write-Log -Message 'IMPORTANT REMINDER: the Azure Policy that created this setting (and any remediation task) must be removed BEFORE a live run. Otherwise Azure can automatically re-create the setting right after it is deleted.' -Level 'WARN'
    }

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    $results       = New-Object 'System.Collections.Generic.List[object]'
    $discovered    = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $rgScopes      = @('')
    if ($ResourceGroupName)
    {
        $rgScopes = $ResourceGroupName
    }
    $subIndex = 0

    Write-Section -Title 'STEP 4 of 5 - Scanning resources and handling the diagnostic setting'

    foreach ($sub in $subs)
    {
        $subIndex++
        Write-Host ''
        Write-Log -Message "Subscription $subIndex of $($subs.Count): $($sub.Name) [$($sub.Id)]"

        # Switch context (Remove-AzDiagnosticSetting does not honour -DefaultProfile)
        try
        {
            $ctxParams = @{ SubscriptionId = $sub.Id }
            if ($sub.TenantId)
            {
                $ctxParams['Tenant'] = $sub.TenantId
            }
            Set-AzContext @ctxParams -WhatIf:$false -ErrorAction Stop | Out-Null
            Write-Log -Message 'Switched to this subscription. Searching for the selected resource types...' -Indent 2
        }
        catch
        {
            $errMsg = $_.Exception.Message
            Write-Warning "Cannot switch to subscription $($sub.Name): $errMsg"
            Write-Log -Message "Could not switch to subscription '$($sub.Name)', so it is SKIPPED. Technical detail: $errMsg" -Level 'ERROR'
            $results.Add((New-ResultRow -Sub $sub -Res ([pscustomobject]@{ Name = '(subscription)'; ResourceGroupName = ''; TypeLabel = ''; ResourceId = '' }) -Status 'Error-Discovery' -Message "Context switch failed: $errMsg"))
            continue
        }

        # Discovery
        $resources = New-Object 'System.Collections.Generic.List[object]'
        foreach ($rg in $rgScopes)
        {
            $getParams = @{}
            if ($rg)
            {
                $getParams['ResourceGroupName'] = $rg
            }

            try
            {
                foreach ($armType in ($ResourceType | Select-Object -Unique))
                {
                    foreach ($item in @(Get-AzResource @getParams -ResourceType $armType -ErrorAction Stop))
                    {
                        $kind = [string]$item.Kind
                        if ($ResourceKind -and (@($ResourceKind | Where-Object { $kind -like $_ }).Count -eq 0))
                        {
                            continue
                        }

                        $resources.Add([pscustomobject]@{ Name = $item.Name; ResourceGroupName = $item.ResourceGroupName; TypeLabel = $armType; ResourceId = $item.ResourceId })

                        foreach ($child in $ChildScope)
                        {
                            $resources.Add([pscustomobject]@{ Name = $item.Name; ResourceGroupName = $item.ResourceGroupName; TypeLabel = ($armType + $child); ResourceId = ($item.ResourceId + $child) })
                        }
                    }
                }
            }
            catch
            {
                $errMsg = $_.Exception.Message
                $scopeText = $(if ($rg) { "resource group '$rg'" } else { 'subscription' })
                Write-Warning "Discovery failed in $scopeText of $($sub.Name): $errMsg"
                Write-Log -Message "Could not search the $scopeText of '$($sub.Name)' for resources, so that part was SKIPPED. Please check you have at least the Reader role there. Technical detail: $errMsg" -Level 'ERROR'
                $results.Add((New-ResultRow -Sub $sub -Res ([pscustomobject]@{ Name = '(discovery)'; ResourceGroupName = $rg; TypeLabel = ''; ResourceId = '' }) -Status 'Error-Discovery' -Message $errMsg))
            }
        }

        # Exact name filter (case-insensitive because Azure resource names are case-insensitive)
        $inScope = $resources.ToArray()
        if ($filterByName)
        {
            $inScope = @($inScope | Where-Object { $targetNames -contains $_.Name })
        }
        foreach ($r in $inScope)
        {
            [void]$discovered.Add($r.Name)
        }
        Write-Log -Message ("Search complete: {0} resource(s) match your filters in this subscription.{1}" -f $inScope.Count, $(if ($inScope.Count -gt 0) { ' Now checking each one for the diagnostic setting...' } else { ' Nothing to check here.' })) -Indent 2

        $resIndex = 0
        foreach ($res in $inScope)
        {
            $resIndex++
            Write-Progress -Activity "Processing $($sub.Name)" -Status ("{0} ({1} of {2})" -f $res.Name, $resIndex, $inScope.Count) -PercentComplete ([int](($resIndex / [Math]::Max($inScope.Count, 1)) * 100))
            Write-Host ''
            Write-Log -Message ("[{0} of {1}] {2}  (type: {3}, resource group: {4})" -f $resIndex, $inScope.Count, $res.Name, $res.TypeLabel, $res.ResourceGroupName)
            Write-Log -Message ("Technical detail - full Azure ID: {0}" -f $res.ResourceId) -LogOnly    

            # --- Read settings ---
            $settings = @()
            try
            {
                $settings = @(Get-AzDiagnosticSetting -ResourceId $res.ResourceId -ErrorAction Stop -WarningAction SilentlyContinue | Where-Object { $_ })
            }
            catch
            {
                $errMsg = $_.Exception.Message
                if ($errMsg -notmatch 'ResourceNotFound|NotFound|404')
                {
                    Write-Warning "Could not read diagnostic settings for $($res.Name): $errMsg"
                    Write-Log -Message "Could not read this resource's diagnostic settings, so it was SKIPPED (nothing changed). Common causes: missing permission, or this resource type does not support diagnostic settings. Technical detail: $errMsg" -Level 'ERROR' -Indent 4
                    $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'Error-ReadSettings' -Message $errMsg))
                    continue
                }
            }

            $exact  = @($settings | Where-Object { $_.Name -ceq $DiagnosticSettingName })
            $near   = @($settings | Where-Object { ($_.Name -ieq $DiagnosticSettingName) -and ($_.Name -cne $DiagnosticSettingName) })

            Write-Log -Message ("Diagnostic settings found on this resource: {0}" -f $(if ($settings.Count -gt 0) { (($settings | ForEach-Object { "'" + $_.Name + "'" }) -join ', ') } else { 'none' })) -Indent 4
            
            $others = @($settings | Where-Object { $_.Name -cne $DiagnosticSettingName } | ForEach-Object { $_.Name })

            if ($exact.Count -eq 0)
            {
                if ($near.Count -gt 0)
                {
                    $nearNames = ($near | ForEach-Object { $_.Name }) -join ', '
                    Write-Warning "$($res.Name): found '$nearNames' which differs from '$DiagnosticSettingName' only by letter case. Skipped."
                    Write-Log -Message "A setting named '$nearNames' exists, but its capital/small letters differ from '$DiagnosticSettingName'. Because the match must be exact, it was NOT touched." -Level 'WARN' -Indent 4
                    $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'Skipped-NameCaseMismatch' -Message "Found '$nearNames' (case differs). Not touched." -OtherNames $others))
                }
                else
                {
                    Write-Log -Message "The setting '$DiagnosticSettingName' is not present here, so there is nothing to do. This is fine (it may already have been removed)." -Indent 4
                    $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'NotFound-NothingToDo' -Message 'The setting is not present on this resource. Nothing to do.' -OtherNames $others))
                }
                continue
            }

            $workspace = [string]$exact[0].WorkspaceId

            # --- Confirm / WhatIf gate ---
            if (-not $PSCmdlet.ShouldProcess(("{0} ({1}) in resource group '{2}'" -f $res.Name, $res.TypeLabel, $res.ResourceGroupName), "Save a backup copy of diagnostic setting '$DiagnosticSettingName' and then DELETE it"))
            {
                if ($isDryRun)
                {
                    $wsShort = $(if ($workspace) { ($workspace -split '/')[-1] } else { 'a destination other than a Log Analytics workspace' })
                    Write-Log -Message ("DRY RUN: setting '{0}' WOULD be backed up and then deleted. It currently sends data to: {1}. The other {2} setting(s) on this resource would be left untouched. NOTHING was changed." -f $DiagnosticSettingName, $wsShort, $others.Count) -Level 'DRYRUN' -Indent 4
                    Write-Log -Message ("Technical detail - destination workspace ID: {0}" -f $workspace) -LogOnly
                    $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'DryRun-WouldDelete' -Message 'Practice run: this setting WOULD be backed up and deleted. Nothing was changed.' -WorkspaceId $workspace -OtherNames $others))
                }
                else
                {
                    Write-Log -Message "You chose not to delete this one at the confirmation prompt, so it was left as it is." -Level 'WARN' -Indent 4
                    $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'Skipped-Declined' -Message 'You chose not to delete this one. Left as it is.' -WorkspaceId $workspace -OtherNames $others))
                }
                continue
            }

            # --- Backup ---
            $backupPath = ''
            if (-not $SkipBackup)
            {
                Write-Log -Message 'Saving a backup copy of the setting before deleting it...' -Indent 4

                try
                {
                    $apiPath = '{0}/providers/Microsoft.Insights/diagnosticSettings/{1}?api-version=2021-05-01-preview' -f $res.ResourceId, [System.Uri]::EscapeDataString($DiagnosticSettingName)
                    $resp = Invoke-AzRestMethod -Path $apiPath -Method GET -ErrorAction Stop
                    if ($resp.StatusCode -ne 200)
                    {
                        throw "REST GET returned status $($resp.StatusCode)"
                    }
                    $json = $resp.Content | ConvertFrom-Json | ConvertTo-Json -Depth 20

                    [void][System.IO.Directory]::CreateDirectory($backupFolder)
                    $safeRg    = ($res.ResourceGroupName -replace '[^\w\.\-]', '_')
                    $safeName  = (($res.Name + '_' + $res.TypeLabel) -replace '[^\w\.\-]', '_')
                    $safeSet   = ($DiagnosticSettingName -replace '[^\w\.\-]', '_')
                    $backupPath = Join-Path -Path $backupFolder -ChildPath ('{0}__{1}__{2}__{3}.json' -f $sub.Id, $safeRg, $safeName, $safeSet)
                    [System.IO.File]::WriteAllText($backupPath, $json, (New-Object System.Text.UTF8Encoding($false)))
                    Write-Log -Message "Backup saved. A copy of the setting was stored in: $backupPath (it can be used to restore the setting if ever needed)." -Level 'OK' -Indent 4
                }
                catch
                {
                    $errMsg = $_.Exception.Message
                    Write-Warning "Backup failed for $($res.Name). Delete skipped. $errMsg"
                    Write-Log -Message "The backup could not be saved, so the setting was NOT deleted (safety rule). Technical detail: $errMsg" -Level 'ERROR' -Indent 4
                    $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'Skipped-BackupFailed' -Message $errMsg -WorkspaceId $workspace -OtherNames $others))
                    continue
                }
            }
            else
            {
                Write-Log -Message 'Backup is switched off (-SkipBackup). The setting will be deleted WITHOUT a backup copy.' -Level 'WARN' -Indent 4
            }            

            # --- Delete ---
            Write-Log -Message "Deleting the setting '$DiagnosticSettingName' now..." -Indent 4

            try
            {
                Remove-AzDiagnosticSetting -ResourceId $res.ResourceId -Name $DiagnosticSettingName -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch
            {
                $errMsg = $_.Exception.Message
                Write-Warning "Delete failed for $($res.Name): $errMsg"
                Write-Log -Message "Azure refused or failed the delete, so the setting is still there. Technical detail: $errMsg" -Level 'ERROR' -Indent 4
                $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'Failed-Delete' -Message $errMsg -BackupPath $backupPath -WorkspaceId $workspace -OtherNames $others))
                continue
            }

            # --- Verify ---
            try
            {
                $after = @(Get-AzDiagnosticSetting -ResourceId $res.ResourceId -ErrorAction Stop -WarningAction SilentlyContinue | Where-Object { $_ -and ($_.Name -ceq $DiagnosticSettingName) })
                if ($after.Count -gt 0)
                {
                    Write-Log -Message "The delete command ran, but the setting is STILL there. Likely causes: an Azure Policy re-created it, or a resource lock. Check Policy assignments / remediation tasks and locks." -Level 'ERROR' -Indent 4
                    $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'Failed-StillPresent' -Message 'Delete ran but the setting is still there. Check Azure Policy and resource locks.' -BackupPath $backupPath -WorkspaceId $workspace -OtherNames $others))
                }
                else
                {
                    Write-Log -Message "SUCCESS: setting '$DiagnosticSettingName' was deleted and confirmed gone. $($others.Count) other setting(s) on this resource were left untouched." -Level 'OK' -Indent 4
                    $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'Deleted' -Message 'Backed up (unless skipped), deleted and confirmed gone.' -BackupPath $backupPath -WorkspaceId $workspace -OtherNames $others))
                }
            }
            catch
            {
                $errMsg = $_.Exception.Message
                if ($errMsg -match 'ResourceNotFound|NotFound|404')
                {
                    Write-Log -Message "SUCCESS: setting '$DiagnosticSettingName' was deleted and confirmed gone." -Level 'OK' -Indent 4
                    $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'Deleted' -Message 'Backed up (unless skipped), deleted and confirmed gone.' -BackupPath $backupPath -WorkspaceId $workspace -OtherNames $others))
                }
                else
                {
                    Write-Log -Message "The delete command succeeded, but the final re-check could not be completed. Please confirm in the Azure portal. Technical detail: $errMsg" -Level 'WARN' -Indent 4
                    $results.Add((New-ResultRow -Sub $sub -Res $res -Status 'Deleted-VerifyUnconfirmed' -Message "Delete call succeeded; verification could not be confirmed: $errMsg" -BackupPath $backupPath -WorkspaceId $workspace -OtherNames $others))
                }
            }
        }
    }
    Write-Progress -Activity 'Processing' -Completed

    # ------------------------------------------------------------------
    # Reconcile requested names that were never found
    # ------------------------------------------------------------------
    Write-Section -Title 'STEP 5 of 5 - Final checks and reports'

    if ($filterByName)
    {
        $notFoundNames = @($targetNames | Where-Object { -not $discovered.Contains($_) })
        foreach ($missingName in $notFoundNames)
        {
            Write-Warning "Requested resource not found in scope: $missingName"
            Write-Log -Message "You asked for the resource '$missingName', but it was not found in any scanned subscription, resource group or resource type. Please check the spelling and the -ResourceType you used." -Level 'WARN'
            $results.Add((New-ResultRow -Sub ([pscustomobject]@{ Id = '(all scanned)'; Name = '' }) -Res ([pscustomobject]@{ Name = $missingName; ResourceGroupName = ''; TypeLabel = ''; ResourceId = '' }) -Status 'ResourceNotFound' -Message 'Name not found in the scanned subscriptions, resource groups or resource types.'))
        }
    }

    # ------------------------------------------------------------------
    # Report + summary
    # ------------------------------------------------------------------
    if ($results.Count -gt 0)
    {
        try
        {
            $results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8 -WhatIf:$false -ErrorAction Stop
            Write-Log -Message "Spreadsheet report (CSV) saved: $csvFile" -Level 'OK'
        }
        catch
        {
            Write-Warning "Could not write CSV report: $($_.Exception.Message)"
            Write-Log -Message "The spreadsheet report (CSV) could not be saved. Technical detail: $($_.Exception.Message)" -Level 'ERROR'
        }
    }

    $statusHelp = @{
        'DryRun-WouldDelete'        = 'Practice run only: the setting was found and WOULD be backed up and deleted in a live run. Nothing was changed.'
        'Deleted'                   = 'Success: the setting was backed up (unless skipped), deleted and confirmed gone.'
        'Deleted-VerifyUnconfirmed' = 'The delete succeeded but the final re-check could not be completed. Please verify in the Azure portal.'
        'NotFound-NothingToDo'      = 'The setting was not present, so there was nothing to remove. No action needed.'
        'Skipped-NameCaseMismatch'  = 'A setting with a similar name but different capital/small letters exists. It was NOT touched.'
        'Skipped-Declined'          = 'You answered No at the confirmation prompt, so it was left as it is.'
        'Skipped-BackupFailed'      = 'The backup could not be saved, so the setting was NOT deleted (safety rule). Needs attention.'
        'Failed-Delete'             = 'Azure refused or failed the delete. The setting is still there. Needs attention.'
        'Failed-StillPresent'       = 'The delete ran but the setting is still there (possibly re-created by Azure Policy). Needs attention.'
        'Error-ReadSettings'        = 'The settings of this resource could not be read, so it was skipped. Needs attention.'
        'Error-Discovery'           = 'The search for resources failed for a subscription or resource group. Needs attention.'
        'ResourceNotFound'          = 'A resource name you supplied was not found anywhere that was scanned. Check the spelling.'
    }

    Write-Section -Title ('RUN SUMMARY - ' + $(if ($isDryRun) { 'DRY RUN (nothing was changed)' } else { 'LIVE RUN' }))

    if ($results.Count -eq 0)
    {
        Write-Log -Message 'No resources matched your selection, so there is nothing to report.' -Level 'WARN'
    }
    else
    {
        Write-Log -Message ("Total items checked or reported: {0}" -f $results.Count)
        foreach ($grp in ($results | Group-Object -Property Status | Sort-Object -Property Name))
        {
            $colour = 'Gray'
            if ($grp.Name -match '^(Failed|Error)|BackupFailed|ResourceNotFound')
            {
                $colour = 'Red'
            }
            elseif ($grp.Name -match 'Skipped|Unconfirmed')
            {
                $colour = 'Yellow'
            }
            elseif ($grp.Name -eq 'Deleted')
            {
                $colour = 'Green'
            }
            elseif ($grp.Name -match '^DryRun')
            {
                $colour = 'Cyan'
            }

            $help = [string]$statusHelp[$grp.Name]
            Write-Host ('  {0,3} x {1}' -f $grp.Count, $grp.Name) -ForegroundColor $colour
            Write-Host ('        {0}' -f $help) -ForegroundColor Gray
            Write-Log -Message ('Summary: {0} = {1}. Meaning: {2}' -f $grp.Name, $grp.Count, $help) -LogOnly
        }
    }

    $needsAttention = @($results | Where-Object { $_.Status -match '^(Failed|Error)|BackupFailed|ResourceNotFound|Unconfirmed' }).Count
    Write-Host ''
    if ($needsAttention -gt 0)
    {
        Write-Log -Message ("{0} item(s) need your attention. Open the log file and search for ERROR or WARN to see what happened." -f $needsAttention) -Level 'ERROR'
    }
    elseif ($results.Count -gt 0)
    {
        Write-Log -Message 'No problems were found during this run.' -Level 'OK'
    }
    if ($isDryRun -and (@($results | Where-Object { $_.Status -eq 'DryRun-WouldDelete' }).Count -gt 0))
    {
        Write-Log -Message 'NEXT STEP: review the CSV report. When you are happy with the list, run the same command again WITHOUT -DryRun / -WhatIf to remove the setting.'
    }

    Write-Host ''
    Write-Host 'Files created by this run:' -ForegroundColor Cyan
    Write-Host "  Log file (full detail)           : $logFile"
    if ($results.Count -gt 0)
    {
        Write-Host "  CSV report (one row per resource): $csvFile"
    }
    if ((-not $isDryRun) -and (-not $SkipBackup))
    {
        Write-Host "  Backups of removed settings      : $backupFolder"
    }
    Write-Log -Message "Files: log=$logFile | csv=$csvFile | backups=$backupFolder" -LogOnly
    Write-Log -Message 'Run finished.' -Level 'OK'
    Write-Host ''
    
    if ($PassThru)
    {
        $results
    }
}
