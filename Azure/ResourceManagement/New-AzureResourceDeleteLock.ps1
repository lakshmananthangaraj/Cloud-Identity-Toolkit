<#

Author          : Lakshmanan Thangaraj
Version         : 1.3
Created-On      : 20 July 2026
Modified-On     : 28 July 2026

.SYNOPSIS
    Applies "CanNotDelete" management locks to Web Apps, Function Apps, and/or
    Logic Apps across one or more Azure subscriptions.

.DESCRIPTION
    New-AzureResourceDeleteLock scans one or more Azure subscriptions and applies a
    CanNotDelete resource lock to resources matching the selected resource
    type(s): WebApp, FunctionApp, LogicApp, or All (Web Apps and Function Apps
    share the ARM type Microsoft.Web/sites and are distinguished by the Kind
    property; Logic Apps are Microsoft.Logic/workflows).

    Scope can be narrowed to:
        - Specific resources (-ResourceName), optionally combined with
          -ResourceGroupName to disambiguate duplicate names.
        - Specific Resource Groups (-ResourceGroupName only).
        - The entire subscription (neither parameter supplied — see WARNING
          under -ResourceGroupName / -ResourceName below).

    The function:
        - Verifies Az.Accounts and Az.Resources are installed, and displays
          the exact Install-Module command if not.
        - Checks for an active Azure session (Get-AzContext) and, if none is
          found, prompts the user to sign in via Connect-AzAccount. Sign-in
          success is explicitly re-validated before continuing.
        - Skips any resource that already has a lock at its own scope
          (any LockLevel), so existing protections are never touched.
        - Treats a failed "does this resource already have a lock" check as
          a reason to SKIP that resource, not a reason to proceed — avoids
          creating duplicate/conflicting locks when the check itself errors.
        - If one Subscription ID in a multi-subscription list fails to
          resolve, that one is skipped (with a warning) and the rest of the
          run continues — a single bad ID no longer aborts the entire call.
        - Surfaces resource-discovery failures (e.g. permission gaps on a
          Resource Group) as explicit warnings instead of silently treating
          them as "zero matching resources."
        - Supports -WhatIf / -Confirm on the actual lock-creation step.
          ConfirmImpact is High, reflecting that an unscoped run can lock
          every matching resource across an entire subscription in one go.
        - Logs every step to the console using plain Write-Host output only —
          no external/custom toolkit functions or scripts are required. This
          function is fully self-contained.
        - Exports a full CSV report and also returns the results as
          PowerShell objects for pipeline reuse.
        - Can display a plain-language explanation of Microsoft's documented
          lock behavior and gotchas via -ShowHelp (see that parameter).

.PARAMETER ResourceType
    Mandatory. One or more resource types to target: WebApp, FunctionApp,
    LogicApp, or All. Accepts an array, e.g. -ResourceType WebApp,FunctionApp.
    Use 'All' to target every supported type in one call (equivalent to
    WebApp, FunctionApp, LogicApp combined); it can also be mixed with other
    values with no ill effect.

.PARAMETER SubscriptionId
    Optional. One or more Subscription IDs to process. If omitted, only the
    currently active Az context subscription is used. If any ID in a
    multi-value list fails to resolve, it is skipped (with a warning) and
    the remaining valid subscriptions are still processed.

.PARAMETER ResourceGroupName
    Optional. One or more Resource Group names to scope the search to. If
    combined with -ResourceName, each name is looked up inside each of these
    Resource Groups.

    WARNING — If BOTH -ResourceGroupName and -ResourceName are omitted, the
    function scans and locks matching resources across the ENTIRE
    subscription, not just "one resource" or "one group." In plain terms:
    if you only pass -ResourceType LogicApp with no group/name filter, every
    Logic App in every Resource Group in that subscription gets locked in
    one run. Always pass -ResourceGroupName and/or -ResourceName when you
    want to touch a smaller, specific set of resources. Use -WhatIf first
    to preview exactly what would be locked before running for real.

.PARAMETER ResourceName
    Optional. One or more specific resource names to target. If
    -ResourceGroupName is also supplied, lookups are scoped per Resource
    Group; otherwise each name is searched for across the subscription. See
    the WARNING under -ResourceGroupName about what happens if this and
    -ResourceGroupName are both left empty.

.PARAMETER LockName
    Optional. Name given to each created lock. Default: "CanNotDelete-AutoApplied".

.PARAMETER LockNotes
    Optional. Notes stored on each created lock. Default: a short description
    identifying this function as the source of the lock.

.PARAMETER OutputPath
    Optional. Directory where the CSV report will be saved. Defaults to the
    current directory.

.PARAMETER ShowHelp
    Optional switch. When supplied, the function prints a plain-language
    explanation of what a CanNotDelete lock does and does not protect
    against, based on Microsoft's official guidance, then exits immediately
    without checking prerequisites, authenticating, or touching Azure in any
    way. Use this any time you (or someone else running this script) want a
    refresher before locking resources. A short version of the same caution
    is also always shown automatically before a real run.

.INPUTS
    None. You cannot pipe objects to New-AzureResourceDeleteLock.

.OUTPUTS
    System.Management.Automation.PSCustomObject
    One object per evaluated resource (SubscriptionName, SubscriptionId,
    ResourceGroup, ResourceName, ResourceType, Kind, ResourceId, Action,
    LockName, Status, Message, TimestampUTC). Also exported to CSV.

.EXAMPLE
    # Just read the plain-language guidance on locks; makes no changes
    New-AzureResourceDeleteLock -ResourceType LogicApp -ShowHelp

.EXAMPLE
    # Lock every Web App and Function App in the whole subscription (current context)
    New-AzureResourceDeleteLock -ResourceType WebApp,FunctionApp

.EXAMPLE
    # Lock only Logic Apps in two specific Resource Groups, across two subscriptions
    New-AzureResourceDeleteLock -ResourceType LogicApp `
        -SubscriptionId "sub-id-1","sub-id-2" `
        -ResourceGroupName "rg-integration","rg-workflows"

.EXAMPLE
    # Preview what would happen (no changes made) for specific named resources
    New-AzureResourceDeleteLock -ResourceType WebApp -ResourceGroupName "rg-prod" `
        -ResourceName "app-checkout","app-billing" -WhatIf

.EXAMPLE
    # Apply locks and save the CSV report to a custom folder
    New-AzureResourceDeleteLock -ResourceType WebApp,FunctionApp,LogicApp -OutputPath "C:\Reports\Locks"

.EXAMPLE
    # Lock every supported resource type (Web Apps, Function Apps, Logic Apps)
    New-AzureResourceDeleteLock -ResourceType All -WhatIf

.NOTES
    Requirements : PowerShell 5.1+, Az.Accounts, Az.Resources
                   Install-Module -Name Az.Accounts, Az.Resources -Scope CurrentUser -AllowClobber
    Permissions  : Microsoft.Authorization/locks/write on each target scope
                   (typically via Owner, Contributor, or User Access Administrator
                   at the relevant Resource Group/Subscription level).
    Assumption   : "Skip resources that already have a lock" is evaluated at the
                   resource's own scope only (any LockLevel). Locks inherited from
                   a parent Resource Group or Subscription are not treated as a
                   reason to skip, since the goal here is a lock on the resource
                   itself. Flag if inherited locks should also count as "already
                   protected."
    Assumption   : The "already locked" check does not distinguish locks created
                   by THIS function from locks created any other way — ANY
                   existing lock (any name, any source) causes a skip. Running
                   this function multiple times with different -LockName values
                   will NOT create duplicate locks on an already-locked resource;
                   it will simply keep skipping it.
    No external
    dependency   : This script does not call, dot-source, or require any custom
                   or shared "toolkit" scripts. All console output uses plain
                   built-in Write-Host. You can copy this single file anywhere
                   and run it standalone.

    Things to know before you run this (plain language, based on Microsoft's
    official "Lock your Azure resources" documentation):
        - A lock on a resource only protects THAT resource (and, if it has
          any, its extension resources like diagnostic settings). It does
          NOT spread sideways to other resources sitting in the same
          Resource Group. It only flows downward, parent to child.
        - Locks only stop management/control-plane actions (create, update,
          delete via the Azure Resource Manager API or portal). They do NOT
          stop the app from running, and they do NOT protect data inside the
          resource (e.g. a lock on a Logic App does not protect its run
          history or connections from being changed).
        - CanNotDelete blocks deletion but still allows normal updates — a
          locked Logic App can still be redeployed/updated in place via
          Portal, ARM/Bicep, or CI/CD, as long as the deployment does not
          try to delete and recreate the resource.
        - The type of deployment/automation matters: pipelines or scripts
          that delete a resource and recreate it from scratch WILL fail
          while a CanNotDelete lock is on. Pipelines that update the
          existing resource in place are typically unaffected.
        - If a CanNotDelete lock is placed on a Resource Group (not just a
          single resource), Azure can no longer automatically clean up old
          deployment history in that group. After 800 deployments pile up,
          further deployments to that Resource Group start failing. This
          script only locks the resource itself, not the Resource Group, so
          this specific issue does not apply to locks created by this
          function — but it's worth knowing if anyone later locks the
          Resource Group by hand.
        - Only users with Owner, User Access Administrator, or an equivalent
          custom role can create or remove locks — regular Contributor
          access is not enough.
        - Always test with -WhatIf first, especially before running against
          an entire subscription with no -ResourceGroupName / -ResourceName
          filter.

    CHANGELOG:
        v1.3 - 28 July 2026 - Fixed Author block to match standard flat format.
                              Added .INPUTS/.OUTPUTS/.LINK sections. Fixed bug
                              where an invalid/inaccessible -SubscriptionId
                              aborted the ENTIRE run (now skips that
                              subscription and continues with the rest — this
                              is a behavior change, flagged to user). Fixed
                              bug where a failed "already locked?" check was
                              silently treated as "not locked," risking a
                              duplicate/conflicting lock attempt — it is now
                              treated as a reason to SKIP that resource.
                              Discovery failures (previously silently
                              swallowed via -ErrorAction SilentlyContinue) are
                              now surfaced as explicit warnings so permission
                              gaps aren't indistinguishable from "no resources
                              found." Added explicit re-validation that
                              Connect-AzAccount actually produced a signed-in
                              context before continuing. Bumped ConfirmImpact
                              to High given the subscription-wide blast radius
                              when no -ResourceGroupName/-ResourceName filter
                              is supplied.
        v1.2 - 20 July 2026 - Removed all dependency on the shared/custom
                              console-output toolkit (Write-Banner,
                              Write-SectionHeader, Write-Step, Write-Info,
                              Write-Success, Write-Failure); replaced with
                              plain built-in Write-Host calls so the script
                              is fully self-contained. Added a -ShowHelp
                              switch that prints Microsoft's documented lock
                              considerations in plain language and exits
                              without making changes; a short version of the
                              same caution is now also shown automatically
                              before every real run. Expanded comment-based
                              help to clearly document what happens when
                              -ResourceGroupName / -ResourceName are both
                              omitted. No changes to discovery, filtering,
                              matching, or locking logic.
        v1.1 - 20 July 2026 - Removed the toolkit dot-sourcing/fallback block;
                              toolkit functions were called directly and
                              assumed to be globally available in the session.
                              Added 'All' as a valid -ResourceType value to
                              target every supported type in one call.
        v1.0 - 20 July 2026 - Initial release.

.LINK
    https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources

#>


Function New-AzureResourceDeleteLock
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "One or more resource types to target: WebApp, FunctionApp, LogicApp, or All.")]
        [ValidateSet('WebApp', 'FunctionApp', 'LogicApp', 'All')]
        [string[]]$ResourceType,

        [Parameter(Mandatory = $false, HelpMessage = "One or more Subscription IDs. Defaults to the current Az context subscription.")]
        [string[]]$SubscriptionId,

        [Parameter(Mandatory = $false, HelpMessage = "One or more Resource Group names to scope the search to.")]
        [string[]]$ResourceGroupName,

        [Parameter(Mandatory = $false, HelpMessage = "One or more specific resource names to target.")]
        [string[]]$ResourceName,

        [Parameter(Mandatory = $false, HelpMessage = "Name assigned to each created lock.")]
        [ValidateNotNullOrEmpty()]
        [string]$LockName = "CanNotDelete-AutoApplied",

        [Parameter(Mandatory = $false, HelpMessage = "Notes stored on each created lock.")]
        [string]$LockNotes = "Applied by New-AzureResourceDeleteLock for delete protection.",

        [Parameter(Mandatory = $false, HelpMessage = "Directory path to save the CSV report.")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = (Get-Location).Path,

        [Parameter(Mandatory = $false, HelpMessage = "Show a plain-language explanation of lock behavior/limitations and exit without making changes.")]
        [switch]$ShowHelp
    )

    #region ── Plain-language guidance block (Microsoft lock documentation) ──────
    # Shared text used both by -ShowHelp (full version, script exits after) and
    # automatically before every real run (short version, script continues).
    Function Show-LockGuidance
    {
        param([switch]$FullVersion)

        Write-Host ""
        Write-Host "=====================================================================" -ForegroundColor Yellow
        Write-Host "                ABOUT DELETE LOCKS — PLEASE READ                     " -ForegroundColor Yellow
        Write-Host "=====================================================================" -ForegroundColor Yellow
        Write-Host "  A 'CanNotDelete' lock stops a resource from being deleted, but it" -ForegroundColor Gray
        Write-Host "  still allows normal updates/redeployments in place." -ForegroundColor Gray
        Write-Host "  It only protects the exact resource it is applied to — it does NOT" -ForegroundColor Gray
        Write-Host "  spread to other resources sitting in the same Resource Group." -ForegroundColor Gray
        Write-Host "  It does NOT stop the app from running, and it does NOT protect the" -ForegroundColor Gray
        Write-Host "  data/content inside the resource." -ForegroundColor Gray

        if ($FullVersion)
        {
            Write-Host "" -ForegroundColor Gray
            Write-Host "  A few things worth knowing before you lock anything:" -ForegroundColor Gray
            Write-Host "   - Deployments that UPDATE a resource in place are fine while it is" -ForegroundColor Gray
            Write-Host "     locked. Deployments that DELETE and recreate the resource from" -ForegroundColor Gray
            Write-Host "     scratch will fail until the lock is removed." -ForegroundColor Gray
            Write-Host "   - If a lock is later placed on a Resource Group itself (not a" -ForegroundColor Gray
            Write-Host "     single resource), Azure can no longer clean up old deployment" -ForegroundColor Gray
            Write-Host "     history automatically; after 800 deployments pile up, further" -ForegroundColor Gray
            Write-Host "     deployments to that group start failing. This script only locks" -ForegroundColor Gray
            Write-Host "     individual resources, so this does not apply to what it creates." -ForegroundColor Gray
            Write-Host "   - Only Owner / User Access Administrator (or an equivalent custom" -ForegroundColor Gray
            Write-Host "     role) can create or remove locks — Contributor alone is not" -ForegroundColor Gray
            Write-Host "     enough." -ForegroundColor Gray
            Write-Host "   - If you run this WITHOUT -ResourceGroupName or -ResourceName, it" -ForegroundColor Gray
            Write-Host "     locks every matching resource type across the WHOLE subscription" -ForegroundColor Gray
            Write-Host "     in one go — not just one resource or one group." -ForegroundColor Gray
            Write-Host "   - Always try -WhatIf first to preview exactly what would be locked." -ForegroundColor Gray
            Write-Host "" -ForegroundColor Gray
            Write-Host "  Full Microsoft documentation:" -ForegroundColor Gray
            Write-Host "  https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources" -ForegroundColor Gray
        }

        Write-Host "=====================================================================" -ForegroundColor Yellow
        Write-Host ""
    }
    #endregion

    if ($ShowHelp)
    {
        Show-LockGuidance -FullVersion
        Write-Host "  -ShowHelp was supplied — no prerequisite checks, sign-in, or Azure" -ForegroundColor Cyan
        Write-Host "  changes were made. Re-run without -ShowHelp to actually apply locks." -ForegroundColor Cyan
        Write-Host ""
        return
    }

    #region ── Expand 'All' into the full supported type list ────────────────────
    if ($ResourceType -contains 'All')
    {
        $ResourceType = @('WebApp', 'FunctionApp', 'LogicApp')
    }
    else
    {
        # De-duplicate in case the caller passed overlapping values manually.
        $ResourceType = $ResourceType | Select-Object -Unique
    }
    #endregion

    #region ── Banner ──────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "=====================================================================" -ForegroundColor Cyan
    Write-Host "  New-AzureResourceDeleteLock" -ForegroundColor Cyan
    Write-Host "  CanNotDelete Lock Enforcement - Web / Function / Logic Apps" -ForegroundColor Cyan
    Write-Host "=====================================================================" -ForegroundColor Cyan
    Write-Host ""
    #endregion

    Show-LockGuidance

    #region ── Step 1: Prerequisite Check ─────────────────────────────────────────
    Write-Host ""
    Write-Host "--- Step 1 of 5: Checking Prerequisites ---" -ForegroundColor DarkCyan
    Write-Host ""

    $requiredModules = @('Az.Accounts', 'Az.Resources')
    $missingModules  = @()

    foreach ($requiredModule in $requiredModules)
    {
        if (-not (Get-Module -ListAvailable -Name $requiredModule))
        {
            $missingModules += $requiredModule
        }
    }

    if ($missingModules.Count -gt 0)
    {
        Write-Host "  ! Missing required module(s): $($missingModules -join ', ')" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Install the missing module(s) with:" -ForegroundColor Yellow
        Write-Host "    Install-Module -Name $($missingModules -join ', ') -Scope CurrentUser -AllowClobber" -ForegroundColor White
        Write-Host ""
        return
    }

    Write-Host "  OK Required modules present: $($requiredModules -join ', ')" -ForegroundColor Green
    #endregion

    #region ── Step 2: Authentication Check ───────────────────────────────────────
    Write-Host ""
    Write-Host "--- Step 2 of 5: Verifying Azure Authentication ---" -ForegroundColor DarkCyan
    Write-Host ""

    $activeContext = $null
    try
    {
        $activeContext = Get-AzContext -ErrorAction SilentlyContinue
    }
    catch
    {
        $activeContext = $null
    }

    if (-not $activeContext -or -not $activeContext.Account)
    {
        Write-Host "  i No active Azure session detected. Prompting for sign-in..." -ForegroundColor Gray
        try
        {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $activeContext = Get-AzContext

            if (-not $activeContext -or -not $activeContext.Account)
            {
                Write-Host "  ! Sign-in did not complete (no active account after Connect-AzAccount). Aborting." -ForegroundColor Red
                return
            }
        }
        catch
        {
            Write-Host "  ! Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }

    Write-Host "  OK Signed in as $($activeContext.Account.Id) (Tenant: $($activeContext.Tenant.Id))" -ForegroundColor Green
    $originalContext = $activeContext
    #endregion

    #region ── Step 3: Resolve Target Subscriptions ───────────────────────────────
    Write-Host ""
    Write-Host "--- Step 3 of 5: Resolving Target Subscriptions ---" -ForegroundColor DarkCyan
    Write-Host ""

    $targetSubscriptions = New-Object System.Collections.Generic.List[Object]

    try
    {
        if ($SubscriptionId -and $SubscriptionId.Count -gt 0)
        {
            $failedSubscriptionIds = @()

            foreach ($subId in $SubscriptionId)
            {
                try
                {
                    $subscriptionObject = Get-AzSubscription -SubscriptionId $subId -ErrorAction Stop
                    $targetSubscriptions.Add($subscriptionObject)
                }
                catch
                {
                    $failedSubscriptionIds += $subId
                    Write-Host "  ! Could not resolve subscription '$subId' — skipping. $($_.Exception.Message)" -ForegroundColor Red
                }
            }

            if ($failedSubscriptionIds.Count -gt 0)
            {
                Write-Host "  ! $($failedSubscriptionIds.Count) subscription(s) skipped due to resolution errors: $($failedSubscriptionIds -join ', ')" -ForegroundColor Yellow
            }

            if ($targetSubscriptions.Count -eq 0)
            {
                Write-Host "  ! None of the supplied SubscriptionId values could be resolved. Aborting." -ForegroundColor Red
                return
            }
        }
        else
        {
            $subscriptionObject = Get-AzSubscription -SubscriptionId $activeContext.Subscription.Id -ErrorAction Stop
            $targetSubscriptions.Add($subscriptionObject)
        }
    }
    catch
    {
        Write-Host "  ! Failed to resolve subscription(s): $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    Write-Host "  i Target subscription(s): $($targetSubscriptions.Name -join ', ')" -ForegroundColor Gray

    if ($ResourceName -and $ResourceName.Count -gt 0)
    {
        Write-Host "  i Scope: specific resource(s) — $($ResourceName -join ', ')" -ForegroundColor Gray
    }
    elseif ($ResourceGroupName -and $ResourceGroupName.Count -gt 0)
    {
        Write-Host "  i Scope: Resource Group(s) — $($ResourceGroupName -join ', ')" -ForegroundColor Gray
    }
    else
    {
        Write-Host "  i Scope: ENTIRE SUBSCRIPTION (no Resource Group / resource filter supplied)" -ForegroundColor Yellow
        Write-Host "    Every matching resource type in every Resource Group will be evaluated." -ForegroundColor Yellow
    }

    Write-Host "  i Resource type(s): $($ResourceType -join ', ')" -ForegroundColor Gray
    #endregion

    #region ── Resource Type Map ──────────────────────────────────────────────────
    # Web Apps and Function Apps share the same ARM type (Microsoft.Web/sites) and
    # are distinguished only by the 'Kind' property. Logic Apps have their own
    # dedicated ARM type. Add new entries here to extend -ResourceType later
    # (e.g. StorageAccount) without touching the matching/locking logic below.
    $resourceTypeMap = @{
        'WebApp'      = @{ ArmType = 'Microsoft.Web/sites';        KindPattern = '^app($|,)' }
        'FunctionApp' = @{ ArmType = 'Microsoft.Web/sites';        KindPattern = 'functionapp' }
        'LogicApp'    = @{ ArmType = 'Microsoft.Logic/workflows';  KindPattern = $null }
    }
    #endregion

    #region ── Step 4: Discover, Filter, and Lock Resources ──────────────────────
    Write-Host ""
    Write-Host "--- Step 4 of 5: Discovering and Locking Matching Resources ---" -ForegroundColor DarkCyan
    Write-Host ""

    $results = New-Object System.Collections.Generic.List[Object]

    foreach ($subscription in $targetSubscriptions)
    {
        Write-Host ""
        Write-Host "  i Switching context to subscription: $($subscription.Name) ($($subscription.Id))" -ForegroundColor Gray

        try
        {
            Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
        }
        catch
        {
            Write-Host "  ! Could not switch to subscription '$($subscription.Id)': $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        #region -- Discover candidate resources for this subscription --
        $candidateResources = New-Object System.Collections.Generic.List[Object]

        try
        {
            if ($ResourceName -and $ResourceName.Count -gt 0)
            {
                if ($ResourceGroupName -and $ResourceGroupName.Count -gt 0)
                {
                    foreach ($rg in $ResourceGroupName)
                    {
                        foreach ($rn in $ResourceName)
                        {
                            $found = $null
                            try
                            {
                                $found = Get-AzResource -ResourceGroupName $rg -Name $rn -ErrorAction Stop
                            }
                            catch
                            {
                                Write-Host "  ! Lookup failed for '$rn' in RG '$rg': $($_.Exception.Message)" -ForegroundColor Yellow
                            }
                            if ($found)
                            {
                                foreach ($item in @($found)) { $candidateResources.Add($item) }
                            }
                        }
                    }
                }
                else
                {
                    foreach ($rn in $ResourceName)
                    {
                        $found = $null
                        try
                        {
                            $found = Get-AzResource -Name $rn -ErrorAction Stop
                        }
                        catch
                        {
                            Write-Host "  ! Lookup failed for '$rn': $($_.Exception.Message)" -ForegroundColor Yellow
                        }
                        if ($found)
                        {
                            foreach ($item in @($found)) { $candidateResources.Add($item) }
                        }
                    }
                }
            }
            elseif ($ResourceGroupName -and $ResourceGroupName.Count -gt 0)
            {
                foreach ($rg in $ResourceGroupName)
                {
                    $found = $null
                    try
                    {
                        $found = Get-AzResource -ResourceGroupName $rg -ErrorAction Stop
                    }
                    catch
                    {
                        Write-Host "  ! Lookup failed for RG '$rg' — possible permission gap: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                    if ($found)
                    {
                        foreach ($item in @($found)) { $candidateResources.Add($item) }
                    }
                }
            }
            else
            {
                $found = $null
                try
                {
                    $found = Get-AzResource -ErrorAction Stop
                }
                catch
                {
                    Write-Host "  ! Subscription-wide resource discovery failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }
                if ($found)
                {
                    foreach ($item in @($found)) { $candidateResources.Add($item) }
                }
            }
        }
        catch
        {
            Write-Host "  ! Resource discovery failed for subscription '$($subscription.Name)': $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
        #endregion

        #region -- Filter to the selected resource type(s), matching Kind where relevant --
        $matchedResources = New-Object System.Collections.Generic.List[Object]

        foreach ($candidate in $candidateResources)
        {
            foreach ($selectedType in $ResourceType)
            {
                $typeDefinition = $resourceTypeMap[$selectedType]

                if ($candidate.ResourceType -ne $typeDefinition.ArmType)
                {
                    continue
                }

                if ($null -eq $typeDefinition.KindPattern)
                {
                    $matchedResources.Add($candidate)
                    break
                }
                elseif ($candidate.Kind -and ($candidate.Kind -match $typeDefinition.KindPattern))
                {
                    $matchedResources.Add($candidate)
                    break
                }
            }
        }

        Write-Host "  i Found $($matchedResources.Count) matching resource(s) in '$($subscription.Name)'." -ForegroundColor Gray
        #endregion

        #region -- Evaluate and apply locks --
        $stepCounter = 0
        $totalCount  = $matchedResources.Count

        foreach ($resource in $matchedResources)
        {
            $stepCounter++
            Write-Host "  [$stepCounter/$totalCount] $($resource.Name) [$($resource.ResourceGroupName)]" -ForegroundColor White

            $resultRow = [PSCustomObject]@{
                SubscriptionName = $subscription.Name
                SubscriptionId   = $subscription.Id
                ResourceGroup    = $resource.ResourceGroupName
                ResourceName     = $resource.Name
                ResourceType     = $resource.ResourceType
                Kind             = $resource.Kind
                ResourceId       = $resource.ResourceId
                Action           = ""
                LockName         = ""
                Status           = ""
                Message          = ""
                TimestampUTC     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }

            $existingLocks = $null
            try
            {
                $existingLocks = Get-AzResourceLock -Scope $resource.ResourceId -ErrorAction Stop
            }
            catch
            {
                $resultRow.Action  = "Skipped"
                $resultRow.Status  = "LockCheckError"
                $resultRow.Message = "Could not verify existing locks — skipped for safety: $($_.Exception.Message)"
                Write-Host "    ! Could not verify existing locks — skipping this resource for safety." -ForegroundColor Yellow
                $results.Add($resultRow)
                continue
            }

            try
            {
                if ($existingLocks -and @($existingLocks).Count -gt 0)
                {
                    $resultRow.Action   = "Skipped"
                    $resultRow.Status   = "AlreadyLocked"
                    $resultRow.LockName = (@($existingLocks) | Select-Object -ExpandProperty Name) -join ", "
                    $resultRow.Message  = "Resource already has $(@($existingLocks).Count) lock(s); skipped."
                    Write-Host "    i Already locked — skipped." -ForegroundColor Gray
                }
                elseif ($PSCmdlet.ShouldProcess($resource.ResourceId, "Apply CanNotDelete lock"))
                {
                    New-AzResourceLock -LockLevel CanNotDelete -LockName $LockName `
                        -LockNotes $LockNotes -Scope $resource.ResourceId -Force -ErrorAction Stop | Out-Null

                    $resultRow.Action   = "LockApplied"
                    $resultRow.Status   = "Success"
                    $resultRow.LockName = $LockName
                    $resultRow.Message  = "CanNotDelete lock applied successfully."
                    Write-Host "    OK CanNotDelete lock applied." -ForegroundColor Green
                }
                else
                {
                    $resultRow.Action  = "SkippedWhatIf"
                    $resultRow.Status  = "WhatIf"
                    $resultRow.Message = "No changes made (-WhatIf)."
                }
            }
            catch
            {
                $resultRow.Action  = "Failed"
                $resultRow.Status  = "Error"
                $resultRow.Message = $_.Exception.Message
                Write-Host "    ! Error: $($_.Exception.Message)" -ForegroundColor Red
            }
            finally
            {
                $results.Add($resultRow)
            }
        }
        #endregion
    }
    #endregion

    #region ── Step 5: Export CSV Report ──────────────────────────────────────────
    Write-Host ""
    Write-Host "--- Step 5 of 5: Exporting CSV Report ---" -ForegroundColor DarkCyan
    Write-Host ""

    if (-not (Test-Path -Path $OutputPath))
    {
        try
        {
            New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
            Write-Host "  i Created output directory: $OutputPath" -ForegroundColor Gray
        }
        catch
        {
            Write-Host "  ! Failed to create output directory '$OutputPath': $($_.Exception.Message)" -ForegroundColor Red
            $OutputPath = (Get-Location).Path
        }
    }

    $timestamp   = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $csvFileName = "ResourceDeleteLock_Report_$timestamp.csv"
    $csvFilePath = Join-Path -Path $OutputPath -ChildPath $csvFileName

    try
    {
        $results | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "  OK CSV report saved to: $csvFilePath" -ForegroundColor Green
    }
    catch
    {
        Write-Host "  ! Failed to export CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
    #endregion

    #region ── Restore Original Context & Summarize ───────────────────────────────
    try
    {
        Set-AzContext -SubscriptionId $originalContext.Subscription.Id -ErrorAction SilentlyContinue | Out-Null
    }
    catch
    {
        # Non-fatal: original context restoration is a courtesy, not a requirement.
    }

    $lockedCount   = @($results | Where-Object { $_.Status -eq 'Success' }).Count
    $skippedCount  = @($results | Where-Object { $_.Status -eq 'AlreadyLocked' }).Count
    $whatIfCount   = @($results | Where-Object { $_.Status -eq 'WhatIf' }).Count
    $failedCount   = @($results | Where-Object { $_.Status -eq 'Error' }).Count
    $lockCheckErrorCount = @($results | Where-Object { $_.Status -eq 'LockCheckError' }).Count

    Write-Host ""
    Write-Host "--- Summary ---" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  i  Total resources evaluated  : $($results.Count)" -ForegroundColor Gray
    Write-Host "  OK Locks applied              : $lockedCount" -ForegroundColor Green
    Write-Host "  i  Already locked (skipped)   : $skippedCount" -ForegroundColor Gray
    Write-Host "  i  Skipped due to -WhatIf     : $whatIfCount" -ForegroundColor Gray
    if ($lockCheckErrorCount -gt 0)
    {
        Write-Host "  !  Skipped (lock-check error) : $lockCheckErrorCount" -ForegroundColor Yellow
    }
    if ($failedCount -gt 0)
    {
        Write-Host "  !  Failed                     : $failedCount" -ForegroundColor Red
    }
    Write-Host ""
    #endregion

    return $results
}

#region ── Entry Point ────────────────────────────────────────────────────────────
if ($MyInvocation.InvocationName -ne '.')
{
    Write-Host ""
    Write-Host "Function 'New-AzureResourceDeleteLock' loaded. Usage examples:" -ForegroundColor DarkGray
    Write-Host "   New-AzureResourceDeleteLock -ResourceType LogicApp -ShowHelp" -ForegroundColor White
    Write-Host "   New-AzureResourceDeleteLock -ResourceType WebApp,FunctionApp" -ForegroundColor White
    Write-Host "   New-AzureResourceDeleteLock -ResourceType LogicApp -ResourceGroupName 'rg-integration' -WhatIf" -ForegroundColor White
    Write-Host "   New-AzureResourceDeleteLock -ResourceType All -WhatIf" -ForegroundColor White
    Write-Host ""
}
#endregion
