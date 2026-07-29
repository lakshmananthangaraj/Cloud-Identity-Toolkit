<#

Author       : Lakshmanan Thangaraj
Version      : 2.0
Created-On   : 11 February 2026
Modified-On  : 29 July 2026

.SYNOPSIS
    Audits Azure RBAC role assignments across one or more subscriptions,
    with optional filtering to assignments scoped to Azure Key Vault.

.DESCRIPTION
    Get-AzureKeyVaultRBACAssignments retrieves Azure Role-Based Access
    Control (RBAC) role assignments across all subscriptions the caller
    has access to, or a specific list of subscription IDs. It can
    optionally restrict results to assignments scoped directly at an
    Azure Key Vault resource, and can export the collected data to CSV
    for audit, governance, or least-privilege review purposes.

    The function is designed to run unattended in automation (via
    -Force and -NoGridView) as well as interactively, and degrades
    gracefully on hosts where Out-GridView is not available (PowerShell 7+
    without the graphical tools module, Azure Cloud Shell, SSH sessions,
    CI/CD runners, or non-Windows hosts).

    NOTE ON SENSITIVE DATA: the output and any exported CSV contain
    personally identifiable information (display names and sign-in
    names of users, groups, and service principals). Treat exported
    files as containing PII: store them in an access-controlled
    location and delete them once the audit/report cycle is complete.

.PARAMETER SubscriptionIds
    One or more specific Azure subscription IDs (GUIDs) to audit.
    Mutually exclusive with -AllSubscriptions.

.PARAMETER CsvPath
    Full path (including file name, must end in .csv) to write the
    exported report to when -ExportToCsv is used. Defaults to a file
    named 'AzureRBACAssignments-Report.csv' in the current user's
    temp directory, which works cross-platform (Windows/macOS/Linux).
    The parent folder is created automatically if it does not exist.

.PARAMETER AllSubscriptions
    Audit every subscription the currently authenticated account can
    see. This is the default behavior if neither this switch nor
    -SubscriptionIds is supplied. Mutually exclusive with
    -SubscriptionIds.

.PARAMETER KeyVaultOnly
    Restrict results to role assignments whose Scope path contains
    '/providers/Microsoft.KeyVault/vaults/'. See Known Limitations
    regarding inherited assignments this will not catch.

.PARAMETER ExportToCsv
    Export the collected role assignments to the path in -CsvPath.

.PARAMETER NoGridView
    Skip the interactive Out-GridView window even if it is available
    on this host. Recommended for unattended/automation runs.

.PARAMETER Force
    Suppress the interactive Az module install confirmation prompt
    and proceed with installation automatically if the required Az
    sub-modules are missing. Recommended for unattended/automation
    runs.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    [PSCustomObject] — one object per role assignment, with the
    properties: SubscriptionName, SubscriptionId, TenantId,
    DisplayName, SignInName, ObjectType, RoleDefinitionName, Scope.

.EXAMPLE
    Get-AzureKeyVaultRBACAssignments -AllSubscriptions

    Audits RBAC assignments across every subscription visible to the
    current account and displays them in an interactive grid (if
    available).

.EXAMPLE
    Get-AzureKeyVaultRBACAssignments -SubscriptionIds "11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222" -KeyVaultOnly

    Audits only Key Vault-scoped RBAC assignments in the two specified
    subscriptions.

.EXAMPLE
    Get-AzureKeyVaultRBACAssignments -AllSubscriptions -ExportToCsv -CsvPath "D:\Audits\KeyVaultRBAC.csv" -NoGridView -Force -Verbose

    Runs unattended (no install prompt, no grid view), exports full
    results to CSV, and emits verbose diagnostic logging.

.EXAMPLE
    $results = Get-AzureKeyVaultRBACAssignments -AllSubscriptions -KeyVaultOnly -NoGridView
    $results | Where-Object { $_.RoleDefinitionName -eq 'Owner' }

    Captures the returned objects in a variable for further filtering
    or reporting in your own scripts, rather than relying on the grid
    view or CSV export.

.NOTES
    ────────────────────────────────────────────────────────────────
    VERSION HISTORY
    ────────────────────────────────────────────────────────────────
    CHANGELOG:
        v2.0 - 29 Jul 2026 - Major rewrite prior to public release:
                                - Fixed install-confirmation logic bug that always
                                evaluated to true regardless of user input.
                                - Replaced Exit calls with terminating errors (Exit was
                                killing the entire host session, not just the function).
                                - Replaced hardcoded 'C:\Temp' default CSV path with a
                                cross-platform temp-directory path.
                                - Made Out-GridView usage conditional/optional so the
                                script no longer fails on PowerShell 7+, Cloud Shell,
                                SSH sessions, or non-Windows hosts; added -NoGridView.
                                - Replaced coarse 'Az' umbrella module check with targeted
                                checks for Az.Accounts and Az.Resources.
                                - Added -Force for unattended module installation.
                                - Added GUID validation on -SubscriptionIds and made
                                -AllSubscriptions / -SubscriptionIds mutually exclusive
                                parameter sets.
                                - Added CsvPath validation (must end in .csv; parent
                                folder created automatically).
                                - Added try/catch around all external calls (module
                                install, Connect-AzAccount, CSV export).
                                - Added [CmdletBinding()], -Verbose diagnostic logging,
                                and full comment-based help per current standards.
                                - Function now returns the collected objects to the
                                pipeline in addition to optional grid view/CSV export.
                                - Documented PII handling considerations for exported data.
        v1.0 - 11 Feb 2026 - Initial release.

    ────────────────────────────────────────────────────────────────
    PRE-REQUISITES
    ────────────────────────────────────────────────────────────────
    - PowerShell 5.1, or PowerShell 7+ (cross-platform).
    - Az.Accounts and Az.Resources modules (the function will offer
        to install them if missing, unless -Force is used to skip the
        prompt).
    - An Azure account with at least the Reader role at the
        subscription level, and permission to read
        Microsoft.Authorization/roleAssignments/read.
    - For the interactive grid view: Out-GridView, which is built in
        to Windows PowerShell 5.1, but on PowerShell 7+ requires the
        separate 'Microsoft.PowerShell.GraphicalTools' module and a
        graphical session. The function detects its absence and skips
        the grid view automatically rather than failing.

    ────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ────────────────────────────────────────────────────────────────
    1. Validate parameter set (AllSubscriptions vs SubscriptionIds)
        and CsvPath (if exporting).
    2. Verify Az.Accounts and Az.Resources are installed; offer to
        install them (or install automatically if -Force is used).
    3. Verify/establish an authenticated Azure session.
    4. Resolve the target list of subscriptions.
    5. For each subscription: set context, retrieve role assignments,
        optionally filter to Key Vault scope, normalize into report
        objects. Failures on one subscription are logged as warnings
        and do not stop the run.
    6. Display results in Out-GridView if available and not suppressed.
    7. Export to CSV if requested.
    8. Return the full collected object set to the pipeline.

    ────────────────────────────────────────────────────────────────
    KNOWN LIMITATIONS
    ────────────────────────────────────────────────────────────────
    - -KeyVaultOnly matches assignments whose Scope string contains
        '/providers/Microsoft.KeyVault/vaults/'. It will NOT catch role
        assignments made at a higher scope (management group,
        subscription, or resource group) that also happen to grant
        effective access to a Key Vault — those won't contain the
        Key Vault resource path in their own Scope property. Treat
        -KeyVaultOnly as "assignments made directly on a vault," not
        "everyone with any access to a vault."
    - Classic (co-)administrators are not included; only Azure RBAC
        role assignments are returned.
    - No retry/backoff logic for Azure Resource Manager throttling.
        Very large tenants with many subscriptions may need to be
        chunked via -SubscriptionIds if throttled.
    - The function does not itself verify the caller's permission
        level in advance; insufficient permissions on a given
        subscription surface as a per-subscription warning rather than
        a pre-flight check.

    ────────────────────────────────────────────────────────────────
    SECURITY NOTE
    ────────────────────────────────────────────────────────────────
    No credentials, secrets, or tenant-specific identifiers are
    hardcoded in this script. Exported CSV files contain personally
    identifiable information (names/sign-in names) — handle and store
    them accordingly.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azroleassignment

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.accounts/connect-azaccount

.LINK
    https://learn.microsoft.com/en-us/azure/role-based-access-control/overview

#>


Function Get-AzureKeyVaultRBACAssignments
{
    
    [CmdletBinding(DefaultParameterSetName = 'AllSubscriptions')]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'SpecificSubscriptions')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string[]]$SubscriptionIds,

        [ValidateScript({
            if ($_ -notmatch '\.csv$')
            {
                throw "CsvPath must end with a '.csv' extension."
            }
            $true
        })]
        [string]$CsvPath = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'AzureRBACAssignments-Report.csv'),

        [Parameter(ParameterSetName = 'AllSubscriptions')]
        [switch]$AllSubscriptions,

        [switch]$KeyVaultOnly,

        [switch]$ExportToCsv,

        [switch]$NoGridView,

        [switch]$Force
    )

    #------------------------------------------------------------------ [ Step 1: Verify required Az sub-modules ]
    $requiredModules = @('Az.Accounts', 'Az.Resources')
    $missingModules = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missingModules)
    {
        Write-Host "The following required modules are not installed: $($missingModules -join ', ')" -ForegroundColor Yellow

        $shouldInstall = $Force

        if (-not $Force)
        {
            $installAz = Read-Host "Would you like to install them now? (Y/N)"
            $shouldInstall = $installAz -match '^[Yy]$'
        }

        if ($shouldInstall)
        {
            try
            {
                Write-Host "Installing missing modules, please wait..." -ForegroundColor Yellow
                Install-Module -Name $missingModules -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module -Name $missingModules -ErrorAction Stop
                Write-Host "Required modules installed and imported successfully." -ForegroundColor Green
            }
            catch
            {
                throw "Failed to install/import required modules ($($missingModules -join ', ')): $_"
            }
        }
        else
        {
            throw "Module installation declined. This function cannot proceed without $($missingModules -join ', ')."
        }
    }
    else
    {
        Write-Verbose "All required modules (Az.Accounts, Az.Resources) are already installed."
    }

    #------------------------------------------------------------------ [ Step 2: Validate/prepare CSV export path ]
    if ($ExportToCsv)
    {
        $csvFolder = Split-Path -Path $CsvPath -Parent
        if ($csvFolder -and -not (Test-Path -Path $csvFolder))
        {
            try
            {
                Write-Verbose "Creating output folder: $csvFolder"
                New-Item -Path $csvFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            catch
            {
                throw "Unable to create the output folder '$csvFolder' for -CsvPath: $_"
            }
        }
    }

    $allRoleAssignments = @()

    #------------------------------------------------------------------ [ Step 3: Ensure an authenticated session ]
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext)
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] No active session found. Prompting for authentication..." -ForegroundColor Yellow
        try
        {
            Connect-AzAccount -WarningAction Ignore -ErrorAction Stop | Out-Null
        }
        catch
        {
            throw "Failed to authenticate to Azure: $_"
        }
    }
    else
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Active session found. Proceeding with the following current context..." -ForegroundColor Green
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $($currentContext.Name) - $($currentContext.Environment.Name)" -ForegroundColor Cyan
    }

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Fetching Azure RBAC role assignments..." -ForegroundColor Green

    #------------------------------------------------------------------ [ Step 4: Resolve target subscriptions ]
    if ($PSCmdlet.ParameterSetName -eq 'SpecificSubscriptions')
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Processing specific subscriptions..." -ForegroundColor Yellow
        $subscriptions = Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $SubscriptionIds -contains $_.Id }

        $foundIds = $subscriptions.Id
        $notFound = $SubscriptionIds | Where-Object { $foundIds -notcontains $_ }
        if ($notFound)
        {
            Write-Warning "The following subscription ID(s) were not found or are not accessible: $($notFound -join ', ')"
        }
    }
    else
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Processing all subscriptions..." -ForegroundColor Yellow
        $subscriptions = Get-AzSubscription -WarningAction SilentlyContinue
    }

    $subscriptionCount = @($subscriptions).Count
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Total subscriptions processing: $subscriptionCount" -ForegroundColor Green

    if ($subscriptionCount -eq 0)
    {
        Write-Warning "No accessible subscriptions found for the specified criteria. Nothing to process."
        return
    }

    #------------------------------------------------------------------ [ Step 5: Collect role assignments per subscription ]
    $subscriptionIndex = 1

    foreach ($sub in $subscriptions)
    {
        try
        {
            $progressPercent = [math]::Round(($subscriptionIndex / $subscriptionCount) * 100)
            Write-Progress -Activity "Processing Subscriptions" -Status "$subscriptionIndex of $subscriptionCount" -PercentComplete $progressPercent

            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Processing subscription-$($subscriptionIndex) : $($sub.Name)" -ForegroundColor Cyan
            Write-Verbose "Setting context to subscription '$($sub.Name)' ($($sub.Id))"

            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue -InformationAction SilentlyContinue -ErrorAction Stop | Out-Null

            $roleAssignments = Get-AzRoleAssignment -ErrorAction Stop

            if ($KeyVaultOnly)
            {
                $roleAssignments = $roleAssignments | Where-Object {
                    $_.Scope -like "*/providers/Microsoft.KeyVault/vaults/*"
                }
            }

            $allRoleAssignments += $roleAssignments | ForEach-Object {
                [pscustomobject]@{
                    SubscriptionName   = $sub.Name
                    SubscriptionId     = $sub.Id
                    TenantId           = $sub.TenantId
                    DisplayName        = $_.DisplayName
                    SignInName         = $_.SignInName
                    ObjectType         = $_.ObjectType
                    RoleDefinitionName = $_.RoleDefinitionName
                    Scope              = $_.Scope
                }
            }
        }
        catch
        {
            Write-Warning "[$(Get-Date -Format 'HH:mm:ss')] Failed to retrieve role assignments for subscription '$($sub.Name)' ($($sub.Id)). Error: $_"
        }
        finally
        {
            $subscriptionIndex++
        }
    }

    Write-Progress -Activity "Processing Subscriptions" -Completed

    #------------------------------------------------------------------ [ Step 6 & 7: Present / export results ]
    if ($allRoleAssignments.Count -gt 0)
    {
        $gridViewAvailable = -not $NoGridView -and (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue)

        if ($gridViewAvailable)
        {
            $allRoleAssignments | Out-GridView -Title "Azure RBAC Role Assignments"
        }
        elseif (-not $NoGridView)
        {
            Write-Verbose "Out-GridView is not available on this host (common on PowerShell 7+ without Microsoft.PowerShell.GraphicalTools, Cloud Shell, SSH, or CI runners). Skipping interactive grid view."
        }

        if ($ExportToCsv)
        {
            try
            {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Exporting results to CSV: $CsvPath" -ForegroundColor Yellow
                $allRoleAssignments | Export-Csv -Path $CsvPath -NoTypeInformation -ErrorAction Stop
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Export completed successfully. Note: this file contains personal data (names/sign-in names) - store and share it accordingly." -ForegroundColor Green
            }
            catch
            {
                Write-Warning "[$(Get-Date -Format 'HH:mm:ss')] Failed to export CSV to '$CsvPath'. Error: $_"
            }
        }
    }
    else
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] No role assignments found across the specified subscriptions." -ForegroundColor Green
    }

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Processing of Azure RBAC role assignments completed successfully." -ForegroundColor Green

    return $allRoleAssignments
}
