<#

Author       : Lakshmanan Thangaraj
Version      : 1.1
Created-On   : 26 May 2026
Modified-On  : 27 July 2026

.SYNOPSIS
    Audits Azure Storage Account SAS tokens, stored access policies, and connection
    strings across one or all subscriptions, then exports a detailed CSV report.

.DESCRIPTION
    Get-AzureStorageAccountSASTokenAudit scans every Storage Account in the target subscription(s),
    inspects:
      - Account-level SAS configuration (allowed services, resource types, permissions,
        expiry bounds, IP restrictions, protocol enforcement)
      - Stored Access Policies on Blob containers, File shares, Queues and Tables
      - Account keys - age, rotation status, and whether access-key auth is enabled
      - Shared-Key / Anonymous-access exposure flags
      - Key Vault secrets that contain storage connection strings (optional)

    Each finding is risk-rated (Critical / High / Medium / Low / Info) and written to
    a timestamped CSV. A structured PSCustomObject array is also returned to the
    pipeline so callers can feed it directly into Generate-SASTokenAuditDashboard.ps1.

    Authentication for per-account policy inspection prefers Azure AD (Entra ID) based
    access via -UseConnectedAccount, falling back to the account key only if that
    fails. This matters for two reasons: it avoids holding a plaintext account key in
    memory when it isn't necessary, and it means accounts that have already disabled
    Shared Key auth (a best practice this tool itself recommends) still get fully
    audited instead of being silently skipped.

.PARAMETER SubscriptionId
    One or more Subscription IDs to audit. Accepts pipeline input.
    Mutually exclusive with -AllSubscriptions.

.PARAMETER AllSubscriptions
    When specified, audits every subscription the authenticated principal can access.
    Mutually exclusive with -SubscriptionId.

.PARAMETER ResourceGroupName
    Optional. Limit the scan to a specific Resource Group.

.PARAMETER StorageAccountName
    Optional. Limit the scan to a single Storage Account. Can be used on its own
    (searches across all accessible accounts) or combined with -ResourceGroupName
    for a direct, targeted lookup.

.PARAMETER IncludeKeyVaultSecrets
    When specified, scans Key Vault secrets in each subscription for connection
    strings that embed storage account keys or SAS tokens. Requires the Az.KeyVault
    module.

.PARAMETER ExpiryWarningDays
    Number of days ahead to flag "Expiring Soon" policies. Default: 30.

.PARAMETER OutputPath
    Full path for the output CSV.
    Defaults to "$env:TEMP\AzSASTokenAudit_<timestamp>.csv".

.PARAMETER OutputJsonPath
    Optional. If supplied, also writes the full result set as JSON to this path.
    Used by Generate-SASTokenAuditDashboard.ps1.

.PARAMETER Force
    Overwrites the output file if it already exists.

.INPUTS
    System.String[]
        One or more Subscription IDs can be piped in (by value or by property name),
        when using the -SubscriptionId parameter set.

.OUTPUTS
    PSCustomObject[]
        One object per finding, including SubscriptionId, ResourceGroup,
        StorageAccount, FindingType, RiskRating, Details, Recommendation, expiry
        fields, and a suggested RemediationCmd. Also written to CSV (-OutputPath)
        and optionally JSON (-OutputJsonPath).

.EXAMPLE
    # Audit all subscriptions, open results in Excel
    Get-AzureStorageAccountSASTokenAudit -AllSubscriptions -OutputPath "C:\Reports\SASAudit.csv"

.EXAMPLE
    # Audit a single subscription with Key Vault secret scanning
    Get-AzureStorageAccountSASTokenAudit `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -IncludeKeyVaultSecrets `
        -ExpiryWarningDays 60

.EXAMPLE
    # Audit specific resource group and pipe results to dashboard generator
    $results = Get-AzureStorageAccountSASTokenAudit `
        -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceGroupName "rg-storage-prod"
    $results | Export-Csv "C:\Reports\SAS.csv" -NoTypeInformation

.EXAMPLE
    # Multiple subscriptions via array
    $subs = @("sub-id-1","sub-id-2","sub-id-3")
    Get-AzureStorageAccountSASTokenAudit -SubscriptionId $subs -OutputPath "C:\Reports\MultiSub.csv"

.EXAMPLE
    # Single named account, searched across all accessible subscriptions/resource groups
    Get-AzureStorageAccountSASTokenAudit -AllSubscriptions -StorageAccountName "prodstorage01"

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.1 (27-Jul-2026) - Security/quality hardening pass:
                         - Per-account context now prefers Azure AD auth
                           (-UseConnectedAccount) over the raw account key, falling
                           back to the key only if AAD access fails - avoids
                           unnecessary key exposure and stops accounts with Shared
                           Key auth already disabled from being silently skipped.
                         - Fixed -StorageAccountName so it works standalone
                           (previously required -ResourceGroupName due to how the
                           underlying cmdlet parameter sets work).
                         - Added an upfront Az.KeyVault dependency check for
                           -IncludeKeyVaultSecrets instead of failing mid-run.
                         - Replaced script-scoped state ($script:Results, etc.)
                           with function-local variables - Begin/Process/End
                           already share one scope, so this was unnecessarily
                           broad and a collision risk if dot-sourced into a module
                           alongside other functions.
                         - Corrected the "Shared Key Auth Enabled" finding wording
                           so it doesn't claim certainty when the underlying
                           property is actually indeterminate ($null).
                         - Fixed $null comparison order (PSScriptAnalyzer
                           PSPossibleIncorrectComparisonWithNull).
                         - Removed the unused -Context parameter from
                           Get-RiskRating.
                         - Lowered #Requires from PS 7.0 to 5.1 - no PS7-only
                           syntax was actually in use, and this widens
                           compatibility to Windows PowerShell environments.
                         - Moved Author block to the top in the repo's standard
                           flat format; added .INPUTS/.OUTPUTS/.LINK.
    1.0 (26-May-2026) - Initial release.
    ─────────────────────────────────────────────────────────────────────────────
    Prerequisites:
    ─────────────────────────────────────────────────────────────────────────────
        Install-Module Az.Accounts, Az.Storage, Az.Resources -Scope CurrentUser
        Install-Module Az.KeyVault -Scope CurrentUser   # only if using -IncludeKeyVaultSecrets

    Required RBAC (minimum, read-only):
        - Storage Account: Reader (account-level properties) plus Storage Blob
          Data Reader / Storage Queue Data Reader / Storage File Data Privileged
          Reader / Storage Table Data Reader for policy inspection via Azure AD
          auth. Falls back to Storage Account Contributor (or equivalent
          key-listing rights) only if Azure AD auth isn't available.
        - Key Vault Reader + Key Vault Secrets User (if -IncludeKeyVaultSecrets)
    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Key Vault secret detection (-IncludeKeyVaultSecrets) uses a name-based
          heuristic (looks for "sas"/"connstr"/etc. in the secret name) - it does
          not inspect secret values, so it can both miss relevant secrets with
          unrelated names and flag unrelated secrets with matching names.
        - RemediationCmd values are suggested commands to review and adapt, not
          to run unattended - always confirm resource names/scope before executing.
        - Does not itself verify or test whether a flagged SAS token is still
          valid/usable - findings are based on policy/configuration state only.

.LINK
    Shared Access Signatures (SAS) overview
    https://learn.microsoft.com/azure/storage/common/storage-sas-overview

.LINK
    Prevent Shared Key authorization for an Azure Storage account
    https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent

#>


Function Get-AzureStorageAccountSASTokenAudit
{
    [CmdletBinding(DefaultParameterSetName = 'BySubscription', SupportsShouldProcess)]
    param (
        [Parameter(ParameterSetName = 'BySubscription', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('SubId')]
        [string[]]$SubscriptionId,

        [Parameter(ParameterSetName = 'AllSubscriptions', Mandatory)]
        [switch]$AllSubscriptions,

        [Parameter()]
        [string]$ResourceGroupName,

        [Parameter()]
        [string]$StorageAccountName,

        [Parameter()]
        [switch]$IncludeKeyVaultSecrets,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$ExpiryWarningDays = 30,

        [Parameter()]
        [string]$OutputPath = "$env:TEMP\AzSASTokenAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

        [Parameter()]
        [string]$OutputJsonPath,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        #region ── Banner ──────────────────────────────────────────────────────────
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║         Azure SAS Token Expiry Auditor  v1.1                 ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        #endregion

        #region ── Output path validation ──────────────────────────────────────────
        $outDir = Split-Path -Path $OutputPath -Parent
        if ($outDir -and -not (Test-Path $outDir)) {
            Write-Verbose "Creating output directory: $outDir"
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }
        if ((Test-Path $OutputPath) -and -not $Force) {
            throw "Output file '$OutputPath' already exists. Use -Force to overwrite."
        }
        #endregion

        #region ── Conditional dependency check ────────────────────────────────────
        if ($IncludeKeyVaultSecrets -and -not (Get-Module -ListAvailable -Name Az.KeyVault)) {
            throw "-IncludeKeyVaultSecrets requires the Az.KeyVault module. Install it with: Install-Module Az.KeyVault -Scope CurrentUser"
        }
        #endregion

        #region ── Authentication check ────────────────────────────────────────────
        Write-Host "  🔐  Checking authentication…" -ForegroundColor Cyan
        try {
            $ctx = Get-AzContext -ErrorAction Stop
            if (-not $ctx -or -not $ctx.Account) {
                Write-Host "  ⚠   No active Azure session found. Prompting for login…" -ForegroundColor Yellow
                Connect-AzAccount -ErrorAction Stop | Out-Null
                $ctx = Get-AzContext
            }
            Write-Host "  ✅  Authenticated as: $($ctx.Account.Id)" -ForegroundColor Green
            Write-Host "  ✅  Tenant          : $($ctx.Tenant.Id)" -ForegroundColor Green
        }
        catch {
            Write-Host "  ❌  Authentication failed: $_" -ForegroundColor Red
            throw
        }
        #endregion

        #region ── Shared state (function-local - Begin/Process/End share one scope) ─
        $Now      = Get-Date
        $Results  = [System.Collections.Generic.List[PSCustomObject]]::new()
        $Counters = @{ Total=0; Critical=0; High=0; Medium=0; Low=0; Info=0; Errors=0 }
        $SubscriptionsToAudit = @()
        #endregion

        #region ── Shared helpers ──────────────────────────────────────────────────
        function Write-Log {
            param([string]$Message, [string]$Level = 'INFO')
            $ts = Get-Date -Format 'HH:mm:ss'
            $col = switch ($Level) {
                'INFO'    { 'Cyan'    }
                'SUCCESS' { 'Green'   }
                'WARN'    { 'Yellow'  }
                'ERROR'   { 'Red'     }
                default   { 'White'   }
            }
            Write-Host "  [$ts] [$Level] $Message" -ForegroundColor $col
        }

        function Get-RiskRating {
            param([string]$Category)
            switch ($Category) {
                'NoExpiry'              { return 'Critical' }
                'KeyAuthEnabled'        { return 'High'     }
                'AnonymousAccess'       { return 'High'     }
                'SharedKeyDisabled'     { return 'Info'     }
                'Expired'               { return 'Critical' }
                'ExpiringSoon'          { return 'High'     }
                'LongExpiry'            { return 'Medium'   }
                'NoIPRestriction'       { return 'Medium'   }
                'HTTPAllowed'           { return 'High'     }
                'NoStoredPolicy'        { return 'Medium'   }
                'OldKey'                { return 'Medium'   }
                'KeyVaultSASSecret'     { return 'High'     }
                'KeyVaultConnString'    { return 'Medium'   }
                default                 { return 'Info'     }
            }
        }

        function New-Finding {
            param(
                [string]$SubscriptionId,
                [string]$SubscriptionName,
                [string]$ResourceGroup,
                [string]$StorageAccount,
                [string]$Location,
                [string]$Sku,
                [string]$FindingType,
                [string]$Scope,          # Account | Container | Share | Queue | Table | KeyVault
                [string]$ScopeName,
                [string]$PolicyName,
                [string]$RiskRating,
                [string]$Details,
                [string]$Recommendation,
                [datetime]$ExpiryDate    = [datetime]::MinValue,
                [int]$DaysUntilExpiry    = -999,
                [string]$AllowedServices = '',
                [string]$AllowedPermissions = '',
                [string]$IPRange         = '',
                [string]$Protocol        = '',
                [bool]$IsRevocable       = $false,
                [string]$RemediationCmd  = ''
            )

            $Counters['Total']++
            if ($Counters.ContainsKey($RiskRating)) { $Counters[$RiskRating]++ }

            $expiryStr = if ($ExpiryDate -ne [datetime]::MinValue) { $ExpiryDate.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }
            $daysStr   = if ($DaysUntilExpiry -ne -999)            { $DaysUntilExpiry }                            else { 'N/A' }

            return [PSCustomObject]@{
                AuditTimestamp      = $Now.ToString('yyyy-MM-dd HH:mm:ss')
                SubscriptionId      = $SubscriptionId
                SubscriptionName    = $SubscriptionName
                ResourceGroup       = $ResourceGroup
                StorageAccount      = $StorageAccount
                Location            = $Location
                Sku                 = $Sku
                FindingType         = $FindingType
                Scope               = $Scope
                ScopeName           = $ScopeName
                PolicyName          = $PolicyName
                RiskRating          = $RiskRating
                Details             = $Details
                Recommendation      = $Recommendation
                ExpiryDate          = $expiryStr
                DaysUntilExpiry     = $daysStr
                AllowedServices     = $AllowedServices
                AllowedPermissions  = $AllowedPermissions
                IPRange             = $IPRange
                Protocol            = $Protocol
                IsRevocable         = $IsRevocable
                RemediationCmd      = $RemediationCmd
            }
        }
        #endregion
    }

    process {
        # Collect subscription IDs — will be deduplicated and processed in end{}
        if ($PSCmdlet.ParameterSetName -eq 'BySubscription') {
            $SubscriptionsToAudit += $SubscriptionId
        }
    }

    end {
        #region ── Resolve subscriptions ───────────────────────────────────────────
        if ($AllSubscriptions) {
            Write-Log "Retrieving all accessible subscriptions…"
            $allSubs = Get-AzSubscription -ErrorAction Stop
            $SubscriptionsToAudit = @($allSubs | Select-Object -ExpandProperty Id)
            Write-Log "Found $($SubscriptionsToAudit.Count) subscription(s)" 'SUCCESS'
        }

        $SubscriptionsToAudit = @($SubscriptionsToAudit | Select-Object -Unique)

        if ($SubscriptionsToAudit.Count -eq 0) {
            Write-Log "No subscriptions to audit." 'WARN'
            return
        }
        #endregion

        #region ── Per-subscription loop ───────────────────────────────────────────
        foreach ($subId in $SubscriptionsToAudit) {

            Write-Host ""
            Write-Log "━━━ Subscription: $subId ━━━"

            try {
                $sub = Set-AzContext -SubscriptionId $subId -ErrorAction Stop
                $subName = $sub.Subscription.Name
                Write-Log "Switched context → $subName" 'SUCCESS'
            }
            catch {
                Write-Log "Cannot switch to subscription $subId : $_" 'ERROR'
                $Counters['Errors']++
                continue
            }

            #region ── Get storage accounts ────────────────────────────────────────
            # -StorageAccountName works standalone (searched/filtered client-side)
            # or combined with -ResourceGroupName for a direct, targeted lookup -
            # Get-AzStorageAccount itself requires both Name and ResourceGroupName
            # together, so we branch rather than always passing both/neither.
            try {
                if ($ResourceGroupName -and $StorageAccountName) {
                    $storageAccounts = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
                }
                elseif ($ResourceGroupName) {
                    $storageAccounts = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
                }
                else {
                    $storageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
                    if ($StorageAccountName) {
                        $storageAccounts = @($storageAccounts | Where-Object { $_.StorageAccountName -eq $StorageAccountName })
                    }
                }
            }
            catch {
                Write-Log "Failed to list Storage Accounts in $subId : $_" 'ERROR'
                $Counters['Errors']++
                continue
            }

            if (-not $storageAccounts) {
                Write-Log "No storage accounts found in $subName" 'WARN'
                continue
            }

            Write-Log "Found $($storageAccounts.Count) storage account(s) in $subName"
            #endregion

            foreach ($sa in $storageAccounts) {

                $saName = $sa.StorageAccountName
                $rgName = $sa.ResourceGroupName
                $loc    = $sa.PrimaryLocation
                $sku    = $sa.Sku.Name

                Write-Log "  → Auditing: $saName ($rgName)"

                # ── Get storage context - prefer Azure AD auth, fall back to the
                #    account key only if that fails. Avoids holding the raw key
                #    unnecessarily, and ensures accounts with Shared Key auth
                #    already disabled still get fully audited.
                $saContext = $null
                try {
                    $saContext = New-AzStorageContext -StorageAccountName $saName -UseConnectedAccount -ErrorAction Stop
                }
                catch {
                    Write-Log "    ⚠ Azure AD context failed for $saName ($($_.Exception.Message)) - falling back to account key." 'WARN'
                    try {
                        $keys = Get-AzStorageAccountKey -ResourceGroupName $rgName -Name $saName -ErrorAction Stop
                        $saContext = New-AzStorageContext -StorageAccountName $saName -StorageAccountKey $keys[0].Value -ErrorAction Stop
                        Remove-Variable -Name keys -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Log "    ⚠ Cannot get storage keys for $saName either (RBAC may restrict): $_" 'WARN'
                    }
                }

                # ─────────────────────────────────────────────────────────────────
                # CHECK 1 — Shared Key / Anonymous access flags
                # ─────────────────────────────────────────────────────────────────
                $allowSharedKey  = $sa.AllowSharedKeyAccess
                $allowBlobPublic = $sa.AllowBlobPublicAccess

                if ($null -eq $allowSharedKey -or $allowSharedKey -eq $true) {
                    $Results.Add((New-Finding `
                        -SubscriptionId     $subId `
                        -SubscriptionName   $subName `
                        -ResourceGroup      $rgName `
                        -StorageAccount     $saName `
                        -Location           $loc `
                        -Sku                $sku `
                        -FindingType        'SharedKey Auth Enabled' `
                        -Scope              'Account' `
                        -ScopeName          $saName `
                        -PolicyName         'N/A' `
                        -RiskRating         (Get-RiskRating 'KeyAuthEnabled') `
                        -Details            'Shared Key authentication is enabled or its status could not be confirmed. If enabled, any client holding the account key can generate arbitrary SAS tokens with full permissions and no expiry.' `
                        -Recommendation     'Disable Shared Key auth via: Set-AzStorageAccount -ResourceGroupName "<rg>" -Name "<sa>" -AllowSharedKeyAccess $false. Use Azure AD (Entra ID) auth with managed identities instead.' `
                        -RemediationCmd     "Set-AzStorageAccount -ResourceGroupName '$rgName' -Name '$saName' -AllowSharedKeyAccess `$false"
                    ))
                }

                if ($allowBlobPublic -eq $true) {
                    $Results.Add((New-Finding `
                        -SubscriptionId     $subId `
                        -SubscriptionName   $subName `
                        -ResourceGroup      $rgName `
                        -StorageAccount     $saName `
                        -Location           $loc `
                        -Sku                $sku `
                        -FindingType        'Anonymous Blob Access Allowed' `
                        -Scope              'Account' `
                        -ScopeName          $saName `
                        -PolicyName         'N/A' `
                        -RiskRating         (Get-RiskRating 'AnonymousAccess') `
                        -Details            'AllowBlobPublicAccess is enabled. Individual containers may be set to anonymous/public, allowing unauthenticated read access without any SAS token.' `
                        -Recommendation     'Disable anonymous access: Set-AzStorageAccount -ResourceGroupName "<rg>" -Name "<sa>" -AllowBlobPublicAccess $false' `
                        -RemediationCmd     "Set-AzStorageAccount -ResourceGroupName '$rgName' -Name '$saName' -AllowBlobPublicAccess `$false"
                    ))
                }

                # ─────────────────────────────────────────────────────────────────
                # CHECK 2 — Account key age (rotation hygiene)
                # ─────────────────────────────────────────────────────────────────
                try {
                    $keyCreationTimes = $sa.KeyCreationTime
                    if ($keyCreationTimes) {
                        foreach ($keyProp in @('Key1', 'Key2')) {
                            $keyDate = $keyCreationTimes.$keyProp
                            if ($keyDate) {
                                $ageDays = ($Now - $keyDate).Days
                                if ($ageDays -gt 90) {
                                    $Results.Add((New-Finding `
                                        -SubscriptionId     $subId `
                                        -SubscriptionName   $subName `
                                        -ResourceGroup      $rgName `
                                        -StorageAccount     $saName `
                                        -Location           $loc `
                                        -Sku                $sku `
                                        -FindingType        "Stale Account Key ($keyProp)" `
                                        -Scope              'Account' `
                                        -ScopeName          $saName `
                                        -PolicyName         $keyProp `
                                        -RiskRating         (Get-RiskRating 'OldKey') `
                                        -Details            "$keyProp was last rotated $ageDays days ago (on $($keyDate.ToString('yyyy-MM-dd'))). Keys older than 90 days increase the blast radius of any credential exposure." `
                                        -Recommendation     'Rotate storage account keys every 90 days. Store keys in Key Vault and configure automatic rotation. Command: New-AzStorageAccountKey -ResourceGroupName "<rg>" -Name "<sa>" -KeyName "<key1|key2>"' `
                                        -DaysUntilExpiry    (0 - $ageDays) `
                                        -RemediationCmd     "New-AzStorageAccountKey -ResourceGroupName '$rgName' -Name '$saName' -KeyName '$($keyProp.ToLower())'"
                                    ))
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Log "    ⚠ Could not read key creation times for $saName" 'WARN'
                }

                # Skip stored-policy checks if we could not get a storage context
                if (-not $saContext) {
                    Write-Log "    ⚠ Skipping policy checks for $saName (no storage context)" 'WARN'
                    continue
                }

                # ─────────────────────────────────────────────────────────────────
                # CHECK 3 — Blob Container Stored Access Policies
                # ─────────────────────────────────────────────────────────────────
                try {
                    $containers = Get-AzStorageContainer -Context $saContext -ErrorAction SilentlyContinue
                    foreach ($container in $containers) {
                        $policies = Get-AzStorageContainerStoredAccessPolicy `
                                        -Container $container.Name `
                                        -Context   $saContext `
                                        -ErrorAction SilentlyContinue

                        if (-not $policies) {
                            # Containers with no stored access policies mean any SAS
                            # issued against them cannot be revoked before key rotation
                            $Results.Add((New-Finding `
                                -SubscriptionId     $subId `
                                -SubscriptionName   $subName `
                                -ResourceGroup      $rgName `
                                -StorageAccount     $saName `
                                -Location           $loc `
                                -Sku                $sku `
                                -FindingType        'No Stored Access Policy' `
                                -Scope              'Container' `
                                -ScopeName          $container.Name `
                                -PolicyName         'N/A' `
                                -RiskRating         (Get-RiskRating 'NoStoredPolicy') `
                                -Details            "Container '$($container.Name)' has no Stored Access Policy. SAS tokens issued without a policy cannot be revoked (except by rotating the account key), making them irrevocable until expiry." `
                                -Recommendation     'Create a Stored Access Policy for each container, then issue SAS tokens linked to the policy. This enables instant revocation without key rotation.' `
                                -IsRevocable        $false `
                                -RemediationCmd     "New-AzStorageContainerStoredAccessPolicy -Container '$($container.Name)' -Context `$saContext -Policy 'read-policy' -Permission 'r' -ExpiryTime (Get-Date).AddDays(90)"
                            ))
                            continue
                        }

                        foreach ($pol in $policies) {
                            $expiry     = $pol.SharedAccessExpiryTime
                            $daysLeft   = if ($expiry) { [int]($expiry - $Now).TotalDays } else { -999 }
                            $permission = $pol.Permissions

                            # No expiry set
                            if (-not $expiry) {
                                $Results.Add((New-Finding `
                                    -SubscriptionId     $subId `
                                    -SubscriptionName   $subName `
                                    -ResourceGroup      $rgName `
                                    -StorageAccount     $saName `
                                    -Location           $loc `
                                    -Sku                $sku `
                                    -FindingType        'Policy Without Expiry' `
                                    -Scope              'Container' `
                                    -ScopeName          $container.Name `
                                    -PolicyName         $pol.Id `
                                    -RiskRating         (Get-RiskRating 'NoExpiry') `
                                    -Details            "Stored Access Policy '$($pol.Id)' on container '$($container.Name)' has NO expiry date. SAS tokens referencing this policy will never expire unless the policy is deleted." `
                                    -Recommendation     'Always set an expiry date on Stored Access Policies. Maximum recommended lifetime is 1 year; prefer 90 days for sensitive data.' `
                                    -AllowedPermissions $permission `
                                    -IsRevocable        $true `
                                    -RemediationCmd     "Set-AzStorageContainerStoredAccessPolicy -Container '$($container.Name)' -Context `$saContext -Policy '$($pol.Id)' -ExpiryTime (Get-Date).AddDays(90)"
                                ))
                            }
                            # Already expired
                            elseif ($daysLeft -lt 0) {
                                $Results.Add((New-Finding `
                                    -SubscriptionId     $subId `
                                    -SubscriptionName   $subName `
                                    -ResourceGroup      $rgName `
                                    -StorageAccount     $saName `
                                    -Location           $loc `
                                    -Sku                $sku `
                                    -FindingType        'Expired Policy' `
                                    -Scope              'Container' `
                                    -ScopeName          $container.Name `
                                    -PolicyName         $pol.Id `
                                    -RiskRating         (Get-RiskRating 'Expired') `
                                    -Details            "Stored Access Policy '$($pol.Id)' expired on $($expiry.ToString('yyyy-MM-dd')) ($([Math]::Abs($daysLeft)) days ago). Expired policies should be removed to maintain a clean, auditable posture." `
                                    -Recommendation     'Remove expired policies promptly. If still needed, recreate with a fresh expiry. Implement policy lifecycle alerts.' `
                                    -ExpiryDate         $expiry `
                                    -DaysUntilExpiry    $daysLeft `
                                    -AllowedPermissions $permission `
                                    -IsRevocable        $true `
                                    -RemediationCmd     "Remove-AzStorageContainerStoredAccessPolicy -Container '$($container.Name)' -Context `$saContext -Policy '$($pol.Id)'"
                                ))
                            }
                            # Expiring within warning window
                            elseif ($daysLeft -le $ExpiryWarningDays) {
                                $Results.Add((New-Finding `
                                    -SubscriptionId     $subId `
                                    -SubscriptionName   $subName `
                                    -ResourceGroup      $rgName `
                                    -StorageAccount     $saName `
                                    -Location           $loc `
                                    -Sku                $sku `
                                    -FindingType        'Policy Expiring Soon' `
                                    -Scope              'Container' `
                                    -ScopeName          $container.Name `
                                    -PolicyName         $pol.Id `
                                    -RiskRating         (Get-RiskRating 'ExpiringSoon') `
                                    -Details            "Stored Access Policy '$($pol.Id)' expires in $daysLeft day(s) on $($expiry.ToString('yyyy-MM-dd')). All SAS tokens referencing this policy will stop working at expiry." `
                                    -Recommendation     "Renew the policy before $($expiry.ToString('yyyy-MM-dd')). Consider using rolling policies with overlapping validity windows." `
                                    -ExpiryDate         $expiry `
                                    -DaysUntilExpiry    $daysLeft `
                                    -AllowedPermissions $permission `
                                    -IsRevocable        $true `
                                    -RemediationCmd     "Set-AzStorageContainerStoredAccessPolicy -Container '$($container.Name)' -Context `$saContext -Policy '$($pol.Id)' -ExpiryTime (Get-Date).AddDays(90)"
                                ))
                            }
                            # Very long expiry (> 1 year)
                            elseif ($daysLeft -gt 365) {
                                $Results.Add((New-Finding `
                                    -SubscriptionId     $subId `
                                    -SubscriptionName   $subName `
                                    -ResourceGroup      $rgName `
                                    -StorageAccount     $saName `
                                    -Location           $loc `
                                    -Sku                $sku `
                                    -FindingType        'Excessive Policy Lifetime' `
                                    -Scope              'Container' `
                                    -ScopeName          $container.Name `
                                    -PolicyName         $pol.Id `
                                    -RiskRating         (Get-RiskRating 'LongExpiry') `
                                    -Details            "Stored Access Policy '$($pol.Id)' expires in $daysLeft days ($($expiry.ToString('yyyy-MM-dd'))). Policies valid for over 1 year represent a prolonged exposure window." `
                                    -Recommendation     'Shorten policy lifetime to 90–180 days maximum. Implement automated renewal via Azure Automation.' `
                                    -ExpiryDate         $expiry `
                                    -DaysUntilExpiry    $daysLeft `
                                    -AllowedPermissions $permission `
                                    -IsRevocable        $true
                                ))
                            }
                        }
                    }
                }
                catch {
                    Write-Log "    ⚠ Error reading containers for $saName : $_" 'WARN'
                }

                # ─────────────────────────────────────────────────────────────────
                # CHECK 4 — File Share Stored Access Policies
                # ─────────────────────────────────────────────────────────────────
                try {
                    if ($sa.Kind -ne 'BlobStorage') {
                        $shares = Get-AzStorageShare -Context $saContext -ErrorAction SilentlyContinue
                        foreach ($share in $shares) {
                            $policies = Get-AzStorageShareStoredAccessPolicy `
                                            -ShareName $share.Name `
                                            -Context   $saContext `
                                            -ErrorAction SilentlyContinue

                            foreach ($pol in $policies) {
                                $expiry   = $pol.SharedAccessExpiryTime
                                $daysLeft = if ($expiry) { [int]($expiry - $Now).TotalDays } else { -999 }

                                if (-not $expiry) {
                                    $Results.Add((New-Finding `
                                        -SubscriptionId     $subId `
                                        -SubscriptionName   $subName `
                                        -ResourceGroup      $rgName `
                                        -StorageAccount     $saName `
                                        -Location           $loc `
                                        -Sku                $sku `
                                        -FindingType        'File Share Policy Without Expiry' `
                                        -Scope              'FileShare' `
                                        -ScopeName          $share.Name `
                                        -PolicyName         $pol.Id `
                                        -RiskRating         'Critical' `
                                        -Details            "File Share Stored Access Policy '$($pol.Id)' on share '$($share.Name)' has no expiry. Indefinite SAS tokens can be used to exfiltrate all file share content." `
                                        -Recommendation     'Set an expiry date on all File Share policies. For SMB lift-and-shift workloads, prefer Azure AD Kerberos authentication over SAS.' `
                                        -AllowedPermissions $pol.Permissions `
                                        -IsRevocable        $true `
                                        -RemediationCmd     "Set-AzStorageShareStoredAccessPolicy -ShareName '$($share.Name)' -Context `$saContext -Policy '$($pol.Id)' -ExpiryTime (Get-Date).AddDays(90)"
                                    ))
                                }
                                elseif ($daysLeft -lt 0) {
                                    $Results.Add((New-Finding `
                                        -SubscriptionId     $subId `
                                        -SubscriptionName   $subName `
                                        -ResourceGroup      $rgName `
                                        -StorageAccount     $saName `
                                        -Location           $loc `
                                        -Sku                $sku `
                                        -FindingType        'Expired File Share Policy' `
                                        -Scope              'FileShare' `
                                        -ScopeName          $share.Name `
                                        -PolicyName         $pol.Id `
                                        -RiskRating         'Critical' `
                                        -Details            "File Share policy '$($pol.Id)' expired $([Math]::Abs($daysLeft)) days ago. Remove or renew immediately." `
                                        -Recommendation     'Remove expired file share policies. Implement lifecycle management alerts via Azure Monitor.' `
                                        -ExpiryDate         $expiry `
                                        -DaysUntilExpiry    $daysLeft `
                                        -IsRevocable        $true `
                                        -RemediationCmd     "Remove-AzStorageShareStoredAccessPolicy -ShareName '$($share.Name)' -Context `$saContext -Policy '$($pol.Id)'"
                                    ))
                                }
                                elseif ($daysLeft -le $ExpiryWarningDays) {
                                    $Results.Add((New-Finding `
                                        -SubscriptionId     $subId `
                                        -SubscriptionName   $subName `
                                        -ResourceGroup      $rgName `
                                        -StorageAccount     $saName `
                                        -Location           $loc `
                                        -Sku                $sku `
                                        -FindingType        'File Share Policy Expiring Soon' `
                                        -Scope              'FileShare' `
                                        -ScopeName          $share.Name `
                                        -PolicyName         $pol.Id `
                                        -RiskRating         'High' `
                                        -Details            "File Share policy '$($pol.Id)' expires in $daysLeft day(s) on $($expiry.ToString('yyyy-MM-dd'))." `
                                        -Recommendation     "Renew the policy before $($expiry.ToString('yyyy-MM-dd')). Consider rolling renewals." `
                                        -ExpiryDate         $expiry `
                                        -DaysUntilExpiry    $daysLeft `
                                        -IsRevocable        $true `
                                        -RemediationCmd     "Set-AzStorageShareStoredAccessPolicy -ShareName '$($share.Name)' -Context `$saContext -Policy '$($pol.Id)' -ExpiryTime (Get-Date).AddDays(90)"
                                    ))
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Log "    ⚠ Error reading file shares for $saName : $_" 'WARN'
                }

                # ─────────────────────────────────────────────────────────────────
                # CHECK 5 — Queue Stored Access Policies
                # ─────────────────────────────────────────────────────────────────
                try {
                    $queues = Get-AzStorageQueue -Context $saContext -ErrorAction SilentlyContinue
                    foreach ($queue in $queues) {
                        $policies = Get-AzStorageQueueStoredAccessPolicy `
                                        -Queue   $queue.Name `
                                        -Context $saContext `
                                        -ErrorAction SilentlyContinue

                        foreach ($pol in $policies) {
                            $expiry   = $pol.SharedAccessExpiryTime
                            $daysLeft = if ($expiry) { [int]($expiry - $Now).TotalDays } else { -999 }

                            if (-not $expiry) {
                                $Results.Add((New-Finding `
                                    -SubscriptionId     $subId `
                                    -SubscriptionName   $subName `
                                    -ResourceGroup      $rgName `
                                    -StorageAccount     $saName `
                                    -Location           $loc `
                                    -Sku                $sku `
                                    -FindingType        'Queue Policy Without Expiry' `
                                    -Scope              'Queue' `
                                    -ScopeName          $queue.Name `
                                    -PolicyName         $pol.Id `
                                    -RiskRating         'Critical' `
                                    -Details            "Queue Stored Access Policy '$($pol.Id)' on queue '$($queue.Name)' has no expiry date." `
                                    -Recommendation     'Set expiry on all queue policies. Process queue messages via managed identity instead of SAS where possible.' `
                                    -AllowedPermissions $pol.Permissions `
                                    -IsRevocable        $true `
                                    -RemediationCmd     "Set-AzStorageQueueStoredAccessPolicy -Queue '$($queue.Name)' -Context `$saContext -Policy '$($pol.Id)' -ExpiryTime (Get-Date).AddDays(90)"
                                ))
                            }
                            elseif ($daysLeft -lt 0 -or $daysLeft -le $ExpiryWarningDays) {
                                $rt = if ($daysLeft -lt 0) { 'Critical' } else { 'High' }
                                $Results.Add((New-Finding `
                                    -SubscriptionId     $subId `
                                    -SubscriptionName   $subName `
                                    -ResourceGroup      $rgName `
                                    -StorageAccount     $saName `
                                    -Location           $loc `
                                    -Sku                $sku `
                                    -FindingType        $(if ($daysLeft -lt 0) {'Expired Queue Policy'} else {'Queue Policy Expiring Soon'}) `
                                    -Scope              'Queue' `
                                    -ScopeName          $queue.Name `
                                    -PolicyName         $pol.Id `
                                    -RiskRating         $rt `
                                    -Details            "Queue policy '$($pol.Id)' on '$($queue.Name)': $(if($daysLeft -lt 0){"expired $([Math]::Abs($daysLeft)) days ago"}else{"expires in $daysLeft day(s)"})." `
                                    -Recommendation     'Renew or remove expired/expiring queue policies immediately.' `
                                    -ExpiryDate         $expiry `
                                    -DaysUntilExpiry    $daysLeft `
                                    -IsRevocable        $true
                                ))
                            }
                        }
                    }
                }
                catch {
                    Write-Log "    ⚠ Error reading queues for $saName : $_" 'WARN'
                }

                # ─────────────────────────────────────────────────────────────────
                # CHECK 6 — Table Stored Access Policies
                # ─────────────────────────────────────────────────────────────────
                try {
                    $tables = Get-AzStorageTable -Context $saContext -ErrorAction SilentlyContinue
                    foreach ($table in $tables) {
                        $policies = Get-AzStorageTableStoredAccessPolicy `
                                        -Table   $table.Name `
                                        -Context $saContext `
                                        -ErrorAction SilentlyContinue

                        foreach ($pol in $policies) {
                            $expiry   = $pol.SharedAccessExpiryTime
                            $daysLeft = if ($expiry) { [int]($expiry - $Now).TotalDays } else { -999 }

                            if (-not $expiry) {
                                $Results.Add((New-Finding `
                                    -SubscriptionId     $subId `
                                    -SubscriptionName   $subName `
                                    -ResourceGroup      $rgName `
                                    -StorageAccount     $saName `
                                    -Location           $loc `
                                    -Sku                $sku `
                                    -FindingType        'Table Policy Without Expiry' `
                                    -Scope              'Table' `
                                    -ScopeName          $table.Name `
                                    -PolicyName         $pol.Id `
                                    -RiskRating         'Critical' `
                                    -Details            "Table Stored Access Policy '$($pol.Id)' on table '$($table.Name)' has no expiry date." `
                                    -Recommendation     'Set expiry on all table policies. Prefer managed identity authentication for table access.' `
                                    -AllowedPermissions $pol.Permissions `
                                    -IsRevocable        $true
                                ))
                            }
                        }
                    }
                }
                catch {
                    Write-Log "    ⚠ Error reading tables for $saName : $_" 'WARN'
                }

            } # end foreach storage account

            # ─────────────────────────────────────────────────────────────────────
            # CHECK 7 — Key Vault secrets containing connection strings / SAS tokens
            # ─────────────────────────────────────────────────────────────────────
            if ($IncludeKeyVaultSecrets) {
                Write-Log "  Scanning Key Vaults for storage secrets in $subName…"
                try {
                    $kvs = Get-AzKeyVault -ErrorAction SilentlyContinue
                    foreach ($kv in $kvs) {
                        try {
                            $secrets = Get-AzKeyVaultSecret -VaultName $kv.VaultName -ErrorAction SilentlyContinue
                            foreach ($secret in $secrets) {
                                $sName = $secret.Name.ToLower()
                                $isConnStr = $sName -match 'connstr|connection.string|storageconn|azure.storage'
                                $isSAS     = $sName -match 'sas|sharedaccess|sastoken'
                                if ($isConnStr -or $isSAS) {
                                    $expiry   = $secret.Expires
                                    $daysLeft = if ($expiry) { [int]($expiry - $Now).TotalDays } else { -999 }
                                    $rt       = if ($isSAS) { Get-RiskRating 'KeyVaultSASSecret' } else { Get-RiskRating 'KeyVaultConnString' }

                                    $Results.Add((New-Finding `
                                        -SubscriptionId     $subId `
                                        -SubscriptionName   $subName `
                                        -ResourceGroup      $kv.ResourceGroupName `
                                        -StorageAccount     'Key Vault Secret' `
                                        -Location           $kv.Location `
                                        -Sku                'KeyVault' `
                                        -FindingType        $(if ($isSAS) {'SAS Token in Key Vault'} else {'Connection String in Key Vault'}) `
                                        -Scope              'KeyVault' `
                                        -ScopeName          $kv.VaultName `
                                        -PolicyName         $secret.Name `
                                        -RiskRating         $rt `
                                        -Details            "Secret '$($secret.Name)' in Key Vault '$($kv.VaultName)' appears to contain a $(if($isSAS){'SAS token'}else{'storage connection string (which embeds account keys)'}).$(if($expiry){" Secret expiry: $($expiry.ToString('yyyy-MM-dd')). Days until expiry: $daysLeft."}else{' Secret has no expiry set.'})" `
                                        -Recommendation     $(if ($isSAS) {'Rotate SAS token and update secret. Prefer Managed Identity over SAS in applications. Ensure secret has an expiry matching the SAS token lifetime.'} else {'Replace connection string authentication with Managed Identity. If connection strings are required, enable automatic secret rotation via Key Vault rotation policy.'}) `
                                        -ExpiryDate         $(if ($expiry) { $expiry } else { [datetime]::MinValue }) `
                                        -DaysUntilExpiry    $(if ($expiry) { $daysLeft } else { -999 }) `
                                        -IsRevocable        $true
                                    ))
                                }
                            }
                        }
                        catch {
                            Write-Log "    ⚠ Cannot read secrets from Key Vault '$($kv.VaultName)': $_" 'WARN'
                        }
                    }
                }
                catch {
                    Write-Log "  ⚠ Could not enumerate Key Vaults in $subName : $_" 'WARN'
                }
            }

        } # end foreach subscription

        #region ── Export results ───────────────────────────────────────────────────
        Write-Host ""
        Write-Log "━━━ Exporting Results ━━━"

        if ($Results.Count -gt 0) {
            $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
            Write-Log "CSV exported → $OutputPath" 'SUCCESS'

            if ($OutputJsonPath) {
                $Results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputJsonPath -Encoding UTF8 -Force
                Write-Log "JSON exported → $OutputJsonPath" 'SUCCESS'
            }
        }
        else {
            Write-Log "No findings to export — all storage accounts passed all checks! ✅" 'SUCCESS'
        }
        #endregion

        #region ── Summary ─────────────────────────────────────────────────────────
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║                      Audit Summary                           ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  📊  Total Findings    : $($Counters['Total'])"   -ForegroundColor White
        Write-Host "  🔴  Critical          : $($Counters['Critical'])" -ForegroundColor Red
        Write-Host "  🟠  High              : $($Counters['High'])"     -ForegroundColor DarkYellow
        Write-Host "  🟡  Medium            : $($Counters['Medium'])"   -ForegroundColor Yellow
        Write-Host "  🟢  Low               : $($Counters['Low'])"      -ForegroundColor Green
        Write-Host "  🔵  Info              : $($Counters['Info'])"     -ForegroundColor Cyan
        Write-Host "  ❌  Errors (skipped)  : $($Counters['Errors'])"   -ForegroundColor DarkRed
        Write-Host ""
        Write-Host "  📁  Output            : $OutputPath" -ForegroundColor White
        Write-Host ""
        #endregion

        # Return results to pipeline
        return $Results
    }
}
