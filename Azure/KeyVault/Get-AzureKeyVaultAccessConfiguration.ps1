<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 21 August 2025
Modified-On  : 11 February 2026

.SYNOPSIS
    Audits Azure Key Vault access configuration across one or more
    subscriptions, classifying each vault as RBAC-based or ACL-based
    and surfacing any legacy access policies that remain on
    RBAC-enabled vaults.

.DESCRIPTION
    Get-AzureKeyVaultAccessConfiguration scans Azure Key Vaults across all
    subscriptions the caller has access to, or a caller-specified list
    of subscription IDs or names. For every vault discovered it
    determines the active access model (RBAC authorization vs. legacy
    Access Policy / ACL-based), extracts the individual access-policy
    entries for ACL-based vaults, and flags any residual access
    policies found on RBAC-enabled vaults (which are inactive but
    still visible and may cause confusion during audits).

    At the end of each run the function prints a summary to the host
    showing total vaults discovered, the RBAC vs. ACL split as counts
    and percentages, and the number of RBAC vaults that still carry
    legacy (inactive) access policies.

    This function is intended for Key Vault governance, security
    auditing, and migration assessments from Access Policies to
    RBAC-based access control.

    Results can optionally be exported to a CSV file for further
    analysis or audit records.

.PARAMETER AllSubscriptions
    Scan Key Vaults across every subscription visible to the currently
    authenticated account. Mutually exclusive with
    -SpecificSubscriptions.

.PARAMETER SpecificSubscriptions
    One or more subscription IDs (GUIDs) or subscription display names
    to target. The function attempts to resolve each entry first by ID
    and then by name, and emits a warning for any entry it cannot
    locate. Mutually exclusive with -AllSubscriptions.

.PARAMETER ExportCsv
    Full path (including file name) to write a CSV export of the
    collected vault access configuration records. When omitted, no
    file is written. The parent directory must already exist.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    [PSCustomObject] — one object per vault access-policy entry (or
    one object per vault for RBAC-based vaults), with the properties:
    SubscriptionName, SubscriptionId, KeyVaultName, ResourceGroup,
    Location, ResourceId, VaultUri, RbacAuthorizationEnabled,
    AccessType, AccessPolicyUser, PermissionsKeys, PermissionsSecrets,
    PermissionsCertificates, PermissionsStorage.

.EXAMPLE
    Get-AzureKeyVaultAccessConfiguration -AllSubscriptions

    Scans all accessible subscriptions and prints an access
    configuration summary for every Key Vault discovered.

.EXAMPLE
    Get-AzureKeyVaultAccessConfiguration -SpecificSubscriptions "sub-id-1","sub-id-2"

    Scans only the two named subscriptions, resolving each entry by
    ID or display name.

.EXAMPLE
    Get-AzureKeyVaultAccessConfiguration -AllSubscriptions -ExportCsv "C:\Temp\KeyVaultReport.csv"

    Scans all subscriptions and exports the full results to the
    specified CSV file in addition to printing the summary.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (21-Aug-2025) - Initial release.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Az.Accounts module (the function installs it automatically if absent).
    2. Az.KeyVault module (the function installs it automatically if absent).
    3. An active Azure login session. The function calls Connect-AzAccount
       automatically if no session is detected.
    4. At least the Reader role at the subscription level and permission to
       read Microsoft.KeyVault/vaults/read on the target vaults.

    ─────────────────────────────────────────────────────────────────────────────
    Execution Flow:
    ─────────────────────────────────────────────────────────────────────────────
    1. Verify that the Az.KeyVault module is available; install if missing.
    2. Verify or establish an authenticated Azure session.
    3. Resolve the target list of subscriptions from -AllSubscriptions or
       -SpecificSubscriptions.
    4. For each subscription: set context, enumerate Key Vaults, re-fetch each
       vault with full properties to obtain access policy and RBAC flag details,
       and emit one result object per access-policy entry (ACL-based vaults) or
       one result object per vault (RBAC-based / empty vaults).
    5. Export results to CSV if -ExportCsv is supplied.
    6. Print a summary to the host: subscription count, vault count, RBAC vs.
       ACL split, and RBAC vaults carrying legacy (inactive) access policies.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Access policy entries are only enumerated on ACL-based vaults
      (EnableRbacAuthorization = $false). On RBAC-enabled vaults the individual
      policy entries are not expanded — only a vault-level row is emitted.
    - Legacy access policies that remain on RBAC-enabled vaults are detected at
      the vault level (counted in the summary) but their individual permission
      entries are not written to the results collection.
    - The function does not verify the caller's effective permissions on each
      subscription in advance; insufficient permissions surface as empty vault
      lists rather than explicit errors.
    - No retry or back-off logic is included for Azure Resource Manager
      throttling. Very large tenants with many subscriptions may need to be
      processed in smaller batches via -SpecificSubscriptions.
    - Classic co-administrators are not reflected; only Azure RBAC and legacy
      Key Vault access policies are in scope.

.LINK
    https://learn.microsoft.com/en-us/azure/key-vault/general/

.LINK
    https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide

.LINK
    https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.keyvault/get-azkeyvault

#>


Function Get-AzureKeyVaultAccessConfiguration
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [switch]$AllSubscriptions,

        [Parameter(Mandatory=$false)]
        [string[]]$SpecificSubscriptions,

        [Parameter(Mandatory=$false)]
        [string]$ExportCsv
    )

    #------------------------------------------------------------------ [ Step 1: Verify required Az sub-modules ]
    if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) 
    {
        Write-Host "Az.KeyVault module not found. Installing..." -ForegroundColor Yellow
        Install-Module -Name Az.KeyVault -Scope CurrentUser -Force
        Import-Module Az.KeyVault -Force
    }

    #------------------------------------------------------------------ [ Step 2: Ensure an authenticated session ]
    try 
    {
        $context = Get-AzContext
        if (-not $context) 
        {
            Write-Host "You are not logged in. Connecting to Azure..." -ForegroundColor Yellow
            Connect-AzAccount -ErrorAction Stop -WarningAction Ignore
        }
    }
    catch 
    {
        Write-Error "Failed to authenticate to Azure. Please check your account and try again."
        return
    }

    #------------------------------------------------------------------ [ Step 3: Resolve target subscriptions ]
    $subscriptions = @()

    if ($AllSubscriptions) 
    {
        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue -WarningAction Ignore
    }
    elseif ($SpecificSubscriptions) 
    {
        # Build the list first…
        $subscriptions = foreach ($sub in $SpecificSubscriptions) 
        {
            try 
            {
                $s = Get-AzSubscription -SubscriptionId $sub -ErrorAction SilentlyContinue -WarningAction Ignore
                if (-not $s) { $s = Get-AzSubscription -SubscriptionName $sub -ErrorAction SilentlyContinue -WarningAction Ignore }
                $s   # emit either the found subscription or $null
            }
            catch 
            {
                Write-Warning "Subscription '$sub' not found or not accessible."
            }
        }

        # …then filter out nulls
        $subscriptions = $subscriptions | Where-Object { $_ -ne $null }
    }
    else 
    {
        Write-Warning "Please specify either -AllSubscriptions or -SpecificSubscriptions."
        return
    }

    #------------------------------------------------------------------ [ Step 4: Collect vault access configuration per subscription ]
    $results = @()

    $totalSubscriptions = @($subscriptions).Count
    $currentIndex = 0

    Write-Host "Processing $totalSubscriptions subscription(s)..." -ForegroundColor Green

    foreach ($sub in $subscriptions) 
    {
        $currentIndex++

        Set-AzContext -SubscriptionId $sub.Id -WarningAction Ignore | Out-Null

        Write-Host "Checking Subscription [$currentIndex/$totalSubscriptions] : $($sub.Name)" -ForegroundColor Cyan

        $keyVaults = Get-AzKeyVault
        foreach ($kv in $keyVaults) 
        {
            # Re-fetch vault with full properties to include AccessPolicies and config
            $kvDetails = Get-AzKeyVault -ResourceGroupName $kv.ResourceGroupName -VaultName $kv.VaultName
            
            $isRbacEnabled = [bool]$kvDetails.EnableRbacAuthorization

            $accessPolicies = $kvDetails.AccessPolicies

            if (-not $isRbacEnabled -and $accessPolicies -and $accessPolicies.Count -gt 0)
            {
                foreach ($policy in $accessPolicies) {
                    $results += [PSCustomObject]@{
                        SubscriptionName         = $sub.Name
                        SubscriptionId           = $sub.Id
                        KeyVaultName             = $kv.VaultName
                        ResourceGroup            = $kv.ResourceGroupName
                        Location                 = $kv.Location
                        ResourceId               = $kvDetails.ResourceId
                        VaultUri                 = $kvDetails.VaultUri
                        RbacAuthorizationEnabled = $kvDetails.EnableRbacAuthorization
                        AccessType               = if ($isRbacEnabled) { "RBAC-Based" } else { "ACL-Based" }
                        AccessPolicyUser         = if ($policy.DisplayName) { $policy.DisplayName } else { $policy.ObjectId }
                        PermissionsKeys          = ($policy.PermissionsToKeys -join ", ")
                        PermissionsSecrets       = ($policy.PermissionsToSecrets -join ", ")
                        PermissionsCertificates  = ($policy.PermissionsToCertificates -join ", ")
                        PermissionsStorage       = ($policy.PermissionsToStorage -join ", ")
                    }
                }
            }
            else 
            {
                $results += [PSCustomObject]@{
                    SubscriptionName          = $sub.Name
                    SubscriptionId            = $sub.Id
                    KeyVaultName              = $kv.VaultName
                    ResourceGroup             = $kv.ResourceGroupName
                    Location                  = $kv.Location
                    ResourceId                = $kvDetails.ResourceId
                    VaultUri                  = $kvDetails.VaultUri
                    RbacAuthorizationEnabled  = $kvDetails.EnableRbacAuthorization
                    AccessType                = if ($isRbacEnabled) { "RBAC-Based" } else { "ACL-Based" }
                    AccessPolicyUser          = ""
                    PermissionsKeys           = ""
                    PermissionsSecrets        = ""
                    PermissionsCertificates   = ""
                    PermissionsStorage        = ""
                }
            }
        }
    }

    #------------------------------------------------------------------ [ Step 5: Export to CSV if requested ]
    if ($ExportCsv) {
        try {
            $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Force
            Write-Host "Results exported to $ExportCsv" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to export results to CSV. Error: $_"
        }
    }

    #------------------------------------------------------------------ [ Step 6: Print summary ]
    Write-Host "`n========== Key Vault Access Configuration Summary ==========" -ForegroundColor Green

    $totalVaults = @($results | Select-Object -ExpandProperty KeyVaultName -Unique).Count
    $rbacVaults  = @($results | Where-Object { $_.AccessType -eq "RBAC-Based" } | Select-Object -ExpandProperty KeyVaultName -Unique).Count
    $aclVaults   = @($results | Where-Object { $_.AccessType -eq "ACL-Based" } | Select-Object -ExpandProperty KeyVaultName -Unique).Count

    $rbacPercent = if ($totalVaults -gt 0) { [math]::Round(($rbacVaults / $totalVaults) * 100, 2) } else { 0 }
    $aclPercent  = if ($totalVaults -gt 0) { [math]::Round(($aclVaults / $totalVaults) * 100, 2) } else { 0 }

    Write-Host ("Subscriptions Scanned : {0}" -f $totalSubscriptions) -ForegroundColor Cyan
    Write-Host ("Key Vaults Discovered : {0}" -f $totalVaults) -ForegroundColor Cyan

    Write-Host ("RBAC-Based Vaults     : {0} ({1}%)" -f $rbacVaults, $rbacPercent) -ForegroundColor Green
    Write-Host ("ACL-Based Vaults      : {0} ({1}%)" -f $aclVaults, $aclPercent) -ForegroundColor Yellow

    # Legacy Access Policies on RBAC vaults
    $legacyPolicyVaults = $results |
        Where-Object {
            $_.RbacAuthorizationEnabled -eq $true -and
            $_.AccessPolicyUser -ne ""
        } |
        Select-Object -ExpandProperty KeyVaultName -Unique

    if (@($legacyPolicyVaults).Count -gt 0) 
    {
        Write-Host ("RBAC Vaults with Legacy Access Policies (Inactive) : {0}" -f $legacyPolicyVaults.Count) -ForegroundColor Red
    }
    else 
    {
        Write-Host "RBAC Vaults with Legacy Access Policies (Inactive) : 0" -ForegroundColor Green
    }

    Write-Host "=============================================================`n" -ForegroundColor Green
}
