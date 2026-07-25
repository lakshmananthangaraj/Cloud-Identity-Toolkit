<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 25 July 2026
Modified-On     : 25 July 2026

.SYNOPSIS
    Removes (soft-deletes) a secret from Azure Key Vault using either UserAccount or Managed Identity authentication.

.DESCRIPTION
    The Remove-AzureKeyVaultSecret function deletes a secret from Azure Key Vault based on the
    specified authentication method.

    By default, Azure Key Vault soft-deletes secrets: the secret moves into a recoverable
    "deleted" state for the vault's configured retention period rather than being permanently
    destroyed. This function reflects that behavior by default. An optional -PurgePermanently
    switch is available to immediately and permanently purge the secret afterward, if the
    vault's purge-protection setting allows it — this is irreversible.

    It supports two authentication types:
        - UserAccount (interactive Azure login)
        - ManagedIdentity (Azure resource-based identity)

    The function performs the following operations:
        - Validates the Az PowerShell module installation, offering to install it if missing
        - Authenticates to Azure using the selected authentication method
        - Ensures valid Azure context when using UserAccount authentication
        - Prompts for confirmation before deleting (unless -Force is specified)
        - Removes (soft-deletes) the secret from Azure Key Vault
        - Optionally purges the secret permanently if -PurgePermanently is specified
        - Handles errors related to authentication and secret removal

.PARAMETER VaultName
    Specifies the name of the Azure Key Vault from which the secret will be removed.

.PARAMETER SecretName
    Specifies the name of the secret to remove from the Key Vault.

.PARAMETER Force
    Suppresses the interactive confirmation prompt before removing the secret.
    Intended for automation scenarios; use with care.

.PARAMETER PurgePermanently
    Optional. After soft-deleting the secret, immediately and permanently purges it,
    bypassing the vault's soft-delete retention period. This is IRREVERSIBLE and only
    succeeds if the vault does not have purge protection enabled. Triggers its own
    separate confirmation prompt (also suppressed by -Force).

.PARAMETER AuthenticationType
    Specifies the authentication method used to access Azure Key Vault.

    Valid values:
        - UserAccount
        - ManagedIdentity

.PARAMETER TenantId
    Specifies the Azure Active Directory Tenant ID.
    Required only when AuthenticationType is set to UserAccount.

.PARAMETER SubscriptionId
    Specifies the Azure Subscription ID.
    Required only when AuthenticationType is set to UserAccount.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Boolean
        Returns $true if the secret was successfully removed (and purged, if requested).
        Returns $false if removal fails or is cancelled by the user.

.EXAMPLE
    Remove-AzureKeyVaultSecret -VaultName "MyKeyVault" -SecretName "OldClientSecret" -AuthenticationType ManagedIdentity

    Soft-deletes a secret using Managed Identity authentication, after confirmation.

.EXAMPLE
    Remove-AzureKeyVaultSecret -VaultName "MyKeyVault" -SecretName "OldClientSecret" -AuthenticationType UserAccount -TenantId "xxxx-xxxx" -SubscriptionId "xxxx-xxxx" -Force

    Soft-deletes a secret using interactive UserAccount authentication, skipping confirmation.

.EXAMPLE
    Remove-AzureKeyVaultSecret -VaultName "MyKeyVault" -SecretName "OldClientSecret" -AuthenticationType ManagedIdentity -PurgePermanently

    Soft-deletes and then permanently purges the secret (irreversible; requires
    separate confirmation and no purge protection on the vault).

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (25-Jul-2026)  - Initial release, built to match Get-AzureKeyVaultSecretValue
                              template, authentication logic, and console output style

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (installed automatically on first run if missing,
            with user confirmation).
        2. Appropriate Key Vault access permissions (Delete Secret permission;
            Purge Secret permission additionally required for -PurgePermanently).
        3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Check for the Az module; offer to install it if missing
        Step 2  →  Authenticate via UserAccount (interactive) or ManagedIdentity
        Step 3  →  Confirm deletion (unless -Force), then soft-delete via
                    Remove-AzKeyVaultSecret
        Step 4  →  If -PurgePermanently, confirm and permanently purge via
                    Remove-AzKeyVaultSecret -InRemovedState
        Step 5  →  Return $true/$false based on outcome

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Default behavior is SOFT-DELETE, not permanent deletion. The secret
            remains recoverable (via Undo-AzKeyVaultSecretRemoval or similar)
            during the vault's retention period unless -PurgePermanently is used.
        - -PurgePermanently fails if the vault has purge protection enabled — by
            design, Azure does not allow bypassing purge protection.
        - -Force suppresses BOTH the removal confirmation and the purge
            confirmation; use deliberately in automation, not as a default habit.
        - UserAccount authentication is interactive and not suitable for
            unattended automation; use ManagedIdentity for that scenario.
        - Declining the Az module installation prompt, or a module install
            failure, calls Exit — this will terminate the entire calling script/
            session, not just this function.

.LINK
    Key Vault quickstart (PowerShell)
    https://learn.microsoft.com/azure/key-vault/secrets/quick-create-powershell

.LINK
    Remove-AzKeyVaultSecret reference
    https://learn.microsoft.com/powershell/module/az.keyvault/remove-azkeyvaultsecret

#>


Function Remove-AzureKeyVaultSecret
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $true)]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [string]$SecretName,

        [switch]$Force,

        [switch]$PurgePermanently,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("UserAccount", "ManagedIdentity")]
        [string]$AuthenticationType,
        
        # Only required if AuthenticationType is UserAccount
        [string]$TenantId,
        
        # Only required if AuthenticationType is UserAccount
        [string]$SubscriptionId
    )

    # Check if the Az module is installed
    if (-not (Get-Module -ListAvailable -Name Az)) 
    {
        Write-Host "Az module is not installed on this system." -ForegroundColor Yellow
        $installAz = Read-Host "Would you like to install the Az module now? (Y/N)"
    
        if ($installAz -eq 'Y' -or $installAz -eq 'y') 
        {
            try 
            {
                Write-Host "Installing the Az module on this system, please wait...." -ForegroundColor Yellow
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "Az module has been successfully installed and imported." -ForegroundColor Green
            } 
            catch 
            {
                Write-Host "Error installing and importing Az module: $_" -ForegroundColor Red
                Exit
            }
        } 
        else 
        {
            Write-Host "Az module installation declined. The script cannot proceed without the Az module." -ForegroundColor Yellow
            Exit
        }
    } 
    else 
    {
        Write-Host "Az module is already installed." -ForegroundColor Cyan
    }

    try 
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting authentication process..." -ForegroundColor Yellow

        # Authentication based on the specified AuthenticationType
        if ($AuthenticationType -eq "UserAccount") 
        {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Authenticating as UserAccount..." -ForegroundColor Cyan
            if (-not $TenantId -or -not $SubscriptionId) 
            {
                throw "TenantId and SubscriptionId are required when using UserAccount authentication."
            }
            
            # Check for an active session and prompt for authentication if none is found
            $currentContext = Get-AzContext -ErrorAction SilentlyContinue
            
            if (-not $currentContext) 
            {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] No active session found. Prompting for authentication..." -ForegroundColor Yellow
                Connect-AzAccount -TenantId $TenantId -SubscriptionId $SubscriptionId -WarningAction Ignore
                Set-AzContext -Subscription $SubscriptionId -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
            }
            else
            {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Active session found. Proceeding with the following current context..." -ForegroundColor Green
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $($currentContext.Name) - $($currentContext.Environment.Name)" -ForegroundColor Cyan
            }
            
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] UserAccount authentication successful." -ForegroundColor Green
        }
        elseif ($AuthenticationType -eq "ManagedIdentity") 
        {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Authenticating as Managed Identity..." -ForegroundColor Cyan
            Connect-AzAccount -Identity -WarningAction Ignore
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Managed Identity authentication successful." -ForegroundColor Green
        }

        # Confirm before soft-deleting, unless -Force was specified
        if (-not $Force)
        {
            $confirmRemove = Read-Host "Are you sure you want to remove secret '$SecretName' from vault '$VaultName'? (Y/N)"
            if ($confirmRemove -ne 'Y' -and $confirmRemove -ne 'y')
            {
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Removal cancelled by user." -ForegroundColor Yellow
                return $false
            }
        }

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Removing (soft-deleting) secret '$SecretName' from Key Vault '$VaultName'..." -ForegroundColor Yellow

        # Soft-delete the secret
        Remove-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -Force -WarningAction SilentlyContinue -ErrorAction Stop

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Secret removed (soft-deleted) successfully." -ForegroundColor Green

        # Optionally purge permanently
        if ($PurgePermanently)
        {
            if (-not $Force)
            {
                $confirmPurge = Read-Host "This will PERMANENTLY purge '$SecretName' and cannot be undone. Continue? (Y/N)"
                if ($confirmPurge -ne 'Y' -and $confirmPurge -ne 'y')
                {
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Purge cancelled by user. Secret remains soft-deleted." -ForegroundColor Yellow
                    return $true
                }
            }

            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Purging secret '$SecretName' permanently..." -ForegroundColor Yellow
            Remove-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -InRemovedState -Force -WarningAction SilentlyContinue -ErrorAction Stop
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Secret purged permanently." -ForegroundColor Green
        }

        return $true
    }
    catch 
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Failed to remove the secret from Key Vault. Details: $_" -ForegroundColor Red
        return $false
    }
}
