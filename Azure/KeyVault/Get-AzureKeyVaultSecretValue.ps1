<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 28 August 2024
Modified-On     : 03 May 2026

.SYNOPSIS
    Retrieves a secret value from Azure Key Vault using either UserAccount or Managed Identity authentication.

.DESCRIPTION
    The Get-AzureKeyVaultSecretValue function retrieves a secret from Azure Key Vault based on the
    specified authentication method.

    It supports two authentication types:
        - UserAccount (interactive Azure login)
        - ManagedIdentity (Azure resource-based identity)

    The function performs the following operations:
        - Validates the Az PowerShell module installation, offering to install it if missing
        - Authenticates to Azure using the selected authentication method
        - Ensures valid Azure context when using UserAccount authentication
        - Retrieves a secret value from Azure Key Vault
        - Handles errors related to authentication and secret retrieval
        - Returns the secret in plain text format

.PARAMETER VaultName
    Specifies the name of the Azure Key Vault from which the secret will be retrieved.

.PARAMETER SecretName
    Specifies the name of the secret stored in the Key Vault.

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
    System.String
        Returns the secret value as plain text if retrieval is successful.
        Returns $null if the secret cannot be retrieved.

.EXAMPLE
    Get-AzureKeyVaultSecretValue -VaultName "MyKeyVault" -SecretName "MySecret" -AuthenticationType ManagedIdentity

    Retrieves a secret from Key Vault using Managed Identity authentication.

.EXAMPLE
    Get-AzureKeyVaultSecretValue -VaultName "MyKeyVault" -SecretName "MySecret" -AuthenticationType UserAccount -TenantId "xxxx-xxxx" -SubscriptionId "xxxx-xxxx"

    Retrieves a secret using interactive UserAccount authentication.

.EXAMPLE
    $secret = Get-AzureKeyVaultSecretValue -VaultName "MyKeyVault" -SecretName "AppSecret" -AuthenticationType ManagedIdentity

    Stores the retrieved secret in a variable for further use.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (28-Aug-2024)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (installed automatically on first run if missing,
            with user confirmation).
        2. Appropriate Key Vault access permissions (Get Secret permission).
        3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Check for the Az module; offer to install it if missing
        Step 2  →  Authenticate via UserAccount (interactive) or ManagedIdentity
        Step 3  →  Retrieve the secret from Key Vault via Get-AzKeyVaultSecret
        Step 4  →  Return the secret as plain text, or $null on failure

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Returns the secret as plain text in memory; caller is responsible for
            handling it securely (avoid writing to logs, console history, etc.).
        - UserAccount authentication is interactive and not suitable for
            unattended automation; use ManagedIdentity for that scenario.
        - Declining the Az module installation prompt, or a module install
            failure, calls Exit — this will terminate the entire calling script/
            session, not just this function.

.LINK
    Key Vault quickstart (PowerShell)
    https://learn.microsoft.com/azure/key-vault/secrets/quick-create-powershell

.LINK
    Get-AzKeyVaultSecret reference
    https://learn.microsoft.com/powershell/module/az.keyvault/get-azkeyvaultsecret

#>


Function Get-AzureKeyVaultSecretValue
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $true)]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [string]$SecretName,
        
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
        
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Retrieving secret '$SecretName' from Key Vault '$VaultName'..." -ForegroundColor Yellow
        
        # Retrieve the secret from Key Vault
        $secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -AsPlainText -WarningAction SilentlyContinue
        if ($null -eq $secret) 
        {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Secret retrieval failed. Please check the VaultName, SecretName, and permissions." -ForegroundColor Red
            return $null
        }
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Secret retrieved successfully." -ForegroundColor Green
        return $secret
    }
    catch 
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Failed to retrieve the client secret from Key Vault. Details: $_" -ForegroundColor Red
        return $null
    }
}
