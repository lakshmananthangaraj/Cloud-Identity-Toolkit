<#

Author          : Lakshmanan Thangaraj
Version         : 1.1
Created-On      : 25 July 2026
Modified-On     : 25 July 2026

.SYNOPSIS
    Creates or updates a secret value in Azure Key Vault using either UserAccount or Managed Identity authentication.

.DESCRIPTION
    The New-AzureKeyVaultSecret function creates a new secret, or updates an existing secret's
    value, in Azure Key Vault based on the specified authentication method.

    Because Azure Key Vault's underlying Set-AzKeyVaultSecret operation is idempotent, calling
    this function with a SecretName that already exists in the vault creates a new version of
    that secret rather than failing — this function is effectively "create or update."

    It supports two authentication types:
        - UserAccount (interactive Azure login)
        - ManagedIdentity (Azure resource-based identity)

    The function performs the following operations:
        - Validates the Az PowerShell module installation, offering to install it if missing
        - Authenticates to Azure using the selected authentication method
        - Ensures valid Azure context when using UserAccount authentication
        - Converts the supplied plain-text secret value to a SecureString
        - Creates or updates the secret in Azure Key Vault
        - Handles errors related to authentication and secret creation
        - Returns the resulting secret's metadata (name and version)
    
    Some environments enforce an Azure Policy requiring all Key Vault secrets to
    have an expiration date (e.g. the built-in "Key Vault secrets should have an
    expiration date" policy). If your vault/subscription enforces this, use the
    optional -ExpiresInDays parameter to satisfy it; otherwise the Set-AzKeyVaultSecret
    call will fail with a "Forbidden ... disallowed by policy" error.

.PARAMETER VaultName
    Specifies the name of the Azure Key Vault in which the secret will be created or updated.

.PARAMETER SecretName
    Specifies the name of the secret to create or update in the Key Vault.

.PARAMETER SecretValue
    Specifies the plain-text value of the secret to store. The function converts this to a
    SecureString internally before calling Set-AzKeyVaultSecret; the plain-text value is not
    written to Key Vault directly.

.PARAMETER ExpiresInDays
     Optional. Number of days from now on which the secret should expire, passed through
     to Set-AzKeyVaultSecret's -Expires as (Get-Date).AddDays(ExpiresInDays).
 
     Required in environments that enforce the "Key Vault secrets should have an
     expiration date" Azure Policy (or similar) — without it, secret creation will
     fail with a Forbidden/policy-denied error in those environments. Omit this
     parameter entirely in environments with no such policy to create a
     non-expiring secret, same as before.

.PARAMETER ContentType
    Optional. A free-text content-type label stored alongside the secret (e.g. "ClientSecret",
    "ConnectionString"), useful for identifying what a secret is used for in reporting.

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
    System.Management.Automation.PSCustomObject
        Returns an object containing the created/updated secret's Name and Version if
        successful. Returns $null if creation fails.

.EXAMPLE
    New-AzureKeyVaultSecret -VaultName "MyKeyVault" -SecretName "ClientSecret" -SecretValue "P@ssw0rd123" -AuthenticationType ManagedIdentity

    Creates or updates a secret using Managed Identity authentication.

.EXAMPLE
    New-AzureKeyVaultSecret -VaultName "MyKeyVault" -SecretName "ClientSecret" -SecretValue "P@ssw0rd123" -AuthenticationType UserAccount -TenantId "xxxx-xxxx" -SubscriptionId "xxxx-xxxx"

    Creates or updates a secret using interactive UserAccount authentication.

.EXAMPLE
    New-AzureKeyVaultSecret -VaultName "MyKeyVault" -SecretName "ConnString" -SecretValue $connString -ContentType "ConnectionString" -AuthenticationType ManagedIdentity

    Creates a secret with a descriptive ContentType label.

.EXAMPLE
    New-AzureKeyVaultSecret -VaultName "MyKeyVault" -SecretName "ClientSecret" -SecretValue "P@ssw0rd123" -ExpiresInDays 365 -AuthenticationType ManagedIdentity

    Creates a secret that expires in 365 days — required in environments that
    enforce a Key Vault "secrets must have an expiration date" policy.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (25-Jul-2026)  - Initial release
        1.1 (25-Jul-2026)  - Added optional ExpiresInDays parameter to satisfy
                              Azure Policy assignments requiring Key Vault secrets
                              to have an expiration date (e.g. "Key Vault secrets
                              should have an expiration date"). When omitted,
                              behavior is unchanged from 1.0 (no expiry set).

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (installed automatically on first run if missing,
            with user confirmation).
        2. Appropriate Key Vault access permissions (Set Secret permission).
        3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Check for the Az module; offer to install it if missing
        Step 2  →  Authenticate via UserAccount (interactive) or ManagedIdentity
        Step 3  →  Convert SecretValue to a SecureString
        Step 4  →  Create/update the secret via Set-AzKeyVaultSecret
        Step 5  →  Return the secret's Name/Version, or $null on failure

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - SecretValue is accepted as a plain [string] parameter for consistency
            with Get-AzureKeyVaultSecretValue's plain-text convention. This means
            the value can appear in PowerShell command history, transcripts, or
            process listings on the calling machine. For shared or logged
            environments, consider changing this parameter to [SecureString] and
            prompting interactively instead of passing it as an argument.
        - This function creates a NEW VERSION on every call if SecretName already
            exists — it does not warn you before overwriting/versioning an
            existing secret.
        - If your subscription/vault enforces an Azure Policy requiring an
            expiration date on secrets, you MUST supply -ExpiresInDays or the
            call will fail with "Forbidden ... disallowed by policy". This
            function does not detect such policies in advance; the error only
            surfaces at the point of calling Set-AzKeyVaultSecret.
        - UserAccount authentication is interactive and not suitable for
            unattended automation; use ManagedIdentity for that scenario.
        - Declining the Az module installation prompt, or a module install
            failure, calls Exit — this will terminate the entire calling script/
            session, not just this function.

.LINK
    Key Vault quickstart (PowerShell)
    https://learn.microsoft.com/azure/key-vault/secrets/quick-create-powershell

.LINK
    Set-AzKeyVaultSecret reference
    https://learn.microsoft.com/powershell/module/az.keyvault/set-azkeyvaultsecret

#>


Function New-AzureKeyVaultSecret
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $true)]
        [string]$VaultName,

        [Parameter(Mandatory = $true)]
        [string]$SecretName,

        [Parameter(Mandatory = $true)]
        [string]$SecretValue,

        [int]$ExpiresInDays,

        [string]$ContentType,
        
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

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Preparing secret '$SecretName' for Key Vault '$VaultName'..." -ForegroundColor Yellow

        # Convert the plain-text secret value to a SecureString
        $secureSecretValue = ConvertTo-SecureString -String $SecretValue -AsPlainText -Force

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Creating/updating secret in Key Vault..." -ForegroundColor Yellow

        # Build optional expiry date if requested
        $expiryDate = $null
        if ($ExpiresInDays)
        {
            $expiryDate = (Get-Date).AddDays($ExpiresInDays)
        }

        # Create or update the secret in Key Vault
        $setParams = @{
            VaultName      = $VaultName
            Name           = $SecretName
            SecretValue    = $secureSecretValue
            WarningAction  = 'SilentlyContinue'
        }
        if ($ContentType) { $setParams.ContentType = $ContentType }
        if ($expiryDate)  { $setParams.Expires     = $expiryDate }
 
        $result = Set-AzKeyVaultSecret @setParams

        if ($null -eq $result) 
        {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Secret creation failed. Please check the VaultName, SecretName, and permissions." -ForegroundColor Red
            return $null
        }

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Secret created/updated successfully." -ForegroundColor Green

        return [PSCustomObject]@{
            Name    = $result.Name
            Version = $result.Version
        }
    }
    catch 
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Failed to create the secret in Key Vault. Details: $_" -ForegroundColor Red
        return $null
    }
}
