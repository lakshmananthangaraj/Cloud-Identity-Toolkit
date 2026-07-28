<#

Author       : Lakshmanan Thangaraj
Version      : 1.1
Created-On   : 23 October 2024
Modified-On  : 27 July 2026

.SYNOPSIS
    Grants a Microsoft Graph API Application permission (App Role) to a Managed
    Identity in Entra ID.

.DESCRIPTION
    Grant-GraphAPIPermissionToManagedIdentity assigns a specified Microsoft Graph
    Application-type permission (App Role) to a Managed Identity's service
    principal. Managed Identities are used to access resources that support
    Entra ID authentication, but the Azure Portal UI has no way to assign Graph
    API permissions to a Managed Identity directly - this function fills that
    gap using Microsoft Graph PowerShell.

    Before assigning anything, the function:
        - Confirms the Managed Identity's service principal resolves to exactly
          one match (display names are not guaranteed unique in a tenant - a
          collision fails loudly rather than assigning to the wrong identity).
        - Checks whether the permission is already assigned, and exits cleanly
          instead of erroring if it is - safe to re-run.

    Because this grants a high-privilege, tenant-wide Application permission
    (the same class of access an admin would otherwise approve interactively
    via admin consent), this function supports -WhatIf and prompts for
    confirmation by default. Use -Force to skip the prompt in unattended
    automation.

.PARAMETER MSIDisplayName
    The display name of the Managed Identity's service principal to which the
    Graph API permission will be assigned.

.PARAMETER PermissionName
    The exact value of the Microsoft Graph Application permission (App Role) to
    assign - e.g. "Device.ReadWrite.All" or "User.Read.All". Must be a
    permission that supports the "Application" member type; permissions that
    are Delegated-only are not valid here and will be rejected.

.PARAMETER Force
    Suppresses the confirmation prompt this function shows by default before
    granting the permission. Intended for unattended/automation scenarios -
    use deliberately, since this still grants a high-privilege permission.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    Microsoft.Graph.PowerShell.Models.MicrosoftGraphAppRoleAssignment
        The app role assignment - either the one just created, or the existing
        one, if the permission was already assigned.

.EXAMPLE
    Grant-GraphAPIPermissionToManagedIdentity -MSIDisplayName "MyManagedIdentity" -PermissionName "Device.ReadWrite.All"

    Prompts for confirmation, then assigns the "Device.ReadWrite.All" Application
    permission to the Managed Identity named "MyManagedIdentity".

.EXAMPLE
    Grant-GraphAPIPermissionToManagedIdentity -MSIDisplayName "MyManagedIdentity" -PermissionName "User.Read.All" -WhatIf

    Dry-run: shows what would be granted without actually assigning anything.

.EXAMPLE
    Grant-GraphAPIPermissionToManagedIdentity -MSIDisplayName "AutomationMSI" -PermissionName "Mail.Send" -Force

    Assigns the permission without an interactive confirmation prompt - for use
    in an unattended pipeline where you've already reviewed what's being granted.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.1 (27-Jul-2026) - Documentation/standards upgrade and hardening pass:
                         renamed from Assign- (not an approved verb) to Grant-,
                         matching this repo's Grant-SharePointSiteSelectedPermission
                         convention; made both parameters mandatory with
                         validation; added -WhatIf/-Confirm support (ConfirmImpact
                         High) plus -Force for automation; added a pre-flight
                         duplicate-assignment check for idempotency; added a
                         match-count check on the MSI lookup to fail loudly on
                         a display-name collision instead of guessing; fixed
                         Connect-MgGraph error handling to stop the script
                         instead of continuing unauthenticated; replaced the
                         Get-InstalledModule check (false negatives when only
                         targeted sub-modules are installed) with a check for
                         the specific cmdlets actually used; corrected
                         .PARAMETER block structure and moved .REMARKS content
                         into .NOTES.
    1.0 (23-Oct-2024) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Microsoft Graph PowerShell - specifically the Microsoft.Graph.Authentication
       and Microsoft.Graph.Applications modules (or the full Microsoft.Graph
       meta-module).
    2. The signed-in account needs Application.ReadWrite.All and
       AppRoleAssignment.ReadWrite.All Graph permissions to run this function.
    3. PowerShell 5.1 or later.
    
    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - If -MSIDisplayName matches more than one service principal, the function
      throws rather than guessing - re-run with a more specific/unique name.
    - Grants Application-type (app-only) permissions only. Delegated permissions
      are not applicable to Managed Identities and are rejected.
    - Does not itself revoke or list existing permissions - see
      Get-MgServicePrincipalAppRoleAssignment for that.

.LINK
    Grant Graph API permission to a Managed Identity object
    https://techcommunity.microsoft.com/t5/azure-integration-services-blog/grant-graph-api-permission-to-managed-identity-object/ba-p/2792127

.LINK
    Grant admin consent for Application permissions (PowerShell)
    https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent?pivots=ms-powershell#grant-admin-consent-for-application-permissions-using-microsoft-graph-powershell

#>


Function Grant-GraphAPIPermissionToManagedIdentity
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MSIDisplayName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PermissionName,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if ($Force) {
        $ConfirmPreference = 'None'
    }

    # Check for the specific cmdlets this function needs, rather than a named
    # module - works whether Microsoft.Graph, or just the targeted
    # Authentication/Applications sub-modules, are installed.
    $requiredCommands = @('Connect-MgGraph', 'Get-MgServicePrincipal', 'Get-MgServicePrincipalAppRoleAssignment', 'New-MgServicePrincipalAppRoleAssignment')
    $missingCommands = $requiredCommands | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) }

    if ($missingCommands) {
        Write-Host "Required Microsoft Graph cmdlet(s) not found: $($missingCommands -join ', ')" -ForegroundColor Red
        Write-Host "Install the required modules first, e.g.:" -ForegroundColor Red
        Write-Host "  Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications -Scope CurrentUser -Force" -ForegroundColor Yellow
        return
    }
    Write-Host "Required Microsoft Graph cmdlets are available. Proceeding..." -ForegroundColor Green

    # Reuse an existing Graph session if one is already connected with the
    # right scopes; otherwise connect.
    $requiredScopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')
    $currentContext = Get-MgContext -ErrorAction SilentlyContinue

    if (-not $currentContext -or ($requiredScopes | Where-Object { $currentContext.Scopes -notcontains $_ })) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Connecting to Microsoft Graph with required scopes..." -ForegroundColor Yellow
        try {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Authenticated and connected to Microsoft Graph." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
            return
        }
    }
    else {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Reusing existing Microsoft Graph session." -ForegroundColor Cyan
    }

    $GraphAppId = '00000003-0000-0000-c000-000000000000'  # Do not change this value (Microsoft Graph's well-known AppId)

    try {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Retrieving the Managed Identity with Display Name: $MSIDisplayName" -ForegroundColor Yellow
        $matchingPrincipals = @(Get-MgServicePrincipal -Filter "displayName eq '$MSIDisplayName'" -ErrorAction Stop)

        if ($matchingPrincipals.Count -eq 0) {
            throw "No service principal found with display name '$MSIDisplayName'."
        }
        if ($matchingPrincipals.Count -gt 1) {
            throw "Found $($matchingPrincipals.Count) service principals with display name '$MSIDisplayName' - display names are not guaranteed unique. Disambiguate and re-run against the correct object."
        }
        $MSI = $matchingPrincipals[0]

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Retrieving the Microsoft Graph service principal..." -ForegroundColor Yellow
        $GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" -ErrorAction Stop

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Resolving App Role for permission: $PermissionName" -ForegroundColor Yellow
        $AppRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains 'Application' }

        if (-not $AppRole) {
            throw "Permission '$PermissionName' was not found as an Application-type App Role on Microsoft Graph. Check the exact permission name and that it supports Application (not just Delegated) access."
        }

        # Idempotency check - don't error on a permission that's already granted.
        $existingAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MSI.Id -All -ErrorAction Stop |
            Where-Object { $_.AppRoleId -eq $AppRole.Id -and $_.ResourceId -eq $GraphServicePrincipal.Id }

        if ($existingAssignment) {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Permission '$PermissionName' is already assigned to '$MSIDisplayName' - nothing to do." -ForegroundColor Cyan
            return $existingAssignment
        }

        $actionDescription = "Grant Application permission '$PermissionName' to Managed Identity '$MSIDisplayName'"
        if (-not $PSCmdlet.ShouldProcess($MSIDisplayName, $actionDescription)) {
            return
        }

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Assigning '$PermissionName' to '$MSIDisplayName'..." -ForegroundColor Cyan
        $newAssignment = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MSI.Id -PrincipalId $MSI.Id -ResourceId $GraphServicePrincipal.Id -AppRoleId $AppRole.Id -ErrorAction Stop
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] '$PermissionName' successfully assigned to '$MSIDisplayName'." -ForegroundColor Green

        return $newAssignment
    }
    catch {
        Write-Error "Error during execution: $($_.Exception.Message)"
    }
    finally {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Script execution completed." -ForegroundColor Green
    }
}
