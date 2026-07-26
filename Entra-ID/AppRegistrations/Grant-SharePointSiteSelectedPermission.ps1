<#

Author          : Lakshmanan Thangaraj
Version         : 2.0
Created-On      : 8 June 2026
Modified-On     : 26 July 2026

.SYNOPSIS
    Assigns Microsoft Graph "Site.Selected" permissions to an application on a SharePoint site.

.DESCRIPTION
    Authenticates against Microsoft Graph using the OAuth 2.0 Client Credentials flow and
    grants a permission role (read, write, or owner) to a target application on a given
    SharePoint site, via the Sites.Selected permission model.

    Before granting, the function checks for an existing permission grant to the same
    target application on the same site:
      - If one already exists with the SAME role  -> no change is made, existing grant returned.
      - If one already exists with a DIFFERENT role -> a warning is shown; nothing is changed
        unless -Force is specified (Graph's permissions API does not support in-place role
        updates, so this would require deleting and recreating the grant).
      - If none exists -> a new grant is created.

    This is a state-changing, security-sensitive operation (it grants access to a SharePoint
    site, up to full Owner control). It supports -WhatIf / -Confirm, and "owner" grants
    require interactive confirmation unless -Force or -Confirm:$false is used.

    Prerequisites:
    - An Entra ID App Registration with Sites.FullControl.All (Application) on Microsoft
      Graph, consented by a Global Administrator or Privileged Role Administrator.
    - A valid Client Secret (or SecureString) for that App Registration.
    - The Target Application's App ID and Display Name.
    - The SharePoint Site ID (format: "hostname,siteCollectionId,webId").

.PARAMETER TenantId
    The Entra ID Tenant ID (GUID). Example: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.PARAMETER ClientId
    The Application (Client) ID of the App Registration that holds Sites.FullControl.All.

.PARAMETER ClientSecret
    The Client Secret as a SecureString. Preferred over -ClientSecretPlainText.
    Example: $sec = Read-Host "Client Secret" -AsSecureString

.PARAMETER ClientSecretPlainText
    The Client Secret as plain text. Provided for automation/CI scenarios only where a
    SecureString isn't practical (e.g. pulling directly from a vetted secret store).
    Prefer -ClientSecret (SecureString) or a secrets manager (Azure Key Vault, etc.) whenever
    possible. Never hardcode this value in a saved script.

.PARAMETER TargetAppId
    The Application (Client) ID of the target application that requires access to the site.

.PARAMETER TargetAppDisplayName
    The Display Name of the target application as registered in Entra ID.

.PARAMETER SiteId
    The SharePoint Site ID.
    Example: "contoso.sharepoint.com,xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx,yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"

.PARAMETER PermissionRole
    Permission role to assign: "read", "write", or "owner". Defaults to "read".
    "owner" grants full control over the site, including managing other permissions —
    the function will prompt for confirmation before granting it unless -Force is used.

.PARAMETER Force
    Suppresses the extra confirmation prompt for "owner" grants, and allows the function
    to proceed past a differing-role idempotency warning. Does not bypass -WhatIf.

.OUTPUTS
    PSCustomObject. The Graph API permission object (existing or newly created), or $null
    on failure.

.EXAMPLE
    # Assign Read permission (SecureString secret, recommended)
    $secret = Read-Host "Enter Client Secret" -AsSecureString
    Grant-SharePointSiteSelectedPermission `
        -TenantId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret $secret `
        -TargetAppId "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -TargetAppDisplayName "My App" `
        -SiteId "contoso.sharepoint.com,abc...,def..." `
        -PermissionRole "read"

.EXAMPLE
    # Preview an Owner grant without making any change
    Grant-SharePointSiteSelectedPermission -TenantId $tid -ClientId $cid -ClientSecret $secret `
        -TargetAppId $appId -TargetAppDisplayName "My App" -SiteId $siteId `
        -PermissionRole "owner" -WhatIf

.EXAMPLE
    # CI/CD pipeline using a secret pulled from a vault as plain text
    Grant-SharePointSiteSelectedPermission -TenantId $tid -ClientId $cid `
        -ClientSecretPlainText $vaultSecret -TargetAppId $appId `
        -TargetAppDisplayName "My App" -SiteId $siteId -PermissionRole "write" -Force

.NOTES
    Permissions : Requires Sites.FullControl.All (Application) on Microsoft Graph.

    Graph API References:
    - Get Access Token  : https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token
    - List Permissions  : GET  https://graph.microsoft.com/v1.0/sites/{siteId}/permissions
    - Assign Permission : POST https://graph.microsoft.com/v1.0/sites/{siteId}/permissions

    CHANGELOG:
      v2.0 - 26 July 2026 - Security/reliability rewrite for public release:
                            - Removed `exit 1` (was terminating the entire host session);
                              function now returns $null and uses Write-Error/throw instead.
                            - Added SupportsShouldProcess (-WhatIf/-Confirm); ConfirmImpact
                              escalates to High for -PermissionRole owner.
                            - Added SecureString -ClientSecret (plain text still available via
                              -ClientSecretPlainText for automation, with an explicit warning).
                            - Added idempotency check: queries existing permissions first and
                              skips/warns instead of creating duplicate grants.
                            - Added GUID format validation on TenantId/ClientId/TargetAppId.
                            - Enforced TLS 1.2 for the current session (PS 5.1 compatibility).
                            - Added retry-with-backoff for Graph 429/5xx responses.
                            - Replaced raw exception dumps with structured Write-Error/-Verbose.
                            - -Force switch to bypass the interactive Owner confirmation.
      v1.0 - 8 June 2026  - Initial release.

#>


Function Grant-SharePointSiteSelectedPermission
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium", DefaultParameterSetName = "SecureSecret")]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Entra ID Tenant ID (GUID).")]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', ErrorMessage = "TenantId must be a valid GUID.")]
        [string]$TenantId,

        [Parameter(Mandatory = $true, HelpMessage = "Client ID of the app with Sites.FullControl.All.")]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', ErrorMessage = "ClientId must be a valid GUID.")]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = "SecureSecret", HelpMessage = "Client Secret as a SecureString (recommended).")]
        [ValidateNotNull()]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = "PlainSecret", HelpMessage = "Client Secret as plain text. Prefer -ClientSecret. For automation only.")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecretPlainText,

        [Parameter(Mandatory = $true, HelpMessage = "App ID of the target application requiring site access.")]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', ErrorMessage = "TargetAppId must be a valid GUID.")]
        [string]$TargetAppId,

        [Parameter(Mandatory = $true, HelpMessage = "Display Name of the target application in Entra ID.")]
        [ValidateNotNullOrEmpty()]
        [string]$TargetAppDisplayName,

        [Parameter(Mandatory = $true, HelpMessage = "SharePoint Site ID (hostname,siteCollectionId,webId).")]
        [ValidateNotNullOrEmpty()]
        [string]$SiteId,

        [Parameter(Mandatory = $false, HelpMessage = "Permission role to assign: read, write, or owner. Defaults to 'read'.")]
        [ValidateSet("read", "write", "owner")]
        [string]$PermissionRole = "read",

        [Parameter(Mandatory = $false, HelpMessage = "Suppress the extra Owner confirmation prompt and proceed past differing-role warnings.")]
        [switch]$Force
    )

    # ── TLS 1.2 enforcement (Windows PowerShell 5.1 may default lower) ─────────
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Verbose "Could not explicitly set TLS 1.2 (likely already enforced by the OS): $_"
    }

    # ── Resolve the secret to plain text only for the duration of this call ────
    $secretPlain = $null
    if ($PSCmdlet.ParameterSetName -eq "SecureSecret") {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
        try   { $secretPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    else {
        Write-Warning "Using -ClientSecretPlainText passes the secret as plain text (visible in PS history/process listing). Prefer -ClientSecret (SecureString) or a secrets manager where possible."
        $secretPlain = $ClientSecretPlainText
    }

    # ── Internal Helper: Invoke a Graph REST call with retry/backoff ───────────
    Function Invoke-GraphRequestWithRetry
    {
        param (
            [string]$Uri,
            [string]$Method = "GET",
            [hashtable]$Headers,
            [string]$Body = $null,
            [int]$MaxRetries = 4
        )

        $attempt = 0
        while ($true) {
            $attempt++
            try {
                $params = @{
                    Uri         = $Uri
                    Method      = $Method
                    Headers     = $Headers
                    ErrorAction = "Stop"
                }
                if ($Body) { $params["Body"] = $Body }
                return Invoke-RestMethod @params
            }
            catch {
                $statusCode = $null
                if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }

                $isRetryable = ($statusCode -eq 429) -or ($statusCode -ge 500 -and $statusCode -le 599)
                if ($isRetryable -and $attempt -le $MaxRetries) {
                    $retryAfter = 2
                    if ($_.Exception.Response -and $_.Exception.Response.Headers["Retry-After"]) {
                        $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
                    }
                    $delay = [Math]::Max($retryAfter, [Math]::Pow(2, $attempt))
                    Write-Verbose "Graph request throttled/failed (status $statusCode). Retry $attempt/$MaxRetries in $delay second(s)."
                    Start-Sleep -Seconds $delay
                    continue
                }
                throw
            }
        }
    }

    # ── Internal Helper: Retrieve Microsoft Graph Access Token ─────────────────
    Function Get-GraphAccessToken
    {
        Write-Verbose "Requesting Microsoft Graph access token for tenant '$TenantId'."

        $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $body = @{
            client_id     = $ClientId
            scope         = "https://graph.microsoft.com/.default"
            client_secret = $secretPlain
            grant_type    = "client_credentials"
        }

        try {
            $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body -ErrorAction Stop
            Write-Verbose "Access token acquired (value not logged)."
            return $response.access_token
        }
        catch {
            Write-Error "Failed to acquire a Graph access token. Verify TenantId/ClientId/ClientSecret and that admin consent has been granted. Use -Verbose for detail."
            Write-Verbose "Token request error: $($_.Exception.Message)"
            return $null
        }
    }

    # ── Internal Helper: Check for an existing grant to the same target app ────
    Function Get-ExistingSitePermission
    {
        param ([string]$AccessToken)

        $headers = @{ Authorization = "Bearer $AccessToken" }
        $listUrl = "https://graph.microsoft.com/v1.0/sites/$SiteId/permissions"

        try {
            $existing = Invoke-GraphRequestWithRetry -Uri $listUrl -Method "GET" -Headers $headers
            return $existing.value | Where-Object {
                $_.grantedToIdentities.application.id -contains $TargetAppId
            }
        }
        catch {
            Write-Verbose "Could not list existing permissions (continuing without idempotency check): $($_.Exception.Message)"
            return $null
        }
    }

    # ── Internal Helper: Assign Permission to Target Application ───────────────
    Function Invoke-AssignSitePermission
    {
        param ([string]$AccessToken)

        $headers = @{
            Authorization  = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        }
        $assignUrl = "https://graph.microsoft.com/v1.0/sites/$SiteId/permissions"

        $permissionBody = @{
            roles               = @($PermissionRole)
            grantedToIdentities = @(
                @{
                    application = @{
                        id          = $TargetAppId
                        displayName = $TargetAppDisplayName
                    }
                }
            )
        } | ConvertTo-Json -Depth 3

        return Invoke-GraphRequestWithRetry -Uri $assignUrl -Method "POST" -Headers $headers -Body $permissionBody
    }

    # ── Main Execution ──────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "===== Grant-SharePointSiteSelectedPermission =====" -ForegroundColor Magenta
    Write-Host "  Site           : $SiteId" -ForegroundColor Gray
    Write-Host "  Target App     : $TargetAppDisplayName ($TargetAppId)" -ForegroundColor Gray
    Write-Host "  Requested Role : $PermissionRole" -ForegroundColor Gray
    Write-Host ""

    if ($PermissionRole -eq "owner" -and -not $Force) {
        $ownerConfirm = $PSCmdlet.ShouldContinue(
            "Grant FULL CONTROL (owner) of site '$SiteId' to '$TargetAppDisplayName'? This allows the app to manage permissions on this site.",
            "Confirm high-privilege grant"
        )
        if (-not $ownerConfirm) {
            Write-Host "Owner grant cancelled by user." -ForegroundColor Yellow
            return $null
        }
    }

    if (-not $PSCmdlet.ShouldProcess("Site '$SiteId'", "Grant '$PermissionRole' to app '$TargetAppDisplayName' ($TargetAppId)")) {
        return $null
    }

    try {
        $accessToken = Get-GraphAccessToken
        if (-not $accessToken) { return $null }

        $existingGrant = Get-ExistingSitePermission -AccessToken $accessToken
        if ($existingGrant) {
            $existingRoles = @($existingGrant.roles) -join ", "
            if ($existingRoles -eq $PermissionRole) {
                Write-Host "No change needed — '$TargetAppDisplayName' already has '$PermissionRole' on this site." -ForegroundColor Cyan
                return $existingGrant
            }
            elseif (-not $Force) {
                Write-Warning "'$TargetAppDisplayName' already has a DIFFERENT role ('$existingRoles') on this site. Graph does not support in-place role updates via this endpoint. Re-run with -Force to proceed anyway (this will add an additional grant rather than replace the existing one), or remove the existing grant first."
                return $existingGrant
            }
            else {
                Write-Verbose "-Force specified — proceeding despite existing role '$existingRoles'."
            }
        }

        $result = Invoke-AssignSitePermission -AccessToken $accessToken
        Write-Host "Permission '$PermissionRole' assigned successfully to '$TargetAppDisplayName'." -ForegroundColor Green
        return $result
    }
    catch {
        Write-Error "Failed to assign site permission. Use -Verbose for full detail. Common causes: insufficient Sites.FullControl.All consent, an invalid SiteId, or a Graph throttling limit exceeded after retries."
        Write-Verbose "Assignment error: $($_.Exception.Message)"
        return $null
    }
    finally {
        # Best-effort clear of the in-memory plain-text secret reference.
        $secretPlain = $null
    }
}
