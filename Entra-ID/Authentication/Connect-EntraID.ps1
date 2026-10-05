<#

Author          : Lakshmanan Thangaraj
Version         : 1.2
Created-On      : 06 June 2024
Modified-On     : 05 October 2026

.SYNOPSIS
    Authenticates to Microsoft Entra ID via the OAuth2 client credentials flow
    and provides a self-renewing bearer token for long-running scripts.

.DESCRIPTION
    Dot-source this file to load two public functions:

        Connect-EntraID
            Establishes the initial app-only session against Microsoft Graph
            using a Client ID, Client Secret (SecureString), and Tenant ID.
            Requests the first access token and stores session state.

        Get-EntraIDAccessToken
            Returns a valid, non-expired access token. If the current token
            is close to expiry (within -RefreshInterval minutes), it is
            silently renewed before being returned. Intended to be called
            inside pagination loops or long-running operations so callers
            never have to think about token lifetime themselves.

    Design notes for reuse and safety:
        - Session state (token, expiry, tenant/client identifiers, and the
          SecureString secret) is kept in SCRIPT SCOPE within this dot-sourced
          file — not $global: — so it cannot collide with other tools or
          modules loaded in the same PowerShell session.
        - The client secret is only ever marshaled to plaintext for the
          instant needed to build the OAuth token request body, then
          immediately scrubbed from memory with ZeroFreeBSTR.
        - No Connect-* call happens automatically. The caller must explicitly
          call Connect-EntraID once, then Get-EntraIDAccessToken as needed —
          matching how Az and Microsoft.Graph modules behave.

.PARAMETER ClientId
    The Application (client) ID of the Azure AD app registration used for
    authentication.

.PARAMETER ClientSecret
    Required for secret authentication. Not used with certificate authentication.
    The client secret associated with the Azure AD app registration, supplied
    as a SecureString. Example:

        $secret = Read-Host -Prompt "Enter client secret" -AsSecureString
        Connect-EntraID -ClientId $id -ClientSecret $secret -TenantId $tid

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate with a private key, installed in
    Cert:\CurrentUser\My or Cert:\LocalMachine\My. The matching public
    certificate (.cer) must be uploaded to the app registration under
    Certificates & secrets. Use this OR -Certificate, not both.

.PARAMETER Certificate
    An X509Certificate2 object that includes its private key. Useful when the
    certificate is loaded from a PFX file instead of the certificate store.
    Use this OR -CertificateThumbprint, not both.

.PARAMETER TenantId
    The Directory (tenant) ID of the Entra ID tenant to authenticate against.

.PARAMETER RefreshInterval
    Number of minutes before token expiry at which Get-EntraIDAccessToken
    should silently renew the token. Default: 5 minutes.

.PARAMETER ShowHelp
    Switch parameter. Displays a friendly, plain-language usage guide and
    returns immediately — no authentication is attempted and no other
    parameters are required when this switch is used.

.INPUTS
    None. These functions do not accept pipeline input.

.OUTPUTS
    System.String
        Connect-EntraID and Get-EntraIDAccessToken both return the current
        bearer token as a plain string, ready to use in an Authorization
        header (e.g. "Bearer <token>").

.EXAMPLE
    . .\Connect-EntraID.ps1
    Connect-EntraID -ShowHelp

    Dot-sources the file and prints the friendly usage guide without
    connecting to anything.

.EXAMPLE
    . .\Connect-EntraID.ps1
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Connect-EntraID -ClientId "8ad5d2f5-xxxx" -ClientSecret $secret -TenantId "f4310b4f-xxxx"

    # ... later, inside a pagination loop or long-running operation ...
    $token = Get-EntraIDAccessToken
    $headers = @{ Authorization = "Bearer $token" }

    Establishes the session once, then pulls a guaranteed-fresh token on
    demand for as many calls as needed, however long the script runs.

.EXAMPLE
    . .\Connect-EntraID.ps1
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Connect-EntraID -ClientId $id -ClientSecret $secret -TenantId $tid -RefreshInterval 10

    Same as above, but renews the token once fewer than 10 minutes remain
    before expiry, instead of the default 5.

.EXAMPLE
    . .\Connect-EntraID.ps1
    Connect-EntraID -ClientId "8ad5d2f5-xxxx" -TenantId "f4310b4f-xxxx" -CertificateThumbprint "A1B2C3...."

    $token = Get-EntraIDAccessToken

    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxPath, $pfxPassword)  # $pfxPassword as SecureString
    Connect-EntraID -ClientId $id -TenantId $tid -Certificate $cert

    $pfxPwd = Read-Host "PFX password" -AsSecureString
    Export-PfxCertificate -Cert $cert -FilePath "$env:TEMP\test.pfx" -Password $pfxPwd

    $pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$env:TEMP\test.pfx", $pfxPwd)
    Connect-EntraID -ClientId $id -TenantId $tid -Certificate $pfxCert -Verbose

    Authenticates with a certificate from the local store. Get-EntraIDAccessToken
    works exactly the same afterwards.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    CHANGELOG:
    ─────────────────────────────────────────────────────────────────────────────
        v1.0 (05-Jun-2024) - Initial version. 
        v1.1 (05-Jul-2026) - Moved all session state from $global: scope
                                 to SCRIPT scope, private to this dot-sourced
                                 file, to make it safe for reuse alongside
                                 other tools without variable collisions and
                                 to allow future multi-session support.
                               - Renamed internal helpers to approved-verb,
                                 public-facing functions: RequestAccessToken
                                 stays private; RenewTokenIfNeeded became the
                                 public Get-EntraIDAccessToken so callers have
                                 one clear entry point for "give me a valid
                                 token right now."
                               - ClientSecret remains a SecureString parameter;
                                 plaintext is marshaled transiently via
                                 PtrToStringAuto and scrubbed immediately with
                                 ZeroFreeBSTR (unchanged behaviour from the
                                 report script's v2.1 update).
                               - Added full comment-based help, Author block,
                                 and -ShowHelp friendly guide, matching the
                                 Cloud-Identity-Toolkit repo documentation
                                 standard.
                               - Added Write-Verbose logging throughout and a
                                 Try/Catch/Finally around token acquisition
                                 for cleaner error handling.
        v1.2 (05-Oct-2026) - Added certificate-based authentication
                                 (client_assertion / private_key_jwt) as an
                                 alternative to client secret. Existing
                                 -ClientSecret usage is unchanged.
                               - New parameters on Connect-EntraID:
                                 -CertificateThumbprint and -Certificate.
                               - New internal helpers: ConvertTo-Base64Url and
                                 New-EntraIDClientAssertion.
                               - RequestAccessToken now branches on the stored
                                 auth method (Secret or Certificate).
                               - Parameter sets renamed: "Run" -> "Secret",
                                 added "Certificate". Default stays "Secret".

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Azure AD App Registration with a client secret configured and the
           Microsoft Graph Application permissions required by whatever
           script calls Get-EntraIDAccessToken (this file only requests a
           token — it does not itself call any Graph endpoints).
        2. PowerShell 5.1 or later.
        3. For certificate auth: a certificate with an exportable or accessible
           private key on the machine running the script, and its public .cer
           uploaded to the app registration.

    ─────────────────────────────────────────────────────────────────────────────
    Functions:
    ─────────────────────────────────────────────────────────────────────────────
        Connect-EntraID          (public)
            Establishes the session: stores TenantId, ClientId, and the
            ClientSecret SecureString in script scope, then requests the
            first access token.

        Get-EntraIDAccessToken   (public)
            Returns a valid access token, silently renewing it first if it
            is within -RefreshInterval minutes of expiry. Safe to call as
            often as needed — e.g. once per page in a pagination loop.

        Show-FriendlyHelp        (internal helper)
            Prints the plain-language usage guide for -ShowHelp.

        RequestAccessToken       (internal helper)
            Performs the actual OAuth2 client_credentials token request.
            Not intended to be called directly by consumers.

.LINK
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/Entra-ID/Authentication

.LINK
    Microsoft identity platform — client credentials flow
    https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow

#>

#--------------------------------------------------------------------------------------------------- [ Script-scope session state ]
# Private to this dot-sourced file. Not $global: — avoids collisions with
# other tools/modules loaded in the same PowerShell session.
$script:EntraIDAccessToken          = $null
$script:EntraIDTokenExpirationTime  = $null
$script:EntraIDRefreshIntervalMins  = 5
$script:EntraIDTenantId             = $null
$script:EntraIDClientId             = $null
$script:EntraIDClientSecretSecure   = $null
$script:EntraIDAuthMethod           = $null   # 'Secret' or 'Certificate'
$script:EntraIDCertificate          = $null

#--------------------------------------------------------------------------------------------------- [ Friendly Help ]

Function Show-FriendlyHelp
{
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║              Connect-EntraID  —  Auth Toolkit v1.0           ║" -ForegroundColor Cyan
    Write-Host "  ║                       Friendly Help                          ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this does:" -ForegroundColor Yellow
    Write-Host "    Authenticates to Entra ID (Azure AD) using app-only client"
    Write-Host "    credentials, then hands you a bearer token you can reuse for"
    Write-Host "    as long as your script runs — it renews itself automatically."
    Write-Host ""
    Write-Host "  Required parameters:" -ForegroundColor Yellow
    Write-Host "    -ClientId      Application (client) ID of your Azure AD app registration"
    Write-Host "    Authenticate with ONE of:" -ForegroundColor Yellow
    Write-Host "      -ClientSecret            Client secret as a SecureString"
    Write-Host "      -CertificateThumbprint   Thumbprint of a cert in your cert store"
    Write-Host "      -Certificate             A certificate object (e.g. loaded from a PFX)"
    Write-Host "    -TenantId      Directory (tenant) ID of the Entra ID tenant"
    Write-Host ""
    Write-Host "  Optional parameters:" -ForegroundColor Yellow
    Write-Host "    -RefreshInterval  Minutes before expiry to renew early (default: 5)"
    Write-Host "    -ShowHelp         Shows this guide and exits, nothing is generated"
    Write-Host ""
    Write-Host "  How to use it:" -ForegroundColor Yellow
    Write-Host "    1. Dot-source this file:               . .\Connect-EntraID.ps1"
    Write-Host "    2. Connect once:                       Connect-EntraID -ClientId ... -ClientSecret ... -TenantId ..."
    Write-Host "    3. Pull a fresh token whenever needed: `$token = Get-EntraIDAccessToken"
    Write-Host ""
    Write-Host "  Example:" -ForegroundColor Yellow
    Write-Host '    . .\Connect-EntraID.ps1'
    Write-Host '    $secret = Read-Host -Prompt "Client secret" -AsSecureString'
    Write-Host '    Connect-EntraID -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
    Write-Host '    $token = Get-EntraIDAccessToken'
    Write-Host ""
    Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
    Write-Host "     Get-Help Connect-EntraID -Full"
    Write-Host ""
}

#--------------------------------------------------------------------------------------------------- [ Internal: token request ]

Function ConvertTo-Base64Url
{
    param([byte[]]$Bytes)
    # JWTs use URL-safe Base64: no padding, '-' and '_' instead of '+' and '/'
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

Function New-EntraIDClientAssertion
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId
    )

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $now           = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $enc           = [System.Text.Encoding]::UTF8

    # Header: tells Entra which cert to verify against (x5t = cert hash)
    $header = [ordered]@{ alg = 'RS256'; typ = 'JWT'; x5t = ConvertTo-Base64Url $Certificate.GetCertHash() }

    # Claims: who we are, who the token is for, and a short lifetime
    $claims = [ordered]@{
        aud = $tokenEndpoint
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = $now
        exp = $now + 600
    }

    $h        = ConvertTo-Base64Url ($enc.GetBytes(($header | ConvertTo-Json -Compress)))
    $p        = ConvertTo-Base64Url ($enc.GetBytes(($claims | ConvertTo-Json -Compress)))
    $unsigned = "$h.$p"

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) { throw "Unable to access the certificate's RSA private key." }

    $signature = $rsa.SignData(
        $enc.GetBytes($unsigned),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    return "$unsigned.$(ConvertTo-Base64Url $signature)"
}

Function RequestAccessToken
{
    [CmdletBinding()]
    param()

    Write-Verbose "Requesting new access token for tenant $script:EntraIDTenantId"

    $tokenEndpoint = "https://login.microsoftonline.com/$script:EntraIDTenantId/oauth2/v2.0/token"

    # Marshal the SecureString to plaintext only for the instant it's needed
    # to build the token request body, then scrub it from memory right after.
    $bstr = [IntPtr]::Zero          # initialised so the Finally block is safe in cert mode
    Try
    {
        $tokenRequestBody = @{
            client_id  = $script:EntraIDClientId
            scope      = "https://graph.microsoft.com/.default"
            grant_type = "client_credentials"
        }

        if ($script:EntraIDAuthMethod -eq 'Certificate')
        {
            Write-Verbose "Using certificate authentication (thumbprint $($script:EntraIDCertificate.Thumbprint))"
            $tokenRequestBody.client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            $tokenRequestBody.client_assertion      = New-EntraIDClientAssertion `
                -Certificate $script:EntraIDCertificate `
                -TenantId    $script:EntraIDTenantId `
                -ClientId    $script:EntraIDClientId
        }
        else
        {
            Write-Verbose "Using client secret authentication"
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:EntraIDClientSecretSecure)
            $plainClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            $tokenRequestBody.client_secret = $plainClientSecret
        }

        $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $tokenRequestBody -ErrorAction Stop

        $script:EntraIDAccessToken         = $tokenResponse.access_token
        $script:EntraIDTokenExpirationTime = (Get-Date).AddSeconds($tokenResponse.expires_in)

        Write-Verbose "Token acquired. Expires at $script:EntraIDTokenExpirationTime"
    }
    Catch
    {
        Write-Error "Failed to obtain access token from Entra ID. Details: $_"
        throw
    }
    Finally
    {
        if ($bstr -ne [IntPtr]::Zero)
        {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $plainClientSecret = $null
        $tokenRequestBody   = $null
    }
}

#--------------------------------------------------------------------------------------------------- [ Public: Connect-EntraID ]

Function Connect-EntraID
{
    [CmdletBinding(DefaultParameterSetName = "Secret")]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "Secret")]
        [Parameter(Mandatory = $true, ParameterSetName = "Certificate")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = "Secret")]
        [ValidateNotNull()]
        [System.Security.SecureString]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = "Secret")]
        [Parameter(Mandatory = $true, ParameterSetName = "Certificate")]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(ParameterSetName = "Certificate")]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = "Certificate")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName = "Secret")]
        [Parameter(ParameterSetName = "Certificate")]
        [int]$RefreshInterval = 5,

        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    if ($ShowHelp)
    {
        Show-FriendlyHelp
        return
    }

    Try
    {
        Write-Verbose "Initializing Entra ID session for tenant $TenantId"

        if ($PSCmdlet.ParameterSetName -eq 'Certificate')
        {
            if (-not $Certificate)
            {
                if (-not $CertificateThumbprint) { throw "Provide -CertificateThumbprint or -Certificate." }
                $thumb = $CertificateThumbprint -replace '\s', ''
                $Certificate = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
                               Where-Object Thumbprint -eq $thumb | Select-Object -First 1
                if (-not $Certificate) { throw "Certificate with thumbprint $thumb not found in CurrentUser\My or LocalMachine\My." }
            }
            if (-not $Certificate.HasPrivateKey) { throw "Certificate has no private key; cannot sign." }

            $script:EntraIDAuthMethod          = 'Certificate'
            $script:EntraIDCertificate         = $Certificate
            $script:EntraIDClientSecretSecure  = $null
        }
        else
        {
            $script:EntraIDAuthMethod          = 'Secret'
            $script:EntraIDClientSecretSecure  = $ClientSecret
            $script:EntraIDCertificate         = $null
        }

        # Common state: same for both methods (these are your old lines, moved below)
        $script:EntraIDAccessToken         = $null
        $script:EntraIDTokenExpirationTime = $null
        $script:EntraIDRefreshIntervalMins = $RefreshInterval
        $script:EntraIDTenantId            = $TenantId
        $script:EntraIDClientId            = $ClientId

        RequestAccessToken

        return $script:EntraIDAccessToken
    }
    Catch
    {
        Write-Error "Failed to connect to Entra ID. Details: $_"
        return $null
    }
}

#--------------------------------------------------------------------------------------------------- [ Public: Get-EntraIDAccessToken ]

Function Get-EntraIDAccessToken
{
    [CmdletBinding()]
    param()

    if (-not $script:EntraIDTenantId)
    {
        Write-Error "No active session. Call Connect-EntraID first."
        return $null
    }

    $needsRenewal = $true
    if ($script:EntraIDAccessToken -and $script:EntraIDTokenExpirationTime)
    {
        $minutesToExpiry = ($script:EntraIDTokenExpirationTime - (Get-Date)).TotalMinutes
        $needsRenewal    = $minutesToExpiry -lt $script:EntraIDRefreshIntervalMins
    }

    if ($needsRenewal)
    {
        Write-Verbose "Token missing or nearing expiry — renewing."
        RequestAccessToken
    }

    return $script:EntraIDAccessToken
}
