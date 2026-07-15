<#

.Author
    Name        : Lakshmanan Thangaraj
    Version     : 2.0
    Created-On  : 06 Feb 2025
    Modified-On : 15 July 2026

.SYNOPSIS
    Generates a certificate expiration report for Azure AD App Registrations using Microsoft Graph API.

.DESCRIPTION
    This function retrieves all Azure AD application registrations and analyzes their keyCredentials
    (certificates) to generate a certificate expiration report.

    It identifies certificates that are:
    - Already expired (based on configurable past days)
    - Expiring soon (based on configurable future threshold)

    The function categorizes certificate health into multiple expiration statuses such as:
    Critical, High, Medium, Low, and Expired.

    It supports pagination, API throttling handling, and exports the final report to a CSV file.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required if using Option A (bring-your-own token) — supply this on its own,
    without -ClientId/-ClientSecret/-TenantId.

    Required permissions:
    - Application.Read.All
    - Directory.Read.All

.PARAMETER ClientId
    The Application (client) ID of the Azure AD app registration used for
    app-only authentication (Option B). Use this together with -ClientSecret
    and -TenantId instead of -AccessToken when running unattended.

.PARAMETER ClientSecret
    The client secret for the app registration, supplied as a SecureString.
    Example:
        $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Used together with -ClientId and -TenantId.

.PARAMETER TenantId
    The Directory (tenant) ID. Required when authenticating via -ClientId and
    -ClientSecret (Option B). Not needed if you're supplying -AccessToken
    directly (Option A).

.PARAMETER RefreshInterval
    Minutes before the access token's expiry to proactively renew it, when
    authenticating via -ClientId/-ClientSecret (Option B). Only relevant for
    long-running exports against large tenants.

    Default: 5

.PARAMETER OutputPath
    File path where the CSV report will be saved.

    Default:
    C:\Temp\AppRegistrations_CertificatesExpirationReport_<timestamp>.CSV

.PARAMETER ExpiredLastDays
    Number of past days to consider for identifying expired certificates.

    Default: 30

.PARAMETER ExpiringNextDays
    Number of future days to check for certificates nearing expiration.

    Default: 60

.PARAMETER ShowHelp
    Prints a plain-language usage guide and exits — no connection is made.

.EXAMPLE
    Get-AppRegistrationCertificateReport -ShowHelp

    Displays a friendly, plain-language summary of parameters and usage
    without connecting to Microsoft Graph.

.EXAMPLE
    Get-AppRegistrationCertificateReport -AccessToken $token

    Generates a certificate expiration report with default settings, using
    a manually supplied bearer token (Option A).

.EXAMPLE
    Get-AppRegistrationCertificateReport -AccessToken $token -OutputPath "C:\Reports\Certs.csv"

    Generates and exports the report to a custom path.

.EXAMPLE
    Get-AppRegistrationCertificateReport -AccessToken $token -ExpiredLastDays 15 -ExpiringNextDays 90

    Customizes expiration evaluation thresholds.

.EXAMPLE
    . .\Connect-EntraID.ps1
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-AppRegistrationCertificateReport -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"

    Authenticates automatically via app-only client credentials (Option B) —
    no manual token copy-paste needed. Ideal for scheduled/unattended runs.

.NOTES
    Key Features:
    - Retrieves app registrations from Microsoft Graph beta endpoint
    - Analyzes keyCredentials (certificates)
    - Classifies certificate expiration status into multiple severity levels
    - Supports pagination and throttling (Retry-After handling)
    - Exports results to CSV
    - Sorts results based on certificate expiration
    - Supports two authentication modes: bring-your-own bearer token (Option A),
      or app-only client credentials via Connect-EntraID.ps1 (Option B)

    Limitations:
    - Requires either a valid Microsoft Graph access token, or app registration
      credentials (-ClientId/-ClientSecret/-TenantId) for app-only auth
    - Uses beta Graph API endpoints
    - Large tenants may result in longer execution time due to sequential processing
    - Depends on keyCredentials availability in applications

    To use app-only authentication, download Connect-EntraID.ps1 from the link below.

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (06 Feb 2025)      - Initial release: bearer-token auth, pagination,
                                 throttling handling, CSV export.
        2.0 (15 Jul 2026)      - Added app-only authentication support via
                                 Connect-EntraID.ps1 (-ClientId/-ClientSecret/
                                 -TenantId), as an alternative to supplying a
                                 raw -AccessToken. Long-running pagination now
                                 silently renews the token when authenticated
                                 this way. Added -ShowHelp guide. Fixed a
                                 throttling bug where a non-429 Graph error
                                 would exit the whole function via `return`
                                 instead of being reported like the secret
                                 report does.

.LINK
    https://learn.microsoft.com/graph/api/application-list

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


#----------------------------------------------------------------------------------- [ Friendly Help Guide ]

Function Show-FriendlyHelp
{
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║        Get-AppRegistrationCertificateReport  v2.0             ║" -ForegroundColor Cyan
    Write-Host "  ║                   Friendly Help Guide                        ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this does:" -ForegroundColor Yellow
    Write-Host "    Scans every Entra ID App Registration in your tenant for"
    Write-Host "    certificates (keyCredentials) that have recently expired or"
    Write-Host "    are expiring soon, and exports the results to a CSV report."
    Write-Host ""
    Write-Host "  Choose ONE authentication method:" -ForegroundColor Yellow
    Write-Host "    Option A — Bring your own token:"
    Write-Host "      -AccessToken   A bearer token (e.g. from Graph Explorer or Connect-MgGraph)"
    Write-Host ""
    Write-Host "  Option B — App-only login (recommended for automation):" -ForegroundColor Yellow
    Write-Host "      (Requires Connect-EntraID.ps1 — get it from the repo:)" -ForegroundColor DarkYellow
    Write-Host "      https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1" -ForegroundColor Cyan
    Write-Host "      -ClientId       Application (client) ID of your app registration"
    Write-Host "      -ClientSecret   The app's client secret, as a SecureString"
    Write-Host "      -TenantId       Directory (tenant) ID"
    Write-Host "      -RefreshInterval  (optional) Minutes before expiry to renew early (default: 5)"
    Write-Host ""
    Write-Host "  Optional parameters (either method):" -ForegroundColor Yellow
    Write-Host "    -OutputPath        Where to save the CSV report"
    Write-Host "    -ExpiredLastDays   Look-back window for recently expired certificates (default: 30)"
    Write-Host "    -ExpiringNextDays  Look-ahead window for soon-to-expire certificates (default: 60)"
    Write-Host "    -ShowHelp          Shows this guide and exits, nothing is generated"
    Write-Host ""
    Write-Host "  Example (Option A):" -ForegroundColor Yellow
    Write-Host '    Get-AppRegistrationCertificateReport -AccessToken $token'
    Write-Host ""
    Write-Host "  Example (Option B):" -ForegroundColor Yellow
    Write-Host '    . .\Connect-EntraID.ps1'
    Write-Host '    $secret = Read-Host -Prompt "Client secret" -AsSecureString'
    Write-Host '    Get-AppRegistrationCertificateReport -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
    Write-Host ""
    Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
    Write-Host "     Get-Help Get-AppRegistrationCertificateReport -Full"
    Write-Host ""
}


#----------------------------------------------------------------------------------- [ Function to Generate App Registration Certificate Expiration Report ]

Function Get-AppRegistrationCertificateReport
{
    [CmdletBinding(DefaultParameterSetName = "Token")]
    param (
        # ── Auth Option A: bring your own token ─────────────────────────────
        [Parameter(Mandatory = $true, ParameterSetName = "Token")]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        # ── Auth Option B: app-only client credentials (via Connect-EntraID) ─
        [Parameter(Mandatory = $true, ParameterSetName = "AppAuth")]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = "AppAuth")]
        [ValidateNotNull()]
        [System.Security.SecureString]$ClientSecret,

        [Parameter(ParameterSetName = "AppAuth")]
        [int]$RefreshInterval = 5,

        [Parameter(Mandatory = $true,  ParameterSetName = "AppAuth")]
        [Parameter(Mandatory = $false, ParameterSetName = "Token")]
        [string]$TenantId = "N/A",

        # ── Optional (either auth method) ────────────────────────────────────
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\Temp\AppRegistrations_CertificatesExpirationReport_$currentDateTime.CSV",

        [Parameter(Mandatory = $false)]
        [int]$ExpiredLastDays = 30,

        [Parameter(Mandatory = $false)]
        [int]$ExpiringNextDays = 60,

        # ── Help ──────────────────────────────────────────────────────────────
        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    # ── Help: show friendly guide and exit ───────────────────────────────────
    if ($ShowHelp)
    {
        Show-FriendlyHelp
        return
    }

    # ── Validate the chosen authentication method ────────────────────────────
    if ($PSCmdlet.ParameterSetName -eq "Token" -and -not $AccessToken)
    {
        Write-Error "AccessToken is required. Please provide a valid Bearer token."
        return
    }

    if ($PSCmdlet.ParameterSetName -eq "AppAuth")
    {
        if (-not (Get-Command Connect-EntraID -ErrorAction SilentlyContinue))
        {
            Write-Error @"
Connect-EntraID function not found.
To use app-only authentication, you need the Connect-EntraID.ps1 helper script.
Download it from:
  https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

Then dot-source it in your session before calling this function, e.g.:
  . .\Connect-EntraID.ps1
"@
            return
        }

        Write-Verbose "Authenticating via app-only client credentials for tenant $TenantId"

        $AccessToken = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId -RefreshInterval $RefreshInterval

        if (-not $AccessToken)
        {
            Write-Error "Failed to obtain an access token via Connect-EntraID. See error above for details."
            return
        }
    }

    $currentDateTime = Get-Date -Format "yyyyMMdd-HHmmss"
    Clear-Host

    # Display Banner
    Write-Host ""
    Write-Host "============================================================================================================== " -ForegroundColor Cyan
    Write-Host "                                      App Registration Certificate Report                                       " -ForegroundColor Yellow
    Write-Host "============================================================================================================== " -ForegroundColor Cyan
    Write-Host "This script retrieves Entra ID App Registrations and generates a report for certificates that have recently     " -ForegroundColor Green
    Write-Host "expired (last $ExpiredLastDays days) or will expire soon (within $ExpiringNextDays days).                       " -ForegroundColor Green
    Write-Host "                                                                                                               " 
    Write-Host "Authentication:                                                                                                " -ForegroundColor White
    Write-Host "- Option A: -AccessToken (bring your own bearer token)                                                         " -ForegroundColor White
    Write-Host "- Option B: -ClientId / -ClientSecret / -TenantId (app-only, via Connect-EntraID.ps1)                          " -ForegroundColor White
    Write-Host "                                                                                                               " 
    Write-Host "Other Parameters:                                                                                              " -ForegroundColor White
    Write-Host "- OutputPath: Path to save the report (Optional)                                                               " -ForegroundColor White
    Write-Host "- ExpiredLastDays: Number of days to check for expired certificates (Optional, default 30 days)                 " -ForegroundColor White
    Write-Host "- ExpiringNextDays: Number of days to check for certificates expiring soon (Optional, default 60 days)          " -ForegroundColor White
    Write-Host "                                                                                                               " 
    Write-Host "Note: Ensure you have the necessary Microsoft Graph API permissions.                                           " -ForegroundColor Yellow
    Write-Host "============================================================================================================== " -ForegroundColor Cyan
    Write-Host ""

    # Ensure Output Directory Exists
    $outputDir = Split-Path -Parent $OutputPath
    If ((Test-Path $outputDir) -eq $false) 
    {
        New-Item -Path $outputDir -ItemType "Directory" | Out-Null
    }

    # Define an empty array to hold all applications
    $allApps = New-Object System.Collections.ArrayList
    $totalApps = 0

    # Define the initial URI to retrieve applications with keyCredentials
    $uri = "https://graph.microsoft.com/beta/applications?`$top=500&`$select=id,appId,displayName,notes,keyCredentials&`$count=true"

    # Start a do-while loop to handle pagination
    do 
    {
        # If authenticated via app-only credentials, pull a fresh token each page —
        # Connect-EntraID silently renews only if it's actually close to expiry, so
        # this is cheap to call every iteration and protects large tenants whose
        # pagination can outlast a single token's lifetime.
        if ($PSCmdlet.ParameterSetName -eq "AppAuth")
        {
            $AccessToken = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId -RefreshInterval $RefreshInterval
        }

        $headers = @{
            "Authorization"    = "Bearer $AccessToken"
            "ConsistencyLevel" = "eventual"
        }

        do 
        {
            Try 
            {
                $partialData = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                $statusCode = $partialData.StatusCode
            }
            catch 
            {
                $statusCode = $_.Exception.Response.StatusCode
                $ErrorObject = $_

                if($statusCode -eq 429) 
                {
                    $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                    Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                    Start-Sleep -Seconds $sleepTime
                }
                else 
                {
                    $ErrorOutput = [PSCustomObject][ordered]@{
                        Response    = $($ErrorObject.Exception.Response)
                        StatusCode  = $($ErrorObject.Exception.Response.StatusCode)
                        Message     = $($ErrorObject.Exception.Message)
                    }
                    $ErrorOutput | Format-List
                    [boolean]$Skip = $true
                }
            }
        } until(($statusCode -eq 200) -or ([boolean]$Skip = $true))

        if($partialData) 
        {
            $AppsData = $partialData.content | ConvertFrom-Json
        }

        Write-Host "[$(Get-Date -Format "HH:mm:ss")] Progress: $($totalApps += $AppsData.value.Count; $totalApps) Applications retrieved so far" -ForegroundColor Cyan

        if ($AppsData.PSObject.Properties['@odata.nextLink']) { $uri = $AppsData.'@odata.nextLink' }
        $AppsData.value | ForEach-Object { $null = $allApps.Add($_) }

    } until (-not($AppsData.PSObject.Properties['@odata.nextLink']))

    # Process Certificates
    $consolidatedData = @()

    foreach ($app in $allApps)
    {
        $currentDate = Get-Date
        $matchedCerts = @()

        foreach ($cert in $app.keyCredentials)
        {
            $certEndDate = $cert.endDateTime
            $certStartDate = $cert.startDateTime
            $certTimeSpan = New-TimeSpan -Start $currentDate -End $certEndDate
            $certExpiresInDays = [math]::Round($certTimeSpan.TotalDays)

            $expiredInLastXDays = $certEndDate -gt ($currentDate.AddDays(-$ExpiredLastDays)) -and $certEndDate -lt $currentDate
            $expiringInNextXDays = $certEndDate -gt $currentDate -and $certEndDate -lt ($currentDate.AddDays($ExpiringNextDays))

            if ($expiredInLastXDays -or $expiringInNextXDays)
            {
                $ExpirationStatus = switch ($certExpiresInDays) 
                {
                    { $_ -lt 0 }   { "Expired"; break }
                    { $_ -le 7 }   { "Critical (<7 days)"; break }
                    { $_ -le 30 }  { "High (<30 days)"; break }
                    { $_ -le 60 }  { "Medium (30 - 60 days)"; break }
                    { $_ -le 90 }  { "Low (60 - 90 days)"; break }
                    default        { "Beyond 90 Days" }
                }

                $thumbprintString = ""
                if ($cert.customKeyIdentifier -is [byte[]]) {
                    $thumbprintString = [System.BitConverter]::ToString($cert.customKeyIdentifier).Replace("-", "")
                }

                $matchedCerts += [PSCustomObject]@{
                    CertificateId     = $cert.keyId
                    StartDate         = $certStartDate
                    EndDate           = $certEndDate
                    Thumbprint        = $thumbprintString
                    CertificateType   = $cert.type
                    Usage             = $cert.usage
                    certDisplayName   = $cert.displayName
                    ExpirationStatus  = $ExpirationStatus
                    ExpiresInDays     = $certExpiresInDays
                }
            }
        }

        if ($matchedCerts.Count -gt 0)
        {
            $consolidatedData += [PSCustomObject]@{
                AppId              = $app.appId
                DisplayName        = $app.displayName
                CertificateId      = ($matchedCerts | ForEach-Object { $_.CertificateId }) -join "; "
                StartDate          = ($matchedCerts | ForEach-Object { $_.StartDate }) -join "; "
                EndDate            = ($matchedCerts | ForEach-Object { $_.EndDate }) -join "; "
                Thumbprint         = ($matchedCerts | ForEach-Object { $_.Thumbprint }) -join "; "
                CertificateType    = ($matchedCerts | ForEach-Object { $_.CertificateType }) -join "; "
                Usage              = ($matchedCerts | ForEach-Object { $_.Usage }) -join "; "
                certDisplayName    = ($matchedCerts | ForEach-Object { $_.certDisplayName }) -join "; "
                ExpirationStatus   = ($matchedCerts | ForEach-Object { $_.ExpirationStatus }) -join "; "
                "Expires In (Days)"= ($matchedCerts | ForEach-Object { $_.ExpiresInDays }) -join "; "
                Notes              = $app.notes
            }
        }
    }

    $consolidatedData | Sort-Object {[int]($_.'Expires In (Days)' -split ';')[0].Trim()} | Export-Csv -Path $OutputPath -NoTypeInformation -Force
    Write-Host "Certificate expiration details exported to $OutputPath" -ForegroundColor Green
}
