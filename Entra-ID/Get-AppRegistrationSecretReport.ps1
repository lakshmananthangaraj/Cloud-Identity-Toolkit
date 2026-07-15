<#

.Author
    Name        : Lakshmanan Thangaraj
    Version     : 2.0
    Created-On  : 06 January 2025
    Modified-On : 15 July 2026

.SYNOPSIS
    Generates a report of Azure AD App Registration client secrets and their expiration status.

.DESCRIPTION
    This function retrieves Azure AD application registrations and analyzes their client secrets
    (passwordCredentials) to generate an expiration report.

    It identifies secrets that are:
    - Expired within a configurable past window
    - Expiring within a configurable future window

    The function supports optional filtering of App Proxy applications, pagination handling,
    and API throttling management. It also classifies secrets into multiple expiration severity levels.

    The final output is exported as a CSV report.

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
    C:\Temp\AppRegistrations_SecretsExpirationReport_<timestamp>.CSV

.PARAMETER IncludeProxyApps
    Indicates whether App Proxy applications should be included in the report.

    Default: $false

.PARAMETER ExpiredLastDays
    Number of past days used to identify recently expired secrets.

    Default: 30

.PARAMETER ExpiringNextDays
    Number of future days used to identify secrets nearing expiration.

    Default: 60

.PARAMETER ShowHelp
    Prints a plain-language usage guide and exits — no connection is made.

.EXAMPLE
    Get-AppRegistrationSecretReport -ShowHelp

    Displays a friendly, plain-language summary of parameters and usage
    without connecting to Microsoft Graph.

.EXAMPLE
    Get-AppRegistrationSecretReport -AccessToken $token

    Generates a client secret expiration report with default settings, using
    a manually supplied bearer token (Option A).

.EXAMPLE
    Get-AppRegistrationSecretReport -AccessToken $token -IncludeProxyApps $true

    Includes App Proxy applications in the report.

.EXAMPLE
    Get-AppRegistrationSecretReport -AccessToken $token -ExpiredLastDays 15 -ExpiringNextDays 90

    Customizes expiration evaluation thresholds.

.EXAMPLE
    $token = Get-AccessToken
    Get-AppRegistrationSecretReport -AccessToken $token -OutputPath "C:\Reports\Secrets.csv"

    Generates and exports the report to a custom path.

.EXAMPLE
    . .\Connect-EntraID.ps1
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-AppRegistrationSecretReport -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"

    Authenticates automatically via app-only client credentials (Option B) —
    no manual token copy-paste needed. Ideal for scheduled/unattended runs.

.NOTES
    Key Features:
    - Retrieves App Registrations from Microsoft Graph beta endpoint
    - Analyzes client secrets (passwordCredentials)
    - Classifies expiration status into severity levels (Critical, High, Medium, Low, Expired)
    - Supports optional App Proxy filtering
    - Handles pagination and API throttling (Retry-After logic)
    - Exports results to CSV format
    - Includes progress tracking during execution
    - Supports two authentication modes: bring-your-own bearer token (Option A),
      or app-only client credentials via Connect-EntraID.ps1 (Option B)

    Limitations:
    - Requires either a valid Microsoft Graph access token, or app registration
      credentials (-ClientId/-ClientSecret/-TenantId) for app-only auth
    - Uses beta Graph API endpoints
    - Large tenants may result in longer execution time
    - Secret hint values are limited metadata only (no actual secret value exposed)

    To use app-only authentication, download Connect-EntraID.ps1 from the link below.

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (06 Jan 2025)      - Initial release: bearer-token auth, pagination,
                                 throttling handling, CSV export.
        2.0 (15 Jul 2026)      - Added app-only authentication support via
                                 Connect-EntraID.ps1 (-ClientId/-ClientSecret/
                                 -TenantId), as an alternative to supplying a
                                 raw -AccessToken. Long-running pagination now
                                 silently renews the token when authenticated
                                 this way. Added -ShowHelp guide. Fixed a bug
                                 where $nonProxyApps was undefined when
                                 -IncludeProxyApps was set to $true.

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
    Write-Host "  ║          Get-AppRegistrationSecretReport  v2.0               ║" -ForegroundColor Cyan
    Write-Host "  ║                   Friendly Help Guide                        ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this does:" -ForegroundColor Yellow
    Write-Host "    Scans every Entra ID App Registration in your tenant for client"
    Write-Host "    secrets that have recently expired or are expiring soon, and"
    Write-Host "    exports the results to a CSV report."
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
    Write-Host "    -IncludeProxyApps  Include App Proxy applications (default: `$false)"
    Write-Host "    -ExpiredLastDays   Look-back window for recently expired secrets (default: 30)"
    Write-Host "    -ExpiringNextDays  Look-ahead window for soon-to-expire secrets (default: 60)"
    Write-Host "    -ShowHelp          Shows this guide and exits, nothing is generated"
    Write-Host ""
    Write-Host "  Example (Option A):" -ForegroundColor Yellow
    Write-Host '    Get-AppRegistrationSecretReport -AccessToken $token'
    Write-Host ""
    Write-Host "  Example (Option B):" -ForegroundColor Yellow
    Write-Host '    . .\Connect-EntraID.ps1'
    Write-Host '    $secret = Read-Host -Prompt "Client secret" -AsSecureString'
    Write-Host '    Get-AppRegistrationSecretReport -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
    Write-Host ""
    Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
    Write-Host "     Get-Help Get-AppRegistrationSecretReport -Full"
    Write-Host ""
}


#----------------------------------------------------------------------------------- [ Function to Generate App Registration Secret Expiration Report ]

Function Get-AppRegistrationSecretReport
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
        [string]$OutputPath = "C:\Temp\AppRegistrations_SecretsExpirationReport_$currentDateTime.CSV",

        [Parameter(Mandatory = $false)]
        [bool]$IncludeProxyApps = $false,               # New parameter to control filtering of App Proxy Applications

        [Parameter(Mandatory = $false)]
        [int]$ExpiredLastDays = 30,                     # Parameter to dynamically set the last N days for expired secrets

        [Parameter(Mandatory = $false)]
        [int]$ExpiringNextDays = 60,                     # Parameter to dynamically set the next N days for secrets expiring

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

    # Display a banner with basic information about the script
    Write-Host ""
    Write-Host "============================================================================================================== " -ForegroundColor Cyan
    Write-Host "                                      App Registration Secret Report                                           " -ForegroundColor Yellow
    Write-Host "============================================================================================================== " -ForegroundColor Cyan
    Write-Host "This script retrieves Entra ID App Registrations and generates a report for secrets that have recently expired " -ForegroundColor Green
    Write-Host "(last $ExpiredLastDays days) or will expire soon (within $ExpiringNextDays days).                              " -ForegroundColor Green
    Write-Host "                                                                                                               " 
    Write-Host "Authentication:                                                                                                " -ForegroundColor White
    Write-Host "- Option A: -AccessToken (bring your own bearer token)                                                         " -ForegroundColor White
    Write-Host "- Option B: -ClientId / -ClientSecret / -TenantId (app-only, via Connect-EntraID.ps1)                          " -ForegroundColor White
    Write-Host "                                                                                                               " 
    Write-Host "Other Parameters:                                                                                              " -ForegroundColor White
    Write-Host "- OutputPath: Path to save the report (Optional)                                                               " -ForegroundColor White
    Write-Host "- IncludeProxyApps: Include App Proxy Apps (Optional), input value will be $true or $false (default)           " -ForegroundColor White
    Write-Host "- ExpiredLastDays: Number of days to check for expired secrets (Optional, default 30 days)                     " -ForegroundColor White
    Write-Host "- ExpiringNextDays: Number of days to check for secrets expiring soon (Optional, default 60 days)              " -ForegroundColor White
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

    # Define an empty array to hold all service principals
    $allApps = New-Object System.Collections.ArrayList
    $totalApps = 0

    # Define the initial URI to retrieve all service principals with select options
    $uri = "https://graph.microsoft.com/beta/applications?`$top=500&`$select=id,appId,displayName,notes,passwordCredentials&`$count=true"

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

        Write-Host "[$(Get-Date -Format "HH:mm:ss")] Progress: $($totalApps += $AppsData.value.Count; $totalApps) App Registrations retrieved so far" -ForegroundColor Cyan

        if ($AppsData.PSObject.Properties['@odata.nextLink']) { $uri = $AppsData.'@odata.nextLink' }
        $AppsData.value | ForEach-Object { $null = $allApps.Add($_) }

    } until (-not($AppsData.PSObject.Properties['@odata.nextLink']))

    # Default: assume no proxy filtering happens, so $nonProxyApps always has a value
    # (fixes a bug where -IncludeProxyApps $true left $nonProxyApps undefined)
    $nonProxyApps = $allApps

    # Filter App Proxy Applications if IncludeProxyApps is false
    if (-not $IncludeProxyApps)
    {
        Write-Host "[$(Get-Date -Format "HH:mm:ss")] Filtering App Proxy Applications" -ForegroundColor Yellow

        $proxyApps = @()
        $totalAppsToFilter = $allApps.Count
        $currentAppIndex = 0

        foreach ($app in $allApps) 
        {
            $currentAppIndex++
            $percentComplete = [math]::Round(($currentAppIndex / $totalAppsToFilter) * 100)

            Write-Progress -Activity "Filtering App Proxy Applications" -Status "Processing $currentAppIndex of $totalAppsToFilter ($percentComplete%)" -PercentComplete $percentComplete

            # Refresh token if authenticated via app-only credentials — this loop
            # can run long on large tenants (one detail call per app)
            if ($PSCmdlet.ParameterSetName -eq "AppAuth")
            {
                $AccessToken = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId -RefreshInterval $RefreshInterval
                $headers["Authorization"] = "Bearer $AccessToken"
            }

            try
            {
                $appProxyDetail = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/applications/$($app.id)?`$select=onPremisesPublishing" -Headers $headers -Method Get -ErrorAction SilentlyContinue

                if ($appProxyDetail -ne $null -and $appProxyDetail.onPremisesPublishing)
                {
                    Write-Host "Debug: App Proxy Application Detected: $($app.displayName)" -ForegroundColor Red
                    $proxyApps += $app
                }
            }
            catch { }
        }

        $nonProxyApps = $allApps | Where-Object { $_.id -notin $proxyApps.id }
        Write-Host "[$(Get-Date -Format "HH:mm:ss")] Filtering Completed." -ForegroundColor Green
        Write-Host "[$(Get-Date -Format "HH:mm:ss")] Total Proxy Apps Excluded: $($proxyApps.Count)" -ForegroundColor Green
        Write-Host "[$(Get-Date -Format "HH:mm:ss")] Total Non-Proxy Applications: $($nonProxyApps.Count)" -ForegroundColor Green
    }

    # Continue with existing logic for processing secrets
    $consolidatedData = @()
    $totalFilteredApps = $nonProxyApps.Count
    $currentFilteredAppIndex = 0

    Write-Host "[$(Get-Date -Format "HH:mm:ss")] Processing Secrets" -ForegroundColor Yellow

    foreach ($app in $nonProxyApps)
    {
        $currentFilteredAppIndex++
        $percentComplete = [math]::Round(($currentFilteredAppIndex / $totalFilteredApps) * 100)

        Write-Progress -Activity "Processing Secrets" -Status "Processing $currentFilteredAppIndex of $totalFilteredApps ($percentComplete%)" -PercentComplete $percentComplete

        foreach ($passwordCredential in $app.passwordCredentials)
        {
            $currentDate = Get-Date
            $secretEndDate = $passwordCredential.endDateTime
            $secretTimeSpan = New-TimeSpan -Start $currentDate -End $secretEndDate
            $secretExpiresInDays = [math]::Round($secretTimeSpan.TotalDays)

            # Determine Expiration Status
            $ExpirationStatus = switch ($secretExpiresInDays) 
            {
                { $_ -lt 0 }   { "Expired"; break }
                { $_ -le 7 }   { "Critical (<7 days)"; break }
                { $_ -le 30 }  { "High (<30 days)"; break }
                { $_ -le 60 }  { "Medium (30 - 60 days)"; break }
                { $_ -le 90 }  { "Low (60 - 90 days)"; break }
                default        { "Beyond 90 Days" }
            }

            # Safe values for AddDays (DateTime supports ~ -9999 to +9999 years)
            $safeExpiredLastDays  = [Math]::Min($ExpiredLastDays, 36500)   # Max 100 years
            $safeExpiringNextDays = [Math]::Min($ExpiringNextDays, 36500)  # Max 100 years

            $expiredInLastXDays  = $secretEndDate -gt ($currentDate.AddDays(-$safeExpiredLastDays)) -and $secretEndDate -lt $currentDate
            $expiringInNextXDays = $secretEndDate -gt $currentDate -and $secretEndDate -lt ($currentDate.AddDays($safeExpiringNextDays))

            if ($expiredInLastXDays -or $expiringInNextXDays)
            {
                $customReportItem = [PSCustomObject]@{
                    AppId                        = $app.appId
                    DisplayName                  = $app.displayName
                    EndDate                      = $secretEndDate
                    "Secret Hint"                = $passwordCredential.hint
                    ExpirationStatus             = $ExpirationStatus
                    "SecretExpiresIn (Days)"     = $secretExpiresInDays
                    Notes                        = $app.notes
                }

                $consolidatedData += $customReportItem
            }
        }
    }

    Write-Host "[$(Get-Date -Format "HH:mm:ss")] Secret Expiration Details Processing Completed." -ForegroundColor Green

    # Export to CSV
    $consolidatedData | Sort-Object {[int]$_.'SecretExpiresIn (Days)'} | Export-Csv -Path $OutputPath -NoTypeInformation -Force
    Write-Host "App Registrations details exported to $OutputPath" -ForegroundColor Green
}
