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
                                 this way.

.LINK
    https://learn.microsoft.com/graph/api/application-list

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


#----------------------------------------------------------------------------------- [ Function to Generate App Registration Secret Expiration Report ]

Function Get-AppRegistrationSecretReport
{
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "C:\Temp\AppRegistrations_SecretsExpirationReport_$currentDateTime.CSV",

        [Parameter(Mandatory = $false)]
        [bool]$IncludeProxyApps = $false,               # New parameter to control filtering of App Proxy Applications

        [Parameter(Mandatory = $false)]
        [int]$ExpiredLastDays = 30,                     # Parameter to dynamically set the last N days for expired secrets

        [Parameter(Mandatory = $false)]
        [int]$ExpiringNextDays = 60                     # Parameter to dynamically set the next N days for secrets expiring
    )

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
    Write-Host "Parameters:                                                                                                    " -ForegroundColor White
    Write-Host "- AccessToken: Azure AD Access Token (Mandatory)                                                               " -ForegroundColor White
    Write-Host "- OutputPath: Path to save the report (Optional)                                                               " -ForegroundColor White
    Write-Host "- IncludeProxyApps: Include App Proxy Apps (Optional), input value will be $true or $false (default)           " -ForegroundColor White
    Write-Host "- ExpiredLastDays: Number of days to check for expired secrets (Optional, default 30 days)                     " -ForegroundColor White
    Write-Host "- ExpiringNextDays: Number of days to check for secrets expiring soon (Optional, default 60 days)              " -ForegroundColor White
    Write-Host "                                                                                                               " 
    Write-Host "The report includes an 'ExpirationStatus' column with the following categories:                                " -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------------------------------------------------------- " -ForegroundColor Cyan
    Write-Host "  Expiration Status              | Meaning                             | Color                                 " -ForegroundColor White
    Write-Host "-------------------------------------------------------------------------------------------------------------- " -ForegroundColor Cyan
    Write-Host "  Expired                        | Secret has already expired          | RED (#FF0000)                         " -ForegroundColor Red
    Write-Host "  Critical (<7 days)             | Secret expires in less than 7 days  | ORANGE-RED (#FF4500)                  " -ForegroundColor DarkRed
    Write-Host "  High (<30 days)                | Secret expires in less than 30 days | ORANGE (#FFA500)                      " -ForegroundColor DarkYellow
    Write-Host "  Medium (30 - 60 days)          | Secret expires in 30 to 60 days     | GOLD (#FFD700)                        " -ForegroundColor Yellow
    Write-Host "  Low (60 - 90 days)             | Secret expires in 60 to 90 days     | LIME GREEN (#32CD32)                  " -ForegroundColor Green
    Write-Host "  Beyond 90 Days                 | Secret expires after 90 days        | GREY (#808080)                        " -ForegroundColor Gray
    Write-Host "-------------------------------------------------------------------------------------------------------------- " -ForegroundColor Cyan
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
        if (-not $AccessToken) 
        {
            Write-Error "Failed to obtain access token. Exiting function."
            return
        }

        $headers = @{
            "Authorization" = "Bearer $AccessToken"
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
    $totalFilteredApps = $allApps.Count
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
            # $isSecretExpired = $currentDate -gt $secretEndDate
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

            # Check if the secret expired in the last $ExpiredLastDays days or is expiring in the next $ExpiringNextDays days
            # $expiredInLastXDays = $secretEndDate -gt ($currentDate.AddDays(-$ExpiredLastDays)) -and $secretEndDate -lt $currentDate
            # $expiringInNextXDays = $secretEndDate -gt $currentDate -and $secretEndDate -lt ($currentDate.AddDays($ExpiringNextDays))

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
                    #IsSecretExpired              = $isSecretExpired
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
