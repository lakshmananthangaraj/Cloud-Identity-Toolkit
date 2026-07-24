<#

Author          : Lakshmanan Thangaraj
Version         : 2.0
Created-On      : 30 July 2024
Modified-On     : 24 July 2026

.SYNOPSIS
    Retrieves Azure AD Application Proxy application details using Microsoft Graph API.

.DESCRIPTION
    This function retrieves detailed configuration information for Azure AD Application Proxy-enabled
    applications using Microsoft Graph beta endpoints.

    It processes multiple application Object IDs, validates existence, retrieves application configuration,
    and extracts on-premises publishing settings including URLs, authentication settings, and session behavior.

    The function supports progress tracking, error handling, and optional export to CSV or JSON formats.

    This function only accepts a direct Bearer token (AccessToken). It does not perform authentication
    itself. If you need to obtain a token via app-only (client credentials) authentication, use the
    companion Connect-EntraID.ps1 script referenced under .LINK below, then pass its returned token
    into -AccessToken.

    The following application proxy attributes are collected:
        - Object-Id, ApplicationId, DisplayName, publisherDomain, signInAudience
        - redirectUris, homePageUrl, logoutUrl
        - implicitGrantSettings (idToken and accessToken issuance)
        - externalUrl, internalUrl, alternateUrl
        - externalAuthenticationType
        - Cookie settings (HttpOnly, Secure, Persistent)
        - Backend certificate validation
        - Application server timeout
        - Application type, ZTNA client access, DNS resolution
        - Verified custom domain certificates and credentials
        - Segments configuration, single sign-on settings
        - On-premises application segments

.PARAMETER ObjectId
    One or more Azure AD Application Object IDs to retrieve details for.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions: 
        Application.Read.All
        Directory.Read.All

    To obtain this token via app-only authentication instead of an interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values: 
        CSV
        JSON

.PARAMETER OutputPath
    File path where the exported output (CSV or JSON) will be saved.

.PARAMETER ShowHelp
    Displays a friendly, plain-language usage guide and exits immediately.
    No authentication is attempted and no other parameters are required
    when this switch is used.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
        An array of custom objects containing Application Proxy details for
        each processed application. Also optionally exports to CSV or JSON.

.EXAMPLE
    Get-AppProxyApplicationDetails -ObjectId $ids -AccessToken $token

    Retrieves Application Proxy details for the specified applications.

.EXAMPLE
    Get-AppProxyApplicationDetails -ObjectId $ids -AccessToken $token -ExportFormat CSV -OutputPath "C:\Reports\AppProxy.csv"

    Retrieves data and exports results to a CSV file.

.EXAMPLE
    Get-AppProxyApplicationDetails -ObjectId $ids -AccessToken $token -ExportFormat JSON -OutputPath "C:\Reports\AppProxy.json"

    Retrieves data and exports results in JSON format.

.EXAMPLE
    Get-AppProxyApplicationDetails -ShowHelp

    Displays the friendly usage guide and exits.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (30-Jul-2024)  - Initial release
        2.0 (24-Jul-2026)  - Added -ShowHelp switch for friendly usage guide
                            - Updated documentation to standard template
                            - Added .LINK reference to Connect-EntraID.ps1

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                Application.Read.All (Application)
                Directory.Read.All   (Application)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Functions:
    ─────────────────────────────────────────────────────────────────────────────
        Show-FriendlyHelp
            Prints a plain-language usage guide (parameters, examples,
            prerequisites) via Write-Host, then returns control to the
            caller so the function can exit early.

        Get-AppProxyApplicationDetails
            Main function that retrieves and exports Application Proxy details.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 0  →  If -ShowHelp was supplied, print the friendly guide and exit
        Step 1  →  Validate each ObjectId exists
        Step 2  →  Retrieve detailed application configuration
        Step 3  →  Extract onPremisesPublishing settings
        Step 4  →  Export to CSV or JSON (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The function uses the /beta Graph API endpoint. Beta endpoints are
            subject to change and are not recommended for production without
            monitoring for breaking changes.
        - Requires a valid bearer token with the specified permissions.
        - Processes applications sequentially; large datasets may impact
            performance.

.LINK
    Microsoft Graph API - Application resource type
    https://learn.microsoft.com/en-us/graph/api/resources/application

.LINK
    Application Proxy documentation
    https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-AppProxyApplicationDetails
{
    [CmdletBinding(DefaultParameterSetName = 'Run')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Run')]
        [string[]]$ObjectId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Run')]
        [string]$AccessToken,

        [Parameter(ParameterSetName = 'Run')]
        [ValidateSet("CSV","JSON")]
        [string]$ExportFormat,

        [Parameter(ParameterSetName = 'Run')]
        [string]$OutputPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Help')]
        [switch]$ShowHelp
    )

    #--------------------------------------------------------------------------------------------------- [ Friendly Help ]

    Function Show-FriendlyHelp
    {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║         Entra ID — Application Proxy Details Report          ║" -ForegroundColor Cyan
        Write-Host "  ║                   Version 2.0  |  Help                       ║" -ForegroundColor Cyan
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  What this function does:" -ForegroundColor Yellow
        Write-Host "    Retrieves detailed Application Proxy configuration for one or more"
        Write-Host "    Entra ID applications via Microsoft Graph API and exports the"
        Write-Host "    results to CSV or JSON format."
        Write-Host ""
        Write-Host "  Required parameters:" -ForegroundColor Yellow
        Write-Host "    -ObjectId      One or more Azure AD Application Object IDs"
        Write-Host "    -AccessToken   Valid OAuth 2.0 Bearer token for Microsoft Graph API"
        Write-Host ""
        Write-Host "  Optional parameters:" -ForegroundColor Yellow
        Write-Host "    -ExportFormat  CSV or JSON (default: none)"
        Write-Host "    -OutputPath    File path for the exported report"
        Write-Host "    -ShowHelp      Shows this guide and exits"
        Write-Host ""
        Write-Host "  Before you run it:" -ForegroundColor Yellow
        Write-Host "    1. Obtain a Microsoft Graph access token with these permissions:"
        Write-Host "         Application.Read.All, Directory.Read.All"
        Write-Host "    2. Use Connect-EntraID.ps1 to get an app-only token:"
        Write-Host "         https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1"
        Write-Host ""
        Write-Host "  Example:" -ForegroundColor Yellow
        Write-Host '    $token = .\Connect-EntraID.ps1 -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"'
        Write-Host '    Get-AppProxyApplicationDetails -ObjectId @("id1","id2") -AccessToken $token -ExportFormat CSV -OutputPath "C:\Reports\AppProxy.csv"'
        Write-Host ""
        Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
        Write-Host "     Get-Help Get-AppProxyApplicationDetails -Full"
        Write-Host ""
    }

    if ($ShowHelp)
    {
        Show-FriendlyHelp
        return
    }

    #--------------------------------------------------------------------------------------------------- [ Script Execution ]

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "      App Proxy Application Details Extraction Tool         " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Starting extraction process...                              " -ForegroundColor Yellow
    Write-Host ""

    # Define the request headers with the access token
    $headers = @{
        "Authorization"    = "Bearer $AccessToken"
        "ConsistencyLevel" = "eventual"
    }

    $Results = @()

    $total = $ObjectId.Count
    $current = 0

    Write-Host "Total Applications to Process : $total" -ForegroundColor Green

    foreach ($Id in $ObjectId)
    {
        $current++
        $percentComplete = [int](($current / $total) * 100)

        Write-Progress -Activity "Retrieving App Proxy Application Details" -Status "Processing $current of $total : $Id" -PercentComplete $percentComplete

        try
        {
            $appCheck = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/applications/$($Id)?`$select=id" -Headers $headers -Method Get   
        }
        catch
        {
            if ($_.Exception.Response.StatusCode -match "NotFound") 
            {
                Write-Host "Application or Resource does not exist or one of its queried reference-property `"$($Id)`" objects are not present" -ForegroundColor Red
                continue
            }
            else 
            {
                $ErrorOutput1 = [PSCustomObject][ordered]@{
                    Response    = $_.Exception.Response.ResponseUri.OriginalString
                    StatusCode  = $_.Exception.Response.StatusCode
                    Message     = $_.Exception.Message
                }
                $ErrorOutput1 | Format-List
                continue
            }
        }

        try 
        {
            $appDetail = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/applications/$($Id)?`$select=id,appId,displayName,publisherDomain,signInAudience,web,onPremisesPublishing" -Headers $headers -Method Get
            
            if ($appDetail.onPremisesPublishing -ne $null -and $appDetail.onPremisesPublishing) 
            {
                $formattedApp = [PSCustomObject]@{
                    'Object-Id'                                       = $appDetail.id
                    'ApplicationId'                                   = $appDetail.appId
                    'DisplayName'                                     = $appDetail.displayName
                    'publisherDomain'                                 = $appDetail.publisherDomain
                    'signInAudience'                                  = $appDetail.signInAudience
                    'redirectUris'                                    = $appDetail.web.redirectUris -join ", "
                    'homePageUrl'                                     = $appDetail.web.homePageUrl
                    'logoutUrl'                                       = $appDetail.web.logoutUrl
                    'implicitGrantSettings-enableIdTokenIssuance'     = $appDetail.web.implicitGrantSettings.enableIdTokenIssuance
                    'implicitGrantSettings-enableAccessTokenIssuance' = $appDetail.web.implicitGrantSettings.enableAccessTokenIssuance
                    'externalUrl'                                     = $appDetail.onPremisesPublishing.externalUrl
                    'internalUrl'                                     = $appDetail.onPremisesPublishing.internalUrl
                    'alternateUrl'                                    = $appDetail.onPremisesPublishing.alternateUrl
                    'externalAuthenticationType'                      = $appDetail.onPremisesPublishing.externalAuthenticationType
                    'isTranslateHostHeaderEnabled'                    = $appDetail.onPremisesPublishing.isTranslateHostHeaderEnabled
                    'isTranslateLinksInBodyEnabled'                   = $appDetail.onPremisesPublishing.isTranslateLinksInBodyEnabled
                    'isOnPremPublishingEnabled'                       = $appDetail.onPremisesPublishing.isOnPremPublishingEnabled
                    'isHttpOnlyCookieEnabled'                         = $appDetail.onPremisesPublishing.isHttpOnlyCookieEnabled
                    'isSecureCookieEnabled'                           = $appDetail.onPremisesPublishing.isSecureCookieEnabled
                    'isPersistentCookieEnabled'                       = $appDetail.onPremisesPublishing.isPersistentCookieEnabled
                    'isBackendCertificateValidationEnabled'           = $appDetail.onPremisesPublishing.isBackendCertificateValidationEnabled
                    'applicationServerTimeout'                        = $appDetail.onPremisesPublishing.applicationServerTimeout
                    'useAlternateUrlForTranslationAndRedirect'        = $appDetail.onPremisesPublishing.useAlternateUrlForTranslationAndRedirect
                    'applicationType'                                 = $appDetail.onPremisesPublishing.applicationType
                    'isStateSessionEnabled'                           = $appDetail.onPremisesPublishing.isStateSessionEnabled
                    'isAccessibleViaZTNAClient'                       = $appDetail.onPremisesPublishing.isAccessibleViaZTNAClient
                    'isDnsResolutionEnabled'                          = $appDetail.onPremisesPublishing.isDnsResolutionEnabled
                    'verifiedCustomDomainCertificatesMetadata'        = $appDetail.onPremisesPublishing.verifiedCustomDomainCertificatesMetadata
                    'verifiedCustomDomainKeyCredential'               = $appDetail.onPremisesPublishing.verifiedCustomDomainKeyCredential
                    'verifiedCustomDomainPasswordCredential'          = $appDetail.onPremisesPublishing.verifiedCustomDomainPasswordCredential
                    'segmentsConfiguration'                           = $appDetail.onPremisesPublishing.segmentsConfiguration
                    'singleSignOnSettings'                            = $appDetail.onPremisesPublishing.singleSignOnSettings | ConvertTo-Json -Compress
                    'onPremisesApplicationSegments'                   = $appDetail.onPremisesPublishing.onPremisesApplicationSegments
                }

                $Results += $formattedApp
            }
            else 
            {
                Write-Host "Application proxy is not configured for Application ID: $Id" -ForegroundColor Yellow
            }
        }
        catch 
        {
            if ($_.Exception.Response.StatusCode -match "NotFound") 
            {
                Write-Host "Application proxy configuration not found or OnPremisesPublishing is not enabled for ApplicationId: $($Id)" -ForegroundColor Red
            }
            else 
            {
                Write-Host "Error retrieving details for ApplicationId: $($Id)" -ForegroundColor Red
                $ErrorOutput = [PSCustomObject][ordered]@{
                    Response    = $_.Exception.Response.ResponseUri.OriginalString
                    StatusCode  = $_.Exception.Response.StatusCode
                    Message     = $_.Exception.Message
                }
                $ErrorOutput | Format-List
            }
        }
    }

    Write-Progress -Activity "Retrieving App Proxy Application Details" -Completed

    # ===== Export Logic =====
    if ($ExportFormat -and $OutputPath)
    {
        # Ensure parent folder exists
        $folder = Split-Path -Path $OutputPath -Parent
        if (-not (Test-Path $folder)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
        }

        switch ($ExportFormat)
        {
            "CSV"  { $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
            "JSON" { $Results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8 }
        }

        Write-Host ""
        Write-Host "Results exported to $OutputPath" -ForegroundColor Green
    }

    # =========================
    # Completion Summary
    # =========================
    Write-Host ""
    Write-Host "Extraction Completed Successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "Total Applications Processed : $current" -ForegroundColor Green
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    #return $Results | Select-Object ApplicationId, DisplayName, publisherDomain, externalUrl, internalUrl, verifiedCustomDomainCertificatesMetadata, singleSignOnSettings | Out-GridView

    return $Results
}
