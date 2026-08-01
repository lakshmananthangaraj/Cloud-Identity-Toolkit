<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 01 August 2026
Modified-On     : 01 August 2026

.SYNOPSIS
    Lists discovered vulnerabilities (CVEs) from Microsoft Defender Threat & Vulnerability
    Management.

.DESCRIPTION
    This function queries the Microsoft Defender for Endpoint native API
    (api.securitycenter.microsoft.com) /api/vulnerabilities endpoint to retrieve the current
    vulnerability catalog known to Threat & Vulnerability Management (TVM), including CVSS
    score, severity, and public exploit indicators.

    IMPORTANT - SEPARATE TOKEN AUDIENCE:
    This API is NOT part of Microsoft Graph. It requires a Bearer token issued for the
    resource https://api.securitycenter.microsoft.com, which is a different token audience
    than graph.microsoft.com. A Graph token (e.g. one obtained for Get-AllUsers or the other
    Defender/security functions in this toolkit) will NOT work here and will return 401.
    See .LINK below for how to acquire an app-only token against this resource.

    It handles pagination automatically via @odata.nextLink, retries on API throttling
    (HTTP 429) using the Retry-After header, and validates the JSON response before
    processing it further.

    Results can optionally be exported to CSV.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token issued for the resource https://api.securitycenter.microsoft.com.
    Required application permission (in the WindowsDefenderATP API, not Graph):
        Vulnerability.Read.All

.PARAMETER Severity
    Optional. Filters vulnerabilities by severity.
    Supported values:
        Low, Medium, High, Critical

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
        An array of custom objects containing selected vulnerability catalog attributes.
        Also optionally exports to CSV.

.EXAMPLE
    Get-M365DefenderVulnerabilities -AccessToken $defenderToken

    Retrieves the full vulnerability catalog known to TVM.

.EXAMPLE
    Get-M365DefenderVulnerabilities -AccessToken $defenderToken -Severity Critical -ExportFormat CSV -ExportPath "C:\Reports\CriticalVulnerabilities.csv"

    Retrieves only Critical-severity vulnerabilities and exports them to CSV.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (01-Aug-2026)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Defender for Endpoint access token (resource:
                https://api.securitycenter.microsoft.com) with the following
                application permission: Vulnerability.Read.All

        2. Threat & Vulnerability Management must be enabled/licensed for the tenant.

        3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - THIS IS NOT A GRAPH ENDPOINT. Do not reuse a graph.microsoft.com Bearer token
            here — it must be requested against api.securitycenter.microsoft.com.
        - This function returns the TVM vulnerability CATALOG (one row per CVE), not a
            per-device breakdown of which of your machines are exposed to each CVE, and
            it does NOT include remediation/patch guidance. exposedMachines gives a count
            only. Per-device exposure lives under /api/machines/{machineId}/vulnerabilities
            and remediation guidance lives under the separate /api/recommendations
            endpoint — both are candidates for a future companion function
            (e.g. Get-DeviceVulnerabilityExposure.ps1) rather than being folded in here.
        - -Severity is applied client-side after retrieval, not as a server-side $filter.
        - description text is returned as-is from Microsoft's catalog and can be long;
            consider post-processing/truncating before reporting to non-technical audiences.
        - SINGLE-TOKEN, SEQUENTIAL PAGINATION: this function uses one static Bearer token
            for the entire pagination run and does not refresh it mid-run. The full catalog
            can be large — narrow with -Severity for faster, more reliable pulls.

.LINK
    Microsoft Defender for Endpoint API - List vulnerabilities
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/get-all-vulnerabilities

.LINK
    Microsoft Defender for Endpoint API - Get access with application context (token audience)
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/exposed-apis-create-app-webapp

#>


Function Get-M365DefenderVulnerabilities
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [ValidateSet("Low", "Medium", "High", "Critical")]
        [string]$Severity,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    if ($ExportPath -and ($ExportPath -match '\.\.[\\/]'))
    {
        Write-Error "ExportPath contains path-traversal characters and was rejected. Exiting function."
        return
    }

    $allVulnerabilities = New-Object System.Collections.ArrayList
    $totalVulnerabilities = 0

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $uri = "https://api.securitycenter.microsoft.com/api/vulnerabilities"

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

            if ($statusCode -eq 429)
            {
                $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                Start-Sleep -Seconds $sleepTime
                continue
            }
            else
            {
                $ErrorOutput = [PSCustomObject][ordered]@{
                    Response   = $($ErrorObject.Exception.Response)
                    StatusCode = $($ErrorObject.Exception.Response.StatusCode)
                    Message    = $($ErrorObject.Exception.Message)
                }
                $ErrorOutput | Format-List
                return
            }
        }

        if ($partialData)
        {
            $vulnData = $partialData.Content | ConvertFrom-Json
        }

        $vulnData.value | ForEach-Object {

            $vuln = $_

            if ($Severity -and ($vuln.severity -ne $Severity)) { return }

            $null = $allVulnerabilities.Add(
                [PSCustomObject][ordered]@{
                    id               = $vuln.id
                    name             = $vuln.name
                    description      = $vuln.description
                    severity         = $vuln.severity
                    cvssV3           = $vuln.cvssV3
                    exposedMachines  = $vuln.exposedMachines
                    publishedOn      = $vuln.publishedOn
                    updatedOn        = $vuln.updatedOn
                    publicExploit    = $vuln.publicExploit
                    exploitVerified  = $vuln.exploitVerified
                    exploitInKit     = $vuln.exploitInKit
                    exploitUris      = if ($vuln.exploitUris) { $vuln.exploitUris -join "; " } else { $null }
                }
            )
        }

        $totalVulnerabilities += $vulnData.value.Count
        Write-Host "Progress: $totalVulnerabilities vulnerability record(s) retrieved so far" -ForegroundColor Cyan

        if ($vulnData.PSObject.Properties['@odata.nextLink']) { $uri = $vulnData.'@odata.nextLink' } else { $uri = $null }

    } until (-not $uri)

    if ($ExportFormat -eq "CSV" -and $ExportPath)
    {
        $allVulnerabilities | Export-Csv -Path $ExportPath -NoTypeInformation -Force
        Write-Host ""
        Write-Host "Vulnerability report exported successfully -> $ExportPath" -ForegroundColor Green
    }

    return $allVulnerabilities
}
