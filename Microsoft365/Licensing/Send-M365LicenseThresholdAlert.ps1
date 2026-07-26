<#

Author          : Lakshmanan Thangaraj
Version         : 2.1
Created-On      : 23 July 2025
Modified-On     : 26 July 2026

.SYNOPSIS
    Evaluates Microsoft 365 license consumption against defined thresholds and sends a modern HTML
    alert email via Microsoft Graph when any SKU falls at or below its configured availability threshold.

.DESCRIPTION
    Send-M365LicenseThresholdAlert evaluates license inventory (SkuPartNumber / TotalLicenses /
    UsedLicenses / UnusedLicenses) against per-SKU thresholds and, when one or more SKUs breach their
    threshold, sends a formatted HTML summary email via the Microsoft Graph sendMail API.

    Authentication is flexible — supply either:
    - A ready-made -AccessToken (e.g. copied from Graph Explorer, or obtained via Connect-MgGraph), for
      quick manual/ad-hoc runs, OR
    - -ClientId, -ClientSecret, and -TenantId, so the function authenticates itself via app-only client
      credentials using Connect-EntraID.ps1 under the hood — ideal for unattended/automated runs
      (Azure Automation, scheduled tasks, CI). Same pattern as Get-PIMActiveEntraIDRoleAssignmentDetails.

    License inventory is also flexible:
    - Pipe in the output of Get-M365LicenseInventory (or any object array with SkuPartNumber /
      TotalLicenses / UsedLicenses / UnusedLicenses) to evaluate a specific snapshot, OR
    - Omit -LicenseInventory entirely and the function retrieves it automatically by calling
      Get-M365LicenseInventory itself, using whichever authentication method you supplied. This is what
      makes a single unattended call possible without wiring the two functions together yourself.

    CHANGELOG:
      v2.1 - 26 July 2026 - Logging detail enhancement:
                            - Log file now records each execution stage instead of only 4 summary
                            lines: auth method/start, token acquisition, inventory fetch count,
                            threshold/email validation results, per-SKU evaluation detail, breach
                            detail per SKU, pre-send email summary, and a run-complete footer.
                            - No behavior change to evaluation/sending logic; console output unchanged
                            aside from the same new lines also appearing on screen.
                            - Log the configured -SkuThresholds key/value pairs (was only logging the
                            count). No other change.
      v2.0 - 26 July 2026 - Automation-focused rewrite:
                            - Added -ClientId/-ClientSecret/-TenantId app-only auth via Connect-EntraID.ps1.
                            - -LicenseInventory is now optional; if omitted, the function calls Get-M365LicenseInventory
                            itself (checked via Get-Command, with a friendly error + download link if not dot-sourced).
                            - Added -TenantName/-TenantId for email branding and -ShowHelp for a plain-language guide.
                            - Rewrote the alert email as an inline-styled, table-based HTML template (header band, KPI
                            chips, status-coded rows, footer) for a modern look that survives Outlook's HTML stripping.
                            - Non-breaking: existing -AccessToken + piped-inventory calls continue to work unchanged.
      v1.0 - 23 July 2025 - Initial private version.

.PARAMETER AccessToken
    Microsoft Graph bearer token. Used with the "Token" parameter set for ad-hoc/manual runs. Requires
    Mail.Send (plus whatever Get-M365LicenseInventory needs, if it ends up being called automatically).

.PARAMETER ClientId
    Application (client) ID of the Azure AD app registration, for app-only auth via Connect-EntraID.ps1.
    Use with -ClientSecret and -TenantId instead of -AccessToken for unattended runs.

.PARAMETER ClientSecret
    Client secret for the app registration, as a SecureString. Example:
    $secret = Read-Host -Prompt "Client secret" -AsSecureString

.PARAMETER TenantId
    Directory (tenant) ID. Required for app-only auth; optional (display-only, in the email footer) when
    using -AccessToken.

.PARAMETER RefreshInterval
    Minutes before expiry to proactively renew the token when using app-only auth. Default: 5.

.PARAMETER TenantName
    Display name shown in the alert email header/footer (e.g. "Contoso Ltd"). Cosmetic only.

.PARAMETER LicenseInventory
    Optional. License inventory objects to evaluate (e.g. output of Get-M365LicenseInventory), accepted
    via the pipeline. If omitted, the function retrieves inventory itself using Get-M365LicenseInventory
    and whichever authentication method you supplied.

.PARAMETER SkuThresholds
    Mandatory. Hashtable of minimum acceptable "percent free" per SKU part number.
    Format: @{ "SKU_PART_NUMBER" = <ThresholdPercent 0-100> }

.PARAMETER EmailTo
    Mandatory. One or more recipient addresses for the alert.

.PARAMETER EmailFrom
    Mandatory. Sender mailbox address; must be a mailbox the token is authorized to send as.

.PARAMETER CcAddress
    Optional. CC recipients.

.PARAMETER BccAddress
    Optional. BCC recipients.

.PARAMETER EmailSubject
    Optional. Default: "M365 License Threshold Alert".

.PARAMETER LogPath
    Optional. Defaults to "$env:TEMP\M365LicenseThresholdAlert_<timestamp>.log".

.PARAMETER ExportCsvPath
    Optional. Exports the full evaluation report (all monitored SKUs, not just breaches) to this CSV path.

.PARAMETER AlwaysSend
    Optional switch. By default the email only sends when at least one SKU breaches its threshold. Set
    this to send a status email every run, even when everything is healthy.

.PARAMETER PassThru
    Optional switch. Returns the evaluation report as objects, in addition to (or instead of, under
    -WhatIf) sending the email.

.PARAMETER ShowHelp
    Switch. Prints a plain-language usage guide and exits without evaluating or sending anything.

.INPUTS
    [PSCustomObject] License inventory objects via the pipeline (optional).

.OUTPUTS
    [PSCustomObject] Threshold-evaluation rows, only when -PassThru is specified.

.EXAMPLE
    # Display the built-in help guide with authentication methods, parameter descriptions,
    # and common usage examples without executing the function.

    Send-M365LicenseThresholdAlert -ShowHelp

.EXAMPLE
    # Authenticate using an Entra ID App Registration and automatically retrieve the
    # Microsoft 365 license inventory before evaluating thresholds.

    . .\Connect-EntraID.ps1

    $ClientSecret = Read-Host "Enter Client Secret" -AsSecureString

    $Thresholds = @{
        "ENTERPRISEPACK"    = 10
        "AAD_PREMIUM_P2"    = 5
        "POWER_BI_PRO"      = 15
    }

    Send-M365LicenseThresholdAlert `
        -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientSecret $ClientSecret `
        -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -TenantName "Contoso Ltd" `
        -SkuThresholds $Thresholds `
        -EmailTo "m365admin@contoso.com" `
        -EmailFrom "alerts@contoso.com"
    
.EXAMPLE
    # Fully unattended — no piping needed, retrieves inventory itself, authenticates itself
    . .\Connect-EntraID.ps1
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    $thresholds = @{ "EXCHANGEENTERPRISE" = 10; "AAD_PREMIUM_P2" = 5 }

    Send-M365LicenseThresholdAlert -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" `
        -TenantName "Contoso Ltd" -SkuThresholds $thresholds -EmailTo "admin@contoso.com" -EmailFrom "alerts@contoso.com"

.EXAMPLE
    # Manual token, evaluate a specific pre-fetched snapshot
    Get-M365LicenseInventory -AccessToken $token |
        Send-M365LicenseThresholdAlert -AccessToken $token -SkuThresholds $thresholds `
            -EmailTo "admin@contoso.com" -EmailFrom "alerts@contoso.com"

.EXAMPLE
    # Dry run — evaluate and inspect without sending mail
    Send-M365LicenseThresholdAlert -AccessToken $token -SkuThresholds $thresholds `
        -EmailTo "admin@contoso.com" -EmailFrom "alerts@contoso.com" -PassThru -WhatIf

.EXAMPLE
    Send-M365LicenseThresholdAlert -ShowHelp

.NOTES
    Requirements:
    - Microsoft Graph: Mail.Send (plus whatever Get-M365LicenseInventory requires, if auto-invoked).
    - App-only auth requires Connect-EntraID.ps1 dot-sourced first (see .LINK).
    - Auto-fetch requires Get-M365LicenseInventory.ps1 dot-sourced first (see .LINK), unless you pipe
      inventory in yourself.
    - PowerShell 5.1 or later.

    Known limitations:
    - "Total" (per Get-M365LicenseInventory) includes Enabled + Warning + Suspended + LockedOut units.
      LockedOut units aren't assignable, so "% free" reads slightly more optimistic than true assignable
      capacity on tenants with locked-out units. Adjust in Get-M365LicenseInventory if you need
      Enabled-only availability math.
    - Email notifications only; no Teams/adaptive-card support yet.
    - Single-tenant; no multi-tenant aggregation.

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    2.0 (26-Jul-2026) - App-only auth, self-fetching inventory, modern HTML email, ShowHelp guide.
                      - Public-release rewrite: security cleanup, retry/backoff, validation.
    1.0 (23-Jul-2025) - Initial private version.

.LINK
    Get-M365LicenseInventory.ps1 (required if not piping inventory in yourself)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Microsoft365/Licensing/Get-M365LicenseInventory.ps1

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1
#>


Function Show-M365LicenseThresholdAlertHelp
{
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║        Send-M365LicenseThresholdAlert v2.0 — Help Guide      ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this does:" -ForegroundColor Yellow
    Write-Host "    Evaluates M365 license usage against your thresholds and emails an alert"
    Write-Host "    when any SKU is running low. Can fetch the inventory itself — no need to"
    Write-Host "    run Get-M365LicenseInventory separately unless you want to."
    Write-Host ""
    Write-Host "  Choose ONE authentication method:" -ForegroundColor Yellow
    Write-Host "    Option A — Bring your own token:"
    Write-Host "      -AccessToken       A bearer token (e.g. from Graph Explorer or Connect-MgGraph)"
    Write-Host ""
    Write-Host "    Option B — App-only login (recommended for automation):" -ForegroundColor Yellow
    Write-Host "      (Requires Connect-EntraID.ps1 — get it from the repo:)" -ForegroundColor DarkYellow
    Write-Host "      https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1" -ForegroundColor Cyan
    Write-Host "      -ClientId          Application (client) ID of your app registration" -ForegroundColor Yellow
    Write-Host "      -ClientSecret      The app's client secret, as a SecureString" -ForegroundColor Yellow
    Write-Host "      -TenantId          Directory (tenant) ID" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Required either way:" -ForegroundColor Yellow
    Write-Host "      -SkuThresholds     @{ 'SKU_PART_NUMBER' = <ThresholdPercent> }"
    Write-Host "      -EmailTo / -EmailFrom"
    Write-Host ""
    Write-Host "  Example (Option B, fully unattended):" -ForegroundColor Yellow
    Write-Host '      . .\Connect-EntraID.ps1'
    Write-Host '      $secret = Read-Host -Prompt "Client secret" -AsSecureString'
    Write-Host '      Send-M365LicenseThresholdAlert -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" `'
    Write-Host '          -SkuThresholds $thresholds -EmailTo "admin@contoso.com" -EmailFrom "alerts@contoso.com"'
    Write-Host ""
    Write-Host "  For full parameter documentation, run:" -ForegroundColor Green
    Write-Host "    Get-Help Send-M365LicenseThresholdAlert -Full"
    Write-Host ""
}


Function Send-M365LicenseThresholdAlert
{
    [CmdletBinding(DefaultParameterSetName = "Token", SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param
    (
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

        # ── Shared: auth (AppAuth) and/or email branding (both) ──────────────
        [Parameter(Mandatory = $true, ParameterSetName = "AppAuth")]
        [Parameter(Mandatory = $false, ParameterSetName = "Token")]
        [string]$TenantId = "N/A",

        [Parameter(Mandatory = $false)]
        [string]$TenantName = "Your Organization",

        # ── Evaluation & alerting ─────────────────────────────────────────────
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "Token")]
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "AppAuth")]
        [PSCustomObject[]]$LicenseInventory,

        [Parameter(Mandatory = $true, ParameterSetName = "Token")]
        [Parameter(Mandatory = $true, ParameterSetName = "AppAuth")]
        [ValidateNotNullOrEmpty()]
        [hashtable]$SkuThresholds,

        [Parameter(Mandatory = $true, ParameterSetName = "Token")]
        [Parameter(Mandatory = $true, ParameterSetName = "AppAuth")]
        [ValidateNotNullOrEmpty()]
        [string[]]$EmailTo,

        [Parameter(Mandatory = $true, ParameterSetName = "Token")]
        [Parameter(Mandatory = $true, ParameterSetName = "AppAuth")]
        [ValidateNotNullOrEmpty()]
        [string]$EmailFrom,

        [Parameter(Mandatory = $false)]
        [string[]]$CcAddress,

        [Parameter(Mandatory = $false)]
        [string[]]$BccAddress,

        [Parameter(Mandatory = $false)]
        [string]$EmailSubject = "M365 License Threshold Alert",

        [Parameter(Mandatory = $false)]
        [string]$LogPath = (Join-Path $env:TEMP "M365LicenseThresholdAlert_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"),

        [Parameter(Mandatory = $false)]
        [string]$ExportCsvPath,

        [Parameter(Mandatory = $false)]
        [switch]$AlwaysSend,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru,

        # ── Help ──────────────────────────────────────────────────────────────
        [Parameter(Mandatory = $true, ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    Begin
    {
        $script:showHelpRequested = ($PSCmdlet.ParameterSetName -eq "Help")
        if ($showHelpRequested) { Show-M365LicenseThresholdAlertHelp; return }

        # Enforce TLS 1.2 for older PowerShell 5.1 hosts that may default to a weaker protocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        $allInventory = New-Object System.Collections.Generic.List[object]

        Function Write-ExecutionLog
        {
            param(
                [string]$Message,
                [ValidateSet("INFO","SUCCESS","WARNING","ERROR")]
                [string]$Level = "INFO"
            )
            $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
            switch ($Level) {
                "ERROR"   { Write-Host $entry -ForegroundColor Red }
                "WARNING" { Write-Host $entry -ForegroundColor Yellow }
                "SUCCESS" { Write-Host $entry -ForegroundColor Green }
                default   { Write-Host $entry -ForegroundColor Gray }
            }
            try { $entry | Out-File -FilePath $LogPath -Append -Encoding UTF8 }
            catch { Write-Warning "Could not write to log file '$LogPath': $_" }
            # NOTE: never log $AccessToken/$ClientSecret here, not even truncated.
        }

        Function Test-EmailAddressFormat
        {
            param([string]$Address)
            try { [void][System.Net.Mail.MailAddress]::new($Address); return $true }
            catch { return $false }
        }

        Function Send-GraphEmailWithRetry
        {
            param(
                [string]$FromAddress, [string[]]$ToAddress, [string[]]$Cc, [string[]]$Bcc,
                [string]$Subject, [string]$HtmlBody, [string]$Token, [int]$MaxRetries = 3
            )

            $graphUri = "https://graph.microsoft.com/v1.0/users/$FromAddress/sendMail"

            $payload = @{
                message = @{
                    subject      = $Subject
                    body         = @{ contentType = "HTML"; content = $HtmlBody }
                    toRecipients = @($ToAddress | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
                }
            }
            if ($Cc)  { $payload.message.ccRecipients  = @($Cc  | ForEach-Object { @{ emailAddress = @{ address = $_ } } }) }
            if ($Bcc) { $payload.message.bccRecipients = @($Bcc | ForEach-Object { @{ emailAddress = @{ address = $_ } } }) }

            $bodyJson = $payload | ConvertTo-Json -Depth 6
            $headers  = @{ Authorization = "Bearer $Token" }

            $attempt = 0
            do {
                $attempt++
                try
                {
                    Invoke-RestMethod -Uri $graphUri -Method Post -Headers $headers -ContentType "application/json" -Body $bodyJson -TimeoutSec 30 -ErrorAction Stop
                    return $true
                }
                catch
                {
                    $statusCode = $null
                    if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
                    $isTransient = ($statusCode -eq 429) -or ($statusCode -ge 500)

                    if ($isTransient -and $attempt -lt $MaxRetries)
                    {
                        $retryAfter = 5
                        try {
                            if ($_.Exception.Response.Headers["Retry-After"]) {
                                $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
                            }
                        } catch { }
                        Write-ExecutionLog -Level "WARNING" -Message "Graph sendMail throttled/transient error (attempt $attempt/$MaxRetries). Retrying in $retryAfter sec."
                        Start-Sleep -Seconds $retryAfter
                        continue
                    }

                    Write-ExecutionLog -Level "ERROR" -Message "Graph sendMail failed permanently: $($_.Exception.Message)"
                    return $false
                }
            } while ($attempt -lt $MaxRetries)

            return $false
        }

        # ── Resolve the access token up front (Token or AppAuth) ───────────────
        if ($PSCmdlet.ParameterSetName -eq "AppAuth")
        {
            if (-not (Get-Command Connect-EntraID -ErrorAction SilentlyContinue))
            {
                Write-Error @"
Connect-EntraID function not found.
To use app-only authentication, download Connect-EntraID.ps1 and dot-source it before calling this function:
https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

Example:
  . .\Connect-EntraID.ps1
"@
                $script:showHelpRequested = $true   # short-circuit Process/End below
                return
            }
            Write-ExecutionLog -Message "Auth method: AppAuth (ClientId/ClientSecret/TenantId). Requesting token via Connect-EntraID for tenant '$TenantId'."
            Write-Verbose "Authenticating via app-only client credentials for tenant $TenantId"
            $AccessToken = Connect-EntraID -ClientId $ClientId -ClientSecret $ClientSecret -TenantId $TenantId -RefreshInterval $RefreshInterval
            if (-not $AccessToken)
            {
                Write-ExecutionLog -Level "ERROR" -Message "Connect-EntraID did not return an access token. Aborting."
                Write-Error "Failed to obtain an access token via Connect-EntraID. See error above for details."
                $script:showHelpRequested = $true
                return
            }
            Write-ExecutionLog -Level "SUCCESS" -Message "Access token acquired via app-only auth (token value not logged)."
        }
        else
        {
            Write-ExecutionLog -Message "Auth method: Token (pre-supplied -AccessToken)."
        }
    }

    Process
    {
        if ($showHelpRequested) { return }
        foreach ($item in $LicenseInventory) { $allInventory.Add($item) }
        if ($LicenseInventory) {
            Write-ExecutionLog -Message "Received $($LicenseInventory.Count) piped -LicenseInventory record(s) in this pipeline batch."
        }
    }

    End
    {
        if ($showHelpRequested) { return }

        Write-Host ""
        Write-Host "=====================================================================" -ForegroundColor Cyan
        Write-Host " M365 License Threshold Evaluation — $TenantName" -ForegroundColor Cyan
        Write-Host "=====================================================================" -ForegroundColor Cyan
        Write-ExecutionLog -Message "Run started. LogPath='$LogPath'; SkuThresholds=$($SkuThresholds.Count); EmailTo=$($EmailTo -join '; '); AlwaysSend=$($AlwaysSend.IsPresent); PassThru=$($PassThru.IsPresent)."

        # ── Auto-fetch inventory if none was piped in ──────────────────────────
        if ($allInventory.Count -eq 0)
        {
            Write-ExecutionLog -Message "No -LicenseInventory supplied — retrieving automatically via Get-M365LicenseInventory."
            if (-not (Get-Command Get-M365LicenseInventory -ErrorAction SilentlyContinue))
            {
                Write-ExecutionLog -Level "ERROR" -Message "Get-M365LicenseInventory command not found. Aborting run."
                Write-Error @"
Get-M365LicenseInventory function not found.
Either pipe your own inventory objects in, or download and dot-source Get-M365LicenseInventory.ps1:
https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Microsoft365/Licensing/Get-M365LicenseInventory.ps1
"@
                return
            }
            $fetched = Get-M365LicenseInventory -AccessToken $AccessToken
            if (-not $fetched) {
                Write-ExecutionLog -Level "ERROR" -Message "Get-M365LicenseInventory returned no data. Aborting."
                return
            }
            foreach ($item in $fetched) { $allInventory.Add($item) }
            Write-ExecutionLog -Level "SUCCESS" -Message "Retrieved $($fetched.Count) inventory record(s) via Get-M365LicenseInventory."
        }

        Write-ExecutionLog -Message "Evaluating $($allInventory.Count) inventory record(s) against $($SkuThresholds.Count) configured threshold(s)."
        Write-ExecutionLog -Message "Configured thresholds: $(($SkuThresholds.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)%" }) -join '; ')."

        foreach ($key in $SkuThresholds.Keys) {
            $val = $SkuThresholds[$key]
            if ($val -lt 0 -or $val -gt 100) {
                Write-ExecutionLog -Level "ERROR" -Message "Threshold for '$key' is $val — must be between 0 and 100. Aborting."
                return
            }
        }
        Write-ExecutionLog -Message "All $($SkuThresholds.Count) configured threshold(s) passed range validation (0-100)."

        $allAddresses = @($EmailFrom) + $EmailTo + $CcAddress + $BccAddress | Where-Object { $_ }
        foreach ($addr in $allAddresses) {
            if (-not (Test-EmailAddressFormat -Address $addr)) {
                Write-ExecutionLog -Level "ERROR" -Message "'$addr' is not a valid email address. Aborting."
                return
            }
        }
        Write-ExecutionLog -Message "All $($allAddresses.Count) email address(es) (To/From/Cc/Bcc) passed format validation."

        $report = foreach ($sku in $allInventory) {
            if (-not $SkuThresholds.ContainsKey($sku.SkuPartNumber)) { continue }

            $total  = [int]$sku.TotalLicenses
            $unused = [int]$sku.UnusedLicenses
            $percentFree = if ($total -gt 0) { [math]::Round(($unused / $total) * 100, 2) } else { 0 }
            $threshold = $SkuThresholds[$sku.SkuPartNumber]
            $isBreached = ($percentFree -le $threshold)

            Write-ExecutionLog -Level $(if ($isBreached) { "WARNING" } else { "INFO" }) -Message "SKU '$($sku.SkuPartNumber)': Total=$total, Used=$($sku.UsedLicenses), Unused=$unused, %Free=$percentFree, Threshold=$threshold% -> $(if ($isBreached) { 'BREACHED' } else { 'OK' })."

            [PSCustomObject]@{
                SkuPartNumber  = $sku.SkuPartNumber
                TotalLicenses  = $total
                UsedLicenses   = $sku.UsedLicenses
                UnusedLicenses = $unused
                PercentFree    = $percentFree
                ThresholdPct   = $threshold
                IsBreached     = $isBreached
            }
        }

        if (-not $report) {
            Write-ExecutionLog -Level "WARNING" -Message "None of the configured SkuThresholds keys matched any SKU in the supplied inventory. Nothing to evaluate."
            return
        }

        $breaches = @($report | Where-Object { $_.IsBreached })
        $healthy  = $report.Count - $breaches.Count
        Write-ExecutionLog -Message "Evaluated $($report.Count) monitored SKU(s); $($breaches.Count) below threshold."
        if ($breaches.Count -gt 0) {
            Write-ExecutionLog -Level "WARNING" -Message "Breached SKU(s): $(($breaches | ForEach-Object { "$($_.SkuPartNumber) ($($_.PercentFree)% free, threshold $($_.ThresholdPct)%)" }) -join '; ')."
        }
        $unmatchedThresholds = @($SkuThresholds.Keys | Where-Object { $_ -notin $report.SkuPartNumber })
        if ($unmatchedThresholds.Count -gt 0) {
            Write-ExecutionLog -Level "WARNING" -Message "Configured threshold SKU(s) not found in inventory (skipped): $($unmatchedThresholds -join '; ')."
        }

        if ($ExportCsvPath) {
            try {
                $report | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                Write-ExecutionLog -Level "SUCCESS" -Message "Evaluation report exported to $ExportCsvPath"
            } catch {
                Write-ExecutionLog -Level "ERROR" -Message "Failed to export CSV to '$ExportCsvPath': $_"
            }
        }

        if ($breaches.Count -eq 0 -and -not $AlwaysSend) {
            Write-ExecutionLog -Level "SUCCESS" -Message "No thresholds breached and -AlwaysSend not specified. Skipping email."
            if ($PassThru) { return $report }
            return
        }

        # ── Refresh the token right before sending, in case inventory retrieval took a while ──
        if ($PSCmdlet.ParameterSetName -eq "AppAuth" -and (Get-Command Get-EntraIDAccessToken -ErrorAction SilentlyContinue)) {
            Write-ExecutionLog -Message "Refreshing access token before send (app-only auth path)."
            $AccessToken = Get-EntraIDAccessToken
        }
        Write-ExecutionLog -Message "Preparing alert email: Subject='$EmailSubject'; To=$($EmailTo -join '; ')$(if ($CcAddress) { "; Cc=$($CcAddress -join '; ')" })$(if ($BccAddress) { "; Bcc=$($BccAddress -join '; ')" })."

        # ── Build modern HTML email (inline-styled, table-based for Outlook compatibility) ──
        $statusColor  = if ($breaches.Count -gt 0) { "#d13438" } else { "#107c10" }
        $statusLabel  = if ($breaches.Count -gt 0) { "$($breaches.Count) SKU(s) need attention" } else { "All monitored SKUs healthy" }
        $generatedAt  = Get-Date -Format "dddd, MMMM dd, yyyy hh:mm tt"

        $rows = foreach ($row in ($report | Sort-Object IsBreached -Descending)) {
            $rowBg     = if ($row.IsBreached) { "#fdf2f2" } else { "#ffffff" }
            $badgeBg   = if ($row.IsBreached) { "#d13438" } else { "#107c10" }
            $badgeText = if ($row.IsBreached) { "BELOW THRESHOLD" } else { "OK" }
            @"
<tr style="background-color:$rowBg;border-bottom:1px solid #edf0f2;">
  <td style="padding:12px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:13px;color:#242424;font-weight:600;">$($row.SkuPartNumber)</td>
  <td style="padding:12px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:13px;color:#605e5c;">$($row.TotalLicenses)</td>
  <td style="padding:12px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:13px;color:#605e5c;">$($row.UsedLicenses)</td>
  <td style="padding:12px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:13px;color:#605e5c;">$($row.UnusedLicenses)</td>
  <td style="padding:12px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:13px;color:#242424;font-weight:600;">$($row.PercentFree)%</td>
  <td style="padding:12px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:13px;color:#605e5c;">$($row.ThresholdPct)%</td>
  <td style="padding:12px 14px;">
    <span style="display:inline-block;padding:3px 10px;border-radius:12px;background-color:$badgeBg;color:#ffffff;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;font-weight:700;letter-spacing:.3px;">$badgeText</span>
  </td>
</tr>
"@
        }

        $htmlBody = @"
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/></head>
<body style="margin:0;padding:0;background-color:#f3f2f1;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f3f2f1;padding:24px 0;">
<tr><td align="center">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.08);">

  <!-- Header band -->
  <tr>
    <td style="background-color:#242424;padding:24px 32px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:18px;color:#ffffff;font-weight:700;">M365 License Threshold Alert</td>
          <td align="right" style="font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:12px;color:#c8c6c4;">$TenantName</td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Status strip -->
  <tr>
    <td style="background-color:$statusColor;padding:10px 32px;">
      <span style="font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:13px;color:#ffffff;font-weight:600;">$statusLabel</span>
    </td>
  </tr>

  <!-- KPI chips -->
  <tr>
    <td style="padding:24px 32px 8px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td width="33%" style="padding-right:8px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f3f2f1;border-radius:6px;">
              <tr><td style="padding:14px 16px;">
                <div style="font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:22px;color:#242424;font-weight:700;">$($report.Count)</div>
                <div style="font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#605e5c;text-transform:uppercase;letter-spacing:.4px;">Monitored SKUs</div>
              </td></tr>
            </table>
          </td>
          <td width="33%" style="padding-right:8px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#fdf2f2;border-radius:6px;">
              <tr><td style="padding:14px 16px;">
                <div style="font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:22px;color:#d13438;font-weight:700;">$($breaches.Count)</div>
                <div style="font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#605e5c;text-transform:uppercase;letter-spacing:.4px;">Below Threshold</div>
              </td></tr>
            </table>
          </td>
          <td width="33%">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f1faf1;border-radius:6px;">
              <tr><td style="padding:14px 16px;">
                <div style="font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:22px;color:#107c10;font-weight:700;">$healthy</div>
                <div style="font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#605e5c;text-transform:uppercase;letter-spacing:.4px;">Healthy</div>
              </td></tr>
            </table>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Table -->
  <tr>
    <td style="padding:8px 32px 24px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #edf0f2;border-radius:6px;overflow:hidden;">
        <thead>
          <tr style="background-color:#faf9f8;">
            <th align="left" style="padding:10px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#605e5c;text-transform:uppercase;letter-spacing:.4px;">SKU</th>
            <th align="left" style="padding:10px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#605e5c;text-transform:uppercase;letter-spacing:.4px;">Total</th>
            <th align="left" style="padding:10px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#605e5c;text-transform:uppercase;letter-spacing:.4px;">Used</th>
            <th align="left" style="padding:10px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#605e5c;text-transform:uppercase;letter-spacing:.4px;">Unused</th>
            <th align="left" style="padding:10px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#605e5c;text-transform:uppercase;letter-spacing:.4px;">% Free</th>
            <th align="left" style="padding:10px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#605e5c;text-transform:uppercase;letter-spacing:.4px;">Threshold</th>
            <th align="left" style="padding:10px 14px;font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#605e5c;text-transform:uppercase;letter-spacing:.4px;">Status</th>
          </tr>
        </thead>
        <tbody>$($rows -join "`n")</tbody>
      </table>
    </td>
  </tr>

  <!-- Footer -->
  <tr>
    <td style="padding:16px 32px 24px;border-top:1px solid #edf0f2;">
      <div style="font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:11px;color:#a19f9d;">
        Generated $generatedAt &middot; Cloud Identity Automation &middot; Tenant ID: $TenantId
      </div>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>
"@

        if ($PSCmdlet.ShouldProcess("$($EmailTo -join ', ')", "Send M365 license threshold alert email")) {
            $sent = Send-GraphEmailWithRetry -FromAddress $EmailFrom -ToAddress $EmailTo -Cc $CcAddress -Bcc $BccAddress `
                        -Subject $EmailSubject -HtmlBody $htmlBody -Token $AccessToken

            if ($sent) { Write-ExecutionLog -Level "SUCCESS" -Message "Alert email sent to $($EmailTo -join '; ')." }
            else        { Write-ExecutionLog -Level "ERROR"   -Message "Alert email could not be sent. See log for details." }
        }
        else {
            Write-ExecutionLog -Message "ShouldProcess declined (-WhatIf or -Confirm) — email not sent."
        }

        if ($PassThru) {
            Write-ExecutionLog -Message "-PassThru specified — returning $($report.Count) report row(s) to caller."
            return $report
        }
        Write-ExecutionLog -Message "Run complete."
    }
}
