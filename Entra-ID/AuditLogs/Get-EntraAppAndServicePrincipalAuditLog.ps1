<#

Author          : Lakshmanan Thangaraj
Version         : 2.0
Created-On      : 22 June 2026
Modified-On     : 28 July 2026

.SYNOPSIS
    Retrieves audit logs from Microsoft Entra ID (Azure AD) for applications and service principals,
    with optional filtering by a specific object, dual authentication modes, and enterprise-scale
    performance controls.

.DESCRIPTION
    The Get-EntraAppAndServicePrincipalAuditLog function connects to Microsoft Graph (beta endpoint)
    and fetches audit log entries within a specified timeframe.

    Authentication is flexible — supply either:
        - A ready-made -AccessToken (e.g. copied from Graph Explorer, or obtained via
          Connect-MgGraph), for quick manual/ad-hoc runs, OR
        - -ClientId, -ClientSecret, and -TenantId, so the function authenticates itself
          via app-only client credentials using Connect-EntraID.ps1 under the hood —
          ideal for unattended/automated runs (Azure Automation, scheduled tasks, CI).

    The function operates in two modes, selected automatically based on parameters provided:

    MODE 1 — General Audit Mode (default, no target specified):
        Retrieves all audit events under the 'ApplicationManagement' category for the specified
        time period. This covers app registrations, service principal changes, permission grants,
        credential updates, deletions, and more. Scoped to ApplicationManagement category to ensure
        enterprise-scale performance — avoids pulling the entire tenant audit log.

    MODE 2 — Targeted Audit Mode (-TargetObjectId or -TargetObjectName provided):
        Retrieves ALL audit events across ALL categories for a specific Application or Service
        Principal. Uses server-side filtering by Object ID for best performance. Display name
        filtering is applied client-side after retrieval.

    This is useful for:
    - Monitoring new app registrations and service principal creations.
    - Detecting suspicious or untracked identity object creation.
    - Investigating all audit activity for a specific application or service principal.
    - Governance, audit, and security compliance reporting at enterprise scale.

.PARAMETER AccessToken
    Microsoft Graph access token used for authentication. Use this on its own for quick manual runs
    (Graph Explorer / Connect-MgGraph). Requires delegated or app **AuditLog.Read.All** and/or
    **Directory.Read.All**.

.PARAMETER ClientId
    The Application (client) ID of the Azure AD app registration used for app-only authentication.
    Use together with -ClientSecret and -TenantId instead of -AccessToken when running unattended.

.PARAMETER ClientSecret
    The client secret for the app registration, supplied as a SecureString. Example:
        $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Used together with -ClientId and -TenantId.

.PARAMETER TenantId
    The Directory (tenant) ID (GUID). Required when authenticating via -ClientId/-ClientSecret.

.PARAMETER RefreshInterval
    Only used in app-only mode. Minutes before token expiry that Connect-EntraID/Get-EntraIDAccessToken
    should proactively renew the token. Default is 5.

.PARAMETER TimeFrameInDays
    Specifies how many past days of audit data should be retrieved. Default is 7 days.
    Graph retains directory audit logs for a maximum of 30 days on most tenant license tiers, so this
    is validated to the 1–30 range.

.PARAMETER OutputPath
    Full file path or folder path for the CSV export (when OutputFormat is CSV).
    - If a full file path is provided (e.g. C:\Audit\report.csv), it is used as-is.
    - If a folder path is provided (e.g. C:\Audit\), a filename is auto-generated in the format:
      EntraAuditLog-<ApplicationType>-<timestamp>.csv

.PARAMETER OutputFormat
    The format in which results are exported. Currently only CSV is supported. Default is CSV.

.PARAMETER ApplicationType
    Used for output filename generation only.
    Acceptable values:
    - Application      : Label for App Registration focused runs
    - ServicePrincipal : Label for Service Principal focused runs
    - All              : Default label for combined runs

.PARAMETER TargetObjectName
    Optional. Triggers Targeted Audit Mode. Filters results to a specific Application or
    Service Principal by its display name (partial match, client-side). Literal characters only —
    wildcard characters in the value are escaped, so they are matched literally rather than treated
    as patterns.

.PARAMETER TargetObjectId
    Optional. Triggers Targeted Audit Mode. Filters results to a specific Application or
    Service Principal by its Object ID (exact GUID match, server-side — the most efficient option).

.PARAMETER ShowHelp
    Switch. Prints a friendly usage guide and exits without making any Graph calls.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    - Console output : Summary table of audit records
    - File output    : CSV file with detailed audit information

.OUTPUT FIELDS
    | Field              | Description                                                          |
    |--------------------|----------------------------------------------------------------------|
    | ActivityTime       | Timestamp when the activity was logged                               |
    | ActivityName       | Activity display name (e.g., "Add application", "Update application")|
    | AppDisplayName     | Display name of the primary target resource                          |
    | AppId              | Object ID of the primary target resource                             |
    | TargetResourceType | Resource type (e.g., Application, ServicePrincipal, User)            |
    | InitiatorType      | Type of initiator (User, Application, ServicePrincipal, System)      |
    | InitiatorName      | UPN or display name of who/what performed the action                 |
    | InitiatorID        | Object ID of the initiator                                           |
    | Category           | Audit log category (e.g., ApplicationManagement, UserManagement)     |
    | Result             | Result of the operation (success, failure)                           |
    | CorrelationId      | Operation correlation ID                                             |
    | ActivityId         | Unique activity ID of the audit log entry                            |

.EXAMPLE
    Get-EntraAppAndServicePrincipalAuditLog -AccessToken $token -OutputPath "C:\Audit\"

    Bring-your-own-token, Option A. Retrieves the last 7 days of ApplicationManagement audit
    events and auto-generates an output filename in C:\Audit\.

.EXAMPLE
    Get-EntraAppAndServicePrincipalAuditLog -AccessToken $token -TimeFrameInDays 3 -OutputPath "C:\Audit\AppAudit.csv"

    Option A. Retrieves the last 3 days of events and saves to a specific file.

.EXAMPLE
    Get-EntraAppAndServicePrincipalAuditLog -AccessToken $token -TimeFrameInDays 30 -TargetObjectName "Payroll-Sync-App" -OutputPath "C:\Audit\"

    Option A, Targeted Audit Mode — all audit events for the app/service principal whose display
    name contains 'Payroll-Sync-App', for the last 30 days.

.EXAMPLE
    Get-EntraAppAndServicePrincipalAuditLog -AccessToken $token -TimeFrameInDays 30 -TargetObjectId "a1b2c3d4-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -OutputPath "C:\Audit\"

    Option A, Targeted Audit Mode by Object ID — most efficient targeted lookup (server-side filter).

.EXAMPLE
    . .\Connect-EntraID.ps1
    $secret = Read-Host -Prompt "Client secret" -AsSecureString
    Get-EntraAppAndServicePrincipalAuditLog -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" -OutputPath "C:\Audit\"

    Option B — app-only client credentials. No manual token copy-paste needed; ideal for scheduled
    or unattended runs. Requires Connect-EntraID.ps1 (see .NOTES / .LINK below).

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (22-Jun-2026)      - Initial release: General + Targeted Audit modes,
                                 bring-your-own-token authentication only.
        1.2 (22-Jun-2026)      - Prior published revision (bring-your-own-token only).
        2.0 (28-Jul-2026)      - Added app-only authentication support via
                                 Connect-EntraID.ps1 (-ClientId/-ClientSecret/-TenantId),
                                 mirroring Get-PIMActiveEntraIDRoleAssignmentDetails.ps1.
                                 Fixed: UTC/local Get-Date mismatch in date-range filter;
                                 System.Web.HttpUtility dependency (not guaranteed on
                                 PS7/Core) replaced with [Uri]::EscapeDataString;
                                 -TargetObjectName no longer treated as a wildcard
                                 pattern (literal characters escaped before -like);
                                 removed dead $createdObjectType computation; added
                                 GUID validation on -TargetObjectId/-TenantId; added
                                 range validation on -TimeFrameInDays; added HTTP 429
                                 (throttling) retry handling on every page fetch;
                                 added -ShowHelp friendly guide.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    - PowerShell 5.1+ (Windows) or PowerShell Core 7+ (cross-platform).
    - Internet access to https://graph.microsoft.com.
    - Option A (bring your own token):
        Any way to obtain a Graph bearer token with AuditLog.Read.All and/or
        Directory.Read.All, e.g.:
          Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All"
          $token = (Get-MgContext) | ... # or capture via -AccessToken from Graph Explorer
        Simplest ad-hoc option: sign in to https://aka.ms/ge and copy the access token
        from the "Access token" tab after running a query with the required scopes consented.
    - Option B (app-only / client credentials, for automation):
        1. Register an app in Entra ID (App registrations > New registration).
        2. Under API permissions, add **Application** permissions (not delegated):
           AuditLog.Read.All, Directory.Read.All — then grant admin consent.
        3. Create a client secret (Certificates & secrets > New client secret).
        4. Download Connect-EntraID.ps1 and dot-source it before calling this function:
           https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1
        5. Call with -ClientId, -ClientSecret (SecureString), -TenantId instead of -AccessToken.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW:
    ─────────────────────────────────────────────────────────────────────────────
    1. Validate parameters (GUID formats, date range, output path).
    2. If -ShowHelp, print guide and exit — no Graph calls made.
    3. If AppAuth parameter set, confirm Connect-EntraID is available and obtain an
       initial access token.
    4. Build the server-side $filter — by Object ID + date range (Targeted/ID mode),
       or by ApplicationManagement category + date range (General mode).
    5. Page through /beta/auditLogs/directoryAudits, retrying on HTTP 429 using the
       Retry-After header; re-fetch a fresh token each page in AppAuth mode.
    6. Normalize each entry's initiator (User/Application/ServicePrincipal/System) and
       primary target resource into a flat object.
    7. If -TargetObjectName was supplied, apply the client-side literal-text filter.
    8. Print a console summary and export to CSV.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Uses the Microsoft Graph **beta** endpoint (per Microsoft Learn, beta contracts can
      change without notice) — pin/review periodically if used in production automation.
    - Graph directory audit log retention is ~30 days on most tenant license tiers;
      -TimeFrameInDays is capped at 30 for this reason.
    - -TargetObjectName filtering is client-side (no server-side display-name filter exists
      for this endpoint) — on very large tenants, General Audit Mode volume plus a broad name
      filter can be slower than -TargetObjectId.
    - This function does not write to or modify any resource — it is read-only.

.LINK
    https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-beta

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Show-EntraAppAuditLogHelp
{
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║     Get-EntraAppAndServicePrincipalAuditLog  v2.0            ║" -ForegroundColor Cyan
    Write-Host "  ║                   Friendly Help Guide                        ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  What this does:" -ForegroundColor Yellow
    Write-Host "    Retrieves Entra ID audit log events for application registrations and"
    Write-Host "    service principals — either broadly (ApplicationManagement category) or"
    Write-Host "    narrowed to one specific app/service principal (all categories)."
    Write-Host ""
    Write-Host "  Choose ONE authentication method:" -ForegroundColor Yellow
    Write-Host "    Option A — Bring your own token:"
    Write-Host "      -AccessToken   A bearer token (e.g. from Graph Explorer or Connect-MgGraph)"
    Write-Host ""
    Write-Host "  Option B — App-only login (recommended for automation):" -ForegroundColor Yellow
    Write-Host "      (Requires Connect-EntraID.ps1 — get it from the repo:)" -ForegroundColor DarkYellow
    Write-Host "      https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1" -ForegroundColor Cyan
    Write-Host "      -ClientId       Application (client) ID of your app registration" -ForegroundColor Yellow
    Write-Host "      -ClientSecret   The app's client secret, as a SecureString" -ForegroundColor Yellow
    Write-Host "      -TenantId       Directory (tenant) ID" -ForegroundColor Yellow
    Write-Host "      -RefreshInterval  (optional) Minutes before expiry to renew early (default: 5)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Example (Option A):" -ForegroundColor Yellow
    Write-Host '    Get-EntraAppAndServicePrincipalAuditLog -AccessToken $token -OutputPath "C:\Audit\"'
    Write-Host ""
    Write-Host "  Example (Option B):" -ForegroundColor Yellow
    Write-Host '    . .\Connect-EntraID.ps1'
    Write-Host '    $secret = Read-Host -Prompt "Client secret" -AsSecureString'
    Write-Host '    Get-EntraAppAndServicePrincipalAuditLog -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" -OutputPath "C:\Audit\"'
    Write-Host ""
    Write-Host "  For full parameter and function documentation, run:" -ForegroundColor Green
    Write-Host "     Get-Help Get-EntraAppAndServicePrincipalAuditLog -Full"
    Write-Host ""
}


Function Get-EntraAppAndServicePrincipalAuditLog
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

        [Parameter(Mandatory = $true, ParameterSetName = "AppAuth")]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$TenantId,

        [Parameter(ParameterSetName = "AppAuth")]
        [ValidateRange(1, 60)]
        [int]$RefreshInterval = 5,

        [ValidateRange(1, 30)]
        [int]$TimeFrameInDays = 7,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [ValidateSet("CSV")]
        [string]$OutputFormat = "CSV",

        [ValidateSet("Application", "ServicePrincipal", "All")]
        [string]$ApplicationType = "All",

        # Optional filter by display name. Matches Application OR Service Principal, literal partial match.
        [string]$TargetObjectName,

        # Optional filter by Object ID / App ID. Matches Application OR Service Principal, exact match.
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$TargetObjectId,

        # ── Help ──────────────────────────────────────────────────────────────
        [Parameter(ParameterSetName = "Help")]
        [switch]$ShowHelp
    )

    if ($ShowHelp)
    {
        Show-EntraAppAuditLogHelp
        return
    }

    # ── Path validation (block traversal sequences before they reach Join-Path) ──
    if ($OutputPath -match '\.\.[\\/]' -or $OutputPath -match '[\x00-\x1F]')
    {
        Write-Error "OutputPath contains invalid or path-traversal characters: $OutputPath"
        return
    }

    # ── Resolve access token ──────────────────────────────────────────────────
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

    # ── Build date range (UTC, consistently) ──────────────────────────────────
    $startDate = (Get-Date).ToUniversalTime().AddDays(-$TimeFrameInDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $endDate   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Build server-side filter based on parameters provided:
    # - TargetObjectId   : filter by specific object ID + date range (server-side, most efficient)
    # - TargetObjectName : filter by date range only, name matched client-side after retrieval
    # - Neither          : filter by date range only, restricted to ApplicationManagement category
    if ($TargetObjectId)
    {
        $rawFilter = "targetResources/any(t:t/id eq '$TargetObjectId') and activityDateTime ge $startDate"
    }
    else
    {
        $rawFilter = "category eq 'ApplicationManagement' and activityDateTime ge $startDate"
    }
    # [Uri]::EscapeDataString is portable across Windows PowerShell 5.1 and PowerShell 7/Core;
    # System.Web.HttpUtility is not guaranteed loaded on non-Windows PS7 sessions.
    $encodedFilter = [Uri]::EscapeDataString($rawFilter)
    $uri = "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$filter=$encodedFilter"

    Write-Host "`n🔍 Retrieving audit logs for the last $TimeFrameInDays day(s)" -ForegroundColor Cyan
    Write-Host "🗓️  Timeframe: From $startDate to $endDate" -ForegroundColor Cyan
    if ($TargetObjectId)   { Write-Host "🎯 Filtering for specific Object ID: $TargetObjectId" -ForegroundColor Cyan }
    if ($TargetObjectName) { Write-Host "🎯 Filtering for specific display name containing: '$TargetObjectName'" -ForegroundColor Cyan }
    Write-Host "📡 Connecting to Microsoft Graph API..." -ForegroundColor DarkCyan

    [System.Collections.ArrayList]$logs = @()

    try
    {
        do
        {
            # In AppAuth mode, re-fetch the token each page — Get-EntraIDAccessToken only
            # renews when actually close to expiry, so this is cheap and protects long
            # pagination runs on large tenants from outliving a single ~60-minute token.
            if ($PSCmdlet.ParameterSetName -eq "AppAuth")
            {
                $AccessToken = Get-EntraIDAccessToken
            }
            $headers = @{ Authorization = "Bearer $AccessToken" }

            $response  = $null
            $skipPage  = $false
            do
            {
                try
                {
                    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
                    $statusCode = 200
                }
                catch
                {
                    $statusCode = $_.Exception.Response.StatusCode

                    if ($statusCode -eq 429)
                    {
                        $retryAfter = $_.Exception.Response.Headers.Item("Retry-After")
                        if (-not $retryAfter) { $retryAfter = 10 }
                        Write-Host "⏳ Throttled by Graph (429). Waiting $retryAfter second(s) before retrying..." -ForegroundColor Yellow
                        Start-Sleep -Seconds $retryAfter
                    }
                    else
                    {
                        Write-Error "Graph request failed ($statusCode): $($_.Exception.Message)"
                        $skipPage = $true
                    }
                }
            } until ($statusCode -eq 200 -or $skipPage)

            if ($skipPage -or -not $response) { break }

            foreach ($entry in $response.value)
            {
                $initiatedBy     = $entry.initiatedBy
                $initiatedByType = if ($initiatedBy.PSObject.Properties['@odata.type']) { $initiatedBy.'@odata.type' } else { $null }
                $initiatorType   = "System/Unknown"
                $initiatorName   = if ($entry.loggedByService) { $entry.loggedByService } else { "N/A" }
                $initiatorId     = "N/A"

                if ($initiatedBy.user)
                {
                    $initiatorName = $initiatedBy.user.userPrincipalName
                    $initiatorId   = $initiatedBy.user.id
                    $initiatorType = "User"
                }
                elseif ($initiatedBy.app)
                {
                    $initiatorName = $initiatedBy.app.displayName
                    $initiatorId   = $initiatedBy.app.servicePrincipalId
                    $initiatorType = "Application"
                }
                elseif ($initiatedBy.servicePrincipal)
                {
                    $initiatorName = $initiatedBy.servicePrincipal.displayName
                    $initiatorId   = $initiatedBy.servicePrincipal.id
                    $initiatorType = "ServicePrincipal"
                }
                elseif ($initiatedByType)
                {
                    $initiatorType = $initiatedByType -replace "#microsoft.graph.", ""
                }

                # Find the primary resource across all targetResources entries.
                # If a specific target is requested, match by ID or name first.
                # Otherwise fall back to first Application/ServicePrincipal typed entry, then index [0].
                if ($TargetObjectId)
                {
                    $primaryResource = $entry.targetResources | Where-Object { $_.id -eq $TargetObjectId } | Select-Object -First 1
                }
                elseif ($TargetObjectName)
                {
                    $escapedName     = [System.Management.Automation.WildcardPattern]::Escape($TargetObjectName)
                    $primaryResource = $entry.targetResources | Where-Object { $_.displayName -like "*$escapedName*" } | Select-Object -First 1
                }
                else
                {
                    $primaryResource = $entry.targetResources | Where-Object { $_.type -in @('Application', 'ServicePrincipal') } | Select-Object -First 1
                }
                if (-not $primaryResource) { $primaryResource = $entry.targetResources[0] }

                $null = $logs.Add([PSCustomObject]@{
                    ActivityTime       = $entry.activityDateTime
                    ActivityName       = $entry.activityDisplayName
                    AppDisplayName     = $primaryResource.displayName
                    AppId              = $primaryResource.id
                    TargetResourceType = $primaryResource.type
                    InitiatorType      = $initiatorType
                    InitiatorName      = $initiatorName
                    InitiatorID        = $initiatorId
                    Category           = $entry.category
                    Result             = $entry.result
                    CorrelationId      = $entry.correlationId
                    ActivityId         = $entry.id
                })
            }

            $uri = if ($response.PSObject.Properties['@odata.nextLink']) { $response.'@odata.nextLink' } else { $null }

        } while ($uri)

        # TargetObjectId is already filtered server-side above.
        # TargetObjectName has no server-side support — apply the literal client-side filter here.
        if ($TargetObjectName -and $logs.Count -gt 0)
        {
            $escapedName = [System.Management.Automation.WildcardPattern]::Escape($TargetObjectName)
            [System.Collections.ArrayList]$logs = @($logs | Where-Object { $_.AppDisplayName -like "*$escapedName*" })
        }

        if ($logs.Count -eq 0)
        {
            if ($TargetObjectId -or $TargetObjectName)
            {
                $targetLabel = if ($TargetObjectId) { $TargetObjectId } else { $TargetObjectName }
                Write-Host "⚠️  No audit logs found for object [$targetLabel] in the last $TimeFrameInDays day(s)." -ForegroundColor Yellow
            }
            else
            {
                Write-Host "⚠️  No audit logs found in the last $TimeFrameInDays day(s)." -ForegroundColor Yellow
            }
        }
        else
        {
            Write-Host "`n📄 Total Records Retrieved: $($logs.Count)" -ForegroundColor Green
            $logs | Format-Table ActivityTime, ActivityName, AppDisplayName, InitiatorType, InitiatorName -AutoSize
        }

        if ($OutputFormat -eq "CSV")
        {
            # Auto-generate filename if OutputPath is a folder (no .csv extension)
            if ($OutputPath -match '[\\/]$' -or (Test-Path $OutputPath -PathType Container))
            {
                $timestamp  = (Get-Date).ToString("yyyy-MM-dd-HHmmss")
                $OutputPath = Join-Path $OutputPath "EntraAuditLog-$ApplicationType-$timestamp.csv"
            }
            $logs | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Host "`n✅ Audit logs successfully exported to: $OutputPath" -ForegroundColor Green
        }
    }
    catch
    {
        Write-Error "❌ Error fetching audit logs: $_"
    }
}
