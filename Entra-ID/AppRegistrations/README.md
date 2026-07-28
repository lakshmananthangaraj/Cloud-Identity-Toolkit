# App Registration Reports & Permissions Toolkit

This folder contains PowerShell functions that scan every Entra ID (Azure AD)
App Registration in your tenant — and, for SharePoint-related scenarios, act
on the Sites.Selected permission model directly.

If you've ever had to answer "which app secrets or certificates are about to
break production?", "which apps can access this SharePoint site?", or
prepare for a security review, these scripts turn that into a two-minute
task instead of clicking through App Registrations one by one in the portal.

---

## What's in this folder

| Script | What it does |
|---|---|
| **`Get-AppRegistrationSecretReport.ps1`** | Reports on client secrets on every App Registration that expired recently, or are expiring soon, with a severity rating for each |
| **`Get-AppRegistrationCertificateReport.ps1`** | Reports on certificates (keyCredentials) on every App Registration that expired recently, or are expiring soon, with a severity rating for each |
| **`Get-AppSiteSelectedPermissions.ps1`** | Read-only audit of Microsoft Graph "Sites.Selected" grants — look up which SharePoint sites an app can access (forward lookup), or which apps can access a given site (reverse lookup) |
| **`Grant-SharePointSiteSelectedPermission.ps1`** | Grants (or verifies) a Sites.Selected permission role — read, write, or owner — for an application on a specific SharePoint site |

---

## Why this is useful

For a **security or compliance team**, this answers questions like:
- Which app secrets or certificates are expiring in the next 30/60/90 days, before something breaks in production?
- Which secrets or certificates already expired — and might explain a recent authentication failure?
- Are there App Proxy applications skewing the picture, and can they be excluded from the count?
- Which SharePoint sites can a given application currently reach, and at what permission level?
- Which applications currently have access to a sensitive SharePoint site — is that access still justified?

For **IT operations**, it's a fast, repeatable export — no manual portal digging, and it can be scheduled to run automatically (see [Authentication](#authentication) below).

For **leadership / non-technical readers**, the `ExpirationStatus` column translates raw dates into plain-language severity levels (Critical, High, Medium, Low, Expired) that don't require Graph or PowerShell knowledge to interpret.

---

## Key features

### Secret & Certificate reports
- ✅ Pull **every** App Registration across the whole tenant, handling pagination automatically — nothing is missed on large tenants
- ✅ Gracefully wait and retry if Microsoft Graph throttles the request (HTTP 429), instead of failing partway through
- ✅ Classify each secret/certificate into a severity level: **Expired, Critical (<7 days), High (<30 days), Medium (30–60 days), Low (60–90 days), Beyond 90 Days**
- ✅ Optional filtering to exclude App Proxy applications from the report
- ✅ Configurable look-back and look-ahead windows (`-ExpiredLastDays`, `-ExpiringNextDays`)
- ✅ Export clean, structured data to CSV, ready to open in Excel or pipe into Power BI
- ✅ Two supported ways to authenticate (see below) — whichever fits how you run the script

### Sites.Selected permission tools
- ✅ **Forward lookup**: which SharePoint sites can a given app access?
- ✅ **Reverse lookup**: which apps can access a given SharePoint site (by Site ID or Site URL)?
- ✅ Parallel scanning on PowerShell 7+ (`-ThrottleLimit`), with automatic fallback to sequential mode on PowerShell 5.x
- ✅ Idempotency check before granting — an existing grant with the same role is left alone; a differing role warns instead of silently duplicating
- ✅ `-WhatIf` / `-Confirm` support, with extra interactive confirmation required for `owner`-level grants
- ✅ Two authentication modes for the read side (Interactive delegated login, or app-only Service Principal)

---

## Prerequisites

1. **PowerShell 5.1 or later** (Windows PowerShell or PowerShell 7+). PowerShell 7+ is required for parallel scanning in `Get-AppSiteSelectedPermissions.ps1`.
2. **An Entra ID app registration** (or an existing signed-in session) with the following Microsoft Graph permissions, depending on which script you're using:

| Script | Required Graph permissions (Application) |
|---|---|
| `Get-AppRegistrationSecretReport.ps1` | `Application.Read.All`, `Directory.Read.All` |
| `Get-AppRegistrationCertificateReport.ps1` | `Application.Read.All`, `Directory.Read.All` |
| `Get-AppSiteSelectedPermissions.ps1` | `Sites.FullControl.All`, `Application.Read.All` |
| `Grant-SharePointSiteSelectedPermission.ps1` | `Sites.FullControl.All` (consent required from a Global Administrator or Privileged Role Administrator) |

> **Note:** Microsoft Graph does not currently expose a lower, read-only permission for the site-permissions endpoints, which is why the Sites.Selected scripts above require `Sites.FullControl.All` even for the read-only lookup script.

---

## Authentication

Authentication support **varies by script** — check the table below before picking an approach.

| Script | Bring-your-own token | App-only (Client ID/Secret/Tenant) | Interactive delegated login |
|---|:---:|:---:|:---:|
| `Get-AppRegistrationSecretReport.ps1` | ✅ | ✅ | — |
| `Get-AppRegistrationCertificateReport.ps1` | ✅ | ✅ | — |
| `Get-AppSiteSelectedPermissions.ps1` | — | ✅ (`-AuthMode ServicePrincipal`) | ✅ (`-AuthMode Interactive`) |
| `Grant-SharePointSiteSelectedPermission.ps1` | — | ✅ | — |

### Option A — Bring your own token (quick, manual runs)

Applies to the two report scripts. Use this if you already have a Graph access token — for example, copied from [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer), or obtained via `Connect-MgGraph`.

```powershell
Get-AppRegistrationSecretReport -AccessToken $token
Get-AppRegistrationCertificateReport -AccessToken $token
```

This is the fastest way to try the script out, but a token copied from a browser session is short-lived (about an hour) and isn't suitable for anything unattended or scheduled.

### Option B — App-only login (recommended for automation)

For scheduled tasks, Azure Automation, or any unattended run, use the companion authentication helper published alongside this folder:

**[`Connect-EntraID.ps1`](../Authentication/Connect-EntraID.ps1)**

This uses the standard OAuth2 **client credentials flow** with an app registration (Client ID + Client Secret + Tenant ID) — no human sign-in required, and the underlying token is renewed automatically for you if a run takes a while.

```powershell
. .\Connect-EntraID.ps1
$secret = Read-Host -Prompt "Client secret" -AsSecureString

Get-AppRegistrationSecretReport -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>"
```

`Get-AppSiteSelectedPermissions.ps1` and `Grant-SharePointSiteSelectedPermission.ps1` take their own `-ClientId` / `-ClientSecret` / `-TenantId` parameters directly (app-only, client credentials flow) rather than relying on `Connect-EntraID.ps1`. `Get-AppSiteSelectedPermissions.ps1` additionally supports `-AuthMode Interactive` for a delegated, signed-in-user login — useful for ad-hoc audits where a dedicated app registration isn't available. If a Graph session is already connected when either function is called, it's reused rather than torn down.

```powershell
# Get-AppSiteSelectedPermissions.ps1 — interactive login
Get-AppSiteSelectedPermissions -TargetAppId "<app-id>" -AuthMode Interactive

# Get-AppSiteSelectedPermissions.ps1 — app-only login
$secret = Read-Host "Client Secret" -AsSecureString
Get-AppSiteSelectedPermissions -TargetAppId "<app-id>" -AuthMode ServicePrincipal `
    -TenantId "<tenant-id>" -ClientId "<client-id>" -ClientSecret $secret

# Grant-SharePointSiteSelectedPermission.ps1 — app-only login
Grant-SharePointSiteSelectedPermission -TenantId "<tenant-id>" -ClientId "<client-id>" `
    -ClientSecret $secret -TargetAppId "<target-app-id>" -TargetAppDisplayName "My App" `
    -SiteId "<site-id>" -PermissionRole "read"
```

> **On security:** a client secret is a shared credential, so store it the same way you'd store any sensitive password — in a secure vault (e.g. Azure Key Vault), never hardcoded in a script or committed to source control. If you're running this from inside Azure (an Automation Account or Function App), a **Managed Identity** is a stronger option still, since there's no secret to manage or leak at all. All four scripts accept the client secret as a `SecureString` (recommended); the two Sites.Selected scripts also accept a plain-text secret via `-ClientSecretPlainText` for automation/CI scenarios where a `SecureString` isn't practical — prefer the `SecureString` parameter or a vault wherever possible.

---

## Quick start

```powershell
# --- Reports (secrets / certificates) ---

# 1. See what parameters and options are available, without connecting to anything
Get-AppRegistrationCertificateReport -ShowHelp

# 2. Run with a manual token
Get-AppRegistrationSecretReport -AccessToken $token
Get-AppRegistrationCertificateReport -AccessToken $token

# 3. Run with app-only authentication, excluding App Proxy apps, custom windows
. .\Connect-EntraID.ps1
$secret = Read-Host -Prompt "Client secret" -AsSecureString
Get-AppRegistrationSecretReport -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" -ExpiredLastDays 15 -ExpiringNextDays 90

# --- Sites.Selected permissions ---

# 4. Which sites can this app access? (interactive login)
Get-AppSiteSelectedPermissions -TargetAppId "<app-id>" -AuthMode Interactive

# 5. Who has access to this site? (reverse lookup, interactive login)
Get-AppSiteSelectedPermissions -AuthMode Interactive -TargetSiteUrl "https://contoso.sharepoint.com/sites/HR"

# 6. Preview granting Owner access without making any change
Grant-SharePointSiteSelectedPermission -TenantId $tid -ClientId $cid -ClientSecret $secret `
    -TargetAppId $appId -TargetAppDisplayName "My App" -SiteId $siteId `
    -PermissionRole "owner" -WhatIf

# 7. Grant Read access
Grant-SharePointSiteSelectedPermission -TenantId $tid -ClientId $cid -ClientSecret $secret `
    -TargetAppId $appId -TargetAppDisplayName "My App" -SiteId $siteId -PermissionRole "read"
```

Every parameter, example, and prerequisite is also documented inline — run `Get-Help <FunctionName> -Full` for the complete reference on any script in this folder.

---

## Common parameters

### Report scripts (`Get-AppRegistrationSecretReport.ps1`, `Get-AppRegistrationCertificateReport.ps1`)

| Parameter | Purpose |
|---|---|
| `-AccessToken` | Supply a ready-made bearer token (Option A) |
| `-ClientId` / `-ClientSecret` / `-TenantId` | App-only authentication (Option B) |
| `-RefreshInterval` | Minutes before expiry to renew the token early when using Option B (default: 5) |
| `-OutputPath` | Path to save the CSV report (defaults to `C:\Temp\...`) |
| `-IncludeProxyApps` | Include App Proxy applications in the report (default: `$false`) — secret report only |
| `-ExpiredLastDays` | Look-back window for recently expired secrets/certificates (default: 30) |
| `-ExpiringNextDays` | Look-ahead window for soon-to-expire secrets/certificates (default: 60) |
| `-ShowHelp` | Prints a plain-language usage guide and exits — no connection is made |

### `Get-AppSiteSelectedPermissions.ps1`

| Parameter | Purpose |
|---|---|
| `-TargetAppId` | App whose Sites.Selected access you want to audit (required for forward lookup; optional filter for reverse lookup) |
| `-TargetSiteId` / `-TargetSiteUrl` | Provide either one to trigger a reverse lookup — who has access to this site? |
| `-AuthMode` | `Interactive` (delegated login) or `ServicePrincipal` (app-only) |
| `-TenantId` / `-ClientId` / `-ClientSecret` / `-ClientSecretPlainText` | Required for `-AuthMode ServicePrincipal` |
| `-ThrottleLimit` | Number of sites processed in parallel on PowerShell 7+ (default: 10) |
| `-ExportCsv` | Optional path to export results as CSV |

### `Grant-SharePointSiteSelectedPermission.ps1`

| Parameter | Purpose |
|---|---|
| `-TenantId` / `-ClientId` / `-ClientSecret` / `-ClientSecretPlainText` | App-only authentication (required) |
| `-TargetAppId` / `-TargetAppDisplayName` | The application being granted access |
| `-SiteId` | The SharePoint site (format: `hostname,siteCollectionId,webId`) |
| `-PermissionRole` | `read`, `write`, or `owner` (default: `read`) |
| `-Force` | Suppresses the confirmation prompt for `owner` grants, and allows proceeding past a differing-role idempotency warning. Does not bypass `-WhatIf` |
| `-WhatIf` / `-Confirm` | Standard PowerShell risk-mitigation switches — preview the change before it's made |

---

## Output

### Secret & certificate reports
Each report exports one row per secret or certificate that falls inside the configured expiration windows:

```powershell
Get-AppRegistrationSecretReport -AccessToken $token -OutputPath "C:\Reports\Secrets.csv"
Get-AppRegistrationCertificateReport -AccessToken $token -OutputPath "C:\Reports\Certs.csv"
```

Each row includes the app's display name and ID, the credential's end date, its hint (secrets) or details, its expiration status, days remaining, and any notes on the app registration.

### `Get-AppSiteSelectedPermissions.ps1`
Returns one object per site-to-app permission grant found (forward or reverse lookup, depending on parameters used). Optionally export to CSV with `-ExportCsv`.

### `Grant-SharePointSiteSelectedPermission.ps1`
Returns the Graph API permission object — either the existing grant (if one already matched) or the newly created one — as a `PSCustomObject`, or `$null` on failure.

---

## A note on responsible use

`Get-AppRegistrationSecretReport.ps1`, `Get-AppRegistrationCertificateReport.ps1`, and `Get-AppSiteSelectedPermissions.ps1` are **read-only** — they don't create, modify, or remove any secrets, certificates, app registrations, or permissions.

`Grant-SharePointSiteSelectedPermission.ps1` is different: it's a **state-changing, security-sensitive operation** that can grant an application up to full Owner control of a SharePoint site. Before using it:

- Always test with `-WhatIf` first, especially for `owner`-level grants.
- Grant the narrowest role (`read` before `write` before `owner`) that actually satisfies the requirement.
- Grant `Sites.FullControl.All` and other broad Graph permissions used by these scripts only to app registrations that genuinely need them.
- Store any client secret in a proper secrets vault, not in plain text.
- Review who has access to run these scripts, who can approve `owner` grants, and where the exported reports (CSV) are stored.

---

## Feedback and contributions

Found an issue, or have an idea to improve this script? Feel free to open an issue or a pull request on the main repository — feedback is always welcome.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/LICENSE) file for details.
