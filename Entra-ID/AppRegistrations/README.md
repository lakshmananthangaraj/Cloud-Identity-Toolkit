# App Registration Secret Expiration Report

This folder contains a PowerShell function that scans every Entra ID (Azure AD)
App Registration in your tenant and reports on client secrets that have
recently expired or are about to.

If you've ever had to answer "which app secrets are about to break production?"
or prepare for a security review, this turns that into a two-minute task
instead of clicking through App Registrations one by one in the portal.

---

## What's in this folder

| Script | What it reports on |
|---|---|
| **`Get-AppRegistrationSecretReport.ps1`** | Client secrets on every App Registration that expired recently, or are expiring soon, with a severity rating for each |

---

## Why this is useful

For a **security or compliance team**, this answers questions like:
- Which app secrets are expiring in the next 30/60/90 days, before something breaks in production?
- Which secrets already expired — and might explain a recent authentication failure?
- Are there App Proxy applications skewing the picture, and can they be excluded from the count?

For **IT operations**, it's a fast, repeatable export — no manual portal digging, and it can be scheduled to run automatically (see [Authentication](#authentication) below).

For **leadership / non-technical readers**, the `ExpirationStatus` column translates raw dates into plain-language severity levels (Critical, High, Medium, Low, Expired) that don't require Graph or PowerShell knowledge to interpret.

---

## Key features

- ✅ Pulls **every** App Registration across the whole tenant, handling pagination automatically — nothing is missed on large tenants
- ✅ Gracefully waits and retries if Microsoft Graph throttles the request (HTTP 429), instead of failing partway through
- ✅ Classifies each secret into a severity level: **Expired, Critical (<7 days), High (<30 days), Medium (30–60 days), Low (60–90 days), Beyond 90 Days**
- ✅ Optional filtering to exclude App Proxy applications from the report
- ✅ Configurable look-back and look-ahead windows (`-ExpiredLastDays`, `-ExpiringNextDays`)
- ✅ Exports clean, structured data to CSV, ready to open in Excel or pipe into Power BI
- ✅ Two supported ways to authenticate (see below) — whichever fits how you run the script

---

## Prerequisites

1. **PowerShell 5.1 or later** (Windows PowerShell or PowerShell 7+).
2. **An Entra ID app registration** (or an existing signed-in session) with the following Microsoft Graph permissions:
   - `Application.Read.All`
   - `Directory.Read.All`

---

## Authentication

The script supports **either** of the following — pick whichever suits your situation. You don't need both.

### Option A — Bring your own token (quick, manual runs)

Use this if you already have a Graph access token — for example, copied from [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer), or obtained via `Connect-MgGraph`.

```powershell
Get-AppRegistrationSecretReport -AccessToken $token
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

> **On security:** a client secret is a shared credential, so store it the same way you'd store any sensitive password — in a secure vault (e.g. Azure Key Vault), never hardcoded in a script or committed to source control. If you're running this from inside Azure (an Automation Account or Function App), a **Managed Identity** is a stronger option still, since there's no secret to manage or leak at all.

---

## Quick start

```powershell
# 1. See what parameters and options are available, without connecting to anything
Get-AppRegistrationSecretReport -ShowHelp

# 2. Run it with a manual token
Get-AppRegistrationSecretReport -AccessToken $token

# 3. Run it with app-only authentication, excluding App Proxy apps, custom windows
. .\Connect-EntraID.ps1
$secret = Read-Host -Prompt "Client secret" -AsSecureString
Get-AppRegistrationSecretReport -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" -ExpiredLastDays 15 -ExpiringNextDays 90
```

Every parameter, example, and prerequisite is also documented inline — run `Get-Help Get-AppRegistrationSecretReport -Full` for the complete reference.

---

## Common parameters

| Parameter | Purpose |
|---|---|
| `-AccessToken` | Supply a ready-made bearer token (Option A) |
| `-ClientId` / `-ClientSecret` / `-TenantId` | App-only authentication (Option B) |
| `-RefreshInterval` | Minutes before expiry to renew the token early when using Option B (default: 5) |
| `-OutputPath` | Path to save the CSV report (defaults to `C:\Temp\...`) |
| `-IncludeProxyApps` | Include App Proxy applications in the report (default: `$false`) |
| `-ExpiredLastDays` | Look-back window for recently expired secrets (default: 30) |
| `-ExpiringNextDays` | Look-ahead window for soon-to-expire secrets (default: 60) |
| `-ShowHelp` | Prints a plain-language usage guide and exits — no connection is made |

---

## Output

The script exports one row per secret that falls inside the configured expiration windows:

```powershell
Get-AppRegistrationSecretReport -AccessToken $token -OutputPath "C:\Reports\Secrets.csv"
```

Each row includes the app's display name and ID, the secret's end date, its hint, its expiration status, days remaining, and any notes on the app registration.

---

## A note on responsible use

This script only **reads** application and directory data — it doesn't create, modify, or remove any secrets or app registrations. Even so, the Graph permissions involved (`Application.Read.All`, `Directory.Read.All`) are broad enough to expose sensitive organizational information, so please:

- Grant these permissions only to app registrations that genuinely need them.
- Store any client secret in a proper secrets vault, not in plain text.
- Review who has access to run this script and where the exported reports (CSV) are stored.

---

## Feedback and contributions

Found an issue, or have an idea to improve this script? Feel free to open an issue or a pull request on the main repository — feedback is always welcome.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/LICENSE) file for details.
