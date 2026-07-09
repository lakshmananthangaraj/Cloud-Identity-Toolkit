# PIM — Entra ID Privileged Identity Management Reporting

This folder contains two PowerShell functions that give you a complete picture of privileged access in your Microsoft Entra ID (Azure AD) tenant — who has it, how they got it, and whether it's permanent or time-bound.

If you've ever had to answer "who currently has Global Administrator?" or prepare for a security audit, these scripts turn that into a two-minute task instead of a morning of clicking through the Entra portal.

---

## What's in this folder

| Script | What it reports on |
|---|---|
| **`Get-PIMActiveEntraIDRoleAssignmentDetails.ps1`** | Roles that are **currently active** right now — either permanently assigned, or temporarily activated through PIM |
| **`Get-PIMEligibleEntraIDRoleAssignmentDetails.ps1`** | Roles that a user, group, or app **could activate** via PIM, but hasn't (yet) |

Run both together and you get the full story: who *has* access today, and who *could get* access on demand — which is exactly the pair of questions a security review usually asks.

Both scripts follow the same design and are safe to use side by side.

---

## Why this is useful

For a **security or compliance team**, this answers questions like:
- Does anyone have a *permanent* Global Administrator assignment, when it should really be time-bound?
- How many people could activate a privileged role but haven't used it in months (a sign it may no longer be needed)?
- Which roles are assigned to service principals or groups instead of named people — often a blind spot in access reviews?

For **IT operations**, it's a fast, repeatable export — no manual portal digging, and it can be scheduled to run automatically (see [Authentication](#authentication) below).

For **leadership / non-technical readers**, the optional HTML dashboard turns all of the above into charts, KPI tiles, and plain-language risk callouts - no PowerShell knowledge required to read the results.

---

## Key features (both scripts)

- ✅ Pulls **every** role assignment across the whole tenant, handling pagination automatically — nothing is missed on large tenants
- ✅ Gracefully waits and retries if Microsoft Graph throttles the request (HTTP 429), instead of failing partway through
- ✅ Recognizes three assignment types: **users**, **groups**, and **service principals (apps)**
- ✅ Returns clean, structured data ready to pipe into CSV, Excel, or Power BI
- ✅ Optional interactive **HTML dashboard** (`-GenerateHtmlDoc`) with:
  - Overview KPIs and a security risk indicator
  - Separate tabs for Users, Groups, and Service Principals
  - Risk Insights (permanent access, high-privilege roles, stale access)
  - One-click CSV / JSON export
  - Light and dark theme, search, sort, and pagination
- ✅ Two supported ways to authenticate (see below) — whichever fits how you run the script

---

## Prerequisites

1. **PowerShell 5.1 or later** (Windows PowerShell or PowerShell 7+).
2. **An Entra ID app registration** (or an existing signed-in session) with the following Microsoft Graph permissions:
   - `RoleManagement.Read.Directory`
   - `Directory.Read.All`

   > **A note on least privilege:** these are the permissions needed to read role assignments and resolve who they belong to. If your PIM usage is limited to users only (no groups or apps), it's worth testing with `RoleManagement.Read.Directory` alone before granting the broader `Directory.Read.All` permission.

3. A modern browser (Chrome, Edge, Firefox) if you plan to view the generated HTML dashboard.

---

## Authentication

Both scripts support **either** of the following — pick whichever suits your situation. You don't need both.

### Option A — Bring your own token (quick, manual runs)

Use this if you already have a Graph access token — for example, copied from [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer), or obtained via `Connect-MgGraph`.

```powershell
Get-PIMActiveEntraIDRoleAssignmentDetails -AccessToken $token -TenantName "Contoso" -GenerateHtmlDoc
```

This is the fastest way to try the script out, but a token copied from a browser session is short-lived (about an hour) and isn't suitable for anything unattended or scheduled.

### Option B — App-only login (recommended for automation)

For scheduled tasks, Azure Automation, or any unattended run, use the companion authentication helper published alongside this folder:

**[`Connect-EntraID.ps1`](../Authentication/Connect-EntraID.ps1)**

This uses the standard OAuth2 **client credentials flow** with an app registration (Client ID + Client Secret + Tenant ID) — no human sign-in required, and the underlying token is renewed automatically for you if a run takes a while.

```powershell
. .\Connect-EntraID.ps1
$secret = Read-Host -Prompt "Client secret" -AsSecureString

Get-PIMActiveEntraIDRoleAssignmentDetails -ClientId "<app-id>" -ClientSecret $secret -TenantId "<tenant-id>" -GenerateHtmlDoc
```

> **On security:** a client secret is a shared credential, so store it the same way you'd store any sensitive password — in a secure vault (e.g. Azure Key Vault), never hardcoded in a script or committed to source control. If you're running this from inside Azure (an Automation Account or Function App), a **Managed Identity** is a stronger option still, since there's no secret to manage or leak at all — that's a natural next step once you're ready to move this into a fully hosted, unattended pipeline.

---

## Quick start

```powershell
# 1. See what parameters and options are available, without connecting to anything
Get-PIMActiveEntraIDRoleAssignmentDetails -ShowHelp

# 2. Run it with a manual token and generate the dashboard
Get-PIMActiveEntraIDRoleAssignmentDetails -AccessToken $token -TenantName "Contoso" -TenantId "<tenant-id>" -GenerateHtmlDoc

# 3. Run the eligible-roles report the same way
Get-PIMEligibleEntraIDRoleAssignmentDetails -AccessToken $token -TenantName "Contoso" -TenantId "<tenant-id>" -GenerateHtmlDoc
```

Every parameter, example, and prerequisite is also documented inline — run `Get-Help Get-PIMActiveEntraIDRoleAssignmentDetails -Full` (or the Eligible equivalent) for the complete reference.

---

## Common parameters

| Parameter | Purpose |
|---|---|
| `-AccessToken` | Supply a ready-made bearer token (Option A) |
| `-ClientId` / `-ClientSecret` / `-TenantId` | App-only authentication (Option B) |
| `-TenantName` | Friendly name shown in the dashboard header |
| `-GenerateHtmlDoc` | Builds and opens the interactive HTML dashboard |
| `-OutputPath` | Folder to save the dashboard to (defaults to your system temp folder) |
| `-ShowHelp` | Prints a plain-language usage guide and exits — no connection is made |

---

## Output

Both scripts return one structured object per role assignment, including the assigned principal (user, group, or app), the role name, assignment state, and start/end times — ready to use as-is or export further:

```powershell
Get-PIMActiveEntraIDRoleAssignmentDetails -AccessToken $token | Export-Csv -Path "ActiveRoles.csv" -NoTypeInformation
```

With `-GenerateHtmlDoc`, the same data is also rendered as a self-contained HTML file you can open in any browser, share with non-technical stakeholders, or archive as an audit snapshot.

---

## A note on responsible use

These scripts only **read** directory and role data — they don't create, modify, or remove any role assignments. Even so, the Graph permissions involved (`Directory.Read.All`, `RoleManagement.Read.Directory`) are broad enough to expose sensitive organizational information, so please:

- Grant these permissions only to app registrations that genuinely need them.
- Store any client secret in a proper secrets vault, not in plain text.
- Review who has access to run these scripts and where the exported reports (CSV/JSON/HTML) are stored.

---

## Feedback and contributions

Found an issue, or have an idea to improve these scripts? Feel free to open an issue or a pull request on the main repository — feedback is always welcome.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/LICENSE) file for details.
