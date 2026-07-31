# SharePoint Online PowerShell Automation

Reusable PowerShell scripts for reporting on and managing **Microsoft SharePoint Online**, built on the **PnP PowerShell** module.

This folder is part of the [Cloud-Identity-Toolkit](../../) — a collection of automation scripts for Microsoft Entra ID, Azure, and Microsoft 365 identity and security operations.

**Who this is for:** Microsoft 365 administrators, cloud/security engineers, and IT professionals who want to automate day-to-day SharePoint Online administration and reporting instead of relying on manual, click-through steps in the admin portal. No deep PowerShell background is required to run the scripts — each one is documented with clear parameters and examples.

---

## What's in this folder

| Script | What it does |
|---|---|
| `Get-SharePointSites.ps1` | Lists every SharePoint Online site in the tenant, including communication sites and team sites — a quick inventory of what exists. |
| `Get-SharePointSiteOwners.ps1` | Identifies the owner(s) of each site, so accountability and ongoing management are clear. |
| `Get-SharePointSitePermissions.ps1` | Reports who (users and groups) has access to a site and at what permission level. |
| `Get-SharePointStorageUsageReport.ps1` | Reports how much storage each site is consuming, useful for capacity planning and cost tracking. |
| `Get-SharePointExternalSharingReport.ps1` | Reports external sharing settings and identifies external (guest) users with access — an important check for data governance and security. |

Each script includes built-in help (comment-based help), so running `Get-Help .\<ScriptName>.ps1 -Full` in PowerShell will show its purpose, parameters, and usage examples.

---

## Before you start (Prerequisites)

To run these scripts, you'll need:

- **PowerShell 7.x** (recommended)
- A **Microsoft Entra ID** tenant
- **SharePoint Online Administrator** rights, or an account with equivalent permissions
- The **PnP PowerShell** module installed
- An **Entra ID App Registration** configured with certificate-based authentication (this is the recommended, more secure alternative to storing a username and password)

> **Why certificate-based authentication?** It allows scripts to run unattended (for example, on a schedule) without ever storing a password, and it's the approach Microsoft recommends for production automation.

---

## Step 1: Install the PnP PowerShell module

```powershell
Install-Module PnP.PowerShell -Scope CurrentUser
```

If it's already installed, keep it current:

```powershell
Update-Module PnP.PowerShell
```

Confirm it installed correctly:

```powershell
Get-Module PnP.PowerShell -ListAvailable
```

---

## Step 2: Register an Entra ID application

PnP PowerShell can register the required Entra ID application for you. Replace every placeholder (the values in `<angle brackets>`) with details specific to your tenant.

```powershell
Register-PnPAzureADApp `
    -ApplicationName "<Application Name>" `
    -Tenant "<tenant>.onmicrosoft.com" `
    -Store CurrentUser `
    -GraphApplicationPermissions "Sites.Read.All" `
    -SharePointApplicationPermissions "Sites.FullControl.All" `
    -GraphDelegatePermissions "Sites.Read.All","User.Read" `
    -SharePointDelegatePermissions "AllSites.FullControl" `
    -CertificatePassword (
        ConvertTo-SecureString "<Certificate Password>" `
        -AsPlainText `
        -Force
    )
```

> **Security note:** Never hardcode passwords, client IDs, tenant names, or certificate secrets directly in a script — especially one that will be shared, committed to source control, or scheduled to run automatically. Use a secure secret store such as **Azure Key Vault** instead, and reference secrets from there at runtime.

---

## Step 3: Connect to SharePoint Online

Build a secure credential object:

```powershell
$password = ConvertTo-SecureString `
    "<Certificate Password>" `
    -AsPlainText `
    -Force
```

Then connect using certificate authentication:

```powershell
Connect-PnPOnline `
    -Url "https://<tenant>.sharepoint.com" `
    -ClientId "<Application (Client) ID>" `
    -CertificatePath "C:\Certificates\<certificate>.pfx" `
    -CertificatePassword $password `
    -Tenant "<tenant>.onmicrosoft.com"
```

---

## Step 4: Verify the connection

```powershell
Get-PnPWeb
```

A successful connection returns basic information about the SharePoint site — confirming you're ready to run the scripts in this folder.

---

## Security best practices

These scripts are built with the following principles in mind, and it's worth carrying them into how you run and maintain them:

- Prefer certificate-based authentication over passwords wherever possible.
- Never store credentials or secrets inside a script.
- Grant only the minimum permissions required for the task (principle of least privilege).
- Rotate certificates on a regular schedule.
- Store certificates in a protected location, with access restricted to those who need it.
- For production or scheduled automation, use **Azure Key Vault** (or an equivalent secret manager) rather than local files.

---

## Learning resources

**Microsoft Learn**
- [SharePoint documentation](https://learn.microsoft.com/sharepoint)
- [Microsoft Entra ID documentation](https://learn.microsoft.com/entra)
- [Microsoft Graph documentation](https://learn.microsoft.com/graph)
- [Microsoft 365 documentation](https://learn.microsoft.com/microsoft-365)
- [Microsoft Learn training paths](https://learn.microsoft.com/training/)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/powershell/microsoftgraph/)
- [SharePoint developer documentation](https://learn.microsoft.com/sharepoint/dev/)

**PnP PowerShell**
- [PnP PowerShell home](https://pnp.github.io/powershell/)
- [Authentication guide](https://pnp.github.io/powershell/articles/authentication.html)
- [Registering an Entra ID application](https://pnp.github.io/powershell/articles/registerapplication.html)
- [Connect-PnPOnline reference](https://pnp.github.io/powershell/cmdlets/Connect-PnPOnline.html)
- [Register-PnPEntraIDApp reference](https://pnp.github.io/powershell/cmdlets/Register-PnPEntraIDApp.html)

**Video walkthrough**
- [Configuring PnP PowerShell authentication and connecting to SharePoint Online](https://www.youtube.com/watch?v=yPd4Lqx08NI)

---

## Getting help / troubleshooting

If a script isn't behaving as expected, work through this checklist before raising an issue:

1. Confirm you're running the latest version of **PnP PowerShell**.
2. Confirm the Entra ID application has been granted the required Microsoft Graph and SharePoint permissions.
3. Confirm admin consent has been granted for those permissions, where required.
4. Review the official documentation linked above for guidance specific to the error you're seeing.
5. If the issue persists, open an issue in this GitHub repository with the exact error message and the steps that led to it — that context makes it much faster to diagnose.

---

## A note on authentication

This folder standardizes on **certificate-based authentication**, which is Microsoft's recommended approach for secure, unattended PowerShell automation. If you're adapting these scripts for your own environment, we'd encourage keeping that same approach rather than falling back to interactive or password-based sign-in.
