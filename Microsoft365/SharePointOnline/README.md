# SharePoint Online PowerShell

This folder contains PowerShell scripts for managing and reporting on **Microsoft SharePoint Online** using **PnP PowerShell**.

The scripts are designed for administrators, cloud engineers, Microsoft 365 engineers, and IT professionals who need to automate SharePoint Online administration.

---

# Prerequisites

Before running any script in this folder, ensure the following prerequisites are completed.

- PowerShell 7.x (Recommended)
- Microsoft Entra ID Tenant
- SharePoint Online Administrator or appropriate permissions
- PnP PowerShell Module
- An Entra ID Application Registration with certificate-based authentication

---

# Install Required Module

Install the latest supported PnP PowerShell module.

```powershell
Install-Module PnP.PowerShell -Scope CurrentUser
```

If the module is already installed:

```powershell
Update-Module PnP.PowerShell
```

Verify installation:

```powershell
Get-Module PnP.PowerShell -ListAvailable
```

---

# Create an Entra ID Application

PnP PowerShell supports creating an Entra ID application automatically.

Replace the placeholder values with your own tenant information.

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

> **Note**
>
> Never hardcode passwords, client IDs, tenant names, or certificates in production scripts. Use secure secret management solutions such as **Azure Key Vault** whenever possible.

---

# Connect to SharePoint Online

Create a secure password object.

```powershell
$password = ConvertTo-SecureString `
    "<Certificate Password>" `
    -AsPlainText `
    -Force
```

Connect using certificate authentication.

```powershell
Connect-PnPOnline `
    -Url "https://<tenant>.sharepoint.com" `
    -ClientId "<Application (Client) ID>" `
    -CertificatePath "C:\Certificates\<certificate>.pfx" `
    -CertificatePassword $password `
    -Tenant "<tenant>.onmicrosoft.com"
```

---

# Verify Connection

Run the following command.

```powershell
Get-PnPWeb
```

If the connection is successful, SharePoint Online site information will be returned.

---

# Folder Contents

| Script | Description |
|---------|-------------|
| Get-SharePointSites.ps1 | Lists all SharePoint Online sites |
| Get-SharePointSiteOwners.ps1 | Retrieves site owners |
| Get-SharePointSitePermissions.ps1 | Reports site permissions |
| Get-SharePointStorageUsageReport.ps1 | Generates storage usage report |
| Get-SharePointExternalSharingReport.ps1 | Reports external sharing configuration |

---

# Security Best Practices

- Use certificate-based authentication.
- Never store passwords inside scripts.
- Grant only the minimum required permissions.
- Rotate certificates regularly.
- Store certificates securely.
- Consider Azure Key Vault for production environments.

---

# Useful Learning Resources

## Microsoft Learn

- Microsoft SharePoint Documentation
- Microsoft Entra ID Documentation
- Microsoft Graph Documentation

## PnP PowerShell

Official PnP PowerShell documentation

## Authentication

PnP PowerShell Authentication Guide

## Registering an Entra ID Application

PnP PowerShell App Registration Guide

---

---

# Official Documentation

The following official resources provide detailed guidance on SharePoint Online, PnP PowerShell, Microsoft Graph, and Microsoft Entra ID.

## Microsoft Learn

| Resource | Description |
|----------|-------------|
| Microsoft SharePoint Documentation | Official documentation for SharePoint Online administration, development, and best practices. |
| Microsoft Entra ID Documentation | Learn about Microsoft Entra ID, identity management, authentication, and application registrations. |
| Microsoft Graph Documentation | Official Microsoft Graph REST API and PowerShell documentation. |
| Microsoft 365 Documentation | Official Microsoft 365 administration documentation. |

### Direct Links

- Microsoft SharePoint Documentation
  https://learn.microsoft.com/sharepoint

- Microsoft Entra ID Documentation
  https://learn.microsoft.com/entra

- Microsoft Graph Documentation
  https://learn.microsoft.com/graph

- Microsoft 365 Documentation
  https://learn.microsoft.com/microsoft-365

---

# Official PnP PowerShell Documentation

PnP PowerShell is the recommended community-driven PowerShell module for Microsoft 365 and SharePoint Online automation.

### Documentation

- PnP PowerShell Home
  https://pnp.github.io/powershell/

- Authentication Guide
  https://pnp.github.io/powershell/articles/authentication.html

- Register an Entra ID Application
  https://pnp.github.io/powershell/articles/registerapplication.html

- Connect-PnPOnline Cmdlet
  https://pnp.github.io/powershell/cmdlets/Connect-PnPOnline.html

- Register-PnPEntraIDApp Cmdlet
  https://pnp.github.io/powershell/cmdlets/Register-PnPEntraIDApp.html

---

# Video Tutorial

The following video provides a practical walkthrough for configuring PnP PowerShell authentication and connecting to SharePoint Online.

▶️ https://www.youtube.com/watch?v=yPd4Lqx08NI

---

# Additional Learning Resources

- Microsoft Learn Training
  https://learn.microsoft.com/training/

- Microsoft Graph PowerShell SDK
  https://learn.microsoft.com/powershell/microsoftgraph/

- SharePoint Developer Documentation
  https://learn.microsoft.com/sharepoint/dev/

---

# Support

If you encounter any issues with the scripts in this repository:

1. Verify that the latest version of **PnP PowerShell** is installed.
2. Ensure the required Microsoft Graph and SharePoint permissions have been granted to the Microsoft Entra ID application.
3. Confirm that administrator consent has been granted where required.
4. Review the official documentation referenced above for troubleshooting guidance.
5. If the issue persists, consider raising an issue in this GitHub repository with detailed error information.


---

# Notes

This repository uses **certificate-based authentication**, which is Microsoft's recommended approach for secure automation and unattended PowerShell execution.
