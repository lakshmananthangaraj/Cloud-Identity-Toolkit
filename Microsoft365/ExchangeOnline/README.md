# Exchange Online PowerShell Automation

Reusable PowerShell scripts for reporting on **Microsoft Exchange Online** mailboxes, built on the **ExchangeOnlineManagement (EXO V3)** module.

This folder is part of the [Cloud-Identity-Toolkit](https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit) - a collection of automation scripts for Microsoft Entra ID, Azure, and Microsoft 365 identity and security operations.

**Who this is for:** Microsoft 365 administrators, security/compliance engineers, help desk staff, and anyone who needs mailbox visibility (permissions, forwarding, retention, holds, usage, etc.) without clicking through the Exchange admin center by hand. You do **not** need to be an experienced PowerShell user to run these — this guide assumes you're setting up PowerShell and Exchange Online access for the first time, and walks through every step.

---

## What's in this folder

| Script | What it does (in plain terms) |
|---|---|
| `Get-Mailboxes.ps1` | Inventories every mailbox in the tenant - type, addresses, hold/archive state. The natural starting point before running anything else. |
| `Get-SharedMailboxes.ps1` | Lists every shared mailbox along with who has Full Access or Send As rights on it - useful for "who can send as sales@company.com" style questions. |
| `Get-MailboxPermissions.ps1` | Audits Full Access, Send As, and Send On Behalf grants across some or all mailboxes - a general access review report. |
| `Get-MailboxDelegates.ps1` | Narrower than the permissions report above - focuses specifically on "who can act as or see into this person's mailbox/calendar" (e.g. executive assistant / manager delegation). |
| `Get-MailboxForwarding.ps1` | Flags mailboxes that are auto-forwarding email, either through a mailbox setting or a hidden Inbox rule. Important for catching data leakage. |
| `Get-InactiveMailboxes.ps1` | Flags mailboxes nobody has logged into recently, plus mailboxes that were deleted but are still being retained under a hold. Good for license clean-up. |
| `Get-MailboxStatistics.ps1` | Reports mailbox size, item count, and last logon time per mailbox - useful for storage and capacity planning. |
| `Get-MailboxAuditStatus.ps1` | Shows whether mailbox audit logging is turned on, and for how long logs are kept - a compliance/security check. |
| `Get-MailboxLitigationHold.ps1` | Lists mailboxes under Litigation Hold or an In-Place/Purview hold - for legal and compliance verification. |
| `Get-MailboxRetention.ps1` | Shows which retention and archive policy (if any) is applied to each mailbox. |
| `Get-MailboxAutoReply.ps1` | Reports Out-of-Office / automatic reply configuration per mailbox - handy for "why isn't my OOF working" tickets. |
| `Get-MailboxProtocols.ps1` | Shows which connection protocols (POP, IMAP, MAPI, OWA, ActiveSync) are enabled per mailbox, and flags legacy/insecure ones (POP3, IMAP4) that are common attack targets. |

Every script has built-in help written directly into the file. Once you've got PowerShell and the module set up (below), you can read the full description, every parameter, and worked examples for any script by running:

```powershell
Get-Help .\Get-Mailboxes.ps1 -Full
```

**A note on how these scripts behave:** every script in this folder always prints its results to the screen (and can be piped to other commands). Saving to a CSV file with `-OutputPath` is always optional, never required.

---

## Before you start (Prerequisites)

You'll need the following before running anything in this folder:

- **A Windows, macOS, or Linux computer** with internet access.
- **PowerShell 5.1 or later** (PowerShell 7.x is recommended if you're installing fresh - see Step 1).
- **A Microsoft 365 / Exchange Online account** with sufficient rights to read mailbox data. As a guideline:
  - For basic inventory/reporting scripts (mailbox lists, statistics, protocols): the **View-Only Recipients** or **View-Only Organization Management** role is usually enough.
  - For permission, delegate, forwarding, hold, and retention reports: **Recipient Management** (or **Organization Management**) role is recommended, since these pull more sensitive configuration data.
  - If you're not sure what role you have, ask your Microsoft 365 Global Administrator - the exact role names are covered in Step 3 below.
- The **ExchangeOnlineManagement** PowerShell module (version 3.x) installed. This is Microsoft's official, supported module for connecting to Exchange Online from PowerShell - it replaces the older "Remote PowerShell" connection method that Microsoft has since retired.
- (Optional, for unattended/scheduled runs) An **Entra ID App Registration** configured with certificate-based authentication, so scripts can run without a human typing a password each time.

> **New to PowerShell?** That's fine. Every command below can be copy-pasted as-is (after you replace anything in `<angle brackets>` with your own details). You'll be running these from the PowerShell console/terminal, not a regular Command Prompt.

---

## Step 1: Install PowerShell 7 (recommended, if you don't already have it)

Windows comes with an older built-in version of PowerShell (5.1), which works fine here, but PowerShell 7 is faster, cross-platform, and Microsoft's current recommendation.

**Windows** (run in an existing PowerShell or Command Prompt window):
```powershell
winget install --id Microsoft.PowerShell --source winget
```

**macOS** (using Homebrew):
```bash
brew install --cask powershell
```

**Linux:** follow the [official Microsoft installation instructions](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux) for your distribution.

After installing, open the new **PowerShell 7** app (sometimes shown as `pwsh`) to run the rest of the commands in this guide. If you'd rather stick with the Windows-builtin PowerShell 5.1, that's supported too - just open "Windows PowerShell" instead.

---

## Step 2: Install the ExchangeOnlineManagement module

This is the official Microsoft module the scripts in this folder depend on. Run this once per computer/user profile:

```powershell
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Repository PSGallery -Force
```

- `-Scope CurrentUser` installs it just for your Windows/macOS user account (no administrator rights needed).
- `-Force` skips a confirmation prompt.

If it's already installed, bring it up to date instead:

```powershell
Update-Module -Name ExchangeOnlineManagement
```

Confirm it installed correctly and check the version (aim for a `3.x` version number):

```powershell
Get-Module -Name ExchangeOnlineManagement -ListAvailable
```

> **First time installing any module from PSGallery?** PowerShell may ask "Untrusted repository, do you want to install anyway?" - answer **Yes** or **Yes to All**. This is expected the first time, since PSGallery isn't marked as a trusted source by default.

---

## Step 3: Confirm you have the right permissions

You don't need to be a Global Administrator to run these scripts - but you do need at least read access to the mailbox data being reported on. In the **Microsoft 365 admin center** or **Entra ID admin center**, ask to be added to one of these Exchange Online role groups (from least to most access):

| Role group | Good for |
|---|---|
| **View-Only Recipients** | Read-only mailbox inventory and statistics reports |
| **View-Only Organization Management** | Broader read-only access, including audit and retention configuration |
| **Recipient Management** | Permission, delegate, forwarding, and hold reports that need deeper mailbox detail |
| **Organization Management** | Full administrative access (typically reserved for Exchange/M365 admins) |

Your Global Administrator can assign you to one of these from **Microsoft 365 admin center > Roles > Exchange**, or via the Exchange admin center under **Roles > Admin roles**.

---

## Step 4: Connect to Exchange Online

Every script in this folder either reuses an already-open Exchange Online session, or - if none is found - automatically prompts you to sign in via `Connect-ExchangeOnline`. So in the simplest case, you can just run a script directly and sign in when prompted.

If you'd rather connect first yourself (recommended, so you can see the sign-in happen clearly):

```powershell
Connect-ExchangeOnline -ShowBanner:$false
```

This opens a browser window (or a device-code prompt in some environments) where you sign in with your Microsoft 365 account. Multi-factor authentication (MFA), if enabled on your account, will be prompted here too - that's expected and is the more secure, Microsoft-recommended way to sign in interactively.

If you manage more than one Microsoft 365 tenant and need to be specific about which one you're connecting to:

```powershell
Connect-ExchangeOnline -UserPrincipalName "<your.email@yourtenant.com>" -ShowBanner:$false
```

### Verify the connection

```powershell
Get-EXOMailbox -ResultSize 1
```

If this returns a single mailbox object without an error, you're connected and ready to run any script in this folder.

### (Optional) Unattended / scheduled connections with certificate-based authentication

If you plan to run these scripts on a schedule (for example, a nightly report via Task Scheduler or GitHub Actions) rather than interactively, use an **Entra ID App Registration with a certificate** instead of a personal sign-in. This is Microsoft's recommended pattern for unattended automation, since it avoids storing any password:

```powershell
Connect-ExchangeOnline `
    -CertificateThumbprint "<certificate thumbprint>" `
    -AppId "<Application (Client) ID>" `
    -Organization "<tenant>.onmicrosoft.com"
```

> **Security note:** never hardcode client IDs, certificate passwords, or tenant names directly inside a script that will be committed to source control or shared. Use a secure secret store such as **Azure Key Vault** and pull those values in at runtime instead.

---

## Step 5: Download and run a script

1. Download or clone this folder (or the whole [Cloud-Identity-Toolkit](https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit) repository) to your computer.
2. Open PowerShell and change into the folder where the scripts live, for example:
   ```powershell
   cd "C:\Scripts\Cloud-Identity-Toolkit\Microsoft365\ExchangeOnline"
   ```
3. Run any script directly. For example, to get a full mailbox inventory:
   ```powershell
   .\Get-Mailboxes.ps1
   ```
   Results print straight to the screen. To also save them to a CSV file for Excel review:
   ```powershell
   .\Get-Mailboxes.ps1 -OutputPath "C:\Reports"
   ```
   (The folder you point `-OutputPath` at must already exist - the scripts will not create it for you. Each script auto-generates a timestamped filename, e.g. `Mailboxes_20260731_143000.csv`, unless you give it a full file path ending in `.csv` instead.)

> **"Running scripts is disabled on this system" error?** Windows blocks unsigned scripts from an untrusted source by default. If you trust the source of these scripts, allow them to run for your current session only:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```
> This is a one-time setting per user profile and does not require administrator rights.

---

## Common ways to use these scripts

```powershell
# Full mailbox inventory, screen output only
.\Get-Mailboxes.ps1

# Same, but also export to CSV
.\Get-Mailboxes.ps1 -OutputPath "C:\Reports"

# Check permissions on one specific mailbox
.\Get-MailboxPermissions.ps1 -Identity "mailbox@contoso.com"

# Find mailboxes with forwarding set up, including hidden Inbox-rule forwarding
.\Get-MailboxForwarding.ps1 -IncludeInboxRules

# Find mailboxes not logged into in the last 30 days (default is 90)
.\Get-InactiveMailboxes.ps1 -InactiveDaysThreshold 30

# List all shared mailboxes and who has access to them, exported to a specific file
.\Get-SharedMailboxes.ps1 -OutputPath "C:\Reports\sharedmailboxes.csv"
```

---

## Security best practices

These scripts are built with the following principles in mind, and it's worth carrying them into how you run and maintain them:

- Prefer certificate-based authentication over interactive sign-in for anything scheduled or unattended.
- Never store credentials, client secrets, or certificate passwords inside a script.
- Request only the minimum role/permission needed for the task (principle of least privilege) - most reports here only need read access.
- Treat CSV exports as sensitive: they can contain permission and mailbox configuration data, so store them somewhere access-controlled rather than a shared, unrestricted folder.
- For production or scheduled automation, use **Azure Key Vault** (or an equivalent secret manager) rather than local certificate files or plaintext secrets.
- Disconnect your session when you're done, especially on a shared machine:
  ```powershell
  Disconnect-ExchangeOnline -Confirm:$false
  ```

---

## Learning resources

**Microsoft Learn**
- [Exchange Online PowerShell overview](https://learn.microsoft.com/powershell/exchange/exchange-online-powershell-v2)
- [ExchangeOnlineManagement module reference](https://learn.microsoft.com/powershell/module/exchange/)
- [Connect-ExchangeOnline reference](https://learn.microsoft.com/powershell/module/exchangeonlinemanagement/connect-exchangeonline)
- [Exchange Online admin roles](https://learn.microsoft.com/exchange/permissions-exo/permissions-exo)
- [Microsoft 365 documentation](https://learn.microsoft.com/microsoft-365)
- [Microsoft Learn training paths](https://learn.microsoft.com/training/)

**Video walkthrough**
- Search "Connect to Exchange Online PowerShell" on the [Microsoft 365 YouTube channel](https://www.youtube.com/@Microsoft365) for an up-to-date, visual walkthrough of the connection steps above.

---

## Getting help / troubleshooting

If a script isn't behaving as expected, work through this checklist before raising an issue:

1. Confirm you're running **ExchangeOnlineManagement 3.x**: `Get-Module -Name ExchangeOnlineManagement -ListAvailable`.
2. Confirm you can connect manually with `Connect-ExchangeOnline -ShowBanner:$false` and that `Get-EXOMailbox -ResultSize 1` returns data without an error.
3. Confirm your account has one of the role groups listed in Step 3 above - a permissions error (`Access Denied` / `Insufficient permissions`) almost always traces back to this.
4. Check the specific script's built-in help for known limitations that might explain unexpected results: `Get-Help .\<ScriptName>.ps1 -Full`.
5. If the issue persists, open an issue in this GitHub repository with the exact error message and the steps that led to it - that context makes it much faster to diagnose.

---

## A note on authentication

For day-to-day, ad-hoc reporting, interactive sign-in via `Connect-ExchangeOnline` (with MFA) is perfectly fine and is what most of these scripts default to. 
If you're adapting any script here for a **scheduled or unattended** job, switch to certificate-based App Registration authentication as shown in Step 4 - that's the approach Microsoft recommends for production automation, and it avoids ever storing a password.
