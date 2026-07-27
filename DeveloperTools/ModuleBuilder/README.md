# Module Builder

Turns a folder of standalone `.ps1` function scripts into a proper, importable
PowerShell module — a `.psm1` loader plus a `.psd1` manifest — without hand-writing
either file.

**Who this is for:** anyone maintaining a growing folder of one-function-per-file
PowerShell scripts (like the rest of this toolkit) who wants a single
`Import-Module` instead of dot-sourcing files by hand, or who wants to package a
subset of scripts (e.g. just the Key Vault functions) as a standalone module for
distribution.

## What's included

| Script | What it does |
|---|---|
| [`New-PSModuleFromScripts.ps1`](./New-PSModuleFromScripts.ps1) | Scans a source folder, discovers functions via AST parsing (not filename guessing), and generates the `.psm1` + `.psd1` for a redistributable module |

## Quick start

```powershell
. .\New-PSModuleFromScripts.ps1

New-PSModuleFromScripts `
    -SourcePath  "C:\Scripts\MyFunctions" `
    -ModuleName  "MyToolkit" `
    -OutputPath  "C:\PowerShell-Modules"

Import-Module "C:\PowerShell-Modules\MyToolkit\MyToolkit.psd1"
Get-Command -Module MyToolkit
```

Each `.ps1` file in `-SourcePath` should contain one or more functions with
standard comment-based help. The function reads the file's syntax tree to find
every function actually defined inside it, so it works even if a filename and
function name don't match exactly.

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-SourcePath` | Yes | Folder containing the `.ps1` scripts to include |
| `-ModuleName` | Yes | Name of the module (also the folder/file base name). Letters, digits, dots, dashes, underscores only |
| `-OutputPath` | No | Where the module folder is created. Defaults to a `Modules` folder next to `-SourcePath`'s parent |
| `-ModuleVersion` | No | Version stamped into the manifest. Default `1.0.0` |
| `-Author` | No | Author stamped into the manifest. Default `Lakshmanan Thangaraj` — override when building on someone else's behalf |
| `-Description` | No | Description stamped into the manifest |
| `-ProjectUri` | No | Optional repo/project URL for the manifest's metadata |
| `-Tags` | No | Optional tags for the manifest's metadata. Default `PowerShell`, `Module` |
| `-Recurse` | No | Switch. Also scans subfolders of `-SourcePath` |
| `-Force` | No | Switch. Rebuilds an existing module folder of the same name (see GUID handling below) |

Supports `-WhatIf` and `-Verbose`.

## Safety behavior worth knowing about

This tool writes files and can delete an existing folder when `-Force` is used,
so it's built with a few deliberate guardrails:

- **`-ModuleName` is validated** against a safe character set — it can never be
  used to make the generated module folder resolve outside `-OutputPath`.
- **Source-overlap protection** — the function refuses to run if the computed
  module folder is the same as, or nests with, `-SourcePath`. This stops
  `-Force` from ever deleting your source scripts before they're copied.
- **Stable module identity** — each new module gets a freshly generated GUID.
  Rebuilding an existing module with `-Force` preserves that module's original
  GUID (read from the prior manifest) instead of assigning a new one every time
  — GUIDs are meant to identify a module across versions, not change on every
  rebuild.
- **Manifest generation uses the real `New-ModuleManifest` cmdlet**, not a
  hand-rolled string template — so `-Author`/`-Description` values are quoted
  and escaped correctly rather than risking a malformed `.psd1`.

## Known limitations

- The generated module dot-sources and runs every `.ps1` file in its `Public`
  folder at `Import-Module` time. Only build modules from source folders you
  trust — this tool checks for function definitions, not for malicious code.
- The generated module is not code-signed. Sign it separately if your
  environment enforces a signed-scripts execution policy.
- `-Author` defaults to this toolkit's maintainer — override it for modules
  built on someone else's behalf.

## Example: packaging part of this toolkit

```powershell
New-PSModuleFromScripts `
    -SourcePath  "..\..\Azure\KeyVault" `
    -ModuleName  "CloudIdentityToolkit.KeyVault" `
    -OutputPath  "C:\PowerShell-Modules" `
    -ProjectUri  "https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit" `
    -Tags        @('Azure', 'KeyVault', 'Security')
```

---
Part of the [Cloud-Identity-Toolkit](https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit) `DeveloperTools` suite. See the
[repository README](https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/README.md) for license and contribution information.