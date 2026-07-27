# Code Quality

Tools for linting and enforcing PowerShell code quality across this repository.

## Scripts

### `Invoke-ScriptAnalyzer.ps1`

Wraps [PSScriptAnalyzer](https://www.powershellgallery.com/packages/PSScriptAnalyzer) to lint an entire folder (or a single file) of PowerShell scripts/modules in one pass, print a console summary, and optionally generate an interactive HTML code-quality dashboard. Built to scan this whole repo at once and to gate CI/CD pipelines on findings.

**Highlights**
- Recursive scan of a folder, or a single file
- Severity filtering (`Error`, `Warning`, `Information`) and rule include/exclude
- Optional custom PSScriptAnalyzer settings file
- CI/CD-friendly: `-FailOnSeverity` returns a non-zero exit code when matching findings exist
- Auto-installs PSScriptAnalyzer for the current user if it isn't already present
- Styled console summary using plain `Write-Host` output — no internal/repo-specific module dependency, runs standalone anywhere
- Optional HTML dashboard: Overview (KPIs), Findings (search/sort/paginate), By Rule, By File, and CSV/JSON export tabs, with dark/light theme toggle

#### Requirements
- PowerShell 5.1+ (Windows PowerShell or PowerShell 7)
- [PSScriptAnalyzer](https://www.powershellgallery.com/packages/PSScriptAnalyzer) module (installed automatically on first run if missing)
- No other dependencies — this script does not use any internal/repo-specific module

#### Usage

Scan the whole repo and print a console summary:

```powershell
. .\Invoke-ScriptAnalyzer.ps1
Invoke-ScriptAnalyzer -Path . -Recurse
```

Scan the repo, ignore a rule this toolkit intentionally violates, and open the HTML dashboard:

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -ExcludeRule 'PSAvoidUsingWriteHost' -GenerateHtmlDoc
```

Scan a single folder and gate a CI/CD pipeline on Errors only:

```powershell
Invoke-ScriptAnalyzer -Path .\Entra-ID -Recurse -Severity Error,Warning -FailOnSeverity Error
```

Scan a single file with a custom settings file:

```powershell
Invoke-ScriptAnalyzer -Path .\Get-AllUsers.ps1 -SettingsPath .\PSScriptAnalyzerSettings.psd1
```

Show the friendly help guide:

```powershell
Invoke-ScriptAnalyzer -ShowHelp
```

Full parameter/example documentation:

```powershell
Get-Help Invoke-ScriptAnalyzer -Full
```

#### Exit codes

Exit codes are only meaningful when `-FailOnSeverity` is supplied:

| Code | Meaning |
|---|---|
| `0` | No findings at/above the specified severity (or `-FailOnSeverity` not supplied) |
| `1` | One or more findings at/above the specified severity were found |

#### Example: GitHub Actions gate

```yaml
- name: Lint PowerShell scripts
  shell: pwsh
  run: |
    . ./DeveloperTools/CodeQuality/Invoke-ScriptAnalyzer.ps1
    Invoke-ScriptAnalyzer -Path . -Recurse -FailOnSeverity Error,Warning
    exit $LASTEXITCODE
```

## Output

`Invoke-ScriptAnalyzer` returns structured finding objects with these properties: `File`, `FullPath`, `Line`, `Column`, `Rule`, `Severity`, `Message` — pipe the result into `Export-Csv`, `ConvertTo-Json`, `Where-Object`, etc. for further processing.
