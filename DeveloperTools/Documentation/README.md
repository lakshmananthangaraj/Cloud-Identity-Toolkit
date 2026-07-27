# Documentation

Tools for keeping this repository's documentation in sync with the actual scripts on disk.

## Scripts

### `Generate-MarkdownDocumentation.ps1`

Scans a folder tree of PowerShell scripts and generates/updates a Markdown catalog of what's there — either inserted as a table into each folder's own `README.md`, or written out as a single consolidated catalog file.

**Highlights**
- Reads script metadata safely — **scripts are never executed**. Function names are discovered via AST parsing (`System.Management.Automation.Language.Parser`), the same safe technique used by [`New-PSModuleFromScripts.ps1`](../ModuleBuilder/New-PSModuleFromScripts.ps1). Synopsis is read via the AST's own `GetHelpContent()` — the same mechanism `Get-Help` uses internally, without running the script.
- Two output modes:
  - **`PerFolderReadme`** *(default)* — inserts/updates a catalog table inside each folder's own `README.md`, between auto-generated marker comments. Everything outside those markers (your own hand-written intro, notes, examples) is left untouched. Creates a minimal `README.md` if a folder doesn't have one yet.
  - **`SingleCatalogFile`** — writes one consolidated Markdown file (default `SCRIPT-CATALOG.md`) covering every scanned folder, without touching any individual README.
- `-WhatIf` support for a dry run before writing anything.
- `-Force` protects against silently overwriting an unrelated file at `-OutputPath` in `SingleCatalogFile` mode — it only overwrites files that already carry this tool's own generated-file marker, unless `-Force` is specified.
- Returns a summary object (`FoldersScanned`, `FoldersDocumented`, `ScriptsDocumented`, `ScriptsWithMissingMetadata`, `OutputFiles`) so you can programmatically check which scripts still need a Synopsis or Author block cleaned up.
- `Write-Verbose` for progress, `Write-Warning` for per-file metadata gaps — no dependency on the shared console toolkit.

#### Requirements
- PowerShell 5.1+
- Write access to the folders being documented (`PerFolderReadme` mode) or to `-OutputPath` (`SingleCatalogFile` mode)
- No other dependencies — this script does not use any internal/repo-specific module

#### Usage

Update the `README.md` in every folder of the repo that contains scripts:

```powershell
. .\Generate-MarkdownDocumentation.ps1
Generate-MarkdownDocumentation -SourcePath "D:\Cloud-Identity-Toolkit" -Recurse
```

Dry-run against a single folder — see what would change without writing anything:

```powershell
Generate-MarkdownDocumentation -SourcePath "D:\Cloud-Identity-Toolkit\Entra-ID\Users" -WhatIf
```

Build one consolidated catalog document for the whole repo instead of touching individual READMEs:

```powershell
Generate-MarkdownDocumentation -SourcePath "D:\Cloud-Identity-Toolkit" -Recurse `
    -Mode SingleCatalogFile -OutputPath "D:\Cloud-Identity-Toolkit\SCRIPT-CATALOG.md" -Force
```

Run with full narration, then inspect which scripts still need documentation cleanup:

```powershell
$result = Generate-MarkdownDocumentation -SourcePath "D:\Cloud-Identity-Toolkit" -Recurse -Verbose
if ($result.ScriptsWithMissingMetadata.Count -gt 0)
{
    $result.ScriptsWithMissingMetadata | Format-Table
}
```

Full parameter/example documentation:

```powershell
Get-Help Generate-MarkdownDocumentation -Full
```

#### Known limitations

- Synopsis extraction relies on a one-function-per-file convention with the help block immediately preceding the function. Files with multiple functions or unconventional layouts may show a blank Synopsis — this is reported via `ScriptsWithMissingMetadata`, not silently hidden.
- If a folder's `README.md` already has a start-marker with no matching end-marker (edited by hand and broken), the function throws rather than guessing where the auto-generated section should end.
- Reflects the current state of the folder on each run — it does not detect or reconcile scripts that were renamed/deleted since the last run beyond what currently exists on disk.

## Output

`Generate-MarkdownDocumentation` returns a summary object with these properties: `FoldersScanned`, `FoldersDocumented`, `ScriptsDocumented`, `ScriptsWithMissingMetadata`, `OutputFiles` — pipe or inspect the result to drive further automation (e.g. failing a build if metadata is missing).