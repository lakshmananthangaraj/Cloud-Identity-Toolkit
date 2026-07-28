<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 27 July 2026
Modified-On  : 27 July 2026

.SYNOPSIS
    Scans a folder tree of PowerShell scripts and generates/updates a Markdown
    catalog of what's there - either as a table inserted into each folder's
    README.md, or as one master catalog file.

.DESCRIPTION
    Generate-MarkdownDocumentation walks -SourcePath (optionally recursing into
    subfolders) and, for every folder that contains at least one .ps1 file,
    builds a table of: script name (linked), synopsis, author-block version,
    and last-modified date.

    Metadata is read safely - the script is never executed. Function names are
    discovered via AST parsing (System.Management.Automation.Language.Parser),
    the same safe technique used by New-PSModuleFromScripts. Synopsis is read
    via the AST's own GetHelpContent() method (the same mechanism Get-Help uses
    internally, but without running the script). Author/Version/Created-On/
    Modified-On are read with a small text pattern match against the file's
    leading comment block, since that custom header isn't a standard
    comment-based-help keyword.

    Two output modes:
      - PerFolderReadme (default): inserts/updates the catalog table inside
        each folder's own README.md, between two auto-generated marker
        comments. Everything outside those markers - your own hand-written
        intro text, notes, examples - is left untouched. If a folder has no
        README.md yet, a minimal one is created.
      - SingleCatalogFile: writes one consolidated Markdown file (default
        SCRIPT-CATALOG.md at -SourcePath) with one section per folder, instead
        of touching any individual README.

.PARAMETER SourcePath
    Root folder to scan for .ps1 scripts.

.PARAMETER Mode
    'PerFolderReadme' (default) or 'SingleCatalogFile'. See .DESCRIPTION.

.PARAMETER OutputPath
    Only used when -Mode is 'SingleCatalogFile'. Path of the master catalog
    file to write. Default: "<SourcePath>\SCRIPT-CATALOG.md".

.PARAMETER ReadmeFileName
    Only used when -Mode is 'PerFolderReadme'. Filename to create/update in
    each qualifying folder. Default: "README.md".

.PARAMETER ExcludeFolder
    Folder names to skip anywhere in the scanned tree. Default: '.git',
    '.github', '.vscode'.

.PARAMETER Recurse
    If specified, scans subfolders of -SourcePath too. Without it, only
    -SourcePath itself is scanned (no descent into subfolders).

.PARAMETER Force
    Only meaningful for -Mode 'SingleCatalogFile'. Without it, the function
    refuses to overwrite an existing file at -OutputPath unless that file
    already carries this tool's own generated-file marker (protects against
    silently overwriting an unrelated file someone else created at that
    path). With -Force, overwrites regardless.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    PSCustomObject with properties: FoldersScanned, FoldersDocumented,
    ScriptsDocumented, ScriptsWithMissingMetadata, OutputFiles.

.EXAMPLE
    Generate-MarkdownDocumentation -SourcePath "D:\Cloud-Identity-Toolkit" -Recurse

    Walks the entire repo and updates the README.md inside every folder that
    contains scripts, leaving hand-written content in each README untouched.

.EXAMPLE
    Generate-MarkdownDocumentation -SourcePath "D:\Cloud-Identity-Toolkit\Entra-ID\Users" -WhatIf

    Dry-run against a single folder - shows what would be written without
    actually touching README.md.

.EXAMPLE
    Generate-MarkdownDocumentation -SourcePath "D:\Cloud-Identity-Toolkit" -Recurse `
        -Mode SingleCatalogFile -OutputPath "D:\Cloud-Identity-Toolkit\SCRIPT-CATALOG.md" -Force

    Builds one consolidated catalog document covering every folder in the repo.

.EXAMPLE
    $result = Generate-MarkdownDocumentation -SourcePath "D:\Cloud-Identity-Toolkit" -Recurse -Verbose
    if ($result.ScriptsWithMissingMetadata.Count -gt 0)
    {
        $result.ScriptsWithMissingMetadata | Format-Table
    }

    Runs with full narration, then inspects which scripts didn't have a
    readable Synopsis or Author block - useful for finding scripts that still
    need documentation cleanup.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (27-Jul-2026) - Initial release.
    
    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. PowerShell 5.1+.
    2. Write access to the folders being documented (PerFolderReadme mode) or
       to -OutputPath (SingleCatalogFile mode).

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
    Step 1 → Determine which folders to scan (SourcePath, +subfolders if -Recurse)
    Step 2 → For each folder, read every .ps1's metadata WITHOUT executing it
    Step 3 → Build a Markdown table per folder
    Step 4 → PerFolderReadme: insert/update table between markers in each
             folder's README.md (create a minimal README if none exists)
             SingleCatalogFile: write one consolidated document
    Step 5 → Return a summary object

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Synopsis extraction relies on your one-function-per-file convention with
      the help block immediately preceding the function. Files with multiple
      functions, or unconventional layouts, may show a blank Synopsis - this
      is reported via ScriptsWithMissingMetadata, not silently hidden.
    - If a folder's README.md already contains a start-marker with no matching
      end-marker (edited by hand and broken), the function throws rather than
      guessing where the auto-generated section is meant to end.
    - Does not detect or reconcile scripts that were renamed/deleted since the
      last run beyond what currently exists on disk - it always reflects the
      current state of the folder, not a diff against a prior catalog.
    - Console Output: Write-Verbose for progress, Write-Warning for per-file
      metadata gaps. No dependency on the shared console toolkit.

.LINK
    about_Comment_Based_Help
    https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_comment_based_help

#>


Function Generate-MarkdownDocumentation {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SourcePath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('PerFolderReadme', 'SingleCatalogFile')]
        [string]$Mode = 'PerFolderReadme',

        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [string]$ReadmeFileName = 'README.md',

        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeFolder = @('.git', '.github', '.vscode'),

        [Parameter(Mandatory = $false)]
        [switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    Begin {
        $markerStart = '<!-- SCRIPT-CATALOG:START - auto-generated by Generate-MarkdownDocumentation.ps1, do not edit between these markers -->'
        $markerEnd = '<!-- SCRIPT-CATALOG:END -->'
        $catalogFileMarker = '<!-- Generated by Generate-MarkdownDocumentation.ps1 -->'

        if (-not (Test-Path -Path $SourcePath)) {
            throw "Source path '$SourcePath' does not exist."
        }

        if ($Mode -eq 'SingleCatalogFile' -and -not $OutputPath) {
            $OutputPath = Join-Path -Path (Resolve-Path -Path $SourcePath).Path -ChildPath 'SCRIPT-CATALOG.md'
        }

        # --- Nested helper: read one script's metadata WITHOUT executing it ---
        function Get-ScriptCatalogEntry {
            param([System.IO.FileInfo]$File)

            $entry = [PSCustomObject]@{
                FileName      = $File.Name
                Synopsis      = ''
                Author        = ''
                Version       = ''
                ModifiedOn    = $File.LastWriteTime.ToString('dd MMM yyyy')
                FunctionNames = @()
                MetadataIssue = $null
                FullHelp      = ''
            }

            try {
                $rawText = Get-Content -Path $File.FullName -Raw -ErrorAction Stop

                # Pull just the FIRST comment block <# ... #> as plain text
                $blockMatch = [regex]::Match($rawText, '(?s)<#(.*?)#>')
                if ($blockMatch.Success) {
                    $headerText = $blockMatch.Groups[1].Value
                    $entry.FullHelp = $headerText

                    # --- Existing regex for Author/Version ---
                    $authorMatch = [regex]::Match($headerText, 'Author\s*:\s*(.+)')
                    if ($authorMatch.Success) { $entry.Author = $authorMatch.Groups[1].Value.Trim() }

                    $versionMatch = [regex]::Match($headerText, 'Version\s*:\s*(.+)')
                    if ($versionMatch.Success) { $entry.Version = $versionMatch.Groups[1].Value.Trim() }

                    # +++ NEW: regex for Synopsis +++
                    $synopsisMatch = [regex]::Match($headerText, '(?s)\.SYNOPSIS\s+(.+?)(?=\r?\n\.|\r?\n\s*$)')
                    if ($synopsisMatch.Success) {
                        $entry.Synopsis = $synopsisMatch.Groups[1].Value.Trim()
                    }
                }

                # AST parse - reads structure only, never runs the code.
                $parseTokens = $null
                $parseErrors = $null
                $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$parseTokens, [ref]$parseErrors)

                $functionAsts = $scriptAst.FindAll(
                    { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] },
                    $true
                )
                $entry.FunctionNames = @($functionAsts | ForEach-Object { $_.Name })

                # Try AST help content first, but fall back to regex if it's empty
                $helpContent = $scriptAst.GetHelpContent()
                if ($helpContent -and $helpContent.Synopsis) {
                    $entry.Synopsis = $helpContent.Synopsis.Trim()
                }
                # If AST synopsis is still empty, keep the regex result (already set above)

                if (-not $entry.Synopsis -or -not $entry.Author) {
                    $entry.MetadataIssue = "Missing $(@(if (-not $entry.Synopsis) {'Synopsis'}; if (-not $entry.Author) {'Author block'}) -join ' and ')"
                }
            }
            catch {
                $entry.MetadataIssue = "Could not read metadata: $($_.Exception.Message)"
            }

            return $entry
        }

        # --- Nested helper: turn a folder's entries into a Markdown table ---
        function ConvertTo-CatalogMarkdownTable 
        {
            param([string]$RelativeFolderLabel, [object[]]$Entries)

            $lines = New-Object -TypeName System.Collections.Generic.List[string]
            $lines.Add("### $RelativeFolderLabel")
            $lines.Add('')
            $lines.Add('| Script | Synopsis | Version | Last Modified |')
            $lines.Add('|---|---|---|---|')

            foreach ($entry in $Entries) {
                $synopsisCell = if ($entry.Synopsis) { ($entry.Synopsis -replace '\s+', ' ') -replace '\|', '\|' } else { '_(no synopsis found)_' }
                $versionCell = if ($entry.Version) { $entry.Version } else { '—' }
                $lines.Add("| [$($entry.FileName)](./$($entry.FileName)) | $synopsisCell | $versionCell | $($entry.ModifiedOn) |")
            }

            $lines.Add('')
            $lines.Add('---')
            $lines.Add('')

            # Add collapsible sections with the full help block for each script
            foreach ($entry in $Entries) 
            {
                if ($entry.FullHelp) 
                {
                    $lines.Add('<details>')
                    $lines.Add("<summary>📖 <strong>$($entry.FileName)</strong> – full help block</summary>")
                    $lines.Add('')
                    $lines.Add('```powershell')
                    $lines.Add($entry.FullHelp)
                    $lines.Add('```')
                    $lines.Add('</details>')
                    $lines.Add('')
                }
            }

            return ($lines -join "`n")
        }

        # --- Nested helper: insert/replace content between markers ---
        function Set-MarkerSection {
            param([string]$ExistingContent, [string]$NewSectionBody)

            $startIndex = $ExistingContent.IndexOf($markerStart)
            $endIndex = $ExistingContent.IndexOf($markerEnd)

            if ($startIndex -ge 0 -and $endIndex -lt 0) {
                throw 'Found a start marker with no matching end marker - this file appears to have been hand-edited inside the auto-generated section. Fix or remove the markers manually before re-running.'
            }

            $replacement = "$markerStart`n`n$NewSectionBody`n$markerEnd"

            if ($startIndex -ge 0) {
                $before = $ExistingContent.Substring(0, $startIndex)
                $after = $ExistingContent.Substring($endIndex + $markerEnd.Length)
                return "$before$replacement$after"
            }
            else {
                $separator = if ($ExistingContent.TrimEnd().Length -gt 0) { "`n`n" } else { '' }
                return "$($ExistingContent.TrimEnd())$separator## 📜 Scripts in this folder`n`n$replacement`n"
            }
        }

        Write-Verbose -Message "=== Generate-MarkdownDocumentation : Mode = $Mode ==="
    }

    Process {
        try {
            $getChildItemParams = @{ Path = $SourcePath; Directory = $true; ErrorAction = 'Stop' }
            if ($Recurse) { $getChildItemParams['Recurse'] = $true }

            $candidateFolders = @((Get-Item -Path $SourcePath), (Get-ChildItem @getChildItemParams)) |
            Where-Object { $ExcludeFolder -notcontains $_.Name }

            $scriptsDocumented = 0
            $metadataIssues = New-Object -TypeName System.Collections.Generic.List[object]
            $outputFiles = New-Object -TypeName System.Collections.Generic.List[string]
            $catalogSections = New-Object -TypeName System.Collections.Generic.List[string]
            $foldersDocumented = 0

            foreach ($folder in $candidateFolders) {
                $scriptFiles = Get-ChildItem -Path $folder.FullName -Filter '*.ps1' -File -ErrorAction Stop | Sort-Object -Property Name
                if (-not $scriptFiles) { continue }

                Write-Verbose -Message "[INFO] Documenting $(@($scriptFiles).Count) script(s) in '$($folder.FullName)'"

                $entries = foreach ($file in $scriptFiles) {
                    $entry = Get-ScriptCatalogEntry -File $file
                    $scriptsDocumented++
                    if ($entry.MetadataIssue) {
                        $metadataIssues.Add([PSCustomObject]@{ File = $file.FullName; Issue = $entry.MetadataIssue })
                        Write-Warning -Message "$($file.Name): $($entry.MetadataIssue)"
                    }
                    $entry
                }

                $relativeFolder = $folder.FullName.Substring((Resolve-Path -Path $SourcePath).Path.Length).TrimStart('\', '/')
                $folderLabel = if ($relativeFolder) { $relativeFolder } else { Split-Path -Path $SourcePath -Leaf }
                $tableMarkdown = ConvertTo-CatalogMarkdownTable -RelativeFolderLabel $folderLabel -Entries $entries
                $foldersDocumented++

                if ($Mode -eq 'PerFolderReadme') {
                    $readmePath = Join-Path -Path $folder.FullName -ChildPath $ReadmeFileName

                    if (-not $PSCmdlet.ShouldProcess($readmePath, 'Update script catalog section')) { continue }

                    $existingContent = if (Test-Path -Path $readmePath) { Get-Content -Path $readmePath -Raw } else { "# $folderLabel`n" }
                    $updatedContent = Set-MarkerSection -ExistingContent $existingContent -NewSectionBody $tableMarkdown
                    Set-Content -Path $readmePath -Value $updatedContent -Encoding UTF8
                    $outputFiles.Add($readmePath)
                }
                else {
                    $catalogSections.Add($tableMarkdown)
                }
            }

            if ($Mode -eq 'SingleCatalogFile') {
                if ((Test-Path -Path $OutputPath) -and -not $Force) {
                    $existing = Get-Content -Path $OutputPath -Raw -ErrorAction SilentlyContinue
                    if ($existing -notmatch [regex]::Escape($catalogFileMarker)) {
                        throw "'$OutputPath' already exists and doesn't look like a file this tool generated. Re-run with -Force to overwrite it anyway, or choose a different -OutputPath."
                    }
                }

                if ($PSCmdlet.ShouldProcess($OutputPath, 'Write consolidated script catalog')) {
                    $catalogContent = "$catalogFileMarker`n# Script Catalog`n`nGenerated $(Get-Date -Format 'dd MMM yyyy, HH:mm').`n`n" + ($catalogSections -join "`n")
                    Set-Content -Path $OutputPath -Value $catalogContent -Encoding UTF8
                    $outputFiles.Add($OutputPath)
                }
            }

            [PSCustomObject]@{
                FoldersScanned             = @($candidateFolders).Count
                FoldersDocumented          = $foldersDocumented
                ScriptsDocumented          = $scriptsDocumented
                ScriptsWithMissingMetadata = $metadataIssues
                OutputFiles                = $outputFiles
            }
        }
        catch {
            Write-Warning -Message "Documentation generation failed: $($_.Exception.Message)"
            throw
        }
    }

    End {
        Write-Verbose -Message '[INFO] Generate-MarkdownDocumentation completed.'
    }
}
