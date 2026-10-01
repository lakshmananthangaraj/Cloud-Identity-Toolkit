<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 26 April 2026
Modified-On  : 30 September 2026

.SYNOPSIS
    Builds a searchable catalog of a PowerShell script library as a self-contained
    HTML dashboard, a JSON metadata file, or both.

.DESCRIPTION
    Export-ScriptCatalog scans a folder of PowerShell (.ps1) scripts, reads each
    script's comment-based help, and turns the result into a script catalog that
    answers the questions every growing script library eventually raises:

        - What scripts do we have, and what does each one do?
        - Which scripts are documented, and which are not?
        - Who wrote a script, and which version is it?
        - Which scripts were changed most recently?

    HTML output is a single self-contained file (no external requests, no
    dependencies) with five tabs:

        Overview        Totals, documentation score, charts, recently modified scripts.
        All Scripts     Searchable, sortable, filterable table with CSV/JSON export.
        Explorer        Scripts grouped by PowerShell verb, with sort options.
        Content Search  Keyword search scoped to name, synopsis, description,
                        parameters or examples.
        Analytics       Largest scripts, scripts that need documentation, size
                        distribution and help coverage by verb.

    JSON output is a structured metadata file (name, author, version, synopsis,
    description, parameters, examples, notes, documentation score and more) that
    other tools, pipelines or AI assistants can read instead of parsing HTML.

    DOCUMENTATION SCORE
    Each script is scored out of 100 using four equal checks: (1) it has a
    comment-based help block, (2) the help has a synopsis, (3) the help has a
    description, and (4) the help has at least one example. The library score is
    the average across all scripts.

    PRIVACY
    By default the report stores paths relative to -Path and shows only the name
    of the scanned folder, so a shared report or screenshot does not reveal local
    user names or server paths. Use -IncludeFullPath to store absolute paths.

    The generated HTML makes no network requests. Script text is escaped before it
    is written into the page, so scanning scripts you did not write does not
    execute anything from them.

.PARAMETER Path
    Folder that contains the .ps1 scripts to catalog. Must be an existing
    file-system folder.

.PARAMETER Format
    Which output to create. 'Html' (default) writes the dashboard, 'Json' writes
    the metadata file only, and 'Both' writes both.

.PARAMETER OutputPath
    Where to save the HTML dashboard. Must end in .html or .htm and must not
    contain '..' path segments. The folder is created if it does not exist.
    Default: ScriptCatalog.html in the system temporary folder.

.PARAMETER JsonOutputPath
    Where to save the JSON metadata file. Must end in .json and must not contain
    '..' path segments. Used when -Format is 'Json' or 'Both'.
    Default: ScriptCatalog.json in the system temporary folder.

.PARAMETER Title
    Title shown in the dashboard sidebar and browser tab. 1 to 80 characters.
    Default: 'Script Catalog'.

.PARAMETER Exclude
    File-name patterns to leave out of the catalog. Default: '*.Tests.ps1'.
    Pass an empty array (@()) to include every .ps1 file.

.PARAMETER Recurse
    Also scan subfolders of -Path.

.PARAMETER IncludeFullPath
    Store and display absolute paths instead of paths relative to -Path.

.PARAMETER OpenBrowser
    Open the HTML dashboard in the default application after it is written.

.PARAMETER Quiet
    Suppress the console banner and progress messages. Warnings and the returned
    result object are not affected.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the properties:
    HtmlPath, JsonPath, ScriptCount, CategoryCount, WithHelp,
    DocumentationScore, SkippedFiles, Duration. HtmlPath or JsonPath is $null
    when that output was not requested or -WhatIf was used.

.EXAMPLE
    Export-ScriptCatalog -Path "D:\Scripts" -Recurse -OpenBrowser

    Scans D:\Scripts and its subfolders, writes ScriptCatalog.html to the temporary
    folder and opens it in the default browser.

.EXAMPLE
    Export-ScriptCatalog -Path ".\Scripts" -OutputPath ".\Reports\Catalog.html" -Title "Contoso Automation Library"

    Writes the dashboard to a custom location with a custom title. The Reports
    folder is created if it does not exist.

.EXAMPLE
    Export-ScriptCatalog -Path "D:\Scripts" -Recurse -Format Json -JsonOutputPath "D:\Data\ScriptCatalog.json"

    Writes only the JSON metadata file, for use by other tools or AI assistants.

.EXAMPLE
    $result = Export-ScriptCatalog -Path "D:\Scripts" -Recurse -Format Both -Quiet
    "{0} scripts, documentation score {1}/100" -f $result.ScriptCount, $result.DocumentationScore

    Writes both outputs without console messages and reads the summary from the
    returned object, which is useful in a pipeline or scheduled task.

.EXAMPLE
    Export-ScriptCatalog -Path "D:\Scripts" -Recurse -WhatIf

    Shows which files would be written without creating them.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (26-Apr-2026) - Analytics tab, CSV/JSON export, health score, help
                        filter, field-scoped search, prev/next navigation,
                        keyboard shortcuts, toast notifications.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. PowerShell 5.1 or later. No external modules are required.
    2. Read access to -Path and write access to the output folder.
    3. Save this file as UTF-8 with BOM if you use Windows PowerShell 5.1, because
       it contains emoji and box-drawing characters.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Help is read with pattern matching, not the PowerShell parser. The first
      block comment that contains a help keyword (.SYNOPSIS, .DESCRIPTION,
      .PARAMETER, .EXAMPLE, .NOTES, .INPUTS, .OUTPUTS or .LINK) is used.
    - Author and Version are read from "Author :" and "Version :" lines in the
      help block or in a header comment block; these are a convention, not part
      of standard PowerShell help.
    - Scripts are grouped by the text before the first hyphen in the file name.
    - The whole catalog is embedded in one HTML file, so very large libraries
      (many thousands of scripts) produce a large page.
    - The script text is never executed; it is only read as text.

.LINK
    about_Comment_Based_Help
    https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_comment_based_help

.LINK
    Approved Verbs for PowerShell Commands
    https://learn.microsoft.com/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands

#>

Function Export-ScriptCatalog {
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ (Test-Path -LiteralPath $_ -PathType Container) -and ((Resolve-Path -LiteralPath $_).Provider.Name -eq 'FileSystem') })]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Html', 'Json', 'Both')]
        [string]$Format = 'Html',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\.html?$')]
        [ValidateScript({ $_ -notmatch '(^|[\\/])\.\.([\\/]|$)' })]
        [string]$OutputPath = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'ScriptCatalog.html'),

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\.json$')]
        [ValidateScript({ $_ -notmatch '(^|[\\/])\.\.([\\/]|$)' })]
        [string]$JsonOutputPath = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'ScriptCatalog.json'),

        [Parameter(Mandatory = $false)]
        [ValidateLength(1, 80)]
        [string]$Title = 'Script Catalog',

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$Exclude = @('*.Tests.ps1'),

        [Parameter(Mandatory = $false)]
        [switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeFullPath,

        [Parameter(Mandatory = $false)]
        [switch]$OpenBrowser,

        [Parameter(Mandatory = $false)]
        [switch]$Quiet
    )

    Begin {
        $startTime = Get-Date
        $invariant = [System.Globalization.CultureInfo]::InvariantCulture
        $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false

        #region ── Helper script blocks ──────────────────────────────────────────
        # These are script blocks rather than nested functions on purpose: tools
        # that scan this file for function definitions (for example a module
        # builder) then see exactly one function, Export-ScriptCatalog.

        # Console message that honours -Quiet.
        $say = {
            param([string]$Message, [string]$Color = 'White')

            if (-not $Quiet) {
                Write-Host -Object $Message -ForegroundColor $Color
            }
        }

        # Makes a string safe to place inside a double-quoted JSON/JavaScript string
        # that is embedded in an HTML <script> block: escapes backslash, quote,
        # control characters, < > & (so "</script>" cannot appear) and the U+2028 /
        # U+2029 line separators.
        $toJsonSafe = {
            param([string]$Text)

            if ([string]::IsNullOrEmpty($Text)) {
                return ''
            }

            $evaluator = [System.Text.RegularExpressions.MatchEvaluator] {
                param($Match)

                $map = @{ '\' = '\\'; '"' = '\"'; "`n" = '\n'; "`r" = '\r'; "`t" = '\t' }
                $value = $Match.Value

                if ($map.ContainsKey($value)) {
                    return $map[$value]
                }

                return ('\u{0:x4}' -f [int][char]$value)
            }

            return [regex]::Replace($Text, '[\\"\u0000-\u001F<>&\u2028\u2029]', $evaluator)
        }

        # Reads one script file and returns its metadata as a PSCustomObject.
        $getMetadata = {
            param([System.IO.FileInfo]$File, [string]$Root, [bool]$FullPath)

            $nameParts = $File.BaseName -split '-', 2
            $verb = 'Other'
            $noun = ''

            if ($nameParts.Count -gt 1 -and $nameParts[0]) {
                $verb = $nameParts[0]
                $noun = $nameParts[1]
            }

            $relativePath = $File.FullName.Substring($Root.Length).TrimStart('\', '/')
            $parameters = New-Object -TypeName System.Collections.Generic.List[object]
            $examples = New-Object -TypeName System.Collections.Generic.List[object]

            $meta = [ordered]@{
                Name         = $File.Name
                BaseName     = $File.BaseName
                Verb         = $verb
                Noun         = $noun
                Path         = $(if ($FullPath) { $File.FullName } else { $relativePath })
                SizeKB       = [math]::Round($File.Length / 1KB, 1)
                LastModified = $File.LastWriteTime.ToString('dd MMM yyyy  HH:mm', [System.Globalization.CultureInfo]::InvariantCulture)
                LastModSort  = $File.LastWriteTime.ToString('yyyyMMddHHmm', [System.Globalization.CultureInfo]::InvariantCulture)
                Author       = ''
                Version      = ''
                Synopsis     = ''
                Description  = ''
                Notes        = ''
                Parameters   = $parameters
                Examples     = $examples
                LineCount    = 0
                HasHelpBlock = $false
                DocScore     = 0
                ReadError    = ''
            }

            try {
                $content = [System.IO.File]::ReadAllText($File.FullName)
                $meta.LineCount = [regex]::Matches($content, "`n").Count + 1

                # Use the first block comment that contains a help keyword, so a
                # license header or other comment is not mistaken for the help.
                $helpKeywordPattern = '(?im)^[ \t]*\.(SYNOPSIS|DESCRIPTION|PARAMETER|EXAMPLE|NOTES|INPUTS|OUTPUTS|LINK)\b'
                $helpText = $null

                foreach ($blockMatch in [regex]::Matches($content, '(?s)<#.*?#>')) {
                    if ($blockMatch.Value -match $helpKeywordPattern) {
                        $helpText = $blockMatch.Value.Substring(2, $blockMatch.Value.Length - 4)
                        break
                    }
                }

                if ($null -ne $helpText) {
                    $meta.HasHelpBlock = $true

                    # Author/Version are looked up in the help block first and then in
                    # any other block comment, so a separate header comment above the
                    # help block (the layout that keeps Get-Help working) is found too.
                    $headerTexts = @($helpText) + @([regex]::Matches($content, '(?s)<#.*?#>') | ForEach-Object { $_.Value })

                    foreach ($headerText in $headerTexts) {
                        if (-not $meta.Author -and $headerText -match '(?m)^[ \t]*Author[ \t]*:[ \t]*(.+?)[ \t]*\r?$') {
                            $meta.Author = $Matches[1].Trim()
                        }

                        if (-not $meta.Version -and $headerText -match '(?m)^[ \t]*Version[ \t]*:[ \t]*(.+?)[ \t]*\r?$') {
                            $meta.Version = $Matches[1].Trim()
                        }
                    }

                    # Split the help block at real help keywords only, so a line in
                    # a description that happens to start with a dot is kept.
                    $sectionPattern = '(?im)^[ \t]*\.(SYNOPSIS|DESCRIPTION|PARAMETER|EXAMPLE|INPUTS|OUTPUTS|NOTES|LINK|COMPONENT|ROLE|FUNCTIONALITY|FORWARDHELPTARGETNAME|FORWARDHELPCATEGORY|REMOTEHELPRUNSPACE|EXTERNALHELP)\b[ \t]*([^\r\n]*)'
                    $sections = [regex]::Matches($helpText, $sectionPattern)

                    for ($i = 0; $i -lt $sections.Count; $i++) {
                        $section = $sections[$i]
                        $keyword = $section.Groups[1].Value.ToUpperInvariant()
                        $inline = $section.Groups[2].Value.Trim()
                        $bodyStart = $section.Index + $section.Length
                        $bodyEnd = $helpText.Length

                        if ($i + 1 -lt $sections.Count) {
                            $bodyEnd = $sections[$i + 1].Index
                        }

                        $body = $helpText.Substring($bodyStart, $bodyEnd - $bodyStart).Trim()

                        switch ($keyword) {
                            'SYNOPSIS' {
                                if (-not $meta.Synopsis) {
                                    $meta.Synopsis = (($inline + ' ' + $body).Trim()) -replace '\s+', ' '
                                }
                            }
                            'DESCRIPTION' {
                                if (-not $meta.Description) {
                                    $meta.Description = ($inline + "`n" + $body).Trim()
                                }
                            }
                            'NOTES' {
                                if (-not $meta.Notes) {
                                    $meta.Notes = (($inline + ' ' + $body).Trim()) -replace '\s+', ' '
                                }
                            }
                            'PARAMETER' {
                                $parameterName = ($inline -split '\s+')[0]

                                if ($parameterName) {
                                    $parameters.Add([PSCustomObject]@{
                                            Name = $parameterName
                                            Desc = ($body -replace '\s+', ' ')
                                        })
                                }
                            }
                            'EXAMPLE' {
                                $exampleText = ($inline + "`n" + $body).Trim()

                                if ($exampleText) {
                                    $exampleLines = $exampleText -split '\r?\n', 2
                                    $comment = ''

                                    if ($exampleLines.Count -gt 1) {
                                        $comment = $exampleLines[1].Trim()
                                    }

                                    $examples.Add([PSCustomObject]@{
                                            Command = $exampleLines[0].Trim()
                                            Comment = $comment
                                        })
                                }
                            }
                        }
                    }
                }
            }
            catch {
                $meta.ReadError = $_.Exception.Message
                $meta.Synopsis = '(Could not read file)'
                Write-Warning -Message "Could not read '$($File.FullName)': $($_.Exception.Message)"
            }

            # Documentation score: four equal checks, 25 points each.
            $passed = 0

            if ($meta.HasHelpBlock) { $passed++ }
            if ($meta.Synopsis -and -not $meta.ReadError) { $passed++ }
            if ($meta.Description) { $passed++ }
            if ($examples.Count -gt 0) { $passed++ }

            $meta.DocScore = $passed * 25

            return [PSCustomObject]$meta
        }

        # Writes a text file as UTF-8 without BOM, creating the folder if needed.
        $writeOutputFile = {
            param([string]$TargetPath, [string]$Content)

            $fullTarget = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TargetPath)
            $targetFolder = Split-Path -Path $fullTarget -Parent

            if ($targetFolder -and -not (Test-Path -LiteralPath $targetFolder)) {
                New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
            }

            [System.IO.File]::WriteAllText($fullTarget, $Content, $utf8NoBom)

            return $fullTarget
        }

        #endregion
    }

    Process {
        try {
            #region ── Scan ─────────────────────────────────────────────────────────

            & $say ''
            & $say '╔══════════════════════════════════════════════════════╗' 'Cyan'
            & $say '║      Script Catalog  v1.0                            ║' 'Cyan'
            & $say '╚══════════════════════════════════════════════════════╝' 'Cyan'
            & $say ''

            $resolvedRoot = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath.TrimEnd('\', '/')
            & $say "  🔍  Scanning: $resolvedRoot" 'Cyan'

            $getParams = @{
                LiteralPath = $resolvedRoot
                Filter      = '*.ps1'
                File        = $true
                ErrorAction = 'SilentlyContinue'
            }

            if ($Recurse) {
                $getParams['Recurse'] = $true
            }

            $scanErrors = $null
            $files = @(Get-ChildItem @getParams -ErrorVariable scanErrors | Sort-Object -Property Name)

            if ($scanErrors) {
                Write-Warning -Message "$(@($scanErrors).Count) folder(s) could not be read and were skipped. First error: $(@($scanErrors)[0].Exception.Message)"
            }

            if ($Exclude.Count -gt 0) {
                $files = @($files | Where-Object {
                        $fileName = $_.Name
                        -not ($Exclude | Where-Object { $fileName -like $_ })
                    })
            }

            if ($files.Count -eq 0) {
                Write-Warning -Message "No .ps1 files found in '$resolvedRoot'."
                return
            }

            #endregion

            #region ── Metadata ─────────────────────────────────────────────────────

            & $say "  📦  Found $($files.Count) scripts — extracting metadata…" 'Cyan'

            $allScripts = New-Object -TypeName System.Collections.Generic.List[object]
            $skippedFiles = New-Object -TypeName System.Collections.Generic.List[string]
            $fileCounter = 0

            foreach ($file in $files) {
                $fileCounter++
                Write-Progress -Activity 'Reading script metadata' -Status $file.Name -PercentComplete ([int](($fileCounter / $files.Count) * 100))
                Write-Verbose -Message "[$fileCounter/$($files.Count)] Processing $($file.Name)"

                $scriptMeta = & $getMetadata -File $file -Root $resolvedRoot -FullPath $IncludeFullPath.IsPresent

                if ($scriptMeta.ReadError) {
                    $skippedFiles.Add($file.FullName)
                }

                $allScripts.Add($scriptMeta)
            }

            Write-Progress -Activity 'Reading script metadata' -Completed

            $categories = @($allScripts | Group-Object -Property Verb | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
            $totalLines = ($allScripts | Measure-Object -Property LineCount -Sum).Sum
            $totalSizeKB = [math]::Round(($allScripts | Measure-Object -Property SizeKB -Sum).Sum, 1)
            $withHelp = @($allScripts | Where-Object { $_.HasHelpBlock }).Count
            $withoutHelp = $allScripts.Count - $withHelp
            $fullyDocumented = @($allScripts | Where-Object { $_.DocScore -eq 100 }).Count
            $avgLines = [math]::Round($totalLines / $allScripts.Count, 0)
            $helpPct = [math]::Round(($withHelp / $allScripts.Count) * 100, 0)
            $fullDocPct = [math]::Round(($fullyDocumented / $allScripts.Count) * 100, 0)
            $docScoreAvg = [int][math]::Round(($allScripts | Measure-Object -Property DocScore -Average).Average, 0)

            & $say '  ✅  Metadata extracted.' 'Green'

            #endregion

            #region ── JSON metadata file ───────────────────────────────────────────

            $jsonWritten = $null

            if ($Format -eq 'Json' -or $Format -eq 'Both') {
                $jsonExport = @($allScripts | ForEach-Object {
                        [PSCustomObject]@{
                            Name               = $_.Name
                            BaseName           = $_.BaseName
                            Verb               = $_.Verb
                            Noun               = $_.Noun
                            Synopsis           = $_.Synopsis
                            Description        = $_.Description
                            Author             = $_.Author
                            Version            = $_.Version
                            Notes              = $_.Notes
                            SizeKB             = $_.SizeKB
                            LineCount          = $_.LineCount
                            LastModified       = $_.LastModified
                            HasHelpBlock       = $_.HasHelpBlock
                            DocumentationScore = $_.DocScore
                            ParamCount         = $_.Parameters.Count
                            Parameters         = $_.Parameters.ToArray()
                            Examples           = $_.Examples.ToArray()
                            Path               = $_.Path
                        }
                    })

                if ($PSCmdlet.ShouldProcess($JsonOutputPath, 'Write script catalog JSON')) {
                    $jsonText = ConvertTo-Json -InputObject $jsonExport -Depth 6
                    $jsonWritten = & $writeOutputFile -TargetPath $JsonOutputPath -Content $jsonText
                    & $say "  ✅  JSON metadata written: $jsonWritten" 'Green'
                }
            }

            #endregion

            #region ── HTML dashboard ───────────────────────────────────────────────

            $htmlWritten = $null

            if ($Format -eq 'Html' -or $Format -eq 'Both') {
                & $say '  🛠   Building dashboard…' 'Cyan'

                $rowsJson = ($allScripts | ForEach-Object {
                        $s = $_

                        $paramsJson = ($s.Parameters | ForEach-Object {
                                '{"name":"' + (& $toJsonSafe $_.Name) + '","desc":"' + (& $toJsonSafe $_.Desc) + '"}'
                            }) -join ','

                        $examplesJson = ($s.Examples | ForEach-Object {
                                '{"cmd":"' + (& $toJsonSafe $_.Command) + '","comment":"' + (& $toJsonSafe $_.Comment) + '"}'
                            }) -join ','

                        $hasHelpText = 'false'
                        if ($s.HasHelpBlock) {
                            $hasHelpText = 'true'
                        }

                        '{"name":"' + (& $toJsonSafe $s.Name) +
                        '","base":"' + (& $toJsonSafe $s.BaseName) +
                        '","verb":"' + (& $toJsonSafe $s.Verb) +
                        '","noun":"' + (& $toJsonSafe $s.Noun) +
                        '","author":"' + (& $toJsonSafe $s.Author) +
                        '","version":"' + (& $toJsonSafe $s.Version) +
                        '","synopsis":"' + (& $toJsonSafe $s.Synopsis) +
                        '","description":"' + (& $toJsonSafe $s.Description) +
                        '","params":[' + $paramsJson +
                        '],"examples":[' + $examplesJson +
                        '],"sizeKB":' + $s.SizeKB.ToString('0.0', $invariant) +
                        ',"lines":' + $s.LineCount +
                        ',"modified":"' + (& $toJsonSafe $s.LastModified) +
                        '","modSort":"' + (& $toJsonSafe $s.LastModSort) +
                        '","hasHelp":' + $hasHelpText +
                        ',"docScore":' + $s.DocScore +
                        ',"path":"' + (& $toJsonSafe $s.Path) + '"}'
                    }) -join ','

                $categoriesJson = ($categories | ForEach-Object {
                        '{"verb":"' + (& $toJsonSafe $_.Name) + '","count":' + $_.Count + '}'
                    }) -join ','

                # Shown in the sidebar: folder name only, unless -IncludeFullPath.
                $pathDisplay = Split-Path -Path $resolvedRoot -Leaf

                if ($IncludeFullPath -or [string]::IsNullOrEmpty($pathDisplay)) {
                    $pathDisplay = $resolvedRoot -replace '\\', '/'
                }

                $titleEncoded = [System.Net.WebUtility]::HtmlEncode($Title)
                $pathDisplayEncoded = [System.Net.WebUtility]::HtmlEncode($pathDisplay)
                $generatedAt = (Get-Date).ToString('dddd, dd MMMM yyyy  HH:mm:ss', $invariant)

                $template = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>__TITLE__</title>
<style>
:root {
  --bg:#0d1117; --surface:#161b22; --surface2:#1c2333; --surface3:#243048;
  --border:#30363d; --accent:#388bfd; --accent2:#39c5cf; --accent3:#a371f7;
  --green:#3fb950; --amber:#d29922; --red:#f85149;
  --text:#e6edf3; --muted:#7d8590; --muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px; --radius-sm:6px; --shadow:0 4px 24px rgba(0,0,0,.5);
}
body.light-theme {
  --bg:#f6f8fa; --surface:#fff; --surface2:#f0f3f6; --surface3:#e4e9ef;
  --border:#d0d7de; --accent:#0969da; --accent2:#0284a8; --accent3:#7c3aed;
  --green:#1a7f37; --amber:#b08000; --red:#cf222e;
  --text:#1f2328; --muted:#636c76; --muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh;overflow-x:hidden;transition:background .25s,color .25s}

/* Sidebar */
#sidebar{position:fixed;top:0;left:0;bottom:0;width:236px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:100;transition:background .25s,border-color .25s}
.sidebar-logo{padding:20px 18px 14px;border-bottom:1px solid var(--border)}
.logo-icon{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),var(--accent3));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:9px}
.sidebar-logo h1{font-size:14px;font-weight:700;color:var(--text);overflow-wrap:anywhere}
.sidebar-logo p{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.version-badge{display:inline-block;margin-top:5px;background:rgba(56,139,253,.15);color:var(--accent);font-family:var(--mono);font-size:10px;padding:1px 8px;border-radius:20px;border:1px solid rgba(56,139,253,.3)}
.sidebar-nav{flex:1;padding:8px 0;overflow-y:auto}
.nav-section-label{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:8px 18px 4px}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 18px;background:none;border:none;cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13.5px;text-align:left;position:relative;transition:all .18s}
.nav-btn .nav-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0}
.nav-btn .nav-badge{margin-left:auto;background:var(--surface3);color:var(--muted2);font-family:var(--mono);font-size:11px;padding:1px 7px;border-radius:20px}
.nav-btn:hover{color:var(--text);background:var(--surface2)}
.nav-btn.active{color:var(--accent);background:rgba(56,139,253,.1)}
.nav-btn.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);border-radius:0 2px 2px 0}
.theme-toggle-wrap{padding:10px 14px;border-top:1px solid var(--border)}
.theme-toggle{display:flex;align-items:center;gap:8px;width:100%;padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;color:var(--muted2);font-family:var(--sans);font-size:13px;transition:all .2s}
.theme-toggle:hover{border-color:var(--accent);color:var(--text)}
.toggle-pill{width:34px;height:18px;background:var(--surface3);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.toggle-pill::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--muted2);transition:transform .2s,background .2s}
body.light-theme .toggle-pill{background:var(--accent)}
body.light-theme .toggle-pill::after{transform:translateX(16px);background:#fff}
.sidebar-footer{padding:10px 18px 12px;border-top:1px solid var(--border);font-size:11px;color:var(--muted);font-family:var(--mono);line-height:1.6}
kbd{display:inline-block;padding:1px 5px;background:var(--surface3);border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:11px;color:var(--muted)}

/* Main */
#main{margin-left:236px;min-height:100vh}
.page{display:none;padding:28px 32px;animation:fadeIn .22s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:22px;display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px}
.page-title{font-size:24px;font-weight:700;color:var(--text)}
.page-subtitle{color:var(--muted);font-size:13px;margin-top:3px}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;border-radius:var(--radius-sm);font-size:13px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface2);color:var(--muted2);transition:all .2s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(56,139,253,.08)}
.btn:disabled{opacity:.4;cursor:default}
.btn-group{display:flex;gap:8px;flex-wrap:wrap}

/* Stat cards */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px 17px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent)}
.stat-card::after{content:'';position:absolute;top:-26px;right:-26px;width:68px;height:68px;border-radius:50%;background:radial-gradient(circle,rgba(59,130,246,.1),transparent 70%)}
.stat-icon{font-size:20px;margin-bottom:8px}
.stat-value{font-size:25px;font-weight:700;color:var(--text);line-height:1}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}
.stat-card.c-blue{border-top:2px solid var(--accent)}
.stat-card.c-cyan{border-top:2px solid var(--accent2)}
.stat-card.c-purple{border-top:2px solid var(--accent3)}
.stat-card.c-green{border-top:2px solid var(--green)}
.stat-card.c-amber{border-top:2px solid var(--amber)}
.stat-card.c-red{border-top:2px solid var(--red)}

/* Health card */
.health-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;display:flex;align-items:center;gap:18px;margin-bottom:22px;flex-wrap:wrap}
.health-ring-wrap{position:relative;width:76px;height:76px;flex-shrink:0}
.health-ring-wrap svg{width:76px;height:76px}
.health-ring-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.health-score-num{font-family:var(--mono);font-size:19px;font-weight:700;line-height:1}
.health-score-pct{font-size:9px;color:var(--muted)}
.health-info{flex:1;min-width:200px}
.health-info h3{font-size:14px;font-weight:700;margin-bottom:4px}
.health-info p{font-size:12px;color:var(--muted2)}
.health-bar-row{display:flex;align-items:center;gap:8px;margin-top:8px;font-size:12px}
.health-mini-bar{flex:1;height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.health-mini-fill{height:100%;border-radius:3px;transition:width 1s ease}

/* Panels & charts */
.section-title{font-size:15px;font-weight:700;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:7px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:22px}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px;cursor:pointer}
.bar-row:hover .bar-label{color:var(--text)}
.bar-label{font-family:var(--mono);font-size:11px;color:var(--muted2);width:88px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1)}
.bar-count{font-family:var(--mono);font-size:11px;color:var(--accent2);width:24px;text-align:right;flex-shrink:0}
#donutWrap{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
#donutSvg{width:180px;height:180px;flex-shrink:0}
.legend-list{flex:1;min-width:130px;display:flex;flex-direction:column;gap:5px;max-height:220px;overflow-y:auto}
.legend-item{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted2);cursor:pointer;padding:2px 4px;border-radius:4px}
.legend-item:hover{background:var(--surface2)}
.legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.legend-pct{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--muted)}
.recent-row{display:flex;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid var(--border)}
.recent-row:last-child{border-bottom:none}
.recent-icon{color:var(--accent);font-size:13px;width:18px;text-align:center;flex-shrink:0}
.recent-name{font-family:var(--mono);font-size:12.5px;color:var(--accent2);flex:1;cursor:pointer}
.recent-name:hover{text-decoration:underline}
.recent-date{color:var(--muted);font-size:11.5px;flex-shrink:0}

/* Table */
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.search-wrap{flex:1;min-width:200px;position:relative}
.search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:13px;pointer-events:none}
input[type=text],select{background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;padding:8px 11px;outline:none;transition:border-color .2s}
input[type=text]{padding-left:34px;width:100%}
input[type=text]:focus,select:focus{border-color:var(--accent)}
select{cursor:pointer}
select option{background:var(--surface2)}
.result-count{color:var(--muted);font-size:13px;flex-shrink:0}
.page-size-wrap{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.page-size-wrap select{padding:5px 8px;font-size:12px}
.scripts-table{width:100%;border-collapse:collapse}
.scripts-table thead th{text-align:left;font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
.scripts-table thead th:hover{color:var(--text)}
.scripts-table thead th.sort-active{color:var(--accent)}
.sort-arrow{margin-left:4px;opacity:.4;font-size:10px}
.sort-active .sort-arrow{opacity:1}
.scripts-table tbody tr{border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s}
.scripts-table tbody tr:hover{background:var(--surface2)}
.scripts-table tbody td{padding:9px 12px;vertical-align:middle;font-size:13.5px}
.td-name{font-family:var(--mono);font-size:12.5px;color:var(--accent2);font-weight:600}
.verb-badge{display:inline-block;padding:2px 9px;border-radius:20px;font-family:var(--sans);font-size:11.5px;font-weight:600}
.td-synopsis{color:var(--muted2);max-width:300px}
.td-synopsis span{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:300px}
.td-meta{color:var(--muted);font-family:var(--mono);font-size:12px;white-space:nowrap}
.help-dot{display:inline-block;width:8px;height:8px;border-radius:50%}
.pagination{display:flex;gap:5px;align-items:center;justify-content:center;flex-wrap:wrap}
.page-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted2);font-family:var(--mono);font-size:12px;padding:5px 10px;border-radius:var(--radius-sm);cursor:pointer;transition:all .2s}
.page-btn:hover{border-color:var(--accent);color:var(--accent)}
.page-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.page-btn:disabled{opacity:.35;cursor:default}

/* Detail panel */
#detailPanel{position:fixed;inset:0;z-index:500;display:none}
#detailPanel.open{display:flex}
#detailBackdrop{position:absolute;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(4px)}
#detailDrawer{position:relative;margin-left:auto;width:min(660px,100vw);height:100vh;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:24px;animation:slideIn .25s ease;display:flex;flex-direction:column}
@keyframes slideIn{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}
.detail-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:18px;flex-shrink:0}
#detailClose{margin-left:auto;background:var(--surface3);border:none;color:var(--muted2);width:30px;height:30px;border-radius:50%;cursor:pointer;font-size:15px;display:flex;align-items:center;justify-content:center;transition:all .2s}
#detailClose:hover{background:var(--red);color:#fff}
#detailContent{flex:1;overflow-y:auto}
.detail-header{margin-bottom:16px}
.detail-name{font-family:var(--mono);font-size:16px;color:var(--accent2);font-weight:600;word-break:break-all}
.detail-path{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:4px;word-break:break-all}
.detail-synopsis{color:var(--muted2);font-size:13.5px;margin-top:7px;font-style:italic}
.detail-meta-row{display:flex;gap:9px;flex-wrap:wrap;margin:12px 0}
.detail-chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:3px 10px;font-size:12px;color:var(--muted2)}
.detail-section{margin-top:18px}
.detail-section-title{font-size:11.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:9px;padding-bottom:5px;border-bottom:1px solid var(--border)}
.detail-description{color:var(--muted2);font-size:13.5px;line-height:1.7;white-space:pre-wrap}
.param-card{background:var(--surface2);border-radius:var(--radius-sm);padding:9px 12px;margin-bottom:5px;border:1px solid var(--border)}
.param-name{font-family:var(--mono);font-size:12.5px;color:var(--accent3)}
.param-desc{color:var(--muted2);font-size:12.5px;margin-top:3px}
.example-block{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;margin-bottom:7px;position:relative}
.example-cmd{font-family:var(--mono);font-size:12.5px;color:var(--green);padding-right:65px;word-break:break-word}
.example-comment{color:var(--muted);font-size:12.5px;margin-top:3px}
.copy-btn{position:absolute;top:8px;right:8px;background:var(--surface2);border:1px solid var(--border);color:var(--muted);border-radius:4px;padding:2px 8px;font-size:11px;cursor:pointer;font-family:var(--sans);transition:all .2s}
.copy-btn:hover{border-color:var(--accent);color:var(--accent)}
.copy-btn.copied{border-color:var(--green);color:var(--green)}

/* Explorer */
.explorer-toolbar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.explorer-search-wrap{flex:1;min-width:200px;position:relative}
.explorer-search-wrap .icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none}
#explorerSearch{width:100%;padding:8px 11px 8px 34px;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);font-family:var(--sans);font-size:14px;outline:none;transition:border-color .2s}
#explorerSearch:focus{border-color:var(--accent)}
.explorer-count{color:var(--muted);font-size:13px}
.explorer-sort{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.verb-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px;align-items:start}
.verb-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);display:flex;flex-direction:column;transition:border-color .2s,box-shadow .2s}
.verb-card:hover{border-color:var(--accent);box-shadow:0 2px 12px rgba(56,139,253,.1)}
.verb-card.expanded{max-height:70vh}
.verb-card-head{display:flex;align-items:center;justify-content:space-between;padding:11px 14px;border-bottom:1px solid var(--border);background:var(--surface2);border-radius:var(--radius) var(--radius) 0 0;flex-shrink:0}
.verb-card-head .vname{font-family:var(--mono);font-size:13.5px;font-weight:600}
.verb-card-head .vcount{font-size:12px;background:var(--surface3);border-radius:20px;padding:2px 9px;color:var(--accent2)}
.verb-scripts{padding:5px 7px;overflow-y:hidden;flex:1}
.verb-card.expanded .verb-scripts{overflow-y:auto}
.verb-script-row{display:flex;align-items:center;gap:7px;padding:6px 7px;border-radius:var(--radius-sm);cursor:pointer;transition:background .15s}
.verb-script-row:hover{background:var(--surface2)}
.vs-icon{color:var(--muted);font-size:10px;flex-shrink:0}
.vs-name{font-family:var(--mono);font-size:12px;color:var(--accent2);flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vs-synopsis{color:var(--muted);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:120px;flex-shrink:0}
.verb-footer{flex-shrink:0;border-top:1px solid var(--border);background:var(--surface);border-radius:0 0 var(--radius) var(--radius)}
.verb-show-more{display:flex;align-items:center;justify-content:center;gap:6px;padding:8px 12px;cursor:pointer;font-size:12px;font-family:var(--sans);transition:background .15s;border-radius:0 0 var(--radius) var(--radius)}
.verb-show-more:hover{background:var(--surface2)}
.show-more-btn{color:var(--accent)}
.vm-count{background:var(--surface3);border-radius:20px;padding:1px 8px;font-family:var(--mono);font-size:11px;color:var(--accent2)}
.show-less-btn{color:var(--muted2);display:none}
.verb-card.expanded .show-more-btn{display:none}
.verb-card.expanded .show-less-btn{display:flex}
.verb-hidden{display:none}
.verb-card.expanded .verb-hidden{display:flex}

/* Search */
.search-hero{text-align:center;padding:12px 0 18px}
.search-hero-title{font-size:22px;font-weight:700;margin-bottom:5px}
.search-hero p{color:var(--muted);font-size:13.5px}
.big-search-wrap{max-width:560px;margin:0 auto 10px;position:relative}
.big-search-wrap .icon{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:15px}
#contentSearchInput{width:100%;padding:12px 13px 12px 42px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-size:15px;color:var(--text);font-family:var(--sans);outline:none;transition:border-color .2s}
#contentSearchInput:focus{border-color:var(--accent)}
.search-filters{display:flex;gap:7px;justify-content:center;margin-bottom:18px;flex-wrap:wrap}
.search-filter-btn{padding:5px 14px;border-radius:20px;font-size:12px;font-family:var(--sans);cursor:pointer;border:1px solid var(--border);background:var(--surface);color:var(--muted2);transition:all .2s}
.search-filter-btn:hover,.search-filter-btn.active{background:rgba(56,139,253,.12);border-color:var(--accent);color:var(--accent)}
.search-result-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;margin-bottom:8px;cursor:pointer;transition:border-color .2s,transform .15s}
.search-result-card:hover{border-color:var(--accent2);transform:translateX(3px)}
.src-head{display:flex;align-items:center;gap:9px;margin-bottom:7px;flex-wrap:wrap}
.src-name{font-family:var(--mono);font-size:13.5px;color:var(--accent2);font-weight:600}
.src-match-type{font-size:10px;color:var(--muted);background:var(--surface2);padding:1px 7px;border-radius:10px;border:1px solid var(--border)}
.src-preview{font-size:12.5px;background:var(--bg);border-radius:var(--radius-sm);padding:7px 10px;color:var(--muted2)}
.src-preview mark{background:rgba(210,153,34,.25);color:var(--amber);border-radius:2px;padding:0 2px}
.search-empty{text-align:center;padding:36px;color:var(--muted);font-size:14px}
.search-empty .emoji{font-size:30px;display:block;margin-bottom:9px}

/* Analytics */
.analytics-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px;margin-bottom:18px}
.analytics-panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px}
.top-list-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);cursor:pointer}
.top-list-row:last-child{border-bottom:none}
.top-list-row:hover .tl-name{color:var(--accent)}
.tl-rank{font-family:var(--mono);font-size:11px;color:var(--muted);width:20px;flex-shrink:0;text-align:center}
.tl-name{font-family:var(--mono);font-size:12px;color:var(--accent2);flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tl-val{font-family:var(--mono);font-size:12px;color:var(--muted);flex-shrink:0}
.size-bucket-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.size-bucket-label{font-size:12px;color:var(--muted2);width:80px;flex-shrink:0}
.size-bucket-bar{flex:1;height:18px;background:var(--surface3);border-radius:4px;overflow:hidden}
.size-bucket-fill{height:100%;border-radius:4px;transition:width .9s ease}
.size-bucket-count{font-family:var(--mono);font-size:11px;color:var(--muted);width:30px;text-align:right;flex-shrink:0}
.hc-row{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px}
.hc-label{width:90px;flex-shrink:0;color:var(--muted2);font-family:var(--mono);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hc-track{flex:1;height:10px;background:var(--surface3);border-radius:5px;overflow:hidden}
.hc-fill{height:100%;border-radius:5px;transition:width .9s ease}
.hc-count{font-family:var(--mono);font-size:12px;color:var(--muted);flex-shrink:0;width:100px;text-align:right}

/* Toast */
#toast{position:fixed;bottom:22px;right:22px;z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 16px;font-size:13px;color:var(--text);box-shadow:var(--shadow);display:flex;align-items:center;gap:8px;transform:translateY(80px);opacity:0;transition:transform .3s ease,opacity .3s ease;pointer-events:none}
#toast.show{transform:translateY(0);opacity:1}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

/* Responsive */
@media(max-width:768px){#sidebar{transform:translateX(-236px);transition:transform .3s}#sidebar.open{transform:translateX(0)}#main{margin-left:0}.page{padding:18px}#menuToggle{display:flex}}
#menuToggle{display:none;position:fixed;top:12px;left:12px;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;cursor:pointer;color:var(--text)}
</style>
</head>
<body>

<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>

<nav id="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">⚡</div>
    <h1>__TITLE__</h1>
    <p title="__PATHDISPLAY__">__PATHDISPLAY__</p>
    <span class="version-badge">v3.0</span>
  </div>
  <div class="sidebar-nav">
    <div class="nav-section-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)">
      <span class="nav-icon">📊</span> Overview
    </button>
    <button class="nav-btn" onclick="showPage('scripts',this)">
      <span class="nav-icon">📄</span> All Scripts
      <span class="nav-badge">__SCRIPTCOUNT__</span>
    </button>
    <button class="nav-btn" onclick="showPage('explorer',this)">
      <span class="nav-icon">🗂</span> Explorer
    </button>
    <button class="nav-btn" onclick="showPage('search',this)">
      <span class="nav-icon">🔍</span> Content Search
    </button>
    <button class="nav-btn" onclick="showPage('analytics',this)">
      <span class="nav-icon">📈</span> Analytics
    </button>
  </div>
  <div class="theme-toggle-wrap">
    <button class="theme-toggle" onclick="toggleTheme()">
      <span id="themeIcon">🌙</span>
      <span id="themeLabel" style="flex:1;text-align:left">Dark Mode</span>
      <span class="toggle-pill"></span>
    </button>
  </div>
  <div class="sidebar-footer">
    Generated<br>__GENERATEDAT__<br>
    <span style="color:var(--accent2)">⌨</span> <kbd>/</kbd> search &nbsp; <kbd>←</kbd><kbd>→</kbd> navigate
  </div>
</nav>

<main id="main">

<!-- OVERVIEW -->
<section id="page-overview" class="page active">
  <div class="page-header">
    <div>
      <div class="page-title">Script Library Overview</div>
      <div class="page-subtitle">A bird's-eye view of your PowerShell collection</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(false)">⬇ Export CSV</button>
      <button class="btn" onclick="exportJSON(false)">⬇ Export JSON</button>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card c-blue"><div class="stat-icon">📄</div><div class="stat-value">__SCRIPTCOUNT__</div><div class="stat-label">Total Scripts</div></div>
    <div class="stat-card c-cyan"><div class="stat-icon">🏷</div><div class="stat-value">__CATCOUNT__</div><div class="stat-label">Verb Categories</div></div>
    <div class="stat-card c-purple"><div class="stat-icon">📏</div><div class="stat-value">__TOTALLINES__</div><div class="stat-label">Total Lines of Code</div></div>
    <div class="stat-card c-green"><div class="stat-icon">📝</div><div class="stat-value">__WITHHELP__</div><div class="stat-label">With Help Docs</div></div>
    <div class="stat-card c-red"><div class="stat-icon">⚠</div><div class="stat-value">__WITHOUTHELP__</div><div class="stat-label">Missing Help Docs</div></div>
    <div class="stat-card c-amber"><div class="stat-icon">📐</div><div class="stat-value">__AVGLINES__</div><div class="stat-label">Avg Lines / Script</div></div>
  </div>

  <div class="health-card">
    <div class="health-ring-wrap">
      <svg viewBox="0 0 76 76">
        <circle cx="38" cy="38" r="30" fill="none" stroke="var(--surface3)" stroke-width="9"/>
        <circle cx="38" cy="38" r="30" fill="none" stroke="#3fb950" stroke-width="9"
          stroke-dasharray="188.5" stroke-dashoffset="188.5" stroke-linecap="round"
          transform="rotate(-90 38 38)" id="healthArc" style="transition:stroke-dashoffset 1.2s ease"/>
      </svg>
      <div class="health-ring-center">
        <span class="health-score-num" id="healthNum" style="color:#3fb950">__HEALTHSCORE__</span>
        <span class="health-score-pct">/ 100</span>
      </div>
    </div>
    <div class="health-info">
      <h3>Documentation Score</h3>
      <p>Average of four checks per script: help block, synopsis, description and at least one example — aim for 100</p>
      <div class="health-bar-row">
        <span style="color:var(--green);font-size:12px">✅ Fully documented</span>
        <div class="health-mini-bar"><div class="health-mini-fill" id="hHelp" style="background:var(--green);width:0%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">__FULLDOC__</span>
      </div>
      <div class="health-bar-row">
        <span style="color:var(--red);font-size:12px">⚠ Needs attention</span>
        <div class="health-mini-bar"><div class="health-mini-fill" id="hNoHelp" style="background:var(--red);width:0%"></div></div>
        <span style="font-family:var(--mono);font-size:12px;color:var(--muted)">__NEEDSDOC__</span>
      </div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="panel">
      <div class="section-title">📊 Scripts by Verb <span style="font-size:11px;color:var(--muted);font-weight:400">(click to filter)</span></div>
      <div id="barsContainer"></div>
    </div>
    <div class="panel">
      <div class="section-title">🍩 Category Distribution</div>
      <div id="donutWrap">
        <svg id="donutSvg" viewBox="0 0 180 180"></svg>
        <div class="legend-list" id="donutLegend"></div>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="section-title">🕐 Recently Modified</div>
    <div id="recentList"></div>
  </div>
</section>

<!-- ALL SCRIPTS -->
<section id="page-scripts" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">All Scripts</div>
      <div class="page-subtitle">Browse, filter and inspect every script in the library</div>
    </div>
    <div class="btn-group">
      <button class="btn" onclick="exportCSV(true)">⬇ Export Filtered CSV</button>
      <button class="btn" onclick="exportJSON(true)">⬇ Export Filtered JSON</button>
    </div>
  </div>
  <div class="toolbar">
    <div class="search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="tableSearch" placeholder="Search name, verb, noun, author, synopsis… (press / to focus)" oninput="filterTable()"/>
    </div>
    <select id="verbFilter" onchange="filterTable()"><option value="">All Categories</option></select>
    <select id="helpFilter" onchange="filterTable()">
      <option value="">All Scripts</option>
      <option value="yes">✅ Has Help</option>
      <option value="no">⚠ No Help</option>
    </select>
    <select id="sortSelect" onchange="filterTable()">
      <option value="name-asc">Name A→Z</option>
      <option value="name-desc">Name Z→A</option>
      <option value="verb-asc">Category A→Z</option>
      <option value="verb-desc">Category Z→A</option>
      <option value="modified-desc">Recently Modified</option>
      <option value="modified-asc">Oldest Modified</option>
      <option value="lines-desc">Most Lines</option>
      <option value="lines-asc">Fewest Lines</option>
      <option value="size-desc">Largest Size</option>
      <option value="size-asc">Smallest Size</option>
    </select>
    <div class="page-size-wrap">
      Show <select id="pageSizeSelect" onchange="changePageSize()"><option>20</option><option>50</option><option>100</option></select>
    </div>
    <span class="result-count" id="resultCount"></span>
  </div>
  <table class="scripts-table">
    <thead><tr>
      <th onclick="sortByCol('name')" id="th-name">Script Name <span class="sort-arrow">↕</span></th>
      <th onclick="sortByCol('verb')" id="th-verb">Category <span class="sort-arrow">↕</span></th>
      <th>Synopsis</th>
      <th onclick="sortByCol('lines')" id="th-lines">Lines <span class="sort-arrow">↕</span></th>
      <th onclick="sortByCol('size')" id="th-size">Size <span class="sort-arrow">↕</span></th>
      <th onclick="sortByCol('modified')" id="th-modified">Modified <span class="sort-arrow">↕</span></th>
      <th title="Documentation completeness (green = 100, amber = 50-75, red = below 50)">Docs</th>
    </tr></thead>
    <tbody id="scriptsTableBody"></tbody>
  </table>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-top:12px">
    <span id="pageInfo" style="font-size:12px;color:var(--muted)"></span>
    <div class="pagination" id="pagination"></div>
  </div>
</section>

<!-- EXPLORER -->
<section id="page-explorer" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Category Explorer</div>
      <div class="page-subtitle">Browse scripts organised by PowerShell verb</div>
    </div>
  </div>
  <div class="explorer-toolbar">
    <div class="explorer-search-wrap">
      <span class="icon">🔎</span>
      <input type="text" id="explorerSearch" placeholder="Filter categories or scripts…" oninput="filterExplorer()"/>
    </div>
    <div class="explorer-sort">
      Sort: <select id="explorerSort" onchange="filterExplorer()">
        <option value="count-desc">Most Scripts</option>
        <option value="count-asc">Fewest Scripts</option>
        <option value="alpha">Alphabetical</option>
      </select>
    </div>
    <span class="explorer-count" id="explorerCount"></span>
  </div>
  <div class="verb-grid" id="verbGrid"></div>
</section>

<!-- CONTENT SEARCH -->
<section id="page-search" class="page">
  <div class="search-hero">
    <div class="search-hero-title">Content Search</div>
    <p>Find scripts by keyword — searches name, synopsis, description, parameters and examples</p>
  </div>
  <div class="big-search-wrap">
    <span class="icon">🔍</span>
    <input type="text" id="contentSearchInput" placeholder="Try: ManagedIdentity, ConditionalAccess, Connect-MgGraph…" oninput="contentSearch()"/>
  </div>
  <div class="search-filters">
    <button class="search-filter-btn active" data-field="all"         onclick="setSearchField(this)">All Fields</button>
    <button class="search-filter-btn"         data-field="name"        onclick="setSearchField(this)">Name</button>
    <button class="search-filter-btn"         data-field="synopsis"    onclick="setSearchField(this)">Synopsis</button>
    <button class="search-filter-btn"         data-field="description" onclick="setSearchField(this)">Description</button>
    <button class="search-filter-btn"         data-field="params"      onclick="setSearchField(this)">Parameters</button>
    <button class="search-filter-btn"         data-field="examples"    onclick="setSearchField(this)">Examples</button>
  </div>
  <div id="searchResults">
    <div class="search-empty"><span class="emoji">💡</span>Type a keyword above to search across all __SCRIPTCOUNT__ scripts</div>
  </div>
</section>

<!-- ANALYTICS -->
<section id="page-analytics" class="page">
  <div class="page-header">
    <div>
      <div class="page-title">Analytics</div>
      <div class="page-subtitle">Deep insights into your script library composition</div>
    </div>
  </div>
  <div class="analytics-grid">
    <div class="analytics-panel">
      <div class="section-title">📏 Largest by Lines</div>
      <div id="topByLines"></div>
    </div>
    <div class="analytics-panel">
      <div class="section-title">💾 Largest by File Size</div>
      <div id="topBySize"></div>
    </div>
    <div class="analytics-panel">
      <div class="section-title">⚠ Needs Documentation</div>
      <div id="missingHelp"></div>
    </div>
    <div class="analytics-panel">
      <div class="section-title">🏷 All Verb Categories</div>
      <div id="allCategories"></div>
    </div>
  </div>
  <div class="panel" style="margin-bottom:16px">
    <div class="section-title">📦 Size Distribution</div>
    <div id="sizeDistribution"></div>
  </div>
  <div class="panel">
    <div class="section-title">📝 Help Coverage by Verb</div>
    <div id="helpCoverage"></div>
  </div>
</section>

</main>

<!-- DETAIL PANEL -->
<div id="detailPanel">
  <div id="detailBackdrop" onclick="closeDetail()"></div>
  <div id="detailDrawer">
    <div class="detail-toolbar">
      <button class="btn" id="detailPrevBtn" onclick="navigateDetail(-1)">‹ Prev</button>
      <button class="btn" id="detailNextBtn" onclick="navigateDetail(1)">Next ›</button>
      <button class="btn" onclick="copyDetailName()">📋 Copy Name</button>
      <button id="detailClose" onclick="closeDetail()" title="Close (Esc)">✕</button>
    </div>
    <div id="detailContent"></div>
  </div>
</div>

<div id="toast"><span id="toastIcon">✅</span><span id="toastMsg">Done</span></div>

<script>
const SCRIPTS    = [__SCRIPTS_JSON__];
const CATEGORIES = [__CATEGORIES_JSON__];
const PALETTE    = ['#3b82f6','#06b6d4','#8b5cf6','#10b981','#f59e0b','#ef4444','#ec4899','#84cc16','#f97316','#a78bfa','#34d399','#fbbf24','#60a5fa','#2dd4bf','#c084fc'];

// ── Utils ──
function escH(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
// escJ builds a JavaScript string literal body for use inside a double-quoted HTML attribute,
// so it is escaped for JavaScript first and then for HTML.
function escJ(s){return escH(String(s==null?'':s).replace(/\\/g,'\\\\').replace(/'/g,"\\'"));}
function docColor(sc){return sc>=100?'var(--green)':sc>=50?'var(--amber)':'var(--red)';}

SCRIPTS.forEach((s,i)=>{ s.id = i; });

const VERB_COLORS = Object.create(null);
CATEGORIES.forEach((c,i) => { VERB_COLORS[c.verb] = PALETTE[i % PALETTE.length]; });

function verbBadge(v) {
  const col = VERB_COLORS[v] || '#64748b';
  return `<span class="verb-badge" style="background:${col}22;color:${col};border:1px solid ${col}44">${escH(v)}</span>`;
}

// ── Toast ──
let _toastT;
function showToast(msg, icon='✅') {
  document.getElementById('toastMsg').textContent = msg;
  document.getElementById('toastIcon').textContent = icon;
  const el = document.getElementById('toast');
  el.classList.add('show');
  clearTimeout(_toastT);
  _toastT = setTimeout(() => el.classList.remove('show'), 2600);
}

// ── Theme ──
function toggleTheme() {
  const light = document.body.classList.toggle('light-theme');
  document.getElementById('themeIcon').textContent  = light ? '☀️' : '🌙';
  document.getElementById('themeLabel').textContent = light ? 'Light Mode' : 'Dark Mode';
  try { localStorage.setItem('ps-catalog-theme', light ? 'light' : 'dark'); } catch(e){}
}
(function(){
  try { if (localStorage.getItem('ps-catalog-theme') === 'light') {
    document.body.classList.add('light-theme');
    document.getElementById('themeIcon').textContent  = '☀️';
    document.getElementById('themeLabel').textContent = 'Light Mode';
  }} catch(e){}
})();

// ── Navigation ──
function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  if (btn) btn.classList.add('active');
}

// ── Documentation score ──
(function(){
  const score = __HEALTHSCORE__;
  const fullPct = __FULLDOCPCT__;
  const arc = document.getElementById('healthArc');
  const num = document.getElementById('healthNum');
  const circ = 2 * Math.PI * 30;
  const col = score >= 80 ? '#3fb950' : score >= 50 ? '#d29922' : '#f85149';
  arc.style.stroke = col; num.style.color = col;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    arc.style.strokeDashoffset = circ * (1 - score / 100);
  }));
  document.getElementById('hHelp').style.width   = fullPct + '%';
  document.getElementById('hNoHelp').style.width = (100 - fullPct) + '%';
})();

// ── Bars ──
(function(){
  const max = Math.max(...CATEGORIES.map(c => c.count));
  const el = document.getElementById('barsContainer');
  CATEGORIES.slice(0,15).forEach((cat,i) => {
    const pct = Math.round((cat.count/max)*100);
    const col = PALETTE[i%PALETTE.length];
    el.innerHTML += `<div class="bar-row" onclick="goToVerb('${escJ(cat.verb)}')">
      <span class="bar-label" title="${escH(cat.verb)}">${escH(cat.verb)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:0%;background:${col}" data-pct="${pct}"></div></div>
      <span class="bar-count">${cat.count}</span></div>`;
  });
  requestAnimationFrame(() => {
    document.querySelectorAll('.bar-fill').forEach(el => { el.style.width = el.dataset.pct + '%'; });
  });
})();

function goToVerb(verb) {
  showPage('scripts', document.querySelectorAll('.nav-btn')[1]);
  document.getElementById('verbFilter').value = verb;
  filterTable();
}

// ── Donut ──
(function(){
  const svg = document.getElementById('donutSvg');
  const legend = document.getElementById('donutLegend');
  const total = CATEGORIES.reduce((s,c) => s+c.count, 0);
  const R=68,cx=90,cy=90,stroke=24;
  const circ = 2*Math.PI*R;
  let offset=0;
  const shown = CATEGORIES.slice(0,10);
  const otherCnt = CATEGORIES.slice(10).reduce((s,c)=>s+c.count,0);
  const items = otherCnt > 0 ? [...shown,{verb:'Other categories',count:otherCnt,isOther:true}] : shown;
  const GAP = 1.5/360;
  items.forEach((cat,i) => {
    const frac=cat.count/total, drawFrac=Math.max(0,frac-GAP);
    const dashLen=drawFrac*circ, gap=circ-dashLen;
    const col=cat.isOther?'#475569':PALETTE[i%PALETTE.length];
    const c=document.createElementNS('http://www.w3.org/2000/svg','circle');
    c.setAttribute('cx',cx);c.setAttribute('cy',cy);c.setAttribute('r',R);
    c.setAttribute('fill','none');c.setAttribute('stroke',col);c.setAttribute('stroke-width',stroke);
    c.setAttribute('stroke-dasharray',`${dashLen} ${gap}`);
    const finalOffset=-(offset*circ)+circ*0.25;
    c.setAttribute('stroke-dashoffset',circ);
    c.style.transition=`stroke-dashoffset 0.9s cubic-bezier(.4,0,.2,1) ${i*0.06}s`;
    svg.appendChild(c);
    requestAnimationFrame(()=>requestAnimationFrame(()=>{c.style.strokeDashoffset=finalOffset;}));
    offset+=frac;
    const pct=Math.round(frac*100);
    const click = cat.isOther ? '' : ` onclick="goToVerb('${escJ(cat.verb)}')"`;
    legend.innerHTML+=`<div class="legend-item"${click}><span class="legend-dot" style="background:${col}"></span><span>${escH(cat.verb)}</span><span class="legend-pct">${cat.count} (${pct}%)</span></div>`;
  });
  const mk=(y,sz,fw,fill,txt)=>{const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',cx);t.setAttribute('y',y);t.setAttribute('text-anchor','middle');t.style.fill=fill;t.setAttribute('font-size',sz);t.setAttribute('font-weight',fw);t.textContent=txt;svg.appendChild(t);};
  mk(cy-6,'20','800','var(--text)',total);
  mk(cy+12,'10','400','var(--muted)','scripts');
})();

// ── Recent ──
(function(){
  const sorted=[...SCRIPTS].sort((a,b)=>b.modSort.localeCompare(a.modSort)).slice(0,10);
  const el=document.getElementById('recentList');
  sorted.forEach(s=>{el.innerHTML+=`<div class="recent-row"><span class="recent-icon">📄</span><span class="recent-name" onclick="openDetail(${s.id})">${escH(s.name)}</span>${verbBadge(s.verb)}<span class="recent-date">${escH(s.modified)}</span></div>`;});
})();

// ── Scripts Table ──
let PAGE_SIZE=20, filteredScripts=[...SCRIPTS], currentPage=1, currentSort='name-asc';
const SORTERS={
  'name-asc':(a,b)=>a.name.localeCompare(b.name),
  'name-desc':(a,b)=>b.name.localeCompare(a.name),
  'verb-asc':(a,b)=>a.verb.localeCompare(b.verb)||a.name.localeCompare(b.name),
  'verb-desc':(a,b)=>b.verb.localeCompare(a.verb)||a.name.localeCompare(b.name),
  'modified-desc':(a,b)=>b.modSort.localeCompare(a.modSort),
  'modified-asc':(a,b)=>a.modSort.localeCompare(b.modSort),
  'lines-desc':(a,b)=>b.lines-a.lines,
  'lines-asc':(a,b)=>a.lines-b.lines,
  'size-desc':(a,b)=>b.sizeKB-a.sizeKB,
  'size-asc':(a,b)=>a.sizeKB-b.sizeKB
};
(function(){
  const sel=document.getElementById('verbFilter');
  CATEGORIES.forEach(c=>{const o=document.createElement('option');o.value=c.verb;o.textContent=`${c.verb} (${c.count})`;sel.appendChild(o);});
  filterTable();
})();

function changePageSize() { PAGE_SIZE=parseInt(document.getElementById('pageSizeSelect').value); currentPage=1; renderTable(); }

function sortByCol(col) {
  const defaults={name:'name-asc',verb:'verb-asc',lines:'lines-desc',size:'size-desc',modified:'modified-desc'};
  if (currentSort.startsWith(col+'-')) { currentSort = col + '-' + (currentSort.endsWith('-asc') ? 'desc' : 'asc'); }
  else { currentSort = defaults[col]; }
  document.getElementById('sortSelect').value=currentSort;
  document.querySelectorAll('.scripts-table thead th').forEach(t=>t.classList.remove('sort-active'));
  const th=document.getElementById('th-'+col);
  if(th){th.classList.add('sort-active');th.querySelector('.sort-arrow').textContent=currentSort.endsWith('asc')?'↑':'↓';}
  filterTable();
}

function filterTable() {
  const q=document.getElementById('tableSearch').value.toLowerCase().trim();
  const verb=document.getElementById('verbFilter').value;
  const help=document.getElementById('helpFilter').value;
  currentSort=document.getElementById('sortSelect').value||currentSort;
  filteredScripts=SCRIPTS.filter(s=>{
    const mQ=!q||s.name.toLowerCase().includes(q)||s.synopsis.toLowerCase().includes(q)||s.verb.toLowerCase().includes(q)||s.noun.toLowerCase().includes(q)||s.author.toLowerCase().includes(q);
    const mV=!verb||s.verb===verb;
    const mH=!help||(help==='yes'?s.hasHelp:!s.hasHelp);
    return mQ&&mV&&mH;
  });
  if(SORTERS[currentSort]) filteredScripts.sort(SORTERS[currentSort]);
  currentPage=1; renderTable();
}

function renderTable() {
  const start=(currentPage-1)*PAGE_SIZE;
  const slice=filteredScripts.slice(start,start+PAGE_SIZE);
  document.getElementById('resultCount').textContent=`${filteredScripts.length} of ${SCRIPTS.length}`;
  document.getElementById('pageInfo').textContent=filteredScripts.length?`Showing ${start+1}–${Math.min(start+PAGE_SIZE,filteredScripts.length)} of ${filteredScripts.length}`:'No scripts match the current filters';
  document.getElementById('scriptsTableBody').innerHTML=slice.map((s,idx)=>`
    <tr onclick="openDetailFromList(${start+idx})">
      <td class="td-name">${escH(s.name)}</td>
      <td>${verbBadge(s.verb)}</td>
      <td class="td-synopsis"><span title="${escH(s.synopsis)}">${escH(s.synopsis)||'<em style="color:var(--muted)">—</em>'}</span></td>
      <td class="td-meta">${s.lines}</td>
      <td class="td-meta">${s.sizeKB} KB</td>
      <td class="td-meta">${escH(s.modified)}</td>
      <td><span class="help-dot" style="background:${docColor(s.docScore)}" title="Documentation score: ${s.docScore}/100"></span></td>
    </tr>`).join('');
  renderPagination();
}

function renderPagination() {
  const total=Math.ceil(filteredScripts.length/PAGE_SIZE);
  const el=document.getElementById('pagination');
  if(total<=1){el.innerHTML='';return;}
  let h=`<button class="page-btn" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>‹</button>`;
  for(let i=1;i<=total;i++){
    if(i===1||i===total||Math.abs(i-currentPage)<=1) h+=`<button class="page-btn ${i===currentPage?'active':''}" onclick="goPage(${i})">${i}</button>`;
    else if(Math.abs(i-currentPage)===2) h+=`<span style="color:var(--muted);padding:0 4px">…</span>`;
  }
  h+=`<button class="page-btn" onclick="goPage(${currentPage+1})" ${currentPage===total?'disabled':''}>›</button>`;
  el.innerHTML=h;
}

function goPage(p) {
  const total=Math.ceil(filteredScripts.length/PAGE_SIZE);
  if(p<1||p>total) return;
  currentPage=p; renderTable();
  window.scrollTo(0,0);
}

// ── Explorer ──
const SHOW_INITIAL=6;
function buildExplorer(ft) {
  const grid=document.getElementById('verbGrid');
  const q=(ft||'').toLowerCase().trim();
  const sm=document.getElementById('explorerSort').value;
  grid.innerHTML=''; let vis=0;
  let cats=[...CATEGORIES];
  if(sm==='count-asc') cats.sort((a,b)=>a.count-b.count);
  else if(sm==='alpha') cats.sort((a,b)=>a.verb.localeCompare(b.verb));
  cats.forEach((cat,i)=>{
    const col=VERB_COLORS[cat.verb]||PALETTE[i%PALETTE.length];
    let scripts=SCRIPTS.filter(s=>s.verb===cat.verb);
    if(q){scripts=scripts.filter(s=>cat.verb.toLowerCase().includes(q)||s.name.toLowerCase().includes(q)||s.synopsis.toLowerCase().includes(q));}
    if(!scripts.length)return; vis++;
    const init=scripts.slice(0,SHOW_INITIAL), extra=scripts.slice(SHOW_INITIAL), hasMore=extra.length>0;
    const mkRow=(s,h)=>`<div class="verb-script-row${h?' verb-hidden':''}" onclick="openDetail(${s.id})"><span class="vs-icon">▸</span><span class="vs-name" title="${escH(s.name)}">${escH(s.name)}</span><span class="vs-synopsis" title="${escH(s.synopsis)}">${escH(s.synopsis)}</span></div>`;
    const footer=hasMore?`<div class="verb-footer"><div class="verb-show-more show-more-btn" onclick="toggleVerbExpand(this)"><span>▾ Show all</span><span class="vm-count">+${extra.length} more</span></div><div class="verb-show-more show-less-btn" onclick="toggleVerbExpand(this)"><span>▴ Show less</span></div></div>`:'';
    grid.innerHTML+=`<div class="verb-card" data-verb="${escH(cat.verb)}"><div class="verb-card-head" style="border-left:3px solid ${col}"><span class="vname" style="color:${col}">${escH(cat.verb)}</span><span class="vcount">${scripts.length} script${scripts.length!==1?'s':''}</span></div><div class="verb-scripts">${init.map(s=>mkRow(s,false)).join('')}${extra.map(s=>mkRow(s,true)).join('')}</div>${footer}</div>`;
  });
  const c=document.getElementById('explorerCount');
  if(c) c.textContent=vis+' categor'+(vis===1?'y':'ies');
}
function toggleVerbExpand(btn) {
  const card=btn.closest('.verb-card');
  const expanding=!card.classList.contains('expanded');
  card.classList.toggle('expanded');
  setTimeout(()=>card.scrollIntoView({behavior:'smooth',block:expanding?'start':'nearest'}),40);
}
function filterExplorer(){buildExplorer(document.getElementById('explorerSearch').value);}
buildExplorer();

// ── Content Search ──
let _st=null, searchField='all';
function setSearchField(btn){document.querySelectorAll('.search-filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');searchField=btn.dataset.field;contentSearch();}
function contentSearch(){clearTimeout(_st);_st=setTimeout(_doSearch,160);}
function _doSearch(){
  const q=document.getElementById('contentSearchInput').value.trim();
  const el=document.getElementById('searchResults');
  if(q.length<2){el.innerHTML='<div class="search-empty"><span class="emoji">💡</span>Type at least 2 characters</div>';return;}
  const ql=q.toLowerCase();
  const hits=SCRIPTS.map(s=>{
    let mt=[];
    if((searchField==='all'||searchField==='name')&&s.name.toLowerCase().includes(ql)) mt.push('name');
    if((searchField==='all'||searchField==='synopsis')&&s.synopsis.toLowerCase().includes(ql)) mt.push('synopsis');
    if((searchField==='all'||searchField==='description')&&s.description.toLowerCase().includes(ql)) mt.push('description');
    if((searchField==='all'||searchField==='params')&&s.params.some(p=>p.name.toLowerCase().includes(ql)||p.desc.toLowerCase().includes(ql))) mt.push('parameters');
    if((searchField==='all'||searchField==='examples')&&s.examples.some(e=>e.cmd.toLowerCase().includes(ql)||e.comment.toLowerCase().includes(ql))) mt.push('examples');
    return mt.length?{s:s,matchTypes:mt}:null;
  }).filter(Boolean);
  if(!hits.length){el.innerHTML=`<div class="search-empty"><span class="emoji">🔍</span>No scripts matched "<strong style="color:var(--text)">${escH(q)}</strong>"</div>`;return;}
  // Escape the text first, then highlight, so script text can never inject markup.
  const re=new RegExp(escH(q).replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'gi');
  el.innerHTML=`<div style="margin-bottom:10px;color:var(--muted);font-size:12px">${hits.length} script${hits.length!==1?'s':''} matched</div>`+
    hits.map(h=>{
      const s=h.s;
      const raw=(s.synopsis||s.description||'').substring(0,180);
      const preview=escH(raw).replace(re,m=>'<mark>'+m+'</mark>');
      const badges=h.matchTypes.map(t=>`<span class="src-match-type">${t}</span>`).join(' ');
      return `<div class="search-result-card" onclick="openDetail(${s.id})"><div class="src-head"><span class="src-name">${escH(s.name)}</span>${verbBadge(s.verb)}${badges}</div><div class="src-preview">${preview||'<em style="color:var(--muted)">No synopsis</em>'}</div></div>`;
    }).join('');
}

// ── Analytics ──
(function(){
  const row=(s,i,val)=>`<div class="top-list-row" onclick="openDetail(${s.id})"><span class="tl-rank">${i}</span><span class="tl-name" title="${escH(s.name)}">${escH(s.name)}</span><span class="tl-val">${val}</span></div>`;
  document.getElementById('topByLines').innerHTML=[...SCRIPTS].sort((a,b)=>b.lines-a.lines).slice(0,8).map((s,i)=>row(s,i+1,s.lines+' lines')).join('');
  document.getElementById('topBySize').innerHTML=[...SCRIPTS].sort((a,b)=>b.sizeKB-a.sizeKB).slice(0,8).map((s,i)=>row(s,i+1,s.sizeKB+' KB')).join('');

  const needs=SCRIPTS.filter(s=>s.docScore<100).sort((a,b)=>a.docScore-b.docScore||a.name.localeCompare(b.name));
  document.getElementById('missingHelp').innerHTML=needs.length===0?'<p style="color:var(--green);font-size:13px">✅ All scripts fully documented!</p>':
    needs.slice(0,10).map(s=>row(s,'⚠',s.docScore+'/100')).join('')+
    (needs.length>10?`<div style="color:var(--muted);font-size:12px;margin-top:7px">…and ${needs.length-10} more</div>`:'');

  document.getElementById('allCategories').innerHTML=CATEGORIES.map((c,i)=>{
    const col=PALETTE[i%PALETTE.length],pct=Math.round((c.count/SCRIPTS.length)*100);
    return `<div class="top-list-row" onclick="goToVerb('${escJ(c.verb)}')"><span class="legend-dot" style="background:${col}"></span><span class="tl-name">${escH(c.verb)}</span><span class="tl-val">${c.count} (${pct}%)</span></div>`;
  }).join('');

  const buckets=[{l:'< 5 KB',fn:s=>s.sizeKB<5},{l:'5–20 KB',fn:s=>s.sizeKB>=5&&s.sizeKB<20},{l:'20–50 KB',fn:s=>s.sizeKB>=20&&s.sizeKB<50},{l:'50+ KB',fn:s=>s.sizeKB>=50}];
  const bCols=['#3b82f6','#06b6d4','#8b5cf6','#f59e0b'];
  const bMax=Math.max(...buckets.map(b=>SCRIPTS.filter(b.fn).length));
  document.getElementById('sizeDistribution').innerHTML=buckets.map((b,i)=>{
    const cnt=SCRIPTS.filter(b.fn).length,pct=bMax?Math.round((cnt/bMax)*100):0;
    return `<div class="size-bucket-row"><span class="size-bucket-label">${b.l}</span><div class="size-bucket-bar"><div class="size-bucket-fill" style="width:0%;background:${bCols[i]}" data-pct="${pct}"></div></div><span class="size-bucket-count">${cnt}</span></div>`;
  }).join('');

  const helpRows=CATEGORIES.map(c=>{
    const vs=SCRIPTS.filter(s=>s.verb===c.verb),wh=vs.filter(s=>s.hasHelp).length,pct=vs.length?Math.round((wh/vs.length)*100):0;
    const col=pct===100?'var(--green)':pct>=50?'var(--amber)':'var(--red)';
    return {verb:c.verb,total:vs.length,wh:wh,pct:pct,col:col};
  }).sort((a,b)=>b.pct-a.pct||a.verb.localeCompare(b.verb));
  document.getElementById('helpCoverage').innerHTML=helpRows.map(r=>`<div class="hc-row"><span class="hc-label" title="${escH(r.verb)}">${escH(r.verb)}</span><div class="hc-track"><div class="hc-fill" style="width:0%;background:${r.col}" data-pct="${r.pct}"></div></div><span class="hc-count">${r.wh}/${r.total} (${r.pct}%)</span></div>`).join('');

  requestAnimationFrame(()=>{
    document.querySelectorAll('.size-bucket-fill,.hc-fill').forEach(el=>{el.style.width=el.dataset.pct+'%';});
  });
})();

// ── Detail panel ──
let currentDetailIndex=-1, detailList=SCRIPTS;
function openDetailFromList(idx){detailList=filteredScripts;currentDetailIndex=idx;_renderDetail(detailList[idx]);}
function openDetail(id){detailList=SCRIPTS;currentDetailIndex=id;if(SCRIPTS[id])_renderDetail(SCRIPTS[id]);}
function navigateDetail(dir){const ni=currentDetailIndex+dir;if(ni<0||ni>=detailList.length)return;currentDetailIndex=ni;_renderDetail(detailList[ni]);}
function _renderDetail(s){
  if(!s)return;
  document.getElementById('detailPrevBtn').disabled=currentDetailIndex<=0;
  document.getElementById('detailNextBtn').disabled=currentDetailIndex>=detailList.length-1;
  const paramsHtml=s.params.length?s.params.map(p=>`<div class="param-card"><div class="param-name">-${escH(p.name)}</div><div class="param-desc">${escH(p.desc)}</div></div>`).join(''):'<p style="color:var(--muted);font-size:12px">No parameters documented.</p>';
  const exHtml=s.examples.length?s.examples.map((e,ei)=>`<div class="example-block"><button class="copy-btn" onclick="copyExample(${s.id},${ei},this)">Copy</button><div class="example-cmd">${escH(e.cmd)}</div>${e.comment?`<div class="example-comment">${escH(e.comment)}</div>`:''}</div>`).join(''):'<p style="color:var(--muted);font-size:12px">No examples documented.</p>';
  document.getElementById('detailContent').innerHTML=`
    <div class="detail-header">
      <div class="detail-name">${escH(s.name)}</div>
      <div class="detail-path">${escH(s.path)}</div>
      ${s.synopsis?`<div class="detail-synopsis">${escH(s.synopsis)}</div>`:''}
    </div>
    <div class="detail-meta-row">
      ${verbBadge(s.verb)}
      ${s.author?`<span class="detail-chip">👤 ${escH(s.author)}</span>`:''}
      ${s.version?`<span class="detail-chip">🏷 v${escH(s.version)}</span>`:''}
      <span class="detail-chip">📏 ${s.lines} lines</span>
      <span class="detail-chip">💾 ${s.sizeKB} KB</span>
      <span class="detail-chip">🕐 ${escH(s.modified)}</span>
      <span class="detail-chip" style="color:${docColor(s.docScore)}">${s.hasHelp?'✅':'⚠'} Docs ${s.docScore}/100</span>
      <span class="detail-chip">${s.params.length} param${s.params.length!==1?'s':''}</span>
      <span class="detail-chip">${s.examples.length} example${s.examples.length!==1?'s':''}</span>
    </div>
    ${s.description?`<div class="detail-section"><div class="detail-section-title">Description</div><div class="detail-description">${escH(s.description)}</div></div>`:''}
    <div class="detail-section"><div class="detail-section-title">Parameters (${s.params.length})</div>${paramsHtml}</div>
    <div class="detail-section"><div class="detail-section-title">Examples (${s.examples.length})</div>${exHtml}</div>`;
  document.getElementById('detailPanel').classList.add('open');
  document.body.style.overflow='hidden';
  document.getElementById('detailContent').scrollTo(0,0);
}
function closeDetail(){document.getElementById('detailPanel').classList.remove('open');document.body.style.overflow='';}
function copyDetailName(){if(currentDetailIndex>=0&&detailList[currentDetailIndex])copyText(detailList[currentDetailIndex].name,null);}
function copyExample(id,ei,btn){const s=SCRIPTS[id];if(s&&s.examples[ei])copyText(s.examples[ei].cmd,btn);}
function copyText(text,btn){
  const done=()=>{showToast('Copied to clipboard!');if(btn){btn.textContent='Copied!';btn.classList.add('copied');setTimeout(()=>{btn.textContent='Copy';btn.classList.remove('copied');},1800);}};
  const fail=()=>showToast('Copy not available in this browser','⚠');
  try{
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done).catch(fail);}
    else{fail();}
  }catch(e){fail();}
}

// ── Exports ──
// A leading = + - @ tab or CR can make a spreadsheet run the cell as a formula, so such cells are prefixed with an apostrophe.
function csvCell(v){let t=String(v==null?'':v);if(/^[=+\-@\t\r]/.test(t))t="'"+t;return '"'+t.replace(/"/g,'""')+'"';}
function exportCSV(filtered){
  const data=filtered?filteredScripts:SCRIPTS;
  const rows=data.map(s=>[csvCell(s.name),csvCell(s.verb),csvCell(s.noun),csvCell(s.author),csvCell(s.version),csvCell(s.synopsis),s.lines,s.sizeKB,csvCell(s.modified),s.hasHelp,s.docScore,csvCell(s.params.map(p=>p.name).join(', ')),csvCell(s.examples.map(e=>e.cmd).join(' | ')),csvCell(s.path)].join(','));
  dlFile('\uFEFF'+['Name,Verb,Noun,Author,Version,Synopsis,Lines,SizeKB,Modified,HasHelp,DocScore,Parameters,Examples,Path',...rows].join('\r\n'),'ScriptCatalog.csv','text/csv;charset=utf-8');
  showToast(`Exported ${data.length} scripts as CSV`);
}
function exportJSON(filtered){
  const data=(filtered?filteredScripts:SCRIPTS).map(s=>({name:s.name,verb:s.verb,noun:s.noun,author:s.author,version:s.version,synopsis:s.synopsis,description:s.description,lines:s.lines,sizeKB:s.sizeKB,modified:s.modified,hasHelp:s.hasHelp,documentationScore:s.docScore,paramCount:s.params.length,exampleCount:s.examples.length,parameters:s.params,examples:s.examples,path:s.path}));
  dlFile(JSON.stringify(data,null,2),'ScriptCatalog.json','application/json');
  showToast(`Exported ${data.length} scripts as JSON`);
}
function dlFile(content,name,type){const b=new Blob([content],{type});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=name;a.click();URL.revokeObjectURL(u);}

// ── Keyboard shortcuts ──
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closeDetail();return;}
  if(e.key==='/'&&document.activeElement.tagName!=='INPUT'&&document.activeElement.tagName!=='SELECT'){
    e.preventDefault();
    const inp=document.querySelector('.page.active input[type=text]');
    if(inp) inp.focus();
  }
  if(document.getElementById('detailPanel').classList.contains('open')){
    if(e.key==='ArrowLeft')  navigateDetail(-1);
    if(e.key==='ArrowRight') navigateDetail(1);
  }
});
</script>
</body>
</html>
'@

                # Single-pass substitution: every __TOKEN__ is replaced exactly once and
                # replaced text is never scanned again, so script text that happens to
                # contain a token name (or a '$' character) cannot alter the page.
                $tokens = @{
                    '__TITLE__'           = $titleEncoded
                    '__PATHDISPLAY__'     = $pathDisplayEncoded
                    '__GENERATEDAT__'     = [System.Net.WebUtility]::HtmlEncode($generatedAt)
                    '__SCRIPTCOUNT__'     = [string]$allScripts.Count
                    '__CATCOUNT__'        = [string]$categories.Count
                    '__TOTALLINES__'      = [string]$totalLines
                    '__WITHHELP__'        = [string]$withHelp
                    '__WITHOUTHELP__'     = [string]$withoutHelp
                    '__AVGLINES__'        = [string]$avgLines
                    '__HEALTHSCORE__'     = [string]$docScoreAvg
                    '__FULLDOC__'         = [string]$fullyDocumented
                    '__NEEDSDOC__'        = [string]($allScripts.Count - $fullyDocumented)
                    '__FULLDOCPCT__'      = [string]$fullDocPct
                    '__SCRIPTS_JSON__'    = $rowsJson
                    '__CATEGORIES_JSON__' = $categoriesJson
                }

                $tokenEvaluator = [System.Text.RegularExpressions.MatchEvaluator] {
                    param($Match)

                    if ($tokens.ContainsKey($Match.Value)) {
                        return $tokens[$Match.Value]
                    }

                    return $Match.Value
                }

                $html = [regex]::Replace($template, '__[A-Z0-9_]+__', $tokenEvaluator)

                if ($PSCmdlet.ShouldProcess($OutputPath, 'Write script catalog HTML dashboard')) {
                    $htmlWritten = & $writeOutputFile -TargetPath $OutputPath -Content $html
                    & $say "  ✅  Dashboard written: $htmlWritten" 'Green'
                }
            }

            #endregion

            #region ── Summary ──────────────────────────────────────────────────────

            $duration = (Get-Date) - $startTime
            $scoreColor = 'Red'

            if ($docScoreAvg -ge 80) {
                $scoreColor = 'Green'
            }
            elseif ($docScoreAvg -ge 50) {
                $scoreColor = 'Yellow'
            }

            & $say ''
            & $say '╔══════════════════════════════════════════════════════╗' 'Cyan'
            & $say '║   ✅  Script Catalog — complete                      ║' 'Cyan'
            & $say '╚══════════════════════════════════════════════════════╝' 'Cyan'
            & $say ''
            & $say "  📊  Scripts indexed   : $($allScripts.Count)"
            & $say "  🏷   Categories        : $($categories.Count)"
            & $say "  📝  With help docs    : $withHelp ($helpPct%)"
            & $say "  📏  Total lines       : $totalLines (avg $avgLines/script, $totalSizeKB KB)"
            & $say "  💯  Documentation     : $docScoreAvg / 100" $scoreColor

            if ($htmlWritten) {
                & $say "  📁  HTML dashboard    : $htmlWritten"
            }

            if ($jsonWritten) {
                & $say "  📁  JSON metadata     : $jsonWritten"
            }

            & $say ''

            if ($OpenBrowser -and $htmlWritten) {
                & $say '  🌐  Opening dashboard…' 'Green'
                Invoke-Item -LiteralPath $htmlWritten
            }

            #endregion

            return [PSCustomObject]@{
                HtmlPath           = $htmlWritten
                JsonPath           = $jsonWritten
                ScriptCount        = $allScripts.Count
                CategoryCount      = $categories.Count
                WithHelp           = $withHelp
                DocumentationScore = $docScoreAvg
                SkippedFiles       = $skippedFiles.ToArray()
                Duration           = $duration
            }
        }
        catch {
            Write-Progress -Activity 'Reading script metadata' -Completed
            Write-Warning -Message "Export-ScriptCatalog failed: $($_.Exception.Message)"
            throw
        }
    }

    End {
        Write-Verbose -Message '[INFO] Export-ScriptCatalog completed.'
    }
}
