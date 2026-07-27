<#

Author       : Lakshmanan Thangaraj
Version      : 1.2
Created-On   : 08 July 2026
Modified-On  : 27 July 2026

.SYNOPSIS
    Builds a redistributable PowerShell module (.psm1 + .psd1) from a folder of
    standalone .ps1 function scripts.

.DESCRIPTION
    New-PSModuleFromScripts scans a source folder for .ps1 files, copies them into
    a new module folder structure (ModuleName\Public\*.ps1), parses each file's
    Abstract Syntax Tree (AST) to reliably discover every function actually defined
    inside it (not just guessing from the file name), and then generates:

        - <ModuleName>.psm1  : dot-sources every script in .\Public and exports
                                the discovered function names.
        - <ModuleName>.psd1  : a standard module manifest built via the real
                                New-ModuleManifest cmdlet (not a hand-rolled
                                string template), so quoting/escaping of
                                Author, Description, etc. is handled correctly.

    This lets you turn a folder of loose scripts into something you can import with
    a single Import-Module call, instead of dot-sourcing each script by hand.

    Function discovery uses [System.Management.Automation.Language.Parser] so it
    correctly handles files that contain more than one function, or where the
    function name doesn't exactly match the file name. Duplicate function names
    across files are flagged as warnings rather than silently overwritten.

    SAFETY BEHAVIOR (v1.2):
        - -ModuleName is validated against a safe character set (letters,
          digits, dot, dash, underscore) so it can never be used to make the
          computed module folder resolve outside -OutputPath.
        - The function refuses to run if the computed module folder is the
          same as, or overlaps with, -SourcePath - this prevents -Force from
          deleting your source scripts before they've been copied.
        - Rebuilding an existing module (-Force) preserves that module's
          original GUID by reading it from the prior .psd1, instead of
          stamping a new identity on every rebuild. A brand-new module gets
          a freshly generated GUID - never a shared/hardcoded one.
        - -Author and -Description are checked for characters that could
          break out of the generated manifest (embedded quotes, line breaks,
          here-string terminators) and rejected with a clear error rather
          than silently corrupting the output.

.PARAMETER SourcePath
    Folder containing the .ps1 scripts to include in the module.

.PARAMETER ModuleName
    Name of the module to create (also used as the folder name and .psm1/.psd1
    base name). Must start with a letter or digit and contain only letters,
    digits, dots, dashes, or underscores - this blocks path-traversal values
    such as ".." or names containing \ or /.

.PARAMETER OutputPath
    Folder under which the "<ModuleName>" module folder will be created.
    Defaults to a "Modules" folder alongside -SourcePath's parent directory.

.PARAMETER ModuleVersion
    Version to stamp into the .psd1 manifest. Default: "1.0.0".

.PARAMETER Author
    Author name stamped into the .psd1 manifest. Default: "Lakshmanan Thangaraj".
    Override this when building a module on someone else's behalf - the default
    reflects this toolkit's primary maintainer, not a requirement.

.PARAMETER Description
    Short description stamped into the .psd1 manifest.

.PARAMETER ProjectUri
    Optional. URL of the project/repository to stamp into the manifest's
    PSData block. Left blank by default - no project is assumed.

.PARAMETER Tags
    Optional. Tags to stamp into the manifest's PSData block. Default:
    'PowerShell', 'Module'.

.PARAMETER Recurse
    If specified, also scans subfolders of -SourcePath for .ps1 files.

.PARAMETER Force
    If specified, deletes and rebuilds an existing module folder of the same name.
    Without this switch, the function refuses to overwrite an existing module folder.
    When rebuilding, the module's original GUID is preserved (see .DESCRIPTION).

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    PSCustomObject with properties: ModuleName, ModulePath, PSM1Path, PSD1Path,
    ModuleGuid, FunctionCount, Functions, SkippedFiles.

.EXAMPLE
    New-PSModuleFromScripts -SourcePath "D:\Github Repository Backup\Azure-Resource-Scripts\Azure RBAC" `
        -ModuleName "MyAzureRBACTools" `
        -OutputPath "D:\PowerShell-Modules" `
        -ProjectUri "https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit" `
        -Tags @('Azure', 'RBAC', 'Governance')

    Builds "D:\PowerShell-Modules\MyAzureRBACTools\MyAzureRBACTools.psm1/.psd1"
    from every .ps1 script in the "Azure RBAC" folder, with project metadata
    stamped into the manifest.

.EXAMPLE
    New-PSModuleFromScripts -SourcePath "D:\Github Repository Backup\PowerShell-Scripts\Entra ID\My Modules" `
        -ModuleName "MyEntraIDTools" `
        -ModuleVersion "2.1.0" `
        -Force

    Rebuilds the "MyEntraIDTools" module (overwriting any previous build) from the
    "Entra ID\My Modules" folder, stamping version 2.1.0 into the manifest while
    preserving the module's original GUID from the prior build.

.EXAMPLE
    $result = New-PSModuleFromScripts -SourcePath ".\MyScripts" -ModuleName "Toolbox" -Recurse
    Import-Module $result.PSD1Path -Force
    Get-Command -Module Toolbox

    Builds the module (including subfolders), immediately imports it, and lists the
    functions that were exported.

.EXAMPLE
    New-PSModuleFromScripts -SourcePath "C:\Users\Lakshmanan\Desktop\CloudIdentityToolkit.Common\" `
        -ModuleName "CloudIdentityToolkit.Common" `
        -OutputPath "C:\Users\Lakshmanan\Desktop\" `
        -Author "Lakshmanan Thangaraj" `
        -Description "Shared console output and logging toolkit (Write-Banner, Write-SectionHeader, Write-Info, Write-Success, Write-Failure, Add-Log) reused across the Cloud-Identity-Toolkit script library."

    Real-world usage: builds the shared console-output toolkit module from its
    source folder, stamping a custom -Author and a descriptive -Description into
    the generated .psd1 manifest.

.EXAMPLE
    New-PSModuleFromScripts -SourcePath ".\MyScripts" -ModuleName "Toolbox" -WhatIf

    Dry-run: shows what module folder would be built and where, without actually
    copying files or writing the .psm1/.psd1 - useful for verifying -OutputPath
    and -ModuleName before committing to a real build.

.EXAMPLE
    New-PSModuleFromScripts -SourcePath ".\MyScripts" -ModuleName "Toolbox" -Recurse -Verbose

    Runs with full narration - shows validation steps, per-file AST parsing
    progress, and a final [SUCCESS]/function-count summary. Useful when
    troubleshooting why a function wasn't discovered or exported.

.EXAMPLE
    $result = New-PSModuleFromScripts -SourcePath ".\MyScripts" -ModuleName "Toolbox" -Force
    if ($result.SkippedFiles.Count -gt 0)
    {
        Write-Warning "Files with no functions found: $($result.SkippedFiles -join ', ')"
    }

    Shows how to inspect the returned object after a build - specifically
    -SkippedFiles, which lists any .ps1 files that were copied into the module
    but contained no discoverable function definitions (e.g. pure script files,
    config files, or files with parse errors).

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.2 (27-Jul-2026) - Security/hardening pass: validated -ModuleName against a
                         safe character set to close a path-traversal risk;
                         added a SourcePath/module-folder overlap guard to
                         prevent -Force from deleting source scripts; replaced
                         the hardcoded shared GUID with a per-module GUID that
                         is generated once and preserved across rebuilds;
                         rejected unsafe characters in -Author/-Description
                         (embedded quotes, line breaks, here-string
                         terminators); switched .psd1 generation to the real
                         New-ModuleManifest cmdlet instead of a hand-rolled
                         string template; added -ProjectUri/-Tags parameters
                         instead of hardcoding project metadata; added
                         .INPUTS/.OUTPUTS/.LINK sections.
    1.1 (23-Jul-2026)  - Expanded .EXAMPLE section: added -WhatIf dry-run,
                         -Verbose narration, real-world CloudIdentityToolkit.Common
                         build, and -SkippedFiles inspection examples.
    1.0 (08-Jul-2026)  - Initial release.
    
    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. PowerShell 5.1+ (uses System.Management.Automation.Language.Parser and
       New-ModuleManifest, both available since PS 5.0/5.1).
    2. Write access to -OutputPath.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
    Step 1 → Validate inputs; confirm SourcePath/module-folder don't overlap
    Step 2 → If rebuilding (-Force), read the GUID from the prior .psd1
    Step 3 → Create the module folder structure; copy .ps1 files into .\Public
    Step 4 → Parse each file's AST to discover function names
    Step 5 → Generate the .psm1 loader/exporter
    Step 6 → Generate the .psd1 manifest via New-ModuleManifest
    Step 7 → Return a summary object (path, GUID, function list, skipped files)
    
    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - The generated .psm1 dot-sources and executes every .ps1 file in its Public
      folder at Import-Module time. Only build modules from source folders you
      trust - this tool does not scan script contents for malicious code, only
      for function definitions.
    - Console Output: Uses Write-Verbose for progress narration (visible with
      -Verbose), Write-Progress for the per-file loop, and Write-Warning for
      non-fatal issues (duplicate function names, files with no functions
      found, unreadable prior GUID). No dependency on the shared console
      toolkit.
    - The generated module is not code-signed; if your environment enforces an
      execution policy requiring signed scripts, you'll need to sign it
      separately after generation.
    - -Author defaults to this toolkit's maintainer name - override it when
      generating a module for someone else.

.LINK
    about_Module_Manifests
    https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_module_manifests

.LINK
    New-ModuleManifest reference
    https://learn.microsoft.com/powershell/module/microsoft.powershell.core/new-modulemanifest

#>


Function New-PSModuleFromScripts
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$SourcePath,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]*$')]
        [string]$ModuleName,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [string]$ModuleVersion = '1.0.0',

        [Parameter(Mandatory = $false)]
        [string]$Author = 'Lakshmanan Thangaraj',

        [Parameter(Mandatory = $false)]
        [string]$Description = 'Custom PowerShell function library.',

        [Parameter(Mandatory = $false)]
        [string]$ProjectUri,

        [Parameter(Mandatory = $false)]
        [string[]]$Tags = @('PowerShell', 'Module'),

        [Parameter(Mandatory = $false)]
        [switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    Begin {
        if (-not $OutputPath) {
            $parentOfSource = Split-Path -Path (Resolve-Path -Path $SourcePath -ErrorAction Stop) -Parent
            $OutputPath = Join-Path -Path $parentOfSource -ChildPath 'Modules'
        }

        # Reject values that could corrupt the generated manifest (embedded
        # quotes are fine - New-ModuleManifest escapes those correctly - but
        # line breaks and here-string terminators are not safe to interpolate
        # anywhere in this function's own string building).
        foreach ($fieldName in @('Author', 'Description')) {
            $fieldValue = Get-Variable -Name $fieldName -ValueOnly
            if ($fieldValue -match '"@|''@|\r|\n') {
                throw "-$fieldName contains characters that are not allowed (line breaks, or the here-string terminator sequences `"@ / '@). Remove them and try again."
            }
        }

        Write-Verbose -Message "=== New-PSModuleFromScripts : Building module '$ModuleName' ==="
    }

    Process {
        try {
            Write-Verbose -Message '--- Validation ---'

            if (-not (Test-Path -Path $SourcePath)) {
                throw "Source path '$SourcePath' does not exist."
            }

            $resolvedSource = (Resolve-Path -Path $SourcePath -ErrorAction Stop).Path.TrimEnd('\', '/')

            $getChildItemParams = @{
                Path        = $SourcePath
                Filter      = '*.ps1'
                ErrorAction = 'Stop'
            }
            if ($Recurse) {
                $getChildItemParams['Recurse'] = $true
            }

            $scriptFiles = Get-ChildItem @getChildItemParams | Sort-Object -Property Name

            if (-not $scriptFiles) {
                throw "No .ps1 files found in '$SourcePath'."
            }

            Write-Verbose -Message "[INFO] Found $($scriptFiles.Count) script file(s) to process."

            $moduleFolder = (Join-Path -Path $OutputPath -ChildPath $ModuleName).TrimEnd('\', '/')
            $publicFolder = Join-Path -Path $moduleFolder -ChildPath 'Public'

            # Safety guard: refuse to proceed if the module folder we're about
            # to (re)build is the same as, or nested inside/around, the
            # source folder. Without this, -Force would delete SourcePath's
            # scripts before they've been copied.
            if ($resolvedSource -ieq $moduleFolder -or
                $resolvedSource.StartsWith("$moduleFolder\", [System.StringComparison]::OrdinalIgnoreCase) -or
                $moduleFolder.StartsWith("$resolvedSource\", [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "The computed module folder ('$moduleFolder') overlaps with -SourcePath ('$resolvedSource'). Choose a different -ModuleName/-OutputPath - this guard exists so -Force can never delete your source scripts."
            }

            if ((Test-Path -Path $moduleFolder) -and -not $Force) {
                throw "Module folder '$moduleFolder' already exists. Re-run with -Force to rebuild it."
            }

            # If we're rebuilding an existing module, preserve its original
            # GUID rather than stamping a new identity on every rebuild.
            $moduleGuid = $null
            $priorPsd1Path = Join-Path -Path $moduleFolder -ChildPath "$ModuleName.psd1"
            if (Test-Path -Path $priorPsd1Path) {
                try {
                    $priorManifest = Import-PowerShellDataFile -Path $priorPsd1Path -ErrorAction Stop
                    if ($priorManifest.GUID) {
                        $moduleGuid = $priorManifest.GUID
                        Write-Verbose -Message "[INFO] Reusing existing module GUID from prior build: $moduleGuid"
                    }
                }
                catch {
                    Write-Warning -Message "Could not read GUID from existing manifest at '$priorPsd1Path' - a new GUID will be generated instead. Details: $($_.Exception.Message)"
                }
            }
            if (-not $moduleGuid) {
                $moduleGuid = [guid]::NewGuid().ToString()
                Write-Verbose -Message "[INFO] Generated new module GUID: $moduleGuid"
            }

            if (-not $PSCmdlet.ShouldProcess($moduleFolder, 'Build PowerShell module')) {
                return
            }

            Write-Verbose -Message '--- Preparing Module Folder ---'

            if (Test-Path -Path $moduleFolder) {
                Remove-Item -Path $moduleFolder -Recurse -Force
            }
            New-Item -Path $publicFolder -ItemType Directory -Force | Out-Null

            Write-Verbose -Message '--- Discovering Functions (AST Parse) ---'

            $allFunctionNames = New-Object -TypeName System.Collections.Generic.List[string]
            $fileCounter = 0
            $filesWithNoFunctions = New-Object -TypeName System.Collections.Generic.List[string]

            foreach ($file in $scriptFiles) {
                $fileCounter++
                $percentComplete = [int](($fileCounter / $scriptFiles.Count) * 100)
                Write-Progress -Activity 'Building module' -Status "Processing $($file.Name)" -PercentComplete $percentComplete
                Write-Verbose -Message "[$fileCounter/$($scriptFiles.Count)] Processing $($file.Name)"

                # Copy the script as-is into the module's Public folder
                Copy-Item -Path $file.FullName -Destination (Join-Path -Path $publicFolder -ChildPath $file.Name) -Force

                $parseTokens = $null
                $parseErrors = $null
                $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$parseTokens, [ref]$parseErrors)

                if ($parseErrors -and $parseErrors.Count -gt 0) {
                    Write-Warning -Message "Parse warning in $($file.Name): $($parseErrors[0].Message) - file was still copied, but review it manually."
                }

                $functionAsts = $scriptAst.FindAll(
                    { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] },
                    $true
                )

                if ($functionAsts.Count -eq 0) {
                    $filesWithNoFunctions.Add($file.Name)
                    continue
                }

                foreach ($functionAst in $functionAsts) {
                    if ($allFunctionNames -contains $functionAst.Name) {
                        Write-Warning -Message "Duplicate function name '$($functionAst.Name)' found in $($file.Name) - it will only be exported once."
                    }
                    else {
                        $allFunctionNames.Add($functionAst.Name)
                    }
                }
            }

            Write-Progress -Activity 'Building module' -Completed

            if ($filesWithNoFunctions.Count -gt 0) {
                Write-Warning -Message "The following file(s) contained no function definitions (copied but not exported): $($filesWithNoFunctions -join ', ')"
            }

            if ($allFunctionNames.Count -eq 0) {
                throw 'No functions were discovered across the source scripts. Aborting module build.'
            }

            $sortedFunctionNames = @($allFunctionNames | Sort-Object -Unique)

            Write-Verbose -Message '--- Generating .psm1 ---'

            $psm1Path = Join-Path -Path $moduleFolder -ChildPath "$ModuleName.psm1"
            $exportListLines = ($sortedFunctionNames | ForEach-Object { "    '$_'" }) -join ",`n"

            $psm1Content = @"
#Requires -Version 5.1

<#
Author       : $Author
Version      : $ModuleVersion
Created-On   : $(Get-Date -Format 'dd MMMM yyyy')
Modified-On  : $(Get-Date -Format 'dd MMMM yyyy')

.SYNOPSIS
    Module loader for $ModuleName - auto-generated from PowerShell function scripts.

.DESCRIPTION
    This file automatically dot-sources every function script (*.ps1) found
    in this module's Public folder, then exposes the approved list of functions to
    anyone who runs Import-Module $ModuleName.

    It does not contain any function logic itself - each function still
    lives in its own .ps1 file, exactly as before. This file only wires
    them together into a proper, importable module.

.NOTES
    CHANGELOG:
        v$ModuleVersion - $(Get-Date -Format 'dd MMMM yyyy') - Module wrapper (re)generated by New-PSModuleFromScripts.
#>

`$FunctionScripts = Get-ChildItem -Path `$PSScriptRoot -Filter '*.ps1' -File -Recurse

foreach (`$ScriptFile in `$FunctionScripts)
{
    try
    {
        . `$ScriptFile.FullName
    }
    catch
    {
        Write-Error "Failed to load `$(`$ScriptFile.Name): `$(`$_.Exception.Message)"
    }
}

Export-ModuleMember -Function @(
$exportListLines
)
"@

            Set-Content -Path $psm1Path -Value $psm1Content -Encoding UTF8

            Write-Verbose -Message '--- Generating .psd1 (via New-ModuleManifest) ---'

            $psd1Path = Join-Path -Path $moduleFolder -ChildPath "$ModuleName.psd1"

            $manifestParams = @{
                Path              = $psd1Path
                RootModule        = "$ModuleName.psm1"
                ModuleVersion     = $ModuleVersion
                Guid              = $moduleGuid
                Author            = $Author
                CompanyName       = $Author
                Copyright         = "(c) $(Get-Date -Format 'yyyy') $Author. All rights reserved."
                Description       = $Description
                PowerShellVersion = '5.1'
                FunctionsToExport = $sortedFunctionNames
                CmdletsToExport   = @()
                VariablesToExport = @()
                AliasesToExport   = @()
                Tags              = $Tags
            }
            if ($ProjectUri) {
                $manifestParams['ProjectUri'] = $ProjectUri
            }

            New-ModuleManifest @manifestParams

            Write-Verbose -Message "[SUCCESS] Module '$ModuleName' built successfully at: $moduleFolder"
            Write-Verbose -Message "[INFO] Exported function count: $($sortedFunctionNames.Count)"
            Write-Verbose -Message "[INFO] Module GUID: $moduleGuid"

            [PSCustomObject]@{
                ModuleName    = $ModuleName
                ModulePath    = $moduleFolder
                PSM1Path      = $psm1Path
                PSD1Path      = $psd1Path
                ModuleGuid    = $moduleGuid
                FunctionCount = $sortedFunctionNames.Count
                Functions     = $sortedFunctionNames
                SkippedFiles  = $filesWithNoFunctions
            }
        }
        catch {
            Write-Progress -Activity 'Building module' -Completed
            Write-Warning -Message "Module build failed: $($_.Exception.Message)"
            throw
        }
    }

    End {
        Write-Verbose -Message '[INFO] New-PSModuleFromScripts completed.'
    }
}
