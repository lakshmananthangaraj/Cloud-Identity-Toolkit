#Requires -Version 5.1

<#
.Author
    Name        : Lakshmanan Thangaraj
    Version     : 1.0
    Created-On  : 05 July 2026
    Modified-On : 05 July 2026

.SYNOPSIS
    Module loader for CloudIdentityToolkit.Common — the shared console output
    and logging toolkit used across all Cloud-Identity-Toolkit scripts.

.DESCRIPTION
    This file automatically dot-sources every function script (*.ps1) found
    in this module's folder, then exposes the approved list of functions to
    anyone who runs Import-Module CloudIdentityToolkit.Common.

    It does not contain any function logic itself — each function still
    lives in its own .ps1 file, exactly as before. This file only wires
    them together into a proper, importable module.

.NOTES
    CHANGELOG:
        v1.0 - 05 July 2026 - Initial module wrapper created. Wraps existing
                              Write-Banner, Write-SectionHeader, Write-Info,
                              Write-Success, Write-Failure, and Add-Log
                              scripts into an importable module.
#>

$FunctionScripts = Get-ChildItem -Path $PSScriptRoot -Filter '*.ps1' -File

foreach ($ScriptFile in $FunctionScripts)
{
    try
    {
        . $ScriptFile.FullName
        Write-Verbose "Loaded function script: $($ScriptFile.Name)"
    }
    catch
    {
        Write-Error "Failed to load $($ScriptFile.Name): $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function @(
    'Write-Banner',
    'Write-SectionHeader',
    'Write-Info',
    'Write-Success',
    'Write-Failure',
    'Add-Log'
)
