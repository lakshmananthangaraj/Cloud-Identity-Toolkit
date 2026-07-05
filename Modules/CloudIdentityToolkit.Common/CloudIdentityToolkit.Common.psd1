#
# Module manifest for module 'CloudIdentityToolkit.Common'
#
# Author       : Lakshmanan Thangaraj
# Version      : 1.0
# Created-On   : 05 July 2026
# Modified-On  : 05 July 2026
#
# CHANGELOG:
#   v1.0 - 05 July 2026 - Initial manifest created for CloudIdentityToolkit.Common.
#

@{
    RootModule        = 'CloudIdentityToolkit.Common.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '792b3db0-04b6-4e69-8408-1d94ed1ea22d'
    Author            = 'Lakshmanan Thangaraj'
    CompanyName       = 'Lakshmanan Thangaraj'
    Copyright         = '(c) 2026 Lakshmanan Thangaraj. All rights reserved.'
    Description       = 'Shared console output and logging toolkit (Write-Banner, Write-SectionHeader, Write-Info, Write-Success, Write-Failure, Add-Log) reused across the Cloud-Identity-Toolkit script library.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Write-Banner',
        'Write-SectionHeader',
        'Write-Info',
        'Write-Success',
        'Write-Failure',
        'Add-Log'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags       = @('EntraID', 'Azure', 'Logging', 'Console', 'CloudIdentityToolkit')
            ProjectUri = 'https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit'
        }
    }
}
