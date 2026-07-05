<#

.SYNOPSIS
    Writes structured and formatted log entries to a text file.

.DESCRIPTION
    The Add-Log function is a reusable logging utility designed to generate
    structured, readable logs for PowerShell scripts. It supports multiple
    log levels, section headers, and a detailed execution header block.

    The function automatically:
    - Creates the log directory if it does not exist
    - Adds timestamps to each log entry
    - Formats output consistently
    - Supports structured sections and execution metadata

.PARAMETER LogPath
    Specifies the full file path where the log will be written.
    If the directory does not exist, it will be created automatically.

.PARAMETER LogType
    Defines the type of log entry.

    Valid values:
    - INFO     : General information
    - SUCCESS  : Successful operation
    - WARNING  : Non-critical issue
    - ERROR    : Critical failure
    - SECTION  : Section header
    - HEADER   : Script execution header

    Default value is INFO.

.PARAMETER Message
    The message content to be written to the log.
    Not required for SECTION or HEADER types.

.PARAMETER Section
    The name of the section when LogType is 'SECTION'.

.PARAMETER NewLineBefore
    Adds an empty line before the log entry.

.PARAMETER NewLineAfter
    Adds an empty line after the log entry.

.PARAMETER Title
    Title of the script (used only when LogType = HEADER).

.PARAMETER Purpose
    Description of the script purpose (used in HEADER).

.PARAMETER Environment
    Environment name (e.g., Dev, Test, Production).

.PARAMETER TenantInfo
    Tenant or organizational context information.

.PARAMETER OutputFormat
    Specifies the log output format (default: Plain Text).

.EXAMPLE
    # --- Example 1: Write a script header at the start of a new log file ---

    $logFile = "C:\Logs\AppSecrets.txt"

    Add-Log -LogPath $logFile -LogType 'HEADER' `
        -Title       "App Registration Secrets Expiration Notification" `
        -Purpose     "Detect and notify about expiring App Secrets in Entra ID" `
        -Environment "Production" `
        -TenantInfo  "Contoso | contoso.onmicrosoft.com" `
        -OutputFormat "Plain Text (.txt)"

    # Output written to log file:
    #
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔐 Script Log      : App Registration Secrets Expiration Notification
    # 📅 Execution Time  : 2025-06-01 09:30:00
    # 👨‍💻 Executed By     : johndoe
    # 💼 Environment     : Production
    # 🧭 Tenant Info     : Contoso | contoso.onmicrosoft.com
    # 📨 Purpose         : Detect and notify about expiring App Secrets in Entra ID
    # 📁 Log File Path   : C:\Logs\AppSecrets.txt
    # 📊 Output Format   : Plain Text (.txt)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

.EXAMPLE
    # --- Example 2: Write a section separator ---

    Add-Log -LogPath "C:\Logs\AppSecrets.txt" -LogType 'SECTION' -Section "Initialization Phase"

    # Output written to log file:
    # ---------------------- 🔹 Initialization Phase ----------------------

.EXAMPLE
    # --- Example 3: Write standard log entries (INFO, SUCCESS, WARNING, ERROR) ---

    $logFile = "C:\Logs\AppSecrets.txt"

    Add-Log -LogPath $logFile -LogType 'INFO'    -Message "Connecting to Azure tenant..."
    Add-Log -LogPath $logFile -LogType 'SUCCESS' -Message "Connected to Azure tenant successfully."
    Add-Log -LogPath $logFile -LogType 'WARNING' -Message "Contributor role detected; Owner role recommended."
    Add-Log -LogPath $logFile -LogType 'ERROR'   -Message "Failed to retrieve 'MyApp01' due to timeout."

    # Output written to log file:
    # [09:31:02] [INFO]      Connecting to Azure tenant...
    # [09:31:03] [SUCCESS]   Connected to Azure tenant successfully.
    # [09:31:03] [WARNING]   Contributor role detected; Owner role recommended.
    # [09:31:04] [ERROR]     Failed to retrieve 'MyApp01' due to timeout.

.EXAMPLE
    # --- Example 4: Insert blank lines for readability ---

    $logFile = "C:\Logs\AppSecrets.txt"

    Add-Log -LogPath $logFile -LogType 'SUCCESS' -Message "Phase 1 complete." -NewLineAfter
    Add-Log -LogPath $logFile -LogType 'SECTION' -Section "Notification Phase"

    # Calling with no parameters other than LogPath also inserts a blank line:
    Add-Log -LogPath $logFile

.EXAMPLE
    # --- Example 5: Full multi-phase script logging workflow ---

    $logFile = "C:\Logs\AppSecrets.txt"

    # Header
    Add-Log -LogPath $logFile -LogType 'HEADER' `
        -Title "App Secrets Expiration Notification" -Purpose "Notify owners of expiring secrets" `
        -Environment "Production" -TenantInfo "Contoso | contoso.onmicrosoft.com"

    Add-Log -LogPath $logFile

    # Phase 1 – Initialization
    Add-Log -LogPath $logFile -LogType 'SECTION' -Section "Initialization Phase"
    Add-Log -LogPath $logFile -LogType 'SUCCESS' -Message "Script started successfully."
    Add-Log -LogPath $logFile -LogType 'INFO'    -Message "Loading required modules..."
    Add-Log -LogPath $logFile -LogType 'SUCCESS' -Message "Modules imported: Az.Accounts, Az.Resources."

    Add-Log -LogPath $logFile

    # Phase 2 – Data Retrieval
    Add-Log -LogPath $logFile -LogType 'SECTION' -Section "Data Retrieval Phase"
    Add-Log -LogPath $logFile -LogType 'INFO'    -Message "Fetching app registrations from Entra ID..."
    Add-Log -LogPath $logFile -LogType 'ERROR'   -Message "Timeout retrieving 'MyApp01'. Skipping."
    Add-Log -LogPath $logFile -LogType 'WARNING' -Message "Secret expiration date missing for 'LegacyApp'."
    Add-Log -LogPath $logFile -LogType 'SUCCESS' -Message "Retrieved secrets for 25 app registrations."

    Add-Log -LogPath $logFile

    # Phase 3 – Notifications
    Add-Log -LogPath $logFile -LogType 'SECTION' -Section "Notification Phase"
    Add-Log -LogPath $logFile -LogType 'INFO'    -Message "Sending notification emails to app owners..."
    Add-Log -LogPath $logFile -LogType 'ERROR'   -Message "SMTP failure for user@example.com."
    Add-Log -LogPath $logFile -LogType 'SUCCESS' -Message "Emails sent to 24 recipients."

    Add-Log -LogPath $logFile

    # Phase 4 – Cleanup
    Add-Log -LogPath $logFile -LogType 'SECTION' -Section "Cleanup Phase"
    Add-Log -LogPath $logFile -LogType 'SUCCESS' -Message "Temporary files removed."
    Add-Log -LogPath $logFile -LogType 'SUCCESS' -Message "Disconnected from Azure session."
    Add-Log -LogPath $logFile -LogType 'SUCCESS' -Message "Script completed successfully."

    Add-Log -LogPath $logFile -NewLineAfter

.NOTES
    This function is designed for reusable logging across automation scripts,
    especially for Azure, Entra ID, and infrastructure workflows.

#>

Function Add-Log
{
    param (
        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [Parameter()]
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'SECTION', 'HEADER')]
        [string]$LogType = 'INFO',

        [Parameter()]
        [string]$Message,

        [Parameter()]
        [string]$Section,

        [Parameter()]
        [switch]$NewLineBefore,

        [Parameter()]
        [switch]$NewLineAfter,

        # Header-specific optional fields
        [string]$Title = "Untitled Script",
        [string]$Purpose = "Describe the purpose here",
        [string]$Environment = "N/A",
        [string]$TenantInfo = "N/A",
        [string]$OutputFormat = "Plain Text (.txt)"
    )

    # Ensure log directory exists
    $folder = Split-Path $LogPath
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }

    # Handle spacing
    if ($NewLineBefore) { Add-Content -Path $LogPath -Value "" }

    # HEADER Block
    if ($LogType -eq 'HEADER') {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $ShortTime = Get-Date -Format "HH:mm:ss"
        $ExecutedBy = $env:USERNAME

        $Header = @"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 Script Log      : $Title
📅 Execution Time  : $Timestamp
👨‍💻 Executed By     : $ExecutedBy
💼 Environment     : $Environment
🧭 Tenant Info     : $TenantInfo
📨 Purpose         : $Purpose
📁 Log File Path   : $LogPath
📊 Output Format   : $OutputFormat
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"@
        $Header | Out-File -FilePath $LogPath -Encoding utf8 -Force
        # "[$ShortTime] [SUCCESS]  Logging started..." | Out-File -FilePath $LogPath -Append
        return
    }

    # SECTION Block
    if ($LogType -eq 'SECTION') {
        $sectionBlock = @"
---------------------- 🔹 $Section ----------------------
"@
        Add-Content -Path $LogPath -Value $sectionBlock
        return
    }

    # Handle empty lines even if no message is supplied
    if ([string]::IsNullOrWhiteSpace($Message)) {
        if ($NewLineBefore) {
            Add-Content -Path $LogPath -Value ""
        }

        if ($NewLineAfter) {
            Add-Content -Path $LogPath -Value ""
        }

        # If no NewLine switches but no message, add single empty line by default
        if (-not $NewLineBefore -and -not $NewLineAfter) {
            Add-Content -Path $LogPath -Value ""
        }
        return
    }

    # Log Entry
    $timestamp = Get-Date -Format "HH:mm:ss"
    $label = ("[$LogType]").PadRight(10)
    $logLine = "[$timestamp] $label $Message"
    Add-Content -Path $LogPath -Value $logLine

    if ($NewLineAfter) { Add-Content -Path $LogPath -Value "" }
}
