<#

.Author
    Name        : Lakshmanan Thangaraj
    Version     : 1.1
    Created-On  : 18 March 2025
    Modified-On : 06 July 2026

.SYNOPSIS
    Decodes a JWT (JSON Web Token) and returns its Header and Payload claims as a single object.

.DESCRIPTION
    JWT decoder utility for PowerShell (inspection only, no validation)
    ConvertFrom-JwtToken splits a JWT into its three dot-separated segments (Header, Payload,
    Signature), Base64Url-decodes the Header and Payload segments, converts them from JSON,
    and returns a single PSCustomObject containing the Header (nested under "JWTHeader") and
    all Payload claims flattened to the top level.

    IMPORTANT SECURITY NOTE:
    This function only DECODES the token — it does NOT verify the signature and does NOT
    confirm the token is authentic, unexpired, or issued by a trusted authority. Anyone can
    forge the Header/Payload of a JWT; only signature verification against the issuer's
    public key (or shared secret) proves a token is genuine. Use this function for
    troubleshooting/inspection only, never as a substitute for proper token validation.

    Also be mindful that decoded claims can contain sensitive information (user identifiers,
    scopes, tenant IDs, etc.). Avoid pasting production access tokens into shared consoles,
    logs, or public gists.

.PARAMETER Token
    The JWT string to decode (e.g., an OAuth2/Entra ID access token or ID token). Mandatory
    unless -Help is specified.

.PARAMETER Help
    Displays a plain-language, beginner-friendly walkthrough of this function directly in the
    console — what it does, how to use it, and a couple of worked examples. This is aimed at
    anyone downloading the script from GitHub who may not be familiar with PowerShell's
    Get-Help convention. For the exhaustive technical reference (full parameter details,
    requirements, version history), run "Get-Help ConvertFrom-JwtToken -Full" instead — that
    content is maintained separately in this comment-based help block.

.EXAMPLE
    ConvertFrom-JwtToken -Token $AccessToken | Format-List

    Decodes the token and displays the Header and all Payload claims.

.EXAMPLE
    $claims = ConvertFrom-JwtToken -Token $AccessToken
    $claims.upn

    Stores the decoded result and reads a specific claim (e.g., User Principal Name).

.EXAMPLE
    ConvertFrom-JwtToken -Help

    Prints a friendly, plain-language explanation of the function to the console.
    No decoding is performed when -Help is used.

.NOTES
    Requirements   : PowerShell 5.1 or later. No external modules required.
    Limitations    : Does NOT validate the token signature, expiry, issuer, or audience.
                        Decoding only — treat output as untrusted until independently verified.
    Naming history : Supersedes the earlier "Decode-JWTToken" function. "Decode" is not an
                        approved PowerShell verb. Named "ConvertFrom" (rather than "Get") because
                        the function transforms data you already have (an existing token string)
                        into another representation — it does not retrieve/fetch a resource from
                        a system or service, which is what "Get" implies. This matches the pattern
                        used by ConvertFrom-Json, ConvertFrom-Csv, and ConvertFrom-SecureString.
    Getting help   : Two help paths are available and intentionally kept in sync manually:
                        1) "ConvertFrom-JwtToken -Help"        -> plain-language walkthrough
                            (this .NOTES/.SYNOPSIS content, re-worded for a general audience)
                        2) "Get-Help ConvertFrom-JwtToken -Full" -> full technical reference
                            (this comment-based help block, verbatim)
                        If you update the behaviour of this function, update BOTH the comment-
                        based help above and the -Help console output below.

    CHANGELOG:
        v1.1 - 06 July 2026  - Added -Help switch parameter to provide a plain-language usage guide directly in the console.
                                 Introduced a user-friendly walkthrough designed for non-technical and first-time users.
                                 Help output is built using the shared console output toolkit (Write-Banner, Write-SectionHeader, Write-Info, Write-Success) for consistent formatting.
                                 Existing comment-based help remains unchanged; Get-Help -Full continues to provide the complete technical reference.
                                 No changes were made to the core JWT decoding logic or functionality.
        v1.0 - 18 March 2025 - Renamed from the interim "Get-JWTTokenDetails" working name to
                                 the semantically correct "ConvertFrom-JwtToken" prior to
                                 publication. Carries forward all v1.0 hardening from the
                                 original Decode-JWTToken rewrite: comment-based help, Author
                                 block, CmdletBinding, ValidateNotNullOrEmpty, Try/Catch error
                                 handling, PSCustomObject output, and an explicit
                                 signature-validation warning.

#>

Function ConvertFrom-JwtToken
{
    [CmdletBinding(DefaultParameterSetName = 'Decode')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Decode')]
        [ValidateNotNullOrEmpty()]
        [string]$Token,

        [Parameter(ParameterSetName = 'Help')]
        [switch]$Help
    )

    if ($Help)
    {
        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host " ConvertFrom-JwtToken " -ForegroundColor Cyan
        Write-Host " A plain-language guide to reading JWT tokens " -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host ""

        Write-Host "WHAT THIS TOOL DOES" -ForegroundColor Yellow
        Write-Host "A JWT (JSON Web Token) is a small text package that systems like Microsoft Entra ID use to carry information about a signed-in user or application - for example, who they are and what they are allowed to do."
        Write-Host "This tool opens that package so you can read what is inside, laid out in a clean and organized way."
        Write-Host ""

        Write-Host "PLEASE KEEP THIS IN MIND" -ForegroundColor Yellow
        Write-Host "This tool only reads the contents of the token. It does not check whether the token is genuine, expired, or came from a trusted source."
        Write-Host "Think of it like reading a shipping label on a box, not verifying whether the box was tampered with."
        Write-Host "Signature validation is a separate process and is intentionally not included here."
        Write-Host ""

        Write-Host "HOW TO USE IT" -ForegroundColor Yellow
        Write-Host "Step 1: Load the script into your session (dot source it):"
        Write-Host "        . .\ConvertFrom-JwtToken.ps1"
        Write-Host "Step 2: Run the function with a token:"
        Write-Host "        ConvertFrom-JwtToken -Token `$AccessToken"
        Write-Host ""

        Write-Host "EXAMPLES" -ForegroundColor Yellow
        Write-Host "Example 1 - Display full token contents:"
        Write-Host "  ConvertFrom-JwtToken -Token `$AccessToken | Format-List"
        Write-Host ""
        Write-Host "Example 2 - Read a specific claim (e.g., user identity):"
        Write-Host "  `$claims = ConvertFrom-JwtToken -Token `$AccessToken"
        Write-Host "  `$claims.upn"
        Write-Host ""

        Write-Host "LOOKING FOR FULL HELP?" -ForegroundColor Yellow
        Write-Host "Run: Get-Help ConvertFrom-JwtToken -Full"
        Write-Host "This shows complete parameter details and technical reference."
        Write-Host ""

        Write-Host "Done. Happy decoding!" -ForegroundColor Green
        Write-Host ""

        return
    }

    Try
    {
        Write-Verbose "Splitting JWT into Header / Payload / Signature segments."
        $TokenParts = $Token -split '\.'

        if ($TokenParts.Length -lt 2)
        {
            Write-Error "Invalid JWT Token Format. Expected at least 2 dot-separated segments (Header.Payload)."
            return
        }

        Function Convert-FromBase64Url
        {
            param ([Parameter(Mandatory = $true)][string]$Base64Url)

            $Base64 = $Base64Url.Replace('-', '+').Replace('_', '/')
            switch ($Base64.Length % 4)
            {
                2 { $Base64 += '==' }
                3 { $Base64 += '=' }
            }
            return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Base64))
        }

        Write-Verbose "Decoding Header segment."
        $JWTHeader = Convert-FromBase64Url $TokenParts[0] | ConvertFrom-Json

        Write-Verbose "Decoding Payload segment."
        $JWTPayload = Convert-FromBase64Url $TokenParts[1] | ConvertFrom-Json

        # Build an ordered result: JWTHeader first, then all payload claims flattened.
        # "JWTHeader" (rather than "Header") avoids colliding with a payload claim
        # that might itself be named "Header".
        $Result = [ordered]@{
            JWTHeader = $JWTHeader
        }

        $JWTPayload.PSObject.Properties | ForEach-Object {
            if ($Result.Contains($_.Name))
            {
                Write-Verbose "Claim '$($_.Name)' collides with an existing key; it will be overwritten."
            }
            $Result[$_.Name] = $_.Value
        }

        return [PSCustomObject]$Result
    }
    Catch
    {
        Write-Error "Failed to decode JWT Token. $($_.Exception.Message)"
    }
}
