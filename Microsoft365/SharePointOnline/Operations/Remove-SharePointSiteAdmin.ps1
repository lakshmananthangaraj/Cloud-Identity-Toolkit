<#

Author       : Lakshmanan Thangaraj
Version      : 1.0
Created-On   : 01 August 2026
Modified-On  : 01 August 2026

.SYNOPSIS
    Removes one or more users as Site Collection Administrators from
    SharePoint Online sites.

.DESCRIPTION
    Connects to the SharePoint Online tenant admin center via the
    SharePoint Online Management Shell (Connect-SPOService) and revokes
    Site Collection Administrator rights using Set-SPOUser. Checks current
    state first and skips sites where the user is already not an admin
    (idempotent). Refuses to remove the last remaining Site Collection
    Administrator from a site unless -Force is supplied, to avoid
    accidentally locking a site with no administrators. Supports
    -WhatIf/-Confirm since this is a permission-changing operation.
    Always returns a full audit-trail report to the console/pipeline; CSV
    export is optional. Designed to complement Add-SharePointSiteAdmin.ps1
    for temporary/task-based access elevation and cleanup.

.PARAMETER TenantAdminUrl
    Mandatory. The SharePoint Online tenant admin center URL, e.g.
    'https://contoso-admin.sharepoint.com'.

.PARAMETER UserPrincipalName
    Mandatory. One or more user principal names (UPNs) / email addresses
    to remove Site Collection Administrator rights from.

.PARAMETER SiteUrl
    Optional. One or more specific site URLs to apply the change to.
    Mutually exclusive with -All and -SiteId. One of -SiteUrl, -SiteId, or
    -All must be supplied - there is no silent default scope for this
    permission-changing script.

.PARAMETER SiteId
    Optional. One or more specific site GUIDs (SiteId) to apply the change
    to. Mutually exclusive with -All and -SiteUrl.

.PARAMETER All
    Optional switch. Apply the change to every site in the tenant. Must be
    supplied explicitly - there is no implicit default scope, given the
    impact of revoking admin rights tenant-wide.

.PARAMETER OutputPath
    Optional. Either a folder or a full .csv file path where the audit-
    trail results will be written, in addition to the on-screen/pipeline
    output. If omitted, results are returned to the console/pipeline only.

.PARAMETER Force
    Optional switch. Suppresses the per-site confirmation prompt AND
    allows removal of the last remaining Site Collection Administrator on
    a site (normally blocked). Use with caution - the action is still
    fully logged in the returned/exported audit trail either way.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
    An array of custom objects, one per site/user combination, containing
    the audit-trail result of the operation (Status, PreviousState,
    NewState, ErrorMessage, Timestamp). Always returned to the
    console/pipeline; also written to CSV when -OutputPath is supplied.

.EXAMPLE
    Remove-SharePointSiteAdmin -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -UserPrincipalName 'admin@contoso.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Retail'

    Removes the specified user's Site Collection Administrator rights on
    the specified site, prompting for confirmation first.

.EXAMPLE
    Remove-SharePointSiteAdmin -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -UserPrincipalName 'admin@contoso.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Retail','https://contoso.sharepoint.com/sites/Finance' -OutputPath 'C:\Reports'

    Removes rights on two specific sites and exports the audit trail to
    C:\Reports\RemoveSharePointSiteAdmin_<timestamp>.csv

.EXAMPLE
    Remove-SharePointSiteAdmin -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -UserPrincipalName 'admin@contoso.com' -SiteId '11111111-2222-3333-4444-555555555555' -OutputPath 'C:\Reports\retail-admin-removed.csv'

    Removes rights on the site matching the specified SiteId and exports
    to the exact file (no timestamp appended).

.EXAMPLE
    Remove-SharePointSiteAdmin -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -UserPrincipalName 'admin@contoso.com','auditor@contoso.com' -All -Verbose

    Removes rights for two users across every site in the tenant (where
    they are not the last remaining admin), with verbose diagnostic
    output.

.EXAMPLE
    Remove-SharePointSiteAdmin -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -UserPrincipalName 'admin@contoso.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Retail' -Force

    Removes rights without confirmation prompts, and allows the removal
    even if this user is the last remaining admin on the site.

.EXAMPLE
    Remove-SharePointSiteAdmin -TenantAdminUrl 'https://contoso-admin.sharepoint.com' -UserPrincipalName 'admin@contoso.com' -SiteUrl 'https://contoso.sharepoint.com/sites/Retail' -WhatIf

    Shows what would happen without making any change.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (31-Jul-2026) - Initial release
    1.0 (01-Aug-2026) - Added automatic module-load detection: on
                         PowerShell 7 (Core), Microsoft.Online.SharePoint.PowerShell
                         is now imported via -UseWindowsPowerShell compatibility
                         mode automatically, since this module only supports
                         Windows PowerShell 5.1 (Desktop) natively; added a
                         clear guidance error message if the module still
                         cannot be loaded

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. Microsoft.Online.SharePoint.PowerShell module installed
       (Install-Module Microsoft.Online.SharePoint.PowerShell). Note: this
       module only supports Windows PowerShell 5.1 (Desktop edition)
       natively; on PowerShell 7 it is imported automatically via
       -UseWindowsPowerShell compatibility mode
    2. SharePoint Online Administrator (or Global Administrator) role
    3. PowerShell 5.1 or later

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - The "last remaining admin" check queries Get-SPOUser for the site
      and counts users with IsSiteAdmin = $true; on sites with a very
      large user list this adds a small amount of latency per site
    - Uses the classic SharePoint Online Management Shell module rather
      than PnP.PowerShell, for consistency with Add-SharePointSiteAdmin.ps1
    - Does not remove the user from any SharePoint group or the site's
      "Owners" group - this only affects the Site Collection Administrator
      flag specifically

.LINK
    https://learn.microsoft.com/en-us/powershell/module/sharepoint-online/set-spouser

.LINK
    https://learn.microsoft.com/en-us/powershell/module/sharepoint-online/get-spouser

#>


Function Remove-SharePointSiteAdmin
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^https://[a-zA-Z0-9-]+-admin\.sharepoint\.com/?$')]
        [string]$TenantAdminUrl,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserPrincipalName,

        [Parameter(Mandatory = $true, ParameterSetName = 'BySiteUrl')]
        [ValidateNotNullOrEmpty()]
        [string[]]$SiteUrl,

        [Parameter(Mandatory = $true, ParameterSetName = 'BySiteId')]
        [ValidateNotNullOrEmpty()]
        [guid[]]$SiteId,

        [Parameter(Mandatory = $true, ParameterSetName = 'All')]
        [switch]$All,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ($_ -match '[<>"|?*]') { throw "OutputPath contains invalid path characters." }
            $isFilePath = [System.IO.Path]::GetExtension($_) -eq '.csv'
            $parentDir  = if ($isFilePath) { Split-Path -Path $_ -Parent } else { $_ }
            if ([string]::IsNullOrWhiteSpace($parentDir)) { $parentDir = '.' }
            if (-not (Test-Path -Path $parentDir -PathType Container)) { throw "Directory '$parentDir' does not exist." }
            $true
        })]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    if ($Force) { $ConfirmPreference = 'None' }

    #region Module load check
    if (-not (Get-Module -Name Microsoft.Online.SharePoint.PowerShell))
    {
        try
        {
            if ($PSVersionTable.PSEdition -eq 'Core')
            {
                Write-Verbose "PowerShell 7 (Core) detected - importing Microsoft.Online.SharePoint.PowerShell in Windows PowerShell compatibility mode..."
                Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell -ErrorAction Stop
            }
            else
            {
                Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop
            }
        }
        catch
        {
            Write-Error "The Microsoft.Online.SharePoint.PowerShell module could not be loaded. If it is not installed, run: Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force. If you are on PowerShell 7, this module only supports the Windows PowerShell compatibility layer (Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell) or must be run from Windows PowerShell 5.1 directly. Original error: $($_.Exception.Message)"
            return
        }
    }
    #endregion

    #region Connection check
    try
    {
        $existing = Get-SPOTenant -ErrorAction SilentlyContinue
        if (-not $existing)
        {
            Write-Verbose "Connecting to SharePoint Online tenant admin center '$TenantAdminUrl'..."
            Connect-SPOService -Url $TenantAdminUrl -ErrorAction Stop
        }
        else
        {
            Write-Verbose "Reusing existing SPOService connection."
        }
    }
    catch
    {
        Write-Error "Failed to connect to SharePoint Online admin center '$TenantAdminUrl': $($_.Exception.Message)"
        return
    }
    #endregion

    #region Resolve site scope
    Write-Progress -Activity "Remove-SharePointSiteAdmin" -Status "Resolving site scope..." -PercentComplete 0
    try
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            'BySiteUrl' { $targetSiteUrls = $SiteUrl | ForEach-Object { $_.TrimEnd('/') } }
            'BySiteId'
            {
                $allSites      = Get-SPOSite -Limit All -ErrorAction Stop
                $matched       = $allSites | Where-Object { $_.SiteId -in $SiteId }
                foreach ($id in ($SiteId | Where-Object { $_ -notin $matched.SiteId })) { Write-Warning "SiteId not found in tenant: '$id'" }
                $targetSiteUrls = $matched.Url
            }
            'All'
            {
                $targetSiteUrls = (Get-SPOSite -Limit All -ErrorAction Stop).Url
            }
        }
    }
    catch
    {
        Write-Error "Failed to resolve site scope: $($_.Exception.Message)"
        return
    }
    Write-Verbose "Resolved $($targetSiteUrls.Count) target site(s)."
    #endregion

    #region Apply changes
    $report      = [System.Collections.Generic.List[object]]::new()
    $totalOps    = $targetSiteUrls.Count * $UserPrincipalName.Count
    $opCounter   = 0

    foreach ($site in $targetSiteUrls)
    {
        foreach ($upn in $UserPrincipalName)
        {
            $opCounter++
            Write-Progress -Activity "Remove-SharePointSiteAdmin" -Status "Processing $upn on $site" `
                -PercentComplete (($opCounter / [Math]::Max($totalOps,1)) * 100)

            $status        = $null
            $previousState = $null
            $newState      = $null
            $errorMessage  = $null

            try
            {
                $currentUser = Get-SPOUser -Site $site -LoginName $upn -ErrorAction SilentlyContinue
                $previousState = if ($currentUser -and $currentUser.IsSiteAdmin) { 'Admin' } elseif ($currentUser) { 'Member' } else { 'NotFound' }

                if (-not $currentUser -or -not $currentUser.IsSiteAdmin)
                {
                    $status   = 'AlreadyNotAdmin'
                    $newState = $previousState
                    Write-Verbose "'$upn' is already not a Site Collection Administrator on '$site' - skipped."
                }
                else
                {
                    $adminCount = @(Get-SPOUser -Site $site -ErrorAction Stop | Where-Object { $_.IsSiteAdmin }).Count

                    if ($adminCount -le 1 -and -not $Force)
                    {
                        $status   = 'Blocked (last remaining admin)'
                        $newState = 'Admin'
                        Write-Warning "'$upn' is the last remaining Site Collection Administrator on '$site' - skipped. Use -Force to override."
                    }
                    elseif ($PSCmdlet.ShouldProcess($site, "Remove '$upn' as Site Collection Administrator"))
                    {
                        Set-SPOUser -Site $site -LoginName $upn -IsSiteCollectionAdmin $false -ErrorAction Stop
                        $status   = 'Removed'
                        $newState = 'Member'
                    }
                    else
                    {
                        $status   = 'Skipped (not confirmed)'
                        $newState = $previousState
                    }
                }
            }
            catch
            {
                $status      = 'Failed'
                $errorMessage = $_.Exception.Message
                Write-Warning "Failed to remove '$upn' as admin on '$site': $errorMessage"
            }

            $report.Add([PSCustomObject]@{
                SiteUrl           = $site
                UserPrincipalName = $upn
                Action            = 'Remove'
                PreviousState     = $previousState
                NewState          = $newState
                Status            = $status
                ErrorMessage      = $errorMessage
                Timestamp         = Get-Date
            })
        }
    }
    Write-Progress -Activity "Remove-SharePointSiteAdmin" -Completed
    Write-Verbose "Completed $($report.Count) operation(s)."

    if ($report.Count -eq 0)
    {
        Write-Host "No sites/users were processed for the specified scope." -ForegroundColor Yellow
    }
    #endregion

    #region Export (optional)
    if ($OutputPath)
    {
        if ([System.IO.Path]::GetExtension($OutputPath) -eq '.csv') { $outFile = $OutputPath }
        else
        {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $outFile   = Join-Path -Path $OutputPath -ChildPath "RemoveSharePointSiteAdmin_$timestamp.csv"
        }
        try
        {
            $report | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Host "Audit trail exported: $outFile" -ForegroundColor Green
        }
        catch
        {
            Write-Error "Failed to export CSV to '$outFile': $($_.Exception.Message)"
        }
    }
    else
    {
        Write-Verbose "No -OutputPath supplied; results returned to the console/pipeline only."
    }
    #endregion

    return $report
}
