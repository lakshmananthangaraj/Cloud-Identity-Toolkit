<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 21 May 2025
Modified-On     : 25 July 2026

.SYNOPSIS
    Retrieves Microsoft 365 license inventory (Subscribed SKUs) from Microsoft Graph.

.DESCRIPTION
    This function queries the Microsoft Graph beta endpoint to retrieve all subscribed
    SKUs (license plans) in the tenant, and calculates usage statistics such as total
    licenses, used licenses, unused licenses, and locked-out licenses for each SKU.

    It enriches each SKU record with:
        - SKU identifiers and display names (skuId, skuPartNumber)
        - Service plan details per license (flattened to a comma-separated list)
        - License consumption metrics (enabled, warning, suspended, lockedOut, consumed)
        - Active vs. inactive license status (derived from capabilityStatus)
        - Derived unused license counts

    Results can optionally be exported to CSV.

    This function is useful for Microsoft 365 licensing governance, capacity planning,
    and license optimization reporting.

    This function only accepts a direct Bearer token (AccessToken). It does not perform
    authentication itself. If you need to obtain a token via app-only (client credentials)
    authentication, use the companion Connect-EntraID.ps1 script referenced under .LINK
    below, then pass its returned token into -AccessToken.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        Directory.Read.All
        Organization.Read.All

    To obtain this token via app-only authentication instead of an interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER ExportFormat
    Specifies the output format for exported data.
    Supported values:
        CSV

.PARAMETER ExportPath
    File path where the exported CSV output will be saved.
    Required only when ExportFormat is set to CSV.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject
        A collection of license inventory objects containing:
            - SkuId, SkuPartNumber, SkuDisplayName
            - ServicePlans (comma-separated)
            - TotalLicenses, UsedLicenses, UnusedLicenses, LockedOutLicenses
            - LicenseType (Active, or the raw capabilityStatus value)
            - ExpirationDate (reserved; currently always $null — see Known Limitations)
        Also optionally exports to CSV.

.EXAMPLE
    Get-M365LicenseInventory -AccessToken $token

    Retrieves Microsoft 365 license inventory and usage statistics.

.EXAMPLE
    Get-M365LicenseInventory -AccessToken $token -ExportFormat CSV -ExportPath "C:\Reports\LicenseInventory.csv"

    Retrieves license inventory and exports the result to a CSV file.

.EXAMPLE
    $inventory = Get-M365LicenseInventory -AccessToken $token
    $inventory | Format-Table

    Retrieves license inventory and displays it in a formatted table.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (21-May-2025)  - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. A valid Microsoft Graph access token with the following permissions:
                Directory.Read.All     (Application)
                Organization.Read.All  (Application)

        2. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ─────────────────────────────────────────────────────────────────────────────
        Step 1  →  Call Microsoft Graph's /beta/subscribedSkus endpoint
        Step 2  →  For each SKU, calculate total/used/unused/locked-out counts
        Step 3  →  Derive LicenseType and flatten ServicePlans
        Step 4  →  Export to CSV (if requested)

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - The function uses the /beta Graph API endpoint. Beta endpoints are
            subject to change and are not recommended for production without
            monitoring for breaking changes.
        - No pagination handling: subscribedSkus typically returns a small,
            single-page result set for most tenants, so @odata.nextLink handling
            was not implemented. Flag if your tenant has an unusually large
            number of SKUs and this needs revisiting.
        - ExpirationDate is currently always $null — the Graph subscribedSkus
            response does not include a per-SKU expiration date; this field is
            reserved for future enrichment (e.g. cross-referencing subscription
            billing data) rather than removed, in case that gets added later.
        - TotalLicenses/UnusedLicenses fall back to the strings "Not Reported"/
            "Unknown" when total is 0, so downstream consumers doing numeric
            comparisons on these columns should account for mixed string/int
            values.
        - This function does not perform authentication itself; it requires a
            pre-acquired Bearer token via -AccessToken.

.LINK
    Microsoft Graph API - subscribedSku resource type
    https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-beta

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function Get-M365LicenseInventory
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [ValidateSet("CSV")]
        [string]$ExportFormat,

        [string]$ExportPath
    )

    $headers = @{
        Authorization = "Bearer $AccessToken"
    }

    $url = "https://graph.microsoft.com/beta/subscribedSkus"

    try 
    {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

        $licenseInventory = foreach ($sku in $response.value) 
        {
            $enabled = $sku.prepaidUnits.enabled
            $warning = $sku.prepaidUnits.warning
            $suspended = $sku.prepaidUnits.suspended
            $lockedOut  = $sku.prepaidUnits.lockedOut

            $used = $sku.consumedUnits

            $total = ($enabled + $warning + $suspended + $lockedOut)
            $unused = $total - $used

            $displayTotal = if ($total -gt 0) { $total } else { "Not Reported" }
            $displayUnused = if ($total -gt 0) { $unused } else { "Unknown" }

            $licenseType = if ($sku.capabilityStatus -eq "Enabled") {
                "Active"
            } else {
                $sku.capabilityStatus
            }

            $servicePlans = ($sku.servicePlans | ForEach-Object { $_.servicePlanName }) -join ', '

            [PSCustomObject]@{
                SkuId             = $sku.skuId
                SkuPartNumber     = $sku.skuPartNumber
                SkuDisplayName    = $sku.skuPartNumber
                ServicePlans      = $servicePlans
                TotalLicenses     = $displayTotal
                UsedLicenses      = $used
                UnusedLicenses    = $displayUnused
                LockedOutLicenses = $lockedOut
                LicenseType       = $licenseType
                ExpirationDate    = $null
            }
        }

        # CSV EXPORT SUPPORT
        if($ExportFormat -eq "CSV" -and $ExportPath)
        {
            $licenseInventory | Export-Csv -Path $ExportPath -NoTypeInformation -Force

            Write-Host ""
            Write-Host "License inventory report exported successfully → $ExportPath" -ForegroundColor Green
        }
        
        return $licenseInventory
        # return $licenseInventory | Select-Object SkuDisplayName, TotalLicenses, UsedLicenses, UnusedLicenses, LockedOutLicenses, LicenseType
    } 
    catch 
    {
        Write-Error "Failed to retrieve license inventory: $_"
    }
}
