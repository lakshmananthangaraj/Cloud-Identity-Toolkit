<#

Author       : Lakshmanan Thangaraj
Version      : 1.2
Created-On   : 15 May 2026
Modified-On  : 29 July 2026

.SYNOPSIS
    Comprehensive Azure NSG Inventory and Data Collection Tool.
    Requirement 1 - Existing NSG Standardization and Compliance Assessment.
    Step 1: Collect Azure NSG inventory for security analysis, compliance assessment,
    and interactive dashboard visualization.

.DESCRIPTION
    Retrieves all NSG details across all or specific Azure Subscriptions
    including:
    - Inbound and outbound security rules
    - Rule priorities, protocols, source/destination, port ranges
    - Subnet and Network Interface associations
    - Outputs a structured CSV report that serves as the baseline dataset for:
        - Existing NSG standardization and compliance assessments
        - Security reviews and risk analysis
        - Interactive HTML dashboard visualization using Generate-AzureNSGDashboard.ps1

.PARAMETER SubscriptionIds
    Optional. One or more Subscription IDs (GUIDs) to target. If omitted,
    all accessible, enabled subscriptions are scanned.

.PARAMETER OutputPath
    Optional. Directory path where the CSV report will be saved. Defaults
    to the current directory. Created automatically if it does not exist.

.PARAMETER ReportPrefix
    Optional. Prefix for the output CSV filename. Default: "NSG_Inventory".
    Must not contain path separators or path-traversal sequences, since it
    is used to build the output file name.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    None directly to the pipeline.

    Writes a structured CSV report to disk that can be:
    - Opened directly in Excel for analysis
    - Imported into Power BI
    - Used as the input dataset for
      Generate-AzureNSGDashboard.ps1 to build an interactive
      HTML dashboard.

.EXAMPLE
    # Scan all subscriptions
    Get-AzureNSGInventory

.EXAMPLE
    # Scan specific subscriptions
    Get-AzureNSGInventory -SubscriptionIds "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"

.EXAMPLE
    # Scan all subscriptions and save to a custom path
    Get-AzureNSGInventory -OutputPath "C:\Reports\NSG" -ReportPrefix "Prod_NSG_Baseline"

.EXAMPLE
    # Generate an interactive dashboard

    Get-AzureNSGInventory -OutputPath "C:\Reports"

    Generate-AzureNSGDashboard -CsvPath "C:\Reports\NSG_Inventory_<timestamp>.csv" -OpenBrowser

    Collects the Azure NSG inventory and converts it into an
    interactive HTML dashboard for security review and reporting.

.NOTES
    ────────────────────────────────────────────────────────────────
    VERSION HISTORY
    ────────────────────────────────────────────────────────────────
    CHANGELOG:
      v1.2 - 29 July 2026 - Standards-compliance update. No changes to
                            data-collection logic, the rule-flattening fix, or the CSV
                            output schema/columns. Changes are documentation, security
                            validation, and formatting only:
                            - Author block field names corrected to Created-On/
                                Modified-On.
                            - Added .INPUTS/.OUTPUTS/.LINK; restructured .NOTES with
                                Version History / Pre-Requisites / Execution Flow /
                                Known Limitations sections.
                            - Added path/name validation on -ReportPrefix to block
                                path separators and path-traversal sequences before it
                                reaches Join-Path (it was previously unvalidated).
                            - Added GUID-format validation on -SubscriptionIds.
                            - Converted control-block brace style to next-line
                                (Allman) convention for Function/if/else/foreach/try/
                                catch blocks; short inline scriptblocks (Where-Object/
                                ForEach-Object filters) left as single-line, matching
                                existing repo idiom.
                            - Corrected the missing-module guidance text to reference
                                the three specific submodules this script actually
                                checks for (Az.Accounts, Az.Network, Az.Resources)
                                instead of the full Az umbrella module.
                            - Added supplementary Write-Verbose diagnostic lines
                                (additive only; no existing Write-Host output changed).
      v1.1 - 15 May 2026 - Fixed PropertyNotFoundException on
                           SourceAddressPrefixes, SourcePortRanges,
                           DestinationAddressPrefixes, DestinationPortRanges. Fixed CSV
                           columns showing System.Collections.Generic.List instead of
                           actual values. All multi-value fields are safely flattened
                           using @() null-safe casting before joining.

    ────────────────────────────────────────────────────────────────
    PRE-REQUISITES
    ────────────────────────────────────────────────────────────────
    - PowerShell 5.1 or later.
    - Az.Accounts, Az.Network, and Az.Resources modules. This function
      does NOT auto-install them (by design, unlike some other scripts
      in this toolkit) — it errors with guidance if any are missing:
        Install-Module -Name Az.Accounts, Az.Network, Az.Resources -Scope CurrentUser -AllowClobber
    - An Azure account with at least Reader access on the target
      subscription(s) and permission to read Network Security Groups,
      subnets, and network interfaces.

    ────────────────────────────────────────────────────────────────
    EXECUTION FLOW
    ────────────────────────────────────────────────────────────────
    1. Verify Az.Accounts, Az.Network, and Az.Resources are installed;
       error out with install guidance if any are missing.
    2. Verify/establish an authenticated Azure session; if a session
       already exists, prompt whether to reuse it or re-authenticate.
    3. Resolve the target list of subscriptions (specific IDs, or all
       enabled subscriptions if none were supplied).
    4. For each subscription: set context, retrieve all NSGs, and for
       each NSG collect subnet/NIC associations, tags, and all custom +
       default security rules (flattening multi-value address/port
       fields safely). NSGs with no rules still produce one placeholder
       row so they appear in the report.
    5. Export the combined results to a timestamped CSV file under
       -OutputPath.
    6. The generated CSV can optionally be consumed by
       Generate-AzureNSGDashboard.ps1 to create an interactive,
       self-contained HTML dashboard for security analysis,
       executive reporting, and risk visualization.

    ────────────────────────────────────────────────────────────────
    KNOWN LIMITATIONS
    ────────────────────────────────────────────────────────────────
    - The "ManagementGroup" column is populated from a subscription tag
      literally named 'ManagementGroup' if one exists — it is NOT
      queried from the actual Azure Management Group hierarchy API. If
      your subscriptions don't carry this tag, expect "N/A" in this
      column; that does not mean no management groups exist.
    - TotalSubnetAssociations / TotalNICAssociations read
      $nsg.Subnets.Count / $nsg.NetworkInterfaces.Count directly, without
      the same null-guard used a few lines earlier for $nsg.Tag. In
      practice Get-AzNetworkSecurityGroup returns empty collections
      (not $null) for these properties, so this has not been observed to
      fail, but it is not defensively guarded the same way.
    - No retry/backoff logic for Azure Resource Manager throttling on
      very large tenants with many subscriptions/NSGs.
    - This function does not auto-install missing modules; it errors
      with a suggested command instead (a deliberate design choice for
      this script, distinct from other toolkit scripts that prompt to
      auto-install).
    - Generate-AzureNSGDashboard.ps1 expects the CSV schema
      produced by this function. If column names or output
      structure change in future versions, the dashboard
      function must be updated accordingly.

.LINK
    Generate-AzureNSGDashboard.ps1 - Interactive HTML dashboard for Azure NSG Inventory reports
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Azure/Network/Generate-AzureNSGDashboard.ps1

.LINK
    https://learn.microsoft.com/en-us/powershell/module/az.network/get-aznetworksecuritygroup

.LINK
    https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview

#>


Function Get-AzureNSGInventory
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, HelpMessage = "One or more Azure Subscription IDs. Leave empty to scan all.")]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false, HelpMessage = "Directory path to save the CSV report.")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = (Get-Location).Path,

        [Parameter(Mandatory = $false, HelpMessage = "Prefix for the output CSV filename.")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ($_ -match '\.\.' -or $_ -match '[\\/:\*\?"<>\|]')
            {
                throw "ReportPrefix must not contain path separators, path-traversal sequences ('..'), or invalid filename characters."
            }
            $true
        })]
        [string]$ReportPrefix = "NSG_Inventory"
    )

    #region ── Helper: Safe Array-to-String Flattener ────────────────────────────
    Function ConvertTo-FlatString
    {
        param(
            [object]$Value      # The raw property (may be $null, string, or List<string>)
        )
        $arr = @($Value | Where-Object { $_ -ne $null -and $_ -ne "" })
        if ($arr.Count -gt 0)
        {
            return ($arr -join ", ")
        }
        return ""
    }
    #endregion

    Function Get-RuleProp
    {
        # Add-Member -PassThru wraps the typed Az object in a plain PSObject,
        # stripping strongly-typed .NET properties. Direct dot-notation throws
        # PropertyNotFoundException on the wrapper for plural properties.
        # PSObject.Properties.Match() bypasses this — it never throws and works
        # on both the original object and any PSObject wrapper.

        param([object]$Rule, [string]$PropertyName)
        $match = $Rule.PSObject.Properties.Match($PropertyName)
        if ($match.Count -gt 0)
        {
            return $Rule.$PropertyName
        }
        return $null
    }
    #endregion

    #region ── Banner ────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║             Azure NSG Inventory & Data Collection Tool               ║" -ForegroundColor Cyan
    Write-Host "║         Requirement 1 - NSG Standardization & Compliance             ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    #endregion

    #region ── Module Check ──────────────────────────────────────────────────────
    Write-Host "[PRE-CHECK] Verifying required Az PowerShell modules..." -ForegroundColor Yellow
    $requiredModules = @("Az.Accounts", "Az.Network", "Az.Resources")
    foreach ($mod in $requiredModules)
    {
        if (-not (Get-Module -ListAvailable -Name $mod))
        {
            Write-Error "Required module '$mod' is not installed. Run: Install-Module -Name Az.Accounts, Az.Network, Az.Resources -Scope CurrentUser -AllowClobber"
            return
        }
    }
    Write-Verbose "All required modules verified: $($requiredModules -join ', ')"
    Write-Host "[PRE-CHECK] All required modules are available." -ForegroundColor Green
    Write-Host ""
    #endregion

    #region ── Authentication Check & Session Management ─────────────────────────
    Write-Host "[AUTH] Checking for active Azure session..." -ForegroundColor Yellow

    $activeContext = $null
    try
    {
        $activeContext = Get-AzContext -ErrorAction SilentlyContinue
    }
    catch
    {
        $activeContext = $null
    }

    if ($null -eq $activeContext -or $null -eq $activeContext.Account)
    {
        Write-Host "[AUTH] No active Azure session detected. Initiating authentication..." -ForegroundColor Yellow
        try
        {
            Connect-AzAccount -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            $activeContext = Get-AzContext
            Write-Host "[AUTH] Authentication successful." -ForegroundColor Green
            Write-Host "       Signed in as  : $($activeContext.Account.Id)" -ForegroundColor Green
            Write-Host "       Tenant        : $($activeContext.Tenant.Id)" -ForegroundColor Green
        }
        catch
        {
            Write-Error "[AUTH] Authentication failed: $_"
            return
        }
    }
    else
    {
        Write-Host "[AUTH] Active session found." -ForegroundColor Green
        Write-Host "       Signed in as  : $($activeContext.Account.Id)" -ForegroundColor Green
        Write-Host "       Tenant        : $($activeContext.Tenant.Id)" -ForegroundColor Green
        Write-Host "       Current Sub   : $($activeContext.Subscription.Name) [$($activeContext.Subscription.Id)]" -ForegroundColor Green

        $reAuth = Read-Host "`n[AUTH] Use existing session? (Y/N, default=Y)"
        if ($reAuth -eq "N" -or $reAuth -eq "n")
        {
            Write-Host "[AUTH] Disconnecting current session and re-authenticating..." -ForegroundColor Yellow
            Disconnect-AzAccount -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
            try
            {
                Connect-AzAccount -ErrorAction Stop | Out-Null
                $activeContext = Get-AzContext
                Write-Host "[AUTH] Re-authentication successful." -ForegroundColor Green
            }
            catch
            {
                Write-Error "[AUTH] Re-authentication failed: $_"
                return
            }
        }
    }
    Write-Host ""
    #endregion

    #region ── Subscription Discovery ───────────────────────────────────────────
    Write-Host "[DISCOVERY] Resolving target subscriptions..." -ForegroundColor Yellow

    $targetSubscriptions = @()

    if ($SubscriptionIds -and @($SubscriptionIds).Count -gt 0)
    {
        Write-Host "[DISCOVERY] Scanning SPECIFIC subscriptions provided: $($SubscriptionIds.Count)" -ForegroundColor Cyan
        foreach ($subId in $SubscriptionIds)
        {
            try
            {
                $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction Stop -WarningAction SilentlyContinue
                $targetSubscriptions += $sub
                Write-Host "            + $($sub.Name) [$($sub.Id)]" -ForegroundColor Gray
            }
            catch
            {
                Write-Warning "[DISCOVERY] Subscription ID '$subId' not found or access denied. Skipping."
            }
        }
    }
    else
    {
        Write-Host "[DISCOVERY] No specific subscriptions provided. Discovering ALL accessible subscriptions..." -ForegroundColor Cyan
        try
        {
            $targetSubscriptions = @(Get-AzSubscription -ErrorAction Stop -WarningAction SilentlyContinue | Where-Object { $_.State -eq "Enabled" })
            Write-Host "[DISCOVERY] Found $(@($targetSubscriptions).Count) enabled subscription(s)." -ForegroundColor Green
            $targetSubscriptions | ForEach-Object {
                Write-Host "            + $($_.Name) [$($_.Id)]" -ForegroundColor Gray
            }
        }
        catch
        {
            Write-Error "[DISCOVERY] Failed to retrieve subscriptions: $_"
            return
        }
    }

    if ($targetSubscriptions.Count -eq 0)
    {
        Write-Error "[DISCOVERY] No valid subscriptions found. Exiting."
        return
    }
    Write-Host ""
    #endregion

    #region ── NSG Collection ────────────────────────────────────────────────────
    $masterReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalNSGs    = 0
    $totalRules   = 0
    $subCounter   = 0

    foreach ($subscription in $targetSubscriptions)
    {
        $subCounter++
        Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "[$subCounter/$($targetSubscriptions.Count)] Processing Subscription: $($subscription.Name)" -ForegroundColor Cyan
        Write-Host "    Subscription ID : $($subscription.Id)" -ForegroundColor Gray

        try
        {
            Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        }
        catch
        {
            Write-Warning "    Failed to switch context to subscription '$($subscription.Name)'. Skipping."
            continue
        }

        # Management Group (best-effort via subscription tag)
        $mgName = "N/A"
        try
        {
            $subDetail = Get-AzSubscription -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($subDetail.Tags -and $subDetail.Tags["ManagementGroup"])
            {
                $mgName = $subDetail.Tags["ManagementGroup"]
            }
        }
        catch
        {
        }

        Write-Host "    Retrieving NSGs..." -ForegroundColor Yellow
        $nsgs = @()
        try
        {
            $nsgs = Get-AzNetworkSecurityGroup -ErrorAction Stop -WarningAction SilentlyContinue
        }
        catch
        {
            Write-Warning "    Failed to retrieve NSGs for subscription '$($subscription.Name)': $_"
            continue
        }

        if ($nsgs.Count -eq 0)
        {
            Write-Host "    No NSGs found in this subscription." -ForegroundColor DarkYellow
            continue
        }

        Write-Host "    Found $($nsgs.Count) NSG(s). Collecting rules and associations..." -ForegroundColor Green
        $totalNSGs += $nsgs.Count

        foreach ($nsg in $nsgs)
        {

            #region ── Subnet Associations ───────────────────────────────────────
            $subnetAssociations = @()
            if ($nsg.Subnets -and $nsg.Subnets.Count -gt 0)
            {
                foreach ($subnet in $nsg.Subnets)
                {
                    $parts      = $subnet.Id -split "/"
                    $vnetName   = if ($parts.Count -ge 9)  { $parts[8]  } else { "Unknown" }
                    $subnetName = if ($parts.Count -ge 11) { $parts[10] } else { "Unknown" }
                    $subnetAssociations += "$vnetName/$subnetName"
                }
            }
            $subnetAssocStr = if ($subnetAssociations.Count -gt 0) { $subnetAssociations -join " | " } else { "None" }
            #endregion

            #region ── NIC Associations ──────────────────────────────────────────
            $nicAssociations = @()
            if ($nsg.NetworkInterfaces -and $nsg.NetworkInterfaces.Count -gt 0)
            {
                foreach ($nic in $nsg.NetworkInterfaces)
                {
                    $parts   = $nic.Id -split "/"
                    $nicName = if ($parts.Count -ge 9) { $parts[8] } else { $nic.Id }
                    $nicAssociations += $nicName
                }
            }
            $nicAssocStr = if ($nicAssociations.Count -gt 0) { $nicAssociations -join " | " } else { "None" }
            #endregion

            #region ── NSG Tags ──────────────────────────────────────────────────
            $nsgTagStr = "None"
            if ($nsg.Tag -and $nsg.Tag.Count -gt 0)
            {
                $nsgTagStr = ($nsg.Tag.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
            }
            #endregion

            #region ── Rules (Custom + Default) ──────────────────────────────────
            $allRules  = @()
            $allRules += $nsg.SecurityRules        | ForEach-Object { $_ | Add-Member -NotePropertyName "RuleSource" -NotePropertyValue "Custom"  -PassThru -Force }
            $allRules += $nsg.DefaultSecurityRules | ForEach-Object { $_ | Add-Member -NotePropertyName "RuleSource" -NotePropertyValue "Default" -PassThru -Force }

            if ($allRules.Count -eq 0)
            {
                # NSG with no rules — still record it so it appears in the report
                $masterReport.Add([PSCustomObject]@{
                    ManagementGroup            = $mgName
                    SubscriptionName           = $subscription.Name
                    SubscriptionId             = $subscription.Id
                    ResourceGroup              = $nsg.ResourceGroupName
                    NSGName                    = $nsg.Name
                    NSGLocation                = $nsg.Location
                    NSGResourceId              = $nsg.Id
                    NSGProvisioningState       = $nsg.ProvisioningState
                    NSGTags                    = $nsgTagStr
                    AssociatedSubnets          = $subnetAssocStr
                    AssociatedNICs             = $nicAssocStr
                    TotalSubnetAssociations    = $nsg.Subnets.Count
                    TotalNICAssociations       = $nsg.NetworkInterfaces.Count
                    RuleSource                 = "N/A"
                    RuleName                   = "NO RULES DEFINED"
                    RuleDirection              = "N/A"
                    RulePriority               = "N/A"
                    RuleAccess                 = "N/A"
                    RuleProtocol               = "N/A"
                    SourceAddressPrefix        = "N/A"
                    SourceAddressPrefixes      = "N/A"
                    SourcePortRange            = "N/A"
                    SourcePortRanges           = "N/A"
                    DestinationAddressPrefix   = "N/A"
                    DestinationAddressPrefixes = "N/A"
                    DestinationPortRange       = "N/A"
                    DestinationPortRanges      = "N/A"
                    RuleDescription            = "NSG has no security rules"
                    RuleProvisioningState      = "N/A"
                    CollectedAtUTC             = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                })
            }
            else
            {
                foreach ($rule in $allRules)
                {
                    $totalRules++

                    $srcAddrSingular  = ConvertTo-FlatString $rule.SourceAddressPrefix
                    $srcAddrPlural    = ConvertTo-FlatString (Get-RuleProp $rule "SourceAddressPrefixes")
                    $srcPortSingular  = ConvertTo-FlatString $rule.SourcePortRange
                    $srcPortPlural    = ConvertTo-FlatString (Get-RuleProp $rule "SourcePortRanges")
                    $dstAddrSingular  = ConvertTo-FlatString $rule.DestinationAddressPrefix
                    $dstAddrPlural    = ConvertTo-FlatString (Get-RuleProp $rule "DestinationAddressPrefixes")
                    $dstPortSingular  = ConvertTo-FlatString $rule.DestinationPortRange
                    $dstPortPlural    = ConvertTo-FlatString (Get-RuleProp $rule "DestinationPortRanges")

                    # Merge singular + plural; de-duplicate in case Az echoes both
                    $srcAddrAll  = @($srcAddrSingular, $srcAddrPlural)  | Where-Object { $_ -ne "" } | Select-Object -Unique
                    $srcPortAll  = @($srcPortSingular, $srcPortPlural)  | Where-Object { $_ -ne "" } | Select-Object -Unique
                    $dstAddrAll  = @($dstAddrSingular, $dstAddrPlural)  | Where-Object { $_ -ne "" } | Select-Object -Unique
                    $dstPortAll  = @($dstPortSingular, $dstPortPlural)  | Where-Object { $_ -ne "" } | Select-Object -Unique

                    $masterReport.Add([PSCustomObject]@{
                        # ── Scope & Identity ──────────────────────────────────
                        ManagementGroup            = $mgName
                        SubscriptionName           = $subscription.Name
                        SubscriptionId             = $subscription.Id
                        ResourceGroup              = $nsg.ResourceGroupName
                        NSGName                    = $nsg.Name
                        NSGLocation                = $nsg.Location
                        NSGResourceId              = $nsg.Id
                        NSGProvisioningState       = $nsg.ProvisioningState
                        NSGTags                    = $nsgTagStr

                        # ── Associations ──────────────────────────────────────
                        AssociatedSubnets          = $subnetAssocStr
                        AssociatedNICs             = $nicAssocStr
                        TotalSubnetAssociations    = $nsg.Subnets.Count
                        TotalNICAssociations       = $nsg.NetworkInterfaces.Count

                        # ── Rule Identity ─────────────────────────────────────
                        RuleSource                 = $rule.RuleSource          # Custom / Default
                        RuleName                   = $rule.Name
                        RuleDirection              = $rule.Direction            # Inbound / Outbound
                        RulePriority               = $rule.Priority
                        RuleAccess                 = $rule.Access              # Allow / Deny
                        RuleProtocol               = $rule.Protocol            # TCP / UDP / ICMP / *

                        # ── Source ────────────────────────────────────────────
                        # Singular = the value when only one address/port is defined.
                        # Plural   = comma-separated list when multiple are defined.
                        # Both are captured; in most cases one will be populated and
                        # the other empty. The "All" merged column combines them.

                        SourceAddressPrefix        = $srcAddrSingular
                        SourceAddressPrefixes      = $srcAddrPlural
                        SourceAddressAll           = ($srcAddrAll -join ", ")   # merged/clean column
                        SourcePortRange            = $srcPortSingular
                        SourcePortRanges           = $srcPortPlural
                        SourcePortAll              = ($srcPortAll -join ", ")   # merged/clean column

                        # ── Destination ───────────────────────────────────────
                        DestinationAddressPrefix   = $dstAddrSingular
                        DestinationAddressPrefixes = $dstAddrPlural
                        DestinationAddressAll      = ($dstAddrAll -join ", ")   # merged/clean column
                        DestinationPortRange       = $dstPortSingular
                        DestinationPortRanges      = $dstPortPlural
                        DestinationPortAll         = ($dstPortAll -join ", ")   # merged/clean column

                        # ── Audit ─────────────────────────────────────────────
                        RuleDescription            = if ($rule.Description) { $rule.Description } else { "" }
                        RuleProvisioningState      = $rule.ProvisioningState
                        CollectedAtUTC             = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    })
                }
            }
            #endregion
        }

        Write-Host "    Completed: $($nsgs.Count) NSGs processed." -ForegroundColor Green
    }
    #endregion

    #region ── Export CSV Report ─────────────────────────────────────────────────
    Write-Host ""
    Write-Host "=====================================================================" -ForegroundColor Cyan
    Write-Host "[EXPORT] Generating CSV report..." -ForegroundColor Yellow

    if (-not (Test-Path -Path $OutputPath))
    {
        try
        {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-Host "[EXPORT] Created output directory: $OutputPath" -ForegroundColor Gray
        }
        catch
        {
            Write-Error "[EXPORT] Failed to create output directory '$OutputPath': $_"
            return
        }
    }

    $timestamp   = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $csvFileName = "${ReportPrefix}_${timestamp}.csv"
    $csvFilePath = Join-Path -Path $OutputPath -ChildPath $csvFileName

    try
    {
        $masterReport | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║                    OK  INVENTORY COMPLETE                            ║" -ForegroundColor Green
        Write-Host "╠══════════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
        Write-Host "║  Subscriptions Scanned : $($targetSubscriptions.Count.ToString().PadRight(44))║" -ForegroundColor Green
        Write-Host "║  Total NSGs Found      : $($totalNSGs.ToString().PadRight(44))║" -ForegroundColor Green
        Write-Host "║  Total Rules Captured  : $($totalRules.ToString().PadRight(44))║" -ForegroundColor Green
        Write-Host "║  Total Report Rows     : $($masterReport.Count.ToString().PadRight(44))║" -ForegroundColor Green
        Write-Host "╠══════════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
        Write-Host "║  Report Saved To:                                                    ║" -ForegroundColor Green
        $truncPath = if ($csvFilePath.Length -gt 68) { "..." + $csvFilePath.Substring($csvFilePath.Length - 65) } else { $csvFilePath }
        Write-Host "║  $($truncPath.PadRight(68))║" -ForegroundColor Green
        Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "[NEXT STEP] Use this CSV as input for:" -ForegroundColor Cyan
        Write-Host "   ► Step 2 : Gap Analysis & Impact Assessment (compare vs mandatory rules)" -ForegroundColor Gray
        Write-Host "   ► Step 3 : Dashboard & Visualization Script (storytelling & insights)" -ForegroundColor Gray
        Write-Host ""
    }
    catch
    {
        Write-Error "[EXPORT] Failed to export CSV: $_"
        return
    }
    #endregion

    # return $masterReport | Select-Object SubscriptionName, ResourceGroup, NSGName, TotalSubnetAssociations, TotalNICAssociations, RuleSource, RuleDirection, RuleName | Ft
}

#region ── Entry Point ────────────────────────────────────────────────────────
if ($MyInvocation.InvocationName -ne ".")
{
    Write-Host ""
    Write-Host "Function 'Get-AzureNSGInventory' loaded. Usage examples:" -ForegroundColor DarkGray
    Write-Host "   Get-AzureNSGInventory" -ForegroundColor White
    Write-Host "   Get-AzureNSGInventory -SubscriptionIds 'sub-id-1','sub-id-2' -OutputPath 'C:\Reports'" -ForegroundColor White
    Write-Host ""
}
#endregion
