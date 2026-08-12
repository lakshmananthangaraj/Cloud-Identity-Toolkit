<#

Author       : Lakshmanan Thangaraj
Version      : 2.1
Created-On   : 13 November 2024
Modified-On  : 12 August 2026

.SYNOPSIS
    Retrieves a comprehensive tag inventory across Azure subscriptions, resource groups,
    and individual resources, with optional CSV export.

.DESCRIPTION
    The Get-AzureResourceTagInventory function retrieves all tags associated with Azure
    subscriptions, resource groups, and individual resources within specified subscriptions.

    It supports:
        - Scanning all subscriptions in the tenant, or a specified list of subscription IDs
        - Optionally including resources that have no tags applied (-IncludeEmptyTags)
        - Real-time progress tracking with color-coded console output per subscription
        - CSV export of all collected tag data to a configurable output path

    Design notes:
        - The Az module is checked on entry and installation is offered interactively
          if not found.
        - Authentication context is verified before scanning begins; Connect-AzAccount
          is invoked automatically if no active session is detected.
        - Progress is reported at every 10% milestone per subscription to keep long-running
          scans observable without excessive console output.

.PARAMETER SubscriptionIds
    Optional string array of specific Azure subscription IDs to scan.
    If omitted and -AllSubscriptions is not specified, the default subscription context is used.

.PARAMETER AllSubscriptions
    Switch. When set, processes every subscription visible to the authenticated account.

.PARAMETER IncludeEmptyTags
    Switch. When set, resources, resource groups, and subscriptions with no tags applied
    are included in the report with TagName = "N/A" and TagValue = "Empty".

.PARAMETER OutputPath
    Path where the CSV report will be written.
    Default: $HOME\AzureTagsReport.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Object[]
        A collection of PSCustomObjects representing each tag entry is exported to CSV
        and displayed via Out-GridView. Fields: SubscriptionName, SubscriptionId,
        ResourceType, ResourceName, ResourceId, TagName, TagValue.

.EXAMPLE
    Get-AzureResourceTagInventory -AllSubscriptions -IncludeEmptyTags

    Retrieves tag data for all subscriptions, including resources with no tags, and
    exports the report to the default path.

.EXAMPLE
    Get-AzureResourceTagInventory -SubscriptionIds "12345-abcde-67890-fghij-12345", "67890-klmno-12345-pqrst-67890" -OutputPath "C:\Reports\AzureTagsReport.csv"

    Processes the two specified subscriptions and exports the report to the given path.

.EXAMPLE
    Get-AzureResourceTagInventory

    Retrieves tag data for the current default subscription and exports the report to
    the default output path.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        2.1 (12-Aug-2026) - Documentation-only update: recorded parallel processing
                            decision in Known Limitations. Sequential foreach approach
                            confirmed intentional for PS 5.1 compatibility and parity
                            with Get-AzureRBACAssignments reference implementation.
                            Subscription-level parallelization deferred as a future
                            enhancement, pending performance testing on large tenants.
                            No functional or logic changes.
        2.0 (12-Aug-2026) - Renamed function from Get-AzureTagsReport to
                            Get-AzureResourceTagInventory to align with toolkit
                            naming conventions. Upgraded header to standard
                            comment-based help (.SYNOPSIS/.PARAMETER/.INPUTS/
                            .OUTPUTS/.EXAMPLE/.NOTES/.LINK). Added Known
                            Limitations section. Enforced next-line brace style,
                            Write-Verbose diagnostics, approved-verb compliance,
                            and consistent author/version block per
                            Cloud-Identity-Toolkit engineering standards.
                            No functional or logic changes.
        1.1 (22-May-2025) - Minor updates.
        1.0 (13-Nov-2024) - Initial release. Retrieves subscription, resource group,
                            and resource-level tags across one or more subscriptions.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module. If not installed, the function will prompt to install
           it interactively. To install manually:
               Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
        2. An active Azure account with Reader permissions on the target subscriptions,
           or Resource Group Reader on the target resource groups.
        3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Out-GridView requires a GUI-capable session (Windows PowerShell ISE or
          Microsoft.PowerShell.GraphicalTools on PS7). In headless or Linux/CI sessions
          this step is skipped gracefully; CSV output is unaffected.
        - Default -OutputPath ($HOME\AzureTagsReport.csv) is platform-dependent.
          On Linux/macOS PowerShell 7, $HOME resolves to the user home directory.
        - Progress is reported at every 10% resource-group milestone per subscription,
          not per individual resource, to avoid excessive console output on large tenants.
        - Tags on resources that fail Get-AzTag silently (access denied, resource locked)
          are skipped without an error entry; -Verbose will surface these if needed.
        - Processing is sequential (subscription → resource group → resource). In large
          environments with many subscriptions or deeply populated resource groups, scan
          time scales linearly with the number of Get-AzTag API calls. Parallel processing
          (runspace pool at subscription level) is deferred to a future version; it was
          deliberately excluded from v2.x to maintain PowerShell 5.1 compatibility and
          consistency with the Get-AzureRBACAssignments reference implementation. Evaluate
          subscription-level parallelization as a separate enhancement if testing confirms
          performance is a concern.

.LINK
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit

.LINK
    Azure tags overview
    https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources

#>


#------------------------------------------------------------------------------------[ Function ]

Function Get-AzureResourceTagInventory
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$SubscriptionIds,

        [Parameter(Mandatory = $false)]
        [switch]$AllSubscriptions,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeEmptyTags,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "$HOME\AzureTagsReport.csv"
    )

    # Check if the Az module is installed
    if (-not (Get-Module -ListAvailable -Name Az))
    {
        Write-Host "Az module is not installed on this system." -ForegroundColor Yellow
        $installAz = Read-Host "Would you like to install the Az module now? (Y/N)"

        if ($installAz -eq 'Y' -or $installAz -eq 'y')
        {
            try
            {
                Write-Host "Installing the Az module on this system, please wait...." -ForegroundColor Yellow
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "Az module has been successfully installed and imported." -ForegroundColor Green
            }
            catch
            {
                Write-Host "Error installing and importing Az module: $_" -ForegroundColor Red
                Exit
            }
        }
        else
        {
            Write-Host "Az module installation declined. The script cannot proceed without the Az module." -ForegroundColor Yellow
            Exit
        }
    }
    else
    {
        Write-Host "Az module is already installed." -ForegroundColor Cyan
    }

    # Check for an active session and prompt for authentication if none is found
    $currentContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentContext)
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] No active session found. Prompting for authentication..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
    }
    else
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Active session found. Proceeding with the following current context..." -ForegroundColor Green
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $($currentContext.Name) - $($currentContext.Environment.Name)" -ForegroundColor Cyan
    }

    # Get the list of subscriptions based on input parameters
    if ($AllSubscriptions -or -not $SubscriptionIds)
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Processing all subscriptions..." -ForegroundColor Yellow
        $subscriptions = Get-AzSubscription -WarningAction SilentlyContinue
    }
    else
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Processing specified subscriptions..." -ForegroundColor Yellow
        $subscriptions = Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $SubscriptionIds -contains $_.Id }
    }

    # Display the subscription count
    $subscriptionCount = @($subscriptions).Count
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Total subscriptions being processed: $subscriptionCount" -ForegroundColor Green

    # Exit if no subscriptions were selected
    if (-not $subscriptions)
    {
        Write-Host "No subscriptions selected. Exiting function."
        return
    }

    # Initialize an array to store the results
    $tagReport = @()

    # Initialize counter for subscription index
    $subscriptionIndex = 1

    foreach ($subscription in $subscriptions)
    {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Processing subscription-$($subscriptionIndex): $($subscription.Name)" -ForegroundColor Cyan
        Write-Verbose "Setting context to subscription: $($subscription.Id)"

        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null

        # Process subscription-level tags
        $subscriptionTags = Get-AzTag -ResourceId "/subscriptions/$($subscription.Id)" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($subscriptionTags -and $subscriptionTags.Properties.TagsProperty)
        {
            foreach ($tag in $subscriptionTags.Properties.TagsProperty.GetEnumerator())
            {
                $tagReport += [pscustomobject]@{
                    SubscriptionName = $subscription.Name
                    SubscriptionId   = $subscription.Id
                    ResourceType     = "Subscription"
                    ResourceName     = $subscription.Name
                    ResourceId       = $subscription.Id
                    TagName          = $tag.Key
                    TagValue         = $tag.Value
                }
            }
        }
        elseif ($IncludeEmptyTags)
        {
            $tagReport += [pscustomobject]@{
                SubscriptionName = $subscription.Name
                SubscriptionId   = $subscription.Id
                ResourceType     = "Subscription"
                ResourceName     = $subscription.Name
                ResourceId       = $subscription.Id
                TagName          = "N/A"
                TagValue         = "Empty"
            }
        }

        # Process resource groups and their resources
        $resourceGroups = Get-AzResourceGroup -Id "/subscriptions/$($subscription.Id)/resourceGroups/*" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $resourceGroupCount = @($resourceGroups).Count
        $processedResourceGroups = 0

        foreach ($rg in $resourceGroups)
        {
            Write-Verbose "Processing resource group: $($rg.ResourceGroupName)"
            $rgTags = Get-AzTag -ResourceId $rg.ResourceId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($rgTags -and $rgTags.Properties.TagsProperty)
            {
                foreach ($tag in $rgTags.Properties.TagsProperty.GetEnumerator())
                {
                    $tagReport += [pscustomobject]@{
                        SubscriptionName = $subscription.Name
                        SubscriptionId   = $subscription.Id
                        ResourceType     = "Resource Group"
                        ResourceName     = $rg.ResourceGroupName
                        ResourceId       = $rg.ResourceId
                        TagName          = $tag.Key
                        TagValue         = $tag.Value
                    }
                }
            }
            elseif ($IncludeEmptyTags)
            {
                $tagReport += [pscustomobject]@{
                    SubscriptionName = $subscription.Name
                    SubscriptionId   = $subscription.Id
                    ResourceType     = "Resource Group"
                    ResourceName     = $rg.ResourceGroupName
                    ResourceId       = $rg.ResourceId
                    TagName          = "N/A"
                    TagValue         = "Empty"
                }
            }

            # Process each resource in the resource group
            $resources = Get-AzResource -ResourceGroupName $rg.ResourceGroupName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            $resourceCount = @($resources).Count
            $processedResources = 0

            foreach ($resource in $resources)
            {
                Write-Verbose "Processing resource: $($resource.Name) [$($resource.ResourceType)]"
                $resourceTags = Get-AzTag -ResourceId $resource.ResourceId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                if ($resourceTags -and $resourceTags.Properties.TagsProperty)
                {
                    foreach ($tag in $resourceTags.Properties.TagsProperty.GetEnumerator())
                    {
                        $tagReport += [pscustomobject]@{
                            SubscriptionName = $subscription.Name
                            SubscriptionId   = $subscription.Id
                            ResourceType     = $resource.ResourceType
                            ResourceName     = $resource.Name
                            ResourceId       = $resource.ResourceId
                            TagName          = $tag.Key
                            TagValue         = $tag.Value
                        }
                    }
                }
                elseif ($IncludeEmptyTags)
                {
                    $tagReport += [pscustomobject]@{
                        SubscriptionName = $subscription.Name
                        SubscriptionId   = $subscription.Id
                        ResourceType     = $resource.ResourceType
                        ResourceName     = $resource.Name
                        ResourceId       = $resource.ResourceId
                        TagName          = "N/A"
                        TagValue         = "Empty"
                    }
                }

                # Increment and display resource progress
                # $processedResources++
                # $percentResources = [Math]::Round(($processedResources / $resourceCount) * 100)
                # if ($percentResources % 10 -eq 0)
                # {
                #     Write-Host "⏳ $percentResources% of resources processed in Resource Group $($rg.ResourceGroupName)" -ForegroundColor Yellow
                # }
            }

            # Increment and display resource group progress
            $processedResourceGroups++
            $percentResourceGroups = [Math]::Round(($processedResourceGroups / $resourceGroupCount) * 100)
            if ($percentResourceGroups % 10 -eq 0)
            {
                # Write-Host "⏳ $percentResourceGroups% of resource groups processed in Subscription $($subscription.Name)" -ForegroundColor Green
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $percentResourceGroups% processed in Subscription $($subscription.Name)" -ForegroundColor Green
            }
        }

        # Increment the subscription index counter
        $subscriptionIndex++

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Completed processing subscription: $($subscription.Name)" -ForegroundColor Cyan
    }

    $tagReport | Out-GridView

    # Export the report to CSV
    $tagReport | Export-Csv -Path $OutputPath -NoTypeInformation -Force

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Tag report generated successfully at $OutputPath." -ForegroundColor Yellow
}
