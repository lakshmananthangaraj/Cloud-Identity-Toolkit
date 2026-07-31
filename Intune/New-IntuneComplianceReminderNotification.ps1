<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 31 July 2026
Modified-On     : 31 July 2026

.SYNOPSIS
    Sends a proactive compliance reminder (email or Teams) to users whose
    devices are heading toward non-compliance, using the Microsoft Graph
    API.

.DESCRIPTION
    Identifies devices in Intune's 'inGracePeriod' compliance state -
    Microsoft's own signal that a device has failed one or more
    compliance checks but is still within the configured grace window
    before enforcement action (e.g. Conditional Access block) kicks in.
    For each such device, resolves the primary user and sends a reminder
    through one of two channels:

        Email         - Microsoft Graph sendMail, sent from a specified
                        shared/service mailbox on the user's behalf
        TeamsWebhook  - An Adaptive Card summary posted to a Teams channel
                        via an Incoming Webhook connector (does not
                        require Mail.Send or Chat.* Graph permissions)

    This function is access-adjacent (it sends unsolicited communications
    to end users) and therefore implements SupportsShouldProcess. Running
    without -Confirm:$false or without explicitly confirming will prompt
    per notification; running with -WhatIf performs a full dry run and
    reports exactly what would be sent without sending anything.

    Handles pagination automatically via @odata.nextLink, retries on API
    throttling (HTTP 429) using the Retry-After header, and validates the
    JSON response before processing. Per-device failures are logged as
    warnings and do not abort the run - one failed notification does not
    stop the rest of the batch.

.PARAMETER AccessToken
    A valid OAuth 2.0 Bearer token for Microsoft Graph API.
    Required permissions:
        DeviceManagementManagedDevices.Read.All
        Mail.Send (Application, if -NotificationChannel Email is used -
            requires application access policy scoping to -FromMailbox)

    To obtain this token via app-only authentication instead of an
    interactive/delegated flow, refer to:
    Connect-EntraID.ps1 (https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1)

.PARAMETER NotificationChannel
    Mandatory. Delivery channel for the reminder.
    Supported values:
        Email        - Requires -FromMailbox
        TeamsWebhook - Requires -TeamsWebhookUrl

.PARAMETER FromMailbox
    Mandatory when -NotificationChannel is 'Email'. The SMTP address of
    the shared/service mailbox the reminder will be sent from via Graph
    sendMail (application permission, scoped via an Exchange Online
    application access policy to this mailbox only).

.PARAMETER TeamsWebhookUrl
    Mandatory when -NotificationChannel is 'TeamsWebhook'. The Incoming
    Webhook URL for the Teams channel that should receive a single
    summary card listing all at-risk devices/users in this run (one
    webhook post per run, not per device, to avoid channel spam).

.PARAMETER GracePeriodMessage
    Optional. Custom reminder message body. If omitted, a default message
    explaining the device is in a compliance grace period and prompting
    the user to resolve it is used.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Array
        An array of custom objects showing each device/user notified (or,
        under -WhatIf, that would have been notified), delivery channel,
        and send result.

.EXAMPLE
    New-IntuneComplianceReminderNotification -AccessToken $token -NotificationChannel Email -FromMailbox 'itnotify@contoso.com' -WhatIf

    Dry run - shows exactly which users would receive an email reminder
    without sending anything.

.EXAMPLE
    New-IntuneComplianceReminderNotification -AccessToken $token -NotificationChannel TeamsWebhook -TeamsWebhookUrl 'https://contoso.webhook.office.com/...' -Confirm:$false

    Posts a single summary card of all at-risk devices to the configured
    Teams channel without an interactive confirmation prompt.

.NOTES
    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
    1.0 (31-Jul-2026) - Initial release

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
    1. A valid Microsoft Graph access token with the following
       permissions:
            DeviceManagementManagedDevices.Read.All (Application or Delegated)
            Mail.Send (Application, scoped via an Exchange Online
                application access policy to -FromMailbox only - do not
                grant tenant-wide Mail.Send for this use case)
    2. For -NotificationChannel TeamsWebhook: an Incoming Webhook
       connector configured on the target Teams channel.
    3. PowerShell 5.1 or later.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
    - Uses the /beta Graph API endpoint for the managedDevices query.
      Beta endpoints are subject to change and are not recommended for
      production without monitoring for breaking changes.
    - "Heading toward non-compliance" is detected via Intune's
      complianceState = 'inGracePeriod' value. This depends on your
      compliance policies having a non-zero grace period configured; if
      your policies enforce immediately (0-day grace period), devices
      will skip this state entirely and this function will not catch
      them before they go non-compliant. Consider pairing with
      Get-IntuneNonCompliantDevice.ps1 for a full before/after picture.
    - Devices with no resolvable primary user (see Get-PrimaryUser.ps1)
      are skipped with a warning, since there is no one to notify.
    - Email channel sends one message per user per run - re-running this
      function daily without de-duplication logic will re-notify the same
      user daily as long as they remain in grace period. Consider adding
      a suppression/state-tracking mechanism (e.g. a CSV or table of
      already-notified device IDs with a timestamp) before scheduling
      this unattended.
    - This function does NOT verify mailbox send-as rights or webhook
      reachability in advance - a misconfigured -FromMailbox or
      -TeamsWebhookUrl will surface as a per-notification failure in the
      output, not a pre-flight error.

.LINK
    Microsoft Graph API - sendMail action
    https://learn.microsoft.com/en-us/graph/api/user-sendmail

.LINK
    Microsoft Teams - Incoming Webhook connectors
    https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook

.LINK
    Connect-EntraID.ps1 (required for app-only authentication)
    https://github.com/lakshmananthangaraj/Cloud-Identity-Toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1

#>


Function New-IntuneComplianceReminderNotification
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Email', 'TeamsWebhook')]
        [string]$NotificationChannel,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
        [string]$FromMailbox,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^https://[a-zA-Z0-9\.\-]+\.webhook\.office\.com/.+$')]
        [string]$TeamsWebhookUrl,

        [Parameter(Mandatory = $false)]
        [string]$GracePeriodMessage = "Your device is currently in a compliance grace period. Please resolve the outstanding compliance issue(s) before the grace period ends to avoid losing access to corporate resources. Contact IT support if you need assistance."
    )

    if ($NotificationChannel -eq 'Email' -and -not $FromMailbox)
    {
        Write-Error "-FromMailbox is required when -NotificationChannel is 'Email'. Exiting function."
        return
    }
    if ($NotificationChannel -eq 'TeamsWebhook' -and -not $TeamsWebhookUrl)
    {
        Write-Error "-TeamsWebhookUrl is required when -NotificationChannel is 'TeamsWebhook'. Exiting function."
        return
    }

    function Invoke-GraphGetWithRetry
    {
        param ([string]$Uri, [hashtable]$Headers)

        do
        {
            Try
            {
                $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
                $statusCode = $response.StatusCode
            }
            catch
            {
                $statusCode = $_.Exception.Response.StatusCode
                $ErrorObject = $_

                if ($statusCode -eq 429)
                {
                    $sleepTime = $_.Exception.Response.Headers.Item("Retry-After")
                    Write-Host "Throttled. Waiting for $sleepTime seconds" -ForegroundColor Cyan
                    Start-Sleep -Seconds $sleepTime
                }
                else
                {
                    $ErrorOutput = [PSCustomObject][ordered]@{
                        Response   = $($ErrorObject.Exception.Response)
                        StatusCode = $($ErrorObject.Exception.Response.StatusCode)
                        Message    = $($ErrorObject.Exception.Message)
                    }
                    $ErrorOutput | Format-List
                    return $null
                }
            }
        } until ($statusCode -eq 200 -or -not $response)

        return $response
    }

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    # Step 1: retrieve devices in grace period
    $atRiskDevices = New-Object System.Collections.ArrayList
    $totalDevices = 0
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$top=100&`$filter=complianceState eq 'inGracePeriod'&`$select=id,deviceName,operatingSystem,userId,userPrincipalName,userDisplayName,emailAddress"

    do
    {
        $partialData = Invoke-GraphGetWithRetry -Uri $uri -Headers $headers
        if (-not $partialData) { Write-Error "Failed to retrieve at-risk devices page. Aborting."; return }

        $deviceData = $partialData.Content | ConvertFrom-Json
        Write-Host ""
        Write-Host "Progress: $($totalDevices += $deviceData.value.Count; $totalDevices) grace-period devices found so far" -ForegroundColor Cyan

        if ($deviceData.PSObject.Properties['@odata.nextLink']) { $uri = $deviceData.'@odata.nextLink' }

        $deviceData.value | ForEach-Object { $null = $atRiskDevices.Add($_) }

    } until (-not ($deviceData.PSObject.Properties['@odata.nextLink']))

    if ($atRiskDevices.Count -eq 0)
    {
        Write-Host "No devices currently in a compliance grace period. Nothing to notify." -ForegroundColor Green
        return @()
    }

    $results = New-Object System.Collections.ArrayList

    if ($NotificationChannel -eq 'Email')
    {
        foreach ($device in $atRiskDevices)
        {
            if (-not $device.userPrincipalName)
            {
                Write-Warning "Skipping device '$($device.deviceName)': no resolvable primary user."
                continue
            }

            $target = "$($device.deviceName) → $($device.userPrincipalName)"

            if ($PSCmdlet.ShouldProcess($target, "Send compliance grace-period email reminder"))
            {
                $mailBody = @{
                    message = @{
                        subject      = "Action needed: $($device.deviceName) is in a compliance grace period"
                        body         = @{
                            contentType = "Text"
                            content     = "$GracePeriodMessage`n`nDevice: $($device.deviceName)`nOperating System: $($device.operatingSystem)"
                        }
                        toRecipients = @(
                            @{ emailAddress = @{ address = $device.userPrincipalName } }
                        )
                    }
                    saveToSentItems = "false"
                }

                try
                {
                    $sendUri = "https://graph.microsoft.com/v1.0/users/$FromMailbox/sendMail"
                    $null = Invoke-WebRequest -Uri $sendUri -Headers $headers -Method Post `
                        -Body ($mailBody | ConvertTo-Json -Depth 5) -ContentType "application/json" -ErrorAction Stop

                    $null = $results.Add([PSCustomObject]@{
                        DeviceName = $device.deviceName
                        UserUPN    = $device.userPrincipalName
                        Channel    = 'Email'
                        Result     = 'Sent'
                    })
                }
                catch
                {
                    Write-Warning "Failed to send email reminder for '$($device.deviceName)': $($_.Exception.Message)"
                    $null = $results.Add([PSCustomObject]@{
                        DeviceName = $device.deviceName
                        UserUPN    = $device.userPrincipalName
                        Channel    = 'Email'
                        Result     = "Failed: $($_.Exception.Message)"
                    })
                }
            }
            else
            {
                $null = $results.Add([PSCustomObject]@{
                    DeviceName = $device.deviceName
                    UserUPN    = $device.userPrincipalName
                    Channel    = 'Email'
                    Result     = 'Skipped (WhatIf/declined)'
                })
            }
        }
    }
    elseif ($NotificationChannel -eq 'TeamsWebhook')
    {
        $target = "Teams channel summary card ($($atRiskDevices.Count) device(s))"

        if ($PSCmdlet.ShouldProcess($target, "Post compliance grace-period summary to Teams webhook"))
        {
            $factList = $atRiskDevices | ForEach-Object {
                @{ name = $_.deviceName; value = "$($_.userPrincipalName) ($($_.operatingSystem))" }
            }

            $card = @{
                "@type"    = "MessageCard"
                "@context" = "http://schema.org/extensions"
                themeColor = "FFA500"
                summary    = "Intune Compliance Grace Period Alert"
                sections   = @(
                    @{
                        activityTitle = "Devices in Compliance Grace Period"
                        text          = $GracePeriodMessage
                        facts         = $factList
                    }
                )
            }

            try
            {
                $null = Invoke-WebRequest -Uri $TeamsWebhookUrl -Method Post `
                    -Body ($card | ConvertTo-Json -Depth 6) -ContentType "application/json" -ErrorAction Stop

                foreach ($device in $atRiskDevices)
                {
                    $null = $results.Add([PSCustomObject]@{
                        DeviceName = $device.deviceName
                        UserUPN    = $device.userPrincipalName
                        Channel    = 'TeamsWebhook'
                        Result     = 'Included in posted summary card'
                    })
                }
            }
            catch
            {
                Write-Warning "Failed to post Teams webhook summary: $($_.Exception.Message)"
                foreach ($device in $atRiskDevices)
                {
                    $null = $results.Add([PSCustomObject]@{
                        DeviceName = $device.deviceName
                        UserUPN    = $device.userPrincipalName
                        Channel    = 'TeamsWebhook'
                        Result     = "Failed: $($_.Exception.Message)"
                    })
                }
            }
        }
        else
        {
            foreach ($device in $atRiskDevices)
            {
                $null = $results.Add([PSCustomObject]@{
                    DeviceName = $device.deviceName
                    UserUPN    = $device.userPrincipalName
                    Channel    = 'TeamsWebhook'
                    Result     = 'Skipped (WhatIf/declined)'
                })
            }
        }
    }

    return $results | Format-Table -AutoSize
}
