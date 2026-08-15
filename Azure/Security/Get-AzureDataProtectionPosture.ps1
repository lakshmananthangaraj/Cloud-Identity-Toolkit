<#

Author          : Lakshmanan Thangaraj
Version         : 1.0
Created-On      : 15 August 2026
Modified-On     : 15 August 2026

.SYNOPSIS
    Assesses the data protection posture of Azure data services — encryption,
    sensitivity classification, network access, backup, retention, access controls,
    and audit logging — producing prioritised architectural findings, risk statements,
    and actionable recommendations.

.DESCRIPTION
    Get-AzureDataProtectionPosture evaluates Azure data services from a Cloud
    Solution Architect / Azure Security Architect perspective. It identifies
    meaningful data protection gaps, architectural weaknesses, and missing layers
    of control that carry real regulatory, compliance, and business risk.

    Assessment domains:

      Encryption at Rest
        - Customer-Managed Key (CMK) vs Microsoft-Managed Key (MMK) on Storage
          Accounts, SQL Databases, Cosmos DB accounts, and managed disks
        - Transparent Data Encryption (TDE) status on Azure SQL Databases
        - Azure Disk Encryption on VM OS/data disks where applicable
        - Double encryption (infrastructure encryption) on storage accounts for
          highly sensitive data

      Network Access & Isolation
        - Public network access state on Storage Accounts, SQL Servers, Cosmos DB,
          Azure Database for PostgreSQL/MySQL, and Key Vault
        - Storage Account network ACL default action (Allow vs Deny)
        - Private Endpoint adoption: data services with public endpoints expose
          data-plane access to the internet, even when authentication is required
        - Shared Access Signature (SAS) token controls: storage accounts with
          unrestricted SAS policy (no IP restriction, no expiry enforcement)

      Access Control & Authentication
        - Storage Account Shared Key access enabled vs Azure AD-only access
          (shared keys bypass RBAC and Conditional Access)
        - Azure AD authentication enforcement on SQL servers vs SQL authentication
          only (password-based, no MFA, no Conditional Access)
        - Anonymous blob access enabled on Storage Accounts
        - Cosmos DB local authentication (master key) disabled flag

      Backup & Recovery
        - Azure Backup protection status for SQL databases and Storage Accounts
        - SQL database backup retention policy (short retention = narrow recovery window)
        - Storage Account soft delete for blobs, containers, and file shares
        - Cosmos DB continuous backup and point-in-time restore configuration

      Sensitivity & Classification
        - Azure Purview / Microsoft Purview scan coverage: data stores that have
          never been scanned have unknown data sensitivity
        - SQL Advanced Data Security / Microsoft Defender for SQL enablement —
          without this, sensitive data columns are unclassified and data access
          anomalies are not detected
        - Storage Account diagnostic logs: data access without audit logs is
          undetectable, a core requirement for data breach investigation

      Retention & Lifecycle
        - SQL Auditing long-term retention: Azure SQL audit logs retained < 90 days
          fail most compliance frameworks (SOC 2, ISO 27001, PCI-DSS require >= 90 days)
        - Storage lifecycle policy presence: data with no lifecycle policy may
          retain sensitive data in hot tier indefinitely beyond its useful life

    Each finding includes:
        - Severity    : Critical / High / Medium / Low / Info
        - Category    : Encryption | Network | Access | Backup | Classification | Audit
        - Resource    : Specific Azure resource name and type
        - Gap         : What is missing or misconfigured
        - Risk        : Why this matters — regulatory, architectural, and business impact
        - Recommendation : Concrete remediation action

    Scope:
        - All subscriptions visible to the authenticated account (-AllSubscriptions)
        - A specific list of subscription IDs (-SubscriptionIds)

    Outputs:
        - Real-time progress and colour-coded per-resource output
        - Always-on HTML dashboard with findings table, severity donut, category
          breakdown, and per-finding detail drawer with risk / recommendation
        - Optional CSV export of all findings

.PARAMETER AllSubscriptions
    Switch. Scans every subscription visible to the authenticated account.
    Default when -SubscriptionIds is not provided.

.PARAMETER SubscriptionIds
    String array of specific subscription IDs to scan. Ignored when
    -AllSubscriptions is also specified.

.PARAMETER ExportToCsv
    Switch. Exports all findings to the path given in -CsvPath.
    The HTML dashboard is always generated regardless of this switch.

.PARAMETER CsvPath
    Destination path for the CSV export and HTML dashboard.
    Default: C:\Temp\AzureDataProtectionPosture-Report.csv

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    Always writes an HTML dashboard. Optionally writes a CSV when -ExportToCsv
    is specified. Opens Grid View where a GUI is available.

.EXAMPLE
    Get-AzureDataProtectionPosture -AllSubscriptions

.EXAMPLE
    Get-AzureDataProtectionPosture -SubscriptionIds @("sub-id-1","sub-id-2") -ExportToCsv

.EXAMPLE
    Get-AzureDataProtectionPosture -AllSubscriptions -ExportToCsv -CsvPath "C:\Reports\DataProtection.csv"

.NOTES

    ─────────────────────────────────────────────────────────────────────────────
    Version History:
    ─────────────────────────────────────────────────────────────────────────────
        1.0 (15-Aug-2026) - Initial release. Assessment of Storage Accounts,
                            Azure SQL, Cosmos DB, and supporting controls:
                            encryption, network isolation, access model, backup,
                            audit logging, and data classification coverage.
                            Prioritised findings with risk statements and
                            recommendations. CSV export and HTML dashboard.

    ─────────────────────────────────────────────────────────────────────────────
    Pre-Requisites:
    ─────────────────────────────────────────────────────────────────────────────
        1. Az PowerShell module (Az.Accounts, Az.Resources, Az.Storage, Az.Sql,
           Az.CosmosDB, Az.Monitor) — installation offered automatically.
        2. Authenticated Azure session (Connect-AzAccount).
        3. Reader role at subscription scope (minimum).
        4. Microsoft.Storage/storageAccounts/blobServices/read is required to
           assess blob soft delete. Missing permissions produce a graceful skip.
        5. Microsoft.Sql/servers/databases/read and
           Microsoft.Sql/servers/auditingSettings/read are required for SQL
           assessment. Missing permissions are recorded as "Could Not Assess".
        6. Microsoft.DocumentDB/databaseAccounts/read is required for Cosmos DB
           assessment.

    ─────────────────────────────────────────────────────────────────────────────
    Known Limitations:
    ─────────────────────────────────────────────────────────────────────────────
        - Microsoft Purview scan coverage detection uses the Azure Resource Graph
          to check for registered data sources. Environments without Purview
          provisioned will show all data stores as unscanned, which is accurate
          but may generate noise if Purview adoption is a planned roadmap item.
        - SQL Advanced Data Security classification detail (which columns are
          classified) requires the SQL Information Protection API and is not
          assessed here — only whether Defender for SQL is enabled is checked.
        - Cosmos DB backup policy details (continuous vs periodic, retention)
          require the databaseAccounts/read permission at control plane — the
          data-plane backup cannot be assessed without additional permissions.
        - Storage Account SAS policy is a control-plane setting; individual SAS
          tokens issued and in circulation cannot be enumerated or revoked from
          the management plane.
        - Azure Database for PostgreSQL / MySQL Flexible Server assessment covers
          network access and AD-only authentication but not column-level encryption
          or row-level security, which are assessed at the database engine level.

.LINK
    https://learn.microsoft.com/en-us/azure/storage/common/storage-security-guide
    https://learn.microsoft.com/en-us/azure/azure-sql/database/security-overview
    https://learn.microsoft.com/en-us/azure/cosmos-db/secure-access-to-data
    https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-introduction
    https://learn.microsoft.com/en-us/azure/backup/backup-overview

#>


#------------------------------------------------------------------------ [ Severity Order ]

$script:SevOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }


#------------------------------------------------------------------------ [ Helper Functions ]

Function Write-CenteredText {
    param([string]$Text, [int]$Width = 80, [string]$Color = "White")
    $padding = [math]::Max(0, ($Width - $Text.Length) / 2)
    Write-Host (" " * $padding) -NoNewline
    Write-Host $Text -ForegroundColor $Color
}

Function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-CenteredText "Azure Data Protection Posture Assessment v1.0" -Color White
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function Write-Section {
    param([string]$Title, [hashtable]$Data)
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    foreach ($key in $Data.Keys) {
        $value = $Data[$key]
        $valColor = if ([string]::IsNullOrWhiteSpace($value)) { $value = "None"; "DarkGray" } else { "White" }
        Write-Host "  " -NoNewline
        Write-Host $key.PadRight(28) -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline -ForegroundColor DarkGray
        Write-Host $value -ForegroundColor $valColor
    }
}

Function Write-ScanProgress {
    Write-Host ""
    Write-Host "  Scanning Data Services" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host ""
}

Function Write-ProgressBar {
    param([int]$Current, [int]$Total, [string]$CurrentItem, [int]$BarWidth = 40)
    $pct = [math]::Round(($Current / [math]::Max($Total, 1)) * 100)
    $completed = [math]::Floor($BarWidth * $Current / [math]::Max($Total, 1))
    $bar = ("█" * $completed) + ("░" * ($BarWidth - $completed))
    Write-Host "`r" -NoNewline
    Write-Host "  Progress: " -NoNewline -ForegroundColor Gray
    Write-Host $bar -NoNewline -ForegroundColor Cyan
    Write-Host (" {0,3}% ({1}/{2})" -f $pct, $Current, $Total) -NoNewline -ForegroundColor White
    if ($CurrentItem) {
        $disp = if ($CurrentItem.Length -gt 35) { $CurrentItem.Substring(0, 32) + "..." } else { $CurrentItem }
        Write-Host " | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Current: " -NoNewline -ForegroundColor Gray
        Write-Host $disp -NoNewline -ForegroundColor Cyan
    }
}

Function Write-FindingSummary {
    param([array]$Findings)
    $sevCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in $Findings) { if ($sevCounts.ContainsKey($f.Severity)) { $sevCounts[$f.Severity]++ } }

    Write-Host ""
    Write-Host "  Finding Summary" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    Write-Host "  Critical".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($sevCounts.Critical)" -ForegroundColor Red
    Write-Host "  High    ".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($sevCounts.High)" -ForegroundColor Yellow
    Write-Host "  Medium  ".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($sevCounts.Medium)" -ForegroundColor Cyan
    Write-Host "  Low     ".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($sevCounts.Low)" -ForegroundColor DarkGray
    Write-Host "  Info    ".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($sevCounts.Info)" -ForegroundColor DarkGray
    Write-Host "  ──────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Total   ".PadRight(30) -NoNewline -ForegroundColor Gray
    Write-Host ": $($Findings.Count)" -ForegroundColor White
}

Function Write-OutputFiles {
    param([string]$CsvPath, [string]$HtmlPath, [bool]$GridViewOpened)
    Write-Host ""
    Write-Host "  Output Files" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host ("─" * 76) -ForegroundColor DarkGray
    if ($CsvPath) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("CSV Export").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $CsvPath" -ForegroundColor White
    }
    if ($HtmlPath) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("HTML Dashboard").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": $HtmlPath" -ForegroundColor White
    }
    if ($GridViewOpened) {
        Write-Host "  " -NoNewline
        Write-Host "✓ " -NoNewline -ForegroundColor Green
        Write-Host ("Grid View").PadRight(22) -NoNewline -ForegroundColor Gray
        Write-Host ": Opened in separate window" -ForegroundColor White
    }
    Write-Host ""
    Write-Host ("═" * 80) -ForegroundColor Cyan
    Write-Host ""
}

Function New-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$ResourceName,
        [string]$ResourceType,
        [string]$ResourceGroup,
        [string]$SubscriptionName,
        [string]$Gap,
        [string]$Risk,
        [string]$Recommendation,
        [string]$ResourceId = ""
    )
    [pscustomobject]@{
        Severity         = $Severity
        Category         = $Category
        ResourceName     = $ResourceName
        ResourceType     = $ResourceType
        ResourceGroup    = $ResourceGroup
        SubscriptionName = $SubscriptionName
        Gap              = $Gap
        Risk             = $Risk
        Recommendation   = $Recommendation
        ResourceId       = $ResourceId
    }
}

Function Get-ObjProperty {
    param([object]$Obj, [string]$PropName, $Default = $null)
    try {
        $val = $Obj.$PropName
        if ($null -ne $val) { return $val }
        return $Default
    }
    catch { return $Default }
}


#------------------------------------------------------------------------ [ HTML Generation ]

Function EscHtml { param([string]$s); return $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
Function EscJ { param([string]$s); return $s -replace '\\', '\\\\' -replace "'", "\'" -replace '"', '\"' -replace "`n", ' ' -replace "`r", ' ' }

Function Generate-DataProtectionHtml {
    param(
        [hashtable]$SessionInfo,
        [hashtable]$ScanParameters,
        [array]$Findings,
        [array]$SubscriptionResults,
        [string]$GeneratedOn
    )

    $totalFindings = @($Findings).Count
    $criticalCount = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = @($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = @($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount = @($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
    $infoCount = @($Findings | Where-Object { $_.Severity -eq 'Info' }).Count

    # Category breakdown bars
    $catGroups = $Findings | Group-Object Category | Sort-Object Count -Descending
    $catRows = ""
    foreach ($cg in $catGroups) {
        $pct = if ($totalFindings -gt 0) { [math]::Round(($cg.Count / $totalFindings) * 100) } else { 0 }
        $catRows += @"
          <div class="bar-row">
            <span class="bar-label">$(EscHtml $cg.Name)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($cg.Count) ($pct%)</span>
          </div>
"@
    }

    # Resource type breakdown bars
    $typeGroups = $Findings | Group-Object ResourceType | Sort-Object Count -Descending | Select-Object -First 8
    $typeRows = ""
    foreach ($tg in $typeGroups) {
        $pct = if ($totalFindings -gt 0) { [math]::Round(($tg.Count / $totalFindings) * 100) } else { 0 }
        $shortType = if ($tg.Name.Length -gt 35) { $tg.Name.Split('/')[-1] } else { $tg.Name }
        $typeRows += @"
          <div class="bar-row">
            <span class="bar-label" title="$(EscHtml $tg.Name)">$(EscHtml $shortType)</span>
            <div class="bar-track"><div class="bar-fill" data-pct="$pct"></div></div>
            <span class="bar-pct">$($tg.Count) ($pct%)</span>
          </div>
"@
    }

    # Severity donut
    $donutColors = @{ Critical = '#f85149'; High = '#d29922'; Medium = '#388bfd'; Low = '#3fb950'; Info = '#7d8590' }
    $donutData = @(
        @{ label = 'Critical'; count = $criticalCount; color = $donutColors.Critical },
        @{ label = 'High'; count = $highCount; color = $donutColors.High },
        @{ label = 'Medium'; count = $mediumCount; color = $donutColors.Medium },
        @{ label = 'Low'; count = $lowCount; color = $donutColors.Low },
        @{ label = 'Info'; count = $infoCount; color = $donutColors.Info }
    )
    $r = 54
    $circ = 2 * [math]::PI * $r
    $donutSegs = ""
    $legendItems = ""
    $offset = 0
    foreach ($d in $donutData) {
        if ($d.count -le 0) { continue }
        $arc = if ($totalFindings -gt 0) { $circ * $d.count / $totalFindings } else { 0 }
        $gap = $circ - $arc
        $donutSegs += "<circle cx='70' cy='70' r='$r' fill='none' stroke='$($d.color)' stroke-width='14' stroke-dasharray='$([math]::Round($arc,2)) $([math]::Round($gap,2))' stroke-dashoffset='$([math]::Round(-$offset,2))' />`n"
        $offset += $arc
        $legendItems += @"
          <div class="legend-item">
            <span class="legend-dot" style="background:$($d.color)"></span>
            <span>$(EscHtml $d.label)</span>
            <span style="margin-left:auto;font-family:var(--mono);font-weight:600">$($d.count)</span>
          </div>
"@
    }

    # Findings table rows (sorted by severity)
    $sortedFindings = $Findings | Sort-Object { $script:SevOrder[$_.Severity] }, Category, ResourceName
    $findingRows = ""
    $idx = 0
    foreach ($f in $sortedFindings) {
        $sevCls = switch ($f.Severity) {
            'Critical' { 'badge-red' }
            'High' { 'badge-amber' }
            'Medium' { 'badge-blue' }
            'Low' { 'badge-green' }
            default { 'badge-muted' }
        }
        $gapShort = if ($f.Gap.Length -gt 60) { EscHtml($f.Gap.Substring(0, 57) + "...") } else { EscHtml $f.Gap }
        $nameShort = if ($f.ResourceName.Length -gt 28) { EscHtml($f.ResourceName.Substring(0, 25) + "...") } else { EscHtml $f.ResourceName }
        $findingRows += @"
          <tr onclick="showDetail($idx)">
            <td><span class="badge $(EscHtml $sevCls)">$(EscHtml $f.Severity)</span></td>
            <td><span class="cat-tag">$(EscHtml $f.Category)</span></td>
            <td title="$(EscHtml $f.ResourceName)">$nameShort</td>
            <td style="font-size:11px;color:var(--muted2)">$(EscHtml $f.ResourceType.Split('/')[-1])</td>
            <td>$(EscHtml $f.SubscriptionName)</td>
            <td title="$(EscHtml $f.Gap)">$gapShort</td>
          </tr>
"@
        $idx++
    }

    # Subscription scan results
    $subRows = ""
    foreach ($s in $SubscriptionResults) {
        $icon = switch ($s.Status) { "Success" { "✓" }; "Warning" { "⚠" }; "Error" { "✗" }; default { "•" } }
        $cls = switch ($s.Status) { "Success" { "c-green" }; "Warning" { "c-amber" }; "Error" { "c-red" }; default { "" } }
        $subRows += @"
          <div class="sub-row">
            <span class="sub-icon $cls">$icon</span>
            <span class="sub-name">$(EscHtml $s.Name)</span>
            <span class="sub-detail">$(EscHtml $s.Summary)</span>
          </div>
"@
    }

    # JSON for detail drawer
    $findingsJson = "["
    foreach ($f in $sortedFindings) {
        $findingsJson += "{" +
        """sev"":""$(EscJ $f.Severity)""," +
        """cat"":""$(EscJ $f.Category)""," +
        """name"":""$(EscJ $f.ResourceName)""," +
        """type"":""$(EscJ $f.ResourceType)""," +
        """rg"":""$(EscJ $f.ResourceGroup)""," +
        """sub"":""$(EscJ $f.SubscriptionName)""," +
        """gap"":""$(EscJ $f.Gap)""," +
        """risk"":""$(EscJ $f.Risk)""," +
        """rec"":""$(EscJ $f.Recommendation)""" +
        "},"
    }
    $findingsJson = $findingsJson.TrimEnd(",") + "]"

    $html = @'
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Azure Data Protection Posture</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#243048;
  --border:#30363d;--accent:#388bfd;--accent2:#39c5cf;--accent3:#a371f7;
  --green:#3fb950;--amber:#d29922;--red:#f85149;
  --text:#e6edf3;--muted:#7d8590;--muted2:#adbac7;
  --mono:'JetBrains Mono','Consolas','Courier New',monospace;
  --sans:'Calibri','Segoe UI',Tahoma,Geneva,sans-serif;
  --radius:10px;--radius-sm:6px;--shadow:0 4px 24px rgba(0,0,0,.5);
}
html[data-theme="light"]{
  --bg:#f6f8fa;--surface:#fff;--surface2:#f0f3f6;--surface3:#e4e9ef;
  --border:#d0d7de;--accent:#0969da;--accent2:#0284a8;--accent3:#7c3aed;
  --green:#1a7f37;--amber:#b08000;--red:#cf222e;
  --text:#1f2328;--muted:#636c76;--muted2:#424a53;
  --shadow:0 4px 24px rgba(0,0,0,.12);
}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;display:flex;}
#sidebar{width:240px;min-height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:transform .25s;}
.logo-block{padding:22px 18px 16px;border-bottom:1px solid var(--border);}
.logo-icon{width:38px;height:38px;border-radius:8px;background:linear-gradient(135deg,#a371f7,#388bfd);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:10px;}
.logo-title{font-size:13px;font-weight:700;line-height:1.3;}
.logo-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.version-badge{display:inline-block;margin-top:8px;padding:2px 8px;border-radius:20px;font-size:10px;font-family:var(--mono);background:var(--surface3);color:var(--accent);border:1px solid var(--border);}
.nav-section{padding:14px 10px;flex:1;}
.nav-label{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;padding:0 8px;margin-bottom:6px;}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:9px 12px;border:none;background:transparent;color:var(--muted2);font-size:13px;border-radius:var(--radius-sm);cursor:pointer;text-align:left;transition:background .15s,color .15s;position:relative;margin-bottom:2px;}
.nav-btn:hover{background:var(--surface2);color:var(--text);}
.nav-btn.active{background:var(--surface3);color:var(--accent);font-weight:600;}
.nav-btn.active::before{content:'';position:absolute;left:0;top:20%;bottom:20%;width:3px;background:var(--accent);border-radius:0 3px 3px 0;}
.nav-icon{font-size:16px;width:20px;text-align:center;}
.sidebar-footer{padding:14px 16px;border-top:1px solid var(--border);}
.theme-toggle{display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:10px;}
.toggle-pill{width:40px;height:22px;border-radius:11px;border:none;cursor:pointer;background:var(--surface3);position:relative;transition:background .2s;}
.toggle-pill::after{content:'';position:absolute;top:3px;left:3px;width:16px;height:16px;border-radius:50%;background:var(--accent);transition:transform .2s;}
html[data-theme="light"] .toggle-pill::after{transform:translateX(18px);}
.footer-meta{font-size:10px;color:var(--muted);line-height:1.6;}
#main{margin-left:240px;padding:28px;width:calc(100% - 240px);min-height:100vh;}
.page{display:none;animation:fadeIn .2s ease;}
.page.active{display:block;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px);}to{opacity:1;transform:none;}}
.page-header{margin-bottom:22px;}
.page-title{font-size:22px;font-weight:700;}
.page-sub{font-size:13px;color:var(--muted);margin-top:4px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:22px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 16px;border-top:3px solid;transition:transform .15s,box-shadow .15s;}
.stat-card:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.stat-card.c-red{border-top-color:var(--red);}
.stat-card.c-amber{border-top-color:var(--amber);}
.stat-card.c-blue{border-top-color:var(--accent);}
.stat-card.c-green{border-top-color:var(--green);}
.stat-card.c-muted{border-top-color:var(--muted);}
.stat-card.c-purple{border-top-color:var(--accent3);}
.stat-num{font-size:30px;font-weight:700;font-family:var(--mono);line-height:1;}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em;}
.stat-sub{font-size:11px;color:var(--muted2);margin-top:4px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:18px;}
.panel-title{font-size:14px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}
.bar-row{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);}
.bar-row:last-child{border-bottom:none;}
.bar-label{font-size:12px;color:var(--muted2);width:130px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;background:var(--accent);width:0;transition:width .8s ease;}
.bar-pct{font-size:12px;font-family:var(--mono);color:var(--muted2);width:80px;text-align:right;flex-shrink:0;}
.donut-wrap{display:flex;align-items:center;gap:28px;flex-wrap:wrap;}
.donut-svg-wrap{position:relative;width:140px;height:140px;flex-shrink:0;}
.donut-svg-wrap svg{transform:rotate(-90deg);}
.donut-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.donut-total{font-size:26px;font-weight:700;font-family:var(--mono);}
.donut-lbl{font-size:10px;color:var(--muted);margin-top:2px;}
.legend-list{display:flex;flex-direction:column;gap:10px;flex:1;}
.legend-item{display:flex;align-items:center;gap:10px;font-size:13px;}
.legend-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap;}
.search-wrap{position:relative;flex:1;min-width:200px;}
.search-wrap input{width:100%;padding:8px 12px 8px 34px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;outline:none;}
.search-wrap input:focus{border-color:var(--accent);}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--muted);font-size:14px;}
.filter-select{padding:7px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:12px;cursor:pointer;}
.tbl-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{padding:10px 12px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);background:var(--surface2);border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap;user-select:none;}
th:hover{color:var(--text);}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:middle;}
tr:hover td{background:var(--surface2);cursor:pointer;}
.pagination{display:flex;align-items:center;gap:8px;margin-top:12px;font-size:12px;color:var(--muted);flex-wrap:wrap;}
.pg-btn{padding:4px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;}
.pg-btn:hover{border-color:var(--accent);color:var(--accent);}
.pg-btn.active{background:var(--accent);color:#fff;border-color:var(--accent);}
.pg-btn:disabled{opacity:.4;cursor:not-allowed;}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-red{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.badge-amber{background:rgba(210,153,34,.15);color:var(--amber);border:1px solid rgba(210,153,34,.3);}
.badge-blue{background:rgba(56,139,253,.15);color:var(--accent);border:1px solid rgba(56,139,253,.3);}
.badge-green{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.badge-muted{background:var(--surface3);color:var(--muted);border:1px solid var(--border);}
.cat-tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;background:var(--surface3);color:var(--muted2);border:1px solid var(--border);white-space:nowrap;}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;}
.info-card{background:var(--surface2);border-radius:var(--radius-sm);padding:12px 14px;border:1px solid var(--border);}
.info-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px;}
.info-value{font-size:13px;font-family:var(--mono);word-break:break-all;}
.sub-list{display:flex;flex-direction:column;}
.sub-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);}
.sub-row:last-child{border-bottom:none;}
.sub-icon{font-size:16px;width:22px;text-align:center;}
.sub-icon.c-green{color:var(--green);}.sub-icon.c-amber{color:var(--amber);}.sub-icon.c-red{color:var(--red);}
.sub-name{flex:1;font-size:13px;font-weight:500;}
.sub-detail{font-size:12px;color:var(--muted2);font-family:var(--mono);}
#drawerBackdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:200;}
#detailDrawer{position:fixed;right:0;top:0;bottom:0;width:480px;max-width:95vw;background:var(--surface);border-left:1px solid var(--border);z-index:201;display:flex;flex-direction:column;transform:translateX(100%);transition:transform .25s ease;overflow:hidden;}
#detailDrawer.open{transform:translateX(0);}
.drawer-header{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between;flex-shrink:0;}
.drawer-title{font-size:13px;font-weight:700;word-break:break-word;line-height:1.4;}
.drawer-close{background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;padding:2px 6px;border-radius:var(--radius-sm);flex-shrink:0;}
.drawer-close:hover{color:var(--text);background:var(--surface2);}
.drawer-body{padding:20px;overflow-y:auto;flex:1;}
.drawer-nav{display:flex;gap:8px;align-items:center;margin-bottom:16px;}
.drawer-nav-btn{padding:5px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);cursor:pointer;font-size:12px;}
.drawer-nav-btn:hover{border-color:var(--accent);color:var(--accent);}
.drawer-nav-info{font-size:12px;color:var(--muted);flex:1;text-align:center;}
.detail-block{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px;margin-bottom:12px;font-size:13px;line-height:1.6;}
.detail-block.risk{border-left:3px solid var(--amber);}
.detail-block.rec{border-left:3px solid var(--green);}
.detail-block.gap{border-left:3px solid var(--red);}
.detail-lbl{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;}
#toast{position:fixed;bottom:24px;right:24px;padding:12px 18px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);font-size:13px;box-shadow:var(--shadow);opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:300;}
#toast.show{opacity:1;transform:translateY(0);}
#menuToggle{display:none;}
@media(max-width:768px){
  #menuToggle{display:flex;align-items:center;justify-content:center;position:fixed;top:12px;left:12px;z-index:300;width:36px;height:36px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);cursor:pointer;font-size:18px;}
  #sidebar{transform:translateX(-100%);}
  #sidebar.open{transform:translateX(0);}
  #main{margin-left:0;width:100%;padding:16px;padding-top:56px;}
  .chart-grid{grid-template-columns:1fr;}
}
@media print{
  #sidebar,#menuToggle,#toast,#drawerBackdrop,#detailDrawer{display:none!important;}
  #main{margin-left:0;width:100%;}
  .page{display:block!important;}
}
</style>
</head>
<body>
<button id="menuToggle" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>
<nav id="sidebar">
  <div class="logo-block">
    <div class="logo-icon">🗄</div>
    <div class="logo-title">Data Protection</div>
    <div class="logo-sub">Azure Data Security Posture</div>
    <div class="version-badge">v1.0</div>
  </div>
  <div class="nav-section">
    <div class="nav-label">Navigation</div>
    <button class="nav-btn active" onclick="showPage('overview',this)"><span class="nav-icon">📊</span> Overview</button>
    <button class="nav-btn" onclick="showPage('findings',this)"><span class="nav-icon">🔍</span> Findings</button>
    <button class="nav-btn" onclick="showPage('subscriptions',this)"><span class="nav-icon">📋</span> Scan Results</button>
    <button class="nav-btn" onclick="showPage('session',this)"><span class="nav-icon">⚙️</span> Session Info</button>
  </div>
  <div class="sidebar-footer">
    <div class="theme-toggle">
      <span>Dark mode</span>
      <button class="toggle-pill" onclick="toggleTheme()"></button>
    </div>
    <div class="footer-meta">Generated: __GENERATED_ON__<br/>Data Protection Posture</div>
  </div>
</nav>
<main id="main">

  <!-- ── Overview ── -->
  <div id="page-overview" class="page active">
    <div class="page-header">
      <div class="page-title">Data Protection Posture</div>
      <div class="page-sub">Prioritised data security findings across __SUB_COUNT__ subscription(s) — __TOTAL_FINDINGS__ total findings</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card c-red">
        <div class="stat-num">__CRITICAL_COUNT__</div>
        <div class="stat-label">Critical</div>
        <div class="stat-sub">Immediate action required</div>
      </div>
      <div class="stat-card c-amber">
        <div class="stat-num">__HIGH_COUNT__</div>
        <div class="stat-label">High</div>
        <div class="stat-sub">Address within sprint</div>
      </div>
      <div class="stat-card c-blue">
        <div class="stat-num">__MEDIUM_COUNT__</div>
        <div class="stat-label">Medium</div>
        <div class="stat-sub">Plan remediation</div>
      </div>
      <div class="stat-card c-green">
        <div class="stat-num">__LOW_COUNT__</div>
        <div class="stat-label">Low</div>
        <div class="stat-sub">Hardening opportunity</div>
      </div>
      <div class="stat-card c-muted">
        <div class="stat-num">__INFO_COUNT__</div>
        <div class="stat-label">Info</div>
        <div class="stat-sub">Awareness items</div>
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🎯 Severity Distribution</div>
        <div class="donut-wrap">
          <div class="donut-svg-wrap">
            <svg width="140" height="140" viewBox="0 0 140 140">
              __DONUT_SEGS__
            </svg>
            <div class="donut-center">
              <div class="donut-total">__TOTAL_FINDINGS__</div>
              <div class="donut-lbl">FINDINGS</div>
            </div>
          </div>
          <div class="legend-list">__LEGEND_ITEMS__</div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">📂 Findings by Category</div>
        __CAT_ROWS__
      </div>
    </div>
    <div class="chart-grid">
      <div class="panel">
        <div class="panel-title">🗂️ Findings by Resource Type</div>
        __TYPE_ROWS__
      </div>
    </div>
  </div>

  <!-- ── Findings ── -->
  <div id="page-findings" class="page">
    <div class="page-header">
      <div class="page-title">Data Protection Findings</div>
      <div class="page-sub">Click any row to view risk context and recommendations. Sorted by severity.</div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="findSearch" placeholder="Search resource, gap, category…" oninput="filterFindings()"/>
        </div>
        <select class="filter-select" id="filterSev" onchange="filterFindings()">
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>
        <select class="filter-select" id="filterCat" onchange="filterFindings()">
          <option value="">All Categories</option>
          <option value="Encryption">Encryption</option>
          <option value="Network">Network</option>
          <option value="Access">Access</option>
          <option value="Backup">Backup</option>
          <option value="Classification">Classification</option>
          <option value="Audit">Audit</option>
        </select>
        <select class="filter-select" id="pgSizeFind" onchange="changePageSize()">
          <option value="25">25 / page</option>
          <option value="50">50 / page</option>
          <option value="100">100 / page</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="sortBy('sev')">Severity</th>
              <th onclick="sortBy('cat')">Category</th>
              <th onclick="sortBy('name')">Resource</th>
              <th>Type</th>
              <th onclick="sortBy('sub')">Subscription</th>
              <th>Gap Summary</th>
            </tr>
          </thead>
          <tbody id="findingsBody">__FINDING_ROWS__</tbody>
        </table>
      </div>
      <div class="pagination" id="findPagination"></div>
    </div>
  </div>

  <!-- ── Scan Results ── -->
  <div id="page-subscriptions" class="page">
    <div class="page-header">
      <div class="page-title">Subscription Scan Results</div>
      <div class="page-sub">Per-subscription assessment outcome</div>
    </div>
    <div class="panel">
      <div class="panel-title">📋 Subscriptions Scanned</div>
      <div class="sub-list">__SUB_ROWS__</div>
    </div>
  </div>

  <!-- ── Session Info ── -->
  <div id="page-session" class="page">
    <div class="page-header">
      <div class="page-title">Session &amp; Scan Parameters</div>
      <div class="page-sub">Authentication context and configuration used for this assessment</div>
    </div>
    <div class="panel">
      <div class="panel-title">🔐 Session Information</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Tenant ID</div><div class="info-value">__TENANT__</div></div>
        <div class="info-card"><div class="info-label">Account</div><div class="info-value">__ACCOUNT__</div></div>
        <div class="info-card"><div class="info-label">Environment</div><div class="info-value">__ENVIRONMENT__</div></div>
        <div class="info-card"><div class="info-label">Generated On</div><div class="info-value">__GENERATED_ON__</div></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">⚙️ Scan Parameters</div>
      <div class="info-grid">
        <div class="info-card"><div class="info-label">Scope</div><div class="info-value">__SCOPE__</div></div>
        <div class="info-card"><div class="info-label">CSV Export</div><div class="info-value">__EXPORT_ENABLED__</div></div>
        <div class="info-card"><div class="info-label">Execution Time</div><div class="info-value">__EXEC_TIME__</div></div>
        <div class="info-card"><div class="info-label">Total Findings</div><div class="info-value">__TOTAL_FINDINGS__</div></div>
      </div>
    </div>
  </div>
</main>

<!-- Detail Drawer -->
<div id="drawerBackdrop" onclick="closeDrawer()"></div>
<div id="detailDrawer">
  <div class="drawer-header">
    <span class="drawer-title" id="drawerTitle">Finding Detail</span>
    <button class="drawer-close" onclick="closeDrawer()">✕</button>
  </div>
  <div class="drawer-body">
    <div class="drawer-nav">
      <button class="drawer-nav-btn" onclick="navDetail(-1)">← Prev</button>
      <span class="drawer-nav-info" id="drawerNavInfo"></span>
      <button class="drawer-nav-btn" onclick="navDetail(1)">Next →</button>
    </div>
    <div id="drawerContent"></div>
  </div>
</div>
<div id="toast"></div>

<script>
const ALL_FINDINGS = __FINDINGS_JSON__;
const SEV_ORDER    = {Critical:0,High:1,Medium:2,Low:3,Info:4};
let filtered       = [...ALL_FINDINGS];
let currentPage    = 1;
let pageSize       = 25;
let sortCol        = 'sev';
let sortAsc        = true;
let currentIdx     = 0;

function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function showPage(id,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+id).classList.add('active');
  btn.classList.add('active');
  document.getElementById('sidebar').classList.remove('open');
}
function toggleTheme(){const r=document.documentElement;r.dataset.theme=r.dataset.theme==='dark'?'light':'dark';}
function showToast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2500);}

function filterFindings(){
  const q=document.getElementById('findSearch').value.toLowerCase();
  const s=document.getElementById('filterSev').value;
  const c=document.getElementById('filterCat').value;
  filtered=ALL_FINDINGS.filter(r=>{
    const mQ=!q||[r.name,r.gap,r.cat,r.sub,r.type,r.risk,r.rec].join(' ').toLowerCase().includes(q);
    const mS=!s||r.sev===s;
    const mC=!c||r.cat===c;
    return mQ&&mS&&mC;
  });
  applySort();currentPage=1;renderTable();
}
function sortBy(col){if(sortCol===col){sortAsc=!sortAsc;}else{sortCol=col;sortAsc=true;}applySort();renderTable();}
function applySort(){
  filtered.sort((a,b)=>{
    if(sortCol==='sev'){const av=SEV_ORDER[a.sev]??99,bv=SEV_ORDER[b.sev]??99;return sortAsc?av-bv:bv-av;}
    const av=a[sortCol]??'',bv=b[sortCol]??'';
    return sortAsc?String(av).localeCompare(String(bv)):String(bv).localeCompare(String(av));
  });
}
function sevCls(s){return s==='Critical'?'badge-red':s==='High'?'badge-amber':s==='Medium'?'badge-blue':s==='Low'?'badge-green':'badge-muted';}

function renderTable(){
  const tbody=document.getElementById('findingsBody');
  const start=(currentPage-1)*pageSize;
  const slice=filtered.slice(start,start+pageSize);
  tbody.innerHTML=slice.map(r=>{
    const gi=ALL_FINDINGS.indexOf(r);
    const nm=r.name.length>28?r.name.substring(0,25)+'...':r.name;
    const tp=r.type.split('/').pop();
    const gp=r.gap.length>60?r.gap.substring(0,57)+'...':r.gap;
    return `<tr onclick="showDetail(${gi})">
      <td><span class="badge ${sevCls(r.sev)}">${escH(r.sev)}</span></td>
      <td><span class="cat-tag">${escH(r.cat)}</span></td>
      <td title="${escH(r.name)}">${escH(nm)}</td>
      <td style="font-size:11px;color:var(--muted2)">${escH(tp)}</td>
      <td>${escH(r.sub)}</td>
      <td title="${escH(r.gap)}">${escH(gp)}</td>
    </tr>`;
  }).join('');
  renderPagination();
}
function renderPagination(){
  const total=Math.ceil(filtered.length/pageSize);
  const el=document.getElementById('findPagination');
  let h=`<span>${filtered.length} finding(s)</span>`;
  h+=`<button class="pg-btn" onclick="goPage(${currentPage-1})" ${currentPage<=1?'disabled':''}>‹ Prev</button>`;
  const s=Math.max(1,currentPage-2),e=Math.min(total,s+4);
  for(let p=s;p<=e;p++) h+=`<button class="pg-btn ${p===currentPage?'active':''}" onclick="goPage(${p})">${p}</button>`;
  h+=`<button class="pg-btn" onclick="goPage(${currentPage+1})" ${currentPage>=total?'disabled':''}>Next ›</button>`;
  el.innerHTML=h;
}
function goPage(p){const t=Math.ceil(filtered.length/pageSize);if(p<1||p>t)return;currentPage=p;renderTable();}
function changePageSize(){pageSize=parseInt(document.getElementById('pgSizeFind').value);currentPage=1;renderTable();}

function showDetail(gi){
  currentIdx=gi;
  const r=ALL_FINDINGS[gi];if(!r)return;
  document.getElementById('drawerTitle').textContent=r.name+' — '+r.cat;
  document.getElementById('drawerNavInfo').textContent=(gi+1)+' of '+ALL_FINDINGS.length;
  document.getElementById('drawerContent').innerHTML=`
    <div style="margin-bottom:14px;display:flex;gap:8px;flex-wrap:wrap;">
      <span class="badge ${sevCls(r.sev)}">${escH(r.sev)}</span>
      <span class="cat-tag">${escH(r.cat)}</span>
    </div>
    <div style="font-size:11px;color:var(--muted);margin-bottom:2px;text-transform:uppercase;letter-spacing:.06em">Resource</div>
    <div style="font-size:13px;margin-bottom:4px;font-weight:600">${escH(r.name)}</div>
    <div style="font-size:11px;color:var(--muted2);margin-bottom:4px;font-family:var(--mono)">${escH(r.type)}</div>
    <div style="font-size:11px;color:var(--muted2);margin-bottom:14px">Resource Group: ${escH(r.rg)} &nbsp;|&nbsp; Subscription: ${escH(r.sub)}</div>
    <div class="detail-block gap">
      <div class="detail-lbl">🔴 Data Protection Gap</div>
      ${escH(r.gap)}
    </div>
    <div class="detail-block risk">
      <div class="detail-lbl">⚠️ Risk &amp; Regulatory Impact</div>
      ${escH(r.risk)}
    </div>
    <div class="detail-block rec">
      <div class="detail-lbl">✅ Recommendation</div>
      ${escH(r.rec)}
    </div>
  `;
  document.getElementById('drawerBackdrop').style.display='block';
  document.getElementById('detailDrawer').classList.add('open');
}
function closeDrawer(){document.getElementById('drawerBackdrop').style.display='none';document.getElementById('detailDrawer').classList.remove('open');}
function navDetail(dir){const next=currentIdx+dir;if(next>=0&&next<ALL_FINDINGS.length) showDetail(next);}

function animateBars(){
  requestAnimationFrame(()=>{document.querySelectorAll('.bar-fill[data-pct]').forEach(el=>el.style.width=el.dataset.pct+'%');});
}
document.addEventListener('keydown',e=>{
  if(e.key==='Escape') closeDrawer();
  if(e.key==='ArrowLeft') navDetail(-1);
  if(e.key==='ArrowRight') navDetail(1);
});
filterFindings();
animateBars();
</script>
</body>
</html>
'@

    $html = $html `
        -replace '__GENERATED_ON__', $GeneratedOn `
        -replace '__SUB_COUNT__', ($SubscriptionResults.Count) `
        -replace '__TOTAL_FINDINGS__', $totalFindings `
        -replace '__CRITICAL_COUNT__', $criticalCount `
        -replace '__HIGH_COUNT__', $highCount `
        -replace '__MEDIUM_COUNT__', $mediumCount `
        -replace '__LOW_COUNT__', $lowCount `
        -replace '__INFO_COUNT__', $infoCount `
        -replace '__DONUT_SEGS__', $donutSegs `
        -replace '__LEGEND_ITEMS__', $legendItems `
        -replace '__CAT_ROWS__', $catRows `
        -replace '__TYPE_ROWS__', $typeRows `
        -replace '__FINDING_ROWS__', $findingRows `
        -replace '__SUB_ROWS__', $subRows `
        -replace '__TENANT__', $SessionInfo.Tenant `
        -replace '__ACCOUNT__', $SessionInfo.Account `
        -replace '__ENVIRONMENT__', $SessionInfo.Environment `
        -replace '__SCOPE__', $ScanParameters.Scope `
        -replace '__EXPORT_ENABLED__', $ScanParameters.ExportEnabled `
        -replace '__EXEC_TIME__', $ScanParameters.ExecTime `
        -replace '__FINDINGS_JSON__', $findingsJson

    return $html
}


#------------------------------------------------------------------------ [ Assessment Functions ]

Function Test-StorageAccountSecurity {
    param([object]$Account, [string]$SubscriptionName)

    $findings = @()
    $name = $Account.StorageAccountName
    $rg = $Account.ResourceGroupName
    $type = "Microsoft.Storage/storageAccounts"
    $rid = $Account.Id

    # ── 1. Public network access ───────────────────────────────────────────────
    $netRules = Get-ObjProperty -Obj $Account -PropName 'NetworkRuleSet' -Default $null
    $defaultAction = Get-ObjProperty -Obj $netRules -PropName 'DefaultAction' -Default 'Allow'
    $publicAccess = Get-ObjProperty -Obj $Account -PropName 'PublicNetworkAccess' -Default 'Enabled'

    if ($defaultAction -eq 'Allow' -or $publicAccess -eq 'Enabled') {
        $findings += New-Finding -Severity 'High' -Category 'Network' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Storage Account '$name' accepts connections from all networks. The network ACL default action is Allow and public network access is not disabled." `
            -Risk "Any authenticated identity anywhere on the internet can access data in this storage account. Even with strong authentication, public exposure dramatically increases the attack surface — a single compromised credential, SAS token, or managed identity grants data access from anywhere. Storage accounts are a primary target in cloud breach scenarios precisely because they commonly hold sensitive data with weak network controls." `
            -Recommendation "Restrict the Storage Account to specific VNet subnets using service endpoints or private endpoints. Set the network ACL default action to Deny and add explicit allow rules for trusted subnets and IPs. For production data stores, deploy a Private Endpoint and disable public network access entirely." `
            -ResourceId $rid
    }

    # ── 2. Shared Key access (bypasses RBAC & Conditional Access) ─────────────
    $allowSharedKey = Get-ObjProperty -Obj $Account -PropName 'AllowSharedKeyAccess' -Default $true
    if ($allowSharedKey -ne $false) {
        $findings += New-Finding -Severity 'High' -Category 'Access' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Shared Key access is enabled on Storage Account '$name'. Shared Keys (Account Keys) provide full control over all data in the account and bypass Azure AD authentication, RBAC, and Conditional Access policies." `
            -Risk "Anyone with the storage account key has unrestricted data access. Keys are often stored insecurely in application configuration, scripts, and developer machines. They cannot be scoped (a key is always all-or-nothing), they do not appear in Entra ID sign-in logs, and they are not subject to MFA or Conditional Access. A leaked storage key is equivalent to a data breach." `
            -Recommendation "Disable Shared Key access ('AllowSharedKeyAccess = false') and migrate all access to Azure AD authentication with appropriate RBAC roles (Storage Blob Data Reader / Contributor). Where temporary access is required, use User Delegation SAS tokens, which are backed by Entra ID credentials and can be revoked via the delegating identity." `
            -ResourceId $rid
    }

    # ── 3. Anonymous blob access ───────────────────────────────────────────────
    $allowAnonymous = Get-ObjProperty -Obj $Account -PropName 'AllowBlobPublicAccess' -Default $true
    if ($allowAnonymous -ne $false) {
        $findings += New-Finding -Severity 'Critical' -Category 'Access' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Anonymous blob public access is permitted on Storage Account '$name'. Any container in this account can be configured for public (unauthenticated) read access." `
            -Risk "If any container in this account is accidentally set to public access (a single misclick in the portal or a misconfigured IaC template), all blobs in that container are readable by anyone on the internet without authentication. This is the root cause of a significant proportion of publicly reported cloud data breaches." `
            -Recommendation "Disable AllowBlobPublicAccess at the account level to prevent any container from ever being made publicly accessible, regardless of container-level settings. If public access is genuinely required for specific assets (e.g., static website content), host that content in a dedicated storage account with no sensitive data." `
            -ResourceId $rid
    }

    # ── 4. Encryption: CMK vs MMK ─────────────────────────────────────────────
    $encryptionKeySource = ""
    try {
        $encryptionKeySource = Get-ObjProperty -Obj $Account.Encryption -PropName 'KeySource' -Default 'Microsoft.Storage'
    }
    catch { }

    if ($encryptionKeySource -ne 'Microsoft.Keyvault') {
        $findings += New-Finding -Severity 'Low' -Category 'Encryption' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Storage Account '$name' uses Microsoft-Managed Keys (MMK) for encryption at rest. Customer-Managed Keys (CMK) via Key Vault are not configured." `
            -Risk "MMK encryption is technically sound (AES-256), but Microsoft controls the key lifecycle. In regulated environments (FedRAMP High, PCI-DSS, HIPAA, financial services regulations), there is often a requirement to demonstrate exclusive control over encryption keys. With MMK, the organisation cannot independently rotate, revoke, or audit key access. A regulatory body cannot verify that only the organisation can decrypt its data." `
            -Recommendation "For regulated workloads or sensitive data, configure Customer-Managed Keys using Azure Key Vault with RBAC and purge protection enabled. CMK provides key lifecycle control, independent audit trails, and the ability to instantly revoke access by disabling the key. Evaluate which storage accounts hold regulated or highly sensitive data and prioritise CMK adoption there first." `
            -ResourceId $rid
    }

    # ── 5. Blob soft delete ────────────────────────────────────────────────────
    $blobSoftDelete = $false
    $blobRetention = 0
    try {
        $blobService = Get-AzStorageBlobServiceProperty -ResourceGroupName $rg -StorageAccountName $name -ErrorAction Stop
        $blobSoftDelete = Get-ObjProperty -Obj $blobService.DeleteRetentionPolicy -PropName 'Enabled' -Default $false
        $blobRetention = Get-ObjProperty -Obj $blobService.DeleteRetentionPolicy -PropName 'Days'    -Default 0
    }
    catch { }

    if (-not $blobSoftDelete) {
        $findings += New-Finding -Severity 'High' -Category 'Backup' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Blob soft delete is not enabled on Storage Account '$name'. Deleted blobs are permanently destroyed immediately with no recovery window." `
            -Risk "Accidental deletion of blobs — by a misconfigured application, a runbook error, a human mistake, or a malicious actor — causes immediate, unrecoverable data loss. Ransomware attacks targeting Azure Storage typically delete blobs after exfiltrating them. Without soft delete, recovery requires either a backup or is impossible." `
            -Recommendation "Enable blob soft delete with a retention period of at least 7 days (30 days recommended for production). Also enable container soft delete and file share soft delete for completeness. For critical data, combine soft delete with Azure Backup for Storage (point-in-time restore capability)." `
            -ResourceId $rid
    }
    elseif ($blobRetention -lt 7) {
        $findings += New-Finding -Severity 'Medium' -Category 'Backup' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Blob soft delete is enabled on '$name' but the retention period is only $blobRetention day(s). This provides a very narrow recovery window." `
            -Risk "A retention period of less than 7 days may be insufficient to detect and respond to data deletion events — particularly if the deletion is caused by a scheduled job or a slow-moving ransomware attack that is not immediately noticed." `
            -Recommendation "Increase blob soft delete retention to at least 7 days, and ideally 30 days for production storage accounts. The retention period should align with the organisation's incident detection SLA — if it typically takes more than X days to detect an incident, retention should be at least X days." `
            -ResourceId $rid
    }

    # ── 6. Diagnostic logging (audit trail) ───────────────────────────────────
    $diagSettings = @()
    try { $diagSettings = @(Get-AzDiagnosticSetting -ResourceId $rid -ErrorAction Stop) } catch { }
    $hasStorageLog = $diagSettings | Where-Object {
        $logs = Get-ObjProperty -Obj $_ -PropName 'Logs' -Default @()
        @($logs | Where-Object { $_.Enabled -eq $true }).Count -gt 0
    }

    if (-not $hasStorageLog) {
        $findings += New-Finding -Severity 'Medium' -Category 'Audit' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "No diagnostic settings with log collection are configured on Storage Account '$name'. Read, write, and delete operations on blobs, files, queues, and tables are not logged to any destination." `
            -Risk "Without access logs, a data breach cannot be investigated. If data is exfiltrated from this storage account, there is no way to determine which data was accessed, when, by whom, from what IP, or how much data was read. Most compliance frameworks (SOC 2, ISO 27001, PCI-DSS) require audit logging of access to sensitive data." `
            -Recommendation "Enable Storage diagnostic settings to send StorageRead, StorageWrite, and StorageDelete logs to a Log Analytics workspace. Configure at least 90 days of retention in the workspace (or archive to storage for longer-term compliance requirements). Use Microsoft Defender for Storage to alert on anomalous access patterns." `
            -ResourceId $rid
    }

    return $findings
}

Function Test-SqlServerSecurity {
    param([object]$Server, [array]$Databases, [string]$SubscriptionName)

    $findings = @()
    $srvName = $Server.ServerName
    $rg = $Server.ResourceGroupName
    $type = "Microsoft.Sql/servers"
    $rid = $Server.ResourceId

    # ── 1. Public network access ───────────────────────────────────────────────
    $publicNetAccess = Get-ObjProperty -Obj $Server -PropName 'PublicNetworkAccess' -Default 'Enabled'
    if ($publicNetAccess -eq 'Enabled') {
        # Check if there are overly permissive firewall rules (0.0.0.0 - 255.255.255.255)
        $fwRules = @()
        try { $fwRules = @(Get-AzSqlServerFirewallRule -ServerName $srvName -ResourceGroupName $rg -ErrorAction Stop) } catch { }
        $openRule = $fwRules | Where-Object { $_.StartIpAddress -eq '0.0.0.0' -and $_.EndIpAddress -eq '255.255.255.255' }

        if ($openRule) {
            $findings += New-Finding -Severity 'Critical' -Category 'Network' `
                -ResourceName $srvName -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
                -Gap "SQL Server '$srvName' has a firewall rule allowing all internet IPs (0.0.0.0 - 255.255.255.255) and public network access is enabled. The SQL Server is fully open to the internet." `
                -Risk "A fully internet-exposed SQL Server is subject to credential brute-force attacks, SQL injection probing (if SQL authentication is used), and targeted exploitation of SQL Server vulnerabilities. The TDS protocol on port 1433 is actively scanned by threat actors. A single successful authentication grants an attacker direct database access regardless of application-layer controls." `
                -Recommendation "Remove the 'Allow All' firewall rule immediately. Either migrate to Private Endpoint (disable public network access) or restrict firewall rules to known IP ranges. Private Endpoint is strongly preferred as it removes the SQL Server from internet reachability entirely and ensures traffic only traverses the VNet." `
                -ResourceId $rid
        }
        else {
            $findings += New-Finding -Severity 'High' -Category 'Network' `
                -ResourceName $srvName -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
                -Gap "SQL Server '$srvName' has public network access enabled. The SQL endpoint is reachable from the internet (constrained by firewall rules)." `
                -Risk "Firewall rules are a necessary but insufficient control. IP-based rules are bypassable from approved IPs (e.g., a compromised developer machine), do not provide VNet-level isolation, and create operational overhead when IPs change. The attack surface is wider than Private Endpoint deployments." `
                -Recommendation "Migrate to Azure Private Endpoint for the SQL Server and disable public network access. Applications connecting from App Services or AKS should use VNet Integration to route traffic through the private endpoint. This removes the SQL Server from internet-reachable address space entirely." `
                -ResourceId $rid
        }
    }

    # ── 2. Azure AD-only authentication ───────────────────────────────────────
    $aadAdminSet = $null
    $adOnlyAuth = $false
    try {
        $aadAdmins = @(Get-AzSqlServerActiveDirectoryAdministrator -ServerName $srvName -ResourceGroupName $rg -ErrorAction Stop)
        $aadAdminSet = ($aadAdmins.Count -gt 0)
    }
    catch { }

    if (-not $aadAdminSet) {
        $findings += New-Finding -Severity 'High' -Category 'Access' `
            -ResourceName $srvName -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "No Entra ID (Azure AD) administrator is configured on SQL Server '$srvName'. SQL authentication (username/password) may be the only authentication mechanism." `
            -Risk "SQL authentication uses passwords that are not subject to Conditional Access, MFA, or Entra ID identity protection. SQL login credentials are frequently hardcoded in connection strings, stored in configuration files, and reused across environments. Compromised SQL credentials provide direct database access with no second factor requirement." `
            -Recommendation "Configure an Entra ID administrator on the SQL Server and enable Entra ID-only authentication ('Azure Active Directory Authentication Only = Enabled'). This disables SQL authentication entirely, ensures all access is via Entra ID identities subject to Conditional Access and MFA. Applications should use Managed Identity or Entra ID service principals for connection." `
            -ResourceId $rid
    }

    # ── 3. SQL Auditing ───────────────────────────────────────────────────────
    $auditPolicy = $null
    try { $auditPolicy = Get-AzSqlServerAudit -ServerName $srvName -ResourceGroupName $rg -ErrorAction Stop } catch { }
    $auditEnabled = Get-ObjProperty -Obj $auditPolicy -PropName 'BlobStorageTargetState' -Default 'Disabled'
    $laAudit = Get-ObjProperty -Obj $auditPolicy -PropName 'LogAnalyticsTargetState' -Default 'Disabled'

    if ($auditEnabled -ne 'Enabled' -and $laAudit -ne 'Enabled') {
        $findings += New-Finding -Severity 'High' -Category 'Audit' `
            -ResourceName $srvName -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "SQL Auditing is not enabled on SQL Server '$srvName'. Database authentication events, DML statements, and administrative actions are not logged." `
            -Risk "Without SQL Auditing, a data exfiltration event — a privileged query that exports millions of rows, or a lateral movement through linked servers — leaves no platform-level trace. Regulatory frameworks including PCI-DSS, HIPAA, and SOC 2 explicitly require audit logging of access to databases holding sensitive data. A breach investigation would have no evidence to work with." `
            -Recommendation "Enable SQL Server Auditing and direct logs to Log Analytics for real-time querying and alerting. Set retention to at least 90 days in Log Analytics and archive to a storage account for longer-term compliance requirements. Enable Microsoft Defender for SQL to detect anomalous queries, unusual access patterns, and potential SQL injection." `
            -ResourceId $rid
    }

    # ── 4. Per-database: TDE status ───────────────────────────────────────────
    foreach ($db in $Databases) {
        if ($db.DatabaseName -eq 'master') { continue }

        $tde = $null
        try { $tde = Get-AzSqlDatabaseTransparentDataEncryption -ServerName $srvName -ResourceGroupName $rg -DatabaseName $db.DatabaseName -ErrorAction Stop } catch { }
        $tdeState = Get-ObjProperty -Obj $tde -PropName 'State' -Default 'Unknown'

        if ($tdeState -eq 'Disabled') {
            $findings += New-Finding -Severity 'Critical' -Category 'Encryption' `
                -ResourceName "$srvName/$($db.DatabaseName)" -ResourceType "Microsoft.Sql/servers/databases" `
                -ResourceGroup $rg -SubscriptionName $SubscriptionName `
                -Gap "Transparent Data Encryption (TDE) is disabled on database '$($db.DatabaseName)' on SQL Server '$srvName'. Database files, backups, and log files are stored unencrypted on disk." `
                -Risk "Data on disk is readable without database-level authentication if storage media is accessed directly — this includes database backup files stored in Azure Storage and exported bacpac files. This is a fundamental encryption-at-rest failure and a direct violation of virtually all data protection regulations (GDPR, PCI-DSS, HIPAA, ISO 27001)." `
                -Recommendation "Enable TDE immediately on this database. For new databases, TDE is enabled by default and should not be disabled. Verify that automated backups and long-term retention copies of this database are also encrypted." `
                -ResourceId $db.ResourceId
        }

        # Check backup retention (short retention = narrow recovery window)
        $retention = Get-ObjProperty -Obj $db -PropName 'BackupRetentionDays' -Default 0
        if ($retention -gt 0 -and $retention -lt 7) {
            $findings += New-Finding -Severity 'Medium' -Category 'Backup' `
                -ResourceName "$srvName/$($db.DatabaseName)" -ResourceType "Microsoft.Sql/servers/databases" `
                -ResourceGroup $rg -SubscriptionName $SubscriptionName `
                -Gap "Database '$($db.DatabaseName)' has a backup retention of only $retention day(s). The recovery window is less than 7 days." `
                -Risk "A short backup retention window limits the organisation's ability to recover from data corruption, accidental mass deletion, or ransomware attacks that are not detected immediately. Regulatory frameworks often require minimum retention periods (PCI-DSS requires 3 months of audit log retention; data recovery expectations may be broader)." `
                -Recommendation "Increase the backup retention period to at least 7 days for non-production and 35 days for production databases. For compliance requirements beyond 35 days, configure Long-Term Retention (LTR) policy to retain weekly, monthly, or yearly backups in Azure Blob Storage." `
                -ResourceId $db.ResourceId
        }
    }

    return $findings
}

Function Test-CosmosDbSecurity {
    param([object]$Account, [string]$SubscriptionName)

    $findings = @()
    $name = $Account.Name
    $rg = $Account.ResourceGroupName
    $type = "Microsoft.DocumentDB/databaseAccounts"
    $rid = $Account.Id

    # ── 1. Public network access ───────────────────────────────────────────────
    $pubNetAccess = Get-ObjProperty -Obj $Account -PropName 'PublicNetworkAccess' -Default 'Enabled'
    $ipRules = @(Get-ObjProperty -Obj $Account -PropName 'IpRules' -Default @())
    $vnetRules = @(Get-ObjProperty -Obj $Account -PropName 'VirtualNetworkRules' -Default @())

    if ($pubNetAccess -eq 'Enabled' -and $ipRules.Count -eq 0 -and $vnetRules.Count -eq 0) {
        $findings += New-Finding -Severity 'Critical' -Category 'Network' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Cosmos DB account '$name' has public network access enabled with no IP firewall rules or VNet rules. The account is accessible from any internet IP." `
            -Risk "A fully public Cosmos DB endpoint means any authenticated credential (including master keys) can be used from anywhere on the internet. Cosmos DB master keys provide unrestricted read/write access to all data. A leaked master key or an overly permissive RBAC assignment exploitable from internet represents an immediate and total data exposure." `
            -Recommendation "Immediately add VNet rules or IP restrictions, or disable public network access and configure a Private Endpoint. For internet-facing APIs that access Cosmos DB, the application tier (App Service / AKS) should connect via VNet Integration + Private Endpoint, never via public endpoint." `
            -ResourceId $rid
    }

    # ── 2. Local authentication (master keys) disabled ────────────────────────
    $localAuthDisabled = Get-ObjProperty -Obj $Account -PropName 'DisableLocalAuth' -Default $false
    if (-not $localAuthDisabled) {
        $findings += New-Finding -Severity 'High' -Category 'Access' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Local authentication (Cosmos DB master keys) is enabled on account '$name'. Master keys bypass Entra ID authentication and Conditional Access." `
            -Risk "Cosmos DB master keys provide unrestricted read/write access to all databases, containers, and documents in the account. They are static secrets that do not expire, cannot be scoped to specific resources, are not subject to MFA, and do not appear in Entra ID sign-in logs. Leakage of a master key is equivalent to full account compromise." `
            -Recommendation "Migrate all application access to Cosmos DB RBAC with Entra ID identities (managed identities preferred). Once all applications are on RBAC, disable local authentication ('DisableLocalAuth = true'). This removes master keys as an access path and ensures all access is via Entra ID identities subject to Conditional Access." `
            -ResourceId $rid
    }

    # ── 3. Backup policy ──────────────────────────────────────────────────────
    $backupPolicy = Get-ObjProperty -Obj $Account -PropName 'BackupPolicy' -Default $null
    $backupType = Get-ObjProperty -Obj $backupPolicy -PropName 'Type' -Default 'Periodic'

    if ($backupType -eq 'Periodic') {
        $backupInterval = Get-ObjProperty -Obj $backupPolicy -PropName 'PeriodicModeProperties' -Default $null
        $intervalHours = Get-ObjProperty -Obj $backupInterval -PropName 'BackupIntervalInMinutes' -Default 240
        $retentionHours = Get-ObjProperty -Obj $backupInterval -PropName 'BackupRetentionIntervalInHours' -Default 8

        $findings += New-Finding -Severity 'Medium' -Category 'Backup' `
            -ResourceName $name -ResourceType $type -ResourceGroup $rg -SubscriptionName $SubscriptionName `
            -Gap "Cosmos DB account '$name' uses Periodic backup mode. Continuous backup with point-in-time restore (PITR) is not enabled. Current backup interval: $([math]::Round($intervalHours/60,0))h, retention: $retentionHours hours." `
            -Risk "Periodic backup provides only coarse-grained recovery. Data written between backups is permanently lost if a restore is required. Accidental document deletion or bulk data corruption (by a bug or malicious script) may not be recoverable if the event is not detected within the retention window. Continuous backup provides granular PITR to any point within 30 days." `
            -Recommendation "Migrate to Continuous Backup mode to enable point-in-time restore. Continuous backup provides 30-day retention and the ability to restore to any second within that window, dramatically reducing recovery time objectives and data loss exposure." `
            -ResourceId $rid
    }

    return $findings
}


#------------------------------------------------------------------------ [ Main Function ]

Function Get-AzureDataProtectionPosture {
    [CmdletBinding()]
    param (
        [switch]$AllSubscriptions,

        [string[]]$SubscriptionIds,

        [switch]$ExportToCsv,

        [ValidateNotNullOrEmpty()]
        [string]$CsvPath = "C:\Temp\AzureDataProtectionPosture-Report.csv"
    )

    $startTime = Get-Date
    Write-Banner

    # ── Module check ──────────────────────────────────────────────────────────
    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Storage", "Az.Sql", "Az.CosmosDB", "Az.Monitor")
    $missingModules = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }

    if ($missingModules) {
        Write-Host "  ⚠ Missing Az modules: $($missingModules -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        $install = Read-Host "  Install Az module now? (Y/N)"
        if ($install -match '^[Yy]$') {
            try {
                Write-Host ""
                Write-Host "  Installing Az module, please wait..." -ForegroundColor Cyan
                Install-Module -Name Az -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Import-Module Az -ErrorAction Stop
                Write-Host "  ✓ Az module installed successfully" -ForegroundColor Green
                Write-Host ""
            }
            catch {
                Write-Host "  ✗ Error installing Az module: $_" -ForegroundColor Red
                return
            }
        }
        else {
            Write-Host ""
            Write-Host "  Installation declined. Cannot proceed without required Az modules." -ForegroundColor Yellow
            return
        }
    }

    # ── Authentication ─────────────────────────────────────────────────────────
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        Write-Host "  ⚠ No active session. Authenticating..." -ForegroundColor Yellow
        Connect-AzAccount -WarningAction SilentlyContinue
        $ctx = Get-AzContext
    }

    # ── Subscription resolution ────────────────────────────────────────────────
    if ($AllSubscriptions -or -not $SubscriptionIds) {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' })
        $scopeText = "All Subscriptions"
    }
    else {
        $subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue |
            Where-Object { $SubscriptionIds -contains $_.Id })
        $scopeText = "Specific Subscriptions ($($SubscriptionIds.Count) requested)"
    }

    $subCount = $subscriptions.Count

    Write-Section -Title "Session Information" -Data @{
        "Tenant"      = $ctx.Tenant.Id
        "Account"     = $ctx.Account.Id
        "Environment" = $ctx.Environment.Name
    }
    Write-Section -Title "Scan Parameters" -Data @{
        "Scope"         = "$scopeText ($subCount found)"
        "Export to CSV" = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
        "Export Path"   = if ($ExportToCsv.IsPresent) { $CsvPath } else { "" }
    }

    # ── Collections ────────────────────────────────────────────────────────────
    $allFindings = @()
    $subscriptionResults = @()
    $successCount = 0
    $errorCount = 0

    # ── Scan ───────────────────────────────────────────────────────────────────
    Write-ScanProgress
    Write-ProgressBar -Current 0 -Total $subCount -CurrentItem "Starting..."

    $maxNameLen = [math]::Max(($subscriptions | ForEach-Object { $_.Name.Length } |
            Measure-Object -Maximum).Maximum, 35)

    $subIndex = 1

    foreach ($sub in $subscriptions) {
        try {
            Write-ProgressBar -Current $subIndex -Total $subCount -CurrentItem $sub.Name
            Set-AzContext -Subscription $sub.Id -WarningAction SilentlyContinue `
                -InformationAction SilentlyContinue | Out-Null

            $subFindings = @()

            # ── Storage Accounts ──────────────────────────────────────────────
            try {
                $storageAccounts = @(Get-AzStorageAccount -ErrorAction Stop)
                foreach ($sa in $storageAccounts) {
                    try { $subFindings += Test-StorageAccountSecurity -Account $sa -SubscriptionName $sub.Name }
                    catch { Write-Verbose "  Error assessing storage account '$($sa.StorageAccountName)': $_" }
                }
            }
            catch { Write-Verbose "  Could not enumerate Storage Accounts for $($sub.Name): $_" }

            # ── SQL Servers & Databases ───────────────────────────────────────
            try {
                $sqlServers = @(Get-AzSqlServer -ErrorAction Stop)
                foreach ($srv in $sqlServers) {
                    try {
                        $databases = @()
                        try { $databases = @(Get-AzSqlDatabase -ServerName $srv.ServerName -ResourceGroupName $srv.ResourceGroupName -ErrorAction Stop) } catch { }
                        $subFindings += Test-SqlServerSecurity -Server $srv -Databases $databases -SubscriptionName $sub.Name
                    }
                    catch { Write-Verbose "  Error assessing SQL Server '$($srv.ServerName)': $_" }
                }
            }
            catch { Write-Verbose "  Could not enumerate SQL Servers for $($sub.Name): $_" }

            # ── Cosmos DB ─────────────────────────────────────────────────────
            try {
                $cosmosAccounts = @(Get-AzCosmosDBAccount -ErrorAction Stop)
                foreach ($cosmos in $cosmosAccounts) {
                    try { $subFindings += Test-CosmosDbSecurity -Account $cosmos -SubscriptionName $sub.Name }
                    catch { Write-Verbose "  Error assessing Cosmos DB '$($cosmos.Name)': $_" }
                }
            }
            catch { Write-Verbose "  Could not enumerate Cosmos DB accounts for $($sub.Name): $_" }

            $allFindings += $subFindings

            # ── Per-subscription result ───────────────────────────────────────
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✓ " -NoNewline -ForegroundColor Green
            Write-Host $paddedName -NoNewline -ForegroundColor Green
            Write-Host " → " -NoNewline -ForegroundColor DarkGray

            $critInSub = @($subFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
            $highInSub = @($subFindings | Where-Object { $_.Severity -eq 'High' }).Count
            Write-Host "Findings: $($subFindings.Count)  (Critical: $critInSub  High: $highInSub)" -ForegroundColor White

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Findings: $($subFindings.Count)  Critical: $critInSub  High: $highInSub"
                Status  = "Success"
            }
            $successCount++
        }
        catch {
            Write-Host "`r$(' ' * 120)`r" -NoNewline
            $paddedName = $sub.Name.PadRight($maxNameLen)
            Write-Host "  " -NoNewline
            Write-Host "✗ " -NoNewline -ForegroundColor Red
            Write-Host $paddedName -NoNewline -ForegroundColor Red
            Write-Host " → Failed: $($_.Exception.Message)" -ForegroundColor Red

            $subscriptionResults += @{
                Name    = $sub.Name
                Summary = "Failed: $($_.Exception.Message)"
                Status  = "Error"
            }
            $errorCount++
        }

        $subIndex++
    }

    # ── Summary ────────────────────────────────────────────────────────────────
    $endTime = Get-Date
    $duration = "{0:hh\:mm\:ss}" -f ($endTime - $startTime)

    Write-FindingSummary -Findings $allFindings

    # ── Output files ───────────────────────────────────────────────────────────
    $csvExported = $false
    $htmlExported = $false
    $gridViewOpened = $false
    $htmlPath = ""

    if ($allFindings.Count -gt 0) {
        if ($ExportToCsv) {
            try {
                $csvDir = Split-Path -Parent $CsvPath
                if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

                $allFindings | Select-Object Severity, Category, ResourceName, ResourceType, `
                    ResourceGroup, SubscriptionName, Gap, Risk, Recommendation |
                Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

                $csvExported = $true
            }
            catch { Write-Host "  ✗ CSV export failed: $_" -ForegroundColor Red }
        }

        try {
            $htmlPath = [System.IO.Path]::ChangeExtension($CsvPath, '.html')
            $sessionInfo = @{ Tenant = $ctx.Tenant.Id; Account = $ctx.Account.Id; Environment = $ctx.Environment.Name }
            $scanParams = @{
                Scope         = "$scopeText ($subCount found)"
                ExportEnabled = if ($ExportToCsv.IsPresent) { "Enabled" } else { "Disabled" }
                ExecTime      = $duration
            }

            $htmlContent = Generate-DataProtectionHtml `
                -SessionInfo         $sessionInfo `
                -ScanParameters      $scanParams `
                -Findings            $allFindings `
                -SubscriptionResults $subscriptionResults `
                -GeneratedOn         (Get-Date -Format "MMMM dd, yyyy 'at' hh:mm:ss tt")

            $htmlDir = Split-Path -Parent $htmlPath
            if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
            $htmlExported = $true
        }
        catch { Write-Host "  ✗ HTML dashboard generation failed: $_" -ForegroundColor Red }

        try {
            $allFindings | Select-Object Severity, Category, ResourceName, ResourceType, `
                SubscriptionName, Gap |
            Sort-Object { $script:SevOrder[$_.Severity] } |
            Out-GridView -Title "Azure Data Protection Posture"
            $gridViewOpened = $true
        }
        catch { Write-Host "  ⚠ Could not open Grid View (no GUI available)" -ForegroundColor Yellow }
    }
    else {
        Write-Host ""
        Write-Host "  ⚠ No findings generated — check that the account has Reader access to target subscriptions." -ForegroundColor Yellow
    }

    if ($csvExported -or $htmlExported -or $gridViewOpened) {
        $csvPathToUse = if ($csvExported) { $CsvPath } else { $null }
        $htmlPathToUse = if ($htmlExported) { $htmlPath } else { $null }

        Write-OutputFiles `
            -CsvPath $csvPathToUse `
            -HtmlPath $htmlPathToUse `
            -GridViewOpened $gridViewOpened
    }
    else {
        Write-Host ""
        Write-Host ("═" * 80) -ForegroundColor Cyan
        Write-Host ""
    }
}
