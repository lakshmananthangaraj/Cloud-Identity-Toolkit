# Cloud Identity Toolkit

A curated, public toolkit of PowerShell scripts and runbooks for managing Entra ID, Azure, and Microsoft 365 identity governance at scale — built from real-world automation work, redacted and generalized for public use.

**Who this is for:** IT professionals, security engineers, cloud architects, and anyone interested in practical identity and governance solutions across Microsoft cloud ecosystems.

## Architecture Overview

```mermaid
flowchart TD

subgraph group_shared["Shared PowerShell"]
  node_common_manifest["Common module manifest<br/>PowerShell module manifest"]
  node_common_module["Common presentation module<br/>PowerShell module"]
  node_logging["Logging helper<br/>PowerShell helper<br/>[Add-Log.ps1]"]
end

subgraph group_entra["Entra ID Operations"]
  node_entra_connect["Entra authentication<br/>PowerShell entry point"]
  node_jwt_decoder["JWT inspection<br/>PowerShell utility"]
  node_directory_report["Directory user inventory<br/>PowerShell report<br/>[Get-AllUsers.ps1]"]
  node_governance_reports["Privileged access report<br/>PowerShell report"]
  node_conditional_access["Conditional Access report<br/>PowerShell report"]
  node_sharepoint_grant["Site Selected permission grant<br/>PowerShell write operation"]
end

subgraph group_cloud["Cloud Operations"]
  node_keyvault_secret["Key Vault secret creation<br/>PowerShell write operation"]
  node_network_dashboard["NSG compliance dashboard<br/>PowerShell report"]
  node_rbac_report["Azure RBAC visualization<br/>PowerShell report"]
  node_license_alert["License threshold alert<br/>PowerShell operational action"]
  node_mailbox_audit["Mailbox audit posture<br/>PowerShell report"]
  node_device_compliance["Device compliance report<br/>PowerShell report"]
end

subgraph group_devtools["Developer Automation"]
  node_script_analysis["Script quality analysis<br/>PowerShell maintenance tool"]
  node_documentation["Markdown documentation generation<br/>PowerShell maintenance tool"]
  node_module_builder["Script module packaging<br/>PowerShell maintenance tool"]
end

subgraph group_external["Microsoft Cloud Boundaries"]
  node_entra_graph{{"Entra ID &amp; Microsoft Graph<br/>tenant API boundary"}}
  node_azure{{"Azure Resource Manager &amp; Key Vault<br/>Azure API boundary"}}
  node_m365{{"Microsoft 365 services<br/>tenant API boundary"}}
  node_intune{{"Intune control plane<br/>tenant API boundary"}}
end

node_operators(("Identity Operators &amp; Human & Workload Identities<br/>(Users, Apps, Managed Identities,<br/>Automation<br/>invokers"))

node_common_manifest -->|"declares"| node_common_module
node_common_module -->|"loads"| node_logging
node_operators -->|"invokes"| node_entra_connect
node_operators -->|"invokes"| node_directory_report
node_operators -->|"invokes"| node_governance_reports
node_operators -->|"authorizes and invokes"| node_sharepoint_grant
node_operators -->|"authorizes and invokes"| node_keyvault_secret
node_operators -->|"invokes"| node_network_dashboard
node_operators -->|"invokes"| node_license_alert
node_operators -->|"invokes"| node_device_compliance
node_entra_connect -->|"authenticates to"| node_entra_graph
node_jwt_decoder -.->|"inspects tokens from"| node_entra_connect
node_directory_report -->|"reads directory state"| node_entra_graph
node_governance_reports -->|"reads governance state"| node_entra_graph
node_conditional_access -->|"reads policy state"| node_entra_graph
node_sharepoint_grant -->|"grants site permission"| node_m365
node_keyvault_secret -->|"creates secret"| node_azure
node_network_dashboard -->|"reads network state"| node_azure
node_rbac_report -->|"reads RBAC state"| node_azure
node_license_alert -->|"reads licenses and sends alert"| node_m365
node_mailbox_audit -->|"reads mailbox posture"| node_m365
node_device_compliance -->|"reads compliance state"| node_intune
node_script_analysis -.->|"supports repository quality"| node_module_builder
node_documentation -.->|"documents packaged scripts"| node_module_builder

click node_common_manifest "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Modules/CloudIdentityToolkit.Common/CloudIdentityToolkit.Common.psd1"
click node_common_module "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Modules/CloudIdentityToolkit.Common/CloudIdentityToolkit.Common.psm1"
click node_logging "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Modules/CloudIdentityToolkit.Common/Add-Log.ps1"
click node_entra_connect "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1"
click node_jwt_decoder "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/Authentication/ConvertFrom-JwtToken.ps1"
click node_directory_report "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/Users/Get-AllUsers.ps1"
click node_governance_reports "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/PIM/Get-PIMActiveEntraIDRoleAssignmentDetails.ps1"
click node_conditional_access "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/ConditionalAccess/Get-ConditionalAccessPoliciesReport.ps1"
click node_sharepoint_grant "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/AppRegistrations/Grant-SharePointSiteSelectedPermission.ps1"
click node_keyvault_secret "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Azure/KeyVault/New-AzureKeyVaultSecret.ps1"
click node_network_dashboard "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Azure/Network/Generate-AzureNSGComplianceDashboard.ps1"
click node_rbac_report "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Azure/RBAC/Generate-RBACVisualizationReport.ps1"
click node_license_alert "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Microsoft365/Licensing/Send-M365LicenseThresholdAlert.ps1"
click node_mailbox_audit "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Microsoft365/ExchangeOnline/Get-MailboxAuditStatus.ps1"
click node_device_compliance "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Intune/Get-DeviceComplianceReport.ps1"
click node_script_analysis "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/DeveloperTools/CodeQuality/Invoke-ScriptAnalyzer.ps1"
click node_documentation "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/DeveloperTools/Documentation/Generate-MarkdownDocumentation.ps1"
click node_module_builder "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/DeveloperTools/ModuleBuilder/New-PSModuleFromScripts.ps1"

classDef toneNeutral fill:#f8fafc,stroke:#334155,stroke-width:1.5px,color:#0f172a
classDef toneBlue fill:#dbeafe,stroke:#2563eb,stroke-width:1.5px,color:#172554
classDef toneAmber fill:#fef3c7,stroke:#d97706,stroke-width:1.5px,color:#78350f
classDef toneMint fill:#dcfce7,stroke:#16a34a,stroke-width:1.5px,color:#14532d
classDef toneRose fill:#ffe4e6,stroke:#e11d48,stroke-width:1.5px,color:#881337
classDef toneIndigo fill:#e0e7ff,stroke:#4f46e5,stroke-width:1.5px,color:#312e81
classDef toneTeal fill:#ccfbf1,stroke:#0f766e,stroke-width:1.5px,color:#134e4a
class node_common_manifest,node_common_module,node_logging toneBlue
class node_entra_connect,node_jwt_decoder,node_directory_report,node_governance_reports,node_conditional_access,node_sharepoint_grant toneAmber
class node_keyvault_secret,node_network_dashboard,node_rbac_report,node_license_alert,node_mailbox_audit,node_device_compliance toneMint
class node_script_analysis,node_documentation,node_module_builder toneRose
class node_entra_graph,node_azure,node_m365,node_intune toneIndigo
class node_operators toneNeutral
```

## What's Included

| Area | What it covers |
|---|---|
| [`Entra-ID/`](./Entra-ID) | User, group, device, admin role (PIM), Conditional Access, MFA, application registration, and application proxy management |
| [`Azure/`](./Azure) | RBAC analysis/consolidation and Key Vault secret management |
| [`Microsoft365/`](./Microsoft365) | License inventory, reporting, and threshold alerting |
| [`DeveloperTools/`](./DeveloperTools) | Static analysis, auto-documentation, and module packaging for this toolkit's own scripts |
| [`Modules/CloudIdentityToolkit.Common`](./Modules/CloudIdentityToolkit.Common) | Shared logging/output helpers used across all scripts |

## Roadmap

This is a long-term, continuously growing project. Planned additions include:

- **AWS IAM** — identity governance and access analysis
- **Microsoft Defender** — security posture and alert automation

Follow the repo or ⭐ star it to track progress as these areas are added.

## Quick start

```powershell
git clone https://github.com/lakshmananthangaraj/cloud-identity-toolkit.git
cd cloud-identity-toolkit
```

Each script includes built-in help documentation and practical examples.

## Security

* No credentials, secrets, or production data are included.
* All examples use placeholder tenants, domains, and identifiers.
* Required permissions are documented for every solution.
* Please review scripts carefully before using them in production environments.

## Contributing

Contributions, suggestions, and discussions are welcome. This repository is maintained as a continuous learning and knowledge-sharing initiative.

## License

MIT - see [LICENSE](./LICENSE).
