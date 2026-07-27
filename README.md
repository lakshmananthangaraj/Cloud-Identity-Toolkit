# Cloud Identity Toolkit

A curated, public toolkit of PowerShell scripts and runbooks for managing Entra ID, Azure, and Microsoft 365 identity governance at scale — built from real-world automation work, redacted and generalized for public use.

**Who this is for:** IT professionals, security engineers, cloud architects, and anyone interested in practical identity and governance solutions across Microsoft cloud ecosystems.

## Architecture Overview

```mermaid
flowchart TD

subgraph group_shared["Shared PowerShell"]
  node_common_manifest["Common module manifest<br/>PowerShell manifest"]
  node_common_module["Common presentation module<br/>PowerShell module"]
  node_logging["Logging helper<br/>PowerShell script<br/>[Add-Log.ps1]"]
end

subgraph group_entra["Entra ID operations"]
  node_entra_auth{{"Entra authentication<br/>PowerShell script"}}
  node_jwt_inspection["JWT token inspection<br/>PowerShell script"]
  node_directory_reporting["Directory inventory<br/>PowerShell scripts<br/>[Get-AllUsers.ps1]"]
  node_stale_devices["Stale device report<br/>PowerShell script"]
  node_mfa_dashboard["MFA dashboard<br/>PowerShell script"]
end

subgraph group_governance["Access governance"]
  node_privileged_roles["Privileged role analysis<br/>PowerShell script"]
  node_conditional_access["Conditional Access report<br/>PowerShell script"]
  node_app_proxy["Application proxy inventory<br/>PowerShell script"]
  node_app_identity["Application identity reporting<br/>PowerShell scripts"]
  node_site_selected_read["Site Selected permissions<br/>PowerShell script"]
  node_site_selected_grant{{"Grant Site Selected permission<br/>PowerShell script"}}
end

subgraph group_cloud["Azure & Microsoft 365"]
  node_azure_admin["Azure administration<br/>PowerShell scripts"]
  node_m365_licensing["Microsoft 365 licensing alert<br/>PowerShell script"]
end

subgraph group_developer["Developer automation"]
  node_static_analysis["Static analysis<br/>PowerShell script"]
  node_documentation["Markdown documentation<br/>PowerShell script"]
  node_module_builder["Module builder<br/>PowerShell script"]
end

node_operators(("Operators<br/>human & non-human<br/>(service principals, managed identities, automation)"))
node_tenant_services[("Microsoft cloud services<br/>external services")]

node_operators -->|"invoke"| node_entra_auth
node_operators -->|"invoke"| node_directory_reporting
node_operators -->|"invoke"| node_privileged_roles
node_operators -->|"authorize and invoke"| node_site_selected_grant
node_operators -->|"invoke"| node_azure_admin
node_operators -->|"invoke"| node_m365_licensing
node_common_manifest -->|"declares"| node_common_module
node_common_module -->|"includes"| node_logging
node_entra_auth -->|"authenticates to"| node_tenant_services
node_jwt_inspection -.->|"inspects tokens from"| node_entra_auth
node_directory_reporting -->|"queries"| node_tenant_services
node_stale_devices -->|"queries"| node_tenant_services
node_mfa_dashboard -->|"queries"| node_tenant_services
node_privileged_roles -->|"queries"| node_tenant_services
node_conditional_access -->|"queries"| node_tenant_services
node_app_proxy -->|"queries"| node_tenant_services
node_app_identity -->|"queries"| node_tenant_services
node_site_selected_read -->|"queries"| node_tenant_services
node_site_selected_grant -->|"changes authorization"| node_tenant_services
node_azure_admin -->|"manages and queries"| node_tenant_services
node_m365_licensing -->|"checks licensing"| node_tenant_services
node_static_analysis -.->|"supports maintained scripts"| node_documentation
node_documentation -.->|"documents packaged scripts"| node_module_builder
node_module_builder -.->|"builds modules from scripts"| node_common_module

click node_common_manifest "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Modules/CloudIdentityToolkit.Common/CloudIdentityToolkit.Common.psd1"
click node_common_module "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Modules/CloudIdentityToolkit.Common/CloudIdentityToolkit.Common.psm1"
click node_logging "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Modules/CloudIdentityToolkit.Common/Add-Log.ps1"
click node_entra_auth "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/Authentication/Connect-EntraID.ps1"
click node_jwt_inspection "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/Authentication/ConvertFrom-JwtToken.ps1"
click node_directory_reporting "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/Users/Get-AllUsers.ps1"
click node_stale_devices "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/Devices/Get-StaleDevices.ps1"
click node_mfa_dashboard "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/MFA/Generate-MFADashboard.ps1"
click node_privileged_roles "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/PIM/Get-PIMActiveEntraIDRoleAssignmentDetails.ps1"
click node_conditional_access "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/ConditionalAccess/Get-ConditionalAccessPoliciesReport.ps1"
click node_app_proxy "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/ApplicationProxy/Get-AppProxyApplications.ps1"
click node_app_identity "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/AppRegistrations/Get-AppRegistrationSecretReport.ps1"
click node_site_selected_read "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/AppRegistrations/Get-AppSiteSelectedPermissions.ps1"
click node_site_selected_grant "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Entra-ID/AppRegistrations/Grant-SharePointSiteSelectedPermission.ps1"
click node_azure_admin "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Azure/KeyVault/New-AzureKeyVaultSecret.ps1"
click node_m365_licensing "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/Microsoft365/Licensing/Send-M365LicenseThresholdAlert.ps1"
click node_static_analysis "https://github.com/lakshmananthangaraj/cloud-identity-toolkit/blob/main/DeveloperTools/CodeQuality/Invoke-ScriptAnalyzer.ps1"
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
class node_entra_auth,node_jwt_inspection,node_directory_reporting,node_stale_devices,node_mfa_dashboard toneAmber
class node_privileged_roles,node_conditional_access,node_app_proxy,node_app_identity,node_site_selected_read,node_site_selected_grant toneMint
class node_azure_admin,node_m365_licensing toneRose
class node_static_analysis,node_documentation,node_module_builder toneIndigo
class node_operators,node_tenant_services toneNeutral
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
- **Microsoft Intune** — device compliance and configuration management scripts

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
