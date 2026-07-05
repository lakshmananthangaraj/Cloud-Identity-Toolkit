# Entra ID MFA Reporting and Dashboard

This folder contains automation scripts for Multi-Factor Authentication (MFA) reporting, visibility, and operational monitoring within Microsoft Entra ID environments.

The solutions collect and analyze MFA registration information for user accounts, including registered authentication methods, adoption status, and overall compliance trends. They are designed to help administrators identify registration gaps, support governance activities, and provide meaningful insights through reports and dashboards.

## Included Scripts

| Script                                  | Purpose                                                                                                          |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `Get-EntraID-MFARegistrationReport.ps1` | Collects user MFA registration details, authentication methods, and adoption metrics for reporting and analysis. |
| `Generate-MFADashboard.ps1`             | Creates an interactive dashboard to visualize MFA adoption, compliance status, and operational insights.         |

## Typical Use Cases

* MFA adoption tracking
* User registration analysis
* Security governance reporting
* Operational health reviews
* Audit preparation
* Executive and management dashboards

## Prerequisites

* Microsoft Graph PowerShell SDK
* Appropriate Entra ID permissions
* Administrative access as documented within each script

## Notes

All examples and outputs included in this repository use sanitized data and placeholder information. No production tenant details, identities, or confidential information are exposed.
