# Microsoft Graph API Least-Privilege Permissions Matrix

IntuneGuard Studio strictly separates **Phase 1 (Read-Only Discovery & Documentation)** from **Phase 2 (Scoped, RFC-Gated Rollout)** so InfoSec can approve read-only deployment rapidly without granting write access to production Intune.

---

## Phase 1: Read-Only Discovery, Conflict Analysis & As-Built Reporting (Recommended Initial ARB Approval)

**App Registration Name:** `IntuneGuard-Studio-AuditReader`  
**Auth Method:** Managed Identity (Azure Container Apps / VM) or X.509 Certificate (12-month rotation via Key Vault). **No client secrets in production.**

| Microsoft Graph Application Permission | Purpose | Endpoints Queried | MAA Impact |
| :--- | :--- | :--- | :--- |
| `DeviceManagementConfiguration.Read.All` | Read Settings Catalog, Device Configs, Endpoint Security, Update Rings & Compliance policies | `/beta/deviceManagement/configurationPolicies`, `/v1.0/deviceManagement/deviceConfigurations`, `/v1.0/deviceManagement/deviceCompliancePolicies` | None (`GET` exempt) |
| `DeviceManagementManagedDevices.Read.All` | Read device OS build, join state, compliance status & ring telemetry | `/v1.0/deviceManagement/managedDevices` | None (`GET` exempt) |
| `DeviceManagementApps.Read.All` | Optional inventory of deployed Win32/LOB apps for As-Built documentation | `/v1.0/deviceManagement/mobileApps` | None (`GET` exempt) |
| `Group.Read.All` | Read Entra security & dynamic device groups to resolve nested group chains & membership rules | `/v1.0/groups`, `/v1.0/groups/{id}/members` | None (`GET` exempt) |
| `AuditLog.Read.All` | Correlate Intune configuration changes with actor UPN, timestamp, and unapproved portal edits | `/v1.0/deviceManagement/auditEvents` | None (`GET` exempt) |
| `Application.Read.All` | Pre-flight audit of Enterprise Apps holding Intune write scopes prior to enabling Multi-Admin Approval (MAA) | `/v1.0/servicePrincipals` | None (`GET` exempt) |

> **Explicitly NOT Requested in Phase 1:** Zero `ReadWrite` permissions, zero `Directory.ReadWrite.All`, zero `RoleManagement`, zero mail/SharePoint/user data access.

---

## Phase 2: Optional Scoped Write App Registration (Only After Phase 1 Sign-Off)

**App Registration Name:** `IntuneGuard-Studio-RolloutOperator`  
**Governance Controls:**
- Protected by **Conditional Access for Workload Identities** (included in **Microsoft Entra Suite / M365 E7**) restricting sign-ins exclusively to your internal egress IP / Azure VNet.
- Must be paired with `INTUNEGUARD_REQUIRE_RFC=true` and Intune **Multi-Admin Approval (MAA)** policy review.

| Microsoft Graph Application Permission | Purpose | Scope Restriction / Guardrail |
| :--- | :--- | :--- |
| `DeviceManagementConfiguration.ReadWrite.All` | Stage OIB/CIS Settings Catalog profiles, ring assignments, and Proactive Remediation scripts | Only triggered via CAB-approved ITIL RFC workflow; never auto-executed by MCP agents. |
| `GroupMember.ReadWrite.All` *(or scoped to Ring Groups via Administrative Units)* | Manage dedicated `SG-Intune-OIB-Ring*` groups only | Scope via Entra **Restricted Management Administrative Units (RMAU)** where supported. |

---

## Outbound Firewall / NSG Allowlist

For regulated network segmentation, restrict outbound TCP/443 from the IntuneGuard Studio container exclusively to:
1. `login.microsoftonline.com` (OAuth 2.0 token acquisition)
2. `graph.microsoft.com` (Microsoft Graph API v1.0 / beta)
