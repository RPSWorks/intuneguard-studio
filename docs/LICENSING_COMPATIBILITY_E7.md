# Microsoft 365 E7 ("Frontier Suite") Licensing Compatibility Matrix

> **Executive Bottom Line:** IntuneGuard Studio runs **100% natively on your existing Microsoft 365 E7 licensing** with **\$0 in additional Microsoft add-on spend** (no Intune Suite add-on required, no third-party SaaS per-seat fees).

---

## How Each IntuneGuard Studio Capability Maps to M365 E7

Microsoft 365 E7 bundles **Microsoft 365 E5**, **Microsoft 365 Copilot**, **Microsoft Entra Suite**, and **Microsoft Agent 365**. Here is the exact 1-to-1 licensing alignment:

| IntuneGuard Studio Feature | Underlying Microsoft Capability | Included in M365 E7? | Notes for Procurement / ARB |
| :--- | :--- | :---: | :--- |
| **OIB & CIS Safe Rollout Policies** | Microsoft Intune Plan 1 (Settings Catalog, Endpoint Security, Device Compliance) | **Yes** (via E5) | Zero Intune Suite add-on needed. |
| **Self-Healing Scripts (`Detect.ps1` / `Remediate.ps1`)** | Intune Endpoint Analytics — Proactive Remediations | **Yes** (via Win11 Enterprise E5) | Fully licensed under E5/E7; deploys native PowerShell self-healing loops. |
| **4-Ring Patching & OOBE Fix** | Windows Update for Business & Windows Autopatch | **Yes** (via Win11 Enterprise E5) | Covers OS Quality, Feature, .NET, Drivers, and Quick Machine Recovery (QMR). |
| **ASR Ring 0 Audit Telemetry** | Microsoft Defender for Endpoint Plan 2 (Advanced Hunting) | **Yes** (via E5 Security) | Harvests legitimate branch peripheral/LOB exclusions during 14-day Audit soak. |
| **Zero Trust Compliance Enforcement** | Entra ID P2 Conditional Access & Risk Policies | **Yes** (via E5 / Entra Suite) | Enables Report-Only Ring 0 validation before enforcing device compliance. |
| **Workload Identity & Network Controls** | Microsoft Entra Suite (Conditional Access for Workload Identities + Global Secure Access) | **Yes** (Bundled in E7) | Locks down IntuneGuard Graph App Registration to corporate VNet/IP. |
| **Removable Media / PII DLP** | Defender Device Control + Microsoft Purview Endpoint DLP | **Yes** (via E5 Compliance) | Prevents member PII exfiltration on unencrypted USB while allowing branch scanners. |
| **Multi-Admin Approval (MAA)** | Intune Tenant Administration MAA | **Yes** (via Intune P1) | Dual-control approval for wipes, scripts, RBAC, and policies. |
| **MCP Server & Agentic Governance** | Microsoft 365 Copilot + **Microsoft Agent 365** | **Yes** (Bundled in E7) | IntuneGuard's MCP server + HITL CAB gate aligns directly with Agent 365 agent observation & governance controls. |

---

## Explicitly Avoided Paid Add-Ons

To prevent unexpected licensing surprises during Architecture Review:
- **Microsoft Intune Suite (add-on):** **NOT required.** We do not depend on Endpoint Privilege Management (EPM), Remote Help, or Enterprise App Management—standard UAC Secure Desktop + Windows LAPS (Entra ID backed) + Proactive Remediations achieve the compliance goals natively within E7.
- **Third-Party SaaS Configuration Managers (Simeon/CoreView, Inforcer):** **NOT required.** Self-hosting IntuneGuard Studio eliminates recurring SaaS subscription bloat and third-party credential custody risks.
