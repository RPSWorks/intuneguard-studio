# Security & Architecture Review Board (ARB) Submission Package

Use this document directly when submitting **IntuneGuard Studio** for InfoSec, Risk Management, and Architecture Review Board sign-off in regulated financial institutions (NCUA / FFIEC / GLBA / SOC 2).

---

## 1. Deployment & Custody Profile

| Security Domain | Control Implemented |
| :--- | :--- |
| **Data Residency / Custody** | 100% self-hosted inside customer boundary. Zero external SaaS control plane. Zero telemetry phoning home. |
| **Network Egress** | Default `synthetic` mode makes **zero** outbound network calls. `live` mode enforces a hardcoded host allowlist (`login.microsoftonline.com`, `graph.microsoft.com`). |
| **Supply Chain / SBOM** | Zero third-party Python packages and zero external JavaScript CDNs/npm packages. Entire runtime is Python 3.12 standard library + first-party code. |
| **Container Hardening** | Runs as non-root UID `10001`, `read_only: true` root filesystem, `no-new-privileges:true`, binds to `127.0.0.1` by default. |
| **HTTP Security Headers** | Enforces `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. |
| **Credential Hygiene** | Never stores credentials in code or SQLite. Production deployment uses **Azure Managed Identity** or **X.509 Certificate / Workload Identity Federation** (zero long-lived client secrets). |
| **ITIL Change Control** | `INTUNEGUARD_REQUIRE_RFC=true` blocks all state transitions lacking a valid Change Ticket / RFC identifier. |
| **Tamper-Evident Logging** | SHA-256 hash-chained SQLite + append-only JSONL exportable directly to Microsoft Sentinel. |

---

## 2. Threat Model & Mitigations

| Threat Scenario | Likelihood (Without Control) | Built-In Mitigation |
| :--- | :--- | :--- |
| **AI / MCP Agent executes unauthorized production Intune change** | High (if naive write tools exposed) | `propose_policy_change` **never** writes directly to Intune. It writes a `PENDING_APPROVAL` record requiring human CAB sign-off with an ITIL RFC ticket. |
| **Compromised container exfiltrates tenant JSON to external host** | Medium | Hardcoded `ALLOWED_LIVE_HOSTS` guard in `LiveGraphAdapter` + recommended Azure NSG / firewall egress rule restricting container outbound traffic strictly to Microsoft Graph IP service tags. |
| **Privilege escalation via over-scoped Entra App Registration** | High | Split App Registration model: Phase 1 uses strictly `*.Read.All` permissions; zero Global Admin or User/Role write permissions. |
| **Enabling Intune Multi-Admin Approval (MAA) breaks existing automation** | High | Built-in MAA Enterprise App Pre-Flight Audit identifies every service principal holding `DeviceManagement*.ReadWrite.All` before MAA is enabled. |
| **Rollout breaks branch check scanners, VoIP softphones, or LOB apps** | High (with raw CIS L2) | OIB common-sense defaults, explicit production breakage callouts, mandatory Ring 0 (Audit) soaking, and 1-click rollback. |

---

## 3. Regulatory Alignment Mapping

- **NCUA 12 CFR Part 748 & ACET:** BitLocker XTS-AES 256 encryption-at-rest, Defender ASR ransomware mitigation, Windows LAPS privileged access control, 14-day patching cadence, removable media write controls, and documented change governance.
- **FFIEC CAT (Cybersecurity Assessment Tool):** Maps directly to Domain 3 (Cybersecurity Controls) — Asset & Configuration Management, Access Control, Patch Management, and Change Management.
- **GLBA Safeguards Rule:** Protects non-public personal information (NPI) on branch and remote endpoints via BitLocker + Purview DLP + USB write restrictions + audited compliance evidence exports.
- **ITIL v4 Change Enablement:** Enforces RFC ticket tagging, pre-change conflict/risk assessment, phased ring implementation, post-change verification, and tamper-evident audit logging.
