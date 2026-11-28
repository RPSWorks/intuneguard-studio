<p align="center">
  <img src="web/assets/logo.png" alt="IntuneGuard Studio Logo" width="136" />
</p>

<h1 align="center">IntuneGuard Studio</h1>

<p align="center">
  <strong>Guided Intune Learning Tracks • Tenant Context Memory • Safe OIB/CIS Rollout • Governed MCP Server</strong><br>
  <em>Open-Source (MIT) • Python 3.12 Stdlib Only • Zero 3rd-Party SaaS Custody • Microsoft 365 E7 Native</em>
</p>

---

Instead of dumping 400 policies and every Intune discipline onto one overwhelming screen, **IntuneGuard Studio** breaks endpoint modernization into **7 bite-sized Guided Tracks**—so engineers of any experience level can pick **one** pitfall today, learn *why* it breaks tenants, inspect *only* what's broken for that topic, fix it safely, and save what they learned into a persistent **Tenant Context Memory** shared by both the team and AI/MCP agents.

Built with **zero third-party runtime dependencies** (pure Python 3.12 stdlib + self-contained HTML/CSS/JS SPA) for regulated financial, healthcare, and enterprise Architecture Review Boards (ARBs). Runs natively on **Microsoft 365 E7 ("Frontier Suite")** with **\$0 add-on spend** (no Intune Suite required).

---

## The 7 Guided Learning Tracks (4-Step Calm Loop)

Every Track follows the same consistent loop: **`1. Learn (30 sec)` → `2. Inspect` → `3. Fix Safely` → `4. Save to Tenant Memory`**

| Track | Focus Area | What It Solves |
| :--- | :--- | :--- |
| **1. Policy Sprawl & GPO Collisions** | Console Hygiene | Unassigned orphans, duplicates, conflicting policies, and tattooed on-prem AD GPO locks |
| **2. Nested Group Detox & Exclusions** | Targeting Architecture | 3-level nested dynamic/static group chains & stale troubleshooting bypasses → 4 clean flat Ring groups |
| **3. Autopilot, ESP & Patch Ring Rescue** | Provisioning & Patching | Mixed Win32/LOB ESP crashes (`0x80070652`), OOBE update timeouts, Device-vs-User update ring reboots, Feature Update ASAP bypasses |
| **4. Over-Privileged Custom RBAC & MAA** | Least Privilege | Tier-1 custom roles accidentally granting Wipe/Delete/Script powers, standing Intune Admins → Entra PIM, and MAA Enterprise App pre-flight |
| **5. Scope Tags & "Invisible Objects"** | Admin Visibility | Policies missing the `Default` tag hiding from HQ/Auditors (fueling duplicates), branch devices missing tags, Scope Tags mistaken for targeting |
| **6. Safe OIB / CIS Compliance Waves** | Hardening Without Breakage | 3-wave OpenIntuneBaseline vs. CIS v5.0.0 rollout with 3rd-party EDR/DLP coexistence guardrails, pre-written auditor rationales, 1-click rollback & Proactive Remediations |
| **7. Device Personas, Kiosks, AVD & Zombie SCCM** | M&A / Mixed-Fleet Reality | Assignment Filter isolation for AVD kiosks, multi-session AVD hosts, EOL Win10 stragglers, active Co-Managed ConfigMgr sliders, and orphaned `ccmexec` / `Registry.pol` scrubbing |

---

## Built for Real-World Traditional & Modern Teams

- **Multi-Engineer Track Ownership:** Engineers can claim active Tracks (preventing overlapping edits across teams) while recording standards into shared **Tenant Context Memory**.
- **Incident / Outage Backtrack Timeline:** Type any outage symptom (`scanner`, `firewall`, `update`, `uac`, `bitlocker`) to correlate unapproved portal edits, SHA-256 ITIL audit events, Tenant Memory decisions, and **1-click rollback candidates**.
- **Real On-Prem AD GPO XML Scanner:** Upload a standard GPMC report (`Get-GPOReport -All -ReportType Xml -Path .\ad_gpos.xml`) for automatic, XXE-safe detection of WSUS, BitLocker, Legacy LAPS, Firewall, Defender, UAC, Edge, and USB GPO collisions.
- **Classic Ops Mode vs. AI/MCP Mode + Light & Dark Themes:** Present cleanly to traditional ops teams in **Classic Ops Mode** (zero AI/MCP jargon on screen) with 1-click Light/Dark mode switching—and flip **AI / MCP View** on when integrating Copilot or Agent 365.
- **Zero-Docker Windows Launcher:** Double-click `Start-IntuneGuard.bat` (or run `python app.py`)—no containers required.
- **3rd-Party Security Stack Coexistence:** Built-in Environment Stack Profile automatically adapts OIB/CIS guardrails when a 3rd-party EDR disables Defender or a 3rd-party DLP/ConfigMgr environment is active, preventing accidental Conditional Access lockouts.

---

## Why Teams & Auditors Love It

- **Built for Multi-Engineer Teams:** Engineers can tackle independent tracks in parallel without stepping on each other, while building a shared **Tenant Context Memory** of standards, exceptions, and cleanup decisions.
- **Historical Context & Outage Backtracking:** Every ring promotion, rollback, track decision, and MCP action is recorded in a local **SHA-256 hash-chained SQLite + JSONL ITIL audit trail** with mandatory RFC ticket gating.
- **Zero-Wait Real-Tenant Integration:**
  - **Path A (Day 1 — Zero App Reg, Zero ARB Wait):** Download `Export-IntuneGuardSnapshot.ps1` (read-only interactive Graph login) and upload the JSON straight into the browser.
  - **Path B (Ongoing Live Integration):** Download `New-IntuneGuardAppReg.ps1` (X.509 cert, zero client secrets, strictly 6 `*.Read.All` scopes, code-enforced outbound allowlist to `graph.microsoft.com` / `login.microsoftonline.com`).
- **AI / MCP That Learns Your Tenant:** Exposes **9 JSON-RPC 2.0 MCP tools** over both `stdio` (`mcp_server.py`) and `POST /mcp`—including `get_tenant_context_memory` (so Copilot / VS Code / local LLMs inherit your team's accumulated tenant context) and `propose_policy_change` (strictly gated behind the Human-in-the-Loop CAB Approval Queue).

---

## Quick Start (Zero Dependencies, Runs in 5 Seconds)

```bash
python app.py
```

Open **http://127.0.0.1:8095** in your browser.

### Run the Standalone MCP Server (`stdio`)
```bash
python mcp_server.py
```

### Run via Hardened Docker Container
```bash
docker compose up --build
```

### Run Automated Verification Suite (12 End-to-End Tests)
```bash
python -m unittest discover -s tests -v
```

---

## Enterprise ARB, E7 Licensing & Roadmap Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — System design, data flows, Mermaid diagrams, and MCP governance boundary
- [`docs/SECURITY_ARB_PACKAGE.md`](docs/SECURITY_ARB_PACKAGE.md) — Threat model, outbound allowlist enforcement, SHA-256 audit chain, and NCUA/FFIEC/GLBA alignment
- [`docs/GRAPH_PERMISSIONS_MATRIX.md`](docs/GRAPH_PERMISSIONS_MATRIX.md) — Least-privilege Graph API scopes (Phase 1 Read-Only vs. Phase 2 Scoped Write)
- [`docs/LICENSING_COMPATIBILITY_E7.md`](docs/LICENSING_COMPATIBILITY_E7.md) — Microsoft 365 E7 ("Frontier Suite") native capability map (zero Intune Suite add-on required)
- [`docs/LEADERSHIP_ROLLOUT_PLAYBOOK.md`](docs/LEADERSHIP_ROLLOUT_PLAYBOOK.md) — Step-by-step leadership pitch, resilient deployment guide, and plain-English Tenant Memory explanation
- [`docs/ENTERPRISE_AI_APIM_MCP_FIT.md`](docs/ENTERPRISE_AI_APIM_MCP_FIT.md) — Level 2.5 Azure APIM AI Gateway-governed MCP integration & Day-1 SharePoint Agent Knowledge Base export
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — Shipped v1.0.x milestones and upcoming v1.1.0 (Deep Graph Parity), v1.2.0 (Offline Drift & Static Demo), and v2.0.0 (Evergreen Catalog & IaC) plans
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — How to add new Guided Learning Tracks, OIB/CIS controls, and Graph parsers
- [`SECURITY.md`](SECURITY.md) — Architectural security guarantees & responsible vulnerability disclosure
- [`LICENSE`](LICENSE) — MIT Open-Source License
