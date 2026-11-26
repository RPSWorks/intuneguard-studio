# Leadership Rollout Playbook & Plain-English Tenant Memory Guide

A practical, zero-jargon guide to pitching **IntuneGuard Studio** (`Learn → Clean → Govern`), standing up resilient core infrastructure inside a regulated enterprise, and explaining **Tenant Context Memory** clearly to leadership, InfoSec, and traditional IT teams.

---

## Part 1: What "Tenant Memory" Actually Is (In Plain Terms)

> **Executive Summary:** "Tenant Memory" is **NOT** a cloud AI service and does **NOT** send your data anywhere. It is simply a **structured, local institutional logbook** that lives on your own server and records *what* your team cleaned, *what* standards you adopted, and *why* exceptions exist.

### Why Traditional Teams Need It
In most Intune environments, critical decisions live in someone's head, buried in a 2-year-old email, or lost when an engineer leaves:
- *"Why is Defender ASR turned off on these machines?"* → Because a 3rd-party EDR disables Defender; turning it on causes conflicts.
- *"Why are these 42 OptiPlex devices excluded from standard update rings?"* → Because they are locked-down AVD thin-client kiosks.
- *"Why do we only allow 3 Scope Tags?"* → Because removing the `Default` tag previously hid 34 policies from auditors and caused duplicate sprawl.

Without a shared logbook, the next engineer undoes your fix—causing repeat outages or audit findings. **Tenant Memory** captures those decisions right inside the workflow (Step 4 of every Track) and ties them to your tamper-evident ITIL audit trail.

### Where Tenant Memory Physically Lives
Everything stays **100% inside your own network** in one configurable folder (`INTUNEGUARD_DATA_DIR`, defaulting to `./data/`):

| File | Format | What It Stores | How to Back Up / Retain |
| :--- | :--- | :--- | :--- |
| `data/intuneguard_audit.db` | Standard **SQLite** database (single file) | `tenant_memory` (team decisions & exceptions), `environment_profile` (3rd-party EDR/DLP/SCCM stack), `rollout_state` (ring history), `pending_proposals` (CAB queue), and `audit_events` (SHA-256 hash-chained log) | Standard nightly file backup, VM snapshot, or persistent **Azure Files / Docker volume** |
| `data/itil_audit_trail.jsonl` | Plain-text **JSON Lines** (append-only) | Exact mirror of every memory recorded, ring promotion, rollback, and CAB approval | Forward directly into **Microsoft Sentinel**, Splunk, or long-term WORM audit storage |

### Key Guarantees for InfoSec & Compliance
- **Zero External AI Cloud:** Nothing leaves your server. No external LLM sees your tenant data.
- **Portable & Vendor-Free:** Because it is plain SQLite + JSONL, you can open it with standard tools, export it to HTML/Markdown Auditor Reports anytime, and never get locked into a vendor SaaS.
- **Optional Future AI Readiness:** If your organization later adopts Copilot / Agent 365 / MCP, AI reads that exact local `tenant_memory` table (read-only) so it respects your documented exceptions instead of guessing.

---

## Part 2: Step-by-Step Leadership & Resilient Deployment Plan

### Step 1: Build Quiet Proof First (Week 1 — Zero Risk)
1. Run `Export-IntuneGuardSnapshot.ps1` (Path A) using your existing read-only Graph login (zero App Registration, zero ARB delay, zero tenant changes).
2. Load the snapshot locally in **Classic Ops View** + **Light Mode**, set your **Environment Stack Profile**, and export the **Auditor HTML Report**.
3. Pick **3 undeniable facts** to share: unapproved changes/policy sprawl count, dead-SCCM/patch stalls, and over-privileged custom RBAC or hidden Scope Tag findings.

### Step 2: The 15-Minute Leadership Pitch (Week 2)
Lead with **audit readiness, preventing outages, and \$0 new software spend** (skip AI/MCP/Docker jargon):
1. Show the exposure using your own read-only snapshot report.
2. Walk through **Learn → Clean → Govern**—emphasizing that Tracks 1, 2, 5, and 7 have **zero end-user disruption**.
3. Highlight **100% Microsoft 365 E7 native compatibility** (zero Intune Suite add-on, zero 3rd-party SaaS custody).
4. Ask only for **Phase 1 Read-Only ARB review** (`docs/SECURITY_ARB_PACKAGE.md` + `docs/GRAPH_PERMISSIONS_MATRIX.md`) and **2 hours/week** for zero-impact console cleanup.

### Step 3: Stand Up Resilient Core Infrastructure (Weeks 3–6)
Move off a single engineer's laptop onto standard enterprise infrastructure:
- **Host:** Hardened internal Windows/Linux utility VM (running `app.py` as a managed service behind internal HTTPS) **OR** a private **Azure Container App** inside your VNet.
- **Identity:** Entra App Registration (`IntuneGuard-Studio-AuditReader`) using **Azure Managed Identity** or an **X.509 Certificate** in Key Vault (never a static client secret or personal admin login), protected by **Entra Conditional Access for Workload Identities** (included in M365 E7).
- **Network Egress:** Firewall/NSG outbound locked strictly to `login.microsoftonline.com` and `graph.microsoft.com`.
- **Durability:** Nightly backup of `data/intuneguard_audit.db` + ship `data/itil_audit_trail.jsonl` to **Microsoft Sentinel** / SIEM.
- **Source Control:** Mirror into internal **Azure DevOps / GitHub Enterprise** with PR review.

### Step 4: Team Operating Cadence (Months 1–3)
- **Month 1 (CLEAN — Zero User Impact):** Divide Tracks 1 (Orphans/GPOs), 2 (Nested Groups → Flat Rings), 5 (Scope Tags), and 7 (AVD Kiosk/Multi-Session/Win10 Filters & Zombie SCCM Scrubbing) across engineers. Record every decision in **Tenant Memory**.
- **Month 2 (STABILIZE):** Execute Track 3 (Autopilot/ESP & Patch Rings) and Track 4 (Custom RBAC least privilege, Entra PIM for standing Intune Admins, Patch My PC MAA exclusion pre-flight).
- **Month 3+ (GOVERN):** Execute Track 6 (OIB/CIS Waves 1→3) with 3rd-Party EDR/DLP guardrails active and ITIL RFC gating.

### Step 5: Keep It Alive Long-Term
1. **New-Hire Onboarding:** Every new Helpdesk/Endpoint engineer runs Tracks 1–5 in Sandbox mode in Week 1 and reads **Tenant Memory** before touching production.
2. **Quarterly Audit Cadence:** Export the 1-click **Auditor HTML Report** for Compliance/CAB—once auditors rely on it, leadership protects the practice.
3. **Quarterly 30-Minute Hygiene Check:** Review monthly Microsoft Intune release changes, verify the SHA-256 audit chain, and catch drift early.
