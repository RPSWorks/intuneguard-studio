# Contributing to IntuneGuard Studio

Thank you for helping make Microsoft Intune management calmer, safer, and more approachable for engineers everywhere!

---

## Guiding Design Principles

Before opening a pull request, please keep our core architecture rules in mind:

1. **Zero Third-Party Runtime Dependencies:** Core backend, HTTP/MCP server, SQLite audit store, and frontend SPA run exclusively on the **Python 3.12 standard library** and vanilla **HTML5/CSS/ES6**. This keeps the supply chain auditable for regulated financial/enterprise Architecture Review Boards.
2. **One Calm Problem at a Time:** Avoid turning screens into overwhelming walls of text. Every new Learning Track should follow the **4-Step Loop**: `1. Learn (30 sec)` → `2. Inspect` → `3. Fix Safely` → `4. Save to Tenant Memory`.
3. **Never Auto-Write Without Human ITIL Gating:** Any MCP tool or automation that modifies Intune state must queue behind the Human-in-the-Loop CAB Approval Gate and require an ITIL RFC ticket.
4. **Never Commit Real Tenant Data:** Use only synthetic/anonymized data in fixtures and tests. `.gitignore` blocks `data/` and `*snapshot*.json`, but always double-check `git status` before pushing.

---

## High-Impact Ways to Contribute

### 1. Add or Improve a Guided Learning Track (`backend/tracks.py`)
Have a painful Intune pitfall you've solved in production (e.g., macOS Platform SSO, Windows 365 Cloud PC baselines, Defender Firewall migration, Hybrid-to-Entra cutover)?
- Add your Track definition in `backend/tracks.py` with `learn` (3 concise cards), `inspect_items`, `fix` (dry-run safe PowerShell), and `memory_template`.
- Add realistic synthetic findings in `backend/synthetic_tenant.py` so anyone can practice the Track without touching production.

### 2. Add or Update an OIB / CIS Control (`backend/baseline_catalog.py`)
- Include the exact Intune OMA-URI / Settings Catalog path, OIB recommended value, strict CIS reference, real-world **"What Breaks in Prod"** warning, pre-written **Auditor Deviation Rationale**, and self-healing `Detect.ps1` + `Remediate.ps1` Proactive Remediation scripts.

### 3. Expand Real-Tenant Snapshot Parsing (`backend/scripts_generator.py` & `backend/analyzer.py`)
- Help expand `Export-IntuneGuardSnapshot.ps1` and `import_offline_snapshot()` so additional Graph objects (ESP profiles, Autopilot profiles, Custom RBAC roles, Scope Tags, GPO Backup XMLs) map cleanly into all 6 Tracks.

### 4. Track Monthly Microsoft Intune Releases
- Submit PRs updating policy URIs, deprecations, Autopatch changes, or Multi-Admin Approval (MAA) expansions when Microsoft ships monthly Intune updates.

---

## Local Development & Verification

```bash
# 1. Start the local workbench
python app.py

# 2. Run the full automated verification suite (must pass 100%)
python -m unittest discover -s tests -v

# 3. Verify clean syntax compilation
python -m py_compile app.py mcp_server.py backend/*.py
```

### Pull Request Checklist
- [ ] Zero external Python or npm runtime dependencies added
- [ ] All unit, API, hash-chain, and MCP tests pass (`python -m unittest discover -s tests -v`)
- [ ] No real tenant IDs, UPNs, client secrets, or customer JSON snapshots included
- [ ] Clear, plain-English explanations suitable for junior and mid-level Intune engineers
