# IntuneGuard Studio — Product & Engineering Roadmap

This roadmap captures the next high-leverage evolutions designed to keep **IntuneGuard Studio** evergreen as Microsoft Intune evolves and teams scale adoption.

---

## Phase 1.5 — Full Real-Tenant Export Parity (Immediate Next Step)
- Expand `Export-IntuneGuardSnapshot.ps1` and `POST /api/tenant/import` to also ingest real tenant exports for:
  - Enrollment Status Page (ESP) profiles & Windows Autopilot Deployment Profiles (Track 3)
  - Custom Intune RBAC Role Definitions & Role Assignments (Track 4)
  - Role Scope Tags & policies missing the `Default` (`0`) tag (Track 5)
  - On-prem AD GPO Backup XML folder import (automatic tattooed GPO collision detection)

## Phase 2 — Team Collaboration & Outage Backtracking
- **Multi-Engineer Track Ownership & Soft Locks:** Allow engineers to claim active Tracks (e.g., Engineer A on Track 2 Nested Groups, Engineer B on Track 4 RBAC) so teams work in parallel without overlapping edits.
- **Incident / Outage Backtrack Timeline:** Enter an outage window (e.g., *"Branch check scanners stopped working Tuesday 10:15 AM"*) to automatically correlate Intune Graph `auditEvents`, recent Ring promotions, and Tenant Context Memory—surfacing likely root causes and 1-click rollback payloads.
- **Automated Drift Webhooks:** Scheduled read-only Graph polling comparing live state against Git snapshots, pushing human-readable before/after diffs to Microsoft Teams, ServiceNow, or Jira when unapproved portal edits occur.

## Phase 3 — Evergreen Intune Release & Baseline Sync (Living Tracks)
- **Monthly Microsoft Intune Release Feed:** Track official Microsoft Intune monthly releases ("What's New in Microsoft Intune"), new Settings Catalog URIs, deprecated policies, Windows Autopatch changes, and Multi-Admin Approval (MAA) expansions.
- **Automated OIB & CIS Benchmark Diffing:** Pull updated OpenIntuneBaseline (OIB) and CIS Intune Benchmark versions as declarative JSON catalogs, flagging *"New Control Available"* or *"Setting Deprecated"* badges directly inside the relevant Learning Track without rewriting core code.
- **Release Impact Alerts:** Warn teams proactively when a Microsoft release affects an existing Tenant Context Memory exception or Automation Enterprise App.

## Phase 4 — Advanced Modernization & Portfolio Distribution
- **Track 7: Direct AD Domain-Joined → Entra ID Joined Readiness & Cutover:** Pre-flight checklist (BitLocker Entra escrow, Cloud Kerberos Trust, GPO scrub, Autopilot hash capture, single-reboot cutover orchestration).
- **Static GitHub Pages Interactive Demo Export:** Optional read-only static build for portfolio, LinkedIn, and conference/peer demos with zero backend hosting required.
