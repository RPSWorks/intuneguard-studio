"""Core IntuneGuard Studio Analysis, Safe Rollout, Conflict Resolution & Report Engine."""
from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from backend.audit_store import AuditStore
from backend.baseline_catalog import (
    BASELINE_CONTROLS,
    RING_METADATA,
    RING_ORDER,
    get_control_by_id,
)
from backend.config import AppConfig
from backend.gpo_parser import parse_gpmc_xml
from backend.graph_adapter import TenantAdapter
from backend.snapshot_normalizer import infer_setting_key as _infer_setting_key
from backend.snapshot_normalizer import normalize_graph_payload
from backend.scripts_generator import (
    generate_app_registration_script,
    generate_offline_export_script,
    generate_orphan_cleanup_script,
    generate_stale_group_cleanup_script,
)
from backend.tracks import (
    AUTOPILOT_ESP_AUDIT_PS1,
    RBAC_AUDIT_PS1,
    SCOPE_TAG_AUDIT_PS1,
    ZOMBIE_SCCM_AND_PERSONAS_PS1,
    build_guided_tracks,
)


class IntuneGuardEngine:
    def __init__(self, config: AppConfig, adapter: TenantAdapter, audit_store: AuditStore) -> None:
        self.config = config
        self.adapter = adapter
        self.audit = audit_store
        self._snapshot = self.adapter.fetch_tenant_snapshot()
        self._seed_initial_audit_if_empty()

    def _seed_initial_audit_if_empty(self) -> None:
        if not self.audit.list_events(limit=1):
            self.audit.log_event(
                actor="system@intuneguard.local",
                channel="SYSTEM_BOOT",
                action="TENANT_BASELINE_SNAPSHOT",
                target_id=self._snapshot["tenant"]["tenant_id"],
                rfc_ticket="INIT-BASELINE",
                status="SUCCEEDED",
                after_state={
                    "mode": self._snapshot["tenant"]["mode"],
                    "total_policies": len(self._snapshot["policies"]),
                    "total_groups": len(self._snapshot["groups"]),
                },
                rationale="Initial read-only tenant discovery and baseline readiness snapshot.",
            )

    def get_tenant_overview(self) -> dict[str, Any]:
        policies = self._snapshot["policies"]
        groups = self._snapshot["groups"]
        gpos = self._snapshot["tattooed_gpos"]
        unapproved = self._snapshot["unapproved_changes"]
        controls = self.evaluate_baseline_dry_run()

        status_counts = Counter(p["status_flag"] for p in policies)
        category_counts = Counter(p["category"] for p in policies)
        nested_groups = [g for g in groups if g["nested_children"]]
        risky_groups = [g for g in groups if g["risk_flag"]]

        ring_counts = Counter(c["current_ring"] for c in controls)
        deployed_score = sum(
            {"Not Deployed": 0, "Ring 0 (Audit)": 25, "Ring 1 (IT Pilot)": 55, "Ring 2 (Branch/Early)": 80, "Ring 3 (Broad Prod)": 100}[c["current_ring"]]
            for c in controls
        )
        readiness_pct = round(deployed_score / max(len(controls), 1))

        # Baseline policies without RFC tags (change control gap)
        no_rfc_count = sum(1 for p in policies if not p.get("rfc_tag"))

        return {
            "tenant": self._snapshot["tenant"],
            "kpis": {
                "total_policies": len(policies),
                "conflicting_policies": status_counts["conflict"],
                "duplicate_policies": status_counts["duplicate"],
                "orphaned_policies": status_counts["orphaned"],
                "unapproved_portal_edits": status_counts["unapproved_change"] + len(unapproved),
                "policies_without_rfc_pct": round((no_rfc_count / max(len(policies), 1)) * 100, 1),
                "total_groups": len(groups),
                "nested_group_chains": len(nested_groups),
                "high_risk_groups": len(risky_groups),
                "tattooed_gpos": len(gpos),
                "oib_rollout_progress_pct": readiness_pct,
                "controls_total": len(controls),
                "controls_in_ring": dict(ring_counts),
            },
            "policies_by_category": dict(category_counts.most_common()),
            "recent_unapproved_changes": unapproved,
            "enterprise_apps_maa_audit": self._snapshot["enterprise_apps"],
            "audit_chain_integrity": self.audit.verify_chain(),
            "e7_compatibility": {
                "license": "Microsoft 365 E7 (Frontier Suite)",
                "intune_suite_required": False,
                "included_capabilities_used": [
                    "Microsoft Intune Plan 1 (Settings Catalog, Endpoint Security, Compliance, MAA)",
                    "Intune Proactive Remediations (Self-Healing PowerShell Detect/Remediate)",
                    "Windows Autopatch & WUfB Patching Rings",
                    "Microsoft Defender for Endpoint P2 (ASR Audit Telemetry & Advanced Hunting)",
                    "Microsoft Entra Suite (Conditional Access, Workload Identity Governance, LAPS)",
                    "Microsoft 365 Copilot & Agent 365 (Governed MCP Integration)",
                ],
            },
        }

    def evaluate_baseline_dry_run(self) -> list[dict[str, Any]]:
        policies = self._snapshot["policies"]
        gpos = self._snapshot["tattooed_gpos"]
        rollout_states = self.audit.get_rollout_states()
        env_profile = self.audit.get_environment_profile()
        total_devices = self._snapshot["tenant"]["devices"].get("total_managed_windows") or 485

        results: list[dict[str, Any]] = []
        for ctrl in BASELINE_CONTROLS:
            ctrl = dict(ctrl)  # shallow copy so dynamic coexistence adaptation never mutates catalog
            matching_policies = [p for p in policies if p["setting_key"] == ctrl["setting_key"]]
            matching_gpos = [g for g in gpos if g["setting_key"] == ctrl["setting_key"]]
            state = rollout_states.get(ctrl["id"])
            current_ring = state["current_ring"] if state else "Not Deployed"
            ring_info = RING_METADATA[current_ring]

            # Dynamic Coexistence Guardrails for real-world 3rd-party EDR / DLP / SCCM stacks
            coexistence_override = None
            if env_profile.get("edr_provider") == "third_party_disabled":
                if ctrl["id"] == "OIB-DEF-002":
                    coexistence_override = "Managed by 3rd-Party EDR — Skip ASR"
                    ctrl["what_breaks_in_prod"] = (
                        "[COEXISTENCE GUARDRAIL] Defender is DISABLED because a 3rd-party EDR is active (non-passive). "
                        "Do NOT deploy Defender ASR rules until EDR passive-mode coexistence is solved or you migrate to MDE."
                    )
                    ctrl["deviation_rationale"] = (
                        "Documented compensating control: Ransomware & exploit prevention are enforced by the active 3rd-party EDR agent. "
                        "Defender ASR is intentionally deferred to prevent driver/service conflicts."
                    )
                elif ctrl["id"] == "OIB-CMP-008":
                    ctrl["what_breaks_in_prod"] = (
                        "[CRITICAL LOCKOUT GUARDRAIL] Because Defender is DISABLED by 3rd-party EDR, NEVER check "
                        "'Require Defender Real-Time Protection' in Intune Compliance + Conditional Access—doing so locks out all users! "
                        "Enforce BitLocker + Secure Boot + Min OS Build + 3rd-Party EDR custom compliance script instead."
                    )
            if env_profile.get("dlp_provider") == "third_party_dlp" and ctrl["id"] == "OIB-USB-010":
                coexistence_override = "Coexistence Review — 3rd-Party DLP Active"
                ctrl["what_breaks_in_prod"] = (
                    "[COEXISTENCE GUARDRAIL] A 3rd-party DLP agent already governs USB/removable media. "
                    "Coordinate policies before enabling Intune BitLocker-To-Go write blocks so both agents don't fight."
                )
            if env_profile.get("sccm_state") in ("co_managed_active", "mixed_active_and_orphaned") and ctrl["id"] == "OIB-UPD-007":
                ctrl["what_breaks_in_prod"] = (
                    "[CO-MANAGEMENT GUARDRAIL] Active ConfigMgr Co-Management sliders override Intune Update Rings if Windows Updates "
                    "still points to ConfigMgr, AND orphaned dead-SCCM clients ignore Intune until zombie ccmexec + Registry.pol locks are scrubbed. "
                    + ctrl["what_breaks_in_prod"]
                )

            has_conflict = any(
                p["status_flag"] in ("conflict", "unapproved_change") for p in matching_policies
            ) or bool(matching_gpos)

            if current_ring == "Ring 3 (Broad Prod)":
                diff_status = "Deployed (Broad Prod)"
            elif current_ring != "Not Deployed":
                diff_status = f"In Rollout ({current_ring})"
            elif coexistence_override:
                diff_status = coexistence_override
            elif has_conflict:
                diff_status = "Policy / GPO Conflict"
            elif ctrl["user_breakage_risk"] == "High":
                diff_status = "High Impact — Start Ring 0 Audit"
            else:
                diff_status = "Ready for Safe Rollout"

            targeted_devices = round(total_devices * ring_info["device_share"])
            # Realistic simulated telemetry for interactive presentation
            if current_ring == "Not Deployed":
                telemetry = {
                    "targeted_devices": 0,
                    "compliant_devices": 0,
                    "audit_alerts": 0,
                    "auto_healed_devices": 0,
                    "user_tickets_predicted": 0,
                }
            else:
                conflict_penalty = 0.08 if (has_conflict and current_ring != "Ring 0 (Audit)") else 0.02
                healed = max(1, round(targeted_devices * conflict_penalty)) if targeted_devices > 0 else 0
                compliant = max(0, targeted_devices - (1 if has_conflict else 0))
                audit_hits = round(targeted_devices * (0.14 if ctrl["user_breakage_risk"] == "High" else 0.04))
                telemetry = {
                    "targeted_devices": targeted_devices,
                    "compliant_devices": compliant,
                    "audit_alerts": audit_hits,
                    "auto_healed_devices": healed,
                    "user_tickets_predicted": 0 if current_ring == "Ring 0 (Audit)" else (1 if ctrl["user_breakage_risk"] == "High" else 0),
                }

            results.append(
                {
                    **ctrl,
                    "diff_status": diff_status,
                    "current_ring": current_ring,
                    "previous_ring": state["previous_ring"] if state else None,
                    "last_rfc": state["last_rfc"] if state else None,
                    "ring_entra_group": ring_info["entra_group"],
                    "ring_description": ring_info["description"],
                    "can_promote": RING_ORDER.index(current_ring) < len(RING_ORDER) - 1,
                    "can_rollback": RING_ORDER.index(current_ring) > 0,
                    "next_ring": (
                        RING_ORDER[RING_ORDER.index(current_ring) + 1]
                        if RING_ORDER.index(current_ring) < len(RING_ORDER) - 1
                        else None
                    ),
                    "conflicting_policies": [
                        {
                            "id": p["id"],
                            "name": p["name"],
                            "category": p["category"],
                            "configured_value": p["configured_value"],
                            "assigned_include": p["assigned_include"],
                            "assigned_exclude": p["assigned_exclude"],
                            "status_flag": p["status_flag"],
                            "conflict_reason": p["conflict_reason"],
                        }
                        for p in matching_policies
                    ],
                    "conflicting_gpos": matching_gpos,
                    "simulated_telemetry": telemetry,
                    "rollout_history": state["history"] if state else [],
                }
            )
        return results

    def get_nested_group_conflicts(self) -> dict[str, Any]:
        groups = self._snapshot["groups"]
        by_id = {g["id"]: g for g in groups}

        def walk_chain(gid: str, depth: int = 0) -> list[dict[str, Any]]:
            if depth > 5 or gid not in by_id:
                return []
            g = by_id[gid]
            children = [walk_chain(cid, depth + 1) for cid in g["nested_children"]]
            flat_children = [item for sub in children for item in sub]
            return [
                {
                    "id": g["id"],
                    "name": g["name"],
                    "type": g["type"],
                    "member_count": g["member_count"],
                    "depth": depth,
                    "risk_flag": g["risk_flag"],
                }
            ] + flat_children

        chains = []
        for g in groups:
            if g["nested_children"]:
                nodes = walk_chain(g["id"])
                max_depth = max(n["depth"] for n in nodes)
                chains.append(
                    {
                        "root_id": g["id"],
                        "root_name": g["name"],
                        "root_type": g["type"],
                        "total_members": g["member_count"],
                        "nesting_depth": max_depth + 1,
                        "risk_flag": g["risk_flag"],
                        "nodes": nodes,
                    }
                )

        return {
            "total_groups": len(groups),
            "nested_chains": chains,
            "high_risk_groups": [g for g in groups if g["risk_flag"]],
            "tattooed_gpos": self._snapshot["tattooed_gpos"],
        }

    def search_policies(
        self,
        *,
        query: str = "",
        status: str = "all",
        category: str = "all",
        page: int = 1,
        page_size: int = 25,
    ) -> dict[str, Any]:
        q = query.strip().lower()
        filtered = []
        for p in self._snapshot["policies"]:
            if status != "all" and p["status_flag"] != status:
                continue
            if category != "all" and p["category"] != category:
                continue
            if q:
                hay = " ".join(
                    [
                        p["name"],
                        p["category"],
                        p["configured_value"],
                        p["modified_by"],
                        p["conflict_reason"],
                        " ".join(p["assigned_include"]),
                        " ".join(p["assigned_exclude"]),
                    ]
                ).lower()
                if q not in hay:
                    continue
            filtered.append(p)

        total = len(filtered)
        start = max(0, (page - 1) * page_size)
        end = start + page_size
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, (total + page_size - 1) // page_size),
            "items": filtered[start:end],
        }

    def transition_ring(
        self,
        *,
        control_id: str,
        action: str,
        rfc_ticket: str,
        actor: str,
        channel: str = "WEB_STUDIO",
        note: str = "",
        target_ring: str | None = None,
    ) -> dict[str, Any]:
        ctrl = get_control_by_id(control_id)
        if not ctrl:
            raise ValueError(f"Unknown baseline control ID: {control_id}")

        rfc_clean = (rfc_ticket or "").strip()
        if self.config.require_rfc_for_writes and not rfc_clean:
            raise ValueError("ITIL Change Control Gate: An RFC / Change Ticket ID (e.g., CHG-2026-1042) is required.")

        states = self.audit.get_rollout_states()
        current_ring = states[control_id]["current_ring"] if control_id in states else "Not Deployed"
        idx = RING_ORDER.index(current_ring)

        if target_ring:
            if target_ring not in RING_ORDER:
                raise ValueError(f"Invalid target ring '{target_ring}'. Allowed: {RING_ORDER}")
            new_ring = target_ring
        elif action == "promote":
            if idx >= len(RING_ORDER) - 1:
                raise ValueError(f"{control_id} is already in {current_ring}.")
            new_ring = RING_ORDER[idx + 1]
        elif action == "rollback":
            if idx <= 0:
                raise ValueError(f"{control_id} is already Not Deployed.")
            new_ring = RING_ORDER[idx - 1]
        else:
            raise ValueError(f"Unsupported action '{action}'. Use 'promote' or 'rollback'.")

        saved = self.audit.save_rollout_state(
            control_id=control_id,
            new_ring=new_ring,
            previous_ring=current_ring,
            rfc_ticket=rfc_clean,
            actor=actor,
            note=note,
        )
        audit_rec = self.audit.log_event(
            actor=actor,
            channel=channel,
            action=f"RING_{action.upper()}",
            target_id=control_id,
            rfc_ticket=rfc_clean,
            status="SUCCEEDED",
            before_state={"ring": current_ring, "group": RING_METADATA[current_ring]["entra_group"]},
            after_state={"ring": new_ring, "group": RING_METADATA[new_ring]["entra_group"]},
            rationale=note or f"{action.title()} {ctrl['name']} from {current_ring} to {new_ring}",
        )
        return {"rollout": saved, "audit_event": audit_rec}

    def reset_to_default_snapshot(self) -> dict[str, Any]:
        self._snapshot = self.adapter.fetch_tenant_snapshot()
        self.audit.log_event(
            actor="engineer@local",
            channel="WEB_STUDIO",
            action="TENANT_RESET_SANDBOX",
            target_id=self._snapshot["tenant"]["tenant_id"],
            status="SUCCEEDED",
            rationale="Switched back to default synthetic 418-policy sandbox tenant.",
        )
        return self.get_tenant_overview()

    def import_offline_snapshot(self, payload: dict[str, Any], actor: str = "engineer@local") -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("Uploaded snapshot must be a valid JSON object.")

        tenant_name = str(payload.get("tenant_name") or "Imported Intune Tenant").strip()
        tenant_id = str(payload.get("tenant_id") or "imported-offline-snapshot").strip()

        self._snapshot = normalize_graph_payload(
            payload,
            mode="imported",
            licensing="Imported Real Tenant Snapshot (Zero Live Credentials Used)",
            industry="Customer Environment",
            modified_by="Imported Snapshot",
            tenant_name_suffix=" (Offline Snapshot Import)",
            require_policies=True,
        )
        policies = self._snapshot["policies"]
        groups = self._snapshot["groups"]

        self.audit.set_playbook_task(
            "s1-connect-tenant",
            True,
            actor=actor,
            notes=f"Imported offline snapshot for '{tenant_name}' ({len(policies)} policies, {len(groups)} groups).",
        )
        self.audit.log_event(
            actor=actor,
            channel="OFFLINE_IMPORT",
            action="IMPORT_TENANT_SNAPSHOT",
            target_id=tenant_id,
            status="SUCCEEDED",
            after_state={"tenant_name": tenant_name, "policies": len(policies), "groups": len(groups)},
            rationale="Loaded read-only offline JSON snapshot exported via Export-IntuneGuardSnapshot.ps1.",
        )
        return self.get_tenant_overview()

    def get_guided_playbook(self) -> dict[str, Any]:
        overview = self.get_tenant_overview()
        controls = self.evaluate_baseline_dry_run()
        progress = self.audit.get_playbook_progress()
        policies = self._snapshot["policies"]
        groups = self._snapshot["groups"]
        gpos = self._snapshot["tattooed_gpos"]

        orphans = [p for p in policies if p["status_flag"] == "orphaned"]
        duplicates = [p for p in policies if p["status_flag"] == "duplicate"]
        conflicts = [p for p in policies if p["status_flag"] == "conflict"]
        risky_groups = [g for g in groups if g["risk_flag"]]
        nested_groups = [g for g in groups if g["nested_children"]]
        critical_gpos = [g for g in gpos if g["severity"] in ("Critical", "High")]

        wave1 = [c for c in controls if c["user_breakage_risk"] == "Low"]
        wave2 = [c for c in controls if c["user_breakage_risk"] == "Medium"]
        wave3 = [c for c in controls if c["user_breakage_risk"] == "High"]

        def task_done(tid: str, auto_condition: bool = False) -> bool:
            if tid in progress:
                return progress[tid]["completed"]
            return auto_condition

        stages = [
            {
                "stage_number": 1,
                "id": "stage-1",
                "title": "Connect & Baseline Your Tenant (Zero Risk)",
                "short_title": "1. Connect",
                "why": (
                    "Never guess inside a 400-policy tenant. Start strictly read-only—either upload an offline JSON snapshot "
                    "using your existing interactive login today (0 ARB wait) or deploy the read-only X.509 App Registration."
                ),
                "tasks": [
                    {
                        "id": "s1-connect-tenant",
                        "title": "Load your tenant data (Path A: Offline Read-Only JSON Snapshot OR Path B: Live Graph App Reg)",
                        "impact": "Zero user impact • Read-only discovery",
                        "completed": task_done("s1-connect-tenant", overview["tenant"]["mode"] in ("imported", "live")),
                        "action_hint": "Use the Connect panel below to download Export-IntuneGuardSnapshot.ps1 and upload your JSON.",
                    },
                    {
                        "id": "s1-review-e7",
                        "title": "Confirm M365 E7 native coverage (Intune P1, Proactive Remediations, Autopatch, Entra Suite, Agent 365)",
                        "impact": "$0 add-on spend • Ready for ARB review",
                        "completed": task_done("s1-review-e7", False),
                        "action_hint": "Share docs/LICENSING_COMPATIBILITY_E7.md and docs/SECURITY_ARB_PACKAGE.md with InfoSec/ARB.",
                    },
                ],
            },
            {
                "stage_number": 2,
                "id": "stage-2",
                "title": "De-Clutter Sprawl Before Touching Users",
                "short_title": "2. Clean Sprawl",
                "why": (
                    "Pushing OIB/CIS baselines on top of 400 conflicting policies and 3-level nested exclusion groups causes "
                    "Intune 'Conflict' states and surprise lockouts. Clean the console first while end users feel NOTHING."
                ),
                "metrics": {
                    "orphaned_policies": len(orphans),
                    "duplicate_policies": len(duplicates),
                    "conflicting_policies": len(conflicts),
                    "risky_groups": len(risky_groups),
                    "nested_chains": len(nested_groups),
                },
                "tasks": [
                    {
                        "id": "s2-archive-orphans",
                        "title": f"Backup & remove {len(orphans)} orphaned (unassigned) policies",
                        "impact": "Zero user impact • Instant console clarity",
                        "completed": task_done("s2-archive-orphans", False),
                        "action_hint": "Download Stage 2A Orphan Cleanup PowerShell script (runs in Dry-Run mode first).",
                    },
                    {
                        "id": "s2-stale-exclusions",
                        "title": f"Audit & retire {len(risky_groups)} stale/high-risk exclusion groups (e.g., 2023 troubleshooting bypasses)",
                        "impact": "Closes silent compliance holes without touching healthy devices",
                        "completed": task_done("s2-stale-exclusions", False),
                        "action_hint": "Inspect Nested Groups tab, then run Stage 2B script to create 4 clean flat OIB Ring groups.",
                    },
                    {
                        "id": "s2-consolidate-dupes",
                        "title": f"Flag {len(duplicates)} duplicate & {len(conflicts)} conflicting policies for phased retirement",
                        "impact": "Prevents MDM winning-provider collisions during Wave 1-3 rollout",
                        "completed": task_done("s2-consolidate-dupes", False),
                        "action_hint": "Filter the 418-Policy Explorer by 'Conflicting' and 'Duplicate' to review owners.",
                    },
                ],
            },
            {
                "stage_number": 3,
                "id": "stage-3",
                "title": "Scrub Tattooed On-Prem GPO Locks (Clear the Runway)",
                "short_title": "3. Scrub GPOs",
                "why": (
                    "Hybrid-joined endpoints ignore Intune Update Rings, BitLocker XTS-256, LAPS, and Defender policies "
                    "when legacy HKLM\\SOFTWARE\\Policies keys remain tattooed from old GPOs. Clear them first via Proactive Remediations."
                ),
                "metrics": {
                    "total_gpos": len(gpos),
                    "critical_high_gpos": len(critical_gpos),
                },
                "tasks": [
                    {
                        "id": "s3-wsus-scrub",
                        "title": "Deploy Remediate-WUfB-StaleWSUSLocks to unblock stalled Windows Update / Autopatch pipelines",
                        "impact": "Fixes silent patching stalls with zero forced reboots",
                        "completed": task_done("s3-wsus-scrub", False),
                        "action_hint": "Copy Detect.ps1 & Remediate.ps1 for OIB-UPD-007 in Tab 4 (Self-Healing Hub).",
                    },
                    {
                        "id": "s3-security-gpos",
                        "title": f"Clear {len(critical_gpos)} critical/high legacy GPO tattoos (BitLocker AES-128, AdmPwd LAPS, Domain Firewall=0)",
                        "impact": "Ensures Intune wins policy precedence cleanly",
                        "completed": task_done("s3-security-gpos", False),
                        "action_hint": "Unlink legacy domain GPOs in AD and deploy corresponding Proactive Remediations.",
                    },
                ],
            },
            {
                "stage_number": 4,
                "id": "stage-4",
                "title": "Roll Out OIB / CIS in 3 Safe Waves (Zero Helpdesk Meltdown)",
                "short_title": "4. Safe Waves",
                "why": (
                    "Never flip all compliance controls at once. Start with Low-Risk quick wins to build leadership trust, "
                    "then move to Medium-Risk controls, and ALWAYS soak High-Risk controls (ASR, Firewall, CA, USB) in Ring 0 Audit for 14 days."
                ),
                "waves": [
                    {
                        "wave": "Wave 1 — Quick Compliance Wins (Low Breakage Risk)",
                        "guidance": "Start in Ring 1 (IT Pilot) -> 7-day soak -> Ring 2 -> Ring 3.",
                        "controls": [{"id": c["id"], "name": c["name"], "current_ring": c["current_ring"]} for c in wave1],
                    },
                    {
                        "wave": "Wave 2 — Controlled Hardening (Medium Breakage Risk)",
                        "guidance": "Validate Credential Guard without UEFI lock, user-targeted Patch Rings, and Edge plugins in Ring 1 & 2.",
                        "controls": [{"id": c["id"], "name": c["name"], "current_ring": c["current_ring"]} for c in wave2],
                    },
                    {
                        "wave": "Wave 3 — High-Impact Security (Mandatory 14-Day Ring 0 Audit)",
                        "guidance": "Run Defender ASR, Firewall merge audit, Conditional Access Report-Only, and USB VID/PID inventory in Ring 0 first.",
                        "controls": [{"id": c["id"], "name": c["name"], "current_ring": c["current_ring"]} for c in wave3],
                    },
                ],
                "tasks": [
                    {
                        "id": "s4-wave1",
                        "title": f"Stage all {len(wave1)} Wave 1 (Low-Risk) controls into Ring 1+ with ITIL RFC tracking",
                        "impact": "Immediate BitLocker, LAPS & Agent 365 compliance lift",
                        "completed": task_done("s4-wave1", all(c["current_ring"] != "Not Deployed" for c in wave1)),
                        "action_hint": "Open Tab 2 (OIB vs CIS Studio) filtered by Low Risk to promote Wave 1.",
                    },
                    {
                        "id": "s4-wave3-audit",
                        "title": f"Start all {len(wave3)} Wave 3 (High-Risk) controls in Ring 0 (Audit Mode) for 14-day telemetry soak",
                        "impact": "Zero branch scanner or call-center VoIP breakage",
                        "completed": task_done("s4-wave3-audit", all(c["current_ring"] != "Not Deployed" for c in wave3)),
                        "action_hint": "Promote ASR, Firewall, Compliance CA, and USB DLP to Ring 0 (Audit).",
                    },
                ],
            },
            {
                "stage_number": 5,
                "id": "stage-5",
                "title": "Lock the Door (ITIL Change Control, MAA & Copilot/MCP)",
                "short_title": "5. Lock & Govern",
                "why": (
                    "Without change governance, a clean tenant drifts back into 400-policy chaos within 6 months. "
                    "Lock in Multi-Admin Approval safely, export your As-Built baseline, and wire MCP + Agent 365 for continuous self-healing."
                ),
                "tasks": [
                    {
                        "id": "s5-maa-preflight",
                        "title": "Whitelist verified automation Enterprise Apps before enabling Intune Multi-Admin Approval (MAA)",
                        "impact": "Prevents HTTP 400/403 breakage in patching/CI pipelines",
                        "completed": task_done("s5-maa-preflight", False),
                        "action_hint": "Review MAA Pre-Flight list in Tenant Overview, then stage OIB-GOV-011.",
                    },
                    {
                        "id": "s5-export-asbuilt",
                        "title": "Export signed As-Built HTML/Markdown Report & verify SHA-256 ITIL audit chain",
                        "impact": "Auditor-ready evidence for NCUA / FFIEC / CAB",
                        "completed": task_done("s5-export-asbuilt", False),
                        "action_hint": "Click 'Export Auditor HTML Report' in the top bar.",
                    },
                    {
                        "id": "s5-connect-mcp",
                        "title": "Connect IntuneGuard MCP Server to VS Code / Copilot / Agent 365 (Human-in-the-Loop Write Gate)",
                        "impact": "Continuous read-only AI diagnostics with zero unapproved writes",
                        "completed": task_done("s5-connect-mcp", False),
                        "action_hint": "Test a tool call and CAB approval in Tab 5 (ITIL Audit & MCP Playground).",
                    },
                ],
            },
        ]

        all_tasks = [t for s in stages for t in s["tasks"]]
        done_count = sum(1 for t in all_tasks if t["completed"])
        for s in stages:
            st_done = sum(1 for t in s["tasks"] if t["completed"])
            s["completed_tasks"] = st_done
            s["total_tasks"] = len(s["tasks"])
            s["status"] = "completed" if st_done == len(s["tasks"]) else ("in_progress" if st_done > 0 else "pending")

        return {
            "overall_progress_pct": round((done_count / max(len(all_tasks), 1)) * 100),
            "completed_tasks": done_count,
            "total_tasks": len(all_tasks),
            "tenant_mode": overview["tenant"]["mode"],
            "tenant_name": overview["tenant"]["name"],
            "stages": stages,
            "scripts": {
                "export_snapshot": {
                    "filename": "Export-IntuneGuardSnapshot.ps1",
                    "content": generate_offline_export_script(),
                },
                "app_registration": {
                    "filename": "New-IntuneGuardAppReg.ps1",
                    "content": generate_app_registration_script(),
                },
                "orphan_cleanup": {
                    "filename": "Stage2A-Archive-OrphanPolicies.ps1",
                    "content": generate_orphan_cleanup_script(orphans),
                },
                "ring_groups": {
                    "filename": "Stage2B-StaleGroups-And-FlatRings.ps1",
                    "content": generate_stale_group_cleanup_script(risky_groups),
                },
                "autopilot_audit": {
                    "filename": "Track3-Audit-Autopilot-ESP-And-PatchRings.ps1",
                    "content": AUTOPILOT_ESP_AUDIT_PS1,
                },
                "rbac_audit": {
                    "filename": "Track4-Audit-CustomRBAC-And-StandingAdmins.ps1",
                    "content": RBAC_AUDIT_PS1,
                },
                "scope_tag_audit": {
                    "filename": "Track5-Audit-ScopeTag-Visibility.ps1",
                    "content": SCOPE_TAG_AUDIT_PS1,
                },
                "zombie_sccm_scrubber": {
                    "filename": "Track7-Scrub-OrphanedSCCM-And-AuditPersonas.ps1",
                    "content": ZOMBIE_SCCM_AND_PERSONAS_PS1,
                },
            },
        }

    def get_guided_tracks(self) -> dict[str, Any]:
        controls = self.evaluate_baseline_dry_run()
        progress = self.audit.get_playbook_progress()
        memories = self.audit.list_memories()
        env_profile = self.audit.get_environment_profile()
        claims = self.audit.list_track_claims()
        tracks = build_guided_tracks(self._snapshot, controls, progress, memories, env_profile, claims)
        completed_count = sum(1 for t in tracks if t["completed"])
        return {
            "tenant": self._snapshot["tenant"],
            "environment_profile": env_profile,
            "completed_tracks": completed_count,
            "total_tracks": len(tracks),
            "mastery_pct": round((completed_count / max(len(tracks), 1)) * 100),
            "memory_entries_count": len(memories),
            "claimed_tracks_count": len(claims),
            "tracks": tracks,
        }

    def import_gpo_xml(self, xml_text: str, actor: str = "endpoint-architect@local") -> dict[str, Any]:
        parsed = parse_gpmc_xml(xml_text)
        self._snapshot["tattooed_gpos"] = parsed["tattooed_gpos"]
        self.audit.log_event(
            actor=actor,
            channel="GPO_XML_IMPORT",
            action="IMPORT_GPMC_XML_REPORT",
            target_id=self._snapshot["tenant"]["tenant_id"],
            status="SUCCEEDED",
            after_state={
                "gpos_scanned": parsed["gpos_scanned"],
                "collisions_found": parsed["collisions_found"],
            },
            rationale=f"Parsed GPMC XML report ({parsed['gpos_scanned']} GPOs scanned, {parsed['collisions_found']} Intune collisions detected).",
        )
        return parsed

    def backtrack_incident(self, query: str = "", limit: int = 35) -> dict[str, Any]:
        """Correlate an outage symptom across unapproved portal edits, ITIL audit trail,
        Tenant Context Memory, and active rollback candidates."""
        q = query.strip().lower()
        terms = [t for t in q.split() if len(t) >= 2] if q else []

        def matches(text: str) -> bool:
            if not terms:
                return True
            low = text.lower()
            return any(t in low for t in terms)

        timeline: list[dict[str, Any]] = []

        for u in self._snapshot.get("unapproved_changes") or []:
            hay = f"{u.get('policy_name','')} {u.get('change_summary','')} {u.get('actor','')} {u.get('severity','')}"
            if matches(hay):
                timeline.append(
                    {
                        "timestamp_utc": u.get("timestamp_utc") or "",
                        "source": "UNAPPROVED_PORTAL_EDIT",
                        "severity": u.get("severity") or "High",
                        "title": u.get("policy_name") or "Direct Portal Edit",
                        "detail": u.get("change_summary") or "",
                        "actor": u.get("actor") or "Unknown",
                        "rfc_ticket": u.get("rfc_ticket") or "NONE",
                    }
                )

        for e in self.audit.list_events(limit=limit):
            hay = f"{e['action']} {e['target_id']} {e['rationale']} {e['actor']} {e['rfc_ticket']}"
            if matches(hay):
                timeline.append(
                    {
                        "timestamp_utc": e["timestamp_utc"],
                        "source": "ITIL_AUDIT_CHAIN",
                        "severity": "Medium" if "ROLLBACK" not in e["action"] else "Info",
                        "title": f"{e['action']} ({e['target_id']})",
                        "detail": e["rationale"] or str(e.get("after") or ""),
                        "actor": e["actor"],
                        "rfc_ticket": e["rfc_ticket"] or "—",
                        "event_hash": e["event_hash"][:14],
                    }
                )

        matched_memories = [
            m
            for m in self.audit.list_memories()
            if matches(f"{m['track_id']} {m['category']} {m['summary']} {m['details']}")
        ]

        controls = self.evaluate_baseline_dry_run()
        rollback_candidates = [
            {
                "control_id": c["id"],
                "name": c["name"],
                "current_ring": c["current_ring"],
                "last_rfc": c["last_rfc"],
                "what_breaks_in_prod": c["what_breaks_in_prod"],
            }
            for c in controls
            if c["can_rollback"]
            and matches(f"{c['id']} {c['domain']} {c['name']} {c['what_breaks_in_prod']}")
        ]

        timeline.sort(key=lambda item: item.get("timestamp_utc") or "", reverse=True)
        return {
            "query": query,
            "timeline_count": len(timeline),
            "timeline": timeline[:limit],
            "related_memories": matched_memories,
            "rollback_candidates": rollback_candidates,
        }

    def generate_auditor_report_markdown(self) -> str:
        overview = self.get_tenant_overview()
        controls = self.evaluate_baseline_dry_run()
        events = self.audit.list_events(limit=25)
        chain = self.audit.verify_chain()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        kpis = overview["kpis"]
        t = overview["tenant"]

        lines = [
            f"# IntuneGuard Studio — As-Built & Compliance Governance Report",
            f"",
            f"- **Generated:** {now}",
            f"- **Tenant:** {t['name']} (`{t['tenant_id']}`)",
            f"- **Licensing Verified:** {t['licensing']} *(Zero Intune Suite add-on required)*",
            f"- **Audit Trail Integrity (SHA-256 Hash Chain):** `{'VERIFIED' if chain['valid'] else 'BROKEN'}` ({chain['checked']} events checked)",
            f"",
            f"## 1. Executive Sprawl & Risk Summary",
            f"| Metric | Value |",
            f"| :--- | :--- |",
            f"| Total Intune Policies Analyzed | **{kpis['total_policies']}** |",
            f"| Conflicting / Overlapping Policies | **{kpis['conflicting_policies']}** |",
            f"| Duplicate Policies | **{kpis['duplicate_policies']}** |",
            f"| Orphaned (Unassigned) Policies | **{kpis['orphaned_policies']}** |",
            f"| Nested Group Assignment Chains | **{kpis['nested_group_chains']}** |",
            f"| Tattooed On-Prem GPO Collisions | **{kpis['tattooed_gpos']}** |",
            f"| Policies Lacking ITIL RFC Tag | **{kpis['policies_without_rfc_pct']}%** |",
            f"| OIB / CIS Safe Rollout Progress | **{kpis['oib_rollout_progress_pct']}%** |",
            f"",
            f"## 2. OpenIntuneBaseline (OIB) vs. CIS v5.0.0 Control Matrix & Deviation Rationales",
            f"| ID | Control | Risk | Current Ring | Status | CIS Reference | Regulatory Mapping |",
            f"| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for c in controls:
            lines.append(
                f"| `{c['id']}` | {c['name']} | {c['user_breakage_risk']} | {c['current_ring']} | {c['diff_status']} | {c['cis_ref']} | {', '.join(c['regulatory_map'])} |"
            )

        lines.append("")
        lines.append("## 3. Auditor Deviation Rationales (OIB vs. Strict CIS)")
        for c in controls:
            lines.extend(
                [
                    f"### {c['id']} — {c['name']}",
                    f"- **OIB Standard:** {c['oib_value']}",
                    f"- **Strict CIS Benchmark:** {c['cis_value']}",
                    f"- **Breakage Warning:** {c['what_breaks_in_prod']}",
                    f"- **Documented Auditor Rationale:** {c['deviation_rationale']}",
                    f"- **M365 E7 Component:** {c['e7_component']}",
                    f"",
                ]
            )

        lines.append("## 4. Recent Hash-Chained ITIL Change & Governance Log")
        lines.append("| Timestamp (UTC) | Event UID | Actor | Action | Target | RFC Ticket | Hash (Short) |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for e in events:
            lines.append(
                f"| {e['timestamp_utc'][:19]} | `{e['event_uid']}` | {e['actor']} | {e['action']} | `{e['target_id']}` | `{e['rfc_ticket'] or 'N/A'}` | `{e['event_hash'][:12]}` |"
            )

        return "\n".join(lines)

    def generate_sharepoint_kb_markdown(self) -> str:
        """Generates a clean, chunk-friendly Markdown Knowledge Base designed for
        SharePoint Document Libraries -> SharePoint Agents & Copilot Agent Builder
        (zero MCP or Copilot Studio dependency required on Day 1)."""
        overview = self.get_tenant_overview()
        controls = self.evaluate_baseline_dry_run()
        env_profile = self.audit.get_environment_profile()
        memories = self.audit.list_memories()
        claims = self.audit.list_track_claims()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        t = overview["tenant"]

        lines = [
            f"# Endpoint Management & Intune Knowledge Base ({t['name']})",
            f"",
            f"> **Purpose:** Drop this file into an approved SharePoint Document Library to ground **SharePoint Agents** and **Copilot Agent Builder** with verified endpoint architecture decisions, coexistence guardrails, and compliance rationales.",
            f"> **Last Exported:** {now} | **Policies Analyzed:** {overview['kpis']['total_policies']} | **Managed Windows Endpoints:** {t['devices'].get('total_managed_windows', 0)}",
            f"",
            f"## 1. Active Security Stack & Coexistence Guardrails (DO NOT VIOLATE)",
            f"- **AV / EDR Stack:** `{env_profile['edr_provider']}`",
            f"- **Endpoint DLP Stack:** `{env_profile['dlp_provider']}`",
            f"- **ConfigMgr / SCCM State:** `{env_profile['sccm_state']}`",
            f"- **AVD Kiosks / Multi-Session Hosts Present:** `{env_profile['has_avd_kiosks']}`",
            f"- **End-of-Life Windows 10 Stragglers Present:** `{env_profile['has_win10_stragglers']}`",
            f"",
            f"## 2. Active Team Track Ownership (Prevent Overlapping Changes)",
        ]
        if claims:
            for tid, cl in claims.items():
                lines.append(f"- **`{tid}`** — Owner: `{cl['owner']}` (Claimed {cl['claimed_at_utc'][:10]}) {cl.get('notes','')}")
        else:
            lines.append("- No tracks currently claimed.")

        lines.extend(["", "## 3. Approved Tenant Context Memory (Decisions & Exceptions)"])
        if memories:
            for m in memories:
                lines.extend(
                    [
                        f"### [{m['category']}] {m['summary']}",
                        f"- **Track:** `{m['track_id']}` | **Recorded By:** `{m['recorded_by']}` | **Date:** {m['recorded_at_utc'][:10]}",
                        f"- **Details:** {m['details']}",
                        f"",
                    ]
                )
        else:
            lines.append("- No custom tenant memories saved yet.")

        lines.extend(["", "## 4. OIB vs. CIS Control Status, Breakage Watchouts & Auditor Rationales"])
        for c in controls:
            lines.extend(
                [
                    f"### {c['id']} — {c['name']}",
                    f"- **Current Ring:** {c['current_ring']} | **Status:** {c['diff_status']} | **Breakage Risk:** {c['user_breakage_risk']}",
                    f"- **CIS / Regulatory Reference:** {c['cis_ref']} ({', '.join(c['regulatory_map'])})",
                    f"- **Production Breakage & Coexistence Watchout:** {c['what_breaks_in_prod']}",
                    f"- **Approved Auditor Rationale:** {c['deviation_rationale']}",
                    f"",
                ]
            )
        return "\n".join(lines)

    def generate_auditor_report_html(self) -> str:
        overview = self.get_tenant_overview()
        controls = self.evaluate_baseline_dry_run()
        events = self.audit.list_events(limit=25)
        chain = self.audit.verify_chain()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        k = overview["kpis"]
        t = overview["tenant"]

        rows_html = []
        for c in controls:
            rows_html.append(
                f"<tr>"
                f"<td><code>{html.escape(c['id'])}</code></td>"
                f"<td><strong>{html.escape(c['name'])}</strong><br><small>{html.escape(c['domain'])}</small></td>"
                f"<td>{html.escape(c['user_breakage_risk'])}</td>"
                f"<td>{html.escape(c['current_ring'])}</td>"
                f"<td>{html.escape(c['diff_status'])}</td>"
                f"<td><small>{html.escape(c['cis_ref'])}<br>{html.escape(', '.join(c['regulatory_map']))}</small></td>"
                f"<td><small>{html.escape(c['deviation_rationale'])}</small></td>"
                f"</tr>"
            )

        audit_rows = []
        for e in events:
            audit_rows.append(
                f"<tr>"
                f"<td>{html.escape(e['timestamp_utc'][:19])}</td>"
                f"<td><code>{html.escape(e['event_uid'])}</code></td>"
                f"<td>{html.escape(e['actor'])}</td>"
                f"<td>{html.escape(e['action'])}</td>"
                f"<td><code>{html.escape(e['target_id'])}</code></td>"
                f"<td><code>{html.escape(e['rfc_ticket'] or 'N/A')}</code></td>"
                f"<td><code>{html.escape(e['event_hash'][:14])}</code></td>"
                f"</tr>"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>IntuneGuard Studio — As-Built & Compliance Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #0f172a; margin: 32px; line-height: 1.5; }}
  h1, h2 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }}
  .meta {{ background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 14px 18px; margin-bottom: 20px; }}
  .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0 24px; }}
  .card {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px; background: #ffffff; }}
  .card .val {{ font-size: 24px; font-weight: 700; color: #0284c7; }}
  .card .lbl {{ font-size: 12px; color: #475569; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0 28px; font-size: 13px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 12px; }}
  @media print {{ body {{ margin: 12px; }} }}
</style>
</head>
<body>
  <h1>IntuneGuard Studio — Executive As-Built & CIS/OIB Compliance Report</h1>
  <div class="meta">
    <strong>Tenant:</strong> {html.escape(t['name'])} (<code>{html.escape(t['tenant_id'])}</code>)<br>
    <strong>Licensing:</strong> {html.escape(t['licensing'])}<br>
    <strong>Generated:</strong> {now} &nbsp;|&nbsp;
    <strong>Hash-Chained Audit Integrity:</strong> <code>{'VERIFIED' if chain['valid'] else 'BROKEN'} ({chain['checked']} events)</code>
  </div>
  <div class="grid">
    <div class="card"><div class="val">{k['total_policies']}</div><div class="lbl">Policies Analyzed</div></div>
    <div class="card"><div class="val">{k['conflicting_policies']}</div><div class="lbl">Conflicting Policies</div></div>
    <div class="card"><div class="val">{k['nested_group_chains']}</div><div class="lbl">Nested Group Chains</div></div>
    <div class="card"><div class="val">{k['oib_rollout_progress_pct']}%</div><div class="lbl">OIB Rollout Progress</div></div>
  </div>
  <h2>1. OpenIntuneBaseline (OIB) vs. CIS v5.0.0 Control Matrix & Auditor Rationales</h2>
  <table>
    <thead><tr><th>ID</th><th>Control</th><th>Risk</th><th>Current Ring</th><th>Status</th><th>CIS / Reg Mapping</th><th>Auditor Deviation Rationale</th></tr></thead>
    <tbody>{''.join(rows_html)}</tbody>
  </table>
  <h2>2. Tamper-Evident ITIL Change & Governance Log</h2>
  <table>
    <thead><tr><th>Timestamp (UTC)</th><th>Event UID</th><th>Actor</th><th>Action</th><th>Target</th><th>RFC Ticket</th><th>SHA-256 Hash</th></tr></thead>
    <tbody>{''.join(audit_rows)}</tbody>
  </table>
</body>
</html>"""
