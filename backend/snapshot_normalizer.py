"""Shared Microsoft Graph Payload Normalizer for Live & Offline Snapshots.

Ensures LiveGraphAdapter.fetch_tenant_snapshot() and IntuneGuardEngine.import_offline_snapshot()
produce identical canonical tenant structures across all 7 Guided Learning Tracks.
"""
from __future__ import annotations

from typing import Any


def infer_setting_key(name: str, category: str) -> str:
    n = f"{name} {category}".lower()
    if "bitlocker" in n or "encrypt" in n:
        return "bitlocker_os_xts_aes256_escrow"
    if "asr" in n or "attack surface" in n or "defender" in n or "antivirus" in n:
        return "defender_asr_core_rules"
    if "laps" in n or "local admin" in n:
        return "windows_laps_entra_rotation"
    if "credential guard" in n or "hvci" in n or "vbs" in n:
        return "credential_guard_hvci_enabled"
    if "firewall" in n:
        return "windows_firewall_all_profiles"
    if "uac" in n or "elevation" in n:
        return "uac_secure_desktop_standard_user"
    if "update" in n or "wufb" in n or "autopatch" in n or "ring" in n:
        return "wufb_patching_rings_oobe_safe"
    if "compliance" in n:
        return "device_compliance_zero_trust_ca"
    if "edge" in n or "browser" in n:
        return "edge_security_baseline_extensions"
    if "usb" in n or "removable" in n or "dlp" in n:
        return "removable_usb_write_control"
    return "general_tenant_policy"


def normalize_graph_payload(
    payload: dict[str, Any],
    *,
    mode: str,
    licensing: str,
    industry: str,
    modified_by: str,
    tenant_name_suffix: str = "",
    require_policies: bool = False,
) -> dict[str, Any]:
    """Normalize a raw Microsoft Graph snapshot (offline JSON or live Graph pulls)."""
    if not isinstance(payload, dict):
        raise ValueError("Tenant snapshot payload must be a valid JSON object.")

    raw_tenant_name = str(payload.get("tenant_name") or "Imported Intune Tenant").strip()
    tenant_name = f"{raw_tenant_name}{tenant_name_suffix}" if tenant_name_suffix else raw_tenant_name
    tenant_id = str(payload.get("tenant_id") or "imported-offline-snapshot").strip()

    raw_cfg = payload.get("configuration_policies") or []
    raw_dev = payload.get("device_configurations") or []
    raw_cmp = payload.get("compliance_policies") or []
    raw_groups = payload.get("groups") or []
    raw_audits = payload.get("audit_events") or []
    raw_autopilot = payload.get("autopilot_profiles") or []
    raw_esp = payload.get("esp_profiles") or []
    raw_roles = payload.get("custom_roles") or []
    raw_tags = payload.get("scope_tags") or []

    win_count = int(payload.get("windows_devices_count") or 0)
    win10_count = int(payload.get("windows_10_count") or 0)
    co_mgmt_count = int(payload.get("co_managed_count") or 0)

    group_lookup = {
        str(g.get("id", "")): str(g.get("displayName", g.get("id", "")))
        for g in raw_groups
        if isinstance(g, dict)
    }

    def extract_assignments(item: dict[str, Any]) -> tuple[list[str], list[str]]:
        inc: list[str] = []
        exc: list[str] = []
        for a in item.get("assignments") or []:
            target = (a or {}).get("target") or {}
            otype = str(target.get("@odata.type") or "")
            gid = str(target.get("groupId") or "")
            label = (
                group_lookup.get(gid, gid)
                if gid
                else (
                    "All Devices"
                    if "allDevices" in otype
                    else "All Users"
                    if "allLicensedUsers" in otype
                    else otype.split(".")[-1]
                )
            )
            if "exclusion" in otype.lower():
                exc.append(label)
            else:
                inc.append(label)
        return inc, exc

    policies: list[dict[str, Any]] = []
    seen_keys: dict[str, int] = {}

    def ingest_list(items: list[Any], default_cat: str) -> None:
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("displayName") or f"Unnamed Policy {idx + 1}")
            cat = (
                default_cat
                if default_cat != "auto"
                else str(item.get("@odata.type") or "Device Configuration").split(".")[-1]
            )
            inc, exc = extract_assignments(item)
            skey = infer_setting_key(name, cat)
            seen_keys[skey] = seen_keys.get(skey, 0) + 1

            if not inc:
                flag = "orphaned"
                reason = "Unassigned policy detected in tenant snapshot."
            elif exc:
                flag = "conflict"
                reason = (
                    f"Policy uses exclusion groups ({', '.join(exc[:2])}) — "
                    "verify no nested include/exclude collision."
                )
            elif seen_keys[skey] > 2 and skey != "general_tenant_policy":
                flag = "duplicate"
                reason = f"Multiple policies target '{skey}' — candidate for consolidation into unified OIB baseline."
            else:
                flag = "healthy"
                reason = ""

            policies.append(
                {
                    "id": str(item.get("id") or f"imp-{len(policies) + 1}"),
                    "name": name,
                    "category": cat,
                    "setting_key": skey,
                    "configured_value": str(item.get("technologies") or item.get("description") or "Graph Config")[:90],
                    "assigned_include": inc,
                    "assigned_exclude": exc,
                    "last_modified": str(item.get("lastModifiedDateTime") or "")[:10] or "Unknown",
                    "modified_by": modified_by,
                    "rfc_tag": None,
                    "status_flag": flag,
                    "conflict_reason": reason,
                }
            )

    ingest_list(raw_cfg, "Settings Catalog")
    ingest_list(raw_dev, "auto")
    ingest_list(raw_cmp, "Device Compliance")

    if require_policies and not policies:
        raise ValueError(
            "No policies found in uploaded JSON. Expected keys: 'configuration_policies', "
            "'device_configurations', or 'compliance_policies' (generated by Export-IntuneGuardSnapshot.ps1)."
        )

    groups = []
    for g in raw_groups:
        if not isinstance(g, dict):
            continue
        gtypes = g.get("groupTypes") or []
        gname = str(g.get("displayName") or g.get("id") or "Unnamed Group")
        is_dyn = "DynamicMembership" in gtypes
        risk = None
        if any(w in gname.lower() for w in ("temp", "exclude", "exception", "bypass", "old", "test")):
            risk = "Flagged by naming heuristic (temp/exclude/bypass/old) — review membership and expiry."
        groups.append(
            {
                "id": str(g.get("id") or f"grp-{len(groups) + 1}"),
                "name": gname,
                "type": "Dynamic" if is_dyn else "Assigned",
                "rule": g.get("membershipRule"),
                "member_count": int(g.get("memberCount") or 0),
                "nested_children": [],
                "risk_flag": risk,
            }
        )

    unapproved = []
    for e in raw_audits[:15]:
        if not isinstance(e, dict):
            continue
        unapproved.append(
            {
                "timestamp_utc": str(e.get("activityDateTime") or ""),
                "actor": str(((e.get("actor") or {}).get("userPrincipalName")) or "Admin/App"),
                "policy_name": str(e.get("displayName") or e.get("componentName") or "Intune Event"),
                "change_summary": str(e.get("activity") or "Configuration change recorded in Intune Audit Logs"),
                "rfc_ticket": None,
                "severity": "Medium",
            }
        )

    # Parse Phase 1.5 real tenant objects for Tracks 3, 4, 5 & 7
    autopilot_findings: list[dict[str, Any]] = []
    for e in raw_esp:
        if not isinstance(e, dict):
            continue
        app_cnt = len(e.get("selectedMobileAppIds") or [])
        timeout = e.get("installProgressTimeoutInMinutes") or 60
        if app_cnt > 6 or timeout < 45:
            autopilot_findings.append(
                {
                    "id": str(e.get("id") or "ESP-IMP"),
                    "object_name": str(e.get("displayName") or "Imported ESP"),
                    "object_type": "Enrollment Status Page (ESP)",
                    "severity": "High",
                    "finding": f"Blocks {app_cnt} apps with {timeout}-min timeout.",
                    "why_it_breaks": "High blocking app counts or short timeouts trigger Autopilot 0x81036502 failures.",
                    "recommended_fix": "Trim blocking apps to <=5 Win32 essentials and set timeout to 60 minutes.",
                }
            )
    for ap in raw_autopilot:
        if not isinstance(ap, dict):
            continue
        utype = ((ap.get("outOfBoxExperienceSettings") or {}).get("userType") or "").lower()
        if utype == "administrator":
            autopilot_findings.append(
                {
                    "id": str(ap.get("id") or "AP-IMP"),
                    "object_name": str(ap.get("displayName") or "Imported Autopilot Profile"),
                    "object_type": "Autopilot Deployment Profile",
                    "severity": "Critical",
                    "finding": "Provisions enrolling users as Local Administrator.",
                    "why_it_breaks": "Violates least privilege and CIS/NCUA endpoint hardening baselines.",
                    "recommended_fix": "Switch OOBE userType to Standard User and use Windows LAPS for audited elevation.",
                }
            )

    role_findings: list[dict[str, Any]] = []
    danger_tokens = ("Wipe", "Delete", "Retire", "Scripts_Assign", "RoleDefinitions_Update")
    for r in raw_roles:
        if not isinstance(r, dict):
            continue
        perms: list[str] = []
        for rp in r.get("rolePermissions") or []:
            for ra in (rp or {}).get("resourceActions") or []:
                perms.extend(ra.get("allowedResourceActions") or [])
        risky = [p for p in perms if any(tok in p for tok in danger_tokens)]
        if risky:
            role_findings.append(
                {
                    "id": str(r.get("id") or "RBAC-IMP"),
                    "role_name": str(r.get("displayName") or "Custom Role"),
                    "members_count": 0,
                    "severity": "High",
                    "overprivileged_permissions": risky[:6],
                    "why_it_is_dangerous": f"Custom role grants {len(risky)} destructive/privileged permissions.",
                    "recommended_fix": "Scope down destructive rights and protect Wipe/Scripts behind Multi-Admin Approval.",
                }
            )

    tag_findings: list[dict[str, Any]] = []
    missing_default_cnt = sum(
        1
        for p in raw_cfg
        if isinstance(p, dict)
        and p.get("roleScopeTagIds")
        and "0" not in [str(x) for x in p.get("roleScopeTagIds")]
    )
    if missing_default_cnt:
        tag_findings.append(
            {
                "id": "TAG-IMP-001",
                "object_name": f"{missing_default_cnt} Policies Missing 'Default' (0) Scope Tag",
                "scope_tags_applied": ["Custom Tags Only"],
                "severity": "High",
                "pitfall": "Policies without the Default Scope Tag are invisible to admins/auditors scoped only to Default.",
                "real_world_symptom": "Engineers create duplicate policies because they cannot see existing ones.",
                "recommended_fix": "Keep Default tag on shared policies or grant Read-Only Auditors All Scope Tags.",
            }
        )
    if len(raw_tags) > 5:
        tag_findings.append(
            {
                "id": "TAG-IMP-002",
                "object_name": f"{len(raw_tags)} Scope Tags Defined in Tenant",
                "scope_tags_applied": [str(t.get("displayName", "")) for t in raw_tags[:5]],
                "severity": "Medium",
                "pitfall": "Excessive Scope Tags complicate RBAC visibility and increase accidental hidden-object traps.",
                "real_world_symptom": "Helpdesk receives 'Device not found' errors during live tickets.",
                "recommended_fix": "Consolidate to <=3 well-documented Scope Tags assigned via flat dynamic device groups.",
            }
        )

    persona_findings: list[dict[str, Any]] = []
    if win10_count > 0:
        persona_findings.append(
            {
                "id": "PER-IMP-W10",
                "object_name": f"{win10_count} End-of-Life Windows 10 Endpoints Detected",
                "severity": "High",
                "finding": "Windows 10 endpoints remain active in Intune and distort Windows 11 compliance baselines.",
                "recommended_fix": "Quarantine via Assignment Filter 'FLT-Windows10-EOL-Quarantine' and track hardware replacement.",
            }
        )
    if co_mgmt_count > 0:
        persona_findings.append(
            {
                "id": "PER-IMP-CM",
                "object_name": f"{co_mgmt_count} ConfigMgr Co-Managed Endpoints Detected",
                "severity": "High",
                "finding": "Endpoints report ConfigMgr/SCCM co-management—verify whether site servers are active or decommissioned.",
                "recommended_fix": "Check Co-Management Workload Sliders on active sites and scrub zombie ccmexec on retired sites.",
            }
        )

    return {
        "tenant": {
            "name": tenant_name,
            "tenant_id": tenant_id,
            "licensing": licensing,
            "industry": industry,
            "mode": mode,
            "devices": {
                "total_managed_windows": win_count,
                "by_segment": dict(payload.get("devices_by_segment") or {}),
                "join_state": dict(payload.get("devices_join_state") or {}),
                "os_versions": dict(payload.get("devices_os_versions") or {}),
            },
        },
        "groups": groups,
        "policies": policies,
        "tattooed_gpos": [],
        "unapproved_changes": unapproved,
        "enterprise_apps": [],
        "autopilot_esp": autopilot_findings,
        "custom_roles": role_findings,
        "scope_tags": tag_findings,
        "device_personas": persona_findings,
    }
